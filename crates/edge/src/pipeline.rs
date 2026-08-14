//! The request path as an ordered list of stages.
//!
//! A stage looks at the request and either waves it through or answers it. That single
//! rule is what makes a WAF block and a cache hit the same mechanism: both just return
//! `Respond` and everything behind them never runs. The last stage in the list is
//! expected to always answer - today that's the origin fetch.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use async_trait::async_trait;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use tracing::warn;

use crate::body::{text, Body};
use crate::config::{Config, Zone};

pub enum Verdict {
    Continue,
    Respond(Response<Body>),
}

/// A stage that could not do its job. Carries the status the client should see.
#[derive(Debug)]
pub struct StageError {
    pub status: StatusCode,
    pub detail: String,
}

impl StageError {
    pub fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }
}

/// Who a request came from, and how. These three are worked out together in
/// `proxy::route` and always travel together - splitting them across arguments is how
/// you end up passing the peer where the client was meant.
#[derive(Debug, Clone)]
pub struct Caller {
    pub peer: SocketAddr,
    pub client: IpAddr,
    /// Whether the *client* used https, not necessarily whether our own leg did.
    pub tls: bool,
    /// Where the client is, looked up once before routing. Empty when no database is
    /// loaded, which is the default.
    pub geo: crate::geoip::Located,
}

/// Everything a stage is allowed to see about the request in flight.
pub struct Ctx<'a> {
    /// Who opened the socket. The forwarding chain and the connection limits care about
    /// this; nothing that identifies a *client* should.
    pub peer: SocketAddr,
    /// Who the request is from, which is the peer unless a trusted proxy said otherwise.
    /// Rate limits, `ip.src` rules and the log all key on this - see `client_ip`.
    pub client: IpAddr,
    pub host: String,
    pub cfg: &'a Config,
    pub zone: &'a Zone,
    pub started: Instant,
    /// Whether the client reached us over https - which behind a proxy that terminates
    /// TLS is not the same as whether our own leg was encrypted.
    pub tls: bool,
    /// Set by the pipeline to whichever stage produced the response.
    pub decided_by: &'static str,
    /// Country and ASN for `client`, resolved once per request. Both the WAF and the
    /// rate limiter read it, so neither pays for a second lookup.
    pub geo: crate::geoip::Located,
    req: Option<Request<Body>>,
}

impl<'a> Ctx<'a> {
    pub fn new(
        caller: Caller,
        host: String,
        cfg: &'a Config,
        zone: &'a Zone,
        req: Request<Body>,
        started: Instant,
    ) -> Self {
        Self {
            peer: caller.peer,
            client: caller.client,
            tls: caller.tls,
            geo: caller.geo,
            host,
            cfg,
            zone,
            started,
            decided_by: "none",
            req: Some(req),
        }
    }

    pub fn req(&self) -> Option<&Request<Body>> {
        self.req.as_ref()
    }

    /// Hand the request over. Either answer straight after, or put it back with
    /// `set_req` - anything else leaves the ctx empty for the stages behind you.
    pub fn take_req(&mut self) -> Option<Request<Body>> {
        self.req.take()
    }

    pub fn set_req(&mut self, req: Request<Body>) {
        self.req = Some(req);
    }

    pub fn method(&self) -> Option<&Method> {
        self.req.as_ref().map(|r| r.method())
    }

    pub fn uri(&self) -> Option<&Uri> {
        self.req.as_ref().map(|r| r.uri())
    }

    pub fn headers(&self) -> Option<&HeaderMap> {
        self.req.as_ref().map(|r| r.headers())
    }

    pub fn headers_mut(&mut self) -> Option<&mut HeaderMap> {
        self.req.as_mut().map(|r| r.headers_mut())
    }
}

#[async_trait]
pub trait Stage: Send + Sync {
    fn name(&self) -> &'static str;

    async fn on_request(&self, ctx: &mut Ctx<'_>) -> Result<Verdict, StageError>;

    /// Runs on the way back out, innermost stage first. Default is to not care.
    async fn on_response(&self, _ctx: &mut Ctx<'_>, _resp: &mut Response<Body>) {}
}

pub struct Pipeline {
    stages: Vec<Box<dyn Stage>>,
}

impl Pipeline {
    pub fn new(stages: Vec<Box<dyn Stage>>) -> Self {
        Self { stages }
    }

    pub fn stage_names(&self) -> Vec<&'static str> {
        self.stages.iter().map(|s| s.name()).collect()
    }

    pub async fn run(&self, ctx: &mut Ctx<'_>) -> Response<Body> {
        let mut answer = None;
        let mut entered = 0; /* how far in we got - filters unwind from here */

        for stage in &self.stages {
            entered += 1;
            match stage.on_request(ctx).await {
                Ok(Verdict::Continue) => {}
                Ok(Verdict::Respond(resp)) => {
                    ctx.decided_by = stage.name();
                    answer = Some(resp);
                    break;
                }
                Err(e) => {
                    warn!("stage {} failed: {}", stage.name(), e.detail);
                    ctx.decided_by = stage.name();
                    answer = Some(text(e.status, &e.detail));
                    break;
                }
            }
        }

        let mut resp = answer.unwrap_or_else(|| {
            /* the terminal stage is supposed to always answer, so this is our bug */
            warn!("pipeline ran off the end with no response");
            text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "500 no stage produced a response",
            )
        });

        for stage in self.stages[..entered].iter().rev() {
            stage.on_response(ctx, &mut resp).await;
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::full;
    use crate::config;
    use std::sync::{Arc, Mutex};

    /// Records the order stages ran in so tests can assert on it.
    #[derive(Clone, Default)]
    struct Trace(Arc<Mutex<Vec<String>>>);

    impl Trace {
        fn push(&self, s: String) {
            self.0.lock().unwrap().push(s);
        }
        fn seen(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    struct Probe {
        name: &'static str,
        trace: Trace,
        verdict: fn() -> Result<Verdict, StageError>,
    }

    #[async_trait]
    impl Stage for Probe {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn on_request(&self, _ctx: &mut Ctx<'_>) -> Result<Verdict, StageError> {
            self.trace.push(format!("{}:req", self.name));
            (self.verdict)()
        }
        async fn on_response(&self, _ctx: &mut Ctx<'_>, resp: &mut Response<Body>) {
            self.trace.push(format!("{}:resp", self.name));
            resp.headers_mut().append("x-ran", self.name.parse().unwrap());
        }
    }

    fn probe(name: &'static str, trace: &Trace, verdict: fn() -> Result<Verdict, StageError>) -> Box<dyn Stage> {
        Box::new(Probe {
            name,
            trace: trace.clone(),
            verdict,
        })
    }

    fn pass() -> Result<Verdict, StageError> {
        Ok(Verdict::Continue)
    }
    fn answer() -> Result<Verdict, StageError> {
        Ok(Verdict::Respond(
            Response::builder().status(418).body(full("teapot")).unwrap(),
        ))
    }
    fn fail() -> Result<Verdict, StageError> {
        Err(StageError::new(StatusCode::BAD_GATEWAY, "502 nope"))
    }

    const CFG: &str = r#"
zones:
  - name: demo
    hostnames: ["demo.local"]
    origin: { url: "http://127.0.0.1:9" }
"#;

    /// Drives a pipeline with a throwaway request and reports what came back.
    async fn run(stages: Vec<Box<dyn Stage>>) -> (Response<Body>, &'static str) {
        let cfg = config::parse(CFG).unwrap();
        let zone = &cfg.zones[0];
        let req = Request::builder().uri("/").body(full("")).unwrap();
        let mut ctx = Ctx::new(
            Caller {
                peer: "127.0.0.1:1234".parse().unwrap(),
                client: "127.0.0.1".parse().unwrap(),
                tls: false,
                geo: Default::default(),
            },
            "demo.local".into(),
            &cfg,
            zone,
            req,
            Instant::now(),
        );
        let resp = Pipeline::new(stages).run(&mut ctx).await;
        (resp, ctx.decided_by)
    }

    #[tokio::test]
    async fn responding_stage_short_circuits_the_rest() {
        let t = Trace::default();
        let (resp, decided) = run(vec![
            probe("first", &t, pass),
            probe("second", &t, answer),
            probe("never", &t, pass),
        ])
        .await;

        assert_eq!(resp.status(), 418);
        assert_eq!(decided, "second");
        /* filters unwind only over the stages that actually ran */
        assert_eq!(
            t.seen(),
            ["first:req", "second:req", "second:resp", "first:resp"]
        );
    }

    #[tokio::test]
    async fn stage_error_becomes_its_status() {
        let t = Trace::default();
        let (resp, decided) = run(vec![probe("boom", &t, fail)]).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(decided, "boom");
    }

    #[tokio::test]
    async fn falling_off_the_end_is_a_500() {
        let t = Trace::default();
        let (resp, _) = run(vec![probe("passes", &t, pass)]).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        /* the filter still runs - the response is real even if nobody claimed it */
        assert_eq!(t.seen(), ["passes:req", "passes:resp"]);
    }

    #[tokio::test]
    async fn every_entered_stage_filters_the_response() {
        let t = Trace::default();
        let (resp, _) = run(vec![probe("outer", &t, pass), probe("inner", &t, answer)]).await;
        assert_eq!(resp.headers().get_all("x-ran").iter().count(), 2);
    }
}
