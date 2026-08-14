//! WAF stage. Runs head rules first, and only buffers the body if some rule
//! actually asks for it - a request blocked on its user agent never costs a read.

use std::sync::Arc;

use async_trait::async_trait;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use tracing::{info, warn};

use crate::body::{full, prefixed, Body};
use crate::config::{OnOversized, WafPolicy};
use crate::metrics::Metrics;
use crate::pages;
use crate::pipeline::{Ctx, Stage, StageError, Verdict};
use crate::waf::{Decoded, Match, Outcome, Phase};

pub struct Waf {
    metrics: Arc<Metrics>,
}

impl Waf {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }
}

#[async_trait]
impl Stage for Waf {
    fn name(&self) -> &'static str {
        "waf"
    }

    async fn on_request(&self, ctx: &mut Ctx<'_>) -> Result<Verdict, StageError> {
        let policy = &ctx.zone.waf;
        if policy.rules.is_empty() {
            return Ok(Verdict::Continue);
        }

        let mut log = Vec::new();
        match scan(ctx, "", Phase::Head, &mut log)? {
            Outcome::Block(hit) => {
                self.report(ctx, &log);
                return Ok(Verdict::Respond(self.blocked(ctx, &hit)));
            }
            /* a skip rule wins outright - don't even read the body */
            Outcome::Skip(hit) => {
                info!("{}: rule {} skipped the waf", ctx.host, hit.rule);
                self.count(ctx, &hit, "skip");
                self.report(ctx, &log);
                return Ok(Verdict::Continue);
            }
            Outcome::Allow => {}
        }

        if policy.rules.needs_body() {
            let body = buffer_body(ctx, policy).await?;
            if let Some(verdict) = self.check_body(ctx, policy, &body, &mut log)? {
                return Ok(verdict);
            }
        }

        self.report(ctx, &log);
        Ok(Verdict::Continue)
    }
}

impl Waf {
    /// Second pass, over the buffered body. Split out so the borrow of `body` stays
    /// clear of the mutation `buffer_body` needs.
    fn check_body(
        &self,
        ctx: &mut Ctx<'_>,
        policy: &WafPolicy,
        body: &Buffered,
        log: &mut Vec<Match>,
    ) -> Result<Option<Verdict>, StageError> {
        if body.truncated && policy.on_oversized_body == OnOversized::Block {
            warn!(
                "{}: body over {} bytes and on_oversized_body is block",
                ctx.host, policy.max_body_bytes
            );
            let hit = Match {
                rule: "body-too-large-to-inspect".into(),
                action: crate::waf::Action::Block,
                severity: crate::waf::Severity::Medium,
            };
            self.report(ctx, log);
            return Ok(Some(Verdict::Respond(self.blocked(ctx, &hit))));
        }
        if body.truncated {
            warn!(
                "{}: only the first {} bytes of the body were inspected",
                ctx.host, policy.max_body_bytes
            );
        }

        let text = String::from_utf8_lossy(body.inspectable(policy.max_body_bytes)).into_owned();
        match scan(ctx, &text, Phase::Body, log)? {
            Outcome::Block(hit) => {
                self.report(ctx, log);
                Ok(Some(Verdict::Respond(self.blocked(ctx, &hit))))
            }
            Outcome::Skip(_) | Outcome::Allow => Ok(None),
        }
    }
}

/// Build the view the rules see and run them.
fn scan(
    ctx: &Ctx<'_>,
    body: &str,
    phase: Phase,
    log: &mut Vec<Match>,
) -> Result<Outcome, StageError> {
    let Some(req) = ctx.req() else {
        return Err(StageError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "500 request went missing before the waf could read it",
        ));
    };
    /* ctx.client, which is the peer unless a *trusted* proxy said otherwise. Reading
       X-Forwarded-For from anyone would let a client pick its own `ip.src` */
    let decoded = Decoded::new(req, &ctx.host, ctx.client, ctx.tls, &ctx.geo);
    Ok(ctx.zone.waf.rules.evaluate(&decoded.input(body), phase, log))
}

struct Buffered {
    /// Everything we consumed. May run past the cap by up to one frame, because a
    /// frame arrives whole and we still have to forward every byte of it.
    bytes: Bytes,
    truncated: bool,
}

impl Buffered {
    fn inspectable(&self, cap: usize) -> &[u8] {
        &self.bytes[..self.bytes.len().min(cap)]
    }
}

/// Read the body far enough to inspect it, then put it back so the origin still
/// gets the whole thing.
async fn buffer_body(ctx: &mut Ctx<'_>, policy: &WafPolicy) -> Result<Buffered, StageError> {
    let Some(req) = ctx.take_req() else {
        return Err(StageError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "500 request went missing before the waf could read it",
        ));
    };
    let (parts, mut body) = req.into_parts();

    let mut buf: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| {
            StageError::new(StatusCode::BAD_REQUEST, format!("400 could not read body: {e}"))
        })?;
        if let Ok(data) = frame.into_data() {
            buf.extend_from_slice(&data);
            if buf.len() >= policy.max_body_bytes {
                truncated = true;
                break;
            }
        }
    }

    let bytes = Bytes::from(buf);
    /* cheap clone - Bytes is refcounted, so putting the body back doesn't copy it */
    let restored = if truncated {
        prefixed(bytes.clone(), body)
    } else {
        full(bytes.clone())
    };
    ctx.set_req(Request::from_parts(parts, restored));

    Ok(Buffered { bytes, truncated })
}

impl Waf {
    fn report(&self, ctx: &Ctx<'_>, log: &[Match]) {
        for hit in log {
            info!(
                "waf log {} severity={} {} {} {}",
                hit.rule,
                hit.severity,
                ctx.client,
                ctx.host,
                ctx.req().map(|r| r.uri().path()).unwrap_or("-")
            );
            self.count(ctx, hit, "log");
        }
    }

    fn blocked(&self, ctx: &Ctx<'_>, hit: &Match) -> Response<Body> {
        warn!(
            "waf block {} severity={} {} {} {}",
            hit.rule,
            hit.severity,
            ctx.client,
            ctx.host,
            ctx.req().map(|r| r.uri().path()).unwrap_or("-")
        );
        self.count(ctx, hit, "block");

        pages::blocked()
    }

    /// Every match, whatever the rule did with it. A rule in dry-run is the case that
    /// most wants a graph: you turn it on to find out how often it would have fired.
    fn count(&self, ctx: &Ctx<'_>, hit: &Match, action: &str) {
        self.metrics.waf_match(
            &ctx.zone.name,
            &hit.rule,
            &hit.severity.to_string(),
            action,
        );
    }
}
