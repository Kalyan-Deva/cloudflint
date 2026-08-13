//! Talking to the origin.
//!
//! `Fetcher` is the bit that does it, shared rather than owned by the stage, because
//! the cache needs to make origin requests of its own for background revalidation.
//! `Origin` is the terminal stage: it always answers, one way or another.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{header, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tracing::{debug, warn};

use crate::body::{adapt, full, with_read_timeout, Body};
use crate::compress;
use crate::config;
use crate::metrics::Metrics;
use crate::origins::Health;
use crate::pipeline::{Ctx, Stage, StageError, Verdict};

pub type HttpClient = Client<HttpConnector, Body>;

/// Single-hop headers that must never be forwarded (RFC 9110 7.6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Where a request is going, and what to do with what comes back. These four are read
/// off one zone and are always used together; as loose arguments they were four chances
/// to pass a zone's name with another zone's pool.
pub struct Upstream<'a> {
    pub zone: &'a str,
    pub pool: &'a config::OriginPool,
    /// The Host the client asked for, which the origin may or may not see - see
    /// `preserve_host`.
    pub host: &'a str,
    pub compression: &'a compress::Policy,
}

pub struct Fetcher {
    client: HttpClient,
    /// Optional so a `Fetcher` can be built in a test without a registry.
    metrics: Option<Arc<Metrics>>,
    /// Also optional: with no registry there is nothing to fail over to either, since a
    /// bare `Fetcher` is only used with a pool of one.
    health: Option<Arc<Health>>,
}

impl Fetcher {
    pub fn new() -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            metrics: None,
            health: None,
        }
    }

    pub fn metered(metrics: Arc<Metrics>, health: Arc<Health>) -> Self {
        Self {
            metrics: Some(metrics),
            health: Some(health),
            ..Self::new()
        }
    }

    /// Every origin request goes through here - the cache's background revalidations as
    /// well as the terminal stage's - which makes it the only place that sees all of
    /// them, and so the only sensible place to judge whether a backend is alive.
    ///
    /// Tries the pool in health order. A backend that refuses the connection is worth
    /// stepping over immediately; one that *times out* is not, because it may well be
    /// doing the work, and a client already waiting the full timeout should not be made
    /// to wait for a second one.
    pub async fn fetch(
        &self,
        to: Upstream<'_>,
        peer: SocketAddr,
        tls: bool,
        req: Request<Body>,
    ) -> Result<Response<Body>, StageError> {
        let Upstream {
            zone,
            pool,
            host,
            compression,
        } = to;

        let candidates = match &self.health {
            Some(health) => health.candidates(zone, pool),
            None => (0..pool.origins.len()).collect(),
        };

        /* captured before the first attempt, because sending consumes the request */
        let replay = replayable(&req);
        /* likewise: the request is gone by the time there is a response to compress */
        let accept = req
            .headers()
            .get(hyper::header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let mut req = Some(req);
        let mut last: Option<StageError> = None;

        for (attempt, &index) in candidates.iter().enumerate() {
            let origin = &pool.origins[index];
            let Some(sending) = req.take().or_else(|| replay.as_ref().map(rebuild)) else {
                /* nothing safe to send twice - the failure stands, and the health note
                   already recorded means the *next* request goes elsewhere */
                break;
            };

            let started = Instant::now();
            /* counted for exactly as long as the request is out, which is what
               least_connections sorts on. A guard rather than two calls, so an early
               return cannot leak a count and strand a backend at the bottom of the
               order forever */
            let counted = self.health.as_ref().map(|h| InFlight::new(h, zone, origin));
            let out = self.send(origin, host, peer, tls, sending).await;
            drop(counted);
            let kind = kind_of(&out);

            let authority = origin.authority.as_str();
            if let Some(metrics) = &self.metrics {
                metrics.origin_call(zone, authority, started.elapsed(), kind);
            }
            if attempt > 0 {
                if let Some(metrics) = &self.metrics {
                    metrics.failover(zone);
                }
                if let Some(health) = &self.health {
                    let from = pool.origins[candidates[attempt - 1]].authority.as_str();
                    health.note_failover(zone, from, authority);
                }
            }
            if let Some(health) = &self.health {
                match kind {
                    None => health.record_success(zone, origin, pool.healthy_after()),
                    Some(_) => health.record_failure(zone, origin, pool),
                }
                if let Some(metrics) = &self.metrics {
                    metrics.origin_health(zone, authority, health.is_healthy(zone, origin));
                }
            }

            match out {
                Ok(resp) => {
                    /* here rather than on the way out to the client: the cache stores
                       what this returns, so each variant is compressed once however
                       often it is served. See `compress` */
                    let (resp, saved) = compress::apply(&accept, resp, compression).await;
                    if let (Some(metrics), Some(saved)) = (&self.metrics, saved) {
                        metrics.compressed(zone, saved.coding.as_str(), saved.before, saved.after);
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    /* a timeout is terminal: see the note above */
                    if kind != Some("unreachable") {
                        return Err(e);
                    }
                    if candidates.len() > 1 && attempt + 1 < candidates.len() {
                        warn!(
                            "zone {zone}: origin {} unreachable, trying the next one",
                            origin.authority
                        );
                    }
                    last = Some(e);
                }
            }
        }

        Err(last.unwrap_or_else(|| {
            StageError::new(
                StatusCode::BAD_GATEWAY,
                "502 no origin could be reached".to_string(),
            )
        }))
    }

    /// One request to one origin, with no pool, no health and no retry. The prober uses
    /// this: a health check that failed over would never find anything unhealthy.
    pub async fn send_direct(
        &self,
        origin: &config::Origin,
        host: &str,
        req: Request<Body>,
    ) -> Result<Response<Body>, StageError> {
        /* the probe is not forwarding anyone's request, so there is no peer to record */
        let nowhere: SocketAddr = ([127, 0, 0, 1], 0).into();
        self.send(origin, host, nowhere, false, req).await
    }

    async fn send(
        &self,
        origin: &config::Origin,
        host: &str,
        peer: SocketAddr,
        tls: bool,
        req: Request<Body>,
    ) -> Result<Response<Body>, StageError> {
        /* an upgrade request needs the very headers that are otherwise single-hop:
           Connection, Upgrade and the websocket key all have to reach the origin */
        let mut req = req;
        let upgrading = is_upgrade(req.headers());
        let client_upgrade = upgrading.then(|| hyper::upgrade::on(&mut req));

        let (mut parts, body) = req.into_parts();
        if !upgrading {
            strip_hop_by_hop(&mut parts.headers);
        }

        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_else(|| "/".into());

        parts.uri = Uri::builder()
            .scheme(origin.scheme.clone())
            .authority(origin.authority.clone())
            .path_and_query(path_and_query)
            .build()
            .map_err(|e| {
                StageError::new(StatusCode::BAD_REQUEST, format!("400 bad request target: {e}"))
            })?;

        /* the client may have arrived over h2, but we speak http/1.1 to origins.
           leaving the version alone makes the origin client reject its own request */
        parts.version = hyper::Version::HTTP_11;

        set_forwarded(&mut parts.headers, host, peer, tls);
        if !origin.preserve_host {
            /* dropping it lets hyper fill Host in from the origin authority */
            parts.headers.remove(header::HOST);
        }

        let sent = self.client.request(Request::from_parts(parts, body));
        match tokio::time::timeout(origin.timeout, sent).await {
            Ok(Ok(mut resp)) => {
                if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                    /* take the origin's upgrade before the response is torn apart */
                    let origin_upgrade = hyper::upgrade::on(&mut resp);
                    let (parts, _) = resp.into_parts();
                    if let Some(client_upgrade) = client_upgrade {
                        tokio::spawn(splice(client_upgrade, origin_upgrade));
                    }
                    /* the 101 goes back with the origin's headers untouched; hyper
                       upgrades our side once it has been written */
                    return Ok(Response::from_parts(parts, full("")));
                }
                /* the same clock on the way back: a stalled origin should not be
                   able to hold our connection to the client open indefinitely */
                let mut resp =
                    resp.map(|b| with_read_timeout(adapt(b), origin.timeout));
                strip_hop_by_hop(resp.headers_mut());
                Ok(resp)
            }
            Ok(Err(e)) => Err(StageError::new(
                StatusCode::BAD_GATEWAY,
                format!("502 origin unreachable: {e}"),
            )),
            Err(_) => Err(StageError::new(
                StatusCode::GATEWAY_TIMEOUT,
                format!("504 origin timed out after {:?}", origin.timeout),
            )),
        }
    }
}

impl Default for Fetcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a fetch failed, or None if it didn't. A 5xx the origin chose to send is not an
/// error here - it arrived, and it is already counted by status in `requests_total`.
fn kind_of(out: &Result<Response<Body>, StageError>) -> Option<&'static str> {
    match out {
        Ok(_) => None,
        Err(e) if e.status == StatusCode::GATEWAY_TIMEOUT => Some("timeout"),
        Err(_) => Some("unreachable"),
    }
}

/// Holds an origin's in-flight count for the life of one request.
///
/// The count only decrements when this is dropped, so a cancelled request - a client that
/// goes away mid-flight - releases it too. A pair of increment/decrement calls would not:
/// dropping a future runs destructors, it does not run the rest of the function.
struct InFlight<'a> {
    health: &'a Health,
    zone: &'a str,
    origin: &'a config::Origin,
}

impl<'a> InFlight<'a> {
    fn new(health: &'a Health, zone: &'a str, origin: &'a config::Origin) -> Self {
        health.started(zone, origin);
        InFlight {
            health,
            zone,
            origin,
        }
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.health.finished(self.zone, self.origin);
    }
}

/// Everything needed to send the same request again somewhere else.
struct Head {
    method: hyper::Method,
    uri: Uri,
    version: hyper::Version,
    headers: HeaderMap,
}

/// Whether this request could be sent to a second origin at all.
///
/// Two hurdles, and both matter. **Idempotence**: replaying a POST that may already have
/// been received would charge somebody's card twice, so only methods defined as
/// idempotent qualify. **A body we still have**: our bodies are streams, and once one
/// has been read towards the first origin it is gone - so only a request with no body can
/// be repeated. That is nearly all traffic a failover is for, and refusing to guess about
/// the rest is the honest limit rather than a gap. An upgrade is excluded outright: the
/// whole point of it is the connection it happens on.
fn replayable(req: &Request<Body>) -> Option<Head> {
    /* for size_hint, which is on the Body trait rather than the extension trait */
    use hyper::body::Body as _;
    use hyper::Method;

    let idempotent = matches!(
        *req.method(),
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    );
    let bodyless = req.body().size_hint().exact() == Some(0);

    (idempotent && bodyless && !is_upgrade(req.headers())).then(|| Head {
        method: req.method().clone(),
        uri: req.uri().clone(),
        version: req.version(),
        headers: req.headers().clone(),
    })
}

fn rebuild(head: &Head) -> Request<Body> {
    /* http::request::Parts is not Clone and has no public constructor, so borrow one
       from a throwaway request and fill it in */
    let (mut parts, _) = Request::new(()).into_parts();
    parts.method = head.method.clone();
    parts.uri = head.uri.clone();
    parts.version = head.version;
    parts.headers = head.headers.clone();
    Request::from_parts(parts, full(""))
}

pub struct Origin {
    fetcher: Arc<Fetcher>,
}

impl Origin {
    pub fn new(fetcher: Arc<Fetcher>) -> Self {
        Self { fetcher }
    }
}

#[async_trait]
impl Stage for Origin {
    fn name(&self) -> &'static str {
        "origin"
    }

    async fn on_request(&self, ctx: &mut Ctx<'_>) -> Result<Verdict, StageError> {
        let Some(req) = ctx.take_req() else {
            return Err(StageError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "500 request was already consumed",
            ));
        };
        let resp = self
            .fetcher
            .fetch(
                Upstream {
                    zone: &ctx.zone.name,
                    pool: &ctx.zone.origins,
                    host: &ctx.host,
                    compression: &ctx.zone.compression,
                },
                ctx.peer,
                ctx.tls,
                req,
            )
            .await?;
        Ok(Verdict::Respond(resp))
    }
}

pub fn is_upgrade(headers: &HeaderMap) -> bool {
    let names_upgrade = header_str(headers, header::CONNECTION)
        .unwrap_or("")
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    names_upgrade && headers.contains_key(header::UPGRADE)
}

/// Once both sides have switched protocols, get out of the way and copy bytes.
///
/// From here it isn't HTTP any more, so there is nothing left for a proxy to inspect
/// or cache - websockets, and anything else built on Upgrade, just flow through.
async fn splice(client: hyper::upgrade::OnUpgrade, origin: hyper::upgrade::OnUpgrade) {
    let (client, origin) = match tokio::try_join!(client, origin) {
        Ok(pair) => pair,
        Err(e) => {
            debug!("upgrade never completed: {e}");
            return;
        }
    };

    let mut client = TokioIo::new(client);
    let mut origin = TokioIo::new(origin);
    match tokio::io::copy_bidirectional(&mut client, &mut origin).await {
        Ok((up, down)) => debug!("upgraded connection closed, {up} up / {down} down"),
        Err(e) => debug!("upgraded connection ended: {e}"),
    }
}

fn set_forwarded(headers: &mut HeaderMap, host: &str, peer: SocketAddr, tls: bool) {
    let chain = match header_str(headers, "x-forwarded-for") {
        Some(prev) => format!("{prev}, {}", peer.ip()),
        None => peer.ip().to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&chain) {
        headers.insert("x-forwarded-for", v);
    }
    if let Ok(v) = HeaderValue::from_str(host) {
        headers.insert("x-forwarded-host", v);
    }
    headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_static(if tls { "https" } else { "http" }),
    );
}

pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    /* Connection names further headers that are also single-hop, so read it first */
    let named: Vec<HeaderName> = header_str(headers, header::CONNECTION)
        .unwrap_or("")
        .split(',')
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();

    for name in named {
        headers.remove(&name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

fn header_str<K: header::AsHeaderName>(headers: &HeaderMap, key: K) -> Option<&str> {
    headers.get(key).and_then(|v| v.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn strips_standard_hop_by_hop() {
        let mut h = headers(&[
            ("connection", "close"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("accept", "text/html"),
        ]);
        strip_hop_by_hop(&mut h);
        assert!(h.get("connection").is_none());
        assert!(h.get("keep-alive").is_none());
        assert!(h.get("transfer-encoding").is_none());
        assert_eq!(h.get("accept").unwrap(), "text/html");
    }

    #[test]
    fn strips_headers_named_by_connection() {
        let mut h = headers(&[
            ("connection", "x-hop-one, x-hop-two"),
            ("x-hop-one", "a"),
            ("x-hop-two", "b"),
            ("x-keep", "c"),
        ]);
        strip_hop_by_hop(&mut h);
        assert!(h.get("x-hop-one").is_none());
        assert!(h.get("x-hop-two").is_none());
        assert_eq!(h.get("x-keep").unwrap(), "c");
    }

    #[test]
    fn appends_to_existing_forwarded_for() {
        let peer: SocketAddr = "203.0.113.9:44321".parse().unwrap();
        let mut h = headers(&[("x-forwarded-for", "198.51.100.1")]);
        set_forwarded(&mut h, "demo.local", peer, false);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "198.51.100.1, 203.0.113.9");
        assert_eq!(h.get("x-forwarded-host").unwrap(), "demo.local");
    }

    #[test]
    fn starts_forwarded_for_when_absent() {
        let peer: SocketAddr = "203.0.113.9:44321".parse().unwrap();
        let mut h = HeaderMap::new();
        set_forwarded(&mut h, "demo.local", peer, false);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "203.0.113.9");
    }
}
