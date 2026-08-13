//! Front door. Works out which zone a request belongs to, hands it to the pipeline,
//! tidies up whatever comes back, and records what happened.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{header, Request, Response, StatusCode};
use tracing::info;

use crate::analytics::{now_ms, Event};
use crate::body::{adapt, text, with_read_timeout, Body};
use crate::config::Config;
use crate::pipeline::{Caller, Ctx};
use crate::stages::origin::strip_hop_by_hop;
use crate::Edge;

/// Header the cache stage labels its decision with.
const CACHE_HEADER: &str = "cloudflint-cache";

struct Outcome {
    resp: Response<Body>,
    decided_by: &'static str,
    /// Empty when the request never matched a zone.
    zone: String,
    /// The peer, unless a trusted proxy told us otherwise - see `client_ip`.
    client: IpAddr,
}

pub async fn handle(
    req: Request<Incoming>,
    edge: Arc<Edge>,
    peer: SocketAddr,
    tls: bool,
) -> Result<Response<Body>, Infallible> {
    let started = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let host = host_of(&req).unwrap_or_default();

    /* one atomic load, then this request works off a config that cannot change
       underneath it even if a reload lands mid-flight */
    let cfg = edge.snap.current();

    let mut outcome = route(req, &cfg, &edge, peer, started, tls).await;
    finalize(&mut outcome.resp);

    let took = started.elapsed();
    let status = outcome.resp.status();
    let cache = outcome
        .resp
        .headers()
        .get(CACHE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    /* metrics and the event are recorded from the same three facts, so a graph and
       the log can't tell different stories about one request */
    edge.metrics.request(
        &outcome.zone,
        status.as_u16(),
        outcome.decided_by,
        took,
        cache.as_deref(),
    );

    edge.analytics.record(Event {
        at_ms: now_ms(),
        zone: outcome.zone,
        host,
        method: method.to_string(),
        path: path.clone(),
        status: status.as_u16(),
        duration_us: took.as_micros() as u64,
        decided_by: outcome.decided_by.to_string(),
        cache,
        client_ip: outcome.client.to_string(),
    });

    /* the client first, since that is the one somebody will search for; the peer only
       when it is a different address, which is the sign a proxy is in front of us */
    let via = match outcome.client == peer.ip() {
        true => String::new(),
        false => format!(" via {}", peer.ip()),
    };
    info!(
        "{}{via} {method} {path} -> {status} [{}] in {took:?}",
        outcome.client, outcome.decided_by
    );
    Ok(outcome.resp)
}

/// HTTP/2 puts the authority on the uri, HTTP/1.1 in the Host header.
fn host_of(req: &Request<Incoming>) -> Option<String> {
    req.uri().host().map(str::to_owned).or_else(|| {
        req.headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    })
}

async fn route(
    req: Request<Incoming>,
    cfg: &Config,
    edge: &Edge,
    peer: SocketAddr,
    started: Instant,
    tls: bool,
) -> Outcome {
    /* resolved once, before anything else, so every stage answers "who is this?" the
       same way - and so a request that never finds a zone is still attributed to
       somebody. Who to trust is node-wide config, not the zone's, so it is knowable
       this early */
    let client = cfg.client_ip.resolve(peer, req.headers());
    /* and the same question about the scheme: our leg may be plaintext because
       something in front terminated TLS, which is not the same as the client not
       using it. `ssl` rules and the forwarded-proto we pass on both mean the client */
    let tls = cfg.client_ip.resolve_tls(peer, req.headers(), tls);

    let Some(host) = host_of(&req) else {
        return Outcome {
            resp: text(StatusCode::BAD_REQUEST, "400 missing host"),
            decided_by: "route",
            zone: String::new(),
            client,
        };
    };
    let Some(zone) = cfg.zone_for(&host) else {
        return Outcome {
            resp: text(StatusCode::NOT_FOUND, "404 no zone configured for this host"),
            decided_by: "route",
            zone: String::new(),
            client,
        };
    };

    /* the clock is per frame, so a big honest upload is fine while a sender that
       goes quiet mid-request is not */
    let (parts, body) = req.into_parts();
    let body = with_read_timeout(adapt(body), edge.node.body_read_timeout);

    let mut ctx = Ctx::new(
        Caller { peer, client, tls },
        host,
        cfg,
        zone,
        Request::from_parts(parts, body),
        started,
    );
    let resp = edge.pipeline.run(&mut ctx).await;

    Outcome {
        resp,
        decided_by: ctx.decided_by,
        zone: zone.name.clone(),
        client,
    }
}

/// Applies to every response, whoever produced it.
fn finalize(resp: &mut Response<Body>) {
    /* a 101 is the one response whose hop-by-hop headers are the whole point:
       Connection and Upgrade are what tell the client the switch happened */
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        strip_hop_by_hop(resp.headers_mut());
    }
    resp.headers_mut()
        .insert(header::SERVER, HeaderValue::from_static("cloudflint"));
}
