//! The edge's own small admin API.
//!
//! Purge lives here rather than in the control plane because the cache is here - the
//! control plane can only ask. Deliberately hand-rolled rather than pulling a web
//! framework into the data plane for four endpoints.
//!
//! Every endpoint except `/admin/health` needs a bearer token, taken from the
//! environment rather than the config file - the config travels to other nodes and is
//! editable in the dashboard, which is no place for a secret. Bind it to loopback or
//! an interface only your control plane can reach as well; the token is the control,
//! the network boundary is the belt.
//!
//! `/metrics` lives here too, on the same listener, so it inherits that boundary: a
//! scrape endpoint on the traffic port would be reachable by everyone the proxy is
//! for. It is token-guarded like everything else, because Prometheus can hold a bearer
//! token and a scrape is a list of your zones, rule ids and traffic shape. Setting
//! `CLOUDVEIL_METRICS_OPEN=1` opens that one endpoint, for the case where the admin
//! listener is already on an interface only the monitoring network can reach.

use std::sync::Arc;
use std::time::Instant;

use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::auth::Guard;
use crate::body::{adapt, full, Body};
use crate::cache::Store;
use crate::snapshot::Snapshot;
use crate::Edge;

/// What to throw away. Exactly one of these should be set.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeRequest {
    /// A full url, e.g. `http://demo.local/page?a=1`.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub all: bool,
}

/// Where the admin token comes from. Not the config file - see `auth`.
pub const TOKEN_VAR: &str = "CLOUDVEIL_ADMIN_TOKEN";
/// Set to `1` to serve `/metrics` without a token. See the module note.
pub const METRICS_OPEN_VAR: &str = "CLOUDVEIL_METRICS_OPEN";

fn metrics_are_open() -> bool {
    matches!(std::env::var(METRICS_OPEN_VAR).as_deref(), Ok("1") | Ok("true"))
}

pub async fn serve(listener: TcpListener, edge: Arc<Edge>) -> anyhow::Result<()> {
    let started = Instant::now();
    /* fails rather than starting open: anything that can reach this port can empty
       your cache, and "keep it internal" is a document, not a control */
    let guard = Arc::new(Guard::from_env(TOKEN_VAR)?);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                debug!("admin accept failed: {e}");
                continue;
            }
        };
        let edge = edge.clone();
        let guard = guard.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let edge = edge.clone();
                let guard = guard.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(route(req, edge, guard, started).await)
                }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                debug!("{peer}: admin connection closed: {e}");
            }
        });
    }
}

async fn route(
    req: Request<hyper::body::Incoming>,
    edge: Arc<Edge>,
    guard: Arc<Guard>,
    started: Instant,
) -> Response<Body> {
    let path = req.uri().path().to_owned();

    /* health stays open so an orchestrator can probe it without holding a secret;
       it says nothing a port scan wouldn't already tell you */
    let open = path == "/admin/health" || (path == "/metrics" && metrics_are_open());
    if !open && !guard.allows(req.headers()) {
        return problem(StatusCode::UNAUTHORIZED, "a bearer token is required");
    }

    match (req.method(), path.as_str()) {
        (&Method::GET, "/admin/health") => ok(json!({
            "status": "ok",
            "uptime_s": started.elapsed().as_secs(),
        })),

        (&Method::GET, "/admin/stats") => {
            let cfg = edge.snap.current();
            let stats = edge.store.stats();
            let (seen, dropped) = edge.analytics.counts();
            ok(json!({
                "zones": cfg.zones.len(),
                "cache": { "entries": stats.entries, "bytes": stats.bytes },
                "events": { "seen": seen, "dropped": dropped },
                "uptime_s": started.elapsed().as_secs(),
            }))
        }

        (&Method::GET, "/admin/recent") => {
            let limit = query_limit(req.uri().query()).unwrap_or(100);
            ok(json!(edge.analytics.recent(limit)))
        }

        (&Method::GET, "/metrics") => metrics(&edge, started),

        (&Method::GET, "/admin/stream") => stream(&edge),

        (&Method::POST, "/admin/purge") => purge(req, &edge.store, &edge.snap).await,

        _ => problem(StatusCode::NOT_FOUND, "no such endpoint"),
    }
}

/// A Prometheus scrape.
///
/// Two kinds of number end up in one document: the counters the request path records
/// as it goes, and the values that are read off live state right here. Cache size,
/// uptime and the event counts are the second kind - mirroring them into the registry
/// would give them one more chance to be wrong, and they cost a mutex to read.
fn metrics(edge: &Edge, started: Instant) -> Response<Body> {
    use crate::metrics as m;

    let mut body = edge.metrics.render();

    let stats = edge.store.stats();
    m::gauge(
        &mut body,
        "cloudveil_cache_entries",
        "Responses currently held in the cache.",
        stats.entries as f64,
    );
    m::gauge(
        &mut body,
        "cloudveil_cache_bytes",
        "Bytes of cached response bodies and headers.",
        stats.bytes as f64,
    );

    let cfg = edge.snap.current();
    m::gauge(
        &mut body,
        "cloudveil_zones",
        "Zones in the config this node is serving.",
        cfg.zones.len() as f64,
    );
    m::gauge(
        &mut body,
        "cloudveil_uptime_seconds",
        "Seconds since this node's admin api came up.",
        started.elapsed().as_secs_f64(),
    );

    let (seen, dropped) = edge.analytics.counts();
    m::counter(
        &mut body,
        "cloudveil_events_recorded_total",
        "Request events recorded.",
        seen as f64,
    );
    m::counter(
        &mut body,
        "cloudveil_events_dropped_total",
        "Request events shed because the queue to the control plane was full.",
        dropped as f64,
    );
    m::counter(
        &mut body,
        "cloudveil_metrics_series_dropped_total",
        "Records dropped because a metric hit its series cap. Above zero means a \
         series is missing rather than idle.",
        edge.metrics.dropped_series() as f64,
    );
    m::labelled_gauge(
        &mut body,
        "cloudveil_build_info",
        "Always 1; the version is in the label.",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1.0,
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", m::CONTENT_TYPE)
        .body(full(body))
        .expect("metrics response is always valid")
}

/// Server-sent events, one request event per message.
///
/// A watcher that can't keep up misses events rather than slowing the edge down -
/// the broadcast channel drops the oldest and carries on.
fn stream(edge: &Edge) -> Response<Body> {
    use http_body_util::StreamBody;
    use hyper::body::{Bytes, Frame};
    use tokio_stream::wrappers::BroadcastStream;
    use tokio_stream::StreamExt;

    let events = BroadcastStream::new(edge.analytics.subscribe()).filter_map(|got| {
        let event = got.ok()?;
        let json = serde_json::to_string(&event).ok()?;
        Some(Ok::<_, crate::body::BodyError>(Frame::data(Bytes::from(
            format!("data: {json}\n\n"),
        ))))
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("connection", "keep-alive")
        .body(StreamBody::new(events).boxed())
        .expect("stream response is always valid")
}

async fn purge(
    req: Request<hyper::body::Incoming>,
    store: &Store,
    snap: &Snapshot,
) -> Response<Body> {
    let body = match adapt(req.into_body()).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => return problem(StatusCode::BAD_REQUEST, &format!("could not read body: {e}")),
    };

    let ask: PurgeRequest = match serde_json::from_slice(&body) {
        Ok(ask) => ask,
        Err(e) => return problem(StatusCode::BAD_REQUEST, &format!("bad json: {e}")),
    };

    let removed = match (&ask.url, &ask.tag, &ask.zone, ask.all) {
        (Some(url), None, None, false) => match purge_url(store, snap, url) {
            Ok(n) => n,
            Err(why) => return problem(StatusCode::BAD_REQUEST, &why),
        },
        (None, Some(tag), None, false) => store.purge_tag(tag),
        (None, None, Some(zone), false) => store.purge_zone(zone),
        (None, None, None, true) => store.purge_all(),
        _ => {
            return problem(
                StatusCode::BAD_REQUEST,
                "give exactly one of url, tag, zone or all",
            )
        }
    };

    info!("purge {ask:?} removed {removed} entries");
    ok(json!({ "removed": removed }))
}

/// A url purge has to rebuild the key the same way a request would, or it would only
/// ever match by luck.
fn purge_url(store: &Store, snap: &Snapshot, url: &str) -> Result<usize, String> {
    let uri: hyper::Uri = url.parse().map_err(|e| format!("bad url `{url}`: {e}"))?;
    let Some(host) = uri.host() else {
        return Err(format!("url `{url}` has no host"));
    };

    let cfg = snap.current();
    let Some(zone) = cfg.zone_for(host) else {
        return Err(format!("no zone serves `{host}`"));
    };

    let req = Request::builder()
        .uri(uri.clone())
        .body(full(""))
        .map_err(|e| format!("bad url `{url}`: {e}"))?;

    let key = crate::cache::policy::build_key(&zone.name, host, &req, &zone.cache);
    /* variants differ only by the vary part of the key, so drop all of them */
    Ok(store.purge_where(|k, _| {
        k.zone == key.zone && k.host == key.host && k.path == key.path && k.query == key.query
    }))
}

fn query_limit(query: Option<&str>) -> Option<usize> {
    query?
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == "limit")
        .and_then(|(_, v)| v.parse().ok())
}

fn ok(value: serde_json::Value) -> Response<Body> {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(full(body))
        .expect("json response is always valid")
}

fn problem(status: StatusCode, message: &str) -> Response<Body> {
    let body = serde_json::to_vec(&json!({ "error": message })).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full(body))
        .expect("json response is always valid")
}
