//! The edge's own small admin API.
//!
//! Purge lives here rather than in the control plane because the cache is here - the
//! control plane can only ask. Deliberately hand-rolled rather than pulling a web
//! framework into the data plane for four endpoints.
//!
//! Bind it to loopback, or to an interface only your control plane can reach. There
//! is no authentication: anything that can talk to this port can empty your cache.

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

pub async fn serve(listener: TcpListener, edge: Arc<Edge>) -> anyhow::Result<()> {
    let started = Instant::now();

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                debug!("admin accept failed: {e}");
                continue;
            }
        };
        let edge = edge.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let edge = edge.clone();
                async move { Ok::<_, std::convert::Infallible>(route(req, edge, started).await) }
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
    started: Instant,
) -> Response<Body> {
    let path = req.uri().path().to_owned();

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

        (&Method::GET, "/admin/stream") => stream(&edge),

        (&Method::POST, "/admin/purge") => purge(req, &edge.store, &edge.snap).await,

        _ => problem(StatusCode::NOT_FOUND, "no such endpoint"),
    }
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
