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

    /* deliberately without a shutdown arm: this listener stays up for the whole drain
       so an orchestrator can keep reading /admin/health and see the node say it is
       going away. The process exiting is what closes it. */
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
        /* unhealthy the instant a shutdown starts, and before any listener closes: a
           load balancer has to be told to stop sending work *first*, or it keeps
           aiming requests at a node that is on its way out */
        (&Method::GET, "/admin/health") => {
            let draining = edge.shutdown.draining();
            let body = json!({
                "status": if draining { "draining" } else { "ok" },
                "uptime_s": started.elapsed().as_secs(),
            });
            match draining {
                false => ok(body),
                true => json_with(StatusCode::SERVICE_UNAVAILABLE, body),
            }
        }

        (&Method::GET, "/admin/stats") => {
            let cfg = edge.snap.current();
            let stats = edge.store.stats();
            let (seen, dropped) = edge.analytics.counts();

            /* per origin, because "the zone is fine" is not the same as "everything
               behind it is", and a backup quietly carrying all the traffic is exactly
               what somebody would want to notice */
            let origins: Vec<_> = cfg
                .zones
                .iter()
                .map(|z| {
                    let backends: Vec<_> = edge
                        .origins
                        .report(&z.name, &z.origins)
                        .into_iter()
                        .map(|(origin, healthy)| json!({ "origin": origin, "healthy": healthy }))
                        .collect();
                    json!({ "zone": z.name, "origins": backends })
                })
                .collect();

            ok(json!({
                "zones": cfg.zones.len(),
                "origins": origins,
                "cache": { "entries": stats.entries, "bytes": stats.bytes },
                "events": { "seen": seen, "dropped": dropped },
                "uptime_s": started.elapsed().as_secs(),
            }))
        }

        (&Method::GET, "/admin/recent") => {
            let limit = query_limit(req.uri().query()).unwrap_or(100);
            ok(json!(edge.analytics.recent(limit)))
        }

        (&Method::GET, "/admin/origins") => ok(origins(&edge)),

        (&Method::GET, "/admin/certificates") => ok(certificates(&edge)),

        (&Method::GET, "/metrics") => metrics(&edge, started),

        (&Method::GET, "/admin/stream") => stream(&edge),

        (&Method::POST, "/admin/purge") => purge(req, &edge.store, &edge.snap).await,

        _ => problem(StatusCode::NOT_FOUND, "no such endpoint"),
    }
}

/// Certificates: the ones we present to clients, and how we talk to origins.
///
/// Reported from the certificates actually **loaded and serving**, not from what config
/// asks for. Those differ exactly when something is wrong, which is when somebody looks.
fn certificates(edge: &Edge) -> serde_json::Value {
    let cfg = edge.snap.current();
    let live = edge.tls.as_ref().map(|t| t.report()).unwrap_or_default();

    let zones: Vec<_> = cfg
        .zones
        .iter()
        .map(|zone| {
            let cert = live.iter().find(|c| c.zone == zone.name);
            let origin_tls = &zone.origin_tls;
            let https_origin = zone
                .origins
                .origins
                .iter()
                .any(|o| o.scheme == hyper::http::uri::Scheme::HTTPS);

            json!({
                "zone": zone.name,
                "hostnames": zone.hostnames,
                /* manual until acme lands; the field exists so the answer has a place
                   to change rather than a shape to change */
                "mode": match zone.tls.is_some() {
                    true => "manual",
                    false => "off",
                },
                "configured": zone.tls.as_ref().map(|t| t.cert.display().to_string()),
                /* the load-bearing one: config naming a certificate is not the same as
                   that certificate being the one in use */
                "deployed": cert.is_some(),
                "status": cert.map(|c| c.status()).unwrap_or(match zone.tls.is_some() {
                    true => "not_loaded",
                    false => "none",
                }),
                "subject": cert.map(|c| c.subject.clone()),
                "issuer": cert.map(|c| c.issuer.clone()),
                "self_signed": cert.map(|c| c.self_signed),
                "dns_names": cert.map(|c| c.dns_names.clone()).unwrap_or_default(),
                "not_before_ms": cert.map(|c| c.not_before_ms),
                "not_after_ms": cert.map(|c| c.not_after_ms),
                "days_left": cert.map(|c| c.days_left()),
                /* nothing renews these yet, and saying so is better than an empty field
                   somebody reads as "soon" */
                "renews_at_ms": serde_json::Value::Null,
                "renewal": "manual",
                "origin": {
                    "https": https_origin,
                    "verify": origin_tls.verify,
                    "ca": origin_tls.ca.as_ref().map(|p| p.display().to_string()),
                    "mtls": origin_tls.client_cert.is_some(),
                    "mode": match (https_origin, origin_tls.verify, origin_tls.client_cert.is_some()) {
                        (false, _, _) => "plaintext",
                        (true, false, _) => "encrypted, not verified",
                        (true, true, false) => "verified",
                        (true, true, true) => "verified, mutual",
                    },
                },
            })
        })
        .collect();

    json!({
        "listener": cfg.tls.as_ref().map(|t| json!({
            "listen": t.listen.to_string(),
            "redirect_http": t.redirect_http,
        })),
        "zones": zones,
    })
}

/// Everything known about each zone's backends, for the dashboard.
///
/// Read out of the metrics registry rather than kept a second time: the counters the
/// request path already writes are the same numbers a person wants to see, and a parallel
/// set of them would eventually disagree. Latency is a bucket estimate, good enough for
/// "about 3ms" and not pretending to be more.
fn origins(edge: &Edge) -> serde_json::Value {
    let cfg = edge.snap.current();
    let m = &edge.metrics;

    let zones: Vec<_> = cfg
        .zones
        .iter()
        .map(|zone| {
            let name = zone.name.as_str();
            let counts: Vec<u64> = zone
                .origins
                .origins
                .iter()
                .map(|o| m.origin_requests.get(&[name, o.authority.as_str()]))
                .collect();
            let total: u64 = counts.iter().sum();

            let backends: Vec<_> = zone
                .origins
                .origins
                .iter()
                .zip(&counts)
                .map(|(o, requests)| {
                    let authority = o.authority.as_str();
                    let errors: u64 = ["unreachable", "timeout"]
                        .iter()
                        .map(|kind| m.origin_errors.get(&[name, authority, kind]))
                        .sum();
                    let latency = |q: f64| {
                        m.origin_duration
                            .quantile(&[name, authority], q)
                            .map(|s| (s * 1000.0 * 100.0).round() / 100.0)
                    };

                    json!({
                        "origin": format!("{}://{}", o.scheme, authority),
                        "authority": authority,
                        "healthy": edge.origins.is_healthy(name, o),
                        "weight": o.weight,
                        "in_flight": edge.origins.in_flight(name, o),
                        "requests": requests,
                        "errors": errors,
                        /* of the traffic this node sent to the zone, not of all of it */
                        "traffic_share": match total {
                            0 => 0.0,
                            total => (*requests as f64 / total as f64 * 1000.0).round() / 10.0,
                        },
                        "error_rate": match requests {
                            0 => 0.0,
                            n => (errors as f64 / *n as f64 * 1000.0).round() / 10.0,
                        },
                        "p50_ms": latency(0.5),
                        "p95_ms": latency(0.95),
                        "probes_ok": m.origin_probes.get(&[name, authority, "ok"]),
                        "probes_failed": m.origin_probes.get(&[name, authority, "failed"]),
                    })
                })
                .collect();

            json!({
                "zone": name,
                "strategy": zone.origins.strategy.as_str(),
                "probe": zone.origins.probe.as_ref().map(|p| json!({
                    "path": p.path,
                    "every_secs": p.every.as_secs(),
                })),
                "unhealthy_after": zone.origins.unhealthy_after,
                "retry_after_secs": zone.origins.retry_after.as_secs(),
                "requests": total,
                "failovers": m.origin_failovers.get(&[name]),
                "origins": backends,
            })
        })
        .collect();

    json!({ "zones": zones, "recent_failovers": edge.origins.failovers() })
}

/// A Prometheus scrape.
///
/// Two kinds of number end up in one document: the counters the request path records
/// as it goes, and the values that are read off live state right here. Cache size,
/// uptime and the event counts are the second kind - mirroring them into the registry
/// would give them one more chance to be wrong, and they cost a mutex to read.
fn metrics(edge: &Edge, started: Instant) -> Response<Body> {
    use crate::metrics as m;

    let cfg = edge.snap.current();

    /* before the render, not after: an origin that has been quietly healthy since boot
       has never called `origin_health`, and a gauge that only appears once something has
       gone wrong is a gauge nobody can alert on */
    for zone in &cfg.zones {
        for (origin, healthy) in edge.origins.report(&zone.name, &zone.origins) {
            edge.metrics.origin_health(&zone.name, &origin, healthy);
        }
    }

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
    m::gauge(
        &mut body,
        "cloudveil_draining",
        "1 while this node is shutting down and finishing its live connections.",
        match edge.shutdown.draining() {
            true => 1.0,
            false => 0.0,
        },
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
    json_with(StatusCode::OK, value)
}

fn json_with(status: StatusCode, value: serde_json::Value) -> Response<Body> {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
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
