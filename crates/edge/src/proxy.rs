//! Front door. Works out which zone a request belongs to, hands it to the pipeline,
//! and tidies up whatever comes back.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{header, Request, Response, StatusCode};
use tracing::info;

use crate::body::{text, Body};
use crate::config::Config;
use crate::pipeline::{Ctx, Pipeline};
use crate::snapshot::Snapshot;
use crate::stages::origin::strip_hop_by_hop;

pub async fn handle(
    req: Request<Incoming>,
    snap: Arc<Snapshot>,
    pipeline: Arc<Pipeline>,
    peer: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    let started = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    /* one atomic load, then this request works off a config that cannot change
       underneath it even if a reload lands mid-flight */
    let cfg = snap.current();

    let (mut resp, decided_by) = route(req, &cfg, &pipeline, peer, started).await;
    finalize(&mut resp);

    info!(
        "{peer} {method} {path} -> {} [{decided_by}] in {:?}",
        resp.status(),
        started.elapsed()
    );
    Ok(resp)
}

async fn route(
    req: Request<Incoming>,
    cfg: &Config,
    pipeline: &Pipeline,
    peer: SocketAddr,
    started: Instant,
) -> (Response<Body>, &'static str) {
    /* HTTP/2 puts the authority on the uri, HTTP/1.1 in the Host header */
    let host = req.uri().host().map(str::to_owned).or_else(|| {
        req.headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    });

    let Some(host) = host else {
        return (text(StatusCode::BAD_REQUEST, "400 missing host"), "route");
    };
    let Some(zone) = cfg.zone_for(&host) else {
        return (
            text(StatusCode::NOT_FOUND, "404 no zone configured for this host"),
            "route",
        );
    };

    let mut ctx = Ctx::new(peer, host, cfg, zone, req.map(|b| b.boxed()), started);
    let resp = pipeline.run(&mut ctx).await;
    (resp, ctx.decided_by)
}

/// Applies to every response, whoever produced it.
fn finalize(resp: &mut Response<Body>) {
    strip_hop_by_hop(resp.headers_mut());
    resp.headers_mut()
        .insert(header::SERVER, HeaderValue::from_static("cloudveil"));
}
