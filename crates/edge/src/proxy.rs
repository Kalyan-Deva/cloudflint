//! The forwarding path. Phase 1: route on Host, forward to the origin, hand the
//! response back. The pipeline stages (WAF, cache, rate limit) slot in here later.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{header, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use tracing::{info, warn};

use crate::config::Config;

pub type Body = BoxBody<Bytes, hyper::Error>;
pub type HttpClient = Client<HttpConnector, Incoming>;

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

pub async fn handle(
    req: Request<Incoming>,
    cfg: Arc<Config>,
    client: HttpClient,
    peer: SocketAddr,
) -> Result<Response<Body>, Infallible> {
    let started = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    let resp = forward(req, &cfg, &client, peer).await;

    info!(
        "{peer} {method} {path} -> {} in {:?}",
        resp.status(),
        started.elapsed()
    );
    Ok(resp)
}

async fn forward(
    req: Request<Incoming>,
    cfg: &Config,
    client: &HttpClient,
    peer: SocketAddr,
) -> Response<Body> {
    /* HTTP/2 puts the authority on the uri, HTTP/1.1 in the Host header */
    let host = req
        .uri()
        .host()
        .map(str::to_owned)
        .or_else(|| header_str(req.headers(), header::HOST).map(str::to_owned));

    let Some(host) = host else {
        return text(StatusCode::BAD_REQUEST, "400 missing host");
    };
    let Some(zone) = cfg.zone_for(&host) else {
        return text(StatusCode::NOT_FOUND, "404 no zone configured for this host");
    };
    let origin = &zone.origin;

    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop(&mut parts.headers);

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".into());

    let upstream = Uri::builder()
        .scheme(origin.scheme.clone())
        .authority(origin.authority.clone())
        .path_and_query(path_and_query);
    let upstream = match upstream.build() {
        Ok(u) => u,
        Err(e) => {
            warn!("zone `{}`: could not build upstream uri: {e}", zone.name);
            return text(StatusCode::BAD_REQUEST, "400 bad request target");
        }
    };

    set_forwarded(&mut parts.headers, &host, peer);
    if !origin.preserve_host {
        /* dropping it lets hyper fill Host in from the origin authority */
        parts.headers.remove(header::HOST);
    }
    parts.uri = upstream;

    let resp = tokio::time::timeout(origin.timeout, client.request(Request::from_parts(parts, body)));
    let mut resp = match resp.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            warn!("zone `{}`: origin request failed: {e}", zone.name);
            return text(StatusCode::BAD_GATEWAY, "502 origin unreachable");
        }
        Err(_) => {
            warn!("zone `{}`: origin timed out after {:?}", zone.name, origin.timeout);
            return text(StatusCode::GATEWAY_TIMEOUT, "504 origin timed out");
        }
    };

    strip_hop_by_hop(resp.headers_mut());
    resp.headers_mut()
        .insert(header::SERVER, HeaderValue::from_static("cloudveil"));
    resp.map(|b| b.boxed())
}

fn set_forwarded(headers: &mut HeaderMap, host: &str, peer: SocketAddr) {
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
    /* always http until TLS termination lands in a later phase */
    headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
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

fn text(status: StatusCode, msg: &str) -> Response<Body> {
    let body = Full::new(Bytes::from(format!("{msg}\n")))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::SERVER, "cloudveil")
        .body(body)
        .expect("static error response is always valid")
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
        set_forwarded(&mut h, "demo.local", peer);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "198.51.100.1, 203.0.113.9");
        assert_eq!(h.get("x-forwarded-host").unwrap(), "demo.local");
    }

    #[test]
    fn starts_forwarded_for_when_absent() {
        let peer: SocketAddr = "203.0.113.9:44321".parse().unwrap();
        let mut h = HeaderMap::new();
        set_forwarded(&mut h, "demo.local", peer);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "203.0.113.9");
    }
}
