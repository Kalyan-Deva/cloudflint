//! Terminal stage: fetch from the origin. Always answers, one way or another.

use std::net::SocketAddr;

use async_trait::async_trait;
use http_body_util::BodyExt;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{header, Request, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::body::Body;
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

pub struct Origin {
    client: HttpClient,
}

impl Origin {
    pub fn new() -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
        }
    }
}

impl Default for Origin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Stage for Origin {
    fn name(&self) -> &'static str {
        "origin"
    }

    async fn on_request(&self, ctx: &mut Ctx<'_>) -> Result<Verdict, StageError> {
        let origin = &ctx.zone.origin;

        let Some(req) = ctx.take_req() else {
            return Err(StageError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "500 request was already consumed",
            ));
        };
        let (mut parts, body) = req.into_parts();
        strip_hop_by_hop(&mut parts.headers);

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
            .map_err(|e| StageError::new(StatusCode::BAD_REQUEST, format!("400 bad request target: {e}")))?;

        set_forwarded(&mut parts.headers, &ctx.host, ctx.peer);
        if !origin.preserve_host {
            /* dropping it lets hyper fill Host in from the origin authority */
            parts.headers.remove(header::HOST);
        }

        let sent = self.client.request(Request::from_parts(parts, body));
        match tokio::time::timeout(origin.timeout, sent).await {
            Ok(Ok(resp)) => Ok(Verdict::Respond(resp.map(|b| b.boxed()))),
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
