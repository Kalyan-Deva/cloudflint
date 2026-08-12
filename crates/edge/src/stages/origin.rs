//! Talking to the origin.
//!
//! `Fetcher` is the bit that does it, shared rather than owned by the stage, because
//! the cache needs to make origin requests of its own for background revalidation.
//! `Origin` is the terminal stage: it always answers, one way or another.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{header, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tracing::debug;

use crate::body::{adapt, full, with_read_timeout, Body};
use crate::config;
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

pub struct Fetcher {
    client: HttpClient,
}

impl Fetcher {
    pub fn new() -> Self {
        Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
        }
    }

    pub async fn fetch(
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
            .fetch(&ctx.zone.origin, &ctx.host, ctx.peer, ctx.tls, req)
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
