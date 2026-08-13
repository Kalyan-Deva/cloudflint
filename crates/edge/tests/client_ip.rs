//! Behind a proxy, with real sockets.
//!
//! The unit tests in `client_ip` cover the resolver. What matters here is the thing the
//! resolver exists for: that a per-IP rate limit behind a load balancer counts clients
//! rather than counting the load balancer, and that turning the trust off puts it back
//! to counting the peer.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use cloudflint_edge::snapshot::Snapshot;
use cloudflint_edge::{config, serve, Edge};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| async move {
                    /* echo back what the proxy told us about the client */
                    let get = |k: &str| {
                        req.headers()
                            .get(k)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("-")
                            .to_owned()
                    };
                    let body = format!(
                        "xff={} xfp={}",
                        get("x-forwarded-for"),
                        get("x-forwarded-proto")
                    );
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

/// A zone with a limit of two requests per client, and a rule that only trusts
/// `$trusted` addresses - both of which now read the resolved client.
fn zone_yaml(origin: SocketAddr, trusted_proxies: &str) -> String {
    format!(
        r#"
{trusted_proxies}
lists:
  blocked:
    - 198.51.100.66
zones:
  - name: demo
    hostnames: ["demo.local"]
    origin:
      url: "http://{origin}"
    cache:
      enabled: false
    waf:
      rulesets: []
      rules:
        - id: block-one-client
          expression: ip.src in $blocked
          action: block
          severity: high
    rate_limits:
      - id: per-client
        key: ip
        requests: 2
        window_secs: 60
        action: block
"#
    )
}

async fn spawn_edge(origin: SocketAddr, trusted_proxies: &str) -> SocketAddr {
    let cfg = config::parse(&zone_yaml(origin, trusted_proxies)).expect("config should parse");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, Edge::new(Arc::new(Snapshot::new(cfg)))).await;
    });
    addr
}

fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// A request pretending to have come through a proxy.
async fn get_as(edge: SocketAddr, forwarded_for: Option<&str>) -> (StatusCode, String) {
    let mut req = Request::builder()
        .uri(format!("http://{edge}/"))
        .header("host", "demo.local");
    if let Some(chain) = forwarded_for {
        req = req.header("x-forwarded-for", chain);
    }
    let resp = client()
        .request(req.body(Full::new(Bytes::new())).unwrap())
        .await
        .expect("the edge should answer");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// The tests connect over loopback, so that is the "load balancer" to trust.
const TRUSTS_LOOPBACK: &str = "client_ip:\n  trusted_proxies: [127.0.0.0/8]";

#[tokio::test]
async fn a_per_ip_limit_counts_clients_not_the_load_balancer() {
    let origin = spawn_origin().await;
    let edge = spawn_edge(origin, TRUSTS_LOOPBACK).await;

    /* two requests is the whole allowance, and the third is over it */
    for n in 1..=2 {
        let (status, _) = get_as(edge, Some("198.51.100.7")).await;
        assert_eq!(status, StatusCode::OK, "request {n} should be allowed");
    }
    let (status, _) = get_as(edge, Some("198.51.100.7")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    /* a different client, arriving down the same connection from the same peer, has its
       own allowance - this is the assertion the whole feature exists for */
    let (status, _) = get_as(edge, Some("198.51.100.8")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "one client hitting its limit must not limit everybody else"
    );
}

#[tokio::test]
async fn without_trusted_proxies_the_header_is_ignored() {
    let origin = spawn_origin().await;
    /* no client_ip block at all: the default */
    let edge = spawn_edge(origin, "").await;

    let (status, _) = get_as(edge, Some("198.51.100.7")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get_as(edge, Some("198.51.100.8")).await;
    assert_eq!(status, StatusCode::OK);

    /* every request came from the same peer, so they shared one bucket however much
       they claimed otherwise */
    let (status, _) = get_as(edge, Some("198.51.100.9")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "an untrusted claim must not buy a fresh allowance"
    );
}

#[tokio::test]
async fn a_waf_rule_matches_the_client_a_trusted_proxy_reported() {
    let origin = spawn_origin().await;
    let edge = spawn_edge(origin, TRUSTS_LOOPBACK).await;

    let (status, _) = get_as(edge, Some("198.51.100.66")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "ip.src should see the real client");

    let (status, _) = get_as(edge, Some("198.51.100.67")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_forwarding_chain_still_records_every_hop() {
    let origin = spawn_origin().await;
    let edge = spawn_edge(origin, TRUSTS_LOOPBACK).await;

    let (status, body) = get_as(edge, Some("198.51.100.7")).await;
    assert_eq!(status, StatusCode::OK);
    /* the client, then us appending the peer we actually saw */
    assert!(
        body.contains("xff=198.51.100.7, 127.0.0.1"),
        "the origin should see the whole chain, not just our view of it: {body}"
    );
}

#[tokio::test]
async fn a_trusted_proxy_can_report_that_the_client_used_https() {
    let origin = spawn_origin().await;
    let edge = spawn_edge(origin, TRUSTS_LOOPBACK).await;

    let req = Request::builder()
        .uri(format!("http://{edge}/"))
        .header("host", "demo.local")
        .header("x-forwarded-for", "198.51.100.7")
        .header("x-forwarded-proto", "https")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.expect("the edge should answer");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);

    /* our own leg was plaintext, but the client's was not, and that is what gets
       passed on rather than what we happened to receive */
    assert!(body.contains("xfp=https"), "body was {body}");
}
