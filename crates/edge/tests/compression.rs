//! Compression through the whole pipeline.
//!
//! The unit tests in `compress` cover the decisions. What matters here is the bit those
//! cannot see: that a compressed response is what the *cache* stores, so a variant is
//! compressed once and served many times, and that clients who ask for different
//! encodings do not end up sharing one entry.

use std::convert::Infallible;
use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use cloudveil_edge::snapshot::Snapshot;
use cloudveil_edge::{admin, config, serve, Edge};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

const TOKEN: &str = "cv_compresstoken0123456789abcdef0123456789abcdef0123456789ab";

/// The page every test asks for: big enough to be worth compressing, and repetitive
/// enough that the saving is unmistakable.
fn page() -> String {
    "<p>the quick brown fox jumps over the lazy dog</p>\n".repeat(200)
}

async fn spawn_origin(hits: Arc<AtomicUsize>, cacheable: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let hits = hits.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let body = match req.uri().path() {
                            "/binary" => vec![0u8; 5000],
                            _ => page().into_bytes(),
                        };
                        let kind = match req.uri().path() {
                            "/binary" => "image/png",
                            _ => "text/html; charset=utf-8",
                        };
                        let mut resp = Response::builder()
                            .header("content-type", kind)
                            /* what the origin was asked, echoed back so a test can see
                               whether we forwarded the client's accept-encoding */
                            .header(
                                "x-origin-saw",
                                req.headers()
                                    .get("accept-encoding")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("-"),
                            );
                        if cacheable {
                            resp = resp.header("cache-control", "max-age=300");
                        } else {
                            resp = resp.header("cache-control", "no-store");
                        }
                        Ok::<_, Infallible>(resp.body(Full::new(Bytes::from(body))).unwrap())
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

fn zone_yaml(origin: SocketAddr, cache: bool, compression: &str) -> String {
    format!(
        "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    \
         origin:\n      url: \"http://{origin}\"\n    \
         cache:\n      enabled: {cache}\n{compression}"
    )
}

async fn spawn_edge(yaml: &str) -> (SocketAddr, SocketAddr) {
    std::env::set_var(admin::TOKEN_VAR, TOKEN);
    let cfg = config::parse(yaml).expect("test config should parse");
    let edge = Edge::new(Arc::new(Snapshot::new(cfg)));

    let traffic = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let traffic_addr = traffic.local_addr().unwrap();
    {
        let edge = edge.clone();
        tokio::spawn(async move {
            let _ = serve(traffic, edge).await;
        });
    }
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = admin::serve(admin_listener, edge).await;
    });

    (traffic_addr, admin_addr)
}

fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

struct Got {
    status: StatusCode,
    encoding: String,
    cache: String,
    body: Vec<u8>,
    origin_saw: String,
}

async fn get(edge: SocketAddr, path: &str, accept: &str) -> Got {
    let mut req = Request::builder()
        .uri(format!("http://{edge}{path}"))
        .header("host", "demo.local");
    if !accept.is_empty() {
        req = req.header("accept-encoding", accept);
    }
    /* identity is what hyper's client would otherwise not send at all */
    let resp = client()
        .request(req.body(Full::new(Bytes::new())).unwrap())
        .await
        .expect("the edge should answer");

    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_owned()
    };
    let status = resp.status();
    let encoding = header("content-encoding");
    let cache = header("cloudveil-cache");
    let origin_saw = header("x-origin-saw");
    let body = resp.into_body().collect().await.unwrap().to_bytes().to_vec();

    Got {
        status,
        encoding,
        cache,
        body,
        origin_saw,
    }
}

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut out)
        .expect("should be valid gzip");
    out
}

fn unbrotli(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    brotli::Decompressor::new(bytes, 4096)
        .read_to_end(&mut out)
        .expect("should be valid brotli");
    out
}

#[tokio::test]
async fn compresses_a_page_for_a_client_that_asks() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), false).await;
    let (edge, _) = spawn_edge(&zone_yaml(origin, false, "")).await;

    let got = get(edge, "/", "gzip, deflate, br").await;

    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.encoding, "br", "brotli is preferred when offered");
    assert!(
        got.body.len() < page().len() / 4,
        "{} bytes for a {} byte page",
        got.body.len(),
        page().len()
    );
    assert_eq!(unbrotli(&got.body), page().into_bytes());
}

#[tokio::test]
async fn leaves_a_client_that_asks_for_nothing_alone() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), false).await;
    let (edge, _) = spawn_edge(&zone_yaml(origin, false, "")).await;

    let got = get(edge, "/", "").await;
    assert_eq!(got.encoding, "-", "no accept-encoding, no compression");
    assert_eq!(got.body, page().into_bytes());
}

#[tokio::test]
async fn a_cached_variant_is_compressed_once_and_served_many_times() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), true).await;
    let (edge, _) = spawn_edge(&zone_yaml(origin, true, "")).await;

    let first = get(edge, "/", "gzip").await;
    assert_eq!(first.cache, "MISS");
    assert_eq!(first.encoding, "gzip");

    for _ in 0..3 {
        let hit = get(edge, "/", "gzip").await;
        assert_eq!(hit.cache, "HIT");
        assert_eq!(hit.encoding, "gzip", "the stored entry is the compressed one");
        assert_eq!(hit.body, first.body, "byte for byte the same object");
    }

    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the origin was asked once, and so was the compressor"
    );
}

#[tokio::test]
async fn clients_wanting_different_encodings_do_not_share_an_entry() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), true).await;
    let (edge, _) = spawn_edge(&zone_yaml(origin, true, "")).await;

    let brotli = get(edge, "/", "br").await;
    let gzip = get(edge, "/", "gzip").await;
    let plain = get(edge, "/", "").await;

    assert_eq!(brotli.encoding, "br");
    assert_eq!(gzip.encoding, "gzip");
    assert_eq!(plain.encoding, "-");

    /* three variants, three origin fetches, and each decodes to the same page */
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    assert_eq!(unbrotli(&brotli.body), page().into_bytes());
    assert_eq!(gunzip(&gzip.body), page().into_bytes());
    assert_eq!(plain.body, page().into_bytes());

    /* and each variant is then served from cache */
    assert_eq!(get(edge, "/", "br").await.cache, "HIT");
    assert_eq!(get(edge, "/", "gzip").await.cache, "HIT");
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_q_zero_client_is_not_handed_a_shared_entry() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), true).await;
    let (edge, _) = spawn_edge(&zone_yaml(origin, true, "")).await;

    /* fills the gzip variant */
    assert_eq!(get(edge, "/", "gzip").await.encoding, "gzip");

    /* this client names gzip only to refuse it. if the cache key and the compressor
       disagreed about what that means, it would be handed the gzip entry and be unable
       to read it */
    let refused = get(edge, "/", "gzip;q=0").await;
    assert_eq!(refused.encoding, "-");
    assert_eq!(refused.body, page().into_bytes());
}

#[tokio::test]
async fn the_origin_still_sees_what_the_client_asked_for() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), false).await;
    let (edge, _) = spawn_edge(&zone_yaml(origin, false, "")).await;

    /* the header is forwarded rather than swallowed, so an origin that would rather
       compress its own responses still gets the chance - and if it does, we leave the
       result alone */
    let got = get(edge, "/", "gzip, br").await;
    assert_eq!(got.origin_saw, "gzip, br");
}

#[tokio::test]
async fn does_not_compress_what_is_already_compressed() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), false).await;
    let (edge, _) = spawn_edge(&zone_yaml(origin, false, "")).await;

    let got = get(edge, "/binary", "gzip, br").await;
    assert_eq!(got.encoding, "-", "a png is not worth gzipping");
    assert_eq!(got.body.len(), 5000);
}

#[tokio::test]
async fn a_zone_can_turn_it_off() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), false).await;
    let (edge, _) = spawn_edge(&zone_yaml(
        origin,
        false,
        "    compression:\n      enabled: false\n",
    ))
    .await;

    let got = get(edge, "/", "gzip, br").await;
    assert_eq!(got.encoding, "-");
    assert_eq!(got.body, page().into_bytes());
}

#[tokio::test]
async fn the_minimum_size_is_respected() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), false).await;
    let (edge, _) = spawn_edge(&zone_yaml(
        origin,
        false,
        "    compression:\n      min_bytes: 100000\n",
    ))
    .await;

    let got = get(edge, "/", "gzip").await;
    assert_eq!(got.encoding, "-", "the page is under the floor");
    assert_eq!(got.body, page().into_bytes());
}

#[tokio::test]
async fn vary_tells_downstream_caches_the_body_depends_on_the_request() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), false).await;
    let (edge, _) = spawn_edge(&zone_yaml(origin, false, "")).await;

    let req = Request::builder()
        .uri(format!("http://{edge}/"))
        .header("host", "demo.local")
        .header("accept-encoding", "gzip")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.unwrap();

    let vary: Vec<&str> = resp
        .headers()
        .get_all("vary")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        vary.iter().any(|v| v.to_ascii_lowercase().contains("accept-encoding")),
        "vary was {vary:?}"
    );
}

#[tokio::test]
async fn compression_shows_up_in_the_scrape() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone(), false).await;
    let (edge, admin) = spawn_edge(&zone_yaml(origin, false, "")).await;

    get(edge, "/", "gzip").await;

    let req = Request::builder()
        .uri(format!("http://{admin}/metrics"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);

    assert!(
        body.contains(r#"cloudveil_compressed_total{zone="demo",coding="gzip"} 1"#),
        "no compression counter:\n{body}"
    );

    let value = |name: &str| -> f64 {
        body.lines()
            .find(|l| l.starts_with(name) && l[name.len()..].starts_with(' '))
            .and_then(|l| l[name.len()..].trim().parse().ok())
            .unwrap_or_else(|| panic!("no {name} in\n{body}"))
    };
    let before = value(r#"cloudveil_compressed_bytes_in_total{zone="demo"}"#);
    let after = value(r#"cloudveil_compressed_bytes_out_total{zone="demo"}"#);
    assert!(after < before, "{after} should be less than {before}");
}
