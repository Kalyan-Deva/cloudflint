//! Rate limiting end to end, including the bit that matters most: a limited request
//! must not reach the origin.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

struct Origin {
    hits: AtomicUsize,
    status: AtomicU16,
}

impl Origin {
    fn new() -> Arc<Self> {
        Arc::new(Origin {
            hits: AtomicUsize::new(0),
            status: AtomicU16::new(200),
        })
    }
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn spawn_origin(origin: Arc<Origin>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let origin = origin.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let origin = origin.clone();
                    async move {
                        origin.hits.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(origin.status.load(Ordering::SeqCst))
                                .body(Full::new(Bytes::from_static(b"origin ok")))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

/// `extra` is indented yaml appended to the zone.
async fn spawn_proxy(origin: SocketAddr, extra: &str) -> SocketAddr {
    let yaml = format!(
        "zones:\n  \
         - name: demo\n    \
           hostnames: [\"demo.local\"]\n    \
           origin:\n      url: \"http://{origin}\"\n    \
           waf:\n      rulesets: []\n    \
           cache:\n      enabled: false\n{extra}"
    );
    let cfg = config::parse(&yaml).expect("test config should parse");
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

async fn get(proxy: SocketAddr, path: &str, headers: &[(&str, &str)]) -> (StatusCode, Option<String>) {
    let mut req = Request::builder()
        .uri(format!("http://{proxy}{path}"))
        .header("host", "demo.local");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = client()
        .request(req.body(Full::new(Bytes::new())).unwrap())
        .await
        .expect("proxy should answer");

    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let status = resp.status();
    let _ = resp.into_body().collect().await;
    (status, retry_after)
}

fn limit(id: &str, extra: &str) -> String {
    format!(
        "    rate_limits:\n      \
         - id: {id}\n        \
           requests: 3\n        \
           window_secs: 60\n{extra}"
    )
}

#[tokio::test]
async fn allows_the_burst_then_refuses() {
    let origin = Origin::new();
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, &limit("per-ip", "")).await;

    for n in 0..3 {
        assert_eq!(get(proxy, "/", &[]).await.0, StatusCode::OK, "request {n}");
    }

    let (status, retry_after) = get(proxy, "/", &[]).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry_after.is_some(), "a 429 should say when to come back");
    assert_eq!(origin.hits(), 3, "the limited request must not reach the origin");
}

#[tokio::test]
async fn a_log_only_limit_lets_everything_through() {
    let origin = Origin::new();
    let proxy = spawn_proxy(
        spawn_origin(origin.clone()).await,
        &limit("per-ip", "        action: log\n"),
    )
    .await;

    for _ in 0..6 {
        assert_eq!(get(proxy, "/", &[]).await.0, StatusCode::OK);
    }
    assert_eq!(origin.hits(), 6);
}

#[tokio::test]
async fn a_limit_can_be_scoped_to_part_of_the_site() {
    let origin = Origin::new();
    let proxy = spawn_proxy(
        spawn_origin(origin.clone()).await,
        &limit(
            "api-only",
            "        match: 'http.request.uri.path contains \"/api/\"'\n",
        ),
    )
    .await;

    for _ in 0..3 {
        assert_eq!(get(proxy, "/api/thing", &[]).await.0, StatusCode::OK);
    }
    assert_eq!(get(proxy, "/api/thing", &[]).await.0, StatusCode::TOO_MANY_REQUESTS);

    /* the rest of the site is untouched by that limit */
    for _ in 0..5 {
        assert_eq!(get(proxy, "/index.html", &[]).await.0, StatusCode::OK);
    }
}

#[tokio::test]
async fn ip_path_counts_each_path_separately() {
    let origin = Origin::new();
    let proxy = spawn_proxy(
        spawn_origin(origin.clone()).await,
        &limit("per-path", "        key: ip_path\n"),
    )
    .await;

    for _ in 0..3 {
        assert_eq!(get(proxy, "/one", &[]).await.0, StatusCode::OK);
    }
    assert_eq!(get(proxy, "/one", &[]).await.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        get(proxy, "/two", &[]).await.0,
        StatusCode::OK,
        "a different path has its own allowance"
    );
}

#[tokio::test]
async fn a_header_key_counts_per_api_key() {
    let origin = Origin::new();
    let proxy = spawn_proxy(
        spawn_origin(origin.clone()).await,
        &limit("per-key", "        key: \"header:x-api-key\"\n"),
    )
    .await;

    let alice = [("x-api-key", "alice")];
    let bob = [("x-api-key", "bob")];

    for _ in 0..3 {
        assert_eq!(get(proxy, "/", &alice).await.0, StatusCode::OK);
    }
    assert_eq!(get(proxy, "/", &alice).await.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(get(proxy, "/", &bob).await.0, StatusCode::OK);

    /* nothing to count by, so the limit does not apply */
    for _ in 0..5 {
        assert_eq!(get(proxy, "/", &[]).await.0, StatusCode::OK);
    }
}

#[tokio::test]
async fn several_limits_stack() {
    let origin = Origin::new();
    let extra = "    rate_limits:\n      \
                 - id: burst\n        \
                   requests: 5\n        \
                   window_secs: 1\n      \
                 - id: sustained\n        \
                   requests: 2\n        \
                   window_secs: 3600\n";
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, extra).await;

    /* the tighter of the two is what actually bites */
    for _ in 0..2 {
        assert_eq!(get(proxy, "/", &[]).await.0, StatusCode::OK);
    }
    assert_eq!(get(proxy, "/", &[]).await.0, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn the_allowance_refills() {
    let origin = Origin::new();
    let extra = "    rate_limits:\n      \
                 - id: quick\n        \
                   requests: 2\n        \
                   window_secs: 1\n";
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, extra).await;

    for _ in 0..2 {
        assert_eq!(get(proxy, "/", &[]).await.0, StatusCode::OK);
    }
    assert_eq!(get(proxy, "/", &[]).await.0, StatusCode::TOO_MANY_REQUESTS);

    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(get(proxy, "/", &[]).await.0, StatusCode::OK);
}

#[tokio::test]
async fn no_limits_means_no_limiting() {
    let origin = Origin::new();
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    for _ in 0..50 {
        assert_eq!(get(proxy, "/", &[]).await.0, StatusCode::OK);
    }
    assert_eq!(origin.hits(), 50);
}

/// The adaptive tier: once the origin starts failing, the same limit lets less
/// through than it did while things were healthy.
#[tokio::test]
async fn a_failing_origin_tightens_the_limit() {
    let origin = Origin::new();
    let extra = "    rate_limits:\n      \
                 - id: per-ip\n        \
                   requests: 10\n        \
                   window_secs: 3600\n    \
                 adaptive:\n      \
                   window_secs: 1\n      \
                   min_requests: 4\n      \
                   tighten_to: 0.2\n";
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, extra).await;

    /* healthy: the full allowance is there */
    for n in 0..4 {
        assert_eq!(get(proxy, "/", &[]).await.0, StatusCode::OK, "healthy request {n}");
    }

    /* origin falls over, and keeps failing for a full window */
    origin.status.store(503, Ordering::SeqCst);
    for _ in 0..5 {
        get(proxy, "/", &[]).await;
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;

    /* the next request rolls the window, sees the strain, and clamps the bucket */
    get(proxy, "/", &[]).await;

    let mut limited = false;
    for _ in 0..5 {
        if get(proxy, "/", &[]).await.0 == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "a struggling origin should have tightened the limit");
}

#[tokio::test]
async fn a_healthy_origin_is_never_tightened() {
    let origin = Origin::new();
    let extra = "    rate_limits:\n      \
                 - id: per-ip\n        \
                   requests: 30\n        \
                   window_secs: 3600\n    \
                 adaptive:\n      \
                   window_secs: 1\n      \
                   min_requests: 4\n      \
                   tighten_to: 0.1\n";
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, extra).await;

    for _ in 0..10 {
        get(proxy, "/", &[]).await;
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;

    for n in 0..15 {
        assert_eq!(
            get(proxy, "/", &[]).await.0,
            StatusCode::OK,
            "request {n} was limited despite a healthy origin"
        );
    }
}

#[tokio::test]
async fn bad_limits_are_refused_at_config_load() {
    let cases = [
        ("        key: nonsense\n", "have: ip, ip_path"),
        ("        match: 'http.request.body contains \"x\"'\n", "cannot match on the request body"),
        ("        action: skip\n", "can only block or log"),
    ];

    for (extra, expected) in cases {
        let yaml = format!(
            "zones:\n  \
             - name: demo\n    \
               hostnames: [\"demo.local\"]\n    \
               origin:\n      url: \"http://127.0.0.1:9\"\n{}",
            limit("bad", extra)
        );
        let err = format!("{:#}", config::parse(&yaml).unwrap_err());
        assert!(err.contains(expected), "expected `{expected}` in: {err}");
    }
}

#[tokio::test]
async fn zero_requests_is_refused_rather_than_silently_blocking_everything() {
    let yaml = "zones:\n  \
                - name: demo\n    \
                  hostnames: [\"demo.local\"]\n    \
                  origin:\n      url: \"http://127.0.0.1:9\"\n    \
                  rate_limits:\n      \
                  - id: nope\n        \
                    requests: 0\n        \
                    window_secs: 60\n";
    let err = format!("{:#}", config::parse(yaml).unwrap_err());
    assert!(err.contains("zero requests"), "got: {err}");
}
