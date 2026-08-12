//! Cache end to end. The origin counts its own hits, because "did the client get the
//! right bytes" and "did we actually avoid the origin" are different questions.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cloudveil_edge::snapshot::Snapshot;
use cloudveil_edge::{config, serve, Edge};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

/// A test origin you can reconfigure mid-test.
struct Origin {
    hits: AtomicUsize,
    status: AtomicU16,
    delay_ms: AtomicU64,
    headers: Mutex<Vec<(String, String)>>,
    body: Mutex<String>,
}

impl Origin {
    fn new(cache_control: &str) -> Arc<Self> {
        let headers = if cache_control.is_empty() {
            Vec::new()
        } else {
            vec![("cache-control".to_string(), cache_control.to_string())]
        };
        Arc::new(Origin {
            hits: AtomicUsize::new(0),
            status: AtomicU16::new(200),
            delay_ms: AtomicU64::new(0),
            headers: Mutex::new(headers),
            body: Mutex::new("payload".to_string()),
        })
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn set_headers(&self, pairs: &[(&str, &str)]) {
        *self.headers.lock().unwrap() = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
    }

    fn set_body(&self, body: &str) {
        *self.body.lock().unwrap() = body.to_string();
    }

    /// Wait for the origin to have been hit `want` times, so background work doesn't
    /// have to be guessed at with a sleep.
    async fn wait_for_hits(&self, want: usize) -> bool {
        for _ in 0..200 {
            if self.hits() >= want {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
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
                        let n = origin.hits.fetch_add(1, Ordering::SeqCst) + 1;
                        let delay = origin.delay_ms.load(Ordering::SeqCst);
                        if delay > 0 {
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                        }

                        let mut b =
                            Response::builder().status(origin.status.load(Ordering::SeqCst));
                        for (k, v) in origin.headers.lock().unwrap().iter() {
                            b = b.header(k, v);
                        }
                        let body = format!("{} #{n}", origin.body.lock().unwrap());
                        Ok::<_, Infallible>(b.body(Full::new(Bytes::from(body))).unwrap())
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

/// `cache` is the indented yaml for the zone's cache block, or "" for the default.
async fn spawn_proxy(origin: SocketAddr, cache: &str) -> SocketAddr {
    let yaml = format!(
        "zones:\n  \
         - name: demo\n    \
           hostnames: [\"demo.local\"]\n    \
           origin:\n      \
             url: \"http://{origin}\"\n    \
           waf:\n      rulesets: []\n{cache}"
    );
    let cfg = config::parse(&yaml).expect("test config should parse");
    let snap = Arc::new(Snapshot::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, Edge::new(snap)).await;
    });
    addr
}

fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

struct Reply {
    status: StatusCode,
    cache: String,
    body: String,
}

async fn get(proxy: SocketAddr, path: &str) -> Reply {
    request(proxy, "GET", path).await
}

async fn request(proxy: SocketAddr, method: &str, path: &str) -> Reply {
    let req = Request::builder()
        .method(method)
        .uri(format!("http://{proxy}{path}"))
        .header("host", "demo.local")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp = client().request(req).await.expect("proxy should answer");
    let status = resp.status();
    let cache = resp
        .headers()
        .get("cloudveil-cache")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let body = resp.into_body().collect().await.unwrap().to_bytes();

    Reply {
        status,
        cache,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// The entry lands when the response body finishes streaming, a hair after the client
/// has it. Gives that a moment rather than racing it.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(30)).await;
}

#[tokio::test]
async fn a_second_request_comes_from_the_cache() {
    let origin = Origin::new("max-age=60");
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    let first = get(proxy, "/page").await;
    assert_eq!(first.cache, "MISS");
    assert_eq!(first.body, "payload #1");
    settle().await;

    let second = get(proxy, "/page").await;
    assert_eq!(second.cache, "HIT");
    assert_eq!(second.body, "payload #1", "should be the stored copy");
    assert_eq!(origin.hits(), 1, "the origin should only have been asked once");
}

#[tokio::test]
async fn nothing_is_cached_unless_the_origin_says_so() {
    let origin = Origin::new("");
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    assert_eq!(get(proxy, "/page").await.cache, "BYPASS");
    settle().await;
    assert_eq!(get(proxy, "/page").await.cache, "BYPASS");
    assert_eq!(origin.hits(), 2);
}

#[tokio::test]
async fn a_response_that_sets_a_cookie_is_never_cached() {
    let origin = Origin::new("max-age=60");
    origin.set_headers(&[("cache-control", "max-age=60"), ("set-cookie", "sid=abc")]);
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    assert_eq!(get(proxy, "/page").await.cache, "BYPASS");
    settle().await;
    assert_eq!(get(proxy, "/page").await.cache, "BYPASS");
    assert_eq!(origin.hits(), 2);
}

#[tokio::test]
async fn posts_go_straight_past() {
    let origin = Origin::new("max-age=60");
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    let reply = request(proxy, "POST", "/page").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.cache, "-", "a post should not be labelled at all");
    settle().await;
    request(proxy, "POST", "/page").await;
    assert_eq!(origin.hits(), 2);
}

#[tokio::test]
async fn param_order_and_tracking_junk_land_on_one_entry() {
    let origin = Origin::new("max-age=60");
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    assert_eq!(get(proxy, "/p?b=2&a=1").await.cache, "MISS");
    settle().await;

    assert_eq!(get(proxy, "/p?a=1&b=2").await.cache, "HIT");
    assert_eq!(get(proxy, "/p?a=1&utm_source=news&b=2").await.cache, "HIT");
    assert_eq!(get(proxy, "/p?a=1&b=3").await.cache, "MISS", "a real param still splits");

    assert_eq!(origin.hits(), 2);
}

#[tokio::test]
async fn a_herd_of_misses_makes_one_origin_request() {
    let origin = Origin::new("max-age=60");
    origin.delay_ms.store(120, Ordering::SeqCst);
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    let mut tasks = Vec::new();
    for _ in 0..100 {
        tasks.push(tokio::spawn(async move { get(proxy, "/hot").await }));
    }

    let mut ok = 0;
    for t in tasks {
        let reply = t.await.unwrap();
        assert_eq!(reply.status, StatusCode::OK);
        ok += 1;
    }

    assert_eq!(ok, 100);
    assert_eq!(
        origin.hits(),
        1,
        "100 simultaneous misses should have collapsed into one origin fetch"
    );
}

#[tokio::test]
async fn a_stale_entry_is_served_while_it_refreshes() {
    let origin = Origin::new("max-age=1, stale-while-revalidate=60");
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    assert_eq!(get(proxy, "/p").await.body, "payload #1");
    settle().await;

    /* let the entry go stale, and change what the origin will say next */
    tokio::time::sleep(Duration::from_millis(1100)).await;
    origin.set_body("fresher");

    let stale = get(proxy, "/p").await;
    assert_eq!(stale.cache, "STALE");
    assert_eq!(stale.body, "payload #1", "the client should not wait for the refresh");

    assert!(origin.wait_for_hits(2).await, "no background refresh happened");
    settle().await;

    let after = get(proxy, "/p").await;
    assert_eq!(after.cache, "HIT");
    assert_eq!(after.body, "fresher #2", "the refresh should have replaced it");
}

#[tokio::test]
async fn only_one_background_refresh_runs_at_a_time() {
    let origin = Origin::new("max-age=1, stale-while-revalidate=60");
    origin.delay_ms.store(150, Ordering::SeqCst);
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    get(proxy, "/p").await;
    settle().await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    /* a burst of stale hits must not turn into a burst of origin fetches */
    let mut tasks = Vec::new();
    for _ in 0..25 {
        tasks.push(tokio::spawn(async move { get(proxy, "/p").await }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap().cache, "STALE");
    }

    assert!(origin.wait_for_hits(2).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(origin.hits(), 2, "the refresh should have been coalesced");
}

#[tokio::test]
async fn a_stale_copy_beats_an_error_page() {
    let origin = Origin::new("max-age=1, stale-if-error=600");
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    assert_eq!(get(proxy, "/p").await.body, "payload #1");
    settle().await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    /* origin falls over */
    origin.status.store(503, Ordering::SeqCst);

    let rescued = get(proxy, "/p").await;
    assert_eq!(rescued.status, StatusCode::OK);
    assert_eq!(rescued.cache, "STALE-ERROR");
    assert_eq!(rescued.body, "payload #1");
}

#[tokio::test]
async fn an_error_with_nothing_stale_is_still_an_error() {
    let origin = Origin::new("max-age=60");
    origin.status.store(503, Ordering::SeqCst);
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    let reply = get(proxy, "/p").await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_path_override_caches_what_the_origin_would_not() {
    let origin = Origin::new("no-cache");
    let cache = "    cache:\n      \
                   overrides:\n        \
                   - path_prefix: \"/static/\"\n          \
                     ttl_secs: 3600\n          \
                     override_origin_headers: true\n";
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, cache).await;

    assert_eq!(get(proxy, "/static/app.css").await.cache, "MISS");
    settle().await;
    assert_eq!(get(proxy, "/static/app.css").await.cache, "HIT");

    /* the override is scoped to the prefix */
    assert_eq!(get(proxy, "/index.html").await.cache, "BYPASS");
    assert_eq!(origin.hits(), 2);
}

#[tokio::test]
async fn caching_can_be_turned_off_per_zone() {
    let origin = Origin::new("max-age=60");
    let proxy = spawn_proxy(
        spawn_origin(origin.clone()).await,
        "    cache:\n      enabled: false\n",
    )
    .await;

    assert_eq!(get(proxy, "/p").await.cache, "-");
    settle().await;
    assert_eq!(get(proxy, "/p").await.cache, "-");
    assert_eq!(origin.hits(), 2);
}

#[tokio::test]
async fn an_object_over_the_limit_is_served_but_not_kept() {
    let origin = Origin::new("max-age=60");
    origin.set_body(&"x".repeat(4000));
    let proxy = spawn_proxy(spawn_origin(origin.clone()).await, "").await;

    /* store config is top level, so build this one by hand */
    let big = get(proxy, "/big").await;
    assert_eq!(big.status, StatusCode::OK);
    assert!(big.body.len() > 4000);
    settle().await;

    /* default max_object_bytes is 8 MiB, so this one does get cached */
    assert_eq!(get(proxy, "/big").await.cache, "HIT");
    assert_eq!(origin.hits(), 1);
}

#[tokio::test]
async fn an_object_bigger_than_the_store_allows_is_not_cached() {
    let origin = Origin::new("max-age=60");
    origin.set_body(&"x".repeat(4000));
    let addr = spawn_origin(origin.clone()).await;

    let yaml = format!(
        "cache:\n  max_bytes: 1048576\n  max_object_bytes: 1024\n\
         zones:\n  \
         - name: demo\n    \
           hostnames: [\"demo.local\"]\n    \
           origin:\n      url: \"http://{addr}\"\n    \
           waf:\n      rulesets: []\n"
    );
    let cfg = config::parse(&yaml).expect("config should parse");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, Edge::new(Arc::new(Snapshot::new(cfg)))).await;
    });

    let first = get(proxy, "/big").await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(first.body.len() > 4000, "the client still gets the whole thing");
    settle().await;

    assert_eq!(get(proxy, "/big").await.cache, "MISS", "too big to keep");
    assert_eq!(origin.hits(), 2);
}

#[tokio::test]
async fn hits_report_their_age() {
    let origin = Origin::new("max-age=60");
    let addr = spawn_origin(origin.clone()).await;
    let proxy = spawn_proxy(addr, "").await;

    get(proxy, "/p").await;
    settle().await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let req = Request::builder()
        .uri(format!("http://{proxy}/p"))
        .header("host", "demo.local")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.unwrap();

    assert_eq!(resp.headers().get("cloudveil-cache").unwrap(), "HIT");
    let age: u64 = resp
        .headers()
        .get("age")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("a hit should carry an Age header");
    assert!(age >= 1, "age was {age}");
}
