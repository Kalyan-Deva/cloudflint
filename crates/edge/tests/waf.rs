//! WAF end to end. The thing that actually matters here is that a blocked request
//! never reaches the origin, so the origin counts what it sees.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Origin that counts hits and reports how many body bytes it received.
async fn spawn_origin(hits: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let hits = hits.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let body = req.into_body().collect().await.map(|b| b.to_bytes());
                        let n = body.map(|b| b.len()).unwrap_or(0);
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                            "origin ok, {n} body bytes"
                        )))))
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

/// `waf` is the indented yaml for the zone's waf block, or "" for the default.
async fn spawn_proxy(origin: SocketAddr, waf: &str) -> SocketAddr {
    let yaml = format!(
        "zones:\n  \
         - name: demo\n    \
           hostnames: [\"demo.local\"]\n    \
           origin:\n      \
             url: \"http://{origin}\"\n{waf}"
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

async fn get(proxy: SocketAddr, path: &str) -> (StatusCode, String) {
    send(proxy, "GET", path, "", &[]).await
}

async fn send(
    proxy: SocketAddr,
    method: &str,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method(method)
        .uri(format!("http://{proxy}{path}"))
        .header("host", "demo.local");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Full::new(Bytes::from(body.to_owned()))).unwrap();

    let resp = client().request(req).await.expect("proxy should answer");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// A zone with no waf block at all still gets the core ruleset.
#[tokio::test]
async fn the_waf_is_on_by_default() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    let proxy = spawn_proxy(origin, "").await;

    let (status, body) = get(proxy, "/search?id=1%20union%20select%20password").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("Cloudflint"), "expected the block page, got {body}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the origin should never have been touched");
}

#[tokio::test]
async fn normal_traffic_goes_straight_through() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    let proxy = spawn_proxy(origin, "").await;

    let (status, body) = get(proxy, "/search?q=how+to+bake+bread&page=2").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("origin ok"), "got {body}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn percent_encoding_does_not_get_you_past_the_rules() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    let proxy = spawn_proxy(origin, "").await;

    for path in [
        "/x?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "/x?id=1+union+select+1",
        "/files/%2e%2e%2f%2e%2e%2fetc/passwd",
        "/.env",
    ] {
        let (status, _) = get(proxy, path).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} should have been blocked");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_scanner_that_announces_itself_gets_blocked() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    let proxy = spawn_proxy(origin, "").await;

    let (blocked, _) = send(proxy, "GET", "/", "", &[("user-agent", "sqlmap/1.7.2#stable")]).await;
    assert_eq!(blocked, StatusCode::FORBIDDEN);

    let (fine, _) = send(proxy, "GET", "/", "", &[("user-agent", "Mozilla/5.0")]).await;
    assert_eq!(fine, StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_empty_ruleset_turns_the_waf_off() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    let proxy = spawn_proxy(origin, "    waf:\n      rulesets: []\n").await;

    let (status, _) = get(proxy, "/search?id=1%20union%20select%20password").await;

    assert_eq!(status, StatusCode::OK, "the waf should have been off");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_zone_can_add_its_own_rule() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    let waf = "    waf:\n      \
                 rules:\n        \
                 - id: no-admin\n          \
                   expression: 'http.request.uri.path contains \"/admin\"'\n          \
                   action: block\n";
    let proxy = spawn_proxy(origin, waf).await;

    assert_eq!(get(proxy, "/admin/login").await.0, StatusCode::FORBIDDEN);
    assert_eq!(get(proxy, "/login").await.0, StatusCode::OK);
}

#[tokio::test]
async fn bodies_are_not_read_when_no_rule_asks_for_them() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    /* core is head-only, so this body should pass straight through uninspected */
    let proxy = spawn_proxy(origin, "").await;

    let (status, body) = send(proxy, "POST", "/submit", "q=1 union select 1", &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("18 body bytes"), "origin reported: {body}");
}

#[tokio::test]
async fn body_rules_catch_a_posted_payload() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    let proxy = spawn_proxy(origin, "    waf:\n      rulesets: [core, core-body]\n").await;

    let (blocked, _) = send(proxy, "POST", "/submit", "q=1 union select 1", &[]).await;
    assert_eq!(blocked, StatusCode::FORBIDDEN);
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    let (fine, body) = send(proxy, "POST", "/submit", "q=sourdough starter", &[]).await;
    assert_eq!(fine, StatusCode::OK);
    assert!(body.contains("19 body bytes"), "origin reported: {body}");
}

#[tokio::test]
async fn an_oversized_body_still_reaches_the_origin_whole() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    let proxy = spawn_proxy(
        origin,
        "    waf:\n      rulesets: [core-body]\n      max_body_bytes: 64\n",
    )
    .await;

    let payload = "sourdough ".repeat(200); /* 2000 bytes, well past the cap */
    let (status, body) = send(proxy, "POST", "/submit", &payload, &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(&format!("{} body bytes", payload.len())),
        "the origin should have received every byte, it reported: {body}"
    );
}

#[tokio::test]
async fn an_oversized_body_can_be_made_to_fail_closed() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    let proxy = spawn_proxy(
        origin,
        "    waf:\n      rulesets: [core-body]\n      max_body_bytes: 64\n      on_oversized_body: block\n",
    )
    .await;

    let payload = "sourdough ".repeat(200);
    let (status, _) = send(proxy, "POST", "/submit", &payload, &[]).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    /* a body under the cap is unaffected */
    let (small, _) = send(proxy, "POST", "/submit", "tiny", &[]).await;
    assert_eq!(small, StatusCode::OK);
}

#[tokio::test]
async fn an_attack_inside_an_oversized_body_is_still_caught_in_the_first_chunk() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;
    let proxy = spawn_proxy(
        origin,
        "    waf:\n      rulesets: [core-body]\n      max_body_bytes: 64\n",
    )
    .await;

    let payload = format!("q=1 union select 1{}", "&pad=x".repeat(500));
    let (status, _) = send(proxy, "POST", "/submit", &payload, &[]).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_bad_rule_is_refused_at_config_load() {
    let bad = "zones:\n  \
               - name: demo\n    \
                 hostnames: [\"demo.local\"]\n    \
                 origin:\n      url: \"http://127.0.0.1:9\"\n    \
                 waf:\n      \
                   rules:\n        \
                   - id: nonsense\n          \
                     expression: 'made.up.field eq \"x\"'\n          \
                     action: block\n";

    let err = config::parse(bad).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("nonsense"), "should name the rule: {msg}");
    assert!(msg.contains("unknown field"), "should explain why: {msg}");
}
