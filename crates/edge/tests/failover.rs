//! Origins dying, with real sockets.
//!
//! The unit tests in `origins` cover the health bookkeeping. These are about what a
//! client sees when a backend goes away: that it keeps getting answers, that the dead
//! origin stops being asked, that a request nobody could safely repeat is not repeated,
//! and that an origin coming back is noticed without anybody having to walk into it.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

const TOKEN: &str = "cv_failovertoken0123456789abcdef0123456789abcdef0123456789ab";

/// An origin that says which one it is, counts what it received, and can be told to
/// start failing without closing its listener.
struct Backend {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    sick: Arc<AtomicBool>,
    /// Milliseconds to dawdle before answering, so a request can be caught in flight.
    slow: Arc<AtomicUsize>,
}

async fn spawn_backend(tag: &'static str) -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let sick = Arc::new(AtomicBool::new(false));
    let slow = Arc::new(AtomicUsize::new(0));

    {
        let hits = hits.clone();
        let sick = sick.clone();
        let slow = slow.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let hits = hits.clone();
                let sick = sick.clone();
                let slow = slow.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let hits = hits.clone();
                        let sick = sick.clone();
                        let slow = slow.clone();
                        async move {
                            hits.fetch_add(1, Ordering::SeqCst);
                            let wait = slow.load(Ordering::SeqCst);
                            if wait > 0 {
                                tokio::time::sleep(Duration::from_millis(wait as u64)).await;
                            }
                            let status = match sick.load(Ordering::SeqCst) {
                                true => StatusCode::INTERNAL_SERVER_ERROR,
                                false => StatusCode::OK,
                            };
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .header("x-backend", tag)
                                    .body(Full::new(Bytes::from(format!(
                                        "{tag} {}",
                                        req.uri().path()
                                    ))))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
    }

    Backend {
        addr,
        hits,
        sick,
        slow,
    }
}

/// A port nothing is listening on, so connecting to it is refused immediately.
async fn dead_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

fn zone_yaml(origins: &[SocketAddr], policy: &str) -> String {
    let list: String = origins
        .iter()
        .map(|o| format!("      - url: \"http://{o}\"\n"))
        .collect();
    format!(
        "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    \
         origins:\n{list}    origin_policy:\n{policy}    \
         cache:\n      enabled: false\n"
    )
}

async fn spawn_edge(yaml: &str) -> (Arc<Edge>, SocketAddr, SocketAddr) {
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
    {
        let edge = edge.clone();
        tokio::spawn(async move {
            let _ = admin::serve(admin_listener, edge).await;
        });
    }

    (edge, traffic_addr, admin_addr)
}

fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// Returns the status and which backend answered.
async fn get(edge: SocketAddr, path: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .uri(format!("http://{edge}{path}"))
        .header("host", "demo.local")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.expect("the edge should answer");
    let status = resp.status();
    let who = resp
        .headers()
        .get("x-backend")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_owned();
    let _ = resp.into_body().collect().await;
    (status, who)
}

async fn post(edge: SocketAddr, path: &str, body: &str) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{edge}{path}"))
        .header("host", "demo.local")
        .body(Full::new(Bytes::from(body.to_owned())))
        .unwrap();
    client()
        .request(req)
        .await
        .expect("the edge should answer")
        .status()
}

async fn admin_json(admin: SocketAddr, path: &str) -> serde_json::Value {
    let req = Request::builder()
        .uri(format!("http://{admin}{path}"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.expect("admin should answer");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).expect("admin should answer json")
}

async fn scrape(admin: SocketAddr) -> String {
    let req = Request::builder()
        .uri(format!("http://{admin}/metrics"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.expect("admin should answer");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&body).into_owned()
}

#[tokio::test]
async fn a_dead_primary_fails_over_within_the_same_request() {
    let dead = dead_port().await;
    let backup = spawn_backend("backup").await;
    let (_, edge, _) = spawn_edge(&zone_yaml(
        &[dead, backup.addr],
        "      unhealthy_after: 3\n      retry_after_secs: 60\n",
    ))
    .await;

    /* the primary is refused, so the client gets the backup rather than a 502 - and
       gets it on the first request, not the second */
    let (status, who) = get(edge, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who, "backup");
    assert_eq!(backup.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_dead_origin_stops_being_asked() {
    let dead = dead_port().await;
    let backup = spawn_backend("backup").await;
    let (edge_state, edge, admin) = spawn_edge(&zone_yaml(
        &[dead, backup.addr],
        "      unhealthy_after: 2\n      retry_after_secs: 60\n",
    ))
    .await;

    for _ in 0..4 {
        let (status, who) = get(edge, "/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(who, "backup");
    }

    /* two failures took it out, so the last two requests went straight to the backup */
    let cfg = edge_state.snap.current();
    let pool = &cfg.zones[0].origins;
    assert!(!edge_state.origins.is_healthy("demo", &pool.origins[0]));
    assert!(edge_state.origins.is_healthy("demo", &pool.origins[1]));

    let body = scrape(admin).await;
    let dead_series = format!(r#"cloudveil_origin_healthy{{zone="demo",origin="{dead}"}} 0"#);
    assert!(body.contains(&dead_series), "no unhealthy gauge:\n{body}");
    assert!(
        body.contains(r#"cloudveil_origin_failovers_total{zone="demo"}"#),
        "failovers should be counted:\n{body}"
    );
    assert!(
        body.contains(&format!(
            r#"cloudveil_origin_errors_total{{zone="demo",origin="{dead}",kind="unreachable"}}"#
        )),
        "errors should name the origin that failed:\n{body}"
    );
}

#[tokio::test]
async fn a_request_nobody_could_repeat_safely_is_not_repeated() {
    let dead = dead_port().await;
    let backup = spawn_backend("backup").await;
    let (_, edge, _) = spawn_edge(&zone_yaml(
        &[dead, backup.addr],
        "      unhealthy_after: 3\n      retry_after_secs: 60\n",
    ))
    .await;

    /* a POST carries a body we have already streamed and may have been acted on, so it
       fails rather than being sent twice */
    let status = post(edge, "/pay", "amount=100").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        backup.hits.load(Ordering::SeqCst),
        0,
        "a POST must never be replayed against another origin"
    );

    /* but the failure was still noticed, so the next GET goes to the backup */
    let (status, who) = get(edge, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who, "backup");
}

#[tokio::test]
async fn a_5xx_is_the_origins_answer_not_a_failure() {
    let one = spawn_backend("one").await;
    let two = spawn_backend("two").await;
    one.sick.store(true, Ordering::SeqCst);

    let (edge_state, edge, _) = spawn_edge(&zone_yaml(
        &[one.addr, two.addr],
        "      unhealthy_after: 1\n      retry_after_secs: 60\n",
    ))
    .await;

    /* the origin answered, so the client gets the answer - failing over on a 500 would
       double every error the application meant to send */
    let (status, who) = get(edge, "/").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(who, "one");
    assert_eq!(two.hits.load(Ordering::SeqCst), 0);

    let cfg = edge_state.snap.current();
    assert!(
        edge_state
            .origins
            .is_healthy("demo", &cfg.zones[0].origins.origins[0]),
        "a 500 is not a dead backend"
    );
}

#[tokio::test]
async fn round_robin_spreads_requests_across_the_pool() {
    let one = spawn_backend("one").await;
    let two = spawn_backend("two").await;
    let (_, edge, _) = spawn_edge(&zone_yaml(
        &[one.addr, two.addr],
        "      strategy: round_robin\n",
    ))
    .await;

    for _ in 0..6 {
        let (status, _) = get(edge, "/").await;
        assert_eq!(status, StatusCode::OK);
    }

    assert_eq!(one.hits.load(Ordering::SeqCst), 3);
    assert_eq!(two.hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn weighted_sends_traffic_in_proportion() {
    let big = spawn_backend("big").await;
    let small = spawn_backend("small").await;

    let list = format!(
        "      - url: \"http://{}\"\n        weight: 3\n      - url: \"http://{}\"\n        weight: 1\n",
        big.addr, small.addr
    );
    let yaml = format!(
        "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origins:\n{list}    \
         origin_policy:\n      strategy: weighted\n    cache:\n      enabled: false\n"
    );
    let (_, edge, _) = spawn_edge(&yaml).await;

    for _ in 0..8 {
        let (status, _) = get(edge, "/").await;
        assert_eq!(status, StatusCode::OK);
    }

    assert_eq!(big.hits.load(Ordering::SeqCst), 6);
    assert_eq!(small.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn least_connections_avoids_the_busy_origin() {
    let slow = spawn_backend("slow").await;
    let quick = spawn_backend("quick").await;
    slow.slow.store(400, Ordering::SeqCst);

    let (_, edge, _) = spawn_edge(&zone_yaml(
        &[slow.addr, quick.addr],
        "      strategy: least_connections\n",
    ))
    .await;

    /* the first request goes to the first origin - nothing is in flight yet, so there is
       nothing to choose between them - and stays there for 400ms */
    let busy = tokio::spawn(async move { get(edge, "/slow").await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    /* while it is out, the slow origin has one in flight and the quick one none */
    let (status, who) = get(edge, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who, "quick", "a busy backend should not be handed more work");

    let (status, who) = busy.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who, "slow");

    /* and once it is free again, it is a candidate like any other */
    assert_eq!(slow.hits.load(Ordering::SeqCst), 1);
    assert_eq!(quick.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_probe_finds_a_dead_origin_before_anybody_asks() {
    let dead = dead_port().await;
    let backup = spawn_backend("backup").await;
    let (edge_state, _, admin) = spawn_edge(&zone_yaml(
        &[dead, backup.addr],
        "      unhealthy_after: 1\n      retry_after_secs: 60\n      \
         probe:\n        path: /\n        every_secs: 1\n        timeout_ms: 500\n        \
         healthy_after: 1\n",
    ))
    .await;

    /* no traffic at all - the prober is the only thing making requests */
    let cfg = edge_state.snap.current();
    let pool = &cfg.zones[0].origins;
    let mut noticed = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !edge_state.origins.is_healthy("demo", &pool.origins[0]) {
            noticed = true;
            break;
        }
    }
    assert!(noticed, "a probe should have found the dead origin on its own");
    assert!(edge_state.origins.is_healthy("demo", &pool.origins[1]));

    let body = scrape(admin).await;
    assert!(
        body.contains(&format!(
            r#"cloudveil_origin_probes_total{{zone="demo",origin="{dead}",result="failed"}}"#
        )),
        "probe failures should be counted:\n{body}"
    );
    assert!(
        body.contains(&format!(
            r#"cloudveil_origin_probes_total{{zone="demo",origin="{}",result="ok"}}"#,
            backup.addr
        )),
        "and probe successes too:\n{body}"
    );
}

#[tokio::test]
async fn a_probe_brings_an_origin_back_without_a_request_finding_it() {
    let one = spawn_backend("one").await;
    let two = spawn_backend("two").await;
    /* healthy but answering 500, which the probe treats as a failure */
    one.sick.store(true, Ordering::SeqCst);

    let (edge_state, _, _) = spawn_edge(&zone_yaml(
        &[one.addr, two.addr],
        "      unhealthy_after: 1\n      retry_after_secs: 1\n      \
         probe:\n        path: /\n        every_secs: 1\n        timeout_ms: 500\n        \
         healthy_after: 1\n",
    ))
    .await;

    let cfg = edge_state.snap.current();
    let pool = &cfg.zones[0].origins;

    let mut down = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !edge_state.origins.is_healthy("demo", &pool.origins[0]) {
            down = true;
            break;
        }
    }
    assert!(down, "the probe should have taken the sick origin out");

    /* it recovers, and only the prober is there to notice */
    one.sick.store(false, Ordering::SeqCst);
    let mut back = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if edge_state.origins.is_healthy("demo", &pool.origins[0]) {
            back = true;
            break;
        }
    }
    assert!(back, "a recovered origin should come back on its own");
}

#[tokio::test]
async fn the_admin_api_reports_what_a_dashboard_needs() {
    let dead = dead_port().await;
    let backup = spawn_backend("backup").await;
    let (_, edge, admin) = spawn_edge(&zone_yaml(
        &[dead, backup.addr],
        "      unhealthy_after: 1\n      retry_after_secs: 60\n",
    ))
    .await;

    for _ in 0..3 {
        assert_eq!(get(edge, "/").await.0, StatusCode::OK);
    }

    let report = admin_json(admin, "/admin/origins").await;
    let zone = &report["zones"][0];

    assert_eq!(zone["zone"], "demo");
    assert_eq!(zone["strategy"], "first_healthy");
    assert_eq!(zone["failovers"], 1, "one failover, then the dead one was skipped");

    let origins = zone["origins"].as_array().unwrap();
    assert_eq!(origins.len(), 2);
    assert_eq!(origins[0]["healthy"], false, "the dead primary");
    assert_eq!(origins[1]["healthy"], true);

    /* everything that was served came from the backup */
    assert_eq!(origins[1]["requests"], 3);
    assert_eq!(origins[1]["traffic_share"], 75.0, "3 of 4 attempts");
    assert_eq!(origins[1]["errors"], 0);
    assert_eq!(origins[0]["errors"], 1);
    assert!(
        origins[1]["p50_ms"].as_f64().is_some(),
        "a served origin should have a latency estimate: {}",
        origins[1]
    );
    assert!(origins[0]["p95_ms"].is_null() || origins[0]["p95_ms"].as_f64().is_some());

    /* and the failover shows up as an event, not just a count */
    let events = report["recent_failovers"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["from"], dead.to_string());
    assert_eq!(events[0]["to"], backup.addr.to_string());
    assert_eq!(events[0]["zone"], "demo");
    assert!(events[0]["at_ms"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn one_origin_still_behaves_exactly_as_before() {
    let only = spawn_backend("only").await;
    let cfg = format!(
        "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    \
         origin:\n      url: \"http://{}\"\n",
        only.addr
    );
    let (_, edge, _) = spawn_edge(&cfg).await;

    let (status, who) = get(edge, "/hello").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(who, "only");
    assert_eq!(only.hits.load(Ordering::SeqCst), 1);
}
