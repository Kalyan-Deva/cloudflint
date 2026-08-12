//! The whole loop, with both halves actually running.
//!
//! Control plane holds the config, edge pulls it, traffic flows, events come back,
//! a purge goes out to the edge and empties its cache.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body as AxumBody;
use axum::http::Request as AxumRequest;
use cloudveil_api::db::Db;
use cloudveil_api::{router, Api};
use cloudveil_edge::snapshot::{self, Snapshot};
use cloudveil_edge::{admin, config, serve, Edge};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{json, Value};
use tokio::net::TcpListener;

async fn spawn_origin(hits: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let hits = hits.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let hits = hits.clone();
                    async move {
                        let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("cache-control", "max-age=300")
                                .body(Full::new(Bytes::from(format!("origin #{n}"))))
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

async fn spawn_control_plane(edges: Vec<String>) -> (SocketAddr, Db) {
    let db = Db::open(":memory:").expect("in-memory db");
    let api = Api {
        db: db.clone(),
        edges: Arc::new(edges),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(api)).await;
    });
    (addr, db)
}

fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

async fn get(addr: SocketAddr, host: &str, path: &str) -> (StatusCode, String, Option<String>) {
    let req = Request::builder()
        .uri(format!("http://{addr}{path}"))
        .header("host", host)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.expect("should answer");
    let status = resp.status();
    let cache = resp
        .headers()
        .get("cloudveil-cache")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned(), cache)
}

/// Talk to the control plane over a real socket, same as the edge does.
async fn api_call(addr: SocketAddr, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let payload = body.map(|v| serde_json::to_vec(&v).unwrap()).unwrap_or_default();
    let req = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(payload)))
        .unwrap();

    let resp = client().request(req).await.expect("control plane should answer");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn until(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

#[tokio::test]
async fn the_edge_pulls_its_config_and_reports_back() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;

    /* the edge's admin port has to be known before the control plane starts, so it
       can be told where to send purges */
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    let (api_addr, _db) = spawn_control_plane(vec![format!("http://{admin_addr}")]).await;

    /* the real config lives in the control plane */
    let real = format!(
        "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://{origin}\"\n    waf:\n      rulesets: []\n"
    );
    let (status, _) = api_call(
        api_addr,
        "PUT",
        "/v1/config",
        Some(json!({ "yaml": real, "note": "from the test" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    /* the edge boots on a placeholder that serves a different host entirely */
    let bootstrap = format!(
        "control_plane: \"http://{api_addr}\"\nzones:\n  - name: placeholder\n    hostnames: [\"nothing.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n"
    );
    let snap = Arc::new(Snapshot::new(config::parse(&bootstrap).unwrap()));
    let edge = Edge::new(snap.clone());
    snapshot::watch_remote(
        format!("http://{api_addr}"),
        snap.clone(),
        Duration::from_millis(50),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_addr = listener.local_addr().unwrap();
    {
        let edge = edge.clone();
        tokio::spawn(async move {
            let _ = serve(listener, edge).await;
        });
    }
    {
        let edge = edge.clone();
        tokio::spawn(async move {
            let _ = admin::serve(admin_listener, edge).await;
        });
    }

    /* before the pull lands, demo.local is not a zone this edge knows */
    assert_eq!(get(edge_addr, "demo.local", "/p").await.0, StatusCode::NOT_FOUND);

    let pulled = {
        let snap = snap.clone();
        until(move || snap.current().zone_for("demo.local").is_some()).await
    };
    assert!(pulled, "the edge never pulled the config from the control plane");

    /* and now it serves it */
    let (status, body, cache) = get(edge_addr, "demo.local", "/p").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "origin #1");
    assert_eq!(cache.as_deref(), Some("MISS"));

    tokio::time::sleep(Duration::from_millis(50)).await;
    let (_, body, cache) = get(edge_addr, "demo.local", "/p").await;
    assert_eq!(cache.as_deref(), Some("HIT"));
    assert_eq!(body, "origin #1");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    /* events are batched once a second, so give the flusher a beat */
    let summary_has_traffic = {
        let mut seen = false;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let (_, s) = api_call(api_addr, "GET", "/v1/analytics/summary?since_mins=60", None).await;
            if s["requests"].as_u64().unwrap_or(0) >= 2 {
                assert!(s["cache_hits"].as_u64().unwrap() >= 1, "summary: {s}");
                seen = true;
                break;
            }
        }
        seen
    };
    assert!(summary_has_traffic, "the control plane never received any events");

    /* a purge from the control plane has to reach the data plane's cache */
    let (status, body) = api_call(
        api_addr,
        "POST",
        "/v1/purge",
        Some(json!({ "url": "http://demo.local/p" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "purge reported: {body}");
    assert_eq!(body["edges"][0]["ok"], true);

    let (_, body, cache) = get(edge_addr, "demo.local", "/p").await;
    assert_eq!(cache.as_deref(), Some("MISS"), "the entry should have been purged");
    assert_eq!(body, "origin #2");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_control_plane_that_goes_away_does_not_take_traffic_with_it() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;

    /* a control plane url that answers nothing at all */
    let yaml = format!(
        "control_plane: \"http://127.0.0.1:9\"\nzones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://{origin}\"\n    waf:\n      rulesets: []\n"
    );
    let snap = Arc::new(Snapshot::new(config::parse(&yaml).unwrap()));
    let edge = Edge::new(snap.clone());
    snapshot::watch_remote(
        "http://127.0.0.1:9".to_string(),
        snap.clone(),
        Duration::from_millis(20),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, edge).await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    let (status, body, _) = get(addr, "demo.local", "/p").await;
    assert_eq!(status, StatusCode::OK, "an unreachable control plane must not stop traffic");
    assert_eq!(body, "origin #1");
}

#[tokio::test]
async fn the_admin_api_reports_what_the_edge_is_holding() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(hits.clone()).await;

    let yaml = format!(
        "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://{origin}\"\n    waf:\n      rulesets: []\n"
    );
    let snap = Arc::new(Snapshot::new(config::parse(&yaml).unwrap()));
    let edge = Edge::new(snap);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    {
        let edge = edge.clone();
        tokio::spawn(async move {
            let _ = serve(listener, edge).await;
        });
    }
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = admin::serve(admin_listener, edge).await;
    });

    get(proxy, "demo.local", "/one").await;
    get(proxy, "demo.local", "/two").await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status, stats) = api_call(admin_addr, "GET", "/admin/stats", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stats["zones"], 1);
    assert_eq!(stats["cache"]["entries"], 2);
    assert_eq!(stats["events"]["seen"], 2);

    let (_, recent) = api_call(admin_addr, "GET", "/admin/recent?limit=1", None).await;
    let recent = recent.as_array().unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0]["path"], "/two", "newest first");
    assert_eq!(recent[0]["zone"], "demo");

    /* purge by zone, straight at the edge */
    let (status, body) = api_call(
        admin_addr,
        "POST",
        "/admin/purge",
        Some(json!({ "zone": "demo" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["removed"], 2);

    let (_, stats) = api_call(admin_addr, "GET", "/admin/stats", None).await;
    assert_eq!(stats["cache"]["entries"], 0);
    assert_eq!(stats["cache"]["bytes"], 0);
}

#[tokio::test]
async fn a_purge_naming_nothing_useful_is_refused() {
    let yaml = "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n";
    let snap = Arc::new(Snapshot::new(config::parse(yaml).unwrap()));
    let edge = Edge::new(snap);

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = admin::serve(admin_listener, edge).await;
    });

    let (status, body) = api_call(admin_addr, "POST", "/admin/purge", Some(json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("exactly one"));

    let (status, body) = api_call(
        admin_addr,
        "POST",
        "/admin/purge",
        Some(json!({ "url": "http://nobody.local/x" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("no zone serves"));
}

/// Keeps the unused-import warning honest about AxumBody/AxumRequest.
#[tokio::test]
async fn the_router_answers_health_in_process() {
    use tower::ServiceExt;

    let (_, db) = (0, Db::open(":memory:").unwrap());
    let app = router(Api {
        db,
        edges: Arc::new(vec![]),
    });
    let resp = app
        .oneshot(
            AxumRequest::builder()
                .uri("/health")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
