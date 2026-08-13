//! Stopping, with real sockets.
//!
//! The unit tests in `shutdown` cover the bookkeeping. What matters here is what a
//! client sees: a request already in flight when the signal lands must still be
//! answered, a new connection must not be, and the process must not be held open by
//! either.

use std::convert::Infallible;
use std::net::SocketAddr;
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

const TOKEN: &str = "cv_shutdowntoken0123456789abcdef0123456789abcdef0123456789ab";

/// An origin that takes its time, so a request can still be in flight when the signal
/// arrives.
async fn spawn_origin(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| async move {
                    tokio::time::sleep(delay).await;
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("slow but sure"))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

fn zone_yaml(origin: SocketAddr) -> String {
    format!(
        "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    \
         origin:\n      url: \"http://{origin}\"\n    cache:\n      enabled: false\n"
    )
}

async fn spawn_edge(origin: SocketAddr) -> (Arc<Edge>, SocketAddr) {
    let cfg = config::parse(&zone_yaml(origin)).expect("test config should parse");
    let edge = Edge::new(Arc::new(Snapshot::new(cfg)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    {
        let edge = edge.clone();
        tokio::spawn(async move {
            let _ = serve(listener, edge).await;
        });
    }
    (edge, addr)
}

fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

fn request(addr: SocketAddr, path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(format!("http://{addr}{path}"))
        .header("host", "demo.local")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

#[tokio::test]
async fn a_request_in_flight_is_still_answered() {
    let origin = spawn_origin(Duration::from_millis(300)).await;
    let (edge, addr) = spawn_edge(origin).await;

    let inflight = tokio::spawn(async move { client().request(request(addr, "/slow")).await });

    /* long enough for the request to be on its way to the origin */
    tokio::time::sleep(Duration::from_millis(60)).await;
    edge.shutdown.begin("test");

    let resp = inflight
        .await
        .expect("the request task should not panic")
        .expect("a request already in flight must still get an answer");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"slow but sure");

    /* and the drain sees it finish rather than timing out */
    assert!(
        edge.shutdown.drain(Duration::from_secs(5)).await,
        "the connection should have closed itself once the response was written"
    );
}

#[tokio::test]
async fn nothing_new_is_accepted_once_draining() {
    let origin = spawn_origin(Duration::from_millis(10)).await;
    let (edge, addr) = spawn_edge(origin).await;

    /* prove the listener works first, or the assertion below proves nothing */
    let resp = client().request(request(addr, "/")).await.expect("should answer");
    assert_eq!(resp.status(), StatusCode::OK);
    /* drain the body so this connection is finished with and can be reused or closed */
    let _ = resp.into_body().collect().await;

    edge.shutdown.begin("test");
    edge.shutdown.drain(Duration::from_secs(5)).await;

    /* the listener is closed, so this is a connection refused rather than a response.
       a fresh client, since a pooled connection would not need to connect at all */
    let refused = client().request(request(addr, "/")).await;
    assert!(refused.is_err(), "the listener should be closed by now");
}

#[tokio::test]
async fn a_keep_alive_connection_is_closed_rather_than_left_open() {
    let origin = spawn_origin(Duration::from_millis(10)).await;
    let (edge, addr) = spawn_edge(origin).await;

    /* one client, reused, so the connection is still open and idle afterwards */
    let client = client();
    let resp = client.request(request(addr, "/")).await.expect("should answer");
    let _ = resp.into_body().collect().await;

    edge.shutdown.begin("test");

    /* if the idle connection were left open, this would sit here until the deadline */
    assert!(
        edge.shutdown.drain(Duration::from_secs(5)).await,
        "an idle keep-alive connection should be closed by the drain, not waited on"
    );
}

#[tokio::test]
async fn health_says_draining_before_anything_is_torn_down() {
    let origin = spawn_origin(Duration::from_millis(10)).await;
    let (edge, _) = spawn_edge(origin).await;

    std::env::set_var(admin::TOKEN_VAR, TOKEN);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = listener.local_addr().unwrap();
    {
        let edge = edge.clone();
        tokio::spawn(async move {
            let _ = admin::serve(listener, edge).await;
        });
    }

    let health = |addr: SocketAddr| async move {
        let req = Request::builder()
            .uri(format!("http://{addr}/admin/health"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client().request(req).await.expect("health should answer");
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    };

    let (status, body) = health(admin_addr).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#""status":"ok""#), "health said {body}");

    edge.shutdown.begin("test");

    /* the load balancer has to be told to look away first - so this flips as soon as
       the signal lands, not when the last connection goes */
    let (status, body) = health(admin_addr).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains(r#""status":"draining""#), "health said {body}");

    let scrape = Request::builder()
        .uri(format!("http://{admin_addr}/metrics"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(scrape).await.expect("metrics should answer");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("\ncloudveil_draining 1\n"),
        "a scrape should show the node draining too"
    );
}
