//! End to end: real origin, real proxy, real sockets.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use cloudveil_edge::{config, serve};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

/// Origin that reports back what the proxy sent it.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let get = |k: &str| {
        req.headers()
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_owned()
    };
    let body = format!(
        "path={} host={} xff={} xfh={} xfp={}",
        req.uri().path(),
        get("host"),
        get("x-forwarded-for"),
        get("x-forwarded-host"),
        get("x-forwarded-proto"),
    );
    Ok(Response::builder()
        .header("x-origin", "yes")
        .header("trailer", "x-should-be-stripped") /* hop-by-hop */
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = http1::Builder::new()
                    .serve_connection(io, service_fn(echo))
                    .await;
            });
        }
    });
    addr
}

async fn spawn_proxy(origin: SocketAddr, preserve_host: bool) -> SocketAddr {
    let text = format!(
        "zones:\n  \
         - name: demo\n    \
           hostnames: [\"demo.local\"]\n    \
           origin:\n      \
             url: \"http://{origin}\"\n      \
             preserve_host: {preserve_host}\n"
    );
    let cfg = Arc::new(config::parse(&text).expect("test config should parse"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, cfg).await;
    });
    addr
}

fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

async fn get(proxy: SocketAddr, host: &str, path: &str) -> (StatusCode, hyper::HeaderMap, String) {
    let req = Request::builder()
        .uri(format!("http://{proxy}{path}"))
        .header("host", host)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.expect("proxy should answer");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn forwards_to_the_origin() {
    let origin = spawn_origin().await;
    let proxy = spawn_proxy(origin, true).await;

    let (status, headers, body) = get(proxy, "demo.local", "/hello?a=1").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("path=/hello"), "body was {body}");
    assert!(body.contains("xfh=demo.local"), "body was {body}");
    assert!(body.contains("xff=127.0.0.1"), "body was {body}");
    assert!(body.contains("xfp=http"), "body was {body}");
    assert_eq!(headers.get("x-origin").unwrap(), "yes");
    assert_eq!(headers.get("server").unwrap(), "cloudveil");
}

#[tokio::test]
async fn preserves_the_client_host_by_default() {
    let origin = spawn_origin().await;
    let proxy = spawn_proxy(origin, true).await;

    let (_, _, body) = get(proxy, "demo.local", "/").await;
    assert!(body.contains("host=demo.local"), "body was {body}");
}

#[tokio::test]
async fn rewrites_host_when_asked() {
    let origin = spawn_origin().await;
    let proxy = spawn_proxy(origin, false).await;

    let (_, _, body) = get(proxy, "demo.local", "/").await;
    assert!(body.contains(&format!("host={origin}")), "body was {body}");
}

#[tokio::test]
async fn strips_hop_by_hop_from_the_response() {
    let origin = spawn_origin().await;
    let proxy = spawn_proxy(origin, true).await;

    let (_, headers, _) = get(proxy, "demo.local", "/").await;
    assert!(headers.get("trailer").is_none(), "hop-by-hop header leaked through");
}

#[tokio::test]
async fn unknown_host_gets_404() {
    let origin = spawn_origin().await;
    let proxy = spawn_proxy(origin, true).await;

    let (status, _, body) = get(proxy, "nobody.local", "/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("no zone"), "body was {body}");
}

#[tokio::test]
async fn dead_origin_gets_502() {
    /* bind then drop, so the port is almost certainly closed */
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let proxy = spawn_proxy(dead, true).await;

    let (status, _, _) = get(proxy, "demo.local", "/").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}
