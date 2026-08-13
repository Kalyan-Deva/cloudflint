//! End to end: real origins, real proxy, real sockets.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cloudflint_edge::snapshot::{self, Snapshot};
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

const TICK: Duration = Duration::from_millis(20);

/// Origin that reports back who it is and what the proxy sent it.
async fn echo(tag: &'static str, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let get = |k: &str| {
        req.headers()
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_owned()
    };
    let body = format!(
        "origin={tag} path={} host={} xff={} xfh={} xfp={}",
        req.uri().path(),
        get("host"),
        get("x-forwarded-for"),
        get("x-forwarded-host"),
        get("x-forwarded-proto"),
    );
    Ok(Response::builder()
        .header("x-origin", tag)
        .header("trailer", "x-should-be-stripped") /* hop-by-hop */
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

async fn spawn_origin(tag: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = http1::Builder::new()
                    .serve_connection(io, service_fn(move |req| echo(tag, req)))
                    .await;
            });
        }
    });
    addr
}

/// An origin stuck on HTTP/1.0 - python's http.server is the one everybody meets.
async fn spawn_old_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .version(hyper::Version::HTTP_10)
                            .body(Full::new(Bytes::from("old")))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

fn zone_yaml(origin: SocketAddr, preserve_host: bool) -> String {
    format!(
        "zones:\n  \
         - name: demo\n    \
           hostnames: [\"demo.local\"]\n    \
           origin:\n      \
             url: \"http://{origin}\"\n      \
             preserve_host: {preserve_host}\n"
    )
}

async fn start(snap: Arc<Snapshot>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, Edge::new(snap)).await;
    });
    addr
}

async fn spawn_proxy(origin: SocketAddr, preserve_host: bool) -> SocketAddr {
    let cfg = config::parse(&zone_yaml(origin, preserve_host)).expect("test config should parse");
    start(Arc::new(Snapshot::new(cfg))).await
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
    let origin = spawn_origin("a").await;
    let proxy = spawn_proxy(origin, true).await;

    let (status, headers, body) = get(proxy, "demo.local", "/hello?a=1").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("path=/hello"), "body was {body}");
    assert!(body.contains("xfh=demo.local"), "body was {body}");
    assert!(body.contains("xff=127.0.0.1"), "body was {body}");
    assert!(body.contains("xfp=http"), "body was {body}");
    assert_eq!(headers.get("x-origin").unwrap(), "a");
    assert_eq!(headers.get("server").unwrap(), "cloudflint");
}

#[tokio::test]
async fn preserves_the_client_host_by_default() {
    let origin = spawn_origin("a").await;
    let proxy = spawn_proxy(origin, true).await;

    let (_, _, body) = get(proxy, "demo.local", "/").await;
    assert!(body.contains("host=demo.local"), "body was {body}");
}

#[tokio::test]
async fn rewrites_host_when_asked() {
    let origin = spawn_origin("a").await;
    let proxy = spawn_proxy(origin, false).await;

    let (_, _, body) = get(proxy, "demo.local", "/").await;
    assert!(body.contains(&format!("host={origin}")), "body was {body}");
}

#[tokio::test]
async fn strips_hop_by_hop_from_the_response() {
    let origin = spawn_origin("a").await;
    let proxy = spawn_proxy(origin, true).await;

    let (_, headers, _) = get(proxy, "demo.local", "/").await;
    assert!(headers.get("trailer").is_none(), "hop-by-hop header leaked through");
}

#[tokio::test]
async fn unknown_host_gets_404() {
    let origin = spawn_origin("a").await;
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

#[tokio::test]
async fn answers_the_client_in_the_clients_own_http_version() {
    /* the version belongs to the hop, not to the message. Forwarding the origin's meant
       a 1.0 backend downgraded the client's connection too, and since Connection is
       stripped as hop-by-hop a 1.0 response with no keep-alive header ends the
       connection - so every proxied response cost a fresh handshake */
    let origin = spawn_old_origin().await;
    let proxy = spawn_proxy(origin, true).await;

    let req = Request::builder()
        .uri(format!("http://{proxy}/"))
        .header("host", "demo.local")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client().request(req).await.expect("proxy should answer");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.version(),
        hyper::Version::HTTP_11,
        "the origin's HTTP/1.0 leaked out to the client"
    );
}

#[tokio::test]
async fn moves_traffic_to_a_new_origin_on_reload() {
    let a = spawn_origin("a").await;
    let b = spawn_origin("b").await;

    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path: PathBuf = std::env::temp_dir().join(format!("cloudflint-e2e-{unique}.yaml"));
    std::fs::write(&path, zone_yaml(a, true)).unwrap();

    let snap = Arc::new(Snapshot::new(config::load(&path).unwrap()));
    snapshot::watch_every(path.clone(), snap.clone(), TICK);
    let proxy = start(snap).await;

    let (_, _, body) = get(proxy, "demo.local", "/").await;
    assert!(body.contains("origin=a"), "body was {body}");

    std::fs::write(&path, zone_yaml(b, true)).unwrap();

    let mut moved = false;
    for _ in 0..100 {
        tokio::time::sleep(TICK).await;
        let (_, _, body) = get(proxy, "demo.local", "/").await;
        if body.contains("origin=b") {
            moved = true;
            break;
        }
    }
    assert!(moved, "traffic never moved to the reloaded origin");

    let _ = std::fs::remove_file(&path);
}
