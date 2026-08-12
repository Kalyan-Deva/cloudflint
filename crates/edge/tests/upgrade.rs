//! Connection upgrades.
//!
//! `Upgrade` and `Connection` are single-hop headers, so stripping them is normally
//! right - but doing it to an upgrade request kills the very thing it is asking for.
//! Anything built on Upgrade, websockets included, used to break outright behind
//! this proxy.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use cloudveil_edge::snapshot::Snapshot;
use cloudveil_edge::{config, serve, Edge};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An origin that accepts an upgrade and then talks a toy line protocol: it echoes
/// whatever it is sent, in upper case.
async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|mut req: Request<Incoming>| async move {
                    if req.headers().get("upgrade").is_none() {
                        return Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                            "ordinary response",
                        ))));
                    }

                    /* take the upgrade, then answer 101 so hyper performs it */
                    tokio::spawn(async move {
                        let Ok(upgraded) = hyper::upgrade::on(&mut req).await else {
                            return;
                        };
                        let mut io = TokioIo::new(upgraded);
                        let mut buf = [0u8; 256];
                        loop {
                            match io.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    let shout = buf[..n].to_ascii_uppercase();
                                    if io.write_all(&shout).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });

                    Ok(Response::builder()
                        .status(StatusCode::SWITCHING_PROTOCOLS)
                        .header("upgrade", "echo")
                        .header("connection", "Upgrade")
                        .header("x-origin-agreed", "yes")
                        .body(Full::new(Bytes::new()))
                        .unwrap())
                });

                let _ = http1::Builder::new()
                    .serve_connection(io, svc)
                    .with_upgrades()
                    .await;
            });
        }
    });
    addr
}

async fn spawn_proxy(origin: SocketAddr) -> SocketAddr {
    let yaml = format!(
        "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    \
           origin:\n      url: \"http://{origin}\"\n    \
           waf:\n      rulesets: []\n"
    );
    let cfg = config::parse(&yaml).expect("config should parse");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, Edge::new(Arc::new(Snapshot::new(cfg)))).await;
    });
    addr
}

#[tokio::test]
async fn an_upgrade_survives_the_proxy_and_bytes_flow_both_ways() {
    let proxy = spawn_proxy(spawn_origin().await).await;

    let stream = TcpStream::connect(proxy).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("handshake");
    tokio::spawn(conn.with_upgrades());

    let req = Request::builder()
        .uri("/socket")
        .header("host", "demo.local")
        .header("connection", "Upgrade")
        .header("upgrade", "echo")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp = send.send_request(req).await.expect("proxy should answer");

    assert_eq!(
        resp.status(),
        StatusCode::SWITCHING_PROTOCOLS,
        "the proxy should have passed the 101 through"
    );
    assert_eq!(
        resp.headers().get("x-origin-agreed").unwrap(),
        "yes",
        "the origin's own 101 headers should survive"
    );
    assert_eq!(resp.headers().get("upgrade").unwrap(), "echo");


    /* a client takes its upgrade from the response; a server takes it from the
       request. and now it is not http any more - just bytes, both ways */
    let upgraded = hyper::upgrade::on(resp)
        .await
        .expect("client side should upgrade");
    let mut io = TokioIo::new(upgraded);

    io.write_all(b"hello through the veil").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = io.read(&mut buf).await.unwrap();

    assert_eq!(
        String::from_utf8_lossy(&buf[..n]),
        "HELLO THROUGH THE VEIL",
        "the origin should have seen our bytes and answered"
    );
}

#[tokio::test]
async fn an_ordinary_request_on_the_same_zone_is_unaffected() {
    let proxy = spawn_proxy(spawn_origin().await).await;

    let stream = TcpStream::connect(proxy).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);

    let req = Request::builder()
        .uri("/plain")
        .header("host", "demo.local")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp = send.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    /* hop-by-hop stripping still applies to everything that is not an upgrade */
    assert!(
        resp.headers().get("upgrade").is_none(),
        "a plain response should carry no upgrade header"
    );

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(String::from_utf8_lossy(&body), "ordinary response");
}
