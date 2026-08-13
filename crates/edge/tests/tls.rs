//! HTTPS end to end, with a real handshake against a real certificate.
//!
//! These drive the connection by hand rather than through a pooled client - it is
//! less code than teaching hyper-util's connector about rustls, and it lets the
//! tests assert on what ALPN actually settled on.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use cloudflint_edge::snapshot::Snapshot;
use cloudflint_edge::tls::{install_crypto_provider, Tls};
use cloudflint_edge::{config, serve, serve_redirect, serve_tls, Edge};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// Origin that reports back what the proxy told it about the connection.
async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let proto = req
                        .headers()
                        .get("x-forwarded-proto")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-")
                        .to_owned();
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                        "origin saw proto={proto}"
                    )))))
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

struct Certs {
    dir: PathBuf,
    cert: String,
    key: String,
}

/// A clock is not enough on Windows, where its resolution is coarse enough that two
/// tests starting together get the same "unique" directory and quietly overwrite
/// each other's certificates.
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn make_certs(tag: &str, names: &[&str]) -> Certs {
    let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "cloudflint-tlsint-{tag}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let generated =
        rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    let cert = dir.join("edge.crt");
    let key = dir.join("edge.key");
    std::fs::write(&cert, generated.cert.pem()).unwrap();
    std::fs::write(&key, generated.signing_key.serialize_pem()).unwrap();

    Certs {
        cert: cert.display().to_string().replace('\\', "/"),
        key: key.display().to_string().replace('\\', "/"),
        dir,
    }
}

/// Trusts exactly the cert we just made and nothing else.
fn client_config(cert_pem: &str, alpn: &[&[u8]]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert_pem).unwrap(),
    )) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg
}

async fn connect(addr: SocketAddr, name: &str, cfg: rustls::ClientConfig) -> TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap();
    TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .expect("handshake should succeed")
}

struct Running {
    https: SocketAddr,
    http: SocketAddr,
    certs: Certs,
}

impl Running {
    fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.certs.dir);
    }
}

async fn start(redirect: bool) -> Running {
    install_crypto_provider();
    let origin = spawn_origin().await;
    let certs = make_certs("e2e", &["demo.local", "localhost"]);

    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http.local_addr().unwrap();
    let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_addr = https.local_addr().unwrap();

    let yaml = format!(
        "listen: \"{http_addr}\"\n\
         tls:\n  listen: \"{https_addr}\"\n  redirect_http: {redirect}\n\
         zones:\n  - name: demo\n    hostnames: [\"demo.local\", \"localhost\"]\n    \
           origin:\n      url: \"http://{origin}\"\n    \
           waf:\n      rulesets: []\n    \
           cache:\n      enabled: false\n    \
           tls:\n      cert: \"{}\"\n      key: \"{}\"\n",
        certs.cert, certs.key
    );
    let cfg = config::parse(&yaml).expect("config should parse");
    let tls = Arc::new(Tls::new(&cfg).unwrap().expect("tls should be configured"));
    let edge = Edge::with_tls(Arc::new(Snapshot::new(cfg)), Some(tls));

    {
        let edge = edge.clone();
        tokio::spawn(async move {
            let _ = serve_tls(https, edge).await;
        });
    }
    if redirect {
        let port = https_addr.port();
        let shutdown = edge.shutdown.clone();
        let challenges = edge.challenges.clone();
        tokio::spawn(async move {
            let _ = serve_redirect(http, port, shutdown, challenges).await;
        });
    } else {
        let edge = edge.clone();
        tokio::spawn(async move {
            let _ = serve(http, edge).await;
        });
    }

    Running {
        https: https_addr,
        http: http_addr,
        certs,
    }
}

async fn get_over_h1(run: &Running, path: &str) -> (StatusCode, String) {
    let stream = connect(run.https, "localhost", client_config(&run.certs.cert, &[b"http/1.1"])).await;
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(&b"http/1.1"[..]),
        "expected http/1.1"
    );

    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("h1 handshake");
    tokio::spawn(conn);

    let req = Request::builder()
        .uri(path)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = send.send_request(req).await.expect("request");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn serves_https_and_tells_the_origin_so() {
    let run = start(false).await;

    let (status, body) = get_over_h1(&run, "/page").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body, "origin saw proto=https",
        "the origin should be told the client used https"
    );
    run.cleanup();
}

#[tokio::test]
async fn plaintext_still_says_http() {
    let run = start(false).await;
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/page", run.http))
        .header("host", "demo.local")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp = client.request(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(String::from_utf8_lossy(&body), "origin saw proto=http");
    run.cleanup();
}

#[tokio::test]
async fn the_plaintext_listener_can_redirect_instead() {
    let run = start(true).await;
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/page?a=1", run.http))
        .header("host", "demo.local")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        &format!("https://demo.local:{}/page?a=1", run.https.port())
    );
    run.cleanup();
}

/// ALPN should settle on h2 when the client offers it, and the edge should speak it.
#[tokio::test]
async fn negotiates_http2() {
    let run = start(false).await;
    let stream = connect(run.https, "localhost", client_config(&run.certs.cert, &[b"h2"])).await;

    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "the edge should have agreed to http/2"
    );

    let (mut send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("h2 handshake");
    tokio::spawn(conn);

    let req = Request::builder()
        .uri("https://localhost/page")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = send.send_request(req).await.expect("h2 request");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(String::from_utf8_lossy(&body), "origin saw proto=https");
    run.cleanup();
}

/// A name we hold no certificate for still gets one, so the client sees an honest
/// 404 from the proxy rather than a confusing handshake failure.
#[tokio::test]
async fn an_unknown_hostname_still_gets_a_certificate() {
    let run = start(false).await;

    let mut cfg = client_config(&run.certs.cert, &[b"http/1.1"]);
    cfg.enable_sni = true;

    let tcp = TcpStream::connect(run.https).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("elsewhere.local").unwrap();
    let attempt = TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await;

    /* it fails on our side, verifying the name - which means the server did offer
       a certificate rather than aborting with no_certificate */
    let err = attempt.expect_err("a cert for the wrong name should not verify");
    let message = err.to_string();
    assert!(
        message.contains("NotValidForName") || message.contains("not valid for name"),
        "expected a name mismatch, got: {message}"
    );
    run.cleanup();
}

#[tokio::test]
async fn the_waf_can_see_that_a_request_arrived_over_https() {
    install_crypto_provider();
    let origin = spawn_origin().await;
    let certs = make_certs("wafssl", &["localhost"]);

    let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_addr = https.local_addr().unwrap();

    /* `ssl` used to be rejected at parse time as "not available yet" */
    let yaml = format!(
        "listen: \"127.0.0.1:0\"\n\
         tls:\n  listen: \"{https_addr}\"\n\
         zones:\n  - name: demo\n    hostnames: [\"localhost\"]\n    \
           origin:\n      url: \"http://{origin}\"\n    \
           cache:\n      enabled: false\n    \
           tls:\n      cert: \"{}\"\n      key: \"{}\"\n    \
           waf:\n      rulesets: []\n      rules:\n        \
             - id: only-over-tls\n          expression: 'not ssl'\n          action: block\n",
        certs.cert, certs.key
    );
    let cfg = config::parse(&yaml).expect("`ssl` should now be a real field");
    let tls = Arc::new(Tls::new(&cfg).unwrap().unwrap());
    let edge = Edge::with_tls(Arc::new(Snapshot::new(cfg)), Some(tls));

    tokio::spawn(async move {
        let _ = serve_tls(https, edge).await;
    });

    let run = Running {
        https: https_addr,
        http: https_addr,
        certs,
    };
    let (status, _) = get_over_h1(&run, "/page").await;

    assert_eq!(status, StatusCode::OK, "https should not be blocked by `not ssl`");
    run.cleanup();
}
