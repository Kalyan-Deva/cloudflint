//! HTTPS to the origin, with a real TLS origin on a real socket.
//!
//! The point of these is the *refusals*. It is easy to write TLS to an origin that
//! appears to work and validates nothing, and the only way to know the difference is to
//! present a certificate that should be rejected and check that it is.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

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
use tokio_rustls::TlsAcceptor;

/// Windows' clock is too coarse to make unique directory names from, so count instead.
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct Pem {
    dir: PathBuf,
    cert: String,
    key: String,
    /// The certificate again, to hand to whoever has to trust it.
    ca: String,
}

/// A self-signed certificate for `localhost`, plus its own file as a CA.
fn make_cert(tag: &str, name: &str) -> Pem {
    let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "cloudveil-origintls-{tag}-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let made = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    let cert = dir.join("origin.crt");
    let key = dir.join("origin.key");
    std::fs::write(&cert, made.cert.pem()).unwrap();
    std::fs::write(&key, made.signing_key.serialize_pem()).unwrap();

    let path = |p: &PathBuf| p.display().to_string().replace('\\', "/");
    Pem {
        cert: path(&cert),
        key: path(&key),
        ca: path(&cert),
        dir,
    }
}

impl Drop for Pem {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An https origin. With `require_client_cert`, only clients holding a certificate signed
/// by `client_ca` get in - mTLS from the origin's side.
async fn spawn_tls_origin(pem: &Pem, client_ca: Option<&str>) -> SocketAddr {
    cloudveil_edge::tls::install_crypto_provider();

    let chain = cloudveil_edge::cp::load_certs(&pem.cert).unwrap();
    let key = cloudveil_edge::cp::load_key(&pem.key).unwrap();

    let config = match client_ca {
        Some(ca) => rustls::ServerConfig::builder()
            .with_client_cert_verifier(cloudveil_edge::cp::client_verifier(ca).unwrap())
            .with_single_cert(chain, key)
            .unwrap(),
        None => rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    };

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    /* a client we would not accept, which is the point of some tests */
                    return;
                };
                let svc = service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from("secure origin")))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

fn zone_yaml(origin: SocketAddr, origin_tls: &str) -> String {
    /* the certificate is for `localhost`, so the origin url has to say localhost too -
       an address would not match it, which is exactly the check being exercised */
    format!(
        "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    \
         origin:\n      url: \"https://localhost:{}\"\n      timeout_ms: 4000\n    \
         cache:\n      enabled: false\n{origin_tls}",
        origin.port()
    )
}

async fn spawn_edge(yaml: &str) -> SocketAddr {
    let cfg = config::parse(yaml).expect("test config should parse");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, Edge::new(Arc::new(Snapshot::new(cfg)))).await;
    });
    addr
}

async fn get(edge: SocketAddr) -> (StatusCode, String) {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .uri(format!("http://{edge}/"))
        .header("host", "demo.local")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.expect("the edge should answer");
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn an_https_origin_works_when_its_ca_is_trusted() {
    let pem = make_cert("trusted", "localhost");
    let origin = spawn_tls_origin(&pem, None).await;
    let edge = spawn_edge(&zone_yaml(
        origin,
        &format!("    origin_tls:\n      ca: \"{}\"\n", pem.ca),
    ))
    .await;

    let (status, body) = get(edge).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "secure origin");
}

#[tokio::test]
async fn an_untrusted_certificate_is_refused() {
    let pem = make_cert("untrusted", "localhost");
    let origin = spawn_tls_origin(&pem, None).await;
    /* no ca named, so the origin's self-signed certificate is not trusted by anything */
    let edge = spawn_edge(&zone_yaml(origin, "")).await;

    let (status, _) = get(edge).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "a certificate signed by nobody we trust must not be accepted"
    );
}

#[tokio::test]
async fn verification_can_be_turned_off_deliberately() {
    let pem = make_cert("skip", "localhost");
    let origin = spawn_tls_origin(&pem, None).await;
    let edge = spawn_edge(&zone_yaml(origin, "    origin_tls:\n      verify: false\n")).await;

    let (status, body) = get(edge).await;
    assert_eq!(status, StatusCode::OK, "verify: false should reach it anyway");
    assert_eq!(body, "secure origin");
}

#[tokio::test]
async fn a_certificate_for_the_wrong_name_is_refused() {
    /* trusted as a CA, but issued for a name this origin is not reached by */
    let pem = make_cert("wrongname", "somewhere.else");
    let origin = spawn_tls_origin(&pem, None).await;
    let edge = spawn_edge(&zone_yaml(
        origin,
        &format!("    origin_tls:\n      ca: \"{}\"\n", pem.ca),
    ))
    .await;

    let (status, _) = get(edge).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "trusting the issuer is not the same as the name matching"
    );
}

#[tokio::test]
async fn an_origin_demanding_a_client_certificate_gets_one() {
    let server = make_cert("mtls-server", "localhost");
    let client = make_cert("mtls-client", "cloudveil-edge");
    let origin = spawn_tls_origin(&server, Some(&client.ca)).await;

    /* without a client certificate first, to prove the origin really is demanding one */
    let bare = spawn_edge(&zone_yaml(
        origin,
        &format!("    origin_tls:\n      ca: \"{}\"\n", server.ca),
    ))
    .await;
    let (status, _) = get(bare).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "the origin should have refused us");

    /* and now with one */
    let edge = spawn_edge(&zone_yaml(
        origin,
        &format!(
            "    origin_tls:\n      ca: \"{}\"\n      client_cert: \"{}\"\n      client_key: \"{}\"\n",
            server.ca, client.cert, client.key
        ),
    ))
    .await;
    let (status, body) = get(edge).await;
    assert_eq!(status, StatusCode::OK, "mTLS to the origin should be accepted");
    assert_eq!(body, "secure origin");
}

#[tokio::test]
async fn a_plaintext_origin_still_works_through_the_same_client() {
    /* the connector speaks either scheme, so this is the regression test for having
       swapped build_http() out from under everything */
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("plain origin"))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let edge = spawn_edge(&format!(
        "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    \
         origin:\n      url: \"http://{addr}\"\n    cache:\n      enabled: false\n"
    ))
    .await;

    let (status, body) = get(edge).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "plain origin");
}
