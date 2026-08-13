//! How the edge talks to the control plane.
//!
//! One place, because there are two callers - the config pull and the analytics
//! flush - and they must agree on identity. Both present the same bearer token and,
//! when configured, the same client certificate.
//!
//! Everything here comes from the environment rather than the config file: the
//! config travels between nodes and is editable in the dashboard, so a node's own
//! credentials have no business being in it.

use std::sync::Arc;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::info;

pub const TOKEN_VAR: &str = "CLOUDFLINT_CP_TOKEN";
pub const CLIENT_CERT_VAR: &str = "CLOUDFLINT_CLIENT_CERT";
pub const CLIENT_KEY_VAR: &str = "CLOUDFLINT_CLIENT_KEY";
pub const CA_VAR: &str = "CLOUDFLINT_CP_CA";

type Https = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// A connection to the control plane, with whatever identity this node has.
#[derive(Clone)]
pub struct ControlPlane {
    client: Https,
    base: String,
    token: Option<String>,
}

impl ControlPlane {
    pub fn from_env(base: impl Into<String>) -> Result<ControlPlane> {
        let base = base.into().trim_end_matches('/').to_owned();
        let tls = client_tls().context("building the control plane tls config")?;

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            /* http is still allowed: mTLS is worth having and not worth forcing on
               someone running both halves on one box */
            .https_or_http()
            .enable_http1()
            .wrap_connector(http);

        let token = std::env::var(TOKEN_VAR).ok().filter(|t| !t.is_empty());
        if token.is_none() && base.starts_with("http") {
            tracing::warn!(
                "{TOKEN_VAR} is not set - the control plane will refuse this edge if it \
                 requires a token"
            );
        }

        Ok(ControlPlane {
            client: Client::builder(TokioExecutor::new()).build(connector),
            base,
            token,
        })
    }

    fn request(&self, method: Method, path: &str, body: Bytes) -> Result<Request<Full<Bytes>>> {
        let mut req = Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base))
            .header("content-type", "application/json");

        if let Some(token) = &self.token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        Ok(req.body(Full::new(body))?)
    }

    pub async fn get(&self, path: &str) -> Result<Bytes> {
        let req = self.request(Method::GET, path, Bytes::new())?;
        self.send(req).await
    }

    pub async fn post(&self, path: &str, body: Vec<u8>) -> Result<Bytes> {
        let req = self.request(Method::POST, path, Bytes::from(body))?;
        self.send(req).await
    }

    async fn send(&self, req: Request<Full<Bytes>>) -> Result<Bytes> {
        let resp = self
            .client
            .request(req)
            .await
            .context("could not reach the control plane")?;

        let status = resp.status();
        let body = resp.into_body().collect().await?.to_bytes();

        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            anyhow::bail!(
                "the control plane rejected this edge's credentials ({status}) - check \
                 {TOKEN_VAR} and any client certificate"
            );
        }
        if !status.is_success() {
            anyhow::bail!("control plane answered {status}");
        }
        Ok(body)
    }
}

/// Trust the public roots, plus a private CA if one is named, and present a client
/// certificate if this node has one.
fn client_tls() -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Ok(path) = std::env::var(CA_VAR) {
        let added = load_certs(&path)?;
        let count = added.len();
        for cert in added {
            roots.add(cert)?;
        }
        info!("trusting {count} certificate(s) from {path} for the control plane");
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);

    match (std::env::var(CLIENT_CERT_VAR), std::env::var(CLIENT_KEY_VAR)) {
        (Ok(cert), Ok(key)) => {
            let chain = load_certs(&cert)?;
            let key = load_key(&key)?;
            info!("presenting client certificate {cert} to the control plane");
            Ok(builder.with_client_auth_cert(chain, key)?)
        }
        _ => Ok(builder.with_no_client_auth()),
    }
}

pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
    rustls_pemfile::certs(&mut std::io::BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("reading certificates from {path}"))
}

pub fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
    rustls_pemfile::private_key(&mut std::io::BufReader::new(file))
        .with_context(|| format!("reading a private key from {path}"))?
        .ok_or_else(|| anyhow::anyhow!("{path} contains no private key"))
}

/// Server side of mTLS: only accept clients holding a certificate this CA signed.
pub fn client_verifier(ca_path: &str) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in load_certs(ca_path)? {
        roots.add(cert)?;
    }
    rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("building the client certificate verifier")
}
