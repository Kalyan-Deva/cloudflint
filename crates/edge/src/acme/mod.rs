//! Certificates that get themselves, and renew themselves.
//!
//! Nobody runs a public edge renewing certificates by hand, so this is the last thing
//! standing between "TLS works" and "TLS keeps working". RFC 8555, hand-rolled like the
//! rest, and the flow is smaller than its reputation:
//!
//! 1. Fetch the directory, which names every other endpoint.
//! 2. Create (or re-find) an account, keyed by the account key itself.
//! 3. Ask for an order over the zone's hostnames.
//! 4. For each name, answer an **http-01** challenge - serve `token.thumbprint` at a
//!    well-known path - and tell the CA to come and look.
//! 5. Send a CSR, wait for the order to go valid, download the chain.
//! 6. Write the chain and its key where the zone's `tls` block already points, and let
//!    `tls::watch` pick them up. No restart, no reconfiguration.
//!
//! Two things make this safe to leave running unattended:
//!
//! **It writes where the config already points.** ACME does not introduce a second place
//! certificates live; it fills in the files the SNI resolver is already reading. A zone
//! configured for ACME and a zone with a certificate somebody bought are the same zone as
//! far as everything downstream is concerned.
//!
//! **It gives up rather than hammering.** A CA that says no gets one attempt per retry
//! window, not a loop. Let's Encrypt's rate limits are strict and a proxy that trips them
//! cannot serve TLS at all for a week, which is worse than the certificate it was chasing.

pub mod jws;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{HeaderMap, Method, Request, StatusCode};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info, warn};

use crate::config::{AcmeConfig, Config};
use jws::AccountKey;

/// Where an http-01 challenge is answered. Fixed by RFC 8555.
pub const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Tokens we are currently expected to answer for, and what to answer.
///
/// Shared with the request path rather than served by a listener of its own: the CA has to
/// reach this on port 80 for the name being certified, and port 80 is already ours. It
/// also has to work *before* there is any certificate, which is why the redirect listener
/// answers challenges instead of sending the CA to https.
#[derive(Default)]
pub struct Challenges(Mutex<HashMap<String, String>>);

impl Challenges {
    pub fn new() -> Arc<Self> {
        Arc::new(Challenges::default())
    }

    pub fn put(&self, token: &str, authorization: &str) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token.to_owned(), authorization.to_owned());
    }

    pub fn take(&self, token: &str) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(token);
    }

    pub fn answer(&self, token: &str) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(token)
            .cloned()
    }

    /// The answer for a path, if it is a challenge path at all.
    pub fn for_path(&self, path: &str) -> Option<String> {
        self.answer(path.strip_prefix(CHALLENGE_PREFIX)?)
    }

    pub fn pending(&self) -> usize {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

type HttpsClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// A conversation with one ACME server.
pub struct Acme {
    client: HttpsClient,
    key: AccountKey,
    directory: Directory,
    /// Set once the account exists; every later request is signed with it rather than
    /// with the whole key.
    account: Option<String>,
    /// ACME nonces are single use. Every response hands out the next one, so the only
    /// time we ask for one is at the very start.
    nonce: Option<String>,
    /// Which issuance profile to ask for, when the server offers a choice.
    profile: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

#[derive(Debug, Deserialize)]
struct Order {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    finalize: String,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Authorization {
    status: String,
    #[serde(default)]
    challenges: Vec<Challenge>,
}

#[derive(Debug, Deserialize)]
struct Challenge {
    r#type: String,
    url: String,
    #[serde(default)]
    token: String,
}

impl Acme {
    pub async fn connect(cfg: &AcmeConfig) -> Result<Acme> {
        let key = AccountKey::load_or_create(&cfg.account_key)?;
        let client = build_client(cfg)?;

        let body = get(&client, &cfg.directory)
            .await
            .with_context(|| format!("fetching the acme directory at {}", cfg.directory))?;
        let directory: Directory =
            serde_json::from_slice(&body.1).context("the acme directory is not what we expect")?;

        Ok(Acme {
            client,
            key,
            directory,
            account: None,
            nonce: None,
            profile: cfg.profile.clone(),
        })
    }

    /// Create the account, or find the one this key already has. ACME makes these the
    /// same request, which is what lets this run on every start without bookkeeping.
    pub async fn account(&mut self, contact: Option<&str>) -> Result<()> {
        let payload = match contact {
            Some(contact) => json!({
                "termsOfServiceAgreed": true,
                "contact": [contact],
            }),
            None => json!({ "termsOfServiceAgreed": true }),
        };

        let url = self.directory.new_account.clone();
        let (headers, _) = self.post(&url, &payload.to_string(), false).await?;
        let account = header(&headers, "location")
            .context("the acme server did not say where the account is")?;

        info!("acme account {account}");
        self.account = Some(account);
        Ok(())
    }

    /// The whole issuance flow for one set of names.
    pub async fn certify(
        &mut self,
        names: &[String],
        challenges: &Challenges,
        wait: Duration,
    ) -> Result<String> {
        let identifiers: Vec<_> = names
            .iter()
            .map(|n| json!({ "type": "dns", "value": n }))
            .collect();

        /* a profile is only sent when one is configured. Naming one pins how long the
           certificate lasts - a server offering several and left to choose may not choose
           the same one twice, which turns "renew at 30 days left" into a loop if it hands
           back a six day certificate. Sending nothing is right for a CA that has no
           profiles, which is most of them */
        let order_request = match &self.profile {
            Some(profile) => json!({ "identifiers": identifiers, "profile": profile }),
            None => json!({ "identifiers": identifiers }),
        };

        let url = self.directory.new_order.clone();
        let (headers, body) = self
            .post(&url, &order_request.to_string(), false)
            .await
            .context("asking for a new order")?;

        let order_url = header(&headers, "location").context("no order url")?;
        let mut order: Order = serde_json::from_slice(&body).context("the order is unreadable")?;
        debug!("acme order {order_url} is {}", order.status);

        for authorization in order.authorizations.clone() {
            self.authorize(&authorization, challenges, wait)
                .await
                .with_context(|| format!("authorization {authorization}"))?;
        }

        /* the key for the certificate itself, which is not the account key - a leaked
           certificate key must not also be the identity that can issue more */
        let (csr, key_pem) = csr(names)?;
        let (_, body) = self
            .post(&order.finalize, &json!({ "csr": csr }).to_string(), false)
            .await
            .context("sending the csr")?;
        order = serde_json::from_slice(&body).context("the finalized order is unreadable")?;

        let deadline = std::time::Instant::now() + wait;
        while order.status != "valid" {
            if order.status == "invalid" {
                bail!("the acme server rejected the order");
            }
            if std::time::Instant::now() > deadline {
                bail!("the order was still `{}` after {wait:?}", order.status);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            let (_, body) = self.post(&order_url, "", false).await?;
            order = serde_json::from_slice(&body).context("re-reading the order")?;
        }

        let url = order.certificate.context("a valid order with no certificate")?;
        let (_, chain) = self.post(&url, "", true).await.context("downloading the certificate")?;
        let chain = String::from_utf8(chain.to_vec()).context("the certificate is not text")?;

        Ok(format!("{chain}\u{0}{key_pem}"))
    }

    /// Answer one authorization's http-01 challenge and wait for the CA to agree.
    async fn authorize(
        &mut self,
        url: &str,
        challenges: &Challenges,
        wait: Duration,
    ) -> Result<()> {
        let (_, body) = self.post(url, "", false).await?;
        let auth: Authorization = serde_json::from_slice(&body).context("unreadable authorization")?;

        if auth.status == "valid" {
            /* already answered on an earlier run, and still good */
            return Ok(());
        }

        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == "http-01")
            .context("the acme server offered no http-01 challenge")?;

        let authorization = self.key.key_authorization(&challenge.token);
        challenges.put(&challenge.token, &authorization);
        /* removed however this ends - a token left behind is a path that answers with a
           secret nobody asked about any more */
        let _cleanup = Cleanup {
            challenges,
            token: challenge.token.clone(),
        };

        /* an empty object, not an empty payload: this is "come and check", and it is the
           one place an empty {} and a post-as-get mean different things */
        self.post(&challenge.url.clone(), "{}", false)
            .await
            .context("telling the acme server to validate")?;

        let deadline = std::time::Instant::now() + wait;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let (_, body) = self.post(url, "", false).await?;
            let auth: Authorization = serde_json::from_slice(&body)?;

            match auth.status.as_str() {
                "valid" => return Ok(()),
                "invalid" | "revoked" | "expired" => {
                    bail!("the acme server could not validate this name ({})", auth.status)
                }
                other => {
                    if std::time::Instant::now() > deadline {
                        bail!("still `{other}` after {wait:?}");
                    }
                }
            }
        }
    }

    /// One signed request. `raw` skips JSON, for the certificate download.
    async fn post(&mut self, url: &str, payload: &str, raw: bool) -> Result<(HeaderMap, Bytes)> {
        let nonce = match self.nonce.take() {
            Some(nonce) => nonce,
            None => self.fresh_nonce().await?,
        };
        let body = self.key.sign(url, &nonce, payload, self.account.as_deref())?;

        let accept = match raw {
            true => "application/pem-certificate-chain",
            false => "application/json",
        };
        let req = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header("content-type", "application/jose+json")
            .header("accept", accept)
            .header("user-agent", "cloudflint")
            .body(Full::new(Bytes::from(body)))?;

        let resp = self.client.request(req).await.context("acme request failed")?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await?.to_bytes();

        /* every response carries the next nonce, so the happy path never asks for one */
        if let Some(next) = header(&headers, "replay-nonce") {
            self.nonce = Some(next);
        }

        if status == StatusCode::BAD_REQUEST && problem_is_bad_nonce(&body) {
            /* the one error worth retrying blindly: the server tells us the right nonce
               in the same response */
            debug!("acme said the nonce was stale, retrying once");
            return Box::pin(self.post(url, payload, raw)).await;
        }
        if !status.is_success() {
            bail!("acme answered {status}: {}", describe_problem(&body));
        }
        Ok((headers, body))
    }

    /// GET rather than HEAD. RFC 8555 has servers support both, and a HEAD carrying the
    /// `content-length: 0` hyper adds for an empty body is refused by at least one of them
    /// - the GET form answers 204 with the same header and no argument.
    async fn fresh_nonce(&mut self) -> Result<String> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&self.directory.new_nonce)
            .header("user-agent", "cloudflint")
            .body(Full::new(Bytes::new()))?;

        let resp = self.client.request(req).await.context("asking for a nonce")?;
        let status = resp.status();
        let found = header(resp.headers(), "replay-nonce");
        let body = resp.into_body().collect().await?.to_bytes();

        found.with_context(|| {
            format!(
                "no nonce from {}, which answered {status}: {}",
                self.directory.new_nonce,
                describe_problem(&body)
            )
        })
    }
}

/// Takes a challenge token back out of the store however the attempt ended.
struct Cleanup<'a> {
    challenges: &'a Challenges,
    token: String,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        self.challenges.take(&self.token);
    }
}

/// A CSR for these names, plus the PEM of the key that signed it.
fn csr(names: &[String]) -> Result<(String, String)> {
    let key = rcgen::KeyPair::generate().context("generating a certificate key")?;
    let mut params = rcgen::CertificateParams::new(names.to_vec())
        .context("building the certificate request")?;
    /* the CA fills in the rest; a CSR that argues about validity dates gets ignored */
    params.distinguished_name = rcgen::DistinguishedName::new();

    let request = params
        .serialize_request(&key)
        .context("signing the certificate request")?;

    Ok((jws::b64url(request.der()), key.serialize_pem()))
}

fn build_client(cfg: &AcmeConfig) -> Result<HttpsClient> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    /* a test CA, for a staging server that is not publicly trusted - this is what makes
       verifying against Pebble possible without turning verification off */
    if let Some(ca) = &cfg.ca {
        let path = ca.display().to_string();
        for cert in crate::cp::load_certs(&path)? {
            roots.add(cert).with_context(|| format!("acme.ca {path}"))?;
        }
        info!("trusting {path} for the acme server");
    }

    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);

    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

async fn get(client: &HttpsClient, url: &str) -> Result<(HeaderMap, Bytes)> {
    let req = Request::builder()
        .uri(url)
        .header("user-agent", "cloudflint")
        .body(Full::new(Bytes::new()))?;
    let resp = client.request(req).await?;
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((headers, body))
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_owned)
}

fn problem_is_bad_nonce(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["type"].as_str().map(|t| t.ends_with(":badNonce")))
        .unwrap_or(false)
}

/// ACME errors are RFC 7807 problem documents, which are worth reading out properly - the
/// detail is usually the entire explanation.
fn describe_problem(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return String::from_utf8_lossy(body).chars().take(300).collect();
    };
    let detail = value["detail"].as_str().unwrap_or("");
    let kind = value["type"].as_str().unwrap_or("");
    match (kind, detail) {
        ("", "") => String::from_utf8_lossy(body).chars().take(300).collect(),
        (kind, "") => kind.to_owned(),
        ("", detail) => detail.to_owned(),
        (kind, detail) => format!("{detail} ({kind})"),
    }
}

/// Split what `certify` returns back into the chain and the key.
fn split_bundle(bundle: &str) -> Option<(&str, &str)> {
    bundle.split_once('\u{0}')
}

/// How long a certificate has left, or None if there is no readable certificate there.
fn days_left(cert_path: &Path) -> Option<i64> {
    use x509_parser::prelude::*;

    let text = std::fs::read_to_string(cert_path).ok()?;
    let der = rustls_pemfile::certs(&mut text.as_bytes())
        .next()?
        .ok()?;
    let (_, parsed) = X509Certificate::from_der(&der).ok()?;

    let now = crate::analytics::now_ms() as i64 / 1000;
    Some((parsed.validity().not_after.timestamp() - now) / 86_400)
}

/// Keep every ACME zone's certificate present and current.
///
/// One task for the whole node, checking on a timer. Issuance and renewal are the same
/// operation - a missing certificate is just one with no days left - so there is one code
/// path rather than two that could disagree.
pub fn spawn(snap: Arc<crate::snapshot::Snapshot>, challenges: Arc<Challenges>) {
    let boot = snap.current();
    let Some(cfg) = boot.acme.clone() else { return };

    if !boot.zones.iter().any(|z| z.acme) {
        debug!("acme is configured but no zone asks for it");
        return;
    }

    tokio::spawn(async move {
        /* a short wait first: the listener that answers challenges has to be up before
           we invite a CA to knock on it */
        tokio::time::sleep(Duration::from_secs(2)).await;

        let mut ticker = tokio::time::interval(cfg.check_every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            if let Err(e) = sweep(&snap, &cfg, &challenges).await {
                warn!("acme: {e:#}");
            }
        }
    });
}

/// One pass over every zone that wants ACME.
async fn sweep(
    snap: &crate::snapshot::Snapshot,
    cfg: &AcmeConfig,
    challenges: &Challenges,
) -> Result<()> {
    let live = snap.current();
    let due: Vec<_> = live
        .zones
        .iter()
        .filter(|z| z.acme && z.tls.is_some())
        .filter_map(|z| {
            let paths = z.tls.as_ref()?;
            let left = days_left(&paths.cert);
            let due = match left {
                None => true,
                Some(days) => days <= cfg.renew_before_days as i64,
            };
            due.then(|| {
                (
                    z.name.clone(),
                    /* wildcards cannot be done over http-01 - the CA has to reach a
                       specific name - so they are skipped rather than attempted */
                    z.hostnames
                        .iter()
                        .filter(|h| !h.starts_with("*."))
                        .cloned()
                        .collect::<Vec<_>>(),
                    paths.cert.clone(),
                    paths.key.clone(),
                    left,
                )
            })
        })
        .collect();

    if due.is_empty() {
        return Ok(());
    }

    let mut acme = Acme::connect(cfg).await?;
    acme.account(cfg.contact.as_deref()).await?;

    for (zone, names, cert_path, key_path, left) in due {
        if names.is_empty() {
            warn!("zone {zone}: acme is on but every hostname is a wildcard, which http-01 cannot do");
            continue;
        }
        match left {
            None => info!("zone {zone}: no certificate yet, asking for one for {names:?}"),
            Some(days) => info!("zone {zone}: certificate has {days} days left, renewing"),
        }

        match acme.certify(&names, challenges, cfg.timeout).await {
            Ok(bundle) => {
                let Some((chain, key)) = split_bundle(&bundle) else {
                    warn!("zone {zone}: the issued bundle was malformed");
                    continue;
                };
                if let Err(e) = write_pair(&cert_path, &key_path, chain, key) {
                    warn!("zone {zone}: could not save the new certificate: {e:#}");
                    continue;
                }
                info!(
                    "zone {zone}: certificate issued and written to {} - it will be picked up within seconds",
                    cert_path.display()
                );
            }
            Err(e) => warn!("zone {zone}: could not get a certificate: {e:#}"),
        }
    }
    Ok(())
}

/// Write the key first, then the chain.
///
/// The order matters because something else is watching these files: a reload that reads a
/// new certificate against an old key fails and is retried, while the other way round can
/// leave a key with no certificate. Neither is served, but one of them is quieter.
fn write_pair(cert_path: &Path, key_path: &Path, chain: &str, key: &str) -> Result<()> {
    for path in [cert_path, key_path] {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
    }
    std::fs::write(key_path, key).with_context(|| format!("writing {}", key_path.display()))?;
    std::fs::write(cert_path, chain).with_context(|| format!("writing {}", cert_path.display()))?;
    Ok(())
}

/// What the admin api reports about ACME.
pub fn report(cfg: &Config, challenges: &Challenges) -> serde_json::Value {
    let Some(acme) = &cfg.acme else {
        return json!({ "enabled": false });
    };
    json!({
        "enabled": true,
        "directory": acme.directory,
        "contact": acme.contact,
        "renew_before_days": acme.renew_before_days,
        "check_every_secs": acme.check_every.as_secs(),
        "zones": cfg.zones.iter().filter(|z| z.acme).map(|z| z.name.clone()).collect::<Vec<_>>(),
        "challenges_pending": challenges.pending(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_is_answered_only_at_its_own_path() {
        let challenges = Challenges::new();
        challenges.put("tok", "tok.print");

        assert_eq!(
            challenges.for_path("/.well-known/acme-challenge/tok").as_deref(),
            Some("tok.print")
        );
        assert!(challenges.for_path("/.well-known/acme-challenge/other").is_none());
        assert!(challenges.for_path("/tok").is_none());
        assert!(challenges.for_path("/.well-known/acme-challenge/").is_none());
    }

    #[test]
    fn a_token_is_forgotten_when_the_attempt_ends() {
        let challenges = Challenges::new();
        {
            let _cleanup = Cleanup {
                challenges: &challenges,
                token: "tok".into(),
            };
            challenges.put("tok", "tok.print");
            assert_eq!(challenges.pending(), 1);
        }
        assert_eq!(challenges.pending(), 0, "even if the attempt failed");
    }

    #[test]
    fn a_csr_covers_every_name_and_keeps_its_key() {
        let names = vec!["a.example".to_string(), "b.example".to_string()];
        let (csr, key) = csr(&names).expect("a csr");

        assert!(!csr.is_empty());
        assert!(!csr.contains('+') && !csr.contains('/'), "base64url for a jws field");
        assert!(key.contains("PRIVATE KEY"), "the key comes back as pem");
    }

    #[test]
    fn a_bundle_splits_back_into_a_chain_and_a_key() {
        let bundle = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n\u{0}-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----\n";
        let (chain, key) = split_bundle(bundle).expect("two halves");

        assert!(chain.contains("CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
        assert!(split_bundle("no separator").is_none());
    }

    #[test]
    fn problem_documents_are_read_out_rather_than_dumped() {
        let body = br#"{"type":"urn:ietf:params:acme:error:unauthorized","detail":"nope"}"#;
        assert_eq!(
            describe_problem(body),
            "nope (urn:ietf:params:acme:error:unauthorized)"
        );
        assert_eq!(describe_problem(b"not json at all"), "not json at all");
        assert!(problem_is_bad_nonce(
            br#"{"type":"urn:ietf:params:acme:error:badNonce"}"#
        ));
        assert!(!problem_is_bad_nonce(
            br#"{"type":"urn:ietf:params:acme:error:unauthorized"}"#
        ));
    }

    #[test]
    fn days_left_of_a_missing_file_is_nothing_rather_than_zero() {
        assert_eq!(days_left(Path::new("/nope/missing.crt")), None);
    }

    /// A zone with acme on, and whatever top-level block the test is about.
    fn config(acme: &str) -> anyhow::Result<Config> {
        crate::config::parse(&format!(
            "{acme}zones:\n  - name: demo\n    hostnames: [\"demo.example\"]\n    \
             origin:\n      url: \"http://127.0.0.1:9\"\n    \
             tls:\n      cert: \"c.crt\"\n      key: \"c.key\"\n      acme: true\n"
        ))
    }

    #[test]
    fn a_zone_asking_for_acme_with_no_server_named_is_refused() {
        let err = format!("{:#}", config("").expect_err("should not parse"));
        assert!(err.contains("acme"), "unhelpful: {err}");
        assert!(err.contains("demo"), "should name the zone: {err}");
    }

    #[test]
    fn a_sensible_acme_block_parses_with_the_defaults_we_want() {
        let cfg = config("acme:\n  directory: \"https://acme.test/dir\"\n").expect("should parse");
        let acme = cfg.acme.expect("an acme config");

        assert_eq!(acme.directory, "https://acme.test/dir");
        assert_eq!(acme.renew_before_days, 30, "a third of a 90 day certificate");
        assert_eq!(acme.check_every.as_secs(), 12 * 3600);
        assert!(acme.contact.is_none());
        assert!(cfg.zones[0].acme, "the zone opted in");
    }

    #[test]
    fn the_settings_that_would_quietly_never_renew_are_refused() {
        let cases = [
            ("acme:\n  directory: \"acme.test/dir\"\n", "scheme"),
            (
                "acme:\n  directory: \"https://a/d\"\n  renew_before_days: 0\n",
                "renew_before_days",
            ),
            (
                "acme:\n  directory: \"https://a/d\"\n  check_every_secs: 0\n",
                "check_every_secs",
            ),
            (
                "acme:\n  directory: \"https://a/d\"\n  contact: \"ops@example.test\"\n",
                "mailto",
            ),
        ];
        for (yaml, expected) in cases {
            let err = format!("{:#}", config(yaml).expect_err("should not parse"));
            assert!(err.contains(expected), "expected `{expected}` in: {err}");
        }
    }

    #[test]
    fn acme_is_off_unless_a_zone_asks_for_it() {
        let cfg = crate::config::parse(
            "acme:\n  directory: \"https://acme.test/dir\"\nzones:\n  - name: demo\n    \
             hostnames: [\"demo.example\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n",
        )
        .expect("should parse");

        assert!(cfg.acme.is_some(), "the server is named");
        assert!(!cfg.zones[0].acme, "but no zone opted in");
        assert_eq!(report(&cfg, &Challenges::new())["zones"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn the_report_says_what_is_going_on() {
        let cfg = config("acme:\n  directory: \"https://acme.test/dir\"\n  contact: \"mailto:a@b.c\"\n")
            .expect("should parse");
        let challenges = Challenges::new();
        challenges.put("tok", "tok.print");

        let shown = report(&cfg, &challenges);
        assert_eq!(shown["enabled"], true);
        assert_eq!(shown["directory"], "https://acme.test/dir");
        assert_eq!(shown["contact"], "mailto:a@b.c");
        assert_eq!(shown["zones"][0], "demo");
        assert_eq!(shown["challenges_pending"], 1);

        /* and with no acme block at all it says so rather than half-filling itself */
        let plain = crate::config::parse(
            "zones:\n  - name: demo\n    hostnames: [\"d.example\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n",
        )
        .unwrap();
        assert_eq!(report(&plain, &challenges)["enabled"], false);
    }
}

