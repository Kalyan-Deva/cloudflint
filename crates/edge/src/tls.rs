//! TLS termination.
//!
//! Certificates are named by the config but loaded here, not in `config::parse`.
//! That keeps parsing pure: the control plane validates config it was handed without
//! needing the cert files, which only exist on the edges.
//!
//! Reloading works the same way the config snapshot does. The resolver rustls holds
//! is a stable `Arc`; the certificates inside it are swapped atomically, so new certs
//! take effect on the next handshake without rebuilding the acceptor or dropping a
//! single live connection.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use tracing::{info, warn};

use crate::config::Config;

/// What we offer, best first. h2 needs no extra work beyond saying so - the auto
/// server builder reads what was negotiated and speaks whichever we agreed on.
const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

#[derive(Default)]
struct Certs {
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// `("demo.local", key)` from a `*.demo.local` hostname.
    wildcards: Vec<(String, Arc<CertifiedKey>)>,
    /// Used when the client sends no SNI at all, or names something we don't have.
    fallback: Option<Arc<CertifiedKey>>,
}

/// Picks a certificate by the name the client asked for.
pub struct SniResolver(ArcSwap<Certs>);

impl SniResolver {
    fn new(certs: Certs) -> Self {
        SniResolver(ArcSwap::from_pointee(certs))
    }

    fn store(&self, certs: Certs) {
        self.0.store(Arc::new(certs));
    }

    pub fn known_names(&self) -> Vec<String> {
        let certs = self.0.load();
        let mut names: Vec<String> = certs.exact.keys().cloned().collect();
        names.extend(certs.wildcards.iter().map(|(base, _)| format!("*.{base}")));
        names.sort();
        names
    }
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SniResolver").field(&self.known_names()).finish()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let certs = self.0.load();
        let Some(name) = hello.server_name() else {
            return certs.fallback.clone();
        };
        let name = name.to_ascii_lowercase();

        if let Some(key) = certs.exact.get(&name) {
            return Some(key.clone());
        }
        /* one label only, the same rule the router uses for `*.demo.local` */
        if let Some((_, rest)) = name.split_once('.') {
            if let Some((_, key)) = certs.wildcards.iter().find(|(base, _)| base == rest) {
                return Some(key.clone());
            }
        }
        certs.fallback.clone()
    }
}

/// Everything the TLS listener needs, built once at boot.
pub struct Tls {
    pub server: Arc<ServerConfig>,
    resolver: Arc<SniResolver>,
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls").field("certs", &self.resolver.known_names()).finish()
    }
}

impl Tls {
    pub fn new(cfg: &Config) -> Result<Option<Tls>> {
        if cfg.tls.is_none() {
            return Ok(None);
        }
        let certs = load(cfg).context("loading certificates")?;
        if certs.exact.is_empty() && certs.wildcards.is_empty() {
            bail!("tls is configured but no zone has a cert and key");
        }

        let resolver = Arc::new(SniResolver::new(certs));
        let mut server = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        server.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();

        info!("tls certificates for: {}", resolver.known_names().join(", "));
        Ok(Some(Tls {
            server: Arc::new(server),
            resolver,
        }))
    }

    /// Pick up certificates named by a config that has just been reloaded. A cert
    /// that fails to load leaves the running one in place - the same rule the config
    /// watcher follows, for the same reason.
    pub fn reload(&self, cfg: &Config) {
        match load(cfg) {
            Ok(certs) if certs.exact.is_empty() && certs.wildcards.is_empty() => {
                warn!("reloaded config has no usable certificates, keeping the current ones");
            }
            Ok(certs) => {
                self.resolver.store(certs);
                info!("tls certificates reloaded: {}", self.resolver.known_names().join(", "));
            }
            Err(e) => warn!("could not reload certificates, keeping the current ones: {e:#}"),
        }
    }
}

fn load(cfg: &Config) -> Result<Certs> {
    let mut certs = Certs::default();

    for zone in &cfg.zones {
        let Some(paths) = &zone.tls else { continue };
        let key = load_pair(&paths.cert, &paths.key)
            .with_context(|| format!("zone `{}`", zone.name))?;
        let key = Arc::new(key);

        for hostname in &zone.hostnames {
            match hostname.strip_prefix("*.") {
                Some(base) => certs.wildcards.push((base.to_owned(), key.clone())),
                None => {
                    certs.exact.insert(hostname.clone(), key.clone());
                }
            }
        }
        /* first zone with a cert answers for anything unrecognised, which is what
           makes `curl https://127.0.0.1` work at all */
        certs.fallback.get_or_insert(key);
    }
    Ok(certs)
}

fn load_pair(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let chain = read_certs(cert_path)?;
    if chain.is_empty() {
        bail!("{} contains no certificates", cert_path.display());
    }
    let key = read_key(key_path)?;

    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .with_context(|| format!("{} is not a usable private key", key_path.display()))?;

    Ok(CertifiedKey::new(chain, signing))
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))
}

fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .with_context(|| format!("reading a private key from {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("{} contains no private key", path.display()))
}

/// rustls needs a crypto provider chosen before anything else touches it. Called
/// from both binaries and from the tests.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use std::io::Write;

    /// A throwaway self-signed cert, written to disk the way a real one would be.
    fn write_cert(dir: &Path, stem: &str, names: &[&str]) -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(
            names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .expect("self-signed cert");

        let cert_path = dir.join(format!("{stem}.crt"));
        let key_path = dir.join(format!("{stem}.key"));
        File::create(&cert_path)
            .unwrap()
            .write_all(cert.cert.pem().as_bytes())
            .unwrap();
        File::create(&key_path)
            .unwrap()
            .write_all(cert.signing_key.serialize_pem().as_bytes())
            .unwrap();

        (
            cert_path.display().to_string().replace('\\', "/"),
            key_path.display().to_string().replace('\\', "/"),
        )
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cloudveil-tls-{tag}-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config_with(dir: &Path) -> Config {
        let (cert, key) = write_cert(dir, "demo", &["demo.local", "*.demo.local"]);
        let (other_cert, other_key) = write_cert(dir, "other", &["other.local"]);
        config::parse(&format!(
            "tls:\n  listen: \"127.0.0.1:8443\"\n\
             zones:\n  \
             - name: demo\n    hostnames: [\"demo.local\", \"*.demo.local\"]\n    \
               origin:\n      url: \"http://127.0.0.1:9\"\n    \
               tls:\n      cert: \"{cert}\"\n      key: \"{key}\"\n  \
             - name: other\n    hostnames: [\"other.local\"]\n    \
               origin:\n      url: \"http://127.0.0.1:9\"\n    \
               tls:\n      cert: \"{other_cert}\"\n      key: \"{other_key}\"\n"
        ))
        .expect("config should parse")
    }

    #[test]
    fn loads_a_cert_per_zone_and_indexes_every_hostname() {
        install_crypto_provider();
        let dir = temp_dir("load");
        let tls = Tls::new(&config_with(&dir)).unwrap().expect("tls configured");

        assert_eq!(
            tls.resolver.known_names(),
            ["*.demo.local", "demo.local", "other.local"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nothing_is_built_when_tls_is_not_configured() {
        install_crypto_provider();
        let cfg = config::parse(
            "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n",
        )
        .unwrap();
        assert!(Tls::new(&cfg).unwrap().is_none());
    }

    #[test]
    fn tls_without_any_cert_is_refused_rather_than_started_deaf() {
        install_crypto_provider();
        let cfg = config::parse(
            "tls:\n  listen: \"127.0.0.1:8443\"\nzones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n",
        )
        .unwrap();
        let err = Tls::new(&cfg).unwrap_err().to_string();
        assert!(err.contains("no zone has a cert"), "unexpected error: {err}");
    }

    #[test]
    fn a_missing_cert_file_says_which_zone() {
        install_crypto_provider();
        let cfg = config::parse(
            "tls:\n  listen: \"127.0.0.1:8443\"\nzones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n    tls:\n      cert: \"nope.crt\"\n      key: \"nope.key\"\n",
        )
        .unwrap();
        let err = format!("{:#}", Tls::new(&cfg).unwrap_err());
        assert!(err.contains("zone `demo`"), "unexpected error: {err}");
        assert!(err.contains("nope.crt"), "unexpected error: {err}");
    }

    #[test]
    fn a_broken_reload_keeps_the_certificates_it_had() {
        install_crypto_provider();
        let dir = temp_dir("reload");
        let tls = Tls::new(&config_with(&dir)).unwrap().unwrap();
        let before = tls.resolver.known_names();

        let broken = config::parse(
            "tls:\n  listen: \"127.0.0.1:8443\"\nzones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n    tls:\n      cert: \"gone.crt\"\n      key: \"gone.key\"\n",
        )
        .unwrap();
        tls.reload(&broken);

        assert_eq!(tls.resolver.known_names(), before, "certs should not have changed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_good_reload_swaps_them() {
        install_crypto_provider();
        let dir = temp_dir("swap");
        let tls = Tls::new(&config_with(&dir)).unwrap().unwrap();

        let (cert, key) = write_cert(&dir, "third", &["third.local"]);
        let next = config::parse(&format!(
            "tls:\n  listen: \"127.0.0.1:8443\"\nzones:\n  - name: third\n    hostnames: [\"third.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n    tls:\n      cert: \"{cert}\"\n      key: \"{key}\"\n"
        ))
        .unwrap();
        tls.reload(&next);

        assert_eq!(tls.resolver.known_names(), ["third.local"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
