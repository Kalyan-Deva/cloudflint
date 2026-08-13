//! HTTPS on the way to the origin.
//!
//! Encrypting the client's leg and then sending everything on in the clear is a
//! surprisingly common way to have TLS on a diagram and not in the traffic. Until now the
//! origin client was built with `build_http()`, so config would happily accept an
//! `https://` origin url and then fail every request to it — the loudest kind of gap,
//! but a gap.
//!
//! **Validation is on by default and there is no way to leave it on by accident.** The
//! origin's certificate is checked against the public roots plus whatever CA a zone names,
//! and the hostname has to match. `verify: false` exists because self-signed origins on
//! private networks are real, but it says so in the log every time the profile is built,
//! and it is per zone rather than global so one internal service cannot quietly disable
//! checking for everything else.
//!
//! Client certificates - mTLS to the origin - are the other half: the origin gets to know
//! it is talking to us, which is what lets it refuse everyone who is not.
//!
//! Profiles are built lazily and cached, keyed by their own settings, because a rustls
//! config is expensive to assemble and a connection pool wants to be reused. Zones sharing
//! settings share a client; the default profile covers every plaintext origin too, since
//! the connector speaks either.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tracing::{info, warn};

use crate::config::{Config, OriginTls};
use crate::cp::{load_certs, load_key};

/// Turn a zone's settings into a rustls client config.
pub fn client_config(tls: &OriginTls) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(ca) = &tls.ca {
        let path = ca.display().to_string();
        let added = load_certs(&path).with_context(|| format!("origin_tls.ca {path}"))?;
        let count = added.len();
        for cert in added {
            roots.add(cert).with_context(|| format!("origin_tls.ca {path}"))?;
        }
        info!("trusting {count} certificate(s) from {path} for origins");
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);

    let mut config = match (&tls.client_cert, &tls.client_key) {
        (Some(cert), Some(key)) => {
            let cert = cert.display().to_string();
            let key = key.display().to_string();
            let chain = load_certs(&cert).with_context(|| format!("origin_tls.client_cert {cert}"))?;
            let signing = load_key(&key).with_context(|| format!("origin_tls.client_key {key}"))?;
            info!("presenting client certificate {cert} to origins");
            builder
                .with_client_auth_cert(chain, signing)
                .context("origin_tls client certificate")?
        }
        _ => builder.with_no_client_auth(),
    };

    if !tls.verify {
        /* said out loud every time, because a config that silently stopped checking
           certificates is indistinguishable from one that never checked */
        warn!(
            "origin certificate verification is OFF for this profile - anything on the \
             path to the origin can read and rewrite the traffic"
        );
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(TrustAnything));
    }

    Ok(config)
}

/// Build every zone's profile once at startup, so a path that does not exist is a startup
/// failure rather than a 502 the first time somebody visits that zone.
pub fn preflight(cfg: &Config) -> Result<()> {
    for zone in &cfg.zones {
        if zone.origin_tls.is_default() {
            continue;
        }
        client_config(&zone.origin_tls)
            .with_context(|| format!("zone `{}`: origin_tls", zone.name))?;
    }
    Ok(())
}

/// A verifier that accepts anything, for `verify: false`.
///
/// rustls deliberately ships no such thing, which is the right default for a library. It
/// is written out here rather than pulled from a crate so that the one place in Cloudflint
/// that can skip a certificate check is visible in Cloudflint's own source.
#[derive(Debug)]
struct TrustAnything;

impl ServerCertVerifier for TrustAnything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        /* whatever the provider can do: we are not judging the signature anyway */
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn zone_with(origin_tls: &str) -> Config {
        let yaml = format!(
            "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    \
             origin:\n      url: \"https://origin.internal\"\n{origin_tls}"
        );
        config::parse(&yaml).expect("test config should parse")
    }

    #[test]
    fn the_default_profile_verifies_and_presents_nothing() {
        let cfg = zone_with("");
        let tls = &cfg.zones[0].origin_tls;

        assert!(tls.verify, "validation must be the default");
        assert!(tls.is_default());
        assert!(client_config(tls).is_ok());
        /* nothing to load, so nothing to fail at startup */
        assert!(preflight(&cfg).is_ok());
    }

    #[test]
    fn turning_verification_off_still_builds() {
        crate::tls::install_crypto_provider();
        let cfg = zone_with("    origin_tls:\n      verify: false\n");
        let tls = &cfg.zones[0].origin_tls;

        assert!(!tls.verify);
        assert!(!tls.is_default());
        assert!(client_config(tls).is_ok());
    }

    #[test]
    fn a_missing_ca_is_a_startup_failure_not_a_surprise_later() {
        let cfg = zone_with("    origin_tls:\n      ca: \"/nope/does-not-exist.pem\"\n");
        let err = preflight(&cfg).expect_err("a path that is not there should fail");
        let text = format!("{err:#}");

        assert!(text.contains("origin_tls"), "unhelpful error: {text}");
        assert!(text.contains("demo"), "should name the zone: {text}");
    }

    #[test]
    fn a_client_certificate_needs_its_key() {
        /* only half of a pair is a config mistake, and config catches it */
        let broken = config::parse(
            "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    \
             origin:\n      url: \"https://origin.internal\"\n    \
             origin_tls:\n      client_cert: \"a.crt\"\n",
        );
        let err = format!("{:#}", broken.expect_err("half a pair should be refused"));
        assert!(err.contains("client_key"), "unhelpful error: {err}");
    }
}
