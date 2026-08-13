//! The signing half of ACME: an account key, and the JWS every request is wrapped in.
//!
//! ACME authenticates requests by signing them, not with a token. Every POST is a
//! flattened JWS whose protected header carries the URL being called and a single-use
//! nonce, which is what stops a captured request being replayed anywhere else.
//!
//! ES256 rather than RS256: the account key is generated here and never typed by anyone,
//! so there is no reason to prefer the larger, slower option. `ring` signs P-256 in the
//! fixed 64-byte `r || s` form, which is exactly what JWS wants - the ASN.1 form would
//! have to be unpacked.
//!
//! Base64url is hand-rolled for the same reason `hex` in `auth` is: it is fifteen lines,
//! it needs the URL alphabet without padding, and it is not worth a dependency.

use anyhow::{Context, Result};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::json;

/// The account's key pair, which *is* the account as far as the CA is concerned.
pub struct AccountKey {
    pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl AccountKey {
    /// A new key, and its PKCS#8 PEM so the caller can keep it.
    pub fn generate() -> Result<(AccountKey, String)> {
        let rng = SystemRandom::new();
        let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("could not generate an account key"))?;
        let pem = pem("PRIVATE KEY", der.as_ref());
        let key = AccountKey::from_pkcs8(der.as_ref())?;
        Ok((key, pem))
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<AccountKey> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|e| anyhow::anyhow!("not a usable P-256 account key: {e}"))?;
        Ok(AccountKey { pair, rng })
    }

    /// Read one from a PEM file, or make one and write it there.
    pub fn load_or_create(path: &std::path::Path) -> Result<AccountKey> {
        if let Ok(text) = std::fs::read_to_string(path) {
            let der = unpem(&text).context("reading the acme account key")?;
            return AccountKey::from_pkcs8(&der);
        }

        let (key, pem) = AccountKey::generate()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        std::fs::write(path, pem)
            .with_context(|| format!("writing a new acme account key to {}", path.display()))?;
        tracing::info!("generated a new acme account key at {}", path.display());
        Ok(key)
    }

    /// The public key as a JWK, with members in the order RFC 7638 requires - which is
    /// lexicographic, because the thumbprint is a hash of this exact text.
    pub fn jwk(&self) -> String {
        let public = self.pair.public_key().as_ref();
        /* uncompressed point: 0x04 || X || Y */
        let (x, y) = public[1..].split_at(32);
        format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            b64url(x),
            b64url(y)
        )
    }

    /// RFC 7638 thumbprint: SHA-256 of the canonical JWK, base64url.
    pub fn thumbprint(&self) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, self.jwk().as_bytes());
        b64url(digest.as_ref())
    }

    /// What an http-01 challenge has to serve: the token, a dot, and the thumbprint.
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint())
    }

    /// A flattened JWS for one request. `kid` is the account URL once there is one; the
    /// very first request (newAccount) has no account yet and sends the whole key instead.
    pub fn sign(&self, url: &str, nonce: &str, payload: &str, kid: Option<&str>) -> Result<String> {
        let protected = match kid {
            Some(kid) => format!(
                r#"{{"alg":"ES256","kid":"{kid}","nonce":"{nonce}","url":"{url}"}}"#
            ),
            None => format!(
                r#"{{"alg":"ES256","jwk":{},"nonce":"{nonce}","url":"{url}"}}"#,
                self.jwk()
            ),
        };

        let protected = b64url(protected.as_bytes());
        let payload = b64url(payload.as_bytes());
        let signing_input = format!("{protected}.{payload}");

        let signature = self
            .pair
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|_| anyhow::anyhow!("signing the acme request failed"))?;

        Ok(json!({
            "protected": protected,
            "payload": payload,
            "signature": b64url(signature.as_ref()),
        })
        .to_string())
    }
}

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url, no padding - what every field in a JWS uses.
pub fn b64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b = |i: usize| *chunk.get(i).unwrap_or(&0) as u32;
        let packed = (b(0) << 16) | (b(1) << 8) | b(2);
        /* one output character per 6 bits, and one fewer for each byte we did not have */
        let keep = chunk.len() + 1;
        for i in 0..keep {
            let index = (packed >> (18 - i * 6)) & 0x3f;
            out.push(ALPHABET[index as usize] as char);
        }
    }
    out
}

/// Wrap DER in a PEM block.
fn pem(label: &str, der: &[u8]) -> String {
    let body = base64_standard(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The one place standard base64 is needed - PEM predates the url-safe alphabet.
fn base64_standard(bytes: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = |i: usize| *chunk.get(i).unwrap_or(&0) as u32;
        let packed = (b(0) << 16) | (b(1) << 8) | b(2);
        for i in 0..4 {
            match i <= chunk.len() {
                true => out.push(alphabet[((packed >> (18 - i * 6)) & 0x3f) as usize] as char),
                false => out.push('='),
            }
        }
    }
    out
}

/// The body of a PEM block, decoded.
fn unpem(text: &str) -> Result<Vec<u8>> {
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();

    let mut out = Vec::with_capacity(body.len() / 4 * 3);
    let mut packed = 0u32;
    let mut bits = 0;
    for c in body.chars() {
        if c == '=' {
            break;
        }
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            other => anyhow::bail!("`{other}` is not base64"),
        };
        packed = (packed << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((packed >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_the_rfc_examples() {
        /* RFC 4648 test vectors, with the url alphabet and no padding */
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(b"foob"), "Zm9vYg");
        assert_eq!(b64url(b"fooba"), "Zm9vYmE");
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        /* the two characters that differ from standard base64 */
        assert_eq!(b64url(&[251, 255]), "-_8");
    }

    #[test]
    fn pem_round_trips() {
        let bytes: Vec<u8> = (0..200u32).map(|n| (n * 7 % 256) as u8).collect();
        let text = pem("PRIVATE KEY", &bytes);

        assert!(text.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(text.trim_end().ends_with("-----END PRIVATE KEY-----"));
        assert!(
            text.lines().all(|l| l.len() <= 64),
            "pem lines are wrapped at 64"
        );
        assert_eq!(unpem(&text).unwrap(), bytes);
    }

    #[test]
    fn an_account_key_survives_being_written_and_read() {
        let (key, pem) = AccountKey::generate().unwrap();
        let der = unpem(&pem).unwrap();
        let again = AccountKey::from_pkcs8(&der).unwrap();

        assert_eq!(key.jwk(), again.jwk(), "the same key, so the same jwk");
        assert_eq!(key.thumbprint(), again.thumbprint());
    }

    #[test]
    fn the_jwk_is_canonical_because_the_thumbprint_depends_on_it() {
        let (key, _) = AccountKey::generate().unwrap();
        let jwk = key.jwk();

        /* members in lexicographic order, no whitespace: RFC 7638 hashes this text, so
           any prettiness here would produce a thumbprint the CA does not agree with */
        assert!(jwk.starts_with(r#"{"crv":"P-256","kty":"EC","x":""#), "{jwk}");
        assert!(!jwk.contains(' '));
        assert!(!jwk.contains('\n'));

        /* and it parses as the json it claims to be */
        let parsed: serde_json::Value = serde_json::from_str(&jwk).unwrap();
        assert_eq!(parsed["kty"], "EC");
        assert_eq!(parsed["crv"], "P-256");
        /* 32 bytes each, base64url with no padding */
        assert_eq!(parsed["x"].as_str().unwrap().len(), 43);
        assert_eq!(parsed["y"].as_str().unwrap().len(), 43);
    }

    #[test]
    fn a_thumbprint_is_a_sha256_in_base64url() {
        let (key, _) = AccountKey::generate().unwrap();
        let print = key.thumbprint();

        assert_eq!(print.len(), 43, "32 bytes, base64url, unpadded");
        assert!(!print.contains('='));
        assert!(!print.contains('+') && !print.contains('/'));
    }

    #[test]
    fn a_key_authorization_is_the_token_and_the_thumbprint() {
        let (key, _) = AccountKey::generate().unwrap();
        let auth = key.key_authorization("tok3n");

        let (token, print) = auth.split_once('.').expect("token.thumbprint");
        assert_eq!(token, "tok3n");
        assert_eq!(print, key.thumbprint());
    }

    #[test]
    fn a_signed_request_has_the_shape_acme_expects() {
        let (key, _) = AccountKey::generate().unwrap();
        let jws = key
            .sign("https://acme.test/new-order", "nonce1", r#"{"a":1}"#, Some("acct/1"))
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();

        for field in ["protected", "payload", "signature"] {
            assert!(parsed[field].is_string(), "missing {field}");
        }
        /* the signature is 64 bytes: r || s, not asn.1 */
        assert_eq!(parsed["signature"].as_str().unwrap().len(), 86);

        let header: serde_json::Value =
            serde_json::from_slice(&unb64url(parsed["protected"].as_str().unwrap())).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["nonce"], "nonce1");
        assert_eq!(header["url"], "https://acme.test/new-order");
        assert_eq!(header["kid"], "acct/1");
        assert!(header["jwk"].is_null(), "a kid request must not also send the key");
    }

    #[test]
    fn the_first_request_sends_the_key_instead_of_an_account() {
        let (key, _) = AccountKey::generate().unwrap();
        let jws = key.sign("https://acme.test/new-acct", "n", "{}", None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&unb64url(parsed["protected"].as_str().unwrap())).unwrap();

        assert!(header["kid"].is_null());
        assert_eq!(header["jwk"]["kty"], "EC");
    }

    #[test]
    fn a_post_as_get_signs_an_empty_payload() {
        let (key, _) = AccountKey::generate().unwrap();
        let jws = key.sign("https://acme.test/order/1", "n", "", Some("acct/1")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();

        assert_eq!(
            parsed["payload"], "",
            "an empty payload is how acme does an authenticated GET"
        );
    }

    /// Decode base64url, for tests that want to read back what was signed.
    fn unb64url(s: &str) -> Vec<u8> {
        unpem(s).expect("base64url should decode")
    }
}
