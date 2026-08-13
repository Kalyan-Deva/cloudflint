//! Bearer tokens, and the one rule that keeps them safe to operate.
//!
//! **Secrets never travel in config.** The config file is pulled from the control
//! plane and shown in the dashboard's editor, so anything written there is visible to
//! everyone who can see the dashboard and is overwritten on the next reload. Tokens
//! and key paths therefore come from the environment, which is node-local, not from
//! the config that moves between nodes.
//!
//! Tokens are 256 bits of randomness, so they get a plain SHA-256 rather than a
//! password hash - argon2 exists to make *guessable* secrets expensive to try, and
//! there is nothing to guess here. Only the hash is ever stored.

use anyhow::{bail, Result};
use hyper::header::{HeaderMap, AUTHORIZATION};
use ring::rand::SecureRandom;

/// Compare without an early exit. ring's helper for this is deprecated and it is
/// four lines, so here it is: fold every byte in before deciding.
fn same(a: &[u8], b: &[u8]) -> bool {
    /* the length of a hash is not a secret */
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// Recognisable in a log or a config, and obviously not a password.
const PREFIX: &str = "cfl_";

/// Mint a new token. Returned once, in the clear - store the hash, not this.
pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("the system random number generator should work");
    format!("{PREFIX}{}", hex(&bytes))
}

pub fn hash(token: &str) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, token.as_bytes()).as_ref())
}

/// Compare in constant time.
///
/// Both sides are hashes rather than the secrets themselves, so a timing leak here
/// would only reveal a hash - but comparing them properly costs nothing and means
/// nobody has to reason about that.
pub fn matches(presented: &str, stored_hash: &str) -> bool {
    same(hash(presented).as_bytes(), stored_hash.as_bytes())
}

/// The token from an `Authorization: Bearer ...` header.
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|t| !t.is_empty())
}

/// A single token, for a service that only needs one - the edge admin API.
///
/// Reading it from the environment is deliberate: see the module note.
#[derive(Debug)]
pub struct Guard {
    hash: String,
}

impl Guard {
    /// Refuses to exist without a token. An admin API that can empty your cache
    /// should fail to start rather than start open.
    pub fn from_env(var: &str) -> Result<Guard> {
        match std::env::var(var) {
            Ok(token) if token.len() >= 16 => Ok(Guard { hash: hash(&token) }),
            Ok(_) => bail!("{var} is too short to be a token - mint one with `cloudflint-token`"),
            Err(_) => bail!(
                "{var} is not set. The admin api has no other protection, so it will not \
                 start without one - mint one with `cloudflint-token`"
            ),
        }
    }

    pub fn from_hash(hash: impl Into<String>) -> Guard {
        Guard { hash: hash.into() }
    }

    pub fn allows(&self, headers: &HeaderMap) -> bool {
        match bearer(headers) {
            Some(token) => matches(token, &self.hash),
            None => false,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0xf) as u32, 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn tokens_are_unique_and_recognisable() {
        let a = generate();
        let b = generate();

        assert_ne!(a, b);
        assert!(a.starts_with(PREFIX));
        /* derived from the prefix rather than a number: this test failed the day the
           project was renamed, which is not something a token test should notice */
        assert_eq!(a.len(), PREFIX.len() + 64, "256 bits, hex encoded");
    }

    #[test]
    fn a_token_matches_only_its_own_hash() {
        let token = generate();
        let stored = hash(&token);

        assert!(matches(&token, &stored));
        assert!(!matches(&generate(), &stored));
        assert!(!matches("", &stored));
        /* the hash is not the token */
        assert!(!matches(&stored, &stored));
    }

    #[test]
    fn hashing_is_stable_and_hides_the_token() {
        let token = generate();
        assert_eq!(hash(&token), hash(&token));
        assert!(!hash(&token).contains(&token[3..]));
        assert_eq!(hash(&token).len(), 64);
    }

    #[test]
    fn reads_a_bearer_header_and_nothing_else() {
        assert_eq!(bearer(&headers("Bearer cfl_abc")), Some("cfl_abc"));
        assert_eq!(bearer(&headers("bearer cfl_abc")), Some("cfl_abc"));
        assert_eq!(bearer(&headers("Basic cfl_abc")), None);
        assert_eq!(bearer(&headers("cfl_abc")), None);
        assert_eq!(bearer(&headers("Bearer ")), None);
        assert_eq!(bearer(&HeaderMap::new()), None);
    }

    #[test]
    fn a_guard_lets_the_right_token_through_and_nothing_else() {
        let token = generate();
        let guard = Guard::from_hash(hash(&token));

        assert!(guard.allows(&headers(&format!("Bearer {token}"))));
        assert!(!guard.allows(&headers(&format!("Bearer {}", generate()))));
        assert!(!guard.allows(&HeaderMap::new()));
    }

    #[test]
    fn a_missing_or_silly_token_stops_the_guard_existing() {
        let var = "CLOUDFLINT_TEST_TOKEN_THAT_IS_NOT_SET";
        std::env::remove_var(var);
        let err = Guard::from_env(var).unwrap_err().to_string();
        assert!(err.contains("will not start"), "unhelpful error: {err}");

        std::env::set_var(var, "short");
        assert!(Guard::from_env(var).unwrap_err().to_string().contains("too short"));

        let token = generate();
        std::env::set_var(var, &token);
        assert!(Guard::from_env(var).unwrap().allows(&headers(&format!("Bearer {token}"))));
        std::env::remove_var(var);
    }
}
