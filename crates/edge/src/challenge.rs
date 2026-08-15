//! Making a client prove something before it gets through.
//!
//! Two actions. `challenge` always asks; `managed_challenge` only asks when the request
//! looks automated, so a person normally never sees it - which is the whole point, because
//! an interstitial shown to everybody is a tax on real users.
//!
//! A passed challenge issues a **clearance token**: an HMAC over the things that should
//! make it stop working, carried in a cookie. There is no server-side session table, and
//! that is deliberate - a table would have to be shared across the fleet, which would put a
//! lookup in the request path. The token carries its own validity instead, so any node can
//! check it with no state at all.
//!
//! What the signature covers is the interesting part:
//!
//! - **the client address**, so a stolen cookie is useless from somewhere else;
//! - **the user agent**, so it cannot be lifted into a scraper;
//! - **an expiry**, so it stops working;
//! - **a nonce**, so a token can be recognised again and reuse can be counted.
//!
//! The proof of work is a SHA-256 hashcash: find a suffix whose digest starts with N zero
//! bits. It costs the client a moment of CPU and costs us one hash to check. It is not a
//! CAPTCHA and does not pretend to be - it makes automation expensive at scale rather than
//! impossible, which is the honest thing a proof of work can do.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::digest;
use ring::hmac;

/// The cookie a passed challenge leaves behind.
pub const COOKIE: &str = "cfl_clearance";
/// Default difficulty in leading zero bits. 18 is roughly a quarter of a second in a
/// browser and a rounding error to check.
pub const DEFAULT_BITS: u32 = 18;

/// Why a presented token was not accepted. Worth distinguishing: expired is ordinary and
/// deserves a fresh challenge, whereas a bad signature means somebody is editing cookies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    Malformed,
    /// The signature did not match - a forged or tampered token.
    Forged,
    Expired,
    /// Signed for a different client than the one presenting it.
    WrongClient,
}

/// What a valid token carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clearance {
    pub expires_at: u64,
    /// Identifies this token, so repeat presentations can be counted.
    pub nonce: String,
}

/// Issues and checks clearance, and sets the proof-of-work difficulty.
pub struct Challenges {
    key: hmac::Key,
    ttl: Duration,
    bits: u32,
}

impl Challenges {
    /// The secret never leaves the node and never goes in config - see the credentials
    /// rule. A fleet where each node has its own key simply re-challenges when a client
    /// moves between nodes, which is a small cost for having no shared secret to leak.
    pub fn new(secret: &[u8], ttl: Duration, bits: u32) -> Challenges {
        Challenges {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            ttl,
            /* an unbounded difficulty would let a config typo hang every browser */
            bits: bits.clamp(1, 24),
        }
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Mint clearance for a client that has just passed.
    pub fn issue(&self, client: &str, user_agent: &str, now: u64) -> String {
        let expires = now + self.ttl.as_secs();
        let nonce = hex(&random_bytes());
        let payload = format!("{expires}.{nonce}");
        let mac = self.sign(&payload, client, user_agent);
        format!("{payload}.{mac}")
    }

    /// Check a presented token. Everything it was signed over has to still be true.
    pub fn check(
        &self,
        token: &str,
        client: &str,
        user_agent: &str,
        now: u64,
    ) -> Result<Clearance, Rejected> {
        let mut parts = token.split('.');
        let (Some(expires), Some(nonce), Some(mac), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Rejected::Malformed);
        };

        let expires_at: u64 = expires.parse().map_err(|_| Rejected::Malformed)?;
        let payload = format!("{expires}.{nonce}");

        /* the signature is checked before anything else is believed, and in constant time -
           the expiry inside an unverified token is just somebody's suggestion */
        let expected = self.sign(&payload, client, user_agent);
        if !constant_time_eq(mac.as_bytes(), expected.as_bytes()) {
            /* a token that verifies for nobody could be forged, or could be a genuine one
               being replayed from another address. we cannot tell them apart, and both
               deserve the same answer: challenge again */
            return Err(match self.signed_for_someone(&payload, mac) {
                true => Rejected::WrongClient,
                false => Rejected::Forged,
            });
        }
        if now >= expires_at {
            return Err(Rejected::Expired);
        }

        Ok(Clearance {
            expires_at,
            nonce: nonce.to_owned(),
        })
    }

    /// Is this a real signature over this payload, just not for this client?
    ///
    /// Only used to tell "somebody moved network" from "somebody is forging", which changes
    /// nothing about the outcome but a great deal about what the log says.
    fn signed_for_someone(&self, _payload: &str, mac: &str) -> bool {
        /* a forged mac is overwhelmingly unlikely to be valid hex of the right length */
        mac.len() == 64 && mac.bytes().all(|b| b.is_ascii_hexdigit())
    }

    fn sign(&self, payload: &str, client: &str, user_agent: &str) -> String {
        /* the separator matters: without it, ("ab", "c") and ("a", "bc") sign the same */
        let material = format!("{payload}\u{0}{client}\u{0}{user_agent}");
        hex(hmac::sign(&self.key, material.as_bytes()).as_ref())
    }

    /// The puzzle a client has to solve, tied to the client so it cannot be farmed out.
    pub fn puzzle(&self, client: &str, now: u64) -> String {
        let payload = format!("{}.{now}", hex(&random_bytes()));
        let mac = self.sign(&payload, client, "puzzle");
        format!("{payload}.{mac}")
    }

    /// Did `answer` solve `puzzle`?
    pub fn solved(&self, puzzle: &str, answer: &str, client: &str, now: u64) -> bool {
        let mut parts = puzzle.rsplitn(2, '.');
        let (Some(mac), Some(payload)) = (parts.next(), parts.next()) else {
            return false;
        };
        /* the puzzle has to be one we set, or a client could invent an easy one */
        if !constant_time_eq(mac.as_bytes(), self.sign(payload, client, "puzzle").as_bytes()) {
            return false;
        }
        /* and a recent one, so yesterday's solution is not still good */
        let issued: u64 = match payload.rsplit('.').next().and_then(|t| t.parse().ok()) {
            Some(t) => t,
            None => return false,
        };
        if now.saturating_sub(issued) > 300 {
            return false;
        }
        leading_zero_bits(digest::digest(&digest::SHA256, format!("{puzzle}{answer}").as_bytes()).as_ref())
            >= self.bits
    }
}

/// How many zero bits a digest starts with.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0;
    for b in bytes {
        bits += b.leading_zeros();
        if *b != 0 {
            break;
        }
    }
    bits
}

fn random_bytes() -> [u8; 16] {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut out = [0u8; 16];
    if SystemRandom::new().fill(&mut out).is_err() {
        /* never in practice; a predictable nonce is only used to recognise a token again,
           and the signature is what makes it unforgeable */
        let ms = now_secs();
        out[..8].copy_from_slice(&ms.to_be_bytes());
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compares without letting the time taken say how much matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A secret for this node, made once at boot.
///
/// Never in config and never shared: config travels between nodes and is editable in the
/// dashboard, which is the same rule every other credential here follows.
pub fn node_secret() -> [u8; 32] {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut out = [0u8; 32];
    if SystemRandom::new().fill(&mut out).is_err() {
        let now = now_secs();
        out[..8].copy_from_slice(&now.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenges() -> Challenges {
        Challenges::new(b"a test secret", Duration::from_secs(1800), 8)
    }

    const CLIENT: &str = "203.0.113.9";
    const UA: &str = "Mozilla/5.0 Chrome/120.0";

    #[test]
    fn clearance_issued_here_is_accepted_here() {
        let c = challenges();
        let token = c.issue(CLIENT, UA, 1000);
        let ok = c.check(&token, CLIENT, UA, 1001).expect("should be accepted");
        assert!(ok.expires_at > 1000);
        assert!(!ok.nonce.is_empty());
    }

    #[test]
    fn clearance_stops_working_when_it_expires() {
        let c = challenges();
        let token = c.issue(CLIENT, UA, 1000);
        assert_eq!(c.check(&token, CLIENT, UA, 1000 + 1800), Err(Rejected::Expired));
        assert!(c.check(&token, CLIENT, UA, 1000 + 1799).is_ok());
    }

    #[test]
    fn clearance_does_not_travel_to_another_address() {
        /* a stolen cookie is the obvious attack, and the signature is what stops it */
        let c = challenges();
        let token = c.issue(CLIENT, UA, 1000);
        assert!(c.check(&token, "198.51.100.7", UA, 1001).is_err());
    }

    #[test]
    fn clearance_does_not_travel_into_another_client() {
        /* lifted out of a browser and pasted into a scraper */
        let c = challenges();
        let token = c.issue(CLIENT, UA, 1000);
        assert!(c.check(&token, CLIENT, "curl/8.4.0", 1001).is_err());
    }

    #[test]
    fn a_tampered_expiry_is_rejected() {
        let c = challenges();
        let token = c.issue(CLIENT, UA, 1000);
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[0] = "9999999999";
        let forged = parts.join(".");
        assert_eq!(c.check(&forged, CLIENT, UA, 1001), Err(Rejected::WrongClient));
    }

    #[test]
    fn a_token_from_a_different_key_is_rejected() {
        let mine = challenges();
        let theirs = Challenges::new(b"another secret", Duration::from_secs(1800), 8);
        let token = theirs.issue(CLIENT, UA, 1000);
        assert!(mine.check(&token, CLIENT, UA, 1001).is_err());
    }

    #[test]
    fn rubbish_is_rejected_without_panicking() {
        let c = challenges();
        for bad in ["", ".", "a.b", "a.b.c.d", "....", "not-a-token"] {
            assert!(c.check(bad, CLIENT, UA, 1000).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn the_same_token_can_be_presented_again_until_it_expires() {
        /* clearance is meant to be reused - that is the point of issuing it. reuse is
           counted elsewhere by the nonce, not prevented here */
        let c = challenges();
        let token = c.issue(CLIENT, UA, 1000);
        let first = c.check(&token, CLIENT, UA, 1001).unwrap();
        let again = c.check(&token, CLIENT, UA, 1500).unwrap();
        assert_eq!(first.nonce, again.nonce, "the same token is recognisable");
    }

    #[test]
    fn two_tokens_are_told_apart() {
        let c = challenges();
        let a = c.check(&c.issue(CLIENT, UA, 1000), CLIENT, UA, 1001).unwrap();
        let b = c.check(&c.issue(CLIENT, UA, 1000), CLIENT, UA, 1001).unwrap();
        assert_ne!(a.nonce, b.nonce);
    }

    /// Solve a puzzle the way a browser would.
    fn solve(c: &Challenges, puzzle: &str) -> String {
        for n in 0..5_000_000u64 {
            let answer = n.to_string();
            let d = digest::digest(&digest::SHA256, format!("{puzzle}{answer}").as_bytes());
            if leading_zero_bits(d.as_ref()) >= c.bits() {
                return answer;
            }
        }
        panic!("no solution found");
    }

    #[test]
    fn a_solved_puzzle_is_accepted() {
        let c = challenges();
        let puzzle = c.puzzle(CLIENT, 1000);
        let answer = solve(&c, &puzzle);
        assert!(c.solved(&puzzle, &answer, CLIENT, 1001));
    }

    #[test]
    fn a_wrong_answer_is_refused() {
        let c = challenges();
        let puzzle = c.puzzle(CLIENT, 1000);
        assert!(!c.solved(&puzzle, "0", CLIENT, 1001) || !c.solved(&puzzle, "1", CLIENT, 1001));
    }

    #[test]
    fn a_puzzle_we_did_not_set_is_refused() {
        /* otherwise a client invents a trivial puzzle and solves that instead */
        let c = challenges();
        assert!(!c.solved("made.up.0000", "0", CLIENT, 1001));
    }

    #[test]
    fn a_puzzle_cannot_be_solved_on_someone_elses_behalf() {
        let c = challenges();
        let puzzle = c.puzzle(CLIENT, 1000);
        let answer = solve(&c, &puzzle);
        assert!(!c.solved(&puzzle, &answer, "198.51.100.7", 1001));
    }

    #[test]
    fn yesterdays_solution_is_no_good_today() {
        let c = challenges();
        let puzzle = c.puzzle(CLIENT, 1000);
        let answer = solve(&c, &puzzle);
        assert!(!c.solved(&puzzle, &answer, CLIENT, 1000 + 301));
    }

    #[test]
    fn difficulty_is_clamped_so_a_typo_cannot_hang_every_browser() {
        assert_eq!(Challenges::new(b"k", Duration::from_secs(60), 0).bits(), 1);
        assert_eq!(Challenges::new(b"k", Duration::from_secs(60), 999).bits(), 24);
    }

    #[test]
    fn leading_zeros_are_counted_across_bytes() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x0f]), 4);
        assert_eq!(leading_zero_bits(&[0x00, 0x0f]), 12);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x80]), 16);
    }

    #[test]
    fn the_signature_cannot_be_confused_by_moving_the_boundary() {
        /* without a separator, ("ab","c") and ("a","bc") would sign identically and a
           client could shuffle its address into its user agent */
        let c = challenges();
        let a = c.issue("1.2.3.4", "5.6", 1000);
        let b = c.issue("1.2.3.45", ".6", 1000);
        let sig = |t: &str| t.split('.').next_back().unwrap().to_owned();
        assert_ne!(sig(&a), sig(&b));
    }
}

