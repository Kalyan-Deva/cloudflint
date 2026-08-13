//! Who the client actually is.
//!
//! Everything the edge decides per client is keyed on one address: rate limit buckets,
//! `ip.src` rules, the live log. When Cloudveil is the first thing traffic touches, that
//! address is the peer on the socket and there is nothing to work out.
//!
//! Put it behind anything - a cloud load balancer, another CDN, an ingress controller -
//! and the peer becomes that thing. Every client in the world collapses into one rate
//! limit bucket and every `ip.src` rule matches the proxy. Nothing errors; the limits
//! just quietly stop being limits.
//!
//! The header that carries the truth is also the easiest header in HTTP to lie about, so
//! this cannot simply be "trust `X-Forwarded-For`" - that hands every client a way to
//! forge its own identity and walk past the limits it was caught by. What makes it safe
//! is only ever believing hops we were told to believe:
//!
//! - The **peer** must be a trusted proxy. If whoever opened the socket is not on the
//!   list, the header is decoration and the peer is the client. This one rule is what
//!   makes forgery pointless.
//! - The chain is then walked **right to left** - newest hop first - and the first
//!   address that is *not* a trusted proxy is the client. Anything a client wrote itself
//!   sits further left than the address its own proxy appended, so it is never reached.
//! - If every hop on the chain is trusted, the leftmost is the client. That is the case
//!   where the caller really is inside your own network.
//!
//! With no trusted proxies configured - the default - none of this runs and the peer is
//! always the client. Turning it on is a deployment decision, and a wrong list is worse
//! than no list.

use std::net::{IpAddr, SocketAddr};

use anyhow::Result;
use hyper::header::HeaderName;
use hyper::HeaderMap;

use crate::waf::Net;

/// The header a proxy in front of us records addresses in.
pub const DEFAULT_HEADER: &str = "x-forwarded-for";

/// Node-wide, not per zone: what sits in front of this process is a property of where it
/// is deployed, and the answer cannot differ per hostname.
#[derive(Debug, Clone)]
pub struct ClientIp {
    /// `x-forwarded-for` by default. Single-value headers work unchanged - a chain of
    /// one, whose only entry is the client.
    pub header: HeaderName,
    /// Empty means never look at the header at all.
    pub trusted: Vec<Net>,
}

impl Default for ClientIp {
    fn default() -> Self {
        ClientIp {
            header: HeaderName::from_static(DEFAULT_HEADER),
            trusted: Vec::new(),
        }
    }
}

impl ClientIp {
    pub fn new(header: &str, trusted: &[String]) -> Result<Self> {
        let header = HeaderName::try_from(header.to_ascii_lowercase().as_str())
            .map_err(|_| anyhow::anyhow!("`{header}` is not a valid header name"))?;
        let trusted = trusted
            .iter()
            .map(|t| Net::parse(t))
            .collect::<Result<Vec<_>>>()?;
        Ok(ClientIp { header, trusted })
    }

    pub fn trusts(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(ip))
    }

    /// The client's address, given who we are talking to and what they claim.
    pub fn resolve(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        let peer = peer.ip();
        /* the load-bearing check: an untrusted peer's claims are worth nothing */
        if self.trusted.is_empty() || !self.trusts(peer) {
            return peer;
        }
        let Some(chain) = headers.get(&self.header).and_then(|v| v.to_str().ok()) else {
            return peer;
        };

        let hops: Vec<&str> = chain.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
        let mut leftmost = None;

        for hop in hops.iter().rev() {
            let Some(addr) = parse_hop(hop) else {
                /* an entry we cannot read means we have lost track of the chain. stop
                   rather than guess: further left is where forgeries live */
                break;
            };
            leftmost = Some(addr);
            if !self.trusts(addr) {
                return addr;
            }
        }

        /* every hop was a proxy we trust, so the client really is one of ours */
        leftmost.unwrap_or(peer)
    }
}

/// Fixed rather than configurable: unlike the address header, everyone spells this one
/// the same way.
const PROTO_HEADER: &str = "x-forwarded-proto";

impl ClientIp {
    /// Whether the *client* used https. Behind a proxy that terminates TLS and forwards
    /// plaintext, our own leg says nothing about that - and a `not ssl` rule that fires
    /// on every request is a rule that blocks the whole site.
    pub fn resolve_tls(&self, peer: SocketAddr, headers: &HeaderMap, tls: bool) -> bool {
        if self.trusted.is_empty() || !self.trusts(peer.ip()) {
            return tls;
        }
        match headers.get(PROTO_HEADER).and_then(|v| v.to_str().ok()) {
            /* the leftmost value, same as the address chain: the first proxy to see the
               client is the one that knows what the client did */
            Some(proto) => match proto.split(',').next().map(str::trim) {
                Some(first) if first.eq_ignore_ascii_case("https") => true,
                Some(first) if first.eq_ignore_ascii_case("http") => false,
                _ => tls,
            },
            None => tls,
        }
    }
}

/// One entry of the chain. Most are a bare address; some proxies write `addr:port`, and
/// IPv6 turns up bracketed with or without one.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    if let Ok(addr) = hop.parse::<IpAddr>() {
        return Some(addr);
    }
    if let Ok(addr) = hop.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    /* `[2001:db8::1]` with no port is not a SocketAddr and not an IpAddr */
    hop.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn cfg(trusted: &[&str]) -> ClientIp {
        let owned: Vec<String> = trusted.iter().map(|t| t.to_string()).collect();
        ClientIp::new(DEFAULT_HEADER, &owned).expect("test config should build")
    }

    fn peer(s: &str) -> SocketAddr {
        format!("{s}:44321").parse().expect("test peer should parse")
    }

    fn chain(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(DEFAULT_HEADER),
            HeaderValue::from_str(value).expect("test header should be valid"),
        );
        headers
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address should parse")
    }

    #[test]
    fn with_nothing_trusted_the_peer_is_the_client() {
        let cfg = cfg(&[]);
        assert_eq!(
            cfg.resolve(peer("203.0.113.9"), &chain("198.51.100.7")),
            ip("203.0.113.9"),
            "the default must ignore the header completely"
        );
    }

    #[test]
    fn an_untrusted_peer_cannot_claim_to_speak_for_anyone() {
        let cfg = cfg(&["10.0.0.0/8"]);
        /* the whole anti-forgery property in one assertion */
        assert_eq!(
            cfg.resolve(peer("203.0.113.9"), &chain("1.2.3.4")),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn a_trusted_proxy_is_believed() {
        let cfg = cfg(&["10.0.0.0/8"]);
        assert_eq!(
            cfg.resolve(peer("10.1.2.3"), &chain("198.51.100.7")),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn the_rightmost_untrusted_hop_wins() {
        let cfg = cfg(&["10.0.0.0/8", "172.16.0.0/12"]);
        /* a client that made something up, then its real address as the first proxy
           recorded it, then two hops inside our network */
        let headers = chain("9.9.9.9, 198.51.100.7, 10.0.0.5, 172.16.4.4");
        assert_eq!(
            cfg.resolve(peer("10.1.2.3"), &headers),
            ip("198.51.100.7"),
            "the forged entry sits further left and must never be reached"
        );
    }

    #[test]
    fn a_chain_of_only_trusted_hops_falls_back_to_the_leftmost() {
        let cfg = cfg(&["10.0.0.0/8"]);
        assert_eq!(
            cfg.resolve(peer("10.1.2.3"), &chain("10.9.9.9, 10.0.0.5")),
            ip("10.9.9.9"),
            "the caller really is inside the trusted range"
        );
    }

    #[test]
    fn a_trusted_peer_with_no_header_is_still_just_the_peer() {
        let cfg = cfg(&["10.0.0.0/8"]);
        assert_eq!(
            cfg.resolve(peer("10.1.2.3"), &HeaderMap::new()),
            ip("10.1.2.3")
        );
        assert_eq!(cfg.resolve(peer("10.1.2.3"), &chain("   ")), ip("10.1.2.3"));
    }

    #[test]
    fn an_unreadable_entry_stops_the_walk_rather_than_being_believed() {
        let cfg = cfg(&["10.0.0.0/8"]);
        /* junk on the right: we never learn anything, so the peer stands */
        assert_eq!(
            cfg.resolve(peer("10.1.2.3"), &chain("198.51.100.7, unknown")),
            ip("10.1.2.3")
        );
        /* junk further left, after a good answer, changes nothing */
        assert_eq!(
            cfg.resolve(peer("10.1.2.3"), &chain("unknown, 198.51.100.7")),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn entries_may_carry_a_port_or_brackets() {
        let cfg = cfg(&["10.0.0.0/8"]);
        assert_eq!(
            cfg.resolve(peer("10.1.2.3"), &chain("198.51.100.7:51234")),
            ip("198.51.100.7")
        );
        assert_eq!(
            cfg.resolve(peer("10.1.2.3"), &chain("[2001:db8::1]:443")),
            ip("2001:db8::1")
        );
        assert_eq!(
            cfg.resolve(peer("10.1.2.3"), &chain("[2001:db8::2]")),
            ip("2001:db8::2")
        );
        assert_eq!(
            cfg.resolve(peer("10.1.2.3"), &chain("2001:db8::3")),
            ip("2001:db8::3")
        );
    }

    #[test]
    fn a_single_value_header_works_the_same_way() {
        /* cf-connecting-ip and true-client-ip hold one address, not a chain */
        let cfg = ClientIp::new("cf-connecting-ip", &["10.0.0.0/8".into()]).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("cf-connecting-ip"),
            HeaderValue::from_static("198.51.100.7"),
        );
        /* and the header it is not told to read is ignored */
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("9.9.9.9"),
        );

        assert_eq!(cfg.resolve(peer("10.1.2.3"), &headers), ip("198.51.100.7"));
    }

    #[test]
    fn ipv6_proxies_are_trusted_by_range_too() {
        let cfg = cfg(&["2001:db8::/32"]);
        let peer: SocketAddr = "[2001:db8::5]:44321".parse().unwrap();
        assert_eq!(cfg.resolve(peer, &chain("198.51.100.7")), ip("198.51.100.7"));
    }

    #[test]
    fn a_v4_range_does_not_trust_a_v6_peer() {
        let cfg = cfg(&["0.0.0.0/0"]);
        let v6: SocketAddr = "[2001:db8::5]:44321".parse().unwrap();
        assert_eq!(
            cfg.resolve(v6, &chain("198.51.100.7")),
            ip("2001:db8::5"),
            "families must not be mixed silently"
        );
    }

    #[test]
    fn a_trusted_proxy_can_say_the_client_used_https() {
        let cfg = cfg(&["10.0.0.0/8"]);
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(PROTO_HEADER),
            HeaderValue::from_static("https"),
        );

        /* our own leg is plaintext, but the client's was not */
        assert!(cfg.resolve_tls(peer("10.1.2.3"), &headers, false));
        /* and an untrusted peer saying the same thing changes nothing */
        assert!(!cfg.resolve_tls(peer("203.0.113.9"), &headers, false));
    }

    #[test]
    fn our_own_leg_is_the_answer_when_nobody_credible_says_otherwise() {
        let cfg = cfg(&["10.0.0.0/8"]);
        let proto = |value: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(
                HeaderName::from_static(PROTO_HEADER),
                HeaderValue::from_static(value),
            );
            headers
        };

        assert!(!cfg.resolve_tls(peer("10.1.2.3"), &proto("http"), true), "downgrade is honoured too");
        assert!(cfg.resolve_tls(peer("10.1.2.3"), &proto("nonsense"), true));
        assert!(cfg.resolve_tls(peer("10.1.2.3"), &HeaderMap::new(), true));
        /* a chain of protos: the leftmost is the client's */
        assert!(cfg.resolve_tls(peer("10.1.2.3"), &proto("https, http"), false));
    }

    #[test]
    fn a_bad_header_name_or_range_is_refused_rather_than_ignored() {
        assert!(ClientIp::new("not a header", &[]).is_err());
        assert!(ClientIp::new(DEFAULT_HEADER, &["10.0.0.0/40".into()]).is_err());
        assert!(ClientIp::new(DEFAULT_HEADER, &["hello".into()]).is_err());
    }
}
