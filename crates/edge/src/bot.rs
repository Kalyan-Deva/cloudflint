//! Working out whether a request came from a person.
//!
//! The output is a **score from 1 to 99**, low meaning automated. Not a boolean, because
//! the honest state of knowledge is a degree of confidence: a request can look slightly
//! off without being worth blocking, and a rule author is better served by
//! `bot.score lt "30"` than by somebody else's threshold baked in.
//!
//! Three kinds of evidence, and they are deliberately kept apart:
//!
//! 1. **Verification** - a crawler that says it is Googlebot *and* comes from Google's
//!    network is verified. One that says it is Googlebot from a consumer VPS is not merely
//!    unverified, it is lying, and that is the strongest cheap signal there is.
//! 2. **Consistency** - real browsers send a particular shape of request. A client claiming
//!    to be Chrome with no `Accept-Language` and no `Accept-Encoding` is not Chrome.
//! 3. **Provenance** - where the address is. A datacenter is not an accusation on its own
//!    (see `geoip`), but a datacenter *claiming to be a browser* is.
//!
//! What this deliberately does **not** do is a network call. Real crawler verification is
//! usually reverse DNS plus a forward confirm, which is a DNS round trip inside a request -
//! the same thing the whole architecture refuses elsewhere. Matching the published address
//! ranges instead is exact, free, and answers the same question.

use std::net::IpAddr;

use hyper::HeaderMap;

use crate::geoip::Located;
use crate::waf::compile::Net;

/// The lowest score. Reserved for a client caught lying about who it is.
const IMPOSTOR: u8 = 1;
/// What a verified crawler gets. Well below any sane "is a bot" threshold, because it *is*
/// a bot - the point is that it is a welcome one, which `bot.verified` says separately.
const VERIFIED_BOT: u8 = 20;
/// A request with nothing wrong with it.
const CLEAN: u8 = 99;

/// What we concluded about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// 1..=99. Low is automated, high is probably a person.
    pub score: u8,
    /// A crawler that proved it is who it claims. Never true for an unknown client.
    pub verified: bool,
    /// The crawler's name when recognised - `googlebot`, `bingbot` - else empty.
    pub name: String,
    /// Why the score is what it is, for the log and the dashboard. A score with no
    /// explanation is impossible to argue with, which makes it impossible to tune.
    pub reasons: Vec<&'static str>,
}

impl Default for Verdict {
    fn default() -> Self {
        Verdict {
            score: CLEAN,
            verified: false,
            name: String::new(),
            reasons: Vec::new(),
        }
    }
}

impl Verdict {
    /// A bot we are glad to see: verified, and therefore not to be challenged.
    pub fn good(&self) -> bool {
        self.verified
    }

    /// Automated and not vouched for. What a `challenge` rule is usually after.
    pub fn bad(&self, below: u8) -> bool {
        !self.verified && self.score < below
    }
}

/// One crawler we know how to check.
#[derive(Debug, Clone)]
pub struct Crawler {
    pub name: String,
    /// Lower-cased substring of the user agent that claims to be this crawler.
    pub claims: String,
    /// The networks it is genuinely allowed to come from. Empty means the claim can never
    /// be verified, so the crawler is only ever *recognised*, never trusted.
    pub networks: Vec<Net>,
    /// AS numbers it is allowed to come from, as an alternative to listing prefixes.
    pub asns: Vec<u32>,
}

/// The crawlers recognised out of the box, by the address ranges their operators publish.
///
/// Kept short and boring on purpose. A wrong entry here does not fail safe - it would let
/// somebody spoof a trusted crawler - so a range only appears if it is published and
/// stable. Everything else belongs in config.
pub fn builtin_crawlers() -> Vec<Crawler> {
    let net = |s: &str| Net::parse(s).expect("a built-in range should parse");

    vec![
        Crawler {
            name: "googlebot".into(),
            claims: "googlebot".into(),
            networks: vec![],
            /* Google crawls from AS15169. Listing the ASN rather than the prefixes means
               this does not rot every time they announce a new block */
            asns: vec![15169],
        },
        Crawler {
            name: "bingbot".into(),
            claims: "bingbot".into(),
            networks: vec![],
            asns: vec![8075],
        },
        Crawler {
            name: "applebot".into(),
            claims: "applebot".into(),
            networks: vec![],
            asns: vec![714, 6185],
        },
        Crawler {
            name: "duckduckbot".into(),
            claims: "duckduckbot".into(),
            networks: vec![net("20.191.45.212/32"), net("40.88.21.235/32")],
            asns: vec![],
        },
        Crawler {
            name: "uptimerobot".into(),
            claims: "uptimerobot".into(),
            networks: vec![],
            asns: vec![],
        },
    ]
}

/// User agents that do not pretend to be anything else. Not malicious by definition -
/// plenty of legitimate automation says `curl` - but they are certainly not people.
const HONEST_TOOLS: &[&str] = &[
    "curl/", "wget/", "python-requests", "python-urllib", "go-http-client", "java/",
    "okhttp", "libwww-perl", "axios/", "node-fetch", "httpie", "postmanruntime", "guzzle",
    "apache-httpclient", "aiohttp", "scrapy",
];

/// Tools whose entire purpose is finding a way in.
const ATTACK_TOOLS: &[&str] = &[
    "sqlmap", "nikto", "nmap", "masscan", "nessus", "acunetix", "havij", "dirbuster",
    "gobuster", "wpscan", "zgrab", "metasploit", "burpsuite", "hydra",
];

/// Strings a real browser's user agent contains.
const BROWSERISH: &[&str] = &["mozilla/", "chrome/", "safari/", "firefox/", "edg/", "opera/"];

pub struct Detector {
    crawlers: Vec<Crawler>,
}

impl Default for Detector {
    fn default() -> Self {
        Detector::new(builtin_crawlers())
    }
}

impl Detector {
    pub fn new(crawlers: Vec<Crawler>) -> Detector {
        Detector { crawlers }
    }

    /// Score one request. Cheap enough for the request path: a few string searches and, at
    /// most, a walk over a handful of CIDR ranges.
    pub fn assess(&self, ip: IpAddr, headers: &HeaderMap, geo: &Located) -> Verdict {
        let ua = headers
            .get(hyper::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        let mut v = Verdict::default();

        /* an attack tool is not worth scoring subtly */
        if ATTACK_TOOLS.iter().any(|t| ua.contains(t)) {
            v.score = IMPOSTOR;
            v.reasons.push("the user agent names an attack tool");
            return v;
        }

        /* does it claim to be a crawler we know? */
        if let Some(crawler) = self.crawlers.iter().find(|c| ua.contains(&c.claims)) {
            v.name = crawler.name.clone();
            let checkable = !crawler.networks.is_empty() || !crawler.asns.is_empty();
            let from_theirs = crawler.networks.iter().any(|n| n.contains(ip))
                || geo.asn.map(|a| crawler.asns.contains(&a)).unwrap_or(false);

            return match (checkable, from_theirs) {
                (true, true) => {
                    v.verified = true;
                    v.score = VERIFIED_BOT;
                    v.reasons.push("a verified crawler, from its own network");
                    v
                }
                /* the strongest signal in the whole module: claiming to be Googlebot from
                   somebody else's network is not a mistake anyone makes by accident */
                (true, false) => {
                    v.score = IMPOSTOR;
                    v.reasons.push("claims to be a known crawler but is not on its network");
                    v
                }
                /* recognised but unprovable - treated as an ordinary bot, not trusted */
                (false, _) => {
                    v.score = 30;
                    v.reasons.push("a known crawler, but there is no way to verify it");
                    v
                }
            };
        }

        if ua.is_empty() {
            v.score = 5;
            v.reasons.push("no user agent at all");
            return v;
        }
        if HONEST_TOOLS.iter().any(|t| ua.contains(t)) {
            v.score = 25;
            v.reasons.push("the user agent is a http client, not a browser");
            /* an http library coming out of a datacenter is ordinary; the same library
               from a residential address is more interesting, but not by much */
            return v;
        }

        /* from here on it claims to be a browser, so the question is whether it behaves
           like one. each inconsistency is worth a bite out of the score rather than an
           immediate verdict, because any single one of them has innocent explanations */
        let mut penalty = 0u8;
        let claims_browser = BROWSERISH.iter().any(|b| ua.contains(b));

        if !claims_browser {
            penalty += 30;
            v.reasons.push("the user agent is neither a browser nor a known tool");
        } else {
            if !headers.contains_key(hyper::header::ACCEPT) {
                penalty += 25;
                v.reasons.push("a browser would send Accept");
            }
            if !headers.contains_key(hyper::header::ACCEPT_LANGUAGE) {
                penalty += 20;
                v.reasons.push("a browser would send Accept-Language");
            }
            if !headers.contains_key(hyper::header::ACCEPT_ENCODING) {
                penalty += 20;
                v.reasons.push("a browser would send Accept-Encoding");
            }
            /* a modern Chrome says so; its absence alongside a Chrome user agent is a
               mismatch between what it claims and what it is */
            if ua.contains("chrome/") && !headers.contains_key("sec-fetch-mode") {
                penalty += 15;
                v.reasons.push("claims Chrome but sends no Sec-Fetch headers");
            }
        }

        if geo.hosting {
            penalty += 25;
            v.reasons.push("a browser session coming out of a datacenter");
        }
        if geo.tor {
            penalty += 10;
            v.reasons.push("a tor exit node");
        }

        v.score = CLEAN.saturating_sub(penalty).max(IMPOSTOR);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, val) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(val).unwrap(),
            );
        }
        h
    }

    /// What a real Chrome sends, near enough.
    fn browser() -> HeaderMap {
        headers(&[
            ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
            ("accept", "text/html,application/xhtml+xml"),
            ("accept-language", "en-GB,en;q=0.9"),
            ("accept-encoding", "gzip, deflate, br"),
            ("sec-fetch-mode", "navigate"),
        ])
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn geo_asn(asn: u32) -> Located {
        Located {
            asn: Some(asn),
            ..Located::default()
        }
    }

    #[test]
    fn a_plausible_browser_scores_clean() {
        let v = Detector::default().assess(ip("203.0.113.9"), &browser(), &Located::default());
        assert_eq!(v.score, CLEAN);
        assert!(!v.verified);
        assert!(v.reasons.is_empty(), "a clean request needs no explanation");
    }

    #[test]
    fn googlebot_from_google_is_verified() {
        let h = headers(&[("user-agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")]);
        let v = Detector::default().assess(ip("66.249.66.1"), &h, &geo_asn(15169));

        assert!(v.verified);
        assert_eq!(v.name, "googlebot");
        assert_eq!(v.score, VERIFIED_BOT);
        assert!(v.good(), "a verified crawler should not be challenged");
        assert!(!v.bad(30), "and should not read as malicious");
    }

    #[test]
    fn googlebot_from_somewhere_else_is_an_impostor() {
        /* the signal the whole module exists for: nobody claims to be Googlebot from a
           consumer VPS by accident */
        let h = headers(&[("user-agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")]);
        let v = Detector::default().assess(ip("203.0.113.9"), &h, &geo_asn(64512));

        assert!(!v.verified);
        assert_eq!(v.score, IMPOSTOR);
        assert_eq!(v.name, "googlebot", "we still know what it claimed to be");
        assert!(v.bad(30));
        assert!(v.reasons[0].contains("not on its network"));
    }

    #[test]
    fn a_crawler_with_no_published_ranges_is_recognised_but_never_trusted() {
        let h = headers(&[("user-agent", "Mozilla/5.0 (compatible; UptimeRobot/2.0)")]);
        let v = Detector::default().assess(ip("203.0.113.9"), &h, &Located::default());

        assert_eq!(v.name, "uptimerobot");
        assert!(!v.verified, "nothing to check it against means it cannot be trusted");
        assert!(v.score < 50);
    }

    #[test]
    fn a_crawler_verified_by_address_range_rather_than_asn() {
        let h = headers(&[("user-agent", "DuckDuckBot/1.1")]);
        let v = Detector::default().assess(ip("20.191.45.212"), &h, &Located::default());
        assert!(v.verified);

        /* one address off is not the range */
        let v = Detector::default().assess(ip("20.191.45.213"), &h, &Located::default());
        assert!(!v.verified);
        assert_eq!(v.score, IMPOSTOR);
    }

    #[test]
    fn an_attack_tool_goes_straight_to_the_bottom() {
        for tool in ["sqlmap/1.7", "Nikto/2.5", "masscan/1.3"] {
            let v = Detector::default().assess(
                ip("203.0.113.9"),
                &headers(&[("user-agent", tool)]),
                &Located::default(),
            );
            assert_eq!(v.score, IMPOSTOR, "{tool} should score bottom");
            assert!(v.bad(30));
        }
    }

    #[test]
    fn an_honest_http_client_is_a_bot_but_not_an_impostor() {
        /* curl is not lying about anything, and plenty of legitimate automation uses it */
        let v = Detector::default().assess(
            ip("203.0.113.9"),
            &headers(&[("user-agent", "curl/8.4.0")]),
            &Located::default(),
        );
        assert!(v.score > IMPOSTOR, "not an impostor");
        assert!(v.score < 50, "but plainly not a person");
    }

    #[test]
    fn no_user_agent_at_all_scores_very_low() {
        let v = Detector::default().assess(ip("203.0.113.9"), &HeaderMap::new(), &Located::default());
        assert!(v.score < 10);
        assert!(v.reasons[0].contains("no user agent"));
    }

    #[test]
    fn claiming_to_be_a_browser_without_a_browser_shape_costs_score() {
        /* the common scraper: a copied Chrome user agent and nothing else */
        let h = headers(&[("user-agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36")]);
        let v = Detector::default().assess(ip("203.0.113.9"), &h, &Located::default());

        assert!(v.score < 40, "score was {}", v.score);
        assert!(v.reasons.iter().any(|r| r.contains("Accept-Language")));
        assert!(v.reasons.iter().any(|r| r.contains("Sec-Fetch")));
    }

    #[test]
    fn a_browser_from_a_datacenter_is_worth_noticing() {
        let datacenter = Located {
            hosting: true,
            ..Located::default()
        };
        let clean = Detector::default().assess(ip("203.0.113.9"), &browser(), &Located::default());
        let hosted = Detector::default().assess(ip("203.0.113.9"), &browser(), &datacenter);

        assert!(hosted.score < clean.score, "a datacenter browser should score lower");
        assert!(hosted.reasons.iter().any(|r| r.contains("datacenter")));
        /* but on its own it is not damning - plenty of real traffic is proxied */
        assert!(hosted.score > 50, "score was {}", hosted.score);
    }

    #[test]
    fn the_penalties_stack_towards_the_floor_without_going_under_it() {
        let awful = Located {
            hosting: true,
            tor: true,
            ..Located::default()
        };
        let h = headers(&[("user-agent", "Mozilla/5.0 Chrome/120.0")]);
        let v = Detector::default().assess(ip("203.0.113.9"), &h, &awful);

        assert!(v.score >= IMPOSTOR, "the score must never underflow");
        assert!(v.score < 15, "score was {}", v.score);
    }

    #[test]
    fn a_score_always_lands_in_range() {
        /* whatever the input, a rule comparing against 1..99 must have a number to compare */
        let cases: Vec<HeaderMap> = vec![
            HeaderMap::new(),
            browser(),
            headers(&[("user-agent", "")]),
            headers(&[("user-agent", "sqlmap")]),
            headers(&[("user-agent", "Googlebot")]),
        ];
        for h in cases {
            let v = Detector::default().assess(ip("203.0.113.9"), &h, &Located::default());
            assert!((IMPOSTOR..=CLEAN).contains(&v.score), "score was {}", v.score);
        }
    }

    #[test]
    fn extra_crawlers_can_be_configured() {
        let detector = Detector::new(vec![Crawler {
            name: "housebot".into(),
            claims: "housebot".into(),
            networks: vec![Net::parse("10.0.0.0/8").unwrap()],
            asns: vec![],
        }]);
        let h = headers(&[("user-agent", "HouseBot/1.0")]);

        assert!(detector.assess(ip("10.1.2.3"), &h, &Located::default()).verified);
        assert!(!detector.assess(ip("192.0.2.1"), &h, &Located::default()).verified);
        /* and the built-ins are gone, because the caller replaced them */
        let google = headers(&[("user-agent", "Googlebot/2.1")]);
        assert!(!detector.assess(ip("66.249.66.1"), &google, &geo_asn(15169)).verified);
    }
}
