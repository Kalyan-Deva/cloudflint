//! What may be cached, for how long, and under what key.
//!
//! All of this is header archaeology, so it lives away from the stage that uses it.

use std::collections::HashSet;
use std::time::Duration;

use hyper::header::{self, HeaderMap};
use hyper::{Method, Request, StatusCode};

use super::Key;
use crate::body::Body;

/// Statuses worth holding on to. Deliberately short - no ranges, no redirect chains
/// beyond the permanent ones.
const CACHEABLE_STATUS: &[u16] = &[200, 203, 204, 301, 308, 404, 410];

/// Origin header naming the tags an entry can be purged by.
pub const TAG_HEADER: &str = "cache-tag";

#[derive(Debug, Clone)]
pub struct CachePolicy {
    pub enabled: bool,
    /// Request headers that form part of the key, lowercased.
    pub vary_on: Vec<String>,
    /// Query params dropped from the key entirely - tracking junk.
    pub ignore_query_params: HashSet<String>,
    /// If set, only these params are part of the key. None means all of them.
    pub key_query_params: Option<HashSet<String>>,
    pub stale_while_revalidate: Duration,
    pub stale_if_error: Duration,
    /// How long a request will wait behind another request for the same key.
    pub coalesce_wait: Duration,
    pub overrides: Vec<PathOverride>,
}

#[derive(Debug, Clone)]
pub struct PathOverride {
    pub path_prefix: String,
    pub ttl: Duration,
    /// Cache for `ttl` whatever the origin's Cache-Control says.
    pub override_origin_headers: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttl {
    pub fresh_for: Duration,
    pub stale_while_revalidate: Duration,
    pub stale_if_error: Duration,
}

/// Whether we'll look this request up at all.
pub fn request_cacheable(req: &Request<Body>) -> bool {
    if req.method() != Method::GET {
        return false;
    }
    if req.headers().contains_key(header::AUTHORIZATION) {
        return false;
    }
    /* `no-store` from a client is honoured; `no-cache` is not. Letting anyone force an
       origin fetch by sending a header is a free way to knock the origin over. */
    !parse_cache_control(req.headers()).no_store
}

pub fn build_key(zone: &str, host: &str, req: &Request<Body>, policy: &CachePolicy) -> Key {
    Key {
        zone: zone.to_owned(),
        host: host.to_ascii_lowercase(),
        path: req.uri().path().to_owned(),
        query: canonical_query(req.uri().query().unwrap_or(""), policy),
        vary: vary_key(req.headers(), policy),
    }
}

/// Sorted, with the junk removed, so `?b=2&a=1` and `?a=1&b=2&utm_source=x` land on
/// the same entry instead of shredding the cache into near-duplicates.
fn canonical_query(raw: &str, policy: &CachePolicy) -> String {
    let mut kept: Vec<(&str, &str)> = raw
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            if policy.ignore_query_params.contains(&lower) {
                return false;
            }
            match &policy.key_query_params {
                Some(only) => only.contains(&lower),
                None => true,
            }
        })
        .collect();

    kept.sort_unstable();
    kept.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn vary_key(headers: &HeaderMap, policy: &CachePolicy) -> String {
    policy
        .vary_on
        .iter()
        .map(|name| {
            let raw = headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            format!("{name}={}", normalize_vary(name, raw))
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// `gzip, deflate, br` and `br;q=1.0, gzip` want the same cached object. Without
/// this every browser's exact header spelling gets its own copy.
///
/// For accept-encoding this is deliberately the *same* function the compressor picks
/// with: entries are compressed before they are stored, so a key that disagreed with
/// the chosen encoding would serve one client another's bytes.
fn normalize_vary(name: &str, value: &str) -> String {
    if name != "accept-encoding" {
        return value.trim().to_ascii_lowercase();
    }
    crate::compress::preferred(value).as_str().to_string()
}

/// How long this response may be held, or None to not hold it at all.
pub fn response_ttl(
    status: StatusCode,
    headers: &HeaderMap,
    path: &str,
    policy: &CachePolicy,
) -> Option<Ttl> {
    /* a response that sets a cookie is per-user by definition. no override gets to
       turn this off - handing one visitor another's session is not a tuning choice */
    if headers.contains_key(header::SET_COOKIE) {
        return None;
    }
    if !vary_is_keyable(headers, policy) {
        return None;
    }

    let cc = parse_cache_control(headers);
    if cc.no_store || cc.private {
        return None;
    }

    let over = policy
        .overrides
        .iter()
        .find(|o| path.starts_with(&o.path_prefix));

    let stale_while_revalidate = cc
        .stale_while_revalidate
        .map(Duration::from_secs)
        .unwrap_or(policy.stale_while_revalidate);
    let stale_if_error = cc
        .stale_if_error
        .map(Duration::from_secs)
        .unwrap_or(policy.stale_if_error);

    if let Some(o) = over {
        if o.override_origin_headers {
            return Some(Ttl {
                fresh_for: o.ttl,
                stale_while_revalidate,
                stale_if_error,
            });
        }
    }

    if !CACHEABLE_STATUS.contains(&status.as_u16()) {
        return None;
    }
    /* no-cache means revalidate every time, and we don't do conditional requests yet */
    if cc.no_cache {
        return None;
    }

    let fresh_for = match cc.s_maxage.or(cc.max_age) {
        Some(secs) => Duration::from_secs(secs),
        None => over.map(|o| o.ttl)?,
    };

    if fresh_for.is_zero() && stale_while_revalidate.is_zero() {
        return None;
    }
    Some(Ttl {
        fresh_for,
        stale_while_revalidate,
        stale_if_error,
    })
}

/// We can only key on headers the zone already varies on. Anything else and we'd be
/// storing one variant under a key that other variants would match.
fn vary_is_keyable(headers: &HeaderMap, policy: &CachePolicy) -> bool {
    let Some(vary) = headers.get(header::VARY).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    vary.split(',').all(|name| {
        let name = name.trim().to_ascii_lowercase();
        !name.is_empty() && name != "*" && policy.vary_on.contains(&name)
    })
}

pub fn tags(headers: &HeaderMap) -> Vec<String> {
    headers
        .get(TAG_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CacheControl {
    pub no_store: bool,
    pub no_cache: bool,
    pub private: bool,
    pub public: bool,
    pub max_age: Option<u64>,
    pub s_maxage: Option<u64>,
    pub stale_while_revalidate: Option<u64>,
    pub stale_if_error: Option<u64>,
}

pub fn parse_cache_control(headers: &HeaderMap) -> CacheControl {
    let mut cc = CacheControl::default();

    for raw in headers.get_all(header::CACHE_CONTROL) {
        let Ok(value) = raw.to_str() else { continue };
        for token in value.split(',') {
            let token = token.trim();
            let (name, arg) = match token.split_once('=') {
                Some((n, v)) => (n.trim(), Some(v.trim().trim_matches('"'))),
                None => (token, None),
            };
            let secs = || arg.and_then(|a| a.parse::<u64>().ok());

            match name.to_ascii_lowercase().as_str() {
                "no-store" => cc.no_store = true,
                "no-cache" => cc.no_cache = true,
                "private" => cc.private = true,
                "public" => cc.public = true,
                "max-age" => cc.max_age = secs(),
                "s-maxage" => cc.s_maxage = secs(),
                "stale-while-revalidate" => cc.stale_while_revalidate = secs(),
                "stale-if-error" => cc.stale_if_error = secs(),
                _ => {}
            }
        }
    }
    cc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::full;

    fn policy() -> CachePolicy {
        CachePolicy {
            enabled: true,
            vary_on: vec!["accept-encoding".into()],
            ignore_query_params: ["utm_source", "fbclid"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            key_query_params: None,
            stale_while_revalidate: Duration::ZERO,
            stale_if_error: Duration::from_secs(60),
            coalesce_wait: Duration::from_secs(5),
            overrides: vec![PathOverride {
                path_prefix: "/static/".into(),
                ttl: Duration::from_secs(604800),
                override_origin_headers: true,
            }],
        }
    }

    fn req(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut b = Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(full("")).unwrap()
    }

    fn resp_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn ttl(pairs: &[(&str, &str)], path: &str) -> Option<Ttl> {
        response_ttl(StatusCode::OK, &resp_headers(pairs), path, &policy())
    }

    #[test]
    fn only_plain_gets_are_looked_up() {
        assert!(request_cacheable(&req("/a", &[])));
        assert!(!request_cacheable(&req("/a", &[("authorization", "Bearer x")])));
        assert!(!request_cacheable(&req("/a", &[("cache-control", "no-store")])));
        /* a client asking for no-cache does not get to force an origin fetch */
        assert!(request_cacheable(&req("/a", &[("cache-control", "no-cache")])));

        let post = Request::builder()
            .method(Method::POST)
            .uri("/a")
            .body(full(""))
            .unwrap();
        assert!(!request_cacheable(&post));
    }

    #[test]
    fn query_order_and_tracking_junk_do_not_split_the_cache() {
        let a = build_key("z", "demo.local", &req("/p?b=2&a=1", &[]), &policy());
        let b = build_key(
            "z",
            "demo.local",
            &req("/p?a=1&utm_source=news&b=2&fbclid=xyz", &[]),
            &policy(),
        );
        assert_eq!(a, b);
        assert_eq!(a.query, "a=1&b=2");
    }

    #[test]
    fn only_listed_params_key_the_entry_when_configured() {
        let mut p = policy();
        p.key_query_params = Some(["v"].iter().map(|s| s.to_string()).collect());

        let a = build_key("z", "demo.local", &req("/p?v=2&noise=a", &[]), &p);
        let b = build_key("z", "demo.local", &req("/p?v=2&noise=b", &[]), &p);
        let c = build_key("z", "demo.local", &req("/p?v=3", &[]), &p);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn accept_encoding_collapses_to_one_token() {
        let brotli = build_key(
            "z",
            "demo.local",
            &req("/p", &[("accept-encoding", "gzip, deflate, br")]),
            &policy(),
        );
        let also_brotli = build_key(
            "z",
            "demo.local",
            &req("/p", &[("accept-encoding", "br;q=1.0, gzip;q=0.8")]),
            &policy(),
        );
        let gzip = build_key(
            "z",
            "demo.local",
            &req("/p", &[("accept-encoding", "gzip")]),
            &policy(),
        );
        let none = build_key("z", "demo.local", &req("/p", &[]), &policy());

        assert_eq!(brotli, also_brotli);
        assert_ne!(brotli, gzip);
        assert_ne!(gzip, none);
        assert_eq!(none.vary, "accept-encoding=identity");
    }

    #[test]
    fn takes_the_ttl_from_cache_control() {
        assert_eq!(
            ttl(&[("cache-control", "max-age=60")], "/a").unwrap().fresh_for,
            Duration::from_secs(60)
        );
        /* s-maxage is for shared caches, so it wins */
        assert_eq!(
            ttl(&[("cache-control", "max-age=60, s-maxage=300")], "/a")
                .unwrap()
                .fresh_for,
            Duration::from_secs(300)
        );
        assert_eq!(
            ttl(&[("cache-control", "max-age=60, stale-while-revalidate=30")], "/a")
                .unwrap()
                .stale_while_revalidate,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn nothing_is_cached_without_being_told_to() {
        assert!(ttl(&[], "/a").is_none());
        assert!(ttl(&[("content-type", "text/html")], "/a").is_none());
    }

    #[test]
    fn refuses_anything_user_specific() {
        assert!(ttl(&[("cache-control", "max-age=60"), ("set-cookie", "sid=1")], "/a").is_none());
        assert!(ttl(&[("cache-control", "private, max-age=60")], "/a").is_none());
        assert!(ttl(&[("cache-control", "no-store")], "/a").is_none());
        assert!(ttl(&[("cache-control", "no-cache")], "/a").is_none());
    }

    #[test]
    fn a_path_override_can_beat_the_origin() {
        let forced = ttl(&[("cache-control", "no-cache")], "/static/app.css").unwrap();
        assert_eq!(forced.fresh_for, Duration::from_secs(604800));

        /* but not the safety rules */
        assert!(ttl(
            &[("cache-control", "max-age=60"), ("set-cookie", "sid=1")],
            "/static/app.css"
        )
        .is_none());
        assert!(ttl(&[("cache-control", "private")], "/static/app.css").is_none());
    }

    #[test]
    fn a_non_forcing_override_only_fills_in_a_missing_ttl() {
        let mut p = policy();
        p.overrides = vec![PathOverride {
            path_prefix: "/img/".into(),
            ttl: Duration::from_secs(3600),
            override_origin_headers: false,
        }];

        let filled = response_ttl(StatusCode::OK, &resp_headers(&[]), "/img/a.png", &p).unwrap();
        assert_eq!(filled.fresh_for, Duration::from_secs(3600));

        let origin_wins = response_ttl(
            StatusCode::OK,
            &resp_headers(&[("cache-control", "max-age=30")]),
            "/img/a.png",
            &p,
        )
        .unwrap();
        assert_eq!(origin_wins.fresh_for, Duration::from_secs(30));
    }

    #[test]
    fn refuses_a_vary_we_cannot_key_on() {
        assert!(ttl(&[("cache-control", "max-age=60"), ("vary", "*")], "/a").is_none());
        assert!(
            ttl(&[("cache-control", "max-age=60"), ("vary", "cookie")], "/a").is_none(),
            "cookie is not in vary_on, so we cannot tell the variants apart"
        );
        assert!(ttl(
            &[("cache-control", "max-age=60"), ("vary", "Accept-Encoding")],
            "/a"
        )
        .is_some());
    }

    #[test]
    fn only_some_statuses_are_worth_keeping() {
        let cc = resp_headers(&[("cache-control", "max-age=60")]);
        for code in [200, 301, 404, 410] {
            let status = StatusCode::from_u16(code).unwrap();
            assert!(
                response_ttl(status, &cc, "/a", &policy()).is_some(),
                "{code} should be cacheable"
            );
        }
        for code in [500, 502, 302, 206] {
            let status = StatusCode::from_u16(code).unwrap();
            assert!(
                response_ttl(status, &cc, "/a", &policy()).is_none(),
                "{code} should not be cacheable"
            );
        }
    }

    #[test]
    fn reads_purge_tags() {
        assert_eq!(
            tags(&resp_headers(&[("cache-tag", "home, nav ,  ")])),
            ["home", "nav"]
        );
        assert!(tags(&resp_headers(&[])).is_empty());
    }

    #[test]
    fn parses_the_directives_it_cares_about() {
        let cc = parse_cache_control(&resp_headers(&[(
            "cache-control",
            "public, max-age=60, s-maxage=\"120\", stale-if-error=600, nonsense",
        )]));
        assert!(cc.public);
        assert_eq!(cc.max_age, Some(60));
        assert_eq!(cc.s_maxage, Some(120));
        assert_eq!(cc.stale_if_error, Some(600));
        assert!(!cc.no_store);
    }
}
