//! Lowers a parsed expression into a tree of closures.
//!
//! Everything expensive - regex compilation, CIDR parsing, list building - happens
//! here, once, at config load. What survives into the request path is a single
//! `Fn(&Input) -> bool`.

use std::borrow::Cow;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Context, Result};
use hyper::HeaderMap;
use regex::Regex;

use super::ast::{Expr, Field, Op, Operand};
use super::Lists;

/// The request as the rules see it. Path, query and uri arrive percent-decoded -
/// `union%20select` has to look like `union select` or the rules are decoration.
pub struct Input<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub host: &'a str,
    pub body: &'a str,
    pub headers: &'a HeaderMap,
    pub ip: IpAddr,
    /// Whether the client reached the edge over https.
    pub tls: bool,
    /// Where the client is, if a country database is loaded. None means unknown - and a
    /// rule comparing it therefore does not match, rather than matching everything.
    pub country: Option<&'a str>,
    pub continent: Option<&'a str>,
    pub asn: Option<u32>,
    pub as_org: Option<&'a str>,
    pub hosting: bool,
    pub vpn: bool,
    pub tor: bool,
}

pub type Pred = Box<dyn Fn(&Input) -> bool + Send + Sync>;

type StrTest = Box<dyn Fn(&str) -> bool + Send + Sync>;

pub fn compile(expr: &Expr, lists: &Lists) -> Result<Pred> {
    Ok(match expr {
        Expr::And(a, b) => {
            let (a, b) = (compile(a, lists)?, compile(b, lists)?);
            Box::new(move |i| a(i) && b(i))
        }
        Expr::Or(a, b) => {
            let (a, b) = (compile(a, lists)?, compile(b, lists)?);
            Box::new(move |i| a(i) || b(i))
        }
        Expr::Not(a) => {
            let a = compile(a, lists)?;
            Box::new(move |i| !a(i))
        }
        Expr::Cmp { field, op, operand } => cmp(field, *op, operand, lists)?,
    })
}

fn cmp(field: &Field, op: Op, operand: &Operand, lists: &Lists) -> Result<Pred> {
    if matches!(field, Field::IpSrc) {
        return ip_cmp(op, operand, lists);
    }
    /* the bare booleans, which carry no operator - `ssl`, `not ip.src.is_tor` */
    match field {
        Field::Ssl => return Ok(Box::new(|i: &Input| i.tls)),
        Field::IpHosting => return Ok(Box::new(|i: &Input| i.hosting)),
        Field::IpVpn => return Ok(Box::new(|i: &Input| i.vpn)),
        Field::IpTor => return Ok(Box::new(|i: &Input| i.tor)),
        /* deliberately hiding, as opposed to merely being in a datacenter */
        Field::IpAnonymous => return Ok(Box::new(|i: &Input| i.vpn || i.tor)),
        _ => {}
    }
    /* `ne` is just a negated `eq`, which also gives it sane multi-value semantics:
       "no value of this header equals x" rather than "some value doesn't".

       Except for a field that can be *absent*. Negating `eq` there turns "not GB" into
       "not known to be GB", so a node whose geo database is missing would match every
       request - a `ne` rule that blocks would block the world. `ne` therefore means
       "known, and different", and an unknown address matches neither direction. */
    if op == Op::Ne {
        let eq = cmp(field, Op::Eq, operand, lists)?;
        let field = field.clone();
        return Ok(Box::new(move |i| known(&field, i) && !eq(i)));
    }

    let test: StrTest = match op {
        Op::Eq => {
            let want = single(operand, lists)?;
            Box::new(move |v| v == want)
        }
        Op::Contains => {
            let want = single(operand, lists)?;
            Box::new(move |v| v.contains(&want))
        }
        Op::Matches => {
            let pat = single(operand, lists)?;
            let re = Regex::new(&pat).with_context(|| format!("bad regex `{pat}`"))?;
            Box::new(move |v| re.is_match(v))
        }
        Op::In => {
            let set: HashSet<String> = multi(operand, lists)?.into_iter().collect();
            Box::new(move |v| set.contains(v))
        }
        Op::Ne => unreachable!("handled above"),
    };
    Ok(field_pred(field.clone(), test))
}

/// Whether this request has a value for the field at all.
///
/// Only the geo fields can be missing; everything else is always present, even if empty,
/// so an absent header is an empty string rather than an unknown one.
fn known(field: &Field, i: &Input) -> bool {
    match field {
        Field::GeoCountry => i.country.is_some(),
        Field::GeoContinent => i.continent.is_some(),
        Field::GeoAsn => i.asn.is_some(),
        Field::GeoAsOrg => i.as_org.is_some(),
        _ => true,
    }
}

fn field_pred(field: Field, test: StrTest) -> Pred {
    Box::new(move |i: &Input| match &field {
        Field::Method => test(i.method),
        Field::Uri => test(i.uri),
        Field::Path => test(i.path),
        Field::Query => test(i.query),
        Field::Body => test(i.body),
        Field::Host => test(i.host),
        /* a header can repeat; the rule fires if any value matches */
        Field::Header(name) => i
            .headers
            .get_all(name.as_str())
            .iter()
            .any(|v| v.to_str().map(&test).unwrap_or(false)),
        /* an address we cannot place matches nothing. the alternative - treating unknown
           as a value - would make `ip.geoip.country ne "GB"` block every request the
           moment the database went missing */
        Field::GeoCountry => i.country.map(&test).unwrap_or(false),
        /* compared as decimal text, so eq / in / matches all work unchanged. a number
           has exactly one spelling here, so there is nothing to normalise */
        Field::GeoAsn => i.asn.map(|n| test(&n.to_string())).unwrap_or(false),
        Field::GeoContinent => i.continent.map(&test).unwrap_or(false),
        Field::GeoAsOrg => i.as_org.map(&test).unwrap_or(false),
        Field::IpSrc
        | Field::Ssl
        | Field::IpHosting
        | Field::IpVpn
        | Field::IpTor
        | Field::IpAnonymous => unreachable!("compiled separately"),
    })
}

fn single(operand: &Operand, _lists: &Lists) -> Result<String> {
    match operand {
        Operand::Str(s) => Ok(s.clone()),
        Operand::List(_) => bail!("this operator takes one value, not a list - use `in`"),
        Operand::Named(n) => bail!("`${n}` is a list - use `in`"),
    }
}

fn multi(operand: &Operand, lists: &Lists) -> Result<Vec<String>> {
    match operand {
        Operand::Str(s) => Ok(vec![s.clone()]),
        Operand::List(v) => Ok(v.clone()),
        Operand::Named(n) => lists
            .get(n)
            .cloned()
            .ok_or_else(|| anyhow!("unknown list `${n}` - define it under `lists:` in the config")),
    }
}

fn ip_cmp(op: Op, operand: &Operand, lists: &Lists) -> Result<Pred> {
    match op {
        Op::Eq | Op::In => {
            let nets: Vec<Net> = multi(operand, lists)?
                .iter()
                .map(|s| Net::parse(s))
                .collect::<Result<_>>()?;
            Ok(Box::new(move |i: &Input| {
                nets.iter().any(|n| n.contains(i.ip))
            }))
        }
        Op::Ne => {
            let inner = ip_cmp(Op::In, operand, lists)?;
            Ok(Box::new(move |i| !inner(i)))
        }
        Op::Contains | Op::Matches => {
            bail!("ip.src only supports eq, ne and in")
        }
    }
}

/// An address or a CIDR range. Public because the client-ip resolver needs the same
/// question answered - "is this address in one of these ranges?" - and two
/// implementations of that would eventually disagree.
#[derive(Clone, Copy, Debug)]
pub struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    pub fn parse(s: &str) -> Result<Net> {
        let (host, prefix) = match s.split_once('/') {
            None => (s, None),
            Some((h, p)) => (
                h,
                Some(
                    p.parse::<u8>()
                        .with_context(|| format!("`{s}`: prefix must be a number"))?,
                ),
            ),
        };
        let addr: IpAddr = host
            .parse()
            .with_context(|| format!("`{s}` is not an ip address or cidr range"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            bail!("`{s}`: prefix must be 0..={max}");
        }
        Ok(Net { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(a)) => v4_in(a, net, self.prefix),
            (IpAddr::V6(net), IpAddr::V6(a)) => v6_in(a, net, self.prefix),
            /* no v4-in-v6 games: a rule written for one family shouldn't
               silently start matching the other */
            _ => false,
        }
    }
}

#[cfg(test)]
mod geo_tests {
    use super::*;
    use crate::waf::Lists;

    /// Everything a geo lookup could have found, so a test states only what it cares about.
    #[derive(Default, Clone, Copy)]
    struct G<'a> {
        country: Option<&'a str>,
        continent: Option<&'a str>,
        asn: Option<u32>,
        as_org: Option<&'a str>,
        hosting: bool,
        vpn: bool,
        tor: bool,
    }

    fn fires_with(expr: &str, g: G) -> bool {
        let ast = crate::waf::parser::parse(expr).expect("expression should parse");
        let pred = compile(&ast, &Lists::new()).expect("expression should compile");
        let headers = HeaderMap::new();
        pred(&Input {
            method: "GET",
            uri: "/",
            path: "/",
            query: "",
            host: "demo.local",
            body: "",
            headers: &headers,
            ip: "203.0.113.9".parse().unwrap(),
            tls: false,
            country: g.country,
            continent: g.continent,
            asn: g.asn,
            as_org: g.as_org,
            hosting: g.hosting,
            vpn: g.vpn,
            tor: g.tor,
        })
    }

    fn fires(expr: &str, country: Option<&str>, asn: Option<u32>) -> bool {
        fires_with(
            expr,
            G {
                country,
                asn,
                ..G::default()
            },
        )
    }

    #[test]
    fn a_continent_rule_matches_the_continent() {
        let g = G {
            continent: Some("EU"),
            ..G::default()
        };
        assert!(fires_with(r#"ip.geoip.continent eq "EU""#, g));
        assert!(fires_with(r#"ip.geoip.continent in ["EU", "NA"]"#, g));
        assert!(!fires_with(r#"ip.geoip.continent eq "AS""#, g));
        /* and unknown still matches nothing, in either direction */
        assert!(!fires_with(r#"ip.geoip.continent eq "EU""#, G::default()));
        assert!(!fires_with(r#"ip.geoip.continent ne "EU""#, G::default()));
    }

    #[test]
    fn an_as_org_rule_can_match_a_provider_by_name() {
        /* the point of having the name as well as the number: one rule instead of the
           dozens of ASNs a big cloud announces */
        let g = G {
            as_org: Some("AMAZON-02"),
            ..G::default()
        };
        assert!(fires_with(r#"ip.geoip.asorg contains "AMAZON""#, g));
        assert!(fires_with(r#"ip.geoip.asorg matches "(?i)amazon""#, g));
        assert!(!fires_with(r#"ip.geoip.asorg contains "GOOGLE""#, g));
    }

    #[test]
    fn the_bare_booleans_stand_alone_like_ssl() {
        let datacenter = G {
            hosting: true,
            ..G::default()
        };
        assert!(fires_with("ip.src.is_hosting", datacenter));
        assert!(!fires_with("ip.src.is_vpn", datacenter));
        assert!(!fires_with("ip.src.is_tor", datacenter));
        /* a cloud tenant is not the same as somebody hiding */
        assert!(!fires_with("ip.src.is_anonymous", datacenter));
        assert!(fires_with("not ip.src.is_tor", datacenter));
    }

    #[test]
    fn anonymous_means_vpn_or_tor() {
        let vpn = G {
            vpn: true,
            ..G::default()
        };
        let tor = G {
            tor: true,
            ..G::default()
        };
        assert!(fires_with("ip.src.is_anonymous", vpn));
        assert!(fires_with("ip.src.is_anonymous", tor));
        assert!(!fires_with("ip.src.is_anonymous", G::default()));
    }

    #[test]
    fn the_signals_combine_with_the_rest_of_the_language() {
        /* the rule somebody actually writes: a datacenter pretending to browse from a
           country we do not serve */
        let expr = r#"ip.src.is_hosting and ip.geoip.country eq "RU""#;
        assert!(fires_with(
            expr,
            G {
                hosting: true,
                country: Some("RU"),
                ..G::default()
            }
        ));
        assert!(!fires_with(
            expr,
            G {
                hosting: false,
                country: Some("RU"),
                ..G::default()
            }
        ));
    }

    #[test]
    fn a_country_rule_matches_the_country() {
        assert!(fires(r#"ip.geoip.country eq "GB""#, Some("GB"), None));
        assert!(!fires(r#"ip.geoip.country eq "GB""#, Some("DE"), None));
    }

    #[test]
    fn a_country_rule_can_take_a_list() {
        let expr = r#"ip.geoip.country in ["CN", "RU", "KP"]"#;
        assert!(fires(expr, Some("RU"), None));
        assert!(!fires(expr, Some("GB"), None));
    }

    #[test]
    fn an_unknown_country_matches_nothing() {
        /* the important half: with no database loaded every geo rule must be inert, not
           universally true. `ne` is the dangerous direction - it would block the world */
        assert!(!fires(r#"ip.geoip.country eq "GB""#, None, None));
        assert!(!fires(r#"ip.geoip.country ne "GB""#, None, None));
        assert!(!fires(r#"ip.geoip.country in ["CN", "RU"]"#, None, None));
    }

    #[test]
    fn ne_on_a_known_country_still_works() {
        assert!(fires(r#"ip.geoip.country ne "GB""#, Some("DE"), None));
        assert!(!fires(r#"ip.geoip.country ne "GB""#, Some("GB"), None));
    }

    #[test]
    fn an_asn_is_compared_as_its_number_written_out() {
        assert!(fires(r#"ip.geoip.asnum eq "64512""#, None, Some(64512)));
        assert!(!fires(r#"ip.geoip.asnum eq "64512""#, None, Some(64513)));
        /* no leading-zero or whitespace spellings to worry about, because the text comes
           from formatting the number rather than from the request */
        assert!(!fires(r#"ip.geoip.asnum eq "064512""#, None, Some(64512)));
    }

    #[test]
    fn an_asn_rule_can_take_a_list() {
        let expr = r#"ip.geoip.asnum in ["64512", "64513"]"#;
        assert!(fires(expr, None, Some(64513)));
        assert!(!fires(expr, None, Some(64514)));
    }

    #[test]
    fn an_unknown_asn_matches_nothing() {
        assert!(!fires(r#"ip.geoip.asnum eq "64512""#, None, None));
        assert!(!fires(r#"ip.geoip.asnum ne "64512""#, None, None));
    }

    #[test]
    fn country_and_asn_combine_with_everything_else() {
        /* the shape a real rule takes: somewhere hostile, on a hosting provider's asn */
        let expr = r#"ip.geoip.country eq "RU" and ip.geoip.asnum eq "64512""#;
        assert!(fires(expr, Some("RU"), Some(64512)));
        assert!(!fires(expr, Some("RU"), Some(64513)));
        assert!(!fires(expr, Some("GB"), Some(64512)));
    }
}

fn v4_in(a: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - prefix);
    (u32::from(a) & mask) == (u32::from(net) & mask)
}

fn v6_in(a: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - prefix);
    (u128::from(a) & mask) == (u128::from(net) & mask)
}

/// Percent-decoding, and `+` as space for query strings. Borrows when there is
/// nothing to do, which is the common case.
pub fn decode(s: &str, plus_is_space: bool) -> Cow<'_, str> {
    let has_plus = plus_is_space && s.contains('+');
    if !s.contains('%') && !has_plus {
        return Cow::Borrowed(s);
    }

    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                /* a stray % is just a %, not an error */
                _ => {
                    out.push(b[i]);
                    i += 1;
                }
            },
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::parser::parse;
    use hyper::header::{HeaderName, HeaderValue};

    fn lists() -> Lists {
        Lists::from([
            ("trusted".to_string(), vec!["127.0.0.1".to_string(), "10.0.0.0/8".to_string()]),
            ("bots".to_string(), vec!["curl".to_string(), "wget".to_string()]),
        ])
    }

    struct Req {
        method: String,
        path: String,
        query: String,
        host: String,
        body: String,
        headers: HeaderMap,
        ip: IpAddr,
    }

    impl Default for Req {
        fn default() -> Self {
            Req {
                method: "GET".into(),
                path: "/".into(),
                query: String::new(),
                host: "demo.local".into(),
                body: String::new(),
                headers: HeaderMap::new(),
                ip: "127.0.0.1".parse().unwrap(),
            }
        }
    }

    impl Req {
        fn header(mut self, k: &str, v: &str) -> Self {
            self.headers.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
            self
        }
        fn input(&self) -> Input<'_> {
            Input {
                method: &self.method,
                uri: &self.path,
                path: &self.path,
                query: &self.query,
                host: &self.host,
                body: &self.body,
                headers: &self.headers,
                ip: self.ip,
                tls: false,
                country: None,
                continent: None,
                asn: None,
                as_org: None,
                hosting: false,
                vpn: false,
                tor: false,
            }
        }
    }

    fn fires(expr: &str, req: &Req) -> bool {
        let ast = parse(expr).expect("expression should parse");
        let pred = compile(&ast, &lists()).expect("expression should compile");
        pred(&req.input())
    }

    #[test]
    fn compares_strings() {
        let r = Req {
            path: "/admin/login".into(),
            ..Default::default()
        };
        assert!(fires(r#"http.request.uri.path contains "/admin""#, &r));
        assert!(fires(r#"http.request.uri.path matches "^/admin/""#, &r));
        assert!(fires(r#"http.request.uri.path ne "/""#, &r));
        assert!(!fires(r#"http.request.uri.path eq "/admin""#, &r));
    }

    #[test]
    fn combines_with_and_or_not() {
        let r = Req {
            method: "POST".into(),
            path: "/admin".into(),
            ..Default::default()
        };
        assert!(fires(
            r#"http.request.method eq "POST" and http.request.uri.path eq "/admin""#,
            &r
        ));
        assert!(!fires(
            r#"http.request.method eq "GET" and http.request.uri.path eq "/admin""#,
            &r
        ));
        assert!(fires(
            r#"http.request.method eq "GET" or http.request.uri.path eq "/admin""#,
            &r
        ));
        assert!(fires(r#"not http.request.method eq "GET""#, &r));
    }

    #[test]
    fn any_value_of_a_repeated_header_can_match() {
        let r = Req::default().header("x-tag", "one").header("x-tag", "two");
        assert!(fires(r#"http.request.headers["x-tag"] eq "two""#, &r));
        assert!(fires(r#"http.request.headers["X-Tag"] eq "one""#, &r));
        assert!(!fires(r#"http.request.headers["x-tag"] eq "three""#, &r));
        /* ne means no value matches, not "some value differs" */
        assert!(!fires(r#"http.request.headers["x-tag"] ne "two""#, &r));
    }

    #[test]
    fn a_missing_header_never_matches() {
        let r = Req::default();
        assert!(!fires(r#"http.request.headers["user-agent"] eq "curl""#, &r));
        assert!(!fires(r#"http.request.headers["user-agent"] matches ".""#, &r));
        /* which is how a rule spots requests with no user agent at all */
        assert!(fires(r#"not http.request.headers["user-agent"] matches ".""#, &r));
    }

    #[test]
    fn matches_ips_and_cidr_ranges() {
        let inside = Req {
            ip: "10.4.5.6".parse().unwrap(),
            ..Default::default()
        };
        let outside = Req {
            ip: "203.0.113.9".parse().unwrap(),
            ..Default::default()
        };
        assert!(fires("ip.src in $trusted", &inside));
        assert!(!fires("ip.src in $trusted", &outside));
        assert!(fires(r#"ip.src eq "203.0.113.9""#, &outside));
        assert!(fires(r#"ip.src in ["203.0.113.0/24"]"#, &outside));
        assert!(!fires(r#"ip.src in ["203.0.114.0/24"]"#, &outside));
        assert!(fires(r#"ip.src in ["0.0.0.0/0"]"#, &outside));
    }

    #[test]
    fn v4_and_v6_do_not_bleed_into_each_other() {
        let v6 = Req {
            ip: "2001:db8::1".parse().unwrap(),
            ..Default::default()
        };
        assert!(!fires(r#"ip.src in ["0.0.0.0/0"]"#, &v6));
        assert!(fires(r#"ip.src in ["2001:db8::/32"]"#, &v6));
    }

    #[test]
    fn named_string_lists_work_too() {
        let curl = Req::default().header("user-agent", "curl");
        assert!(fires(r#"http.request.headers["user-agent"] in $bots"#, &curl));
    }

    #[test]
    fn rejects_bad_rules_at_compile_time() {
        let bad = [
            (r#"http.request.uri.path matches "(unclosed""#, "bad regex"),
            (r#"http.request.uri.path eq $bots"#, "list where a string goes"),
            (r#"ip.src contains "10.""#, "contains on an ip"),
            (r#"ip.src in ["not-an-ip"]"#, "junk in an ip list"),
            (r#"ip.src in ["10.0.0.0/40"]"#, "prefix too long"),
            (r#"http.host in $nope"#, "unknown list"),
        ];
        for (src, why) in bad {
            let ast = parse(src).expect("should parse fine");
            assert!(compile(&ast, &lists()).is_err(), "should have rejected {why}: {src}");
        }
    }

    #[test]
    fn decodes_percent_escapes() {
        assert_eq!(decode("plain", false), "plain");
        assert_eq!(decode("union%20select", false), "union select");
        assert_eq!(decode("%2e%2e%2fetc", false), "../etc");
        assert_eq!(decode("a+b", true), "a b");
        assert_eq!(decode("a+b", false), "a+b");
        /* malformed escapes stay as written rather than eating the next characters */
        assert_eq!(decode("100%", false), "100%");
        assert_eq!(decode("%zz", false), "%zz");
        assert_eq!(decode("%2", false), "%2");
    }

    #[test]
    fn decode_borrows_when_there_is_nothing_to_do() {
        assert!(matches!(decode("/nothing/here", true), Cow::Borrowed(_)));
        assert!(matches!(decode("/a%20b", true), Cow::Owned(_)));
    }
}
