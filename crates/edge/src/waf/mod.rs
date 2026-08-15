//! The WAF: rules in, a verdict out.
//!
//! Rules are declared in YAML, parsed and compiled once at config load, and evaluated
//! as closures on the request path. Rules that only look at the head run before the
//! body is buffered, so a request blocked on its user agent never costs a body read.

pub mod ast;
pub mod compile;
pub mod parser;

pub use compile::{decode, Input, Net};

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use anyhow::{anyhow, bail, Context, Result};
use hyper::{HeaderMap, Request};
use serde::Deserialize;

use crate::body::Body;

/// A request with its path and query already percent-decoded, ready to be handed to
/// the rules. Shared by the WAF and the rate limiter so both see identical fields -
/// a rate limit scoped to `/api/` has to mean the same thing a WAF rule would.
pub struct Decoded<'a> {
    method: &'a str,
    host: &'a str,
    headers: &'a HeaderMap,
    ip: IpAddr,
    tls: bool,
    path: Cow<'a, str>,
    query: Cow<'a, str>,
    uri: Cow<'a, str>,
    /// Resolved once per request, before any stage runs - two stages asking the same
    /// question of the same database would be two lookups for one answer.
    geo: &'a crate::geoip::Located,
    /// Scored once per request, for the same reason.
    bot: &'a crate::bot::Verdict,
}

impl<'a> Decoded<'a> {
    pub fn new(
        req: &'a Request<Body>,
        host: &'a str,
        ip: IpAddr,
        tls: bool,
        geo: &'a crate::geoip::Located,
        bot: &'a crate::bot::Verdict,
    ) -> Self {
        Decoded {
            method: req.method().as_str(),
            host,
            headers: req.headers(),
            ip,
            tls,
            path: decode(req.uri().path(), false),
            query: decode(req.uri().query().unwrap_or(""), true),
            uri: decode(
                req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/"),
                true,
            ),
            geo,
            bot,
        }
    }

    pub fn input(&'a self, body: &'a str) -> Input<'a> {
        Input {
            method: self.method,
            uri: &self.uri,
            path: &self.path,
            query: &self.query,
            host: self.host,
            body,
            headers: self.headers,
            ip: self.ip,
            tls: self.tls,
            country: self.geo.country.as_deref(),
            continent: self.geo.continent.as_deref(),
            asn: self.geo.asn,
            as_org: self.geo.as_org.as_deref(),
            hosting: self.geo.hosting,
            vpn: self.geo.vpn,
            tor: self.geo.tor,
            bot_score: self.bot.score,
            bot_verified: self.bot.verified,
            bot_name: &self.bot.name,
        }
    }
}

/// Named lists shared by every zone, e.g. `$trusted`.
pub type Lists = HashMap<String, Vec<String>>;

/// Rulesets that ship with the binary. Embedded rather than read from disk so a
/// deployed edge is one file and can't half-start with a missing ruleset.
const BUILTIN: &[(&str, &str)] = &[
    ("core", include_str!("../../../../rulesets/core.yaml")),
    ("core-body", include_str!("../../../../rulesets/core-body.yaml")),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Answer the request ourselves with a 403.
    Block,
    /// Record the match and carry on. How you tune a rule before enforcing it.
    Log,
    /// Stop evaluating and let the request through.
    Skip,
    /// Ask the client to prove itself before letting it through.
    Challenge,
    /// Ask only when the request looks automated, so a person normally never sees it.
    /// Spelled out, because `managedchallenge` is not a word anybody would guess.
    #[serde(rename = "managed_challenge")]
    ManagedChallenge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// A rule that fired.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Match {
    pub rule: String,
    pub action: Action,
    pub severity: Severity,
}

/// What a request would do to a ruleset, rule by rule.
///
/// Unlike `evaluate` this doesn't stop at the first terminal match - the point is to
/// show someone tuning a rule everything their request touches, including the rules
/// that a block in front of them would normally hide.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Explained {
    pub matched: Vec<Match>,
    /// allow, block or skip.
    pub outcome: &'static str,
    /// The rule that decided it, if any did.
    pub decided_by: Option<String>,
    /// Rules that were not run because they need a body and none was given.
    pub skipped_needing_body: Vec<String>,
}

pub enum Outcome {
    Allow,
    Block(Match),
    Skip(Match),
}

/// Which rules to run. Head rules first; body rules only once we've buffered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Head,
    Body,
}

struct Rule {
    id: String,
    action: Action,
    severity: Severity,
    needs_body: bool,
    needs_geoip: bool,
    pred: compile::Pred,
}

#[derive(Default)]
pub struct Ruleset {
    rules: Vec<Rule>,
    needs_body: bool,
    needs_geoip: bool,
}

impl std::fmt::Debug for Ruleset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        /* compiled rules are closures; the ids are the useful part */
        f.debug_struct("Ruleset")
            .field("rules", &self.rules.iter().map(|r| &r.id).collect::<Vec<_>>())
            .field("needs_body", &self.needs_body)
            .finish()
    }
}

impl Ruleset {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True if any rule looks at the body. When false the body is never buffered.
    pub fn needs_body(&self) -> bool {
        self.needs_body
    }

    /// True if any rule asks where an address is. Config load refuses such a rule when no
    /// database is named, rather than letting it never match.
    pub fn needs_geoip(&self) -> bool {
        self.needs_geoip
    }

    pub fn rule_ids(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.id.as_str()).collect()
    }

    /// Run every rule and report all of them, for the rule tester.
    pub fn explain(&self, input: &Input, has_body: bool) -> Explained {
        let mut out = Explained {
            matched: Vec::new(),
            outcome: "allow",
            decided_by: None,
            skipped_needing_body: Vec::new(),
        };
        let mut decided = false;

        for rule in &self.rules {
            if rule.needs_body && !has_body {
                out.skipped_needing_body.push(rule.id.clone());
                continue;
            }
            if !(rule.pred)(input) {
                continue;
            }

            out.matched.push(Match {
                rule: rule.id.clone(),
                action: rule.action,
                severity: rule.severity,
            });

            /* record what would have happened, but keep going so the tester can
               show everything the request touches */
            if !decided {
                match rule.action {
                    Action::Block => {
                        out.outcome = "block";
                        out.decided_by = Some(rule.id.clone());
                        decided = true;
                    }
                    Action::Skip => {
                        out.outcome = "skip";
                        out.decided_by = Some(rule.id.clone());
                        decided = true;
                    }
                    _ => {}
                }
            }
        }
        out
    }

    /// Rules run in declaration order. The first `block` or `skip` ends it; `log`
    /// matches pile up in `log` and evaluation continues.
    pub fn evaluate(&self, input: &Input, phase: Phase, log: &mut Vec<Match>) -> Outcome {
        for rule in &self.rules {
            let belongs = match phase {
                Phase::Head => !rule.needs_body,
                Phase::Body => rule.needs_body,
            };
            if !belongs || !(rule.pred)(input) {
                continue;
            }
            let hit = Match {
                rule: rule.id.clone(),
                action: rule.action,
                severity: rule.severity,
            };
            match rule.action {
                /* a challenge short-circuits exactly like a block; what differs is the
                   response, and the stage decides that from `hit.action` */
                Action::Block | Action::Challenge | Action::ManagedChallenge => {
                    return Outcome::Block(hit)
                }
                Action::Skip => return Outcome::Skip(hit),
                Action::Log => log.push(hit),

            }
        }
        Outcome::Allow
    }
}

/// A rule as written in YAML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    pub id: String,
    pub expression: String,
    pub action: Action,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub description: Option<String>,
    /// Fixtures. Not used at runtime - `cargo test` runs them.
    #[serde(default)]
    pub tests: Vec<RuleTest>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleTest {
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub expect: Expect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expect {
    Match,
    Nomatch,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuleset {
    #[serde(default)]
    rules: Vec<RawRule>,
}

/// Pull the named built-in rulesets, tack the zone's own rules on the end, compile.
pub fn build(rulesets: &[String], inline: Vec<RawRule>, lists: &Lists) -> Result<Ruleset> {
    let mut raw = Vec::new();
    for name in rulesets {
        raw.extend(builtin_rules(name)?);
    }
    raw.extend(inline);
    compile_all(raw, lists)
}

pub fn builtin_names() -> Vec<&'static str> {
    BUILTIN.iter().map(|(n, _)| *n).collect()
}

pub fn builtin_rules(name: &str) -> Result<Vec<RawRule>> {
    let text = BUILTIN
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
        .ok_or_else(|| {
            anyhow!(
                "unknown ruleset `{name}` (built in: {})",
                builtin_names().join(", ")
            )
        })?;
    let parsed: RawRuleset = serde_yaml::from_str(text)
        .with_context(|| format!("built-in ruleset `{name}` is malformed"))?;
    Ok(parsed.rules)
}

fn compile_all(raw: Vec<RawRule>, lists: &Lists) -> Result<Ruleset> {
    let mut ids = HashSet::new();
    let mut rules = Vec::with_capacity(raw.len());

    for r in raw {
        if !ids.insert(r.id.clone()) {
            bail!("duplicate rule id `{}`", r.id);
        }
        let rule = compile_one(&r, lists).with_context(|| format!("rule `{}`", r.id))?;
        rules.push(rule);
    }

    let needs_body = rules.iter().any(|r| r.needs_body);
    let needs_geoip = rules.iter().any(|r| r.needs_geoip);
    Ok(Ruleset {
        rules,
        needs_body,
        needs_geoip,
    })
}

fn compile_one(raw: &RawRule, lists: &Lists) -> Result<Rule> {
    let expr = parser::parse(&raw.expression)?;
    Ok(Rule {
        id: raw.id.clone(),
        action: raw.action,
        severity: raw.severity,
        needs_body: expr.needs_body(),
        needs_geoip: expr.needs_geoip(),
        pred: compile::compile(&expr, lists)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use hyper::HeaderMap;

    fn ruleset(yaml: &str) -> Ruleset {
        let raw: RawRuleset = serde_yaml::from_str(yaml).expect("test ruleset should parse");
        compile_all(raw.rules, &Lists::new()).expect("test ruleset should compile")
    }

    /// Runs one fixture the same way the stage would: decoded path/query, raw body.
    fn fixture_fires(rule: &Rule, t: &RuleTest) -> bool {
        let method = t.method.clone().unwrap_or_else(|| "GET".into());
        let raw_path = t.path.clone().unwrap_or_else(|| "/".into());
        let raw_query = t.query.clone().unwrap_or_default();
        let host = t.host.clone().unwrap_or_else(|| "demo.local".into());
        let body = t.body.clone().unwrap_or_default();
        let ip = t
            .ip
            .clone()
            .unwrap_or_else(|| "203.0.113.9".into())
            .parse()
            .expect("fixture ip should parse");

        let mut headers = HeaderMap::new();
        for (k, v) in &t.headers {
            headers.append(
                HeaderName::from_bytes(k.as_bytes()).expect("fixture header name"),
                HeaderValue::from_str(v).expect("fixture header value"),
            );
        }

        let path = decode(&raw_path, false);
        let query = decode(&raw_query, true);
        let raw_uri = if raw_query.is_empty() {
            raw_path.clone()
        } else {
            format!("{raw_path}?{raw_query}")
        };
        let uri = decode(&raw_uri, true);

        (rule.pred)(&Input {
            method: &method,
            uri: &uri,
            path: &path,
            query: &query,
            host: &host,
            body: &body,
            headers: &headers,
            ip,
            tls: false,
            country: None,
            continent: None,
            asn: None,
            as_org: None,
            hosting: false,
            vpn: false,
            tor: false,
            bot_score: 99,
            bot_verified: false,
            bot_name: "",
        })
    }

    /// Every built-in rule has to prove it catches what it claims and leaves normal
    /// traffic alone. A rule with no fixtures is a rule nobody has checked.
    #[test]
    fn builtin_rulesets_pass_their_own_fixtures() {
        for name in builtin_names() {
            let raws = builtin_rules(name).expect("built-in ruleset should load");
            assert!(!raws.is_empty(), "ruleset `{name}` is empty");

            for raw in &raws {
                let rule = compile_one(raw, &Lists::new())
                    .unwrap_or_else(|e| panic!("{name}/{}: {e:#}", raw.id));

                let matches = raw.tests.iter().filter(|t| t.expect == Expect::Match).count();
                let nomatches = raw.tests.len() - matches;
                assert!(
                    matches > 0 && nomatches > 0,
                    "{name}/{}: needs at least one match and one nomatch fixture \
                     (has {matches} and {nomatches})",
                    raw.id
                );

                for (n, t) in raw.tests.iter().enumerate() {
                    let fired = fixture_fires(&rule, t);
                    let want = t.expect == Expect::Match;
                    assert_eq!(
                        fired, want,
                        "{name}/{} fixture #{n}: expected {:?}, rule {} - {t:?}",
                        raw.id,
                        t.expect,
                        if fired { "fired" } else { "did not fire" }
                    );
                }
            }
        }
    }

    #[test]
    fn core_rules_ignore_ordinary_traffic() {
        let rules = build(&["core".into()], vec![], &Lists::new()).unwrap();
        let benign = [
            ("/", ""),
            ("/index.html", ""),
            ("/search", "q=how+to+make+bread"),
            ("/articles/2026/rust-and-async", "page=2&sort=new"),
            ("/api/v1/users", "id=42&fields=name,email"),
            ("/static/app.css", "v=8f2c1a"),
            ("/checkout", "item=union-jack-flag&qty=1"),
            ("/blog/selection-of-reunion-photos", ""),
        ];
        let headers = {
            let mut h = HeaderMap::new();
            h.insert("user-agent", HeaderValue::from_static("Mozilla/5.0"));
            h
        };

        for (path, query) in benign {
            let decoded_q = decode(query, true);
            let uri = format!("{path}?{decoded_q}");
            let input = Input {
                method: "GET",
                uri: &uri,
                path,
                query: &decoded_q,
                host: "demo.local",
                body: "",
                headers: &headers,
                ip: "203.0.113.9".parse().unwrap(),
                tls: false,
                country: None,
                continent: None,
                asn: None,
                as_org: None,
                hosting: false,
                vpn: false,
                tor: false,
                bot_score: 99,
                bot_verified: false,
                bot_name: "",
            };
            let mut log = Vec::new();
            assert!(
                matches!(rules.evaluate(&input, Phase::Head, &mut log), Outcome::Allow),
                "core ruleset false-positived on {path}?{query}"
            );
            assert!(log.is_empty(), "core ruleset logged on {path}?{query}: {log:?}");
        }
    }

    const ORDER: &str = r#"
rules:
  - id: allow-health
    expression: 'http.request.uri.path eq "/health"'
    action: skip
  - id: block-everything
    expression: 'http.request.uri.path matches "."'
    action: block
  - id: never-reached
    expression: 'http.request.uri.path matches "."'
    action: log
"#;

    fn probe(rules: &Ruleset, path: &str) -> (String, Vec<Match>) {
        let headers = HeaderMap::new();
        let input = Input {
            method: "GET",
            uri: path,
            path,
            query: "",
            host: "demo.local",
            body: "",
            headers: &headers,
            ip: "203.0.113.9".parse().unwrap(),
            tls: false,
            country: None,
            continent: None,
            asn: None,
            as_org: None,
            hosting: false,
            vpn: false,
            tor: false,
            bot_score: 99,
            bot_verified: false,
            bot_name: "",
        };
        let mut log = Vec::new();
        let out = match rules.evaluate(&input, Phase::Head, &mut log) {
            Outcome::Allow => "allow".to_string(),
            Outcome::Block(m) => format!("block:{}", m.rule),
            Outcome::Skip(m) => format!("skip:{}", m.rule),
        };
        (out, log)
    }

    #[test]
    fn first_terminal_match_wins() {
        let rules = ruleset(ORDER);
        assert_eq!(probe(&rules, "/health").0, "skip:allow-health");
        assert_eq!(probe(&rules, "/other").0, "block:block-everything");
        /* the log rule sits behind a block, so it never gets a look in */
        assert!(probe(&rules, "/other").1.is_empty());
    }

    #[test]
    fn log_rules_accumulate_without_stopping() {
        let rules = ruleset(
            r#"
rules:
  - id: note-one
    expression: 'http.request.uri.path matches "."'
    action: log
  - id: note-two
    expression: 'http.request.uri.path contains "/x"'
    action: log
"#,
        );
        let (outcome, log) = probe(&rules, "/x");
        assert_eq!(outcome, "allow");
        assert_eq!(
            log.iter().map(|m| m.rule.as_str()).collect::<Vec<_>>(),
            ["note-one", "note-two"]
        );
    }

    #[test]
    fn body_rules_are_held_back_for_the_second_pass() {
        let rules = ruleset(
            r#"
rules:
  - id: body-rule
    expression: 'http.request.body contains "boom"'
    action: block
"#,
        );
        assert!(rules.needs_body());

        let headers = HeaderMap::new();
        let mut input = Input {
            method: "POST",
            uri: "/",
            path: "/",
            query: "",
            host: "demo.local",
            body: "boom",
            headers: &headers,
            ip: "203.0.113.9".parse().unwrap(),
            tls: false,
            country: None,
            continent: None,
            asn: None,
            as_org: None,
            hosting: false,
            vpn: false,
            tor: false,
            bot_score: 99,
            bot_verified: false,
            bot_name: "",
        };

        let mut log = Vec::new();
        /* the head pass must not touch it even though the body is sitting right there */
        assert!(matches!(
            rules.evaluate(&input, Phase::Head, &mut log),
            Outcome::Allow
        ));
        assert!(matches!(
            rules.evaluate(&input, Phase::Body, &mut log),
            Outcome::Block(_)
        ));

        input.body = "fine";
        assert!(matches!(
            rules.evaluate(&input, Phase::Body, &mut log),
            Outcome::Allow
        ));
    }

    #[test]
    fn head_only_rulesets_never_ask_for_the_body() {
        let rules = build(&["core".into()], vec![], &Lists::new()).unwrap();
        assert!(!rules.needs_body(), "the core ruleset should not force body buffering");
        assert!(build(&["core-body".into()], vec![], &Lists::new())
            .unwrap()
            .needs_body());
    }

    #[test]
    fn rejects_duplicate_ids() {
        let dup = r#"
rules:
  - id: same
    expression: 'http.host eq "a"'
    action: block
  - id: same
    expression: 'http.host eq "b"'
    action: block
"#;
        let raw: RawRuleset = serde_yaml::from_str(dup).unwrap();
        let err = compile_all(raw.rules, &Lists::new()).unwrap_err().to_string();
        assert!(err.contains("duplicate rule id"), "unexpected error: {err}");
    }

    #[test]
    fn the_challenge_actions_compile_now_that_there_is_an_interstitial() {
        /* both of these were refused at config load until there was something to serve */
        let set = ruleset(
            r#"
rules:
  - id: prove-it
    action: challenge
    expression: >-
      http.request.uri.path contains "/admin"
  - id: maybe-prove-it
    action: managed_challenge
    expression: >-
      http.request.uri.path contains "/api"
"#,
        );
        assert_eq!(set.len(), 2, "both challenge actions should compile");
    }

    #[test]
    fn unknown_ruleset_names_list_what_exists() {
        let err = build(&["nope".into()], vec![], &Lists::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("core"), "unhelpful error: {err}");
    }
}
