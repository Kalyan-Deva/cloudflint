//! Counters, gauges and histograms, in the format Prometheus scrapes.
//!
//! Hand-rolled for the same reason the admin API is: the whole of the text exposition
//! format that matters here is three lines of header and one line per series, and a
//! metrics crate would bring a registry, a macro layer and a global singleton into the
//! data plane to produce it. Everything here is explicit - a family is a field on
//! `Metrics`, and `Metrics` is passed to the code that records into it, the same way
//! the cache store is.
//!
//! Two rules the hot path depends on:
//!
//! - Recording is one atomic add under a read lock. A new label combination takes the
//!   write lock once, the first time it is seen, and never again.
//! - Series are capped. Label values come from config (zone and rule names) or from a
//!   fixed set (status, decision, severity), so cardinality is bounded by design - the
//!   cap is there so a mistake costs a missing series rather than the node's memory.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

/// What a scrape response says it is. Prometheus is happy with the version it knows.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Most distinct label combinations one family will track. Past this, records are
/// counted as dropped instead - see the module note.
const MAX_SERIES: usize = 2048;

/// Bucket edges in seconds. Tight at the bottom because a proxy that is working lives
/// there: a WAF block lands in hundreds of microseconds and a cache hit not much more,
/// so buckets that start at 5ms would put "fast" and "very fast" in the same box.
const BUCKETS: &[f64] = &[
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Zone label for a request that never matched one.
const UNROUTED: &str = "unrouted";

/// A float gauge, held as bits so it needs no lock.
#[derive(Debug, Default)]
pub struct Gauge(AtomicU64);

impl Gauge {
    pub fn set(&self, value: f64) {
        self.0.store(value.to_bits(), Ordering::Relaxed);
    }

    pub fn add(&self, delta: f64) {
        let mut current = self.0.load(Ordering::Relaxed);
        loop {
            let next = (f64::from_bits(current) + delta).to_bits();
            match self.0.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(seen) => current = seen,
            }
        }
    }

    pub fn get(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::Relaxed))
    }
}

/// A histogram over `BUCKETS`.
///
/// Only the bucket an observation falls in is touched, so recording costs one atomic
/// add rather than one per bucket; the cumulative counts Prometheus wants are summed
/// at render time, which happens once a scrape.
#[derive(Debug)]
pub struct Hist {
    /// One per edge in `BUCKETS`. Anything past the last edge is only in `count`.
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
    /// Microseconds, so the running total needs no float atomic.
    sum_us: AtomicU64,
}

impl Default for Hist {
    fn default() -> Self {
        Hist {
            buckets: BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }
}

impl Hist {
    pub fn observe(&self, seconds: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us
            .fetch_add((seconds * 1e6).max(0.0) as u64, Ordering::Relaxed);

        if let Some(index) = BUCKETS.iter().position(|edge| seconds <= *edge) {
            self.buckets[index].fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct Series<V> {
    labels: Box<[Box<str>]>,
    value: V,
}

impl<V> Series<V> {
    fn is(&self, labels: &[&str]) -> bool {
        self.labels.len() == labels.len()
            && self
                .labels
                .iter()
                .zip(labels)
                .all(|(mine, theirs)| mine.as_ref() == *theirs)
    }
}

/// One metric name, and every label combination seen for it.
pub struct Family<V> {
    name: &'static str,
    help: &'static str,
    label_names: &'static [&'static str],
    series: RwLock<HashMap<u64, Series<V>>>,
    dropped: AtomicU64,
}

pub type Counter = Family<AtomicU64>;
pub type Gauges = Family<Gauge>;
pub type Histogram = Family<Hist>;

impl<V: Default> Family<V> {
    pub fn new(name: &'static str, help: &'static str, label_names: &'static [&'static str]) -> Self {
        Family {
            name,
            help,
            label_names,
            series: RwLock::new(HashMap::new()),
            dropped: AtomicU64::new(0),
        }
    }

    /// Do something to the value for one label combination, creating it if needed.
    ///
    /// Returns false when the record went nowhere, which is either the series cap or -
    /// vanishingly unlikely - two label sets hashing the same. Both are counted; both
    /// mean a lost record rather than a wrong one.
    fn touch(&self, labels: &[&str], f: impl FnOnce(&V)) -> bool {
        debug_assert_eq!(labels.len(), self.label_names.len(), "{}", self.name);
        let key = hash(labels);

        {
            let series = self.series.read().unwrap_or_else(|e| e.into_inner());
            if let Some(found) = series.get(&key) {
                if found.is(labels) {
                    f(&found.value);
                    return true;
                }
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }

        let mut series = self.series.write().unwrap_or_else(|e| e.into_inner());
        if series.len() >= MAX_SERIES && !series.contains_key(&key) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let entry = series.entry(key).or_insert_with(|| Series {
            labels: labels.iter().map(|l| Box::from(*l)).collect(),
            value: V::default(),
        });
        if !entry.is(labels) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        f(&entry.value);
        true
    }

    /// Read one series without creating it, so asking about a series is never the
    /// reason it appears in a scrape.
    fn peek<R>(&self, labels: &[&str], f: impl FnOnce(&V) -> R) -> Option<R> {
        let series = self.series.read().unwrap_or_else(|e| e.into_inner());
        let found = series.get(&hash(labels))?;
        found.is(labels).then(|| f(&found.value))
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Every series, sorted, so a scrape reads the same way twice.
    fn sorted<R>(&self, mut each: impl FnMut(&[Box<str>], &V) -> R) -> Vec<R> {
        let series = self.series.read().unwrap_or_else(|e| e.into_inner());
        let mut all: Vec<&Series<V>> = series.values().collect();
        all.sort_by(|a, b| a.labels.as_ref().cmp(b.labels.as_ref()));
        all.into_iter().map(|s| each(&s.labels, &s.value)).collect()
    }

    fn header(&self, out: &mut String, kind: &str) {
        let _ = writeln!(out, "# HELP {} {}", self.name, self.help);
        let _ = writeln!(out, "# TYPE {} {kind}", self.name);
    }

    /// `{zone="demo",status="200"}`, or nothing at all for an unlabelled family.
    fn labels(&self, values: &[Box<str>], extra: Option<(&str, &str)>) -> String {
        let mut pairs: Vec<String> = self
            .label_names
            .iter()
            .zip(values)
            .map(|(name, value)| format!("{name}=\"{}\"", escape(value)))
            .collect();
        if let Some((name, value)) = extra {
            pairs.push(format!("{name}=\"{}\"", escape(value)));
        }
        match pairs.is_empty() {
            true => String::new(),
            false => format!("{{{}}}", pairs.join(",")),
        }
    }
}

impl Counter {
    pub fn inc(&self, labels: &[&str]) {
        self.add(labels, 1);
    }

    pub fn add(&self, labels: &[&str], by: u64) {
        self.touch(labels, |v| {
            v.fetch_add(by, Ordering::Relaxed);
        });
    }

    pub fn get(&self, labels: &[&str]) -> u64 {
        self.peek(labels, |v| v.load(Ordering::Relaxed)).unwrap_or(0)
    }

    pub fn render_into(&self, out: &mut String) {
        self.header(out, "counter");
        for line in self.sorted(|labels, value| {
            format!(
                "{}{} {}\n",
                self.name,
                self.labels(labels, None),
                value.load(Ordering::Relaxed)
            )
        }) {
            out.push_str(&line);
        }
    }
}

impl Gauges {
    pub fn set(&self, labels: &[&str], value: f64) {
        self.touch(labels, |g| g.set(value));
    }

    pub fn add(&self, labels: &[&str], delta: f64) {
        self.touch(labels, |g| g.add(delta));
    }

    pub fn get(&self, labels: &[&str]) -> f64 {
        self.peek(labels, |g| g.get()).unwrap_or(0.0)
    }

    pub fn render_into(&self, out: &mut String) {
        self.header(out, "gauge");
        for line in self.sorted(|labels, value| {
            format!(
                "{}{} {}\n",
                self.name,
                self.labels(labels, None),
                number(value.get())
            )
        }) {
            out.push_str(&line);
        }
    }
}

impl Histogram {
    pub fn observe(&self, labels: &[&str], took: Duration) {
        self.touch(labels, |h| h.observe(took.as_secs_f64()));
    }

    pub fn render_into(&self, out: &mut String) {
        self.header(out, "histogram");
        for block in self.sorted(|labels, hist| {
            let mut block = String::new();
            /* the exposition format wants cumulative counts, so carry the running
               total up through the buckets */
            let mut running = 0;
            for (index, edge) in BUCKETS.iter().enumerate() {
                running += hist.buckets[index].load(Ordering::Relaxed);
                let _ = writeln!(
                    block,
                    "{}_bucket{} {running}",
                    self.name,
                    self.labels(labels, Some(("le", &number(*edge))))
                );
            }
            let count = hist.count.load(Ordering::Relaxed);
            let _ = writeln!(
                block,
                "{}_bucket{} {count}",
                self.name,
                self.labels(labels, Some(("le", "+Inf")))
            );
            let seconds = hist.sum_us.load(Ordering::Relaxed) as f64 / 1e6;
            let _ = writeln!(
                block,
                "{}_sum{} {}",
                self.name,
                self.labels(labels, None),
                number(seconds)
            );
            let _ = writeln!(block, "{}_count{} {count}", self.name, self.labels(labels, None));
            block
        }) {
            out.push_str(&block);
        }
    }
}

/// Everything the edge counts. One per process, built at boot and shared.
pub struct Metrics {
    pub requests: Counter,
    pub request_duration: Histogram,
    pub cache_results: Counter,
    pub waf_matches: Counter,
    pub ratelimit_decisions: Counter,
    pub ratelimit_factor: Gauges,
    pub origin_requests: Counter,
    pub origin_errors: Counter,
    pub origin_duration: Histogram,
    pub origin_healthy: Gauges,
    pub origin_failovers: Counter,
    pub origin_probes: Counter,
    pub connections: Counter,
    pub connections_refused: Counter,
    pub connections_active: Gauges,
    pub tls_handshake_failures: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            requests: Counter::new(
                "cloudveil_requests_total",
                "Requests answered, by zone, status and the stage that decided.",
                &["zone", "status", "decided_by"],
            ),
            request_duration: Histogram::new(
                "cloudveil_request_duration_seconds",
                "Time from accepting a request to answering it.",
                &["zone"],
            ),
            cache_results: Counter::new(
                "cloudveil_cache_results_total",
                "Cache decisions, by outcome: hit, miss, stale, stale-error or bypass.",
                &["zone", "result"],
            ),
            waf_matches: Counter::new(
                "cloudveil_waf_matches_total",
                "WAF rule matches, by rule, severity and what the rule did.",
                &["zone", "rule", "severity", "action"],
            ),
            ratelimit_decisions: Counter::new(
                "cloudveil_ratelimit_decisions_total",
                "Requests over a rate limit, by rule and whether it was enforced.",
                &["zone", "rule", "action"],
            ),
            ratelimit_factor: Gauges::new(
                "cloudveil_ratelimit_factor",
                "What rate limit allowances are currently multiplied by; below 1 means \
                 the adaptive tier has tightened this zone.",
                &["zone"],
            ),
            origin_requests: Counter::new(
                "cloudveil_origin_requests_total",
                "Requests sent to an origin, including background revalidations.",
                &["zone", "origin"],
            ),
            origin_errors: Counter::new(
                "cloudveil_origin_errors_total",
                "Origin requests that failed, by kind: unreachable or timeout.",
                &["zone", "origin", "kind"],
            ),
            origin_duration: Histogram::new(
                "cloudveil_origin_duration_seconds",
                "Time waiting for an origin to start answering.",
                &["zone", "origin"],
            ),
            origin_healthy: Gauges::new(
                "cloudveil_origin_healthy",
                "1 while an origin is in rotation, 0 while it is taken out.",
                &["zone", "origin"],
            ),
            origin_failovers: Counter::new(
                "cloudveil_origin_failovers_total",
                "Requests that had to be sent to a second origin because the first \
                 could not be reached.",
                &["zone"],
            ),
            origin_probes: Counter::new(
                "cloudveil_origin_probes_total",
                "Health probes sent, by result.",
                &["zone", "origin", "result"],
            ),
            connections: Counter::new(
                "cloudveil_connections_total",
                "Connections accepted.",
                &[],
            ),
            connections_refused: Counter::new(
                "cloudveil_connections_refused_total",
                "Connections refused at accept time, by reason.",
                &["reason"],
            ),
            connections_active: Gauges::new(
                "cloudveil_connections_active",
                "Connections currently open.",
                &[],
            ),
            tls_handshake_failures: Counter::new(
                "cloudveil_tls_handshake_failures_total",
                "TLS handshakes that never completed, by reason.",
                &["reason"],
            ),
        }
    }

    /// One finished request. The single place the per-request series are written, so
    /// they cannot disagree with each other about what happened.
    pub fn request(
        &self,
        zone: &str,
        status: u16,
        decided_by: &str,
        took: Duration,
        cache: Option<&str>,
    ) {
        let zone = zone_label(zone);
        let status = status.to_string();
        self.requests.inc(&[zone, &status, decided_by]);
        self.request_duration.observe(&[zone], took);

        if let Some(result) = cache {
            self.cache_results
                .inc(&[zone, &result.to_ascii_lowercase()]);
        }
    }

    pub fn waf_match(&self, zone: &str, rule: &str, severity: &str, action: &str) {
        self.waf_matches
            .inc(&[zone_label(zone), rule, severity, action]);
    }

    pub fn ratelimit(&self, zone: &str, rule: &str, action: &str) {
        self.ratelimit_decisions
            .inc(&[zone_label(zone), rule, action]);
    }

    /// One origin fetch. `kind` is None when it worked - a 5xx from a healthy-looking
    /// origin is a status, not an error, and shows up in `requests_total`.
    ///
    /// Labelled by origin as well as zone, because with a pool the useful question stops
    /// being "is the origin slow" and becomes "which one".
    pub fn origin_call(&self, zone: &str, origin: &str, took: Duration, kind: Option<&str>) {
        let zone = zone_label(zone);
        self.origin_requests.inc(&[zone, origin]);
        self.origin_duration.observe(&[zone, origin], took);
        if let Some(kind) = kind {
            self.origin_errors.inc(&[zone, origin, kind]);
        }
    }

    pub fn origin_health(&self, zone: &str, origin: &str, healthy: bool) {
        self.origin_healthy.set(
            &[zone_label(zone), origin],
            match healthy {
                true => 1.0,
                false => 0.0,
            },
        );
    }

    pub fn failover(&self, zone: &str) {
        self.origin_failovers.inc(&[zone_label(zone)]);
    }

    pub fn probe(&self, zone: &str, origin: &str, result: &str) {
        self.origin_probes.inc(&[zone_label(zone), origin, result]);
    }

    pub fn connection_opened(&self) {
        self.connections.inc(&[]);
        self.connections_active.add(&[], 1.0);
    }

    pub fn connection_closed(&self) {
        self.connections_active.add(&[], -1.0);
    }

    /// Records that could not be stored, over every family. Worth scraping: it is the
    /// only sign that a series is missing rather than idle.
    pub fn dropped_series(&self) -> u64 {
        self.requests.dropped()
            + self.request_duration.dropped()
            + self.cache_results.dropped()
            + self.waf_matches.dropped()
            + self.ratelimit_decisions.dropped()
            + self.ratelimit_factor.dropped()
            + self.origin_requests.dropped()
            + self.origin_errors.dropped()
            + self.origin_duration.dropped()
            + self.origin_healthy.dropped()
            + self.origin_failovers.dropped()
            + self.origin_probes.dropped()
            + self.connections.dropped()
            + self.connections_refused.dropped()
            + self.connections_active.dropped()
            + self.tls_handshake_failures.dropped()
    }

    /// Everything this registry holds, in exposition format. Whoever serves it adds
    /// the values that are read rather than counted - see `gauge` and `counter`.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        self.requests.render_into(&mut out);
        self.request_duration.render_into(&mut out);
        self.cache_results.render_into(&mut out);
        self.waf_matches.render_into(&mut out);
        self.ratelimit_decisions.render_into(&mut out);
        self.ratelimit_factor.render_into(&mut out);
        self.origin_requests.render_into(&mut out);
        self.origin_errors.render_into(&mut out);
        self.origin_duration.render_into(&mut out);
        self.origin_healthy.render_into(&mut out);
        self.origin_failovers.render_into(&mut out);
        self.origin_probes.render_into(&mut out);
        self.connections.render_into(&mut out);
        self.connections_refused.render_into(&mut out);
        self.connections_active.render_into(&mut out);
        self.tls_handshake_failures.render_into(&mut out);
        out
    }
}

/// A single gauge read straight off live state at scrape time. Cache size and uptime
/// work this way: mirroring them into a registry would only give them a chance to be
/// wrong.
pub fn gauge(out: &mut String, name: &str, help: &str, value: f64) {
    sample(out, name, help, "gauge", &[], value);
}

pub fn counter(out: &mut String, name: &str, help: &str, value: f64) {
    sample(out, name, help, "counter", &[], value);
}

/// A gauge with fixed labels, for things like `build_info{version="0.1.0"} 1`.
pub fn labelled_gauge(
    out: &mut String,
    name: &str,
    help: &str,
    labels: &[(&str, &str)],
    value: f64,
) {
    sample(out, name, help, "gauge", labels, value);
}

fn sample(out: &mut String, name: &str, help: &str, kind: &str, labels: &[(&str, &str)], value: f64) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");

    let labels = match labels.is_empty() {
        true => String::new(),
        false => format!(
            "{{{}}}",
            labels
                .iter()
                .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    };
    let _ = writeln!(out, "{name}{labels} {}", number(value));
}

fn zone_label(zone: &str) -> &str {
    match zone.is_empty() {
        true => UNROUTED,
        false => zone,
    }
}

/// Label values are the only part of a scrape that isn't ours: rule ids and zone names
/// come from a config file somebody typed.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Prometheus wants `NaN`, `+Inf` and `-Inf` spelled its way, and plain decimals
/// otherwise - `{}` on an f64 already gives `1` and `0.5` rather than `1.0e0`.
fn number(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return match value.is_sign_positive() {
            true => "+Inf".into(),
            false => "-Inf".into(),
        };
    }
    format!("{value}")
}

fn hash(labels: &[&str]) -> u64 {
    let mut hasher = DefaultHasher::new();
    /* the count goes in too, so ["a","bc"] and ["ab","c"] can't collide by concatenation */
    labels.len().hash(&mut hasher);
    for label in labels {
        label.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value on a line, for a metric named exactly `name` with these labels.
    fn line(rendered: &str, prefix: &str) -> Option<String> {
        rendered
            .lines()
            .find(|l| l.starts_with(prefix) && l[prefix.len()..].starts_with(' '))
            .map(|l| l[prefix.len()..].trim().to_owned())
    }

    #[test]
    fn counts_per_label_combination() {
        let m = Metrics::new();
        m.request("demo", 200, "cache", Duration::from_millis(2), Some("HIT"));
        m.request("demo", 200, "cache", Duration::from_millis(3), Some("HIT"));
        m.request("demo", 403, "waf", Duration::from_micros(400), None);

        assert_eq!(m.requests.get(&["demo", "200", "cache"]), 2);
        assert_eq!(m.requests.get(&["demo", "403", "waf"]), 1);
        assert_eq!(m.cache_results.get(&["demo", "hit"]), 2);
        assert_eq!(m.requests.get(&["demo", "500", "origin"]), 0);
    }

    #[test]
    fn a_request_that_matched_no_zone_is_still_counted() {
        let m = Metrics::new();
        m.request("", 404, "route", Duration::from_millis(1), None);
        assert_eq!(m.requests.get(&["unrouted", "404", "route"]), 1);
    }

    #[test]
    fn renders_the_exposition_format() {
        let m = Metrics::new();
        m.request("demo", 200, "origin", Duration::from_millis(20), Some("MISS"));
        let out = m.render();

        assert!(
            out.contains("# HELP cloudveil_requests_total Requests answered"),
            "no help line:\n{out}"
        );
        assert!(out.contains("# TYPE cloudveil_requests_total counter"));
        assert_eq!(
            line(&out, r#"cloudveil_requests_total{zone="demo",status="200",decided_by="origin"}"#),
            Some("1".into())
        );
        assert_eq!(
            line(&out, r#"cloudveil_cache_results_total{zone="demo",result="miss"}"#),
            Some("1".into())
        );
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_end_at_the_count() {
        let m = Metrics::new();
        for ms in [1, 30, 30, 4000] {
            m.request_duration.observe(&["demo"], Duration::from_millis(ms));
        }
        let out = m.render();

        let at = |le: &str| {
            line(
                &out,
                &format!(r#"cloudveil_request_duration_seconds_bucket{{zone="demo",le="{le}"}}"#),
            )
        };
        assert_eq!(at("0.001"), Some("1".into()), "1ms falls in the 1ms bucket");
        assert_eq!(at("0.01"), Some("1".into()));
        assert_eq!(at("0.05"), Some("3".into()), "the two 30ms observations join it");
        assert_eq!(at("10"), Some("4".into()), "4s is under the last edge");
        assert_eq!(at("+Inf"), Some("4".into()));
        assert_eq!(
            line(&out, r#"cloudveil_request_duration_seconds_count{zone="demo"}"#),
            Some("4".into())
        );
        assert_eq!(
            line(&out, r#"cloudveil_request_duration_seconds_sum{zone="demo"}"#),
            Some("4.061".into())
        );
    }

    #[test]
    fn an_observation_past_the_last_bucket_only_lands_in_inf() {
        let m = Metrics::new();
        m.request_duration.observe(&["slow"], Duration::from_secs(30));
        let out = m.render();

        assert_eq!(
            line(&out, r#"cloudveil_request_duration_seconds_bucket{zone="slow",le="10"}"#),
            Some("0".into())
        );
        assert_eq!(
            line(&out, r#"cloudveil_request_duration_seconds_bucket{zone="slow",le="+Inf"}"#),
            Some("1".into())
        );
    }

    #[test]
    fn gauges_go_up_and_down() {
        let m = Metrics::new();
        m.connection_opened();
        m.connection_opened();
        m.connection_closed();

        assert_eq!(m.connections.get(&[]), 2);
        assert_eq!(m.connections_active.get(&[]), 1.0);
        /* an unlabelled family renders with no braces at all */
        assert!(m.render().contains("\ncloudveil_connections_active 1\n"));
    }

    #[test]
    fn the_adaptive_factor_is_a_gauge_not_a_counter() {
        let m = Metrics::new();
        m.ratelimit_factor.set(&["demo"], 0.5);
        m.ratelimit_factor.set(&["demo"], 1.0);
        assert_eq!(m.ratelimit_factor.get(&["demo"]), 1.0);
        assert!(m.render().contains(r#"cloudveil_ratelimit_factor{zone="demo"} 1"#));
    }

    #[test]
    fn label_values_from_a_config_file_cannot_break_a_line() {
        let m = Metrics::new();
        m.waf_match("demo", "rule \"one\"\nwith\\junk", "high", "block");
        let out = m.render();

        assert!(
            out.contains(r#"rule="rule \"one\"\nwith\\junk""#),
            "not escaped:\n{out}"
        );
        /* every line is either a comment or a sample - nothing broke out */
        for l in out.lines() {
            assert!(
                l.starts_with('#') || l.starts_with("cloudveil_"),
                "stray line: {l}"
            );
        }
    }

    #[test]
    fn series_are_capped_and_the_loss_is_counted() {
        let family = Counter::new("cloudveil_test_total", "A test.", &["n"]);
        for n in 0..(MAX_SERIES + 50) {
            family.inc(&[&n.to_string()]);
        }

        assert_eq!(family.dropped(), 50);
        /* the ones already being tracked keep working */
        family.inc(&["0"]);
        assert_eq!(family.get(&["0"]), 2);
    }

    #[test]
    fn a_scrape_reads_the_same_way_twice() {
        let m = Metrics::new();
        for zone in ["b", "a", "c"] {
            m.request(zone, 200, "origin", Duration::from_millis(1), None);
        }
        assert_eq!(m.render(), m.render());
    }

    #[test]
    fn pulled_samples_carry_their_own_headers() {
        let mut out = String::new();
        gauge(&mut out, "cloudveil_cache_bytes", "Bytes held.", 4096.0);
        counter(&mut out, "cloudveil_events_dropped_total", "Events shed.", 3.0);
        labelled_gauge(
            &mut out,
            "cloudveil_build_info",
            "Version.",
            &[("version", "0.1.0")],
            1.0,
        );

        assert!(out.contains("# TYPE cloudveil_cache_bytes gauge"));
        assert!(out.contains("\ncloudveil_cache_bytes 4096\n"));
        assert!(out.contains("# TYPE cloudveil_events_dropped_total counter"));
        assert!(out.contains(r#"cloudveil_build_info{version="0.1.0"} 1"#));
    }

    #[test]
    fn odd_floats_are_spelled_the_way_prometheus_wants() {
        assert_eq!(number(1.0), "1");
        assert_eq!(number(0.5), "0.5");
        assert_eq!(number(f64::NAN), "NaN");
        assert_eq!(number(f64::INFINITY), "+Inf");
        assert_eq!(number(f64::NEG_INFINITY), "-Inf");
    }
}

