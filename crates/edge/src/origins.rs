//! Which backend gets the request, and whether it is worth trying at all.
//!
//! Until now a zone had exactly one origin, so "pick an origin" was not a decision and
//! an origin going down was a zone going down. `stale-if-error` softened that for URLs
//! that happened to be cached and did nothing for the rest. Keeping a site up when a
//! backend dies is most of why anyone puts a proxy in front of one.
//!
//! Two halves. **Passive** health is free: every origin request already passes through
//! `Fetcher`, so counting what it sees costs nothing and needs no extra traffic. It is
//! also always late - somebody's request is the thing that discovers the problem.
//! **Active** probes cost a request every few seconds and know before anybody asks, and
//! they are the only way a dead origin comes *back* without a user walking into it.
//!
//! Health state lives here rather than in `Config`, because config is swapped wholesale
//! on reload and health must survive that - editing a WAF rule should not forget that an
//! origin is down.
//!
//! One rule worth stating out loud: **when every origin looks unhealthy, we try anyway.**
//! Health is a guess built from a handful of failures, and a guess that can take the
//! whole site down is worse than no guess at all. Better to send a request at something
//! that will probably fail than to answer 502 without trying.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{Origin, OriginPool, Strategy};
use crate::metrics::Metrics;
use crate::snapshot::Snapshot;
use crate::stages::origin::Fetcher;

/// What we think of one origin in one zone.
struct State {
    /// Reset by any success. Drives the decision to take an origin out.
    failures: u32,
    /// Only counted while an origin is down, so a flapping backend has to prove itself.
    successes: u32,
    /// Some means unhealthy, and when to try it again.
    down_until: Option<Instant>,
    /// When a probe last went out, so one ticker can serve every interval.
    last_probe: Option<Instant>,
    /// Requests sent and not yet answered. What `least_connections` sorts on.
    in_flight: u32,
    /// Credit for the weighted round-robin, in the smooth variant: every pick adds each
    /// origin's weight and takes the highest, which spreads a 3:1 split as ABAA rather
    /// than AAAB.
    credit: i64,
}

impl State {
    fn new() -> Self {
        State {
            failures: 0,
            successes: 0,
            down_until: None,
            last_probe: None,
            in_flight: 0,
            credit: 0,
        }
    }

    fn healthy(&self, now: Instant) -> bool {
        match self.down_until {
            None => true,
            /* the cooldown expiring does not make it healthy, it makes it worth
               trying again - the next result decides */
            Some(until) => now >= until,
        }
    }
}

/// One request that had to be sent somewhere else. Kept as a list rather than only a
/// counter because "it failed over 40 times" and "it failed over 40 times in the last
/// minute, always away from the same backend" are different problems.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Failover {
    pub at_ms: u64,
    pub zone: String,
    pub from: String,
    pub to: String,
}

/// How many to remember. A dashboard shows a handful; anything longer belongs in the
/// analytics the events already feed.
const FAILOVERS: usize = 32;

#[derive(Default)]
pub struct Health {
    states: Mutex<HashMap<Key, State>>,
    /// Round-robin cursor per zone.
    next: Mutex<HashMap<String, usize>>,
    /// Only for the metrics gauge, which wants a number rather than a lock.
    live: AtomicUsize,
    failovers: Mutex<VecDeque<Failover>>,
}

/// A zone plus an origin's authority. The authority rather than the index, so reordering
/// the list in config doesn't shuffle what we know about each backend.
type Key = (String, String);

fn key(zone: &str, origin: &Origin) -> Key {
    (zone.to_owned(), origin.authority.to_string())
}

impl Health {
    pub fn new() -> Arc<Self> {
        Arc::new(Health::default())
    }

    /// The order to try origins in: everything healthy first, in the strategy's order,
    /// then everything else. Never empty for a non-empty pool - see the module note.
    ///
    /// The balancing strategies all decide among the *healthy* origins, which is why the
    /// split happens after the ordering rather than before it: an unhealthy backend
    /// should not be able to consume a turn or a share of the weights.
    pub fn candidates(&self, zone: &str, pool: &OriginPool) -> Vec<usize> {
        let now = Instant::now();
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());

        let all: Vec<usize> = (0..pool.origins.len()).collect();
        let (mut up, down): (Vec<usize>, Vec<usize>) = all.into_iter().partition(|i| {
            states
                .get(&key(zone, &pool.origins[*i]))
                .map(|s| s.healthy(now))
                .unwrap_or(true)
        });

        match pool.strategy {
            /* already in preference order */
            Strategy::FirstHealthy => {}
            Strategy::RoundRobin => {
                if up.len() > 1 {
                    let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
                    let cursor = next.entry(zone.to_owned()).or_insert(0);
                    let start = *cursor % up.len();
                    *cursor = start + 1;
                    up.rotate_left(start);
                }
            }
            Strategy::Weighted => {
                if up.len() > 1 {
                    let chosen = self.weighted_pick(zone, pool, &up, &mut states);
                    /* the winner first, the rest behind it as fallbacks */
                    if let Some(at) = up.iter().position(|i| *i == chosen) {
                        up.rotate_left(at);
                    }
                }
            }
            Strategy::LeastConnections => {
                up.sort_by_key(|i| {
                    states
                        .get(&key(zone, &pool.origins[*i]))
                        .map(|s| s.in_flight)
                        .unwrap_or(0)
                });
            }
        }

        up.into_iter().chain(down).collect()
    }

    /// Smooth weighted round-robin: every pick gives each origin its weight in credit and
    /// takes whoever has the most, then charges the winner the total. A 3:1 split comes
    /// out ABAA rather than AAAB, which matters because the bursty version parks three
    /// requests on one backend and then idles it.
    fn weighted_pick(
        &self,
        zone: &str,
        pool: &OriginPool,
        up: &[usize],
        states: &mut HashMap<Key, State>,
    ) -> usize {
        let total: i64 = up.iter().map(|i| pool.origins[*i].weight as i64).sum();

        let mut best = up[0];
        let mut best_credit = i64::MIN;
        for &i in up {
            let origin = &pool.origins[i];
            let state = states.entry(key(zone, origin)).or_insert_with(State::new);
            state.credit += origin.weight as i64;
            if state.credit > best_credit {
                best_credit = state.credit;
                best = i;
            }
        }

        if let Some(state) = states.get_mut(&key(zone, &pool.origins[best])) {
            state.credit -= total;
        }
        best
    }

    /// Counts a request against an origin for as long as it is in flight. Only
    /// `least_connections` reads this, but it is cheap enough to keep always.
    pub fn started(&self, zone: &str, origin: &Origin) {
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        let state = states.entry(key(zone, origin)).or_insert_with(State::new);
        state.in_flight = state.in_flight.saturating_add(1);
    }

    pub fn finished(&self, zone: &str, origin: &Origin) {
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = states.get_mut(&key(zone, origin)) {
            state.in_flight = state.in_flight.saturating_sub(1);
        }
    }

    pub fn in_flight(&self, zone: &str, origin: &Origin) -> u32 {
        self.states
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key(zone, origin))
            .map(|s| s.in_flight)
            .unwrap_or(0)
    }

    pub fn record_success(&self, zone: &str, origin: &Origin, healthy_after: u32) {
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        let state = states.entry(key(zone, origin)).or_insert_with(State::new);

        state.failures = 0;
        if state.down_until.is_some() {
            state.successes += 1;
            if state.successes >= healthy_after.max(1) {
                state.down_until = None;
                state.successes = 0;
                tracing::info!("zone {zone}: origin {} is back", origin.authority);
            }
        }
    }

    pub fn record_failure(&self, zone: &str, origin: &Origin, pool: &OriginPool) {
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        let state = states.entry(key(zone, origin)).or_insert_with(State::new);

        state.successes = 0;
        state.failures += 1;
        if state.failures >= pool.unhealthy_after.max(1) && state.down_until.is_none() {
            state.down_until = Some(Instant::now() + pool.retry_after);
            tracing::warn!(
                "zone {zone}: origin {} taken out after {} failures, retrying in {:?}",
                origin.authority,
                state.failures,
                pool.retry_after
            );
        } else if state.down_until.is_some() {
            /* still down: push the cooldown out rather than letting it lapse into a
               retry the moment it expires while the origin is plainly still broken */
            state.down_until = Some(Instant::now() + pool.retry_after);
        }
    }

    pub fn is_healthy(&self, zone: &str, origin: &Origin) -> bool {
        let now = Instant::now();
        self.states
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key(zone, origin))
            .map(|s| s.healthy(now))
            .unwrap_or(true)
    }

    /// Every origin's state, for the admin api and the scrape.
    pub fn report(&self, zone: &str, pool: &OriginPool) -> Vec<(String, bool)> {
        pool.origins
            .iter()
            .map(|o| (o.authority.to_string(), self.is_healthy(zone, o)))
            .collect()
    }

    /// Whether a probe is due, marking it as sent if so. Doing both under one lock keeps
    /// two ticks from probing the same origin twice.
    fn probe_due(&self, zone: &str, origin: &Origin, every: Duration) -> bool {
        let now = Instant::now();
        let mut states = self.states.lock().unwrap_or_else(|e| e.into_inner());
        let state = states.entry(key(zone, origin)).or_insert_with(State::new);

        match state.last_probe {
            Some(last) if now.saturating_duration_since(last) < every => false,
            _ => {
                state.last_probe = Some(now);
                true
            }
        }
    }

    pub fn probes_in_flight(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    pub fn note_failover(&self, zone: &str, from: &str, to: &str) {
        let mut log = self.failovers.lock().unwrap_or_else(|e| e.into_inner());
        if log.len() == FAILOVERS {
            log.pop_front();
        }
        log.push_back(Failover {
            at_ms: crate::analytics::now_ms(),
            zone: zone.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
        });
    }

    /// Newest first, which is the order anybody looking at them wants.
    pub fn failovers(&self) -> Vec<Failover> {
        self.failovers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .cloned()
            .collect()
    }
}

/// How often the prober wakes up. Each origin is still probed on its own interval; this
/// is only the granularity, and one task is enough for any number of them.
const TICK: Duration = Duration::from_millis(500);

/// Start the prober. Reads the live snapshot every tick, so a reload that adds an origin
/// or changes an interval is picked up without restarting anything.
pub fn spawn_probes(
    snap: Arc<Snapshot>,
    health: Arc<Health>,
    fetcher: Arc<Fetcher>,
    metrics: Arc<Metrics>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            let cfg = snap.current();

            for zone in &cfg.zones {
                let Some(probe) = zone.origins.probe.clone() else {
                    continue;
                };
                for origin in &zone.origins.origins {
                    if !health.probe_due(&zone.name, origin, probe.every) {
                        continue;
                    }

                    let host = zone
                        .hostnames
                        .first()
                        .cloned()
                        .unwrap_or_else(|| origin.authority.to_string());

                    let task = Probe {
                        zone: zone.name.clone(),
                        origin: origin.clone(),
                        pool: zone.origins.clone(),
                        probe: probe.clone(),
                        host,
                        health: health.clone(),
                        fetcher: fetcher.clone(),
                        metrics: metrics.clone(),
                    };
                    tokio::spawn(task.run());
                }
            }
        }
    });
}

struct Probe {
    zone: String,
    origin: Origin,
    pool: OriginPool,
    probe: crate::config::ProbeConfig,
    host: String,
    health: Arc<Health>,
    fetcher: Arc<Fetcher>,
    metrics: Arc<Metrics>,
}

impl Probe {
    async fn run(self) {
        self.health.live.fetch_add(1, Ordering::Relaxed);
        let outcome = self.send().await;
        self.health.live.fetch_sub(1, Ordering::Relaxed);

        let authority = self.origin.authority.to_string();
        match outcome {
            Ok(()) => {
                self.health
                    .record_success(&self.zone, &self.origin, self.pool.healthy_after());
                self.metrics.probe(&self.zone, &authority, "ok");
            }
            Err(why) => {
                /* a probe failure counts the same as a request failure: two signals
                   about one origin should not be two separate opinions */
                self.health.record_failure(&self.zone, &self.origin, &self.pool);
                self.metrics.probe(&self.zone, &authority, "failed");
                tracing::debug!("zone {}: probe of {authority} failed: {why}", self.zone);
            }
        }
        self.metrics.origin_health(
            &self.zone,
            &authority,
            self.health.is_healthy(&self.zone, &self.origin),
        );
    }

    async fn send(&self) -> Result<(), String> {
        use crate::body::full;

        let url = format!(
            "{}://{}{}",
            self.origin.scheme, self.origin.authority, self.probe.path
        );
        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(&url)
            .header(hyper::header::HOST, &self.host)
            .body(full(""))
            .map_err(|e| format!("bad probe request: {e}"))?;

        /* the probe's own timeout, not the origin's: a health check that waits as long
           as a real request is a health check that notices far too late */
        let probing = Origin {
            timeout: self.probe.timeout,
            ..self.origin.clone()
        };
        let resp = self
            .fetcher
            .send_direct(&probing, &self.host, req)
            .await
            .map_err(|e| e.detail)?;

        /* 2xx and 3xx only. a 500 from a health endpoint is the endpoint doing its job */
        match resp.status().is_success() || resp.status().is_redirection() {
            true => Ok(()),
            false => Err(format!("probe returned {}", resp.status())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn pool(yaml: &str) -> OriginPool {
        let cfg = config::parse(yaml).expect("test config should parse");
        cfg.zones[0].origins.clone()
    }

    /// Two origins, first-healthy.
    fn two() -> OriginPool {
        pool(
            r#"
zones:
  - name: demo
    hostnames: ["demo.local"]
    origins:
      - url: "http://10.0.0.1:80"
      - url: "http://10.0.0.2:80"
    origin_policy:
      unhealthy_after: 2
      retry_after_secs: 60
"#,
        )
    }

    #[test]
    fn a_healthy_pool_is_tried_in_order() {
        let health = Health::new();
        assert_eq!(health.candidates("demo", &two()), vec![0, 1]);
    }

    #[test]
    fn an_origin_is_taken_out_after_enough_failures_and_not_before() {
        let pool = two();
        let health = Health::new();

        health.record_failure("demo", &pool.origins[0], &pool);
        assert_eq!(
            health.candidates("demo", &pool),
            vec![0, 1],
            "one failure is not a dead origin"
        );

        health.record_failure("demo", &pool.origins[0], &pool);
        assert_eq!(
            health.candidates("demo", &pool),
            vec![1, 0],
            "the second failure moves it to the back"
        );
        assert!(!health.is_healthy("demo", &pool.origins[0]));
        assert!(health.is_healthy("demo", &pool.origins[1]));
    }

    #[test]
    fn a_success_forgives_earlier_failures() {
        let pool = two();
        let health = Health::new();

        health.record_failure("demo", &pool.origins[0], &pool);
        health.record_success("demo", &pool.origins[0], 1);
        health.record_failure("demo", &pool.origins[0], &pool);

        assert_eq!(
            health.candidates("demo", &pool),
            vec![0, 1],
            "the counter restarted, so this is failure one of two"
        );
    }

    #[test]
    fn a_down_origin_needs_healthy_after_successes_to_come_back() {
        let pool = two();
        let health = Health::new();
        for _ in 0..2 {
            health.record_failure("demo", &pool.origins[0], &pool);
        }
        assert!(!health.is_healthy("demo", &pool.origins[0]));

        health.record_success("demo", &pool.origins[0], 2);
        assert!(!health.is_healthy("demo", &pool.origins[0]), "one is not enough");

        health.record_success("demo", &pool.origins[0], 2);
        assert!(health.is_healthy("demo", &pool.origins[0]));
    }

    #[test]
    fn everything_down_still_gets_tried() {
        let pool = two();
        let health = Health::new();
        for _ in 0..2 {
            health.record_failure("demo", &pool.origins[0], &pool);
            health.record_failure("demo", &pool.origins[1], &pool);
        }

        let candidates = health.candidates("demo", &pool);
        assert_eq!(
            candidates.len(),
            2,
            "a guess about health must not be able to take the site down"
        );
    }

    #[test]
    fn the_cooldown_expiring_puts_an_origin_back_in_the_queue() {
        let pool = pool(
            r#"
zones:
  - name: demo
    hostnames: ["demo.local"]
    origins:
      - url: "http://10.0.0.1:80"
      - url: "http://10.0.0.2:80"
    origin_policy:
      unhealthy_after: 1
      retry_after_secs: 0
"#,
        );
        let health = Health::new();
        health.record_failure("demo", &pool.origins[0], &pool);

        /* a zero cooldown means the very next request tries it again */
        assert!(health.is_healthy("demo", &pool.origins[0]));
    }

    #[test]
    fn round_robin_moves_the_starting_point() {
        let pool = pool(
            r#"
zones:
  - name: demo
    hostnames: ["demo.local"]
    origins:
      - url: "http://10.0.0.1:80"
      - url: "http://10.0.0.2:80"
      - url: "http://10.0.0.3:80"
    origin_policy:
      strategy: round_robin
"#,
        );
        let health = Health::new();

        assert_eq!(health.candidates("demo", &pool), vec![0, 1, 2]);
        assert_eq!(health.candidates("demo", &pool), vec![1, 2, 0]);
        assert_eq!(health.candidates("demo", &pool), vec![2, 0, 1]);
        assert_eq!(health.candidates("demo", &pool), vec![0, 1, 2]);
    }

    #[test]
    fn round_robin_still_prefers_a_healthy_origin() {
        let pool = pool(
            r#"
zones:
  - name: demo
    hostnames: ["demo.local"]
    origins:
      - url: "http://10.0.0.1:80"
      - url: "http://10.0.0.2:80"
    origin_policy:
      strategy: round_robin
      unhealthy_after: 1
      retry_after_secs: 60
"#,
        );
        let health = Health::new();
        health.record_failure("demo", &pool.origins[1], &pool);

        /* whatever the cursor says, the dead one goes last */
        for _ in 0..4 {
            assert_eq!(health.candidates("demo", &pool), vec![0, 1]);
        }
    }

    #[test]
    fn weighted_spreads_in_proportion_and_smoothly() {
        let pool = pool(
            r#"
zones:
  - name: demo
    hostnames: ["demo.local"]
    origins:
      - url: "http://10.0.0.1:80"
        weight: 3
      - url: "http://10.0.0.2:80"
        weight: 1
    origin_policy:
      strategy: weighted
"#,
        );
        let health = Health::new();

        let picks: Vec<usize> = (0..8)
            .map(|_| health.candidates("demo", &pool)[0])
            .collect();

        /* three of the first for every one of the second */
        assert_eq!(picks.iter().filter(|p| **p == 0).count(), 6);
        assert_eq!(picks.iter().filter(|p| **p == 1).count(), 2);
        /* and interleaved rather than in a run: the bursty version would park three
           requests on one backend and then idle it */
        assert_eq!(picks[..4], [0, 0, 1, 0], "picks were {picks:?}");
    }

    #[test]
    fn weighted_ignores_an_unhealthy_origins_share() {
        let pool = pool(
            r#"
zones:
  - name: demo
    hostnames: ["demo.local"]
    origins:
      - url: "http://10.0.0.1:80"
        weight: 5
      - url: "http://10.0.0.2:80"
        weight: 1
    origin_policy:
      strategy: weighted
      unhealthy_after: 1
      retry_after_secs: 60
"#,
        );
        let health = Health::new();
        health.record_failure("demo", &pool.origins[0], &pool);

        /* the heavy origin is out, so every pick is the light one - its weight does not
           entitle it to turns it cannot serve */
        for _ in 0..4 {
            assert_eq!(health.candidates("demo", &pool)[0], 1);
        }
    }

    #[test]
    fn least_connections_prefers_the_idle_origin() {
        let pool = pool(
            r#"
zones:
  - name: demo
    hostnames: ["demo.local"]
    origins:
      - url: "http://10.0.0.1:80"
      - url: "http://10.0.0.2:80"
    origin_policy:
      strategy: least_connections
"#,
        );
        let health = Health::new();

        health.started("demo", &pool.origins[0]);
        health.started("demo", &pool.origins[0]);
        assert_eq!(health.candidates("demo", &pool)[0], 1, "the busy one is second");
        assert_eq!(health.in_flight("demo", &pool.origins[0]), 2);

        health.started("demo", &pool.origins[1]);
        health.started("demo", &pool.origins[1]);
        health.started("demo", &pool.origins[1]);
        assert_eq!(health.candidates("demo", &pool)[0], 0, "now the other way round");

        /* finishing releases the count */
        for _ in 0..3 {
            health.finished("demo", &pool.origins[1]);
        }
        assert_eq!(health.in_flight("demo", &pool.origins[1]), 0);
        assert_eq!(health.candidates("demo", &pool)[0], 1);
    }

    #[test]
    fn a_finish_without_a_start_cannot_go_negative() {
        let pool = two();
        let health = Health::new();
        health.finished("demo", &pool.origins[0]);
        assert_eq!(health.in_flight("demo", &pool.origins[0]), 0);
    }

    #[test]
    fn round_robin_only_turns_among_healthy_origins() {
        let pool = pool(
            r#"
zones:
  - name: demo
    hostnames: ["demo.local"]
    origins:
      - url: "http://10.0.0.1:80"
      - url: "http://10.0.0.2:80"
      - url: "http://10.0.0.3:80"
    origin_policy:
      strategy: round_robin
      unhealthy_after: 1
      retry_after_secs: 60
"#,
        );
        let health = Health::new();
        health.record_failure("demo", &pool.origins[1], &pool);

        /* two healthy origins left, so the turn alternates between those two and the
           dead one never takes a turn */
        let picks: Vec<usize> = (0..4)
            .map(|_| health.candidates("demo", &pool)[0])
            .collect();
        assert_eq!(picks, vec![0, 2, 0, 2], "picks were {picks:?}");
    }

    #[test]
    fn health_is_per_zone_and_per_origin() {
        let pool = two();
        let health = Health::new();
        for _ in 0..2 {
            health.record_failure("demo", &pool.origins[0], &pool);
        }

        assert!(!health.is_healthy("demo", &pool.origins[0]));
        assert!(
            health.is_healthy("other", &pool.origins[0]),
            "the same backend in another zone is a different question"
        );
    }

    #[test]
    fn a_probe_is_only_due_once_per_interval() {
        let pool = two();
        let health = Health::new();
        let every = Duration::from_secs(30);

        assert!(health.probe_due("demo", &pool.origins[0], every));
        assert!(!health.probe_due("demo", &pool.origins[0], every));
        /* a different origin is due on its own schedule */
        assert!(health.probe_due("demo", &pool.origins[1], every));
    }

    #[test]
    fn a_report_names_every_origin() {
        let pool = two();
        let health = Health::new();
        for _ in 0..2 {
            health.record_failure("demo", &pool.origins[1], &pool);
        }

        assert_eq!(
            health.report("demo", &pool),
            vec![
                ("10.0.0.1:80".to_string(), true),
                ("10.0.0.2:80".to_string(), false)
            ]
        );
    }
}
