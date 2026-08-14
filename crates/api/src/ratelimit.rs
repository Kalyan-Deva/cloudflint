//! Fleet-wide rate limiting, without putting this process in the request path.
//!
//! A rate limit counted per node is not the limit anybody wrote down: ten edges each
//! allowing 100 requests a minute is a limit of a thousand. The obvious fix - ask a shared
//! store on every request - is the one thing the architecture forbids, because it would
//! make every request depend on this process being up and fast.
//!
//! So this never authorises anything. It answers one question, on a timer: **what share of
//! this key's traffic is yours?** An edge seeing a third of the requests for one address
//! applies a third of the configured limit, and the shares across the fleet add up to one
//! limit rather than one per node.
//!
//! Consequences worth knowing, all of them deliberate:
//!
//! - **It converges rather than being exact.** Between syncs an edge enforces the share it
//!   was last given, so a sudden shift in traffic can overshoot for one interval. A limit
//!   window is normally much longer than the sync interval, so the overshoot is small.
//! - **An unreachable control plane degrades to per-node limits** - exactly today's
//!   behaviour, never to "no limits" and never to "block everything".
//! - **Only heavy hitters are shared.** A key approaching its limit is by definition
//!   high-volume, so the keys that matter are the ones that get reported; the long tail is
//!   left to local counting where it was already correct.
//! - Kept in memory, not SQLite. It is written every few seconds by every node and is
//!   worthless after a restart - the fleet refills it within one interval.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// A sample older than this is ignored, and the edge that sent it treated as gone.
///
/// Three intervals, the same reasoning as the fleet's offline threshold: one missed sync is
/// a lost packet, three is a node that has stopped talking. Keeping a dead edge's traffic
/// in the total would shrink every surviving node's share and throttle real users.
const STALE_AFTER: Duration = Duration::from_secs(15);

/// The smallest share an edge is ever given.
///
/// Strictly proportional shares are right globally and cruel locally: a node seeing one
/// request in a thousand for some key would get a thousandth of the allowance and start
/// refusing its own handful of users. A floor trades a little global precision for not
/// punishing a node that is merely quiet.
const MIN_SHARE: f64 = 0.05;

/// What one edge reports about one key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Observed {
    /// The hashed subject - an address, an address and path, a header value. Hashed on the
    /// edge, so no client identifier ever reaches this process.
    pub key: u64,
    /// Requests per second this edge is seeing for that key.
    pub rate: f64,
}

/// One rule's worth of report from one edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub edge_id: String,
    pub rule: String,
    pub keys: Vec<Observed>,
}

/// What the edge should do with its own configured limit, per key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Share {
    pub key: u64,
    /// Multiply the configured limit by this. 1.0 means "all of it", which is what a
    /// single-node fleet always gets.
    pub share: f64,
    /// How many edges are currently seeing this key. Only for the dashboard - a key on one
    /// node is a local problem, the same key on forty is a distributed attack.
    pub edges: usize,
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    rate: f64,
    at: Instant,
}

#[derive(Default)]
struct Key {
    /// Per edge, its last reported rate.
    edges: HashMap<String, Sample>,
}

impl Key {
    /// Drop anything stale, then total what is left.
    fn live_total(&mut self, now: Instant) -> f64 {
        self.edges
            .retain(|_, s| now.saturating_duration_since(s.at) < STALE_AFTER);
        self.edges.values().map(|s| s.rate).sum()
    }
}

/// Every key the fleet is currently counting, per rule.
#[derive(Default)]
pub struct Fleet {
    rules: Mutex<HashMap<String, HashMap<u64, Key>>>,
}

impl Fleet {
    pub fn new() -> Fleet {
        Fleet::default()
    }

    /// Take one edge's report and answer with that edge's share of each key.
    pub fn sync(&self, report: &Report) -> Vec<Share> {
        self.sync_at(report, Instant::now())
    }

    fn sync_at(&self, report: &Report, now: Instant) -> Vec<Share> {
        let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        let keys = rules.entry(report.rule.clone()).or_default();

        let mut out = Vec::with_capacity(report.keys.len());
        for observed in &report.keys {
            let entry = keys.entry(observed.key).or_default();
            entry.edges.insert(
                report.edge_id.clone(),
                Sample {
                    /* a negative or absurd rate is a bug or a lie; either way it must not
                       be able to hand somebody else a bigger share by going below zero */
                    rate: observed.rate.max(0.0),
                    at: now,
                },
            );

            let total = entry.live_total(now);
            let mine = entry.edges.get(&report.edge_id).map(|s| s.rate).unwrap_or(0.0);

            /* with one edge reporting, or with no traffic to divide, the share is the whole
               limit - so a single-node fleet behaves exactly as it did before any of this */
            let share = match total > 0.0 {
                true => (mine / total).clamp(MIN_SHARE, 1.0),
                false => 1.0,
            };

            out.push(Share {
                key: observed.key,
                share,
                edges: entry.edges.len(),
            });
        }
        out
    }

    /// Forget stale keys. Called on sync so the map cannot grow forever on its own.
    pub fn sweep(&self) -> usize {
        self.sweep_at(Instant::now())
    }

    fn sweep_at(&self, now: Instant) -> usize {
        let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        let mut dropped = 0;

        for keys in rules.values_mut() {
            keys.retain(|_, key| {
                key.edges
                    .retain(|_, s| now.saturating_duration_since(s.at) < STALE_AFTER);
                let keep = !key.edges.is_empty();
                if !keep {
                    dropped += 1;
                }
                keep
            });
        }
        rules.retain(|_, keys| !keys.is_empty());
        dropped
    }

    /// Keys currently tracked, for the scrape and the dashboard.
    pub fn tracked(&self) -> usize {
        let rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        rules.values().map(|k| k.len()).sum()
    }

    /// The keys the fleet is seeing on the most edges - a distributed attack, if it is one.
    pub fn spread(&self, limit: usize) -> Vec<(String, u64, usize, f64)> {
        let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let mut out = Vec::new();

        for (rule, keys) in rules.iter_mut() {
            for (key, entry) in keys.iter_mut() {
                let total = entry.live_total(now);
                if !entry.edges.is_empty() {
                    out.push((rule.clone(), *key, entry.edges.len(), total));
                }
            }
        }
        /* most edges first, then by rate, so the worst offender is at the top */
        out.sort_by(|a, b| b.2.cmp(&a.2).then(b.3.total_cmp(&a.3)));
        out.truncate(limit);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(edge: &str, rule: &str, keys: &[(u64, f64)]) -> Report {
        Report {
            edge_id: edge.into(),
            rule: rule.into(),
            keys: keys.iter().map(|(key, rate)| Observed { key: *key, rate: *rate }).collect(),
        }
    }

    #[test]
    fn one_edge_gets_the_whole_limit() {
        /* the property that makes this safe to turn on: a single-node fleet is unchanged */
        let fleet = Fleet::new();
        let shares = fleet.sync(&report("a", "tight", &[(1, 50.0)]));
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].share, 1.0);
        assert_eq!(shares[0].edges, 1);
    }

    #[test]
    fn two_edges_seeing_the_same_traffic_split_it_evenly() {
        let fleet = Fleet::new();
        let now = Instant::now();
        fleet.sync_at(&report("a", "tight", &[(1, 50.0)]), now);
        let shares = fleet.sync_at(&report("b", "tight", &[(1, 50.0)]), now);

        assert!((shares[0].share - 0.5).abs() < 1e-9, "share was {}", shares[0].share);
        assert_eq!(shares[0].edges, 2);

        /* and the first edge is told the same thing on its next sync */
        let shares = fleet.sync_at(&report("a", "tight", &[(1, 50.0)]), now);
        assert!((shares[0].share - 0.5).abs() < 1e-9);
    }

    #[test]
    fn shares_follow_the_traffic_rather_than_the_headcount() {
        /* an edge taking most of the requests for a key should get most of the allowance,
           or the limit throttles the busy node while the quiet one hoards budget */
        let fleet = Fleet::new();
        let now = Instant::now();
        fleet.sync_at(&report("busy", "tight", &[(7, 90.0)]), now);
        fleet.sync_at(&report("quiet", "tight", &[(7, 10.0)]), now);

        let busy = fleet.sync_at(&report("busy", "tight", &[(7, 90.0)]), now);
        assert!((busy[0].share - 0.9).abs() < 1e-9, "share was {}", busy[0].share);
        let quiet = fleet.sync_at(&report("quiet", "tight", &[(7, 10.0)]), now);
        assert!((quiet[0].share - 0.1).abs() < 1e-9, "share was {}", quiet[0].share);
    }

    #[test]
    fn the_shares_for_one_key_add_up_to_one_limit() {
        /* the whole point: five nodes must not add up to five times the limit */
        let fleet = Fleet::new();
        let now = Instant::now();
        let rates = [40.0, 30.0, 20.0, 5.0, 5.0];
        for (i, rate) in rates.iter().enumerate() {
            fleet.sync_at(&report(&format!("e{i}"), "tight", &[(3, *rate)]), now);
        }

        let total: f64 = (0..rates.len())
            .map(|i| fleet.sync_at(&report(&format!("e{i}"), "tight", &[(3, rates[i])]), now)[0].share)
            .sum();
        assert!((total - 1.0).abs() < 1e-9, "shares summed to {total}");
    }

    #[test]
    fn a_very_quiet_edge_still_gets_a_floor() {
        /* strictly proportional would hand this node a thousandth of the allowance and
           start refusing its own few users */
        let fleet = Fleet::new();
        let now = Instant::now();
        fleet.sync_at(&report("loud", "tight", &[(1, 1000.0)]), now);
        let shares = fleet.sync_at(&report("whisper", "tight", &[(1, 1.0)]), now);
        assert_eq!(shares[0].share, MIN_SHARE);
    }

    #[test]
    fn an_edge_that_stops_reporting_stops_counting() {
        /* otherwise a decommissioned node's traffic keeps shrinking everyone else's share
           forever, throttling real users on behalf of a machine that no longer exists */
        let fleet = Fleet::new();
        let start = Instant::now();
        fleet.sync_at(&report("gone", "tight", &[(1, 50.0)]), start);
        fleet.sync_at(&report("here", "tight", &[(1, 50.0)]), start);

        let later = start + STALE_AFTER + Duration::from_secs(1);
        let shares = fleet.sync_at(&report("here", "tight", &[(1, 50.0)]), later);
        assert_eq!(shares[0].share, 1.0, "the survivor should get the whole limit back");
        assert_eq!(shares[0].edges, 1);
    }

    #[test]
    fn rules_are_counted_separately() {
        let fleet = Fleet::new();
        let now = Instant::now();
        fleet.sync_at(&report("a", "per-ip", &[(1, 50.0)]), now);
        let other = fleet.sync_at(&report("b", "per-token", &[(1, 50.0)]), now);
        /* same key, different rule - they must not pool */
        assert_eq!(other[0].share, 1.0);
        assert_eq!(other[0].edges, 1);
        assert_eq!(fleet.tracked(), 2);
    }

    #[test]
    fn a_negative_rate_cannot_buy_a_bigger_share() {
        let fleet = Fleet::new();
        let now = Instant::now();
        fleet.sync_at(&report("honest", "tight", &[(1, 50.0)]), now);
        let liar = fleet.sync_at(&report("liar", "tight", &[(1, -1000.0)]), now);
        /* clamped to zero, so it gets the floor rather than an enormous share */
        assert_eq!(liar[0].share, MIN_SHARE);
        let honest = fleet.sync_at(&report("honest", "tight", &[(1, 50.0)]), now);
        assert_eq!(honest[0].share, 1.0, "the liar contributed nothing to the total");
    }

    #[test]
    fn a_key_nobody_is_sending_traffic_for_gets_the_whole_limit() {
        let fleet = Fleet::new();
        let shares = fleet.sync(&report("a", "tight", &[(1, 0.0)]));
        assert_eq!(shares[0].share, 1.0);
    }

    #[test]
    fn sweeping_forgets_keys_no_edge_reports_any_more() {
        let fleet = Fleet::new();
        let start = Instant::now();
        fleet.sync_at(&report("a", "tight", &[(1, 5.0), (2, 5.0)]), start);
        assert_eq!(fleet.tracked(), 2);

        assert_eq!(fleet.sweep_at(start + Duration::from_secs(1)), 0, "nothing is stale yet");
        assert_eq!(fleet.tracked(), 2);

        assert_eq!(fleet.sweep_at(start + STALE_AFTER + Duration::from_secs(1)), 2);
        assert_eq!(fleet.tracked(), 0, "the map must not grow forever");
    }

    #[test]
    fn spread_puts_the_most_widely_seen_key_first() {
        /* one address on every edge is a distributed attack; the same volume on one edge
           is one noisy client, and they should not read the same */
        let fleet = Fleet::new();
        let now = Instant::now();
        for edge in ["a", "b", "c"] {
            fleet.sync_at(&report(edge, "tight", &[(99, 10.0)]), now);
        }
        fleet.sync_at(&report("a", "tight", &[(1, 500.0)]), now);

        let spread = fleet.spread(10);
        assert_eq!(spread[0].1, 99, "the key on three edges should lead");
        assert_eq!(spread[0].2, 3);
        assert!((spread[0].3 - 30.0).abs() < 1e-9, "fleet rate should be summed");
        assert_eq!(spread[1].1, 1);
    }
}
