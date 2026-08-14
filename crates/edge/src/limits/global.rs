//! The edge half of fleet-wide rate limiting.
//!
//! Every `interval` this reports the busiest keys belonging to `global`-scoped rules and
//! stores the share the control plane hands back. Nothing here is on the request path: the
//! request path only ever reads the share already sitting on the bucket, and a share it has
//! never been given is 1.0 - which is exactly per-node limiting.
//!
//! So the failure modes are all the harmless direction. Control plane down: shares stop
//! being updated and eventually every bucket is back to its full local limit. Control plane
//! slow: the report waits, the request path does not. Node just started: full limit until
//! the first sync, one interval away.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::Scope;
use crate::cp::ControlPlane;
use crate::limits::Buckets;
use crate::snapshot::Snapshot;

/// How many keys one report carries. The control plane refuses more than 512, and a node
/// with more hot keys than this has bigger problems than limit precision.
const TOP_KEYS: usize = 256;

/// What we send. Mirrors `cloudflint_api::ratelimit::Report` - deliberately duplicated
/// rather than shared, because the edge crate must not depend on the control plane crate
/// (the dependency runs the other way).
#[derive(Debug, Serialize)]
struct Report<'a> {
    edge_id: &'a str,
    rule: &'a str,
    keys: Vec<Observed>,
}

#[derive(Debug, Serialize)]
struct Observed {
    key: u64,
    rate: f64,
}

#[derive(Debug, Deserialize)]
struct Answer {
    #[serde(default)]
    shares: Vec<Share>,
}

#[derive(Debug, Deserialize)]
struct Share {
    key: u64,
    share: f64,
}

/// Report heavy hitters and apply shares, for as long as this process lives.
pub fn spawn(
    snap: Arc<Snapshot>,
    buckets: Arc<Buckets>,
    base: String,
    edge_id: String,
    interval: Duration,
) {
    let cp = match ControlPlane::from_env(&base) {
        Ok(cp) => cp,
        Err(e) => {
            warn!("global rate limits disabled, cannot reach the control plane: {e:#}");
            return;
        }
    };
    info!("global rate limits: reporting to {base} every {interval:?}");

    tokio::spawn(async move {
        let mut last_err = String::new();

        loop {
            tokio::time::sleep(interval).await;

            /* which rules are fleet-wide is read fresh each time, so switching a rule to
               global takes effect on the next tick rather than needing a restart */
            let global: Vec<String> = snap
                .current()
                .zones
                .iter()
                .flat_map(|z| z.rate_limits.iter())
                .filter(|r| r.scope == Scope::Global)
                .map(|r| r.id.clone())
                .collect();

            /* drained unconditionally, even with no global rules: the counters are per
               interval, and leaving them to accumulate would make the first report after
               someone enables a global rule wildly overstate the rate */
            let hitters = buckets.heavy_hitters(TOP_KEYS, interval);
            if global.is_empty() {
                continue;
            }

            /* one report per rule, because that is how the control plane totals them -
               the same key under two rules is two different limits */
            for rule in &global {
                let keys: Vec<Observed> = hitters
                    .iter()
                    .filter(|(r, _, _)| r.as_ref() == rule.as_str())
                    .map(|(_, key, rate)| Observed { key: *key, rate: *rate })
                    .collect();

                if keys.is_empty() {
                    continue;
                }
                let count = keys.len();

                match sync(&cp, &edge_id, rule, keys).await {
                    Ok(shares) => {
                        if !last_err.is_empty() {
                            info!("control plane reachable again, shares resumed");
                            last_err.clear();
                        }
                        debug!("global limits: {count} keys reported for `{rule}`");
                        buckets.apply_shares(&shares);
                    }
                    Err(e) => {
                        /* the same message every tick would drown the log for as long as
                           the control plane is away, which could be a long time */
                        if e != last_err {
                            warn!(
                                "global rate limits: {e} - falling back to per-node limits \
                                 until this clears"
                            );
                            last_err = e;
                        }
                    }
                }
            }
        }
    });
}

async fn sync(
    cp: &ControlPlane,
    edge_id: &str,
    rule: &str,
    keys: Vec<Observed>,
) -> Result<Vec<(u64, f64)>, String> {
    let report = Report {
        edge_id,
        rule,
        keys,
    };
    let body = serde_json::to_vec(&report).map_err(|e| format!("could not encode: {e}"))?;
    let answer = cp
        .post("/v1/ratelimit/sync", body)
        .await
        .map_err(|e| format!("{e:#}"))?;

    let answer: Answer = serde_json::from_slice(&answer)
        .map_err(|e| format!("the control plane sent something unexpected: {e}"))?;

    Ok(answer.shares.into_iter().map(|s| (s.key, s.share)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::key_of;

    #[test]
    fn a_report_round_trips_through_json() {
        let report = Report {
            edge_id: "edge-1",
            rule: "tight",
            keys: vec![Observed { key: 7, rate: 12.5 }],
        };
        let text = serde_json::to_string(&report).unwrap();
        assert!(text.contains("\"edge_id\":\"edge-1\""), "{text}");
        assert!(text.contains("\"rule\":\"tight\""), "{text}");
        assert!(text.contains("\"key\":7"), "{text}");
    }

    #[test]
    fn an_answer_without_shares_parses() {
        /* a control plane too old to know about shares should not break the sync */
        let answer: Answer = serde_json::from_str("{}").unwrap();
        assert!(answer.shares.is_empty());
    }

    #[test]
    fn shares_are_read_back_in_the_form_buckets_wants() {
        let answer: Answer =
            serde_json::from_str(r#"{"shares":[{"key":7,"share":0.25,"edges":4}]}"#).unwrap();
        let pairs: Vec<(u64, f64)> = answer.shares.into_iter().map(|s| (s.key, s.share)).collect();
        assert_eq!(pairs, vec![(7, 0.25)]);
    }

    #[test]
    fn a_share_actually_shrinks_the_local_allowance() {
        /* the property the whole feature rests on: after the control plane says "you get a
           quarter", this node stops allowing the full limit */
        let buckets = Buckets::new(1024);
        let key = key_of(&["tight", "1.2.3.4"]);

        /* full limit first: 20 tokens means 20 requests */
        let mut allowed = 0;
        for _ in 0..40 {
            if buckets.take(key, "tight", 20.0, 20.0).allowed {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 20, "the full limit should allow its whole burst");

        /* now a quarter share, on a fresh key so the bucket starts full */
        let key = key_of(&["tight", "5.6.7.8"]);
        buckets.take(key, "tight", 20.0, 20.0);
        buckets.apply_shares(&[(key, 0.25)]);

        let mut allowed = 0;
        for _ in 0..40 {
            if buckets.take(key, "tight", 20.0, 20.0).allowed {
                allowed += 1;
            }
        }
        assert!(
            allowed <= 6,
            "a quarter share should allow about a quarter of the burst, allowed {allowed}"
        );
    }

    #[test]
    fn a_key_never_given_a_share_keeps_the_whole_limit() {
        /* this is what makes it safe to enable: no share means today's behaviour */
        let buckets = Buckets::new(1024);
        let key = key_of(&["tight", "9.9.9.9"]);
        let mut allowed = 0;
        for _ in 0..40 {
            if buckets.take(key, "tight", 20.0, 20.0).allowed {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 20);
    }

    #[test]
    fn heavy_hitters_reports_rates_and_resets() {
        let buckets = Buckets::new(1024);
        let hot = key_of(&["tight", "hot"]);
        let cold = key_of(&["tight", "cold"]);

        for _ in 0..30 {
            buckets.take(hot, "tight", 1000.0, 1000.0);
        }
        buckets.take(cold, "tight", 1000.0, 1000.0);

        let hitters = buckets.heavy_hitters(10, Duration::from_secs(2));
        assert_eq!(hitters.len(), 2);
        /* busiest first, and the rate is per second over the interval */
        assert_eq!(hitters[0].1, hot);
        assert!((hitters[0].2 - 15.0).abs() < 1e-9, "rate was {}", hitters[0].2);
        assert_eq!(hitters[1].1, cold);

        /* and the counters reset, or the next report would double-count */
        assert!(
            buckets.heavy_hitters(10, Duration::from_secs(2)).is_empty(),
            "counters should have been drained"
        );
    }

    #[test]
    fn only_the_busiest_keys_are_kept() {
        let buckets = Buckets::new(4096);
        for n in 0..50 {
            let key = key_of(&["tight", &n.to_string()]);
            for _ in 0..=n {
                buckets.take(key, "tight", 1000.0, 1000.0);
            }
        }

        let hitters = buckets.heavy_hitters(5, Duration::from_secs(1));
        assert_eq!(hitters.len(), 5);
        /* the top five by rate, in order */
        assert!(hitters[0].2 > hitters[4].2);
        assert!((hitters[0].2 - 50.0).abs() < 1e-9, "rate was {}", hitters[0].2);
    }
}
