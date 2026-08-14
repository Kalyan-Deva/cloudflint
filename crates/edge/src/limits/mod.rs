//! Rate limiting: token buckets, connection limits, and the origin-health signal
//! that tightens the buckets when the origin starts struggling.
//!
//! Counters are per node by default. A rule with `scope: global` is divided across the
//! fleet instead - see `global` - by giving each node a share of the limit proportional to
//! the traffic it is seeing for that key. A node that has never been given a share uses
//! all of it, so per-node remains the behaviour when nothing is configured or when the
//! control plane is away.

pub mod conn;
pub mod global;
pub mod health;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use crate::waf;

const SHARDS: usize = 16;

/// What happened when we asked for a token.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    pub allowed: bool,
    /// How long until a token is available. Zero when allowed.
    pub retry_after: Duration,
}

struct Bucket {
    tokens: f64,
    last: Instant,
    /// Requests seen since the last report, for working out this node's rate.
    seen: u32,
    /// This node's slice of a fleet-wide limit, 1.0 until the control plane says
    /// otherwise. A node-scoped rule is never told anything, so it stays 1.0 and the
    /// limit behaves exactly as it always has.
    share: f64,
    /// Which rule this bucket belongs to, so a report can say what is being hit.
    rule: Box<str>,
}

/// Sharded so a hot key doesn't put every other key behind one lock, and bounded so
/// an attacker cycling through source addresses can't grow it without limit - the
/// least recently used keys fall out, which for a rate limiter just means their
/// allowance resets.
pub struct Buckets {
    shards: Vec<Mutex<LruCache<u64, Bucket>>>,
}

impl Buckets {
    pub fn new(max_keys: usize) -> Self {
        let per_shard = NonZeroUsize::new((max_keys / SHARDS).max(64)).expect("non-zero");
        Buckets {
            shards: (0..SHARDS)
                .map(|_| Mutex::new(LruCache::new(per_shard)))
                .collect(),
        }
    }

    /// Take one token. `capacity` doubles as the burst allowance.
    ///
    /// `rule` is only remembered, never compared - the rule is already part of `key`.
    pub fn take(&self, key: u64, rule: &str, capacity: f64, refill_per_sec: f64) -> Verdict {
        let now = Instant::now();

        let mut shard = self.shards[(key as usize) % SHARDS].lock().unwrap();
        let bucket = shard.get_or_insert_mut(key, || Bucket {
            tokens: capacity.max(1.0),
            last: now,
            seen: 0,
            share: 1.0,
            rule: rule.into(),
        });

        /* counted before the verdict, because a refused request is still traffic - and a
           key being refused everywhere is exactly the one the fleet needs to know about */
        bucket.seen = bucket.seen.saturating_add(1);

        /* this node's slice of the limit. capacity floors at one token or a small share
           would refuse everything including the first request */
        let capacity = (capacity * bucket.share).max(1.0);
        let refill_per_sec = (refill_per_sec * bucket.share).max(f64::MIN_POSITIVE);

        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Verdict {
                allowed: true,
                retry_after: Duration::ZERO,
            };
        }

        let short_by = 1.0 - bucket.tokens;
        Verdict {
            allowed: false,
            retry_after: Duration::from_secs_f64(short_by / refill_per_sec),
        }
    }

    /// The busiest keys since the last call, and reset their counters.
    ///
    /// Only heavy hitters are worth sending: a key near its limit is by definition
    /// high-volume, so this captures the ones that matter and leaves the long tail to
    /// local counting, where it was already right.
    pub fn heavy_hitters(&self, top: usize, since: Duration) -> Vec<(Box<str>, u64, f64)> {
        let secs = since.as_secs_f64().max(0.001);
        let mut all = Vec::new();

        for shard in &self.shards {
            let mut shard = shard.lock().unwrap_or_else(|e| e.into_inner());
            for (key, bucket) in shard.iter_mut() {
                let seen = std::mem::take(&mut bucket.seen);
                if seen > 0 {
                    all.push((bucket.rule.clone(), *key, seen as f64 / secs));
                }
            }
        }

        all.sort_by(|a, b| b.2.total_cmp(&a.2));
        all.truncate(top);
        all
    }

    /// Record what the control plane says this node's slice of each key is.
    ///
    /// A key that has since fallen out of the LRU is skipped rather than re-created: it
    /// would come back with a full bucket anyway, and inventing one here would mean a
    /// share applied to traffic nobody is sending.
    pub fn apply_shares(&self, shares: &[(u64, f64)]) {
        for (key, share) in shares {
            let mut shard = self.shards[(*key as usize) % SHARDS]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(bucket) = shard.peek_mut(key) {
                bucket.share = share.clamp(0.0, 1.0);
            }
        }
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }
}

pub fn key_of(parts: &[&str]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    hasher.finish()
}

/// What a limit counts by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    Ip,
    IpPath,
    /// A request header, for per-API-key limits. Requests without it are not limited.
    Header(String),
}

pub struct RateRule {
    pub id: String,
    /// Whether this limit counts on this node alone or across the whole fleet.
    pub scope: crate::config::Scope,
    /// Optional WAF expression scoping the rule to some requests.
    pub matcher: Option<waf::compile::Pred>,
    pub subject: Subject,
    pub requests: u32,
    pub window: Duration,
    pub action: waf::Action,
}

impl RateRule {
    pub fn capacity(&self) -> f64 {
        self.requests as f64
    }

    pub fn refill_per_sec(&self) -> f64 {
        self.requests as f64 / self.window.as_secs_f64().max(0.001)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buckets() -> Buckets {
        Buckets::new(1024)
    }

    #[test]
    fn spends_the_burst_then_refuses() {
        let b = buckets();
        let key = key_of(&["rule", "1.2.3.4"]);

        for n in 0..5 {
            assert!(b.take(key, "test", 5.0, 5.0).allowed, "request {n} should have passed");
        }
        let refused = b.take(key, "test", 5.0, 5.0);
        assert!(!refused.allowed);
        assert!(refused.retry_after > Duration::ZERO);
    }

    #[test]
    fn keys_are_counted_separately() {
        let b = buckets();
        let one = key_of(&["rule", "1.2.3.4"]);
        let two = key_of(&["rule", "5.6.7.8"]);

        for _ in 0..5 {
            b.take(one, "test", 5.0, 5.0);
        }
        assert!(!b.take(one, "test", 5.0, 5.0).allowed);
        assert!(b.take(two, "test", 5.0, 5.0).allowed, "a different ip has its own allowance");
    }

    #[test]
    fn the_same_subject_under_two_rules_does_not_share_a_bucket() {
        let b = buckets();
        let strict = key_of(&["strict", "1.2.3.4"]);
        let loose = key_of(&["loose", "1.2.3.4"]);

        for _ in 0..2 {
            b.take(strict, "test", 2.0, 2.0);
        }
        assert!(!b.take(strict, "test", 2.0, 2.0).allowed);
        assert!(b.take(loose, "test", 2.0, 2.0).allowed);
    }

    #[tokio::test]
    async fn tokens_come_back_over_time() {
        let b = buckets();
        let key = key_of(&["rule", "1.2.3.4"]);
        /* 5 at a time, refilling at 50 a second */
        let (cap, rate) = (5.0, 50.0);

        for _ in 0..5 {
            assert!(b.take(key, "test", cap, rate).allowed);
        }
        assert!(!b.take(key, "test", cap, rate).allowed);

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(b.take(key, "test", cap, rate).allowed, "tokens should have refilled");
    }

    #[tokio::test]
    async fn refill_never_exceeds_the_burst() {
        let b = buckets();
        let key = key_of(&["rule", "1.2.3.4"]);
        let (cap, rate) = (5.0, 50.0);

        b.take(key, "test", cap, rate);
        /* long enough to refill several times over, if it were allowed to */
        tokio::time::sleep(Duration::from_millis(400)).await;

        for _ in 0..5 {
            assert!(b.take(key, "test", cap, rate).allowed);
        }
        assert!(!b.take(key, "test", cap, rate).allowed, "idling is not unlimited credit");
    }

    #[test]
    fn retry_after_points_at_the_next_token() {
        let b = buckets();
        let key = key_of(&["rule", "1.2.3.4"]);

        /* 2 per second */
        b.take(key, "test", 2.0, 2.0);
        b.take(key, "test", 2.0, 2.0);
        let refused = b.take(key, "test", 2.0, 2.0);

        assert!(!refused.allowed);
        assert!(
            refused.retry_after <= Duration::from_millis(600),
            "expected about half a second, got {:?}",
            refused.retry_after
        );
    }

    #[test]
    fn the_table_stays_bounded() {
        let b = Buckets::new(SHARDS * 64);
        for n in 0..50_000 {
            b.take(key_of(&["rule", &n.to_string()]), "test", 5.0, 5.0);
        }
        assert!(
            b.tracked() <= SHARDS * 64,
            "tracked {} keys, which is more than the cap",
            b.tracked()
        );
    }

    /// The adaptive tier changes the capacity of a bucket that already exists. The
    /// leftover balance gets clamped to the new ceiling straight away - it isn't
    /// carried over, and the client isn't retroactively charged for what they already
    /// spent under the looser limit.
    #[test]
    fn tightening_clamps_the_leftover_allowance() {
        let b = buckets();
        let key = key_of(&["rule", "1.2.3.4"]);

        /* one request under a limit of 10 leaves 9 in the bucket */
        assert!(b.take(key, "test", 10.0, 10.0).allowed);

        /* the tier halves it: those 9 become 5, not 9 */
        for n in 0..5 {
            assert!(b.take(key, "test", 5.0, 5.0).allowed, "request {n} should have passed");
        }
        assert!(!b.take(key, "test", 5.0, 5.0).allowed, "the leftover burst was not clamped");
    }
}
