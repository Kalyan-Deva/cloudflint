//! The cache: what we store, and the store itself.
//!
//! Sharded so a hot key doesn't serialise every other lookup behind one mutex. Each
//! shard keeps its own byte budget and evicts its own least-recently-used entries.

pub mod inflight;
pub mod policy;
pub mod tee;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::body::Bytes;
use hyper::{HeaderMap, StatusCode};
use lru::LruCache;

const SHARDS: usize = 16;

/// What makes two requests the same request, as far as the cache is concerned.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    pub zone: String,
    pub host: String,
    pub path: String,
    /// Cache-relevant query params, sorted. Tracking junk is already gone.
    pub query: String,
    /// The request headers this zone varies on, flattened.
    pub vary: String,
}

pub struct Entry {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub stored_at: Instant,
    pub fresh_for: Duration,
    /// How long past `fresh_for` we'll serve this while refreshing behind it.
    pub stale_while_revalidate: Duration,
    /// How long past `fresh_for` we'll serve this if the origin is down.
    pub stale_if_error: Duration,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    /// Past its ttl but inside the stale-while-revalidate window.
    Stale,
    Expired,
}

impl Entry {
    pub fn age(&self) -> Duration {
        self.stored_at.elapsed()
    }

    pub fn freshness(&self) -> Freshness {
        let age = self.age();
        if age <= self.fresh_for {
            Freshness::Fresh
        } else if age <= self.fresh_for + self.stale_while_revalidate {
            Freshness::Stale
        } else {
            Freshness::Expired
        }
    }

    /// Expired, but still better than handing the client a 502.
    pub fn usable_on_error(&self) -> bool {
        self.age() <= self.fresh_for + self.stale_if_error
    }

    /// Rough footprint. The body dominates; the rest is a nod to the headers and key.
    pub fn weight(&self) -> usize {
        self.body.len() + 512
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub entries: usize,
    pub bytes: usize,
}

struct Shard {
    lru: LruCache<Key, Arc<Entry>>,
    bytes: usize,
}

pub struct Store {
    shards: Vec<Mutex<Shard>>,
    shard_budget: usize,
    max_object_bytes: usize,
}

impl Store {
    pub fn new(max_bytes: usize, max_object_bytes: usize) -> Self {
        /* a shard always has room for one full-size object, even if that puts the
           total a little over max_bytes - better than an object that can never land */
        let shard_budget = (max_bytes / SHARDS).max(max_object_bytes + 512);

        let shards = (0..SHARDS)
            .map(|_| {
                Mutex::new(Shard {
                    lru: LruCache::unbounded(),
                    bytes: 0,
                })
            })
            .collect();

        Store {
            shards,
            shard_budget,
            max_object_bytes,
        }
    }

    pub fn max_object_bytes(&self) -> usize {
        self.max_object_bytes
    }

    fn shard(&self, key: &Key) -> &Mutex<Shard> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        &self.shards[(hasher.finish() as usize) % SHARDS]
    }

    pub fn get(&self, key: &Key) -> Option<Arc<Entry>> {
        let mut shard = self.shard(key).lock().unwrap();
        shard.lru.get(key).cloned()
    }

    /// Returns false if the object is too big to be worth holding.
    pub fn insert(&self, key: Key, entry: Arc<Entry>) -> bool {
        if entry.body.len() > self.max_object_bytes {
            return false;
        }
        let weight = entry.weight();

        let mut shard = self.shard(&key).lock().unwrap();
        if let Some(old) = shard.lru.put(key, entry) {
            shard.bytes = shard.bytes.saturating_sub(old.weight());
        }
        shard.bytes += weight;

        while shard.bytes > self.shard_budget {
            match shard.lru.pop_lru() {
                Some((_, evicted)) => shard.bytes = shard.bytes.saturating_sub(evicted.weight()),
                None => break,
            }
        }
        true
    }

    pub fn remove(&self, key: &Key) -> bool {
        let mut shard = self.shard(key).lock().unwrap();
        match shard.lru.pop(key) {
            Some(old) => {
                shard.bytes = shard.bytes.saturating_sub(old.weight());
                true
            }
            None => false,
        }
    }

    /// Drop everything the predicate likes. Purges are rare, so a scan is fine.
    pub fn purge_where(&self, pick: impl Fn(&Key, &Entry) -> bool) -> usize {
        let mut removed = 0;
        for shard in &self.shards {
            let mut shard = shard.lock().unwrap();
            let doomed: Vec<Key> = shard
                .lru
                .iter()
                .filter(|(k, e)| pick(k, e))
                .map(|(k, _)| k.clone())
                .collect();

            for key in doomed {
                if let Some(old) = shard.lru.pop(&key) {
                    shard.bytes = shard.bytes.saturating_sub(old.weight());
                    removed += 1;
                }
            }
        }
        removed
    }

    pub fn purge_zone(&self, zone: &str) -> usize {
        self.purge_where(|k, _| k.zone == zone)
    }

    pub fn purge_tag(&self, tag: &str) -> usize {
        self.purge_where(|_, e| e.tags.iter().any(|t| t == tag))
    }

    pub fn purge_all(&self) -> usize {
        self.purge_where(|_, _| true)
    }

    pub fn stats(&self) -> Stats {
        let mut stats = Stats::default();
        for shard in &self.shards {
            let shard = shard.lock().unwrap();
            stats.entries += shard.lru.len();
            stats.bytes += shard.bytes;
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(path: &str) -> Key {
        Key {
            zone: "demo".into(),
            host: "demo.local".into(),
            path: path.into(),
            query: String::new(),
            vary: String::new(),
        }
    }

    fn entry(body_len: usize, ttl_secs: u64) -> Arc<Entry> {
        Arc::new(Entry {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from(vec![b'x'; body_len]),
            stored_at: Instant::now(),
            fresh_for: Duration::from_secs(ttl_secs),
            stale_while_revalidate: Duration::ZERO,
            stale_if_error: Duration::ZERO,
            tags: Vec::new(),
        })
    }

    fn tagged(tags: &[&str]) -> Arc<Entry> {
        let mut e = entry(10, 60);
        Arc::get_mut(&mut e).unwrap().tags = tags.iter().map(|t| t.to_string()).collect();
        e
    }

    #[test]
    fn stores_and_returns() {
        let store = Store::new(1 << 20, 1 << 16);
        assert!(store.insert(key("/a"), entry(100, 60)));

        let got = store.get(&key("/a")).expect("should have been cached");
        assert_eq!(got.body.len(), 100);
        assert!(store.get(&key("/b")).is_none());
        assert_eq!(store.stats().entries, 1);
    }

    #[test]
    fn refuses_objects_over_the_limit() {
        let store = Store::new(1 << 20, 1000);
        assert!(!store.insert(key("/big"), entry(5000, 60)));
        assert!(store.get(&key("/big")).is_none());
    }

    #[test]
    fn replacing_an_entry_does_not_double_count_bytes() {
        let store = Store::new(1 << 20, 1 << 16);
        store.insert(key("/a"), entry(1000, 60));
        let after_first = store.stats().bytes;
        store.insert(key("/a"), entry(1000, 60));

        assert_eq!(store.stats().entries, 1);
        assert_eq!(store.stats().bytes, after_first);
    }

    #[test]
    fn evicts_the_least_recently_used_when_full() {
        /* 6000 bytes per shard: three 1712-byte entries fit, a fourth does not */
        let store = Store::new(SHARDS * 6000, 4096);

        /* everything into one shard so eviction is deterministic */
        let shard_of = |k: &Key| {
            let mut h = DefaultHasher::new();
            k.hash(&mut h);
            (h.finish() as usize) % SHARDS
        };
        let target = shard_of(&key("/0"));
        let mut same_shard: Vec<Key> = Vec::new();
        let mut n = 0;
        while same_shard.len() < 4 {
            let k = key(&format!("/{n}"));
            if shard_of(&k) == target {
                same_shard.push(k);
            }
            n += 1;
        }

        for k in &same_shard[..3] {
            store.insert(k.clone(), entry(1200, 60));
        }
        /* touch the first so the second becomes least-recently-used */
        assert!(store.get(&same_shard[0]).is_some());
        store.insert(same_shard[3].clone(), entry(1200, 60));

        assert!(store.get(&same_shard[0]).is_some(), "recently used entry was evicted");
        assert!(store.get(&same_shard[1]).is_none(), "lru entry should have gone");
        assert!(store.get(&same_shard[2]).is_some());
        assert!(store.get(&same_shard[3]).is_some());
        assert!(store.stats().bytes <= 6000, "shard went over budget");
    }

    #[test]
    fn freshness_moves_through_the_windows() {
        let mut e = Entry {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            stored_at: Instant::now() - Duration::from_secs(10),
            fresh_for: Duration::from_secs(30),
            stale_while_revalidate: Duration::from_secs(60),
            stale_if_error: Duration::from_secs(600),
            tags: Vec::new(),
        };
        assert_eq!(e.freshness(), Freshness::Fresh);

        e.stored_at = Instant::now() - Duration::from_secs(45);
        assert_eq!(e.freshness(), Freshness::Stale);
        assert!(e.usable_on_error());

        e.stored_at = Instant::now() - Duration::from_secs(120);
        assert_eq!(e.freshness(), Freshness::Expired);
        assert!(e.usable_on_error(), "still inside stale-if-error");

        e.stored_at = Instant::now() - Duration::from_secs(1000);
        assert!(!e.usable_on_error());
    }

    #[test]
    fn purges_by_url_tag_and_zone() {
        let store = Store::new(1 << 20, 1 << 16);
        store.insert(key("/a"), tagged(&["home", "nav"]));
        store.insert(key("/b"), tagged(&["nav"]));
        store.insert(key("/c"), tagged(&["other"]));

        assert!(store.remove(&key("/a")));
        assert!(!store.remove(&key("/a")), "second purge of the same url is a no-op");

        assert_eq!(store.purge_tag("nav"), 1);
        assert!(store.get(&key("/b")).is_none());
        assert!(store.get(&key("/c")).is_some());

        let mut elsewhere = key("/c");
        elsewhere.zone = "other-zone".into();
        store.insert(elsewhere.clone(), entry(10, 60));

        assert_eq!(store.purge_zone("demo"), 1);
        assert!(store.get(&elsewhere).is_some(), "other zones are untouched");
        assert_eq!(store.stats().entries, 1);
    }

    #[test]
    fn purging_keeps_the_byte_count_honest() {
        let store = Store::new(1 << 20, 1 << 16);
        for n in 0..20 {
            store.insert(key(&format!("/{n}")), entry(500, 60));
        }
        assert_eq!(store.purge_all(), 20);
        assert_eq!(store.stats(), Stats { entries: 0, bytes: 0 });
    }
}
