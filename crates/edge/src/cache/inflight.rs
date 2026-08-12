//! Request coalescing.
//!
//! 500 simultaneous misses on one key must produce one origin fetch, not 500. Without
//! this a cold cache turns the first spike of traffic into a self-inflicted DDoS on
//! the origin - which is exactly when the origin can least afford it.
//!
//! One request per key becomes the leader and goes to the origin. The rest wait for
//! it, then look in the cache again. Nobody waits forever: past `wait_for` they give
//! up and fetch for themselves, so a wedged leader degrades to today's behaviour
//! rather than hanging every request behind it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use super::Key;

#[derive(Default)]
pub struct Inflight {
    map: Mutex<HashMap<Key, Arc<Notify>>>,
}

pub enum Join {
    /// You go to the origin. Hold the guard until the entry is stored.
    Leader(Leader),
    /// Someone else already did. Look in the cache again.
    Waited,
}

/// Releases the key and wakes the waiters when dropped - including on error, or if
/// the response body never finishes, which is the whole reason it's a guard.
pub struct Leader {
    inflight: Arc<Inflight>,
    key: Key,
    notify: Arc<Notify>,
}

impl Drop for Leader {
    fn drop(&mut self) {
        if let Ok(mut map) = self.inflight.map.lock() {
            map.remove(&self.key);
        }
        self.notify.notify_waiters();
    }
}

impl Inflight {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the key if it's free, otherwise don't wait around. Used by background
    /// revalidation, where piling up is worse than skipping.
    pub fn try_lead(self: &Arc<Self>, key: &Key) -> Option<Leader> {
        let mut map = self.map.lock().unwrap();
        if map.contains_key(key) {
            return None;
        }
        let notify = Arc::new(Notify::new());
        map.insert(key.clone(), notify.clone());
        Some(Leader {
            inflight: self.clone(),
            key: key.clone(),
            notify,
        })
    }

    pub async fn join(self: &Arc<Self>, key: &Key, wait_for: Duration) -> Join {
        let notify = {
            let mut map = self.map.lock().unwrap();
            match map.get(key) {
                Some(existing) => existing.clone(),
                None => {
                    let notify = Arc::new(Notify::new());
                    map.insert(key.clone(), notify.clone());
                    return Join::Leader(Leader {
                        inflight: self.clone(),
                        key: key.clone(),
                        notify,
                    });
                }
            }
        };

        let notified = notify.notified();
        tokio::pin!(notified);
        /* register before checking the map again: if the leader finishes after this
           point it will wake us, and if it finished before, the key is already gone.
           Without both halves there's a window where we'd wait for a notification
           that has already been sent. */
        notified.as_mut().enable();

        if !self.map.lock().unwrap().contains_key(key) {
            return Join::Waited;
        }

        let _ = tokio::time::timeout(wait_for, notified).await;
        Join::Waited
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn key(path: &str) -> Key {
        Key {
            zone: "demo".into(),
            host: "demo.local".into(),
            path: path.into(),
            query: String::new(),
            vary: String::new(),
        }
    }

    #[tokio::test]
    async fn one_leader_per_key() {
        let inflight = Arc::new(Inflight::new());

        let first = inflight.join(&key("/a"), Duration::from_millis(50)).await;
        assert!(matches!(first, Join::Leader(_)));

        /* a different key is unaffected */
        let other = inflight.join(&key("/b"), Duration::from_millis(50)).await;
        assert!(matches!(other, Join::Leader(_)));

        /* the same key waits, then gives up because the leader never finishes */
        let waiter = inflight.join(&key("/a"), Duration::from_millis(20)).await;
        assert!(matches!(waiter, Join::Waited));
    }

    #[tokio::test]
    async fn dropping_the_leader_releases_the_key() {
        let inflight = Arc::new(Inflight::new());
        let leader = inflight.join(&key("/a"), Duration::from_millis(50)).await;
        assert_eq!(inflight.len(), 1);

        drop(leader);
        assert_eq!(inflight.len(), 0);

        /* the next request through gets to lead */
        assert!(matches!(
            inflight.join(&key("/a"), Duration::from_millis(50)).await,
            Join::Leader(_)
        ));
    }

    #[tokio::test]
    async fn a_herd_produces_one_fetch() {
        let inflight = Arc::new(Inflight::new());
        let fetches = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();
        for _ in 0..200 {
            let inflight = inflight.clone();
            let fetches = fetches.clone();
            let done = done.clone();
            tasks.push(tokio::spawn(async move {
                match inflight.join(&key("/hot"), Duration::from_secs(5)).await {
                    Join::Leader(leader) => {
                        fetches.fetch_add(1, Ordering::SeqCst);
                        /* stand in for an origin round trip */
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        drop(leader);
                    }
                    Join::Waited => {}
                }
                done.fetch_add(1, Ordering::SeqCst);
            }));
        }

        for t in tasks {
            t.await.unwrap();
        }

        assert_eq!(fetches.load(Ordering::SeqCst), 1, "the origin should have been hit once");
        assert_eq!(done.load(Ordering::SeqCst), 200, "every waiter should have been woken");
        assert_eq!(inflight.len(), 0);
    }

    #[tokio::test]
    async fn a_leader_that_panics_still_wakes_the_waiters() {
        let inflight = Arc::new(Inflight::new());

        let leader = inflight.join(&key("/a"), Duration::from_secs(5)).await;
        let boom = tokio::spawn(async move {
            let _guard = leader;
            panic!("origin fetch fell over");
        });

        /* would sit here for the full 5s if the guard hadn't released on unwind */
        let waiter = tokio::time::timeout(
            Duration::from_secs(1),
            inflight.join(&key("/a"), Duration::from_secs(5)),
        )
        .await;

        assert!(waiter.is_ok(), "waiter was left hanging by a panicking leader");
        assert!(boom.await.is_err());
    }

    #[tokio::test]
    async fn try_lead_does_not_queue_up() {
        let inflight = Arc::new(Inflight::new());
        let held = inflight.try_lead(&key("/a")).expect("first should lead");

        assert!(inflight.try_lead(&key("/a")).is_none(), "should not have queued");

        drop(held);
        assert!(inflight.try_lead(&key("/a")).is_some());
    }
}
