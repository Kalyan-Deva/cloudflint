//! Where request events go.
//!
//! Two destinations, neither of which a request ever waits on: a small in-memory ring
//! the admin API can read back, and a bounded channel feeding a task that ships
//! batches to the control plane. When the channel is full events are dropped and
//! counted. That is the whole point - analytics are the first thing that should
//! suffer under load, not the traffic they describe.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

/// How many events wait to be shipped before we start dropping them.
const QUEUE: usize = 8192;
/// Biggest batch we'll put in one request.
const BATCH: usize = 500;
const FLUSH_EVERY: Duration = Duration::from_secs(1);
const RECENT: usize = 500;
/// Backlog a live watcher can fall behind by before it starts missing events.
const LIVE: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub at_ms: u64,
    pub zone: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_us: u64,
    /// Which stage produced the response: route, ratelimit, waf, cache or origin.
    pub decided_by: String,
    /// HIT / MISS / STALE / BYPASS, when the cache had an opinion.
    pub cache: Option<String>,
    pub client_ip: String,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct Sink {
    tx: Option<mpsc::Sender<Event>>,
    /// Live tap for the dashboard. Nothing is sent unless somebody is watching.
    live: broadcast::Sender<Event>,
    recent: Mutex<VecDeque<Event>>,
    dropped: AtomicU64,
    seen: AtomicU64,
}

impl Sink {
    /// Off by default: with no control plane we still keep the ring, so the admin
    /// API is useful on a standalone edge.
    pub fn new(control_plane: Option<String>) -> Arc<Self> {
        let (tx, rx) = match &control_plane {
            Some(_) => {
                let (tx, rx) = mpsc::channel(QUEUE);
                (Some(tx), Some(rx))
            }
            None => (None, None),
        };

        let sink = Arc::new(Sink {
            tx,
            live: broadcast::channel(LIVE).0,
            recent: Mutex::new(VecDeque::with_capacity(RECENT)),
            dropped: AtomicU64::new(0),
            seen: AtomicU64::new(0),
        });

        if let (Some(url), Some(rx)) = (control_plane, rx) {
            tokio::spawn(ship(url, rx));
        }
        sink
    }

    /// Watch events as they happen. A slow watcher misses events rather than
    /// slowing anything down.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.live.subscribe()
    }

    pub fn record(&self, event: Event) {
        self.seen.fetch_add(1, Ordering::Relaxed);
        if self.live.receiver_count() > 0 {
            let _ = self.live.send(event.clone());
        }
        {
            let mut recent = self.recent.lock().unwrap();
            if recent.len() == RECENT {
                recent.pop_front();
            }
            recent.push_back(event.clone());
        }

        if let Some(tx) = &self.tx {
            /* try_send, never send - a request must not wait on analytics */
            if tx.try_send(event).is_err() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<Event> {
        let recent = self.recent.lock().unwrap();
        recent.iter().rev().take(limit).cloned().collect()
    }

    pub fn counts(&self) -> (u64, u64) {
        (
            self.seen.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }
}

async fn ship(url: String, mut rx: mpsc::Receiver<Event>) {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let endpoint = format!("{}/v1/events", url.trim_end_matches('/'));
    let mut batch: Vec<Event> = Vec::with_capacity(BATCH);
    let mut ticker = tokio::time::interval(FLUSH_EVERY);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            got = rx.recv() => match got {
                Some(event) => {
                    batch.push(event);
                    if batch.len() >= BATCH {
                        post(&client, &endpoint, &mut batch).await;
                    }
                }
                None => break,
            },
            _ = ticker.tick() => post(&client, &endpoint, &mut batch).await,
        }
    }
    post(&client, &endpoint, &mut batch).await;
}

async fn post(
    client: &Client<HttpConnector, Full<Bytes>>,
    endpoint: &str,
    batch: &mut Vec<Event>,
) {
    if batch.is_empty() {
        return;
    }
    let count = batch.len();
    let body = match serde_json::to_vec(&*batch) {
        Ok(body) => body,
        Err(e) => {
            warn!("analytics: could not encode {count} events: {e}");
            batch.clear();
            return;
        }
    };
    /* a failed flush is dropped rather than retried. holding a growing backlog of
       old events would cost more than the events are worth */
    batch.clear();

    let req = Request::builder()
        .method(Method::POST)
        .uri(endpoint)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)));

    let Ok(req) = req else {
        warn!("analytics: bad endpoint {endpoint}");
        return;
    };

    match client.request(req).await {
        Ok(resp) if resp.status().is_success() => {
            let _ = resp.into_body().collect().await;
            debug!("analytics: shipped {count} events");
        }
        Ok(resp) => warn!("analytics: control plane answered {}", resp.status()),
        Err(e) => warn!("analytics: could not reach the control plane: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(path: &str) -> Event {
        Event {
            at_ms: now_ms(),
            zone: "demo".into(),
            host: "demo.local".into(),
            method: "GET".into(),
            path: path.into(),
            status: 200,
            duration_us: 1234,
            decided_by: "origin".into(),
            cache: Some("MISS".into()),
            client_ip: "203.0.113.9".into(),
        }
    }

    #[tokio::test]
    async fn keeps_the_most_recent_events_newest_first() {
        let sink = Sink::new(None);
        for n in 0..5 {
            sink.record(event(&format!("/{n}")));
        }

        let recent = sink.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].path, "/4");
        assert_eq!(recent[2].path, "/2");
    }

    #[tokio::test]
    async fn the_ring_does_not_grow_without_limit() {
        let sink = Sink::new(None);
        for n in 0..(RECENT + 250) {
            sink.record(event(&format!("/{n}")));
        }

        assert_eq!(sink.recent(usize::MAX).len(), RECENT);
        let (seen, dropped) = sink.counts();
        assert_eq!(seen, (RECENT + 250) as u64);
        assert_eq!(dropped, 0, "with no control plane there is nothing to drop");
    }

    #[tokio::test]
    async fn events_are_dropped_rather_than_queued_forever() {
        /* nothing is draining the channel, so it fills and then sheds */
        let sink = Sink::new(Some("http://127.0.0.1:1".into()));
        for n in 0..(QUEUE + 1000) {
            sink.record(event(&format!("/{n}")));
        }

        let (seen, dropped) = sink.counts();
        assert_eq!(seen, (QUEUE + 1000) as u64);
        assert!(dropped > 0, "a full queue should have shed events");
    }

    #[test]
    fn an_event_survives_a_round_trip_through_json() {
        let json = serde_json::to_string(&event("/a")).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, "/a");
        assert_eq!(back.cache.as_deref(), Some("MISS"));
    }
}
