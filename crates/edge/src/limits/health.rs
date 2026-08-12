//! The adaptive tier.
//!
//! Watches how the origin is doing and tightens rate limits while it's struggling.
//! The idea is that a fixed limit is tuned for a healthy origin: when the origin is
//! already failing or crawling, the same traffic that was fine yesterday is now
//! making things worse, and the useful response is to let less of it through.
//!
//! Deliberately blunt - counts over a fixed window, one decision per window, one
//! multiplier. Anything cleverer wants traffic history we don't have yet.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hyper::StatusCode;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy)]
pub struct Adaptive {
    pub enabled: bool,
    pub window: Duration,
    /// Don't judge a window with less traffic than this in it.
    pub min_requests: u32,
    pub error_ratio: f64,
    pub slow: Duration,
    pub slow_ratio: f64,
    /// Multiplier applied to every rate limit while strained.
    pub tighten_to: f64,
}

struct ZoneHealth {
    window_start: Instant,
    total: u32,
    errors: u32,
    slow: u32,
    strained: bool,
}

impl ZoneHealth {
    fn new(now: Instant) -> Self {
        ZoneHealth {
            window_start: now,
            total: 0,
            errors: 0,
            slow: 0,
            strained: false,
        }
    }

    /// Close the window if it's over, and decide what the next one starts believing.
    fn roll(&mut self, zone: &str, cfg: &Adaptive, now: Instant) {
        if now.saturating_duration_since(self.window_start) < cfg.window {
            return;
        }

        let was = self.strained;
        self.strained = if self.total >= cfg.min_requests {
            let errors = self.errors as f64 / self.total as f64;
            let slow = self.slow as f64 / self.total as f64;
            errors > cfg.error_ratio || slow > cfg.slow_ratio
        } else {
            /* too little traffic to tell - assume fine rather than punish a quiet zone */
            false
        };

        if self.strained && !was {
            warn!(
                "zone {zone} looks strained ({}/{} errors, {}/{} slow) - rate limits tightened to {:.0}%",
                self.errors,
                self.total,
                self.slow,
                self.total,
                cfg.tighten_to * 100.0
            );
        } else if was && !self.strained {
            info!("zone {zone} recovered - rate limits back to normal");
        }

        self.window_start = now;
        self.total = 0;
        self.errors = 0;
        self.slow = 0;
    }
}

#[derive(Default)]
pub struct Health {
    zones: Mutex<HashMap<String, ZoneHealth>>,
}

impl Health {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, zone: &str, cfg: &Adaptive, status: StatusCode, took: Duration) {
        if !cfg.enabled {
            return;
        }
        let now = Instant::now();
        let mut zones = self.zones.lock().unwrap();
        let health = zones
            .entry(zone.to_owned())
            .or_insert_with(|| ZoneHealth::new(now));

        health.roll(zone, cfg, now);
        health.total += 1;
        if status.is_server_error() {
            health.errors += 1;
        }
        if took >= cfg.slow {
            health.slow += 1;
        }
    }

    /// What to multiply rate limit allowances by right now.
    pub fn factor(&self, zone: &str, cfg: &Adaptive) -> f64 {
        if !cfg.enabled {
            return 1.0;
        }
        let now = Instant::now();
        let mut zones = self.zones.lock().unwrap();
        let Some(health) = zones.get_mut(zone) else {
            return 1.0;
        };
        /* roll here too, so a zone that goes quiet after a bad patch recovers
           instead of staying tightened until the next request arrives */
        health.roll(zone, cfg, now);

        if health.strained {
            cfg.tighten_to.clamp(0.01, 1.0)
        } else {
            1.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Adaptive {
        Adaptive {
            enabled: true,
            window: Duration::from_millis(100),
            min_requests: 10,
            error_ratio: 0.25,
            slow: Duration::from_millis(500),
            slow_ratio: 0.5,
            tighten_to: 0.5,
        }
    }

    fn ok() -> StatusCode {
        StatusCode::OK
    }
    fn boom() -> StatusCode {
        StatusCode::BAD_GATEWAY
    }

    fn feed(h: &Health, cfg: &Adaptive, n: u32, status: StatusCode, took: Duration) {
        for _ in 0..n {
            h.record("demo", cfg, status, took);
        }
    }

    #[tokio::test]
    async fn a_healthy_zone_is_left_alone() {
        let (h, c) = (Health::new(), cfg());
        feed(&h, &c, 50, ok(), Duration::from_millis(5));

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(h.factor("demo", &c), 1.0);
    }

    #[tokio::test]
    async fn errors_tighten_the_limits() {
        let (h, c) = (Health::new(), cfg());
        feed(&h, &c, 20, boom(), Duration::from_millis(5));
        feed(&h, &c, 20, ok(), Duration::from_millis(5));

        /* the verdict lands when the window closes, not before */
        assert_eq!(h.factor("demo", &c), 1.0);

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(h.factor("demo", &c), 0.5);
    }

    #[tokio::test]
    async fn slowness_counts_as_strain_too() {
        let (h, c) = (Health::new(), cfg());
        feed(&h, &c, 40, ok(), Duration::from_millis(900));

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(h.factor("demo", &c), 0.5);
    }

    #[tokio::test]
    async fn a_quiet_zone_is_never_judged() {
        let (h, c) = (Health::new(), cfg());
        /* every single request failed, but there were only three of them */
        feed(&h, &c, 3, boom(), Duration::from_millis(5));

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(h.factor("demo", &c), 1.0);
    }

    #[tokio::test]
    async fn it_lets_go_once_things_recover() {
        let (h, c) = (Health::new(), cfg());
        feed(&h, &c, 40, boom(), Duration::from_millis(5));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(h.factor("demo", &c), 0.5);

        feed(&h, &c, 40, ok(), Duration::from_millis(5));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(h.factor("demo", &c), 1.0);
    }

    #[tokio::test]
    async fn a_zone_that_goes_silent_recovers_on_its_own() {
        let (h, c) = (Health::new(), cfg());
        feed(&h, &c, 40, boom(), Duration::from_millis(5));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(h.factor("demo", &c), 0.5);

        /* no further traffic at all - the next empty window clears it */
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(h.factor("demo", &c), 1.0);
    }

    #[tokio::test]
    async fn zones_are_judged_separately() {
        let (h, c) = (Health::new(), cfg());
        for _ in 0..40 {
            h.record("bad", &c, boom(), Duration::from_millis(5));
            h.record("good", &c, ok(), Duration::from_millis(5));
        }

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(h.factor("bad", &c), 0.5);
        assert_eq!(h.factor("good", &c), 1.0);
    }

    #[tokio::test]
    async fn switching_it_off_switches_it_off() {
        let (h, mut c) = (Health::new(), cfg());
        c.enabled = false;
        feed(&h, &c, 40, boom(), Duration::from_millis(5));

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(h.factor("demo", &c), 1.0);
    }
}
