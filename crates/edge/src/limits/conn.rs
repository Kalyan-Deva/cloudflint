//! Connection limits, applied at accept time.
//!
//! These run before a single byte of HTTP is parsed, which is the point: slowloris
//! and its relatives don't send a complete request, so anything that waits for one
//! has already lost. Capping how many connections one address can hold, and how fast
//! it can open them, blunts that regardless of what the connections go on to do.
//!
//! Node-wide rather than per zone, because at accept time we don't know the zone yet.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use super::{key_of, Buckets};
use crate::metrics::Metrics;

pub struct ConnLimits {
    /// 0 means no cap.
    max_per_ip: u32,
    new_per_sec: f64,
    rate: Buckets,
    live: Mutex<HashMap<IpAddr, u32>>,
    /// Counting connections belongs here because this is what already sees every
    /// accept and every close - the guard's lifetime *is* the connection's.
    metrics: Option<Arc<Metrics>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    TooMany,
    TooFast,
}

/// Holds a slot for as long as the connection lives.
pub struct ConnGuard {
    limits: Arc<ConnLimits>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(metrics) = &self.limits.metrics {
            metrics.connection_closed();
        }
        let mut live = match self.limits.live.lock() {
            Ok(live) => live,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(count) = live.get_mut(&self.ip) {
            *count -= 1;
            /* drop the entry entirely, or the map grows with every address seen */
            if *count == 0 {
                live.remove(&self.ip);
            }
        }
    }
}

impl ConnLimits {
    pub fn new(max_per_ip: u32, new_per_sec: u32) -> Self {
        ConnLimits {
            max_per_ip,
            new_per_sec: new_per_sec as f64,
            rate: Buckets::new(4096),
            live: Mutex::new(HashMap::new()),
            metrics: None,
        }
    }

    /// The same limits, counting what they see.
    pub fn metered(max_per_ip: u32, new_per_sec: u32, metrics: Arc<Metrics>) -> Self {
        ConnLimits {
            metrics: Some(metrics),
            ..Self::new(max_per_ip, new_per_sec)
        }
    }

    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<ConnGuard, Refusal> {
        if self.new_per_sec > 0.0 {
            let key = key_of(&["conn", &ip.to_string()]);
            /* one second of connections is also the burst */
            if !self.rate.take(key, "conn", self.new_per_sec, self.new_per_sec).allowed {
                return Err(self.refuse(Refusal::TooFast));
            }
        }

        if self.max_per_ip > 0 {
            let mut live = self.live.lock().unwrap();
            let count = live.entry(ip).or_insert(0);
            if *count >= self.max_per_ip {
                return Err(self.refuse(Refusal::TooMany));
            }
            *count += 1;
        }

        if let Some(metrics) = &self.metrics {
            metrics.connection_opened();
        }
        Ok(ConnGuard {
            limits: self.clone(),
            ip,
        })
    }

    fn refuse(&self, why: Refusal) -> Refusal {
        if let Some(metrics) = &self.metrics {
            metrics.connections_refused.inc(&[match why {
                Refusal::TooMany => "too_many",
                Refusal::TooFast => "too_fast",
            }]);
        }
        why
    }

    #[cfg(test)]
    fn held_by(&self, ip: IpAddr) -> u32 {
        self.live.lock().unwrap().get(&ip).copied().unwrap_or(0)
    }

    #[cfg(test)]
    fn tracked_ips(&self) -> usize {
        self.live.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn caps_concurrent_connections_per_address() {
        let limits = Arc::new(ConnLimits::new(3, 0));
        let addr = ip("203.0.113.9");

        let held: Vec<_> = (0..3)
            .map(|n| limits.admit(addr).unwrap_or_else(|_| panic!("connection {n} refused")))
            .collect();

        assert!(matches!(limits.admit(addr), Err(Refusal::TooMany)));
        assert_eq!(limits.held_by(addr), 3);

        drop(held);
        assert_eq!(limits.held_by(addr), 0);
        assert!(limits.admit(addr).is_ok(), "slots should free up again");
    }

    #[test]
    fn one_address_cannot_starve_another() {
        let limits = Arc::new(ConnLimits::new(2, 0));
        let noisy = ip("203.0.113.9");
        let quiet = ip("198.51.100.4");

        let _held: Vec<_> = (0..2).map(|_| limits.admit(noisy).unwrap()).collect();

        assert!(limits.admit(noisy).is_err());
        assert!(limits.admit(quiet).is_ok());
    }

    #[test]
    fn caps_how_fast_connections_can_be_opened() {
        let limits = Arc::new(ConnLimits::new(0, 5));
        let addr = ip("203.0.113.9");

        /* dropped straight away, so concurrency is never the reason */
        for n in 0..5 {
            assert!(limits.admit(addr).is_ok(), "connection {n} should have been allowed");
        }
        assert!(matches!(limits.admit(addr), Err(Refusal::TooFast)));
    }

    #[test]
    fn zero_means_no_cap() {
        let limits = Arc::new(ConnLimits::new(0, 0));
        let addr = ip("203.0.113.9");

        let held: Vec<_> = (0..500).map(|_| limits.admit(addr).unwrap()).collect();
        assert_eq!(held.len(), 500);
    }

    #[test]
    fn the_live_table_does_not_grow_forever() {
        let limits = Arc::new(ConnLimits::new(4, 0));

        for n in 0..1000 {
            let addr = ip(&format!("10.0.{}.{}", n / 256, n % 256));
            let guard = limits.admit(addr).unwrap();
            drop(guard);
        }
        assert_eq!(limits.tracked_ips(), 0, "closed connections should leave nothing behind");
    }
}
