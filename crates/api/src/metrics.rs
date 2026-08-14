//! What the control plane counts about itself.
//!
//! Deliberately thin. The interesting numbers about traffic are the edge's, and asking
//! this process for them would mean asking the database, on a timer, forever. What is
//! worth scraping here is whether the management path is working: is it up, is it
//! taking config, is it taking events, are purges reaching the edges.

use std::sync::Arc;
use std::time::Instant;

use cloudflint_edge::metrics::{self, Counter};

/// Fleet totals, read at scrape time like everything else that lives elsewhere.
#[derive(Debug, Clone, Copy, Default)]
pub struct Fleet {
    pub healthy: usize,
    pub degraded: usize,
    pub outdated: usize,
    pub config_mismatch: usize,
    pub offline: usize,
    pub up_to_date: usize,
    pub requests_per_sec: f64,
}

pub struct ApiMetrics {
    pub started: Instant,
    pub events: Counter,
    pub config_writes: Counter,
    pub purges: Counter,
    pub heartbeats: Counter,
}

impl ApiMetrics {
    /// Shared straight away - the router clones its state per request.
    pub fn new() -> Arc<Self> {
        Arc::new(ApiMetrics {
            started: Instant::now(),
            events: Counter::new(
                "cloudflint_api_events_ingested_total",
                "Request events accepted from edges.",
                &[],
            ),
            config_writes: Counter::new(
                "cloudflint_api_config_writes_total",
                "Config revisions stored or activated, by what happened.",
                &["kind"],
            ),
            purges: Counter::new(
                "cloudflint_api_purges_total",
                "Purges fanned out to edges, by whether every edge agreed.",
                &["outcome"],
            ),
            heartbeats: Counter::new(
                "cloudflint_api_heartbeats_total",
                "Heartbeats accepted from edges.",
                &[],
            ),
        })
    }

    /// The scrape body. Same format as the edge's, and the same rule: counters come
    /// from the registry, everything else is read where it lives.
    ///
    /// `fleet` is None when the database could not be read. A scrape must not fail just
    /// because one of its numbers is unavailable - an unreadable database is exactly when
    /// somebody is looking at this - so the series is left out instead.
    pub fn render(&self, revisions: Option<i64>, edges: usize, fleet: Option<Fleet>) -> String {
        let mut out = String::with_capacity(1024);
        self.events.render_into(&mut out);
        self.config_writes.render_into(&mut out);
        self.purges.render_into(&mut out);
        self.heartbeats.render_into(&mut out);

        if let Some(fleet) = fleet {
            metrics::labelled_gauges(
                &mut out,
                "cloudflint_fleet_edges",
                "Edges known to this control plane, by derived status.",
                "status",
                &[
                    ("healthy", fleet.healthy as f64),
                    ("degraded", fleet.degraded as f64),
                    ("outdated", fleet.outdated as f64),
                    ("config_mismatch", fleet.config_mismatch as f64),
                    ("offline", fleet.offline as f64),
                ],
            );
            metrics::gauge(
                &mut out,
                "cloudflint_fleet_edges_up_to_date",
                "Edges serving the config revision the fleet is meant to be on.",
                fleet.up_to_date as f64,
            );
            metrics::gauge(
                &mut out,
                "cloudflint_fleet_requests_per_second",
                "Requests per second across the fleet, as last reported by each node.",
                fleet.requests_per_sec,
            );
        }

        metrics::gauge(
            &mut out,
            "cloudflint_api_uptime_seconds",
            "Seconds since this control plane started.",
            self.started.elapsed().as_secs_f64(),
        );
        metrics::gauge(
            &mut out,
            "cloudflint_api_edges_configured",
            "Edge admin urls this control plane will fan purges out to.",
            edges as f64,
        );
        if let Some(revision) = revisions {
            metrics::gauge(
                &mut out,
                "cloudflint_api_active_revision",
                "Id of the config revision the edges are being served.",
                revision as f64,
            );
        }
        metrics::labelled_gauge(
            &mut out,
            "cloudflint_api_build_info",
            "Always 1; the version is in the label.",
            &[("version", env!("CARGO_PKG_VERSION"))],
            1.0,
        );
        out
    }
}
