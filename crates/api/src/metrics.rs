//! What the control plane counts about itself.
//!
//! Deliberately thin. The interesting numbers about traffic are the edge's, and asking
//! this process for them would mean asking the database, on a timer, forever. What is
//! worth scraping here is whether the management path is working: is it up, is it
//! taking config, is it taking events, are purges reaching the edges.

use std::sync::Arc;
use std::time::Instant;

use cloudflint_edge::metrics::{self, Counter};

pub struct ApiMetrics {
    pub started: Instant,
    pub events: Counter,
    pub config_writes: Counter,
    pub purges: Counter,
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
        })
    }

    /// The scrape body. Same format as the edge's, and the same rule: counters come
    /// from the registry, everything else is read where it lives.
    pub fn render(&self, revisions: Option<i64>, edges: usize) -> String {
        let mut out = String::with_capacity(1024);
        self.events.render_into(&mut out);
        self.config_writes.render_into(&mut out);
        self.purges.render_into(&mut out);

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
