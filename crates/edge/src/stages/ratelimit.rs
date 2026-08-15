//! Rate limiting, plus the response side of the adaptive tier.
//!
//! Sits ahead of the cache: a client hammering one URL should be slowed down even
//! though serving them from cache is cheap, because the point of the limit is the
//! client's behaviour, not our cost.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hyper::{Response, StatusCode};
use tracing::{info, warn};

use crate::body::Body;
use crate::limits::health::Health;
use crate::limits::{key_of, Buckets, RateRule, Subject};
use crate::metrics::Metrics;
use crate::pages;
use crate::pipeline::{Ctx, Stage, StageError, Verdict};
use crate::waf::{Action, Decoded};

pub struct RateLimit {
    buckets: Arc<Buckets>,
    health: Arc<Health>,
    metrics: Arc<Metrics>,
}

impl RateLimit {
    pub fn new(buckets: Arc<Buckets>, health: Arc<Health>, metrics: Arc<Metrics>) -> Self {
        Self {
            buckets,
            health,
            metrics,
        }
    }
}

#[async_trait]
impl Stage for RateLimit {
    fn name(&self) -> &'static str {
        "ratelimit"
    }

    async fn on_request(&self, ctx: &mut Ctx<'_>) -> Result<Verdict, StageError> {
        let zone = ctx.zone;
        if zone.rate_limits.is_empty() {
            return Ok(Verdict::Continue);
        }
        let Some(req) = ctx.req() else {
            return Err(StageError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "500 request went missing before the rate limiter could read it",
            ));
        };

        let factor = self.health.factor(&zone.name, &zone.adaptive);
        /* a gauge rather than a counter: what an alert wants to know is whether this
           zone is tightened right now, not how many times it has been */
        self.metrics.ratelimit_factor.set(&[&zone.name], factor);

        let decoded = Decoded::new(req, &ctx.host, ctx.client, ctx.tls, &ctx.geo, &ctx.bot);
        let input = decoded.input("");

        for rule in &zone.rate_limits {
            if let Some(matcher) = &rule.matcher {
                if !matcher(&input) {
                    continue;
                }
            }
            let Some(subject) = subject_of(rule, ctx) else {
                /* nothing to count by, e.g. a header limit on a request without it */
                continue;
            };

            let verdict = self.buckets.take(
                key_of(&[&rule.id, &subject]),
                &rule.id,
                rule.capacity() * factor,
                rule.refill_per_sec() * factor,
            );
            if verdict.allowed {
                continue;
            }

            match rule.action {
                Action::Log => {
                    self.metrics.ratelimit(&zone.name, &rule.id, "log");
                    info!(
                        "ratelimit log {} {} {} would have been limited",
                        rule.id, ctx.host, subject
                    );
                }
                _ => {
                    self.metrics.ratelimit(&zone.name, &rule.id, "block");
                    warn!(
                        "ratelimit block {} {} {}{} retry in {:?}",
                        rule.id,
                        ctx.host,
                        subject,
                        if factor < 1.0 { " (tightened)" } else { "" },
                        verdict.retry_after
                    );
                    return Ok(Verdict::Respond(limited(verdict.retry_after)));
                }
            }
        }

        Ok(Verdict::Continue)
    }

    /// The adaptive tier's input. Every request that got this far passes back through
    /// here, which makes it the one place that sees both the outcome and the timing.
    async fn on_response(&self, ctx: &mut Ctx<'_>, resp: &mut Response<Body>) {
        self.health.record(
            &ctx.zone.name,
            &ctx.zone.adaptive,
            resp.status(),
            ctx.started.elapsed(),
        );
    }
}

fn subject_of(rule: &RateRule, ctx: &Ctx<'_>) -> Option<String> {
    /* the client, not the peer: behind a load balancer every request shares one peer,
       and a per-ip limit keyed on that is one bucket for the whole internet */
    let ip = ctx.client;
    match &rule.subject {
        Subject::Ip => Some(ip.to_string()),
        Subject::IpPath => {
            let path = ctx.req()?.uri().path();
            Some(format!("{ip}|{path}"))
        }
        Subject::Header(name) => ctx
            .req()?
            .headers()
            .get(name.as_str())
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    }
}

fn limited(retry_after: Duration) -> Response<Body> {
    pages::rate_limited(retry_after.as_secs_f64().ceil() as u64)
}
