//! Cache stage.
//!
//! On a miss this stage goes to the origin itself rather than waving the request on,
//! so the whole miss path - coalescing, storing, falling back to stale - lives in one
//! place instead of being smeared across two stages and a response filter.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use hyper::body::Bytes;
use hyper::header::{HeaderValue, AGE};
use hyper::{Request, Response, StatusCode};
use tracing::{debug, warn};

use crate::body::{full, Body};
use crate::cache::inflight::{Inflight, Join, Leader};
use crate::cache::policy::{self, CachePolicy};
use crate::cache::tee::tee;
use crate::cache::{Entry, Freshness, Key, Store};
use crate::pipeline::{Ctx, Stage, StageError, Verdict};
use crate::stages::origin::Fetcher;

/// Header we report the cache decision in. Handy in a browser, and the integration
/// tests lean on it heavily.
const STATUS_HEADER: &str = "cloudveil-cache";

/// Origin responses that count as "the origin is having a bad time" for the purposes
/// of stale-if-error (RFC 5861).
const ERROR_STATUS: &[u16] = &[500, 502, 503, 504];

pub struct Cache {
    store: Arc<Store>,
    inflight: Arc<Inflight>,
    fetcher: Arc<Fetcher>,
}

impl Cache {
    pub fn new(store: Arc<Store>, fetcher: Arc<Fetcher>) -> Self {
        Self {
            store,
            inflight: Arc::new(Inflight::new()),
            fetcher,
        }
    }
}

#[async_trait]
impl Stage for Cache {
    fn name(&self) -> &'static str {
        "cache"
    }

    async fn on_request(&self, ctx: &mut Ctx<'_>) -> Result<Verdict, StageError> {
        let policy = &ctx.zone.cache;
        if !policy.enabled {
            return Ok(Verdict::Continue);
        }
        let Some(req) = ctx.req() else {
            return Err(gone());
        };
        if !policy::request_cacheable(req) || crate::stages::origin::is_upgrade(req.headers()) {
            /* the origin stage handles it, and marks nothing. an upgrade in
               particular must not be labelled or stored - it stops being http */
            return Ok(Verdict::Continue);
        }

        let key = policy::build_key(&ctx.zone.name, &ctx.host, req, policy);

        if let Some(entry) = self.store.get(&key) {
            match entry.freshness() {
                Freshness::Fresh => return Ok(Verdict::Respond(serve(&entry, "HIT"))),
                Freshness::Stale => {
                    self.revalidate_behind(ctx, &key, policy);
                    return Ok(Verdict::Respond(serve(&entry, "STALE")));
                }
                /* expired, but keep it around - it may still beat a 502 */
                Freshness::Expired => {}
            }
        }

        self.miss(ctx, key, policy).await
    }
}

impl Cache {
    async fn miss(
        &self,
        ctx: &mut Ctx<'_>,
        key: Key,
        policy: &CachePolicy,
    ) -> Result<Verdict, StageError> {
        let leader = match self.inflight.join(&key, policy.coalesce_wait).await {
            Join::Leader(leader) => Some(leader),
            Join::Waited => {
                /* whoever led may have filled it in while we waited */
                if let Some(entry) = self.store.get(&key) {
                    if entry.freshness() == Freshness::Fresh {
                        return Ok(Verdict::Respond(serve(&entry, "HIT")));
                    }
                }
                None
            }
        };

        let Some(req) = ctx.take_req() else {
            return Err(gone());
        };
        let fetched = self
            .fetcher
            .fetch(
                &ctx.zone.name,
                &ctx.zone.origin,
                &ctx.host,
                ctx.peer,
                ctx.tls,
                req,
            )
            .await;

        /* an origin usually fails by answering 503, not by refusing the connection,
           so stale-if-error has to cover both or it almost never fires */
        let trouble = match &fetched {
            Err(e) => Some(e.detail.clone()),
            Ok(resp) if ERROR_STATUS.contains(&resp.status().as_u16()) => {
                Some(format!("origin returned {}", resp.status()))
            }
            Ok(_) => None,
        };

        if let Some(why) = trouble {
            if let Some(stale) = self.store.get(&key) {
                if stale.usable_on_error() {
                    warn!(
                        "{} {}: {why}, serving a {}s old copy",
                        ctx.host,
                        key.path,
                        stale.age().as_secs()
                    );
                    return Ok(Verdict::Respond(serve(&stale, "STALE-ERROR")));
                }
            }
        }

        let resp = fetched?;

        Ok(Verdict::Respond(self.store_and_serve(resp, key, policy, leader)))
    }

    /// Decide whether to keep the response, and either way hand it straight on.
    fn store_and_serve(
        &self,
        resp: Response<Body>,
        key: Key,
        policy: &CachePolicy,
        leader: Option<Leader>,
    ) -> Response<Body> {
        let ttl = policy::response_ttl(resp.status(), resp.headers(), &key.path, policy);

        let Some(ttl) = ttl else {
            /* leader drops here, so anyone waiting stops waiting */
            return labelled(resp, "BYPASS");
        };

        let (mut parts, body) = resp.into_parts();
        let tags = policy::tags(&parts.headers);
        /* origin bookkeeping, not the client's business */
        parts.headers.remove(policy::TAG_HEADER);

        let status = parts.status;
        let headers = parts.headers.clone();
        let store = self.store.clone();

        let body = tee(body, self.store.max_object_bytes(), move |bytes: Bytes| {
            let stored = store.insert(
                key,
                Arc::new(Entry {
                    status,
                    headers,
                    body: bytes,
                    stored_at: Instant::now(),
                    fresh_for: ttl.fresh_for,
                    stale_while_revalidate: ttl.stale_while_revalidate,
                    stale_if_error: ttl.stale_if_error,
                    tags,
                }),
            );
            /* only now do the waiters get woken, so they find the entry rather than
               racing us back to the origin */
            drop(leader);
            debug!("cache store: {stored}");
        });

        labelled(Response::from_parts(parts, body), "MISS")
    }

    /// Refresh a stale entry without making the client wait for it.
    fn revalidate_behind(&self, ctx: &Ctx<'_>, key: &Key, _policy: &CachePolicy) {
        /* if a refresh is already running, one is enough */
        let Some(leader) = self.inflight.try_lead(key) else {
            return;
        };
        let Some(req) = ctx.req() else { return };

        let mut builder = Request::builder().method(hyper::Method::GET).uri(req.uri());
        for (name, value) in req.headers() {
            builder = builder.header(name, value);
        }
        let Ok(replay) = builder.body(full("")) else {
            return;
        };

        let fetcher = self.fetcher.clone();
        let store = self.store.clone();
        let origin = ctx.zone.origin.clone();
        let host = ctx.host.clone();
        let peer = ctx.peer;
        let tls = ctx.tls;
        let key = key.clone();
        let path = key.path.clone();
        let ttl_policy = ctx.zone.cache.clone();
        let zone = ctx.zone.name.clone();

        tokio::spawn(async move {
            let _leader = leader;
            let resp = match fetcher.fetch(&zone, &origin, &host, peer, tls, replay).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("{host} {path}: background revalidation failed: {}", e.detail);
                    return;
                }
            };

            let Some(ttl) = policy::response_ttl(resp.status(), resp.headers(), &path, &ttl_policy)
            else {
                /* it stopped being cacheable - drop what we had rather than keep
                   serving something the origin no longer wants cached */
                store.remove(&key);
                return;
            };

            let (parts, body) = resp.into_parts();
            let tags = policy::tags(&parts.headers);
            let status = parts.status;
            let mut headers = parts.headers;
            headers.remove(policy::TAG_HEADER);

            let max = store.max_object_bytes();
            let collected = collect_capped(body, max).await;
            let Some(bytes) = collected else { return };

            store.insert(
                key,
                Arc::new(Entry {
                    status,
                    headers,
                    body: bytes,
                    stored_at: Instant::now(),
                    fresh_for: ttl.fresh_for,
                    stale_while_revalidate: ttl.stale_while_revalidate,
                    stale_if_error: ttl.stale_if_error,
                    tags,
                }),
            );
            debug!("{host} {path}: revalidated");
        });
    }
}

/// Nobody is waiting on this one, so it can be read straight into memory.
async fn collect_capped(body: Body, limit: usize) -> Option<Bytes> {
    use http_body_util::BodyExt;

    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        if let Ok(data) = frame.into_data() {
            if buf.len() + data.len() > limit {
                return None;
            }
            buf.extend_from_slice(&data);
        }
    }
    Some(Bytes::from(buf))
}

fn serve(entry: &Entry, label: &str) -> Response<Body> {
    let mut resp = Response::new(full(entry.body.clone()));
    *resp.status_mut() = entry.status;
    *resp.headers_mut() = entry.headers.clone();

    if let Ok(age) = HeaderValue::from_str(&entry.age().as_secs().to_string()) {
        resp.headers_mut().insert(AGE, age);
    }
    labelled(resp, label)
}

fn labelled(mut resp: Response<Body>, label: &str) -> Response<Body> {
    if let Ok(value) = HeaderValue::from_str(label) {
        resp.headers_mut().insert(STATUS_HEADER, value);
    }
    resp
}

fn gone() -> StageError {
    StageError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "500 request went missing before the cache could read it",
    )
}

