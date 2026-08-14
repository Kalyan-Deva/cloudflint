//! Cloudflint control plane.
//!
//! Owns the config and the analytics. Never sits in anyone's request path: the edge
//! pulls a snapshot from here and then serves traffic entirely from memory, so this
//! process being slow, wedged or missing is a management inconvenience rather than
//! an outage.

pub mod db;
pub mod metrics;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use cloudflint_edge::analytics::Event;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

use crate::db::Db;
use crate::metrics::ApiMetrics;

/// Events older than this are dropped on ingest.
const KEEP_EVENTS: Duration = Duration::from_secs(7 * 24 * 3600);

#[derive(Clone)]
pub struct Api {
    pub db: Db,
    /// Edge admin urls to fan purges out to. Purges have to reach the data plane -
    /// the cache lives there, and this process can only ask.
    pub edges: Arc<Vec<String>>,
    /// The token this process presents to those edges. Their admin API is guarded
    /// too, so asking politely is not enough.
    pub edge_token: Option<Arc<String>>,
    pub metrics: Arc<ApiMetrics>,
}

impl Api {
    pub fn new(db: Db, edges: Vec<String>, edge_token: Option<Arc<String>>) -> Self {
        Api {
            db,
            edges: Arc::new(edges),
            edge_token,
            metrics: ApiMetrics::new(),
        }
    }
}

pub fn router(api: Api) -> Router {
    /* health is the only thing outside the fence, so an orchestrator can probe it
       without holding a credential. everything that reads or changes anything is
       behind a token. */
    let guarded = Router::new()
        .route("/v1/config", get(get_config).put(put_config))
        .route("/v1/config/revisions", get(list_revisions))
        .route("/v1/config/revisions/{id}/activate", post(activate))
        .route("/v1/events", post(ingest))
        .route("/v1/analytics/summary", get(summary))
        .route("/v1/analytics/timeseries", get(timeseries))
        .route("/v1/zones", get(zones))
        .route("/v1/edges", get(list_edges))
        .route("/v1/edges/{id}", axum::routing::delete(forget_edge))
        .route("/v1/edges/{id}/heartbeat", post(heartbeat))
        .route("/v1/waf/test", post(waf_test))
        .route("/v1/purge", post(purge))
        .route("/v1/tokens", get(list_tokens).post(mint_token))
        .route("/v1/tokens/{id}", axum::routing::delete(revoke_token))
        .route_layer(axum::middleware::from_fn_with_state(api.clone(), require_token));

    /* the same call as the edge makes about its own /metrics, and for the same
       reasons - see cloudflint_edge::admin */
    let scrape = Router::new().route("/metrics", get(metrics));
    let scrape = match metrics_are_open() {
        true => scrape,
        false => scrape.route_layer(axum::middleware::from_fn_with_state(
            api.clone(),
            require_token,
        )),
    };

    Router::new()
        .route("/health", get(health))
        .merge(guarded)
        .merge(scrape)
        .with_state(api)
}

fn metrics_are_open() -> bool {
    matches!(
        std::env::var(cloudflint_edge::admin::METRICS_OPEN_VAR).as_deref(),
        Ok("1") | Ok("true")
    )
}

/// A Prometheus scrape of the management path. The traffic numbers are the edge's.
async fn metrics(State(api): State<Api>) -> impl IntoResponse {
    /* a scrape must not be able to fail: an unreadable database is exactly when
       somebody is looking at this, so it reports what it can and leaves the revision
       out rather than answering 500 */
    let revision = api.db.active_config().ok().flatten().map(|c| c.revision);
    let fleet = api
        .db
        .edges(revision, OFFLINE_AFTER_S, now_ms())
        .ok()
        .map(|edges| crate::metrics::Fleet {
            healthy: edges.iter().filter(|e| e.status == "healthy").count(),
            degraded: edges.iter().filter(|e| e.status == "degraded").count(),
            outdated: edges.iter().filter(|e| e.status == "outdated").count(),
            config_mismatch: edges.iter().filter(|e| e.status == "config_mismatch").count(),
            offline: edges.iter().filter(|e| e.status == "offline").count(),
            up_to_date: edges.iter().filter(|e| e.up_to_date).count(),
            /* summed from what each node last said, not measured here - an offline node
               contributes nothing, which is the honest answer */
            requests_per_sec: edges
                .iter()
                .filter(|e| e.status != "offline")
                .map(|e| e.requests_per_sec)
                .sum(),
        });
    let body = api.metrics.render(revision, api.edges.len(), fleet);

    (
        [(axum::http::header::CONTENT_TYPE, cloudflint_edge::metrics::CONTENT_TYPE)],
        body,
    )
}

/// Every guarded route goes through here first.
async fn require_token(
    State(api): State<Api>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, Problem> {
    let Some(token) = cloudflint_edge::auth::bearer(req.headers()) else {
        return Err(Problem(
            StatusCode::UNAUTHORIZED,
            "a bearer token is required".into(),
        ));
    };

    match api.db.token_holder(token, now_ms()) {
        Ok(Some(name)) => {
            tracing::debug!("request authorised as `{name}`");
            Ok(next.run(req).await)
        }
        Ok(None) => Err(Problem(
            StatusCode::UNAUTHORIZED,
            "that token is not recognised".into(),
        )),
        Err(e) => Err(internal(e)),
    }
}

#[derive(Deserialize)]
pub struct MintToken {
    pub name: String,
}

/// Mint a token. The secret is in the response and never stored, so this is the only
/// time anyone will see it.
async fn mint_token(State(api): State<Api>, Json(body): Json<MintToken>) -> ApiResult {
    if body.name.trim().is_empty() {
        return Err(bad_request("a token needs a name, so it can be recognised later"));
    }
    let token = cloudflint_edge::auth::generate();
    let id = api
        .db
        .add_token(body.name.trim(), &token, now_ms())
        .map_err(internal)?;

    info!("token `{}` minted", body.name.trim());
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "name": body.name.trim(),
            "token": token,
            "note": "this is the only time this token is shown - only its hash is stored"
        })),
    )
        .into_response())
}

async fn list_tokens(State(api): State<Api>) -> ApiResult {
    Ok(Json(api.db.tokens().map_err(internal)?).into_response())
}

async fn revoke_token(State(api): State<Api>, Path(id): Path<i64>) -> ApiResult {
    match api.db.revoke_token(id).map_err(internal)? {
        true => Ok(Json(json!({ "revoked": id })).into_response()),
        false => Err(Problem(StatusCode::NOT_FOUND, format!("no token {id}"))),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

type ApiResult = Result<axum::response::Response, Problem>;

/// An error with a status and a sentence, rendered as json.
pub struct Problem(StatusCode, String);

impl IntoResponse for Problem {
    fn into_response(self) -> axum::response::Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad_request(e: impl std::fmt::Display) -> Problem {
    Problem(StatusCode::BAD_REQUEST, format!("{e:#}"))
}

fn internal(e: impl std::fmt::Display) -> Problem {
    Problem(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

async fn get_config(State(api): State<Api>) -> ApiResult {
    match api.db.active_config().map_err(internal)? {
        Some(active) => Ok(Json(active).into_response()),
        None => Err(Problem(
            StatusCode::NOT_FOUND,
            "no config has been uploaded yet".into(),
        )),
    }
}

#[derive(Deserialize)]
pub struct PutConfig {
    pub yaml: String,
    #[serde(default)]
    pub note: String,
}

async fn put_config(State(api): State<Api>, Json(body): Json<PutConfig>) -> ApiResult {
    /* validated with the edge's own parser, so this can never hand out a config the
       data plane would refuse - the failure lands here, at write time, not out
       there at reload time */
    let id = api
        .db
        .put_config(&body.yaml, &body.note, now_ms())
        .map_err(bad_request)?;

    api.metrics.config_writes.inc(&["stored"]);
    info!("config revision {id} stored and made active");
    Ok((StatusCode::CREATED, Json(json!({ "revision": id }))).into_response())
}

#[derive(Deserialize)]
pub struct Limit {
    #[serde(default)]
    pub limit: Option<usize>,
}

async fn list_revisions(State(api): State<Api>, Query(q): Query<Limit>) -> ApiResult {
    let revisions = api
        .db
        .revisions(q.limit.unwrap_or(50).min(500))
        .map_err(internal)?;
    Ok(Json(revisions).into_response())
}

async fn activate(State(api): State<Api>, Path(id): Path<i64>) -> ApiResult {
    api.db.activate(id).map_err(bad_request)?;
    api.metrics.config_writes.inc(&["rolled_back"]);
    info!("config revision {id} activated");
    Ok(Json(json!({ "revision": id })).into_response())
}

async fn ingest(State(api): State<Api>, Json(events): Json<Vec<Event>>) -> ApiResult {
    if events.is_empty() {
        return Ok(Json(json!({ "stored": 0 })).into_response());
    }
    let stored = api.db.insert_events(&events).map_err(internal)?;
    api.metrics.events.add(&[], stored as u64);

    let cutoff = now_ms() - KEEP_EVENTS.as_millis() as i64;
    if let Err(e) = api.db.prune_events(cutoff) {
        warn!("could not prune old events: {e}");
    }
    Ok(Json(json!({ "stored": stored })).into_response())
}

#[derive(Deserialize)]
pub struct SummaryQuery {
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub since_mins: Option<i64>,
}

async fn summary(State(api): State<Api>, Query(q): Query<SummaryQuery>) -> ApiResult {
    let since = now_ms() - q.since_mins.unwrap_or(60).clamp(1, 60 * 24 * 30) * 60_000;
    let summary = api
        .db
        .summary(q.zone.as_deref(), since)
        .map_err(internal)?;
    Ok(Json(summary).into_response())
}

#[derive(Deserialize)]
pub struct SeriesQuery {
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub since_mins: Option<i64>,
    #[serde(default)]
    pub buckets: Option<i64>,
}

async fn timeseries(State(api): State<Api>, Query(q): Query<SeriesQuery>) -> ApiResult {
    let mins = q.since_mins.unwrap_or(60).clamp(1, 60 * 24 * 30);
    let since = now_ms() - mins * 60_000;
    let series = api
        .db
        .timeseries(q.zone.as_deref(), since, q.buckets.unwrap_or(60))
        .map_err(internal)?;
    Ok(Json(json!({ "since_mins": mins, "buckets": series })).into_response())
}

#[derive(Debug, Serialize)]
pub struct ZoneView {
    pub name: String,
    pub hostnames: Vec<String>,
    /// The first origin. Kept so anything reading one origin still works.
    pub origin: String,
    pub origins: Vec<String>,
    pub origin_strategy: &'static str,
    /// The probe path, when active health checks are on.
    pub origin_probe: Option<String>,
    pub preserve_host: bool,
    pub origin_timeout_ms: u64,
    pub waf_rules: Vec<String>,
    pub waf_reads_body: bool,
    pub cache_enabled: bool,
    pub cache_vary_on: Vec<String>,
    pub cache_overrides: Vec<String>,
    pub rate_limits: Vec<String>,
    pub adaptive: bool,
}

/// The active config, read back as structure rather than yaml, so the dashboard
/// doesn't have to parse it and can't disagree with the edge about what it means.
async fn zones(State(api): State<Api>) -> ApiResult {
    let Some(active) = api.db.active_config().map_err(internal)? else {
        return Err(Problem(
            StatusCode::NOT_FOUND,
            "no config has been uploaded yet".into(),
        ));
    };
    let cfg = cloudflint_edge::config::parse(&active.yaml).map_err(internal)?;

    let views: Vec<ZoneView> = cfg
        .zones
        .iter()
        .map(|z| ZoneView {
            name: z.name.clone(),
            hostnames: z.hostnames.clone(),
            /* the first origin, for anything that only has room for one */
            origin: z.origins.urls().first().cloned().unwrap_or_default(),
            origins: z.origins.urls(),
            origin_strategy: z.origins.strategy.as_str(),
            origin_probe: z.origins.probe.as_ref().map(|p| p.path.clone()),
            preserve_host: z.origins.first().preserve_host,
            origin_timeout_ms: z.origins.first().timeout.as_millis() as u64,
            waf_rules: z.waf.rules.rule_ids().iter().map(|s| s.to_string()).collect(),
            waf_reads_body: z.waf.rules.needs_body(),
            cache_enabled: z.cache.enabled,
            cache_vary_on: z.cache.vary_on.clone(),
            cache_overrides: z
                .cache
                .overrides
                .iter()
                .map(|o| format!("{} for {}s", o.path_prefix, o.ttl.as_secs()))
                .collect(),
            rate_limits: z
                .rate_limits
                .iter()
                .map(|r| format!("{}: {}/{}s", r.id, r.requests, r.window.as_secs()))
                .collect(),
            adaptive: z.adaptive.enabled,
        })
        .collect();

    Ok(Json(json!({ "revision": active.revision, "zones": views })).into_response())
}

/// How long after its last heartbeat a node is called offline.
///
/// Three intervals: one missed beat is a lost packet or a busy moment, three in a row is
/// a node that has stopped talking. The interval is the edge's setting, so this is
/// expressed in seconds and defaults to three times the default.
const OFFLINE_AFTER_S: i64 = 45;

/// A node reporting in. This both registers it and records the sample.
///
/// The id in the path has to match the one in the body: they can only differ if
/// something is confused about which node this is, and guessing which to believe would
/// be how one node's numbers end up filed under another's name.
async fn heartbeat(
    State(api): State<Api>,
    Path(id): Path<String>,
    Json(beat): Json<cloudflint_edge::fleet::Heartbeat>,
) -> ApiResult {
    if beat.edge_id != id {
        return Err(bad_request(format!(
            "this heartbeat is addressed to `{id}` but says it is from `{}`",
            beat.edge_id
        )));
    }
    if beat.edge_id.trim().is_empty() {
        return Err(bad_request("an edge needs an id"));
    }

    let known = api.db.record_heartbeat(&beat, now_ms());
    if let Err(e) = known {
        return Err(internal(e));
    }
    api.metrics.heartbeats.inc(&[]);

    /* the answer is the whole rollout mechanism: the node learns what it is supposed to
       be running, and reports next time whether it got there */
    let desired = api.db.active_config().ok().flatten().map(|c| c.revision);
    Ok(Json(json!({ "desired_revision": desired })).into_response())
}

async fn list_edges(State(api): State<Api>) -> ApiResult {
    let desired = api.db.active_config().map_err(internal)?.map(|c| c.revision);
    let edges = api
        .db
        .edges(desired, OFFLINE_AFTER_S, now_ms())
        .map_err(internal)?;

    /* counted here rather than in the browser so the numbers on the page and the
       numbers in a scrape come from the same place */
    let count = |status: &str| edges.iter().filter(|e| e.status == status).count();

    Ok(Json(json!({
        "desired_revision": desired,
        "offline_after_s": OFFLINE_AFTER_S,
        "newest_version": crate::db::newest_version(
            edges
                .iter()
                .filter(|e| e.status != "offline")
                .map(|e| e.version.clone()),
        ),
        "counts": {
            "total": edges.len(),
            "healthy": count("healthy"),
            "degraded": count("degraded"),
            "outdated": count("outdated"),
            "config_mismatch": count("config_mismatch"),
            "offline": count("offline"),
            "up_to_date": edges.iter().filter(|e| e.up_to_date).count(),
        },
        "regions": regions_of(&edges),
        "edges": edges,
    }))
    .into_response())
}

/// Per region, because a fleet view that cannot tell you a whole POP is dark is not
/// worth having.
///
/// "Healthy" here is the strict sense - a region whose nodes are all up but all running
/// last week's config is not a region anybody should see a green number for.
fn regions_of(edges: &[crate::db::EdgeView]) -> Vec<serde_json::Value> {
    let mut seen: Vec<(String, usize, usize)> = Vec::new();
    for edge in edges {
        let name = edge.region.clone().unwrap_or_else(|| "unlabelled".into());
        let healthy = (edge.status == "healthy") as usize;
        match seen.iter_mut().find(|(r, _, _)| *r == name) {
            Some((_, total, ok)) => {
                *total += 1;
                *ok += healthy;
            }
            None => seen.push((name, 1, healthy)),
        }
    }
    seen.sort_by(|a, b| a.0.cmp(&b.0));
    seen.into_iter()
        .map(|(region, total, healthy)| {
            json!({ "region": region, "total": total, "healthy": healthy })
        })
        .collect()
}

async fn forget_edge(State(api): State<Api>, Path(id): Path<String>) -> ApiResult {
    match api.db.forget_edge(&id).map_err(internal)? {
        true => {
            info!("edge `{id}` forgotten");
            Ok(Json(json!({ "forgotten": id })).into_response())
        }
        false => Err(Problem(StatusCode::NOT_FOUND, format!("no edge `{id}`"))),
    }
}

#[derive(Deserialize)]
pub struct WafTest {
    pub zone: String,
    /// Test unsaved rules by passing the yaml; omit to use the active config.
    #[serde(default)]
    pub yaml: Option<String>,
    #[serde(default = "get_method")]
    pub method: String,
    #[serde(default = "root")]
    pub path: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default = "example_ip")]
    pub ip: String,
    /// Pretend the request arrived over https, for rules that check `ssl`.
    #[serde(default)]
    pub tls: bool,
}

fn get_method() -> String {
    "GET".into()
}
fn root() -> String {
    "/".into()
}
fn example_ip() -> String {
    "203.0.113.9".into()
}

/// Run a made-up request against a zone's rules and report everything it touches.
///
/// This is the whole reason the control plane links the edge crate: the answer here
/// has to be the answer the edge would give, not a second implementation that drifts.
async fn waf_test(State(api): State<Api>, Json(t): Json<WafTest>) -> ApiResult {
    use cloudflint_edge::waf::{decode, Input};

    let yaml = match t.yaml {
        Some(yaml) => yaml,
        None => {
            api.db
                .active_config()
                .map_err(internal)?
                .ok_or_else(|| Problem(StatusCode::NOT_FOUND, "no config yet".into()))?
                .yaml
        }
    };
    let cfg = cloudflint_edge::config::parse(&yaml).map_err(bad_request)?;
    let zone = cfg
        .zones
        .iter()
        .find(|z| z.name == t.zone)
        .ok_or_else(|| bad_request(format!("no zone called `{}`", t.zone)))?;

    let mut headers = hyper::HeaderMap::new();
    for (name, value) in &t.headers {
        let name = hyper::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| bad_request(format!("bad header name `{name}`")))?;
        let value = hyper::header::HeaderValue::from_str(value)
            .map_err(|_| bad_request(format!("bad header value for `{name}`")))?;
        headers.append(name, value);
    }
    let ip = t
        .ip
        .parse()
        .map_err(|_| bad_request(format!("`{}` is not an ip address", t.ip)))?;

    /* decoded exactly as the edge decodes it, or the tester would lie */
    let path = decode(&t.path, false);
    let query = decode(&t.query, true);
    let raw_uri = if t.query.is_empty() {
        t.path.clone()
    } else {
        format!("{}?{}", t.path, t.query)
    };
    let uri = decode(&raw_uri, true);

    let explained = zone.waf.rules.explain(
        &Input {
            method: &t.method,
            uri: &uri,
            path: &path,
            query: &query,
            host: zone.hostnames.first().map(|s| s.as_str()).unwrap_or(""),
            body: &t.body,
            headers: &headers,
            ip,
            tls: t.tls,
        },
        !t.body.is_empty(),
    );

    Ok(Json(explained).into_response())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeRequest {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub all: bool,
}

#[derive(Debug, Serialize)]
pub struct EdgeResult {
    pub edge: String,
    pub ok: bool,
    pub detail: String,
}

async fn purge(State(api): State<Api>, Json(ask): Json<PurgeRequest>) -> ApiResult {
    let set = [ask.url.is_some(), ask.tag.is_some(), ask.zone.is_some(), ask.all]
        .iter()
        .filter(|x| **x)
        .count();
    if set != 1 {
        return Err(bad_request("give exactly one of url, tag, zone or all"));
    }
    if api.edges.is_empty() {
        return Err(Problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "no edges are configured to purge".into(),
        ));
    }

    let body = serde_json::to_vec(&ask).map_err(internal)?;
    let mut results = Vec::with_capacity(api.edges.len());
    for edge in api.edges.iter() {
        results.push(ask_edge(edge, &body, api.edge_token.as_deref()).await);
    }

    /* report per edge rather than collapsing to one status: "mostly purged" is a
       thing that happens, and hiding it would be worse than saying so */
    let all_ok = results.iter().all(|r| r.ok);
    api.metrics.purges.inc(&[match (all_ok, results.iter().any(|r| r.ok)) {
        (true, _) => "ok",
        (false, true) => "partial",
        (false, false) => "failed",
    }]);
    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::MULTI_STATUS
    };
    Ok((status, Json(json!({ "edges": results }))).into_response())
}

async fn ask_edge(base: &str, body: &[u8], token: Option<&String>) -> EdgeResult {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let url = format!("{}/admin/purge", base.trim_end_matches('/'));

    let mut req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(&url)
        .header("content-type", "application/json");

    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let req = req.body(Full::new(Bytes::copy_from_slice(body)));

    let Ok(req) = req else {
        return EdgeResult {
            edge: base.to_owned(),
            ok: false,
            detail: "bad edge url".into(),
        };
    };

    match client.request(req).await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp
                .into_body()
                .collect()
                .await
                .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
                .unwrap_or_default();
            EdgeResult {
                edge: base.to_owned(),
                ok: status.is_success(),
                detail: body,
            }
        }
        Err(e) => EdgeResult {
            edge: base.to_owned(),
            ok: false,
            detail: format!("unreachable: {e}"),
        },
    }
}
