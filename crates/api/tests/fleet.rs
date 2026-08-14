//! The fleet: nodes reporting in, and what the control plane makes of them.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use cloudflint_api::db::Db;
use cloudflint_api::{router, Api};
use cloudflint_edge::fleet::{CertState, Heartbeat, NO_REVISION};
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "cfl_fleet_test_token";

fn app() -> axum::Router {
    let db = Db::open(":memory:").expect("in-memory db");
    db.add_token("tests", TOKEN, 0).expect("token should store");
    router(Api::new(db, Vec::new(), None))
}

async fn call(app: &axum::Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"));
    let req = match body {
        Some(value) => req
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&value).unwrap()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };

    let resp = app.clone().oneshot(req).await.expect("router should answer");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn beat(edge_id: &str) -> Heartbeat {
    Heartbeat {
        edge_id: edge_id.into(),
        region: Some("lhr".into()),
        label: Some("test node".into()),
        version: "0.1.0".into(),
        started_at_ms: now_ms() - 60_000,
        uptime_s: 60,
        active_revision: NO_REVISION,
        draining: false,
        cpu_percent: 3.5,
        memory_bytes: 64 * 1024 * 1024,
        memory_total_bytes: 16 * 1024 * 1024 * 1024,
        connections_active: 4,
        requests_total: 1000,
        requests_per_sec: 12.5,
        cache_entries: 7,
        cache_bytes: 4096,
        zones: 1,
        origins_total: 2,
        origins_healthy: 2,
        certificates: vec![CertState {
            zone: "demo".into(),
            mode: "acme".into(),
            status: "valid".into(),
            deployed: true,
            not_after_ms: Some(now_ms() as i64 + 30 * 86_400_000),
        }],
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn as_json(beat: &Heartbeat) -> Value {
    serde_json::to_value(beat).unwrap()
}

fn config_for(zone: &str) -> String {
    format!(
        "zones:\n  - name: {zone}\n    hostnames: [\"{zone}.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n"
    )
}

#[tokio::test]
async fn a_heartbeat_registers_a_node_that_was_never_enrolled() {
    /* registration is not a separate step: a node that can report in is in the fleet.
       that is what makes a replaced control plane heal itself */
    let app = app();
    let (status, _) = call(
        &app,
        "POST",
        "/v1/edges/edge-1/heartbeat",
        Some(as_json(&beat("edge-1"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["counts"]["total"], 1);
    assert_eq!(body["counts"]["healthy"], 1);
    assert_eq!(body["edges"][0]["edge_id"], "edge-1");
    assert_eq!(body["edges"][0]["region"], "lhr");
    assert_eq!(body["edges"][0]["version"], "0.1.0");
    assert_eq!(body["edges"][0]["status"], "healthy");
}

#[tokio::test]
async fn everything_the_node_reported_comes_back_out() {
    let app = app();
    call(&app, "POST", "/v1/edges/e/heartbeat", Some(as_json(&beat("e")))).await;

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    let edge = &body["edges"][0];
    assert_eq!(edge["cpu_percent"], 3.5);
    assert_eq!(edge["memory_bytes"], 64 * 1024 * 1024_i64);
    assert_eq!(edge["connections_active"], 4);
    assert_eq!(edge["requests_per_sec"], 12.5);
    assert_eq!(edge["cache_entries"], 7);
    assert_eq!(edge["cache_bytes"], 4096);
    assert_eq!(edge["origins_healthy"], 2);
    assert_eq!(edge["label"], "test node");
    /* certificates go in as json and must come back as structure, not as a string */
    assert_eq!(edge["certificates"][0]["zone"], "demo");
    assert_eq!(edge["certificates"][0]["mode"], "acme");
    assert!(edge["certificates"][0]["deployed"].as_bool().unwrap());
}

#[tokio::test]
async fn heartbeats_replace_rather_than_accumulate() {
    let app = app();
    for n in 0..4 {
        let mut b = beat("edge-1");
        b.requests_total = 100 * n;
        call(&app, "POST", "/v1/edges/edge-1/heartbeat", Some(as_json(&b))).await;
    }

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(body["counts"]["total"], 1, "one node, however often it reports");
    assert_eq!(body["edges"][0]["requests_total"], 300);
}

#[tokio::test]
async fn a_heartbeat_addressed_to_someone_else_is_refused() {
    /* believing either half would file one node's numbers under another's name */
    let app = app();
    let (status, body) = call(
        &app,
        "POST",
        "/v1/edges/edge-1/heartbeat",
        Some(as_json(&beat("edge-2"))),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("edge-2"),
        "the error should name the mismatch, got {body}"
    );
}

#[tokio::test]
async fn the_ack_names_the_revision_the_node_should_be_running() {
    let app = app();
    /* no config yet, so there is nothing to be on */
    let (_, body) = call(&app, "POST", "/v1/edges/e/heartbeat", Some(as_json(&beat("e")))).await;
    assert!(body["desired_revision"].is_null());

    call(
        &app,
        "PUT",
        "/v1/config",
        Some(json!({ "yaml": config_for("demo") })),
    )
    .await;

    let (_, body) = call(&app, "POST", "/v1/edges/e/heartbeat", Some(as_json(&beat("e")))).await;
    assert_eq!(body["desired_revision"], 1, "the ack is how a rollout is driven");
}

#[tokio::test]
async fn a_node_behind_on_config_is_a_config_mismatch_and_says_why() {
    let app = app();
    call(&app, "PUT", "/v1/config", Some(json!({ "yaml": config_for("a") }))).await;
    call(&app, "PUT", "/v1/config", Some(json!({ "yaml": config_for("b") }))).await;

    let mut behind = beat("edge-1");
    behind.active_revision = 1;
    call(&app, "POST", "/v1/edges/edge-1/heartbeat", Some(as_json(&behind))).await;

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    let edge = &body["edges"][0];
    assert_eq!(edge["status"], "config_mismatch");
    assert!(!edge["up_to_date"].as_bool().unwrap());
    let note = edge["note"].as_str().unwrap();
    assert!(note.contains('1') && note.contains('2'), "note was {note}");
    assert_eq!(body["counts"]["config_mismatch"], 1);
    assert_eq!(body["counts"]["up_to_date"], 0);
}

#[tokio::test]
async fn a_node_on_the_desired_revision_is_up_to_date() {
    let app = app();
    call(&app, "PUT", "/v1/config", Some(json!({ "yaml": config_for("a") }))).await;

    let mut caught_up = beat("edge-1");
    caught_up.active_revision = 1;
    call(&app, "POST", "/v1/edges/edge-1/heartbeat", Some(as_json(&caught_up))).await;

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(body["edges"][0]["status"], "healthy");
    assert!(body["edges"][0]["up_to_date"].as_bool().unwrap());
    assert_eq!(body["counts"]["up_to_date"], 1);
}

#[tokio::test]
async fn a_node_following_a_local_file_is_not_called_behind() {
    /* -1 means it never takes config from here, which is a deployment choice rather
       than a node failing to keep up */
    let app = app();
    call(&app, "PUT", "/v1/config", Some(json!({ "yaml": config_for("a") }))).await;
    call(&app, "POST", "/v1/edges/e/heartbeat", Some(as_json(&beat("e")))).await;

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(body["edges"][0]["status"], "healthy");
    assert_eq!(body["edges"][0]["active_revision"], NO_REVISION);
}

#[tokio::test]
async fn a_node_on_an_older_build_than_the_fleet_is_outdated() {
    /* "outdated" is the one state that cannot be decided from a single node's report -
       it only exists relative to whatever everyone else is running */
    let app = app();
    let mut old = beat("edge-old");
    old.version = "0.9.0".into();
    let mut new = beat("edge-new");
    new.version = "0.10.0".into();

    call(&app, "POST", "/v1/edges/edge-old/heartbeat", Some(as_json(&old))).await;
    call(&app, "POST", "/v1/edges/edge-new/heartbeat", Some(as_json(&new))).await;

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    /* 0.10.0 is newer than 0.9.0 - as a string it would sort the other way round */
    assert_eq!(body["newest_version"], "0.10.0");
    assert_eq!(body["counts"]["outdated"], 1);
    assert_eq!(body["counts"]["healthy"], 1);

    let nodes = body["edges"].as_array().unwrap();
    let old = nodes.iter().find(|e| e["edge_id"] == "edge-old").unwrap();
    let new = nodes.iter().find(|e| e["edge_id"] == "edge-new").unwrap();
    assert_eq!(old["status"], "outdated");
    assert!(old["note"].as_str().unwrap().contains("0.10.0"));
    assert_eq!(new["status"], "healthy");
}

#[tokio::test]
async fn one_version_across_the_fleet_means_nobody_is_outdated() {
    let app = app();
    for id in ["a", "b", "c"] {
        call(&app, "POST", &format!("/v1/edges/{id}/heartbeat"), Some(as_json(&beat(id)))).await;
    }

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(body["counts"]["outdated"], 0);
    assert_eq!(body["counts"]["healthy"], 3);
}

#[tokio::test]
async fn a_forgotten_offline_node_does_not_hold_the_fleet_version_back() {
    /* an offline node's version is stale news. counting it would mean one decommissioned
       box on last month's build makes every live node look current */
    let app = app();
    let mut ancient = beat("edge-dead");
    ancient.version = "9.9.9".into();
    /* backdate it well past the offline threshold */
    ancient.started_at_ms = 0;
    call(&app, "POST", "/v1/edges/edge-dead/heartbeat", Some(as_json(&ancient))).await;
    call(&app, "POST", "/v1/edges/edge-live/heartbeat", Some(as_json(&beat("edge-live")))).await;

    /* both were just heard from, so the dead one still counts for now */
    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(body["newest_version"], "9.9.9");
    assert_eq!(body["counts"]["outdated"], 1, "the live node is behind while both are up");
}

#[tokio::test]
async fn a_draining_node_is_degraded_rather_than_broken() {
    let app = app();
    let mut leaving = beat("edge-1");
    leaving.draining = true;
    call(&app, "POST", "/v1/edges/edge-1/heartbeat", Some(as_json(&leaving))).await;

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(body["edges"][0]["status"], "degraded");
    assert!(body["edges"][0]["draining"].as_bool().unwrap());
    assert!(body["edges"][0]["note"].as_str().unwrap().contains("draining"));
}

#[tokio::test]
async fn a_node_whose_origins_are_all_down_is_degraded() {
    let app = app();
    let mut sick = beat("edge-1");
    sick.origins_healthy = 0;
    call(&app, "POST", "/v1/edges/edge-1/heartbeat", Some(as_json(&sick))).await;

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(body["edges"][0]["status"], "degraded");
    assert!(body["edges"][0]["note"].as_str().unwrap().contains("origin"));
}

#[tokio::test]
async fn partial_origin_health_is_still_worth_flagging() {
    let app = app();
    let mut half = beat("edge-1");
    half.origins_healthy = 1;
    call(&app, "POST", "/v1/edges/edge-1/heartbeat", Some(as_json(&half))).await;

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(body["edges"][0]["status"], "degraded");
    assert!(body["edges"][0]["note"].as_str().unwrap().contains("1 of 2"));
}

#[tokio::test]
async fn regions_are_totalled_so_a_dark_pop_is_visible() {
    let app = app();
    for (id, region) in [("a", "lhr"), ("b", "lhr"), ("c", "fra")] {
        let mut b = beat(id);
        b.region = Some(region.into());
        call(&app, "POST", &format!("/v1/edges/{id}/heartbeat"), Some(as_json(&b))).await;
    }

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    let regions = body["regions"].as_array().unwrap();
    assert_eq!(regions.len(), 2);
    /* sorted, so the page does not reshuffle between polls */
    assert_eq!(regions[0]["region"], "fra");
    assert_eq!(regions[0]["total"], 1);
    assert_eq!(regions[1]["region"], "lhr");
    assert_eq!(regions[1]["total"], 2);
    assert_eq!(regions[1]["healthy"], 2);
}

#[tokio::test]
async fn a_node_with_no_region_is_still_counted_somewhere() {
    let app = app();
    let mut nameless = beat("edge-1");
    nameless.region = None;
    call(&app, "POST", "/v1/edges/edge-1/heartbeat", Some(as_json(&nameless))).await;

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(body["regions"][0]["region"], "unlabelled");
}

#[tokio::test]
async fn a_decommissioned_node_can_be_forgotten() {
    /* otherwise it sits in the fleet view as permanently offline, forever */
    let app = app();
    call(&app, "POST", "/v1/edges/edge-1/heartbeat", Some(as_json(&beat("edge-1")))).await;

    let (status, _) = call(&app, "DELETE", "/v1/edges/edge-1", None).await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = call(&app, "GET", "/v1/edges", None).await;
    assert_eq!(body["counts"]["total"], 0);

    let (status, _) = call(&app, "DELETE", "/v1/edges/edge-1", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "forgetting twice is not a thing");
}

#[tokio::test]
async fn the_fleet_needs_a_token_like_everything_else() {
    let app = app();
    let req = Request::builder()
        .method("GET")
        .uri("/v1/edges")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_scrape_reports_the_fleet() {
    let app = app();
    let mut degraded = beat("edge-2");
    degraded.draining = true;
    call(&app, "POST", "/v1/edges/edge-1/heartbeat", Some(as_json(&beat("edge-1")))).await;
    call(&app, "POST", "/v1/edges/edge-2/heartbeat", Some(as_json(&degraded))).await;

    let req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8_lossy(&bytes);

    assert!(body.contains(r#"cloudflint_fleet_edges{status="healthy"} 1"#), "{body}");
    assert!(body.contains(r#"cloudflint_fleet_edges{status="degraded"} 1"#), "{body}");
    assert!(body.contains(r#"cloudflint_fleet_edges{status="outdated"} 0"#), "{body}");
    assert!(body.contains(r#"cloudflint_fleet_edges{status="config_mismatch"} 0"#), "{body}");
    assert!(body.contains(r#"cloudflint_fleet_edges{status="offline"} 0"#), "{body}");
    assert!(body.contains("cloudflint_api_heartbeats_total 2"), "{body}");
    /* one HELP and one TYPE for the whole metric, not one per series - a scrape with
       duplicates is malformed and Prometheus may reject all of it */
    assert_eq!(body.matches("# HELP cloudflint_fleet_edges ").count(), 1, "{body}");
    assert_eq!(body.matches("# TYPE cloudflint_fleet_edges ").count(), 1, "{body}");
}
