//! Control plane API.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use cloudveil_api::db::Db;
use cloudveil_api::{router, Api};
use serde_json::{json, Value};
use tower::ServiceExt;

/// Every guarded route needs a token now, so the fixture mints one and every call
/// carries it. `TOKEN` is what the tests present; the db stores only its hash.
const TOKEN: &str = "cv_testtoken0123456789abcdef0123456789abcdef0123456789abcdef01";

fn app(edges: Vec<String>) -> axum::Router {
    let db = Db::open(":memory:").expect("in-memory db");
    db.add_token("tests", TOKEN, 0).expect("token should store");
    router(Api {
        db,
        edges: Arc::new(edges),
        edge_token: None,
    })
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
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
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

fn config_for(zone: &str) -> String {
    format!(
        "zones:\n  - name: {zone}\n    hostnames: [\"{zone}.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n"
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn event(zone: &str, status: u16, us: u64, cache: Option<&str>, path: &str) -> Value {
    json!({
        "at_ms": now_ms(),
        "zone": zone,
        "host": format!("{zone}.local"),
        "method": "GET",
        "path": path,
        "status": status,
        "duration_us": us,
        "decided_by": if status == 403 { "waf" } else { "origin" },
        "cache": cache,
        "client_ip": "203.0.113.9",
    })
}

#[tokio::test]
async fn stores_a_config_and_hands_it_back() {
    let app = app(vec![]);

    let (status, _) = call(&app, "GET", "/v1/config", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "nothing uploaded yet");

    let (status, body) = call(
        &app,
        "PUT",
        "/v1/config",
        Some(json!({ "yaml": config_for("demo"), "note": "first" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["revision"], 1);

    let (status, body) = call(&app, "GET", "/v1/config", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revision"], 1);
    assert_eq!(body["note"], "first");
    assert!(body["yaml"].as_str().unwrap().contains("demo.local"));
}

/// The control plane validates with the edge's own parser, so a config that would
/// break the data plane fails here at write time rather than out there at reload.
#[tokio::test]
async fn refuses_a_config_the_edge_would_refuse() {
    let app = app(vec![]);

    let bad = "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"example.com\"\n";
    let (status, body) = call(&app, "PUT", "/v1/config", Some(json!({ "yaml": bad }))).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error"].as_str().unwrap();
    assert!(message.contains("scheme"), "unhelpful error: {message}");

    let (status, _) = call(&app, "GET", "/v1/config", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the bad config must not have landed");
}

#[tokio::test]
async fn every_write_is_a_revision_and_any_of_them_can_come_back() {
    let app = app(vec![]);

    for zone in ["one", "two", "three"] {
        call(
            &app,
            "PUT",
            "/v1/config",
            Some(json!({ "yaml": config_for(zone), "note": zone })),
        )
        .await;
    }

    let (status, list) = call(&app, "GET", "/v1/config/revisions", None).await;
    assert_eq!(status, StatusCode::OK);
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0]["id"], 3, "newest first");
    assert_eq!(list[0]["active"], true);
    assert_eq!(list[2]["active"], false);

    /* roll back to the first */
    let (status, _) = call(&app, "POST", "/v1/config/revisions/1/activate", None).await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = call(&app, "GET", "/v1/config", None).await;
    assert_eq!(body["revision"], 1);
    assert!(body["yaml"].as_str().unwrap().contains("one.local"));

    let (status, body) = call(&app, "POST", "/v1/config/revisions/99/activate", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("no revision 99"));
}

#[tokio::test]
async fn ingests_events_and_adds_them_up() {
    let app = app(vec![]);

    let batch = json!([
        event("demo", 200, 1_000, Some("HIT"), "/a"),
        event("demo", 200, 2_000, Some("MISS"), "/a"),
        event("demo", 200, 3_000, Some("HIT"), "/b"),
        event("demo", 403, 500, None, "/admin"),
        event("demo", 502, 90_000, None, "/slow"),
        event("other", 200, 1_000, Some("HIT"), "/x"),
    ]);
    let (status, body) = call(&app, "POST", "/v1/events", Some(batch)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["stored"], 6);

    let (status, s) = call(
        &app,
        "GET",
        "/v1/analytics/summary?zone=demo&since_mins=43200",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(s["requests"], 5, "the other zone should not be counted");
    assert_eq!(s["errors"], 1);
    assert_eq!(s["blocked"], 1);
    assert_eq!(s["cache_hits"], 2);
    assert_eq!(s["cache_eligible"], 3);
    assert!(s["p95_us"].as_u64().unwrap() >= s["p50_us"].as_u64().unwrap());

    let top = s["top_paths"].as_array().unwrap();
    assert_eq!(top[0][0], "/a", "the busiest path should come first");
    assert_eq!(top[0][1], 2);

    let stages: Vec<&str> = s["by_stage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| pair[0].as_str().unwrap())
        .collect();
    assert!(stages.contains(&"waf"));
    assert!(stages.contains(&"origin"));
}

#[tokio::test]
async fn a_summary_over_all_zones_counts_everything() {
    let app = app(vec![]);
    call(
        &app,
        "POST",
        "/v1/events",
        Some(json!([
            event("demo", 200, 1_000, Some("HIT"), "/a"),
            event("other", 200, 1_000, Some("HIT"), "/x"),
        ])),
    )
    .await;

    let (_, s) = call(&app, "GET", "/v1/analytics/summary?since_mins=43200", None).await;
    assert_eq!(s["requests"], 2);
}

#[tokio::test]
async fn an_empty_batch_is_fine() {
    let app = app(vec![]);
    let (status, body) = call(&app, "POST", "/v1/events", Some(json!([]))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["stored"], 0);
}

#[tokio::test]
async fn purge_needs_exactly_one_target() {
    let app = app(vec!["http://127.0.0.1:9".to_string()]);

    for ask in [json!({}), json!({ "tag": "nav", "all": true })] {
        let (status, body) = call(&app, "POST", "/v1/purge", Some(ask)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("exactly one"));
    }
}

#[tokio::test]
async fn purge_says_so_when_there_is_nowhere_to_send_it() {
    let app = app(vec![]);
    let (status, body) = call(&app, "POST", "/v1/purge", Some(json!({ "all": true }))).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error"].as_str().unwrap().contains("no edges"));
}

/// An edge that can't be reached is reported rather than swallowed - "mostly purged"
/// is a real state and pretending otherwise is worse than saying so.
#[tokio::test]
async fn an_unreachable_edge_is_reported_per_edge() {
    let app = app(vec!["http://127.0.0.1:9".to_string()]);
    let (status, body) = call(&app, "POST", "/v1/purge", Some(json!({ "all": true }))).await;

    assert_eq!(status, StatusCode::MULTI_STATUS);
    let edges = body["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0]["ok"], false);
    assert!(edges[0]["detail"].as_str().unwrap().contains("unreachable"));
}

#[tokio::test]
async fn describes_the_zones_in_the_active_config() {
    let app = app(vec![]);
    let yaml = "zones:\n  - name: demo\n    hostnames: [\"demo.local\", \"*.demo.local\"]\n    origin:\n      url: \"http://127.0.0.1:8081\"\n    rate_limits:\n      - id: api\n        requests: 100\n        window_secs: 60\n";
    call(&app, "PUT", "/v1/config", Some(json!({ "yaml": yaml }))).await;

    let (status, body) = call(&app, "GET", "/v1/zones", None).await;
    assert_eq!(status, StatusCode::OK);

    let zone = &body["zones"][0];
    assert_eq!(zone["name"], "demo");
    assert_eq!(zone["origin"], "http://127.0.0.1:8081");
    assert_eq!(zone["hostnames"][1], "*.demo.local");
    assert_eq!(zone["cache_enabled"], true);
    assert_eq!(zone["rate_limits"][0], "api: 100/60s");
    /* the core ruleset is on by default, so the zone should list its rules */
    assert!(zone["waf_rules"].as_array().unwrap().len() > 5);
    assert_eq!(zone["waf_reads_body"], false);
}

#[tokio::test]
async fn the_rule_tester_reports_everything_a_request_touches() {
    let app = app(vec![]);
    let yaml = "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n    waf:\n      rulesets: [core]\n      rules:\n        - id: watch-search\n          expression: 'http.request.uri.path eq \"/search\"'\n          action: log\n";
    call(&app, "PUT", "/v1/config", Some(json!({ "yaml": yaml }))).await;

    /* an attack that also trips a log rule: both should be reported, even though
       the block would normally hide whatever sits behind it */
    let (status, body) = call(
        &app,
        "POST",
        "/v1/waf/test",
        Some(json!({
            "zone": "demo",
            "path": "/search",
            "query": "id=1%20union%20select%201",
            "headers": { "user-agent": "Mozilla/5.0" }
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["outcome"], "block");
    assert_eq!(body["decided_by"], "sqli-union-select");

    let hit: Vec<&str> = body["matched"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["rule"].as_str().unwrap())
        .collect();
    assert!(hit.contains(&"sqli-union-select"));
    assert!(hit.contains(&"watch-search"), "matched: {hit:?}");
}

#[tokio::test]
async fn the_rule_tester_says_when_it_skipped_body_rules() {
    let app = app(vec![]);
    let yaml = "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n    waf:\n      rulesets: [core-body]\n";
    call(&app, "PUT", "/v1/config", Some(json!({ "yaml": yaml }))).await;

    let (_, no_body) = call(
        &app,
        "POST",
        "/v1/waf/test",
        Some(json!({ "zone": "demo", "path": "/submit" })),
    )
    .await;
    assert_eq!(no_body["outcome"], "allow");
    assert!(!no_body["skipped_needing_body"].as_array().unwrap().is_empty());

    let (_, with_body) = call(
        &app,
        "POST",
        "/v1/waf/test",
        Some(json!({ "zone": "demo", "method": "POST", "path": "/submit", "body": "q=1 union select 1" })),
    )
    .await;
    assert_eq!(with_body["outcome"], "block");
    assert!(with_body["skipped_needing_body"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn the_rule_tester_can_try_rules_that_are_not_saved_yet() {
    let app = app(vec![]);
    let draft = "zones:\n  - name: demo\n    hostnames: [\"demo.local\"]\n    origin:\n      url: \"http://127.0.0.1:9\"\n    waf:\n      rulesets: []\n      rules:\n        - id: draft-rule\n          expression: 'http.request.uri.path contains \"/secret\"'\n          action: block\n";

    let (status, body) = call(
        &app,
        "POST",
        "/v1/waf/test",
        Some(json!({ "zone": "demo", "yaml": draft, "path": "/secret/x" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "nothing was saved, and it still worked");
    assert_eq!(body["decided_by"], "draft-rule");
}

#[tokio::test]
async fn everything_but_health_needs_a_token() {
    let app = app(vec![]);

    /* health is deliberately open, so an orchestrator can probe it */
    let health = app
        .clone()
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    for (method, uri) in [
        ("GET", "/v1/config"),
        ("PUT", "/v1/config"),
        ("GET", "/v1/config/revisions"),
        ("POST", "/v1/events"),
        ("GET", "/v1/analytics/summary"),
        ("GET", "/v1/zones"),
        ("POST", "/v1/waf/test"),
        ("POST", "/v1/purge"),
        ("GET", "/v1/tokens"),
    ] {
        let bare = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            bare.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} answered without a token"
        );
    }
}

#[tokio::test]
async fn a_token_nobody_minted_is_refused() {
    let app = app(vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/config")
                .header("authorization", "Bearer cv_this_was_never_minted_anywhere")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_minted_token_works_and_can_be_revoked() {
    let app = app(vec![]);

    let (status, minted) =
        call(&app, "POST", "/v1/tokens", Some(json!({ "name": "an edge" }))).await;
    assert_eq!(status, StatusCode::CREATED);
    let secret = minted["token"].as_str().expect("the secret, once").to_owned();
    let id = minted["id"].as_i64().unwrap();

    let with = |token: String| {
        Request::builder()
            .uri("/v1/config/revisions")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };

    let used = app.clone().oneshot(with(secret.clone())).await.unwrap();
    assert_eq!(used.status(), StatusCode::OK, "a fresh token should work");

    /* listed, but the secret itself is never readable back */
    let (_, listed) = call(&app, "GET", "/v1/tokens", None).await;
    let text = listed.to_string();
    assert!(text.contains("an edge"));
    assert!(!text.contains(&secret), "the token must not be readable back");

    let (status, _) = call(&app, "DELETE", &format!("/v1/tokens/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);

    let after = app.oneshot(with(secret)).await.unwrap();
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "revoking should take effect immediately"
    );
}

#[tokio::test]
async fn the_traffic_chart_gets_real_buckets() {
    let app = app(vec![]);
    call(
        &app,
        "POST",
        "/v1/events",
        Some(json!([
            event("demo", 200, 1_000, Some("HIT"), "/a"),
            event("demo", 200, 2_000, Some("MISS"), "/a"),
            event("demo", 403, 500, None, "/admin"),
            event("demo", 429, 200, None, "/api"),
            event("demo", 502, 90_000, None, "/slow"),
        ])),
    )
    .await;

    let (status, body) = call(
        &app,
        "GET",
        "/v1/analytics/timeseries?zone=demo&since_mins=60&buckets=10",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let buckets = body["buckets"].as_array().unwrap();
    assert!(!buckets.is_empty(), "events just went in, so there should be a bucket");

    let total: u64 = buckets.iter().map(|b| b["requests"].as_u64().unwrap()).sum();
    let blocked: u64 = buckets.iter().map(|b| b["blocked"].as_u64().unwrap()).sum();
    let limited: u64 = buckets.iter().map(|b| b["limited"].as_u64().unwrap()).sum();
    let errors: u64 = buckets.iter().map(|b| b["errors"].as_u64().unwrap()).sum();
    let hits: u64 = buckets.iter().map(|b| b["cache_hits"].as_u64().unwrap()).sum();

    assert_eq!(total, 5);
    assert_eq!(blocked, 1);
    assert_eq!(limited, 1);
    assert_eq!(errors, 1);
    assert_eq!(hits, 1);
}

#[tokio::test]
async fn an_empty_window_gives_an_empty_chart_rather_than_an_error() {
    let app = app(vec![]);
    let (status, body) = call(&app, "GET", "/v1/analytics/timeseries?since_mins=5", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["buckets"].as_array().unwrap().is_empty());
}
