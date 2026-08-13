//! Traffic in, scrape out. Drives real requests through the edge and then reads
//! `/metrics` off its admin api, because the interesting part is not that a counter
//! increments - it is that what the request path did and what a scrape says agree.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use cloudveil_edge::snapshot::Snapshot;
use cloudveil_edge::{admin, config, serve, Edge};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

const TOKEN: &str = "cv_metricstoken0123456789abcdef0123456789abcdef0123456789abcd";

async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("cache-control", "max-age=300")
                            .body(Full::new(Bytes::from("hello")))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

fn zone_yaml(origin: SocketAddr) -> String {
    format!(
        r#"
zones:
  - name: demo
    hostnames: ["demo.local"]
    origin:
      url: "http://{origin}"
    waf:
      # no built-in rulesets, so the only matches a scrape can show are these two
      rulesets: []
      rules:
        - id: block-teapots
          expression: http.request.uri.path contains "/teapot"
          action: block
          severity: high
        - id: watch-robots
          expression: http.request.uri.path contains "/robots"
          action: log
          severity: low
    rate_limits:
      - id: tight
        match: http.request.uri.path contains "/limited"
        key: ip
        requests: 2
        window_secs: 60
        action: block
"#
    )
}

/// An edge plus its admin api, both on loopback.
async fn spawn(origin: SocketAddr) -> (SocketAddr, SocketAddr) {
    std::env::set_var(admin::TOKEN_VAR, TOKEN);

    let cfg = config::parse(&zone_yaml(origin)).expect("test config should parse");
    let edge = Edge::new(Arc::new(Snapshot::new(cfg)));

    let traffic = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let traffic_addr = traffic.local_addr().unwrap();
    {
        let edge = edge.clone();
        tokio::spawn(async move {
            let _ = serve(traffic, edge).await;
        });
    }

    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = admin::serve(admin_listener, edge).await;
    });

    (traffic_addr, admin_addr)
}

fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

async fn get(addr: SocketAddr, host: &str, path: &str) -> StatusCode {
    let req = Request::builder()
        .uri(format!("http://{addr}{path}"))
        .header("host", host)
        .body(Full::new(Bytes::new()))
        .unwrap();
    client()
        .request(req)
        .await
        .expect("the edge should answer")
        .status()
}

async fn scrape(admin: SocketAddr, token: Option<&str>) -> (StatusCode, String, String) {
    let mut req = Request::builder().uri(format!("http://{admin}/metrics"));
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = client()
        .request(req.body(Full::new(Bytes::new())).unwrap())
        .await
        .expect("the admin api should answer");

    let status = resp.status();
    let kind = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, kind, String::from_utf8_lossy(&body).into_owned())
}

/// The value of one sample line, by its exact name and labels.
fn sample(scraped: &str, series: &str) -> Option<f64> {
    scraped
        .lines()
        .find(|l| l.starts_with(series) && l[series.len()..].starts_with(' '))
        .and_then(|l| l[series.len()..].trim().parse().ok())
}

#[tokio::test]
async fn a_scrape_reports_what_the_request_path_did() {
    let origin = spawn_origin().await;
    let (traffic, admin) = spawn(origin).await;

    /* a miss then a hit on the same url, a waf block, a logged rule, an unknown
       host, and one request over a rate limit */
    assert_eq!(get(traffic, "demo.local", "/page").await, StatusCode::OK);
    assert_eq!(get(traffic, "demo.local", "/page").await, StatusCode::OK);
    assert_eq!(get(traffic, "demo.local", "/teapot").await, StatusCode::FORBIDDEN);
    assert_eq!(get(traffic, "demo.local", "/robots.txt").await, StatusCode::OK);
    assert_eq!(get(traffic, "nobody.local", "/").await, StatusCode::NOT_FOUND);
    for _ in 0..2 {
        get(traffic, "demo.local", "/limited").await;
    }
    assert_eq!(
        get(traffic, "demo.local", "/limited").await,
        StatusCode::TOO_MANY_REQUESTS
    );

    let (status, kind, body) = scrape(admin, Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(kind.starts_with("text/plain"), "content type was {kind}");

    assert_eq!(
        sample(&body, r#"cloudveil_requests_total{zone="demo",status="403",decided_by="waf"}"#),
        Some(1.0),
        "the waf block is missing:\n{body}"
    );
    assert_eq!(
        sample(&body, r#"cloudveil_requests_total{zone="unrouted",status="404",decided_by="route"}"#),
        Some(1.0),
        "a request that matched no zone should still be counted:\n{body}"
    );
    assert_eq!(
        sample(&body, r#"cloudveil_requests_total{zone="demo",status="429",decided_by="ratelimit"}"#),
        Some(1.0)
    );

    /* the cache labelled the first request for a url MISS and the next one HIT, and
       the counters say the same: /page, /robots.txt and /limited missed once each,
       and the second /page and second /limited hit */
    assert_eq!(
        sample(&body, r#"cloudveil_cache_results_total{zone="demo",result="hit"}"#),
        Some(2.0),
        "cache hits are wrong:\n{body}"
    );
    assert_eq!(
        sample(&body, r#"cloudveil_cache_results_total{zone="demo",result="miss"}"#),
        Some(3.0)
    );

    assert_eq!(
        sample(&body, r#"cloudveil_waf_matches_total{zone="demo",rule="block-teapots",severity="high",action="block"}"#),
        Some(1.0)
    );
    assert_eq!(
        sample(&body, r#"cloudveil_waf_matches_total{zone="demo",rule="watch-robots",severity="low",action="log"}"#),
        Some(1.0),
        "a log-action rule is exactly the one you want a graph of:\n{body}"
    );
    assert_eq!(
        sample(&body, r#"cloudveil_ratelimit_decisions_total{zone="demo",rule="tight",action="block"}"#),
        Some(1.0)
    );
    assert_eq!(sample(&body, r#"cloudveil_ratelimit_factor{zone="demo"}"#), Some(1.0));

    /* one origin fetch per miss - nothing for a hit, a block or a 429. Labelled by
       origin as well as zone, so "which backend" is answerable */
    assert_eq!(
        sample(
            &body,
            &format!(r#"cloudveil_origin_requests_total{{zone="demo",origin="{origin}"}}"#)
        ),
        Some(3.0)
    );
    assert_eq!(
        sample(
            &body,
            &format!(
                r#"cloudveil_origin_errors_total{{zone="demo",origin="{origin}",kind="unreachable"}}"#
            )
        ),
        None
    );
    /* and the only origin there is has been quietly healthy all along */
    assert_eq!(
        sample(
            &body,
            &format!(r#"cloudveil_origin_healthy{{zone="demo",origin="{origin}"}}"#)
        ),
        Some(1.0),
        "a healthy origin needs a series too, or there is nothing to alert on:\n{body}"
    );

    /* the histogram's +Inf bucket is every request that reached a zone */
    assert_eq!(
        sample(&body, r#"cloudveil_request_duration_seconds_bucket{zone="demo",le="+Inf"}"#),
        Some(7.0)
    );
    assert_eq!(
        sample(&body, r#"cloudveil_request_duration_seconds_count{zone="demo"}"#),
        Some(7.0)
    );

    assert_eq!(sample(&body, "cloudveil_cache_entries"), Some(3.0), "three urls were cached");
    assert!(sample(&body, "cloudveil_cache_bytes").unwrap_or(0.0) > 0.0);
    assert_eq!(sample(&body, "cloudveil_zones"), Some(1.0));
    assert_eq!(
        sample(&body, "cloudveil_events_recorded_total"),
        Some(8.0),
        "seven requests to the zone plus the one that matched none"
    );
    assert_eq!(sample(&body, "cloudveil_metrics_series_dropped_total"), Some(0.0));
    assert!(sample(&body, "cloudveil_uptime_seconds").is_some());
    assert!(body.contains("cloudveil_build_info{version="));

    /* connections were counted at accept time and released when they closed */
    assert!(sample(&body, "cloudveil_connections_total").unwrap_or(0.0) >= 1.0);
    assert!(sample(&body, "cloudveil_connections_active").is_some());
}

#[tokio::test]
async fn a_dead_origin_shows_up_as_an_origin_error() {
    /* bind then drop, so the port is almost certainly closed */
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let (traffic, admin) = spawn(dead).await;

    assert_eq!(get(traffic, "demo.local", "/page").await, StatusCode::BAD_GATEWAY);

    let (_, _, body) = scrape(admin, Some(TOKEN)).await;
    assert_eq!(
        sample(
            &body,
            &format!(
                r#"cloudveil_origin_errors_total{{zone="demo",origin="{dead}",kind="unreachable"}}"#
            )
        ),
        Some(1.0),
        "an unreachable origin should be an origin error, not just a 502:\n{body}"
    );
    assert_eq!(
        sample(&body, r#"cloudveil_requests_total{zone="demo",status="502",decided_by="cache"}"#),
        Some(1.0)
    );
}

#[tokio::test]
async fn a_scrape_needs_a_token_unless_it_is_opened() {
    let origin = spawn_origin().await;
    let (_, admin) = spawn(origin).await;

    let (status, _, _) = scrape(admin, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "metrics are a token away by default");

    /* both cases in one test: the env var is process-wide, so they cannot safely be
       two tests running at the same time */
    std::env::set_var(admin::METRICS_OPEN_VAR, "1");
    let (status, _, body) = scrape(admin, None).await;
    std::env::remove_var(admin::METRICS_OPEN_VAR);

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("# TYPE cloudveil_requests_total counter"));

    let (status, _, _) = scrape(admin, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
