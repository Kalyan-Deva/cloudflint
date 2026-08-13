# Cloudveil

An edge reverse proxy with a WAF, a cache and rate limiting, written from scratch in
Rust. Nothing here wraps nginx or Envoy.

Two processes and a dashboard:

- `cloudveil-edge` — data plane. tokio + hyper + rustls, sits in front of origins.
- `cloudveil-api` — control plane. axum + SQLite. Owns config and analytics.
- `dashboard/` — Next.js UI on port 3020.

## What it does

- **TLS** termination with per-zone certificates selected by SNI, HTTP/2 via ALPN,
  hot certificate reload, and an optional HTTP→HTTPS redirect listener.
- **WAF** with an expression language, compiled to closures at config load. Two
  rulesets ship embedded: `core` (head-only) and `core-body` (opt-in).
- **Cache** with request coalescing, stale-while-revalidate, stale-if-error, and purge
  by URL, tag or zone.
- **Rate limiting** with token buckets keyed by IP, IP+path or header, per-IP
  connection caps, read timeouts, and an adaptive tier that tightens while an origin
  is failing.
- **WebSockets** and other `Upgrade` connections pass through.
- **Control plane** holding config as revisions with one-click rollback, plus
  analytics ingested from the edges.
- **Prometheus `/metrics`** on both processes, and JSON logs on request.

## Running it

```bash
cargo run -p cloudveil-api -- 127.0.0.1:9000 cloudveil.db http://127.0.0.1:9001
```

```bash
cargo run -p cloudveil-edge -- cloudveil.yaml
```

```bash
npm --prefix dashboard run dev
```

The control plane prints a bootstrap token on first start. Give it to the edge and the
dashboard — see Credentials below.

### Certificates

```bash
# self-signed cert for an edge's https listener
cargo run -p cloudveil-edge --bin cloudveil-cert -- certs demo.local "*.demo.local" localhost
```

```bash
# a CA plus server and client certs, for mTLS between edge and control plane
cargo run -p cloudveil-edge --bin cloudveil-cert -- --mtls certs localhost
```

## Config

`cloudveil.yaml` is the full annotated example. In brief:

```yaml
listen: "127.0.0.1:8080"
control_plane: "http://127.0.0.1:9000" # optional; omit to run from the file alone
admin_listen: "127.0.0.1:9001" # optional; purge and stats

tls:
  listen: "127.0.0.1:8443"
  redirect_http: true
  handshake_timeout_ms: 10000

cache: # store sizing, read once at boot
  max_bytes: 268435456
  max_object_bytes: 8388608

limits: # node-wide, applied at accept time
  max_connections_per_ip: 256
  new_connections_per_ip_per_sec: 128
  header_read_timeout_ms: 10000
  body_read_timeout_ms: 30000
  max_connection_age_secs: 300

lists:
  trusted: [127.0.0.1, 10.0.0.0/8]

zones:
  - name: demo
    hostnames: [demo.local, "*.demo.local"]
    origin:
      url: "http://127.0.0.1:8081" # scheme is required
      preserve_host: true
      timeout_ms: 30000
    tls:
      cert: "certs/demo.local.crt"
      key: "certs/demo.local.key"

    waf:
      rulesets: [core] # add core-body to inspect request bodies
      max_body_bytes: 131072
      on_oversized_body: allow # or block
      rules:
        - id: admin-needs-tls
          expression: http.request.uri.path contains "/admin" and not ssl
          action: block # block | log | skip

    cache:
      enabled: true
      vary_on: [accept-encoding]
      stale_while_revalidate_secs: 0
      stale_if_error_secs: 60
      coalesce_wait_ms: 5000
      overrides:
        - path_prefix: "/static/"
          ttl_secs: 604800
          override_origin_headers: true

    rate_limits:
      - id: api-per-ip
        match: http.request.uri.path contains "/api/"
        key: ip # ip | ip_path | header:<name>
        requests: 100
        window_secs: 60
        action: block # or log

    adaptive:
      window_secs: 10
      min_requests: 20
      error_ratio: 0.25
      slow_ms: 1000
      slow_ratio: 0.5
      tighten_to: 0.5
```

Editing the file — or the config in the control plane — takes effect within a couple of
seconds with no restart. A config that does not parse is refused. Changing `listen`
needs a restart.

Exact hostnames beat wildcards: `*.demo.local` covers `api.demo.local` but not
`demo.local` itself or `a.b.demo.local`.

### WAF expressions

```
http.request.method            http.request.uri          http.request.uri.path
http.request.uri.query         http.request.body         http.host
http.request.headers["name"]   ip.src                    ssl
```

Operators: `eq` `ne` `contains` `matches` `in`, combined with `and` `or` `not`.
`ssl` is a bare boolean. Path, query and URI are percent-decoded before matching.

## Credentials

Secrets come from the environment, not from config.

| Variable | Where | What |
|---|---|---|
| `CLOUDVEIL_API_TOKEN` | control plane, dashboard | bootstrap / dashboard token |
| `CLOUDVEIL_ADMIN_TOKEN` | edge, dashboard | edge admin token (the edge will not start without it) |
| `CLOUDVEIL_CP_TOKEN` | edge | token the edge presents to the control plane |
| `CLOUDVEIL_EDGE_TOKEN` | control plane | token the control plane presents to edges when purging |
| `CLOUDVEIL_CLIENT_CERT` / `_KEY` | edge | client certificate for mTLS |
| `CLOUDVEIL_CP_CA` | edge | CA to trust for the control plane |
| `CLOUDVEIL_API_TLS_CERT` / `_KEY` | control plane | serve HTTPS |
| `CLOUDVEIL_API_CLIENT_CA` | control plane | require client certificates |

`/health` on both APIs is unauthenticated so orchestrators can probe it. Everything
else needs a bearer token.

Two more environment variables, neither of them secret:

| Variable | Where | What |
|---|---|---|
| `CLOUDVEIL_LOG_FORMAT` | both | `json` for one JSON object per line; anything else is the human format |
| `CLOUDVEIL_METRICS_OPEN` | both | `1` serves `/metrics` without a token |

`RUST_LOG` sets the level and filter as usual; the default is `info`.

## API

| | |
|---|---|
| `GET /v1/config` | active revision |
| `PUT /v1/config` | store a revision and activate it |
| `GET /v1/config/revisions` | history |
| `POST /v1/config/revisions/{id}/activate` | roll back |
| `GET /v1/zones` | active config, parsed |
| `POST /v1/waf/test` | run a request against a zone's rules |
| `POST /v1/events` | analytics ingest |
| `GET /v1/analytics/summary` | counts, cache ratio, p50/p95, top paths and IPs |
| `GET /v1/analytics/timeseries` | bucketed counts for the traffic chart |
| `POST /v1/purge` | `{url}`, `{tag}`, `{zone}` or `{all:true}` |
| `GET/POST/DELETE /v1/tokens` | mint, list, revoke |

Edge admin API: `/admin/health`, `/admin/stats`, `/admin/recent`, `/admin/stream`
(SSE), `/admin/purge`, `/metrics`.

## Metrics

`GET /metrics` in Prometheus text format, on the edge's admin listener (`admin_listen`)
and on the control plane. Both need a bearer token unless `CLOUDVEIL_METRICS_OPEN=1`.

```yaml
scrape_configs:
  - job_name: cloudveil-edge
    static_configs: [{ targets: ["127.0.0.1:9001"] }]
    authorization: { credentials: "cv_..." } # CLOUDVEIL_ADMIN_TOKEN
```

From the edge:

| Series | Type | Labels |
|---|---|---|
| `cloudveil_requests_total` | counter | `zone`, `status`, `decided_by` |
| `cloudveil_request_duration_seconds` | histogram | `zone` |
| `cloudveil_cache_results_total` | counter | `zone`, `result` (`hit`/`miss`/`stale`/`stale-error`/`bypass`) |
| `cloudveil_waf_matches_total` | counter | `zone`, `rule`, `severity`, `action` |
| `cloudveil_ratelimit_decisions_total` | counter | `zone`, `rule`, `action` |
| `cloudveil_ratelimit_factor` | gauge | `zone` — below 1 while the adaptive tier is tightening |
| `cloudveil_origin_requests_total` | counter | `zone` |
| `cloudveil_origin_errors_total` | counter | `zone`, `kind` (`unreachable`/`timeout`) |
| `cloudveil_origin_duration_seconds` | histogram | `zone` |
| `cloudveil_connections_total` | counter | |
| `cloudveil_connections_refused_total` | counter | `reason` (`too_many`/`too_fast`) |
| `cloudveil_connections_active` | gauge | |
| `cloudveil_tls_handshake_failures_total` | counter | `reason` (`failed`/`timeout`) |
| `cloudveil_cache_entries`, `cloudveil_cache_bytes` | gauge | |
| `cloudveil_zones`, `cloudveil_uptime_seconds` | gauge | |
| `cloudveil_events_recorded_total`, `cloudveil_events_dropped_total` | counter | |
| `cloudveil_metrics_series_dropped_total` | counter | above zero means a series hit its cardinality cap |
| `cloudveil_build_info` | gauge | `version` |

A request that matched no zone is labelled `zone="unrouted"`. From the control plane:
`cloudveil_api_events_ingested_total`, `cloudveil_api_config_writes_total{kind}`,
`cloudveil_api_purges_total{outcome}`, `cloudveil_api_uptime_seconds`,
`cloudveil_api_edges_configured`, `cloudveil_api_active_revision`,
`cloudveil_api_build_info`.

## Tests

```bash
cargo test
```

Unit tests plus integration tests that run real origins over real sockets: forwarding,
TLS and HTTP/2, upgrades, WAF rule fixtures, cache behaviour, rate limits, and the full
edge/control-plane loop.

## Notes

- Rate limit counters are per node.
- Origin connections are HTTP/1.1.
- One origin per zone; no health checking or failover yet.
- Only ever run on Windows so far.

## Licence

MIT
