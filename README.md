# Cloudveil

[![ci](https://github.com/Kalyan-Deva/cloudveil/actions/workflows/ci.yml/badge.svg)](https://github.com/Kalyan-Deva/cloudveil/actions/workflows/ci.yml)

An edge reverse proxy with a WAF, a cache and rate limiting, written from scratch in
Rust. Nothing here wraps nginx or Envoy.

Two processes and a dashboard:

- `cloudveil-edge` — data plane. tokio + hyper + rustls, sits in front of origins.
- `cloudveil-api` — control plane. axum + SQLite. Owns config and analytics.
- `dashboard/` — Next.js UI on port 3020. Overview, zones, **origins** (health, latency,
  error rate, traffic share, failover events), WAF rules with a rule tester, a live log,
  config with revisions and rollback, and tokens.

## What it does

- **TLS** termination with per-zone certificates selected by SNI, HTTP/2 via ALPN,
  hot certificate reload, and an optional HTTP→HTTPS redirect listener.
- **HTTPS to the origin** with certificate validation on by default, per-zone trust for an
  internal CA, and optional client certificates for origin mTLS.
- **WAF** with an expression language, compiled to closures at config load. Two
  rulesets ship embedded: `core` (head-only) and `core-body` (opt-in).
- **Cache** with request coalescing, stale-while-revalidate, stale-if-error, and purge
  by URL, tag or zone.
- **Rate limiting** with token buckets keyed by IP, IP+path or header, per-IP
  connection caps, read timeouts, and an adaptive tier that tightens while an origin
  is failing.
- **Origin failover** across a pool of backends, with passive health from real traffic
  and optional active probes.
- **Compression** with brotli and gzip, applied before the cache so each variant is
  compressed once rather than on every hit.
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

### With Docker

One image holds both binaries; which one runs is the command.

```bash
docker build -t cloudveil .
```

```bash
CLOUDVEIL_API_TOKEN=cv_$(openssl rand -hex 32) CLOUDVEIL_ADMIN_TOKEN=cv_$(openssl rand -hex 32) docker compose up
```

That brings up the control plane on `127.0.0.1:9000`, the edge on `:8080` with its admin
API on `127.0.0.1:9001`, and an nginx container to act as an origin. Edge config is
`deploy/edge.yaml`, mounted read-only. Set `stop_grace_period` above the edge's
`limits.drain_timeout_secs`, or the runtime will cut a drain short.

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
  drain_timeout_secs: 30

client_ip: # who the client is when something sits in front of this node
  header: x-forwarded-for
  trusted_proxies: [] # empty (the default) means the header is never read

lists:
  trusted: [127.0.0.1, 10.0.0.0/8]

zones:
  - name: demo
    hostnames: [demo.local, "*.demo.local"]
    origin: # one backend
      url: "http://127.0.0.1:8081" # scheme is required
      preserve_host: true
      timeout_ms: 30000

    # or several, instead of `origin`, in preference order
    origins:
      - url: "http://127.0.0.1:8081"
      - url: "http://127.0.0.1:8082"
    origin_policy:
      # first_healthy | round_robin | weighted | least_connections
      strategy: first_healthy
      unhealthy_after: 3 # consecutive failures before it is taken out
      retry_after_secs: 10 # how long it stays out
      probe: # optional active checks
        path: /healthz
        every_secs: 10
        timeout_ms: 2000
        healthy_after: 2 # successes before it gets traffic again
    tls: # this zone's certificate, for clients
      cert: "certs/demo.local.crt"
      key: "certs/demo.local.key"

    origin_tls: # how we talk to an https:// origin
      verify: true # on by default; false is per zone and logged every time
      ca: "certs/internal-ca.pem" # an internal issuer, if the origin has one
      client_cert: "certs/edge-client.crt" # mTLS to the origin
      client_key: "certs/edge-client.key"

    waf:
      rulesets: [core] # add core-body to inspect request bodies
      max_body_bytes: 131072
      on_oversized_body: allow # or block
      rules:
        - id: admin-needs-tls
          expression: http.request.uri.path contains "/admin" and not ssl
          action: block # block | log | skip

    compression: # on by default
      enabled: true
      min_bytes: 1024 # below this the headers cost more than the saving
      max_bytes: 1048576 # above this it streams through uncompressed
      # types: [text/html, application/json] # defaults to the built-in text-ish list

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

### HTTPS to the origin

An `https://` origin url is reached over TLS with the certificate **verified** — public
roots plus any `origin_tls.ca` a zone names, and the hostname has to match the url. A
plaintext origin goes through the same client; the connector speaks either.

`verify: false` exists for self-signed origins on private networks. It is per zone rather
than global, so one internal service cannot quietly turn checking off for everything else,
and it logs a warning every time the profile is built.

`client_cert` / `client_key` present a client certificate, which is what lets an origin
refuse everyone who is not this proxy. Clients are cached per distinct profile, so zones
with the same settings share a connection pool. A path that does not exist stops the edge
starting rather than failing the first request to that zone.

### Compression

Brotli and gzip, on by default for text-ish content types above `min_bytes`. Brotli wins
when a client offers both, at quality 4 rather than 11 — compressing on the fly costs a
person's time, and 11 is roughly an order of magnitude slower for a few percent.

It runs on the response as it arrives from the origin, **before the cache stores it**, so
a cached variant is compressed once however many times it is served. The cache key already
folds `Accept-Encoding` down to one token, so a brotli client and a gzip client get
separate entries — and the code that picks an encoding is the same code that builds that
part of the key, because if they disagreed a client could be handed bytes it cannot read.

Never touched: anything already carrying `Content-Encoding`, `Cache-Control:
no-transform`, `206 Partial Content`, a type not on the list, or a response with no
`Content-Type` at all. Bodies over `max_bytes` stream through uncompressed; streaming
compression is a deferral, not a feature.

### Origins and failover

A zone's `origins` are tried in health order, and the strategy decides among the healthy
ones — an origin that is out of rotation never takes a turn or a share of the weights:

| strategy | |
|---|---|
| `first_healthy` | earlier entries win: a primary with backups behind it |
| `round_robin` | one each in turn |
| `weighted` | in proportion to each origin's `weight`, interleaved rather than in runs |
| `least_connections` | fewest requests in flight, which follows how long requests actually take |

Passive health comes free from real traffic:
after `unhealthy_after` consecutive failures a backend is taken out for
`retry_after_secs`. Active `probe`s cost a request every few seconds and are the only way
a recovered backend comes back without a user finding it first.

What counts as a failure is deliberately narrow:

| | |
|---|---|
| connection refused | failure, and the request is retried on the next origin |
| timeout | failure, but **not** retried — the origin may be doing the work, and the client has already waited the full timeout |
| any HTTP status, including 5xx | not a failure. The origin answered; that is its answer |

A request is only retried if it can be repeated safely: an idempotent method
(`GET`/`HEAD`/`OPTIONS`/`TRACE`) with no body. A `POST` that fails gets a 502, and the
failure is still recorded so the *next* request goes elsewhere.

When every origin looks unhealthy they are all tried anyway. Health is a guess from a
handful of failures, and a guess that can take the whole site down is worse than no guess.

Per-origin health shows up in `/admin/stats` and as `cloudveil_origin_healthy{zone,origin}`.

### Behind a load balancer

Rate limits, `ip.src` rules and the log all key on the client's address. By default that
is the peer on the socket, which is correct when Cloudveil is the first thing traffic
touches — and wrong behind a load balancer, where every client would share one bucket.

Set `client_ip.trusted_proxies` to the addresses you actually run. The chain in
`client_ip.header` is then read, but only from a peer on that list, and only the hops on
it are believed: walking right to left, the first address that isn't a trusted proxy is
the client. Anything a client wrote itself sits further left than the address its own
proxy appended, so it is never reached.

Only list ranges you control. Anything on the list can name any client it likes.

A trusted proxy's `X-Forwarded-Proto` is honoured the same way, so `ssl` rules mean what
the client did rather than what our own leg happened to be. Per-IP *connection* caps
(`limits.max_connections_per_ip`) stay on the peer — they apply at accept time, before
there is a request to read a header from.

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

Edge admin API: `/admin/health`, `/admin/stats`, `/admin/origins`,
`/admin/certificates`, `/admin/recent`, `/admin/stream` (SSE), `/admin/purge`, `/metrics`.

`/admin/certificates` reports what is **loaded and serving** — subject, issuer, validity,
days left, the names the certificate actually covers, whether it is self-signed — plus how
each zone talks to its origins. Reported from the live certificates rather than from
config, because the two differ exactly when something is wrong.

`/admin/origins` is the origin dashboard's data: per backend, whether it is in rotation,
requests, errors and error rate, traffic share, in-flight count, p50/p95 estimated from the
latency buckets, probe results, plus the last 32 failover events. All of it read out of the
counters the request path already writes — there is no second set to disagree with them.

## Shutting down

On `SIGTERM` (or ctrl-c) the edge:

1. reports `{"status":"draining"}` with a 503 on `/admin/health`, and
   `cloudveil_draining 1` on `/metrics`;
2. closes its traffic listeners, so nothing new is accepted;
3. lets live connections finish the response in flight — HTTP/1.1 stops keeping alive,
   HTTP/2 gets a GOAWAY;
4. exits once the last one closes, or after `limits.drain_timeout_secs` regardless.

The admin listener stays up for the whole drain so health can still be read. The control
plane drains the same way, with a fixed 10s deadline.

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
| `cloudveil_origin_requests_total` | counter | `zone`, `origin` |
| `cloudveil_origin_errors_total` | counter | `zone`, `origin`, `kind` (`unreachable`/`timeout`) |
| `cloudveil_origin_duration_seconds` | histogram | `zone`, `origin` |
| `cloudveil_origin_healthy` | gauge | `zone`, `origin` — 0 while taken out of rotation |
| `cloudveil_origin_failovers_total` | counter | `zone` |
| `cloudveil_origin_probes_total` | counter | `zone`, `origin`, `result` |
| `cloudveil_compressed_total` | counter | `zone`, `coding` |
| `cloudveil_compressed_bytes_in_total` / `_out_total` | counter | `zone` — the difference is the saving |
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
TLS and HTTP/2, upgrades, WAF rule fixtures, cache behaviour, rate limits, shutdown
draining, client-IP resolution, and the full edge/control-plane loop.

CI runs `cargo clippy -D warnings` and the suite on Linux and Windows — both, because the
signal handling is written twice behind `cfg(unix)` and `cfg(windows)` — plus the
dashboard build, and a Docker job that builds the image, brings the compose stack up,
proxies a request through it, checks the WAF blocks, and asserts the container exits 0
when stopped. There is no `cargo fmt` check: the source is formatted by hand.

## Notes

- Rate limit counters are per node.
- Origin connections are HTTP/1.1.
- Origin health is per node: each edge forms its own opinion of a backend.
- Built and tested on Windows and Linux. The container image has not been built yet.

## Licence

MIT
