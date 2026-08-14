//! SQLite, behind a mutex.
//!
//! The control plane is not in anyone's request path, so a single connection under a
//! lock is plenty and avoids a pool's worth of machinery. The blocking calls are
//! short enough not to be worth `spawn_blocking`; if that stops being true, the
//! honest fix is a real pool rather than pretending.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{bail, Context, Result};
use cloudflint_edge::analytics::Event;
use rusqlite::{params, Connection};
use serde::Serialize;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS revisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    yaml       TEXT    NOT NULL,
    note       TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

-- exactly one row, naming the revision the edges should be running
CREATE TABLE IF NOT EXISTS active (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    revision_id INTEGER NOT NULL REFERENCES revisions(id)
);

CREATE TABLE IF NOT EXISTS events (
    at_ms       INTEGER NOT NULL,
    zone        TEXT    NOT NULL,
    host        TEXT    NOT NULL,
    method      TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    status      INTEGER NOT NULL,
    duration_us INTEGER NOT NULL,
    decided_by  TEXT    NOT NULL,
    cache       TEXT,
    client_ip   TEXT    NOT NULL,
    country     TEXT,
    asn         INTEGER
);

CREATE TABLE IF NOT EXISTS tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    hash         TEXT    NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);

-- one row per edge, replaced wholesale by each heartbeat. the fleet is small enough
-- that history per node belongs in the metrics system rather than here.
CREATE TABLE IF NOT EXISTS edges (
    edge_id             TEXT    PRIMARY KEY,
    region              TEXT,
    label               TEXT,
    version             TEXT    NOT NULL DEFAULT '',
    started_at_ms       INTEGER NOT NULL DEFAULT 0,
    first_seen_ms       INTEGER NOT NULL,
    last_seen_ms        INTEGER NOT NULL,
    active_revision     INTEGER NOT NULL DEFAULT -1,
    -- when this node first reported the revision it is on, so a rollout can be timed
    acked_at_ms         INTEGER,
    draining            INTEGER NOT NULL DEFAULT 0,
    cpu_percent         REAL    NOT NULL DEFAULT 0,
    memory_bytes        INTEGER NOT NULL DEFAULT 0,
    memory_total_bytes  INTEGER NOT NULL DEFAULT 0,
    connections_active  INTEGER NOT NULL DEFAULT 0,
    requests_total      INTEGER NOT NULL DEFAULT 0,
    requests_per_sec    REAL    NOT NULL DEFAULT 0,
    cache_entries       INTEGER NOT NULL DEFAULT 0,
    cache_bytes         INTEGER NOT NULL DEFAULT 0,
    zones               INTEGER NOT NULL DEFAULT 0,
    origins_total       INTEGER NOT NULL DEFAULT 0,
    origins_healthy     INTEGER NOT NULL DEFAULT 0,
    certificates        TEXT    NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS events_at ON events(at_ms);
CREATE INDEX IF NOT EXISTS events_zone_at ON events(zone, at_ms);
CREATE INDEX IF NOT EXISTS edges_last_seen ON edges(last_seen_ms);
"#;

#[derive(Debug, Clone, Serialize)]
pub struct Revision {
    pub id: i64,
    pub note: String,
    pub created_at: i64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveConfig {
    pub revision: i64,
    pub yaml: String,
    pub note: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Summary {
    pub requests: u64,
    pub errors: u64,
    pub blocked: u64,
    pub rate_limited: u64,
    pub cache_hits: u64,
    pub cache_eligible: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub by_stage: Vec<(String, u64)>,
    pub top_paths: Vec<(String, u64)>,
    pub top_ips: Vec<(String, u64)>,
    /// Empty when no edge has a geo database - the panels then have nothing to draw,
    /// which is the honest answer rather than a chart of "unknown".
    pub top_countries: Vec<(String, u64)>,
    pub top_asns: Vec<(String, u64)>,
}

/// One bucket of the traffic chart.
#[derive(Debug, Clone, Serialize)]
pub struct Bucket {
    pub at_ms: i64,
    pub requests: u64,
    pub blocked: u64,
    pub limited: u64,
    pub errors: u64,
    pub cache_hits: u64,
    pub p95_us: u64,
}

/// One node as the control plane last heard it, plus what that means now.
#[derive(Debug, Clone, Serialize)]
pub struct EdgeView {
    pub edge_id: String,
    pub region: Option<String>,
    pub label: Option<String>,
    pub version: String,
    pub started_at_ms: i64,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// Seconds since the last heartbeat, which is what "is it alive" actually means.
    pub last_seen_age_s: i64,
    pub uptime_s: i64,
    pub active_revision: i64,
    pub acked_at_ms: Option<i64>,
    /// True when this node is serving the revision the fleet is supposed to be on.
    pub up_to_date: bool,
    pub draining: bool,
    /// online, degraded or offline. Derived, never stored - a stored status would be
    /// wrong the moment a node goes quiet without saying so.
    pub status: &'static str,
    /// Why it is not simply online, for the one case where that needs a sentence.
    pub note: Option<String>,
    pub cpu_percent: f64,
    pub memory_bytes: i64,
    pub memory_total_bytes: i64,
    pub connections_active: i64,
    pub requests_total: i64,
    pub requests_per_sec: f64,
    pub cache_entries: i64,
    pub cache_bytes: i64,
    pub zones: i64,
    pub origins_total: i64,
    pub origins_healthy: i64,
    pub certificates: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenInfo {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &str) -> Result<Db> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path).with_context(|| format!("opening {path}"))?
        };
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
            .ok();
        conn.execute_batch(SCHEMA).context("creating schema")?;
        /* CREATE TABLE IF NOT EXISTS does nothing to a table that already exists, so a
           database from before these columns needs them added rather than assumed */
        for (column, kind) in [("country", "TEXT"), ("asn", "INTEGER")] {
            add_column(&conn, "events", column, kind)?;
        }

        Ok(Db {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(conn) => conn,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Store a new revision and make it the active one.
    pub fn put_config(&self, yaml: &str, note: &str, now: i64) -> Result<i64> {
        /* validated by the edge's own parser, so the control plane can never hand
           out a config the data plane would refuse */
        cloudflint_edge::config::parse(yaml).context("config is not valid")?;

        let conn = self.lock();
        conn.execute(
            "INSERT INTO revisions (yaml, note, created_at) VALUES (?1, ?2, ?3)",
            params![yaml, note, now],
        )?;
        let id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO active (id, revision_id) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET revision_id = excluded.revision_id",
            params![id],
        )?;
        Ok(id)
    }

    pub fn active_config(&self) -> Result<Option<ActiveConfig>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT r.id, r.yaml, r.note, r.created_at
             FROM revisions r JOIN active a ON a.revision_id = r.id",
        )?;
        let mut rows = stmt.query([])?;

        match rows.next()? {
            Some(row) => Ok(Some(ActiveConfig {
                revision: row.get(0)?,
                yaml: row.get(1)?,
                note: row.get(2)?,
                created_at: row.get(3)?,
            })),
            None => Ok(None),
        }
    }

    pub fn revisions(&self, limit: usize) -> Result<Vec<Revision>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT r.id, r.note, r.created_at,
                    COALESCE((SELECT 1 FROM active a WHERE a.revision_id = r.id), 0)
             FROM revisions r ORDER BY r.id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(Revision {
                id: row.get(0)?,
                note: row.get(1)?,
                created_at: row.get(2)?,
                active: row.get::<_, i64>(3)? == 1,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Roll back (or forward) to an existing revision without copying it.
    pub fn activate(&self, id: i64) -> Result<()> {
        let conn = self.lock();
        let exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM revisions WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )?;
        if exists == 0 {
            bail!("no revision {id}");
        }
        conn.execute(
            "INSERT INTO active (id, revision_id) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET revision_id = excluded.revision_id",
            params![id],
        )?;
        Ok(())
    }

    /// Record a heartbeat, registering the node if this is the first one.
    ///
    /// Registration is not a separate call on purpose: a node that can heartbeat is
    /// registered, and one that cannot is not interesting. That also means a control
    /// plane restarting, or its database being replaced, heals itself within one
    /// interval instead of needing every edge to be told to enrol again.
    pub fn record_heartbeat(&self, beat: &cloudflint_edge::fleet::Heartbeat, now: i64) -> Result<()> {
        let certificates = serde_json::to_string(&beat.certificates).unwrap_or_else(|_| "[]".into());
        let conn = self.lock();

        /* acked_at is kept when the revision has not changed, so it records when this
           node *reached* the revision rather than when it last mentioned it */
        conn.execute(
            "INSERT INTO edges (
                 edge_id, region, label, version, started_at_ms, first_seen_ms, last_seen_ms,
                 active_revision, acked_at_ms, draining, cpu_percent, memory_bytes,
                 memory_total_bytes, connections_active, requests_total, requests_per_sec,
                 cache_entries, cache_bytes, zones, origins_total, origins_healthy, certificates
             ) VALUES (?1,?2,?3,?4,?5,?6,?6,?7,?6,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)
             ON CONFLICT(edge_id) DO UPDATE SET
                 region = excluded.region,
                 label = excluded.label,
                 version = excluded.version,
                 started_at_ms = excluded.started_at_ms,
                 last_seen_ms = excluded.last_seen_ms,
                 acked_at_ms = CASE
                     WHEN edges.active_revision = excluded.active_revision THEN edges.acked_at_ms
                     ELSE excluded.last_seen_ms
                 END,
                 active_revision = excluded.active_revision,
                 draining = excluded.draining,
                 cpu_percent = excluded.cpu_percent,
                 memory_bytes = excluded.memory_bytes,
                 memory_total_bytes = excluded.memory_total_bytes,
                 connections_active = excluded.connections_active,
                 requests_total = excluded.requests_total,
                 requests_per_sec = excluded.requests_per_sec,
                 cache_entries = excluded.cache_entries,
                 cache_bytes = excluded.cache_bytes,
                 zones = excluded.zones,
                 origins_total = excluded.origins_total,
                 origins_healthy = excluded.origins_healthy,
                 certificates = excluded.certificates",
            params![
                beat.edge_id,
                beat.region,
                beat.label,
                beat.version,
                beat.started_at_ms as i64,
                now,
                beat.active_revision,
                beat.draining as i64,
                beat.cpu_percent,
                beat.memory_bytes as i64,
                beat.memory_total_bytes as i64,
                beat.connections_active as i64,
                beat.requests_total as i64,
                beat.requests_per_sec,
                beat.cache_entries as i64,
                beat.cache_bytes as i64,
                beat.zones as i64,
                beat.origins_total as i64,
                beat.origins_healthy as i64,
                certificates,
            ],
        )?;
        Ok(())
    }

    /// The whole fleet, most recently heard from first.
    ///
    /// `offline_after_s` decides what counts as gone; it comes from the caller because
    /// it is derived from the heartbeat interval, which is the edge's setting.
    pub fn edges(&self, desired_revision: Option<i64>, offline_after_s: i64, now: i64) -> Result<Vec<EdgeView>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT edge_id, region, label, version, started_at_ms, first_seen_ms, last_seen_ms,
                    active_revision, acked_at_ms, draining, cpu_percent, memory_bytes,
                    memory_total_bytes, connections_active, requests_total, requests_per_sec,
                    cache_entries, cache_bytes, zones, origins_total, origins_healthy, certificates
             FROM edges ORDER BY last_seen_ms DESC",
        )?;

        /* built without a status first: "outdated" is relative to the newest version
           anywhere in the fleet, which is not knowable while still reading rows */
        let rows = stmt.query_map([], |row| {
            let last_seen_ms: i64 = row.get(6)?;
            let started_at_ms: i64 = row.get(4)?;
            let active_revision: i64 = row.get(7)?;
            let certificates: String = row.get(21)?;

            Ok(EdgeView {
                edge_id: row.get(0)?,
                region: row.get(1)?,
                label: row.get(2)?,
                version: row.get(3)?,
                started_at_ms,
                first_seen_ms: row.get(5)?,
                last_seen_ms,
                last_seen_age_s: (now - last_seen_ms).max(0) / 1000,
                uptime_s: match started_at_ms > 0 {
                    true => (last_seen_ms - started_at_ms).max(0) / 1000,
                    false => 0,
                },
                active_revision,
                acked_at_ms: row.get(8)?,
                up_to_date: match desired_revision {
                    Some(want) => active_revision == want,
                    None => true,
                },
                draining: row.get::<_, i64>(9)? == 1,
                /* filled in below, once the whole fleet is in hand */
                status: "healthy",
                note: None,
                cpu_percent: row.get(10)?,
                memory_bytes: row.get(11)?,
                memory_total_bytes: row.get(12)?,
                connections_active: row.get(13)?,
                requests_total: row.get(14)?,
                requests_per_sec: row.get(15)?,
                cache_entries: row.get(16)?,
                cache_bytes: row.get(17)?,
                zones: row.get(18)?,
                origins_total: row.get(19)?,
                origins_healthy: row.get(20)?,
                /* stored as text because sqlite has no json type worth using; parsed
                   back here so the dashboard gets structure rather than a string */
                certificates: serde_json::from_str(&certificates)
                    .unwrap_or(serde_json::Value::Array(vec![])),
            })
        })?;
        let mut edges = rows.collect::<rusqlite::Result<Vec<_>>>()?;

        /* an offline node's version is stale news and should not hold the fleet's
           "newest" back - otherwise one forgotten box makes every live node look current */
        let newest = newest_version(
            edges
                .iter()
                .filter(|e| e.last_seen_age_s <= offline_after_s)
                .map(|e| e.version.clone()),
        );

        for edge in &mut edges {
            let (status, note) = status_of(&Judgement {
                last_seen_age_s: edge.last_seen_age_s,
                offline_after_s,
                draining: edge.draining,
                desired_revision,
                active_revision: edge.active_revision,
                origins_total: edge.origins_total,
                origins_healthy: edge.origins_healthy,
                version: &edge.version,
                newest_version: &newest,
            });
            edge.status = status;
            edge.note = note;
        }
        Ok(edges)
    }

    /// Forget a node. For one that has been decommissioned - otherwise it sits in the
    /// fleet view as permanently offline.
    pub fn forget_edge(&self, edge_id: &str) -> Result<bool> {
        let conn = self.lock();
        Ok(conn.execute("DELETE FROM edges WHERE edge_id = ?1", params![edge_id])? > 0)
    }

    /// Only the hash is stored. The token itself is shown once, when it is minted.
    pub fn add_token(&self, name: &str, token: &str, now: i64) -> Result<i64> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO tokens (name, hash, created_at) VALUES (?1, ?2, ?3)",
            params![name, cloudflint_edge::auth::hash(token), now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// The name behind a presented token, or None.
    ///
    /// The lookup is by hash, so there is no secret to compare in variable time - an
    /// attacker who could measure this would learn which hash they had already found.
    pub fn token_holder(&self, presented: &str, now: i64) -> Result<Option<String>> {
        let conn = self.lock();
        let hash = cloudflint_edge::auth::hash(presented);

        let found: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, name FROM tokens WHERE hash = ?1",
                params![hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        match found {
            Some((id, name)) => {
                let _ = conn.execute(
                    "UPDATE tokens SET last_used_at = ?1 WHERE id = ?2",
                    params![now, id],
                );
                Ok(Some(name))
            }
            None => Ok(None),
        }
    }

    pub fn tokens(&self) -> Result<Vec<TokenInfo>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, last_used_at FROM tokens ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TokenInfo {
                id: row.get(0)?,
                name: row.get(1)?,
                created_at: row.get(2)?,
                last_used_at: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn token_count(&self) -> Result<i64> {
        let conn = self.lock();
        Ok(conn.query_row("SELECT COUNT(*) FROM tokens", [], |row| row.get(0))?)
    }

    pub fn revoke_token(&self, id: i64) -> Result<bool> {
        let conn = self.lock();
        Ok(conn.execute("DELETE FROM tokens WHERE id = ?1", params![id])? > 0)
    }

    /// Counts per time bucket, for the traffic chart. Bucket width is derived from
    /// the window so the chart always has roughly the same number of bars.
    pub fn timeseries(
        &self,
        zone: Option<&str>,
        since_ms: i64,
        buckets: i64,
    ) -> Result<Vec<Bucket>> {
        let conn = self.lock();
        let all_zones = zone.is_none();
        let zone = zone.unwrap_or("");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let width = ((now - since_ms) / buckets.clamp(4, 500)).max(1000);

        let mut stmt = conn.prepare(
            "SELECT (at_ms / ?4) * ?4 AS t,
                    COUNT(*),
                    COALESCE(SUM(status = 403), 0),
                    COALESCE(SUM(status = 429), 0),
                    COALESCE(SUM(status >= 500), 0),
                    COALESCE(SUM(cache = 'HIT' OR cache = 'STALE' OR cache = 'STALE-ERROR'), 0),
                    COALESCE(MAX(duration_us), 0)
             FROM events
             WHERE at_ms >= ?1 AND (?2 OR zone = ?3)
             GROUP BY t ORDER BY t",
        )?;

        let rows = stmt.query_map(params![since_ms, all_zones, zone, width], |row| {
            Ok(Bucket {
                at_ms: row.get(0)?,
                requests: row.get::<_, i64>(1)? as u64,
                blocked: row.get::<_, i64>(2)? as u64,
                limited: row.get::<_, i64>(3)? as u64,
                errors: row.get::<_, i64>(4)? as u64,
                cache_hits: row.get::<_, i64>(5)? as u64,
                /* the slowest request in the bucket - honest, and cheaper than a
                   percentile per bucket */
                p95_us: row.get::<_, i64>(6)? as u64,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn insert_events(&self, events: &[Event]) -> Result<usize> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO events
                 (at_ms, zone, host, method, path, status, duration_us, decided_by, cache,
                  client_ip, country, asn)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            )?;
            for e in events {
                stmt.execute(params![
                    e.at_ms as i64,
                    e.zone,
                    e.host,
                    e.method,
                    e.path,
                    e.status as i64,
                    e.duration_us as i64,
                    e.decided_by,
                    e.cache,
                    e.client_ip,
                    e.country,
                    e.asn,
                ])?;
            }
        }
        tx.commit()?;
        Ok(events.len())
    }

    /// Drop events older than `keep_ms`. Called on ingest, so it needs to be cheap.
    pub fn prune_events(&self, before_ms: i64) -> Result<usize> {
        let conn = self.lock();
        Ok(conn.execute("DELETE FROM events WHERE at_ms < ?1", params![before_ms])?)
    }

    pub fn summary(&self, zone: Option<&str>, since_ms: i64) -> Result<Summary> {
        let conn = self.lock();
        let zone_filter = zone.unwrap_or("");
        let all_zones = zone.is_none();

        let mut summary = Summary::default();

        let row = conn.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(status >= 500), 0),
                    COALESCE(SUM(status = 403), 0),
                    COALESCE(SUM(status = 429), 0),
                    COALESCE(SUM(cache = 'HIT' OR cache = 'STALE' OR cache = 'STALE-ERROR'), 0),
                    COALESCE(SUM(cache IS NOT NULL), 0)
             FROM events
             WHERE at_ms >= ?1 AND (?2 OR zone = ?3)",
            params![since_ms, all_zones, zone_filter],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )?;

        summary.requests = row.0 as u64;
        summary.errors = row.1 as u64;
        summary.blocked = row.2 as u64;
        summary.rate_limited = row.3 as u64;
        summary.cache_hits = row.4 as u64;
        summary.cache_eligible = row.5 as u64;

        if summary.requests > 0 {
            summary.p50_us = percentile(&conn, since_ms, all_zones, zone_filter, row.0, 50)?;
            summary.p95_us = percentile(&conn, since_ms, all_zones, zone_filter, row.0, 95)?;
        }

        summary.by_stage = group(
            &conn,
            "decided_by",
            since_ms,
            all_zones,
            zone_filter,
            usize::MAX,
        )?;
        summary.top_paths = group(&conn, "path", since_ms, all_zones, zone_filter, 10)?;
        summary.top_ips = group(&conn, "client_ip", since_ms, all_zones, zone_filter, 10)?;
        /* NULL rows are dropped rather than bucketed as "unknown": a request nobody could
           place is not a country, and showing it as one would put it top of the chart */
        summary.top_countries = group(&conn, "country", since_ms, all_zones, zone_filter, 15)?;
        summary.top_asns = group(&conn, "asn", since_ms, all_zones, zone_filter, 15)?;

        Ok(summary)
    }
}

/// Everything a node's status is derived from. A struct rather than nine arguments,
/// which is the point at which a signature stops being readable.
pub struct Judgement<'a> {
    pub last_seen_age_s: i64,
    pub offline_after_s: i64,
    pub draining: bool,
    pub desired_revision: Option<i64>,
    pub active_revision: i64,
    pub origins_total: i64,
    pub origins_healthy: i64,
    pub version: &'a str,
    /// The newest version anywhere in the fleet. A node behind it is `outdated` - which
    /// is only knowable by looking at every node, so it cannot be decided per row.
    pub newest_version: &'a str,
}

/// What to call a node, and why.
///
/// Derived on every read rather than stored, because the interesting state is *silence*
/// and silence does not arrive as an update. A node that dies without a word would keep
/// whatever status it last wrote, forever, which is precisely the case this has to get
/// right.
///
/// Order is the whole design, worst first:
///
/// - `offline` beats everything: nothing else can be known about a node that isn't talking.
/// - `degraded` is next and covers the two states that are about *this node's* health -
///   draining, and origins it cannot reach. Draining outranks config because a node on its
///   way out is expected to stop taking config, and reporting that as a rollout failure
///   would cry wolf on every deploy.
/// - `config_mismatch` before `outdated`: running the wrong rules is a security question,
///   running an old build is a maintenance one.
fn status_of(j: &Judgement) -> (&'static str, Option<String>) {
    if j.last_seen_age_s > j.offline_after_s {
        return (
            "offline",
            Some(format!("no heartbeat for {}s", j.last_seen_age_s)),
        );
    }
    if j.draining {
        return ("degraded", Some("draining, on its way out".into()));
    }
    if j.origins_total > 0 && j.origins_healthy == 0 {
        return (
            "degraded",
            Some("every origin is unhealthy on this node".into()),
        );
    }

    /* -1 means this node follows a local file, so there is no revision to be behind */
    if let Some(want) = j.desired_revision {
        if j.active_revision != want && j.active_revision != cloudflint_edge::fleet::NO_REVISION {
            return (
                "config_mismatch",
                Some(format!(
                    "on config revision {}, fleet is on {want}",
                    j.active_revision
                )),
            );
        }
    }
    if is_older(j.version, j.newest_version) {
        return (
            "outdated",
            Some(format!(
                "running {}, the fleet has {}",
                j.version, j.newest_version
            )),
        );
    }
    if j.origins_total > 0 && j.origins_healthy < j.origins_total {
        return (
            "degraded",
            Some(format!(
                "{} of {} origins healthy",
                j.origins_healthy, j.origins_total
            )),
        );
    }
    ("healthy", None)
}

/// Compare two dotted version strings numerically, component by component.
///
/// String order is wrong for versions the moment a number reaches double digits - "0.10.0"
/// sorts before "0.9.0" - and this decides whether a node is called outdated, so getting
/// it wrong would flag a freshly deployed node as stale. Anything non-numeric (a `-rc1`
/// suffix, an empty string from a node too old to report one) compares as 0, which keeps
/// it from ever being called *newer* than a release.
fn is_older(version: &str, newest: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> {
        v.split(['.', '-', '+'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (a, b) = (parts(version), parts(newest));
    let len = a.len().max(b.len());

    for i in 0..len {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x < y;
        }
    }
    false
}

/// The newest version any node reports, which is what the others are measured against.
pub fn newest_version(versions: impl IntoIterator<Item = String>) -> String {
    versions.into_iter().fold(String::new(), |best, v| {
        match is_older(&best, &v) {
            true => v,
            false => best,
        }
    })
}

/// Add a column to an existing table, if it is not already there.
///
/// SQLite has no `ADD COLUMN IF NOT EXISTS`, and re-adding one is an error rather than a
/// no-op, so the table is asked what it has first. This is the whole migration story: the
/// events table is append-only history, and every added column is nullable.
fn add_column(conn: &Connection, table: &str, column: &str, kind: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let existing: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;

    if !existing.iter().any(|c| c == column) {
        conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {kind}"), [])
            .with_context(|| format!("adding {table}.{column}"))?;
    }
    Ok(())
}

/// Nearest-rank percentile. Exact rather than estimated, which is affordable at the
/// volumes a single node produces and avoids explaining a sketch to anyone.
fn percentile(
    conn: &Connection,
    since_ms: i64,
    all_zones: bool,
    zone: &str,
    count: i64,
    pct: i64,
) -> Result<u64> {
    let offset = ((count * pct) / 100).clamp(0, count.saturating_sub(1));
    let value: i64 = conn.query_row(
        "SELECT duration_us FROM events
         WHERE at_ms >= ?1 AND (?2 OR zone = ?3)
         ORDER BY duration_us LIMIT 1 OFFSET ?4",
        params![since_ms, all_zones, zone, offset],
        |row| row.get(0),
    )?;
    Ok(value as u64)
}


fn group(
    conn: &Connection,
    column: &str,
    since_ms: i64,
    all_zones: bool,
    zone: &str,
    limit: usize,
) -> Result<Vec<(String, u64)>> {
    /* the column name is ours, never a caller's - values still go through params */
    let sql = format!(
        "SELECT CAST({column} AS TEXT), COUNT(*) AS n FROM events
         WHERE at_ms >= ?1 AND (?2 OR zone = ?3) AND {column} IS NOT NULL
         GROUP BY {column} ORDER BY n DESC LIMIT ?4"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params![since_ms, all_zones, zone, limit.min(1000) as i64],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64)),
    )?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
#[cfg(test)]
mod tests {
    use super::*;

    /// A node that has just reported in, healthy and on the right config.
    fn healthy() -> Judgement<'static> {
        Judgement {
            last_seen_age_s: 2,
            offline_after_s: 45,
            draining: false,
            desired_revision: Some(7),
            active_revision: 7,
            origins_total: 2,
            origins_healthy: 2,
            version: "1.2.3",
            newest_version: "1.2.3",
        }
    }

    fn call(j: Judgement) -> (&'static str, Option<String>) {
        status_of(&j)
    }

    #[test]
    fn a_node_reporting_in_and_keeping_up_is_healthy() {
        let (status, note) = call(healthy());
        assert_eq!(status, "healthy");
        assert!(note.is_none(), "healthy needs no explanation");
    }

    #[test]
    fn silence_past_the_deadline_is_offline() {
        let mut args = healthy();
        args.last_seen_age_s = 46;
        let (status, note) = call(args);
        assert_eq!(status, "offline");
        assert!(note.unwrap().contains("46s"));
    }

    #[test]
    fn one_missed_beat_is_not_offline() {
        /* the threshold is three intervals precisely so a single lost packet or a busy
           moment does not take a node out of the fleet */
        let mut args = healthy();
        args.last_seen_age_s = 45;
        assert_eq!(call(args).0, "healthy");
    }

    #[test]
    fn offline_beats_everything_else() {
        /* nothing else can be known about a node that is not talking, so a stale
           report of being behind or draining must not outrank the silence */
        let mut args = healthy();
        args.last_seen_age_s = 600;
        args.draining = true;
        args.active_revision = 1;
        args.origins_healthy = 0;
        args.version = "0.9.0";
        assert_eq!(call(args).0, "offline");
    }

    #[test]
    fn draining_outranks_being_behind() {
        /* a node on its way out is expected to stop taking config; reporting that as a
           rollout failure would cry wolf on every deploy */
        let mut args = healthy();
        args.draining = true;
        args.active_revision = 1;
        let (status, note) = call(args);
        assert_eq!(status, "degraded");
        assert!(note.unwrap().contains("draining"));
    }

    #[test]
    fn every_origin_down_outranks_being_behind() {
        let mut args = healthy();
        args.active_revision = 1;
        args.origins_healthy = 0;
        assert!(call(args).1.unwrap().contains("every origin"));
    }

    #[test]
    fn being_behind_on_config_is_its_own_state() {
        let mut args = healthy();
        args.active_revision = 5;
        let (status, note) = call(args);
        assert_eq!(status, "config_mismatch");
        let note = note.unwrap();
        assert!(note.contains('5') && note.contains('7'), "note was {note}");
    }

    #[test]
    fn a_node_on_a_local_file_is_never_behind() {
        let mut args = healthy();
        args.active_revision = cloudflint_edge::fleet::NO_REVISION;
        assert_eq!(call(args).0, "healthy");
    }

    #[test]
    fn no_desired_revision_means_nothing_to_compare() {
        let mut args = healthy();
        args.desired_revision = None;
        args.active_revision = 3;
        assert_eq!(call(args).0, "healthy");
    }

    #[test]
    fn an_old_build_is_outdated() {
        let mut args = healthy();
        args.version = "1.2.2";
        let (status, note) = call(args);
        assert_eq!(status, "outdated");
        let note = note.unwrap();
        assert!(note.contains("1.2.2") && note.contains("1.2.3"), "note was {note}");
    }

    #[test]
    fn the_wrong_config_matters_more_than_an_old_build() {
        /* running the wrong rules is a security question; running an old binary is a
           maintenance one, and a node doing both should say the more serious thing */
        let mut args = healthy();
        args.version = "1.0.0";
        args.active_revision = 5;
        assert_eq!(call(args).0, "config_mismatch");
    }

    #[test]
    fn a_node_ahead_of_the_fleet_is_not_outdated() {
        /* mid-deploy the first upgraded node is newer than "newest" was a moment ago */
        let mut args = healthy();
        args.version = "2.0.0";
        args.newest_version = "1.2.3";
        assert_eq!(call(args).0, "healthy");
    }

    #[test]
    fn some_origins_down_is_degraded_but_lower_priority() {
        let mut args = healthy();
        args.origins_healthy = 1;
        let (status, note) = call(args);
        assert_eq!(status, "degraded");
        assert!(note.unwrap().contains("1 of 2"));
    }

    #[test]
    fn a_node_serving_no_origins_at_all_is_not_called_unhealthy() {
        /* zero of zero healthy is a node with no zones, not a broken one - the guard
           on origins_total is what keeps this from reading as an outage */
        let mut args = healthy();
        args.origins_total = 0;
        args.origins_healthy = 0;
        assert_eq!(call(args).0, "healthy");
    }

    #[test]
    fn versions_compare_as_numbers_not_as_text() {
        /* the bug this exists to prevent: "0.10.0" sorts before "0.9.0" as a string,
           which would call a freshly deployed node outdated */
        assert!(is_older("0.9.0", "0.10.0"));
        assert!(!is_older("0.10.0", "0.9.0"));
        assert!(is_older("1.2.3", "1.2.10"));
        assert!(!is_older("1.2.3", "1.2.3"));
        assert!(is_older("1.2", "1.2.1"), "a missing component counts as zero");
        assert!(!is_older("1.2.0", "1.2"));
    }

    #[test]
    fn an_unparseable_version_is_never_called_newer() {
        /* a node too old to report one, or a build with a suffix we do not understand */
        assert!(is_older("", "1.0.0"));
        assert!(!is_older("1.0.0", ""));
        assert!(is_older("1.0.0-rc1", "1.0.1"));
    }

    #[test]
    fn the_newest_version_is_the_highest_anyone_reports() {
        let versions = ["1.2.3", "0.9.0", "1.10.0", "1.2.10"].map(String::from);
        assert_eq!(newest_version(versions), "1.10.0");
        assert_eq!(newest_version(Vec::new()), "");
    }

    #[test]
    fn an_acked_revision_keeps_its_timestamp_across_heartbeats() {
        let db = Db::open(":memory:").unwrap();
        let mut beat = cloudflint_edge::fleet::Heartbeat {
            edge_id: "e".into(),
            region: None,
            label: None,
            version: "0.1.0".into(),
            started_at_ms: 0,
            uptime_s: 0,
            active_revision: 4,
            draining: false,
            cpu_percent: 0.0,
            memory_bytes: 0,
            memory_total_bytes: 0,
            connections_active: 0,
            requests_total: 0,
            requests_per_sec: 0.0,
            cache_entries: 0,
            cache_bytes: 0,
            zones: 0,
            origins_total: 0,
            origins_healthy: 0,
            certificates: vec![],
        };

        db.record_heartbeat(&beat, 1_000).unwrap();
        let first = db.edges(Some(4), 45, 1_000).unwrap()[0].acked_at_ms;
        assert_eq!(first, Some(1_000));

        /* same revision, later beat: the ack is when it *reached* that revision, so it
           must not creep forward every time the node mentions it again */
        db.record_heartbeat(&beat, 9_000).unwrap();
        assert_eq!(db.edges(Some(4), 45, 9_000).unwrap()[0].acked_at_ms, Some(1_000));

        /* a new revision is a new ack */
        beat.active_revision = 5;
        db.record_heartbeat(&beat, 12_000).unwrap();
        assert_eq!(db.edges(Some(5), 45, 12_000).unwrap()[0].acked_at_ms, Some(12_000));
    }

    #[test]
    fn a_database_from_before_the_geo_columns_gets_them_added() {
        /* the case CREATE TABLE IF NOT EXISTS silently does nothing for: a real deployment
           whose events table predates these columns. without the migration every insert
           would fail with "table events has no column named country" */
        let path = std::env::temp_dir().join(format!(
            "cloudflint-migrate-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);

        {
            /* the old schema, exactly as it was before geo */
            let old = Connection::open(&path).unwrap();
            old.execute_batch(
                "CREATE TABLE events (
                     at_ms INTEGER NOT NULL, zone TEXT NOT NULL, host TEXT NOT NULL,
                     method TEXT NOT NULL, path TEXT NOT NULL, status INTEGER NOT NULL,
                     duration_us INTEGER NOT NULL, decided_by TEXT NOT NULL, cache TEXT,
                     client_ip TEXT NOT NULL
                 );
                 INSERT INTO events VALUES (1000,'demo','demo.local','GET','/',200,10,'origin',NULL,'1.2.3.4');",
            )
            .unwrap();
        }

        let db = Db::open(path.to_str().unwrap()).expect("an older database should migrate");

        /* the old row survived, and a new one with geo goes in */
        db.insert_events(&[Event {
            at_ms: 2000,
            zone: "demo".into(),
            host: "demo.local".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            duration_us: 20,
            decided_by: "origin".into(),
            cache: None,
            client_ip: "5.6.7.8".into(),
            country: Some("GB".into()),
            asn: Some(64512),
        }])
        .expect("inserting with geo should work after the migration");

        let summary = db.summary(None, 0).unwrap();
        assert_eq!(summary.requests, 2, "the pre-migration row is still there");
        /* only the new row has a country, and the old NULL is not a bucket */
        assert_eq!(summary.top_countries, vec![("GB".to_string(), 1)]);
        assert_eq!(summary.top_asns, vec![("64512".to_string(), 1)]);

        /* and opening it twice does not try to add the columns again */
        drop(db);
        assert!(Db::open(path.to_str().unwrap()).is_ok(), "reopening should be a no-op");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn requests_nobody_could_place_are_left_out_rather_than_bucketed() {
        let db = Db::open(":memory:").unwrap();
        let plain = |ip: &str, country: Option<&str>| Event {
            at_ms: 1000,
            zone: "demo".into(),
            host: "demo.local".into(),
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            duration_us: 10,
            decided_by: "origin".into(),
            cache: None,
            client_ip: ip.into(),
            country: country.map(str::to_owned),
            asn: None,
        };
        db.insert_events(&[
            plain("1.1.1.1", Some("GB")),
            plain("2.2.2.2", None),
            plain("3.3.3.3", None),
        ])
        .unwrap();

        let summary = db.summary(None, 0).unwrap();
        assert_eq!(summary.requests, 3);
        /* two of three had no country, and they must not out-rank the one that did */
        assert_eq!(summary.top_countries, vec![("GB".to_string(), 1)]);
        assert!(summary.top_asns.is_empty(), "no asns were reported at all");
    }

    #[test]
    fn first_seen_survives_later_heartbeats() {
        let db = Db::open(":memory:").unwrap();
        let beat = cloudflint_edge::fleet::Heartbeat {
            edge_id: "e".into(),
            region: None,
            label: None,
            version: "0.1.0".into(),
            started_at_ms: 500,
            uptime_s: 0,
            active_revision: -1,
            draining: false,
            cpu_percent: 0.0,
            memory_bytes: 0,
            memory_total_bytes: 0,
            connections_active: 0,
            requests_total: 0,
            requests_per_sec: 0.0,
            cache_entries: 0,
            cache_bytes: 0,
            zones: 0,
            origins_total: 0,
            origins_healthy: 0,
            certificates: vec![],
        };

        db.record_heartbeat(&beat, 1_000).unwrap();
        db.record_heartbeat(&beat, 5_000).unwrap();

        let view = &db.edges(None, 45, 5_000).unwrap()[0];
        assert_eq!(view.first_seen_ms, 1_000, "first seen is when we first heard of it");
        assert_eq!(view.last_seen_ms, 5_000);
        assert_eq!(view.last_seen_age_s, 0);
        /* uptime is measured from the node's own clock, against the beat we last had */
        assert_eq!(view.uptime_s, (5_000 - 500) / 1000);
    }
}
