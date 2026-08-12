//! SQLite, behind a mutex.
//!
//! The control plane is not in anyone's request path, so a single connection under a
//! lock is plenty and avoids a pool's worth of machinery. The blocking calls are
//! short enough not to be worth `spawn_blocking`; if that stops being true, the
//! honest fix is a real pool rather than pretending.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{bail, Context, Result};
use cloudveil_edge::analytics::Event;
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
    client_ip   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS events_at ON events(at_ms);
CREATE INDEX IF NOT EXISTS events_zone_at ON events(zone, at_ms);
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
        cloudveil_edge::config::parse(yaml).context("config is not valid")?;

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

    pub fn insert_events(&self, events: &[Event]) -> Result<usize> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO events
                 (at_ms, zone, host, method, path, status, duration_us, decided_by, cache, client_ip)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
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

        Ok(summary)
    }
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
        "SELECT {column}, COUNT(*) AS n FROM events
         WHERE at_ms >= ?1 AND (?2 OR zone = ?3)
         GROUP BY {column} ORDER BY n DESC LIMIT ?4"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params![since_ms, all_zones, zone, limit.min(1000) as i64],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64)),
    )?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
