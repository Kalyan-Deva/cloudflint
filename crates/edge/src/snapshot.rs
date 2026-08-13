//! The config the request path reads.
//!
//! Readers take an `Arc`, writers swap the pointer. A reload costs one atomic store and
//! never blocks a request, and a config that fails to parse is dropped on the floor -
//! the edge keeps serving the last good one rather than falling over.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use tracing::{info, warn};

use crate::config::{self, Config};

const POLL: Duration = Duration::from_secs(2);

pub struct Snapshot(ArcSwap<Config>);

impl Snapshot {
    pub fn new(cfg: Config) -> Self {
        Self(ArcSwap::from_pointee(cfg))
    }

    pub fn current(&self) -> Arc<Config> {
        self.0.load_full()
    }

    pub fn store(&self, cfg: Config) {
        self.0.store(Arc::new(cfg));
    }
}

/// Watch `path` and reload when it changes. Later this is where the control plane
/// snapshot pull goes; for now the file on disk is the source of truth.
pub fn watch(path: PathBuf, snap: Arc<Snapshot>) {
    watch_every(path, snap, POLL)
}

pub fn watch_every(path: PathBuf, snap: Arc<Snapshot>, every: Duration) {
    /* take the baseline here, not inside the task - anything written between this call
       and the task's first poll would otherwise look like it had always been there */
    let mut seen = fingerprint(&path);

    tokio::spawn(async move {
        let mut last_err = String::new();

        loop {
            tokio::time::sleep(every).await;

            let now = fingerprint(&path);
            if now == seen {
                continue;
            }

            match config::load(&path) {
                Ok(cfg) => {
                    seen = now;
                    last_err.clear();

                    let running = snap.current();
                    if cfg.listen != running.listen {
                        warn!(
                            "listen address changed to {}, that needs a restart - still on {}",
                            cfg.listen, running.listen
                        );
                    }
                    info!("config reloaded, {} zone(s)", cfg.zones.len());
                    snap.store(cfg);
                }
                Err(e) => {
                    /* leave `seen` alone so a half-written file gets picked up next tick,
                       and don't repeat ourselves while the file stays broken */
                    let msg = format!("{e:#}");
                    if msg != last_err {
                        warn!("config reload failed, staying on the running config: {msg}");
                        last_err = msg;
                    }
                }
            }
        }
    });
}

/// Pull config from the control plane instead of a file.
///
/// Same contract as the file watcher: a snapshot that doesn't parse is logged and
/// dropped, and an unreachable control plane changes nothing. The edge keeps serving
/// whatever it last agreed with - a control plane outage must not become an outage.
pub fn watch_remote(base: String, snap: Arc<Snapshot>, every: Duration) {
    let cp = match crate::cp::ControlPlane::from_env(&base) {
        Ok(cp) => cp,
        Err(e) => {
            warn!("cannot pull config from {base}: {e:#}");
            return;
        }
    };

    tokio::spawn(async move {
        let mut running = 0i64;
        let mut last_err = String::new();

        loop {
            tokio::time::sleep(every).await;

            match fetch(&cp).await {
                Ok(Some(pulled)) if pulled.revision != running => {
                    match config::parse(&pulled.yaml) {
                        Ok(cfg) => {
                            info!(
                                "config revision {} pulled from the control plane, {} zone(s)",
                                pulled.revision,
                                cfg.zones.len()
                            );
                            running = pulled.revision;
                            last_err.clear();
                            snap.store(cfg);
                        }
                        Err(e) => {
                            /* don't record the revision, so a fixed one still lands */
                            note_once(&mut last_err, format!("{e:#}"));
                        }
                    }
                }
                Ok(_) => last_err.clear(),
                Err(e) => note_once(&mut last_err, e),
            }
        }

        async fn fetch(cp: &crate::cp::ControlPlane) -> Result<Option<Pulled>, String> {
            let body = cp.get("/v1/config").await.map_err(|e| format!("{e:#}"))?;
            serde_json::from_slice::<Pulled>(&body)
                .map(Some)
                .map_err(|e| format!("control plane sent something unexpected: {e}"))
        }
    });
}

#[derive(serde::Deserialize)]
struct Pulled {
    revision: i64,
    yaml: String,
}

/// Log a recurring problem once rather than every poll.
fn note_once(last: &mut String, message: String) {
    if *last != message {
        warn!("config pull failed, staying on the running config: {message}");
        *last = message;
    }
}

/// mtime alone misses same-second rewrites often enough to be annoying; size is free.
fn fingerprint(path: &Path) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    const TICK: Duration = Duration::from_millis(20);

    fn temp_path(tag: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("cloudflint-{tag}-{}-{unique}.yaml", std::process::id()))
    }

    fn cfg_with(zone: &str) -> String {
        format!(
            "zones:\n  - name: {zone}\n    hostnames: [\"{zone}.local\"]\n    origin: {{ url: \"http://127.0.0.1:9\" }}\n"
        )
    }

    /// Polls until `check` passes or we give up, so tests don't race the watcher.
    async fn eventually(snap: &Snapshot, check: impl Fn(&Config) -> bool) -> bool {
        for _ in 0..100 {
            if check(&snap.current()) {
                return true;
            }
            tokio::time::sleep(TICK).await;
        }
        false
    }

    #[tokio::test]
    async fn picks_up_a_changed_file() {
        let path = temp_path("reload");
        std::fs::write(&path, cfg_with("before")).unwrap();

        let snap = Arc::new(Snapshot::new(config::load(&path).unwrap()));
        watch_every(path.clone(), snap.clone(), TICK);
        assert_eq!(snap.current().zones[0].name, "before");

        std::fs::write(&path, cfg_with("after")).unwrap();
        assert!(
            eventually(&snap, |c| c.zones[0].name == "after").await,
            "watcher never picked up the new config"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn keeps_the_running_config_when_the_new_one_is_broken() {
        let path = temp_path("broken");
        std::fs::write(&path, cfg_with("good")).unwrap();

        let snap = Arc::new(Snapshot::new(config::load(&path).unwrap()));
        watch_every(path.clone(), snap.clone(), TICK);

        std::fs::write(&path, "zones: [ this is not valid").unwrap();
        tokio::time::sleep(TICK * 10).await;
        assert_eq!(snap.current().zones[0].name, "good");

        /* and it recovers once the file is fixed, rather than needing a restart */
        std::fs::write(&path, cfg_with("fixed")).unwrap();
        assert!(
            eventually(&snap, |c| c.zones[0].name == "fixed").await,
            "watcher gave up after a bad config"
        );

        let _ = std::fs::remove_file(&path);
    }
}
