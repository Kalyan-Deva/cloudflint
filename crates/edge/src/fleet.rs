//! Who this node is, and telling the control plane how it is doing.
//!
//! A fleet is many edges and one control plane, and the control plane cannot go
//! looking for them: edges live behind NAT, come up in autoscaling groups and get
//! replaced without warning. So the edge reports in. Every `heartbeat_secs` it posts
//! its identity and a snapshot of itself, and the answer names the config revision it
//! is *supposed* to be running - which is how a rollout gets acknowledged.
//!
//! **Identity cannot come from the config file.** The config is fleet-wide: one
//! revision is pulled by every node, so anything in it is by definition the same
//! everywhere. A node's own name and region therefore come from the environment, the
//! same rule the credentials already follow - see `cp`.
//!
//! Nothing here is in the request path, and a control plane that is down changes
//! nothing except that the dashboard stops hearing from this node.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tracing::{debug, info, warn};

use crate::analytics::now_ms;
use crate::cp::ControlPlane;
use crate::Edge;

pub const ID_VAR: &str = "CLOUDFLINT_EDGE_ID";
pub const REGION_VAR: &str = "CLOUDFLINT_REGION";
pub const LABEL_VAR: &str = "CLOUDFLINT_EDGE_LABEL";

/// Revision value meaning "not following the control plane".
pub const NO_REVISION: i64 = -1;

/// What this node calls itself. Stable across restarts if you set `CLOUDFLINT_EDGE_ID`.
#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    pub edge_id: String,
    pub region: Option<String>,
    pub label: Option<String>,
    /// The build, so a fleet half way through a deploy is visible as one.
    pub version: &'static str,
}

impl Identity {
    pub fn from_env() -> Identity {
        let (edge_id, how) = match env(ID_VAR) {
            Some(id) => (id, "from the environment"),
            None => match hostname() {
                Some(host) => (host, "from the hostname"),
                None => (random_id(), "generated"),
            },
        };

        /* a generated id is a new node to the control plane every time this process
           restarts, which litters the fleet view with ghosts. worth saying out loud
           rather than quietly doing the wrong thing */
        if how == "generated" {
            warn!(
                "no {ID_VAR} and no hostname - using the generated id `{edge_id}`, which \
                 changes on every restart. set {ID_VAR} to keep one identity"
            );
        } else {
            debug!("edge id `{edge_id}` {how}");
        }

        Identity {
            edge_id,
            region: env(REGION_VAR),
            label: env(LABEL_VAR),
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// The machine's name, which in a container is the container - stable for as long as
/// that node exists, which is exactly the lifetime we want an id to have.
fn hostname() -> Option<String> {
    #[cfg(windows)]
    {
        env("COMPUTERNAME")
    }
    #[cfg(not(windows))]
    {
        /* the file rather than $HOSTNAME: the variable is a shell's, not the
           process's, and is usually absent under an init system or in a container */
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|h| h.trim().to_owned())
            .filter(|h| !h.is_empty())
            .or_else(|| env("HOSTNAME"))
    }
}

fn random_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 6];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        /* no entropy is not a reason to fail to start; the clock is unique enough to
           tell two nodes apart, which is all this fallback has to do */
        let ms = now_ms();
        bytes.copy_from_slice(&ms.to_be_bytes()[2..8]);
    }
    format!("edge-{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Everything the control plane is told, once per heartbeat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Heartbeat {
    pub edge_id: String,
    pub region: Option<String>,
    pub label: Option<String>,
    pub version: String,
    /// Wall clock, so the control plane can show when this node came up rather than
    /// only how long it has been up by the time anyone looks.
    pub started_at_ms: u64,
    pub uptime_s: u64,
    /// The revision actually being served, or -1 when following a local file.
    pub active_revision: i64,
    pub draining: bool,

    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub memory_total_bytes: u64,

    pub connections_active: u64,
    pub requests_total: u64,
    pub requests_per_sec: f64,

    pub cache_entries: u64,
    pub cache_bytes: u64,

    pub zones: usize,
    pub origins_total: usize,
    pub origins_healthy: usize,

    pub certificates: Vec<CertState>,
}

/// Per zone, whether the certificate this node is *serving* is the one it should be.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertState {
    pub zone: String,
    /// acme, manual or off.
    pub mode: String,
    /// valid, expiring, expired, not_loaded or none.
    pub status: String,
    /// True when a certificate is actually loaded, not merely configured.
    pub deployed: bool,
    pub not_after_ms: Option<i64>,
}

/// What the control plane says back.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ack {
    /// The revision this node is meant to be on. Compared against what it is on, this
    /// is the rollout state for this node.
    #[serde(default)]
    pub desired_revision: Option<i64>,
}

/// Samples the things that only make sense as a rate or need an OS call.
pub struct Sampler {
    system: Mutex<System>,
    pid: Pid,
    cores: usize,
    /// Requests counter and the moment it was read, for the next rate.
    last: Mutex<Option<(Instant, u64)>>,
}

impl Sampler {
    pub fn new() -> Sampler {
        Sampler {
            system: Mutex::new(System::new()),
            pid: Pid::from_u32(std::process::id()),
            /* logical cpus, because that is what sysinfo's per-core percentage is
               relative to. std knows this and cannot answer zero, so there is no
               divide-by-zero to guard below */
            cores: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
            last: Mutex::new(None),
        }
    }

    /// Process cpu as a share of the whole machine, and resident memory.
    ///
    /// sysinfo reports cpu per core, so a process using two cores flat reads as 200 -
    /// true, and not what "how busy is this node" means. Divided by the core count it
    /// is a percentage of the box, which is the number a fleet view wants.
    ///
    /// The first sample after start is always 0: a cpu percentage is work done between
    /// two observations and there has only been one.
    fn resources(&self) -> (f64, u64, u64) {
        let mut system = self.system.lock().unwrap_or_else(|e| e.into_inner());
        system.refresh_memory();
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );

        let total = system.total_memory();
        match system.process(self.pid) {
            Some(p) => {
                let cpu = (p.cpu_usage() as f64 / self.cores as f64).clamp(0.0, 100.0);
                (round2(cpu), p.memory(), total)
            }
            None => (0.0, 0, total),
        }
    }

    /// Requests per second since the previous heartbeat.
    fn rate(&self, requests_total: u64) -> f64 {
        let now = Instant::now();
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());

        let rate = match *last {
            Some((then, count)) => {
                let secs = now.duration_since(then).as_secs_f64();
                /* saturating: a counter can only go backwards if it was reset, and
                   reporting a negative rate for that is worse than reporting none */
                match secs > 0.0 {
                    true => round2(requests_total.saturating_sub(count) as f64 / secs),
                    false => 0.0,
                }
            }
            None => 0.0,
        };
        *last = Some((now, requests_total));
        rate
    }

    /// One complete picture of this node.
    pub fn sample(&self, edge: &Edge, identity: &Identity) -> Heartbeat {
        let cfg = edge.snap.current();
        let cache = edge.store.stats();
        let (cpu_percent, memory_bytes, memory_total_bytes) = self.resources();
        let requests_total = edge.metrics.requests.total();

        let mut origins_total = 0;
        let mut origins_healthy = 0;
        for zone in &cfg.zones {
            for (_, healthy) in edge.origins.report(&zone.name, &zone.origins) {
                origins_total += 1;
                if healthy {
                    origins_healthy += 1;
                }
            }
        }

        let live = edge.tls.as_ref().map(|t| t.report()).unwrap_or_default();
        let certificates = cfg
            .zones
            .iter()
            .filter(|z| z.tls.is_some())
            .map(|zone| {
                let cert = live.iter().find(|c| c.zone == zone.name);
                CertState {
                    zone: zone.name.clone(),
                    mode: match zone.acme {
                        true => "acme".into(),
                        false => "manual".into(),
                    },
                    /* what is loaded, not what is configured - they differ exactly
                       when something is wrong, which is when anyone looks */
                    status: cert.map(|c| c.status()).unwrap_or("not_loaded").to_owned(),
                    deployed: cert.is_some(),
                    not_after_ms: cert.map(|c| c.not_after_ms),
                }
            })
            .collect();

        let started_at_ms = edge.started_at_ms;
        Heartbeat {
            edge_id: identity.edge_id.clone(),
            region: identity.region.clone(),
            label: identity.label.clone(),
            version: identity.version.to_owned(),
            started_at_ms,
            uptime_s: now_ms().saturating_sub(started_at_ms) / 1000,
            active_revision: edge.revision.load(Ordering::Relaxed),
            draining: edge.shutdown.draining(),
            cpu_percent,
            memory_bytes,
            memory_total_bytes,
            connections_active: edge.metrics.connections_active.get(&[]).max(0.0) as u64,
            requests_total,
            requests_per_sec: self.rate(requests_total),
            cache_entries: cache.entries as u64,
            cache_bytes: cache.bytes as u64,
            zones: cfg.zones.len(),
            origins_total,
            origins_healthy,
            certificates,
        }
    }
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Report in, for as long as this process lives.
///
/// One heartbeat is sent immediately so a node appears in the fleet the moment it
/// starts rather than one interval later - the first minute after a deploy is exactly
/// when somebody is watching.
pub fn spawn(edge: Arc<Edge>, base: String, every: Duration, identity: Identity) {
    let cp = match ControlPlane::from_env(&base) {
        Ok(cp) => cp,
        Err(e) => {
            warn!("fleet heartbeats disabled, cannot reach the control plane: {e:#}");
            return;
        }
    };

    info!(
        "registering with the control plane as `{}`{} every {:?}",
        identity.edge_id,
        identity
            .region
            .as_deref()
            .map(|r| format!(" in {r}"))
            .unwrap_or_default(),
        every
    );

    tokio::spawn(async move {
        let sampler = Sampler::new();
        let mut last_err = String::new();
        let mut behind_since: Option<Instant> = None;

        loop {
            let beat = sampler.sample(&edge, &identity);
            let active = beat.active_revision;

            match send(&cp, &beat).await {
                Ok(ack) => {
                    if !last_err.is_empty() {
                        info!("control plane reachable again, heartbeats resumed");
                        last_err.clear();
                    }
                    behind_since = rollout_lag(ack.desired_revision, active, behind_since);
                }
                Err(e) => {
                    /* the same message every tick would drown the log for as long as
                       the control plane is down, which could be a long time */
                    if e != last_err {
                        warn!("heartbeat failed, will keep trying: {e}");
                        last_err = e;
                    }
                }
            }

            /* stop heartbeating the moment a drain starts, but send one last beat
               saying so first - the beat above already carries `draining` */
            tokio::select! {
                _ = tokio::time::sleep(every) => {}
                _ = edge.shutdown.signalled() => {
                    let mut goodbye = sampler.sample(&edge, &identity);
                    goodbye.draining = true;
                    let _ = send(&cp, &goodbye).await;
                    debug!("final heartbeat sent, this node is draining");
                    return;
                }
            }
        }
    });
}

/// Warn once when a node stays behind the fleet's config revision.
///
/// Being briefly behind is normal - the config puller runs on its own timer. Being
/// behind for a while means this node is not taking the config, which is the failure
/// a rollout view exists to show.
fn rollout_lag(desired: Option<i64>, active: i64, behind_since: Option<Instant>) -> Option<Instant> {
    const GRACE: Duration = Duration::from_secs(60);

    let desired = desired?;
    if active == desired || active == NO_REVISION {
        return None;
    }

    match behind_since {
        Some(since) if since.elapsed() >= GRACE => {
            warn!(
                "still on config revision {active} but the control plane wants {desired}, \
                 {}s after it was published",
                since.elapsed().as_secs()
            );
            /* reset the clock so this repeats occasionally rather than every tick */
            Some(Instant::now())
        }
        Some(since) => Some(since),
        None => Some(Instant::now()),
    }
}

async fn send(cp: &ControlPlane, beat: &Heartbeat) -> Result<Ack, String> {
    let body = serde_json::to_vec(beat).map_err(|e| format!("could not encode: {e}"))?;
    let path = format!("/v1/edges/{}/heartbeat", urlencode(&beat.edge_id));
    let answer = cp.post(&path, body).await.map_err(|e| format!("{e:#}"))?;

    /* an ack that doesn't parse is not worth failing the heartbeat over - the beat
       itself landed, which is the part that matters */
    Ok(serde_json::from_slice(&answer).unwrap_or_default())
}

/// Percent-encode anything that would change what path is being addressed.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Where a config revision gets published from, so the heartbeat can report it.
pub fn revision_cell() -> Arc<AtomicI64> {
    Arc::new(AtomicI64::new(NO_REVISION))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_id_wins_over_everything() {
        std::env::set_var(ID_VAR, "edge-lhr-1");
        let id = Identity::from_env();
        std::env::remove_var(ID_VAR);
        assert_eq!(id.edge_id, "edge-lhr-1");
    }

    #[test]
    fn an_id_is_always_produced() {
        /* whatever the environment offers, a node must be able to name itself or it
           can never appear in the fleet at all */
        let id = Identity::from_env();
        assert!(!id.edge_id.is_empty());
        assert_eq!(id.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn a_generated_id_is_unique() {
        assert_ne!(random_id(), random_id());
    }

    #[test]
    fn the_first_rate_is_zero_and_the_next_is_real() {
        let sampler = Sampler::new();
        assert_eq!(sampler.rate(100), 0.0, "nothing to compare the first sample to");

        std::thread::sleep(Duration::from_millis(50));
        let rate = sampler.rate(150);
        /* 50 requests in ~50ms is ~1000/s; the sleep is not exact, so just check it
           landed in the right order of magnitude rather than on a number */
        assert!(rate > 100.0, "rate was {rate}");
    }

    #[test]
    fn a_counter_that_went_backwards_reads_as_no_traffic() {
        let sampler = Sampler::new();
        sampler.rate(1000);
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(sampler.rate(5), 0.0, "a reset counter must not report a negative rate");
    }

    #[test]
    fn a_node_following_a_local_file_is_never_behind() {
        /* -1 means "not taking config from here at all", which is not the same as
           being late with it */
        assert!(rollout_lag(Some(7), NO_REVISION, None).is_none());
    }

    #[test]
    fn being_on_the_desired_revision_clears_the_lag() {
        assert!(rollout_lag(Some(7), 7, Some(Instant::now())).is_none());
    }

    #[test]
    fn being_behind_starts_a_clock() {
        let first = rollout_lag(Some(8), 7, None);
        assert!(first.is_some(), "falling behind should start the clock");
        /* and it keeps the original instant rather than restarting it each tick */
        let second = rollout_lag(Some(8), 7, first);
        assert_eq!(first, second);
    }

    #[test]
    fn url_encoding_covers_what_would_change_the_path() {
        assert_eq!(urlencode("edge-lhr-1"), "edge-lhr-1");
        assert_eq!(urlencode("a/b"), "a%2Fb");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("../x"), "..%2Fx");
    }

    #[test]
    fn a_heartbeat_survives_a_round_trip_through_json() {
        let beat = Heartbeat {
            edge_id: "edge-1".into(),
            region: Some("lhr".into()),
            label: None,
            version: "0.1.0".into(),
            started_at_ms: 1,
            uptime_s: 2,
            active_revision: 3,
            draining: false,
            cpu_percent: 1.5,
            memory_bytes: 4,
            memory_total_bytes: 5,
            connections_active: 6,
            requests_total: 7,
            requests_per_sec: 8.5,
            cache_entries: 9,
            cache_bytes: 10,
            zones: 1,
            origins_total: 2,
            origins_healthy: 2,
            certificates: vec![CertState {
                zone: "demo".into(),
                mode: "acme".into(),
                status: "valid".into(),
                deployed: true,
                not_after_ms: Some(11),
            }],
        };

        let back: Heartbeat = serde_json::from_str(&serde_json::to_string(&beat).unwrap()).unwrap();
        assert_eq!(back.edge_id, "edge-1");
        assert_eq!(back.region.as_deref(), Some("lhr"));
        assert_eq!(back.active_revision, 3);
        assert_eq!(back.certificates[0].status, "valid");
    }

    #[test]
    fn an_empty_ack_parses_so_a_terse_control_plane_still_works() {
        let ack: Ack = serde_json::from_str("{}").unwrap();
        assert!(ack.desired_revision.is_none());
    }
}
