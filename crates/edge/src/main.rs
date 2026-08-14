use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use cloudflint_edge::snapshot::{self, Snapshot};
use cloudflint_edge::tls::{self, Tls};
use cloudflint_edge::{admin, config, logging, serve, serve_redirect, serve_tls, Edge};
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    logging::init();

    let path: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "cloudflint.yaml".to_owned())
        .into();

    tls::install_crypto_provider();

    let cfg = config::load(&path)?;
    let listen = cfg.listen;
    let control_plane = cfg.control_plane.clone();
    let admin_listen = cfg.admin_listen;
    let tls_cfg = cfg.tls.clone();
    let fleet_cfg = cfg.fleet;

    /* certificates load here rather than in the parser, so a bad path stops the
       edge starting instead of failing the first handshake of the day */
    let tls = Tls::new(&cfg)?.map(Arc::new);
    /* and the same for the certificates we present *to* origins */
    cloudflint_edge::origin_tls::preflight(&cfg)?;
    /* geo databases too: a rule asking where a client is, on a node whose database is
       missing, should be a startup failure rather than a rule that quietly never fires */
    let geo = cloudflint_edge::geoip::Geo::load(&cfg.geoip)?.map(Arc::new);

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;

    info!("cloudflint edge listening on {listen}");
    info!(
        "cache store: {} MiB, objects up to {} MiB",
        cfg.cache.max_bytes / (1024 * 1024),
        cfg.cache.max_object_bytes / (1024 * 1024)
    );
    for zone in &cfg.zones {
        info!(
            "  zone {} -> {} ({})",
            zone.name,
            zone.origins.urls().join(", "),
            zone.hostnames.join(", ")
        );
        if let Some(probe) = &zone.origins.probe {
            info!(
                "    probing {} every {:?}, out after {} failures",
                probe.path, probe.every, zone.origins.unhealthy_after
            );
        }
    }

    let snap = Arc::new(Snapshot::new(cfg));
    let edge = Edge::with_tls_and_geo(snap.clone(), tls.clone(), geo);
    if let Some(geo) = &edge.geo {
        for (which, kind) in geo.describe() {
            info!("geoip {which}: {kind}");
        }
    }
    info!("pipeline: {}", edge.stage_names().join(" -> "));

    /* before any listener is up, so a signal arriving during startup is still heard */
    edge.shutdown.listen();
    let drain_timeout = edge.node_limits().drain_timeout;

    /* certificates follow both the config and the files it points at - see tls::watch */
    if let Some(tls) = &tls {
        tls::watch(tls.clone(), snap.clone(), std::time::Duration::from_secs(5));
    }
    /* and acme keeps those files current, which is why it needs nothing else wired to it */
    cloudflint_edge::acme::spawn(snap.clone(), edge.challenges.clone());

    match &control_plane {
        Some(url) => {
            info!("control plane at {url} - pulling config and shipping analytics there");
            snapshot::watch_remote(
                url.clone(),
                snap.clone(),
                std::time::Duration::from_secs(5),
                edge.revision.clone(),
            );
            /* and report in, so the fleet view knows this node exists at all. after the
               puller, so the first heartbeat is more likely to carry a real revision */
            if fleet_cfg.enabled {
                let identity = cloudflint_edge::fleet::Identity::from_env();
                /* fleet-wide rate limits are reported under the same identity: the control
                   plane divides a limit between nodes, so it has to know which node is
                   asking, and inventing a second name for the same box would double it */
                cloudflint_edge::limits::global::spawn(
                    snap.clone(),
                    edge.buckets.clone(),
                    url.clone(),
                    identity.edge_id.clone(),
                    fleet_cfg.ratelimit_sync,
                );
                cloudflint_edge::fleet::spawn(
                    edge.clone(),
                    url.clone(),
                    fleet_cfg.heartbeat,
                    identity,
                );
            }
        }
        None => snapshot::watch(path, snap.clone()),
    }

    if let Some(addr) = admin_listen {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding admin listener on {addr}"))?;
        info!("admin api on {addr} - purge, stats and /metrics, bearer token required");
        let edge = edge.clone();
        tokio::spawn(async move {
            if let Err(e) = admin::serve(listener, edge).await {
                tracing::error!("admin api stopped: {e}");
            }
        });
    }

    /* the plaintext listener either serves traffic or redirects to https, and which
       one is only known further down - an Option so the compiler can see it is used
       exactly once either way */
    let mut plaintext = Some(listener);

    /* https last, so the watcher and the admin api are already up either way */
    if let (Some(tls_cfg), Some(_)) = (&tls_cfg, &tls) {
        let https = TcpListener::bind(tls_cfg.listen)
            .await
            .with_context(|| format!("binding {}", tls_cfg.listen))?;
        info!("https on {} (h2 and http/1.1)", tls_cfg.listen);

        {
            let edge = edge.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_tls(https, edge).await {
                    tracing::error!("https listener stopped: {e}");
                }
            });
        }

        if tls_cfg.redirect_http {
            info!("plaintext on {listen} redirects to https");
            let listener = plaintext.take().expect("the plaintext listener is still here");
            let port = tls_cfg.listen.port();
            let shutdown = edge.shutdown.clone();
            let challenges = edge.challenges.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_redirect(listener, port, shutdown, challenges).await {
                    tracing::error!("redirect listener stopped: {e}");
                }
            });
        }
    }

    if let Some(listener) = plaintext {
        let edge = edge.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(listener, edge).await {
                tracing::error!("listener stopped: {e}");
            }
        });
    }

    /* every listener runs in its own task now, so this is where the process waits -
       and where a shutdown is sequenced: signal, stop accepting, drain, exit */
    edge.shutdown.signalled().await;
    edge.shutdown.drain(drain_timeout).await;
    info!("goodbye");
    Ok(())
}
