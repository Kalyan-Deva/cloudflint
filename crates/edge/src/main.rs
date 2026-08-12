use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use cloudveil_edge::snapshot::{self, Snapshot};
use cloudveil_edge::tls::{self, Tls};
use cloudveil_edge::{admin, config, serve, serve_redirect, serve_tls, Edge};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let path: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "cloudveil.yaml".to_owned())
        .into();

    tls::install_crypto_provider();

    let cfg = config::load(&path)?;
    let listen = cfg.listen;
    let control_plane = cfg.control_plane.clone();
    let admin_listen = cfg.admin_listen;
    let tls_cfg = cfg.tls.clone();

    /* certificates load here rather than in the parser, so a bad path stops the
       edge starting instead of failing the first handshake of the day */
    let tls = Tls::new(&cfg)?.map(Arc::new);

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;

    info!("cloudveil edge listening on {listen}");
    info!(
        "cache store: {} MiB, objects up to {} MiB",
        cfg.cache.max_bytes / (1024 * 1024),
        cfg.cache.max_object_bytes / (1024 * 1024)
    );
    for zone in &cfg.zones {
        info!(
            "  zone {} -> {}://{} ({})",
            zone.name,
            zone.origin.scheme,
            zone.origin.authority,
            zone.hostnames.join(", ")
        );
    }

    let snap = Arc::new(Snapshot::new(cfg));
    let edge = Edge::with_tls(snap.clone(), tls.clone());
    info!("pipeline: {}", edge.stage_names().join(" -> "));

    match &control_plane {
        Some(url) => {
            info!("control plane at {url} - pulling config and shipping analytics there");
            snapshot::watch_remote(url.clone(), snap.clone(), std::time::Duration::from_secs(5));
        }
        None => snapshot::watch(path, snap.clone()),
    }

    if let Some(addr) = admin_listen {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding admin listener on {addr}"))?;
        info!("admin api on {addr} - purge and stats, no authentication, keep it internal");
        let edge = edge.clone();
        tokio::spawn(async move {
            if let Err(e) = admin::serve(listener, edge).await {
                tracing::error!("admin api stopped: {e}");
            }
        });
    }

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
            return serve_redirect(listener, tls_cfg.listen.port()).await;
        }
    }

    serve(listener, edge).await
}
