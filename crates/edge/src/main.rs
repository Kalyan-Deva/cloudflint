use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use cloudveil_edge::snapshot::{self, Snapshot};
use cloudveil_edge::{config, serve, stages};
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

    let cfg = config::load(&path)?;
    let listen = cfg.listen;

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;

    info!("cloudveil edge listening on {listen}");
    info!("pipeline: {}", stages::build().stage_names().join(" -> "));
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
    snapshot::watch(path, snap.clone());

    serve(listener, snap).await
}
