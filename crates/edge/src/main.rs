use std::sync::Arc;

use anyhow::{Context, Result};
use cloudveil_edge::{config, serve};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "cloudveil.yaml".to_owned());
    let cfg = Arc::new(config::load(&path)?);

    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;

    info!("cloudveil edge listening on {}", cfg.listen);
    for zone in &cfg.zones {
        info!(
            "  zone {} -> {}://{} ({})",
            zone.name,
            zone.origin.scheme,
            zone.origin.authority,
            zone.hostnames.join(", ")
        );
    }

    serve(listener, cfg).await
}
