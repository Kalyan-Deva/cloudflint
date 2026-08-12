use std::sync::Arc;

use anyhow::{Context, Result};
use cloudveil_api::db::Db;
use cloudveil_api::{router, Api};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Usage: cloudveil-api [listen] [db path] [edge admin url, ...]
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .init();

    let mut args = std::env::args().skip(1);
    let listen = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_owned());
    let db_path = args.next().unwrap_or_else(|| "cloudveil.db".to_owned());
    let edges: Vec<String> = args.collect();

    let db = Db::open(&db_path).with_context(|| format!("opening {db_path}"))?;
    let api = Api {
        db,
        edges: Arc::new(edges.clone()),
    };

    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding {listen}"))?;

    info!("cloudveil control plane on {listen}, storing to {db_path}");
    match edges.len() {
        0 => info!("no edge admin urls given - purge will have nowhere to go"),
        _ => info!("purging to: {}", edges.join(", ")),
    }

    axum::serve(listener, router(api)).await?;
    Ok(())
}
