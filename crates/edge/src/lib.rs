//! Cloudveil edge - the data plane. Everything in here sits in the request path,
//! so it stays free of database calls and blocking work.

pub mod config;
pub mod proxy;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use crate::config::Config;

/// Accept loop. Runs until the listener dies; each connection gets its own task.
pub async fn serve(listener: TcpListener, cfg: Arc<Config>) -> Result<()> {
    let client: proxy::HttpClient = Client::builder(TokioExecutor::new()).build_http();

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                /* usually fd exhaustion - back off so we don't spin the cpu */
                warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        let cfg = cfg.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| proxy::handle(req, cfg.clone(), client.clone(), peer));
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                debug!("{peer}: connection closed: {e}");
            }
        });
    }
}
