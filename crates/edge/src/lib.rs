//! Cloudveil edge - the data plane. Everything in here sits in the request path,
//! so it stays free of database calls and blocking work.

pub mod body;
pub mod config;
pub mod pipeline;
pub mod proxy;
pub mod snapshot;
pub mod stages;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{debug, warn};

use crate::snapshot::Snapshot;

/// Accept loop. Runs until the listener dies; each connection gets its own task.
pub async fn serve(listener: TcpListener, snap: Arc<Snapshot>) -> Result<()> {
    /* built once and shared - stages hold things like the origin connection pool */
    let pipeline = Arc::new(stages::build());

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

        let snap = snap.clone();
        let pipeline = pipeline.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                proxy::handle(req, snap.clone(), pipeline.clone(), peer)
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                debug!("{peer}: connection closed: {e}");
            }
        });
    }
}
