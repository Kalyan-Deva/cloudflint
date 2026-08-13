//! Cloudveil edge - the data plane. Everything in here sits in the request path,
//! so it stays free of database calls and blocking work.

pub mod admin;
pub mod analytics;
pub mod auth;
pub mod body;
pub mod cache;
pub mod client_ip;
pub mod config;
pub mod cp;
pub mod limits;
pub mod logging;
pub mod metrics;
pub mod pages;
pub mod pipeline;
pub mod proxy;
pub mod shutdown;
pub mod snapshot;
pub mod stages;
pub mod tls;
pub mod waf;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use crate::body::{full, Body};
use crate::cache::Store;
use crate::config::NodeLimits;
use crate::limits::conn::ConnLimits;
use crate::metrics::Metrics;
use crate::pipeline::Pipeline;
use crate::shutdown::Shutdown;
use crate::snapshot::Snapshot;
use crate::tls::Tls;

/// Everything built once at boot and shared for the process's life.
///
/// The connection pool, the cache store and the rate limit counters all live in
/// here. None of them should be thrown away on a config reload, which is why they
/// are built from the boot snapshot and then left alone - the per-request policy
/// still comes from the live snapshot.
pub struct Edge {
    pub snap: Arc<Snapshot>,
    pub store: Arc<Store>,
    pub analytics: Arc<analytics::Sink>,
    pub metrics: Arc<Metrics>,
    pub shutdown: Arc<Shutdown>,
    pub tls: Option<Arc<Tls>>,
    pipeline: Arc<Pipeline>,
    node: NodeLimits,
}

impl Edge {
    pub fn new(snap: Arc<Snapshot>) -> Arc<Self> {
        Self::with_tls(snap, None)
    }

    pub fn with_tls(snap: Arc<Snapshot>, tls: Option<Arc<Tls>>) -> Arc<Self> {
        let boot = snap.current();
        let store = Arc::new(Store::new(
            boot.cache.max_bytes,
            boot.cache.max_object_bytes,
        ));
        let analytics = analytics::Sink::new(boot.control_plane.clone());
        let metrics = Arc::new(Metrics::new());
        let pipeline = Arc::new(stages::build(store.clone(), metrics.clone()));
        let node = boot.limits;

        Arc::new(Edge {
            snap,
            store,
            analytics,
            metrics,
            shutdown: Shutdown::new(),
            tls,
            pipeline,
            node,
        })
    }

    pub fn stage_names(&self) -> Vec<&'static str> {
        self.pipeline.stage_names()
    }

    pub fn node_limits(&self) -> NodeLimits {
        self.node
    }
}

/// Plaintext accept loop.
pub async fn serve(listener: TcpListener, edge: Arc<Edge>) -> Result<()> {
    accept_loop(listener, edge, None).await
}

/// TLS accept loop. Same pipeline, same limits; the only difference is a handshake
/// in front and `tls` being true for everything behind it.
pub async fn serve_tls(listener: TcpListener, edge: Arc<Edge>) -> Result<()> {
    let Some(tls) = edge.tls.clone() else {
        anyhow::bail!("serve_tls called without any tls configuration");
    };
    let acceptor = TlsAcceptor::from(tls.server.clone());
    accept_loop(listener, edge, Some(acceptor)).await
}

async fn accept_loop(
    listener: TcpListener,
    edge: Arc<Edge>,
    acceptor: Option<TlsAcceptor>,
) -> Result<()> {
    let node = edge.node;
    let conns = Arc::new(ConnLimits::metered(
        node.max_connections_per_ip,
        node.new_connections_per_ip_per_sec,
        edge.metrics.clone(),
    ));
    let handshake_timeout = edge
        .snap
        .current()
        .tls
        .as_ref()
        .map(|t| t.handshake_timeout)
        .unwrap_or(Duration::from_secs(10));

    loop {
        let accepted = tokio::select! {
            /* biased so a signal that lands at the same moment as a connection wins:
               accepting one more request while draining is exactly what we said we
               would stop doing */
            biased;
            _ = edge.shutdown.signalled() => {
                debug!("draining - closing the listener");
                return Ok(());
            }
            accepted = listener.accept() => accepted,
        };

        let (stream, peer) = match accepted {
            Ok(v) => v,
            Err(e) => {
                /* usually fd exhaustion - back off so we don't spin the cpu */
                warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        /* before a single byte of http - or of the handshake - is read. slowloris
           and friends never send a complete request, so anything that waits for one
           has already lost, and a tls handshake is far too expensive to hand out
           for free.

           necessarily the peer, not the client: there is no request yet to read a
           forwarded-for header from. behind a proxy these caps therefore apply to the
           proxy, which is the right answer for connections and the wrong one for
           clients - that is what the per-client rate limits are for */
        let guard = match conns.admit(peer.ip()) {
            Ok(guard) => guard,
            Err(why) => {
                debug!("{peer}: connection refused, {why:?}");
                drop(stream);
                continue;
            }
        };

        let edge = edge.clone();
        let acceptor = acceptor.clone();
        /* held until this connection is finished with, so a drain knows to wait */
        let token = edge.shutdown.token();
        tokio::spawn(async move {
            let _guard = guard;
            let _token = token;
            let metrics = edge.metrics.clone();

            match acceptor {
                None => run(TokioIo::new(stream), edge, peer, node, false).await,
                Some(acceptor) => {
                    /* the header timeout can't cover this: it only starts once there
                       is a decrypted stream to read headers from */
                    match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            run(TokioIo::new(stream), edge, peer, node, true).await
                        }
                        Ok(Err(e)) => {
                            metrics.tls_handshake_failures.inc(&["failed"]);
                            debug!("{peer}: tls handshake failed: {e}");
                        }
                        Err(_) => {
                            metrics.tls_handshake_failures.inc(&["timeout"]);
                            debug!("{peer}: tls handshake timed out");
                        }
                    }
                }
            }
        });
    }
}

/// Serve one connection, speaking whatever ALPN settled on.
async fn run<I>(io: TokioIo<I>, edge: Arc<Edge>, peer: std::net::SocketAddr, node: NodeLimits, tls: bool)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let shutdown = edge.shutdown.clone();
    let svc = service_fn(move |req| proxy::handle(req, edge.clone(), peer, tls));

    let mut builder = auto::Builder::new(TokioExecutor::new());
    /* the timer is not optional: hyper panics at connection time if a timeout is
       set without one, which is a loud failure but only on the very first request */
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(node.header_read_timeout);
    builder.http2().timer(TokioTimer::new());

    /* with_upgrades, or a websocket 101 would be answered and then abandoned */
    let conn = builder.serve_connection_with_upgrades(io, svc);
    /* pinned because a graceful shutdown has to be asked of a connection that is
       already being polled - it is a message to it, not a way of dropping it */
    let mut conn = std::pin::pin!(conn);

    /* an upper bound on any one connection, so a slow request can't hold a slot
       indefinitely even if it keeps dribbling bytes to stay alive */
    let age = tokio::time::sleep(node.max_connection_age);
    let mut age = std::pin::pin!(age);

    /* asked once and only once - `signalled` stays ready forever afterwards, so an
       unguarded arm would spin */
    let mut asked = false;
    loop {
        tokio::select! {
            done = conn.as_mut() => {
                if let Err(e) = done {
                    debug!("{peer}: connection closed: {e}");
                }
                return;
            }
            _ = &mut age => {
                debug!("{peer}: closed after {:?}", node.max_connection_age);
                return;
            }
            _ = shutdown.signalled(), if !asked => {
                asked = true;
                /* finish the response in flight and then close: http/1.1 stops
                   keeping alive, http/2 gets a GOAWAY. the loop goes round once
                   more to poll the connection out */
                debug!("{peer}: draining");
                conn.as_mut().graceful_shutdown();
            }
        }
    }
}

/// A plaintext listener that does nothing but point people at https.
///
/// Deliberately not part of the pipeline: it answers before routing, so it works for
/// hostnames this node doesn't even serve, and there is nothing here worth a WAF.
pub async fn serve_redirect(
    listener: TcpListener,
    https_port: u16,
    shutdown: Arc<Shutdown>,
) -> Result<()> {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = shutdown.signalled() => return Ok(()),
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, peer)) = accepted else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let token = shutdown.token();

        tokio::spawn(async move {
            let _token = token;
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| async move {
                let host = req
                    .headers()
                    .get(hyper::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(|h| h.split(':').next().unwrap_or(h).to_owned())
                    .unwrap_or_default();

                let target = match https_port {
                    443 => format!("https://{host}{}", path_of(&req)),
                    port => format!("https://{host}:{port}{}", path_of(&req)),
                };

                let resp = Response::builder()
                    .status(StatusCode::MOVED_PERMANENTLY)
                    .header(hyper::header::LOCATION, target)
                    .body(full(""))
                    .expect("redirect is always valid");
                Ok::<_, std::convert::Infallible>(resp)
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                debug!("{peer}: redirect connection closed: {e}");
            }
        });
    }
}

fn path_of(req: &hyper::Request<hyper::body::Incoming>) -> String {
    req.uri()
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".into())
}

/// Response bodies from the redirect listener share the edge's body type.
pub type RedirectBody = Body;
