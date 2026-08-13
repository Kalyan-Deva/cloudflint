use std::sync::Arc;

use anyhow::{Context, Result};
use cloudveil_api::db::Db;
use cloudveil_api::{router, Api};
use cloudveil_edge::shutdown::Shutdown;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// Bootstrap token, read once when the database has none.
const BOOTSTRAP_VAR: &str = "CLOUDVEIL_API_TOKEN";
const TLS_CERT_VAR: &str = "CLOUDVEIL_API_TLS_CERT";
const TLS_KEY_VAR: &str = "CLOUDVEIL_API_TLS_KEY";
/// Naming a CA here turns on mTLS: only clients holding a certificate it signed get in.
const CLIENT_CA_VAR: &str = "CLOUDVEIL_API_CLIENT_CA";
/// The token this process presents to the edges' admin APIs when purging.
const EDGE_TOKEN_VAR: &str = "CLOUDVEIL_EDGE_TOKEN";
/// Not configurable: nothing here is worth waiting on for long. A config write either
/// finished or it didn't, and the client will find out which.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Usage: cloudveil-api [listen] [db path] [edge admin url, ...]
#[tokio::main]
async fn main() -> Result<()> {
    cloudveil_edge::logging::init();
    cloudveil_edge::tls::install_crypto_provider();

    let mut args = std::env::args().skip(1);
    let listen = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_owned());
    let db_path = args.next().unwrap_or_else(|| "cloudveil.db".to_owned());
    let edges: Vec<String> = args.collect();

    let db = Db::open(&db_path).with_context(|| format!("opening {db_path}"))?;
    bootstrap_token(&db)?;

    let edge_token = std::env::var(EDGE_TOKEN_VAR).ok().map(Arc::new);
    if edge_token.is_none() && !edges.is_empty() {
        warn!("{EDGE_TOKEN_VAR} is not set - the edges will refuse purges from here");
    }

    let api = Api::new(db, edges.clone(), edge_token);

    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding {listen}"))?;

    info!("cloudveil control plane on {listen}, storing to {db_path}");
    match edges.len() {
        0 => info!("no edge admin urls given - purge will have nowhere to go"),
        _ => info!("purging to: {}", edges.join(", ")),
    }

    /* the control plane is not in anyone's request path, so its shutdown is the simple
       kind: stop accepting, let whatever is in flight finish, go. Nothing is draining
       towards it and nothing downstream depends on it staying up. */
    let shutdown = Shutdown::new();
    shutdown.listen();

    match acceptor()? {
        Some(acceptor) => {
            info!("serving https");
            serve_tls(listener, router(api), acceptor, shutdown).await
        }
        None => {
            warn!("serving plaintext - set {TLS_CERT_VAR} and {TLS_KEY_VAR} for https");
            let stopping = shutdown.clone();
            axum::serve(listener, router(api))
                .with_graceful_shutdown(async move { stopping.signalled().await })
                .await?;
            info!("goodbye");
            Ok(())
        }
    }
}

/// A control plane with no tokens is a control plane anyone can rewrite, so it never
/// starts that way. The first token comes from the environment or is generated and
/// printed once.
fn bootstrap_token(db: &Db) -> Result<()> {
    if db.token_count()? > 0 {
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    match std::env::var(BOOTSTRAP_VAR) {
        Ok(token) if token.len() >= 16 => {
            db.add_token("bootstrap", &token, now)?;
            info!("stored the token from {BOOTSTRAP_VAR}");
        }
        Ok(_) => anyhow::bail!("{BOOTSTRAP_VAR} is too short to be a token"),
        Err(_) => {
            let token = cloudveil_edge::auth::generate();
            db.add_token("bootstrap", &token, now)?;
            println!();
            println!("  No tokens existed, so one has been made for you:");
            println!();
            println!("      {token}");
            println!();
            println!("  This is the only time it will be shown - only its hash is stored.");
            println!("  Give it to your edges as CLOUDVEIL_CP_TOKEN and to the dashboard");
            println!("  as CLOUDVEIL_API_TOKEN.");
            println!();
        }
    }
    Ok(())
}

fn acceptor() -> Result<Option<TlsAcceptor>> {
    let (Ok(cert), Ok(key)) = (std::env::var(TLS_CERT_VAR), std::env::var(TLS_KEY_VAR)) else {
        return Ok(None);
    };
    let chain = cloudveil_edge::cp::load_certs(&cert)?;
    let key = cloudveil_edge::cp::load_key(&key)?;

    let config = match std::env::var(CLIENT_CA_VAR) {
        Ok(ca) => {
            info!("requiring client certificates signed by {ca}");
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(cloudveil_edge::cp::client_verifier(&ca)?)
                .with_single_cert(chain, key)?
        }
        Err(_) => {
            warn!("no {CLIENT_CA_VAR} - any client may connect, token permitting");
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)?
        }
    };
    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

async fn serve_tls(
    listener: TcpListener,
    app: axum::Router,
    acceptor: TlsAcceptor,
    shutdown: Arc<Shutdown>,
) -> Result<()> {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = shutdown.signalled() => break,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let token = shutdown.token();

        tokio::spawn(async move {
            let _token = token;
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                /* the usual cause is a client with no certificate, or the wrong one */
                Err(e) => return debug!("{peer}: tls handshake failed: {e}"),
            };
            let svc = TowerToHyperService::new(app);
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                debug!("{peer}: connection closed: {e}");
            }
        });
    }

    shutdown.drain(DRAIN_TIMEOUT).await;
    info!("goodbye");
    Ok(())
}
