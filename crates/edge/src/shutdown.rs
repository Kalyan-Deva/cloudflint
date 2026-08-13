//! Stopping on purpose.
//!
//! A proxy is the process every request goes through, so how it stops is as much a
//! feature as how it serves. Killing it mid-flight turns a deploy into other people's
//! 502s. The sequence here is the one orchestrators expect:
//!
//! 1. A signal arrives - SIGTERM from Kubernetes or Docker, ctrl-c from a terminal.
//! 2. The node starts *draining*: `/admin/health` goes unhealthy immediately, so a load
//!    balancer stops sending new work before anything is torn down. This ordering is
//!    the whole point - a node that drains before it looks unhealthy still drops the
//!    requests in flight towards it.
//! 3. Listeners stop accepting. Live connections are told to finish: HTTP/1.1 closes
//!    after the response in flight, HTTP/2 gets a GOAWAY.
//! 4. We wait for the last connection to go, up to `drain_timeout`, then exit anyway.
//!    An unbounded wait is not "graceful", it is a process that will not die.
//!
//! Tracking live connections uses the dropped-sender trick rather than a counter: every
//! connection holds a clone of an mpsc sender, and the receiver only reports closed once
//! every clone is gone. No counter to leak, and it composes with a timeout for free.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

/// Held for the life of a connection. Dropping it is what says "this one is done".
pub type Token = mpsc::Sender<()>;

pub struct Shutdown {
    /// false while serving, true once draining. Watch rather than broadcast so a task
    /// that asks late still learns it has already happened.
    signal: watch::Sender<bool>,
    /// The sender every connection clones. Taken and dropped by `drain`, so the
    /// receiver cannot close while we are still holding one ourselves.
    live: Mutex<Option<Token>>,
    done: Mutex<Option<mpsc::Receiver<()>>>,
}

impl Shutdown {
    pub fn new() -> Arc<Self> {
        let (live, done) = mpsc::channel(1);
        Arc::new(Shutdown {
            signal: watch::channel(false).0,
            live: Mutex::new(Some(live)),
            done: Mutex::new(Some(done)),
        })
    }

    /// Watch for the signals that mean "stop". Spawns a task and returns.
    ///
    /// SIGTERM is the one that matters: it is what `docker stop` and a Kubernetes pod
    /// deletion send, and the default handler kills the process outright.
    pub fn listen(self: &Arc<Self>) {
        let shutdown = self.clone();
        tokio::spawn(async move {
            let why = wait_for_a_signal().await;
            shutdown.begin(why);
        });
    }

    /// Start draining. Idempotent - a second signal changes nothing, so an impatient
    /// operator pressing ctrl-c twice does not shorten anyone's request.
    pub fn begin(&self, why: &str) {
        if !self.signal.send_replace(true) {
            info!("{why} - draining, no new connections");
        }
    }

    pub fn draining(&self) -> bool {
        *self.signal.borrow()
    }

    /// Resolves as soon as draining has started, including if it started already.
    ///
    /// Cancel-safe, so it can sit in a `select!` next to an accept or a connection.
    pub async fn signalled(&self) {
        let mut rx = self.signal.subscribe();
        loop {
            /* the borrow guard is dropped before the await, or this future would not
               be Send and no accept loop could hold it */
            let draining = *rx.borrow_and_update();
            if draining {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// A token to hold for the life of a connection. None once draining has finished,
    /// at which point there is nobody left to wait for it.
    pub fn token(&self) -> Option<Token> {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Wait for every live connection to finish, or for the deadline. Returns true if
    /// they all went on their own.
    ///
    /// Only meaningful once; the second call has nothing left to wait on.
    pub async fn drain(&self, deadline: Duration) -> bool {
        /* drop our own sender first, or the channel can never close */
        self.live.lock().unwrap_or_else(|e| e.into_inner()).take();

        let Some(mut done) = self.done.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return true;
        };

        match tokio::time::timeout(deadline, done.recv()).await {
            Ok(_) => {
                info!("every connection closed");
                true
            }
            Err(_) => {
                warn!("still busy after {deadline:?} - exiting anyway");
                false
            }
        }
    }
}

#[cfg(unix)]
async fn wait_for_a_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = match signal(SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => {
            warn!("cannot listen for SIGTERM ({e}) - ctrl-c only");
            let _ = tokio::signal::ctrl_c().await;
            return "interrupted";
        }
    };
    tokio::select! {
        _ = term.recv() => "SIGTERM",
        _ = tokio::signal::ctrl_c() => "interrupted",
    }
}

#[cfg(windows)]
async fn wait_for_a_signal() -> &'static str {
    use tokio::signal::windows;

    /* the console equivalents of SIGTERM: a close button and a system shutdown */
    let mut close = match windows::ctrl_close() {
        Ok(close) => close,
        Err(e) => {
            warn!("cannot listen for console close ({e}) - ctrl-c only");
            let _ = tokio::signal::ctrl_c().await;
            return "interrupted";
        }
    };
    let mut stopping = windows::ctrl_shutdown().ok();

    tokio::select! {
        _ = close.recv() => "console closing",
        _ = async { match &mut stopping {
            Some(s) => { s.recv().await; }
            /* nothing to wait for, so wait forever and let the others decide */
            None => std::future::pending().await,
        } } => "system shutting down",
        _ = tokio::signal::ctrl_c() => "interrupted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signalled_resolves_for_watchers_before_and_after() {
        let shutdown = Shutdown::new();
        assert!(!shutdown.draining());

        let early = {
            let shutdown = shutdown.clone();
            tokio::spawn(async move { shutdown.signalled().await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        shutdown.begin("test");

        early.await.expect("a watcher waiting beforehand should be woken");
        /* and one that turns up afterwards must not wait for a second signal */
        tokio::time::timeout(Duration::from_millis(100), shutdown.signalled())
            .await
            .expect("a late watcher should return immediately");
        assert!(shutdown.draining());
    }

    #[tokio::test]
    async fn drain_waits_for_the_last_connection() {
        let shutdown = Shutdown::new();
        let one = shutdown.token().expect("a token before draining");
        let two = shutdown.token().expect("a token before draining");

        let waiting = {
            let shutdown = shutdown.clone();
            tokio::spawn(async move { shutdown.drain(Duration::from_secs(5)).await })
        };

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "two connections are still live");

        drop(one);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "one connection is still live");

        drop(two);
        assert!(waiting.await.unwrap(), "they all closed on their own");
    }

    #[tokio::test]
    async fn a_stuck_connection_does_not_stop_us_leaving() {
        let shutdown = Shutdown::new();
        let _stuck = shutdown.token().expect("a token before draining");

        let all_closed = shutdown.drain(Duration::from_millis(50)).await;
        assert!(!all_closed, "the deadline should have run out");
    }

    #[tokio::test]
    async fn draining_twice_is_harmless() {
        let shutdown = Shutdown::new();
        shutdown.begin("first");
        shutdown.begin("second");
        assert!(shutdown.draining());
        assert!(shutdown.drain(Duration::from_millis(50)).await);
        assert!(
            shutdown.drain(Duration::from_millis(50)).await,
            "a second drain has nothing left to wait for"
        );
    }

    #[tokio::test]
    async fn tokens_stop_being_handed_out_once_draining_is_over() {
        let shutdown = Shutdown::new();
        assert!(shutdown.token().is_some());
        shutdown.drain(Duration::from_millis(10)).await;
        assert!(
            shutdown.token().is_none(),
            "nobody is waiting on connections any more"
        );
    }
}
