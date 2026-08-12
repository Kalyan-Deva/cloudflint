//! One body type for everything, so origin responses and responses we make up
//! ourselves are the same shape - plus the wrappers that make a body do something
//! useful on its way past.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use hyper::{header, Response, StatusCode};
use tokio::time::{sleep, Instant, Sleep};

pub type Body = BoxBody<Bytes, BodyError>;

/// Why a body stopped early.
///
/// This exists so a read that stalls can fail. `hyper::Error` has no public
/// constructor, so a body whose error type is `hyper::Error` can only ever pass
/// through failures it was handed - it can never raise one of its own.
#[derive(Debug)]
pub enum BodyError {
    Upstream(hyper::Error),
    /// Nothing arrived within the read timeout. A stalled sender, or a deliberate one.
    ReadTimeout(Duration),
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BodyError::Upstream(e) => write!(f, "{e}"),
            BodyError::ReadTimeout(d) => write!(f, "no data for {d:?}"),
        }
    }
}

impl std::error::Error for BodyError {}

impl From<hyper::Error> for BodyError {
    fn from(e: hyper::Error) -> Self {
        BodyError::Upstream(e)
    }
}

/// Adapt a hyper body (a request or response straight off the wire) to ours.
pub fn adapt<B>(body: B) -> Body
where
    B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
{
    body.map_err(BodyError::from).boxed()
}

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

pub fn text(status: StatusCode, msg: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(format!("{msg}\n")))
        .expect("static error response is always valid")
}

/// A body with already-read bytes stuck back on the front.
///
/// The WAF reads the start of a body to inspect it. When the body turns out to be
/// bigger than we're willing to buffer we still have to forward every byte, so the
/// part we consumed gets pushed back in front of whatever is left on the wire.
pub struct Prefixed {
    prefix: Option<Bytes>,
    rest: Body,
}

pub fn prefixed(prefix: Bytes, rest: Body) -> Body {
    Prefixed {
        prefix: Some(prefix),
        rest,
    }
    .boxed()
}

impl HttpBody for Prefixed {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        if let Some(prefix) = this.prefix.take() {
            if !prefix.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(prefix))));
            }
        }
        Pin::new(&mut this.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.as_ref().is_none_or(|p| p.is_empty()) && self.rest.is_end_stream()
    }

    /// Has to account for the prefix, or hyper frames the request wrong.
    fn size_hint(&self) -> SizeHint {
        let rest = self.rest.size_hint();
        let extra = self.prefix.as_ref().map_or(0, |p| p.len() as u64);

        let mut hint = SizeHint::new();
        hint.set_lower(rest.lower() + extra);
        if let Some(upper) = rest.upper() {
            hint.set_upper(upper + extra);
        }
        hint
    }
}

/// Gives up on a body that stops sending.
///
/// The clock is per frame, not per body, so a large slow-but-honest upload is fine
/// while a sender that opens a request and then dribbles - or stops entirely - gets
/// dropped instead of holding a connection open indefinitely. That's the slow-POST
/// half of slowloris; the header half is hyper's `header_read_timeout`.
pub struct Timed {
    inner: Body,
    per_frame: Duration,
    idle: Pin<Box<Sleep>>,
}

pub fn with_read_timeout(inner: Body, per_frame: Duration) -> Body {
    Timed {
        inner,
        per_frame,
        idle: Box::pin(sleep(per_frame)),
    }
    .boxed()
}

impl HttpBody for Timed {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => {
                /* polling the timer also registers the waker, so we get woken to fail */
                if this.idle.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Some(Err(BodyError::ReadTimeout(this.per_frame))));
                }
                Poll::Pending
            }
            ready => {
                this.idle.as_mut().reset(Instant::now() + this.per_frame);
                ready
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn collect(body: Body) -> Vec<u8> {
        body.collect().await.unwrap().to_bytes().to_vec()
    }

    #[tokio::test]
    async fn prefix_comes_out_before_the_rest() {
        let body = prefixed(Bytes::from_static(b"head"), full("tail"));
        assert_eq!(collect(body).await, b"headtail");
    }

    #[tokio::test]
    async fn an_empty_prefix_changes_nothing() {
        let body = prefixed(Bytes::new(), full("tail"));
        assert_eq!(collect(body).await, b"tail");
    }

    #[test]
    fn size_hint_counts_the_prefix() {
        let body = Prefixed {
            prefix: Some(Bytes::from_static(b"1234")),
            rest: full("567"),
        };
        let hint = body.size_hint();
        assert_eq!(hint.lower(), 7);
        assert_eq!(hint.upper(), Some(7));
    }

    #[tokio::test]
    async fn a_body_that_arrives_in_time_is_untouched() {
        let body = with_read_timeout(full("all here already"), Duration::from_millis(50));
        assert_eq!(collect(body).await, b"all here already");
    }

    /// Stands in for a sender that opened a request and then went quiet.
    struct Stalled;

    impl HttpBody for Stalled {
        type Data = Bytes;
        type Error = BodyError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn a_body_that_stalls_gives_up() {
        let body = with_read_timeout(Stalled.boxed(), Duration::from_millis(30));

        let err = body.collect().await.expect_err("should have timed out");
        assert!(matches!(err, BodyError::ReadTimeout(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn the_clock_is_per_frame_not_per_body() {
        /* three frames, each arriving well inside the window, total well outside it */
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BodyError>>(4);
        tokio::spawn(async move {
            for part in ["one ", "two ", "three"] {
                tokio::time::sleep(Duration::from_millis(40)).await;
                let _ = tx.send(Ok(Frame::data(Bytes::from(part)))).await;
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let body = with_read_timeout(
            http_body_util::StreamBody::new(stream).boxed(),
            Duration::from_millis(100),
        );

        assert_eq!(collect(body).await, b"one two three");
    }
}
