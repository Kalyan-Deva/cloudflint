//! A response body that fills the cache on its way past.
//!
//! The alternative is buffering the whole response before sending any of it, which
//! would trade every cache miss's time-to-first-byte for the convenience of having
//! the bytes in one place. So instead the client gets frames as they arrive and we
//! keep a copy alongside; if the copy grows past the limit we drop it and stop
//! bothering, and if the client disconnects half way the callback never runs.
//!
//! Completion is by byte count when the length is known, and by end-of-stream when it
//! isn't. Waiting only for end-of-stream doesn't work: with a Content-Length the
//! writer stops as soon as it has written that many bytes and never polls again, so
//! the last poll simply never arrives and nothing ever gets stored.

use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};

use crate::body::{Body, BodyError};

type OnComplete = Box<dyn FnOnce(Bytes) + Send + Sync>;

pub struct Tee {
    inner: Body,
    buf: Vec<u8>,
    limit: usize,
    /// How many bytes to expect, when the body says. None means stream to the end.
    expect: Option<u64>,
    /// Set once the body outgrew the limit; the copy is dropped and never resumed.
    gave_up: bool,
    on_complete: Option<OnComplete>,
}

/// Wrap `inner` so `on_complete` gets the full body once it has streamed cleanly and
/// stayed under `limit`. Any other ending - too big, aborted, errored - and it never
/// fires.
pub fn tee(
    inner: Body,
    limit: usize,
    on_complete: impl FnOnce(Bytes) + Send + Sync + 'static,
) -> Body {
    Tee {
        expect: inner.size_hint().exact(),
        inner,
        buf: Vec::new(),
        limit,
        gave_up: false,
        on_complete: Some(Box::new(on_complete)),
    }
    .boxed()
}

impl Tee {
    /// Fire if we've seen everything we were told to expect.
    fn check_complete(&mut self) {
        if self.expect == Some(self.buf.len() as u64) {
            self.complete();
        }
    }

    fn complete(&mut self) {
        if self.gave_up {
            return;
        }
        if let Some(done) = self.on_complete.take() {
            done(Bytes::from(std::mem::take(&mut self.buf)));
        }
    }
}

impl HttpBody for Tee {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        /* covers a declared-empty body, which may never be polled to the end */
        this.check_complete();

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if !this.gave_up {
                    if let Some(data) = frame.data_ref() {
                        if this.buf.len() + data.len() > this.limit {
                            this.gave_up = true;
                            this.buf = Vec::new();
                        } else {
                            this.buf.extend_from_slice(data);
                        }
                    }
                    this.check_complete();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                this.complete();
                Poll::Ready(None)
            }
            other => other,
        }
    }

    /// Always false, even when the inner body is done - it guarantees the writer takes
    /// the final poll for bodies whose length we don't know up front.
    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::full;
    use std::future::poll_fn;
    use std::sync::{Arc, Mutex};

    type Seen = Arc<Mutex<Option<Bytes>>>;

    fn catcher() -> (Seen, impl FnOnce(Bytes) + Send + Sync + 'static) {
        let seen: Seen = Arc::new(Mutex::new(None));
        let sink = seen.clone();
        (seen, move |b: Bytes| *sink.lock().unwrap() = Some(b))
    }

    fn raw(inner: Body, limit: usize, on_done: impl FnOnce(Bytes) + Send + Sync + 'static) -> Tee {
        Tee {
            expect: inner.size_hint().exact(),
            inner,
            buf: Vec::new(),
            limit,
            gave_up: false,
            on_complete: Some(Box::new(on_done)),
        }
    }

    #[tokio::test]
    async fn passes_the_body_through_and_keeps_a_copy() {
        let (seen, on_done) = catcher();
        let body = tee(full("hello world"), 1024, on_done);

        let got = body.collect().await.unwrap().to_bytes();

        assert_eq!(got, "hello world");
        assert_eq!(seen.lock().unwrap().as_deref(), Some(&b"hello world"[..]));
    }

    /// The one that matters: a writer that knows the length stops polling the moment
    /// it has all the bytes, so the copy has to be finished by then.
    #[tokio::test]
    async fn completes_on_the_last_byte_not_the_last_poll() {
        let (seen, on_done) = catcher();
        let mut body = raw(full("hello"), 1024, on_done);

        let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;

        assert!(frame.is_some(), "expected a data frame");
        assert_eq!(
            seen.lock().unwrap().as_deref(),
            Some(&b"hello"[..]),
            "should have been cached without waiting for end-of-stream"
        );
    }

    #[tokio::test]
    async fn gives_up_on_a_body_over_the_limit() {
        let (seen, on_done) = catcher();
        let body = tee(full("far too much content"), 4, on_done);

        let got = body.collect().await.unwrap().to_bytes();

        assert_eq!(got, "far too much content", "the client still gets everything");
        assert!(seen.lock().unwrap().is_none(), "nothing should have been cached");
    }

    #[tokio::test]
    async fn an_abandoned_body_caches_nothing() {
        let (seen, on_done) = catcher();
        let body = tee(full("hello"), 1024, on_done);

        /* client hung up before reading it */
        drop(body);

        assert!(seen.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn an_empty_body_still_completes() {
        let (seen, on_done) = catcher();
        let body = tee(full(""), 1024, on_done);

        let got = body.collect().await.unwrap().to_bytes();

        assert!(got.is_empty());
        assert_eq!(seen.lock().unwrap().as_deref(), Some(&b""[..]));
    }
}
