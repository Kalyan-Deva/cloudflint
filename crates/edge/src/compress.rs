//! Making responses smaller on the way out.
//!
//! A proxy whose job is bandwidth and latency that doesn't compress is a strange proxy,
//! and this was the biggest thing still missing from the response path.
//!
//! **Where it happens is the interesting decision.** Compression runs on the response as
//! it arrives from the origin - *before* the cache stores it - not on the way out to each
//! client. The cache key already folds `Accept-Encoding` down to one token, so a brotli
//! client and a gzip client get separate entries, and each variant is compressed exactly
//! once however many times it is served. Compressing after the cache would mean burning
//! CPU on every hit to produce bytes we already had.
//!
//! That only works if the thing choosing an encoding and the thing building the cache key
//! agree to the letter. If the key said `gzip` while the chooser decided `identity` -
//! because of a `gzip;q=0`, say - two clients would share one entry and one of them would
//! get bytes it cannot read. So both call `preferred`, and there is deliberately no
//! second implementation of "what does this client accept".
//!
//! Bodies are buffered to compress, capped by `max_bytes`; anything larger streams
//! through untouched. Streaming compression would be better for time-to-first-byte on a
//! big page and is written down as deferred rather than pretended.

use std::io::Write;

use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};

use crate::body::{full, prefixed, Body};

/// What we can produce. Deflate is deliberately absent: it is legacy, gzip is the same
/// algorithm with a header everyone agrees on, and a coding we cannot produce would
/// desynchronise the cache key from the chosen encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    Identity,
    Gzip,
    Brotli,
}

impl Coding {
    pub fn as_str(self) -> &'static str {
        match self {
            Coding::Identity => "identity",
            Coding::Gzip => "gzip",
            Coding::Brotli => "br",
        }
    }
}

/// Per-zone knobs. On by default: a CDN that has to be told to compress is a CDN that
/// mostly doesn't.
#[derive(Debug, Clone)]
pub struct Policy {
    pub enabled: bool,
    /// Below this, the headers cost more than the saving.
    pub min_bytes: usize,
    /// Above this, stream it through instead of buffering it to compress.
    pub max_bytes: usize,
    /// Content types worth compressing, matched on the part before any `;`.
    pub types: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            enabled: true,
            min_bytes: 1024,
            max_bytes: 1024 * 1024,
            types: default_types(),
        }
    }
}

impl Policy {
    pub fn off() -> Self {
        Policy {
            enabled: false,
            ..Default::default()
        }
    }
}

pub fn default_types() -> Vec<String> {
    [
        "text/html",
        "text/css",
        "text/plain",
        "text/xml",
        "text/javascript",
        "application/javascript",
        "application/json",
        "application/xml",
        "application/xhtml+xml",
        "application/rss+xml",
        "application/atom+xml",
        "application/wasm",
        "image/svg+xml",
        "font/ttf",
        "font/otf",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// The best encoding this client will take. Shared with the cache key - see the module
/// note about why that is not optional.
///
/// Quality values are honoured only as far as `q=0` meaning "not this one", which is the
/// part that changes the answer. Ranking by fractional q would let a client ask for gzip
/// over brotli, which no real client does and which would multiply cache entries.
pub fn preferred(accept: &str) -> Coding {
    let mut br = false;
    let mut gzip = false;
    let mut star = false;

    for part in accept.split(',') {
        let mut bits = part.split(';');
        let token = bits.next().unwrap_or("").trim();
        let refused = bits.any(|p| {
            let p = p.trim();
            p.strip_prefix("q=")
                .map(|q| q.trim().parse::<f32>().map(|q| q <= 0.0).unwrap_or(false))
                .unwrap_or(false)
        });
        if refused {
            continue;
        }
        if token.eq_ignore_ascii_case("br") {
            br = true;
        } else if token.eq_ignore_ascii_case("gzip") {
            gzip = true;
        } else if token == "*" {
            star = true;
        }
    }

    match (br || star, gzip) {
        (true, _) => Coding::Brotli,
        (false, true) => Coding::Gzip,
        (false, false) => Coding::Identity,
    }
}

/// What happened, for the counters.
pub struct Saved {
    pub coding: Coding,
    pub before: usize,
    pub after: usize,
}

/// Compress a response if it is worth it and allowed. Returns what it did, so the caller
/// can count it without inspecting headers again.
pub async fn apply(
    accept: &str,
    resp: Response<Body>,
    policy: &Policy,
) -> (Response<Body>, Option<Saved>) {
    if !policy.enabled {
        return (resp, None);
    }
    let coding = preferred(accept);
    if coding == Coding::Identity || !worth_it(&resp, policy) {
        return (resp, None);
    }

    let (mut parts, body) = resp.into_parts();

    /* known length outside the useful range: decided without reading a byte */
    if let Some(len) = content_length(&parts.headers) {
        if len < policy.min_bytes || len > policy.max_bytes {
            return (Response::from_parts(parts, body), None);
        }
    }

    let bytes = match read_capped(body, policy.max_bytes).await {
        Read::All(bytes) => bytes,
        /* over the cap: push what we read back in front of the rest, the same trick the
           waf uses when a request body is too big to inspect. Reading part of a stream
           must never cost the client the bytes we read */
        Read::Capped(prefix, rest) => {
            return (Response::from_parts(parts, prefixed(prefix, rest)), None);
        }
    };

    if bytes.len() < policy.min_bytes {
        return (Response::from_parts(parts, full(bytes)), None);
    }

    let before = bytes.len();
    let Ok(squeezed) = encode(coding, &bytes) else {
        return (Response::from_parts(parts, full(bytes)), None);
    };

    /* incompressible data can come out bigger, and shipping that plus a header would be
       worse than doing nothing */
    if squeezed.len() >= before {
        return (Response::from_parts(parts, full(bytes)), None);
    }

    let after = squeezed.len();
    parts.headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static(coding.as_str()),
    );
    parts.headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&after.to_string()).expect("a number is a valid header"),
    );
    add_vary(&mut parts.headers);

    (
        Response::from_parts(parts, full(squeezed)),
        Some(Saved {
            coding,
            before,
            after,
        }),
    )
}

/// Everything that decides "no" without looking at the body.
fn worth_it(resp: &Response<Body>, policy: &Policy) -> bool {
    let headers = resp.headers();

    /* already encoded: re-encoding would be nonsense and decoding to re-encode is not
       our business */
    if let Some(existing) = headers.get(header::CONTENT_ENCODING) {
        if !existing.as_bytes().eq_ignore_ascii_case(b"identity") {
            return false;
        }
    }
    /* the origin explicitly asked us not to touch it (RFC 9111) */
    if let Some(cc) = headers.get(header::CACHE_CONTROL).and_then(|v| v.to_str().ok()) {
        if cc.to_ascii_lowercase().contains("no-transform") {
            return false;
        }
    }
    /* a partial response is bytes at offsets, and compressing it moves them */
    if resp.status() == StatusCode::PARTIAL_CONTENT {
        return false;
    }
    if !resp.status().is_success() || resp.status() == StatusCode::NO_CONTENT {
        return false;
    }

    let Some(kind) = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) else {
        /* no content type is no information, and guessing at bytes is how you gzip a
           jpeg */
        return false;
    };
    let kind = kind.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    policy.types.iter().any(|t| t == &kind)
}

fn content_length(headers: &hyper::HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Downstream caches have to know the body depends on the request header, even though
/// ours keys on it already.
fn add_vary(headers: &mut hyper::HeaderMap) {
    let already = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("accept-encoding") || t.trim() == "*")
        });
    if !already {
        headers.append(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
}

enum Read {
    /// The whole body, small enough to work with.
    All(hyper::body::Bytes),
    /// What was read before the cap, and whatever is still coming.
    Capped(hyper::body::Bytes, Body),
}

async fn read_capped(body: Body, cap: usize) -> Read {
    use http_body_util::BodyExt;
    use hyper::body::Bytes;

    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let Some(frame) = body.frame().await else {
            return Read::All(Bytes::from(buf));
        };
        let Ok(frame) = frame else {
            /* the body itself failed. hand back what we have plus the broken stream, so
               the failure reaches the client as a failure rather than as our own text */
            return Read::Capped(Bytes::from(buf), body);
        };
        if let Ok(data) = frame.into_data() {
            if buf.len() + data.len() > cap {
                let mut prefix = buf;
                prefix.extend_from_slice(&data);
                return Read::Capped(Bytes::from(prefix), body);
            }
            buf.extend_from_slice(&data);
        }
    }
}

/// Levels are chosen for compressing on the fly rather than for the smallest possible
/// output: brotli 11 is roughly an order of magnitude slower than 4 for a few percent,
/// and a proxy pays that cost while somebody waits.
fn encode(coding: Coding, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    match coding {
        Coding::Identity => Ok(bytes.to_vec()),
        Coding::Gzip => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
            encoder.write_all(bytes)?;
            encoder.finish()
        }
        Coding::Brotli => {
            let mut out = Vec::new();
            {
                let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 4, 22);
                writer.write_all(bytes)?;
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::full;
    use http_body_util::BodyExt;

    fn html(len: usize) -> Response<Body> {
        let body = "<p>hello there</p>".repeat(len / 18 + 1);
        Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=utf-8")
            .body(full(body))
            .unwrap()
    }

    async fn read(resp: Response<Body>) -> Vec<u8> {
        resp.into_body().collect().await.unwrap().to_bytes().to_vec()
    }

    #[test]
    fn picks_the_best_coding_a_client_will_take() {
        assert_eq!(preferred("gzip, deflate, br"), Coding::Brotli);
        assert_eq!(preferred("gzip, deflate"), Coding::Gzip);
        assert_eq!(preferred("deflate"), Coding::Identity);
        assert_eq!(preferred(""), Coding::Identity);
        assert_eq!(preferred("*"), Coding::Brotli);
        assert_eq!(preferred("GZIP"), Coding::Gzip, "tokens are case insensitive");
    }

    #[test]
    fn q_zero_means_not_that_one() {
        assert_eq!(preferred("br;q=0, gzip"), Coding::Gzip);
        assert_eq!(preferred("gzip;q=0"), Coding::Identity);
        assert_eq!(preferred("br;q=0, gzip;q=0"), Coding::Identity);
        /* a non-zero q is accepted, not ranked */
        assert_eq!(preferred("gzip;q=1.0, br;q=0.1"), Coding::Brotli);
    }

    #[tokio::test]
    async fn compresses_html_and_says_so() {
        let policy = Policy::default();
        let (resp, saved) = apply("gzip", html(4000), &policy).await;
        let saved = saved.expect("html of 4kb should compress");

        assert_eq!(saved.coding, Coding::Gzip);
        assert!(saved.after < saved.before / 2, "{} -> {}", saved.before, saved.after);
        assert_eq!(resp.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(
            resp.headers()[header::CONTENT_LENGTH],
            saved.after.to_string().as_str()
        );
        assert_eq!(resp.headers()[header::VARY], "accept-encoding");

        /* and the bytes really are gzip, not just labelled as such */
        let body = read(resp).await;
        assert_eq!(&body[..2], &[0x1f, 0x8b], "gzip magic");
        assert_eq!(body.len(), saved.after);
    }

    #[tokio::test]
    async fn brotli_when_the_client_prefers_it() {
        let (resp, saved) = apply("br, gzip", html(4000), &Policy::default()).await;
        assert_eq!(saved.unwrap().coding, Coding::Brotli);
        assert_eq!(resp.headers()[header::CONTENT_ENCODING], "br");
    }

    #[tokio::test]
    async fn round_trips_through_gzip_unchanged() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let original = read(html(4000)).await;
        let (resp, _) = apply("gzip", html(4000), &Policy::default()).await;
        let compressed = read(resp).await;

        let mut back = Vec::new();
        GzDecoder::new(&compressed[..])
            .read_to_end(&mut back)
            .expect("our own gzip should decode");
        assert_eq!(back, original);
    }

    #[tokio::test]
    async fn round_trips_through_brotli_unchanged() {
        use std::io::Read;

        let original = read(html(4000)).await;
        let (resp, _) = apply("br", html(4000), &Policy::default()).await;
        let compressed = read(resp).await;

        let mut back = Vec::new();
        brotli::Decompressor::new(&compressed[..], 4096)
            .read_to_end(&mut back)
            .expect("our own brotli should decode");
        assert_eq!(back, original);
    }

    #[tokio::test]
    async fn leaves_alone_what_it_should() {
        let policy = Policy::default();

        let cases: Vec<(&str, Response<Body>)> = vec![
            ("a client that wants nothing", html(4000)),
            ("too small to be worth it", html(1)),
        ];
        for (why, resp) in cases {
            let accept = match why.starts_with("a client") {
                true => "",
                false => "gzip",
            };
            let (_, saved) = apply(accept, resp, &policy).await;
            assert!(saved.is_none(), "{why}");
        }

        /* already encoded by the origin */
        let mut resp = html(4000);
        resp.headers_mut()
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let (_, saved) = apply("br", resp, &policy).await;
        assert!(saved.is_none(), "must not re-encode");

        /* the origin said not to */
        let mut resp = html(4000);
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, no-transform"),
        );
        let (_, saved) = apply("gzip", resp, &policy).await;
        assert!(saved.is_none(), "no-transform means no transform");

        /* a type that is already compressed */
        let resp = Response::builder()
            .status(200)
            .header("content-type", "image/jpeg")
            .body(full(vec![7u8; 4000]))
            .unwrap();
        let (_, saved) = apply("gzip", resp, &policy).await;
        assert!(saved.is_none(), "gzipping a jpeg is work for nothing");

        /* no content type at all */
        let resp = Response::builder().status(200).body(full("x".repeat(4000))).unwrap();
        let (_, saved) = apply("gzip", resp, &policy).await;
        assert!(saved.is_none());

        /* a range response */
        let resp = Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header("content-type", "text/html")
            .body(full("x".repeat(4000)))
            .unwrap();
        let (_, saved) = apply("gzip", resp, &policy).await;
        assert!(saved.is_none());
    }

    #[tokio::test]
    async fn a_body_over_the_cap_streams_through_untouched() {
        let policy = Policy {
            max_bytes: 2048,
            ..Default::default()
        };
        let resp = html(8000);
        let expected = read(html(8000)).await;

        let (resp, saved) = apply("gzip", resp, &policy).await;
        assert!(saved.is_none());
        assert_eq!(read(resp).await, expected, "the body must survive intact");
    }

    #[tokio::test]
    async fn a_known_length_outside_the_range_is_decided_without_reading() {
        let policy = Policy {
            max_bytes: 2048,
            ..Default::default()
        };
        let big = "<p>x</p>".repeat(1000);
        let expected = big.clone().into_bytes();
        let resp = Response::builder()
            .status(200)
            .header("content-type", "text/html")
            .header("content-length", big.len().to_string())
            .body(full(big))
            .unwrap();

        let (resp, saved) = apply("gzip", resp, &policy).await;
        assert!(saved.is_none());
        assert_eq!(read(resp).await, expected);
    }

    #[tokio::test]
    async fn incompressible_bytes_are_left_as_they_are() {
        /* random-ish bytes labelled as text: gzip will make them bigger */
        let noise: Vec<u8> = (0..4000u32).map(|n| (n.wrapping_mul(2654435761) >> 13) as u8).collect();
        let resp = Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(full(noise.clone()))
            .unwrap();

        let (resp, saved) = apply("gzip", resp, &Policy::default()).await;
        match saved {
            None => assert_eq!(read(resp).await, noise, "left alone, unchanged"),
            Some(s) => assert!(s.after < s.before, "if it did compress it must have helped"),
        }
    }

    #[tokio::test]
    async fn an_existing_vary_is_extended_not_replaced() {
        let mut resp = html(4000);
        resp.headers_mut()
            .insert(header::VARY, HeaderValue::from_static("accept-language"));

        let (resp, _) = apply("gzip", resp, &Policy::default()).await;
        let varies: Vec<&str> = resp
            .headers()
            .get_all(header::VARY)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert!(varies.contains(&"accept-language"));
        assert!(varies.contains(&"accept-encoding"));
    }

    #[tokio::test]
    async fn vary_is_not_repeated_when_the_origin_already_said_it() {
        let mut resp = html(4000);
        resp.headers_mut().insert(
            header::VARY,
            HeaderValue::from_static("Accept-Encoding, Accept-Language"),
        );

        let (resp, _) = apply("gzip", resp, &Policy::default()).await;
        assert_eq!(resp.headers().get_all(header::VARY).iter().count(), 1);
    }

    #[tokio::test]
    async fn a_disabled_policy_does_nothing() {
        let (resp, saved) = apply("br, gzip", html(4000), &Policy::off()).await;
        assert!(saved.is_none());
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
    }
}
