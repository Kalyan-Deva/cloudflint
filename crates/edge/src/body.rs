//! One body type for everything we hand back, so origin responses and responses we
//! make up ourselves are the same shape.

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{header, Response, StatusCode};

pub type Body = BoxBody<Bytes, hyper::Error>;

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
