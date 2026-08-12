//! The pages a visitor sees when we stop their request.
//!
//! Deliberately plain: no rule ids, no limits, no timings. Whoever is on the other
//! end might be a person who mistyped something, or might be probing us, and neither
//! needs to be told how the decision was reached.

use hyper::{header, Response, StatusCode};

use crate::body::{full, Body};

pub fn blocked() -> Response<Body> {
    page(
        StatusCode::FORBIDDEN,
        "This request was blocked",
        "Our filters flagged it as an attack. If you think that's wrong, get in touch \
         with the site owner and tell them roughly when it happened.",
    )
}

pub fn rate_limited(retry_after_secs: u64) -> Response<Body> {
    let mut resp = page(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many requests",
        "You've made a lot of requests in a short time, so we've paused this one. \
         Wait a moment and try again.",
    );
    if let Ok(value) = header::HeaderValue::from_str(&retry_after_secs.max(1).to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, value);
    }
    resp
}

fn page(status: StatusCode, heading: &str, message: &str) -> Response<Body> {
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{heading}</title>
<style>
  html {{ background: #14161a; }}
  body {{
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    background: #14161a; color: #e6e3dd;
    font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }}
  main {{ max-width: 30rem; padding: 2rem 1.5rem; }}
  h1 {{ margin: 0 0 .75rem; font-size: 1.125rem; font-weight: 600; letter-spacing: -.01em; }}
  p {{ margin: 0 0 1.25rem; color: #8b9099; }}
  .mark {{ color: #c9784a; font-weight: 600; }}
  hr {{ border: 0; border-top: 1px solid #2a2e35; margin: 1.25rem 0; }}
  small {{ color: #8b9099; }}
</style>
</head>
<body>
<main>
  <h1>{heading}</h1>
  <p>{message}</p>
  <hr>
  <small>Served by <span class="mark">Cloudveil</span></small>
</main>
</body>
</html>
"#
    );

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full(html))
        .expect("static page is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_page_gives_nothing_away() {
        let resp = blocked();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn rate_limiting_says_when_to_come_back() {
        let resp = rate_limited(42);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "42");

        /* never tell someone to retry in zero seconds */
        let now = rate_limited(0);
        assert_eq!(now.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }
}
