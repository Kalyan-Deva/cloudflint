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
  <small>Served by <span class="mark">Cloudflint</span></small>
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

/// The interstitial. Solves a hashcash puzzle in the browser, then re-requests the page
/// with the answer on the query string - so there is no separate verify endpoint to guard,
/// and a client that cannot run JavaScript simply never gets through, which is the point.
pub fn challenge(puzzle: &str, bits: u32) -> Response<Body> {
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Checking your browser</title><style>
body{{font:15px/1.6 -apple-system,Segoe UI,sans-serif;background:#14161a;color:#e6e3dd;
display:grid;place-items:center;height:100vh;margin:0}}
.card{{border:1px solid #2a2e35;border-radius:5px;background:#1c1f24;padding:26px 30px;max-width:420px}}
h1{{font-size:17px;margin:0 0 8px}}p{{color:#8b9099;margin:0}}
.bar{{height:3px;background:#2a2e35;border-radius:2px;margin-top:18px;overflow:hidden}}
.fill{{height:100%;width:0;background:#c9784a;transition:width .2s}}</style></head>
<body><div class="card"><h1>Checking your browser</h1>
<p>This takes a moment and happens once.</p><div class="bar"><div class="fill" id="f"></div></div>
<noscript><p style="color:#b8574d;margin-top:14px">JavaScript is required to continue.</p></noscript>
</div><script>
const puzzle={puzzle:?}, bits={bits};
async function sha(s){{const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));
return new Uint8Array(b)}}
function zeros(a){{let n=0;for(const b of a){{if(b===0){{n+=8;continue}}
let v=b,c=0;while(v<128){{c++;v<<=1}}return n+c}}return n}}
(async()=>{{for(let n=0;n<50000000;n++){{
if(n%2000===0)document.getElementById('f').style.width=Math.min(95,n/400)+'%';
if(zeros(await sha(puzzle+n))>=bits){{
const u=new URL(location.href);u.searchParams.set('__cfl_p',puzzle);u.searchParams.set('__cfl_a',n);
location.replace(u.toString());return}}}}}})();
</script></body></html>"#
    );

    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        /* never cached: the puzzle is single-use and client-bound */
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(full(html))
        .expect("the interstitial is always valid")
}

/// Passed. Sets clearance and sends them to the page they asked for.
pub fn cleared(path: &str, token: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, path)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        /* HttpOnly so script cannot read it, SameSite=Lax so it survives a normal
           navigation without riding along on cross-site requests */
        .header(
            hyper::header::SET_COOKIE,
            format!(
                "{}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800",
                crate::challenge::COOKIE
            ),
        )
        .body(full(""))
        .expect("the clearance redirect is always valid")
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

