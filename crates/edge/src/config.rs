//! Edge config. The YAML on disk is deserialized into `raw` types, then validated
//! into the types the request path actually uses, so nothing gets parsed per request.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use hyper::http::uri::{Authority, Scheme};
use hyper::Uri;

#[derive(Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub zones: Vec<Zone>,
}

#[derive(Debug)]
pub struct Zone {
    pub name: String,
    pub hostnames: Vec<String>, /* normalized, may start with "*." */
    pub origin: Origin,
}

#[derive(Debug)]
pub struct Origin {
    pub scheme: Scheme,
    pub authority: Authority,
    pub preserve_host: bool,
    pub timeout: Duration,
}

impl Config {
    /// Zone serving this Host header, exact match beating a wildcard.
    pub fn zone_for(&self, host: &str) -> Option<&Zone> {
        let host = normalize_host(host);
        let exact = self
            .zones
            .iter()
            .find(|z| z.hostnames.contains(&host));
        exact.or_else(|| {
            self.zones
                .iter()
                .find(|z| z.hostnames.iter().any(|h| wildcard_match(h, &host)))
        })
    }
}

pub fn load(path: &str) -> Result<Config> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    parse(&text).with_context(|| format!("in {path}"))
}

pub fn parse(text: &str) -> Result<Config> {
    let raw: raw::Config = serde_yaml::from_str(text)?;
    if raw.zones.is_empty() {
        bail!("config has no zones");
    }

    let mut zones = Vec::with_capacity(raw.zones.len());
    for z in raw.zones {
        if z.hostnames.is_empty() {
            bail!("zone `{}` has no hostnames", z.name);
        }
        zones.push(Zone {
            origin: origin_from(&z.name, z.origin)?,
            hostnames: z.hostnames.iter().map(|h| normalize_host(h)).collect(),
            name: z.name,
        });
    }
    Ok(Config {
        listen: raw.listen,
        zones,
    })
}

fn origin_from(zone: &str, o: raw::Origin) -> Result<Origin> {
    let uri: Uri = o
        .url
        .parse()
        .with_context(|| format!("zone `{zone}`: bad origin url `{}`", o.url))?;

    /* insist on an explicit scheme: bare "example.com" parses fine as authority-form
       and would silently become plaintext http for someone who meant https */
    let Some(scheme) = uri.scheme().cloned() else {
        bail!("zone `{zone}`: origin url `{}` needs a scheme, e.g. http://127.0.0.1:8080", o.url);
    };
    if scheme != Scheme::HTTP && scheme != Scheme::HTTPS {
        bail!("zone `{zone}`: origin scheme `{scheme}` is not supported");
    }
    let Some(authority) = uri.authority().cloned() else {
        bail!("zone `{zone}`: origin url `{}` has no host", o.url);
    };
    if !uri.path().is_empty() && uri.path() != "/" {
        bail!("zone `{zone}`: origin url must not carry a path (got `{}`)", uri.path());
    }
    if o.timeout_ms == 0 {
        bail!("zone `{zone}`: origin timeout_ms must be > 0");
    }

    Ok(Origin {
        scheme,
        authority,
        preserve_host: o.preserve_host,
        timeout: Duration::from_millis(o.timeout_ms),
    })
}

/// Lowercase, drop the port and any trailing root dot. Handles `[::1]:8080`.
fn normalize_host(h: &str) -> String {
    let h = h.trim();
    let h = match h.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => h.split(':').next().unwrap_or(h),
    };
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// `*.example.com` covers `a.example.com` but not `example.com` or `a.b.example.com`.
fn wildcard_match(pattern: &str, host: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    match host.strip_suffix(suffix) {
        Some(label) => {
            label.len() > 1 && label.ends_with('.') && !label[..label.len() - 1].contains('.')
        }
        None => false,
    }
}

mod raw {
    use super::SocketAddr;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        #[serde(default = "default_listen")]
        pub listen: SocketAddr,
        pub zones: Vec<Zone>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Zone {
        pub name: String,
        pub hostnames: Vec<String>,
        pub origin: Origin,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Origin {
        pub url: String,
        #[serde(default = "yes")]
        pub preserve_host: bool,
        #[serde(default = "default_timeout_ms")]
        pub timeout_ms: u64,
    }

    fn default_listen() -> SocketAddr {
        "0.0.0.0:8080".parse().unwrap()
    }
    fn yes() -> bool {
        true
    }
    fn default_timeout_ms() -> u64 {
        30_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
listen: "127.0.0.1:9000"
zones:
  - name: demo
    hostnames: ["Demo.Local", "*.demo.local"]
    origin:
      url: "http://127.0.0.1:8081"
  - name: other
    hostnames: ["other.local"]
    origin:
      url: "https://example.com"
      preserve_host: false
      timeout_ms: 1500
"#;

    #[test]
    fn parses_and_normalizes() {
        let cfg = parse(SAMPLE).unwrap();
        assert_eq!(cfg.listen.port(), 9000);
        assert_eq!(cfg.zones[0].hostnames, vec!["demo.local", "*.demo.local"]);
        assert!(cfg.zones[0].origin.preserve_host);
        assert_eq!(cfg.zones[1].origin.scheme, Scheme::HTTPS);
        assert_eq!(cfg.zones[1].origin.timeout, Duration::from_millis(1500));
    }

    #[test]
    fn routes_by_host() {
        let cfg = parse(SAMPLE).unwrap();
        assert_eq!(cfg.zone_for("demo.local").unwrap().name, "demo");
        assert_eq!(cfg.zone_for("DEMO.local:8080").unwrap().name, "demo");
        assert_eq!(cfg.zone_for("demo.local.").unwrap().name, "demo");
        assert_eq!(cfg.zone_for("api.demo.local").unwrap().name, "demo");
        assert_eq!(cfg.zone_for("other.local").unwrap().name, "other");
        assert!(cfg.zone_for("nope.local").is_none());
        assert!(cfg.zone_for("a.b.demo.local").is_none());
    }

    #[test]
    fn exact_beats_wildcard() {
        let cfg = parse(
            r#"
zones:
  - name: wild
    hostnames: ["*.demo.local"]
    origin: { url: "http://127.0.0.1:1" }
  - name: exact
    hostnames: ["api.demo.local"]
    origin: { url: "http://127.0.0.1:2" }
"#,
        )
        .unwrap();
        assert_eq!(cfg.zone_for("api.demo.local").unwrap().name, "exact");
        assert_eq!(cfg.zone_for("www.demo.local").unwrap().name, "wild");
    }

    #[test]
    fn rejects_bad_origins() {
        let cases = [
            ("no scheme", "127.0.0.1:8080"),
            ("no scheme", "example.com"),
            ("bad scheme", "ftp://example.com"),
            ("has a path", "http://example.com/api"),
        ];
        for (why, url) in cases {
            let text = format!(
                "zones:\n  - name: z\n    hostnames: [\"a.local\"]\n    origin: {{ url: \"{url}\" }}\n"
            );
            assert!(parse(&text).is_err(), "should have rejected {why}: {url}");
        }
    }

    #[test]
    fn rejects_empty_config() {
        assert!(parse("zones: []").is_err());
        assert!(parse("zones:\n  - name: z\n    hostnames: []\n    origin: { url: \"http://a.b\" }").is_err());
    }
}
