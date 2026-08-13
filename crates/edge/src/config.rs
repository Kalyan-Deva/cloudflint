//! Edge config. The YAML on disk is deserialized into `raw` types, then validated
//! into the types the request path actually uses, so nothing gets parsed per request.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use hyper::http::uri::{Authority, Scheme};
use hyper::Uri;

use crate::cache::policy::{CachePolicy, PathOverride};
use crate::client_ip::ClientIp;
use crate::compress::Policy as CompressionPolicy;
use crate::limits::health::Adaptive;
use crate::limits::{RateRule, Subject};
use crate::waf;

#[derive(Debug)]
pub struct Config {
    pub listen: SocketAddr,
    /// Store sizing. Read once at boot; changing it needs a restart.
    pub cache: StoreConfig,
    /// Connection limits and read timeouts. Also boot-time - they apply before we
    /// know which zone a connection is even for.
    pub limits: NodeLimits,
    /// Where to pull config from and ship analytics to. None means this file is the
    /// only source of truth and nothing leaves the box.
    pub control_plane: Option<String>,
    /// Where to serve purge and stats. None means no admin listener at all.
    pub admin_listen: Option<SocketAddr>,
    /// How to work out who the client is when something sits in front of this node.
    /// Node-wide: what is in front of a process cannot differ per hostname.
    pub client_ip: ClientIp,
    /// None means plaintext only.
    pub tls: Option<TlsConfig>,
    /// Where to get certificates automatically. None means every certificate is somebody
    /// else's problem, which is the default.
    pub acme: Option<AcmeConfig>,
    pub zones: Vec<Zone>,
}

/// One ACME server, for the whole node.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub directory: String,
    /// Where the CA writes to about expiry and problems. Optional, and worth setting.
    pub contact: Option<String>,
    /// The account key *is* the account, so this file is the thing to keep.
    pub account_key: PathBuf,
    /// Renew once a certificate has this many days left. Let's Encrypt issues for 90 and
    /// recommends 30, which leaves two more windows to get it right.
    pub renew_before_days: u32,
    pub check_every: Duration,
    /// How long to wait for a challenge or an order to go valid.
    pub timeout: Duration,
    /// A CA to trust for the ACME server itself, for a staging server that is not
    /// publicly trusted. Not for skipping verification - there is no option for that.
    pub ca: Option<PathBuf>,
    /// The issuance profile to ask for, when a server offers several and they differ in
    /// how long the certificate lasts. None sends nothing, which is right for a CA that
    /// has no profiles.
    pub profile: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub listen: SocketAddr,
    /// A handshake is expensive, and a client that starts one and then dawdles is
    /// slowloris by another route. hyper's header timeout is no help here - it only
    /// starts once there is a decrypted stream to read headers from.
    pub handshake_timeout: Duration,
    /// Answer plaintext requests with a redirect to the https listener.
    pub redirect_http: bool,
}

/// Where a zone's certificate lives. Loaded by `tls`, not by the parser - the
/// control plane validates config without having the files.
#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub struct NodeLimits {
    pub max_connections_per_ip: u32,
    pub new_connections_per_ip_per_sec: u32,
    pub header_read_timeout: Duration,
    pub body_read_timeout: Duration,
    pub max_connection_age: Duration,
    /// How long a shutdown waits for connections to finish before leaving anyway.
    pub drain_timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct StoreConfig {
    pub max_bytes: usize,
    pub max_object_bytes: usize,
}

pub struct Zone {
    pub name: String,
    pub hostnames: Vec<String>, /* normalized, may start with "*." */
    pub origins: OriginPool,
    /// How to talk TLS to this zone's origins. Only used for `https://` origins.
    pub origin_tls: OriginTls,
    pub waf: WafPolicy,
    pub cache: CachePolicy,
    pub compression: CompressionPolicy,
    pub rate_limits: Vec<RateRule>,
    pub adaptive: Adaptive,
    pub tls: Option<TlsPaths>,
    /// Let ACME keep the files in `tls` up to date. Deliberately a flag on the existing
    /// block rather than a second place certificates can come from.
    pub acme: bool,
}

/// A zone's compiled rules plus the knobs around them.
pub struct WafPolicy {
    pub rules: waf::Ruleset,
    pub max_body_bytes: usize,
    /// What to do when a body is too big to inspect: let it through or block it.
    pub on_oversized_body: OnOversized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnOversized {
    #[default]
    Allow,
    Block,
}

#[derive(Debug, Clone)]
pub struct Origin {
    pub scheme: Scheme,
    pub authority: Authority,
    pub preserve_host: bool,
    pub timeout: Duration,
    /// Share of traffic under `weighted`, relative to the other origins. Ignored by
    /// every other strategy.
    pub weight: u32,
}

/// A zone's backends, in the order they should be tried, plus what to do when one of
/// them stops answering. A single `origin:` in config becomes a pool of one, so there is
/// only ever one code path on the request side.
#[derive(Debug, Clone)]
pub struct OriginPool {
    /// Never empty. Order is meaningful for `FirstHealthy`.
    pub origins: Vec<Origin>,
    pub strategy: Strategy,
    /// Consecutive failures before an origin is taken out of rotation.
    pub unhealthy_after: u32,
    /// How long it stays out before it is worth trying again.
    pub retry_after: Duration,
    /// Active health checks. None means passive only - failures are noticed by the
    /// requests that hit them.
    pub probe: Option<ProbeConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strategy {
    /// Earlier origins are preferred: a primary with backups behind it.
    #[default]
    FirstHealthy,
    /// Spread requests across everything healthy, one each in turn.
    RoundRobin,
    /// Round-robin in proportion to each origin's `weight`, for backends of different
    /// sizes.
    Weighted,
    /// Whichever healthy origin has the fewest requests in flight. Follows how long
    /// requests actually take rather than assuming they are all alike.
    LeastConnections,
}

impl Strategy {
    /// The name it is written as in config, so nothing else has to keep its own copy of
    /// this mapping.
    pub fn as_str(self) -> &'static str {
        match self {
            Strategy::FirstHealthy => "first_healthy",
            Strategy::RoundRobin => "round_robin",
            Strategy::Weighted => "weighted",
            Strategy::LeastConnections => "least_connections",
        }
    }
}

/// What the edge does when it connects to an `https://` origin.
///
/// Paths rather than environment variables, matching the zone's own `tls` block: a path is
/// not a secret, the file it points at is, and both have to exist on the node either way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OriginTls {
    /// An extra CA to trust, for an origin with an internal certificate.
    pub ca: Option<PathBuf>,
    /// A client certificate to present - mTLS to the origin.
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    /// Check the origin's certificate. True unless somebody deliberately says otherwise.
    pub verify: bool,
}

impl OriginTls {
    /// Whether this is just "verify, public roots, no client certificate", which needs
    /// nothing loaded and no profile of its own.
    pub fn is_default(&self) -> bool {
        self.verify && self.ca.is_none() && self.client_cert.is_none() && self.client_key.is_none()
    }

    /// Identifies a profile, so zones asking for the same thing share one client and its
    /// connection pool.
    pub fn profile(&self) -> String {
        let path = |p: &Option<PathBuf>| p.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
        format!(
            "{}|{}|{}|{}",
            self.verify,
            path(&self.ca),
            path(&self.client_cert),
            path(&self.client_key)
        )
    }
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub path: String,
    pub every: Duration,
    /// The probe's own timeout, deliberately shorter than a request's.
    pub timeout: Duration,
    /// Consecutive probe successes before a dead origin is used again.
    pub healthy_after: u32,
}

impl OriginPool {
    /// The single origin, for the many places that only ever have one.
    pub fn first(&self) -> &Origin {
        &self.origins[0]
    }

    pub fn healthy_after(&self) -> u32 {
        self.probe.as_ref().map(|p| p.healthy_after).unwrap_or(1)
    }

    pub fn urls(&self) -> Vec<String> {
        self.origins
            .iter()
            .map(|o| format!("{}://{}", o.scheme, o.authority))
            .collect()
    }
}

impl std::fmt::Debug for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        /* compiled rules are closures, so print the count instead */
        f.debug_struct("Zone")
            .field("name", &self.name)
            .field("hostnames", &self.hostnames)
            .field("origins", &self.origins)
            .field("waf_rules", &self.waf.rules.len())
            .field("cache", &self.cache.enabled)
            .field("rate_limits", &self.rate_limits.len())
            .field("tls", &self.tls.is_some())
            .finish()
    }
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

pub fn load(path: impl AsRef<Path>) -> Result<Config> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    parse(&text).with_context(|| format!("in {}", path.display()))
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
            origins: pool_from(&z.name, z.origin, z.origins, z.origin_policy)?,
            origin_tls: origin_tls_from(&z.name, z.origin_tls)?,
            waf: waf_from(&z.name, z.waf, &raw.lists)?,
            cache: cache_from(&z.name, z.cache)?,
            compression: compression_from(&z.name, z.compression)?,
            rate_limits: rate_limits_from(&z.name, z.rate_limits, &raw.lists)?,
            adaptive: adaptive_from(&z.name, z.adaptive)?,
            acme: z.tls.as_ref().map(|t| t.acme).unwrap_or(false),
            tls: z.tls.map(|t| TlsPaths {
                cert: PathBuf::from(t.cert),
                key: PathBuf::from(t.key),
            }),
            hostnames: z.hostnames.iter().map(|h| normalize_host(h)).collect(),
            name: z.name,
        });
    }

    if raw.cache.max_object_bytes > raw.cache.max_bytes {
        bail!("cache.max_object_bytes cannot be larger than cache.max_bytes");
    }

    Ok(Config {
        listen: raw.listen,
        cache: StoreConfig {
            max_bytes: raw.cache.max_bytes,
            max_object_bytes: raw.cache.max_object_bytes,
        },
        limits: NodeLimits {
            max_connections_per_ip: raw.limits.max_connections_per_ip,
            new_connections_per_ip_per_sec: raw.limits.new_connections_per_ip_per_sec,
            header_read_timeout: Duration::from_millis(raw.limits.header_read_timeout_ms),
            body_read_timeout: Duration::from_millis(raw.limits.body_read_timeout_ms),
            max_connection_age: Duration::from_secs(raw.limits.max_connection_age_secs),
            drain_timeout: Duration::from_secs(raw.limits.drain_timeout_secs),
        },
        control_plane: raw.control_plane.map(|u| u.trim_end_matches('/').to_owned()),
        admin_listen: raw.admin_listen,
        client_ip: ClientIp::new(&raw.client_ip.header, &raw.client_ip.trusted_proxies)
            .context("client_ip")?,
        tls: raw.tls.map(|t| TlsConfig {
            listen: t.listen,
            handshake_timeout: Duration::from_millis(t.handshake_timeout_ms),
            redirect_http: t.redirect_http,
        }),
        acme: acme_from(raw.acme, &zones)?,
        zones,
    })
}

fn rate_limits_from(
    zone: &str,
    rules: Vec<raw::RateLimit>,
    lists: &waf::Lists,
) -> Result<Vec<RateRule>> {
    let mut out = Vec::with_capacity(rules.len());
    let mut seen = std::collections::HashSet::new();

    for r in rules {
        if !seen.insert(r.id.clone()) {
            bail!("zone `{zone}`: duplicate rate limit id `{}`", r.id);
        }
        if r.requests == 0 {
            bail!(
                "zone `{zone}`: rate limit `{}` allows zero requests - use a waf block rule instead",
                r.id
            );
        }
        if r.window_secs == 0 {
            bail!("zone `{zone}`: rate limit `{}` needs window_secs above zero", r.id);
        }
        if !matches!(r.action, waf::Action::Block | waf::Action::Log) {
            bail!("zone `{zone}`: rate limit `{}` can only block or log", r.id);
        }

        let subject = match r.key.as_str() {
            "ip" => Subject::Ip,
            "ip_path" => Subject::IpPath,
            other => match other.strip_prefix("header:") {
                Some(name) if !name.is_empty() => Subject::Header(name.to_ascii_lowercase()),
                _ => bail!(
                    "zone `{zone}`: rate limit `{}` has key `{other}` (have: ip, ip_path, header:<name>)",
                    r.id
                ),
            },
        };

        let matcher = match &r.r#match {
            None => None,
            Some(expr) => {
                let ast = waf::parser::parse(expr)
                    .with_context(|| format!("zone `{zone}`: rate limit `{}`", r.id))?;
                if ast.needs_body() {
                    /* the limit is decided before we would ever buffer a body */
                    bail!(
                        "zone `{zone}`: rate limit `{}` cannot match on the request body",
                        r.id
                    );
                }
                Some(
                    waf::compile::compile(&ast, lists)
                        .with_context(|| format!("zone `{zone}`: rate limit `{}`", r.id))?,
                )
            }
        };

        out.push(RateRule {
            id: r.id,
            matcher,
            subject,
            requests: r.requests,
            window: Duration::from_secs(r.window_secs),
            action: r.action,
        });
    }
    Ok(out)
}

fn adaptive_from(zone: &str, a: raw::Adaptive) -> Result<Adaptive> {
    if !(0.0..=1.0).contains(&a.tighten_to) {
        bail!("zone `{zone}`: adaptive.tighten_to must be between 0 and 1");
    }
    if a.window_secs == 0 {
        bail!("zone `{zone}`: adaptive.window_secs must be above zero");
    }
    Ok(Adaptive {
        enabled: a.enabled,
        window: Duration::from_secs(a.window_secs),
        min_requests: a.min_requests,
        error_ratio: a.error_ratio,
        slow: Duration::from_millis(a.slow_ms),
        slow_ratio: a.slow_ratio,
        tighten_to: a.tighten_to,
    })
}

fn cache_from(zone: &str, c: raw::Cache) -> Result<CachePolicy> {
    let mut overrides = Vec::with_capacity(c.overrides.len());
    for o in c.overrides {
        if !o.path_prefix.starts_with('/') {
            bail!("zone `{zone}`: cache override path_prefix must start with `/` (got `{}`)", o.path_prefix);
        }
        overrides.push(PathOverride {
            path_prefix: o.path_prefix,
            ttl: Duration::from_secs(o.ttl_secs),
            override_origin_headers: o.override_origin_headers,
        });
    }

    Ok(CachePolicy {
        enabled: c.enabled,
        vary_on: c.vary_on.iter().map(|v| v.to_ascii_lowercase()).collect(),
        ignore_query_params: c
            .ignore_query_params
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .collect(),
        key_query_params: c
            .key_query_params
            .map(|ps| ps.iter().map(|p| p.to_ascii_lowercase()).collect()),
        stale_while_revalidate: Duration::from_secs(c.stale_while_revalidate_secs),
        stale_if_error: Duration::from_secs(c.stale_if_error_secs),
        coalesce_wait: Duration::from_millis(c.coalesce_wait_ms),
        overrides,
    })
}

fn waf_from(zone: &str, w: raw::Waf, lists: &waf::Lists) -> Result<WafPolicy> {
    if w.max_body_bytes == 0 {
        bail!("zone `{zone}`: waf.max_body_bytes must be > 0");
    }
    let rules = waf::build(&w.rulesets, w.rules, lists)
        .with_context(|| format!("zone `{zone}`: waf"))?;

    Ok(WafPolicy {
        rules,
        max_body_bytes: w.max_body_bytes,
        on_oversized_body: w.on_oversized_body,
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

    if o.weight == 0 {
        bail!("zone `{zone}`: origin weight must be > 0 - to take a backend out, remove it");
    }

    Ok(Origin {
        scheme,
        authority,
        preserve_host: o.preserve_host,
        timeout: Duration::from_millis(o.timeout_ms),
        weight: o.weight,
    })
}

fn acme_from(raw: Option<raw::Acme>, zones: &[Zone]) -> Result<Option<AcmeConfig>> {
    let Some(raw) = raw else {
        /* a zone asking for acme with no acme server named is a config that looks like it
           will get certificates and never will */
        if let Some(zone) = zones.iter().find(|z| z.acme) {
            bail!(
                "zone `{}` sets tls.acme but there is no top-level `acme` block naming a server",
                zone.name
            );
        }
        return Ok(None);
    };

    if !raw.directory.starts_with("https://") && !raw.directory.starts_with("http://") {
        bail!("acme.directory `{}` needs a scheme", raw.directory);
    }
    if raw.renew_before_days == 0 {
        bail!("acme.renew_before_days must be > 0, or a certificate is only renewed once it has expired");
    }
    if raw.check_every_secs == 0 {
        bail!("acme.check_every_secs must be > 0");
    }
    if let Some(contact) = &raw.contact {
        /* the CA will reject anything else, and finding that out at issuance time is a
           slower way to learn it */
        if !contact.starts_with("mailto:") {
            bail!("acme.contact `{contact}` should be a mailto: address");
        }
    }

    Ok(Some(AcmeConfig {
        directory: raw.directory,
        contact: raw.contact,
        account_key: PathBuf::from(raw.account_key),
        renew_before_days: raw.renew_before_days,
        check_every: Duration::from_secs(raw.check_every_secs),
        timeout: Duration::from_secs(raw.timeout_secs),
        ca: raw.ca.map(PathBuf::from),
        profile: raw.profile,
    }))
}

fn origin_tls_from(zone: &str, t: raw::OriginTls) -> Result<OriginTls> {
    /* a certificate without its key would fail at handshake time, on a request, in
       production. it is a typo, and a typo should not wait that long to be a problem */
    match (&t.client_cert, &t.client_key) {
        (Some(_), None) => bail!("zone `{zone}`: origin_tls.client_cert needs client_key too"),
        (None, Some(_)) => bail!("zone `{zone}`: origin_tls.client_key needs client_cert too"),
        _ => {}
    }
    Ok(OriginTls {
        ca: t.ca.map(PathBuf::from),
        client_cert: t.client_cert.map(PathBuf::from),
        client_key: t.client_key.map(PathBuf::from),
        verify: t.verify,
    })
}

fn compression_from(zone: &str, c: raw::Compression) -> Result<CompressionPolicy> {
    if c.max_bytes < c.min_bytes {
        bail!("zone `{zone}`: compression.max_bytes is below min_bytes, so nothing would ever compress");
    }
    Ok(CompressionPolicy {
        enabled: c.enabled,
        min_bytes: c.min_bytes,
        max_bytes: c.max_bytes,
        types: c
            .types
            .unwrap_or_else(crate::compress::default_types)
            .iter()
            .map(|t| t.trim().to_ascii_lowercase())
            .collect(),
    })
}

/// `origin:` for one backend, `origins:` for several. Both end up as a pool, so the
/// request path never has two shapes to handle.
fn pool_from(
    zone: &str,
    one: Option<raw::Origin>,
    many: Option<Vec<raw::Origin>>,
    policy: Option<raw::OriginPolicy>,
) -> Result<OriginPool> {
    let raw_origins = match (one, many) {
        (Some(_), Some(_)) => bail!(
            "zone `{zone}`: give either `origin` for one backend or `origins` for several, not both"
        ),
        (Some(one), None) => vec![one],
        (None, Some(many)) if many.is_empty() => {
            bail!("zone `{zone}`: `origins` is empty - a zone needs somewhere to send traffic")
        }
        (None, Some(many)) => many,
        (None, None) => bail!("zone `{zone}`: no origin"),
    };

    let mut origins = Vec::with_capacity(raw_origins.len());
    for raw in raw_origins {
        let origin = origin_from(zone, raw)?;
        /* two entries for the same backend would share one health state and give it a
           double share of the traffic, neither of which anybody means to ask for */
        if origins
            .iter()
            .any(|o: &Origin| o.authority == origin.authority && o.scheme == origin.scheme)
        {
            bail!("zone `{zone}`: origin `{}` is listed twice", origin.authority);
        }
        origins.push(origin);
    }

    let policy = policy.unwrap_or_default();
    let strategy = match policy.strategy.as_str() {
        "first_healthy" => Strategy::FirstHealthy,
        "round_robin" => Strategy::RoundRobin,
        "weighted" => Strategy::Weighted,
        "least_connections" => Strategy::LeastConnections,
        other => bail!(
            "zone `{zone}`: origin strategy `{other}` (have: first_healthy, round_robin, \
             weighted, least_connections)"
        ),
    };
    if strategy == Strategy::Weighted && origins.iter().all(|o| o.weight == 1) && origins.len() > 1 {
        /* every weight left at the default makes this plain round-robin with more
           machinery, which is almost certainly not what somebody meant to write */
        bail!("zone `{zone}`: strategy is weighted but no origin has a weight - set some, or use round_robin");
    }
    if policy.unhealthy_after == 0 {
        bail!("zone `{zone}`: origin_policy.unhealthy_after must be > 0, or nothing is ever taken out");
    }

    let probe = match policy.probe {
        None => None,
        Some(p) => {
            if !p.path.starts_with('/') {
                bail!("zone `{zone}`: probe path `{}` must start with /", p.path);
            }
            if p.every_secs == 0 {
                bail!("zone `{zone}`: probe every_secs must be > 0");
            }
            if p.timeout_ms == 0 {
                bail!("zone `{zone}`: probe timeout_ms must be > 0");
            }
            if p.healthy_after == 0 {
                bail!("zone `{zone}`: probe healthy_after must be > 0, or nothing ever recovers");
            }
            Some(ProbeConfig {
                path: p.path,
                every: Duration::from_secs(p.every_secs),
                timeout: Duration::from_millis(p.timeout_ms),
                healthy_after: p.healthy_after,
            })
        }
    };

    Ok(OriginPool {
        origins,
        strategy,
        unhealthy_after: policy.unhealthy_after,
        retry_after: Duration::from_secs(policy.retry_after_secs),
        probe,
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
    use super::{OnOversized, SocketAddr};
    use crate::waf;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        #[serde(default = "default_listen")]
        pub listen: SocketAddr,
        /// Named lists the rules refer to as `$name`.
        #[serde(default)]
        pub lists: waf::Lists,
        #[serde(default)]
        pub cache: Store,
        #[serde(default)]
        pub limits: Limits,
        #[serde(default)]
        pub control_plane: Option<String>,
        #[serde(default)]
        pub admin_listen: Option<SocketAddr>,
        #[serde(default)]
        pub client_ip: ClientIp,
        #[serde(default)]
        pub tls: Option<Tls>,
        #[serde(default)]
        pub acme: Option<Acme>,
        pub zones: Vec<Zone>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Acme {
        pub directory: String,
        #[serde(default)]
        pub contact: Option<String>,
        #[serde(default = "default_account_key")]
        pub account_key: String,
        #[serde(default = "default_renew_before")]
        pub renew_before_days: u32,
        #[serde(default = "default_acme_check")]
        pub check_every_secs: u64,
        #[serde(default = "default_acme_timeout")]
        pub timeout_secs: u64,
        #[serde(default)]
        pub ca: Option<String>,
        /// Only sent if set. See `AcmeConfig::profile`.
        #[serde(default)]
        pub profile: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ClientIp {
        #[serde(default = "default_client_ip_header")]
        pub header: String,
        /// Empty - the default - means the header is never read. See `client_ip`.
        #[serde(default)]
        pub trusted_proxies: Vec<String>,
    }

    impl Default for ClientIp {
        fn default() -> Self {
            ClientIp {
                header: default_client_ip_header(),
                trusted_proxies: Vec::new(),
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Tls {
        pub listen: SocketAddr,
        #[serde(default = "default_handshake_timeout")]
        pub handshake_timeout_ms: u64,
        #[serde(default = "yes")]
        pub redirect_http: bool,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TlsPaths {
        pub cert: String,
        pub key: String,
        /// Keep these two files up to date automatically. See the `acme` block.
        #[serde(default)]
        pub acme: bool,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Limits {
        /// 0 means no cap.
        #[serde(default = "default_max_conns")]
        pub max_connections_per_ip: u32,
        #[serde(default = "default_new_conns")]
        pub new_connections_per_ip_per_sec: u32,
        #[serde(default = "default_header_timeout")]
        pub header_read_timeout_ms: u64,
        #[serde(default = "default_body_timeout")]
        pub body_read_timeout_ms: u64,
        #[serde(default = "default_conn_age")]
        pub max_connection_age_secs: u64,
        #[serde(default = "default_drain")]
        pub drain_timeout_secs: u64,
    }

    impl Default for Limits {
        fn default() -> Self {
            Limits {
                max_connections_per_ip: default_max_conns(),
                new_connections_per_ip_per_sec: default_new_conns(),
                header_read_timeout_ms: default_header_timeout(),
                body_read_timeout_ms: default_body_timeout(),
                max_connection_age_secs: default_conn_age(),
                drain_timeout_secs: default_drain(),
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Store {
        #[serde(default = "default_store_bytes")]
        pub max_bytes: usize,
        #[serde(default = "default_object_bytes")]
        pub max_object_bytes: usize,
    }

    impl Default for Store {
        fn default() -> Self {
            Store {
                max_bytes: default_store_bytes(),
                max_object_bytes: default_object_bytes(),
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Zone {
        pub name: String,
        pub hostnames: Vec<String>,
        /// One backend. Exactly one of this and `origins` is required.
        #[serde(default)]
        pub origin: Option<Origin>,
        /// Several, in preference order.
        #[serde(default)]
        pub origins: Option<Vec<Origin>>,
        #[serde(default)]
        pub origin_policy: Option<OriginPolicy>,
        #[serde(default)]
        pub origin_tls: OriginTls,
        #[serde(default)]
        pub waf: Waf,
        #[serde(default)]
        pub cache: Cache,
        #[serde(default)]
        pub compression: Compression,
        #[serde(default)]
        pub rate_limits: Vec<RateLimit>,
        #[serde(default)]
        pub adaptive: Adaptive,
        #[serde(default)]
        pub tls: Option<TlsPaths>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OriginTls {
        #[serde(default)]
        pub ca: Option<String>,
        #[serde(default)]
        pub client_cert: Option<String>,
        #[serde(default)]
        pub client_key: Option<String>,
        /// Deliberately defaults to true, and deliberately not global.
        #[serde(default = "yes")]
        pub verify: bool,
    }

    impl Default for OriginTls {
        fn default() -> Self {
            OriginTls {
                ca: None,
                client_cert: None,
                client_key: None,
                verify: true,
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Compression {
        #[serde(default = "yes")]
        pub enabled: bool,
        #[serde(default = "default_min_compress")]
        pub min_bytes: usize,
        #[serde(default = "default_max_compress")]
        pub max_bytes: usize,
        /// Absent means the built-in list of text-ish types.
        #[serde(default)]
        pub types: Option<Vec<String>>,
    }

    impl Default for Compression {
        fn default() -> Self {
            Compression {
                enabled: true,
                min_bytes: default_min_compress(),
                max_bytes: default_max_compress(),
                types: None,
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OriginPolicy {
        /// first_healthy | round_robin
        #[serde(default = "default_strategy")]
        pub strategy: String,
        #[serde(default = "default_unhealthy_after")]
        pub unhealthy_after: u32,
        #[serde(default = "default_retry_after")]
        pub retry_after_secs: u64,
        #[serde(default)]
        pub probe: Option<Probe>,
    }

    impl Default for OriginPolicy {
        fn default() -> Self {
            OriginPolicy {
                strategy: default_strategy(),
                unhealthy_after: default_unhealthy_after(),
                retry_after_secs: default_retry_after(),
                probe: None,
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Probe {
        #[serde(default = "default_probe_path")]
        pub path: String,
        #[serde(default = "default_probe_every")]
        pub every_secs: u64,
        #[serde(default = "default_probe_timeout")]
        pub timeout_ms: u64,
        #[serde(default = "default_healthy_after")]
        pub healthy_after: u32,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RateLimit {
        pub id: String,
        /// Optional waf expression scoping the limit. Cannot look at the body.
        #[serde(default)]
        pub r#match: Option<String>,
        /// ip | ip_path | header:<name>
        #[serde(default = "default_key")]
        pub key: String,
        pub requests: u32,
        pub window_secs: u64,
        #[serde(default = "block_action")]
        pub action: waf::Action,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Adaptive {
        #[serde(default = "yes")]
        pub enabled: bool,
        #[serde(default = "default_adaptive_window")]
        pub window_secs: u64,
        #[serde(default = "default_min_requests")]
        pub min_requests: u32,
        #[serde(default = "default_error_ratio")]
        pub error_ratio: f64,
        #[serde(default = "default_slow_ms")]
        pub slow_ms: u64,
        #[serde(default = "default_slow_ratio")]
        pub slow_ratio: f64,
        #[serde(default = "default_tighten_to")]
        pub tighten_to: f64,
    }

    impl Default for Adaptive {
        fn default() -> Self {
            Adaptive {
                enabled: true,
                window_secs: default_adaptive_window(),
                min_requests: default_min_requests(),
                error_ratio: default_error_ratio(),
                slow_ms: default_slow_ms(),
                slow_ratio: default_slow_ratio(),
                tighten_to: default_tighten_to(),
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Cache {
        #[serde(default = "yes")]
        pub enabled: bool,
        #[serde(default = "default_vary_on")]
        pub vary_on: Vec<String>,
        #[serde(default = "default_ignored_params")]
        pub ignore_query_params: Vec<String>,
        /// Absent means every param is part of the key.
        #[serde(default)]
        pub key_query_params: Option<Vec<String>>,
        #[serde(default)]
        pub stale_while_revalidate_secs: u64,
        #[serde(default = "default_stale_if_error")]
        pub stale_if_error_secs: u64,
        #[serde(default = "default_coalesce_wait")]
        pub coalesce_wait_ms: u64,
        #[serde(default)]
        pub overrides: Vec<CacheOverride>,
    }

    /// Caching is on by default, but with no default ttl - nothing is held unless the
    /// origin asks for it or an override says so. Safe, and still useful out of the box.
    impl Default for Cache {
        fn default() -> Self {
            Cache {
                enabled: true,
                vary_on: default_vary_on(),
                ignore_query_params: default_ignored_params(),
                key_query_params: None,
                stale_while_revalidate_secs: 0,
                stale_if_error_secs: default_stale_if_error(),
                coalesce_wait_ms: default_coalesce_wait(),
                overrides: Vec::new(),
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CacheOverride {
        pub path_prefix: String,
        pub ttl_secs: u64,
        #[serde(default)]
        pub override_origin_headers: bool,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Waf {
        /// Built-in rulesets to load. Empty list turns the WAF off for the zone.
        #[serde(default = "default_rulesets")]
        pub rulesets: Vec<String>,
        #[serde(default)]
        pub rules: Vec<waf::RawRule>,
        #[serde(default = "default_max_body")]
        pub max_body_bytes: usize,
        #[serde(default)]
        pub on_oversized_body: OnOversized,
    }

    /// A zone with no `waf:` block still gets the core ruleset - a WAF you have to
    /// remember to switch on is a WAF that is off.
    impl Default for Waf {
        fn default() -> Self {
            Waf {
                rulesets: default_rulesets(),
                rules: Vec::new(),
                max_body_bytes: default_max_body(),
                on_oversized_body: OnOversized::default(),
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Origin {
        pub url: String,
        #[serde(default = "yes")]
        pub preserve_host: bool,
        #[serde(default = "default_timeout_ms")]
        pub timeout_ms: u64,
        /// Only read by the `weighted` strategy.
        #[serde(default = "default_weight")]
        pub weight: u32,
    }

    fn default_listen() -> SocketAddr {
        "0.0.0.0:8080".parse().unwrap()
    }
    fn yes() -> bool {
        true
    }
    fn default_weight() -> u32 {
        1
    }
    fn default_account_key() -> String {
        "certs/acme-account.key".to_string()
    }
    /// Let's Encrypt issues for 90 days and suggests renewing at 30, which leaves two more
    /// chances if the first attempt fails.
    fn default_renew_before() -> u32 {
        30
    }
    /// Twice a day. Renewal is not urgent and a CA's rate limits are, so there is nothing
    /// to gain from looking more often.
    fn default_acme_check() -> u64 {
        12 * 3600
    }
    fn default_acme_timeout() -> u64 {
        90
    }
    fn default_timeout_ms() -> u64 {
        30_000
    }
    fn default_rulesets() -> Vec<String> {
        vec!["core".to_string()]
    }
    fn default_max_body() -> usize {
        128 * 1024
    }
    fn default_store_bytes() -> usize {
        256 * 1024 * 1024
    }
    fn default_object_bytes() -> usize {
        8 * 1024 * 1024
    }
    fn default_vary_on() -> Vec<String> {
        vec!["accept-encoding".to_string()]
    }
    /// Tracking parameters that would otherwise shard the cache per visitor.
    fn default_ignored_params() -> Vec<String> {
        [
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_term",
            "utm_content",
            "gclid",
            "fbclid",
            "msclkid",
            "mc_cid",
            "mc_eid",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }
    fn default_stale_if_error() -> u64 {
        60
    }
    fn default_coalesce_wait() -> u64 {
        5_000
    }
    fn default_max_conns() -> u32 {
        256
    }
    fn default_new_conns() -> u32 {
        128
    }
    /// The slowloris number. A client that cannot finish its headers in ten seconds
    /// is either broken or trying something.
    fn default_header_timeout() -> u64 {
        10_000
    }
    fn default_body_timeout() -> u64 {
        30_000
    }
    fn default_conn_age() -> u64 {
        300
    }
    /// Long enough for a slow page, short enough that a deploy doesn't stall on one
    /// stuck client. Kubernetes' own default grace period is 30s.
    fn default_drain() -> u64 {
        30
    }
    fn default_client_ip_header() -> String {
        crate::client_ip::DEFAULT_HEADER.to_string()
    }
    fn default_strategy() -> String {
        "first_healthy".to_string()
    }
    /// Under a kilobyte the headers cost more than the saving.
    fn default_min_compress() -> usize {
        1024
    }
    /// Compressing buffers the body, so this is also the most memory one response can
    /// cost. Anything larger streams through untouched.
    fn default_max_compress() -> usize {
        1024 * 1024
    }
    /// Three, not one: a single failed request is usually the request's fault, and
    /// taking a backend out on one is how a blip becomes an outage.
    fn default_unhealthy_after() -> u32 {
        3
    }
    fn default_retry_after() -> u64 {
        10
    }
    fn default_probe_path() -> String {
        "/".to_string()
    }
    fn default_probe_every() -> u64 {
        10
    }
    fn default_probe_timeout() -> u64 {
        2_000
    }
    /// Two, so a backend that is flapping has to answer twice before it gets traffic.
    fn default_healthy_after() -> u32 {
        2
    }
    fn default_key() -> String {
        "ip".to_string()
    }
    fn block_action() -> waf::Action {
        waf::Action::Block
    }
    fn default_adaptive_window() -> u64 {
        10
    }
    fn default_min_requests() -> u32 {
        20
    }
    fn default_error_ratio() -> f64 {
        0.25
    }
    fn default_slow_ms() -> u64 {
        1_000
    }
    fn default_slow_ratio() -> f64 {
        0.5
    }
    fn default_tighten_to() -> f64 {
        0.5
    }
    fn default_handshake_timeout() -> u64 {
        10_000
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
        assert!(cfg.zones[0].origins.first().preserve_host);
        assert_eq!(cfg.zones[1].origins.first().scheme, Scheme::HTTPS);
        assert_eq!(cfg.zones[1].origins.first().timeout, Duration::from_millis(1500));
        /* a single `origin:` is a pool of one, so the request path has one shape */
        assert_eq!(cfg.zones[0].origins.origins.len(), 1);
        assert_eq!(cfg.zones[0].origins.strategy, Strategy::FirstHealthy);
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
