//! Reading MaxMind DB (`.mmdb`) files, from scratch.
//!
//! The format is two halves. A **binary search tree** whose depth is the bit length of the
//! address: at each node you take the left or right record depending on the next bit of
//! the address, and you stop when a record points past the tree into the **data section**,
//! which is a self-describing encoding of maps, strings and integers.
//!
//! No database is bundled. `geoip.country`/`geoip.asn` name files that are already on the
//! box - GeoLite2, DB-IP, or a paid MaxMind database - because none of them can be
//! redistributed and a stale copy of the world is worse than none.
//!
//! Only what the WAF asks for is decoded: the country ISO code, and the AS number and
//! organisation. Records are navigated lazily rather than decoded into a tree, so looking
//! up a country never reads a city record's worth of bytes.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{bail, Context, Result};
use tracing::info;

/// Sits between the search tree and the data section.
const SEPARATOR: usize = 16;
const METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";
/// A metadata section further back than this is a malformed file, not a big one.
const METADATA_MAX: usize = 128 * 1024;

/// What a lookup found. Both halves are optional because one file rarely has both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Located {
    /// ISO 3166-1 alpha-2, upper case, e.g. `GB`.
    pub country: Option<String>,
    /// Two letters: AF AN AS EU NA OC SA.
    pub continent: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    /// A datacenter or cloud network rather than somebody's home connection. Not an
    /// accusation by itself - plenty of legitimate traffic comes from clouds - but it is
    /// the most useful single signal about a client claiming to be a browser.
    pub hosting: bool,
    /// A commercial VPN or open proxy network.
    pub vpn: bool,
    /// A known Tor exit, from a list the operator supplies.
    pub tor: bool,
}

impl Located {
    pub fn is_empty(&self) -> bool {
        self.country.is_none() && self.asn.is_none()
    }

    /// Deliberately hiding where they are, as opposed to merely being in a datacenter.
    pub fn anonymous(&self) -> bool {
        self.vpn || self.tor
    }
}

pub struct Database {
    bytes: Vec<u8>,
    node_count: u32,
    record_size: u8,
    /// 4 or 6. A v4 database cannot answer a v6 question at all.
    ip_version: u8,
    search_tree_size: usize,
    /// Where a v4 lookup starts in a v6 tree - 96 zero bits down.
    ipv4_start: u32,
    pub kind: String,
}

impl Database {
    pub fn open(path: &Path) -> Result<Database> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let db = Database::parse(bytes).with_context(|| format!("parsing {}", path.display()))?;
        info!(
            "geoip: loaded {} ({}, {} nodes) from {}",
            db.kind,
            match db.ip_version {
                4 => "ipv4",
                _ => "ipv6",
            },
            db.node_count,
            path.display()
        );
        Ok(db)
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Database> {
        /* the metadata is at the *end*, behind the last occurrence of the marker - last,
           because nothing stops the marker's bytes appearing inside the data itself */
        let from = bytes.len().saturating_sub(METADATA_MAX);
        let start = bytes[from..]
            .windows(METADATA_MARKER.len())
            .rposition(|w| w == METADATA_MARKER)
            .map(|p| from + p + METADATA_MARKER.len())
            .ok_or_else(|| anyhow::anyhow!("not a MaxMind database: no metadata marker"))?;

        /* metadata is encoded like any other record, but its pointers - if it had any -
           would be relative to itself, so it is read with its own base */
        let meta = Reader {
            bytes: &bytes,
            base: start,
        };

        let node_count = meta
            .u64_at(meta.key(start, "node_count").context("no node_count")?)
            .context("node_count is not a number")? as u32;
        let record_size = meta
            .u64_at(meta.key(start, "record_size").context("no record_size")?)
            .context("record_size is not a number")? as u8;
        let ip_version = meta
            .u64_at(meta.key(start, "ip_version").context("no ip_version")?)
            .context("ip_version is not a number")? as u8;
        let kind = meta
            .str_at(meta.key(start, "database_type").context("no database_type")?)
            .unwrap_or("unknown")
            .to_owned();

        if !matches!(record_size, 24 | 28 | 32) {
            bail!("record_size {record_size} is not 24, 28 or 32");
        }
        if !matches!(ip_version, 4 | 6) {
            bail!("ip_version {ip_version} is not 4 or 6");
        }

        let node_size = record_size as usize * 2 / 8;
        let search_tree_size = node_count as usize * node_size;
        if search_tree_size + SEPARATOR > bytes.len() {
            bail!("the search tree does not fit in the file");
        }

        let mut db = Database {
            bytes,
            node_count,
            record_size,
            ip_version,
            search_tree_size,
            ipv4_start: 0,
            kind,
        };
        db.ipv4_start = db.find_ipv4_start()?;
        Ok(db)
    }

    /// In a v6 tree, v4 space hangs 96 zero bits down. Walking there once at load saves
    /// doing it on every v4 lookup, which is nearly all of them.
    fn find_ipv4_start(&self) -> Result<u32> {
        if self.ip_version == 4 {
            return Ok(0);
        }
        let mut node = 0u32;
        for _ in 0..96 {
            if node >= self.node_count {
                break;
            }
            node = self.record(node, 0)?;
        }
        Ok(node)
    }

    /// One record out of a node. `bit` is 0 for the left record, 1 for the right.
    fn record(&self, node: u32, bit: u8) -> Result<u32> {
        let node_size = self.record_size as usize * 2 / 8;
        let at = node as usize * node_size;
        let n = self
            .bytes
            .get(at..at + node_size)
            .ok_or_else(|| anyhow::anyhow!("node {node} is past the end of the tree"))?;

        Ok(match (self.record_size, bit) {
            (24, 0) => u32::from_be_bytes([0, n[0], n[1], n[2]]),
            (24, _) => u32::from_be_bytes([0, n[3], n[4], n[5]]),
            /* 28 bits: the middle byte carries the top nibble of each record, high nibble
               for the left and low for the right */
            (28, 0) => u32::from_be_bytes([0, n[0], n[1], n[2]]) | ((n[3] as u32 & 0xF0) << 20),
            (28, _) => u32::from_be_bytes([0, n[4], n[5], n[6]]) | ((n[3] as u32 & 0x0F) << 24),
            (32, 0) => u32::from_be_bytes([n[0], n[1], n[2], n[3]]),
            (32, _) => u32::from_be_bytes([n[4], n[5], n[6], n[7]]),
            _ => bail!("record_size {} is not supported", self.record_size),
        })
    }

    /// Walk the tree for one address and return where its data starts, if any.
    fn find(&self, ip: IpAddr) -> Result<Option<usize>> {
        let (mut node, bits): (u32, Vec<u8>) = match ip {
            IpAddr::V4(v4) => (self.ipv4_start, v4.octets().to_vec()),
            IpAddr::V6(v6) => {
                if self.ip_version == 4 {
                    /* a v4 database has nothing to say about v6, and pretending otherwise
                       would answer every v6 request with whatever 0.0.0.0 maps to */
                    return Ok(None);
                }
                (0, v6.octets().to_vec())
            }
        };

        for byte in bits {
            for shift in (0..8).rev() {
                if node >= self.node_count {
                    break;
                }
                node = self.record(node, (byte >> shift) & 1)?;
            }
        }

        /* exactly node_count means "no data for this address"; anything larger is an
           offset into the data section */
        if node <= self.node_count {
            return Ok(None);
        }
        let at = self.search_tree_size + (node as usize - self.node_count as usize);
        match at < self.bytes.len() {
            true => Ok(Some(at)),
            false => Ok(None),
        }
    }

    /// Country, ASN and AS organisation for an address, as far as this file knows them.
    pub fn lookup(&self, ip: IpAddr) -> Located {
        let Ok(Some(at)) = self.find(ip) else {
            return Located::default();
        };
        let r = self.reader();

        Located {
            /* GeoLite2-Country nests it; some databases put the code at the top level */
            country: r
                .key(at, "country")
                .and_then(|c| r.key(c, "iso_code"))
                .or_else(|| r.key(at, "country_code"))
                .and_then(|c| r.str_at(c))
                .map(|s| s.to_ascii_uppercase()),
            continent: r
                .key(at, "continent")
                .and_then(|c| r.key(c, "code"))
                .and_then(|c| r.str_at(c))
                .map(|s| s.to_ascii_uppercase()),
            asn: r
                .key(at, "autonomous_system_number")
                .and_then(|a| r.u64_at(a))
                .map(|n| n as u32),
            as_org: r
                .key(at, "autonomous_system_organization")
                .and_then(|a| r.str_at(a))
                .map(str::to_owned),
            /* filled in by `Geo`, which is the only thing holding the lists */
            hosting: false,
            vpn: false,
            tor: false,
        }
    }

    fn reader(&self) -> Reader<'_> {
        Reader {
            bytes: &self.bytes,
            base: self.search_tree_size + SEPARATOR,
        }
    }
}

/// The databases this node has, ready to answer a request.
///
/// Two files rather than one because that is how they are published: country and ASN are
/// separate downloads, and a deployment may well have only one of them.
///
/// Loaded here rather than in `config::parse`, for the same reason certificates are: the
/// control plane validates config it has no files for, and a missing database should stop
/// this node starting rather than fail the first request of the day.
pub struct Geo {
    country: Option<Database>,
    asn: Option<Database>,
    signals: Signals,
}

/// Turning facts into signals.
///
/// The facts come from a database. Whether an AS *is* "a hosting provider" is a judgement,
/// and one that goes stale, so it is a keyword match over the AS organisation name with the
/// defaults overridable in config - a wrong guess should be fixable without a release.
///
/// Tor is not a judgement at all, it is a published list. The Tor Project publishes its
/// exit nodes, so the operator points at that file and the answer is exact.
#[derive(Debug, Default)]
pub struct Signals {
    hosting: Vec<String>,
    vpn: Vec<String>,
    tor_exits: std::collections::HashSet<IpAddr>,
}

/// Names that nearly always mean a datacenter. Matched case-insensitively against the AS
/// organisation, so "AMAZON-02" and "Amazon Data Services" both land.
const HOSTING_WORDS: &[&str] = &[
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode", "vultr",
    "hetzner", "ovh", "scaleway", "oracle cloud", "alibaba", "tencent", "cloudflare",
    "fastly", "akamai", "leaseweb", "contabo", "choopa", "hostinger", "rackspace",
    "equinix", "colocation", "datacenter", "data center", "hosting", "cloud",
];

/// Names that suggest a consumer VPN or open proxy rather than a cloud tenant.
const VPN_WORDS: &[&str] = &[
    "vpn", "nordvpn", "expressvpn", "surfshark", "mullvad", "private internet access",
    "cyberghost", "ipvanish", "windscribe", "purevpn", "torguard", "proxy", "anonymizer",
];

impl Signals {
    fn load(cfg: &crate::config::GeoipConfig) -> Result<Signals> {
        /* given a list, use it *instead of* the defaults rather than as well: an operator
           overriding this wants their answer, not ours plus theirs */
        let words = |extra: &[String], defaults: &[&str]| -> Vec<String> {
            match extra.is_empty() {
                true => defaults.iter().map(|w| w.to_string()).collect(),
                false => extra.iter().map(|w| w.to_lowercase()).collect(),
            }
        };

        let mut tor_exits = std::collections::HashSet::new();
        if let Some(path) = &cfg.tor_exits {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading the tor exit list {}", path.display()))?;
            for line in text.lines() {
                /* the published list carries comments and blank lines */
                let line = line.split('#').next().unwrap_or("").trim();
                if let Ok(ip) = line.parse() {
                    tor_exits.insert(ip);
                }
            }
            info!(
                "geoip: {} tor exit nodes from {}",
                tor_exits.len(),
                path.display()
            );
        }

        Ok(Signals {
            hosting: words(&cfg.hosting_keywords, HOSTING_WORDS),
            vpn: words(&cfg.vpn_keywords, VPN_WORDS),
            tor_exits,
        })
    }

    fn apply(&self, ip: IpAddr, found: &mut Located) {
        if let Some(org) = &found.as_org {
            let org = org.to_lowercase();
            found.hosting = self.hosting.iter().any(|w| org.contains(w.as_str()));
            found.vpn = self.vpn.iter().any(|w| org.contains(w.as_str()));
        }
        found.tor = self.tor_exits.contains(&ip);
    }
}

impl Geo {
    /// None when no database is configured at all, so the request path can skip the
    /// lookup entirely rather than asking two empty questions per request.
    pub fn load(cfg: &crate::config::GeoipConfig) -> Result<Option<Geo>> {
        if !cfg.is_configured() {
            return Ok(None);
        }
        Ok(Some(Geo {
            country: cfg.country.as_deref().map(Database::open).transpose()?,
            asn: cfg.asn.as_deref().map(Database::open).transpose()?,
            signals: Signals::load(cfg)?,
        }))
    }

    /// Whatever both files together know about an address.
    pub fn lookup(&self, ip: IpAddr) -> Located {
        let mut found = Located::default();
        if let Some(db) = &self.country {
            let c = db.lookup(ip);
            found.country = c.country;
            found.continent = c.continent;
            /* a combined database may carry both, so don't throw the asn away */
            found.asn = c.asn;
            found.as_org = c.as_org;
        }
        if let Some(db) = &self.asn {
            let a = db.lookup(ip);
            found.asn = a.asn.or(found.asn);
            found.as_org = a.as_org.or(found.as_org);
            found.country = found.country.or(a.country);
            found.continent = found.continent.or(a.continent);
        }
        self.signals.apply(ip, &mut found);
        found
    }

    /// What was loaded, for the admin API and the startup log.
    pub fn describe(&self) -> Vec<(&'static str, &str)> {
        let mut out = Vec::new();
        if let Some(db) = &self.country {
            out.push(("country", db.kind.as_str()));
        }
        if let Some(db) = &self.asn {
            out.push(("asn", db.kind.as_str()));
        }
        out
    }
}

/// Decodes the self-describing data section.
///
/// `base` is where pointers are measured from - the data section for records, and the
/// metadata's own start for metadata.
struct Reader<'a> {
    bytes: &'a [u8],
    base: usize,
}

/// The types this needs. Everything else is skipped over rather than understood.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Kind {
    Pointer,
    Str,
    Double,
    Bytes,
    U16,
    U32,
    Map,
    I32,
    U64,
    U128,
    Array,
    Container,
    EndMarker,
    Bool,
    Float,
    Other(u8),
}

impl From<u8> for Kind {
    fn from(t: u8) -> Kind {
        match t {
            1 => Kind::Pointer,
            2 => Kind::Str,
            3 => Kind::Double,
            4 => Kind::Bytes,
            5 => Kind::U16,
            6 => Kind::U32,
            7 => Kind::Map,
            8 => Kind::I32,
            9 => Kind::U64,
            10 => Kind::U128,
            11 => Kind::Array,
            12 => Kind::Container,
            13 => Kind::EndMarker,
            14 => Kind::Bool,
            15 => Kind::Float,
            other => Kind::Other(other),
        }
    }
}

/// A decoded control byte: what this value is, how big, and where its payload starts.
struct Head {
    kind: Kind,
    size: usize,
    at: usize,
}

impl<'a> Reader<'a> {
    fn head(&self, at: usize) -> Option<Head> {
        let control = *self.bytes.get(at)?;
        let mut kind = Kind::from(control >> 5);
        let mut next = at + 1;

        /* type 0 means the real type is in the following byte, offset by 7 */
        if control >> 5 == 0 {
            kind = Kind::from(self.bytes.get(next)?.checked_add(7)?);
            next += 1;
        }

        let mut size = (control & 0x1f) as usize;
        /* 29, 30 and 31 are escapes: the size is in the next 1, 2 or 3 bytes, biased so
           that no size can be written two ways */
        match size {
            29 => {
                size = 29 + *self.bytes.get(next)? as usize;
                next += 1;
            }
            30 => {
                size = 285 + self.be(next, 2)? as usize;
                next += 2;
            }
            31 => {
                size = 65821 + self.be(next, 3)? as usize;
                next += 3;
            }
            _ => {}
        }
        Some(Head {
            kind,
            size,
            at: next,
        })
    }

    fn be(&self, at: usize, len: usize) -> Option<u64> {
        let slice = self.bytes.get(at..at + len)?;
        Some(slice.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
    }

    /// Follow pointers until something else is reached. A pointer to a pointer is legal
    /// and a pointer to itself is not, so this cannot be a plain loop without a bound.
    fn resolve(&self, mut at: usize) -> Option<(Head, usize)> {
        for _ in 0..8 {
            let head = self.head(at)?;
            if head.kind != Kind::Pointer {
                return Some((head, at));
            }
            at = self.pointer(&head)?;
        }
        None
    }

    /// A pointer's size field is really two fields: two bits of length, three of value.
    fn pointer(&self, head: &Head) -> Option<usize> {
        let kind = (head.size >> 3) & 0x3;
        let high = (head.size & 0x7) as u64;
        let target = match kind {
            0 => (high << 8) | self.be(head.at, 1)?,
            1 => ((high << 16) | self.be(head.at, 2)?) + 2048,
            2 => ((high << 24) | self.be(head.at, 3)?) + 526_336,
            /* the four-byte form carries the whole value, so the three high bits are
               unused rather than the top of the number */
            _ => self.be(head.at, 4)?,
        };
        Some(self.base + target as usize)
    }

    /// Where the value at `at` ends, so a map's keys can be walked without decoding them.
    fn skip(&self, at: usize) -> Option<usize> {
        let head = self.head(at)?;
        Some(match head.kind {
            Kind::Pointer => {
                head.at
                    + match (head.size >> 3) & 0x3 {
                        0 => 1,
                        1 => 2,
                        2 => 3,
                        _ => 4,
                    }
            }
            Kind::Map => {
                let mut pos = head.at;
                for _ in 0..head.size {
                    pos = self.skip(pos)?; /* key */
                    pos = self.skip(pos)?; /* value */
                }
                pos
            }
            Kind::Array => {
                let mut pos = head.at;
                for _ in 0..head.size {
                    pos = self.skip(pos)?;
                }
                pos
            }
            Kind::Bool => head.at,
            _ => head.at + head.size,
        })
    }

    /// The value for `key` in the map at `at`, without decoding the rest of it.
    fn key(&self, at: usize, key: &str) -> Option<usize> {
        let (head, _) = self.resolve(at)?;
        if head.kind != Kind::Map {
            return None;
        }

        let mut pos = head.at;
        for _ in 0..head.size {
            let (name, after_key) = {
                let (k, _) = self.resolve(pos)?;
                let name = match k.kind {
                    Kind::Str => self.bytes.get(k.at..k.at + k.size)?,
                    _ => &[][..],
                };
                (name, self.skip(pos)?)
            };
            if name == key.as_bytes() {
                return Some(after_key);
            }
            pos = self.skip(after_key)?;
        }
        None
    }

    fn str_at(&self, at: usize) -> Option<&'a str> {
        let (head, _) = self.resolve(at)?;
        match head.kind {
            Kind::Str => std::str::from_utf8(self.bytes.get(head.at..head.at + head.size)?).ok(),
            _ => None,
        }
    }

    fn u64_at(&self, at: usize) -> Option<u64> {
        let (head, _) = self.resolve(at)?;
        match head.kind {
            Kind::U16 | Kind::U32 | Kind::U64 | Kind::U128 => match head.size {
                0 => Some(0),
                n => self.be(head.at, n),
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes the handful of types a test database needs.
    ///
    /// Written against the format description rather than against the decoder, and the
    /// decoder is separately checked against byte sequences from the specification below -
    /// so the two agreeing means something.
    #[derive(Default)]
    struct Builder {
        out: Vec<u8>,
    }

    impl Builder {
        fn control(&mut self, kind: u8, size: usize) {
            /* only the short forms are needed: nothing in these fixtures is big */
            assert!(size < 29, "test builder only writes short values");
            match kind < 8 {
                true => self.out.push((kind << 5) | size as u8),
                false => {
                    self.out.push(size as u8);
                    self.out.push(kind - 7);
                }
            }
        }

        fn string(&mut self, s: &str) -> &mut Self {
            self.control(2, s.len());
            self.out.extend_from_slice(s.as_bytes());
            self
        }

        fn uint32(&mut self, v: u32) -> &mut Self {
            let bytes = v.to_be_bytes();
            let start = bytes.iter().position(|b| *b != 0).unwrap_or(4);
            let used = &bytes[start..];
            self.control(6, used.len());
            self.out.extend_from_slice(used);
            self
        }

        fn map(&mut self, pairs: usize) -> &mut Self {
            self.control(7, pairs);
            self
        }
    }

    /// A two-leaf database: 0.0.0.0/1 is GB, 128.0.0.0/1 is DE with an ASN.
    fn tiny_db() -> Vec<u8> {
        /* one node, 24-bit records, so the tree is six bytes. both records point into the
           data section: node_count(1) + 16 + offset */
        let node_count = 1u32;
        let mut data = Builder::default();

        let gb_at = data.out.len();
        data.map(1).string("country").map(1).string("iso_code").string("GB");
        let de_at = data.out.len();
        data.map(2)
            .string("country")
            .map(1)
            .string("iso_code")
            .string("DE")
            .string("autonomous_system_number")
            .uint32(64512);

        let left = node_count as usize + SEPARATOR + gb_at;
        let right = node_count as usize + SEPARATOR + de_at;

        let mut out = Vec::new();
        out.extend_from_slice(&(left as u32).to_be_bytes()[1..]);
        out.extend_from_slice(&(right as u32).to_be_bytes()[1..]);
        out.extend_from_slice(&[0u8; SEPARATOR]);
        out.extend_from_slice(&data.out);

        let mut meta = Builder::default();
        meta.map(4)
            .string("node_count")
            .uint32(node_count)
            .string("record_size")
            .uint32(24)
            .string("ip_version")
            .uint32(4)
            .string("database_type")
            .string("Test-Country");

        out.extend_from_slice(METADATA_MARKER);
        out.extend_from_slice(&meta.out);
        out
    }

    #[test]
    fn reads_the_metadata() {
        let db = Database::parse(tiny_db()).expect("should parse");
        assert_eq!(db.node_count, 1);
        assert_eq!(db.record_size, 24);
        assert_eq!(db.ip_version, 4);
        assert_eq!(db.kind, "Test-Country");
    }

    #[test]
    fn walks_the_tree_to_the_right_leaf() {
        let db = Database::parse(tiny_db()).unwrap();
        /* the very first bit of the address picks the record */
        assert_eq!(db.lookup("1.2.3.4".parse().unwrap()).country.as_deref(), Some("GB"));
        assert_eq!(db.lookup("200.0.0.1".parse().unwrap()).country.as_deref(), Some("DE"));
    }

    #[test]
    fn reads_an_asn_alongside_a_country() {
        let db = Database::parse(tiny_db()).unwrap();
        let found = db.lookup("200.0.0.1".parse().unwrap());
        assert_eq!(found.asn, Some(64512));
        assert_eq!(found.country.as_deref(), Some("DE"));
        /* and the other leaf has no asn rather than a wrong one */
        assert_eq!(db.lookup("1.2.3.4".parse().unwrap()).asn, None);
    }

    #[test]
    fn a_v4_database_says_nothing_about_v6() {
        /* the alternative is answering every v6 request with whatever 0.0.0.0 maps to */
        let db = Database::parse(tiny_db()).unwrap();
        assert!(db.lookup("2001:db8::1".parse().unwrap()).is_empty());
    }

    #[test]
    fn a_file_that_is_not_a_database_is_refused() {
        let e = match Database::parse(vec![0u8; 4096]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a file of zeroes is not a database"),
        };
        assert!(e.contains("no metadata marker"), "unhelpful error: {e}");
    }

    #[test]
    fn a_truncated_tree_is_refused_rather_than_read_off_the_end() {
        let mut bytes = tiny_db();
        let tree = Database::parse(bytes.clone())
            .map(|db| db.search_tree_size)
            .expect("the untruncated file should parse");
        bytes.truncate(tree + 2);
        assert!(Database::parse(bytes).is_err());
    }

    /* the decoder, against byte sequences the format description gives explicitly */

    fn reader(bytes: &[u8]) -> Reader<'_> {
        Reader { bytes, base: 0 }
    }

    #[test]
    fn decodes_the_documented_string_encoding() {
        /* 0x44 = type 2 (utf8), length 4 */
        let bytes = [0x44, b'a', b'b', b'c', b'd'];
        assert_eq!(reader(&bytes).str_at(0), Some("abcd"));
    }

    #[test]
    fn decodes_the_documented_integer_encodings() {
        /* 0xc1 0x01 = uint32, one byte, value 1 */
        assert_eq!(reader(&[0xc1, 0x01]).u64_at(0), Some(1));
        /* a zero-length integer is zero, not an error */
        assert_eq!(reader(&[0xc0]).u64_at(0), Some(0));
        /* 0xa2 0x01 0xf4 = uint16, two bytes, 500 */
        assert_eq!(reader(&[0xa2, 0x01, 0xf4]).u64_at(0), Some(500));
    }

    #[test]
    fn a_size_of_29_or_more_reads_its_length_from_the_next_bytes() {
        /* control 0x5d = type 2, size marker 29: real length is 29 + next byte */
        let mut bytes = vec![0x5d, 0x00];
        bytes.extend(std::iter::repeat_n(b'x', 29));
        assert_eq!(reader(&bytes).str_at(0), Some("x".repeat(29).as_str()));
    }

    #[test]
    fn follows_a_pointer_to_its_target() {
        /* 0x20 0x05 = pointer, size kind 0, target 5; at 5 sits "hi" */
        let bytes = [0x20, 0x05, 0x00, 0x00, 0x00, 0x42, b'h', b'i'];
        assert_eq!(reader(&bytes).str_at(0), Some("hi"));
    }

    #[test]
    fn a_pointer_that_loops_gives_up_instead_of_hanging() {
        /* a pointer at 0 aiming at itself: a malformed file must not wedge the edge */
        let bytes = [0x20, 0x00];
        assert_eq!(reader(&bytes).str_at(0), None);
    }

    #[test]
    fn finds_a_key_without_decoding_its_neighbours() {
        let mut b = Builder::default();
        b.map(2)
            .string("a")
            .string("first")
            .string("wanted")
            .string("second");
        let r = reader(&b.out);
        assert_eq!(r.key(0, "wanted").and_then(|p| r.str_at(p)), Some("second"));
        assert_eq!(r.key(0, "a").and_then(|p| r.str_at(p)), Some("first"));
        assert_eq!(r.key(0, "missing"), None);
    }

    #[test]
    fn skipping_a_nested_map_lands_after_all_of_it() {
        /* the case that breaks a naive walker: a value that is itself a map has to be
           stepped over whole, or the next key is read out of the middle of it */
        let mut b = Builder::default();
        b.map(2)
            .string("nested")
            .map(2)
            .string("x")
            .string("1")
            .string("y")
            .string("2")
            .string("after")
            .string("found me");
        let r = reader(&b.out);
        assert_eq!(r.key(0, "after").and_then(|p| r.str_at(p)), Some("found me"));
    }
}
