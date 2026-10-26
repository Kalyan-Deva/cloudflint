//! The L2 cache: entries on disk, so a restart does not start cold.
//!
//! Memory is L1 and stays the fast path. This tier exists for the thing memory cannot do -
//! survive the process - and for holding far more than RAM will. A hit here is a file read
//! and a promotion into L1; a miss costs one `stat` that failed.
//!
//! Three properties are load-bearing, and each one is a way this could quietly corrupt a
//! site if it were done the obvious way instead:
//!
//! 1. **A write is atomic.** Bytes go to a temporary name and are then renamed into place,
//!    which is atomic on both Linux and Windows. Writing directly to the final name would
//!    mean a crash mid-write leaves a *truncated file with a valid name* - and a truncated
//!    response served as if it were whole is worse than no cache at all.
//! 2. **Every entry validates itself.** A magic number, a format version and the body length
//!    are all in the header, so a file that is short, stale-format or garbage is a miss
//!    rather than a wrong answer.
//! 3. **The index is memory, the truth is the directory.** The index is rebuilt by scanning
//!    at boot. Persisting it would create a second thing that can disagree with reality, and
//!    the disagreement would always be discovered at the worst moment.
//!
//! What this deliberately does **not** do is write on the request path - see `Store`, which
//! hands entries here from a background task. An SSD write inside a request would make the
//! origin's latency the disk's latency.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tracing::{debug, info};

/// `CFL1` - present so a stray file in the directory is not read as an entry.
const MAGIC: &[u8; 4] = b"CFL1";
/// Bumped when the layout changes. Old entries then fail validation and are swept, which
/// is the whole upgrade story: a format change empties the tier rather than misreading it.
const VERSION: u8 = 1;
/// magic(4) + version(1) + stored_at(8) + ttl(4) + status(2) + headers_len(4) + body_len(8)
const HEADER: usize = 31;

/// One entry as it sits on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub status: u16,
    /// Serialised as `name\0value\0` pairs - responses can repeat a header, so a map here
    /// would silently drop `set-cookie`.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub stored_at: u64,
    pub ttl_secs: u32,
}

impl Entry {
    pub fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.stored_at) >= self.ttl_secs as u64
    }

    fn encode(&self) -> Vec<u8> {
        let mut headers = Vec::new();
        for (name, value) in &self.headers {
            headers.extend_from_slice(name.as_bytes());
            headers.push(0);
            headers.extend_from_slice(value.as_bytes());
            headers.push(0);
        }

        let mut out = Vec::with_capacity(HEADER + headers.len() + self.body.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.stored_at.to_be_bytes());
        out.extend_from_slice(&self.ttl_secs.to_be_bytes());
        out.extend_from_slice(&self.status.to_be_bytes());
        out.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.body.len() as u64).to_be_bytes());
        out.extend_from_slice(&headers);
        out.extend_from_slice(&self.body);
        out
    }

    /// Read an entry back, or say why it is not one.
    ///
    /// Every length is checked against what is actually there. A file that claims a bigger
    /// body than it has is exactly what a crash mid-write produces, and it must not read as
    /// a short but valid response.
    fn decode(bytes: &[u8]) -> Result<Entry> {
        if bytes.len() < HEADER {
            bail!("too short to be an entry");
        }
        if &bytes[0..4] != MAGIC {
            bail!("not a cache entry");
        }
        if bytes[4] != VERSION {
            bail!("written by a different version");
        }

        let be64 = |at: usize| -> u64 {
            u64::from_be_bytes(bytes[at..at + 8].try_into().expect("bounds checked"))
        };
        let stored_at = be64(5);
        let ttl_secs = u32::from_be_bytes(bytes[13..17].try_into()?);
        let status = u16::from_be_bytes(bytes[17..19].try_into()?);
        let headers_len = u32::from_be_bytes(bytes[19..23].try_into()?) as usize;
        let body_len = be64(23) as usize;

        /* the check that makes a truncated file a miss rather than a wrong answer */
        if bytes.len() != HEADER + headers_len + body_len {
            bail!(
                "truncated: {} bytes on disk, {} expected",
                bytes.len(),
                HEADER + headers_len + body_len
            );
        }

        let headers_at = &bytes[HEADER..HEADER + headers_len];
        let mut headers = Vec::new();
        let mut parts = headers_at.split(|b| *b == 0);
        while let (Some(name), Some(value)) = (parts.next(), parts.next()) {
            if name.is_empty() {
                continue;
            }
            headers.push((
                String::from_utf8_lossy(name).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            ));
        }

        Ok(Entry {
            status,
            headers,
            body: bytes[HEADER + headers_len..].to_vec(),
            stored_at,
            ttl_secs,
        })
    }
}

/// What the index remembers about a file, so eviction never has to read one.
#[derive(Debug, Clone, Copy)]
struct Slot {
    bytes: u64,
    /// Bumped on every hit; eviction takes the smallest. A counter rather than a clock,
    /// because two entries touched in the same second still have an order.
    used: u64,
}

/// The on-disk tier.
pub struct Disk {
    dir: PathBuf,
    max_bytes: u64,
    index: Mutex<Index>,
}

#[derive(Default)]
struct Index {
    slots: HashMap<u64, Slot>,
    bytes: u64,
    clock: u64,
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl Disk {
    /// Open the tier, rebuilding the index from what is actually on disk.
    ///
    /// Anything that does not validate is deleted here rather than left to fail a request
    /// later - boot is the right moment to find out, and it keeps the byte total honest.
    pub fn open(dir: impl Into<PathBuf>, max_bytes: u64) -> Result<Disk> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating the cache directory {}", dir.display()))?;

        let mut index = Index::default();
        let mut swept = 0u64;

        for entry in std::fs::read_dir(&dir)?.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            /* a leftover temp file is a write that never completed */
            if name.ends_with(".tmp") {
                let _ = std::fs::remove_file(&path);
                swept += 1;
                continue;
            }
            let Some(key) = u64::from_str_radix(name, 16).ok() else {
                continue;
            };

            match std::fs::read(&path).ok().map(|b| Entry::decode(&b)) {
                Some(Ok(_)) => {
                    let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    index.clock += 1;
                    index.slots.insert(
                        key,
                        Slot {
                            bytes,
                            used: index.clock,
                        },
                    );
                    index.bytes += bytes;
                }
                _ => {
                    let _ = std::fs::remove_file(&path);
                    swept += 1;
                }
            }
        }

        info!(
            "cache l2: {} entries, {} MiB in {}{}",
            index.slots.len(),
            index.bytes / (1024 * 1024),
            dir.display(),
            match swept {
                0 => String::new(),
                n => format!(", swept {n} unreadable"),
            }
        );

        let disk = Disk {
            dir,
            max_bytes,
            index: Mutex::new(index),
        };
        disk.evict_to_fit();
        Ok(disk)
    }

    fn path(&self, key: u64) -> PathBuf {
        self.dir.join(format!("{key:016x}"))
    }

    /// Fetch an entry, if it is here and still good.
    pub fn get(&self, key: u64, now: u64) -> Option<Entry> {
        let path = self.path(key);
        let bytes = std::fs::read(&path).ok();

        let found = match bytes.as_deref().map(Entry::decode) {
            Some(Ok(entry)) => entry,
            Some(Err(e)) => {
                /* a file that does not validate is removed, not retried - it will not get
                   better, and leaving it means paying to read it again on every request */
                debug!("cache l2: dropping {key:016x}: {e}");
                self.forget(key);
                return None;
            }
            None => {
                self.index.lock().unwrap_or_else(|e| e.into_inner()).misses += 1;
                return None;
            }
        };

        if found.expired(now) {
            self.forget(key);
            return None;
        }

        let mut index = self.index.lock().unwrap_or_else(|e| e.into_inner());
        index.hits += 1;
        index.clock += 1;
        let clock = index.clock;
        if let Some(slot) = index.slots.get_mut(&key) {
            slot.used = clock;
        }
        Some(found)
    }

    /// Write an entry. Called from a background task, never from the request path.
    pub fn put(&self, key: u64, entry: &Entry) -> Result<()> {
        let encoded = entry.encode();
        let size = encoded.len() as u64;

        /* an object larger than the whole tier would evict everything and still not fit */
        if size > self.max_bytes {
            bail!("entry is larger than the whole l2 cache");
        }

        /* temp then rename: a crash before the rename leaves a .tmp file, which the next
           boot sweeps, rather than a half-written entry under a name something will read */
        let tmp = self.dir.join(format!("{key:016x}.{}.tmp", std::process::id()));
        std::fs::write(&tmp, &encoded).with_context(|| format!("writing {}", tmp.display()))?;
        if let Err(e) = std::fs::rename(&tmp, self.path(key)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).context("renaming the new entry into place");
        }

        {
            let mut index = self.index.lock().unwrap_or_else(|e| e.into_inner());
            index.clock += 1;
            let clock = index.clock;
            if let Some(old) = index.slots.insert(
                key,
                Slot {
                    bytes: size,
                    used: clock,
                },
            ) {
                index.bytes = index.bytes.saturating_sub(old.bytes);
            }
            index.bytes += size;
        }

        self.evict_to_fit();
        Ok(())
    }

    /// Drop one entry from disk and the index.
    pub fn forget(&self, key: u64) {
        let _ = std::fs::remove_file(self.path(key));
        let mut index = self.index.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = index.slots.remove(&key) {
            index.bytes = index.bytes.saturating_sub(slot.bytes);
        }
    }

    /// Empty the tier. What a purge-all has to reach.
    pub fn clear(&self) {
        let mut index = self.index.lock().unwrap_or_else(|e| e.into_inner());
        for key in index.slots.keys() {
            let _ = std::fs::remove_file(self.dir.join(format!("{key:016x}")));
        }
        index.slots.clear();
        index.bytes = 0;
    }

    /// Least recently used out until the tier is under its cap.
    fn evict_to_fit(&self) {
        let mut index = self.index.lock().unwrap_or_else(|e| e.into_inner());
        while index.bytes > self.max_bytes {
            let Some((&key, _)) = index.slots.iter().min_by_key(|(_, slot)| slot.used) else {
                break;
            };
            if let Some(slot) = index.slots.remove(&key) {
                index.bytes = index.bytes.saturating_sub(slot.bytes);
                index.evictions += 1;
                let _ = std::fs::remove_file(self.dir.join(format!("{key:016x}")));
                debug!("cache l2: evicted {key:016x}");
            }
        }
    }

    pub fn stats(&self) -> DiskStats {
        let index = self.index.lock().unwrap_or_else(|e| e.into_inner());
        DiskStats {
            entries: index.slots.len(),
            bytes: index.bytes,
            hits: index.hits,
            misses: index.misses,
            evictions: index.evictions,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskStats {
    pub entries: usize,
    pub bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Wipe a directory of anything that is not ours, used when the cache path changes.
pub fn is_entry_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.len() == 16 && u64::from_str_radix(n, 16).is_ok())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Windows clock resolution is too coarse for a timestamp to be unique across parallel
    /// tests - two of them would share a directory and delete each other's entries.
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "cloudflint-l2-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn entry(body: &str, ttl: u32, now: u64) -> Entry {
        Entry {
            status: 200,
            headers: vec![
                ("content-type".into(), "text/html".into()),
                ("set-cookie".into(), "a=1".into()),
                ("set-cookie".into(), "b=2".into()),
            ],
            body: body.as_bytes().to_vec(),
            stored_at: now,
            ttl_secs: ttl,
        }
    }

    #[test]
    fn an_entry_survives_a_round_trip() {
        let e = entry("hello", 60, 1000);
        let back = Entry::decode(&e.encode()).expect("should decode");
        assert_eq!(back, e);
    }

    #[test]
    fn a_repeated_header_is_not_collapsed() {
        /* a map would silently drop one of two set-cookie headers, which is a real bug and
           an invisible one */
        let back = Entry::decode(&entry("x", 60, 1).encode()).unwrap();
        let cookies: Vec<_> = back
            .headers
            .iter()
            .filter(|(n, _)| n == "set-cookie")
            .collect();
        assert_eq!(cookies.len(), 2, "both cookies should survive");
    }

    #[test]
    fn a_truncated_file_is_refused_rather_than_served_short() {
        /* exactly what a crash mid-write leaves behind. serving it would hand a client
           half a response as though it were whole */
        let full = entry("a much longer body than the header", 60, 1).encode();
        for cut in [HEADER, HEADER + 4, full.len() - 1] {
            assert!(Entry::decode(&full[..cut]).is_err(), "accepted a {cut}-byte file");
        }
    }

    #[test]
    fn a_foreign_file_is_not_an_entry() {
        assert!(Entry::decode(b"").is_err());
        assert!(Entry::decode(b"just some text sitting in the directory").is_err());
        let mut wrong_version = entry("x", 60, 1).encode();
        wrong_version[4] = 99;
        assert!(Entry::decode(&wrong_version).is_err(), "a future format must not be read");
    }

    #[test]
    fn what_goes_in_comes_back_out() {
        let dir = temp_dir("roundtrip");
        let disk = Disk::open(&dir, 1 << 20).unwrap();
        disk.put(1, &entry("body one", 60, 1000)).unwrap();

        let got = disk.get(1, 1001).expect("should be a hit");
        assert_eq!(got.body, b"body one");
        assert_eq!(got.status, 200);
        assert_eq!(disk.stats().entries, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_miss_is_a_miss() {
        let dir = temp_dir("miss");
        let disk = Disk::open(&dir, 1 << 20).unwrap();
        assert!(disk.get(404, 1000).is_none());
        assert_eq!(disk.stats().misses, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_expired_entry_is_a_miss_and_is_removed() {
        let dir = temp_dir("expiry");
        let disk = Disk::open(&dir, 1 << 20).unwrap();
        disk.put(7, &entry("stale", 30, 1000)).unwrap();

        assert!(disk.get(7, 1029).is_some(), "still fresh");
        assert!(disk.get(7, 1030).is_none(), "ttl reached");
        assert_eq!(disk.stats().entries, 0, "and it should not be left on disk");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cache_survives_a_restart() {
        /* the entire reason this tier exists */
        let dir = temp_dir("restart");
        {
            let disk = Disk::open(&dir, 1 << 20).unwrap();
            disk.put(11, &entry("persisted", 3600, 1000)).unwrap();
            disk.put(12, &entry("also persisted", 3600, 1000)).unwrap();
        }

        let reopened = Disk::open(&dir, 1 << 20).unwrap();
        assert_eq!(reopened.stats().entries, 2, "the index should rebuild from disk");
        assert_eq!(reopened.get(11, 1001).unwrap().body, b"persisted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_half_written_file_is_swept_at_boot_not_served() {
        let dir = temp_dir("halfwritten");
        {
            let disk = Disk::open(&dir, 1 << 20).unwrap();
            disk.put(21, &entry("good", 3600, 1000)).unwrap();
        }
        /* a crash mid-write, both shapes: a leftover temp file and a truncated entry */
        std::fs::write(dir.join("00000000000000ff.9999.tmp"), b"partial").unwrap();
        let good = std::fs::read(dir.join(format!("{:016x}", 21u64))).unwrap();
        std::fs::write(dir.join(format!("{:016x}", 22u64)), &good[..good.len() - 5]).unwrap();

        let reopened = Disk::open(&dir, 1 << 20).unwrap();
        assert_eq!(reopened.stats().entries, 1, "only the intact entry should remain");
        assert!(reopened.get(22, 1001).is_none(), "the truncated one must not be served");
        assert!(!dir.join("00000000000000ff.9999.tmp").exists(), "temp file left behind");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_tier_stays_under_its_cap() {
        let dir = temp_dir("evict");
        let one = entry(&"x".repeat(1000), 3600, 1000).encode().len() as u64;
        /* room for about three */
        let disk = Disk::open(&dir, one * 3 + 10).unwrap();

        for key in 1..=6u64 {
            disk.put(key, &entry(&"x".repeat(1000), 3600, 1000)).unwrap();
        }

        let stats = disk.stats();
        assert!(stats.bytes <= one * 3 + 10, "over cap: {} bytes", stats.bytes);
        assert!(stats.entries <= 3, "{} entries left", stats.entries);
        assert!(stats.evictions > 0, "nothing was evicted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn eviction_takes_the_least_recently_used() {
        let dir = temp_dir("lru");
        let one = entry(&"y".repeat(500), 3600, 1000).encode().len() as u64;
        let disk = Disk::open(&dir, one * 2 + 10).unwrap();

        disk.put(1, &entry(&"y".repeat(500), 3600, 1000)).unwrap();
        disk.put(2, &entry(&"y".repeat(500), 3600, 1000)).unwrap();
        /* touch 1 so 2 becomes the coldest */
        assert!(disk.get(1, 1001).is_some());
        disk.put(3, &entry(&"y".repeat(500), 3600, 1000)).unwrap();

        assert!(disk.get(1, 1001).is_some(), "the recently used one should survive");
        assert!(disk.get(2, 1001).is_none(), "the coldest should have gone");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_object_bigger_than_the_whole_tier_is_refused() {
        /* storing it would evict everything else and still not fit */
        let dir = temp_dir("toobig");
        let disk = Disk::open(&dir, 512).unwrap();
        assert!(disk.put(1, &entry(&"z".repeat(4096), 3600, 1000)).is_err());
        assert_eq!(disk.stats().entries, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overwriting_a_key_does_not_double_count_its_bytes() {
        let dir = temp_dir("overwrite");
        let disk = Disk::open(&dir, 1 << 20).unwrap();
        disk.put(1, &entry("first", 3600, 1000)).unwrap();
        let after_one = disk.stats().bytes;
        disk.put(1, &entry("first", 3600, 1000)).unwrap();

        assert_eq!(disk.stats().entries, 1);
        assert_eq!(disk.stats().bytes, after_one, "bytes should not accumulate");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clearing_empties_the_directory() {
        let dir = temp_dir("clear");
        let disk = Disk::open(&dir, 1 << 20).unwrap();
        for key in 1..=4u64 {
            disk.put(key, &entry("x", 3600, 1000)).unwrap();
        }
        disk.clear();

        assert_eq!(disk.stats().entries, 0);
        assert_eq!(disk.stats().bytes, 0);
        assert!(Disk::open(&dir, 1 << 20).unwrap().stats().entries == 0, "and on disk too");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_filename_is_recognisable() {
        assert!(is_entry_file(Path::new("00000000000000ff")));
        assert!(!is_entry_file(Path::new("notes.txt")));
        assert!(!is_entry_file(Path::new("00000000000000ff.tmp")));
    }
}
