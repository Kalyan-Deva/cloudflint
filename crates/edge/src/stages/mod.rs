pub mod cache;
pub mod origin;
pub mod ratelimit;
pub mod waf;

use std::sync::Arc;

use crate::cache::Store;
use crate::limits::health::Health;
use crate::limits::Buckets;
use crate::pipeline::{Pipeline, Stage};

/// Rate limiting first: a client that is over its allowance should be turned away
/// before we spend anything on them, and it is the cheapest check we have. Then the
/// WAF, then the cache, then the origin - which stays last because it always answers.
///
/// The store is passed in rather than made here because the admin API needs to purge
/// it. The per-zone policy every stage works from still comes from the live snapshot.
pub fn build(store: Arc<Store>) -> Pipeline {
    let fetcher = Arc::new(origin::Fetcher::new());
    let buckets = Arc::new(Buckets::new(1 << 16));
    let health = Arc::new(Health::new());

    Pipeline::new(vec![
        Box::new(ratelimit::RateLimit::new(buckets, health)) as Box<dyn Stage>,
        Box::new(waf::Waf),
        Box::new(cache::Cache::new(store, fetcher.clone())),
        Box::new(origin::Origin::new(fetcher)),
    ])
}
