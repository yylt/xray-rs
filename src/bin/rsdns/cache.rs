use ahash::RandomState;
use hickory_proto::rr::rdata::svcb::SVCB;
use hickory_proto::rr::RecordType;
use moka::future::Cache;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: RecordType,
}

impl CacheKey {
    pub fn new(name: impl Into<String>, qtype: RecordType) -> Self {
        Self {
            name: name.into(),
            qtype,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CacheRecord {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Mx { preference: u16, exchange: String },
    Txt(Vec<String>),
    Https(SVCB),
    NxDomain,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub records: Arc<[CacheRecord]>,
    pub expires_at: Instant,
    pub ttl: u32,
}

impl CacheEntry {
    pub fn action_name(&self) -> &'static str {
        if self.records.is_empty() {
            return "forward-cache-fail";
        }
        match &self.records[0] {
            CacheRecord::NxDomain => "forward-cache-nxdomain",
            _ => "forward-cache",
        }
    }

    pub fn remaining_ttl(&self, keep_ttl: bool) -> u32 {
        if keep_ttl {
            return self.ttl;
        }
        let now = Instant::now();
        if now >= self.expires_at {
            return 0;
        }
        (self.expires_at - now).as_secs() as u32
    }
}

pub enum CacheResult {
    Fresh(CacheEntry),
    Stale(CacheEntry),
    Miss,
}

#[derive(Clone)]
pub struct DnsCache {
    inner: Cache<CacheKey, CacheEntry, RandomState>,
    min_ttl: Duration,
    max_ttl: Duration,
    serve_expired: bool,
    pub keep_ttl: bool,
}

impl DnsCache {
    pub fn new(size: usize, min_ttl: u32, max_ttl: u32, serve_expired: bool, keep_ttl: bool) -> Self {
        let cache = Cache::builder()
            .max_capacity(size as u64)
            .build_with_hasher(RandomState::new());
        Self {
            inner: cache,
            min_ttl: Duration::from_secs(min_ttl as u64),
            max_ttl: Duration::from_secs(max_ttl as u64),
            serve_expired,
            keep_ttl,
        }
    }

    pub async fn get_cached(&self, key: &CacheKey) -> CacheResult {
        if let Some(entry) = self.inner.get(key).await {
            let now = Instant::now();
            if entry.expires_at > now {
                return CacheResult::Fresh(entry);
            }
            if self.serve_expired {
                return CacheResult::Stale(entry);
            }
        }
        CacheResult::Miss
    }

    pub async fn put(&self, key: CacheKey, records: Vec<CacheRecord>, ttl: u32) {
        let now = Instant::now();
        let ttl_duration = if self.keep_ttl {
            Duration::from_secs(ttl as u64)
        } else {
            Duration::from_secs(ttl as u64).clamp(self.min_ttl, self.max_ttl)
        };
        let entry = CacheEntry {
            records: records.into(),
            expires_at: now + ttl_duration,
            ttl,
        };
        self.inner.insert(key, entry).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_cache_fresh() {
        let cache = DnsCache::new(10, 60, 3600, false, false);
        let key = CacheKey::new("example.com", RecordType::A);
        let records = vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
        cache.put(key.clone(), records.clone(), 300).await;

        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
    }

    #[tokio::test]
    async fn test_cache_stale() {
        let cache = DnsCache::new(10, 0, 1, true, false);
        let key = CacheKey::new("stale.com", RecordType::A);
        cache.put(key.clone(), vec![], 0).await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Stale(_)));
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = DnsCache::new(10, 60, 3600, false, false);
        let key = CacheKey::new("miss.com", RecordType::A);
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Miss));
    }

    #[tokio::test]
    async fn test_cache_empty_entry() {
        let cache = DnsCache::new(10, 60, 3600, false, false);
        let key = CacheKey::new("block.test", RecordType::A);
        cache.put(key.clone(), vec![], 300).await;
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
    }

    #[tokio::test]
    async fn test_remaining_ttl_decrement() {
        let cache = DnsCache::new(10, 0, 3600, false, false);
        let key = CacheKey::new("ttl.test", RecordType::A);
        let records = vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
        cache.put(key.clone(), records, 5).await;
        tokio::time::sleep(Duration::from_millis(1100)).await;

        if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
            let remaining = entry.remaining_ttl(false);
            assert!(remaining < 5, "remaining_ttl should decrement: {}", remaining);
        } else {
            panic!("expected Fresh");
        }
    }

    #[tokio::test]
    async fn test_remaining_ttl_keepttl() {
        let cache = DnsCache::new(10, 0, 3600, false, true);
        let key = CacheKey::new("keepttl.test", RecordType::A);
        let records = vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
        cache.put(key.clone(), records, 5).await;
        tokio::time::sleep(Duration::from_millis(1100)).await;

        if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
            let remaining = entry.remaining_ttl(true);
            assert_eq!(remaining, 5, "keep_ttl should return original TTL");
        } else {
            panic!("expected Fresh");
        }
    }
}
