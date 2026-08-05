use lru::LruCache;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
}

impl CacheKey {
    pub fn new(name: &str, qtype: u16) -> Self {
        Self {
            name: name.to_string(),
            qtype,
        }
    }
}

#[derive(Debug, Clone)]
pub enum BlockCache {
    NXDomain,
    Poison,
}

#[derive(Debug, Clone)]
pub enum CacheRecord {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Block(BlockCache),
    /// HTTPS/SVCB 类型记录，存放应答记录的完整 wire 编码
    Https(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub records: Vec<CacheRecord>,
    pub expires_at: Instant,
    pub ttl: u32,
}

impl CacheEntry {
    pub fn action_name(&self) -> &'static str {
        for r in &self.records {
            match r {
                CacheRecord::Block(_b) => return "block-cache",
                CacheRecord::Https(_) => return "forward-cache",
                _ => {}
            }
        }
        if self.records.is_empty() {
            return "forward-cache-fail";
        }
        "forward-cache"
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
    inner: Arc<Mutex<LruCache<CacheKey, CacheEntry>>>,
    min_ttl: Duration,
    max_ttl: Duration,
    serve_expired: bool,
    pub keep_ttl: bool,
}

impl DnsCache {
    pub fn new(size: usize, min_ttl: u32, max_ttl: u32, serve_expired: bool, keep_ttl: bool) -> Self {
        let cap = NonZeroUsize::new(size).unwrap_or_else(|| NonZeroUsize::new(1024).unwrap());
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(cap))),
            min_ttl: Duration::from_secs(min_ttl as u64),
            max_ttl: Duration::from_secs(max_ttl as u64),
            serve_expired,
            keep_ttl,
        }
    }

    pub async fn get_cached(&self, key: &CacheKey) -> CacheResult {
        let mut cache = self.inner.lock().await;
        if let Some(entry) = cache.get(key) {
            let now = Instant::now();
            if entry.expires_at > now {
                return CacheResult::Fresh(entry.clone());
            }
            if self.serve_expired {
                return CacheResult::Stale(entry.clone());
            }
            cache.pop(key);
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
            records,
            expires_at: now + ttl_duration,
            ttl,
        };
        let mut cache = self.inner.lock().await;
        cache.put(key, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_cache_fresh() {
        let cache = DnsCache::new(10, 60, 3600, false, false);
        let key = CacheKey::new("example.com", 1);
        let records = vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
        cache.put(key.clone(), records.clone(), 300).await;

        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
    }

    #[tokio::test]
    async fn test_cache_stale() {
        let cache = DnsCache::new(10, 0, 1, true, false);
        let key = CacheKey::new("stale.com", 1);
        cache.put(key.clone(), vec![], 0).await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Stale(_)));
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = DnsCache::new(10, 60, 3600, false, false);
        let key = CacheKey::new("miss.com", 1);
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Miss));
    }

    #[tokio::test]
    async fn test_cache_block() {
        let cache = DnsCache::new(10, 60, 3600, false, false);
        let key = CacheKey::new("block.test", 1);
        cache
            .put(key.clone(), vec![CacheRecord::Block(BlockCache::NXDomain)], 300)
            .await;
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
    }

    #[tokio::test]
    async fn test_remaining_ttl_decrement() {
        let cache = DnsCache::new(10, 0, 3600, false, false);
        let key = CacheKey::new("ttl.test", 1);
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
        let key = CacheKey::new("keepttl.test", 1);
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
