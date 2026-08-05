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

#[derive(Debug, Clone)]
pub enum BlockCache {
    NXDomain,
    Poison,
}

#[derive(Debug, Clone)]
pub enum CacheRecord {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    Block(BlockCache),
    HTTPS(Vec<u8>),
    Other(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub records: Vec<CacheRecord>,
    pub expires_at: Instant,
}

impl CacheEntry {
    pub fn action_name(&self) -> &'static str {
        for r in &self.records {
            match r {
                CacheRecord::Block(b) => {
                    return match b {
                        BlockCache::NXDomain => "block-nxdomain-cache",
                        BlockCache::Poison => "block-poison-cache",
                    }
                }
                CacheRecord::HTTPS(_) => return "forward-cache",
                CacheRecord::Other(_) => return "forward-cache",
                _ => {}
            }
        }
        "forward-cache"
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
}

impl DnsCache {
    pub fn new(size: usize, min_ttl: u32, max_ttl: u32, serve_expired: bool) -> Self {
        let cap = NonZeroUsize::new(size).unwrap_or_else(|| NonZeroUsize::new(1024).unwrap());
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(cap))),
            min_ttl: Duration::from_secs(min_ttl as u64),
            max_ttl: Duration::from_secs(max_ttl as u64),
            serve_expired,
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

    pub async fn put(&self, key: CacheKey, records: Vec<CacheRecord>, ttl: u32, keep_ttl: bool) {
        let ttl_duration = if keep_ttl {
            Duration::from_secs(ttl as u64)
        } else {
            Duration::from_secs(ttl as u64).clamp(self.min_ttl, self.max_ttl)
        };
        let entry = CacheEntry {
            records,
            expires_at: Instant::now() + ttl_duration,
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
        let cache = DnsCache::new(10, 60, 3600, false);
        let key = CacheKey {
            name: "example.com".into(),
            qtype: 1,
        };
        let records = vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
        cache.put(key.clone(), records.clone(), 300, false).await;

        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
    }

    #[tokio::test]
    async fn test_cache_stale() {
        let cache = DnsCache::new(10, 0, 1, true);
        let key = CacheKey {
            name: "stale.com".into(),
            qtype: 1,
        };
        cache.put(key.clone(), vec![], 0, false).await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Stale(_)));
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = DnsCache::new(10, 60, 3600, false);
        let key = CacheKey {
            name: "miss.com".into(),
            qtype: 1,
        };
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Miss));
    }

    #[tokio::test]
    async fn test_cache_block() {
        let cache = DnsCache::new(10, 60, 3600, false);
        let key = CacheKey {
            name: "block.test".into(),
            qtype: 1,
        };
        cache
            .put(key.clone(), vec![CacheRecord::Block(BlockCache::NXDomain)], 300, false)
            .await;
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
    }
}
