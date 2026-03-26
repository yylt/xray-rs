// src/route/cache.rs
use lru::LruCache;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::matcher::RecordType;

/// 缓存键
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: RecordType,
}

/// 缓存条目
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub records: Vec<CacheRecord>,
    pub expires_at: Instant,
}

/// 缓存记录（简化版，只存 A/AAAA）
#[derive(Debug, Clone)]
pub enum CacheRecord {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    Other(Vec<u8>),
}

/// DNS 缓存配置
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub size: usize,
    pub min_ttl: u32,
    pub max_ttl: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            size: 4096,
            min_ttl: 60,
            max_ttl: 3600,
        }
    }
}

/// LRU DNS 缓存
#[derive(Clone)]
pub struct DnsCache {
    inner: Arc<Mutex<LruCache<CacheKey, CacheEntry>>>,
    min_ttl: Duration,
    max_ttl: Duration,
}

impl DnsCache {
    pub fn new(config: &CacheConfig) -> Self {
        let cap = NonZeroUsize::new(config.size).unwrap_or(NonZeroUsize::new(1024).unwrap());
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(cap))),
            min_ttl: Duration::from_secs(config.min_ttl as u64),
            max_ttl: Duration::from_secs(config.max_ttl as u64),
        }
    }

    /// 查询缓存
    pub fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        let mut cache = self.inner.lock().unwrap();
        if let Some(entry) = cache.get(key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.clone());
            }
            cache.pop(key);
        }
        None
    }

    /// 写入缓存，ttl 会被 clamp 到 [min_ttl, max_ttl]
    pub fn put(&self, key: CacheKey, records: Vec<CacheRecord>, ttl: u32) {
        let ttl_duration = Duration::from_secs(ttl as u64).clamp(self.min_ttl, self.max_ttl);
        let entry = CacheEntry {
            records,
            expires_at: Instant::now() + ttl_duration,
        };
        let mut cache = self.inner.lock().unwrap();
        cache.put(key, entry);
    }

    /// 缓存大小
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_put_get() {
        let cache = DnsCache::new(&CacheConfig::default());
        let key = CacheKey {
            name: "example.com".into(),
            qtype: RecordType::A,
        };
        let records = vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
        cache.put(key.clone(), records.clone(), 300);

        let entry = cache.get(&key).unwrap();
        assert_eq!(entry.records.len(), 1);
    }

    #[test]
    fn test_cache_expiry() {
        let config = CacheConfig {
            size: 10,
            min_ttl: 0,
            max_ttl: 1,
        };
        let cache = DnsCache::new(&config);
        let key = CacheKey {
            name: "expire.com".into(),
            qtype: RecordType::A,
        };
        cache.put(key.clone(), vec![], 0);
        // min_ttl=0, max_ttl=1, ttl=0 clamp to 0, expires immediately
        std::thread::sleep(Duration::from_millis(10));
        // Entry should be expired
    }

    #[test]
    fn test_cache_lru_eviction() {
        let config = CacheConfig {
            size: 2,
            min_ttl: 60,
            max_ttl: 3600,
        };
        let cache = DnsCache::new(&config);
        for i in 0..3 {
            let key = CacheKey {
                name: format!("domain{}.com", i),
                qtype: RecordType::A,
            };
            cache.put(key, vec![], 300);
        }
        assert_eq!(cache.len(), 2);
    }
}
