//! `cache` stage — cache-first query cache (core `DnsCache` + pipeline
//! stage).
//!
//! Pipeline position: after `groups`, before `rules`.  The stage splits
//! into two calls driven by the server:
//!
//! - [`Cache::lookup`]: `ctx.skip_cache` → `Continue`; Fresh → build
//!   response and `Respond` (short-circuits before rules); Stale
//!   (serve_expired) → build fallback response from stale entry, mark
//!   `ctx.served_stale`, `Continue` (the rules stage then re-runs through
//!   the pipeline to refresh the entry with a fresh upstream answer);
//!   Miss → `Continue`.
//! - [`Cache::write_back`]: after the rules stage fills `ctx.response`, if
//!   the response came from upstream (`ctx.action` starts with "forward")
//!   and `!ctx.skip_cache`, it is written to cache.

use ahash::RandomState;
use hickory_proto::rr::rdata::svcb::SVCB;
use hickory_proto::rr::RecordType;
use log::warn;
use moka::future::Cache as MokaCache;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{CacheConfig, Config};
use crate::metrics::{Counter, Gauge, MetricsRegistry};
use crate::plugins::util::{build_response_from_cache, build_servfail, cache_upstream_response};
use crate::query::{QueryContext, Step};

// ---------------------------------------------------------------------------
// Cache core
// ---------------------------------------------------------------------------

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
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Https(SVCB),
    NxDomain,
    /// Empty NOERROR answer for a query type that has no records (NoData).
    NoData,
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
            CacheRecord::NoData => "forward-cache-nodata",
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

/// Per-operation cache metrics.  Created by the cache stage; attached to
/// the [`DnsCache`] via [`DnsCache::attach_metrics`].
#[derive(Clone, Default)]
pub struct CacheMetrics {
    pub lookup_total: Option<Counter>,
    pub entries: Option<Gauge>,
    pub serve_expired_total: Option<Counter>,
}

impl CacheMetrics {
    /// Registers all cache metrics on `registry`.
    pub fn register(registry: &MetricsRegistry) -> Self {
        Self {
            lookup_total: Some(registry.counter("rsdns_cache_lookup_total", "Cache lookups", &["result"])),
            entries: Some(registry.gauge("rsdns_cache_entries", "Current cache entries", &[])),
            serve_expired_total: Some(registry.counter("rsdns_cache_serve_expired_total", "Stale entries served", &[])),
        }
    }
}

#[derive(Clone)]
pub struct DnsCache {
    inner: MokaCache<CacheKey, CacheEntry, RandomState>,
    min_ttl: Duration,
    max_ttl: Duration,
    serve_expired: bool,
    pub keep_ttl: bool,
    metrics: Arc<std::sync::OnceLock<CacheMetrics>>,
}

impl DnsCache {
    /// Builds a cache with a shared metrics slot (filled in by the cache
    /// stage's `register_metrics`).
    pub fn new_metric(size: usize, min_ttl: u32, max_ttl: u32, serve_expired: bool, keep_ttl: bool) -> Self {
        let metrics: Arc<std::sync::OnceLock<CacheMetrics>> = Arc::new(std::sync::OnceLock::new());
        let cache = MokaCache::builder()
            .max_capacity(size as u64)
            .build_with_hasher(RandomState::new());
        Self {
            inner: cache,
            min_ttl: Duration::from_secs(min_ttl as u64),
            max_ttl: Duration::from_secs(max_ttl as u64),
            serve_expired,
            keep_ttl,
            metrics,
        }
    }

    /// Attaches the metrics collected by the cache stage.
    pub fn attach_metrics(&self, metrics: CacheMetrics) {
        let _ = self.metrics.set(metrics);
        if let Some(m) = self.metrics.get() {
            if let Some(g) = &m.entries {
                g.set(self.inner.entry_count());
            }
        }
    }

    pub async fn get_cached(&self, key: &CacheKey) -> CacheResult {
        let result = if let Some(entry) = self.inner.get(key).await {
            let now = Instant::now();
            if entry.expires_at > now {
                CacheResult::Fresh(entry)
            } else if self.serve_expired {
                CacheResult::Stale(entry)
            } else {
                CacheResult::Miss
            }
        } else {
            CacheResult::Miss
        };

        if let Some(m) = self.metrics.get() {
            let label = match &result {
                CacheResult::Fresh(_) => "fresh",
                CacheResult::Stale(_) => "stale",
                CacheResult::Miss => "miss",
            };
            if let Some(c) = &m.lookup_total {
                c.with_label_values(&[label]).inc();
            }
            if matches!(result, CacheResult::Stale(_)) {
                if let Some(c) = &m.serve_expired_total {
                    c.inc();
                }
            }
        }
        result
    }

    pub async fn put(&self, key: CacheKey, records: Vec<CacheRecord>, ttl: u32) {
        let now = Instant::now();
        let ttl_duration = if self.keep_ttl {
            Duration::from_secs(ttl as u64)
        } else {
            let d = Duration::from_secs(ttl as u64);
            d.clamp(self.min_ttl, self.max_ttl)
        };
        let entry = CacheEntry {
            records: records.into(),
            expires_at: now + ttl_duration,
            ttl,
        };
        self.inner.insert(key, entry).await;
        if let Some(m) = self.metrics.get() {
            if let Some(g) = &m.entries {
                g.set(self.inner.entry_count());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

/// Builds the cache stage from the `cache:` config section (or the default).
pub fn init(config: &Config, registry: &MetricsRegistry) -> Cache {
    let raw = config.plugin_sections.get("cache").cloned().unwrap_or_default();
    let cfg: CacheConfig = serde_yaml::from_value(raw).unwrap_or_default();
    let cache = DnsCache::new_metric(
        cfg.size.unwrap_or(4096),
        cfg.min_ttl.unwrap_or(60),
        cfg.max_ttl.unwrap_or(3600),
        cfg.serve_expired.unwrap_or(false),
        cfg.keep_ttl.unwrap_or(false),
    );
    let metrics = CacheMetrics::register(registry);
    cache.attach_metrics(metrics);
    Cache { cache }
}

/// The cache stage.
pub struct Cache {
    cache: DnsCache,
}

impl Cache {
    /// Cache-first lookup.  Returns `Respond` when a fresh cached entry
    /// answers; `Continue` on miss or stale (stale sets `ctx.served_stale`
    /// so the server spawns a background pipeline re-run).
    pub async fn lookup(&self, ctx: &mut QueryContext) -> Step {
        if ctx.skip_cache {
            return Step::Continue;
        }

        match self.cache.get_cached(&ctx.key).await {
            CacheResult::Fresh(entry) => {
                // 缓存命中：答案已在写回前按测速排序，跳过 speed 阶段重复探测。
                ctx.skip_speed = true;
                let action = entry.action_name();
                match build_response_from_cache(&ctx.msg, &entry, self.cache.keep_ttl) {
                    Ok(resp) => {
                        ctx.response = Some(resp);
                        ctx.action = action.into();
                        Step::Respond
                    }
                    Err(e) => {
                        warn!("building cache response for {} failed: {}", ctx.name(), e);
                        ctx.response = Some(build_servfail(&ctx.msg));
                        ctx.action = action.into();
                        Step::Respond
                    }
                }
            }
            CacheResult::Stale(entry) => {
                // 缓存命中（stale 兜底）：先以 stale 应答返回，同样跳过 speed
                // 阶段；后续规则阶段会用上游新鲜结果替换（此时未命中缓存，
                // skip_speed 保持原值，新鲜结果仍会走 speed 排序）。
                ctx.skip_speed = true;
                let response = match build_response_from_cache(&ctx.msg, &entry, self.cache.keep_ttl) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("building cache stale for {} failed: {}", ctx.name(), e);
                        build_servfail(&ctx.msg)
                    }
                };
                // 先以 stale 应答兜底，并标记 `served_stale`；规则阶段会尝试
                // 用上游的新鲜结果替换它（`refresh_stale`），成功则写回缓存。
                ctx.response = Some(response);
                ctx.action = "forward-stale".into();
                ctx.served_stale = true;
                Step::Continue
            }
            CacheResult::Miss => Step::Continue,
        }
    }

    /// Writes an upstream response back into the cache (positive records +
    /// NXDOMAIN negative), unless `ctx.skip_cache` was set, the response
    /// did not come from upstream, or it is still an unreplaced stale
    /// fallback (`ctx.served_stale`).
    pub async fn write_back(&self, ctx: &QueryContext) {
        if ctx.skip_cache || ctx.served_stale {
            return;
        }
        if let Some(response) = ctx.response.as_ref() {
            if ctx.action.starts_with("forward") {
                // rules 的 ttl 覆盖已应用在 response 上。
                let rewrite_ttl = None;
                cache_upstream_response(&self.cache, &ctx.key, response, rewrite_ttl).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_cache_fresh() {
        let cache = DnsCache::new_metric(10, 60, 3600, false, false);
        let key = CacheKey::new("example.com", RecordType::A);
        let records = vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
        cache.put(key.clone(), records.clone(), 300).await;

        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
    }

    #[tokio::test]
    async fn test_cache_stale() {
        let cache = DnsCache::new_metric(10, 0, 1, true, false);
        let key = CacheKey::new("stale.com", RecordType::A);
        cache.put(key.clone(), vec![], 0).await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Stale(_)));
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = DnsCache::new_metric(10, 60, 3600, false, false);
        let key = CacheKey::new("miss.com", RecordType::A);
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Miss));
    }

    #[tokio::test]
    async fn test_cache_empty_entry() {
        let cache = DnsCache::new_metric(10, 60, 3600, false, false);
        let key = CacheKey::new("block.test", RecordType::A);
        cache.put(key.clone(), vec![], 300).await;
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
    }

    #[tokio::test]
    async fn test_cache_nodata_action_name() {
        let cache = DnsCache::new_metric(10, 60, 3600, false, false);
        let key = CacheKey::new("nodata.test", RecordType::A);
        cache.put(key.clone(), vec![CacheRecord::NoData], 300).await;
        if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
            assert_eq!(entry.action_name(), "forward-cache-nodata");
        } else {
            panic!("expected Fresh");
        }
    }

    #[tokio::test]
    async fn test_remaining_ttl_decrement() {
        let cache = DnsCache::new_metric(10, 0, 3600, false, false);
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
        let cache = DnsCache::new_metric(10, 0, 3600, false, true);
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
