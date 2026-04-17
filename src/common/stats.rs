use ahash::RandomState;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
/// Traffic statistics for a single outbound
#[derive(Debug, Default)]
pub struct TrafficStats {
    uplink: AtomicU64,   // bytes sent to remote (upload)
    downlink: AtomicU64, // bytes received from remote (download)
}

impl TrafficStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_uplink(&self, bytes: u64) {
        self.uplink.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_downlink(&self, bytes: u64) {
        self.downlink.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn uplink(&self) -> u64 {
        self.uplink.load(Ordering::Relaxed)
    }

    pub fn downlink(&self) -> u64 {
        self.downlink.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.uplink() + self.downlink()
    }
}

/// Global traffic statistics manager
#[derive(Debug, Default)]
pub struct StatsCollector {
    // Per-outbound stats indexed by tag
    per_outbound: HashMap<String, Arc<TrafficStats>, RandomState>,
    // Global totals
    global: Arc<TrafficStats>,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self {
            per_outbound: HashMap::with_hasher(RandomState::new()),
            global: Arc::new(TrafficStats::new()),
        }
    }

    /// Register an outbound tag for tracking (if not already registered)
    pub fn register_outbound(&mut self, tag: impl Into<String>) -> Arc<TrafficStats> {
        let tag = tag.into();
        self.per_outbound
            .entry(tag.clone())
            .or_insert_with(|| Arc::new(TrafficStats::new()))
            .clone()
    }

    /// Get stats for a specific outbound tag
    pub fn get_outbound_stats(&self, tag: &str) -> Option<Arc<TrafficStats>> {
        self.per_outbound.get(tag).cloned()
    }

    /// Check if an outbound tag is registered
    pub fn has_outbound(&self, tag: &str) -> bool {
        self.per_outbound.contains_key(tag)
    }

    /// Get global stats
    pub fn global_stats(&self) -> Arc<TrafficStats> {
        self.global.clone()
    }

    /// Get all registered outbound tags
    pub fn outbound_tags(&self) -> Vec<String> {
        self.per_outbound.keys().cloned().collect()
    }

    /// Get total traffic across all outbounds (calculated on demand)
    pub fn calculate_total(&self) -> (u64, u64) {
        let mut total_uplink = 0u64;
        let mut total_downlink = 0u64;

        for stats in self.per_outbound.values() {
            total_uplink += stats.uplink();
            total_downlink += stats.downlink();
        }

        (total_uplink, total_downlink)
    }
}

/// Thread-safe shared stats collector
pub type SharedStats = Arc<RwLock<StatsCollector>>;

pub fn create_shared_stats() -> SharedStats {
    Arc::new(RwLock::new(StatsCollector::new()))
}
