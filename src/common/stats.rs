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

/// Non-sensitive configuration labels and current payload counters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficSnapshot {
    pub direction: String,
    pub tag: String,
    pub proxy: String,
    pub transport: String,
    pub security: String,
    pub supported: bool,
    pub uplink: u64,
    pub downlink: u64,
}

/// Both views of one business flow; never sum inbound and outbound totals.
#[derive(Clone, Default)]
pub struct TrafficCounters {
    pub inbound: Option<Arc<TrafficStats>>,
    pub outbound: Option<Arc<TrafficStats>>,
}

impl TrafficCounters {
    pub fn record_uplink(&self, bytes: u64) {
        for stats in self.inbound.iter().chain(self.outbound.iter()) {
            stats.record_uplink(bytes);
        }
    }

    pub fn record_downlink(&self, bytes: u64) {
        for stats in self.inbound.iter().chain(self.outbound.iter()) {
            stats.record_downlink(bytes);
        }
    }
}

/// Global traffic statistics manager
#[derive(Debug, Default)]
pub struct StatsCollector {
    // Per-outbound stats indexed by tag
    per_outbound: HashMap<String, Arc<TrafficStats>, RandomState>,
    per_inbound: HashMap<String, Arc<TrafficStats>, RandomState>,
    metadata: Vec<TrafficSnapshot>,
    // Global totals
    global: Arc<TrafficStats>,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self {
            per_outbound: HashMap::with_hasher(RandomState::new()),
            per_inbound: HashMap::with_hasher(RandomState::new()),
            metadata: Vec::new(),
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

    pub fn register_metadata(&mut self, metadata: TrafficSnapshot) {
        if metadata.direction == "inbound" {
            self.per_inbound.entry(metadata.tag.clone()).or_default();
        } else {
            self.register_outbound(&metadata.tag);
        }
        self.metadata
            .retain(|item| item.direction != metadata.direction || item.tag != metadata.tag);
        self.metadata.push(metadata);
    }

    pub fn counters(&self, inbound: &str, outbound: &str) -> TrafficCounters {
        TrafficCounters {
            inbound: self.per_inbound.get(inbound).cloned(),
            outbound: self.get_outbound_stats(outbound),
        }
    }

    pub fn snapshot(&self) -> Vec<TrafficSnapshot> {
        let mut snapshots = self.metadata.clone();
        for item in &mut snapshots {
            let counters = if item.direction == "inbound" {
                &self.per_inbound
            } else {
                &self.per_outbound
            };
            if let Some(stats) = counters.get(&item.tag) {
                item.uplink = stats.uplink();
                item.downlink = stats.downlink();
            }
        }
        snapshots.sort_by(|a, b| (&a.direction, &a.tag).cmp(&(&b.direction, &b.tag)));
        snapshots
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
