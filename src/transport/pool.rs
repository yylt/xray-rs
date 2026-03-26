use ahash::RandomState;
// Connection pool with Tower-based load balancing
use log::{info, trace};
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening circuit
    pub failure_threshold: usize,
    /// Duration to wait before attempting to close circuit
    pub timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Health status of a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
}

/// Connection status for graceful draining
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Normal operation
    Active,
    /// Marked for removal, no new connections
    Draining,
}

/// Connection state for a single destination
pub struct ConnectionState<T> {
    /// The connection/channel (lazy initialized)
    pub connection: Option<T>,
    /// Connection status (Active or Draining)
    pub conn_status: ConnectionStatus,
    /// Health status
    pub health: HealthStatus,
    /// Number of consecutive failures
    pub failure_count: AtomicUsize,
    /// Number of active requests (for least-connections)
    pub active_requests: AtomicUsize,
    /// Last failure time
    pub last_failure: Option<Instant>,
    /// Average latency in nanoseconds (EWMA)
    pub avg_latency_ns: AtomicU64,
}

impl<T> ConnectionState<T> {
    /// EWMA smoothing factor: 0.2 means 20% weight for new value, 80% for old
    const EWMA_ALPHA: f64 = 0.2;

    pub fn new() -> Self {
        Self {
            connection: None,
            conn_status: ConnectionStatus::Active,
            health: HealthStatus::Healthy,
            failure_count: AtomicUsize::new(0),
            active_requests: AtomicUsize::new(0),
            last_failure: None,
            avg_latency_ns: AtomicU64::new(0),
        }
    }

    /// Check if circuit breaker allows connection
    pub fn can_connect(&self, config: &CircuitBreakerConfig) -> bool {
        if self.health == HealthStatus::Healthy {
            return true;
        }

        // Check if timeout has passed
        if let Some(last_failure) = self.last_failure {
            if last_failure.elapsed() >= config.timeout {
                return true; // Try to recover
            }
        }

        false
    }

    /// Record a successful request
    pub fn record_success(&mut self) {
        self.failure_count.store(0, Ordering::Relaxed);
        self.health = HealthStatus::Healthy;
        self.last_failure = None;
    }

    /// Record a failed request
    pub fn record_failure(&mut self, config: &CircuitBreakerConfig) {
        let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= config.failure_threshold {
            self.health = HealthStatus::Unhealthy;
            self.last_failure = Some(Instant::now());
        }
    }

    /// Record latency using EWMA
    pub fn record_latency(&self, latency_ns: u64) {
        let current = self.avg_latency_ns.load(Ordering::Relaxed);
        let new_avg = if current == 0 {
            // First measurement
            latency_ns
        } else {
            // EWMA: new_avg = α * new_value + (1-α) * old_avg
            let current_f = current as f64;
            let latency_f = latency_ns as f64;
            (Self::EWMA_ALPHA * latency_f + (1.0 - Self::EWMA_ALPHA) * current_f) as u64
        };
        self.avg_latency_ns.store(new_avg, Ordering::Relaxed);
    }

    /// Get average latency in nanoseconds
    pub fn get_avg_latency_ns(&self) -> u64 {
        self.avg_latency_ns.load(Ordering::Relaxed)
    }

    /// Get current load (for least-connections)
    pub fn load(&self) -> usize {
        self.active_requests.load(Ordering::Relaxed)
    }

    /// Increment active request count
    pub fn inc_active(&self) {
        self.active_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active request count
    pub fn dec_active(&self) {
        self.active_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Connection pool with load balancing
pub struct ConnectionPool<T> {
    /// Destination addresses
    destinations: Vec<SocketAddr>,
    /// Connection states per destination
    pool: Arc<RwLock<HashMap<SocketAddr, ConnectionState<T>, RandomState>>>,
    /// Load balancer
    load_balancer: Arc<super::balancer::LoadBalancer>,
    /// Circuit breaker configuration
    circuit_breaker_config: CircuitBreakerConfig,
}

impl<T> ConnectionPool<T> {
    pub fn new(
        destinations: Vec<SocketAddr>,
        strategy: super::balancer::Strategy,
        circuit_breaker_config: CircuitBreakerConfig,
    ) -> Self {
        Self {
            destinations,
            pool: Arc::new(RwLock::new(HashMap::with_hasher(RandomState::new()))),
            load_balancer: Arc::new(super::balancer::LoadBalancer::new(strategy)),
            circuit_breaker_config,
        }
    }

    /// Select a destination using load balancing
    pub async fn select_destination(&self) -> Result<SocketAddr> {
        let pool = self.pool.read().await;

        // Filter healthy destinations
        let mut healthy_dests = Vec::new();
        for addr in &self.destinations {
            if let Some(state) = pool.get(addr) {
                if state.can_connect(&self.circuit_breaker_config) {
                    healthy_dests.push(*addr);
                }
            } else {
                // Not yet initialized, consider healthy
                healthy_dests.push(*addr);
            }
        }

        if healthy_dests.is_empty() {
            return Err(Error::new(ErrorKind::NotConnected, "No healthy destinations available"));
        }

        // Use load balancer to select
        match self.load_balancer.strategy() {
            super::balancer::Strategy::RoundRobin | super::balancer::Strategy::First => {
                // Convert SocketAddr to IpAddr for balancer
                let ips: Vec<_> = healthy_dests.iter().map(|a| a.ip()).collect();
                let selected_ip = self
                    .load_balancer
                    .select(&ips)
                    .ok_or_else(|| Error::new(ErrorKind::NotFound, "Load balancer returned no destination"))?;

                // Find the SocketAddr with matching IP
                healthy_dests
                    .into_iter()
                    .find(|addr| addr.ip() == selected_ip)
                    .ok_or_else(|| Error::new(ErrorKind::NotFound, "Selected IP not found"))
            }
            super::balancer::Strategy::Random => {
                // For random, just use the balancer's logic
                let ips: Vec<_> = healthy_dests.iter().map(|a| a.ip()).collect();
                let selected_ip = self
                    .load_balancer
                    .select(&ips)
                    .ok_or_else(|| Error::new(ErrorKind::NotFound, "Load balancer returned no destination"))?;

                healthy_dests
                    .into_iter()
                    .find(|addr| addr.ip() == selected_ip)
                    .ok_or_else(|| Error::new(ErrorKind::NotFound, "Selected IP not found"))
            }
            super::balancer::Strategy::LeastConnections => {
                // For least connections, use the dedicated method
                drop(pool);
                self.select_least_connections().await
            }
            super::balancer::Strategy::FastestAverage => {
                // For fastest average, use the dedicated method
                drop(pool);
                self.select_fastest_average().await
            }
        }
    }

    /// Select destination using least-connections strategy
    pub async fn select_least_connections(&self) -> Result<SocketAddr> {
        let pool = self.pool.read().await;

        let mut best_addr = None;
        let mut min_load = usize::MAX;

        for addr in &self.destinations {
            if let Some(state) = pool.get(addr) {
                if !state.can_connect(&self.circuit_breaker_config) {
                    continue;
                }
                let load = state.load();
                if load < min_load {
                    min_load = load;
                    best_addr = Some(*addr);
                }
            } else {
                // Not initialized, has 0 load
                return Ok(*addr);
            }
        }

        best_addr.ok_or_else(|| Error::new(ErrorKind::NotConnected, "No healthy destinations available"))
    }

    /// Get or create connection state
    pub async fn get_or_create_state<F, Fut>(
        &self,
        addr: SocketAddr,
        create_fn: F,
    ) -> Result<Arc<RwLock<HashMap<SocketAddr, ConnectionState<T>, RandomState>>>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut pool = self.pool.write().await;

        if !pool.contains_key(&addr) {
            let connection = create_fn().await?;
            let mut state = ConnectionState::new();
            state.connection = Some(connection);
            pool.insert(addr, state);
        }

        drop(pool);
        Ok(self.pool.clone())
    }

    /// Record success for a destination
    pub async fn record_success(&self, addr: SocketAddr) {
        let mut pool = self.pool.write().await;
        if let Some(state) = pool.get_mut(&addr) {
            state.record_success();
        }
    }

    /// Record failure for a destination
    pub async fn record_failure(&self, addr: SocketAddr) {
        let mut pool = self.pool.write().await;
        if let Some(state) = pool.get_mut(&addr) {
            state.record_failure(&self.circuit_breaker_config);
        }
    }

    /// Get pool reference
    pub fn pool(&self) -> Arc<RwLock<HashMap<SocketAddr, ConnectionState<T>, RandomState>>> {
        self.pool.clone()
    }

    /// Select destination using fastest average strategy
    pub async fn select_fastest_average(&self) -> Result<SocketAddr> {
        let pool = self.pool.read().await;

        let mut best_addr = None;
        let mut min_latency = u64::MAX;

        for addr in &self.destinations {
            if let Some(state) = pool.get(addr) {
                // Skip draining or unhealthy
                if state.conn_status != ConnectionStatus::Active {
                    continue;
                }
                if !state.can_connect(&self.circuit_breaker_config) {
                    continue;
                }

                let latency = state.get_avg_latency_ns();

                // Uninitialized connections (latency == 0) are prioritized
                if latency == 0 {
                    return Ok(*addr);
                }

                if latency < min_latency {
                    min_latency = latency;
                    best_addr = Some(*addr);
                }
            } else {
                // Not yet initialized, try it first
                return Ok(*addr);
            }
        }

        best_addr.ok_or_else(|| Error::new(ErrorKind::NotConnected, "No healthy destinations available"))
    }

    /// Record latency for a destination
    pub async fn record_latency(&self, addr: SocketAddr, latency_ns: u64) {
        let pool = self.pool.read().await;
        if let Some(state) = pool.get(&addr) {
            state.record_latency(latency_ns);
            trace!(
                "Recorded latency for {}: {}ms (avg: {}ms)",
                addr,
                latency_ns / 1_000_000,
                state.get_avg_latency_ns() / 1_000_000
            );
        }
    }

    /// Update addresses with graceful draining strategy
    pub async fn update_addresses(&mut self, new_addrs: Vec<SocketAddr>) {
        let mut pool = self.pool.write().await;
        let old_addrs = &self.destinations;

        // 1. Mark addresses not in new list as Draining
        for addr in old_addrs {
            if !new_addrs.contains(addr) {
                if let Some(state) = pool.get_mut(addr) {
                    state.conn_status = ConnectionStatus::Draining;
                    info!("Marking {} as draining", addr);
                }
            }
        }

        // 2. Mark addresses in new list as Active (reactivate if was draining)
        for addr in &new_addrs {
            if let Some(state) = pool.get_mut(addr) {
                if state.conn_status == ConnectionStatus::Draining {
                    state.conn_status = ConnectionStatus::Active;
                    info!("Reactivating {}", addr);
                }
            }
        }

        // 3. Update destination list
        drop(pool);
        self.destinations = new_addrs;

        info!("Address update complete: {} destinations", self.destinations.len());
    }

    /// Update addresses only if changed
    pub async fn update_if_changed(&mut self, new_addrs: Vec<SocketAddr>) {
        if self.destinations != new_addrs {
            info!("Addresses changed, updating pool");
            self.update_addresses(new_addrs).await;
        }
    }

    /// Clean up draining connections with no active requests
    pub async fn cleanup_draining(&self) {
        let mut pool = self.pool.write().await;
        let before = pool.len();

        pool.retain(|addr, state| {
            let should_keep = !(state.conn_status == ConnectionStatus::Draining
                && state.active_requests.load(Ordering::Relaxed) == 0);

            if !should_keep {
                info!("Cleaning up draining connection: {}", addr);
            }

            should_keep
        });

        let after = pool.len();
        if before != after {
            info!("Cleaned up {} draining connections", before - after);
        }
    }
}
