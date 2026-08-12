//! Connection pool with adaptive address selection.
//!
//! The pool manages a fixed-capacity set of long-lived DNS connections
//! (one per resolved upstream address × pool `max_size`).  Connections are
//! **shared**: `checkout()` returns a `CloneableSender` that can be used
//! concurrently by multiple callers.  All callers multiplex queries over
//! the same underlying TCP/TLS/QUIC stream.
//!
//! ## Address selection
//!
//! When a new connection needs to be created, `pick_addr()` selects an
//! address from the pool's address list using weighted random selection:
//!
//! - Addresses currently in a **cool-down** period are excluded.
//! - `PreferFamily` filters out non-preferred address families.
//! - Remaining addresses are weighted by `1 / (1 + consecutive_failures)`.
//! - If no candidate passes the filters, a fallback path relaxes the
//!   cool-down filter (but still respects `PreferFamily`).
//!
//! ## Failure feedback & cool-down
//!
//! Each time a connection to an address fails to be created (connect
//! error), the address's `consecutive_failures` counter is incremented.
//! When it reaches `max_consecutive_fail`, the address enters cool-down
//! for `cool_down` seconds.  All idle connections to that address are
//! evicted.  Successful health checks reset the failure counter.
//!
//! ## Health checking (non-UDP only)
//!
//! The reaper runs every 10 s.  For non-UDP pools, it periodically sends
//! a `SOA .` query through idle connections.  If the query fails, the
//! address is penalized and dead connections are removed.  Successful
//! probes clear the address failure counter (early cool-down exit).
//!
//! ## Connection lifecycle
//!
//! - Connections are **never** returned to an idle pool.  Once created,
//!   they live in `self.connections` and are available to all checkouts
//!   via round-robin cursor selection.
//! - Dead connections (`is_shutdown()`) and connections exceeding
//!   `max_lifetime` are removed by the reaper.
//! - `refill_idle()` ensures the number of active connections never drops
//!   below `min_idle`.
//!
//! ## Locking strategy
//!
//! All locks use `parking_lot` primitives (not `std::sync`) for lower
//! contention and no poisoning.  Lock scopes are intentionally tight:
//!
//! | Field           | Lock              | Rationale |
//! |-----------------|-------------------|-----------|
//! | `connections`   | `parking_lot::Mutex` | `VecDeque` is not `Send+Sync`; lock held only for push/pop/retain |
//! | `addresses`     | **no lock**       | `Vec` is immutable after construction; per-entry state uses `AtomicU32` + `parking_lot::Mutex<Option<Instant>>` |
//! | `reaper_handle` | `parking_lot::Mutex` | written once at startup, read never |
//!
//! No `RwLock` is used because `addresses` is never mutated after
//! construction — only its elements' interior fields change.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

use super::conn::{ping_soa, CloneableSender, ConnFactory};

/// Address family preference for new connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferFamily {
    Any,
    Ipv4,
    Ipv6,
}

/// Tunable parameters for the connection pool.
///
/// All fields have sensible defaults (see [`Default`] impl).  Users
/// override them in rsdns.yaml via `pool:` blocks.
pub struct PoolConfig {
    /// Maximum number of concurrent connections in this pool.
    pub max_size: usize,
    /// Floor for connection count — the reaper refills to this level.
    pub min_idle: usize,
    /// Connections unused longer than this are eligible for reaping.
    pub idle_timeout: Duration,
    /// Absolute upper bound on a connection's lifetime.  Connections
    /// surviving this long are evicted regardless of health.
    pub max_lifetime: Duration,
    /// How often (per connection) a health check SOA probe is sent.
    pub health_interval: Duration,
    /// Timeout for transport-level connection establishment.
    pub connect_timeout: Duration,
    /// Per-request DNS timeout inside `CloneableSender`'s background task.
    pub dns_timeout: Duration,
    /// Address family filter (Any / Ipv4 / Ipv6).
    pub prefer_family: PreferFamily,
    /// Timeout for a single health-check SOA query.
    pub health_check_timeout: Duration,
    /// After this many consecutive failures, an address enters cool-down.
    pub max_consecutive_fail: u32,
    /// Duration for which a penalised address is excluded from selection.
    pub cool_down: Duration,
    /// If true, health checks are skipped (UDP has no persistent connections).
    pub is_udp: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: 3,
            min_idle: 1,
            idle_timeout: Duration::from_secs(10),
            max_lifetime: Duration::from_secs(300),
            health_interval: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(3),
            dns_timeout: Duration::from_secs(3),
            prefer_family: PreferFamily::Any,
            health_check_timeout: Duration::from_secs(3),
            max_consecutive_fail: 2,
            cool_down: Duration::from_secs(30),
            is_udp: false,
        }
    }
}

/// Per-address health tracking.
///
/// `consecutive_failures` uses an `AtomicU32` for lock-free increments.
/// `cooldown_until` uses `parking_lot::Mutex` — it is only contended
/// between concurrent `record_failure`/`record_success` calls, which are
/// rare (one per connection error or successful health probe).
struct AddrState {
    /// The resolved IP:port.
    addr: SocketAddr,
    /// Monotonic failure counter; incremented on connect errors and failed
    /// health probes.  Atomically reset to 0 on success.
    consecutive_failures: AtomicU32,
    /// `Some(t)` ⇒ address is excluded from selection until `t`.
    /// Protected by a thin `parking_lot::Mutex` since it is accessed only
    /// in `record_failure` / `record_success` / `in_cooldown`.
    cooldown_until: Mutex<Option<Instant>>,
}

impl AddrState {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            consecutive_failures: AtomicU32::new(0),
            cooldown_until: Mutex::new(None),
        }
    }

    fn in_cooldown(&self) -> bool {
        self.cooldown_until.lock().is_some_and(|until| until > Instant::now())
    }

    /// Increments the failure counter.  If the threshold is reached,
    /// puts this address into cool-down for `cool_down` duration.
    fn record_failure(&self, max_consecutive_fail: u32, cool_down: Duration) {
        let cnt = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if cnt >= max_consecutive_fail {
            *self.cooldown_until.lock() = Some(Instant::now() + cool_down);
        }
    }

    /// Resets failures and clears cool-down (e.g. after a successful health
    /// check).
    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.cooldown_until.lock() = None;
    }
}

/// A single connection held by the pool.
///
/// `sender` is a shared `CloneableSender` — multiple concurrent
/// `UpstreamGroup::query()` calls share the same underlying transport.
/// Metadata fields drive the reaper's eviction decisions.
struct PooledConn {
    id: usize,
    sender: CloneableSender,
    created_at: Instant,
    /// Updated on every `checkout()` that returns this connection.
    last_used: Instant,
    /// The IP:port this connection was established to.
    addr: SocketAddr,
    in_flight: usize,
    error_count: u32,
}

impl PooledConn {
    fn is_shutdown(&self) -> bool {
        self.sender.is_shutdown()
    }

    fn is_expired(&self, max_lifetime: Duration, idle_timeout: Duration) -> bool {
        self.created_at.elapsed() > max_lifetime || self.last_used.elapsed() > idle_timeout
    }

    fn take_error_count(&mut self) -> u32 {
        std::mem::take(&mut self.error_count)
    }
}

pub struct CheckoutGuard {
    sender: CloneableSender,
    pool: Weak<ConnectionPool>,
    conn_id: usize,
    reported: bool,
}

impl CheckoutGuard {
    pub fn sender(&self) -> &CloneableSender {
        &self.sender
    }

    pub fn record_success(mut self) {
        self.report(true);
    }

    pub fn record_failure(mut self) {
        self.report(false);
    }

    fn report(&mut self, success: bool) {
        if self.reported {
            return;
        }
        if let Some(pool) = self.pool.upgrade() {
            pool.release(self.conn_id, success);
        }
        self.reported = true;
    }
}

impl Drop for CheckoutGuard {
    fn drop(&mut self) {
        self.report(true);
    }
}

/// Manages a fixed-capacity set of long-lived DNS connections.
///
/// All state is behind `Arc` so the pool can be cheaply cloned and passed
/// into multiple `UpstreamClient` instances.
pub struct ConnectionPool {
    /// All connections, active and idle.  Protected by `parking_lot::Mutex`
    /// — lock is held only for push/pop/retain, never across `.await`.
    connections: Arc<Mutex<VecDeque<PooledConn>>>,
    /// Current total connections (checked-out + idle).  Atomic to avoid
    /// locking for reads in capacity checks.
    active_count: Arc<AtomicUsize>,
    /// Hard cap on total connections.
    max_size: usize,
    /// Reaper keeps at least this many connections alive.
    min_idle: usize,
    /// Immutable after construction.  Per-entry state (`consecutive_failures`,
    /// `cooldown_until`) uses internal synchronisation — no external lock
    /// needed.
    addresses: Vec<AddrState>,
    /// Protocol-specific factory closure (from [`super::factory`]).
    factory: ConnFactory,
    /// Copy of the pool configuration (sizing, timeouts, adaptive selection
    /// thresholds).
    config: PoolConfig,
    /// Handle to the reaper task — stored so that it is not detached and
    /// panics are visible in test output.
    reaper_handle: Mutex<Option<JoinHandle<()>>>,
    /// Monotonic round-robin cursor for connection selection.
    cursor: AtomicUsize,
    conn_id_gen: AtomicUsize,
}

impl ConnectionPool {
    /// Creates a new pool and spawns its background reaper.
    ///
    /// `addresses` is the initial set of resolved upstream addresses.
    /// `factory` is the protocol-specific connection factory (from
    /// [`super::factory`]).  `config` controls sizing, timeouts, and
    /// adaptive selection parameters.
    ///
    /// The pool starts empty — connections are created lazily on the first
    /// `checkout()`, then replenished by the reaper.
    pub fn new(mut addresses: Vec<SocketAddr>, factory: ConnFactory, config: PoolConfig) -> Arc<Self> {
        addresses.sort_unstable();
        addresses.dedup();
        let addrs: Vec<AddrState> = addresses.into_iter().map(AddrState::new).collect();
        let pool = Arc::new(Self {
            connections: Arc::new(Mutex::new(VecDeque::new())),
            active_count: Arc::new(AtomicUsize::new(0)),
            max_size: config.max_size,
            min_idle: config.min_idle,
            addresses: addrs,
            factory,
            config,
            reaper_handle: Mutex::new(None),
            cursor: AtomicUsize::new(0),
            conn_id_gen: AtomicUsize::new(1),
        });

        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move { pool_clone.reaper_loop().await });
        *pool.reaper_handle.lock() = Some(handle);

        pool
    }

    // ── Address selection ─────────────────────────────────────────

    /// Picks the best address for a new connection using weighted random
    /// selection.
    ///
    /// Steps:
    /// 1. Filter out addresses in cool-down and non-preferred families.
    /// 2. Compute per-address weight: `1 / (1 + consecutive_failures)`.
    /// 3. Pick an address with probability proportional to weight.
    /// 4. If no candidates pass the primary filters, fall back to
    ///    `pick_addr_fallback()` (relaxes cool-down, keeps family filter).
    fn pick_addr(&self) -> Option<SocketAddr> {
        let mut candidates: Vec<(SocketAddr, f64)> = Vec::with_capacity(self.addresses.len());
        for state in self.addresses.iter() {
            if state.in_cooldown() {
                continue;
            }

            match self.config.prefer_family {
                PreferFamily::Ipv4 if !state.addr.is_ipv4() => continue,
                PreferFamily::Ipv6 if !state.addr.is_ipv6() => continue,
                _ => {}
            }

            let failures = state.consecutive_failures.load(Ordering::Relaxed);
            let weight = 1.0 / (1.0 + failures as f64);
            candidates.push((state.addr, weight));
        }

        if candidates.is_empty() {
            return self.pick_addr_fallback();
        }

        let total_weight: f64 = candidates.iter().map(|(_, w)| w).sum();
        let pick: f64 = rand::random_range(0.0..total_weight);
        let mut cumulative = 0.0;
        for (addr, weight) in candidates {
            cumulative += weight;
            if pick <= cumulative {
                return Some(addr);
            }
        }

        None
    }

    /// Fallback: relax cool-down filter, still respect `PreferFamily`.
    fn pick_addr_fallback(&self) -> Option<SocketAddr> {
        let mut candidates: Vec<SocketAddr> = Vec::with_capacity(self.addresses.len());
        for state in self.addresses.iter() {
            match self.config.prefer_family {
                PreferFamily::Ipv4 if !state.addr.is_ipv4() => continue,
                PreferFamily::Ipv6 if !state.addr.is_ipv6() => continue,
                _ => {}
            }
            candidates.push(state.addr);
        }
        if candidates.is_empty() {
            return self.addresses.first().map(|s| s.addr);
        }
        let idx = rand::random_range(0..candidates.len());
        Some(candidates[idx])
    }

    // ── Address feedback ──────────────────────────────────────────

    /// Records a connection failure for `addr`.  If the failure threshold
    /// is reached, the address enters cool-down and all its idle
    /// connections are evicted.
    fn on_conn_error(&self, addr: SocketAddr) {
        if let Some(state) = self.addresses.iter().find(|s| s.addr == addr) {
            state.record_failure(self.config.max_consecutive_fail, self.config.cool_down);
            if state.in_cooldown() {
                self.evict_all_for(addr);
            }
        }
    }

    /// Records a successful health check — resets the address failure
    /// counter and clears cool-down.
    fn on_conn_success(&self, addr: SocketAddr) {
        if let Some(state) = self.addresses.iter().find(|s| s.addr == addr) {
            state.record_success();
        }
    }

    /// Evicts all connections to `addr` from the pool.
    fn evict_all_for(&self, addr: SocketAddr) {
        let mut conns = self.connections.lock();
        let before = conns.len();
        conns.retain(|c| c.addr != addr || c.in_flight > 0);
        let removed = before - conns.len();
        if removed > 0 {
            self.active_count.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    fn release(&self, conn_id: usize, success: bool) {
        let mut feedback = None;
        {
            let mut conns = self.connections.lock();
            let Some(conn) = conns.iter_mut().find(|conn| conn.id == conn_id) else {
                return;
            };

            if conn.in_flight > 0 {
                conn.in_flight -= 1;
            }
            conn.last_used = Instant::now();
            if !success {
                conn.error_count = conn.error_count.saturating_add(1);
            }

            if conn.in_flight == 0 {
                feedback = Some((conn.addr, conn.take_error_count()));
            }
        }

        if let Some((addr, errors)) = feedback {
            if errors == 0 {
                self.on_conn_success(addr);
            } else {
                for _ in 0..errors.min(self.config.max_consecutive_fail) {
                    self.on_conn_error(addr);
                }
            }
        }
    }

    fn next_conn_id(&self) -> usize {
        self.conn_id_gen.fetch_add(1, Ordering::Relaxed)
    }

    fn idle_count(&self) -> usize {
        self.connections
            .lock()
            .iter()
            .filter(|conn| conn.in_flight == 0)
            .count()
    }

    fn build_conn(&self, sender: CloneableSender, addr: SocketAddr, in_flight: usize) -> PooledConn {
        PooledConn {
            id: self.next_conn_id(),
            sender,
            created_at: Instant::now(),
            last_used: Instant::now(),
            addr,
            in_flight,
            error_count: 0,
        }
    }

    // ── Public API ────────────────────────────────────────────────

    /// Returns a `CloneableSender` for querying the upstream.
    ///
    /// The sender is selected from existing connections via round-robin;
    /// if none are available and `active_count < max_size`, a new
    /// connection is created.  Returns `None` only when the pool is
    /// saturated and all existing connections are in use.
    ///
    /// This is the primary public entry point for `UpstreamClient::query()`.
    pub async fn checkout(self: &Arc<Self>) -> Option<CheckoutGuard> {
        loop {
            {
                let mut conns = self.connections.lock();
                if !conns.is_empty() {
                    let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % conns.len();
                    if let Some(conn) = conns.get_mut(idx) {
                        if conn.is_shutdown() || conn.is_expired(self.config.max_lifetime, Duration::MAX) {
                            if conn.in_flight == 0 {
                                conns.remove(idx);
                                self.active_count.fetch_sub(1, Ordering::Relaxed);
                            }
                            continue;
                        }
                        conn.in_flight += 1;
                        conn.last_used = Instant::now();
                        return Some(CheckoutGuard {
                            sender: conn.sender.clone(),
                            pool: Arc::downgrade(self),
                            conn_id: conn.id,
                            reported: false,
                        });
                    }
                }
            }

            let current = self.active_count.load(Ordering::Relaxed);
            if current >= self.max_size {
                return None;
            }

            let addr = self.pick_addr()?;

            match super::conn::build_cloneable(
                &self.factory,
                addr,
                self.config.dns_timeout,
                self.config.connect_timeout,
            )
            .await
            {
                Ok(sender) => {
                    let conn = self.build_conn(sender.clone(), addr, 1);
                    let mut conns = self.connections.lock();
                    self.active_count.fetch_add(1, Ordering::Relaxed);
                    conns.push_back(conn);
                    return Some(CheckoutGuard {
                        sender,
                        pool: Arc::downgrade(self),
                        conn_id: conns.back().map(|conn| conn.id).unwrap_or_default(),
                        reported: false,
                    });
                }
                Err(_) => {
                    self.on_conn_error(addr);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            }
        }
    }

    // ── Background maintenance ────────────────────────────────────

    /// Reaper loop: runs every 10 s, never exits.
    async fn reaper_loop(&self) {
        let interval = Duration::from_secs(10);
        loop {
            tokio::time::sleep(interval).await;
            self.reap().await;
        }
    }

    /// Single reaper cycle.
    ///
    /// 1. Removes dead connections (`is_shutdown()`) and connections older
    ///    than `max_lifetime`.
    /// 2. For non-UDP pools, health-checks one stale connection (last used
    ///    `>` `health_interval`).  On success, clears the address failure
    ///    counter.  On failure, penalizes the address and removes dead
    ///    connections on that address.
    /// 3. Calls `refill_idle()` to bring the connection count up to
    ///    `min_idle`.
    async fn reap(&self) {
        // phase 1: evict dead / expired connections
        {
            let mut conns = self.connections.lock();
            let before = conns.len();
            conns.retain(|conn| {
                conn.in_flight > 0
                    || (!conn.is_shutdown() && !conn.is_expired(self.config.max_lifetime, self.config.idle_timeout))
            });
            let removed = before - conns.len();
            if removed > 0 {
                self.active_count.fetch_sub(removed, Ordering::Relaxed);
            }
        }

        // phase 2: health check (non-UDP only, one connection per cycle)
        if !self.config.is_udp {
            let conn_info = {
                let conns = self.connections.lock();
                conns
                    .iter()
                    .find(|c| c.last_used.elapsed() > self.config.health_interval)
                    .map(|c| (c.sender.clone(), c.addr))
            };

            if let Some((sender, addr)) = conn_info {
                let healthy = tokio::time::timeout(self.config.health_check_timeout, ping_soa(&sender))
                    .await
                    .unwrap_or(false);

                if healthy {
                    self.on_conn_success(addr);
                } else {
                    self.on_conn_error(addr);
                    let mut conns = self.connections.lock();
                    let before = conns.len();
                    conns.retain(|c| c.addr != addr || c.in_flight > 0 || !c.is_shutdown());
                    let removed = before - conns.len();
                    if removed > 0 {
                        self.active_count.fetch_sub(removed, Ordering::Relaxed);
                    }
                }
            }
        }

        // phase 3: refill to min_idle
        self.refill_idle().await;
    }

    /// Creates new connections until `active_count >= min_idle` (but never
    /// exceeding `max_size`).
    async fn refill_idle(&self) {
        while self.idle_count() < self.min_idle {
            if self.active_count.load(Ordering::Relaxed) >= self.max_size {
                break;
            }
            let addr = match self.pick_addr() {
                Some(a) => a,
                None => break,
            };

            match super::conn::build_cloneable(
                &self.factory,
                addr,
                self.config.dns_timeout,
                self.config.connect_timeout,
            )
            .await
            {
                Ok(sender) => {
                    let conn = self.build_conn(sender.clone(), addr, 0);
                    let mut conns = self.connections.lock();
                    self.active_count.fetch_add(1, Ordering::Relaxed);
                    conns.push_back(conn);
                }
                Err(_) => {
                    self.on_conn_error(addr);
                    break;
                }
            }
        }
    }
}
