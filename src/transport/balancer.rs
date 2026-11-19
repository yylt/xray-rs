use ahash::RandomState;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// gRPC 负载均衡策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Strategy {
    /// round-robin
    RoundRobin,
    /// Power-of-two choices with least-loaded score
    #[default]
    LeastLoadedP2c,
    /// Least Connections
    LeastConnections,
}

impl Strategy {
    pub fn from_strategy_str(s: &str) -> Self {
        match s {
            "round_robin" => Strategy::RoundRobin,
            "least_loaded" => Strategy::LeastLoadedP2c,
            "least_connection" => Strategy::LeastConnections,
            _ => Strategy::LeastLoadedP2c,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GrpcTargetKey {
    Tcp(std::net::SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

#[derive(Debug)]
pub struct TargetState {
    inflight: AtomicUsize,
    failure_penalty: AtomicUsize,
    draining: AtomicBool,
}

impl TargetState {
    fn new() -> Self {
        Self {
            inflight: AtomicUsize::new(0),
            failure_penalty: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
        }
    }

    pub fn record_stream_opened(&self) {
        self.inflight.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_stream_closed(&self) {
        let _ = self
            .inflight
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    pub fn record_open_success(&self) {
        let _ = self
            .failure_penalty
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    pub fn record_open_failure(&self) {
        self.failure_penalty.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_draining(&self, draining: bool) {
        self.draining.store(draining, Ordering::Relaxed);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }

    pub fn load_score(&self) -> usize {
        self.inflight.load(Ordering::Relaxed) + self.failure_penalty.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct SelectedTarget {
    pub key: GrpcTargetKey,
    pub state: Arc<TargetState>,
}

/// Owns one load reservation from selection through stream destruction.
/// Dropping a cancelled or failed open releases its reservation as well.
pub struct TargetLease {
    state: Arc<TargetState>,
}

impl Drop for TargetLease {
    fn drop(&mut self) {
        self.state.record_stream_closed();
    }
}

struct BalancerEntry<C> {
    state: Arc<TargetState>,
    channel: Option<C>,
    channel_lock: Arc<Mutex<()>>,
}

impl<C> BalancerEntry<C> {
    fn new() -> Self {
        Self {
            state: Arc::new(TargetState::new()),
            channel: None,
            channel_lock: Arc::new(Mutex::new(())),
        }
    }
}

struct BalancerPool<C> {
    targets: HashMap<GrpcTargetKey, BalancerEntry<C>, RandomState>,
    order: Vec<GrpcTargetKey>,
}

impl<C> BalancerPool<C> {
    fn new() -> Self {
        Self {
            targets: HashMap::with_hasher(RandomState::new()),
            order: Vec::new(),
        }
    }
}

pub struct Balancer<C> {
    strategy: Strategy,
    counter: AtomicUsize,
    pool: Arc<RwLock<BalancerPool<C>>>,
}

pub type GrpcBalancer = Balancer<tonic::transport::Channel>;

impl<C> Balancer<C> {
    pub fn new(strategy: Strategy) -> Self {
        Self {
            strategy,
            counter: AtomicUsize::new(0),
            pool: Arc::new(RwLock::new(BalancerPool::new())),
        }
    }

    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    pub async fn sync_targets(&self, new_targets: Vec<GrpcTargetKey>) {
        let mut pool = self.pool.write().await;
        let new_set: HashSet<_> = new_targets.iter().cloned().collect();

        for target in &new_targets {
            let entry = pool.targets.entry(target.clone()).or_insert_with(BalancerEntry::new);
            entry.state.set_draining(false);
        }

        for (target, entry) in pool.targets.iter_mut() {
            if !new_set.contains(target) {
                entry.state.set_draining(true);
            }
        }

        pool.targets
            .retain(|_, entry| !(entry.state.is_draining() && entry.state.inflight() == 0));

        let mut seen = HashSet::new();
        pool.order = new_targets
            .into_iter()
            .filter(|target| seen.insert(target.clone()) && pool.targets.contains_key(target))
            .collect();
    }

    pub async fn channel_lock(&self, key: &GrpcTargetKey) -> Option<Arc<Mutex<()>>> {
        self.pool
            .read()
            .await
            .targets
            .get(key)
            .map(|entry| entry.channel_lock.clone())
    }

    pub async fn cached_channel(&self, key: &GrpcTargetKey) -> Option<C>
    where
        C: Clone,
    {
        self.pool
            .read()
            .await
            .targets
            .get(key)
            .and_then(|entry| entry.channel.clone())
    }

    pub async fn cache_channel(&self, key: &GrpcTargetKey, channel: C) -> Option<C>
    where
        C: Clone,
    {
        let mut pool = self.pool.write().await;
        let entry = pool.targets.get_mut(key)?;
        entry.channel = Some(channel.clone());
        Some(channel)
    }

    pub async fn remove_cached_channel(&self, key: &GrpcTargetKey) {
        if let Some(entry) = self.pool.write().await.targets.get_mut(key) {
            entry.channel = None;
        }
    }

    pub async fn select_target(&self, excluded: &[GrpcTargetKey]) -> Option<SelectedTarget> {
        let excluded: HashSet<_> = excluded.iter().cloned().collect();
        let pool = self.pool.read().await;

        self.select_from_pool(&pool, &excluded)
    }

    fn select_from_pool(&self, pool: &BalancerPool<C>, excluded: &HashSet<GrpcTargetKey>) -> Option<SelectedTarget> {
        match self.strategy {
            Strategy::RoundRobin => self.select_round_robin(pool, excluded),
            Strategy::LeastLoadedP2c => self.select_least_loaded_p2c(pool, excluded),
            Strategy::LeastConnections => self.select_least_connections(pool, excluded),
        }
    }

    async fn reserve_target(&self, excluded: &[GrpcTargetKey]) -> Option<(SelectedTarget, TargetLease)> {
        let excluded = excluded.iter().cloned().collect();
        // Selection and reservation must be atomic relative to other selectors.
        // No network await occurs while holding the pool lock.
        let pool = self.pool.write().await;
        let selected = self.select_from_pool(&pool, &excluded)?;
        selected.state.record_stream_opened();
        let lease = TargetLease {
            state: selected.state.clone(),
        };
        Some((selected, lease))
    }

    fn select_round_robin(&self, pool: &BalancerPool<C>, excluded: &HashSet<GrpcTargetKey>) -> Option<SelectedTarget> {
        let len = pool.order.len();
        if len == 0 {
            return None;
        }

        let start = self.counter.fetch_add(1, Ordering::Relaxed);
        for offset in 0..len {
            let key = &pool.order[(start + offset) % len];
            let entry = pool.targets.get(key)?;
            if excluded.contains(key) || entry.state.is_draining() {
                continue;
            }
            return Some(SelectedTarget {
                key: key.clone(),
                state: entry.state.clone(),
            });
        }

        None
    }

    fn select_least_loaded_p2c(
        &self,
        pool: &BalancerPool<C>,
        excluded: &HashSet<GrpcTargetKey>,
    ) -> Option<SelectedTarget> {
        let candidates: Vec<_> = pool
            .order
            .iter()
            .filter_map(|key| {
                let entry = pool.targets.get(key)?;
                if excluded.contains(key) || entry.state.is_draining() {
                    return None;
                }
                Some(SelectedTarget {
                    key: key.clone(),
                    state: entry.state.clone(),
                })
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        let len = candidates.len();
        let pick = if len == 1 {
            0
        } else {
            let first = self.counter.fetch_add(1, Ordering::Relaxed) % len;
            let second = (first + 1 + self.counter.fetch_add(1, Ordering::Relaxed)) % len;
            let a = &candidates[first];
            let b = &candidates[second];
            if a.state.load_score() <= b.state.load_score() {
                first
            } else {
                second
            }
        };

        Some(candidates[pick].clone())
    }

    fn select_least_connections(
        &self,
        pool: &BalancerPool<C>,
        excluded: &HashSet<GrpcTargetKey>,
    ) -> Option<SelectedTarget> {
        let candidates = pool.order.iter().filter_map(|key| {
            let entry = pool.targets.get(key)?;
            if excluded.contains(key) || entry.state.is_draining() {
                return None;
            }
            Some(SelectedTarget {
                key: key.clone(),
                state: entry.state.clone(),
            })
        });

        candidates.min_by_key(|target| {
            let inflight = target.state.inflight();
            let failure_penalty = target.state.failure_penalty.load(Ordering::Relaxed);

            // 评分策略：基础分为连接数
            // 加上 failure_penalty 倍数的惩罚。这里以 (inflight + 1) * failure_penalty 为惩罚基数
            // 也可以简单的返回 inflight + failure_penalty * 权重
            // 这里我们用一种确保失败越多，排序越靠后的方法：
            // 权重惩罚 = 失败次数 * 10 （每次失败相当于加10个连接的负载）
            inflight + failure_penalty * 10
        })
    }

    pub async fn open_with_retry<T, F, Fut>(&self, mut open: F) -> Result<(TargetLease, T)>
    where
        F: FnMut(GrpcTargetKey) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let total_targets = self.pool.read().await.order.len();
        if total_targets == 0 {
            return Err(Error::new(ErrorKind::NotConnected, "No gRPC targets available"));
        }

        let mut excluded = Vec::new();
        let mut last_error = None;
        let max_attempts = total_targets.min(3);

        for _ in 0..max_attempts {
            let (selected, lease) = match self.reserve_target(&excluded).await {
                Some(reserved) => reserved,
                None => break,
            };

            match open(selected.key.clone()).await {
                Ok(value) => {
                    selected.state.record_open_success();
                    return Ok((lease, value));
                }
                Err(err) => {
                    selected.state.record_open_failure();
                    excluded.push(selected.key.clone());
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::new(ErrorKind::NotConnected, "No selectable gRPC targets")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generic_channel_cache_preserves_retained_targets_and_removes_stale_values() {
        let balancer = Balancer::<String>::new(Strategy::LeastConnections);
        let key = GrpcTargetKey::Tcp("127.0.0.1:443".parse().unwrap());
        assert!(balancer.cache_channel(&key, "missing".into()).await.is_none());
        balancer.sync_targets(vec![key.clone()]).await;
        assert!(balancer.cached_channel(&key).await.is_none());
        assert_eq!(balancer.cache_channel(&key, "cached".into()).await.as_deref(), Some("cached"));
        balancer.sync_targets(vec![key.clone()]).await;
        assert_eq!(balancer.cached_channel(&key).await.as_deref(), Some("cached"));
        balancer.remove_cached_channel(&key).await;
        assert!(balancer.cached_channel(&key).await.is_none());
        balancer.cache_channel(&key, "replaced".into()).await;
        balancer.sync_targets(Vec::new()).await;
        assert!(balancer.cached_channel(&key).await.is_none());
    }

    #[tokio::test]
    async fn channel_locks_are_per_target_and_cancellation_releases_them() {
        use std::future::Future;
        use std::task::Poll;
        let balancer = GrpcBalancer::new(Strategy::LeastConnections);
        let a = GrpcTargetKey::Tcp("127.0.0.1:443".parse().unwrap());
        let b = GrpcTargetKey::Tcp("127.0.0.2:443".parse().unwrap());
        balancer.sync_targets(vec![a.clone(), b.clone()]).await;
        let lock_a = balancer.channel_lock(&a).await.unwrap();
        let lock_b = balancer.channel_lock(&b).await.unwrap();
        assert!(Arc::ptr_eq(&lock_a, &balancer.channel_lock(&a).await.unwrap()));
        let mut blocked_open = Box::pin(async {
            let _guard = lock_a.lock().await;
            std::future::pending::<()>().await;
        });
        assert!(std::future::poll_fn(|cx| Poll::Ready(blocked_open.as_mut().poll(cx).is_pending())).await);
        assert!(lock_a.try_lock().is_err());
        assert!(lock_b.try_lock().is_ok());
        drop(blocked_open);
        assert!(lock_a.try_lock().is_ok());
        balancer.sync_targets(vec![a.clone(), b]).await;
        assert!(Arc::ptr_eq(&lock_a, &balancer.channel_lock(&a).await.unwrap()));
    }

    #[tokio::test]
    async fn failed_opens_release_load_and_success_keeps_one_lease() {
        for strategy in [
            Strategy::RoundRobin,
            Strategy::LeastConnections,
            Strategy::LeastLoadedP2c,
        ] {
            let balancer = GrpcBalancer::new(strategy);
            let targets: Vec<_> = (1..=5)
                .map(|n| GrpcTargetKey::Tcp(std::net::SocketAddr::from(([127, 0, 0, n], 443))))
                .collect();
            balancer.sync_targets(targets).await;
            let mut attempts = Vec::new();
            let result = balancer
                .open_with_retry(|key| {
                    attempts.push(key);
                    std::future::ready(Err::<(), _>(Error::new(ErrorKind::ConnectionRefused, "test")))
                })
                .await;
            assert!(result.is_err());
            assert_eq!(attempts.len(), 3);
            assert_eq!(attempts.iter().collect::<HashSet<_>>().len(), 3);
            assert!(balancer
                .pool
                .read()
                .await
                .targets
                .values()
                .all(|entry| entry.state.inflight() == 0));
            let (lease, ()) = balancer.open_with_retry(|_| std::future::ready(Ok(()))).await.unwrap();
            assert_eq!(lease.state.inflight(), 1);
            // In-progress and established reservations both protect draining entries.
            balancer.sync_targets(Vec::new()).await;
            assert!(lease.state.is_draining());
            assert_eq!(balancer.pool.read().await.targets.len(), 1);
            let state = lease.state.clone();
            drop(lease);
            assert_eq!(state.inflight(), 0);
            balancer.sync_targets(Vec::new()).await;
            assert!(balancer.pool.read().await.targets.is_empty());
        }
    }

    #[tokio::test]
    async fn concurrent_opens_reserve_distinct_targets_and_cancel_cleanly() {
        use std::future::Future;
        use std::task::Poll;
        let balancer = GrpcBalancer::new(Strategy::LeastConnections);
        let targets: Vec<_> = (1..=5)
            .map(|n| GrpcTargetKey::Tcp(std::net::SocketAddr::from(([127, 0, 0, n], 443))))
            .collect();
        balancer.sync_targets(targets.clone()).await;
        let seen = std::sync::Mutex::new(Vec::new());
        let mut opens: Vec<_> = (0..5)
            .map(|_| {
                Box::pin(balancer.open_with_retry(|key| {
                    seen.lock().unwrap().push(key);
                    std::future::pending::<Result<()>>()
                }))
            })
            .collect();
        for open in &mut opens {
            assert!(std::future::poll_fn(|cx| Poll::Ready(open.as_mut().poll(cx).is_pending())).await);
        }
        assert_eq!(seen.lock().unwrap().iter().collect::<HashSet<_>>().len(), 5);
        drop(opens);
        for target in targets {
            let pool = balancer.pool.read().await;
            assert_eq!(pool.targets[&target].state.inflight(), 0);
        }
    }
}
