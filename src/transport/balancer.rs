use ahash::RandomState;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// gRPC 负载均衡策略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// round-robin
    RoundRobin,
    /// Power-of-two choices with least-loaded score
    LeastLoadedP2c,
    /// Least Connections
    LeastConnections,
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy::LeastLoadedP2c
    }
}

impl Strategy {
    pub fn from_str(s: &str) -> Self {
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
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    pub fn record_open_success(&self) {
        let _ = self
            .failure_penalty
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
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

struct BalancerEntry {
    state: Arc<TargetState>,
    channel: Option<tonic::transport::Channel>,
}

impl BalancerEntry {
    fn new() -> Self {
        Self {
            state: Arc::new(TargetState::new()),
            channel: None,
        }
    }
}

struct BalancerPool {
    targets: HashMap<GrpcTargetKey, BalancerEntry, RandomState>,
    order: Vec<GrpcTargetKey>,
}

impl BalancerPool {
    fn new() -> Self {
        Self {
            targets: HashMap::with_hasher(RandomState::new()),
            order: Vec::new(),
        }
    }
}

pub struct GrpcBalancer {
    strategy: Strategy,
    counter: AtomicUsize,
    pool: Arc<RwLock<BalancerPool>>,
}

impl GrpcBalancer {
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

    pub async fn cached_channel(&self, key: &GrpcTargetKey) -> Option<tonic::transport::Channel> {
        self.pool
            .read()
            .await
            .targets
            .get(key)
            .and_then(|entry| entry.channel.clone())
    }

    pub async fn cache_channel(
        &self,
        key: &GrpcTargetKey,
        channel: tonic::transport::Channel,
    ) -> Option<tonic::transport::Channel> {
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

        match self.strategy {
            Strategy::RoundRobin => self.select_round_robin(&pool, &excluded),
            Strategy::LeastLoadedP2c => self.select_least_loaded_p2c(&pool, &excluded),
            Strategy::LeastConnections => self.select_least_connections(&pool, &excluded),
        }
    }

    fn select_round_robin(&self, pool: &BalancerPool, excluded: &HashSet<GrpcTargetKey>) -> Option<SelectedTarget> {
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
        pool: &BalancerPool,
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
        pool: &BalancerPool,
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

    pub async fn open_with_retry<T, F, Fut>(&self, mut open: F) -> Result<(SelectedTarget, T)>
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
            let selected = match self.select_target(&excluded).await {
                Some(selected) => selected,
                None => break,
            };

            match open(selected.key.clone()).await {
                Ok(value) => {
                    selected.state.record_open_success();
                    selected.state.record_stream_opened();
                    return Ok((selected, value));
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
