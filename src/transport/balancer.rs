// src/transport/balancer.rs
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// 负载均衡策略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// 使用第一个 IP（默认）
    First,
    /// 轮询所有 IP
    RoundRobin,
    /// 随机选择
    Random,
    /// 最少连接数
    LeastConnections,
    /// 最快平均延迟（基于 EWMA）
    FastestAverage,
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy::RoundRobin
    }
}

impl Strategy {
    pub fn from_str(s: &str) -> Self {
        match s {
            "round_robin" => Strategy::RoundRobin,
            "random" => Strategy::Random,
            "least_connections" => Strategy::LeastConnections,
            "fastest_average" => Strategy::FastestAverage,
            _ => Strategy::First,
        }
    }
}

/// 通用负载均衡器
pub struct LoadBalancer {
    strategy: Strategy,
    counter: AtomicUsize,
}

impl LoadBalancer {
    pub fn new(strategy: Strategy) -> Self {
        Self {
            strategy,
            counter: AtomicUsize::new(0),
        }
    }

    /// 从 IP 列表中选择一个
    pub fn select(&self, ips: &[IpAddr]) -> Option<IpAddr> {
        if ips.is_empty() {
            return None;
        }

        match self.strategy {
            Strategy::First => Some(ips[0]),
            Strategy::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % ips.len();
                Some(ips[idx])
            }
            Strategy::Random => {
                // 简单实现：使用 counter 作为伪随机
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % ips.len();
                Some(ips[idx])
            }
            Strategy::LeastConnections | Strategy::FastestAverage => {
                // LeastConnections 和 FastestAverage 需要连接池状态
                // 实际逻辑在 ConnectionPool 中实现，这里退化为 First
                Some(ips[0])
            }
        }
    }

    /// 获取当前策略
    pub fn strategy(&self) -> Strategy {
        self.strategy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_first_strategy() {
        let lb = LoadBalancer::new(Strategy::First);
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        ];

        assert_eq!(lb.select(&ips), Some(ips[0]));
        assert_eq!(lb.select(&ips), Some(ips[0]));
    }

    #[test]
    fn test_round_robin_strategy() {
        let lb = LoadBalancer::new(Strategy::RoundRobin);
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
        ];

        assert_eq!(lb.select(&ips), Some(ips[0]));
        assert_eq!(lb.select(&ips), Some(ips[1]));
        assert_eq!(lb.select(&ips), Some(ips[2]));
        assert_eq!(lb.select(&ips), Some(ips[0]));
    }

    #[test]
    fn test_empty_ips() {
        let lb = LoadBalancer::new(Strategy::RoundRobin);
        assert_eq!(lb.select(&[]), None);
    }
}
