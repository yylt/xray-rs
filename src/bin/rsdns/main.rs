// bin/rsdns/main.rs
mod config;
mod server;
mod upstream;

use config::{Config, DomainMatch};

use ahash::AHashMap;
use clap::Parser;
use log::{error, info};
use lru::LruCache;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use xray_rs::common::domain_trie::{DomainSuffixTrie, DomainSuffixTrieBuilder};
use xray_rs::route::dns::{Action, DnsRule};
use xray_rs::route::matcher::RecordType;

use server::DnsServer;
use upstream::UpstreamClient;

/// rsdns - DNS server with rule-based routing
#[derive(Parser, Debug)]
#[command(name = "rsdns")]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "rsdns.yaml")]
    config: PathBuf,
}

/// 缓存键
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: String,
    qtype: u16,
}

/// 缓存记录
#[derive(Debug, Clone)]
enum CacheRecord {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    Other(Vec<u8>),
}

/// 缓存条目
#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<CacheRecord>,
    expires_at: Instant,
}

/// 使用 LRU 的 DNS 缓存
#[derive(Clone)]
struct DnsCache {
    inner: Arc<Mutex<LruCache<CacheKey, CacheEntry>>>,
    min_ttl: Duration,
    max_ttl: Duration,
}

impl DnsCache {
    fn new(size: usize, min_ttl: u32, max_ttl: u32) -> Self {
        let cap = NonZeroUsize::new(size).unwrap_or(NonZeroUsize::new(1024).unwrap());
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(cap))),
            min_ttl: Duration::from_secs(min_ttl as u64),
            max_ttl: Duration::from_secs(max_ttl as u64),
        }
    }

    async fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        let mut cache = self.inner.lock().await;
        if let Some(entry) = cache.get(key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.clone());
            }
            cache.pop(key);
        }
        None
    }

    fn clamp_ttl(&self, ttl: u32) -> Duration {
        let secs = ttl.clamp(self.min_ttl.as_secs() as u32, self.max_ttl.as_secs() as u32);
        Duration::from_secs(secs as u64)
    }
}

/// 从 YAML 文件加载配置
fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    Config::from_file(path)
}

/// 构建域名后缀 trie
fn build_groups_trie(config: &[std::collections::HashMap<String, Vec<String>>]) -> DomainSuffixTrie {
    let mut builder = DomainSuffixTrieBuilder::new();

    for group_map in config {
        for (tag, items) in group_map {
            for item in items {
                if item.starts_with("file:") {
                    let path = PathBuf::from(&item[5..]);
                    match std::fs::read_to_string(&path) {
                        Ok(content) => {
                            for line in content.lines() {
                                let line = line.trim();
                                if !line.is_empty() && !line.starts_with('#') {
                                    // 支持通配符格式: *.example.com 或 example.com
                                    let domain = line.trim_start_matches("*.");
                                    builder.insert(domain, tag);
                                }
                            }
                            info!("Loaded group file {:?} for tag '{}'", path, tag);
                        }
                        Err(e) => error!("Failed to load group file {:?}: {}", path, e),
                    }
                } else {
                    // 直接插入域名
                    builder.insert(item, tag);
                }
            }
        }
    }

    builder.build().expect("fst build failed")
}

/// 构建 hosts 表 (domain -> IpAddr)
fn build_hosts(config: &[String]) -> AHashMap<String, Vec<IpAddr>> {
    let mut hosts: AHashMap<String, Vec<IpAddr>> = AHashMap::default();

    for item in config {
        if item.starts_with("file:") {
            let path = PathBuf::from(&item[5..]);
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    for line in content.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                                for domain in &parts[1..] {
                                    hosts.entry(domain.to_string()).or_default().push(ip);
                                }
                            }
                        }
                    }
                    info!("Loaded hosts from {:?}", path);
                }
                Err(e) => error!("Failed to load hosts {:?}: {}", path, e),
            }
        } else {
            // 解析 inline host: "1.1.1.1 xx.yy"
            let parts: Vec<&str> = item.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(ip) = parts[0].parse::<IpAddr>() {
                    hosts.entry(parts[1].to_string()).or_default().push(ip);
                }
            }
        }
    }
    hosts
}

/// 构建规则列表
fn build_rules(config: &[config::RuleConfig], _trie: &DomainSuffixTrie) -> Vec<DnsRule> {
    config
        .iter()
        .map(|rc| {
            let matchers = vec![];

            // 客户端 IP 匹配
            if let Some(ref client_ip) = rc.r#match.client_ip {
                info!("Client IP match {} not fully implemented", client_ip);
            }

            // 确定动作类型
            let action = if let Some(ref upstream) = rc.upstream {
                Action::Forward {
                    upstream: upstream.clone(),
                    outbound_tag: None,
                }
            } else if let Some(ref cname) = rc.cname {
                Action::Rewrite {
                    ip: cname.parse().unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                }
            } else if let Some(ref ip) = rc.ip {
                Action::Rewrite {
                    ip: ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                }
            } else {
                Action::Block
            };

            DnsRule { matchers, action }
        })
        .collect()
}

/// 构建上游客户端
fn build_upstreams(
    config: &[std::collections::HashMap<String, config::UpstreamDetail>],
) -> AHashMap<String, UpstreamClient> {
    let mut upstreams = AHashMap::default();
    for upstream_map in config {
        for (name, detail) in upstream_map {
            if let Some(first_server) = detail.server.first() {
                if let Some(client) = parse_upstream(first_server) {
                    upstreams.insert(name.clone(), client);
                }
            }
        }
    }
    upstreams
}

fn parse_upstream(addr: &str) -> Option<UpstreamClient> {
    if addr.starts_with("udp://") {
        let addr = addr.trim_start_matches("udp://");
        if let Ok(sock_addr) = addr.parse::<SocketAddr>() {
            return Some(UpstreamClient::new_udp(vec![sock_addr]));
        }
    } else if addr.starts_with("tcp://") {
        let addr = addr.trim_start_matches("tcp://");
        if let Ok(sock_addr) = addr.parse::<SocketAddr>() {
            return Some(UpstreamClient::new_tcp(vec![sock_addr]));
        }
    } else if addr.starts_with("tls://") {
        let addr = addr.trim_start_matches("tls://");
        // TODO: 实现 TLS upstream
        if let Ok(sock_addr) = addr.parse::<SocketAddr>() {
            return Some(UpstreamClient::new_tcp(vec![sock_addr]));
        }
    } else if addr.starts_with("https://") {
        // TODO: 实现 DoH upstream
        return None;
    }
    // 默认使用 UDP
    if let Ok(sock_addr) = addr.parse::<SocketAddr>() {
        return Some(UpstreamClient::new_udp(vec![sock_addr]));
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();
    let config_path = args.config.to_string_lossy();
    info!("Loading config from {}", config_path);

    let config = load_config(&config_path)?;

    // 构建组件
    let groups_trie = build_groups_trie(&config.groups);
    let hosts = build_hosts(&config.hosts);
    let rules = build_rules(&config.rules, &groups_trie);
    let upstreams = build_upstreams(&config.upstreams);

    // 创建 LRU 缓存
    let cache_config = config.cache.unwrap_or_default();
    let cache = DnsCache::new(
        cache_config.size.unwrap_or(4096),
        cache_config.min_ttl.unwrap_or(60),
        cache_config.max_ttl.unwrap_or(3600),
    );

    info!("Built {} groups in trie", config.groups.len());
    info!("Built {} hosts entries", hosts.len());
    info!("Built {} rules", rules.len());
    info!("Built {} upstreams", upstreams.len());

    // 找默认 upstream
    let default_upstream = config
        .upstreams
        .first()
        .and_then(|m| m.keys().next().cloned())
        .unwrap_or_else(|| "default".to_string());

    // 启动监听
    for bind in &config.bind {
        let addr_str = bind.address.clone();

        if addr_str.starts_with("udp://") {
            let addr: SocketAddr = addr_str.trim_start_matches("udp://").parse()?;
            info!("Starting UDP server on {}", addr);
            // 暂用占位，实际需要重构 server.rs 来使用新的 cache/trie
            tokio::spawn(async move {
                info!("Server would run on {}", addr);
            });
        } else {
            // 尝试直接解析为 SocketAddr
            if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                info!("Starting UDP server on {}", addr);
                tokio::spawn(async move {
                    info!("Server would run on {}", addr);
                });
            }
        }
        // TODO: tcp://, tls://, https://
    }

    // 保持运行
    info!("rsdns started, press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_example_config() {
        let config = Config::from_file("example/example-rsdns.yaml").expect("load failed");
        assert_eq!(config.bind.len(), 2);
        assert_eq!(config.groups.len(), 1);
        assert_eq!(config.upstreams.len(), 2);
        assert!(config.cache.is_some());
        assert_eq!(config.hosts.len(), 2);
        assert_eq!(config.rules.len(), 4);
    }
}
