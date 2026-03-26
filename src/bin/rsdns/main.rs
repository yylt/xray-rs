// bin/rsdns/main.rs
mod server;
mod upstream;

use ahash::RandomState;
use clap::Parser;
use log::{error, info};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use xray_rs::route::cache::{CacheConfig, DnsCache};
use xray_rs::route::dns::{Action, DnsRule, HostsTable, RuleEngine};
use xray_rs::route::matcher::{DomainMatcher, DomainSet, Matcher};

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

/// 配置文件结构
#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default)]
    listen: Vec<ListenConfig>,
    #[serde(default)]
    groups: HashMap<String, GroupConfig>,
    #[serde(default)]
    upstreams: HashMap<String, UpstreamConfig>,
    cache: Option<CacheConfigYaml>,
    hosts: Option<HostsConfigYaml>,
    #[serde(default)]
    rules: Vec<RuleConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ListenConfig {
    Simple(String),
    Full { addr: String },
}

#[derive(Debug, Deserialize)]
struct GroupConfig {
    file: Option<PathBuf>,
    inline: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UpstreamConfig {
    addr: Option<String>,
    addrs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CacheConfigYaml {
    size: Option<usize>,
    min_ttl: Option<u32>,
    max_ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct HostsConfigYaml {
    files: Option<Vec<PathBuf>>,
    inline: Option<Vec<InlineHost>>,
}

#[derive(Debug, Deserialize)]
struct InlineHost {
    domain: String,
    ip: String,
}

#[derive(Debug, Deserialize)]
struct RuleConfig {
    #[serde(rename = "match")]
    match_: Option<MatchConfig>,
    action: ActionConfig,
}

#[derive(Debug, Deserialize)]
struct MatchConfig {
    domain: Option<Vec<DomainMatchConfig>>,
    group: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DomainMatchConfig {
    Suffix { suffix: String },
    Exact { exact: String },
}

#[derive(Debug, Deserialize)]
struct ActionConfig {
    #[serde(rename = "type")]
    type_: String,
    upstream: Option<String>,
    outbound_tag: Option<String>,
    ip: Option<String>,
}

fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = serde_yaml::from_str(&content)?;
    Ok(config)
}

fn build_groups(config: &HashMap<String, GroupConfig>) -> HashMap<String, DomainSet, RandomState> {
    let mut groups = HashMap::with_hasher(RandomState::new());
    for (name, gc) in config {
        let mut set = DomainSet::new();
        if let Some(path) = &gc.file {
            match DomainSet::load_file(path) {
                Ok(loaded) => set = loaded,
                Err(e) => error!("Failed to load group file {:?}: {}", path, e),
            }
        }
        if let Some(inline) = &gc.inline {
            for domain in inline {
                set.add_exact(domain.clone());
            }
        }
        groups.insert(name.clone(), set);
    }
    groups
}

fn build_hosts(config: &Option<HostsConfigYaml>) -> HostsTable {
    let mut hosts = HostsTable::new();
    if let Some(hc) = config {
        if let Some(files) = &hc.files {
            for path in files {
                match HostsTable::load_file(path) {
                    Ok(loaded) => {
                        info!("Loaded hosts from {:?}", path);
                        // Merge hosts
                        hosts = loaded;
                    }
                    Err(e) => error!("Failed to load hosts {:?}: {}", path, e),
                }
            }
        }
        if let Some(inline) = &hc.inline {
            for h in inline {
                if let Ok(ip) = h.ip.parse() {
                    hosts.add(&h.domain, ip);
                }
            }
        }
    }
    hosts
}

fn build_rules(config: &[RuleConfig]) -> Vec<DnsRule> {
    config
        .iter()
        .map(|rc| {
            let matchers = if let Some(m) = &rc.match_ {
                let mut ms = vec![];
                if let Some(domains) = &m.domain {
                    let dm: Vec<DomainMatcher> = domains
                        .iter()
                        .map(|d| match d {
                            DomainMatchConfig::Suffix { suffix } => DomainMatcher::Suffix(suffix.clone()),
                            DomainMatchConfig::Exact { exact } => DomainMatcher::Exact(exact.clone()),
                        })
                        .collect();
                    ms.push(Matcher::Domain(dm));
                }
                if let Some(groups) = &m.group {
                    ms.push(Matcher::Group(groups.clone()));
                }
                ms
            } else {
                vec![]
            };

            let action = match rc.action.type_.as_str() {
                "block" => Action::Block,
                "rewrite" => Action::Rewrite {
                    ip: rc
                        .action
                        .ip
                        .as_ref()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or("0.0.0.0".parse().unwrap()),
                },
                _ => Action::Forward {
                    upstream: rc.action.upstream.clone().unwrap_or_default(),
                    outbound_tag: rc.action.outbound_tag.clone(),
                },
            };

            DnsRule { matchers, action }
        })
        .collect()
}

fn build_upstreams(config: &HashMap<String, UpstreamConfig>) -> HashMap<String, UpstreamClient> {
    let mut upstreams = HashMap::new();
    for (name, uc) in config {
        let addr_str = uc.addr.as_ref().or_else(|| uc.addrs.as_ref().and_then(|a| a.first()));
        if let Some(addr) = addr_str {
            if let Some(client) = parse_upstream(addr) {
                upstreams.insert(name.clone(), client);
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
    }
    // Default to UDP if no scheme
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
    let groups = build_groups(&config.groups);
    let hosts = build_hosts(&config.hosts);
    let rules = build_rules(&config.rules);
    let upstreams = build_upstreams(&config.upstreams);

    let cache_config = config
        .cache
        .map(|c| CacheConfig {
            size: c.size.unwrap_or(4096),
            min_ttl: c.min_ttl.unwrap_or(60),
            max_ttl: c.max_ttl.unwrap_or(3600),
        })
        .unwrap_or_default();
    let cache = DnsCache::new(&cache_config);

    let rule_engine = Arc::new(RuleEngine::new(rules, groups, hosts));

    // 找默认 upstream
    let default_upstream = config.upstreams.keys().next().cloned().unwrap_or_default();

    let server = DnsServer::new(rule_engine, Arc::new(cache), upstreams, default_upstream);

    // 启动监听
    for listen in &config.listen {
        let addr_str = match listen {
            ListenConfig::Simple(s) => s.clone(),
            ListenConfig::Full { addr, .. } => addr.clone(),
        };

        if addr_str.starts_with("udp://") {
            let addr: SocketAddr = addr_str.trim_start_matches("udp://").parse()?;
            let server = server.clone_for_spawn();
            tokio::spawn(async move {
                if let Err(e) = server.serve_udp(addr).await {
                    error!("UDP server error: {}", e);
                }
            });
        }
        // TODO: tcp://, tls://, https://
    }

    // 保持运行
    info!("rsdns started, press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down");
    Ok(())
}
