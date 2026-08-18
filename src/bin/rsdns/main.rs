mod cache;
mod config;
mod conn;
mod factory;
mod hosts;
mod pool;
mod rule;
mod server;
mod upstream;

use ahash::AHashMap;
use clap::Parser;
use log::{error, info, warn};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use xray_rs::build_info;
use xray_rs::common::{
    domain_trie::{DomainSuffixTrie, DomainSuffixTrieBuilder},
    rslog,
    tls::default_tls_client_config,
};

use cache::DnsCache;
use config::{Config, QueryModeConfig};
use hickory_proto::rr::RecordType;
use hosts::HostsTrieBuilder;
use rule::{BlockResponse, Rule, RuleAction};
use server::{DnsServer, QueryLogger};
use upstream::{QueryMode, UpstreamClient, UpstreamGroup};

type TlsConfig = Arc<rustls::ClientConfig>;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[command(name = "rsdns")]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'c', long = "config", default_value = "rsdns.yaml")]
    config: PathBuf,
}

fn build_groups_trie(groups: &std::collections::HashMap<String, Vec<String>>) -> DomainSuffixTrie {
    let mut builder = DomainSuffixTrieBuilder::new();

    for (tag, items) in groups {
        for item in items {
            if let Some(file_path) = item.strip_prefix("file:") {
                match std::fs::read_to_string(file_path) {
                    Ok(content) => {
                        for line in content.lines() {
                            let line = line.trim();
                            if !line.is_empty() && !line.starts_with('#') {
                                let domain = line.trim_start_matches("*.");
                                builder.insert(domain, tag);
                            }
                        }
                        info!("Loaded group file {} for tag '{}'", file_path, tag);
                    }
                    Err(e) => error!("Failed to load group file {}: {}", file_path, e),
                }
            } else {
                let domain = item.trim_start_matches("*.");
                builder.insert(domain, tag);
            }
        }
    }

    builder.build().expect("FST build failed")
}

fn build_hosts_trie(entries: &[String]) -> hosts::HostsTrie {
    let mut builder = HostsTrieBuilder::new();

    for entry in entries {
        if let Some(file_path) = entry.strip_prefix("file:") {
            match std::fs::read_to_string(file_path) {
                Ok(content) => {
                    for line in content.lines() {
                        parse_hosts_line(&mut builder, line);
                    }
                    info!("Loaded hosts from {}", file_path);
                }
                Err(e) => error!("Failed to load hosts {}: {}", file_path, e),
            }
        } else {
            parse_hosts_line(&mut builder, entry);
        }
    }

    builder.build()
}

fn parse_hosts_line(builder: &mut HostsTrieBuilder, line: &str) {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    if let Ok(ip) = parts[0].parse::<IpAddr>() {
        for domain in &parts[1..] {
            builder.insert(domain, ip);
        }
    }
}

fn build_rules(config_rules: &[config::RuleConfig]) -> Vec<Rule> {
    config_rules
        .iter()
        .map(|rc| {
            let group = match &rc.r#match {
                config::MatchTarget::Group(g) => g.clone(),
                config::MatchTarget::Wildcard(w) => w.clone(),
            };
            let qtype = rc.qtype.as_ref().map(|qt| parse_qtype(qt));
            let action = match &rc.action {
                config::RuleActionConfig::Block { response } => RuleAction::Block {
                    response: match response {
                        config::BlockResponse::Nxdomain => BlockResponse::NXDomain,
                        config::BlockResponse::Poison => BlockResponse::Poison,
                    },
                },
                config::RuleActionConfig::Cname {
                    target,
                    ttl,
                    upstream,
                    deny_qtypes,
                } => RuleAction::Cname {
                    target: target.clone(),
                    ttl: ttl.unwrap_or(600),
                    upstream: upstream.clone(),
                    deny_qtypes: deny_qtypes.iter().map(|qt| parse_qtype(qt)).collect(),
                },
                config::RuleActionConfig::Forward {
                    upstream,
                    cache,
                    ttl,
                    deny_qtypes,
                } => RuleAction::Forward {
                    upstream: upstream.clone(),
                    cache: *cache,
                    ttl: *ttl,
                    deny_qtypes: deny_qtypes.iter().map(|qt| parse_qtype(qt)).collect(),
                },
            };
            Rule { group, qtype, action }
        })
        .collect()
}

fn parse_qtype(s: &str) -> hickory_proto::rr::RecordType {
    match s.as_bytes() {
        b"A" | b"a" => RecordType::A,
        b"AAAA" | b"aaaa" => RecordType::AAAA,
        b"ANY" | b"any" => RecordType::ANY,
        b"CNAME" | b"cname" => RecordType::CNAME,
        b"MX" | b"mx" => RecordType::MX,
        b"TXT" | b"txt" => RecordType::TXT,
        b"NS" | b"ns" => RecordType::NS,
        b"SOA" | b"soa" => RecordType::SOA,
        b"PTR" | b"ptr" => RecordType::PTR,
        b"SRV" | b"srv" => RecordType::SRV,
        b"HTTPS" | b"https" => RecordType::HTTPS,
        _ => s
            .parse::<u16>()
            .map(RecordType::from)
            .unwrap_or_else(|_| panic!("invalid query type: {s}")),
    }
}

#[derive(Clone)]
enum UpstreamConfig {
    Pool {
        pool: Arc<pool::ConnectionPool>,
        bootstrap: bool,
    },
    NeedResolve {
        server_name: String,
        port: u16,
        tls_config: TlsConfig,
        raw_pool: Option<config::RawPoolConfig>,
        bootstrap: bool,
        protocol: ResolveProtocol,
    },
    Tcp {
        addr: SocketAddr,
        bootstrap: bool,
        raw_pool: Option<config::RawPoolConfig>,
    },
}

#[derive(Clone)]
enum ResolveProtocol {
    Tls,
    Doh { host: Arc<str>, path: Arc<str> },
    Doh3 { host: Arc<str>, path: Arc<str> },
    Doq { host: Arc<str> },
}

impl UpstreamConfig {
    fn is_bootstrap(&self) -> bool {
        match self {
            Self::Pool { bootstrap, .. } | Self::Tcp { bootstrap, .. } | Self::NeedResolve { bootstrap, .. } => {
                *bootstrap
            }
        }
    }

    fn needs_resolve(&self) -> bool {
        matches!(self, Self::NeedResolve { .. })
    }

    fn from_tls_url(rest: &str, bootstrap: bool, raw_pool: Option<config::RawPoolConfig>) -> Option<Self> {
        let (host, port) = parse_host_port(rest)?;
        let tls_config = default_tls_client_config();
        match host.as_str().parse::<IpAddr>() {
            Ok(ip) => {
                let addr = SocketAddr::new(ip, port);
                let pool_cfg = raw_pool.unwrap_or_default().into_pool_config(false);
                let pool = pool::ConnectionPool::new(vec![addr], factory::tls_factory(host, tls_config), pool_cfg);
                Some(Self::Pool { pool, bootstrap })
            }
            Err(_) => Some(Self::NeedResolve {
                server_name: host,
                port,
                tls_config,
                raw_pool,
                bootstrap,
                protocol: ResolveProtocol::Tls,
            }),
        }
    }

    fn from_http_url(addr: &str, bootstrap: bool, raw_pool: Option<config::RawPoolConfig>) -> Option<Self> {
        let parsed: url::Url = addr.parse().ok()?;
        let host: Arc<str> = parsed.host_str()?.to_string().into();
        let port = parsed.port_or_known_default().unwrap_or(443);
        let path: Arc<str> = match parsed.query() {
            Some(q) => format!("{}?{}", parsed.path(), q),
            None => parsed.path().to_string(),
        }
        .into();

        let tls_config = default_tls_client_config();
        let factory_fn: fn(Arc<str>, Arc<str>, Arc<rustls::ClientConfig>) -> conn::ConnFactory = match parsed.scheme() {
            "https" => factory::doh_factory,
            "h3" => factory::doh3_factory,
            _ => return None,
        };
        let protocol = match parsed.scheme() {
            "https" => ResolveProtocol::Doh {
                host: host.clone(),
                path: path.clone(),
            },
            _ => ResolveProtocol::Doh3 {
                host: host.clone(),
                path: path.clone(),
            },
        };

        let pool_cfg = raw_pool.clone().unwrap_or_default().into_pool_config(false);
        match host.as_ref().parse::<IpAddr>() {
            Ok(ip) => {
                let addr = SocketAddr::new(ip, port);
                let pool = pool::ConnectionPool::new(vec![addr], factory_fn(host, path, tls_config), pool_cfg);
                Some(Self::Pool { pool, bootstrap })
            }
            Err(_) => Some(Self::NeedResolve {
                server_name: host.to_string(),
                port,
                tls_config,
                raw_pool,
                bootstrap,
                protocol,
            }),
        }
    }

    fn from_quic_url(rest: &str, bootstrap: bool, raw_pool: Option<config::RawPoolConfig>) -> Option<Self> {
        let (host, port) = parse_host_port(rest)?;
        let tls_config = default_tls_client_config();
        let host_arc: Arc<str> = host.as_str().into();
        match host.as_str().parse::<IpAddr>() {
            Ok(ip) => {
                let addr = SocketAddr::new(ip, port);
                let pool_cfg = raw_pool.unwrap_or_default().into_pool_config(false);
                let pool = pool::ConnectionPool::new(vec![addr], factory::doq_factory(host_arc, tls_config), pool_cfg);
                Some(Self::Pool { pool, bootstrap })
            }
            Err(_) => Some(Self::NeedResolve {
                server_name: host,
                port,
                tls_config,
                raw_pool,
                bootstrap,
                protocol: ResolveProtocol::Doq { host: host_arc },
            }),
        }
    }
}

fn build_tcp_pool(addr: SocketAddr, raw_pool: Option<config::RawPoolConfig>) -> Arc<pool::ConnectionPool> {
    let pool_cfg = raw_pool.unwrap_or_default().into_pool_config(false);
    pool::ConnectionPool::new(vec![addr], factory::tcp_factory(), pool_cfg)
}

fn build_udp_pool(addr: SocketAddr, raw_pool: Option<config::RawPoolConfig>) -> Arc<pool::ConnectionPool> {
    let pool_cfg = raw_pool.unwrap_or_default().into_pool_config(true);
    pool::ConnectionPool::new(vec![addr], factory::udp_factory(), pool_cfg)
}

fn parse_host_port(s: &str) -> Option<(String, u16)> {
    s.rsplit_once(':')
        .and_then(|(host, port_str)| port_str.parse::<u16>().ok().map(|port| (host.to_string(), port)))
        .or_else(|| Some((s.to_string(), 853)))
}

fn parse_upstream(addr: &str, bootstrap: bool, raw_pool: Option<config::RawPoolConfig>) -> Option<UpstreamConfig> {
    use UpstreamConfig as U;
    if let Some(rest) = addr.strip_prefix("udp://") {
        let sock_addr: SocketAddr = rest.parse().ok()?;
        let pool = build_udp_pool(sock_addr, raw_pool);
        return Some(U::Pool { pool, bootstrap });
    }
    if let Some(rest) = addr.strip_prefix("tcp://") {
        let sock_addr: SocketAddr = rest
            .parse::<SocketAddr>()
            .or_else(|_| format!("{}:53", rest).parse())
            .ok()?;
        return Some(U::Tcp {
            addr: sock_addr,
            bootstrap,
            raw_pool,
        });
    }
    if let Some(rest) = addr.strip_prefix("tls://") {
        return U::from_tls_url(rest, bootstrap, raw_pool);
    }
    if addr.starts_with("https://") {
        return U::from_http_url(addr, bootstrap, raw_pool);
    }
    if addr.starts_with("h3://") {
        return U::from_http_url(addr, bootstrap, raw_pool);
    }
    if let Some(rest) = addr.strip_prefix("quic://") {
        return U::from_quic_url(rest, bootstrap, raw_pool);
    }
    let sock_addr: SocketAddr = addr
        .parse::<SocketAddr>()
        .or_else(|_| format!("{}:53", addr).parse())
        .ok()?;
    let pool = build_udp_pool(sock_addr, raw_pool);
    Some(U::Pool { pool, bootstrap })
}

async fn bootstrap_resolve_all(
    bootstrap_clients: &[UpstreamClient],
    targets: &[(usize, UpstreamConfig)],
) -> Vec<(usize, Vec<SocketAddr>)> {
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::{Name, RData, RecordType};

    async fn resolve_host_all(bootstrap_clients: &[UpstreamClient], host: &str, port: u16) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();

        for qtype in [RecordType::A, RecordType::AAAA] {
            let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
            let mut q = hickory_proto::op::Query::new();
            if let Ok(name) = Name::from_utf8(host) {
                q.set_name(name);
            } else {
                continue;
            }
            q.set_query_type(qtype);
            q.set_query_class(hickory_proto::rr::DNSClass::IN);
            msg.queries.push(q);
            msg.metadata.recursion_desired = true;

            for client in bootstrap_clients {
                match client.query(&msg).await {
                    Ok(resp) => {
                        for answer in &resp.answers {
                            match answer.data {
                                RData::A(ip) => {
                                    addrs.push(SocketAddr::new(IpAddr::V4(ip.0), port));
                                }
                                RData::AAAA(ip) => {
                                    addrs.push(SocketAddr::new(IpAddr::V6(ip.0), port));
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Bootstrap query failed for {} ({}): {}", host, qtype, e);
                    }
                }
            }
        }
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    let mut results = Vec::new();
    for (idx, cfg) in targets {
        let (host_str, port) = match cfg {
            UpstreamConfig::NeedResolve { server_name, port, .. } => (server_name.clone(), *port),
            _ => continue,
        };
        let addrs = resolve_host_all(bootstrap_clients, &host_str, port).await;
        results.push((*idx, addrs));
    }
    results
}

fn materialize_static_pool(cfg: &mut UpstreamConfig) {
    if let UpstreamConfig::Tcp {
        addr,
        bootstrap,
        raw_pool,
    } = cfg
    {
        let pool = build_tcp_pool(*addr, raw_pool.clone());
        *cfg = UpstreamConfig::Pool {
            pool,
            bootstrap: *bootstrap,
        };
    }
}

async fn build_bootstrap_pools(configs: &mut [UpstreamConfig]) -> Vec<UpstreamClient> {
    let mut clients = Vec::new();
    for cfg in configs {
        if matches!(cfg, UpstreamConfig::Tcp { bootstrap: true, .. }) {
            materialize_static_pool(cfg);
        }
        if cfg.is_bootstrap() {
            if let UpstreamConfig::Pool { pool, bootstrap: _ } = cfg {
                clients.push(UpstreamClient::new(pool.clone()));
            }
        }
    }
    clients
}

fn build_resolved_pool(cfg: &UpstreamConfig, addrs: Vec<SocketAddr>) -> io::Result<Arc<pool::ConnectionPool>> {
    match cfg {
        UpstreamConfig::NeedResolve {
            server_name,
            tls_config,
            raw_pool,
            protocol,
            ..
        } => {
            let pool_cfg = raw_pool.clone().unwrap_or_default().into_pool_config(false);
            let factory: conn::ConnFactory = match protocol {
                ResolveProtocol::Tls => factory::tls_factory(server_name.clone(), tls_config.clone()),
                ResolveProtocol::Doh { host, path } => {
                    factory::doh_factory(host.clone(), path.clone(), tls_config.clone())
                }
                ResolveProtocol::Doh3 { host, path } => {
                    factory::doh3_factory(host.clone(), path.clone(), tls_config.clone())
                }
                ResolveProtocol::Doq { host } => factory::doq_factory(host.clone(), tls_config.clone()),
            };
            Ok(pool::ConnectionPool::new(addrs, factory, pool_cfg))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "not a resolve config")),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = rslog::init(log::LevelFilter::Info);

    build_info::log_startup_info("rsdns");

    let args = Args::parse();
    let config_path = args.config.to_string_lossy();
    info!("Loading config from {}", config_path);

    let config = Config::from_file(&config_path)?;

    let groups_trie = build_groups_trie(&config.groups);
    if !config.groups.is_empty() {
        info!("domain groups loaded:");
        for (tag, domains) in &config.groups {
            info!("  '{}': {} items", tag, domains.len());
        }
    }
    let hosts_trie = build_hosts_trie(&config.hosts);
    if !config.hosts.is_empty() {
        info!("hosts entries: {}", config.hosts.len());
    }
    let rules = build_rules(&config.rules);
    info!("rules: {}", rules.len());

    let cache_config = config.cache.unwrap_or_default();
    let cache = DnsCache::new(
        cache_config.size.unwrap_or(4096),
        cache_config.min_ttl.unwrap_or(60),
        cache_config.max_ttl.unwrap_or(3600),
        cache_config.serve_expired.unwrap_or(false),
        cache_config.keep_ttl.unwrap_or(false),
    );

    let mut all_configs: Vec<UpstreamConfig> = Vec::new();
    let mut upstream_map: Vec<(String, Vec<usize>, QueryModeConfig)> = Vec::new();

    info!("rsdns starting, upstream pools: {}", config.upstream.len());
    for (name, group) in &config.upstream {
        let servers = &group.servers;
        info!("  upstream pool '{}': {} server(s)", name, servers.len());
        let mut indices = Vec::new();
        for server in servers {
            let idx = all_configs.len();
            let protocol_label = classify_upstream(&server.address);
            let bootstrap_label = if server.bootstrap { "bootstrap" } else { "upstream" };
            info!("    {} {} server: {}", bootstrap_label, protocol_label, server.address);

            if let Some(cfg) = parse_upstream(&server.address, server.bootstrap, server.pool.clone()) {
                all_configs.push(cfg);
                indices.push(idx);
            } else {
                warn!("    failed to parse upstream: {}", server.address);
            }
        }
        upstream_map.push((name.clone(), indices, group.mode));
    }

    // Phase 1: bootstrap pools
    let bootstrap_clients = build_bootstrap_pools(&mut all_configs).await;
    info!("bootstrap clients: {}", bootstrap_clients.len());

    // Phase 2: resolve domain upstreams via bootstrap (A + AAAA = all addresses)
    let dynamic_indices: Vec<usize> = all_configs
        .iter()
        .enumerate()
        .filter(|(_, c)| c.needs_resolve() && !c.is_bootstrap())
        .map(|(i, _)| i)
        .collect();

    if !dynamic_indices.is_empty() {
        info!("resolving {} dynamic upstream(s) via bootstrap...", dynamic_indices.len());
        let dynamic_entries: Vec<(usize, UpstreamConfig)> =
            dynamic_indices.iter().map(|&i| (i, all_configs[i].clone())).collect();
        let resolved = bootstrap_resolve_all(&bootstrap_clients, &dynamic_entries).await;

        for (idx, addrs) in resolved {
            if addrs.is_empty() {
                return Err(format!("failed to resolve dynamic upstream index={}", idx).into());
            }
            info!("    resolved index={} -> {} addresses: {:?}", idx, addrs.len(), addrs);

            let pool = build_resolved_pool(&all_configs[idx], addrs)
                .map_err(|e| format!("failed to build resolved pool index={}: {}", idx, e))?;

            all_configs[idx] = UpstreamConfig::Pool { pool, bootstrap: false };
        }
    }

    // Phase 3: build remaining TCP pools (non-domain, non-bootstrap)
    for cfg in &mut all_configs {
        if matches!(cfg, UpstreamConfig::Tcp { bootstrap: false, .. }) {
            materialize_static_pool(cfg);
        }
    }

    // Phase 4: assemble UpstreamGroup
    let upstreams: AHashMap<String, UpstreamGroup> = upstream_map
        .into_iter()
        .map(|(name, indices, mode)| {
            let clients: Vec<UpstreamClient> = indices
                .iter()
                .filter_map(|&i| match &all_configs[i] {
                    UpstreamConfig::Pool { pool, bootstrap: _ } => Some(UpstreamClient::new(pool.clone())),
                    _ => None,
                })
                .collect();
            let mode = match mode {
                QueryModeConfig::Serial => QueryMode::Serial,
                QueryModeConfig::Parallel => QueryMode::Parallel,
            };
            (name, UpstreamGroup::new(clients, mode))
        })
        .collect();

    let logger = Arc::new(QueryLogger::new(&config.log)?);
    logger.start_flush_task(Duration::from_secs(5));
    let server = DnsServer::new(hosts_trie, groups_trie, rules, cache, upstreams, logger.clone());

    info!("listening on {} address(es)", config.bind.len());
    for bind in &config.bind {
        let addr_str = &bind.address;

        if let Some(rest) = addr_str.strip_prefix("tcp://") {
            let addr: SocketAddr = rest.parse()?;
            let s = server.clone_inner();
            info!("  TCP {}", addr);
            tokio::spawn(async move {
                if let Err(e) = s.serve_tcp(addr).await {
                    error!("TCP server on {} failed: {}", addr, e);
                }
            });
        } else {
            let addr: SocketAddr = addr_str.parse()?;
            let s = server.clone_inner();
            info!("  UDP {}", addr);
            tokio::spawn(async move {
                if let Err(e) = s.serve_udp(addr).await {
                    error!("UDP server on {} failed: {}", addr, e);
                }
            });
        }
    }

    info!("rsdns started, press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down");
    logger.flush();
    Ok(())
}

fn classify_upstream(addr: &str) -> &'static str {
    if addr.starts_with("udp://") {
        "UDP"
    } else if addr.starts_with("tcp://") {
        "TCP"
    } else if addr.starts_with("tls://") {
        "TLS"
    } else if addr.starts_with("https://") {
        "DoH"
    } else if addr.starts_with("h3://") {
        "DoH3"
    } else if addr.starts_with("quic://") {
        "DoQ"
    } else {
        "UDP"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_rules_maps_forward_deny_qtypes() {
        let rules = build_rules(&[config::RuleConfig {
            r#match: config::MatchTarget::Wildcard("*".into()),
            qtype: None,
            action: config::RuleActionConfig::Forward {
                upstream: "default".into(),
                cache: true,
                ttl: Some(60),
                deny_qtypes: vec!["AAAA".into(), "HTTPS".into()],
            },
        }]);

        match &rules[0].action {
            RuleAction::Forward {
                upstream,
                cache,
                ttl,
                deny_qtypes,
            } => {
                assert_eq!(upstream, "default");
                assert!(*cache);
                assert_eq!(*ttl, Some(60));
                assert_eq!(deny_qtypes, &vec![RecordType::AAAA, RecordType::HTTPS]);
            }
            _ => panic!("expected forward rule"),
        }
    }
}
