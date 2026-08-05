#![allow(deprecated)]

mod cache;
mod config;
mod hosts;
mod rule;
mod server;
mod upstream;

use ahash::AHashMap;
use clap::Parser;
use log::{error, info, warn};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use xray_rs::common::trie::{DomainMarisa, DomainMarisaBuilder};

use cache::DnsCache;
use config::Config;
use hosts::HostsTrieBuilder;
use rule::{BlockResponse, Rule, RuleAction};
use server::DnsServer;
use upstream::{UpstreamClient, UpstreamGroup};

#[derive(Parser, Debug)]
#[command(name = "rsdns")]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short = 'c', long = "config", default_value = "rsdns.yaml")]
    config: PathBuf,
}

fn load_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    Config::from_file(path)
}

fn build_groups_trie(groups: &std::collections::HashMap<String, Vec<String>>) -> DomainMarisa {
    let mut builder = DomainMarisaBuilder::new();

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

    builder.build()
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
                config::RuleActionConfig::Cname { target, ttl } => RuleAction::Cname {
                    target: target.clone(),
                    ttl: ttl.unwrap_or(600),
                },
                config::RuleActionConfig::Forward {
                    upstream,
                    cache,
                    ttl,
                    keep_ttl,
                } => RuleAction::Forward {
                    upstream: upstream.clone(),
                    cache: *cache,
                    ttl: *ttl,
                    keep_ttl: *keep_ttl,
                },
            };
            Rule { group, qtype, action }
        })
        .collect()
}

fn parse_qtype(s: &str) -> u16 {
    match s.to_uppercase().as_str() {
        "A" => 1,
        "AAAA" => 28,
        "ANY" => 255,
        "CNAME" => 5,
        "MX" => 15,
        "TXT" => 16,
        "NS" => 2,
        "SOA" => 6,
        "PTR" => 12,
        "SRV" => 33,
        _ => {
            if let Ok(v) = s.parse::<u16>() {
                v
            } else {
                0
            }
        }
    }
}

fn parse_upstream(addr: &str, bootstrap: bool) -> Option<UpstreamClient> {
    if let Some(rest) = addr.strip_prefix("udp://") {
        let sock_addr: SocketAddr = rest.parse().ok()?;
        let mut client = UpstreamClient::new_udp(vec![sock_addr]);
        client.bootstrap = bootstrap;
        return Some(client);
    }
    if let Some(rest) = addr.strip_prefix("tcp://") {
        let sock_addr: SocketAddr = rest.parse().ok()?;
        let mut client = UpstreamClient::new_tcp(vec![sock_addr]);
        client.bootstrap = bootstrap;
        return Some(client);
    }
    if let Some(rest) = addr.strip_prefix("tls://") {
        let (host, port) = parse_host_port(rest)?;
        let sock_addr = resolve_static(&host, port)?;
        let tls_config = default_tls_config();
        let mut client = UpstreamClient::new_tls(vec![sock_addr], host, tls_config);
        client.bootstrap = bootstrap;
        client.is_dynamic = false;
        return Some(client);
    }
    if let Some(rest) = addr.strip_prefix("https://") {
        let tls_config = default_tls_config();
        let mut client = UpstreamClient::new_doh(addr.to_string(), tls_config);
        client.bootstrap = bootstrap;
        return Some(client);
    }
    if let Some(_rest) = addr.strip_prefix("h3://") {
        let tls_config = default_tls_config();
        let mut client = UpstreamClient::new_doh3(addr.to_string(), tls_config);
        client.bootstrap = bootstrap;
        return Some(client);
    }

    let sock_addr: SocketAddr = addr
        .parse::<SocketAddr>()
        .or_else(|_| format!("{}:53", addr).parse())
        .ok()?;
    let mut client = UpstreamClient::new_udp(vec![sock_addr]);
    client.bootstrap = bootstrap;
    Some(client)
}

fn parse_host_port(s: &str) -> Option<(String, u16)> {
    let (host, port_str) = s.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    Some((host.to_string(), port))
}

fn resolve_static(host: &str, port: u16) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    let addr_str = format!("{}:{}", host, port);
    let mut addrs = addr_str.to_socket_addrs().ok()?;
    addrs.next()
}

fn default_tls_config() -> Arc<tokio_rustls::rustls::ClientConfig> {
    use tokio_rustls::rustls::crypto::ring::default_provider;
    default_provider().install_default().ok();

    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("load native certs") {
        root_store.add(cert).ok();
    }
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
}

async fn bootstrap_resolve(
    bootstrap_clients: &[Arc<UpstreamClient>],
    target_addrs: &[String],
) -> Vec<Option<SocketAddr>> {
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::{Name, RData, RecordType};
    use log::debug;

    let mut results = vec![None; target_addrs.len()];

    for (i, addr_str) in target_addrs.iter().enumerate() {
        if let Some(rest) = addr_str.strip_prefix("tls://") {
            let parsed = parse_host_port(rest);
            let (host, port) = match parsed {
                Some((h, p)) => (h, p),
                None => continue,
            };

            let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
            let mut q = hickory_proto::op::Query::new();
            q.set_name(Name::from_utf8(&host).unwrap());
            q.set_query_type(RecordType::A);
            q.set_query_class(hickory_proto::rr::DNSClass::IN);
            msg.queries.push(q);
            msg.metadata.recursion_desired = true;

            for client in bootstrap_clients {
                match client.query(&msg).await {
                    Ok(resp) => {
                        for answer in &resp.answers {
                            if let RData::A(ip) = answer.data {
                                let addr = SocketAddr::new(IpAddr::V4(ip.0), port);
                                debug!("Bootstrap resolved {} -> {}", addr_str, addr);
                                results[i] = Some(addr);
                                break;
                            }
                        }
                        if results[i].is_some() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Bootstrap query failed for {}: {}", addr_str, e);
                    }
                }
            }
        }
    }

    results
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();
    let config_path = args.config.to_string_lossy();
    info!("Loading config from {}", config_path);

    let config = load_config(&config_path)?;

    let groups_trie = build_groups_trie(&config.groups);
    let hosts_trie = build_hosts_trie(&config.hosts);
    let rules = build_rules(&config.rules);

    let cache_config = config.cache.unwrap_or_default();
    let cache = DnsCache::new(
        cache_config.size.unwrap_or(4096),
        cache_config.min_ttl.unwrap_or(60),
        cache_config.max_ttl.unwrap_or(3600),
        cache_config.serve_expired.unwrap_or(false),
    );

    let mut bootstrap_clients: Vec<UpstreamClient> = Vec::new();
    let mut dynamic_addrs: Vec<(usize, String)> = Vec::new();
    let mut upstream_clients: Vec<(String, Vec<UpstreamClient>)> = Vec::new();

    for (name, pool) in &config.upstream {
        let mut clients = Vec::new();
        for (idx, server) in pool.servers.iter().enumerate() {
            if let Some(mut client) = parse_upstream(&server.address, server.bootstrap) {
                if client.bootstrap {
                    bootstrap_clients.push(client.clone());
                }
                if server.bootstrap && !client.bootstrap {
                    dynamic_addrs.push((idx, server.address.clone()));
                }
                clients.push(client);
            }
        }
        upstream_clients.push((name.clone(), clients));
    }

    let bootstrap_arcs: Vec<Arc<UpstreamClient>> = bootstrap_clients.into_iter().map(Arc::new).collect();

    if !dynamic_addrs.is_empty() {
        let target_strs: Vec<String> = dynamic_addrs.iter().map(|(_, s)| s.clone()).collect();
        let resolved = bootstrap_resolve(&bootstrap_arcs, &target_strs).await;

        let mut upstream_groups: Vec<(String, Vec<UpstreamClient>)> = Vec::new();
        for (name, clients) in upstream_clients {
            let mut new_clients = Vec::new();
            for (idx, mut client) in clients.into_iter().enumerate() {
                for (di, (dyn_idx, _)) in dynamic_addrs.iter().enumerate() {
                    if idx == *dyn_idx {
                        if let Some(addr) = resolved[di] {
                            client.addrs = vec![addr];
                        }
                    }
                }
                new_clients.push(client);
            }
            upstream_groups.push((name, new_clients));
        }
        upstream_clients = upstream_groups;
    }

    let upstreams: AHashMap<String, UpstreamGroup> = upstream_clients
        .into_iter()
        .map(|(name, clients)| (name, UpstreamGroup::new(clients)))
        .collect();

    let server = DnsServer::new(hosts_trie, groups_trie, rules, cache, upstreams);

    for bind in &config.bind {
        let addr_str = &bind.address;

        if let Some(rest) = addr_str.strip_prefix("tcp://") {
            let addr: SocketAddr = rest.parse()?;
            let s = server.clone_inner();
            tokio::spawn(async move {
                if let Err(e) = s.serve_tcp(addr).await {
                    error!("TCP server on {} failed: {}", addr, e);
                }
            });
        } else {
            let addr: SocketAddr = addr_str.parse()?;
            let s = server.clone_inner();
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
    Ok(())
}
