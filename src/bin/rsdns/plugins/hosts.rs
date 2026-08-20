//! `hosts` stage — static host overrides.
//!
//! Looks up the queried name in the hosts trie; on hit, builds a response
//! and short-circuits the pipeline (`Step::Respond`), mirroring the old
//! `hosts`-first behaviour.

use log::{error, info};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use xray_rs::common::domain_trie::{DomainSuffixTrie, DomainSuffixTrieBuilder};

use crate::config::Config;
use crate::metrics::{Counter, Gauge, MetricsRegistry};
use crate::plugins::util::{build_hosts_response, build_servfail};
use crate::query::{QueryContext, Step};

pub struct HostsTrie {
    trie: DomainSuffixTrie,
    ips: Vec<Vec<IpAddr>>,
}

impl HostsTrie {
    pub fn lookup(&self, domain: &str) -> Option<&[IpAddr]> {
        self.trie
            .lookup(domain)
            .and_then(|tag_str| tag_str.parse::<usize>().ok())
            .and_then(|idx| self.ips.get(idx))
            .map(|v| v.as_slice())
    }
}

pub struct HostsTrieBuilder {
    builder: DomainSuffixTrieBuilder,
    ips: Vec<Vec<IpAddr>>,
    domain_to_idx: HashMap<String, usize>,
}

impl HostsTrieBuilder {
    pub fn new() -> Self {
        Self {
            builder: DomainSuffixTrieBuilder::new(),
            ips: Vec::new(),
            domain_to_idx: HashMap::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, ip: IpAddr) {
        let domain = domain.trim_start_matches("*.");
        let idx = *self.domain_to_idx.entry(domain.to_string()).or_insert_with(|| {
            let idx = self.ips.len();
            self.ips.push(Vec::new());
            self.builder.insert(domain, &idx.to_string());
            idx
        });
        if let Some(entries) = self.ips.get_mut(idx) {
            entries.push(ip);
        }
    }

    pub fn build(self) -> HostsTrie {
        HostsTrie {
            trie: self.builder.build().expect("FST build failed"),
            ips: self.ips,
        }
    }
}

impl Default for HostsTrieBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 解析一行 hosts 条目：`IP domain [domain...]`。
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

/// 从配置条目（内联行或 `file://` 前缀）构建 hosts trie。
fn build_hosts_trie(entries: &[String]) -> HostsTrie {
    let mut builder = HostsTrieBuilder::new();

    for entry in entries {
        if let Some(file_path) = entry.strip_prefix("file://") {
            match std::fs::read_to_string(file_path) {
                Ok(content) => {
                    for line in content.lines() {
                        parse_hosts_line(&mut builder, line);
                    }
                    info!("Loaded hosts from {}", file_path);
                }
                Err(e) => error!("Failed to load hosts {}: {}", file_path, e),
            }
        } else if let Some(file_path) = entry.strip_prefix("file:") {
            // legacy single-colon prefix kept for compatibility with docs
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

struct HostsMetrics {
    lookup_total: Counter,
    hit_total: Counter,
    entries: Gauge,
}

impl HostsMetrics {
    fn new(registry: &MetricsRegistry) -> Self {
        Self {
            lookup_total: registry.counter("rsdns_hosts_lookup_total", "Hosts trie lookups", &[]),
            hit_total: registry.counter("rsdns_hosts_hit_total", "Hosts trie hits", &[]),
            entries: registry.gauge("rsdns_hosts_entries", "Loaded hosts entries", &[]),
        }
    }
}

/// The hosts stage.
pub struct Hosts {
    trie: Arc<HostsTrie>,
    metrics: std::sync::OnceLock<HostsMetrics>,
}

/// Builds the hosts stage from the `hosts:` config section (or none).
pub fn init(config: &Config, registry: &MetricsRegistry) -> Hosts {
    let raw = config.plugin_sections.get("hosts").cloned().unwrap_or_default();
    let entries: Vec<String> = if raw.is_null() {
        Vec::new()
    } else {
        serde_yaml::from_value(raw).unwrap_or_default()
    };
    let trie = build_hosts_trie(&entries);
    let metrics = HostsMetrics::new(registry);
    metrics.entries.set(entries.len() as u64);
    Hosts {
        trie: Arc::new(trie),
        metrics: std::sync::OnceLock::from(metrics),
    }
}

impl Hosts {
    /// Static mapping hit → `Respond`; miss → `Continue`.
    pub fn handle<'a>(&'a self, ctx: &'a mut QueryContext) -> Step {
        if let Some(m) = self.metrics.get() {
            m.lookup_total.inc();
        }
        let name = ctx.name();
        if let Some(ips) = self.trie.lookup(name) {
            if let Some(m) = self.metrics.get() {
                m.hit_total.inc();
            }
            match build_hosts_response(&ctx.msg, name, ctx.qtype(), ips) {
                Ok(resp) => {
                    ctx.response = Some(resp);
                    ctx.action = "hosts".into();
                    Step::Respond
                }
                Err(e) => {
                    log::warn!("hosts building response for {} failed: {}", name, e);
                    ctx.response = Some(build_servfail(&ctx.msg));
                    ctx.action = "hosts".into();
                    Step::Respond
                }
            }
        } else {
            Step::Continue
        }
    }
}
