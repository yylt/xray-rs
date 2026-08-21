//! `hosts` stage — static host overrides.
//!
//! Looks up the queried name in the hosts trie; on hit, builds a response
//! and short-circuits the pipeline (`Step::Respond`), mirroring the old
//! `hosts`-first behaviour.
//!
//! Inline entries build the trie at startup; `file://` entries are loaded
//! at startup and watched with the `notify` library, rebuilding the trie
//! and atomically swapping it on change.

use log::{error, info, warn};
use notify::{EventKind, RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
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

/// 从内联条目 + 文件内容构建 hosts trie。文件读取失败视为空内容。
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
    trie: Arc<RwLock<Arc<HostsTrie>>>,
    metrics: Arc<HostsMetrics>,
}

/// 校验 watch 事件：仅关注写入/重命名/删除/创建（含原子替换 tmp->target）。
fn is_change_event(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::Create(_) | EventKind::Remove(_) | EventKind::Modify(_) | EventKind::Any | EventKind::Other
    )
}

/// Builds the hosts stage from the `hosts:` config section (or none),
/// spawning a notify watcher per `file://` entry.
pub fn init(config: &Config, registry: &MetricsRegistry) -> Hosts {
    let raw = config.plugin_sections.get("hosts").cloned().unwrap_or_default();
    let entries: Vec<String> = if raw.is_null() {
        Vec::new()
    } else {
        serde_yaml::from_value(raw).unwrap_or_default()
    };
    let trie = Arc::new(build_hosts_trie(&entries));
    let metrics = Arc::new(HostsMetrics::new(registry));
    metrics.entries.set(trie.ips.len() as u64);
    let current = Arc::new(RwLock::new(trie));

    // 为每个 file 源 spawn notify watcher：变化时重建 trie 并原子替换。
    for entry in &entries {
        let file_path = entry.strip_prefix("file://").or_else(|| entry.strip_prefix("file:"));
        let Some(file_path) = file_path else { continue };
        let path = PathBuf::from(file_path);
        let cb_entries = entries.clone();
        let cb_current = current.clone();
        let cb_metrics = metrics.clone();
        match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            if !is_change_event(&event.kind) || event.flag().is_some() {
                return;
            }
            let new_trie = build_hosts_trie(&cb_entries);
            cb_metrics.entries.set(new_trie.ips.len() as u64);
            *cb_current.write() = Arc::new(new_trie);
        }) {
            Ok(mut watcher) => {
                if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
                    warn!("hosts: failed to watch {}: {}", path.display(), e);
                } else {
                    // 持有 watcher 直到进程退出，保持文件监控存活。
                    tokio::spawn(async move {
                        std::future::pending::<()>().await;
                        drop(watcher);
                    });
                }
            }
            Err(e) => {
                warn!("hosts: failed to watch {}: {}", path.display(), e);
            }
        }
    }

    Hosts { trie: current, metrics }
}

impl Hosts {
    /// Static mapping hit → `Respond`; miss → `Continue`.
    pub fn handle<'a>(&'a self, ctx: &'a mut QueryContext) -> Step {
        self.metrics.lookup_total.inc();
        let name = ctx.name();
        let ips = self.trie.read().lookup(name).map(|v| v.to_vec());
        if let Some(ips) = ips {
            self.metrics.hit_total.inc();
            match build_hosts_response(&ctx.msg, name, ctx.qtype(), &ips) {
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
