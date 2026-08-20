//! `groups` stage — domain group membership resolution.
//!
//! Each configured group owns an independent `DomainSuffixTrie`
//! ([`GroupTrie`]).  The stage does **not** short-circuit: it resolves
//! which group the queried name belongs to (first match by config order),
//! sets `ctx.group` and `ctx.skip_cache`, then continues the pipeline.
//!
//! Groups can load domains from inline entries, `file://` paths and
//! `https://` URLs; groups with remote sources and `auto_reload > 0`
//! refresh them on a per-group period, atomically swapping the trie.

use bytes::Bytes;
use http_body_util::BodyExt;
use log::{info, warn};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, Interval, MissedTickBehavior};

use xray_rs::common::domain_trie::{DomainSuffixTrie, DomainSuffixTrieBuilder};
use xray_rs::common::tls::default_tls_client_config;

use crate::config::{Config, GroupConfig};
use crate::metrics::{Counter, Gauge, MetricsRegistry};
use crate::query::{QueryContext, Step};

/// A remote (reloadable) domain source.
#[derive(Debug, Clone)]
enum GroupSource {
    File(String),
    Https(String),
}

/// The currently-active trie for one group.
struct GroupTrie {
    trie: DomainSuffixTrie,
    version: u64,
    entry_count: usize,
}

/// Per-group state, shared with the reload task via `Arc`.
struct GroupState {
    name: String,
    skip_cache: bool,
    auto_reload: Option<u64>,
    inline: Vec<String>,
    remote: Vec<GroupSource>,
    /// Active trie (atomically replaced on reload).
    current: RwLock<GroupTrie>,
    /// Fingerprint of the last successfully loaded remote content.
    last_remote: parking_lot::Mutex<Option<Vec<String>>>,
}

impl GroupState {
    fn build_from(cfg: &GroupConfig) -> Self {
        let mut inline = Vec::new();
        let mut remote = Vec::new();
        for item in &cfg.domains {
            if let Some(path) = item.strip_prefix("file://") {
                remote.push(GroupSource::File(path.to_string()));
            } else if let Some(path) = item.strip_prefix("file:") {
                remote.push(GroupSource::File(path.to_string()));
            } else if let Some(url) = item.strip_prefix("https://") {
                remote.push(GroupSource::Https(format!("https://{url}")));
            } else {
                inline.push(item.trim_start_matches("*.").to_string());
            }
        }
        let initial = GroupTrie {
            trie: DomainSuffixTrie::new(),
            version: 0,
            entry_count: 0,
        };
        Self {
            name: cfg.name.clone(),
            skip_cache: cfg.skip_cache,
            auto_reload: cfg.auto_reload,
            inline,
            remote,
            current: RwLock::new(initial),
            last_remote: parking_lot::Mutex::new(None),
        }
    }
}

/// 解析一行域名数据：整行注释/空行忽略；剥 `*.` 前缀。
fn parse_domain_lines(content: &str, out: &mut Vec<String>) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // 行内可能带尾随注释/空白，取第一个词。
        let domain = line.split_whitespace().next().unwrap_or(line);
        let domain = domain.trim_start_matches("*.");
        if !domain.is_empty() {
            out.push(domain.to_string());
        }
    }
}

/// 用内联域名 + 远程域名构建一张组 trie。
fn build_group_trie(inline: &[String], remote: &[String], version: u64) -> GroupTrie {
    let mut builder = DomainSuffixTrieBuilder::new();
    let mut count = 0usize;
    for d in inline {
        builder.insert(d, "hit");
        count += 1;
    }
    for d in remote {
        builder.insert(d, "hit");
        count += 1;
    }
    let trie = builder.build().expect("FST build failed");
    GroupTrie {
        trie,
        version,
        entry_count: count,
    }
}

/// 拉取所有远程源（file 读盘 / https GET），返回合并后的域名列表。
async fn fetch_remote_domains(sources: &[GroupSource]) -> std::io::Result<Vec<String>> {
    let mut all = Vec::new();
    for src in sources {
        match src {
            GroupSource::File(path) => {
                let content = tokio::fs::read_to_string(path).await?;
                parse_domain_lines(&content, &mut all);
            }
            GroupSource::Https(url) => {
                let content = fetch_https(url).await?;
                parse_domain_lines(&content, &mut all);
            }
        }
    }
    Ok(all)
}

/// 通过 hyper + hyper-rustls 拉取一个 https 文本源（限制大小与超时）。
async fn fetch_https(url: &str) -> std::io::Result<String> {
    const MAX_BODY: usize = 4 * 1024 * 1024;
    const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

    let uri: hyper::Uri = url.parse().map_err(std::io::Error::other)?;
    let tls = default_tls_client_config();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config((*tls).clone())
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: hyper_util::client::legacy::Client<_, FullBody> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector);

    let resp = tokio::time::timeout(FETCH_TIMEOUT, client.get(uri))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("GET {url} timed out")))?
        .map_err(std::io::Error::other)?;

    if !resp.status().is_success() {
        return Err(std::io::Error::other(format!("GET {url}: HTTP {}", resp.status())));
    }

    let body = tokio::time::timeout(FETCH_TIMEOUT, resp.into_body().collect())
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "reading body timed out"))?
        .map_err(std::io::Error::other)?;
    let bytes = body.to_bytes();
    if bytes.len() > MAX_BODY {
        return Err(std::io::Error::other(format!(
            "GET {url}: body too large ({} bytes)",
            bytes.len()
        )));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

type FullBody = http_body_util::Full<Bytes>;

/// 单次组重载：拉取远程源，内容有变化则重建 trie 并原子替换。
async fn reload_group(state: &Arc<GroupState>, metrics: &GroupsMetrics) {
    let remote_domains = match fetch_remote_domains(&state.remote).await {
        Ok(d) => d,
        Err(e) => {
            warn!("reload group '{}' failed: {}", state.name, e);
            return;
        }
    };

    // 内容指纹：排序后的域名列表。无变化则跳过重建。
    let mut fingerprint = remote_domains.clone();
    fingerprint.sort_unstable();
    {
        let mut last = state.last_remote.lock();
        if last.as_ref() == Some(&fingerprint) {
            return;
        }
        *last = Some(fingerprint);
    }

    let version = state.current.read().version + 1;
    let new_trie = build_group_trie(&state.inline, &remote_domains, version);
    *state.current.write() = new_trie;
    metrics
        .entries
        .with_label_values(&[&state.name])
        .set(state.current.read().entry_count as u64);
    info!(
        "group '{}' reloaded: {} entries (version {})",
        state.name,
        state.current.read().entry_count,
        version
    );
}

/// 组重载/初始加载任务：先立即加载一次（覆盖 https 首次拉取），
/// 若 `auto_reload > 0` 则按周期循环。
async fn reload_loop(state: Arc<GroupState>, metrics: Arc<GroupsMetrics>) {
    reload_group(&state, &metrics).await;

    let Some(secs) = state.auto_reload.filter(|&s| s > 0) else {
        return; // 一次性初始加载完成
    };
    let mut iv: Interval = interval(Duration::from_secs(secs));
    iv.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        iv.tick().await;
        reload_group(&state, &metrics).await;
    }
}

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

struct GroupsMetrics {
    lookup_total: Counter,
    hit_total: Counter,
    entries: Gauge,
}

impl GroupsMetrics {
    fn new(registry: &MetricsRegistry) -> Self {
        Self {
            lookup_total: registry.counter("rsdns_groups_lookup_total", "Group resolution attempts", &[]),
            hit_total: registry.counter("rsdns_groups_hit_total", "Group hits", &["group"]),
            entries: registry.gauge("rsdns_groups_entries", "Entries per group", &["group"]),
        }
    }
}

/// The groups stage.
pub struct Groups {
    groups: Vec<Arc<GroupState>>,
    metrics: std::sync::OnceLock<Arc<GroupsMetrics>>,
}

/// Builds the groups stage from the top-level `groups[]` array, registering
/// metrics and spawning remote reload tasks.
pub fn init(config: &Config, registry: &MetricsRegistry) -> Groups {
    let metrics = Arc::new(GroupsMetrics::new(registry));
    let mut states: Vec<Arc<GroupState>> = Vec::new();

    for cfg in config.groups.iter() {
        let state = Arc::new(GroupState::build_from(cfg));
        // 初始加载：同步读入内联 + file 源（https 由 reload_loop 首次异步拉取）。
        match load_initial(&state) {
            Ok(trie) => {
                *state.current.write() = trie;
                info!(
                    "group '{}': {} entries ({} inline, {} remote source(s))",
                    state.name,
                    state.current.read().entry_count,
                    state.inline.len(),
                    state.remote.len()
                );
            }
            Err(e) => {
                // 保留空 trie，重载任务会再尝试；仅告警。
                warn!("group '{}' initial load failed: {}", state.name, e);
            }
        }
        metrics
            .entries
            .with_label_values(&[&state.name])
            .set(state.current.read().entry_count as u64);
        // 有远程源的组：spawn 初始加载 + 周期重载任务。
        if !state.remote.is_empty() {
            let state = state.clone();
            let m = metrics.clone();
            tokio::spawn(async move {
                reload_loop(state, m).await;
            });
        }
        states.push(state);
    }

    Groups {
        groups: states,
        metrics: std::sync::OnceLock::from(metrics),
    }
}

/// 同步加载内联 + file 源；https 源留空（异步任务补拉）。
fn load_initial(state: &Arc<GroupState>) -> std::io::Result<GroupTrie> {
    let mut remote = Vec::new();
    for src in &state.remote {
        match src {
            GroupSource::File(path) => {
                let content = std::fs::read_to_string(path)?;
                parse_domain_lines(&content, &mut remote);
            }
            GroupSource::Https(_) => {}
        }
    }
    Ok(build_group_trie(&state.inline, &remote, 0))
}

impl Groups {
    /// Resolves the queried name's group (first hit by config order),
    /// sets `ctx.group` / `ctx.skip_cache`, and continues the pipeline.
    pub fn handle(&self, ctx: &mut QueryContext) -> Step {
        if let Some(m) = self.metrics.get() {
            m.lookup_total.inc();
        }
        let name = ctx.name();
        for state in &self.groups {
            if state.current.read().trie.lookup(name).is_some() {
                ctx.group = Some(state.name.clone());
                if state.skip_cache {
                    ctx.skip_cache = true;
                }
                if let Some(m) = self.metrics.get() {
                    m.hit_total.with_label_values(&[&state.name]).inc();
                }
                return Step::Continue;
            }
        }
        Step::Continue
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_lines_handles_comments_and_wildcards() {
        let mut out = Vec::new();
        parse_domain_lines(
            "# comment\n\ndoubleclick.net\n*.googlesyndication.com\n  spaced.example.com  \n",
            &mut out,
        );
        assert_eq!(
            out,
            vec![
                "doubleclick.net".to_string(),
                "googlesyndication.com".to_string(),
                "spaced.example.com".to_string()
            ]
        );
    }

    #[test]
    fn test_build_group_trie_lookup() {
        let trie = build_group_trie(&["ad.example".to_string()], &["doubleclick.net".to_string()], 0);
        assert!(trie.trie.lookup("sub.ad.example").is_some());
        assert!(trie.trie.lookup("doubleclick.net").is_some());
        assert!(trie.trie.lookup("example.com").is_none());
        assert_eq!(trie.entry_count, 2);
    }

    #[test]
    fn test_group_state_classifies_sources() {
        let cfg = GroupConfig {
            name: "g".into(),
            domains: vec![
                "file:///tmp/a.txt".into(),
                "https://example.com/list.txt".into(),
                "inline.example".into(),
            ],
            auto_reload: Some(60),
            skip_cache: true,
        };
        let state = GroupState::build_from(&cfg);
        assert_eq!(state.inline, vec!["inline.example".to_string()]);
        assert_eq!(state.remote.len(), 2);
        assert!(matches!(state.remote[0], GroupSource::File(_)));
        assert!(matches!(state.remote[1], GroupSource::Https(_)));
        assert_eq!(state.auto_reload, Some(60));
        assert!(state.skip_cache);
    }

    #[test]
    fn test_http_client_type_is_send() {
        // 编译期检查：fetch_https 内部使用的 client 类型可构造。
        fn assert_send<T: Send>() {}
        assert_send::<
            hyper_util::client::legacy::Client<
                hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
                FullBody,
            >,
        >();
    }
}
