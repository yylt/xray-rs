//! Configuration types for rsdns.
//!
//! The top-level [`Config`] mirrors `rsdns.yaml`.  `ServerConfig` gains
//! an optional [`RawPoolConfig`] block for connection-pool tuning.
//! `RawPoolConfig` is converted to the runtime [`PoolConfig`] via
//! `into_pool_config()`.

use serde::Deserialize;
use std::collections::HashMap;

use super::pool::{PoolConfig, PreferFamily};

/// Root configuration, deserialised from rsdns.yaml.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    /// Listen addresses: `"0.0.0.0:53"` for UDP, `"tcp://0.0.0.0:53"` for TCP.
    #[serde(default)]
    pub bind: Vec<BindConfig>,
    /// Named domain groups for rule matching.  Keys are group names,
    /// values are suffix patterns (supports `"file:"` prefix, `"*."` wildcards).
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,
    /// Upstream pools keyed by name. Each pool can be a plain server list or
    /// an object with an explicit query mode.
    #[serde(default)]
    pub upstream: HashMap<String, UpstreamGroupConfig>,
    /// Optional cache tuning (LRU capacity, TTL bounds, stale serving).
    pub cache: Option<CacheConfig>,
    /// Static host overrides (suffix-matched).  Format: `"IP domain"`,
    /// supports `"file:"` prefix and `"*."` wildcards.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// DNS routing rules, evaluated in order, first match stops.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    /// Query log configuration (optional).
    #[serde(default)]
    pub log: LogConfig,
}

/// A single listening address.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BindConfig {
    /// `"0.0.0.0:53"` (UDP) or `"tcp://0.0.0.0:53"` (TCP).
    pub address: String,
}

/// A single upstream server entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address with optional scheme: `"223.5.5.5"`, `"tls://dot.pub"`,
    /// `"https://doh.pub/dns-query"`, `"h3://..."`, `"quic://..."`.
    pub address: String,
    /// If `true`, this server is used only for bootstrap DNS resolution,
    /// never for query forwarding.
    #[serde(default)]
    pub bootstrap: bool,
    /// Optional connection-pool configuration (see [`RawPoolConfig`]).
    #[serde(default)]
    pub pool: Option<RawPoolConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamGroupConfig {
    #[serde(default)]
    pub mode: QueryModeConfig,
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QueryModeConfig {
    Parallel,
    #[default]
    Serial,
}

/// Cache behaviour tuning.  All fields are optional; missing fields use
/// the defaults defined in `DnsCache::new()`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CacheConfig {
    /// LRU capacity (default 4096).
    #[serde(default)]
    pub size: Option<usize>,
    /// Minimum TTL to clamp responses to (seconds).
    #[serde(default)]
    pub min_ttl: Option<u32>,
    /// Maximum TTL to clamp responses to (seconds).
    #[serde(default)]
    pub max_ttl: Option<u32>,
    /// If `true`, serve stale cache entries when the upstream is unreachable.
    #[serde(default)]
    pub serve_expired: Option<bool>,
    /// If `true`, preserve the upstream's original TTL (overrides `min_ttl`/`max_ttl`).
    #[serde(default)]
    pub keep_ttl: Option<bool>,
}

/// A single DNS routing rule.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    /// Match target: a group name (from `[groups]`) or a plain wildcard pattern.
    #[serde(alias = "r#match")]
    pub r#match: MatchTarget,
    /// Optional query-type filter (`"A"`, `"AAAA"`, `"ANY"`, …).
    #[serde(default)]
    pub qtype: Option<String>,
    /// Action to take when this rule matches.
    pub action: RuleActionConfig,
}

/// What a rule's `match` field refers to.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum MatchTarget {
    /// `match: ad` — references a group in `[groups]`.
    Group(String),
    /// `match: "*"` or `match: "*.example.com"` — literal wildcard.
    Wildcard(String),
}

impl Default for MatchTarget {
    fn default() -> Self {
        MatchTarget::Wildcard("*".into())
    }
}

/// What happens when a rule matches.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum RuleActionConfig {
    /// Return NXDomain or a poison record (0.0.0.0 / ::).
    #[serde(rename = "block")]
    Block {
        #[serde(default = "default_block_response")]
        response: BlockResponse,
    },
    /// Rewrite the query to a CNAME target, recursively resolve, return the
    /// target's IP along with a synthetic CNAME record.
    #[serde(rename = "cname")]
    Cname {
        /// Canonical name target.
        target: String,
        /// Optional TTL override for the CNAME and resolved records.
        ttl: Option<u32>,
        /// Upstream pool name to resolve the target.
        upstream: String,
        /// Refuse these query types before resolving (e.g. ["A", "AAAA"]).
        #[serde(default)]
        deny_qtypes: Vec<String>,
    },
    /// Forward the query to a named upstream pool.
    #[serde(rename = "forward")]
    Forward {
        /// `upstream` pool name (must exist in `[upstream]`).
        #[serde(default)]
        upstream: String,
        /// `false` means bypass the cache entirely for this rule.
        #[serde(default = "default_true")]
        cache: bool,
        /// If set, rewrite the response TTL to this value.
        ttl: Option<u32>,
        /// Refuse these query types before forwarding upstream (e.g. ["A", "AAAA"]).
        #[serde(default)]
        deny_qtypes: Vec<String>,
    },
}

/// Block response variant.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponse {
    Nxdomain,
    Poison,
}

fn default_block_response() -> BlockResponse {
    BlockResponse::Nxdomain
}

fn default_true() -> bool {
    true
}

/// User-facing pool configuration as parsed from YAML.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawPoolConfig {
    pub max_size: Option<usize>,
    pub min_idle: Option<usize>,
    pub idle_timeout: Option<u64>,
    pub max_lifetime: Option<u64>,
    pub health_interval: Option<u64>,
    pub connect_timeout: Option<u64>,
    pub dns_timeout: Option<u64>,

    /// `"any"` (default), `"ipv4"`, or `"ipv6"`.
    pub prefer_family: Option<String>,
    /// Seconds before a health-check SOA probe times out.
    pub health_check_timeout: Option<u64>,
    /// Consecutive failures before an address enters cool-down.
    pub max_consecutive_fail: Option<u32>,
    /// Cool-down duration in seconds.
    pub cool_down_secs: Option<u64>,
}

/// 将可选的秒数配置转换为 [`Duration`]，缺省时用 `default`。
fn opt_dur(secs: Option<u64>, default: std::time::Duration) -> std::time::Duration {
    secs.map(std::time::Duration::from_secs).unwrap_or(default)
}

impl RawPoolConfig {
    /// Converts the raw YAML config into a runtime [`PoolConfig`].
    ///
    /// `is_udp` controls the `max_size` default: UDP uses 1 since it does
    /// not benefit from multiple long-lived pooled connections.
    pub fn into_pool_config(self, is_udp: bool) -> PoolConfig {
        let defaults = PoolConfig::default();
        PoolConfig {
            max_size: self.max_size.unwrap_or(if is_udp { 1 } else { defaults.max_size }),
            min_idle: self.min_idle.unwrap_or(defaults.min_idle),
            idle_timeout: opt_dur(self.idle_timeout, defaults.idle_timeout),
            max_lifetime: opt_dur(self.max_lifetime, defaults.max_lifetime),
            health_interval: opt_dur(self.health_interval, defaults.health_interval),
            connect_timeout: opt_dur(self.connect_timeout, defaults.connect_timeout),
            dns_timeout: opt_dur(self.dns_timeout, defaults.dns_timeout),
            prefer_family: match self.prefer_family.as_deref() {
                Some("ipv4") => PreferFamily::Ipv4,
                Some("ipv6") => PreferFamily::Ipv6,
                _ => PreferFamily::Any,
            },
            health_check_timeout: opt_dur(self.health_check_timeout, defaults.health_check_timeout),
            max_consecutive_fail: self.max_consecutive_fail.unwrap_or(defaults.max_consecutive_fail),
            cool_down: opt_dur(self.cool_down_secs, defaults.cool_down),
            is_udp,
        }
    }
}

/// Query log configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    /// Format template with placeholders: `{type}`, `{name}`, `{proto}`, `{remote}`,
    /// `{action}`, `{port}`, `{size}`, `{duration}`, `{rcode}`.
    /// Default: `"{remote}:{port} {name} [{type}] {rcode} {duration}"`
    #[serde(default = "default_format")]
    pub format: String,

    /// Log file path.  None means stdout.
    pub file: Option<String>,

    /// Write buffer size in bytes, default 16384 (16 KB).
    /// 查询日志先在写任务中累积，达到该字节数时写入一次。
    #[serde(default = "default_buf_size")]
    pub buf_size: usize,

    /// Flush interval in seconds, default 5.
    /// 即使未达到 `buf_size`，也按此间隔将累积的日志写入。
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: Option<u64>,
}

fn default_format() -> String {
    "{remote} {name} \"{type}\" [{answers}] \"{action}\" {duration}s".into()
}

fn default_buf_size() -> usize {
    16384
}

fn default_flush_interval_secs() -> Option<u64> {
    Some(5)
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            file: None,
            buf_size: default_buf_size(),
            flush_interval_secs: default_flush_interval_secs(),
        }
    }
}

impl Config {
    /// Parses a YAML string into a [`Config`].
    pub fn from_yaml_str(content: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(content)
    }

    /// Reads a YAML file and parses it into a [`Config`].
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::from_yaml_str(&content)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_example_config() {
        let yaml = r#"
bind:
  - address: "0.0.0.0:53"
  - address: "tcp://0.0.0.0:53"
groups:
  ad:
    - "*.doubleclick.net"
  intranet:
    - "*.corp.internal"
upstream:
  default:
    servers:
      - address: 223.5.5.5
        bootstrap: true
      - address: tls://dot.pub
        pool:
          max_size: 8
          prefer_family: ipv4
  overseas:
    mode: parallel
    servers:
      - address: tls://8.8.8.8
cache:
  size: 4096
  min_ttl: 60
  max_ttl: 3600
  serve_expired: true
hosts:
  - "127.0.0.1 localhost"
rules:
  - match: ad
    action:
      type: block
      response: poison
  - match: intranet
    action:
      type: forward
      upstream: default
      cache: false
  - match: "*"
    action:
      type: forward
      upstream: default
      deny_qtypes: ["HTTPS"]
"#;
        let config = Config::from_yaml_str(yaml).expect("parse failed");
        assert_eq!(config.bind.len(), 2);
        assert_eq!(config.bind[0].address, "0.0.0.0:53");
        assert_eq!(config.bind[1].address, "tcp://0.0.0.0:53");
        assert_eq!(config.groups.len(), 2);
        assert_eq!(config.upstream.len(), 2);
        assert_eq!(config.upstream["default"].mode, QueryModeConfig::Serial);
        assert_eq!(config.upstream["overseas"].mode, QueryModeConfig::Parallel);
        assert_eq!(config.upstream["default"].servers.len(), 2);
        assert!(config.cache.is_some());
        assert_eq!(config.cache.as_ref().unwrap().size, Some(4096));
        assert_eq!(config.hosts.len(), 1);
        assert_eq!(config.rules.len(), 3);
    }

    #[test]
    fn test_legacy_upstream_list_defaults_to_serial() {
        let yaml = r#"
upstream:
  default:
    servers:
      - address: 223.5.5.5
"#;
        let config = Config::from_yaml_str(yaml).expect("parse failed");
        assert_eq!(config.upstream["default"].mode, QueryModeConfig::Serial);
        assert_eq!(config.upstream["default"].servers.len(), 1);
    }

    #[test]
    fn test_pool_config_parse() {
        let pc = RawPoolConfig {
            max_size: Some(8),
            prefer_family: Some("ipv4".into()),
            max_consecutive_fail: Some(5),
            ..Default::default()
        };
        let pool = pc.into_pool_config(false);
        assert_eq!(pool.max_size, 8);
        assert_eq!(pool.prefer_family, PreferFamily::Ipv4);
        assert_eq!(pool.max_consecutive_fail, 5);
    }

    #[test]
    fn test_udp_pool_defaults_to_single_connection() {
        let pool = RawPoolConfig::default().into_pool_config(true);
        assert_eq!(pool.max_size, 1);
    }
}
