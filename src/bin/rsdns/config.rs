use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// 主配置结构
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub bind: Vec<BindConfig>,
    #[serde(default)]
    pub groups: Vec<HashMap<String, Vec<String>>>,
    #[serde(default)]
    pub upstreams: Vec<HashMap<String, UpstreamDetail>>,
    pub cache: Option<CacheConfig>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

/// 监听地址配置
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BindConfig {
    pub address: String,
    #[serde(default)]
    pub ip6: Option<bool>,
    #[serde(default)]
    pub ip4: Option<bool>,
    #[serde(default)]
    pub cert_file: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
}

/// 上游 DNS 详细配置
#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpstreamDetail {
    #[serde(default)]
    pub bootstrap: bool,
    #[serde(default)]
    pub server: Vec<String>,
}

/// 缓存配置
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CacheConfig {
    #[serde(default)]
    pub size: Option<usize>,
    #[serde(default)]
    pub min_ttl: Option<u32>,
    #[serde(default)]
    pub max_ttl: Option<u32>,
}

/// 规则配置
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuleConfig {
    pub r#match: MatchConfig,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub cache: Option<bool>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub ip6: Option<bool>,
    #[serde(default)]
    pub cname: Option<String>,
}

/// 匹配条件配置
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MatchConfig {
    #[serde(default)]
    pub domain: Option<Vec<DomainMatch>>,
    #[serde(default)]
    pub client_ip: Option<String>,
}

/// 域名匹配项
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DomainMatch {
    Group { group: String },
    Exact(String),
}

impl Config {
    /// 从 YAML 字符串加载配置
    pub fn from_yaml_str(content: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(content)
    }

    /// 从文件路径加载配置
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
  - address: 0.0.0.0:53
    ip6: off
    ip4: on
groups:
  - ad:
      - file:/path/to/file
      - example.com
upstreams:
  - doh:
      bootstrap: false
      server:
        - https://x.x/dns-query
cache:
  size: 1024
  min_ttl: 30
  max_ttl: 300
hosts:
  - file:/path/to/file
  - "1.1.1.1 xx.yy"
rules:
  - match:
      domain:
        - group:ad
    ip: 0.0.0.0
"#;
        let config = Config::from_yaml_str(yaml).expect("parse failed");
        assert_eq!(config.bind.len(), 1);
        assert_eq!(config.bind[0].address, "0.0.0.0:53");
        assert_eq!(config.groups.len(), 1);
        assert!(config.cache.is_some());
        assert_eq!(config.cache.as_ref().unwrap().size, Some(1024));
    }
}
