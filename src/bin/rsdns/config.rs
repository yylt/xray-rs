use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub bind: Vec<BindConfig>,
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub upstream: HashMap<String, UpstreamPool>,
    pub cache: Option<CacheConfig>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BindConfig {
    pub address: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpstreamPool {
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    #[serde(default)]
    pub bootstrap: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CacheConfig {
    #[serde(default)]
    pub size: Option<usize>,
    #[serde(default)]
    pub min_ttl: Option<u32>,
    #[serde(default)]
    pub max_ttl: Option<u32>,
    #[serde(default)]
    pub serve_expired: Option<bool>,
    #[serde(default)]
    pub keep_ttl: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    #[serde(alias = "r#match")]
    pub r#match: MatchTarget,
    #[serde(default)]
    pub qtype: Option<String>,
    pub action: RuleActionConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum MatchTarget {
    Group(String),
    Wildcard(String),
}

impl Default for MatchTarget {
    fn default() -> Self {
        MatchTarget::Wildcard("*".into())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum RuleActionConfig {
    #[serde(rename = "block")]
    Block {
        #[serde(default = "default_block_response")]
        response: BlockResponse,
    },
    #[serde(rename = "cname")]
    Cname { target: String, ttl: Option<u32> },
    #[serde(rename = "forward")]
    Forward {
        #[serde(default)]
        upstream: String,
        #[serde(default = "default_true")]
        cache: bool,
        ttl: Option<u32>,
        #[serde(rename = "keep_ttl")]
        keep_ttl: Option<bool>,
    },
}

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

impl Config {
    pub fn from_yaml_str(content: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(content)
    }

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
  overseas:
    servers:
      - address: tls://8.8.8.8
cache:
  size: 4096
  min_ttl: 60
  max_ttl: 3600
  serve_expired: true
  keep_ttl: false
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
      keep_ttl: true
"#;
        let config = Config::from_yaml_str(yaml).expect("parse failed");
        assert_eq!(config.bind.len(), 2);
        assert_eq!(config.bind[0].address, "0.0.0.0:53");
        assert_eq!(config.bind[1].address, "tcp://0.0.0.0:53");
        assert_eq!(config.groups.len(), 2);
        assert_eq!(config.upstream.len(), 2);
        assert!(config.cache.is_some());
        assert_eq!(config.cache.as_ref().unwrap().size, Some(4096));
        assert_eq!(config.hosts.len(), 1);
        assert_eq!(config.rules.len(), 3);
    }
}
