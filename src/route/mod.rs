pub mod cache;
pub mod dns;
pub mod matcher;
pub mod resolver;
pub mod router;
pub mod trie;

pub use resolver::DnsResolver;
pub use router::Router;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io, net::IpAddr, sync::Arc, time::Duration};

use self::trie::{DomainTrieBuilder, IpTrieBuilder};

const DEFAULT_FORWARD_IDLE_TIMEOUT_SECS: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingSettings {
    #[serde(rename = "domainStrategy")]
    domain_strategy: Strategy,

    #[serde(rename = "rules")]
    rules: Option<Vec<Rule>>,

    #[serde(rename = "fallback")]
    fallback: Option<Fallback>,

    #[serde(rename = "forwardIdleTimeout")]
    forward_idle_timeout: Option<u64>,
}

impl RoutingSettings {
    pub fn build_router(&self, dns: Arc<DnsResolver>, dns_groups: &[DnsGroup]) -> io::Result<Router> {
        let dns_groups_by_name: HashMap<&str, &DnsGroup> =
            dns_groups.iter().map(|group| (group.name.as_str(), group)).collect();

        let mut domain_builder = DomainTrieBuilder::new();
        let mut ip_builder = IpTrieBuilder::new();

        if let Some(rules) = &self.rules {
            for rule in rules {
                let target_tag = &rule.outbound_tag;
                let has_conditions = rule.domain.is_some() || rule.ips.is_some() || rule.inbound_tag.is_some();

                if !has_conditions {
                    log::warn!(
                        "routing rule with outbound_tag '{}' has no conditions (domain/ip/inboundTag), ignoring",
                        target_tag
                    );
                    continue;
                }

                if let Some(domains) = &rule.domain {
                    for domain in domains {
                        add_domain_rule(&mut domain_builder, &dns_groups_by_name, domain, target_tag)?;
                    }
                }

                if let Some(ips) = &rule.ips {
                    for ip in ips {
                        add_ip_rule(&mut ip_builder, ip, target_tag)?;
                    }
                }
            }
        }

        let mut router =
            Router::new_with_tries(self.domain_strategy.clone(), domain_builder.build(), ip_builder.build())
                .with_dns(dns);

        if let Some(fallback) = &self.fallback {
            router.set_fallback(fallback.tags.clone());
        }

        if let Some(rules) = &self.rules {
            for rule in rules {
                if let Some(t) = &rule.inbound_tag {
                    router.add_inbound_rule(t, &rule.outbound_tag);
                }
            }
        }

        Ok(router)
    }

    pub fn forward_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.forward_idle_timeout.unwrap_or(DEFAULT_FORWARD_IDLE_TIMEOUT_SECS))
    }
}

fn add_domain_rule(
    builder: &mut DomainTrieBuilder,
    dns_groups_by_name: &HashMap<&str, &DnsGroup>,
    domain: &str,
    outbound_tag: &str,
) -> io::Result<()> {
    let domain = domain.trim();

    if let Some(group_name) = domain.strip_prefix("dns:") {
        let group = dns_groups_by_name.get(group_name).copied().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("dns group '{}' not found", group_name))
        })?;
        add_dns_group_rule(builder, group, outbound_tag)?;
    } else if let Some(file_path) = domain.strip_prefix("file:") {
        add_domain_rules_from_file(builder, file_path, outbound_tag)?;
    } else {
        add_domain_rule_entry(builder, domain, outbound_tag);
    }

    Ok(())
}

fn add_domain_rule_entry(builder: &mut DomainTrieBuilder, domain: &str, outbound_tag: &str) {
    let domain = domain.trim();
    builder.insert(domain, outbound_tag);
}

fn add_ip_rule(builder: &mut IpTrieBuilder, ip_rule: &str, outbound_tag: &str) -> io::Result<()> {
    let ip_rule = ip_rule.trim();

    if let Some(file_path) = ip_rule.strip_prefix("file:") {
        add_ip_rules_from_file(builder, file_path, outbound_tag)?;
    } else if let Some(cidr) = parse_ip_rule(ip_rule) {
        builder.insert(cidr, outbound_tag);
    }

    Ok(())
}

fn parse_ip_rule(ip_rule: &str) -> Option<IpNet> {
    if let Ok(cidr) = ip_rule.parse::<IpNet>() {
        return Some(cidr);
    }

    let ip = ip_rule.parse::<IpAddr>().ok()?;
    Some(IpNet::from(ip))
}

fn add_ip_rules_from_file(builder: &mut IpTrieBuilder, file_path: &str, outbound_tag: &str) -> io::Result<()> {
    for (line_no, line) in read_rule_lines(file_path)?.into_iter().enumerate() {
        let cidr = parse_ip_rule(&line).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid ip rule in file '{}', line {}: {}", file_path, line_no + 1, line),
            )
        })?;
        builder.insert(cidr, outbound_tag);
    }

    Ok(())
}

fn add_domain_rules_from_file(builder: &mut DomainTrieBuilder, file_path: &str, outbound_tag: &str) -> io::Result<()> {
    for line in read_rule_lines(file_path)? {
        add_domain_rule_entry(builder, &line, outbound_tag);
    }

    Ok(())
}

fn add_dns_group_rule(builder: &mut DomainTrieBuilder, group: &DnsGroup, outbound_tag: &str) -> io::Result<()> {
    for file_path in &group.files {
        add_domain_rules_from_file(builder, file_path, outbound_tag)?;
    }

    for domain in &group.inline {
        let domain = domain.trim();
        if domain.is_empty() {
            continue;
        }
        add_domain_rule_entry(builder, domain, outbound_tag);
    }

    Ok(())
}

fn read_rule_lines(file_path: &str) -> io::Result<Vec<String>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let reader = BufReader::new(File::open(file_path)?);
    let mut lines = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        lines.push(line.to_owned());
    }

    Ok(lines)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum Strategy {
    #[default]
    #[serde(rename = "AsIs")]
    AsIs,
    #[serde(rename = "IPIfNonMatch")]
    IPIfNonMatch,
    #[serde(rename = "IPOnDemand")]
    IPOnDemand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Rule {
    #[serde(rename = "domain", alias = "domains")]
    domain: Option<Vec<String>>,

    #[serde(rename = "ip", alias = "ips")]
    ips: Option<Vec<String>>,

    #[serde(rename = "inboundTag")]
    inbound_tag: Option<String>,

    #[serde(rename = "outboundTag")]
    outbound_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fallback {
    #[serde(rename = "tags")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSettings {
    #[serde(rename = "disableCache", default)]
    pub disable_cache: bool,

    #[serde(rename = "hosts", default)]
    pub hosts: Vec<String>,

    #[serde(rename = "servers", default)]
    pub servers: Vec<String>,

    #[serde(rename = "groups", default)]
    pub groups: Vec<DnsGroup>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            disable_cache: true,
            hosts: vec![],
            servers: vec![],
            groups: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsGroup {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "files", default)]
    pub files: Vec<String>,

    #[serde(rename = "inline", default)]
    pub inline: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_idle_timeout_can_be_configured() {
        let settings: RoutingSettings = serde_json::from_str(
            r#"{
                "domainStrategy": "AsIs",
                "forwardIdleTimeout": 15
            }"#,
        )
        .unwrap();

        assert_eq!(settings.forward_idle_timeout(), std::time::Duration::from_secs(15));
    }
}
