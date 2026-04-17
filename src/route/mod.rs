pub mod cache;
pub mod dns;
pub mod matcher;
pub mod resolver;
pub mod router;
pub mod trie;

pub use resolver::DnsResolver;
pub use router::{Router, SharedRouter};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{io, net::IpAddr, sync::Arc};

use self::trie::{DomainMarisaBuilder, IpTrieBuilder};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingSettings {
    #[serde(rename = "domainStrategy")]
    domain_strategy: Strategy,

    #[serde(rename = "rules")]
    rules: Option<Vec<Rule>>,

    #[serde(rename = "fallbackTags")]
    fallback_tags: Option<Vec<String>>,
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

impl RoutingSettings {
    pub fn build_router(&self, dns: Arc<DnsResolver>) -> io::Result<Router> {
        let mut domain_builder = DomainMarisaBuilder::new();
        let mut ip_builder = IpTrieBuilder::new();

        if let Some(rules) = &self.rules {
            for rule in rules {
                let target_tag = &rule.outbound_tag;
                let has_conditions = rule.domain.is_some() || rule.ips.is_some() || rule.inbound_tag.is_some();

                log::debug!(
                    target: "route::config",
                    "processing routing rule: domains={:?}, ips={:?}, inbound_tag={:?}, outbound_tag={:?}",
                    rule.domain,
                    rule.ips,
                    rule.inbound_tag,
                    rule.outbound_tag,
                );

                if !has_conditions {
                    log::warn!(
                        "routing rule with outbound_tag '{}' has no conditions (domain/ip/inboundTag), ignoring",
                        target_tag
                    );
                    continue;
                }

                if let Some(domains) = &rule.domain {
                    for domain in domains {
                        add_domain_rule(&mut domain_builder, domain, target_tag)?;
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

        if let Some(fallback) = &self.fallback_tags {
            router.set_fallback(fallback.clone());
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
}

fn add_domain_rule(builder: &mut DomainMarisaBuilder, domain: &str, outbound_tag: &str) -> io::Result<()> {
    let domain = domain.trim();

    if let Some(file_path) = domain.strip_prefix("file:") {
        add_domain_rules_from_file(builder, file_path, outbound_tag)?;
    } else {
        add_domain_rule_entry(builder, domain, outbound_tag);
    }

    Ok(())
}

fn add_domain_rule_entry(builder: &mut DomainMarisaBuilder, domain: &str, outbound_tag: &str) {
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

fn add_domain_rules_from_file(
    builder: &mut DomainMarisaBuilder,
    file_path: &str,
    outbound_tag: &str,
) -> io::Result<()> {
    for line in read_rule_lines(file_path)? {
        add_domain_rule_entry(builder, &line, outbound_tag);
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
