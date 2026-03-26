// src/route/dns.rs
#![allow(unused_imports)]
use ahash::RandomState;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::matcher::{DomainMatcher, DomainSet, Matcher, RecordType};

/// DNS 查询
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub name: String,
    pub qtype: RecordType,
    pub client_ip: IpAddr,
}

/// 规则动作
#[derive(Debug, Clone)]
pub enum Action {
    Forward {
        upstream: String,
        outbound_tag: Option<String>,
    },
    Block,
    Rewrite {
        ip: IpAddr,
    },
    Hosts,
}

/// Hosts 表
#[derive(Debug, Clone, Default)]
pub struct HostsTable {
    v4: HashMap<String, Vec<Ipv4Addr>, RandomState>,
    v6: HashMap<String, Vec<Ipv6Addr>, RandomState>,
}

impl HostsTable {
    pub fn new() -> Self {
        Self {
            v4: HashMap::with_hasher(RandomState::new()),
            v6: HashMap::with_hasher(RandomState::new()),
        }
    }

    pub fn add(&mut self, domain: &str, ip: IpAddr) {
        let domain = domain.to_lowercase();
        match ip {
            IpAddr::V4(v4) => self.v4.entry(domain).or_default().push(v4),
            IpAddr::V6(v6) => self.v6.entry(domain).or_default().push(v6),
        }
    }

    pub fn lookup_v4(&self, domain: &str) -> Option<&Vec<Ipv4Addr>> {
        self.v4.get(&domain.to_lowercase())
    }

    pub fn lookup_v6(&self, domain: &str) -> Option<&Vec<Ipv6Addr>> {
        self.v6.get(&domain.to_lowercase())
    }

    /// 从标准 /etc/hosts 格式文件加载
    pub fn load_file(path: &std::path::Path) -> std::io::Result<Self> {
        use std::io::{BufRead, BufReader};
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut table = Self::new();
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                for domain in &parts[1..] {
                    table.add(domain, ip);
                }
            }
        }
        Ok(table)
    }

    /// Merge another HostsTable into this one
    pub fn merge(&mut self, other: HostsTable) {
        for (domain, ips) in other.v4 {
            self.v4.entry(domain).or_default().extend(ips);
        }
        for (domain, ips) in other.v6 {
            self.v6.entry(domain).or_default().extend(ips);
        }
    }
}

/// 单条规则
#[derive(Debug, Clone)]
pub struct DnsRule {
    pub matchers: Vec<Matcher>,
    pub action: Action,
}

impl DnsRule {
    /// 检查是否匹配（所有 matcher 需全部命中，AND 语义）
    pub fn matches(&self, query: &DnsQuery, groups: &HashMap<String, DomainSet, RandomState>) -> bool {
        if self.matchers.is_empty() {
            return true; // 无 matcher 表示默认规则
        }
        self.matchers
            .iter()
            .all(|m| m.matches(&query.name, query.qtype, query.client_ip, groups))
    }
}

/// 规则引擎
#[derive(Debug)]
pub struct RuleEngine {
    rules: Vec<DnsRule>,
    groups: HashMap<String, DomainSet, RandomState>,
    hosts: HostsTable,
}

impl RuleEngine {
    pub fn new(rules: Vec<DnsRule>, groups: HashMap<String, DomainSet, RandomState>, hosts: HostsTable) -> Self {
        Self { rules, groups, hosts }
    }

    /// 评估查询，返回匹配的动作
    pub fn evaluate(&self, query: &DnsQuery) -> &Action {
        // 先检查 hosts
        let has_hosts = match query.qtype {
            RecordType::A => self.hosts.lookup_v4(&query.name).is_some(),
            RecordType::AAAA => self.hosts.lookup_v6(&query.name).is_some(),
            _ => false,
        };
        if has_hosts {
            static HOSTS_ACTION: Action = Action::Hosts;
            return &HOSTS_ACTION;
        }

        // 按顺序匹配规则
        for rule in &self.rules {
            if rule.matches(query, &self.groups) {
                return &rule.action;
            }
        }

        // 返回静态默认动作
        static DEFAULT: Action = Action::Forward {
            upstream: String::new(),
            outbound_tag: None,
        };
        &DEFAULT
    }

    pub fn hosts(&self) -> &HostsTable {
        &self.hosts
    }

    /// 获取 domain 对应的 outbound_tag（供 rsray 路由使用）
    pub fn outbound_tag(&self, domain: &str, _port: u16) -> Option<String> {
        let query = DnsQuery {
            id: 0,
            name: domain.to_string(),
            qtype: RecordType::A,
            client_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        match self.evaluate(&query) {
            Action::Forward { outbound_tag, .. } => outbound_tag.clone(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosts_table() {
        let mut hosts = HostsTable::new();
        hosts.add("localhost", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        hosts.add("localhost", IpAddr::V6(Ipv6Addr::LOCALHOST));

        assert_eq!(hosts.lookup_v4("localhost").unwrap().len(), 1);
        assert_eq!(hosts.lookup_v6("LOCALHOST").unwrap().len(), 1);
    }

    #[test]
    fn test_rule_engine_hosts_priority() {
        let mut hosts = HostsTable::new();
        hosts.add("myhost.local", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        let engine = RuleEngine::new(vec![], HashMap::with_hasher(RandomState::new()), hosts);
        let query = DnsQuery {
            id: 1,
            name: "myhost.local".into(),
            qtype: RecordType::A,
            client_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };

        assert!(matches!(engine.evaluate(&query), Action::Hosts));
    }

    #[test]
    fn test_rule_engine_rule_match() {
        let rules = vec![DnsRule {
            matchers: vec![Matcher::Domain(vec![DomainMatcher::Suffix("cn".into())])],
            action: Action::Forward {
                upstream: "cn".into(),
                outbound_tag: Some("cn-proxy".into()),
            },
        }];

        let engine = RuleEngine::new(rules, HashMap::with_hasher(RandomState::new()), HostsTable::new());
        let query = DnsQuery {
            id: 1,
            name: "baidu.cn".into(),
            qtype: RecordType::A,
            client_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };

        match engine.evaluate(&query) {
            Action::Forward { upstream, outbound_tag } => {
                assert_eq!(upstream, "cn");
                assert_eq!(outbound_tag.as_deref(), Some("cn-proxy"));
            }
            _ => panic!("expected Forward"),
        }
    }

    #[test]
    fn test_outbound_tag() {
        let rules = vec![
            DnsRule {
                matchers: vec![Matcher::Domain(vec![DomainMatcher::Suffix("blocked.com".into())])],
                action: Action::Block,
            },
            DnsRule {
                matchers: vec![Matcher::Domain(vec![DomainMatcher::Suffix("proxy.com".into())])],
                action: Action::Forward {
                    upstream: "secure".into(),
                    outbound_tag: Some("overseas".into()),
                },
            },
        ];

        let engine = RuleEngine::new(rules, HashMap::with_hasher(RandomState::new()), HostsTable::new());

        assert_eq!(engine.outbound_tag("foo.blocked.com", 443), None);
        assert_eq!(engine.outbound_tag("foo.proxy.com", 443), Some("overseas".into()));
        assert_eq!(engine.outbound_tag("unknown.com", 443), None);
    }

    #[test]
    fn test_hosts_table_merge() {
        let mut hosts1 = HostsTable::new();
        hosts1.add("host1.local", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        let mut hosts2 = HostsTable::new();
        hosts2.add("host2.local", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        hosts2.add("host1.local", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        hosts1.merge(hosts2);

        // host1.local should have both IPs
        assert_eq!(hosts1.lookup_v4("host1.local").unwrap().len(), 2);
        // host2.local should be present
        assert_eq!(hosts1.lookup_v4("host2.local").unwrap().len(), 1);
    }
}
