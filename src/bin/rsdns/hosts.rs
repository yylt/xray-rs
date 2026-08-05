#![allow(deprecated)]

use std::collections::HashMap;
use std::net::IpAddr;
use xray_rs::common::trie::{DomainMarisa, DomainMarisaBuilder};

pub struct HostsTrie {
    trie: DomainMarisa,
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
    builder: DomainMarisaBuilder,
    ips: Vec<Vec<IpAddr>>,
    domain_to_idx: HashMap<String, usize>,
}

impl HostsTrieBuilder {
    pub fn new() -> Self {
        Self {
            builder: DomainMarisaBuilder::new(),
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
            trie: self.builder.build(),
            ips: self.ips,
        }
    }
}

impl Default for HostsTrieBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_hosts_trie_exact() {
        let mut builder = HostsTrieBuilder::new();
        builder.insert("localhost", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let trie = builder.build();

        let result = trie.lookup("localhost");
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0], IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_hosts_trie_wildcard() {
        let mut builder = HostsTrieBuilder::new();
        builder.insert("*.ad-domain.com", IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        let trie = builder.build();

        assert!(trie.lookup("foo.ad-domain.com").is_some());
        assert!(trie.lookup("bar.ad-domain.com").is_some());
        assert!(trie.lookup("ad-domain.com").is_some());
    }

    #[test]
    fn test_hosts_trie_miss() {
        let mut builder = HostsTrieBuilder::new();
        builder.insert("localhost", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let trie = builder.build();

        assert!(trie.lookup("other.com").is_none());
    }

    #[test]
    fn test_hosts_trie_multiple_ips() {
        let mut builder = HostsTrieBuilder::new();
        builder.insert("localhost", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        builder.insert("localhost", IpAddr::V6(Ipv6Addr::LOCALHOST));
        let trie = builder.build();

        let result = trie.lookup("localhost").unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(result.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
