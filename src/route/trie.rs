use ahash::AHashMap;
use ipnet::IpNet;
use std::net::IpAddr;

type TagId = u32;

#[derive(Default, Debug)]
struct TagPoolBuilder {
    ids: AHashMap<Box<str>, TagId>,
    values: Vec<Box<str>>,
}

impl TagPoolBuilder {
    fn new() -> Self {
        Self::default()
    }

    fn intern(&mut self, value: &str) -> TagId {
        if let Some(&id) = self.ids.get(value) {
            return id;
        }

        let id = self.values.len() as TagId;
        let boxed: Box<str> = value.into();
        self.ids.insert(boxed.clone(), id);
        self.values.push(boxed);
        id
    }

    fn finish(self) -> Vec<Box<str>> {
        self.values
    }
}

#[derive(Default)]
pub struct DomainTrieBuilder {
    buckets: AHashMap<Box<str>, AHashMap<Box<str>, TagId>>,
    tags: TagPoolBuilder,
}

impl DomainTrieBuilder {
    pub fn new() -> Self {
        Self {
            buckets: AHashMap::new(),
            tags: TagPoolBuilder::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, tag: &str) {
        let Some(normalized) = normalize_domain(domain) else {
            return;
        };

        let Some(bucket_key) = last_label(&normalized) else {
            return;
        };

        let reversed = reverse_domain(&normalized);
        let tag_id = self.tags.intern(tag);

        self.buckets
            .entry(bucket_key.into())
            .or_default()
            .insert(reversed.into_boxed_str(), tag_id);
    }

    pub fn build(self) -> DomainTrie {
        let mut buckets = AHashMap::with_capacity(self.buckets.len());

        for (bucket, rules) in self.buckets {
            let mut rules: Vec<_> = rules
                .into_iter()
                .map(|(reversed, tag)| DomainRule { reversed, tag })
                .collect();

            rules.sort_unstable_by(|left, right| {
                right
                    .reversed
                    .len()
                    .cmp(&left.reversed.len())
                    .then_with(|| left.reversed.cmp(&right.reversed))
            });

            buckets.insert(bucket, rules);
        }

        DomainTrie {
            buckets,
            tags: self.tags.finish(),
        }
    }
}

#[derive(Debug)]
pub struct DomainTrie {
    buckets: AHashMap<Box<str>, Vec<DomainRule>>,
    tags: Vec<Box<str>>,
}

#[derive(Debug)]
struct DomainRule {
    reversed: Box<str>,
    tag: TagId,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self {
            buckets: AHashMap::new(),
            tags: Vec::new(),
        }
    }

    pub fn lookup(&self, domain: &str) -> Option<&str> {
        let normalized = normalize_domain(domain)?;
        let bucket_key = last_label(&normalized)?;
        let reversed = reverse_domain(&normalized);
        let rules = self.buckets.get(bucket_key)?;

        for rule in rules {
            if reversed == rule.reversed.as_ref()
                || (reversed.starts_with(rule.reversed.as_ref())
                    && reversed.as_bytes().get(rule.reversed.len()) == Some(&b'.'))
            {
                return Some(self.tag(rule.tag));
            }
        }

        None
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    fn tag(&self, id: TagId) -> &str {
        self.tags[id as usize].as_ref()
    }
}

#[derive(Debug)]
pub struct IpTrieBuilder {
    v4: Vec<AHashMap<u32, TagId>>,
    v6: Vec<AHashMap<u128, TagId>>,
    active_v4_prefixes: Vec<u8>,
    active_v6_prefixes: Vec<u8>,
    tags: TagPoolBuilder,
}

impl IpTrieBuilder {
    pub fn new() -> Self {
        Self {
            v4: empty_v4_prefix_maps(),
            v6: empty_v6_prefix_maps(),
            active_v4_prefixes: Vec::new(),
            active_v6_prefixes: Vec::new(),
            tags: TagPoolBuilder::new(),
        }
    }

    pub fn insert(&mut self, cidr: IpNet, tag: &str) {
        let tag_id = self.tags.intern(tag);

        match cidr {
            IpNet::V4(net) => {
                let prefix_len = net.prefix_len() as usize;
                let network = u32::from(net.network());
                let table = &mut self.v4[prefix_len];
                let was_empty = table.is_empty();
                table.insert(network, tag_id);
                if was_empty {
                    self.active_v4_prefixes.push(prefix_len as u8);
                }
            }
            IpNet::V6(net) => {
                let prefix_len = net.prefix_len() as usize;
                let network = u128::from(net.network());
                let table = &mut self.v6[prefix_len];
                let was_empty = table.is_empty();
                table.insert(network, tag_id);
                if was_empty {
                    self.active_v6_prefixes.push(prefix_len as u8);
                }
            }
        }
    }

    pub fn build(mut self) -> IpTrie {
        self.active_v4_prefixes.sort_unstable_by(|left, right| right.cmp(left));
        self.active_v6_prefixes.sort_unstable_by(|left, right| right.cmp(left));

        let v4_prefixes_desc = self
            .active_v4_prefixes
            .into_iter()
            .map(|prefix_len| Ipv4PrefixMap {
                prefix_len,
                networks: std::mem::take(&mut self.v4[prefix_len as usize]),
            })
            .collect();
        let v6_prefixes_desc = self
            .active_v6_prefixes
            .into_iter()
            .map(|prefix_len| Ipv6PrefixMap {
                prefix_len,
                networks: std::mem::take(&mut self.v6[prefix_len as usize]),
            })
            .collect();

        IpTrie {
            v4: Ipv4PrefixTable {
                prefixes_desc: v4_prefixes_desc,
            },
            v6: Ipv6PrefixTable {
                prefixes_desc: v6_prefixes_desc,
            },
            tags: self.tags.finish(),
        }
    }
}

#[derive(Debug)]
pub struct IpTrie {
    v4: Ipv4PrefixTable,
    v6: Ipv6PrefixTable,
    tags: Vec<Box<str>>,
}

#[derive(Debug)]
struct Ipv4PrefixTable {
    prefixes_desc: Vec<Ipv4PrefixMap>,
}

#[derive(Debug)]
struct Ipv6PrefixTable {
    prefixes_desc: Vec<Ipv6PrefixMap>,
}

#[derive(Debug)]
struct Ipv4PrefixMap {
    prefix_len: u8,
    networks: AHashMap<u32, TagId>,
}

#[derive(Debug)]
struct Ipv6PrefixMap {
    prefix_len: u8,
    networks: AHashMap<u128, TagId>,
}

impl IpTrie {
    pub fn new() -> Self {
        Self {
            v4: Ipv4PrefixTable {
                prefixes_desc: Vec::new(),
            },
            v6: Ipv6PrefixTable {
                prefixes_desc: Vec::new(),
            },
            tags: Vec::new(),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                for prefix in &self.v4.prefixes_desc {
                    let network = normalize_v4(bits, prefix.prefix_len);
                    if let Some(&tag) = prefix.networks.get(&network) {
                        return Some(self.tag(tag));
                    }
                }
                None
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                for prefix in &self.v6.prefixes_desc {
                    let network = normalize_v6(bits, prefix.prefix_len);
                    if let Some(&tag) = prefix.networks.get(&network) {
                        return Some(self.tag(tag));
                    }
                }
                None
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.prefixes_desc.is_empty() && self.v6.prefixes_desc.is_empty()
    }

    fn tag(&self, id: TagId) -> &str {
        self.tags[id as usize].as_ref()
    }
}

fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_matches('.');
    if domain.is_empty() {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

fn last_label(domain: &str) -> Option<&str> {
    if domain.is_empty() {
        return None;
    }
    match domain.rsplit_once('.') {
        Some((_, last)) => Some(last),
        None => Some(domain),
    }
}

fn reverse_domain(domain: &str) -> String {
    let mut out = String::with_capacity(domain.len());
    for (i, label) in domain.rsplit('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(label);
    }
    out
}

fn empty_v4_prefix_maps() -> Vec<AHashMap<u32, TagId>> {
    (0..=32).map(|_| AHashMap::new()).collect()
}

fn empty_v6_prefix_maps() -> Vec<AHashMap<u128, TagId>> {
    (0..=128).map(|_| AHashMap::new()).collect()
}

fn normalize_v4(bits: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - prefix_len))
    }
}

fn normalize_v6(bits: u128, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - prefix_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_domain_trie(rules: &[(&str, &str)]) -> DomainTrie {
        let mut builder = DomainTrieBuilder::new();
        for (domain, tag) in rules {
            builder.insert(domain, tag);
        }
        builder.build()
    }

    fn build_ip_trie(rules: &[(&str, &str)]) -> IpTrie {
        let mut builder = IpTrieBuilder::new();
        for (cidr, tag) in rules {
            builder.insert(cidr.parse().unwrap(), tag);
        }
        builder.build()
    }

    #[test]
    fn test_domain_trie_suffix_match() {
        let trie = build_domain_trie(&[("google.com", "proxy")]);
        assert_eq!(trie.lookup("www.google.com"), Some("proxy"));
        assert_eq!(trie.lookup("google.com"), Some("proxy"));
        assert_eq!(trie.lookup("notgoogle.com"), None);
    }

    #[test]
    fn test_domain_trie_full_prefix_is_suffix_rule() {
        let trie = build_domain_trie(&[("foo.com", "direct")]);
        assert_eq!(trie.lookup("foo.com"), Some("direct"));
        assert_eq!(trie.lookup("sub.foo.com"), Some("direct"));
    }

    #[test]
    fn test_domain_trie_longest_match() {
        let trie = build_domain_trie(&[("com", "proxy"), ("cn.com", "direct")]);
        assert_eq!(trie.lookup("foo.cn.com"), Some("direct"));
        assert_eq!(trie.lookup("foo.us.com"), Some("proxy"));
    }

    #[test]
    fn test_ip_trie_cidr_match() {
        use std::net::IpAddr;

        let trie = build_ip_trie(&[("192.168.0.0/16", "direct")]);
        assert_eq!(trie.lookup("192.168.1.1".parse::<IpAddr>().unwrap()), Some("direct"));
        assert_eq!(trie.lookup("10.0.0.1".parse::<IpAddr>().unwrap()), None);
    }

    #[test]
    fn test_ip_trie_longest_prefix() {
        use std::net::IpAddr;

        let trie = build_ip_trie(&[("10.0.0.0/8", "proxy"), ("10.10.0.0/16", "direct")]);
        assert_eq!(trie.lookup("10.10.1.1".parse::<IpAddr>().unwrap()), Some("direct"));
        assert_eq!(trie.lookup("10.20.1.1".parse::<IpAddr>().unwrap()), Some("proxy"));
    }
}
