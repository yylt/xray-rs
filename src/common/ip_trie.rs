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

    fn finish(self) -> Box<[Box<str>]> {
        self.values.into_boxed_slice()
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

impl Default for IpTrieBuilder {
    fn default() -> Self {
        Self::new()
    }
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

        for i in &self.active_v4_prefixes {
            self.v4[*i as usize].shrink_to_fit();
        }
        for i in &self.active_v6_prefixes {
            self.v6[*i as usize].shrink_to_fit();
        }

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
    tags: Box<[Box<str>]>,
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

impl Default for IpTrie {
    fn default() -> Self {
        Self::new()
    }
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
            tags: Box::new([]),
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_empty_trie_lookup_miss() {
        let builder = IpTrieBuilder::new();
        let trie = builder.build();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(trie.lookup(ip).is_none(), "empty trie lookup should miss");
    }

    #[test]
    fn test_lookup_match() {
        let mut builder = IpTrieBuilder::new();
        let cidr = "192.168.0.0/16".parse::<IpNet>().unwrap();
        builder.insert(cidr, "local_network");
        let trie = builder.build();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(trie.lookup(ip), Some("local_network"));

        let network_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(trie.lookup(network_ip), Some("local_network"));

        let broadcast_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255));
        assert_eq!(trie.lookup(broadcast_ip), Some("local_network"));
    }

    #[test]
    fn test_lookup_mismatch() {
        let mut builder = IpTrieBuilder::new();
        let cidr = "192.168.0.0/16".parse::<IpNet>().unwrap();
        builder.insert(cidr, "local_network");
        let trie = builder.build();

        let ip_other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(trie.lookup(ip_other).is_none());

        let ip_another = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        assert!(trie.lookup(ip_another).is_none());

        let before_network = IpAddr::V4(Ipv4Addr::new(192, 167, 255, 255));
        assert!(trie.lookup(before_network).is_none());

        let after_network = IpAddr::V4(Ipv4Addr::new(192, 169, 0, 0));
        assert!(trie.lookup(after_network).is_none());
    }

    #[test]
    fn test_ipv6_empty_trie_lookup_miss() {
        let builder = IpTrieBuilder::new();
        let trie = builder.build();

        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(trie.lookup(ip).is_none());
    }

    #[test]
    fn test_ipv6_lookup_match() {
        let mut builder = IpTrieBuilder::new();
        let cidr = "2001:db8::/32".parse::<IpNet>().unwrap();
        builder.insert(cidr, "ipv6_network");
        let trie = builder.build();

        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        assert_eq!(trie.lookup(ip), Some("ipv6_network"));

        let network_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        assert_eq!(trie.lookup(network_ip), Some("ipv6_network"));

        let another_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0xffff, 0, 0, 0, 0xffff));
        assert_eq!(trie.lookup(another_ip), Some("ipv6_network"));
    }

    #[test]
    fn test_ipv6_lookup_mismatch() {
        let mut builder = IpTrieBuilder::new();
        let cidr = "2001:db8::/32".parse::<IpNet>().unwrap();
        builder.insert(cidr, "ipv6_network");
        let trie = builder.build();

        let other_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1));
        assert!(trie.lookup(other_ip).is_none());

        let another_ip = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1));
        assert!(trie.lookup(another_ip).is_none());

        let after_network = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0));
        assert!(trie.lookup(after_network).is_none());
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut builder = IpTrieBuilder::new();
        builder.insert("10.0.0.0/8".parse().unwrap(), "broad");
        builder.insert("10.1.0.0/16".parse().unwrap(), "narrow");
        let trie = builder.build();

        assert_eq!(trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))), Some("narrow"));
        assert_eq!(trie.lookup(IpAddr::V4(Ipv4Addr::new(10, 2, 2, 3))), Some("broad"));
    }
}
