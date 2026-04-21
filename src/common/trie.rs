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

#[derive(Default, Debug)]
struct LabelPoolBuilder {
    ids: AHashMap<Box<str>, LabelRef>,
    values: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct LabelRef {
    offset: u32,
    len: u16,
}

impl LabelPoolBuilder {
    fn intern(&mut self, value: &str) -> LabelRef {
        if let Some(&label_ref) = self.ids.get(value) {
            return label_ref;
        }

        let label_ref = LabelRef {
            offset: self.values.len() as u32,
            len: value.len() as u16,
        };
        self.values.extend_from_slice(value.as_bytes());

        let boxed: Box<str> = value.into();
        self.ids.insert(boxed, label_ref);
        label_ref
    }

    fn finish(self) -> Vec<u8> {
        self.values
    }
}

#[derive(Default, Debug)]
struct BuildNode {
    tag: Option<TagId>,
    children: AHashMap<Box<str>, BuildNode>,
}

#[derive(Default, Debug)]
pub struct DomainMarisaBuilder {
    root: BuildNode,
    tags: TagPoolBuilder,
}
#[deprecated(since = "0.1.0", note = "请使用 common::domain_trie 代替")]
impl DomainMarisaBuilder {
    pub fn new() -> Self {
        Self {
            root: BuildNode::default(),
            tags: TagPoolBuilder::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, tag: &str) {
        let Some(normalized) = normalize_domain(domain) else {
            return;
        };

        let labels: Vec<&str> = normalized.rsplit('.').collect();
        log::debug!(
            target: "route::trie",
            "insert domain rule: normalized={:?}, reversed_labels={:?}, tag={:?}",
            normalized,
            labels,
            tag,
        );

        let tag_id = self.tags.intern(tag);
        let mut node = &mut self.root;

        for label in labels {
            node = node.children.entry(label.into()).or_default();
        }

        node.tag = Some(tag_id);
    }

    pub fn build(self) -> DomainMarisa {
        let mut flattener = DomainFlattener::default();
        flattener.flatten_node(self.root);

        let trie = DomainMarisa {
            nodes: flattener.nodes,
            edges: flattener.edges,
            labels: flattener.labels.finish(),
            tags: self.tags.finish(),
        };

        log::debug!(
            target: "route::trie",
            "built domain trie: nodes={}, edges={}, tags={:?}",
            trie.nodes.len(),
            trie.edges.len(),
            trie.tags,
        );

        trie
    }
}

#[derive(Debug)]
pub struct DomainMarisa {
    nodes: Vec<DomainNode>,
    edges: Vec<DomainEdge>,
    labels: Vec<u8>,
    tags: Vec<Box<str>>,
}

#[derive(Debug)]
struct DomainNode {
    edge_start: u32,
    edge_count: u32,
    tag: Option<TagId>,
}

#[derive(Debug)]
struct DomainEdge {
    label_offset: u32,
    label_len: u16,
    child: u32,
}

#[derive(Default, Debug)]
struct DomainFlattener {
    nodes: Vec<DomainNode>,
    edges: Vec<DomainEdge>,
    labels: LabelPoolBuilder,
}

impl DomainFlattener {
    fn flatten_node(&mut self, node: BuildNode) -> u32 {
        let node_index = self.nodes.len() as u32;
        self.nodes.push(DomainNode {
            edge_start: 0,
            edge_count: 0,
            tag: node.tag,
        });

        let edge_start = self.edges.len() as u32;
        let mut children: Vec<_> = node.children.into_iter().collect();
        children.sort_unstable_by(|left, right| left.0.cmp(&right.0));

        let edge_count = children.len() as u32;
        for _ in 0..edge_count {
            self.edges.push(DomainEdge {
                label_offset: 0,
                label_len: 0,
                child: 0,
            });
        }

        for (index, (label, child)) in children.into_iter().enumerate() {
            let label_ref = self.labels.intern(label.as_ref());
            let child_index = self.flatten_node(child);
            self.edges[edge_start as usize + index] = DomainEdge {
                label_offset: label_ref.offset,
                label_len: label_ref.len,
                child: child_index,
            };
        }

        self.nodes[node_index as usize] = DomainNode {
            edge_start,
            edge_count,
            tag: node.tag,
        };
        node_index
    }
}

impl DomainMarisa {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            labels: Vec::new(),
            tags: Vec::new(),
        }
    }

    pub fn lookup(&self, domain: &str) -> Option<&str> {
        let normalized = normalize_domain(domain)?;
        let mut node_index = 0usize;
        let mut best = self.nodes.get(node_index).and_then(|node| node.tag);
        let mut traversed_labels: Vec<&str> = Vec::new();
        let mut best_match = best.map(|_| String::new());

        for label in normalized.rsplit('.') {
            let node = self.nodes.get(node_index)?;
            let Some(child_index) = self.find_child(node, label) else {
                break;
            };
            node_index = child_index as usize;
            traversed_labels.push(label);
            if let Some(tag) = self.nodes[node_index].tag {
                best = Some(tag);
                best_match = Some(traversed_labels.iter().rev().copied().collect::<Vec<_>>().join("."));
            }
        }

        let matched_tag = best.map(|tag| self.tag(tag));
        let matched_suffix = best_match.as_deref().unwrap_or("<none>");

        log::debug!(
            target: "route::trie",
            "domain lookup: input={:?}, normalized={:?}, longest_match={:?}, tag={:?}",
            domain,
            normalized,
            matched_suffix,
            matched_tag,
        );

        matched_tag
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn find_child(&self, node: &DomainNode, label: &str) -> Option<u32> {
        let start = node.edge_start as usize;
        let end = start + node.edge_count as usize;
        let edges = &self.edges[start..end];

        edges
            .binary_search_by(|edge| self.edge_label(edge).cmp(label))
            .ok()
            .map(|index| edges[index].child)
    }

    fn edge_label(&self, edge: &DomainEdge) -> &str {
        let start = edge.label_offset as usize;
        let end = start + edge.label_len as usize;
        std::str::from_utf8(&self.labels[start..end]).expect("stored domain label must be valid utf-8")
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

#[deprecated(since = "0.1.0", note = "请使用 common::domain_trie 代替")]
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
    #![allow(deprecated)]
    use super::*;
    fn build_domain_marisa(rules: &[(&str, &str)]) -> DomainMarisa {
        let mut builder = DomainMarisaBuilder::new();
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
    fn test_domain_marisa_suffix_match() {
        let trie = build_domain_marisa(&[("google.com", "proxy")]);
        assert_eq!(trie.lookup("www.google.com"), Some("proxy"));
        assert_eq!(trie.lookup("google.com"), Some("proxy"));
        assert_eq!(trie.lookup("notgoogle.com"), None);
    }

    #[test]
    fn test_domain_marisa_full_prefix_is_suffix_rule() {
        let trie = build_domain_marisa(&[("foo.com", "direct")]);
        assert_eq!(trie.lookup("foo.com"), Some("direct"));
        assert_eq!(trie.lookup("sub.foo.com"), Some("direct"));
    }

    #[test]
    fn test_domain_marisa_longest_match() {
        let trie = build_domain_marisa(&[("com", "proxy"), ("cn.com", "direct")]);
        assert_eq!(trie.lookup("foo.cn.com"), Some("direct"));
        assert_eq!(trie.lookup("foo.us.com"), Some("proxy"));
    }

    #[test]
    fn test_domain_marisa_multiple_tlds_and_nested_suffixes() {
        let trie = build_domain_marisa(&[
            ("github.com", "tj"),
            ("cloudflare.com", "tj"),
            ("mozilla.com", "tj"),
            ("example.cn", "cn"),
            ("deep.example.cn", "deep-cn"),
            ("service.io", "io"),
        ]);

        assert_eq!(trie.lookup("github.com"), Some("tj"));
        assert_eq!(trie.lookup("api.github.com"), Some("tj"));
        assert_eq!(trie.lookup("www.cloudflare.com"), Some("tj"));
        assert_eq!(trie.lookup("download.mozilla.com"), Some("tj"));
        assert_eq!(trie.lookup("foo.example.cn"), Some("cn"));
        assert_eq!(trie.lookup("a.deep.example.cn"), Some("deep-cn"));
        assert_eq!(trie.lookup("agent.service.io"), Some("io"));
        assert_eq!(trie.lookup("unknown.org"), None);
    }

    #[test]
    fn test_domain_marisa_normalizes_case_and_trailing_dot() {
        let trie = build_domain_marisa(&[("google.com", "proxy")]);
        assert_eq!(trie.lookup("WWW.Google.COM."), Some("proxy"));
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
