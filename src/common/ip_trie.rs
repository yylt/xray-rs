use ahash::AHashMap;
use ipnet::IpNet;
use std::net::IpAddr;

type TagId = u32;
type NodeIndex = u32;
const EMPTY_NODE: NodeIndex = 0; // 0 作为空节点的占位符

#[derive(Debug, Clone, Copy)]
struct IpNode {
    children: [NodeIndex; 2],
    tag_id: u32,
}

impl IpNode {
    fn new() -> Self {
        Self {
            children: [EMPTY_NODE; 2],
            tag_id: u32::MAX,
        }
    }
}
#[derive(Debug)]
pub struct IpTrie {
    nodes: Vec<IpNode>,
    v4_root: NodeIndex,
    v6_root: NodeIndex,
    tags: Box<[Box<str>]>,
}
#[derive(Debug)]
pub struct IpTrieBuilder {
    nodes: Vec<IpNode>,
    v4_root: NodeIndex,
    v6_root: NodeIndex,
    tag_to_id: AHashMap<Box<str>, TagId>,
    id_to_tag: Vec<Box<str>>,
}

impl IpTrieBuilder {
    pub fn new() -> Self {
        let mut nodes = Vec::with_capacity(256);
        nodes.push(IpNode::new());

        Self {
            nodes,
            v4_root: EMPTY_NODE,
            v6_root: EMPTY_NODE,
            tag_to_id: AHashMap::new(),
            id_to_tag: Vec::new(),
        }
    }

    pub fn insert(&mut self, cidr: IpNet, tag: &str) {
        let tag_id = *self.tag_to_id.entry(tag.into()).or_insert_with(|| {
            let id = self.id_to_tag.len() as u32;
            self.id_to_tag.push(tag.into());
            id
        });

        match cidr {
            IpNet::V4(net) => {
                self.v4_root = Self::insert_bitwise(
                    &mut self.nodes,
                    self.v4_root,
                    u32::from(net.network()) as u128,
                    net.prefix_len(),
                    32,
                    tag_id,
                );
            }
            IpNet::V6(net) => {
                self.v6_root = Self::insert_bitwise(
                    &mut self.nodes,
                    self.v6_root,
                    u128::from(net.network()),
                    net.prefix_len(),
                    128,
                    tag_id,
                );
            }
        }
    }

    fn insert_bitwise(
        nodes: &mut Vec<IpNode>,
        mut curr_root: NodeIndex,
        val: u128,
        prefix_len: u8,
        max_bits: u8,
        tag_id: u32,
    ) -> NodeIndex {
        // 如果根节点尚未创建，先创建一个
        if curr_root == EMPTY_NODE {
            curr_root = nodes.len() as NodeIndex;
            nodes.push(IpNode::new());
        }

        let mut curr_idx = curr_root;

        for i in 0..prefix_len {
            let bit = ((val >> (max_bits - 1 - i)) & 1) as usize;

            let next_idx = nodes[curr_idx as usize].children[bit];

            if next_idx == EMPTY_NODE {
                let new_node_idx = nodes.len() as NodeIndex;
                nodes.push(IpNode::new());
                nodes[curr_idx as usize].children[bit] = new_node_idx;
                curr_idx = new_node_idx;
            } else {
                curr_idx = next_idx;
            }
        }

        nodes[curr_idx as usize].tag_id = tag_id;

        curr_root
    }

    pub fn build(self) -> IpTrie {
        IpTrie {
            nodes: self.nodes,
            v4_root: self.v4_root,
            v6_root: self.v6_root,
            tags: self.id_to_tag.into_boxed_slice(),
        }
    }
}

impl IpTrie {
    pub fn new() -> Self {
        Self {
            nodes: vec![IpNode::new()],
            v4_root: EMPTY_NODE,
            v6_root: EMPTY_NODE,
            tags: Box::new([]),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V4(v4) => self.lookup_bitwise(self.v4_root, u32::from(v4), 32),
            IpAddr::V6(v6) => self.lookup_bitwise(self.v6_root, u128::from(v6), 128),
        }
    }

    fn lookup_bitwise<T: Into<u128>>(&self, root: NodeIndex, bits: T, max_bits: u8) -> Option<&str> {
        if root == EMPTY_NODE {
            return None;
        }

        let val: u128 = bits.into();
        let mut curr = root;
        let mut last_found_tag = None;

        for i in 0..max_bits {
            let node = &self.nodes[curr as usize];

            if node.tag_id != u32::MAX {
                last_found_tag = Some(node.tag_id);
            }

            let bit = ((val >> (max_bits - 1 - i)) & 1) as usize;
            let next = node.children[bit];

            if next == EMPTY_NODE {
                break;
            }
            curr = next;
        }

        // 循环结束后检查最后一个匹配节点
        let final_node = &self.nodes[curr as usize];
        if final_node.tag_id != u32::MAX {
            last_found_tag = Some(final_node.tag_id);
        }

        last_found_tag.map(|id| self.tags[id as usize].as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_empty_trie_lookup_miss() {
        // 空初始化测试：创建空的 trie，查询应返回 None
        let builder = IpTrieBuilder::new();
        let trie = builder.build();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(trie.lookup(ip).is_none(), "空 trie 查询应返回 None");
    }

    #[test]
    fn test_lookup_match() {
        // 匹配测试：插入 CIDR 规则后，查询该网段内 IP 应命中
        let mut builder = IpTrieBuilder::new();
        let cidr = "192.168.0.0/16".parse::<IpNet>().unwrap();
        builder.insert(cidr, "local_network");
        let trie = builder.build();

        // 命中：同网段 IP
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(trie.lookup(ip), Some("local_network"), "同网段 IP 应命中");

        // 边界：网络地址本身
        let network_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(trie.lookup(network_ip), Some("local_network"));

        // 边界：广播地址（192.168.255.255）
        let broadcast_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255));
        assert_eq!(trie.lookup(broadcast_ip), Some("local_network"));
    }

    #[test]
    fn test_lookup_mismatch() {
        // 不匹配测试：插入规则后，查询其他网段 IP 应未命中
        let mut builder = IpTrieBuilder::new();
        let cidr = "192.168.0.0/16".parse::<IpNet>().unwrap();
        builder.insert(cidr, "local_network");
        let trie = builder.build();

        // 未命中：不同网段 IP（10.x.x.x）
        let ip_other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(trie.lookup(ip_other).is_none(), "不同网段 IP 应未命中");

        // 未命中：另一不同网段（172.x.x.x）
        let ip_another = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        assert!(trie.lookup(ip_another).is_none());

        // 边界：刚好在网段前一个地址
        let before_network = IpAddr::V4(Ipv4Addr::new(192, 167, 255, 255));
        assert!(trie.lookup(before_network).is_none());

        // 边界：刚好在网段后一个地址
        let after_network = IpAddr::V4(Ipv4Addr::new(192, 169, 0, 0));
        assert!(trie.lookup(after_network).is_none());
    }

    #[test]
    fn test_ipv6_empty_trie_lookup_miss() {
        // IPv6 空初始化测试
        let builder = IpTrieBuilder::new();
        let trie = builder.build();

        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(trie.lookup(ip).is_none(), "IPv6 空 trie 查询应返回 None");
    }

    #[test]
    fn test_ipv6_lookup_match() {
        // IPv6 匹配测试
        let mut builder = IpTrieBuilder::new();
        let cidr = "2001:db8::/32".parse::<IpNet>().unwrap();
        builder.insert(cidr, "ipv6_network");
        let trie = builder.build();

        // 命中：同网段 IPv6
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        assert_eq!(trie.lookup(ip), Some("ipv6_network"), "IPv6 同网段应命中");

        // 命中：网络地址本身
        let network_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        assert_eq!(trie.lookup(network_ip), Some("ipv6_network"));

        // 命中：网段内其他地址
        let another_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0xffff, 0, 0, 0, 0xffff));
        assert_eq!(trie.lookup(another_ip), Some("ipv6_network"));
    }

    #[test]
    fn test_ipv6_lookup_mismatch() {
        // IPv6 不匹配测试
        let mut builder = IpTrieBuilder::new();
        let cidr = "2001:db8::/32".parse::<IpNet>().unwrap();
        builder.insert(cidr, "ipv6_network");
        let trie = builder.build();

        // 未命中：不同网段 IPv6
        let other_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1));
        assert!(trie.lookup(other_ip).is_none(), "IPv6 不同网段应未命中");

        // 未命中：完全不同的前缀
        let another_ip = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1));
        assert!(trie.lookup(another_ip).is_none());

        // 边界：刚好在网段后一个地址
        let after_network = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0));
        assert!(trie.lookup(after_network).is_none());
    }
}
