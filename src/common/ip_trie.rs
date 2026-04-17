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

pub struct IpTrie {
    nodes: Vec<IpNode>,
    v4_root: NodeIndex,
    v6_root: NodeIndex,
    tags: Box<[Box<str>]>,
}

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
