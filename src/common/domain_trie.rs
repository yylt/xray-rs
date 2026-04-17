use ahash::AHashMap;

pub type TagId = u32;
pub type LabelId = u32;
pub type NodeIndex = u32;

#[derive(Default)]
struct BuilderNode {
    // LabelId -> 下一个节点的索引
    children: AHashMap<LabelId, NodeIndex>,
    tag_id: Option<TagId>,
}

pub struct DomainSuffixTrie {
    nodes: Vec<BuilderNode>,
    tags: Box<[Box<str>]>,
    label_map: AHashMap<Box<str>, LabelId>,
}

pub struct DomainSuffixTrieBuilder {
    nodes: Vec<BuilderNode>,
    label_to_id: AHashMap<Box<str>, LabelId>,
    id_to_label: Vec<Box<str>>,
    tag_to_id: AHashMap<Box<str>, TagId>,
    id_to_tag: Vec<Box<str>>,
}

impl DomainSuffixTrieBuilder {
    pub fn new() -> Self {
        Self {
            nodes: vec![BuilderNode::default()],
            label_to_id: AHashMap::new(),
            id_to_label: Vec::new(),
            tag_to_id: AHashMap::new(),
            id_to_tag: Vec::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, tag: &str) {
        let tag_id = self.intern_tag(tag);
        let mut current_idx = 0;

        for label_str in domain.trim_matches('.').rsplit('.') {
            let label_id = self.intern_label(label_str);

            if let Some(&next_idx) = self.nodes[current_idx].children.get(&label_id) {
                current_idx = next_idx as usize;
            } else {
                let next_idx = self.nodes.len() as NodeIndex;
                self.nodes[current_idx].children.insert(label_id, next_idx);
                self.nodes.push(BuilderNode::default());
                current_idx = next_idx as usize;
            }
        }

        self.nodes[current_idx].tag_id = Some(tag_id);
    }

    fn intern_label(&mut self, label: &str) -> LabelId {
        if let Some(&id) = self.label_to_id.get(label) {
            return id;
        }
        let id = self.id_to_label.len() as LabelId;
        let boxed: Box<str> = label.to_lowercase().into();
        self.label_to_id.insert(boxed.clone(), id);
        self.id_to_label.push(boxed);
        id
    }

    fn intern_tag(&mut self, tag: &str) -> TagId {
        if let Some(&id) = self.tag_to_id.get(tag) {
            return id;
        }
        let id = self.id_to_tag.len() as TagId;
        let boxed: Box<str> = tag.into();
        self.tag_to_id.insert(boxed.clone(), id);
        self.id_to_tag.push(boxed);
        id
    }

    pub fn build(self) -> DomainSuffixTrie {
        DomainSuffixTrie {
            nodes: self.nodes,
            tags: self.id_to_tag.into_boxed_slice(),
            label_map: self.label_to_id,
        }
    }
}

impl DomainSuffixTrie {
    pub fn lookup(&self, domain: &str) -> Option<&str> {
        let mut current_idx = 0;
        let mut best_tag = self.nodes[0].tag_id;

        for label_str in domain.trim_matches('.').rsplit('.') {
            let label_id = match self.label_map.get(label_str) {
                Some(&id) => id,
                None => return best_tag.map(|id| self.tags[id as usize].as_ref()),
            };

            // 2. 根据 LabelId 往下走
            if let Some(&next_idx) = self.nodes[current_idx].children.get(&label_id) {
                current_idx = next_idx as usize;
                if let Some(t) = self.nodes[current_idx].tag_id {
                    best_tag = Some(t);
                }
            } else {
                break;
            }
        }

        best_tag.map(|id| self.tags[id as usize].as_ref())
    }
}
