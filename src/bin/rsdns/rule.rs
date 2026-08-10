use hickory_proto::rr::RecordType;
use xray_rs::common::domain_trie::DomainSuffixTrie;

#[derive(Debug, Clone)]
pub enum RuleAction {
    Block {
        response: BlockResponse,
    },
    Cname {
        target: String,
        ttl: u32,
        upstream: String,
        deny_qtypes: Vec<RecordType>,
    },
    Forward {
        upstream: String,
        cache: bool,
        ttl: Option<u32>,
        deny_qtypes: Vec<RecordType>,
    },
}

#[derive(Debug, Clone)]
pub enum BlockResponse {
    NXDomain,
    Poison,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub group: String,
    pub qtype: Option<RecordType>,
    pub action: RuleAction,
}

impl Rule {
    pub fn matches(&self, domain: &str, qtype: RecordType, groups_trie: &DomainSuffixTrie) -> bool {
        if let Some(expected_qtype) = self.qtype {
            // ANY matches all query types, same as None
            if expected_qtype != RecordType::ANY && expected_qtype != qtype {
                return false;
            }
        }
        let domain = domain.trim_end_matches('.');
        self.group == "*" || groups_trie.lookup(domain).is_some_and(|tag| tag == self.group.as_str())
    }
}
