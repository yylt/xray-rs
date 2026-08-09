use xray_rs::common::domain_trie::DomainSuffixTrie;

#[derive(Debug, Clone)]
pub enum RuleAction {
    Block {
        response: BlockResponse,
    },
    Cname {
        target: String,
        ttl: u32,
    },
    Forward {
        upstream: String,
        cache: bool,
        ttl: Option<u32>,
        deny_qtypes: Vec<u16>,
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
    pub qtype: Option<u16>,
    pub action: RuleAction,
}

impl Rule {
    pub fn matches(&self, domain: &str, qtype: u16, groups_trie: &DomainSuffixTrie) -> bool {
        if let Some(expected_qtype) = self.qtype {
            if expected_qtype != 0 && expected_qtype != qtype {
                return false;
            }
        }

        let domain = domain.trim_end_matches('.');

        if self.group == "*" {
            return true;
        }

        groups_trie
            .lookup(domain)
            .map(|tag| tag == self.group.as_str())
            .unwrap_or(false)
    }
}
