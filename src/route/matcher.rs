// src/route/matcher.rs
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;

/// 域名匹配器
#[derive(Debug, Clone)]
pub enum DomainMatcher {
    Exact(String),
    Suffix(String),
}

impl DomainMatcher {
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            DomainMatcher::Exact(d) => domain.eq_ignore_ascii_case(d),
            DomainMatcher::Suffix(s) => {
                domain.eq_ignore_ascii_case(s) || domain.to_lowercase().ends_with(&format!(".{}", s.to_lowercase()))
            }
        }
    }
}

/// DNS 记录类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    PTR,
    SRV,
    Other(u16),
}

impl From<u16> for RecordType {
    fn from(v: u16) -> Self {
        match v {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            5 => RecordType::CNAME,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            2 => RecordType::NS,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            33 => RecordType::SRV,
            other => RecordType::Other(other),
        }
    }
}

/// 域名分组（加载自文件或内联）
#[derive(Debug, Clone, Default)]
pub struct DomainSet {
    exact: HashSet<String>,
    suffixes: Vec<String>,
}

impl DomainSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_exact(&mut self, domain: String) {
        self.exact.insert(domain.to_lowercase());
    }

    pub fn add_suffix(&mut self, suffix: String) {
        self.suffixes.push(suffix.to_lowercase());
    }

    pub fn exacts(&self) -> impl Iterator<Item = &str> {
        self.exact.iter().map(String::as_str)
    }

    pub fn suffixes(&self) -> impl Iterator<Item = &str> {
        self.suffixes.iter().map(String::as_str)
    }

    pub fn contains(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        if self.exact.contains(&lower) {
            return true;
        }
        for s in &self.suffixes {
            if lower == *s || lower.ends_with(&format!(".{}", s)) {
                return true;
            }
        }
        false
    }

    /// 从文件加载，每行一个域名，# 开头为注释
    pub fn load_file(path: &std::path::Path) -> std::io::Result<Self> {
        use std::io::{BufRead, BufReader};
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut set = Self::new();
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            set.add_suffix(line.to_string());
        }
        Ok(set)
    }

    /// 返回所有域名的迭代器（exact 和 suffixes）
    pub fn iter(&self) -> impl Iterator<Item = String> + '_ {
        self.exact.iter().cloned().chain(self.suffixes.iter().cloned())
    }

    /// 合并另一个 DomainSet 到当前集合
    pub fn merge(&mut self, other: DomainSet) {
        self.exact.extend(other.exact);
        self.suffixes.extend(other.suffixes);
    }
}

/// 匹配器枚举
#[derive(Debug, Clone)]
pub enum Matcher {
    Domain(Vec<DomainMatcher>),
    Group(Vec<String>),
    Qtype(Vec<RecordType>),
    ClientIp(Vec<IpNet>),
}

impl Matcher {
    /// 检查是否匹配（需要 groups 上下文用于 Group 匹配）
    pub fn matches(
        &self,
        domain: &str,
        qtype: RecordType,
        client_ip: IpAddr,
        groups: &std::collections::HashMap<String, DomainSet, ahash::RandomState>,
    ) -> bool {
        match self {
            Matcher::Domain(matchers) => matchers.iter().any(|m| m.matches(domain)),
            Matcher::Group(names) => names
                .iter()
                .any(|name| groups.get(name).map(|set| set.contains(domain)).unwrap_or(false)),
            Matcher::Qtype(types) => types.contains(&qtype),
            Matcher::ClientIp(nets) => nets.iter().any(|net| net.contains(&client_ip)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matcher_exact() {
        let m = DomainMatcher::Exact("example.com".into());
        assert!(m.matches("example.com"));
        assert!(m.matches("EXAMPLE.COM"));
        assert!(!m.matches("sub.example.com"));
    }

    #[test]
    fn test_domain_matcher_suffix() {
        let m = DomainMatcher::Suffix("example.com".into());
        assert!(m.matches("example.com"));
        assert!(m.matches("sub.example.com"));
        assert!(m.matches("a.b.example.com"));
        assert!(!m.matches("notexample.com"));
    }

    #[test]
    fn test_domain_set() {
        let mut set = DomainSet::new();
        set.add_exact("foo.com".into());
        set.add_suffix("bar.com".into());
        assert!(set.contains("foo.com"));
        assert!(!set.contains("sub.foo.com"));
        assert!(set.contains("bar.com"));
        assert!(set.contains("sub.bar.com"));
    }

    #[test]
    fn test_domain_set_iter() {
        let mut set = DomainSet::new();
        set.add_exact("foo.com".into());
        set.add_exact("bar.com".into());
        set.add_suffix("example.com".into());

        let domains: Vec<String> = set.iter().collect();
        assert_eq!(domains.len(), 3);
        assert!(domains.contains(&"foo.com".to_string()));
        assert!(domains.contains(&"bar.com".to_string()));
        assert!(domains.contains(&"example.com".to_string()));
    }

    #[test]
    fn test_domain_set_merge() {
        let mut set1 = DomainSet::new();
        set1.add_exact("foo.com".into());
        set1.add_suffix("bar.com".into());

        let mut set2 = DomainSet::new();
        set2.add_exact("baz.com".into());
        set2.add_suffix("qux.com".into());

        set1.merge(set2);

        assert!(set1.contains("foo.com"));
        assert!(set1.contains("bar.com"));
        assert!(set1.contains("baz.com"));
        assert!(set1.contains("qux.com"));
        assert!(set1.contains("sub.bar.com"));
        assert!(set1.contains("sub.qux.com"));
    }
}
