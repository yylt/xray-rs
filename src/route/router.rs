use ahash::RandomState;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::common::Address;
use crate::proxy::ProxyStream;
use crate::route::{
    trie::{DomainMarisa, IpTrie},
    DnsResolver, Strategy,
};

#[derive(Debug, Clone, PartialEq)]
pub struct RoutingResult {
    pub primary_tag: String,
    pub fallback_tags: Vec<String>,
}

impl RoutingResult {
    pub fn new(primary_tag: impl Into<String>) -> Self {
        Self {
            primary_tag: primary_tag.into(),
            fallback_tags: Vec::new(),
        }
    }

    pub fn with_fallbacks(primary_tag: impl Into<String>, fallback_tags: Vec<String>) -> Self {
        Self {
            primary_tag: primary_tag.into(),
            fallback_tags,
        }
    }
}

#[derive(Debug)]
pub struct Router {
    domain_strategy: Strategy,
    domain_trie: DomainMarisa,
    ip_trie: IpTrie,
    inbound_rules: HashMap<String, String, RandomState>,
    default_tag: Option<String>,
    dns: Option<Arc<DnsResolver>>,
    fallback_tags: Vec<String>,
}

impl Router {
    pub fn new() -> Self {
        Self::new_with_strategy(Strategy::default())
    }

    pub fn new_with_strategy(strategy: Strategy) -> Self {
        Self::new_with_tries(strategy, DomainMarisa::new(), IpTrie::new())
    }

    pub fn new_with_tries(strategy: Strategy, domain_trie: DomainMarisa, ip_trie: IpTrie) -> Self {
        Self {
            domain_strategy: strategy,
            domain_trie,
            ip_trie,
            inbound_rules: HashMap::with_hasher(RandomState::new()),
            default_tag: None,
            dns: None,
            fallback_tags: Vec::new(),
        }
    }

    pub fn with_dns(mut self, dns: Arc<DnsResolver>) -> Self {
        self.dns = Some(dns);
        self
    }

    pub fn set_default(&mut self, tag: impl Into<String>) {
        self.default_tag = Some(tag.into());
    }

    pub fn add_inbound_rule(&mut self, inbound_tag: &str, outbound_tag: &str) {
        self.inbound_rules
            .insert(inbound_tag.to_string(), outbound_tag.to_string());
    }

    pub fn set_fallback(&mut self, tags: Vec<String>) {
        self.fallback_tags = tags;
    }

    /// 核心路由：给定 ProxyStream，返回应使用的 outbound tag
    ///
    /// 优先级：inbound_tag > domain_strategy rules > default
    pub async fn route(&self, stream: &ProxyStream) -> Option<RoutingResult> {
        log::debug!(
            target: "route::router",
            "route start: strategy={:?}, inbound_tag={:?}, dst={:?}",
            self.domain_strategy,
            stream.metadata.inbound_tag,
            stream.metadata.dst,
        );

        if !stream.metadata.inbound_tag.is_empty() {
            if let Some(tag) = self.inbound_rules.get(&stream.metadata.inbound_tag) {
                log::debug!(
                    target: "route::router",
                    "route matched inbound rule: inbound_tag={:?}, outbound_tag={:?}",
                    stream.metadata.inbound_tag,
                    tag,
                );
                return Some(self.resolve_tag(tag));
            }
        }

        match self.domain_strategy {
            Strategy::AsIs => {
                if let Address::Domain(domain, _) = &stream.metadata.dst {
                    if let Some(tag) = self.domain_trie.lookup(domain) {
                        log::debug!(
                            target: "route::router",
                            "route AsIs: domain trie matched domain={:?}, tag={:?}",
                            domain,
                            tag,
                        );
                        return Some(self.resolve_tag(tag));
                    }
                    log::debug!(
                        target: "route::router",
                        "route AsIs: domain trie no match for domain={:?}",
                        domain,
                    );
                }
                if let Address::Inet(s) = &stream.metadata.dst {
                    if let Some(tag) = self.ip_trie.lookup(s.ip()) {
                        log::debug!(
                            target: "route::router",
                            "route AsIs: ip trie matched ip={:?}, tag={:?}",
                            s.ip(),
                            tag,
                        );
                        return Some(self.resolve_tag(tag));
                    }
                }
            }
            Strategy::IPIfNonMatch => {
                if let Address::Domain(domain, _) = &stream.metadata.dst {
                    if let Some(tag) = self.domain_trie.lookup(domain) {
                        log::debug!(
                            target: "route::router",
                            "route IPIfNonMatch: domain trie matched domain={:?}, tag={:?}",
                            domain,
                            tag,
                        );
                        return Some(self.resolve_tag(tag));
                    }
                    log::debug!(
                        target: "route::router",
                        "route IPIfNonMatch: domain trie no match for domain={:?}",
                        domain,
                    );
                    if let Some(dns) = &self.dns {
                        if let Ok(ips) = dns.resolve(domain).await {
                            if let Some(ip) = ips.first() {
                                if let Some(tag) = self.ip_trie.lookup(*ip) {
                                    log::debug!(
                                        target: "route::router",
                                        "route IPIfNonMatch: ip trie matched resolved ip={:?}, tag={:?}",
                                        ip,
                                        tag,
                                    );
                                    return Some(self.resolve_tag(tag));
                                }
                            }
                        }
                    }
                }
                if let Address::Inet(s) = &stream.metadata.dst {
                    if let Some(tag) = self.ip_trie.lookup(s.ip()) {
                        log::debug!(
                            target: "route::router",
                            "route IPIfNonMatch: ip trie matched ip={:?}, tag={:?}",
                            s.ip(),
                            tag,
                        );
                        return Some(self.resolve_tag(tag));
                    }
                }
            }
            Strategy::IPOnDemand => {
                let ip_opt: Option<IpAddr> = match &stream.metadata.dst {
                    Address::Inet(s) => Some(s.ip()),
                    Address::Domain(domain, _) => {
                        if let Some(dns) = &self.dns {
                            dns.resolve(domain).await.ok().and_then(|ips| ips.first().copied())
                        } else {
                            None
                        }
                    }
                    Address::Unix(_) => None,
                };

                if let Address::Domain(domain, _) = &stream.metadata.dst {
                    if let Some(tag) = self.domain_trie.lookup(domain) {
                        log::debug!(
                            target: "route::router",
                            "route IPOnDemand: domain trie matched domain={:?}, tag={:?}",
                            domain,
                            tag,
                        );
                        return Some(self.resolve_tag(tag));
                    }
                }

                if let Some(ip) = ip_opt {
                    if let Some(tag) = self.ip_trie.lookup(ip) {
                        log::debug!(
                            target: "route::router",
                            "route IPOnDemand: ip trie matched ip={:?}, tag={:?}",
                            ip,
                            tag,
                        );
                        return Some(self.resolve_tag(tag));
                    }
                }
            }
        }

        if let Some(tag) = self.default_tag.as_ref() {
            log::debug!(
                target: "route::router",
                "route fallback to default tag={:?}",
                tag,
            );
            return Some(RoutingResult::new(tag));
        }
        log::debug!(target: "route::router", "route no match and no default");
        None
    }

    fn resolve_tag(&self, tag: &str) -> RoutingResult {
        if !self.fallback_tags.is_empty() {
            return RoutingResult::with_fallbacks(tag, self.fallback_tags.clone());
        }
        RoutingResult::new(tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::{
        trie::{DomainMarisaBuilder, IpTrieBuilder},
        DnsSettings,
    };

    fn build_router(strategy: Strategy, domains: &[(&str, &str)], ips: &[(&str, &str)]) -> Router {
        let mut domain_builder = DomainMarisaBuilder::new();
        for (domain, tag) in domains {
            domain_builder.insert(domain, tag);
        }

        let mut ip_builder = IpTrieBuilder::new();
        for (cidr, tag) in ips {
            ip_builder.insert(cidr.parse().unwrap(), tag);
        }

        Router::new_with_tries(strategy, domain_builder.build(), ip_builder.build())
    }

    #[test]
    fn test_routing_result_creation() {
        let result = RoutingResult::new("proxy");
        assert_eq!(result.primary_tag, "proxy");
        assert_eq!(result.fallback_tags, Vec::<String>::new());

        let result_with_fallbacks = RoutingResult::with_fallbacks("proxy", vec!["direct".to_string()]);
        assert_eq!(result_with_fallbacks.primary_tag, "proxy");
        assert_eq!(result_with_fallbacks.fallback_tags, vec!["direct".to_string()]);
    }

    #[tokio::test]
    async fn test_router_strategy_as_is() {
        use crate::common::{Address, Protocol};
        use crate::proxy::{ProxyStream, StreamMetadata};
        use std::net::SocketAddr;
        use tokio::net::TcpStream;

        let mut router = build_router(Strategy::AsIs, &[("google.com", "proxy")], &[("10.0.0.0/8", "direct")]);
        router.set_default("default");

        async fn create_test_stream(dst: Address) -> ProxyStream {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let stream = TcpStream::connect(addr).await.unwrap();

            ProxyStream {
                metadata: StreamMetadata {
                    dst,
                    src: "127.0.0.1:1234".parse::<SocketAddr>().unwrap().into(),
                    protocol: Protocol::Tcp,
                    inbound_tag: String::new(),
                },
                inner: crate::transport::TrStream::Tcp(stream),
            }
        }

        let stream = create_test_stream(Address::Domain("www.google.com".to_string(), 443)).await;
        let result = router.route(&stream).await.unwrap();
        assert_eq!(result.primary_tag, "proxy");
        assert_eq!(result.fallback_tags, Vec::<String>::new());

        let stream2 = create_test_stream(Address::Domain("unknown.com".to_string(), 443)).await;
        let result = router.route(&stream2).await.unwrap();
        assert_eq!(result.primary_tag, "default");
    }

    #[tokio::test]
    async fn test_router_strategy_ip_if_non_match() {
        use crate::common::{Address, Protocol};
        use crate::proxy::{ProxyStream, StreamMetadata};
        use std::net::SocketAddr;
        use tokio::net::TcpStream;

        let dns = Arc::new(DnsResolver::new(DnsSettings::default()).unwrap());
        let mut router =
            build_router(Strategy::IPIfNonMatch, &[("google.com", "proxy")], &[("10.0.0.0/8", "direct")]).with_dns(dns);
        router.set_default("default");

        async fn create_test_stream(dst: Address) -> ProxyStream {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let stream = TcpStream::connect(addr).await.unwrap();

            ProxyStream {
                metadata: StreamMetadata {
                    dst,
                    src: "127.0.0.1:1234".parse::<SocketAddr>().unwrap().into(),
                    protocol: Protocol::Tcp,
                    inbound_tag: String::new(),
                },
                inner: crate::transport::TrStream::Tcp(stream),
            }
        }

        let stream = create_test_stream(Address::Domain("www.google.com".to_string(), 443)).await;
        let result = router.route(&stream).await.unwrap();
        assert_eq!(result.primary_tag, "proxy");

        let stream2 = create_test_stream(Address::Domain("unknown.com".to_string(), 443)).await;
        let result = router.route(&stream2).await.unwrap();
        assert_eq!(result.primary_tag, "default");
    }

    #[tokio::test]
    async fn test_router_strategy_ip_on_demand() {
        use crate::common::{Address, Protocol};
        use crate::proxy::{ProxyStream, StreamMetadata};
        use std::net::SocketAddr;
        use tokio::net::TcpStream;

        let dns = Arc::new(DnsResolver::new(DnsSettings::default()).unwrap());
        let router =
            build_router(Strategy::IPOnDemand, &[("google.com", "proxy")], &[("10.0.0.0/8", "direct")]).with_dns(dns);

        async fn create_test_stream(dst: Address) -> ProxyStream {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let stream = TcpStream::connect(addr).await.unwrap();

            ProxyStream {
                metadata: StreamMetadata {
                    dst,
                    src: "127.0.0.1:1234".parse::<SocketAddr>().unwrap().into(),
                    protocol: Protocol::Tcp,
                    inbound_tag: String::new(),
                },
                inner: crate::transport::TrStream::Tcp(stream),
            }
        }

        let stream = create_test_stream(Address::Domain("www.google.com".to_string(), 443)).await;
        let result = router.route(&stream).await.unwrap();
        assert_eq!(result.primary_tag, "proxy");
    }
}
