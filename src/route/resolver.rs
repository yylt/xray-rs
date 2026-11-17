use std::{io, net::IpAddr};

/// Stateless system resolver. DNS/hosts configuration and any system-side
/// caching belong to the operating system, not this process.
#[derive(Debug)]
pub struct DnsResolver;

impl DnsResolver {
    pub async fn resolve(&self, domain: &str) -> io::Result<Vec<IpAddr>> {
        log::debug!("DNS: {} using system resolver", domain);
        let addrs: Vec<_> = tokio::net::lookup_host((domain, 0))
            .await?
            .map(|addr| addr.ip())
            .collect();
        if addrs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("no address for {domain}")));
        }
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn system_resolver_handles_localhost_and_ip_literals() {
        let resolver = DnsResolver;
        let ips = resolver.resolve("localhost").await.unwrap();
        assert!(!ips.is_empty());
        assert!(ips.iter().all(IpAddr::is_loopback));
        for literal in ["127.0.0.1", "::1"] {
            assert_eq!(
                resolver.resolve(literal).await.unwrap(),
                vec![literal.parse::<IpAddr>().unwrap()]
            );
        }
        assert!(resolver.resolve("invalid\0name").await.is_err());
        assert!(!resolver.resolve("localhost").await.unwrap().is_empty());
    }
}
