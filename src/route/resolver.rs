use super::*;
use ahash::RandomState;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSettings {
    #[serde(rename = "hosts", default)]
    pub hosts: Vec<String>,

    #[serde(rename = "servers", default)]
    pub servers: Vec<String>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            hosts: vec![],
            servers: vec![],
        }
    }
}

/// DNS 服务器配置（带 resolver 实例）
#[derive(Debug)]
struct DnsServerInstance {
    resolver: TokioResolver,
}

/// DNS 解析器
#[derive(Debug)]
pub struct DnsResolver {
    hosts: HashMap<String, Vec<IpAddr>, RandomState>,
    resolvers: Vec<DnsServerInstance>,
}

impl DnsResolver {
    /// 从 DnsSettings 创建 DnsResolver
    pub fn new(settings: DnsSettings) -> std::io::Result<Self> {
        let mut hosts = HashMap::with_hasher(RandomState::new());

        // 加载 hosts
        for host_entry in &settings.hosts {
            if host_entry.starts_with("file://") {
                let file_path = &host_entry[7..];
                match Self::load_hosts_file(file_path) {
                    Ok(file_hosts) => {
                        log::info!("Loaded {} hosts from {}", file_hosts.len(), file_path);
                        hosts.extend(file_hosts);
                    }
                    Err(e) => {
                        log::warn!("Failed to load hosts file {}: {}", file_path, e);
                    }
                }
            } else if let Some((domain, ips_str)) = host_entry.split_once(':') {
                let ips: Vec<IpAddr> = ips_str.split(',').filter_map(|s| s.trim().parse().ok()).collect();

                if !ips.is_empty() {
                    hosts.insert(domain.trim().to_lowercase(), ips);
                }
            }
        }

        // 创建 resolver 实例（复用连接）
        let mut resolvers = Vec::new();
        for server in &settings.servers {
            match Self::create_resolver(server) {
                Ok(instance) => resolvers.push(instance),
                Err(e) => {
                    log::warn!("Failed to create resolver for {}: {}", server, e);
                }
            }
        }

        Ok(Self { hosts, resolvers })
    }

    fn create_resolver(server: &str) -> std::io::Result<DnsServerInstance> {
        use std::net::SocketAddr;

        // UDP/TCP DNS
        let addr: SocketAddr = server
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        let name_server =
            NameServerConfig::new(addr.ip(), true, vec![ConnectionConfig::tcp(), ConnectionConfig::udp()]);
        let config = ResolverConfig::from_parts(None, vec![], vec![name_server]);

        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(ResolverOpts::default())
            .build()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        Ok(DnsServerInstance { resolver })
    }

    fn load_hosts_file(path: &str) -> std::io::Result<HashMap<String, Vec<IpAddr>, RandomState>> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut hosts = HashMap::with_hasher(RandomState::new());

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                for domain in &parts[1..] {
                    hosts.entry(domain.to_lowercase()).or_insert_with(Vec::new).push(ip);
                }
            }
        }

        Ok(hosts)
    }

    pub async fn resolve(&self, domain: &str) -> std::io::Result<Vec<IpAddr>> {
        // 检查 hosts
        if let Some(ips) = self.hosts.get(domain) {
            log::debug!("DNS: {} resolved from hosts: {:?}", domain, ips);
            return Ok(ips.clone());
        }

        //  查询 DNS servers
        if !self.resolvers.is_empty() {
            match self.query_servers_concurrent(domain).await {
                Ok(ips) => {
                    log::debug!("DNS: {} resolved from servers: {:?}", domain, ips);
                    return Ok(ips);
                }
                Err(e) => {
                    log::warn!("DNS: query failed for {}: {}", domain, e);
                    return Err(e);
                }
            }
        }

        // 系统 resolver
        log::debug!("DNS: {} using system resolver", domain);
        let addrs: Vec<IpAddr> = tokio::net::lookup_host(format!("{}:0", domain))
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
            .map(|addr| addr.ip())
            .collect();

        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no address for {}", domain),
            ));
        }

        Ok(addrs)
    }

    async fn query_servers_concurrent(&self, domain: &str) -> std::io::Result<Vec<IpAddr>> {
        use futures::stream::{FuturesUnordered, StreamExt};

        let mut futures = FuturesUnordered::new();

        for instance in &self.resolvers {
            futures.push(async move { instance.resolver.lookup_ip(domain).await });
        }

        let mut last_err = None;

        while let Some(result) = futures.next().await {
            match result {
                Ok(lookup) => {
                    let records: Vec<IpAddr> = lookup.iter().collect();
                    if !records.is_empty() {
                        return Ok(records);
                    }
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err
            .map(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No records found")))
    }
}
