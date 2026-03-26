use ahash::RandomState;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::TokioResolver;

use super::DnsSettings;

/// DNS 缓存条目
#[derive(Debug)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    expires: Instant,
}

/// DNS 缓存
#[derive(Debug)]
struct DnsCache {
    entries: RwLock<HashMap<String, CacheEntry, RandomState>>,
    ttl: Duration,
}

impl DnsCache {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_hasher(RandomState::new())),
            ttl,
        }
    }

    fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let map = self.entries.read().unwrap();
        map.get(domain).and_then(|entry| {
            if Instant::now() < entry.expires {
                Some(entry.ips.clone())
            } else {
                None
            }
        })
    }

    fn insert(&self, domain: &str, ips: Vec<IpAddr>) {
        if self.ttl.as_secs() == 0 {
            return;
        }
        let mut map = self.entries.write().unwrap();
        map.insert(
            domain.to_string(),
            CacheEntry {
                ips,
                expires: Instant::now() + self.ttl,
            },
        );
    }
}

/// DNS 服务器配置（带 resolver 实例）
#[derive(Debug)]
struct DnsServerInstance {
    resolver: TokioResolver,
    server_type: String,
}

/// DNS 解析器
#[derive(Debug)]
pub struct DnsResolver {
    hosts: HashMap<String, Vec<IpAddr>, RandomState>,
    resolvers: Vec<DnsServerInstance>,
    cache: DnsCache,
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

        let cache_ttl = if settings.disable_cache {
            Duration::from_secs(0)
        } else {
            Duration::from_secs(300)
        };

        log::info!("DNS resolver initialized: {} hosts, {} resolvers", hosts.len(), resolvers.len());

        Ok(Self {
            hosts,
            resolvers,
            cache: DnsCache::new(cache_ttl),
        })
    }

    /// 创建 resolver 实例（会复用连接）
    fn create_resolver(server: &str) -> std::io::Result<DnsServerInstance> {
        use std::net::SocketAddr;

        if server.starts_with("tcp://") {
            // TCP DNS
            let addr_str = &server[6..];
            let addr: SocketAddr = addr_str
                .parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));

            let resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
                .with_options(ResolverOpts::default())
                .build();

            Ok(DnsServerInstance {
                resolver,
                server_type: format!("TCP({})", addr_str),
            })
        } else if server.starts_with("https://") {
            // DoH - hickory-resolver 0.24 支持预设的 DNS 服务
            let config = if server.contains("dns.google") {
                ResolverConfig::google()
            } else if server.contains("cloudflare-dns.com") || server.contains("1.1.1.1") {
                ResolverConfig::cloudflare()
            } else if server.contains("doh.pub") {
                // doh.pub 使用 Cloudflare 的配置（都是标准 DoH）
                ResolverConfig::cloudflare()
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("Custom DoH server not supported in hickory-resolver 0.24: {}", server),
                ));
            };

            let resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
                .with_options(ResolverOpts::default())
                .build();

            Ok(DnsServerInstance {
                resolver,
                server_type: format!("DoH({})", server),
            })
        } else if server.starts_with("tls://") {
            // DoT - hickory-resolver 0.24 可能不直接支持 DoT
            // 暂时返回不支持错误
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("DoT (DNS over TLS) not yet supported in hickory-resolver 0.24: {}", server),
            ));
        } else {
            // UDP DNS
            let addr: SocketAddr = server
                .parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));

            let resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
                .with_options(ResolverOpts::default())
                .build();

            Ok(DnsServerInstance {
                resolver,
                server_type: format!("UDP({})", server),
            })
        }
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
        let domain_lower = domain.to_lowercase();

        // 1. 检查 hosts
        if let Some(ips) = self.hosts.get(&domain_lower) {
            log::debug!("DNS: {} resolved from hosts: {:?}", domain, ips);
            return Ok(ips.clone());
        }

        // 2. 检查缓存
        if let Some(ips) = self.cache.get(&domain_lower) {
            log::debug!("DNS: {} resolved from cache: {:?}", domain, ips);
            return Ok(ips);
        }

        // 3. 查询 DNS servers（如果配置了）
        if !self.resolvers.is_empty() {
            match self.query_servers_concurrent(domain).await {
                Ok(ips) => {
                    log::debug!("DNS: {} resolved from servers: {:?}", domain, ips);
                    self.cache.insert(&domain_lower, ips.clone());
                    return Ok(ips);
                }
                Err(e) => {
                    log::warn!("DNS: query failed for {}: {}", domain, e);
                    return Err(e);
                }
            }
        }

        // 4. 使用系统 resolver
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

        self.cache.insert(&domain_lower, addrs.clone());
        Ok(addrs)
    }

    /// 并发查询所有 DNS servers，返回最快的响应（使用 JoinSet）
    async fn query_servers_concurrent(&self, domain: &str) -> std::io::Result<Vec<IpAddr>> {
        use tokio::task::JoinSet;
        use tokio::time::{timeout, Duration};

        let mut set = JoinSet::new();
        let query_timeout = Duration::from_secs(5);

        // 为每个 resolver 添加查询任务
        for instance in &self.resolvers {
            let resolver = instance.resolver.clone();
            let domain = domain.to_string();
            let server_type = instance.server_type.clone();

            set.spawn(async move {
                log::debug!("DNS: querying {} for {}", server_type, domain);
                let result = resolver
                    .lookup_ip(&domain)
                    .await
                    .map(|response| response.iter().collect::<Vec<IpAddr>>())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));

                if let Ok(ref ips) = result {
                    log::debug!("DNS: {} returned {} addresses for {}", server_type, ips.len(), domain);
                } else if let Err(ref e) = result {
                    log::debug!("DNS: {} failed for {}: {}", server_type, domain, e);
                }

                result
            });
        }

        // 等待第一个成功的响应
        let mut last_error = None;

        let result = timeout(query_timeout, async {
            while let Some(result) = set.join_next().await {
                match result {
                    Ok(Ok(ips)) if !ips.is_empty() => {
                        // 成功获取结果，中止其他任务
                        set.abort_all();
                        return Ok(ips);
                    }
                    Ok(Ok(_)) => {
                        // 空结果，继续等待
                        continue;
                    }
                    Ok(Err(e)) => {
                        last_error = Some(e);
                        continue;
                    }
                    Err(e) => {
                        last_error = Some(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Task join error: {}", e),
                        ));
                        continue;
                    }
                }
            }

            Err(last_error
                .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "all DNS servers failed")))
        })
        .await;

        match result {
            Ok(r) => r,
            Err(_) => {
                // 超时，中止所有任务
                set.abort_all();
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS query timeout"))
            }
        }
    }
}
