// bin/rsdns/server.rs
#![allow(unused_imports)]
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType as HickoryRecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use log::{debug, error, info};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use xray_rs::route::cache::{CacheKey, CacheRecord, DnsCache};
use xray_rs::route::dns::{Action, DnsQuery, RuleEngine};
use xray_rs::route::matcher::RecordType;

use super::upstream::UpstreamClient;

const MAX_DNS_SIZE: usize = 4096;

/// DNS 服务器
pub struct DnsServer {
    rule_engine: Arc<RuleEngine>,
    cache: Arc<DnsCache>,
    upstreams: Arc<HashMap<String, UpstreamClient>>,
    default_upstream: String,
}

impl DnsServer {
    pub fn new(
        rule_engine: Arc<RuleEngine>,
        cache: Arc<DnsCache>,
        upstreams: HashMap<String, UpstreamClient>,
        default_upstream: String,
    ) -> Self {
        Self {
            rule_engine,
            cache,
            upstreams: Arc::new(upstreams),
            default_upstream,
        }
    }

    /// 启动 UDP 监听
    pub async fn serve_udp(&self, addr: SocketAddr) -> io::Result<()> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!("DNS server listening on UDP {}", addr);

        let mut buf = vec![0u8; MAX_DNS_SIZE];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();

            let server = self.clone_inner();
            let socket_clone = socket.clone();
            tokio::spawn(async move {
                match server.handle_query(&data, src.ip()).await {
                    Ok(response) => {
                        if let Err(e) = socket_clone.send_to(&response, src).await {
                            error!("Failed to send response: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to handle query: {}", e);
                    }
                }
            });
        }
    }

    fn clone_inner(&self) -> DnsServerInner {
        DnsServerInner {
            rule_engine: self.rule_engine.clone(),
            cache: self.cache.clone(),
            upstreams: self.upstreams.clone(),
            default_upstream: self.default_upstream.clone(),
        }
    }

    pub fn clone_for_spawn(&self) -> Self {
        Self {
            rule_engine: self.rule_engine.clone(),
            cache: self.cache.clone(),
            upstreams: self.upstreams.clone(),
            default_upstream: self.default_upstream.clone(),
        }
    }
}

struct DnsServerInner {
    rule_engine: Arc<RuleEngine>,
    cache: Arc<DnsCache>,
    upstreams: Arc<HashMap<String, UpstreamClient>>,
    default_upstream: String,
}

impl DnsServerInner {
    async fn handle_query(&self, data: &[u8], client_ip: IpAddr) -> io::Result<Vec<u8>> {
        let msg = Message::from_vec(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let query = msg
            .queries()
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no query"))?;

        let name = query.name().to_string().trim_end_matches('.').to_string();
        let qtype: RecordType = u16::from(query.query_type()).into();

        debug!("Query: {} {:?} from {}", name, qtype, client_ip);

        let dns_query = DnsQuery {
            id: msg.id(),
            name: name.clone(),
            qtype,
            client_ip,
        };

        // 检查缓存
        let cache_key = CacheKey {
            name: name.clone(),
            qtype,
        };
        if let Some(entry) = self.cache.get(&cache_key) {
            debug!("Cache hit for {}", name);
            return self.build_response(&msg, &entry.records);
        }

        // 评估规则
        let action = self.rule_engine.evaluate(&dns_query);
        let response = match action {
            Action::Block => self.build_nxdomain(&msg),
            Action::Rewrite { ip } => self.build_rewrite(&msg, *ip),
            Action::Hosts => self.build_hosts_response(&msg, &name, qtype),
            Action::Forward { upstream, .. } => {
                let upstream_name = if upstream.is_empty() {
                    &self.default_upstream
                } else {
                    upstream
                };
                self.forward_query(&msg, upstream_name).await
            }
        }?;

        Ok(response)
    }

    fn build_response(&self, query: &Message, _records: &[CacheRecord]) -> io::Result<Vec<u8>> {
        let mut response = query.clone();
        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::NoError);

        response
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    fn build_nxdomain(&self, query: &Message) -> io::Result<Vec<u8>> {
        let mut response = query.clone();
        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::NXDomain);
        response
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    fn build_rewrite(&self, query: &Message, _ip: IpAddr) -> io::Result<Vec<u8>> {
        let mut response = query.clone();
        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::NoError);
        // TODO: 添加 rewrite 的 A/AAAA 记录
        response
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    fn build_hosts_response(&self, query: &Message, name: &str, qtype: RecordType) -> io::Result<Vec<u8>> {
        let mut response = query.clone();
        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::NoError);

        let hosts = self.rule_engine.hosts();
        match qtype {
            RecordType::A => {
                if let Some(_ips) = hosts.lookup_v4(name) {
                    // TODO: 添加 A 记录
                }
            }
            RecordType::AAAA => {
                if let Some(_ips) = hosts.lookup_v6(name) {
                    // TODO: 添加 AAAA 记录
                }
            }
            _ => {}
        }

        response
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn forward_query(&self, query: &Message, upstream_name: &str) -> io::Result<Vec<u8>> {
        let upstream = self
            .upstreams
            .get(upstream_name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("upstream {} not found", upstream_name)))?;

        let response = upstream.query(query).await?;

        // TODO: 写入缓存

        response
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}
