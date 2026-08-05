use ahash::AHashMap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::RData;
use hickory_proto::rr::{DNSClass, Name, Record, RecordType as HickoryRecordType};
use hickory_proto::serialize::binary::BinEncodable;
use log::{error, info, warn};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use xray_rs::common::trie::DomainMarisa;

use super::cache::{BlockCache, CacheKey, CacheRecord, CacheResult, DnsCache};
use super::hosts::HostsTrie;
use super::rule::{BlockResponse, Rule, RuleAction};
use super::upstream::UpstreamGroup;

const MAX_DNS_SIZE: usize = 4096;

pub struct DnsServer {
    hosts_trie: Arc<HostsTrie>,
    groups_trie: Arc<DomainMarisa>,
    rules: Arc<Vec<Rule>>,
    cache: Arc<DnsCache>,
    upstreams: Arc<AHashMap<String, UpstreamGroup>>,
}

impl DnsServer {
    pub fn new(
        hosts_trie: HostsTrie,
        groups_trie: DomainMarisa,
        rules: Vec<Rule>,
        cache: DnsCache,
        upstreams: AHashMap<String, UpstreamGroup>,
    ) -> Self {
        Self {
            hosts_trie: Arc::new(hosts_trie),
            groups_trie: Arc::new(groups_trie),
            rules: Arc::new(rules),
            cache: Arc::new(cache),
            upstreams: Arc::new(upstreams),
        }
    }

    pub async fn serve_udp(&self, addr: SocketAddr) -> io::Result<()> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!("rsdns listening on UDP {}", addr);

        let mut buf = vec![0u8; MAX_DNS_SIZE];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();

            let socket = socket.clone();
            let self_clone = self.clone_inner();
            tokio::spawn(async move {
                match self_clone.handle_query(&data, src.ip()).await {
                    Ok(response) => {
                        if let Err(e) = socket.send_to(&response, src).await {
                            error!("Failed to send UDP response: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to handle query: {}", e);
                    }
                }
            });
        }
    }

    pub async fn serve_tcp(&self, addr: SocketAddr) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("rsdns listening on TCP {}", addr);

        loop {
            let (mut stream, src) = listener.accept().await?;
            let self_clone = self.clone_inner();
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if let Err(e) = stream.read_exact(&mut len_buf).await {
                    error!("TCP read len from {}: {}", src, e);
                    return;
                }
                let req_len = u16::from_be_bytes(len_buf) as usize;

                if req_len > MAX_DNS_SIZE {
                    error!("TCP request too large from {}: {}", src, req_len);
                    return;
                }

                let mut data = vec![0u8; req_len];
                if let Err(e) = stream.read_exact(&mut data).await {
                    error!("TCP read data from {}: {}", src, e);
                    return;
                }

                match self_clone.handle_query(&data, src.ip()).await {
                    Ok(response) => {
                        let len = (response.len() as u16).to_be_bytes();
                        if stream.write_all(&len).await.is_err() {
                            return;
                        }
                        if let Err(e) = stream.write_all(&response).await {
                            error!("Failed to send TCP response to {}: {}", src, e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to handle TCP query from {}: {}", src, e);
                    }
                }
            });
        }
    }

    pub fn clone_inner(&self) -> Self {
        Self {
            hosts_trie: self.hosts_trie.clone(),
            groups_trie: self.groups_trie.clone(),
            rules: self.rules.clone(),
            cache: self.cache.clone(),
            upstreams: self.upstreams.clone(),
        }
    }

    async fn handle_query(&self, data: &[u8], client_ip: IpAddr) -> io::Result<Vec<u8>> {
        let msg = Message::from_vec(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let query = msg
            .queries
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no question"))?;

        let name = query.name().to_string().trim_end_matches('.').to_lowercase();
        let qtype: u16 = u16::from(query.query_type());
        let qtype_str = qtype_to_str(qtype);

        let msg_id = msg.id;
        let (mut response, action, cached) = self.do_query_with_log(&msg, &name, qtype).await;
        response.metadata.id = msg_id;

        info!(
            "client={} type={} domain={} action={} cache={}",
            client_ip, qtype_str, name, action, cached
        );

        response
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn do_query_with_log(
        &self,
        msg: &Message,
        name: &str,
        qtype: u16,
    ) -> (Message, &'static str, bool) {
        let result = self.do_query(msg, name, qtype).await;
        match result {
            Ok((resp, action, cached)) => (resp, action, cached),
            Err(e) => {
                warn!("Query failed for {}: {}", name, e);
                (self.build_servfail(msg), "servfail", false)
            }
        }
    }

    async fn do_query(
        &self,
        msg: &Message,
        name: &str,
        qtype: u16,
    ) -> Result<(Message, &'static str, bool), io::Error> {
        if let Some(ips) = self.hosts_trie.lookup(name) {
            let resp = self.build_hosts_response(msg, name, qtype, ips)?;
            return Ok((resp, "hosts", false));
        }

        let cache_key = CacheKey {
            name: name.to_string(),
            qtype,
        };

        if let CacheResult::Fresh(entry) = self.cache.get_cached(&cache_key).await {
            let resp = self.build_response_from_cache(msg, &entry.records)?;
            return Ok((resp, entry.action_name(), true));
        }

        let rule = self.rules.iter().find(|r| r.matches(name, qtype, &self.groups_trie));

        match rule {
            Some(rule) => match &rule.action {
                RuleAction::Block { response } => {
                    let (resp, block) = match response {
                        BlockResponse::NXDomain => (self.build_nxdomain(msg)?, BlockCache::NXDomain),
                        BlockResponse::Poison => (self.build_poison(msg, name, qtype)?, BlockCache::Poison),
                    };
                    self.cache
                        .put(cache_key.clone(), vec![CacheRecord::Block(block)], 300, false)
                        .await;
                    let action = match response {
                        BlockResponse::NXDomain => "block-nxdomain",
                        BlockResponse::Poison => "block-poison",
                    };
                    Ok((resp, action, false))
                }
                RuleAction::Cname { target, ttl } => {
                    let resp = self.handle_cname(msg, name, qtype, target, *ttl).await?;
                    Ok((resp, "cname", false))
                }
                RuleAction::Forward {
                    upstream,
                    cache: use_cache,
                    ttl: rewrite_ttl,
                    keep_ttl,
                } => self
                    .handle_forward_with_log(
                        msg, name, qtype, upstream, *use_cache, *rewrite_ttl, *keep_ttl,
                    )
                    .await,
            },
            None => {
                let resp = self.build_nxdomain(msg)?;
                Ok((resp, "nxdomain", false))
            }
        }
    }

    async fn handle_forward_with_log(
        &self,
        msg: &Message,
        name: &str,
        qtype: u16,
        upstream: &str,
        use_cache: bool,
        rewrite_ttl: Option<u32>,
        keep_ttl: Option<bool>,
    ) -> Result<(Message, &'static str, bool), io::Error> {
        if !use_cache {
            let resp = self
                .forward_to_upstream(msg, upstream, name, qtype, rewrite_ttl, keep_ttl)
                .await?;
            return Ok((resp, "forward", false));
        }

        let cache_key = CacheKey {
            name: name.to_string(),
            qtype,
        };

        match self.cache.get_cached(&cache_key).await {
            CacheResult::Fresh(entry) => {
                let resp = self.build_response_from_cache(msg, &entry.records)?;
                Ok((resp, "forward", true))
            }
            CacheResult::Stale(entry) => match self
                .forward_to_upstream(msg, upstream, name, qtype, rewrite_ttl, keep_ttl)
                .await
            {
                Ok(resp) => Ok((resp, "forward", false)),
                Err(_) => {
                    let resp = self.build_response_from_cache(msg, &entry.records)?;
                    Ok((resp, "forward-stale", true))
                }
            },
            CacheResult::Miss => {
                let resp = self
                    .forward_to_upstream(msg, upstream, name, qtype, rewrite_ttl, keep_ttl)
                    .await?;
                Ok((resp, "forward", false))
            }
        }
    }

    async fn forward_to_upstream(
        &self,
        msg: &Message,
        upstream: &str,
        name: &str,
        qtype: u16,
        rewrite_ttl: Option<u32>,
        keep_ttl: Option<bool>,
    ) -> io::Result<Message> {
        let group = self
            .upstreams
            .get(upstream)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("upstream {} not found", upstream)))?;

        let mut response = group.query(msg).await?;

        let records = extract_cache_records(&response);

        if !records.is_empty() {
            let ttl = extract_min_ttl(&response);
            let effective_keep_ttl = keep_ttl.unwrap_or(false);
            let final_ttl = if let Some(rttl) = rewrite_ttl { rttl } else { ttl };
            let cache_key = CacheKey {
                name: name.to_string(),
                qtype,
            };
            self.cache.put(cache_key, records, final_ttl, effective_keep_ttl).await;
        }

        if let Some(rttl) = rewrite_ttl {
            rewrite_ttl_in_response(&mut response, rttl);
        }

        Ok(response)
    }

    async fn handle_cname(
        &self,
        msg: &Message,
        _name: &str,
        qtype: u16,
        target: &str,
        ttl: u32,
    ) -> io::Result<Message> {
        let cname_msg = build_cname_query(msg, target, qtype);
        let default_upstream = self.upstreams.keys().next().map(|s| s.as_str()).unwrap_or("default");

        let mut response = self
            .forward_to_upstream(&cname_msg, default_upstream, target, qtype, Some(ttl), Some(true))
            .await?;

        let cname_name = Name::from_utf8(target).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let query_name = msg
            .queries
            .first()
            .map(|q| q.name().clone())
            .unwrap_or_else(|| Name::new());

        let cname_record =
            Record::from_rdata(query_name, ttl, RData::CNAME(hickory_proto::rr::rdata::CNAME(cname_name)));
        response.answers.push(cname_record.into());
        response.metadata.id = msg.id;

        Ok(response)
    }

    fn build_hosts_response(&self, msg: &Message, name: &str, qtype: u16, ips: &[IpAddr]) -> io::Result<Message> {
        let mut response = make_response_base(msg)?;
        let rr_name = Name::from_utf8(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        for ip in ips {
            let record = match (ip, qtype) {
                (IpAddr::V4(v4), 1) | (IpAddr::V4(v4), 255) => {
                    Record::from_rdata(rr_name.clone(), 300, RData::A(A(*v4)))
                }
                (IpAddr::V6(v6), 28) | (IpAddr::V6(v6), 255) => {
                    Record::from_rdata(rr_name.clone(), 300, RData::AAAA(AAAA(*v6)))
                }
                _ => continue,
            };
            response.answers.push(record.into());
        }

        Ok(response)
    }

    fn build_nxdomain(&self, msg: &Message) -> io::Result<Message> {
        let mut response = make_response_base(msg)?;
        response.metadata.response_code = ResponseCode::NXDomain;
        Ok(response)
    }

    fn build_poison(&self, msg: &Message, name: &str, qtype: u16) -> io::Result<Message> {
        let mut response = make_response_base(msg)?;
        let rr_name = Name::from_utf8(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        match qtype {
            1 | 255 => {
                let record = Record::from_rdata(rr_name.clone(), 300, RData::A(A(Ipv4Addr::new(0, 0, 0, 0))));
                response.answers.push(record.into());
                response.metadata.response_code = ResponseCode::NoError;
            }
            _ => {
                response.metadata.response_code = ResponseCode::NoError;
            }
        }
        match qtype {
            28 | 255 => {
                let record = Record::from_rdata(rr_name, 300, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
                response.answers.push(record.into());
            }
            _ => {}
        }

        Ok(response)
    }

    fn build_servfail(&self, msg: &Message) -> Message {
        let mut response = msg.clone();
        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = ResponseCode::ServFail;
        response
    }

    fn build_response_from_cache(&self, msg: &Message, records: &[CacheRecord]) -> io::Result<Message> {
        for record in records {
            if let CacheRecord::Block(ref block) = record {
                return match block {
                    BlockCache::NXDomain => self.build_nxdomain(msg),
                    BlockCache::Poison => {
                        let query = msg.queries.first().ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "no question")
                        })?;
                        let name = query.name().to_string().trim_end_matches('.').to_lowercase();
                        let qtype: u16 = u16::from(query.query_type());
                        self.build_poison(msg, &name, qtype)
                    }
                };
            }
        }

        let mut response = make_response_base(msg)?;
        let query = msg.queries.first().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "no question")
        })?;
        let name = query.name().clone();
        for record in records {
            let r = match record {
                CacheRecord::A(ip) => Record::from_rdata(name.clone(), 60, RData::A(A(*ip))),
                CacheRecord::AAAA(ip) => Record::from_rdata(name.clone(), 60, RData::AAAA(AAAA(*ip))),
                CacheRecord::HTTPS(_) | CacheRecord::Block(_) | CacheRecord::Other(_) => continue,
            };
            response.answers.push(r.into());
        }

        Ok(response)
    }
}

fn make_response_base(msg: &Message) -> io::Result<Message> {
    let mut response = Message::new(msg.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_available = true;
    if let Some(q) = msg.queries.first() {
        response.queries.push(q.clone());
    }
    Ok(response)
}

fn extract_cache_records(msg: &Message) -> Vec<CacheRecord> {
    let mut records = Vec::new();
    for answer in &msg.answers {
        match &answer.data {
            RData::A(ip) => records.push(CacheRecord::A(ip.0)),
            RData::AAAA(ip) => records.push(CacheRecord::AAAA(ip.0)),
            RData::HTTPS(data) => {
                let wire = BinEncodable::to_bytes(&data.0).unwrap_or_default();
                records.push(CacheRecord::HTTPS(wire))
            }
            _ => {}
        }
    }
    records
}

fn extract_min_ttl(msg: &Message) -> u32 {
    msg.answers.iter().map(|r| r.ttl).min().unwrap_or(300)
}

fn rewrite_ttl_in_response(msg: &mut Message, ttl: u32) {
    for answer in &mut msg.answers {
        answer.ttl = ttl;
    }
}

fn qtype_to_str(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        28 => "AAAA",
        255 => "ANY",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        2 => "NS",
        6 => "SOA",
        12 => "PTR",
        33 => "SRV",
        65 => "HTTPS",
        _ => "OTHER",
    }
}

fn build_cname_query(query: &Message, target: &str, qtype: u16) -> Message {
    let mut msg = query.clone();
    if let Ok(name) = Name::from_utf8(target) {
        let mut q = hickory_proto::op::Query::new();
        q.set_name(name);
        q.set_query_type(match qtype {
            28 => HickoryRecordType::AAAA,
            _ => HickoryRecordType::A,
        });
        q.set_query_class(DNSClass::IN);
        msg.queries.clear();
        msg.queries.push(q);
    }
    msg
}
