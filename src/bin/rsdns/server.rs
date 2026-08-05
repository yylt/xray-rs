use ahash::AHashMap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::RData;
use hickory_proto::rr::{DNSClass, Name, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use log::{error, info, warn};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use xray_rs::common::trie::DomainMarisa;

use super::cache::{BlockCache, CacheEntry, CacheKey, CacheRecord, CacheResult, DnsCache};
use super::config::LogConfig;
use super::hosts::HostsTrie;
use super::rule::{BlockResponse, Rule, RuleAction};
use super::upstream::UpstreamGroup;

const MAX_DNS_SIZE: usize = 4096;

pub struct QueryLog {
    pub qtype: u16,
    pub name: String,
    pub proto: &'static str,
    pub remote: IpAddr,
    pub port: u16,
    pub size: usize,
    pub duration: Duration,
    pub rcode: ResponseCode,
    pub action: String,
}

impl QueryLog {
    pub fn format(&self, template: &str) -> String {
        let mut result = String::with_capacity(template.len() + 128);
        let mut rest = template;
        while let Some(start) = rest.find('{') {
            result.push_str(&rest[..start]);
            rest = &rest[start + 1..];
            if let Some(end) = rest.find('}') {
                self.write_field(&mut result, &rest[..end]);
                rest = &rest[end + 1..];
            } else {
                result.push('{');
            }
        }
        result.push_str(rest);
        result
    }

    fn write_field(&self, w: &mut impl std::fmt::Write, key: &str) {
        let _ = match key {
            "duration" => write!(w, "{:.5}", self.duration.as_secs_f64()),
            "proto" => w.write_str(self.proto),
            "rcode" => w.write_str(format_rcode(self.rcode)),
            "name" => w.write_str(&self.name),
            "type" => write!(w, "{}", self.qtype),
            "port" => write!(w, "{}", self.port),
            "size" => write!(w, "{}", self.size),
            "action" => w.write_str(&self.action),
            "remote" => match &self.remote {
                IpAddr::V4(v4) => write!(w, "{}", v4),
                IpAddr::V6(v6) => write!(w, "[{}]", v6),
            },
            _ => write!(w, "{{{}}}", key),
        };
    }
}

fn format_rcode(rcode: ResponseCode) -> &'static str {
    match rcode {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::Refused => "REFUSED",
        ResponseCode::FormErr => "FORMERR",
        _ => "UNKNOWN",
    }
}

enum LogWriter {
    Stdout(BufWriter<std::io::Stdout>),
    File(BufWriter<File>),
}

impl LogWriter {
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        match self {
            LogWriter::Stdout(w) => writeln!(w, "{}", line),
            LogWriter::File(w) => writeln!(w, "{}", line),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            LogWriter::Stdout(w) => w.flush(),
            LogWriter::File(w) => w.flush(),
        }
    }
}

pub struct QueryLogger {
    writer: Arc<Mutex<LogWriter>>,
    template: String,
}

impl QueryLogger {
    pub fn new(cfg: &LogConfig) -> io::Result<Self> {
        let writer = match &cfg.file {
            Some(path) => LogWriter::File(BufWriter::with_capacity(cfg.buf_size, File::create(path)?)),
            None => LogWriter::Stdout(BufWriter::with_capacity(cfg.buf_size, std::io::stdout())),
        };
        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            template: cfg.format.clone(),
        })
    }

    fn write(&self, qlog: &QueryLog) {
        let line = qlog.format(&self.template);
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.write_line(&line);
        }
    }

    pub fn flush(&self) {
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.flush();
        }
    }

    pub fn start_flush_task(self: &Arc<Self>, interval: Duration) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                this.flush();
            }
        });
    }
}

pub struct DnsServer {
    hosts_trie: Arc<HostsTrie>,
    groups_trie: Arc<DomainMarisa>,
    rules: Arc<Vec<Rule>>,
    cache: Arc<DnsCache>,
    upstreams: Arc<AHashMap<String, UpstreamGroup>>,
    logger: Arc<QueryLogger>,
}

impl DnsServer {
    pub fn new(
        hosts_trie: HostsTrie,
        groups_trie: DomainMarisa,
        rules: Vec<Rule>,
        cache: DnsCache,
        upstreams: AHashMap<String, UpstreamGroup>,
        logger: Arc<QueryLogger>,
    ) -> Self {
        Self {
            hosts_trie: Arc::new(hosts_trie),
            groups_trie: Arc::new(groups_trie),
            rules: Arc::new(rules),
            cache: Arc::new(cache),
            upstreams: Arc::new(upstreams),
            logger,
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
                match self_clone.handle_query(&data, src, "udp").await {
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

                match self_clone.handle_query(&data, src, "tcp").await {
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
            logger: self.logger.clone(),
        }
    }

    async fn handle_query(&self, data: &[u8], client_addr: SocketAddr, proto: &'static str) -> io::Result<Vec<u8>> {
        let start = Instant::now();
        let msg = Message::from_vec(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let query = msg
            .queries
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no question"))?;

        let name = query.name().to_ascii().to_lowercase().trim_end_matches('.').to_string();
        let qtype = u16::from(query.query_type());

        let cache_key = CacheKey::new(&name, qtype);
        let msg_id = msg.id;
        let (mut response, action) = self.do_query(&msg, &cache_key).await;
        response.metadata.id = msg_id;
        let elapsed = start.elapsed();

        let qlog = QueryLog {
            qtype,
            name,
            proto,
            remote: client_addr.ip(),
            port: client_addr.port(),
            size: data.len(),
            duration: elapsed,
            rcode: response.metadata.response_code,
            action,
        };
        self.logger.write(&qlog);

        response
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// 执行DNS查询：hosts → 缓存 → 规则匹配 → 上游转发/拦截
    /// 返回(应答报文, 动作标签)
    async fn do_query(&self, msg: &Message, cache_key: &CacheKey) -> (Message, String) {
        // hosts 文件优先
        if let Some(ips) = self.hosts_trie.lookup(&cache_key.name) {
            return match self.build_hosts_response(msg, &cache_key.name, cache_key.qtype, ips) {
                Ok(resp) => (resp, "hosts".into()),
                Err(e) => {
                    warn!("hosts building response for {} failed: {}", cache_key.name, e);
                    (self.build_servfail(msg), "hosts".into())
                }
            };
        }

        // 缓存命中且未过期，直接返回
        if let CacheResult::Fresh(entry) = self.cache.get_cached(cache_key).await {
            let action = entry.action_name();
            return match self.build_response_from_cache(msg, &entry) {
                Ok(resp) => (resp, action.into()),
                Err(e) => {
                    warn!("building cache response for {} failed: {}", cache_key.name, e);
                    (self.build_servfail(msg), action.into())
                }
            };
        }

        // 匹配规则
        let rule = self
            .rules
            .iter()
            .find(|r| r.matches(&cache_key.name, cache_key.qtype, &self.groups_trie));

        match rule {
            Some(rule) => match &rule.action {
                RuleAction::Block { response } => {
                    let (resp, block) = match response {
                        BlockResponse::NXDomain => (self.build_nxdomain(msg), BlockCache::NXDomain),
                        BlockResponse::Poison => {
                            (self.build_poison(msg, &cache_key.name, cache_key.qtype), BlockCache::Poison)
                        }
                    };
                    self.cache
                        .put(cache_key.clone(), vec![CacheRecord::Block(block)], 300)
                        .await;
                    let action = match response {
                        BlockResponse::NXDomain => "block-nxdomain",
                        BlockResponse::Poison => "block-poison",
                    };
                    match resp {
                        Ok(r) => (r, action.into()),
                        Err(e) => {
                            warn!("block response for {} failed: {}", cache_key.name, e);
                            (self.build_servfail(msg), "block".into())
                        }
                    }
                }
                RuleAction::Cname { target, ttl } => match self.handle_cname(msg, cache_key, target, *ttl).await {
                    Ok(resp) => (resp, "cname".into()),
                    Err(e) => {
                        warn!("cname for {} -> {} failed: {}", cache_key.name, target, e);
                        (self.build_servfail(msg), "cname".into())
                    }
                },
                RuleAction::Forward {
                    upstream,
                    cache: use_cache,
                    ttl: rewrite_ttl,
                } => {
                    self.handle_forward(msg, cache_key, upstream, *use_cache, *rewrite_ttl)
                        .await
                }
            },
            // 无匹配规则，返回 NXDomain
            None => match self.build_nxdomain(msg) {
                Ok(resp) => (resp, "nxdomain".into()),
                Err(e) => {
                    warn!("nxdomain for {} failed: {}", cache_key.name, e);
                    (self.build_servfail(msg), "servfail".into())
                }
            },
        }
    }

    /// 处理 forward 规则：缓存直回、serve_expired 后台刷新、无缓存时上游查询
    async fn handle_forward(
        &self,
        msg: &Message,
        cache_key: &CacheKey,
        upstream: &str,
        use_cache: bool,
        rewrite_ttl: Option<u32>,
    ) -> (Message, String) {
        let action_label = format!("forward({})", upstream);
        if !use_cache {
            return match self.forward_to_upstream(msg, upstream, cache_key, rewrite_ttl).await {
                Ok(resp) => (resp, action_label),
                Err(e) => {
                    warn!("forward {} to upstream {} failed: {}", cache_key.name, upstream, e);
                    (self.build_servfail(msg), action_label)
                }
            };
        }

        match self.cache.get_cached(cache_key).await {
            CacheResult::Fresh(entry) => match self.build_response_from_cache(msg, &entry) {
                Ok(resp) => (resp, action_label),
                Err(e) => {
                    warn!("build cache response for {} failed: {}", cache_key.name, e);
                    (self.build_servfail(msg), action_label)
                }
            },
            // 缓存已过期但允许返回陈旧数据：先回陈旧数据，同时后台刷新
            CacheResult::Stale(entry) => {
                let response = match self.build_response_from_cache(msg, &entry) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("build cache stale for {} failed: {}", cache_key.name, e);
                        self.build_servfail(msg)
                    }
                };
                // 后台异步刷新，仅传递需要的 Arc 字段，避免 clone_inner
                let cache = self.cache.clone();
                let upstreams = self.upstreams.clone();
                let us = upstream.to_string();
                let ck = cache_key.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward_to_upstream_bg(&cache, &upstreams, &ck, &us, rewrite_ttl).await {
                        warn!("background refresh for {} failed: {}", ck.name, e);
                    }
                });
                (response, format!("forward-stale({})", upstream))
            }
            CacheResult::Miss => match self.forward_to_upstream(msg, upstream, cache_key, rewrite_ttl).await {
                Ok(resp) => (resp, action_label),
                Err(e) => {
                    warn!("forward {} to upstream {} failed: {}", cache_key.name, upstream, e);
                    (self.build_servfail(msg), action_label)
                }
            },
        }
    }

    /// 查询上游 DNS 并缓存结果
    async fn forward_to_upstream(
        &self,
        msg: &Message,
        upstream: &str,
        cache_key: &CacheKey,
        rewrite_ttl: Option<u32>,
    ) -> io::Result<Message> {
        let group = self
            .upstreams
            .get(upstream)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("upstream {} not found", upstream)))?;

        let response = group.query(msg).await?;

        cache_upstream_response(&self.cache, cache_key, &response, rewrite_ttl).await;

        let mut response = response;
        if let Some(rttl) = rewrite_ttl {
            rewrite_ttl_in_response(&mut response, rttl);
        }

        Ok(response)
    }

    /// 处理 CNAME 规则：解析目标域名的实际 IP，并为原域名附加 CNAME 记录
    async fn handle_cname(&self, msg: &Message, cache_key: &CacheKey, target: &str, ttl: u32) -> io::Result<Message> {
        let cname_msg = build_cname_query(msg, target, cache_key.qtype);
        let default_upstream = self.upstreams.keys().next().map(|s| s.as_str()).unwrap_or("default");
        let ck = CacheKey::new(target, cache_key.qtype);

        let mut response = self
            .forward_to_upstream(&cname_msg, default_upstream, &ck, Some(ttl))
            .await?;

        let cname_name = Name::from_utf8(target).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let query_name = msg.queries.first().map(|q| q.name().clone()).unwrap_or_default();

        let cname_record = Record::from_rdata(query_name, ttl, RData::CNAME(CNAME(cname_name)));
        response.answers.push(cname_record);
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
            response.answers.push(record);
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
                response.answers.push(record);
                response.metadata.response_code = ResponseCode::NoError;
            }
            _ => {
                response.metadata.response_code = ResponseCode::NoError;
            }
        }
        match qtype {
            28 | 255 => {
                let record = Record::from_rdata(rr_name, 300, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
                response.answers.push(record);
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

    /// 从缓存条目构造应答报文
    fn build_response_from_cache(&self, msg: &Message, entry: &CacheEntry) -> io::Result<Message> {
        let records = &entry.records;
        for record in records {
            if let CacheRecord::Block(ref block) = record {
                return match block {
                    BlockCache::NXDomain => self.build_nxdomain(msg),
                    BlockCache::Poison => {
                        let query = msg
                            .queries
                            .first()
                            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no question"))?;
                        let name = query.name().to_ascii().to_lowercase().trim_end_matches('.').to_string();
                        let qtype = u16::from(query.query_type());
                        self.build_poison(msg, &name, qtype)
                    }
                };
            }
        }

        let mut response = make_response_base(msg)?;
        let query = msg
            .queries
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no question"))?;
        let name = query.name().clone();
        let reply_ttl = entry.remaining_ttl(self.cache.keep_ttl);
        for record in records {
            let r = match record {
                CacheRecord::A(ip) => Record::from_rdata(name.clone(), reply_ttl, RData::A(A(*ip))),
                CacheRecord::Aaaa(ip) => Record::from_rdata(name.clone(), reply_ttl, RData::AAAA(AAAA(*ip))),
                CacheRecord::Https(wire) => {
                    let mut decoder = BinDecoder::new(wire);
                    Record::read(&mut decoder).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                }
                CacheRecord::Block(_) => continue,
            };
            response.answers.push(r);
        }

        Ok(response)
    }
}

/// 基本应答骨架
fn make_response_base(msg: &Message) -> io::Result<Message> {
    let mut response = Message::new(msg.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_available = true;
    if let Some(q) = msg.queries.first() {
        response.queries.push(q.clone());
    }
    Ok(response)
}

/// 从上游应答中提取可缓存的记录（A / AAAA / HTTPS），无匹配类型时返回 None
fn extract_cache_records(msg: &Message) -> Option<Vec<CacheRecord>> {
    let mut records = Vec::new();
    for answer in &msg.answers {
        match &answer.data {
            RData::A(ip) => records.push(CacheRecord::A(ip.0)),
            RData::AAAA(ip) => records.push(CacheRecord::Aaaa(ip.0)),
            RData::HTTPS(_data) => {
                records.push(CacheRecord::Https(Vec::new()));
            }
            _ => {}
        }
    }
    if records.is_empty() {
        None
    } else {
        Some(records)
    }
}

/// 取应答中所有记录的最小 TTL，空应答默认 300 秒
fn extract_min_ttl(msg: &Message) -> u32 {
    msg.answers.iter().map(|r| r.ttl).min().unwrap_or(300)
}

/// 将应答中所有记录的 TTL 改写为指定值
fn rewrite_ttl_in_response(msg: &mut Message, ttl: u32) {
    for answer in &mut msg.answers {
        answer.ttl = ttl;
    }
}

/// 将上游应答记录写入缓存
async fn cache_upstream_response(cache: &DnsCache, cache_key: &CacheKey, response: &Message, rewrite_ttl: Option<u32>) {
    if let Some(records) = extract_cache_records(response) {
        let ttl = extract_min_ttl(response);
        let final_ttl = rewrite_ttl.unwrap_or(ttl);
        cache.put(cache_key.clone(), records, final_ttl).await;
    }
}

/// 后台异步刷新缓存（serve_expired 使用）
async fn forward_to_upstream_bg(
    cache: &DnsCache,
    upstreams: &AHashMap<String, UpstreamGroup>,
    cache_key: &CacheKey,
    upstream: &str,
    rewrite_ttl: Option<u32>,
) -> io::Result<()> {
    let group = upstreams
        .get(upstream)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("upstream {} not found", upstream)))?;

    let response = group.query_bg(cache_key).await?;
    cache_upstream_response(cache, cache_key, &response, rewrite_ttl).await;
    Ok(())
}

/// 构造 CNAME 目标的子查询报文（默认 type=A，除非原查询是 AAAA）
fn build_cname_query(query: &Message, target: &str, qtype: u16) -> Message {
    let mut msg = query.clone();
    if let Ok(name) = Name::from_utf8(target) {
        let mut q = hickory_proto::op::Query::new();
        q.set_name(name);
        q.set_query_type(match qtype {
            28 => hickory_proto::rr::RecordType::AAAA,
            _ => hickory_proto::rr::RecordType::A,
        });
        q.set_query_class(DNSClass::IN);
        msg.queries.clear();
        msg.queries.push(q);
    }
    msg
}
