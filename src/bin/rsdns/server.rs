use ahash::AHashMap;
use bytes::{BufMut, BytesMut};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, HTTPS, MX, TXT};
use hickory_proto::rr::RData;
use hickory_proto::rr::{Name, Record, RecordType};
use log::{error, info, warn};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use std::os::fd::IntoRawFd;
use std::os::unix::io::FromRawFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, MissedTickBehavior};

use xray_rs::common::domain_trie::DomainSuffixTrie;

use super::cache::{CacheEntry, CacheKey, CacheRecord, CacheResult, DnsCache};
#[cfg(test)]
use super::config;
use super::config::LogConfig;
use super::factory::is_h3_cleanup_error;
use super::hosts::HostsTrie;
use super::rule::{BlockResponse, Rule, RuleAction};
use super::upstream::UpstreamGroup;

const MAX_DNS_SIZE: usize = 4096;

pub struct QueryLog<'a> {
    pub qtype: RecordType,
    pub name: String,
    pub proto: &'static str,
    pub remote: IpAddr,
    pub port: u16,
    pub size: usize,
    pub duration: Duration,
    pub rcode: ResponseCode,
    pub action: String,
    pub answers: &'a str,
}

/// 查询日志模板中的一个占位符字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Duration,
    Proto,
    Rcode,
    Name,
    QType,
    Port,
    Size,
    Action,
    Remote,
    Answers,
}

impl Field {
    /// 占位符名 → 字段；未识别的名字返回 `None`，原样保留为字面量。
    fn parse(key: &str) -> Option<Self> {
        Some(match key {
            "duration" => Self::Duration,
            "proto" => Self::Proto,
            "rcode" => Self::Rcode,
            "name" => Self::Name,
            "type" => Self::QType,
            "port" => Self::Port,
            "size" => Self::Size,
            "action" => Self::Action,
            "remote" => Self::Remote,
            "answers" => Self::Answers,
            _ => return None,
        })
    }
}

/// 预编译的模板：字面量段落与字段占位符交替。
/// 启动时由 [`compile_template`] 解析一次，此后每条查询只按序填充字段值。
#[derive(Debug, Clone)]
struct CompiledTemplate {
    segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Text(String),
    Field(Field),
}

/// 将用户模板预编译为段落序列，替代每次查询时的模板解析。
fn compile_template(template: &str) -> CompiledTemplate {
    let mut segments = Vec::new();
    let mut rest = template;
    let mut text = String::new();
    loop {
        let Some(start) = rest.find('{') else {
            text.push_str(rest);
            break;
        };
        text.push_str(&rest[..start]);
        rest = &rest[start + 1..];
        if let Some(end) = rest.find('}') {
            match Field::parse(&rest[..end]) {
                Some(field) => {
                    if !text.is_empty() {
                        segments.push(Segment::Text(std::mem::take(&mut text)));
                    }
                    segments.push(Segment::Field(field));
                }
                None => text.push_str(&format!("{{{}}}", &rest[..end])),
            }
            rest = &rest[end + 1..];
        } else {
            text.push('{');
            text.push_str(rest);
            break;
        }
    }
    if !text.is_empty() {
        segments.push(Segment::Text(text));
    }
    CompiledTemplate { segments }
}

impl QueryLog<'_> {
    /// 按预编译模板将字段填充进 `out`（先清空）。仅做段遍历与值写入，无模板解析。
    fn format_into(&self, template: &CompiledTemplate, out: &mut BytesMut) {
        out.clear();
        for segment in &template.segments {
            match segment {
                Segment::Text(t) => out.extend_from_slice(t.as_bytes()),
                Segment::Field(field) => match field {
                    Field::Duration => {
                        let _ = write!(out, "{:.5}", self.duration.as_secs_f64());
                    }
                    Field::Proto => out.extend_from_slice(self.proto.as_bytes()),
                    Field::Rcode => out.extend_from_slice(format_rcode(self.rcode).as_bytes()),
                    Field::Name => out.extend_from_slice(self.name.as_bytes()),
                    Field::QType => {
                        let _ = write!(out, "{}", self.qtype);
                    }
                    Field::Port => {
                        let _ = write!(out, "{}", self.port);
                    }
                    Field::Size => {
                        let _ = write!(out, "{}", self.size);
                    }
                    Field::Action => out.extend_from_slice(self.action.as_bytes()),
                    Field::Remote => match &self.remote {
                        IpAddr::V4(v4) => {
                            let _ = write!(out, "{}", v4);
                        }
                        IpAddr::V6(v6) => {
                            let _ = write!(out, "[{}]", v6);
                        }
                    },
                    Field::Answers => out.extend_from_slice(self.answers.as_bytes()),
                },
            }
        }
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

fn format_answer_types(msg: &Message, out: &mut String) {
    out.clear();
    for r in &msg.answers {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&r.record_type().to_string());
    }
    if out.is_empty() {
        out.push('-');
    }
}

fn flush_pending(pending: &mut BytesMut, writer: &mut Box<dyn Write + Send>) {
    if !pending.is_empty() {
        if let Err(e) = writer.write_all(pending) {
            warn!("query log write failed: {}", e);
        }
        pending.clear();
    }
}

/// 查询日志：预编译模板 + 异步 mpsc 写入 + `BytesMut` 累积缓冲 + 周期 flush 任务。
///
/// - 模板在 [`QueryLogger::new`] 时编译一次，热路径只做字段值填充。
/// - 每条日志通过 mpsc 投递给后台写任务，由写任务累积到 `buf_size` 字节或
///   `flush_interval` 到期才真正写盘，查询线程不被磁盘 IO 阻塞。
/// - [`QueryLogger::new`] 内部启动一个 tokio 周期 flush 任务。
/// - [`QueryLogger::flush`] 为异步方法，需 `await`；进程退出前调用以落盘剩余日志。
pub struct QueryLogger {
    template: CompiledTemplate,
    tx: mpsc::Sender<WriteMsg>,
}

enum WriteMsg {
    Line(BytesMut),
    /// 携带 oneshot 应答：后台写任务完成落盘后通知调用方，保证 flush 返回即已写盘。
    Flush(oneshot::Sender<()>),
}

impl QueryLogger {
    pub async fn new(cfg: &LogConfig) -> io::Result<Arc<Self>> {
        let mut writer: Box<dyn Write + Send> = match &cfg.file {
            Some(path) => Box::new(File::create(path)?),
            None => Box::new(std::io::stdout()),
        };

        let buf_size = cfg.buf_size.max(1);
        let flush_interval = Duration::from_secs(cfg.flush_interval_secs.unwrap_or(5));

        let channel_size = 1024; // 或 cfg.buf_size * 4
        let (tx, mut rx) = mpsc::channel::<WriteMsg>(channel_size);

        let logger = Arc::new(Self {
            template: compile_template(&cfg.format),
            tx,
        });

        tokio::spawn(async move {
            let mut pending = BytesMut::with_capacity(buf_size.min(64 * 1024));
            let mut timer = interval(flush_interval);
            timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        match msg {
                            Some(WriteMsg::Line(line)) => {
                                pending.put_slice(&line);
                                if pending.len() >= buf_size {
                                    flush_pending(&mut pending, &mut writer);
                                }
                            }
                            Some(WriteMsg::Flush(ack)) => {
                                flush_pending(&mut pending, &mut writer);
                                let _ = ack.send(());
                            }
                            None => break,
                        }
                    }
                    _ = timer.tick() => {
                        flush_pending(&mut pending, &mut writer);
                    }
                }
            }

            flush_pending(&mut pending, &mut writer);
        });

        Ok(logger)
    }

    pub async fn write(&self, qlog: &QueryLog<'_>) {
        let mut line = BytesMut::with_capacity(160);
        qlog.format_into(&self.template, &mut line);
        line.put_u8(b'\n');

        // 异步发送，通道满时会等待
        // 如果接收端关闭，会返回错误
        let _ = self.tx.send(WriteMsg::Line(line)).await;
    }

    pub async fn flush(&self) {
        let (ack, rx) = oneshot::channel();
        if self.tx.send(WriteMsg::Flush(ack)).await.is_ok() {
            // 等待后台任务完成写盘，确保 flush 返回时日志已落盘。
            let _ = rx.await;
        }
    }
}

pub struct DnsServer {
    hosts_trie: Arc<HostsTrie>,
    groups_trie: Arc<DomainSuffixTrie>,
    rules: Arc<Vec<Rule>>,
    cache: Arc<DnsCache>,
    upstreams: Arc<AHashMap<String, UpstreamGroup>>,
    logger: Arc<QueryLogger>,
}

impl DnsServer {
    pub fn new(
        hosts_trie: HostsTrie,
        groups_trie: DomainSuffixTrie,
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
        let socket = self.bind_udp_dual_stack(addr).await?;
        let socket = Arc::new(socket);
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
        let listener = self.bind_tcp_dual_stack(addr).await?;
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

        let mut name = query.name().to_lowercase().to_ascii();
        name.truncate(name.trim_end_matches('.').len());
        let qtype = query.query_type();

        let cache_key = CacheKey::new(name.clone(), qtype);
        let msg_id = msg.id;
        let (mut response, action) = self.do_query(&msg, &cache_key).await;
        response.metadata.id = msg_id;
        let elapsed = start.elapsed();

        let mut answers = String::new();
        format_answer_types(&response, &mut answers);
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
            answers: &answers,
        };
        self.logger.write(&qlog).await;
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
                    let resp = match response {
                        BlockResponse::NXDomain => self.build_nxdomain(msg),
                        BlockResponse::Poison => self.build_poison(msg, &cache_key.name, cache_key.qtype),
                    };
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
                RuleAction::Cname {
                    target,
                    ttl,
                    upstream,
                    deny_qtypes,
                } => {
                    match self
                        .handle_cname(msg, cache_key, target, *ttl, upstream, deny_qtypes)
                        .await
                    {
                        Ok(resp) => (resp, "cname".into()),
                        Err(e) => {
                            warn!("cname for {} -> {} failed: {}", cache_key.name, target, e);
                            (self.build_servfail(msg), "cname".into())
                        }
                    }
                }
                RuleAction::Forward {
                    upstream,
                    cache: use_cache,
                    ttl: rewrite_ttl,
                    deny_qtypes,
                } => {
                    self.handle_forward(msg, cache_key, upstream, *use_cache, *rewrite_ttl, deny_qtypes)
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
        deny_qtypes: &[RecordType],
    ) -> (Message, String) {
        let action_label = format!("forward({})", upstream);
        if deny_qtypes.contains(&cache_key.qtype) {
            return match self.build_nodata(msg) {
                Ok(resp) => (resp, format!("forward-nodata({})", upstream)),
                Err(e) => {
                    warn!("build_nodata for {} failed: {}", cache_key.name, e);
                    (self.build_servfail(msg), action_label)
                }
            };
        }
        if !use_cache {
            return match self.forward_to_upstream(msg, upstream, cache_key, rewrite_ttl).await {
                Ok(resp) => (resp, action_label),
                Err(e) => {
                    self.log_upstream_error("forward", cache_key.name.as_str(), upstream, &e);
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
                        if is_soft_upstream_error(&e) {
                            info!("background refresh for {} closed: {}", ck.name, e);
                        } else {
                            warn!("background refresh for {} failed: {}", ck.name, e);
                        }
                    }
                });
                (response, format!("forward-stale({})", upstream))
            }
            CacheResult::Miss => match self.forward_to_upstream(msg, upstream, cache_key, rewrite_ttl).await {
                Ok(resp) => (resp, action_label),
                Err(e) => {
                    self.log_upstream_error("forward", cache_key.name.as_str(), upstream, &e);
                    (self.build_servfail(msg), action_label)
                }
            },
        }
    }

    /// 查询上游 DNS 并缓存结果。
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

        let response = group.query(msg).await;

        match response {
            Ok(response) => {
                cache_upstream_response(&self.cache, cache_key, &response, rewrite_ttl).await;
                let mut response = response;
                if let Some(rttl) = rewrite_ttl {
                    rewrite_ttl_in_response(&mut response, rttl);
                }
                sort_answers_cname_last(&mut response.answers);
                Ok(response)
            }
            Err(e) => Err(e),
        }
    }

    /// 处理 CNAME 规则：返回 CNAME 记录，并通过指定 upstream 代查 target 的真实记录。
    /// 若上游查询失败，则仅返回 CNAME 记录作为降级。
    async fn handle_cname(
        &self,
        msg: &Message,
        cache_key: &CacheKey,
        target: &str,
        ttl: u32,
        upstream: &str,
        deny_qtypes: &[RecordType],
    ) -> io::Result<Message> {
        if deny_qtypes.contains(&cache_key.qtype) {
            return self.build_nodata(msg);
        }
        let query_name = msg.queries.first().map(|q| q.name().clone()).unwrap_or_default();
        let cname_name = Name::from_utf8(target).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let cname_record = Record::from_rdata(query_name.clone(), ttl, RData::CNAME(CNAME(cname_name)));

        let target_msg = make_query_msg(target, cache_key.qtype)?;
        let target_cache_key = CacheKey::new(target.to_string(), cache_key.qtype);

        let response = match self
            .forward_to_upstream(&target_msg, upstream, &target_cache_key, Some(ttl))
            .await
        {
            Ok(mut upstream_resp) => {
                upstream_resp.metadata.id = msg.id;
                upstream_resp.queries = msg.queries.clone();
                for answer in &mut upstream_resp.answers {
                    answer.name = query_name.clone();
                }
                upstream_resp
            }
            Err(e) => {
                warn!(
                    "cname resolve target {} for {} failed: {}, fallback to CNAME only",
                    target, cache_key.name, e
                );
                // 降级：仅返回 CNAME 记录
                let mut resp = make_response_base(msg)?;
                resp.answers.push(cname_record);
                resp.metadata.id = msg.id;
                resp
            }
        };

        Ok(response)
    }

    fn build_hosts_response(
        &self,
        msg: &Message,
        name: &str,
        qtype: RecordType,
        ips: &[IpAddr],
    ) -> io::Result<Message> {
        let mut response = make_response_base(msg)?;
        let rr_name = Name::from_utf8(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        for ip in ips {
            let record = match (ip, qtype) {
                (IpAddr::V4(v4), RecordType::A) | (IpAddr::V4(v4), RecordType::ANY) => {
                    Record::from_rdata(rr_name.clone(), 300, RData::A(A(*v4)))
                }
                (IpAddr::V6(v6), RecordType::AAAA) | (IpAddr::V6(v6), RecordType::ANY) => {
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

    fn build_poison(&self, msg: &Message, name: &str, qtype: RecordType) -> io::Result<Message> {
        let mut response = make_response_base(msg)?;
        let rr_name = Name::from_utf8(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        match qtype {
            RecordType::A | RecordType::ANY => {
                let record = Record::from_rdata(rr_name.clone(), 300, RData::A(A(Ipv4Addr::new(0, 0, 0, 0))));
                response.answers.push(record);
                response.metadata.response_code = ResponseCode::NoError;
            }
            _ => {
                response.metadata.response_code = ResponseCode::NoError;
            }
        }
        match qtype {
            RecordType::AAAA | RecordType::ANY => {
                let record = Record::from_rdata(rr_name, 300, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
                response.answers.push(record);
            }
            _ => {}
        }

        Ok(response)
    }

    fn build_servfail(&self, msg: &Message) -> Message {
        let mut response = Message::new(0, MessageType::Response, OpCode::Query);
        response.metadata = msg.metadata;
        response.metadata.message_type = MessageType::Response;
        response.metadata.response_code = ResponseCode::ServFail;
        response.queries = msg.queries.clone();
        response
    }

    fn build_nodata(&self, msg: &Message) -> io::Result<Message> {
        make_response_base(msg)
    }

    /// 绑定 UDP socket，若地址为 IPv6 则同时设置双栈（IPV6_V6ONLY=0），
    /// 使一个 socket 可同时处理 IPv4 和 IPv6 流量。
    async fn bind_udp_dual_stack(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = if addr.is_ipv6() {
            let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_only_v6(false)?;
            sock.set_reuse_address(true)?;
            sock.bind(&socket2::SockAddr::from(addr))?;
            sock.set_nonblocking(true)?;
            // SAFETY: sock is a valid fd we just created and configured
            let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(sock.into_raw_fd()) };
            UdpSocket::from_std(std_socket)?
        } else {
            UdpSocket::bind(addr).await?
        };
        Ok(socket)
    }

    /// 绑定 TCP listener，若地址为 IPv6 则设置双栈（IPV6_V6ONLY=0）。
    async fn bind_tcp_dual_stack(&self, addr: SocketAddr) -> io::Result<TcpListener> {
        let listener = if addr.is_ipv6() {
            let sock = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
            sock.set_only_v6(false)?;
            sock.set_reuse_address(true)?;
            sock.bind(&socket2::SockAddr::from(addr))?;
            sock.listen(1024)?;
            sock.set_nonblocking(true)?;
            // SAFETY: sock is a valid fd we just created and configured
            let std_listener = unsafe { std::net::TcpListener::from_raw_fd(sock.into_raw_fd()) };
            TcpListener::from_std(std_listener)?
        } else {
            TcpListener::bind(addr).await?
        };
        Ok(listener)
    }

    fn log_upstream_error(&self, op: &str, name: &str, upstream: &str, err: &io::Error) {
        if is_soft_upstream_error(err) {
            info!("{} {} to upstream {} closed: {}", op, name, upstream, err);
        } else {
            warn!("{} {} to upstream {} failed: {}", op, name, upstream, err);
        }
    }

    /// 从缓存条目构造应答报文
    fn build_response_from_cache(&self, msg: &Message, entry: &CacheEntry) -> io::Result<Message> {
        let mut response = make_response_base(msg)?;
        let query = msg
            .queries
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no question"))?;
        let name = query.name().clone();
        let reply_ttl = entry.remaining_ttl(self.cache.keep_ttl);
        let records = &entry.records;
        for record in records.iter() {
            let r = match record {
                CacheRecord::A(ip) => Record::from_rdata(name.clone(), reply_ttl, RData::A(A(*ip))),
                CacheRecord::Aaaa(ip) => Record::from_rdata(name.clone(), reply_ttl, RData::AAAA(AAAA(*ip))),
                CacheRecord::Cname(target) => {
                    let cname_name =
                        Name::from_utf8(target).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    Record::from_rdata(name.clone(), reply_ttl, RData::CNAME(CNAME(cname_name)))
                }
                CacheRecord::Mx { preference, exchange } => {
                    let exchange_name =
                        Name::from_utf8(exchange).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    Record::from_rdata(name.clone(), reply_ttl, RData::MX(MX::new(*preference, exchange_name)))
                }
                CacheRecord::Txt(txt_data) => {
                    Record::from_rdata(name.clone(), reply_ttl, RData::TXT(TXT::new(txt_data.clone())))
                }
                CacheRecord::Https(svcb) => {
                    Record::from_rdata(name.clone(), reply_ttl, RData::HTTPS(HTTPS(svcb.clone())))
                }
                CacheRecord::NxDomain => continue,
            };
            response.answers.push(r);
        }

        if let Some(CacheRecord::NxDomain) = records.first() {
            response.metadata.response_code = ResponseCode::NXDomain;
        }

        sort_answers_cname_last(&mut response.answers);

        Ok(response)
    }
}
fn is_soft_upstream_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
    ) || is_h3_cleanup_error(&err.to_string())
}

/// 构造一个用于上游查询的 DNS Message
pub(crate) fn make_query_msg(name: &str, qtype: RecordType) -> io::Result<Message> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(Name::from_utf8(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);
    q.set_query_type(qtype);
    q.set_query_class(hickory_proto::rr::DNSClass::IN);
    msg.queries.push(q);
    msg.metadata.recursion_desired = true;
    Ok(msg)
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

/// 将 CNAME 记录排序到最后面，A/AAAA 等其他类型排在前面。
/// 这样客户端优先获得直接地址记录。
fn sort_answers_cname_last(answers: &mut [Record]) {
    answers.sort_by_key(|r| matches!(r.data, RData::CNAME(_)));
}

/// 从上游应答中提取可缓存的记录（A / AAAA / CNAME / MX / TXT / HTTPS）
fn extract_cache_records(msg: &Message) -> Option<Vec<CacheRecord>> {
    let mut records = Vec::new();
    for answer in &msg.answers {
        match &answer.data {
            RData::A(ip) => records.push(CacheRecord::A(ip.0)),
            RData::AAAA(ip) => records.push(CacheRecord::Aaaa(ip.0)),
            RData::CNAME(cname) => records.push(CacheRecord::Cname(cname.0.to_ascii())),
            RData::MX(mx) => records.push(CacheRecord::Mx {
                preference: mx.preference,
                exchange: mx.exchange.to_ascii(),
            }),
            RData::TXT(txt) => {
                let strings: Vec<String> = txt
                    .txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect();
                records.push(CacheRecord::Txt(strings))
            }
            RData::HTTPS(https) => records.push(CacheRecord::Https(https.0.clone())),
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

/// 将上游应答记录写入缓存（包括正常记录和 NXDOMAIN 负缓存）
async fn cache_upstream_response(cache: &DnsCache, cache_key: &CacheKey, response: &Message, rewrite_ttl: Option<u32>) {
    if let Some(records) = extract_cache_records(response) {
        let ttl = extract_min_ttl(response);
        let final_ttl = rewrite_ttl.unwrap_or(ttl);
        cache.put(cache_key.clone(), records, final_ttl).await;
        return;
    }

    let rcode = response.metadata.response_code;
    let negative_record = match rcode {
        ResponseCode::NXDomain => Some(CacheRecord::NxDomain),
        _ => None,
    };

    if let Some(record) = negative_record {
        let ttl = extract_min_ttl(response);
        let final_ttl = rewrite_ttl.unwrap_or(ttl);
        cache.put(cache_key.clone(), vec![record], final_ttl).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_template() -> CompiledTemplate {
        compile_template(r#"{remote} {name} "{type}" [{answers}] "{action}" {duration}s"#)
    }

    fn sample_qlog<'a>(answers: &'a str) -> QueryLog<'a> {
        QueryLog {
            qtype: RecordType::A,
            name: "www.example.com".into(),
            proto: "udp",
            remote: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            port: 5353,
            size: 29,
            duration: Duration::from_micros(1250),
            rcode: ResponseCode::NoError,
            action: "forward(default)".into(),
            answers,
        }
    }

    fn render(qlog: &QueryLog, template: &CompiledTemplate) -> String {
        let mut out = BytesMut::new();
        qlog.format_into(template, &mut out);
        String::from_utf8(out.to_vec()).unwrap()
    }

    #[test]
    fn test_compile_template_parses_placeholders() {
        let t = compile_template("{name} {type} {port} {size} {duration} {rcode} {remote} {action} {proto} {answers}");
        assert_eq!(
            t.segments,
            vec![
                Segment::Field(Field::Name),
                Segment::Text(" ".into()),
                Segment::Field(Field::QType),
                Segment::Text(" ".into()),
                Segment::Field(Field::Port),
                Segment::Text(" ".into()),
                Segment::Field(Field::Size),
                Segment::Text(" ".into()),
                Segment::Field(Field::Duration),
                Segment::Text(" ".into()),
                Segment::Field(Field::Rcode),
                Segment::Text(" ".into()),
                Segment::Field(Field::Remote),
                Segment::Text(" ".into()),
                Segment::Field(Field::Action),
                Segment::Text(" ".into()),
                Segment::Field(Field::Proto),
                Segment::Text(" ".into()),
                Segment::Field(Field::Answers),
            ]
        );
    }

    #[test]
    fn test_unknown_and_unclosed_placeholders_kept_as_literal() {
        let t = compile_template("a{unknown}b{");
        assert_eq!(t.segments, vec![Segment::Text("a{unknown}b{".into())]);
        // 混合：已知字段正常解析，未知/孤立花括号保留为字面量
        let t = compile_template("{name} {bogus} {");
        assert_eq!(
            t.segments,
            vec![Segment::Field(Field::Name), Segment::Text(" {bogus} {".into()),]
        );
    }

    #[test]
    fn test_render_default_template() {
        let t = test_template();
        let qlog = sample_qlog("A");
        let line = render(&qlog, &t);
        assert_eq!(line, r#"192.168.1.100 www.example.com "A" [A] "forward(default)" 0.00125s"#);
    }

    #[test]
    fn test_render_ipv6_brackets() {
        let t = compile_template("{remote}:{port}");
        let qlog = QueryLog {
            remote: IpAddr::V6("2001:db8::1".parse().unwrap()),
            port: 53,
            ..sample_qlog("A")
        };
        assert_eq!(render(&qlog, &t), "[2001:db8::1]:53");
    }

    #[test]
    fn test_render_unknown_rcode_and_no_answers() {
        let t = compile_template("{rcode} [{answers}]");
        let qlog = QueryLog {
            rcode: ResponseCode::BADVERS,
            answers: "-",
            ..sample_qlog("-")
        };
        assert_eq!(render(&qlog, &t), "UNKNOWN [-]");
    }

    #[test]
    fn test_format_answer_types_empty() {
        let mut out = String::new();
        let msg = Message::new(0, MessageType::Response, OpCode::Query);
        format_answer_types(&msg, &mut out);
        assert_eq!(out, "-");
    }

    #[tokio::test]
    async fn test_logger_writes_and_flushes() {
        // 临时文件：验证异步写盘 + flush 真正将行落盘。
        let path = std::env::temp_dir().join(format!("rsdns-qlog-write-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cfg = config::LogConfig {
            format: "{name} {type} {rcode}".into(),
            file: Some(path.to_string_lossy().into_owned()),
            buf_size: 4096,
            flush_interval_secs: Some(5),
        };
        let logger = QueryLogger::new(&cfg).await.unwrap();
        logger.write(&sample_qlog("A")).await;
        logger.write(&sample_qlog("A")).await;
        logger.flush().await;
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "www.example.com A NOERROR\nwww.example.com A NOERROR\n");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_logger_multiple_flushes_are_ordered() {
        let path = std::env::temp_dir().join(format!("rsdns-qlog-flush-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cfg = config::LogConfig {
            format: "{name}".into(),
            file: Some(path.to_string_lossy().into_owned()),
            buf_size: 4096,
            flush_interval_secs: Some(5),
        };
        let logger = QueryLogger::new(&cfg).await.unwrap();
        for _ in 0..3 {
            logger.write(&sample_qlog("A")).await;
            logger.flush().await;
        }
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "www.example.com\nwww.example.com\nwww.example.com\n");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_logger_flushes_when_buf_size_reached() {
        // buf_size 很小：写一条即达到阈值，无需 flush 或等待 interval 即可落盘。
        let path = std::env::temp_dir().join(format!("rsdns-qlog-bufsize-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cfg = config::LogConfig {
            format: "{name}".into(),
            file: Some(path.to_string_lossy().into_owned()),
            buf_size: 10,
            flush_interval_secs: Some(3600),
        };
        let logger = QueryLogger::new(&cfg).await.unwrap();
        logger.write(&sample_qlog("A")).await;
        // 后台写任务达到 buf_size 即写盘；轮询等待文件出现。
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let content = loop {
            // 文件在 `new()` 中即被创建，可能为空；须等到内容非空才算落盘。
            if let Ok(content) = std::fs::read_to_string(&path) {
                if !content.is_empty() {
                    break content;
                }
            }
            if std::time::Instant::now() > deadline {
                panic!("timed out waiting for query log flush");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(content, "www.example.com\n");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_logger_flushes_on_configured_interval() {
        // flush_interval 很短：即使未达到 buf_size，也会按时落盘。
        let path = std::env::temp_dir().join(format!("rsdns-qlog-interval-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cfg = config::LogConfig {
            format: "{name}".into(),
            file: Some(path.to_string_lossy().into_owned()),
            buf_size: 64 * 1024,
            flush_interval_secs: Some(1),
        };
        let logger = QueryLogger::new(&cfg).await.unwrap();
        logger.write(&sample_qlog("A")).await;
        // 不调用 flush：等待 flush 任务按 interval 落盘。
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "www.example.com\n");
        let _ = std::fs::remove_file(&path);
    }
}
