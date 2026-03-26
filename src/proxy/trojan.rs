use super::*;
use crate::common::parse;
use log::{debug, error, warn};
use sha2::{Digest, Sha224};
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const TROJAN_HASH_LEN: usize = 56; // SHA224 hex
const TROJAN_HEADER_LEN: usize = TROJAN_HASH_LEN + 2; // hash + CRLF
const TROJAN_CRLF: [u8; 2] = *b"\r\n";
const TROJAN_CMD_CONNECT: u8 = 0x01;
const TROJAN_CMD_UDP_ASSOCIATE: u8 = 0x03;

#[derive(Serialize, Deserialize, Debug)]
pub struct InSetting {
    #[serde(rename = "password")]
    password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutSetting {
    #[serde(rename = "address")]
    pub address: String,

    #[serde(rename = "port")]
    pub port: u16,

    #[serde(rename = "password")]
    pub password: String,
}

pub struct Proxy {
    password_hash: String,
    server: Address,
    tr: transport::Transport,
}

struct TrojanUdpStream {
    inner: transport::TrStream,
    // 当前实现采用“单 stream 固定单目标”的 UDP-over-stream 简化语义：
    // 同一条 Trojan UDP stream 上所有写出的 frame 都编码为同一个 target。
    // 这满足当前 sink/app 的固定目标转发模型，但不是 tj.md 意义上“每个包可切换目标”的完整语义。
    target: Address,
    read_raw: Vec<u8>,
    read_payload: Vec<u8>,
    read_payload_pos: usize,
    write_frame: Vec<u8>,
    write_frame_pos: usize,
    pending_input_len: usize,
}

impl TrojanUdpStream {
    fn new(inner: transport::TrStream, target: Address) -> Self {
        Self {
            inner,
            target,
            read_raw: Vec::new(),
            read_payload: Vec::new(),
            read_payload_pos: 0,
            write_frame: Vec::new(),
            write_frame_pos: 0,
            pending_input_len: 0,
        }
    }

    fn queue_payload(&mut self, payload: Vec<u8>) {
        self.read_payload = payload;
        self.read_payload_pos = 0;
    }

    fn flush_payload_to_buf(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_payload_pos >= self.read_payload.len() {
            self.read_payload.clear();
            self.read_payload_pos = 0;
            return false;
        }

        let remaining = &self.read_payload[self.read_payload_pos..];
        let to_copy = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..to_copy]);
        self.read_payload_pos += to_copy;

        if self.read_payload_pos >= self.read_payload.len() {
            self.read_payload.clear();
            self.read_payload_pos = 0;
        }

        true
    }

    fn drain_complete_udp_frame(&mut self) -> std::io::Result<bool> {
        match parse_trojan_udp_packet(&self.read_raw)? {
            Some((_addr, payload, consumed)) => {
                self.read_raw.drain(..consumed);
                self.queue_payload(payload);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl AsyncRead for TrojanUdpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        loop {
            if self.flush_payload_to_buf(buf) {
                return Poll::Ready(Ok(()));
            }

            match self.drain_complete_udp_frame() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }

            let mut temp = [0u8; 8192];
            let mut temp_buf = ReadBuf::new(&mut temp);

            match Pin::new(&mut self.inner).poll_read(cx, &mut temp_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = temp_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }

                    self.read_raw.extend_from_slice(filled);
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for TrojanUdpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if self.write_frame.is_empty() {
            match build_trojan_udp_packet(&self.target, buf) {
                Ok(frame) => {
                    self.pending_input_len = buf.len();
                    self.write_frame = frame;
                    self.write_frame_pos = 0;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        while self.write_frame_pos < self.write_frame.len() {
            let start = self.write_frame_pos;
            let frame = std::mem::take(&mut self.write_frame);
            let chunk = &frame[start..];

            match Pin::new(&mut self.inner).poll_write(cx, chunk) {
                Poll::Ready(Ok(0)) => {
                    self.write_frame = frame;
                    return Poll::Ready(Err(Error::new(ErrorKind::WriteZero, "failed to write trojan udp frame")));
                }
                Poll::Ready(Ok(n)) => {
                    self.write_frame_pos += n;
                    if start + n < frame.len() {
                        self.write_frame = frame;
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.write_frame = frame;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.write_frame = frame;
                    return Poll::Pending;
                }
            }
        }

        let written = self.pending_input_len;
        self.write_frame.clear();
        self.write_frame_pos = 0;
        self.pending_input_len = 0;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Proxy {
    pub fn new_inbound(sets: &InSetting, tr: transport::Transport) -> Result<Self> {
        Ok(Self {
            password_hash: compute_password_hash(&sets.password),
            server: Address::Inet(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::LOCALHOST,
                0,
            ))),
            tr,
        })
    }

    pub fn new_outbound(
        sets: &OutSetting,
        tr: transport::Transport,
        _dns: std::sync::Arc<crate::route::DnsResolver>,
    ) -> Result<Self> {
        Ok(Self {
            password_hash: compute_password_hash(&sets.password),
            server: Address::try_from((&sets.address.as_str(), Some(sets.port)))?,
            tr,
        })
    }

    pub async fn listen(self, addr: Address) -> BoxStream<ProxyStream, std::io::Error> {
        let stream_result = self.tr.listen(&addr).await;

        match stream_result {
            Ok(transport_stream) => {
                let password_hash = self.password_hash.clone();

                let proxy_stream = async_stream::stream! {
                    tokio::pin!(transport_stream);

                    while let Some(result) = tokio_stream::StreamExt::next(&mut transport_stream).await {
                        match result {
                            Ok((stream, peer_addr)) => {
                                match handle_inbound(stream, peer_addr, &password_hash).await {
                                    Ok(ps) => yield Ok(ps),
                                    Err(e) => yield Err(e),
                                }
                            }
                            Err(e) => yield Err(e),
                        }
                    }
                };
                Box::pin(proxy_stream)
            }
            Err(e) => Box::pin(tokio_stream::once(Err(e))),
        }
    }

    pub async fn connect(&self, target: &Address, protocol: Protocol) -> std::io::Result<transport::TrStream> {
        debug!(
            "[Trojan][connect] dialing server={:?}, target={:?}, protocol={:?}",
            self.server, target, protocol
        );
        let mut stream = self.tr.connect(&self.server, Protocol::Tcp).await?;
        debug!(
            "[Trojan][connect] transport connected to server={:?}, sending request for target={:?}",
            self.server, target
        );
        let cmd = match protocol {
            Protocol::Tcp => TROJAN_CMD_CONNECT,
            Protocol::Udp => TROJAN_CMD_UDP_ASSOCIATE,
        };

        send_trojan_request(&mut stream, &self.password_hash, cmd, target).await?;
        debug!("[Trojan][connect] request sent cmd=0x{:02x}, target={:?}", cmd, target);

        if protocol == Protocol::Udp {
            Ok(transport::TrStream::Tun(Box::new(TrojanUdpStream::new(stream, target.clone()))))
        } else {
            Ok(stream)
        }
    }

    pub async fn run(&mut self) {}
}

pub fn compute_password_hash(password: &str) -> String {
    Sha224::digest(password.as_bytes())
        .iter()
        .map(|x| format!("{:02x}", x))
        .collect::<String>()
}

async fn handle_inbound(
    mut stream: transport::TrStream,
    peer_addr: Address,
    expected_hash: &str,
) -> std::io::Result<ProxyStream> {
    debug!("[Trojan][inbound] accepted peer={:?}", peer_addr);
    let mut header = [0u8; TROJAN_HEADER_LEN];
    AsyncReadExt::read_exact(&mut stream, &mut header).await?;

    if header[TROJAN_HASH_LEN..] != TROJAN_CRLF {
        error!(
            "[Trojan][inbound] peer={:?} invalid header: missing CRLF after password hash",
            peer_addr
        );
        return Err(Error::new(ErrorKind::InvalidData, "Missing CRLF after trojan password hash"));
    }

    let received_hash = std::str::from_utf8(&header[..TROJAN_HASH_LEN])
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid hash encoding"))?;

    if let Err(e) = verify_password(received_hash, expected_hash) {
        warn!(
            "[Trojan][inbound] peer={:?} password mismatch hash_prefix={} err={}",
            peer_addr,
            &received_hash[..received_hash.len().min(8)],
            e
        );
        return Err(e);
    }
    debug!(
        "[Trojan][inbound] peer={:?} password verified hash_prefix={}",
        peer_addr,
        &received_hash[..received_hash.len().min(8)]
    );

    let cmd = read_command(&mut stream).await?;
    debug!("[Trojan][inbound] peer={:?} cmd=0x{:02x}", peer_addr, cmd);
    let dest = read_target_address(&mut stream).await?;
    debug!(
        "[Trojan][inbound] peer={:?} target={:?} after cmd=0x{:02x}",
        peer_addr, dest, cmd
    );
    read_crlf(&mut stream, "trojan request").await?;

    let protocol = match cmd {
        TROJAN_CMD_CONNECT => Protocol::Tcp,
        TROJAN_CMD_UDP_ASSOCIATE => Protocol::Udp,
        _ => {
            error!("[Trojan][inbound] peer={:?} unsupported cmd=0x{:02x}", peer_addr, cmd);
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Unsupported trojan command: {}", cmd),
            ));
        }
    };

    let stream = if protocol == Protocol::Udp {
        transport::TrStream::Tun(Box::new(TrojanUdpStream::new(stream, dest.clone())))
    } else {
        stream
    };

    debug!(
        "[Trojan][inbound] peer={:?} established protocol={:?} target={:?}",
        peer_addr, protocol, dest
    );
    Ok(ProxyStream::new(protocol, peer_addr, dest, stream))
}

fn verify_password(received: &str, expected: &str) -> std::io::Result<()> {
    if received != expected {
        Err(Error::new(ErrorKind::PermissionDenied, "Invalid trojan password"))
    } else {
        Ok(())
    }
}

async fn read_command(stream: &mut transport::TrStream) -> std::io::Result<u8> {
    let mut cmd = [0u8; 1];
    AsyncReadExt::read_exact(stream, &mut cmd).await?;
    Ok(cmd[0])
}

async fn read_crlf(stream: &mut transport::TrStream, context: &str) -> std::io::Result<()> {
    let mut crlf = [0u8; 2];
    AsyncReadExt::read_exact(stream, &mut crlf).await?;

    if crlf != TROJAN_CRLF {
        return Err(Error::new(ErrorKind::InvalidData, format!("Missing CRLF after {}", context)));
    }

    Ok(())
}

async fn read_target_address(stream: &mut transport::TrStream) -> std::io::Result<Address> {
    let mut atyp = [0u8; 1];
    AsyncReadExt::read_exact(stream, &mut atyp).await?;

    let mut data = vec![atyp[0]];
    match atyp[0] {
        0x01 => {
            let mut rest = [0u8; 6];
            AsyncReadExt::read_exact(stream, &mut rest).await?;
            data.extend_from_slice(&rest);
        }
        0x03 => {
            let mut len = [0u8; 1];
            AsyncReadExt::read_exact(stream, &mut len).await?;
            data.push(len[0]);
            let mut rest = vec![0u8; len[0] as usize + 2];
            AsyncReadExt::read_exact(stream, &mut rest).await?;
            data.extend_from_slice(&rest);
        }
        0x04 => {
            let mut rest = [0u8; 18];
            AsyncReadExt::read_exact(stream, &mut rest).await?;
            data.extend_from_slice(&rest);
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, format!("Invalid address type: {}", atyp[0]))),
    }

    let (addr, _) = parse::parse_address_from_bytes(&data)?;
    Ok(addr)
}

fn parse_trojan_udp_packet(packet: &[u8]) -> std::io::Result<Option<(Address, Vec<u8>, usize)>> {
    let addr_total_len = match trojan_udp_addr_total_len(packet) {
        Some(len) => len,
        None => return Ok(None),
    };

    let (addr, addr_len) = parse::parse_address_from_bytes(&packet[..addr_total_len])?;
    debug_assert_eq!(addr_len, addr_total_len);

    let header_len = addr_len + 2 + TROJAN_CRLF.len();
    if packet.len() < header_len {
        return Ok(None);
    }

    let length_offset = addr_len;
    let payload_len = u16::from_be_bytes([packet[length_offset], packet[length_offset + 1]]) as usize;

    let crlf_offset = length_offset + 2;
    if packet[crlf_offset..crlf_offset + 2] != TROJAN_CRLF {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid Trojan UDP CRLF delimiter"));
    }

    let payload_offset = crlf_offset + 2;
    let consumed = payload_offset + payload_len;
    if packet.len() < consumed {
        return Ok(None);
    }

    Ok(Some((addr, packet[payload_offset..consumed].to_vec(), consumed)))
}

fn trojan_udp_addr_total_len(packet: &[u8]) -> Option<usize> {
    let atyp = *packet.first()?;
    match atyp {
        0x01 => {
            let total = 1 + 4 + 2;
            (packet.len() >= total).then_some(total)
        }
        0x03 => {
            let domain_len = *packet.get(1)? as usize;
            let total = 1 + 1 + domain_len + 2;
            (packet.len() >= total).then_some(total)
        }
        0x04 => {
            let total = 1 + 16 + 2;
            (packet.len() >= total).then_some(total)
        }
        _ => None,
    }
}

fn build_trojan_udp_packet(target: &Address, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(Error::new(ErrorKind::InvalidInput, "Trojan UDP payload too large"));
    }

    let mut packet = parse::encode_address_to_bytes(target)?;
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(&TROJAN_CRLF);
    packet.extend_from_slice(payload);
    Ok(packet)
}

async fn send_trojan_request(
    stream: &mut transport::TrStream,
    password_hash: &str,
    cmd: u8,
    target: &Address,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(password_hash.as_bytes());
    buf.extend_from_slice(&TROJAN_CRLF);
    buf.push(cmd);

    let addr_bytes = parse::encode_address_to_bytes(target)?;
    buf.extend_from_slice(&addr_bytes);
    buf.extend_from_slice(&TROJAN_CRLF);

    debug!(
        "[Trojan][connect] encoded request cmd=0x{:02x}, target={:?}, hash_prefix={}, bytes={}",
        cmd,
        target,
        &password_hash[..password_hash.len().min(8)],
        buf.len()
    );
    AsyncWriteExt::write_all(stream, &buf).await?;
    AsyncWriteExt::flush(stream).await?;
    Ok(())
}
