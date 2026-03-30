use super::*;
use crate::common;
use crate::common::socks::Socks5Processor;
use ahash::RandomState;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

pub struct UdpState {
    socket: Arc<UdpSocket>,
    pub sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession, RandomState>>>,
}

impl UdpState {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            sessions: Arc::new(Mutex::new(HashMap::with_hasher(RandomState::new()))),
        }
    }

    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

pub struct UdpFrame {
    pub target: Address,
    pub data: Vec<u8>,
}

pub struct UdpSession {
    pub client_addr: SocketAddr,
    pub last_activity: Instant,
    pub cancel_token: CancellationToken,
    pub outbound_sockets: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>, RandomState>>>,
    pub stream_tx: Option<mpsc::Sender<UdpFrame>>,
}

impl UdpSession {
    pub fn new(client_addr: SocketAddr) -> Self {
        Self {
            client_addr,
            last_activity: Instant::now(),
            cancel_token: CancellationToken::new(),
            outbound_sockets: Arc::new(Mutex::new(HashMap::with_hasher(RandomState::new()))),
            stream_tx: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
}

pub enum ProxyMode {
    Inbound {
        account: Option<common::Account>,
        udp: bool,
        udp_state: Option<Arc<UdpState>>,
    },
    Outbound {
        server: ServerConfig,
        account: Option<common::Account>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InSetting {
    #[serde(rename = "account")]
    pub account: Option<common::Account>,

    #[serde(rename = "udp")]
    pub udp: Option<bool>,

    #[serde(rename = "ip")]
    pub ip: Option<String>,
}

impl Default for InSetting {
    fn default() -> Self {
        Self {
            account: None,
            udp: None,
            ip: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutSetting {
    #[serde(rename = "address")]
    pub address: String,

    #[serde(rename = "port")]
    pub port: u16,

    #[serde(rename = "account")]
    pub account: Option<common::Account>,
}

struct SocksUdpStream {
    inner: transport::TrStream,
    target: Address,
    read_raw: Vec<u8>,
    read_payload: Vec<u8>,
    read_payload_pos: usize,
    write_frame: Vec<u8>,
    write_frame_pos: usize,
    pending_input_len: usize,
}

impl SocksUdpStream {
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
        match parse_socks5_udp_packet_partial(&self.read_raw)? {
            Some((_addr, payload, consumed)) => {
                self.read_raw.drain(..consumed);
                self.queue_payload(payload);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl AsyncRead for SocksUdpStream {
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

impl AsyncWrite for SocksUdpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if self.write_frame.is_empty() {
            let target = self.target.clone();
            if let Err(e) = build_socks5_udp_packet_into(&target, buf, &mut self.write_frame) {
                return Poll::Ready(Err(e));
            }
            self.pending_input_len = buf.len();
            self.write_frame_pos = 0;
        }

        while self.write_frame_pos < self.write_frame.len() {
            let this = &mut *self;
            let chunk = &this.write_frame[this.write_frame_pos..];
            match Pin::new(&mut this.inner).poll_write(cx, chunk) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write socks udp frame",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_frame_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
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

struct SocksInboundUdpStream {
    control: transport::TrStream,
    rx: mpsc::Receiver<UdpFrame>,
    read_frame: Vec<u8>,
    read_pos: usize,
    client_addr: SocketAddr,
    udp_state: Arc<UdpState>,
    default_target: Address,
    write_frame: Vec<u8>,
    write_frame_pos: usize,
    pending_input_len: usize,
}

impl SocksInboundUdpStream {
    fn new(
        control: transport::TrStream,
        rx: mpsc::Receiver<UdpFrame>,
        client_addr: SocketAddr,
        udp_state: Arc<UdpState>,
        default_target: Address,
        initial_payload: Option<Vec<u8>>,
    ) -> Self {
        Self {
            control,
            rx,
            read_frame: initial_payload.unwrap_or_default(),
            read_pos: 0,
            client_addr,
            udp_state,
            default_target,
            write_frame: Vec::new(),
            write_frame_pos: 0,
            pending_input_len: 0,
        }
    }
}

impl Drop for SocksInboundUdpStream {
    fn drop(&mut self) {
        let client_addr = self.client_addr;
        let udp_state = self.udp_state.clone();
        tokio::spawn(async move {
            udp_state.sessions.lock().await.remove(&client_addr);
        });
    }
}

impl AsyncRead for SocksInboundUdpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.read_pos < self.read_frame.len() {
            let remaining = &self.read_frame[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_frame.len() {
                self.read_frame.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(frame)) => {
                let mut payload = frame.data;
                let to_copy = payload.len().min(buf.remaining());
                buf.put_slice(&payload[..to_copy]);
                if to_copy < payload.len() {
                    self.read_frame = payload.split_off(to_copy);
                    self.read_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SocksInboundUdpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if self.write_frame.is_empty() {
            let default_target = self.default_target.clone();
            if let Err(e) = build_socks5_udp_packet_into(&default_target, buf, &mut self.write_frame) {
                return Poll::Ready(Err(e));
            }
            self.pending_input_len = buf.len();
            self.write_frame_pos = 0;
        }

        while self.write_frame_pos < self.write_frame.len() {
            let this = &mut *self;
            let chunk = &this.write_frame[this.write_frame_pos..];
            match this.udp_state.socket().poll_send_to(cx, chunk, this.client_addr) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to send inbound socks udp frame",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_frame_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let written = self.pending_input_len;
        self.write_frame.clear();
        self.write_frame_pos = 0;
        self.pending_input_len = 0;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.control).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.control).poll_shutdown(cx)
    }
}

pub struct Proxy {
    tr: transport::Transport,
    mode: ProxyMode,
}

impl Proxy {
    pub fn new_inbound(set: &InSetting, tr: transport::Transport) -> Result<Self> {
        Ok(Self {
            tr,
            mode: ProxyMode::Inbound {
                account: set.account.clone(),
                udp: set.udp.unwrap_or(false),
                udp_state: None, // Will be initialized in listen()
            },
        })
    }

    pub fn new_outbound(set: &OutSetting, tr: transport::Transport) -> Result<Self> {
        let server = ServerConfig {
            address: set.address.clone(),
            port: set.port,
        };

        Ok(Self {
            tr,
            mode: ProxyMode::Outbound {
                server: server.clone(),
                account: set.account.clone(),
            },
        })
    }

    /// Establish outbound connection to target through SOCKS5 proxy
    pub async fn connect(&self, target: &Address, protocol: Protocol) -> std::io::Result<transport::TrStream> {
        if let ProxyMode::Outbound { server, account } = &self.mode {
            let server_addr = Address::Domain(server.address.clone(), server.port);
            let mut stream = self.tr.connect(&server_addr, Protocol::Tcp).await?;

            let processor = Socks5Processor::new(account.clone());
            processor
                .handshake(&mut stream)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Handshake failed: {}", e)))?;

            match protocol {
                Protocol::Tcp => {
                    send_connect_request(&mut stream, target).await?;
                    recv_connect_reply(&mut stream).await?;
                    Ok(stream)
                }
                Protocol::Udp => {
                    send_udp_associate_request(&mut stream, target).await?;
                    recv_connect_reply(&mut stream).await?;
                    Ok(transport::TrStream::Tun(Box::new(SocksUdpStream::new(stream, target.clone()))))
                }
            }
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "connect() called on inbound proxy",
            ))
        }
    }

    /// Run background tasks for outbound proxy (no-op for SOCKS5)
    pub async fn run(&mut self) {
        // Outbound mode doesn't need background tasks
        // UDP Associate is established on-demand via ensure_udp_associate()
    }

    pub async fn listen(self, addr: Address) -> BoxStream<ProxyStream, std::io::Error> {
        // Check if UDP is enabled
        let udp_enabled = match &self.mode {
            ProxyMode::Inbound { udp, .. } => *udp,
            _ => false,
        };

        if udp_enabled {
            // UDP-enabled mode: bind shared port and handle both TCP and UDP
            self.listen_with_udp(addr).await
        } else {
            // TCP-only mode: use original logic
            self.listen_tcp_only(addr).await
        }
    }

    /// Listen in TCP-only mode (original behavior)
    async fn listen_tcp_only(self, addr: Address) -> BoxStream<ProxyStream, std::io::Error> {
        let stream_result = self.tr.listen(&addr).await;
        log::info!("socks5 start Listening on {:?}", addr);
        match stream_result {
            Ok(transport_stream) => {
                // Extract account from mode
                let account = match &self.mode {
                    ProxyMode::Inbound { account, .. } => account.clone(),
                    ProxyMode::Outbound { .. } => None,
                };

                let proxy_stream = async_stream::stream! {
                    tokio::pin!(transport_stream);

                    while let Some(result) = tokio_stream::StreamExt::next(&mut transport_stream).await {
                        match result {
                            Ok((stream, peer_addr)) => {
                                match Self::handle_connection(stream, peer_addr, account.clone()).await {
                                    Ok(ps) => yield Ok(ps),
                                    Err(e) => {
                                        log::error!("SOCKS5 connection error: {}", e);
                                        yield Err(e);
                                    }
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

    /// Listen with UDP support enabled
    async fn listen_with_udp(mut self, addr: Address) -> BoxStream<ProxyStream, std::io::Error> {
        log::info!("socks5 start Listening on {:?}", addr);
        // Convert address to SocketAddr
        let sockaddr = match resolve_address(&addr).await {
            Ok(sa) => sa,
            Err(e) => return Box::pin(tokio_stream::once(Err(e))),
        };

        // Bind shared port (TCP + UDP)
        let (tcp_listener, udp_socket) = match bind_shared_port(&sockaddr).await {
            Ok(pair) => pair,
            Err(e) => return Box::pin(tokio_stream::once(Err(e))),
        };

        // Create UDP state
        let udp_state = Arc::new(UdpState::new(Arc::new(udp_socket)));

        // Update mode with UDP state
        if let ProxyMode::Inbound {
            udp_state: ref mut state,
            ..
        } = &mut self.mode
        {
            *state = Some(udp_state.clone());
        }

        // Spawn UDP receive loop
        tokio::spawn(udp_receive_loop(udp_state.clone()));

        // Extract account from mode
        let account = match &self.mode {
            ProxyMode::Inbound { account, .. } => account.clone(),
            ProxyMode::Outbound { .. } => None,
        };

        // Handle TCP connections with UDP Associate support
        let proxy_stream = async_stream::stream! {
            loop {
                match tcp_listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let tr_stream = transport::TrStream::Tcp(stream);
                        let peer_address = Address::Inet(peer_addr);

                        match Self::handle_connection_with_udp(
                            tr_stream,
                            peer_address,
                            account.clone(),
                            udp_state.clone(),
                        ).await {
                            Ok(Some(ps)) => yield Ok(ps),
                            Ok(None) => {
                                // UDP Associate handled, no ProxyStream to yield
                            }
                            Err(e) => {
                                log::error!("SOCKS5 connection error: {}", e);
                                yield Err(e);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("TCP accept error: {}", e);
                        yield Err(e);
                    }
                }
            }
        };

        Box::pin(proxy_stream)
    }
}

// --- 连接处理 ---

impl Proxy {
    /// 处理单个 SOCKS5 入站连接：握手 + 解析请求 + 返回 ProxyStream
    async fn handle_connection(
        stream: transport::TrStream,
        peer_addr: Address,
        account: Option<common::Account>,
    ) -> std::io::Result<ProxyStream> {
        let mut processor = Socks5Processor::new(account);
        let (stream, _cmd, target_addr) = processor
            .process(stream)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("SOCKS5 handshake failed: {}", e)))?;
        log::debug!("SOCKS5 connection to {}", target_addr);
        Ok(ProxyStream::new(Protocol::Tcp, peer_addr, target_addr, stream))
    }

    /// Handle connection with UDP Associate support.
    /// Returns Some(ProxyStream) for TCP connections, None for UDP Associate.
    async fn handle_connection_with_udp(
        stream: transport::TrStream,
        peer_addr: Address,
        account: Option<common::Account>,
        udp_state: Arc<UdpState>,
    ) -> std::io::Result<Option<ProxyStream>> {
        let processor = Socks5Processor::new(account);
        let mut stream = stream;
        processor
            .handshake(&mut stream)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("SOCKS5 handshake failed: {}", e)))?;

        let (cmd, target_addr) = processor
            .get_request(&mut stream)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("SOCKS5 request failed: {}", e)))?;

        match cmd {
            common::socks::Command::UdpAssociate => {
                let client_addr = match peer_addr.clone() {
                    Address::Inet(sa) => sa,
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "UDP Associate requires inet address",
                        ));
                    }
                };

                let target = normalize_udp_associate_target(&target_addr, client_addr);
                processor
                    .send_reply(&mut stream, common::socks::Reply::Succeeded, &target)
                    .await
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, format!("SOCKS5 reply failed: {}", e))
                    })?;

                let (tx, rx) = mpsc::channel(128);
                {
                    let mut sessions = udp_state.sessions.lock().await;
                    let session = sessions
                        .entry(client_addr)
                        .or_insert_with(|| UdpSession::new(client_addr));
                    session.last_activity = Instant::now();
                    session.stream_tx = Some(tx);
                }

                let udp_stream = transport::TrStream::Tun(Box::new(SocksInboundUdpStream::new(
                    stream,
                    rx,
                    client_addr,
                    udp_state,
                    target.clone(),
                    None,
                )));

                Ok(Some(ProxyStream::new(Protocol::Udp, peer_addr, target, udp_stream)))
            }
            _ => {
                processor
                    .send_reply(&mut stream, common::socks::Reply::Succeeded, &target_addr)
                    .await
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, format!("SOCKS5 reply failed: {}", e))
                    })?;

                Ok(Some(ProxyStream::new(Protocol::Tcp, peer_addr, target_addr, stream)))
            }
        }
    }
}

// --- Helper Functions ---

/// Binds both TCP and UDP to the same port.
/// This is essential for SOCKS5 UDP Associate where the TCP control connection
/// and UDP data channel share a port.
pub async fn bind_shared_port(addr: &SocketAddr) -> std::io::Result<(TcpListener, UdpSocket)> {
    // Bind TCP first
    let tcp_listener = TcpListener::bind(addr).await?;
    let tcp_addr = tcp_listener.local_addr()?;

    // Bind UDP to same port
    let udp_socket = UdpSocket::bind(tcp_addr).await?;

    Ok((tcp_listener, udp_socket))
}

/// UDP receive loop that continuously receives UDP packets, validates client sessions,
/// parses SOCKS5 UDP packets, and spawns forwarding tasks.
pub async fn udp_receive_loop(udp_state: Arc<UdpState>) {
    let mut buf = vec![0u8; 65535];

    loop {
        match udp_state.socket().recv_from(&mut buf).await {
            Ok((len, client_addr)) => {
                // Check session exists
                if !udp_state.sessions.lock().await.contains_key(&client_addr) {
                    continue;
                }

                // Parse SOCKS5 UDP packet - handle errors gracefully
                let parse_result = parse_socks5_udp_packet(&buf[..len]);
                let (target_addr, data) = match parse_result {
                    Ok((addr, data)) => (addr, data),
                    Err(e) => {
                        log::warn!("Failed to parse UDP packet from {}: {}", client_addr, e);
                        continue;
                    }
                };

                // Update last activity
                let mut delivered_to_stream = false;
                if let Some(session) = udp_state.sessions.lock().await.get_mut(&client_addr) {
                    session.last_activity = Instant::now();
                    if let Some(tx) = &session.stream_tx {
                        match tx.try_send(UdpFrame {
                            target: target_addr.clone(),
                            data: data.clone(),
                        }) {
                            Ok(()) => {
                                delivered_to_stream = true;
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                log::warn!("UDP stream channel full for {}", client_addr);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                session.stream_tx = None;
                            }
                        }
                    }
                }

                if delivered_to_stream {
                    continue;
                }

                // Spawn forwarding task
                tokio::spawn(forward_udp_packet(udp_state.clone(), client_addr, target_addr, data));
            }
            Err(e) => log::error!("UDP recv error: {}", e),
        }
    }
}

/// Parse SOCKS5 UDP packet format.
///
/// SOCKS5 UDP packet format:
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
pub fn parse_socks5_udp_packet(packet: &[u8]) -> std::io::Result<(Address, Vec<u8>)> {
    if packet.len() < 4 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "UDP packet too short"));
    }

    // Check fragmentation (not supported)
    let frag = packet[2];
    if frag != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP fragmentation not supported",
        ));
    }

    // Parse address using existing parser
    let (addr, addr_len) = crate::common::parse::parse_address_from_bytes(&packet[3..])?;

    // Extract data
    let data_offset = 3 + addr_len;
    let data = packet[data_offset..].to_vec();

    Ok((addr, data))
}

/// Build SOCKS5 UDP packet format.
///
/// SOCKS5 UDP packet format:
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
pub fn build_socks5_udp_packet(target: &Address, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(3 + encoded_address_len(target) + data.len());
    build_socks5_udp_packet_into(target, data, &mut packet)?;
    Ok(packet)
}

fn build_socks5_udp_packet_into(target: &Address, data: &[u8], packet: &mut Vec<u8>) -> std::io::Result<()> {
    packet.clear();
    packet.reserve(3 + encoded_address_len(target) + data.len());

    // RSV (2 bytes) + FRAG (1 byte)
    packet.extend_from_slice(&[0, 0, 0]);

    // ATYP + DST.ADDR + DST.PORT
    let addr_bytes = crate::common::parse::encode_address_to_bytes(target)?;
    packet.extend_from_slice(&addr_bytes);

    // DATA
    packet.extend_from_slice(data);

    Ok(())
}

fn build_socks5_command_packet(cmd: u8, target: &Address) -> std::io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(3 + encoded_address_len(target));
    packet.extend_from_slice(&[0x05, cmd, 0x00]);

    let addr_bytes = crate::common::parse::encode_address_to_bytes(target)?;
    packet.extend_from_slice(&addr_bytes);

    Ok(packet)
}

fn encoded_address_len(target: &Address) -> usize {
    match target {
        Address::Inet(SocketAddr::V4(_)) => 1 + 4 + 2,
        Address::Inet(SocketAddr::V6(_)) => 1 + 16 + 2,
        Address::Domain(domain, _) => 1 + 1 + domain.len() + 2,
        Address::Unix(path) => 1 + 1 + path.to_string_lossy().len() + 2,
    }
}

fn parse_socks5_udp_packet_partial(packet: &[u8]) -> std::io::Result<Option<(Address, Vec<u8>, usize)>> {
    if packet.len() < 4 {
        return Ok(None);
    }

    if packet[0] != 0 || packet[1] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid socks5 udp reserved bytes",
        ));
    }

    if packet[2] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "UDP fragmentation not supported",
        ));
    }

    let addr_len = match socks_udp_addr_total_len(&packet[3..]) {
        Some(len) => len,
        None => return Ok(None),
    };

    let (addr, parsed_addr_len) = crate::common::parse::parse_address_from_bytes(&packet[3..3 + addr_len])?;
    debug_assert_eq!(addr_len, parsed_addr_len);

    let payload_offset = 3 + addr_len;
    let payload = packet[payload_offset..].to_vec();
    Ok(Some((addr, payload, packet.len())))
}

fn socks_udp_addr_total_len(packet: &[u8]) -> Option<usize> {
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

fn normalize_udp_associate_target(target: &Address, client_addr: SocketAddr) -> Address {
    match target {
        Address::Inet(sa) if sa.ip().is_unspecified() && sa.port() == 0 => Address::Inet(client_addr),
        Address::Domain(domain, port) if domain == "0.0.0.0" && *port == 0 => Address::Inet(client_addr),
        _ => target.clone(),
    }
}

/// Forward UDP packet to target address.
pub async fn forward_udp_packet(
    udp_state: Arc<UdpState>,
    client_addr: SocketAddr,
    target_addr: Address,
    data: Vec<u8>,
) -> std::io::Result<()> {
    let target_sockaddr = resolve_address(&target_addr).await?;

    let session_outbound_sockets = {
        let sessions = udp_state.sessions.lock().await;
        let session = sessions
            .get(&client_addr)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Session not found"))?;
        session.outbound_sockets.clone()
    };

    if let Some(sock) = session_outbound_sockets.lock().await.get(&target_sockaddr).cloned() {
        sock.send_to(&data, target_sockaddr).await?;
        return Ok(());
    }

    let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    {
        let mut sockets = session_outbound_sockets.lock().await;
        if let Some(existing) = sockets.get(&target_sockaddr).cloned() {
            existing.send_to(&data, target_sockaddr).await?;
            return Ok(());
        }
        sockets.insert(target_sockaddr, sock.clone());
    }

    tokio::spawn(receive_from_target(
        udp_state.clone(),
        client_addr,
        target_addr.clone(),
        target_sockaddr,
        sock.clone(),
    ));

    sock.send_to(&data, target_sockaddr).await?;
    Ok(())
}

async fn resolve_address(addr: &Address) -> std::io::Result<SocketAddr> {
    match addr {
        Address::Inet(sa) => Ok(*sa),
        Address::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No addresses found")),
        Address::Unix(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unix sockets not supported for UDP",
        )),
    }
}

pub async fn receive_from_target(
    udp_state: Arc<UdpState>,
    client_addr: SocketAddr,
    target_addr: Address,
    target_sockaddr: SocketAddr,
    outbound_socket: Arc<UdpSocket>,
) {
    let mut buf = vec![0u8; 65535];
    let idle_timeout = Duration::from_secs(30);

    loop {
        match tokio::time::timeout(idle_timeout, outbound_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                // Encapsulate and send back to client
                if let Ok(response) = build_socks5_udp_packet(&target_addr, &buf[..len]) {
                    let _ = udp_state.socket().send_to(&response, client_addr).await;
                }
            }
            _ => {
                // Timeout or error, clean up and exit
                log::debug!("Closing outbound socket for {} -> {:?}", client_addr, target_addr);

                // Remove socket from session's outbound_sockets map
                if let Some(session) = udp_state.sessions.lock().await.get(&client_addr) {
                    session.outbound_sockets.lock().await.remove(&target_sockaddr);
                }

                break;
            }
        }
    }
}

/// Handle UDP Associate TCP control connection.
/// Registers session, sends reply, keeps connection alive, and cleans up on disconnect.
pub async fn handle_udp_associate(
    mut stream: transport::TrStream,
    client_addr: SocketAddr,
    udp_state: Arc<UdpState>,
) -> std::io::Result<()> {
    let cancel_token = CancellationToken::new();

    // Register session
    {
        let mut sessions = udp_state.sessions.lock().await;
        sessions.insert(client_addr, UdpSession::new(client_addr));
    }

    // Send reply
    let udp_addr = udp_state.socket().local_addr()?;
    send_udp_associate_reply(&mut stream, &udp_addr).await?;

    // Keep alive
    tokio::select! {
        _ = keep_tcp_alive(stream) => {},
        _ = cancel_token.cancelled() => {},
    }

    // Cleanup
    udp_state.sessions.lock().await.remove(&client_addr);
    Ok(())
}

/// Keep TCP connection alive by reading until disconnect.
async fn keep_tcp_alive(mut stream: transport::TrStream) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 1];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return Ok(()), // Connection closed
            Ok(_) => {}             // Unexpected data
            Err(e) => return Err(e),
        }
    }
}

/// Send UDP Associate reply with BND.ADDR set to UDP socket address.
async fn send_udp_associate_reply(stream: &mut transport::TrStream, udp_addr: &SocketAddr) -> std::io::Result<()> {
    use bytes::{BufMut, BytesMut};
    use tokio::io::AsyncWriteExt;

    let mut buf = BytesMut::new();
    buf.put_u8(0x05); // VER
    buf.put_u8(0x00); // REP = succeeded
    buf.put_u8(0x00); // RSV

    // BND.ADDR = UDP socket address
    let addr = Address::Inet(*udp_addr);
    addr.write_to_buf(&mut buf);

    stream.write_all(&buf).await?;
    Ok(())
}

// --- Outbound UDP Associate Implementation ---

/// Send UDP Associate request to SOCKS5 server.
/// Request format: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
async fn send_udp_associate_request<T>(stream: &mut T, target: &Address) -> std::io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    let buf = build_socks5_command_packet(0x03, target)?;
    stream.write_all(&buf).await?;
    Ok(())
}

/// Send CONNECT request to SOCKS5 server.
/// Request format: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
async fn send_connect_request<T>(stream: &mut T, target: &Address) -> std::io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    let buf = build_socks5_command_packet(0x01, target)?;
    stream.write_all(&buf).await?;
    Ok(())
}

/// Receive CONNECT reply from SOCKS5 server.
/// Reply format: VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(var) BND.PORT(2)
async fn recv_connect_reply<T>(stream: &mut T) -> std::io::Result<()>
where
    T: AsyncRead + Unpin,
{
    // Read fixed header: VER REP RSV ATYP
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid SOCKS version: {}", header[0]),
        ));
    }

    if header[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("CONNECT failed: reply code {}", header[1]),
        ));
    }

    // Read and discard BND.ADDR and BND.PORT
    let _addr = Address::read_from_with_type(stream, header[3])
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to parse address: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_socks5_command_packet_ipv4_connect() {
        let target = Address::Inet("127.0.0.1:8080".parse().unwrap());
        let packet = build_socks5_command_packet(0x01, &target).unwrap();

        assert_eq!(packet, vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]);
    }

    #[test]
    fn build_socks5_command_packet_domain_udp_associate() {
        let target = Address::Domain("example.com".to_string(), 53);
        let packet = build_socks5_command_packet(0x03, &target).unwrap();

        assert_eq!(packet[0..3], [0x05, 0x03, 0x00]);
        assert_eq!(packet[3], 0x03);
        assert_eq!(packet[4], 11);
        assert_eq!(&packet[5..16], b"example.com");
        assert_eq!(&packet[16..18], &[0x00, 0x35]);
    }
}
