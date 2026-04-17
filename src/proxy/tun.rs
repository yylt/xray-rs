use super::*;
use ahash::RandomState;
use bytes::Bytes;
use etherparse::{NetHeaders, PacketHeaders};
use log::{debug, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InSetting {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "mtu", default = "default_mtu")]
    pub mtu: u16,

    #[serde(rename = "cidrs")]
    pub cidrs: Vec<String>,

    #[serde(rename = "auto_route")]
    pub auto_route: Option<bool>,
}

fn default_mtu() -> u16 {
    1500
}

impl Default for InSetting {
    fn default() -> Self {
        Self {
            name: "tun0".to_string(),
            mtu: 1500,
            cidrs: vec!["10.0.0.1/24".to_string()],
            auto_route: Some(true),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FlowKey {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

pub struct FlowState {
    pub sender: mpsc::Sender<Bytes>,
    pub last_activity: Instant,
}

// Channel-based stream adapter for TUN flows
pub struct TunStream {
    rx: mpsc::Receiver<Bytes>,
    tx: mpsc::Sender<Bytes>,
    read_buf: Bytes,
    read_pos: usize,
}

impl TunStream {
    pub fn new(rx: mpsc::Receiver<Bytes>, tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            rx,
            tx,
            read_buf: Bytes::new(),
            read_pos: 0,
        }
    }
}

impl AsyncRead for TunStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have data in the buffer, copy it
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf.slice(self.read_pos..);
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            // Clear buffer if fully consumed
            if self.read_pos >= self.read_buf.len() {
                self.read_buf = Bytes::new();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // Try to receive new data
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                // Store remaining data if any
                if to_copy < data.len() {
                    self.read_buf = data.slice(to_copy..);
                    self.read_pos = 0;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TunStream {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let data = Bytes::copy_from_slice(buf);
        let len = data.len();
        match self.tx.try_send(data) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(mpsc::error::TrySendError::Full(_)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "Channel full")))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Channel closed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct ConnectionPool {
    flows: Arc<Mutex<HashMap<FlowKey, FlowState, RandomState>>>,
    tcp_timeout: Duration,
    udp_timeout: Duration,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            flows: Arc::new(Mutex::new(HashMap::with_hasher(RandomState::new()))),
            tcp_timeout: Duration::from_secs(300), // 5 minutes
            udp_timeout: Duration::from_secs(30),  // 30 seconds
        }
    }

    pub async fn get_or_create(
        &self,
        key: FlowKey,
    ) -> std::io::Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, bool)> {
        let mut flows = self.flows.lock().await;

        if let Some(state) = flows.get_mut(&key) {
            state.last_activity = Instant::now();
            // For existing flows, create a new receiver channel
            let (_tx, rx) = mpsc::channel(100);
            Ok((state.sender.clone(), rx, false))
        } else {
            let (tx, rx) = mpsc::channel(100);
            flows.insert(
                key.clone(),
                FlowState {
                    sender: tx.clone(),
                    last_activity: Instant::now(),
                },
            );
            Ok((tx, rx, true))
        }
    }

    pub async fn cleanup_expired(&self) {
        let mut flows = self.flows.lock().await;
        let now = Instant::now();

        flows.retain(|key, state| {
            let timeout = match key.protocol {
                Protocol::Tcp => self.tcp_timeout,
                Protocol::Udp => self.udp_timeout,
            };
            now.duration_since(state.last_activity) < timeout
        });
    }
}

pub fn parse_packet(data: &[u8]) -> std::io::Result<(FlowKey, Bytes)> {
    let headers = PacketHeaders::from_ip_slice(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Parse error: {}", e)))?;

    let (src_ip, dst_ip) = match headers.net {
        Some(NetHeaders::Ipv4(h, _)) => (
            IpAddr::V4(std::net::Ipv4Addr::from(h.source)),
            IpAddr::V4(std::net::Ipv4Addr::from(h.destination)),
        ),
        Some(NetHeaders::Ipv6(h, _)) => (
            IpAddr::V6(std::net::Ipv6Addr::from(h.source)),
            IpAddr::V6(std::net::Ipv6Addr::from(h.destination)),
        ),
        Some(NetHeaders::Arp(_)) => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unsupported ARP packet"))
        }
        None => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "No IP header")),
    };

    let (src_port, dst_port, protocol) = match headers.transport {
        Some(etherparse::TransportHeader::Tcp(h)) => (h.source_port, h.destination_port, Protocol::Tcp),
        Some(etherparse::TransportHeader::Udp(h)) => (h.source_port, h.destination_port, Protocol::Udp),
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unsupported protocol")),
    };

    let payload = Bytes::copy_from_slice(headers.payload.slice());

    Ok((
        FlowKey {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port,
            dst_port,
            protocol,
        },
        payload,
    ))
}

pub fn build_packet(flow_key: &FlowKey, payload: &[u8]) -> std::io::Result<Bytes> {
    use etherparse::PacketBuilder;

    let mut packet = Vec::with_capacity(1500);

    // Build packet (swap src/dst for response)
    match (flow_key.dst_addr, flow_key.src_addr) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), 64);

            match flow_key.protocol {
                Protocol::Tcp => {
                    let builder = builder.tcp(
                        flow_key.dst_port,
                        flow_key.src_port,
                        0, // sequence number
                        0, // window size
                    );
                    builder.write(&mut packet, payload).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, format!("Write TCP packet error: {}", e))
                    })?;
                }
                Protocol::Udp => {
                    let builder = builder.udp(flow_key.dst_port, flow_key.src_port);
                    builder.write(&mut packet, payload).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, format!("Write UDP packet error: {}", e))
                    })?;
                }
            }
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), 64);

            match flow_key.protocol {
                Protocol::Tcp => {
                    let builder = builder.tcp(
                        flow_key.dst_port,
                        flow_key.src_port,
                        0, // sequence number
                        0, // window size
                    );
                    builder.write(&mut packet, payload).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, format!("Write TCP packet error: {}", e))
                    })?;
                }
                Protocol::Udp => {
                    let builder = builder.udp(flow_key.dst_port, flow_key.src_port);
                    builder.write(&mut packet, payload).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, format!("Write UDP packet error: {}", e))
                    })?;
                }
            }
        }
        _ => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "IP version mismatch"));
        }
    }

    Ok(Bytes::from(packet))
}
#[allow(unused)]
pub struct Proxy {
    setting: InSetting,
    dns: Arc<crate::route::DnsResolver>,
}

impl Proxy {
    pub fn new_inbound(set: &InSetting, dns: Arc<crate::route::DnsResolver>) -> std::io::Result<Self> {
        Ok(Self {
            setting: set.clone(),
            dns,
        })
    }

    fn create_tun_device(setting: &InSetting) -> std::io::Result<::tun::AsyncDevice> {
        let mut config = ::tun::Configuration::default();
        config.tun_name(&setting.name).mtu(setting.mtu).up();

        // Parse and add IP addresses
        for cidr in &setting.cidrs {
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() != 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid CIDR: {}", cidr),
                ));
            }

            let addr: IpAddr = parts[0].parse().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid IP address: {}", e))
            })?;

            let prefix: u8 = parts[1].parse().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid prefix length: {}", e))
            })?;

            match addr {
                IpAddr::V4(ip) => {
                    config
                        .address(IpAddr::V4(ip))
                        .netmask(IpAddr::V4(prefix_to_netmask_v4(prefix)));
                }
                IpAddr::V6(ip) => {
                    config
                        .address(IpAddr::V6(ip))
                        .netmask(IpAddr::V6(prefix_to_netmask_v6(prefix)));
                }
            }
        }

        ::tun::create_as_async(&config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to create TUN device: {}", e)))
    }

    pub async fn listen(self, _addr: Address) -> BoxStream<ProxyStream, std::io::Error> {
        // Create TUN device
        let device = match Self::create_tun_device(&self.setting) {
            Ok(d) => d,
            Err(e) => {
                log::error!("Failed to create TUN device: {}", e);
                return Box::pin(tokio_stream::empty());
            }
        };

        info!("TUN device created: {}", self.setting.name);

        // Create channel for ProxyStream objects
        let (stream_tx, stream_rx) = mpsc::channel(100);

        // Initialize connection pool
        let pool = Arc::new(ConnectionPool::new());

        // Spawn cleanup loop
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                pool_clone.cleanup_expired().await;
                debug!("Cleaned up expired flows");
            }
        });

        // Spawn packet reader loop
        let mtu = self.setting.mtu;
        let device_clone = Arc::new(Mutex::new(device));
        let device_writer = device_clone.clone();

        tokio::spawn(async move {
            let buf_size = mtu as usize + ::tun::PACKET_INFORMATION_LENGTH;
            let mut buf = vec![0u8; buf_size];

            loop {
                let mut device = device_clone.lock().await;
                match device.read(&mut buf).await {
                    Ok(n) => {
                        drop(device); // Release lock immediately
                        let packet = &buf[::tun::PACKET_INFORMATION_LENGTH..n];

                        match parse_packet(packet) {
                            Ok((flow_key, payload)) => {
                                match pool.get_or_create(flow_key.clone()).await {
                                    Ok((sender, _write_rx, is_new)) => {
                                        if is_new {
                                            info!("New flow detected: {:?}", flow_key);

                                            // Create ProxyStream for new flow
                                            let dst_addr = Address::Inet(std::net::SocketAddr::new(
                                                flow_key.dst_addr,
                                                flow_key.dst_port,
                                            ));
                                            let src_addr = Address::Inet(std::net::SocketAddr::new(
                                                flow_key.src_addr,
                                                flow_key.src_port,
                                            ));

                                            // Create bidirectional channels for the stream
                                            let (write_tx, write_rx_stream) = mpsc::channel(100);
                                            let (_read_tx, read_rx) = mpsc::channel(100);

                                            // Create TunStream adapter
                                            let tun_stream = TunStream::new(read_rx, write_tx);

                                            // Wrap in transport stream
                                            let tr_stream = transport::TrStream::Tun(Box::new(tun_stream));

                                            // Create ProxyStream
                                            let proxy_stream = ProxyStream::new(
                                                flow_key.protocol.clone(),
                                                src_addr,
                                                dst_addr,
                                                tr_stream,
                                            )
                                            .with_tag("tun-in");

                                            // Send ProxyStream through channel
                                            if let Err(e) = stream_tx.send(Ok(proxy_stream)).await {
                                                warn!("Failed to send ProxyStream: {}", e);
                                            }

                                            // Spawn task to handle response packets from proxy to TUN
                                            let flow_key_clone = flow_key.clone();
                                            let device_writer_clone = device_writer.clone();
                                            tokio::spawn(async move {
                                                let mut write_rx = write_rx_stream;
                                                while let Some(data) = write_rx.recv().await {
                                                    match build_packet(&flow_key_clone, &data) {
                                                        Ok(packet) => {
                                                            let mut full_packet =
                                                                vec![0u8; ::tun::PACKET_INFORMATION_LENGTH];
                                                            full_packet.extend_from_slice(&packet);

                                                            let mut device = device_writer_clone.lock().await;
                                                            if let Err(e) = device.write(&full_packet).await {
                                                                warn!("Failed to write packet to TUN device: {}", e);
                                                                break;
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!("Failed to build response packet: {}", e);
                                                        }
                                                    }
                                                }
                                                debug!("Response handler closed for flow: {:?}", flow_key_clone);
                                            });
                                        }

                                        // Forward packet payload to flow handler
                                        if !payload.is_empty() {
                                            if let Err(e) = sender.send(payload).await {
                                                warn!("Failed to send packet to flow: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to get or create flow: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                trace!("Failed to parse packet: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to read from TUN device: {}", e);
                        break;
                    }
                }
            }
        });

        // Return stream of ProxyStream objects
        Box::pin(ReceiverStream::new(stream_rx))
    }
}

fn prefix_to_netmask_v4(prefix: u8) -> std::net::Ipv4Addr {
    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
    std::net::Ipv4Addr::from(mask)
}

fn prefix_to_netmask_v6(prefix: u8) -> std::net::Ipv6Addr {
    let mask = if prefix == 0 { 0u128 } else { !0u128 << (128 - prefix) };
    std::net::Ipv6Addr::from(mask)
}
