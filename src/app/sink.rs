use crate::{
    common::{forward::StreamForwarder, Address, Protocol},
    proxy::{Outbounder, ProxyStream},
    route::DnsResolver,
    transport::{self, TrStream},
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 流量出口
pub enum ConnectionSink {
    Direct(DirectSink),
    Proxy(ProxySink),
    Block,
    Daemon(DaemonSink),
}

impl ConnectionSink {
    /// 处理一条 ProxyStream
    pub async fn handle(&self, stream: ProxyStream, forwarder: &StreamForwarder) -> std::io::Result<()> {
        match self {
            ConnectionSink::Direct(sink) => sink.handle(stream, forwarder).await,
            ConnectionSink::Proxy(sink) => sink.handle(stream, forwarder).await,
            ConnectionSink::Block => {
                drop(stream);
                Ok(())
            }
            ConnectionSink::Daemon(_) => {
                // Daemon sinks don't handle individual streams
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Daemon sinks cannot handle proxy streams",
                ))
            }
        }
    }

    pub fn is_daemon(&self) -> bool {
        matches!(self, ConnectionSink::Daemon(_))
    }
}

/// 直连出口：解析域名后直接 TCP 连接目标
pub struct DirectSink {
    pub dns: Arc<DnsResolver>,
    pub transport: transport::Transport,
}

impl DirectSink {
    async fn handle(&self, stream: ProxyStream, forwarder: &StreamForwarder) -> std::io::Result<()> {
        let dst = self.resolve(&stream.metadata.dst).await?;
        match stream.metadata.protocol {
            Protocol::Tcp => {
                let remote = self.transport.connect(&dst, Protocol::Tcp).await?;
                forwarder.forward(stream.inner, remote).await?;
                Ok(())
            }
            Protocol::Udp => self.handle_udp(stream, dst).await,
        }
    }

    async fn handle_udp(&self, stream: ProxyStream, dst: Address) -> std::io::Result<()> {
        let mut inbound = stream.inner;
        let mut remote = self.transport.connect(&dst, Protocol::Udp).await?;

        let remote_socket = match &mut remote {
            transport::TrStream::Udp(socket) => socket,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP direct sink requires UDP transport stream",
                ))
            }
        };

        let mut inbound_buf = vec![0u8; 65535];
        let mut remote_buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                inbound_read = inbound.read(&mut inbound_buf) => {
                    let n = inbound_read?;
                    if n == 0 {
                        break;
                    }
                    remote_socket.send(&inbound_buf[..n]).await?;
                }
                remote_read = remote_socket.recv(&mut remote_buf) => {
                    let n = remote_read?;
                    if n == 0 {
                        break;
                    }
                    inbound.write_all(&remote_buf[..n]).await?;
                    inbound.flush().await?;
                }
            }
        }

        let _ = inbound.shutdown().await;
        Ok(())
    }

    async fn resolve(&self, addr: &Address) -> std::io::Result<Address> {
        match addr {
            Address::Domain(domain, port) => {
                let ips = self.dns.resolve(domain).await?;
                let ip = ips.first().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, format!("no address for {}", domain))
                })?;
                Ok(Address::Inet(std::net::SocketAddr::new(*ip, *port)))
            }
            other => Ok(other.clone()),
        }
    }
}

/// 代理出口：通过 trojan/socks 代理连接目标
pub struct ProxySink {
    pub outbounder: Outbounder,
}

impl ProxySink {
    async fn handle(&self, stream: ProxyStream, forwarder: &StreamForwarder) -> std::io::Result<()> {
        let remote = self
            .try_connect(&stream.metadata.dst, stream.metadata.protocol.clone())
            .await?;
        forwarder.forward(stream.inner, remote).await?;
        Ok(())
    }

    /// 尝试建立到目标地址的代理连接（不消费 inbound stream）
    /// 用于支持 fallback 重试：只有连接成功后才消费 stream
    pub async fn try_connect(&self, dst: &Address, protocol: crate::common::Protocol) -> std::io::Result<TrStream> {
        self.outbounder.connect(dst, protocol).await
    }
}

/// Daemon mode sink: for protocols like Revers that run as background daemons
pub struct DaemonSink {
    pub outbounder: Outbounder,
}

impl DaemonSink {
    pub async fn run(mut self) -> std::io::Result<()> {
        let mut retry = 0u32;
        loop {
            match self.outbounder.run().await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let secs = std::cmp::min(2u64.pow(retry.min(8)), 300);
                    log::error!("daemon sink error: {}, retry in {}s", e, secs);
                    retry += 1;
                    tokio::time::sleep(tokio::time::Duration::from_secs(secs)).await;
                }
            }
        }
    }
}
