// bin/rsdns/upstream.rs
#![allow(unused)]
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_SIZE: usize = 4096;

/// 上游协议类型
#[derive(Debug, Clone)]
pub enum UpstreamProtocol {
    Udp,
    Tcp,
    Tls { server_name: String },
    Https { url: String },
}

/// 上游客户端
#[derive(Clone)]
pub struct UpstreamClient {
    addrs: Vec<SocketAddr>,
    protocol: UpstreamProtocol,
    tls_config: Option<Arc<ClientConfig>>,
}

impl UpstreamClient {
    pub fn new_udp(addrs: Vec<SocketAddr>) -> Self {
        Self {
            addrs,
            protocol: UpstreamProtocol::Udp,
            tls_config: None,
        }
    }

    pub fn new_tcp(addrs: Vec<SocketAddr>) -> Self {
        Self {
            addrs,
            protocol: UpstreamProtocol::Tcp,
            tls_config: None,
        }
    }

    pub fn new_tls(addrs: Vec<SocketAddr>, server_name: String, tls_config: Arc<ClientConfig>) -> Self {
        Self {
            addrs,
            protocol: UpstreamProtocol::Tls { server_name },
            tls_config: Some(tls_config),
        }
    }

    pub async fn query(&self, msg: &Message) -> io::Result<Message> {
        let addr = self
            .addrs
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no upstream address"))?;

        match &self.protocol {
            UpstreamProtocol::Udp => self.query_udp(*addr, msg).await,
            UpstreamProtocol::Tcp => self.query_tcp(*addr, msg).await,
            UpstreamProtocol::Tls { server_name } => self.query_tls(*addr, server_name, msg).await,
            UpstreamProtocol::Https { url } => self.query_doh(url, msg).await,
        }
    }

    async fn query_udp(&self, addr: SocketAddr, msg: &Message) -> io::Result<Message> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let buf = msg
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        socket.send_to(&buf, addr).await?;

        let mut recv_buf = vec![0u8; MAX_DNS_SIZE];
        let (len, _) = timeout(DNS_TIMEOUT, socket.recv_from(&mut recv_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP timeout"))??;

        Message::from_vec(&recv_buf[..len]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn query_tcp(&self, addr: SocketAddr, msg: &Message) -> io::Result<Message> {
        let mut stream = timeout(DNS_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))??;

        let buf = msg
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // DNS over TCP: 2-byte length prefix
        let len = (buf.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&buf).await?;

        // Read response
        let mut len_buf = [0u8; 2];
        timeout(DNS_TIMEOUT, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP read timeout"))??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut recv_buf = vec![0u8; resp_len];
        stream.read_exact(&mut recv_buf).await?;

        Message::from_vec(&recv_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn query_tls(&self, addr: SocketAddr, server_name: &str, msg: &Message) -> io::Result<Message> {
        let tls_config = self
            .tls_config
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS config not set"))?;

        let connector = TlsConnector::from(tls_config.clone());
        let tcp_stream = timeout(DNS_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS connect timeout"))??;

        let server_name = server_name
            .to_string()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?;
        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        let buf = msg
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // DNS over TLS: same as TCP with 2-byte length prefix
        let len = (buf.len() as u16).to_be_bytes();
        tls_stream.write_all(&len).await?;
        tls_stream.write_all(&buf).await?;

        let mut len_buf = [0u8; 2];
        timeout(DNS_TIMEOUT, tls_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS read timeout"))??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut recv_buf = vec![0u8; resp_len];
        tls_stream.read_exact(&mut recv_buf).await?;

        Message::from_vec(&recv_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn query_doh(&self, _url: &str, _msg: &Message) -> io::Result<Message> {
        // DoH 实现需要 hyper，暂时返回未实现
        Err(io::Error::new(io::ErrorKind::Other, "DoH not implemented yet"))
    }
}
