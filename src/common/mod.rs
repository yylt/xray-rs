pub mod forward;
pub mod parse;
pub mod socks;
pub mod tls;

use core::{pin::Pin, result::Result};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncReadExt};

use bytes::{BufMut, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};

pub type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'static>>;
pub type BoxStream<T, E> = Pin<Box<dyn tokio_stream::Stream<Item = Result<T, E>> + Send + 'static>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Account {
    #[serde(rename = "user")]
    pub username: String,
    #[serde(rename = "pass")]
    pub password: String,
}

impl Account {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub enum Address {
    Inet(std::net::SocketAddr),
    Unix(std::path::PathBuf),
    Domain(String, u16),
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::Inet(addr)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Inet(addr) => write!(f, "{}", addr),
            Address::Unix(path) => write!(f, "{}", path.display()),
            Address::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}
impl From<PathBuf> for Address {
    fn from(path: PathBuf) -> Self {
        Address::Unix(path)
    }
}

impl From<&Path> for Address {
    fn from(path: &Path) -> Self {
        Address::Unix(path.to_path_buf())
    }
}

impl<T: AsRef<str>> TryFrom<(T, Option<u16>)> for Address {
    type Error = std::io::Error;

    fn try_from((host, port): (T, Option<u16>)) -> Result<Self, Self::Error> {
        let host_str = host.as_ref().trim();

        // 处理 Unix socket 前缀
        if host_str.starts_with("unix:") {
            let path = host_str.trim_start_matches("unix:");
            // 去掉可能的 "//" 前缀（类似URL）
            let path = path.trim_start_matches("//");
            return Ok(Address::Unix(std::path::PathBuf::from(path)));
        }

        if host_str.starts_with("file://") {
            let path = host_str.trim_start_matches("file://");
            return Ok(Address::Unix(std::path::PathBuf::from(path)));
        }

        // 检查是否是绝对或相对文件路径
        let path = std::path::Path::new(host_str);
        if path.is_absolute()
            || host_str.starts_with("./")
            || host_str.starts_with("../")
            || (path.extension().is_some() && (host_str.contains(".sock") || host_str.contains(".socket")))
        {
            // 对于Unix socket，端口参数通常被忽略
            return Ok(Address::Unix(path.to_path_buf()));
        }

        // 原有的网络地址处理逻辑...
        // 处理可能的 SocketAddr 格式 (IP:port)
        if let Ok(socket_addr) = std::net::SocketAddr::from_str(host_str) {
            let final_addr = if let Some(p) = port {
                std::net::SocketAddr::new(socket_addr.ip(), p)
            } else {
                socket_addr
            };
            return Ok(Address::Inet(final_addr));
        }

        // 处理域名:端口格式
        if let Some((domain, port_str)) = host_str.rsplit_once(':') {
            if let Ok(parsed_port) = port_str.parse::<u16>() {
                let final_port = port.unwrap_or(parsed_port);
                return Ok(Address::Domain(domain.to_string(), final_port));
            }
        }

        // 处理纯 IP 地址
        if let Ok(ip_addr) = std::net::IpAddr::from_str(host_str) {
            let port = port.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Port is required for IP address: {}", host_str),
                )
            })?;
            let socket_addr = std::net::SocketAddr::new(ip_addr, port);
            return Ok(Address::Inet(socket_addr));
        }

        // 处理纯域名/主机名
        let port = port.unwrap_or(443);
        Ok(Address::Domain(host_str.to_string(), port))
    }
}

impl Address {
    /// 从异步读取流中解析地址（SOCKS5协议格式）
    pub async fn read_from<R>(reader: &mut R) -> socks::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let atyp = reader.read_u8().await?;
        Self::read_from_with_type(reader, atyp).await
    }

    /// 从异步读取流中解析地址，使用已知的地址类型（SOCKS5协议格式）
    pub async fn read_from_with_type<R>(reader: &mut R, atyp: u8) -> socks::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        match atyp {
            0x01 => {
                // IPv4
                let mut ip = [0u8; 4];
                reader.read_exact(&mut ip).await?;
                let port = reader.read_u16().await?;
                Ok(Address::Inet(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))))
            }
            0x03 => {
                // Domain name
                let len = reader.read_u8().await? as usize;
                let mut domain = vec![0u8; len];
                reader.read_exact(&mut domain).await?;
                let port = reader.read_u16().await?;
                let domain = String::from_utf8_lossy(&domain).to_string();
                Ok(Address::Domain(domain, port))
            }
            0x04 => {
                // IPv6
                let mut ip = [0u8; 16];
                reader.read_exact(&mut ip).await?;
                let port = reader.read_u16().await?;
                Ok(Address::Inet(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))))
            }
            _ => Err(socks::Socks5Error::InvalidAddressType(atyp)),
        }
    }

    /// 将地址写入缓冲区（SOCKS5协议格式）
    pub fn write_to_buf(&self, buf: &mut BytesMut) {
        match self {
            Address::Inet(SocketAddr::V4(addr)) => {
                buf.put_u8(0x01); // IPv4
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Address::Inet(SocketAddr::V6(addr)) => {
                buf.put_u8(0x04); // IPv6
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Address::Domain(domain, port) => {
                buf.put_u8(0x03); // Domain name
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
            Address::Unix(path) => {
                buf.put_u8(0x0F); // Unix domain socket (自定义)
                let path_str = path.to_string_lossy();
                buf.put_u8(path_str.len() as u8);
                buf.put_slice(path_str.as_bytes());
                // Unix 域套接字没有端口，我们写入 0
                buf.put_u16(0);
            }
        }
    }

    /// 获取地址的端口（对于 Unix 域套接字返回 0）
    pub fn port(&self) -> u16 {
        match self {
            Address::Inet(addr) => addr.port(),
            Address::Domain(_, port) => *port,
            Address::Unix(_) => 0,
        }
    }

    /// 获取地址的主机部分（用于显示）
    pub fn host(&self) -> String {
        match self {
            Address::Inet(addr) => addr.ip().to_string(),
            Address::Domain(domain, _) => domain.clone(),
            Address::Unix(path) => path.to_string_lossy().to_string(),
        }
    }

    /// 是否为 Unix 域套接字地址
    pub fn is_unix(&self) -> bool {
        matches!(self, Address::Unix(_))
    }

    /// 是否为 Inet 地址
    pub fn is_inet(&self) -> bool {
        matches!(self, Address::Inet(_))
    }

    /// 是否为域名地址
    pub fn is_domain(&self) -> bool {
        matches!(self, Address::Domain(_, _))
    }
}
