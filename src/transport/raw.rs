use super::*;
use log::warn;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

pub struct Raw {
    opt: sockopt::SocketOpt,
    tls_client: Option<tls::client::Tls>,
    tls_server: Option<tls::server::Tls>,
    dns: std::sync::Arc<crate::route::DnsResolver>,
}

impl Raw {
    pub fn new(sset: &StreamSettings, dns: std::sync::Arc<crate::route::DnsResolver>) -> Self {
        let tls_client = if sset.security == Security::Tls {
            sset.tls_settings.as_ref().and_then(|ts| tls::client::new(ts).ok())
        } else {
            None
        };

        let tls_server = if sset.security == Security::Tls {
            sset.tls_settings.as_ref().and_then(|ts| tls::server::new(ts).ok())
        } else {
            None
        };

        Self {
            opt: sset.sockopt.clone(),
            tls_client,
            tls_server,
            dns,
        }
    }

    pub fn dns(&self) -> &std::sync::Arc<crate::route::DnsResolver> {
        &self.dns
    }

    /// 建立连接
    /// 如果配置了 TLS，会自动进行 TLS 握手
    pub async fn connect(&self, dest: &Address, proto: Protocol) -> Result<TrStream> {
        match (dest, proto) {
            // TCP 连接 - 支持域名解析和多地址重试
            (Address::Inet(addr), Protocol::Tcp) => self.connect_tcp(addr).await,
            (Address::Domain(_domain, _port), Protocol::Tcp) => {
                // 解析域名
                let socket_addrs = self.resolve_address(dest).await?;

                if socket_addrs.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "No addresses resolved"));
                }

                // 尝试所有地址，直到成功
                let mut last_err = None;
                for addr in socket_addrs {
                    match self.connect_tcp(&addr).await {
                        Ok(stream) => return Ok(stream),
                        Err(e) => {
                            warn!("Failed to connect to {}: {}", addr, e);
                            last_err = Some(e);
                        }
                    }
                }

                Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "All addresses failed")))
            }

            // Unix 域套接字
            #[cfg(unix)]
            (Address::Unix(path), Protocol::Tcp) => {
                let stream = UnixStream::connect(path).await?;
                let stream = self.opt.apply_unixstream(stream)?;
                Ok(TrStream::Unix(stream))
            }
            #[cfg(not(unix))]
            (Address::Unix(_), Protocol::Tcp) => {
                Err(io::Error::new(io::ErrorKind::Unsupported, super::UNIX_SOCKET_UNSUPPORTED))
            }

            // UDP 连接
            (Address::Inet(addr), Protocol::Udp) => {
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                socket.connect(addr).await?;
                Ok(TrStream::Udp(socket))
            }

            _ => Err(io::Error::new(io::ErrorKind::Other, "不支持的地址类型和协议组合")),
        }
    }

    async fn resolve_address(&self, dest: &Address) -> Result<Vec<std::net::SocketAddr>> {
        match dest {
            Address::Inet(addr) => Ok(vec![*addr]),
            Address::Domain(domain, port) => match self.dns.resolve(domain).await {
                Ok(ips) => {
                    let addrs: Vec<std::net::SocketAddr> =
                        ips.iter().map(|ip| std::net::SocketAddr::new(*ip, *port)).collect();
                    Ok(addrs)
                }
                Err(e) => Err(io::Error::new(io::ErrorKind::NotFound, format!("DNS resolution failed: {}", e))),
            },
            Address::Unix(_) => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unix socket doesn't support DNS")),
        }
    }

    /// 监听，只支持 TCP 和 Unix
    pub async fn listen(&self, addr: &Address) -> Result<BoxStream<(TrStream, Address), std::io::Error>> {
        match addr {
            Address::Inet(addr) => self.listen_tcp(addr).await,
            #[cfg(unix)]
            Address::Unix(path) => self.listen_unix(path).await,
            #[cfg(not(unix))]
            Address::Unix(_) => {
                Err(std::io::Error::new(std::io::ErrorKind::Unsupported, super::UNIX_SOCKET_UNSUPPORTED).into())
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "listen only supports TCP and Unix addresses",
            )
            .into()),
        }
    }

    // TCP 连接辅助方法
    async fn connect_tcp(&self, addr: &std::net::SocketAddr) -> Result<TrStream> {
        let stream = TcpStream::connect(addr).await?;
        let stream = self.opt.apply_tcpstream(stream)?;

        if let Some(ref tls) = self.tls_client {
            let tls_stream = tls.connect(addr, stream).await?;
            Ok(TrStream::TlsClient(tls_stream))
        } else {
            Ok(TrStream::Tcp(stream))
        }
    }

    // TCP 监听辅助方法
    async fn listen_tcp(&self, addr: &std::net::SocketAddr) -> Result<BoxStream<(TrStream, Address), std::io::Error>> {
        let listener = TcpListener::bind(addr).await?;
        let opt = self.opt.clone();
        let tls_server = self.tls_server.clone();

        let stream = async_stream::stream! {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let stream = match opt.apply_tcpstream(stream) {
                            Ok(s) => s,
                            Err(e) => {
                                yield Err(e);
                                continue;
                            }
                        };

                        let final_stream = if let Some(ref tls) = tls_server {
                            match tls.accept(stream).await {
                                Ok(tls_stream) => TrStream::TlsServer(tls_stream),
                                Err(e) => {
                                    yield Err(e);
                                    continue;
                                }
                            }
                        } else {
                            TrStream::Tcp(stream)
                        };

                        yield Ok((final_stream, Address::Inet(peer_addr)));
                    }
                    Err(e) => yield Err(e),
                }
            }
        };

        Ok(Box::pin(stream))
    }

    // Unix 监听辅助方法
    #[cfg(unix)]
    async fn listen_unix(&self, path: &std::path::PathBuf) -> Result<BoxStream<(TrStream, Address), std::io::Error>> {
        // 清理已存在的 socket 文件
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        let opt = self.opt.clone();
        let path = path.clone();

        let stream = async_stream::stream! {
            loop {
                match listener.accept().await {
                    Ok((stream, _peer_addr)) => {
                        let stream = match opt.apply_unixstream(stream) {
                            Ok(s) => s,
                            Err(e) => {
                                yield Err(e);
                                continue;
                            }
                        };
                        yield Ok((TrStream::Unix(stream), Address::Unix(path.clone())));
                    }
                    Err(e) => yield Err(e),
                }
            }
        };

        Ok(Box::pin(stream))
    }
}
