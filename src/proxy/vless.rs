use super::*;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VLESS_VERSION: u8 = 0;
const VLESS_CMD_TCP: u8 = 0x01;
const VLESS_ADDR_IPV4: u8 = 0x01;
const VLESS_ADDR_DOMAIN: u8 = 0x02;
const VLESS_ADDR_IPV6: u8 = 0x03;

#[derive(Serialize, Deserialize, Debug)]
pub struct InSetting {
    #[serde(rename = "id")]
    id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OutSetting {
    #[serde(rename = "address")]
    pub address: String,

    #[serde(rename = "port")]
    pub port: u16,

    #[serde(rename = "id")]
    pub id: String,
}

pub struct Proxy {
    user_id: [u8; 16],
    server: Address,
    tr: transport::Transport,
}

impl Proxy {
    pub fn new_inbound(sets: &InSetting, tr: transport::Transport) -> Result<Self> {
        Ok(Self {
            user_id: parse_uuid(&sets.id)?,
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
            user_id: parse_uuid(&sets.id)?,
            server: Address::try_from((&sets.address.as_str(), Some(sets.port)))?,
            tr,
        })
    }

    pub async fn listen(self, addr: Address) -> BoxStream<ProxyStream, std::io::Error> {
        let stream_result = self.tr.listen(&addr).await;

        match stream_result {
            Ok(transport_stream) => {
                let user_id = self.user_id.clone();

                let proxy_stream = async_stream::stream! {
                    tokio::pin!(transport_stream);

                    while let Some(result) = tokio_stream::StreamExt::next(&mut transport_stream).await {
                        match result {
                            Ok((stream, peer_addr)) => {
                                match handle_inbound(stream, peer_addr, &user_id).await {
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
        if protocol == Protocol::Udp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "VLESS outbound UDP-over-stream is not supported in this path",
            ));
        }
        let mut stream = self.tr.connect(&self.server, Protocol::Tcp).await?;
        send_vless_request(&mut stream, &self.user_id, target).await?;
        read_vless_response(&mut stream).await?;
        Ok(stream)
    }

    pub async fn run(&mut self) {}
}

fn parse_uuid(id: &str) -> std::io::Result<[u8; 16]> {
    let parsed = uuid::Uuid::parse_str(id)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid VLESS UUID: {}", e)))?;
    Ok(*parsed.as_bytes())
}

async fn handle_inbound(
    mut stream: transport::TrStream,
    peer_addr: Address,
    expected_user_id: &[u8; 16],
) -> std::io::Result<ProxyStream> {
    let dest = read_vless_request(&mut stream, expected_user_id).await?;
    send_vless_response(&mut stream).await?;
    Ok(ProxyStream::new(Protocol::Tcp, peer_addr, dest, stream))
}

async fn read_vless_request<R>(stream: &mut R, expected_user_id: &[u8; 16]) -> std::io::Result<Address>
where
    R: AsyncRead + Unpin,
{
    let mut version = [0u8; 1];
    AsyncReadExt::read_exact(stream, &mut version).await?;
    if version[0] != VLESS_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid VLESS version: {}", version[0]),
        ));
    }

    let mut user_id = [0u8; 16];
    AsyncReadExt::read_exact(stream, &mut user_id).await?;
    if &user_id != expected_user_id {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Invalid VLESS user id",
        ));
    }

    let mut addon_len = [0u8; 1];
    AsyncReadExt::read_exact(stream, &mut addon_len).await?;
    if addon_len[0] > 0 {
        let mut addon = vec![0u8; addon_len[0] as usize];
        AsyncReadExt::read_exact(stream, &mut addon).await?;
    }

    let mut cmd = [0u8; 1];
    AsyncReadExt::read_exact(stream, &mut cmd).await?;
    if cmd[0] != VLESS_CMD_TCP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("Unsupported VLESS command: {}", cmd[0]),
        ));
    }

    read_target_address(stream).await
}

async fn send_vless_request<W>(stream: &mut W, user_id: &[u8; 16], target: &Address) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = BytesMut::with_capacity(128);
    buf.put_u8(VLESS_VERSION);
    buf.put_slice(user_id);
    buf.put_u8(0);
    buf.put_u8(VLESS_CMD_TCP);
    write_target_address(target, &mut buf)?;

    AsyncWriteExt::write_all(stream, &buf).await?;
    AsyncWriteExt::flush(stream).await?;
    Ok(())
}

async fn send_vless_response<W>(stream: &mut W) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    AsyncWriteExt::write_all(stream, &[VLESS_VERSION, 0]).await?;
    AsyncWriteExt::flush(stream).await?;
    Ok(())
}

async fn read_vless_response<R>(stream: &mut R) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut version = [0u8; 1];
    AsyncReadExt::read_exact(stream, &mut version).await?;
    if version[0] != VLESS_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid VLESS response version: {}", version[0]),
        ));
    }

    let mut addon_len = [0u8; 1];
    AsyncReadExt::read_exact(stream, &mut addon_len).await?;
    if addon_len[0] > 0 {
        let mut addon = vec![0u8; addon_len[0] as usize];
        AsyncReadExt::read_exact(stream, &mut addon).await?;
    }

    Ok(())
}

fn write_target_address(addr: &Address, buf: &mut BytesMut) -> std::io::Result<()> {
    match addr {
        Address::Inet(std::net::SocketAddr::V4(addr)) => {
            buf.put_u16(addr.port());
            buf.put_u8(VLESS_ADDR_IPV4);
            buf.put_slice(&addr.ip().octets());
            Ok(())
        }
        Address::Inet(std::net::SocketAddr::V6(addr)) => {
            buf.put_u16(addr.port());
            buf.put_u8(VLESS_ADDR_IPV6);
            buf.put_slice(&addr.ip().octets());
            Ok(())
        }
        Address::Domain(domain, port) => {
            if domain.as_bytes().len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Domain name too long for VLESS",
                ));
            }
            buf.put_u16(*port);
            buf.put_u8(VLESS_ADDR_DOMAIN);
            buf.put_u8(domain.len() as u8);
            buf.put_slice(domain.as_bytes());
            Ok(())
        }
        Address::Unix(_) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unix address is not supported by VLESS",
        )),
    }
}

async fn read_target_address<R>(stream: &mut R) -> std::io::Result<Address>
where
    R: AsyncRead + Unpin,
{
    let mut port_buf = [0u8; 2];
    AsyncReadExt::read_exact(stream, &mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    let mut atyp = [0u8; 1];
    AsyncReadExt::read_exact(stream, &mut atyp).await?;

    match atyp[0] {
        VLESS_ADDR_IPV4 => {
            let mut ip = [0u8; 4];
            AsyncReadExt::read_exact(stream, &mut ip).await?;
            Ok(Address::Inet(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(ip),
                port,
            ))))
        }
        VLESS_ADDR_DOMAIN => {
            let mut len_buf = [0u8; 1];
            AsyncReadExt::read_exact(stream, &mut len_buf).await?;
            let domain_len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; domain_len];
            AsyncReadExt::read_exact(stream, &mut domain_buf).await?;
            let domain = String::from_utf8(domain_buf).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid domain encoding: {}", e))
            })?;
            Ok(Address::Domain(domain, port))
        }
        VLESS_ADDR_IPV6 => {
            let mut ip = [0u8; 16];
            AsyncReadExt::read_exact(stream, &mut ip).await?;
            Ok(Address::Inet(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(ip),
                port,
                0,
                0,
            ))))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid VLESS address type: {}", atyp[0]),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_parse_uuid_ok() {
        let id = "11111111-1111-1111-1111-111111111111";
        let parsed = parse_uuid(id);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap().len(), 16);
    }

    #[test]
    fn test_parse_uuid_invalid() {
        let parsed = parse_uuid("invalid-uuid");
        assert!(parsed.is_err());
        assert_eq!(parsed.err().unwrap().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_read_target_address_ipv4() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let addr = Address::Inet(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080)));
        let mut buf = BytesMut::new();
        write_target_address(&addr, &mut buf).unwrap();

        tokio::spawn(async move {
            let _ = client.write_all(&buf).await;
        });

        let decoded = read_target_address(&mut server).await.unwrap();
        match decoded {
            Address::Inet(sa) => assert_eq!(sa, "127.0.0.1:8080".parse::<SocketAddr>().unwrap()),
            _ => panic!("expected inet address"),
        }
    }

    #[tokio::test]
    async fn test_read_target_address_domain() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let addr = Address::Domain("example.com".to_string(), 443);
        let mut buf = BytesMut::new();
        write_target_address(&addr, &mut buf).unwrap();

        tokio::spawn(async move {
            let _ = client.write_all(&buf).await;
        });

        let decoded = read_target_address(&mut server).await.unwrap();
        match decoded {
            Address::Domain(domain, port) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("expected domain address"),
        }
    }

    #[tokio::test]
    async fn test_read_target_address_ipv6() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let addr = Address::Inet(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0, 0)));
        let mut buf = BytesMut::new();
        write_target_address(&addr, &mut buf).unwrap();

        tokio::spawn(async move {
            let _ = client.write_all(&buf).await;
        });

        let decoded = read_target_address(&mut server).await.unwrap();
        match decoded {
            Address::Inet(sa) => assert_eq!(sa, "[::1]:8443".parse::<SocketAddr>().unwrap()),
            _ => panic!("expected inet address"),
        }
    }

    #[tokio::test]
    async fn test_read_vless_request_ok() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let user_id = parse_uuid("11111111-1111-1111-1111-111111111111").unwrap();
        let target = Address::Domain("example.com".to_string(), 443);

        tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.put_u8(VLESS_VERSION);
            buf.put_slice(&user_id);
            buf.put_u8(0);
            buf.put_u8(VLESS_CMD_TCP);
            write_target_address(&target, &mut buf).unwrap();
            let _ = client.write_all(&buf).await;
        });

        let decoded = read_vless_request(&mut server, &user_id).await.unwrap();
        match decoded {
            Address::Domain(domain, port) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("expected domain address"),
        }
    }

    #[tokio::test]
    async fn test_read_vless_request_invalid_uuid() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let expected = parse_uuid("11111111-1111-1111-1111-111111111111").unwrap();
        let actual = parse_uuid("22222222-2222-2222-2222-222222222222").unwrap();
        let target = Address::Domain("example.com".to_string(), 443);

        tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.put_u8(VLESS_VERSION);
            buf.put_slice(&actual);
            buf.put_u8(0);
            buf.put_u8(VLESS_CMD_TCP);
            write_target_address(&target, &mut buf).unwrap();
            let _ = client.write_all(&buf).await;
        });

        let err = read_vless_request(&mut server, &expected).await.err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_vless_response_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(32);

        let writer = tokio::spawn(async move {
            send_vless_response(&mut client).await.unwrap();
        });

        let reader = tokio::spawn(async move {
            read_vless_response(&mut server).await.unwrap();
        });

        writer.await.unwrap();
        reader.await.unwrap();
    }
}
