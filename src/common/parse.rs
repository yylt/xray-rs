use super::Address;
use std::io::{Error, ErrorKind, Result};

/// 解析 host:port 字符串为 Address
pub fn parse_host_port(target: &str) -> Result<Address> {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid port number"))?;
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            Ok(Address::Inet(std::net::SocketAddr::new(ip, port)))
        } else {
            Ok(Address::Domain(host.to_string(), port))
        }
    } else {
        Err(Error::new(ErrorKind::InvalidData, "Invalid host:port format"))
    }
}

/// 解析 host 字符串，无端口时使用默认端口
pub fn parse_host_with_default_port(host: &str, default_port: u16) -> Address {
    match parse_host_port(host) {
        Ok(addr) => addr,
        Err(_) => {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                Address::Inet(std::net::SocketAddr::new(ip, default_port))
            } else {
                Address::Domain(host.to_string(), default_port)
            }
        }
    }
}

/// Base64 解码
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim();
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for &byte in input.as_bytes() {
        if byte == b'=' {
            break;
        }
        let value = BASE64_CHARS
            .iter()
            .position(|&c| c == byte)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid base64 character"))? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(result)
}

/// 从字节流解析 SOCKS5/Trojan 风格的地址 (ATYP + ADDR + PORT)
/// 返回 (Address, 消耗的字节数)
pub fn parse_address_from_bytes(data: &[u8]) -> Result<(Address, usize)> {
    if data.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty address data"));
    }
    let atyp = data[0];
    let mut cursor = 1;

    match atyp {
        0x01 => {
            // IPv4: 4 bytes IP + 2 bytes port
            if data.len() < cursor + 6 {
                return Err(Error::new(ErrorKind::InvalidData, "Too short for IPv4 address"));
            }
            let ip = std::net::Ipv4Addr::new(data[cursor], data[cursor + 1], data[cursor + 2], data[cursor + 3]);
            cursor += 4;
            let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
            cursor += 2;
            Ok((
                Address::Inet(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port))),
                cursor,
            ))
        }
        0x03 => {
            // Domain: 1 byte len + domain + 2 bytes port
            if data.len() < cursor + 1 {
                return Err(Error::new(ErrorKind::InvalidData, "Too short for domain length"));
            }
            let len = data[cursor] as usize;
            cursor += 1;
            if data.len() < cursor + len + 2 {
                return Err(Error::new(ErrorKind::InvalidData, "Too short for domain address"));
            }
            let domain = String::from_utf8_lossy(&data[cursor..cursor + len]).to_string();
            cursor += len;
            let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
            cursor += 2;
            Ok((Address::Domain(domain, port), cursor))
        }
        0x04 => {
            // IPv6: 16 bytes IP + 2 bytes port
            if data.len() < cursor + 18 {
                return Err(Error::new(ErrorKind::InvalidData, "Too short for IPv6 address"));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[cursor..cursor + 16]);
            cursor += 16;
            let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
            cursor += 2;
            Ok((
                Address::Inet(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                ))),
                cursor,
            ))
        }
        _ => Err(Error::new(ErrorKind::InvalidData, format!("Invalid address type: {}", atyp))),
    }
}

/// 将 Address 编码为 SOCKS5/Trojan 风格的字节 (ATYP + ADDR + PORT)
pub fn encode_address_to_bytes(addr: &Address) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    match addr {
        Address::Inet(std::net::SocketAddr::V4(v4)) => {
            buf.push(0x01);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        Address::Inet(std::net::SocketAddr::V6(v6)) => {
            buf.push(0x04);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        Address::Domain(domain, port) => {
            buf.push(0x03);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Unix(_) => {
            return Err(Error::new(ErrorKind::Unsupported, "Unix address not supported in wire format"));
        }
    }
    Ok(buf)
}
