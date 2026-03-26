use super::*;

use std::io;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 错误类型
#[derive(Error, Debug)]
pub enum Socks5Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid SOCKS version: expected {expected}, got {got}")]
    InvalidVersion { expected: u8, got: u8 },

    #[error("Invalid reserved byte: expected {expected}, got {got}")]
    InvalidReserved { expected: u8, got: u8 },

    #[error("Unsupported authentication method: {0}")]
    UnsupportedAuthMethod(u8),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid command: {0}")]
    InvalidCommand(u8),

    #[error("Invalid address type: {0}")]
    InvalidAddressType(u8),

    #[error("Invalid reply: {0}")]
    InvalidReply(u8),

    #[error("Connection rejected")]
    ConnectionRejected,

    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

pub type Result<T> = std::result::Result<T, Socks5Error>;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMethod {
    NoAuth = 0x00,
    UsernamePassword = 0x02,
    NoAcceptable = 0xFF,
}

// authen method
impl TryFrom<u8> for AuthMethod {
    type Error = Socks5Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(AuthMethod::NoAuth),
            0x02 => Ok(AuthMethod::UsernamePassword),
            0xFF => Ok(AuthMethod::NoAcceptable),
            _ => Err(Socks5Error::UnsupportedAuthMethod(value)),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = Socks5Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociate),
            _ => Err(Socks5Error::InvalidCommand(value)),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl TryFrom<u8> for Reply {
    type Error = Socks5Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Reply::Succeeded),
            0x01 => Ok(Reply::GeneralFailure),
            0x02 => Ok(Reply::ConnectionNotAllowed),
            0x03 => Ok(Reply::NetworkUnreachable),
            0x04 => Ok(Reply::HostUnreachable),
            0x05 => Ok(Reply::ConnectionRefused),
            0x06 => Ok(Reply::TtlExpired),
            0x07 => Ok(Reply::CommandNotSupported),
            0x08 => Ok(Reply::AddressTypeNotSupported),
            _ => Err(Socks5Error::InvalidReply(value)),
        }
    }
}

/// SOCKS5 连接处理器
pub struct Socks5Processor {
    auth: Option<Account>,
}

fn build_method_selection_reply(method: AuthMethod) -> [u8; 2] {
    [0x05, method as u8]
}

fn build_auth_status_reply(success: bool) -> [u8; 2] {
    [0x01, if success { 0x00 } else { 0x01 }]
}

fn build_reply_packet(reply: Reply, addr: &Address) -> Result<Vec<u8>> {
    if addr.is_unix() {
        return Err(Socks5Error::ProtocolError("unix domain not supported".into()));
    }

    let mut buf = BytesMut::with_capacity(reply_packet_len(addr));
    buf.put_u8(0x05);
    buf.put_u8(reply as u8);
    buf.put_u8(0x00);
    addr.write_to_buf(&mut buf);
    Ok(buf.to_vec())
}

fn reply_packet_len(addr: &Address) -> usize {
    match addr {
        Address::Inet(std::net::SocketAddr::V4(_)) => 3 + 1 + 4 + 2,
        Address::Inet(std::net::SocketAddr::V6(_)) => 3 + 1 + 16 + 2,
        Address::Domain(domain, _) => 3 + 1 + 1 + domain.len() + 2,
        Address::Unix(path) => 3 + 1 + 1 + path.to_string_lossy().len() + 2,
    }
}

impl Socks5Processor {
    /// 创建新的 SOCKS5 处理器，只包含认证信息
    pub fn new(auth: Option<Account>) -> Self {
        Self { auth }
    }

    /// 处理完整的 SOCKS5 握手和请求
    pub async fn process<T>(&mut self, mut stream: T) -> Result<(T, Command, Address)>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // 执行握手
        self.handshake(&mut stream).await?;

        // 获取请求
        let (cmd, addr) = self.get_request(&mut stream).await?;

        // 发送成功响应
        self.send_reply(&mut stream, Reply::Succeeded, &addr).await?;

        Ok((stream, cmd, addr))
    }

    /// SOCKS5 握手阶段
    /// Made public to support client-mode handshake for outbound UDP Associate
    pub async fn handshake<T>(&self, stream: &mut T) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // 读取握手请求
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        // 验证版本
        if buf[0] != 0x05 {
            return Err(Socks5Error::InvalidVersion {
                expected: 0x05,
                got: buf[0],
            });
        }

        let nmethods = buf[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        // 选择认证方法
        let selected_method = self.select_auth_method(&methods)?;

        // 发送选择的认证方法
        stream.write_all(&build_method_selection_reply(selected_method)).await?;

        // 如果需要认证，执行认证
        if selected_method == AuthMethod::UsernamePassword {
            self.authenticate(stream).await?;
        }

        Ok(())
    }

    /// 选择认证方法
    fn select_auth_method(&self, methods: &[u8]) -> Result<AuthMethod> {
        if self.auth.is_some() {
            if methods.contains(&(AuthMethod::UsernamePassword as u8)) {
                return Ok(AuthMethod::UsernamePassword);
            }
        } else {
            if methods.contains(&(AuthMethod::NoAuth as u8)) {
                return Ok(AuthMethod::NoAuth);
            }
        }

        Ok(AuthMethod::NoAcceptable)
    }

    /// 用户名密码认证
    async fn authenticate<T>(&self, stream: &mut T) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let account = self.auth.as_ref().unwrap();

        // 读取认证请求
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        if buf[0] != 0x01 {
            return Err(Socks5Error::ProtocolError("Invalid authentication version".into()));
        }

        let uname_len = buf[1] as usize;
        let mut uname = vec![0u8; uname_len];
        stream.read_exact(&mut uname).await?;

        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;
        let passwd_len = buf[0] as usize;
        let mut passwd = vec![0u8; passwd_len];
        stream.read_exact(&mut passwd).await?;

        // 验证用户名密码，避免额外构造 Cow<String>
        let auth_success = uname == account.username.as_bytes() && passwd == account.password.as_bytes();

        stream.write_all(&build_auth_status_reply(auth_success)).await?;

        if auth_success {
            Ok(())
        } else {
            Err(Socks5Error::AuthenticationFailed)
        }
    }

    /// 获取客户端请求
    pub async fn get_request<T>(&self, stream: &mut T) -> Result<(Command, Address)>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;

        log::debug!("[SOCKS5] Request header: {:02x?}", header);

        // 验证版本
        if header[0] != 0x05 {
            log::error!("[SOCKS5] Invalid version: expected 0x05, got 0x{:02x}", header[0]);
            return Err(Socks5Error::InvalidVersion {
                expected: 0x05,
                got: header[0],
            });
        }

        // 解析命令
        let cmd = Command::try_from(header[1])?;
        log::debug!("[SOCKS5] Command: {:?}", cmd);

        // 验证保留字节
        if header[2] != 0x00 {
            log::error!("[SOCKS5] Invalid reserved byte: expected 0x00, got 0x{:02x}", header[2]);
            return Err(Socks5Error::InvalidReserved {
                expected: 0x00,
                got: header[2],
            });
        }

        log::debug!("[SOCKS5] Address type byte: 0x{:02x}", header[3]);

        // 解析地址 - 使用已经读取的地址类型
        let addr = Address::read_from_with_type(stream, header[3]).await?;
        log::debug!("[SOCKS5] Parsed address: {:?}", addr);

        Ok((cmd, addr))
    }

    /// 发送响应
    pub async fn send_reply<T>(&self, stream: &mut T, reply: Reply, addr: &Address) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let packet = build_reply_packet(reply, addr)?;
        stream.write_all(&packet).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_reply_packet_ipv4_succeeded() {
        let addr = Address::Inet("127.0.0.1:8080".parse().unwrap());
        let packet = build_reply_packet(Reply::Succeeded, &addr).unwrap();

        assert_eq!(packet, vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]);
    }

    #[test]
    fn build_reply_packet_rejects_unix_address() {
        let addr = Address::Unix("/tmp/test.sock".into());
        let err = build_reply_packet(Reply::Succeeded, &addr).unwrap_err();

        match err {
            Socks5Error::ProtocolError(msg) => assert!(msg.contains("unix domain not supported")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
