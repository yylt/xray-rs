use serde::{Deserialize, Serialize};

use crate::common::*;
use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream};
use std::io::{self, Result};
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpStream, UdpSocket};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;

mod sockopt;

pub mod balancer;
pub mod grpc;
pub mod raw;
pub mod tls;
pub mod websocket;

#[allow(dead_code)]
pub(crate) const UNIX_SOCKET_UNSUPPORTED: &str = "Unix domain sockets are unsupported on this platform";

#[allow(dead_code)]
pub(crate) fn unix_socket_supported() -> bool {
    cfg!(unix)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSettings {
    #[serde(rename = "network", default)]
    network: Network,

    #[serde(rename = "security", default)]
    security: Security,

    #[serde(rename = "sockopt", default)]
    sockopt: sockopt::SocketOpt,

    #[serde(rename = "tlsSettings")]
    tls_settings: Option<tls::TlsSettings>,

    #[serde(rename = "wsSettings")]
    ws_settings: Option<websocket::WsSettings>,

    #[serde(rename = "grpcSettings")]
    grpc_settings: Option<grpc::GrpcSettings>,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            network: Network::default(),
            security: Security::default(),
            sockopt: sockopt::SocketOpt::default(),
            tls_settings: None,
            ws_settings: None,
            grpc_settings: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub enum Network {
    #[default]
    #[serde(rename = "tcp", alias = "raw")]
    Tcp,
    #[serde(rename = "grpc")]
    Grpc,
    #[serde(rename = "ws", alias = "websocket")]
    Ws,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub enum Security {
    #[default]
    #[serde(rename = "none")]
    None,
    #[serde(rename = "tls")]
    Tls,
}

// Trait alias for streams that are both readable and writable
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncStream for T {}

pub enum TrStream {
    Tcp(TcpStream),
    TlsClient(tokio_rustls::client::TlsStream<TcpStream>),
    TlsServer(tokio_rustls::server::TlsStream<TcpStream>),
    #[cfg(unix)]
    Unix(UnixStream),
    Udp(UdpSocket),
    Buffered(Box<BufferedStream>),
    Grpc(grpc::GrpcStream),
    WebSocketTls(Box<WebSocketIo<tokio_rustls::client::TlsStream<TcpStream>>>),
    WebSocketTlsServer(Box<WebSocketIo<tokio_rustls::server::TlsStream<TcpStream>>>),
    WebSocketPlain(Box<WebSocketIo<TcpStream>>),
    Tun(Box<dyn AsyncStream>),
}

pub struct WebSocketIo<IO> {
    inner: WebSocketStream<IO>,
    read_buf: BytesMut,
}

impl<IO> WebSocketIo<IO> {
    fn new(inner: WebSocketStream<IO>) -> Self {
        Self {
            inner,
            read_buf: BytesMut::new(),
        }
    }
}

fn websocket_err_to_io(err: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

impl<IO> AsyncRead for WebSocketIo<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if !this.read_buf.is_empty() {
            let to_copy = std::cmp::min(this.read_buf.len(), buf.remaining());
            let chunk = this.read_buf.split_to(to_copy);
            buf.put_slice(&chunk[..]);
            return std::task::Poll::Ready(Ok(()));
        }

        loop {
            match std::pin::Pin::new(&mut this.inner).poll_next(cx) {
                std::task::Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    let to_copy = std::cmp::min(data.len(), buf.remaining());
                    buf.put_slice(&data[..to_copy]);
                    if to_copy < data.len() {
                        this.read_buf.extend_from_slice(&data[to_copy..]);
                    }
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(Some(Ok(Message::Text(text)))) => {
                    let data = text.to_string().into_bytes();
                    let to_copy = std::cmp::min(data.len(), buf.remaining());
                    buf.put_slice(&data[..to_copy]);
                    if to_copy < data.len() {
                        this.read_buf.extend_from_slice(&data[to_copy..]);
                    }
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(Some(Ok(Message::Ping(_))))
                | std::task::Poll::Ready(Some(Ok(Message::Pong(_)))) => {
                    continue;
                }
                std::task::Poll::Ready(Some(Ok(Message::Close(_)))) => {
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(Some(Ok(_))) => {
                    continue;
                }
                std::task::Poll::Ready(Some(Err(err))) => {
                    return std::task::Poll::Ready(Err(websocket_err_to_io(err)));
                }
                std::task::Poll::Ready(None) => {
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

impl<IO> AsyncWrite for WebSocketIo<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_ready(cx) {
            std::task::Poll::Ready(Ok(())) => {
                std::pin::Pin::new(&mut this.inner)
                    .start_send(Message::Binary(buf.to_vec().into()))
                    .map_err(websocket_err_to_io)?;
                std::task::Poll::Ready(Ok(buf.len()))
            }
            std::task::Poll::Ready(Err(err)) => std::task::Poll::Ready(Err(websocket_err_to_io(err))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner)
            .poll_flush(cx)
            .map_err(websocket_err_to_io)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner)
            .poll_close(cx)
            .map_err(websocket_err_to_io)
    }
}

// Buffered stream wrapper for HTTP proxy
pub struct BufferedStream {
    inner: Box<TrStream>,
    buffer: Option<Bytes>,
    buffer_pos: usize,
}

impl BufferedStream {
    pub fn new(inner: TrStream, buffer: impl Into<Bytes>) -> Self {
        Self {
            inner: Box::new(inner),
            buffer: Some(buffer.into()),
            buffer_pos: 0,
        }
    }
}

impl AsyncRead for BufferedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // First, send the buffered data
        let this = &mut *self;
        if let Some(data) = &this.buffer {
            if this.buffer_pos < data.len() {
                let remaining = &data[this.buffer_pos..];
                let to_copy = std::cmp::min(buf.remaining(), remaining.len());
                buf.put_slice(&remaining[..to_copy]);
                this.buffer_pos += to_copy;

                if this.buffer_pos >= data.len() {
                    this.buffer = None;
                }

                return std::task::Poll::Ready(Ok(()));
            }
        }

        // Then forward to inner stream
        std::pin::Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for BufferedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for TrStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            TrStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TrStream::TlsClient(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TrStream::TlsServer(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            TrStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TrStream::Udp(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP does not support stream read",
            ))),
            TrStream::Buffered(s) => std::pin::Pin::new(&mut **s).poll_read(cx, buf),
            TrStream::Grpc(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            TrStream::WebSocketTls(s) => std::pin::Pin::new(&mut **s).poll_read(cx, buf),
            TrStream::WebSocketTlsServer(s) => std::pin::Pin::new(&mut **s).poll_read(cx, buf),
            TrStream::WebSocketPlain(s) => std::pin::Pin::new(&mut **s).poll_read(cx, buf),
            TrStream::Tun(s) => std::pin::Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TrStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            TrStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            TrStream::TlsClient(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            TrStream::TlsServer(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            TrStream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            TrStream::Udp(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP does not support stream write",
            ))),
            TrStream::Buffered(s) => std::pin::Pin::new(&mut **s).poll_write(cx, buf),
            TrStream::Grpc(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            TrStream::WebSocketTls(s) => std::pin::Pin::new(&mut **s).poll_write(cx, buf),
            TrStream::WebSocketTlsServer(s) => std::pin::Pin::new(&mut **s).poll_write(cx, buf),
            TrStream::WebSocketPlain(s) => std::pin::Pin::new(&mut **s).poll_write(cx, buf),
            TrStream::Tun(s) => std::pin::Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            TrStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            TrStream::TlsClient(s) => std::pin::Pin::new(s).poll_flush(cx),
            TrStream::TlsServer(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            TrStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
            TrStream::Udp(_) => std::task::Poll::Ready(Ok(())),
            TrStream::Buffered(s) => std::pin::Pin::new(&mut **s).poll_flush(cx),
            TrStream::Grpc(s) => std::pin::Pin::new(s).poll_flush(cx),
            TrStream::WebSocketTls(s) => std::pin::Pin::new(&mut **s).poll_flush(cx),
            TrStream::WebSocketTlsServer(s) => std::pin::Pin::new(&mut **s).poll_flush(cx),
            TrStream::WebSocketPlain(s) => std::pin::Pin::new(&mut **s).poll_flush(cx),
            TrStream::Tun(s) => std::pin::Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            TrStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TrStream::TlsClient(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TrStream::TlsServer(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            TrStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TrStream::Udp(_) => std::task::Poll::Ready(Ok(())),
            TrStream::Buffered(s) => std::pin::Pin::new(&mut **s).poll_shutdown(cx),
            TrStream::Grpc(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            TrStream::WebSocketTls(s) => std::pin::Pin::new(&mut **s).poll_shutdown(cx),
            TrStream::WebSocketTlsServer(s) => std::pin::Pin::new(&mut **s).poll_shutdown(cx),
            TrStream::WebSocketPlain(s) => std::pin::Pin::new(&mut **s).poll_shutdown(cx),
            TrStream::Tun(s) => std::pin::Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

// all should support inbound and outbound
pub enum Transport {
    Raw(raw::Raw), // Tcp, Udp, Unix,
    WebSocket(websocket::WebSocket),
    Grpc(grpc::Grpc),
}

impl Transport {
    pub fn new(
        set: &StreamSettings,
        server: Option<Address>,
        dns: std::sync::Arc<crate::route::DnsResolver>,
    ) -> Result<Self> {
        match set.network {
            Network::Tcp => Ok(Transport::Raw(raw::Raw::new(set, dns))),
            Network::Grpc => Ok(Transport::Grpc(grpc::Grpc::new(set, server, dns)?)),
            Network::Ws => Ok(Transport::WebSocket(websocket::WebSocket::new(set, dns)?)),
        }
    }

    /// Get DNS resolver reference
    pub fn dns(&self) -> &std::sync::Arc<crate::route::DnsResolver> {
        match self {
            Transport::Grpc(grpc) => grpc.dns(),
            Transport::WebSocket(ws) => ws.dns(),
            Transport::Raw(raw) => raw.dns(),
        }
    }

    pub async fn listen(&self, addr: &Address) -> Result<BoxStream<(TrStream, Address), std::io::Error>> {
        match self {
            Transport::Raw(raw) => raw.listen(addr).await,
            Transport::WebSocket(ws) => ws.listen(addr).await,
            Transport::Grpc(grpc) => grpc.listen(addr).await,
        }
    }

    pub async fn connect(&self, dest: &Address, proto: Protocol) -> Result<TrStream> {
        match self {
            Transport::Raw(raw) => raw.connect(dest, proto).await,
            Transport::WebSocket(ws) => ws.connect(dest).await,
            Transport::Grpc(grpc) => grpc.connect(dest, proto).await,
        }
    }
}
