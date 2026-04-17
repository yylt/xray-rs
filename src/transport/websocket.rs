use super::*;
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{Request as WsRequest, Response as WsResponse};
use tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL;
use tokio_tungstenite::tungstenite::http::HeaderValue;

// NOTE: WebSocket streams don't directly implement AsyncRead/AsyncWrite
// because WebSocket is a message-oriented protocol, not a byte stream.
// The WebSocketStream type provides read_message() and write_message() methods
// for frame-based I/O. Applications using WebSocket transport need to handle
// message framing, or a frame-to-stream adapter layer would be needed for
// transparent byte-stream usage with existing proxy protocols.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsSettings {
    #[serde(rename = "path", default = "default_path")]
    path: String,
}

fn default_path() -> String {
    "/ws".to_string()
}

impl Default for WsSettings {
    fn default() -> Self {
        Self { path: default_path() }
    }
}

// WebSocket transport implementation using tokio-tungstenite
//
// Architecture:
// - Client: TCP/TLS → WebSocket handshake → WebSocketIo adapter → AsyncRead/Write
// - Server: TCP listener → Accept → TLS (optional) → WebSocket accept → WebSocketIo adapter
//
// The WebSocketIo adapter (in mod.rs) converts message-oriented WebSocket frames
// to byte-oriented AsyncRead/AsyncWrite streams for transparent proxy protocol usage.
//
// See docs/websocket_design.md for detailed design documentation.
pub struct WebSocket {
    settings: WsSettings,
    opt: sockopt::SocketOpt,
    tls_client: Option<tls::client::Tls>,
    tls_server: Option<tls::server::Tls>,
    dns: std::sync::Arc<crate::route::DnsResolver>,
}

impl WebSocket {
    pub fn new(sset: &StreamSettings, dns: std::sync::Arc<crate::route::DnsResolver>) -> std::io::Result<Self> {
        let ws_settings = sset.ws_settings.as_ref().cloned().unwrap_or_default();

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

        Ok(Self {
            settings: ws_settings,
            opt: sset.sockopt.clone(),
            tls_client,
            tls_server,
            dns,
        })
    }

    pub fn dns(&self) -> &std::sync::Arc<crate::route::DnsResolver> {
        &self.dns
    }

    pub async fn connect(&self, addr: &crate::common::Address, pre_data: Option<Bytes>) -> std::io::Result<TrStream> {
        log::debug!("WebSocket client connecting to {:?}", addr);

        let socket_addrs = self.resolve_address(addr).await?;

        if socket_addrs.is_empty() {
            warn!("No addresses resolved for {:?}", addr);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "No addresses resolved"));
        }

        self.connect_tcp(&socket_addrs[0], pre_data).await
    }

    async fn resolve_address(&self, dest: &Address) -> std::io::Result<Vec<std::net::SocketAddr>> {
        match dest {
            Address::Inet(addr) => Ok(vec![*addr]),
            Address::Domain(domain, port) => match self.dns.resolve(domain).await {
                Ok(ips) => {
                    let addrs: Vec<std::net::SocketAddr> =
                        ips.iter().map(|ip| std::net::SocketAddr::new(*ip, *port)).collect();
                    Ok(addrs)
                }
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("DNS resolution failed: {}", e),
                )),
            },
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "WebSocket only supports Inet and Domain addresses",
            )),
        }
    }

    fn build_client_request(&self, uri: &str, pre_data: Option<&Bytes>) -> std::io::Result<http::Request<()>> {
        let mut request = uri
            .into_client_request()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        if let Some(data) = pre_data {
            let encoded = general_purpose::STANDARD_NO_PAD.encode(data);
            let header_value = HeaderValue::from_str(&encoded)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            request.headers_mut().insert(SEC_WEBSOCKET_PROTOCOL, header_value);
        }

        Ok(request)
    }

    async fn connect_tcp(&self, addr: &std::net::SocketAddr, pre_data: Option<Bytes>) -> std::io::Result<TrStream> {
        log::debug!("Establishing WebSocket connection to {}", addr);

        let tcp_stream = TcpStream::connect(addr).await?;
        let tcp_stream = self.opt.apply_tcpstream(tcp_stream)?;

        if let Some(ref tls) = self.tls_client {
            let tls_stream = tls.connect(addr, tcp_stream).await?;
            log::debug!("TLS handshake successful with {}", addr);

            let uri = format!("wss://{}:{}{}", addr.ip(), addr.port(), self.settings.path);
            let request = self.build_client_request(&uri, pre_data.as_ref())?;

            let (ws_stream, _response) = tokio_tungstenite::client_async(request, tls_stream)
                .await
                .map_err(|e| {
                    warn!("WebSocket handshake failed for {}: {}", addr, e);
                    std::io::Error::other(e)
                })?;

            log::debug!("WebSocket TLS connection established to {}", addr);
            Ok(TrStream::WebSocketTls(Box::new(WebSocketIo::new(ws_stream))))
        } else {
            let uri = format!("ws://{}:{}{}", addr.ip(), addr.port(), self.settings.path);
            let request = self.build_client_request(&uri, pre_data.as_ref())?;

            let (ws_stream, _response) = tokio_tungstenite::client_async(request, tcp_stream)
                .await
                .map_err(|e| {
                    warn!("WebSocket handshake failed for {}: {}", addr, e);
                    std::io::Error::other(e)
                })?;

            log::debug!("WebSocket plain connection established to {}", addr);
            Ok(TrStream::WebSocketPlain(Box::new(WebSocketIo::new(ws_stream))))
        }
    }

    pub async fn listen(
        &self,
        addr: &crate::common::Address,
    ) -> std::io::Result<crate::common::BoxStream<(TrStream, crate::common::Address), std::io::Error>> {
        match addr {
            Address::Inet(addr) => self.listen_tcp(addr).await,
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "WebSocket listen only supports Inet addresses",
            )),
        }
    }

    async fn listen_tcp(
        &self,
        addr: &std::net::SocketAddr,
    ) -> std::io::Result<crate::common::BoxStream<(TrStream, Address), std::io::Error>> {
        log::debug!("Starting WebSocket listener on {}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        log::debug!("WebSocket listener bound successfully to {}", addr);

        let opt = self.opt.clone();
        let tls_server = self.tls_server.clone();

        let stream = async_stream::stream! {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        debug!("Accepted TCP connection from {}", peer_addr);

                        // 应用 socket 选项
                        let stream = match opt.apply_tcpstream(stream) {
                            Ok(s) => {
                                debug!("Socket options applied for {}", peer_addr);
                                s
                            }
                            Err(e) => {
                                warn!("Failed to apply socket options for {}: {}", peer_addr, e);
                                yield Err(e);
                                continue;
                            }
                        };

                        // 处理 TLS 握手
                        if let Some(ref tls) = tls_server {
                            debug!("Performing TLS handshake for {}", peer_addr);
                            match tls.accept(stream).await {
                                Ok(tls_stream) => {
                                    debug!("TLS handshake successful for {}", peer_addr);
                                    // TLS 连接，使用 WebSocketTlsServer
                                    match perform_websocket_handshake(tls_stream).await {
                                        Ok(ws_stream) => {
                                            yield Ok((ws_stream, Address::Inet(peer_addr)));
                                        }
                                        Err(e) => {
                                            warn!("WebSocket handshake failed for {}: {}", peer_addr, e);
                                            yield Err(e);
                                            continue;
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("TLS handshake failed for {}: {}", peer_addr, e);
                                    yield Err(e);
                                    continue;
                                }
                            }
                        } else {
                            // 普通连接，使用 WebSocketPlain
                            match perform_websocket_handshake(stream).await {
                                Ok(ws_stream) => {
                                    debug!("WebSocket plain connection accepted from {}", peer_addr);
                                    yield Ok((ws_stream, Address::Inet(peer_addr)));
                                }
                                Err(e) => {
                                    warn!("WebSocket handshake failed for {}: {}", peer_addr, e);
                                    yield Err(e);
                                    continue;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to accept TCP connection: {}", e);
                        yield Err(e);
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

// 定义连接类型
pub enum WebSocketConnectionType {
    Plain,     // 普通 WebSocket (TcpStream)
    TlsServer, // 服务端 TLS WebSocket
    TlsClient, // 客户端 TLS WebSocket
}

async fn perform_websocket_handshake<S>(stream: S) -> std::io::Result<TrStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    tokio_tungstenite::WebSocketStream<S>: IntoTrStream,
{
    let early_data_cell = std::sync::Arc::new(parking_lot::Mutex::new(None));
    let early_data_cell_cloned = early_data_cell.clone();

    let ws_stream = tokio_tungstenite::accept_hdr_async(stream, move |req: &WsRequest, mut res: WsResponse| {
        if let Some(value) = req.headers().get(SEC_WEBSOCKET_PROTOCOL) {
            if let Ok(value_str) = value.to_str() {
                if let Ok(data) = general_purpose::STANDARD_NO_PAD.decode(value_str) {
                    *early_data_cell_cloned.lock() = Some(Bytes::from(data));
                }
            }

            res.headers_mut().insert(SEC_WEBSOCKET_PROTOCOL, value.clone());
            return Ok(res);
        }
        Ok(res)
    })
    .await
    .map_err(|e| std::io::Error::other(e))?;

    let early_data = early_data_cell.lock().take();
    Ok(ws_stream.into_tr_stream(early_data))
}

trait IntoTrStream {
    fn into_tr_stream(self, early_data: Option<Bytes>) -> TrStream;
}

impl IntoTrStream for tokio_tungstenite::WebSocketStream<TcpStream> {
    fn into_tr_stream(self, early_data: Option<Bytes>) -> TrStream {
        let ws_io = match early_data {
            Some(data) => WebSocketIo::new_with_read_buf(self, data),
            None => WebSocketIo::new(self),
        };
        TrStream::WebSocketPlain(Box::new(ws_io))
    }
}

impl IntoTrStream for tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>> {
    fn into_tr_stream(self, early_data: Option<Bytes>) -> TrStream {
        let ws_io = match early_data {
            Some(data) => WebSocketIo::new_with_read_buf(self, data),
            None => WebSocketIo::new(self),
        };
        TrStream::WebSocketTlsServer(Box::new(ws_io))
    }
}
