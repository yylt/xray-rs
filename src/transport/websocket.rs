use super::*;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::net::TcpStream;

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

    #[serde(rename = "headers", default)]
    headers: Map<String, Value>,

    #[serde(rename = "maxEarlyData")]
    max_early_data: Option<i32>,
}

fn default_path() -> String {
    "/ws".to_string()
}

impl Default for WsSettings {
    fn default() -> Self {
        Self {
            path: default_path(),
            headers: Map::new(),
            max_early_data: None,
        }
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

    pub async fn connect(&self, addr: &crate::common::Address) -> std::io::Result<TrStream> {
        log::debug!("WebSocket client connecting to {:?}", addr);

        // Resolve address
        let socket_addrs = self.resolve_address(addr).await?;

        if socket_addrs.is_empty() {
            warn!("No addresses resolved for {:?}", addr);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "No addresses resolved"));
        }

        // Simple strategy: try first address
        // (WebSocket typically doesn't need complex load balancing)
        self.connect_tcp(&socket_addrs[0]).await
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

    async fn connect_tcp(&self, addr: &std::net::SocketAddr) -> std::io::Result<TrStream> {
        log::debug!("Establishing WebSocket connection to {}", addr);

        // Establish TCP connection
        let tcp_stream = TcpStream::connect(addr).await?;
        let tcp_stream = self.opt.apply_tcpstream(tcp_stream)?;

        // Perform TLS handshake if configured
        if let Some(ref tls) = self.tls_client {
            let tls_stream = tls.connect(addr, tcp_stream).await?;
            log::debug!("TLS handshake successful with {}", addr);

            // Build WebSocket request with custom headers
            let uri = format!("wss://{}:{}{}", addr.ip(), addr.port(), self.settings.path);
            let mut request = http::Request::builder()
                .uri(&uri)
                .header("Host", format!("{}:{}", addr.ip(), addr.port()))
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13");

            // Add custom headers
            for (key, value) in &self.settings.headers {
                if let Some(value_str) = value.as_str() {
                    request = request.header(key.as_str(), value_str);
                }
            }

            let request = request
                .body(())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

            let (ws_stream, _response) = tokio_tungstenite::client_async(request, tls_stream)
                .await
                .map_err(|e| {
                    warn!("WebSocket handshake failed for {}: {}", addr, e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })?;

            log::debug!("WebSocket TLS connection established to {}", addr);
            Ok(TrStream::WebSocketTls(Box::new(WebSocketIo::new(ws_stream))))
        } else {
            // Build WebSocket request with custom headers
            let uri = format!("ws://{}:{}{}", addr.ip(), addr.port(), self.settings.path);
            let mut request = http::Request::builder()
                .uri(&uri)
                .header("Host", format!("{}:{}", addr.ip(), addr.port()))
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13");

            // Add custom headers
            for (key, value) in &self.settings.headers {
                if let Some(value_str) = value.as_str() {
                    request = request.header(key.as_str(), value_str);
                }
            }

            let request = request
                .body(())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

            let (ws_stream, _response) = tokio_tungstenite::client_async(request, tcp_stream)
                .await
                .map_err(|e| {
                    warn!("WebSocket handshake failed for {}: {}", addr, e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
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

                        // Handle TLS if configured
                        let result = if let Some(ref tls) = tls_server {
                            debug!("Performing TLS handshake for {}", peer_addr);
                            match tls.accept(stream).await {
                                Ok(tls_stream) => {
                                    debug!("TLS handshake successful for {}", peer_addr);
                                    match tokio_tungstenite::accept_async(tls_stream).await {
                                        Ok(ws_stream) => {
                                            log::debug!("WebSocket TLS connection accepted from {}", peer_addr);
                                            Ok(TrStream::WebSocketTlsServer(Box::new(WebSocketIo::new(ws_stream))))
                                        }
                                        Err(e) => {
                                            warn!("WebSocket handshake failed for {}: {}", peer_addr, e);
                                            Err(std::io::Error::new(std::io::ErrorKind::Other, e))
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("TLS handshake failed for {}: {}", peer_addr, e);
                                    Err(e)
                                }
                            }
                        } else {
                            debug!("Accepting plain WebSocket connection from {}", peer_addr);
                            match tokio_tungstenite::accept_async(stream).await {
                                Ok(ws_stream) => {
                                    log::debug!("WebSocket plain connection accepted from {}", peer_addr);
                                    Ok(TrStream::WebSocketPlain(Box::new(WebSocketIo::new(ws_stream))))
                                }
                                Err(e) => {
                                    warn!("WebSocket handshake failed for {}: {}", peer_addr, e);
                                    Err(std::io::Error::new(std::io::ErrorKind::Other, e))
                                }
                            }
                        };

                        match result {
                            Ok(ws_stream) => {
                                yield Ok((ws_stream, Address::Inet(peer_addr)));
                            }
                            Err(e) => {
                                yield Err(e);
                                continue;
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
