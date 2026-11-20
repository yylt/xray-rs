mod client;
mod packet;
use crate::common::{Address, BoxStream, Protocol};
use crate::route::DnsResolver;
use crate::transport::sockopt::SocketOpt;
use crate::transport::tls;

use bytes::Bytes;
use http::{header, Request, Response, StatusCode};
use hyper::body::{Body, Frame, Incoming};
use serde::{Deserialize, Serialize};
use std::future::Future;

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio_util::io::StreamReader;
use tokio_util::sync::PollSender;

use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use log::{debug, error};
use std::time::{Duration, Instant};

use super::*;

/// HTTP/2 stream-level flow-control window advertised by both roles. Downloads
/// dominate XHTTP traffic and the client's window is what bounds them, but the
/// server applies the same value to its upload streams for symmetry.
const DEFAULT_HTTP2_INITIAL_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
/// HTTP/2 connection-level window as a multiple of the stream-level window.
const HTTP2_INITIAL_CONNECTION_WINDOW_MULTIPLE: u32 = 2;
/// HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE is a 31-bit quantity.
const MAX_HTTP2_INITIAL_STREAM_WINDOW: u32 = (1 << 31) - 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XhttpSettings {
    #[serde(rename = "path")]
    pub path: String,

    #[serde(rename = "mode")]
    pub mode: Option<String>, // Only packet-up is supported; omitted defaults to it.

    #[serde(rename = "upload")]
    pub upload: Option<ServerConfig>,

    #[serde(rename = "download")]
    pub download: Option<ServerConfig>,

    #[serde(rename = "http2InitialWindowSize")]
    pub http2_initial_window_size: Option<u32>,

    #[serde(rename = "loadBalancer")]
    pub load_balancer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    // An omitted address is resolved once in Xhttp::new.
    #[serde(default, deserialize_with = "deserialize_endpoint_address")]
    pub address: String,

    #[serde(rename = "port")]
    pub port: u16,
}

fn deserialize_endpoint_address<'de, D: serde::Deserializer<'de>>(deserializer: D) -> StdResult<String, D::Error> {
    let address = String::deserialize(deserializer)?;
    if address.trim().is_empty() {
        return Err(serde::de::Error::custom("XHTTP endpoint address must not be empty"));
    }
    Ok(address)
}

// ---------------------------------------------------------------------------
// Body implementation for streaming
// ---------------------------------------------------------------------------

pub struct ChannelBody {
    rx: mpsc::Receiver<StdResult<Frame<Bytes>, Infallible>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<StdResult<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

// ---------------------------------------------------------------------------
// Xhttp Transport
// ---------------------------------------------------------------------------

pub struct Xhttp {
    settings: XhttpSettings,
    opt: SocketOpt,
    tls_client: Option<tls::client::Tls>,
    tls_server: Option<tls::server::Tls>,
    dns: std::sync::Arc<DnsResolver>,
    h2_window: u32,

    upload_pool: ClientPool,
    download_pool: ClientPool,
    packet_sessions: packet::PacketSessions,
}

type DownloadResponse = Pin<Box<dyn Future<Output = IoResult<client::ClientBody>> + Send + Sync>>;

type ClientBalancer = super::balancer::Balancer<Arc<client::ClientTarget>>;

struct ClientPool {
    balancer: ClientBalancer,
    discovery: Mutex<DiscoveryState>,
}

#[derive(Default)]
struct DiscoveryState {
    initialized: bool,
    refresh_at: Option<Instant>,
    retry_at: Option<Instant>,
    generation: u64,
}

impl ClientPool {
    fn new(strategy: super::balancer::Strategy) -> Self {
        Self {
            balancer: ClientBalancer::new(strategy),
            discovery: Mutex::new(DiscoveryState::default()),
        }
    }

    async fn discover<F, Fut>(&self, config: &ServerConfig, resolve: F) -> IoResult<u64>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = IoResult<Vec<std::net::IpAddr>>>,
    {
        let mut state = self.discovery.lock().await;
        let now = Instant::now();
        if state.retry_at.is_some_and(|at| now < at) {
            return if state.initialized {
                Ok(state.generation)
            } else {
                Err(Error::new(ErrorKind::NotConnected, "XHTTP DNS discovery backing off"))
            };
        }
        if state.initialized && state.refresh_at.is_none_or(|at| now < at) {
            return Ok(state.generation);
        }
        let ips = match config.address.parse::<std::net::IpAddr>() {
            Ok(ip) => Ok(vec![ip]),
            Err(_) => match tokio::time::timeout(Duration::from_secs(10), resolve()).await {
                Ok(result) => result,
                Err(_) => Err(Error::new(ErrorKind::TimedOut, "XHTTP DNS resolution timed out")),
            },
        };
        state.retry_at = Some(Instant::now() + Duration::from_secs(1));
        match ips {
            Ok(ips) if !ips.is_empty() => {
                self.balancer
                    .sync_targets(
                        ips.into_iter()
                            .map(|ip| super::balancer::GrpcTargetKey::Tcp(std::net::SocketAddr::new(ip, config.port)))
                            .collect(),
                    )
                    .await;
                state.initialized = true;
                state.generation = state.generation.wrapping_add(1);
                state.refresh_at = config
                    .address
                    .parse::<std::net::IpAddr>()
                    .is_err()
                    .then(|| Instant::now() + Duration::from_secs(300));
                Ok(state.generation)
            }
            result => {
                if state.initialized {
                    return Ok(state.generation);
                }
                Err(result
                    .err()
                    .unwrap_or_else(|| Error::new(ErrorKind::NotFound, "XHTTP DNS returned no IPs")))
            }
        }
    }

    async fn invalidate(&self, generation: u64) {
        let mut state = self.discovery.lock().await;
        if state.generation == generation {
            state.refresh_at = Some(Instant::now());
        }
    }
}

impl Xhttp {
    fn empty_body() -> ChannelBody {
        ChannelBody { rx: mpsc::channel(1).1 }
    }

    fn stream_response(status: StatusCode, body: ChannelBody) -> Response<ChannelBody> {
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CACHE_CONTROL, "no-cache, no-store")
            .header("X-Accel-Buffering", "no")
            // Disable buffering for nginx/other proxies
            .header("X-Cache-Status", "BYPASS")
            .body(body)
            .unwrap()
    }

    pub fn new(sset: &StreamSettings, server: Option<Address>, dns: Arc<DnsResolver>) -> IoResult<Self> {
        let mut settings = sset
            .xhttp_settings
            .clone()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "xhttpSettings is required"))?;
        if settings.mode.as_deref().is_some_and(|mode| mode != "packet-up") {
            return Err(Error::new(ErrorKind::InvalidInput, "unsupported XHTTP mode"));
        }
        settings.path = format!("/{}", settings.path.trim_matches('/'));
        if settings.path == "/" {
            settings.path.clear();
        }
        let fallback = match server {
            Some(Address::Inet(addr)) => Some(ServerConfig {
                address: addr.ip().to_string(),
                port: addr.port(),
            }),
            Some(Address::Domain(address, port)) => Some(ServerConfig { address, port }),
            _ => None,
        };
        let (tls_client, tls_server) = if sset.security == Security::Tls {
            let ts = sset
                .tls_settings
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "XHTTP TLS requires tlsSettings"))?;
            (Some(tls::client::new_http2(ts)?), Some(tls::server::new(ts)?))
        } else {
            (None, None)
        };
        let tls_name = tls_client.as_ref().and_then(|tls| tls.server_name());
        if tls_name.is_some_and(|name| name.trim().is_empty()) {
            return Err(Error::new(ErrorKind::InvalidInput, "XHTTP TLS serverName must not be empty"));
        }
        let resolve = |endpoint: &mut ServerConfig, inherited: Option<&ServerConfig>| -> IoResult<()> {
            if endpoint.address.is_empty() {
                endpoint.address = tls_name
                    .or_else(|| fallback.as_ref().map(|config| config.address.as_str()))
                    .or_else(|| inherited.map(|config| config.address.as_str()))
                    .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "XHTTP endpoint address missing"))?
                    .to_owned();
            } else if endpoint.address.trim().is_empty() {
                return Err(Error::new(ErrorKind::InvalidInput, "XHTTP endpoint address must not be empty"));
            }
            Ok(())
        };
        settings.upload = settings.upload.or_else(|| {
            fallback.as_ref().map(|config| ServerConfig {
                address: String::new(),
                port: config.port,
            })
        });
        if let Some(upload) = &mut settings.upload {
            resolve(upload, None)?;
        }
        if let Some(download) = &mut settings.download {
            resolve(download, settings.upload.as_ref())?;
        } else {
            settings.download = settings.upload.clone();
        }
        let strategy = super::balancer::Strategy::from_strategy_str(
            settings.load_balancer.as_deref().unwrap_or("least_connection"),
        );
        let h2_window = settings
            .http2_initial_window_size
            .unwrap_or(DEFAULT_HTTP2_INITIAL_STREAM_WINDOW);
        // Zero would stall every stream; the protocol maximum is 2^31-1.
        if h2_window == 0 || h2_window > MAX_HTTP2_INITIAL_STREAM_WINDOW {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "XHTTP http2InitialWindowSize must be between 1 and 2147483647",
            ));
        }
        Ok(Self {
            settings,
            opt: sset.sockopt.clone(),
            tls_client,
            tls_server,
            dns,
            h2_window,
            upload_pool: ClientPool::new(strategy),
            download_pool: ClientPool::new(strategy),
            packet_sessions: Arc::default(),
        })
    }

    pub fn dns(&self) -> &std::sync::Arc<DnsResolver> {
        &self.dns
    }

    async fn get_client(
        &self,
        pool: &ClientPool,
        key: &super::balancer::GrpcTargetKey,
        config: &ServerConfig,
    ) -> IoResult<Arc<client::ClientTarget>> {
        if let Some(target) = pool.balancer.cached_channel(key).await {
            if !target.is_closed() {
                return Ok(target);
            }
        }
        let lock = pool
            .balancer
            .channel_lock(key)
            .await
            .ok_or_else(|| Error::new(ErrorKind::NotConnected, "XHTTP target removed"))?;
        let _guard = lock.lock().await;
        if let Some(target) = pool.balancer.cached_channel(key).await {
            if !target.is_closed() {
                return Ok(target);
            }
        }
        let addr = match key {
            super::balancer::GrpcTargetKey::Tcp(addr) => *addr,
            #[cfg(unix)]
            super::balancer::GrpcTargetKey::Unix(_) => {
                return Err(Error::new(ErrorKind::Unsupported, "XHTTP client requires TCP"));
            }
        };
        let target = Arc::new(client::ClientTarget::new(
            addr,
            config.address.clone(),
            self.opt.clone(),
            self.tls_client.clone(),
            self.h2_window,
        ));
        pool.balancer
            .cache_channel(key, target)
            .await
            .ok_or_else(|| Error::new(ErrorKind::NotConnected, "XHTTP target removed"))
    }

    pub async fn connect(&self, _dest: &Address, _proto: Protocol) -> IoResult<super::TrStream> {
        let config = self
            .settings
            .upload
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "XHTTP upload endpoint missing"))?;
        let pool = &self.upload_pool;
        let generation = pool.discover(config, || self.dns.resolve(&config.address)).await?;
        let opened = pool
            .balancer
            .open_with_retry(|key| async move {
                tokio::time::timeout(Duration::from_secs(10), self.connect_inner(&key))
                    .await
                    .map_err(|_| Error::new(ErrorKind::TimedOut, "XHTTP stream establishment timed out"))?
            })
            .await;
        match opened {
            Ok((lease, mut stream)) => {
                stream.target_leases.push(lease);
                Ok(super::TrStream::Xhttp(Box::new(stream)))
            }
            Err(err) => {
                pool.invalidate(generation).await;
                Err(err)
            }
        }
    }

    fn request_uri(&self, config: Option<&ServerConfig>, path: &str) -> IoResult<http::Uri> {
        let config = config.ok_or_else(|| Error::new(ErrorKind::InvalidInput, "missing XHTTP endpoint"))?;
        // Use the same resolved endpoint name for DNS, TLS and virtual-host routing.
        let host = &config.address;
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{}]", host)
        } else {
            host.to_string()
        };
        http::Uri::builder()
            .scheme(if self.tls_client.is_some() { "https" } else { "http" })
            .authority(format!("{}:{}", host, config.port))
            .path_and_query(path)
            .build()
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e))
    }

    async fn connect_inner(&self, key: &super::balancer::GrpcTargetKey) -> IoResult<XhttpStream> {
        let uuid = uuid::Uuid::new_v4().to_string();
        let path = format!("{}/{}", self.settings.path, uuid);
        let config = self.settings.upload.as_ref().unwrap();
        let sender = self.get_client(&self.upload_pool, key, config).await?;
        sender.connect().await?;
        let mut leases = Vec::new();
        let incoming = if self.settings.upload == self.settings.download {
            self.establish_get(&path, &self.upload_pool, key).await?
        } else {
            let config = self.settings.download.as_ref().unwrap();
            let pool = &self.download_pool;
            let generation = pool.discover(config, || self.dns.resolve(&config.address)).await?;
            match pool
                .balancer
                .open_with_retry(|key| {
                    let path = &path;
                    async move { self.establish_get(path, pool, &key).await }
                })
                .await
            {
                Ok((lease, body)) => {
                    leases.push(lease);
                    body
                }
                Err(error) => {
                    pool.invalidate(generation).await;
                    return Err(error);
                }
            }
        };
        let mut stream =
            packet::connect(sender, incoming, self.request_uri(self.settings.upload.as_ref(), &path)?).await?;
        stream.target_leases = leases;
        Ok(stream)
    }

    async fn establish_get(
        &self,
        path: &str,
        pool: &ClientPool,
        key: &super::balancer::GrpcTargetKey,
    ) -> IoResult<DownloadResponse> {
        let config = self.settings.download.as_ref().unwrap();
        let get_client = self.get_client(pool, key, config).await?;
        let download_address = self
            .settings
            .download
            .as_ref()
            .map(|d| d.address.as_str())
            .unwrap_or("");

        debug!("[xhttp][client] issuing GET path={} host={}", path, download_address);
        let get_req = Request::builder()
            .method("GET")
            .uri(self.request_uri(self.settings.download.as_ref(), path)?)
            .header("User-Agent", "xray-rs/v0.1.0")
            .body(Bytes::new())
            .unwrap();

        let response = get_client.send(get_req).await?;
        Ok(Box::pin(async move {
            let response = tokio::time::timeout(Duration::from_secs(10), response)
                .await
                .map_err(|_| Error::new(ErrorKind::TimedOut, "XHTTP GET response headers timed out"))?
                .map_err(Error::other)?;
            if response.status() != StatusCode::OK {
                return Err(Error::new(
                    ErrorKind::ConnectionRefused,
                    format!("Download failed with status: {}", response.status()),
                ));
            }
            Ok(response.into_body())
        }))
    }

    fn listener_stream(
        mut stream_rx: mpsc::Receiver<(super::TrStream, Address)>,
    ) -> BoxStream<(super::TrStream, Address), std::io::Error> {
        let stream = async_stream::stream! {
            while let Some(item) = stream_rx.recv().await {
                yield Ok(item);
            }
        };

        Box::pin(stream)
    }

    pub async fn listen(&self, addr: &Address) -> IoResult<BoxStream<(super::TrStream, Address), std::io::Error>> {
        match addr {
            Address::Inet(addr) => self.listen_tcp(addr).await,
            #[cfg(unix)]
            Address::Unix(path) => self.listen_unix(path).await,
            #[cfg(not(unix))]
            Address::Unix(_) => Err(Error::new(
                ErrorKind::Unsupported,
                "Unix sockets not supported on this platform",
            )),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "xhttp listen only supports Inet and Unix addresses",
            )),
        }
    }

    async fn listen_tcp(
        &self,
        addr: &std::net::SocketAddr,
    ) -> IoResult<BoxStream<(super::TrStream, Address), std::io::Error>> {
        let (stream_tx, stream_rx) = mpsc::channel(DEFAULT_CHANNEL_SERVER_CAPACITY);
        let listener = super::bind_tcp_listener(*addr)?;
        let packet_sessions = self.packet_sessions.clone();
        let stx = stream_tx.clone();
        let base_path = self.settings.path.clone();
        let h2_window = self.h2_window;
        let sockopt = self.opt.clone();
        let tls_server = self.tls_server.clone();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, peer_addr)) = listener.accept().await {
                    let stream = match sockopt.apply_tcpstream(stream) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Failed to apply sockopt for {}: {}", peer_addr, e);
                            continue;
                        }
                    };

                    let packet_sessions = packet_sessions.clone();
                    let stx_clone = stx.clone();
                    let base_path_clone = base_path.clone();
                    let tls_server = tls_server.clone();

                    tokio::spawn(async move {
                        if let Some(tls) = &tls_server {
                            match tls.clone().accept(stream).await {
                                Ok(tls_stream) => {
                                    let io = TokioIo::new(tls_stream);
                                    Self::serve_connection(
                                        io,
                                        packet_sessions,
                                        stx_clone,
                                        base_path_clone,
                                        h2_window,
                                        Address::Inet(peer_addr),
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    error!("TLS accept error from {}: {}", peer_addr, e);
                                }
                            }
                        } else {
                            let io = TokioIo::new(stream);
                            Self::serve_connection(
                                io,
                                packet_sessions,
                                stx_clone,
                                base_path_clone,
                                h2_window,
                                Address::Inet(peer_addr),
                            )
                            .await;
                        }
                    });
                }
            }
        });

        Ok(Self::listener_stream(stream_rx))
    }

    #[cfg(unix)]
    async fn listen_unix(
        &self,
        path: &std::path::Path,
    ) -> IoResult<BoxStream<(super::TrStream, Address), std::io::Error>> {
        if self.tls_server.is_some() {
            return Err(Error::new(ErrorKind::InvalidInput, "xhttp Unix listen does not support TLS"));
        }
        let (listener, path) = super::bind_unix_listener(path)?;
        let (stream_tx, stream_rx) = mpsc::channel(DEFAULT_CHANNEL_SERVER_CAPACITY);
        let packet_sessions = self.packet_sessions.clone();
        let stx = stream_tx.clone();
        let base_path = self.settings.path.clone();
        let h2_window = self.h2_window;
        let sockopt = self.opt.clone();
        let listener_path = path.clone();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let stream = match sockopt.apply_unixstream(stream) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Failed to apply sockopt for {:?}: {}", listener_path, e);
                            continue;
                        }
                    };

                    let packet_sessions = packet_sessions.clone();
                    let stx_clone = stx.clone();
                    let base_path_clone = base_path.clone();
                    let peer_addr = Address::Unix(listener_path.clone());

                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        Self::serve_connection(io, packet_sessions, stx_clone, base_path_clone, h2_window, peer_addr)
                            .await;
                    });
                }
            }
        });

        Ok(Self::listener_stream(stream_rx))
    }

    async fn serve_connection<I>(
        conn_io: TokioIo<I>,
        packet_sessions: packet::PacketSessions,
        stx: mpsc::Sender<(super::TrStream, Address)>,
        base_path: String,
        h2_window: u32,
        peer_addr: Address,
    ) where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connection_peer = peer_addr.clone();
        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
            let packet_sessions = packet_sessions.clone();
            let stx = stx.clone();
            let base_path = base_path.clone();
            let peer_addr = peer_addr.clone();

            async move {
                if !matches!(req.version(), http::Version::HTTP_11 | http::Version::HTTP_2) {
                    return Ok::<_, Infallible>(Self::stream_response(
                        StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                        Self::empty_body(),
                    ));
                }
                let path = req.uri().path().to_string();

                // Validate base path
                if !path.starts_with(&format!("{}/", base_path)) || path.len() <= base_path.len() + 1 {
                    return Ok::<_, Infallible>(Self::stream_response(StatusCode::NOT_FOUND, Self::empty_body()));
                }
                let id = path[base_path.len() + 1..].to_string();
                Ok::<_, Infallible>(packet::handle(req, packet_sessions, stx, peer_addr, &id).await)
            }
        });

        // Support both HTTP/1.1 (behind nginx) and HTTP/2
        // Note: HTTP/1.1 processes requests sequentially per connection
        let mut builder = AutoBuilder::new(TokioExecutor::new());
        builder
            .http2()
            .initial_stream_window_size(h2_window)
            .initial_connection_window_size(h2_window.saturating_mul(HTTP2_INITIAL_CONNECTION_WINDOW_MULTIPLE));
        if let Err(err) = builder.serve_connection(conn_io, service).await {
            error!("[xhttp][server] connection error peer={:?}: {:?}", connection_peer, err);
        }
    }
}

// ---------------------------------------------------------------------------
// XhttpStream: AsyncRead + AsyncWrite
// ---------------------------------------------------------------------------

pub struct XhttpStream {
    packet: packet::PacketStream,
    target_leases: Vec<super::balancer::TargetLease>,
}

impl XhttpStream {
    fn new_packet(packet: packet::PacketStream) -> Self {
        Self {
            packet,
            target_leases: Vec::new(),
        }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.packet).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        Pin::new(&mut self.packet).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.packet).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut self.packet).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "xhttp/capacity_tests.rs"]
mod capacity_tests;

#[cfg(test)]
#[path = "xhttp/tests.rs"]
mod regression_tests;

#[cfg(test)]
#[path = "xhttp/packet_tests.rs"]
mod packet_tests;

#[cfg(test)]
#[path = "xhttp/endpoint_tests.rs"]
mod endpoint_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http2_window_defaults_to_four_mib_and_rejects_out_of_range() {
        let build = |window: serde_json::Value| {
            let mut value = serde_json::json!({
                "network": "xhttp", "xhttpSettings": {"path": "/test"}
            });
            if !window.is_null() {
                value["xhttpSettings"]["http2InitialWindowSize"] = window;
            }
            let settings: StreamSettings = serde_json::from_value(value).unwrap();
            Xhttp::new(&settings, None, Arc::new(DnsResolver))
        };
        assert_eq!(build(serde_json::Value::Null).unwrap().h2_window, 4 * 1024 * 1024);
        assert_eq!(build(serde_json::json!(1_048_576)).unwrap().h2_window, 1_048_576);
        for invalid in [serde_json::json!(0), serde_json::json!(2_147_483_648u64)] {
            let error = build(invalid).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{error}");
        }
    }

    #[test]
    fn outbound_defaults_and_tls_errors() {
        let mut value = serde_json::json!({
            "network": "xhttp", "xhttpSettings": {"path": "/test", "mode": "packet-up"}
        });
        let server = Address::Domain("example.com".to_string(), 443);
        let settings: StreamSettings = serde_json::from_value(value.clone()).unwrap();
        let transport = Xhttp::new(&settings, Some(server.clone()), Arc::new(DnsResolver)).unwrap();
        assert_eq!(transport.settings.upload.as_ref().unwrap().address, "example.com");
        assert_eq!(transport.settings.upload, transport.settings.download);
        value["security"] = serde_json::json!("tls");
        for tls in [
            serde_json::Value::Null,
            serde_json::json!({"alpn": ["http/1.1"]}),
            serde_json::json!({"cipherSuites": ["invalid"]}),
        ] {
            value["tlsSettings"] = tls;
            let settings = serde_json::from_value(value.clone()).unwrap();
            assert!(Xhttp::new(&settings, Some(server.clone()), Arc::new(DnsResolver)).is_err());
        }
    }

    #[test]
    fn request_uri_preserves_scheme_virtual_host_port_and_ipv6() {
        for (security, tls_settings, address, expected) in [
            ("none", serde_json::Value::Null, "127.0.0.1", "http://127.0.0.1:8443/test/id"),
            ("none", serde_json::Value::Null, "::1", "http://[::1]:8443/test/id"),
            (
                "tls",
                serde_json::json!({"serverName": "example.com", "alpn": ["h2"]}),
                "127.0.0.1",
                "https://127.0.0.1:8443/test/id",
            ),
        ] {
            let settings: StreamSettings = serde_json::from_value(serde_json::json!({
                "network": "xhttp", "security": security, "tlsSettings": tls_settings,
                "xhttpSettings": {"path": "/test", "upload": {"address": address, "port": 8443}}
            }))
            .unwrap();
            let transport = Xhttp::new(&settings, None, Arc::new(DnsResolver)).unwrap();
            if security == "tls" {
                assert!(transport.tls_client.is_some());
            }
            assert_eq!(
                transport
                    .request_uri(transport.settings.upload.as_ref(), "/test/id")
                    .unwrap()
                    .to_string(),
                expected
            );
            assert!(transport.request_uri(None, "/test/id").is_err());
            assert!(transport
                .request_uri(transport.settings.upload.as_ref(), "bad path")
                .is_err());
        }
    }
}
