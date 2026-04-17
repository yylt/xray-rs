use crate::common::{Address, BoxStream, Protocol};
use crate::route::DnsResolver;
use crate::transport::sockopt::SocketOpt;
use crate::transport::tls;

use bytes::Bytes;
use http::{header, Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::body::{Body, Frame, Incoming};
use pin_project_lite::pin_project;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_util::io::StreamReader;
use tokio_util::sync::PollSender;

use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use log::{error, trace, warn};
use std::time::{Duration, Instant};

use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XhttpSettings {
    #[serde(rename = "path")]
    pub path: String,

    #[serde(rename = "mode")]
    pub mode: Option<String>, // "stream-one" for single POST channel, None for dual-channel

    #[serde(rename = "upload")]
    pub upload: Option<ServerConfig>,

    #[serde(rename = "download")]
    pub download: Option<ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(rename = "address")]
    pub address: String,

    #[serde(rename = "port")]
    pub port: u16,
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
// Server pairing state
// ---------------------------------------------------------------------------

pub enum PendingStream {
    // POST arrived first, waiting for GET to complete the pair
    UploadPending {
        incoming: Incoming, // read client upload data from POST body
        post_response_tx: mpsc::Sender<StdResult<Frame<Bytes>, Infallible>>, // write to POST response
        timestamp: Instant,
    },
    // GET arrived first, waiting for POST to complete the pair
    DownloadPending {
        get_response_tx: mpsc::Sender<StdResult<Frame<Bytes>, Infallible>>, // write to GET response
        timestamp: Instant,
    },
}

const PENDING_STREAM_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Xhttp Transport
// ---------------------------------------------------------------------------

pub struct Xhttp {
    settings: XhttpSettings,
    opt: SocketOpt,
    tls_client: Option<tls::client::Tls>,
    tls_server: Option<tls::server::Tls>,
    dns: std::sync::Arc<DnsResolver>,

    // Client connection cache using RwLock for fast read access
    upload_client: Arc<RwLock<Option<SendRequest<ChannelBody>>>>,
    download_client: Arc<RwLock<Option<SendRequest<Empty<Bytes>>>>>,

    // Server stream matching
    pending_streams: Arc<Mutex<HashMap<String, PendingStream>>>,
}

impl Xhttp {
    fn empty_body() -> ChannelBody {
        ChannelBody { rx: mpsc::channel(1).1 }
    }

    fn stream_response(status: StatusCode, body: ChannelBody) -> Response<ChannelBody> {
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CACHE_CONTROL, "no-store")
            .header("X-Accel-Buffering", "no")
            // Disable buffering for nginx/other proxies
            .header("X-Cache-Status", "BYPASS")
            .body(body)
            .unwrap()
    }

    fn cleanup_expired_pending_streams(map: &mut HashMap<String, PendingStream>) {
        let now = Instant::now();
        map.retain(|id, pending| {
            let timestamp = match pending {
                PendingStream::UploadPending { timestamp, .. } => *timestamp,
                PendingStream::DownloadPending { timestamp, .. } => *timestamp,
            };
            let expired = now.duration_since(timestamp) > PENDING_STREAM_TIMEOUT;
            if expired {
                warn!("[xhttp][server] dropping expired pending stream id={}", id);
            }
            !expired
        });
    }

    pub fn new(sset: &StreamSettings, _server: Option<Address>, dns: std::sync::Arc<DnsResolver>) -> IoResult<Self> {
        let xhttp_settings = sset
            .xhttp_settings
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "xhttpSettings is required"))?;

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
            settings: xhttp_settings.clone(),
            opt: sset.sockopt.clone(),
            tls_client,
            tls_server,
            dns,
            upload_client: Arc::new(RwLock::new(None)),
            download_client: Arc::new(RwLock::new(None)),
            pending_streams: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn dns(&self) -> &std::sync::Arc<DnsResolver> {
        &self.dns
    }

    // Resolve server config and establish TCP connection (shared helper)
    async fn resolve_and_connect(
        &self,
        config: Option<&ServerConfig>,
        name: &str,
    ) -> IoResult<(TcpStream, std::net::SocketAddr)> {
        let cfg = config.ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput, format!("{} config is not set in XhttpSettings", name))
        })?;

        let ips = self.dns.resolve(&cfg.address).await.map_err(|e| {
            Error::new(ErrorKind::NotFound, format!("DNS resolution failed for {}: {}", cfg.address, e))
        })?;

        if ips.is_empty() {
            return Err(Error::new(ErrorKind::NotFound, format!("No IP found for {}", cfg.address)));
        }

        let socket_addr = std::net::SocketAddr::new(ips[0], cfg.port);
        let stream = TcpStream::connect(&socket_addr).await?;
        let stream = self.opt.apply_tcpstream(stream)?;
        Ok((stream, socket_addr))
    }

    // Perform HTTP/2 handshake and spawn connection task (shared helper)
    async fn http2_handshake<B>(
        &self,
        stream: TcpStream,
        socket_addr: std::net::SocketAddr,
        name: &str,
    ) -> IoResult<SendRequest<B>>
    where
        B: Body + Unpin + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let request_sender = if let Some(tls) = &self.tls_client {
            let tls_stream = tls.connect(&socket_addr, stream).await?;
            let (request_sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(tls_stream))
                .await
                .map_err(|e| Error::new(ErrorKind::ConnectionAborted, e.to_string()))?;

            let name = name.to_string();
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("Error in {} HTTP/2 TLS connection: {:?}", name, e);
                }
            });
            request_sender
        } else {
            let (request_sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(stream))
                .await
                .map_err(|e| Error::new(ErrorKind::ConnectionAborted, e.to_string()))?;

            let name = name.to_string();
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("Error in {} HTTP/2 connection: {:?}", name, e);
                }
            });
            request_sender
        };
        Ok(request_sender)
    }

    /// Get upload client (POST channel with streaming body)
    async fn get_upload_client(&self) -> IoResult<SendRequest<ChannelBody>> {
        // Check cache first
        let client_opt = self.upload_client.read().await;
        if let Some(client) = client_opt.as_ref() {
            if client.is_ready() {
                return Ok(client.clone());
            }
        }
        drop(client_opt);

        let mut write_lock = self.upload_client.write().await;
        if let Some(client) = write_lock.as_ref() {
            if client.is_ready() {
                return Ok(client.clone());
            }
        }

        let (stream, socket_addr) = self
            .resolve_and_connect(self.settings.upload.as_ref(), "upload")
            .await?;
        let request_sender: SendRequest<ChannelBody> = self.http2_handshake(stream, socket_addr, "upload").await?;
        *write_lock = Some(request_sender.clone());
        Ok(request_sender)
    }

    /// Get download client (GET channel with empty body)
    async fn get_download_client(&self) -> IoResult<SendRequest<Empty<Bytes>>> {
        // Check cache first
        let client_opt = self.download_client.read().await;
        if let Some(client) = client_opt.as_ref() {
            if client.is_ready() {
                return Ok(client.clone());
            }
        }
        drop(client_opt);

        let mut write_lock = self.download_client.write().await;
        if let Some(client) = write_lock.as_ref() {
            if client.is_ready() {
                return Ok(client.clone());
            }
        }

        let (stream, socket_addr) = self
            .resolve_and_connect(self.settings.download.as_ref(), "download")
            .await?;
        let request_sender: SendRequest<Empty<Bytes>> = self.http2_handshake(stream, socket_addr, "download").await?;
        *write_lock = Some(request_sender.clone());
        Ok(request_sender)
    }

    pub async fn connect(&self, _dest: &Address, _proto: Protocol) -> IoResult<super::TrStream> {
        let stream = self.connect_inner().await?;
        Ok(super::TrStream::Xhttp(Box::new(stream)))
    }

    async fn connect_inner(&self) -> IoResult<crate::transport::xhttp::XhttpStream> {
        // Generate a random UUID
        let uuid = uuid::Uuid::new_v4().to_string();
        let path = format!("{}/{}", self.settings.path, uuid);
        let mode: XhttpMode = self.settings.mode.clone().into();

        // --- Execute Upload (POST) - establish first and keep it alive ---
        let (post_tx, post_rx) = mpsc::channel(DEFAULT_CHANNEL_CLIENT_CAPACITY);
        let body = ChannelBody { rx: post_rx };

        let upload_address = self.settings.upload.as_ref().map(|u| u.address.as_str()).unwrap_or("");
        let mut post_client = self.get_upload_client().await?;
        warn!("[xhttp][client] issuing POST path={} host={}", path, upload_address);
        let post_req = Request::builder()
            .method("POST")
            .uri(&path)
            .header("Host", upload_address)
            .header("User-Agent", "xray-rs/v0.1.0")
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .unwrap();

        let post_response = post_client
            .send_request(post_req)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("POST request failed: {}", e)))?;

        warn!(
            "[xhttp][client] POST established path={} status={}",
            path,
            post_response.status()
        );

        if post_response.status() != StatusCode::OK {
            return Err(Error::new(
                ErrorKind::ConnectionRefused,
                format!("Upload failed with status: {}", post_response.status()),
            ));
        }

        let incoming = match mode {
            XhttpMode::StreamUp => self.establish_get(&path).await?,
            XhttpMode::StreamOne => post_response.into_body(),
        };

        // Assemble stream based on mode: incoming response body for read, POST request (post_tx) for write
        Ok(XhttpStream::new_with_mode(incoming, PollSender::new(post_tx), None, mode))
    }

    async fn establish_get(&self, path: &str) -> IoResult<Incoming> {
        let mut get_client = self.get_download_client().await?;
        let download_address = self
            .settings
            .download
            .as_ref()
            .map(|d| d.address.as_str())
            .unwrap_or("");

        warn!("[xhttp][client] issuing GET path={} host={}", path, download_address);
        let get_req = Request::builder()
            .method("GET")
            .uri(path)
            .header("Host", download_address)
            .header("User-Agent", "xray-rs/v0.1.0")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let get_response = get_client
            .send_request(get_req)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("GET request failed: {}", e)))?;

        warn!("[xhttp][client] GET established path={} status={}", path, get_response.status());

        if get_response.status() != StatusCode::OK {
            return Err(Error::new(
                ErrorKind::ConnectionRefused,
                format!("Download failed with status: {}", get_response.status()),
            ));
        }

        Ok(get_response.into_body())
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
        let listener = TcpListener::bind(addr).await?;
        let pending = self.pending_streams.clone();
        let stx = stream_tx.clone();
        let base_path = self.settings.path.clone();
        let mode: XhttpMode = self.settings.mode.clone().into();
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

                    let pending_clone = pending.clone();
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
                                        pending_clone,
                                        stx_clone,
                                        base_path_clone,
                                        mode,
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
                                pending_clone,
                                stx_clone,
                                base_path_clone,
                                mode,
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
        path: &std::path::PathBuf,
    ) -> IoResult<BoxStream<(super::TrStream, Address), std::io::Error>> {
        if self.tls_server.is_some() {
            return Err(Error::new(ErrorKind::InvalidInput, "xhttp Unix listen does not support TLS"));
        }
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        let (stream_tx, stream_rx) = mpsc::channel(DEFAULT_CHANNEL_SERVER_CAPACITY);
        let pending = self.pending_streams.clone();
        let stx = stream_tx.clone();
        let base_path = self.settings.path.clone();
        let mode: XhttpMode = self.settings.mode.clone().into();
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

                    let pending_clone = pending.clone();
                    let stx_clone = stx.clone();
                    let base_path_clone = base_path.clone();
                    let peer_addr = Address::Unix(listener_path.clone());

                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        Self::serve_connection(io, pending_clone, stx_clone, base_path_clone, mode, peer_addr).await;
                    });
                }
            }
        });

        Ok(Self::listener_stream(stream_rx))
    }

    async fn serve_connection<I>(
        conn_io: TokioIo<I>,
        pending: Arc<Mutex<HashMap<String, PendingStream>>>,
        stx: mpsc::Sender<(super::TrStream, Address)>,
        base_path: String,
        mode: XhttpMode,
        peer_addr: Address,
    ) where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
            let pending = pending.clone();
            let stx = stx.clone();
            let base_path = base_path.clone();
            let peer_addr = peer_addr.clone();

            async move {
                let path = req.uri().path().to_string();

                // Validate base path
                if !path.starts_with(&base_path) || path.len() <= base_path.len() + 1 {
                    return Ok::<_, Infallible>(Self::stream_response(StatusCode::NOT_FOUND, Self::empty_body()));
                }
                let id = path[base_path.len() + 1..].to_string();

                if req.method() == http::Method::POST {
                    warn!("[xhttp][server] recv POST peer={:?} path={} id={}", peer_addr, path, id);
                    warn!(
                        "[xhttp][server] POST version={:?} host={:?} content-type={:?}",
                        req.version(),
                        req.headers().get(header::HOST),
                        req.headers().get(header::CONTENT_TYPE)
                    );
                    let content_type = req
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("");
                    if !content_type.starts_with("application/octet-stream") {
                        error!(
                            "[xhttp][server] invalid POST content-type peer={:?} path={} id={} content_type={}",
                            peer_addr, path, id, content_type
                        );
                        return Ok::<_, Infallible>(Self::stream_response(StatusCode::BAD_REQUEST, Self::empty_body()));
                    }

                    // Extract POST body (for reading client upload data)
                    let incoming = req.into_body();

                    // Create POST response channel - for sending data back to client via POST response
                    let (post_resp_tx, post_resp_rx) =
                        mpsc::channel::<StdResult<Frame<Bytes>, Infallible>>(DEFAULT_CHANNEL_SERVER_CAPACITY);
                    let post_body = ChannelBody { rx: post_resp_rx };

                    if mode == XhttpMode::StreamOne {
                        let xstream = XhttpStream::new_stream_one(incoming, PollSender::new(post_resp_tx));
                        match stx
                            .send((super::TrStream::Xhttp(Box::new(xstream)), peer_addr.clone()))
                            .await
                        {
                            Ok(()) => {
                                warn!(
                                    "[xhttp][server] forwarded stream-one stream from POST peer={:?} id={}",
                                    peer_addr, id
                                )
                            }
                            Err(e) => error!(
                                "[xhttp][server] failed to forward stream-one stream from POST peer={:?} id={} err={}",
                                peer_addr, id, e
                            ),
                        }
                        return Ok::<_, Infallible>(Self::stream_response(StatusCode::OK, post_body));
                    }

                    // Lock scope: minimize critical section - only HashMap operations, no await inside
                    let matched_get_tx = {
                        let mut map = pending.lock().await;
                        Self::cleanup_expired_pending_streams(&mut map);
                        if let Some(PendingStream::DownloadPending { get_response_tx, .. }) = map.remove(&id) {
                            warn!("[xhttp][server] matched POST with pending GET peer={:?} id={}", peer_addr, id);
                            Some(get_response_tx)
                        } else {
                            warn!("[xhttp][server] store POST as upload pending peer={:?} id={}", peer_addr, id);
                            None
                        }
                    }; // Lock released here

                    if let Some(get_tx) = matched_get_tx {
                        // Pairing complete: GET arrived before POST
                        // Create dual-channel XhttpStream
                        warn!("[xhttp][server] POST creating dual-channel XhttpStream with incoming (POST body) and both tx channels peer={:?} id={}", peer_addr, id);
                        let xstream = XhttpStream::new_stream_up(
                            incoming,
                            PollSender::new(post_resp_tx),
                            PollSender::new(get_tx),
                        );
                        // Send to upstream outside of lock
                        match stx
                            .send((super::TrStream::Xhttp(Box::new(xstream)), peer_addr.clone()))
                            .await
                        {
                            Ok(()) => {
                                warn!("[xhttp][server] forwarded dual-channel stream from POST peer={:?} id={}", peer_addr, id)
                            }
                            Err(e) => error!(
                                "[xhttp][server] failed to forward dual-channel stream from POST peer={:?} id={} err={}",
                                peer_addr, id, e
                            ),
                        }
                        // Return POST response - upstream will write to it
                        warn!(
                            "[xhttp][server] POST returning response body channel to client peer={:?} id={}",
                            peer_addr, id
                        );
                        return Ok::<_, Infallible>(Self::stream_response(StatusCode::OK, post_body));
                    }

                    // No pending GET: store POST as pending
                    // Note: post_resp_tx and incoming are moved into pending, they can't be used here
                    warn!("[xhttp][server] POST no pending GET, storing as pending and returning empty response peer={:?} id={}", peer_addr, id);
                    {
                        let mut map = pending.lock().await;
                        map.insert(
                            id.clone(),
                            PendingStream::UploadPending {
                                incoming,
                                post_response_tx: post_resp_tx,
                                timestamp: Instant::now(),
                            },
                        );
                    }

                    // Return POST response for stream-one mode
                    // In stream-up mode, this will be auxiliary when GET arrives
                    Ok::<_, Infallible>(Self::stream_response(StatusCode::OK, post_body))
                } else if req.method() == http::Method::GET {
                    if mode == XhttpMode::StreamOne {
                        return Ok::<_, Infallible>(Self::stream_response(
                            StatusCode::METHOD_NOT_ALLOWED,
                            Self::empty_body(),
                        ));
                    }

                    warn!(
                        "[xhttp][server] recv GET peer={:?} path={} id={} version={:?} host={:?}",
                        peer_addr,
                        path,
                        id,
                        req.version(),
                        req.headers().get(header::HOST)
                    );
                    // Create GET response channel - for sending data to client via GET response
                    let (get_resp_tx, get_resp_rx) =
                        mpsc::channel::<StdResult<Frame<Bytes>, Infallible>>(DEFAULT_CHANNEL_SERVER_CAPACITY);
                    let get_body = ChannelBody { rx: get_resp_rx };

                    // Lock scope: minimize critical section - only HashMap operations
                    let matched_post = {
                        let mut map = pending.lock().await;
                        Self::cleanup_expired_pending_streams(&mut map);
                        if let Some(PendingStream::UploadPending {
                            incoming,
                            post_response_tx,
                            ..
                        }) = map.remove(&id)
                        {
                            warn!("[xhttp][server] matched GET with pending POST peer={:?} id={}", peer_addr, id);
                            Some((incoming, post_response_tx))
                        } else {
                            warn!("[xhttp][server] store GET as download pending peer={:?} id={}", peer_addr, id);
                            None
                        }
                    }; // Lock released here

                    if let Some((incoming, post_resp_tx)) = matched_post {
                        // Pairing complete: POST arrived before GET
                        // Create dual-channel XhttpStream
                        let xstream = XhttpStream::new_stream_up(
                            incoming,
                            PollSender::new(post_resp_tx),
                            PollSender::new(get_resp_tx),
                        );
                        warn!("[xhttp][server] GET pairing complete - XhttpStream created with both channels, about to forward to upstream peer={:?} id={}", peer_addr, id);
                        // Send to upstream outside of lock
                        match stx
                            .send((super::TrStream::Xhttp(Box::new(xstream)), peer_addr.clone()))
                            .await
                        {
                            Ok(()) => {
                                warn!(
                                    "[xhttp][server] forwarded dual-channel stream from GET peer={:?} id={}",
                                    peer_addr, id
                                )
                            }
                            Err(e) => error!(
                                "[xhttp][server] failed to forward dual-channel stream from GET peer={:?} id={} err={}",
                                peer_addr, id, e
                            ),
                        }
                    } else {
                        // No pending POST: store GET as pending
                        let mut map = pending.lock().await;
                        map.insert(
                            id.clone(),
                            PendingStream::DownloadPending {
                                get_response_tx: get_resp_tx,
                                timestamp: Instant::now(),
                            },
                        );
                    }

                    // Always return GET response - in stream-up mode this is the primary download channel
                    warn!(
                        "[xhttp][server] returning GET response body to client peer={:?} id={}",
                        peer_addr, id
                    );
                    Ok::<_, Infallible>(Self::stream_response(StatusCode::OK, get_body))
                } else {
                    Ok::<_, Infallible>(Self::stream_response(StatusCode::METHOD_NOT_ALLOWED, Self::empty_body()))
                }
            }
        });

        // Support both HTTP/1.1 (behind nginx) and HTTP/2
        // Note: HTTP/1.1 processes requests sequentially per connection
        if let Err(err) = AutoBuilder::new(TokioExecutor::new())
            .serve_connection(conn_io, service)
            .await
        {
            error!("[xhttp][server] connection error: {:?}", err);
        }
    }
}

// ---------------------------------------------------------------------------
// XhttpStream: AsyncRead + AsyncWrite
// ---------------------------------------------------------------------------

use futures::stream::Stream;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum XhttpMode {
    /// Stream-up mode: POST for upload, GET for download (default, matches spec)
    StreamUp,
    /// Stream-one mode: single POST channel for bidirectional stream
    StreamOne,
}

impl From<Option<String>> for XhttpMode {
    fn from(mode: Option<String>) -> Self {
        match mode.as_deref() {
            Some("stream-one") => XhttpMode::StreamOne,
            Some("stream-up") | None => XhttpMode::StreamUp,
            _ => {
                warn!(
                    "[xhttp] unknown mode '{}', defaulting to stream-up",
                    mode.as_deref().unwrap_or("null")
                );
                XhttpMode::StreamUp
            }
        }
    }
}

// Shared state for tracking stream lifecycle
struct StreamState {
    read_closed: AtomicBool,
    write_closed: AtomicBool,
}

impl StreamState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            read_closed: AtomicBool::new(false),
            write_closed: AtomicBool::new(false),
        })
    }
}

// ---------------------------------------------------------------------------
// XhttpStream: AsyncRead + AsyncWrite
// ---------------------------------------------------------------------------

// Wrap `Incoming` with an AsyncRead implementation
pin_project! {
    struct IncomingStream {
        #[pin]
        incoming: Incoming,
        // Track stream state for EOF handling
        state: Arc<StreamState>,
    }
}

impl Stream for IncomingStream {
    type Item = std::io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            match this.incoming.as_mut().poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if frame.is_data() {
                        let data = frame.into_data().unwrap_or_default();
                        if data.is_empty() {
                            // HTTP/1.1 chunked encoding may send empty data frames as keepalive
                            // Continue reading instead of returning empty data
                            trace!("[xhttp][stream] incoming body received empty data frame, continuing");
                            continue;
                        }
                        warn!("[xhttp][stream] incoming body received data frame len={}", data.len());
                        return Poll::Ready(Some(Ok(data)));
                    }

                    if frame.is_trailers() {
                        warn!("[xhttp][stream] incoming body received trailers - stream ending");
                    } else {
                        warn!("[xhttp][stream] ignoring unknown frame type from incoming body");
                    }
                    continue;
                }
                Poll::Ready(Some(Err(e))) => {
                    error!("[xhttp][stream] incoming body frame error: {}", e);
                    return Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))));
                }
                Poll::Ready(None) => {
                    warn!("[xhttp][stream] incoming body EOF - hyper Incoming closed");
                    this.state.read_closed.store(true, Ordering::Relaxed);
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// A full duplex stream that handles both read and write
pub struct XhttpStream {
    reader: Pin<Box<StreamReader<IncomingStream, Bytes>>>,
    /// POST response channel - for stream-one mode or stream-up mode fallback
    post_tx: Option<PollSender<StdResult<Frame<Bytes>, Infallible>>>,
    /// GET response channel - for stream-up mode (preferred for download)
    get_tx: Option<PollSender<StdResult<Frame<Bytes>, Infallible>>>,
    mode: XhttpMode,
    /// Shared state for tracking which halves are closed
    state: Arc<StreamState>,
}

impl XhttpStream {
    /// Create for stream-up mode (POST + GET channels, default mode)
    pub fn new_stream_up(
        incoming: Incoming,
        post_tx: PollSender<StdResult<Frame<Bytes>, Infallible>>,
        get_tx: PollSender<StdResult<Frame<Bytes>, Infallible>>,
    ) -> Self {
        Self::new_with_mode(incoming, post_tx, Some(get_tx), XhttpMode::StreamUp)
    }

    /// Create for stream-one mode (single POST channel)
    pub fn new_stream_one(incoming: Incoming, post_tx: PollSender<StdResult<Frame<Bytes>, Infallible>>) -> Self {
        Self::new_with_mode(incoming, post_tx, None, XhttpMode::StreamOne)
    }

    /// Create with specified mode
    pub fn new_with_mode(
        incoming: Incoming,
        post_tx: PollSender<StdResult<Frame<Bytes>, Infallible>>,
        get_tx: Option<PollSender<StdResult<Frame<Bytes>, Infallible>>>,
        mode: XhttpMode,
    ) -> Self {
        let state = StreamState::new();

        let stream_reader = StreamReader::new(IncomingStream {
            incoming,
            state: state.clone(),
        });
        Self {
            reader: Box::pin(stream_reader),
            post_tx: Some(post_tx),
            get_tx,
            mode,
            state,
        }
    }
}

impl Drop for XhttpStream {
    fn drop(&mut self) {
        let write_closed = self.state.write_closed.load(Ordering::Relaxed);
        let read_closed = self.state.read_closed.load(Ordering::Relaxed);

        warn!(
            "[xhttp][stream] XhttpStream dropping mode={:?} read_closed={} write_closed={} post_tx_closed={} get_tx_closed={}",
            self.mode,
            read_closed,
            write_closed,
            self.post_tx.as_ref().map(|t| t.is_closed()).unwrap_or(true),
            self.get_tx.as_ref().map(|t| t.is_closed()).unwrap_or(true)
        );

        // Only close all channels when write is explicitly closed (shutdown called)
        // In Stream-up mode, read EOF (GET body end) should NOT close write channel
        let should_close_write = write_closed || self.mode == XhttpMode::StreamOne;

        if should_close_write {
            if let Some(ref mut tx) = self.post_tx {
                tx.close();
            }
            if let Some(ref mut tx) = self.get_tx {
                tx.close();
            }
        }
        // If only read closed (GET EOF in Stream-up mode), channels remain open until stream drop completes
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        self.reader.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    /// Write strategy:
    /// - Stream-up mode: prefer GET response channel (its purpose is download)
    /// - Stream-one mode: use POST response channel
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        // Select target channel based on mode and availability
        let this = self.get_mut();
        let target_tx: Option<&mut PollSender<StdResult<Frame<Bytes>, Infallible>>> = match this.mode {
            XhttpMode::StreamUp => {
                // Stream-up mode: prefer GET response channel (download), fallback to POST
                if let Some(ref mut tx) = this.get_tx {
                    Some(tx)
                } else {
                    this.post_tx.as_mut()
                }
            }
            XhttpMode::StreamOne => this.post_tx.as_mut(),
        };

        if let Some(tx) = target_tx {
            match tx.poll_reserve(cx) {
                Poll::Ready(Ok(())) => {
                    let size = buf.len();
                    let frame = Frame::data(Bytes::copy_from_slice(buf));
                    if let Err(e) = tx.send_item(Ok(frame)) {
                        warn!(
                            "[xhttp][stream] write failed - send_item error: {:?}, mode={:?} has_post={} has_get={}",
                            e,
                            this.mode,
                            this.post_tx.is_some(),
                            this.get_tx.is_some()
                        );
                        return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, format!("Send failed: {:?}", e))));
                    }
                    Poll::Ready(Ok(size))
                }
                Poll::Ready(Err(e)) => {
                    warn!(
                        "[xhttp][stream] write failed - poll_reserve error: {:?}, mode={:?} has_post={} has_get={}",
                        e,
                        this.mode,
                        this.post_tx.is_some(),
                        this.get_tx.is_some()
                    );
                    Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, format!("Reserve failed: {:?}", e))))
                }
                Poll::Pending => {
                    // Channel is full, backpressure applied - no log at trace level to avoid spam
                    Poll::Pending
                }
            }
        } else {
            error!(
                "[xhttp][stream] write failed - no available write channel, mode={:?}",
                this.mode
            );
            Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "No write channel initialized")))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = self.get_mut();
        // Mark write as closed - this is the signal to close all channels in Drop
        this.state.write_closed.store(true, Ordering::Relaxed);
        this.state.read_closed.store(true, Ordering::Relaxed);

        // Close both channels
        if let Some(ref mut tx) = this.post_tx {
            tx.close();
        }
        if let Some(ref mut tx) = this.get_tx {
            tx.close();
        }
        Poll::Ready(Ok(()))
    }
}
