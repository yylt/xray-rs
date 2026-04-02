use crate::common::{Address, BoxStream, Protocol};
use crate::route::DnsResolver;
use crate::transport::sockopt::SocketOpt;
use crate::transport::tls;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::body::{Body, Frame, Incoming};
use pin_project_lite::pin_project;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_util::io::StreamReader;
use tokio_util::sync::PollSender;

use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use log::error;
use std::time::Instant;

use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XhttpSettings {
    #[serde(rename = "path")]
    pub path: String,

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
    UploadPending {
        incoming: Incoming,
        timestamp: Instant,
    },
    DownloadPending {
        tx: mpsc::Sender<StdResult<Frame<Bytes>, Infallible>>,
        timestamp: Instant,
    },
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

    // Client connection cache using RwLock for fast read access
    upload_client: Arc<RwLock<Option<SendRequest<ChannelBody>>>>,
    download_client: Arc<RwLock<Option<SendRequest<Empty<Bytes>>>>>,

    // Server stream matching
    pending_streams: Arc<Mutex<HashMap<String, PendingStream>>>,
}

impl Xhttp {
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

    // Connect client to specific endpoint and start HTTP/2 task if needed
    async fn get_upload_client(&self) -> IoResult<SendRequest<ChannelBody>> {
        let client_opt = self.upload_client.read().await;
        if let Some(client) = client_opt.as_ref() {
            if client.is_ready() {
                return Ok(client.clone());
            }
        }
        drop(client_opt);

        let mut write_lock = self.upload_client.write().await;
        // Check again after acquiring write lock
        if let Some(client) = write_lock.as_ref() {
            if client.is_ready() {
                return Ok(client.clone());
            }
        }

        let upload_config = self
            .settings
            .upload
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "upload config is not set in XhttpSettings"))?;

        let ips = self.dns.resolve(&upload_config.address).await.map_err(|e| {
            Error::new(
                ErrorKind::NotFound,
                format!("DNS resolution failed for {}: {}", upload_config.address, e),
            )
        })?;

        if ips.is_empty() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("No IP found for {}", upload_config.address),
            ));
        }

        let socket_addr = std::net::SocketAddr::new(ips[0], upload_config.port);

        // Connect using the resolved address
        let stream = TcpStream::connect(&socket_addr).await?;
        let stream = self.opt.apply_tcpstream(stream)?;

        let request_sender = if let Some(tls) = &self.tls_client {
            let tls_stream = tls.connect(&socket_addr, stream).await?;
            let (request_sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(tls_stream))
                .await
                .map_err(|e| Error::new(ErrorKind::ConnectionAborted, e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("Error in upload HTTP/2 TLS connection: {:?}", e);
                }
            });
            request_sender
        } else {
            let (request_sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(stream))
                .await
                .map_err(|e| Error::new(ErrorKind::ConnectionAborted, e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("Error in upload HTTP/2 connection: {:?}", e);
                }
            });
            request_sender
        };

        *write_lock = Some(request_sender.clone());
        Ok(request_sender)
    }

    async fn get_download_client(&self) -> IoResult<SendRequest<Empty<Bytes>>> {
        let client_opt = self.download_client.read().await;
        if let Some(client) = client_opt.as_ref() {
            if client.is_ready() {
                return Ok(client.clone());
            }
        }
        drop(client_opt);

        let mut write_lock = self.download_client.write().await;
        // Check again after acquiring write lock
        if let Some(client) = write_lock.as_ref() {
            if client.is_ready() {
                return Ok(client.clone());
            }
        }

        let download_config = self
            .settings
            .download
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "download config is not set in XhttpSettings"))?;

        let ips = self.dns.resolve(&download_config.address).await.map_err(|e| {
            Error::new(
                ErrorKind::NotFound,
                format!("DNS resolution failed for {}: {}", download_config.address, e),
            )
        })?;

        if ips.is_empty() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("No IP found for {}", download_config.address),
            ));
        }

        let socket_addr = std::net::SocketAddr::new(ips[0], download_config.port);

        // Connect using the resolved address
        let stream = TcpStream::connect(&socket_addr).await?;
        let stream = self.opt.apply_tcpstream(stream)?;

        let request_sender = if let Some(tls) = &self.tls_client {
            let tls_stream = tls.connect(&socket_addr, stream).await?;
            let (request_sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(tls_stream))
                .await
                .map_err(|e| Error::new(ErrorKind::ConnectionAborted, e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("Error in download HTTP/2 TLS connection: {:?}", e);
                }
            });
            request_sender
        } else {
            let (request_sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(stream))
                .await
                .map_err(|e| Error::new(ErrorKind::ConnectionAborted, e.to_string()))?;

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("Error in download HTTP/2 connection: {:?}", e);
                }
            });
            request_sender
        };

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

        // --- Execute Download (GET) ---
        let mut get_client = self.get_download_client().await?;
        let download_address = self
            .settings
            .download
            .as_ref()
            .map(|d| d.address.as_str())
            .unwrap_or("");
        let get_req = Request::builder()
            .method("GET")
            .uri(&path)
            .header("Host", download_address)
            .header("User-Agent", "xray-rs/v0.1.0")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let get_response = get_client
            .send_request(get_req)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("GET request failed: {}", e)))?;

        if get_response.status() != StatusCode::OK {
            return Err(Error::new(
                ErrorKind::ConnectionRefused,
                format!("Download failed with status: {}", get_response.status()),
            ));
        }
        let incoming = get_response.into_body();

        // --- Execute Upload (POST) ---
        let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_CLIENT_CAPACITY);
        let body = ChannelBody { rx };

        let upload_address = self.settings.upload.as_ref().map(|u| u.address.as_str()).unwrap_or("");
        let mut post_client = self.get_upload_client().await?;
        let post_req = Request::builder()
            .method("POST")
            .uri(&path)
            .header("Host", upload_address)
            .header("User-Agent", "xray-rs/v0.1.0")
            .header("Content-Type", "application/octet-stream")
            .header("Transfer-Encoding", "chunked")
            .body(body)
            .unwrap();

        // Spawn a task to drive the POST request to avoid blocking on it while reading/writing
        tokio::spawn(async move {
            if let Err(e) = post_client.send_request(post_req).await {
                error!("POST request failed: {}", e);
            }
        });

        // Assemble stream
        Ok(XhttpStream::new(incoming, PollSender::new(tx)))
    }

    pub async fn listen(&self, addr: &Address) -> IoResult<BoxStream<(super::TrStream, Address), std::io::Error>> {
        let (stream_tx, mut stream_rx) = mpsc::channel(1024);

        let bind_addr = match addr {
            Address::Inet(a) => a.to_string(),
            #[cfg(unix)]
            Address::Unix(p) => p.to_string_lossy().to_string(),
            
            _ => return Err(Error::new(ErrorKind::InvalidInput, "Unsupported address type for TCP listener")),
        };

        let listener = TcpListener::bind(&bind_addr).await?;
        let pending = self.pending_streams.clone();
        let stx = stream_tx.clone();
        let base_path = self.settings.path.clone();
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
                                    Self::serve_connection(io, pending_clone, stx_clone, base_path_clone, peer_addr).await;
                                }
                                Err(e) => {
                                    error!("TLS accept error from {}: {}", peer_addr, e);
                                }
                            }
                        } else {
                            let io = TokioIo::new(stream);
                            Self::serve_connection(io, pending_clone, stx_clone, base_path_clone, peer_addr).await;
                        }
                    });
                }
            }
        });

        let stream = async_stream::stream! {
            while let Some(item) = stream_rx.recv().await {
                yield Ok(item);
            }
        };

        Ok(Box::pin(stream))
    }
    async fn serve_connection<I>(
        conn_io: TokioIo<I>,
        pending: Arc<Mutex<HashMap<String, PendingStream>>>,
        stx: mpsc::Sender<(super::TrStream, Address)>,
        base_path: String,
        peer_addr: core::net::SocketAddr,
    ) where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
            let pending = pending.clone();
            let stx = stx.clone();
            let base_path = base_path.clone();

            async move {
                let path = req.uri().path().to_string();

                // Validate base path
                if !path.starts_with(&base_path) || path.len() <= base_path.len() + 1 {
                    let body = ChannelBody { rx: mpsc::channel(1).1 };
                    return Ok::<_, Infallible>(Response::builder().status(StatusCode::NOT_FOUND).body(body).unwrap());
                }
                let id = path[base_path.len() + 1..].to_string();

                if req.method() == http::Method::POST {
                    let content_type = req
                        .headers()
                        .get("Content-Type")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("");
                    if content_type != "application/octet-stream" {
                        let body = ChannelBody { rx: mpsc::channel(1).1 };
                        return Ok::<_, Infallible>(
                            Response::builder().status(StatusCode::BAD_REQUEST).body(body).unwrap(),
                        );
                    }
                    let mut map = pending.lock().await;
                    if let Some(PendingStream::DownloadPending { tx, .. }) = map.remove(&id) {
                        // Match found
                        let incoming = req.into_body();
                        let xstream = XhttpStream::new(incoming, PollSender::new(tx));

                        let _ = stx
                            .send((super::TrStream::Xhttp(Box::new(xstream)), Address::Inet(peer_addr)))
                            .await;
                    } else {
                        map.insert(
                            id,
                            PendingStream::UploadPending {
                                incoming: req.into_body(),
                                timestamp: Instant::now(),
                            },
                        );
                    }
                    let body = ChannelBody { rx: mpsc::channel(1).1 };
                    Ok::<_, Infallible>(Response::new(body))
                } else if req.method() == http::Method::GET {
                    let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_SERVER_CAPACITY);
                    let body = ChannelBody { rx };

                    let mut map = pending.lock().await;
                    if let Some(PendingStream::UploadPending { incoming, .. }) = map.remove(&id) {
                        // Match found
                        let xstream = XhttpStream::new(incoming, PollSender::new(tx));

                        let _ = stx
                            .send((super::TrStream::Xhttp(Box::new(xstream)), Address::Inet(peer_addr)))
                            .await;
                    } else {
                        map.insert(
                            id,
                            PendingStream::DownloadPending {
                                tx,
                                timestamp: Instant::now(),
                            },
                        );
                    }

                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("Transfer-Encoding", "chunked")
                            .body(body)
                            .unwrap(),
                    )
                } else {
                    let body = ChannelBody { rx: mpsc::channel(1).1 };
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(body)
                            .unwrap(),
                    )
                }
            }
        });

        if let Err(err) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(conn_io, service)
            .await
        {
            error!("Error serving connection: {:?}", err);
        }
    }
}

// ---------------------------------------------------------------------------
// XhttpStream: AsyncRead + AsyncWrite
// ---------------------------------------------------------------------------

use futures::stream::Stream;

// ---------------------------------------------------------------------------
// XhttpStream: AsyncRead + AsyncWrite
// ---------------------------------------------------------------------------

// Wrap `Incoming` with an AsyncRead implementation
pin_project! {
    struct IncomingStream {
        #[pin]
        incoming: Incoming,
    }
}

impl Stream for IncomingStream {
    type Item = std::io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        match this.incoming.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.is_data() {
                    Poll::Ready(Some(Ok(frame.into_data().unwrap_or_default())))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// A full duplex stream that handles both read and write
pub struct XhttpStream {
    reader: Pin<Box<StreamReader<IncomingStream, Bytes>>>,
    tx: Option<PollSender<StdResult<Frame<Bytes>, Infallible>>>,
}

impl XhttpStream {
    pub fn new(incoming: Incoming, tx: PollSender<StdResult<Frame<Bytes>, Infallible>>) -> Self {
        let stream_reader = StreamReader::new(IncomingStream { incoming });
        Self {
            reader: Box::pin(stream_reader),
            tx: Some(tx),
        }
    }
}

impl Drop for XhttpStream {
    fn drop(&mut self) {}
}

impl AsyncRead for XhttpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        self.reader.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        if let Some(ref mut tx) = self.tx {
            match tx.poll_reserve(cx) {
                Poll::Ready(Ok(())) => {
                    let size = buf.len();
                    let frame = Frame::data(Bytes::copy_from_slice(buf));
                    let _ = tx.send_item(Ok(frame));
                    Poll::Ready(Ok(size))
                }
                Poll::Ready(Err(_)) => Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "Write side closed"))),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "No write channel initialized")))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        if let Some(ref mut tx) = self.tx {
            tx.close();
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
