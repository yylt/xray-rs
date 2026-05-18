use super::*;
use crate::common::Address;
use crate::generated::grpc_generated as pb;
use bytes::{Buf, Bytes, BytesMut};
use futures::ready;
use ginepro::{LoadBalancedChannel, ResolutionStrategy};
use log::error;
use pb::{tunnel_client::TunnelClient, tunnel_server::Tunnel, Hunk, MultiHunk};
use serde::{Deserialize, Serialize};
use std::{
    io::{Error, ErrorKind, Result as IoResult},
    pin::Pin,
    result::Result,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
    sync::mpsc,
};
use tokio_stream::StreamExt;
use tokio_util::sync::PollSender;

const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;
const DEFAULT_HTTP2_KEEP_ALIVE_INTERVAL_SECS: u64 = 30;
const DEFAULT_HTTP2_KEEP_ALIVE_WHILE_IDLE: bool = true;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcSettings {
    #[serde(rename = "serviceName")]
    service_name: String,

    #[serde(rename = "multiMode")]
    multi_mode: Option<bool>,

    #[serde(rename = "authority")]
    authority: Option<String>,

    #[serde(rename = "userAgent")]
    user_agent: Option<String>,

    #[serde(rename = "bufByteSize")]
    buf_byte_size: Option<usize>,

    #[serde(
        rename = "http2KeepAliveInterval",
        default,
        deserialize_with = "deserialize_option_duration_secs"
    )]
    http2_keep_alive_interval: Option<std::time::Duration>,

    #[serde(rename = "http2KeepAliveWhileIdle")]
    http2_keep_alive_while_idle: Option<bool>,
}

fn deserialize_option_duration_secs<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = Option::<u64>::deserialize(deserializer)?;
    Ok(secs.map(Duration::from_secs))
}

pub struct Grpc {
    outbound: Option<OutGrpc>,
    inbound: InGrpc,
    dns: std::sync::Arc<crate::route::DnsResolver>,
}

impl Grpc {
    pub fn new(
        sset: &super::StreamSettings,
        server: Option<Address>,
        dns: std::sync::Arc<crate::route::DnsResolver>,
    ) -> IoResult<Self> {
        let grpc_settings = sset
            .grpc_settings
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "grpc_settings is required"))?;

        let outbound = match server {
            Some(_) => Some(OutGrpc::new(sset, server, grpc_settings)?),
            None => None,
        };

        Ok(Self {
            outbound,
            inbound: InGrpc::new(sset, Arc::<str>::from(grpc_settings.service_name.clone()))?,
            dns,
        })
    }

    pub fn dns(&self) -> &std::sync::Arc<crate::route::DnsResolver> {
        &self.dns
    }

    pub async fn connect(&self, dest: &Address, proto: crate::common::Protocol) -> IoResult<super::TrStream> {
        match &self.outbound {
            Some(outbound) => outbound.connect(dest, proto).await,
            None => Err(Error::new(ErrorKind::NotConnected, "grpc outbound not configured")),
        }
    }

    pub async fn listen(
        &self,
        addr: &Address,
    ) -> IoResult<crate::common::BoxStream<(super::TrStream, Address), std::io::Error>> {
        self.inbound.listen(addr).await
    }
}

pub struct OutGrpc {
    service_name: String,
    multi_mode: bool,
    authority: Option<String>,
    user_agent: Option<String>,
    tls_settings: Option<super::tls::TlsSettings>,
    endpoint_buffer_size: usize,
    endpoint_timeout: Duration,
    keep_alive_while_idle: bool,
    target: OutboundTarget,
    use_tls: bool,
    cached_channel: Mutex<Option<OutboundChannel>>,
}

enum OutboundTarget {
    Domain(String, u16),
    Inet(std::net::SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

#[derive(Clone)]
enum OutboundChannel {
    Standard(tonic::transport::Channel),
    Balanced(LoadBalancedChannel),
}

impl OutGrpc {
    fn new(sset: &super::StreamSettings, server: Option<Address>, settings: &GrpcSettings) -> IoResult<Self> {
        let target = match server {
            Some(Address::Domain(domain, port)) => OutboundTarget::Domain(domain, port),
            Some(Address::Inet(addr)) => OutboundTarget::Inet(addr),
            #[cfg(unix)]
            Some(Address::Unix(path)) => OutboundTarget::Unix(path),
            #[cfg(not(unix))]
            Some(Address::Unix(_)) => return Err(Error::new(ErrorKind::Unsupported, super::UNIX_SOCKET_UNSUPPORTED)),
            _ => return Err(Error::new(ErrorKind::InvalidInput, "grpc outbound server is required")),
        };

        Ok(Self {
            service_name: settings.service_name.clone(),
            multi_mode: settings.multi_mode.unwrap_or(false),
            authority: settings.authority.clone(),
            user_agent: settings.user_agent.clone(),
            tls_settings: sset.tls_settings.clone(),
            endpoint_buffer_size: settings.buf_byte_size.unwrap_or(DEFAULT_BUFFER_SIZE),
            endpoint_timeout: settings
                .http2_keep_alive_interval
                .unwrap_or(Duration::from_secs(DEFAULT_HTTP2_KEEP_ALIVE_INTERVAL_SECS)),
            keep_alive_while_idle: settings
                .http2_keep_alive_while_idle
                .unwrap_or(DEFAULT_HTTP2_KEEP_ALIVE_WHILE_IDLE),
            target,
            use_tls: sset.security == super::Security::Tls,
            cached_channel: Mutex::new(None),
        })
    }

    pub async fn connect(&self, _dest: &Address, _proto: crate::common::Protocol) -> IoResult<super::TrStream> {
        let cached = self.get_or_create_channel().await?;
        let stream = match self.open_stream_via_channel(cached.clone()).await {
            Ok(stream) => stream,
            Err(first_err) => {
                self.invalidate_channel().await;
                let rebuilt = self.get_or_create_channel().await?;
                match self.open_stream_via_channel(rebuilt).await {
                    Ok(stream) => stream,
                    Err(_) => return Err(first_err),
                }
            }
        };

        Ok(super::TrStream::Grpc(stream))
    }

    fn build_client_tls_config(
        &self,
        domain: &str,
        _tls_settings: Option<&super::tls::TlsSettings>,
    ) -> IoResult<tonic::transport::ClientTlsConfig> {
        let server_name = if let Some(authority) = &self.authority {
            authority.clone()
        } else {
            domain.to_string()
        };

        let cert_result = rustls_native_certs::load_native_certs();

        if !cert_result.errors.is_empty() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Failed to load some native certs: {:?}", cert_result.errors),
            ));
        }

        let tls = tonic::transport::ClientTlsConfig::new()
            .domain_name(server_name)
            .ca_certificates(cert_result.certs.into_iter().map(|cert| {
                tonic::transport::Certificate::from_pem(cert.as_ref())
            }));

        Ok(tls)
    }

    async fn build_balanced_channel(&self, domain: &str, port: u16) -> IoResult<LoadBalancedChannel> {
        let mut builder = LoadBalancedChannel::builder((domain.to_string(), port))
            .dns_probe_interval(self.endpoint_timeout)
            .connect_timeout(self.endpoint_timeout)
            .timeout(self.endpoint_timeout)
            .resolution_strategy(ResolutionStrategy::Eager {
                timeout: self.endpoint_timeout,
            });

        if self.use_tls {
            let tls = self.build_client_tls_config(domain, self.tls_settings.as_ref())?;
            builder = builder.with_tls(tls);
        }

        builder
            .channel()
            .await
            .map_err(|e| Error::new(ErrorKind::ConnectionRefused, e.to_string()))
    }

    async fn build_inet_channel(&self, addr: &std::net::SocketAddr) -> IoResult<tonic::transport::Channel> {
        let server_name = if let Some(authority) = &self.authority {
            authority.clone()
        } else {
            addr.ip().to_string()
        };
        let mut endpoint = if self.use_tls {
            tonic::transport::Endpoint::from_shared(format!("https://{}", server_name))
        } else {
            tonic::transport::Endpoint::from_shared(format!("http://{}", server_name))
        }
        .map_err(|err| Error::new(ErrorKind::InvalidInput, err.to_string()))?;

        if let Some(user_agent) = &self.user_agent {
            endpoint = endpoint
                .user_agent(user_agent)
                .map_err(|err| Error::new(ErrorKind::InvalidInput, err.to_string()))?;
        }

        endpoint = endpoint
            .http2_keep_alive_interval(self.endpoint_timeout)
            .keep_alive_while_idle(self.keep_alive_while_idle)
            .buffer_size(self.endpoint_buffer_size)
            .http2_adaptive_window(true);

        if self.use_tls {
            endpoint = endpoint
                .tls_config(self.build_client_tls_config(&server_name, self.tls_settings.as_ref())?)
                .map_err(|err| Error::new(ErrorKind::InvalidInput, err.to_string()))?;
        }

        endpoint
            .connect()
            .await
            .map_err(|err| Error::new(ErrorKind::ConnectionRefused, err.to_string()))
    }

    #[cfg(unix)]
    async fn build_unix_channel(&self, path: &std::path::PathBuf) -> IoResult<tonic::transport::Channel> {
        let endpoint = tonic::transport::Endpoint::try_from("http://localhost")
            .map_err(|err| Error::new(ErrorKind::InvalidInput, err.to_string()))?;
        let path = path.clone();

        endpoint
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let path = path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|err| Error::new(ErrorKind::ConnectionRefused, err.to_string()))
    }

    async fn get_or_create_channel(&self) -> IoResult<OutboundChannel> {
        let mut cached = self.cached_channel.lock().await;
        if let Some(channel) = cached.as_ref() {
            return Ok(channel.clone());
        }

        let channel = match &self.target {
            OutboundTarget::Domain(domain, port) => OutboundChannel::Balanced(self.build_balanced_channel(domain, *port).await?),
            OutboundTarget::Inet(addr) => OutboundChannel::Standard(self.build_inet_channel(addr).await?),
            #[cfg(unix)]
            OutboundTarget::Unix(path) => OutboundChannel::Standard(self.build_unix_channel(path).await?),
        };
        *cached = Some(channel.clone());
        Ok(channel)
    }

    async fn invalidate_channel(&self) {
        *self.cached_channel.lock().await = None;
    }

    async fn open_stream_via_channel(&self, channel: OutboundChannel) -> IoResult<GrpcStream> {
        match channel {
            OutboundChannel::Standard(channel) => {
                self.open_stream_with_client(TunnelClient::new(channel, self.service_name.clone()))
                    .await
            }
            OutboundChannel::Balanced(channel) => {
                self.open_stream_with_client(TunnelClient::new(channel, self.service_name.clone()))
                    .await
            }
        }
    }

    async fn open_stream_with_client<T>(&self, mut client: TunnelClient<T>) -> IoResult<GrpcStream>
    where
        T: tonic::client::GrpcService<tonic::body::Body> + Send + 'static,
        T::Error: Into<tonic::codegen::StdError>,
        T::Future: Send,
        T::ResponseBody: tonic::codegen::Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    {
        let (grpc_stream, incoming_tx, outgoing_rx) = make_service();
        let is_multi = self.multi_mode;

        let task = tokio::spawn(async move {
            if is_multi {
                let request = tonic::Request::new(async_stream::stream! {
                    let mut outgoing_rx = outgoing_rx;
                    while let Some(bytes) = outgoing_rx.recv().await {
                        yield MultiHunk { data: vec![bytes] };
                    }
                });
                match client.tun_multi(request).await {
                    Ok(response) => {
                        let mut stream = response.into_inner();
                        while let Ok(message) = stream.message().await {
                            match message {
                                Some(multi_hunk) => {
                                    for data in multi_hunk.data {
                                        if incoming_tx.send(data).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                                None => return,
                            }
                        }
                    }
                    Err(err) => error!("gRPC tun_multi failed code: {:?}, msg: {}", err.code(), err.message()),
                }
            } else {
                let request = tonic::Request::new(async_stream::stream! {
                    let mut outgoing_rx = outgoing_rx;
                    while let Some(bytes) = outgoing_rx.recv().await {
                        yield Hunk { data: bytes };
                    }
                });
                match client.tun(request).await {
                    Ok(response) => {
                        let mut stream = response.into_inner();
                        while let Ok(message) = stream.message().await {
                            match message {
                                Some(hunk) => {
                                    if incoming_tx.send(hunk.data).await.is_err() {
                                        return;
                                    }
                                }
                                None => return,
                            }
                        }
                    }
                    Err(err) => error!("gRPC tun failed code: {:?}, msg: {}", err.code(), err.message()),
                }
            }
        });

        let mut grpc_stream = grpc_stream;
        grpc_stream.task = Some(task);
        Ok(grpc_stream)
    }
}

pub struct InGrpc {
    service_name: Arc<str>,
    tls_server: Option<crate::transport::tls::server::Tls>,
}

impl InGrpc {
    fn new(sset: &super::StreamSettings, service_name: Arc<str>) -> IoResult<Self> {
        let tls_server = if sset.security == super::Security::Tls {
            sset.tls_settings
                .as_ref()
                .and_then(|ts| crate::transport::tls::server::new(ts).ok())
        } else {
            None
        };

        Ok(Self {
            service_name,
            tls_server,
        })
    }

    pub async fn listen(
        &self,
        addr: &Address,
    ) -> IoResult<crate::common::BoxStream<(super::TrStream, Address), std::io::Error>> {
        match addr {
            Address::Inet(addr) => self.listen_tcp(addr).await,
            #[cfg(unix)]
            Address::Unix(path) => self.listen_unix(path).await,
            #[cfg(not(unix))]
            Address::Unix(_) => Err(Error::new(ErrorKind::Unsupported, super::UNIX_SOCKET_UNSUPPORTED)),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "gRPC listen only supports TCP and Unix addresses",
            )),
        }
    }

    async fn listen_tcp(
        &self,
        addr: &std::net::SocketAddr,
    ) -> IoResult<crate::common::BoxStream<(super::TrStream, Address), std::io::Error>> {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(addr).await?;
        let service_name = self.service_name.clone();
        let tls_server = self.tls_server.clone();
        let (stream_tx, mut stream_rx) = mpsc::channel::<(GrpcStream, Address)>(DEFAULT_CHANNEL_SERVER_CAPACITY);

        let stream = async_stream::stream! {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((tcp_stream, peer_addr)) => {
                                let service_name = service_name.clone();
                                let tls_server = tls_server.clone();
                                let stream_tx = stream_tx.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = serve_incoming_connection(
                                        tcp_stream,
                                        Address::Inet(peer_addr),
                                        service_name,
                                        stream_tx,
                                        tls_server,
                                    ).await {
                                        error!("gRPC tcp connection handler error: {}", e);
                                    }
                                });
                            }
                            Err(e) => error!("Failed to accept TCP connection: {}", e),
                        }
                    }
                    Some((grpc_stream, peer_addr)) = stream_rx.recv() => {
                        yield Ok((super::TrStream::Grpc(grpc_stream), peer_addr));
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }

    #[cfg(unix)]
    async fn listen_unix(
        &self,
        path: &std::path::PathBuf,
    ) -> IoResult<crate::common::BoxStream<(super::TrStream, Address), std::io::Error>> {
        use tokio::net::UnixListener;

        if self.tls_server.is_some() {
            return Err(Error::new(ErrorKind::InvalidInput, "gRPC Unix listen does not support TLS"));
        }
        if path.exists() {
            std::fs::remove_file(path)?;
        }

        let listener = UnixListener::bind(path)?;
        let service_name = self.service_name.clone();
        let listener_path = path.clone();
        let (stream_tx, mut stream_rx) = mpsc::channel::<(GrpcStream, Address)>(DEFAULT_CHANNEL_SERVER_CAPACITY);

        let stream = async_stream::stream! {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((unix_stream, _)) => {
                                let service_name = service_name.clone();
                                let stream_tx = stream_tx.clone();
                                let peer_addr = Address::Unix(listener_path.clone());

                                tokio::spawn(async move {
                                    if let Err(e) = serve_incoming_connection(
                                        unix_stream,
                                        peer_addr,
                                        service_name,
                                        stream_tx,
                                        None,
                                    ).await {
                                        error!("gRPC unix connection handler error: {}", e);
                                    }
                                });
                            }
                            Err(e) => error!("Failed to accept Unix connection: {}", e),
                        }
                    }
                    Some((grpc_stream, peer_addr)) = stream_rx.recv() => {
                        yield Ok((super::TrStream::Grpc(grpc_stream), peer_addr));
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

#[derive(Clone)]
struct TunnelService {
    peer_addr: Address,
    stream_tx: mpsc::Sender<(GrpcStream, Address)>,
}

#[tonic::async_trait]
impl Tunnel for TunnelService {
    type TunStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<Hunk, tonic::Status>> + Send + 'static>>;
    type TunMultiStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<MultiHunk, tonic::Status>> + Send + 'static>>;

    async fn tun(
        &self,
        request: tonic::Request<tonic::Streaming<Hunk>>,
    ) -> std::result::Result<tonic::Response<Self::TunStream>, tonic::Status> {
        let (grpc_stream, incoming_tx, mut outgoing_rx) = make_service();
        self.stream_tx
            .send((grpc_stream, self.peer_addr.clone()))
            .await
            .map_err(|_| tonic::Status::internal("failed to hand off grpc stream"))?;

        tokio::spawn(async move {
            let mut inbound = request.into_inner();
            while let Some(message) = inbound.next().await {
                match message {
                    Ok(message) => {
                        if incoming_tx.send(message.data).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });

        let stream: Self::TunStream = Box::pin(async_stream::stream! {
            while let Some(bytes) = outgoing_rx.recv().await {
                yield Ok(Hunk { data: bytes });
            }
        });
        Ok(tonic::Response::new(stream))
    }

    async fn tun_multi(
        &self,
        request: tonic::Request<tonic::Streaming<MultiHunk>>,
    ) -> std::result::Result<tonic::Response<Self::TunMultiStream>, tonic::Status> {
        let (grpc_stream, incoming_tx, mut outgoing_rx) = make_service();
        self.stream_tx
            .send((grpc_stream, self.peer_addr.clone()))
            .await
            .map_err(|_| tonic::Status::internal("failed to hand off grpc stream"))?;

        tokio::spawn(async move {
            let mut inbound = request.into_inner();
            while let Some(message) = inbound.next().await {
                match message {
                    Ok(message) => {
                        for data in message.data {
                            if incoming_tx.send(data).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(_) => return,
                }
            }
        });

        let stream: Self::TunMultiStream = Box::pin(async_stream::stream! {
            while let Some(bytes) = outgoing_rx.recv().await {
                yield Ok(MultiHunk { data: vec![bytes] });
            }
        });
        Ok(tonic::Response::new(stream))
    }
}

async fn serve_incoming_connection<IO>(
    stream: IO,
    peer_addr: Address,
    service_name: Arc<str>,
    stream_tx: mpsc::Sender<(GrpcStream, Address)>,
    tls_server: Option<crate::transport::tls::server::Tls>,
) -> IoResult<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper_util::service::TowerToHyperService::new(pb::tunnel_server::TunnelServer::new(
        TunnelService {
            peer_addr: peer_addr.clone(),
            stream_tx,
        },
        service_name.as_ref().to_owned(),
    ));

    if let Some(tls) = tls_server {
        let tls_stream = tls.accept(stream).await?;
        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let builder = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .serve_connection(io, service)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    } else {
        let io = hyper_util::rt::TokioIo::new(stream);
        let builder = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .serve_connection(io, service)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }

    Ok(())
}

fn make_service() -> (GrpcStream, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
    let (incoming_tx, incoming_rx) = mpsc::channel::<Bytes>(DEFAULT_CHANNEL_CLIENT_CAPACITY);
    let (outgoing_tx, outgoing_rx) = mpsc::channel::<Bytes>(DEFAULT_CHANNEL_CLIENT_CAPACITY);

    let stream_service = GrpcStream {
        read_buf: Bytes::new(),
        write_buf: BytesMut::with_capacity(8192),
        incoming_rx: Some(incoming_rx),
        outgoing_tx: Some(PollSender::new(outgoing_tx)),
        task: None,
    };

    (stream_service, incoming_tx, outgoing_rx)
}

pub struct GrpcStream {
    read_buf: Bytes,
    write_buf: BytesMut,
    incoming_rx: Option<mpsc::Receiver<Bytes>>,
    outgoing_tx: Option<PollSender<Bytes>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for GrpcStream {
    fn drop(&mut self) {
        self.incoming_rx.take();
        self.outgoing_tx.take();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        if !self.read_buf.is_empty() {
            let to_copy = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf[..to_copy]);
            self.read_buf.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        if let Some(ref mut incoming_rx) = self.incoming_rx {
            match Pin::new(incoming_rx).poll_recv(cx) {
                Poll::Ready(Some(mut data)) => {
                    let to_copy = std::cmp::min(data.len(), buf.remaining());
                    buf.put_slice(&data[..to_copy]);

                    if to_copy < data.len() {
                        data.advance(to_copy);
                        self.read_buf = data;
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(None) => Poll::Ready(Ok(())),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        if self.write_buf.len() >= 1048576 && self.as_mut().poll_flush(cx)?.is_pending() {
            return Poll::Pending;
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        let this = self.get_mut();

        let tx = match this.outgoing_tx.as_mut() {
            Some(tx) => tx,
            None => return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "closed"))),
        };

        while !this.write_buf.is_empty() {
            match Pin::new(&mut *tx).poll_reserve(cx) {
                Poll::Ready(Ok(())) => {
                    let data = this.write_buf.split().freeze();
                    if tx.send_item(data).is_err() {
                        return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "send failed")));
                    }
                }
                Poll::Ready(Err(_)) => return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "sender closed"))),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        self.outgoing_tx.take();
        Poll::Ready(Ok(()))
    }
}
