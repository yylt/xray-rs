use crate::common::Address;
use crate::generated::grpc_generated as pb;
use crate::transport::{ConnectInfo, ConnectedStream};
use ahash::RandomState;

use http::uri::PathAndQuery;
use serde::{Deserialize, Serialize};

use bytes::{Buf, Bytes, BytesMut};
use pb::*;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind, Result as IoResult},
    marker::PhantomData,
    pin::Pin,
    result::Result,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Instant,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, RwLock},
};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tower::ServiceExt;

use log::{debug, error, warn};

static BUF_BYTE_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcSettings {
    #[serde(rename = "serviceName")]
    service_name: String,

    #[serde(rename = "multiMode")]
    multi_mode: Option<bool>,

    #[serde(rename = "authority")]
    authority: Option<String>,

    #[serde(rename = "maxConcurrentStreams")]
    max_concurrent_streams: Option<u32>,

    #[serde(rename = "initialWindowSize")]
    initial_window_size: Option<u32>,

    #[serde(rename = "userAgent")]
    user_agent: Option<String>,

    #[serde(rename = "sendCompression")]
    send_compression: Option<String>,

    #[serde(rename = "bufByteSize")]
    buf_byte_size: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ConnectionTarget {
    Tcp(std::net::SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl ConnectionTarget {
    fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            ConnectionTarget::Tcp(addr) => Some(*addr),
            #[cfg(unix)]
            ConnectionTarget::Unix(_) => None,
        }
    }
}

fn rotate_candidates(mut candidates: Vec<ConnectionTarget>, offset: usize) -> Vec<ConnectionTarget> {
    let len = candidates.len();
    if len > 0 {
        candidates.rotate_left(offset % len);
    }
    candidates
}

pub struct Grpc {
    route_config: RouteConfig,
    sockopt: super::sockopt::SocketOpt,
    tls_client: Option<crate::transport::tls::client::Tls>,
    tls_server: Option<crate::transport::tls::server::Tls>,
    channels: Arc<RwLock<HashMap<ConnectionTarget, tonic::transport::Channel, RandomState>>>,
    index: AtomicUsize,
    dns: std::sync::Arc<crate::route::DnsResolver>,
}

impl Grpc {
    pub fn new(sset: &super::StreamSettings, dns: std::sync::Arc<crate::route::DnsResolver>) -> IoResult<Self> {
        let grpc_settings = sset
            .grpc_settings
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "grpc_settings is required"))?;

        let tls_client = if sset.security == super::Security::Tls {
            sset.tls_settings
                .as_ref()
                .and_then(|ts| crate::transport::tls::client::new(ts).ok())
        } else {
            None
        };

        let tls_server = if sset.security == super::Security::Tls {
            sset.tls_settings
                .as_ref()
                .and_then(|ts| crate::transport::tls::server::new(ts).ok())
        } else {
            None
        };

        Ok(Self {
            route_config: RouteConfig::from(grpc_settings),
            sockopt: sset.sockopt.clone(),
            tls_client,
            tls_server,
            channels: Arc::new(RwLock::new(HashMap::with_hasher(RandomState::new()))),
            index: AtomicUsize::new(0),
            dns,
        })
    }

    pub fn dns(&self) -> &std::sync::Arc<crate::route::DnsResolver> {
        &self.dns
    }

    /// Connect with multi-address support and DNS resolution
    pub async fn connect(&self, dest: &Address, proto: crate::common::Protocol) -> IoResult<super::TrStream> {
        Ok(self.connect_with_info(dest, proto).await?.stream)
    }

    pub async fn connect_with_info(
        &self,
        dest: &Address,
        _proto: crate::common::Protocol,
    ) -> IoResult<ConnectedStream> {
        let candidates = self.order_targets_for_connect(dest).await?;
        let mut last_error = None;

        for target in candidates {
            let connect_started = Instant::now();
            match self.open_stream_via_target(&target).await {
                Ok(stream) => {
                    return Ok(ConnectedStream {
                        stream: super::TrStream::Grpc(stream),
                        info: ConnectInfo {
                            via: target.socket_addr(),
                            duration: Some(connect_started.elapsed()),
                        },
                    });
                }
                Err(err) => {
                    self.remove_cached_channel(&target).await;
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::new(ErrorKind::NotConnected, "gRPC connect failed with no targets")))
    }

    async fn resolve_targets(&self, dest: &Address) -> IoResult<Vec<ConnectionTarget>> {
        match dest {
            Address::Inet(addr) => Ok(vec![ConnectionTarget::Tcp(*addr)]),
            #[cfg(unix)]
            Address::Unix(path) => Ok(vec![ConnectionTarget::Unix(path.clone())]),
            #[cfg(not(unix))]
            Address::Unix(_) => Err(Error::new(ErrorKind::Unsupported, super::UNIX_SOCKET_UNSUPPORTED)),
            Address::Domain(domain, port) => match self.dns.resolve(domain).await {
                Ok(ips) => {
                    let targets: Vec<ConnectionTarget> = ips
                        .into_iter()
                        .map(|ip| ConnectionTarget::Tcp(std::net::SocketAddr::new(ip, *port)))
                        .collect();

                    if targets.is_empty() {
                        return Err(Error::new(
                            ErrorKind::NotFound,
                            format!("DNS resolved {} but got no addresses", domain),
                        ));
                    }
                    Ok(targets)
                }
                Err(e) => {
                    error!("DNS resolution failed for {}: {}", domain, e);
                    Err(Error::new(ErrorKind::NotFound, format!("DNS resolution failed: {}", e)))
                }
            },
        }
    }

    async fn order_targets_for_connect(&self, dest: &Address) -> IoResult<Vec<ConnectionTarget>> {
        let candidates = self.resolve_targets(dest).await?;

        if matches!(dest, Address::Domain(_, _)) && candidates.len() > 1 {
            let offset = self.index.fetch_add(1, Ordering::Relaxed) % candidates.len();
            return Ok(rotate_candidates(candidates, offset));
        }

        Ok(candidates)
    }

    async fn cached_channel(&self, target: &ConnectionTarget) -> Option<tonic::transport::Channel> {
        self.channels.read().await.get(target).cloned()
    }

    async fn cache_channel(
        &self,
        target: &ConnectionTarget,
        channel: tonic::transport::Channel,
    ) -> tonic::transport::Channel {
        self.channels.write().await.insert(target.clone(), channel.clone());
        channel
    }

    async fn connect_channel_new(&self, target: &ConnectionTarget) -> IoResult<tonic::transport::Channel> {
        let server_name = self.authority_for_target(target);
        let use_tls = matches!(target, ConnectionTarget::Tcp(_)) && self.tls_client.is_some();
        let endpoint = if use_tls {
            tonic::transport::Endpoint::from_shared(format!("https://{}", server_name))
        } else {
            tonic::transport::Endpoint::from_shared(format!("http://{}", server_name))
        };

        let mut ep = endpoint.map_err(|err| Error::new(ErrorKind::InvalidInput, err.to_string()))?;
        if let Some(user_agent) = &self.route_config.user_agent {
            ep = ep
                .user_agent(user_agent.clone())
                .map_err(|err| Error::new(ErrorKind::InvalidInput, err.to_string()))?;
        }
        if let Some(initial_window_size) = self.route_config.initial_window_size {
            ep = ep.initial_stream_window_size(initial_window_size);
            ep = ep.initial_connection_window_size(initial_window_size);
        }

        let connector_target = target.clone();
        let sockopt = self.sockopt.clone();
        let tls_client = self.tls_client.clone();

        ep.connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let target = connector_target.clone();
            let sockopt = sockopt.clone();
            let tls_client = tls_client.clone();

            async move {
                let io = Self::dial_grpc_transport(target, sockopt, tls_client).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(io))
            }
        }))
        .await
        .map_err(|err| {
            error!("gRPC channel connect failed to {:?}: {}", target, err);
            Error::new(ErrorKind::ConnectionRefused, err.to_string())
        })
    }

    async fn dial_grpc_transport(
        target: ConnectionTarget,
        sockopt: super::sockopt::SocketOpt,
        tls_client: Option<crate::transport::tls::client::Tls>,
    ) -> IoResult<super::TrStream> {
        match target {
            ConnectionTarget::Tcp(addr) => {
                let tcp_stream = tokio::net::TcpStream::connect(addr).await?;
                let tcp_stream = sockopt.apply_tcpstream(tcp_stream)?;

                if let Some(tls_client) = tls_client {
                    let tls_stream = tls_client.connect(&addr, tcp_stream).await?;
                    Ok(super::TrStream::TlsClient(tls_stream))
                } else {
                    Ok(super::TrStream::Tcp(tcp_stream))
                }
            }
            #[cfg(unix)]
            ConnectionTarget::Unix(path) => {
                let unix_stream = tokio::net::UnixStream::connect(path).await?;
                let unix_stream = sockopt.apply_unixstream(unix_stream)?;
                Ok(super::TrStream::Unix(unix_stream))
            }
        }
    }

    async fn start_streaming_task(
        is_multi: bool,
        path: PathAndQuery,
        grpc_client: tonic::client::Grpc<tonic::transport::Channel>,
        write_rx: mpsc::Receiver<Bytes>,
        read_tx: mpsc::Sender<Bytes>,
    ) {
        debug!(
            "[gRPC][client] starting stream mode={} path={}",
            if is_multi { "multi" } else { "single" },
            path
        );
        if is_multi {
            Self::run_multi_stream(path, grpc_client, write_rx, read_tx).await;
        } else {
            Self::run_single_stream(path, grpc_client, write_rx, read_tx).await;
        }
    }

    async fn run_multi_stream(
        path: PathAndQuery,
        mut grpc_client: tonic::client::Grpc<tonic::transport::Channel>,
        write_rx: mpsc::Receiver<Bytes>,
        read_tx: mpsc::Sender<Bytes>,
    ) {
        let path_for_log = path.clone();
        let req = tonic::Request::new(ReceiverStream::new(write_rx).map(|bytes| MultiHunk {
            data: vec![bytes.to_vec()],
        }));

        match grpc_client
            .streaming(req, path, tonic_prost::ProstCodec::default())
            .await
        {
            Ok(grpc_response) => {
                debug!("[gRPC][client] stream opened mode=multi path={}", path_for_log);
                let mut stream: tonic::codec::Streaming<MultiHunk> = grpc_response.into_inner();
                while let Ok(message) = stream.message().await {
                    match message {
                        Some(multi_hunk) => {
                            for data in multi_hunk.data {
                                if let Err(e) = read_tx.send(Bytes::from(data)).await {
                                    error!("Error send gRPC stream: {}", e);
                                    return;
                                }
                            }
                        }
                        None => {
                            debug!("[gRPC][client] remote closed stream mode=multi path={}", path_for_log);
                            return;
                        }
                    }
                }
            }
            Err(err) => {
                error!("gRPC streaming call failed code: {:?}): {}", err.code(), err.message());
            }
        }
    }

    async fn run_single_stream(
        path: PathAndQuery,
        mut grpc_client: tonic::client::Grpc<tonic::transport::Channel>,
        write_rx: mpsc::Receiver<Bytes>,
        read_tx: mpsc::Sender<Bytes>,
    ) {
        let path_for_log = path.clone();
        let req = tonic::Request::new(ReceiverStream::new(write_rx).map(|bytes| Hunk { data: bytes.to_vec() }));

        match grpc_client
            .streaming(req, path, tonic_prost::ProstCodec::default())
            .await
        {
            Ok(grpc_response) => {
                debug!("[gRPC][client] stream opened mode=single path={}", path_for_log);
                let mut stream: tonic::codec::Streaming<Hunk> = grpc_response.into_inner();
                while let Ok(message) = stream.message().await {
                    match message {
                        Some(hunk) => {
                            if let Err(e) = read_tx.send(Bytes::from(hunk.data)).await {
                                error!("Failed to send data: {}", e);
                                return;
                            }
                        }
                        None => {
                            debug!("[gRPC][client] remote closed stream mode=single path={}", path_for_log);
                            return;
                        }
                    }
                }
            }
            Err(err) => {
                error!("gRPC streaming call failed code: {:?}): {}", err.code(), err.message());
            }
        }
    }

    async fn open_stream_on_channel(
        &self,
        target: &ConnectionTarget,
        channel: tonic::transport::Channel,
    ) -> IoResult<GrpcStream> {
        let path = self.route_config.path();
        let mut grpc_client = tonic::client::Grpc::new(channel);
        if let Some(send_compression) = self.route_config.send_compression {
            grpc_client = grpc_client.send_compressed(send_compression);
        }

        debug!(
            "[gRPC][client] preparing stream target={:?} path={} mode={}",
            target,
            path,
            if self.route_config.multi_mode {
                "multi"
            } else {
                "single"
            }
        );
        grpc_client
            .ready()
            .await
            .map_err(|err| Error::new(ErrorKind::ConnectionAborted, err.to_string()))?;

        let buf_byte_size = self.route_config.buf_byte_size;
        let (grpc_stream, (read_tx, write_rx)) = make_service(buf_byte_size);
        let is_multi = self.route_config.multi_mode;

        tokio::spawn(async move {
            Self::start_streaming_task(is_multi, path, grpc_client, write_rx, read_tx).await;
        });

        Ok(grpc_stream)
    }

    async fn open_stream_via_target(&self, target: &ConnectionTarget) -> IoResult<GrpcStream> {
        if let Some(channel) = self.cached_channel(target).await {
            let mut readiness = channel.clone();
            if readiness.ready().await.is_ok() {
                return self.open_stream_on_channel(target, channel).await;
            }
            self.remove_cached_channel(target).await;
        }

        let channel = self.rebuild_channel(target).await?;
        self.open_stream_on_channel(target, channel).await
    }

    async fn remove_cached_channel(&self, target: &ConnectionTarget) {
        self.channels.write().await.remove(target);
    }

    async fn rebuild_channel(&self, target: &ConnectionTarget) -> IoResult<tonic::transport::Channel> {
        let channel = self.connect_channel_new(target).await?;
        Ok(self.cache_channel(target, channel).await)
    }

    fn authority_for_target(&self, target: &ConnectionTarget) -> String {
        if let Some(authority) = &self.route_config.authority {
            return authority.clone();
        }

        match target {
            ConnectionTarget::Tcp(addr) => addr.ip().to_string(),
            #[cfg(unix)]
            ConnectionTarget::Unix(_) => "localhost".to_string(),
        }
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
            _ => {
                error!("gRPC listen only supports TCP and Unix addresses, got: {:?}", addr);
                Err(Error::new(
                    ErrorKind::InvalidInput,
                    "gRPC listen only supports TCP and Unix addresses",
                ))
            }
        }
    }

    async fn listen_tcp(
        &self,
        addr: &std::net::SocketAddr,
    ) -> IoResult<crate::common::BoxStream<(super::TrStream, Address), std::io::Error>> {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(addr).await?;
        log::info!("gRPC listener bound successfully to {}", addr);

        let sockopt = self.sockopt.clone();
        let tls_server = self.tls_server.clone();
        let context = self.listen_context();
        let (stream_tx, mut stream_rx) = mpsc::channel::<(GrpcStream, Address)>(128);

        let stream = async_stream::stream! {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((tcp_stream, peer_addr)) => {
                                let tcp_stream = match sockopt.apply_tcpstream(tcp_stream) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to apply sockopt for {}: {}", peer_addr, e);
                                        continue;
                                    }
                                };

                                let tls_server = tls_server.clone();
                                let route_config = context.route_config.clone();
                                let stream_tx = stream_tx.clone();
                                let buf_byte_size = context.buf_byte_size;
                                let initial_window_size = context.initial_window_size;
                                let max_concurrent_streams = context.max_concurrent_streams;

                                tokio::spawn(async move {
                                    let peer_addr = Address::Inet(peer_addr);
                                    if let Err(e) = handle_connection(
                                        tcp_stream,
                                        peer_addr,
                                        route_config,
                                        stream_tx,
                                        buf_byte_size,
                                        initial_window_size,
                                        max_concurrent_streams,
                                        tls_server,
                                    )
                                    .await {
                                        error!("Connection handler error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept TCP connection: {}", e);
                                continue;
                            }
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
        log::info!("gRPC Unix listener bound successfully to {:?}", path);

        let sockopt = self.sockopt.clone();
        let context = self.listen_context();
        let listener_path = path.clone();
        let (stream_tx, mut stream_rx) = mpsc::channel::<(GrpcStream, Address)>(128);

        let stream = async_stream::stream! {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((unix_stream, _)) => {
                                let unix_stream = match sockopt.apply_unixstream(unix_stream) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to apply Unix sockopt on {:?}: {}", listener_path, e);
                                        continue;
                                    }
                                };

                                let route_config = context.route_config.clone();
                                let stream_tx = stream_tx.clone();
                                let buf_byte_size = context.buf_byte_size;
                                let initial_window_size = context.initial_window_size;
                                let max_concurrent_streams = context.max_concurrent_streams;
                                let unix_listener_path = listener_path.clone();
                                let peer_addr = Address::Unix(unix_listener_path.clone());

                                tokio::spawn(async move {
                                    if let Err(e) = handle_connection(
                                        unix_stream,
                                        peer_addr,
                                        route_config,
                                        stream_tx,
                                        buf_byte_size,
                                        initial_window_size,
                                        max_concurrent_streams,
                                        None,
                                    )
                                    .await {
                                    error!("Connection handler error for {:?}: {}", unix_listener_path, e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept Unix connection on {:?}: {}", listener_path, e);
                                continue;
                            }
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

    fn listen_context(&self) -> ListenContext {
        ListenContext {
            route_config: Arc::new(self.route_config.clone()),
            buf_byte_size: self.route_config.buf_byte_size,
            initial_window_size: self.route_config.initial_window_size,
            max_concurrent_streams: self.route_config.max_concurrent_streams,
        }
    }
}

struct ListenContext {
    route_config: Arc<RouteConfig>,
    buf_byte_size: usize,
    initial_window_size: Option<u32>,
    max_concurrent_streams: Option<u32>,
}

struct TunGrpcService<M> {
    peer_addr: Address,
    stream_tx: mpsc::Sender<(GrpcStream, Address)>,
    buf_byte_size: usize,
    _marker: PhantomData<M>,
}

impl<M> Clone for TunGrpcService<M> {
    fn clone(&self) -> Self {
        Self {
            peer_addr: self.peer_addr.clone(),
            stream_tx: self.stream_tx.clone(),
            buf_byte_size: self.buf_byte_size,
            _marker: PhantomData,
        }
    }
}

trait TunMessage: prost::Message + Default + Send + 'static {
    fn into_bytes_vec(self) -> Vec<Bytes>;
    fn from_bytes(bytes: Bytes) -> Self;
}

impl TunMessage for Hunk {
    fn into_bytes_vec(self) -> Vec<Bytes> {
        vec![Bytes::from(self.data)]
    }

    fn from_bytes(bytes: Bytes) -> Self {
        Self { data: bytes.to_vec() }
    }
}

impl TunMessage for MultiHunk {
    fn into_bytes_vec(self) -> Vec<Bytes> {
        self.data.into_iter().map(Bytes::from).collect()
    }

    fn from_bytes(bytes: Bytes) -> Self {
        Self {
            data: vec![bytes.to_vec()],
        }
    }
}

impl<M> TunGrpcService<M>
where
    M: TunMessage,
{
    async fn start_stream(&self) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>), tonic::Status> {
        let (grpc_stream, (read_tx, write_rx)) = make_service(self.buf_byte_size);
        debug!("[gRPC][server] handoff stream peer={:?}", self.peer_addr);
        self.stream_tx
            .send((grpc_stream, self.peer_addr.clone()))
            .await
            .map_err(|e| {
                error!("Failed to send gRPC stream for {:?}: {}", self.peer_addr, e);
                tonic::Status::internal("failed to hand off grpc stream")
            })?;
        Ok((read_tx, write_rx))
    }

    fn spawn_reader(&self, mut request_stream: tonic::Streaming<M>, read_tx: mpsc::Sender<Bytes>) {
        let peer_addr = self.peer_addr.clone();
        tokio::spawn(async move {
            while let Some(message) = request_stream.next().await {
                match message {
                    Ok(message) => {
                        for data in message.into_bytes_vec() {
                            if let Err(e) = read_tx.send(data).await {
                                error!("Failed to forward gRPC data from {:?}: {}", peer_addr, e);
                                return;
                            }
                        }
                    }
                    Err(_e) => {
                        break;
                    }
                }
            }
            debug!("[gRPC][server] request stream ended peer={:?}", peer_addr);
        });
    }

    async fn handle<B>(&self, req: http::Request<B>) -> http::Response<tonic::body::Body>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<tonic::codegen::StdError> + Send + 'static,
    {
        use tonic::server::StreamingService;

        #[derive(Clone)]
        struct TunMethod<M>(TunGrpcService<M>);

        impl<M> StreamingService<M> for TunMethod<M>
        where
            M: TunMessage,
        {
            type Response = M;
            type ResponseStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<M, tonic::Status>> + Send + 'static>>;
            type Future = Pin<
                Box<
                    dyn std::future::Future<Output = Result<tonic::Response<Self::ResponseStream>, tonic::Status>>
                        + Send,
                >,
            >;

            fn call(&mut self, request: tonic::Request<tonic::Streaming<M>>) -> Self::Future {
                let service = self.0.clone();
                Box::pin(async move {
                    let (read_tx, write_rx) = service.start_stream().await?;
                    service.spawn_reader(request.into_inner(), read_tx);
                    let response_stream: Self::ResponseStream =
                        Box::pin(ReceiverStream::new(write_rx).map(|bytes| Ok(M::from_bytes(bytes))));
                    Ok(tonic::Response::new(response_stream))
                })
            }
        }

        let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
        grpc.streaming(TunMethod(self.clone()), req).await
    }
}

async fn handle_connection<IO>(
    stream: IO,
    peer_addr: Address,
    route_config: Arc<RouteConfig>,
    stream_tx: mpsc::Sender<(GrpcStream, Address)>,
    buf_byte_size: usize,
    initial_window_size: Option<u32>,
    max_concurrent_streams: Option<u32>,
    tls_server: Option<crate::transport::tls::server::Tls>,
) -> IoResult<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use hyper::service::service_fn;

    debug!("[gRPC][server] accepted connection peer={:?}", peer_addr);

    // Create service function
    let service_peer_addr = peer_addr.clone();
    let service = service_fn(move |req: http::Request<hyper::body::Incoming>| {
        let route_config = route_config.clone();
        let stream_tx = stream_tx.clone();
        let peer_addr = service_peer_addr.clone();

        async move {
            let route_result = route_config.match_request(&req);

            match route_result {
                ServerRoute::None => {
                    warn!("No matching route for request from {:?}, path: {}", peer_addr, req.uri().path());
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(http::StatusCode::NOT_FOUND)
                            .body(tonic::body::Body::empty())
                            .unwrap(),
                    )
                }
                ServerRoute::Tun => {
                    debug!(
                        "[gRPC][server] matched route=Tun peer={:?} path={}",
                        peer_addr,
                        req.uri().path()
                    );
                    let service = TunGrpcService::<Hunk> {
                        peer_addr,
                        stream_tx,
                        buf_byte_size,
                        _marker: PhantomData,
                    };
                    Ok::<_, std::convert::Infallible>(service.handle(req).await)
                }
                ServerRoute::TunMulti => {
                    debug!(
                        "[gRPC][server] matched route=TunMulti peer={:?} path={}",
                        peer_addr,
                        req.uri().path()
                    );
                    let service = TunGrpcService::<MultiHunk> {
                        peer_addr,
                        stream_tx,
                        buf_byte_size,
                        _marker: PhantomData,
                    };
                    Ok::<_, std::convert::Infallible>(service.handle(req).await)
                }
            }
        }
    });

    // Apply TLS if configured and serve
    if let Some(tls) = tls_server {
        match tls.accept(stream).await {
            Ok(tls_stream) => {
                let io = hyper_util::rt::TokioIo::new(tls_stream);

                let mut builder = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
                if let Some(initial_window_size) = initial_window_size {
                    builder.initial_stream_window_size(initial_window_size);
                    builder.initial_connection_window_size(initial_window_size);
                }
                if let Some(max_concurrent_streams) = max_concurrent_streams {
                    builder.max_concurrent_streams(max_concurrent_streams);
                }
                let conn = builder.serve_connection(io, service);

                if let Err(e) = conn.await {
                    error!("HTTP/2 connection error for {:?}: {}", peer_addr, e);
                    return Err(Error::new(ErrorKind::Other, e.to_string()));
                }
            }
            Err(e) => {
                error!("TLS handshake failed for {:?}: {}", peer_addr, e);
                return Err(e);
            }
        }
    } else {
        let io = hyper_util::rt::TokioIo::new(stream);

        let mut builder = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        if let Some(initial_window_size) = initial_window_size {
            builder.initial_stream_window_size(initial_window_size);
            builder.initial_connection_window_size(initial_window_size);
        }
        if let Some(max_concurrent_streams) = max_concurrent_streams {
            builder.max_concurrent_streams(max_concurrent_streams);
        }
        let conn = builder.serve_connection(io, service);

        if let Err(e) = conn.await {
            error!("HTTP/2 connection error for {:?}: {}", peer_addr, e);
            return Err(Error::new(ErrorKind::Other, e.to_string()));
        }
    }

    Ok(())
}

#[derive(Default)]
pub struct GrpcStream {
    read_rx: Option<mpsc::Receiver<Bytes>>,
    write_tx: Option<mpsc::Sender<Bytes>>,
    read_buf: BytesMut,
}

pub fn make_service(buf_byte_size: usize) -> (GrpcStream, (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)) {
    let (read_tx, read_rx) = mpsc::channel(buf_byte_size);
    let (write_tx, write_rx) = mpsc::channel(buf_byte_size);

    let stream_service = GrpcStream {
        read_rx: Some(read_rx),
        write_tx: Some(write_tx),
        read_buf: BytesMut::new(),
    };
    (stream_service, (read_tx, write_rx))
}

#[derive(Debug, Clone)]
struct RouteConfig {
    authority: Option<String>,
    path: http::uri::PathAndQuery,
    multi_mode: bool,
    max_concurrent_streams: Option<u32>,
    initial_window_size: Option<u32>,
    user_agent: Option<String>,
    send_compression: Option<tonic::codec::CompressionEncoding>,
    buf_byte_size: usize,
    tun_path: http::uri::PathAndQuery,
    multi_tun_path: http::uri::PathAndQuery,
}

#[derive(Debug, Clone, Copy)]
enum ServerRoute {
    Tun,
    TunMulti,
    None,
}

impl RouteConfig {
    fn path(&self) -> PathAndQuery {
        self.path.clone()
    }

    fn normalized_service_path(settings: &GrpcSettings) -> String {
        const DEFAULT_PATH: &str = "/grpc";

        if settings.service_name.is_empty() {
            DEFAULT_PATH.to_string()
        } else if settings.service_name.starts_with('/') {
            settings.service_name.clone()
        } else {
            format!("/{}", settings.service_name)
        }
    }

    fn match_request<B>(&self, _req: &http::Request<B>) -> ServerRoute {
        let v = match &self.authority {
            None => true,
            Some(local) => {
                match _req
                    .headers()
                    .get(http::header::HOST)
                    .or_else(|| _req.headers().get(":authority"))
                {
                    Some(req_host) => req_host.to_str().map_or(false, |s| s == local),
                    None => false,
                }
            }
        };
        if !v {
            return ServerRoute::None;
        }
        match _req.uri().path() {
            p if p == self.tun_path.as_str() => ServerRoute::Tun,
            p if p == self.multi_tun_path.as_str() => ServerRoute::TunMulti,
            _ => ServerRoute::None,
        }
    }
}

impl From<&GrpcSettings> for RouteConfig {
    fn from(settings: &GrpcSettings) -> Self {
        let service_path = RouteConfig::normalized_service_path(settings);

        let multi_mode = settings.multi_mode.unwrap_or(false);
        let tun_path = PathAndQuery::try_from(format!("{}/Tun", service_path).as_str())
            .unwrap_or_else(|_| PathAndQuery::from_static("/grpc/Tun"));
        let multi_tun_path = PathAndQuery::try_from(format!("{}/TunMulti", service_path).as_str())
            .unwrap_or_else(|_| PathAndQuery::from_static("/grpc/TunMulti"));
        let path = if multi_mode {
            multi_tun_path.clone()
        } else {
            tun_path.clone()
        };
        let send_compression = match settings.send_compression.as_deref() {
            Some(value) if value.eq_ignore_ascii_case("gzip") => Some(tonic::codec::CompressionEncoding::Gzip),
            _ => None,
        };

        RouteConfig {
            authority: settings.authority.clone(),
            path,
            multi_mode,
            max_concurrent_streams: settings.max_concurrent_streams,
            initial_window_size: settings.initial_window_size,
            user_agent: settings.user_agent.clone(),
            send_compression,
            buf_byte_size: settings.buf_byte_size.unwrap_or(BUF_BYTE_SIZE),
            tun_path,
            multi_tun_path,
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

        if let Some(ref mut read_rx) = self.read_rx {
            match read_rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    let to_copy = std::cmp::min(data.len(), buf.remaining());
                    buf.put_slice(&data[..to_copy]);

                    if to_copy < data.len() {
                        self.read_buf.extend_from_slice(&data[to_copy..]);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        if let Some(ref write_tx) = self.write_tx {
            match write_tx.try_send(Bytes::copy_from_slice(buf)) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Err(_) => Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "write channel closed"))),
            }
        } else {
            Poll::Ready(Err(Error::new(ErrorKind::NotConnected, "write channel not initialized")))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::{rotate_candidates, ConnectionTarget, GrpcSettings};

    #[test]
    fn deserialize_grpc_settings_max_concurrent_streams() {
        let settings: GrpcSettings = serde_json::from_str(
            r#"{
                "serviceName": "grpc",
                "multiMode": false,
                "maxConcurrentStreams": 32
            }"#,
        )
        .unwrap();

        let debug = format!("{settings:?}");
        assert!(debug.contains("max_concurrent_streams: Some(32)"), "{debug}");
    }

    #[test]
    fn deserialize_grpc_settings_initial_window_size() {
        let settings: GrpcSettings = serde_json::from_str(
            r#"{
                "serviceName": "grpc",
                "multiMode": false,
                "initialWindowSize": 1048576
            }"#,
        )
        .unwrap();

        let debug = format!("{settings:?}");
        assert!(debug.contains("initial_window_size: Some(1048576)"), "{debug}");
    }

    #[test]
    fn deserialize_grpc_settings_user_agent() {
        let settings: GrpcSettings = serde_json::from_str(
            r#"{
                "serviceName": "grpc",
                "multiMode": false,
                "userAgent": "rsray-test-agent"
            }"#,
        )
        .unwrap();

        let debug = format!("{settings:?}");
        assert!(debug.contains("user_agent: Some(\"rsray-test-agent\")"), "{debug}");
    }

    #[test]
    fn deserialize_grpc_settings_send_compression() {
        let settings: GrpcSettings = serde_json::from_str(
            r#"{
                "serviceName": "grpc",
                "multiMode": false,
                "sendCompression": "gzip"
            }"#,
        )
        .unwrap();

        let debug = format!("{settings:?}");
        assert!(debug.contains("send_compression: Some("), "{debug}");
    }

    #[test]
    fn rotate_candidates_uses_offset_as_start_index() {
        let candidates = vec![
            ConnectionTarget::Tcp("127.0.0.1:1".parse().unwrap()),
            ConnectionTarget::Tcp("127.0.0.2:1".parse().unwrap()),
            ConnectionTarget::Tcp("127.0.0.3:1".parse().unwrap()),
        ];

        let rotated = rotate_candidates(candidates, 1);

        assert_eq!(
            rotated,
            vec![
                ConnectionTarget::Tcp("127.0.0.2:1".parse().unwrap()),
                ConnectionTarget::Tcp("127.0.0.3:1".parse().unwrap()),
                ConnectionTarget::Tcp("127.0.0.1:1".parse().unwrap()),
            ]
        );
    }
}
