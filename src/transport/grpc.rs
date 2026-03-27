use crate::common::Address;
use crate::generated::grpc_generated as pb;
use http::uri::PathAndQuery;
use serde::{Deserialize, Serialize};

use bytes::{Buf, Bytes, BytesMut};
use pb::*;
use std::{
    io::{Error, ErrorKind, Result as IoResult},
    marker::PhantomData,
    pin::Pin,
    result::Result,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
    task::JoinHandle,
};
use tokio_stream::StreamExt;
use tokio_util::sync::PollSender;
use tower::ServiceExt;

use log::{debug, error, warn};

const DEFAULT_BUFFER_SIZE: usize = 128 * 1024;
const DEFAULT_CONCURRENT_LIMIT: usize = 256;
const DEFAULT_HTTP2_KEEP_ALIVE_INTERVAL_SECS: u64 = 10;
const DEFAULT_HTTP2_KEEP_ALIVE_WHILE_IDLE: bool = false;
const DEFAULT_DNS_REFRESH_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcSettings {
    #[serde(rename = "serviceName")]
    service_name: String,

    #[serde(rename = "multiMode")]
    multi_mode: Option<bool>,

    #[serde(rename = "authority")]
    authority: Option<String>,

    #[serde(rename = "concurrentLimit")]
    concurrent_limit: Option<usize>,

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ConnectionTarget {
    Tcp(std::net::SocketAddr),
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl ConnectionTarget {
    fn to_balancer_key(&self) -> super::balancer::GrpcTargetKey {
        match self {
            ConnectionTarget::Tcp(addr) => super::balancer::GrpcTargetKey::Tcp(*addr),
            #[cfg(unix)]
            ConnectionTarget::Unix(path) => super::balancer::GrpcTargetKey::Unix(path.clone()),
        }
    }

    fn from_balancer_key(key: &super::balancer::GrpcTargetKey) -> Self {
        match key {
            super::balancer::GrpcTargetKey::Tcp(addr) => ConnectionTarget::Tcp(*addr),
            #[cfg(unix)]
            super::balancer::GrpcTargetKey::Unix(path) => ConnectionTarget::Unix(path.clone()),
        }
    }
}

pub struct Grpc {
    route_config: RouteConfig,
    sockopt: super::sockopt::SocketOpt,
    tls_client: Option<crate::transport::tls::client::Tls>,
    tls_server: Option<crate::transport::tls::server::Tls>,
    balancer: Arc<super::balancer::GrpcBalancer>,
    dns: std::sync::Arc<crate::route::DnsResolver>,
    dns_refresh_task: Option<JoinHandle<()>>,
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

        let route_config = RouteConfig::from(grpc_settings);
        let balancer = Arc::new(super::balancer::GrpcBalancer::new(super::balancer::Strategy::LeastLoadedP2c));

        let dns_refresh_task = Self::spawn_dns_refresh_task(server.clone(), dns.clone(), balancer.clone());

        Ok(Self {
            route_config,
            sockopt: sset.sockopt.clone(),
            tls_client,
            tls_server,
            balancer,
            dns,
            dns_refresh_task,
        })
    }

    fn spawn_dns_refresh_task(
        server: Option<Address>,
        dns: Arc<crate::route::DnsResolver>,
        balancer: Arc<super::balancer::GrpcBalancer>,
    ) -> Option<JoinHandle<()>> {
        match server.clone() {
            None => None,
            Some(Address::Inet(addr)) => Some(tokio::spawn(async move {
                balancer
                    .sync_targets(vec![ConnectionTarget::Tcp(addr).to_balancer_key()])
                    .await;
            })),
            #[cfg(unix)]
            Some(Address::Unix(path)) => Some(tokio::spawn(async move {
                balancer
                    .sync_targets(vec![ConnectionTarget::Unix(path).to_balancer_key()])
                    .await;
            })),
            #[cfg(not(unix))]
            Some(Address::Unix(_)) => None,
            Some(Address::Domain(domain, port)) => Some(tokio::spawn(async move {
                let interval = Duration::from_secs(DEFAULT_DNS_REFRESH_INTERVAL_SECS);
                loop {
                    match dns.resolve(&domain).await {
                        Ok(ips) => {
                            let targets: Vec<_> = ips
                                .into_iter()
                                .map(|ip| ConnectionTarget::Tcp(std::net::SocketAddr::new(ip, port)).to_balancer_key())
                                .collect();

                            if targets.is_empty() {
                                warn!("DNS resolved {} but got no addresses", domain);
                            } else {
                                balancer.sync_targets(targets).await;
                            }
                        }
                        Err(e) => {
                            error!("DNS resolution failed for {}: {}", domain, e);
                        }
                    }
                    tokio::time::sleep(interval).await;
                }
            })),
        }
    }

    pub fn dns(&self) -> &std::sync::Arc<crate::route::DnsResolver> {
        &self.dns
    }

    /// Connect using balancer-managed targets/channel cache.
    pub async fn connect(&self, _dest: &Address, _proto: crate::common::Protocol) -> IoResult<super::TrStream> {
        let (selected, mut stream) = self
            .balancer
            .open_with_retry(|key| async move { self.open_stream_via_target_key(&key).await })
            .await?;

        stream.target_state = Some(selected.state.clone());
        Ok(super::TrStream::Grpc(stream))
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
                .user_agent(user_agent)
                .map_err(|err| Error::new(ErrorKind::InvalidInput, err.to_string()))?;
        }
        ep = ep
            .concurrency_limit(self.route_config.concurrent_limit)
            .http2_keep_alive_interval(self.route_config.http2_keep_alive_interval)
            .keep_alive_while_idle(self.route_config.http2_keep_alive_while_idle)
            .buffer_size(self.route_config.buf_byte_size)
            .http2_adaptive_window(true);

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
        outgoing_rx: mpsc::Receiver<Bytes>,
        incoming_tx: mpsc::Sender<Bytes>,
    ) {
        debug!(
            "[gRPC][client] starting stream mode={} path={}",
            if is_multi { "multi" } else { "single" },
            path
        );
        if is_multi {
            Self::run_multi_stream(path, grpc_client, outgoing_rx, incoming_tx).await;
        } else {
            Self::run_single_stream(path, grpc_client, outgoing_rx, incoming_tx).await;
        }
    }

    async fn run_multi_stream(
        path: PathAndQuery,
        mut grpc_client: tonic::client::Grpc<tonic::transport::Channel>,
        mut outgoing_rx: mpsc::Receiver<Bytes>,
        incoming_tx: mpsc::Sender<Bytes>,
    ) {
        let path_for_log = path.clone();
        let req = tonic::Request::new(async_stream::stream! {
            while let Some(bytes) = outgoing_rx.recv().await {
                yield MultiHunk { data: vec![bytes] };
            }
        });

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
                                if incoming_tx.send(data).await.is_err() {
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
                error!("gRPC streaming call failed code: {:?}, msg: {}", err.code(), err.message());
            }
        }
    }

    async fn run_single_stream(
        path: PathAndQuery,
        mut grpc_client: tonic::client::Grpc<tonic::transport::Channel>,
        mut outgoing_rx: mpsc::Receiver<Bytes>,
        incoming_tx: mpsc::Sender<Bytes>,
    ) {
        let path_for_log = path.clone();
        let req = tonic::Request::new(async_stream::stream! {
            while let Some(bytes) = outgoing_rx.recv().await {
                yield Hunk { data: bytes };
            }
        });

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
                            if incoming_tx.send(hunk.data).await.is_err() {
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
                error!("gRPC streaming call failed code: {:?}, msg: {}", err.code(), err.message());
            }
        }
    }

    async fn open_stream_on_channel(&self, channel: tonic::transport::Channel) -> IoResult<GrpcStream> {
        let path = self.route_config.path();
        let mut grpc_client = tonic::client::Grpc::new(channel);
        grpc_client
            .ready()
            .await
            .map_err(|err| Error::new(ErrorKind::ConnectionAborted, err.to_string()))?;

        let (grpc_stream, incoming_tx, outgoing_rx) = make_service(self.route_config.buf_byte_size);
        let is_multi = self.route_config.multi_mode;

        let task = tokio::spawn(async move {
            Self::start_streaming_task(is_multi, path, grpc_client, outgoing_rx, incoming_tx).await;
        });

        let mut grpc_stream = grpc_stream;
        grpc_stream.task = Some(task);
        Ok(grpc_stream)
    }

    async fn open_stream_via_target_key(&self, key: &super::balancer::GrpcTargetKey) -> IoResult<GrpcStream> {
        if let Some(channel) = self.balancer.cached_channel(key).await {
            let mut readiness = channel.clone();
            if readiness.ready().await.is_ok() {
                return self.open_stream_on_channel(channel).await;
            }
            self.balancer.remove_cached_channel(key).await;
        }

        let target = ConnectionTarget::from_balancer_key(key);
        let channel = self.connect_channel_new(&target).await?;
        let channel = self
            .balancer
            .cache_channel(key, channel.clone())
            .await
            .ok_or_else(|| Error::new(ErrorKind::NotConnected, "gRPC target disappeared during channel rebuild"))?;
        self.open_stream_on_channel(channel).await
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
        let route_config = Arc::new(self.route_config.clone());
        let (stream_tx, mut stream_rx) = mpsc::channel::<(GrpcStream, Address)>(self.route_config.buf_byte_size);

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
                                let route_config = route_config.clone();
                                let stream_tx = stream_tx.clone();
                                let buf_byte_size = route_config.buf_byte_size;

                                tokio::spawn(async move {
                                    let peer_addr = Address::Inet(peer_addr);
                                    if let Err(e) = handle_connection(
                                        tcp_stream,
                                        peer_addr,
                                        route_config,
                                        stream_tx,
                                        buf_byte_size,
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
        let route_config = Arc::new(self.route_config.clone());
        let listener_path = path.clone();
        let (stream_tx, mut stream_rx) = mpsc::channel::<(GrpcStream, Address)>(self.route_config.buf_byte_size);

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

                                let route_config = route_config.clone();
                                let stream_tx = stream_tx.clone();
                                let buf_byte_size = route_config.buf_byte_size;
                                let unix_listener_path = listener_path.clone();
                                let peer_addr = Address::Unix(unix_listener_path.clone());

                                tokio::spawn(async move {
                                    if let Err(e) = handle_connection(
                                        unix_stream,
                                        peer_addr,
                                        route_config,
                                        stream_tx,
                                        buf_byte_size,
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
}

impl Drop for Grpc {
    fn drop(&mut self) {
        if let Some(task) = self.dns_refresh_task.take() {
            task.abort();
        }
    }
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
    fn into_chunks(self) -> TunChunks;
    fn from_bytes(bytes: Bytes) -> Self;
}

enum TunChunks {
    One(Option<Bytes>),
    Many(std::vec::IntoIter<Bytes>),
}

impl Iterator for TunChunks {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            TunChunks::One(slot) => slot.take(),
            TunChunks::Many(iter) => iter.next(),
        }
    }
}

impl TunMessage for Hunk {
    fn into_chunks(self) -> TunChunks {
        TunChunks::One(Some(self.data))
    }

    fn from_bytes(bytes: Bytes) -> Self {
        Self { data: bytes }
    }
}

impl TunMessage for MultiHunk {
    fn into_chunks(self) -> TunChunks {
        TunChunks::Many(self.data.into_iter())
    }

    fn from_bytes(bytes: Bytes) -> Self {
        Self { data: vec![bytes] }
    }
}

impl<M> TunGrpcService<M>
where
    M: TunMessage,
{
    async fn start_stream(&self) -> Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>), tonic::Status> {
        let (grpc_stream, incoming_tx, outgoing_rx) = make_service(self.buf_byte_size);
        debug!("[gRPC][server] handoff stream peer={:?}", self.peer_addr);
        self.stream_tx
            .send((grpc_stream, self.peer_addr.clone()))
            .await
            .map_err(|e| {
                error!("Failed to send gRPC stream for {:?}: {}", self.peer_addr, e);
                tonic::Status::internal("failed to hand off grpc stream")
            })?;
        Ok((incoming_tx, outgoing_rx))
    }

    fn spawn_reader(&self, mut request_stream: tonic::Streaming<M>, incoming_tx: mpsc::Sender<Bytes>) {
        let peer_addr = self.peer_addr.clone();
        tokio::spawn(async move {
            while let Some(message) = request_stream.next().await {
                match message {
                    Ok(message) => {
                        for data in message.into_chunks() {
                            if incoming_tx.send(data).await.is_err() {
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
                    let (incoming_tx, mut outgoing_rx) = service.start_stream().await?;
                    service.spawn_reader(request.into_inner(), incoming_tx);
                    let response_stream: Self::ResponseStream = Box::pin(async_stream::stream! {
                        while let Some(bytes) = outgoing_rx.recv().await {
                            yield Ok(M::from_bytes(bytes));
                        }
                    });
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
    tls_server: Option<crate::transport::tls::server::Tls>,
) -> IoResult<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use hyper::service::service_fn;

    debug!("[gRPC][server] accepted connection peer={:?}", peer_addr);

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

    if let Some(tls) = tls_server {
        match tls.accept(stream).await {
            Ok(tls_stream) => {
                let io = hyper_util::rt::TokioIo::new(tls_stream);

                let builder = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
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

        let builder = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        let conn = builder.serve_connection(io, service);

        if let Err(e) = conn.await {
            error!("HTTP/2 connection error for {:?}: {}", peer_addr, e);
            return Err(Error::new(ErrorKind::Other, e.to_string()));
        }
    }

    Ok(())
}

pub struct GrpcStream {
    read_buf: BytesMut,
    incoming_rx: Option<mpsc::Receiver<Bytes>>,
    outgoing_tx: Option<PollSender<Bytes>>,
    task: Option<tokio::task::JoinHandle<()>>,
    target_state: Option<Arc<super::balancer::TargetState>>,
}

fn make_service(buf_byte_size: usize) -> (GrpcStream, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
    let (incoming_tx, incoming_rx) = mpsc::channel::<Bytes>(buf_byte_size);
    let (outgoing_tx, outgoing_rx) = mpsc::channel::<Bytes>(buf_byte_size);

    let stream_service = GrpcStream {
        read_buf: BytesMut::new(),
        incoming_rx: Some(incoming_rx),
        outgoing_tx: Some(PollSender::new(outgoing_tx)),
        task: None,
        target_state: None,
    };

    (stream_service, incoming_tx, outgoing_rx)
}

#[derive(Debug, Clone)]
struct RouteConfig {
    authority: Option<String>,
    path: http::uri::PathAndQuery,
    multi_mode: bool,
    concurrent_limit: usize,
    user_agent: Option<String>,
    buf_byte_size: usize,
    http2_keep_alive_interval: Duration,
    http2_keep_alive_while_idle: bool,
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

        RouteConfig {
            authority: settings.authority.clone(),
            path,
            multi_mode,
            concurrent_limit: settings.concurrent_limit.unwrap_or(DEFAULT_CONCURRENT_LIMIT),
            user_agent: settings.user_agent.clone(),
            buf_byte_size: settings.buf_byte_size.unwrap_or(DEFAULT_BUFFER_SIZE),
            http2_keep_alive_interval: settings
                .http2_keep_alive_interval
                .unwrap_or(Duration::from_secs(DEFAULT_HTTP2_KEEP_ALIVE_INTERVAL_SECS)),
            http2_keep_alive_while_idle: settings
                .http2_keep_alive_while_idle
                .unwrap_or(DEFAULT_HTTP2_KEEP_ALIVE_WHILE_IDLE),
            tun_path,
            multi_tun_path,
        }
    }
}

impl Drop for GrpcStream {
    fn drop(&mut self) {
        self.incoming_rx.take();
        self.outgoing_tx.take();
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(state) = self.target_state.take() {
            state.record_stream_closed();
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
                Poll::Ready(Some(data)) => {
                    let to_copy = std::cmp::min(data.len(), buf.remaining());
                    buf.put_slice(&data[..to_copy]);

                    if to_copy < data.len() {
                        self.read_buf.extend_from_slice(&data[to_copy..]);
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
        if let Some(ref mut outgoing_tx) = self.outgoing_tx {
            match Pin::new(&mut *outgoing_tx).poll_reserve(cx) {
                Poll::Ready(Ok(())) => {
                    let size = buf.len();
                    let _ = outgoing_tx.send_item(Bytes::copy_from_slice(buf));
                    Poll::Ready(Ok(size))
                }
                Poll::Ready(Err(_)) => Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "write side closed"))),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Err(Error::new(ErrorKind::NotConnected, "write buffer not initialized")))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.outgoing_tx.take();
        Poll::Ready(Ok(()))
    }
}
