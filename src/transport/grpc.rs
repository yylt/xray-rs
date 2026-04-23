use super::*;
use crate::{common::Address, generated::grpc_generated};
use bytes::{Buf, Bytes, BytesMut};
use http::Uri;
use serde::{Deserialize, Serialize};
use std::{
    io::{Error, ErrorKind, Result as IoResult},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures::{ready, StreamExt};
use log::{error, warn};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, Mutex},
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::PollSender;
use tonic::codegen::*;
use tonic::transport::channel;

const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;
const DEFAULT_HTTP2_KEEP_ALIVE_INTERVAL_SECS: u64 = 30;
const DEFAULT_HTTP2_KEEP_ALIVE_WHILE_IDLE: bool = true;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcSettings {
    #[serde(rename = "serviceName")]
    pub service_name: String,

    #[serde(rename = "multiMode")]
    pub multi_mode: Option<bool>,

    #[serde(rename = "authority")]
    pub authority: Option<String>,

    #[serde(rename = "userAgent")]
    pub user_agent: Option<String>,

    #[serde(rename = "bufByteSize")]
    pub buf_byte_size: Option<usize>,
}

fn get_hostport(sset: &super::StreamSettings, grpc_settings: &GrpcSettings) -> IoResult<(String, bool)> {
    if let Some(tls) = &sset.tls_settings {
        if let Some(server_name) = &tls.server_name {
            Ok((server_name.clone(), true))
        } else if let Some(authority) = &grpc_settings.authority {
            Ok((authority.clone(), true))
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "must set tlsSettings.serverName or grpcSettings.authority for gRPC over TLS",
            ))
        }
    } else if let Some(authority) = &grpc_settings.authority {
        Ok((authority.clone(), false))
    } else {
        Err(Error::new(
            ErrorKind::InvalidInput,
            "must set grpcSettings.authority when TLS is disabled",
        ))
    }
}

fn parse_uri(uri: String) -> IoResult<Uri> {
    uri.parse::<Uri>()
        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid uri {}: {}", uri, e)))
}

fn endpoint_uri_from_address(address: &Address, is_tls: bool) -> IoResult<Uri> {
    let scheme = if is_tls { "https" } else { "http" };
    match address {
        Address::Inet(addr) => parse_uri(format!("{}://{}", scheme, addr)),
        Address::Domain(domain, port) => parse_uri(format!("{}://{}:{}", scheme, domain, port)),
        #[cfg(unix)]
        Address::Unix(_) => Err(Error::new(ErrorKind::Unsupported, "gRPC over Unix socket is not supported yet")),
        #[cfg(not(unix))]
        Address::Unix(_) => Err(Error::new(ErrorKind::Unsupported, super::UNIX_SOCKET_UNSUPPORTED)),
    }
}

struct ChannelBuilder {
    endpoint_uri: Uri,
    origin_uri: Uri,
    user_agent: String,
    buf_byte_size: usize,
}

impl ChannelBuilder {
    fn new(address: Address, sset: &super::StreamSettings, grpc_settings: &GrpcSettings) -> IoResult<Self> {
        let (host, is_tls) = get_hostport(sset, grpc_settings)?;
        let endpoint_uri = endpoint_uri_from_address(&address, is_tls)?;
        let origin_uri = parse_uri(format!("{}://{}", if is_tls { "https" } else { "http" }, host))?;

        Ok(Self {
            endpoint_uri,
            origin_uri,
            user_agent: grpc_settings
                .user_agent
                .as_ref()
                .map_or("grpc/1.20".to_string(), |x| x.clone()),
            buf_byte_size: grpc_settings.buf_byte_size.map_or(DEFAULT_BUFFER_SIZE, |x| x),
        })
    }

    fn build_endpoint(&self) -> IoResult<channel::Endpoint> {
        let endpoint = channel::Channel::builder(self.endpoint_uri.clone())
            .buffer_size(self.buf_byte_size)
            .http2_keep_alive_interval(Duration::from_secs(DEFAULT_HTTP2_KEEP_ALIVE_INTERVAL_SECS))
            .keep_alive_while_idle(DEFAULT_HTTP2_KEEP_ALIVE_WHILE_IDLE)
            .user_agent(self.user_agent.clone())
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("invalid user-agent: {}", e)))?;

        Ok(endpoint)
    }

    fn build(&self) -> IoResult<channel::Channel> {
        Ok(self.build_endpoint()?.connect_lazy())
    }

    fn origin(&self) -> Uri {
        self.origin_uri.clone()
    }
}

fn grpc_status_to_io(status: tonic::Status) -> Error {
    Error::new(ErrorKind::ConnectionAborted, status.to_string())
}

pub struct Grpc {
    dns: Arc<crate::route::DnsResolver>,
    client: Mutex<grpc_generated::tunnel_client::TunnelClient<channel::Channel>>,
    multimode: bool,
    buf_byte_size: usize,
    service_name: String,
}

impl Grpc {
    pub fn new(
        sset: &super::StreamSettings,
        server: Option<Address>,
        dns: Arc<crate::route::DnsResolver>,
    ) -> IoResult<Self> {
        let grpc_settings = sset
            .grpc_settings
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "grpc_settings is required"))?;

        let server = server.ok_or_else(|| Error::new(ErrorKind::InvalidInput, "grpc server address is required"))?;
        let cb = ChannelBuilder::new(server, sset, grpc_settings)?;

        let channel = cb.build()?;
        let client =
            grpc_generated::tunnel_client::TunnelClient::with_origin(channel, &grpc_settings.service_name, cb.origin());

        Ok(Grpc {
            dns,
            service_name: grpc_settings.service_name.clone(),
            client: Mutex::new(client),
            multimode: grpc_settings.multi_mode.unwrap_or(false),
            buf_byte_size: grpc_settings.buf_byte_size.map_or(DEFAULT_BUFFER_SIZE, |x| x),
        })
    }

    pub fn dns(&self) -> &Arc<crate::route::DnsResolver> {
        &self.dns
    }

    /// Connect using gRPC bidirectional stream tunnel.
    pub async fn connect(&self, _dest: &Address, proto: crate::common::Protocol) -> IoResult<super::TrStream> {
        if proto != crate::common::Protocol::Tcp {
            return Err(Error::new(ErrorKind::Unsupported, "gRPC transport only supports TCP streams"));
        }

        let (stream_service, incoming_tx, outgoing_rx) = make_service(self.buf_byte_size);

        if self.multimode {
            let request_stream =
                ReceiverStream::new(outgoing_rx).map(|data| grpc_generated::MultiHunk { data: vec![data] });

            let mut client = self.client.lock().await;
            let response = client.tun_multi(request_stream).await.map_err(grpc_status_to_io)?;
            let mut inbound = response.into_inner();
            drop(client);

            tokio::spawn(async move {
                loop {
                    match inbound.message().await {
                        Ok(Some(chunk)) => {
                            for data in chunk.data {
                                if incoming_tx.send(data).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Ok(None) => return,
                        Err(status) => {
                            warn!("gRPC tun_multi stream closed with error: {}", status);
                            return;
                        }
                    }
                }
            });
        } else {
            let request_stream = ReceiverStream::new(outgoing_rx).map(|data| grpc_generated::Hunk { data });

            let mut client = self.client.lock().await;
            let response = client.tun(request_stream).await.map_err(grpc_status_to_io)?;
            let mut inbound = response.into_inner();
            drop(client);

            tokio::spawn(async move {
                loop {
                    match inbound.message().await {
                        Ok(Some(chunk)) => {
                            if incoming_tx.send(chunk.data).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => return,
                        Err(status) => {
                            warn!("gRPC tun stream closed with error: {}", status);
                            return;
                        }
                    }
                }
            });
        }

        Ok(TrStream::Grpc(stream_service))
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
        let (new_conn_tx, new_conn_rx) = tokio::sync::mpsc::channel(32);
        let sname = self.service_name.clone();
        let server_future = async move {
            let service = GrpcTunnelService { new_conn_tx };

            if let Err(e) = tonic::transport::Server::builder()
                .add_service(grpc_generated::tunnel_server::TunnelServer::new(service, sname.as_str))
                .serve(*addr)
                .await
            {
                error!("gRPC server failed: {}", e);
            }
        };

        tokio::spawn(server_future);

        let stream = tokio_stream::wrappers::ReceiverStream::new(new_conn_rx).map(Ok).boxed();
        Ok(stream)
    }

    #[cfg(unix)]
    async fn listen_unix(
        &self,
        _path: &std::path::PathBuf,
    ) -> IoResult<crate::common::BoxStream<(super::TrStream, Address), std::io::Error>> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "gRPC inbound listen over Unix socket is not implemented yet",
        ))
    }
}

struct GrpcTunnelService {
    new_conn_tx: tokio::sync::mpsc::Sender<(super::TrStream, Address)>,
}

#[tonic::async_trait]
impl grpc_generated::tunnel_server::Tunnel for GrpcTunnelService {
    type TunStream = tokio_stream::wrappers::ReceiverStream<grpc_generated::Hunk>;
    type TunMultiStream = tokio_stream::wrappers::ReceiverStream<grpc_generated::MultiHunk>;

    async fn tun(
        &self,
        request: tonic::Request<tonic::Streaming<grpc_generated::Hunk>>,
    ) -> Result<tonic::Response<Self::TunStream>, tonic::Status> {
        let mut incoming_stream = request.into_inner();
        let (stream_service, incoming_tx, mut outgoing_rx) = make_service(self.buf_byte_size);
        // 获取客户端地址（如果有）
        let remote_addr = request
            .remote_addr()
            .map(|addr| Address::Inet(addr))
            .unwrap_or_else(|| Address::Other("unknown".to_string()));

        // 将新连接发送给 listen 返回的 stream
        if self
            .new_conn_tx
            .send((TrStream::Grpc(stream_service), remote_addr))
            .await
            .is_err()
        {
            return Err(tonic::Status::internal("failed to send new connection"));
        }

        // 启动任务：从 gRPC 请求流中读取数据，写入 incoming_tx
        let inbound_task = tokio::spawn(async move {
            while let Some(chunk) = incoming_stream.message().await? {
                if incoming_tx.send(chunk.data).await.is_err() {
                    break;
                }
            }
            Ok::<_, tonic::Status>(())
        });

        // 创建响应流：将 outgoing_rx 的数据转换为 gRPC Hunk 并发送给客户端
        let output_stream =
            tokio_stream::wrappers::ReceiverStream::new(outgoing_rx).map(|data| grpc_generated::Hunk { data });

        // 等待 inbound 任务完成（忽略结果，因为流关闭时会自动结束）
        tokio::spawn(async move {
            let _ = inbound_task.await;
        });

        Ok(tonic::Response::new(output_stream))
    }

    async fn tun_multi(
        &self,
        request: tonic::Request<tonic::Streaming<grpc_generated::MultiHunk>>,
    ) -> Result<tonic::Response<Self::TunMultiStream>, tonic::Status> {
        let mut incoming_stream = request.into_inner();
        let (stream_service, incoming_tx, mut outgoing_rx) = make_service(self.buf_byte_size);
        let remote_addr = request
            .remote_addr()
            .map(|addr| Address::Inet(addr))
            .unwrap_or_else(|| Address::Other("unknown".to_string()));

        if self
            .new_conn_tx
            .send((TrStream::Grpc(stream_service), remote_addr))
            .await
            .is_err()
        {
            return Err(tonic::Status::internal("failed to send new connection"));
        }

        let inbound_task = tokio::spawn(async move {
            while let Some(chunk) = incoming_stream.message().await? {
                for data in chunk.data {
                    if incoming_tx.send(data).await.is_err() {
                        break;
                    }
                }
            }
            Ok::<_, tonic::Status>(())
        });

        let output_stream = tokio_stream::wrappers::ReceiverStream::new(outgoing_rx)
            .map(|data| grpc_generated::MultiHunk { data: vec![data] });

        tokio::spawn(async move {
            let _ = inbound_task.await;
        });

        Ok(tonic::Response::new(output_stream))
    }
}

fn make_service(_buf_byte_size: usize) -> (GrpcStream, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
    let (incoming_tx, incoming_rx) = mpsc::channel::<Bytes>(DEFAULT_CHANNEL_CLIENT_CAPACITY);
    let (outgoing_tx, outgoing_rx) = mpsc::channel::<Bytes>(DEFAULT_CHANNEL_CLIENT_CAPACITY);

    let stream_service = GrpcStream {
        read_buf: Bytes::new(),
        write_buf: BytesMut::with_capacity(8192),
        incoming_rx: Some(incoming_rx),
        outgoing_tx: Some(PollSender::new(outgoing_tx)),
    };

    (stream_service, incoming_tx, outgoing_rx)
}

pub struct GrpcStream {
    read_buf: Bytes,
    write_buf: BytesMut,
    incoming_rx: Option<mpsc::Receiver<Bytes>>,
    outgoing_tx: Option<PollSender<Bytes>>,
}

impl Drop for GrpcStream {
    fn drop(&mut self) {
        self.incoming_rx.take();
        self.outgoing_tx.take();
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
        if self.write_buf.len() >= 1048576 {
            if self.as_mut().poll_flush(cx)?.is_pending() {
                return Poll::Pending;
            }
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
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "sender closed")));
                }
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
