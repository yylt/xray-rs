use serde::{Serialize, Deserialize};
use crate::common::common;

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::fmt::{Debug, Display};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};

pub mod grpc;
pub mod http;
pub mod tcp;
pub mod websocket;
pub mod tls;
mod sock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSettings {
    #[serde(rename = "network", default)]
    network: common::Network,
    
    #[serde(rename = "security", default)]
    security: common::Security,

    #[serde(rename = "sockopt", default)]
    socket_options: sock::SocketOpt,

    #[serde(rename = "tlsSettings")]
    tls_settings: Option<tls::TlsSettings>,

    #[serde(rename = "tcpSettings")]
    tcp_settings: Option<tcp::TcpSettings>,

    #[serde(rename = "wsSettings")]
    ws_settings: Option<websocket::WsSettings>,

    #[serde(rename = "grpcSettings")]
    grpc_settings: Option<grpc::GrpcSettings>,

    #[serde(rename = "httpSettings")]
    http_settings: Option<http::HttpSettings>,
}

/// Specify a transport layer, like GRPC, TLS
#[async_trait]
pub trait Transport: Debug + Send + Sync {
    type Acceptor: Send + Sync;
    type RawStream: Send + Sync;
    type Stream: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync + Debug;

    fn new(config: &StreamSettings) -> Result<Self>
    where
        Self: Sized;

    /// Provide the transport with socket options
    fn hint(conn: &Self::Stream, opts: sock::SocketOpt);

    async fn bind<T: ToSocketAddrs + Send + Sync>(&self, addr: T) -> Result<Self::Acceptor>;
    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)>;
    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream>;
}

#[cfg(test)]
mod test {
    use serde_json;
    use super::*;
    use crate::common::common;
    #[test]
    fn test_stream(){
        let data = r#"
            {
                "security": "tls"
            }"#;

        // Parse the string of data into serde_json::Value.
        let v: StreamSettings = serde_json::from_str(data).unwrap();
        println!("streamsettings: {:?}", serde_json::to_string(&v));
        assert!(matches!(v.network, common::Network::Tcp));
        assert!(matches!(v.security, common::Security::Tls));
    }
}