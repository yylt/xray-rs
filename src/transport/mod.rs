use std::fmt;
use serde_json::{self,Value};
use serde::{Serialize, Deserialize};

pub mod grpc;
pub mod http;
pub mod tcp;
pub mod websocket;
pub mod tls;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSettings {
    
    network: String,

    security: Option<String>,

    #[serde(rename = "tlsSettings")]
    tls_settings: Option<tls::TlsSettings>,

    #[serde(rename = "tcpSettings")]
    tcp_settings: Option<tcp::tcpSettings>,

    #[serde(rename = "wsSettings")]
    ws_settings: Option<websocket::WsSettings>,

    #[serde(rename = "grpcSettings")]
    grpc_settings: Option<grpc::GrpcSettings>,

    #[serde(rename = "httpSettings")]
    http_settings: Option<http::HttpSettings>,

    #[serde(rename = "sockopt")]
    socket_options: Option<SocketOpt>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketOpt {

    #[serde(rename = "mark")]
    mark: Option<i16>,

    #[serde(rename = "tcpFastOpen")]
    tcp_fast_open: Option<bool>,

    #[serde(rename = "tcpKeepAliveInterval")]
    tcp_keepalive_interval: Option<i16>,

    #[serde(rename = "tcpKeepAliveIdle")]
    tcp_keepalive_idle: Option<bool>,

    #[serde(rename = "tcpNoDelay")]
    tcp_nodelay: Option<bool>,

    #[serde(rename = "tcpcongestion")]
    tcp_congestion: Option<String>,

    #[serde(rename = "interface")]
    interface: Option<String>,
}