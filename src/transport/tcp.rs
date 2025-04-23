use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSettings {
    #[serde(rename = "acceptProxyProtocol")]
    accept_proxy_protocol: Option<bool>,

}