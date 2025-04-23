use serde::{Serialize, Deserialize};
use std::net;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Account {
    pub user: String,
    pub pass: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub enum Network {
    #[default] 
    #[serde(rename="tcp")]
    Tcp,
    #[serde(rename="udp")]
    Udp,
    #[serde(rename="unix")]
    Unix,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub enum Security {
    #[default] 
    #[serde(rename="none")]
    None,
    #[serde(rename="tls")]
    Tls,
}

pub struct IpPort {
    pub ip: net::IpAddr,
    pub port: u16,
}

pub enum Address {
    Ipport(IpPort),
    Domain(String),
}
