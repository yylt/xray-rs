use serde::{Serialize, Deserialize};
use crate::common::common;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InSetting {
    #[serde(rename = "accounts")]
    pub accounts: Vec<common::Account>,

    #[serde(rename = "udp")]
    pub udp: bool,

    #[serde(rename = "ip")]
    pub ip: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutSetting {
    #[serde(rename = "servers")]
    pub servers: Vec<Server>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Server {
    #[serde(rename = "users")]
    pub accounts: Vec<common::Account>,

    #[serde(rename = "address")]
    pub address: String,

    #[serde(rename = "port")]
    pub port: u16,
}