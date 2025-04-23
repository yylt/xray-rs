use serde::{Serialize, Deserialize};
use crate::common::common;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InSetting {
    #[serde(rename = "accounts")]
    pub accounts: Vec<common::Account>,

    #[serde(rename = "allowTransparent")]
    pub allow_transparent: bool,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutSetting {
    #[serde(rename = "users")]
    pub accounts: Vec<common::Account>,

    #[serde(rename = "address")]
    pub address: String,

    #[serde(rename = "port")]
    pub port: u16,
}