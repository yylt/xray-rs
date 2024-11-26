use std::fmt;
use serde_json::{self,Value};
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct tcpSettings {
    #[serde(rename = "acceptProxyProtocol")]
    acceptProxyProtocol: Option<bool>,

}