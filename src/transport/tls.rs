
use std::fmt;
use serde_json::{self,Value};
use serde::{Serialize, Deserialize};




#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {

    #[serde(rename = "serverName")]
    server_name: Option<String>,

    #[serde(rename = "alpn")]
    alpn_protocols: Option<Vec<String>>,

    #[serde(rename = "allowInsecure")]
    allow_insecure: Option<bool>,

    #[serde(rename = "verifyCertificate")]
    verify_certificate: Option<bool>,
}