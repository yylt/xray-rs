use std::fmt;
use serde_json::{self,Value};
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcSettings {
    #[serde(rename = "serviceName")]
    service_name: String,

    #[serde(rename = "multiMode")]
    multi_mode: Option<bool>,
}