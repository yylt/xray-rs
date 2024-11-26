use std::fmt;
use serde_json::{self, Map, Value};
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsSettings {
    #[serde(rename = "path")]
    path: String,

    #[serde(rename = "headers")]
    headers: Map<String, Value>,

    #[serde(rename = "maxEarlyData")]
    max_early_data: Option<i32>,
}