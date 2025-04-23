use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSettings {
    #[serde(rename = "host")]
    host: String, 

    #[serde(rename = "path")]
    path: Option<String>,

    #[serde(rename = "method")]
    method: Option<String>,

}