use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InSetting {
    #[serde(rename = "address")]
    pub address: Option<String>,

    #[serde(rename = "port")]
    pub port: u16,

    #[serde(rename = "network")]
    pub network: Option<String>,

    #[serde(rename = "followRedirect")]
    pub follow_redirect: Option<bool>,
}