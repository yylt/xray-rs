use clap;
use std::fmt;
use serde_json::{self,Value};
use serde::{Serialize, Deserialize};
use crate::{proxy, transport, common::routing};


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    
    outbounds: Option<Vec::<Outbound>>,

    inbounds: Option<Vec::<Inbound>>,

    routing: Option<routing::Routing>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Outbound {

    #[serde(flatten)]
    settings: Option<proxy::Settings>,

    tag: Option<String>,

    #[serde(rename = "streamSettings")]
    stream_settings: Option<transport::StreamSettings>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inbound {

    listen: String,

    port: Option<u16>,

    #[serde(flatten)]
    settings: Option<proxy::Settings>,

    tag: Option<String>,

    #[serde(rename = "streamSettings")]
    stream_settings: Option<transport::StreamSettings>,
}


#[cfg(test)]
mod test {
    use serde_json::{Value};
    use super::*;

    #[test]
    fn parse_conf1(){
    }
}
