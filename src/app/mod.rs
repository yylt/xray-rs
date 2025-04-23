pub mod routing;
pub mod inbound;
pub mod outbound;

use crate::{proxy, transport};
use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct Inbound {

    listen: String,

    port: Option<u16>,

    #[serde(flatten)]
    settings: Option<proxy::InboundSettings>,

    tag: Option<String>,

    #[serde(rename = "streamSettings")]
    stream_settings: Option<transport::StreamSettings>,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Outbound {

    #[serde(flatten)]
    settings: Option<proxy::OutboundSettings>,

    tag: Option<String>,

    #[serde(rename = "streamSettings")]
    stream_settings: Option<transport::StreamSettings>,
}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Routing {
    #[serde(rename = "domainStrategy")]
    domain_strategy: Strategy,

    #[serde(rename = "rules")]
    rules: Option<Vec<Rule>>,

    #[serde(rename = "balancers")]
    balancers: Option<Vec<Balance>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum Strategy {
    #[default] 
    #[serde(rename="AsIs")]
    AsIs,
    #[serde(rename="IPIfNonMatch")]
    IPIfNonMatch,
    #[serde(rename="IPOnDemand")]
    IPOnDemand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(rename = "domain")]
    domain: Option<Vec<String>>,

    #[serde(rename = "ip")]
    dst_ip: Option<Vec<String>>,

    #[serde(rename = "port")]
    dst_port: Option<Vec<String>>,

    #[serde(rename = "inboundTag")]
    inbound_tag: Option<Vec<String>>,

    #[serde(rename = "outboundTag")]
    outbound_tag: Option<String>,

    #[serde(rename = "balancerTag")]
    balancer_tag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {   
    #[serde(rename = "tag")]
    tag: String,

    #[serde(rename = "fallbackTag")]
    fallback_tag: Option<String>,

    #[serde(rename = "selector")]
    selector: Vec<String>,
}