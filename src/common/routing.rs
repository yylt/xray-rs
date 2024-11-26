
use std::fmt;
use serde_json::{self,Value};
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Routing {
    #[serde(rename = "domainStrategy")]
    domain_strategy: Option<String>,

    #[serde(rename = "rules")]
    rules: Option<Vec<Rule>>,

    #[serde(rename = "balancers")]
    balancers: Option<Vec<Balance>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(rename = "domainMatcher")]
    domain_matcher: Option<String>,

    #[serde(rename = "domains")]
    domains: Option<Vec<String>>,

    #[serde(rename = "ip")]
    ip: Option<Vec<String>>,

    #[serde(rename = "port")]
    port: Option<Vec<String>>,

    #[serde(rename = "sourcePort")]
    source_port: Option<Vec<String>>,

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