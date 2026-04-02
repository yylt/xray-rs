pub mod http;
pub mod reverse;
pub mod socks;
pub mod trojan;
#[cfg(feature = "tun")]
pub mod tun;
pub mod vless;

use crate::{
    common::*,
    transport::{self, TrStream},
};

use serde::{de::Error as DeError, Deserialize, Serialize};

use std::io::Result;


#[derive(Serialize, Debug)]
#[serde(tag = "protocol", content = "settings")]
pub enum InboundSettings {
    #[serde(rename = "http")]
    Http(http::InSetting),

    #[serde(rename = "socks")]
    Socks(socks::InSetting),

    #[serde(rename = "trojan")]
    Trojan(trojan::InSetting),

    #[serde(rename = "vless")]
    Vless(vless::InSetting),

    #[cfg(feature = "tun")]
    #[serde(rename = "tun")]
    Tun(tun::InSetting),

    #[serde(rename = "reverse")]
    Reverse(reverse::InSetting),
}

#[derive(Deserialize)]
struct RawInboundSettings {
    protocol: String,
    settings: Option<serde_json::Value>,
}

fn deserialize_settings<T, E>(settings: Option<serde_json::Value>) -> std::result::Result<T, E>
where
    T: serde::de::DeserializeOwned,
    E: DeError,
{
    let value = settings.ok_or_else(|| E::missing_field("settings"))?;
    serde_json::from_value(value).map_err(E::custom)
}

impl<'de> Deserialize<'de> for InboundSettings {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawInboundSettings::deserialize(deserializer)?;

        match raw.protocol.as_str() {
            "http" => match raw.settings {
                Some(value) => serde_json::from_value(value)
                    .map(InboundSettings::Http)
                    .map_err(D::Error::custom),
                None => Ok(InboundSettings::Http(http::InSetting::default())),
            },
            "socks" => match raw.settings {
                Some(value) => serde_json::from_value(value)
                    .map(InboundSettings::Socks)
                    .map_err(D::Error::custom),
                None => Ok(InboundSettings::Socks(socks::InSetting::default())),
            },
            "trojan" => deserialize_settings(raw.settings).map(InboundSettings::Trojan),
            "vless" => deserialize_settings(raw.settings).map(InboundSettings::Vless),
            #[cfg(feature = "tun")]
            "tun" => deserialize_settings(raw.settings).map(InboundSettings::Tun),
            "reverse" => deserialize_settings(raw.settings).map(InboundSettings::Reverse),
            other => Err(D::Error::unknown_variant(
                other,
                &["http", "socks", "trojan", "vless", "reverse"],
            )),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "protocol", content = "settings")]
pub enum OutboundSettings {
    #[serde(rename = "blackhole")]
    Black,

    #[serde(rename = "freedom")]
    Freedom,

    #[serde(rename = "socks")]
    Socks(socks::OutSetting),

    #[serde(rename = "trojan")]
    Trojan(trojan::OutSetting),

    #[serde(rename = "vless")]
    Vless(vless::OutSetting),

    #[serde(rename = "reverse")]
    Reverse(reverse::OutSetting),
}

pub struct StreamMetadata {
    pub src: Address,
    pub dst: Address,
    pub protocol: Protocol,
    pub inbound_tag: String,
}

pub struct ProxyStream {
    pub metadata: StreamMetadata,
    pub inner: transport::TrStream,
}

impl ProxyStream {
    pub fn new(prot: Protocol, src: Address, dst: Address, inner: transport::TrStream) -> Self {
        Self {
            metadata: StreamMetadata {
                src,
                dst,
                protocol: prot,
                inbound_tag: String::new(),
            },
            inner,
        }
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.metadata.inbound_tag = tag.into();
        self
    }

    pub fn dst(&self) -> &Address {
        &self.metadata.dst
    }

    pub fn into_inner(self) -> transport::TrStream {
        self.inner
    }
}

pub enum Inbounder {
    Http(http::Proxy),
    Socks(socks::Proxy),
    Trojan(trojan::Proxy),
    Vless(vless::Proxy),
    Reverse(reverse::ReversInbound),
    #[cfg(feature = "tun")]
    Tun(tun::Proxy),
}

impl Inbounder {
    pub fn new(
        set: Option<&InboundSettings>,
        sset: Option<&transport::StreamSettings>,
        dns: std::sync::Arc<crate::route::DnsResolver>,
    ) -> Result<Self> {
        let trset = match sset {
            None => &transport::StreamSettings::default(),
            Some(settings) => settings,
        };
        let tr = transport::Transport::new(trset, None, dns.clone())?;
        let inb = match set {
            None => return Err(tokio::io::Error::new(tokio::io::ErrorKind::Other, "no inbound settings".to_string())),
            Some(settings) => match settings {
                InboundSettings::Socks(s) => Inbounder::Socks(socks::Proxy::new_inbound(s, tr)?),
                InboundSettings::Http(h) => Inbounder::Http(http::Proxy::new_inbound(h, tr)?),
                InboundSettings::Trojan(t) => Inbounder::Trojan(trojan::Proxy::new_inbound(t, tr)?),
                InboundSettings::Vless(v) => Inbounder::Vless(vless::Proxy::new_inbound(v, tr)?),
                #[cfg(feature = "tun")]
                InboundSettings::Tun(t) => {
                    // TUN doesn't use transport layer
                    Inbounder::Tun(tun::Proxy::new_inbound(t, dns)?)
                }
                InboundSettings::Reverse(f) => Inbounder::Reverse(reverse::ReversInbound::new(f, tr)?),
            },
        };
        Ok(inb)
    }

    pub async fn run(self, addr: Address) -> Result<()> {
        match self {
            Inbounder::Reverse(proxy) => proxy.run(addr).await,
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "inbound should use listen() method",
            )),
        }
    }

    // start listening
    pub async fn listen(self, addr: Address) -> BoxStream<ProxyStream, std::io::Error> {
        match self {
            Inbounder::Http(proxy) => proxy.listen(addr).await,
            Inbounder::Socks(proxy) => proxy.listen(addr).await,
            Inbounder::Trojan(proxy) => proxy.listen(addr).await,
            Inbounder::Vless(proxy) => proxy.listen(addr).await,
            #[cfg(feature = "tun")]
            Inbounder::Tun(proxy) => proxy.listen(addr).await,
            _ => Box::pin(tokio_stream::once(Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "inbound uses run() method, not listen pattern",
            )))),
        }
    }
}

pub enum Outbounder {
    Socks(socks::Proxy),
    Trojan(trojan::Proxy),
    Vless(vless::Proxy),
    Reverse(reverse::ReversOutbound),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_http_inbound_without_settings_uses_defaults() {
        let json = r#"{"protocol":"http"}"#;

        let settings = serde_json::from_str::<InboundSettings>(json).unwrap();

        match settings {
            InboundSettings::Http(setting) => {
                assert!(setting.account.is_none());
                assert_eq!(setting.allow_transparent, None);
            }
            _ => panic!("expected http inbound settings"),
        }
    }

    #[test]
    fn deserialize_socks_inbound_without_settings_uses_defaults() {
        let json = r#"{"protocol":"socks"}"#;

        let settings = serde_json::from_str::<InboundSettings>(json).unwrap();

        match settings {
            InboundSettings::Socks(setting) => {
                assert!(setting.account.is_none());
                assert_eq!(setting.udp, None);
                assert_eq!(setting.ip, None);
            }
            _ => panic!("expected socks inbound settings"),
        }
    }

    #[test]
    fn deserialize_http_inbound_with_settings_still_works() {
        let json = r#"{
            "protocol":"http",
            "settings": {
                "allowTransparent": true
            }
        }"#;

        let settings = serde_json::from_str::<InboundSettings>(json).unwrap();

        match settings {
            InboundSettings::Http(setting) => {
                assert_eq!(setting.allow_transparent, Some(true));
            }
            _ => panic!("expected http inbound settings"),
        }
    }

    #[test]
    fn deserialize_socks_inbound_with_settings_still_works() {
        let json = r#"{
            "protocol":"socks",
            "settings": {
                "udp": true,
                "ip": "127.0.0.1"
            }
        }"#;

        let settings = serde_json::from_str::<InboundSettings>(json).unwrap();

        match settings {
            InboundSettings::Socks(setting) => {
                assert_eq!(setting.udp, Some(true));
                assert_eq!(setting.ip.as_deref(), Some("127.0.0.1"));
            }
            _ => panic!("expected socks inbound settings"),
        }
    }

    #[cfg(not(feature = "tun"))]
    #[test]
    fn deserialize_tun_inbound_without_feature_fails() {
        let json = r#"{
            "protocol":"tun",
            "settings": {
                "name": "tun0",
                "cidrs": ["10.0.0.1/24"]
            }
        }"#;

        let err = serde_json::from_str::<InboundSettings>(json).unwrap_err();
        assert!(err.to_string().contains("unknown variant `tun`"));
    }
}

impl Outbounder {
    pub fn new(
        set: Option<&OutboundSettings>,
        sset: Option<&transport::StreamSettings>,
        dns: std::sync::Arc<crate::route::DnsResolver>,
    ) -> std::io::Result<Self> {
        let trset = match sset {
            None => &transport::StreamSettings::default(),
            Some(settings) => settings,
        };

        let ob = match set {
            None => return Err(tokio::io::Error::new(tokio::io::ErrorKind::Other, "no outbound settings".to_string())),
            Some(OutboundSettings::Black) | Some(OutboundSettings::Freedom) => {
                return Err(tokio::io::Error::new(
                    tokio::io::ErrorKind::Other,
                    "black|free protocol should be handled at app layer".to_string(),
                ))
            }
            Some(OutboundSettings::Socks(s)) => {
                let server = Address::try_from((&s.address.as_str(), Some(s.port)))?;
                let tr = transport::Transport::new(trset, Some(server), dns.clone())?;
                Outbounder::Socks(socks::Proxy::new_outbound(s, tr)?)
            }
            Some(OutboundSettings::Trojan(s)) => {
                let server = Address::try_from((&s.address.as_str(), Some(s.port)))?;
                let tr = transport::Transport::new(trset, Some(server), dns.clone())?;
                Outbounder::Trojan(trojan::Proxy::new_outbound(s, tr, dns)?)
            }
            Some(OutboundSettings::Vless(s)) => {
                let server = Address::try_from((&s.address.as_str(), Some(s.port)))?;
                let tr = transport::Transport::new(trset, Some(server), dns.clone())?;
                Outbounder::Vless(vless::Proxy::new_outbound(s, tr, dns)?)
            }
            Some(OutboundSettings::Reverse(s)) => {
                let server = Address::try_from((&s.address.as_str(), Some(s.port)))?;
                let tr = transport::Transport::new(trset, Some(server), dns.clone())?;
                Outbounder::Reverse(reverse::ReversOutbound::new(s, tr)?)
            }
        };
        Ok(ob)
    }

    // start outbound, some daemon need
    pub async fn run(&mut self) -> Result<()> {
        match self {
            Outbounder::Reverse(proxy) => proxy.run().await,
            _ => Err(tokio::io::Error::new(tokio::io::ErrorKind::Other, "protocol not support".to_string())),
        }
    }

    /// 建立出站连接，返回已就绪的 TrStream
    pub async fn connect(&self, dst: &Address, protocol: Protocol) -> std::io::Result<TrStream> {
        match self {
            Outbounder::Socks(proxy) => proxy.connect(dst, protocol).await,
            Outbounder::Trojan(proxy) => proxy.connect(dst, protocol).await,
            Outbounder::Vless(proxy) => proxy.connect(dst, protocol).await,
            Outbounder::Reverse(_proxy) => {
                // Reverse outbound uses gRPC tunneling, not direct connect
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Reverse outbound uses run() method, not direct connect",
                ))
            }
        }
    }
}
