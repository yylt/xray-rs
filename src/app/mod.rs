pub mod sink;
pub mod source;

pub use sink::{ConnectionSink, DaemonSink, DirectSink, ProxySink};
pub use source::{ConnectionSource, DaemonSource, ListenSource};

use crate::{common::*, proxy, route::DnsResolver, transport};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::common::stats::SharedStats;
use crate::route::SharedRouter;

#[derive(Serialize, Deserialize, Debug)]
pub struct InboundSettings {
    pub listen: String,
    pub port: Option<u16>,

    #[serde(flatten)]
    pub settings: Option<proxy::InboundSettings>,

    pub tag: Option<String>,

    #[serde(rename = "streamSettings", default)]
    pub stream_settings: Option<transport::StreamSettings>,
}

impl InboundSettings {
    pub fn build_source(
        self,
        dns: Arc<DnsResolver>,
        sinks: Option<Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>>,
    ) -> std::io::Result<ConnectionSource> {
        self.build_source_with_deps(dns, None, None, sinks)
    }

    /// Build source with additional dependencies for special inbounds like API
    pub fn build_source_with_deps(
        self,
        dns: Arc<DnsResolver>,
        stats: Option<SharedStats>,
        router: Option<SharedRouter>,
        sinks: Option<Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>>,
    ) -> std::io::Result<ConnectionSource> {
        let tag = self.tag.clone().unwrap_or_else(|| "in".into());
        let listen_addr = Address::try_from((&self.listen, self.port))?;

        match self.settings.as_ref() {
            Some(proxy::InboundSettings::Api(_)) => {
                let inbounder = proxy::Inbounder::new_with_deps(
                    self.settings.as_ref(),
                    self.stream_settings.as_ref(),
                    dns,
                    stats,
                    router,
                    sinks,
                )?;
                Ok(ConnectionSource::Daemon(DaemonSource { inbounder, listen_addr }))
            }
            Some(proxy::InboundSettings::Reverse(_)) => {
                let inbounder = proxy::Inbounder::new(self.settings.as_ref(), self.stream_settings.as_ref(), dns)?;
                Ok(ConnectionSource::Daemon(DaemonSource { inbounder, listen_addr }))
            }
            Some(settings) => {
                let inbounder = proxy::Inbounder::new(Some(settings), self.stream_settings.as_ref(), dns)?;
                Ok(ConnectionSource::Listen(ListenSource {
                    tag,
                    inbounder,
                    listen_addr,
                }))
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "inbound settings missing",
            )),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OutboundSettings {
    #[serde(flatten)]
    pub settings: Option<proxy::OutboundSettings>,

    pub tag: Option<String>,

    #[serde(rename = "streamSettings", default)]
    pub stream_settings: Option<transport::StreamSettings>,
}

impl OutboundSettings {
    pub fn build_sink(self, dns: Arc<DnsResolver>) -> std::io::Result<ConnectionSink> {
        let sink = match &self.settings {
            Some(proxy::OutboundSettings::Black) => ConnectionSink::Block,
            Some(proxy::OutboundSettings::Freedom) | None => {
                let tr = transport::Transport::new(
                    self.stream_settings
                        .as_ref()
                        .unwrap_or(&transport::StreamSettings::default()),
                    None,
                    dns.clone(),
                )?;
                ConnectionSink::Direct(DirectSink { dns, transport: tr })
            }
            Some(proxy::OutboundSettings::Reverse(_)) => {
                let outbounder = proxy::Outbounder::new(self.settings.as_ref(), self.stream_settings.as_ref(), dns)?;
                ConnectionSink::Daemon(DaemonSink { outbounder })
            }
            Some(settings) => {
                let outbounder = proxy::Outbounder::new(Some(settings), self.stream_settings.as_ref(), dns)?;
                ConnectionSink::Proxy(ProxySink { outbounder })
            }
        };
        Ok(sink)
    }
}
