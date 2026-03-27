use ahash::RandomState;
use clap;
use std::{collections::HashMap, fs, io, sync::Arc};

use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;

use crate::{
    app::{self, ConnectionSink},
    common::forward::StreamForwarder,
    proxy::{self},
    route::{DnsResolver, DnsSettings, RoutingSettings},
};

#[derive(Debug, clap::Args)]
pub struct Run {
    #[arg(short, long, value_name = "config filepath", default_value = "config.yaml")]
    config: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    #[serde(rename = "outbounds")]
    outbounds: Option<Vec<app::OutboundSettings>>,

    #[serde(rename = "inbounds")]
    inbounds: Option<Vec<app::InboundSettings>>,

    #[serde(rename = "routing")]
    routing: Option<RoutingSettings>,

    #[serde(rename = "dns")]
    dns: Option<DnsSettings>,
}

impl Run {
    pub fn run(&self) -> io::Result<()> {
        let f = fs::File::open(&self.config)?;
        let config: Config = match &self.config {
            s if s.ends_with(".json") => serde_json::from_reader(f)?,
            s if s.ends_with(".yaml") || s.ends_with(".yml") => {
                serde_yaml::from_reader(f).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            }
            _ => return Err(io::Error::new(io::ErrorKind::Other, "unsupported config format")),
        };

        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

        rt.block_on(run_proxy(config))
    }
}

async fn run_proxy(config: Config) -> io::Result<()> {
    log::info!("Starting xray-rs proxy");

    let Config {
        outbounds,
        inbounds,
        routing,
        dns,
    } = config;

    // 1. DNS resolver
    let (dns_settings, has_dns_config) = match dns {
        Some(dns_settings) => (dns_settings, true),
        None => (DnsSettings::default(), false),
    };
    let dns = {
        if has_dns_config {
            log::info!("Initializing DNS resolver with config");
        } else {
            log::info!("No DNS config, using system resolver");
        }
        Arc::new(DnsResolver::new(dns_settings)?)
    };

    // 2. Build outbound sinks
    let mut sinks: HashMap<String, Arc<ConnectionSink>, RandomState> = HashMap::with_hasher(RandomState::new());
    let mut handles = vec![];
    let mut first_tag = None;
    let mut proxy_counter = 1;

    if let Some(outbounds) = outbounds {
        log::info!("Building {} outbound(s)", outbounds.len());
        for ob_set in outbounds {
            let tag = ob_set.tag.clone().unwrap_or_else(|| match &ob_set.settings {
                Some(proxy::OutboundSettings::Freedom) | None => "freedom".to_string(),
                Some(proxy::OutboundSettings::Black) => "black".to_string(),
                _ => {
                    let t = format!("proxy{}", proxy_counter);
                    proxy_counter += 1;
                    t
                }
            });

            log::info!("[{}] Building outbound sink", tag);
            if first_tag.is_none() {
                first_tag = Some(tag.clone());
            }
            let sink = ob_set.build_sink(dns.clone())?;

            if sink.is_daemon() {
                log::info!("[{}] Starting daemon outbound", tag);
                let handle = tokio::spawn(async move {
                    if let ConnectionSink::Daemon(ds) = sink {
                        if let Err(e) = ds.run().await {
                            log::error!("[{}] daemon sink exited: {}", tag, e);
                        }
                    }
                });
                handles.push(handle);
            } else {
                sinks.insert(tag, Arc::new(sink));
            }
        }
    }

    // 3. Build router
    let router = Arc::new(match routing {
        Some(rs) => {
            let mut router = rs.build_router(dns.clone())?;
            if let Some(tag) = first_tag {
                router.set_default(tag);
            }
            router
        }
        None => {
            let mut router = crate::route::router::Router::new();
            if let Some(tag) = first_tag {
                router.set_default(tag);
            }
            router
        }
    });

    // 4. Build and start inbounds
    if let Some(inbounds) = inbounds {
        log::info!("Starting {} inbounds", inbounds.len());
        for ib_set in inbounds {
            let tag = ib_set.tag.clone().unwrap_or_else(|| "in".into());
            let source = ib_set.build_source(dns.clone())?;

            if source.is_daemon() {
                log::debug!("[{}] Starting daemon inbound", tag);
                let handle = tokio::spawn(async move {
                    if let Err(e) = source.run_daemon().await {
                        log::error!("[{}] daemon source exited: {}", tag, e);
                    }
                });
                handles.push(handle);
            } else {
                let sinks = sinks.clone();
                let router = router.clone();
                let forwarder = Arc::new(StreamForwarder::new());

                let handle = tokio::spawn(async move {
                    let mut stream = source.run_listen().await.unwrap();
                    while let Some(result) = stream.next().await {
                        match result {
                            Err(e) => log::error!("listener error: {}", e),
                            Ok(proxy_stream) => {
                                let sinks = sinks.clone();
                                let router = router.clone();
                                let forwarder = forwarder.clone();
                                tokio::spawn(async move {
                                    if let Some(result) = router.route(&proxy_stream).await {
                                        log::info!(
                                            "{} to {} [{} -> {}]",
                                            proxy_stream.metadata.src,
                                            proxy_stream.metadata.dst,
                                            proxy_stream.metadata.inbound_tag,
                                            result.primary_tag
                                        );

                                        let mut tags_to_try = vec![result.primary_tag.clone()];
                                        tags_to_try.extend(result.fallback_tags.clone());

                                        let dst = proxy_stream.metadata.dst.clone();

                                        for (_idx, tag) in tags_to_try.iter().enumerate() {
                                            if let Some(sink) = sinks.get(tag) {
                                                match sink.as_ref() {
                                                    app::ConnectionSink::Proxy(proxy_sink) => {
                                                        match proxy_sink
                                                            .try_connect(&dst, proxy_stream.metadata.protocol.clone())
                                                            .await
                                                        {
                                                            Ok(connected) => {
                                                                let _ = forwarder
                                                                    .forward(proxy_stream.inner, connected)
                                                                    .await;
                                                                return;
                                                            }
                                                            Err(_e) => {
                                                                continue;
                                                            }
                                                        }
                                                    }
                                                    _ => {
                                                        let _ = sink.handle(proxy_stream, forwarder.as_ref()).await;
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        log::error!("[Routing] No route found");
                                    }
                                });
                            }
                        }
                    }
                });
                handles.push(handle);
            }
        }
    }

    // 5. Wait for all tasks
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}
