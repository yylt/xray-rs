use clap;
use std::{collections::HashMap, fs, io, sync::Arc};

use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;

use crate::{
    app::{self, ConnectionSink},
    common::stats,
    proxy::{self},
    route::{DnsResolver, DnsSettings, Router, RoutingSettings},
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

/// 构建并启动代理服务的主入口函数
async fn run_proxy(config: Config) -> io::Result<()> {
    log::info!("Starting xray-rs proxy");

    let Config {
        outbounds,
        inbounds,
        routing,
        dns,
    } = config;

    // Phase 1: 初始化 DNS resolver
    let dns = init_dns_resolver(dns).await?;

    // Phase 2: 初始化 stats collector
    let stats = stats::create_shared_stats();

    // Phase 3: 构建 outbound sinks
    let (sinks, _outbound_tags, mut handles, first_tag) =
        build_outbound_sinks(outbounds, dns.clone(), stats.clone()).await?;

    // Phase 4: 构建 router
    let router = build_router(routing, first_tag, dns.clone()).await?;

    // Phase 5: 构建并启动 inbounds
    if let Some(inbounds) = inbounds {
        start_inbounds(inbounds, sinks, router, stats, dns, &mut handles).await?;
    }

    // Phase 6: 等待所有任务完成
    wait_for_completion(handles).await;
    Ok(())
}

/// Phase 1: 初始化 DNS resolver
async fn init_dns_resolver(dns: Option<DnsSettings>) -> io::Result<Arc<DnsResolver>> {
    let (dns_settings, has_dns_config) = match dns {
        Some(dns_settings) => (dns_settings, true),
        None => (DnsSettings::default(), false),
    };

    if has_dns_config {
        log::info!("Initializing DNS resolver with config");
    } else {
        log::info!("No DNS config, using system resolver");
    }

    Ok(Arc::new(DnsResolver::new(dns_settings)?))
}

/// Phase 3: 构建 outbound sinks
/// 返回: (sinks, outbound_tags, daemon_handles, first_tag)
async fn build_outbound_sinks(
    outbounds: Option<Vec<app::OutboundSettings>>,
    dns: Arc<DnsResolver>,
    stats: stats::SharedStats,
) -> io::Result<(
    Arc<HashMap<String, Arc<ConnectionSink>>>,
    Vec<String>,
    Vec<tokio::task::JoinHandle<()>>,
    Option<String>,
)> {
    let mut sinks_builder: HashMap<String, Arc<ConnectionSink>> = HashMap::new();
    let mut handles = vec![];
    let mut first_tag = None;
    let mut proxy_counter = 1;
    let mut outbound_tags: Vec<String> = Vec::new();

    if let Some(outbounds) = outbounds {
        log::info!("Building {} outbound(s)", outbounds.len());
        for ob_set in outbounds {
            let tag = ob_set.tag.clone().unwrap_or_else(|| match &ob_set.settings {
                Some(proxy::OutboundSettings::Freedom) | None => "freedom".to_string(),
                Some(proxy::OutboundSettings::Black) => "black".to_string(),
                _ => {
                    let t = format!("proxy-{}", proxy_counter);
                    proxy_counter += 1;
                    t
                }
            });

            log::info!("[{}] Building outbound sink", tag);
            if first_tag.is_none() {
                first_tag = Some(tag.clone());
            }

            // Register outbound for stats tracking (skip blackhole and direct)
            let needs_stats = !matches!(ob_set.settings.as_ref(), Some(proxy::OutboundSettings::Black));

            if needs_stats {
                outbound_tags.push(tag.clone());
                let mut stats_guard = stats.write().await;
                stats_guard.register_outbound(&tag);
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
                sinks_builder.insert(tag, Arc::new(sink));
            }
        }
    }

    let sinks: Arc<HashMap<String, Arc<ConnectionSink>>> = Arc::new(sinks_builder);
    Ok((sinks, outbound_tags, handles, first_tag))
}

/// Phase 4: 构建 router
async fn build_router(
    routing: Option<RoutingSettings>,
    first_tag: Option<String>,
    dns: Arc<DnsResolver>,
) -> io::Result<Arc<tokio::sync::RwLock<Router>>> {
    let router = match routing {
        Some(rs) => {
            let router = rs.build_router(dns)?;
            if let Some(tag) = first_tag {
                router.set_default(tag).await;
            }
            tokio::sync::RwLock::new(router)
        }
        None => {
            let router = Router::new();
            if let Some(tag) = first_tag {
                router.set_default(tag).await;
            }
            tokio::sync::RwLock::new(router)
        }
    };

    Ok(Arc::new(router))
}

/// Phase 5: 启动 inbound 服务
async fn start_inbounds(
    inbounds: Vec<app::InboundSettings>,
    sinks: Arc<HashMap<String, Arc<ConnectionSink>>>,
    router: Arc<tokio::sync::RwLock<Router>>,
    stats: stats::SharedStats,
    dns: Arc<DnsResolver>,
    handles: &mut Vec<tokio::task::JoinHandle<()>>,
) -> io::Result<()> {
    log::info!("Starting {} inbounds", inbounds.len());

    for ib_set in inbounds {
        let tag = ib_set.tag.clone().unwrap_or_else(|| "in".into());
        let is_api = matches!(ib_set.settings.as_ref(), Some(proxy::InboundSettings::Api(_)));

        let source = if is_api {
            ib_set.build_source_with_deps(
                dns.clone(),
                Some(stats.clone()),
                Some(router.clone()),
                Some(sinks.clone()),
            )?
        } else {
            ib_set.build_source(dns.clone(), Some(sinks.clone()))?
        };

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
            let stats = stats.clone();
            let handle = tokio::spawn(async move {
                let mut stream = source.run_listen().await.unwrap();
                while let Some(result) = stream.next().await {
                    match result {
                        Err(e) => log::error!("listener error: {}", e),
                        Ok(proxy_stream) => {
                            let sinks = sinks.clone();
                            let router = router.clone();
                            let stats = stats.clone();
                            tokio::spawn(handle_proxy_stream(proxy_stream, sinks, router, stats));
                        }
                    }
                }
            });
            handles.push(handle);
        }
    }

    Ok(())
}

/// 处理单个代理连接流
async fn handle_proxy_stream(
    proxy_stream: crate::proxy::ProxyStream,
    sinks: Arc<HashMap<String, Arc<ConnectionSink>>>,
    router: Arc<tokio::sync::RwLock<Router>>,
    stats: stats::SharedStats,
) {
    // Perform routing
    let routing_result = router.read().await.route(&proxy_stream).await;

    if let Some(result) = routing_result {
        log::info!(
            "{} to {} [{} -> {}]",
            proxy_stream.metadata.src,
            proxy_stream.metadata.dst,
            proxy_stream.metadata.inbound_tag,
            result.primary_tag
        );

        let tags_to_try = std::iter::once(&result.primary_tag).chain(result.fallback_tags.iter());
        let mut stream = Some(proxy_stream);

        for tag in tags_to_try {
            let current_stream = match stream.take() {
                Some(stream) => stream,
                None => return,
            };

            let Some(sink) = sinks.get(tag) else {
                stream = Some(current_stream);
                continue;
            };

            match sink.as_ref() {
                app::ConnectionSink::Proxy(proxy_sink) => match proxy_sink.handle(current_stream).await {
                    Ok(Some(next_stream)) => {
                        stream = Some(next_stream);
                    }
                    Ok(None) => return,
                    Err(e) => {
                        log::error!("handler failed: {:?}", e);
                        return;
                    }
                },
                _ => {
                    let _ = sink.handle(current_stream).await;
                    return;
                }
            }
        }

        if stream.is_some() {
            log::error!("[Routing] All outbound tags failed");
        }
    } else {
        log::error!("[Routing] No route found");
    }
}

/// Phase 6: 等待所有任务完成
async fn wait_for_completion(handles: Vec<tokio::task::JoinHandle<()>>) {
    for h in handles {
        let _ = h.await;
    }
}
