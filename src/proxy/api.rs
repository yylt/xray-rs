use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::app::ConnectionSink;
use crate::common::stats::SharedStats;
use crate::common::{Address, BoxStream, Protocol};
use crate::route::SharedRouter;

mod metrics;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InSetting {
    #[serde(default = "default_retention")]
    pub retention: String,
}

fn default_retention() -> String {
    "24h".into()
}

impl Default for InSetting {
    fn default() -> Self {
        Self {
            retention: default_retention(),
        }
    }
}

#[derive(Debug)]
pub struct ApiInbound {
    history: Arc<tokio::sync::RwLock<metrics::History>>,
    stats: SharedStats,
    router: SharedRouter,
    sinks: Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>, // outbound sinks for probing
}

impl ApiInbound {
    pub fn new(
        settings: &InSetting,
        stats: SharedStats,
        router: SharedRouter,
        sinks: Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>,
    ) -> io::Result<Self> {
        Ok(Self {
            history: Arc::new(tokio::sync::RwLock::new(metrics::History::new(metrics::duration(
                &settings.retention,
            )?))),
            stats,
            router,
            sinks,
        })
    }

    /// Run the API server (daemon mode)
    pub async fn run(self, addr: SocketAddr) -> io::Result<()> {
        let listener = crate::transport::bind_tcp_listener(addr)?;
        log::info!("API server listening on {}", addr);

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(metrics::SAMPLE_SECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let (stream, peer_addr) = tokio::select! {
                _ = interval.tick() => {
                    let snapshot = self.stats.read().await.snapshot();
                    self.history.write().await.sample(snapshot, Instant::now(), metrics::timestamp_ms(), metrics::resident_memory());
                    continue;
                }
                accepted = listener.accept() => accepted?,
            };
            if let Err(e) = stream.set_nodelay(true) {
                log::error!("Failed to set TCP_NODELAY for {}: {}", peer_addr, e);
                continue;
            }
            let io = hyper_util::rt::TokioIo::new(stream);

            // Create service function for this connection
            let history = self.history.clone();
            let stats = self.stats.clone();
            let router = self.router.clone();
            let sinks = self.sinks.clone();

            tokio::spawn(async move {
                let service_fn = service_fn(move |req| {
                    let history = history.clone();
                    let stats = stats.clone();
                    let router = router.clone();
                    let sinks = sinks.clone();
                    async move { handle_request(req, history, stats, router, sinks).await }
                });
                if let Err(err) = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, service_fn)
                    .await
                {
                    log::debug!("API connection error: {:?}", err);
                }
            });
        }
    }

    /// Listen for API connections (not used, api is daemon mode)
    pub async fn listen(self, _addr: crate::common::Address) -> BoxStream<crate::proxy::ProxyStream, io::Error> {
        Box::pin(tokio_stream::empty())
    }
}

async fn handle_request(
    req: Request<Incoming>,
    history: Arc<tokio::sync::RwLock<metrics::History>>,
    stats: SharedStats,
    router: SharedRouter,
    sinks: Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path();

    match (method.as_str(), path) {
        ("GET", "/") => Ok(text_response(
            "text/html; charset=utf-8",
            include_str!("metrics.html").to_string(),
        )),
        ("GET", "/metrics") => {
            let snapshot = stats.read().await.snapshot();
            Ok(text_response(
                "text/plain; version=0.0.4; charset=utf-8",
                history.read().await.prometheus(&snapshot),
            ))
        }
        ("GET", "/metrics/history") => {
            let history = history.read().await;
            let range = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
                .find(|(key, _)| key == "range")
                .map(|(_, value)| metrics::duration(&value))
                .unwrap_or_else(|| Ok(history.retention()));
            let range = match range {
                Ok(range) if range <= history.retention() => range,
                _ => {
                    return Ok(json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error": "invalid range or range exceeds retention"}),
                    ))
                }
            };
            let snapshot = stats.read().await.snapshot();
            Ok(json_response(
                StatusCode::OK,
                history.response(range, &snapshot, Instant::now()),
            ))
        }
        ("GET", "/stats") => handle_get_stats(req, stats).await,
        ("POST", "/handler") => handle_post_handler(req, router, sinks).await,
        ("GET", "/check") => handle_get_check(req, sinks).await,
        _ => Ok(json_response(StatusCode::NOT_FOUND, json!({"error": "not found"}))),
    }
}

async fn handle_get_stats(req: Request<Incoming>, stats: SharedStats) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let name: Option<String> = req.uri().query().and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "name")
            .map(|(_, v)| v.to_string())
    });

    let stats = stats.read().await;

    let response = if let Some(name) = name {
        // Per-outbound stats
        if let Some(outbound_stats) = stats.get_outbound_stats(&name) {
            json!({
                "name": name,
                "uplink": outbound_stats.uplink(),
                "downlink": outbound_stats.downlink(),
            })
        } else {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                json!({"error": format!("outbound '{}' not found", name)}),
            ));
        }
    } else {
        // Global total stats
        let (uplink, downlink) = stats.calculate_total();
        json!({
            "uplink": uplink,
            "downlink": downlink,
        })
    };

    Ok(json_response(StatusCode::OK, response))
}

async fn handle_post_handler(
    req: Request<Incoming>,
    router: SharedRouter,
    sinks: Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let body = match read_body(req).await {
        Ok(body) => body,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("failed to read body: {}", e)}),
            ));
        }
    };

    let request: HandlerRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("invalid json: {}", e)}),
            ));
        }
    };

    match sinks.get(&request.tag) {
        Some(_) => {
            // tag exists, proceed
        }
        None => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("outbound tag '{}' not found", request.tag)}),
            ));
        }
    };

    // Update default route
    router.write().await.set_default(request.tag.clone()).await;

    Ok(json_response(
        StatusCode::OK,
        json!({
            "current": request.tag,
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct HandlerRequest {
    tag: String,
}

fn text_response(content_type: &str, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    let body_bytes = Bytes::from(body.to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Full::new(body_bytes))
        .unwrap()
}

async fn read_body(req: Request<Incoming>) -> io::Result<Bytes> {
    use http_body_util::BodyExt;
    let body = req.into_body();

    let collected = body.collect().await.map_err(io::Error::other)?;
    Ok(collected.to_bytes())
}

async fn handle_get_check(
    req: Request<Incoming>,
    sinks: Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Parse query parameters
    let query_str = req.uri().query().unwrap_or("");
    let query_params: std::collections::HashMap<String, String> = url::form_urlencoded::parse(query_str.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Validate ob parameter
    let ob = match query_params.get("ob") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => {
            return Ok(json_response(StatusCode::BAD_REQUEST, json!({"error": "ob is required"})));
        }
    };

    // Get target URL with default
    let default_target = "https://www.gstatic.com/generate_204";
    let target = query_params.get("target").filter(|v| !v.is_empty()).cloned();
    let target_url = target.as_deref().unwrap_or(default_target);

    // Get the sink for this outbound
    let sink = match sinks.get(&ob) {
        Some(s) => s,
        None => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("outbound sink '{}' not found", ob)}),
            ));
        }
    };

    // Parse target URL
    let target_addr = match parse_url_to_address(target_url) {
        Some(addr) => addr,
        None => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("invalid target URL: {}", target_url)}),
            ));
        }
    };

    // Perform latency check
    let latency_ms = match probe_outbound_latency(sink, &target_addr).await {
        Ok(ms) => ms,
        Err(e) => {
            return Ok(json_response(
                StatusCode::BAD_GATEWAY,
                json!({"error": format!("probe failed: {}", e)}),
            ));
        }
    };

    // Return success response
    Ok(json_response(
        StatusCode::OK,
        json!({
            "ob": ob,
            "target": target_url,
            "latency_ms": latency_ms,
        }),
    ))
}

/// Parse a URL string to Address
fn parse_url_to_address(url_str: &str) -> Option<Address> {
    // Handle http:// or https:// URLs
    if url_str.starts_with("http://") || url_str.starts_with("https://") {
        let url = url::Url::parse(url_str).ok()?;
        let host = url.host_str()?;
        let port = url.port_or_known_default()?;
        Address::try_from((host, Some(port))).ok()
    } else {
        // Try to parse as host:port directly
        let parts: Vec<&str> = url_str.split(':').collect();
        if parts.len() == 2 {
            let host = parts[0];
            let port: u16 = parts[1].parse().ok()?;
            Address::try_from((host, Some(port))).ok()
        } else {
            None
        }
    }
}

/// Probe latency through an outbound
async fn probe_outbound_latency(sink: &ConnectionSink, target: &Address) -> io::Result<u64> {
    let start = Instant::now();

    match sink {
        ConnectionSink::Proxy(proxy_sink) => {
            // Use the outbound proxy to connect
            let mut stream = proxy_sink
                .try_connect(target, Protocol::Tcp)
                .await
                .map_err(|e| io::Error::other(format!("connect failed: {}", e)))?;

            // Send a simple HTTP request to get latency
            let http_req = format!("HEAD /generate_204 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", target);

            stream
                .write_all(http_req.as_bytes())
                .await
                .map_err(|e| io::Error::other(format!("write failed: {}", e)))?;

            // Read response to ensure connection works
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf).await;
        }
        ConnectionSink::Direct(direct_sink) => {
            // Direct connection using transport
            let dst = target.clone();
            let resolved = match &dst {
                Address::Domain(domain, port) => {
                    let ips = direct_sink
                        .dns
                        .resolve(domain)
                        .await
                        .map_err(|e| io::Error::other(format!("dns resolve failed: {}", e)))?;
                    let ip = ips
                        .first()
                        .ok_or_else(|| io::Error::other(format!("no address for {}", domain)))?;
                    Address::Inet(std::net::SocketAddr::new(*ip, *port))
                }
                _ => dst.clone(),
            };
            let _stream = direct_sink
                .transport
                .connect(&resolved, Protocol::Tcp, None)
                .await
                .map_err(|e| io::Error::other(format!("connect failed: {}", e)))?;

            // Note: DirectSink connects directly, so we just measure connection time
            // For a more accurate measurement, we'd need to send data
        }
        ConnectionSink::Block => {
            return Err(io::Error::other("blackhole outbound cannot probe"));
        }
        ConnectionSink::Daemon(_) => {
            return Err(io::Error::other("daemon outbound not supported for probing"));
        }
    }

    let elapsed = start.elapsed();
    Ok(elapsed.as_millis() as u64)
}
