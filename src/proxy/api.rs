use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(all(target_os = "linux", feature = "profiling"))]
use std::time::Duration;
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
use tokio::net::TcpListener;

use crate::app::ConnectionSink;
use crate::common::stats::SharedStats;
use crate::common::{Address, BoxStream, Protocol};
use crate::route::SharedRouter;

// Profiling handlers - only on Linux
#[cfg(all(target_os = "linux", feature = "profiling"))]
mod profiling {
    use super::*;

    /// Query parameters for profiling endpoints
    #[derive(Debug, Deserialize)]
    pub struct ProfilingQuery {
        #[serde(default = "default_seconds")]
        pub seconds: u64,
    }

    fn default_seconds() -> u64 {
        10
    }

    impl ProfilingQuery {
        /// Parse query string and validate seconds parameter
        pub fn from_query(query: Option<&str>) -> Result<Self, String> {
            let query_str = query.unwrap_or("");
            let params: std::collections::HashMap<String, String> = url::form_urlencoded::parse(query_str.as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            let seconds = params
                .get("seconds")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or_else(default_seconds);

            // Validate bounds: 0 < seconds <= 300 (5 minutes max)
            if seconds == 0 {
                return Err("seconds must be greater than 0".to_string());
            }
            if seconds > 300 {
                return Err("seconds must not exceed 300".to_string());
            }

            Ok(Self { seconds })
        }
    }

    /// Binary response helper for profile data
    fn binary_response(status: StatusCode, body: Bytes, filename: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Disposition", format!("attachment; filename=\"{}\"", filename))
            .body(Full::new(body))
            .unwrap()
    }

    fn encode_profile(profile: pprof::protos::Profile) -> Vec<u8> {
        use pprof::protos::Message;
        let mut buf = Vec::new();
        profile.encode(&mut buf).unwrap_or_default();
        buf
    }

    /// CPU profile handler using pprof
    pub async fn handle_pprof_cpu(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let query = match ProfilingQuery::from_query(req.uri().query()) {
            Ok(q) => q,
            Err(e) => {
                return Ok(super::json_response(StatusCode::BAD_REQUEST, json!({"error": e})));
            }
        };

        // Create pprof profiler
        let guard = pprof::ProfilerGuardBuilder::default()
            .frequency(100) // 100 Hz sampling
            .blocklist(&["libc", "libgcc", "ld-linux"])
            .build();

        let guard = match guard {
            Ok(g) => g,
            Err(e) => {
                return Ok(super::json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": format!("failed to start profiler: {}", e)}),
                ));
            }
        };

        // Wait for sampling duration
        tokio::time::sleep(Duration::from_secs(query.seconds)).await;

        // Generate protobuf profile
        match guard.report().build() {
            Ok(report) => match report.pprof() {
                Ok(profile) => {
                    let profile_bytes = encode_profile(profile);
                    Ok(binary_response(StatusCode::OK, Bytes::from(profile_bytes), "profile.pb"))
                }
                Err(e) => Ok(super::json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": format!("failed to generate profile: {}", e)}),
                )),
            },
            Err(e) => Ok(super::json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("failed to build report: {}", e)}),
            )),
        }
    }

    /// Memory profile handler using jemalloc
    /// MALLOC_CONF="prof:true,prof_active:true" ./binary start
    pub async fn handle_prof_mem(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        #[cfg(all(feature = "jemalloc", feature = "profiling"))]
        {
            use std::ffi::CString;

            // Get query parameters
            let query = match ProfilingQuery::from_query(req.uri().query()) {
                Ok(q) => q,
                Err(e) => {
                    return Ok(super::json_response(StatusCode::BAD_REQUEST, json!({"error": e})));
                }
            };

            // Wait for sampling window
            tokio::time::sleep(Duration::from_secs(query.seconds)).await;

            // Trigger memory profiling dump
            let temp_path = format!("/tmp/jemalloc_profile_{}.prof", std::process::id());

            // Use raw mallctl to dump the heap profile
            let cmd = CString::new(format!("prof.dump,{}", temp_path)).unwrap();

            unsafe {
                let ret = tikv_jemalloc_sys::mallctl(
                    cmd.as_ptr() as *const i8,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                );
                if ret != 0 {
                    return Ok(super::json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"error": format!("jemalloc dump failed with code: {}", ret)}),
                    ));
                }
            }

            // Read the dump file
            match tokio::fs::read(&temp_path).await {
                Ok(data) => {
                    // Clean up temp file
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    Ok(binary_response(StatusCode::OK, Bytes::from(data), "profile.pb"))
                }
                Err(e) => {
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    Ok(super::json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"error": format!("failed to read profile: {}", e)}),
                    ))
                }
            }
        }

        #[cfg(not(all(feature = "jemalloc", feature = "profiling")))]
        {
            Ok(super::json_response(
                StatusCode::NOT_IMPLEMENTED,
                json!({"error": "jemalloc and profiling features required"}),
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InSetting {
    /// Optional authentication token for API access
    pub token: Option<String>,
}

#[derive(Debug)]
pub struct ApiInbound {
    settings: InSetting,
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
            settings: settings.clone(),
            stats,
            router,
            sinks,
        })
    }

    /// Run the API server (daemon mode)
    pub async fn run(self, addr: SocketAddr) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        log::info!("API server listening on {}", addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let io = hyper_util::rt::TokioIo::new(stream);

            // Create service function for this connection
            let settings = self.settings.clone();
            let stats = self.stats.clone();
            let router = self.router.clone();
            let sinks = self.sinks.clone();

            tokio::spawn(async move {
                let service_fn = service_fn(move |req| {
                    let settings = settings.clone();
                    let stats = stats.clone();
                    let router = router.clone();
                    let sinks = sinks.clone();
                    async move { handle_request(req, settings, stats, router, sinks).await }
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
    settings: InSetting,
    stats: SharedStats,
    router: SharedRouter,
    sinks: Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Check auth token if configured
    if let Some(ref token) = settings.token {
        let header_token = req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));

        if header_token != Some(token.as_str()) {
            return Ok(json_response(StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"})));
        }
    }

    let method = req.method().clone();
    let path = req.uri().path();

    match (method.as_str(), path) {
        ("GET", "/stats") => handle_get_stats(req, stats).await,
        ("POST", "/handler") => handle_post_handler(req, router, sinks).await,
        ("GET", "/check") => handle_get_check(req, sinks).await,
        // Profiling endpoints - Linux only
        #[cfg(all(target_os = "linux", feature = "profiling"))]
        ("GET", "/pprof/cpu") => profiling::handle_pprof_cpu(req).await,
        #[cfg(all(target_os = "linux", feature = "profiling"))]
        ("GET", "/prof/mem") => profiling::handle_prof_mem(req).await,
        #[cfg(not(all(target_os = "linux", feature = "profiling")))]
        ("GET", "/pprof/cpu") | ("GET", "/prof/mem") => Ok(json_response(
            StatusCode::NOT_IMPLEMENTED,
            json!({"error": "profiling only supported on Linux with profiling feature enabled"}),
        )),
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

    let _sink = match sinks.get(&request.tag) {
        Some(_sink) => (),
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

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    let body_bytes = Bytes::from(body.to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(body_bytes))
        .unwrap()
}

async fn read_body(req: Request<Incoming>) -> io::Result<Bytes> {
    use http_body_util::BodyExt;
    let body = req.into_body();

    let collected = body
        .collect()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
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
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("connect failed: {}", e)))?;

            // Send a simple HTTP request to get latency
            let http_req = format!("HEAD /generate_204 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", target);

            stream
                .write_all(http_req.as_bytes())
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("write failed: {}", e)))?;

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
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("dns resolve failed: {}", e)))?;
                    let ip = ips
                        .first()
                        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, format!("no address for {}", domain)))?;
                    Address::Inet(std::net::SocketAddr::new(*ip, *port))
                }
                _ => dst.clone(),
            };
            let _stream = direct_sink
                .transport
                .connect(&resolved, Protocol::Tcp, None)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("connect failed: {}", e)))?;

            // Note: DirectSink connects directly, so we just measure connection time
            // For a more accurate measurement, we'd need to send data
        }
        ConnectionSink::Block => {
            return Err(io::Error::new(io::ErrorKind::Other, "blackhole outbound cannot probe"));
        }
        ConnectionSink::Daemon(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "daemon outbound not supported for probing",
            ));
        }
    }

    let elapsed = start.elapsed();
    Ok(elapsed.as_millis() as u64)
}
