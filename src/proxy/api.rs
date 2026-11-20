use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
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

use crate::app::{self, ConnectionSink};
use crate::common::stats::SharedStats;
use crate::common::{Address, BoxStream, Protocol};
use crate::route::{DnsResolver, RoutingSettings, SharedRouter};

mod metrics;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InSetting {
    #[serde(default = "default_retention")]
    pub retention: String,
    #[serde(default)]
    pub token: Option<String>,
}

fn default_retention() -> String {
    "24h".into()
}

impl Default for InSetting {
    fn default() -> Self {
        Self {
            retention: default_retention(),
            token: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagementState {
    config_path: PathBuf,
    token: Arc<tokio::sync::RwLock<Option<String>>>,
    restart: tokio::sync::watch::Sender<bool>,
    dns: Arc<DnsResolver>,
}

impl ManagementState {
    pub fn new(
        config_path: PathBuf,
        token: Option<String>,
        restart: tokio::sync::watch::Sender<bool>,
        dns: Arc<DnsResolver>,
    ) -> Self {
        Self {
            config_path,
            token: Arc::new(tokio::sync::RwLock::new(token)),
            restart,
            dns,
        }
    }
}

#[derive(Debug)]
pub struct ApiInbound {
    history: Arc<tokio::sync::RwLock<metrics::History>>,
    stats: SharedStats,
    router: SharedRouter,
    sinks: Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>,
    management: ManagementState,
}

impl ApiInbound {
    pub fn new(
        settings: &InSetting,
        stats: SharedStats,
        router: SharedRouter,
        sinks: Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>,
        management: ManagementState,
    ) -> io::Result<Self> {
        Ok(Self {
            history: Arc::new(tokio::sync::RwLock::new(metrics::History::new(metrics::duration(
                &settings.retention,
            )?))),
            stats,
            router,
            sinks,
            management,
        })
    }

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
            let history = self.history.clone();
            let stats = self.stats.clone();
            let router = self.router.clone();
            let sinks = self.sinks.clone();
            let management = self.management.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    handle_request(
                        req,
                        history.clone(),
                        stats.clone(),
                        router.clone(),
                        sinks.clone(),
                        management.clone(),
                    )
                });
                if let Err(err) = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, service)
                    .await
                {
                    log::debug!("API connection error: {:?}", err);
                }
            });
        }
    }

    pub async fn listen(self, _addr: crate::common::Address) -> BoxStream<crate::proxy::ProxyStream, io::Error> {
        Box::pin(tokio_stream::empty())
    }
}

#[derive(Serialize, Deserialize)]
struct FileConfig {
    #[serde(default)]
    outbounds: Option<Vec<app::OutboundSettings>>,
    #[serde(default)]
    inbounds: Option<Vec<app::InboundSettings>>,
    #[serde(default)]
    routing: Option<RoutingSettings>,
    #[serde(default)]
    log: Option<crate::common::rslog::LogSettings>,
}

async fn handle_request(
    req: Request<Incoming>,
    history: Arc<tokio::sync::RwLock<metrics::History>>,
    stats: SharedStats,
    router: SharedRouter,
    sinks: Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>,
    management: ManagementState,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    if method == hyper::Method::GET && path == "/" {
        return Ok(text_response(
            "text/html; charset=utf-8",
            include_str!("management.html").to_string(),
        ));
    }
    if !path.starts_with("/api/v1/") {
        return Ok(json_response(StatusCode::NOT_FOUND, json!({"error":"not found"})));
    }
    let token = management.token.read().await.clone();
    if let Some(expected) = token.as_deref() {
        let authorized = req
            .headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            == Some(expected);
        if !authorized {
            return Ok(json_response(StatusCode::UNAUTHORIZED, json!({"error":"unauthorized"})));
        }
    }
    match (method.as_str(), path.as_str()) {
        ("GET", "/api/v1/config") => {
            let text = match std::fs::read_to_string(&management.config_path) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::INTERNAL_SERVER_ERROR, e)),
            };
            let value: serde_json::Value = match parse_config(&management.config_path, &text) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::INTERNAL_SERVER_ERROR, e)),
            };
            let version = config_version(text.as_bytes());
            let mut safe = value;
            let token_set = management.token.read().await.is_some();
            if let Some(item) = safe
                .get_mut("inbounds")
                .and_then(|v| v.as_array_mut())
                .and_then(|items| {
                    items
                        .iter_mut()
                        .find(|v| v.get("protocol").and_then(|p| p.as_str()) == Some("api"))
                })
            {
                if let Some(settings) = item.get_mut("settings").and_then(|v| v.as_object_mut()) {
                    settings.remove("token");
                }
            }
            Ok(json_response(
                StatusCode::OK,
                json!({"version":version,"config":safe,"token_set":token_set}),
            ))
        }
        ("PUT", "/api/v1/config") => {
            let body = match read_body(req).await {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, e)),
            };
            let request: ConfigWrite = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, e)),
            };
            let current = match std::fs::read(&management.config_path) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::INTERNAL_SERVER_ERROR, e)),
            };
            if config_version(&current) != request.expected_version {
                return Ok(json_response(
                    StatusCode::CONFLICT,
                    json!({"error":"configuration version conflict","version":config_version(&current)}),
                ));
            }
            let mut candidate = match serde_json::to_value(request.config) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, e)),
            };
            if let Some(items) = candidate.get_mut("inbounds").and_then(|v| v.as_array_mut()) {
                for item in items
                    .iter_mut()
                    .filter(|v| v.get("protocol").and_then(|p| p.as_str()) == Some("api"))
                {
                    if let Some(settings) = item.get_mut("settings").and_then(|v| v.as_object_mut()) {
                        settings.remove("token");
                    }
                }
            }
            if let Some(old_token) = parse_config(&management.config_path, std::str::from_utf8(&current).unwrap_or(""))
                .ok()
                .and_then(|v| {
                    v.get("inbounds")
                        .and_then(|v| v.as_array())
                        .and_then(|items| {
                            items
                                .iter()
                                .find(|v| v.get("protocol").and_then(|p| p.as_str()) == Some("api"))
                        })
                        .and_then(|v| v.pointer("/settings/token"))
                        .cloned()
                })
            {
                if let Some(item) = candidate
                    .get_mut("inbounds")
                    .and_then(|v| v.as_array_mut())
                    .and_then(|items| {
                        items
                            .iter_mut()
                            .find(|v| v.get("protocol").and_then(|p| p.as_str()) == Some("api"))
                    })
                {
                    item["settings"]["token"] = old_token;
                }
            }
            let serialized = match serialize_config(&management.config_path, &candidate) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, e)),
            };
            let parsed = match parse_typed_config(&management.config_path, &serialized) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, e)),
            };
            let current_value =
                parse_config(&management.config_path, std::str::from_utf8(&current).unwrap_or("")).unwrap_or_default();
            let routing_changed = current_value.get("routing") != candidate.get("routing");
            let full_restart = current_value.get("inbounds") != candidate.get("inbounds")
                || current_value.get("outbounds") != candidate.get("outbounds");
            if routing_changed {
                if let Some(routing) = parsed.routing.as_ref() {
                    let next = match routing.build_router(management.dns.clone()) {
                        Ok(v) => v,
                        Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, e)),
                    };
                    if let Some(tag) = parsed
                        .outbounds
                        .as_ref()
                        .and_then(|o| o.first())
                        .and_then(|o| o.tag.clone())
                    {
                        next.set_default(tag).await;
                    }
                    *router.write().await = next;
                }
            }
            if let Err(e) = atomic_write(&management.config_path, &serialized) {
                if routing_changed {
                    if let Some(old_routing) = current_value
                        .get("routing")
                        .and_then(|v| serde_json::from_value::<RoutingSettings>(v.clone()).ok())
                    {
                        if let Ok(previous) = old_routing.build_router(management.dns.clone()) {
                            *router.write().await = previous;
                        }
                    }
                }
                return Ok(error_response(StatusCode::INTERNAL_SERVER_ERROR, e));
            }
            Ok(json_response(
                StatusCode::OK,
                json!({"version":config_version(serialized.as_bytes()),"status":if full_restart {"pending_restart"} else {"applied"},"restart_required":full_restart}),
            ))
        }
        ("GET", "/api/v1/status") => Ok(json_response(StatusCode::OK, json!({"running":true}))),
        ("GET", "/api/v1/stats") => handle_get_stats(req, stats).await,
        ("GET", "/api/v1/metrics") => {
            let snapshot = stats.read().await.snapshot();
            Ok(text_response(
                "text/plain; version=0.0.4; charset=utf-8",
                history.read().await.prometheus(&snapshot),
            ))
        }
        ("GET", "/api/v1/metrics/history") => {
            let history = history.read().await;
            let range = url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
                .find(|(k, _)| k == "range")
                .map(|(_, v)| metrics::duration(&v))
                .unwrap_or_else(|| Ok(history.retention()));
            let range = match range {
                Ok(v) if v <= history.retention() => v,
                _ => {
                    return Ok(json_response(
                        StatusCode::BAD_REQUEST,
                        json!({"error":"invalid range or range exceeds retention"}),
                    ))
                }
            };
            let snapshot = stats.read().await.snapshot();
            Ok(json_response(
                StatusCode::OK,
                history.response(range, &snapshot, Instant::now()),
            ))
        }
        ("POST", "/api/v1/token") => {
            let body = match read_body(req).await {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, e)),
            };
            let value: TokenWrite = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, e)),
            };
            let text = match std::fs::read_to_string(&management.config_path) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::INTERNAL_SERVER_ERROR, e)),
            };
            let mut config = match parse_config(&management.config_path, &text) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::INTERNAL_SERVER_ERROR, e)),
            };
            let api_inbound = config
                .get_mut("inbounds")
                .and_then(|v| v.as_array_mut())
                .and_then(|items| {
                    items
                        .iter_mut()
                        .find(|v| v.get("protocol").and_then(|p| p.as_str()) == Some("api"))
                });
            let Some(api_inbound) = api_inbound else {
                return Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    json!({"error":"api inbound configuration is missing"}),
                ));
            };
            api_inbound["settings"]["token"] = json!(value.token);
            let text = match serialize_config(&management.config_path, &config) {
                Ok(v) => v,
                Err(e) => return Ok(error_response(StatusCode::BAD_REQUEST, e)),
            };
            if let Err(e) = parse_typed_config(&management.config_path, &text) {
                return Ok(error_response(StatusCode::BAD_REQUEST, e));
            }
            if let Err(e) = atomic_write(&management.config_path, &text) {
                return Ok(error_response(StatusCode::INTERNAL_SERVER_ERROR, e));
            }
            *management.token.write().await = value.token.clone().filter(|v| !v.is_empty());
            Ok(json_response(
                StatusCode::OK,
                json!({"token_set":management.token.read().await.is_some()}),
            ))
        }
        ("POST", "/api/v1/restart") => {
            let _ = management.restart.send(true);
            Ok(json_response(StatusCode::ACCEPTED, json!({"accepted":true})))
        }
        ("GET", "/api/v1/check") => handle_get_check(req, sinks).await,
        _ => Ok(json_response(StatusCode::NOT_FOUND, json!({"error":"not found"}))),
    }
}

#[derive(Deserialize)]
struct ConfigWrite {
    expected_version: String,
    config: serde_json::Value,
}
#[derive(Deserialize)]
struct TokenWrite {
    token: Option<String>,
}

fn parse_config(path: &std::path::Path, text: &str) -> io::Result<serde_json::Value> {
    if path.extension().is_some_and(|v| v == "json") {
        serde_json::from_str(text).map_err(io::Error::other)
    } else {
        serde_yaml::from_str::<serde_json::Value>(text).map_err(io::Error::other)
    }
}
fn parse_typed_config(path: &std::path::Path, text: &str) -> io::Result<FileConfig> {
    if path.extension().is_some_and(|v| v == "json") {
        serde_json::from_str(text).map_err(io::Error::other)
    } else {
        serde_yaml::from_str(text).map_err(io::Error::other)
    }
}
fn serialize_config(path: &std::path::Path, value: &serde_json::Value) -> io::Result<String> {
    if path.extension().is_some_and(|v| v == "json") {
        serde_json::to_string_pretty(value).map_err(io::Error::other)
    } else {
        serde_yaml::to_string(value).map_err(io::Error::other)
    }
}
fn config_version(bytes: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
fn atomic_write(path: &std::path::Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("config path has no filename"))?
        .to_string_lossy();
    let temp = parent.join(format!(".{}.{}.tmp", name, std::process::id()));
    let permissions = std::fs::metadata(path)?.permissions();
    let result = (|| {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        file.set_permissions(permissions)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
fn error_response(status: StatusCode, error: impl std::fmt::Display) -> Response<Full<Bytes>> {
    json_response(status, json!({"error":error.to_string()}))
}

async fn handle_get_stats(req: Request<Incoming>, stats: SharedStats) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let name = req.uri().query().and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "name")
            .map(|(_, v)| v.to_string())
    });
    let stats = stats.read().await;
    let response = if let Some(name) = name {
        if let Some(s) = stats.get_outbound_stats(&name) {
            json!({"name":name,"uplink":s.uplink(),"downlink":s.downlink()})
        } else {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                json!({"error":format!("outbound '{}' not found",name)}),
            ));
        }
    } else {
        let (uplink, downlink) = stats.calculate_total();
        json!({"uplink":uplink,"downlink":downlink})
    };
    Ok(json_response(StatusCode::OK, response))
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
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
async fn read_body(req: Request<Incoming>) -> io::Result<Bytes> {
    use http_body_util::BodyExt;
    Ok(req.into_body().collect().await.map_err(io::Error::other)?.to_bytes())
}

async fn handle_get_check(
    req: Request<Incoming>,
    sinks: Arc<std::collections::HashMap<String, Arc<ConnectionSink>>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let query: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
    let ob = match query.get("ob") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return Ok(json_response(StatusCode::BAD_REQUEST, json!({"error":"ob is required"}))),
    };
    let target_url = query
        .get("target")
        .filter(|v| !v.is_empty())
        .map(String::as_str)
        .unwrap_or("https://www.gstatic.com/generate_204");
    let sink = match sinks.get(&ob) {
        Some(v) => v,
        None => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                json!({"error":format!("outbound sink '{}' not found",ob)}),
            ))
        }
    };
    let target = match parse_url_to_address(target_url) {
        Some(v) => v,
        None => {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                json!({"error":format!("invalid target URL: {}",target_url)}),
            ))
        }
    };
    match probe_outbound_latency(sink, &target).await {
        Ok(ms) => Ok(json_response(
            StatusCode::OK,
            json!({"ob":ob,"target":target_url,"latency_ms":ms}),
        )),
        Err(e) => Ok(error_response(StatusCode::BAD_GATEWAY, e)),
    }
}
fn parse_url_to_address(value: &str) -> Option<Address> {
    if value.starts_with("http://") || value.starts_with("https://") {
        let url = url::Url::parse(value).ok()?;
        Address::try_from((url.host_str()?, Some(url.port_or_known_default()?))).ok()
    } else {
        let (host, port) = value.rsplit_once(':')?;
        Address::try_from((host, Some(port.parse().ok()?))).ok()
    }
}
async fn probe_outbound_latency(sink: &ConnectionSink, target: &Address) -> io::Result<u64> {
    let start = Instant::now();
    match sink {
        ConnectionSink::Proxy(proxy) => {
            let mut stream = proxy
                .try_connect(target, Protocol::Tcp)
                .await
                .map_err(io::Error::other)?;
            let host = target.to_string();
            stream
                .write_all(
                    format!("HEAD /generate_204 HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host).as_bytes(),
                )
                .await?;
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf).await;
        }
        ConnectionSink::Direct(direct) => {
            let resolved = match target {
                Address::Domain(domain, port) => {
                    let ip = direct
                        .dns
                        .resolve(domain)
                        .await
                        .map_err(io::Error::other)?
                        .first()
                        .copied()
                        .ok_or_else(|| io::Error::other("no address"))?;
                    Address::Inet(SocketAddr::new(ip, *port))
                }
                _ => target.clone(),
            };
            let _ = direct
                .transport
                .connect(&resolved, Protocol::Tcp, None)
                .await
                .map_err(io::Error::other)?;
        }
        ConnectionSink::Block => return Err(io::Error::other("blackhole outbound cannot probe")),
        ConnectionSink::Daemon(_) => return Err(io::Error::other("daemon outbound not supported for probing")),
    }
    Ok(start.elapsed().as_millis() as u64)
}
