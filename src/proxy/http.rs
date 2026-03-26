use super::*;
use crate::common::parse;

const MAX_HEADERS: usize = 64;
const BUFFER_SIZE: usize = 8192;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InSetting {
    #[serde(rename = "account")]
    pub account: Option<Account>,

    #[serde(rename = "allowTransparent")]
    pub allow_transparent: Option<bool>,
}

impl Default for InSetting {
    fn default() -> Self {
        Self {
            account: None,
            allow_transparent: None,
        }
    }
}

pub struct Proxy {
    account: Option<Account>,
    allow_transparent: bool,
    tr: transport::Transport,
}

impl Proxy {
    pub fn new_inbound(set: &InSetting, tr: transport::Transport) -> Result<Self> {
        Ok(Self {
            account: set.account.clone(),
            allow_transparent: set.allow_transparent.map_or(false, |x| x),
            tr,
        })
    }

    pub async fn listen(self, addr: Address) -> BoxStream<ProxyStream, std::io::Error> {
        log::info!("http start Listening on {:?}", addr);
        let stream_result = self.tr.listen(&addr).await;

        match stream_result {
            Ok(transport_stream) => {
                let account = self.account.clone();
                let allow_transparent = self.allow_transparent;

                let proxy_stream = async_stream::stream! {
                    tokio::pin!(transport_stream);

                    while let Some(result) = tokio_stream::StreamExt::next(&mut transport_stream).await {
                        match result {
                            Ok((stream, peer_addr)) => {
                                match Self::handle_connection(stream, peer_addr, &account, allow_transparent).await {
                                    Ok(ps) => yield Ok(ps),
                                    Err(e) => yield Err(e),
                                }
                            }
                            Err(e) => yield Err(e),
                        }
                    }
                };
                Box::pin(proxy_stream)
            }
            Err(e) => Box::pin(tokio_stream::once(Err(e))),
        }
    }
}

// --- 连接处理 ---

impl Proxy {
    /// 处理单个入站连接
    async fn handle_connection(
        mut stream: transport::TrStream,
        peer_addr: Address,
        account: &Option<Account>,
        _allow_transparent: bool,
    ) -> std::io::Result<ProxyStream> {
        log::debug!("[HTTP] New connection from {:?}", peer_addr);

        let mut buf = vec![0u8; BUFFER_SIZE];
        let n = AsyncReadExt::read(&mut stream, &mut buf).await?;
        if n == 0 {
            log::error!("[HTTP] Connection closed before receiving request");
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed before receiving request",
            ));
        }

        log::debug!("[HTTP] Received {} bytes", n);

        let (method, path, _header_len) = parse_request_line(&buf[..n])?;
        log::debug!("[HTTP] Request: {} {}", method, path);

        // 认证检查
        if let Some(acc) = account {
            log::debug!("[HTTP] Checking proxy authentication");
            check_proxy_auth(&buf[..n], acc, &mut stream).await?;
        }

        if method.eq_ignore_ascii_case("CONNECT") {
            log::debug!("[HTTP] Handling CONNECT request to {}", path);
            handle_connect(stream, peer_addr, path).await
        } else {
            log::debug!("[HTTP] Handling plain HTTP request");
            handle_plain_http(stream, peer_addr, &buf[..n]).await
        }
    }
}

// --- HTTP 请求解析 ---

/// 解析请求行，返回 (method, path, header_len)
fn parse_request_line(data: &[u8]) -> std::io::Result<(String, String, usize)> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);

    match req.parse(data) {
        Ok(httparse::Status::Complete(header_len)) => {
            let method = req
                .method
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Missing HTTP method"))?
                .to_string();
            let path = req
                .path
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Missing HTTP path"))?
                .to_string();
            Ok((method, path, header_len))
        }
        Ok(httparse::Status::Partial) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP request headers too large (>8KB)",
        )),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse HTTP request: {}", e),
        )),
    }
}

/// 从 HTTP 请求头中提取指定 header 的值
fn extract_header<'a>(data: &'a [u8], name: &str) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(data).is_ok() {
        for header in req.headers.iter() {
            if header.name.eq_ignore_ascii_case(name) {
                if let Ok(v) = std::str::from_utf8(header.value) {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

// --- 认证 ---

/// 检查 Proxy-Authorization 头
async fn check_proxy_auth(data: &[u8], account: &Account, stream: &mut transport::TrStream) -> std::io::Result<()> {
    let authorized = extract_header(data, "Proxy-Authorization")
        .and_then(|auth_value| {
            let encoded = auth_value.strip_prefix("Basic ")?;
            let decoded_bytes = parse::base64_decode(encoded).ok()?;
            let decoded = String::from_utf8(decoded_bytes).ok()?;
            let (user, pass) = decoded.split_once(':')?;
            if user == account.username && pass == account.password {
                Some(true)
            } else {
                None
            }
        })
        .unwrap_or(false);

    if !authorized {
        let response =
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n";
        let _ = AsyncWriteExt::write_all(stream, response).await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Proxy authentication failed",
        ));
    }
    Ok(())
}

// --- CONNECT / 普通 HTTP 处理 ---

/// 处理 CONNECT 隧道请求
async fn handle_connect(
    mut stream: transport::TrStream,
    peer_addr: Address,
    path: String,
) -> std::io::Result<ProxyStream> {
    log::debug!("[HTTP] Parsing CONNECT destination: {}", path);
    let dest = parse::parse_host_port(&path)?;
    log::debug!("[HTTP] CONNECT destination: {:?}", dest);

    let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    AsyncWriteExt::write_all(&mut stream, response).await?;
    log::debug!("[HTTP] Sent 200 Connection Established");

    Ok(ProxyStream::new(Protocol::Tcp, peer_addr, dest, stream))
}

/// 处理普通 HTTP 代理请求 (GET/POST 等)
async fn handle_plain_http(
    stream: transport::TrStream,
    peer_addr: Address,
    raw_request: &[u8],
) -> std::io::Result<ProxyStream> {
    log::debug!("[HTTP] Extracting Host header");
    let host = extract_header(raw_request, "Host").ok_or_else(|| {
        log::error!("[HTTP] Missing Host header");
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Missing Host header")
    })?;

    log::debug!("[HTTP] Plain HTTP request to host: {}", host);
    let dest = parse::parse_host_with_default_port(&host, 80);
    log::debug!("[HTTP] Destination: {:?}", dest);

    let buffered = transport::BufferedStream::new(stream, raw_request.to_vec());
    let wrapped = transport::TrStream::Buffered(Box::new(buffered));
    Ok(ProxyStream::new(Protocol::Tcp, peer_addr, dest, wrapped))
}
