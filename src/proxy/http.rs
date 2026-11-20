use super::*;
use crate::common::parse;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_HEADERS: usize = 64;
const BUFFER_SIZE: usize = 8192;
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct InSetting {
    #[serde(rename = "account")]
    pub account: Option<Account>,

    #[serde(rename = "allowTransparent")]
    pub allow_transparent: Option<bool>,
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
            allow_transparent: set.allow_transparent.unwrap_or(false),
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
                                match Self::handle_connection(stream, peer_addr.clone(), &account, allow_transparent).await {
                                    Ok(ps) => yield Ok(ps),
                                    Err(e) => {
                                        match e.kind() {
                                            std::io::ErrorKind::UnexpectedEof => {
                                                log::debug!("[HTTP] peer {:?} closed connection before sending a complete request: {}", peer_addr, e);
                                            }
                                            std::io::ErrorKind::InvalidData => {
                                                log::debug!("[HTTP] invalid request from {:?}: {}", peer_addr, e);
                                            }
                                            std::io::ErrorKind::PermissionDenied => {
                                                log::debug!("[HTTP] authentication failed from {:?}: {}", peer_addr, e);
                                            }
                                            _ => {
                                                log::warn!("[HTTP] connection handling error from {:?}: {}", peer_addr, e);
                                            }
                                        }
                                    }
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

        let buf = read_http_request_head(&mut stream).await?;
        log::debug!("[HTTP] Received {} bytes before header completion", buf.len());

        let (method, path, header_len) = parse_request_line(&buf)?;
        log::debug!("[HTTP] Request: {} {}", method, path);

        // 认证检查
        if let Some(acc) = account {
            log::debug!("[HTTP] Checking proxy authentication");
            check_proxy_auth(&buf, acc, &mut stream).await?;
        }

        let remainder = if buf.len() > header_len {
            Some(buf.slice(header_len..))
        } else {
            None
        };

        if method.eq_ignore_ascii_case("CONNECT") {
            log::debug!("[HTTP] Handling CONNECT request to {}", path);
            handle_connect(stream, peer_addr, &path, remainder).await
        } else {
            log::debug!("[HTTP] Handling plain HTTP request");
            handle_plain_http(stream, peer_addr, buf, &path, header_len).await
        }
    }
}

// --- HTTP 请求解析 ---

async fn read_http_request_head(stream: &mut transport::TrStream) -> std::io::Result<Bytes> {
    let mut buf = BytesMut::with_capacity(BUFFER_SIZE.min(1024));
    let mut chunk = [0u8; 1024];

    loop {
        let n = AsyncReadExt::read(stream, &mut chunk).await?;
        if n == 0 {
            if buf.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Connection closed before receiving request",
                ));
            }

            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed before receiving complete HTTP headers",
            ));
        }

        buf.extend_from_slice(&chunk[..n]);

        if find_header_terminator(&buf).is_some() {
            return Ok(buf.freeze());
        }

        if buf.len() >= BUFFER_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("HTTP request headers too large (>{} bytes)", BUFFER_SIZE),
            ));
        }
    }
}

fn find_header_terminator(data: &[u8]) -> Option<usize> {
    data.windows(HEADER_TERMINATOR.len())
        .position(|window| window == HEADER_TERMINATOR)
        .map(|pos| pos + HEADER_TERMINATOR.len())
}

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
            std::io::ErrorKind::UnexpectedEof,
            "Incomplete HTTP request headers",
        )),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse HTTP request: {}", e),
        )),
    }
}

/// 从 HTTP 请求头中提取指定 header 的值
fn extract_header(data: &[u8], name: &str) -> Option<String> {
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
    stream: transport::TrStream,
    peer_addr: Address,
    path: &str,
    remainder: Option<Bytes>,
) -> std::io::Result<ProxyStream> {
    log::debug!("[HTTP] Parsing CONNECT destination: {}", path);
    let dest = parse::parse_host_port(path)?;
    log::debug!("[HTTP] CONNECT destination: {:?}", dest);

    let stream = wrap_stream_with_prefix(stream, remainder);
    Ok(ProxyStream::new(Protocol::Tcp, peer_addr, dest, stream)
        .with_bpf_eligibility(true)
        .with_connect_response())
}

fn wrap_stream_with_prefix(stream: transport::TrStream, prefix: Option<Bytes>) -> transport::TrStream {
    match prefix {
        Some(prefix) if !prefix.is_empty() => {
            let buffered = transport::BufferedStream::new(stream, prefix);
            transport::TrStream::Buffered(Box::new(buffered))
        }
        _ => stream,
    }
}

/// 处理普通 HTTP 代理请求 (GET/POST 等)
async fn handle_plain_http(
    stream: transport::TrStream,
    peer_addr: Address,
    raw_request: Bytes,
    path: &str,
    header_len: usize,
) -> std::io::Result<ProxyStream> {
    log::debug!("[HTTP] Extracting Host header");
    let host = extract_header(&raw_request, "Host").ok_or_else(|| {
        log::error!("[HTTP] Missing Host header");
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Missing Host header")
    })?;

    log::debug!("[HTTP] Plain HTTP request to host: {}", host);
    let dest = parse::parse_host_with_default_port(&host, 80);
    log::debug!("[HTTP] Destination: {:?}", dest);

    if let Some(rewritten) = rewrite_request_line(&raw_request, path, header_len) {
        let wrapped = wrap_stream_with_prefix(stream, Some(Bytes::from(rewritten)));
        Ok(ProxyStream::new(Protocol::Tcp, peer_addr, dest, wrapped).with_bpf_eligibility(true))
    } else {
        let wrapped = wrap_stream_with_prefix(stream, Some(raw_request));
        Ok(ProxyStream::new(Protocol::Tcp, peer_addr, dest, wrapped).with_bpf_eligibility(true))
    }
}

fn rewrite_request_line(raw: &[u8], absolute_uri: &str, header_len: usize) -> Option<Vec<u8>> {
    if !absolute_uri.starts_with("http://") && !absolute_uri.starts_with("https://") {
        return None;
    }

    let uri_start = raw
        .windows(absolute_uri.len())
        .position(|w| w == absolute_uri.as_bytes())?;

    let scheme_end = absolute_uri.find("://")? + 3;
    let path_start = absolute_uri[scheme_end..].find('/')? + scheme_end;
    let origin_path = &absolute_uri[path_start..];

    let header_part = &raw[header_len..];
    let mut result = Vec::with_capacity(header_part.len() + origin_path.len() + 64);
    result.extend_from_slice(&raw[..uri_start]);
    result.extend_from_slice(origin_path.as_bytes());
    result.extend_from_slice(&raw[uri_start + absolute_uri.len()..]);

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Address;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn pending_connect(payload: &[u8]) -> (TcpStream, ProxyStream) {
        let (client, server) = tcp_pair().await;
        let mut request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec();
        request.extend_from_slice(payload);
        // Supply the whole read explicitly so preread coverage does not depend on TCP packetization.
        let stream = wrap_stream_with_prefix(transport::TrStream::Tcp(server), Some(Bytes::from(request)));
        let proxy_stream =
            Proxy::handle_connection(stream, Address::Inet("127.0.0.1:12345".parse().unwrap()), &None, false)
                .await
                .unwrap();
        (client, proxy_stream)
    }

    #[tokio::test]
    async fn connect_preserves_preread_tls_bytes() {
        let tls_hello = b"\x16\x03\x01\x00fake-client-hello";
        let (mut client, mut proxy_stream) = pending_connect(tls_hello).await;

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), client.read(&mut [0; 1]),)
                .await
                .is_err(),
            "CONNECT must not succeed before outbound confirmation"
        );

        proxy_stream.confirm_connected().await.unwrap();
        let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        let mut received = vec![0; response.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, response);
        proxy_stream.confirm_connected().await.unwrap();
        proxy_stream
            .reject_connection(&std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
            .await
            .unwrap();

        match proxy_stream.metadata.dst {
            Address::Domain(ref host, port) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            other => panic!("unexpected destination: {:?}", other),
        }

        assert!(proxy_stream.metadata.bpf_eligible);
        let mut inner = proxy_stream.inner;
        let mut buf = vec![0u8; tls_hello.len()];
        inner.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, tls_hello);
        inner.write_all(b"tunnel data").await.unwrap();
        inner.shutdown().await.unwrap();
        let mut remaining = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut remaining))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            remaining, b"tunnel data",
            "confirmation and rejection must not add another response"
        );
    }

    #[tokio::test]
    async fn connect_rejection_sends_one_error_response_and_closes() {
        for (kind, expected) in [
            (
                std::io::ErrorKind::ConnectionRefused,
                &b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"[..],
            ),
            (
                std::io::ErrorKind::TimedOut,
                &b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"[..],
            ),
        ] {
            let (mut client, mut proxy_stream) = pending_connect(b"unforwarded payload").await;
            let error = std::io::Error::from(kind);
            proxy_stream.reject_connection(&error).await.unwrap();
            proxy_stream.reject_connection(&error).await.unwrap();
            proxy_stream.confirm_connected().await.unwrap();
            let mut response = Vec::new();
            // Keep the stream alive: EOF must come from rejection, not from dropping it.
            tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response, expected);
        }
    }

    fn direct_sink() -> crate::app::ConnectionSink {
        let dns = std::sync::Arc::new(crate::route::DnsResolver);
        crate::app::ConnectionSink::Direct(crate::app::DirectSink {
            transport: transport::Transport::new(&transport::StreamSettings::default(), None, dns.clone()).unwrap(),
            dns,
            prefer: AddressPreference::System,
            connect_timeout: std::time::Duration::from_secs(5),
            #[cfg(target_os = "linux")]
            bpf: None,
        })
    }

    #[tokio::test]
    async fn connect_direct_sink_confirms_and_forwards_preread_payload() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (mut client, mut stream) = pending_connect(b"client hello").await;
            stream.metadata.dst = Address::Inet(target.local_addr().unwrap());
            let forwarding = tokio::spawn(async move {
                direct_sink()
                    .handle(stream, &crate::common::forward::StreamForwarder::new())
                    .await
            });
            let (mut remote, _) = target.accept().await.unwrap();
            let mut hello = [0; 12];
            remote.read_exact(&mut hello).await.unwrap();
            assert_eq!(&hello, b"client hello");
            remote.write_all(b"server hello").await.unwrap();
            remote.shutdown().await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"HTTP/1.1 200 Connection Established\r\n\r\nserver hello");
            forwarding.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn connect_direct_sink_refusal_sends_502_without_200() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            // Reserve a port without listening so no other test can claim it before connect.
            let target = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
            target
                .bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap().into())
                .unwrap();
            let (mut client, mut stream) = pending_connect(b"client hello").await;
            stream.metadata.dst = Address::Inet(target.local_addr().unwrap().as_socket().unwrap());
            let error = direct_sink()
                .handle(stream, &crate::common::forward::StreamForwarder::new())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                response,
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn connect_confirmation_write_failure_closes_outbound() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (client, server) = tokio::io::duplex(64);
            drop(client); // A closed in-memory peer makes the 200 write fail deterministically.
            let stream = ProxyStream::new(
                Protocol::Tcp,
                Address::Inet("127.0.0.1:12345".parse().unwrap()),
                Address::Inet(target.local_addr().unwrap()),
                transport::TrStream::Tun(Box::new(server)),
            )
            .with_connect_response();
            let error = direct_sink()
                .handle(stream, &crate::common::forward::StreamForwarder::new())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
            let (mut remote, _) = target.accept().await.unwrap();
            assert_eq!(remote.read(&mut [0; 1]).await.unwrap(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn plain_http_rewrites_absolute_uri_to_origin_form() {
        let (mut client, server) = tcp_pair().await;

        let request = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let expected = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";

        let writer = tokio::spawn(async move {
            client.write_all(request).await.unwrap();
        });

        let proxy_stream = Proxy::handle_connection(
            transport::TrStream::Tcp(server),
            Address::Inet("127.0.0.1:12345".parse().unwrap()),
            &None,
            false,
        )
        .await
        .unwrap();

        writer.await.unwrap();

        match proxy_stream.metadata.dst {
            Address::Domain(ref host, port) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
            }
            other => panic!("unexpected destination: {:?}", other),
        }

        assert!(proxy_stream.metadata.bpf_eligible);
        let mut inner = proxy_stream.inner;
        let mut buf = vec![0u8; expected.len()];
        inner.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, expected);
    }
}
