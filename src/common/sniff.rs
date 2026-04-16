use bytes::BytesMut;
use log::{debug, error, trace};
use tokio::net::TcpStream;

/// Maximum number of bytes to peek for protocol detection
const MAX_SNIFF_BYTES: usize = 1024;

/// Result of protocol sniffing
#[derive(Debug, Clone)]
pub enum SniffResult {
    /// HTTP/1.x request with Host header
    Http { host: String },
    /// TLS ClientHello with SNI
    Tls { sni: String },
    /// Unknown/unsupported protocol
    Unknown,
}

impl SniffResult {
    /// Get the host/sni if available
    pub fn host(&self) -> Option<String> {
        match self {
            SniffResult::Http { host } => Some(host.clone()),
            SniffResult::Tls { sni } => Some(sni.clone()),
            SniffResult::Unknown => None,
        }
    }

    /// Check if this is HTTP
    pub fn is_http(&self) -> bool {
        matches!(self, SniffResult::Http { .. })
    }

    /// Check if this is TLS
    pub fn is_tls(&self) -> bool {
        matches!(self, SniffResult::Tls { .. })
    }
}

/// Peek at a stream to detect protocol and extract host/SNI.
/// Returns the sniff result and the peeked bytes (so they can be re-injected).
pub async fn sniff_stream(
    stream: &mut TcpStream,
    max_bytes: Option<usize>,
) -> std::io::Result<(SniffResult, BytesMut)> {
    let max = max_bytes.unwrap_or(MAX_SNIFF_BYTES);
    let mut buf = BytesMut::with_capacity(max);

    // Use peek to read without consuming
    let n = stream.peek(&mut buf).await?;

    if n == 0 {
        return Ok((SniffResult::Unknown, buf));
    }

    let result = sniff_bytes(&buf[..n]);
    debug!("Sniffed {} bytes, result: {:?}", n, result);

    Ok((result, buf))
}

/// Sniff protocol from bytes without consuming the stream.
/// This is useful when you already have buffered data.
pub fn sniff_bytes(data: &[u8]) -> SniffResult {
    if data.is_empty() {
        return SniffResult::Unknown;
    }

    // Check for TLS handshake
    if is_tls_handshake(data) {
        trace!("Detected TLS handshake");
        if let Some(sni) = extract_sni(data) {
            return SniffResult::Tls { sni };
        }
    }

    // Check for HTTP request
    if is_http_request(data) {
        trace!("Detected HTTP request");
        if let Some(host) = extract_http_host(data) {
            return SniffResult::Http { host };
        }
    }

    SniffResult::Unknown
}

/// Check if data looks like a TLS ClientHello
fn is_tls_handshake(data: &[u8]) -> bool {
    // TLS record header:
    // ContentType: 0x16 (handshake)
    // Version: 0x03 0x01 (TLS 1.0) or higher
    // Length: 2 bytes
    if data.len() < 5 {
        return false;
    }

    // Content type must be 0x16 (handshake)
    if data[0] != 0x16 {
        return false;
    }

    // Version check: major version 0x03, minor >= 0x01
    if data[1] != 0x03 || data[2] < 0x01 {
        return false;
    }

    // Check handshake type: 0x01 = ClientHello
    // TLS record header is 5 bytes, then HandshakeType (1) + Length (3)
    if data.len() >= 6 && data[5] == 0x01 {
        return true;
    }

    false
}

/// Extract SNI from TLS ClientHello
fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS ClientHello parsing
    // Reference: RFC 5246, 8446
    let mut pos = 5; // Skip record header

    // Handshake type (1) + length (3)
    pos += 4;

    // Protocol version (2)
    if pos + 2 > data.len() {
        return None;
    }
    pos += 2;

    // Random (32)
    if pos + 32 > data.len() {
        return None;
    }
    pos += 32;

    // Session ID length + session ID
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > data.len() {
        return None;
    }
    // Cipher suites
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos >= data.len() {
        return None;
    }
    // Compression methods
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;

    // Extensions
    if pos + 2 > data.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if pos + extensions_len > data.len() {
        return None;
    }

    // Parse extensions
    let extensions_end = pos + extensions_len;
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

        if ext_type == 0x0000 {
            // SNI extension
            return parse_sni_extension(&data[pos + 4..pos + 4 + ext_len]);
        }

        pos += 4 + ext_len;
    }

    None
}

/// Parse SNI extension
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + list_len > data.len() {
        return None;
    }

    let mut pos = 2;
    let list_end = 2 + list_len;

    while pos + 3 <= list_end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;

        if name_type == 0 {
            // HostName type
            if pos + 3 + name_len <= list_end {
                let name = &data[pos + 3..pos + 3 + name_len];
                return String::from_utf8(name.to_vec()).ok();
            }
        }

        pos += 3 + name_len;
    }

    None
}

/// Check if data looks like an HTTP request
fn is_http_request(data: &[u8]) -> bool {
    // Common HTTP methods - using starts_with instead of exact matching
    let methods: &[&[u8]] = &[
        b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT",
    ];

    for method in methods {
        if data.len() >= method.len() && &data[..method.len()] == *method {
            // Check for space after method
            if data.len() > method.len() && data[method.len()] == b' ' {
                return true;
            }
        }
    }

    // Also check for HTTP/2 connection preface
    if data.starts_with(b"PRI * HTTP/2") {
        return true;
    }

    false
}

/// Extract Host header from HTTP request
fn extract_http_host(data: &[u8]) -> Option<String> {
    // Convert to string for parsing (may contain binary data, but headers are ASCII)
    let text = String::from_utf8_lossy(data);

    // Find Host header
    // HTTP format: "Host: value\r\n"
    for line in text.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("host:") {
            let host = line[5..].trim();
            // Remove port if present
            if let Some(colon_pos) = host.rfind(':') {
                let port_part = &host[colon_pos + 1..];
                if port_part.parse::<u16>().is_ok() {
                    return Some(host[..colon_pos].to_string());
                }
            }
            return Some(host.to_string());
        }
    }

    None
}

/// Unified interface to sniff host from either HTTP Host header or TLS SNI.
/// Returns the hostname if sniffed successfully, None otherwise.
pub async fn sniff_host_or_sni(stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    match sniff_stream(stream, None).await {
        Ok((result, _)) => Ok(result.host()),
        Err(e) => {
            error!("Sniff error: {}", e);
            Ok(None)
        }
    }
}

/// Buffered sniff that ensures peeked data can be properly handled.
/// This version returns a buffer containing the sniffed data for re-injection.
pub async fn sniff_with_buffer(stream: &mut TcpStream) -> std::io::Result<(Option<String>, BytesMut)> {
    let (result, buf) = sniff_stream(stream, None).await?;
    Ok((result.host(), buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_request() {
        assert!(is_http_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n"));
        assert!(is_http_request(b"POST /api HTTP/1.1\r\n"));
        assert!(is_http_request(b"PUT /resource HTTP/1.1\r\n"));
        assert!(!is_http_request(b"HTTP/1.1 200 OK\r\n")); // Response, not request
        assert!(!is_http_request(b"\x16\x03\x01\x00\x68")); // TLS
    }

    #[test]
    fn test_extract_http_host() {
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_http_host(http), Some("example.com".to_string()));

        let http_port = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(extract_http_host(http_port), Some("example.com".to_string()));

        let no_host = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_host(no_host), None);
    }

    #[test]
    fn test_is_tls_handshake() {
        // Valid TLS 1.2 ClientHello prefix
        let tls_12 = b"\x16\x03\x01\x00\x68\x01\x00\x00\x64";
        assert!(is_tls_handshake(tls_12));

        // TLS 1.3 (version in record layer is 1.2 for backwards compat)
        let tls_13 = b"\x16\x03\x01\x00\xff\x01\x00\x00\xfb";
        assert!(is_tls_handshake(tls_13));

        // Not TLS
        let not_tls = b"GET / HTTP/1.1";
        assert!(!is_tls_handshake(not_tls));

        // ServerHello (not ClientHello)
        let server_hello = b"\x16\x03\x03\x00\x31\x02\x00\x00\x2d";
        assert!(!is_tls_handshake(server_hello));
    }

    #[test]
    fn test_sniff_bytes_http() {
        let http = b"GET /api HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        match sniff_bytes(http) {
            SniffResult::Http { host } => assert_eq!(host, "api.example.com"),
            _ => panic!("Expected HTTP result"),
        }
    }

    #[test]
    fn test_sniff_bytes_unknown() {
        let binary = b"\x00\x01\x02\x03\x04\x05";
        assert!(matches!(sniff_bytes(binary), SniffResult::Unknown));
    }

    #[test]
    fn test_sniff_result_host() {
        let http = SniffResult::Http {
            host: "test.com".to_string(),
        };
        assert_eq!(http.host(), Some("test.com".to_string()));

        let tls = SniffResult::Tls {
            sni: "tls.test.com".to_string(),
        };
        assert_eq!(tls.host(), Some("tls.test.com".to_string()));

        let unknown = SniffResult::Unknown;
        assert_eq!(unknown.host(), None);
    }
}
