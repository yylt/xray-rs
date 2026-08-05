use futures::stream::FuturesUnordered;
use futures::StreamExt;
use hickory_proto::op::Message;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_SIZE: usize = 4096;

#[derive(Debug, Clone)]
pub enum UpstreamProtocol {
    Udp,
    Tcp,
    Tls { server_name: String },
    Https { url: String },
    H3 { url: String },
}

#[derive(Clone)]
pub struct UpstreamClient {
    pub addrs: Vec<SocketAddr>,
    pub protocol: UpstreamProtocol,
    tls_config: Option<Arc<ClientConfig>>,
    pub bootstrap: bool,
    pub is_dynamic: bool,
}

impl UpstreamClient {
    pub fn new_udp(addrs: Vec<SocketAddr>) -> Self {
        Self {
            addrs,
            protocol: UpstreamProtocol::Udp,
            tls_config: None,
            bootstrap: false,
            is_dynamic: false,
        }
    }

    pub fn new_tcp(addrs: Vec<SocketAddr>) -> Self {
        Self {
            addrs,
            protocol: UpstreamProtocol::Tcp,
            tls_config: None,
            bootstrap: false,
            is_dynamic: false,
        }
    }

    pub fn new_tls(addrs: Vec<SocketAddr>, server_name: String, tls_config: Arc<ClientConfig>) -> Self {
        Self {
            addrs,
            protocol: UpstreamProtocol::Tls { server_name },
            tls_config: Some(tls_config),
            bootstrap: false,
            is_dynamic: false,
        }
    }

    pub fn new_doh(url: String, tls_config: Arc<ClientConfig>) -> Self {
        Self {
            addrs: Vec::new(),
            protocol: UpstreamProtocol::Https { url },
            tls_config: Some(tls_config),
            bootstrap: false,
            is_dynamic: false,
        }
    }

    pub fn new_doh3(url: String, tls_config: Arc<ClientConfig>) -> Self {
        Self {
            addrs: Vec::new(),
            protocol: UpstreamProtocol::H3 { url },
            tls_config: Some(tls_config),
            bootstrap: false,
            is_dynamic: false,
        }
    }

    pub async fn query(&self, msg: &Message) -> io::Result<Message> {
        match &self.protocol {
            UpstreamProtocol::Udp => {
                let addr = self
                    .addrs
                    .first()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no upstream address"))?;
                self.query_udp(*addr, msg).await
            }
            UpstreamProtocol::Tcp => {
                let addr = self
                    .addrs
                    .first()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no upstream address"))?;
                self.query_tcp(*addr, msg).await
            }
            UpstreamProtocol::Tls { server_name } => {
                let addr = self
                    .addrs
                    .first()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no upstream address"))?;
                self.query_tls(*addr, server_name, msg).await
            }
            UpstreamProtocol::Https { url } => self.query_doh(url, msg).await,
            UpstreamProtocol::H3 { url } => self.query_doh3(url, msg).await,
        }
    }

    async fn query_udp(&self, addr: SocketAddr, msg: &Message) -> io::Result<Message> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let buf = msg
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        socket.send_to(&buf, addr).await?;

        let mut recv_buf = vec![0u8; MAX_DNS_SIZE];
        let (len, _) = timeout(DNS_TIMEOUT, socket.recv_from(&mut recv_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP timeout"))??;

        Message::from_vec(&recv_buf[..len]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn query_tcp(&self, addr: SocketAddr, msg: &Message) -> io::Result<Message> {
        let mut stream = timeout(DNS_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timeout"))??;

        let buf = msg
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let len = (buf.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&buf).await?;

        let mut len_buf = [0u8; 2];
        timeout(DNS_TIMEOUT, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP read timeout"))??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut recv_buf = vec![0u8; resp_len];
        stream.read_exact(&mut recv_buf).await?;

        Message::from_vec(&recv_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn query_tls(&self, addr: SocketAddr, server_name: &str, msg: &Message) -> io::Result<Message> {
        let tls_config = self
            .tls_config
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS config not set"))?;

        let connector = TlsConnector::from(tls_config.clone());
        let tcp_stream = timeout(DNS_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS connect timeout"))??;

        let server_name: ServerName<'static> = server_name
            .to_string()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?;
        let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

        let buf = msg
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let len = (buf.len() as u16).to_be_bytes();
        tls_stream.write_all(&len).await?;
        tls_stream.write_all(&buf).await?;

        let mut len_buf = [0u8; 2];
        timeout(DNS_TIMEOUT, tls_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS read timeout"))??;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut recv_buf = vec![0u8; resp_len];
        tls_stream.read_exact(&mut recv_buf).await?;

        Message::from_vec(&recv_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn query_doh(&self, url: &str, msg: &Message) -> io::Result<Message> {
        let tls_config = self
            .tls_config
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS config not set for DoH"))?;

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config.as_ref().clone())
            .https_or_http()
            .enable_http2()
            .build();

        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

        let wire = msg
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let body = Full::new(Bytes::from(wire));

        let uri: hyper::Uri = url
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid DoH URL: {}", e)))?;

        let req = hyper::Request::post(uri)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(body)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("build request: {}", e)))?;

        let resp = timeout(DNS_TIMEOUT, client.request(req))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoH timeout"))?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("DoH request: {}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(io::Error::new(io::ErrorKind::Other, format!("DoH HTTP error: {}", status)));
        }

        let body_bytes = timeout(DNS_TIMEOUT, resp.collect())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoH body timeout"))?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("DoH body: {}", e)))?
            .to_bytes();

        Message::from_vec(&body_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn query_doh3(&self, _url: &str, _msg: &Message) -> io::Result<Message> {
        Err(io::Error::new(io::ErrorKind::Other, "DoH3 not implemented yet"))
    }
}

pub struct UpstreamGroup {
    clients: Vec<Arc<UpstreamClient>>,
}

impl UpstreamGroup {
    pub fn new(clients: Vec<UpstreamClient>) -> Self {
        Self {
            clients: clients.into_iter().map(Arc::new).collect(),
        }
    }

    pub async fn query(&self, msg: &Message) -> io::Result<Message> {
        let mut futs: FuturesUnordered<_> = self
            .clients
            .iter()
            .map(|client| {
                let client = client.clone();
                let msg_owned = msg.clone();
                async move { client.query(&msg_owned).await }
            })
            .collect();

        let mut first_err: Option<io::Error> = None;
        while let Some(result) = futs.next().await {
            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        Err(first_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "no upstream servers configured")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upstream_client_new_udp() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let client = UpstreamClient::new_udp(vec![addr]);
        assert_eq!(client.addrs.len(), 1);
        assert!(matches!(client.protocol, UpstreamProtocol::Udp));
    }

    #[test]
    fn test_upstream_group_new() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let group = UpstreamGroup::new(vec![UpstreamClient::new_udp(vec![addr])]);
        assert_eq!(group.clients.len(), 1);
    }
}
