use crate::{
    common::{
        forward::{CountingStream, StreamForwarder},
        stats::TrafficCounters,
        Address, Protocol,
    },
    proxy::{AddressPreference, Outbounder, ProxyStream},
    route::DnsResolver,
    transport::{self, TrStream},
};
use std::{collections::HashSet, future::Future, net::IpAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 流量出口
pub enum ConnectionSink {
    Direct(DirectSink),
    Proxy(ProxySink),
    Block,
    Daemon(DaemonSink),
}

impl std::fmt::Debug for ConnectionSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionSink::Direct(_) => write!(f, "ConnectionSink::Direct(<...>)")?,
            ConnectionSink::Proxy(_) => write!(f, "ConnectionSink::Proxy(<...>)")?,
            ConnectionSink::Block => write!(f, "ConnectionSink::Block")?,
            ConnectionSink::Daemon(_) => write!(f, "ConnectionSink::Daemon(<...>)")?,
        }
        Ok(())
    }
}

impl ConnectionSink {
    /// 处理一条 ProxyStream
    pub async fn handle(&self, stream: ProxyStream, forwarder: &StreamForwarder) -> std::io::Result<()> {
        self.handle_with_counters(stream, forwarder, TrafficCounters::default())
            .await
    }

    pub async fn handle_with_counters(
        &self,
        mut stream: ProxyStream,
        forwarder: &StreamForwarder,
        counters: TrafficCounters,
    ) -> std::io::Result<()> {
        match self {
            ConnectionSink::Direct(sink) => sink.handle(stream, forwarder, counters).await,
            ConnectionSink::Proxy(sink) => sink.handle(stream, forwarder, counters).await,
            ConnectionSink::Block => {
                let error = std::io::Error::new(std::io::ErrorKind::NotConnected, "connection blocked");
                if let Err(response_error) = stream.reject_connection(&error).await {
                    log::debug!("failed to reject blocked inbound: {response_error}");
                }
                Ok(())
            }
            ConnectionSink::Daemon(_) => {
                let error =
                    std::io::Error::new(std::io::ErrorKind::Unsupported, "Daemon sinks cannot handle proxy streams");
                if let Err(response_error) = stream.reject_connection(&error).await {
                    log::debug!("failed to reject daemon inbound: {response_error}");
                }
                Err(error)
            }
        }
    }

    pub fn is_daemon(&self) -> bool {
        matches!(self, ConnectionSink::Daemon(_))
    }
}

/// 直连出口：解析域名后直接 TCP 连接目标
pub struct DirectSink {
    pub dns: Arc<DnsResolver>,
    pub transport: transport::Transport,
    pub prefer: AddressPreference,
    pub connect_timeout: Duration,
    #[cfg(target_os = "linux")]
    pub bpf: Option<Arc<crate::common::bpf::BpfRelay>>,
}

impl DirectSink {
    async fn handle(
        &self,
        mut stream: ProxyStream,
        forwarder: &StreamForwarder,
        counters: TrafficCounters,
    ) -> std::io::Result<()> {
        let remote = match self
            .try_connect(&stream.metadata.dst, stream.metadata.protocol.clone())
            .await
        {
            Ok(remote) => remote,
            Err(error) => {
                if let Err(response_error) = stream.reject_connection(&error).await {
                    log::debug!("failed to reject inbound connection: {response_error}");
                }
                return Err(error);
            }
        };
        stream.confirm_connected().await?;
        match stream.metadata.protocol {
            Protocol::Tcp => {
                #[cfg(target_os = "linux")]
                if let Some(bpf) = &self.bpf {
                    if stream.metadata.bpf_eligible && stream.inner.is_plain_tcp() && remote.is_plain_tcp() {
                        let (mut local, prefix) = stream
                            .inner
                            .into_tcp_with_prefix()
                            .ok_or_else(|| std::io::Error::other("BPF inbound lost its TCP transport"))?;
                        let (mut remote, remote_prefix) = remote
                            .into_tcp_with_prefix()
                            .ok_or_else(|| std::io::Error::other("BPF outbound lost its TCP transport"))?;
                        // Complete preread writes before either receive hook can redirect new bytes.
                        CountingStream {
                            inner: &mut remote,
                            counters: counters.clone(),
                            uplink: true,
                        }
                        .write_all(&prefix)
                        .await?;
                        CountingStream {
                            inner: &mut local,
                            counters: counters.clone(),
                            uplink: false,
                        }
                        .write_all(&remote_prefix)
                        .await?;
                        return match bpf
                            .clone()
                            .forward_with_counters(local, remote, counters.clone())
                            .await?
                        {
                            crate::common::bpf::Outcome::Kernel => Ok(()),
                            crate::common::bpf::Outcome::Userspace(local, remote) => {
                                log::debug!("BPF fallback to userspace forwarding for TCP to {}", stream.metadata.dst);
                                forwarder
                                    .forward_with_counters(TrStream::Tcp(local), TrStream::Tcp(remote), counters)
                                    .await?;
                                Ok(())
                            }
                        };
                    }
                    log::debug!("BPF skipped: connection is not HTTP/SOCKS over plain TCP");
                }
                forwarder.forward_with_counters(stream.inner, remote, counters).await?;
                Ok(())
            }
            Protocol::Udp => self.handle_udp(stream, remote, counters).await,
        }
    }

    async fn handle_udp(
        &self,
        stream: ProxyStream,
        mut remote: TrStream,
        counters: TrafficCounters,
    ) -> std::io::Result<()> {
        let mut inbound = CountingStream {
            inner: stream.inner,
            counters: counters.clone(),
            uplink: false,
        };
        let remote_socket = match &mut remote {
            transport::TrStream::Udp(socket) => socket,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP direct sink requires UDP transport stream",
                ))
            }
        };

        let mut inbound_buf = vec![0u8; 65535];
        let mut remote_buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                inbound_read = inbound.read(&mut inbound_buf) => {
                    let n = inbound_read?;
                    if n == 0 {
                        break;
                    }
                    let sent = remote_socket.send(&inbound_buf[..n]).await?;
                    counters.record_uplink(sent as u64);
                }
                remote_read = remote_socket.recv(&mut remote_buf) => {
                    let n = remote_read?;
                    if n == 0 {
                        break;
                    }
                    inbound.write_all(&remote_buf[..n]).await?;
                    inbound.flush().await?;
                }
            }
        }

        let _ = inbound.shutdown().await;
        Ok(())
    }

    /// Establish a remote without consuming or forwarding any inbound data.
    pub async fn try_connect(&self, dst: &Address, protocol: Protocol) -> std::io::Result<TrStream> {
        let candidates = match dst {
            Address::Domain(domain, port) => ordered_ips(self.dns.resolve(domain).await?, self.prefer)
                .into_iter()
                .map(|ip| Address::Inet(std::net::SocketAddr::new(ip, *port)))
                .collect(),
            other => vec![other.clone()],
        };
        connect_candidates(candidates, self.connect_timeout, |addr| {
            let protocol = protocol.clone();
            async move { self.transport.connect(&addr, protocol, None).await }
        })
        .await
    }
}

fn ordered_ips(mut ips: Vec<IpAddr>, prefer: AddressPreference) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    ips.retain(|ip| seen.insert(*ip));
    match prefer {
        AddressPreference::System => {}
        AddressPreference::Ipv4 => ips.sort_by_key(IpAddr::is_ipv6),
        AddressPreference::Ipv6 => ips.sort_by_key(IpAddr::is_ipv4),
    }
    ips
}

async fn connect_candidates<T, F, Fut>(
    candidates: Vec<Address>,
    connect_timeout: Duration,
    mut connect: F,
) -> std::io::Result<T>
where
    F: FnMut(Address) -> Fut,
    Fut: Future<Output = std::io::Result<T>>,
{
    let mut last_error =
        std::io::Error::new(std::io::ErrorKind::NotFound, "no candidate address for freedom connection");
    for addr in candidates {
        let result = tokio::time::timeout(connect_timeout, connect(addr.clone())).await;
        let error = match result {
            Ok(Ok(remote)) => {
                log::debug!("freedom connected to {addr}");
                return Ok(remote);
            }
            Ok(Err(error)) => error,
            Err(_) => std::io::Error::new(std::io::ErrorKind::TimedOut, "transport connection timed out"),
        };
        log::warn!("freedom connection to {addr} failed: {error}");
        last_error = std::io::Error::new(error.kind(), format!("freedom connection to {addr} failed: {error}"));
    }
    Err(last_error)
}

pub struct ProxySink {
    pub outbounder: Outbounder,
}

impl ProxySink {
    async fn handle(
        &self,
        mut stream: ProxyStream,
        forwarder: &StreamForwarder,
        counters: TrafficCounters,
    ) -> std::io::Result<()> {
        let remote = match self
            .try_connect(&stream.metadata.dst, stream.metadata.protocol.clone())
            .await
        {
            Ok(remote) => remote,
            Err(error) => {
                if let Err(response_error) = stream.reject_connection(&error).await {
                    log::debug!("failed to reject inbound connection: {response_error}");
                }
                return Err(error);
            }
        };
        stream.confirm_connected().await?;
        forwarder.forward_with_counters(stream.inner, remote, counters).await?;
        Ok(())
    }

    /// 尝试建立到目标地址的代理连接（不消费 inbound stream）
    /// 用于支持 fallback 重试：只有连接成功后才消费 stream
    pub async fn try_connect(&self, dst: &Address, protocol: crate::common::Protocol) -> std::io::Result<TrStream> {
        self.outbounder.connect(dst, protocol, None).await
    }
}

pub struct DaemonSink {
    pub outbounder: Outbounder,
}

impl DaemonSink {
    pub async fn run(mut self) -> std::io::Result<()> {
        let mut retry = 0u32;
        loop {
            match self.outbounder.run().await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let secs = std::cmp::min(2u64.pow(retry.min(8)), 300);
                    log::error!("daemon sink error: {}, retry in {}s", e, secs);
                    retry += 1;
                    tokio::time::sleep(tokio::time::Duration::from_secs(secs)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::stats::TrafficStats;
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::time::{timeout, Duration};

    #[test]
    fn freedom_address_order_is_stable_and_unique() {
        let ips: Vec<IpAddr> = ["::2", "192.0.2.2", "::1", "192.0.2.1", "::2", "192.0.2.2"]
            .into_iter()
            .map(|ip| ip.parse().unwrap())
            .collect();
        for (prefer, expected) in [
            (AddressPreference::System, vec!["::2", "192.0.2.2", "::1", "192.0.2.1"]),
            (AddressPreference::Ipv4, vec!["192.0.2.2", "192.0.2.1", "::2", "::1"]),
            (AddressPreference::Ipv6, vec!["::2", "::1", "192.0.2.2", "192.0.2.1"]),
        ] {
            assert_eq!(
                ordered_ips(ips.clone(), prefer),
                expected
                    .into_iter()
                    .map(|ip| ip.parse::<IpAddr>().unwrap())
                    .collect::<Vec<_>>()
            );
        }
        assert!(ordered_ips(vec![], AddressPreference::Ipv4).is_empty());
    }

    fn candidates() -> Vec<Address> {
        (1..=3)
            .map(|last| Address::Inet(format!("192.0.2.{last}:80").parse().unwrap()))
            .collect()
    }

    #[tokio::test]
    async fn freedom_retries_errors_and_stops_on_success() {
        let mut attempts = Vec::new();
        let result = connect_candidates(candidates(), Duration::from_secs(1), |addr| {
            attempts.push(addr.to_string());
            let attempt = attempts.len();
            async move {
                if attempt == 1 {
                    Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                } else {
                    Ok(attempt)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result, 2);
        assert_eq!(attempts, ["192.0.2.1:80", "192.0.2.2:80"]);
    }

    #[tokio::test]
    async fn freedom_retries_timeout_and_reports_all_failures() {
        let mut attempts = 0;
        let result = connect_candidates(candidates(), Duration::from_millis(1), |_| {
            attempts += 1;
            let attempt = attempts;
            async move {
                if attempt == 1 {
                    std::future::pending::<()>().await;
                }
                Ok(attempt)
            }
        })
        .await
        .unwrap();
        assert_eq!(result, 2);
        assert_eq!(attempts, 2);
        let mut attempts = 0;
        let error = connect_candidates::<(), _, _>(candidates(), Duration::from_secs(1), |_| {
            attempts += 1;
            async { Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)) }
        })
        .await
        .unwrap_err();
        assert_eq!(attempts, 3);
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        assert!(error.to_string().contains("192.0.2.3:80"));
        let error = connect_candidates::<(), _, _>(
            vec![Address::Inet("127.0.0.1:80".parse().unwrap())],
            Duration::from_millis(1),
            |_| std::future::pending::<std::io::Result<()>>(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let error = connect_candidates::<(), _, _>(vec![], Duration::from_secs(1), |_| async { unreachable!() })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn freedom_build_sink_carries_settings_and_defaults() {
        for (yaml, prefer, ms) in [
            ("protocol: freedom\n", AddressPreference::System, 5000),
            (
                "protocol: freedom\nsettings:\n  prefer: ipv6\n  connectTimeoutMs: 23\n",
                AddressPreference::Ipv6,
                23,
            ),
            ("{}", AddressPreference::System, 5000),
        ] {
            let outbound: crate::app::OutboundSettings = serde_yaml::from_str(yaml).unwrap();
            let ConnectionSink::Direct(sink) = outbound.build_sink(Arc::new(DnsResolver)).unwrap() else {
                panic!("expected freedom sink")
            };
            assert_eq!(sink.prefer, prefer);
            assert_eq!(sink.connect_timeout, Duration::from_millis(ms));
        }
    }

    async fn direct_flow(protocol: Protocol) {
        timeout(Duration::from_secs(5), async {
            let dns = Arc::new(DnsResolver);
            let sink = DirectSink {
                transport: transport::Transport::new(&transport::StreamSettings::default(), None, dns.clone()).unwrap(),
                dns,
                prefer: AddressPreference::System,
                connect_timeout: Duration::from_secs(5),
                #[cfg(target_os = "linux")]
                bpf: None,
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let (inbound, _) = listener.accept().await.unwrap();
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let dst = match protocol {
                Protocol::Tcp => tcp.local_addr().unwrap(),
                Protocol::Udp => udp.local_addr().unwrap(),
            };
            let stream = ProxyStream::new(
                protocol.clone(),
                Address::Inet(client.local_addr().unwrap()),
                Address::Inet(dst),
                TrStream::Tcp(inbound),
            );
            let inbound_stats = Arc::new(TrafficStats::new());
            let outbound_stats = Arc::new(TrafficStats::new());
            let counters = TrafficCounters {
                inbound: Some(inbound_stats.clone()),
                outbound: Some(outbound_stats.clone()),
            };
            let task = tokio::spawn(async move { sink.handle(stream, &StreamForwarder::new(), counters).await });
            client.write_all(b"ping").await.unwrap();
            let mut buf = [0; 4];
            match protocol {
                Protocol::Tcp => {
                    let (mut remote, _) = tcp.accept().await.unwrap();
                    remote.read_exact(&mut buf).await.unwrap();
                    remote.write_all(b"pong").await.unwrap();
                    client.read_exact(&mut buf).await.unwrap();
                    assert!(!task.is_finished());
                    for stats in [&inbound_stats, &outbound_stats] {
                        assert_eq!((stats.uplink(), stats.downlink()), (4, 4));
                    }
                    drop(remote);
                }
                Protocol::Udp => {
                    let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
                    assert_eq!(n, 4);
                    udp.send_to(b"pong", peer).await.unwrap();
                    client.read_exact(&mut buf).await.unwrap();
                    assert!(!task.is_finished());
                    for stats in [&inbound_stats, &outbound_stats] {
                        assert_eq!((stats.uplink(), stats.downlink()), (4, 4));
                    }
                }
            }
            drop(client);
            task.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn direct_tcp_counts_while_open() {
        direct_flow(Protocol::Tcp).await;
    }

    #[tokio::test]
    async fn direct_udp_counts_while_open() {
        direct_flow(Protocol::Udp).await;
    }
}

#[cfg(all(test, target_os = "linux"))]
mod bpf_tests {
    use super::*;
    use crate::common::bpf::BpfRelay;
    use crate::{
        common::Protocol,
        proxy::{FreedomSettings, OutboundSettings as ProxyOutboundSettings},
        transport::BufferedStream,
    };
    use aya::maps::SockHash;
    use bytes::Bytes;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{sleep, timeout, Duration};

    /// Preread prefix an HTTP inbound would have buffered before routing.
    const PREFIX: &[u8] = b"GET / HTTP/1.1\r\nHost: target\r\n\r\n";

    fn freedom(bpf: bool) -> crate::app::OutboundSettings {
        crate::app::OutboundSettings {
            tag: None,
            settings: Some(ProxyOutboundSettings::Freedom(FreedomSettings {
                bpf,
                ..FreedomSettings::default()
            })),
            stream_settings: None,
        }
    }

    fn dns() -> Arc<DnsResolver> {
        Arc::new(DnsResolver)
    }

    fn inbound_stream(inbound: TcpStream, peer: std::net::SocketAddr, target: std::net::SocketAddr) -> ProxyStream {
        let inner = TrStream::Buffered(Box::new(BufferedStream::new(
            TrStream::Tcp(inbound),
            Bytes::from_static(PREFIX),
        )));
        ProxyStream::new(Protocol::Tcp, Address::Inet(peer), Address::Inet(target), inner).with_bpf_eligibility(true)
    }

    /// Wait until both sockets are armed, otherwise the relay silently used
    /// userspace forwarding and the test would prove nothing about the kernel path.
    async fn wait_armed(relay: &BpfRelay) {
        for _ in 0..500 {
            let armed = {
                let ebpf = relay.ebpf.lock().unwrap();
                SockHash::<_, u64>::try_from(ebpf.map("sockets").unwrap())
                    .unwrap()
                    .keys()
                    .count()
            };
            if armed == 2 {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("BPF relay never armed");
    }

    /// Run one buffered HTTP request through the sink and assert the prefix is
    /// delivered exactly once, in order, before any later payload.
    async fn relay_buffered_request(sink: ConnectionSink) {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(inbound_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (inbound, peer) = inbound_listener.accept().await.unwrap();
        let bpf = match &sink {
            ConnectionSink::Direct(direct) => direct.bpf.clone(),
            _ => None,
        };
        let stream = inbound_stream(inbound, peer, target_addr);
        let inbound_stats = Arc::new(crate::common::stats::TrafficStats::new());
        let outbound_stats = Arc::new(crate::common::stats::TrafficStats::new());
        let counters = TrafficCounters {
            inbound: Some(inbound_stats.clone()),
            outbound: Some(outbound_stats.clone()),
        };
        let relay = tokio::spawn(async move {
            let forwarder = StreamForwarder::new();
            sink.handle_with_counters(stream, &forwarder, counters).await
        });
        let (mut target, _) = target_listener.accept().await.unwrap();
        if let Some(bpf) = &bpf {
            wait_armed(bpf).await;
        }

        let mut head = vec![0; PREFIX.len()];
        target.read_exact(&mut head).await.unwrap();
        assert_eq!(head, PREFIX);
        client.write_all(b"body").await.unwrap();
        let mut body = [0; 4];
        target.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"body");

        // Half-close must not truncate the reverse direction.
        client.shutdown().await.unwrap();
        let mut tail = Vec::new();
        target.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty());
        target.write_all(b"reply").await.unwrap();
        target.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
        relay.await.unwrap().unwrap();
        for stats in [&inbound_stats, &outbound_stats] {
            assert_eq!(stats.uplink(), (PREFIX.len() + 4) as u64);
            assert_eq!(stats.downlink(), 5);
        }
    }

    #[tokio::test]
    async fn freedom_without_bpf_keeps_userspace_forwarding() {
        let sink = freedom(false).build_sink(dns()).unwrap();
        let ConnectionSink::Direct(direct) = &sink else {
            panic!("freedom must build a direct sink");
        };
        assert!(direct.bpf.is_none(), "BPF must stay uninitialized by default");
        timeout(Duration::from_secs(15), relay_buffered_request(sink))
            .await
            .expect("userspace relay timed out");
    }

    #[tokio::test]
    #[ignore = "requires root/CAP_BPF, kernel SK_SKB support and clang"]
    async fn freedom_bpf_relays_buffered_request_once() {
        let sink = freedom(true).build_sink(dns()).unwrap();
        let ConnectionSink::Direct(direct) = &sink else {
            panic!("freedom must build a direct sink");
        };
        assert!(direct.bpf.is_some(), "bpf: true must load the relay at startup");
        timeout(Duration::from_secs(15), relay_buffered_request(sink))
            .await
            .expect("BPF relay timed out");
    }
}
