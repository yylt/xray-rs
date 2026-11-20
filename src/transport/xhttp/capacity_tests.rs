use super::super::balancer::{GrpcTargetKey, TargetState};
use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinSet;

const IPS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
];

struct Backends {
    port: u16,
    accepts: [Arc<AtomicUsize>; 2],
    tasks: JoinSet<()>,
}

impl Backends {
    async fn start(limit: u32, sessions: packet::PacketSessions) -> Self {
        let first = TcpListener::bind((IPS[0], 0)).await.unwrap();
        let port = first.local_addr().unwrap().port();
        let second = TcpListener::bind((IPS[1], port)).await.unwrap();
        let accepts = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        let mut tasks = JoinSet::new();
        for (listener, count) in [first, second].into_iter().zip(accepts.iter().cloned()) {
            let sessions = sessions.clone();
            tasks.spawn(async move {
                let (tx, mut rx) = mpsc::channel::<(super::super::TrStream, Address)>(32);
                let mut children = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (socket, peer) = accepted.unwrap();
                            count.fetch_add(1, Ordering::SeqCst);
                            let sessions = sessions.clone();
                            let tx = tx.clone();
                            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                                let sessions = sessions.clone();
                                let tx = tx.clone();
                                async move {
                                    let suffix = req.uri().path().strip_prefix("/test/").unwrap().to_owned();
                                    Ok::<_, Infallible>(packet::handle(
                                        req, sessions, tx, Address::Inet(peer), &suffix,
                                    ).await)
                                }
                            });
                            children.spawn(async move {
                                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                                    .max_concurrent_streams(limit)
                                    .serve_connection(TokioIo::new(socket), service)
                                    .await;
                            });
                        }
                        Some((mut stream, _)) = rx.recv() => {
                            children.spawn(async move {
                                let mut bytes = [0; 256];
                                while let Ok(n) = stream.read(&mut bytes).await {
                                    if n == 0 || stream.write_all(&bytes[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            });
                        }
                        Some(result) = children.join_next() => { result.unwrap(); }
                    }
                }
            });
        }
        Self { port, accepts, tasks }
    }

    fn counts(&self) -> [usize; 2] {
        self.accepts.each_ref().map(|count| count.load(Ordering::SeqCst))
    }
}

impl Drop for Backends {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

fn transport(upload: u16, download: Option<u16>) -> Xhttp {
    let mut settings = serde_json::json!({
        "network": "xhttp",
        "xhttpSettings": {
            "path": "/test", "loadBalancer": "round_robin",
            "upload": {"address": "xhttp.test.invalid", "port": upload}
        }
    });
    if let Some(port) = download {
        settings["xhttpSettings"]["download"] = serde_json::json!({"address": "download.test.invalid", "port": port});
    }
    Xhttp::new(&serde_json::from_value(settings).unwrap(), None, Arc::new(DnsResolver)).unwrap()
}

async fn discover(transport: &Xhttp, ips: &[IpAddr]) {
    transport
        .upload_pool
        .discover(transport.settings.upload.as_ref().unwrap(), || async { Ok(ips.to_vec()) })
        .await
        .unwrap();
}

async fn states(pool: &ClientPool, port: u16) -> [Arc<TargetState>; 2] {
    let key = |ip| GrpcTargetKey::Tcp(SocketAddr::new(ip, port));
    let first = pool.balancer.select_target(&[key(IPS[1])]).await.unwrap();
    let second = pool.balancer.select_target(&[key(IPS[0])]).await.unwrap();
    [first.state, second.state]
}

fn destination() -> Address {
    Address::Inet(SocketAddr::new(IPS[0], 1))
}

async fn echo(stream: &mut super::super::TrStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut received = vec![0; payload.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
async fn one_stream_peer_expands_for_posts_and_later_gets_then_reuses() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let servers = Backends::start(1, Arc::default()).await;
        let transport = transport(servers.port, None);
        discover(&transport, &IPS[..1]).await;
        let dest = destination();
        let mut first = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        echo(&mut first, b"POST while the first GET stays open").await;
        assert!(servers.counts()[0] >= 2, "GET and POST cannot share a capacity-one connection");
        let warm = servers.counts();
        for _ in 0..8 {
            echo(&mut first, b"reuse the completed POST slot").await;
        }
        assert_eq!(servers.counts(), warm, "serial POSTs must reuse released capacity");

        // The second GET may consume the spare POST connection or open another.
        // Neither it nor either tunnel's next POST may wait for the first GET to end.
        let mut second = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        echo(&mut second, b"second GET is live too").await;
        echo(&mut first, b"first GET is still live").await;
        assert!(servers.counts()[0] >= 3);
        assert_eq!(servers.counts()[1], 0);
        let warm = servers.counts();
        for _ in 0..8 {
            echo(&mut first, b"first serial POST").await;
            echo(&mut second, b"second serial POST").await;
        }
        assert_eq!(servers.counts(), warm, "completed POST slots must remain reusable");
    })
    .await
    .expect("capacity-one GET/POST expansion stalled");
}

#[tokio::test]
async fn low_peer_limit_expands_both_ips_without_unbalancing_tunnel_leases() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let servers = Backends::start(1, Arc::default()).await;
        let transport = transport(servers.port, None);
        discover(&transport, &IPS).await;
        let states = states(&transport.upload_pool, servers.port).await;
        let dest = destination();
        let mut streams = futures::future::join_all((0..8).map(|_| transport.connect(&dest, Protocol::Tcp)))
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        assert_eq!(states.each_ref().map(|state| state.inflight()), [4, 4]);
        futures::future::join_all(
            streams
                .iter_mut()
                .map(|stream| echo(stream, b"low-limit multi-IP echo")),
        )
        .await;
        let counts = servers.counts();
        // Four long GETs plus at least one POST slot on each IP. At most one
        // connection per concurrent request is needed, even during expansion.
        assert!(
            counts.into_iter().all(|count| (5..=8).contains(&count)),
            "accepts per IP: {counts:?}"
        );
        assert_eq!(states.each_ref().map(|state| state.inflight()), [4, 4]);
        for stream in &mut streams {
            echo(stream, b"reuse each IP's spare capacity").await;
        }
        assert_eq!(servers.counts(), counts);
        drop(streams);
        assert_eq!(states.each_ref().map(|state| state.inflight()), [0, 0]);
    })
    .await
    .expect("multi-IP capacity expansion stalled");
}

#[tokio::test]
async fn zero_advertised_capacity_returns_error_without_reconnect_storm() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let servers = Backends::start(0, Arc::default()).await;
        let transport = transport(servers.port, None);
        discover(&transport, &IPS).await;
        let states = states(&transport.upload_pool, servers.port).await;
        let error = tokio::time::timeout(Duration::from_secs(5), transport.connect(&destination(), Protocol::Tcp))
            .await
            .expect("zero peer capacity must return an explicit error, not wait indefinitely")
            .err()
            .expect("a peer advertising zero streams cannot establish a tunnel");
        assert!(!error.to_string().is_empty());
        let counts = servers.counts();
        assert!(
            counts.into_iter().all(|count| count <= 1),
            "zero-capacity reconnect storm: {counts:?}"
        );
        assert!(counts.into_iter().sum::<usize>() >= 1);
        assert_eq!(states.each_ref().map(|state| state.inflight()), [0, 0]);
    })
    .await
    .expect("zero-capacity regression timed out");
}

#[tokio::test]
async fn separate_upload_endpoint_retries_healthy_ip_before_returning_tunnel() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let sessions: packet::PacketSessions = Arc::default();
        let upload = Backends::start(1, sessions.clone()).await;
        let download = Backends::start(1, sessions).await;
        let transport = transport(upload.port, Some(download.port));
        let refused = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
        discover(&transport, &[refused, IPS[0]]).await;
        transport
            .download_pool
            .discover(transport.settings.download.as_ref().unwrap(), || async { Ok(vec![IPS[1]]) })
            .await
            .unwrap();
        let key = |ip| GrpcTargetKey::Tcp(SocketAddr::new(ip, upload.port));
        let failed = transport
            .upload_pool
            .balancer
            .select_target(&[key(IPS[0])])
            .await
            .unwrap()
            .state;
        let healthy = transport
            .upload_pool
            .balancer
            .select_target(&[key(refused)])
            .await
            .unwrap()
            .state;
        let dest = destination();
        let mut stream = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        assert_eq!(failed.inflight(), 0);
        assert_eq!(healthy.inflight(), 1);
        echo(&mut stream, b"separate upload retries before exposing the tunnel").await;
        assert_eq!(upload.counts(), [1, 0]);
        assert_eq!(download.counts(), [0, 1]);
        drop(stream);
        assert_eq!(failed.inflight(), 0);
        assert_eq!(healthy.inflight(), 0);
    })
    .await
    .expect("separate upload endpoint failover stalled");
}

#[tokio::test]
async fn separate_low_limit_endpoints_expand_downloads_and_reuse_uploads() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let sessions: packet::PacketSessions = Arc::default();
        let upload = Backends::start(1, sessions.clone()).await;
        let download = Backends::start(1, sessions).await;
        let transport = transport(upload.port, Some(download.port));
        discover(&transport, &IPS[..1]).await;
        transport
            .download_pool
            .discover(transport.settings.download.as_ref().unwrap(), || async { Ok(vec![IPS[1]]) })
            .await
            .unwrap();
        let dest = destination();
        let mut streams = Vec::new();
        for _ in 0..4 {
            let mut stream = transport.connect(&dest, Protocol::Tcp).await.unwrap();
            echo(&mut stream, b"GET and POST use separate endpoints").await;
            streams.push(stream);
        }
        assert_eq!(upload.counts(), [1, 0], "serial uploads should share one connection");
        assert_eq!(download.counts(), [0, 4], "each long GET needs its own capacity-one connection");
        for stream in &mut streams {
            echo(stream, b"separate endpoint capacity is reusable").await;
        }
        assert_eq!(upload.counts(), [1, 0]);
        assert_eq!(download.counts(), [0, 4]);
    })
    .await
    .expect("separate low-limit endpoints stalled");
}
