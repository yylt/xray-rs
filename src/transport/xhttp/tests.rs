use super::super::balancer::{GrpcTargetKey, TargetState};
use super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

const IPS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
];

struct Backends {
    port: u16,
    accepts: [Arc<AtomicUsize>; 2],
    tasks: Vec<JoinHandle<()>>,
    resets: Vec<mpsc::Sender<tokio::sync::oneshot::Sender<()>>>,
}

impl Backends {
    async fn start() -> Self {
        let first = TcpListener::bind((IPS[0], 0)).await.unwrap();
        let port = first.local_addr().unwrap().port();
        let second = TcpListener::bind((IPS[1], port)).await.unwrap();
        let accepts = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        let mut tasks = Vec::new();
        let mut resets = Vec::new();
        for (listener, count) in [first, second].into_iter().zip(accepts.iter().cloned()) {
            let (reset_tx, mut reset_rx) = mpsc::channel::<tokio::sync::oneshot::Sender<()>>(1);
            resets.push(reset_tx);
            tasks.push(tokio::spawn(async move {
                let packet_sessions: packet::PacketSessions = Arc::default();
                let (tx, mut rx) = mpsc::channel(32);
                let mut children = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (socket, peer) = accepted.unwrap();
                            count.fetch_add(1, Ordering::SeqCst);
                            children.spawn(Xhttp::serve_connection(
                                TokioIo::new(socket), packet_sessions.clone(), tx.clone(),
                                "/test".to_owned(), DEFAULT_HTTP2_INITIAL_STREAM_WINDOW, Address::Inet(peer),
                            ));
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
                        Some(done) = reset_rx.recv() => {
                            children.shutdown().await;
                            let _ = done.send(());
                        }
                        Some(result) = children.join_next() => { result.unwrap(); }
                    }
                }
            }));
        }
        Self {
            port,
            accepts,
            tasks,
            resets,
        }
    }
}

impl Drop for Backends {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn transport(port: u16, strategy: &str) -> Xhttp {
    let settings = serde_json::from_value(serde_json::json!({
        "network": "xhttp",
        "xhttpSettings": {
            "path": "/test", "loadBalancer": strategy,
            "upload": {"address": "xhttp.test.invalid", "port": port}
        }
    }))
    .unwrap();
    Xhttp::new(&settings, None, Arc::new(DnsResolver)).unwrap()
}

fn key(port: u16, ip: IpAddr) -> GrpcTargetKey {
    GrpcTargetKey::Tcp(SocketAddr::new(ip, port))
}

async fn states(pool: &ClientPool, port: u16) -> [Arc<TargetState>; 2] {
    let first = pool.balancer.select_target(&[key(port, IPS[1])]).await.unwrap();
    let second = pool.balancer.select_target(&[key(port, IPS[0])]).await.unwrap();
    [first.state, second.state]
}

async fn echo(stream: &mut super::super::TrStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut received = vec![0; payload.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);
}

async fn concurrent_tunnels() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let servers = Backends::start().await;
        let transport = transport(servers.port, "round_robin");
        let config = transport.settings.upload.as_ref().unwrap();
        transport
            .upload_pool
            .discover(config, || async { Ok(IPS.to_vec()) })
            .await
            .unwrap();
        let states = states(&transport.upload_pool, servers.port).await;
        let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
        let mut streams = futures::future::join_all((0..8).map(|_| transport.connect(&dest, Protocol::Tcp)))
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        assert_eq!(states.each_ref().map(|state| state.inflight()), [4, 4]);
        futures::future::join_all(streams.iter_mut().map(|stream| echo(stream, b"multiplexed echo"))).await;
        assert_eq!(servers.accepts.each_ref().map(|count| count.load(Ordering::SeqCst)), [1, 1]);
        drop(streams);
        assert_eq!(states.each_ref().map(|state| state.inflight()), [0, 0]);
        // A later tunnel must reuse the still-live cached connection, too.
        let mut stream = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        echo(&mut stream, b"reuse after drop").await;
        assert_eq!(servers.accepts.each_ref().map(|count| count.load(Ordering::SeqCst)), [1, 1]);
    })
    .await
    .expect("loopback tunnels timed out");
}

#[tokio::test]
async fn packet_up_sessions_share_one_connection_per_ip() {
    concurrent_tunnels().await;
}

#[tokio::test]
async fn omitted_mode_uses_packet_up_and_unknown_mode_is_rejected() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let servers = Backends::start().await;
        let mut settings: StreamSettings = serde_json::from_value(serde_json::json!({
            "network": "xhttp",
            "xhttpSettings": {
                "path": "/test",
                "upload": {"address": "xhttp.test.invalid", "port": servers.port}
            }
        }))
        .unwrap();
        let transport = Xhttp::new(&settings, None, Arc::new(DnsResolver)).unwrap();
        transport
            .upload_pool
            .discover(transport.settings.upload.as_ref().unwrap(), || async { Ok(vec![IPS[0]]) })
            .await
            .unwrap();
        let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
        let mut stream = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        echo(&mut stream, b"packet-up default").await;
        stream.flush().await.unwrap();

        for mode in ["stream-up", "stream-one", "packate-up", "unknown-mode"] {
            settings.xhttp_settings.as_mut().unwrap().mode = Some(mode.to_owned());
            let error = Xhttp::new(&settings, None, Arc::new(DnsResolver))
                .err()
                .expect("unsupported mode must fail at construction");
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
    })
    .await
    .expect("default mode packet-up echo timed out");
}

#[tokio::test]
async fn packet_up_large_bidirectional_echo_exceeds_buffers() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let servers = Backends::start().await;
        let transport = transport(servers.port, "round_robin");
        transport
            .upload_pool
            .discover(transport.settings.upload.as_ref().unwrap(), || async { Ok(vec![IPS[0]]) })
            .await
            .unwrap();
        let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
        let stream = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        let payload = (0..2 * 1024 * 1024 + 123).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let mut received = vec![0; payload.len()];
        let (mut reader, mut writer) = tokio::io::split(stream);
        // Drain the echo while uploading: a sequential write/read would deadlock
        // on bounded HTTP, packet, and business-stream buffers.
        tokio::try_join!(
            async {
                writer.write_all(&payload).await?;
                writer.flush().await
            },
            reader.read_exact(&mut received),
        )
        .unwrap();
        assert_eq!(received, payload);
    })
    .await
    .expect("large packet-up echo stalled");
}

#[tokio::test]
async fn closed_cached_connection_redials_same_target() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let servers = Backends::start().await;
        let transport = transport(servers.port, "round_robin");
        let pool = &transport.upload_pool;
        pool.discover(transport.settings.upload.as_ref().unwrap(), || async { Ok(vec![IPS[0]]) })
            .await
            .unwrap();
        let target = key(servers.port, IPS[0]);
        let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
        let mut first = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        echo(&mut first, b"before disconnect").await;
        drop(first);
        let cached = pool.balancer.cached_channel(&target).await.unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        servers.resets[0].send(done_tx).await.unwrap();
        done_rx.await.unwrap();
        while !cached.is_closed() {
            tokio::task::yield_now().await;
        }
        let mut second = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        echo(&mut second, b"after reconnect").await;
        assert!(cached.is_closed());
        assert!(!pool.balancer.cached_channel(&target).await.unwrap().is_closed());
        assert_eq!(servers.accepts[0].load(Ordering::SeqCst), 2);
    })
    .await
    .expect("closed cached connection did not reconnect");
}

#[tokio::test]
async fn least_connection_reserves_before_network_and_releases_on_cancel() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let servers = Backends::start().await;
        let transport = transport(servers.port, "least_connection");
        transport
            .upload_pool
            .discover(transport.settings.upload.as_ref().unwrap(), || async { Ok(IPS.to_vec()) })
            .await
            .unwrap();
        let pool = &transport.upload_pool;
        let states = states(pool, servers.port).await;
        let locks = [
            pool.balancer.channel_lock(&key(servers.port, IPS[0])).await.unwrap(),
            pool.balancer.channel_lock(&key(servers.port, IPS[1])).await.unwrap(),
        ];
        let guards = [locks[0].lock().await, locks[1].lock().await];
        let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
        let mut opens = (0..8)
            .map(|_| Box::pin(transport.connect(&dest, Protocol::Tcp)))
            .collect::<Vec<_>>();
        for open in &mut opens {
            std::future::poll_fn(|cx| {
                assert!(std::future::Future::poll(open.as_mut(), cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(states.each_ref().map(|state| state.inflight()), [4, 4]);
        assert_eq!(servers.accepts.each_ref().map(|count| count.load(Ordering::SeqCst)), [0, 0]);
        drop(opens);
        assert_eq!(states.each_ref().map(|state| state.inflight()), [0, 0]);
        drop(guards);
        let mut stream = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        assert_eq!(states.iter().map(|state| state.inflight()).sum::<usize>(), 1);
        echo(&mut stream, b"after cancellation").await;
        drop(stream);
        assert_eq!(states.each_ref().map(|state| state.inflight()), [0, 0]);
    })
    .await
    .expect("cancelled opens failed to recover");
}

#[tokio::test]
async fn refused_target_retries_healthy_ip_without_leaking_lease() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut servers = Backends::start().await;
        servers.tasks[0].abort();
        assert!((&mut servers.tasks[0]).await.as_ref().unwrap_err().is_cancelled());
        let transport = transport(servers.port, "round_robin");
        transport
            .upload_pool
            .discover(transport.settings.upload.as_ref().unwrap(), || async { Ok(IPS.to_vec()) })
            .await
            .unwrap();
        let states = states(&transport.upload_pool, servers.port).await;
        let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
        let mut stream = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        assert_eq!(states.each_ref().map(|state| state.inflight()), [0, 1]);
        echo(&mut stream, b"healthy fallback").await;
        assert_eq!(servers.accepts.each_ref().map(|count| count.load(Ordering::SeqCst)), [0, 1]);
        drop(stream);
        assert_eq!(states.each_ref().map(|state| state.inflight()), [0, 0]);
    })
    .await
    .expect("failover timed out");
}

#[tokio::test]
async fn discovery_failure_recovers_and_refresh_preserves_live_tunnels() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let servers = Backends::start().await;
        let transport = transport(servers.port, "round_robin");
        let pool = &transport.upload_pool;
        let config = transport.settings.upload.as_ref().unwrap();
        assert!(pool
            .discover(config, || async { Err(Error::other("DNS unavailable")) })
            .await
            .is_err());
        assert!(pool
            .discover(config, || async { panic!("initial DNS backoff ignored") })
            .await
            .is_err());
        pool.discovery.lock().await.retry_at = None;
        let resolutions = AtomicUsize::new(0);
        let discovered = futures::future::join_all((0..8).map(|_| {
            pool.discover(config, || async {
                resolutions.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                Ok(vec![IPS[0], IPS[1], IPS[0]])
            })
        }))
        .await;
        let generation = discovered[0].as_ref().copied().unwrap();
        assert!(discovered
            .iter()
            .all(|result| result.as_ref().is_ok_and(|value| *value == generation)));
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        // Remove success backoff so this exercises freshness, not retry throttling.
        pool.discovery.lock().await.retry_at = None;
        assert_eq!(
            pool.discover(config, || async { panic!("fresh snapshot resolved again") })
                .await
                .unwrap(),
            generation
        );
        let states = states(pool, servers.port).await;
        let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
        let mut old = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        assert_eq!(states.each_ref().map(|state| state.inflight()), [1, 0]);
        {
            let mut discovery = pool.discovery.lock().await;
            discovery.refresh_at = Some(Instant::now());
            discovery.retry_at = None;
        }
        assert_eq!(
            pool.discover(config, || async { Err(Error::other("refresh failed")) })
                .await
                .unwrap(),
            generation
        );
        assert!(pool.balancer.cached_channel(&key(servers.port, IPS[0])).await.is_some());
        assert_eq!(
            pool.discover(config, || async { panic!("refresh backoff ignored") })
                .await
                .unwrap(),
            generation
        );
        echo(&mut old, b"survives failed refresh").await;
        pool.discovery.lock().await.retry_at = None;
        let refreshed = pool
            .discover(config, || async { Ok(vec![IPS[1], IPS[1]]) })
            .await
            .unwrap();
        assert_ne!(refreshed, generation);
        assert!(states[0].is_draining());
        assert_eq!(states[0].inflight(), 1);
        let mut new = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        assert_eq!(states.each_ref().map(|state| state.inflight()), [1, 1]);
        echo(&mut old, b"draining is not disconnected").await;
        echo(&mut new, b"replacement target").await;
        assert_eq!(servers.accepts.each_ref().map(|count| count.load(Ordering::SeqCst)), [1, 1]);
        drop((old, new));
        assert_eq!(states.each_ref().map(|state| state.inflight()), [0, 0]);
    })
    .await
    .expect("DNS refresh regression timed out");
}

// Model a proxy that does not return POST headers until upload data arrives.
async fn delayed_post_headers_server(tasks: &mut JoinSet<()>, reject_upload: bool) -> Xhttp {
    let listener = TcpListener::bind((IPS[0], 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (echo_tx, echo_rx) = mpsc::channel(1);
    let echo_rx = Arc::new(Mutex::new(Some(echo_rx)));
    let uploaded = Arc::new(tokio::sync::Notify::new());
    tasks.spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let echo_tx = echo_tx.clone();
            let echo_rx = echo_rx.clone();
            let uploaded = uploaded.clone();
            let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                let echo_tx = echo_tx.clone();
                let echo_rx = echo_rx.clone();
                let uploaded = uploaded.clone();
                async move {
                    let response = if request.method() == http::Method::GET {
                        // Model both response headers deferred until upload starts.
                        uploaded.notified().await;
                        Xhttp::stream_response(
                            StatusCode::OK,
                            ChannelBody {
                                rx: echo_rx.lock().await.take().unwrap(),
                            },
                        )
                    } else {
                        assert_eq!(request.method(), http::Method::POST);
                        let mut body = request.into_body();
                        let bytes = loop {
                            let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                                .await
                                .expect("POST ended before upload data")
                                .unwrap();
                            match frame.into_data() {
                                Ok(bytes) if !bytes.is_empty() => break bytes,
                                _ => {}
                            }
                        };
                        uploaded.notify_one();
                        if reject_upload {
                            Xhttp::stream_response(StatusCode::FORBIDDEN, Xhttp::empty_body())
                        } else {
                            echo_tx.send(Ok(Frame::data(bytes))).await.unwrap();
                            Xhttp::stream_response(StatusCode::OK, Xhttp::empty_body())
                        }
                    };
                    Ok::<_, Infallible>(response)
                }
            });
            connections.spawn(async move {
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let transport = transport(port, "round_robin");
    transport
        .upload_pool
        .discover(transport.settings.upload.as_ref().unwrap(), || async { Ok(vec![IPS[0]]) })
        .await
        .unwrap();
    transport
}

#[tokio::test]
async fn packet_up_flush_waits_for_http_ack_and_shutdown_sends_no_packet() {
    let mut tasks = JoinSet::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        let listener = TcpListener::bind((IPS[0], 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
        let observed_tx = Arc::new(Mutex::new(Some(observed_tx)));
        let release = Arc::new(tokio::sync::Notify::new());
        let server_release = release.clone();
        let uploads = Arc::new(AtomicUsize::new(0));
        let server_uploads = uploads.clone();
        let (_download_tx, download_rx) = mpsc::channel(1);
        let download_rx = Arc::new(Mutex::new(Some(download_rx)));
        tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                let observed_tx = observed_tx.clone();
                let release = server_release.clone();
                let uploads = server_uploads.clone();
                let download_rx = download_rx.clone();
                async move {
                    let response = if request.method() == http::Method::GET {
                        Xhttp::stream_response(
                            StatusCode::OK,
                            ChannelBody {
                                rx: download_rx.lock().await.take().unwrap(),
                            },
                        )
                    } else {
                        assert_eq!(request.method(), http::Method::POST);
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        assert_eq!(&body[..], b"wait for ACK");
                        uploads.fetch_add(1, Ordering::SeqCst);
                        observed_tx.lock().await.take().unwrap().send(()).unwrap();
                        release.notified().await;
                        Xhttp::stream_response(StatusCode::OK, Xhttp::empty_body())
                    };
                    Ok::<_, Infallible>(response)
                }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(socket), service)
                .await;
        });
        let transport = transport(port, "round_robin");
        transport
            .upload_pool
            .discover(transport.settings.upload.as_ref().unwrap(), || async { Ok(vec![IPS[0]]) })
            .await
            .unwrap();
        let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
        let mut stream = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        stream.write_all(b"wait for ACK").await.unwrap();
        observed_rx.await.unwrap();
        let mut flush = Box::pin(stream.flush());
        std::future::poll_fn(|cx| {
            assert!(flush.as_mut().poll(cx).is_pending(), "flush completed before HTTP ACK");
            Poll::Ready(())
        })
        .await;
        release.notify_one();
        flush.await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(uploads.load(Ordering::SeqCst), 1);
    })
    .await
    .expect("packet-up delayed HTTP ACK timed out");
}

#[tokio::test]
async fn packet_up_http_rejection_surfaces_on_flush_and_read() {
    let mut tasks = JoinSet::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        for read_error in [false, true] {
            let transport = delayed_post_headers_server(&mut tasks, true).await;
            let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
            let mut stream = transport.connect(&dest, Protocol::Tcp).await.unwrap();
            stream.write_all(b"trigger packet 403").await.unwrap();
            let error = if read_error {
                stream
                    .read(&mut [0; 1])
                    .await
                    .expect_err("POST 403 must not become EOF")
            } else {
                stream.flush().await.expect_err("flush must wait for the HTTP ACK")
            };
            assert!(error.to_string().contains("403"), "unexpected upload error: {error}");
        }
    })
    .await
    .expect("packet-up HTTP rejection did not reach flush/read");
}

#[tokio::test]
async fn packet_up_get_eof_before_upload_disallows_write_and_flush() {
    let mut tasks = JoinSet::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        let listener = TcpListener::bind((IPS[0], 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let service = hyper::service::service_fn(|request: Request<Incoming>| async move {
                assert_eq!(request.method(), http::Method::GET, "upload must not start after GET EOF");
                Ok::<_, Infallible>(Xhttp::stream_response(StatusCode::OK, Xhttp::empty_body()))
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(socket), service)
                .await;
        });
        let transport = transport(port, "round_robin");
        transport
            .upload_pool
            .discover(transport.settings.upload.as_ref().unwrap(), || async { Ok(vec![IPS[0]]) })
            .await
            .unwrap();
        let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
        let mut stream = transport.connect(&dest, Protocol::Tcp).await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(stream.flush().await.unwrap_err().kind(), ErrorKind::BrokenPipe);
        assert_eq!(stream.write_all(b"too late").await.unwrap_err().kind(), ErrorKind::BrokenPipe);
        assert_eq!(stream.flush().await.unwrap_err().kind(), ErrorKind::BrokenPipe);
    })
    .await
    .expect("packet-up failed to observe GET EOF before upload");
}

// Read the SETTINGS frame that advertises SETTINGS_INITIAL_WINDOW_SIZE.
async fn advertised_window<S: tokio::io::AsyncRead + Unpin>(socket: &mut S, expect_preface: bool) -> u32 {
    if expect_preface {
        let mut preface = [0; 24];
        socket.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    }
    loop {
        let mut header = [0; 9];
        socket.read_exact(&mut header).await.unwrap();
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0; length];
        socket.read_exact(&mut payload).await.unwrap();
        if header[3] == 4 && header[4] & 1 == 0 {
            for setting in payload.as_chunks::<6>().0 {
                if setting[..2] == [0, 4] {
                    return u32::from_be_bytes(setting[2..].try_into().unwrap());
                }
            }
            // An omitted SETTINGS_INITIAL_WINDOW_SIZE means the protocol default.
            return 65_535;
        }
    }
}

#[tokio::test]
async fn configured_window_is_advertised_on_the_client_wire() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind((IPS[0], 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let settings: StreamSettings = serde_json::from_value(serde_json::json!({
            "network": "xhttp",
            "xhttpSettings": {
                "path": "/test", "http2InitialWindowSize": 4_194_304,
                "upload": {"address": "127.0.0.1", "port": port}
            }
        }))
        .unwrap();
        let transport = Xhttp::new(&settings, None, Arc::new(DnsResolver)).unwrap();
        let dest = Address::Inet(SocketAddr::new(IPS[0], 1));
        let dial = tokio::spawn(async move { drop(transport.connect(&dest, Protocol::Tcp).await) });
        let (mut socket, _) = listener.accept().await.unwrap();
        assert_eq!(advertised_window(&mut socket, true).await, 4_194_304);
        dial.abort();
        let _ = dial.await;
    })
    .await
    .expect("client window advertisement timed out");
}

#[tokio::test]
async fn configured_window_is_advertised_on_the_server_wire() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let settings: StreamSettings = serde_json::from_value(serde_json::json!({
            "network": "xhttp",
            "xhttpSettings": {"path": "/test", "http2InitialWindowSize": 4_194_304}
        }))
        .unwrap();
        let transport = Xhttp::new(&settings, None, Arc::new(DnsResolver)).unwrap();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (stx, _rx) = mpsc::channel(1);
        tokio::spawn(Xhttp::serve_connection(
            TokioIo::new(server),
            Arc::default(),
            stx,
            "/test".to_owned(),
            transport.h2_window,
            Address::Inet(SocketAddr::new(IPS[0], 1)),
        ));
        client.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
        // An empty peer SETTINGS frame keeps the server handshake progressing.
        client.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
        assert_eq!(advertised_window(&mut client, false).await, 4_194_304);
    })
    .await
    .expect("server window advertisement timed out");
}
