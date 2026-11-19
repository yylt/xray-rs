use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server {
    sender: SendRequest<ChannelBody>,
    sessions: packet::PacketSessions,
    accepted: mpsc::Receiver<(super::super::TrStream, Address)>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Server {
    async fn start(capacity: usize) -> Self {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let sessions: packet::PacketSessions = Arc::default();
        let (tx, accepted) = mpsc::channel(capacity);
        let server_task = tokio::spawn(Xhttp::serve_connection(
            TokioIo::new(server),
            sessions.clone(),
            tx,
            "/test".to_owned(),
            DEFAULT_HTTP2_INITIAL_STREAM_WINDOW,
            Address::Inet("127.0.0.1:12345".parse().unwrap()),
        ));
        let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(client))
            .await
            .unwrap();
        let client_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        Self {
            sender,
            sessions,
            accepted,
            tasks: vec![server_task, client_task],
        }
    }

    async fn request(&mut self, method: &str, suffix: &str, data: &[u8], length: Option<usize>) -> Response<Incoming> {
        let (tx, rx) = mpsc::channel(1);
        if !data.is_empty() {
            tx.try_send(Ok(Frame::data(Bytes::copy_from_slice(data)))).unwrap();
        }
        drop(tx);
        let mut request = Request::builder()
            .method(method)
            .uri(format!("http://localhost/test/{suffix}"));
        if let Some(length) = length {
            request = request.header(header::CONTENT_LENGTH, length);
        }
        self.sender.ready().await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            self.sender.send_request(request.body(ChannelBody { rx }).unwrap()),
        )
        .await
        .expect("packet request hung")
        .unwrap()
    }

    async fn wait_removed(&self, id: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.sessions.lock().await.contains_key(id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("closed GET left its packet session behind");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[tokio::test]
async fn packet_requests_validate_length_sequence_and_identity() {
    let mut server = Server::start(8).await;
    let id = uuid::Uuid::new_v4().to_string();
    let path = format!("{id}/0");
    assert_eq!(
        server.request("POST", &path, b"x", None).await.status(),
        StatusCode::LENGTH_REQUIRED
    );
    assert_eq!(
        server
            .request("POST", &path, &vec![0; 64 * 1024 + 1], Some(64 * 1024 + 1))
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        server.request("POST", &format!("{id}/1"), b"x", Some(1)).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        server.request("POST", "not-a-uuid/0", b"x", Some(1)).await.status(),
        StatusCode::BAD_REQUEST
    );
    let boundary = Request::builder()
        .method("GET")
        .uri(format!("http://localhost/test-other/{id}"))
        .body(Xhttp::empty_body())
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), server.sender.send_request(boundary))
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    // Rejected requests must release sequence zero rather than poison its reservation.
    let response = server.request("POST", &path, b"first", Some(5)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "0");
    assert!(response.into_body().collect().await.unwrap().to_bytes().is_empty());
    assert_eq!(
        server.request("POST", &path, b"duplicate", Some(9)).await.status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn packet_post_before_get_delivers_once_and_get_drop_reclaims_session() {
    let mut server = Server::start(8).await;
    let id = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        server
            .request("POST", &format!("{id}/0"), b"before GET", Some(10))
            .await
            .status(),
        StatusCode::OK
    );
    assert!(server.accepted.try_recv().is_err());
    let response = server.request("GET", &id, &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), server.accepted.recv())
        .await
        .unwrap()
        .unwrap();
    let mut bytes = [0; 10];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"before GET");
    assert_eq!(server.request("GET", &id, &[], None).await.status(), StatusCode::CONFLICT);
    assert!(server.accepted.try_recv().is_err());
    assert_eq!(
        server
            .request("POST", &format!("{id}/0"), b"duplicate", Some(9))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        server
            .request("POST", &format!("{id}/1"), b"next", Some(4))
            .await
            .status(),
        StatusCode::OK
    );
    let mut next = [0; 4];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut next))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&next, b"next");
    stream.write_all(b"download").await.unwrap();
    let mut body = response.into_body();
    let frame = tokio::time::timeout(Duration::from_secs(2), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.into_data().unwrap(), "download");
    drop(body);
    server.wait_removed(&id).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut next))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn packet_post_without_get_expires_without_subsequent_requests() {
    let mut server = Server::start(8).await;
    let id = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        server
            .request("POST", &format!("{id}/0"), b"orphan", Some(6))
            .await
            .status(),
        StatusCode::OK
    );
    assert!(server.sessions.lock().await.contains_key(&id));
    tokio::time::timeout(Duration::from_secs(32), async {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            if !server.sessions.lock().await.contains_key(&id) {
                break;
            }
        }
    })
    .await
    .expect("POST-only session did not expire without further traffic");
    assert!(server.accepted.try_recv().is_err());
}

#[tokio::test]
async fn packet_slow_business_reader_backpressures_posts_without_losing_bytes() {
    let mut server = Server::start(8).await;
    let id = uuid::Uuid::new_v4().to_string();
    let response = server.request("GET", &id, &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(2), server.accepted.recv())
        .await
        .unwrap()
        .unwrap();
    let packet_size = 64 * 1024;
    let mut expected = Vec::new();
    let mut backpressured = false;
    // The duplex buffer, in-progress bridge write and queued packet must not
    // acknowledge unlimited uploads while business reads nothing.
    for seq in 0..8u8 {
        let data = vec![seq; packet_size];
        expected.extend_from_slice(&data);
        let path = format!("{id}/{seq}");
        let request = server.request("POST", &path, &data, Some(packet_size));
        tokio::pin!(request);
        match tokio::time::timeout(Duration::from_millis(50), request.as_mut()).await {
            Ok(response) => assert_eq!(response.status(), StatusCode::OK),
            Err(_) => {
                backpressured = true;
                let mut received = vec![0; expected.len()];
                let (ack, read) = tokio::time::timeout(Duration::from_secs(2), async {
                    tokio::join!(request.as_mut(), stream.read_exact(&mut received))
                })
                .await
                .expect("draining business stream did not release POST backpressure");
                assert_eq!(ack.status(), StatusCode::OK);
                read.unwrap();
                assert_eq!(received, expected);
                break;
            }
        }
    }
    assert!(backpressured, "server ACKed eight full packets without a business reader");
    drop(response);
    server.wait_removed(&id).await;
}

#[tokio::test]
async fn packet_business_drop_ends_get_and_reclaims_session() {
    let mut server = Server::start(8).await;
    let id = uuid::Uuid::new_v4().to_string();
    let response = server.request("GET", &id, &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let (stream, _) = tokio::time::timeout(Duration::from_secs(2), server.accepted.recv())
        .await
        .unwrap()
        .unwrap();
    drop(stream);
    let body = tokio::time::timeout(Duration::from_secs(2), response.into_body().collect())
        .await
        .unwrap()
        .unwrap();
    assert!(body.to_bytes().is_empty());
    server.wait_removed(&id).await;
}

#[tokio::test]
async fn packet_full_accept_queue_rejects_get_without_leaking_session() {
    let mut server = Server::start(1).await;
    let first = uuid::Uuid::new_v4().to_string();
    let first_response = server.request("GET", &first, &[], None).await;
    assert_eq!(first_response.status(), StatusCode::OK);
    let second = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        server.request("GET", &second, &[], None).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(!server.sessions.lock().await.contains_key(&second));
    drop(first_response);
    server.wait_removed(&first).await;
}

// Each HTTP/1 request gets its own connection, as a proxy can do. The long GET
// must not occupy the connection used for subsequent finite packet POSTs.
struct Http1Server {
    sessions: packet::PacketSessions,
    tx: mpsc::Sender<(super::super::TrStream, Address)>,
    accepted: mpsc::Receiver<(super::super::TrStream, Address)>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Http1Server {
    fn new() -> Self {
        let (tx, accepted) = mpsc::channel(8);
        Self {
            sessions: Arc::default(),
            tx,
            accepted,
            tasks: Vec::new(),
        }
    }

    async fn request(&mut self, version: http::Version, suffix: &str, data: Option<&[u8]>) -> Response<Incoming> {
        let (client, server) = tokio::io::duplex(4096);
        self.tasks.push(tokio::spawn(Xhttp::serve_connection(
            TokioIo::new(server),
            self.sessions.clone(),
            self.tx.clone(),
            "/test".to_owned(),
            DEFAULT_HTTP2_INITIAL_STREAM_WINDOW,
            Address::Unix("/dev/shm/xhttp.socket".into()),
        )));
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        self.tasks.push(tokio::spawn(async move {
            connection.await.unwrap();
        }));
        let (tx, rx) = mpsc::channel(1);
        let mut request = Request::builder()
            .version(version)
            .method(if data.is_some() { "POST" } else { "GET" })
            .uri(format!("/test/{suffix}"))
            .header(header::HOST, "localhost");
        if let Some(data) = data {
            request = request.header(header::CONTENT_LENGTH, data.len());
            tx.try_send(Ok(Frame::data(Bytes::copy_from_slice(data)))).unwrap();
        }
        drop(tx);
        sender
            .send_request(request.body(ChannelBody { rx }).unwrap())
            .await
            .unwrap()
    }
}

impl Drop for Http1Server {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[tokio::test]
async fn partial_http1_request_reproduces_incomplete_message_without_a_packet_session() {
    // serve_connection logs and consumes its error, so use the same AutoBuilder
    // here to assert its type. An unfinished header never reaches the handler.
    let (mut client, server) = tokio::io::duplex(4096);
    let service = hyper::service::service_fn(|_: Request<Incoming>| async {
        Ok::<_, Infallible>(Xhttp::stream_response(StatusCode::OK, Xhttp::empty_body()))
    });
    let builder = AutoBuilder::new(TokioExecutor::new());
    let connection = builder.serve_connection(TokioIo::new(server), service);
    let partial = async {
        client
            .write_all(b"POST /test/00000000-0000-4000-8000-000000000001/0 HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(connection, partial) })
        .await
        .expect("partial HTTP request did not terminate");
    let error = result.unwrap_err();
    assert!(error.downcast_ref::<hyper::Error>().unwrap().is_incomplete_message());
}

#[tokio::test]
async fn truncated_http1_chunked_download_reports_incoming_body_frame_error() {
    // Deliberately truncate an HTTP/1.1 chunk, rather than merely close a valid
    // HTTP/1.0 close-delimited response. This reproduces a frame-error category,
    // not evidence that a proxy truncated the reported production connection.
    let (client, mut server) = tokio::io::duplex(4096);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        let exchange = async {
            let request = Request::builder()
                .uri("/test/00000000-0000-4000-8000-000000000001")
                .header(header::HOST, "localhost")
                .body(Xhttp::empty_body())
                .unwrap();
            let response = sender.send_request(request).await.unwrap();
            let mut download = StreamReader::new(IncomingStream {
                incoming: response.into_body(),
            });
            let error = download.read_to_end(&mut Vec::new()).await.unwrap_err();
            assert!(error.to_string().contains("error reading a body from connection"), "{error}");
        };
        let truncated = async {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(server.read_u8().await.unwrap());
            }
            server
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        };
        let (_, (), ()) = tokio::join!(connection, exchange, truncated);
    })
    .await
    .expect("truncated HTTP response did not terminate");
}

#[tokio::test]
async fn packet_http1_finite_upload_long_download_and_interactive_messages() {
    for version in [http::Version::HTTP_11] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut server = Http1Server::new();
            let id = "00000000-0000-4000-8000-000000000001";
            let ack = server
                .request(version, &format!("{id}/0"), Some(b"finite request"))
                .await;
            assert_eq!(ack.status(), StatusCode::OK);
            assert_eq!(ack.headers()[header::CONTENT_LENGTH], "0");
            assert!(ack.into_body().collect().await.unwrap().to_bytes().is_empty());
            let response = server.request(version, id, None).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
            assert_eq!(response.headers()[header::TRANSFER_ENCODING], "chunked");
            let (mut business, peer) = server.accepted.recv().await.unwrap();
            assert!(matches!(peer, Address::Unix(path) if path == std::path::Path::new("/dev/shm/xhttp.socket")));
            let mut request = [0; 14];
            business.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"finite request");
            let mut download = StreamReader::new(IncomingStream {
                incoming: response.into_body(),
            });
            // Larger than both the HTTP duplex and packet bridge buffers. The
            // business writer stays alive after sending it: EOF cannot flush it.
            let expected = vec![0x5a; 256 * 1024 + 17];
            let mut received = vec![0; expected.len()];
            let (write, read) = tokio::join!(business.write_all(&expected), download.read_exact(&mut received));
            write.unwrap();
            read.unwrap();
            assert_eq!(received, expected);
            for (seq, message) in [(1, b"ping"), (2, b"pong")] {
                let ack = server.request(version, &format!("{id}/{seq}"), Some(message)).await;
                assert_eq!(ack.status(), StatusCode::OK);
                assert!(ack.into_body().collect().await.unwrap().to_bytes().is_empty());
                let mut bytes = [0; 4];
                business.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, message);
                business.write_all(&bytes).await.unwrap();
                download.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, message);
            }
            drop(business);
            let mut trailing = Vec::new();
            download.read_to_end(&mut trailing).await.unwrap();
            assert!(trailing.is_empty());
        })
        .await
        .unwrap_or_else(|_| panic!("{version:?} packet exchange hung"));
    }
}
