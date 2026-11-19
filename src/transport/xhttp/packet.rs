//! Basic body/path packet-up: finite uploads and a long-lived download.
use super::*;
use bytes::BytesMut;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::Mutex as StdMutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;

const CLIENT_PACKET_SIZE: usize = 64 * 1024;
const MAX_PACKET_SIZE: usize = CLIENT_PACKET_SIZE;
const MAX_SESSIONS: usize = 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) type PacketSessions = Arc<Mutex<HashMap<String, Arc<PacketSession>>>>;

#[derive(Default)]
struct SessionState {
    active: bool,
    closed: bool,
    next: u64,
    // None reserves a sequence while its HTTP body is being read.
    packets: BTreeMap<u64, Option<Bytes>>,
}

pub(super) struct PacketSession {
    state: StdMutex<SessionState>,
    ready: Notify,
    capacity: Notify,
    upload_lock: Mutex<()>,
    expiry_cancel: Arc<Notify>,
}

impl PacketSession {
    fn new() -> Self {
        Self {
            state: StdMutex::new(SessionState::default()),
            ready: Notify::new(),
            capacity: Notify::new(),
            upload_lock: Mutex::new(()),
            expiry_cancel: Arc::new(Notify::new()),
        }
    }

    async fn reserve(self: &Arc<Self>, seq: u64) -> StdResult<Reservation, StatusCode> {
        loop {
            let available = self.capacity.notified();
            tokio::pin!(available);
            available.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap();
                if state.closed {
                    return Err(StatusCode::GONE);
                }
                // Serial uploads only; never acknowledge gaps or duplicate bytes.
                if seq != state.next || seq == u64::MAX || state.packets.contains_key(&seq) {
                    return Err(StatusCode::CONFLICT);
                }
                if state.packets.is_empty() {
                    state.packets.insert(seq, None);
                    return Ok(Reservation {
                        session: self.clone(),
                        seq,
                        committed: false,
                    });
                }
            }
            available.await;
        }
    }
}

struct Reservation {
    session: Arc<PacketSession>,
    seq: u64,
    committed: bool,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            self.session.state.lock().unwrap().packets.remove(&self.seq);
            self.session.capacity.notify_waiters();
        }
    }
}

fn response(status: StatusCode) -> Response<ChannelBody> {
    let mut response = Xhttp::stream_response(status, Xhttp::empty_body());
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
    response
}

fn parse_suffix(suffix: &str, post: bool) -> Option<(&str, Option<u64>)> {
    let mut parts = suffix.split('/');
    let id = parts.next()?;
    if id.len() != 36 || uuid::Uuid::parse_str(id).is_err() {
        return None;
    }
    let seq = if post {
        let raw = parts.next()?;
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(raw.parse().ok()?)
    } else {
        None
    };
    parts.next().is_none().then_some((id, seq))
}

pub(super) async fn handle(
    req: Request<Incoming>,
    sessions: PacketSessions,
    stx: mpsc::Sender<(super::super::TrStream, Address)>,
    peer: Address,
    suffix: &str,
) -> Response<ChannelBody> {
    let post = req.method() == http::Method::POST;
    if !post && req.method() != http::Method::GET {
        return response(StatusCode::METHOD_NOT_ALLOWED);
    }
    let Some((id, seq)) = parse_suffix(suffix, post) else {
        return response(StatusCode::BAD_REQUEST);
    };
    let id = id.to_owned();
    let session = {
        let mut map = sessions.lock().await;
        if let Some(session) = map.get(&id) {
            session.clone()
        } else {
            if map.len() >= MAX_SESSIONS {
                return response(StatusCode::SERVICE_UNAVAILABLE);
            }
            let session = Arc::new(PacketSession::new());
            map.insert(id.clone(), session.clone());
            let sessions = Arc::downgrade(&sessions);
            let weak_session = Arc::downgrade(&session);
            let id = id.clone();
            let expiry_cancel = session.expiry_cancel.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(REQUEST_TIMEOUT) => {},
                    _ = expiry_cancel.notified() => return,
                }
                if let (Some(sessions), Some(session)) = (sessions.upgrade(), weak_session.upgrade()) {
                    let mut map = sessions.lock().await;
                    let mut state = session.state.lock().unwrap();
                    if !state.active {
                        state.closed = true;
                        session.capacity.notify_waiters();
                        if map.get(&id).is_some_and(|current| Arc::ptr_eq(current, &session)) {
                            map.remove(&id);
                        }
                    }
                }
            });
            session
        }
    };

    if let Some(seq) = seq {
        // At most one pending POST per session, including capacity waiters.
        let Ok(_upload_guard) = session.upload_lock.try_lock() else {
            return response(StatusCode::CONFLICT);
        };
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        let mut reservation = match tokio::time::timeout_at(deadline, session.reserve(seq)).await {
            Ok(Ok(reservation)) => reservation,
            Ok(Err(status)) => return response(status),
            Err(_) => return response(StatusCode::REQUEST_TIMEOUT),
        };
        let declared = match req.headers().get(header::CONTENT_LENGTH) {
            Some(value) => match value.to_str().ok().and_then(|v| v.parse::<usize>().ok()) {
                Some(size) if size <= MAX_PACKET_SIZE => Some(size),
                Some(_) => return response(StatusCode::PAYLOAD_TOO_LARGE),
                None => return response(StatusCode::BAD_REQUEST),
            },
            None => return response(StatusCode::LENGTH_REQUIRED),
        };
        let collect = async {
            let mut body = req.into_body();
            let mut data = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
                if let Ok(bytes) = frame.into_data() {
                    if data.len().saturating_add(bytes.len()) > MAX_PACKET_SIZE {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    data.extend_from_slice(&bytes);
                }
            }
            if declared.is_some_and(|size| size != data.len()) {
                return Err(StatusCode::BAD_REQUEST);
            }
            Ok(Bytes::from(data))
        };
        let data = match tokio::time::timeout_at(deadline, collect).await {
            Ok(Ok(data)) => data,
            Ok(Err(status)) => return response(status),
            Err(_) => return response(StatusCode::REQUEST_TIMEOUT),
        };
        {
            let mut state = session.state.lock().unwrap();
            if state.closed {
                return response(StatusCode::GONE);
            }
            state.packets.insert(seq, Some(data));
            state.next += 1;
            reservation.committed = true;
        }
        session.ready.notify_one();
        return response(StatusCode::OK);
    }

    {
        let mut state = session.state.lock().unwrap();
        if state.active || state.closed {
            return response(StatusCode::CONFLICT);
        }
        state.active = true;
        session.expiry_cancel.notify_one();
    }
    let (business, bridge) = tokio::io::duplex(CLIENT_PACKET_SIZE);
    let (tx, rx) = mpsc::channel(2);
    let stream = XhttpStream::new_packet(PacketStream::server(business));
    // Do not leave a claimed GET session behind when the accept queue is full.
    if stx
        .try_send((super::super::TrStream::Xhttp(Box::new(stream)), peer))
        .is_err()
    {
        session.state.lock().unwrap().closed = true;
        session.capacity.notify_waiters();
        sessions.lock().await.remove(&id);
        return response(StatusCode::SERVICE_UNAVAILABLE);
    }
    tokio::spawn(async move {
        let (mut download, mut upload) = tokio::io::split(bridge);
        let upload_session = session.clone();
        let uploads = async move {
            loop {
                let notified = upload_session.ready.notified();
                let packet = {
                    let mut state = upload_session.state.lock().unwrap();
                    if state.closed {
                        return Ok::<(), Error>(());
                    }
                    match state.packets.first_key_value() {
                        Some((&seq, Some(_))) => state.packets.remove(&seq).flatten(),
                        _ => None,
                    }
                };
                match packet {
                    Some(data) => {
                        upload_session.capacity.notify_waiters();
                        upload.write_all(&data).await?;
                    }
                    None => notified.await,
                }
            }
        };
        let downloads = async {
            // Read each chunk once and hand the filled prefix to hyper without copying it.
            let mut data = BytesMut::with_capacity(CLIENT_PACKET_SIZE);
            loop {
                data.reserve(CLIENT_PACKET_SIZE);
                let size = download.read_buf(&mut data).await?;
                if size == 0 {
                    return Ok::<(), Error>(());
                }
                tx.send(Ok(Frame::data(data.split().freeze())))
                    .await
                    .map_err(|_| Error::other("GET closed"))?;
            }
        };
        tokio::select! {
            _ = uploads => {},
            _ = downloads => {},
            _ = tx.closed() => {},
        }
        session.state.lock().unwrap().closed = true;
        session.capacity.notify_waiters();
        sessions.lock().await.remove(&id);
    });
    Xhttp::stream_response(StatusCode::OK, ChannelBody { rx })
}

#[derive(Default)]
struct Progress {
    acknowledged: AtomicU64,
    error: StdMutex<Option<String>>,
    download_closed: AtomicBool,
    stopped: tokio_util::sync::CancellationToken,
    read_waker: futures::task::AtomicWaker,
    write_waker: futures::task::AtomicWaker,
}

impl Progress {
    fn result(&self) -> IoResult<()> {
        match &*self.error.lock().unwrap() {
            Some(error) => Err(Error::new(ErrorKind::BrokenPipe, error.clone())),
            None => Ok(()),
        }
    }

    fn fail(&self, error: Error) {
        *self.error.lock().unwrap() = Some(error.to_string());
        self.stopped.cancel();
        self.read_waker.wake();
        self.write_waker.wake();
    }
}

struct Upload {
    tx: PollSender<Bytes>,
    accepted: u64,
    closed: bool,
}

/// Owns the bounded bridge and cancels HTTP work when the business stream drops.
pub(super) struct PacketStream {
    io: DuplexStream,
    upload: Option<Upload>,
    progress: Arc<Progress>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl PacketStream {
    fn server(io: DuplexStream) -> Self {
        Self {
            io,
            upload: None,
            progress: Arc::new(Progress::default()),
            tasks: Vec::new(),
        }
    }
}

impl Drop for PacketStream {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub(super) async fn connect(
    mut sender: SendRequest<ChannelBody>,
    get_response: DownloadResponse,
    uri: http::Uri,
) -> IoResult<XhttpStream> {
    let (io, mut download) = tokio::io::duplex(CLIENT_PACKET_SIZE);
    let (tx, mut rx) = mpsc::channel::<Bytes>(2);
    let progress = Arc::new(Progress::default());
    let upload_progress = progress.clone();
    let upload_task = tokio::spawn(async move {
        let work = async {
            let mut seq = 0u64;
            while let Some(data) = rx.recv().await {
                let mut parts = uri.clone().into_parts();
                parts.path_and_query = Some(
                    format!("{}/{}", uri.path().trim_end_matches('/'), seq)
                        .parse()
                        .map_err(Error::other)?,
                );
                let packet_uri = http::Uri::from_parts(parts).map_err(Error::other)?;
                let (body_tx, body_rx) = mpsc::channel(1);
                let len = data.len();
                body_tx.try_send(Ok(Frame::data(data))).map_err(Error::other)?;
                drop(body_tx);
                let request = Request::builder()
                    .method("POST")
                    .uri(packet_uri)
                    .header(header::CONTENT_LENGTH, len)
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(ChannelBody { rx: body_rx })
                    .map_err(Error::other)?;
                let exchange = async {
                    sender.ready().await.map_err(Error::other)?;
                    let response = sender.send_request(request).await.map_err(Error::other)?;
                    if response.status() != StatusCode::OK {
                        return Err(Error::other(format!("packet upload failed: {}", response.status())));
                    }
                    let mut body = response.into_body();
                    let mut received = 0usize;
                    while let Some(frame) = body.frame().await {
                        if let Ok(data) = frame.map_err(Error::other)?.into_data() {
                            received = received.saturating_add(data.len());
                            if received > MAX_PACKET_SIZE {
                                return Err(Error::other("packet ACK body too large"));
                            }
                        }
                    }
                    Ok::<(), Error>(())
                };
                tokio::time::timeout(REQUEST_TIMEOUT, exchange)
                    .await
                    .map_err(|_| Error::new(ErrorKind::TimedOut, "packet ACK timed out"))??;
                seq = seq
                    .checked_add(1)
                    .ok_or_else(|| Error::other("packet sequence exhausted"))?;
                upload_progress.acknowledged.store(seq, Ordering::Release);
                upload_progress.write_waker.wake();
            }
            Ok::<(), Error>(())
        };
        tokio::select! {
            result = work => if let Err(error) = result { upload_progress.fail(error); },
            _ = upload_progress.stopped.cancelled() => {},
        }
    });
    let download_progress = progress.clone();
    let download_task = tokio::spawn(async move {
        let work = async {
            let incoming = get_response.await?;
            let mut reader = StreamReader::new(IncomingStream { incoming });
            tokio::io::copy(&mut reader, &mut download).await?;
            Ok::<(), Error>(())
        };
        tokio::select! {
            result = work => match result {
                Err(error) => download_progress.fail(error),
                Ok(()) => {
                    download_progress.download_closed.store(true, Ordering::Release);
                    download_progress.write_waker.wake();
                    download_progress.stopped.cancel();
                }
            },
            _ = download_progress.stopped.cancelled() => {},
        }
    });
    Ok(XhttpStream::new_packet(PacketStream {
        io,
        upload: Some(Upload {
            tx: PollSender::new(tx),
            accepted: 0,
            closed: false,
        }),
        progress,
        tasks: vec![upload_task, download_task],
    }))
}

impl AsyncRead for PacketStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<IoResult<()>> {
        self.progress.read_waker.register(cx.waker());
        if let Err(error) = self.progress.result() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for PacketStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<IoResult<usize>> {
        self.progress.write_waker.register(cx.waker());
        if let Err(error) = self.progress.result() {
            return Poll::Ready(Err(error));
        }
        let download_closed = self.progress.download_closed.load(Ordering::Acquire);
        let Some(upload) = &mut self.upload else {
            return Pin::new(&mut self.io).poll_write(cx, data);
        };
        if upload.closed || download_closed {
            return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "packet upload closed")));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match upload.tx.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "packet upload stopped"))),
            Poll::Ready(Ok(())) => {
                let len = data.len().min(CLIENT_PACKET_SIZE);
                if upload.tx.send_item(Bytes::copy_from_slice(&data[..len])).is_err() {
                    return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "packet upload stopped")));
                }
                upload.accepted += 1;
                Poll::Ready(Ok(len))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.progress.write_waker.register(cx.waker());
        if let Err(error) = self.progress.result() {
            return Poll::Ready(Err(error));
        }
        match &self.upload {
            Some(_) if self.progress.download_closed.load(Ordering::Acquire) => {
                Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "packet download closed")))
            }
            Some(upload) if self.progress.acknowledged.load(Ordering::Acquire) < upload.accepted => Poll::Pending,
            Some(_) => Poll::Ready(Ok(())),
            None => Pin::new(&mut self.io).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        if let Some(upload) = &mut self.upload {
            // No private EOF packet: close only the local upload worker.
            upload.closed = true;
            upload.tx.close();
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_bridge() -> (PacketStream, mpsc::Receiver<Bytes>, DuplexStream) {
        let (io, peer) = tokio::io::duplex(CLIENT_PACKET_SIZE);
        let (tx, rx) = mpsc::channel(2);
        (
            PacketStream {
                io,
                upload: Some(Upload {
                    tx: PollSender::new(tx),
                    accepted: 0,
                    closed: false,
                }),
                progress: Arc::new(Progress::default()),
                tasks: Vec::new(),
            },
            rx,
            peer,
        )
    }

    #[tokio::test]
    async fn flush_and_shutdown_wait_for_ack_without_closing_download() {
        let (mut stream, mut rx, mut peer) = client_bridge();
        stream.write_all(b"one").await.unwrap();
        stream.write_all(b"two").await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), "one");
        assert_eq!(rx.recv().await.unwrap(), "two");
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_pending());
        assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_pending());
        stream.progress.acknowledged.store(1, Ordering::Release);
        assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_pending());
        stream.progress.acknowledged.store(2, Ordering::Release);
        stream.shutdown().await.unwrap();
        assert!(rx.recv().await.is_none());
        assert!(stream.write_all(b"three").await.is_err());
        peer.write_all(b"still downloading").await.unwrap();
        let mut data = [0; 17];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"still downloading");
    }

    #[tokio::test]
    async fn bounded_writes_and_background_errors() {
        let (mut stream, mut rx, _peer) = client_bridge();
        let data = vec![7; CLIENT_PACKET_SIZE * 2];
        assert_eq!(stream.write(&data).await.unwrap(), CLIENT_PACKET_SIZE);
        assert_eq!(stream.write(&data).await.unwrap(), CLIENT_PACKET_SIZE);
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_write(&mut cx, b"full").is_pending());
        assert_eq!(rx.recv().await.unwrap().len(), CLIENT_PACKET_SIZE);
        stream.progress.fail(Error::other("HTTP 500"));
        assert!(stream.write_all(b"error").await.is_err());
        assert!(stream.flush().await.is_err());
        assert!(stream.shutdown().await.is_err());
        let mut data = [0];
        assert!(stream.read(&mut data).await.is_err());
    }

    #[tokio::test]
    async fn dropping_stream_aborts_workers() {
        let (mut stream, _rx, _peer) = client_bridge();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        stream.tasks.push(tokio::spawn(async move {
            let _tx = tx;
            std::future::pending::<()>().await;
        }));
        drop(stream);
        assert!(tokio::time::timeout(Duration::from_secs(1), rx).await.unwrap().is_err());
    }

    #[tokio::test]
    async fn reservations_enforce_order_and_apply_backpressure() {
        let session = Arc::new(PacketSession::new());
        assert!(matches!(session.reserve(1).await, Err(StatusCode::CONFLICT)));
        let first = session.reserve(0).await.unwrap();
        assert!(matches!(session.reserve(0).await, Err(StatusCode::CONFLICT)));
        drop(first);
        let mut first = session.reserve(0).await.unwrap();
        {
            let mut state = session.state.lock().unwrap();
            state.packets.insert(0, Some(Bytes::from_static(b"packet")));
            state.next = 1;
            first.committed = true;
        }
        let pending = session.reserve(1);
        tokio::pin!(pending);
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        session.state.lock().unwrap().packets.remove(&0);
        session.capacity.notify_waiters();
        drop(pending.await.unwrap());
        assert!(matches!(session.reserve(0).await, Err(StatusCode::CONFLICT)));
        session.state.lock().unwrap().closed = true;
        assert!(matches!(session.reserve(1).await, Err(StatusCode::GONE)));
    }

    #[test]
    fn paths_require_uuid_and_decimal_sequence() {
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(parse_suffix(&format!("{id}/0"), true), Some((id.as_str(), Some(0))));
        assert_eq!(parse_suffix(&id, false), Some((id.as_str(), None)));
        for suffix in ["", "/", "/-1", "/1/2", "/18446744073709551616"] {
            assert!(parse_suffix(&format!("{id}{suffix}"), true).is_none());
        }
        assert!(parse_suffix("session/0", true).is_none());
    }
}
