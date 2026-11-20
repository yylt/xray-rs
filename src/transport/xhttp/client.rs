use crate::transport::{sockopt::SocketOpt, tls};
use bytes::Bytes;
use futures::Stream;
use h2::{client::SendRequest, Reason, RecvStream, SendStream};
use http::{Request, Response};
use std::future::{poll_fn, Future};
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub(super) type ResponseFuture = Pin<Box<dyn Future<Output = IoResult<Response<ClientBody>>> + Send + Sync>>;

pub(super) struct ClientTarget {
    addr: SocketAddr,
    name: String,
    opt: SocketOpt,
    tls: Option<tls::client::Tls>,
    window: u32,
    connections: StdMutex<Vec<Arc<StdMutex<Connection>>>>,
    dial: Mutex<()>,
}

struct Connection {
    sender: SendRequest<Bytes>,
    inflight: usize,
    closed: bool,
    draining: bool,
    driver: Option<tokio::task::AbortHandle>,
}

impl Connection {
    fn accepting(&mut self) -> bool {
        if self.closed || self.draining {
            return false;
        }
        // Only detect GOAWAY/errors and clear pending-open bookkeeping here.
        // Readiness is NOT a peer-capacity reservation; admission checks the
        // native SETTINGS limit and our own inflight count separately.
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        match self.sender.poll_ready(&mut cx) {
            Poll::Ready(Ok(())) => true,
            Poll::Ready(Err(_)) => {
                self.draining = true;
                false
            }
            Poll::Pending => false,
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}

// Keep the reset handle even after request EOS: RecvStream::drop alone need not
// cancel a stream while the sender still retains a pending-open reference.
struct RequestGuard {
    stream: SendStream<Bytes>,
    connection: Arc<StdMutex<Connection>>,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        let mut connection = self.connection.lock().unwrap();
        self.stream.send_reset(Reason::CANCEL);
        connection.inflight -= 1;
    }
}

struct PendingResponse {
    // Reset and release our reservation before dropping the response handle.
    guard: Option<RequestGuard>,
    response: h2::client::ResponseFuture,
    data: Bytes,
}

pub(super) struct ClientBody {
    guard: Option<RequestGuard>,
    recv: RecvStream,
}

impl ClientTarget {
    pub(super) fn new(
        addr: SocketAddr,
        name: String,
        opt: SocketOpt,
        tls: Option<tls::client::Tls>,
        window: u32,
    ) -> Self {
        Self {
            addr,
            name,
            opt,
            tls,
            window,
            connections: StdMutex::new(Vec::new()),
            dial: Mutex::new(()),
        }
    }

    pub(super) fn is_closed(&self) -> bool {
        let connections = self.connections.lock().unwrap();
        !connections.is_empty()
            && connections.iter().all(|connection| {
                let mut state = connection.lock().unwrap();
                state.accepting();
                state.closed || state.draining
            })
    }

    pub(super) async fn connect(&self) -> IoResult<()> {
        if let Some(result) = self.connected() {
            return result;
        }
        let _dial = self.dial.lock().await;
        if let Some(result) = self.connected() {
            return result;
        }
        let connection = self.open_connection().await?;
        self.connections.lock().unwrap().push(connection);
        self.connected()
            .unwrap_or_else(|| Err(Error::new(ErrorKind::NotConnected, "XHTTP connection closed")))
    }

    fn connected(&self) -> Option<IoResult<()>> {
        let connections = self.connections.lock().unwrap();
        let mut live = false;
        for connection in connections.iter() {
            let mut state = connection.lock().unwrap();
            state.accepting();
            if !state.closed && !state.draining {
                live = true;
                if state.sender.current_max_send_streams() != 0 {
                    return Some(Ok(()));
                }
            }
        }
        live.then(|| Err(Error::new(ErrorKind::WouldBlock, "XHTTP peer advertises zero stream capacity")))
    }

    pub(super) async fn send(&self, request: Request<Bytes>) -> IoResult<ResponseFuture> {
        if request.body().len() > 64 * 1024 {
            return Err(Error::new(ErrorKind::InvalidInput, "XHTTP request body exceeds 64 KiB"));
        }
        let mut request = Some(request);
        if let Some(response) = self.try_send(&mut request)? {
            return Ok(response);
        }
        let _dial = self.dial.lock().await;
        if let Some(response) = self.try_send(&mut request)? {
            return Ok(response);
        }
        let connection = self.open_connection().await?;
        // Reserve the new connection before publishing it to concurrent callers.
        let response = Self::admit(&connection, &mut request);
        self.connections.lock().unwrap().push(connection);
        response?.ok_or_else(|| Error::new(ErrorKind::WouldBlock, "XHTTP peer advertises zero stream capacity"))
    }

    fn try_send(&self, request: &mut Option<Request<Bytes>>) -> IoResult<Option<ResponseFuture>> {
        let mut connections = self.connections.lock().unwrap();
        connections.retain(|connection| !connection.lock().unwrap().closed);
        let mut zero_capacity = false;
        for connection in connections.iter() {
            if let Some(response) = Self::admit(connection, request)? {
                return Ok(Some(response));
            }
            let state = connection.lock().unwrap();
            zero_capacity |= !state.closed && !state.draining && state.sender.current_max_send_streams() == 0;
        }
        if zero_capacity {
            return Err(Error::new(ErrorKind::WouldBlock, "XHTTP peer advertises zero stream capacity"));
        }
        Ok(None)
    }

    fn admit(
        connection: &Arc<StdMutex<Connection>>,
        request: &mut Option<Request<Bytes>>,
    ) -> IoResult<Option<ResponseFuture>> {
        let mut state = connection.lock().unwrap();
        // The driver polls under this same lock, so SETTINGS cannot change
        // between this capacity check and the actual request submission.
        if !state.accepting() || state.inflight >= state.sender.current_max_send_streams() {
            return Ok(None);
        }
        let (mut parts, data) = request.take().unwrap().into_parts();
        parts.version = http::Version::HTTP_2;
        let (response, stream) = state
            .sender
            .send_request(Request::from_parts(parts, ()), data.is_empty())
            .map_err(Error::other)?;
        state.inflight += 1;
        Ok(Some(Box::pin(PendingResponse {
            guard: Some(RequestGuard {
                stream,
                connection: connection.clone(),
            }),
            response,
            data,
        })))
    }

    async fn open_connection(&self) -> IoResult<Arc<StdMutex<Connection>>> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let tcp = self.opt.apply_tcpstream(TcpStream::connect(self.addr).await?)?;
            match &self.tls {
                Some(tls) => self.handshake(tls.connect_http2(&self.name, tcp).await?).await,
                None => self.handshake(tcp).await,
            }
        })
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "XHTTP HTTP/2 initialization timed out"))?
    }

    async fn handshake<T>(&self, io: T) -> IoResult<Arc<StdMutex<Connection>>>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(self.window)
            .initial_connection_window_size(self.window.saturating_mul(2).min((1 << 31) - 1));
        let (sender, mut driver) = builder.handshake::<_, Bytes>(io).await.map_err(Error::other)?;
        let mut ping = driver
            .ping_pong()
            .ok_or_else(|| Error::other("XHTTP HTTP/2 ping unavailable"))?;
        let connection = Arc::new(StdMutex::new(Connection {
            sender,
            inflight: 0,
            closed: false,
            draining: false,
            driver: None,
        }));
        let weak = Arc::downgrade(&connection);
        let task = tokio::spawn(async move {
            let _ = poll_fn(|cx| {
                let Some(connection) = weak.upgrade() else {
                    return Poll::Ready(Ok(()));
                };
                let mut state = connection.lock().unwrap();
                let result = Pin::new(&mut driver).poll(cx);
                if result.is_ready() {
                    state.closed = true;
                }
                result
            })
            .await;
        });
        connection.lock().unwrap().driver = Some(task.abort_handle());
        // The peer's initial SETTINGS precedes its PING ACK on the wire. Do not
        // cache a sender whose initial (unbounded) limit is still speculative.
        ping.ping(h2::Ping::opaque()).await.map_err(Error::other)?;
        Ok(connection)
    }
}

impl Future for PendingResponse {
    type Output = IoResult<Response<ClientBody>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // A peer may reject the request without granting any upload capacity.
        // Register response wakes before waiting for the request window.
        match Pin::new(&mut this.response).poll(cx) {
            Poll::Pending => {}
            Poll::Ready(Ok(response)) => {
                let (parts, recv) = response.into_parts();
                return Poll::Ready(Ok(Response::from_parts(
                    parts,
                    ClientBody {
                        guard: this.guard.take(),
                        recv,
                    },
                )));
            }
            Poll::Ready(Err(error)) => {
                this.guard.take();
                return Poll::Ready(Err(Error::other(error)));
            }
        }
        while !this.data.is_empty() {
            let stream = &mut this.guard.as_mut().unwrap().stream;
            stream.reserve_capacity(this.data.len());
            let capacity = match stream.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(capacity))) => capacity,
                Poll::Ready(Some(Err(error))) => {
                    this.guard.take();
                    return Poll::Ready(Err(Error::other(error)));
                }
                Poll::Ready(None) => {
                    this.guard.take();
                    return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "XHTTP request stream closed")));
                }
            };
            let data = this.data.split_to(capacity.min(this.data.len()));
            if let Err(error) = stream.send_data(data, this.data.is_empty()) {
                this.guard.take();
                return Poll::Ready(Err(Error::other(error)));
            }
        }
        Poll::Pending
    }
}

impl Stream for ClientBody {
    type Item = IoResult<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.guard.is_none() {
            return Poll::Ready(None);
        }
        match this.recv.poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(data))) => {
                if let Err(error) = this.recv.flow_control().release_capacity(data.len()) {
                    this.guard.take();
                    return Poll::Ready(Some(Err(Error::other(error))));
                }
                Poll::Ready(Some(Ok(data)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.guard.take();
                Poll::Ready(Some(Err(Error::other(error))))
            }
            Poll::Ready(None) => match this.recv.poll_trailers(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(_)) => {
                    this.guard.take();
                    Poll::Ready(None)
                }
                Poll::Ready(Err(error)) => {
                    this.guard.take();
                    Poll::Ready(Some(Err(Error::other(error))))
                }
            },
        }
    }
}

#[cfg(test)]
#[path = "goaway_tests.rs"]
mod goaway_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    async fn frame(peer: &mut DuplexStream) -> (u8, u8, Vec<u8>) {
        let mut header = [0; 9];
        peer.read_exact(&mut header).await.unwrap();
        let len = (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        let mut payload = vec![0; len];
        peer.read_exact(&mut payload).await.unwrap();
        (header[3], header[4], payload)
    }

    async fn settings(peer: &mut DuplexStream, limit: u32) {
        let mut frame = vec![0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3];
        frame.extend_from_slice(&limit.to_be_bytes());
        peer.write_all(&frame).await.unwrap();
    }

    fn target() -> ClientTarget {
        ClientTarget::new(
            "127.0.0.1:1".parse().unwrap(),
            "localhost".into(),
            SocketOpt::default(),
            None,
            65535,
        )
    }

    #[tokio::test]
    async fn settings_barrier_dynamic_limits_and_cancel() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let target = target();
            let (io, mut peer) = tokio::io::duplex(4096);
            let mut handshake = Box::pin(target.handshake(io));
            // Handshake alone writes the preface but must not expose the
            // speculative unlimited stream count before the peer replies.
            assert!(tokio::time::timeout(Duration::from_millis(20), &mut handshake)
                .await
                .is_err());
            let mut preface = [0; 24];
            peer.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            settings(&mut peer, 1).await;
            loop {
                let (kind, flags, payload) = frame(&mut peer).await;
                if kind == 6 && flags == 0 {
                    peer.write_all(&[0, 0, 8, 6, 1, 0, 0, 0, 0]).await.unwrap();
                    peer.write_all(&payload).await.unwrap();
                    break;
                }
            }
            let connection = handshake.await.unwrap();
            assert_eq!(connection.lock().unwrap().sender.current_max_send_streams(), 1);
            let mut request = Some(Request::get("http://localhost/").body(Bytes::new()).unwrap());
            let response = ClientTarget::admit(&connection, &mut request).unwrap().unwrap();
            assert_eq!(connection.lock().unwrap().inflight, 1);
            drop(response);
            assert_eq!(connection.lock().unwrap().inflight, 0);
            settings(&mut peer, 0).await;
            while connection.lock().unwrap().sender.current_max_send_streams() != 0 {
                tokio::task::yield_now().await;
            }
            target.connections.lock().unwrap().push(connection.clone());
            let mut request = Some(Request::get("http://localhost/").body(Bytes::new()).unwrap());
            assert!(matches!(target.try_send(&mut request), Err(error) if error.kind() == ErrorKind::WouldBlock));
            settings(&mut peer, 2).await;
            while connection.lock().unwrap().sender.current_max_send_streams() != 2 {
                tokio::task::yield_now().await;
            }
            assert!(target.try_send(&mut request).unwrap().is_some());
        })
        .await
        .unwrap();
    }
}
