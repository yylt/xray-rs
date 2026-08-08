//! Connection abstraction layer for rsdns.
//!
//! This module provides the core connection primitives:
//!
//! - [`CloneableSender`]: a lightweight `DnsHandle` wrapper around any
//!   `DnsRequestSender`, replacing `DnsExchange` with full lifecycle control.
//!   Uses an internal mpsc channel + background task pattern.  `Clone`
//!   shares the same underlying connection — multiple callers multiplex
//!   requests over a single TCP/TLS/QUIC stream.
//!
//! - [`ConnFactory`]: a type-erased async factory closure that builds a
//!   `DnsRequestSender` from a `SocketAddr`.  Each protocol (UDP, TCP, TLS,
//!   DoH, DoH3, DoQ) supplies its own factory in [`super::factory`].
//!
//! - [`build_cloneable`]: convenience helper that calls a `ConnFactory` with
//!   both connect and DNS timeouts, wraps the result in a `CloneableSender`.
//!
//! - [`ping_soa`]: quick SOA "." probe used by the connection pool's health
//!   checker to verify a connection is still alive.

use futures::Stream;
use hickory_net::xfer::{DnsHandle, DnsRequestSender, DnsResponseStream};
use hickory_proto::op::{DnsRequest, DnsResponse};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub use hickory_net::NetError;

const CLONEABLE_QUEUE_CAPACITY: usize = 256;

/// Type-erased boxed `DnsRequestSender`.
pub type BoxedDnsSender = Box<dyn DnsRequestSender + Send>;

/// A lightweight `DnsHandle` wrapper around a `DnsRequestSender`.
///
/// ## Design
///
/// `hickory_net::xfer::DnsExchange` was the previous foundation.  It wraps a
/// `DnsRequestSender` in an mpsc channel + background task and provides a
/// `Clone`-able `DnsHandle`.  However, `DnsExchange` hides the background
/// task behind `RuntimeProvider`, making it impossible to monitor or abort
/// the underlying I/O loop.
///
/// `CloneableSender` replaces `DnsExchange` with a manual, transparent
/// implementation:
///
/// - A `tokio::spawn`'d background task polls the `DnsRequestSender`'s
///   `send_message()` → `DnsResponseStream` loop.
/// - A bounded `mpsc::Sender` is the public handle.  `Clone` creates a
///   new sender pointing at the same background task — multiple callers
///   share one underlying connection.
/// - `is_shutdown()` uses an `AtomicBool` that is set when the background
///   task exits (either normally or due to a timeout).  This lets the
///   connection pool perform zero-overhead liveness checks.
/// - **Timeout semantics**: when a DNS response does not arrive within
///   `dns_timeout`, the background task calls `sender.shutdown()` on the
///   underlying stream *and* sets the shutdown flag.  This is critical
///   because after a timeout the stream may still deliver a stale response
///   later; the connection is considered dead and must be discarded.
///
/// ## Why not `DnsExchange`?
///
/// | Feature              | `DnsExchange`   | `CloneableSender` |
/// |----------------------|-----------------|-------------------|
/// | Background task      | opaque          | `JoinHandle` accessible |
/// | Shutdown detection   | no public API   | `AtomicBool` load |
/// | Timeout → shutdown   | no              | yes |
/// | `RuntimeProvider`    | required        | not needed |
///
/// ## Example
///
/// ```ignore
/// let sender: BoxedDnsSender = Box::new(some_dns_request_sender);
/// let cloneable = CloneableSender::new(sender, Duration::from_secs(5));
///
/// // Use as a DnsHandle:
/// cloneable.send(request).first_answer().await?;
///
/// // Cheap clone — same underlying connection:
/// let c2 = cloneable.clone();
/// tokio::spawn(async move { c2.send(request2).first_answer().await });
/// ```
#[derive(Clone)]
pub struct CloneableSender {
    tx: mpsc::Sender<(DnsRequest, oneshot::Sender<Result<DnsResponse, NetError>>)>,
    shutdown: Arc<AtomicBool>,
}

impl CloneableSender {
    /// Creates a `CloneableSender` backed by `sender`.
    ///
    /// Spawns a background task that:
    /// 1. dequeues requests from the internal mpsc channel,
    /// 2. calls `sender.send_message(request)` to obtain a response stream,
    /// 3. awaits one response (or a `dns_timeout` — see below),
    /// 4. sends the result back to the caller via a oneshot channel.
    ///
    /// **Timeout handling**: if the response does not arrive before
    /// `dns_timeout`, the background task:
    /// - calls `sender.shutdown()` on the underlying stream,
    /// - stores `true` in `shutdown`, making future `is_shutdown()` calls
    ///   return `true`,
    /// - returns `NetError::from("dns timeout")` to the caller.
    ///
    /// After a timeout the `CloneableSender` is irreversibly dead — the
    /// connection pool will detect this via `is_shutdown()` and reclaim it.
    pub fn new(mut sender: BoxedDnsSender, dns_timeout: Duration) -> Self {
        let (tx, mut rx) =
            mpsc::channel::<(DnsRequest, oneshot::Sender<Result<DnsResponse, NetError>>)>(CLONEABLE_QUEUE_CAPACITY);
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        let _bg = tokio::spawn(async move {
            loop {
                let (req, reply) = match rx.recv().await {
                    Some(v) => v,
                    None => break,
                };

                let mut stream = sender.send_message(req);
                let result = tokio::select! {
                    item = poll_response_stream_next(&mut stream) => item,
                    _ = tokio::time::sleep(dns_timeout) => {
                        sender.shutdown();
                        shutdown_clone.store(true, Ordering::Release);
                        let _ = reply.send(Err(NetError::from("dns timeout")));
                        // UdpClientStream panics on send_message after
                        // shutdown; break immediately — connection is dead.
                        break;
                    }
                };

                let _ = reply.send(result);
            }
            sender.shutdown();
            shutdown_clone.store(true, Ordering::Release);
        });

        Self { tx, shutdown }
    }

    /// Returns `true` if the underlying connection has been shut down.
    ///
    /// This is a single `AtomicBool::load(Acquire)` — effectively free.
    /// The flag is set when:
    /// - a DNS query times out (background task calls `sender.shutdown()`),
    /// - `sender.send_message()` returns an error or the stream closes,
    /// - all senders are dropped and the background task exits normally.
    ///
    /// The connection pool uses this in its reaper and on every checkout
    /// to skip dead connections without locking or I/O.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

// ── DnsHandle impl ────────────────────────────────────────────────
//
// Allows CloneableSender to be used everywhere hickory expects a
// DnsHandle: `FirstAnswer`, `DnsExchange`, retry wrappers, etc.

impl DnsHandle for CloneableSender {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = hickory_net::runtime::TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let (tx, rx) = oneshot::channel();
        let send_result = self.tx.try_send((request, tx));
        if let Err(err) = send_result {
            let msg = match err {
                tokio::sync::mpsc::error::TrySendError::Full(_) => "sender queue full",
                tokio::sync::mpsc::error::TrySendError::Closed(_) => "sender closed",
            };
            return Box::pin(ImmediateErrorStream {
                error: Some(NetError::from(msg)),
            });
        }
        Box::pin(OneshotStream { inner: Some(rx) })
    }
}

struct ImmediateErrorStream {
    error: Option<NetError>,
}

impl Stream for ImmediateErrorStream {
    type Item = Result<DnsResponse, NetError>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.error.take().map(Err))
    }
}

/// A `Stream` that yields at most one item from a `oneshot::Receiver`.
///
/// Used to convert the oneshot reply channel into the `Stream` interface
/// that `DnsHandle::send()` requires.
struct OneshotStream {
    inner: Option<oneshot::Receiver<Result<DnsResponse, NetError>>>,
}

impl Stream for OneshotStream {
    type Item = Result<DnsResponse, NetError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut() {
            Some(rx) => Pin::new(rx).poll(cx).map(|r| match r {
                Ok(val) => {
                    self.inner = None;
                    Some(val)
                }
                Err(_) => {
                    self.inner = None;
                    Some(Err(NetError::from("sender dropped")))
                }
            }),
            None => Poll::Ready(None),
        }
    }
}

/// Polls the `DnsResponseStream` for exactly one item.
///
/// This is the core of the background task's I/O loop.  We await a single
/// response (or stream termination / timeout) and then pass the result
/// back to the caller.  The `pin_mut!` inside is necessary because
/// `DnsResponseStream` is `!Unpin` (it contains a boxed future).
pub(crate) async fn poll_response_stream_next(stream: &mut DnsResponseStream) -> Result<DnsResponse, NetError> {
    use futures::StreamExt;
    futures::pin_mut!(stream);
    match stream.next().await {
        Some(Ok(resp)) => Ok(resp),
        Some(Err(e)) => Err(e),
        None => Err(NetError::from("stream closed")),
    }
}

// ── Connection factory type ───────────────────────────────────────

/// Type-erased async factory: given a `SocketAddr`, produces a boxed
/// `DnsRequestSender`.
///
/// Each protocol module (`udp_factory`, `tcp_factory`, …) returns one of
/// these.  The connection pool stores a `ConnFactory` and calls it to
/// create new connections on demand.
pub type ConnFactory =
    Arc<dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = io::Result<BoxedDnsSender>> + Send>> + Send + Sync>;

// ── Helpers ───────────────────────────────────────────────────────

/// Builds a `CloneableSender` by invoking a `ConnFactory` with timeout
/// wrapping.
///
/// # Arguments
///
/// * `factory` — the connection factory for the desired protocol.
/// * `addr` — the target `SocketAddr`.
/// * `dns_timeout` — passed to `CloneableSender::new`; per-request DNS
///   timeout in the background task.
/// * `connect_timeout` — maximum time allowed for the factory to establish
///   the transport-level connection (TCP handshake, TLS negotiation, QUIC
///   connect, etc.).
///
/// Returns `io::ErrorKind::TimedOut` if connect exceeds `connect_timeout`,
/// or the factory's own error on failure.
pub async fn build_cloneable(
    factory: &ConnFactory,
    addr: SocketAddr,
    dns_timeout: Duration,
    connect_timeout: Duration,
) -> io::Result<CloneableSender> {
    let result: io::Result<BoxedDnsSender> = tokio::time::timeout(connect_timeout, factory(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))?
        .map_err(|e| io::Error::other(e.to_string()));

    let sender = match result {
        Ok(s) => s,
        Err(e) => return Err(e),
    };
    Ok(CloneableSender::new(sender, dns_timeout))
}

/// Sends a `SOA .` query through `sender` and returns `true` if a
/// response is received.
///
/// This is the standard DNS liveness probe used by the connection pool's
/// reaper for non-UDP protocols.  The "." SOA query is lightweight and
/// well-supported by virtually all recursive resolvers.
///
/// Note: this does **not** set a timeout.  The caller (reaper) should
/// wrap this in `tokio::time::timeout(health_check_timeout, ping_soa(...))`
/// to ensure a stuck connection doesn't hang the reaper.
pub async fn ping_soa(sender: &CloneableSender) -> bool {
    use hickory_proto::op::{DnsRequestOptions, Message, MessageType, OpCode};
    use hickory_proto::rr::{DNSClass, Name, RecordType};

    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    let mut q = hickory_proto::op::Query::new();
    q.set_name(Name::from_utf8(".").unwrap());
    q.set_query_type(RecordType::SOA);
    q.set_query_class(DNSClass::IN);
    msg.queries.push(q);
    msg.metadata.recursion_desired = true;

    let request = DnsRequest::new(msg, DnsRequestOptions::default());
    let stream = sender.send(request);
    futures::pin_mut!(stream);
    use futures::StreamExt;
    matches!(stream.next().await, Some(Ok(_)))
}
