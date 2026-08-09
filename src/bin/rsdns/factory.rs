//! Protocol-specific connection factories.
//!
//! Each public function returns a [`ConnFactory`] — an `Arc<dyn Fn(SocketAddr) ->
//! Pin<Box<dyn Future<…>>>>>` closure that, given a resolved `SocketAddr`, creates a
//! fresh `DnsRequestSender` for that protocol.
//!
//! All factories use `.build()` rather than `.exchange()`, giving the connection
//! pool (`[super::pool::ConnectionPool]`) direct ownership of the underlying
//! `DnsRequestSender` and full control over its lifecycle.
//!
//! ## Protocol notes
//!
//! | Protocol  | hickory-net type          | Wrapping |
//! |-----------|---------------------------|----------|
//! | UDP       | `UdpClientStream`         | none (implements `DnsRequestSender` directly) |
//! | TCP       | `TcpClientStream`         | `MuxedSender` (drives `DnsMultiplexer` Stream + Send sides) |
//! | TLS (DoT) | `TlsClientStream` (alias) | `MuxedSender` (same as TCP) |
//! | DoH (h2)  | `HttpsClientStream`       | none (HTTP/2 native multiplexing) |
//! | DoH3 (h3) | `H3ClientStream`          | none (QUIC native multiplexing) |
//! | DoQ       | `QuicClientStream`        | none (QUIC native multiplexing) |
//!
//! `MuxedSender` is required for TCP and TLS because [`DnsMultiplexer`] is
//! dual-faced: `send_message()` queues requests and returns a response stream,
//! while `DnsMultiplexer::poll_next()` drives I/O to actually send queued bytes
//! and dispatch incoming responses to the correct active request.  Without
//! someone polling the `Stream` side, responses never arrive.
//!
//! `MuxedSender` spawns a background task that continuously polls the
//! multiplexer's `Stream` side, and receives `send_message` requests via an
//! internal mpsc channel.  It does **not** use `DnsExchange`.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::Stream;
use futures::StreamExt;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::xfer::dns_multiplexer::DnsMultiplexer;
use hickory_net::xfer::{DnsClientStream, DnsRequestSender, DnsResponseStream};
use hickory_net::NetError;
use hickory_proto::op::{DnsRequest, DnsResponse};
use hickory_proto::ProtoError;
use rustls::pki_types::ServerName;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::conn::{BoxedDnsSender, ConnFactory};

/// Per-request DNS timeout used inside the multiplexer / stream.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MUX_REQUEST_QUEUE_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// MuxedSender — self-driving wrapper around DnsMultiplexer
// ---------------------------------------------------------------------------

/// A [`DnsRequestSender`] backed by a [`DnsMultiplexer`] with an I/O driver task.
struct MuxedSender {
    tx: tokio::sync::mpsc::Sender<(DnsRequest, oneshot::Sender<Result<DnsResponse, NetError>>)>,
    shutdown: Arc<AtomicBool>,
    stop_tx: watch::Sender<bool>,
    _bg: tokio::task::JoinHandle<()>,
}

impl MuxedSender {
    fn spawn<S>(mux: DnsMultiplexer<S>) -> Self
    where
        S: DnsClientStream + Send + 'static,
    {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(DnsRequest, oneshot::Sender<Result<DnsResponse, NetError>>)>(
            MUX_REQUEST_QUEUE_CAPACITY,
        );
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let stop_tx_bg = stop_tx.clone();

        let _bg = tokio::spawn(async move {
            let mut mux = Box::pin(mux);
            let mut replies = JoinSet::new();

            loop {
                tokio::select! {
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    msg = rx.recv(), if !shutdown_clone.load(Ordering::Acquire) => {
                        let Some((dns_request, reply)) = msg else { break };
                        let mut resp = mux.send_message(dns_request);
                        let mut stop_rx = stop_tx_bg.subscribe();
                        replies.spawn(async move {
                            let result = tokio::select! {
                                changed = stop_rx.changed() => match changed {
                                    Ok(_) if *stop_rx.borrow() => Err(NetError::from(ProtoError::from("connection shutdown"))),
                                    Ok(_) => Err(NetError::from(ProtoError::from("connection closed"))),
                                    Err(_) => Err(NetError::from(ProtoError::from("connection closed"))),
                                },
                                _ = tokio::time::sleep(DNS_TIMEOUT) => Err(NetError::from(ProtoError::from("dns timeout"))),
                                result = super::conn::poll_response_stream_next(&mut resp) => result,
                            };
                            let _ = reply.send(result);
                        });
                    }
                    item = mux.next() => {
                        match item {
                            Some(Ok(())) => {}
                            Some(Err(_)) | None => break,
                        }
                    }
                    Some(_) = replies.join_next(), if !replies.is_empty() => {
                    }
                }
            }

            mux.shutdown();
            let _ = stop_tx_bg.send(true);
            replies.abort_all();
            while replies.join_next().await.is_some() {}
            while let Ok((_, reply)) = rx.try_recv() {
                let _ = reply.send(Err(NetError::from(ProtoError::from("connection closed"))));
            }
            shutdown_clone.store(true, Ordering::Release);
        });

        Self {
            tx,
            shutdown,
            stop_tx,
            _bg,
        }
    }
}

impl DnsRequestSender for MuxedSender {
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
        let (reply_tx, reply_rx) = oneshot::channel();
        let send_result = self.tx.try_send((request, reply_tx));
        let fut = async move {
            if let Err(err) = send_result {
                let msg = match err {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => "mux request queue full",
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => "mux sender dropped",
                };
                return Err(NetError::from(ProtoError::from(msg)));
            }
            match reply_rx.await {
                Ok(result) => result,
                Err(_) => Err(NetError::from(ProtoError::from("mux sender dropped"))),
            }
        };
        DnsResponseStream::from(Box::pin(fut))
    }

    fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.stop_tx.send(true);
    }

    fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

impl Stream for MuxedSender {
    type Item = Result<(), NetError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.shutdown.load(Ordering::Acquire) {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol factories
// ---------------------------------------------------------------------------

// ── UDP ────────────────────────────────────────────────────────────

pub fn udp_factory() -> ConnFactory {
    Arc::new(|addr: SocketAddr| {
        let fut = async move {
            let stream = hickory_net::udp::UdpClientStream::builder(addr, TokioRuntimeProvider::default())
                .with_timeout(Some(DNS_TIMEOUT))
                .build();
            let boxed: BoxedDnsSender = Box::new(stream);
            Ok(boxed)
        };
        Box::pin(fut)
    })
}

// ── TCP ────────────────────────────────────────────────────────────

pub fn tcp_factory() -> ConnFactory {
    Arc::new(|addr: SocketAddr| {
        let fut = async move {
            let (stream, handle) =
                hickory_net::tcp::TcpClientStream::new(addr, None, Some(DNS_TIMEOUT), TokioRuntimeProvider::default());
            let tcp_stream = stream.await.map_err(|e| io::Error::other(e.to_string()))?;
            let mux = DnsMultiplexer::new(tcp_stream, handle).with_timeout(DNS_TIMEOUT);
            let boxed: BoxedDnsSender = Box::new(MuxedSender::spawn(mux));
            Ok(boxed)
        };
        Box::pin(fut)
    })
}

// ── TLS (DNS-over-TLS) ─────────────────────────────────────────────

pub fn tls_factory(server_name: String, tls_config: Arc<rustls::ClientConfig>) -> ConnFactory {
    Arc::new(move |addr: SocketAddr| {
        let server_name_str = server_name.clone();
        let client_config = tls_config.clone();
        let fut = async move {
            let sn = ServerName::try_from(server_name_str)
                .map_err(|e| io::Error::other(format!("invalid server name: {}", e)))?;
            let (stream, handle) =
                hickory_net::tls::tls_client_connect(addr, sn, client_config, TokioRuntimeProvider::default());
            let tls_stream = stream.await.map_err(|e| io::Error::other(e.to_string()))?;
            let mux = DnsMultiplexer::new(tls_stream, handle).with_timeout(DNS_TIMEOUT);
            let boxed: BoxedDnsSender = Box::new(MuxedSender::spawn(mux));
            Ok(boxed)
        };
        Box::pin(fut)
    })
}

// ── DoH (DNS-over-HTTPS, HTTP/2) ───────────────────────────────────

pub fn doh_factory(host: Arc<str>, path: Arc<str>, tls_config: Arc<rustls::ClientConfig>) -> ConnFactory {
    Arc::new(move |addr: SocketAddr| {
        let host = host.clone();
        let path = path.clone();
        let tls_config = tls_config.clone();
        let fut = async move {
            let stream = hickory_net::h2::HttpsClientStream::builder(tls_config, TokioRuntimeProvider::default())
                .build(addr, host, path)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            let boxed: BoxedDnsSender = Box::new(stream);
            Ok(boxed)
        };
        Box::pin(fut)
    })
}

// ── DoH3 (DNS-over-HTTP/3) ─────────────────────────────────────────

pub fn doh3_factory(host: Arc<str>, path: Arc<str>, tls_config: Arc<rustls::ClientConfig>) -> ConnFactory {
    Arc::new(move |addr: SocketAddr| {
        let host = host.clone();
        let path = path.clone();
        let tls_config = tls_config.clone();
        let fut = async move {
            let quic_config = tls_config.as_ref().clone();
            let stream = hickory_net::h3::H3ClientStream::builder()
                .crypto_config(quic_config)
                .build(addr, host, path)
                .await
                .map_err(|e| normalize_h3_error(e.to_string()))?;
            let boxed: BoxedDnsSender = Box::new(stream);
            Ok(boxed)
        };
        Box::pin(fut)
    })
}

// ── DoQ (DNS-over-QUIC) ────────────────────────────────────────────

pub fn doq_factory(host: Arc<str>, tls_config: Arc<rustls::ClientConfig>) -> ConnFactory {
    Arc::new(move |addr: SocketAddr| {
        let host = host.clone();
        let tls_config = tls_config.clone();
        let fut = async move {
            let quic_config = tls_config.as_ref().clone();
            let stream = hickory_net::quic::QuicClientStream::builder()
                .crypto_config(quic_config)
                .build(addr, host)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            let boxed: BoxedDnsSender = Box::new(stream);
            Ok(boxed)
        };
        Box::pin(fut)
    })
}

fn normalize_h3_error(err: String) -> io::Error {
    if is_h3_cleanup_error(&err) {
        io::Error::new(io::ErrorKind::ConnectionAborted, "h3 connection closed")
    } else {
        io::Error::other(err)
    }
}

pub(crate) fn is_h3_cleanup_error(err: &str) -> bool {
    err.contains("H3_NO_ERROR")
        || err.contains("ApplicationClose")
        || err.contains("connection closed")
        || err.contains("stream closed")
}
