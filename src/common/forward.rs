use crate::common::stats::{TrafficCounters, TrafficStats};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Counts only bytes accepted by the destination writer, including partial writes.
pub(crate) struct CountingStream<T> {
    pub inner: T,
    pub counters: TrafficCounters,
    pub uplink: bool,
}

impl<T: AsyncRead + Unpin> AsyncRead for CountingStream<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountingStream<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if this.uplink {
                    this.counters.record_uplink(n as u64);
                } else {
                    this.counters.record_downlink(n as u64);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
use crate::transport::TrStream;

/// Alias for the forwarding future result
pub type ForwardFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<(u64, u64)>> + Send + 'a>>;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub struct StreamForwarder;

const DEFAULT_BUF_SIZE: usize = 64 * 1024;
impl Default for StreamForwarder {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamForwarder {
    pub fn new() -> Self {
        Self
    }

    pub fn forward<'a>(&'a self, mut local: TrStream, mut remote: TrStream) -> ForwardFuture<'a> {
        Box::pin(async move {
            let result =
                tokio::io::copy_bidirectional_with_sizes(&mut local, &mut remote, DEFAULT_BUF_SIZE, DEFAULT_BUF_SIZE)
                    .await;

            let _ = local.shutdown().await;
            let _ = remote.shutdown().await;

            result
        })
    }

    /// Forward with traffic statistics tracking
    pub fn forward_with_stats<'a>(
        &'a self,
        local: TrStream,
        remote: TrStream,
        stats: Arc<TrafficStats>,
    ) -> ForwardFuture<'a> {
        self.forward_with_counters(
            local,
            remote,
            TrafficCounters {
                inbound: None,
                outbound: Some(stats),
            },
        )
    }

    pub fn forward_with_counters<'a>(
        &'a self,
        local: TrStream,
        remote: TrStream,
        counters: TrafficCounters,
    ) -> ForwardFuture<'a> {
        Box::pin(async move {
            let mut local = CountingStream {
                inner: local,
                counters: counters.clone(),
                uplink: false,
            };
            let mut remote = CountingStream {
                inner: remote,
                counters,
                uplink: true,
            };
            let result =
                tokio::io::copy_bidirectional_with_sizes(&mut local, &mut remote, DEFAULT_BUF_SIZE, DEFAULT_BUF_SIZE)
                    .await;
            let _ = local.shutdown().await;
            let _ = remote.shutdown().await;
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TrStream;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    struct FailingWriter(bool);

    impl AsyncWrite for FailingWriter {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.0 {
                Poll::Ready(Err(io::Error::other("failed")))
            } else {
                this.0 = true;
                Poll::Ready(Ok(buf.len().min(2)))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn partial_write_survives_subsequent_error() {
        let stats = Arc::new(TrafficStats::new());
        let mut writer = CountingStream {
            inner: FailingWriter(false),
            counters: TrafficCounters {
                inbound: Some(stats.clone()),
                outbound: None,
            },
            uplink: true,
        };
        assert!(writer.write_all(b"hello").await.is_err());
        assert_eq!(stats.uplink(), 2);
        assert_eq!(stats.downlink(), 0);
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn test_stream_forwarder_basic() {
        let (stream1, mut peer1) = tcp_pair().await;
        let (stream2, mut peer2) = tcp_pair().await;

        let forwarder = StreamForwarder::new();
        let forward_task =
            tokio::spawn(async move { forwarder.forward(TrStream::Tcp(stream1), TrStream::Tcp(stream2)).await });

        peer1.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        peer2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        peer2.write_all(b"pong").await.unwrap();
        peer1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        drop(peer1);
        drop(peer2);
        let _ = forward_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_stream_forwarder_preserves_half_close_response() {
        let (stream1, mut peer1) = tcp_pair().await;
        let (stream2, mut peer2) = tcp_pair().await;

        let forwarder = StreamForwarder::new();
        let forward_task =
            tokio::spawn(async move { forwarder.forward(TrStream::Tcp(stream1), TrStream::Tcp(stream2)).await });

        peer1.write_all(b"hello").await.unwrap();
        peer1.shutdown().await.unwrap();

        let mut req = [0u8; 5];
        peer2.read_exact(&mut req).await.unwrap();
        assert_eq!(&req, b"hello");

        peer2.write_all(b"world").await.unwrap();
        peer2.shutdown().await.unwrap();

        let mut resp = [0u8; 5];
        peer1.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"world");

        let _ = forward_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_stream_forwarder_with_stats() {
        let (stream1, mut peer1) = tcp_pair().await;
        let (stream2, mut peer2) = tcp_pair().await;

        let stats = Arc::new(TrafficStats::new());
        let forwarder = StreamForwarder::new();
        let stats_clone = stats.clone();
        let forward_task = tokio::spawn(async move {
            forwarder
                .forward_with_stats(TrStream::Tcp(stream1), TrStream::Tcp(stream2), stats_clone)
                .await
        });

        peer1.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        peer2.read_exact(&mut buf).await.unwrap();

        peer2.write_all(b"pong").await.unwrap();
        peer1.read_exact(&mut buf).await.unwrap();

        assert!(!forward_task.is_finished());
        assert_eq!(stats.uplink(), 4);
        assert_eq!(stats.downlink(), 4);
        drop(peer1);
        drop(peer2);
        let (uplink, downlink) = forward_task.await.unwrap().unwrap();

        assert_eq!(uplink, 4); // "ping"
        assert_eq!(downlink, 4); // "pong"
        assert_eq!(stats.uplink(), 4);
        assert_eq!(stats.downlink(), 4);
    }
}
