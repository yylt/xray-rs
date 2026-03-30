use crate::transport::TrStream;
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

    pub fn forward<'a>(
        &'a self,
        mut local: TrStream,
        mut remote: TrStream,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<(u64, u64)>> + Send + 'a>> {
        Box::pin(async move {
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
}
