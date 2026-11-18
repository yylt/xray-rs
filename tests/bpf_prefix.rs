use bytes::Bytes;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use xray_rs::transport::{BufferedStream, TrStream};

#[tokio::test]
async fn tcp_extraction_preserves_nested_unread_prefix_order() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let inner = TrStream::Buffered(Box::new(BufferedStream::new(
        TrStream::Tcp(server),
        Bytes::from_static(b"body"),
    )));
    let mut outer = TrStream::Buffered(Box::new(BufferedStream::new(inner, Bytes::from_static(b"header"))));
    let mut consumed = [0; 2];
    outer.read_exact(&mut consumed).await.unwrap();
    assert_eq!(&consumed, b"he");
    assert!(outer.is_plain_tcp());
    let (_, prefix) = outer.into_tcp_with_prefix().unwrap();
    assert_eq!(&prefix[..], b"aderbody");
    drop(client);
}

#[tokio::test]
async fn udp_cannot_be_unwrapped_as_tcp() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stream = TrStream::Buffered(Box::new(BufferedStream::new(
        TrStream::Udp(socket),
        Bytes::from_static(b"data"),
    )));
    assert!(!stream.is_plain_tcp());
    assert!(stream.into_tcp_with_prefix().is_none());
}
