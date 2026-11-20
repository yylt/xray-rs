use super::*;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

async fn read_frame(peer: &mut DuplexStream) -> (u8, u8, Vec<u8>) {
    let mut header = [0; 9];
    peer.read_exact(&mut header).await.unwrap();
    let len = (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    let mut payload = vec![0; len];
    peer.read_exact(&mut payload).await.unwrap();
    (header[3], header[4], payload)
}

#[tokio::test]
async fn goaway_retires_sender_without_cancelling_accepted_request() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let target = ClientTarget::new(
            "127.0.0.1:1".parse().unwrap(),
            "localhost".into(),
            SocketOpt::default(),
            None,
            65535,
        );
        let (io, mut peer) = tokio::io::duplex(4096);
        let handshake = target.handshake(io);
        let peer_handshake = async {
            let mut preface = [0; 24];
            peer.read_exact(&mut preface).await.unwrap();
            // Initial SETTINGS: allow two concurrent streams.
            peer.write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 2])
                .await
                .unwrap();
            loop {
                let (kind, flags, payload) = read_frame(&mut peer).await;
                if kind == 6 && flags == 0 {
                    peer.write_all(&[0, 0, 8, 6, 1, 0, 0, 0, 0]).await.unwrap();
                    peer.write_all(&payload).await.unwrap();
                    break;
                }
            }
        };
        let (connection, ()) = tokio::join!(handshake, peer_handshake);
        let connection = connection.unwrap();
        target.connections.lock().unwrap().push(connection.clone());
        let mut first = Some(Request::get("http://localhost/first").body(Bytes::new()).unwrap());
        let response = target.try_send(&mut first).unwrap().unwrap();
        loop {
            if read_frame(&mut peer).await.0 == 1 {
                break;
            }
        }
        // Graceful GOAWAY accepts stream 1, while refusing any new streams.
        peer.write_all(&[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0])
            .await
            .unwrap();
        loop {
            let refused = {
                let mut state = connection.lock().unwrap();
                let mut cx = Context::from_waker(futures::task::noop_waker_ref());
                matches!(state.sender.poll_ready(&mut cx), Poll::Ready(Err(_)))
            };
            if refused {
                break;
            }
            tokio::task::yield_now().await;
        }
        let mut next = Some(Request::get("http://localhost/next").body(Bytes::new()).unwrap());
        assert!(target.try_send(&mut next).unwrap().is_none());
        assert!(next.is_some(), "GOAWAY must not consume the unsent request");
        assert_eq!(connection.lock().unwrap().inflight, 1);
        // The accepted GET must survive retiring the sender. HPACK indexed :status 200.
        peer.write_all(&[0, 0, 1, 1, 4, 0, 0, 0, 1, 0x88]).await.unwrap();
        peer.write_all(&[0, 0, 2, 0, 1, 0, 0, 0, 1, b'o', b'k']).await.unwrap();
        let mut body = response.await.unwrap().into_body();
        assert_eq!(body.next().await.unwrap().unwrap(), Bytes::from_static(b"ok"));
        assert!(body.next().await.is_none());
        assert_eq!(connection.lock().unwrap().inflight, 0);
    })
    .await
    .expect("GOAWAY regression test timed out");
}

#[tokio::test]
async fn early_response_is_observed_with_zero_upload_window() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let target = ClientTarget::new(
            "127.0.0.1:1".parse().unwrap(),
            "localhost".into(),
            SocketOpt::default(),
            None,
            65535,
        );
        let (io, mut peer) = tokio::io::duplex(4096);
        let peer_handshake = async {
            let mut preface = [0; 24];
            peer.read_exact(&mut preface).await.unwrap();
            // MAX_CONCURRENT_STREAMS=2; INITIAL_WINDOW_SIZE=0.
            peer.write_all(&[0, 0, 12, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 2, 0, 4, 0, 0, 0, 0])
                .await
                .unwrap();
            loop {
                let (kind, flags, payload) = read_frame(&mut peer).await;
                if kind == 6 && flags == 0 {
                    peer.write_all(&[0, 0, 8, 6, 1, 0, 0, 0, 0]).await.unwrap();
                    peer.write_all(&payload).await.unwrap();
                    break;
                }
            }
        };
        let (connection, ()) = tokio::join!(target.handshake(io), peer_handshake);
        let connection = connection.unwrap();
        target.connections.lock().unwrap().push(connection.clone());
        let response = target
            .send(
                Request::post("http://localhost/upload")
                    .body(Bytes::from_static(b"blocked upload"))
                    .unwrap(),
            )
            .await
            .unwrap();
        loop {
            if read_frame(&mut peer).await.0 == 1 {
                break;
            }
        }
        // Literal :status = 403, with END_HEADERS and END_STREAM. No upload credit.
        peer.write_all(&[0, 0, 5, 1, 5, 0, 0, 0, 1, 0x08, 0x03, b'4', b'0', b'3'])
            .await
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
        drop(response);
        assert_eq!(connection.lock().unwrap().inflight, 0);
    })
    .await
    .expect("early response blocked behind request flow control");
}
