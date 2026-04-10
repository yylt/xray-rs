use serde::{Deserialize, Serialize};
use socket2::Socket;
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketOpt {
    #[serde(rename = "recvBufferSize")]
    recv_buffer_size: Option<usize>,

    #[serde(rename = "sendBufferSize")]
    send_buffer_size: Option<usize>,

    #[serde(rename = "tcpNoDelay")]
    tcp_nodelay: Option<bool>,

    #[serde(rename = "tcpCongestion")]
    tcp_congestion: Option<String>,
}

impl Default for SocketOpt {
    fn default() -> Self {
        SocketOpt {
            recv_buffer_size: Some(102400), // 100k
            send_buffer_size: Some(81920),  // 80k
            tcp_nodelay: Some(true),
            tcp_congestion: None,
        }
    }
}

impl SocketOpt {
    pub fn apply_tcpstream(&self, stream: TcpStream) -> std::io::Result<TcpStream> {
        let socket: Socket = stream.into_std()?.into();

        if let Some(nodelay) = self.tcp_nodelay {
            socket.set_tcp_nodelay(nodelay)?;
        }
        if let Some(size) = self.recv_buffer_size {
            socket.set_recv_buffer_size(size)?;
        }
        if let Some(size) = self.send_buffer_size {
            socket.set_send_buffer_size(size)?;
        }

        #[cfg(target_os = "linux")]
        if let Some(congestion) = &self.tcp_congestion {
            socket.set_tcp_congestion(congestion.as_bytes())?;
        }

        let std_stream: std::net::TcpStream = socket.into();
        Ok(TcpStream::from_std(std_stream)?)
    }

    #[cfg(unix)]
    pub fn apply_unixstream(&self, stream: UnixStream) -> std::io::Result<UnixStream> {
        let socket: Socket = stream.into_std()?.into();

        if let Some(size) = self.recv_buffer_size {
            socket.set_recv_buffer_size(size)?;
        }
        if let Some(size) = self.send_buffer_size {
            socket.set_send_buffer_size(size)?;
        }

        let std_stream: std::os::unix::net::UnixStream = socket.into();
        Ok(UnixStream::from_std(std_stream)?)
    }
}
