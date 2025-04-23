use serde::{Serialize, Deserialize};




#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketOpt {

    #[serde(rename = "mark")]
    mark: Option<i16>,

    #[serde(rename = "interface")]
    interface: Option<String>,

    #[serde(rename = "readTimeout")]
    read_timeout: Option<i16>,

    #[serde(rename = "writeTimeout")]
    write_timeout: Option<i16>,

    #[serde(rename = "recvBufferSize")]
    recv_buffer_size: Option<usize>,

    #[serde(rename = "sendBufferSize")]
    send_buffer_size: Option<usize>,

    #[serde(rename = "tcpNoDelay")]
    tcp_nodelay: Option<bool>,

    #[serde(rename = "tcpcongestion")]
    tcp_congestion: Option<String>,
}

impl Default for SocketOpt {
    fn default() -> Self {
        SocketOpt {
            mark: None,
            interface: None,
            tcp_congestion: None,
            read_timeout: Some(5),
            write_timeout: Some(5),
            recv_buffer_size: Some(2097152), // 2MB
            send_buffer_size: Some(2097152), // 
            tcp_nodelay: Some(true), // true,
        }
    }
}

impl SocketOpt {
    // 
}