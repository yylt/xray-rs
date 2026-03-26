use super::*;
use crate::common::socks::Socks5Processor;
use crate::proxy::trojan;
use ahash::RandomState;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

// Message types
const MSG_REGISTER: u8 = 0x01;
const MSG_NEW_CONN: u8 = 0x02;
const MSG_DATA_HANDSHAKE: u8 = 0x03;
const MSG_HEARTBEAT: u8 = 0x04;
const MSG_TARGET_RESULT: u8 = 0x05;

// Protocol constants
const PASSWORD_HASH_LEN: usize = 64;
const UUID_LEN: usize = 16;

#[allow(unused)]
#[derive(Debug, Clone)]
enum ControlMessage {
    NewConnection {
        conn_id: Uuid,
        target: Address,
    },
    Heartbeat {
        timestamp: u64,
    },
    TargetResult {
        conn_id: Uuid,
        success: bool,
        error_code: u8,
    },
    Shutdown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InSetting {
    #[serde(rename = "password")]
    pub password: String,

    #[serde(rename = "heartbeat")]
    pub heartbeat: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutSetting {
    #[serde(rename = "address")]
    pub address: String,

    #[serde(rename = "port")]
    pub port: u16,

    #[serde(rename = "remote_port")]
    pub remote_port: u16,

    #[serde(rename = "password")]
    pub password: String,
}

// ============================================================================
// Shared Protocol Functions
// ============================================================================

fn encode_register_message(password_hash: &str, remote_port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + PASSWORD_HASH_LEN + 2);
    buf.push(MSG_REGISTER);
    buf.extend_from_slice(password_hash.as_bytes());
    buf.extend_from_slice(&remote_port.to_be_bytes());
    buf
}

fn encode_register_response_success(client_id: Uuid) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 1 + UUID_LEN);
    buf.push(MSG_REGISTER);
    buf.push(0x00); // success
    buf.extend_from_slice(client_id.as_bytes());
    buf
}

fn encode_register_response_failure(status: u8, error_msg: &str) -> Vec<u8> {
    let msg_bytes = error_msg.as_bytes();
    let msg_len = msg_bytes.len() as u16;
    let mut buf = Vec::with_capacity(1 + 1 + 2 + msg_bytes.len());
    buf.push(MSG_REGISTER);
    buf.push(status);
    buf.extend_from_slice(&msg_len.to_be_bytes());
    buf.extend_from_slice(msg_bytes);
    buf
}

async fn read_address_from_stream(stream: &mut transport::TrStream) -> Result<Address> {
    let mut addr_type = [0u8; 1];
    stream.read_exact(&mut addr_type).await?;

    match addr_type[0] {
        0x01 => {
            // IPv4
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);

            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            Ok(Address::Inet(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port))))
        }
        0x03 => {
            // Domain
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let domain_len = len_buf[0] as usize;

            let mut domain_buf = vec![0u8; domain_len];
            stream.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8_lossy(&domain_buf).to_string();

            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);

            Ok(Address::Domain(domain, port))
        }
        0x04 => {
            // IPv6
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            let mut port_bytes = [0u8; 2];
            stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);

            Ok(Address::Inet(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(buf),
                port,
                0,
                0,
            ))))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid address type: {}", addr_type[0]),
        )),
    }
}

async fn send_socks5_success(stream: &mut TcpStream, bind_addr: &Address) -> Result<()> {
    let mut response = vec![0x05, 0x00, 0x00]; // VER, REP (success), RSV

    // Add bind address
    match bind_addr {
        Address::Inet(addr) => {
            match addr {
                std::net::SocketAddr::V4(v4) => {
                    response.push(0x01); // IPv4
                    response.extend_from_slice(&v4.ip().octets());
                    response.extend_from_slice(&v4.port().to_be_bytes());
                }
                std::net::SocketAddr::V6(v6) => {
                    response.push(0x04); // IPv6
                    response.extend_from_slice(&v6.ip().octets());
                    response.extend_from_slice(&v6.port().to_be_bytes());
                }
            }
        }
        Address::Domain(domain, port) => {
            response.push(0x03); // Domain
            response.push(domain.len() as u8);
            response.extend_from_slice(domain.as_bytes());
            response.extend_from_slice(&port.to_be_bytes());
        }
        _ => {
            // Use 0.0.0.0:0 as placeholder
            response.push(0x01);
            response.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
    }

    stream.write_all(&response).await?;
    Ok(())
}

async fn send_socks5_error(stream: &mut TcpStream, error_code: u8) -> Result<()> {
    let response = vec![
        0x05,       // VER
        error_code, // REP
        0x00,       // RSV
        0x01,       // ATYP (IPv4)
        0, 0, 0, 0, // Bind address (0.0.0.0)
        0, 0, // Bind port (0)
    ];

    stream.write_all(&response).await?;
    Ok(())
}

// ============================================================================
// reverse Inbound (Server)
// ============================================================================

pub struct ReversInbound {
    password_hash: String,
    heartbeat: Duration,
    tr: transport::Transport,
}

impl ReversInbound {
    pub fn new(setting: &InSetting, tr: transport::Transport) -> Result<Self> {
        // Validate password length
        if setting.password.len() < 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Password must be at least 8 characters",
            ));
        }

        let heartbeat = setting.heartbeat.unwrap_or(30);
        if heartbeat == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Heartbeat must be greater than 0",
            ));
        }

        Ok(Self {
            password_hash: trojan::compute_password_hash(&setting.password),
            heartbeat: Duration::from_secs(heartbeat),
            tr,
        })
    }

    pub async fn run(self, listen_addr: Address) -> Result<()> {
        info!("Starting reverse Inbound on {:?}", listen_addr);

        let control_server = Arc::new(ControlServer::new());

        // Listen for control connections
        let listener = self.tr.listen(&listen_addr).await?;

        tokio::pin!(listener);

        // spawn a cleanup task
        let control_server_clone = control_server.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;

                let mut pending = control_server_clone.pending_conns.write().await;
                let now = Instant::now();

                pending.retain(|conn_id, conn| {
                    let elapsed = now.duration_since(conn.created_at).as_secs();
                    if elapsed > 30 {
                        warn!("Removing stale pending connection: {}", conn_id);
                        false
                    } else {
                        true
                    }
                });
            }
        });

        while let Some(result) = tokio_stream::StreamExt::next(&mut listener).await {
            match result {
                Ok((stream, peer_addr)) => {
                    info!("New control connection from {:?}", peer_addr);
                    let password_hash = self.password_hash.clone();
                    let control_server = control_server.clone();
                    let heartbeat = self.heartbeat;
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_connection(stream, peer_addr, password_hash, heartbeat, control_server).await
                        {
                            error!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept control connection: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn handle_connection(
        mut stream: transport::TrStream,
        _peer_addr: Address,
        password_hash: String,
        heartbeat: Duration,
        control_server: Arc<ControlServer>,
    ) -> Result<()> {
        // Peek first byte to determine connection type
        let mut msg_type = [0u8; 1];
        stream.read_exact(&mut msg_type).await?;

        match msg_type[0] {
            MSG_REGISTER => {
                Self::handle_control_connection(stream, _peer_addr, password_hash, heartbeat, control_server).await
            }
            MSG_DATA_HANDSHAKE => Self::handle_data_connection_inbound(stream, _peer_addr, control_server).await,
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown message type: {}", msg_type[0]),
            )),
        }
    }

    async fn handle_control_connection(
        mut stream: transport::TrStream,
        _peer_addr: Address,
        expected_password_hash: String,
        heartbeat: Duration,
        control_server: Arc<ControlServer>,
    ) -> Result<()> {
        // Read password hash
        let mut password_hash = vec![0u8; PASSWORD_HASH_LEN];
        stream.read_exact(&mut password_hash).await?;

        let received_hash = String::from_utf8_lossy(&password_hash);

        // Verify password
        if received_hash != expected_password_hash {
            let response = encode_register_response_failure(0x01, "Invalid password");
            stream.write_all(&response).await?;
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Invalid password"));
        }

        // Read remote_port
        let mut port_bytes = [0u8; 2];
        stream.read_exact(&mut port_bytes).await?;
        let remote_port = u16::from_be_bytes(port_bytes);

        // Validate port range
        if remote_port < 1024 {
            let response = encode_register_response_failure(0x03, "Invalid port range");
            stream.write_all(&response).await?;
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid port range"));
        }

        // Generate client ID
        let client_id = Uuid::new_v4();

        // Create channel for control messages
        let (control_tx, mut control_rx) = mpsc::channel::<ControlMessage>(32);
        let heartbeat_tx = control_tx.clone();

        // Start SOCKS5 server
        let control_server_clone = control_server.clone();
        let client_id_str = client_id.to_string();
        let socks_handle = tokio::spawn(async move {
            if let Err(e) = Self::run_socks5_server(remote_port, control_server_clone, client_id_str).await {
                error!("SOCKS5 server error: {}", e);
            }
        });

        // Register client
        match control_server
            .register_client(client_id.to_string(), remote_port, control_tx, socks_handle)
            .await
        {
            Ok(_) => {
                let response = encode_register_response_success(client_id);
                stream.write_all(&response).await?;
                info!("Client {} registered on port {}", client_id, remote_port);
            }
            Err(e) => {
                let response = encode_register_response_failure(0x02, &e.to_string());
                stream.write_all(&response).await?;
                return Err(e);
            }
        }

        let heartbeat_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(heartbeat);
            interval.tick().await;

            loop {
                interval.tick().await;

                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if heartbeat_tx
                    .send(ControlMessage::Heartbeat { timestamp })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // Handle control messages
        loop {
            tokio::select! {
                Some(msg) = control_rx.recv() => {
                    match msg {
                        ControlMessage::NewConnection { conn_id, target } => {
                            // Send new connection notification to client
                            let mut msg_buf = Vec::with_capacity(1 + UUID_LEN + 64);
                            msg_buf.push(MSG_NEW_CONN);
                            msg_buf.extend_from_slice(conn_id.as_bytes());

                            // Encode target address
                            match &target {
                                Address::Inet(addr) => {
                                    match addr {
                                        std::net::SocketAddr::V4(v4) => {
                                            msg_buf.push(0x01); // IPv4
                                            msg_buf.extend_from_slice(&v4.ip().octets());
                                            msg_buf.extend_from_slice(&v4.port().to_be_bytes());
                                        }
                                        std::net::SocketAddr::V6(v6) => {
                                            msg_buf.push(0x04); // IPv6
                                            msg_buf.extend_from_slice(&v6.ip().octets());
                                            msg_buf.extend_from_slice(&v6.port().to_be_bytes());
                                        }
                                    }
                                }
                                Address::Domain(domain, port) => {
                                    msg_buf.push(0x03); // Domain
                                    msg_buf.push(domain.len() as u8);
                                    msg_buf.extend_from_slice(domain.as_bytes());
                                    msg_buf.extend_from_slice(&port.to_be_bytes());
                                }
                                Address::Unix(_) => {
                                    error!("Unix socket not supported in reverse");
                                    continue;
                                }
                            }

                            if let Err(e) = stream.write_all(&msg_buf).await {
                                error!("Failed to send new connection message: {}", e);
                                break;
                            }

                            debug!("Sent new connection notification for {}", conn_id);
                        }
                        ControlMessage::Heartbeat { timestamp } => {
                            let mut msg_buf = Vec::with_capacity(1 + 8);
                            msg_buf.push(MSG_HEARTBEAT);
                            msg_buf.extend_from_slice(&timestamp.to_be_bytes());

                            if stream.write_all(&msg_buf).await.is_err() {
                                break;
                            }
                        }
                        ControlMessage::Shutdown => {
                            info!("Shutting down control connection for client {}", client_id);
                            break;
                        }
                        _ => {
                            // Handle other message types if needed
                        }
                    }
                }
            }
        }

        heartbeat_handle.abort();

        // Cleanup
        control_server.unregister_client(&client_id.to_string()).await;

        Ok(())
    }

    async fn handle_data_connection_inbound(
        mut stream: transport::TrStream,
        _peer_addr: Address,
        control_server: Arc<ControlServer>,
    ) -> Result<()> {
        // Read connection ID
        let mut conn_id_bytes = [0u8; UUID_LEN];
        stream.read_exact(&mut conn_id_bytes).await?;
        let conn_id = Uuid::from_bytes(conn_id_bytes);

        debug!("Data connection for {}", conn_id);

        // Find pending connection
        let pending_conn = {
            let mut pending = control_server.pending_conns.write().await;
            pending.remove(&conn_id)
        };

        let mut pending_conn = match pending_conn {
            Some(conn) => {
                // Check timeout (30 seconds)
                if conn.created_at.elapsed().as_secs() > 30 {
                    let response = vec![MSG_DATA_HANDSHAKE, 0x02]; // timeout
                    stream.write_all(&response).await?;
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Pending connection timeout"));
                }
                conn
            }
            None => {
                let response = vec![MSG_DATA_HANDSHAKE, 0x01]; // not found
                stream.write_all(&response).await?;
                return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Connection ID not found"));
            }
        };

        // Send success response
        let response = vec![MSG_DATA_HANDSHAKE, 0x00];
        stream.write_all(&response).await?;

        debug!("Data connection handshake successful for {}", conn_id);

        // Wait for target connection result
        let mut result_msg = [0u8; 3];
        stream.read_exact(&mut result_msg).await?;

        if result_msg[0] != MSG_TARGET_RESULT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected target result message",
            ));
        }

        if result_msg[1] != 0x00 {
            // Target connection failed
            let error_code = result_msg[2];
            error!("Target connection failed with code: {}", error_code);

            let socks_error = match error_code {
                0x03 => 0x03,
                0x04 => 0x04,
                0x05 => 0x05,
                _ => 0x01,
            };

            send_socks5_error(&mut pending_conn.socks_stream, socks_error).await?;
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Target connection failed"));
        }

        // Target connection successful
        send_socks5_success(&mut pending_conn.socks_stream, &pending_conn.target_addr).await?;

        // Forward traffic bidirectionally using StreamForwarder
        let forwarder = crate::common::forward::StreamForwarder::new();
        let socks_tr_stream = transport::TrStream::Tcp(pending_conn.socks_stream);

        if let Err(e) = forwarder.forward(stream, socks_tr_stream).await {
            error!("Traffic forwarding error: {}", e);
        }

        Ok(())
    }

    async fn handle_socks5_connection(
        stream: TcpStream,
        _peer_addr: std::net::SocketAddr,
        control_server: Arc<ControlServer>,
        client_id: String,
    ) -> Result<()> {
        // Parse SOCKS5 handshake
        let mut processor = Socks5Processor::new(None);
        let (socks_stream, cmd, target_addr) = processor
            .process(stream)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if cmd != crate::common::socks::Command::Connect {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Only CONNECT command is supported",
            ));
        }

        debug!("SOCKS5 target: {:?}", target_addr);

        // Generate connection ID
        let conn_id = Uuid::new_v4();

        // Store pending connection - must happen before sending notification to avoid race
        {
            let mut pending = control_server.pending_conns.write().await;
            pending.insert(
                conn_id,
                PendingConn {
                    socks_stream,
                    target_addr: target_addr.clone(),
                    created_at: Instant::now(),
                },
            );
        }

        // Notify client via control connection
        let clients = control_server.clients.read().await;
        if let Some(client) = clients.get(&client_id) {
            let msg = ControlMessage::NewConnection {
                conn_id,
                target: target_addr,
            };

            if let Err(e) = client.control_tx.send(msg).await {
                error!("Failed to send new connection notification: {}", e);
                // Remove pending connection
                control_server.pending_conns.write().await.remove(&conn_id);
                return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Control connection closed"));
            }
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Client not found"));
        }

        Ok(())
    }

    async fn run_socks5_server(remote_port: u16, control_server: Arc<ControlServer>, client_id: String) -> Result<()> {
        let listen_addr = format!("0.0.0.0:{}", remote_port);
        let listener = TcpListener::bind(&listen_addr).await?;

        info!("SOCKS5 server listening on {}", listen_addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("SOCKS5 connection from {}", peer_addr);

                    let control_server = control_server.clone();
                    let client_id = client_id.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_socks5_connection(stream, peer_addr, control_server, client_id).await
                        {
                            error!("SOCKS5 connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept SOCKS5 connection: {}", e);
                }
            }
        }
    }
}

// ============================================================================
// reverse Outbound (Client)
// ============================================================================

pub struct ReversOutbound {
    server_addr: Address,
    remote_port: u16,
    password: String,
    tr: transport::Transport,
}

impl ReversOutbound {
    pub fn new(setting: &OutSetting, tr: transport::Transport) -> Result<Self> {
        // Validate password length
        if setting.password.len() < 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Password must be at least 8 characters",
            ));
        }

        // Parse server address
        let server_addr = Address::Domain(setting.address.clone(), setting.port);

        Ok(Self {
            server_addr,
            remote_port: setting.remote_port,
            password: setting.password.clone(),
            tr,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Starting reverse Outbound, connecting to {:?}", self.server_addr);

        // Establish control connection
        let mut control_stream = self.tr.connect(&self.server_addr, Protocol::Tcp).await?;

        // Send registration message
        let password_hash = trojan::compute_password_hash(&self.password);
        let register_msg = encode_register_message(&password_hash, self.remote_port);
        control_stream.write_all(&register_msg).await?;

        info!("Sent registration request for port {}", self.remote_port);

        // Read registration response
        let mut msg_type = [0u8; 1];
        control_stream.read_exact(&mut msg_type).await?;

        if msg_type[0] != MSG_REGISTER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected registration response",
            ));
        }

        let mut status = [0u8; 1];
        control_stream.read_exact(&mut status).await?;

        if status[0] != 0x00 {
            // Registration failed, read error message
            let mut len_bytes = [0u8; 2];
            control_stream.read_exact(&mut len_bytes).await?;
            let msg_len = u16::from_be_bytes(len_bytes) as usize;

            let mut error_msg = vec![0u8; msg_len];
            control_stream.read_exact(&mut error_msg).await?;

            let error_str = String::from_utf8_lossy(&error_msg);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Registration failed: {}", error_str),
            ));
        }

        // Read client ID
        let mut client_id_bytes = [0u8; UUID_LEN];
        control_stream.read_exact(&mut client_id_bytes).await?;
        let client_id = Uuid::from_bytes(client_id_bytes);

        info!("Registration successful, client ID: {}", client_id);

        loop {
            // Read message type
            let mut msg_type = [0u8; 1];
            match control_stream.read_exact(&mut msg_type).await {
                Ok(_) => {}
                Err(e) => {
                    error!("Control connection closed: {}", e);
                    break;
                }
            }

            match msg_type[0] {
                MSG_NEW_CONN => {
                    // Read connection ID
                    let mut conn_id_bytes = [0u8; UUID_LEN];
                    control_stream.read_exact(&mut conn_id_bytes).await?;
                    let conn_id = Uuid::from_bytes(conn_id_bytes);

                    // Read target address
                    let target_addr = read_address_from_stream(&mut control_stream).await?;

                    info!("New connection request: {} -> {:?}", conn_id, target_addr);

                    // Create new data connection to server
                    let data_stream = match self.tr.connect(&self.server_addr, Protocol::Tcp).await {
                        Ok(stream) => stream,
                        Err(e) => {
                            error!("Failed to connect to server for data connection: {}", e);
                            continue;
                        }
                    };

                    // Spawn task to handle data connection
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_data_connection(conn_id, target_addr, data_stream).await {
                            error!("Data connection error for {}: {}", conn_id, e);
                        }
                    });
                }
                MSG_HEARTBEAT => {
                    let mut timestamp_bytes = [0u8; 8];
                    control_stream.read_exact(&mut timestamp_bytes).await?;
                }
                _ => {
                    warn!("Unknown message type: {}", msg_type[0]);
                }
            }
        }
        Ok(())
    }

    async fn handle_data_connection(
        conn_id: Uuid,
        target_addr: Address,
        mut data_stream: transport::TrStream,
    ) -> Result<()> {
        // Send data connection handshake
        let mut handshake = Vec::with_capacity(1 + UUID_LEN);
        handshake.push(MSG_DATA_HANDSHAKE);
        handshake.extend_from_slice(conn_id.as_bytes());
        data_stream.write_all(&handshake).await?;

        debug!("Sent data connection handshake for {}", conn_id);

        // Read handshake response
        let mut msg_type = [0u8; 1];
        data_stream.read_exact(&mut msg_type).await?;

        if msg_type[0] != MSG_DATA_HANDSHAKE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected data handshake response",
            ));
        }

        let mut status = [0u8; 1];
        data_stream.read_exact(&mut status).await?;

        if status[0] != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Data handshake failed with status: {}", status[0]),
            ));
        }

        debug!("Data connection handshake successful for {}", conn_id);

        // Connect to target - resolve address first
        let target_socket_addr = match &target_addr {
            Address::Inet(addr) => *addr,
            Address::Domain(domain, port) => {
                // Simple DNS resolution
                let addrs: Vec<_> = tokio::net::lookup_host((domain.as_str(), *port)).await?.collect();

                addrs.into_iter().next().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, format!("Failed to resolve domain: {}", domain))
                })?
            }
            Address::Unix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Unix sockets not supported for reverse",
                ));
            }
        };

        let target_result = match tokio::net::TcpStream::connect(target_socket_addr).await {
            Ok(target_stream) => {
                info!("Connected to target: {:?}", target_addr);

                // Send success notification
                let result_msg = vec![MSG_TARGET_RESULT, 0x00, 0x00];
                data_stream.write_all(&result_msg).await?;

                // Forward traffic using StreamForwarder
                let forwarder = crate::common::forward::StreamForwarder::new();
                let target_tr_stream = transport::TrStream::Tcp(target_stream);

                if let Err(e) = forwarder.forward(data_stream, target_tr_stream).await {
                    error!("Traffic forwarding error: {}", e);
                }

                Ok(())
            }
            Err(e) => {
                error!("Failed to connect to target: {}", e);

                // Determine error code
                let error_code = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => 0x05,
                    std::io::ErrorKind::NotFound => 0x04,
                    _ => 0x01,
                };

                // Send failure notification
                let result_msg = vec![MSG_TARGET_RESULT, 0x01, error_code];
                data_stream.write_all(&result_msg).await?;

                Err(e)
            }
        };

        target_result
    }
}

// ============================================================================
// Shared Helper Structures
// ============================================================================

struct ControlServer {
    clients: Arc<RwLock<HashMap<String, ClientInfo, RandomState>>>,
    pending_conns: Arc<RwLock<HashMap<Uuid, PendingConn, RandomState>>>,
}
#[allow(unused)]
struct ClientInfo {
    client_id: String,
    remote_port: u16,
    control_tx: mpsc::Sender<ControlMessage>,
    socks_handle: tokio::task::JoinHandle<()>,
}

struct PendingConn {
    socks_stream: tokio::net::TcpStream,
    target_addr: Address,
    created_at: Instant,
}

impl ControlServer {
    fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::with_hasher(RandomState::new()))),
            pending_conns: Arc::new(RwLock::new(HashMap::with_hasher(RandomState::new()))),
        }
    }

    async fn register_client(
        &self,
        client_id: String,
        remote_port: u16,
        control_tx: mpsc::Sender<ControlMessage>,
        socks_handle: tokio::task::JoinHandle<()>,
    ) -> Result<()> {
        let mut clients = self.clients.write().await;

        // Check if port is already in use
        for client in clients.values() {
            if client.remote_port == remote_port {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("Port {} already in use", remote_port),
                ));
            }
        }

        clients.insert(
            client_id.clone(),
            ClientInfo {
                client_id,
                remote_port,
                control_tx,
                socks_handle,
            },
        );

        Ok(())
    }

    async fn unregister_client(&self, client_id: &str) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.remove(client_id) {
            client.socks_handle.abort();
        }
    }
}
