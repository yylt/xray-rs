//! DNS upstream client and group types.
//!
//! An [`UpstreamClient`] wraps a [`ConnectionPool`] and exposes a simple
//! `query()` interface. An [`UpstreamGroup`] can query multiple clients in
//! serial or parallel mode.
//!
//! ## Error classification
//!
//! `UpstreamClient::query()` returns `io::Result<Message>`.  Errors
//! (returned as `Err(_)`) indicate that **no valid DNS response was
//! received** — the caller should retry the next server in the group
//! (`UpstreamGroup`) or return a SERVFAIL to the client.
//!
//! Errors that **do** produce `Err` (and thus trigger retry or SERVFAIL):
//!
//! | Source layer       | Example error                  | io::ErrorKind      |
//! |--------------------|--------------------------------|--------------------|
//! | Pool exhausted     | `NotConnected` — all max_size connections busy | NotConnected |
//! | Connection setup   | TCP connect / TLS handshake / QUIC handshake timeout or refused | TimedOut, ConnectionRefused, ConnectionReset |
//! | Connection dead    | `sender queue full` / `sender closed` — CloneableSender already shut down | BrokenPipe, Other |
//! | DNS transport      | `dns timeout` — no response within `dns_timeout` | TimedOut |
//! | Stream closed      | Multiplexer or QUIC stream terminated | ConnectionAborted, ConnectionReset, UnexpectedEof |
//! | DNS format         | Wire-format parse error in response | Other |
//! | Mux queue overflow | `mux request queue full` (256 outstanding requests) | Other |
//!
//! Errors that do **not** produce `Err` (they arrive as `Ok(Message)`)
//! because a valid DNS response was received:
//!
//! | DNS rcode       | Meaning                        | Handler responsibility |
//! |-----------------|--------------------------------|------------------------|
//! | SERVFAIL        | Upstream resolver failed       | Propagated as-is; caller may return SERVFAIL |
//! | NXDOMAIN        | Name does not exist            | Cached as negative (NxDomain) in `cache_upstream_response` |
//! | REFUSED         | Upstream refused the query     | Propagated as-is |
//! | FORMERR         | Upstream rejected query format | Propagated as-is |
//! | NoError (empty) | No records of requested type   | Cached as negative (NoData) in `cache_upstream_response` |
//!
//! `UpstreamGroup` retry semantics:
//!
//! - **Serial mode**: iterates clients; first `Ok` response wins; on `Err`,
//!   moves to the next client.  Returns the last error if all clients fail.
//! - **Parallel mode**: races all clients concurrently; first `Ok` wins;
//!   on `Err`, waits for remaining.  Returns the last error if all fail.
//!
//! In both modes, retry is at the **server** (UpstreamClient) granularity,
//! not at the connection level.  Connection-level retry (same server,
//! different address) is handled internally by `ConnectionPool::checkout()`.

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message};
use std::io;
use std::sync::Arc;

use super::pool::ConnectionPool;
use hickory_net::xfer::{DnsHandle, FirstAnswer};

/// A single upstream DNS client backed by a connection pool.
///
/// Cheap to clone — all clones share the same pool via `Arc`.
#[derive(Clone)]
pub struct UpstreamClient {
    pool: Arc<ConnectionPool>,
}

impl UpstreamClient {
    /// Creates a client that draws connections from `pool`.
    pub fn new(pool: Arc<ConnectionPool>) -> Self {
        Self { pool }
    }

    /// Sends a DNS query through the pool and returns the response.
    ///
    /// Internally calls `pool.checkout()` to obtain a `CloneableSender`,
    /// then `sender.send(request).first_answer().await`.
    pub async fn query(&self, msg: &Message) -> io::Result<Message> {
        let guard = self
            .pool
            .checkout()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no available connection in pool"))?;

        let request = DnsRequest::new(msg.clone(), DnsRequestOptions::default());
        let result = guard
            .sender()
            .send(request)
            .first_answer()
            .await
            .map(|response| response.into_message())
            .map_err(io::Error::other);

        match result {
            Ok(message) => {
                guard.record_success();
                Ok(message)
            }
            Err(err) => {
                guard.record_failure();
                Err(err)
            }
        }
    }
}

/// A group of upstream clients queried concurrently.
/// This is the top-level type stored in `DnsServer::upstreams`, keyed by
/// the upstream pool name from the config.
pub struct UpstreamGroup {
    clients: Vec<UpstreamClient>,
    mode: QueryMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryMode {
    Serial,
    Parallel,
}

impl UpstreamGroup {
    /// Creates a group from a list of clients.
    pub fn new(clients: Vec<UpstreamClient>, mode: QueryMode) -> Self {
        Self { clients, mode }
    }

    /// Sends `msg` using the group's configured query mode.
    pub async fn query(&self, msg: &Message) -> io::Result<Message> {
        match self.mode {
            QueryMode::Serial => self.query_serial(msg).await,
            QueryMode::Parallel => self.query_parallel(msg).await,
        }
    }

    async fn query_serial(&self, msg: &Message) -> io::Result<Message> {
        let mut first_err: Option<io::Error> = None;
        for client in &self.clients {
            match client.query(msg).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        Err(first_err.unwrap_or_else(|| io::Error::other("no upstream servers configured")))
    }

    async fn query_parallel(&self, msg: &Message) -> io::Result<Message> {
        let msg_arc = Arc::new(msg.clone());
        let mut futs: FuturesUnordered<_> = self
            .clients
            .iter()
            .map(|client| {
                let client = client.clone();
                let m = msg_arc.clone();
                async move { client.query(&m).await }
            })
            .collect();

        let mut first_err: Option<io::Error> = None;
        while let Some(result) = futs.next().await {
            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        Err(first_err.unwrap_or_else(|| io::Error::other("no upstream servers configured")))
    }

    /// Builds a query message from a cache key and sends it.
    ///
    /// Used by the serve-expired background refresh path.
    pub async fn query_bg(&self, cache_key: &super::cache::CacheKey) -> io::Result<Message> {
        let msg = super::server::make_query_msg(&cache_key.name, cache_key.qtype)?;
        self.query(&msg).await
    }
}
