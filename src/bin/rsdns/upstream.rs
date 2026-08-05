//! DNS upstream client and group types.
//!
//! An [`UpstreamClient`] wraps a [`ConnectionPool`] and exposes a simple
//! `query()` interface.  An [`UpstreamGroup`] fans queries out to multiple
//! clients concurrently, returning the first successful response.

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message};
use hickory_proto::rr::{DNSClass, Name, RecordType};
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
///
/// All clients in the group are queried in parallel via `FuturesUnordered`;
/// the first successful response wins.  If all clients fail, the last
/// error is returned.
///
/// This is the top-level type stored in `DnsServer::upstreams`, keyed by
/// the upstream pool name from the config.
pub struct UpstreamGroup {
    clients: Vec<UpstreamClient>,
}

impl UpstreamGroup {
    /// Creates a group from a list of clients.
    pub fn new(clients: Vec<UpstreamClient>) -> Self {
        Self { clients }
    }

    /// Sends `msg` to all clients in parallel; returns the first successful
    /// response, or the last failure if all fail.
    pub async fn query(&self, msg: &Message) -> io::Result<Message> {
        let mut futs: FuturesUnordered<_> = self
            .clients
            .iter()
            .map(|client| {
                let client = client.clone();
                let msg_owned = msg.clone();
                async move { client.query(&msg_owned).await }
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
        let mut msg = Message::new(0, hickory_proto::op::MessageType::Query, hickory_proto::op::OpCode::Query);
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_utf8(&cache_key.name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);
        q.set_query_type(match cache_key.qtype {
            28 => RecordType::AAAA,
            1 => RecordType::A,
            _ => RecordType::A,
        });
        q.set_query_class(DNSClass::IN);
        msg.queries.push(q);
        msg.metadata.recursion_desired = true;
        self.query(&msg).await
    }
}
