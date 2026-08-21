//! Per-query context threaded through the fixed rsdns pipeline.
//!
//! The pipeline is a fixed sequence of stages (see `server.rs`):
//!
//! ```text
//! logs → hosts → groups → cache → rules
//! ```
//!
//! `upstream` is **not** a pipeline stage: it is assembled at startup into
//! [`crate::upstream::Upstreams`] and held directly by the `rules` stage
//! (forward / cname) — no per-query injection is needed.
//!
//! Each stage reads and mutates the shared [`QueryContext`], and either
//! short-circuits with [`Step::Respond`] (a response is ready in
//! `ctx.response`) or continues with [`Step::Continue`].

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use std::net::SocketAddr;
use std::time::Instant;

use super::plugins::cache::CacheKey;

/// What a pipeline stage wants the caller to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Continue to the next stage.
    Continue,
    /// `ctx.response` is ready; stop the pipeline.
    Respond,
}

impl Step {
    pub fn is_respond(self) -> bool {
        matches!(self, Step::Respond)
    }
}

/// Per-query context threaded through the whole pipeline.
pub struct QueryContext {
    /// The original query message.
    pub msg: Message,
    /// Cache key derived from the question (lowercased name + qtype).
    pub key: CacheKey,
    /// Client address.
    pub client: SocketAddr,
    /// "udp" or "tcp".
    pub proto: &'static str,
    /// When the query was received (set by the server before the pipeline).
    pub start: Instant,
    /// Size of the original request in bytes (for query logging).
    pub size: usize,

    // Control bits — stages may flip these.
    /// When set, the `logs` stage does not print this query.
    pub skip_log: bool,
    /// When set, the `cache` stage skips both lookup and write-back.
    pub skip_cache: bool,
    /// When set, the `speed` stage skips latency-ordered answer sorting
    /// (set by the groups stage for groups with `skip_speed: true`).
    pub skip_speed: bool,

    // State filled in by stages along the pipeline.
    /// Set by a responding stage (hosts / cache / rules).
    pub response: Option<Message>,
    /// Human-readable action label for logging/metrics (e.g. "hosts",
    /// "forward(default)", "block-nxdomain", "forward-stale").
    pub action: String,
    /// Domain group the queried name belongs to (set by the groups stage).
    pub group: Option<String>,
    /// Placeholder captures from the matched rule target (e.g. `{1}` in
    /// `match: "{1}.example.com"`); index = placeholder number - 1.  Set by
    /// the rules stage; reused by actions (e.g. `cname.target`).
    pub captures: Vec<String>,
    /// Set by the cache stage when a stale entry was served as a fallback;
    /// the rules stage tries to replace it with a fresh upstream answer.
    pub served_stale: bool,
}

impl QueryContext {
    pub fn new(
        msg: Message,
        key: CacheKey,
        client: SocketAddr,
        proto: &'static str,
        start: Instant,
        size: usize,
    ) -> Self {
        Self {
            msg,
            key,
            client,
            proto,
            start,
            size,
            skip_log: false,
            skip_cache: false,
            skip_speed: false,
            response: None,
            action: String::new(),
            group: None,
            captures: Vec::new(),
            served_stale: false,
        }
    }

    /// Convenience: the lowercase query name without trailing dot.
    pub fn name(&self) -> &str {
        &self.key.name
    }

    pub fn qtype(&self) -> RecordType {
        self.key.qtype
    }
}
