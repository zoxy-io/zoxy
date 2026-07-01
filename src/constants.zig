//! All static limits live here (TigerStyle: "put a limit on everything; control
//! the number of things"). Sizing the proxy is choosing these numbers; total
//! memory is a function of them and is reserved up front.

const std = @import("std");

/// Maximum concurrent downstream connections per worker. Beyond this, new
/// connections are rejected (backpressure), never queued via allocation.
pub const connections_max: u32 = 256;

/// Per-connection read buffer. Must hold a full HTTP request head (see later
/// `head_bytes_max`) plus a useful chunk of body.
pub const read_buf_bytes: usize = 16 * 1024;

/// io_uring submission/completion queue depth per worker (power of two).
pub const io_ring_entries: u16 = 4096;

/// listen(2) backlog per worker listener.
pub const accept_backlog: u32 = 1024;

/// Maximum request header lines. Beyond this a request is rejected (431),
/// never grown. The head must also fit within `read_buf_bytes`.
pub const headers_max: usize = 64;

/// Per-direction relay buffer for streaming request bodies and responses.
pub const relay_buf_bytes: usize = 16 * 1024;

/// Overall per-connection deadline. Backstops slow-loris clients and stalled
/// relays: a connection that lives longer than this is torn down.
pub const connection_timeout_ns: u63 = 30 * std.time.ns_per_s;
