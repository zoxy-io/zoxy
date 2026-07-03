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

/// Maximum clusters in a config. Bounds the per-worker balancer state so
/// round-robin counters can be reserved statically, one per cluster.
pub const clusters_max: usize = 64;

/// Per-direction relay buffer for streaming request bodies and responses.
pub const relay_buf_bytes: usize = 16 * 1024;

/// Bounds inside the chunked transfer-coding decoder (http/chunked.zig):
/// hex size digits (16 spans a full u64), extension bytes per chunk, and
/// total trailer-section bytes. Beyond any of these the message is malformed.
pub const chunk_size_digits_max: u8 = 16;
pub const chunk_extension_bytes_max: u32 = 256;
pub const trailer_bytes_max: u32 = 4096;

/// Per-request deadline, first head byte to last response byte. Backstops
/// slow-loris clients, stalled relays, and unresponsive upstreams.
pub const request_timeout_ns: u63 = 30 * std.time.ns_per_s;

/// How long a keep-alive connection may sit idle between requests.
pub const idle_timeout_ns: u63 = 60 * std.time.ns_per_s;

/// The per-connection timer fires at least this often and re-checks the
/// current absolute deadline. Deadlines can therefore move (request phase ->
/// idle phase) without any cancel/re-arm dance — exactly one timeout op is
/// in flight per connection — at the cost of up to one tick of enforcement
/// slop when a deadline moves closer.
pub const timeout_tick_ns: u63 = 1 * std.time.ns_per_s;

/// Idle upstream connections parked per worker (across all endpoints).
/// Checkin beyond this closes the connection instead of keeping it.
pub const upstream_idle_max: usize = 64;

/// Worker slots in per-worker metrics (SO_REUSEPORT distribution). Workers
/// beyond this share the last slot — the counters are diagnostic.
pub const workers_max: usize = 64;

/// Delay before re-arming accept after fd/resource exhaustion (EMFILE etc.).
/// An immediate re-arm would fail again instantly and spin the worker at
/// 100% CPU for as long as the condition persists.
pub const accept_retry_delay_ns: u63 = 100 * std.time.ns_per_ms;
