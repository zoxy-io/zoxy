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

/// Maximum endpoints in a single cluster. Bounds the per-worker resilience
/// state (in-flight counts, outlier ejection, health) so it can be reserved
/// statically, one slot per (cluster, endpoint).
pub const endpoints_per_cluster_max: u32 = 16;

/// Hard cap on a cluster's configured `retry.max`. Bounds the retry loop and
/// the worst-case backoff shift (`base << attempts`).
pub const retry_attempts_max: u8 = 5;

/// Defaults for a cluster `retry` block: fully-jittered exponential backoff,
/// delay drawn uniformly from [0, min(base << attempt, cap)).
pub const retry_backoff_base_ns_default: u63 = 25 * std.time.ns_per_ms;
pub const retry_backoff_cap_ns_default: u63 = 1 * std.time.ns_per_s;

/// Retry budget defaults (Envoy-style): retries may be in flight up to
/// max(budget_min, requests_active * budget_percent / 100) per worker.
pub const retry_budget_percent_default: u8 = 20;
pub const retry_budget_min_default: u32 = 3;

/// Defaults for a cluster `outlier` block (passive outlier detection):
/// consecutive attempt failures before an endpoint is ejected, how long it
/// stays ejected, and the ceiling on the ejected share of a cluster.
pub const outlier_consecutive_failures_default: u32 = 5;
pub const outlier_ejection_ns_default: u63 = 30 * std.time.ns_per_s;
pub const outlier_ejection_percent_max_default: u8 = 50;

/// Defaults for a cluster `health_check` block (active TCP-connect probes,
/// per worker, in-ring).
pub const health_interval_ns_default: u63 = 5 * std.time.ns_per_s;
pub const health_timeout_ns_default: u63 = 2 * std.time.ns_per_s;
pub const health_threshold_healthy_default: u16 = 2;
pub const health_threshold_unhealthy_default: u16 = 3;

/// Concurrent health probes in flight per worker; further due probes wait
/// for a free slot (bounded, never queued via allocation).
pub const health_probes_inflight_max: u32 = 8;

/// The health checker's scheduler tick: due-probe scan and probe-timeout
/// enforcement granularity.
pub const health_tick_ns: u63 = 100 * std.time.ns_per_ms;

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

/// The heap behind OpenSSL's process-global memory hook, reserved at startup
/// only when TLS is configured. Exhaustion fails the OpenSSL operation and
/// that handshake is rejected — load-shedding, never OOM, never growth.
/// Sized generously for now; Phase 3's termination slice measures actual
/// per-handshake usage and re-derives this from connections_max * workers.
pub const tls_heap_bytes: usize = 64 * 1024 * 1024;

/// Bounds a TLS certificate/private-key PEM file read at startup. Real cert
/// chains are a few KB; anything near this limit is a misconfiguration. Must
/// stay below maxInt(c_int): the PEM bytes cross the OpenSSL FFI boundary.
pub const tls_pem_bytes_max: u32 = 256 * 1024;

/// Each half of a connection's BIO pair buffers this much ciphertext (the
/// pair is the in-memory "network" between the SSL state machine and our
/// ring ops). Sized to hold one maximum TLS record (16 KiB payload + record
/// overhead) with headroom; larger flights loop through WANT_READ/WANT_WRITE.
pub const tls_bio_pair_bytes: usize = 18 * 1024;
