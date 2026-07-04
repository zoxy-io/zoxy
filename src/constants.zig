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

/// Maglev lookup-table entries per consistent-hash cluster (built at config
/// time, immutable after). Prime, per the algorithm ("Maglev: A Fast and
/// Reliable Software Network Load Balancer", §3.4); Envoy's default. Balance
/// error scales with endpoints/entries — at 16 endpoints it is under 0.1%.
/// One byte per entry: 64 KiB per hashed cluster.
pub const maglev_table_entries: u32 = 65537;

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

/// HTTP/2 frame payload bound: the SETTINGS_MAX_FRAME_SIZE we advertise to
/// peers and enforce on every received frame header (a longer frame is a
/// FRAME_SIZE_ERROR connection error before its payload arrives). The
/// RFC 9113 minimum-and-default 16 KiB, matching `relay_buf_bytes` so one
/// frame's payload always fits a relay buffer.
pub const h2_frame_payload_bytes_max: u24 = 16384;

/// HPACK dynamic-table capacity we advertise (SETTINGS_HEADER_TABLE_SIZE)
/// and reserve, per decoder — the RFC 7541 default. Peer size updates may
/// shrink the table, never exceed this.
pub const h2_header_table_bytes: u32 = 4096;

/// Decoded header-list bound we advertise (SETTINGS_MAX_HEADER_LIST_SIZE)
/// and enforce: the sum over fields of name + value + 32 (RFC 9113 §10.5.1).
/// Matches the HTTP/1.1 head budget (`read_buf_bytes`).
pub const h2_header_list_bytes_max: u32 = 16 * 1024;

/// Concurrent streams per HTTP/2 connection: advertised
/// (SETTINGS_MAX_CONCURRENT_STREAMS) and enforced with fixed stream slots —
/// excess opens are refused (REFUSED_STREAM), never grown.
pub const h2_streams_max: u32 = 64;

/// Per-stream receive window we advertise (SETTINGS_INITIAL_WINDOW_SIZE):
/// the relay-buffer size, so a stream's read-ahead permission equals the
/// buffer that will carry it (docs/DESIGN.md §7 Phase 5).
pub const h2_stream_window_bytes: u31 = 16 * 1024;

/// Connection-level receive-window target, raised from the 64 KiB protocol
/// default by one WINDOW_UPDATE at connection start: full per-stream
/// windows for every slot, so the connection window never throttles
/// multiplexing below the per-stream bound.
pub const h2_connection_window_bytes: u31 = h2_streams_max * h2_stream_window_bytes;

/// Encoded header-block accumulation bound (HEADERS plus CONTINUATIONs,
/// RFC 9113 §4.3) — a block must be complete before HPACK decoding. Also
/// the CONTINUATION-flood defense: a block still unfinished past this kills
/// the connection (ENHANCE_YOUR_CALM).
pub const h2_header_block_bytes_max: u32 = 16 * 1024;

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

/// Bound between "drain begins" (SIGTERM, or the trigger fd) and the forced
/// teardown of whatever is still open. Applied as a clamp on every live
/// connection's supreme deadline, so the existing per-connection ticking
/// timer enforces it — a worker is gone at most this long (plus one tick)
/// after the signal, whatever clients and origins do.
pub const drain_timeout_ns: u63 = 30 * std.time.ns_per_s;

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

/// The heap behind OpenSSL's process-global memory hook is reserved at
/// startup (TLS configured only) as
///   tls_heap_base_bytes + tls_heap_per_connection_bytes * connections_max * workers.
/// Exhaustion fails the OpenSSL operation and that handshake is rejected —
/// load-shedding, never OOM, never growth. The reservation is virtual;
/// pages are touched only as the heap carves (measured RSS follows load).
///
/// Measured 2026-07-04 (zoxy_tls_heap_carved_bytes, TLS 1.3, EC P-256):
/// one live TLS connection costs ~161 KiB of heap (consistent at 64 and
/// 256 concurrent connections: 11.1 MiB and 42.2 MiB carved) — the BIO
/// pair plus OpenSSL's per-SSL state, doubled-ish by power-of-two class
/// rounding. Process baseline (library init + SSL_CTX) was 0.9 MiB.
pub const tls_heap_base_bytes: usize = 8 * 1024 * 1024;
pub const tls_heap_per_connection_bytes: usize = 192 * 1024;

/// Bounds a TLS certificate/private-key PEM file read at startup. Real cert
/// chains are a few KB; anything near this limit is a misconfiguration. Must
/// stay below maxInt(c_int): the PEM bytes cross the OpenSSL FFI boundary.
pub const tls_pem_bytes_max: u32 = 256 * 1024;

/// Maximum server identities on the TLS listener (the default plus SNI
/// additions). Bounds the SNI table scan and the startup context builds.
pub const tls_identities_max: usize = 16;

/// Each half of a connection's BIO pair buffers this much ciphertext (the
/// pair is the in-memory "network" between the SSL state machine and our
/// ring ops). Sized to hold one maximum TLS record (16 KiB payload + record
/// overhead) with headroom; larger flights loop through WANT_READ/WANT_WRITE.
pub const tls_bio_pair_bytes: usize = 18 * 1024;
