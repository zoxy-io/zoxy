//! The reverse-proxy data path (docs/DESIGN.md §5, §7). Per downstream
//! connection: receive the request head, route it to a cluster, connect an
//! upstream, forward the spliced head plus the *framed* request body, parse
//! the response head, then relay the framed response back. Both directions
//! know where their message ends (RFC 9112 §6.3 via `h1.BodyFramer`), so the
//! connection closes as soon as the response completes — an upstream that
//! ignores `Connection: close` cannot pin the slot until the deadline — and
//! bytes past a message end (a pipelined next request) are never forwarded.
//! Everything is reserved up front — the serving path allocates nothing.
//!
//! Lifetime: `refs` counts in-flight io_uring operations for a connection.
//! `teardown` flips `closing` and closes both fds; the resulting (and any other
//! pending) completions decrement `refs`, and the last one releases the slot.
//!
//! Downstream keep-alive: when a framed response completes for an HTTP/1.1
//! keep-alive client, the request is logged, pipelined bytes slide to the
//! front of the head buffer, and the connection parses its next head —
//! every request re-routed from scratch. Hop-by-hop headers are stripped in
//! both directions.
//!
//! Upstream keep-alive: requests are forwarded without a `Connection`
//! header (HTTP/1.1 default keep-alive), and a framed, reusable response
//! parks its connection in the per-worker `UpstreamPool`, keyed by
//! endpoint. A pooled connection the upstream closed while idle fails on
//! first use before any response byte — that request is replayed once on a
//! fresh connection (only possible when it fit entirely in the prime
//! segments). `Upgrade` requests are refused with 501; unframeable
//! exchanges close both sides.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const assert = std.debug.assert;

const io_mod = @import("../io/io.zig");
const IO = io_mod.IO;
const Completion = io_mod.Completion;
const constants = @import("../constants.zig");
const Listener = @import("listener.zig").Listener;
const h1 = @import("../http/h1.zig");
const h2_frame = @import("../http/h2_frame.zig");
const hpack = @import("../http/hpack.zig");
const config = @import("../config.zig");
const Router = @import("../proxy/router.zig").Router;
const balancer = @import("../proxy/balancer.zig");
const maglev = @import("../proxy/maglev.zig");
const resilience_mod = @import("../proxy/resilience.zig");
const Resilience = resilience_mod.Resilience;
const UpstreamPool = @import("../proxy/upstream_pool.zig").UpstreamPool;
const Counters = @import("../obs/metrics.zig").Counters;
const Counter = @import("../obs/metrics.zig").Counter;
const access_log = @import("../obs/access_log.zig");
const AccessLog = access_log.AccessLog;
const guard = @import("../mem/guard.zig");
const terminator = @import("../tls/terminator.zig");
const kernel_tls = @import("../tls/kernel.zig");
const h2_proxy = @import("h2_proxy.zig");
const H2ConnPool = h2_proxy.H2ConnPool;
const H2LegPool = h2_proxy.LegPool;
const Ip4Address = std.Io.net.Ip4Address;

const Pool = @import("pool.zig").Pool(ProxyConn);
/// TLS legs, pooled per worker like connections. Sized by config —
/// `connections_max` per TLS-speaking side (downstream termination,
/// upstream re-encryption) — so a conn's acquire of at most one leg per
/// side can never find the pool empty. Null when the config has no TLS.
pub const TlsLegPool = @import("pool.zig").Pool(ProxyConn.Tls);

// Fixed error responses (Connection: close so the client stops after reading).
const response_400 = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const response_404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const response_431 = "HTTP/1.1 431 Request Header Fields Too Large\r\n" ++
    "Content-Length: 0\r\nConnection: close\r\n\r\n";
const response_501 = "HTTP/1.1 501 Not Implemented\r\n" ++
    "Content-Length: 0\r\nConnection: close\r\n\r\n";
const response_502 = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const response_503 = "HTTP/1.1 503 Service Unavailable\r\n" ++
    "Content-Length: 0\r\nConnection: close\r\n\r\n";
const response_504 = "HTTP/1.1 504 Gateway Timeout\r\n" ++
    "Content-Length: 0\r\nConnection: close\r\n\r\n";
const response_505 = "HTTP/1.1 505 HTTP Version Not Supported\r\n" ++
    "Content-Length: 0\r\nConnection: close\r\n\r\n";

/// Placeholder for `ProxyConn.policy` between requests; every feature off,
/// every limit unbounded — it is never gated on outside a routed request.
const policy_default = config.ResiliencePolicy{};

/// Why an upstream attempt died before its response head completed.
/// Everything here happens strictly before any byte reaches the client, so
/// the request may be replayed when the safety conditions hold.
const AttemptFailure = enum {
    connect_error,
    send_error,
    recv_error,
    upstream_eof,
    per_try_timeout,
};

/// Terminates the upstream-bound head after the hop-by-hop headers are
/// stripped. Nothing is injected in their place: an HTTP/1.1 upstream
/// defaults to keep-alive, which is what the connection pool wants; the
/// response's own framing (not EOF) ends the exchange.
const head_terminator = "\r\n";

/// Injected into a relayed response head when the downstream connection
/// will close after it (RFC 9112 §9.6: a close must be announced — without
/// this, an HTTP/1.1 client assumes keep-alive, pipelines its next request,
/// and reads our close as a failure).
const close_header_line = "Connection: close\r\n";

/// Upper bound on prime segments: one kept run around each skipped header line
/// plus the `Connection: close` injection and any buffered body bytes.
const prime_segments_max = constants.headers_max + 3;

/// One direction of the relay: read from `src_fd`, write to `dst_fd`, repeat.
///
/// Backpressure (docs/DESIGN.md §1.4): strict recv -> send -> recv over a single
/// fixed buffer. We never read the next chunk until the current one is fully
/// written, so a slow destination stalls the source: its socket receive buffer
/// fills and TCP flow control throttles the peer. Memory per direction is
/// therefore bounded to `relay_buf_bytes` regardless of stream size — a stronger
/// guarantee than watermark read-disable, which only matters when reading ahead
/// into a growable buffer (a later throughput option we deliberately skip).
const Pipe = struct {
    conn: *ProxyConn,
    src_fd: posix.socket_t,
    dst_fd: posix.socket_t,
    /// True for the upstream->client direction (drives bytes_to_client metrics).
    to_client: bool,
    /// Frames the message flowing through this direction; bytes beyond the
    /// message end are never forwarded.
    framer: h1.BodyFramer,
    buf: [constants.relay_buf_bytes]u8,
    filled: usize,
    sent: usize,
    recv_completion: Completion,
    send_completion: Completion,

    fn arm_recv(pipe: *Pipe) void {
        assert(pipe.src_fd >= 0);
        assert(!pipe.framer.is_complete()); // a finished direction is never re-armed
        if (!pipe.to_client and pipe.conn.tls != null) {
            // The request-body direction reads from a TLS client.
            const leg = pipe.conn.tls.?;
            return pipe.conn.tls_recv_start(leg, &pipe.buf, on_tls_recv);
        }
        if (pipe.to_client and pipe.conn.upstream_tls != null) {
            // The response direction reads from a TLS origin.
            const leg = pipe.conn.upstream_tls.?;
            return pipe.conn.tls_recv_start(leg, &pipe.buf, on_upstream_tls_recv);
        }
        pipe.conn.retain();
        pipe.conn.io.recv(*Pipe, pipe, on_recv, &pipe.recv_completion, pipe.src_fd, &pipe.buf);
    }

    fn on_recv(pipe: *Pipe, _: *Completion, result: io_mod.RecvError!usize) void {
        defer pipe.conn.release_ref();
        if (pipe.conn.closing) return;
        pipe.handle_recv(result);
    }

    fn on_tls_recv(conn: *ProxyConn, result: io_mod.RecvError!usize) void {
        conn.request_pipe.handle_recv(result);
    }

    fn on_upstream_tls_recv(conn: *ProxyConn, result: io_mod.RecvError!usize) void {
        conn.response_pipe.handle_recv(result);
    }

    fn handle_recv(pipe: *Pipe, result: io_mod.RecvError!usize) void {
        assert(!pipe.conn.closing); // both callers bail first
        const n = result catch return pipe.conn.teardown();
        if (n == 0) return pipe.on_eof();
        assert(n <= pipe.buf.len); // the read can never exceed the fixed buffer
        const consumed = pipe.framer.consume(pipe.buf[0..n]) catch
            return pipe.conn.teardown(); // malformed chunked framing
        // A short consume means the message ended inside this read.
        assert(consumed == n or pipe.framer.is_complete());
        if (consumed < n) {
            if (pipe.to_client) {
                // The upstream sent bytes past the response end; its
                // connection is in an unknown state and must not be pooled.
                pipe.conn.response_pipe_overflow = true;
            } else {
                // Pipelined bytes landed here instead of head_buf; they
                // cannot be handed to the next request — reuse is off.
                pipe.conn.request_pipe_overflow = true;
            }
        }
        if (consumed == 0) return pipe.finish(); // everything read is past the end
        pipe.filled = consumed;
        pipe.sent = 0;
        assert(pipe.sent < pipe.filled);
        pipe.arm_send();
    }

    fn on_eof(pipe: *Pipe) void {
        // EOF is a legal terminator only for a close-delimited response;
        // anything else is a truncated message or the client quitting.
        if (pipe.to_client and pipe.framer.framing == .until_close) {
            return pipe.conn.response_complete();
        }
        pipe.conn.teardown();
    }

    fn arm_send(pipe: *Pipe) void {
        assert(pipe.sent < pipe.filled);
        if (pipe.to_client and pipe.conn.tls != null) {
            // The response direction writes to a TLS client. The completion
            // reports plaintext consumed, so byte accounting stays in
            // application bytes on both paths.
            const leg = pipe.conn.tls.?;
            return pipe.conn.tls_send_start(leg, pipe.buf[pipe.sent..pipe.filled], on_tls_send);
        }
        if (!pipe.to_client and pipe.conn.upstream_tls != null) {
            // The request-body direction writes to a TLS origin.
            const leg = pipe.conn.upstream_tls.?;
            return pipe.conn.tls_send_start(
                leg,
                pipe.buf[pipe.sent..pipe.filled],
                on_upstream_tls_send,
            );
        }
        pipe.conn.retain();
        pipe.conn.io.send(
            *Pipe,
            pipe,
            on_send,
            &pipe.send_completion,
            pipe.dst_fd,
            pipe.buf[pipe.sent..pipe.filled],
        );
    }

    fn on_send(pipe: *Pipe, _: *Completion, result: io_mod.SendError!usize) void {
        defer pipe.conn.release_ref();
        if (pipe.conn.closing) return;
        pipe.handle_send(result);
    }

    fn on_tls_send(conn: *ProxyConn, result: io_mod.SendError!usize) void {
        conn.response_pipe.handle_send(result);
    }

    fn on_upstream_tls_send(conn: *ProxyConn, result: io_mod.SendError!usize) void {
        conn.request_pipe.handle_send(result);
    }

    fn handle_send(pipe: *Pipe, result: io_mod.SendError!usize) void {
        assert(!pipe.conn.closing); // both callers bail first
        const m = result catch return pipe.conn.teardown();
        if (pipe.to_client) {
            pipe.conn.metrics.bytes_to_client.add(m);
            pipe.conn.bytes_out += m;
        } else {
            pipe.conn.metrics.bytes_to_upstream.add(m);
        }
        pipe.sent += m;
        assert(pipe.sent <= pipe.filled); // never send past what we read
        if (pipe.sent < pipe.filled) return pipe.arm_send(); // finish a partial write
        if (pipe.framer.is_complete()) return pipe.finish();
        pipe.arm_recv();
    }

    fn finish(pipe: *Pipe) void {
        assert(pipe.framer.is_complete());
        if (pipe.to_client) return pipe.conn.response_complete();
        // Request body fully forwarded: this direction goes idle; the
        // connection lives on until the response completes.
        pipe.conn.request_forwarded = true;
    }
};

pub const ProxyConn = struct {
    io: *IO,
    pool: *Pool,
    router: *const Router,
    resilience: *Resilience,
    upstream_pool: *UpstreamPool,
    /// This worker's metrics shard (single writer; totals are summed on the
    /// read side by `Metrics.total`).
    metrics: *Counters,
    access: *AccessLog,
    /// The worker's PRNG (P2C draws, retry jitter). Never re-seeded here.
    random: std.Random,

    downstream_fd: posix.socket_t,
    upstream_fd: posix.socket_t,
    closing: bool,
    /// In-flight io_uring operations for this connection.
    refs: u32,
    request_timeout_ns: u63,
    idle_timeout_ns: u63,
    /// Absolute (CLOCK_MONOTONIC) deadline for the current phase. Phase
    /// transitions just move it; the single ticking timer enforces it.
    deadline_ns: u64,
    timeout_armed: bool,
    /// Absolute per-attempt deadline (connect through first response byte);
    /// 0 = inactive. Armed only for replayable requests (`arm_try_deadline`),
    /// enforced by the same ticking timer, subordinate to `deadline_ns`.
    try_deadline_ns: u64,
    /// The per-try deadline passed: the attempt's in-flight upstream op has
    /// been killed and must drain through `attempt_drained`.
    attempt_dead: bool,
    /// A cancel targeting `connect_completion` is in flight; never submit a
    /// second one — a stale cancel could kill a later attempt's connect on
    /// the reused completion.
    try_connect_cancel_pending: bool,

    head_buf: [constants.read_buf_bytes]u8,
    head_filled: usize,
    /// Request headers during routing; reused for the response head parse
    /// (the request's entries are dead once the prime segments are built).
    headers_storage: [constants.headers_max]h1.Header,

    /// Method of the current request — decides the response framing (HEAD).
    request_method: h1.Method,
    /// Frames the request body; seeded here, then handed to the request_pipe pipe.
    request_framer: h1.BodyFramer,
    /// Offset in `head_buf` where the current request (head + framed body
    /// prefix) ends; bytes beyond it belong to the next, pipelined request.
    request_end: usize,
    /// The whole request has been forwarded upstream (nothing in flight).
    request_forwarded: bool,
    /// The client asked for keep-alive (HTTP/1.1 without `Connection: close`).
    downstream_keep_alive: bool,
    /// Set at response-head time: keep-alive client and a framed response.
    response_reusable: bool,
    /// Pipelined bytes leaked into the request_pipe relay buffer — reuse is off (they
    /// cannot be recovered into `head_buf` without another copy path).
    request_pipe_overflow: bool,
    /// The upstream sent bytes past the response end — its connection is in
    /// an unknown protocol state and must not be pooled.
    response_pipe_overflow: bool,
    /// Where the current upstream connection goes (pool key; retry target).
    endpoint_address: Ip4Address,
    /// Resilience accounting keys for the current request (valid while the
    /// matching flag below is set).
    cluster_index: u32,
    endpoint_index: u32,
    /// The routed cluster's resilience policy (into the immutable Config;
    /// `&policy_default` between requests).
    policy: *const config.ResiliencePolicy,
    /// The routed cluster (into the immutable Config; a retry re-picks its
    /// endpoint from here). Null between requests.
    cluster: ?*const config.Cluster,
    /// Consistent-hash affinity for the current request (maglev clusters,
    /// docs/DESIGN.md §7 Phase 4): the key's hash, kept so a retry can walk
    /// the same table deterministically instead of re-randomizing.
    affinity_hash: u64,
    /// The pick above actually used the hash (the cluster is maglev AND the
    /// key existed — a missing hash header falls back to P2C).
    affinity_hashed: bool,
    /// Configured retries spent on this request (tier 2; the free stale-pool
    /// replay does not count). Bounded by `policy.retry_max`.
    attempts_used: u8,
    /// A retry is owed once its gates clear (`maybe_start_retry`).
    retry_scheduled: bool,
    /// The backoff timer is in flight on `retry_timeout_completion`.
    retry_pending: bool,
    /// This request holds a charge in the cluster's `retries_active`.
    retry_charged: bool,
    /// The request was counted in `resilience.requests_active` (admission
    /// happened); cleared by exactly one `settle_accounting`.
    request_admitted: bool,
    /// An attempt is counted in the endpoint's `in_flight`; cleared by
    /// exactly one `close_attempt`.
    attempt_open: bool,
    /// A dial is counted in `pending_dials`; always settled by `on_connect`
    /// (io_uring delivers a completion even for cancelled ops).
    dial_pending: bool,
    /// The upstream fd is counted in `connections_active`; cleared wherever
    /// `upstream_fd` drops to -1.
    upstream_accounted: bool,
    /// The upstream connection came from the pool (a stale close is possible).
    upstream_pooled: bool,
    /// Set at response-head time: framed HTTP/1.1 response without
    /// `Connection: close` — the upstream connection can be pooled.
    upstream_reusable: bool,
    /// The one-shot stale-connection retry has been spent.
    upstream_retry_used: bool,
    /// The whole request fit in the prime segments, so it can be replayed
    /// verbatim on a fresh connection if a pooled one turns out stale.
    request_replayable: bool,
    /// At least one response byte arrived — a failure is no longer a stale
    /// pooled connection, and the request must not be replayed.
    response_bytes_received: bool,
    /// The previous request's upstream close has not completed yet.
    upstream_close_pending: bool,
    /// A request is in flight (or aborted mid-flight) — controls whether the
    /// final teardown writes an access-log record.
    request_active: bool,
    /// The worker is draining (docs/DESIGN.md §7 Phase 4): this connection
    /// must not be reused after the in-flight response — the response head
    /// gets `Connection: close` injected if it has not been relayed yet, and
    /// `response_complete` closes instead of `finish_request`. Set by the
    /// drain sweep only; connection-scoped (no reset between requests —
    /// draining never un-happens).
    drain_close: bool,

    // The upstream-bound head as slices of `head_buf` (plus the static
    // `Connection: close` injection), laid out by `build_prime_segments`.
    prime_segments: [prime_segments_max][]const u8,
    prime_segment_count: usize,
    prime_segment_index: usize,
    /// Bytes sent of the current segment.
    prime_sent: usize,

    // Fixed error response in flight (`fail`); empty when unused.
    fail_response: []const u8,
    fail_sent: usize,

    // Access-log accounting (slices point into head_buf).
    log_method: []const u8,
    log_target: []const u8,
    outcome: access_log.Outcome,
    bytes_out: u64,

    recv_head_completion: Completion,
    connect_completion: Completion,
    aux_completion: Completion, // prime send / error-response send
    close_downstream_completion: Completion,
    /// Per-request upstream closes (finish_request / stale retry), guarded by
    /// `upstream_close_pending`. Teardown must NOT reuse this one: a previous
    /// request's close may still be in flight on it, and re-submitting a
    /// Completion that is in flight corrupts the ring (double callback,
    /// double release_ref). Found by the simulator, seed 1693.
    close_upstream_completion: Completion,
    /// Teardown's own upstream close (teardown runs at most once).
    teardown_close_upstream_completion: Completion,
    timeout_completion: Completion,
    timeout_cancel_completion: Completion,
    connect_cancel_completion: Completion,
    /// The per-try abort's connect cancel. Teardown owns
    /// `connect_cancel_completion` unconditionally; sharing would risk a
    /// double submit when a teardown lands during an aborting attempt.
    try_connect_cancel_completion: Completion,
    /// Retry backoff timer (`retry_pending` guards it) and teardown's cancel
    /// of it — its own pair: the ticking deadline timer must keep running
    /// through a backoff wait.
    retry_timeout_completion: Completion,
    retry_cancel_completion: Completion,

    request_pipe: Pipe,
    response_pipe: Pipe,

    /// Downstream TLS state; null on a plaintext listener. Connection-scoped:
    /// checked out of `tls_legs` at accept (or the connection is shed),
    /// checked back in with the slot — or earlier, at the kernel switchover.
    tls: ?*Tls,
    /// Upstream TLS state (re-encryption); null between attempts and on
    /// plaintext clusters. Attempt-scoped: checked out after connect,
    /// checked in at dispose_upstream (or with the slot on teardown).
    upstream_tls: ?*Tls,
    /// The worker's leg pool; null iff the config has no TLS anywhere (then
    /// neither leg is ever acquired). From the server, set at start.
    tls_legs: ?*TlsLegPool,
    /// Per-cluster upstream client contexts (by cluster.index); empty when
    /// no cluster re-encrypts. From the server, set at start.
    upstream_tls_contexts: []const ?*const terminator.Context,
    /// The worker's HTTP/2 pools, non-null iff `tls.http2` (docs/DESIGN.md
    /// §7 Phase 5). When a downstream handshake negotiates `h2` in ALPN, the
    /// connection is handed to a fresh `H2Conn` from this pool; the leg pool
    /// is passed on for its per-stream upstream transactions. From the
    /// server, set at start.
    h2_conn_pool: ?*H2ConnPool,
    h2_leg_pool: ?*H2LegPool,
    /// Buffered plaintext must be delivered from the event loop, never
    /// synchronously from a logical-op start (TigerStyle: no recursion) —
    /// hence a zero-delay yield timer per side. CONNECTION-scoped, not
    /// leg-scoped: an upstream yield can outlive its attempt's leg, and a
    /// leg-embedded completion re-armed by the next leg at the same address
    /// while still in the ring corrupts it (found by CI on the pooled-TLS
    /// test). A pending yield coalesces: it pumps whatever leg is current
    /// when it fires.
    downstream_yield_pending: bool,
    upstream_yield_pending: bool,
    downstream_yield_completion: Completion,
    upstream_yield_completion: Completion,
    /// The record layer lives in the kernel (docs/DESIGN.md §6): `tls` is
    /// null again and every downstream op is a plain ring op on the fd; only
    /// the polite close differs (an alert cmsg instead of a channel).
    ktls_active: bool,
    /// The close_notify alert send (a `send_message` cmsg) is in flight.
    ktls_notify_pending: bool,
    /// The alert's msghdr machinery — must outlive the send_message op.
    ktls_close_control: kernel_tls.RecordTypeControl,
    ktls_close_segments: [1]posix.iovec_const,
    ktls_close_message: linux.msghdr_const,

    free_next: ?*ProxyConn,
    /// Maintained by `Pool`: true between acquire and release. Makes every
    /// slot in `pool.items` classifiable for the drain sweep and diagnostics.
    in_use: bool,

    /// The downstream TLS layer (docs/DESIGN.md §6). The `Channel` transforms
    /// bytes; this struct owns the wire staging and the *logical* plaintext
    /// operations the HTTP state machine thinks it is running. Exactly one
    /// logical recv and one logical send can be active at a time (the HTTP
    /// machine serializes each direction); wire ops carry the io_uring refs.
    /// Upstream traffic never passes through here.
    const Tls = struct {
        channel: terminator.Channel,
        /// Which fd this leg wraps and how its failures route: the
        /// downstream leg is the connection (errors tear down), the
        /// upstream leg is the current attempt (errors feed the retry
        /// machinery, like any upstream socket error).
        side: Side,
        handshake_complete: bool,
        /// Ciphertext between io.recv and the BIO feed; a partial feed
        /// (pair full) compacts the remainder to the front.
        wire_recv_buf: [constants.tls_bio_pair_bytes]u8,
        wire_recv_staged: usize,
        wire_recv_in_flight: bool,
        /// Ciphertext between the BIO drain and io.send.
        wire_send_buf: [constants.tls_bio_pair_bytes]u8,
        wire_send_filled: usize,
        wire_send_sent: usize,
        wire_send_in_flight: bool,
        /// Active logical plaintext recv: target borrowed from the caller
        /// until delivery through `recv_callback`.
        recv_target: ?[]u8,
        recv_callback: *const fn (*ProxyConn, io_mod.RecvError!usize) void,
        /// Active logical plaintext send (`send_active` guards it).
        send_source: []const u8,
        send_consumed: usize,
        send_active: bool,
        send_callback: *const fn (*ProxyConn, io_mod.SendError!usize) void,
        /// A close_notify is queued and flushing; when the wire drains,
        /// teardown runs. Normal logical progress stops in this mode. The
        /// flush is bounded by the connection deadline: the ticking timer is
        /// still armed and its expiry tears down regardless.
        notify_then_teardown: bool,
        /// The handshake completed and the kernel switchover decision is
        /// owed — taken once the wire goes idle (tls_try_kernel_switch).
        /// HTTP does not start until the decision lands.
        kernel_switch_pending: bool,
        /// Copied from the Context at accept (the config escape hatch).
        kernel_offload_enabled: bool,
        /// Traffic secrets the keylog callback fills during the handshake;
        /// OpenSSL holds a raw pointer to this field (stable: the conn is
        /// pooled), armed at channel init.
        secrets: terminator.TrafficSecrets,
        wire_recv_completion: Completion,
        wire_send_completion: Completion,

        // Pool bookkeeping (`Pool(Tls)`): legs live in a per-worker pool,
        // not inline in ProxyConn — inline they cost 2 x 36KiB of dirtied
        // pages per connection even on plaintext workloads.
        free_next: ?*Tls,
        in_use: bool,

        const Side = enum { downstream, upstream };

        /// Field-by-field reset of a pooled leg. Deliberately NOT a struct
        /// assignment: the wire buffers stay untouched (a whole-struct write
        /// would dirty their 36KiB even when TLS never stages a byte) and
        /// the pool's own bookkeeping fields must survive.
        fn reset(leg: *Tls, channel: terminator.Channel, side: Side, kernel_offload: bool) void {
            assert(leg.in_use); // freshly acquired from the pool
            assert(leg.free_next == null);
            leg.channel = channel;
            leg.side = side;
            leg.handshake_complete = false;
            leg.wire_recv_staged = 0;
            leg.wire_recv_in_flight = false;
            leg.wire_send_filled = 0;
            leg.wire_send_sent = 0;
            leg.wire_send_in_flight = false;
            leg.recv_target = null;
            leg.recv_callback = undefined;
            leg.send_source = "";
            leg.send_consumed = 0;
            leg.send_active = false;
            leg.send_callback = undefined;
            leg.notify_then_teardown = false;
            leg.kernel_switch_pending = false;
            leg.kernel_offload_enabled = kernel_offload;
            leg.secrets = .{};
            leg.wire_recv_completion = undefined;
            leg.wire_send_completion = undefined;
        }
    };

    pub fn start(
        conn: *ProxyConn,
        io: *IO,
        pool: *Pool,
        router: *const Router,
        resilience: *Resilience,
        upstream_pool: *UpstreamPool,
        metrics: *Counters,
        access: *AccessLog,
        random: std.Random,
        downstream_fd: posix.socket_t,
        request_timeout_ns: u63,
        idle_timeout_ns: u63,
        tls_context: ?*const terminator.Context,
        upstream_tls_contexts: []const ?*const terminator.Context,
        tls_legs: ?*TlsLegPool,
        h2_conn_pool: ?*H2ConnPool,
        h2_leg_pool: ?*H2LegPool,
    ) void {
        assert(downstream_fd >= 0);
        assert((h2_conn_pool == null) == (h2_leg_pool == null)); // wired together
        assert(h2_conn_pool == null or tls_context != null); // h2 rides TLS ALPN
        // TLS first, before any state or metrics: exhaustion of the TLS heap
        // sheds the whole connection here (reject, never a partial start).
        conn.tls = null;
        conn.upstream_tls = null;
        conn.tls_legs = tls_legs;
        conn.upstream_tls_contexts = upstream_tls_contexts;
        conn.h2_conn_pool = h2_conn_pool;
        conn.h2_leg_pool = h2_leg_pool;
        conn.downstream_yield_pending = false;
        conn.upstream_yield_pending = false;
        conn.ktls_active = false;
        conn.ktls_notify_pending = false;
        if (tls_context) |context| {
            assert(tls_legs != null); // wired together with the context
            // Sized one leg per connection, so a fresh conn always finds one;
            // shed like heap exhaustion if the invariant ever breaks.
            const leg = tls_legs.?.acquire() orelse {
                metrics.tls_handshake_failures.add(1);
                metrics.rejected.add(1);
                io.close_now(downstream_fd);
                pool.release(conn);
                return;
            };
            const channel = terminator.Channel.init(context) catch {
                tls_legs.?.release(leg);
                metrics.tls_handshake_failures.add(1);
                metrics.rejected.add(1);
                io.close_now(downstream_fd);
                pool.release(conn);
                return;
            };
            leg.reset(channel, .downstream, context.kernel_offload);
            // The keylog callback fills these secrets during the handshake;
            // armed here, at the leg's checked-out (pool-stable) address.
            leg.channel.capture_secrets(&leg.secrets);
            conn.tls = leg;
        }
        conn.io = io;
        conn.pool = pool;
        conn.router = router;
        conn.resilience = resilience;
        conn.upstream_pool = upstream_pool;
        conn.random = random;
        conn.metrics = metrics;
        conn.access = access;
        conn.downstream_fd = downstream_fd;
        conn.upstream_fd = -1;
        conn.closing = false;
        conn.drain_close = false; // accepts stop before the drain sweep runs
        conn.refs = 0;
        conn.request_timeout_ns = request_timeout_ns;
        conn.idle_timeout_ns = idle_timeout_ns;
        conn.set_deadline(request_timeout_ns); // a fresh connection owes a request
        conn.timeout_armed = false;
        conn.head_filled = 0;
        conn.upstream_close_pending = false;
        conn.try_connect_cancel_pending = false;
        conn.reset_request_state();
        conn.request_active = true; // a fresh connection owes us a request
        metrics.accepted.add(1);
        metrics.active.add(1);
        conn.arm_timeout();
        // A TLS connection handshakes before HTTP: the client speaks first
        // (ClientHello), so this arms the first wire recv. Handshake and
        // request share the request deadline already running.
        if (conn.tls != null) {
            conn.tls_handshake_progress(conn.tls.?);
        } else {
            conn.arm_recv_head();
        }
        assert(conn.timeout_armed); // both the deadline and the first recv are in flight
        assert(conn.refs >= 1);
    }

    /// Move the current phase's deadline; the ticking timer picks it up.
    fn set_deadline(conn: *ProxyConn, timeout_ns: u63) void {
        assert(timeout_ns > 0);
        conn.deadline_ns = conn.io.now_ns() + timeout_ns;
    }

    fn arm_timeout(conn: *ProxyConn) void {
        assert(!conn.timeout_armed);
        const now = conn.io.now_ns();
        // Sleep to the nearest deadline (overall or per-try), but at most one
        // tick: if a deadline moves closer meanwhile (request phase -> idle
        // phase, a per-try arming), enforcement is late by at most the tick.
        var target_ns = conn.deadline_ns;
        if (conn.try_deadline_ns != 0 and conn.try_deadline_ns < target_ns) {
            target_ns = conn.try_deadline_ns;
        }
        const remaining = if (target_ns > now) target_ns - now else 1;
        const sleep_ns: u63 = @intCast(@min(remaining, constants.timeout_tick_ns));
        assert(sleep_ns > 0);
        conn.retain();
        conn.timeout_armed = true;
        conn.io.timeout(*ProxyConn, conn, on_timeout, &conn.timeout_completion, sleep_ns);
    }

    fn on_timeout(conn: *ProxyConn, _: *Completion, _: io_mod.TimeoutError!void) void {
        defer conn.release_ref();
        conn.timeout_armed = false;
        if (conn.closing) return; // fired late / we cancelled it
        const now = conn.io.now_ns();
        if (now >= conn.deadline_ns) { // the overall deadline is supreme
            // The drain sweep clamps deadlines: at this point the connection
            // outlived the drain limit and is being forced closed.
            if (conn.drain_close) conn.metrics.drain_forced_closes.add(1);
            return conn.teardown();
        }
        if (conn.try_deadline_ns != 0 and now >= conn.try_deadline_ns) conn.abort_attempt();
        conn.arm_timeout(); // still time left (or a deadline moved); keep watching
    }

    fn retain(conn: *ProxyConn) void {
        conn.refs += 1;
    }

    /// Clear everything scoped to a single request. Connection-scoped state
    /// (fds, refs, the deadline, `head_filled`, `upstream_close_pending`) stays.
    fn reset_request_state(conn: *ProxyConn) void {
        conn.request_method = .other;
        conn.request_framer = h1.BodyFramer.init(.none);
        conn.request_end = 0;
        conn.request_forwarded = false;
        conn.downstream_keep_alive = false;
        conn.response_reusable = false;
        conn.request_pipe_overflow = false;
        conn.response_pipe_overflow = false;
        conn.endpoint_address = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 };
        conn.cluster_index = 0;
        conn.endpoint_index = 0;
        conn.policy = &policy_default;
        conn.cluster = null;
        conn.affinity_hash = 0;
        conn.affinity_hashed = false;
        conn.attempts_used = 0;
        conn.retry_scheduled = false;
        conn.retry_pending = false;
        conn.retry_charged = false;
        conn.request_admitted = false;
        conn.attempt_open = false;
        conn.dial_pending = false;
        conn.upstream_accounted = false;
        conn.upstream_pooled = false;
        conn.upstream_reusable = false;
        conn.upstream_retry_used = false;
        conn.try_deadline_ns = 0;
        conn.attempt_dead = false;
        conn.request_replayable = false;
        conn.response_bytes_received = false;
        conn.request_active = false;
        conn.prime_segment_count = 0;
        conn.prime_segment_index = 0;
        conn.prime_sent = 0;
        conn.fail_response = "";
        conn.fail_sent = 0;
        conn.log_method = "";
        conn.log_target = "";
        conn.outcome = .aborted;
        conn.bytes_out = 0;
    }

    // ---- resilience accounting --------------------------------------------

    /// An attempt on `endpoint_index` begins (first try or a replay).
    fn open_attempt(conn: *ProxyConn, endpoint_index: u32) void {
        assert(!conn.attempt_open); // the previous attempt was settled
        assert(conn.request_admitted); // attempts only exist under a request
        conn.endpoint_index = endpoint_index;
        conn.attempt_open = true;
        conn.resilience.attempt_start(conn.cluster_index, endpoint_index);
    }

    /// The open attempt ends with `outcome`; exactly once per attempt. Also
    /// disarms the per-try deadline — a settled attempt must never be
    /// aborted by a stale timer tick.
    fn close_attempt(conn: *ProxyConn, outcome: resilience_mod.AttemptOutcome) void {
        assert(conn.attempt_open);
        conn.attempt_open = false;
        conn.try_deadline_ns = 0;
        const cluster = conn.cluster.?; // an open attempt implies a routed request
        const ejected = conn.resilience.attempt_finish(
            conn.cluster_index,
            conn.endpoint_index,
            outcome,
            conn.policy,
            @intCast(cluster.endpoints.len),
            conn.io.now_ns(),
        );
        if (ejected) conn.metrics.outlier_ejections.add(1);
        // A settling retry attempt returns its budget charge.
        conn.release_retry_charge();
    }

    /// Final accounting for the current request. Idempotent (flag-guarded):
    /// `fail` settles and later triggers `teardown`, which settles again as
    /// a no-op; a teardown with no request in flight is also a no-op.
    fn settle_accounting(conn: *ProxyConn, outcome: resilience_mod.AttemptOutcome) void {
        if (conn.attempt_open) conn.close_attempt(outcome);
        // Covers a teardown mid-backoff, when the charge has no open attempt.
        conn.release_retry_charge();
        if (conn.request_admitted) {
            conn.request_admitted = false;
            conn.resilience.request_finish(conn.cluster_index);
        }
        assert(!conn.attempt_open); // negative space: nothing left open
        assert(!conn.request_admitted);
    }

    /// Count a scheduled retry against the cluster's retry budget; released
    /// when the retried attempt settles (or the connection does).
    fn charge_retry(conn: *ProxyConn) void {
        assert(!conn.retry_charged); // the previous charge was released
        conn.retry_charged = true;
        conn.resilience.retry_start(conn.cluster_index);
    }

    fn release_retry_charge(conn: *ProxyConn) void {
        if (!conn.retry_charged) return;
        conn.retry_charged = false;
        conn.resilience.retry_finish(conn.cluster_index);
    }

    /// The upstream fd came into this connection's hands (fresh dial or pool
    /// checkout): count it toward the cluster's connections.
    fn account_upstream_open(conn: *ProxyConn) void {
        assert(conn.upstream_fd >= 0);
        assert(!conn.upstream_accounted); // the previous fd was dropped
        conn.upstream_accounted = true;
        conn.resilience.connection_open(conn.cluster_index);
    }

    /// The upstream fd is leaving (pooled, closed, or torn down): undo
    /// `account_upstream_open` exactly once. Called wherever `upstream_fd`
    /// drops to -1; a drop with nothing accounted is a no-op (teardown of a
    /// connection that never dialed).
    fn account_upstream_drop(conn: *ProxyConn) void {
        if (!conn.upstream_accounted) return;
        conn.upstream_accounted = false;
        conn.resilience.connection_close(conn.cluster_index);
    }

    /// Hand a leg back to the worker's pool. The channel is already gone —
    /// deinit'ed by the caller, or parked (upstream pool / kernel switch).
    fn tls_leg_release(conn: *ProxyConn, leg: *Tls) void {
        assert(!leg.wire_recv_in_flight); // release points are wire-quiescent
        assert(!leg.wire_send_in_flight);
        assert(conn.tls_legs != null); // a leg exists, so the pool does
        conn.tls_legs.?.release(leg);
    }

    fn release_ref(conn: *ProxyConn) void {
        assert(conn.refs > 0);
        conn.refs -= 1;
        if (conn.closing and conn.refs == 0) {
            // Quiescent: no op can touch the channels anymore. Their SSL +
            // BIO pairs return to the TLS heap with the slot, the legs to
            // the worker's pool.
            if (conn.tls) |tls| {
                tls.channel.deinit();
                conn.tls_leg_release(tls);
                conn.tls = null;
            }
            if (conn.upstream_tls) |leg| {
                leg.channel.deinit();
                conn.tls_leg_release(leg);
                conn.upstream_tls = null;
            }
            conn.metrics.active.sub(1);
            // A keep-alive connection that closed between requests has
            // nothing left to log — its requests were logged as they
            // finished.
            if (conn.request_active) {
                conn.access.record(.{
                    .method = conn.log_method,
                    .target = conn.log_target,
                    .outcome = conn.outcome,
                    .bytes_to_client = conn.bytes_out,
                });
            }
            conn.pool.release(conn); // fds already closed
        }
    }

    fn teardown(conn: *ProxyConn) void {
        if (conn.closing) return; // idempotent: a second call returns here
        conn.closing = true;
        // Whatever was in flight ends here. Aborted, not failed: a client
        // that vanished mid-exchange says nothing about the endpoint.
        conn.settle_accounting(.aborted);
        // Cancel the ops that shutdown() cannot reach: the deadline timer (no fd)
        // and any in-flight connect (shutdown of a connecting socket is a no-op).
        // A cancel that matches nothing returns ENOENT — harmless.
        if (conn.timeout_armed) {
            conn.timeout_armed = false;
            conn.cancel_op(&conn.timeout_cancel_completion, &conn.timeout_completion);
        }
        // A backoff wait must not pin the slot for its full delay.
        if (conn.retry_pending) {
            conn.retry_pending = false;
            conn.cancel_op(&conn.retry_cancel_completion, &conn.retry_timeout_completion);
        }
        conn.cancel_op(&conn.connect_cancel_completion, &conn.connect_completion);
        // Closing an fd does NOT cancel a recv/send already pending on it in
        // io_uring. shutdown() forces those to complete so the refcount drains;
        // then we close the fd.
        if (conn.downstream_fd >= 0) {
            conn.io.shutdown_socket(conn.downstream_fd);
            conn.retain();
            conn.io.close(
                *ProxyConn,
                conn,
                on_closed,
                &conn.close_downstream_completion,
                conn.downstream_fd,
            );
            conn.downstream_fd = -1;
        }
        if (conn.upstream_fd >= 0) {
            conn.io.shutdown_socket(conn.upstream_fd);
            conn.retain();
            conn.io.close(
                *ProxyConn,
                conn,
                on_closed,
                &conn.teardown_close_upstream_completion,
                conn.upstream_fd,
            );
            conn.upstream_fd = -1;
            conn.account_upstream_drop();
        }
    }

    fn cancel_op(conn: *ProxyConn, cancel_completion: *Completion, target: *const Completion) void {
        conn.retain();
        conn.io.cancel(*ProxyConn, conn, on_cancel, cancel_completion, target);
    }

    fn on_cancel(conn: *ProxyConn, _: *Completion, _: io_mod.CancelError!void) void {
        conn.release_ref();
    }

    fn on_closed(conn: *ProxyConn, _: *Completion, _: io_mod.CloseError!void) void {
        conn.release_ref();
    }

    // ---- TLS legs -----------------------------------------------------------
    //
    // Sans-io Channel + these drivers = the BIO-pair relay, one `Tls` leg per
    // encrypted hop: downstream (termination) and upstream (re-encryption).
    // The HTTP machine calls tls_recv_start/tls_send_start exactly where it
    // would call io.recv/io.send on that leg's fd; deliveries arrive through
    // the stored callback from a wire completion (or the yield timer), so the
    // control flow shape is identical to the plaintext path. Failures route
    // by side: the downstream leg is the connection (teardown), the upstream
    // leg is the current attempt (the retry machinery, via the active logical
    // op's callback — the same path a plain upstream socket error takes).
    // Server-initiated downstream closes flush a close_notify first
    // (`close_downstream`); upstream closes stay abrupt in U2 (origins
    // tolerate a client hangup after a delivered response).

    fn tls_leg_fd(conn: *const ProxyConn, leg: *const Tls) posix.socket_t {
        return switch (leg.side) {
            .downstream => conn.downstream_fd,
            .upstream => conn.upstream_fd,
        };
    }

    /// The cluster's re-encryption context for the routed request, if any.
    fn upstream_tls_context(conn: *const ProxyConn) ?*const terminator.Context {
        if (conn.upstream_tls_contexts.len == 0) return null;
        assert(conn.cluster_index < conn.upstream_tls_contexts.len);
        return conn.upstream_tls_contexts[conn.cluster_index];
    }

    /// Begin a logical plaintext recv into `target`. One at a time per leg;
    /// the callback receives plaintext byte count (0 = clean TLS EOF).
    fn tls_recv_start(
        conn: *ProxyConn,
        leg: *Tls,
        target: []u8,
        callback: *const fn (*ProxyConn, io_mod.RecvError!usize) void,
    ) void {
        assert(target.len > 0);
        assert(leg.handshake_complete); // HTTP only runs post-handshake
        assert(leg.recv_target == null); // one logical recv at a time
        leg.recv_target = target;
        leg.recv_callback = callback;
        // Plaintext may already be decrypted and waiting (pipelined requests
        // inside one record batch): deliver from the event loop, never from
        // this call stack.
        conn.tls_arm_yield(leg);
    }

    /// Begin a logical plaintext send of `source`. One at a time per leg;
    /// the callback fires when every byte is encrypted *and* on the wire.
    fn tls_send_start(
        conn: *ProxyConn,
        leg: *Tls,
        source: []const u8,
        callback: *const fn (*ProxyConn, io_mod.SendError!usize) void,
    ) void {
        assert(source.len > 0);
        assert(leg.handshake_complete);
        assert(!leg.send_active); // one logical send at a time
        leg.send_active = true;
        leg.send_source = source;
        leg.send_consumed = 0;
        leg.send_callback = callback;
        // Never delivers synchronously: fresh records always leave pending
        // ciphertext, so completion waits for at least one wire send.
        conn.tls_progress(leg);
    }

    /// The central pump: run after every wire completion. Order matters —
    /// draining sends first frees pair space that unblocks reads.
    fn tls_progress(conn: *ProxyConn, leg: *Tls) void {
        if (conn.closing) return;
        if (leg.notify_then_teardown) return conn.tls_notify_progress();
        if (!leg.handshake_complete) return conn.tls_handshake_progress(leg);
        if (leg.kernel_switch_pending) return conn.tls_try_kernel_switch();
        conn.tls_send_progress(leg);
        if (conn.closing) return; // a delivered send may have torn down
        conn.tls_recv_progress(leg);
    }

    /// A broken upstream leg (wire error, protocol failure, or EOF outside a
    /// logical recv): deliver through whichever logical op waits — its
    /// handler feeds the attempt machinery exactly like a plain upstream
    /// socket error — else settle the attempt directly.
    fn tls_upstream_broken(conn: *ProxyConn) void {
        assert(!conn.closing);
        const leg = conn.upstream_tls.?;
        assert(leg.side == .upstream);
        if (leg.recv_target != null) {
            leg.recv_target = null;
            return leg.recv_callback(conn, error.ConnectionResetByPeer);
        }
        if (leg.send_active) {
            leg.send_active = false;
            return leg.send_callback(conn, error.ConnectionResetByPeer);
        }
        // Handshake phase (or between logical ops): the attempt is broken.
        if (conn.attempt_dead) return conn.attempt_drained();
        if (conn.attempt_open) return conn.attempt_failed(.connect_error);
        conn.teardown();
    }

    /// The kernel switchover decision (docs/DESIGN.md §6), owed since the
    /// handshake completed and taken exactly once the wire is idle: every
    /// userspace-encrypted byte must be out (a pending wire send would be
    /// double-encrypted by kernel TX) and no wire recv may be in flight (it
    /// would complete with kernel-decrypted plaintext into the ciphertext
    /// staging). HTTP starts — arm_recv_head — only after the decision, on
    /// whichever relay won.
    fn tls_try_kernel_switch(conn: *ProxyConn) void {
        assert(!conn.closing);
        const tls = conn.tls.?;
        assert(tls.side == .downstream); // upstream never switches (tickets)
        assert(tls.kernel_switch_pending);
        assert(tls.handshake_complete);
        assert(tls.recv_target == null); // HTTP has not started
        assert(!tls.send_active);
        conn.tls_flush_wire_send(tls);
        if (tls.wire_send_in_flight or tls.wire_send_sent != tls.wire_send_filled) return;
        if (tls.channel.pending_ciphertext() != 0) return; // flush loops back here
        if (tls.wire_recv_in_flight) return; // its completion loops back here

        tls.kernel_switch_pending = false;
        // The wire is now idle (all our ciphertext out, nothing pending, no
        // wire recv in flight) — the exact quiescent point the h2 handoff
        // also needs. A client that negotiated `h2` in ALPN goes to the H2
        // data path from here; any staged bytes past the handshake (a
        // coalesced preface) ride along.
        if (conn.h2_selected(tls)) return conn.hand_off_to_h2(tls);
        const eligible = tls.kernel_offload_enabled and
            tls.wire_recv_staged == 0 and
            tls.channel.kernel_switch_eligible();
        if (eligible) switched: {
            const parameters = tls.channel.kernel_parameters(&tls.secrets) catch
                break :switched; // unsupported suite / secrets missing
            conn.io.enable_kernel_tls(
                conn.downstream_fd,
                parameters.transmit.bytes(),
                parameters.receive.bytes(),
            ) catch break :switched; // no module / kernel refused the cipher
            // The kernel owns the record layer: the channel (SSL + BIO
            // pair) returns to the TLS heap *now*, the leg to the worker's
            // pool, and every downstream op from here on is a plain ring op
            // on the fd.
            tls.channel.deinit();
            conn.tls_leg_release(tls);
            conn.tls = null;
            conn.ktls_active = true;
            conn.metrics.tls_ktls_active.add(1);
            conn.arm_recv_head();
            return;
        }
        conn.metrics.tls_ktls_fallbacks.add(1);
        conn.arm_recv_head(); // userspace relay, as before the switchover existed
    }

    /// The downstream handshake negotiated `h2` and this listener offers it.
    fn h2_selected(conn: *const ProxyConn, tls: *const Tls) bool {
        if (conn.h2_conn_pool == null) return false;
        assert(tls.side == .downstream);
        const alpn = tls.channel.alpn_selected() orelse return false;
        return std.mem.eql(u8, alpn, terminator.alpn_h2);
    }

    /// Move the terminated `h2` connection to a fresh `H2Conn`: the channel
    /// and the fd change hands, this `ProxyConn` relinquishes both and
    /// returns to its pool. Called only at the quiescent switchover point,
    /// so no wire op references the fd and no ciphertext is pending. Pool
    /// exhaustion sheds the connection (the client retries).
    fn hand_off_to_h2(conn: *ProxyConn, tls: *Tls) void {
        assert(!conn.closing);
        assert(tls.side == .downstream);
        assert(tls.handshake_complete);
        assert(!tls.wire_send_in_flight and tls.wire_send_sent == tls.wire_send_filled);
        assert(tls.channel.pending_ciphertext() == 0);
        assert(!tls.wire_recv_in_flight);
        assert(conn.downstream_fd >= 0);
        assert(!conn.request_forwarded); // no HTTP has flowed
        const h2 = conn.h2_conn_pool.?.acquire() orelse {
            // Every H2 slot taken: shed like any pool exhaustion. The client
            // retries; nothing was committed to an endpoint.
            conn.metrics.rejected.add(1);
            return conn.teardown();
        };
        // The bytes the handshaker read past the handshake — a coalesced
        // client preface — travel with the channel as `staged`.
        const staged = tls.wire_recv_buf[0..tls.wire_recv_staged];
        h2.start(
            conn.io,
            conn.h2_conn_pool.?,
            conn.h2_leg_pool.?,
            conn.router,
            conn.resilience,
            conn.upstream_pool,
            conn.metrics,
            conn.access,
            conn.random,
            conn.downstream_fd,
            conn.request_timeout_ns,
            conn.idle_timeout_ns,
            constants.drain_timeout_ns, // the same fixed bound the H1 side uses
            tls.channel, // ownership moves to the H2Conn
            staged,
        );
        conn.metrics.tls_h2_handoffs.add(1);
        // Relinquish: the channel and fd are the H2Conn's now. Null the leg's
        // channel view (release must not deinit it) and the fd (teardown must
        // not close it), then tear down to return this slot to the H1 pool.
        conn.tls = null;
        conn.tls_leg_release(tls);
        conn.downstream_fd = -1;
        conn.teardown();
    }

    /// Close the downstream connection the way the peer's TLS stack wants:
    /// queue a close_notify, flush it, then tear down. Three shapes: the
    /// userspace channel writes the alert into the pair; a kernel-switched
    /// connection sends it as a TLS_SET_RECORD_TYPE cmsg (the kernel
    /// encrypts it); plaintext (or an unfinished handshake) tears down
    /// directly.
    fn close_downstream(conn: *ProxyConn) void {
        if (conn.closing) return;
        if (conn.ktls_active) return conn.ktls_send_close_notify();
        const tls = if (conn.tls) |tls| tls else return conn.teardown();
        if (!tls.handshake_complete) return conn.teardown();
        if (tls.notify_then_teardown) return; // already flushing
        assert(!tls.send_active); // callers close only after a delivered send
        tls.notify_then_teardown = true;
        tls.channel.shutdown_notify();
        conn.tls_notify_progress();
    }

    /// Create the upstream leg and start its handshake (client speaks
    /// first, so this emits the ClientHello). Heap exhaustion sheds the
    /// request like a breaker rejection: the endpoint saw nothing.
    fn upstream_tls_begin(conn: *ProxyConn, context: *const terminator.Context) void {
        assert(!conn.closing);
        assert(conn.upstream_fd >= 0);
        assert(conn.upstream_tls == null); // one leg per attempt
        assert(conn.tls_legs != null); // an upstream context implies a leg pool
        // Sized one upstream leg per connection, so this cannot run dry;
        // shed like heap exhaustion if the invariant ever breaks.
        const leg = conn.tls_legs.?.acquire() orelse {
            conn.metrics.tls_handshake_failures.add(1);
            conn.close_attempt(.aborted);
            return conn.fail(response_503);
        };
        const channel = terminator.Channel.init(context) catch {
            conn.tls_legs.?.release(leg);
            conn.metrics.tls_handshake_failures.add(1);
            conn.close_attempt(.aborted);
            return conn.fail(response_503);
        };
        leg.reset(channel, .upstream, false);
        conn.upstream_tls = leg;
        conn.tls_handshake_progress(leg);
    }

    /// One alert record through the kernel: payload in the iovec, record
    /// type in the control message. Teardown follows the completion either
    /// way; a stalled peer is bounded by the still-armed deadline timer.
    fn ktls_send_close_notify(conn: *ProxyConn) void {
        assert(conn.ktls_active);
        assert(conn.tls == null); // the channel was freed at the switchover
        assert(!conn.closing);
        if (conn.ktls_notify_pending) return; // already in flight
        conn.ktls_notify_pending = true;
        conn.ktls_close_control = kernel_tls.RecordTypeControl.init(kernel_tls.record_type_alert);
        conn.ktls_close_segments = .{.{
            .base = &kernel_tls.alert_close_notify,
            .len = kernel_tls.alert_close_notify.len,
        }};
        conn.ktls_close_message = .{
            .name = null,
            .namelen = 0,
            .iov = &conn.ktls_close_segments,
            .iovlen = conn.ktls_close_segments.len,
            .control = &conn.ktls_close_control,
            .controllen = @sizeOf(kernel_tls.RecordTypeControl),
            .flags = 0,
        };
        conn.retain();
        conn.io.send_message(
            *ProxyConn,
            conn,
            on_ktls_close_notify_sent,
            &conn.aux_completion,
            conn.downstream_fd,
            &conn.ktls_close_message,
        );
    }

    fn on_ktls_close_notify_sent(
        conn: *ProxyConn,
        _: *Completion,
        result: io_mod.SendError!usize,
    ) void {
        defer conn.release_ref();
        conn.ktls_notify_pending = false;
        _ = result catch {}; // best effort: the close proceeds regardless
        if (conn.closing) return;
        conn.teardown();
    }

    /// The notify-mode pump: flush until the alert (and anything queued
    /// before it) is on the wire, then tear down. A wire error tears down
    /// via the send completion; a stalled peer is bounded by the deadline.
    fn tls_notify_progress(conn: *ProxyConn) void {
        assert(!conn.closing);
        const tls = conn.tls.?;
        assert(tls.notify_then_teardown);
        conn.tls_flush_wire_send(tls);
        const wire_idle = !tls.wire_send_in_flight and
            tls.wire_send_sent == tls.wire_send_filled;
        if (wire_idle and tls.channel.pending_ciphertext() == 0) conn.teardown();
    }

    fn tls_handshake_progress(conn: *ProxyConn, leg: *Tls) void {
        assert(!conn.closing);
        assert(!leg.handshake_complete);
        assert(leg.recv_target == null); // no HTTP before the handshake
        assert(!leg.send_active);
        switch (leg.channel.handshake_step()) {
            .done => {
                leg.handshake_complete = true;
                conn.metrics.tls_handshakes.add(1);
                switch (leg.side) {
                    // HTTP waits for the switchover decision; it arms
                    // arm_recv_head on whichever relay wins. A first
                    // request already decrypted in the channel defeats
                    // eligibility and rides the userspace path's yield.
                    .downstream => {
                        leg.kernel_switch_pending = true;
                        conn.tls_try_kernel_switch();
                    },
                    // The upstream leg is ready: forward the primed request.
                    .upstream => conn.arm_prime(),
                }
            },
            .want_io => {
                conn.tls_flush_wire_send(leg);
                conn.tls_arm_wire_recv(leg);
            },
            .failed => {
                conn.metrics.tls_handshake_failures.add(1);
                switch (leg.side) {
                    .downstream => conn.teardown(),
                    // A refused certificate or broken origin handshake is
                    // an attempt failure: retryable on another endpoint.
                    .upstream => conn.tls_upstream_broken(),
                }
            },
        }
    }

    fn tls_send_progress(conn: *ProxyConn, leg: *Tls) void {
        assert(!conn.closing);
        if (leg.send_active) {
            // Encrypt as much as the pair accepts; it drains below.
            var budget: u32 = 64; // bounded: each pass consumes or breaks
            while (leg.send_consumed < leg.send_source.len and budget > 0) : (budget -= 1) {
                switch (leg.channel.write_plaintext(leg.send_source[leg.send_consumed..])) {
                    .bytes => |consumed| leg.send_consumed += consumed,
                    .want_io => break, // pair full: drain, come back
                    .failed => return conn.tls_leg_failed(leg),
                }
            }
        }
        conn.tls_flush_wire_send(leg);
        const wire_idle = !leg.wire_send_in_flight and
            leg.wire_send_sent == leg.wire_send_filled;
        if (leg.send_active and leg.send_consumed == leg.send_source.len and
            leg.channel.pending_ciphertext() == 0 and wire_idle)
        {
            leg.send_active = false;
            leg.send_callback(conn, leg.send_consumed);
        }
    }

    fn tls_recv_progress(conn: *ProxyConn, leg: *Tls) void {
        assert(!conn.closing);
        const target = leg.recv_target orelse return;
        // Two passes: a read that wants more may be satisfied once staged
        // ciphertext (blocked on a full pair) is fed.
        for (0..2) |pass| {
            switch (leg.channel.read_plaintext(target)) {
                .bytes => |n| {
                    assert(n > 0);
                    leg.recv_target = null;
                    return leg.recv_callback(conn, n);
                },
                .closed => { // close_notify: clean EOF, like recv() == 0
                    leg.recv_target = null;
                    return leg.recv_callback(conn, 0);
                },
                .want_io => {
                    if (pass == 1) break;
                    conn.tls_feed_staged(leg);
                },
                .failed => return conn.tls_leg_failed(leg),
            }
        }
        conn.tls_flush_wire_send(leg); // a WANT_WRITE read (key update) needs it
        conn.tls_arm_wire_recv(leg);
    }

    fn tls_leg_failed(conn: *ProxyConn, leg: *Tls) void {
        switch (leg.side) {
            .downstream => conn.teardown(),
            .upstream => conn.tls_upstream_broken(),
        }
    }

    /// Feed staged wire ciphertext into the pair; a partial feed compacts
    /// the remainder forward (the pair drains as plaintext is read).
    fn tls_feed_staged(conn: *ProxyConn, leg: *Tls) void {
        _ = conn;
        if (leg.wire_recv_staged == 0) return;
        const fed = leg.channel.feed_ciphertext(leg.wire_recv_buf[0..leg.wire_recv_staged]);
        assert(fed <= leg.wire_recv_staged);
        if (fed == 0) return; // pair full: reads will drain it
        if (fed < leg.wire_recv_staged) {
            std.mem.copyForwards(
                u8,
                leg.wire_recv_buf[0 .. leg.wire_recv_staged - fed],
                leg.wire_recv_buf[fed..leg.wire_recv_staged],
            );
        }
        leg.wire_recv_staged -= fed;
    }

    fn tls_arm_wire_recv(conn: *ProxyConn, leg: *Tls) void {
        assert(!conn.closing);
        const fd = conn.tls_leg_fd(leg);
        assert(fd >= 0);
        if (leg.wire_recv_in_flight) return;
        // Staging full means the pair is also full; reads make the space —
        // wire recv re-arms on the next progress pass.
        if (leg.wire_recv_staged == leg.wire_recv_buf.len) return;
        leg.wire_recv_in_flight = true;
        conn.retain();
        switch (leg.side) {
            .downstream => conn.io.recv(
                *ProxyConn,
                conn,
                on_downstream_wire_recv,
                &leg.wire_recv_completion,
                fd,
                leg.wire_recv_buf[leg.wire_recv_staged..],
            ),
            .upstream => conn.io.recv(
                *ProxyConn,
                conn,
                on_upstream_wire_recv,
                &leg.wire_recv_completion,
                fd,
                leg.wire_recv_buf[leg.wire_recv_staged..],
            ),
        }
    }

    fn on_downstream_wire_recv(
        conn: *ProxyConn,
        _: *Completion,
        result: io_mod.RecvError!usize,
    ) void {
        defer conn.release_ref();
        conn.tls_wire_recv_done(conn.tls.?, result);
    }

    fn on_upstream_wire_recv(
        conn: *ProxyConn,
        _: *Completion,
        result: io_mod.RecvError!usize,
    ) void {
        defer conn.release_ref();
        // The leg may already be disposed when a teardown raced this
        // completion; nothing is left to progress then.
        if (conn.upstream_tls) |leg| conn.tls_wire_recv_done(leg, result);
    }

    fn tls_wire_recv_done(conn: *ProxyConn, leg: *Tls, result: io_mod.RecvError!usize) void {
        leg.wire_recv_in_flight = false;
        if (conn.closing) return;
        const n = result catch return conn.tls_leg_failed(leg);
        if (n == 0) return conn.tls_wire_eof(leg);
        leg.wire_recv_staged += n;
        assert(leg.wire_recv_staged <= leg.wire_recv_buf.len);
        conn.tls_feed_staged(leg);
        conn.tls_progress(leg);
    }

    /// TCP EOF without close_notify (a truncation, or an impolite peer). A
    /// waiting logical recv gets the EOF to handle like the plaintext path;
    /// otherwise the leg's side decides (connection over / attempt broken).
    fn tls_wire_eof(conn: *ProxyConn, leg: *Tls) void {
        assert(!conn.closing);
        if (leg.handshake_complete and leg.recv_target != null) {
            leg.recv_target = null;
            return leg.recv_callback(conn, 0);
        }
        switch (leg.side) {
            .downstream => conn.teardown(),
            .upstream => conn.tls_upstream_broken(),
        }
    }

    /// Keep exactly one wire send in flight while ciphertext is pending,
    /// refilling the staging buffer from the pair between sends.
    fn tls_flush_wire_send(conn: *ProxyConn, leg: *Tls) void {
        assert(!conn.closing);
        const fd = conn.tls_leg_fd(leg);
        assert(fd >= 0);
        if (leg.wire_send_in_flight) return;
        if (leg.wire_send_sent == leg.wire_send_filled) {
            leg.wire_send_filled = leg.channel.drain_ciphertext(&leg.wire_send_buf);
            leg.wire_send_sent = 0;
            if (leg.wire_send_filled == 0) return; // nothing pending
        }
        assert(leg.wire_send_sent < leg.wire_send_filled);
        leg.wire_send_in_flight = true;
        conn.retain();
        switch (leg.side) {
            .downstream => conn.io.send(
                *ProxyConn,
                conn,
                on_downstream_wire_send,
                &leg.wire_send_completion,
                fd,
                leg.wire_send_buf[leg.wire_send_sent..leg.wire_send_filled],
            ),
            .upstream => conn.io.send(
                *ProxyConn,
                conn,
                on_upstream_wire_send,
                &leg.wire_send_completion,
                fd,
                leg.wire_send_buf[leg.wire_send_sent..leg.wire_send_filled],
            ),
        }
    }

    fn on_downstream_wire_send(
        conn: *ProxyConn,
        _: *Completion,
        result: io_mod.SendError!usize,
    ) void {
        defer conn.release_ref();
        conn.tls_wire_send_done(conn.tls.?, result);
    }

    fn on_upstream_wire_send(
        conn: *ProxyConn,
        _: *Completion,
        result: io_mod.SendError!usize,
    ) void {
        defer conn.release_ref();
        if (conn.upstream_tls) |leg| conn.tls_wire_send_done(leg, result);
    }

    fn tls_wire_send_done(conn: *ProxyConn, leg: *Tls, result: io_mod.SendError!usize) void {
        leg.wire_send_in_flight = false;
        if (conn.closing) return;
        const m = result catch return conn.tls_leg_failed(leg);
        leg.wire_send_sent += m;
        assert(leg.wire_send_sent <= leg.wire_send_filled);
        conn.tls_progress(leg);
    }

    /// One yield per side may be in flight; further requests coalesce (the
    /// pending yield pumps whatever leg is current when it fires). The flag
    /// and completion are connection-scoped so a leg swap can never re-arm
    /// a completion that is still in the ring.
    fn tls_arm_yield(conn: *ProxyConn, leg: *Tls) void {
        assert(!conn.closing);
        switch (leg.side) {
            .downstream => {
                if (conn.downstream_yield_pending) return;
                conn.downstream_yield_pending = true;
                conn.retain();
                conn.io.timeout(
                    *ProxyConn,
                    conn,
                    on_downstream_yield,
                    &conn.downstream_yield_completion,
                    0,
                );
            },
            .upstream => {
                if (conn.upstream_yield_pending) return;
                conn.upstream_yield_pending = true;
                conn.retain();
                conn.io.timeout(
                    *ProxyConn,
                    conn,
                    on_upstream_yield,
                    &conn.upstream_yield_completion,
                    0,
                );
            },
        }
    }

    fn on_downstream_yield(conn: *ProxyConn, _: *Completion, _: io_mod.TimeoutError!void) void {
        defer conn.release_ref();
        conn.downstream_yield_pending = false;
        if (conn.closing) return;
        // The leg may be gone: the kernel switchover freed it and HTTP now
        // runs on plain ring ops — nothing left to pump.
        const leg = if (conn.tls) |leg| leg else return;
        conn.tls_progress(leg);
    }

    fn on_upstream_yield(conn: *ProxyConn, _: *Completion, _: io_mod.TimeoutError!void) void {
        defer conn.release_ref();
        conn.upstream_yield_pending = false;
        if (conn.closing) return;
        // The attempt's leg may be gone (disposed) or replaced (the next
        // request's resumed leg) by the time a stale yield fires; pumping
        // the current leg — or nothing — is safe: progress is idempotent.
        const leg = if (conn.upstream_tls) |leg| leg else return;
        conn.tls_progress(leg);
    }

    // ---- request head -----------------------------------------------------

    fn arm_recv_head(conn: *ProxyConn) void {
        assert(conn.downstream_fd >= 0);
        if (conn.head_filled == conn.head_buf.len) return conn.fail(response_431);
        assert(conn.head_filled < conn.head_buf.len); // there is room to read into
        if (conn.tls != null) {
            return conn.tls_recv_start(
                conn.tls.?,
                conn.head_buf[conn.head_filled..],
                handle_recv_head,
            );
        }
        conn.retain();
        conn.io.recv(
            *ProxyConn,
            conn,
            on_recv_head,
            &conn.recv_head_completion,
            conn.downstream_fd,
            conn.head_buf[conn.head_filled..],
        );
    }

    fn on_recv_head(conn: *ProxyConn, _: *Completion, result: io_mod.RecvError!usize) void {
        defer conn.release_ref();
        if (conn.closing) return;
        conn.handle_recv_head(result);
    }

    fn handle_recv_head(conn: *ProxyConn, result: io_mod.RecvError!usize) void {
        assert(!conn.closing); // both callers bail first
        const n = result catch return conn.teardown();
        if (n == 0) return conn.teardown(); // client closed before (or between) requests
        // Idle phase ends with the first byte: the request clock starts.
        if (!conn.request_active) conn.set_deadline(conn.request_timeout_ns);
        conn.request_active = true; // bytes arrived: a request is in flight
        assert(n <= conn.head_buf.len - conn.head_filled); // recv was bounded by the tail
        conn.head_filled += n;
        assert(conn.head_filled <= conn.head_buf.len);
        conn.process_head();
    }

    /// Parse whatever head bytes are buffered and dispatch: route a complete
    /// request, or read more. Entered from the recv path and — on a reused
    /// connection — directly from `finish_request` (pipelined bytes may
    /// already hold the whole next head).
    fn process_head(conn: *ProxyConn) void {
        assert(conn.downstream_fd >= 0);
        assert(conn.head_filled <= conn.head_buf.len);
        const parsed = h1.parse(
            conn.head_buf[0..conn.head_filled],
            &conn.headers_storage,
        ) catch |err| return conn.fail(response_for_parse_error(err));
        switch (parsed) {
            .incomplete => conn.arm_recv_head(),
            .complete => |request| {
                conn.log_method = request.method_text;
                conn.log_target = request.target;
                conn.metrics.requests.add(1);
                conn.route_and_connect(&request);
            },
        }
    }

    /// Pick this request's endpoint: the cluster's Maglev table when it has
    /// one and the request offers the key (the target, or the configured
    /// header), P2C least-request otherwise. The affinity hash is stored so
    /// retries walk the same table deterministically.
    fn pick_endpoint(
        conn: *ProxyConn,
        cluster: *const config.Cluster,
        request: *const h1.Request,
    ) ?u32 {
        assert(!conn.affinity_hashed); // fresh per request (reset_request_state)
        assert(conn.cluster_index == cluster.index); // set by the caller just before
        const state = conn.resilience.cluster_state(conn.cluster_index);
        const now_ns = conn.io.now_ns();
        if (cluster.maglev_table.len > 0) {
            const key: ?[]const u8 = switch (cluster.hash_on) {
                .target => request.target,
                .header => request.header(cluster.hash_header),
            };
            if (key != null and key.?.len > 0) {
                conn.affinity_hash = maglev.hash_key(key.?);
                conn.affinity_hashed = true;
                return balancer.pick_hashed(cluster, state, conn.affinity_hash, now_ns, null);
            }
            // Absent/empty key: nothing to be consistent about — P2C below.
        }
        return balancer.pick_least_request(cluster, state, conn.random, now_ns, null);
    }

    fn route_and_connect(conn: *ProxyConn, request: *const h1.Request) void {
        assert(conn.upstream_fd < 0); // no upstream socket yet
        // A protocol upgrade cannot survive the forced `Connection: close`;
        // refuse it honestly rather than letting it fail at the upstream.
        if (request.header("upgrade") != null) return conn.fail(response_501);
        // Smuggling-shaped framing (TE+CL, duplicate/garbage Content-Length)
        // is rejected before any byte reaches an upstream.
        const framing = h1.request_framing(request) catch return conn.fail(response_400);
        conn.request_method = request.method;
        conn.request_framer = h1.BodyFramer.init(framing);
        const connection = ConnectionTokens.collect(request.headers);
        // A truncated token list means incomplete hop-by-hop classification;
        // refuse rather than forward a header we should have stripped.
        if (connection.overflow) return conn.fail(response_400);
        conn.downstream_keep_alive = keep_alive_requested(request, &connection);
        const cluster = conn.router.route(request.host(), request.target) orelse
            return conn.fail(response_404);
        conn.cluster_index = @intCast(cluster.index);
        conn.policy = &cluster.policy;
        conn.cluster = cluster;
        if (!conn.resilience.admit_request(conn.cluster_index, conn.policy)) {
            conn.metrics.breaker_requests_rejected.add(1);
            return conn.fail(response_503);
        }
        conn.resilience.request_start(conn.cluster_index);
        conn.request_admitted = true;
        const endpoint_index = conn.pick_endpoint(cluster, request) orelse
            return conn.fail(response_503);
        const endpoint = &cluster.endpoints[endpoint_index];
        // Body bytes already buffered behind the head count toward the frame;
        // anything past the request's end (a pipelined next request) must not
        // reach the upstream.
        const body = conn.head_buf[request.head_len..conn.head_filled];
        const body_consumed = conn.request_framer.consume(body) catch
            return conn.fail(response_400);
        conn.request_end = request.head_len + body_consumed;
        conn.build_prime_segments(request, conn.request_end, &connection);
        // Replayable = the whole request is in the prime segments; a stale
        // pooled connection can then be retried without losing body bytes.
        conn.request_replayable = conn.request_framer.is_complete();
        conn.endpoint_address = endpoint.address;
        // The attempt opens once the endpoint interaction begins — after the
        // request-side 4xx rejections above, so a client error can never be
        // settled against the endpoint.
        conn.open_attempt(endpoint_index);
        conn.arm_try_deadline();
        conn.begin_attempt();
    }

    /// Open the upstream side of the current attempt: a pooled connection
    /// when one is parked for the endpoint, else a fresh dial.
    fn begin_attempt(conn: *ProxyConn) void {
        assert(conn.attempt_open);
        assert(conn.upstream_fd < 0);
        assert(conn.upstream_tls == null); // the previous leg was disposed
        const cluster_wants_tls = conn.upstream_tls_context() != null;
        if (conn.upstream_pool.checkout(conn.endpoint_address)) |parked| {
            assert(parked.fd >= 0);
            // Two clusters may share an endpoint address with different TLS
            // postures; a parked connection of the wrong kind is useless to
            // this attempt — close it and dial fresh.
            if (cluster_wants_tls != (parked.channel != null)) {
                if (parked.channel) |channel| channel.deinit();
                conn.io.close_now(parked.fd);
                return conn.connect_upstream();
            }
            if (parked.channel) |channel| {
                // Resume the parked TLS session as this attempt's leg: the
                // handshake is long done, so the prime goes straight out.
                assert(conn.tls_legs != null); // a parked channel implies TLS config
                const leg = conn.tls_legs.?.acquire() orelse {
                    // Cannot happen by sizing. Nothing committed yet: drop
                    // the parked connection and dial fresh (the dial's own
                    // leg acquire sheds if the pool is truly dry).
                    channel.deinit();
                    conn.io.close_now(parked.fd);
                    return conn.connect_upstream();
                };
                leg.reset(channel, .upstream, false);
                leg.handshake_complete = true;
                conn.upstream_tls = leg;
            }
            conn.upstream_fd = parked.fd;
            conn.account_upstream_open();
            conn.upstream_pooled = true;
            conn.metrics.upstream_reused.add(1);
            return conn.arm_prime(); // already connected: skip the dial
        }
        conn.connect_upstream();
    }

    fn connect_upstream(conn: *ProxyConn) void {
        assert(conn.upstream_fd < 0);
        conn.upstream_pooled = false;
        if (!conn.resilience.admit_dial(conn.cluster_index, conn.policy)) {
            conn.metrics.breaker_dials_rejected.add(1);
            // The endpoint never saw this attempt — a breaker rejection is
            // load shedding, not an endpoint-health signal.
            conn.close_attempt(.aborted);
            return conn.fail(response_503);
        }
        conn.upstream_fd = conn.io.open_tcp_socket() orelse return conn.fail(response_502);
        assert(conn.upstream_fd >= 0);
        conn.account_upstream_open();
        conn.dial_pending = true;
        conn.resilience.dial_start(conn.cluster_index);
        conn.retain();
        conn.io.connect(
            *ProxyConn,
            conn,
            on_connect,
            &conn.connect_completion,
            conn.upstream_fd,
            sockaddr_in(conn.endpoint_address),
        );
    }

    fn on_connect(conn: *ProxyConn, _: *Completion, result: io_mod.ConnectError!void) void {
        defer conn.release_ref();
        // The dial settles before the closing check: a cancelled connect
        // still delivers its completion, and this is its only settle point.
        assert(conn.dial_pending);
        conn.dial_pending = false;
        conn.resilience.dial_finish(conn.cluster_index);
        if (conn.closing) return;
        // Cancelled (or raced to completion) by a per-try abort: drain.
        if (conn.attempt_dead) return conn.attempt_drained();
        result catch return conn.attempt_failed(.connect_error);
        assert(conn.upstream_fd >= 0);
        // A re-encrypting cluster handshakes before the request; the prime
        // follows from the upstream leg's handshake-done continuation.
        if (conn.upstream_tls_context()) |context| return conn.upstream_tls_begin(context);
        conn.arm_prime();
    }

    // ---- per-try timeout ----------------------------------------------------

    /// Arm the per-attempt deadline. Only for replayable requests: in that
    /// window the attempt owns exactly one in-flight upstream op at a time
    /// (connect, prime send, or response-head recv — never a relay pipe),
    /// so an abort drains deterministically. Streaming requests run under
    /// the overall deadline alone (a documented simplification).
    fn arm_try_deadline(conn: *ProxyConn) void {
        assert(conn.attempt_open);
        assert(!conn.attempt_dead);
        conn.try_deadline_ns = 0;
        if (conn.policy.per_try_timeout_ns == 0) return;
        if (!conn.request_replayable) return;
        conn.try_deadline_ns = conn.io.now_ns() + conn.policy.per_try_timeout_ns;
    }

    /// The per-try deadline passed. Kill the attempt's single in-flight
    /// upstream op and let its completion drain through `attempt_drained`.
    /// Never `fail` from here: the in-flight op may own `aux_completion` (a
    /// prime send), which `fail` would resubmit while it sits in the ring.
    fn abort_attempt(conn: *ProxyConn) void {
        assert(!conn.closing);
        assert(conn.attempt_open);
        assert(conn.request_replayable); // arm_try_deadline's clean window
        assert(!conn.attempt_dead);
        conn.try_deadline_ns = 0;
        conn.attempt_dead = true;
        conn.metrics.per_try_timeouts.add(1);
        if (conn.dial_pending) {
            // shutdown() cannot reach a connecting socket; cancel the op.
            if (!conn.try_connect_cancel_pending) {
                conn.try_connect_cancel_pending = true;
                conn.retain();
                conn.io.cancel(
                    *ProxyConn,
                    conn,
                    on_try_connect_cancel,
                    &conn.try_connect_cancel_completion,
                    &conn.connect_completion,
                );
            }
            return;
        }
        // A prime send or response-head recv is in flight: shutdown forces
        // it to complete; its callback sees `attempt_dead` and drains.
        assert(conn.upstream_fd >= 0);
        conn.io.shutdown_socket(conn.upstream_fd);
    }

    fn on_try_connect_cancel(conn: *ProxyConn, _: *Completion, _: io_mod.CancelError!void) void {
        conn.try_connect_cancel_pending = false;
        if (!conn.closing) conn.maybe_start_retry(); // a retry may be gated on this cancel
        conn.release_ref();
    }

    /// The aborted attempt's in-flight op has drained: the connection is
    /// quiescent (`aux_completion` free, nothing pending upstream) and the
    /// failure can be handled honestly — retried or answered 504.
    fn attempt_drained(conn: *ProxyConn) void {
        assert(conn.attempt_dead);
        assert(!conn.closing);
        conn.attempt_dead = false;
        conn.attempt_failed(.per_try_timeout);
    }

    /// An upstream attempt died before the response head completed (nothing
    /// was forwarded downstream yet). Two retry tiers, then terminal: the
    /// built-in stale-pool replay (same endpoint, immediate, free), a
    /// configured retry (new endpoint pick, jittered backoff, budgeted), or
    /// a clean 502/504.
    fn attempt_failed(conn: *ProxyConn, reason: AttemptFailure) void {
        assert(!conn.closing);
        assert(conn.attempt_open);
        const terminal = if (reason == .per_try_timeout) response_504 else response_502;
        // Replay safety: the whole request must still sit in the prime
        // segments and no response byte may have reached the client. The
        // close-completion guard mirrors the Phase-1 rule (seed 1693): a
        // previous close still in flight owns `close_upstream_completion`.
        const replayable = conn.request_replayable and !conn.response_bytes_received and
            !conn.upstream_close_pending;
        if (!replayable) return conn.fail(terminal);
        // Tier 1 — a parked keep-alive connection the upstream closed under
        // us: normal pool churn, not an endpoint-health signal. Replay once,
        // same endpoint, no backoff, no budget charge. (A per-try timeout is
        // a health signal, pooled or not — it takes the configured path.)
        if (conn.upstream_pooled and !conn.upstream_retry_used and reason != .per_try_timeout) {
            conn.upstream_retry_used = true;
            conn.metrics.upstream_retried.add(1);
            conn.close_attempt(.failure_stale_pool);
            conn.dispose_upstream();
            conn.prime_segment_index = 0;
            conn.prime_sent = 0;
            conn.open_attempt(conn.endpoint_index);
            conn.arm_try_deadline(); // the replay is a fresh attempt with a fresh budget
            return conn.connect_upstream(); // deliberately fresh: never a pooled sibling
        }
        // Tier 2 — configured retries, gated by the retry budget and the
        // max_retries breaker.
        if (conn.attempts_used < conn.policy.retry_max) {
            if (conn.resilience.admit_retry(conn.cluster_index, conn.policy)) {
                return conn.schedule_retry();
            }
            conn.metrics.retry_budget_exhausted.add(1);
        }
        conn.fail(terminal);
    }

    /// Settle the failed attempt, dispose of its upstream, and arm the
    /// fully-jittered exponential backoff. The retry itself starts in
    /// `maybe_start_retry` once every gate clears.
    fn schedule_retry(conn: *ProxyConn) void {
        assert(!conn.closing);
        assert(conn.request_replayable);
        assert(!conn.retry_scheduled); // one scheduled retry at a time
        assert(!conn.retry_pending);
        conn.close_attempt(.failure); // a real failure: feeds outlier detection
        conn.charge_retry();
        conn.attempts_used += 1;
        assert(conn.attempts_used <= constants.retry_attempts_max);
        conn.metrics.retry_attempts.add(1);
        conn.dispose_upstream();
        // Full jitter: uniform in [0, min(base << used, cap)) — desynchronizes
        // retry herds better than equal-jitter (AWS Architecture Blog,
        // "Exponential Backoff and Jitter").
        const shift: u6 = @intCast(conn.attempts_used - 1);
        const ceiling = @min(
            @as(u64, conn.policy.retry_backoff_base_ns) << shift,
            conn.policy.retry_backoff_cap_ns,
        );
        assert(ceiling > 0); // base >= 1ns is enforced at parse
        const delay_ns: u63 = @intCast(@max(conn.random.uintLessThan(u64, ceiling), 1));
        conn.retry_scheduled = true;
        conn.retry_pending = true;
        conn.retain();
        conn.io.timeout(
            *ProxyConn,
            conn,
            on_retry_backoff,
            &conn.retry_timeout_completion,
            delay_ns,
        );
    }

    fn on_retry_backoff(conn: *ProxyConn, _: *Completion, _: io_mod.TimeoutError!void) void {
        defer conn.release_ref();
        conn.retry_pending = false;
        if (conn.closing) return; // cancelled by teardown; the charge settles there
        conn.maybe_start_retry();
    }

    /// Start the scheduled retry once every gate has cleared: the backoff
    /// expired, the dead upstream's close completed (its completion is
    /// reused), and no stale connect-cancel is in flight (it could kill the
    /// new dial). Each gate-clearing callback calls this; the last one
    /// through starts the attempt.
    fn maybe_start_retry(conn: *ProxyConn) void {
        assert(!conn.closing);
        if (!conn.retry_scheduled) return;
        if (conn.retry_pending) return;
        if (conn.upstream_close_pending) return;
        if (conn.try_connect_cancel_pending) return;
        conn.retry_scheduled = false;
        assert(!conn.attempt_open); // settled when the retry was scheduled
        assert(conn.request_replayable);
        assert(conn.upstream_fd < 0);
        const cluster = conn.cluster.?; // set at route time, request still active
        // Prefer a different endpoint than the one that just failed. A
        // hashed request keeps walking its table (deterministic next),
        // everything else re-draws P2C.
        const state = conn.resilience.cluster_state(conn.cluster_index);
        const endpoint_index = if (conn.affinity_hashed)
            balancer.pick_hashed(
                cluster,
                state,
                conn.affinity_hash,
                conn.io.now_ns(),
                conn.endpoint_index,
            ) orelse return conn.fail(response_502) // unreachable: routed non-empty
        else
            balancer.pick_least_request(
                cluster,
                state,
                conn.random,
                conn.io.now_ns(),
                conn.endpoint_index,
            ) orelse return conn.fail(response_502); // unreachable: cluster routed non-empty
        conn.endpoint_address = cluster.endpoints[endpoint_index].address;
        conn.prime_segment_index = 0;
        conn.prime_sent = 0;
        assert(conn.head_filled >= conn.request_end); // the prime segments are intact
        conn.open_attempt(endpoint_index);
        conn.arm_try_deadline();
        conn.begin_attempt();
    }

    /// Shutdown + close the current upstream fd on the per-request close
    /// completion. Callers hold `!upstream_close_pending` (checked by the
    /// replay gate or guaranteed by phase).
    fn dispose_upstream(conn: *ProxyConn) void {
        if (conn.upstream_fd < 0) return;
        assert(!conn.upstream_close_pending);
        // The attempt's TLS leg dies with its connection. Dispose points are
        // quiescent — no wire op can be in flight (their completions are how
        // the attempt settled); a stale yield is guarded by its callback.
        if (conn.upstream_tls) |leg| {
            assert(!leg.wire_recv_in_flight);
            assert(!leg.wire_send_in_flight);
            leg.channel.deinit();
            conn.tls_leg_release(leg);
            conn.upstream_tls = null;
        }
        conn.io.shutdown_socket(conn.upstream_fd);
        conn.upstream_close_pending = true;
        conn.retain();
        conn.io.close(
            *ProxyConn,
            conn,
            on_upstream_closed,
            &conn.close_upstream_completion,
            conn.upstream_fd,
        );
        conn.upstream_fd = -1;
        conn.account_upstream_drop();
    }

    // ---- forward buffered request bytes, then relay -----------------------

    /// Lay out the upstream-bound request as slices of `head_buf`: hop-by-hop
    /// header lines are skipped and a static `Connection: close` terminator is
    /// injected, all without copying a byte. This makes one-request-per-
    /// connection real: the upstream closes after its response, and a second
    /// pipelined request can never reach the first request's cluster.
    fn build_prime_segments(
        conn: *ProxyConn,
        request: *const h1.Request,
        body_end: usize,
        connection: *const ConnectionTokens,
    ) void {
        assert(request.head_len >= 4); // shortest head: request line + blank line
        assert(request.head_len <= conn.head_filled);
        assert(body_end >= request.head_len); // the frame starts after the head
        assert(body_end <= conn.head_filled); // and never exceeds what was read
        var count: usize = 0;
        var kept_start: usize = 0;
        for (request.headers) |header| {
            if (!is_hop_by_hop_header(connection, header.name)) continue;
            const line_start = @intFromPtr(header.line.ptr) - @intFromPtr(&conn.head_buf);
            assert(line_start >= kept_start); // header lines are in buffer order
            assert(line_start + header.line.len <= request.head_len);
            if (line_start > kept_start) {
                conn.prime_segments[count] = conn.head_buf[kept_start..line_start];
                count += 1;
            }
            kept_start = line_start + header.line.len;
        }
        const head_end = request.head_len - 2; // stop before the blank-line CRLF
        if (head_end > kept_start) {
            conn.prime_segments[count] = conn.head_buf[kept_start..head_end];
            count += 1;
        }
        conn.prime_segments[count] = head_terminator;
        count += 1;
        if (body_end > request.head_len) { // framed body bytes already buffered
            conn.prime_segments[count] = conn.head_buf[request.head_len..body_end];
            count += 1;
        }
        assert(count >= 2); // at least the request line and the injected close
        assert(count <= prime_segments_max);
        conn.prime_segment_count = count;
        conn.prime_segment_index = 0;
        conn.prime_sent = 0;
    }

    fn arm_prime(conn: *ProxyConn) void {
        assert(conn.upstream_fd >= 0);
        assert(conn.prime_segment_index < conn.prime_segment_count);
        const segment = conn.prime_segments[conn.prime_segment_index];
        assert(conn.prime_sent < segment.len);
        if (conn.upstream_tls != null) {
            const leg = conn.upstream_tls.?;
            return conn.tls_send_start(leg, segment[conn.prime_sent..], handle_prime_sent);
        }
        conn.retain();
        conn.io.send(
            *ProxyConn,
            conn,
            on_prime_sent,
            &conn.aux_completion,
            conn.upstream_fd,
            segment[conn.prime_sent..],
        );
    }

    fn on_prime_sent(conn: *ProxyConn, _: *Completion, result: io_mod.SendError!usize) void {
        defer conn.release_ref();
        if (conn.closing) return;
        conn.handle_prime_sent(result);
    }

    fn handle_prime_sent(conn: *ProxyConn, result: io_mod.SendError!usize) void {
        assert(!conn.closing); // both callers bail first
        // Killed by a per-try abort (the shutdown errored this send — or the
        // send won the race; either way the attempt is dead): drain.
        if (conn.attempt_dead) return conn.attempt_drained();
        const m = result catch return conn.attempt_failed(.send_error);
        // The primed head is upstream traffic too — without this, a GET-only
        // workload reports zero bytes_to_upstream (only the relay pipe counts).
        conn.metrics.bytes_to_upstream.add(m);
        const segment = conn.prime_segments[conn.prime_segment_index];
        conn.prime_sent += m;
        assert(conn.prime_sent <= segment.len); // never forward past the segment
        if (conn.prime_sent < segment.len) return conn.arm_prime(); // finish a partial write
        conn.prime_segment_index += 1;
        conn.prime_sent = 0;
        if (conn.prime_segment_index < conn.prime_segment_count) return conn.arm_prime();
        conn.start_relay();
    }

    fn start_relay(conn: *ProxyConn) void {
        assert(conn.downstream_fd >= 0);
        assert(conn.upstream_fd >= 0);
        conn.outcome = .proxied;
        conn.request_pipe.conn = conn;
        conn.request_pipe.src_fd = conn.downstream_fd;
        conn.request_pipe.dst_fd = conn.upstream_fd;
        conn.request_pipe.to_client = false;
        conn.request_pipe.framer = conn.request_framer; // continues where the prime left off
        conn.request_pipe.filled = 0;
        conn.request_pipe.sent = 0;
        conn.response_pipe.conn = conn;
        conn.response_pipe.src_fd = conn.upstream_fd;
        conn.response_pipe.dst_fd = conn.downstream_fd;
        conn.response_pipe.to_client = true;
        // Placeholder until the response head parses (begin_response_relay);
        // the response_pipe pipe callbacks never run before then.
        conn.response_pipe.framer = h1.BodyFramer.init(.until_close);
        conn.response_pipe.filled = 0;
        conn.response_pipe.sent = 0;
        // The request_pipe direction only runs while request-body bytes are owed.
        conn.request_forwarded = conn.request_pipe.framer.is_complete();
        if (!conn.request_forwarded) conn.request_pipe.arm_recv();
        conn.arm_recv_response_head();
    }

    // ---- response head ------------------------------------------------------

    /// Accumulate the response head in the response_pipe pipe's buffer (nothing is
    /// forwarded downstream until it parses, so an unparseable upstream can
    /// still be answered with a clean 502).
    fn arm_recv_response_head(conn: *ProxyConn) void {
        assert(conn.upstream_fd >= 0);
        const pipe = &conn.response_pipe;
        // The head-phase reads stop short of the buffer end so a
        // `Connection: close` injection always has room (body-phase relay
        // reads, after the head is forwarded, use the whole buffer again).
        const capacity = pipe.buf.len - close_header_line.len;
        if (pipe.filled >= capacity) return conn.fail(response_502); // head too large
        assert(pipe.filled < capacity); // there is room to read into
        if (conn.upstream_tls != null) {
            const leg = conn.upstream_tls.?;
            return conn.tls_recv_start(
                leg,
                pipe.buf[pipe.filled..capacity],
                handle_recv_response_head,
            );
        }
        conn.retain();
        conn.io.recv(
            *ProxyConn,
            conn,
            on_recv_response_head,
            &pipe.recv_completion,
            conn.upstream_fd,
            pipe.buf[pipe.filled..capacity],
        );
    }

    fn on_recv_response_head(
        conn: *ProxyConn,
        _: *Completion,
        result: io_mod.RecvError!usize,
    ) void {
        defer conn.release_ref();
        if (conn.closing) return;
        conn.handle_recv_response_head(result);
    }

    fn handle_recv_response_head(conn: *ProxyConn, result: io_mod.RecvError!usize) void {
        assert(!conn.closing); // both callers bail first
        // Killed by a per-try abort: drain (any raced-in bytes are moot).
        if (conn.attempt_dead) return conn.attempt_drained();
        const n = result catch return conn.attempt_failed(.recv_error);
        if (n == 0) return conn.attempt_failed(.upstream_eof); // closed without a response
        conn.response_bytes_received = true;
        conn.try_deadline_ns = 0; // the attempt reached its first response byte
        conn.response_pipe.filled += n;
        assert(conn.response_pipe.filled <= conn.response_pipe.buf.len);
        const parsed = h1.parse_response(
            conn.response_pipe.buf[0..conn.response_pipe.filled],
            &conn.headers_storage, // the request's headers are dead by now
        ) catch return conn.fail(response_502);
        switch (parsed) {
            .incomplete => conn.arm_recv_response_head(),
            .complete => |response| conn.begin_response_relay(&response),
        }
    }

    fn begin_response_relay(conn: *ProxyConn, response: *const h1.Response) void {
        assert(response.head_len > 0);
        assert(response.head_len <= conn.response_pipe.filled);
        // An interim (1xx) response precedes the real one; relay everything
        // until the upstream closes. (Proper 1xx handling comes with the
        // upstream pool slice.)
        const framing = if (response.status < 200)
            h1.Framing.until_close
        else
            h1.response_framing(conn.request_method, response) catch
                return conn.fail(response_502); // conflicting framing: refuse to guess
        const pipe = &conn.response_pipe;
        // Collected once; a truncated (overflow) list means incomplete
        // hop-by-hop classification, which poisons any reuse or splicing.
        const connection = ConnectionTokens.collect(response.headers);
        // Reuse intent: a framed response to a keep-alive client. The final
        // decision (`can_reuse_downstream`) also needs the request forwarded.
        // A draining worker never reuses — falling into the injection branch
        // below, so the client is told `Connection: close` (RFC 9112 §9.6).
        conn.response_reusable = conn.downstream_keep_alive and
            framing != .until_close and
            !connection.overflow and
            !conn.drain_close;
        // The upstream connection can be pooled when the response is framed
        // HTTP/1.1 that does not announce a close. (Decided before the strip
        // below invalidates the header slices.)
        conn.upstream_reusable = framing != .until_close and
            response.status >= 200 and
            response.version_minor == 1 and
            !connection.overflow and
            !connection.names("close");
        var head_len = response.head_len;
        if (conn.response_reusable) {
            // The upstream's connection-management headers (a close
            // announcement, keep-alive hints) are hop semantics between it
            // and us; a keep-alive client must not see them and close on us.
            head_len -= conn.strip_response_head(response, &connection);
        } else if (response.status >= 200 and !connection.names("close")) {
            // We will close the downstream connection after this response;
            // the head must say so (RFC 9112 §9.6) or an HTTP/1.1 client
            // assumes keep-alive and reads our close as a failure. Interim
            // (1xx) heads are relayed untouched — they are not the response.
            head_len += conn.inject_response_close(head_len);
        }
        pipe.framer = h1.BodyFramer.init(framing);
        const body = pipe.buf[head_len..pipe.filled];
        const body_consumed = pipe.framer.consume(body) catch return conn.fail(response_502);
        // Forward the head plus the framed body prefix; bytes past the
        // message end are dropped (the upstream must not pipeline at us) and
        // taint the connection against pooling.
        if (body_consumed < body.len) conn.response_pipe_overflow = true;
        pipe.filled = head_len + body_consumed;
        pipe.sent = 0;
        assert(pipe.sent < pipe.filled); // the head alone is never empty
        pipe.arm_send(); // Pipe.on_send continues: finish, or relay the rest
    }

    /// Remove hop-by-hop header lines (`Connection` + everything it names,
    /// `Keep-Alive`, `Proxy-Connection`) from the response head, in place:
    /// the head lives in our relay buffer, so the remainder shifts left (one
    /// bounded copy). For an HTTP/1.1 client, absence of `Connection` means
    /// keep-alive — nothing needs injecting. Returns the bytes removed.
    fn strip_response_head(
        conn: *ProxyConn,
        response: *const h1.Response,
        connection: *const ConnectionTokens,
    ) usize {
        const pipe = &conn.response_pipe;
        assert(response.head_len <= pipe.filled);
        assert(response.headers.len <= constants.headers_max);
        // Decide up front: compaction below invalidates the header slices.
        var remove: [constants.headers_max]bool = undefined;
        for (response.headers, 0..) |header, index| {
            remove[index] = is_hop_by_hop_header(connection, header.name);
        }
        var write: usize = 0;
        var read: usize = 0;
        var removed: usize = 0;
        for (response.headers, 0..) |header, index| {
            if (!remove[index]) continue;
            const line_start = @intFromPtr(header.line.ptr) - @intFromPtr(&pipe.buf);
            assert(line_start >= read); // header lines are in buffer order
            assert(line_start + header.line.len <= response.head_len);
            const keep = line_start - read;
            std.mem.copyForwards(u8, pipe.buf[write .. write + keep], pipe.buf[read..line_start]);
            write += keep;
            read = line_start + header.line.len;
            removed += header.line.len;
        }
        const tail = pipe.filled - read;
        std.mem.copyForwards(u8, pipe.buf[write .. write + tail], pipe.buf[read..pipe.filled]);
        assert(removed == read - write);
        pipe.filled -= removed;
        return removed;
    }

    /// Insert `Connection: close` before the head's terminating blank line,
    /// shifting the buffered body prefix right (one bounded copy; the head
    /// phase reserved the room). Returns the bytes inserted.
    fn inject_response_close(conn: *ProxyConn, head_len: usize) usize {
        const pipe = &conn.response_pipe;
        assert(head_len >= 4); // shortest head: status line + blank line
        assert(head_len <= pipe.filled);
        assert(pipe.filled + close_header_line.len <= pipe.buf.len); // reserved in head recv
        const insert_at = head_len - 2; // before the blank-line CRLF
        std.mem.copyBackwards(
            u8,
            pipe.buf[insert_at + close_header_line.len .. pipe.filled + close_header_line.len],
            pipe.buf[insert_at..pipe.filled],
        );
        @memcpy(pipe.buf[insert_at..][0..close_header_line.len], close_header_line);
        pipe.filled += close_header_line.len;
        return close_header_line.len;
    }

    /// The framed response has been fully forwarded: keep the downstream
    /// connection when everything lines up, else close. Closing *here*,
    /// rather than on EOF, is what keeps a lingering upstream from pinning
    /// the slot.
    fn response_complete(conn: *ProxyConn) void {
        assert(conn.outcome == .proxied); // only a relayed response completes
        conn.settle_accounting(.success);
        conn.maybe_pool_upstream();
        // The response is fully delivered: a close here is server-initiated
        // and polite (close_notify for a TLS client). `drain_close` covers a
        // drain that began after this response's head (with its reuse
        // decision) was already relayed: complete response, then close.
        if (!conn.can_reuse_downstream() or conn.drain_close) return conn.close_downstream();
        conn.finish_request();
    }

    /// Park the upstream connection for the next request to this endpoint —
    /// independent of whether the *downstream* connection survives.
    fn maybe_pool_upstream(conn: *ProxyConn) void {
        if (!conn.upstream_reusable) return;
        if (conn.response_pipe_overflow) return;
        // The request must be fully forwarded with nothing in flight: if the
        // upstream answered while the client was still uploading, a request_pipe send
        // may still be pending on this very fd — parking it would strand the
        // operation and leak stray body bytes into a pooled connection.
        // (Found by the simulator, seed 1693.)
        if (!conn.request_forwarded) return;
        if (conn.upstream_fd < 0) return;
        assert(conn.endpoint_address.port != 0); // set when the request routed
        // A TLS leg parks its channel with the fd — but only fully quiescent:
        // no unfed ciphertext, no wire op in flight, nothing pending in the
        // pair, nothing buffered inside the SSL. Leftover plaintext in the
        // SSL would corrupt the next request's response head; unprocessed
        // session tickets land in the same check, and closing is the safe
        // answer to both.
        var parked_channel: ?terminator.Channel = null;
        if (conn.upstream_tls) |leg| {
            conn.tls_feed_staged(leg); // a record tail may still be staged
            const quiescent = leg.wire_recv_staged == 0 and
                !leg.wire_recv_in_flight and
                !leg.wire_send_in_flight and
                leg.channel.pending_ciphertext() == 0 and
                leg.channel.kernel_switch_eligible(); // nothing buffered in the SSL
            if (!quiescent) return; // finish_request / teardown closes it
            parked_channel = leg.channel; // ownership moves to the upstream pool
            conn.tls_leg_release(leg); // the leg (wire staging) does not
            conn.upstream_tls = null;
        }
        // Nothing is pending on the fd: the response was fully received and
        // fully forwarded before this point.
        conn.upstream_pool.checkin(
            conn.io,
            conn.endpoint_address,
            conn.upstream_fd,
            parked_channel,
        );
        conn.upstream_fd = -1;
        conn.account_upstream_drop(); // idle pooled fds are not cluster connections
    }

    /// Downstream reuse requires: keep-alive client + framed response
    /// (established at response-head time), the request fully forwarded with
    /// nothing in flight, no pipelined bytes stranded in the relay buffer,
    /// and the previous upstream close completed (its completion is reused).
    fn can_reuse_downstream(conn: *const ProxyConn) bool {
        if (!conn.response_reusable) return false;
        if (!conn.request_forwarded) return false;
        if (conn.request_pipe_overflow) return false;
        if (conn.upstream_close_pending) return false;
        return true;
    }

    /// The exchange finished and the downstream connection stays open: log
    /// the request, drop the per-request upstream, slide pipelined bytes to
    /// the front of the head buffer, reset per-request state, and parse the
    /// next head (which may already be complete in the buffer).
    fn finish_request(conn: *ProxyConn) void {
        assert(!conn.closing);
        assert(conn.downstream_fd >= 0);
        assert(conn.outcome == .proxied);
        conn.access.record(.{
            .method = conn.log_method,
            .target = conn.log_target,
            .outcome = conn.outcome,
            .bytes_to_client = conn.bytes_out,
        });
        // Same discipline as teardown: shutdown so any straggler op on the
        // fd completes, then close.
        conn.dispose_upstream();
        assert(conn.request_end <= conn.head_filled);
        const excess = conn.head_filled - conn.request_end;
        if (excess > 0) {
            std.mem.copyForwards(
                u8,
                conn.head_buf[0..excess],
                conn.head_buf[conn.request_end..conn.head_filled],
            );
        }
        conn.head_filled = excess;
        conn.reset_request_state();
        conn.request_active = conn.head_filled > 0; // pipelined bytes = a request in flight
        // A pipelined request starts its clock now; otherwise the idle clock runs.
        const next_timeout_ns =
            if (conn.request_active) conn.request_timeout_ns else conn.idle_timeout_ns;
        conn.set_deadline(next_timeout_ns);
        conn.process_head();
    }

    fn on_upstream_closed(conn: *ProxyConn, _: *Completion, _: io_mod.CloseError!void) void {
        conn.upstream_close_pending = false;
        if (!conn.closing) conn.maybe_start_retry(); // a retry may be gated on this close
        conn.release_ref();
    }

    // ---- error path -------------------------------------------------------

    fn fail(conn: *ProxyConn, response: []const u8) void {
        assert(conn.downstream_fd >= 0);
        assert(response.len > 12); // "HTTP/1.1 XXX": status class read at index 9
        // An attempt can only be open here for an upstream fault (client
        // errors fail before `open_attempt`), so `failure` is an honest
        // endpoint-health signal.
        conn.settle_accounting(.failure);
        conn.outcome = outcome_for(response);
        // Status class is the first digit of the code at index 9 ("HTTP/1.1 X").
        if (response[9] == '4') {
            conn.metrics.client_errors.add(1);
        } else {
            conn.metrics.upstream_errors.add(1);
        }
        conn.fail_response = response;
        conn.fail_sent = 0;
        conn.arm_fail_send();
    }

    fn arm_fail_send(conn: *ProxyConn) void {
        assert(conn.downstream_fd >= 0);
        assert(conn.fail_sent < conn.fail_response.len);
        if (conn.tls != null) {
            return conn.tls_send_start(
                conn.tls.?,
                conn.fail_response[conn.fail_sent..],
                handle_fail_sent,
            );
        }
        conn.retain();
        conn.io.send(
            *ProxyConn,
            conn,
            on_fail_sent,
            &conn.aux_completion,
            conn.downstream_fd,
            conn.fail_response[conn.fail_sent..],
        );
    }

    fn on_fail_sent(conn: *ProxyConn, _: *Completion, result: io_mod.SendError!usize) void {
        defer conn.release_ref();
        if (conn.closing) return;
        conn.handle_fail_sent(result);
    }

    fn handle_fail_sent(conn: *ProxyConn, result: io_mod.SendError!usize) void {
        assert(!conn.closing); // both callers bail first
        const m = result catch return conn.teardown();
        conn.fail_sent += m;
        assert(conn.fail_sent <= conn.fail_response.len); // never send past the response
        if (conn.fail_sent < conn.fail_response.len) return conn.arm_fail_send();
        conn.close_downstream(); // the full response is out; close politely
    }
};

/// Accept loop: one pooled `ProxyConn` per accepted downstream socket.
pub const ProxyServer = struct {
    io: *IO,
    pool: *Pool,
    listener: Listener,
    router: *const Router,
    /// This worker's metrics shard (single writer; the worker resolves it
    /// from the sharded `Metrics` before init — tests pass a bare set).
    metrics: *Counters,
    access: *AccessLog,
    resilience: Resilience,
    upstream_pool: UpstreamPool,
    /// Per-worker PRNG for P2C draws and retry jitter. Tests keep the
    /// deterministic default; `main.zig` seeds each worker from startup
    /// entropy, `sim.zig` from the iteration seed (both post-init).
    prng: std.Random.DefaultPrng,
    /// Downstream TLS termination context; null = plaintext listener. Set by
    /// the worker after init, like `prng` (tests set it for the TLS
    /// end-to-end case). Shared across workers: with the session cache and
    /// tickets off it is immutable, and SSL_new only bumps its refcount.
    tls_context: ?*const terminator.Context,
    /// Upstream re-encryption contexts, one slot per cluster (by
    /// `cluster.index`; null = plaintext upstream). Set by the worker after
    /// init; empty means "no cluster re-encrypts". Used from U2 onward.
    upstream_tls_contexts: []const ?*const terminator.Context,
    /// This worker's TLS leg pool; set by the worker after init alongside
    /// the contexts. Null iff neither side speaks TLS.
    tls_legs: ?*TlsLegPool,
    /// This worker's HTTP/2 pools (docs/DESIGN.md §7 Phase 5): non-null iff
    /// `tls.http2`, set by the worker after init. When a downstream ALPN
    /// negotiates `h2`, the connection is handed to an `H2Conn` from these.
    h2_conn_pool: ?*H2ConnPool,
    h2_leg_pool: ?*H2LegPool,
    request_timeout_ns: u63,
    idle_timeout_ns: u63,
    /// Drain-to-forced-teardown bound; set by the worker after init like
    /// `prng` (the simulator shrinks it to force the deadline path).
    drain_timeout_ns: u63,
    /// Graceful drain (docs/DESIGN.md §7 Phase 4). Once `draining` is set:
    /// no new accepts, the listener closes, idle connections close politely,
    /// in-flight responses are completed-then-closed, and the worker's loop
    /// exits when `drain_complete()`.
    draining: bool,
    /// The listener fd has been closed (exactly once, by the drain path).
    listener_closed: bool,
    /// Server-scoped ring ops in flight: the accept, its retry timer, the
    /// accept cancel, and the drain-trigger recv. `drain_complete` requires
    /// zero so a worker never abandons a live op on ring teardown.
    operations_pending: u32,
    accept_pending: bool,
    /// Shared-listener refcount (accept_mode = shared, docs/DESIGN.md §7
    /// Phase 4): every worker holds the *same* listener fd, so only the last
    /// worker out may close it — an earlier close would hand the fd number
    /// back for reuse while sibling workers still have ops referencing it.
    /// Null = this worker owns its listener (reuseport mode, tests). Wired
    /// by the worker before `start`, like `prng`.
    listener_refs: ?*Counter,
    /// Wired by the worker before `start` (-1 = none): a byte, EOF, or error
    /// on this fd — main's socketpair poke — begins the drain. The pending
    /// recv is what lets a signal wake a worker blocked in the ring.
    drain_trigger_fd: posix.socket_t,
    drain_trigger_buf: [1]u8,
    accept_completion: Completion,
    accept_retry_completion: Completion,
    accept_cancel_completion: Completion,
    drain_trigger_completion: Completion,

    pub fn init(
        io: *IO,
        pool: *Pool,
        listener: Listener,
        router: *const Router,
        metrics: *Counters,
        access: *AccessLog,
        request_timeout_ns: u63,
        idle_timeout_ns: u63,
    ) ProxyServer {
        return .{
            .io = io,
            .pool = pool,
            .listener = listener,
            .router = router,
            .metrics = metrics,
            .access = access,
            .resilience = .{},
            .upstream_pool = .{},
            .prng = .init(0),
            .tls_context = null,
            .upstream_tls_contexts = &.{},
            .tls_legs = null,
            .h2_conn_pool = null,
            .h2_leg_pool = null,
            .request_timeout_ns = request_timeout_ns,
            .idle_timeout_ns = idle_timeout_ns,
            .drain_timeout_ns = constants.drain_timeout_ns,
            .draining = false,
            .listener_closed = false,
            .operations_pending = 0,
            .accept_pending = false,
            .listener_refs = null,
            .drain_trigger_fd = -1,
            .drain_trigger_buf = undefined,
            .accept_completion = undefined,
            .accept_retry_completion = undefined,
            .accept_cancel_completion = undefined,
            .drain_trigger_completion = undefined,
        };
    }

    /// Close every pooled upstream connection (tests; workers run forever).
    pub fn deinit(server: *ProxyServer) void {
        server.upstream_pool.drain(server.io);
    }

    pub fn start(server: *ProxyServer) void {
        assert(!server.draining); // a drained server never restarts
        server.arm_accept();
        if (server.drain_trigger_fd >= 0) server.arm_drain_trigger();
        assert(server.operations_pending >= 1); // at least the accept is in flight
    }

    fn arm_accept(server: *ProxyServer) void {
        assert(!server.accept_pending); // one accept in flight, always
        assert(!server.draining); // every re-arm site checks first
        server.accept_pending = true;
        server.operations_pending += 1;
        server.io.accept(
            *ProxyServer,
            server,
            on_accept,
            &server.accept_completion,
            server.listener.fd,
        );
    }

    fn on_accept(
        server: *ProxyServer,
        _: *Completion,
        result: io_mod.AcceptError!posix.socket_t,
    ) void {
        assert(server.accept_pending);
        server.accept_pending = false;
        server.operations_pending -= 1;
        if (server.draining) {
            // The accept loop ends here — cancelled, or one last connection
            // raced the cancel and is shed unserved. Either way the listener
            // closes now: refused-at-connect beats accepted-then-ignored.
            if (result) |fd| {
                server.metrics.rejected.add(1);
                server.io.close_now(fd);
            } else |_| {}
            server.close_listener();
            return;
        }
        if (result) |fd| {
            assert(fd >= 0);
            server.io.set_tcp_no_delay(fd); // response heads are small writes too
            if (server.pool.acquire()) |conn| {
                conn.start(
                    server.io,
                    server.pool,
                    server.router,
                    &server.resilience,
                    &server.upstream_pool,
                    server.metrics,
                    server.access,
                    server.prng.random(),
                    fd,
                    server.request_timeout_ns,
                    server.idle_timeout_ns,
                    server.tls_context,
                    server.upstream_tls_contexts,
                    server.tls_legs,
                    server.h2_conn_pool,
                    server.h2_leg_pool,
                );
            } else {
                server.metrics.rejected.add(1);
                server.io.close_now(fd); // backpressure: reject, never allocate
            }
            server.arm_accept();
        } else |err| switch (err) {
            // Quota/resource exhaustion persists; an immediate re-arm would
            // fail again instantly and spin the loop at 100% CPU. Back off.
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            error.SystemResources,
            => {
                server.operations_pending += 1;
                server.io.timeout(
                    *ProxyServer,
                    server,
                    on_accept_retry,
                    &server.accept_retry_completion,
                    constants.accept_retry_delay_ns,
                );
            },
            // Transient, per-connection failures (e.g. the peer aborted its
            // handshake); accept the next connection immediately.
            else => server.arm_accept(),
        }
    }

    fn on_accept_retry(
        server: *ProxyServer,
        _: *Completion,
        result: io_mod.TimeoutError!void,
    ) void {
        result catch {}; // even a failed timer must not stop the accept loop
        assert(server.operations_pending > 0);
        server.operations_pending -= 1;
        // A drain that began during the backoff wait finds no accept pending
        // to cancel; the accept loop ends on this tick instead.
        if (server.draining) return server.close_listener();
        server.arm_accept();
    }

    // ---- graceful drain (docs/DESIGN.md §7 Phase 4) -------------------------

    fn arm_drain_trigger(server: *ProxyServer) void {
        assert(server.drain_trigger_fd >= 0);
        assert(!server.draining);
        server.operations_pending += 1;
        server.io.recv(
            *ProxyServer,
            server,
            on_drain_trigger,
            &server.drain_trigger_completion,
            server.drain_trigger_fd,
            server.drain_trigger_buf[0..],
        );
    }

    fn on_drain_trigger(
        server: *ProxyServer,
        _: *Completion,
        result: io_mod.RecvError!usize,
    ) void {
        assert(server.operations_pending > 0);
        server.operations_pending -= 1;
        // A byte is the poke; EOF or an error means the main thread is gone.
        // All of them mean the same thing: stop taking work and finish up.
        _ = result catch {};
        server.begin_drain();
    }

    /// Begin the graceful drain: stop accepting (cancel the pending accept —
    /// its completion closes the listener), clamp every live connection's
    /// deadline to the drain limit, close the idle ones politely, and mark
    /// the busy ones close-after-response. Idempotent.
    pub fn begin_drain(server: *ProxyServer) void {
        if (server.draining) return;
        server.draining = true;
        server.metrics.draining.add(1);
        if (server.accept_pending) {
            server.operations_pending += 1;
            server.io.cancel(
                *ProxyServer,
                server,
                on_accept_cancel,
                &server.accept_cancel_completion,
                &server.accept_completion,
            );
        } else if (!server.listener_closed) {
            // No accept in flight (a backoff wait, or a server that never
            // started): nothing will deliver a completion — close here.
            server.close_listener();
        }
        const deadline_ns = server.io.now_ns() + server.drain_timeout_ns;
        for (server.pool.items) |*conn| {
            if (!conn.in_use) continue;
            if (conn.closing) continue; // already on its way out
            conn.drain_close = true;
            // The supreme deadline now also bounds the drain: the ticking
            // timer force-closes whatever outlives it (`drain_forced_closes`).
            if (conn.deadline_ns > deadline_ns) conn.deadline_ns = deadline_ns;
            // Idle between requests: close now, politely (close_notify /
            // kTLS alert for TLS clients). A connection owing or serving a
            // request (`request_active`) finishes it first; the response
            // path closes via `drain_close`.
            if (!conn.request_active) conn.close_downstream();
        }
        // The handed-off HTTP/2 connections drain in parallel: each stages a
        // GOAWAY, completes its in-flight streams, then closes (§7 Phase 5).
        if (server.h2_conn_pool) |h2_pool| {
            for (h2_pool.items) |*h2| {
                if (!h2.in_use) continue;
                h2.begin_drain();
            }
        }
        assert(server.draining);
    }

    fn on_accept_cancel(
        server: *ProxyServer,
        _: *Completion,
        _: io_mod.CancelError!void,
    ) void {
        // ENOENT (the accept won the race) is fine: on_accept saw `draining`
        // and closed the listener itself.
        assert(server.operations_pending > 0);
        server.operations_pending -= 1;
    }

    /// Close the listener fd exactly once. Nothing is ever pending on it at
    /// this point (the accept completed or was never armed), so the close is
    /// synchronous. Queued-but-unaccepted handshakes get RST — unavoidable
    /// with a closing listener (the hot-restart handoff is what avoids it).
    /// A shared listener (accept_mode = shared) closes when the *last*
    /// worker's drain reaches this point.
    fn close_listener(server: *ProxyServer) void {
        assert(server.draining); // only the drain path closes the listener
        if (server.listener_closed) return;
        server.listener_closed = true;
        assert(!server.accept_pending); // never close under a live accept
        if (server.listener_refs) |refs| {
            const remaining_before = refs.fetch_sub(1);
            assert(remaining_before >= 1); // one decrement per worker, exactly
            if (remaining_before > 1) return; // siblings still hold the fd
        }
        server.io.close_now(server.listener.fd);
    }

    /// The worker's exit condition: draining, every connection slot back in
    /// the pool, and no server-scoped op left on the ring. The parked
    /// upstream connections are closed by `deinit` after this returns true.
    pub fn drain_complete(server: *const ProxyServer) bool {
        if (!server.draining) return false;
        if (server.operations_pending > 0) return false;
        if (server.pool.free_count != server.pool.capacity) return false;
        // Handed-off H2 connections and their upstream legs must also be home.
        if (server.h2_conn_pool) |h2_pool| {
            if (h2_pool.free_count != h2_pool.capacity) return false;
        }
        if (server.h2_leg_pool) |leg_pool| {
            if (leg_pool.free_count != leg_pool.capacity) return false;
        }
        assert(server.listener_closed); // no ops pending implies the accept ended
        assert(!server.accept_pending);
        return true;
    }
};

pub const ConnPool = Pool;

fn response_for_parse_error(err: h1.ParseError) []const u8 {
    return switch (err) {
        error.Malformed => response_400,
        error.TooManyHeaders => response_431,
        error.UnsupportedVersion => response_505,
    };
}

fn outcome_for(response: []const u8) access_log.Outcome {
    if (response.ptr == response_400.ptr) return .bad_request;
    if (response.ptr == response_404.ptr) return .not_found;
    if (response.ptr == response_431.ptr) return .too_large;
    if (response.ptr == response_501.ptr) return .not_implemented;
    if (response.ptr == response_502.ptr) return .no_upstream;
    if (response.ptr == response_503.ptr) return .unavailable;
    if (response.ptr == response_504.ptr) return .upstream_timeout;
    return .bad_version; // response_505
}

/// The comma-separated tokens named by a message's `Connection` header(s),
/// collected once per message. Classifying each header used to re-scan every
/// header and re-split the token lists — O(headers²), measured at ~9% of
/// data-path CPU; against this list it is O(headers × tokens).
const ConnectionTokens = struct {
    tokens: [tokens_max][]const u8,
    count: usize,
    /// More tokens than the table holds. Absurd for a legitimate message,
    /// and classification would be incomplete — callers must refuse to
    /// splice or reuse anything based on a truncated list.
    overflow: bool,

    const tokens_max = 8;

    fn collect(headers: []const h1.Header) ConnectionTokens {
        var connection = ConnectionTokens{ .tokens = undefined, .count = 0, .overflow = false };
        for (headers) |header| {
            if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
            // Bounded by the value's length (itself bounded by the head buffer).
            var candidates = std.mem.splitScalar(u8, header.value, ',');
            while (candidates.next()) |candidate| {
                const trimmed = std.mem.trim(u8, candidate, " \t");
                if (trimmed.len == 0) continue;
                if (connection.count == tokens_max) {
                    connection.overflow = true;
                    return connection;
                }
                connection.tokens[connection.count] = trimmed;
                connection.count += 1;
            }
        }
        assert(connection.count <= tokens_max);
        return connection;
    }

    fn names(connection: *const ConnectionTokens, token: []const u8) bool {
        assert(token.len > 0);
        for (connection.tokens[0..connection.count]) |candidate| {
            if (std.ascii.eqlIgnoreCase(candidate, token)) return true;
        }
        return false;
    }
};

/// RFC 9110 §7.6.1: `Connection` itself, the legacy keep-alive headers, and
/// any header the message's `Connection` value names are hop-by-hop — they
/// must not be forwarded past this hop (either direction).
fn is_hop_by_hop_header(connection: *const ConnectionTokens, name: []const u8) bool {
    assert(name.len > 0); // parser rejects empty header names
    if (std.ascii.eqlIgnoreCase(name, "connection")) return true;
    if (std.ascii.eqlIgnoreCase(name, "keep-alive")) return true;
    if (std.ascii.eqlIgnoreCase(name, "proxy-connection")) return true;
    return connection.names(name);
}

/// Whether the client's request permits downstream connection reuse. Only
/// HTTP/1.1 (keep-alive by default) qualifies; HTTP/1.0 keep-alive is a
/// relic we treat as close (it would require injecting a response header).
fn keep_alive_requested(request: *const h1.Request, connection: *const ConnectionTokens) bool {
    if (request.version_minor != 1) return false;
    return !connection.names("close");
}

fn sockaddr_in(address: Ip4Address) linux.sockaddr.in {
    return .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, address.port),
        .addr = @bitCast(address.bytes),
    };
}

fn monotonic_nanos() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ---- tests ----------------------------------------------------------------

/// Minimal origin driven on the same IO loop: accept a connection, read the
/// request (the proxy primes it as several segmented sends), reply with a
/// fixed response, and close — then accept the next connection (the proxy
/// dials a fresh upstream per request). With `close_after_send = false` it
/// lingers instead, so tests can prove the proxy finishes without an
/// upstream EOF. All received bytes accumulate in `request_buf` so tests can
/// assert on what was actually forwarded.
const TestOrigin = struct {
    io: *IO,
    listener: Listener,
    response: []const u8,
    /// Respond once the bytes received *since the last response* contain
    /// this needle (default: the end of a request head).
    respond_after: []const u8 = "\r\n\r\n",
    close_after_send: bool = true,
    sent: usize = 0,
    fd: posix.socket_t = -1,
    request_buf: [1024]u8 = undefined,
    request_len: usize = 0,
    /// Where the current connection's scan starts (per-response marker).
    served_mark: usize = 0,
    accept_c: Completion = undefined,
    recv_c: Completion = undefined,
    send_c: Completion = undefined,
    close_c: Completion = undefined,

    fn start(origin: *TestOrigin) void {
        origin.io.accept(*TestOrigin, origin, on_accept, &origin.accept_c, origin.listener.fd);
    }
    fn on_accept(
        origin: *TestOrigin,
        _: *Completion,
        result: io_mod.AcceptError!posix.socket_t,
    ) void {
        origin.fd = result catch return;
        origin.arm_recv();
    }
    fn arm_recv(origin: *TestOrigin) void {
        origin.io.recv(
            *TestOrigin,
            origin,
            on_recv,
            &origin.recv_c,
            origin.fd,
            origin.request_buf[origin.request_len..],
        );
    }
    fn on_recv(origin: *TestOrigin, _: *Completion, result: io_mod.RecvError!usize) void {
        const n = result catch return;
        if (n == 0) return; // peer closed before completing the request
        origin.request_len += n;
        const unserved = origin.request_buf[origin.served_mark..origin.request_len];
        if (std.mem.indexOf(u8, unserved, origin.respond_after) == null) {
            return origin.arm_recv();
        }
        origin.sent = 0;
        origin.arm_send();
    }
    fn arm_send(origin: *TestOrigin) void {
        origin.io.send(
            *TestOrigin,
            origin,
            on_send,
            &origin.send_c,
            origin.fd,
            origin.response[origin.sent..],
        );
    }
    fn on_send(origin: *TestOrigin, _: *Completion, result: io_mod.SendError!usize) void {
        origin.sent += result catch return;
        if (origin.sent < origin.response.len) return origin.arm_send(); // finish a partial write
        origin.served_mark = origin.request_len;
        // Lingering keeps the connection open — and keeps reading, so a
        // pooled upstream connection can carry the next request.
        if (!origin.close_after_send) return origin.arm_recv();
        origin.io.close(*TestOrigin, origin, on_close, &origin.close_c, origin.fd);
        origin.fd = -1;
    }
    fn on_close(origin: *TestOrigin, _: *Completion, _: io_mod.CloseError!void) void {
        origin.start(); // serve the proxy's next upstream connection
    }
};

test "proxy: forwards a request to an upstream and relays the response" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    // Origin on an ephemeral port, on this same loop.
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    // Config routes everything to a cluster pointing at the origin.
    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    // Client connects to the proxy and drives its request on the same loop.
    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(
                *@This(),
                c,
                on_send,
                &c.send_c,
                c.fd,
                "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n",
            );
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]);

    // Let the proxy finish tearing the connection down and reclaim its slot.
    while (pool.free_count != pool.capacity) try io.run_once();

    // Every byte the proxy sent upstream (the spliced head — the client sent
    // no body) must be counted; the origin received exactly what was sent.
    try std.testing.expectEqual(
        @as(u64, origin.request_len),
        metrics.bytes_to_upstream.load(),
    );
    // Resilience accounting drains with the connection.
    try std.testing.expect(server.resilience.is_idle());
}

/// A TLS client on the test IO loop: a client-role `Channel` glued to a real
/// socket. Handshakes, sends one request, accumulates plaintext until EOF.
const TlsTestClient = struct {
    io: *IO,
    fd: posix.socket_t,
    channel: terminator.Channel,
    request: []const u8,
    request_written: bool = false,
    /// Stop after this much plaintext (0 = read until EOF).
    expected_total: usize = 0,
    /// Hold the first request this long after the handshake instead of
    /// writing it into the Finished flight — lets the server's kernel
    /// switchover decide on a quiet wire (0 = write immediately, which
    /// usually coalesces with Finished and forces the userspace fallback).
    request_delay_ns: u63 = 0,
    delay_armed: bool = false,
    delay_c: Completion = undefined,
    wire_in: [constants.tls_bio_pair_bytes]u8 = undefined,
    wire_out: [constants.tls_bio_pair_bytes]u8 = undefined,
    wire_out_filled: usize = 0,
    wire_out_sent: usize = 0,
    send_in_flight: bool = false,
    recv_in_flight: bool = false,
    plain_buf: [512]u8 = undefined,
    plain_len: usize = 0,
    /// The server sent close_notify before closing (polite TLS shutdown).
    saw_close_notify: bool = false,
    done: bool = false,
    send_c: Completion = undefined,
    recv_c: Completion = undefined,

    fn go(client: *TlsTestClient) void {
        _ = client.channel.handshake_step(); // emit the ClientHello
        client.progress();
    }

    fn write_request(client: *TlsTestClient) void {
        assert(!client.request_written);
        const written = client.channel.write_plaintext(client.request);
        std.testing.expectEqual(
            terminator.Channel.WriteResult{ .bytes = client.request.len },
            written,
        ) catch unreachable; // a short first write means a broken pair
        client.request_written = true;
    }

    fn on_request_delay(client: *TlsTestClient, _: *Completion, _: io_mod.TimeoutError!void) void {
        client.write_request();
        client.progress();
    }

    fn progress(client: *TlsTestClient) void {
        _ = client.channel.handshake_step();
        if (client.channel.handshake_done() and !client.request_written) {
            if (client.request_delay_ns > 0) {
                if (!client.delay_armed) {
                    client.delay_armed = true;
                    client.io.timeout(
                        *TlsTestClient,
                        client,
                        on_request_delay,
                        &client.delay_c,
                        client.request_delay_ns,
                    );
                }
            } else {
                client.write_request();
            }
        }
        // Drain every buffered record: no wire event will re-run this if
        // plaintext is left sitting in the channel.
        var budget: u32 = 16;
        while (client.request_written and budget > 0) : (budget -= 1) {
            switch (client.channel.read_plaintext(client.plain_buf[client.plain_len..])) {
                .bytes => |n| client.plain_len += n,
                .closed => {
                    client.saw_close_notify = true;
                    client.done = true;
                    break;
                },
                .want_io, .failed => break,
            }
        }
        if (client.expected_total > 0 and client.plain_len >= client.expected_total) {
            client.done = true;
        }
        client.flush_wire();
        client.arm_wire_recv();
    }

    fn flush_wire(client: *TlsTestClient) void {
        if (client.send_in_flight) return;
        if (client.wire_out_sent == client.wire_out_filled) {
            client.wire_out_filled = client.channel.drain_ciphertext(&client.wire_out);
            client.wire_out_sent = 0;
            if (client.wire_out_filled == 0) return;
        }
        client.send_in_flight = true;
        client.io.send(
            *TlsTestClient,
            client,
            on_send,
            &client.send_c,
            client.fd,
            client.wire_out[client.wire_out_sent..client.wire_out_filled],
        );
    }

    fn on_send(client: *TlsTestClient, _: *Completion, result: io_mod.SendError!usize) void {
        client.send_in_flight = false;
        const m = result catch return;
        client.wire_out_sent += m;
        client.progress();
    }

    fn arm_wire_recv(client: *TlsTestClient) void {
        if (client.recv_in_flight or client.done) return;
        client.recv_in_flight = true;
        client.io.recv(*TlsTestClient, client, on_recv, &client.recv_c, client.fd, &client.wire_in);
    }

    fn on_recv(client: *TlsTestClient, _: *Completion, result: io_mod.RecvError!usize) void {
        client.recv_in_flight = false;
        const n = result catch 0;
        if (n == 0) {
            client.done = true; // the proxy tore down after the response
            return;
        }
        const fed = client.channel.feed_ciphertext(client.wire_in[0..n]);
        std.testing.expectEqual(n, fed) catch unreachable; // an empty pair always fits a read
        client.progress();
    }
};

const install_proxy_test_hook = @import("../tls/openssl.zig").install_memory_hook_for_tests;

test "proxy: terminates TLS end to end — handshake, relay, heap drain" {
    const gpa = std.testing.allocator;
    const hook = @import("../tls/openssl.zig");
    install_proxy_test_hook();
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    const server_context = try terminator.Context.init_server(
        @embedFile("../tls/testdata/certificate.pem"),
        @embedFile("../tls/testdata/private_key.pem"),
    );
    defer server_context.deinit();
    const client_context = try terminator.Context.init_client(.insecure);
    defer client_context.deinit();

    var pool = try Pool.init(gpa, 4);
    var tls_legs = try TlsLegPool.init(gpa, 8);
    defer tls_legs.deinit(gpa);
    defer pool.deinit(gpa);
    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.tls_context = &server_context;
    server.tls_legs = &tls_legs;
    server.start();

    const proxy_port = proxy_listener.bound_address().port;
    // Exchange one is the warm-up: OpenSSL's first handshake lazily
    // allocates process-lifetime state (per-thread RNG, error strings).
    try run_tls_exchange(&io, &pool, proxy_port, &client_context, response);

    // Steady state: a whole TLS connection through the proxy must return
    // the hook heap to its baseline once the slot is reclaimed.
    const heap_before = hook.memory_hook_stats();
    try run_tls_exchange(&io, &pool, proxy_port, &client_context, response);
    try std.testing.expectEqual(heap_before.live_count, hook.memory_hook_stats().live_count);
    try std.testing.expectEqual(@as(u64, 0), hook.memory_hook_stats().rejection_count);

    try std.testing.expectEqual(@as(u64, 2), metrics.tls_handshakes.load());
    try std.testing.expectEqual(@as(u64, 0), metrics.tls_handshake_failures.load());
    // Every handshake takes exactly one switchover decision. This client
    // writes its request into the Finished flight, so whether the kernel or
    // the userspace relay serves it depends on TCP coalescing — both must
    // produce identical bytes (that is the fallback guarantee).
    try std.testing.expectEqual(
        @as(u64, 2),
        metrics.tls_ktls_active.load() + metrics.tls_ktls_fallbacks.load(),
    );
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: TLS keep-alive carries pipelined requests on one handshake" {
    const gpa = std.testing.allocator;
    install_proxy_test_hook();
    // No `Connection: close`: both hops stay reusable.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .close_after_send = false, // linger: the upstream pool reuses it
    };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    const server_context = try terminator.Context.init_server(
        @embedFile("../tls/testdata/certificate.pem"),
        @embedFile("../tls/testdata/private_key.pem"),
    );
    defer server_context.deinit();
    const client_context = try terminator.Context.init_client(.insecure);
    defer client_context.deinit();

    var pool = try Pool.init(gpa, 4);
    var tls_legs = try TlsLegPool.init(gpa, 8);
    defer tls_legs.deinit(gpa);
    defer pool.deinit(gpa);
    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.tls_context = &server_context;
    server.tls_legs = &tls_legs;
    server.start();

    // Two pipelined requests in one write: the second head is decrypted
    // before the proxy asks for it, exercising the buffered-plaintext
    // (yield) delivery path on the reused connection.
    const client_fd = try connect_loopback(proxy_listener.bound_address().port);
    var client = TlsTestClient{
        .io = &io,
        .fd = client_fd,
        .channel = try terminator.Channel.init(&client_context),
        .request = "GET /one HTTP/1.1\r\nHost: origin\r\n\r\n" ++
            "GET /two HTTP/1.1\r\nHost: origin\r\n\r\n",
        .expected_total = 2 * response.len,
    };
    defer client.channel.deinit();
    client.go();

    try io.run_until_done(&client.done);
    try std.testing.expectEqualStrings(response ++ response, client.plain_buf[0..client.plain_len]);
    try std.testing.expectEqual(@as(u64, 1), metrics.tls_handshakes.load()); // one connection
    try std.testing.expectEqual(@as(u64, 2), metrics.requests.load());
    try std.testing.expectEqual(
        @as(u64, 1), // one decision; which way depends on flight coalescing
        metrics.tls_ktls_active.load() + metrics.tls_ktls_fallbacks.load(),
    );

    // The client hangs up; the proxy sees TLS-layer EOF and reclaims.
    _ = linux.close(client_fd);
    while (pool.free_count != pool.capacity) try io.run_once();
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: hands the record layer to the kernel after a quiet handshake" {
    const gpa = std.testing.allocator;
    const hook = @import("../tls/openssl.zig");
    install_proxy_test_hook();
    if (!kernel_tls.test_environment_supports_kernel_tls()) return error.SkipZigTest;
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    const server_context = try terminator.Context.init_server(
        @embedFile("../tls/testdata/certificate.pem"),
        @embedFile("../tls/testdata/private_key.pem"),
    );
    defer server_context.deinit();
    const client_context = try terminator.Context.init_client(.insecure);
    defer client_context.deinit();

    var pool = try Pool.init(gpa, 4);
    var tls_legs = try TlsLegPool.init(gpa, 8);
    defer tls_legs.deinit(gpa);
    defer pool.deinit(gpa);
    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.tls_context = &server_context;
    server.tls_legs = &tls_legs;
    server.start();

    const heap_before = hook.memory_hook_stats();
    const client_fd = try connect_loopback(proxy_listener.bound_address().port);
    var client = TlsTestClient{
        .io = &io,
        .fd = client_fd,
        .channel = try terminator.Channel.init(&client_context),
        .request = "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n",
        // Past the Finished flight: the server decides on a quiet wire.
        .request_delay_ns = 20 * std.time.ns_per_ms,
    };
    client.go();

    try io.run_until_done(&client.done);
    try std.testing.expectEqualStrings(response, client.plain_buf[0..client.plain_len]);
    // The switch happened, and the polite close arrived as a *kernel-built*
    // alert record (close_downstream's cmsg path) the client decrypted.
    try std.testing.expectEqual(@as(u64, 1), metrics.tls_ktls_active.load());
    try std.testing.expectEqual(@as(u64, 0), metrics.tls_ktls_fallbacks.load());
    try std.testing.expect(client.saw_close_notify);

    // The channel was freed at the switchover, mid-connection; after slot
    // reclaim and the client channel's release, the heap is at baseline.
    _ = linux.close(client_fd);
    while (pool.free_count != pool.capacity) try io.run_once();
    client.channel.deinit();
    try std.testing.expectEqual(heap_before.live_count, hook.memory_hook_stats().live_count);
    try std.testing.expect(server.resilience.is_idle());
}

/// A TLS origin on the test IO loop: a server-role `Channel` glued to each
/// accepted socket. Reads plaintext until a full head arrives, replies with
/// the fixed response plus close_notify, closes, and accepts the next
/// connection (the U2 proxy dials a TLS origin fresh per request).
const TlsTestOrigin = struct {
    io: *IO,
    listener: Listener,
    context: *const terminator.Context,
    response: []const u8,
    /// False = keep-alive origin: serve request after request on one
    /// connection (the pooled-upstream tests need a lingering peer).
    close_after_send: bool = true,
    connections: u32 = 0,
    channel: terminator.Channel = undefined,
    channel_alive: bool = false,
    fd: posix.socket_t = -1,
    wire_in: [constants.tls_bio_pair_bytes]u8 = undefined,
    wire_out: [constants.tls_bio_pair_bytes]u8 = undefined,
    wire_out_filled: usize = 0,
    wire_out_sent: usize = 0,
    send_in_flight: bool = false,
    recv_in_flight: bool = false,
    request_buf: [1024]u8 = undefined,
    request_len: usize = 0,
    response_written: bool = false,
    served: u32 = 0,
    accept_c: Completion = undefined,
    recv_c: Completion = undefined,
    send_c: Completion = undefined,

    fn start(origin: *TlsTestOrigin) void {
        origin.io.accept(*TlsTestOrigin, origin, on_accept, &origin.accept_c, origin.listener.fd);
    }

    fn on_accept(
        origin: *TlsTestOrigin,
        _: *Completion,
        result: io_mod.AcceptError!posix.socket_t,
    ) void {
        origin.fd = result catch return;
        origin.channel = terminator.Channel.init(origin.context) catch unreachable;
        origin.channel_alive = true;
        origin.connections += 1;
        origin.request_len = 0;
        origin.response_written = false;
        origin.wire_out_filled = 0;
        origin.wire_out_sent = 0;
        origin.progress();
    }

    fn progress(origin: *TlsTestOrigin) void {
        if (!origin.channel_alive) return;
        _ = origin.channel.handshake_step();
        if (origin.channel.handshake_done() and !origin.response_written) {
            var budget: u32 = 16;
            while (budget > 0) : (budget -= 1) {
                switch (origin.channel.read_plaintext(origin.request_buf[origin.request_len..])) {
                    .bytes => |n| origin.request_len += n,
                    else => break,
                }
            }
            const request = origin.request_buf[0..origin.request_len];
            if (std.mem.indexOf(u8, request, "\r\n\r\n") != null) {
                switch (origin.channel.write_plaintext(origin.response)) {
                    .bytes => |n| assert(n == origin.response.len),
                    else => unreachable, // an empty pair takes a full response
                }
                if (origin.close_after_send) {
                    origin.channel.shutdown_notify(); // response, then polite EOF
                    origin.response_written = true;
                } else {
                    // Keep-alive: ready for the next request immediately.
                    origin.request_len = 0;
                }
                origin.served += 1;
            }
        }
        origin.flush_wire();
        origin.arm_wire_recv();
        const wire_idle = !origin.send_in_flight and
            origin.wire_out_sent == origin.wire_out_filled;
        if (origin.response_written and wire_idle and
            origin.channel.pending_ciphertext() == 0)
        {
            origin.close_connection();
        }
    }

    fn flush_wire(origin: *TlsTestOrigin) void {
        if (origin.send_in_flight or !origin.channel_alive) return;
        if (origin.wire_out_sent == origin.wire_out_filled) {
            origin.wire_out_filled = origin.channel.drain_ciphertext(&origin.wire_out);
            origin.wire_out_sent = 0;
            if (origin.wire_out_filled == 0) return;
        }
        origin.send_in_flight = true;
        origin.io.send(
            *TlsTestOrigin,
            origin,
            on_send,
            &origin.send_c,
            origin.fd,
            origin.wire_out[origin.wire_out_sent..origin.wire_out_filled],
        );
    }

    fn on_send(origin: *TlsTestOrigin, _: *Completion, result: io_mod.SendError!usize) void {
        origin.send_in_flight = false;
        const m = result catch return origin.close_connection();
        origin.wire_out_sent += m;
        origin.progress();
    }

    fn arm_wire_recv(origin: *TlsTestOrigin) void {
        if (origin.recv_in_flight or !origin.channel_alive) return;
        if (origin.response_written) return; // nothing more expected
        origin.recv_in_flight = true;
        origin.io.recv(*TlsTestOrigin, origin, on_recv, &origin.recv_c, origin.fd, &origin.wire_in);
    }

    fn on_recv(origin: *TlsTestOrigin, _: *Completion, result: io_mod.RecvError!usize) void {
        origin.recv_in_flight = false;
        if (!origin.channel_alive) return; // connection already closed
        const n = result catch return origin.close_connection();
        if (n == 0) return origin.close_connection();
        const fed = origin.channel.feed_ciphertext(origin.wire_in[0..n]);
        assert(fed == n); // the pair always has room for one read
        origin.progress();
    }

    fn close_connection(origin: *TlsTestOrigin) void {
        if (origin.channel_alive) {
            origin.channel.deinit();
            origin.channel_alive = false;
        }
        if (origin.fd >= 0) {
            _ = linux.shutdown(origin.fd, linux.SHUT.RDWR);
            _ = linux.close(origin.fd);
            origin.fd = -1;
        }
        origin.start(); // serve the proxy's next connection
    }
};

test "proxy: re-encrypts to a verified TLS origin" {
    const gpa = std.testing.allocator;
    install_proxy_test_hook();
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    // The origin presents the fixture identity (CN=zoxy.test)...
    const origin_context = try terminator.Context.init_server(
        @embedFile("../tls/testdata/certificate.pem"),
        @embedFile("../tls/testdata/private_key.pem"),
    );
    defer origin_context.deinit();
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TlsTestOrigin{
        .io = &io,
        .listener = origin_listener,
        .context = &origin_context,
        .response = response,
    };
    origin.start();

    // ...and the proxy's upstream context demands exactly that identity.
    const upstream_context = try terminator.Context.init_client(.{ .authority = .{
        .bundle_pem = @embedFile("../tls/testdata/certificate.pem"),
        .host = "zoxy.test",
    } });
    defer upstream_context.deinit();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    var tls_legs = try TlsLegPool.init(gpa, 8);
    defer tls_legs.deinit(gpa);
    defer pool.deinit(gpa);
    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    const upstream_contexts = [_]?*const terminator.Context{&upstream_context};
    server.upstream_tls_contexts = &upstream_contexts;
    server.tls_legs = &tls_legs;
    server.start();

    // A plaintext client: only the upstream hop is encrypted.
    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);
    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: origin\r\nConnection: close\r\n\r\n");
            c.arm_recv();
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) {
                c.done = true;
                return;
            }
            c.len += n;
            c.arm_recv();
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]);
    try std.testing.expectEqual(@as(u32, 1), origin.served);
    try std.testing.expectEqual(@as(u64, 1), metrics.tls_handshakes.load()); // the upstream hop
    try std.testing.expectEqual(@as(u64, 0), metrics.tls_handshake_failures.load());
    while (pool.free_count != pool.capacity) try io.run_once();
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: pools and resumes a TLS upstream — one handshake, two requests" {
    const gpa = std.testing.allocator;
    install_proxy_test_hook();
    // Keep-alive on both hops: no Connection header from the origin.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    var io = try IO.init(64, 0);
    defer io.deinit();

    const origin_context = try terminator.Context.init_server(
        @embedFile("../tls/testdata/certificate.pem"),
        @embedFile("../tls/testdata/private_key.pem"),
    );
    defer origin_context.deinit();
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TlsTestOrigin{
        .io = &io,
        .listener = origin_listener,
        .context = &origin_context,
        .response = response,
        .close_after_send = false, // linger: the pool can reuse it
    };
    origin.start();

    const upstream_context = try terminator.Context.init_client(.{ .authority = .{
        .bundle_pem = @embedFile("../tls/testdata/certificate.pem"),
        .host = "zoxy.test",
    } });
    defer upstream_context.deinit();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    var tls_legs = try TlsLegPool.init(gpa, 8);
    defer tls_legs.deinit(gpa);
    defer pool.deinit(gpa);
    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    const upstream_contexts = [_]?*const terminator.Context{&upstream_context};
    server.upstream_tls_contexts = &upstream_contexts;
    server.tls_legs = &tls_legs;
    server.start();

    // Two pipelined requests on one downstream connection: request two must
    // ride the parked TLS upstream, not a second handshake.
    const client = try connect_loopback(proxy_listener.bound_address().port);
    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        expected_total: usize,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET /one HTTP/1.1\r\n" ++
                "Host: origin\r\n\r\n" ++ "GET /two HTTP/1.1\r\nHost: origin\r\n\r\n");
            c.arm_recv();
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) {
                c.done = true;
                return;
            }
            c.len += n;
            if (c.len >= c.expected_total) {
                c.done = true;
                return;
            }
            c.arm_recv();
        }
    };
    var c = Client{ .io = &io, .fd = client, .expected_total = 2 * response.len };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expectEqualStrings(response ++ response, c.buf[0..c.len]);
    try std.testing.expectEqual(@as(u32, 2), origin.served);
    try std.testing.expectEqual(@as(u32, 1), origin.connections); // one TLS session
    try std.testing.expectEqual(@as(u64, 1), metrics.tls_handshakes.load());
    try std.testing.expectEqual(@as(u64, 1), metrics.upstream_reused.load());

    // The client hangs up; the parked channel drains with the pool.
    _ = linux.close(client);
    while (pool.free_count != pool.capacity) try io.run_once();
    try std.testing.expectEqual(@as(u32, 1), server.upstream_pool.count); // parked again
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: a wrong upstream authority fails the attempt with a 502" {
    const gpa = std.testing.allocator;
    install_proxy_test_hook();

    var io = try IO.init(64, 0);
    defer io.deinit();

    const origin_context = try terminator.Context.init_server(
        @embedFile("../tls/testdata/certificate.pem"),
        @embedFile("../tls/testdata/private_key.pem"),
    );
    defer origin_context.deinit();
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TlsTestOrigin{
        .io = &io,
        .listener = origin_listener,
        .context = &origin_context,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    };
    origin.start();

    // The proxy trusts a different authority: the handshake must fail and
    // the client must get an honest 502, not a hang or a teardown.
    const upstream_context = try terminator.Context.init_client(.{ .authority = .{
        .bundle_pem = @embedFile("../tls/testdata/other_certificate.pem"),
        .host = "zoxy.test",
    } });
    defer upstream_context.deinit();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    var tls_legs = try TlsLegPool.init(gpa, 8);
    defer tls_legs.deinit(gpa);
    defer pool.deinit(gpa);
    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    const upstream_contexts = [_]?*const terminator.Context{&upstream_context};
    server.upstream_tls_contexts = &upstream_contexts;
    server.tls_legs = &tls_legs;
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);
    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: origin\r\nConnection: close\r\n\r\n");
            c.arm_recv();
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) {
                c.done = true;
                return;
            }
            c.len += n;
            c.arm_recv();
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expect(std.mem.startsWith(u8, c.buf[0..c.len], "HTTP/1.1 502 "));
    try std.testing.expectEqual(@as(u32, 0), origin.served); // nothing reached it
    try std.testing.expect(metrics.tls_handshake_failures.load() >= 1);
    while (pool.free_count != pool.capacity) try io.run_once();
    try std.testing.expect(server.resilience.is_idle());
}

/// One full TLS request/response through the proxy on the shared loop; waits
/// for the proxy to reclaim the connection slot (which frees its channel).
fn run_tls_exchange(
    io: *IO,
    pool: *Pool,
    proxy_port: u16,
    client_context: *const terminator.Context,
    expected_response: []const u8,
) !void {
    const client_fd = try connect_loopback(proxy_port);
    defer _ = linux.close(client_fd);
    var client = TlsTestClient{
        .io = io,
        .fd = client_fd,
        .channel = try terminator.Channel.init(client_context),
        .request = "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n",
    };
    defer client.channel.deinit();
    client.go();

    try io.run_until_done(&client.done);
    try std.testing.expectEqualStrings(expected_response, client.plain_buf[0..client.plain_len]);
    // A server-initiated close (Connection: close exchange) must be polite:
    // close_notify before FIN, so a strict client sees clean EOF.
    try std.testing.expect(client.saw_close_notify);
    while (pool.free_count != pool.capacity) try io.run_once();
}

test "proxy: a response the proxy will close after announces Connection: close" {
    const gpa = std.testing.allocator;
    // The origin's response implies keep-alive (no Connection header); the
    // client asks for close — the relayed head must announce the close the
    // proxy is about to perform.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .close_after_send = false, // origin keeps alive; the close is ours
    };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);
    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);
    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: origin\r\nConnection: close\r\n\r\n");
            c.arm_recv();
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) { // EOF: the proxy closed, as announced
                c.done = true;
                return;
            }
            c.len += n;
            c.arm_recv();
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    const received = c.buf[0..c.len];
    try std.testing.expect(std.mem.indexOf(u8, received, "Connection: close\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, received, "\r\n\r\nHELLO"));
    while (pool.free_count != pool.capacity) try io.run_once();
}

test "proxy: strips hop-by-hop headers from the forwarded request" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    // `Connection` names "x-hop", making X-Hop hop-by-hop as well; the whole
    // connection-management block must vanish (nothing is injected: an
    // HTTP/1.1 upstream defaults to keep-alive, which the pool wants).
    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: o\r\n" ++
                "Connection: close, x-hop\r\n" ++
                "X-Hop: secret\r\n" ++
                "Keep-Alive: timeout=5\r\n" ++
                "Accept: */*\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]);
    while (pool.free_count != pool.capacity) try io.run_once();

    const forwarded = origin.request_buf[0..origin.request_len];
    try std.testing.expect(std.mem.startsWith(u8, forwarded, "GET / HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Host: o\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Accept: */*\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, forwarded, "\r\n\r\n"));
    try std.testing.expect(std.ascii.indexOfIgnoreCase(forwarded, "connection") == null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(forwarded, "keep-alive") == null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(forwarded, "x-hop") == null);
}

test "proxy: refuses an Upgrade request with 501 instead of tunneling it" {
    const gpa = std.testing.allocator;
    var io = try IO.init(16, 0);
    defer io.deinit();

    // The endpoint is never contacted; the refusal happens before routing.
    var cfg = try config.parse(gpa,
        \\{ "listen": "0.0.0.0:0", "routes": [{ "cluster": "o" }],
        \\  "clusters": [{ "name": "o", "endpoints": ["127.0.0.1:9"] }] }
    );
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 2);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET /ws HTTP/1.1\r\n" ++
                "Host: o\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expect(std.mem.startsWith(u8, c.buf[0..c.len], "HTTP/1.1 501 "));
    while (pool.free_count != pool.capacity) try io.run_once();
}

test "proxy: completes promptly when a lingering upstream sends a framed response" {
    const gpa = std.testing.allocator;
    // Content-Length framing, and the origin never closes: before framed
    // relay, this connection was pinned until the 30s deadline.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .close_after_send = false,
    };
    origin.start();
    defer if (origin.fd >= 0) {
        _ = linux.close(origin.fd);
    };

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: o\r\nConnection: close\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    const started_ns = monotonic_nanos();
    try io.run_until_done(&c.done);
    // The origin's head implied keep-alive; the proxy closes after this
    // response, so the relayed head announces it (RFC 9112 §9.6).
    const expected = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";
    try std.testing.expectEqualStrings(expected, c.buf[0..c.len]);
    while (pool.free_count != pool.capacity) try io.run_once();
    // Well under the 30s deadline: the framer ended the response, not a timer.
    try std.testing.expect(monotonic_nanos() - started_ns < 5 * std.time.ns_per_s);
}

test "proxy: relays a chunked response and ends it at the terminal chunk" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "5\r\nHELLO\r\n6\r\nWORLD!\r\n0\r\n\r\n";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    // The origin lingers: only chunked end-detection can finish this request.
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .close_after_send = false,
    };
    origin.start();
    defer if (origin.fd >= 0) {
        _ = linux.close(origin.fd);
    };

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        total: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.arm_recv();
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: o\r\nConnection: close\r\n\r\n");
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.total..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) { // EOF: the proxy closed after the terminal chunk
                c.done = true;
                return;
            }
            c.total += n;
            c.arm_recv();
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    // Keep-alive origin + closing client: the relayed head announces our close.
    const expected = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" ++
        "5\r\nHELLO\r\n6\r\nWORLD!\r\n0\r\n\r\n";
    try std.testing.expectEqualStrings(expected, c.buf[0..c.total]);
    while (pool.free_count != pool.capacity) try io.run_once();
}

test "proxy: serves pipelined requests sequentially, each routed on its own" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok";
    // What the client sees: the hop-by-hop Connection header is stripped
    // (the forced upstream close must not leak to a keep-alive client).
    const client_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        expected_total: usize,
        buf: [512]u8 = undefined,
        total: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.arm_recv();
            // Two requests in one write. The second must reach the origin
            // only after the first response completes — and on a *fresh*
            // upstream connection, freshly routed.
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n" ++
                "GET /second HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.total..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) {
                c.done = true;
                return;
            }
            c.total += n;
            if (c.total >= c.expected_total) {
                c.done = true;
                return;
            }
            c.arm_recv();
        }
    };
    var c = Client{ .io = &io, .fd = client, .expected_total = client_response.len * 2 };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expectEqualStrings(client_response ++ client_response, c.buf[0..c.total]);

    const forwarded = origin.request_buf[0..origin.request_len];
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, forwarded, "GET "));
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "GET /second ") != null);

    // The downstream connection is still open (keep-alive); closing it
    // releases the slot.
    _ = linux.close(client);
    while (pool.free_count != pool.capacity) try io.run_once();
}

test "proxy: reuses the downstream connection for sequential keep-alive requests" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\nHELLO";
    const client_response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);

    // Two requests, the second sent only after the first response arrives —
    // on the same downstream socket, without reconnecting.
    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        expected: []const u8,
        buf: [512]u8 = undefined,
        len: usize = 0,
        responses: u32 = 0,
        matched: bool = true,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.arm_recv();
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET /one HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) {
                c.done = true;
                return;
            }
            c.len += n;
            if (c.len < c.expected.len) return c.arm_recv(); // response still partial
            c.matched = c.matched and std.mem.eql(u8, c.expected, c.buf[0..c.len]);
            c.responses += 1;
            c.len = 0;
            if (c.responses == 2) {
                c.done = true;
                return;
            }
            c.arm_recv();
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET /two HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
    };
    var c = Client{ .io = &io, .fd = client, .expected = client_response };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expect(c.matched);
    try std.testing.expectEqual(@as(u32, 2), c.responses);
    try std.testing.expectEqual(@as(u64, 2), metrics.requests.load());
    // One downstream connection carried both requests...
    try std.testing.expectEqual(@as(u64, 1), metrics.accepted.load());
    // ...and each went to the origin on its own upstream connection.
    const forwarded = origin.request_buf[0..origin.request_len];
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "GET /one ") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "GET /two ") != null);

    _ = linux.close(client);
    while (pool.free_count != pool.capacity) try io.run_once();
}

test "proxy: reuses a pooled upstream connection for the next request" {
    const gpa = std.testing.allocator;
    // No `Connection: close`, so the upstream connection is poolable; the
    // origin lingers and keeps reading — request /two must arrive on the
    // very same connection, without a second accept.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .close_after_send = false,
    };
    origin.start();
    defer if (origin.fd >= 0) {
        _ = linux.close(origin.fd);
    };

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        expected: []const u8,
        buf: [512]u8 = undefined,
        len: usize = 0,
        responses: u32 = 0,
        matched: bool = true,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.arm_recv();
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET /one HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) {
                c.done = true;
                return;
            }
            c.len += n;
            if (c.len < c.expected.len) return c.arm_recv();
            c.matched = c.matched and std.mem.eql(u8, c.expected, c.buf[0..c.len]);
            c.responses += 1;
            c.len = 0;
            if (c.responses == 2) {
                c.done = true;
                return;
            }
            c.arm_recv();
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET /two HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
    };
    var c = Client{ .io = &io, .fd = client, .expected = response };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expect(c.matched);
    try std.testing.expectEqual(@as(u32, 2), c.responses);
    // The second request rode the pooled connection...
    try std.testing.expectEqual(@as(u64, 1), metrics.upstream_reused.load());
    // ...which the origin observes as both requests on one accept.
    const forwarded = origin.request_buf[0..origin.request_len];
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "GET /one ") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "GET /two ") != null);

    _ = linux.close(client);
    while (pool.free_count != pool.capacity) try io.run_once();
}

test "proxy: retries a stale pooled upstream on a fresh connection" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .close_after_send = false,
    };
    origin.start();
    defer if (origin.fd >= 0) {
        _ = linux.close(origin.fd);
    };

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        expected: []const u8,
        buf: [512]u8 = undefined,
        len: usize = 0,
        responses: u32 = 0,
        matched: bool = true,
        got_first: bool = false,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.arm_recv();
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET /one HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn send_second(c: *@This()) void {
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET /two HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) {
                c.done = true;
                return;
            }
            c.len += n;
            if (c.len < c.expected.len) return c.arm_recv();
            c.matched = c.matched and std.mem.eql(u8, c.expected, c.buf[0..c.len]);
            c.responses += 1;
            c.len = 0;
            if (c.responses == 1) {
                c.got_first = true;
                return c.arm_recv();
            }
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client, .expected = response };
    c.go();

    try io.run_until_done(&c.got_first);
    // The upstream closes the connection while it idles in the pool —
    // exactly what a server-side keep-alive timeout does.
    _ = linux.shutdown(origin.fd, linux.SHUT.RDWR);
    _ = linux.close(origin.fd);
    origin.fd = -1;
    origin.start(); // ready to accept the retry's fresh dial

    c.send_second();
    try io.run_until_done(&c.done);
    try std.testing.expect(c.matched);
    try std.testing.expectEqual(@as(u32, 2), c.responses);
    // The stale connection was checked out, failed, and was replaced.
    try std.testing.expectEqual(@as(u64, 1), metrics.upstream_reused.load());
    try std.testing.expectEqual(@as(u64, 1), metrics.upstream_retried.load());
    try std.testing.expectEqual(@as(u64, 0), metrics.upstream_errors.load());

    _ = linux.close(client);
    while (pool.free_count != pool.capacity) try io.run_once();
    // The replay opened a second attempt on the same endpoint; both attempts
    // and the request itself must be settled.
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: does not reuse the connection for an HTTP/1.0 client" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        total: usize = 0,
        eof: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.arm_recv();
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.0\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.total..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) { // the proxy must close on us: 1.0 never reuses
                c.eof = true;
                return;
            }
            c.total += n;
            c.arm_recv();
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.eof);
    // No reuse means no stripping either: the head passes through verbatim.
    try std.testing.expectEqualStrings(response, c.buf[0..c.total]);
    while (pool.free_count != pool.capacity) try io.run_once();
}

test "proxy: streams a framed request body to the upstream" {
    const gpa = std.testing.allocator;
    const body = "0123456789";
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    // The origin only answers once the whole body has arrived.
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .respond_after = body,
    };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        body: []const u8,
        body_sent: bool = false,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            // Head first; the body follows in a separate send so it travels
            // through the request_pipe relay pipe, not just the prime.
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "POST / HTTP/1.1\r\n" ++
                "Host: o\r\nConnection: close\r\nContent-Length: 10\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            if (c.body_sent) return;
            c.body_sent = true;
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, c.body);
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client, .body = body };
    c.go();

    try io.run_until_done(&c.done);
    // Keep-alive origin + closing client: the relayed head announces our close.
    const expected = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    try std.testing.expectEqualStrings(expected, c.buf[0..c.len]);
    while (pool.free_count != pool.capacity) try io.run_once();

    const forwarded = origin.request_buf[0..origin.request_len];
    try std.testing.expect(std.mem.endsWith(u8, forwarded, body));
}

test "proxy: answers 502 when the upstream response is unparseable" {
    const gpa = std.testing.allocator;

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = "NOT-HTTP-AT-ALL\r\n\r\n",
    };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expect(std.mem.startsWith(u8, c.buf[0..c.len], "HTTP/1.1 502 "));
    while (pool.free_count != pool.capacity) try io.run_once();
    // The failed attempt (an upstream fault, mid-flight) must be settled.
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: circuit breaker rejects a request beyond max_requests with 503" {
    const gpa = std.testing.allocator;

    var io = try IO.init(64, 0);
    defer io.deinit();

    // The origin never answers (the needle never arrives), so the first
    // request stays in flight and holds requests_active at 1.
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        .respond_after = "NEVER-SENT",
    };
    origin.start();

    var json_buf: [384]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"],
        \\     "circuit_breaker": {{ "max_requests": 1 }} }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    const short_timeout: u63 = 250 * std.time.ns_per_ms; // reclaims the held request
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        short_timeout,
        short_timeout,
    );
    defer server.deinit();
    server.start();

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [256]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };

    // First request is admitted and parks in flight at the silent origin.
    const first_fd = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(first_fd);
    var first = Client{ .io = &io, .fd = first_fd };
    first.go();
    while (server.resilience.clusters[0].requests_active != 1) try io.run_once();

    // The second trips the breaker: rejected at admission, before any dial.
    const second_fd = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(second_fd);
    var second = Client{ .io = &io, .fd = second_fd };
    second.go();
    try io.run_until_done(&second.done);
    try std.testing.expect(std.mem.startsWith(u8, second.buf[0..second.len], "HTTP/1.1 503 "));
    try std.testing.expectEqual(@as(u64, 1), metrics.breaker_requests_rejected.load());
    try std.testing.expectEqual(@as(u64, 0), metrics.breaker_dials_rejected.load());

    // The deadline reclaims the held request; every counter drains.
    while (pool.free_count != pool.capacity) try io.run_once();
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: circuit breaker rejects a dial beyond max_connections with 503" {
    const gpa = std.testing.allocator;

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        .respond_after = "NEVER-SENT",
    };
    origin.start();

    var json_buf: [384]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"],
        \\     "circuit_breaker": {{ "max_connections": 1 }} }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    const short_timeout: u63 = 250 * std.time.ns_per_ms;
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        short_timeout,
        short_timeout,
    );
    defer server.deinit();
    server.start();

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [256]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };

    // The first request holds its upstream connection (connections_active = 1).
    const first_fd = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(first_fd);
    var first = Client{ .io = &io, .fd = first_fd };
    first.go();
    while (server.resilience.clusters[0].connections_active != 1) try io.run_once();

    // The second is admitted (no max_requests) but its dial is rejected.
    const second_fd = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(second_fd);
    var second = Client{ .io = &io, .fd = second_fd };
    second.go();
    try io.run_until_done(&second.done);
    try std.testing.expect(std.mem.startsWith(u8, second.buf[0..second.len], "HTTP/1.1 503 "));
    try std.testing.expectEqual(@as(u64, 1), metrics.breaker_dials_rejected.load());
    try std.testing.expectEqual(@as(u64, 0), metrics.breaker_requests_rejected.load());

    while (pool.free_count != pool.capacity) try io.run_once();
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: a configured retry survives an upstream that dies once" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    // An origin that kills its first connection on accept (EOF before any
    // response byte — a crash-looping backend), then serves normally.
    const FlakyOrigin = struct {
        io: *IO,
        listener: Listener,
        response: []const u8,
        failures_left: u32,
        fd: posix.socket_t = -1,
        request_buf: [1024]u8 = undefined,
        request_len: usize = 0,
        sent: usize = 0,
        accept_c: Completion = undefined,
        recv_c: Completion = undefined,
        send_c: Completion = undefined,
        fn start(origin: *@This()) void {
            origin.io.accept(*@This(), origin, on_accept, &origin.accept_c, origin.listener.fd);
        }
        fn on_accept(
            origin: *@This(),
            _: *Completion,
            result: io_mod.AcceptError!posix.socket_t,
        ) void {
            const fd = result catch return;
            if (origin.failures_left > 0) {
                origin.failures_left -= 1;
                origin.io.shutdown_socket(fd);
                origin.io.close_now(fd);
                return origin.start(); // die on this one, serve the next
            }
            origin.fd = fd;
            origin.arm_recv();
        }
        fn arm_recv(origin: *@This()) void {
            origin.io.recv(
                *@This(),
                origin,
                on_recv,
                &origin.recv_c,
                origin.fd,
                origin.request_buf[origin.request_len..],
            );
        }
        fn on_recv(origin: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch return;
            if (n == 0) return;
            origin.request_len += n;
            const seen = origin.request_buf[0..origin.request_len];
            if (std.mem.indexOf(u8, seen, "\r\n\r\n") == null) return origin.arm_recv();
            origin.arm_send();
        }
        fn arm_send(origin: *@This()) void {
            origin.io.send(
                *@This(),
                origin,
                on_send,
                &origin.send_c,
                origin.fd,
                origin.response[origin.sent..],
            );
        }
        fn on_send(origin: *@This(), _: *Completion, result: io_mod.SendError!usize) void {
            origin.sent += result catch return;
            if (origin.sent < origin.response.len) return origin.arm_send();
        }
    };

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = FlakyOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .failures_left = 1,
    };
    origin.start();

    var json_buf: [384]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"],
        \\     "retry": {{ "max": 2, "backoff_base_ms": 1, "backoff_cap_ms": 10 }} }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [256]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    // The client sees the retried attempt's clean 200 — never the failure.
    // (The hop-by-hop `Connection: close` is stripped for a keep-alive client.)
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO",
        c.buf[0..c.len],
    );
    try std.testing.expectEqual(@as(u64, 1), metrics.retry_attempts.load());
    // Tier 1 (stale-pool) was not involved: the first dial was fresh.
    try std.testing.expectEqual(@as(u64, 0), metrics.upstream_retried.load());

    // Close the keep-alive client so the drain below is not an idle-timeout wait.
    _ = linux.close(client);
    while (pool.free_count != pool.capacity) try io.run_once();
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: outlier detection ejects a dead endpoint and traffic routes around it" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    // A dead endpoint: a port that had a listener (so nothing else claims
    // it) and does not anymore — connects are refused instantly.
    var dead_listener = try Listener.open(Ip4Address.loopback(0), 8);
    const dead_port = dead_listener.bound_address().port;
    dead_listener.close();

    // One failure ejects (threshold 1); a retry covers the request that
    // draws the dead endpoint first.
    var json_buf: [512]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o",
        \\     "endpoints": ["127.0.0.1:{d}", "127.0.0.1:{d}"],
        \\     "retry": {{ "max": 2, "backoff_base_ms": 1, "backoff_cap_ms": 10 }},
        \\     "outlier": {{ "consecutive_failures": 1, "ejection_ms": 60000 }} }}] }}
    , .{ origin_listener.bound_address().port, dead_port });
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [256]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };

    // Every sequential request succeeds: a draw of the dead endpoint fails
    // fast (refused), ejects it, and the retry lands on the live one.
    var successes: u32 = 0;
    for (0..6) |_| {
        const fd = try connect_loopback(proxy_listener.bound_address().port);
        var c = Client{ .io = &io, .fd = fd };
        c.go();
        try io.run_until_done(&c.done);
        try std.testing.expect(std.mem.startsWith(u8, c.buf[0..c.len], "HTTP/1.1 200 "));
        successes += 1;
        _ = linux.close(fd);
        while (pool.free_count != pool.capacity) try io.run_once();
    }
    try std.testing.expectEqual(@as(u32, 6), successes);
    // The dead endpoint was drawn at least once and ejected exactly once
    // (its 60s ejection outlives the test, so it never returns).
    try std.testing.expectEqual(@as(u64, 1), metrics.outlier_ejections.load());
    try std.testing.expect(metrics.retry_attempts.load() >= 1);
    try std.testing.expect(server.resilience.is_idle());
    try std.testing.expectEqual(@as(u32, 1), server.resilience.clusters[0].ejected_count);
}

test "proxy: per-try timeout answers 504 while the overall deadline still runs" {
    const gpa = std.testing.allocator;

    var io = try IO.init(64, 0);
    defer io.deinit();

    // The origin accepts and reads but never responds (the needle never
    // arrives) — a wedged upstream, the per-try timeout's reason to exist.
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        .respond_after = "NEVER-SENT",
    };
    origin.start();

    // per-try (1s, the validation floor) well under the overall deadline
    // (10s): the client must get a 504, not a silent 10s teardown.
    var json_buf: [384]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"],
        \\     "per_try_timeout_ms": 1000 }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        10 * std.time.ns_per_s,
        10 * std.time.ns_per_s,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);
    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [256]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expect(std.mem.startsWith(u8, c.buf[0..c.len], "HTTP/1.1 504 "));
    try std.testing.expectEqual(@as(u64, 1), metrics.per_try_timeouts.load());

    while (pool.free_count != pool.capacity) try io.run_once();
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: relays a response larger than the relay buffer with bounded memory" {
    const gpa = std.testing.allocator;
    // A body several times the relay buffer forces many recv->send cycles; the
    // proxy still holds at most `relay_buf_bytes` per direction throughout.
    const body_len = constants.relay_buf_bytes * 4 + 123;
    const header = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    const response = try gpa.alloc(u8, header.len + body_len);
    defer gpa.free(response);
    @memcpy(response[0..header.len], header);
    for (response[header.len..], 0..) |*b, i| b.* = @truncate(i);

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [4096]u8 = undefined,
        total: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.arm_recv();
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) { // EOF: the whole response has been relayed
                c.done = true;
                return;
            }
            c.total += n;
            c.arm_recv();
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expectEqual(response.len, c.total);
    while (pool.free_count != pool.capacity) try io.run_once();
}

test "proxy: a stalled connection is reclaimed by the deadline" {
    const gpa = std.testing.allocator;
    var io = try IO.init(16, 0);
    defer io.deinit();

    var cfg = try config.parse(gpa,
        \\{ "listen": "0.0.0.0:0", "routes": [{ "cluster": "o" }],
        \\  "clusters": [{ "name": "o", "endpoints": ["127.0.0.1:9"] }] }
    );
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 2);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    const short_timeout: u63 = 50 * std.time.ns_per_ms;
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        short_timeout,
        short_timeout,
    );
    defer server.deinit();
    server.start();

    // Slow-loris: connect, send a partial head, then never finish it.
    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);
    const partial = "GET / HTTP/1.1\r\n"; // no terminating blank line
    _ = linux.write(client, partial, partial.len);

    // The slot is taken once the proxy accepts...
    while (pool.free_count == pool.capacity) try io.run_once();
    try std.testing.expectEqual(pool.capacity - 1, pool.free_count);
    // ...and the deadline must reclaim it; without the timer this would hang.
    while (pool.free_count != pool.capacity) try io.run_once();
    // Teardown before routing: nothing was ever counted, nothing leaks.
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: an idle keep-alive connection is reclaimed by the idle timeout" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .close_after_send = false,
    };
    origin.start();
    defer if (origin.fd >= 0) {
        _ = linux.close(origin.fd);
    };

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    // Idle enforcement lags by at most the in-flight timer, which is bounded
    // by the request timeout here — keep both short so the test is fast.
    const request_timeout: u63 = 300 * std.time.ns_per_ms;
    const idle_timeout: u63 = 100 * std.time.ns_per_ms;
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        request_timeout,
        idle_timeout,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    // One complete keep-alive exchange; then the client goes silent.
    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        expected: []const u8,
        buf: [512]u8 = undefined,
        len: usize = 0,
        got_response: bool = false,
        eof: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.arm_recv();
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn arm_recv(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) { // the idle deadline closed us
                c.eof = true;
                return;
            }
            c.len += n;
            if (c.len >= c.expected.len) c.got_response = true;
            c.arm_recv();
        }
    };
    var c = Client{ .io = &io, .fd = client, .expected = response };
    c.go();

    const started_ns = monotonic_nanos();
    try io.run_until_done(&c.eof);
    try std.testing.expect(c.got_response);
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]);
    while (pool.free_count != pool.capacity) try io.run_once();
    // Reclaimed by the idle deadline (~100-400ms), not the old 30s whole-life
    // deadline and not the request timeout alone.
    try std.testing.expect(monotonic_nanos() - started_ns < 2 * std.time.ns_per_s);
}

/// A keep-alive test client: sends one request, accumulates response bytes,
/// records the EOF the drain's close delivers.
const DrainTestClient = struct {
    io: *IO,
    fd: posix.socket_t,
    request: []const u8,
    buf: [512]u8 = undefined,
    len: usize = 0,
    eof: bool = false,
    send_c: Completion = undefined,
    recv_c: Completion = undefined,

    fn go(c: *DrainTestClient) void {
        c.arm_recv();
        c.io.send(*DrainTestClient, c, on_send, &c.send_c, c.fd, c.request);
    }
    fn arm_recv(c: *DrainTestClient) void {
        c.io.recv(*DrainTestClient, c, on_recv, &c.recv_c, c.fd, c.buf[c.len..]);
    }
    fn on_send(c: *DrainTestClient, _: *Completion, _: io_mod.SendError!usize) void {
        _ = c;
    }
    fn on_recv(c: *DrainTestClient, _: *Completion, result: io_mod.RecvError!usize) void {
        const n = result catch 0;
        if (n == 0) {
            c.eof = true;
            return;
        }
        c.len += n;
        c.arm_recv();
    }
};

/// True while the pool holds no live connection that is idle between
/// requests — pump until this flips to observe the sweep's idle-close path.
fn no_idle_connection(pool: *Pool) bool {
    for (pool.items) |*conn| {
        if (conn.in_use and !conn.request_active and !conn.closing) return false;
    }
    return true;
}

fn expect_connect_refused(port: u16) !void {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    try std.testing.expect(linux.errno(rc) == .SUCCESS);
    const fd: posix.socket_t = @intCast(rc);
    defer _ = linux.close(fd);
    const sa = sockaddr_in(Ip4Address.loopback(port));
    const connect_rc = linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
    try std.testing.expect(linux.errno(connect_rc) == .CONNREFUSED);
}

test "proxy: drain closes an idle keep-alive connection and refuses new connects" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .close_after_send = false, // keep-alive on both hops
    };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    // No defer close: the drain path closes the listener exactly once.
    const proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    const proxy_port = proxy_listener.bound_address().port;
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_port);
    defer _ = linux.close(client);
    var c = DrainTestClient{
        .io = &io,
        .fd = client,
        .request = "GET / HTTP/1.1\r\nHost: o\r\n\r\n", // keep-alive
    };
    c.go();

    // Let the exchange finish so the connection is idle between requests.
    while (no_idle_connection(&pool)) try io.run_once();
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]);
    try std.testing.expect(!c.eof); // keep-alive: the proxy is holding it open

    server.begin_drain();
    // The sweep closes the idle connection; the client sees a clean EOF.
    while (!c.eof) try io.run_once();
    while (!server.drain_complete()) try io.run_once();
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]); // nothing extra
    try std.testing.expectEqual(@as(u64, 1), metrics.draining.load());
    try std.testing.expectEqual(@as(u64, 0), metrics.drain_forced_closes.load());
    try std.testing.expect(server.resilience.is_idle());

    // The listener closed with the accept loop: connects are refused now.
    try expect_connect_refused(proxy_port);
}

test "proxy: drain during a request completes it with Connection: close injected" {
    const gpa = std.testing.allocator;
    // The origin's response is keep-alive shaped: the close announcement the
    // client sees can only come from the proxy's drain injection.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = response,
        .close_after_send = false,
    };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    const proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    // Connect, wait for the accept, and only then drain: the connection owes
    // a request (`request_active`), so the sweep leaves it running and the
    // response path must do the closing.
    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);
    while (metrics.active.load() == 0) try io.run_once();
    server.begin_drain();

    var c = DrainTestClient{
        .io = &io,
        .fd = client,
        .request = "GET / HTTP/1.1\r\nHost: o\r\n\r\n", // asked for keep-alive
    };
    c.go();
    while (!c.eof) try io.run_once();
    while (!server.drain_complete()) try io.run_once();

    // Full response delivered, with the close announced (RFC 9112 §9.6).
    const received = c.buf[0..c.len];
    try std.testing.expect(std.mem.indexOf(u8, received, "Connection: close\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, received, "\r\n\r\nHELLO"));
    try std.testing.expectEqual(@as(u64, 1), metrics.requests.load());
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: maglev cluster pins a target to one endpoint and spreads targets" {
    const gpa = std.testing.allocator;
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    // Two origins = two endpoints; close-per-request so the
    // single-connection TestOrigins re-arm between exchanges.
    var listener_a = try Listener.open(Ip4Address.loopback(0), 8);
    defer listener_a.close();
    var origin_a = TestOrigin{ .io = &io, .listener = listener_a, .response = response };
    origin_a.start();
    var listener_b = try Listener.open(Ip4Address.loopback(0), 8);
    defer listener_b.close();
    var origin_b = TestOrigin{ .io = &io, .listener = listener_b, .response = response };
    origin_b.start();

    var json_buf: [384]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "lb": {{ "policy": "maglev" }},
        \\     "endpoints": ["127.0.0.1:{d}", "127.0.0.1:{d}"] }}] }}
    , .{ listener_a.bound_address().port, listener_b.bound_address().port });
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);
    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const exchange = struct {
        fn run(io_: *IO, port: u16, request: []const u8) !void {
            const fd = try connect_loopback(port);
            defer _ = linux.close(fd);
            var c = DrainTestClient{ .io = io_, .fd = fd, .request = request };
            c.go();
            while (!c.eof) try io_.run_once();
            try std.testing.expect(std.mem.endsWith(u8, c.buf[0..c.len], "\r\n\r\nHELLO"));
        }
    }.run;
    const proxy_port = proxy_listener.bound_address().port;

    // The same target, three times: every request must land on ONE origin.
    const pinned = "GET /pin/me HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    const before_a = origin_a.request_len;
    const before_b = origin_b.request_len;
    for (0..3) |_| try exchange(&io, proxy_port, pinned);
    const a_grew = origin_a.request_len > before_a;
    const b_grew = origin_b.request_len > before_b;
    try std.testing.expect(a_grew != b_grew); // exactly one endpoint served all three

    // Distinct targets must spread: after a dozen, both origins have seen
    // traffic (deterministic in the fixed hash — tuned once, stable forever).
    var target_buf: [96]u8 = undefined;
    for (0..12) |sequence| {
        const request = try std.fmt.bufPrint(
            &target_buf,
            "GET /spread/{d} HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n",
            .{sequence},
        );
        try exchange(&io, proxy_port, request);
    }
    try std.testing.expect(origin_a.request_len > before_a);
    try std.testing.expect(origin_b.request_len > before_b);

    while (pool.free_count != pool.capacity) try io.run_once();
    try std.testing.expect(server.resilience.is_idle());
}

test "proxy: two servers share one listener and the last drain closes it once" {
    const gpa = std.testing.allocator;
    // Close-per-request on the upstream side: the single-connection
    // TestOrigin re-arms its accept after each close, so rounds may land on
    // either server (each dials its own upstream) without wedging it.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool_a = try Pool.init(gpa, 4);
    defer pool_a.deinit(gpa);
    var pool_b = try Pool.init(gpa, 4);
    defer pool_b.deinit(gpa);

    // ONE listener; both servers arm accepts on it (accept_mode = shared).
    const proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    const proxy_port = proxy_listener.bound_address().port;
    var listener_refs = Counter{ .value = 2 };
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server_a = ProxyServer.init(
        &io,
        &pool_a,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server_a.deinit();
    var server_b = ProxyServer.init(
        &io,
        &pool_b,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server_b.deinit();
    server_a.listener_refs = &listener_refs;
    server_b.listener_refs = &listener_refs;
    server_a.start();
    server_b.start();

    // Four sequential exchanges; the kernel picks whichever server's accept
    // is pending — every one must be served regardless of which won it.
    var round: u32 = 0;
    while (round < 4) : (round += 1) {
        const client = try connect_loopback(proxy_port);
        defer _ = linux.close(client);
        var c = DrainTestClient{
            .io = &io,
            .fd = client,
            .request = "GET / HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n",
        };
        c.go();
        while (!c.eof) try io.run_once();
        try std.testing.expect(std.mem.endsWith(u8, c.buf[0..c.len], "\r\n\r\nHELLO"));
    }
    try std.testing.expectEqual(@as(u64, 4), metrics.requests.load());
    try std.testing.expectEqual(@as(u64, 4), metrics.accepted.load());

    // Both drain; the refcount makes the LAST one close the shared fd —
    // an earlier close would recycle the fd number under the sibling.
    server_a.begin_drain();
    server_b.begin_drain();
    while (!server_a.drain_complete() or !server_b.drain_complete()) try io.run_once();
    try std.testing.expectEqual(@as(u64, 0), listener_refs.load());
    try expect_connect_refused(proxy_port);
}

test "proxy: a byte on the drain trigger fd begins the drain" {
    const gpa = std.testing.allocator;

    var io = try IO.init(64, 0);
    defer io.deinit();

    var cfg = try config.parse(gpa,
        \\{ "listen": "0.0.0.0:0", "routes": [{ "cluster": "o" }],
        \\  "clusters": [{ "name": "o", "endpoints": ["127.0.0.1:9"] }] }
    );
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    const proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    const proxy_port = proxy_listener.bound_address().port;
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();

    // The worker wiring: a socketpair whose worker end has a recv pending on
    // the ring — one byte from the main thread is the whole protocol.
    var fds: [2]i32 = undefined;
    const pair_rc = linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC,
        0,
        &fds,
    );
    try std.testing.expect(linux.errno(pair_rc) == .SUCCESS);
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);
    server.drain_trigger_fd = fds[0];
    server.start();
    try std.testing.expect(!server.draining);

    const poke = [1]u8{'d'};
    try std.testing.expectEqual(@as(usize, 1), linux.write(fds[1], &poke, poke.len));
    while (!server.drain_complete()) try io.run_once();
    try std.testing.expect(server.draining);
    try std.testing.expectEqual(@as(u64, 1), metrics.draining.load());
    try expect_connect_refused(proxy_port);
}

test "proxy: the serving path allocates nothing after startup (zero-alloc gate)" {
    var counting = guard.CountingAllocator{ .backing = std.testing.allocator };
    const gpa = counting.allocator();
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO";

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{ .io = &io, .listener = origin_listener, .response = response };
    origin.start();

    var json_buf: [512]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0",
        \\   "routes": [{{ "path_prefix": "/m", "cluster": "m" }}, {{ "cluster": "o" }}],
        \\   "clusters": [
        \\     {{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }},
        \\     {{ "name": "m", "lb": {{ "policy": "maglev" }},
        \\       "endpoints": ["127.0.0.1:{d}"] }} ] }}
    , .{ origin_listener.bound_address().port, origin_listener.bound_address().port });
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    // No defer close: the drain at the end of this test closes the listener.
    const proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.start();

    const client = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client);

    const Client = struct {
        io: *IO,
        fd: posix.socket_t,
        buf: [512]u8 = undefined,
        len: usize = 0,
        done: bool = false,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        fn go(c: *@This()) void {
            c.io.recv(*@This(), c, on_recv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, on_send, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: o\r\nConnection: close\r\n\r\n");
        }
        fn on_send(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn on_recv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    // Snapshot after every startup allocation (config, pool) is done.
    const baseline = counting.allocation_count();

    try io.run_until_done(&c.done);
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]);
    while (pool.free_count != pool.capacity) try io.run_once();

    // The full accept -> parse -> route -> connect -> relay -> log path must not
    // have touched the allocator.
    try std.testing.expectEqual(baseline, counting.allocation_count());

    // The consistent-hash path — key hash, Maglev table walk — is on the
    // serving path too, and equally allocation-free (the table was built at
    // config time, before the baseline snapshot).
    const hashed_fd = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(hashed_fd);
    var hashed = DrainTestClient{
        .io = &io,
        .fd = hashed_fd,
        .request = "GET /m/key HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n",
    };
    hashed.go();
    while (!hashed.eof) try io.run_once();
    try std.testing.expect(std.mem.endsWith(u8, hashed.buf[0..hashed.len], "HELLO"));
    while (pool.free_count != pool.capacity) try io.run_once();
    try std.testing.expectEqual(baseline, counting.allocation_count());

    // Drain is on the serving path too (it runs while requests fly): the
    // sweep, the accept cancel, and the listener close allocate nothing.
    server.begin_drain();
    while (!server.drain_complete()) try io.run_once();
    try std.testing.expectEqual(baseline, counting.allocation_count());
}

/// An h2-over-TLS client on the test loop: a client `Channel` glued to a
/// socket, driving the handshake (offering `h2`), then the HTTP/2 preface +
/// one GET, decrypting server frames into a status + body. The end-to-end
/// counterpart of the H2Conn-side isolation tests — here the full
/// ProxyConn handshaker + ALPN handoff is exercised.
const TlsH2ProxyClient = struct {
    io: *IO,
    fd: posix.socket_t,
    channel: terminator.Channel,
    handshake_done: bool = false,
    sent_opening: bool = false,
    plain_out: [512]u8 = undefined,
    plain_out_len: usize = 0,
    plain_out_encrypted: usize = 0,
    wire_out: [constants.tls_bio_pair_bytes]u8 = undefined,
    wire_out_filled: usize = 0,
    wire_out_sent: usize = 0,
    send_in_flight: bool = false,
    recv_in_flight: bool = false,
    wire_in: [constants.tls_bio_pair_bytes]u8 = undefined,
    frame_buf: [8192]u8 = undefined,
    frame_len: usize = 0,
    decoder: hpack.Decoder = .{},
    fields: [16]hpack.Header = undefined,
    fields_storage: [1024]u8 = undefined,
    status: u16 = 0,
    body: [256]u8 = undefined,
    body_len: usize = 0,
    done: bool = false,
    reset: bool = false,
    send_c: Completion = undefined,
    recv_c: Completion = undefined,

    fn go(client: *TlsH2ProxyClient) void {
        _ = client.channel.handshake_step(); // ClientHello
        client.progress();
    }

    fn build_opening(client: *TlsH2ProxyClient) void {
        var len: usize = 0;
        @memcpy(client.plain_out[0..h2_frame.client_preface.len], h2_frame.client_preface);
        len += h2_frame.client_preface.len;
        var settings: [64]u8 = undefined;
        const settings_len = h2_frame.write_settings(&.{}, &settings);
        @memcpy(client.plain_out[len..][0..settings_len], settings[0..settings_len]);
        len += settings_len;
        var block: [128]u8 = undefined;
        var block_len: usize = 0;
        block_len += hpack.encode_header(":method", "GET", block[block_len..]) catch unreachable;
        block_len += hpack.encode_header(":scheme", "https", block[block_len..]) catch unreachable;
        block_len += hpack.encode_header(":path", "/", block[block_len..]) catch unreachable;
        block_len += hpack.encode_header(":authority", "o", block[block_len..]) catch unreachable;
        h2_frame.write_frame_header(.{
            .length = @intCast(block_len),
            .type = .headers,
            .flags = h2_frame.Flags.end_headers | h2_frame.Flags.end_stream,
            .stream_id = 1,
        }, client.plain_out[len..][0..h2_frame.frame_header_bytes]);
        len += h2_frame.frame_header_bytes;
        @memcpy(client.plain_out[len..][0..block_len], block[0..block_len]);
        len += block_len;
        client.plain_out_len = len;
    }

    fn progress(client: *TlsH2ProxyClient) void {
        _ = client.channel.handshake_step();
        if (client.channel.handshake_done() and !client.sent_opening) {
            client.sent_opening = true;
            client.build_opening();
        }
        var enc_budget: u32 = 16;
        while (client.plain_out_encrypted < client.plain_out_len and enc_budget > 0) : (enc_budget -= 1) {
            switch (client.channel.write_plaintext(client.plain_out[client.plain_out_encrypted..client.plain_out_len])) {
                .bytes => |c| client.plain_out_encrypted += c,
                .want_io => break,
                .failed => return,
            }
        }
        var read_budget: u32 = 32;
        while (read_budget > 0) : (read_budget -= 1) {
            var plain: [1024]u8 = undefined;
            switch (client.channel.read_plaintext(&plain)) {
                .bytes => |n| client.consume_frames(plain[0..n]),
                .closed => {
                    client.done = true;
                    break;
                },
                .want_io, .failed => break,
            }
        }
        client.flush_wire();
        client.arm_wire_recv();
    }

    fn consume_frames(client: *TlsH2ProxyClient, plain: []const u8) void {
        @memcpy(client.frame_buf[client.frame_len..][0..plain.len], plain);
        client.frame_len += plain.len;
        var offset: usize = 0;
        while (true) {
            const frame = (h2_frame.parse_frame(client.frame_buf[offset..client.frame_len]) catch {
                client.reset = true;
                client.done = true;
                break;
            }) orelse break;
            offset += frame.wire_bytes();
            switch (frame.header.type) {
                .headers => {
                    const decoded = client.decoder.decode(frame.payload, &client.fields, &client.fields_storage) catch unreachable;
                    client.status = std.fmt.parseInt(u16, decoded[0].value, 10) catch 0;
                    if (frame.header.flags & h2_frame.Flags.end_stream != 0) client.done = true;
                },
                .data => {
                    @memcpy(client.body[client.body_len..][0..frame.payload.len], frame.payload);
                    client.body_len += frame.payload.len;
                    if (frame.header.flags & h2_frame.Flags.end_stream != 0) client.done = true;
                },
                .rst_stream => {
                    client.reset = true;
                    client.done = true;
                },
                else => {},
            }
        }
        std.mem.copyForwards(u8, client.frame_buf[0 .. client.frame_len - offset], client.frame_buf[offset..client.frame_len]);
        client.frame_len -= offset;
    }

    fn flush_wire(client: *TlsH2ProxyClient) void {
        if (client.send_in_flight) return;
        if (client.wire_out_sent == client.wire_out_filled) {
            client.wire_out_filled = client.channel.drain_ciphertext(&client.wire_out);
            client.wire_out_sent = 0;
            if (client.wire_out_filled == 0) return;
        }
        client.send_in_flight = true;
        client.io.send(*TlsH2ProxyClient, client, on_send, &client.send_c, client.fd, client.wire_out[client.wire_out_sent..client.wire_out_filled]);
    }
    fn on_send(client: *TlsH2ProxyClient, _: *Completion, result: io_mod.SendError!usize) void {
        client.send_in_flight = false;
        client.wire_out_sent += result catch return;
        client.progress();
    }
    fn arm_wire_recv(client: *TlsH2ProxyClient) void {
        if (client.recv_in_flight or client.done) return;
        client.recv_in_flight = true;
        client.io.recv(*TlsH2ProxyClient, client, on_recv, &client.recv_c, client.fd, &client.wire_in);
    }
    fn on_recv(client: *TlsH2ProxyClient, _: *Completion, result: io_mod.RecvError!usize) void {
        client.recv_in_flight = false;
        const n = result catch 0;
        if (n == 0) {
            client.done = true;
            return;
        }
        const fed = client.channel.feed_ciphertext(client.wire_in[0..n]);
        std.testing.expectEqual(n, fed) catch unreachable;
        client.progress();
    }
};

test "proxy: negotiates h2 over TLS and hands the connection to the H2 data path" {
    const gpa = std.testing.allocator;
    install_proxy_test_hook();

    var io = try IO.init(64, 0);
    defer io.deinit();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();
    var origin = TestOrigin{
        .io = &io,
        .listener = origin_listener,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO",
        .close_after_send = false, // keep-alive: the pooled upstream lingers
    };
    origin.start();

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.bound_address().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var server_context = try terminator.Context.init_server(
        @embedFile("../tls/testdata/certificate.pem"),
        @embedFile("../tls/testdata/private_key.pem"),
    );
    defer server_context.deinit();
    terminator.enable_h2(&server_context);
    const client_context = try terminator.Context.init_client(.insecure);
    defer client_context.deinit();

    var pool = try Pool.init(gpa, 2);
    defer pool.deinit(gpa);
    var legs = try TlsLegPool.init(gpa, 2);
    defer legs.deinit(gpa);
    var h2_pool = try H2ConnPool.init(gpa, 2);
    defer h2_pool.deinit(gpa);
    var h2_legs = try H2LegPool.init(gpa, 4);
    defer h2_legs.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Counters{};
    var access = AccessLog{ .fd = -1 };
    var server = ProxyServer.init(
        &io,
        &pool,
        proxy_listener,
        &router,
        &metrics,
        &access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    defer server.deinit();
    server.tls_context = &server_context;
    server.tls_legs = &legs;
    server.h2_conn_pool = &h2_pool;
    server.h2_leg_pool = &h2_legs;
    server.start();

    const client_fd = try connect_loopback(proxy_listener.bound_address().port);
    defer _ = linux.close(client_fd);
    var client = TlsH2ProxyClient{
        .io = &io,
        .fd = client_fd,
        .channel = try terminator.Channel.init(&client_context),
    };
    defer client.channel.deinit();
    const offer = "\x02h2\x08http/1.1";
    try std.testing.expectEqual(
        @as(c_int, 0),
        @import("../tls/openssl.zig").SSL_set_alpn_protos(client.channel.ssl, offer.ptr, offer.len),
    );
    client.go();

    try io.run_until_done(&client.done);
    try std.testing.expect(!client.reset);
    try std.testing.expectEqual(@as(u16, 200), client.status);
    try std.testing.expectEqualStrings("HELLO", client.body[0..client.body_len]);
    // The connection took the h2 handoff, not the H1 path.
    try std.testing.expectEqual(@as(u64, 1), metrics.tls_h2_handoffs.load());

    // Drain sweeps the handed-off H2 connection too; everything comes home.
    server.begin_drain();
    while (!server.drain_complete()) try io.run_once();
    try std.testing.expect(server.resilience.is_idle());
}

fn connect_loopback(port: u16) !posix.socket_t {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    try std.testing.expect(linux.errno(rc) == .SUCCESS);
    const fd: posix.socket_t = @intCast(rc);
    const sa = sockaddr_in(Ip4Address.loopback(port));
    try std.testing.expect(
        linux.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) == .SUCCESS,
    );
    return fd;
}
