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
const config = @import("../config.zig");
const Router = @import("../proxy/router.zig").Router;
const RoundRobin = @import("../proxy/balancer.zig").RoundRobin;
const UpstreamPool = @import("../proxy/upstream_pool.zig").UpstreamPool;
const Metrics = @import("../obs/metrics.zig").Metrics;
const access_log = @import("../obs/access_log.zig");
const AccessLog = access_log.AccessLog;
const guard = @import("../mem/guard.zig");
const Ip4Address = std.Io.net.Ip4Address;

const Pool = @import("pool.zig").Pool(ProxyConn);

// Fixed error responses (Connection: close so the client stops after reading).
const resp_400 = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const resp_404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const resp_431 = "HTTP/1.1 431 Request Header Fields Too Large\r\n" ++
    "Content-Length: 0\r\nConnection: close\r\n\r\n";
const resp_501 = "HTTP/1.1 501 Not Implemented\r\n" ++
    "Content-Length: 0\r\nConnection: close\r\n\r\n";
const resp_502 = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const resp_503 = "HTTP/1.1 503 Service Unavailable\r\n" ++
    "Content-Length: 0\r\nConnection: close\r\n\r\n";
const resp_505 = "HTTP/1.1 505 HTTP Version Not Supported\r\n" ++
    "Content-Length: 0\r\nConnection: close\r\n\r\n";

/// Terminates the upstream-bound head after the hop-by-hop headers are
/// stripped. Nothing is injected in their place: an HTTP/1.1 upstream
/// defaults to keep-alive, which is what the connection pool wants; the
/// response's own framing (not EOF) ends the exchange.
const head_terminator = "\r\n";

/// Upper bound on prime segments: one kept run around each skipped header line
/// plus the `Connection: close` injection and any buffered body bytes.
const prime_segments_max = constants.headers_max + 3;

/// One direction of the relay: read from `src_fd`, write to `dst_fd`, repeat.
///
/// Backpressure (docs/DESIGN.md §8): strict recv -> send -> recv over a single
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

    fn armRecv(pipe: *Pipe) void {
        assert(pipe.src_fd >= 0);
        assert(!pipe.framer.isComplete()); // a finished direction is never re-armed
        pipe.conn.retain();
        pipe.conn.io.recv(*Pipe, pipe, onRecv, &pipe.recv_completion, pipe.src_fd, &pipe.buf);
    }

    fn onRecv(pipe: *Pipe, _: *Completion, result: io_mod.RecvError!usize) void {
        defer pipe.conn.releaseRef();
        if (pipe.conn.closing) return;
        const n = result catch return pipe.conn.teardown();
        if (n == 0) return pipe.onEof();
        assert(n <= pipe.buf.len); // the read can never exceed the fixed buffer
        const consumed = pipe.framer.consume(pipe.buf[0..n]) catch
            return pipe.conn.teardown(); // malformed chunked framing
        // A short consume means the message ended inside this read.
        assert(consumed == n or pipe.framer.isComplete());
        if (consumed < n) {
            if (pipe.to_client) {
                // The upstream sent bytes past the response end; its
                // connection is in an unknown state and must not be pooled.
                pipe.conn.u2d_overflow = true;
            } else {
                // Pipelined bytes landed here instead of head_buf; they
                // cannot be handed to the next request — reuse is off.
                pipe.conn.d2u_overflow = true;
            }
        }
        if (consumed == 0) return pipe.finish(); // everything read is past the end
        pipe.filled = consumed;
        pipe.sent = 0;
        assert(pipe.sent < pipe.filled);
        pipe.armSend();
    }

    fn onEof(pipe: *Pipe) void {
        // EOF is a legal terminator only for a close-delimited response;
        // anything else is a truncated message or the client quitting.
        if (pipe.to_client and pipe.framer.framing == .until_close) {
            return pipe.conn.responseComplete();
        }
        pipe.conn.teardown();
    }

    fn armSend(pipe: *Pipe) void {
        assert(pipe.sent < pipe.filled);
        pipe.conn.retain();
        pipe.conn.io.send(
            *Pipe,
            pipe,
            onSend,
            &pipe.send_completion,
            pipe.dst_fd,
            pipe.buf[pipe.sent..pipe.filled],
        );
    }

    fn onSend(pipe: *Pipe, _: *Completion, result: io_mod.SendError!usize) void {
        defer pipe.conn.releaseRef();
        if (pipe.conn.closing) return;
        const m = result catch return pipe.conn.teardown();
        if (pipe.to_client) {
            pipe.conn.metrics.bytes_to_client.add(m);
            pipe.conn.bytes_out += m;
        } else {
            pipe.conn.metrics.bytes_to_upstream.add(m);
        }
        pipe.sent += m;
        assert(pipe.sent <= pipe.filled); // never send past what we read
        if (pipe.sent < pipe.filled) return pipe.armSend(); // finish a partial write
        if (pipe.framer.isComplete()) return pipe.finish();
        pipe.armRecv();
    }

    fn finish(pipe: *Pipe) void {
        assert(pipe.framer.isComplete());
        if (pipe.to_client) return pipe.conn.responseComplete();
        // Request body fully forwarded: this direction goes idle; the
        // connection lives on until the response completes.
        pipe.conn.request_forwarded = true;
    }
};

pub const ProxyConn = struct {
    io: *IO,
    pool: *Pool,
    router: *const Router,
    rr: *RoundRobin,
    upstream_pool: *UpstreamPool,
    metrics: *Metrics,
    access: *AccessLog,

    down_fd: posix.socket_t,
    up_fd: posix.socket_t,
    closing: bool,
    /// In-flight io_uring operations for this connection.
    refs: u32,
    request_timeout_ns: u63,
    idle_timeout_ns: u63,
    /// Absolute (CLOCK_MONOTONIC) deadline for the current phase. Phase
    /// transitions just move it; the single ticking timer enforces it.
    deadline_ns: u64,
    timeout_armed: bool,

    head_buf: [constants.read_buf_bytes]u8,
    head_filled: usize,
    /// Request headers during routing; reused for the response head parse
    /// (the request's entries are dead once the prime segments are built).
    headers_storage: [constants.headers_max]h1.Header,

    /// Method of the current request — decides the response framing (HEAD).
    request_method: h1.Method,
    /// Frames the request body; seeded here, then handed to the d2u pipe.
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
    /// Pipelined bytes leaked into the d2u relay buffer — reuse is off (they
    /// cannot be recovered into `head_buf` without another copy path).
    d2u_overflow: bool,
    /// The upstream sent bytes past the response end — its connection is in
    /// an unknown protocol state and must not be pooled.
    u2d_overflow: bool,
    /// Where the current upstream connection goes (pool key; retry target).
    endpoint_address: Ip4Address,
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
    up_close_pending: bool,
    /// A request is in flight (or aborted mid-flight) — controls whether the
    /// final teardown writes an access-log record.
    request_active: bool,

    // The upstream-bound head as slices of `head_buf` (plus the static
    // `Connection: close` injection), laid out by `buildPrimeSegments`.
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
    close_down_completion: Completion,
    /// Per-request upstream closes (finishRequest / stale retry), guarded by
    /// `up_close_pending`. Teardown must NOT reuse this one: a previous
    /// request's close may still be in flight on it, and re-submitting a
    /// Completion that is in flight corrupts the ring (double callback,
    /// double releaseRef). Found by the simulator, seed 1693.
    close_up_completion: Completion,
    /// Teardown's own upstream close (teardown runs at most once).
    teardown_close_up_completion: Completion,
    timeout_completion: Completion,
    timeout_cancel_completion: Completion,
    connect_cancel_completion: Completion,

    d2u: Pipe,
    u2d: Pipe,

    free_next: ?*ProxyConn,

    pub fn start(
        conn: *ProxyConn,
        io: *IO,
        pool: *Pool,
        router: *const Router,
        rr: *RoundRobin,
        upstream_pool: *UpstreamPool,
        metrics: *Metrics,
        access: *AccessLog,
        down_fd: posix.socket_t,
        request_timeout_ns: u63,
        idle_timeout_ns: u63,
    ) void {
        assert(down_fd >= 0);
        conn.io = io;
        conn.pool = pool;
        conn.router = router;
        conn.rr = rr;
        conn.upstream_pool = upstream_pool;
        conn.metrics = metrics;
        conn.access = access;
        conn.down_fd = down_fd;
        conn.up_fd = -1;
        conn.closing = false;
        conn.refs = 0;
        conn.request_timeout_ns = request_timeout_ns;
        conn.idle_timeout_ns = idle_timeout_ns;
        conn.setDeadline(request_timeout_ns); // a fresh connection owes a request
        conn.timeout_armed = false;
        conn.head_filled = 0;
        conn.up_close_pending = false;
        conn.resetRequestState();
        conn.request_active = true; // a fresh connection owes us a request
        metrics.accepted.add(1);
        metrics.active.add(1);
        conn.armTimeout();
        conn.armRecvHead();
        assert(conn.timeout_armed); // both the deadline and the first recv are in flight
        assert(conn.refs >= 1);
    }

    /// Move the current phase's deadline; the ticking timer picks it up.
    fn setDeadline(conn: *ProxyConn, timeout_ns: u63) void {
        assert(timeout_ns > 0);
        conn.deadline_ns = conn.io.now_ns() + timeout_ns;
    }

    fn armTimeout(conn: *ProxyConn) void {
        assert(!conn.timeout_armed);
        const now = conn.io.now_ns();
        // Sleep to the deadline, but at most one tick: if the deadline moves
        // closer meanwhile (request phase -> idle phase), enforcement is late
        // by at most the tick.
        const remaining = if (conn.deadline_ns > now) conn.deadline_ns - now else 1;
        const sleep_ns: u63 = @intCast(@min(remaining, constants.timeout_tick_ns));
        assert(sleep_ns > 0);
        conn.retain();
        conn.timeout_armed = true;
        conn.io.timeout(*ProxyConn, conn, onTimeout, &conn.timeout_completion, sleep_ns);
    }

    fn onTimeout(conn: *ProxyConn, _: *Completion, _: io_mod.TimeoutError!void) void {
        defer conn.releaseRef();
        conn.timeout_armed = false;
        if (conn.closing) return; // fired late / we cancelled it
        if (conn.io.now_ns() >= conn.deadline_ns) return conn.teardown(); // deadline exceeded
        conn.armTimeout(); // still time left (or the deadline moved); keep watching
    }

    fn retain(conn: *ProxyConn) void {
        conn.refs += 1;
    }

    /// Clear everything scoped to a single request. Connection-scoped state
    /// (fds, refs, the deadline, `head_filled`, `up_close_pending`) stays.
    fn resetRequestState(conn: *ProxyConn) void {
        conn.request_method = .other;
        conn.request_framer = h1.BodyFramer.init(.none);
        conn.request_end = 0;
        conn.request_forwarded = false;
        conn.downstream_keep_alive = false;
        conn.response_reusable = false;
        conn.d2u_overflow = false;
        conn.u2d_overflow = false;
        conn.endpoint_address = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 };
        conn.upstream_pooled = false;
        conn.upstream_reusable = false;
        conn.upstream_retry_used = false;
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

    fn releaseRef(conn: *ProxyConn) void {
        assert(conn.refs > 0);
        conn.refs -= 1;
        if (conn.closing and conn.refs == 0) {
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
        if (conn.closing) return;
        conn.closing = true;
        assert(conn.closing); // idempotent: a second call returns above
        // Cancel the ops that shutdown() cannot reach: the deadline timer (no fd)
        // and any in-flight connect (shutdown of a connecting socket is a no-op).
        // A cancel that matches nothing returns ENOENT — harmless.
        if (conn.timeout_armed) {
            conn.timeout_armed = false;
            conn.cancelOp(&conn.timeout_cancel_completion, &conn.timeout_completion);
        }
        conn.cancelOp(&conn.connect_cancel_completion, &conn.connect_completion);
        // Closing an fd does NOT cancel a recv/send already pending on it in
        // io_uring. shutdown() forces those to complete so the refcount drains;
        // then we close the fd.
        if (conn.down_fd >= 0) {
            conn.io.shutdown_socket(conn.down_fd);
            conn.retain();
            conn.io.close(*ProxyConn, conn, onClosed, &conn.close_down_completion, conn.down_fd);
            conn.down_fd = -1;
        }
        if (conn.up_fd >= 0) {
            conn.io.shutdown_socket(conn.up_fd);
            conn.retain();
            conn.io.close(
                *ProxyConn,
                conn,
                onClosed,
                &conn.teardown_close_up_completion,
                conn.up_fd,
            );
            conn.up_fd = -1;
        }
    }

    fn cancelOp(conn: *ProxyConn, cancel_completion: *Completion, target: *const Completion) void {
        conn.retain();
        conn.io.cancel(*ProxyConn, conn, onCancel, cancel_completion, target);
    }

    fn onCancel(conn: *ProxyConn, _: *Completion, _: io_mod.CancelError!void) void {
        conn.releaseRef();
    }

    fn onClosed(conn: *ProxyConn, _: *Completion, _: io_mod.CloseError!void) void {
        conn.releaseRef();
    }

    // ---- request head -----------------------------------------------------

    fn armRecvHead(conn: *ProxyConn) void {
        assert(conn.down_fd >= 0);
        if (conn.head_filled == conn.head_buf.len) return conn.fail(resp_431);
        assert(conn.head_filled < conn.head_buf.len); // there is room to read into
        conn.retain();
        conn.io.recv(
            *ProxyConn,
            conn,
            onRecvHead,
            &conn.recv_head_completion,
            conn.down_fd,
            conn.head_buf[conn.head_filled..],
        );
    }

    fn onRecvHead(conn: *ProxyConn, _: *Completion, result: io_mod.RecvError!usize) void {
        defer conn.releaseRef();
        if (conn.closing) return;
        const n = result catch return conn.teardown();
        if (n == 0) return conn.teardown(); // client closed before (or between) requests
        // Idle phase ends with the first byte: the request clock starts.
        if (!conn.request_active) conn.setDeadline(conn.request_timeout_ns);
        conn.request_active = true; // bytes arrived: a request is in flight
        assert(n <= conn.head_buf.len - conn.head_filled); // recv was bounded by the tail
        conn.head_filled += n;
        assert(conn.head_filled <= conn.head_buf.len);
        conn.processHead();
    }

    /// Parse whatever head bytes are buffered and dispatch: route a complete
    /// request, or read more. Entered from the recv path and — on a reused
    /// connection — directly from `finishRequest` (pipelined bytes may
    /// already hold the whole next head).
    fn processHead(conn: *ProxyConn) void {
        assert(conn.down_fd >= 0);
        assert(conn.head_filled <= conn.head_buf.len);
        const parsed = h1.parse(
            conn.head_buf[0..conn.head_filled],
            &conn.headers_storage,
        ) catch |err| return conn.fail(responseForParseError(err));
        switch (parsed) {
            .incomplete => conn.armRecvHead(),
            .complete => |request| {
                conn.log_method = request.method_text;
                conn.log_target = request.target;
                conn.metrics.requests.add(1);
                conn.routeAndConnect(&request);
            },
        }
    }

    fn routeAndConnect(conn: *ProxyConn, request: *const h1.Request) void {
        assert(conn.up_fd < 0); // no upstream socket yet
        // A protocol upgrade cannot survive the forced `Connection: close`;
        // refuse it honestly rather than letting it fail at the upstream.
        if (request.header("upgrade") != null) return conn.fail(resp_501);
        // Smuggling-shaped framing (TE+CL, duplicate/garbage Content-Length)
        // is rejected before any byte reaches an upstream.
        const framing = h1.requestFraming(request) catch return conn.fail(resp_400);
        conn.request_method = request.method;
        conn.request_framer = h1.BodyFramer.init(framing);
        const connection = ConnectionTokens.collect(request.headers);
        // A truncated token list means incomplete hop-by-hop classification;
        // refuse rather than forward a header we should have stripped.
        if (connection.overflow) return conn.fail(resp_400);
        conn.downstream_keep_alive = keepAliveRequested(request, &connection);
        const cluster = conn.router.route(request.host(), request.target) orelse
            return conn.fail(resp_404);
        const endpoint = conn.rr.pick(cluster) orelse return conn.fail(resp_503);
        // Body bytes already buffered behind the head count toward the frame;
        // anything past the request's end (a pipelined next request) must not
        // reach the upstream.
        const body = conn.head_buf[request.head_len..conn.head_filled];
        const body_consumed = conn.request_framer.consume(body) catch
            return conn.fail(resp_400);
        conn.request_end = request.head_len + body_consumed;
        conn.buildPrimeSegments(request, conn.request_end, &connection);
        // Replayable = the whole request is in the prime segments; a stale
        // pooled connection can then be retried without losing body bytes.
        conn.request_replayable = conn.request_framer.isComplete();
        conn.endpoint_address = endpoint.address;
        if (conn.upstream_pool.checkout(endpoint.address)) |pooled_fd| {
            assert(pooled_fd >= 0);
            conn.up_fd = pooled_fd;
            conn.upstream_pooled = true;
            conn.metrics.upstream_reused.add(1);
            return conn.armPrime(); // already connected: skip the dial
        }
        conn.connectUpstream();
    }

    fn connectUpstream(conn: *ProxyConn) void {
        assert(conn.up_fd < 0);
        conn.upstream_pooled = false;
        conn.up_fd = conn.io.open_tcp_socket() orelse return conn.fail(resp_502);
        assert(conn.up_fd >= 0);
        conn.retain();
        conn.io.connect(
            *ProxyConn,
            conn,
            onConnect,
            &conn.connect_completion,
            conn.up_fd,
            sockaddrIn(conn.endpoint_address),
        );
    }

    fn onConnect(conn: *ProxyConn, _: *Completion, result: io_mod.ConnectError!void) void {
        defer conn.releaseRef();
        if (conn.closing) return;
        result catch return conn.fail(resp_502);
        assert(conn.up_fd >= 0);
        conn.armPrime();
    }

    /// The upstream connection died before the response head completed. For
    /// a pooled connection that yielded no response byte this is the classic
    /// stale keep-alive close — replay the request once on a fresh dial.
    /// Anything else gets the client a clean 502 (nothing was forwarded
    /// downstream yet).
    fn upstreamFailed(conn: *ProxyConn) void {
        assert(!conn.closing);
        assert(conn.up_fd >= 0);
        const retryable = conn.upstream_pooled and !conn.upstream_retry_used and
            conn.request_replayable and !conn.response_bytes_received and
            !conn.up_close_pending;
        if (!retryable) return conn.fail(resp_502);
        conn.upstream_retry_used = true;
        conn.metrics.upstream_retried.add(1);
        // Drop the dead fd; its prime/recv ops have already completed.
        conn.io.shutdown_socket(conn.up_fd);
        conn.up_close_pending = true;
        conn.retain();
        conn.io.close(
            *ProxyConn,
            conn,
            onUpstreamClosed,
            &conn.close_up_completion,
            conn.up_fd,
        );
        conn.up_fd = -1;
        // Replay: rewind the prime cursor and dial the same endpoint fresh.
        // (u2d state may still hold the previous request's leftovers; it is
        // reset when the relay starts — no response byte arrived for *this*
        // request, per the retryable check above.)
        assert(!conn.response_bytes_received);
        conn.prime_segment_index = 0;
        conn.prime_sent = 0;
        conn.connectUpstream();
    }

    // ---- forward buffered request bytes, then relay -----------------------

    /// Lay out the upstream-bound request as slices of `head_buf`: hop-by-hop
    /// header lines are skipped and a static `Connection: close` terminator is
    /// injected, all without copying a byte. This makes one-request-per-
    /// connection real: the upstream closes after its response, and a second
    /// pipelined request can never reach the first request's cluster.
    fn buildPrimeSegments(
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
            if (!isHopByHopHeader(connection, header.name)) continue;
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

    fn armPrime(conn: *ProxyConn) void {
        assert(conn.up_fd >= 0);
        assert(conn.prime_segment_index < conn.prime_segment_count);
        const segment = conn.prime_segments[conn.prime_segment_index];
        assert(conn.prime_sent < segment.len);
        conn.retain();
        conn.io.send(
            *ProxyConn,
            conn,
            onPrimeSent,
            &conn.aux_completion,
            conn.up_fd,
            segment[conn.prime_sent..],
        );
    }

    fn onPrimeSent(conn: *ProxyConn, _: *Completion, result: io_mod.SendError!usize) void {
        defer conn.releaseRef();
        if (conn.closing) return;
        const m = result catch return conn.upstreamFailed();
        // The primed head is upstream traffic too — without this, a GET-only
        // workload reports zero bytes_to_upstream (only the relay pipe counts).
        conn.metrics.bytes_to_upstream.add(m);
        const segment = conn.prime_segments[conn.prime_segment_index];
        conn.prime_sent += m;
        assert(conn.prime_sent <= segment.len); // never forward past the segment
        if (conn.prime_sent < segment.len) return conn.armPrime(); // finish a partial write
        conn.prime_segment_index += 1;
        conn.prime_sent = 0;
        if (conn.prime_segment_index < conn.prime_segment_count) return conn.armPrime();
        conn.startRelay();
    }

    fn startRelay(conn: *ProxyConn) void {
        assert(conn.down_fd >= 0);
        assert(conn.up_fd >= 0);
        conn.outcome = .proxied;
        conn.d2u.conn = conn;
        conn.d2u.src_fd = conn.down_fd;
        conn.d2u.dst_fd = conn.up_fd;
        conn.d2u.to_client = false;
        conn.d2u.framer = conn.request_framer; // continues where the prime left off
        conn.d2u.filled = 0;
        conn.d2u.sent = 0;
        conn.u2d.conn = conn;
        conn.u2d.src_fd = conn.up_fd;
        conn.u2d.dst_fd = conn.down_fd;
        conn.u2d.to_client = true;
        // Placeholder until the response head parses (beginResponseRelay);
        // the u2d pipe callbacks never run before then.
        conn.u2d.framer = h1.BodyFramer.init(.until_close);
        conn.u2d.filled = 0;
        conn.u2d.sent = 0;
        // The d2u direction only runs while request-body bytes are owed.
        conn.request_forwarded = conn.d2u.framer.isComplete();
        if (!conn.request_forwarded) conn.d2u.armRecv();
        conn.armRecvResponseHead();
    }

    // ---- response head ------------------------------------------------------

    /// Accumulate the response head in the u2d pipe's buffer (nothing is
    /// forwarded downstream until it parses, so an unparseable upstream can
    /// still be answered with a clean 502).
    fn armRecvResponseHead(conn: *ProxyConn) void {
        assert(conn.up_fd >= 0);
        const pipe = &conn.u2d;
        if (pipe.filled == pipe.buf.len) return conn.fail(resp_502); // head too large
        assert(pipe.filled < pipe.buf.len); // there is room to read into
        conn.retain();
        conn.io.recv(
            *ProxyConn,
            conn,
            onRecvResponseHead,
            &pipe.recv_completion,
            conn.up_fd,
            pipe.buf[pipe.filled..],
        );
    }

    fn onRecvResponseHead(conn: *ProxyConn, _: *Completion, result: io_mod.RecvError!usize) void {
        defer conn.releaseRef();
        if (conn.closing) return;
        const n = result catch return conn.upstreamFailed();
        if (n == 0) return conn.upstreamFailed(); // upstream closed without a response
        conn.response_bytes_received = true;
        conn.u2d.filled += n;
        assert(conn.u2d.filled <= conn.u2d.buf.len);
        const parsed = h1.parseResponse(
            conn.u2d.buf[0..conn.u2d.filled],
            &conn.headers_storage, // the request's headers are dead by now
        ) catch return conn.fail(resp_502);
        switch (parsed) {
            .incomplete => conn.armRecvResponseHead(),
            .complete => |response| conn.beginResponseRelay(&response),
        }
    }

    fn beginResponseRelay(conn: *ProxyConn, response: *const h1.Response) void {
        assert(response.head_len > 0);
        assert(response.head_len <= conn.u2d.filled);
        // An interim (1xx) response precedes the real one; relay everything
        // until the upstream closes. (Proper 1xx handling comes with the
        // upstream pool slice.)
        const framing = if (response.status < 200)
            h1.Framing.until_close
        else
            h1.responseFraming(conn.request_method, response) catch
                return conn.fail(resp_502); // conflicting framing: refuse to guess
        const pipe = &conn.u2d;
        // Collected once; a truncated (overflow) list means incomplete
        // hop-by-hop classification, which poisons any reuse or splicing.
        const connection = ConnectionTokens.collect(response.headers);
        // Reuse intent: a framed response to a keep-alive client. The final
        // decision (`canReuseDownstream`) also needs the request forwarded.
        conn.response_reusable = conn.downstream_keep_alive and
            framing != .until_close and
            !connection.overflow;
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
            head_len -= conn.stripResponseHead(response, &connection);
        }
        pipe.framer = h1.BodyFramer.init(framing);
        const body = pipe.buf[head_len..pipe.filled];
        const body_consumed = pipe.framer.consume(body) catch return conn.fail(resp_502);
        // Forward the head plus the framed body prefix; bytes past the
        // message end are dropped (the upstream must not pipeline at us) and
        // taint the connection against pooling.
        if (body_consumed < body.len) conn.u2d_overflow = true;
        pipe.filled = head_len + body_consumed;
        pipe.sent = 0;
        assert(pipe.sent < pipe.filled); // the head alone is never empty
        pipe.armSend(); // Pipe.onSend continues: finish, or relay the rest
    }

    /// Remove hop-by-hop header lines (`Connection` + everything it names,
    /// `Keep-Alive`, `Proxy-Connection`) from the response head, in place:
    /// the head lives in our relay buffer, so the remainder shifts left (one
    /// bounded copy). For an HTTP/1.1 client, absence of `Connection` means
    /// keep-alive — nothing needs injecting. Returns the bytes removed.
    fn stripResponseHead(
        conn: *ProxyConn,
        response: *const h1.Response,
        connection: *const ConnectionTokens,
    ) usize {
        const pipe = &conn.u2d;
        assert(response.head_len <= pipe.filled);
        assert(response.headers.len <= constants.headers_max);
        // Decide up front: compaction below invalidates the header slices.
        var remove: [constants.headers_max]bool = undefined;
        for (response.headers, 0..) |header, index| {
            remove[index] = isHopByHopHeader(connection, header.name);
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

    /// The framed response has been fully forwarded: keep the downstream
    /// connection when everything lines up, else close. Closing *here*,
    /// rather than on EOF, is what keeps a lingering upstream from pinning
    /// the slot.
    fn responseComplete(conn: *ProxyConn) void {
        assert(conn.outcome == .proxied); // only a relayed response completes
        conn.maybePoolUpstream();
        if (!conn.canReuseDownstream()) return conn.teardown();
        conn.finishRequest();
    }

    /// Park the upstream connection for the next request to this endpoint —
    /// independent of whether the *downstream* connection survives.
    fn maybePoolUpstream(conn: *ProxyConn) void {
        if (!conn.upstream_reusable) return;
        if (conn.u2d_overflow) return;
        // The request must be fully forwarded with nothing in flight: if the
        // upstream answered while the client was still uploading, a d2u send
        // may still be pending on this very fd — parking it would strand the
        // operation and leak stray body bytes into a pooled connection.
        // (Found by the simulator, seed 1693.)
        if (!conn.request_forwarded) return;
        if (conn.up_fd < 0) return;
        assert(conn.endpoint_address.port != 0); // set when the request routed
        // Nothing is pending on the fd: the response was fully received and
        // fully forwarded before this point.
        conn.upstream_pool.checkin(conn.io, conn.endpoint_address, conn.up_fd);
        conn.up_fd = -1;
    }

    /// Downstream reuse requires: keep-alive client + framed response
    /// (established at response-head time), the request fully forwarded with
    /// nothing in flight, no pipelined bytes stranded in the relay buffer,
    /// and the previous upstream close completed (its completion is reused).
    fn canReuseDownstream(conn: *const ProxyConn) bool {
        if (!conn.response_reusable) return false;
        if (!conn.request_forwarded) return false;
        if (conn.d2u_overflow) return false;
        if (conn.up_close_pending) return false;
        return true;
    }

    /// The exchange finished and the downstream connection stays open: log
    /// the request, drop the per-request upstream, slide pipelined bytes to
    /// the front of the head buffer, reset per-request state, and parse the
    /// next head (which may already be complete in the buffer).
    fn finishRequest(conn: *ProxyConn) void {
        assert(!conn.closing);
        assert(conn.down_fd >= 0);
        assert(conn.outcome == .proxied);
        conn.access.record(.{
            .method = conn.log_method,
            .target = conn.log_target,
            .outcome = conn.outcome,
            .bytes_to_client = conn.bytes_out,
        });
        if (conn.up_fd >= 0) {
            // Same discipline as teardown: shutdown so any straggler op on
            // the fd completes, then close.
            conn.io.shutdown_socket(conn.up_fd);
            conn.up_close_pending = true;
            conn.retain();
            conn.io.close(
                *ProxyConn,
                conn,
                onUpstreamClosed,
                &conn.close_up_completion,
                conn.up_fd,
            );
            conn.up_fd = -1;
        }
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
        conn.resetRequestState();
        conn.request_active = conn.head_filled > 0; // pipelined bytes = a request in flight
        // A pipelined request starts its clock now; otherwise the idle clock runs.
        const next_timeout_ns =
            if (conn.request_active) conn.request_timeout_ns else conn.idle_timeout_ns;
        conn.setDeadline(next_timeout_ns);
        conn.processHead();
    }

    fn onUpstreamClosed(conn: *ProxyConn, _: *Completion, _: io_mod.CloseError!void) void {
        conn.up_close_pending = false;
        conn.releaseRef();
    }

    // ---- error path -------------------------------------------------------

    fn fail(conn: *ProxyConn, response: []const u8) void {
        assert(conn.down_fd >= 0);
        assert(response.len > 12); // "HTTP/1.1 XXX": status class read at index 9
        conn.outcome = outcomeFor(response);
        // Status class is the first digit of the code at index 9 ("HTTP/1.1 X").
        if (response[9] == '4') {
            conn.metrics.client_errors.add(1);
        } else {
            conn.metrics.upstream_errors.add(1);
        }
        conn.fail_response = response;
        conn.fail_sent = 0;
        conn.armFailSend();
    }

    fn armFailSend(conn: *ProxyConn) void {
        assert(conn.down_fd >= 0);
        assert(conn.fail_sent < conn.fail_response.len);
        conn.retain();
        conn.io.send(
            *ProxyConn,
            conn,
            onFailSent,
            &conn.aux_completion,
            conn.down_fd,
            conn.fail_response[conn.fail_sent..],
        );
    }

    fn onFailSent(conn: *ProxyConn, _: *Completion, result: io_mod.SendError!usize) void {
        defer conn.releaseRef();
        if (conn.closing) return;
        const m = result catch return conn.teardown();
        conn.fail_sent += m;
        assert(conn.fail_sent <= conn.fail_response.len); // never send past the response
        if (conn.fail_sent < conn.fail_response.len) return conn.armFailSend();
        conn.teardown(); // the full response is out; close the connection
    }
};

/// Accept loop: one pooled `ProxyConn` per accepted downstream socket.
pub const ProxyServer = struct {
    io: *IO,
    pool: *Pool,
    listener: Listener,
    router: *const Router,
    metrics: *Metrics,
    access: *AccessLog,
    rr: RoundRobin,
    upstream_pool: UpstreamPool,
    /// Which `Metrics.worker_accepted` slot this worker's accepts count
    /// toward; set by the worker after init (tests leave the default).
    worker_index: u32,
    request_timeout_ns: u63,
    idle_timeout_ns: u63,
    accept_completion: Completion,
    accept_retry_completion: Completion,

    pub fn init(
        io: *IO,
        pool: *Pool,
        listener: Listener,
        router: *const Router,
        metrics: *Metrics,
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
            .rr = .{},
            .upstream_pool = .{},
            .worker_index = 0,
            .request_timeout_ns = request_timeout_ns,
            .idle_timeout_ns = idle_timeout_ns,
            .accept_completion = undefined,
            .accept_retry_completion = undefined,
        };
    }

    /// Close every pooled upstream connection (tests; workers run forever).
    pub fn deinit(server: *ProxyServer) void {
        server.upstream_pool.drain(server.io);
    }

    pub fn start(server: *ProxyServer) void {
        server.armAccept();
    }

    fn armAccept(server: *ProxyServer) void {
        server.io.accept(
            *ProxyServer,
            server,
            onAccept,
            &server.accept_completion,
            server.listener.fd,
        );
    }

    fn onAccept(
        server: *ProxyServer,
        _: *Completion,
        result: io_mod.AcceptError!posix.socket_t,
    ) void {
        if (result) |fd| {
            assert(fd >= 0);
            assert(server.worker_index < constants.workers_max);
            server.metrics.worker_accepted[server.worker_index].add(1);
            server.io.set_tcp_no_delay(fd); // response heads are small writes too
            if (server.pool.acquire()) |conn| {
                conn.start(
                    server.io,
                    server.pool,
                    server.router,
                    &server.rr,
                    &server.upstream_pool,
                    server.metrics,
                    server.access,
                    fd,
                    server.request_timeout_ns,
                    server.idle_timeout_ns,
                );
            } else {
                server.metrics.rejected.add(1);
                server.io.close_now(fd); // backpressure: reject, never allocate
            }
            server.armAccept();
        } else |err| switch (err) {
            // Quota/resource exhaustion persists; an immediate re-arm would
            // fail again instantly and spin the loop at 100% CPU. Back off.
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            error.SystemResources,
            => server.io.timeout(
                *ProxyServer,
                server,
                onAcceptRetry,
                &server.accept_retry_completion,
                constants.accept_retry_delay_ns,
            ),
            // Transient, per-connection failures (e.g. the peer aborted its
            // handshake); accept the next connection immediately.
            else => server.armAccept(),
        }
    }

    fn onAcceptRetry(server: *ProxyServer, _: *Completion, result: io_mod.TimeoutError!void) void {
        result catch {}; // even a failed timer must not stop the accept loop
        server.armAccept();
    }
};

pub const ConnPool = Pool;

fn responseForParseError(err: h1.ParseError) []const u8 {
    return switch (err) {
        error.Malformed => resp_400,
        error.TooManyHeaders => resp_431,
        error.UnsupportedVersion => resp_505,
    };
}

fn outcomeFor(response: []const u8) access_log.Outcome {
    if (response.ptr == resp_400.ptr) return .bad_request;
    if (response.ptr == resp_404.ptr) return .not_found;
    if (response.ptr == resp_431.ptr) return .too_large;
    if (response.ptr == resp_501.ptr) return .not_implemented;
    if (response.ptr == resp_502.ptr) return .no_upstream;
    if (response.ptr == resp_503.ptr) return .unavailable;
    return .bad_version; // resp_505
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
fn isHopByHopHeader(connection: *const ConnectionTokens, name: []const u8) bool {
    assert(name.len > 0); // parser rejects empty header names
    if (std.ascii.eqlIgnoreCase(name, "connection")) return true;
    if (std.ascii.eqlIgnoreCase(name, "keep-alive")) return true;
    if (std.ascii.eqlIgnoreCase(name, "proxy-connection")) return true;
    return connection.names(name);
}

/// Whether the client's request permits downstream connection reuse. Only
/// HTTP/1.1 (keep-alive by default) qualifies; HTTP/1.0 keep-alive is a
/// relic we treat as close (it would require injecting a response header).
fn keepAliveRequested(request: *const h1.Request, connection: *const ConnectionTokens) bool {
    if (request.version_minor != 1) return false;
    return !connection.names("close");
}

fn sockaddrIn(address: Ip4Address) linux.sockaddr.in {
    return .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, address.port),
        .addr = @bitCast(address.bytes),
    };
}

fn monotonicNanos() u64 {
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
        origin.io.accept(*TestOrigin, origin, onAccept, &origin.accept_c, origin.listener.fd);
    }
    fn onAccept(
        origin: *TestOrigin,
        _: *Completion,
        result: io_mod.AcceptError!posix.socket_t,
    ) void {
        origin.fd = result catch return;
        origin.armRecv();
    }
    fn armRecv(origin: *TestOrigin) void {
        origin.io.recv(
            *TestOrigin,
            origin,
            onRecv,
            &origin.recv_c,
            origin.fd,
            origin.request_buf[origin.request_len..],
        );
    }
    fn onRecv(origin: *TestOrigin, _: *Completion, result: io_mod.RecvError!usize) void {
        const n = result catch return;
        if (n == 0) return; // peer closed before completing the request
        origin.request_len += n;
        const unserved = origin.request_buf[origin.served_mark..origin.request_len];
        if (std.mem.indexOf(u8, unserved, origin.respond_after) == null) {
            return origin.armRecv();
        }
        origin.sent = 0;
        origin.armSend();
    }
    fn armSend(origin: *TestOrigin) void {
        origin.io.send(
            *TestOrigin,
            origin,
            onSend,
            &origin.send_c,
            origin.fd,
            origin.response[origin.sent..],
        );
    }
    fn onSend(origin: *TestOrigin, _: *Completion, result: io_mod.SendError!usize) void {
        origin.sent += result catch return;
        if (origin.sent < origin.response.len) return origin.armSend(); // finish a partial write
        origin.served_mark = origin.request_len;
        // Lingering keeps the connection open — and keeps reading, so a
        // pooled upstream connection can carry the next request.
        if (!origin.close_after_send) return origin.armRecv();
        origin.io.close(*TestOrigin, origin, onClose, &origin.close_c, origin.fd);
        origin.fd = -1;
    }
    fn onClose(origin: *TestOrigin, _: *Completion, _: io_mod.CloseError!void) void {
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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
    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, &c.buf);
            c.io.send(
                *@This(),
                c,
                onSend,
                &c.send_c,
                c.fd,
                "GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n",
            );
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: o\r\n" ++
                "Connection: close, x-hop\r\n" ++
                "X-Hop: secret\r\n" ++
                "Keep-Alive: timeout=5\r\n" ++
                "Accept: */*\r\n\r\n");
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
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
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET /ws HTTP/1.1\r\n" ++
                "Host: o\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n");
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: o\r\nConnection: close\r\n\r\n");
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    const started_ns = monotonicNanos();
    try io.run_until_done(&c.done);
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]);
    while (pool.free_count != pool.capacity) try io.run_once();
    // Well under the 30s deadline: the framer ended the response, not a timer.
    try std.testing.expect(monotonicNanos() - started_ns < 5 * std.time.ns_per_s);
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.armRecv();
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: o\r\nConnection: close\r\n\r\n");
        }
        fn armRecv(c: *@This()) void {
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, c.buf[c.total..]);
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) { // EOF: the proxy closed after the terminal chunk
                c.done = true;
                return;
            }
            c.total += n;
            c.armRecv();
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expectEqualStrings(response, c.buf[0..c.total]);
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.armRecv();
            // Two requests in one write. The second must reach the origin
            // only after the first response completes — and on a *fresh*
            // upstream connection, freshly routed.
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n" ++
                "GET /second HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn armRecv(c: *@This()) void {
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, c.buf[c.total..]);
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
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
            c.armRecv();
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);

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
            c.armRecv();
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET /one HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn armRecv(c: *@This()) void {
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) {
                c.done = true;
                return;
            }
            c.len += n;
            if (c.len < c.expected.len) return c.armRecv(); // response still partial
            c.matched = c.matched and std.mem.eql(u8, c.expected, c.buf[0..c.len]);
            c.responses += 1;
            c.len = 0;
            if (c.responses == 2) {
                c.done = true;
                return;
            }
            c.armRecv();
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET /two HTTP/1.1\r\n" ++
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);

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
            c.armRecv();
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET /one HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn armRecv(c: *@This()) void {
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) {
                c.done = true;
                return;
            }
            c.len += n;
            if (c.len < c.expected.len) return c.armRecv();
            c.matched = c.matched and std.mem.eql(u8, c.expected, c.buf[0..c.len]);
            c.responses += 1;
            c.len = 0;
            if (c.responses == 2) {
                c.done = true;
                return;
            }
            c.armRecv();
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET /two HTTP/1.1\r\n" ++
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);

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
            c.armRecv();
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET /one HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn sendSecond(c: *@This()) void {
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET /two HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn armRecv(c: *@This()) void {
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) {
                c.done = true;
                return;
            }
            c.len += n;
            if (c.len < c.expected.len) return c.armRecv();
            c.matched = c.matched and std.mem.eql(u8, c.expected, c.buf[0..c.len]);
            c.responses += 1;
            c.len = 0;
            if (c.responses == 1) {
                c.got_first = true;
                return c.armRecv();
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

    c.sendSecond();
    try io.run_until_done(&c.done);
    try std.testing.expect(c.matched);
    try std.testing.expectEqual(@as(u32, 2), c.responses);
    // The stale connection was checked out, failed, and was replaced.
    try std.testing.expectEqual(@as(u64, 1), metrics.upstream_reused.load());
    try std.testing.expectEqual(@as(u64, 1), metrics.upstream_retried.load());
    try std.testing.expectEqual(@as(u64, 0), metrics.upstream_errors.load());

    _ = linux.close(client);
    while (pool.free_count != pool.capacity) try io.run_once();
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.armRecv();
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET / HTTP/1.0\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn armRecv(c: *@This()) void {
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, c.buf[c.total..]);
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) { // the proxy must close on us: 1.0 never reuses
                c.eof = true;
                return;
            }
            c.total += n;
            c.armRecv();
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, &c.buf);
            // Head first; the body follows in a separate send so it travels
            // through the d2u relay pipe, not just the prime.
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "POST / HTTP/1.1\r\n" ++
                "Host: o\r\nConnection: close\r\nContent-Length: 10\r\n\r\n");
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            if (c.body_sent) return;
            c.body_sent = true;
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, c.body);
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client, .body = body };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]);
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    try io.run_until_done(&c.done);
    try std.testing.expect(std.mem.startsWith(u8, c.buf[0..c.len], "HTTP/1.1 502 "));
    while (pool.free_count != pool.capacity) try io.run_once();
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
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.armRecv();
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET / HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn armRecv(c: *@This()) void {
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, &c.buf);
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) { // EOF: the whole response has been relayed
                c.done = true;
                return;
            }
            c.total += n;
            c.armRecv();
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
    var metrics = Metrics{};
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
    const client = try connectLoopback(proxy_listener.boundAddress().port);
    defer _ = linux.close(client);
    const partial = "GET / HTTP/1.1\r\n"; // no terminating blank line
    _ = linux.write(client, partial, partial.len);

    // The slot is taken once the proxy accepts...
    while (pool.free_count == pool.capacity) try io.run_once();
    try std.testing.expectEqual(pool.capacity - 1, pool.free_count);
    // ...and the deadline must reclaim it; without the timer this would hang.
    while (pool.free_count != pool.capacity) try io.run_once();
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
    , .{origin_listener.boundAddress().port});
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
    var metrics = Metrics{};
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.armRecv();
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: o\r\n\r\n");
        }
        fn armRecv(c: *@This()) void {
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, c.buf[c.len..]);
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            const n = result catch 0;
            if (n == 0) { // the idle deadline closed us
                c.eof = true;
                return;
            }
            c.len += n;
            if (c.len >= c.expected.len) c.got_response = true;
            c.armRecv();
        }
    };
    var c = Client{ .io = &io, .fd = client, .expected = response };
    c.go();

    const started_ns = monotonicNanos();
    try io.run_until_done(&c.eof);
    try std.testing.expect(c.got_response);
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]);
    while (pool.free_count != pool.capacity) try io.run_once();
    // Reclaimed by the idle deadline (~100-400ms), not the old 30s whole-life
    // deadline and not the request timeout alone.
    try std.testing.expect(monotonicNanos() - started_ns < 2 * std.time.ns_per_s);
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

    var json_buf: [256]u8 = undefined;
    const cfg_text = try std.fmt.bufPrint(&json_buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
        \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
    , .{origin_listener.boundAddress().port});
    var cfg = try config.parse(gpa, cfg_text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    var pool = try Pool.init(gpa, 4);
    defer pool.deinit(gpa);

    var metrics = Metrics{};
    var access = AccessLog{ .fd = -1 };
    var proxy_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer proxy_listener.close();
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

    const client = try connectLoopback(proxy_listener.boundAddress().port);
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
            c.io.recv(*@This(), c, onRecv, &c.recv_c, c.fd, &c.buf);
            c.io.send(*@This(), c, onSend, &c.send_c, c.fd, "GET / HTTP/1.1\r\n" ++
                "Host: o\r\nConnection: close\r\n\r\n");
        }
        fn onSend(c: *@This(), _: *Completion, _: io_mod.SendError!usize) void {
            _ = c;
        }
        fn onRecv(c: *@This(), _: *Completion, result: io_mod.RecvError!usize) void {
            c.len = result catch 0;
            c.done = true;
        }
    };
    var c = Client{ .io = &io, .fd = client };
    c.go();

    // Snapshot after every startup allocation (config, pool) is done.
    const baseline = counting.allocationCount();

    try io.run_until_done(&c.done);
    try std.testing.expectEqualStrings(response, c.buf[0..c.len]);
    while (pool.free_count != pool.capacity) try io.run_once();

    // The full accept -> parse -> route -> connect -> relay -> log path must not
    // have touched the allocator.
    try std.testing.expectEqual(baseline, counting.allocationCount());
}

fn connectLoopback(port: u16) !posix.socket_t {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    try std.testing.expect(posix.errno(rc) == .SUCCESS);
    const fd: posix.socket_t = @intCast(rc);
    const sa = sockaddrIn(Ip4Address.loopback(port));
    try std.testing.expect(
        posix.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) == .SUCCESS,
    );
    return fd;
}
