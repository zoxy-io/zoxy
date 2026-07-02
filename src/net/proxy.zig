//! The Phase-0 reverse-proxy data path (docs/DESIGN.md §5, §7). Per downstream
//! connection: receive the request head, route it to a cluster, connect an
//! upstream, forward the buffered request bytes, then relay both directions
//! until either side closes. Everything is reserved up front — the serving path
//! allocates nothing.
//!
//! Lifetime: `refs` counts in-flight io_uring operations for a connection.
//! `teardown` flips `closing` and closes both fds; the resulting (and any other
//! pending) completions decrement `refs`, and the last one releases the slot.
//!
//! Phase-0 contract: **one request per connection.** The head is primed
//! upstream with hop-by-hop headers stripped and `Connection: close` injected
//! (zero-copy, as bounded segmented sends), so a compliant upstream closes
//! after its response; the first EOF in either direction tears the whole
//! connection down. Without the forced close, a keep-alive client could pin a
//! pool slot until the deadline and relay further pipelined requests through
//! the tunnel picked by the *first* request's route — a routing bypass.
//! Responses are relayed verbatim; real keep-alive needs response framing
//! (Phase 2). `Upgrade` requests cannot survive a forced close and are
//! refused with 501.

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

/// Injected in place of the request's hop-by-hop headers when priming the
/// upstream, terminating the head: one request per connection, so the upstream
/// closes after its response (see the module comment).
const connection_close_header = "Connection: close\r\n\r\n";

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
/// into a growable buffer (a Phase-1 throughput option we deliberately skip).
const Pipe = struct {
    conn: *ProxyConn,
    src_fd: posix.socket_t,
    dst_fd: posix.socket_t,
    /// True for the upstream->client direction (drives bytes_to_client metrics).
    to_client: bool,
    buf: [constants.relay_buf_bytes]u8,
    filled: usize,
    sent: usize,
    recv_completion: Completion,
    send_completion: Completion,

    fn armRecv(pipe: *Pipe) void {
        assert(pipe.src_fd >= 0);
        pipe.conn.retain();
        pipe.conn.io.recv(*Pipe, pipe, onRecv, &pipe.recv_completion, pipe.src_fd, &pipe.buf);
    }

    fn onRecv(pipe: *Pipe, _: *Completion, result: io_mod.RecvError!usize) void {
        defer pipe.conn.releaseRef();
        if (pipe.conn.closing) return;
        const n = result catch return pipe.conn.teardown();
        if (n == 0) return pipe.conn.teardown(); // EOF on this half
        assert(n <= pipe.buf.len); // the read can never exceed the fixed buffer
        pipe.filled = n;
        pipe.sent = 0;
        assert(pipe.sent < pipe.filled); // n > 0, so there is something to send
        pipe.armSend();
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
        pipe.armRecv();
    }
};

pub const ProxyConn = struct {
    io: *IO,
    pool: *Pool,
    router: *const Router,
    rr: *RoundRobin,
    metrics: *Metrics,
    access: *AccessLog,

    down_fd: posix.socket_t,
    up_fd: posix.socket_t,
    closing: bool,
    /// In-flight io_uring operations for this connection.
    refs: u32,
    /// Overall deadline; the timer is armed for the connection's whole life.
    timeout_ns: u63,
    timeout_armed: bool,

    head_buf: [constants.read_buf_bytes]u8,
    head_filled: usize,
    headers_storage: [constants.headers_max]h1.Header,

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
    close_up_completion: Completion,
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
        metrics: *Metrics,
        access: *AccessLog,
        down_fd: posix.socket_t,
        timeout_ns: u63,
    ) void {
        assert(down_fd >= 0);
        conn.io = io;
        conn.pool = pool;
        conn.router = router;
        conn.rr = rr;
        conn.metrics = metrics;
        conn.access = access;
        conn.down_fd = down_fd;
        conn.up_fd = -1;
        conn.closing = false;
        conn.refs = 0;
        conn.timeout_ns = timeout_ns;
        conn.timeout_armed = false;
        conn.head_filled = 0;
        conn.prime_segment_count = 0;
        conn.prime_segment_index = 0;
        conn.prime_sent = 0;
        conn.fail_response = "";
        conn.fail_sent = 0;
        conn.log_method = "";
        conn.log_target = "";
        conn.outcome = .aborted;
        conn.bytes_out = 0;
        metrics.accepted.add(1);
        metrics.active.add(1);
        conn.armTimeout();
        conn.armRecvHead();
        assert(conn.timeout_armed); // both the deadline and the first recv are in flight
        assert(conn.refs >= 1);
    }

    fn armTimeout(conn: *ProxyConn) void {
        assert(!conn.timeout_armed);
        conn.retain();
        conn.timeout_armed = true;
        conn.io.timeout(*ProxyConn, conn, onTimeout, &conn.timeout_completion, conn.timeout_ns);
    }

    fn onTimeout(conn: *ProxyConn, _: *Completion, _: io_mod.TimeoutError!void) void {
        defer conn.releaseRef();
        conn.timeout_armed = false;
        if (conn.closing) return; // fired late / we cancelled it
        conn.teardown(); // deadline exceeded
    }

    fn retain(conn: *ProxyConn) void {
        conn.refs += 1;
    }

    fn releaseRef(conn: *ProxyConn) void {
        assert(conn.refs > 0);
        conn.refs -= 1;
        if (conn.closing and conn.refs == 0) {
            conn.metrics.active.sub(1);
            conn.access.record(.{
                .method = conn.log_method,
                .target = conn.log_target,
                .outcome = conn.outcome,
                .bytes_to_client = conn.bytes_out,
            });
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
            _ = linux.shutdown(conn.down_fd, linux.SHUT.RDWR);
            conn.retain();
            conn.io.close(*ProxyConn, conn, onClosed, &conn.close_down_completion, conn.down_fd);
            conn.down_fd = -1;
        }
        if (conn.up_fd >= 0) {
            _ = linux.shutdown(conn.up_fd, linux.SHUT.RDWR);
            conn.retain();
            conn.io.close(*ProxyConn, conn, onClosed, &conn.close_up_completion, conn.up_fd);
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
        if (n == 0) return conn.teardown(); // client closed before completing the head
        assert(n <= conn.head_buf.len - conn.head_filled); // recv was bounded by the tail
        conn.head_filled += n;
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
        const cluster = conn.router.route(request.host(), request.target) orelse
            return conn.fail(resp_404);
        const endpoint = conn.rr.pick(cluster) orelse return conn.fail(resp_503);
        conn.buildPrimeSegments(request);
        conn.up_fd = createTcpSocket() orelse return conn.fail(resp_502);
        assert(conn.up_fd >= 0);
        conn.retain();
        conn.io.connect(
            *ProxyConn,
            conn,
            onConnect,
            &conn.connect_completion,
            conn.up_fd,
            sockaddrIn(endpoint.address),
        );
    }

    fn onConnect(conn: *ProxyConn, _: *Completion, result: io_mod.ConnectError!void) void {
        defer conn.releaseRef();
        if (conn.closing) return;
        result catch return conn.fail(resp_502);
        assert(conn.up_fd >= 0);
        conn.armPrime();
    }

    // ---- forward buffered request bytes, then relay -----------------------

    /// Lay out the upstream-bound request as slices of `head_buf`: hop-by-hop
    /// header lines are skipped and a static `Connection: close` terminator is
    /// injected, all without copying a byte. This makes one-request-per-
    /// connection real: the upstream closes after its response, and a second
    /// pipelined request can never reach the first request's cluster.
    fn buildPrimeSegments(conn: *ProxyConn, request: *const h1.Request) void {
        assert(request.head_len >= 4); // shortest head: request line + blank line
        assert(request.head_len <= conn.head_filled);
        var count: usize = 0;
        var kept_start: usize = 0;
        for (request.headers) |header| {
            if (!isHopByHopHeader(request, header.name)) continue;
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
        conn.prime_segments[count] = connection_close_header;
        count += 1;
        if (conn.head_filled > request.head_len) { // body bytes already buffered
            conn.prime_segments[count] = conn.head_buf[request.head_len..conn.head_filled];
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
        const m = result catch return conn.teardown();
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
        conn.d2u.filled = 0;
        conn.d2u.sent = 0;
        conn.u2d.conn = conn;
        conn.u2d.src_fd = conn.up_fd;
        conn.u2d.dst_fd = conn.down_fd;
        conn.u2d.to_client = true;
        conn.u2d.filled = 0;
        conn.u2d.sent = 0;
        conn.d2u.armRecv();
        conn.u2d.armRecv();
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
    timeout_ns: u63,
    accept_completion: Completion,
    accept_retry_completion: Completion,

    pub fn init(
        io: *IO,
        pool: *Pool,
        listener: Listener,
        router: *const Router,
        metrics: *Metrics,
        access: *AccessLog,
        timeout_ns: u63,
    ) ProxyServer {
        return .{
            .io = io,
            .pool = pool,
            .listener = listener,
            .router = router,
            .metrics = metrics,
            .access = access,
            .rr = .{},
            .timeout_ns = timeout_ns,
            .accept_completion = undefined,
            .accept_retry_completion = undefined,
        };
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
            if (server.pool.acquire()) |conn| {
                conn.start(
                    server.io,
                    server.pool,
                    server.router,
                    &server.rr,
                    server.metrics,
                    server.access,
                    fd,
                    server.timeout_ns,
                );
            } else {
                server.metrics.rejected.add(1);
                _ = linux.close(fd); // backpressure: reject, never allocate
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

/// RFC 9110 §7.6.1: `Connection` itself, the legacy keep-alive headers, and
/// any header the request's `Connection` value names are hop-by-hop — they
/// must not be forwarded to the upstream.
fn isHopByHopHeader(request: *const h1.Request, name: []const u8) bool {
    assert(name.len > 0); // parser rejects empty header names
    if (std.ascii.eqlIgnoreCase(name, "connection")) return true;
    if (std.ascii.eqlIgnoreCase(name, "keep-alive")) return true;
    if (std.ascii.eqlIgnoreCase(name, "proxy-connection")) return true;
    for (request.headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
        // Bounded by the header value's length (itself bounded by the head buffer).
        var tokens = std.mem.splitScalar(u8, header.value, ',');
        while (tokens.next()) |token| {
            const trimmed = std.mem.trim(u8, token, " \t");
            if (std.ascii.eqlIgnoreCase(trimmed, name)) return true;
        }
    }
    return false;
}

fn createTcpSocket() ?posix.socket_t {
    const flags = linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
    const rc = linux.socket(linux.AF.INET, flags, 0);
    if (posix.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

fn sockaddrIn(address: Ip4Address) linux.sockaddr.in {
    return .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, address.port),
        .addr = @bitCast(address.bytes),
    };
}

// ---- tests ----------------------------------------------------------------

/// Minimal origin driven on the same IO loop: accept one connection, read the
/// request head (the proxy primes it as several segmented sends), reply with a
/// fixed response, and close. The received bytes stay in `request_buf` so tests
/// can assert on what was actually forwarded.
const TestOrigin = struct {
    io: *IO,
    listener: Listener,
    response: []const u8,
    sent: usize = 0,
    fd: posix.socket_t = -1,
    request_buf: [1024]u8 = undefined,
    request_len: usize = 0,
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
        if (n == 0) return; // peer closed before completing the head
        origin.request_len += n;
        const received = origin.request_buf[0..origin.request_len];
        // Respond only once the whole head has arrived.
        if (std.mem.indexOf(u8, received, "\r\n\r\n") == null) return origin.armRecv();
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
        origin.io.close(*TestOrigin, origin, onClose, &origin.close_c, origin.fd);
        origin.fd = -1;
    }
    fn onClose(origin: *TestOrigin, _: *Completion, _: io_mod.CloseError!void) void {
        _ = origin;
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
        constants.connection_timeout_ns,
    );
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
                "GET / HTTP/1.1\r\nHost: origin\r\n\r\n",
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
}

test "proxy: strips hop-by-hop headers and forces Connection: close upstream" {
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
        constants.connection_timeout_ns,
    );
    server.start();

    const client = try connectLoopback(proxy_listener.boundAddress().port);
    defer _ = linux.close(client);

    // `Connection` names "x-hop", making X-Hop hop-by-hop as well; all of the
    // keep-alive machinery must be replaced by a single `Connection: close`.
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
                "Connection: keep-alive, x-hop\r\n" ++
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
    try std.testing.expect(std.mem.endsWith(u8, forwarded, "Connection: close\r\n\r\n"));
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
        constants.connection_timeout_ns,
    );
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
        constants.connection_timeout_ns,
    );
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
    );
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
        constants.connection_timeout_ns,
    );
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
