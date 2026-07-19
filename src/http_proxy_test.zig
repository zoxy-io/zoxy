//! Directed L7 scenarios over SimIo (§9), separate from the L4 harness
//! in server_test.zig so neither over-generalizes the other. Covers head
//! ingestion and static-response rejects (before any dial), and the full
//! upstream leg against a scripted HTTP origin: request head + framed
//! body forwarded, response head + framed body relayed back, byte-exact
//! under 1-byte adversarial delivery. Every scenario ends with counters
//! reconciled and all pools drained.

const std = @import("std");

const config_module = @import("config.zig");
const router = @import("http/router.zig");
const Io = @import("io/io.zig");
const parser = @import("http/parser.zig");
const Server = @import("Server.zig").Server;
const SimIo = @import("io/SimIo.zig");

const assert = std.debug.assert;

const ServerSim = Server(SimIo);

/// A scripted HTTP client: sends `request` (the adversary may split the
/// send), then reads until the peer closes, recording the response bytes
/// and whether the close was an orderly FIN or an RST — the §2 property
/// (a delivered response must end in FIN, never a data-discarding RST).
const HttpClient = struct {
    io: *SimIo = undefined,
    server: *ServerSim = undefined,
    connect_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    socket: SimIo.Socket = undefined,
    address: std.Io.net.IpAddress = undefined,
    request: []const u8 = undefined,
    /// Sent on the same connection once the first response is complete —
    /// sequential keep-alive, never pipelining.
    second_request: ?[]const u8 = null,
    /// A client to start when this one finishes (upstream-reuse tests
    /// chain connections deterministically).
    next: ?*HttpClient = null,
    /// The last client begins the drain; a scenario that wants to watch
    /// the idle sweep instead arms a drain timer and clears this.
    drain_on_finish: bool = true,
    sent_len: u32 = 0,
    receive_buffer: [4096]u8 = undefined,
    received_len: u32 = 0,
    outcome: Outcome = .pending,

    const Outcome = enum(u8) { pending, fin, reset };

    fn start(client: *HttpClient, io: *SimIo, server: *ServerSim, address: std.Io.net.IpAddress) void {
        client.io = io;
        client.server = server;
        client.address = address;
        io.connect(address, &client.connect_completion, HttpClient, client, onConnect);
    }

    fn onConnect(client: *HttpClient, result: Io.ConnectError!SimIo.Socket) void {
        client.socket = result catch unreachable;
        client.armRecv();
        client.armSend();
    }

    fn armSend(client: *HttpClient) void {
        assert(client.sent_len < client.request.len);
        client.io.send(
            client.socket,
            client.request[client.sent_len..],
            &client.send_completion,
            HttpClient,
            client,
            onSend,
        );
    }

    fn onSend(client: *HttpClient, result: Io.SendError!u32) void {
        // A reject may close the connection before the whole request is
        // sent; a send failure then is expected, not an error.
        const sent = result catch return;
        client.sent_len += sent;
        assert(client.sent_len <= client.request.len);
        if (client.sent_len < client.request.len) {
            client.armSend();
        }
    }

    fn armRecv(client: *HttpClient) void {
        client.io.recv(
            client.socket,
            client.receive_buffer[client.received_len..],
            &client.recv_completion,
            HttpClient,
            client,
            onRecv,
        );
    }

    fn onRecv(client: *HttpClient, result: Io.RecvError!u32) void {
        const received = result catch |err| {
            client.outcome = if (err == error.Reset) .reset else .fin;
            client.io.closeNow(client.socket);
            if (client.next) |successor| {
                client.next = null;
                successor.start(client.io, client.server, client.address);
                return;
            }
            if (client.drain_on_finish) {
                // Begin the drain so the run winds down instead of idling
                // on the armed accept — the L4 harness does the same.
                client.server.beginDrain();
            }
            return;
        };
        assert(received >= 1);
        client.received_len += received;
        assert(client.received_len <= client.receive_buffer.len);
        client.maybeSendSecond();
        client.armRecv();
    }

    /// Sequential keep-alive: once the first response is complete (its
    /// content-length body fully received), send the queued second
    /// request on the same connection.
    fn maybeSendSecond(client: *HttpClient) void {
        const queued = client.second_request orelse return;
        var storage: parser.HeaderStorage = undefined;
        const first = parser.parseResponseHead(
            client.receive_buffer[0..client.received_len],
            false,
            &storage,
            .get,
        ) catch return; // Incomplete head: keep reading.
        const body_len: u32 = switch (first.framing) {
            .content_length => |length| @intCast(length),
            else => 0,
        };
        if (client.received_len < first.head_len + body_len) {
            return;
        }
        client.second_request = null;
        client.request = queued;
        client.sent_len = 0;
        client.armSend();
    }

    fn response(client: *const HttpClient) []const u8 {
        return client.receive_buffer[0..client.received_len];
    }
};

/// A scripted HTTP origin: reads requests (head + framed body, tracked
/// with zoxy's own parser so the test asserts on exactly what the proxy
/// forwarded) and answers each with the canned `response`. It keeps its
/// connection alive between requests — parked upstream connections come
/// back to it — unless `close_after_response` scripts the origin-side
/// close (until-close bodies, and the stale-parked scenario). One
/// connection per scenario: a second accept trips an assert, which is
/// itself the reuse witness.
const HttpOrigin = struct {
    io: *SimIo = undefined,
    listener: SimIo.Listener = undefined,
    accept_completion: SimIo.Completion = .{},
    listening: bool = false,
    response: []const u8 = "",
    close_after_response: bool = false,
    conn: OConn = .{},
    accepted: bool = false,
    requests_served: u32 = 0,

    const OConn = struct {
        origin: *HttpOrigin = undefined,
        socket: SimIo.Socket = undefined,
        recv_completion: SimIo.Completion = .{},
        send_completion: SimIo.Completion = .{},
        request_buffer: [16384]u8 = undefined,
        request_len: u32 = 0,
        /// Start of the request currently being read; earlier requests
        /// stay captured in the buffer for the tests' assertions.
        request_offset: u32 = 0,
        request_complete: bool = false,
        closed: bool = false,
        /// Total bytes expected for the current request (head + framed
        /// body), known once its head parses. 0 means not parsed yet.
        request_expected: u32 = 0,
        response_sent: u32 = 0,

        fn armRecv(oconn: *OConn) void {
            oconn.origin.io.recv(
                oconn.socket,
                oconn.request_buffer[oconn.request_len..],
                &oconn.recv_completion,
                OConn,
                oconn,
                onRecv,
            );
        }

        fn onRecv(oconn: *OConn, result: Io.RecvError!u32) void {
            const received = result catch {
                oconn.origin.io.closeNow(oconn.socket);
                oconn.closed = true;
                return;
            };
            oconn.request_len += received;
            oconn.tryAdvance();
        }

        /// Parse the head once to learn the total request size (head +
        /// content-length body — the only body shape these tests send),
        /// then read until the whole request has arrived and respond.
        fn tryAdvance(oconn: *OConn) void {
            if (oconn.request_expected == 0) {
                var storage: parser.HeaderStorage = undefined;
                const request = parser.parseRequestHead(
                    oconn.request_buffer[oconn.request_offset..oconn.request_len],
                    false,
                    &storage,
                ) catch |err| {
                    if (err == error.Incomplete) {
                        oconn.armRecv();
                        return;
                    }
                    oconn.origin.io.closeNow(oconn.socket);
                    oconn.closed = true;
                    return;
                };
                const body_length: u32 = switch (request.framing) {
                    .content_length => |length| @intCast(length),
                    else => 0,
                };
                oconn.request_expected = request.head_len + body_length;
            }
            const current_len = oconn.request_len - oconn.request_offset;
            assert(current_len <= oconn.request_expected);
            if (current_len < oconn.request_expected) {
                oconn.armRecv();
                return;
            }
            oconn.request_complete = true;
            oconn.armSend();
        }

        fn armSend(oconn: *OConn) void {
            assert(oconn.response_sent < oconn.origin.response.len);
            oconn.origin.io.send(
                oconn.socket,
                oconn.origin.response[oconn.response_sent..],
                &oconn.send_completion,
                OConn,
                oconn,
                onSend,
            );
        }

        fn onSend(oconn: *OConn, result: Io.SendError!u32) void {
            const sent = result catch {
                oconn.origin.io.closeNow(oconn.socket);
                oconn.closed = true;
                return;
            };
            oconn.response_sent += sent;
            if (oconn.response_sent < oconn.origin.response.len) {
                oconn.armSend();
                return;
            }
            oconn.origin.requests_served += 1;
            if (oconn.origin.close_after_response) {
                oconn.origin.io.closeNow(oconn.socket);
                oconn.closed = true;
                return;
            }
            // Keep-alive: the next request appends after this one (the
            // buffer keeps every request for the tests' assertions).
            oconn.request_offset = oconn.request_len;
            oconn.request_expected = 0;
            oconn.response_sent = 0;
            oconn.armRecv();
        }
    };

    fn start(origin: *HttpOrigin, io: *SimIo, address: std.Io.net.IpAddress) !void {
        origin.io = io;
        origin.listener = try io.listen(address);
        origin.listening = true;
        origin.armAccept();
    }

    fn armAccept(origin: *HttpOrigin) void {
        origin.io.accept(origin.listener, &origin.accept_completion, HttpOrigin, origin, onAccept);
    }

    fn onAccept(origin: *HttpOrigin, result: Io.AcceptError!SimIo.Socket) void {
        const socket = result catch |err| {
            assert(err == error.Canceled);
            return;
        };
        assert(!origin.accepted);
        origin.accepted = true;
        origin.conn.origin = origin;
        origin.conn.socket = socket;
        origin.conn.armRecv();
        origin.armAccept();
    }

    /// Close a still-open origin-side connection at scenario end so the
    /// socket leak check is exact — its EOF delivery may race the loop
    /// stop (the L4 harness does the same).
    fn closeRemaining(origin: *HttpOrigin) void {
        if (origin.accepted and !origin.conn.closed) {
            origin.io.closeNow(origin.conn.socket);
            origin.conn.closed = true;
        }
    }

    fn stopListening(origin: *HttpOrigin) void {
        if (origin.listening) {
            origin.io.listenClose(origin.listener);
            origin.listening = false;
        }
    }
};

/// Single-listener L7 harness: one http listener, a scripted origin, one
/// client.
const Http1Bed = struct {
    arena_state: std.heap.ArenaAllocator,
    sim_io: SimIo,
    endpoints: [1]std.Io.net.IpAddress,
    clusters: [1]config_module.Config.Cluster,
    routes: [1]router.Route,
    listeners: [1]config_module.Config.Listener,
    config: config_module.Config,
    server: ServerSim,
    origin: HttpOrigin,
    client: HttpClient,
    client2: HttpClient,
    drain_timer_completion: SimIo.Completion,

    const idle_timeout_ms: u32 = 1000;

    fn bindAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
    }

    fn originAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
    }

    const Options = struct {
        seed: u64,
        partial_io: bool = false,
        origin_response: []const u8 = "",
        origin_listens: bool = true,
        origin_closes: bool = false,
    };

    fn setUp(bed: *Http1Bed, gpa: std.mem.Allocator, options: Options) !void {
        bed.arena_state = std.heap.ArenaAllocator.init(gpa);
        errdefer bed.arena_state.deinit();
        const arena = bed.arena_state.allocator();

        try bed.sim_io.init(arena, .{
            .seed = options.seed,
            .adversary = .{ .partial_io = options.partial_io },
        });
        bed.endpoints = .{originAddress()};
        bed.clusters = .{.{ .name = "origin", .endpoints = &bed.endpoints }};
        bed.routes = .{.{ .prefix = "/", .cluster_index = 0 }};
        bed.listeners = .{.{ .bind_address = bindAddress(), .routes = &bed.routes, .protocol = .http }};
        bed.config = .{
            .listeners = &bed.listeners,
            .clusters = &bed.clusters,
            .connect_timeout_ms = 50,
            .idle_timeout_ms = idle_timeout_ms,
            .drain_deadline_ms = 1000,
            .max_lifetime_ms = 0,
        };
        try bed.server.init(arena, &bed.sim_io, &bed.config, .{
            .conn_slots = 4,
            .relay_buffers = 2,
            .upstream_slots = 2,
        });
        try bed.server.start();
        bed.origin = .{
            .response = options.origin_response,
            .close_after_response = options.origin_closes,
        };
        if (options.origin_listens) {
            try bed.origin.start(&bed.sim_io, originAddress());
        }
        bed.client = .{};
        bed.client2 = .{};
        bed.drain_timer_completion = .{};
    }

    /// A sweep-observation scenario cannot let the client drive the drain
    /// (the drain reaps parked upstreams instantly); this timer drains
    /// after the idle sweep has had time to act.
    fn armDrainTimer(bed: *Http1Bed, delay_ms: u32) void {
        bed.sim_io.timerStart(
            &bed.drain_timer_completion,
            @as(u64, delay_ms) * std.time.ns_per_ms,
            Http1Bed,
            bed,
            onDrainTimer,
        );
    }

    fn onDrainTimer(bed: *Http1Bed, result: Io.TimerError!void) void {
        result catch unreachable; // Nothing cancels the test drain timer.
        bed.server.beginDrain();
    }

    fn tearDown(bed: *Http1Bed) void {
        bed.arena_state.deinit();
    }

    /// Send one request and run to quiescence. The client begins the
    /// drain when it sees the connection close, so a single run winds the
    /// whole scenario down; by the time it returns the client has its
    /// outcome and the pools have drained.
    fn exchange(bed: *Http1Bed, request: []const u8) !void {
        bed.client.request = request;
        bed.client.start(&bed.sim_io, &bed.server, bindAddress());
        try bed.sim_io.run();
        bed.origin.stopListening();
    }

    fn expectDrained(bed: *Http1Bed) !void {
        bed.origin.closeRemaining();
        try std.testing.expect(bed.server.isIdle());
        try std.testing.expect(bed.server.reconcile());
        try std.testing.expect(bed.sim_io.sockets.isFullyReleased());
    }
};

test "l7: a malformed request head is answered 400 and closed with FIN" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 1 });
    defer bed.tearDown();

    // A bare LF terminator is a smuggling shape the parser rejects (§7).
    try bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_request"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: a malformed chunked body coalesced with the head is answered 400" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 7,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // The head is valid, so it is sent upstream and the response leg is
    // about to arm — but the chunk-size line coalesced behind it opens with
    // a non-hex byte, a framing violation the moment it is fed. The client
    // still gets a 400, not the bare teardown a post-arm detection forces
    // (§7): the body is validated before the response recv commits its op.
    try bed.exchange("POST /x HTTP/1.1\r\nHost: o\r\nTransfer-Encoding: chunked\r\n\r\nZ");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_request"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: oversize request line is 414, oversize header section is 431" {
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 2 });
        defer bed.tearDown();

        const long_target = "/" ++ ("a" ** 9000);
        try bed.exchange("GET " ++ long_target ++ " HTTP/1.1\r\n");

        try std.testing.expectEqualStrings(
            "HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_uri_too_long"));
        try bed.expectDrained();
    }
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 3 });
        defer bed.tearDown();

        const filler = "X-Filler: " ++ ("v" ** 200) ++ "\r\n";
        var request: [10000]u8 = undefined;
        var len: usize = 0;
        const prefix = "GET / HTTP/1.1\r\nHost: a\r\n";
        @memcpy(request[0..prefix.len], prefix);
        len += prefix.len;
        while (len + filler.len <= request.len) {
            @memcpy(request[len..][0..filler.len], filler);
            len += filler.len;
        }
        try bed.exchange(request[0..len]);

        try std.testing.expectEqualStrings(
            "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_headers_too_large"));
        try bed.expectDrained();
    }
}

test "l7: CONNECT and Upgrade are answered 501" {
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 4 });
        defer bed.tearDown();
        try bed.exchange("CONNECT origin:443 HTTP/1.1\r\nHost: origin\r\n\r\n");
        try std.testing.expectEqualStrings(
            "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_not_implemented"));
        try bed.expectDrained();
    }
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 5 });
        defer bed.tearDown();
        try bed.exchange("GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n");
        try std.testing.expectEqualStrings(
            "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_not_implemented"));
        try bed.expectDrained();
    }
}

test "l7: a GET is proxied and the origin's response relayed back" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 6,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    });
    defer bed.tearDown();

    try bed.exchange("GET /path HTTP/1.1\r\nHost: origin.example\r\nConnection: close\r\n\r\n");

    // The client saw the origin's response, rewritten with Connection:
    // close (the proxy announces the coming close), ending in a FIN.
    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        bed.client.response(),
    );
    // The origin received the request, rewritten with Connection: close.
    try std.testing.expect(bed.origin.conn.request_complete);
    var storage: parser.HeaderStorage = undefined;
    const forwarded = try parser.parseRequestHead(
        bed.origin.conn.request_buffer[0..bed.origin.conn.request_len],
        false,
        &storage,
    );
    try std.testing.expectEqual(parser.Method.get, forwarded.method);
    try std.testing.expectEqualStrings("/path", forwarded.target);
    // The client asked to close, but that is hop-by-hop: the upstream
    // connection stays reusable (§5) — the client's Connection header is
    // stripped and no close is injected toward the origin.
    try std.testing.expect(forwarded.keep_alive);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: a POST body is forwarded and a sized response returned, byte-exact under the adversary" {
    var seed: u64 = 1;
    while (seed <= 12) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = seed,
            .partial_io = true,
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange("POST /submit HTTP/1.1\r\nHost: o\r\nConnection: close\r\nContent-Length: 11\r\n\r\nhello world");

        try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
        try std.testing.expectEqualStrings(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            bed.client.response(),
        );
        // The origin received the whole 11-byte body after the head.
        try std.testing.expect(bed.origin.conn.request_complete);
        var storage: parser.HeaderStorage = undefined;
        const forwarded = try parser.parseRequestHead(
            bed.origin.conn.request_buffer[0..bed.origin.conn.request_len],
            false,
            &storage,
        );
        const body = bed.origin.conn.request_buffer[forwarded.head_len..bed.origin.conn.request_len];
        try std.testing.expectEqualStrings("hello world", body);
        try bed.expectDrained();
    }
}

test "l7: a body coalesced with the head, larger than a relay buffer, forwards intact" {
    // The client sends head + a 6000-byte body in one shot: the excess
    // (~6 KB) exceeds a 4 KiB relay buffer, so it must be forwarded
    // straight from the 8 KiB head buffer, not copied through one.
    const body_len = 6000;
    var request: [7000]u8 = undefined;
    const head = "POST /big HTTP/1.1\r\nHost: o\r\nConnection: close\r\nContent-Length: 6000\r\n\r\n";
    @memcpy(request[0..head.len], head);
    for (request[head.len .. head.len + body_len], 0..) |*byte, index| {
        byte.* = @intCast('A' + (index % 26));
    }
    const request_len = head.len + body_len;

    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 40,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    try bed.exchange(request[0..request_len]);

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    // The origin received the whole 6000-byte body byte-for-byte.
    try std.testing.expect(bed.origin.conn.request_complete);
    var storage: parser.HeaderStorage = undefined;
    const forwarded = try parser.parseRequestHead(
        bed.origin.conn.request_buffer[0..bed.origin.conn.request_len],
        false,
        &storage,
    );
    const forwarded_body = bed.origin.conn.request_buffer[forwarded.head_len..bed.origin.conn.request_len];
    try std.testing.expectEqualStrings(request[head.len..request_len], forwarded_body);
    try bed.expectDrained();
}

test "l7: a connection-close (until-close) response body relays to the client's EOF" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 20,
        // No Content-Length and no Transfer-Encoding: the body runs to
        // the origin's close (§6.3 until-close), so the origin must close.
        .origin_response = "HTTP/1.1 200 OK\r\n\r\nstreamed body bytes",
        .origin_closes = true,
    });
    defer bed.tearDown();

    try bed.exchange("GET /stream HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nstreamed body bytes",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try bed.expectDrained();
}

test "l7: an unreachable origin is answered 502" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 30, .origin_listens = false });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: rejects survive 1-byte adversarial delivery across seeds" {
    var seed: u64 = 1;
    while (seed <= 15) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = seed, .partial_io = true });
        defer bed.tearDown();

        try bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");

        try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
        try std.testing.expectEqualStrings(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_request"));
        try bed.expectDrained();
    }
}

test "l7: the head-read deadline reaps a slowloris that never completes" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 7 });
    defer bed.tearDown();

    // A partial head with no terminator: the client sends it and then
    // goes silent, so only the head-read deadline can end the connection.
    try bed.exchange("GET / HTTP/1.1\r\nHost: a\r\n");

    try std.testing.expectEqual(@as(usize, 0), bed.client.response().len);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: a single close-terminated exchange allocates nothing after init" {
    // §9 zero-alloc gate for the L7 upstream leg: a full proxied
    // exchange — dial, request head + body, response, forward, close —
    // under a counting allocator, then again under one that *fails* past
    // the init count.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var bed: Http1Bed = undefined;
    try bed.setUp(failing.allocator(), .{ .seed = 9, .partial_io = true, .origin_response = response });
    defer bed.tearDown();
    const allocations_after_init = failing.allocations;
    try bed.exchange("POST /p HTTP/1.1\r\nHost: o\r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc");
    try bed.expectDrained();
    try std.testing.expectEqual(allocations_after_init, failing.allocations);

    var strict = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = allocations_after_init,
    });
    var strict_bed: Http1Bed = undefined;
    try strict_bed.setUp(strict.allocator(), .{ .seed = 9, .partial_io = true, .origin_response = response });
    defer strict_bed.tearDown();
    try strict_bed.exchange("POST /p HTTP/1.1\r\nHost: o\r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc");
    try strict_bed.expectDrained();
}

test "l7: the keep-alive reuse turnaround allocates nothing after init" {
    // §9 zero-alloc gate for the §5 park/checkout/reset path: two
    // requests on one client connection reuse the parked upstream — the
    // most allocation-prone L7 lifecycle code, and the one a single
    // close-terminated exchange never touches. Counting run, then a
    // failing run pinned to the init count.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const second_request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    const first_request = "GET /one HTTP/1.1\r\nHost: o\r\n\r\n";

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var bed: Http1Bed = undefined;
    try bed.setUp(failing.allocator(), .{ .seed = 50, .origin_response = response });
    defer bed.tearDown();
    const allocations_after_init = failing.allocations;
    bed.client.second_request = second_request;
    try bed.exchange(first_request);
    try bed.expectDrained();
    // The turnaround must actually have parked and reused the upstream,
    // or this gates nothing.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(allocations_after_init, failing.allocations);

    var strict = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = allocations_after_init,
    });
    var strict_bed: Http1Bed = undefined;
    try strict_bed.setUp(strict.allocator(), .{ .seed = 50, .origin_response = response });
    defer strict_bed.tearDown();
    strict_bed.client.second_request = second_request;
    try strict_bed.exchange(first_request);
    try strict_bed.expectDrained();
}

test "l7: an http listener admits without a relay buffer" {
    // The idle L7 connection holds a slot only (§5): a reject never
    // touches the relay pool.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 8 });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_relay_buffers"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try bed.expectDrained();
}

test "l7: downstream keep-alive serves two requests on one connection" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 50,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // First request asks to keep the connection; the second announces the
    // close, ending the scenario cleanly.
    bed.client.second_request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\n\r\n");

    // One client connection, two responses: the first without a close
    // announcement, the second with one, then FIN.
    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("l7_responses"));
    // The idle turnaround also parked and reused the upstream connection.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(@as(u32, 2), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: a parked upstream connection is reused across client connections" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 51,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // Two separate client connections, each closing downstream — the
    // upstream connection parks after the first and serves the second
    // (the origin accepting only once is asserted in its harness).
    bed.client.next = &bed.client2;
    bed.client2.request = "GET /b HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client2.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client2.response(),
    );
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(@as(u32, 2), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: the idle sweep reaps a parked upstream past its deadline" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 52,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // The client must not drain (that reaps parked instantly); a timer
    // drains well after the sweep has had time to act on the idle
    // deadline.
    bed.client.drain_on_finish = false;
    bed.armDrainTimer(Http1Bed.idle_timeout_ms * 3);
    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_idle_reaped"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("upstream_reused"));
    try bed.expectDrained();
}

test "l7: a pipelining client gets its first response, then the close" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 53,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // Both requests in one write: the second is pipelined. Pipelining is
    // unsupported — the first exchange completes and the connection
    // closes; the client recovers by retrying per RFC.
    try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\n\r\n" ++
        "GET /two HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: a stale parked connection is answered 502 until Phase 2's replay" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 54,
        // The origin's response claims keep-alive, but it closes right
        // after — the §5 stale-parked scenario, detected on first use.
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .origin_closes = true,
    });
    defer bed.tearDown();

    bed.client.next = &bed.client2;
    bed.client2.request = "GET /b HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client2.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client2.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
    try bed.expectDrained();
}
