//! Directed L7 scenarios over SimIo (§9), separate from the L4 harness
//! in server_test.zig so neither over-generalizes the other. This slice
//! covers head ingestion and the static-response rejects: a client sends
//! a request head (split arbitrarily by the adversary) and observes
//! either the exact static error response or, for a valid request, a
//! clean close with no response — the upstream leg lands next. Every
//! scenario ends with counters reconciled and all pools drained.

const std = @import("std");

const config_module = @import("config.zig");
const Io = @import("io/io.zig");
const Server = @import("Server.zig").Server;
const SimIo = @import("io/SimIo.zig");

const assert = std.debug.assert;

const ServerSim = Server(SimIo);

/// A scripted HTTP client: sends `request` (the adversary may split the
/// send into 1-byte pieces), then reads until the peer closes,
/// accumulating the response bytes for the assertions.
const HttpClient = struct {
    io: *SimIo = undefined,
    /// Drained when this client's exchange ends, so the run reaches true
    /// quiescence instead of deadlocking on the still-armed accept — the
    /// L4 harness drains from client-end for the same reason.
    server: *ServerSim = undefined,
    connect_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    socket: SimIo.Socket = undefined,
    request: []const u8 = undefined,
    sent_len: u32 = 0,
    receive_buffer: [512]u8 = undefined,
    received_len: u32 = 0,
    /// Set once the server closes (FIN) or resets the connection.
    closed: bool = false,

    fn start(client: *HttpClient, io: *SimIo, server: *ServerSim, address: std.Io.net.IpAddress) void {
        client.io = io;
        client.server = server;
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
        const received = result catch {
            // FIN or RST: the exchange is over. Begin the drain so the
            // run winds down instead of idling on the armed accept.
            client.io.closeNow(client.socket);
            client.closed = true;
            client.server.beginDrain();
            return;
        };
        assert(received >= 1);
        client.received_len += received;
        assert(client.received_len <= client.receive_buffer.len);
        client.armRecv();
    }

    fn response(client: *const HttpClient) []const u8 {
        return client.receive_buffer[0..client.received_len];
    }
};

/// Single-listener L7 harness: one http listener, no origin (the
/// upstream leg is not exercised in this slice), one client.
const Http1Bed = struct {
    arena_state: std.heap.ArenaAllocator,
    sim_io: SimIo,
    endpoints: [1]std.Io.net.IpAddress,
    clusters: [1]config_module.Config.Cluster,
    listeners: [1]config_module.Config.Listener,
    config: config_module.Config,
    server: ServerSim,
    client: HttpClient,

    const idle_timeout_ms: u32 = 1000;

    fn bindAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
    }

    fn originAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
    }

    fn setUp(bed: *Http1Bed, gpa: std.mem.Allocator, seed: u64, partial_io: bool) !void {
        bed.arena_state = std.heap.ArenaAllocator.init(gpa);
        errdefer bed.arena_state.deinit();
        const arena = bed.arena_state.allocator();

        try bed.sim_io.init(arena, .{ .seed = seed, .adversary = .{ .partial_io = partial_io } });
        bed.endpoints = .{originAddress()};
        bed.clusters = .{.{ .name = "origin", .endpoints = &bed.endpoints }};
        bed.listeners = .{.{ .bind_address = bindAddress(), .cluster_index = 0, .protocol = .http }};
        bed.config = .{
            .listeners = &bed.listeners,
            .clusters = &bed.clusters,
            .connect_timeout_ms = 50,
            .idle_timeout_ms = idle_timeout_ms,
            .drain_deadline_ms = 1000,
            .max_lifetime_ms = 0,
        };
        try bed.server.init(arena, &bed.sim_io, &bed.config, .{ .conn_slots = 4, .relay_buffers = 2 });
        try bed.server.start();
        bed.client = .{};
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
    }

    fn expectDrained(bed: *Http1Bed) !void {
        try std.testing.expect(bed.server.isIdle());
        try std.testing.expect(bed.server.reconcile());
        try std.testing.expect(bed.sim_io.sockets.isFullyReleased());
    }
};

test "l7: a malformed request head is answered 400 and closed" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, 1, false);
    defer bed.tearDown();

    // A bare LF terminator is a smuggling shape the parser rejects (§7).
    try bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");

    try std.testing.expect(bed.client.closed);
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
        try bed.setUp(std.testing.allocator, 2, false);
        defer bed.tearDown();

        // A request line longer than head_bytes_max with no CRLF: 414.
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
        try bed.setUp(std.testing.allocator, 3, false);
        defer bed.tearDown();

        // A valid request line, then a header section that overflows the
        // buffer before the terminating CRLF: 431.
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
        try bed.setUp(std.testing.allocator, 4, false);
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
        try bed.setUp(std.testing.allocator, 5, false);
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

test "l7: a valid request is closed without a response (upstream leg pending)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, 6, false);
    defer bed.tearDown();

    try bed.exchange("GET /path HTTP/1.1\r\nHost: origin.example\r\n\r\n");

    // No response yet — the upstream leg lands next slice — but the
    // connection is torn down cleanly and accounted for.
    try std.testing.expect(bed.client.closed);
    try std.testing.expectEqual(@as(usize, 0), bed.client.response().len);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_bad_request"));
    try bed.expectDrained();
}

test "l7: rejects survive 1-byte adversarial delivery across seeds" {
    // The head arrives one byte per recv: the parse-retry loop must reach
    // the same verdict however the request is fragmented (§7).
    var seed: u64 = 1;
    while (seed <= 15) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, seed, true);
        defer bed.tearDown();

        try bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");

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
    try bed.setUp(std.testing.allocator, 7, false);
    defer bed.tearDown();

    // A partial head with no terminator: the client sends it and then
    // goes silent, so only the head-read deadline can end the connection.
    try bed.exchange("GET / HTTP/1.1\r\nHost: a\r\n");

    try std.testing.expect(bed.client.closed);
    try std.testing.expectEqual(@as(usize, 0), bed.client.response().len);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: the head-ingestion path allocates nothing after init" {
    // §9 zero-alloc gate for L7: run a reject exchange (head recv, parse,
    // static response, lingering close, teardown) under a counting
    // allocator, then again under one that *fails* past the init count.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var bed: Http1Bed = undefined;
    try bed.setUp(failing.allocator(), 9, true);
    defer bed.tearDown();
    const allocations_after_init = failing.allocations;
    try bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");
    try bed.expectDrained();
    try std.testing.expectEqual(allocations_after_init, failing.allocations);

    var strict = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = allocations_after_init,
    });
    var strict_bed: Http1Bed = undefined;
    try strict_bed.setUp(strict.allocator(), 9, true);
    defer strict_bed.tearDown();
    try strict_bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");
    try strict_bed.expectDrained();
}

test "l7: an http listener admits without a relay buffer" {
    // The idle L7 connection holds a slot only (§5): even with the relay
    // pool sized to zero-usable it still admits and rejects.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, 8, false);
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("shed_relay_buffers"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try bed.expectDrained();
}
