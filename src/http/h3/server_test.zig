//! HTTP/3 through the whole server (#449), under the simulator: a TLS
//! `http` listener with a QUIC binding, an HTTP/1.1 origin behind it, and
//! an HTTP/3 client (`TestClient`) whose requests cross the endpoint, the
//! handshake, the session, the shared exchange and the origin, and whose
//! answers come back the same way. Then the drain: the client's close,
//! the connection's closing period, the endpoint's own close, and every
//! pool given back.

const std = @import("std");

const config_module = @import("../../config.zig");
const extension = @import("../../extension.zig");
const Options = @import("../../Options.zig");
const Server = @import("../../Server.zig").Server;
const SimIo = @import("../../io/SimIo.zig");
const Io = @import("../../io/io.zig");
const Credentials = @import("../../tls/Credentials.zig");
const defaults = @import("../../defaults.zig");
const TestClient = @import("TestClient.zig");

const assert = std.debug.assert;

const cert_pem = @embedFile("../../tls/testdata/cert.pem");
const key_pem = @embedFile("../../tls/testdata/key.pem");

const runtime: extension.Runtime = .{ .Io = SimIo, .extensions = .{} };
const ServerType = Server(runtime);
const Client = TestClient.TestClient(SimIo);

fn loopback(port: u16) std.Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
}

const listen_port: u16 = 18443;
const origin_port: u16 = 19443;
const origin_answer = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";

const options: Options = .{
    .listeners = &.{.{
        .bind = .{ .ip = loopback(listen_port) },
        .tls = .{ .cert_pem = cert_pem, .key_pem = key_pem, .label = "the test's fixture" },
        .protocol = .{ .http = .{
            .target = .{ .cluster = "origin" },
            .max_body_bytes = defaults.max_body_bytes,
            .keepalive_requests = defaults.keepalive_requests,
            .quic = .{ .bind = .{ .ip = loopback(listen_port) } },
        } },
    }},
    .clusters = &.{.{
        .name = "origin",
        .endpoints = &.{.{ .address = .{ .ip = loopback(origin_port) } }},
        .pick = defaults.pick,
    }},
    .timeouts = defaults.timeouts,
    .limits = .{
        .conn_slots = 16,
        .relay_buffers = 8,
        .tls_engines = 4,
        .h2_streams = 8,
        .quic_connections = 2,
    },
};

/// An origin that answers every request head with `origin_answer` and
/// closes.
const Origin = struct {
    io: *SimIo,
    listener: SimIo.Listener,
    accept_completion: SimIo.Completion,
    conns: [4]OriginConn,
    answered: u32,
    listening: bool,

    fn start(origin: *Origin, io: *SimIo) !void {
        origin.io = io;
        origin.accept_completion = .{};
        origin.conns = @splat(.{});
        origin.answered = 0;
        origin.listener = try io.listen(&.{ .ip = loopback(origin_port) }, null);
        origin.listening = true;
        io.accept(origin.listener, &origin.accept_completion, Origin, origin, onAccept);
    }

    fn onAccept(origin: *Origin, result: Io.AcceptError!SimIo.Socket) void {
        const socket = result catch return;
        for (&origin.conns) |*conn| {
            if (conn.open) continue;
            conn.* = .{ .origin = origin, .socket = socket, .open = true };
            conn.armRecv();
            break;
        } else origin.io.closeNow(socket);
        origin.io.accept(origin.listener, &origin.accept_completion, Origin, origin, onAccept);
    }

    fn stop(origin: *Origin) void {
        if (origin.listening) origin.io.listenClose(origin.listener);
        origin.listening = false;
        for (&origin.conns) |*conn| {
            if (conn.open) conn.close();
        }
    }
};

const OriginConn = struct {
    origin: *Origin = undefined,
    socket: SimIo.Socket = undefined,
    recv_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    head: [1024]u8 = undefined,
    head_len: u16 = 0,
    sent_len: u16 = 0,
    open: bool = false,

    fn armRecv(conn: *OriginConn) void {
        conn.origin.io.recv(conn.socket, conn.head[conn.head_len..], &conn.recv_completion, OriginConn, conn, onRecv);
    }

    fn onRecv(conn: *OriginConn, result: Io.RecvError!u32) void {
        const received = result catch return conn.close();
        conn.head_len += @intCast(received);
        if (std.mem.indexOf(u8, conn.head[0..conn.head_len], "\r\n\r\n") == null) {
            if (conn.head_len == conn.head.len) return conn.close();
            return conn.armRecv();
        }
        conn.armSend();
    }

    fn armSend(conn: *OriginConn) void {
        conn.origin.io.send(conn.socket, origin_answer[conn.sent_len..], &conn.send_completion, OriginConn, conn, onSend);
    }

    fn onSend(conn: *OriginConn, result: Io.SendError!u32) void {
        const sent = result catch return conn.close();
        conn.sent_len += @intCast(sent);
        if (conn.sent_len < origin_answer.len) return conn.armSend();
        conn.origin.answered += 1;
        conn.close();
    }

    fn close(conn: *OriginConn) void {
        assert(conn.open);
        conn.origin.io.closeNow(conn.socket);
        conn.open = false;
    }
};

const Bed = struct {
    arena_state: std.heap.ArenaAllocator,
    sim_io: SimIo,
    config: config_module.Config,
    server: ServerType,
    credentials: [1]?Credentials,
    origin: Origin,
    client: Client,

    fn create(seed: u64) !*Bed {
        const bed = try std.testing.allocator.create(Bed);
        errdefer std.testing.allocator.destroy(bed);
        bed.arena_state = .init(std.testing.allocator);
        errdefer bed.arena_state.deinit();
        const arena = bed.arena_state.allocator();
        bed.config = try config_module.resolve(arena, &options);
        const limits = bed.config.limits;
        try bed.sim_io.init(arena, .{
            .seed = seed,
            .buffer_group_count = limits.head_buffers,
            .buffer_group_bytes = limits.head_buffer_bytes,
        });
        try bed.server.init(arena, &bed.sim_io, &bed.config, limits);
        try bed.server.bindExtensions(&.{ .arena = arena });
        bed.credentials = .{try Credentials.load(arena, cert_pem, key_pem, .{ .deterministic_nonce = true })};
        bed.server.setTlsCredentials(&bed.credentials);
        try bed.origin.start(&bed.sim_io);
        try bed.server.start();
        return bed;
    }

    fn destroy(bed: *Bed) void {
        if (bed.credentials[0]) |*credentials| credentials.deinit();
        bed.arena_state.deinit();
        std.testing.allocator.destroy(bed);
    }

    /// The client is done: the server drains, which is what ends the run.
    fn onClientDone(context: *anyopaque) void {
        const bed: *Bed = @ptrCast(@alignCast(context));
        bed.origin.stop();
        bed.server.beginDrain();
    }

    fn run(bed: *Bed, requests: []const TestClient.Request) !void {
        var seed: [64]u8 = undefined;
        for (&seed, 0..) |*octet, index| octet.* = @intCast(index + 1);
        try bed.client.start(&bed.sim_io, loopback(listen_port), requests, seed, onClientDone, bed);
        try bed.sim_io.run();
        try std.testing.expect(bed.client.done);
        try std.testing.expect(bed.server.isIdle());
        try std.testing.expect(bed.server.reconcile());
    }
};

test "h3 server: a request over QUIC reaches the origin, and its answer comes back" {
    const bed = try Bed.create(1);
    defer bed.destroy();
    try bed.run(&.{.{ .path = "/hello" }});
    const answer = &bed.client.answers[0];
    try std.testing.expectEqual(@as(u16, 200), answer.status);
    try std.testing.expect(answer.finished);
    try std.testing.expectEqualStrings("hello", answer.bodyBytes());
    try std.testing.expectEqual(@as(u32, 1), bed.origin.answered);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("h3_admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("h3_handshakes"));
}

test "h3 server: a request answered on the spot — a 400 staged while it opens — goes back whole" {
    // A space cannot split an HTTP/1.1 request line: the head the request is
    // written out as does not parse, and §7 answers it at once, from inside
    // the open that decoded it.
    const bed = try Bed.create(2);
    defer bed.destroy();
    try bed.run(&.{ .{ .path = "/a b" }, .{ .path = "/hello" } });
    try std.testing.expectEqual(@as(u16, 400), bed.client.answers[0].status);
    try std.testing.expect(bed.client.answers[0].finished);
    try std.testing.expectEqual(@as(u16, 200), bed.client.answers[1].status);
    try std.testing.expectEqualStrings("hello", bed.client.answers[1].bodyBytes());
    try std.testing.expectEqual(@as(u32, 1), bed.origin.answered);
}
