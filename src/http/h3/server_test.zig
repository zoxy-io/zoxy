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

/// The bed's options with a request cap of one: the second request on a
/// connection is the one that reaches it, so its answer is the last.
const capped_options: Options = .{
    .listeners = &.{.{
        .bind = .{ .ip = loopback(listen_port) },
        .tls = .{ .cert_pem = cert_pem, .key_pem = key_pem, .label = "the test's fixture" },
        .protocol = .{ .http = .{
            .target = .{ .cluster = "origin" },
            .max_body_bytes = defaults.max_body_bytes,
            .keepalive_requests = 1,
            .quic = .{ .bind = .{ .ip = loopback(listen_port) } },
        } },
    }},
    .clusters = options.clusters,
    .timeouts = options.timeouts,
    .limits = options.limits,
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
    /// A second client, started when the first is done — while its
    /// connection still holds its slot through the closing period.
    second: Client,
    second_requests: []const TestClient.Request,

    fn create(seed: u64) !*Bed {
        return createUnder(seed, .{});
    }

    /// Under the datagram adversary `adversary` states.
    fn createUnder(seed: u64, adversary: SimIo.Adversary) !*Bed {
        return createWith(seed, adversary, &options);
    }

    /// Under the options `stated` gives, for a test that needs a timeout
    /// or a limit other than the bed's own.
    fn createWith(seed: u64, adversary: SimIo.Adversary, stated: *const Options) !*Bed {
        const bed = try std.testing.allocator.create(Bed);
        errdefer std.testing.allocator.destroy(bed);
        bed.arena_state = .init(std.testing.allocator);
        errdefer bed.arena_state.deinit();
        const arena = bed.arena_state.allocator();
        bed.config = try config_module.resolve(arena, stated);
        const limits = bed.config.limits;
        try bed.sim_io.init(arena, .{
            .seed = seed,
            .adversary = adversary,
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

    fn onFirstDone(context: *anyopaque) void {
        const bed: *Bed = @ptrCast(@alignCast(context));
        var seed: [64]u8 = undefined;
        for (&seed, 0..) |*octet, index| octet.* = @intCast(index + 101);
        bed.second.start(&bed.sim_io, loopback(listen_port), bed.second_requests, seed, onClientDone, bed) catch unreachable;
    }

    /// Two clients, the second after the first.
    fn runPair(bed: *Bed, first: []const TestClient.Request, second: []const TestClient.Request) !void {
        bed.second_requests = second;
        var seed: [64]u8 = undefined;
        for (&seed, 0..) |*octet, index| octet.* = @intCast(index + 1);
        try bed.client.start(&bed.sim_io, loopback(listen_port), first, seed, onFirstDone, bed);
        try bed.sim_io.run();
        try std.testing.expect(bed.second.done);
        try std.testing.expect(bed.server.isIdle());
        try std.testing.expect(bed.server.reconcile());
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

test "h3 server: an uppercase field name is H3_MESSAGE_ERROR on its stream, and its sibling is answered" {
    // RFC 9114 §4.2: a field name with an uppercase character is malformed,
    // which cancels the request it is on and nothing else.
    const bed = try Bed.create(3);
    defer bed.destroy();
    try bed.run(&.{
        .{ .path = "/a", .headers = &.{.{ .name = "X-Upper", .value = "1" }} },
        .{ .path = "/hello" },
    });
    try std.testing.expect(bed.client.answers[0].reset);
    try std.testing.expectEqual(@as(u16, 0), bed.client.answers[0].status);
    try std.testing.expectEqual(@as(u16, 200), bed.client.answers[1].status);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("h3_malformed_requests"));
}

test "h3 server: a field section that does not decode closes the connection with QPACK's error" {
    // RFC 9204 §2.2: a representation naming a dynamic table entry the
    // server never offered (it advertises a capacity of zero) cannot decode.
    const bed = try Bed.create(4);
    defer bed.destroy();
    try bed.run(&.{.{ .raw_section = &.{ 0x00, 0x00, 0x80 } }});
    try std.testing.expectEqual(@as(u16, 0), bed.client.answers[0].status);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("h3_qpack_failures"));
    try std.testing.expectEqual(@as(u32, 0), bed.origin.answered);
}

/// A long-header datagram in a version this server does not speak, sent
/// from a socket of its own, and the Version Negotiation it earns read.
const VersionProbe = struct {
    io: *SimIo,
    socket: SimIo.UdpSocket,
    datagram: [1200]u8,
    send_completion: SimIo.DatagramCompletion,
    receive_completion: SimIo.DatagramCompletion,
    answer: [256]u8,
    answer_len: u32,
    bed: *Bed,

    fn start(probe: *VersionProbe, bed: *Bed) !void {
        probe.io = &bed.sim_io;
        probe.bed = bed;
        probe.answer_len = 0;
        probe.send_completion = .{};
        probe.receive_completion = .{};
        probe.socket = try probe.io.udpBind(.{ .ip4 = .loopback(0) });
        @memset(&probe.datagram, 0);
        // Long header, Initial type bits; version 0x0a0a0a0a (RFC 9000 §15's
        // reserved pattern); an eight-octet destination and source.
        probe.datagram[0] = 0xc0;
        std.mem.writeInt(u32, probe.datagram[1..5], 0x0a0a_0a0a, .big);
        probe.datagram[5] = 8;
        @memset(probe.datagram[6..14], 0x11);
        probe.datagram[14] = 8;
        @memset(probe.datagram[15..23], 0x22);
        const server = loopback(listen_port);
        probe.io.recvFrom(probe.socket, &probe.answer, &probe.receive_completion, VersionProbe, probe, onAnswer);
        probe.io.sendTo(probe.socket, &probe.datagram, 0, &server, &probe.send_completion, VersionProbe, probe, onSent);
    }

    fn onSent(probe: *VersionProbe, result: Io.SendToError!u32) void {
        const sent = result catch 0;
        assert(sent == probe.datagram.len);
    }

    fn onAnswer(probe: *VersionProbe, result: Io.RecvFromError!Io.Datagram) void {
        const datagram = result catch return;
        probe.answer_len = datagram.len;
        probe.io.udpClose(probe.socket);
        probe.bed.origin.stop();
        probe.bed.server.beginDrain();
    }
};

test "h3 server: a datagram in a version it does not speak is answered with Version Negotiation" {
    const bed = try Bed.create(5);
    defer bed.destroy();
    const probe = try std.testing.allocator.create(VersionProbe);
    defer std.testing.allocator.destroy(probe);
    try probe.start(bed);
    try bed.sim_io.run();
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("h3_version_negotiations"));
    // RFC 9000 §17.2.1: version zero, and the client's IDs echoed swapped.
    try std.testing.expect(probe.answer_len >= 7);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, probe.answer[1..5], .big));
    try std.testing.expect(bed.server.isIdle());
}

test "h3 server: a client the pool's pressure Retries proves its address and is served" {
    // The first connection holds one of the two slots through its closing
    // period, so the second meets the watermark: a Retry, its token
    // returned in the next Initial, and the connection then admitted under
    // the ID the Retry named (RFC 9000 §8.1.2, §7.3).
    const bed = try Bed.create(6);
    defer bed.destroy();
    try bed.runPair(&.{.{ .path = "/one" }}, &.{.{ .path = "/two" }});
    try std.testing.expectEqual(@as(u16, 200), bed.client.answers[0].status);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("h3_retries"));
    try std.testing.expectEqual(@as(u16, 200), bed.second.answers[0].status);
    try std.testing.expectEqualStrings("hello", bed.second.answers[0].bodyBytes());
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("h3_handshakes"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("h3_tokens_refused"));
}

test "h3 server: a Retried client's Initial, delivered twice, starts one connection" {
    // After a Retry the client's Initials carry the ID the Retry named until
    // it hears this side's; a copy of one must find the connection the
    // first copy started, not admit a second the client will never finish.
    const bed = try Bed.createUnder(7, .{ .partial_io = false, .udp_duplicate_percent = 100 });
    defer bed.destroy();
    try bed.runPair(&.{.{ .path = "/one" }}, &.{.{ .path = "/two" }});
    try std.testing.expectEqual(@as(u16, 200), bed.second.answers[0].status);
    // Each copy of its first Initial is Retried on its own — a Retry is
    // stateless — and the client takes the first (RFC 9000 §17.2.5.2).
    try std.testing.expect(bed.server.counters.get("h3_retries") >= 1);
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("h3_admitted"));
    // The pool is full while the copy arrives, so a copy taken for a new
    // client is shed rather than admitted — which says the same thing.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("h3_shed_connections"));
}

test "h3 server: a connection the request cap ends closes only once the client has heard all of it" {
    // The first request is answered; the second reaches the cap of one, so
    // the GOAWAY names it and it is refused. With no exchange left, the
    // connection closed in the same pass — and a closing endpoint sends
    // CONNECTION_CLOSE and nothing else (RFC 9000 §10.2.1), so the first
    // answer, handed to the transport and not yet sent, never was. On every
    // seed. zrk saw a clean close with that request in flight: one read
    // error per capped connection, exactly 1,000 on the benchmark's c1k-h3.
    for (1..9) |seed| {
        const bed = try Bed.createWith(seed, .{ .partial_io = false }, &capped_options);
        defer bed.destroy();
        try bed.run(&.{ .{ .path = "/one" }, .{ .path = "/two" } });
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_keepalive_requests_capped"));
        // The GOAWAY reached the client, naming the second request.
        try std.testing.expectEqual(@as(?u64, 4), bed.client.goaway);
        // The first, below it, arrived whole.
        try std.testing.expect(bed.client.answers[0].finished);
        try std.testing.expectEqualStrings("hello", bed.client.answers[0].bodyBytes());
        // The second was refused, which is what lets a client send it
        // again on another connection (RFC 9114 §5.2).
        try std.testing.expect(bed.client.answers[1].reset);
        try std.testing.expect(!bed.client.answers[1].finished);
        try std.testing.expectEqual(@as(u32, 1), bed.origin.answered);
    }
}

/// A client of the capped bed that goes once its answers are in
/// (`TestClient.vanishes`), and a look at the server's QUIC pool a while
/// later: long past a few probe timeouts, far short of the idle window.
const GoneClient = struct {
    bed: *Bed,
    timer: SimIo.Completion,
    /// QUIC connections the server still held at the look.
    held: ?u32,

    const requests = [_]TestClient.Request{ .{ .path = "/one" }, .{ .path = "/two" } };
    const look_after_ns: u64 = 2 * std.time.ns_per_s;

    fn start(gone: *GoneClient, bed: *Bed, seed_base: u8) !void {
        assert(@as(u64, bed.config.idle_timeout_ms) * std.time.ns_per_ms > 10 * look_after_ns);
        gone.bed = bed;
        gone.timer = .{};
        gone.held = null;
        var seed: [64]u8 = undefined;
        for (&seed, 0..) |*octet, index| octet.* = @intCast(index + seed_base);
        try bed.client.start(&bed.sim_io, loopback(listen_port), &requests, seed, onClientDone, gone);
        bed.client.vanishes = true;
        bed.sim_io.timerStart(&gone.timer, look_after_ns, GoneClient, gone, onLook);
    }

    fn onClientDone(context: *anyopaque) void {
        _ = context;
    }

    fn onLook(gone: *GoneClient, result: Io.TimerError!void) void {
        result catch unreachable;
        var held: u32 = 0;
        for (gone.bed.server.h3_owners) |owner| {
            if (owner != null) held += 1;
        }
        gone.held = held;
        gone.bed.origin.stop();
        gone.bed.server.beginDrain();
    }
};

test "h3 server: a capped connection whose client has gone frees its slot in a few probe timeouts" {
    // #475. The cap of one answers the first request and refuses the
    // second at the GOAWAY, and the client goes without acknowledging the
    // last of it: a client whose final datagram, its acknowledgement and
    // its close, was lost. The connection waited for that acknowledgement
    // until an idle window after the GOAWAY, a minute here, and held its
    // whole slot throughout. Now its probes go unanswered and it closes a
    // few PTOs in.
    for (1..9) |seed| {
        const bed = try Bed.createWith(seed, .{ .partial_io = false }, &capped_options);
        defer bed.destroy();
        const gone = try std.testing.allocator.create(GoneClient);
        defer std.testing.allocator.destroy(gone);
        try gone.start(bed, @intCast(seed));
        try bed.sim_io.run();
        try std.testing.expect(bed.client.done);
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_keepalive_requests_capped"));
        try std.testing.expect(bed.client.answers[0].finished);
        try std.testing.expect(bed.client.answers[1].reset);
        try std.testing.expectEqual(@as(?u32, 0), gone.held);
        try std.testing.expect(bed.server.isIdle());
        try std.testing.expect(bed.server.reconcile());
    }
}

test "h3 server: a client the pool has no room for is refused, not left to time out" {
    // One HTTP/3 connection at a time. The second client starts while the
    // first's connection still holds the slot through its closing period,
    // so its Initial is shed. Unanswered, it waited out its handshake
    // timeout (#454); now it hears CONNECTION_REFUSED and ends at once.
    var stated = options;
    stated.limits.quic_connections = 1;
    const bed = try Bed.createWith(5, .{}, &stated);
    defer bed.destroy();
    try bed.runPair(&.{.{ .path = "/one" }}, &.{.{ .path = "/two" }});
    try std.testing.expect(bed.client.answers[0].finished);
    try std.testing.expect(bed.second.refused);
    try std.testing.expect(!bed.second.answers[0].finished);
    const shed = bed.server.counters.get("h3_shed_connections");
    try std.testing.expect(shed >= 1);
    // Every shed is answered: a send buffer was free for each.
    try std.testing.expectEqual(shed, bed.server.counters.get("h3_refused"));
    try std.testing.expectEqual(@as(u32, 1), bed.origin.answered);
}

/// A client that says one Initial and then nothing, ever: a TestClient's
/// real first datagram — a ClientHello the server opens and answers — taken
/// off a socket standing in for the server, the client abandoned, and the
/// datagram sent on once from a socket that closes as soon as it has. The
/// server's flight and its retransmission go unheard, so the client's 1200
/// octets are all its address ever proves (RFC 9000 §8.1), and nothing
/// afterwards hands the transport a clock.
const SilentClient = struct {
    io: *SimIo,
    bed: *Bed,
    client: Client,
    capture: SimIo.UdpSocket,
    sender: SimIo.UdpSocket,
    initial: [SimIo.datagram_bytes_max]u8,
    initial_len: u32,
    capture_completion: SimIo.DatagramCompletion,
    send_completion: SimIo.DatagramCompletion,
    drain_timer: SimIo.Completion,
    /// The drain left the connection closing with nothing it may send.
    closing: bool,

    /// Past the first probe timeout's retransmission, which spends what
    /// the amplification limit allows, and past the unheard window.
    const drain_after_ns: u64 = 1500 * std.time.ns_per_ms;

    fn start(probe: *SilentClient, bed: *Bed) !void {
        probe.io = &bed.sim_io;
        probe.bed = bed;
        probe.initial_len = 0;
        probe.closing = false;
        probe.capture_completion = .{};
        probe.send_completion = .{};
        probe.drain_timer = .{};
        probe.capture = try probe.io.udpBind(.{ .ip4 = .loopback(0) });
        probe.io.recvFrom(probe.capture, &probe.initial, &probe.capture_completion, SilentClient, probe, onCaptured);
        var seed: [64]u8 = undefined;
        for (&seed, 0..) |*octet, index| octet.* = @intCast(index + 1);
        const requests = [_]TestClient.Request{.{ .path = "/never" }};
        try probe.client.start(probe.io, probe.io.udpAddress(probe.capture), &requests, seed, onClientDone, probe);
        probe.io.timerStart(&probe.drain_timer, drain_after_ns, SilentClient, probe, onDrain);
    }

    fn onCaptured(probe: *SilentClient, result: Io.RecvFromError!Io.Datagram) void {
        const datagram = result catch unreachable;
        assert(datagram.len >= 1200);
        probe.initial_len = datagram.len;
        probe.io.udpClose(probe.capture);
        probe.client.abandon();
        probe.sender = probe.io.udpBind(.{ .ip4 = .loopback(0) }) catch unreachable;
        const server = loopback(listen_port);
        const initial = probe.initial[0..probe.initial_len];
        probe.io.sendTo(probe.sender, initial, 0, &server, &probe.send_completion, SilentClient, probe, onSent);
    }

    fn onSent(probe: *SilentClient, result: Io.SendToError!u32) void {
        const sent = result catch 0;
        assert(sent == probe.initial_len);
        probe.io.udpClose(probe.sender);
    }

    fn onClientDone(context: *anyopaque) void {
        _ = context;
    }

    fn onDrain(probe: *SilentClient, result: Io.TimerError!void) void {
        result catch unreachable;
        probe.bed.origin.stop();
        probe.bed.server.beginDrain();
        // The test's premise, held rather than assumed: the drain closed the
        // one connection, and its close has nowhere it may go.
        var held: u32 = 0;
        for (probe.bed.server.h3_owners) |owner| {
            const conn = owner orelse continue;
            held += 1;
            const quic = &conn.h3.?.quic;
            probe.closing = quic.state == .closing and !quic.wantsSend();
        }
        assert(held == 1);
    }
};

test "h3 server: a handshake drained once its client fell silent still ends, with nothing it may send" {
    // Soak #141. The drain closes a connection whose handshake never
    // confirmed outright, and the CONNECTION_CLOSE cannot go: the flight
    // and its retransmission spent the three times 1200 octets the client's
    // address allows. With no send, no clock saw the closing state, so the
    // transport had no timer; the deadline fell back to the unheard window,
    // long past, and the timer fired at the same instant forever. A short
    // idle window puts that fallback in the past, as the soak's seeds had.
    var stated = options;
    // The head budget must sit between the dial budget and the idle window.
    stated.timeouts.connect_ms = 50;
    stated.timeouts.idle_ms = 200;
    stated.timeouts.head_ms = defaults.headMs(stated.timeouts.connect_ms, stated.timeouts.idle_ms);
    const bed = try Bed.createWith(9, .{}, &stated);
    defer bed.destroy();
    const probe = try std.testing.allocator.create(SilentClient);
    defer std.testing.allocator.destroy(probe);
    try probe.start(bed);
    try bed.sim_io.run();
    try std.testing.expect(probe.closing);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("h3_admitted"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("h3_handshakes"));
    try std.testing.expect(bed.server.isIdle());
    try std.testing.expect(bed.server.reconcile());
}
