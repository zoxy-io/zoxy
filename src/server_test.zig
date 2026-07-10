//! Directed Server lifecycle scenarios over SimIo (§9): happy-path
//! accept → dial → teardown with pools draining to zero, every §8
//! exhaustion rung witnessed by its counter and by what the shed client
//! actually observes on the wire (RST vs FIN), connect-refused, and the
//! counter-reconciliation invariant after every scenario. The harness
//! plays origin and clients through the seam on the same loop.

const std = @import("std");

const config_module = @import("config.zig");
const Io = @import("io/Io.zig");
const Server = @import("Server.zig").Server;
const SimIo = @import("io/SimIo.zig");

const assert = std.debug.assert;

const ServerSim = Server(SimIo);

const Scenario = struct {
    io: *SimIo,
    server: *ServerSim,
    origin: Origin,
    clients: [4]Client,
    clients_count: u8,
    ended_count: u8 = 0,

    fn clientEnded(scenario: *Scenario) void {
        scenario.ended_count += 1;
        assert(scenario.ended_count <= scenario.clients_count);
        if (scenario.ended_count == scenario.clients_count) {
            scenario.server.beginDrain();
            scenario.origin.stopListening();
        }
    }

    fn outcomeCount(scenario: *const Scenario, outcome: Client.Outcome) u8 {
        var count: u8 = 0;
        for (scenario.clients[0..scenario.clients_count]) |*client| {
            if (client.outcome == outcome) count += 1;
        }
        return count;
    }
};

const Origin = struct {
    io: *SimIo = undefined,
    listener: SimIo.Listener = undefined,
    accept_completion: SimIo.Completion = .{},
    conns: [4]OriginConn = @splat(.{}),
    conns_count: u8 = 0,
    listening: bool = false,

    const OriginConn = struct {
        origin: *Origin = undefined,
        socket: SimIo.Socket = undefined,
        recv_completion: SimIo.Completion = .{},
        buffer: [64]u8 = undefined,
        done: bool = false,
    };

    fn start(origin: *Origin, io: *SimIo, address: std.Io.net.IpAddress) !void {
        origin.io = io;
        origin.listener = try io.listen(address);
        origin.listening = true;
        origin.armAccept();
    }

    fn armAccept(origin: *Origin) void {
        origin.io.accept(origin.listener, &origin.accept_completion, Origin, origin, onAccept);
    }

    fn onAccept(origin: *Origin, result: Io.AcceptError!SimIo.Socket) void {
        const socket = result catch |err| {
            assert(err == error.Canceled);
            return;
        };
        assert(origin.conns_count < origin.conns.len);
        const conn = &origin.conns[origin.conns_count];
        origin.conns_count += 1;
        conn.origin = origin;
        conn.socket = socket;
        origin.io.recv(socket, &conn.buffer, &conn.recv_completion, OriginConn, conn, onRecv);
        origin.armAccept();
    }

    fn onRecv(conn: *OriginConn, result: Io.RecvError!u32) void {
        if (result) |_| {
            conn.origin.io.recv(
                conn.socket,
                &conn.buffer,
                &conn.recv_completion,
                OriginConn,
                conn,
                onRecv,
            );
        } else |_| {
            conn.origin.io.closeNow(conn.socket);
            conn.done = true;
        }
    }

    fn stopListening(origin: *Origin) void {
        if (origin.listening) {
            origin.io.listenClose(origin.listener);
            origin.listening = false;
        }
    }
};

const Client = struct {
    scenario: *Scenario = undefined,
    connect_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    buffer: [64]u8 = undefined,
    socket: SimIo.Socket = undefined,
    outcome: Outcome = .pending,

    const Outcome = enum(u8) { pending, refused, eof, reset };

    fn start(client: *Client, scenario: *Scenario, address: std.Io.net.IpAddress) void {
        client.scenario = scenario;
        scenario.io.connect(address, &client.connect_completion, Client, client, onConnect);
    }

    fn onConnect(client: *Client, result: Io.ConnectError!SimIo.Socket) void {
        client.socket = result catch {
            client.outcome = .refused;
            client.scenario.clientEnded();
            return;
        };
        client.armRecv();
    }

    fn armRecv(client: *Client) void {
        client.scenario.io.recv(
            client.socket,
            &client.buffer,
            &client.recv_completion,
            Client,
            client,
            onRecv,
        );
    }

    fn onRecv(client: *Client, result: Io.RecvError!u32) void {
        if (result) |_| {
            client.armRecv();
            return;
        } else |err| {
            client.outcome = switch (err) {
                error.EndOfStream => .eof,
                error.Reset => .reset,
                else => .eof,
            };
            client.scenario.io.closeNow(client.socket);
            client.scenario.clientEnded();
        }
    }
};

const TestBed = struct {
    arena_state: std.heap.ArenaAllocator,
    sim_io: SimIo,
    endpoints: [1]std.Io.net.IpAddress,
    clusters: [1]config_module.Config.Cluster,
    listeners: [1]config_module.Config.Listener,
    cfg: config_module.Config,
    server: ServerSim,
    scenario: Scenario,

    fn bindAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
    }

    fn originAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
    }

    fn setUp(
        bed: *TestBed,
        options: ServerSim.InitOptions,
        sim_options: SimIo.Options,
        origin_listens: bool,
    ) !void {
        bed.arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer bed.arena_state.deinit();
        const arena = bed.arena_state.allocator();

        try bed.sim_io.init(arena, sim_options);
        bed.endpoints = .{originAddress()};
        bed.clusters = .{.{ .name = "origin", .endpoints = &bed.endpoints }};
        bed.listeners = .{.{ .bind_address = bindAddress(), .cluster_index = 0 }};
        bed.cfg = .{
            .listeners = &bed.listeners,
            .clusters = &bed.clusters,
            .connect_timeout_ms = 50,
            .idle_timeout_ms = 1000,
            .drain_deadline_ms = 1000,
        };
        try bed.server.init(arena, &bed.sim_io, &bed.cfg, options);
        try bed.server.start();

        bed.scenario = .{
            .io = &bed.sim_io,
            .server = &bed.server,
            .origin = .{},
            .clients = @splat(.{}),
            .clients_count = 0,
        };
        if (origin_listens) {
            try bed.scenario.origin.start(&bed.sim_io, originAddress());
        }
    }

    fn startClients(bed: *TestBed, count: u8) void {
        assert(count >= 1);
        assert(count <= bed.scenario.clients.len);
        bed.scenario.clients_count = count;
        for (bed.scenario.clients[0..count]) |*client| {
            client.start(&bed.scenario, bindAddress());
        }
    }

    fn tearDown(bed: *TestBed) void {
        bed.arena_state.deinit();
    }

    fn expectDrained(bed: *TestBed) !void {
        try std.testing.expect(bed.server.isIdle());
        try std.testing.expect(bed.server.counters.reconcile(0));
        try std.testing.expect(bed.sim_io.sockets.isFullyReleased());
    }
};

test "server: happy lifecycle drains pools and reconciles across seeds" {
    var seed: u64 = 1;
    while (seed <= 10) : (seed += 1) {
        var bed: TestBed = undefined;
        try bed.setUp(
            .{ .conn_slots = 4, .relay_buffers = 2 },
            .{ .seed = seed, .adversary = .{ .connect_delay_ns_max = 2_000_000 } },
            true,
        );
        defer bed.tearDown();

        bed.startClients(1);
        try bed.sim_io.run();

        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("accepted"));
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
        try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
        // The slice-7 stub tears down right after dialing, so the origin's
        // accept may adversarially lose the race against the end of the
        // scenario; if it did accept, it must have observed the close.
        // Slice 8's relay makes origin participation deterministic.
        try std.testing.expect(bed.scenario.origin.conns_count <= 1);
        if (bed.scenario.origin.conns_count == 1) {
            try std.testing.expect(bed.scenario.origin.conns[0].done);
        }
        try bed.expectDrained();
    }
}

test "server: conn-slot exhaustion sheds with RST; deadline reaps the holder" {
    var bed: TestBed = undefined;
    try bed.setUp(
        .{ .conn_slots = 1, .relay_buffers = 1 },
        .{ .seed = 21 },
        true,
    );
    defer bed.tearDown();

    // Pin the proxy→origin dial only; the clients' own connects stay live.
    bed.sim_io.blackholeAddress(TestBed.originAddress());
    bed.startClients(2);
    try bed.sim_io.run();

    // One client held the only slot until the connect deadline reaped it
    // (orderly FIN); the other was shed at the gate with an RST.
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("accepted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("shed_conn_slots"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.reset));
    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u8, 0), bed.scenario.origin.conns_count);
    try bed.expectDrained();
}

test "server: relay-buffer exhaustion sheds with a quiet close" {
    var bed: TestBed = undefined;
    try bed.setUp(
        .{ .conn_slots = 2, .relay_buffers = 1 },
        .{ .seed = 22 },
        true,
    );
    defer bed.tearDown();

    bed.sim_io.blackholeAddress(TestBed.originAddress());
    bed.startClients(2);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("shed_relay_buffers"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("shed_conn_slots"));
    // Both clients end with FIN: the shed one quietly, the admitted one
    // when the deadline reaped its black-holed dial.
    try std.testing.expectEqual(@as(u8, 2), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u8, 0), bed.scenario.outcomeCount(.reset));
    try bed.expectDrained();
}

test "server: refused upstream tears the connection down and is counted" {
    var bed: TestBed = undefined;
    try bed.setUp(
        .{ .conn_slots = 2, .relay_buffers = 1 },
        .{ .seed = 23 },
        false, // no origin listening: every dial is refused
    );
    defer bed.tearDown();

    bed.startClients(1);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try bed.expectDrained();
}
