//! Directed Server scenarios over SimIo (§9). With the relay in place
//! (slice 8) these prove the actual L4 promise: a client's bytes reach
//! the origin and the echo comes back byte-exact through the proxy,
//! under 1-byte partial deliveries and adversarial ordering; FINs relay
//! in both directions; idle connections meet the deadline; every §8
//! exhaustion rung is witnessed by its counter and by what the shed
//! client observes on the wire (RST vs FIN); and counters reconcile
//! with pools drained after every scenario.

const std = @import("std");

const config_module = @import("config.zig");
const Io = @import("io/Io.zig");
const Server = @import("Server.zig").Server;
const SimIo = @import("io/SimIo.zig");

const assert = std.debug.assert;

const ServerSim = Server(SimIo);

const echo_token = "proxied-echo-token-0123456789abc";

pub const Scenario = struct {
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

/// A scripted origin: echoes every chunk back (strict recv → send →
/// recv, like the proxy), closes on the client's FIN — or, in `reset`
/// mode, answers the first chunk with an RST (misbehaving origin, §9).
pub const Origin = struct {
    io: *SimIo = undefined,
    listener: SimIo.Listener = undefined,
    accept_completion: SimIo.Completion = .{},
    conns: [4]OriginConn = @splat(.{}),
    conns_count: u8 = 0,
    listening: bool = false,
    mode: Mode = .echo,

    const Mode = enum(u8) { echo, reset_on_first_chunk };

    const OriginConn = struct {
        origin: *Origin = undefined,
        socket: SimIo.Socket = undefined,
        recv_completion: SimIo.Completion = .{},
        send_completion: SimIo.Completion = .{},
        buffer: [64]u8 = undefined,
        transfer_len: u32 = 0,
        sent_len: u32 = 0,
        done: bool = false,

        fn armRecv(conn: *OriginConn) void {
            conn.origin.io.recv(
                conn.socket,
                &conn.buffer,
                &conn.recv_completion,
                OriginConn,
                conn,
                onRecv,
            );
        }

        fn onRecv(conn: *OriginConn, result: Io.RecvError!u32) void {
            const received = result catch {
                conn.origin.io.closeNow(conn.socket);
                conn.done = true;
                return;
            };
            assert(received >= 1);
            if (conn.origin.mode == .reset_on_first_chunk) {
                conn.origin.io.setLingerRst(conn.socket) catch unreachable;
                conn.origin.io.closeNow(conn.socket);
                conn.done = true;
                return;
            }
            conn.transfer_len = received;
            conn.sent_len = 0;
            conn.armSend();
        }

        fn armSend(conn: *OriginConn) void {
            assert(conn.sent_len < conn.transfer_len);
            conn.origin.io.send(
                conn.socket,
                conn.buffer[conn.sent_len..conn.transfer_len],
                &conn.send_completion,
                OriginConn,
                conn,
                onSend,
            );
        }

        fn onSend(conn: *OriginConn, result: Io.SendError!u32) void {
            const sent = result catch {
                conn.origin.io.closeNow(conn.socket);
                conn.done = true;
                return;
            };
            conn.sent_len += sent;
            assert(conn.sent_len <= conn.transfer_len);
            if (conn.sent_len < conn.transfer_len) {
                conn.armSend();
            } else {
                conn.armRecv();
            }
        }
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
        conn.armRecv();
        origin.armAccept();
    }

    fn stopListening(origin: *Origin) void {
        if (origin.listening) {
            origin.io.listenClose(origin.listener);
            origin.listening = false;
        }
    }
};

/// A scripted client. In `exchange` mode it sends the token, expects the
/// byte-exact echo, FINs, and waits for the proxied FIN back; otherwise
/// it connects and stays silent (idle-deadline fodder).
pub const Client = struct {
    scenario: *Scenario = undefined,
    connect_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    receive_buffer: [64]u8 = undefined,
    socket: SimIo.Socket = undefined,
    exchange: bool = false,
    sent_len: u32 = 0,
    received_len: u32 = 0,
    fin_sent: bool = false,
    send_pending: bool = false,
    terminal_outcome: ?Outcome = null,
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
        if (client.exchange) {
            client.armSend();
        }
    }

    fn armSend(client: *Client) void {
        assert(client.sent_len < echo_token.len);
        assert(!client.send_pending);
        client.send_pending = true;
        client.scenario.io.send(
            client.socket,
            echo_token[client.sent_len..],
            &client.send_completion,
            Client,
            client,
            onSend,
        );
    }

    fn onSend(client: *Client, result: Io.SendError!u32) void {
        assert(client.send_pending);
        client.send_pending = false;
        // A send error mid-teardown is legal; the recv path decides the
        // connection's fate.
        const sent = result catch {
            client.settleIfTerminal();
            return;
        };
        client.sent_len += sent;
        assert(client.sent_len <= echo_token.len);
        if (client.terminal_outcome != null) {
            client.settleIfTerminal();
        } else if (client.sent_len < echo_token.len) {
            client.armSend();
        }
    }

    fn armRecv(client: *Client) void {
        client.scenario.io.recv(
            client.socket,
            client.receive_buffer[client.received_len..],
            &client.recv_completion,
            Client,
            client,
            onRecv,
        );
    }

    fn onRecv(client: *Client, result: Io.RecvError!u32) void {
        const received = result catch |err| {
            // The §5 rule applies to the harness too: the socket may only
            // close once the concurrent send op has also settled.
            client.terminal_outcome = switch (err) {
                error.EndOfStream => .eof,
                error.Reset => .reset,
                else => .eof,
            };
            client.settleIfTerminal();
            return;
        };
        client.received_len += received;
        assert(client.received_len <= echo_token.len);
        if (client.exchange) {
            if (client.received_len == echo_token.len) {
                if (!client.fin_sent) {
                    client.fin_sent = true;
                    client.scenario.io.shutdown(client.socket, .write);
                }
            }
        }
        client.armRecv();
    }

    fn settleIfTerminal(client: *Client) void {
        if (client.terminal_outcome) |terminal| {
            if (!client.send_pending) {
                client.outcome = terminal;
                client.scenario.io.closeNow(client.socket);
                client.scenario.clientEnded();
            }
        }
    }
};

pub const TestBed = struct {
    arena_state: std.heap.ArenaAllocator,
    sim_io: SimIo,
    endpoints: [1]std.Io.net.IpAddress,
    clusters: [1]config_module.Config.Cluster,
    listeners: [1]config_module.Config.Listener,
    cfg: config_module.Config,
    server: ServerSim,
    scenario: Scenario,

    pub const SetUpOptions = struct {
        server: ServerSim.InitOptions = .{ .conn_slots = 4, .relay_buffers = 2 },
        sim: SimIo.Options,
        origin_listens: bool = true,
        idle_timeout_ms: u32 = 1000,
    };

    fn bindAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
    }

    fn originAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
    }

    pub fn setUp(bed: *TestBed, gpa: std.mem.Allocator, options: SetUpOptions) !void {
        bed.arena_state = std.heap.ArenaAllocator.init(gpa);
        errdefer bed.arena_state.deinit();
        const arena = bed.arena_state.allocator();

        try bed.sim_io.init(arena, options.sim);
        bed.endpoints = .{originAddress()};
        bed.clusters = .{.{ .name = "origin", .endpoints = &bed.endpoints }};
        bed.listeners = .{.{ .bind_address = bindAddress(), .cluster_index = 0 }};
        bed.cfg = .{
            .listeners = &bed.listeners,
            .clusters = &bed.clusters,
            .connect_timeout_ms = 50,
            .idle_timeout_ms = options.idle_timeout_ms,
            .drain_deadline_ms = 1000,
        };
        try bed.server.init(arena, &bed.sim_io, &bed.cfg, options.server);
        try bed.server.start();

        bed.scenario = .{
            .io = &bed.sim_io,
            .server = &bed.server,
            .origin = .{},
            .clients = @splat(.{}),
            .clients_count = 0,
        };
        if (options.origin_listens) {
            try bed.scenario.origin.start(&bed.sim_io, originAddress());
        }
    }

    pub fn startClients(bed: *TestBed, count: u8, exchange: bool) void {
        assert(count >= 1);
        assert(count <= bed.scenario.clients.len);
        bed.scenario.clients_count = count;
        for (bed.scenario.clients[0..count]) |*client| {
            client.exchange = exchange;
            client.start(&bed.scenario, bindAddress());
        }
    }

    pub fn tearDown(bed: *TestBed) void {
        bed.arena_state.deinit();
    }

    pub fn expectDrained(bed: *TestBed) !void {
        try std.testing.expect(bed.server.isIdle());
        try std.testing.expect(bed.server.counters.reconcile(0));
        try std.testing.expect(bed.sim_io.sockets.isFullyReleased());
    }
};

test "relay: proxied echo is byte-exact under the adversary across seeds" {
    var seed: u64 = 1;
    while (seed <= 15) : (seed += 1) {
        var bed: TestBed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .sim = .{
                .seed = seed,
                .adversary = .{ .partial_io = true, .connect_delay_ns_max = 2_000_000 },
            },
        });
        defer bed.tearDown();

        bed.startClients(1, true);
        try bed.sim_io.run();

        const client = &bed.scenario.clients[0];
        try std.testing.expectEqual(Client.Outcome.eof, client.outcome);
        try std.testing.expectEqualStrings(
            echo_token,
            client.receive_buffer[0..client.received_len],
        );
        try std.testing.expectEqual(@as(u8, 1), bed.scenario.origin.conns_count);
        try std.testing.expect(bed.scenario.origin.conns[0].done);
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
        try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("deadline_expired"));
        try bed.expectDrained();
    }
}

test "relay: idle timeout reaps a silent connection" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 31 }, .idle_timeout_ms = 50 });
    defer bed.tearDown();

    bed.startClients(1, false);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "relay: an origin reset mid-exchange tears the connection down" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 33, .adversary = .{ .partial_io = false } } });
    defer bed.tearDown();

    bed.scenario.origin.mode = .reset_on_first_chunk;
    bed.startClients(1, true);
    try bed.sim_io.run();

    // The client observes the teardown (as FIN or the propagated reset);
    // the echo never completes but the slot is fully reclaimed.
    try std.testing.expect(bed.scenario.clients[0].outcome != .pending);
    try std.testing.expect(bed.scenario.clients[0].received_len < echo_token.len);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "drain: terminate signal stops accepting and reaps stragglers at the drain deadline" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 41 }, .idle_timeout_ms = 60_000 });
    defer bed.tearDown();

    // A silent client would idle for a minute; the drain must not wait
    // for it — the server-owned drain timer reaps it instead.
    bed.startClients(1, false);
    bed.sim_io.scheduleSignal(.terminate, bed.sim_io.nowNs() + 5_000_000);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("drained_at_deadline"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "server: conn-slot exhaustion sheds with RST; deadline reaps the holder" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .server = .{ .conn_slots = 1, .relay_buffers = 1 },
        .sim = .{ .seed = 21 },
    });
    defer bed.tearDown();

    // Pin the proxy→origin dial only; the clients' own connects stay live.
    bed.sim_io.blackholeAddress(TestBed.originAddress());
    bed.startClients(2, false);
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
    try bed.setUp(std.testing.allocator, .{
        .server = .{ .conn_slots = 2, .relay_buffers = 1 },
        .sim = .{ .seed = 22 },
    });
    defer bed.tearDown();

    bed.sim_io.blackholeAddress(TestBed.originAddress());
    bed.startClients(2, false);
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
    try bed.setUp(std.testing.allocator, .{
        .server = .{ .conn_slots = 2, .relay_buffers = 1 },
        .sim = .{ .seed = 23 },
        .origin_listens = false, // no origin: every dial is refused
    });
    defer bed.tearDown();

    bed.startClients(1, false);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try bed.expectDrained();
}
