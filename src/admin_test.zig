//! Directed admin-listener scenarios over SimIo (§9). The scrape path is a
//! data-path state machine — accept → send → lingering close → re-arm, with
//! its own deadline reaper and drain teardown — so it earns the same
//! deterministic gate as the relay: a virtual scrape client drives it, the
//! response is asserted byte-exact against the counters' own rendering, and
//! every run ends with the server idle, sockets released, and counters
//! reconciled. Adversarial seeds split every send and recv down to one byte
//! and inject resets, exercising the short-send resume and the error/
//! teardown paths; a stalled client proves the deadline reaper frees the
//! single reserved slot.

const std = @import("std");

const admin = @import("admin.zig");
const config_module = @import("config.zig");
const constants = @import("constants.zig");
const counters_module = @import("counters.zig");
const router = @import("http/router.zig");
const Io = @import("io/io.zig");
const Server = @import("Server.zig").Server;
const SimIo = @import("io/SimIo.zig");

const assert = std.debug.assert;
const testing = std.testing;

const ServerSim = Server(SimIo);

const request = "GET /metrics HTTP/1.1\r\nHost: admin\r\n\r\n";

fn adminAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9100") catch unreachable;
}
fn bindAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
}
fn originAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
}

const Harness = struct {
    arena_state: std.heap.ArenaAllocator,
    sim_io: SimIo,
    endpoints: [1]std.Io.net.IpAddress,
    clusters: [1]config_module.Config.Cluster,
    routes: [1]router.Route,
    listeners: [1]config_module.Config.Listener,
    config: config_module.Config,
    server: ServerSim,
    scrape: Scrape,
    holder: Holder,

    fn setUp(harness: *Harness, gpa: std.mem.Allocator, sim: SimIo.Options) !void {
        harness.arena_state = std.heap.ArenaAllocator.init(gpa);
        errdefer harness.arena_state.deinit();
        const arena = harness.arena_state.allocator();

        try harness.sim_io.init(arena, sim);
        harness.endpoints = .{originAddress()};
        harness.clusters = .{.{ .name = "origin", .endpoints = &harness.endpoints }};
        harness.routes = .{.{ .prefix = "/", .cluster_index = 0 }};
        harness.listeners = .{.{
            .bind_address = bindAddress(),
            .routes = &harness.routes,
            .protocol = .l4,
        }};
        harness.config = .{
            .listeners = &harness.listeners,
            .clusters = &harness.clusters,
            .connect_timeout_ms = 50,
            .idle_timeout_ms = 1000,
            .drain_deadline_ms = 1000,
            .max_lifetime_ms = 0,
        };
        try harness.server.init(arena, &harness.sim_io, &harness.config, .{
            .conn_slots = 4,
            .relay_buffers = 2,
        });
        harness.server.setAdminBind(adminAddress());
        try harness.server.start();
        harness.scrape = .{ .server = &harness.server, .io = &harness.sim_io };
        harness.holder = .{};
    }

    fn tearDown(harness: *Harness) void {
        harness.arena_state.deinit();
    }

    fn expectDrained(harness: *Harness) !void {
        try testing.expect(harness.server.isIdle());
        try testing.expect(harness.server.reconcile());
        try testing.expect(harness.sim_io.sockets.isFullyReleased());
    }
};

/// The response an undisturbed scrape must receive: the fixed head then a
/// rendering of *all-zero* counters. The server renders the body at accept
/// time, before `admin_served` (or any counter this scenario touches) moves,
/// so the on-the-wire snapshot is always the zero state — checkable
/// byte-for-byte regardless of what the counters read after the run.
fn expectedResponse(buffer: []u8) []const u8 {
    assert(buffer.len >= admin.response_bytes_max);
    var zero: counters_module.Counters = .{};
    @memcpy(buffer[0..admin.response_head.len], admin.response_head);
    const body = zero.render(buffer[admin.response_head.len..]);
    return buffer[0 .. admin.response_head.len + body.len];
}

/// A scripted scrape client. `.normal` sends the request and reads the
/// response to EOF; `.drain_mid_scrape` begins the server drain the instant
/// the first response byte arrives, so the drain tears down an established,
/// mid-flight scrape while the client is still reading (the client's live
/// recv observes the teardown, so nothing is orphaned); `.stall` never reads
/// or closes and arms a far-future timer so the run outlives the scrape
/// deadline — the reaper must free the slot before the timer closes.
const Scrape = struct {
    server: *ServerSim = undefined,
    io: *SimIo = undefined,
    connect_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    timer_completion: SimIo.Completion = .{},
    socket: SimIo.Socket = undefined,
    recv_buffer: [admin.response_bytes_max]u8 = undefined,
    received_len: u32 = 0,
    sent_len: u32 = 0,
    send_pending: bool = false,
    mode: Mode = .normal,
    outcome: Outcome = .pending,
    drained: bool = false,

    const Mode = enum { normal, drain_mid_scrape, stall };
    const Outcome = enum { pending, refused, eof, reset };

    fn start(scrape: *Scrape) void {
        scrape.io.connect(adminAddress(), &scrape.connect_completion, Scrape, scrape, onConnect);
    }

    fn onConnect(scrape: *Scrape, result: Io.ConnectError!SimIo.Socket) void {
        scrape.socket = result catch {
            scrape.outcome = .refused;
            scrape.beginDrainOnce();
            return;
        };
        if (scrape.mode == .stall) {
            // Neither read nor close: sit until the scrape deadline reaps the
            // slot. A far-future timer keeps the run progressing past the
            // deadline, then closes so the run can drain to idle.
            scrape.io.timerStart(
                &scrape.timer_completion,
                @as(u64, constants.admin_scrape_deadline_ms + 1000) * std.time.ns_per_ms,
                Scrape,
                scrape,
                onStallTimer,
            );
            return;
        }
        scrape.armRecv();
        scrape.armSend();
    }

    fn armSend(scrape: *Scrape) void {
        assert(scrape.sent_len < request.len);
        assert(!scrape.send_pending);
        scrape.send_pending = true;
        scrape.io.send(
            scrape.socket,
            request[scrape.sent_len..],
            &scrape.send_completion,
            Scrape,
            scrape,
            onSend,
        );
    }

    fn onSend(scrape: *Scrape, result: Io.SendError!u32) void {
        assert(scrape.send_pending);
        scrape.send_pending = false;
        const sent = result catch {
            // A send error mid-scrape is legal (the server reset or tore
            // down); the recv path settles the outcome.
            scrape.settleIfTerminal();
            return;
        };
        scrape.sent_len += sent;
        assert(scrape.sent_len <= request.len);
        if (scrape.outcome != .pending) {
            scrape.settleIfTerminal();
        } else if (scrape.sent_len < request.len) {
            scrape.armSend();
        }
    }

    fn armRecv(scrape: *Scrape) void {
        assert(scrape.received_len < scrape.recv_buffer.len);
        scrape.io.recv(
            scrape.socket,
            scrape.recv_buffer[scrape.received_len..],
            &scrape.recv_completion,
            Scrape,
            scrape,
            onRecv,
        );
    }

    fn onRecv(scrape: *Scrape, result: Io.RecvError!u32) void {
        const received = result catch |err| {
            scrape.outcome = switch (err) {
                error.Reset => .reset,
                else => .eof,
            };
            scrape.settleIfTerminal();
            return;
        };
        scrape.received_len += received;
        assert(scrape.received_len <= scrape.recv_buffer.len);
        // Race the drain against the established scrape: the first response
        // byte proves the admin is mid-send (or draining), so beginning the
        // drain now forces its in-flight teardown while this recv stays live
        // to witness it.
        if (scrape.mode == .drain_mid_scrape) scrape.beginDrainOnce();
        scrape.armRecv();
    }

    fn onStallTimer(scrape: *Scrape, result: Io.TimerError!void) void {
        result catch unreachable;
        assert(scrape.mode == .stall);
        // The deadline has long since reaped the scrape; close and drain so
        // the run reaches idle.
        scrape.io.closeNow(scrape.socket);
        scrape.beginDrainOnce();
    }

    fn settleIfTerminal(scrape: *Scrape) void {
        if (scrape.outcome == .pending) return;
        if (scrape.send_pending) return;
        scrape.io.closeNow(scrape.socket);
        scrape.beginDrainOnce();
    }

    /// The scrape is over: begin the server drain (closing the admin
    /// listener) so the loop can quiesce, exactly once.
    fn beginDrainOnce(scrape: *Scrape) void {
        if (scrape.drained) return;
        scrape.drained = true;
        scrape.server.beginDrain();
    }
};

/// A data-path holder for the drain-race scenario: it connects to the L4
/// listener whose origin is blackholed, so the proxy's upstream dial hangs
/// and the conn slot stays occupied until the connect deadline. That keeps
/// the pools non-empty — and the loop running — long enough for the raced
/// admin scrape to finish tearing down and the scrape client to observe it,
/// instead of the server stopping the instant its only work (the scrape)
/// drains. It settles when its own conn is reaped. (The established sim idiom
/// for this race — see server_test's "accept that raced the drain".)
const Holder = struct {
    io: *SimIo = undefined,
    connect_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    socket: SimIo.Socket = undefined,
    scratch: [64]u8 = undefined,
    settled: bool = false,

    fn start(holder: *Holder, io: *SimIo) void {
        holder.io = io;
        io.connect(bindAddress(), &holder.connect_completion, Holder, holder, onConnect);
    }

    fn onConnect(holder: *Holder, result: Io.ConnectError!SimIo.Socket) void {
        holder.socket = result catch {
            holder.settled = true;
            return;
        };
        holder.io.recv(holder.socket, &holder.scratch, &holder.recv_completion, Holder, holder, onRecv);
    }

    fn onRecv(holder: *Holder, result: Io.RecvError!u32) void {
        // The proxy never relays (origin blackholed), so the only recv
        // completion is the teardown reset/FIN when the conn is reaped —
        // close and settle.
        _ = result catch {};
        holder.io.closeNow(holder.socket);
        holder.settled = true;
    }
};

test "admin: a scrape returns the counters as byte-exact Prometheus text" {
    var seed: u64 = 1;
    while (seed <= 20) : (seed += 1) {
        var harness: Harness = undefined;
        // partial_io splits every send and recv, exercising the short-send
        // resume and fragmented drain without severing the exchange.
        try harness.setUp(testing.allocator, .{
            .seed = seed,
            .adversary = .{ .partial_io = true },
        });
        defer harness.tearDown();

        harness.scrape.start();
        try harness.sim_io.run();

        try testing.expectEqual(Scrape.Outcome.eof, harness.scrape.outcome);
        var expected_buffer: [admin.response_bytes_max]u8 = undefined;
        const expected = expectedResponse(&expected_buffer);
        try testing.expectEqualStrings(
            expected,
            harness.scrape.recv_buffer[0..harness.scrape.received_len],
        );
        try testing.expectEqual(@as(u64, 1), harness.server.counters.get("admin_served"));
        try harness.expectDrained();
    }
}

test "admin: a scrape stays intact and drains under resets" {
    // reset_percent severs connections mid-exchange: the scrape may see a
    // truncated response, but every byte it did receive must be a prefix of
    // the true response, and the server must still drain to idle.
    var seed: u64 = 1;
    while (seed <= 20) : (seed += 1) {
        var harness: Harness = undefined;
        try harness.setUp(testing.allocator, .{
            .seed = seed,
            .adversary = .{ .partial_io = true, .reset_percent = 25 },
        });
        defer harness.tearDown();

        harness.scrape.start();
        try harness.sim_io.run();

        var expected_buffer: [admin.response_bytes_max]u8 = undefined;
        const expected = expectedResponse(&expected_buffer);
        const got = harness.scrape.recv_buffer[0..harness.scrape.received_len];
        try testing.expect(std.mem.startsWith(u8, expected, got));
        try harness.expectDrained();
    }
}

test "admin: a drain racing an in-flight scrape tears down cleanly" {
    var seed: u64 = 1;
    while (seed <= 20) : (seed += 1) {
        var harness: Harness = undefined;
        try harness.setUp(testing.allocator, .{
            .seed = seed,
            .adversary = .{ .partial_io = true },
        });
        defer harness.tearDown();

        // Blackhole the origin so the holder's dial hangs, pinning a conn
        // slot until the connect deadline — that keeps the loop alive while
        // the raced admin scrape tears down and the scrape client observes it.
        harness.sim_io.blackholeAddress(originAddress());
        harness.holder.start(&harness.sim_io);
        harness.scrape.mode = .drain_mid_scrape;
        harness.scrape.start();
        try harness.sim_io.run();

        // The scrape may complete or be torn down by the drain; either way no
        // op or socket leaks, and counters reconcile.
        try testing.expect(harness.holder.settled);
        try harness.expectDrained();
    }
}

test "admin: the scrape deadline reaps a client that never finishes" {
    var harness: Harness = undefined;
    try harness.setUp(testing.allocator, .{ .seed = 7, .adversary = .{ .partial_io = false } });
    defer harness.tearDown();

    harness.scrape.mode = .stall;
    harness.scrape.start();
    try harness.sim_io.run();

    // The reaper freed the slot before the client ever finished — witnessed
    // by its counter — and the run still drained clean.
    try testing.expectEqual(@as(u64, 1), harness.server.counters.get("admin_reaped"));
    try harness.expectDrained();
}

test "admin: draining an idle-and-accepting listener releases cleanly" {
    // A direct, timing-independent reproduction of the once-fixed drain bug:
    // a Canceled accept during drain must clear `listening` so the loop can
    // reach quiescence. The admin listener is armed and accepting with zero
    // scrapes ever served when the drain begins, so `beginDrain` closes the
    // listener, `listenClose` cancels the armed accept, and onAccept's
    // draining branch must return the admin to quiescent. A regression that
    // left `listening` set would strand `isQuiescent`, and the run would
    // deadlock instead of draining.
    var harness: Harness = undefined;
    try harness.setUp(testing.allocator, .{ .seed = 1, .adversary = .{ .partial_io = false } });
    defer harness.tearDown();

    harness.server.beginDrain();
    try harness.sim_io.run();

    try harness.expectDrained();
}
