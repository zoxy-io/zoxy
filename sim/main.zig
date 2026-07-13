//! The §9 deterministic-simulation gate: `zig build sim -- [seed]
//! [iterations] | fuzz`. Every seed derives a scenario (client count,
//! seed-derived tokens, adversary knobs, pool sizes that force the §8
//! rungs, misbehaving-origin scripts) and runs the *real* serving path
//! over SimIo — twice, asserting the two trace hashes are identical, so
//! replayability itself is gated. Invariants per seed: no deadlock,
//! pools drain to zero, counters reconcile, every byte a client gets
//! back is a prefix of what it sent (echo integrity), and every virtual
//! socket is released. A failure prints its seed; the same seed replays
//! the exact schedule.

const std = @import("std");

const zoxy = @import("zoxy");

const Io = zoxy.Io;
const SimIo = zoxy.Io.SimIo;
const ServerSim = zoxy.Server(SimIo);
const Origin = zoxy.testing.Origin(SimIo);

const assert = std.debug.assert;

const clients_max: u8 = 6;
const token_bytes_max: u8 = 48;
/// Virtual time from scenario start after which stuck work is force-ended.
const scenario_end_ns: u64 = 2_000_000_000;
const default_seed: u64 = 1;
const default_iterations: u64 = 64;
const progress_interval: u64 = 500;

pub fn main(init: std.process.Init) !u8 {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();

    if (arguments.len == 2 and std.mem.eql(u8, arguments[1], "fuzz")) {
        var count: u64 = 0;
        while (true) : (count += 1) {
            var seed_bytes: [8]u8 = undefined;
            init.io.random(&seed_bytes);
            const seed = std.mem.readInt(u64, &seed_bytes, .little);
            checkSeed(&arena_state, seed) catch return 1;
            if (count % progress_interval == 0) {
                std.debug.print("sim fuzz: {d} seeds ok, latest {d}\n", .{ count + 1, seed });
            }
        }
    }

    const first_seed = if (arguments.len >= 2)
        try std.fmt.parseUnsigned(u64, arguments[1], 10)
    else
        default_seed;
    const iterations = if (arguments.len >= 3)
        try std.fmt.parseUnsigned(u64, arguments[2], 10)
    else
        default_iterations;
    assert(iterations >= 1);

    var seed = first_seed;
    while (seed < first_seed + iterations) : (seed += 1) {
        checkSeed(&arena_state, seed) catch return 1;
    }
    std.debug.print("sim: {d} seed(s) ok, {d}..{d}\n", .{
        iterations,
        first_seed,
        first_seed + iterations - 1,
    });
    return 0;
}

/// One seed, run twice: the second run must produce a byte-identical
/// delivery trace or determinism itself is broken.
fn checkSeed(arena_state: *std.heap.ArenaAllocator, seed: u64) !void {
    const first = runSeed(arena_state, seed) catch |err| {
        std.debug.print("sim: FAILURE seed={d} error={t}\n", .{ seed, err });
        return err;
    };
    const second = runSeed(arena_state, seed) catch |err| {
        std.debug.print("sim: FAILURE on replay seed={d} error={t}\n", .{ seed, err });
        return err;
    };
    if (first != second) {
        std.debug.print(
            "sim: NONDETERMINISM seed={d} trace {x} != {x}\n",
            .{ seed, first, second },
        );
        return error.NonDeterministic;
    }
}

fn runSeed(arena_state: *std.heap.ArenaAllocator, seed: u64) !u64 {
    _ = arena_state.reset(.retain_capacity);
    const arena = arena_state.allocator();

    var harness: Harness = undefined;
    try harness.setUp(arena, seed);
    harness.startClients();
    harness.io.run() catch |err| {
        // Deadlock is precisely what this gate exists to catch.
        return err;
    };
    try harness.verify();
    return harness.io.trace_hash;
}

const Harness = struct {
    io: SimIo,
    server: ServerSim,
    endpoints: [1]std.Io.net.IpAddress,
    clusters: [1]zoxy.config.Config.Cluster,
    listener_configs: [1]zoxy.config.Config.Listener,
    config: zoxy.config.Config,
    origin: Origin,
    clients: [clients_max]Client,
    clients_count: u8,
    ended_count: u8,
    end_timer_completion: SimIo.Completion,
    scenario_prng: std.Random.DefaultPrng,

    fn bindAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
    }

    fn originAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
    }

    fn setUp(harness: *Harness, arena: std.mem.Allocator, seed: u64) !void {
        // Scenario shape and Io schedule use *separate* streams from one
        // seed, so harness decisions never perturb delivery order.
        harness.scenario_prng = std.Random.DefaultPrng.init(seed ^ 0x5a5a5a5a5a5a5a5a);
        const random = harness.scenario_prng.random();

        const adversary: SimIo.Adversary = .{
            .partial_io = true,
            .connect_delay_ns_max = random.uintAtMost(u64, 5_000_000),
            .connect_refuse_percent = random.uintAtMost(u8, 20),
            .reset_percent = random.uintAtMost(u8, 10),
            .kernel_pressure_percent = random.uintAtMost(u8, 8),
        };
        try harness.io.init(arena, .{ .seed = seed, .adversary = adversary });

        harness.endpoints = .{originAddress()};
        harness.clusters = .{.{ .name = "origin", .endpoints = &harness.endpoints }};
        harness.listener_configs = .{.{ .bind_address = bindAddress(), .cluster_index = 0 }};
        harness.config = .{
            .listeners = &harness.listener_configs,
            .clusters = &harness.clusters,
            .connect_timeout_ms = 20 + random.uintAtMost(u32, 40),
            .idle_timeout_ms = 30 + random.uintAtMost(u32, 70),
            .drain_deadline_ms = 100,
        };

        // A quarter of seeds shrink the pools to force the §8 rungs.
        const force_exhaustion = random.uintLessThan(u8, 4) == 0;
        const options: ServerSim.InitOptions = if (force_exhaustion)
            .{ .conn_slots = 1 + random.uintLessThan(u32, 2), .relay_buffers = 1 }
        else
            .{ .conn_slots = 2 * clients_max, .relay_buffers = clients_max };
        try harness.server.init(arena, &harness.io, &harness.config, options);
        try harness.server.start();

        harness.origin = .{
            .mode_selector = pickOriginMode,
            .context = harness,
        };
        try harness.origin.start(&harness.io, Harness.originAddress());

        harness.clients_count = 1 + random.uintLessThan(u8, clients_max);
        harness.ended_count = 0;
        harness.clients = @splat(.{});
        for (harness.clients[0..harness.clients_count]) |*client| {
            client.harness = harness;
            client.token_len = 1 + random.uintLessThan(u8, token_bytes_max);
            random.bytes(client.token[0..client.token_len]);
            client.silent = random.uintLessThan(u8, 5) == 0;
        }

        harness.end_timer_completion = .{};
        harness.io.timerStart(
            &harness.end_timer_completion,
            scenario_end_ns,
            Harness,
            harness,
            onScenarioEnd,
        );
    }

    fn startClients(harness: *Harness) void {
        assert(harness.clients_count >= 1);
        for (harness.clients[0..harness.clients_count]) |*client| {
            client.begin();
        }
    }

    fn clientEnded(harness: *Harness) void {
        harness.ended_count += 1;
        assert(harness.ended_count <= harness.clients_count);
        if (harness.ended_count == harness.clients_count) {
            harness.endScenario();
        }
    }

    /// Belt and suspenders: fires even if some client never ends (a
    /// black-holed connect, a stuck exchange) and force-ends the run.
    fn onScenarioEnd(harness: *Harness, result: Io.TimerError!void) void {
        result catch return;
        harness.endScenario();
    }

    fn endScenario(harness: *Harness) void {
        for (harness.clients[0..harness.clients_count]) |*client| {
            client.cancelIfStuck();
        }
        harness.server.beginDrain();
        harness.origin.stopListening();
    }

    fn verify(harness: *Harness) !void {
        // The loop may stop before harness-side terminal completions
        // deliver; close what remains so the socket-leak check is exact.
        for (harness.clients[0..harness.clients_count]) |*client| {
            client.closeIfOpen();
        }
        harness.origin.closeRemaining();

        if (!harness.server.isIdle()) return error.PoolLeak;
        if (!harness.server.reconcile()) return error.CountersDiverged;
        if (!harness.io.sockets.isFullyReleased()) return error.SocketLeak;
        for (harness.clients[0..harness.clients_count]) |*client| {
            try client.verifyIntegrity();
        }
    }
};

/// Per-accept origin behavior, drawn from the harness's scenario PRNG so
/// each proxied connection meets a random misbehavior (echo / RST / mute /
/// frozen) — the §9 adversarial-origin coverage.
fn pickOriginMode(context: ?*anyopaque) zoxy.testing.Mode {
    const harness: *Harness = @ptrCast(@alignCast(context.?));
    return harness.scenario_prng.random().enumValue(zoxy.testing.Mode);
}

/// A scripted client with a seed-derived token. Sends the token, FINs
/// after the full echo, and treats any terminal recv as the end; silent
/// clients connect and wait to be reaped. Integrity invariant: every
/// byte received must be a prefix of the token sent — the proxy may cut
/// a stream short, but it must never corrupt or reorder it.
const Client = struct {
    harness: *Harness = undefined,
    connect_completion: SimIo.Completion = .{},
    connect_cancel_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    token: [token_bytes_max]u8 = undefined,
    token_len: u8 = 0,
    receive_buffer: [token_bytes_max]u8 = undefined,
    /// Once the echo is complete, the recv waiting on the FIN lands here;
    /// any byte that arrives is an integrity violation, recorded below.
    overrun_scratch: [1]u8 = undefined,
    overrun: bool = false,
    socket: SimIo.Socket = undefined,
    silent: bool = false,
    connected: bool = false,
    connect_settled: bool = false,
    cancel_requested: bool = false,
    fin_sent: bool = false,
    closed: bool = false,
    ended: bool = false,
    send_pending: bool = false,
    recv_terminal: bool = false,
    sent_len: u32 = 0,
    received_len: u32 = 0,

    fn begin(client: *Client) void {
        client.harness.io.connect(
            Harness.bindAddress(),
            &client.connect_completion,
            Client,
            client,
            onConnect,
        );
    }

    fn onConnect(client: *Client, result: Io.ConnectError!SimIo.Socket) void {
        client.connect_settled = true;
        client.socket = result catch {
            client.end();
            return;
        };
        client.connected = true;
        client.armRecv();
        if (!client.silent and client.token_len > 0) {
            client.armSend();
        }
    }

    fn armSend(client: *Client) void {
        assert(client.sent_len < client.token_len);
        assert(!client.send_pending);
        client.send_pending = true;
        client.harness.io.send(
            client.socket,
            client.token[client.sent_len..client.token_len],
            &client.send_completion,
            Client,
            client,
            onSend,
        );
    }

    fn onSend(client: *Client, result: Io.SendError!u32) void {
        assert(client.send_pending);
        client.send_pending = false;
        const sent = result catch {
            client.settleIfTerminal();
            return;
        };
        client.sent_len += sent;
        assert(client.sent_len <= client.token_len);
        if (client.recv_terminal) {
            client.settleIfTerminal();
        } else if (client.sent_len < client.token_len) {
            client.armSend();
        }
    }

    fn armRecv(client: *Client) void {
        const buffer = if (client.received_len == client.token_len)
            &client.overrun_scratch
        else
            client.receive_buffer[client.received_len..client.token_len];
        client.harness.io.recv(
            client.socket,
            buffer,
            &client.recv_completion,
            Client,
            client,
            onRecv,
        );
    }

    fn onRecv(client: *Client, result: Io.RecvError!u32) void {
        const received = result catch {
            // The §5 rule applies to the harness too: the socket may only
            // close once the concurrent send op has also settled.
            client.recv_terminal = true;
            client.settleIfTerminal();
            return;
        };
        assert(received >= 1);
        if (client.received_len == client.token_len) {
            client.overrun = true;
        } else {
            client.received_len += received;
            assert(client.received_len <= client.token_len);
            if (client.received_len == client.token_len) {
                if (!client.fin_sent) {
                    client.fin_sent = true;
                    client.harness.io.shutdown(client.socket, .write);
                }
            }
        }
        client.armRecv();
    }

    /// Scenario end: a connect the adversary black-holed must still be
    /// reaped — the same seam op the proxy itself relies on (§5).
    fn cancelIfStuck(client: *Client) void {
        if (client.connect_settled or client.cancel_requested) return;
        client.cancel_requested = true;
        client.harness.io.connectCancel(
            &client.connect_completion,
            &client.connect_cancel_completion,
            Client,
            client,
            onConnectCanceled,
        );
    }

    fn onConnectCanceled(client: *Client) void {
        if (!client.connect_settled) {
            client.connect_settled = true;
            client.end();
        }
    }

    fn settleIfTerminal(client: *Client) void {
        assert(client.recv_terminal or !client.send_pending);
        if (client.recv_terminal and !client.send_pending) {
            client.closeIfOpen();
            client.end();
        }
    }

    fn closeIfOpen(client: *Client) void {
        if (client.connected and !client.closed) {
            client.closed = true;
            client.harness.io.closeNow(client.socket);
        }
    }

    fn end(client: *Client) void {
        if (client.ended) return;
        client.ended = true;
        client.harness.clientEnded();
    }

    fn verifyIntegrity(client: *const Client) !void {
        if (client.overrun) return error.EchoOverrun;
        assert(client.received_len <= client.token_len);
        if (!std.mem.eql(
            u8,
            client.receive_buffer[0..client.received_len],
            client.token[0..client.received_len],
        )) {
            return error.EchoCorrupted;
        }
    }
};
