//! The §9 deterministic-simulation gate: `zig build sim -- [seed]
//! [iterations] | fuzz`. Every seed derives a scenario (client count,
//! seed-derived tokens, adversary knobs, pool sizes that force the §8
//! rungs, misbehaving-origin scripts) and runs the *real* serving path
//! over SimIo — twice, asserting the two trace hashes are identical, so
//! replayability itself is gated. Scenarios mix protocols: an L4 echo
//! population and an L7 HTTP population share one server, so the pools
//! feel cross-protocol pressure. A quarter of seeds run *clean* — the
//! adversary off and the origin well-behaved — hardening the oracles
//! from prefix-legality to the scripts' exact golden outcomes (sim/l7.zig).
//! Invariants per seed: no deadlock, pools drain to zero, counters
//! reconcile, every L4 echo byte is a prefix of what was sent, every L7
//! response is a prefix of a legal transcript, no malformed byte ever
//! reaches the origin (§7), and every virtual socket is released. A
//! failure prints its seed; the same seed replays the exact schedule.

const std = @import("std");

const zoxy = @import("zoxy");

const l7 = @import("l7.zig");

const Io = zoxy.Io;
const SimIo = zoxy.Io.SimIo;
const ServerSim = zoxy.Server(SimIo);
const Origin = zoxy.testing.Origin(SimIo);
const HttpOrigin = l7.HttpOrigin(SimIo);
const HttpClient = l7.Client(SimIo);

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
    endpoints_l4: [1]std.Io.net.IpAddress,
    endpoints_http: [1]std.Io.net.IpAddress,
    clusters: [2]zoxy.config.Config.Cluster,
    routes_l4: [1]zoxy.http.router.Route,
    routes_http: [1]zoxy.http.router.Route,
    listener_configs: [2]zoxy.config.Config.Listener,
    config: zoxy.config.Config,
    origin: Origin,
    origin_http: HttpOrigin,
    clients: [clients_max]Client,
    l7_clients: [clients_max]HttpClient,
    l4_count: u8,
    l7_count: u8,
    clients_count: u8,
    ended_count: u8,
    /// Clean seeds run without the adversary and with a well-behaved
    /// origin, so the L7 oracles demand exact golden outcomes.
    clean: bool,
    end_timer_completion: SimIo.Completion,
    scenario_prng: std.Random.DefaultPrng,

    fn bindAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
    }

    fn httpBindAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8081") catch unreachable;
    }

    fn originAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
    }

    fn httpOriginAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9001") catch unreachable;
    }

    fn setUp(harness: *Harness, arena: std.mem.Allocator, seed: u64) !void {
        // Scenario shape and Io schedule use *separate* streams from one
        // seed, so harness decisions never perturb delivery order.
        harness.scenario_prng = std.Random.DefaultPrng.init(seed ^ 0x5a5a5a5a5a5a5a5a);
        const random = harness.scenario_prng.random();

        // A quarter of seeds run clean: adversary off, origin
        // well-behaved, so the L7 golden oracles demand each script's
        // exact outcome — a silently dropped 400 or a shed that should
        // not happen fails the seed instead of passing as a "cut".
        harness.clean = random.uintLessThan(u8, 4) == 0;
        try harness.io.init(arena, .{
            .seed = seed,
            .adversary = deriveAdversary(random, harness.clean),
        });
        harness.deriveTopology(random);
        try harness.startServerAndOrigins(arena, random);
        harness.populateClients(random);

        harness.end_timer_completion = .{};
        harness.io.timerStart(
            &harness.end_timer_completion,
            scenario_end_ns,
            Harness,
            harness,
            onScenarioEnd,
        );
    }

    fn deriveAdversary(random: std.Random, clean: bool) SimIo.Adversary {
        if (clean) {
            return .{ .partial_io = false };
        }
        return .{
            .partial_io = true,
            .connect_delay_ns_max = random.uintAtMost(u64, 5_000_000),
            .connect_refuse_percent = random.uintAtMost(u8, 20),
            .reset_percent = random.uintAtMost(u8, 10),
            .kernel_pressure_percent = random.uintAtMost(u8, 8),
        };
    }

    fn deriveTopology(harness: *Harness, random: std.Random) void {
        harness.endpoints_l4 = .{originAddress()};
        harness.endpoints_http = .{httpOriginAddress()};
        harness.clusters = .{
            .{ .name = "origin-l4", .endpoints = &harness.endpoints_l4 },
            .{ .name = "origin-http", .endpoints = &harness.endpoints_http },
        };
        harness.routes_l4 = .{.{ .prefix = "/", .cluster_index = 0 }};
        harness.routes_http = .{.{ .prefix = "/", .cluster_index = 1 }};
        harness.listener_configs = .{
            .{ .bind_address = bindAddress(), .routes = &harness.routes_l4, .protocol = .l4 },
            .{ .bind_address = httpBindAddress(), .routes = &harness.routes_http, .protocol = .http },
        };
        harness.config = .{
            .listeners = &harness.listener_configs,
            .clusters = &harness.clusters,
            .connect_timeout_ms = 20 + random.uintAtMost(u32, 40),
            .idle_timeout_ms = 30 + random.uintAtMost(u32, 70),
            .drain_deadline_ms = 100,
            // A third of seeds arm the max-lifetime cap (§6). The range
            // straddles the idle timeout so the clamp sometimes reaps an
            // actively-relaying connection and sometimes never bites —
            // both paths under the adversary. 0 leaves it disabled.
            .max_lifetime_ms = if (random.uintLessThan(u8, 3) == 0)
                10 + random.uintAtMost(u32, 90)
            else
                0,
        };
    }

    fn startServerAndOrigins(harness: *Harness, arena: std.mem.Allocator, random: std.Random) !void {
        // A quarter of adversarial seeds shrink the pools to force the
        // §8 rungs; clean seeds keep ample pools so golden outcomes
        // never meet a shed.
        const force_exhaustion = !harness.clean and random.uintLessThan(u8, 4) == 0;
        const options: ServerSim.InitOptions = if (force_exhaustion)
            .{
                .conn_slots = 1 + random.uintLessThan(u32, 2),
                .relay_buffers = 1,
                .upstream_slots = 1,
            }
        else
            .{
                .conn_slots = 2 * clients_max,
                // Clean seeds size the pool so the §8 pressure watermark
                // (ceil of 3/4 capacity) sits above the whole client
                // population: a golden outcome must never meet a
                // pressure-announced close, which is correct behavior
                // but not the script's exact transcript.
                .relay_buffers = if (harness.clean) 2 * clients_max else clients_max,
                .upstream_slots = 2 * clients_max,
            };
        try harness.server.init(arena, &harness.io, &harness.config, options);
        try harness.server.start();

        harness.origin = .{
            .mode_selector = pickOriginMode,
            .context = harness,
        };
        try harness.origin.start(&harness.io, Harness.originAddress());
        harness.origin_http = .{
            .mode_selector = pickHttpOriginMode,
            .context = harness,
        };
        try harness.origin_http.start(&harness.io, Harness.httpOriginAddress());
    }

    fn populateClients(harness: *Harness, random: std.Random) void {
        // Each client flips a protocol coin: mixed populations put both
        // serving paths under one schedule and shared pools.
        harness.clients_count = 1 + random.uintLessThan(u8, clients_max);
        harness.l4_count = 0;
        harness.l7_count = 0;
        harness.ended_count = 0;
        harness.clients = @splat(.{});
        harness.l7_clients = @splat(.{});
        var index: u8 = 0;
        while (index < harness.clients_count) : (index += 1) {
            if (random.boolean()) {
                const client = &harness.l7_clients[harness.l7_count];
                harness.l7_count += 1;
                client.prepare(
                    &harness.io,
                    httpBindAddress(),
                    random.enumValue(l7.Script),
                    harness.clean,
                );
                client.on_ended = l7ClientEnded;
                client.context = harness;
            } else {
                const client = &harness.clients[harness.l4_count];
                harness.l4_count += 1;
                client.harness = harness;
                client.token_len = 1 + random.uintLessThan(u8, token_bytes_max);
                random.bytes(client.token[0..client.token_len]);
                client.silent = random.uintLessThan(u8, 5) == 0;
            }
        }
        assert(harness.l4_count + harness.l7_count == harness.clients_count);
    }

    fn startClients(harness: *Harness) void {
        assert(harness.clients_count >= 1);
        assert(harness.l4_count + harness.l7_count == harness.clients_count);
        for (harness.clients[0..harness.l4_count]) |*client| {
            client.begin();
        }
        for (harness.l7_clients[0..harness.l7_count]) |*client| {
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
        for (harness.clients[0..harness.l4_count]) |*client| {
            client.cancelIfStuck();
        }
        for (harness.l7_clients[0..harness.l7_count]) |*client| {
            client.cancelIfStuck();
        }
        harness.server.beginDrain();
        harness.origin.stopListening();
        harness.origin_http.stopListening();
    }

    fn verify(harness: *Harness) !void {
        // The loop may stop before harness-side terminal completions
        // deliver; close what remains so the socket-leak check is exact.
        for (harness.clients[0..harness.l4_count]) |*client| {
            client.closeIfOpen();
        }
        for (harness.l7_clients[0..harness.l7_count]) |*client| {
            client.closeIfOpen();
        }
        harness.origin.closeRemaining();
        harness.origin_http.closeRemaining();

        if (!harness.server.isIdle()) return error.PoolLeak;
        if (!harness.server.reconcile()) return error.CountersDiverged;
        if (!harness.io.sockets.isFullyReleased()) return error.SocketLeak;
        // §7: no malformed byte may ever reach an origin.
        if (harness.origin_http.violations != 0) return error.OriginSawMalformedBytes;
        for (harness.clients[0..harness.l4_count]) |*client| {
            try client.verifyIntegrity();
        }
        for (harness.l7_clients[0..harness.l7_count]) |*client| {
            try client.verify();
        }
    }
};

/// The L7 client's ended hook: type-erased because l7.zig cannot know the
/// harness type.
fn l7ClientEnded(context: ?*anyopaque) void {
    const harness: *Harness = @ptrCast(@alignCast(context.?));
    harness.clientEnded();
}

/// Per-accept origin behavior, drawn from the harness's scenario PRNG so
/// each proxied connection meets a random misbehavior (echo / RST / mute /
/// frozen) — the §9 adversarial-origin coverage.
fn pickOriginMode(context: ?*anyopaque) zoxy.testing.Mode {
    const harness: *Harness = @ptrCast(@alignCast(context.?));
    return harness.scenario_prng.random().enumValue(zoxy.testing.Mode);
}

/// Per-accept HTTP-origin misbehavior, drawn like the L4 origin's. Clean
/// seeds pin every connection to the well-behaved sized mode so golden
/// outcomes stay exact.
fn pickHttpOriginMode(context: ?*anyopaque) l7.OriginMode {
    const harness: *Harness = @ptrCast(@alignCast(context.?));
    if (harness.clean) return .sized;
    return harness.scenario_prng.random().enumValue(l7.OriginMode);
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
