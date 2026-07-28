//! One scenario of the simulation gate (§9): every seed derives a
//! topology (client count, seed-derived tokens, adversary knobs, pool
//! sizes that force the §8 rungs, misbehaving-origin scripts) and runs
//! the *real* serving path over SimIo. Scenarios mix protocols: an L4
//! echo population (sim/l4.zig) and an L7 HTTP population (sim/l7.zig)
//! share one server, so the pools feel cross-protocol pressure. A
//! quarter of seeds run *clean* — the adversary off and the origin
//! well-behaved — hardening the oracles from prefix-legality to the
//! scripts' exact golden outcomes.
//!
//! Invariants per seed: no deadlock, pools drain to zero, counters
//! reconcile, every L4 echo byte is a prefix of what was sent, every L7
//! response is a prefix of a legal transcript, no malformed byte ever
//! reaches the origin (§7), and every virtual socket is released.

const std = @import("std");

const zoxy = @import("zoxy");

const l4 = @import("l4.zig");
const l7 = @import("l7.zig");

const Io = zoxy.Io;
const SimIo = zoxy.Io.SimIo;
const ServerSim = zoxy.Server(SimIo);
const Origin = zoxy.testing.Origin(SimIo);
const HttpOrigin = l7.HttpOrigin(SimIo);
const HttpClient = l7.Client(SimIo);
const EchoClient = l4.Client(SimIo);

const assert = std.debug.assert;

const Harness = @This();

const clients_max: u8 = 6;
/// Virtual time from scenario start after which stuck work is force-ended.
const scenario_end_ns: u64 = 2_000_000_000;

io: SimIo,
server: ServerSim,
endpoints_l4: [1]std.Io.net.IpAddress,
endpoints_http: [1]std.Io.net.IpAddress,
clusters: [2]zoxy.config.Config.Cluster,
routes_l4: [1]zoxy.http.router.Route,
routes_http: [1]zoxy.http.router.Route,
filters_http: [3]zoxy.http.filter.Rule,
listener_configs: [2]zoxy.config.Config.Listener,
config: zoxy.config.Config,
origin: Origin,
origin_http: HttpOrigin,
clients: [clients_max]EchoClient,
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

pub fn setUp(harness: *Harness, arena: std.mem.Allocator, seed: u64) !void {
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
        // A blackholed dial hangs until the connect deadline — the §8
        // dial-timeout 504 path, exercised under schedule fuzz.
        .connect_blackhole_percent = random.uintAtMost(u8, 10),
        .reset_percent = random.uintAtMost(u8, 10),
        .kernel_pressure_percent = random.uintAtMost(u8, 8),
    };
}

fn deriveTopology(harness: *Harness, random: std.Random) void {
    harness.endpoints_l4 = .{originAddress()};
    harness.endpoints_http = .{httpOriginAddress()};
    // Each cluster draws its pick policy independently so mixed
    // rr+p2c configs (one cluster each way) flow through the balancer
    // under the schedule fuzz, not just the two uniform pairings.
    // Single-endpoint clusters short-circuit either policy identically
    // today; the draw is pre-wired coverage for a multi-endpoint
    // topology.
    const pick_l4: zoxy.config.Config.Cluster.Pick =
        if (random.boolean()) .p2c else .rr;
    const pick_http: zoxy.config.Config.Cluster.Pick =
        if (random.boolean()) .p2c else .rr;
    harness.clusters = .{
        .{ .name = "origin-l4", .endpoints = &harness.endpoints_l4, .pick = pick_l4 },
        .{ .name = "origin-http", .endpoints = &harness.endpoints_http, .pick = pick_http },
    };
    harness.routes_l4 = .{.{ .prefix = "/", .cluster_index = 0 }};
    harness.routes_http = .{.{ .prefix = "/", .cluster_index = 1 }};
    harness.wireListeners();
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
        // Same shape for the §8 request deadline: a third of seeds arm
        // it, over a range that straddles both the connect and idle
        // timeouts drawn above — so it sometimes fires inside a dial,
        // sometimes mid-exchange, and sometimes never, all under the
        // adversary. 0 leaves it disabled.
        .request_timeout_ms = if (random.uintLessThan(u8, 3) == 0)
            10 + random.uintAtMost(u32, 90)
        else
            0,
    };
}

/// The deterministic half of the topology: two listeners, and the §7
/// filters on the HTTP one — one action each, scoped to a distinct path
/// so they fire only for the filter_* scripts and leave every other
/// script's golden outcome untouched: reject `/reject`, add a header
/// under `/edit`, rewrite `/rewrite` → `/sim`.
fn wireListeners(harness: *Harness) void {
    harness.filters_http = .{
        .{
            .match = .{ .path_prefix = "/reject" },
            .actions = &.{.{ .reject = 403 }},
        },
        .{
            .match = .{ .path_prefix = "/edit" },
            .actions = &.{.{ .header_set = .{ .name = "X-Sim-Filter", .value = "on" } }},
        },
        .{
            .match = .{ .path_prefix = "/rewrite" },
            .actions = &.{.{ .rewrite_prefix = .{ .from = "/rewrite", .to = "/sim" } }},
        },
    };
    harness.listener_configs = .{
        .{ .bind_address = bindAddress(), .routes = &harness.routes_l4, .protocol = .l4 },
        .{
            .bind_address = httpBindAddress(),
            .routes = &harness.routes_http,
            .filters = &harness.filters_http,
            .protocol = .http,
        },
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
            // Clean seeds size every pool so its §8 pressure
            // watermark (ceil of 3/4 capacity: 9 of 12) sits above
            // the whole client population (6): a golden outcome must
            // never meet a pressure-announced close or a shortened
            // parked deadline — correct behavior, but not the
            // script's exact transcript. All three flags (relay,
            // conn, upstream) ride this margin; a clean-seed client
            // bump must re-check it, and the upstream margin also
            // rides the single-endpoint topology (checkout-before-
            // dial caps acquired at the live client count — parked
            // conns per endpoint could accumulate past it under a
            // multi-endpoint clean topology).
            .conn_slots = 2 * clients_max,
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
            client.on_ended = clientEndedHook;
            client.context = harness;
        } else {
            const client = &harness.clients[harness.l4_count];
            harness.l4_count += 1;
            var token: [l4.token_bytes_max]u8 = undefined;
            const token_len = 1 + random.uintLessThan(u8, l4.token_bytes_max);
            random.bytes(token[0..token_len]);
            const silent = random.uintLessThan(u8, 5) == 0;
            client.prepare(&harness.io, bindAddress(), token[0..token_len], silent);
            client.on_ended = clientEndedHook;
            client.context = harness;
        }
    }
    assert(harness.l4_count + harness.l7_count == harness.clients_count);
}

pub fn startClients(harness: *Harness) void {
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

pub fn verify(harness: *Harness) !void {
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

/// Both clients' ended hook: type-erased because the client files cannot
/// know the harness type.
fn clientEndedHook(context: ?*anyopaque) void {
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
