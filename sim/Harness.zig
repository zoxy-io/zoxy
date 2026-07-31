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
/// The slowest §7 probe pacing a non-outage seed may draw. Named so the
/// origin-capacity bound below is derived from the same number the draw
/// uses, not restated in prose.
const health_interval_floor_ms: u32 = 100;
/// Upper bound on probe sweeps one scenario can run against a listening
/// origin: the interval floor paces them across the scenario, plus the
/// immediate first sweep. Outage seeds pace far tighter but stop their
/// origin within tens of milliseconds, so their passing probes stay
/// under this bound too.
const probe_sweeps_max: u64 =
    scenario_end_ns / (health_interval_floor_ms * std.time.ns_per_ms) + 1;

comptime {
    // Passing probes consume origin conn slots (accept-and-vanish, never
    // recycled), on top of each origin's client-driven worst case: one
    // conn per L4 client, and the pre-probe capacity of 32 the 4096-seed
    // sweeps validated for the HTTP origin's dial churn.
    assert(Origin.conns_max >= @as(u64, clients_max) + probe_sweeps_max);
    assert(HttpOrigin.conns_max >= 32 + probe_sweeps_max);
}

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
/// Virtual instant at which the HTTP origin stops listening mid-run, or
/// 0 for never. Drawn on a fraction of checked-http adversarial seeds:
/// probes then start refusing while parked connections from earlier
/// exchanges still exist, which is the only schedule that reaches the
/// §5 parked-close on ejection under the fuzz — chance alone almost
/// never lines an ejection up with a parked conn. Statistical, not
/// guaranteed: a scenario that winds down before the drawn instant
/// never sees its outage, which is fine — the sweep needs the schedule
/// to land often, not on every draw.
http_origin_stop_at_ns: u64,
http_origin_stop_completion: SimIo.Completion,
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
    harness.http_origin_stop_completion = .{};
    if (harness.http_origin_stop_at_ns != 0) {
        assert(harness.http_origin_stop_at_ns < scenario_end_ns);
        harness.io.timerStart(
            &harness.http_origin_stop_completion,
            harness.http_origin_stop_at_ns,
            Harness,
            harness,
            onHttpOriginStop,
        );
    }
}

/// The mid-run origin outage (§7): refused dials are a fate clients
/// already meet under the adversary's own knobs, so the prefix oracles
/// absorb it — what it adds is probes failing against a cluster that
/// still holds parked connections.
fn onHttpOriginStop(harness: *Harness, result: Io.TimerError!void) void {
    result catch return;
    harness.origin_http.stopListening();
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
        // Dial-time kernel pressure (§8): the witnessKernelPressure
        // sites on both dial paths were unreachable under every seed
        // until this fate existed (issue #106, kind B).
        .connect_pressure_percent = random.uintAtMost(u8, 5),
        // A sink that has fallen behind (§8). Most seeds keep it instant;
        // some stall it past a whole scenario, which is what fills the
        // staging buffers and makes the drop rung reachable at all.
        .log_write_stall_ns = if (random.uintLessThan(u8, 4) == 0)
            random.uintAtMost(u64, 200_000_000)
        else
            0,
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
    // Each cluster draws §7 active health checks independently, so the
    // prober runs its whole lifecycle — sweeps, fall/rise transitions
    // under the adversary's connect fates, parked-close on ejection, and
    // drain from every state — inside the schedule fuzz. Fail-open keeps
    // a single-endpoint topology's routing unchanged whatever the
    // verdicts, so the L7 golden oracles hold on clean seeds (where
    // probes always pass) and prefix-legality holds under the adversary.
    const connect_timeout_ms: u32 = 20 + random.uintAtMost(u32, 40);
    const health = deriveHealthChecks(harness.clean, random, connect_timeout_ms);
    harness.http_origin_stop_at_ns = health.http_origin_stop_at_ns;
    harness.clusters = .{
        .{ .name = "origin-l4", .endpoints = &harness.endpoints_l4, .pick = pick_l4, .check = health.check_l4 },
        .{ .name = "origin-http", .endpoints = &harness.endpoints_http, .pick = pick_http, .check = health.check_http },
    };
    harness.routes_l4 = .{.{ .prefix = "/", .cluster_index = 0 }};
    harness.routes_http = .{.{ .prefix = "/", .cluster_index = 1 }};
    harness.wireListeners();
    harness.config = .{
        .listeners = &harness.listener_configs,
        .clusters = &harness.clusters,
        .connect_timeout_ms = connect_timeout_ms,
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
        // Three seeds in four run with the access log on, so the sink,
        // its staging swap, and the per-request captures all take the
        // schedule fuzz; the fourth leaves it off, which is the shape
        // that must reserve nothing and read no clock (§5, §8).
        .access_log_sink = if (random.uintLessThan(u8, 4) == 0) null else .stdout,
        .health_interval_ms = health.interval_ms,
    };
}

/// The §7 health-check shape of one scenario: which clusters probe, how
/// fast, and whether the HTTP origin dies mid-run.
const HealthDraw = struct {
    check_l4: ?Check,
    check_http: ?Check,
    interval_ms: u32,
    http_origin_stop_at_ns: u64,
};

const Check = zoxy.config.Config.Cluster.Check;

/// An eighth of adversarial seeds are outage seeds: the HTTP origin
/// stops listening while clients are still live and parked connections
/// still exist — most scenarios wind down within tens of virtual
/// milliseconds, so the outage lands inside that window, paced in
/// milliseconds so fall's three misses do too. Outage seeds check only
/// the http cluster: the tight pacing on a stuck 2 s scenario would
/// otherwise stream hundreds of passing probes into the L4 origin's
/// conn table, while the stopped HTTP origin refuses its probes and a
/// refused probe consumes no origin conn. Everyone else paces from the
/// `health_interval_floor_ms` the origin-capacity bound is derived at.
fn deriveHealthChecks(clean: bool, random: std.Random, timeout_ms: u32) HealthDraw {
    assert(timeout_ms >= 1);
    const outage = !clean and random.uintLessThan(u8, 8) == 0;
    // Thresholds draw around their defaults so a configured fall/rise —
    // not only the compiled one — decides ejections under the fuzz.
    const tcp_check: Check = .{
        .timeout_ms = timeout_ms,
        .fall = 1 + random.uintAtMost(u8, 3),
        .rise = 1 + random.uintAtMost(u8, 2),
    };
    const draw: HealthDraw = .{
        .check_l4 = if (!outage and random.boolean()) tcp_check else null,
        .check_http = if (outage or random.boolean()) tcp_check else null,
        .interval_ms = if (outage)
            5 + random.uintAtMost(u32, 10)
        else
            health_interval_floor_ms + random.uintAtMost(u32, 400),
        .http_origin_stop_at_ns = if (outage)
            (10 + random.uintAtMost(u64, 30)) * std.time.ns_per_ms
        else
            0,
    };
    // An outage always probes the cluster it exists to eject, and the
    // instant always precedes the scenario-end backstop.
    assert(draw.http_origin_stop_at_ns == 0 or draw.check_http != null);
    assert(draw.http_origin_stop_at_ns < scenario_end_ns);
    assert(draw.interval_ms >= 1);
    return draw;
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
    // Adversarial seeds size the staging buffers at the floor — one
    // worst-case line each — so the buffer swap runs constantly and every
    // line meets a nearly-full buffer, against the default's hundred-line
    // headroom where the swap fires once a scenario. The *drop* rung
    // itself stays out of reach here: a scenario emits a handful of lines
    // and filling even the floor takes dozens, so it is pinned by a
    // directed test (`access_log_test.zig`) rather than left to a seed
    // that cannot generate the volume.
    const access_log_buffer_bytes: u32 = if (harness.config.access_log_sink == null)
        0
    else if (harness.clean)
        zoxy.constants.access_log_buffer_bytes_default
    else
        zoxy.constants.access_log_buffer_bytes_min;
    const options: ServerSim.InitOptions = if (force_exhaustion)
        .{
            .conn_slots = 1 + random.uintLessThan(u32, 2),
            .relay_buffers = 1,
            .upstream_slots = 1,
            .access_log_buffer_bytes = access_log_buffer_bytes,
        }
    else
        .{
            .access_log_buffer_bytes = access_log_buffer_bytes,
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
    try harness.verifyAccessLog();
    for (harness.clients[0..harness.l4_count]) |*client| {
        try client.verifyIntegrity();
    }
    for (harness.l7_clients[0..harness.l7_count]) |*client| {
        try client.verify();
    }
}

/// The §8 access log's invariants (§9). The sink is a virtual file the
/// harness can read back, so what an operator would have seen is checkable
/// rather than merely believed: the bytes are whole lines, there are
/// exactly as many of them as the counter claims, each is shaped like the
/// documented record, and — when nothing was dropped — every outcome the
/// data path counted has a line to go with it.
///
/// Structural rather than a full JSON parse: `parseFromSlice` allocates,
/// and the simulator does not. The escaping that a parse would catch is
/// pinned by `access_log.zig`'s own tests, against inputs far more hostile
/// than the scripts here send.
fn verifyAccessLog(harness: *Harness) !void {
    const counters = &harness.server.counters;
    const sink = harness.io.sinkBytes();
    if (harness.io.sink_overflow_bytes != 0) return error.AccessLogSinkOverflowed;
    // The sink never fails in the sweep, so every accepted line must have
    // reached it; a failure here would silently weaken every check below.
    if (counters.get("access_log_write_failed") != 0) return error.AccessLogWriteFailed;

    if (harness.config.access_log_sink == null) {
        // Off means off: no bytes, and no counter moved (§5).
        if (sink.len != 0) return error.AccessLogWroteWhileOff;
        if (counters.get("access_log_lines") != 0) return error.AccessLogCountedWhileOff;
        if (counters.get("access_log_dropped") != 0) return error.AccessLogCountedWhileOff;
        return;
    }

    // The drain does not stop the loop until the sink is quiet (§8), so
    // the last byte written is the last byte of a line — never half of one.
    if (sink.len != 0 and sink[sink.len - 1] != '\n') return error.AccessLogTruncatedLine;
    var lines = std.mem.splitScalar(u8, sink, '\n');
    var line_count: u64 = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue; // The tail after the final newline.
        line_count += 1;
        try verifyAccessLogLine(line);
    }
    if (line_count != counters.get("access_log_lines")) return error.AccessLogLineCountDiverged;

    // Nothing was dropped, so every outcome the data path counted owes a
    // line — plus one per L4 connection and per request that ended without
    // a verdict, which is why this is an inequality.
    if (counters.get("access_log_dropped") == 0) {
        if (counters.get("access_log_lines") < l7OutcomeTotal(counters)) {
            return error.AccessLogMissedAnOutcome;
        }
    }
}

/// Every L7 outcome that answers a client, summed. Each one runs through
/// `respond` or `finishExchange`, and both emit a line.
fn l7OutcomeTotal(counters: *const zoxy.counters.Counters) u64 {
    const answered = [_][]const u8{
        "l7_responses",
        "l7_bad_request",
        "l7_uri_too_long",
        "l7_headers_too_large",
        "l7_not_implemented",
        "l7_no_route",
        "l7_filtered",
        "l7_shed_relay_buffers",
        "l7_shed_upstream_slots",
        "l7_bad_gateway",
        "l7_gateway_timeout",
    };
    var total: u64 = 0;
    inline for (answered) |name| {
        total += counters.get(name);
    }
    return total;
}

/// One line's shape: a JSON object carrying every key the record defines,
/// in the order `renderLine` writes them.
fn verifyAccessLogLine(line: []const u8) !void {
    assert(line.len >= 1);
    if (line[0] != '{') return error.AccessLogLineNotAnObject;
    if (line[line.len - 1] != '}') return error.AccessLogLineNotAnObject;
    const required = [_][]const u8{
        "\"time\":\"",
        "\"kind\":\"",
        "\"outcome\":\"",
        "\"client\":\"",
        "\"duration_us\":",
        "\"bytes_in\":",
        "\"bytes_out\":",
        "\"cluster\":",
        "\"upstream\":",
    };
    var searched: usize = 0;
    for (required) |key| {
        // Searched forward from the previous key, so the order is checked
        // too: a renderer that emitted the right keys in a shuffled order
        // would still break a consumer reading them positionally.
        const at = std.mem.indexOfPos(u8, line, searched, key) orelse
            return error.AccessLogLineMissingKey;
        searched = at + key.len;
    }
    // An HTTP line carries the request fields; an L4 line must not, or a
    // consumer keying off `kind` finds a status for a connection that
    // never had one.
    const is_http = std.mem.indexOf(u8, line, "\"kind\":\"http\"") != null;
    const has_status = std.mem.indexOf(u8, line, "\"status\":") != null;
    if (is_http != has_status) return error.AccessLogLineWrongShape;
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
