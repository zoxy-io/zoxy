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
/// "203.0.113.255:65535" is 19 bytes; the slack is headroom, not hope.
const announced_bytes_max: u8 = 32;
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
/// The #142 gate drawn for the l4 listener; `populateClients` reads it
/// to decide whether its clients open with headers.
proxy_protocol_l4: ?zoxy.config.Config.Listener.ProxyProtocol,
/// The #142 send half drawn for the l4 cluster; the origin double then
/// expects and strips a header on every connection, and `verify` holds
/// what it heard against what the clients were (`verifyUpstreamIdentities`).
proxy_protocol_send_l4: ?zoxy.config.Config.Cluster.ProxyProtocolSend,
/// Per-L4-client address its header announced (len 0 = none): distinct
/// per client, so `verifyAccessLog` can demand the log states each one
/// on clean seeds — presence is attribution.
l4_announced: [clients_max][announced_bytes_max]u8,
l4_announced_len: [clients_max]u8,
/// The same announcement as an address (valid where `l4_announced_len`
/// is nonzero), for the #142 send-identity oracle — text serves the log
/// needle, this serves `IpAddress.eql`.
l4_announced_address: [clients_max]std.Io.net.IpAddress,
l4_count: u8,
l7_count: u8,
clients_count: u8,
ended_count: u8,
/// Clean seeds run without the adversary and with a well-behaved
/// origin, so the L7 oracles demand exact golden outcomes.
clean: bool,
/// Decided before `io.init` (the ring the sim registers must equal the
/// limit the server accounts against — Server.init asserts the match),
/// consumed by `startServerAndOrigins` for the rest of the pool shape.
force_exhaustion: bool,
head_buffers: u32,
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
/// Virtual instant at which the drain begins, or 0 for "at the
/// scenario's end like every other seed".
///
/// Every seed already drains — `endScenario` calls `beginDrain` — but by
/// then the clients have finished, so the drain's two race-dependent
/// rungs stay out of reach: an accept completion already in flight when
/// the drain starts (`shed_draining`), and a connection still live when
/// the drain deadline fires (`drained_at_deadline`). Starting the drain
/// while the scenario is still working is what puts traffic in front of
/// it. Clean seeds never draw one — a drain is a legitimate reason to
/// miss a golden outcome, which is the thing those seeds exist to
/// forbid.
///
/// It is not free: a seed that stops accepting early serves less. Across
/// the 4096-seed sweep this costs about 6% of the client work
/// (`accepted` 12599 → 11858, `l7_responses` 2234 → 2119) and a quarter
/// of the probes, since a draining server stops the prober. Eight rungs
/// for 6% is the trade being made, and raising the draw rate would buy
/// coverage margin at a steeper one.
drain_at_ns: u64,
drain_completion: SimIo.Completion,
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
    // A quarter of adversarial seeds shrink the pools to force the §8
    // rungs. Drawn here rather than in `startServerAndOrigins` because
    // the head-buffer ring is the Io backend's to register, and its size
    // must be settled before the backend exists. 1–3 ring buffers, so
    // across the sweep some seeds shed at the ring (1: a second
    // concurrent head finds it empty) and others get far enough to shed
    // at the relay rung instead (2–3: heads bind, the deeper rungs
    // starve) — one size would shadow one rung or the other.
    harness.force_exhaustion = !harness.clean and random.uintLessThan(u8, 4) == 0;
    harness.head_buffers = if (harness.force_exhaustion)
        1 + random.uintLessThan(u32, 3)
    else
        // The clean-seed watermark margin, same reasoning as the pools
        // below in `startServerAndOrigins`.
        2 * clients_max;
    try harness.io.init(arena, .{
        .seed = seed,
        .adversary = deriveAdversary(random, harness.clean),
        .buffer_group_count = harness.head_buffers,
    });
    // Which cause the sim reports for every failure it injects (§8).
    // Production reads it off an errno; a virtual socket table has none,
    // so the scenario states one — and drawing it per seed is what makes
    // four of the five `kernel_pressure_*` cause counters reachable at
    // all: under the fixed `out_of_buffers` default that one counter
    // carried every injected failure of a 4096-seed sweep and the other
    // four stayed at zero. A clean seed injects nothing, so it keeps the
    // default rather than choosing a cause it will never report.
    if (!harness.clean) {
        harness.io.setPressureCause(random.enumValue(Io.Pressure.Cause));
    }
    harness.drain_at_ns = deriveDrainAt(harness.clean, random);
    harness.deriveTopology(random);
    try harness.startServerAndOrigins(arena, random);
    harness.injectOneShotFaults(random);
    harness.populateClients(random);

    harness.end_timer_completion = .{};
    harness.io.timerStart(
        &harness.end_timer_completion,
        scenario_end_ns,
        Harness,
        harness,
        onScenarioEnd,
    );
    harness.drain_completion = .{};
    if (harness.drain_at_ns != 0) {
        assert(harness.drain_at_ns < scenario_end_ns);
        harness.io.timerStart(
            &harness.drain_completion,
            harness.drain_at_ns,
            Harness,
            harness,
            onDrainStart,
        );
    }
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

/// One of the two optional deadlines a scenario may arm, or 0 for "off".
///
/// A third of seeds arm each, over a range that straddles the connect and
/// idle timeouts drawn alongside them — so an armed one sometimes fires
/// inside a dial, sometimes mid-exchange, and sometimes never, all under
/// the adversary. The two callers share this because they share the
/// question; what differs is the clock each hangs off, which is what
/// their call sites say.
fn deriveOptionalDeadlineMs(random: std.Random) u32 {
    if (random.uintLessThan(u8, 3) != 0) return 0;
    const deadline_ms = 10 + random.uintAtMost(u32, 90);
    assert(deadline_ms >= 10);
    assert(deadline_ms <= 100);
    return deadline_ms;
}

/// When the drain starts, for the seeds that start one early.
///
/// Bimodal, because the two rungs want opposite instants and one window
/// cannot serve both. `shed_draining` needs the drain inside the opening
/// accept burst, while sockets are still queued — a millisecond in.
/// `drained_at_deadline` needs the drain to arrive after an exchange has
/// begun, with a deadline short enough to still find it running (see
/// `drain_deadline_ms` below, which is the other half of reaching it).
///
/// The split is load-bearing, not decoration: replacing it with one
/// uniform 0.1-150 ms window drops `shed_draining` to 1 and 0 per 1024
/// seeds from two starts — a census failure — while leaving
/// `drained_at_deadline` untouched at 23-24.
fn deriveDrainAt(clean: bool, random: std.Random) u64 {
    if (clean) return 0;
    if (random.uintLessThan(u8, 4) != 0) return 0;
    const at_ns = if (random.boolean())
        100_000 + random.uintAtMost(u64, 3 * std.time.ns_per_ms)
    else
        (10 + random.uintAtMost(u64, 140)) * std.time.ns_per_ms;
    assert(at_ns >= 100_000);
    assert(at_ns < scenario_end_ns);
    return at_ns;
}

/// How long the drain gives its stragglers (§8).
///
/// A deadline long enough that the drain always finishes first is a
/// deadline that never reaps, and `drained_at_deadline` stays
/// unreachable however the drain itself is timed — measured: at the
/// fixed 100 ms the timer delivered on 54 of 400 seeds and found every
/// connection already tearing down. Seeds that drain early therefore
/// sometimes draw one short enough to still find work running, which is
/// a setting production operators tune too. Seeds that drain only at the
/// scenario's end keep the roomy default: there is nothing left to reap
/// by then, and a short deadline would say nothing about it.
///
/// A minority draw 0 — "no cap" (§5), the shape a config that names no
/// deadline gets, where `beginDrain` arms no timer at all and the drain
/// ends only when the last connection does. Kept a minority on purpose:
/// those seeds cannot reach `drained_at_deadline`, and that rung's
/// census margin is already the thinnest in the gate.
fn deriveDrainDeadlineMs(drain_at_ns: u64, random: std.Random) u32 {
    assert(drain_at_ns < scenario_end_ns);
    if (drain_at_ns == 0) return 100;
    if (random.uintLessThan(u8, 4) == 0) return 0;
    if (!random.boolean()) return 100;
    const deadline_ms = 1 + random.uintAtMost(u32, 4);
    assert(deadline_ms >= 1);
    return deadline_ms;
}

/// The drawn mid-scenario drain (§8). `beginDrain` is idempotent, so the
/// scenario-end drain that follows is a no-op rather than a second one.
fn onDrainStart(harness: *Harness, result: Io.TimerError!void) void {
    result catch return;
    harness.server.beginDrain();
}

/// The one-shot faults the sweep would otherwise never pull (§9).
///
/// `SimIo` carries an injector for each — the set-option one exists
/// precisely because "64 seeds stayed green because nothing could make
/// the call fail" — but until now no seed called either, so the paths
/// they reach stayed as unreachable as they were before the injectors
/// were written. Adversarial seeds only: a fault is the wrong thing to
/// hand a seed whose oracle is an exact golden outcome.
///
/// A pending set-option fault is claimed by whoever makes the next
/// `setNodelay`/`setLingerRst` call, and that is not always the server:
/// an origin double closing in reset mode makes one too. The first
/// version of this function assumed the server always got there first
/// and panicked the sweep on the seed that proved otherwise, which is
/// why both doubles now absorb the error instead of taking it as
/// `unreachable`. A fault landing on a double costs that origin its RST
/// and nothing else, and the server still claims most of them: it calls
/// `setNodelay` on every admission and every upstream dial, far earlier
/// and far oftener than a double reaches a reset-mode close. Measured,
/// since the split is the part worth doubting rather than asserting —
/// `kernel_pressure_set_option` lands 232-265 times per 1024 seeds
/// against roughly 288 faults drawn.
fn injectOneShotFaults(harness: *Harness, random: std.Random) void {
    assert(harness.server.listeners.len >= 1);
    assert(harness.server.listeners.len <= harness.listener_configs.len);
    if (harness.clean) return;
    if (random.uintLessThan(u8, 4) == 0) {
        const faults = 1 + random.uintAtMost(u8, 1);
        for (0..faults) |_| harness.io.injectSetOptionError();
    }
    // An accept that fails backs the listener off by
    // `accept_retry_delay_ms` and retries; the queued socket keeps its
    // place, so no client is lost to this — it costs the scenario ten
    // milliseconds of its two seconds.
    if (random.uintLessThan(u8, 4) == 0) {
        const index = random.uintLessThan(usize, harness.server.listeners.len);
        harness.io.injectAcceptError(harness.server.listeners[index].listener);
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
        // A sink that has fallen behind (§8): the resume-a-short-write and
        // stalled-drain paths, under schedule fuzz. Most seeds keep it
        // instant; some stall it past a whole scenario.
        //
        // It does *not* reach the drop rung, whatever a stall's length: a
        // scenario emits single-digit lines against staging buffers
        // holding ~130, so there is nothing to overflow. The sweep's
        // census names `access_log_dropped` as uncovered for exactly that
        // reason, and src/access_log_test.zig drives the burst instead.
        .log_write_stall_ns = if (random.uintLessThan(u8, 4) == 0)
            random.uintAtMost(u64, 200_000_000)
        else
            0,
    };
}

fn randomPick(random: std.Random) zoxy.config.Config.Cluster.Pick {
    return random.enumValue(zoxy.config.Config.Cluster.Pick);
}

fn deriveTopology(harness: *Harness, random: std.Random) void {
    harness.endpoints_l4 = .{originAddress()};
    harness.endpoints_http = .{httpOriginAddress()};
    // Each cluster draws its pick policy independently so mixed configs
    // (one cluster each way) flow through the balancer under the schedule
    // fuzz, not just the uniform pairings. Single-endpoint clusters
    // short-circuit every policy identically today; the draw is pre-wired
    // coverage for a multi-endpoint topology. `hash` rides here for what
    // the *scenario* can exercise — the pick path, the health mask, and
    // the L4/L7 plumbing of the client address — while the properties it
    // exists for (stickiness, minimal disruption on ejection) are pinned
    // by `balancer.zig`'s own tests, which can hold thousands of distinct
    // clients against a multi-endpoint cluster as a scenario cannot.
    const pick_l4 = randomPick(random);
    const pick_http = randomPick(random);
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
    harness.proxy_protocol_send_l4 = deriveProxyProtocolSend(random);
    harness.clusters = .{
        .{
            .name = "origin-l4",
            .endpoints = &harness.endpoints_l4,
            .pick = pick_l4,
            .check = health.check_l4,
            .max_inflight = deriveMaxInflight(harness.clean, random),
            .proxy_protocol_send = harness.proxy_protocol_send_l4,
        },
        .{
            .name = "origin-http",
            .endpoints = &harness.endpoints_http,
            .pick = pick_http,
            .check = health.check_http,
            .max_inflight = deriveMaxInflight(harness.clean, random),
        },
    };
    harness.routes_l4 = .{.{ .prefix = "/", .cluster_index = 0 }};
    harness.routes_http = .{.{ .prefix = "/", .cluster_index = 1 }};
    harness.proxy_protocol_l4 = deriveProxyProtocol(random);
    harness.wireListeners(deriveForwarded(random));
    harness.config = .{
        .listeners = &harness.listener_configs,
        .clusters = &harness.clusters,
        .connect_timeout_ms = connect_timeout_ms,
        // Drawn *above* the dial budget rather than independently: the
        // loader rejects the other order (§5), so an independent draw would
        // spend seeds on a config production cannot load.
        .idle_timeout_ms = connect_timeout_ms + 10 + random.uintAtMost(u32, 70),
        .drain_deadline_ms = deriveDrainDeadlineMs(harness.drain_at_ns, random),
        // The §6 age cap: measured from the connection's birth, so the
        // clamp sometimes reaps an actively-relaying connection.
        .max_lifetime_ms = deriveOptionalDeadlineMs(random),
        // The §8 per-exchange deadline: measured from routing instead, so
        // the same range lands on a different clock.
        .request_timeout_ms = deriveOptionalDeadlineMs(random),
        // Three seeds in four run with the access log on, so the sink,
        // its staging swap, and the per-request captures all take the
        // schedule fuzz; the fourth leaves it off, which is the shape
        // that must reserve nothing and read no clock (§5, §8).
        .access_log_sink = if (random.uintLessThan(u8, 4) == 0) null else .stdout,
        .health_interval_ms = health.interval_ms,
    };
}

/// The §8 per-endpoint cap for one cluster, or null for uncapped.
///
/// Only adversarial seeds cap, and the reason is the oracle rather than
/// the mechanism: a refusal is a `503` an L7 script did not ask for and a
/// close an L4 client did not expect, both of which a clean seed's golden
/// outcomes forbid. Under the adversary they are ordinary fates — the
/// prefix oracles already tolerate a cut, and a cap-shed `503` is the
/// same shape as the pool-exhaustion one those seeds already produce.
///
/// The value is drawn *below* the client population on purpose. A cap
/// the scenario cannot reach exercises the comparison and nothing else;
/// at one or two against up to six clients, both refusal paths run
/// against real contention, and every seed still crosses back under the
/// cap as connections finish — so the recovery side runs too.
fn deriveMaxInflight(clean: bool, random: std.Random) ?u32 {
    if (clean) return null;
    if (random.uintLessThan(u8, 3) != 0) return null;
    return 1 + random.uintAtMost(u32, 1);
}

/// Which check the http cluster runs, if any. An outage seed always
/// takes the dial check: its origin stops listening, so a request check
/// would only ever reach the same refused dial by a longer route.
fn checkHttpDraw(
    checked: bool,
    outage: bool,
    random: std.Random,
    tcp_check: Check,
    http_check: Check,
) ?Check {
    if (!checked) return null;
    if (outage) return tcp_check;
    return if (random.boolean()) http_check else tcp_check;
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
    // Half the checked http clusters probe with a real request instead of
    // a dial, so the send and recv legs — and the shutdown that ends one
    // when a deadline or a drain lands mid-leg — take the schedule fuzz.
    // A quarter of those expect a status the origin never sends, which is
    // the only way to reach the wrong-status ejection: every other
    // failure here is a transport failure, and a check that could not
    // tell those apart would be the whole point missed.
    var http_check = tcp_check;
    http_check.kind = .http;
    http_check.http = .{
        .path = "/health",
        .expect_status = if (random.uintLessThan(u8, 4) == 0) 599 else 200,
    };
    const checked_http = outage or random.boolean();
    const draw: HealthDraw = .{
        // The L4 origin echoes bytes rather than speaking HTTP, so only
        // the dial check is meaningful against it.
        .check_l4 = if (!outage and random.boolean()) tcp_check else null,
        .check_http = checkHttpDraw(checked_http, outage, random, tcp_check, http_check),
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
///
/// `forwarded` is the one drawn part: §7 client-address forwarding adds a
/// rendered header on every request the listener serves, so it is a
/// data-path state the sweep has to reach rather than leave to the
/// directed tests. It cannot perturb a golden outcome — the scripts assert
/// on what the *client* receives, and this only changes what the origin
/// sees — and the origin oracle rejects malformed bytes either way.
/// A third of seeds leave §7 forwarding off — the shape every config that
/// predates it keeps — and the rest split between the two trust modes, so
/// the render's suppression and the chain assembly both take the schedule
/// fuzz rather than only the directed tests.
///
/// The mode alone is not coverage, and the census said so. `append` and
/// `replace` render identical bytes unless a request actually carries an
/// inbound chain, so what separates them lives in the scripts:
/// `forwarded_inbound` supplies one every mode must handle, and
/// `forwarded_oversize` one that only `append` can drop.
fn deriveForwarded(random: std.Random) ?zoxy.config.Config.Listener.Forwarded {
    return switch (random.uintLessThan(u8, 3)) {
        0 => null,
        1 => .replace,
        else => .append,
    };
}

/// The #142 receive gate on the l4 listener: a third of seeds require a
/// PROXY header, clean seeds included — the phase is deterministic, so a
/// clean seed's headers always complete and the golden oracles gain the
/// accept path, while adversarial seeds split headers across deliveries
/// and cut them mid-read. Like `deriveForwarded`, the mode alone is not
/// coverage: what the clients *send* decides which verdict fires, and
/// `deriveProxyHeader` scripts that spread — including no header at all,
/// which is the refusal `require` exists to make.
fn deriveProxyProtocol(random: std.Random) ?zoxy.config.Config.Listener.ProxyProtocol {
    if (random.uintLessThan(u8, 3) == 0) {
        return .require;
    }
    return null;
}

/// The #142 send half on the l4 cluster: half the announcing seeds speak
/// v2 (what the writers' real receivers — cloud LBs, HAProxy — expect),
/// the rest v1, and half send nothing at all. Drawn independently of the
/// receive gate, so the sweep reaches all four quadrants — including the
/// chain, where the identity announced in must be the identity announced
/// out. The prober needs no carve-out: `check_l4` is always the
/// dial-only tcp check, which gives a stripping origin no bytes to
/// judge.
fn deriveProxyProtocolSend(random: std.Random) ?zoxy.config.Config.Cluster.ProxyProtocolSend {
    return switch (random.uintLessThan(u8, 6)) {
        0 => .v1,
        1, 2 => .v2,
        else => null,
    };
}

fn wireListeners(harness: *Harness, forwarded: ?zoxy.config.Config.Listener.Forwarded) void {
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
        .{
            .bind_address = bindAddress(),
            .routes = &harness.routes_l4,
            .protocol = .l4,
            .proxy_protocol = harness.proxy_protocol_l4,
        },
        .{
            .bind_address = httpBindAddress(),
            .routes = &harness.routes_http,
            .filters = &harness.filters_http,
            .protocol = .http,
            .forwarded = forwarded,
        },
    };
}

fn startServerAndOrigins(harness: *Harness, arena: std.mem.Allocator, random: std.Random) !void {
    // A quarter of adversarial seeds shrink the pools to force the
    // §8 rungs; clean seeds keep ample pools so golden outcomes
    // never meet a shed. Decided in `setUp` (see `force_exhaustion`)
    // because the ring size had to precede `io.init`.
    const force_exhaustion = harness.force_exhaustion;
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
            // head_buffers ≤ conn_slots is a Server.init precondition, so
            // the slot draw starts at whatever the ring draw chose.
            .conn_slots = harness.head_buffers + random.uintLessThan(u32, 2),
            .relay_buffers = 1,
            .upstream_slots = 1,
            .head_buffers = harness.head_buffers,
            // Capacity 1: the first render engages the pressure flag, so
            // the engage counter stays reachable even though the shed
            // rung itself is relay-shadowed (see sim/main.zig uncovered).
            .upstream_head_buffers = 1,
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
            .head_buffers = harness.head_buffers,
            .upstream_head_buffers = 2 * clients_max,
        };
    try harness.server.init(arena, &harness.io, &harness.config, options);
    try harness.server.start();

    harness.origin = .{
        .mode_selector = pickOriginMode,
        .context = harness,
        .expect_proxy_header = harness.proxy_protocol_send_l4 != null,
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
    harness.l4_announced_len = @splat(0);
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
            const l4_index = harness.l4_count;
            harness.l4_count += 1;
            var token: [l4.token_bytes_max]u8 = undefined;
            const token_len = 1 + random.uintLessThan(u8, l4.token_bytes_max);
            random.bytes(token[0..token_len]);
            const silent = random.uintLessThan(u8, 5) == 0;
            // A silent client sends nothing, header included: on a
            // require-listener it is the connect-budget reap's fodder,
            // and drawing it a header it would never send would teach
            // `verifyAccessLog` to demand an announcement that never
            // crossed the wire.
            var prefix_buffer: [l4.prefix_bytes_max]u8 = undefined;
            const prefix = if (silent)
                ""
            else
                harness.deriveProxyHeader(random, l4_index, &prefix_buffer);
            client.prepare(
                &harness.io,
                bindAddress(),
                token[0..token_len],
                prefix,
                silent,
            );
            client.on_ended = clientEndedHook;
            client.context = harness;
        }
    }
    assert(harness.l4_count + harness.l7_count == harness.clients_count);
}

/// The header an L4 client opens with when the listener requires one
/// (#142), or "" — the gate off, or one draw in six sending nothing so
/// the sweep reaches the refusal too (the random token then opens the
/// stream, and `require` closes on its first byte; the rare token that
/// happens to open like a header meets the connect-budget reap instead).
/// The spread covers both spec versions and both verdict families:
/// announcing headers (v1 TCP4, v2 INET) carry a per-client distinct
/// address that is recorded for the clean-seed log oracle, and
/// non-announcing ones (v1 UNKNOWN, v2 LOCAL) are the health-check shape
/// that must keep the observed peer.
fn deriveProxyHeader(
    harness: *Harness,
    random: std.Random,
    l4_index: u8,
    buffer: *[l4.prefix_bytes_max]u8,
) []const u8 {
    assert(l4_index < clients_max);
    assert(harness.l4_announced_len[l4_index] == 0);
    if (harness.proxy_protocol_l4 == null) {
        return "";
    }
    const octet: u8 = l4_index + 1;
    const port: u16 = 40_000 + @as(u16, l4_index);
    switch (random.uintLessThan(u8, 6)) {
        0 => return "",
        1 => return "PROXY UNKNOWN\r\n",
        2 => {
            // v2 LOCAL: a fronting proxy's health check.
            @memcpy(buffer[0..16], "\r\n\r\n\x00\r\nQUIT\n" ++ "\x20\x00\x00\x00");
            return buffer[0..16];
        },
        3 => {
            // v2 PROXY INET announcing 203.0.113.<octet>:<port>.
            @memcpy(buffer[0..16], "\r\n\r\n\x00\r\nQUIT\n" ++ "\x21\x11\x00\x0c");
            buffer[16..20].* = .{ 203, 0, 113, octet };
            buffer[20..24].* = .{ 10, 0, 0, 1 };
            std.mem.writeInt(u16, buffer[24..26], port, .big);
            std.mem.writeInt(u16, buffer[26..28], 443, .big);
            harness.recordAnnounced(l4_index, octet, port);
            return buffer[0..28];
        },
        else => {
            // v1 TCP4, the same announcement in text.
            const line = std.fmt.bufPrint(
                buffer,
                "PROXY TCP4 203.0.113.{d} 10.0.0.1 {d} 443\r\n",
                .{ octet, port },
            ) catch unreachable; // 46 bytes at most, into 64.
            harness.recordAnnounced(l4_index, octet, port);
            return line;
        },
    }
}

fn recordAnnounced(harness: *Harness, l4_index: u8, octet: u8, port: u16) void {
    assert(l4_index < clients_max);
    const text = std.fmt.bufPrint(
        &harness.l4_announced[l4_index],
        "203.0.113.{d}:{d}",
        .{ octet, port },
    ) catch unreachable; // 19 bytes at most, into announced_bytes_max.
    // The shortest form is "203.0.113.1:40000"; anything outside the
    // template's range means the format string drifted from the record.
    assert(text.len >= 17);
    assert(text.len <= 19);
    harness.l4_announced_len[l4_index] = @intCast(text.len);
    harness.l4_announced_address[l4_index] =
        .{ .ip4 = .{ .bytes = .{ 203, 0, 113, octet }, .port = port } };
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
    // #142 send: on any seed, garbage where a header belongs is zoxy's
    // bug — the writers are pure and the adversary splits deliveries but
    // never corrupts bytes, so a cut lands as EOF, not as a violation.
    if (harness.origin.proxy_header_violations != 0) {
        return error.OriginSawInvalidProxyHeader;
    }
    try harness.verifyUpstreamIdentities();
    try harness.verifyAccessLog();
    for (harness.clients[0..harness.l4_count]) |*client| {
        try client.verifyIntegrity();
    }
    for (harness.l7_clients[0..harness.l7_count]) |*client| {
        try client.verify();
    }
}

/// #142 send, every seed: whatever identity the origin heard must be one
/// some L4 client *was* — the announced-in address where the client
/// carried one through the require listener, the observed peer
/// otherwise. Inverted membership deliberately: origin conns whose drawn
/// mode never parses (mute, frozen, reset) record nothing, and a cut
/// header lands as EOF, so demanding every client be heard would fail
/// legal schedules — but an identity heard that no client was is always
/// a bug. Identities are per-client distinct (announced 203.0.113.N,
/// synthetic ports climb), so a match is attribution, and a parsed
/// header must always announce: zoxy's writers have no LOCAL/UNKNOWN
/// arm. The completeness direction lives in the directed tests, where
/// the origin's mode is pinned to echo.
fn verifyUpstreamIdentities(harness: *const Harness) !void {
    if (harness.proxy_protocol_send_l4 == null) {
        assert(!harness.origin.expect_proxy_header);
        return;
    }
    for (harness.origin.conns[0..harness.origin.conns_count]) |*conn| {
        if (!conn.header_done) continue;
        const announced = conn.announced orelse
            return error.UpstreamHeaderAnnouncedNothing;
        var matched = false;
        var index: u8 = 0;
        while (index < harness.l4_count) : (index += 1) {
            const expected: std.Io.net.IpAddress =
                if (harness.l4_announced_len[index] > 0)
                    harness.l4_announced_address[index]
                else
                    harness.clients[index].observed_address orelse continue;
            if (expected.eql(&announced)) matched = true;
        }
        if (!matched) return error.UpstreamHeardUnknownIdentity;
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
    const tally = try tallyAccessLog(sink);
    if (tally.total != counters.get("access_log_lines")) {
        return error.AccessLogLineCountDiverged;
    }

    // A dropped line would make the equality below false for a reason
    // that has nothing to do with the counter list it exists to pin, so
    // the real condition fails first and under its own name. The rung is
    // out of a scenario's reach (see the §9 census's `uncovered` entry),
    // and the census proves that across the range — but only once the
    // range finishes, which is too late to explain a single seed.
    if (counters.get("access_log_dropped") != 0) return error.AccessLogDroppedInSweep;

    // Every HTTP line is either an outcome the data path counted or an
    // abort — an equality, and the reason this file no longer asks
    // whether the log wrote *enough* lines. The `>=` it replaces was
    // satisfied by writing too many, which is precisely how #129's
    // phantom line per keep-alive connection cleared 4096 seeds.
    //
    // It also pins `l7OutcomeTotal`'s list: a new answered counter left
    // out of it fails this on the first seed that reaches the rung, which
    // is how `l7_shed_endpoint_inflight` turned out to have been missing
    // since it shipped.
    if (tally.http != l7OutcomeTotal(counters) + tally.http_aborted) {
        return error.AccessLogHttpLinesDiverged;
    }

    // A clean seed answers everything it starts, so an abort is a bug
    // rather than an adversary's work. Not quite by construction: what a
    // clean seed removes is every *cause* of an abort — no resets, no
    // kernel pressure, a well-behaved origin, and no drawn drain
    // (`deriveDrainAt` skips clean seeds) — while the request and
    // lifetime deadlines are still drawn and armed. They do not fire
    // because a well-behaved origin answers within microseconds of
    // virtual time, which is an argument about pacing rather than a
    // guarantee; it held across all 1578 clean runs of the sweep.
    //
    // This is the half with teeth. The equality above counts a phantom
    // abort on both sides and passes; this one refuses it outright, and
    // is what fails on seed 10 when #129's bug is put back.
    if (harness.clean) {
        if (tally.http_aborted != 0) return error.AccessLogAbortedOnCleanSeed;
        // And each L4 connection is one line: the clients connect once
        // apiece, clean-seed pools are sized well past the population so
        // none is shed at admission, and an L4 connection stamps its
        // clock on admission rather than on first byte — so even the
        // silent clients (`sim/l4.zig` draws some) owe a line, theirs
        // reporting `bytes_in: 0`.
        if (tally.l4 != harness.l4_count) return error.AccessLogL4LinesDiverged;
        try harness.verifyAnnouncedClients(sink);
    }
}

/// #142, clean seeds only: a client that announced an address via its
/// PROXY header must be logged *as* that address — the same field the §7
/// hash pick keys on, so this is the sweep's witness that the header is
/// believed, not merely consumed (reverting the one believe-the-header
/// line fails seed 20 here). Adversarial seeds are excluded because a cut
/// mid-header rightly logs the observed peer; that a clean seed's header
/// always completes ahead of any drawn deadline is the same pacing
/// argument the clean-abort check above rests on. The addresses are
/// distinct per client, so presence is attribution.
fn verifyAnnouncedClients(harness: *const Harness, sink: []const u8) !void {
    assert(harness.clean);
    assert(harness.l4_count <= clients_max);
    var l4_index: u8 = 0;
    while (l4_index < harness.l4_count) : (l4_index += 1) {
        const announced_len = harness.l4_announced_len[l4_index];
        if (announced_len == 0) continue;
        var needle_buffer: [announced_bytes_max + 11]u8 = undefined;
        const needle = std.fmt.bufPrint(
            &needle_buffer,
            "\"client\":\"{s}\"",
            .{harness.l4_announced[l4_index][0..announced_len]},
        ) catch unreachable; // The key wrapper is exactly 11 bytes.
        if (std.mem.indexOf(u8, sink, needle) == null) {
            return error.AccessLogAnnouncedClientMissing;
        }
    }
}

/// What the sink's lines are, counted by kind and outcome. Every line is
/// shape-checked on the way past, so a malformed one fails here rather
/// than being silently tallied.
const LineTally = struct {
    total: u64 = 0,
    http: u64 = 0,
    l4: u64 = 0,
    http_aborted: u64 = 0,
};

fn tallyAccessLog(sink: []const u8) !LineTally {
    var tally: LineTally = .{};
    var lines = std.mem.splitScalar(u8, sink, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue; // The tail after the final newline.
        tally.total += 1;
        try verifyAccessLogLine(line);
        if (std.mem.indexOf(u8, line, "\"kind\":\"http\"") == null) {
            tally.l4 += 1;
            continue;
        }
        tally.http += 1;
        if (std.mem.indexOf(u8, line, "\"outcome\":\"aborted\"") != null) {
            tally.http_aborted += 1;
        }
    }
    assert(tally.http + tally.l4 == tally.total);
    assert(tally.http_aborted <= tally.http);
    return tally;
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
        "l7_shed_endpoint_inflight",
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
