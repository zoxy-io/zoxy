//! Tier 0.5 — the live gate (DESIGN.md §9): the shipped binary, on a real
//! kernel, against a real origin, on every change.
//!
//! The three deterministic gates run the real data path against virtual
//! sockets and a virtual clock. That is what makes them exhaustive, and it
//! is also what they cannot answer: both bugs that motivated this tier
//! were found by *running* the thing (#129's phantom access-log line per
//! keep-alive connection, #130's health probes idling out their whole
//! timeout). Each was afterwards teachable to the simulator; neither was
//! caught by it first, because each needed the shape to be known before it
//! could be looked for.
//!
//! So this gate asserts *equalities on real output*: a shared runner's
//! timing noise must not be able to move a verdict. N requests produce
//! exactly N access-log lines. Anything whose verdict needs a
//! run-to-run comparison is Tier 1's job (`zig build bench`) and would
//! make a per-change gate that fails on noise.
//!
//! The health-probe rate is the one exception, and it is the exception
//! that proves the rule: #130 was a bug *no* equality could see, because
//! every verdict the prober reached was correct and only its rate was
//! wrong. So that one check is a band — deliberately loose enough that
//! scheduling cannot move it, and still decisive because what it is aimed
//! at runs two orders of magnitude slow, not a little slow.
//!
//! The origin lives in this process (smoke/origin.zig) rather than being
//! nginx; the load is this file's own client (smoke/client.zig) rather
//! than zrk. Both are deliberate — see those files.

const builtin = @import("builtin");
const std = @import("std");

const client_module = @import("client.zig");
const origin_module = @import("origin.zig");
const scrape_module = @import("scrape.zig");

const Io = std.Io;

const assert = std.debug.assert;

const work_directory = ".zig-cache/zoxy-smoke";
const config_path = work_directory ++ "/zoxy.json";
const access_log_path = work_directory ++ "/access.log";
const zoxy_log_path = work_directory ++ "/zoxy.log";

/// The L7 load: keep-alive connections, each serving the same count. Both
/// numbers are above one on purpose — the access-log equality this gate
/// exists for is a per-*request* claim that a per-*connection* bug
/// satisfies, so a single request on a single connection could not tell
/// the two apart (#129).
const keep_alive_connections: u8 = 4;
const requests_per_connection: u32 = 16;

/// Requests per pass for the origin's bulk target, which arrives as one
/// delivery large enough to overrun zoxy's head buffer — the §7 path
/// where a response's coalesced body excess leaves in a second write
/// (`l7_response_excess_sent`). The simulator's census exempts that
/// counter for want of exactly this delivery.
const large_requests: u32 = 4;

/// The load runs twice over the same connections, with the process's
/// resident set read between the passes. The first pass is what makes the
/// second measurable: zoxy's pools are lazily resident, so an unwarmed
/// reading would climb for reasons that are not allocation. Two identical
/// passes mean any growth between the readings is work the second pass
/// did that the first did not, which — under §5's zero-allocation-after-
/// startup promise — is nothing.
const load_passes: u32 = 2;

/// Connections closed before the drain; the rest are still open when
/// SIGTERM lands. Both teardown paths — a client that left and a drain
/// that reaped — must write nothing, and only running both proves it.
const connections_closed_early: u8 = 2;

/// The L4 load: one exchange per connection, each connection closed by the
/// client. An L4 connection *is* its own log unit (§8), so this is the
/// other half of the line arithmetic.
const l4_connections: u8 = 2;

/// The #178 leg: three exchanges on one connection against the
/// cookie-keyed cluster — assigned (no cookie), followed (the echo),
/// repicked (a forged tag). Run *after* the counter scrapes, so the
/// labeled-partition equality those assert still describes a run where
/// only the `origin` cluster has served.
const sticky_exchanges: u32 = 3;

const exchanges_per_pass: u32 =
    @as(u32, keep_alive_connections) * requests_per_connection + large_requests;
const http_exchanges: u32 = load_passes * exchanges_per_pass;
const access_log_lines_expected: u32 =
    http_exchanges + sticky_exchanges + l4_connections;

/// What the resident set may grow by between the two passes. Measured at
/// exactly zero, run after run — the tolerance is headroom for page
/// granularity and a runtime's own bookkeeping on some other kernel, not
/// a number anything is expected to spend. It still sits under what a
/// per-request allocation of even a kilobyte would cost across a pass of
/// this size, which is the only thing it is looking for.
const rss_growth_kb_max: u64 = 64;

/// Every connection zoxy's data listeners accept in one run: the load's
/// own, plus the readiness probe that connects and asks nothing. Admin
/// scrapes are not among them — the admin plane sits outside the
/// accepted/admitted/shed accounting entirely (§8), which is what lets
/// this be an equality rather than a floor.
///
/// It is an equality on *ports the kernel just handed out*, so a stranger
/// connecting to one between `reservePorts` and zoxy's bind would fail
/// the run. That window is microseconds wide on a port nothing advertises,
/// and the alternative — a floor — is satisfied by a proxy accepting
/// connections nobody made.
const sticky_connections: u32 = 1;
const readiness_probes: u32 = 1;
const connections_expected: u32 = keep_alive_connections +
    load_passes * large_requests + l4_connections + sticky_connections +
    readiness_probes;

/// What the harness holds open against the origin at its peak: every live
/// client connection can have an upstream connection of its own, parked or
/// leased, plus the odd straggler mid-teardown — and one more for the
/// sticky cluster, whose pool parks its own upstream connection (§5
/// pools key by cluster, so the origin cluster's parked one is not
/// reused for it).
const origin_connections_peak: u8 = keep_alive_connections + l4_connections + 2 + 1;

/// The drain's cap on waiting for the connections left open above. A
/// drain cannot tell an idle keep-alive connection from one about to send
/// a request, so it waits for both and reaps what is left at this
/// deadline (§8) — which is the whole of this run's shutdown cost, and
/// therefore the number to keep small. Short enough to stay a gate that
/// runs in a second; long enough that nothing here is racing it, since
/// the load is finished before SIGTERM is sent.
const drain_deadline_ms: u32 = 300;

/// zoxy's pools, shrunk from the lean defaults (§5). Nothing here is a
/// scenario — the load is a handful of connections — so the smallest
/// config that serves it starts fastest and keeps the process's resident
/// set a number a human can read at a glance.
const zoxy_limits = .{ .conn_slots = 32, .relay_buffers = 16, .upstream_slots = 16 };

/// The head buffer zoxy binds for this run — `limits.head_buffer_bytes`
/// is not set, so this is `constants.head_buffer_bytes_default`, spelled
/// again rather than imported. Duplicating it is safe *here* in a way it
/// would not be elsewhere: the only thing that reads it is the
/// bulk-response premise below, and a default that moved past the bulk
/// body would fail this gate's excess equality outright rather than
/// quietly stop exercising the branch.
const zoxy_head_buffer_bytes: u32 = 8 * 1024;

comptime {
    assert(keep_alive_connections >= 2);
    assert(requests_per_connection >= 2);
    // The resident-set claim is "an identical pass costs nothing", and
    // the reading sits *between* the two passes `runLoad` makes — so this
    // constant names that shape for the arithmetic that depends on it
    // rather than parameterizing a loop.
    assert(load_passes == 2);
    assert(large_requests >= 1);
    // The bulk response's premise: its body has to overrun the head
    // buffer, or the excess the gate counts never exists (§7).
    assert(origin_module.large_body_bytes > zoxy_head_buffer_bytes);
    assert(connections_closed_early >= 1);
    assert(connections_closed_early < keep_alive_connections);
    assert(l4_connections >= 1);
    // The origin serves this harness and nothing else, so its pool has to
    // cover the peak with room for the wake-up connections `stop` sends.
    assert(origin_connections_peak < origin_module.serve_tasks);
    // Every client connection needs a slot and a relay buffer at once.
    assert(zoxy_limits.relay_buffers >= keep_alive_connections + l4_connections);
    assert(zoxy_limits.conn_slots >= zoxy_limits.relay_buffers);
    // And every connection this run opens must be admitted rather than
    // shed, or `accepted == connections_expected` would be measuring the
    // conn wall instead of the load.
    assert(zoxy_limits.conn_slots >= connections_expected);
}

/// The health-check shape this run configures, and the window it is
/// measured over (#130). Correctness proves nothing here: a prober that
/// never cancels its probe deadline reports every verdict correctly and
/// gets only the *rate* wrong, which a virtual clock hides behind "it
/// still passed" and a wall clock cannot.
///
/// The band is deliberately loose — a shared runner's scheduling must not
/// move a verdict — and still decisive, because the failure it is aimed
/// at is not a slow prober but one running two orders of magnitude slower
/// than configured.
const health_interval_ms: u32 = 25;
const health_probe_timeout_ms: u32 = 1000;
const probe_window_ms: u32 = 500;
const probe_window_ns: u64 = @as(u64, probe_window_ms) * std.time.ns_per_ms;
/// Whole intervals the window holds — a partial one sends no probe.
const probes_implied: u32 = @divFloor(probe_window_ms, health_interval_ms);
/// A quarter of the implied rate: four times slower than configured is
/// still working, and slower than that is not pacing at all.
const probes_min: u32 = @divFloor(probes_implied, 4);
const probes_max: u32 = probes_implied * 3;

comptime {
    assert(health_interval_ms >= 1);
    assert(probe_window_ms >= 4 * health_interval_ms);
    assert(probes_min >= 2);
    assert(probes_min < probes_implied);
    assert(probes_implied < probes_max);
    // What makes the floor a gate rather than a preference: a probe that
    // idles out its whole timeout instead of finishing (#130 exactly)
    // cannot fit `probes_min` of itself into the window, so the shape is
    // caught by arithmetic and not by taste.
    assert(@divFloor(probe_window_ms, health_probe_timeout_ms) < probes_min);
}

/// The whole run's wall-clock budget. Fifty times what a run takes, so it
/// is never a verdict on speed — it exists because every wait in this
/// harness is a wait on the process under test, and the failure this gate
/// most wants to catch loudly (a proxy that will not drain, #130's
/// neighbourhood) is exactly the one that would otherwise wedge a build
/// step until CI's own timeout killed it with no diagnosis.
const watchdog_budget_ns: u64 = 30 * std.time.ns_per_s;

/// The origin's serve tasks take its address, and the clients hold
/// readers and writers pointing into their own buffers — both want
/// storage that outlives no scope and moves for no reason, which is what
/// static means here (§5's discipline, applied to the harness).
var origin: origin_module.Origin = undefined;
/// The clients start *closed* rather than undefined, so `connect` can
/// assert it is not overwriting a live connection — which is what makes
/// one slot safely reusable below.
var clients: [keep_alive_connections]client_module.Client = @splat(.{});
/// The slot for connections that serve exactly one exchange and close —
/// the bulk requests and the L4 leg. One at a time by construction: each
/// is closed before the next is opened, and `connect` asserts it.
var single_client: client_module.Client = .{};

/// The proxy the watchdog kills if it fires, published by `spawnZoxy`.
/// Zero until then — the watchdog can outlive the spawn failing.
var watchdog_child_pid = std.atomic.Value(i32).init(0);

const Flags = struct {
    zoxy_path: []const u8 = "zig-out/bin/zoxy",
};

/// The ports zoxy is told to bind. Kernel-assigned rather than fixed: a
/// per-change gate must not fail because a developer's other terminal is
/// already on 18080.
const Ports = struct {
    http: u16,
    l4: u16,
    admin: u16,
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    const flags = try parseFlags(args);

    // Armed before anything that can block, and cancelled by the defer on
    // every exit path — success, failure, or a propagated error.
    var watchdog: Io.Group = .init;
    try watchdog.concurrent(io, watchdogTask, .{io});
    defer watchdog.cancel(io);

    // A setup failure — a refused scrape, a proxy that never listened —
    // is reported the same way a failed verdict is, because to whoever is
    // reading a red gate they are the same question: what did zoxy do?
    // Answering it with a bare error trace and no log would be the one
    // reply that helps least.
    return run(arena, io, &flags) catch |err| {
        std.debug.print("FAIL: the smoke run could not finish ({t})\n", .{err});
        printZoxyLog(io);
        return 1;
    };
}

/// One whole run, from an empty work directory to a verdict.
fn run(arena: std.mem.Allocator, io: Io, flags: *const Flags) !u8 {
    try prepareWorkDirectory(io);
    try origin.start(io, origin_connections_peak);
    // Ordered against the child's own teardown below: defers unwind
    // last-declared-first, so zoxy is always gone before this runs — which
    // is what releases the origin tasks parked in `read` on its upstream
    // connections.
    defer origin.stop();

    const ports = try reservePorts(io);
    try writeConfig(arena, io, &ports, origin.port);
    var child = try spawnZoxy(io, flags.zoxy_path);
    var running = true;
    defer if (running) child.kill(io);

    try awaitListening(io, ports.http);
    const memory = try runLoad(arena, io, &ports, child.id);

    // Scraped before the drain: the admin listener closes with every
    // other one when SIGTERM lands (§8).
    const counters = try countersPassed(arena, io, ports.admin, origin.port);
    // The #178 leg runs after the scrapes above on purpose — see
    // `sticky_exchanges` — and brings its own scrape.
    const sticky_ok = try stickyPassed(arena, io, &ports);
    const drained_cleanly = try drain(io, &child, &running);
    const lines = try readAccessLog(arena, io);
    // Every check runs and prints; a run that fails two ways should say
    // both, not stop at the first.
    const log_ok = accessLogPassed(&lines);
    const memory_ok = memoryPassed(&memory);
    const drain_ok = drainPassed(drained_cleanly);
    const passed = log_ok and counters.passed and sticky_ok and memory_ok and drain_ok;
    return report(io, &lines, &counters, &memory, passed);
}

/// The run's one line of output when everything held, and the proxy's own
/// output when something did not. The probe count and the resident set
/// are in it either way — a margin nobody can see is a margin nobody can
/// watch across runs.
fn report(
    io: Io,
    lines: *const LogCounts,
    counters: *const CounterVerdict,
    memory: *const Memory,
    passed: bool,
) u8 {
    assert(lines.http_ok <= lines.http);
    if (!passed) {
        printZoxyLog(io);
        return 1;
    }
    var memory_buffer: [64]u8 = undefined;
    std.debug.print(
        "smoke: {d} http + {d} l4 exchanges, {d} access-log lines, counters reconcile, " ++
            "{d} probes in {d}ms, {s}, clean drain\n",
        .{
            lines.http,
            lines.l4,
            access_log_lines_expected,
            counters.probes,
            probe_window_ms,
            memorySummary(memory, &memory_buffer),
        },
    );
    return 0;
}

/// The two readings as text, printed rather than differenced: a resident
/// set may legally *shrink* between them (the kernel reclaims pages when
/// it likes), and `memoryPassed` treats that as a pass — so a delta here
/// would be a subtraction that underflows on a run that was fine.
fn memorySummary(memory: *const Memory, buffer: []u8) []const u8 {
    assert(buffer.len >= 1);
    const before = memory.before_kb orelse return "rss unread";
    const after = memory.after_kb orelse return "rss unread";
    return std.fmt.bufPrint(buffer, "rss {d} -> {d} KiB", .{ before, after }) catch
        "rss unprintable";
}

/// The wall-clock backstop. Nothing in this harness can bound its own
/// wait — a `read` on a proxy that accepted and went quiet, a `wait` on
/// one that will not exit, an origin task parked on a socket the proxy
/// never closed — so the bound is one budget over the whole run, held out
/// here where no wedged operation can be holding it.
///
/// It ends the process rather than reporting upward, because there is no
/// upward: the thread that would receive the report is the wedged one.
/// The proxy is killed first, so a run that times out leaves no orphan
/// holding the ports the next one will ask the kernel for.
fn watchdogTask(io: Io) void {
    io.sleep(Io.Duration.fromNanoseconds(watchdog_budget_ns), .awake) catch |err| {
        // The run finished and cancelled this task, which is every
        // ordinary exit; nothing else cancels it.
        assert(err == error.Canceled);
        return;
    };
    std.debug.print(
        "FAIL: smoke run exceeded its {d}s budget — something is wedged, not slow\n",
        .{watchdog_budget_ns / std.time.ns_per_s},
    );
    const pid = watchdog_child_pid.load(.acquire);
    if (pid != 0) {
        std.posix.kill(pid, .KILL) catch {};
    }
    printZoxyLog(io);
    std.process.exit(3);
}

/// What one run of the access log said, as counts rather than text: the
/// gate's verdicts are equalities over these.
const LogCounts = struct {
    http: u32 = 0,
    l4: u32 = 0,
    /// Lines that were neither, so "the file holds exactly what it should"
    /// is checkable rather than merely "it holds at least that".
    other: u32 = 0,
    /// HTTP lines that both completed and carried the origin's status —
    /// the outcome every request in this load is owed.
    http_ok: u32 = 0,
};

/// The access-log verdict, printed so a red run explains itself without a
/// rerun. Every clause is an equality against a number this harness
/// decided before the run started.
fn accessLogPassed(lines: *const LogCounts) bool {
    // Both are counted off the same lines, in the same pass, so a total
    // below its own subset would mean the counter itself is wrong — which
    // no comparison below would otherwise notice.
    assert(lines.http_ok <= lines.http);
    assert(access_log_lines_expected == http_exchanges + sticky_exchanges + l4_connections);
    var passed = true;
    if (lines.http != http_exchanges + sticky_exchanges) {
        std.debug.print(
            "FAIL: {d} http access-log lines for {d} requests (#129 is exactly this)\n",
            .{ lines.http, http_exchanges + sticky_exchanges },
        );
        passed = false;
    }
    if (lines.l4 != l4_connections) {
        std.debug.print(
            "FAIL: {d} l4 access-log lines for {d} connections\n",
            .{ lines.l4, l4_connections },
        );
        passed = false;
    }
    if (lines.other != 0) {
        std.debug.print("FAIL: {d} access-log lines of no known kind\n", .{lines.other});
        passed = false;
    }
    if (lines.http_ok != lines.http) {
        std.debug.print(
            "FAIL: {d} of {d} http lines did not complete with the origin's 200\n",
            .{ lines.http - lines.http_ok, lines.http },
        );
        passed = false;
    }
    return passed;
}

fn drainPassed(drained_cleanly: bool) bool {
    if (drained_cleanly) return true;
    std.debug.print("FAIL: zoxy did not drain cleanly on SIGTERM\n", .{});
    return false;
}

/// Two scrapes a measured window apart, and every counter verdict the
/// gate holds. The window is what makes the probe band a wall-clock
/// claim; the two scrapes are also what `admin_served` needs, since the
/// first one's own witness is incremented when its last byte lands and
/// can only be read by the next.
fn countersPassed(
    arena: std.mem.Allocator,
    io: Io,
    port: u16,
    origin_port: u16,
) !CounterVerdict {
    assert(port != 0);
    assert(origin_port != 0);
    const first = try scrape_module.parse(try scrape_module.fetch(arena, io, port));
    try io.sleep(Io.Duration.fromNanoseconds(probe_window_ns), .awake);
    const second = try scrape_module.parse(try scrape_module.fetch(arena, io, port));
    const probes = probeDelta(&first, &second);
    const identities_ok = identitiesPassed(&first);
    const probes_ok = probesPassed(probes, &second);
    const admin_ok = adminPassed(&second);
    const labeled_ok = try labeledPassed(arena, &first, origin_port);
    const passed = identities_ok and probes_ok and admin_ok and labeled_ok;
    // A verdict that passed read a probe count; the reported number is
    // never the zero that stands in for a counter the scrape lacked.
    if (passed) assert(probes != null);
    return .{ .passed = passed, .probes = probes orelse 0 };
}

/// The #179 labeled families, judged on the wire like the identities
/// above. This config has one cluster with one endpoint, so every
/// labeled series must carry its whole process total — the partition
/// identities `reconcile` asserts inside the process, re-derived from
/// the rendered text — and the two gauges must be present, with the
/// prober's verdict reading healthy against an origin answering 200.
fn labeledPassed(
    arena: std.mem.Allocator,
    first: *const scrape_module.Scrape,
    origin_port: u16,
) !bool {
    assert(origin_port != 0);
    const endpoint_label = try std.fmt.allocPrint(
        arena,
        "{{cluster=\"origin\",endpoint=\"127.0.0.1:{d}\"}}",
        .{origin_port},
    );
    var passed = true;
    const partitions = [_]struct { family: []const u8, total: []const u8, labeled: bool }{
        .{ .family = "endpoint_responses", .total = "l7_responses", .labeled = true },
        .{ .family = "endpoint_connect_failed", .total = "upstream_connect_failed", .labeled = true },
        .{ .family = "endpoint_health_down", .total = "health_endpoint_down", .labeled = true },
        .{ .family = "endpoint_health_up", .total = "health_endpoint_up", .labeled = true },
        .{ .family = "cluster_l7_shed_inflight", .total = "l7_shed_endpoint_inflight", .labeled = false },
        .{ .family = "cluster_l4_shed_inflight", .total = "l4_shed_endpoint_inflight", .labeled = false },
    };
    for (partitions) |partition| {
        const label = if (partition.labeled) endpoint_label else "{cluster=\"origin\"}";
        const series = try std.fmt.allocPrint(arena, "{s}{s}", .{ partition.family, label });
        const series_value = counterOf(first, series) orelse {
            passed = false;
            continue;
        };
        const total = counterOf(first, partition.total) orelse {
            passed = false;
            continue;
        };
        if (series_value != total) {
            std.debug.print(
                "FAIL: {s} reads {d} but {s} reads {d} — the one endpoint must hold its whole partition\n",
                .{ series, series_value, partition.total, total },
            );
            passed = false;
        }
    }
    const healthy_series = try std.fmt.allocPrint(arena, "endpoint_healthy{s}", .{endpoint_label});
    const healthy = counterOf(first, healthy_series) orelse return false;
    if (healthy != 1) {
        std.debug.print("FAIL: {s} reads {d} against an origin answering 200\n", .{ healthy_series, healthy });
        passed = false;
    }
    const inflight_series = try std.fmt.allocPrint(arena, "endpoint_inflight{s}", .{endpoint_label});
    if (counterOf(first, inflight_series) == null) passed = false;
    return passed;
}

/// What the counter checks decided, and the one number worth printing
/// whether or not they passed: a band whose margin is invisible until it
/// fails cannot be watched across runs.
const CounterVerdict = struct {
    passed: bool,
    probes: u32,
};

/// Probes sent across the measured window, or null when the scrape did
/// not carry the counter at all.
fn probeDelta(first: *const scrape_module.Scrape, second: *const scrape_module.Scrape) ?u32 {
    const before = counterOf(first, "health_probes_sent") orelse return null;
    const after = counterOf(second, "health_probes_sent") orelse return null;
    // A counter only ever rises, and the window is the only thing between
    // these two readings.
    assert(after >= before);
    assert(after - before <= std.math.maxInt(u32));
    return @intCast(after - before);
}

/// The §7 prober, judged on its rate rather than its verdicts (#130).
/// Both ends of the band are gates: the floor catches a prober that
/// waits out something it should have cancelled, the ceiling one that
/// stopped pacing and is spinning on the origin.
///
/// The verdicts are checked too, as invariants that read zero — this
/// origin answers every probe, so a failure or an ejection here is the
/// probe path being wrong about a healthy endpoint.
fn probesPassed(sent: ?u32, second: *const scrape_module.Scrape) bool {
    const failed = counterOf(second, "health_probes_failed") orelse return false;
    const ejected = counterOf(second, "health_endpoint_down") orelse return false;
    // An ejection needs a failed probe, which `reconcile` asserts inside
    // the process; the same must be true of what came out of it.
    assert(ejected <= failed);
    if (sent == null) return false;
    var passed = true;
    if (sent.? < probes_min or sent.? > probes_max) {
        std.debug.print(
            "FAIL: {d} probes in {d}ms at a {d}ms interval — outside the {d}..{d} band\n",
            .{ sent.?, probe_window_ms, health_interval_ms, probes_min, probes_max },
        );
        passed = false;
    }
    if (failed != 0 or ejected != 0) {
        std.debug.print(
            "FAIL: {d} probe(s) failed and {d} ejection(s) against an origin answering 200\n",
            .{ failed, ejected },
        );
        passed = false;
    }
    return passed;
}

/// The admin plane's own witness: the scrape that answered before this
/// one, and no other. Exactly one, not "at least" — the plane serves one
/// at a time (§8's reserved slot), so the second scrape is accepted only
/// after the first has closed.
fn adminPassed(second: *const scrape_module.Scrape) bool {
    const served = counterOf(second, "admin_served") orelse return false;
    if (served == 1) return true;
    std.debug.print("FAIL: {d} admin scrapes served before the second, not 1\n", .{served});
    return false;
}

/// Both of `reconcile`'s identities (§9), re-derived from a live scrape
/// instead of from the struct — the numbers rendered, written to a
/// socket, framed by a close and parsed back, so the whole admin plane is
/// under the same verdict as the arithmetic.
fn identitiesPassed(first: *const scrape_module.Scrape) bool {
    const accepted = counterOf(first, "accepted") orelse return false;
    const admitted = counterOf(first, "admitted") orelse return false;
    const completed = counterOf(first, "completed") orelse return false;
    const in_use = counterOf(first, "conn_slots_in_use") orelse return false;
    const responses = counterOf(first, "l7_responses") orelse return false;
    const reused = counterOf(first, "upstream_reused") orelse return false;
    const excess = counterOf(first, "l7_response_excess_sent") orelse return false;
    // The orderings `reconcile` asserts inside the process, asserted here
    // on the numbers that came back out of it: these are impossible
    // states, not failed verdicts, and a scrape that parsed the wrong
    // bytes into the right names would show up as one of them rather than
    // as a plausible-looking mismatch below.
    assert(admitted <= accepted);
    assert(completed <= admitted);
    assert(in_use <= admitted);
    assert(reused <= responses);
    assert(excess <= responses);
    var passed = true;
    // The gate identity: an accepted connection was admitted or shed,
    // with no third outcome.
    if (accepted != admitted + first.shedTotal()) {
        std.debug.print(
            "FAIL: accepted {d} != admitted {d} + shed {d}\n",
            .{ accepted, admitted, first.shedTotal() },
        );
        passed = false;
    }
    // The flow identity: admitted work is completed or still active.
    if (admitted != completed + in_use) {
        std.debug.print(
            "FAIL: admitted {d} != completed {d} + in use {d}\n",
            .{ admitted, completed, in_use },
        );
        passed = false;
    }
    // Minus the #178 leg, which deliberately runs after this scrape (see
    // `sticky_exchanges`); the whole-run equality is asserted on the
    // sticky verdict's own later scrape.
    if (accepted != connections_expected - sticky_connections) {
        std.debug.print(
            "FAIL: {d} connections accepted, not the {d} opened before this scrape\n",
            .{ accepted, connections_expected - sticky_connections },
        );
        passed = false;
    }
    return loadShapePassed(responses, reused, excess) and passed;
}

/// The load's own shape, read back off the same first scrape — split
/// from `identitiesPassed` when the #178 deferral note pushed that one
/// past the length limit.
fn loadShapePassed(responses: u64, reused: u64, excess: u64) bool {
    var passed = true;
    // The counter and the log describe the same exchanges, so a
    // disagreement is one of the two lying about the same run.
    if (responses != http_exchanges) {
        std.debug.print(
            "FAIL: {d} l7 responses counted for {d} requests\n",
            .{ responses, http_exchanges },
        );
        passed = false;
    }
    // §3's reuse win, witnessed live: this load is one exchange after
    // another against a keep-alive origin, so a proxy that parks nothing
    // is the only way to reach zero here.
    if (reused == 0) {
        std.debug.print("FAIL: no upstream connection was reused across {d} exchanges\n", .{
            http_exchanges,
        });
        passed = false;
    }
    // The §7 branch the simulator cannot reach: an origin delivery that
    // filled the head buffer, so the body excess coalesced with the head
    // had to leave in a write of its own. Every bulk request in this run
    // is that delivery, which is why this is a count rather than a
    // witness.
    if (excess != large_requests * load_passes) {
        std.debug.print(
            "FAIL: {d} responses sent body excess, not the {d} bulk requests this run made\n",
            .{ excess, large_requests * load_passes },
        );
        passed = false;
    }
    return passed;
}

/// A counter the gate reads, or a printed failure and null. A missing
/// name is its own finding — the scrape renders every field, so absence
/// means a rename the harness has not followed, not a zero.
fn counterOf(scrape: *const scrape_module.Scrape, name: []const u8) ?u64 {
    assert(name.len >= 1);
    const value = scrape.value(name);
    if (value == null) {
        std.debug.print("FAIL: the scrape carries no counter named {s}\n", .{name});
    }
    return value;
}

/// The load: two identical passes over the same keep-alive connections
/// with the proxy's resident set read between them, then the L4 leg, then
/// some connections closed and the rest left for the drain.
fn runLoad(
    arena: std.mem.Allocator,
    io: Io,
    ports: *const Ports,
    pid: ?std.process.Child.Id,
) !Memory {
    assert(ports.http != 0);
    assert(ports.l4 != 0);
    var host_buffer: [32]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buffer, "127.0.0.1:{d}", .{ports.http});
    for (&clients) |*client| {
        try client.connect(io, ports.http);
    }
    try runPass(io, ports.http, host, 0);
    // Read between the passes, not before the first: zoxy's pools are
    // lazily resident (§5), so a reading taken before any traffic would
    // climb for reasons that are not allocation.
    const before_kb = try readRssKb(arena, io, pid);
    try runPass(io, ports.http, host, 1);
    const after_kb = try readRssKb(arena, io, pid);
    for (clients[0..connections_closed_early]) |*client| {
        client.close();
    }
    try runL4Load(io, ports.l4, host);
    return .{ .before_kb = before_kb, .after_kb = after_kb };
}

/// One pass: every open connection serves its whole share of ordinary
/// requests, then the bulk target runs on one of them. Both passes are
/// identical, which is what makes the resident set between them a claim
/// about allocation rather than about warmup.
fn runPass(io: Io, port: u16, host: []const u8, pass: u32) !void {
    assert(host.len >= 1);
    assert(clients.len == keep_alive_connections);
    assert(pass < load_passes);
    for (&clients, 0..) |*client, connection| {
        var request: u32 = 0;
        while (request < requests_per_connection) : (request += 1) {
            // Where a failure happened is most of what a failure means
            // here: the same error from the first keep-alive request and
            // from the hundredth are different bugs, and the second is
            // not reproducible by staring at the first.
            const response = client.get(host, "/", .keep_alive, null) catch |err| {
                std.debug.print(
                    "smoke: pass {d} keep-alive connection {d} request {d}: {t}\n",
                    .{ pass, connection, request, err },
                );
                return err;
            };
            try expectResponse(response, origin_module.body.len, .http);
        }
        assert(request == requests_per_connection);
    }
    // The bulk requests announce close, on their own connections because
    // that is what announcing close means. Both halves are load-bearing:
    // the delivery fills the head buffer, and the injected
    // `Connection: close` is what makes zoxy's rendered head longer than
    // the origin's — without which the excess fits beside it exactly and
    // the branch never runs (§7).
    var large: u32 = 0;
    while (large < large_requests) : (large += 1) {
        try single_client.connect(io, port);
        defer single_client.close();
        const response = single_client.get(host, origin_module.large_path, .close, null) catch |err| {
            std.debug.print("smoke: pass {d} bulk request {d}: {t}\n", .{ pass, large, err });
            return err;
        };
        try expectResponse(response, origin_module.large_body_bytes, .http);
    }
    assert(large == large_requests);
}

/// The L4 leg (§6): the same HTTP exchange through the byte relay, which
/// neither parses nor frames it. One connection per exchange, closed by
/// the client — an L4 line describes a connection, not a request.
fn runL4Load(io: Io, port: u16, host: []const u8) !void {
    assert(port != 0);
    assert(host.len >= 1);
    var index: u8 = 0;
    while (index < l4_connections) : (index += 1) {
        try single_client.connect(io, port);
        defer single_client.close();
        const response = single_client.get(host, "/", .keep_alive, null) catch |err| {
            std.debug.print("smoke: l4 connection {d}: {t}\n", .{ index, err });
            return err;
        };
        try expectResponse(response, origin_module.body.len, .l4);
    }
    assert(index == l4_connections);
}

/// Which listener the exchange crossed, because the #175 stamp cuts both
/// ways: the http leg re-renders the response head and must carry it,
/// while the l4 leg's whole claim is byte transparency — the stamp there
/// would mean L7 machinery leaked into the raw relay.
const Leg = enum { http, l4 };

/// The response the origin sent, checked byte-count and all: a hop that
/// truncated or re-framed a body is a data-path bug this tier sees before
/// any counter does — and the bulk target is where a hop is most likely
/// to, since its body crosses the head buffer in more than one piece.
fn expectResponse(response: client_module.Response, body_bytes: u32, leg: Leg) !void {
    // The client parses both out of the wire and bounds them there; a
    // value outside those bounds reaching here would mean the two files
    // disagree about what a response is.
    assert(response.status >= 100);
    assert(response.body_bytes <= client_module.response_body_bytes_max);
    if (response.status != 200) {
        std.debug.print("smoke: origin answered {d}, not 200\n", .{response.status});
        return error.UnexpectedStatus;
    }
    if (response.body_bytes != body_bytes) {
        std.debug.print(
            "smoke: body was {d} bytes, not {d}\n",
            .{ response.body_bytes, body_bytes },
        );
        return error.UnexpectedBody;
    }
    // The #175 stamp, judged per leg: on http its absence means the
    // response edit path did not run on the real wire; on l4 its
    // presence means the relay stopped being a relay.
    switch (leg) {
        .http => if (!response.edited) {
            std.debug.print("smoke: http response carried no X-Zoxy-Smoke stamp\n", .{});
            return error.ResponseEditMissing;
        },
        .l4 => if (response.edited) {
            std.debug.print("smoke: l4-relayed response gained the X-Zoxy-Smoke stamp\n", .{});
            return error.ResponseEditForged;
        },
    }
    // The #178 cookie belongs to the sticky cluster alone: the `origin`
    // cluster is not cookie-keyed, and the l4 leg is a byte relay — a
    // tag on either means the stamp path fired for a cluster that never
    // asked for it.
    if (response.sticky_tag != null) {
        std.debug.print("smoke: a non-sticky response announced an endpoint tag\n", .{});
        return error.StickyStampForged;
    }
}

/// The #178 live round trip: three exchanges on one keep-alive
/// connection against the cookie-keyed cluster, each response judged on
/// the spot, then the counters on a scrape of their own. Runs after
/// `countersPassed` so the partition identities that scrape asserts
/// still describe a one-cluster run.
fn stickyPassed(arena: std.mem.Allocator, io: Io, ports: *const Ports) !bool {
    assert(ports.http != 0);
    assert(ports.admin != 0);
    var host_buffer: [32]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buffer, "127.0.0.1:{d}", .{ports.http});
    try single_client.connect(io, ports.http);
    defer single_client.close();

    // Cookieless: assigned, and the response must announce a tag (the
    // reader enforced the whole grammar before handing it over).
    const assigned = try single_client.get(host, "/sticky", .keep_alive, null);
    try expectStickyResponse(assigned, "assigned", true);
    const tag = assigned.sticky_tag.?;

    // The echo: followed, and no re-stamp — idempotence on the wire.
    var cookie_buffer: [64]u8 = undefined;
    const echo = try std.fmt.bufPrint(&cookie_buffer, "zoxy-smoke-srv={s}", .{&tag});
    const followed = try single_client.get(host, "/sticky", .keep_alive, echo);
    try expectStickyResponse(followed, "followed", false);

    // A forged well-formed tag: repicked, and the re-announcement must
    // name the same endpoint the first exchange was assigned — there is
    // only one, and its tag does not drift within a run.
    const repicked = try single_client.get(
        host,
        "/sticky",
        .close,
        "zoxy-smoke-srv=ffffffffffffffff",
    );
    try expectStickyResponse(repicked, "repicked", true);
    if (!std.mem.eql(u8, &repicked.sticky_tag.?, &tag)) {
        std.debug.print("smoke: the re-announced tag differs from the assigned one\n", .{});
        return false;
    }

    const scrape = try scrape_module.parse(try scrape_module.fetch(arena, io, ports.admin));
    var passed = true;
    const verdicts = [_]struct { name: []const u8, expected: u64 }{
        .{ .name = "l7_sticky_assigned", .expected = 1 },
        .{ .name = "l7_sticky_followed", .expected = 1 },
        .{ .name = "l7_sticky_repicked", .expected = 1 },
    };
    for (verdicts) |verdict| {
        const value = counterOf(&scrape, verdict.name) orelse {
            passed = false;
            continue;
        };
        if (value != verdict.expected) {
            std.debug.print(
                "FAIL: {s} reads {d}, not {d}, after the three sticky exchanges\n",
                .{ verdict.name, value, verdict.expected },
            );
            passed = false;
        }
    }
    // The whole-run accept equality, deferred from `identitiesPassed`:
    // with the sticky connection in, every accepted connection is
    // accounted for again.
    const accepted = counterOf(&scrape, "accepted") orelse return false;
    if (accepted != connections_expected) {
        std.debug.print(
            "FAIL: {d} connections accepted, not the {d} this run opened\n",
            .{ accepted, connections_expected },
        );
        passed = false;
    }
    return passed;
}

/// One sticky response: the ordinary http-leg checks, then the #178
/// announcement judged present or absent by the exchange's role.
fn expectStickyResponse(
    response: client_module.Response,
    role: []const u8,
    expect_tag: bool,
) !void {
    assert(role.len >= 1);
    if (response.status != 200) {
        std.debug.print("smoke: sticky {s} exchange answered {d}, not 200\n", .{ role, response.status });
        return error.UnexpectedStatus;
    }
    if (response.body_bytes != origin_module.body.len) {
        std.debug.print("smoke: sticky {s} exchange body was {d} bytes\n", .{ role, response.body_bytes });
        return error.UnexpectedBody;
    }
    // The listener's #175 stamp applies to this leg like any other —
    // the two response-side mechanisms must coexist on one head.
    if (!response.edited) {
        std.debug.print("smoke: sticky {s} response carried no X-Zoxy-Smoke stamp\n", .{role});
        return error.ResponseEditMissing;
    }
    if (expect_tag and response.sticky_tag == null) {
        std.debug.print("smoke: sticky {s} response announced no tag\n", .{role});
        return error.StickyStampMissing;
    }
    if (!expect_tag and response.sticky_tag != null) {
        std.debug.print("smoke: sticky {s} response re-announced a tag it must not\n", .{role});
        return error.StickyStampForged;
    }
}

/// The proxy's resident set across the measured pass. Null off Linux,
/// where there is no procfs to read it from — the gate says so rather
/// than pretending it checked.
const Memory = struct {
    before_kb: ?u64,
    after_kb: ?u64,
};

/// §5's promise from outside the process: two identical passes, and the
/// second one costs no memory. Growth *inside* a pass would be lazy
/// fault-in working as designed, which is what the first pass is for.
fn memoryPassed(memory: *const Memory) bool {
    if (memory.before_kb == null or memory.after_kb == null) {
        std.debug.print("smoke: resident set unread (no procfs here); memory check skipped\n", .{});
        return true;
    }
    const before = memory.before_kb.?;
    const after = memory.after_kb.?;
    // A live process always has resident pages; zero would mean the
    // reading failed rather than that the proxy shrank to nothing.
    assert(before > 0);
    assert(after > 0);
    if (after <= before + rss_growth_kb_max) return true;
    std.debug.print(
        "FAIL: resident set grew {d} KiB across an identical second pass ({d} -> {d} KiB)\n",
        .{ after - before, before, after },
    );
    return false;
}

/// The proxy's resident set, in KiB. procfs advertises size 0, so this
/// streams rather than trusting a stat.
fn readRssKb(arena: std.mem.Allocator, io: Io, pid: ?std.process.Child.Id) !?u64 {
    if (builtin.os.tag != .linux) return null;
    assert(pid != null);
    const path = try std.fmt.allocPrint(arena, "/proc/{d}/status", .{pid.?});
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var read_buffer: [4096]u8 = undefined;
    var file_reader = file.reader(io, &read_buffer);
    var status: [8192]u8 = undefined;
    const status_len = try file_reader.interface.readSliceShort(&status);
    assert(status_len > 0);
    var lines = std.mem.splitScalar(u8, status[0..status_len], '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "VmRSS:")) continue;
        const digits_start = std.mem.indexOfAny(u8, line, "0123456789") orelse break;
        const digits_end = std.mem.indexOfScalarPos(u8, line, digits_start, ' ') orelse break;
        return try std.fmt.parseUnsigned(u64, line[digits_start..digits_end], 10);
    }
    return error.RssUnavailable;
}

/// Drain, not just death (§8): SIGTERM, then a wait that both reaps the
/// child and reports whether it left of its own accord. Clears `running`
/// so the caller's guarded defer cannot double-kill.
fn drain(io: Io, child: *std.process.Child, running: *bool) !bool {
    assert(running.*);
    assert(child.id != null);
    try std.posix.kill(child.id.?, .TERM);
    const term = try child.wait(io);
    running.* = false;
    return term == .exited and term.exited == 0;
}

/// Count what the run wrote. The whole file is read at once: the log is
/// bounded by the load this harness issued, and a file bigger than the
/// cap is itself the finding.
fn readAccessLog(arena: std.mem.Allocator, io: Io) !LogCounts {
    const bytes_max = @as(usize, access_log_lines_expected + 64) * 1024;
    const text = try Io.Dir.cwd().readFileAlloc(io, access_log_path, arena, .limited(bytes_max));
    assert(text.len <= bytes_max);
    var counts: LogCounts = .{};
    var remaining = std.mem.splitScalar(u8, text, '\n');
    while (remaining.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.indexOf(u8, line, "\"kind\":\"http\"") != null) {
            counts.http += 1;
            const completed = std.mem.indexOf(u8, line, "\"outcome\":\"ok\"") != null;
            const answered = std.mem.indexOf(u8, line, "\"status\":200") != null;
            if (completed and answered) counts.http_ok += 1;
        } else {
            if (std.mem.indexOf(u8, line, "\"kind\":\"l4\"") != null) {
                counts.l4 += 1;
            } else {
                counts.other += 1;
            }
        }
    }
    return counts;
}

/// Two loopback ports the kernel is not using, held open together so it
/// cannot hand out the same one twice, then released for zoxy to bind.
/// There is a window between the release and zoxy's bind; nothing can
/// close it from out here, and it is far smaller than the collision a
/// hard-coded pair would carry on a shared runner.
fn reservePorts(io: Io) !Ports {
    var http_address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var http_listener = try http_address.listen(io, .{ .mode = .stream });
    var l4_address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var l4_listener = try l4_address.listen(io, .{ .mode = .stream });
    var admin_address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var admin_listener = try admin_address.listen(io, .{ .mode = .stream });
    const ports: Ports = .{
        .http = http_listener.socket.address.getPort(),
        .l4 = l4_listener.socket.address.getPort(),
        .admin = admin_listener.socket.address.getPort(),
    };
    http_listener.deinit(io);
    l4_listener.deinit(io);
    admin_listener.deinit(io);
    assert(ports.http != 0);
    assert(ports.l4 != 0);
    assert(ports.admin != 0);
    assert(ports.http != ports.l4);
    assert(ports.http != ports.admin);
    assert(ports.l4 != ports.admin);
    return ports;
}

/// Both protocols against one origin (§6, §7), with the access log on a
/// file rather than stdout: the file is what this gate counts, and a pipe
/// nobody drains is a drop rung (§8) waiting to make the count a lie.
fn writeConfig(arena: std.mem.Allocator, io: Io, ports: *const Ports, origin_port: u16) !void {
    assert(origin_port != 0);
    const config_json = try std.fmt.allocPrint(arena,
        \\{{
        \\    "listeners": [
        \\        {{ "bind": "127.0.0.1:{d}", "protocol": "http",
        \\          "routes": [
        \\              {{ "prefix": "/", "cluster": "origin" }},
        \\              {{ "prefix": "/sticky", "cluster": "sticky" }}
        \\          ],
        \\          "response_filters": [
        \\              {{ "actions": [{{ "header_set": {{ "name": "X-Zoxy-Smoke", "value": "1" }} }}] }}
        \\          ] }},
        \\        {{ "bind": "127.0.0.1:{d}", "cluster": "origin", "protocol": "l4" }}
        \\    ],
        \\    "clusters": {{
        \\        "origin": {{
        \\            "endpoints": ["127.0.0.1:{d}"],
        \\            "check": {{ "type": "http", "path": "/health", "timeout_ms": {d} }}
        \\        }},
        \\        "sticky": {{
        \\            "endpoints": ["127.0.0.1:{d}"],
        \\            "pick": {{ "policy": "hash", "key": "cookie", "name": "zoxy-smoke-srv" }}
        \\        }}
        \\    }},
        \\    "admin": {{ "bind": "127.0.0.1:{d}" }},
        \\    "access_log": {{ "sink": "file", "path": "{s}" }},
        \\    "timeouts": {{
        \\        "connect_ms": 2000,
        \\        "idle_ms": 30000,
        \\        "health_interval_ms": {d},
        \\        "drain_deadline_ms": {d}
        \\    }},
        \\    "limits": {{
        \\        "conn_slots": {d},
        \\        "relay_buffers": {d},
        \\        "upstream_slots": {d}
        \\    }}
        \\}}
        \\
    , .{
        ports.http,
        ports.l4,
        origin_port,
        health_probe_timeout_ms,
        origin_port,
        ports.admin,
        access_log_path,
        health_interval_ms,
        drain_deadline_ms,
        zoxy_limits.conn_slots,
        zoxy_limits.relay_buffers,
        zoxy_limits.upstream_slots,
    });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = config_json });
}

/// A fresh work directory every run: the file sink is append-only by
/// design (§8, so an external rotation is safe), which makes a stale log
/// from the last run indistinguishable from this one's output.
fn prepareWorkDirectory(io: Io) !void {
    try Io.Dir.cwd().createDirPath(io, work_directory);
    Io.Dir.cwd().deleteFile(io, access_log_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

/// zoxy's own output goes to a file rather than this process's stderr:
/// the banner and the drain-time counter dump are a hundred lines of
/// post-mortem that a green per-change gate should not print. A red one
/// prints its tail (`printZoxyLog`).
fn spawnZoxy(io: Io, zoxy_path: []const u8) !std.process.Child {
    assert(zoxy_path.len >= 1);
    const log_file = try Io.Dir.cwd().createFile(io, zoxy_log_path, .{});
    defer log_file.close(io);
    const child = std.process.spawn(io, .{
        .argv = &.{ zoxy_path, config_path },
        .stdout = .{ .file = log_file },
        .stderr = .{ .file = log_file },
    }) catch |err| {
        std.debug.print(
            "smoke: could not spawn {s} ({t}); run `zig build` first\n",
            .{ zoxy_path, err },
        );
        return err;
    };
    // Everything that can wedge from here on is a wait on this process,
    // so the watchdog needs it before the first of those waits.
    assert(child.id != null);
    watchdog_child_pid.store(child.id.?, .release);
    return child;
}

/// Wait for the listener to answer a connect, and nothing more: a probe
/// that sent a *request* would be an exchange, and every exchange in this
/// run is one the line arithmetic already counted. An accepted connection
/// that asks nothing owes no line (§8), so this one is invisible to the
/// gate by construction.
fn awaitListening(io: Io, port: u16) !void {
    assert(port != 0);
    const attempts_max: u16 = 200;
    const retry_delay = Io.Duration.fromNanoseconds(25 * std.time.ns_per_ms);
    var attempt: u16 = 0;
    while (attempt < attempts_max) : (attempt += 1) {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        const stream = address.connect(io, .{ .mode = .stream }) catch {
            // The pause is pacing, not correctness: a sleep that failed
            // or woke early only means the next probe runs sooner, and
            // the attempt cap is what bounds the wait either way.
            io.sleep(retry_delay, .awake) catch {};
            continue;
        };
        stream.close(io);
        return;
    }
    assert(attempt == attempts_max);
    std.debug.print("smoke: zoxy never listened on port {d}\n", .{port});
    printZoxyLog(io);
    return error.ZoxyNeverListened;
}

/// The head of zoxy's captured output, for a failing run — the banner and
/// whatever it said before giving up. Best-effort: this runs when
/// something has already gone wrong, so an unreadable log must not
/// replace the failure that is being reported.
fn printZoxyLog(io: Io) void {
    var buffer: [16 * 1024]u8 = undefined;
    const file = Io.Dir.cwd().openFile(io, zoxy_log_path, .{}) catch return;
    defer file.close(io);
    var read_buffer: [4096]u8 = undefined;
    var file_reader = file.reader(io, &read_buffer);
    const read = file_reader.interface.readSliceShort(&buffer) catch return;
    assert(read <= buffer.len);
    if (read == 0) return;
    std.debug.print("-- {s} --\n{s}\n", .{ zoxy_log_path, buffer[0..read] });
}

fn parseFlags(args: []const [:0]const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--zoxy")) {
            index += 1;
            if (index == args.len) return error.InvalidArguments;
            flags.zoxy_path = args[index];
        } else {
            std.debug.print("usage: smoke [--zoxy path]\n", .{});
            return error.InvalidArguments;
        }
    }
    assert(flags.zoxy_path.len >= 1);
    return flags;
}
