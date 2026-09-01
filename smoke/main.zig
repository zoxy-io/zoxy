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
/// #311's leg runs a second proxy of its own, so it needs its own config
/// and its own output: the point of that leg is a process that *dies*,
/// and it must not be the one every other verdict here is reading.
const watchdog_config_path = work_directory ++ "/watchdog.json";
const watchdog_log_path = work_directory ++ "/watchdog.log";

/// The #159 bodies this run configures. `robots_body` goes through the
/// **file** arm — written here, read by the real binary at startup — so
/// this tier covers the one path the deterministic gates cannot: an
/// actual `open`/`read` of an operator's file. `not_found_body` rides
/// the inline arm beside it, and both are asserted byte-for-byte on the
/// wire (their lengths are the equality; the exact bytes are pinned by
/// the sim and the directed tests).
const robots_path = work_directory ++ "/robots.txt";
const robots_body = "User-agent: *\nDisallow: /private\n";

/// The #301 pre-flight's own files. `--check` writes its whole result to
/// stdout, so the gate captures stdout and stderr apart: the split is the
/// decision that issue made, and a gate that merged the two streams could
/// not see it.
const check_stdout_path = work_directory ++ "/check.out";
const check_log_path = work_directory ++ "/check.log";
const invalid_config_path = work_directory ++ "/invalid.json";

/// A config the *loader* refuses rather than the schema — a bind that is
/// well-shaped JSON and not an address (`ListenerBindInvalid`). Chosen
/// deliberately: the semantic checks are the ones only the real loader
/// makes, so refusing this is what says `--check` runs the loader instead
/// of a second, agreeable validator.
const invalid_config_text =
    \\{"listeners":[{"bind":"not-an-address","cluster":"a"}],
    \\"clusters":{"a":{"endpoints":["127.0.0.1:1"]}}}
;

/// What `--check` must exit with. Spelled here rather than imported from
/// `main.zig`'s `CheckExit`, on the rule the rest of this file follows:
/// the gate reads what the binary *did*, so a drift has to fail loudly
/// rather than agree with itself.
const check_exit_ok: u8 = 0;
const check_exit_invalid_config: u8 = 1;

/// The two lines that must reach stdout for the budget to have been
/// reported at all — the banner's own header, and the verdict line only a
/// check run writes.
const check_banner_needle = "budgets (DESIGN.md";
const check_verdict_needle = "  check   ";

/// The most of a check run's stdout the gate will read. A banner is about
/// 1 KiB; anything near this cap is itself the finding.
const check_output_bytes_max: usize = 16 * 1024;

/// The §4 fixture the terminating listener serves. Handed in by the build
/// rather than embedded here (`@embedFile` cannot escape a module root),
/// and written to the work directory so the proxy reads it off disk the
/// way a deployment's certificate arrives.
const tls_cert_path = work_directory ++ "/cert.pem";
const tls_key_path = work_directory ++ "/key.pem";
const tls_cert_pem = @embedFile("tls_cert_pem");
const tls_key_pem = @embedFile("tls_key_pem");
/// Requests the HTTPS leg issues on one terminated connection. More than
/// one on purpose: the second is a keep-alive turnaround, which is the
/// L7 state a directed test with a single `Connection: close` client
/// cannot reach and where a real defect already lived once.
const tls_requests: u32 = 3;
/// And the one connection they ride, named for the run-wide accept
/// equality: a leg that opened a second connection without saying so here
/// would be caught as an off-by-one rather than pass quietly.
const tls_connections: u32 = 1;
/// Tickets a completed handshake is expected to issue — `constants
/// .tls_tickets_per_handshake`, spelled here rather than imported like
/// the counter names: the gate reads what the binary *wrote*, so a drift
/// must fail loudly rather than agree with itself.
const tls_tickets_per_handshake: u64 = 2;
const not_found_body = "no such route";

/// The #140 fields as they must appear in a written line: the client's
/// header lowercased under `request_headers`, the origin's under
/// `response_headers`. Built from the same constants the two ends send,
/// so a rename cannot leave this gate agreeing with itself.
const logged_request_id = "\"request_headers\":{\"" ++
    lowerAscii(client_module.request_id_header) ++ "\":\"" ++
    client_module.request_id_value ++ "\"}";
const logged_origin_tag = "\"response_headers\":{\"" ++
    lowerAscii(origin_module.tag_header) ++ "\":\"" ++
    origin_module.tag_value ++ "\"}";

/// Lowercase a comptime header name — the spelling zoxy logs a named
/// header under, whatever the config wrote.
fn lowerAscii(comptime name: []const u8) *const [name.len]u8 {
    comptime {
        assert(name.len >= 1);
        var lowered: [name.len]u8 = undefined;
        for (name, &lowered) |byte, *slot| slot.* = std.ascii.toLower(byte);
        const frozen = lowered;
        return &frozen;
    }
}

/// The Host a request must carry to match the main route, and one that
/// deliberately does not — the run's only way to reach a `404`, since
/// every other request is routed by design.
const routed_host_suffix = "127.0.0.1";
const unrouted_host = "not-this-proxy.invalid";

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

/// The #159 leg: two exchanges on one connection — a request no route
/// matches, answered by the configured `404` page, and one the
/// `respond` action answers from the file-backed body. Like the sticky
/// leg it runs after the counter scrapes, so those scrapes keep
/// describing a run whose every request was routed.
const body_exchanges: u32 = 2;

/// The #331 leg: two exchanges on one connection, both under rules that
/// match the path they name — a request under the prefix an `allow` rule
/// admits this host's own address on, which must reach the origin, and
/// one under a prefix whose `allow` names a range this host is not in,
/// which must be refused by the reject beneath it. What a live gate adds
/// over the directed tests is that the *order* decides on the real
/// binary: an allow that stopped nothing answers 403 to the first
/// request, and a reject reached past a matched allow answers it to
/// both. Runs after the scrapes above like the two legs before it.
const allowlist_exchanges: u32 = 2;
/// The one of those the proxy answers itself. Named apart because the
/// log partition below counts what the *origin* served, and this line
/// carries a policy status no origin sent.
const allowlist_refused: u32 = 1;
/// The two prefixes that leg drives, each carrying an `allow` rule over
/// a `reject`. They differ only in the range the allow names: the first
/// is this host's own loopback /8, the second a documentation range no
/// client here can be in — so one request is admitted and the other is
/// refused by rules of identical shape, which is what makes the verdict
/// a property of the client match and not of the path.
const allowed_path = "/allowed";
const refused_path = "/refused";

const exchanges_per_pass: u32 =
    @as(u32, keep_alive_connections) * requests_per_connection + large_requests;
const http_exchanges: u32 = load_passes * exchanges_per_pass;
const access_log_lines_expected: u32 = http_exchanges + sticky_exchanges +
    body_exchanges + allowlist_exchanges + tls_requests + l4_connections;

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
const body_connections: u32 = 1;
const allowlist_connections: u32 = 1;
const readiness_probes: u32 = 1;
const connections_expected: u32 = keep_alive_connections +
    load_passes * large_requests + l4_connections + sticky_connections +
    body_connections + allowlist_connections + tls_connections + readiness_probes;

/// What the harness holds open against the origin at its peak: every live
/// client connection can have an upstream connection of its own, parked or
/// leased, plus the odd straggler mid-teardown — and one more for the
/// sticky cluster, whose pool parks its own upstream connection (§5
/// pools key by cluster, so the origin cluster's parked one is not
/// reused for it).
/// One more for the #331 leg, whose allowed request forwards: it reuses
/// a parked upstream connection whenever one is free, and a dial of its
/// own is the case this headroom covers.
const origin_connections_peak: u8 = keep_alive_connections + l4_connections + 2 + 1 + 1;

/// The drain's cap on waiting for the connections left open above. A
/// drain cannot tell an idle keep-alive connection from one about to send
/// a request, so it waits for both and reaps what is left at this
/// deadline (§8) — which is the whole of this run's shutdown cost, and
/// therefore the number to keep small. Short enough to stay a gate that
/// runs in a second; long enough that nothing here is racing it, since
/// the load is finished before SIGTERM is sent.
const drain_deadline_ms: u32 = 300;

/// #311's serving watchdog, armed for the whole run. The assertion it
/// carries is the *negative* one, and it is the only tier that can make
/// it: this gate spawns the real binary, so a watchdog that fired
/// spuriously would take the process down and every verdict after it
/// would fail — including the drain's own "exited 0". A simulator cannot
/// say that, because the thing being claimed is that nothing real
/// blocked the loop for this long.
///
/// Eight seconds, well above anything this run legitimately pauses for
/// and well under the harness's own wedge deadline. A tighter number
/// would be measuring the runner's scheduler rather than zoxy: the
/// positive leg (`loopWatchdogPassed`) takes the floor instead, on a
/// process it stops on purpose.
const loop_watchdog_ms: u32 = 8_000;

/// zoxy's pools, shrunk from the lean defaults (§5). Nothing here is a
/// scenario — the load is a handful of connections — so the smallest
/// config that serves it starts fastest and keeps the process's resident
/// set a number a human can read at a glance.
///
/// `tls_engines` is set rather than left to default, and it is the one
/// term here that is not merely thrift: an engine costs two orders of
/// magnitude more than a conn slot, so the default (one per slot) would
/// price 32 sessions for a leg that opens one, and the §5 banner this
/// gate prints would stop being a number a reader can sanity-check.
const zoxy_limits = .{
    .conn_slots = 32,
    .relay_buffers = 16,
    .upstream_slots = 16,
    .tls_engines = 2,
};

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
    // Same rule for the engine pool, which is its own admission rung
    // (§8): the https leg must be admitted rather than shed, or its
    // counter verdicts would be measuring the wall.
    assert(zoxy_limits.tls_engines >= tls_connections);
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
const watchdog_budget_ns: u64 = 30 * std.time.ns_per_s + loop_watchdog_stall_ns;

/// #311's leg, and the numbers it rests on.
///
/// The proxy under it is configured at the floor — the shortest bound the
/// mechanism can express — because this is the one place a *tight*
/// watchdog is safe: the process is stopped deliberately, so the stall is
/// not the runner's scheduler being slow, it is `SIGSTOP`.
const loop_watchdog_leg_ms: u32 = 2_000;

/// How long the leg holds the proxy stopped. The alarm is refreshed every
/// half-bound, so at the moment `SIGSTOP` lands it has somewhere between
/// half a bound and a whole one left to run — `alarm(2)` counts real time
/// and a stopped process does not stop the clock, so waiting a full bound
/// past the longest of those is certain, and the rest is margin for a
/// loaded runner's `SIGCONT` taking its time.
const loop_watchdog_stall_ns: u64 =
    (@as(u64, loop_watchdog_leg_ms) + 1_500) * std.time.ns_per_ms;

/// What zoxy exits with when its serving watchdog fires (#311, §8), and
/// what this leg is really asserting: 4 is a drain that could not finish,
/// 5 is a loop that stopped answering during one, 6 is a loop that
/// stopped answering while serving. Spelled out here rather than imported
/// because this harness links no zoxy at all (§9) — it runs the real
/// binary and reads what a supervisor would.
const loop_watchdog_exit_code: u8 = 6;

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

/// What the run is doing, for the watchdog to name if it fires.
///
/// A wedge reports from the *other* thread, so it cannot ask the wedged
/// one where it stopped — this is the only thing that can say. Worth its
/// weight the first time a gate wedges on a platform the author cannot
/// run: "exceeded its budget" says a run hung, which is what the exit
/// code already said; "wedged in: https handshake" says which of a dozen
/// waits it was, and on which side.
///
/// Ordered as the run performs them, so the *last* one reached is also a
/// statement about everything before it having finished.
const Stage = enum {
    starting,
    pre_flight,
    awaiting_listener,
    load,
    counter_scrape,
    sticky_leg,
    bodies_leg,
    allowlist_leg,
    https_handshake,
    https_request,
    https_close_notify,
    https_scrape,
    watchdog_leg,
    drain,
    verdicts,

    fn label(stage: Stage) []const u8 {
        return switch (stage) {
            .starting => "starting the proxy",
            .pre_flight => "the --check pre-flight (#301)",
            .awaiting_listener => "waiting for the listener",
            .load => "the http and l4 load",
            .counter_scrape => "the counter scrapes",
            .sticky_leg => "the sticky leg (#178)",
            .bodies_leg => "the bodies leg (#159)",
            .allowlist_leg => "the allowlist leg (#331)",
            .https_handshake => "the https handshake",
            .watchdog_leg => "the loop-watchdog leg (#311)",
            .https_request => "an https request",
            .https_close_notify => "the https close_notify",
            .https_scrape => "the https leg's scrape",
            .drain => "the drain",
            .verdicts => "reading back the verdicts",
        };
    }
};

var current_stage = std.atomic.Value(u8).init(@intFromEnum(Stage.starting));

/// Which https request is in flight, 1-based, for the stage that repeats.
/// The distinction it draws is the one worth having: the first request on
/// a session and the ones after it are different code (the turnaround),
/// and a wedge that cannot tell them apart leaves both suspect.
var current_https_request = std.atomic.Value(u32).init(0);

/// Publish what the run is about to wait on. Release-ordered against the
/// watchdog's acquire load: the label must be readable by the time the
/// wait it describes can hang.
fn enterStage(stage: Stage) void {
    current_stage.store(@intFromEnum(stage), .release);
}

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
    tls: u16,
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
    // Before the spawn, because that ordering is the claim: the config
    // `--check` just passed is the one this run then serves.
    enterStage(.pre_flight);
    const check_ok = try checkPassed(arena, io, flags.zoxy_path);
    var child = try spawnZoxy(io, flags.zoxy_path);
    var running = true;
    defer if (running) child.kill(io);

    enterStage(.awaiting_listener);
    try awaitListening(io, ports.http);
    enterStage(.load);
    const memory = try runLoad(arena, io, &ports, child.id);

    // Scraped before the drain: the admin listener closes with every
    // other one when SIGTERM lands (§8).
    enterStage(.counter_scrape);
    const counters = try countersPassed(arena, io, ports.admin, origin.port);
    // The #178 leg runs after the scrapes above on purpose — see
    // `sticky_exchanges` — and brings its own scrape.
    enterStage(.sticky_leg);
    const sticky_ok = try stickyPassed(arena, io, &ports);
    enterStage(.bodies_leg);
    const bodies_ok = try bodiesPassed(arena, io, &ports);
    // Last of the plaintext legs, so its scrape is the one that sees
    // every filter verdict this run produced.
    enterStage(.allowlist_leg);
    const allowlist_ok = try allowlistPassed(arena, io, &ports);
    // Last, so its scrape sees the whole run — and so a wedged handshake
    // cannot cost the legs above their verdicts.
    const tls_ok = try tlsPassed(arena, io, &ports);

    // Its own proxy, its own port, and it ends by killing it — so it runs
    // after every leg that needs the main child alive, and before the
    // drain that ends it.
    enterStage(.watchdog_leg);
    const watchdog_ok = try loopWatchdogPassed(arena, io, flags.zoxy_path);

    enterStage(.drain);
    const drained_cleanly = try drain(io, &child, &running);
    enterStage(.verdicts);
    const lines = try readAccessLog(arena, io);
    // Every check runs and prints; a run that fails two ways should say
    // both, not stop at the first.
    const log_ok = accessLogPassed(&lines);
    const memory_ok = memoryPassed(&memory);
    const drain_ok = drainPassed(drained_cleanly);
    const passed = log_ok and counters.passed and sticky_ok and bodies_ok and
        allowlist_ok and tls_ok and memory_ok and drain_ok and check_ok and
        watchdog_ok;
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
            "{d} probes in {d}ms, {s}, --check agrees, watchdog ended a stopped " ++
            "proxy, clean drain\n",
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
    const stage: Stage = @enumFromInt(current_stage.load(.acquire));
    const seconds = watchdog_budget_ns / std.time.ns_per_s;
    if (stage == .https_request) {
        std.debug.print(
            "FAIL: smoke run exceeded its {d}s budget — wedged in: {s} ({d} of {d})\n",
            .{ seconds, stage.label(), current_https_request.load(.acquire), tls_requests },
        );
    } else {
        std.debug.print(
            "FAIL: smoke run exceeded its {d}s budget — wedged in: {s}\n",
            .{ seconds, stage.label() },
        );
    }
    endWedgedProxy(io);
    printZoxyLog(io);
    std.process.exit(3);
}

/// How long the watchdog lets the proxy drain before killing it. Longer
/// than the drain deadline the run configures, so a proxy that is *able*
/// to drain has finished doing so by the time this expires.
const wedge_drain_grace_ns: u64 = 4 * @as(u64, drain_deadline_ms) * std.time.ns_per_ms;

/// End the proxy, asking before insisting.
///
/// SIGTERM first, because a drain makes the proxy dump its counters (§8)
/// — and on a wedge those counters are the best evidence there is: they
/// say how many connections it accepted, how many handshakes completed,
/// and which rung anything was shed on, which together separate "the
/// proxy never saw the request" from "it answered and the harness missed
/// it". A SIGKILL throws all of that away, which is what the first
/// macOS wedge did: the log ended at the startup banner and said nothing
/// about the run.
///
/// Then SIGKILL regardless, since the case being diagnosed is a proxy
/// that may not answer at all. Killing it is what keeps a timed-out run
/// from leaving an orphan on the ports the next run will ask for.
fn endWedgedProxy(io: Io) void {
    const pid = watchdog_child_pid.load(.acquire);
    if (pid == 0) return;
    std.posix.kill(pid, .TERM) catch {
        // Already gone: nothing to drain and nothing to kill.
        return;
    };
    io.sleep(Io.Duration.fromNanoseconds(wedge_drain_grace_ns), .awake) catch {};
    std.posix.kill(pid, .KILL) catch {};
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
    /// The lines no origin served: the #159 leg's page-wearing `404` and
    /// its `respond` answer, and the #331 leg's `403` from outside the
    /// allowed range. None is `ok`, so they are counted apart rather
    /// than weakening the ok-equality.
    http_rejected: u32 = 0,
    http_responded: u32 = 0,
    /// The #140 headers as the log actually spelled them.
    http_with_request_id: u32 = 0,
    http_with_origin_tag: u32 = 0,
};

/// The access-log verdict, printed so a red run explains itself without a
/// rerun. Every clause is an equality against a number this harness
/// decided before the run started.
fn accessLogPassed(lines: *const LogCounts) bool {
    // Both are counted off the same lines, in the same pass, so a total
    // below its own subset would mean the counter itself is wrong — which
    // no comparison below would otherwise notice.
    assert(lines.http_ok <= lines.http);
    // The https leg's requests land here with every other L7 one: a
    // terminated request is an ordinary request by the time it is logged,
    // and a log that told them apart would be the defect.
    const http_lines_expected = http_exchanges + sticky_exchanges +
        body_exchanges + allowlist_exchanges + tls_requests;
    assert(access_log_lines_expected == http_lines_expected + l4_connections);
    var passed = true;
    if (lines.http != http_lines_expected) {
        std.debug.print(
            "FAIL: {d} http access-log lines for {d} requests (#129 is exactly this)\n",
            .{ lines.http, http_lines_expected },
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
    // Every line but the #159 leg's two and the #331 leg's refusal
    // carries the origin's 200; those three carry outcomes only this
    // proxy produces, so the counts partition the http lines exactly.
    if (lines.http_ok + body_exchanges + allowlist_refused != lines.http) {
        std.debug.print(
            "FAIL: {d} of {d} http lines did not complete with the origin's 200\n",
            .{ lines.http - lines.http_ok, lines.http },
        );
        passed = false;
    }
    // Two refusals: the #159 leg's unroutable request, wearing the
    // configured page, and the #331 leg's request from outside the
    // allowed range. One `responded`, from the `respond` action.
    if (lines.http_rejected != 1 + allowlist_refused or lines.http_responded != 1) {
        std.debug.print(
            "FAIL: {d} rejected and {d} responded lines, not {d} and 1 (#159, #331)\n",
            .{ lines.http_rejected, lines.http_responded, 1 + allowlist_refused },
        );
        passed = false;
    }
    return loggedHeadersPassed(lines) and passed;
}

/// The #140 half of the log verdict, split out of `accessLogPassed` on
/// the same terms `loadShapePassed` was split from `identitiesPassed`:
/// the https leg's term pushed that one past the length limit, and these
/// two clauses are the pair that reads as its own claim — not "the log
/// holds the right lines" but "each line carries the headers the config
/// named".
fn loggedHeadersPassed(lines: *const LogCounts) bool {
    assert(lines.http_with_request_id <= lines.http);
    assert(lines.http_with_origin_tag <= lines.http);
    var passed = true;
    // Every http request this gate sends carries the correlation
    // header, so every http line must report it — including the two
    // the proxy answered itself, which is exactly when a join matters.
    if (lines.http_with_request_id != lines.http) {
        std.debug.print(
            "FAIL: {d} of {d} http lines carried the logged X-Request-ID (#140)\n",
            .{ lines.http_with_request_id, lines.http },
        );
        passed = false;
    }
    // The origin's tag rides only the lines whose exchange reached it —
    // never the page, the respond answer or the #331 leg's refusal,
    // which no origin served. Asserted rather than assumed: a near-empty
    // log would otherwise underflow this subtraction into a panic, where
    // the whole point of this function is to print a verdict.
    const origin_served = body_exchanges + allowlist_refused;
    assert(lines.http >= origin_served);
    if (lines.http_with_origin_tag != lines.http - origin_served) {
        std.debug.print(
            "FAIL: {d} of {d} origin-served lines carried the logged X-Origin-Tag (#140)\n",
            .{ lines.http_with_origin_tag, lines.http - origin_served },
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
    // Minus the four legs that deliberately run after this scrape (see
    // `sticky_exchanges`, `body_exchanges`, `allowlist_exchanges` and
    // `tls_requests`); the whole-run equality is asserted on the last of
    // their scrapes.
    const opened_so_far = connections_expected - sticky_connections -
        body_connections - allowlist_connections - tls_connections;
    if (accepted != opened_so_far) {
        std.debug.print(
            "FAIL: {d} connections accepted, not the {d} opened before this scrape\n",
            .{ accepted, opened_so_far },
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
    assert(ports.tls != 0);
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
    // The accept count with this leg in, but still short the connections
    // the #159 and TLS legs open after it — the whole-run equality lands
    // on the last scrape of the run.
    const opened_by_here = connections_expected - body_connections -
        allowlist_connections - tls_connections;
    const accepted = counterOf(&scrape, "accepted") orelse return false;
    if (accepted != opened_by_here) {
        std.debug.print(
            "FAIL: {d} connections accepted, not the {d} opened by here\n",
            .{ accepted, opened_by_here },
        );
        passed = false;
    }
    return passed;
}

/// The #159 leg against the live binary: a request no route matches,
/// answered by the configured `404` page, and one the `respond` action
/// answers from the file-backed body — both on one connection, both
/// judged on their exact framing, then the counters on a scrape. Runs
/// after `countersPassed` so those scrapes still describe a run whose
fn bodiesPassed(arena: std.mem.Allocator, io: Io, ports: *const Ports) !bool {
    assert(ports.http != 0);
    assert(ports.admin != 0);
    var host_buffer: [32]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buffer, "127.0.0.1:{d}", .{ports.http});
    try single_client.connect(io, ports.http);
    defer single_client.close();

    // No route for this Host, so the router's 404 — wearing the inline
    // page rather than the empty static it would have been.
    const not_found = try single_client.get(unrouted_host, "/", .keep_alive, null);
    var passed = expectBodyResponse(not_found, 404, not_found_body.len, "error page");
    if (!expectProxyDate(not_found, "error page")) passed = false;

    // The respond action, off the file arm: the body zoxy read at
    // startup, byte count and all, on a request that never reached an
    // origin.
    const robots = try single_client.get(host, "/robots.txt", .close, null);
    if (!expectBodyResponse(robots, 200, robots_body.len, "respond")) passed = false;
    if (!expectProxyDate(robots, "respond")) passed = false;

    const scrape = try scrape_module.parse(try scrape_module.fetch(arena, io, ports.admin));
    const responded = counterOf(&scrape, "l7_responded") orelse return false;
    if (responded != 1) {
        std.debug.print("FAIL: l7_responded reads {d}, not 1\n", .{responded});
        passed = false;
    }
    const no_route = counterOf(&scrape, "l7_no_route") orelse return false;
    if (no_route != 1) {
        std.debug.print("FAIL: l7_no_route reads {d}, not 1\n", .{no_route});
        passed = false;
    }
    // Short the #331 and TLS legs' connections, which open after this
    // scrape; the last of them carries the whole-run equality.
    const opened_by_here = connections_expected - allowlist_connections - tls_connections;
    const accepted = counterOf(&scrape, "accepted") orelse return false;
    if (accepted != opened_by_here) {
        std.debug.print(
            "FAIL: {d} connections accepted, not the {d} opened by here\n",
            .{ accepted, opened_by_here },
        );
        passed = false;
    }
    return passed;
}

/// The #331 leg against the live binary: the allowlist, both directions,
/// on one connection. `allowed_path` carries an `allow` rule naming the
/// loopback range this harness connects from, over a `reject`;
/// `refused_path` carries that same pair with a range no client here can
/// be in. So one request must reach the origin and the other must be
/// refused — and the build this issue was filed against, where an
/// "allow" rule was a header edit and stopped nothing, answers 403 to
/// both. That is the whole of what a live gate adds here: the two
/// verdicts come off the real binary's own walk over a real config.
///
/// Runs after the legs above and takes its own scrape, so `l7_filtered`
/// reads exactly the one refusal — a reject reached past a matched allow
/// would count two, which no assertion on the *responses* alone could
/// tell from a client that asked twice.
fn allowlistPassed(arena: std.mem.Allocator, io: Io, ports: *const Ports) !bool {
    assert(ports.http != 0);
    assert(ports.admin != 0);
    var host_buffer: [32]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buffer, "127.0.0.1:{d}", .{ports.http});
    try single_client.connect(io, ports.http);
    defer single_client.close();

    // Admitted: the allow stopped the walk before the reject beneath it,
    // so what follows is an ordinary proxied exchange — the origin's
    // body and the listener's #175 stamp, judged as the load's are.
    const allowed = try single_client.get(host, allowed_path, .keep_alive, null);
    try expectResponse(allowed, origin_module.body.len, .http);

    // Refused: the allow above this rule named a range this client is
    // not in, so it never matched and the reject decides.
    const refused = try single_client.get(host, refused_path, .close, null);
    var passed = expectRefusedResponse(refused);
    if (!expectProxyDate(refused, "allowlist reject")) passed = false;

    const scrape = try scrape_module.parse(try scrape_module.fetch(arena, io, ports.admin));
    const filtered = counterOf(&scrape, "l7_filtered") orelse return false;
    if (filtered != allowlist_refused) {
        std.debug.print(
            "FAIL: l7_filtered reads {d}, not the {d} request this run refused (#331)\n",
            .{ filtered, allowlist_refused },
        );
        passed = false;
    }
    return passed;
}

/// The #331 leg's refusal, judged on what a policy reject *is*: the
/// status the rule named, an empty body — no `error_pages` entry claims
/// `403` in this config — and no response-side stamp, because a static
/// never crosses the render the #175 rule lives in.
fn expectRefusedResponse(response: client_module.Response) bool {
    assert(response.status >= 100);
    var passed = true;
    if (response.status != 403) {
        std.debug.print(
            "FAIL: the allowlist refused a request with {d}, not 403\n",
            .{response.status},
        );
        passed = false;
    }
    if (response.body_bytes != 0) {
        std.debug.print(
            "FAIL: the allowlist reject carried {d} body bytes, not 0\n",
            .{response.body_bytes},
        );
        passed = false;
    }
    if (response.edited) {
        std.debug.print("FAIL: the allowlist reject carried the response-filter stamp\n", .{});
        passed = false;
    }
    return passed;
}

/// The #234 stamp on a response zoxy answered itself, against this
/// gate's own clock.
///
/// The simulator proves the slot is patched and well-formed, but its
/// clock is the same one the proxy reads, so it cannot prove the value
/// *means* anything. Here the two are genuinely separate — a real
/// `nowWallNs` on the far side of a socket — so agreement to the minute
/// is a real check: it catches a date stamped from the wrong clock, a
/// slot left at a stale second, and the epoch a never-stamped one would
/// carry.
fn expectProxyDate(response: client_module.Response, role: []const u8) bool {
    assert(role.len >= 1);
    if (!response.from_proxy) {
        std.debug.print("FAIL: the {s} response named no Server\n", .{role});
        return false;
    }
    const date = response.date orelse {
        std.debug.print("FAIL: the {s} response carried no Date\n", .{role});
        return false;
    };
    var wall: std.posix.timespec = undefined;
    // Through `posix.system` so the return convention matches the
    // `posix.errno` that reads it — the #184 lesson, which cost a macOS
    // live-gate panic the one time the two were mixed.
    const rc = std.posix.system.clock_gettime(std.posix.CLOCK.REALTIME, &wall);
    if (std.posix.errno(rc) != .SUCCESS) {
        std.debug.print("FAIL: this gate could not read its own clock\n", .{});
        return false;
    }
    assert(wall.sec >= 0);
    const now: u64 = @intCast(wall.sec);
    // A minute either side. The two clocks are the same system clock, so
    // this bounds the seconds between the stamp and this comparison, not
    // any drift — and the loop is bounded by that window, not by a match.
    var offset: u64 = 0;
    while (offset <= 120) : (offset += 1) {
        var buffer: [64]u8 = undefined;
        const rendered = imfFixdate((now -| 60) + offset, &buffer) orelse {
            std.debug.print("FAIL: this gate could not render a date to compare\n", .{});
            return false;
        };
        if (std.mem.eql(u8, rendered, &date)) return true;
    }
    std.debug.print(
        "FAIL: the {s} response is dated {s}, which is not within a minute of now\n",
        .{ role, date },
    );
    return false;
}

/// This gate's own IMF-fixdate (RFC 9110 §5.6.7), assembled here rather
/// than imported for the reason every other spelling in this file is:
/// the gate must read what the binary wrote, and a formatter shared with
/// it would agree with a wrong weekday, an off-by-one month or a missing
/// zero-pad as readily as with a right one. Null only if the format
/// outgrew the buffer, which four-digit years cannot.
fn imfFixdate(second: u64, buffer: []u8) ?[]const u8 {
    const weekdays = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const months = [_][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = second };
    const epoch_day = epoch.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    return std.fmt.bufPrint(
        buffer,
        "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT",
        .{
            weekdays[(epoch_day.day + 4) % 7],
            @as(u32, month_day.day_index) + 1,
            months[month_day.month.numeric() - 1],
            year_day.year,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        },
    ) catch null;
}

/// One #159 response: the status the config asked for, and a body of
/// exactly the configured length. The length is the equality this tier
/// can hold — that the *bytes* are the operator's is pinned by the
/// simulator's oracle and the directed tests — and it is enough to
/// catch a page served empty, truncated, or from the wrong body.
fn expectBodyResponse(
    response: client_module.Response,
    status: u16,
    body_bytes: usize,
    role: []const u8,
) bool {
    assert(role.len >= 1);
    assert(body_bytes >= 1);
    if (response.status != status) {
        std.debug.print(
            "FAIL: the {s} exchange answered {d}, not {d}\n",
            .{ role, response.status, status },
        );
        return false;
    }
    if (response.body_bytes != body_bytes) {
        std.debug.print(
            "FAIL: the {s} body was {d} bytes, not the configured {d}\n",
            .{ role, response.body_bytes, body_bytes },
        );
        return false;
    }
    // A configured page is a static: it never crosses the response
    // render, so the listener's #175 stamp must not be on it — the same
    // boundary the simulator's oracle holds from outside.
    if (response.edited) {
        std.debug.print("FAIL: the {s} response carried the response-filter stamp\n", .{role});
        return false;
    }
    return true;
}

/// The #125 leg: a real TLS 1.3 handshake against the terminating
/// listener, `tls_requests` exchanges over the session it opens, and a
/// `close_notify` to end it — then the counters on the run's last scrape.
///
/// The client is `std.crypto.tls`, an implementation that shares no code
/// with the one zoxy terminates on. That is the whole point of running
/// this here: ztls agreeing with ztls proves interoperability with
/// nobody, and the two things this tier can prove that no directed test
/// can are that an outside implementation completes the handshake, and
/// that the session survives a keep-alive turnaround — the L7 state where
/// a defect already lived once during this work.
///
/// Runs last, after both late legs, so it carries the whole-run accept
/// equality.
fn tlsPassed(arena: std.mem.Allocator, io: Io, ports: *const Ports) !bool {
    assert(ports.tls != 0);
    assert(ports.admin != 0);
    var host_buffer: [32]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buffer, "127.0.0.1:{d}", .{ports.tls});
    enterStage(.https_handshake);
    try single_client.connectTls(io, ports.tls);
    defer single_client.close();

    var passed = true;
    var request: u32 = 0;
    enterStage(.https_request);
    while (request < tls_requests) : (request += 1) {
        current_https_request.store(request + 1, .release);
        // Keep-alive throughout: the turnaround is what is being tested,
        // and it is also what leaves the connection for `close_notify`
        // to end rather than a response the proxy closed on.
        const response = try single_client.get(host, "/", .keep_alive, null);
        if (!expectTlsResponse(response, request)) passed = false;
    }
    assert(request == tls_requests);
    enterStage(.https_close_notify);
    try single_client.endTls();

    enterStage(.https_scrape);
    const scrape = try scrape_module.parse(try scrape_module.fetch(arena, io, ports.admin));
    const verdicts = [_]struct { name: []const u8, expected: u64 }{
        // One session, completed: the handshake ran once and finished.
        .{ .name = "tls_handshakes_completed", .expected = 1 },
        // And nothing on the failure side. Stated as equalities against
        // zero rather than left unread, because every one of these is a
        // rung a working run must never reach — a session that failed and
        // silently retried would otherwise pass on the count above.
        .{ .name = "tls_handshake_failed", .expected = 0 },
        // The post-handshake flight, witnessed on the shipped binary
        // rather than only in a simulator: it is what carries the ACK
        // that keeps a client's first request out of its own Nagle queue,
        // so a deployment issuing none has the ~45 ms stall back.
        .{ .name = "tls_tickets_issued", .expected = tls_tickets_per_handshake },
        // And nothing resumed: this client is offered tickets and never
        // returns one, so a count here would mean the counter fires on
        // something other than resumption.
        .{ .name = "tls_resumed", .expected = 0 },
        .{ .name = "tls_relay_failed", .expected = 0 },
        .{ .name = "shed_tls_engines", .expected = 0 },
        .{ .name = "shed_tls_crypto", .expected = 0 },
    };
    for (verdicts) |verdict| {
        const value = counterOf(&scrape, verdict.name) orelse {
            passed = false;
            continue;
        };
        if (value != verdict.expected) {
            std.debug.print(
                "FAIL: {s} reads {d}, not {d}, after the https leg\n",
                .{ verdict.name, value, verdict.expected },
            );
            passed = false;
        }
    }
    // The whole-run accept equality, deferred through all three late
    // legs: this is the last scrape, so every connection the run opened
    // is accounted for here or nowhere.
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

/// One response off the terminated listener. The same framing the
/// plaintext legs demand — a decrypted head that reframed the body would
/// fail here exactly as a cleartext one does — plus the absence of the
/// #175 stamp, which is this leg's witness that it reached the *third*
/// listener: the stamp is configured on the plaintext one only, so a
/// response carrying it came from the wrong port.
fn expectTlsResponse(response: client_module.Response, request: u32) bool {
    // The reader's own bounds, restated before the comparisons switch on
    // them: a status or a length outside these did not come off a parse
    // that succeeded, so comparing it would report the wrong failure.
    assert(response.status >= 100);
    assert(response.body_bytes <= client_module.response_body_bytes_max);
    assert(request < tls_requests);
    if (response.status != 200) {
        std.debug.print(
            "FAIL: https request {d} answered {d}, not 200\n",
            .{ request, response.status },
        );
        return false;
    }
    if (response.body_bytes != origin_module.body.len) {
        std.debug.print(
            "FAIL: https request {d} carried {d} body bytes, not the origin's {d}\n",
            .{ request, response.body_bytes, origin_module.body.len },
        );
        return false;
    }
    if (response.edited) {
        std.debug.print(
            "FAIL: https request {d} carried the plaintext listener's stamp\n",
            .{request},
        );
        return false;
    }
    return true;
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
            // The #159 leg's two lines, told apart by the outcomes only
            // it produces: a page the router's 404 wore, and a body the
            // proxy answered with itself. Counting them here is what
            // lets the ok-equality below stay an equality.
            if (std.mem.indexOf(u8, line, "\"outcome\":\"rejected\"") != null) {
                counts.http_rejected += 1;
            }
            if (std.mem.indexOf(u8, line, "\"outcome\":\"responded\"") != null) {
                counts.http_responded += 1;
            }
            // The #140 join, on the real wire: every http line must
            // carry the client's correlation header, and every line
            // whose exchange reached the origin must carry the origin's
            // tag. Spelled out rather than counted loosely — a value
            // that truncated or came from another request is the one
            // failure a correlation field must never have.
            if (std.mem.indexOf(u8, line, logged_request_id) != null) {
                counts.http_with_request_id += 1;
            }
            if (std.mem.indexOf(u8, line, logged_origin_tag) != null) {
                counts.http_with_origin_tag += 1;
            }
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

/// #311's positive leg: stop the loop for real, and watch the kernel
/// finish the sentence.
///
/// This is the only tier that can make this claim. The simulator models
/// the alarm as a deadline its run loop compares a virtual clock against,
/// which proves the *wiring* — a stranded timer plane still reaches the
/// give-up — but a virtual clock cannot be blocked, so what it cannot
/// show is a real process, in a real kernel, that has stopped executing.
/// `SIGSTOP` is exactly that: the process is off the CPU entirely, no
/// completion is delivered, no timer runs, and `alarm(2)` keeps counting
/// because it is the kernel's clock and not the loop's. On `SIGCONT` the
/// pending SIGALRM is delivered before anything else the process was
/// going to do, so the handler wins the race against the refresh by
/// construction rather than by timing.
///
/// A separate proxy with its own config, port and log, because the
/// assertion is that it *dies* — running this against the main child
/// would take every verdict after it.
fn loopWatchdogPassed(arena: std.mem.Allocator, io: Io, zoxy_path: []const u8) !bool {
    const port = try reserveWatchdogPort(io);
    try writeWatchdogConfig(arena, io, port, origin.port);
    var child = try spawnWatchdogZoxy(io, zoxy_path);
    var running = true;
    // Every early return below leaves a stopped or dying process behind,
    // and an orphan holding a port is what the next run trips over.
    defer if (running) child.kill(io);
    assert(child.id != null);
    try awaitListening(io, port);

    try std.posix.kill(child.id.?, .STOP);
    // `try`, where the rest of this harness shrugs a sleep off as pacing:
    // here the sleep *is* the argument. A short one would `SIGCONT` the
    // proxy before the alarm was certain to have expired, and the leg
    // would then report a watchdog that did not fire as a failure of the
    // watchdog rather than of its own timing.
    try io.sleep(Io.Duration.fromNanoseconds(loop_watchdog_stall_ns), .awake);
    try std.posix.kill(child.id.?, .CONT);
    const term = try child.wait(io);
    running = false;

    if (term != .exited or term.exited != loop_watchdog_exit_code) {
        std.debug.print(
            "FAIL: the loop watchdog (#311) did not end the stopped proxy: {any}\n",
            .{term},
        );
        return false;
    }
    // The exit code is what a supervisor reads; the line is what an
    // operator reads. A watchdog that took the process down without
    // saying which silence it was reporting would be the hang it
    // replaced, one layer down.
    const said_so = try watchdogLogMentions(arena, io, "#311");
    if (!said_so) {
        std.debug.print(
            "FAIL: the loop watchdog exited {d} without naming itself on stderr\n",
            .{loop_watchdog_exit_code},
        );
    }
    return said_so;
}

/// Whether the stopped proxy's own output carries `needle`. Read whole:
/// this log is a banner and at most one watchdog line.
fn watchdogLogMentions(arena: std.mem.Allocator, io: Io, needle: []const u8) !bool {
    const bytes_max: usize = 64 * 1024;
    const text = Io.Dir.cwd().readFileAlloc(
        io,
        watchdog_log_path,
        arena,
        .limited(bytes_max),
    ) catch return false;
    return std.mem.indexOf(u8, text, needle) != null;
}

/// One more kernel-assigned port, on `reservePorts`' terms and for its
/// reason — this leg binds a listener of its own while the main proxy
/// still holds all four of that one's.
fn reserveWatchdogPort(io: Io) !u16 {
    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try address.listen(io, .{ .mode = .stream });
    const port = listener.socket.address.getPort();
    listener.deinit(io);
    assert(port != 0);
    return port;
}

/// The smallest config that serves: one http listener, one cluster, and
/// the watchdog this leg is about. Deliberately not the main template —
/// nothing here needs TLS, an access log, health checks or filters, and a
/// config that carried them would put failure modes into a leg whose one
/// job is to be stopped.
fn writeWatchdogConfig(
    arena: std.mem.Allocator,
    io: Io,
    port: u16,
    origin_port: u16,
) !void {
    assert(port != 0);
    assert(origin_port != 0);
    const config_json = try std.fmt.allocPrint(arena, watchdog_config_template, .{
        port,
        origin_port,
        loop_watchdog_leg_ms,
    });
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = watchdog_config_path,
        .data = config_json,
    });
}

const watchdog_config_template =
    \\{{
    \\    "listeners": [
    \\        {{ "bind": "127.0.0.1:{d}", "http": {{
    \\          "routes": [{{ "prefix": "/", "cluster": "origin" }}] }} }}
    \\    ],
    \\    "clusters": {{ "origin": {{ "endpoints": ["127.0.0.1:{d}"] }} }},
    \\    "timeouts": {{ "loop_watchdog_ms": {d} }}
    \\}}
;

/// `spawnZoxy` for the leg's own child: its own log, so the main proxy's
/// output stays the thing `printZoxyLog` shows a failing run.
fn spawnWatchdogZoxy(io: Io, zoxy_path: []const u8) !std.process.Child {
    assert(zoxy_path.len >= 1);
    const log_file = try Io.Dir.cwd().createFile(io, watchdog_log_path, .{});
    defer log_file.close(io);
    return std.process.spawn(io, .{
        .argv = &.{ zoxy_path, watchdog_config_path },
        .stdout = .{ .file = log_file },
        .stderr = .{ .file = log_file },
    });
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
    var tls_address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var tls_listener = try tls_address.listen(io, .{ .mode = .stream });
    var admin_address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var admin_listener = try admin_address.listen(io, .{ .mode = .stream });
    const ports: Ports = .{
        .http = http_listener.socket.address.getPort(),
        .l4 = l4_listener.socket.address.getPort(),
        .tls = tls_listener.socket.address.getPort(),
        .admin = admin_listener.socket.address.getPort(),
    };
    http_listener.deinit(io);
    l4_listener.deinit(io);
    tls_listener.deinit(io);
    admin_listener.deinit(io);
    assert(ports.http != 0);
    assert(ports.l4 != 0);
    assert(ports.tls != 0);
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
    assert(ports.http != 0);
    const config_json = try std.fmt.allocPrint(arena, config_template, .{
        ports.http,
        allowed_path,
        allowed_path,
        refused_path,
        refused_path,
        ports.l4,
        ports.tls,
        tls_cert_path,
        tls_key_path,
        origin_port,
        health_probe_timeout_ms,
        origin_port,
        not_found_body,
        robots_path,
        ports.admin,
        access_log_path,
        health_interval_ms,
        drain_deadline_ms,
        loop_watchdog_ms,
        zoxy_limits.conn_slots,
        zoxy_limits.relay_buffers,
        zoxy_limits.upstream_slots,
        zoxy_limits.tls_engines,
    });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = config_json });
}

/// The config `writeConfig` fills in. A module-level constant rather than
/// a literal inside it: the template is most of the function's length,
/// and it is not logic — separating them keeps the function a readable
/// list of what each hole is, and keeps that list under the length limit
/// as listeners are added.
const config_template =
    \\{{
    \\    "listeners": [
    \\        {{ "bind": "127.0.0.1:{d}", "http": {{
    \\          "routes": [
    \\              {{ "host": "127.0.0.1", "prefix": "/", "cluster": "origin" }},
    \\              {{ "host": "127.0.0.1", "prefix": "/sticky", "cluster": "sticky" }}
    \\          ],
    \\          "request_filters": [
    \\              {{ "match": {{ "path_prefix": "/robots.txt" }},
    \\                "actions": [{{ "respond": {{ "status": 200, "body": "robots" }} }}] }},
    \\              {{ "match": {{ "path_prefix": "{s}", "client": ["127.0.0.0/8"] }},
    \\                "actions": [{{ "allow": true }}] }},
    \\              {{ "match": {{ "path_prefix": "{s}" }}, "actions": [{{ "reject": 403 }}] }},
    \\              {{ "match": {{ "path_prefix": "{s}", "client": ["203.0.113.0/24"] }},
    \\                "actions": [{{ "allow": true }}] }},
    \\              {{ "match": {{ "path_prefix": "{s}" }}, "actions": [{{ "reject": 403 }}] }}
    \\          ],
    \\          "response_filters": [
    \\              {{ "actions": [{{ "header_set": {{ "name": "X-Zoxy-Smoke", "value": "1" }} }}] }}
    \\          ] }} }},
    \\        {{ "bind": "127.0.0.1:{d}", "l4": {{ "cluster": "origin" }} }},
    \\        {{ "bind": "127.0.0.1:{d}",
    \\          "http": {{ "routes": [{{ "host": "127.0.0.1", "prefix": "/", "cluster": "origin" }}] }},
    \\          "tls": {{ "cert": "{s}", "key": "{s}" }} }}
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
    \\    "bodies": {{
    \\        "gone": {{ "inline": "{s}", "content_type": "text/plain" }},
    \\        "robots": {{ "file": "{s}", "content_type": "text/plain" }}
    \\    }},
    \\    "error_pages": {{ "404": "gone" }},
    \\    "admin": {{ "bind": "127.0.0.1:{d}" }},
    \\    "access_log": {{ "sink": "file", "path": "{s}",
    \\        "request_headers": ["X-Request-ID"], "response_headers": ["X-Origin-Tag"] }},
    \\    "timeouts": {{
    \\        "connect_ms": 2000,
    \\        "idle_ms": 30000,
    \\        "health_interval_ms": {d},
    \\        "drain_deadline_ms": {d},
    \\        "loop_watchdog_ms": {d}
    \\    }},
    \\    "limits": {{
    \\        "conn_slots": {d},
    \\        "relay_buffers": {d},
    \\        "upstream_slots": {d},
    \\        "tls_engines": {d}
    \\    }}
    \\}}
    \\
;

/// A fresh work directory every run: the file sink is append-only by
/// design (§8, so an external rotation is safe), which makes a stale log
/// from the last run indistinguishable from this one's output.
fn prepareWorkDirectory(io: Io) !void {
    try Io.Dir.cwd().createDirPath(io, work_directory);
    Io.Dir.cwd().deleteFile(io, access_log_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    // The #159 file arm's input, written before zoxy starts because it
    // is read once at startup (parse-once, §1) — the one thing in this
    // config that comes off the filesystem rather than out of the JSON.
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = robots_path, .data = robots_body });
    // The TLS fixture, written where the config points and read by the
    // proxy at startup like any operator's certificate (§4). Throwaway
    // and self-signed — `src/tls/testdata/README.md` says why the key is
    // committed — so the gate's subject is the record layer, not a trust
    // decision.
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tls_cert_path, .data = tls_cert_pem });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tls_key_path, .data = tls_key_pem });
    // The #301 pre-flight's negative case, written beside the real one so
    // both reach the same binary through the same argument.
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = invalid_config_path,
        .data = invalid_config_text,
    });
}

/// One `--check` run's verdict: the code it exited with, and whether the
/// budget reached **stdout**. The placement is the decision #301 made —
/// a check run's whole output is its result, unlike the startup banner,
/// which is diagnostics beside a process that goes on to serve — so the
/// gate pins it rather than trusting it.
const CheckRun = struct {
    exit_code: u8,
    budget_on_stdout: bool,
};

/// The #301 pre-flight, over the very config this run is about to serve
/// and over one no loader will take.
///
/// That first pairing is the whole claim `--check` makes: it says a
/// config would start here, and the only place that can be *checked* is
/// where the real binary then starts on the same file. The second pins
/// the other half — that the mode refuses what the loader refuses, with
/// the exit code a CI job branches on rather than a bare non-zero.
fn checkPassed(arena: std.mem.Allocator, io: Io, zoxy_path: []const u8) !bool {
    assert(zoxy_path.len >= 1);
    const accepted = try runZoxyCheck(arena, io, zoxy_path, config_path);
    const refused = try runZoxyCheck(arena, io, zoxy_path, invalid_config_path);
    var passed = true;
    if (accepted.exit_code != check_exit_ok) {
        std.debug.print(
            "FAIL: --check refused the config this run then served (exit {d})\n",
            .{accepted.exit_code},
        );
        passed = false;
    }
    if (!accepted.budget_on_stdout) {
        std.debug.print("FAIL: --check wrote no budget to stdout\n", .{});
        passed = false;
    }
    if (refused.exit_code != check_exit_invalid_config) {
        std.debug.print(
            "FAIL: --check did not refuse a config the loader refuses (exit {d})\n",
            .{refused.exit_code},
        );
        passed = false;
    }
    // Nothing was loaded, so there is nothing to price: a budget printed
    // beside a refusal would be a number for a config that does not
    // exist.
    if (refused.budget_on_stdout) {
        std.debug.print("FAIL: --check priced a config it refused\n", .{});
        passed = false;
    }
    return passed;
}

/// One `zoxy --check <config>`, with the two streams captured apart.
fn runZoxyCheck(
    arena: std.mem.Allocator,
    io: Io,
    zoxy_path: []const u8,
    config: []const u8,
) !CheckRun {
    assert(zoxy_path.len >= 1);
    assert(config.len >= 1);
    const out_file = try Io.Dir.cwd().createFile(io, check_stdout_path, .{});
    defer out_file.close(io);
    const log_file = try Io.Dir.cwd().createFile(io, check_log_path, .{});
    defer log_file.close(io);
    var child = try std.process.spawn(io, .{
        .argv = &.{ zoxy_path, "--check", config },
        .stdout = .{ .file = out_file },
        .stderr = .{ .file = log_file },
    });
    const term = try child.wait(io);
    const text = try Io.Dir.cwd().readFileAlloc(
        io,
        check_stdout_path,
        arena,
        .limited(check_output_bytes_max),
    );
    assert(text.len <= check_output_bytes_max);
    return .{
        // A check that died of a signal has no code to report, and the
        // sentinel is outside every code `CheckExit` defines, so it can
        // only ever read as a failure.
        .exit_code = if (term == .exited) term.exited else 255,
        .budget_on_stdout = std.mem.indexOf(u8, text, check_banner_needle) != null and
            std.mem.indexOf(u8, text, check_verdict_needle) != null,
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
