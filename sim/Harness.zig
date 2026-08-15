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
const TlsClient = zoxy.tls.TestClient(SimIo);

const assert = std.debug.assert;

const Harness = @This();

const clients_max: u8 = 6;
/// The §4 terminating population one seed may draw (#125). Small on
/// purpose: a real ECDSA handshake is ~260 µs of libcrypto on each side,
/// so a sweep that gave every client a session would cost minutes rather
/// than the seconds this gate is run at. Two is enough to reach the
/// engine-pool wall on a starved seed, which is the one rung that needs
/// more than one.
const tls_clients_max: u8 = 2;
/// One more slot than a seed may draw, for the resuming client (#204).
/// Exactly one: what it covers is a ticket surviving from one connection
/// to the next, and a second resumer would only re-cover it while
/// doubling the handshake crypto every TLS seed pays for.
const tls_client_slots: u8 = tls_clients_max + 1;
/// Bytes each terminating client echoes. Small: what this population is
/// for is the handshake and the transform, not throughput.
const tls_token_bytes: u8 = 24;
/// The two requests a terminating *http* listener's client sends, in
/// order. Both are the L7 scripts' own bytes, so the origin answers them
/// exactly as it answers a plaintext client's and the difference under
/// test is the transform rather than the request.
///
/// The first is a keep-alive POST: a body, which a GET has none of, and
/// no `Connection: close`, so the exchange leaves the connection open.
/// The second closes it, which is how the client ends without waiting on
/// an idle timeout. Between them is the keep-alive turnaround — the L7
/// state re-entered on a terminated connection, which is where the head
/// source's first defect lived (#204).
const tls_http_followup = l7.scripts.get_request_close;
/// "203.0.113.255:65535" is 19 bytes; the slack is headroom, not hope.
const announced_bytes_max: u8 = 32;
/// Virtual time from scenario start after which stuck work is force-ended.
const scenario_end_ns: u64 = 2_000_000_000;
/// How far a #202 seed steps the wall clock: one whole rotation interval
/// plus a second, so the key is unambiguously overdue rather than
/// balanced on the boundary the directed tests already pin.
const clock_jump_ns: u64 =
    (@as(u64, zoxy.constants.tls_ticket_key_rotation_s) + 1) * std.time.ns_per_s;
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

/// Where a stranding seed places its drop (#206). Two hooks, because the
/// two halves of the class need different instants: `wind_down` takes ops
/// already armed when the drain begins, `teardown` waits for the first
/// cancel submitted once it is under way. Neither is a superset of the
/// other — see `maybeStrandOps` and `armTeardownStrand`.
const DropMode = enum { wind_down, teardown };

/// What the teardown latch waits for. `beginTeardown` arms exactly these
/// two — a pending dial's `connect_cancel` and a live deadline's
/// `timer_cancel` — and it arms them *after* a wind-down drop has already
/// landed, which is what puts them out of that hook's reach.
const teardown_strand_kinds = [_]SimIo.OpKind{ .timer_cancel, .connect_cancel };

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
/// The http cluster's endpoints: the origin at index 0 always, and on a
/// #181 retry seed a second one nothing is listening on (`deriveRetries`).
/// How many are configured is `endpoints_http_count`.
endpoints_http: [2]std.Io.net.IpAddress,
endpoints_http_count: u16,
/// The #174 weight tables the clusters may reference, each as long as
/// the endpoint list it parallels.
weights_l4: [1]u16,
weights_http: [2]u16,
clusters: [2]zoxy.config.Config.Cluster,
routes_l4: [1]zoxy.http.router.Route,
routes_http: [1]zoxy.http.router.Route,
request_filters_http: [5]zoxy.http.filter.Rule,
/// The #175 response rules beside them: the always-on stamp the client
/// oracle requires on every proxied 200, and the 5xx rule whose edit
/// must never appear (the scripted origin answers no 5xx).
response_filters_http: [2]zoxy.http.filter.ResponseRule,
routes_tls: [1]zoxy.http.router.Route,
listener_configs: [3]zoxy.config.Config.Listener,
/// How many of `listener_configs` this seed actually binds: two on a
/// plaintext seed, three when it drew TLS clients (§4).
listeners_count: u8,
config: zoxy.config.Config,
origin: Origin,
origin_http: HttpOrigin,
clients: [clients_max]EchoClient,
l7_clients: [clients_max]HttpClient,
/// The §4 terminating population (#125) and its credentials. Held on the
/// harness because the server borrows the table for its life, and because
/// a `Credentials` owns a libcrypto key that `tearDown` must free — the
/// arena cannot, it is not arena memory.
tls_clients_storage: [tls_client_slots]TlsClient,
/// How many terminating clients the seed drew — what sizes the engine
/// pool — against how many storage slots are in use, which the #204
/// resuming client makes one larger the moment it starts.
tls_clients: u8,
tls_clients_live: u8,
/// Whether the resuming client has started, and the key material it
/// starts with. Drawn up front from the scenario stream rather than when
/// it starts: the draw then sits at a fixed point in that stream instead
/// of one the delivery order chooses.
tls_resume_started: bool,
tls_resume_seeds: [3][32]u8,
/// Set when the wind-down begins, so nothing dials a listener that has
/// stopped accepting.
scenario_ended: bool,
/// What the terminating listener speaks once the handshake hands over.
tls_protocol: zoxy.config.Config.Listener.Protocol,
/// What each terminating client sends, distinct per client so the echo
/// oracle can tell one session's bytes from another's. Read only by the
/// l4 draw; an http terminator sends its script's request instead.
tls_tokens: [tls_client_slots][tls_token_bytes]u8,
/// The script each terminating client sends over an http terminator
/// (#215), one per storage slot including the resuming client's. Drawn
/// rather than fixed so the filter, redirect, static, rejection and
/// sticky paths ride the transform too — the population used to send one
/// POST-then-GET pair, which exercised the response render's happy path
/// and nothing else.
tls_scripts: [tls_client_slots]l7.Script,
tls_credentials: [3]?zoxy.tls.Credentials,
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
/// The seed drew the #178 cookie-keyed http cluster: the pick is
/// forced to `hash` on `canon.sticky_cookie_name`, every L7 client
/// runs the stamp oracle, and `verify` holds the sticky counters to
/// the responses they annotate.
sticky_http: bool,
/// The #181 dial-retry budget on the http cluster; zero on the seeds
/// that carry no second endpoint, which is most of them.
retries_http: u16,
/// The seed allows the #180 upgrade token on its http listener, and has
/// a tunnel pool to carry it. Off on most seeds, so the handshake script
/// keeps proving the `501` every config had before the feature.
upgrades_http: bool,
/// The seed's http origin prefixes an interim `100 Continue` to every
/// answer (#232). Drawn once per seed rather than per accept, so a clean
/// seed's transcript stays exact — which is the point: the golden oracle
/// is what has teeth over the interim path, and it only runs on clean
/// seeds.
interim_http: bool,
tunnels: u32,
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
/// Whether this seed steps the wall clock past a sealing key's rotation
/// interval (#202), and whether it has. Drawn only on seeds that
/// terminate TLS: a plaintext seed seals no ticket, so a jump there would
/// move nothing while shifting the whole sweep's stream position.
clock_jump_wanted: bool,
clock_jumped: bool,
/// Where this seed strands an op, or null for the seeds that strand none
/// (#206) — and, once one has been taken at the wind-down, which kind it
/// was. Separate fields for the reason the pair above is two: what a seed
/// drew and what it did are different facts, and `verify` needs the
/// second to decide whether a stuck drain was asked for. The kind is
/// never part of the draw; both modes take what the schedule armed rather
/// than what a die named (`drawStrandKind`, `armDropNext`).
drop_mode: ?DropMode,
drop_kind: ?SimIo.OpKind,
/// Whether the teardown mode's latch has been armed, so the second
/// wind-down a scenario can have does not arm it twice.
drop_latch_armed: bool,
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

/// The §4 terminating listener (#125). Its own socket rather than TLS on
/// one of the two above, so a seed that draws it changes what reaches
/// *this* port and nothing about the plaintext coverage beside it.
fn tlsBindAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8443") catch unreachable;
}

fn originAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
}

fn httpOriginAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9001") catch unreachable;
}

/// The #181 second endpoint: an address no origin ever binds, so every
/// dial to it is refused by `SimIo.finishConnect`'s own listener lookup
/// rather than by an adversary roll. That is the issue's motivating
/// failure modelled exactly — one endpoint of a cluster refusing while
/// the others are healthy — and it is refused on *clean* seeds too, so
/// the retry path is reached by the seeds whose oracles demand exact
/// outcomes rather than only by the ones that tolerate a cut.
///
/// Dead rather than merely slow on purpose: a black-holed endpoint would
/// time out, and a timed-out dial does not retry (it has spent the
/// budget a retry carries). Dead rather than a second live origin also
/// keeps every oracle untouched — nothing here can serve, so every
/// response the clients check still came from the one origin at index 0,
/// including the #178 sticky tag pinned to its address.
fn refusingEndpointAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9002") catch unreachable;
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
        // #206: a stranded seed reaches the §8 give-up on purpose, and
        // the operator forensics it prints there are two hundred lines
        // apiece. The sweep's verdict is `abortedWith`, not the wording,
        // and a gate whose output scrolls is a gate nobody reads.
        .dump_on_abort = false,
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

    harness.armScenarioTimers();
}

/// The three timers a scenario runs on: the force-end that outlives any
/// stuck work, the optional early drain, and the optional origin outage.
/// Split from `setUp` when the #206 drop pushed that one past the length
/// limit — the same remedy `deriveTopology` took twice before it.
///
/// Every one is armed *after* the population exists, so nothing can fire
/// against a half-built scenario, and every optional one asserts it lands
/// before the force-end — a timer scheduled past that is a timer whose
/// scenario is already over.
fn armScenarioTimers(harness: *Harness) void {
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
    harness.armTeardownStrand();
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

/// The #181 draw: a third of seeds give the http cluster a retry budget
/// and, with it, the refusing second endpoint the budget exists to get
/// past. The two ride together deliberately — a dead endpoint without
/// retries would answer half the requests `502`, which a clean seed's
/// golden outcomes forbid, while retries without one would be a budget
/// nothing ever spends.
///
/// Drawn across the whole legal range rather than fixed at 1, because
/// the two ways a retry can end are decided by which of the budget and
/// the endpoint set runs out first: at 1 retry a second failure answers
/// `502` with the budget spent, while at 2 or more it is the *endpoints*
/// that run out and the answer comes from the exhaustion rung instead.
/// Both are reachable here only because the range is.
/// A pool-starved seed keeps the single-endpoint topology whatever it
/// drew, and the reason is a shadow the §9 census depends on. Those seeds
/// set `relay_buffers` and `upstream_slots` both to 1, and the exemption
/// for `l7_shed_upstream_slots` rests on the L7 path taking the relay
/// buffer first, so the relay rung answers everything that would reach
/// the slot rung. A *second endpoint* breaks that: the one slot can be
/// parked on endpoint 0 while a request picks endpoint 1, which cannot
/// reuse it and must dial — a correct shed, and one no single-endpoint
/// cluster can produce, because there the parked connection is always the
/// one wanted. Found on seed 4316 of a 16384-seed sweep. The behavior
/// itself is covered directly by `src/http_proxy_test.zig`, which
/// exhausts the upstream pool on purpose; what does not belong here is a
/// pool-sizing scenario arriving as a side effect of a retry draw.
fn deriveRetries(harness: *Harness, random: std.Random) void {
    // Drawn either way, so a starved seed's stream position stays where
    // an unstarved one's is and the suppression costs no other coverage.
    const budget: u16 = if (random.uintLessThan(u8, 3) == 0)
        1 + random.uintAtMost(u16, zoxy.constants.cluster_retries_max - 1)
    else
        0;
    if (budget == 0 or harness.force_exhaustion) {
        harness.retries_http = 0;
        harness.endpoints_http_count = 1;
        return;
    }
    harness.retries_http = budget;
    harness.endpoints_http_count = 2;
    harness.endpoints_http[1] = refusingEndpointAddress();
    assert(harness.retries_http >= 1);
    assert(harness.retries_http <= zoxy.constants.cluster_retries_max);
}

/// The #180 draw: a third of seeds allow the WebSocket token and size a
/// tunnel pool for it. The rest keep the `501` — which is not merely the
/// absence of coverage but the other half of the gate, and the shape
/// every config written before the feature still has.
///
/// A clean seed's pool is wide enough that no handshake can be shed,
/// because its oracle demands an exact transcript and a `503` is not the
/// answer its script asked for — the same reason `deriveMaxInflight`
/// caps only under the adversary. An adversarial seed draws a pool small
/// enough to run out, which is what reaches the §8 tunnel rung.
fn deriveUpgrades(harness: *Harness, random: std.Random) void {
    if (random.uintLessThan(u8, 3) != 0) {
        harness.upgrades_http = false;
        harness.tunnels = 0;
        return;
    }
    harness.upgrades_http = true;
    // One tunnel under the adversary, so two concurrent handshakes
    // collide and the §8 rung is reached by ordinary scheduling rather
    // than by a rare coincidence. A clean seed gets room for every
    // client instead: its oracle demands an exact transcript, and a
    // `503` is not the answer its script asked for.
    harness.tunnels = if (harness.clean) clients_max else 1;
    assert(harness.tunnels >= 1);
    assert(harness.tunnels <= clients_max);
}

fn deriveTopology(harness: *Harness, random: std.Random) void {
    harness.endpoints_l4 = .{originAddress()};
    harness.endpoints_http = .{ httpOriginAddress(), httpOriginAddress() };
    deriveRetries(harness, random);
    deriveUpgrades(harness, random);
    // A quarter of seeds. Clean ones included, deliberately: an
    // adversarial seed only holds the transcript to a legal *prefix*, so
    // a proxy that settled on the interim and dropped the real answer
    // would pass there. The exact-outcome oracle is the one that notices.
    harness.interim_http = random.uintLessThan(u8, 4) == 0;
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
    const http_hash_key = deriveSticky(harness, random);
    const pick_http = if (harness.sticky_http) .hash else randomPick(random);
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
    // #174 weights on a single-endpoint topology: the share itself is
    // moot (there is nobody to share against, and one endpoint at any
    // nonzero weight routes identically), but drawing a table at all
    // flows the weights contract — parallel lengths, the nonzero-sum
    // init assertion, the eligibility filter's weight read — through
    // every schedule the adversary can produce. The proportional
    // properties are pinned by balancer.zig's own tests, exactly like
    // `hash`'s stickiness above.
    harness.weights_l4 = .{1 + random.uintAtMost(u16, 255)};
    harness.weights_http = .{
        1 + random.uintAtMost(u16, 255),
        1 + random.uintAtMost(u16, 255),
    };
    wireClusters(harness, random, .{
        .l4 = pick_l4,
        .http = pick_http,
        .http_hash_key = http_hash_key,
    }, health);
    harness.routes_l4 = .{.{ .prefix = "/", .cluster_index = 0 }};
    harness.routes_http = .{.{ .prefix = "/", .cluster_index = 1 }};
    harness.proxy_protocol_l4 = deriveProxyProtocol(random);
    harness.deriveTerminatingDraws(random);
    harness.wireListeners(deriveForwarded(random));
    harness.deriveServerConfig(random, connect_timeout_ms, health.interval_ms);
}

/// The picks the two clusters were drawn with, bundled so `wireClusters`
/// takes one argument for them rather than three positional ones that
/// read alike at the call site.
const ClusterPicks = struct {
    l4: zoxy.config.Config.Cluster.Pick,
    http: zoxy.config.Config.Cluster.Pick,
    http_hash_key: zoxy.config.Config.Cluster.HashKey,
};

/// The two cluster records, split from `deriveTopology` for exactly the
/// reason `deriveTerminatingDraws` below was: the #181 second endpoint
/// pushed that function past the length limit again. Nothing moved but
/// the braces — the literal is still evaluated where it was, so the four
/// draws inside it (a weights coin and a `max_inflight` per cluster) keep
/// their stream positions.
fn wireClusters(
    harness: *Harness,
    random: std.Random,
    picks: ClusterPicks,
    health: HealthDraw,
) void {
    assert(harness.endpoints_http_count >= 1);
    assert(harness.endpoints_http_count <= harness.endpoints_http.len);
    harness.clusters = .{
        .{
            .name = "origin-l4",
            .endpoints = &harness.endpoints_l4,
            .weights = if (random.boolean()) &harness.weights_l4 else null,
            .pick = picks.l4,
            .check = health.check_l4,
            .max_inflight = deriveMaxInflight(harness.clean, random),
            .proxy_protocol_send = harness.proxy_protocol_send_l4,
        },
        .{
            .name = "origin-http",
            .endpoints = harness.endpoints_http[0..harness.endpoints_http_count],
            .weights = if (random.boolean())
                harness.weights_http[0..harness.endpoints_http_count]
            else
                null,
            .pick = picks.http,
            .hash_key = picks.http_hash_key,
            .check = health.check_http,
            .max_inflight = deriveMaxInflight(harness.clean, random),
            .retries = harness.retries_http,
        },
    };
    // The retry budget and the endpoint that makes it spendable ride
    // together (`deriveRetries`), so neither is ever configured alone.
    assert((harness.retries_http == 0) == (harness.endpoints_http_count == 1));
}

/// The §4 terminating draws, split from `deriveTopology` when the #202
/// clock jump pushed that one past the length limit — the same reason,
/// and the same remedy, as `deriveServerConfig`.
///
/// Order is load-bearing rather than incidental: everything here is drawn
/// from the scenario stream, and `deriveClockJump` deliberately draws
/// nothing when the seed took no terminating clients, so a plaintext
/// seed's stream position — and with it every plaintext seed's coverage —
/// stays exactly where it was before any of this existed.
fn deriveTerminatingDraws(harness: *Harness, random: std.Random) void {
    // The terminating listener rides the l4 cluster's endpoint but keeps
    // its own route, so `verifyUpstreamIdentities` can tell a terminated
    // connection's origin conn from a plaintext one's.
    harness.tls_protocol = if (random.boolean()) .http else .l4;
    harness.routes_tls = .{.{
        .prefix = "/",
        .cluster_index = if (harness.tls_protocol == .http) 1 else 0,
    }};
    harness.tls_clients = deriveTlsClients(
        random,
        harness.proxy_protocol_send_l4,
        harness.force_exhaustion,
    );
    harness.listeners_count = if (harness.tls_clients >= 1) 3 else 2;
    for (&harness.tls_scripts) |*script| {
        script.* = l7.scripts.terminating_scripts[
            random.uintLessThan(usize, l7.scripts.terminating_scripts.len)
        ];
    }
    harness.clock_jump_wanted = deriveClockJump(harness.tls_clients, random);
    harness.drop_mode = deriveDropMode(harness.clean, random);
    assert(harness.listeners_count <= harness.listener_configs.len);
    assert(harness.tls_clients >= 1 or !harness.clock_jump_wanted);
}

/// The top-level `Config` draw — the timeouts, the deadlines, and the
/// access-log coin — split from `deriveTopology` when the #178 draw
/// pushed that one past the length limit; the cluster and listener
/// tables it points at are the caller's, already wired.
fn deriveServerConfig(
    harness: *Harness,
    random: std.Random,
    connect_timeout_ms: u32,
    health_interval_ms: u32,
) void {
    assert(connect_timeout_ms >= 1);
    assert(health_interval_ms >= 1);
    harness.config = .{
        // The terminating listener is the third, and only a seed that drew
        // TLS clients binds it. Sliced rather than left inert so a
        // plaintext seed's fd, ring and listener budgets are exactly what
        // they were before TLS existed — otherwise every seed in the sweep
        // would shift, and the coverage this gate already has with it.
        .listeners = harness.listener_configs[0..harness.listeners_count],
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
        // Stated, not drawn: no seed allows an upgrade yet, so this clock
        // is inert and drawing it would move every seed's stream position
        // for coverage that does not exist. The draw arrives with the
        // tunnels themselves (#180).
        .tunnel_timeout_ms = zoxy.constants.tunnel_ms_default,
        // Three seeds in four run with the access log on, so the sink,
        // its staging swap, and the per-request captures all take the
        // schedule fuzz; the fourth leaves it off, which is the shape
        // that must reserve nothing and read no clock (§5, §8).
        .access_log_sink = if (random.uintLessThan(u8, 4) == 0) null else .stdout,
        // #140, on every seed: two scripts send the request header and
        // the sized origin answers with the response one, so both
        // captures run under the whole schedule fuzz. What the sweep
        // proves is shape and value — the objects on exactly the http
        // lines, and never a value the scripts did not send; staleness
        // needs distinguishable values and is the directed tests'.
        .access_log_request_headers = &log_request_headers,
        .access_log_response_headers = &log_response_headers,
        .health_interval_ms = health_interval_ms,
        // #159: a page for `403` on every seed — the one status a
        // script earns from a filter reject — so the configured-page
        // arm of the static path runs under the whole schedule fuzz,
        // and the client can demand its bytes on every 403. `503` is
        // deliberately left out: the sheds keep their empty bodies,
        // which is the opt-in rule stated as a property.
        .error_pages = &error_pages,
    };
}

/// The #178 draw: a quarter of seeds key the http cluster on the sim
/// cookie, forcing `hash` (a cookie key rides no other policy). The
/// rest draw their pick freely, where `hash` means source_ip — so both
/// hash keys, and every keyless policy, flow through the schedule fuzz.
/// The sticky scripts run on every seed either way; on a non-sticky one
/// their cookies are inert bytes, which is itself the oracle. Also
/// re-proves the pinned tag: what the scripts send and the client
/// oracle demands must be what the running mint spells for the one http
/// endpoint, so a hash change fails the sweep loudly instead of quietly
/// re-homing cookie holders.
fn deriveSticky(harness: *Harness, random: std.Random) zoxy.config.Config.Cluster.HashKey {
    harness.sticky_http = random.uintLessThan(u8, 4) == 0;
    var minted_tag: [zoxy.balancer.Balancer.endpoint_tag_len]u8 = undefined;
    zoxy.balancer.Balancer.formatEndpointTag(
        zoxy.balancer.Balancer.addressIdentity(&harness.endpoints_http[0]),
        &minted_tag,
    );
    assert(std.mem.eql(u8, &minted_tag, l7.canon.sticky_tag));
    assert(l7.canon.sticky_cookie_name.len >= 1);
    if (harness.sticky_http) {
        return .{ .cookie = l7.canon.sticky_cookie_name };
    }
    return .source_ip;
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

/// How many §4 terminating clients this seed runs (#125), and so whether
/// it binds a terminating listener at all. A quarter of seeds draw one or
/// two: enough that ~1000 sessions cross the sweep — well past the census
/// floor for a rung to fire reliably — while a real handshake's ~260 µs
/// on each side keeps the gate inside the ~5 s it is run at.
///
/// Refused outright when the l4 cluster announces itself with a PROXY
/// header. That header stages into the relay buffer, which is not where a
/// terminated connection's wire bytes come from, and `config.zig` rejects
/// the pair at load — so a harness that hand-built it would be simulating
/// a deployment nobody can configure.
fn deriveTlsClients(
    random: std.Random,
    send: ?zoxy.config.Config.Cluster.ProxyProtocolSend,
    force_exhaustion: bool,
) u8 {
    if (send != null) return 0;
    if (random.uintLessThan(u8, 4) != 0) return 0;
    // A starved seed runs the full population against its single engine,
    // which is the only way `shed_tls_engines` is reached: with one client
    // the pool is never contended, and drawing the count independently
    // left the rung silent across the whole sweep.
    if (force_exhaustion) return tls_clients_max;
    return 1 + random.uintLessThan(u8, tls_clients_max);
}

/// The §4 engine pool this seed runs with. Zero when it drew no
/// terminating clients, which keeps the pool free to every scenario that
/// does not use it.
///
/// A starved seed gets exactly one engine against up to two sessions:
/// the §4 wall, which is what it was drawn to meet, and the only way
/// `shed_tls_engines` is reached. Every other seed is sized so no session
/// is shed — and that means the drawn count *plus one*, not the drawn
/// count. #204's resuming client dials from the end hook of the session
/// whose ticket it offers, and that session's engine is released a loop
/// turn later, when the server sees the close; the two overlap, and
/// sizing to the population would shed the resumption rather than cover
/// it.
fn deriveTlsEngines(tls_clients: u8, force_exhaustion: bool) u32 {
    assert(tls_clients <= tls_clients_max);
    if (tls_clients == 0) return 0;
    if (force_exhaustion) return 1;
    return @as(u32, tls_clients) + 1;
}

/// Whether a seed steps its wall clock past a rotation interval (#202).
/// Half of the seeds that terminate TLS, and none of the rest: a
/// plaintext seed seals no ticket, so a jump there would move nothing
/// while shifting the whole sweep's stream position — the same argument
/// that keeps the terminating listener off a plaintext seed's budgets.
fn deriveClockJump(tls_clients: u8, random: std.Random) bool {
    assert(tls_clients <= tls_clients_max);
    if (tls_clients == 0) return false;
    return random.boolean();
}

/// The two #159 pages the sweep serves, rendered here exactly as
/// `config.zig`'s loader renders one — the simulator builds its
/// `Config` by hand (no filesystem, no parse), so the shape is spelled
/// out rather than loaded. The client oracle demands these bodies
/// byte-for-byte on every seed.
///
/// The duplication is deliberate but not free: this spelling and the
/// loader's could drift, and nothing here would notice, because what
/// the serving path consumes is the `StaticPage` *fields* — it never
/// re-reads the head it was handed. What that costs is coverage of the
/// loader's exact byte layout, which `config.zig`'s own tests pin
/// instead (`bodies render into complete pages`). Same trade, same
/// reason, as `src/http_proxy_test.zig`'s hand-spelled page.
const error_page: zoxy.config.Config.StaticPage = renderSimPage(403, l7.canon.error_page_body);
const respond_page: zoxy.config.Config.StaticPage = renderSimPage(200, l7.canon.respond_body);
const error_pages = [_]*const zoxy.config.Config.StaticPage{&error_page};

/// The #140 names every seed's config logs, already lowercased the way
/// the loader would leave them (the simulator builds its `Config` by
/// hand, so it owes that spelling itself).
const log_request_headers = [_][]const u8{l7.canon.log_request_header};
const log_response_headers = [_][]const u8{l7.canon.log_response_header};

fn renderSimPage(comptime status: u16, comptime body: []const u8) zoxy.config.Config.StaticPage {
    // The loader's own preconditions, restated where the loader is
    // being stood in for: a status a page may carry, and a body the
    // client oracle can demand.
    comptime assert(zoxy.shed.isPageStatus(status));
    comptime assert(body.len >= 1);
    const head = std.fmt.comptimePrint(
        "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nContent-Type: {s}\r\n",
        .{ status, zoxy.shed.reasonPhrase(status), body.len, l7.canon.page_content_type },
    );
    const keep = head ++ "\r\n" ++ body;
    const close = head ++ "Connection: close\r\n\r\n" ++ body;
    // `renderStaticPage`'s postcondition: the head is a real prefix, so
    // the HEAD slice the serve path takes is never the whole response.
    comptime assert(keep.len > body.len);
    comptime assert(close.len > keep.len);
    return .{
        .status = status,
        .keep = keep,
        .close = close,
        .keep_head_len = keep.len - body.len,
        .close_head_len = close.len - body.len,
    };
}

/// The §7 request rules and the #175 response rules the http listener
/// runs — and, on the seeds whose tls listener terminates http, that one
/// too (#215). Split from `wireListeners` when attaching the second
/// listener's chain took it past the length limit; the two halves are
/// what a listener is made of, in the order the config reads.
fn wireFilters(harness: *Harness) void {
    harness.request_filters_http = .{
        .{
            .match = .{ .path_prefix = "/reject" },
            .actions = &.{.{ .reject = 403 }},
        },
        .{
            // #176: composed target, no host override — the Location the
            // client oracle demands is scheme + the request's own host +
            // its canonical path, `l7.canon.redirect_location` exactly.
            .match = .{ .path_prefix = "/redirect" },
            .actions = &.{.{ .redirect = .{ .status = 301, .target = .{ .composed = .{
                .scheme = .https,
            } } } }},
        },
        .{
            // #159: answered from a configured body, before any
            // post-parse resource is acquired and without reaching an
            // origin. The page is pre-rendered like the loader's, so
            // the sweep exercises the static path's body-carrying arm.
            .match = .{ .path_prefix = "/respond" },
            .actions = &.{.{ .respond = &respond_page }},
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
    // #175 response rules, always on: every response the render forwards
    // gains the stamp — so the client can require it on every 200 and
    // refuse it on every static, which is what separates the two render
    // paths from outside — and the 5xx rule matches a class the scripted
    // origin never answers, so its edit appearing anywhere is the class
    // predicate misfiring under some schedule.
    harness.response_filters_http = .{
        .{
            .match = .{},
            .edits = &.{.{
                .kind = .set,
                .name = l7.canon.response_edit_name,
                .value = l7.canon.response_edit_value,
            }},
        },
        .{
            .match = .{ .status_class = 5 },
            .edits = &.{.{ .kind = .set, .name = l7.canon.response_never_name, .value = "1" }},
        },
    };
}

fn wireListeners(harness: *Harness, forwarded: ?zoxy.config.Config.Listener.Forwarded) void {
    harness.wireFilters();
    // One binding for both filter fields: a tls listener either runs the
    // http listener's whole chain or none of it, and two spellings of the
    // same condition are two chances to edit one and not the other.
    const terminates_http = harness.tls_protocol == .http;
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
            .request_filters = &harness.request_filters_http,
            .response_filters = &harness.response_filters_http,
            .protocol = .http,
            .forwarded = forwarded,
            .upgrades = .{ .websocket = harness.upgrades_http },
        },
        .{
            .bind_address = tlsBindAddress(),
            // Its own route, so a terminated connection's origin conn is
            // one `verifyUpstreamIdentities` can tell from a plaintext
            // client's. Which cluster it points at follows the protocol:
            // an http terminator has to reach an origin that speaks HTTP.
            .routes = &harness.routes_tls,
            // The same filter chain the plaintext http listener runs
            // (#215). The claim termination rests on is that TLS is a
            // phase ahead of the protocol and not a protocol of its own —
            // the same render, the same filters, the same stamps — and a
            // listener configured with no filters cannot test any of it:
            // the response oracle these clients now run would be asking
            // for a stamp the config never ordered. Only on the http
            // draw, since filters on an l4 listener are a config error
            // (`ListenerL4ResponseFilters`) and an l4 relay has no head to
            // apply them to.
            .request_filters = if (terminates_http) &harness.request_filters_http else &.{},
            .response_filters = if (terminates_http) &harness.response_filters_http else &.{},
            // Both, across seeds. Termination is a phase ahead of the
            // protocol (§4), so the two combinations exercise genuinely
            // different code — the L4 relay's transform hooks against the
            // L7 head-fill source and client-write channel — and a sweep
            // that only ever drew one would leave the other's states
            // reachable by nothing.
            .protocol = harness.tls_protocol,
            // Paths nothing reads: the harness embeds the PEMs, so what
            // this states is only that the listener terminates — which is
            // what `Server.start` checks its credentials table against.
            .tls = if (harness.tls_clients >= 1)
                .{ .cert_path = "cert.pem", .key_path = "key.pem" }
            else
                null,
        },
    };
}

/// The staging size this seed runs with (§8, §9). Adversarial seeds sit
/// at the floor — one worst-case line each — so the buffer swap runs
/// constantly and every line meets a nearly-full buffer, against the
/// default's hundred-line headroom where the swap fires once a
/// scenario. The *drop* rung itself stays out of reach here: a scenario
/// emits a handful of lines and filling even the floor takes dozens, so
/// it is pinned by a directed test (`access_log_test.zig`) rather than
/// left to a seed that cannot generate the volume.
///
/// The floor is one line of *this* config, not the static minimum:
/// #140's named headers widen a line, and the loader holds a real
/// config to the wider bound — a hand-built one owes itself the same,
/// or the drop rung would fire on arithmetic rather than on the
/// backpressure it is there to force.
fn deriveAccessLogBuffer(harness: *const Harness) u32 {
    if (harness.config.access_log_sink == null) {
        return 0;
    }
    if (harness.clean) {
        return zoxy.constants.access_log_buffer_bytes_default;
    }
    const floor = @max(
        zoxy.constants.access_log_buffer_bytes_min,
        zoxy.constants.accessLogLineBytes(
            log_request_headers.len + log_response_headers.len,
        ),
    );
    assert(floor >= zoxy.constants.access_log_buffer_bytes_min);
    assert(floor <= zoxy.constants.access_log_buffer_bytes_max);
    return floor;
}

/// The pool sizes this seed runs the server with. A quarter of
/// adversarial seeds shrink them to force the §8 rungs; clean seeds keep
/// ample pools so golden outcomes never meet a shed. Decided in `setUp`
/// (see `force_exhaustion`) because the ring size had to precede
/// `io.init`.
fn deriveInitOptions(harness: *const Harness, random: std.Random) ServerSim.InitOptions {
    const force_exhaustion = harness.force_exhaustion;
    const access_log_buffer_bytes = harness.deriveAccessLogBuffer();
    return if (force_exhaustion)
        .{
            // head_buffers ≤ conn_slots is a Server.init precondition, so
            // the slot draw starts at whatever the ring draw chose.
            .conn_slots = harness.head_buffers + random.uintLessThan(u32, 2),
            .relay_buffers = 1,
            .upstream_slots = 1,
            .head_buffers = harness.head_buffers,
            // Clamped, because a starved seed's slot count is drawn from
            // the ring and can sit below the pool the upgrade draw asked
            // for — and a tunnel is an accepted connection, so a pool
            // wider than the slots that hold one cannot exist (§5). A
            // clamp to zero is legal here and means every handshake on
            // this seed meets the tunnel rung, which is coverage rather
            // than a loss.
            .tunnels = @min(harness.tunnels, harness.head_buffers),
            // Capacity 1: the first render engages the pressure flag, so
            // the engage counter stays reachable even though the shed
            // rung itself is relay-shadowed (see sim/main.zig uncovered).
            .upstream_head_buffers = 1,
            .access_log_buffer_bytes = access_log_buffer_bytes,
            .tls_engines = deriveTlsEngines(harness.tls_clients, force_exhaustion),
        }
    else
        .{
            .tunnels = harness.tunnels,
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
            .tls_engines = deriveTlsEngines(harness.tls_clients, force_exhaustion),
        };
}

fn startServerAndOrigins(harness: *Harness, arena: std.mem.Allocator, random: std.Random) !void {
    const options = harness.deriveInitOptions(random);
    try harness.server.init(arena, &harness.io, &harness.config, options);
    harness.tls_credentials = .{ null, null, null };
    if (harness.tls_clients >= 1) {
        // Index 2: the terminating listener is the third.
        harness.tls_credentials[2] = try zoxy.tls.Credentials.load(
            arena,
            zoxy.tls.testdata.cert_pem,
            zoxy.tls.testdata.key_pem,
            // The deterministic nonce is not optional here: without it the
            // CertificateVerify signature varies run to run, and this
            // gate's whole verdict is that one seed replays byte-exact.
            .{ .deterministic_nonce = true },
        );
        // One slot per listener, non-null exactly at the terminating one.
        harness.server.setTlsCredentials(
            harness.tls_credentials[0..harness.listeners_count],
        );
    }
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

/// The terminating population's per-scenario state: the storage, the
/// slot bookkeeping the resuming client grows, and one echo token per
/// slot.
///
/// A plaintext seed draws nothing here, which is what keeps its stream
/// position — and so the whole sweep's plaintext coverage — exactly
/// where it was before TLS existed.
fn populateTlsClients(harness: *Harness, random: std.Random) void {
    harness.tls_clients_storage = @splat(undefined);
    harness.tls_clients_live = harness.tls_clients;
    harness.tls_resume_started = false;
    harness.scenario_ended = false;
    harness.clock_jumped = false;
    harness.drop_kind = null;
    harness.drop_latch_armed = false;
    assert(harness.tls_clients <= tls_clients_max);
    // One token past the drawn count, for the resuming client's slot.
    const token_count = if (harness.tls_clients >= 1)
        harness.tls_clients + 1
    else
        0;
    assert(token_count <= tls_client_slots);
    for (harness.tls_tokens[0..token_count], 0..) |*token, index| {
        random.bytes(token);
        // A distinguishable first byte, so an echo oracle comparing the
        // wrong session's bytes fails on the first one rather than
        // needing the whole token to collide.
        token[0] = @intCast(index);
    }
}

fn populateClients(harness: *Harness, random: std.Random) void {
    // Each client flips a protocol coin: mixed populations put both
    // serving paths under one schedule and shared pools.
    const plaintext_count = 1 + random.uintLessThan(u8, clients_max);
    // The terminating clients are part of the population the wind-down
    // waits on, so they join the count `clientEnded` compares against.
    harness.clients_count = plaintext_count + harness.tls_clients;
    harness.l4_count = 0;
    harness.l7_count = 0;
    harness.ended_count = 0;
    harness.populateTlsClients(random);
    harness.clients = @splat(.{});
    harness.l7_clients = @splat(.{});
    harness.l4_announced_len = @splat(0);
    var index: u8 = 0;
    while (index < plaintext_count) : (index += 1) {
        if (random.boolean()) {
            const client = &harness.l7_clients[harness.l7_count];
            harness.l7_count += 1;
            // A seed that enables upgrades puts its first two http
            // clients on the handshake, rather than waiting for a
            // uniform draw over every script to produce one. It raises
            // the odds rather than guaranteeing them — the client count
            // and the per-slot coin still decide how many http clients a
            // seed has — but it is what makes two concurrent handshakes,
            // and so the §8 tunnel rung, ordinary across a sweep instead
            // of a coincidence. Every other client still draws freely,
            // so the population keeps its shape.
            const forced_upgrade = harness.upgrades_http and harness.l7_count < 2;
            client.prepare(
                &harness.io,
                httpBindAddress(),
                if (forced_upgrade) .upgrade_request else random.enumValue(l7.Script),
                harness.clean,
                harness.upgrades_http,
                harness.sticky_http,
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
    assert(harness.l4_count + harness.l7_count + harness.tls_clients ==
        harness.clients_count);
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
    assert(harness.l4_count + harness.l7_count + harness.tls_clients ==
        harness.clients_count);
    for (harness.clients[0..harness.l4_count]) |*client| {
        client.begin();
    }
    for (harness.l7_clients[0..harness.l7_count]) |*client| {
        client.begin();
    }
    harness.startTlsClients();
}

/// The §4 population (#125). `TestClient.start` dials immediately rather
/// than splitting prepare from begin, so it runs here rather than in
/// `populateClients` — and its hook has to be set *after*, because `start`
/// clears both hook fields.
///
/// Every seed is drawn from the scenario stream, not from `fillRandom`:
/// the client's key material must not interleave with the server's on the
/// simulator's key stream, or the handshake count would decide what each
/// peer got and the replay would depend on delivery order.
fn startTlsClients(harness: *Harness) void {
    var index: u8 = 0;
    while (index < harness.tls_clients) : (index += 1) {
        const random = harness.scenario_prng.random();
        var seeds: [3][32]u8 = undefined;
        for (&seeds) |*seed| random.bytes(seed);
        harness.startTlsClient(index, &seeds, null);
    }
    if (harness.tls_clients == 0) return;
    const random = harness.scenario_prng.random();
    for (&harness.tls_resume_seeds) |*seed| random.bytes(seed);
}

/// One terminating client into slot `index`, offering `resume_with` if it
/// has one. Shared by the population and by the resuming client, so the
/// two differ in exactly the ticket and nothing else — which is what
/// makes a resumed session's coverage the same coverage, minus a full
/// handshake.
fn startTlsClient(
    harness: *Harness,
    index: u8,
    seeds: *const [3][32]u8,
    resume_with: ?*const zoxy.tls.SessionTicket,
) void {
    assert(index < harness.tls_clients_live);
    const client = &harness.tls_clients_storage[index];
    // What this slot drew, and the one property of it the session's shape
    // turns on: a script whose response is judged exactly as a plain
    // GET's can be followed by one (#204's keep-alive turnaround, judged
    // as `terminating_pair`), and one whose response is a static, a
    // redirect, a rejection or an un-stamped 200 cannot — a single spec
    // could not describe both halves of that pair.
    const entry = l7.scripts.spec(harness.tls_scripts[index]);
    const pairs = harness.tls_protocol == .http and entry.routed_canonical;
    client.start(&harness.io, Harness.tlsBindAddress(), .{
        .host_name = zoxy.tls.testdata.host_name,
        .resume_with = resume_with,
        // An echo token for a relayed session, a real request for a
        // proxied one — the terminated stream has to be what the
        // listener behind it expects, or the head parser answers 400
        // and the transform is never exercised at all.
        .app_data = if (harness.tls_protocol == .http)
            entry.request
        else
            harness.tls_tokens[index][0..tls_token_bytes],
        // How each population knows its peer answered. A relayed
        // session gets its own bytes back, so a byte count is exactly
        // right; a proxied one gets a response, whose length has
        // nothing to do with its request's, so it needs the framing
        // rule (#204). Wiring the echo rule to the proxied population
        // would not fail — it would *hang*, waiting for a response as
        // long as the request that earned it.
        .exchange_end = if (harness.tls_protocol == .http)
            .http_response
        else
            .echo,
        // The second request, on the connection the first left open —
        // only the proxied population has one, since an echo has no
        // turnaround to take.
        .followup_data = if (pairs) tls_http_followup else &.{},
        // A relayed session closes in protocol once its echo is back:
        // an in-band EOF no socket EOF follows, which is the §6
        // half-close a terminated relay can only learn from a decrypt.
        // A paired one lets its second request's `Connection: close` end
        // the connection instead, and finishes on the EOF.
        //
        // An unpaired proxied session takes the relayed shape, and has
        // to: its script's request carries no `Connection: close`, so
        // without this the answered connection would sit in keep-alive
        // until the drain reaped it — holding a conn slot for the rest of
        // the scenario on a fifth of the terminating clients. Closing in
        // protocol instead is the §6 half-close arriving mid-keep-alive,
        // which nothing else in the sweep produces.
        .close_after_echo = !pairs,
        .x25519_seed = seeds[0],
        .p256_seed = seeds[1],
        .random = seeds[2],
    }) catch unreachable; // Seeded keypairs; the inputs are ours.
    // A fresh session holds nothing yet: whatever ticket this slot's
    // previous occupant captured must not survive into the next one, and
    // on the resuming slot that is the difference between offering the
    // issuer's ticket and offering its own.
    assert(client.capturedTicket() == null);
    client.on_end = tlsClientEndedHook;
    client.on_end_context = harness;
}

/// #204's resumption leg. A ticket can only be offered on a *second*
/// connection, so this runs off the first one's end: whichever session
/// captured a ticket, its ticket goes back out on a fresh dial, and the
/// server's `psk_lookup` either opens what it sealed or falls back to a
/// full handshake. Both are legal, which is why the counter is the
/// oracle and not this call succeeding.
///
/// `clients_count` grows *before* `clientEnded` compares against it, so
/// the wind-down waits for the resuming session rather than racing it.
fn maybeStartResumingClient(harness: *Harness) void {
    // The hook is wired to terminating clients only, so reaching here at
    // all means the seed drew some — which is what stops the slot index
    // below from underflowing.
    assert(harness.tls_clients >= 1);
    if (harness.tls_resume_started) return;
    // The wind-down has stopped the listener accepting, so a dial now
    // would only ever measure how a refused connect is reaped.
    if (harness.scenario_ended) return;
    const issuer = harness.ticketIssuer() orelse return;
    const ticket = issuer.capturedTicket().?;
    harness.tls_resume_started = true;
    harness.tls_clients_live += 1;
    harness.clients_count += 1;
    // Exactly one resumer, in exactly the slot past the drawn count —
    // today only the `tls_resume_started` latch keeps that true, so it is
    // worth saying out loud rather than inferring from the latch.
    assert(harness.tls_clients_live == harness.tls_clients + 1);
    assert(harness.tls_clients_live <= tls_client_slots);
    harness.startTlsClient(harness.tls_clients_live - 1, &harness.tls_resume_seeds, ticket);
}

/// The first finished session holding a ticket. A server issues them on
/// every handshake, so this is normally the first client to end — but a
/// refused dial, a cut handshake or a shed engine all end a client with
/// nothing to offer, and on those seeds there is simply no resumption to
/// cover.
fn ticketIssuer(harness: *Harness) ?*TlsClient {
    // The drawn population only: the resuming client's own ticket is
    // never offered again, and its slot may not even exist yet.
    assert(harness.tls_clients >= 1);
    assert(harness.tls_clients <= harness.tls_clients_live);
    for (harness.tls_clients_storage[0..harness.tls_clients]) |*client| {
        if (!client.isEnded()) continue;
        if (client.capturedTicket() != null) return client;
    }
    return null;
}

fn tlsClientEndedHook(context: ?*anyopaque) void {
    const harness: *Harness = @ptrCast(@alignCast(context.?));
    // Before the resumer dials, so its handshake is the one that finds
    // the key overdue and its offered ticket the one sealed under the key
    // being retired.
    harness.maybeJumpClock();
    harness.maybeStartResumingClient();
    harness.clientEnded();
}

fn clientEnded(harness: *Harness) void {
    harness.ended_count += 1;
    assert(harness.ended_count <= harness.clients_count);
    if (harness.ended_count == harness.clients_count) {
        harness.endScenario();
    }
}

/// #206's first hook, on the seeds that drew `.wind_down`: take every
/// armed op of one kind and never deliver it, at the instant the
/// wind-down begins. That is the class of defect no other seed can reach
/// — everything else this simulator does completes, which is faithful to
/// io_uring and blind to what a readiness backend did in #203.
///
/// At the wind-down because that is where the ops worth stranding are
/// armed. Measured over a 4096-seed sweep, the share of wind-downs
/// holding at least one op of a kind: timer 98%, accept 98%, recv 53%,
/// connect 24%, log_write 24%, timer_cancel 15%, recv_group 10%, send
/// 1.2%, connect_cancel 1.0% — and `close` on none of them.
///
/// The kind is picked here, out of what is armed, rather than drawn with
/// the rest of the topology, and the spread above is why. A kind named
/// before the run spends its seed whether or not the wind-down holds one:
/// 230 of the 368 runs that drew a kind found none of it armed and
/// stranded nothing, and the kinds armed under a fifth of the time were
/// out of reach in practice — a blind draw finds `send` armed about once
/// in five sweeps. Picking from the armed set makes every drawn run
/// strand: 316 strands against 124, and 112 runs reaching the §8 give-up
/// against 52. What it costs is a seed's strand being settled before the
/// run starts, which nothing needed — `verify` reads what was stranded,
/// never what was going to be.
///
/// Uniform over *kinds* rather than over pending *ops*, deliberately:
/// accept and timer are four fifths of everything pending, so picking a
/// random op would spend nearly every strand on those two and reach
/// recv_group about once in a sweep.
fn maybeStrandOps(harness: *Harness) void {
    if (harness.drop_mode != .wind_down) return;
    if (harness.drop_kind != null) return;
    if (!harness.giveUpCanExist()) return;
    const kind = harness.drawStrandKind() orelse return;
    const dropped = harness.io.dropPendingOps(kind);
    // The kind came out of the armed set, so a strand that took nothing is
    // a contradiction rather than the legal outcome it used to be: either
    // the pick read a table the drop then disagreed with, or an op left
    // the table between the two calls — and nothing runs in between.
    assert(dropped >= 1);
    // A stranded op stays *pending*, so the table it was counted out of is
    // still the bound; more than that would mean one was counted twice.
    assert(dropped <= harness.io.pending_count);
    // What the seed *did*, which is the fact `verify` reads — recorded
    // after the drop rather than before it, because the excuse it grants
    // ("this run may end at the give-up") is earned by stranding.
    harness.drop_kind = kind;
}

/// #206's second hook, on the seeds that drew `.teardown`: strand the
/// first cancel submitted once the drain is already under way, rather
/// than one that was in flight when it began.
///
/// This is the half a wind-down drop cannot reach, and the issue's own
/// argument for it was wrong the first time round, so it is worth being
/// exact. It is *not* that a slot which can never be released is
/// otherwise unreachable — stranding any conn-armed op leaves one, 76
/// runs a sweep do it. It is that `beginTeardown` arms `connect_cancel`
/// and `deadline_cancel` *after* a wind-down drop has landed, so those
/// two are the only ops in a connection's armed set no drop placed at the
/// wind-down can be holding. #203 was a cancel submitted and never
/// delivered; this hook models it where it happened.
///
/// It waits rather than takes, which is the difference from
/// `drawStrandKind`: an op armed later is in no table to be read now, so
/// this hook cannot know whether it will find anything. Measured over a
/// 4096-seed sweep, 246 of the 784 runs that draw it find a cancel to
/// take; the other 538 are held to the ordinary invariants, having taken
/// nothing. That is the price of reaching an op that does not exist yet,
/// and the mode is drawn twice as often as `.wind_down` to pay it.
///
/// What it buys is the sharpest signal in this issue: **all 246 reach the
/// §8 give-up**, against 112 of the 316 wind-down strands, and 168 of
/// them leave the *connection* plane stuck. A cancel armed during
/// teardown and never delivered leaves that connection's armed set
/// non-empty forever, and `continueTeardown` returns early for as long as
/// that is true — a connection stuck in teardown with its slot held,
/// which is #203 exactly. The other 78 are the prober's, which cancels a
/// dial of its own when the drain stops it.
///
/// **Where it is armed decides what it catches**, which took two
/// measurements to get right and is the sort of thing that rots quietly.
/// Per run that drew the mode, and per strand it took:
///
///   - Armed *before* the doubles' `cancelIfStuck` burst: 82% strand, but
///     a fifth of those took a client double's cancel — the server's
///     drain never waits on one, so the run drained clean and the strand
///     bought nothing.
///   - Armed after the doubles and *before* `beginDrain` returns: 75%
///     strand, and 7% of those land on conns. The prober's stop-cancel is
///     submitted first, from inside the drain, and takes the other 93%.
///   - Armed after `beginDrain` returns: 31% strand, and 68% of those land
///     on conns.
///
/// The last is what ships. It strands on fewer runs because the cancels
/// submitted from inside the drain are gone by then, and that is the
/// point: what is left is the teardown of a connection that was still
/// working when the drain started. Armed at both drain entries, since a
/// seed that drains mid-scenario tears its connections down there.
fn armTeardownStrand(harness: *Harness) void {
    if (harness.drop_mode != .teardown) return;
    if (harness.drop_latch_armed) return;
    if (!harness.giveUpCanExist()) return;
    // Nothing can have been stranded yet: the wind-down hook does not run
    // in this mode, and the latch itself takes nothing until a submit
    // answers it.
    assert(harness.strandedKind() == null);
    harness.drop_latch_armed = true;
    // Both kinds at once, not one drawn of the two: `beginTeardown` arms
    // whichever the connection's state calls for, and a latch naming the
    // other spends the whole scenario waiting for an op that never comes.
    harness.io.armDropNext(&teardown_strand_kinds);
}

/// Whether this seed's drain has a give-up to provoke at all. A zero
/// `drain_deadline_ms` is "no cap" (§5), and the deadline timer is the
/// only thing that ever arms one: `onDrainStuck` is started by
/// `onDrainDeadline`, so a drain with no deadline has no backstop.
/// Stranding an op there asks the proxy for a report the configuration
/// deliberately declined — the drain waits for the last connection
/// however long that takes, by design — and the run ends in `SimIo`'s own
/// deadlock with no diagnostic, which is the same shape the excluded
/// `timer` kind has and just as much a true statement about the
/// backstop's reach rather than a defect.
///
/// Asked at the strand rather than at the draw because the draw runs in
/// `deriveTerminatingDraws` and the deadline is settled one call later in
/// `deriveServerConfig`. Gating the draw needs the deadline first, and
/// swapping two calls re-rolls every draw after them for the whole sweep,
/// taking the §9 census margins with it. Skipping here leaves both hooks
/// having taken nothing, so `verify` holds the seed to the ordinary
/// invariants — exactly what a seed that stranded nothing is for.
///
/// Found by the nightly soak (run #18, 2026-08-13). All four shards hit
/// the 16-failure cap early in their slices — shard 0 at 36k — and every
/// named seed had drawn both a mid-scenario drain with the no-cap
/// deadline and a drop.
fn giveUpCanExist(harness: *const Harness) bool {
    assert(harness.drop_mode != null);
    return harness.config.drain_deadline_ms != 0;
}

/// One kind out of those armed at this wind-down, or null when nothing
/// strandable is armed at all.
///
/// Nothing is excluded any more, and `timer` leaving the exclusion list is
/// what #226 bought. Stranding one used to be the shape §8's backstop
/// provably could not catch — `onDrainStuck` was itself a timer, so a seed
/// that stranded the drain deadline stranded the thing that would have
/// reported it, and the run ended in `SimIo`'s deadlock with no diagnostic
/// at all. The watchdog under it is not an op (`alarmStart`), so it fires
/// whether or not the backend is still delivering, and the same seeds now
/// end in a give-up that says so.
///
/// `close` is here for a different reason and was never an exclusion: it
/// is simply not armed at a wind-down on any measured run, and an
/// armed-set pick spends nothing on a kind that is not there. Its absence
/// is a property of the teardown path — `continueTeardown` waits for
/// `armedCount()` to reach zero and closes *synchronously*, so a
/// connection never has a close to take away — and the admin plane's
/// `submitClose` is the only `io.close` in the proxy.
///
/// Drawn from the scenario stream at the wind-down, so it consumes nothing
/// on the seeds that strand nothing and leaves their stream position — and
/// with it the whole sweep's coverage — where it was.
fn drawStrandKind(harness: *Harness) ?SimIo.OpKind {
    // Adding a kind here needs a matching arm in `strandCanExplainStuck`,
    // which lists `timer` and `none` as `unreachable`: without one the new
    // kind panics every seed that strands it, which is the loudest way to
    // ask whoever adds it which planes it can leave stuck.
    const strandable = [_]SimIo.OpKind{
        .accept,
        .connect,
        .recv,
        .recv_group,
        .send,
        .close,
        .log_write,
        .timer,
        .timer_cancel,
        .connect_cancel,
    };
    var armed: [strandable.len]SimIo.OpKind = undefined;
    var armed_count: usize = 0;
    for (strandable) |kind| {
        if (!harness.io.hasPendingOp(kind)) continue;
        armed[armed_count] = kind;
        armed_count += 1;
    }
    assert(armed_count <= armed.len);
    if (armed_count == 0) return null;
    const kind = armed[harness.scenario_prng.random().uintLessThan(usize, armed_count)];
    // The pick is the whole point: a kind returned here is one the strand
    // that follows can actually take.
    assert(harness.io.hasPendingOp(kind));
    return kind;
}

/// What a seed that ended at the §8 give-up owes instead of the ordinary
/// invariants (#206). A seed that stranded an op the drain waits on
/// cannot finish it and must not be asked to; what is demanded is that
/// the proxy *noticed*. A drain that cannot complete is allowed, a drain
/// that hangs without saying so is not.
///
/// Reached as an alternative for every seed rather than a branch on
/// whether this one dropped anything, because that is the property worth
/// holding: no schedule, dropped op or not, may end with the loop alive
/// and nobody the wiser.
///
/// Split from `verify` when the two oracles below took it to the 70-line
/// limit — the same remedy `setUp` and `deriveTopology` took before it.
/// `pending_ops_live` is passed in rather than asked here because it has
/// to be read before `verify` closes the harness's own sockets.
fn verifyGaveUp(harness: *const Harness, code: u8, pending_ops_live: bool) !void {
    const watchdog = code == ServerSim.drain_watchdog_exit_code;
    if (code != ServerSim.drain_stuck_exit_code and !watchdog) {
        return error.UnexpectedAbort;
    }
    // Only a seed that stranded something is excused. Without this, the
    // branch would accept any stuck drain as "#206 working as intended" —
    // including one a future release bug produced with every op
    // delivered, which is the exact defect this backstop exists to catch
    // and the last thing the sweep should swallow.
    if (harness.strandedKind() == null) return error.DrainStuckWithoutStrand;
    // The give-up is allowed to leave work unfinished. It is not allowed
    // to have freed a slot an op still points at: that is the §5
    // corruption the generation counter exists to catch, and this is the
    // one path where it could hide, since a dropped op never reaches the
    // stale-handle assert every delivered op passes through. #206 asked
    // for this oracle by name.
    if (!pending_ops_live) return error.SlotReleasedUnderPendingOp;
    if (watchdog) return harness.verifyWatchdogGaveUp();
    if (!harness.strandCanExplainStuck()) return error.StrandCannotExplainStuck;
}

/// What the #226 watchdog owes when it is the thing that gave up.
///
/// Not `strandCanExplainStuck`: that oracle asks which plane the drain was
/// waiting on, and reaching this code means nobody was in a position to
/// ask. The loop stopped delivering, so the planes' states are whatever
/// the schedule left them as, and demanding one be stuck would be
/// demanding the wedged process have finished thinking.
///
/// What is demanded instead is that the give-up was the watchdog's — the
/// alarm actually fired, rather than some other path exiting with its
/// code — and that only a stranded *timer* can reach it. That second one
/// is the layering, stated where it breaks: every other kind leaves the
/// drain's own deadline delivering, so `onDrainStuck` fires at the grace
/// and reports the plane, five virtual seconds before the watchdog would.
/// A watchdog fire on any other kind means the informative layer stayed
/// silent when it could have spoken.
fn verifyWatchdogGaveUp(harness: *const Harness) !void {
    if (!harness.io.alarmFired()) return error.WatchdogCodeWithoutWatchdog;
    if (harness.strandedKind() != .timer) return error.WatchdogBeatTheReporter;
}

/// What this seed actually stranded, by whichever hook took it, or null
/// for the seeds that stranded nothing — the fact `verify` reads when it
/// decides whether a stuck drain was asked for. The wind-down drop
/// records its kind on the harness; the teardown latch records its in the
/// backend, because what it took was decided by a submit that happened
/// long after the hook ran.
fn strandedKind(harness: *const Harness) ?SimIo.OpKind {
    const latched = harness.io.droppedNextOp();
    // The modes are alternatives, never both: one draw picks one hook, so
    // a seed with two strands would mean a hook ran outside its mode.
    assert(harness.drop_kind == null or latched == null);
    if (harness.drop_kind != null) assert(harness.drop_mode == .wind_down);
    if (latched) |kind| {
        assert(harness.drop_mode == .teardown);
        assert(kind == .timer_cancel or kind == .connect_cancel);
    }
    return harness.drop_kind orelse latched;
}

/// Whether the strand this seed took could account for a plane the
/// give-up found stuck. Mis-blaming is not hypothetical: the first
/// `onDrainStuck` reported "nothing stuck" while the admin plane held an
/// armed accept (#203), and a backstop that names the wrong plane sends
/// an operator somewhere useless with the process already gone.
///
/// Deliberately permissive — it asks that *some* stuck plane could own an
/// op of the stranded kind, never that a named one is stuck. Which plane a
/// strand lands on is a property of the schedule, and an oracle that
/// pinned it would fail on the rare seed rather than on a defect. That
/// bill was just paid once: #220's deadlock was a gate demanding an
/// outcome the configuration had declined.
///
/// Measured over a 4096-seed sweep, for the shape rather than the rule —
/// which plane each wind-down strand left stuck, in runs: `recv` conns 46,
/// `log_write` the log 24, `timer_cancel` conns 12 and conns+health 2,
/// `connect` health 10 and conns 4, `recv_group` conns 10, `send` conns 2,
/// `connect_cancel` conns 2. `accept` never leaves anything stuck at all —
/// 88 strands, no give-up — and admin is never the stuck plane. The
/// teardown latch adds 246 runs of its own: 168 on conns, the shape it
/// exists for, and 78 on the prober's dial cancel.
fn strandCanExplainStuck(harness: *const Harness) bool {
    const kind = harness.strandedKind().?;
    // Only `verifyGaveUp` calls this, and only after both of its own
    // gates: the run ended at an abort, and this seed stranded something.
    assert(harness.io.abortedWith() != null);
    const conns_stuck = !harness.server.conns.isFullyReleased();
    const admin_stuck = !harness.server.admin.isQuiescent();
    const log_stuck = !harness.server.access_log.isQuiescent();
    const health_stuck = !harness.server.health.isQuiescent();
    // `onDrainStuck` aborts only when one of the four is unfinished, so a
    // give-up with all four done is the backstop firing at nothing.
    assert(conns_stuck or admin_stuck or log_stuck or health_stuck);
    return switch (kind) {
        // The head ring is the connection path's alone (§5).
        .recv_group => conns_stuck,
        // Nothing but the access log writes one.
        .log_write => log_stuck,
        // Connections read, the admin plane reads its scrape, and the
        // prober reads its probe; all three dial except the admin one, and
        // all three write.
        .recv, .send => conns_stuck or admin_stuck or health_stuck,
        .connect => conns_stuck or health_stuck,
        // A listener's accept feeds admission and the admin plane.
        .accept => conns_stuck or admin_stuck,
        // Timers, and the cancels that chase them, belong to a conn's
        // deadline, the prober's pacing or the admin plane's scrape. The
        // access log arms none, which is why it is absent from both.
        .timer, .timer_cancel => conns_stuck or admin_stuck or health_stuck,
        // Only the first two of those three dial, so only they can have a
        // connect to cancel.
        .connect_cancel => conns_stuck or health_stuck,
        // `submitClose` is the proxy's only `io.close`, and it is the admin
        // plane's; a connection's closes are `closeNow`, which leaves no
        // completion to strand. No seed has reached this arm — `close` has
        // never been armed at a wind-down — and it is written out anyway,
        // because the alternative is an exclusion list, and
        // `drawStrandKind` records why this hook no longer keeps one.
        .close => admin_stuck,
        // Out of `drawStrandKind`'s list, so unreachable rather than
        // defaulted: adding one there without giving it an arm here panics
        // every seed that strands it, and a named arm is what makes that
        // obvious to whoever adds the next kind.
        .none => unreachable,
    };
}

/// Where this seed strands, or null for the thirteen in sixteen
/// adversarial seeds that strand nowhere. A small fraction on purpose — a
/// stranded run trades every other oracle for the one it exists to check,
/// since a drain that cannot finish leaves pools held and counters
/// unreconciled by design. Which kind is taken is not decided here;
/// `drawStrandKind` and `armDropNext` take what the schedule armed.
///
/// One draw for both modes, and `.wind_down` keeps the value that used to
/// mean "strand": the sweep's whole stream position hangs off how many
/// values are drawn here, so widening this into a second draw would
/// re-roll every seed after it and take the §9 census margins with it.
/// `.teardown` gets two of the sixteen values to `.wind_down`'s one,
/// because it strands on under a third of the seeds that draw it — see
/// `armTeardownStrand` for why that is a property of what it waits for
/// rather than a fixable one. The two hooks end up perturbing comparable
/// numbers of runs: 316 wind-down strands a sweep against 246.
fn deriveDropMode(clean: bool, random: std.Random) ?DropMode {
    // Adversarial seeds only, for the reason every sibling draw states:
    // a clean seed's oracle is each script's exact golden outcome, and a
    // stranded op ends the run at the give-up before those oracles are
    // reached — for every client in the scenario, not just the one the
    // strand touched. A silently unanswered exchange passing as "the
    // backstop worked" is precisely what clean seeds exist to forbid.
    if (clean) return null;
    return switch (random.uintLessThan(u8, 16)) {
        0 => .wind_down,
        1, 2 => .teardown,
        else => null,
    };
}

/// #202, on the seeds that drew it: step the wall clock past a sealing
/// key's whole rotation interval while the loop's own clock keeps
/// ticking. The next handshake to seal a ticket finds its key overdue and
/// replaces it — the only way a sweep whose scenarios last a virtual
/// second reaches a bound measured in hours.
///
/// Hung off the first terminating session *ending*, not off a virtual
/// instant. Virtual time only advances when a timer comes due, so a whole
/// population can handshake, exchange and close at the same instant — a
/// timer-driven jump measured 9 rotations across the entire sweep,
/// because it fired long after every seal it was meant to precede. This
/// placement measures 198.
///
/// What it covers, measured rather than assumed: a rotation under the
/// adversary's schedules, and a ticket carried across a jump longer than
/// its own lifetime failing to resume: 372 runs fail that way, against
/// 384 unjumped runs that resume. It does *not* cover the two-slot
/// property — a key
/// opening after it has stopped sealing — and cannot, with one jump. One
/// clock ages the key and the ticket together, so a jump big enough to
/// retire a six-hour key also ages every outstanding ticket past its one
/// hour. Reaching that state needs the key old and the ticket young: two
/// jumps, one before the seal and a smaller one after, landing inside the
/// window where the ticket is still valid and its key no longer seals.
/// Left undone deliberately; `src/tls/Tickets.zig` pins it directly.
fn maybeJumpClock(harness: *Harness) void {
    if (!harness.clock_jump_wanted) return;
    if (harness.clock_jumped) return;
    harness.clock_jumped = true;
    harness.io.advanceWallClock(clock_jump_ns);
}

/// Belt and suspenders: fires even if some client never ends (a
/// black-holed connect, a stuck exchange) and force-ends the run. Its
/// sentence spent a while attached to the wrong function — restored here
/// rather than deleted, because "some client never ends" is exactly the
/// case #206 now creates on purpose.
fn onScenarioEnd(harness: *Harness, result: Io.TimerError!void) void {
    result catch return;
    harness.endScenario();
}

fn endScenario(harness: *Harness) void {
    harness.maybeStrandOps();
    harness.scenario_ended = true;
    for (harness.clients[0..harness.l4_count]) |*client| {
        client.cancelIfStuck();
    }
    for (harness.l7_clients[0..harness.l7_count]) |*client| {
        client.cancelIfStuck();
    }
    for (harness.tls_clients_storage[0..harness.tls_clients_live]) |*client| {
        client.cancelIfStuck();
    }
    harness.server.beginDrain();
    harness.armTeardownStrand();
    harness.origin.stopListening();
    harness.origin_http.stopListening();
}

/// Free what the arena cannot (§4): a `Credentials` owns a libcrypto key
/// object, which is not arena memory, so a sweep that only reset the
/// arena would leak one key per seed — twice over, since every seed runs
/// twice for the determinism check.
pub fn tearDown(harness: *Harness) void {
    for (&harness.tls_credentials) |*slot| {
        if (slot.*) |*credentials| {
            credentials.deinit();
            slot.* = null;
        }
    }
    for (harness.tls_clients_storage[0..harness.tls_clients_live]) |*client| {
        client.deinit();
    }
}

pub fn verify(harness: *Harness) !void {
    // #206: asked *before* the cleanup below, and the order is the whole
    // point. A strand takes harness-side ops too — the doubles and the
    // clients arm recvs of their own — and the tidying closes their
    // sockets, so asking afterwards reads the harness putting its own
    // things away as the server having freed a slot under a live
    // reference. Measured on seed 591: live before the cleanup, stale
    // after, with nothing wrong in between. What the oracle is about is
    // the state the run ended in, not the state the tidying leaves.
    const pending_ops_live = harness.io.pendingOpsReferenceLiveSockets();
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

    if (harness.io.abortedWith()) |code| {
        return harness.verifyGaveUp(code, pending_ops_live);
    }
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
    try harness.verifyStickyCounters();
    try harness.verifyAccessLog();
    for (harness.clients[0..harness.l4_count]) |*client| {
        try client.verifyIntegrity();
    }
    for (harness.l7_clients[0..harness.l7_count]) |*client| {
        try client.verify();
    }
    try harness.verifyTlsSessions();
}

/// What a terminated session owes (§4).
///
/// Prefix-legality holds on every seed: whatever came back must be the
/// start of what went out, so a session that decrypted another's bytes or
/// corrupted its own fails wherever it diverged. Exactness is demanded of
/// the sessions that *said* they were done — the client sends its
/// close_notify only once the whole echo is back, so `close_sent` is its
/// own statement that it got everything, and a client that then holds
/// fewer bytes than it sent is a contradiction.
///
/// A proxied session's responses go through the plaintext population's
/// own oracle (#215), which is the point: the argument for terminating
/// in-process is that TLS is a phase ahead of the protocol and not a
/// protocol of its own — the same render, the same filters, the same
/// stamps — and an unexamined response is exactly what leaves that claim
/// untested. It was untested: the #178 sticky stamp shipped 0.2.0
/// omitting `Secure` on terminated connections and `zig build ci` passed
/// identically either side, because all this asked was that the bytes
/// started with "HTTP/1.1 ".
///
/// Not conditioned on `clean`, deliberately, and that is where this stops
/// short of the plaintext oracle. A TLS session costs several more
/// virtual round trips than a plaintext one, so it can legitimately meet
/// the scenario's end mid-exchange on a seed where every plaintext client
/// finished — that is the schedule being short, not the proxy being
/// wrong, and an oracle demanding the golden *count* would fail honest
/// runs. What is demanded is everything that does not depend on how far
/// the schedule got: every complete response parses, carries an allowed
/// status, a canonical body, the #175 stamp its render owes and the #178
/// stamp its cluster owes, and no surplus response beyond the pair.
///
/// Mutation-checked rather than assumed, both directions:
///
///   - Restoring the pre-#125 stamp — no `Secure` on a terminated
///     connection, with the assert that shipped beside it — fails seeds
///     61, 129, 176, 295 and 501 of the first 512. That is the 0.2.0 bug,
///     and this oracle is what would have caught it.
///   - Taking the response filters back off the tls listener fails ~10%
///     of the first 512 on `ResponseEditMissing`, which is how the
///     listener's own filter chain is held to running at all.
///
/// A violation surfaces under the plaintext oracle's own error name.
/// Which population raised it is not in the name, and does not need to
/// be: the plaintext clients verify first, so an error arriving from here
/// is one their transcripts did not have.
fn verifyTlsSessions(harness: *Harness) !void {
    if (harness.tls_clients == 0) return;
    assert(harness.tls_clients_live <= harness.tls_clients_storage.len);
    var closed_count: u8 = 0;
    for (harness.tls_clients_storage[0..harness.tls_clients_live], 0..) |*client, index| {
        const back = client.app_received[0..client.app_received_len];
        if (harness.tls_protocol == .http) {
            // What this slot drew, and the same pairing rule
            // `startTlsClient` sent it under: a `routed_canonical` script
            // took a follow-up GET, so its transcript is the pair's;
            // anything else sent one request and owes its own script's
            // transcript exactly.
            const drawn = l7.scripts.spec(harness.tls_scripts[index]);
            const entry = if (drawn.routed_canonical)
                l7.scripts.terminating_pair
            else
                drawn;
            // The spec the walk judges by describes what this session was
            // asked to send, so what went out cannot exceed it — the check
            // that catches the two drifting apart, since a wider send
            // would be judged against a transcript that never mentions it.
            assert(client.requestsSent() <= entry.expected_responses);
            const walk = HttpClient.walkResponses(
                back,
                entry,
                .{ .sticky = harness.sticky_http, .terminated = true },
            );
            if (walk.violation) |violation| return violation;
            // #204: never more answers than questions. The framing rule
            // the client ends its exchanges on is what lets it count them
            // at all, and a count that ran ahead of what it asked for
            // would mean the transform delivered a response this session
            // never earned — another connection's, or one duplicated
            // across the head source's turnaround. Sound on every seed,
            // since a short schedule can only leave the count *behind*.
            // Kept beside the walk rather than folded into it: the walk
            // bounds responses by the transcript, this bounds them by
            // what this session actually sent.
            if (client.responsesReceived() > client.requestsSent()) {
                return error.TlsResponseCountDiverged;
            }
            // Response bytes, not `handshake_done`: a client believes it
            // is connected once it has processed the server's flight,
            // which is one step before the server has seen its Finished —
            // so the client's own view can legitimately lead the server's
            // counter. A relayed response cannot.
            if (back.len >= 1) closed_count += 1;
            continue;
        }
        const sent = harness.tls_tokens[index][0..tls_token_bytes];
        if (back.len > sent.len) return error.TlsEchoOverrun;
        if (!std.mem.eql(u8, sent[0..back.len], back)) return error.TlsEchoCorrupted;
        if (client.close_sent) {
            closed_count += 1;
            if (back.len != sent.len) return error.TlsEchoTruncated;
        }
    }
    // A session that closed in protocol necessarily completed its
    // handshake, so the counter cannot read lower than that — which is
    // what catches a run that quietly failed handshakes and still
    // satisfied the byte comparison above on empty echoes.
    if (harness.server.counters.get("tls_handshakes_completed") < closed_count) {
        return error.TlsHandshakesDiverged;
    }
}

/// #178, every seed: the sticky verdicts move only when the cookie
/// cluster was drawn, and then at least once per completed forwarded
/// response — every `l7_responses` increment passed through the render
/// commit that credits exactly one verdict. Not an equality: the credit
/// lands at the render commit and `l7_responses` at the exchange's
/// finish, so an adversary cutting between them legally leaves a
/// credited verdict with no finished response. The exact-bytes demand
/// lives in the client's per-response stamp oracle; this holds the
/// *counters* to the responses they annotate.
fn verifyStickyCounters(harness: *const Harness) !void {
    const counters = &harness.server.counters;
    const total = counters.get("l7_sticky_followed") +
        counters.get("l7_sticky_assigned") +
        counters.get("l7_sticky_repicked");
    if (!harness.sticky_http) {
        if (total != 0) return error.StickyCountersDiverged;
        return;
    }
    if (total < counters.get("l7_responses")) return error.StickyCountersDiverged;
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
        // TLS is a phase ahead of the protocol (§4), so a terminated
        // connection logs what it went on to speak: an `l4` terminator
        // adds L4 lines — live, not drawn, since #204's resumer is a
        // second connection — and an `http` one adds exchanges above.
        const terminated_l4: u8 =
            if (harness.tls_protocol == .l4) harness.tls_clients_live else 0;
        if (tally.l4 != harness.l4_count + terminated_l4) {
            return error.AccessLogL4LinesDiverged;
        }
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
        // A tunnel's line is already explained by `tunnels_established`
        // (#180), so it must not also be counted as an unexplained
        // abort. Its outcome legitimately goes both ways — `closed` when
        // both halves said goodbye, `aborted` when a drain or a peer cut
        // it — because after `101` this connection ends the way an L4
        // relay ends, not the way an exchange does. Never `ok`: only
        // `finishExchange` sets that, and a tunnel never returns there.
        // The status is what identifies it: `101` is the one status no
        // ordinary exchange can carry, since the proxy answers it only
        // for a tunnel that its client provably received.
        if (std.mem.indexOf(u8, line, "\"status\":101") != null) {
            continue;
        }
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
        // The #125 sibling: a terminated connection whose head fit and
        // whose body did not. Answered like the two above, so it belongs
        // in the same sum — added while it is free rather than on the
        // first seed that reaches it.
        "l7_body_too_large",
        "l7_not_implemented",
        "l7_no_route",
        "l7_filtered",
        "l7_redirected",
        "l7_responded",
        "l7_shed_relay_buffers",
        "l7_shed_tunnels",
        // A tunnel is an *answered* exchange like any other here (#180):
        // the client asked for an upgrade and got its `101`. It is the
        // one member that reaches neither `respond` nor `finishExchange`
        // — its line is written at close by the ordinary teardown path —
        // which is why the sum's own description above names two paths
        // and this needs a third. Leaving it out makes the line
        // unexplained, exactly what this identity caught on the first
        // seed to carry one.
        "tunnels_established",
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
    try verifyLoggedHeaders(line, is_http);
}

/// The #140 objects (§9). Every seed names one header each way, so an
/// http line must carry both objects and an l4 line neither — a
/// connection has no head to have read one from. Within them, the only
/// value that may ever appear is the one the scripts and the origin
/// send: a capture that truncated or corrupted fails here under every
/// schedule. A capture that went *stale* does not, since every sender
/// shares one value — the directed tests own that one.
fn verifyLoggedHeaders(line: []const u8, is_http: bool) !void {
    const request_key = "\"request_headers\":";
    const response_key = "\"response_headers\":";
    const has_request = std.mem.indexOf(u8, line, request_key) != null;
    const has_response = std.mem.indexOf(u8, line, response_key) != null;
    if (has_request != is_http) return error.AccessLogHeadersWrongShape;
    if (has_response != is_http) return error.AccessLogHeadersWrongShape;
    if (!is_http) return;
    try verifyLoggedValue(line, l7.canon.log_request_header, l7.canon.log_request_value);
    try verifyLoggedValue(line, l7.canon.log_response_header, l7.canon.log_response_value);
}

/// One logged name carries the canonical value or does not appear.
fn verifyLoggedValue(line: []const u8, name: []const u8, value: []const u8) !void {
    assert(name.len >= 1);
    assert(name.len <= zoxy.constants.access_log_header_name_bytes_max);
    assert(value.len >= 1);
    assert(value.len <= zoxy.constants.access_log_header_bytes_max);
    // Sized from the caps the loader enforces, so this helper stays
    // sound for any name and value a config could legally hold — the
    // `catch unreachable`s below are what rest on that.
    var needle_buffer: [zoxy.constants.access_log_header_name_bytes_max + 4]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buffer, "\"{s}\":", .{name}) catch unreachable;
    const at = std.mem.indexOf(u8, line, needle) orelse return;
    var expected_buffer: [
        zoxy.constants.access_log_header_name_bytes_max +
            zoxy.constants.access_log_header_bytes_max + 8
    ]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &expected_buffer,
        "\"{s}\":\"{s}\"",
        .{ name, value },
    ) catch unreachable;
    if (!std.mem.startsWith(u8, line[at..], expected)) {
        return error.AccessLogHeaderValueWrong;
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
    if (harness.clean) {
        return if (harness.interim_http) .interim_then_sized else .sized;
    }
    if (harness.interim_http) return .interim_then_sized;
    return harness.scenario_prng.random().enumValue(l7.OriginMode);
}
