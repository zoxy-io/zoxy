//! The §9 deterministic-simulation gate: `zig build sim -- [seed]
//! [iterations] [keep-going] | fuzz`. Every seed derives a scenario
//! (sim/Harness.zig) and runs the *real* serving path over SimIo — twice,
//! asserting the two trace hashes are identical, so replayability itself
//! is gated. A failure prints its seed; the same seed replays the exact
//! schedule.

const std = @import("std");

const zoxy = @import("zoxy");

const Harness = @import("Harness.zig");
const l7 = @import("l7.zig");

const assert = std.debug.assert;

const Counters = zoxy.counters.Counters;
const SimIo = zoxy.Io.SimIo;

/// The seed `checkSeed` is currently running, for the panic handler
/// below and the hang watchdog. A global because that is what a panic
/// handler can read: by the time one runs, every frame that knew the seed
/// is gone. Atomic because the watchdog reads it from its own task.
var running_seed = std.atomic.Value(u64).init(0);

/// Seeds `checkSeed` has finished, passing or failing: the watchdog's
/// evidence that the sweep is moving.
var seeds_finished = std.atomic.Value(u64).init(0);

/// The sweep's failing seeds, kept where the watchdog can read them too,
/// so a sweep that hangs after failures still names every one. Each
/// entry is stored before the count that publishes it.
var failed_seeds: [failures_max]std.atomic.Value(u64) = @splat(.init(0));
var failed_count = std.atomic.Value(u8).init(0);

/// Name the seed on the way down (#253).
///
/// An oracle failure returns an error and `checkSeed` prints the seed it
/// belongs to. An *assert* does neither: the process aborts inside
/// `io.run()`, and what reaches the operator is a stack trace with no
/// seed in it — which is how a nightly soak came to report a panic it
/// could not reproduce, and why finding the schedule that caused one
/// meant bisecting a million-seed shard by hand. §9's whole claim is
/// that a failure replays from its seed; a failure that cannot name one
/// is outside it.
pub const panic = std.debug.FullPanic(panicWithSeed);

fn panicWithSeed(message: []const u8, first_trace_address: ?usize) noreturn {
    // Printed before the default handler runs, so it survives however the
    // trace itself is truncated. A zero here is not a seed but an answer:
    // the panic happened outside any run — during setup, the census, or
    // the failure report — and no schedule replays it.
    const seed = running_seed.load(.acquire);
    std.debug.print("sim: PANIC seed={d} — replay with: zig build sim -- {d} 1\n", .{ seed, seed });
    std.debug.defaultPanic(message, first_trace_address);
}

const default_seed: u64 = 1;
/// What `zig build sim` (and so `ci`) sweeps. Sized by census, not by
/// feel: at 64 the gate left three scripts — `post_chunked_malformed`,
/// `oversize_uri`, `filter_edit` — with no *clean* seed at all, so
/// their golden-outcome oracles never ran, and the §7 "silent teardown
/// instead of 400" shape had no seed demanding its 400. Every script
/// draws a clean seed by ~1024; 4096 keeps that true with margin as
/// the script table grows, and costs ~5 s (each seed runs twice for the
/// determinism check).
const default_iterations: u64 = 4096;
const progress_interval: u64 = 500;
/// How often a sweep says how far it got: a soak shard is hundreds of
/// thousands of seeds, and a sweep that printed only its verdict could
/// not be told apart from a hung one until the runner cancelled it
/// (run #140). Above `default_iterations`, so `ci` prints none.
const sweep_progress_interval: u64 = 50_000;
/// The wall-clock time one seed may take before the watchdog calls the
/// sweep hung. A seed takes ~4 ms in Debug; what this catches is a seed
/// that never ends — a spin inside one callback, or ops forever ready at
/// a frozen virtual clock — which neither the deadlock check nor the
/// virtual-time alarm can see.
const seed_wall_ns_max: u64 = 60 * std.time.ns_per_s;
/// How often the watchdog looks.
const watchdog_poll_ns: u64 = std.time.ns_per_s;
/// The most failing seeds one `keep-going` sweep names before it stops.
/// Bounded so a systematically broken build prints a census rather than a
/// line per seed; the sweep reports the range it actually reached, so a
/// run that hits this cap never reads as having cleared the remainder.
const failures_max: u8 = 16;

/// Minimum number of seeds required to check the coverage census.
/// Shorter sweeps still check each seed's oracles and replay determinism.
///
/// On adec501, 1024-seed sweeps from #364 missed `h2_shed_streams`,
/// `shed_tls_engines` or `l7_sticky_followed`. Every required counter
/// fired in 36 sweeps of 4096 seeds, including all five reported starts.
/// Per sweep, `shed_tls_engines` fired in 3–20 seeds, `h2_shed_streams`
/// in 4–20, `l7_shed_tunnels` in 4–20, and `upstream_replayed` in 5–20.
/// The other counters named in #364, `l7_shed_head_buffers` and
/// `l7_body_cut_mid_stream`, fired in 11–26 and 37–59 seeds respectively.
const census_iterations_min: u64 = 4096;

comptime {
    assert(default_iterations >= census_iterations_min);
}

/// A counter the sweep expects to stay at (or under) zero, and why.
const Uncovered = struct {
    name: []const u8,
    why: Why,
    /// The argument itself: what reaches the counter instead, or what a
    /// non-zero reading would mean. Printed when the entry's claim stops
    /// holding, so it has to read as an argument rather than a label.
    reason: []const u8,
    /// How often this may fire and still hold. Almost every entry says
    /// `.never`, and that is the whole table's usual claim.
    ///
    /// The exception is an alarm for a regression that would fire
    /// *constantly*, guarding an event that is legal and vanishingly
    /// rare. There the honest claim is a rate, not zero: "never" was
    /// only ever true at the sweep sizes we had run, and a nightly soak
    /// large enough to see the rare event would fail on the legal case
    /// while the regression it guards against is orders of magnitude
    /// louder. Scaling the allowance with the sweep is what keeps the
    /// two apart at every size.
    allowance: Allowance = .never,

    /// The two reasons an entry is here. They look identical to the gate
    /// — both are bounded by their allowance — and want opposite things
    /// from whoever the gate wakes, so the remedy is printed from this
    /// rather than assumed.
    const Why = enum {
        /// No scenario reaches it. A non-zero reading is good news: some
        /// scenario grew, and the entry has outlived its argument.
        unreached,
        /// It can be reached and must not be, past its allowance. A
        /// reading over that is a bug report, and deleting the entry
        /// would be deleting the alarm.
        must_stay_zero,
    };

    const Allowance = union(enum) {
        never,
        /// At most one per this many seeds, plus one — so a small sweep
        /// tolerates a single occurrence of a rare legal event and a
        /// large one scales with its own size, rather than the gate
        /// becoming stricter the longer it runs.
        at_most_one_per: u64,

        fn limit(allowance: Allowance, iterations: u64) u64 {
            return switch (allowance) {
                .never => 0,
                .at_most_one_per => |per| blk: {
                    assert(per >= 1);
                    break :blk 1 + iterations / per;
                },
            };
        }
    };

    /// What to tell the reader when this entry's counter fires past its
    /// allowance.
    fn remedy(entry: *const Uncovered) []const u8 {
        return switch (entry.why) {
            .unreached => "a scenario now reaches it, so delete this entry",
            .must_stay_zero => "this is the alarm, not a coverage note — " ++
                "the invariant broke, so fix the code rather than the table",
        };
    }
};

/// The counters a full sweep never moves. Most are unreachable: a
/// listener the simulator does not configure, a fault it does not
/// inject, a volume it cannot reach — and each names the directed test
/// that covers the path instead, because "no seed reaches it" and
/// "nothing tests it" are different claims and only the first is made
/// here.
///
/// A few are here for the opposite reason: they *can* fire and must not,
/// so a reading of zero is the invariant rather than an admission. `why`
/// says which an entry is, and the gate prints the matching remedy —
/// telling someone to delete the entry when the alarm they just tripped
/// *is* the entry would be the worst advice the tool could give.
///
/// The gate reads both ways — a counter absent from this table must fire
/// at least once, and a counter present must stay at zero — which is what
/// serves both kinds at once, and what stops the table rotting into stale
/// excuses.
const uncovered = [_]Uncovered{
    // #449's HTTP/3 rungs the sweep's conforming clients cannot reach.
    .{
        .name = "h3_protocol_errors",
        .why = .must_stay_zero,
        .reason = "the sweep's HTTP/3 clients conform and the datagram adversary's corruption " ++
            "fails the AEAD, so a protocol error here is the server misreading a stream — " ++
            "as it was when a stream its own read had answered was read again as a new request",
    },
    .{
        .name = "h3_shed_tls_crypto",
        .why = .unreached,
        .reason = "shed_tls_crypto's reason, at the QUIC rung: libcrypto refusing a key " ++
            "derivation needs the fixed heap exhausted, which no scenario reaches",
    },
    .{
        .name = "h3_segments_refused",
        .why = .unreached,
        .reason = "the simulated kernel segments as Linux does; a refusal needs a device " ++
            "without checksum offload, which no scenario models",
    },
    .{
        .name = "h3_qpack_failures",
        .why = .unreached,
        .reason = "the sweep's clients encode with h3's own QPACK; src/http/h3/server_test.zig " ++
            "sends a section that does not decode",
    },
    .{
        .name = "h3_malformed_requests",
        .why = .unreached,
        .reason = "the sweep's clients send well-formed fields; src/http/h3/server_test.zig " ++
            "sends an uppercase field name",
    },
    .{
        .name = "h3_events_overflowed",
        .why = .unreached,
        .reason = "h3 sizes a connection's event queue past what one datagram's packets can " ++
            "raise, and a pass polls it after every datagram; the rung exists so a queue that " ++
            "did overflow is read again rather than lost",
    },
    .{
        .name = "h3_version_negotiations",
        .why = .must_stay_zero,
        // A rate, not zero, and the soak is what proved it: "never" held
        // at 4096 seeds and failed in run #143, 2 to 7 times per 500,000
        // seeds a shard. One per 20,000 leaves several times that as
        // headroom, and still sits orders of magnitude under a regression
        // that answered the sweep's own v1 Initials, which would fire on
        // nearly every seed with an HTTP/3 client.
        .allowance = .{ .at_most_one_per = 20_000 },
        .reason = "the sweep's clients speak QUIC v1; only the adversary corrupting a " ++
            "datagram's version field, with the datagram still 1200 octets, reaches it, " ++
            "and src/http/h3/server_test.zig sends one on purpose",
    },
    // #481's resolver. A quarter of seeds' L4 cluster follows a name its
    // scripted nameservers answer, each by a drawn behaviour under the
    // datagram adversary, so every outcome of a query is reached; what is
    // left is the one only a later round meets.
    .{
        .name = "dns_updates_refused",
        .why = .unreached,
        .reason = "reachable, and unreached in the range: the sweep's nameservers answer a set no " ++
            "cluster can take (none at all) from 150 ms on, so only a seed whose second round, " ++
            "past the 100 ms refresh floor, meets an answering nameserver refuses one, and none " ++
            "of seeds 1..4096 does; src/dns/resolver_test.zig refuses one",
    },
    // §7 HTTP/2 to the origin (#275). A third of seeds' http cluster
    // speaks it, h2c or over TLS, to `TestOrigin` answering the canonical
    // sized 200, so the pool dials, idles and fails to dial under the
    // adversary. What that origin never does is misbehave at the HTTP/2
    // layer, and these are the counters only that reaches; the leg's
    // refusals run under `SimIo` in `src/http_proxy_test.zig`'s `h2 origin:`
    // scenarios, and `client_session_test.zig` drives the session's client
    // role frame by frame.
    .{
        .name = "h2_origin_streams_reset",
        .why = .unreached,
        .reason = "the sweep's HTTP/2 origin answers every stream it is sent; " ++
            "client_session_test covers the reset and GOAWAY refusals",
    },
    .{
        .name = "h2_origin_refused_heads",
        .why = .unreached,
        .reason = "the sweep's HTTP/2 origin answers a canonical head; " ++
            "origin.zig's tests and fuzz cover the refused mappings",
    },
    .{
        .name = "h2_origin_refused_answers",
        .why = .unreached,
        .reason = "the sweep's HTTP/2 origin answers a canonical answer; " ++
            "origin.zig's tests and fuzz cover the refused answers",
    },
    .{
        .name = "h2_origin_tls_failed",
        .why = .unreached,
        .reason = "the sweep's HTTP/2 origin serves the chain its cluster trusts, and the " ++
            "adversary never corrupts a byte; OriginClient's tests and the h2 origin TLS " ++
            "scenarios refuse chains",
    },
    .{
        .name = "health_probes_skipped",
        .why = .unreached,
        .reason = "the sweep's HTTP/2 clusters have one endpoint, since only a retry budget adds a " ++
            "second and HTTP/2 takes none, and their gRPC probe rides that endpoint's connection or " ++
            "dials one in the room the loader's default pool leaves, two per endpoint; " ++
            "http_proxy_test's grpc probe scenarios fill the pool",
    },
    .{
        .name = "upstream_tls_failed",
        .why = .must_stay_zero,
        // A rate: twice in seeds 1..65536 and never in the gate's range.
        // One per 10k sits at three times that and orders of magnitude
        // under a regression, which would fail most HTTPS seeds' dials.
        .allowance = .{ .at_most_one_per = 10_000 },
        .reason = "the sweep's HTTPS origin (#296) serves the chain its cluster trusts, and the " ++
            "TCP adversary never corrupts a byte, so the one failure left is a hangup " ++
            "mid-handshake, which its resets reach about once per 30k seeds; the https " ++
            "origin scenarios refuse a misnamed chain",
    },
    .{
        .name = "l7_shed_upstream_tls",
        .why = .unreached,
        .reason = "the sweep's HTTPS cluster holds as many sessions as upstream slots, so the " ++
            "slot rung answers first; http_proxy_test's https origin scenarios starve the pool",
    },
    .{
        .name = "l7_shed_h2_origin_connections",
        .why = .unreached,
        .reason = "the sweep's HTTP/2 clusters have one endpoint and the loader's two " ++
            "connections for it, which multiplex every request the upstream slots admit; " ++
            "http_proxy_test's h2 origin scenarios starve the pool",
    },
    .{
        .name = "l7_shed_h2_origin_streams",
        .why = .unreached,
        .reason = "the stream pool is the upstream slots' size, as the loader's default is, " ++
            "so the slot rung answers first; http_proxy_test's h2 origin scenarios starve it",
    },
    .{
        .name = "health_probe_deadline_raced",
        .why = .must_stay_zero,
        // Legal and vanishingly rare, so the claim is a rate: the
        // nightly soak saw it once in a million seeds (run
        // 30789778589), where "never" had held for every 4096-seed
        // sweep before it. One per 100k leaves ten times the observed
        // rate as headroom and still sits five orders of magnitude
        // under the regression, which fires more than once per seed.
        .allowance = .{ .at_most_one_per = 100_000 },
        .reason = "the §4 race it counts — a probe deadline firing after its " ++
            "own cancel was issued — is legal and vanishingly rare (once in " ++
            "a million seeds), while a prober that stopped cancelling at all " ++
            "reports every verdict correctly and moves only this. That is " ++
            "#130 exactly. Measured: 1 per million with the fix, 4760 per " ++
            "4096 seeds with it reverted",
    },
    .{
        .name = "l7_headers_too_large",
        .why = .unreached,
        .reason = "no script sends a header section past the head buffer; " ++
            "src/http_proxy_test.zig drives both 431 shapes",
    },
    // The §4 counters (#125) the sweep still cannot move. Seeds do
    // terminate TLS now — a quarter of them bind a terminating listener,
    // l4 or http, and run real handshakes under the adversary — so what
    // is left here is not "no scenario configures one" but a handful of
    // specific events a seeded, non-corrupting schedule of
    // single-connection clients cannot produce. Each names what reaches
    // it instead.
    .{
        .name = "tls_handshake_failed",
        .why = .must_stay_zero,
        // A rate, not zero — and the nightly is what proved it. "Never"
        // held for every 4096-seed sweep and failed on the first soak
        // that ran a million (run 31457966341, ~530 per shard). Measured
        // again locally at 36 in 60k, and both causes are the harness
        // rather than the proxy: 33 of those 36 were scenarios the 2 s
        // virtual cap force-ended, whose `endScenario` cancels every
        // client — including one mid-handshake, whose socket then closes
        // under a server still reading. The other 3 were the adversary
        // failing the *client's* send, which ends that client the same
        // way. Both are exactly what the counter says on the tin: a peer
        // that hung up mid-handshake never became a session.
        //
        // One per 750 seeds leaves better than twice the observed rate
        // as headroom while staying orders of magnitude under any real
        // regression — a handshake path that broke would fail a large
        // fraction of the quarter of seeds that terminate, not one in
        // seventeen hundred.
        .allowance = .{ .at_most_one_per = 750 },
        .reason = "the adversary reorders, splits and delays but never " ++
            "corrupts, and a dial it refuses or black-holes never reaches a " ++
            "handshake at all — so what remains is a peer that leaves " ++
            "mid-flight: a scenario force-ended at its 2 s cap with a " ++
            "handshake still in the air, or a client whose own send the " ++
            "adversary failed. Both are the harness ending a session the " ++
            "proxy was serving correctly. A slot whose signature offer no " ++
            "certificate its name reaches can sign under (#411) is owed its " ++
            "failure by the draw, and is not held against the allowance. " ++
            "A reading past the allowance is " ++
            "not that: it is handshakes failing on their own account, which " ++
            "is a bug report. src/server_test.zig sends plaintext at a TLS " ++
            "port, which is the shape a misdirected client or a scanner " ++
            "actually produces",
    },
    .{
        .name = "shed_tls_crypto",
        .why = .unreached,
        .reason = "libcrypto refusing a key derivation needs the fixed heap " ++
            "exhausted, which no scenario can reach and no directed test " ++
            "fakes — the rung exists so that failure is not read as the " ++
            "engine pool's, and is expected to stay at zero in production too",
    },
    .{
        .name = "l7_body_too_large",
        .why = .unreached,
        .reason = "only a terminated connection can overrun its head buffer " ++
            "— one record decrypts to up to 16 KiB at once, where a plaintext " ++
            "read cannot deliver more than the buffer holds — and the seeds " ++
            "that do terminate send a token far under it; " ++
            "src/http_proxy_test.zig drives it with a small head and an " ++
            "oversize body in one record, against a listener whose head " ++
            "limit sits below the engine's own decrypt floor",
    },
    .{
        .name = "tls_relay_failed",
        .why = .unreached,
        .reason = "seeds do terminate TLS now, but an established session " ++
            "fails mid-relay only for a peer corrupting records or a far " ++
            "side too slow to drain the outbox. The adversary reorders and " ++
            "splits deliveries but never alters a byte, so no schedule it " ++
            "can produce reaches this — and no directed test drives it " ++
            "either, which is the honest gap",
    },
    .{
        .name = "l7_no_route",
        .why = .unreached,
        .reason = "the sim's route table is a single \"/\" prefix, which no " ++
            "path can miss; src/http_proxy_test.zig covers the path- and " ++
            "host-miss 404s",
    },
    .{
        .name = "l7_policy_edit_refused",
        .why = .unreached,
        .reason = "the harness's policies edit with a fixed, valid header, " ++
            "which zoxy never refuses; src/http_proxy_test.zig edits a " ++
            "header zoxy writes itself, and splits one with CRLF",
    },
    .{
        .name = "l7_policy_consult_refused",
        .why = .unreached,
        .reason = "the harness's consulting policy fails open, so no consult " ++
            "of the sweep's refuses (#437); src/http_proxy_test.zig fails one closed",
    },
    .{
        .name = "l7_policy_consult_oversize",
        .why = .unreached,
        .reason = "the harness's consulting policy asks one fixed question, " ++
            "within its bound (#437); src/http_proxy_test.zig sends one past it",
    },
    .{
        .name = "endpoints_parked_closed",
        .why = .unreached,
        .reason = "while the sim's churn departs only the refusing endpoint, " ++
            "nothing it departs has parked (#428); the close is the " ++
            "ejection's own loop (`reapParkedOf`), which health_parked_closed covers",
    },
    .{
        .name = "l7_handler_answer_refused",
        .why = .unreached,
        .reason = "the harness's handler answers within its contract (#434); " ++
            "http_proxy_test holds a misbehaving handler to a 502",
    },
    .{
        .name = "health_probe_request_oversize",
        .why = .unreached,
        .reason = "the harness's check kind sends short, fixed requests " ++
            "(#436); server_test sends one past the bound",
    },
    .{
        .name = "l7_response_policy_edit_refused",
        .why = .unreached,
        .reason = "the harness's response policy adds a fixed, valid " ++
            "header, which zoxy never refuses; src/http_proxy_test.zig " ++
            "edits a framing header on the way out",
    },
    .{
        .name = "l7_policy_route_fallback",
        .why = .unreached,
        .reason = "the harness's listener policy routes only by a name " ++
            "the listener's table carries, resolved at bind, so every " ++
            "choice names a route the table has; src/http_proxy_test.zig chooses one the " ++
            "listener lacks, and one at the route phase",
    },
    .{
        .name = "shed_h2_sessions",
        .why = .unreached,
        .reason = "the simulator's terminating listener offers http/1.1 alone, and only " ++
            "a listener offering h2 alone sheds at accept; " ++
            "src/http_proxy_test.zig drives one directly",
    },
    .{
        .name = "tunnels_drained",
        .why = .unreached,
        .reason = "structural rather than a gap in ambition: the production " ++
            "bound is `tunnel_drain_ms` (5 s) and a whole scenario is 2 s of " ++
            "virtual time, so no schedule this sweep can produce reaches it. " ++
            "Seeds do establish tunnels and do drain with them live — the " ++
            "tunnel dies with its client rather than at the bound. " ++
            "src/http_proxy_test.zig drains a live tunnel under a zero " ++
            "drain_deadline_ms directly, and asserts the loop reached idle",
    },
    .{
        .name = "l7_shed_upstream_head_buffers",
        .why = .unreached,
        .reason = "same shadow as l7_shed_upstream_slots: the relay rung " ++
            "answers first on every pool-starved seed, and reaching this " ++
            "one besides needs two concurrent renders, which upstream_slots " ++
            "= 1 rules out; src/http_proxy_test.zig exhausts the upstream " ++
            "head pool directly",
    },
    .{
        .name = "l7_response_excess_sent",
        .why = .unreached,
        .reason = "no seed raises the adversary's recv cap to head_buffer_bytes_default, " ++
            "so no origin delivery fills the head buffer; " ++
            "src/http_proxy_test.zig builds that delivery, and the Tier-0.5 " ++
            "live gate counts it against a real one",
    },
    .{
        .name = "admin_reaped",
        .why = .unreached,
        .reason = "structural, as tunnels_drained: the scrape deadline " ++
            "(`admin_scrape_deadline_ms`, 5 s) outlasts a whole 2 s scenario, " ++
            "and the scenario's drain tears a held scrape down first. " ++
            "src/admin_test.zig covers the scrape deadline",
    },
    .{
        .name = "access_log_dropped",
        .why = .unreached,
        .reason = "a scenario emits single-digit lines against staging buffers " ++
            "holding ~130, so no schedule can overflow them; " ++
            "src/access_log_test.zig drives the burst",
    },
    .{
        .name = "access_log_write_failed",
        .why = .unreached,
        .reason = "the harness never calls injectLogWriteError; " ++
            "src/access_log_test.zig covers the stop-and-witness",
    },
    .{
        .name = "access_log_reopened",
        .why = .unreached,
        .reason = "the sweep's sink is stdout and no script injects SIGHUP; " ++
            "src/access_log_test.zig drives the rotation swap",
    },
    .{
        .name = "access_log_reopen_failed",
        .why = .unreached,
        .reason = "same as access_log_reopened, plus injectLogReopenError " ++
            "is a directed-test control; src/access_log_test.zig covers " ++
            "the keep-the-old-sink arm",
    },
};

comptime {
    // Every exemption is compared against every counter name, so the
    // default quota runs out at this table's size.
    @setEvalBranchQuota(uncovered.len * Counters.names.len * 32);
    // A census over an empty set would pass by saying nothing, and a
    // table that exempted everything would do the same.
    assert(Counters.names.len >= 1);
    assert(uncovered.len < Counters.names.len);
    // An entry naming a counter that does not exist would exempt nothing
    // while reading as though it exempted something, and a duplicate
    // would let one deletion leave the other behind.
    for (uncovered, 0..) |entry, index| {
        var found = false;
        for (Counters.names) |name| {
            if (std.mem.eql(u8, name, entry.name)) found = true;
        }
        if (!found) {
            @compileError("uncovered names a counter that does not exist: " ++ entry.name);
        }
        // The reason is the whole point of the entry: it is what the
        // sweep prints when the exemption stops being true, and a blank
        // one exempts a rung while saying nothing about what covers it.
        if (entry.reason.len == 0) {
            @compileError("uncovered gives no reason for " ++ entry.name);
        }
        for (uncovered[index + 1 ..]) |later| {
            if (std.mem.eql(u8, entry.name, later.name)) {
                @compileError("uncovered names " ++ entry.name ++ " twice");
            }
        }
    }
}

/// The §4 seam ops no scenario delivers, on the same both-ways terms as
/// `uncovered`. Empty since the admin scrapers (§8) reached the one
/// asynchronous close in the tree; an op added to the seam that no
/// scenario delivers is entered here with what covers it instead.
const uncovered_ops = [_]struct { kind: SimIo.OpKind, reason: []const u8 }{};

comptime {
    // The twin of `uncovered`'s validation: an entry naming `.none`
    // exempts an op that is never delivered by construction, a duplicate
    // lets one deletion leave the other behind, and a blank reason
    // exempts a slice of the seam while saying nothing about it.
    for (uncovered_ops, 0..) |entry, index| {
        if (entry.kind == .none) @compileError("uncovered_ops names the .none op");
        if (entry.reason.len == 0) {
            @compileError("uncovered_ops gives no reason for " ++ @tagName(entry.kind));
        }
        for (uncovered_ops[index + 1 ..]) |later| {
            if (entry.kind == later.kind) {
                @compileError("uncovered_ops names " ++ @tagName(entry.kind) ++ " twice");
            }
        }
    }
    // `.none` is not a deliverable op, so it is never counted as covered.
    assert(uncovered_ops.len < std.enums.values(SimIo.OpKind).len - 1);
}

fn opReasonFor(kind: SimIo.OpKind) ?[]const u8 {
    assert(kind != .none);
    for (uncovered_ops) |entry| {
        if (entry.kind == kind) {
            assert(entry.reason.len >= 1);
            return entry.reason;
        }
    }
    return null;
}

/// The entry for `name`, or null when the sweep is expected to reach it.
/// Linear over a table of a few dozen entries, run once per counter at
/// the end of a sweep.
fn entryFor(name: []const u8) ?*const Uncovered {
    assert(name.len >= 1);
    for (&uncovered) |*entry| {
        if (std.mem.eql(u8, name, entry.name)) {
            // An empty reason would print as an exemption that argued
            // nothing — the comptime block rejects one, and this is where
            // that rejection is felt if it ever stops running.
            assert(entry.reason.len >= 1);
            return entry;
        }
    }
    return null;
}

/// The sweep's metered extension counters (#435), one entry each: the
/// type, the name, and the series the endpoint renders it as.
const ExtensionMetrics = @FieldType(Harness, "server").ExtensionMetrics;
const ExtensionCounter = struct {
    Family: type,
    name: []const u8,
    series: []const u8,
};
const extension_counters: []const ExtensionCounter = blk: {
    var collected: []const ExtensionCounter = &.{};
    for (ExtensionMetrics.metered_types) |Family| {
        const Name = zoxy.extension.CounterName(Family);
        for (@typeInfo(Name).@"enum".field_names) |name| {
            collected = collected ++ [_]ExtensionCounter{.{
                .Family = Family,
                .name = name,
                .series = zoxy.extension.metric_prefix ++ Family.metrics_prefix ++ "_" ++ name,
            }};
        }
    }
    break :blk collected;
};

/// What every counter totalled across a swept range, and the coverage
/// verdict those totals carry (§9).
///
/// `reconcile` gates each seed's *shape* — work is never lost, every shed
/// is witnessed — but nothing gated the sweep's *reach*, so a rung could
/// quietly become unreachable and the gate would stay green describing a
/// path no scenario walks. `kernel_pressure_set_option` was the standing
/// example: `SimIo` grew an injector precisely because "64 seeds stayed
/// green because nothing could make the call fail", and then no seed
/// called the injector for as long as it existed. The census is what
/// said so out loud; the harness now draws that fault, and the entry
/// this table used to carry for it is gone.
const Census = struct {
    totals: [Counters.names.len]u64 = @splat(0),
    /// The same question asked of the §4 seam rather than the §8 ladder:
    /// which *ops* the sweep ever delivered. A counter says a decision was
    /// taken; an op says the ring carried the work. They fail
    /// independently — `close` is delivered by exactly one call site in
    /// the tree, so no counter's silence would have named it.
    ops: [std.enums.values(SimIo.OpKind).len]u64 = @splat(0),
    /// The scripted extensions' own counters (#435), summed over sites:
    /// the metered calls asked whether they ever counted. A counter no
    /// seed moves is a metered path the sweep never walks.
    extension_totals: [extension_counters.len]u64 = @splat(0),
    /// Marked request bodies (#373) the origin checked and found whole:
    /// the one oracle that reads HTTP/2 request bodies, asked whether it
    /// ever ran. No counter says so, since a body that arrives whole is
    /// the proxy doing nothing a rung would count.
    bodies_verified: u64 = 0,
    /// Response heads the harness's response policy read (#424): it
    /// declares no counters, so the census asks it directly whether the
    /// response phase ever ran.
    responses_policed: u64 = 0,
    /// Seeds on which a build's check kind (#436) carried a probe past
    /// its first round: the multi-round path, reached.
    probes_past_first_round: u64 = 0,
    /// Trailer sections (§7) a client heard whole, by population: the
    /// HTTP/1.1 relay, and HTTP/2's and HTTP/3's trailing HEADERS. No
    /// counter says a trailer went through, so the census asks the
    /// clients whose oracles judged one.
    trailers_heard: [Population.count]u64 = @splat(0),
    /// Requests that ended with a trailer section and were answered, by
    /// population: HTTP/1.1's are the sections an origin read exactly as
    /// their head owed them (its relay, reached); HTTP/2's and HTTP/3's
    /// are streams answered whole after their trailers, which the origin's
    /// oracle held to arriving without them (§7).
    request_trailers: [Population.count]u64 = @splat(0),
    /// Origin connections whose #142 header announced an IPv6 client:
    /// the inbound TCP6 and INET6 parse and the proxy's TCP6 and INET6
    /// writers, reached. No counter tells an address's family apart.
    upstream_ip6_announced: u64 = 0,
    /// Forwarded-for chains (§7) an origin read ending in an IPv6 client,
    /// exactly as `bareAddress` writes one.
    forwarded_ip6_verified: u64 = 0,
    /// Handshakes shown each of a #297 listener's certificates — the
    /// default, the P-384 one, the second P-256 one — by the name asked.
    certificates_shown: [Harness.sni_choices_count]u64 = @splat(0),
    /// Requests an origin received carrying a verified client's
    /// fingerprint (#304): mutual TLS, end to end.
    client_certs_forwarded: u64 = 0,
    /// gRPC calls an HTTP/2 client heard answered at their deadline (§8),
    /// Trailers-Only with `grpc-status: 4`.
    grpc_deadlines_heard: u64 = 0,
    /// HTTP/2 clients whose throttled stream the server filled to the
    /// window and no further (RFC 9113 §6.9), and those that lowered their
    /// HPACK table and heard the encoder's resize (RFC 7541 §4.2).
    h2_windows_met: u64 = 0,
    h2_table_resizes: u64 = 0,
    /// Streams answered whole over HTTP/2 on a terminating TLS listener
    /// (#271): what proves the sweep drives `h2` over TLS at all.
    h2_tls_streams: u64 = 0,
    /// Each RFC 9113 violation's owed answer heard (`H2Mode.violations`).
    h2_violations_answered: [l7.H2Mode.violations.len]u64 = @splat(0),
    /// gRPC health calls an HTTP/2 origin answered (§7): SERVING, then
    /// NOT_SERVING.
    grpc_health_answered: [2]u64 = @splat(0),

    const Population = enum(u8) {
        http1,
        http2,
        http3,

        const count = std.enums.values(Population).len;
    };

    fn add(census: *Census, harness: *const Harness) void {
        inline for (Counters.names, 0..) |name, index| {
            const before = census.totals[index];
            const counted = harness.server.counters.get(name);
            // #411: a slot whose offer no certificate could sign under is
            // owed its failed handshake, by the harness's own draw — held
            // against the allowance below only past what was owed.
            const excused = if (comptime std.mem.eql(u8, name, "tls_handshake_failed"))
                @min(counted, harness.tls_scheme_refusals)
            else
                0;
            census.totals[index] += counted - excused;
            // A sweep is bounded by `iterations`, so no honest total can
            // wrap — one that did would read as a rung going quiet.
            assert(census.totals[index] >= before);
        }
        for (std.enums.values(SimIo.OpKind)) |kind| {
            if (kind == .none) continue;
            const before = census.ops[@backingInt(kind)];
            census.ops[@backingInt(kind)] += harness.io.deliveredCount(kind);
            // As the counter loop above: a wrap would read as an op going
            // quiet, which is the one thing this table exists to notice.
            assert(census.ops[@backingInt(kind)] >= before);
        }
        // Each counter names its family's enum at comptime: the quota
        // grows with the list rather than with a guess.
        @setEvalBranchQuota(1000 * (extension_counters.len + 1));
        inline for (extension_counters, &census.extension_totals) |counter, *total| {
            const before = total.*;
            const name = @field(zoxy.extension.CounterName(counter.Family), counter.name);
            total.* += harness.server.extension_metrics.counterTotal(counter.Family, name);
            assert(total.* >= before);
        }
        if (harness.probe_l4.furthest_round >= 1) census.probes_past_first_round += 1;
        const policed_before = census.responses_policed;
        census.responses_policed += harness.response_policy.evaluated;
        assert(census.responses_policed >= policed_before);
        const bodies_before = census.bodies_verified;
        census.bodies_verified += harness.origin_http.bodies_verified;
        assert(census.bodies_verified >= bodies_before);
        census.addTrailers(harness);
        const ip6_before = census.upstream_ip6_announced;
        for (harness.origin.conns[0..harness.origin.conns_count]) |*conn| {
            if (!conn.header_done) continue;
            const announced = conn.announced orelse continue;
            if (announced == .ip6) census.upstream_ip6_announced += 1;
        }
        assert(census.upstream_ip6_announced >= ip6_before);
        census.client_certs_forwarded += harness.origin_http.client_certs_verified;
        if (harness.tls_sni) {
            for (&census.certificates_shown, harness.tls_choices_shown) |*total, shown| total.* += shown;
        }
        const forwarded_before = census.forwarded_ip6_verified;
        census.forwarded_ip6_verified += harness.origin_http.forwarded_ip6_verified;
        assert(census.forwarded_ip6_verified >= forwarded_before);
    }

    /// Some origin must hear an IPv6 client announced (#142): every other
    /// address in the sweep is IPv4, so without one the TCP6 and INET6
    /// forms are written by no seed.
    fn verifyIp6(census: *const Census) bool {
        var held = true;
        if (census.upstream_ip6_announced == 0) {
            std.debug.print("sim census: no origin heard an IPv6 client announced in this sweep\n", .{});
            held = false;
        }
        if (census.forwarded_ip6_verified == 0) {
            std.debug.print("sim census: no origin read a forwarded-for chain ending in an IPv6 client\n", .{});
            held = false;
        }
        assert(held == (census.upstream_ip6_announced >= 1 and census.forwarded_ip6_verified >= 1));
        return held;
    }

    /// Every certificate of a #297 listener must be chosen by a name
    /// somewhere in the range: one no name reaches is a choice
    /// `certificate_set.select` never made under the adversary.
    fn verifyCertificates(census: *const Census) bool {
        for (census.certificates_shown, 0..) |shown, choice| {
            if (shown >= 1) continue;
            std.debug.print("sim census: no handshake was shown certificate {d} of a #297 listener\n", .{choice});
            return false;
        }
        assert(std.mem.min(u64, &census.certificates_shown) >= 1);
        if (census.client_certs_forwarded == 0) {
            std.debug.print("sim census: no origin received a verified client's fingerprint (#304)\n", .{});
            return false;
        }
        if (census.grpc_deadlines_heard == 0) {
            std.debug.print("sim census: no gRPC call was answered at its deadline (§8)\n", .{});
            return false;
        }
        if (census.h2_windows_met == 0) {
            std.debug.print("sim census: no HTTP/2 server send stopped at a client's window\n", .{});
            return false;
        }
        if (census.h2_table_resizes == 0) {
            std.debug.print("sim census: no HTTP/2 client heard its HPACK table resized\n", .{});
            return false;
        }
        for (census.h2_violations_answered, l7.H2Mode.violations) |answered, mode| {
            if (answered >= 1) continue;
            std.debug.print("sim census: no HTTP/2 client's {t} was answered as RFC 9113 owes\n", .{mode});
            return false;
        }
        if (census.h2_tls_streams == 0) {
            std.debug.print("sim census: no stream was answered over HTTP/2 on a TLS listener (#271)\n", .{});
            return false;
        }
        for (census.grpc_health_answered, [_][]const u8{ "SERVING", "NOT_SERVING" }) |answered, said| {
            if (answered >= 1) continue;
            std.debug.print("sim census: no HTTP/2 origin answered a gRPC health call {s} (§7)\n", .{said});
            return false;
        }
        return true;
    }

    /// Run only on a seed whose `verify` passed, as every tally here is:
    /// a client's count is of sections its oracle has already judged.
    fn addTrailers(census: *Census, harness: *const Harness) void {
        // A seed whose drain gave up is judged by its backstop alone, never
        // by its clients' oracles, so nothing they heard is counted here:
        // every count below is of what an oracle has already judged.
        if (harness.io.abortedWith() != null) return;
        const before = census.trailers_heard;
        for (harness.l7_clients[0..harness.l7_count]) |*client| {
            census.trailers_heard[@backingInt(Population.http1)] += client.trailersHeard();
        }
        for (harness.h2_clients[0..harness.h2_count]) |*client| {
            census.trailers_heard[@backingInt(Population.http2)] += client.trailersHeard();
        }
        for (harness.h3_clients[0..harness.h3_count]) |*client| {
            census.trailers_heard[@backingInt(Population.http3)] += client.trailersHeard();
        }
        for (before, census.trailers_heard) |earlier, now| assert(now >= earlier);
        const requests_before = census.request_trailers;
        census.request_trailers[@backingInt(Population.http1)] += harness.origin_http.trailers_verified;
        for (harness.h2_clients[0..harness.h2_count]) |*client| {
            census.request_trailers[@backingInt(Population.http2)] += client.requestTrailersAnswered();
        }
        for (harness.h3_clients[0..harness.h3_count]) |*client| {
            census.request_trailers[@backingInt(Population.http3)] += client.requestTrailersAnswered();
        }
        for (harness.h2_clients[0..harness.h2_count]) |*client| {
            census.grpc_deadlines_heard += client.grpcDeadlinesHeard();
            if (client.violationAnswered()) |mode| {
                const index = std.mem.indexOfScalar(l7.H2Mode, &l7.H2Mode.violations, mode).?;
                census.h2_violations_answered[index] += 1;
            }
            const tuning = client.tuningHeard();
            census.h2_windows_met += @intFromBool(tuning.window_met);
            census.h2_table_resizes += @intFromBool(tuning.resized);
        }
        for (requests_before, census.request_trailers) |earlier, now| assert(now >= earlier);
        census.h2_tls_streams += harness.tls_h2_streams;
        if (harness.grpc_health) |*answer| {
            const index: usize = if (Harness.grpcHealthServing(answer)) 0 else 1;
            census.grpc_health_answered[index] += harness.h2_origin.health_answered;
        }
    }

    /// Every population must hear a trailer section somewhere in the
    /// range: each relays it by a different path (§7), and a path no seed
    /// walks is one the clients' trailer oracles never judged.
    fn verifyTrailers(census: *const Census) bool {
        var held = true;
        for (std.enums.values(Population), census.trailers_heard) |population, heard| {
            if (heard >= 1) continue;
            std.debug.print(
                "sim census: no {s} client heard a trailer section in this sweep; " ++
                    "the trailing origin (`chunked_trailers`) never answered one\n",
                .{@tagName(population)},
            );
            held = false;
        }
        for (std.enums.values(Population), census.request_trailers) |population, answered| {
            if (answered >= 1) continue;
            std.debug.print(
                "sim census: no {s} request trailer section was judged in this sweep " ++
                    "(http1: read by an origin as owed; http2, http3: answered after one)\n",
                .{@tagName(population)},
            );
            held = false;
        }
        assert(held == (std.mem.min(u64, &census.trailers_heard) >= 1 and
            std.mem.min(u64, &census.request_trailers) >= 1));
        return held;
    }

    /// True when every counter agrees with its side of `uncovered`. Each
    /// disagreement prints what to do about it, which is not the same
    /// sentence twice: a silent rung wants a scenario that reaches it, and
    /// a fired entry wants either its deletion or a bug fixed, depending
    /// on which kind of entry it was (`Uncovered.remedy`).
    fn verify(census: *const Census, iterations: u64) bool {
        assert(iterations >= census_iterations_min);
        var held = true;
        var fired: usize = 0;
        // Exempt entries that fired *within* their allowance — the rare
        // legal ones. Counted so the partition below stays exact
        // instead of being loosened to an inequality.
        var allowed_fired: usize = 0;
        for (Counters.names, census.totals) |name, total| {
            if (total != 0) fired += 1;
            const entry = entryFor(name);
            if (entry == null and total == 0) {
                std.debug.print(
                    "sim census: {s} never fired in this sweep. " ++
                        "Widen a scenario or exempt it and say what covers it instead\n",
                    .{name},
                );
                held = false;
            }
            if (entry) |exempt| {
                const limit = exempt.allowance.limit(iterations);
                if (total > limit) {
                    std.debug.print(
                        "sim census: {s} fired {d} time(s) against an allowance " ++
                            "of {d}, and should not have.\n  why: {s}\n  do: {s}\n",
                        .{ name, total, limit, exempt.reason, exempt.remedy() },
                    );
                    held = false;
                }
                if (total != 0 and total <= limit) {
                    allowed_fired += 1;
                }
            }
        }
        assert(fired <= Counters.names.len);
        assert(allowed_fired <= uncovered.len);
        // The verdict restated as a partition: holding means the set that
        // fired is exactly the complement of the exemption table — plus
        // whichever exempt entries fired inside their allowance, which
        // is the one way a name can honestly be on both sides.
        if (held) {
            assert(fired == Counters.names.len - uncovered.len + allowed_fired);
        }
        const ops_held = census.verifyOps();
        const extensions_held = census.verifyExtensionCounters() and census.verifyResponsePolicy() and
            census.verifyProbeRounds();
        const trailers_held = census.verifyTrailers();
        const ip6_held = census.verifyIp6();
        const certificates_held = census.verifyCertificates();
        return census.verifyBodies() and ops_held and extensions_held and trailers_held and ip6_held and certificates_held and held;
    }

    /// Every counter the scripted extensions declare moved somewhere in
    /// the range — the census a build can hold its own counters to.
    /// `past_end` rides on the picker's draws — a quarter of seeds for the
    /// l4 cluster, half for the http one; a range of `census_iterations_min` seeds carries
    /// thousands of those picks, and a given range always draws the same.
    fn verifyExtensionCounters(census: *const Census) bool {
        var held = true;
        inline for (extension_counters, census.extension_totals) |counter, total| {
            if (total == 0) {
                std.debug.print(
                    "sim census: {s} never fired in this sweep; widen a scenario that reaches it\n",
                    .{counter.series},
                );
                held = false;
            }
        }
        return held;
    }

    /// A check kind's probe reached a second round somewhere in the range
    /// (#436).
    fn verifyProbeRounds(census: *const Census) bool {
        if (census.probes_past_first_round >= 1) return true;
        std.debug.print("sim census: no check-kind probe reached a second round in this sweep\n", .{});
        return false;
    }

    /// The response phase ran somewhere in the range (#424).
    fn verifyResponsePolicy(census: *const Census) bool {
        if (census.responses_policed >= 1) return true;
        std.debug.print("sim census: no response head met the response policy in this sweep\n", .{});
        return false;
    }

    /// Some marked body must reach its origin whole in the range: an
    /// origin that never checks one leaves HTTP/2's request bodies
    /// unread by any oracle, whatever else passes.
    fn verifyBodies(census: *const Census) bool {
        if (census.bodies_verified >= 1) return true;
        std.debug.print(
            "sim census: no marked request body reached its origin whole — " ++
                "the HTTP/2 clients' POSTs went unchecked; widen `drawH2Plan`\n",
            .{},
        );
        assert(census.bodies_verified == 0);
        return false;
    }

    /// Every op of the §4 seam must be delivered somewhere in the range.
    /// An op no seed ever carries is a slice of the seam the gate has
    /// never run, whatever its counters say.
    fn verifyOps(census: *const Census) bool {
        var held = true;
        var carried: usize = 0;
        for (std.enums.values(SimIo.OpKind)) |kind| {
            if (kind == .none) continue;
            const delivered = census.ops[@backingInt(kind)];
            if (delivered != 0) carried += 1;
            const reason = opReasonFor(kind);
            if (reason == null and delivered == 0) {
                std.debug.print(
                    "sim census: op {t} never delivered — the seam carried it " ++
                        "no work; widen a scenario, or exempt it and say what does\n",
                    .{kind},
                );
                held = false;
            }
            if (reason != null and delivered != 0) {
                std.debug.print(
                    "sim census: op {t} was delivered {d} time(s) but is exempt " ++
                        "as \"{s}\" — the exemption is no longer true, so delete it\n",
                    .{ kind, delivered, reason.? },
                );
                held = false;
            }
        }
        assert(carried < std.enums.values(SimIo.OpKind).len);
        // The same partition `verify` states for counters: holding means
        // the ops the seam carried are exactly the deliverable set minus
        // the exemptions, not merely that no one op landed wrongly.
        if (held) {
            assert(carried == std.enums.values(SimIo.OpKind).len - 1 - uncovered_ops.len);
        }
        return held;
    }
};

/// One swept range, and whether a failure ends it.
const Sweep = struct {
    first_seed: u64,
    iterations: u64,
    /// Name every failing seed in the range (up to `failures_max`)
    /// instead of stopping at the first. The nightly soak wants the
    /// census: stopping first means a night's evidence is the one seed
    /// the sweep happened to reach, and because the soak's ranges are
    /// keyed to its run number, the abandoned remainder is never
    /// revisited. `ci` wants the opposite — the first failure, fast — so
    /// this is opt-in.
    keep_going: bool,
};

pub fn main(init: std.process.Init) !u8 {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();

    const fuzz = arguments.len == 2 and std.mem.eql(u8, arguments[1], "fuzz");
    const options: ?Sweep = if (fuzz) null else try parseSweep(arguments);
    // Cancelled by the defer on every exit; it only ever reads.
    var watchdog: std.Io.Group = .init;
    try watchdog.concurrent(init.io, watchdogTask, .{ init.io, if (options) |*range| range else null });
    defer watchdog.cancel(init.io);
    if (options) |*range| return sweep(&arena_state, range, init.io);
    return fuzzForever(&arena_state, init.io);
}

/// A sweep that stops moving is named, not left to a runner's timeout: no
/// seed finished for `seed_wall_ns_max` means the running one never will.
/// The verdict is printed in the lines a sweep's own report uses — the
/// failing seeds with the hung one last, and the range verified before it
/// — so the soak's record names the seed, and the process exits. A null
/// range is `fuzz`, whose random seeds have no range to report.
fn watchdogTask(io: std.Io, range: ?*const Sweep) void {
    if (range) |options| assert(options.iterations >= 1);
    // A stall is judged at the poll's granularity, so it must be finer.
    assert(watchdog_poll_ns < seed_wall_ns_max);
    var finished_seen = seeds_finished.load(.acquire);
    var moved_at = std.Io.Timestamp.now(io, .awake);
    while (true) {
        io.sleep(std.Io.Duration.fromNanoseconds(watchdog_poll_ns), .awake) catch |err| {
            // The sweep ended and cancelled this task: every ordinary exit.
            assert(err == error.Canceled);
            return;
        };
        const finished = seeds_finished.load(.acquire);
        if (finished != finished_seen) {
            finished_seen = finished;
            moved_at = std.Io.Timestamp.now(io, .awake);
            continue;
        }
        const stalled_ns = moved_at.untilNow(io, .awake).toNanoseconds();
        if (stalled_ns < seed_wall_ns_max) continue;
        const seed = running_seed.load(.acquire);
        // Between seeds is not a hang: the census or the report is running.
        if (seed == 0) continue;
        // A seed that ended between the two loads was not hung after all;
        // unmoved, the count is exactly the seeds before this one.
        if (seeds_finished.load(.acquire) != finished) continue;
        reportHang(range, seed, finished);
        std.process.exit(1);
    }
}

fn reportHang(range: ?*const Sweep, seed: u64, finished: u64) void {
    assert(seed != 0);
    std.debug.print(
        "sim: HUNG seed={d}: no seed finished in {d} s — replay with: zig build sim -- {d} 1\n",
        .{ seed, seed_wall_ns_max / std.time.ns_per_s, seed },
    );
    const options = range orelse return;
    assert(seed >= options.first_seed);
    const count = failed_count.load(.acquire);
    assert(count < failures_max);
    std.debug.print("sim: {d} seed(s) failed:", .{count + 1});
    for (failed_seeds[0..count]) |*failed| std.debug.print(" {d}", .{failed.load(.monotonic)});
    std.debug.print(" {d}\n", .{seed});
    // Seeds run in order, so every one below the hung seed finished; a
    // hang on the first leaves nothing verified, and says no range.
    assert(finished == seed - options.first_seed);
    if (seed == options.first_seed) return;
    std.debug.print("sim: swept {d}..{d} of {d}..{d}, then hung\n", .{
        options.first_seed,
        seed - 1,
        options.first_seed,
        options.first_seed + options.iterations - 1,
    });
}

/// Random seeds until something breaks: the unbounded companion to the
/// soak's contiguous blocks, for a developer watching one change.
fn fuzzForever(arena_state: *std.heap.ArenaAllocator, io: std.Io) !u8 {
    var count: u64 = 0;
    while (true) : (count += 1) {
        var seed_bytes: [8]u8 = undefined;
        io.random(&seed_bytes);
        const seed = std.mem.readInt(u64, &seed_bytes, .little);
        // Zero is "between seeds" to the watchdog and the panic handler.
        if (seed == 0) continue;
        // No census: a random walk has no range to make a claim about.
        checkSeed(arena_state, seed, null) catch return 1;
        if (count % progress_interval == 0) {
            std.debug.print("sim fuzz: {d} seeds ok, latest {d}\n", .{ count + 1, seed });
        }
    }
}

fn parseSweep(arguments: []const []const u8) !Sweep {
    // argv[0] is the program name; the sweep's arguments follow it.
    assert(arguments.len >= 1);
    var parsed: Sweep = .{
        .first_seed = default_seed,
        .iterations = default_iterations,
        .keep_going = false,
    };
    var positional: u8 = 0;
    for (arguments[1..]) |argument| {
        if (std.mem.eql(u8, argument, "keep-going")) {
            parsed.keep_going = true;
            continue;
        }
        positional += 1;
        switch (positional) {
            1 => parsed.first_seed = try std.fmt.parseUnsigned(u64, argument, 10),
            2 => parsed.iterations = try std.fmt.parseUnsigned(u64, argument, 10),
            else => return error.TooManyArguments,
        }
    }
    if (parsed.iterations == 0) return error.NoIterations;
    // Zero is "between seeds" to the watchdog and the panic handler, and
    // a range must not run past the last seed a u64 names.
    if (parsed.first_seed == 0) return error.SeedZero;
    if (parsed.iterations > std.math.maxInt(u64) - parsed.first_seed) return error.RangeOverflows;
    assert(parsed.iterations >= 1);
    assert(positional <= 2);
    return parsed;
}

/// Sweeps the range and returns the process exit code. Every seed is
/// independent — a fresh `Harness` over a reset arena — so continuing
/// past a failure cannot contaminate the seeds after it.
///
/// This only rescues the *returned* failures: a broken invariant inside
/// the serving path is a `std.debug.assert`, which panics the process
/// whatever this flag says.
fn sweep(arena_state: *std.heap.ArenaAllocator, options: *const Sweep, io: std.Io) !u8 {
    assert(options.iterations >= 1);
    assert(failed_count.load(.monotonic) == 0);
    const end = options.first_seed + options.iterations;
    var seed = options.first_seed;
    var census: Census = .{};
    const began = std.Io.Timestamp.now(io, .awake);
    while (seed < end) : (seed += 1) {
        checkSeed(arena_state, seed, &census) catch {
            const count = failed_count.load(.monotonic);
            assert(count < failures_max);
            failed_seeds[count].store(seed, .monotonic);
            failed_count.store(count + 1, .release);
            if (!options.keep_going or count + 1 == failures_max) break;
        };
        const done = seed - options.first_seed + 1;
        if (done % sweep_progress_interval == 0) reportProgress(options, seed, began, io);
    }
    const count = failed_count.load(.monotonic);
    if (count != 0) {
        var failed: [failures_max]u64 = undefined;
        for (failed_seeds[0..count], failed[0..count]) |*stored, *copy| copy.* = stored.load(.monotonic);
        reportFailures(options, failed[0..count], @min(seed, end - 1));
        return 1;
    }
    assert(seed == end);
    if (!checkCensus(options, &census)) {
        std.debug.print("sim: {d} seed(s) ran, {d}..{d}, census FAILED\n", .{
            options.iterations,
            options.first_seed,
            end - 1,
        });
        return 1;
    }
    std.debug.print("sim: {d} seed(s) ok, {d}..{d}\n", .{
        options.iterations,
        options.first_seed,
        end - 1,
    });
    return 0;
}

/// One line of how far a long sweep got, and how fast: the rate is what
/// tells a slow shard from a hung one before its runner's cap does.
fn reportProgress(options: *const Sweep, seed: u64, began: std.Io.Timestamp, io: std.Io) void {
    assert(seed >= options.first_seed);
    const done = seed - options.first_seed + 1;
    assert(done <= options.iterations);
    const elapsed_ms: u64 = @intCast(@max(1, @divFloor(began.untilNow(io, .awake).toNanoseconds(), std.time.ns_per_ms)));
    std.debug.print("sim: progress {d}/{d} seed(s), at {d}, {d} s, {d} seed(s)/s\n", .{
        done,
        options.iterations,
        seed,
        elapsed_ms / std.time.ms_per_s,
        done * std.time.ms_per_s / elapsed_ms,
    });
}

/// The coverage census over a completed range, and its verdict on stdout.
/// False means the census failed. Only ranges that swept clean reach
/// here — a sweep that stopped early has nothing to say about the rungs
/// its abandoned remainder was carrying.
///
/// A range too short to trust says so rather than passing quietly. That
/// line is the difference between "coverage held" and "coverage was not
/// asked", which a replay would otherwise report identically.
fn checkCensus(options: *const Sweep, census: *const Census) bool {
    assert(options.iterations >= 1);
    if (options.iterations < census_iterations_min) {
        std.debug.print("sim: census skipped, a range of {d} is under the {d} seeds it needs\n", .{
            options.iterations,
            census_iterations_min,
        });
        return true;
    }
    if (!census.verify(options.iterations)) return false;
    std.debug.print("sim: census ok, {d} counter(s) fired, {d} exempt; {d} extension counter(s) fired; {d} seam op(s), {d} exempt; {d} body(ies) verified; trailers heard {d}/{d}/{d}, sent {d}/{d}/{d} (http1/2/3); IPv6 clients {d} announced upstream, {d} forwarded; HTTP/2 windows met {d}, table resizes heard {d}; HTTP/2 over TLS streams {d}\n", .{
        Counters.names.len - uncovered.len,
        uncovered.len,
        extension_counters.len,
        std.enums.values(SimIo.OpKind).len - 1 - uncovered_ops.len,
        uncovered_ops.len,
        census.bodies_verified,
        census.trailers_heard[@backingInt(Census.Population.http1)],
        census.trailers_heard[@backingInt(Census.Population.http2)],
        census.trailers_heard[@backingInt(Census.Population.http3)],
        census.request_trailers[@backingInt(Census.Population.http1)],
        census.request_trailers[@backingInt(Census.Population.http2)],
        census.request_trailers[@backingInt(Census.Population.http3)],
        census.upstream_ip6_announced,
        census.forwarded_ip6_verified,
        census.h2_windows_met,
        census.h2_table_resizes,
        census.h2_tls_streams,
    });
    return true;
}

/// Names every failing seed, then the range actually covered: a sweep
/// that stopped early proves nothing about the seeds past it, and saying
/// so is the difference between a census and a false all-clear.
fn reportFailures(options: *const Sweep, failed: []const u64, swept_last: u64) void {
    assert(failed.len >= 1);
    assert(failed.len <= failures_max);
    assert(swept_last >= options.first_seed);
    const last = options.first_seed + options.iterations - 1;
    std.debug.print("sim: {d} seed(s) failed:", .{failed.len});
    for (failed) |seed| std.debug.print(" {d}", .{seed});
    std.debug.print("\nsim: swept {d}..{d} of {d}..{d}{s}\n", .{
        options.first_seed,
        swept_last,
        options.first_seed,
        last,
        if (failed.len == failures_max) " (failure cap reached)" else "",
    });
}

/// One seed, run twice: the second run must produce a byte-identical
/// delivery trace or determinism itself is broken. Only the first run
/// feeds the census — the replay would double every total, and a census
/// is a claim about what one pass over the range reached.
fn checkSeed(arena_state: *std.heap.ArenaAllocator, seed: u64, census: ?*Census) !void {
    // Zero is the watchdog's and the panic handler's "between seeds".
    assert(seed != 0);
    running_seed.store(seed, .release);
    // Cleared on the way out, so the seed the handler prints is only ever
    // one a run was *inside*. A panic does not run this — which is the
    // point — but the census and the failure report that follow the sweep
    // do, and a panic in either would otherwise name the last seed swept
    // as though its schedule were the cause.
    defer {
        running_seed.store(0, .release);
        _ = seeds_finished.fetchAdd(1, .release);
    }
    const first = runSeed(arena_state, seed, census) catch |err| {
        std.debug.print("sim: FAILURE seed={d} error={t}\n", .{ seed, err });
        return err;
    };
    const second = runSeed(arena_state, seed, null) catch |err| {
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

fn runSeed(arena_state: *std.heap.ArenaAllocator, seed: u64, census: ?*Census) !u64 {
    _ = arena_state.reset(.retain_capacity);
    const arena = arena_state.allocator();

    var harness: Harness = undefined;
    try harness.setUp(arena, seed);
    // Not everything a scenario holds is arena memory: §4's credentials
    // own a libcrypto key, which resetting the arena would leak — once
    // per seed, twice over for the determinism check.
    defer harness.tearDown();
    harness.startClients();
    harness.io.run() catch |err| {
        // Deadlock is precisely what this gate exists to catch.
        return err;
    };
    try harness.verify();
    // After `verify`, so a seed that failed its own oracles never counts
    // toward coverage: a rung is only reached by a run that held.
    if (census) |totals| totals.add(&harness);
    return harness.io.trace_hash;
}
