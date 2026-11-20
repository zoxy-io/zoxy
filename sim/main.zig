//! The §9 deterministic-simulation gate: `zig build sim -- [seed]
//! [iterations] [keep-going] | fuzz`. Every seed derives a scenario
//! (sim/Harness.zig) and runs the *real* serving path over SimIo — twice,
//! asserting the two trace hashes are identical, so replayability itself
//! is gated. A failure prints its seed; the same seed replays the exact
//! schedule.

const std = @import("std");

const zoxy = @import("zoxy");

const Harness = @import("Harness.zig");

const assert = std.debug.assert;

const Counters = zoxy.counters.Counters;
const SimIo = zoxy.Io.SimIo;

/// The seed `checkSeed` is currently running, for the panic handler
/// below. A plain global because that is what a panic handler can read:
/// by the time one runs, every frame that knew the seed is gone.
var running_seed: u64 = 0;

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
    std.debug.print("sim: PANIC seed={d} — replay with: zig build sim -- {d} 1\n", .{
        running_seed,
        running_seed,
    });
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
    // §7 HTTP/2 to the origin. The sweep's origins speak HTTP/1.1 — the
    // byte-exact integrity oracle reads their wire — and no cluster it
    // builds is h2c, so nothing here dials an HTTP/2 origin. The leg and
    // the connection run under `SimIo` in `src/http_proxy_test.zig`'s
    // `h2 origin:` scenarios, against `TestOrigin` (a `Session` on the
    // server role), partial-io seeds included; `client_session_test.zig`
    // drives the session's client role frame by frame.
    .{
        .name = "h2_origin_connections",
        .why = .unreached,
        .reason = "no h2c cluster in the sweep; http_proxy_test's h2 origin scenarios dial one",
    },
    .{
        .name = "h2_origin_connect_failed",
        .why = .unreached,
        .reason = "no h2c cluster in the sweep; the h2 origin 502 scenario dials one nothing listens on",
    },
    .{
        .name = "h2_origin_idle_closed",
        .why = .unreached,
        .reason = "no h2c cluster in the sweep; an idle origin connection is ended by the drain first",
    },
    .{
        .name = "h2_origin_streams_reset",
        .why = .unreached,
        .reason = "no h2c cluster in the sweep; client_session_test covers the reset and GOAWAY refusals",
    },
    .{
        .name = "h2_origin_refused_heads",
        .why = .unreached,
        .reason = "no h2c cluster in the sweep; origin.zig's tests and fuzz cover the refused mappings",
    },
    .{
        .name = "h2_origin_refused_answers",
        .why = .unreached,
        .reason = "no h2c cluster in the sweep; origin.zig's tests and fuzz cover the refused answers",
    },
    .{
        .name = "h2_origin_tls_failed",
        .why = .unreached,
        .reason = "no h2 cluster in the sweep; OriginClient's tests and the h2 origin TLS scenarios refuse chains",
    },
    .{
        .name = "l7_grpc_deadline_exceeded",
        .why = .unreached,
        .reason = "the sweep's clients send no gRPC call; http_proxy_test's grpc deadline scenarios run one out",
    },
    .{
        .name = "health_probes_skipped",
        .why = .unreached,
        .reason = "no h2c cluster in the sweep, so no grpc check; http_proxy_test's grpc probe scenarios fill the pool",
    },
    .{
        .name = "upstream_tls_handshakes",
        .why = .unreached,
        .reason = "no HTTPS cluster in the sweep; http_proxy_test's https origin scenarios handshake",
    },
    .{
        .name = "upstream_tls_failed",
        .why = .unreached,
        .reason = "no HTTPS cluster in the sweep; the https origin scenarios refuse a misnamed chain",
    },
    .{
        .name = "l7_shed_upstream_tls",
        .why = .unreached,
        .reason = "no HTTPS cluster in the sweep, so no session pool to run dry",
    },
    .{
        .name = "l7_shed_h2_origin_connections",
        .why = .unreached,
        .reason = "no h2c cluster in the sweep, so neither origin pool exists to run dry",
    },
    .{
        .name = "l7_shed_h2_origin_streams",
        .why = .unreached,
        .reason = "no h2c cluster in the sweep, so neither origin pool exists to run dry",
    },
    // §6 SNI routing (#298). The sweep's l4 population opens with a
    // scripted prefix its oracle asserts is *never* relayed — the shape
    // a PROXY header has — and a ClientHello is the opposite: it is the
    // client's payload and the backend must receive every byte. Teaching
    // that client a second, relayed-prefix mode would fork the integrity
    // oracle these scenarios exist for, which is a worse trade than
    // covering four verdicts where the whole decision is already
    // reachable in one place.
    //
    // `src/server_test.zig` covers all four against `SimIo` — the same
    // virtual sockets, the same adversary, partial-io seeds included, so
    // the accumulate-and-retry loop is exercised rather than the
    // one-recv path — and its origin double parses the relayed hello to
    // prove the backend still receives what the client sent.
    .{
        .name = "l4_sni_routed",
        .why = .unreached,
        .reason = "the sweep's l4 client scripts prefixes its oracle expects " ++
            "to be stripped, and a ClientHello is relayed; " ++
            "src/server_test.zig's four sni-routing scenarios cover the " ++
            "verdicts against the same SimIo, under partial io",
    },
    .{
        .name = "l4_sni_absent",
        .why = .unreached,
        .reason = "same as l4_sni_routed — covered by src/server_test.zig " ++
            "\"a hello naming nothing takes the any-name route\"",
    },
    .{
        .name = "l4_sni_no_route",
        .why = .unreached,
        .reason = "same as l4_sni_routed — covered by src/server_test.zig " ++
            "\"a name no route claims is closed, not guessed\"",
    },
    .{
        .name = "l4_sni_invalid",
        .why = .unreached,
        .reason = "same as l4_sni_routed — covered by src/server_test.zig " ++
            "\"opening bytes that are not a hello are refused\"",
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
            "proxy was serving correctly. A reading past the allowance is " ++
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
        .name = "tls_rsa_signed",
        .why = .unreached,
        .reason = "the sweep's listeners sign ECDSA under RFC 6979 nonces so a " ++
            "seed replays byte-exact, and RSA-PSS draws a fresh salt per " ++
            "signature — zssl refuses an RSA key that was asked for " ++
            "deterministic signing (#411). engine_test drives RSA handshakes " ++
            "and the choice between key types; the smoke gate's RSA leg " ++
            "reads this counter off the shipped binary",
    },
    .{
        .name = "tls_client_cert_refused",
        .why = .unreached,
        .reason = "no listener in the sweep asks for a client certificate " ++
            "(#304); engine_test drives every refusal — none presented " ++
            "where one is required, a chain to another CA — and " ++
            "server_test counts one end to end through the transport",
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
        .name = "l7_shed_upstream_slots",
        .why = .unreached,
        .reason = "the only seeds that starve a pool set relay_buffers and " ++
            "upstream_slots both to 1, and the L7 path takes the relay " ++
            "buffer first, so the relay rung answers every request that " ++
            "would have reached this one. That shadow needs the starved " ++
            "seeds to stay single-endpoint, which is why the #181 retry " ++
            "draw suppresses its second endpoint on them: one slot parked " ++
            "on endpoint 0 cannot serve a request picking endpoint 1, and " ++
            "the resulting shed is legal but reaches this rung (seed 4316 " ++
            "of 4097..20480, before `deriveRetries` accounted for it); " ++
            "src/http_proxy_test.zig exhausts the upstream pool directly",
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
        .name = "admin_served",
        .why = .unreached,
        .reason = "the sweep configures no admin listener; " ++
            "src/admin_test.zig covers the scrape, and the Tier-0.5 live " ++
            "gate reads its counters through one",
    },
    .{
        .name = "admin_reaped",
        .why = .unreached,
        .reason = "the sweep configures no admin listener; " ++
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
/// `uncovered`. One entry today, and it is a finding rather than a
/// footnote: the whole asynchronous close path is unreached by 4096
/// seeds.
const uncovered_ops = [_]struct { kind: SimIo.OpKind, reason: []const u8 }{
    .{
        .kind = .close,
        .reason = "src/admin.zig is the only asynchronous close in the tree — " ++
            "every serving path closes synchronously via closeNow — and the " ++
            "sweep configures no admin listener; src/admin_test.zig covers it, " ++
            "and the Tier-0.5 live gate delivers real ones through its scrapes",
    },
};

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

    fn add(census: *Census, harness: *const Harness) void {
        inline for (Counters.names, 0..) |name, index| {
            const before = census.totals[index];
            census.totals[index] += harness.server.counters.get(name);
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
        return census.verifyBodies() and ops_held and extensions_held and held;
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

    if (arguments.len == 2 and std.mem.eql(u8, arguments[1], "fuzz")) {
        return fuzzForever(&arena_state, init.io);
    }
    const options = try parseSweep(arguments);
    return sweep(&arena_state, &options);
}

/// Random seeds until something breaks: the unbounded companion to the
/// soak's contiguous blocks, for a developer watching one change.
fn fuzzForever(arena_state: *std.heap.ArenaAllocator, io: std.Io) !u8 {
    var count: u64 = 0;
    while (true) : (count += 1) {
        var seed_bytes: [8]u8 = undefined;
        io.random(&seed_bytes);
        const seed = std.mem.readInt(u64, &seed_bytes, .little);
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
fn sweep(arena_state: *std.heap.ArenaAllocator, options: *const Sweep) !u8 {
    assert(options.iterations >= 1);
    const end = options.first_seed + options.iterations;
    var failed: [failures_max]u64 = @splat(0);
    var failed_count: u8 = 0;
    var seed = options.first_seed;
    var census: Census = .{};
    while (seed < end) : (seed += 1) {
        checkSeed(arena_state, seed, &census) catch {
            assert(failed_count < failures_max);
            failed[failed_count] = seed;
            failed_count += 1;
            if (options.keep_going) {
                if (failed_count == failures_max) break;
            } else {
                break;
            }
        };
    }
    if (failed_count != 0) {
        reportFailures(options, failed[0..failed_count], @min(seed, end - 1));
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
    std.debug.print("sim: census ok, {d} counter(s) fired, {d} exempt; {d} extension counter(s) fired; {d} seam op(s), {d} exempt; {d} body(ies) verified\n", .{
        Counters.names.len - uncovered.len,
        uncovered.len,
        extension_counters.len,
        std.enums.values(SimIo.OpKind).len - 1 - uncovered_ops.len,
        uncovered_ops.len,
        census.bodies_verified,
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
    running_seed = seed;
    // Cleared on the way out, so the seed the handler prints is only ever
    // one a run was *inside*. A panic does not run this — which is the
    // point — but the census and the failure report that follow the sweep
    // do, and a panic in either would otherwise name the last seed swept
    // as though its schedule were the cause.
    defer running_seed = 0;
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
