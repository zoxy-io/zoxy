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

/// The smallest sweep whose census (see `Census`) is believed. Below it a
/// range can miss a rung for want of seeds rather than for want of a
/// path, so a replay — `zig build sim -- <seed> 1` — never fails on
/// coverage.
///
/// Measured, not guessed: 256 seeds cover the whole non-exempt set from
/// every start tried (1, 5k, 100k, 777_777, 31_415_926), while 64 leaves
/// five rungs silent — `l7_uri_too_long`, `upstream_replayed`,
/// `health_parked_closed`, and the recv/send halves of kernel pressure.
/// This is four times the measured floor, and `ci`'s 4096 clears it with
/// the same margin the sweep size itself was chosen for.
const census_iterations_min: u64 = 1024;

/// A counter no scenario can move, and where it is covered instead.
const Uncovered = struct {
    name: []const u8,
    /// Why the sweep cannot reach it, and what reaches it instead.
    /// Printed when the exemption stops being true, so it has to read as
    /// an argument rather than a label.
    reason: []const u8,
};

/// The counters a full sweep provably never moves: a listener the
/// simulator does not configure, a fault it does not inject, a volume it
/// cannot reach. Every entry names the directed test that covers the path
/// instead, because "no seed reaches it" and "nothing tests it" are
/// different claims and only the first one is being made here.
///
/// The gate reads both ways — a counter absent from this table must fire
/// at least once, and a counter present must stay at zero. The second
/// half is what stops the table rotting into stale excuses: widen a
/// scenario until one of these fires and the sweep fails until its entry
/// is deleted.
const uncovered = [_]Uncovered{
    .{
        .name = "l7_headers_too_large",
        .reason = "no script sends a header section past the head buffer; " ++
            "src/http_proxy_test.zig drives both 431 shapes",
    },
    .{
        .name = "l7_no_route",
        .reason = "the sim's route table is a single \"/\" prefix, which no " ++
            "path can miss; src/http_proxy_test.zig covers the path- and " ++
            "host-miss 404s",
    },
    .{
        .name = "l7_shed_upstream_slots",
        .reason = "the only seeds that starve a pool set relay_buffers and " ++
            "upstream_slots both to 1, and the L7 path takes the relay " ++
            "buffer first, so the relay rung answers every request that " ++
            "would have reached this one; src/http_proxy_test.zig " ++
            "exhausts the upstream pool directly",
    },
    .{
        .name = "l7_response_excess_sent",
        .reason = "no seed raises the adversary's recv cap to head_bytes_max, " ++
            "so no origin delivery fills the head buffer; " ++
            "src/http_proxy_test.zig builds that delivery",
    },
    .{
        .name = "kernel_pressure_accept",
        .reason = "the harness never calls injectAcceptError; " ++
            "src/server_test.zig drives the backoff-and-recover path",
    },
    .{
        .name = "kernel_pressure_set_option",
        .reason = "the harness never calls injectSetOptionError; " ++
            "src/server_test.zig and src/http_proxy_test.zig drive both sites",
    },
    .{
        .name = "kernel_pressure_out_of_memory",
        .reason = "the sim classifies every injected failure as out_of_buffers; " ++
            "src/server_test.zig walks the classification arms",
    },
    .{
        .name = "kernel_pressure_fd_limit",
        .reason = "as kernel_pressure_out_of_memory: one cause per sim run",
    },
    .{
        .name = "kernel_pressure_address_unavailable",
        .reason = "as kernel_pressure_out_of_memory: one cause per sim run",
    },
    .{
        .name = "kernel_pressure_other_cause",
        .reason = "as kernel_pressure_out_of_memory: one cause per sim run",
    },
    .{
        .name = "admin_served",
        .reason = "the sweep configures no admin listener; " ++
            "src/admin_test.zig covers the scrape",
    },
    .{
        .name = "admin_reaped",
        .reason = "the sweep configures no admin listener; " ++
            "src/admin_test.zig covers the scrape deadline",
    },
    .{
        .name = "access_log_dropped",
        .reason = "a scenario emits single-digit lines against staging buffers " ++
            "holding ~130, so no schedule can overflow them; " ++
            "src/access_log_test.zig drives the burst",
    },
    .{
        .name = "access_log_write_failed",
        .reason = "the harness never calls injectLogWriteError; " ++
            "src/access_log_test.zig covers the stop-and-witness",
    },
    .{
        .name = "shed_draining",
        .reason = "no seed schedules a terminate signal; " ++
            "src/server_test.zig drives the accept that raced the drain",
    },
    .{
        .name = "drained_at_deadline",
        .reason = "no seed schedules a terminate signal; " ++
            "src/server_test.zig drives the drain deadline",
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

/// The exemption for `name`, or null when the sweep is expected to reach
/// it. Linear over a table of a few dozen entries, run once per counter
/// at the end of a sweep.
fn reasonFor(name: []const u8) ?[]const u8 {
    assert(name.len >= 1);
    for (uncovered) |entry| {
        if (std.mem.eql(u8, name, entry.name)) {
            // An empty reason would print as an exemption that argued
            // nothing — the comptime block rejects one, and this is where
            // that rejection is felt if it ever stops running.
            assert(entry.reason.len >= 1);
            return entry.reason;
        }
    }
    return null;
}

/// What every counter totalled across a swept range, and the coverage
/// verdict those totals carry (§9).
///
/// `reconcile` gates each seed's *shape* — work is never lost, every shed
/// is witnessed — but nothing gated the sweep's *reach*, so a rung could
/// quietly become unreachable and the gate would stay green describing a
/// path no scenario walks. `kernel_pressure_set_option` is the standing
/// example: `SimIo` grew an injector precisely because "64 seeds stayed
/// green because nothing could make the call fail", and no seed has made
/// the call fail since.
const Census = struct {
    totals: [Counters.names.len]u64 = @splat(0),

    fn add(census: *Census, counters: *const Counters) void {
        inline for (Counters.names, 0..) |name, index| {
            const before = census.totals[index];
            census.totals[index] += counters.get(name);
            // A sweep is bounded by `iterations`, so no honest total can
            // wrap — one that did would read as a rung going quiet.
            assert(census.totals[index] >= before);
        }
    }

    /// True when every counter agrees with its side of `uncovered`. Each
    /// disagreement prints what to do about it: a silent rung wants a
    /// scenario that reaches it, a fired exemption wants its entry gone.
    fn verify(census: *const Census) bool {
        var held = true;
        var fired: usize = 0;
        for (Counters.names, census.totals) |name, total| {
            if (total != 0) fired += 1;
            const reason = reasonFor(name);
            if (reason == null and total == 0) {
                std.debug.print(
                    "sim census: {s} never fired — no scenario reaches it; " ++
                        "widen one, or exempt it and say what covers it instead\n",
                    .{name},
                );
                held = false;
            }
            if (reason != null and total != 0) {
                std.debug.print(
                    "sim census: {s} fired {d} time(s) but is exempt as \"{s}\" — " ++
                        "the exemption is no longer true, so delete it\n",
                    .{ name, total, reason.? },
                );
                held = false;
            }
        }
        assert(fired <= Counters.names.len);
        // The verdict restated as a partition: holding means the set that
        // fired is exactly the complement of the exemption table — not
        // merely that no single name was caught on the wrong side.
        if (held) assert(fired == Counters.names.len - uncovered.len);
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
    if (!census.verify()) return false;
    std.debug.print("sim: census ok, {d} counter(s) fired, {d} exempt\n", .{
        Counters.names.len - uncovered.len,
        uncovered.len,
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
    harness.startClients();
    harness.io.run() catch |err| {
        // Deadlock is precisely what this gate exists to catch.
        return err;
    };
    try harness.verify();
    // After `verify`, so a seed that failed its own oracles never counts
    // toward coverage: a rung is only reached by a run that held.
    if (census) |totals| totals.add(&harness.server.counters);
    return harness.io.trace_hash;
}
