//! The §9 deterministic-simulation gate: `zig build sim -- [seed]
//! [iterations] [keep-going] | fuzz`. Every seed derives a scenario
//! (sim/Harness.zig) and runs the *real* serving path over SimIo — twice,
//! asserting the two trace hashes are identical, so replayability itself
//! is gated. A failure prints its seed; the same seed replays the exact
//! schedule.

const std = @import("std");

const Harness = @import("Harness.zig");

const assert = std.debug.assert;

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
        checkSeed(arena_state, seed) catch return 1;
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
    while (seed < end) : (seed += 1) {
        checkSeed(arena_state, seed) catch {
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
    if (failed_count == 0) {
        assert(seed == end);
        std.debug.print("sim: {d} seed(s) ok, {d}..{d}\n", .{
            options.iterations,
            options.first_seed,
            end - 1,
        });
        return 0;
    }
    reportFailures(options, failed[0..failed_count], @min(seed, end - 1));
    return 1;
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
