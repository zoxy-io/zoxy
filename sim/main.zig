//! The §9 deterministic-simulation gate: `zig build sim -- [seed]
//! [iterations] | fuzz`. Every seed derives a scenario (sim/Harness.zig)
//! and runs the *real* serving path over SimIo — twice, asserting the
//! two trace hashes are identical, so replayability itself is gated. A
//! failure prints its seed; the same seed replays the exact schedule.

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

pub fn main(init: std.process.Init) !u8 {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();

    if (arguments.len == 2 and std.mem.eql(u8, arguments[1], "fuzz")) {
        var count: u64 = 0;
        while (true) : (count += 1) {
            var seed_bytes: [8]u8 = undefined;
            init.io.random(&seed_bytes);
            const seed = std.mem.readInt(u64, &seed_bytes, .little);
            checkSeed(&arena_state, seed) catch return 1;
            if (count % progress_interval == 0) {
                std.debug.print("sim fuzz: {d} seeds ok, latest {d}\n", .{ count + 1, seed });
            }
        }
    }

    const first_seed = if (arguments.len >= 2)
        try std.fmt.parseUnsigned(u64, arguments[1], 10)
    else
        default_seed;
    const iterations = if (arguments.len >= 3)
        try std.fmt.parseUnsigned(u64, arguments[2], 10)
    else
        default_iterations;
    assert(iterations >= 1);

    var seed = first_seed;
    while (seed < first_seed + iterations) : (seed += 1) {
        checkSeed(&arena_state, seed) catch return 1;
    }
    std.debug.print("sim: {d} seed(s) ok, {d}..{d}\n", .{
        iterations,
        first_seed,
        first_seed + iterations - 1,
    });
    return 0;
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
