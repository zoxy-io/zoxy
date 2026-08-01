//! The §9 zero-alloc gate: the full serving path — accept, admission,
//! dial, relay, teardown, drain — runs under a counting allocator and
//! the allocation count after `Server.init` must equal the count at the
//! end. A second run under a failing allocator (fail index pinned to
//! the init count) proves the equality is structural: any post-init
//! allocation would error loudly, not just be counted.

const std = @import("std");

const server_test = @import("server_test.zig");

/// Runs the same scenario under `failing` end to end and returns the
/// allocation count observed right after init. The §8 access log renders
/// and writes on the serving path, so it has to be inside this gate
/// rather than beside it: the two staging buffers come out of the
/// startup arena and everything after — the render, the swap, the sink
/// write — must ask for nothing. A log left off here would leave that
/// unproven.
fn runOnce(failing: *std.testing.FailingAllocator) !usize {
    var bed: server_test.TestBed = undefined;
    try bed.setUp(failing.allocator(), .{
        .sim = .{
            .seed = 7,
            .adversary = .{ .partial_io = true, .connect_delay_ns_max = 1_000_000 },
        },
        .access_log = true,
    });
    defer bed.tearDown();

    const allocations_after_init = failing.allocations;
    bed.startClients(2, true);
    try bed.sim_io.run();
    try bed.expectDrained();
    return allocations_after_init;
}

test "zero-alloc gate: the serving path allocates nothing after init" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocations_after_init = try runOnce(&failing);
    try std.testing.expectEqual(allocations_after_init, failing.allocations);

    // Second run: exactly the same scenario, but any allocation past the
    // init count now *fails*. Surviving proves the hot path never asks.
    var strict = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = allocations_after_init,
    });
    _ = try runOnce(&strict);
}
