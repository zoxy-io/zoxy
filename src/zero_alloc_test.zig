//! The §9 zero-alloc gate: the full serving path — accept, admission,
//! dial, relay, teardown, drain — runs under a counting allocator and
//! the allocation count after `Server.init` must equal the count at the
//! end. A second run under a failing allocator (fail index pinned to
//! the init count) proves the equality is structural: any post-init
//! allocation would error loudly, not just be counted.

const std = @import("std");

const server_test = @import("server_test.zig");

test "zero-alloc gate: the serving path allocates nothing after init" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var bed: server_test.TestBed = undefined;
    try bed.setUp(failing.allocator(), .{
        .sim = .{
            .seed = 7,
            .adversary = .{ .partial_io = true, .connect_delay_ns_max = 1_000_000 },
        },
    });
    defer bed.tearDown();

    const allocations_after_init = failing.allocations;
    bed.startClients(2, true);
    try bed.sim_io.run();
    try bed.expectDrained();
    try std.testing.expectEqual(allocations_after_init, failing.allocations);

    // Second run: exactly the same scenario, but any allocation past the
    // init count now *fails*. Surviving proves the hot path never asks.
    var strict = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = allocations_after_init,
    });
    var strict_bed: server_test.TestBed = undefined;
    try strict_bed.setUp(strict.allocator(), .{
        .sim = .{
            .seed = 7,
            .adversary = .{ .partial_io = true, .connect_delay_ns_max = 1_000_000 },
        },
    });
    defer strict_bed.tearDown();
    strict_bed.startClients(2, true);
    try strict_bed.sim_io.run();
    try strict_bed.expectDrained();
}
