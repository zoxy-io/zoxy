//! Cache-line isolation for per-worker mutable state. Workers share nothing
//! logically, but per-worker structs allocated as one array (metrics shards,
//! connection-pool headers, access logs) can still cohabit a cache line at
//! their boundaries — and a line two cores write is ping-ponged between
//! their caches regardless of the logical ownership (false sharing). Wrap
//! the element type in `Padded` and neighbors can never share a line.

const std = @import("std");
const assert = std.debug.assert;

/// The isolation unit. `std.atomic.cache_line` is 128 on x86_64 —
/// deliberately double the 64-byte line, because the L2 spatial prefetcher
/// pulls lines in adjacent pairs and would otherwise couple neighbors.
pub const bytes = std.atomic.cache_line;

/// Wrap `T` so adjacent array elements never share a cache line: the value
/// is over-aligned to the isolation unit, which also rounds the element
/// stride up to a multiple of it.
pub fn Padded(comptime T: type) type {
    return struct {
        value: T align(bytes),

        comptime {
            assert(@alignOf(@This()) >= bytes); // every element starts a fresh line
            assert(@sizeOf(@This()) % bytes == 0); // stride keeps neighbors apart
            assert(@sizeOf(@This()) - @sizeOf(T) < bytes); // padding stays minimal
        }
    };
}

comptime {
    assert(bytes >= 64); // never below a real cache line
    assert(std.math.isPowerOfTwo(bytes));
}

test "cache_line: padded array elements never share a line" {
    const Header = struct { free_count: u32 = 0, capacity: u32 = 0 };
    var slots: [4]Padded(Header) = @splat(.{ .value = .{} });
    for (&slots, 0..) |*slot, index| {
        try std.testing.expectEqual(@as(usize, 0), @intFromPtr(&slot.value) % bytes);
        if (index == 0) continue;
        const distance = @intFromPtr(&slot.value) - @intFromPtr(&slots[index - 1].value);
        try std.testing.expect(distance >= bytes);
        try std.testing.expectEqual(@as(usize, 0), distance % bytes);
    }
}

test "cache_line: padding never doubles a type already line-sized" {
    const Big = struct { buffer: [16 * 1024]u8 align(bytes) };
    try std.testing.expectEqual(@as(usize, 16 * 1024), @sizeOf(Padded(Big)));
}
