//! `Pool(T)` — fixed-capacity object pool: memory reserved once at init
//! from the config arena, an intrusive LIFO free list for cache-warm
//! reuse, and no growth path at all (DESIGN.md §5). Exhaustion returns
//! null — a shed signal, never an error (§8). Every slot carries a
//! generation counter bumped on release so a straggler completion landing
//! in a recycled slot is caught by assertion (§5 release rule).

const std = @import("std");

const assert = std.debug.assert;

/// `pool_next` value marking an acquired slot; doubles as the
/// double-release tripwire.
const sentinel_in_use: u32 = std.math.maxInt(u32);

/// `pool_next`/`free_head` value marking the end of the free list.
const sentinel_none: u32 = std.math.maxInt(u32) - 1;

/// Sanity ceiling on pool capacity — put a limit on everything.
const slots_count_max: u32 = 1 << 24;

pub fn Pool(comptime T: type) type {
    comptime assert(@FieldType(T, "pool_next") == u32);
    comptime assert(@FieldType(T, "generation") == u32);

    return struct {
        slots: []T,
        free_head: u32,
        acquired_count: u32,
        /// High watermark — §8 pressure groundwork.
        acquired_count_peak: u32,

        const Self = @This();

        /// In-place init via out-pointer for pointer stability. `arena`
        /// is the config arena — the only allocating region (§5) — and
        /// this is the pool's only allocation, ever.
        pub fn init(
            pool: *Self,
            arena: std.mem.Allocator,
            count: u32,
        ) error{OutOfMemory}!void {
            assert(count >= 1);
            assert(count <= slots_count_max);

            const slots = try arena.alloc(T, count);
            for (slots, 0..) |*slot, index| {
                const next: u32 = @intCast(index + 1);
                slot.pool_next = if (next < count) next else sentinel_none;
                slot.generation = 0;
            }

            pool.* = .{
                .slots = slots,
                .free_head = 0,
                .acquired_count = 0,
                .acquired_count_peak = 0,
            };
            assert(pool.slots.len == count);
        }

        /// Null means exhausted: the caller sheds (§8). The pool never
        /// grows and never errors. LIFO pop keeps reused slots cache-warm.
        pub fn acquire(pool: *Self) ?*T {
            assert(pool.acquired_count <= pool.slots.len);
            if (pool.free_head == sentinel_none) {
                assert(pool.acquired_count == pool.slots.len);
                return null;
            }

            assert(pool.free_head < pool.slots.len);
            const item = &pool.slots[pool.free_head];
            assert(item.pool_next != sentinel_in_use);
            pool.free_head = item.pool_next;
            item.pool_next = sentinel_in_use;
            pool.acquired_count += 1;
            if (pool.acquired_count > pool.acquired_count_peak) {
                pool.acquired_count_peak = pool.acquired_count;
            }
            assert(pool.free_head == sentinel_none or pool.free_head < pool.slots.len);
            return item;
        }

        /// Bumps the slot generation so any stale reference trips the
        /// next generation assertion (§5), then pushes LIFO.
        pub fn release(pool: *Self, item: *T) void {
            assert(pool.acquired_count >= 1);
            assert(item.pool_next == sentinel_in_use);

            const index = pool.indexOf(item);
            item.generation +%= 1;
            item.pool_next = pool.free_head;
            pool.free_head = index;
            pool.acquired_count -= 1;
            assert(pool.free_head < pool.slots.len);
        }

        pub fn indexOf(pool: *const Self, item: *const T) u32 {
            const base = @intFromPtr(pool.slots.ptr);
            const address = @intFromPtr(item);
            assert(address >= base);
            const index = @divExact(address - base, @sizeOf(T));
            assert(index < pool.slots.len);
            return @intCast(index);
        }

        /// The simulator's leak invariant: every scenario ends here (§9).
        pub fn isFullyReleased(pool: *const Self) bool {
            assert(pool.acquired_count <= pool.slots.len);
            return pool.acquired_count == 0;
        }
    };
}

const TestItem = struct {
    pool_next: u32,
    generation: u32,
    payload: u64,
};

test "pool: acquire-all, exhaustion returns null, release-all" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var pool: Pool(TestItem) = undefined;
    try pool.init(arena_state.allocator(), 4);

    var items: [4]*TestItem = undefined;
    for (&items) |*slot| {
        slot.* = pool.acquire().?;
    }
    try std.testing.expectEqual(@as(u32, 4), pool.acquired_count);
    try std.testing.expectEqual(@as(?*TestItem, null), pool.acquire());

    for (items) |item| {
        pool.release(item);
    }
    try std.testing.expect(pool.isFullyReleased());
    try std.testing.expectEqual(@as(u32, 4), pool.acquired_count_peak);
}

test "pool: LIFO reuse returns the most recently released slot" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var pool: Pool(TestItem) = undefined;
    try pool.init(arena_state.allocator(), 4);

    const first = pool.acquire().?;
    const second = pool.acquire().?;
    pool.release(second);
    const reused = pool.acquire().?;
    try std.testing.expectEqual(second, reused);

    pool.release(first);
    pool.release(reused);
    try std.testing.expect(pool.isFullyReleased());
}

test "pool: generation bumps exactly once per release" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var pool: Pool(TestItem) = undefined;
    try pool.init(arena_state.allocator(), 1);

    const item = pool.acquire().?;
    const generation_before = item.generation;
    pool.release(item);

    const reused = pool.acquire().?;
    try std.testing.expectEqual(item, reused);
    try std.testing.expectEqual(generation_before + 1, reused.generation);
    pool.release(reused);
}

test "pool: zero allocations after init" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var arena_state = std.heap.ArenaAllocator.init(failing.allocator());
    defer arena_state.deinit();

    var pool: Pool(TestItem) = undefined;
    try pool.init(arena_state.allocator(), 16);
    const allocations_after_init = failing.allocations;

    var cycle: u32 = 0;
    while (cycle < 100_000) : (cycle += 1) {
        const item = pool.acquire() orelse unreachable;
        pool.release(item);
    }
    try std.testing.expectEqual(allocations_after_init, failing.allocations);
}

test "pool: indexOf is stable across reuse" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var pool: Pool(TestItem) = undefined;
    try pool.init(arena_state.allocator(), 8);

    const item = pool.acquire().?;
    const index = pool.indexOf(item);
    pool.release(item);
    const reused = pool.acquire().?;
    try std.testing.expectEqual(index, pool.indexOf(reused));
    pool.release(reused);
}
