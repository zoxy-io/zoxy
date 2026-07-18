//! The shared upstream connection pool with per-endpoint idle lists
//! (DESIGN.md §3, §5): one pool for the whole process, owned and touched
//! only by the loop thread — every request sees every parked connection
//! (the Pingora reuse win) with zero synchronization. A slot is
//! pool-acquired for its whole connected life: leased while serving a
//! request, parked on an idle list between requests (it still holds an
//! fd), released only at teardown. A parked upstream holds no armed data
//! op (§5); its deadline timer — embedded when the L7 state machine
//! lands — is the idle timeout, and an origin close that slips through
//! is detected at checkout. Exhaustion is a shed signal (§8), never
//! growth. Idle lists are doubly linked so a deadline-fired teardown
//! unparks from the middle of a list in O(1).

const std = @import("std");

const constants = @import("../constants.zig");
const Pool = @import("../mem/Pool.zig").Pool;

const assert = std.debug.assert;

/// `idle_next`/`idle_prev`/`idle_heads` value marking "no slot".
const idle_none: u32 = std.math.maxInt(u32);

/// Idle lists are indexed by the flattened endpoint key, so the head
/// array covers the worst-case config shape.
const endpoint_keys_max: u32 =
    @as(u32, constants.clusters_max) * constants.endpoints_per_cluster_max;

pub fn UpstreamPool(comptime IoType: type) type {
    return struct {
        slot_pool: Pool(Upstream),
        idle_heads: [endpoint_keys_max]u32,
        /// Parked slots across all endpoints; leased = acquired − idle.
        idle_count: u32,

        const Self = @This();

        /// One upstream connection slot (§5 pool 3): identity, socket,
        /// idle links, and the head buffer response heads are parsed
        /// into and rendered upstream heads are staged in. Embedded
        /// completions and the deadline timer join with the L7 state
        /// machine, one field per proven race (the Conn precedent).
        pub const Upstream = struct {
            pool_next: u32,
            generation: u32,
            /// Undefined until the owner dials; a slot is only parked
            /// after its connection is established.
            socket: IoType.Socket,
            cluster_index: u16,
            endpoint_index: u16,
            parked: bool,
            idle_next: u32,
            idle_prev: u32,
            head: [constants.head_bytes_max]u8,
            /// Valid prefix of `head` while it accumulates a response
            /// head; the rendered upstream request head tracks its own
            /// length in the owning connection instead.
            head_len: u32,
            /// Absolute idle deadline while parked (§5): a parked
            /// connection holds no armed op, so the Server's single sweep
            /// timer compares this against the clock and reaps overdue
            /// connections with a synchronous close.
            deadline_ns: u64,
        };

        /// In-place init via out-pointer for pointer stability. `arena`
        /// is the config arena — the pool's only allocation, ever (§5).
        pub fn init(
            pool: *Self,
            arena: std.mem.Allocator,
            count: u32,
        ) error{OutOfMemory}!void {
            assert(count >= 1);
            try pool.slot_pool.init(arena, count);
            @memset(&pool.idle_heads, idle_none);
            pool.idle_count = 0;
            assert(pool.slot_pool.slots.len == count);
            assert(pool.leasedCount() == 0);
        }

        /// A fresh slot for a new dial to the endpoint, or null when the
        /// pool is exhausted — the caller sheds (§8: 503). The socket is
        /// left undefined for the dialer to fill in.
        pub fn acquire(pool: *Self, cluster_index: u16, endpoint_index: u16) ?*Upstream {
            assert(cluster_index < constants.clusters_max);
            assert(endpoint_index < constants.endpoints_per_cluster_max);
            const upstream = pool.slot_pool.acquire() orelse return null;
            upstream.cluster_index = cluster_index;
            upstream.endpoint_index = endpoint_index;
            upstream.parked = false;
            upstream.idle_next = idle_none;
            upstream.idle_prev = idle_none;
            upstream.head_len = 0;
            upstream.deadline_ns = 0;
            assert(pool.idle_count < pool.slot_pool.acquired_count);
            return upstream;
        }

        /// Parks a leased connection on its endpoint's idle list for
        /// reuse (LIFO: the most recently used connection is the most
        /// likely to still be open and cache-warm).
        pub fn park(pool: *Self, upstream: *Upstream) void {
            assert(!upstream.parked);
            assert(upstream.idle_next == idle_none);
            assert(upstream.idle_prev == idle_none);
            const index = pool.slot_pool.indexOf(upstream);
            const key = endpointKey(upstream.cluster_index, upstream.endpoint_index);

            upstream.idle_next = pool.idle_heads[key];
            if (upstream.idle_next != idle_none) {
                pool.slot_pool.slots[upstream.idle_next].idle_prev = index;
            }
            pool.idle_heads[key] = index;
            upstream.parked = true;
            pool.idle_count += 1;
            assert(pool.idle_count <= pool.slot_pool.acquired_count);
        }

        /// The most recently parked connection for the endpoint, leased
        /// again — or null, and the caller dials fresh via `acquire`.
        pub fn checkout(pool: *Self, cluster_index: u16, endpoint_index: u16) ?*Upstream {
            assert(cluster_index < constants.clusters_max);
            assert(endpoint_index < constants.endpoints_per_cluster_max);
            const key = endpointKey(cluster_index, endpoint_index);
            const head = pool.idle_heads[key];
            if (head == idle_none) {
                return null;
            }

            const upstream = &pool.slot_pool.slots[head];
            assert(upstream.cluster_index == cluster_index);
            assert(upstream.endpoint_index == endpoint_index);
            pool.unpark(upstream);
            return upstream;
        }

        /// Removes a parked connection from anywhere in its idle list —
        /// the head via `checkout`, the middle when its idle deadline
        /// fires and the connection is torn down.
        pub fn unpark(pool: *Self, upstream: *Upstream) void {
            assert(upstream.parked);
            assert(pool.idle_count >= 1);
            const index = pool.slot_pool.indexOf(upstream);
            const key = endpointKey(upstream.cluster_index, upstream.endpoint_index);

            if (upstream.idle_prev == idle_none) {
                assert(pool.idle_heads[key] == index);
                pool.idle_heads[key] = upstream.idle_next;
            } else {
                pool.slot_pool.slots[upstream.idle_prev].idle_next = upstream.idle_next;
            }
            if (upstream.idle_next != idle_none) {
                pool.slot_pool.slots[upstream.idle_next].idle_prev = upstream.idle_prev;
            }
            upstream.idle_next = idle_none;
            upstream.idle_prev = idle_none;
            upstream.parked = false;
            pool.idle_count -= 1;
        }

        /// Returns a leased slot to the free list at connection
        /// teardown. A parked slot must be unparked first — releasing it
        /// directly would leave a dangling idle-list entry.
        pub fn release(pool: *Self, upstream: *Upstream) void {
            assert(!upstream.parked);
            assert(upstream.idle_next == idle_none);
            assert(upstream.idle_prev == idle_none);
            pool.slot_pool.release(upstream);
            assert(pool.idle_count <= pool.slot_pool.acquired_count);
        }

        /// Slots currently serving a request (acquired but not parked).
        pub fn leasedCount(pool: *const Self) u32 {
            assert(pool.idle_count <= pool.slot_pool.acquired_count);
            return pool.slot_pool.acquired_count - pool.idle_count;
        }

        /// The simulator's leak invariant (§9): every scenario drains
        /// every pool to zero.
        pub fn isFullyReleased(pool: *const Self) bool {
            assert(pool.idle_count <= pool.slot_pool.acquired_count);
            return pool.slot_pool.isFullyReleased();
        }
    };
}

fn endpointKey(cluster_index: u16, endpoint_index: u16) u32 {
    assert(cluster_index < constants.clusters_max);
    assert(endpoint_index < constants.endpoints_per_cluster_max);
    return @as(u32, cluster_index) * constants.endpoints_per_cluster_max + endpoint_index;
}

// Tests drive the pool through a socket-free fake Io: the pool never
// touches the socket, it only stores it for the owner.

const TestIo = struct {
    pub const Socket = u32;
};

const TestPool = UpstreamPool(TestIo);

test "upstream: dial-park-checkout-release keeps the same connection" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var pool: TestPool = undefined;
    try pool.init(arena_state.allocator(), 4);

    const dialed = pool.acquire(0, 0).?;
    dialed.socket = 77;
    try std.testing.expectEqual(@as(u32, 1), pool.leasedCount());

    pool.park(dialed);
    try std.testing.expectEqual(@as(u32, 1), pool.idle_count);
    try std.testing.expectEqual(@as(u32, 0), pool.leasedCount());

    // Checkout returns the same live connection — same slot, same
    // socket, same generation (only release recycles a slot).
    const generation_at_park = dialed.generation;
    const reused = pool.checkout(0, 0).?;
    try std.testing.expectEqual(dialed, reused);
    try std.testing.expectEqual(@as(TestIo.Socket, 77), reused.socket);
    try std.testing.expectEqual(generation_at_park, reused.generation);

    pool.release(reused);
    try std.testing.expect(pool.isFullyReleased());
}

test "upstream: checkout is LIFO per endpoint" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var pool: TestPool = undefined;
    try pool.init(arena_state.allocator(), 4);

    const first = pool.acquire(0, 0).?;
    const second = pool.acquire(0, 0).?;
    pool.park(first);
    pool.park(second);

    try std.testing.expectEqual(second, pool.checkout(0, 0).?);
    try std.testing.expectEqual(first, pool.checkout(0, 0).?);
    try std.testing.expectEqual(@as(?*TestPool.Upstream, null), pool.checkout(0, 0));

    pool.release(first);
    pool.release(second);
    try std.testing.expect(pool.isFullyReleased());
}

test "upstream: endpoints do not share idle connections" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var pool: TestPool = undefined;
    try pool.init(arena_state.allocator(), 4);

    const parked = pool.acquire(1, 2).?;
    pool.park(parked);

    // Neither a sibling endpoint nor another cluster may steal it.
    try std.testing.expectEqual(@as(?*TestPool.Upstream, null), pool.checkout(1, 3));
    try std.testing.expectEqual(@as(?*TestPool.Upstream, null), pool.checkout(2, 2));
    try std.testing.expectEqual(parked, pool.checkout(1, 2).?);

    pool.release(parked);
    try std.testing.expect(pool.isFullyReleased());
}

test "upstream: unpark removes from the middle of an idle list" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var pool: TestPool = undefined;
    try pool.init(arena_state.allocator(), 4);

    const first = pool.acquire(0, 0).?;
    const second = pool.acquire(0, 0).?;
    const third = pool.acquire(0, 0).?;
    pool.park(first);
    pool.park(second);
    pool.park(third);

    // An idle deadline fires on the middle entry: it leaves its list and
    // the LIFO order of the rest is undisturbed.
    pool.unpark(second);
    pool.release(second);
    try std.testing.expectEqual(@as(u32, 2), pool.idle_count);

    try std.testing.expectEqual(third, pool.checkout(0, 0).?);
    try std.testing.expectEqual(first, pool.checkout(0, 0).?);
    try std.testing.expectEqual(@as(?*TestPool.Upstream, null), pool.checkout(0, 0));

    pool.release(first);
    pool.release(third);
    try std.testing.expect(pool.isFullyReleased());
}

test "upstream: exhaustion is a shed signal, parked slots stay counted" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var pool: TestPool = undefined;
    try pool.init(arena_state.allocator(), 2);

    const first = pool.acquire(0, 0).?;
    const second = pool.acquire(0, 1).?;
    // A parked connection still owns its slot: the pool is exhausted
    // even though nothing is leased for it.
    pool.park(first);
    pool.park(second);
    try std.testing.expectEqual(@as(?*TestPool.Upstream, null), pool.acquire(0, 2));
    try std.testing.expectEqual(@as(u32, 0), pool.leasedCount());

    pool.unpark(first);
    pool.release(first);
    try std.testing.expectEqual(second, pool.checkout(0, 1).?);
    pool.release(second);
    try std.testing.expect(pool.isFullyReleased());
}

test "upstream: zero allocations after init" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var arena_state = std.heap.ArenaAllocator.init(failing.allocator());
    defer arena_state.deinit();
    var pool: TestPool = undefined;
    try pool.init(arena_state.allocator(), 8);
    const allocations_after_init = failing.allocations;

    var cycle: u32 = 0;
    while (cycle < 100_000) : (cycle += 1) {
        const upstream = pool.acquire(3, 7) orelse unreachable;
        pool.park(upstream);
        const reused = pool.checkout(3, 7) orelse unreachable;
        assert(reused == upstream);
        pool.release(reused);
    }
    try std.testing.expectEqual(allocations_after_init, failing.allocations);
    try std.testing.expect(pool.isFullyReleased());
}
