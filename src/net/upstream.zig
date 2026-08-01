//! The shared upstream connection pool with per-endpoint idle lists
//! (DESIGN.md §3, §5): one pool for the whole process, owned and touched
//! only by the loop thread — every request sees every parked connection
//! (the Pingora reuse win) with zero synchronization. A slot is
//! pool-acquired for its whole connected life: leased while serving a
//! request, parked on an idle list between requests (it still holds an
//! fd), released only at teardown. A parked upstream holds no armed data
//! op (§5); `deadline_ns` is the idle timeout, and an origin close that
//! slips through is detected at checkout. Exhaustion is a shed signal
//! (§8), never growth. Idle lists are doubly linked so a deadline-fired
//! teardown unparks from the middle of a list in O(1).

const std = @import("std");

const constants = @import("../constants.zig");
const Pool = @import("../mem/Pool.zig").Pool;

const assert = std.debug.assert;

/// `idle_next`/`idle_prev`/`idle_heads` value marking "no slot".
const idle_none: u32 = std.math.maxInt(u32);

/// The flattened endpoint index space for one loaded config (§7).
///
/// Seven tables are keyed by it — the pool's idle heads and lease
/// counts, the balancer's cursors-adjacent endpoint hashes, the server's
/// L4 in-flight charges, and the health checker's mask and two streak
/// counters. All were `clusters_max × endpoints_per_cluster_max` fixed
/// arrays sized for the worst config any build could accept; they are
/// now sized for the config this process actually loaded, so a
/// two-endpoint deployment stops carrying a 1024-entry table.
///
/// `stride` is the widest cluster in the config rather than each
/// cluster's own length, which wastes `stride - len` entries per
/// cluster. That buys a multiply instead of a per-cluster offset lookup
/// on the pick path, and the waste is bounded by the config the operator
/// wrote — the same trade the fixed arrays made, minus the part that had
/// nothing to do with this deployment.
pub const EndpointKeys = struct {
    /// Entries per cluster: the largest endpoint count any one cluster
    /// declares. At least 1, so a key is always addressable.
    stride: u16,
    /// `clusters × stride` — the length every endpoint-keyed table has.
    count: u32,

    pub fn init(cluster_count: u16, stride: u16) EndpointKeys {
        assert(cluster_count >= 1);
        assert(stride >= 1);
        const count = @as(u32, cluster_count) * stride;
        assert(count >= 1);
        return .{ .stride = stride, .count = count };
    }

    pub fn key(keys: EndpointKeys, cluster_index: u16, endpoint_index: u16) u32 {
        assert(keys.stride >= 1);
        assert(endpoint_index < keys.stride);
        const flat = @as(u32, cluster_index) * keys.stride + endpoint_index;
        assert(flat < keys.count);
        return flat;
    }
};

pub fn UpstreamPool(comptime IoType: type) type {
    return struct {
        slot_pool: Pool(Upstream),
        /// The config's endpoint index space; every table below has
        /// `keys.count` entries.
        keys: EndpointKeys,
        idle_heads: []u32,
        /// Parked slots across all endpoints; leased = acquired − idle.
        idle_count: u32,
        /// Slots leased per endpoint — the §7 P2C load signal: a lease
        /// is a request in flight against that endpoint, so the balancer
        /// compares two candidates' counts and picks the calmer one.
        /// u16 holds the whole pool (`upstream_slots_max` ≤ 65535).
        leased_counts: []u16,

        const Self = @This();

        /// One upstream connection slot (§5 pool 3): identity, socket,
        /// idle links, the idle deadline, and the head buffer response
        /// heads are parsed into and rendered upstream heads are staged
        /// in. The dial and data-op completions live on the owning
        /// `Conn`, one field per proven race (the Conn precedent).
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
            keys: EndpointKeys,
        ) error{OutOfMemory}!void {
            assert(count >= 1);
            assert(keys.count >= 1);
            try pool.slot_pool.init(arena, count);
            pool.keys = keys;
            pool.idle_heads = try arena.alloc(u32, keys.count);
            pool.leased_counts = try arena.alloc(u16, keys.count);
            @memset(pool.idle_heads, idle_none);
            pool.idle_count = 0;
            @memset(pool.leased_counts, 0);
            assert(pool.slot_pool.slots.len == count);
            assert(pool.idle_heads.len == keys.count);
            assert(pool.leased_counts.len == keys.count);
            assert(pool.leasedCount() == 0);
        }

        /// A fresh slot for a new dial to the endpoint, or null when the
        /// pool is exhausted — the caller sheds (§8: 503). The socket is
        /// left undefined for the dialer to fill in.
        pub fn acquire(pool: *Self, cluster_index: u16, endpoint_index: u16) ?*Upstream {
            assert(endpoint_index < pool.keys.stride);
            const upstream = pool.slot_pool.acquire() orelse return null;
            upstream.cluster_index = cluster_index;
            upstream.endpoint_index = endpoint_index;
            upstream.parked = false;
            upstream.idle_next = idle_none;
            upstream.idle_prev = idle_none;
            upstream.head_len = 0;
            upstream.deadline_ns = 0;
            const key = pool.keys.key(cluster_index, endpoint_index);
            pool.leased_counts[key] += 1;
            assert(pool.leased_counts[key] <= pool.slot_pool.slots.len);
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
            const key = pool.keys.key(upstream.cluster_index, upstream.endpoint_index);

            upstream.idle_next = pool.idle_heads[key];
            if (upstream.idle_next != idle_none) {
                pool.slot_pool.slots[upstream.idle_next].idle_prev = index;
            }
            pool.idle_heads[key] = index;
            upstream.parked = true;
            pool.idle_count += 1;
            // Parked is not leased: the P2C load signal counts only slots
            // actually serving a request.
            assert(pool.leased_counts[key] >= 1);
            pool.leased_counts[key] -= 1;
            assert(pool.idle_count <= pool.slot_pool.acquired_count);
        }

        /// The most recently parked connection for the endpoint, leased
        /// again — or null, and the caller dials fresh via `acquire`.
        pub fn checkout(pool: *Self, cluster_index: u16, endpoint_index: u16) ?*Upstream {
            assert(endpoint_index < pool.keys.stride);

            const key = pool.keys.key(cluster_index, endpoint_index);
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
            const key = pool.keys.key(upstream.cluster_index, upstream.endpoint_index);

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
            // Back to leased — both for a checkout (serving again) and,
            // transiently, for the reap path (its release decrements).
            pool.leased_counts[key] += 1;
            assert(pool.leased_counts[key] <= pool.slot_pool.slots.len);
        }

        /// Returns a leased slot to the free list at connection
        /// teardown. A parked slot must be unparked first — releasing it
        /// directly would leave a dangling idle-list entry.
        pub fn release(pool: *Self, upstream: *Upstream) void {
            assert(!upstream.parked);
            assert(upstream.idle_next == idle_none);
            assert(upstream.idle_prev == idle_none);
            const key = pool.keys.key(upstream.cluster_index, upstream.endpoint_index);
            assert(pool.leased_counts[key] >= 1);
            pool.leased_counts[key] -= 1;
            pool.slot_pool.release(upstream);
            assert(pool.idle_count <= pool.slot_pool.acquired_count);
        }

        /// Slots currently serving a request (acquired but not parked).
        pub fn leasedCount(pool: *const Self) u32 {
            assert(pool.idle_count <= pool.slot_pool.acquired_count);
            return pool.slot_pool.acquired_count - pool.idle_count;
        }

        /// Slots held open on an idle list for reuse (§5). Occupied, not
        /// free: `leasedCount` plus this is what the wall is measured
        /// against, which is why the two are reported separately.
        pub fn parkedCount(pool: *const Self) u32 {
            assert(pool.idle_count <= pool.slot_pool.acquired_count);
            return pool.idle_count;
        }

        /// Slots the pool was sized to — the wall `acquire` sheds at (§8).
        pub fn capacity(pool: *const Self) u32 {
            return pool.slot_pool.capacity();
        }

        /// The simulator's leak invariant (§9): every scenario drains
        /// every pool to zero.
        pub fn isFullyReleased(pool: *const Self) bool {
            assert(pool.idle_count <= pool.slot_pool.acquired_count);
            return pool.slot_pool.isFullyReleased();
        }
    };
}

/// How much work an endpoint is carrying right now, across both
/// protocols (§7). Two tables rather than one running total, because
/// each has its own provable bound and its own single writer: the pool
/// owns `l7` (leases, `leased_counts`) and the server owns `l4` (live
/// relayed connections, which hold no pool slot at all). A shared
/// counter would have to give up `leased_counts <= slot_pool.slots.len`,
/// since L4 connections outnumber the upstream pool whenever
/// `conn_slots` exceeds `upstream_slots` — a legal config.
///
/// A view, not storage: it borrows both tables so the sum is computed
/// where it is read and can never drift from either writer.
///
/// The two count different things — an L7 lease is one in-flight
/// *request*, an L4 charge is one live *connection* — and the sum is
/// deliberate: both are work the origin is doing right now, which is
/// what a load comparison and a capacity limit are about. A cluster
/// reached by both an `l4` and an `http` listener is representable, and
/// there the total is that mixed unit.
pub const Load = struct {
    /// Both tables have `EndpointKeys.count` entries, which is why the
    /// bound below is read off the slice rather than a constant.
    l7: []const u16,
    l4: []const u16,

    /// Total in-flight work against one endpoint. `u32` because the two
    /// ceilings sum past a `u16`'s range in principle, even though no
    /// single deployment reaches both at once.
    pub fn inFlight(load: *const Load, key: u32) u32 {
        assert(load.l7.len == load.l4.len);
        assert(key < load.l7.len);
        return @as(u32, load.l7[key]) + load.l4[key];
    }
};

// Tests drive the pool through a socket-free fake Io: the pool never
// touches the socket, it only stores it for the owner.

const TestIo = struct {
    pub const Socket = u32;
};

const TestPool = UpstreamPool(TestIo);

/// A deliberately ragged test index space — 4 clusters of up to 8
/// endpoints — so a key is never accidentally equal to its endpoint
/// index and a stride bug cannot pass unnoticed.
const test_keys: EndpointKeys = .init(4, 8);

test "upstream: dial-park-checkout-release keeps the same connection" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var pool: TestPool = undefined;
    try pool.init(arena_state.allocator(), 4, test_keys);

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
    try pool.init(arena_state.allocator(), 4, test_keys);

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
    try pool.init(arena_state.allocator(), 4, test_keys);

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
    try pool.init(arena_state.allocator(), 4, test_keys);

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
    try pool.init(arena_state.allocator(), 2, test_keys);

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

test "upstream: leased counts track every lease transition per endpoint" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var pool: TestPool = undefined;
    try pool.init(arena_state.allocator(), 4, test_keys);
    const key_a = test_keys.key(0, 0);
    const key_b = test_keys.key(0, 1);

    // Fresh dials lease against their own endpoints.
    const first = pool.acquire(0, 0).?;
    const second = pool.acquire(0, 0).?;
    const other = pool.acquire(0, 1).?;
    try std.testing.expectEqual(@as(u16, 2), pool.leased_counts[key_a]);
    try std.testing.expectEqual(@as(u16, 1), pool.leased_counts[key_b]);

    // Parking returns the lease; checkout takes it again.
    pool.park(first);
    try std.testing.expectEqual(@as(u16, 1), pool.leased_counts[key_a]);
    const reused = pool.checkout(0, 0).?;
    try std.testing.expectEqual(first, reused);
    try std.testing.expectEqual(@as(u16, 2), pool.leased_counts[key_a]);

    // The reap path (unpark from parked, then release) nets to zero.
    pool.park(second);
    try std.testing.expectEqual(@as(u16, 1), pool.leased_counts[key_a]);
    pool.unpark(second);
    try std.testing.expectEqual(@as(u16, 2), pool.leased_counts[key_a]);
    pool.release(second);
    try std.testing.expectEqual(@as(u16, 1), pool.leased_counts[key_a]);

    // Releases drain both endpoints back to zero, agreeing with the
    // pool-wide count the whole way down.
    try std.testing.expectEqual(pool.leasedCount(), @as(u32, pool.leased_counts[key_a]) +
        pool.leased_counts[key_b]);
    pool.release(reused);
    pool.release(other);
    try std.testing.expectEqual(@as(u16, 0), pool.leased_counts[key_a]);
    try std.testing.expectEqual(@as(u16, 0), pool.leased_counts[key_b]);
    try std.testing.expect(pool.isFullyReleased());
}

test "upstream: zero allocations after init" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var arena_state = std.heap.ArenaAllocator.init(failing.allocator());
    defer arena_state.deinit();
    var pool: TestPool = undefined;
    try pool.init(arena_state.allocator(), 8, test_keys);
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
