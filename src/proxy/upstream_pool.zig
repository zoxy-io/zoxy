//! Per-worker pool of idle upstream HTTP/1.1 connections, keyed by endpoint
//! address (docs/DESIGN.md §7, Phase 1). Fixed slots, linear scans, no
//! allocation: `checkout` takes a live fd for the endpoint if one is parked;
//! `checkin` parks one, or closes it when every slot is taken. A parked fd
//! has no operation pending on it — if the upstream closes it while idle,
//! the next checkout discovers that on first use, and the data path retries
//! once on a fresh connection.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Ip4Address = std.Io.net.Ip4Address;

pub const UpstreamPool = struct {
    slots: [constants.upstream_idle_max]Slot = @splat(.{}),
    /// Parked connections (for asserts and tests).
    count: u32 = 0,

    const Slot = struct {
        fd: posix.socket_t = -1,
        address: Ip4Address = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 },
    };

    /// Take a parked connection to `address`, if any.
    pub fn checkout(pool: *UpstreamPool, address: Ip4Address) ?posix.socket_t {
        for (&pool.slots) |*slot| {
            if (slot.fd < 0) continue;
            if (!addressEqual(slot.address, address)) continue;
            const fd = slot.fd;
            slot.fd = -1;
            assert(pool.count > 0);
            pool.count -= 1;
            assert(fd >= 0);
            return fd;
        }
        return null;
    }

    /// Park an idle connection, or close it when the pool is full. The fd
    /// must have no operation pending on it.
    pub fn checkin(pool: *UpstreamPool, address: Ip4Address, fd: posix.socket_t) void {
        assert(fd >= 0);
        for (&pool.slots) |*slot| {
            if (slot.fd >= 0) continue;
            slot.fd = fd;
            slot.address = address;
            pool.count += 1;
            assert(pool.count <= constants.upstream_idle_max);
            return;
        }
        assert(pool.count == constants.upstream_idle_max);
        _ = linux.close(fd); // every slot taken: not worth keeping
    }

    /// Close every parked connection (worker/test shutdown).
    pub fn drain(pool: *UpstreamPool) void {
        for (&pool.slots) |*slot| {
            if (slot.fd < 0) continue;
            _ = linux.close(slot.fd);
            slot.fd = -1;
            assert(pool.count > 0);
            pool.count -= 1;
        }
        assert(pool.count == 0);
    }
};

fn addressEqual(a: Ip4Address, b: Ip4Address) bool {
    return a.port == b.port and std.mem.eql(u8, &a.bytes, &b.bytes);
}

// ---- tests ----------------------------------------------------------------

test "upstream_pool: checkout matches the endpoint and empties the slot" {
    var pool = UpstreamPool{};
    const address_a = Ip4Address.loopback(1);
    const address_b = Ip4Address.loopback(2);

    // Real fds, so checkin-when-full and drain can close them.
    var pair: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair);
    try std.testing.expectEqual(@as(usize, 0), rc);

    pool.checkin(address_a, pair[0]);
    pool.checkin(address_b, pair[1]);
    try std.testing.expectEqual(@as(u32, 2), pool.count);

    // No connection parked for an unrelated endpoint.
    try std.testing.expect(pool.checkout(Ip4Address.loopback(3)) == null);
    // The parked fd comes back for its endpoint — exactly once.
    try std.testing.expectEqual(pair[0], pool.checkout(address_a).?);
    try std.testing.expect(pool.checkout(address_a) == null);
    try std.testing.expectEqual(@as(u32, 1), pool.count);

    pool.drain(); // closes pair[1]
    try std.testing.expectEqual(@as(u32, 0), pool.count);
    _ = linux.close(pair[0]);
}
