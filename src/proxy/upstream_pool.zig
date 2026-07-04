//! Per-worker pool of idle upstream HTTP/1.1 connections, keyed by endpoint
//! address (docs/DESIGN.md §7, Phase 1). Fixed slots, linear scans, no
//! allocation: `checkout` takes a live connection for the endpoint if one is
//! parked; `checkin` parks one, or closes it when every slot is taken. A
//! parked connection has no operation pending — if the upstream closes it
//! while idle, the next checkout discovers that on first use, and the data
//! path retries once on a fresh connection.
//!
//! A re-encrypted connection (docs/DESIGN.md §6, U3) parks its TLS channel
//! alongside the fd — the channel is quiescent by the park conditions, so
//! resuming is just handing it to the next attempt's leg. The channel's
//! heap stays owned while parked; eviction and drain free it.

const std = @import("std");
const posix = std.posix;
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const terminator = @import("../tls/terminator.zig");
const IO = @import("../io/io.zig").IO;
const Ip4Address = std.Io.net.Ip4Address;

pub const UpstreamPool = struct {
    slots: [constants.upstream_idle_max]Slot = @splat(.{}),
    /// Parked connections (for asserts and tests).
    count: u32 = 0,

    const Slot = struct {
        fd: posix.socket_t = -1,
        address: Ip4Address = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 },
        channel: ?terminator.Channel = null,
    };

    pub const Parked = struct {
        fd: posix.socket_t,
        /// The TLS channel when the connection is re-encrypted; null =
        /// plaintext. Ownership moves to the caller.
        channel: ?terminator.Channel,
    };

    /// Take a parked connection to `address`, if any.
    pub fn checkout(pool: *UpstreamPool, address: Ip4Address) ?Parked {
        for (&pool.slots) |*slot| {
            if (slot.fd < 0) continue;
            if (!address_equal(slot.address, address)) continue;
            const parked = Parked{ .fd = slot.fd, .channel = slot.channel };
            slot.fd = -1;
            slot.channel = null;
            assert(pool.count > 0);
            pool.count -= 1;
            assert(parked.fd >= 0);
            return parked;
        }
        return null;
    }

    /// Park an idle connection, or close it when the pool is full. The fd
    /// must have no operation pending on it; a channel must be quiescent
    /// (nothing staged, buffered, or in flight — the caller's park rules).
    pub fn checkin(
        pool: *UpstreamPool,
        io: *IO,
        address: Ip4Address,
        fd: posix.socket_t,
        channel: ?terminator.Channel,
    ) void {
        assert(fd >= 0);
        for (&pool.slots) |*slot| {
            if (slot.fd >= 0) continue;
            slot.fd = fd;
            slot.address = address;
            slot.channel = channel;
            pool.count += 1;
            assert(pool.count <= constants.upstream_idle_max);
            return;
        }
        assert(pool.count == constants.upstream_idle_max);
        if (channel) |parked_channel| parked_channel.deinit();
        io.close_now(fd); // every slot taken: not worth keeping
    }

    /// Close every parked connection (worker/test shutdown).
    pub fn drain(pool: *UpstreamPool, io: *IO) void {
        for (&pool.slots) |*slot| {
            if (slot.fd < 0) continue;
            if (slot.channel) |parked_channel| parked_channel.deinit();
            slot.channel = null;
            io.close_now(slot.fd);
            slot.fd = -1;
            assert(pool.count > 0);
            pool.count -= 1;
        }
        assert(pool.count == 0);
    }
};

fn address_equal(a: Ip4Address, b: Ip4Address) bool {
    return a.port == b.port and std.mem.eql(u8, &a.bytes, &b.bytes);
}

// ---- tests ----------------------------------------------------------------

test "upstream_pool: checkout matches the endpoint and empties the slot" {
    const linux = std.os.linux;
    var io = try IO.init(8, 0);
    defer io.deinit();

    var pool = UpstreamPool{};
    const address_a = Ip4Address.loopback(1);
    const address_b = Ip4Address.loopback(2);

    // Real fds, so checkin-when-full and drain can close them.
    var pair: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair);
    try std.testing.expectEqual(@as(usize, 0), rc);

    pool.checkin(&io, address_a, pair[0], null);
    pool.checkin(&io, address_b, pair[1], null);
    try std.testing.expectEqual(@as(u32, 2), pool.count);

    // No connection parked for an unrelated endpoint.
    try std.testing.expect(pool.checkout(Ip4Address.loopback(3)) == null);
    // The parked fd comes back for its endpoint — exactly once.
    try std.testing.expectEqual(pair[0], pool.checkout(address_a).?.fd);
    try std.testing.expect(pool.checkout(address_a) == null);
    try std.testing.expectEqual(@as(u32, 1), pool.count);

    pool.drain(&io); // closes pair[1]
    try std.testing.expectEqual(@as(u32, 0), pool.count);
    _ = linux.close(pair[0]);
}
