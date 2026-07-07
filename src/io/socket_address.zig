//! The connect-target address crossing the IO seam. A fixed-size union of the
//! two TCP sockaddr shapes so a `Completion` embeds either family inline —
//! submitting a v6 dial allocates exactly as much as a v4 one: nothing. Both
//! backends (io_uring and the simulator) share this type; the simulator only
//! ever reads the port, so it stays family-agnostic.

const std = @import("std");
const linux = std.os.linux;
const assert = std.debug.assert;

const IpAddress = std.Io.net.IpAddress;

pub const SocketAddress = extern union {
    in: linux.sockaddr.in,
    in6: linux.sockaddr.in6,

    pub fn from_ip(address: IpAddress) SocketAddress {
        return switch (address) {
            .ip4 => |ip4| .{ .in = .{
                .family = linux.AF.INET,
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = @bitCast(ip4.bytes),
            } },
            .ip6 => |ip6| .{ .in6 = .{
                .family = linux.AF.INET6,
                .port = std.mem.nativeToBig(u16, ip6.port),
                .flowinfo = ip6.flow,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            } },
        };
    }

    /// The byte count connect(2) must see: the sockaddr length of the stored
    /// family, never the (larger) union size.
    pub fn length(address: *const SocketAddress) linux.socklen_t {
        assert(address.in.family == linux.AF.INET or address.in.family == linux.AF.INET6);
        return switch (address.in.family) {
            linux.AF.INET => @sizeOf(linux.sockaddr.in),
            linux.AF.INET6 => @sizeOf(linux.sockaddr.in6),
            else => unreachable, // guarded by the assertion above
        };
    }

    /// Native-endian port, family-independent (both layouts lead with
    /// `family` then big-endian `port`). The simulator keys listeners by it.
    pub fn port(address: *const SocketAddress) u16 {
        assert(address.length() >= @sizeOf(linux.sockaddr.in));
        return std.mem.bigToNative(u16, address.in.port);
    }
};

// ---- tests ----------------------------------------------------------------

const testing = std.testing;

test "socket_address: v4 round-trips family, port, and bytes" {
    const ip = IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 0, 7 }, .port = 8443 } };
    const sa = SocketAddress.from_ip(ip);
    try testing.expectEqual(linux.AF.INET, sa.in.family);
    try testing.expectEqual(@as(linux.socklen_t, @sizeOf(linux.sockaddr.in)), sa.length());
    try testing.expectEqual(@as(u16, 8443), sa.port());
    try testing.expectEqual(@as(u32, @bitCast([4]u8{ 192, 168, 0, 7 })), sa.in.addr);
}

test "socket_address: v6 round-trips family, port, bytes, and scope" {
    const bytes = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const ip = IpAddress{ .ip6 = .{
        .bytes = bytes,
        .port = 9001,
        .flow = 3,
        .interface = .{ .index = 2 },
    } };
    const sa = SocketAddress.from_ip(ip);
    try testing.expectEqual(linux.AF.INET6, sa.in6.family);
    try testing.expectEqual(@as(linux.socklen_t, @sizeOf(linux.sockaddr.in6)), sa.length());
    try testing.expectEqual(@as(u16, 9001), sa.port());
    try testing.expectEqualSlices(u8, &bytes, &sa.in6.addr);
    try testing.expectEqual(@as(u32, 3), sa.in6.flowinfo);
    try testing.expectEqual(@as(u32, 2), sa.in6.scope_id);
}
