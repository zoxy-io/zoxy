//! What a name's answers become (#480, #481): its addresses in one order,
//! and a cluster's endpoints with any address that two entries yield kept
//! once. The startup front-end and the resolver that refreshes a name
//! while serving both call these, so a cluster's set is the same function
//! of its answers at either moment.

const std = @import("std");

const assert = std.debug.assert;

const IpAddress = std.Io.net.IpAddress;

/// Order addresses IPv4 first, then by their octets, then by port: the
/// order a resolver happens to answer in is not the set's, and two
/// processes, or two refreshes, with the same answers must agree.
pub fn sortAddresses(addresses: []IpAddress) void {
    std.sort.pdq(IpAddress, addresses, {}, addressLessThan);
    for (addresses[0..addresses.len -| 1], addresses[@min(1, addresses.len)..]) |*earlier, *later| {
        assert(orderAddresses(earlier, later) != .gt);
    }
}

fn addressLessThan(context: void, a: IpAddress, b: IpAddress) bool {
    _ = context;
    return orderAddresses(&a, &b) == .lt;
}

/// IPv4 before IPv6; within a family, by octets and then by port.
pub fn orderAddresses(a: *const IpAddress, b: *const IpAddress) std.math.Order {
    const by_family = std.math.order(@backingInt(a.*), @backingInt(b.*));
    if (by_family != .eq) return by_family;
    const by_bytes = switch (a.*) {
        .ip4 => |lhs| std.mem.order(u8, &lhs.bytes, &b.ip4.bytes),
        .ip6 => |lhs| std.mem.order(u8, &lhs.bytes, &b.ip6.bytes),
    };
    if (by_bytes != .eq) return by_bytes;
    return std.math.order(a.getPort(), b.getPort());
}

comptime {
    // The family order above rests on the tag's: IPv4's tag first.
    assert(@backingInt(IpAddress.Family.ip4) < @backingInt(IpAddress.Family.ip6));
}

/// Keep each address of `entries` once, in the order it first appears,
/// and return how many remain at the front. Of two entries naming one
/// address the kept one carries the lower standby tier, and at one tier
/// the higher weight: the stronger of two claims on one origin, since a
/// weaker one would demote an endpoint someone stated as primary.
///
/// `Entry` has `address`, `weight` and `priority`; its address compares
/// with `eql`. Quadratic in the entries, which a cluster pays once at
/// startup and once per refresh, bounded by its endpoint slots.
pub fn mergeDuplicates(comptime Entry: type, entries: []Entry) u32 {
    assert(entries.len <= std.math.maxInt(u32));
    var kept: u32 = 0;
    for (entries) |entry| {
        const earlier = for (entries[0..kept]) |*candidate| {
            if (candidate.address.eql(&entry.address)) break candidate;
        } else null;
        if (earlier) |held| {
            if (stronger(&entry, held)) {
                held.weight = entry.weight;
                held.priority = entry.priority;
            }
        } else {
            entries[kept] = entry;
            kept += 1;
        }
    }
    assert(kept <= entries.len);
    if (entries.len > 0) assert(kept >= 1);
    return kept;
}

fn stronger(candidate: anytype, held: anytype) bool {
    if (candidate.priority != held.priority) return candidate.priority < held.priority;
    return candidate.weight > held.weight;
}

const TestEntry = struct {
    address: IpAddress,
    weight: u16,
    priority: u8,
};

fn testAddress(literal: []const u8) IpAddress {
    return IpAddress.parseLiteral(literal) catch unreachable;
}

test "sortAddresses: IPv4 first, then octets, then port" {
    var addresses = [_]IpAddress{
        testAddress("[::1]:80"),
        testAddress("10.0.0.2:80"),
        testAddress("10.0.0.1:81"),
        testAddress("10.0.0.1:80"),
    };
    sortAddresses(&addresses);
    try std.testing.expect(addresses[0].eql(&testAddress("10.0.0.1:80")));
    try std.testing.expect(addresses[1].eql(&testAddress("10.0.0.1:81")));
    try std.testing.expect(addresses[2].eql(&testAddress("10.0.0.2:80")));
    try std.testing.expect(addresses[3].eql(&testAddress("[::1]:80")));
}

test "mergeDuplicates: one address kept once, its strongest claim winning" {
    var entries = [_]TestEntry{
        .{ .address = testAddress("10.0.0.1:80"), .weight = 1, .priority = 1 },
        .{ .address = testAddress("10.0.0.2:80"), .weight = 3, .priority = 0 },
        // A lower tier wins over a weight.
        .{ .address = testAddress("10.0.0.1:80"), .weight = 1, .priority = 0 },
        // At one tier, the higher weight wins; a lower one changes nothing.
        .{ .address = testAddress("10.0.0.2:80"), .weight = 5, .priority = 0 },
        .{ .address = testAddress("10.0.0.2:80"), .weight = 2, .priority = 0 },
        // Another port is another endpoint.
        .{ .address = testAddress("10.0.0.1:81"), .weight = 1, .priority = 0 },
    };
    const kept = mergeDuplicates(TestEntry, &entries);
    try std.testing.expectEqual(@as(u32, 3), kept);
    try std.testing.expect(entries[0].address.eql(&testAddress("10.0.0.1:80")));
    try std.testing.expectEqual(@as(u8, 0), entries[0].priority);
    try std.testing.expect(entries[1].address.eql(&testAddress("10.0.0.2:80")));
    try std.testing.expectEqual(@as(u16, 5), entries[1].weight);
    try std.testing.expect(entries[2].address.eql(&testAddress("10.0.0.1:81")));
}

test "mergeDuplicates: nothing to merge leaves the entries as they were" {
    var entries = [_]TestEntry{
        .{ .address = testAddress("10.0.0.1:80"), .weight = 1, .priority = 0 },
        .{ .address = testAddress("10.0.0.2:80"), .weight = 2, .priority = 1 },
    };
    try std.testing.expectEqual(@as(u32, 2), mergeDuplicates(TestEntry, &entries));
    try std.testing.expectEqual(@as(u16, 2), entries[1].weight);
    try std.testing.expectEqual(@as(u32, 0), mergeDuplicates(TestEntry, entries[0..0]));
}

test "fuzz: mergeDuplicates keeps every address once, with its strongest claim" {
    try std.testing.fuzz({}, fuzzMerge, .{});
}

fn fuzzMerge(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var entries: [32]TestEntry = undefined;
    var count: u32 = 0;
    while (count < entries.len and !smith.eos()) : (count += 1) {
        // Eight addresses on two ports, so duplicates are the common case.
        const octet = smith.valueRangeAtMost(u8, 0, 7);
        const port: u16 = if (smith.value(bool)) 80 else 81;
        entries[count] = .{
            .address = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, octet }, .port = port } },
            .weight = smith.valueRangeAtMost(u16, 0, 256),
            .priority = smith.valueRangeAtMost(u8, 0, 7),
        };
    }
    const input = entries;
    const kept = mergeDuplicates(TestEntry, entries[0..count]);
    assert(kept <= count);
    // Every kept address once, and every input address kept, holding the
    // strongest claim any entry made on it.
    for (entries[0..kept], 0..) |*entry, index| {
        for (entries[index + 1 .. kept]) |*later| assert(!later.address.eql(&entry.address));
    }
    for (input[0..count]) |*stated| {
        const held = for (entries[0..kept]) |*entry| {
            if (entry.address.eql(&stated.address)) break entry;
        } else unreachable;
        assert(!stronger(stated, held));
    }
    // A merged set merges to itself.
    assert(mergeDuplicates(TestEntry, entries[0..kept]) == kept);
}
