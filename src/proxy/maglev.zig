//! Maglev consistent hashing ("Maglev: A Fast and Reliable Software Network
//! Load Balancer", Eisenbud et al., §3.4). Each hashed cluster gets a fixed
//! prime-sized lookup table built once at config time: every endpoint fills
//! slots along its own permutation of the table, taking turns, so the table
//! is near-perfectly balanced and endpoint changes disturb few slots. The
//! data path does one hash and one array index — no allocation, no search.
//!
//! This module knows nothing about config or the balancer: it maps endpoint
//! *addresses* to a table of endpoint indices, and keys to hashes.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Ip4Address = std.Io.net.Ip4Address;
const IpAddress = std.Io.net.IpAddress;

/// Seeds for the two permutation hashes and the lookup-key hash. Arbitrary
/// but fixed: every worker (and every restarted process) must build the
/// same table and hash keys identically, or affinity breaks across them.
const seed_offset: u64 = 0x2545f4914f6cdd1d;
const seed_skip: u64 = 0x9e3779b97f4a7c15;
const seed_key: u64 = 0;

comptime {
    // The permutation `(offset + next * skip) % entries` visits every slot
    // exactly once only when `entries` is prime.
    assert(is_prime(constants.maglev_table_entries));
    // Strictly below: maxInt(u8) is the build loop's "unclaimed" sentinel.
    assert(constants.endpoints_per_cluster_max < std.math.maxInt(u8));
}

fn is_prime(n: u32) bool {
    if (n < 2) return false;
    var divisor: u32 = 2;
    while (divisor * divisor <= n) : (divisor += 1) {
        if (n % divisor == 0) return false;
    }
    return true;
}

/// Hash a request's affinity key (target, or a header value).
pub fn hash_key(key: []const u8) u64 {
    assert(key.len > 0); // callers fall back to P2C when there is no key
    return std.hash.Wyhash.hash(seed_key, key);
}

/// The data-path lookup: one modulo, one index.
pub fn lookup(table: []const u8, hash: u64) u8 {
    assert(table.len == constants.maglev_table_entries);
    return table[hash % table.len];
}

/// Fill `table` with endpoint indices, each endpoint claiming slots along
/// its own (offset, skip) permutation in round-robin turns — the classic
/// Maglev population loop. Deterministic in the endpoint addresses.
pub fn build(addresses: []const IpAddress, table: []u8) void {
    assert(table.len == constants.maglev_table_entries);
    assert(addresses.len >= 1);
    assert(addresses.len <= constants.endpoints_per_cluster_max);
    const entries: u64 = table.len;

    var offsets: [constants.endpoints_per_cluster_max]u64 = undefined;
    var skips: [constants.endpoints_per_cluster_max]u64 = undefined;
    var next: [constants.endpoints_per_cluster_max]u64 = @splat(0);
    for (addresses, 0..) |address, index| {
        const key = address_key(address);
        offsets[index] = std.hash.Wyhash.hash(seed_offset, key.slice()) % entries;
        skips[index] = std.hash.Wyhash.hash(seed_skip, key.slice()) % (entries - 1) + 1;
        assert(skips[index] >= 1); // a zero skip would never advance
        assert(skips[index] < entries);
    }

    const unclaimed: u8 = std.math.maxInt(u8);
    @memset(table, unclaimed);
    var filled: u64 = 0;
    // Each endpoint's permutation visits every slot exactly once (prime
    // table), so each endpoint's cursor advances at most `entries` times:
    // the total work is bounded by endpoints x entries.
    var turns: u64 = 0;
    const turns_max = entries * @as(u64, @intCast(addresses.len)) + 1;
    outer: while (filled < entries) {
        for (addresses, 0..) |_, index| {
            turns += 1;
            assert(turns <= turns_max); // the permutation argument above
            var slot = (offsets[index] + next[index] * skips[index]) % entries;
            while (table[slot] != unclaimed) {
                next[index] += 1;
                assert(next[index] < entries); // ran out: impossible while slots remain
                slot = (offsets[index] + next[index] * skips[index]) % entries;
            }
            table[slot] = @intCast(index);
            next[index] += 1;
            filled += 1;
            if (filled == entries) break :outer;
        }
    }
    assert(filled == entries);
}

/// The bytes an endpoint's permutation is derived from. A v4 address keys
/// exactly as it always has (6 bytes: address + port) so pre-IPv6 tables —
/// and with them, fleet-wide affinity — never reshuffle; a v6 address keys
/// on its full 18 bytes, which can never collide with a 6-byte v4 key.
const AddressKey = struct {
    bytes: [18]u8,
    len: u8,

    fn slice(key: *const AddressKey) []const u8 {
        assert(key.len == 6 or key.len == 18);
        return key.bytes[0..key.len];
    }
};

fn address_key(address: IpAddress) AddressKey {
    var key = AddressKey{ .bytes = @splat(0), .len = 0 };
    switch (address) {
        .ip4 => |ip4| {
            key.bytes[0..4].* = ip4.bytes;
            std.mem.writeInt(u16, key.bytes[4..6], ip4.port, .big);
            key.len = 6;
        },
        .ip6 => |ip6| {
            key.bytes[0..16].* = ip6.bytes;
            std.mem.writeInt(u16, key.bytes[16..18], ip6.port, .big);
            key.len = 18;
        },
    }
    return key;
}

// ---- tests ------------------------------------------------------------------

const testing = std.testing;

fn test_addresses(count: u32) [constants.endpoints_per_cluster_max]IpAddress {
    assert(count <= constants.endpoints_per_cluster_max);
    var addresses: [constants.endpoints_per_cluster_max]IpAddress = undefined;
    for (addresses[0..count], 0..) |*address, index| {
        address.* = .{ .ip4 = Ip4Address.loopback(@intCast(9000 + index)) };
    }
    return addresses;
}

test "maglev: every slot is claimed and the table is near-perfectly balanced" {
    const gpa = testing.allocator;
    const table = try gpa.alloc(u8, constants.maglev_table_entries);
    defer gpa.free(table);

    const addresses = test_addresses(5);
    build(addresses[0..5], table);

    var counts = [_]u64{0} ** 5;
    for (table) |entry| {
        try testing.expect(entry < 5);
        counts[entry] += 1;
    }
    // Maglev's population loop guarantees per-endpoint shares within one
    // turn of each other-ish; allow 1% slack around the perfect fifth.
    const perfect = constants.maglev_table_entries / 5;
    for (counts) |count| {
        try testing.expect(count > perfect - perfect / 100);
        try testing.expect(count < perfect + perfect / 100);
    }
}

test "maglev: identical inputs build identical tables (workers must agree)" {
    const gpa = testing.allocator;
    const first = try gpa.alloc(u8, constants.maglev_table_entries);
    defer gpa.free(first);
    const second = try gpa.alloc(u8, constants.maglev_table_entries);
    defer gpa.free(second);

    const addresses = test_addresses(7);
    build(addresses[0..7], first);
    build(addresses[0..7], second);
    try testing.expect(std.mem.eql(u8, first, second));
}

test "maglev: removing an endpoint disturbs few of the surviving slots" {
    const gpa = testing.allocator;
    const with = try gpa.alloc(u8, constants.maglev_table_entries);
    defer gpa.free(with);
    const without = try gpa.alloc(u8, constants.maglev_table_entries);
    defer gpa.free(without);

    const addresses = test_addresses(4);
    build(addresses[0..4], with);
    build(addresses[0..3], without); // endpoint 3 removed

    // Slots that did not belong to the removed endpoint should mostly keep
    // their assignment — that is the consistency being paid for.
    var surviving: u64 = 0;
    var moved: u64 = 0;
    for (with, without) |before, after| {
        if (before == 3) continue; // its slots must move somewhere
        surviving += 1;
        if (before != after) moved += 1;
    }
    try testing.expect(surviving > 0);
    try testing.expect(moved * 100 / surviving < 5); // < 5% of survivors moved
}

test "maglev: a single endpoint claims the whole table" {
    const gpa = testing.allocator;
    const table = try gpa.alloc(u8, constants.maglev_table_entries);
    defer gpa.free(table);
    const addresses = test_addresses(1);
    build(addresses[0..1], table);
    for (table) |entry| try testing.expectEqual(@as(u8, 0), entry);
    try testing.expectEqual(@as(u8, 0), lookup(table, hash_key("/any/target")));
}

test "maglev: mixed v4/v6 endpoints fill a balanced, deterministic table" {
    const gpa = testing.allocator;
    const first = try gpa.alloc(u8, constants.maglev_table_entries);
    defer gpa.free(first);
    const second = try gpa.alloc(u8, constants.maglev_table_entries);
    defer gpa.free(second);

    const addresses = [3]IpAddress{
        .{ .ip4 = Ip4Address.loopback(9000) },
        .{ .ip6 = std.Io.net.Ip6Address.loopback(9000) },
        .{ .ip6 = .{
            .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 },
            .port = 9001,
        } },
    };
    build(&addresses, first);
    build(&addresses, second);
    try testing.expect(std.mem.eql(u8, first, second));

    var counts = [_]u64{0} ** 3;
    for (first) |entry| {
        try testing.expect(entry < 3);
        counts[entry] += 1;
    }
    // Same port on v4 and v6 loopback must still key differently: every
    // endpoint owns a substantial share.
    for (counts) |count| try testing.expect(count > constants.maglev_table_entries / 4);
}

test "maglev: the key hash is stable and spreads distinct keys" {
    const first = hash_key("/users/1234");
    try testing.expectEqual(first, hash_key("/users/1234")); // affinity
    try testing.expect(first != hash_key("/users/1235"));
}
