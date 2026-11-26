//! A DNS name as an endpoint names its origin (#480, #481): what spelling
//! counts as one, the canonical form every later step compares, and
//! which of a name's addresses an endpoint takes.
//!
//! The canonical form is lowercase, without the root's trailing dot: DNS
//! compares names without regard to ASCII case (RFC 4343), and `api.` and
//! `api` name one host to every resolver zoxy asks. One form, so a name
//! spelled two ways is one name to the loader, the banner and the
//! resolver alike.

const std = @import("std");

const constants = @import("../constants.zig");

const assert = std.debug.assert;

const host_bytes_max = constants.dns_host_bytes_max;
const label_bytes_max = constants.dns_label_bytes_max;

/// Which of a name's addresses become endpoints.
pub const Family = enum {
    /// A records alone: the default, since an origin listening on IPv4
    /// alone is the common case, and an AAAA answer it never listens on
    /// would fail a share of every cluster's dials.
    ipv4,
    /// AAAA records alone.
    ipv6,
    /// Both.
    any,

    pub fn admits(family: Family, address: *const std.Io.net.IpAddress) bool {
        return switch (family) {
            .ipv4 => address.* == .ip4,
            .ipv6 => address.* == .ip6,
            .any => true,
        };
    }
};

/// `spelled` in canonical form, written into `buffer` — or null when it
/// is no host name.
pub fn canonical(buffer: *[host_bytes_max]u8, spelled: []const u8) ?[]const u8 {
    if (spelled.len == 0) return null;
    // One trailing dot names the root, which every name ends in anyway.
    const bare = if (spelled[spelled.len - 1] == '.') spelled[0 .. spelled.len - 1] else spelled;
    if (bare.len == 0) return null;
    if (bare.len > host_bytes_max) return null;
    const lowered = std.ascii.lowerString(buffer[0..bare.len], bare);
    assert(lowered.len == bare.len);
    if (!isCanonical(lowered)) return null;
    return lowered;
}

/// Whether `host` is a name in canonical form: labels of letters, digits,
/// hyphens and underscores, none empty, none past 63 octets, none
/// starting or ending with a hyphen; at most 253 octets in all; and a
/// last label that is not all digits, which is a mistyped address rather
/// than a name and must not reach a resolver as one.
///
/// Underscores go past RFC 1123's host names because names in use carry
/// them — a Compose service, an internal zone — and DNS itself allows any
/// octet in a label.
pub fn isCanonical(host: []const u8) bool {
    if (host.len == 0) return false;
    if (host.len > host_bytes_max) return false;
    var labels = std.mem.splitScalar(u8, host, '.');
    var last: []const u8 = "";
    var count: u32 = 0;
    while (labels.next()) |label| : (count += 1) {
        assert(count <= host_bytes_max);
        if (!isLabel(label)) return false;
        last = label;
    }
    assert(count >= 1);
    assert(last.len >= 1);
    for (last) |byte| {
        if (!std.ascii.isDigit(byte)) return true;
    }
    return false;
}

fn isLabel(label: []const u8) bool {
    if (label.len == 0) return false;
    if (label.len > label_bytes_max) return false;
    if (label[0] == '-') return false;
    if (label[label.len - 1] == '-') return false;
    for (label) |byte| {
        const allowed = std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-' or byte == '_';
        if (!allowed) return false;
    }
    return true;
}

test "canonical: lowercased, the root's dot dropped, and refused when it is no name" {
    var buffer: [host_bytes_max]u8 = undefined;
    try std.testing.expectEqualStrings("api.internal", canonical(&buffer, "API.Internal.").?);
    try std.testing.expectEqualStrings("localhost", canonical(&buffer, "localhost").?);
    try std.testing.expectEqualStrings("my_service", canonical(&buffer, "my_service").?);
    try std.testing.expectEqualStrings("a-1.b2.c", canonical(&buffer, "a-1.b2.c").?);
    try std.testing.expect(canonical(&buffer, "") == null);
    try std.testing.expect(canonical(&buffer, ".") == null);
    try std.testing.expect(canonical(&buffer, "api..internal") == null);
    try std.testing.expect(canonical(&buffer, "-api.internal") == null);
    try std.testing.expect(canonical(&buffer, "api-.internal") == null);
    try std.testing.expect(canonical(&buffer, "api internal") == null);
    try std.testing.expect(canonical(&buffer, "::1") == null);
    // A mistyped address is no name: its last label is all digits.
    try std.testing.expect(canonical(&buffer, "10.0.0.256") == null);
    try std.testing.expect(canonical(&buffer, "10.0.0.1a") != null);
}

test "canonical: the label and name bounds" {
    var buffer: [host_bytes_max]u8 = undefined;
    const label_max: [label_bytes_max]u8 = @splat('a');
    const label_short: [61]u8 = @splat('a');
    try std.testing.expect(canonical(&buffer, &label_max) != null);
    try std.testing.expect(canonical(&buffer, label_max ++ "a") == null);
    // Four labels of 63 and three dots: 255 octets, past the bound.
    const long = label_max ++ "." ++ label_max ++ "." ++ label_max ++ "." ++ label_max;
    try std.testing.expect(long.len == 255);
    try std.testing.expect(canonical(&buffer, long) == null);
    const fits = label_max ++ "." ++ label_max ++ "." ++ label_max ++ "." ++ label_short;
    try std.testing.expect(fits.len == host_bytes_max);
    try std.testing.expect(canonical(&buffer, fits) != null);
}

test "Family.admits: each family takes its own addresses" {
    const four = try std.Io.net.IpAddress.parseLiteral("10.0.0.1:80");
    const six = try std.Io.net.IpAddress.parseLiteral("[::1]:80");
    try std.testing.expect(Family.ipv4.admits(&four));
    try std.testing.expect(!Family.ipv4.admits(&six));
    try std.testing.expect(Family.ipv6.admits(&six));
    try std.testing.expect(!Family.ipv6.admits(&four));
    try std.testing.expect(Family.any.admits(&four));
    try std.testing.expect(Family.any.admits(&six));
}

test "fuzz: canonical gives a name in canonical form or none, and again the same" {
    try std.testing.fuzz({}, fuzzCanonical, .{ .corpus = &.{ "API.Internal.", "a-1.b_2.c", "10.0.0.256", "x." } });
}

fn fuzzCanonical(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input: [host_bytes_max + 8]u8 = undefined;
    const input_len = smith.slice(&input);
    assert(input_len <= input.len);
    var buffer: [host_bytes_max]u8 = undefined;
    const name = canonical(&buffer, input[0..input_len]) orelse return;
    assert(name.len >= 1);
    assert(name.len <= host_bytes_max);
    assert(isCanonical(name));
    // Canonical is a fixed point: a canonical name is its own form.
    var again: [host_bytes_max]u8 = undefined;
    const twice = canonical(&again, name).?;
    assert(std.mem.eql(u8, name, twice));
}
