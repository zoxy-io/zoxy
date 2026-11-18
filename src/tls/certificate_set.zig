//! Choosing a listener's certificate by the name the client asked for
//! (#297). A listener may hold several certificates; the first is its
//! default — what a client that names nothing, or names something none of
//! them covers, is shown — and the rest are chosen by the ClientHello's
//! `server_name` (RFC 6066 §3) against each certificate's DNS names.
//!
//! Pure: names in, an index out. The engine reads the name off the first
//! record before zssl does (zssl has no selection hook of its own), and
//! asks this which certificate to start the handshake with.

const std = @import("std");

const constants = @import("../constants.zig");
const Credentials = @import("Credentials.zig");

const assert = std.debug.assert;

/// One certificate a listener can present, and the DNS names it covers.
pub const Choice = struct {
    credentials: *const Credentials,
    /// Lowercase, from the leaf's subjectAltName (`trust.dnsNames`).
    names: []const []const u8,
};

/// The index of the certificate to present for `server_name`: an exact
/// name first, across every certificate in order; then a single-label
/// wildcard (`*.example.com` covers `api.example.com`, never
/// `example.com` or `a.b.example.com` — RFC 9525 §6.3); otherwise the
/// default, index 0. A client that named nothing gets the default too.
pub fn select(choices: []const Choice, server_name: ?[]const u8) usize {
    assert(choices.len >= 1);
    // Both loops below are bounded by what the loader admitted: a set is
    // at most the process's certificates, each at most its names cap.
    assert(choices.len <= constants.tls_certificates_max);
    for (choices) |choice| assert(choice.names.len <= constants.tls_certificate_names_max);
    const name = server_name orelse return 0;
    if (name.len == 0) return 0;
    for (choices, 0..) |choice, index| {
        for (choice.names) |covered| {
            if (std.ascii.eqlIgnoreCase(covered, name)) return index;
        }
    }
    for (choices, 0..) |choice, index| {
        for (choice.names) |covered| {
            if (wildcardCovers(covered, name)) return index;
        }
    }
    return 0;
}

/// `*.rest` covers exactly one label in front of `rest`.
fn wildcardCovers(pattern: []const u8, name: []const u8) bool {
    if (pattern.len < 3 or !std.mem.startsWith(u8, pattern, "*.")) return false;
    assert(pattern.len >= 3);
    const dot = std.mem.indexOfScalar(u8, name, '.') orelse return false;
    if (dot == 0) return false;
    return std.ascii.eqlIgnoreCase(pattern[2..], name[dot + 1 ..]);
}

test "certificate_set: exact names first, then one-label wildcards, then the default (#297)" {
    var credentials: Credentials = undefined;
    const choices = [_]Choice{
        .{ .credentials = &credentials, .names = &.{"default.example"} },
        .{ .credentials = &credentials, .names = &.{ "api.example.com", "*.example.com" } },
        .{ .credentials = &credentials, .names = &.{"www.example.com"} },
    };
    try std.testing.expectEqual(@as(usize, 1), select(&choices, "api.example.com"));
    // An exact name anywhere beats a wildcard earlier in the list.
    try std.testing.expectEqual(@as(usize, 2), select(&choices, "www.example.com"));
    try std.testing.expectEqual(@as(usize, 1), select(&choices, "img.example.com"));
    try std.testing.expectEqual(@as(usize, 1), select(&choices, "IMG.Example.COM"));
    // A wildcard covers one label: not the apex, not two deep.
    try std.testing.expectEqual(@as(usize, 0), select(&choices, "example.com"));
    try std.testing.expectEqual(@as(usize, 0), select(&choices, "a.b.example.com"));
    // Nothing named, or nothing covered: the default.
    try std.testing.expectEqual(@as(usize, 0), select(&choices, null));
    try std.testing.expectEqual(@as(usize, 0), select(&choices, "other.test"));
}
