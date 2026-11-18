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

const zssl = @import("zssl");

const constants = @import("../constants.zig");
const client_hello = @import("../net/client_hello.zig");
const Credentials = @import("Credentials.zig");

const SignatureScheme = zssl.backend.SignatureScheme;

const assert = std.debug.assert;

/// One certificate a listener can present, the DNS names it covers, and
/// what its key can sign under.
pub const Choice = struct {
    credentials: *const Credentials,
    /// Lowercase, from the leaf's subjectAltName (`trust.dnsNames`).
    names: []const []const u8,
    /// `Credentials.schemes`: one ECDSA scheme, or three RSA-PSS (#411).
    schemes: []const SignatureScheme,
};

/// How a certificate came to cover the name asked for, in the order the
/// tiers are tried.
const Tier = enum { exact, wildcard, default };

/// The index of the certificate to present for this ClientHello.
///
/// By name first (#297): an exact name across every certificate, then a
/// single-label wildcard (`*.example.com` covers `api.example.com`, never
/// `example.com` or `a.b.example.com` — RFC 9525 §6.3), then the default
/// at index 0, which is also what a client naming nothing gets.
///
/// Within a tier, by what the client can verify (#411): only a
/// certificate whose key signs under a scheme the hello offered is
/// usable, and among those an ECDSA key beats an RSA one — the loop pays
/// ~0.5 ms or more for an RSA sign and ~15 µs for P-256 — then list order.
/// A tier with nothing usable passes to the next. If no tier has anything
/// usable, the answer is the best name match regardless, and zssl refuses
/// the handshake for want of a common scheme: an honest failure rather
/// than a certificate the client never asked for.
pub fn select(choices: []const Choice, hello: *const client_hello.Hello) usize {
    assert(choices.len >= 1);
    // The loops below are bounded by what the loader admitted: a set is
    // at most the process's certificates, each at most its names cap.
    assert(choices.len <= constants.tls_certificates_max);
    for (choices) |choice| assert(choice.names.len <= constants.tls_certificate_names_max);
    // An empty name names nothing, the same as no extension at all.
    var name: ?[]const u8 = hello.server_name;
    if (name) |named| {
        if (named.len == 0) name = null;
    }
    var fallback: ?usize = null;
    for ([_]Tier{ .exact, .wildcard, .default }) |tier| {
        var best: ?usize = null;
        var best_cost: u8 = std.math.maxInt(u8);
        for (choices, 0..) |*choice, index| {
            if (!covers(choice, index, tier, name)) continue;
            if (fallback == null) fallback = index;
            if (!usable(choice, hello)) continue;
            // Strictly cheaper only, so list order breaks a tie.
            if (cost(choice) >= best_cost) continue;
            best = index;
            best_cost = cost(choice);
        }
        if (best) |index| return index;
    }
    // The default tier always covers index 0, so a match was seen.
    assert(fallback != null);
    return fallback.?;
}

fn covers(choice: *const Choice, index: usize, tier: Tier, name: ?[]const u8) bool {
    assert(choice.names.len <= constants.tls_certificate_names_max);
    switch (tier) {
        .default => return index == 0,
        .exact, .wildcard => {
            const asked = name orelse return false;
            assert(asked.len >= 1);
            for (choice.names) |covered| {
                const hit = switch (tier) {
                    .exact => std.ascii.eqlIgnoreCase(covered, asked),
                    .wildcard => wildcardCovers(covered, asked),
                    .default => unreachable,
                };
                if (hit) return true;
            }
            return false;
        },
    }
}

/// Whether the client offered a scheme this certificate's key signs under.
fn usable(choice: *const Choice, hello: *const client_hello.Hello) bool {
    assert(choice.schemes.len >= 1);
    for (choice.schemes) |scheme| {
        if (hello.offersScheme(@backingInt(scheme))) return true;
    }
    return false;
}

/// What a handshake on this certificate costs the loop, as an order: an
/// ECDSA sign is two orders cheaper than an RSA one.
fn cost(choice: *const Choice) u8 {
    assert(choice.schemes.len >= 1);
    return switch (choice.schemes[0].keyKind()) {
        .ecdsa => 0,
        .rsa => 1,
    };
}

/// `*.rest` covers exactly one label in front of `rest`.
fn wildcardCovers(pattern: []const u8, name: []const u8) bool {
    if (pattern.len < 3 or !std.mem.startsWith(u8, pattern, "*.")) return false;
    assert(pattern.len >= 3);
    const dot = std.mem.indexOfScalar(u8, name, '.') orelse return false;
    if (dot == 0) return false;
    return std.ascii.eqlIgnoreCase(pattern[2..], name[dot + 1 ..]);
}

/// A hello naming `name` and offering `schemes`, for the tests.
fn testHello(name: ?[]const u8, schemes: []const u8) client_hello.Hello {
    return .{ .server_name = name, .signature_algorithms = if (schemes.len == 0) null else schemes };
}

/// ecdsa_secp256r1_sha256 and rsa_pss_rsae_sha256: what RFC 8446 §9.1
/// makes every client offer.
const offers_both = [_]u8{ 0x04, 0x03, 0x08, 0x04 };
const offers_rsa = [_]u8{ 0x08, 0x04 };
const offers_ecdsa = [_]u8{ 0x04, 0x03 };

test "certificate_set: exact names first, then one-label wildcards, then the default (#297)" {
    var credentials: Credentials = undefined;
    const ecdsa: []const SignatureScheme = &.{.ecdsa_secp256r1_sha256};
    const choices = [_]Choice{
        .{ .credentials = &credentials, .names = &.{"default.example"}, .schemes = ecdsa },
        .{ .credentials = &credentials, .names = &.{ "api.example.com", "*.example.com" }, .schemes = ecdsa },
        .{ .credentials = &credentials, .names = &.{"www.example.com"}, .schemes = ecdsa },
    };
    const cases = [_]struct { name: ?[]const u8, chosen: usize }{
        .{ .name = "api.example.com", .chosen = 1 },
        // An exact name anywhere beats a wildcard earlier in the list.
        .{ .name = "www.example.com", .chosen = 2 },
        .{ .name = "img.example.com", .chosen = 1 },
        .{ .name = "IMG.Example.COM", .chosen = 1 },
        // A wildcard covers one label: not the apex, not two deep.
        .{ .name = "example.com", .chosen = 0 },
        .{ .name = "a.b.example.com", .chosen = 0 },
        // Nothing named, or nothing covered: the default.
        .{ .name = null, .chosen = 0 },
        .{ .name = "other.test", .chosen = 0 },
    };
    for (cases) |case| {
        const hello = testHello(case.name, &offers_both);
        try std.testing.expectEqual(case.chosen, select(&choices, &hello));
    }
}

test "certificate_set: within a tier, what the client can verify, ECDSA before RSA (#411)" {
    var credentials: Credentials = undefined;
    const ecdsa: []const SignatureScheme = &.{.ecdsa_secp256r1_sha256};
    const rsa: []const SignatureScheme = &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 };
    const choices = [_]Choice{
        .{ .credentials = &credentials, .names = &.{"default.example"}, .schemes = ecdsa },
        // RSA listed first for the name, ECDSA second: cost, not order, wins.
        .{ .credentials = &credentials, .names = &.{"api.example.com"}, .schemes = rsa },
        .{ .credentials = &credentials, .names = &.{"api.example.com"}, .schemes = ecdsa },
        .{ .credentials = &credentials, .names = &.{"*.example.com"}, .schemes = rsa },
        .{ .credentials = &credentials, .names = &.{"rsa.example.com"}, .schemes = rsa },
        .{ .credentials = &credentials, .names = &.{"ecdsa.example.com"}, .schemes = ecdsa },
    };
    const cases = [_]struct { name: ?[]const u8, offers: []const u8, chosen: usize }{
        .{ .name = "api.example.com", .offers = &offers_both, .chosen = 2 },
        .{ .name = "api.example.com", .offers = &offers_rsa, .chosen = 1 },
        .{ .name = "api.example.com", .offers = &offers_ecdsa, .chosen = 2 },
        // RSA only where the name has nothing else.
        .{ .name = "rsa.example.com", .offers = &offers_both, .chosen = 4 },
        .{ .name = "img.example.com", .offers = &offers_rsa, .chosen = 3 },
        // An exact tier with nothing verifiable passes to the wildcard.
        .{ .name = "ecdsa.example.com", .offers = &offers_rsa, .chosen = 3 },
        .{ .name = "ecdsa.example.com", .offers = &offers_both, .chosen = 5 },
        // An RSA-only client naming nothing the RSA keys cover: nothing
        // usable anywhere, so the best name match, and zssl refuses.
        .{ .name = "other.test", .offers = &offers_rsa, .chosen = 0 },
        // No list at all offers nothing: the name decides, as in #297.
        .{ .name = "api.example.com", .offers = &.{}, .chosen = 1 },
    };
    for (cases) |case| {
        const hello = testHello(case.name, case.offers);
        try std.testing.expectEqual(case.chosen, select(&choices, &hello));
    }
}
