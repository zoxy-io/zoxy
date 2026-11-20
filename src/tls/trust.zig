//! An origin's certificate chain, judged against the trust anchors its
//! cluster names (§7; #296's verification half, for HTTP/2 origins).
//!
//! A TLS client that does not verify is worse than plaintext — it claims a
//! guarantee it does not give — so a cluster that speaks TLS names its
//! anchors and the name its origins must prove, and every handshake is
//! held to both:
//!
//! - every certificate in the chain is framed soundly (`zssl.der_bounds`)
//!   before `std.crypto.Certificate` reads it, because a peer chooses the
//!   bytes and a length that points past the end is a panic there, not an
//!   error;
//! - the leaf carries the name in a subjectAltName: RFC 9525 §6.3 forbids
//!   falling back to the common name, which `verifyHostName` would do;
//! - each certificate is signed by the next and inside its validity
//!   window, and each one that signs another is a CA — basicConstraints
//!   `cA` TRUE, which std does not check, and without which any leaf for
//!   any name could vouch for another;
//! - the chain ends at an anchor: the last certificate *is* one, or one
//!   that is a CA signed it.
//!
//! No allocation: the anchors are parsed once, at load, into the config's
//! arena, and a handshake's verdict reads them and the chain in place.

const std = @import("std");
const zssl = @import("zssl");

const constants = @import("../constants.zig");

const Certificate = std.crypto.Certificate;
const assert = std.debug.assert;

pub const anchors_max = constants.origin_anchors_max;
pub const chain_max = constants.origin_chain_max;
pub const certificate_bytes_max = constants.origin_certificate_bytes_max;

/// A TBSCertificate has at most ten fields (RFC 5280 §4.1): version,
/// serial, signature, issuer, validity, subject, key, two unique IDs and
/// the extensions.
const tbs_fields_max: u32 = 10;

/// What one certificate's extensions are walked to: past it, a
/// certificate is one this file does not judge to be a CA.
const extensions_max: u32 = 64;

pub const ParseError = error{
    /// No certificate in the bundle, or a block that does not decode or
    /// parse as one.
    AnchorsInvalid,
    AnchorsTooMany,
    OutOfMemory,
};

/// Every `CERTIFICATE` block of a PEM bundle, decoded to DER in `arena`
/// and checked to parse. Text outside the blocks is skipped, as every PEM
/// reader does; a block of another label is refused, since a key in a
/// trust bundle is a mistake worth hearing about.
pub fn parseAnchors(arena: std.mem.Allocator, pem: []const u8) ParseError![]const []const u8 {
    try rejectOtherBlocks(pem);
    var anchors: std.ArrayList([]const u8) = .empty;
    var rest = pem;
    const decoder = std.base64.Base64DecoderWithIgnore.init(std.base64.standard_alphabet_chars, '=', " \t\r\n");
    var blocks: u32 = 0;
    while (blocks <= anchors_max) : (blocks += 1) {
        const begin_at = std.mem.indexOf(u8, rest, begin_marker) orelse break;
        if (blocks == anchors_max) return error.AnchorsTooMany;
        const body_start = rest[begin_at + begin_marker.len ..];
        const end_at = std.mem.indexOf(u8, body_start, end_marker) orelse return error.AnchorsInvalid;
        const body = body_start[0..end_at];
        rest = body_start[end_at + end_marker.len ..];
        const bound = decoder.calcSizeUpperBound(body.len);
        if (bound == 0 or bound > certificate_bytes_max) return error.AnchorsInvalid;
        const der = try arena.alloc(u8, bound);
        const length = decoder.decode(der, body) catch return error.AnchorsInvalid;
        if (!wellFormed(der[0..length])) return error.AnchorsInvalid;
        try anchors.append(arena, der[0..length]);
    }
    if (anchors.items.len == 0) return error.AnchorsInvalid;
    assert(anchors.items.len <= anchors_max);
    return anchors.items;
}

const begin_marker = "-----BEGIN CERTIFICATE-----";
const end_marker = "-----END CERTIFICATE-----";

/// Any armored block that is not a certificate makes the bundle invalid.
fn rejectOtherBlocks(pem: []const u8) ParseError!void {
    const any_begin = "-----BEGIN ";
    var rest = pem;
    var blocks: u32 = 0;
    while (std.mem.indexOf(u8, rest, any_begin)) |at| : (blocks += 1) {
        if (blocks > anchors_max) return error.AnchorsTooMany;
        if (!std.mem.startsWith(u8, rest[at..], begin_marker)) return error.AnchorsInvalid;
        rest = rest[at + any_begin.len ..];
    }
}

/// Framed soundly and parsed by std: what every certificate this file
/// reads must be before anything else is asked of it.
fn wellFormed(der: []const u8) bool {
    assert(certificate_bytes_max >= 1);
    if (der.len == 0 or der.len > certificate_bytes_max) return false;
    zssl.der_bounds.validate(der) catch return false;
    const certificate: Certificate = .{ .buffer = der, .index = 0 };
    _ = certificate.parse() catch return false;
    return true;
}

fn parsed(der: []const u8) ?Certificate.Parsed {
    if (!wellFormed(der)) return null;
    const certificate: Certificate = .{ .buffer = der, .index = 0 };
    return certificate.parse() catch null;
}

/// The verdict on a chain, leaf first, for `server_name` at `now_sec`.
pub fn verifyChain(
    anchors: []const []const u8,
    chain: []const []const u8,
    server_name: []const u8,
    now_sec: i64,
) bool {
    assert(anchors.len >= 1);
    assert(server_name.len >= 1);
    if (chain.len == 0 or chain.len > chain_max) return false;
    var certificates: [chain_max]Certificate.Parsed = undefined;
    for (chain, 0..) |der, index| certificates[index] = parsed(der) orelse return false;
    const leaf = certificates[0];
    // RFC 9525 §6.3: the name is matched in the subjectAltName alone.
    if (leaf.subjectAltName().len == 0) return false;
    leaf.verifyHostName(server_name) catch return false;
    return pathVerifies(anchors, chain, &certificates, now_sec);
}

/// The verdict on a *client's* chain, leaf first, at `now_sec` (#304).
/// The server's path rules exactly, without a name: a client
/// certificate names no host this proxy could have asked for, so the
/// identity is the certificate itself (`leafFingerprint`). Extended
/// key usage is not read — a CA trusted here for clients should issue
/// only client certificates, and DESIGN §4 says so where `client_ca`
/// is configured.
pub fn verifyClientChain(
    anchors: []const []const u8,
    chain: []const []const u8,
    now_sec: i64,
) bool {
    assert(anchors.len >= 1);
    assert(anchors.len <= anchors_max);
    if (chain.len == 0 or chain.len > chain_max) return false;
    var certificates: [chain_max]Certificate.Parsed = undefined;
    for (chain, 0..) |der, index| certificates[index] = parsed(der) orelse return false;
    // A CA presenting itself as a client is a key that signs other
    // identities, not an identity: an end-entity leaf only.
    if (isCa(certificates[0])) return false;
    return pathVerifies(anchors, chain, &certificates, now_sec);
}

/// The bytes that name a verified client (#304): SHA-256 over the leaf's
/// DER. Fixed width and allocation-free, so it fits a per-connection
/// slot and a header without a bound to argue; unambiguous where a
/// subject DN is not (two CAs may issue the same DN); and the form
/// operators already pin with (`openssl x509 -fingerprint -sha256`).
pub const fingerprint_bytes = std.crypto.hash.sha2.Sha256.digest_length;

pub fn leafFingerprint(leaf_der: []const u8) [fingerprint_bytes]u8 {
    assert(leaf_der.len >= 1);
    assert(leaf_der.len <= certificate_bytes_max);
    var digest: [fingerprint_bytes]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(leaf_der, &digest, .{});
    return digest;
}

/// The DNS names a leaf certificate covers, lowercased, in the order its
/// subjectAltName lists them (#297) — what a listener with several
/// certificates selects one by. Other name kinds (IP, email, URI) are
/// skipped: a server name in a ClientHello is a DNS name (RFC 6066 §3).
/// Allocates into the startup arena; never on the serving path.
pub fn dnsNames(
    arena: std.mem.Allocator,
    leaf_der: []const u8,
) error{ CertificateInvalid, NamesTooMany, OutOfMemory }![]const []const u8 {
    const leaf = parsed(leaf_der) orelse return error.CertificateInvalid;
    const san = leaf.subjectAltName();
    if (san.len == 0) return &.{};
    const general_names = Tlv.read(san, 0, san.len) orelse return error.CertificateInvalid;
    var names: std.ArrayList([]const u8) = .empty;
    var cursor = general_names.start;
    var seen: u32 = 0;
    while (cursor < general_names.end) : (seen += 1) {
        if (seen == constants.tls_certificate_names_max) return error.NamesTooMany;
        const name = Tlv.read(san, cursor, general_names.end) orelse return error.CertificateInvalid;
        assert(name.end > cursor);
        cursor = name.end;
        // `[2] IMPLICIT IA5String`: a dNSName (RFC 5280 §4.2.1.6).
        if (name.tag != 0x82 or name.end == name.start) continue;
        try names.append(arena, try std.ascii.allocLowerString(arena, san[name.start..name.end]));
    }
    assert(names.items.len <= constants.tls_certificate_names_max);
    return names.items;
}

/// A verified client leaf's names (#432): its subjectAltName URIs and DNS
/// names in the leaf's order, copied into fixed storage — they outlive the
/// handshake bytes they were read from — up to `client_cert_names_max` of
/// them within `client_cert_names_bytes_max` bytes. The kept names are a
/// prefix of the leaf's: the first that does not fit ends them, and
/// `truncated` says so, so a policy that needs every name knows it does
/// not have them.
pub const ClientNames = struct {
    bytes: [constants.client_cert_names_bytes_max]u8 = undefined,
    entries: [constants.client_cert_names_max]Entry = undefined,
    count: u8 = 0,
    bytes_used: u16 = 0,
    truncated: bool = false,

    pub const Kind = enum(u8) { uri, dns };

    pub const Entry = struct {
        kind: Kind,
        start: u16,
        len: u16,
    };

    /// The bytes of entry `index`, valid as long as these names are.
    pub fn value(names: *const ClientNames, index: usize) []const u8 {
        assert(index < names.count);
        const entry = names.entries[index];
        assert(entry.start + entry.len <= names.bytes_used);
        return names.bytes[entry.start..][0..entry.len];
    }

    fn keep(names: *ClientNames, kind: Kind, name: []const u8) void {
        assert(name.len >= 1);
        if (names.count == names.entries.len or name.len > names.bytes.len - names.bytes_used) {
            names.truncated = true;
            return;
        }
        // A DNS name compares without regard to case (RFC 4343), so it is
        // kept lowercased, as #297's selection reads one; a URI as given.
        const kept = names.bytes[names.bytes_used..][0..name.len];
        switch (kind) {
            .uri => @memcpy(kept, name),
            .dns => for (kept, name) |*byte, original| {
                byte.* = std.ascii.toLower(original);
            },
        }
        names.entries[names.count] = .{ .kind = kind, .start = names.bytes_used, .len = @intCast(name.len) };
        names.count += 1;
        names.bytes_used += @intCast(name.len);
    }
};

/// Read a verified client leaf's URI and DNS names into `names` (#432).
/// The leaf already verified, so its framing is sound, but its extension
/// contents are read with explicit bounds all the same: a name that does
/// not frame ends the read, and is reported as a truncation — the names
/// kept are still the leaf's, and a policy is told it may lack some.
pub fn clientNames(leaf_der: []const u8, names: *ClientNames) void {
    names.* = .{};
    const leaf = parsed(leaf_der) orelse {
        names.truncated = true;
        return;
    };
    const san = leaf.subjectAltName();
    if (san.len == 0) return;
    const general_names = Tlv.read(san, 0, san.len) orelse {
        names.truncated = true;
        return;
    };
    var cursor = general_names.start;
    var seen: u32 = 0;
    while (cursor < general_names.end) : (seen += 1) {
        if (seen == constants.tls_certificate_names_max) break;
        const name = Tlv.read(san, cursor, general_names.end) orelse {
            names.truncated = true;
            return;
        };
        assert(name.end > cursor);
        cursor = name.end;
        if (name.end == name.start) continue;
        // `[6] IMPLICIT IA5String` and `[2] IMPLICIT IA5String`: a
        // uniformResourceIdentifier and a dNSName (RFC 5280 §4.2.1.6).
        switch (name.tag) {
            0x86 => names.keep(.uri, san[name.start..name.end]),
            0x82 => names.keep(.dns, san[name.start..name.end]),
            else => {},
        }
        // A prefix, never a list with a gap in it: a shorter name after
        // one that did not fit is not kept either.
        if (names.truncated) return;
    }
    if (cursor < general_names.end) names.truncated = true;
    assert(names.count <= constants.client_cert_names_max);
}

/// Each certificate signed by the next, each issuer a CA, and the last
/// anchored — the path half both verdicts share.
fn pathVerifies(
    anchors: []const []const u8,
    chain: []const []const u8,
    certificates: *const [chain_max]Certificate.Parsed,
    now_sec: i64,
) bool {
    assert(chain.len >= 1);
    assert(chain.len <= chain_max);
    var index: usize = 0;
    while (index + 1 < chain.len) : (index += 1) {
        const issuer = certificates[index + 1];
        certificates[index].verify(issuer, now_sec) catch return false;
        if (!isCa(issuer)) return false;
    }
    const last = certificates[chain.len - 1];
    return anchored(anchors, chain[chain.len - 1], last, now_sec);
}

/// The chain's last certificate is an anchor itself, inside its validity
/// window, or a CA anchor signed it.
fn anchored(anchors: []const []const u8, last_der: []const u8, last: Certificate.Parsed, now_sec: i64) bool {
    assert(anchors.len <= anchors_max);
    for (anchors) |anchor_der| {
        if (std.mem.eql(u8, anchor_der, last_der)) {
            return now_sec >= last.validity.not_before and now_sec <= last.validity.not_after;
        }
    }
    for (anchors) |anchor_der| {
        // Parsed at load, so this cannot fail for a framing reason.
        const anchor = parsed(anchor_der) orelse continue;
        if (!std.mem.eql(u8, last.issuer(), anchor.subject())) continue;
        if (!isCa(anchor)) continue;
        if (now_sec < anchor.validity.not_before or now_sec > anchor.validity.not_after) continue;
        last.verify(anchor, now_sec) catch continue;
        return true;
    }
    return false;
}

/// Whether `certificate` says it is a CA: basicConstraints with `cA`
/// TRUE (RFC 5280 §4.2.1.9). Read with explicit bounds at every step —
/// the extension's value is an OCTET STRING whose own DER `der_bounds`
/// does not descend into.
fn isCa(certificate: Certificate.Parsed) bool {
    const bytes = certificate.certificate.buffer;
    assert(bytes.len >= 1);
    assert(certificate.message_slice.start < bytes.len);
    const tbs = Tlv.read(bytes, certificate.message_slice.start, bytes.len) orelse return false;
    var cursor: usize = tbs.start;
    var fields: u32 = 0;
    while (cursor < tbs.end and fields < tbs_fields_max) : (fields += 1) {
        const field = Tlv.read(bytes, cursor, tbs.end) orelse return false;
        cursor = field.end;
        // [3] EXPLICIT Extensions.
        if (field.tag != 0xa3) continue;
        const extensions = Tlv.read(bytes, field.start, field.end) orelse return false;
        if (extensions.tag != 0x30) return false;
        return basicConstraintsCa(bytes, extensions);
    }
    return false;
}

fn basicConstraintsCa(bytes: []const u8, extensions: Tlv) bool {
    const basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 };
    assert(extensions.tag == 0x30);
    assert(extensions.end <= bytes.len);
    var cursor: usize = extensions.start;
    var count: u32 = 0;
    while (cursor < extensions.end and count < extensions_max) : (count += 1) {
        const extension = Tlv.read(bytes, cursor, extensions.end) orelse return false;
        cursor = extension.end;
        if (extension.tag != 0x30) return false;
        const oid = Tlv.read(bytes, extension.start, extension.end) orelse return false;
        if (oid.tag != 0x06) return false;
        if (!std.mem.eql(u8, bytes[oid.start..oid.end], &basic_constraints)) continue;
        var value = Tlv.read(bytes, oid.end, extension.end) orelse return false;
        // `critical` is optional and comes first when present.
        if (value.tag == 0x01) value = Tlv.read(bytes, value.end, extension.end) orelse return false;
        if (value.tag != 0x04) return false;
        const sequence = Tlv.read(bytes, value.start, value.end) orelse return false;
        if (sequence.tag != 0x30) return false;
        // `cA` DEFAULT FALSE: an empty sequence says not a CA.
        if (sequence.start == sequence.end) return false;
        const ca = Tlv.read(bytes, sequence.start, sequence.end) orelse return false;
        if (ca.tag != 0x01 or ca.end - ca.start != 1) return false;
        return bytes[ca.start] == 0xff;
    }
    return false;
}

/// One tag-length-value, every index checked against `end`: the tag
/// octet, a short or long (at most four-octet) length, and the content.
const Tlv = struct {
    tag: u8,
    start: usize,
    end: usize,

    fn read(bytes: []const u8, at: usize, end: usize) ?Tlv {
        assert(end <= bytes.len);
        if (at + 2 > end) return null;
        const tag = bytes[at];
        const first = bytes[at + 1];
        var cursor = at + 2;
        var length: usize = first;
        if (first & 0x80 != 0) {
            const octets: usize = first & 0x7f;
            if (octets == 0 or octets > 4 or cursor + octets > end) return null;
            length = 0;
            for (bytes[cursor..][0..octets]) |octet| length = (length << 8) | octet;
            cursor += octets;
        }
        if (length > end - cursor) return null;
        return .{ .tag = tag, .start = cursor, .end = cursor + length };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const ca_pem = @embedFile("testdata/origin-ca.pem");
const leaf_pem = @embedFile("testdata/origin-cert.pem");
const other_ca_pem = @embedFile("testdata/other-ca.pem");
const rogue_pem = @embedFile("testdata/rogue-cert.pem");
const self_signed_pem = @embedFile("testdata/cert.pem");

/// 2030-01-01: inside every fixture's window.
const now_2030: i64 = 1_893_456_000;

fn firstDer(arena: std.mem.Allocator, pem: []const u8) ![]const u8 {
    const anchors = try parseAnchors(arena, pem);
    return anchors[0];
}

test "trust: a leaf its CA signed verifies for its name, alone or with the root sent along" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const anchors = try parseAnchors(arena, ca_pem);
    const leaf = try firstDer(arena, leaf_pem);
    const root = anchors[0];
    try testing.expect(verifyChain(anchors, &.{leaf}, "origin.zoxy.test", now_2030));
    try testing.expect(verifyChain(anchors, &.{ leaf, root }, "origin.zoxy.test", now_2030));
}

const client_ca_pem = @embedFile("testdata/client-ca.pem");
const client_leaf_pem = @embedFile("testdata/client-cert.pem");

test "trust: a client chain verifies against its CA with no name, and its fingerprint is the leaf's (#304)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const anchors = try parseAnchors(arena, client_ca_pem);
    const leaf = try firstDer(arena, client_leaf_pem);
    try testing.expect(verifyClientChain(anchors, &.{leaf}, now_2030));
    try testing.expect(verifyClientChain(anchors, &.{ leaf, anchors[0] }, now_2030));
    // The fixture's own fingerprint, as `openssl x509 -fingerprint
    // -sha256` printed it when it was made (testdata/README.md).
    var expected: [fingerprint_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "F1FD192CFF76490BAF1534F777226E96DBB03D9751A657648E0955116D0D4FCB");
    try testing.expectEqualSlices(u8, &expected, &leafFingerprint(leaf));
}

test "trust: a client chain to another anchor, outside its window, or led by a CA is refused (#304)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const anchors = try parseAnchors(arena, client_ca_pem);
    const other = try parseAnchors(arena, other_ca_pem);
    const leaf = try firstDer(arena, client_leaf_pem);
    try testing.expect(!verifyClientChain(other, &.{leaf}, now_2030));
    // 2018 and 2050.
    try testing.expect(!verifyClientChain(anchors, &.{leaf}, 1_514_764_800));
    try testing.expect(!verifyClientChain(anchors, &.{leaf}, 2_524_608_000));
    // A CA presenting itself is refused even where it is the anchor: it
    // is a key that signs identities, not one.
    try testing.expect(!verifyClientChain(anchors, &.{anchors[0]}, now_2030));
    try testing.expect(!verifyClientChain(anchors, &.{}, now_2030));
    // A server leaf from another PKI is no client of this one.
    const origin_leaf = try firstDer(arena, leaf_pem);
    try testing.expect(!verifyClientChain(anchors, &.{origin_leaf}, now_2030));
}

test "trust: a leaf's DNS names are read off its subjectAltName, lowercased (#297)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const origin_leaf = try firstDer(arena, leaf_pem);
    const names = try dnsNames(arena, origin_leaf);
    try testing.expectEqual(@as(usize, 1), names.len);
    try testing.expectEqualStrings("origin.zoxy.test", names[0]);
    // The fuzz seed is that same leaf, so the fuzzer starts in the walk.
    try testing.expectEqualStrings("origin.zoxy.test", (try dnsNames(arena, leaf_der_seed))[0]);
    const spike = try dnsNames(arena, try firstDer(arena, self_signed_pem));
    try testing.expectEqualStrings("spike.zoxy.test", spike[0]);
    // A client certificate names no host at all.
    try testing.expectEqual(@as(usize, 0), (try dnsNames(arena, try firstDer(arena, client_leaf_pem))).len);
    try testing.expectError(error.CertificateInvalid, dnsNames(arena, "not a certificate"));
}

test "trust: another name, another anchor, or a time outside the window is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const anchors = try parseAnchors(arena, ca_pem);
    const other = try parseAnchors(arena, other_ca_pem);
    const leaf = try firstDer(arena, leaf_pem);
    try testing.expect(!verifyChain(anchors, &.{leaf}, "other.zoxy.test", now_2030));
    try testing.expect(!verifyChain(other, &.{leaf}, "origin.zoxy.test", now_2030));
    // 2018 and 2050.
    try testing.expect(!verifyChain(anchors, &.{leaf}, "origin.zoxy.test", 1_514_764_800));
    try testing.expect(!verifyChain(anchors, &.{leaf}, "origin.zoxy.test", 2_524_608_000));
}

test "trust: a chain through a certificate that is not a CA is refused, every signature good" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const anchors = try parseAnchors(arena, ca_pem);
    const leaf = try firstDer(arena, leaf_pem);
    const rogue = try firstDer(arena, rogue_pem);
    try testing.expect(!verifyChain(anchors, &.{ rogue, leaf }, "victim.zoxy.test", now_2030));
    // The leaf is not a CA; the anchor is.
    const leaf_parsed = parsed(leaf).?;
    try testing.expect(!isCa(leaf_parsed));
    try testing.expect(isCa(parsed(anchors[0]).?));
}

test "trust: a pinned self-signed leaf is its own anchor" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const anchors = try parseAnchors(arena, self_signed_pem);
    // Valid from mid-2026: 2030 is inside it.
    try testing.expect(verifyChain(anchors, &.{anchors[0]}, "spike.zoxy.test", now_2030));
    try testing.expect(!verifyChain(anchors, &.{anchors[0]}, "spike.zoxy.test", 1_600_000_000));
}

test "trust: garbage in a chain is refused, never a panic, and a bundle without a certificate is invalid" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const anchors = try parseAnchors(arena, ca_pem);
    const garbage = [_][]const u8{ "", "\x30", "\x30\x84\xff\xff\xff\xff", "\x30\x03\x02\x01\x01" };
    for (garbage) |bytes| {
        try testing.expect(!verifyChain(anchors, &.{bytes}, "origin.zoxy.test", now_2030));
    }
    try testing.expectError(error.AnchorsInvalid, parseAnchors(arena, "no certificates here"));
    try testing.expectError(error.AnchorsInvalid, parseAnchors(arena, begin_marker ++ "\n!!!!\n" ++ end_marker));
    // A key in a trust bundle is refused, not skipped.
    try testing.expectError(error.AnchorsInvalid, parseAnchors(arena, ca_pem ++ "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"));
}

test "fuzz: trust — any chain octets are judged, never a panic" {
    try testing.fuzz({}, fuzzChain, .{ .corpus = &.{ "\x30\x82\x01", "\x30\x03\xa3\x01\x00", leaf_der_seed } });
}

/// The origin leaf as DER, decoded at comptime: a seed that starts the
/// fuzzer inside a real certificate — its SAN included, which is what
/// `dnsNames` walks (#297) — rather than leaving it to find one.
const leaf_der_seed: []const u8 = blk: {
    @setEvalBranchQuota(1_000_000);
    const begin_at = std.mem.indexOf(u8, leaf_pem, begin_marker).? + begin_marker.len;
    const end_at = std.mem.indexOf(u8, leaf_pem, end_marker).?;
    const body = leaf_pem[begin_at..end_at];
    const decoder = std.base64.Base64DecoderWithIgnore.init(std.base64.standard_alphabet_chars, '=', " \t\r\n");
    var der: [decoder.calcSizeUpperBound(body.len)]u8 = undefined;
    const length = decoder.decode(&der, body) catch unreachable;
    const seed = der[0..length].*;
    break :blk &seed;
};

var fuzz_arena_buffer: [64 * 1024]u8 = undefined;

fn fuzzChain(context: void, smith: *testing.Smith) !void {
    _ = context;
    var fixed = std.heap.FixedBufferAllocator.init(&fuzz_arena_buffer);
    const anchors = parseAnchors(fixed.allocator(), ca_pem) catch unreachable;
    var input: [2048]u8 = undefined;
    const input_len = smith.slice(&input);
    _ = verifyChain(anchors, &.{input[0..input_len]}, "origin.zoxy.test", now_2030);
    // The client half (#304) parses the same untrusted bytes by its own
    // path — no name, and an end-entity check the server half lacks.
    _ = verifyClientChain(anchors, &.{input[0..input_len]}, now_2030);
    // #297's walk of the SAN, a third path over the same bytes. Errors
    // are verdicts; only a panic or an overrun is a finding.
    // #432's walk keeps a client's URI and DNS names in fixed storage: no
    // error to return, so every input must leave it within its bounds.
    var client_names: ClientNames = undefined;
    clientNames(input[0..input_len], &client_names);
    assert(client_names.count <= constants.client_cert_names_max);
    assert(client_names.bytes_used <= constants.client_cert_names_bytes_max);
    const names = dnsNames(fixed.allocator(), input[0..input_len]) catch return;
    assert(names.len <= constants.tls_certificate_names_max);
}

const names_ca_pem = @embedFile("testdata/names-ca.pem");
const names_client_pem = @embedFile("testdata/names-client-cert.pem");
const names_many_pem = @embedFile("testdata/names-many-cert.pem");

test "trust: a client leaf's URI and DNS names are kept in its order, its IP skipped (#432)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const anchors = try parseAnchors(arena, names_ca_pem);
    const leaf = try firstDer(arena, names_client_pem);
    try testing.expect(verifyClientChain(anchors, &.{leaf}, now_2030));
    var names: ClientNames = undefined;
    clientNames(leaf, &names);
    try testing.expectEqual(@as(u8, 3), names.count);
    try testing.expect(!names.truncated);
    try testing.expectEqual(ClientNames.Kind.uri, names.entries[0].kind);
    try testing.expectEqualStrings("spiffe://zoxy.test/ns/edge/sa/reports", names.value(0));
    try testing.expectEqual(ClientNames.Kind.dns, names.entries[1].kind);
    try testing.expectEqualStrings("workload.zoxy.test", names.value(1));
    try testing.expectEqualStrings("urn:zoxy:tenant:acme", names.value(2));
}

test "trust: a leaf naming more than a connection keeps is kept to what fits, and says so (#432)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var names: ClientNames = undefined;
    clientNames(try firstDer(arena, names_many_pem), &names);
    try testing.expectEqual(@as(u8, constants.client_cert_names_max), names.count);
    try testing.expect(names.truncated);
    try testing.expectEqualStrings("host-00-with-a-long-enough-label.many.zoxy.test", names.value(0));
    // A leaf with no subjectAltName names nothing, and lacks nothing.
    clientNames(try firstDer(arena, client_leaf_pem), &names);
    try testing.expectEqual(@as(u8, 0), names.count);
    try testing.expect(!names.truncated);
}
