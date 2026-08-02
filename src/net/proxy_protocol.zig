//! PROXY protocol (v1 and v2) header parsing for the receive path
//! (#142): a listener configured to sit behind another proxy learns the
//! real client from a header that proxy prepends, because the kernel's
//! peer address is the proxy's own — and `client_address` is a routing
//! input (`pick: hash`, §7), not just a log field, so the observed peer
//! would pin every client to one endpoint.
//!
//! Parsing is pure and total: bytes in, verdict out, no I/O, no
//! allocation, no third outcome (the §9 fuzz oracle below). The caller
//! accumulates bytes and re-parses from byte 0 on every delivery —
//! detect-and-retry, the same discipline as the HTTP head parser — so the
//! verdicts are monotonic by contract: a strict prefix of a header that
//! parses (or may yet parse) is always `.need_more`, never `.invalid`. A
//! transient `.invalid` would tear down a connection whose next segment
//! completed the header.
//!
//! **Deliberately not here: the decision to look for a header at all.**
//! Accepting one from an arbitrary peer would let any client choose its
//! own sticky backend and forge every access-log line about itself, so
//! the spec forbids sniffing and this parser is only ever consulted on a
//! listener whose config states the peer is trusted — the same
//! per-listener trust statement `forwarded` settled (§7).
//!
//! `client == null` on a successful parse means "keep the observed peer":
//! v1 `UNKNOWN`, v2 `LOCAL`, and every valid non-TCP family land there.
//! Health checks from the fronting proxy arrive exactly this way, so
//! treating them as errors would take the listener down.
//!
//! Spec: https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt

const std = @import("std");
const constants = @import("../constants.zig");

const assert = std.debug.assert;

/// The verdict on a byte prefix. `need_more` never asks past
/// `constants.proxy_header_bytes_max` (asserted in `parse`), so the
/// accumulating caller needs no bound of its own.
pub const Parsed = union(enum) {
    need_more,
    invalid,
    ok: Header,
};

/// A complete header: who the fronting proxy says connected, and how many
/// bytes the header occupies — the relayed payload starts at `bytes_len`.
pub const Header = struct {
    /// The announced client, or null to keep the observed peer (v1
    /// `UNKNOWN`, v2 `LOCAL`, valid non-TCP families). An IPv4-mapped
    /// IPv6 announcement unwraps to the IPv4 address it is, the same
    /// normalization the accept path applies (`XevIo.addressOf`) — one
    /// client must hash one way however its address was conveyed.
    client: ?std.Io.net.IpAddress,
    bytes_len: u32,
};

/// The shortest parse any input can complete: v1's "PROXY UNKNOWN\r\n"
/// (v2's minimum is the 16-byte prelude).
const header_bytes_min: u32 = 15;

const v1_signature = "PROXY ";
/// Spec: a v1 line, CRLF included, never exceeds 107 bytes (the
/// worst-case TCP6 line). Longer without a CRLF is not a v1 header.
const v1_line_bytes_max: u32 = 107;

const v2_signature = "\r\n\r\n\x00\r\nQUIT\n";
/// Signature, version/command byte, family/protocol byte, u16 length.
const v2_prelude_bytes: u32 = 16;

const V1Family = enum { tcp4, tcp6 };

comptime {
    assert(v1_signature.len == 6);
    assert(v2_signature.len == 12);
    assert(header_bytes_min == "PROXY UNKNOWN\r\n".len);
    assert(v2_prelude_bytes == v2_signature.len + 4);
    // Byte 0 discriminates the two versions.
    assert(v1_signature[0] != v2_signature[0]);
    // The cap admits every maximal fixed-size header either version
    // defines; rejecting one the spec allows would be a config trap.
    assert(v1_line_bytes_max <= constants.proxy_header_bytes_max);
    assert(v2_prelude_bytes + 216 <= constants.proxy_header_bytes_max);
}

/// Judge `bytes` as the start of a PROXY protocol header. Callable on any
/// prefix of the client's stream, any number of times.
pub fn parse(bytes: []const u8) Parsed {
    const parsed = parseAny(bytes);
    switch (parsed) {
        // What `need_more` promises the accumulating caller: the answer
        // always arrives within the cap, so a buffer sized by it and a
        // loop bounded by it both suffice.
        .need_more => assert(bytes.len < constants.proxy_header_bytes_max),
        .invalid => {},
        .ok => |header| {
            assert(header.bytes_len >= header_bytes_min);
            assert(header.bytes_len <= bytes.len);
            assert(header.bytes_len <= constants.proxy_header_bytes_max);
        },
    }
    return parsed;
}

fn parseAny(bytes: []const u8) Parsed {
    if (bytes.len == 0) {
        return .need_more;
    }
    if (bytes[0] == v2_signature[0]) {
        return parseV2(bytes);
    }
    if (bytes[0] == v1_signature[0]) {
        return parseV1(bytes);
    }
    // Negative space: neither version starts this way, and no suffix can
    // repair byte 0 — invalid now rather than after 107 more bytes.
    assert(bytes[0] != v1_signature[0]);
    assert(bytes[0] != v2_signature[0]);
    return .invalid;
}

fn parseV1(bytes: []const u8) Parsed {
    assert(bytes.len >= 1);
    assert(bytes[0] == v1_signature[0]);
    const window = bytes[0..@min(bytes.len, v1_line_bytes_max)];
    const line_end = std.mem.indexOf(u8, window, "\r\n") orelse {
        if (bytes.len >= v1_line_bytes_max) {
            return .invalid;
        }
        // No terminator yet. Wait only while the bytes present are still
        // a prefix of the one legal opening; "PROXA" can never recover.
        const signature_window = bytes[0..@min(bytes.len, v1_signature.len)];
        if (!std.mem.startsWith(u8, v1_signature, signature_window)) {
            return .invalid;
        }
        return .need_more;
    };
    const line = window[0..line_end];
    if (!std.mem.startsWith(u8, line, v1_signature)) {
        return .invalid;
    }
    assert(line_end + 2 <= v1_line_bytes_max);
    const bytes_len: u32 = @intCast(line_end + 2);
    var tokens = std.mem.splitScalar(u8, line[v1_signature.len..], ' ');
    const family_token = tokens.first();
    if (std.mem.eql(u8, family_token, "UNKNOWN")) {
        // Spec: for UNKNOWN the receiver ignores everything up to the
        // CRLF. The fronting proxy saw a family it cannot describe (a
        // health check's UNIX socket, say); the observed peer stands.
        return .{ .ok = .{ .client = null, .bytes_len = bytes_len } };
    }
    if (std.mem.eql(u8, family_token, "TCP4")) {
        return parseV1Proxy(.tcp4, &tokens, bytes_len);
    }
    if (std.mem.eql(u8, family_token, "TCP6")) {
        return parseV1Proxy(.tcp6, &tokens, bytes_len);
    }
    return .invalid;
}

/// The four address fields of a TCP4/TCP6 line: exactly four more tokens
/// separated by single spaces (an empty token — doubled, leading, or
/// trailing space — fails address or port parsing), then the line ends.
fn parseV1Proxy(
    family: V1Family,
    tokens: *std.mem.SplitIterator(u8, .scalar),
    bytes_len: u32,
) Parsed {
    assert(bytes_len >= header_bytes_min);
    assert(bytes_len <= v1_line_bytes_max);
    const source_address = tokens.next() orelse return .invalid;
    const destination_address = tokens.next() orelse return .invalid;
    const source_port_token = tokens.next() orelse return .invalid;
    const destination_port_token = tokens.next() orelse return .invalid;
    if (tokens.next() != null) {
        return .invalid;
    }
    const source_port = parsePort(source_port_token) orelse return .invalid;
    const destination_port = parsePort(destination_port_token) orelse return .invalid;
    const client = parseV1Address(family, source_address, source_port) orelse
        return .invalid;
    // The destination is this proxy; validated — parse-or-reject admits
    // no half-checked header — and discarded.
    _ = parseV1Address(family, destination_address, destination_port) orelse
        return .invalid;
    return .{ .ok = .{ .client = client, .bytes_len = bytes_len } };
}

/// Spec-strict decimal port: one to five digits, no leading zero, at most
/// 65535. Stricter than the address parsers need to be because nothing
/// here delegates it.
fn parsePort(token: []const u8) ?u16 {
    if (token.len == 0) {
        return null;
    }
    if (token.len > 5) {
        return null;
    }
    if (token.len > 1) {
        if (token[0] == '0') {
            return null;
        }
    }
    assert(token.len >= 1);
    assert(token.len <= 5);
    var value: u32 = 0;
    for (token) |char| {
        if (char < '0') return null;
        if (char > '9') return null;
        value = value * 10 + (char - '0');
    }
    assert(value <= 99999);
    if (value > std.math.maxInt(u16)) {
        return null;
    }
    return @intCast(value);
}

fn parseV1Address(
    family: V1Family,
    token: []const u8,
    port: u16,
) ?std.Io.net.IpAddress {
    switch (family) {
        .tcp4 => {
            // `Ip4Address.parse` is the strictness delegate: it rejects
            // leading zeros, short octet counts, and trailing bytes.
            const address = std.Io.net.Ip4Address.parse(token, port) catch return null;
            assert(token.len >= 7);
            return .{ .ip4 = address };
        },
        .tcp6 => {
            // Every IPv6 text form contains ':' and no IPv4 form does;
            // requiring it rejects a spec-violating v4 literal on a
            // TCP6 line.
            if (std.mem.findScalar(u8, token, ':') == null) {
                return null;
            }
            const address = std.Io.net.IpAddress.parse(token, port) catch return null;
            assert(address.getPort() == port);
            // `parse` keeps a mapped `::ffff:a.b.c.d` as IPv6; unwrap it
            // to the IPv4 address it is — see `Header.client`.
            return switch (address) {
                .ip4 => address,
                .ip6 => |ip6| std.Io.net.IpAddress.fromIp6(ip6),
            };
        },
    }
}

fn parseV2(bytes: []const u8) Parsed {
    assert(bytes.len >= 1);
    assert(bytes[0] == v2_signature[0]);
    if (bytes.len < v2_signature.len) {
        if (!std.mem.startsWith(u8, v2_signature, bytes)) {
            return .invalid;
        }
        return .need_more;
    }
    if (!std.mem.startsWith(u8, bytes, v2_signature)) {
        return .invalid;
    }
    if (bytes.len < v2_prelude_bytes) {
        return .need_more;
    }
    // Byte 12: protocol version (must be 2) and command.
    const version_command = bytes[12];
    if (version_command >> 4 != 0x2) {
        return .invalid;
    }
    const command = version_command & 0x0F;
    if (command > 0x1) { // 0x0 LOCAL, 0x1 PROXY; the rest are unassigned.
        return .invalid;
    }
    // Byte 13: address family and transport protocol. The spec is
    // explicit that values past the assigned ones "must be rejected as
    // invalid by receivers" — rejection here is mandated, not a choice.
    const family = bytes[13] >> 4;
    const protocol = bytes[13] & 0x0F;
    if (family > 0x3) { // UNSPEC, INET, INET6, UNIX.
        return .invalid;
    }
    if (protocol > 0x2) { // UNSPEC, STREAM, DGRAM.
        return .invalid;
    }
    assert(family <= 0x3);
    assert(protocol <= 0x2);
    const block_len: u32 = std.mem.readInt(u16, bytes[14..16], .big);
    const total_len = v2_prelude_bytes + block_len;
    // The declared length is the peer's number; the cap is ours. Judged
    // before waiting, so an oversize header is rejected at byte 16 rather
    // than trusted to fill a buffer it never fits.
    if (total_len > constants.proxy_header_bytes_max) {
        return .invalid;
    }
    if (command == 0x1) {
        // A PROXY announcement must cover its family's address block;
        // anything past the block is TLVs, consumed and discarded.
        if (block_len < v2AddressBytes(family)) {
            return .invalid;
        }
    }
    if (bytes.len < total_len) {
        return .need_more;
    }
    assert(total_len >= v2_prelude_bytes);
    const client = if (command == 0x1)
        v2Address(family, protocol, bytes[v2_prelude_bytes..total_len])
    else
        null;
    return .{ .ok = .{ .client = client, .bytes_len = total_len } };
}

/// The fixed address-block size a PROXY command must carry per family:
/// source and destination addresses, then source and destination ports.
fn v2AddressBytes(family: u8) u32 {
    assert(family <= 0x3);
    return switch (family) {
        0x0 => 0, // UNSPEC carries whatever it likes; none of it is read.
        0x1 => 4 + 4 + 2 + 2,
        0x2 => 16 + 16 + 2 + 2,
        0x3 => 108 + 108, // AF_UNIX paths; no ports.
        else => unreachable, // Asserted above; families stop at 0x3.
    };
}

/// The announced client of a validated PROXY command, or null to keep
/// the observed peer: only a TCP (STREAM) family conveys a peer this
/// TCP listener can mean anything by. UNSPEC, UNIX, and DGRAM are
/// valid statements — just not about a client we can route.
fn v2Address(family: u8, protocol: u8, block: []const u8) ?std.Io.net.IpAddress {
    assert(family <= 0x3);
    assert(protocol <= 0x2);
    if (protocol != 0x1) {
        return null;
    }
    switch (family) {
        0x1 => {
            assert(block.len >= v2AddressBytes(0x1));
            return .{ .ip4 = .{
                .bytes = block[0..4].*,
                .port = std.mem.readInt(u16, block[8..10], .big),
            } };
        },
        0x2 => {
            assert(block.len >= v2AddressBytes(0x2));
            // `fromIp6` unwraps an IPv4-mapped announcement — see
            // `Header.client` for why the normalization matters.
            return std.Io.net.IpAddress.fromIp6(.{
                .bytes = block[0..16].*,
                .port = std.mem.readInt(u16, block[32..34], .big),
                .flow = 0,
                .interface = .none,
            });
        },
        else => return null, // 0x0 UNSPEC, 0x3 UNIX.
    }
}

// -- tests ---------------------------------------------------------------

const testing = std.testing;

fn clientEql(a: ?std.Io.net.IpAddress, b: ?std.Io.net.IpAddress) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return a.?.eql(&b.?);
}

/// The invariants any input must satisfy — the same oracle unit vectors
/// and the fuzzer share, so a pinned case checks everything fuzz would.
fn checkParse(input: []const u8) void {
    const parsed = parse(input);
    if (parsed == .ok) {
        // Bytes past the header cannot have contributed to the verdict:
        // the header alone must parse to the very same answer.
        const alone = parse(input[0..parsed.ok.bytes_len]);
        assert(alone == .ok);
        assert(alone.ok.bytes_len == parsed.ok.bytes_len);
        assert(clientEql(alone.ok.client, parsed.ok.client));
    }
    // Monotonicity, the accumulate-and-retry contract (module header):
    // while an input has not been judged `.invalid`, every strict prefix
    // of the bytes that led to the verdict must read `.need_more`.
    if (parsed != .invalid) {
        const limit: usize = switch (parsed) {
            .ok => |header| header.bytes_len,
            else => input.len,
        };
        assert(limit <= input.len);
        var prefix_len: usize = 0;
        while (prefix_len < limit) : (prefix_len += 1) {
            assert(parse(input[0..prefix_len]) == .need_more);
        }
    }
}

fn expectClient(input: []const u8, expected: ?std.Io.net.IpAddress, expected_len: u32) !void {
    checkParse(input);
    const parsed = parse(input);
    try testing.expect(parsed == .ok);
    try testing.expectEqual(expected_len, parsed.ok.bytes_len);
    try testing.expect(clientEql(expected, parsed.ok.client));
}

fn expectVerdict(input: []const u8, expected: std.meta.Tag(Parsed)) !void {
    checkParse(input);
    try testing.expectEqual(expected, @as(std.meta.Tag(Parsed), parse(input)));
}

const client_v4: std.Io.net.IpAddress =
    .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 56324 } };

test "proxy protocol v1: the spec's own lines parse to their clients" {
    try expectClient("PROXY TCP4 198.51.100.1 203.0.113.9 56324 443\r\n", client_v4, 47);
    // The spec's worst-case TCP4 line, all fields maximal.
    try expectClient(
        "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n",
        .{ .ip4 = .{ .bytes = .{ 255, 255, 255, 255 }, .port = 65535 } },
        56,
    );
    try expectClient(
        "PROXY TCP6 2001:db8::1 ::1 56324 443\r\n",
        .{ .ip6 = .{
            .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            .port = 56324,
            .flow = 0,
            .interface = .none,
        } },
        38,
    );
    // Payload behind the header is not the parser's to judge.
    try expectClient("PROXY UNKNOWN\r\nGET / HTTP/1.0\r\n\r\n", null, 15);
    try expectClient("PROXY UNKNOWN ignored junk fields\r\n", null, 35);
}

test "proxy protocol v1: a mapped announcement hashes as the IPv4 client it is" {
    const parsed = parse("PROXY TCP6 ::ffff:198.51.100.1 ::1 56324 443\r\n");
    try testing.expect(parsed == .ok);
    try testing.expect(parsed.ok.client.? == .ip4);
    try testing.expect(clientEql(client_v4, parsed.ok.client));
}

test "proxy protocol v1: incomplete lines wait, hopeless ones do not" {
    try expectVerdict("", .need_more);
    try expectVerdict("P", .need_more);
    try expectVerdict("PROXY", .need_more);
    try expectVerdict("PROXY TCP4 198.51.100.1", .need_more);
    try expectVerdict("PROXY TCP4 198.51.100.1 203.0.113.9 56324 443\r", .need_more);
    // Byte 0 can already condemn a stream; so can a broken signature.
    try expectVerdict("QROXY TCP4", .invalid);
    try expectVerdict("PROXA", .invalid);
    try expectVerdict("proxy TCP4 198.51.100.1 203.0.113.9 56324 443\r\n", .invalid);
}

test "proxy protocol v1: the 107-byte line bound is exact" {
    // "PROXY UNKNOWN " + filler + CRLF: UNKNOWN ignores the filler, so
    // the only judgment left is the length's.
    const line_105 = "PROXY UNKNOWN " ++ ("x" ** 91) ++ "\r\n";
    comptime assert(line_105.len == 107);
    try expectClient(line_105, null, 107);
    const line_108 = "PROXY UNKNOWN " ++ ("x" ** 92) ++ "\r\n";
    comptime assert(line_108.len == 108);
    try expectVerdict(line_108, .invalid);
    // 107 bytes and still no CRLF: no v1 line can be forming.
    try expectVerdict("PROXY UNKNOWN " ++ ("x" ** 93), .invalid);
}

test "proxy protocol v1: field discipline is strict" {
    // Doubled space, missing field, trailing space, extra field.
    try expectVerdict("PROXY TCP4  198.51.100.1 203.0.113.9 56324 443\r\n", .invalid);
    try expectVerdict("PROXY TCP4 198.51.100.1 203.0.113.9 56324\r\n", .invalid);
    try expectVerdict("PROXY TCP4 198.51.100.1 203.0.113.9 56324 443 \r\n", .invalid);
    try expectVerdict("PROXY TCP4 198.51.100.1 203.0.113.9 56324 443 7\r\n", .invalid);
    try expectVerdict("PROXY\r\n", .invalid);
    try expectVerdict("PROXY TCP5 198.51.100.1 203.0.113.9 56324 443\r\n", .invalid);
    // Ports: leading zero, overflow, empty, non-digit.
    try expectVerdict("PROXY TCP4 198.51.100.1 203.0.113.9 056324 443\r\n", .invalid);
    try expectVerdict("PROXY TCP4 198.51.100.1 203.0.113.9 65536 443\r\n", .invalid);
    try expectVerdict("PROXY TCP4 198.51.100.1 203.0.113.9 56324 4a3\r\n", .invalid);
    // Family/address mismatch, both directions.
    try expectVerdict("PROXY TCP4 2001:db8::1 203.0.113.9 56324 443\r\n", .invalid);
    try expectVerdict("PROXY TCP6 198.51.100.1 ::1 56324 443\r\n", .invalid);
    // A non-canonical IPv4 octet (leading zero) is the delegate's call.
    try expectVerdict("PROXY TCP4 198.051.100.1 203.0.113.9 56324 443\r\n", .invalid);
    // Port 0 is within the spec's stated range.
    try expectClient(
        "PROXY TCP4 198.51.100.1 203.0.113.9 0 443\r\n",
        .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 0 } },
        43,
    );
}

const v2_local_min = v2_signature ++ "\x20\x00\x00\x00";
const v2_proxy_inet = v2_signature ++ "\x21\x11\x00\x0c" ++
    "\xc6\x33\x64\x01" ++ "\xcb\x00\x71\x09" ++ "\xdc\x04" ++ "\x01\xbb";

test "proxy protocol v2: the binary form parses to its client" {
    comptime assert(v2_proxy_inet.len == 28);
    try expectClient(v2_proxy_inet, client_v4, 28);
    // TLVs ride behind the address block inside the declared length.
    const with_tlv = v2_signature ++ "\x21\x11\x00\x11" ++
        "\xc6\x33\x64\x01" ++ "\xcb\x00\x71\x09" ++ "\xdc\x04" ++ "\x01\xbb" ++
        "\x04\x00\x02\xab\xcd";
    try expectClient(with_tlv, client_v4, 33);
    // Payload behind the declared length is untouched.
    try expectClient(v2_proxy_inet ++ "GET / HTTP/1.0\r\n", client_v4, 28);
    // INET6 with a mapped source unwraps to the IPv4 client (one client,
    // one hash, however conveyed).
    const mapped = v2_signature ++ "\x21\x21\x00\x24" ++
        ("\x00" ** 10) ++ "\xff\xff" ++ "\xc6\x33\x64\x01" ++
        ("\x00" ** 15) ++ "\x01" ++ "\xdc\x04" ++ "\x01\xbb";
    comptime assert(mapped.len == 52);
    try expectClient(mapped, client_v4, 52);
}

test "proxy protocol v2: LOCAL and non-TCP families keep the observed peer" {
    try expectClient(v2_local_min, null, 16);
    // LOCAL with a block: skipped whole.
    try expectClient(v2_signature ++ "\x20\x00\x00\x03" ++ "abc", null, 19);
    // PROXY over UNSPEC, DGRAM, and UNIX: valid statements about peers
    // this TCP listener cannot route by.
    try expectClient(v2_signature ++ "\x21\x00\x00\x00", null, 16);
    const dgram = v2_signature ++ "\x21\x12\x00\x0c" ++ ("\x00" ** 12);
    try expectClient(dgram, null, 28);
    const unix = v2_signature ++ "\x21\x31\x00\xd8" ++ ("\x00" ** 216);
    comptime assert(unix.len == 232);
    try expectClient(unix, null, 232);
}

test "proxy protocol v2: truncations wait, corruption does not" {
    try expectVerdict("\r", .need_more);
    try expectVerdict(v2_signature[0..7], .need_more);
    try expectVerdict(v2_signature, .need_more);
    try expectVerdict(v2_signature ++ "\x21\x11", .need_more);
    try expectVerdict(v2_proxy_inet[0..20], .need_more);
    // A corrupt signature byte, and each rejected nibble.
    try expectVerdict("\r\n\r\n\x00\r\nQUIT\x00" ++ "\x21\x11\x00\x0c", .invalid);
    try expectVerdict(v2_signature ++ "\x11\x11\x00\x0c", .invalid); // version 1
    try expectVerdict(v2_signature ++ "\x22\x11\x00\x0c", .invalid); // command 2
    try expectVerdict(v2_signature ++ "\x21\x41\x00\x0c", .invalid); // family 4
    try expectVerdict(v2_signature ++ "\x21\x13\x00\x0c", .invalid); // protocol 3
    // A PROXY announcement too short for its family's addresses.
    try expectVerdict(v2_signature ++ "\x21\x11\x00\x0b", .invalid);
    try expectVerdict(v2_signature ++ "\x21\x21\x00\x0c", .invalid);
}

test "proxy protocol v2: the declared length meets the cap at byte 16" {
    // 16 + 496 lands exactly on the cap; one more is rejected — before
    // the block arrives, not after a buffer fills with it.
    const at_cap_len = constants.proxy_header_bytes_max - v2_prelude_bytes;
    var at_cap: [constants.proxy_header_bytes_max]u8 = undefined;
    @memcpy(at_cap[0..12], v2_signature);
    at_cap[12] = 0x20; // LOCAL: the block is skipped, not read.
    at_cap[13] = 0x00;
    std.mem.writeInt(u16, at_cap[14..16], @intCast(at_cap_len), .big);
    @memset(at_cap[16..], 0xaa);
    try expectClient(&at_cap, null, constants.proxy_header_bytes_max);

    var over_cap: [v2_prelude_bytes]u8 = undefined;
    @memcpy(over_cap[0..12], v2_signature);
    over_cap[12] = 0x20;
    over_cap[13] = 0x00;
    std.mem.writeInt(u16, over_cap[14..16], @intCast(at_cap_len + 1), .big);
    try expectVerdict(&over_cap, .invalid);
}

const fuzz_corpus_v1 = "PROXY TCP4 198.51.100.1 203.0.113.9 56324 443\r\nGET /\r\n";
const fuzz_corpus_v1_unknown = "PROXY UNKNOWN\r\n";
const fuzz_corpus_v2_local = v2_local_min;
const fuzz_corpus_v2_inet = v2_proxy_inet;

test "fuzz: proxy protocol — parse or reject, no third outcome" {
    try std.testing.fuzz({}, fuzzParseInputs, .{
        .corpus = &.{
            fuzz_corpus_v1,
            fuzz_corpus_v1_unknown,
            fuzz_corpus_v2_local,
            fuzz_corpus_v2_inet,
        },
    });
}

fn fuzzParseInputs(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    // Twice the cap, so over-cap declarations and long garbage both get
    // exercised alongside every legal size.
    var input_buffer: [2 * constants.proxy_header_bytes_max]u8 = undefined;
    const input_len = smith.slice(&input_buffer);
    assert(input_len <= input_buffer.len);
    checkParse(input_buffer[0..input_len]);
}
