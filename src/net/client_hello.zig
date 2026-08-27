//! TLS ClientHello SNI extraction for the L4 receive path (#298): an `l4`
//! listener with a route table learns which backend a connection wants
//! from the `server_name` extension of the first handshake record, and
//! relays the bytes onward **unchanged**.
//!
//! This is not termination and the distinction is the whole value. There
//! is no key material, no `Engine`, no `limits.tls_engines`, no libcrypto
//! heap and no handshake CPU: the parser reads a prefix and the relay
//! forwards it verbatim, which is `pump.zig`'s existing pre-owed-debt
//! entry rather than a transform. It is how one `:443` fronts several TLS
//! services without holding any of their private keys — and the only way
//! to front a backend whose certificate this proxy must *not* be able to
//! present.
//!
//! Parsing is pure and total, on `proxy_protocol.zig`'s terms and for its
//! reasons: bytes in, verdict out, no I/O, no allocation, no third
//! outcome. The caller accumulates and re-parses from byte 0 on every
//! delivery, so the verdicts are monotonic by contract — a strict prefix
//! of a hello that parses (or may yet parse) is always `.need_more`,
//! never `.invalid`. A transient `.invalid` would tear down a connection
//! whose next segment completed the hello.
//!
//! **Unlike the PROXY header, nothing here is consumed.** That header is
//! an envelope this proxy strips; a ClientHello is the client's first
//! payload byte and belongs to the backend. `ok` therefore carries a name
//! and no `bytes_len` — there is no cursor for the relay to skip.
//!
//! Scope, stated because the counter that reports it cannot: the hello
//! must arrive in **one** record. TLS permits a handshake message to span
//! several, and no client in practice fragments its first flight — doing
//! so would need a reassembly buffer or a record-hopping cursor inside a
//! parser that reaches attacker-controlled bytes on every L4 connection,
//! which is a poor trade against a case that does not occur. A fragmented
//! hello is `.invalid` and takes the no-match path, where `l4_sni_invalid`
//! counts it; if that counter ever moves in the field, this is the note
//! to revisit.
//!
//! Spec: RFC 8446 §4.1.2 (ClientHello), RFC 6066 §3 (server_name).

const std = @import("std");
const constants = @import("../constants.zig");

const assert = std.debug.assert;

/// The verdict on a byte prefix. `need_more` never asks past
/// `constants.client_hello_bytes_max` (asserted in `parse`), so the
/// accumulating caller needs no bound of its own.
pub const Parsed = union(enum) {
    need_more,
    invalid,
    /// A well-formed ClientHello. `server_name` is null when it carried
    /// no `server_name` extension — a real and common case (an IP-only
    /// client, an old stack), distinct from a malformed hello and routed
    /// differently: absent takes the any-SNI route, invalid does not.
    ok: struct { server_name: ?[]const u8 },
};

/// TLS record: content type, 2-byte legacy version, 2-byte length.
const record_header_bytes: u32 = 5;
const record_type_handshake: u8 = 0x16;
/// Handshake: 1-byte type, 3-byte length.
const handshake_header_bytes: u32 = 4;
const handshake_type_client_hello: u8 = 0x01;
/// The fixed run after the handshake header: 2-byte legacy version and
/// the 32-byte random, before the first length-prefixed field.
const client_hello_fixed_bytes: u32 = 34;

const extension_server_name: u16 = 0;
const name_type_host_name: u8 = 0;

/// The shortest input that could complete: a record header, a handshake
/// header, and the fixed run. Anything shorter is `need_more` whatever it
/// says.
const client_hello_bytes_min: u32 =
    record_header_bytes + handshake_header_bytes + client_hello_fixed_bytes;

comptime {
    assert(client_hello_bytes_min == 43);
    // The cap must admit a real hello. Post-quantum key shares
    // (X25519MLKEM768) put a modern one at 2-3 KiB, and the record layer
    // itself cannot exceed 16 KiB + the header, so the cap is the record
    // layer's own ceiling rather than a number chosen against today's
    // clients.
    assert(constants.client_hello_bytes_max > client_hello_bytes_min);
    assert(constants.client_hello_bytes_max <= constants.relay_buffer_bytes_max);
}

/// Judge `bytes` as the start of a TLS ClientHello. Callable on any
/// prefix of the client's stream, any number of times.
pub fn parse(bytes: []const u8) Parsed {
    const parsed = parseHello(bytes);
    switch (parsed) {
        // What `need_more` promises the accumulating caller: the answer
        // always arrives within the cap, so a buffer sized by it and a
        // loop bounded by it both suffice.
        .need_more => assert(bytes.len < constants.client_hello_bytes_max),
        .invalid => {},
        .ok => |hello| if (hello.server_name) |name| {
            assert(name.len >= 1);
            // The name aliases `bytes`; it cannot point outside them.
            assert(@intFromPtr(name.ptr) >= @intFromPtr(bytes.ptr));
            assert(@intFromPtr(name.ptr) + name.len <= @intFromPtr(bytes.ptr) + bytes.len);
        },
    }
    return parsed;
}

fn parseHello(bytes: []const u8) Parsed {
    if (bytes.len == 0) {
        return .need_more;
    }
    // Negative space, the same shape `proxy_protocol` opens with: no
    // suffix can repair a first byte that is not a handshake record, so
    // this is invalid now rather than after the cap's worth more.
    if (bytes[0] != record_type_handshake) {
        return .invalid;
    }
    if (bytes.len < record_header_bytes) {
        return .need_more;
    }
    assert(bytes.len >= record_header_bytes);
    const fragment_len = std.mem.readInt(u16, bytes[3..5], .big);
    if (fragment_len == 0) {
        return .invalid;
    }
    // The widening is what keeps this from wrapping: a u16 fragment plus
    // the header cannot overflow a u32, so the comparison below is a real
    // bound rather than one an attacker can roll past.
    const record_len = record_header_bytes + @as(u32, fragment_len);
    assert(record_len > record_header_bytes);
    // The peer's number, capped by ours — `proxy_header_bytes_max`'s own
    // rule. A record this proxy cannot stage is refused rather than
    // waited on forever.
    if (record_len > constants.client_hello_bytes_max) {
        return .invalid;
    }
    if (bytes.len < record_len) {
        return .need_more;
    }
    // Both ends of the slice below, stated where it is taken: the record
    // is wholly present, and it is at least a header long.
    assert(record_len <= bytes.len);
    assert(record_len >= record_header_bytes);
    return parseHandshake(bytes[record_header_bytes..record_len]);
}

/// The handshake message inside one record's fragment. Everything past
/// here is length-prefixed walking, so it reads a cursor rather than
/// slicing by hand.
fn parseHandshake(fragment: []const u8) Parsed {
    assert(fragment.len >= 1);
    if (fragment[0] != handshake_type_client_hello) {
        return .invalid;
    }
    if (fragment.len < handshake_header_bytes) {
        return .invalid;
    }
    const body_len = std.mem.readInt(u24, fragment[1..4], .big);
    // A handshake claiming more than its record holds is the fragmented
    // case this parser does not reassemble (see the module doc), and is
    // indistinguishable here from a lie about the length.
    if (body_len != fragment.len - handshake_header_bytes) {
        return .invalid;
    }
    var cursor: Cursor = .{ .bytes = fragment[handshake_header_bytes..] };
    // legacy_version and random, neither of which routing reads.
    if (!cursor.skip(client_hello_fixed_bytes)) return .invalid;
    // legacy_session_id, cipher_suites, legacy_compression_methods: three
    // length-prefixed runs between the random and the extensions.
    if (!cursor.skipVector(u8)) return .invalid;
    if (!cursor.skipVector(u16)) return .invalid;
    if (!cursor.skipVector(u8)) return .invalid;
    // TLS 1.2 allows a hello to end here. It carries no SNI, which is a
    // verdict rather than an error.
    if (cursor.remaining() == 0) return .{ .ok = .{ .server_name = null } };
    const extensions = cursor.takeVector(u16) orelse return .invalid;
    if (cursor.remaining() != 0) return .invalid;
    return parseExtensions(extensions);
}

fn parseExtensions(extensions: []const u8) Parsed {
    var cursor: Cursor = .{ .bytes = extensions };
    // Bounded by the input: every turn consumes at least the 4-byte
    // extension header, so this cannot run longer than a quarter of it.
    var seen: u32 = 0;
    while (cursor.remaining() >= 4) {
        assert(seen <= constants.client_hello_bytes_max / 4);
        seen += 1;
        const kind = cursor.takeInt(u16) orelse return .invalid;
        const body = cursor.takeVector(u16) orelse return .invalid;
        if (kind != extension_server_name) continue;
        return parseServerName(body);
    }
    // Trailing bytes that are not a whole extension header are a lie
    // about the extensions vector's length.
    if (cursor.remaining() != 0) return .invalid;
    return .{ .ok = .{ .server_name = null } };
}

/// RFC 6066 §3's `ServerNameList`. Only `host_name` is defined, and the
/// RFC says a list must not carry two entries of one type — so the first
/// `host_name` is the answer and anything after it is ignored, which is
/// what every peer does.
fn parseServerName(body: []const u8) Parsed {
    var cursor: Cursor = .{ .bytes = body };
    const list = cursor.takeVector(u16) orelse return .invalid;
    if (cursor.remaining() != 0) return .invalid;
    // RFC 6066 declares `server_name_list<1..2^16-1>`, so an empty list
    // is as illegal as the empty `host_name` refused below, and is
    // refused on the same terms. Judged here rather than left to fall
    // through as "no name": a hello the spec forbids must not quietly
    // take the any-SNI route, which is a routing decision made on input
    // that should never have been accepted.
    if (list.len == 0) return .invalid;
    var entries: Cursor = .{ .bytes = list };
    var seen: u32 = 0;
    while (entries.remaining() >= 3) {
        assert(seen <= constants.client_hello_bytes_max / 3);
        seen += 1;
        const name_type = entries.takeInt(u8) orelse return .invalid;
        const name = entries.takeVector(u16) orelse return .invalid;
        if (name_type != name_type_host_name) continue;
        // An empty host_name names nothing; RFC 6066 forbids it, and
        // treating it as absent would route an illegal hello somewhere.
        if (name.len == 0) return .invalid;
        return .{ .ok = .{ .server_name = name } };
    }
    if (entries.remaining() != 0) return .invalid;
    // A well-formed list with no `host_name` entry: no name to route on,
    // which is the same verdict as no extension at all.
    return .{ .ok = .{ .server_name = null } };
}

/// A forward-only reader over one length-prefixed region. Every taker
/// returns null rather than trapping, so a malformed hello is a verdict
/// and never a panic — this reaches attacker-controlled bytes on every
/// L4 connection.
const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,

    fn remaining(cursor: *const Cursor) usize {
        assert(cursor.at <= cursor.bytes.len);
        return cursor.bytes.len - cursor.at;
    }

    fn skip(cursor: *Cursor, count: u32) bool {
        if (cursor.remaining() < count) return false;
        cursor.at += count;
        assert(cursor.at <= cursor.bytes.len);
        return true;
    }

    fn takeInt(cursor: *Cursor, comptime T: type) ?T {
        const width = @divExact(@typeInfo(T).int.bits, 8);
        if (cursor.remaining() < width) return null;
        const value = std.mem.readInt(T, cursor.bytes[cursor.at..][0..width], .big);
        cursor.at += width;
        assert(cursor.at <= cursor.bytes.len);
        return value;
    }

    /// A `T`-length-prefixed run, returned as a slice of the input.
    ///
    /// Atomic: a run whose declared length overruns the input leaves the
    /// cursor exactly where it was, rather than half-advanced past the
    /// prefix it already read. No caller reads a cursor after a failed
    /// take today — every one of them returns `.invalid` — but a partial
    /// advance is the kind of state a later caller would inherit without
    /// knowing, and restoring it costs one saved index.
    fn takeVector(cursor: *Cursor, comptime T: type) ?[]const u8 {
        const before = cursor.at;
        const len = cursor.takeInt(T) orelse return null;
        if (cursor.remaining() < len) {
            cursor.at = before;
            return null;
        }
        const slice = cursor.bytes[cursor.at..][0..len];
        cursor.at += len;
        assert(cursor.at <= cursor.bytes.len);
        // The one property every caller rests on: what comes back is a
        // view of the input, never a copy and never past its end.
        assert(slice.len == len);
        return slice;
    }

    fn skipVector(cursor: *Cursor, comptime T: type) bool {
        const before = cursor.at;
        const taken = cursor.takeVector(T) != null;
        assert(cursor.at >= before);
        assert(taken or cursor.at == before);
        return taken;
    }
};

const testing = std.testing;

/// Build a ClientHello for the tests: one handshake record, the fixed
/// run, three empty vectors, and whatever extensions a case wants. Kept
/// as a builder rather than a hex blob so a case reads as the shape it is
/// testing — a blob would hide which byte a mutation moved.
const Builder = struct {
    buffer: [1024]u8 = undefined,
    len: usize = 0,

    fn byte(b: *Builder, value: u8) void {
        b.buffer[b.len] = value;
        b.len += 1;
    }

    fn int16(b: *Builder, value: u16) void {
        std.mem.writeInt(u16, b.buffer[b.len..][0..2], value, .big);
        b.len += 2;
    }

    fn slice(b: *Builder, bytes: []const u8) void {
        @memcpy(b.buffer[b.len..][0..bytes.len], bytes);
        b.len += bytes.len;
    }

    /// A whole hello wrapping `extensions`, or omitting the vector when
    /// null (the legal TLS 1.2 shape that carries none).
    fn hello(b: *Builder, extensions: ?[]const u8) []const u8 {
        b.len = 0;
        b.byte(record_type_handshake);
        b.int16(0x0301);
        const record_len_at = b.len;
        b.int16(0); // patched below
        const body_at = b.len;
        b.byte(handshake_type_client_hello);
        b.slice(&.{ 0, 0, 0 }); // patched below
        b.int16(0x0303);
        b.slice(&[_]u8{0} ** 32); // random
        b.byte(0); // legacy_session_id: empty
        b.int16(0); // cipher_suites: empty
        b.byte(0); // legacy_compression_methods: empty
        if (extensions) |bytes| {
            b.int16(@intCast(bytes.len));
            b.slice(bytes);
        }
        const body_len = b.len - body_at;
        std.mem.writeInt(u16, b.buffer[record_len_at..][0..2], @intCast(body_len), .big);
        std.mem.writeInt(
            u24,
            b.buffer[body_at + 1 ..][0..3],
            @intCast(body_len - handshake_header_bytes),
            .big,
        );
        return b.buffer[0..b.len];
    }
};

/// A `server_name` extension naming `name`.
fn sniExtension(out: []u8, name: []const u8) []const u8 {
    var at: usize = 0;
    std.mem.writeInt(u16, out[at..][0..2], extension_server_name, .big);
    at += 2;
    std.mem.writeInt(u16, out[at..][0..2], @intCast(name.len + 5), .big);
    at += 2;
    std.mem.writeInt(u16, out[at..][0..2], @intCast(name.len + 3), .big);
    at += 2;
    out[at] = name_type_host_name;
    at += 1;
    std.mem.writeInt(u16, out[at..][0..2], @intCast(name.len), .big);
    at += 2;
    @memcpy(out[at..][0..name.len], name);
    return out[0 .. at + name.len];
}

test "client_hello: a hello naming a server routes on that name" {
    var extension_buffer: [128]u8 = undefined;
    const extensions = sniExtension(&extension_buffer, "api.example.com");
    var builder: Builder = .{};
    const bytes = builder.hello(extensions);

    const parsed = parse(bytes);
    try testing.expect(parsed == .ok);
    try testing.expectEqualStrings("api.example.com", parsed.ok.server_name.?);
}

test "client_hello: absent is a verdict, not an error" {
    // Two legal shapes carry no name, and both route the any-SNI way
    // rather than being refused: no extensions vector at all (TLS 1.2),
    // and a vector holding some other extension.
    {
        var builder: Builder = .{};
        const parsed = parse(builder.hello(null));
        try testing.expect(parsed == .ok);
        try testing.expect(parsed.ok.server_name == null);
    }
    {
        // One unrelated extension (type 0x000b, ec_point_formats).
        const other = [_]u8{ 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 };
        var builder: Builder = .{};
        const parsed = parse(builder.hello(&other));
        try testing.expect(parsed == .ok);
        try testing.expect(parsed.ok.server_name == null);
    }
}

test "client_hello: every prefix of a valid hello asks for more" {
    // The monotonic contract, which is what lets the caller re-parse from
    // byte 0 on each delivery: no prefix of something that parses may
    // ever answer `invalid`, or a connection whose next segment completed
    // the hello would have been torn down.
    var extension_buffer: [128]u8 = undefined;
    const extensions = sniExtension(&extension_buffer, "db.example.com");
    var builder: Builder = .{};
    const bytes = builder.hello(extensions);

    var length: usize = 0;
    while (length < bytes.len) : (length += 1) {
        try testing.expect(parse(bytes[0..length]) == .need_more);
    }
    try testing.expect(parse(bytes) == .ok);
}

test "client_hello: a first byte that is not a handshake record fails at once" {
    // Negative space: no suffix repairs byte 0, so waiting for the cap's
    // worth of bytes would be a connection held open for nothing.
    try testing.expect(parse("G") == .invalid); // an HTTP request
    try testing.expect(parse(&.{0x17}) == .invalid); // application_data
    try testing.expect(parse(&.{0x15}) == .invalid); // alert
    try testing.expect(parse("") == .need_more);
}

test "client_hello: malformed bodies are refused, never trapped" {
    var extension_buffer: [128]u8 = undefined;
    const extensions = sniExtension(&extension_buffer, "api.example.com");
    var builder: Builder = .{};
    const valid = builder.hello(extensions);

    // A handshake type that is not client_hello.
    {
        var bytes: [512]u8 = undefined;
        @memcpy(bytes[0..valid.len], valid);
        bytes[record_header_bytes] = 0x02; // server_hello
        try testing.expect(parse(bytes[0..valid.len]) == .invalid);
    }
    // A handshake claiming more than its record holds — the fragmented
    // case this parser does not reassemble.
    {
        var bytes: [512]u8 = undefined;
        @memcpy(bytes[0..valid.len], valid);
        const at = record_header_bytes + 1;
        std.mem.writeInt(u24, bytes[at..][0..3], 0xFFFF, .big);
        try testing.expect(parse(bytes[0..valid.len]) == .invalid);
    }
    // A zero-length record names no handshake at all.
    {
        const empty = [_]u8{ record_type_handshake, 0x03, 0x01, 0x00, 0x00 };
        try testing.expect(parse(&empty) == .invalid);
    }
    // A record longer than the cap: the peer's number, refused by ours.
    {
        var bytes: [16]u8 = .{ record_type_handshake, 0x03, 0x01, 0xFF, 0xFF } ++
            [_]u8{0} ** 11;
        try testing.expect(parse(&bytes) == .invalid);
    }
    // An empty host_name names nothing, which RFC 6066 forbids.
    {
        const empty_name = sniExtension(&extension_buffer, "");
        var empty_builder: Builder = .{};
        try testing.expect(parse(empty_builder.hello(empty_name)) == .invalid);
    }
}

test "client_hello: a real OpenSSL hello parses" {
    // The other cases build their input from the same reading of the
    // spec the parser encodes, so they can only catch it disagreeing with
    // itself. This one is a byte string this repository did not author
    // (see testdata/README.md) — 1547 bytes, post-quantum key shares
    // included, which is also the size the cap is sized against.
    const captured = @embedFile("testdata/client_hello_openssl.bin");
    const parsed = parse(captured);
    try testing.expect(parsed == .ok);
    try testing.expectEqualStrings("real.example.com", parsed.ok.server_name.?);

    // And it obeys the monotonic contract too, which the builder cases
    // can only claim for the shape they happen to build.
    var length: usize = 0;
    while (length < captured.len) : (length += 1) {
        try testing.expect(parse(captured[0..length]) == .need_more);
    }
}

/// The §9 oracle: what must hold for *any* bytes, not just the ones a
/// case thought to write. Shared by the mutation sweep and the fuzz gate
/// so the two cannot check different things.
fn checkParse(input: []const u8) void {
    const parsed = parse(input);
    if (parsed == .ok) {
        if (parsed.ok.server_name) |name| {
            // The name is a view of the input, never a copy and never
            // past its end — the property the router will rest on when it
            // compares this against a configured name without owning it.
            assert(name.len >= 1);
            assert(@intFromPtr(name.ptr) >= @intFromPtr(input.ptr));
            assert(@intFromPtr(name.ptr) + name.len <= @intFromPtr(input.ptr) + input.len);
        }
    }
    // Monotonicity, the accumulate-and-retry contract (module header):
    // an input not yet judged `.invalid` must read `.need_more` at every
    // strict prefix, or a connection whose next segment completed the
    // hello would have been torn down mid-handshake.
    if (parsed != .invalid) {
        var prefix_len: usize = 0;
        while (prefix_len < input.len) : (prefix_len += 1) {
            assert(parse(input[0..prefix_len]) == .need_more);
        }
    }
}

/// Seeds for the fuzz gate: one hello per shape the parser forks on, so
/// the mutator starts from inputs that already reach the extension walk
/// rather than having to discover a 43-byte header by chance.
const fuzz_corpus_named = blk: {
    @setEvalBranchQuota(20_000);
    var extension_buffer: [128]u8 = undefined;
    const extensions = sniExtension(&extension_buffer, "api.example.com");
    var builder: Builder = .{};
    const bytes = builder.hello(extensions);
    const frozen = bytes[0..bytes.len].*;
    break :blk &frozen;
};

test "fuzz: client hello — parse or reject, no third outcome" {
    try std.testing.fuzz({}, fuzzParseInputs, .{
        .corpus = &.{
            fuzz_corpus_named,
            @embedFile("testdata/client_hello_openssl.bin"),
        },
    });
}

fn fuzzParseInputs(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    // Past the cap, so an over-cap record declaration and long garbage
    // are both reachable alongside every legal size.
    var input_buffer: [2 * 1024]u8 = undefined;
    const input_len = smith.slice(&input_buffer);
    assert(input_len <= input_buffer.len);
    checkParse(input_buffer[0..input_len]);
}

test "client_hello: every truncation and every single-byte mutation is total" {
    // The §9 oracle for a parser that reaches attacker-controlled bytes
    // on every L4 connection: it must always answer, never trap, and
    // never hand back a name pointing outside the input. `parse`'s own
    // asserts check the last of those, so reaching them is the test.
    var extension_buffer: [128]u8 = undefined;
    const extensions = sniExtension(&extension_buffer, "api.example.com");
    var builder: Builder = .{};
    const valid = builder.hello(extensions);

    var scratch: [512]u8 = undefined;
    var index: usize = 0;
    while (index < valid.len) : (index += 1) {
        // Truncated here.
        checkParse(valid[0..index]);
        // And every byte value at this position, full length.
        var value: u16 = 0;
        while (value <= 0xFF) : (value += 1) {
            @memcpy(scratch[0..valid.len], valid);
            scratch[index] = @intCast(value);
            checkParse(scratch[0..valid.len]);
        }
    }
}
