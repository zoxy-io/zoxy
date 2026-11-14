//! The h1 → h2 boundary for responses (#275): the HTTP/1.1 response head
//! the exchange rendered for its client, read back by
//! `parser.parseResponseHead` and said again as the field section HTTP/2
//! sends — the mirror of `downgrade.zig`, and for the same reason.
//!
//! The exchange already renders a response head with every §7 decision
//! applied: the origin's hop-by-hop fields stripped, the listener's
//! filters and edits, the stickiness cookie, the persistence it announces.
//! Reading that rendering back, rather than mapping the origin's parsed
//! head a second way, keeps one statement of those decisions; what is left
//! here is only what HTTP/2 says differently:
//!
//! - `:status` leads (§8.3.2), and 101 is refused — HTTP/2 has no
//!   Switching Protocols (§8.6), and an upgrade cannot reach here.
//! - Names are lowercase (§8.2.1); HTTP/1.1's are case-insensitive, so the
//!   field is the same field.
//! - Every connection-specific field goes (§8.2.2): the ones `parser`
//!   classifies hop-by-hop, which include the `Connection` line the
//!   renderer wrote for HTTP/1.1 persistence, and `transfer-encoding`,
//!   whose chunking DATA frames replace — the body's framing comes back
//!   as `framing`, for the relay to undo. `trailer` goes with it: the
//!   relay carries a chunked body's payload, not its trailer section, so
//!   a field announcing one would announce nothing. So does any field a
//!   `Connection` line nominates (RFC 9110 §7.6.1) — the renderer strips
//!   those from what it forwards, and this holds any head to the same
//!   rule rather than trust that it did — except the protected ones, as
//!   the renderer has it: a nominated `content-length` is still framing.
//! - `content-length` goes from a 1xx or a 204, which RFC 9110 §8.6 says a
//!   server MUST NOT send it on: an HTTP/1.1 client shrugs, a strict
//!   HTTP/2 one resets the stream. A HEAD or 304 response keeps it — there
//!   it describes the representation, and §8.1.1 allows it.
//!
//! Every value carried is the rendered head's octets, unchanged: the
//! HTTP/1.1 parser already holds them to the bytes RFC 9110 allows, which
//! are the bytes RFC 9113's strict reading allows too.

const std = @import("std");
const h2 = @import("h2");

const constants = @import("../../constants.zig");
const parser = @import("../parser.zig");

const hpack = h2.hpack;
const assert = std.debug.assert;

pub const Error = error{
    /// Not a head HTTP/2 can carry: a 101, or a head the HTTP/1.1 parser
    /// refuses, a head past its buffer included — which, for a head this
    /// proxy rendered itself, is a bug's signature rather than an
    /// origin's. The stream is reset.
    Malformed,
    /// More fields, or more name octets, than the caller lent room for.
    TooLarge,
};

pub const Response = struct {
    status: u16,
    /// A 1xx: more heads follow, and it ends nothing (§8.1).
    interim: bool,
    /// How the body after this head is delimited on the HTTP/1.1 side,
    /// which the relay undoes before DATA carries it.
    framing: parser.BodyFraming,
    /// `:status` first, then the response's fields; the slices point into
    /// `bytes` (names, the status digits) and into the rendered head
    /// (values).
    fields: []const hpack.Field,
    /// Where the head ends in the rendered octets; body octets coalesced
    /// with it follow.
    head_len: u32,
};

/// What `responseHead` writes into: the field list, and the octets of the
/// lowercased names and the status digits. Enough for any head is one
/// field more than `headers_max` and as many octets as the head itself.
pub const Out = struct {
    fields: []hpack.Field,
    bytes: []u8,
};

/// Map the rendered HTTP/1.1 head at the front of `rendered` to the field
/// section HTTP/2 sends. `method` is the request's: it decides whether a
/// body follows (a HEAD response has none, whatever it declares).
pub fn responseHead(
    rendered: []const u8,
    method: parser.Method,
    storage: *parser.HeaderStorage,
    out: *const Out,
) Error!Response {
    assert(rendered.len >= 1);
    // The parser's own bound, stated here where a caller would cross it:
    // `rendered` is a head buffer's contents, coalesced body and all.
    assert(rendered.len <= constants.head_buffer_bytes_max);
    assert(method != .connect); // §7 answers CONNECT itself.
    const parsed = parser.parseResponseHead(rendered, true, storage, method) catch return error.Malformed;
    if (parsed.status == 101) return error.Malformed;
    if (out.fields.len == 0) return error.TooLarge;
    if (out.bytes.len < 3) return error.TooLarge;
    var digits: [3]u8 = undefined;
    _ = std.fmt.bufPrint(&digits, "{d}", .{parsed.status}) catch unreachable; // 100..999.
    @memcpy(out.bytes[0..3], &digits);
    out.fields[0] = .{ .name = ":status", .value = out.bytes[0..3] };
    var count: u32 = 1;
    var used: u32 = 3;
    for (parsed.headers) |*header| {
        if (!carried(&parsed, header)) continue;
        if (count == out.fields.len) return error.TooLarge;
        if (header.name.len > out.bytes.len - used) return error.TooLarge;
        const name = out.bytes[used..][0..header.name.len];
        _ = std.ascii.lowerString(name, header.name);
        used += @intCast(name.len);
        out.fields[count] = .{ .name = name, .value = header.value };
        count += 1;
    }
    assert(count <= out.fields.len);
    assert(used <= out.bytes.len);
    return .{
        .status = parsed.status,
        .interim = parsed.status < 200,
        .framing = parsed.framing,
        .fields = out.fields[0..count],
        .head_len = parsed.head_len,
    };
}

/// Whether a rendered field goes on to HTTP/2: anything but the
/// connection-specific ones (§8.2.2), a `content-length` §8.6 forbids, the
/// trailer announcement, and what a `Connection` line nominates.
fn carried(parsed: *const parser.ResponseHead, header: *const parser.Header) bool {
    assert(header.name.len >= 1);
    assert(parsed.status >= 100);
    if (header.tag.hopByHop()) return false;
    if (header.tag == .transfer_encoding) return false;
    if (header.tag == .content_length) return lengthAllowed(parsed.status);
    if (std.ascii.eqlIgnoreCase(header.name, "trailer")) return false;
    if (!parsed.connection_nominates_header) return true;
    if (header.tag.protected()) return true;
    return !nominated(parsed.headers, header.name);
}

/// RFC 9110 §8.6: never on a 1xx or a 204.
fn lengthAllowed(status: u16) bool {
    if (status < 200) return false;
    return status != 204;
}

/// Whether a `Connection` line in `headers` names `name` (RFC 9110 §7.6.1).
fn nominated(headers: []const parser.Header, name: []const u8) bool {
    assert(name.len >= 1);
    for (headers) |*header| {
        if (header.tag != .connection) continue;
        if (parser.tokenListHas(header.value, name)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const seed = @import("../../testing/bytes.zig").fuzzSeed;
const MessageValidator = h2.fields.MessageValidator;

const Fixture = struct {
    storage: parser.HeaderStorage = undefined,
    fields: [constants.headers_max + 1]hpack.Field = undefined,
    bytes: [4096]u8 = undefined,

    fn map(fixture: *Fixture, rendered: []const u8, method: parser.Method) Error!Response {
        return responseHead(rendered, method, &fixture.storage, &.{ .fields = &fixture.fields, .bytes = &fixture.bytes });
    }
};

fn expectFields(expected: []const [2][]const u8, actual: []const hpack.Field) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| {
        try testing.expectEqualStrings(want[0], got.name);
        try testing.expectEqualStrings(want[1], got.value);
    }
}

/// The session refuses what HTTP/2 cannot carry; every head mapped here
/// must be one it would send.
fn expectValid(fields: []const hpack.Field) !void {
    var validator = MessageValidator.init(.{ .kind = .response, .rules = .strict });
    for (fields) |*field| try validator.field(field);
    try validator.finish();
}

test "response: a rendered HTTP/1.1 head becomes HTTP/2's fields, persistence and chunking gone" {
    var fixture: Fixture = .{};
    const rendered = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n" ++
        "Connection: keep-alive\r\nX-Request-Id: abc\r\n\r\n5\r\nhello\r\n";
    const response = try fixture.map(rendered, .get);
    try expectFields(&.{
        .{ ":status", "200" },
        .{ "content-type", "text/plain" },
        .{ "x-request-id", "abc" },
    }, response.fields);
    try testing.expectEqual(parser.BodyFraming.chunked, response.framing);
    try testing.expect(!response.interim);
    try testing.expectEqualStrings("5\r\nhello\r\n", rendered[response.head_len..]);
    try expectValid(response.fields);
}

test "response: a length is kept, and a HEAD or 304 response says one and carries no body" {
    var fixture: Fixture = .{};
    const rendered = "HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
    const get = try fixture.map(rendered, .get);
    try testing.expectEqual(parser.BodyFraming{ .content_length = 42 }, get.framing);
    try expectFields(&.{ .{ ":status", "200" }, .{ "content-length", "42" } }, get.fields);
    const head = try fixture.map(rendered, .head);
    try testing.expectEqual(parser.BodyFraming.none, head.framing);
    try expectFields(&.{ .{ ":status", "200" }, .{ "content-length", "42" } }, head.fields);
    const not_modified = try fixture.map("HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n", .get);
    try testing.expectEqual(parser.BodyFraming.none, not_modified.framing);
    try expectValid(not_modified.fields);
}

test "response: an interim head is marked so, and 101 has no HTTP/2 form" {
    var fixture: Fixture = .{};
    const hints = try fixture.map("HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n", .get);
    try testing.expect(hints.interim);
    try expectFields(&.{ .{ ":status", "103" }, .{ "link", "</a.css>; rel=preload" } }, hints.fields);
    try testing.expectError(error.Malformed, fixture.map("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", .get));
}

test "response: every connection-specific field goes, and the trailer announcement with them" {
    var fixture: Fixture = .{};
    const rendered = "HTTP/1.1 200 OK\r\nKeep-Alive: timeout=5\r\nProxy-Connection: keep-alive\r\n" ++
        "Upgrade: h2c\r\nTE: trailers\r\nTrailer: X-Checksum\r\nConnection: close\r\nServer: o\r\nContent-Length: 0\r\n\r\n";
    const response = try fixture.map(rendered, .get);
    try expectFields(&.{ .{ ":status", "200" }, .{ "server", "o" }, .{ "content-length", "0" } }, response.fields);
    try expectValid(response.fields);
}

test "response: a length goes from a 1xx or a 204, and a nominated field goes with the connection's" {
    var fixture: Fixture = .{};
    const no_content = try fixture.map("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nServer: o\r\n\r\n", .get);
    try expectFields(&.{ .{ ":status", "204" }, .{ "server", "o" } }, no_content.fields);
    const hints = try fixture.map("HTTP/1.1 103 Hints\r\nContent-Length: 0\r\nLink: <a>\r\n\r\n", .get);
    try expectFields(&.{ .{ ":status", "103" }, .{ "link", "<a>" } }, hints.fields);
    // An origin's nomination, whatever the renderer did with it: the field
    // it names is connection-specific, and a protected one is still framing.
    const nominating = "HTTP/1.1 200 OK\r\nConnection: x-hop, content-length\r\nX-Hop: 1\r\n" ++
        "X-End: 2\r\nContent-Length: 0\r\n\r\n";
    const response = try fixture.map(nominating, .get);
    try expectFields(&.{ .{ ":status", "200" }, .{ "x-end", "2" }, .{ "content-length", "0" } }, response.fields);
}

test "response: past the room lent, the head is refused rather than cut" {
    var storage: parser.HeaderStorage = undefined;
    var fields: [2]hpack.Field = undefined;
    var bytes: [64]u8 = undefined;
    const rendered = "HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\nContent-Length: 0\r\n\r\n";
    try testing.expectError(error.TooLarge, responseHead(rendered, .get, &storage, &.{ .fields = &fields, .bytes = &bytes }));
    var few: [4]u8 = undefined;
    var room: [8]hpack.Field = undefined;
    try testing.expectError(error.TooLarge, responseHead(rendered, .get, &storage, &.{ .fields = &room, .bytes = &few }));
    try testing.expectError(error.Malformed, responseHead("HTTP/1.1 2 OK\r\n\r\n", .get, &storage, &.{ .fields = &room, .bytes = &bytes }));
}

test "fuzz: response — whatever the HTTP/1.1 parser accepts maps to fields HTTP/2 sends, or is refused" {
    try testing.fuzz({}, fuzzResponse, .{ .corpus = &.{
        seed("\x00HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"),
        seed("\x01HTTP/1.1 304 Not Modified\r\nETag: x\r\nConnection: keep-alive\r\n\r\n"),
        seed("\x00HTTP/1.0 103 Hints\r\nLink: <a>\r\n\r\n"),
        seed("\x00HTTP/1.1 200 OK\r\nTrailer: X\r\nUpgrade: y\r\nContent-Length: 3\r\n\r\nabc"),
    } });
}

/// Any octets, read as a response head with a method from the first
/// octet: wherever the HTTP/1.1 parser accepts one, the mapping either
/// refuses it for a stated reason or produces fields HTTP/2's strict
/// validator accepts — every field the parser read that HTTP/2 carries,
/// in order, its name lowercased and its value untouched, and nothing it
/// does not.
fn fuzzResponse(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input: [2048]u8 = undefined;
    const input_len = smith.slice(&input);
    if (input_len < 2) return;
    const methods = [_]parser.Method{ .get, .head, .post };
    const method = methods[input[0] % methods.len];
    const rendered = input[1..input_len];
    var check_storage: parser.HeaderStorage = undefined;
    const parsed = parser.parseResponseHead(rendered, true, &check_storage, method) catch return;
    var fixture: Fixture = .{};
    const response = fixture.map(rendered, method) catch |err| {
        assert(err == error.Malformed);
        assert(parsed.status == 101);
        return;
    };
    assert(response.status == parsed.status);
    assert(response.head_len == parsed.head_len);
    expectValid(response.fields) catch unreachable;
    var index: usize = 1;
    for (parsed.headers) |*header| {
        if (!carried(&parsed, header)) continue;
        const field = response.fields[index];
        assert(field.name.len == header.name.len);
        for (field.name, header.name) |got, want| assert(got == std.ascii.toLower(want));
        assert(std.mem.eql(u8, field.value, header.value));
        index += 1;
    }
    assert(index == response.fields.len);
    // And never a length §8.6 forbids.
    if (!lengthAllowed(parsed.status)) {
        for (response.fields) |field| assert(!std.mem.eql(u8, field.name, "content-length"));
    }
}
