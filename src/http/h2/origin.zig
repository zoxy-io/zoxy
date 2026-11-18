//! The h1 ↔ h2 boundary for an origin reached over HTTP/2: the request the
//! exchange rendered for an HTTP/1.1 origin, said again as the field
//! section HTTP/2 sends, and the origin's answer said again as the
//! HTTP/1.1 response the exchange reads — the mirror of `downgrade.zig`
//! and `response.zig`, at the other end, and for the same reason.
//!
//! The exchange renders an upstream request head with every §7 decision
//! applied: the filters' edits, `X-Forwarded-For`, the `Max-Forwards`
//! decrement, the hop-by-hop fields stripped. Reading that rendering back
//! keeps one statement of those decisions, and the parse that reads it is
//! the one every origin-bound head already passed. What is left here is
//! only what HTTP/2 says differently:
//!
//! - the request line and `Host` become `:method`, `:scheme`,
//!   `:authority` and `:path` (RFC 9113 §8.3.1);
//! - names are lowercase (§8.2.1);
//! - the connection-specific fields go (§8.2.2), `transfer-encoding`
//!   among them — DATA frames the body, and the caller strips the
//!   chunking from the octets it sends;
//! - `te: trailers` is said, the one TE value HTTP/2 allows: this proxy
//!   carries trailers to every client it has (§7), and a gRPC origin
//!   expects to hear it.
//!
//! The answer comes back as an HTTP/1.1 head the exchange parses like any
//! origin's — `parser.parseResponseHead`, the same trust boundary — with
//! the body's framing chosen here: the origin's `content-length` when it
//! declared one, `chunked` otherwise, so that a trailer section has
//! somewhere to go (`trailerSection`), and none when the answer can carry
//! no body at all.

const std = @import("std");
const h2 = @import("h2");

const constants = @import("../../constants.zig");
const parser = @import("../parser.zig");

const hpack = h2.hpack;
const assert = std.debug.assert;

pub const Error = error{
    /// Not a head HTTP/2 can carry, or not one the HTTP/1.1 parser reads
    /// back: the exchange's own rendering, so a bug's signature rather than
    /// a client's. The leg fails.
    Malformed,
    /// More fields, or more octets, than the caller lent room for.
    TooLarge,
};

/// Where `requestFields` writes: the field list, and the octets of the
/// lowercased names and anything this side spells itself.
pub const Out = struct {
    fields: []hpack.Field,
    bytes: []u8,
};

pub const Request = struct {
    /// Pseudo-headers first, then the forwarded fields, then `te`. Values
    /// point into the rendered head and into `Out.bytes`.
    fields: []const hpack.Field,
    /// How the body octets after the head are delimited: what the caller
    /// strips before DATA carries them.
    framing: parser.BodyFraming,
    /// A HEAD: its answer declares a length it never sends.
    bodiless: bool,
    head_len: u32,
};

/// The most fields a request maps to: the parser's bound, four
/// pseudo-headers, and `te`.
pub const request_fields_max: u32 = constants.headers_max + 5;

comptime {
    // Every header the parser admits, beside what this side adds.
    assert(request_fields_max == constants.headers_max + 4 + 1);
}

/// Map the rendered HTTP/1.1 request head at the front of `rendered` to the
/// field section an HTTP/2 origin is sent. `scheme` is the origin's: `http`
/// for h2c.
pub fn requestFields(
    rendered: []const u8,
    scheme: []const u8,
    storage: *parser.HeaderStorage,
    out: *const Out,
) Error!Request {
    assert(rendered.len >= 1);
    assert(rendered.len <= constants.head_buffer_bytes_max);
    assert(scheme.len >= 1);
    const parsed = parser.parseRequestHead(rendered, true, storage, null) catch return error.Malformed;
    // §7 answers a CONNECT itself and refuses an upgrade to an HTTP/2
    // origin at load; neither can be rendered for one.
    if (parsed.method == .connect) return error.Malformed;
    if (parser.headerValue(parsed.headers, "upgrade") != null) return error.Malformed;
    const authority = parsed.routingAuthority() orelse return error.Malformed;
    var writer: Writer = .{ .out = out };
    try writer.field(":method", parsed.method_token);
    try writer.field(":scheme", scheme);
    try writer.field(":authority", authority);
    try writer.field(":path", try writer.path(parsed.target, parsed.method));
    for (parsed.headers) |*header| {
        if (!requestCarries(&parsed, header)) continue;
        try writer.field(try writer.lowered(header.name), header.value);
    }
    try writer.field("te", "trailers");
    assert(writer.count >= 5);
    return .{
        .fields = out.fields[0..writer.count],
        .framing = parsed.framing,
        .bodiless = parsed.method == .head,
        .head_len = parsed.head_len,
    };
}

/// Whether a rendered request field goes on to HTTP/2: not the `Host`
/// that became `:authority`, not a connection-specific field or the
/// framing DATA replaces, not the trailer announcement, and not what a
/// `Connection` line nominates (RFC 9110 §7.6.1) — which the renderer
/// already stripped, and this holds to the same rule rather than trust.
fn requestCarries(parsed: *const parser.RequestHead, header: *const parser.Header) bool {
    assert(header.name.len >= 1);
    if (header.tag == .host) return false;
    if (header.tag.hopByHop()) return false;
    if (header.tag == .transfer_encoding) return false;
    if (std.ascii.eqlIgnoreCase(header.name, "trailer")) return false;
    if (!parsed.connection_nominates_header) return true;
    if (header.tag.protected()) return true;
    return !nominated(parsed.headers, header.name);
}

fn nominated(headers: []const parser.Header, name: []const u8) bool {
    assert(name.len >= 1);
    for (headers) |*header| {
        if (header.tag != .connection) continue;
        if (parser.tokenListHas(header.value, name)) return true;
    }
    return false;
}

const Writer = struct {
    out: *const Out,
    count: u32 = 0,
    used: u32 = 0,

    fn field(writer: *Writer, name: []const u8, value: []const u8) Error!void {
        assert(name.len >= 1);
        assert(writer.count <= writer.out.fields.len);
        if (writer.count == writer.out.fields.len) return error.TooLarge;
        writer.out.fields[writer.count] = .{ .name = name, .value = value };
        writer.count += 1;
    }

    fn lowered(writer: *Writer, name: []const u8) Error![]const u8 {
        assert(name.len >= 1);
        assert(writer.used <= writer.out.bytes.len);
        if (name.len > writer.out.bytes.len - writer.used) return error.TooLarge;
        const target = writer.out.bytes[writer.used..][0..name.len];
        _ = std.ascii.lowerString(target, name);
        writer.used += @intCast(name.len);
        return target;
    }

    /// `:path` (§8.3.1): origin-form as it stands, `*` for a server-wide
    /// OPTIONS, and a bare query given the root it is relative to.
    fn path(writer: *Writer, target: []const u8, method: parser.Method) Error![]const u8 {
        assert(target.len >= 1);
        if (target[0] == '/') return target;
        if (std.mem.eql(u8, target, "*")) {
            if (method != .options) return error.Malformed;
            return target;
        }
        if (target[0] != '?') return error.Malformed;
        if (target.len + 1 > writer.out.bytes.len - writer.used) return error.TooLarge;
        const rooted = writer.out.bytes[writer.used..][0 .. target.len + 1];
        rooted[0] = '/';
        @memcpy(rooted[1..], target);
        writer.used += @intCast(rooted.len);
        return rooted;
    }
};

// ---------------------------------------------------------------------------
// The answer
// ---------------------------------------------------------------------------

/// How the body after a written response head is delimited, which is how
/// the caller writes the DATA and trailers that follow it.
pub const Framing = enum {
    /// No body follows: an interim head, an answer that can carry none, or
    /// one whose stream ended with its head.
    none,
    /// The origin's declared length: DATA octets as they are. A trailer
    /// section has no place in this framing and is dropped.
    length,
    /// Chunked: each run of DATA a chunk, and the end the last chunk with
    /// the trailer section in it.
    chunked,
};

pub const Head = struct {
    len: u32,
    framing: Framing,
};

/// What `responseHead` is told about the answer, from the session's
/// `.response` event and the request it answers.
pub const Answer = struct {
    status: u16,
    /// `:status` among them; skipped.
    fields: []const hpack.Field,
    /// The declared length that binds DATA, as the session read it — null
    /// when none was declared or none binds.
    content_length: ?u64,
    interim: bool,
    end_stream: bool,
    /// The request was a HEAD.
    bodiless: bool,
};

/// Write the HTTP/1.1 head an HTTP/2 answer stands for into `out`, with
/// the framing chosen for its body.
///
/// The session read the fields under RFC 9113's strict rules: no
/// connection-specific field (§8.2.2), and no value with a CR, LF or NUL
/// (§8.2.1). Both are what makes writing them into a head safe, so both
/// are checked again here, where a lapse would be head injection into
/// the exchange's parser — refused as Malformed rather than asserted,
/// because the octets are an origin's.
pub fn responseHead(answer: *const Answer, out: []u8) Error!Head {
    assert(answer.status >= 100 and answer.status <= 599);
    assert(answer.status != 101);
    assert(answer.interim == (answer.status < 200));
    var writer: TextWriter = .{ .out = out };
    try writer.statusLine(answer.status);
    for (answer.fields) |*field| {
        assert(field.name.len >= 1);
        if (field.name[0] == ':') continue;
        // A length is written below, as the framing decides.
        if (std.mem.eql(u8, field.name, "content-length")) continue;
        try writer.carried(field);
    }
    const framing = framingFor(answer);
    switch (framing) {
        .none => try writer.noBody(answer),
        .length => try writer.length(answer.content_length.?),
        .chunked => try writer.line("transfer-encoding", "chunked"),
    }
    try writer.raw("\r\n");
    assert(writer.used <= out.len);
    assert(writer.used >= "HTTP/1.1 100 \r\n\r\n".len);
    return .{ .len = writer.used, .framing = framing };
}

fn framingFor(answer: *const Answer) Framing {
    assert(answer.status >= 100 and answer.status <= 599);
    const framing: Framing = framing: {
        if (answer.interim) break :framing .none;
        if (answer.bodiless) break :framing .none;
        if (answer.status == 204 or answer.status == 304) break :framing .none;
        if (answer.content_length != null) break :framing .length;
        if (answer.end_stream) break :framing .none;
        break :framing .chunked;
    };
    if (framing == .length) assert(answer.content_length != null);
    if (framing == .chunked) assert(!answer.interim and !answer.bodiless and !answer.end_stream);
    return framing;
}

/// The last chunk and its trailer section: `0`, a field line per trailer a
/// chunked scanner would pass on (#244 refuses the names §7 decides, so
/// those are not said), and the closing CRLF. Answers the octets written.
pub fn trailerSection(fields: []const hpack.Field, out: []u8) Error!u32 {
    var writer: TextWriter = .{ .out = out };
    try writer.raw("0\r\n");
    for (fields) |*field| {
        assert(field.name.len >= 1);
        if (field.name[0] == ':') return error.Malformed; // §8.3: none in trailers.
        if (parser.classifyHeaderName(field.name) != .other) continue;
        try writer.carried(field);
    }
    try writer.raw("\r\n");
    assert(writer.used >= "0\r\n\r\n".len);
    assert(writer.used <= out.len);
    // The section the scanner reads back is bounded; one past it is refused
    // there, so it is refused here, where the cause is still known.
    if (writer.used - "0\r\n".len > constants.chunked_trailer_bytes_max) return error.TooLarge;
    return writer.used;
}

const TextWriter = struct {
    out: []u8,
    used: u32 = 0,

    fn raw(writer: *TextWriter, bytes: []const u8) Error!void {
        assert(writer.used <= writer.out.len);
        if (bytes.len > writer.out.len - writer.used) return error.TooLarge;
        @memcpy(writer.out[writer.used..][0..bytes.len], bytes);
        writer.used += @intCast(bytes.len);
        assert(writer.used <= writer.out.len);
    }

    fn line(writer: *TextWriter, name: []const u8, value: []const u8) Error!void {
        assert(name.len >= 1);
        try writer.raw(name);
        try writer.raw(": ");
        try writer.raw(value);
        try writer.raw("\r\n");
    }

    /// An origin's field, written only if a head can carry it: not one
    /// that frames or scopes a connection, and no value that could end
    /// the line it is written on.
    fn carried(writer: *TextWriter, field: *const hpack.Field) Error!void {
        assert(field.name.len >= 1);
        const tag = parser.classifyHeaderName(field.name);
        if (tag.hopByHop() or tag == .transfer_encoding) return error.Malformed;
        if (std.mem.indexOfAny(u8, field.name, "\r\n\x00: ") != null) return error.Malformed;
        if (std.mem.indexOfAny(u8, field.value, "\r\n\x00") != null) return error.Malformed;
        try writer.line(field.name, field.value);
    }

    /// HTTP/2 carries no reason phrase (§8.3.2); the standard one is said
    /// where there is one, and none otherwise, which RFC 9112 §4 allows.
    fn statusLine(writer: *TextWriter, status: u16) Error!void {
        assert(status >= 100 and status <= 599);
        assert(writer.used == 0);
        var digits: [3]u8 = undefined;
        _ = std.fmt.bufPrint(&digits, "{d}", .{status}) catch unreachable; // Three digits.
        try writer.raw("HTTP/1.1 ");
        try writer.raw(&digits);
        try writer.raw(" ");
        const known: std.http.Status = @fromBackingInt(@intCast(status));
        if (known.phrase()) |phrase| try writer.raw(phrase);
        try writer.raw("\r\n");
    }

    /// No body: a length is said only where it describes one the answer
    /// could have had — a HEAD's or a 304's, as the origin declared it, and
    /// zero for a final answer whose stream ended with its head.
    fn noBody(writer: *TextWriter, answer: *const Answer) Error!void {
        assert(writer.used >= 1);
        if (answer.interim or answer.status == 204) return;
        if (answer.content_length) |declared| return writer.length(declared);
        if (answer.bodiless or answer.status == 304) return;
        try writer.length(0);
    }

    fn length(writer: *TextWriter, value: u64) Error!void {
        assert(writer.used >= 1);
        var digits: [20]u8 = undefined;
        const text = std.fmt.bufPrint(&digits, "{d}", .{value}) catch unreachable;
        try writer.line("content-length", text);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const MessageValidator = h2.fields.MessageValidator;

const Fixture = struct {
    storage: parser.HeaderStorage = undefined,
    fields: [request_fields_max]hpack.Field = undefined,
    bytes: [4096]u8 = undefined,
    response_storage: parser.HeaderStorage = undefined,

    fn request(fixture: *Fixture, rendered: []const u8) Error!Request {
        return requestFields(rendered, "http", &fixture.storage, &.{ .fields = &fixture.fields, .bytes = &fixture.bytes });
    }
};

fn expectFields(expected: []const [2][]const u8, actual: []const hpack.Field) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| {
        try testing.expectEqualStrings(want[0], got.name);
        try testing.expectEqualStrings(want[1], got.value);
    }
}

fn expectValid(fields: []const hpack.Field, kind: MessageValidator.Kind) !void {
    var validator = MessageValidator.init(.{ .kind = kind, .rules = .strict });
    for (fields) |*field| try validator.field(field);
    try validator.finish();
}

test "origin: a rendered request becomes HTTP/2's fields, Host as :authority, te: trailers said" {
    var fixture: Fixture = .{};
    const rendered = "POST /helloworld.Greeter/SayHello HTTP/1.1\r\nHost: api.test\r\n" ++
        "Content-Type: application/grpc\r\nTransfer-Encoding: chunked\r\nX-Forwarded-For: 10.0.0.1\r\n\r\n" ++
        "5\r\nhello\r\n";
    const request = try fixture.request(rendered);
    try expectFields(&.{
        .{ ":method", "POST" },
        .{ ":scheme", "http" },
        .{ ":authority", "api.test" },
        .{ ":path", "/helloworld.Greeter/SayHello" },
        .{ "content-type", "application/grpc" },
        .{ "x-forwarded-for", "10.0.0.1" },
        .{ "te", "trailers" },
    }, request.fields);
    try testing.expectEqual(parser.BodyFraming.chunked, request.framing);
    try testing.expectEqualStrings("5\r\nhello\r\n", rendered[request.head_len..]);
    try testing.expect(!request.bodiless);
    try expectValid(request.fields, .request);
}

test "origin: a length, a HEAD, a server-wide OPTIONS and a bare query map as HTTP/2 says them" {
    var fixture: Fixture = .{};
    const length = try fixture.request("PUT /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n");
    try testing.expectEqual(parser.BodyFraming{ .content_length = 3 }, length.framing);
    try testing.expectEqualStrings("content-length", length.fields[4].name);
    try expectValid(length.fields, .request);
    const head = try fixture.request("HEAD / HTTP/1.1\r\nHost: a\r\n\r\n");
    try testing.expect(head.bodiless);
    const options = try fixture.request("OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n");
    try testing.expectEqualStrings("*", options.fields[3].value);
    try expectValid(options.fields, .request);
    // An absolute-form target naming only a query: its root is said.
    const query = try fixture.request("GET http://a?q=1 HTTP/1.1\r\nHost: a\r\n\r\n");
    try testing.expectEqualStrings("/?q=1", query.fields[3].value);
    try expectValid(query.fields, .request);
}

test "origin: what HTTP/2 cannot carry, or the parser refuses, is refused" {
    var fixture: Fixture = .{};
    const refused = [_][]const u8{
        "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
        "CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
        "GET / HTTP/1.0\r\n\r\n",
        "GET /\r\n",
    };
    for (refused) |rendered| {
        try testing.expectError(error.Malformed, fixture.request(rendered));
    }
}

test "origin: connection-specific and nominated fields go" {
    var fixture: Fixture = .{};
    const request = try fixture.request("GET / HTTP/1.1\r\nHost: a\r\nConnection: x-hop\r\nX-Hop: 1\r\n" ++
        "Keep-Alive: timeout=5\r\nTE: gzip\r\nTrailer: X-Sum\r\nX-End: 1\r\n\r\n");
    try expectFields(&.{
        .{ ":method", "GET" },
        .{ ":scheme", "http" },
        .{ ":authority", "a" },
        .{ ":path", "/" },
        .{ "x-end", "1" },
        .{ "te", "trailers" },
    }, request.fields);
    try expectValid(request.fields, .request);
}

fn parseBack(fixture: *Fixture, head: []const u8, method: parser.Method) !parser.ResponseHead {
    return parser.parseResponseHead(head, true, &fixture.response_storage, method);
}

test "origin: an answer with no declared length is chunked, so its trailers have a place" {
    var fixture: Fixture = .{};
    var out: [512]u8 = undefined;
    const head = try responseHead(&.{
        .status = 200,
        .fields = &.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "application/grpc" } },
        .content_length = null,
        .interim = false,
        .end_stream = false,
        .bodiless = false,
    }, &out);
    try testing.expectEqual(Framing.chunked, head.framing);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-type: application/grpc\r\ntransfer-encoding: chunked\r\n\r\n", out[0..head.len]);
    const parsed = try parseBack(&fixture, out[0..head.len], .post);
    try testing.expectEqual(parser.BodyFraming.chunked, parsed.framing);
    try testing.expectEqual(@as(u16, 200), parsed.status);
}

test "origin: a declared length is kept, and an answer that can carry no body says so" {
    var fixture: Fixture = .{};
    var out: [512]u8 = undefined;
    const Case = struct { status: u16, length: ?u64, end_stream: bool, bodiless: bool, framing: Framing, method: parser.Method, want: parser.BodyFraming };
    const cases = [_]Case{
        .{ .status = 200, .length = 5, .end_stream = false, .bodiless = false, .framing = .length, .method = .get, .want = .{ .content_length = 5 } },
        .{ .status = 200, .length = null, .end_stream = true, .bodiless = false, .framing = .none, .method = .get, .want = .{ .content_length = 0 } },
        .{ .status = 200, .length = 42, .end_stream = true, .bodiless = true, .framing = .none, .method = .head, .want = .none },
        .{ .status = 204, .length = null, .end_stream = true, .bodiless = false, .framing = .none, .method = .get, .want = .none },
        .{ .status = 304, .length = 42, .end_stream = true, .bodiless = false, .framing = .none, .method = .get, .want = .none },
        .{ .status = 103, .length = null, .end_stream = false, .bodiless = false, .framing = .none, .method = .get, .want = .none },
        .{ .status = 599, .length = null, .end_stream = false, .bodiless = false, .framing = .chunked, .method = .get, .want = .chunked },
    };
    for (cases) |case| {
        const head = try responseHead(&.{
            .status = case.status,
            .fields = &.{.{ .name = "x-a", .value = "1" }},
            .content_length = case.length,
            .interim = case.status < 200,
            .end_stream = case.end_stream,
            .bodiless = case.bodiless,
        }, &out);
        try testing.expectEqual(case.framing, head.framing);
        const parsed = try parseBack(&fixture, out[0..head.len], case.method);
        try testing.expectEqual(case.status, parsed.status);
        try testing.expectEqual(case.want, parsed.framing);
    }
}

test "origin: a trailer section is the last chunk's, reads back through the scanner, and skips the managed names" {
    var out: [256]u8 = undefined;
    const len = try trailerSection(&.{
        .{ .name = "grpc-status", .value = "0" },
        .{ .name = "content-length", .value = "9" },
        .{ .name = "grpc-message", .value = "" },
    }, &out);
    try testing.expectEqualStrings("0\r\ngrpc-status: 0\r\ngrpc-message: \r\n\r\n", out[0..len]);
    var scanner: parser.ChunkedScanner = .{};
    const fed = try scanner.feed(out[0..len]);
    try testing.expect(fed.done);
    try testing.expectEqual(len, fed.consumed);
    try testing.expectError(error.TooLarge, trailerSection(&.{.{ .name = "x", .value = "y" }}, out[0..8]));
}

test "origin: a trailer section exactly at the scanner's bound goes, and one octet past it is refused" {
    var out: [2 * constants.chunked_trailer_bytes_max]u8 = undefined;
    var value: [constants.chunked_trailer_bytes_max]u8 = @splat('v');
    // `x: <value>\r\n` and the closing CRLF: seven octets beside the value.
    const fits = value[0 .. constants.chunked_trailer_bytes_max - 7];
    const len = try trailerSection(&.{.{ .name = "x", .value = fits }}, &out);
    var scanner: parser.ChunkedScanner = .{};
    const fed = try scanner.feed(out[0..len]);
    try testing.expect(fed.done);
    try testing.expectEqual(constants.chunked_trailer_bytes_max, scanner.trailer_bytes);
    const over = value[0 .. constants.chunked_trailer_bytes_max - 6];
    try testing.expectError(error.TooLarge, trailerSection(&.{.{ .name = "x", .value = over }}, &out));
}

test "origin: a field no head could carry is refused, not written" {
    var out: [256]u8 = undefined;
    const bad = [_]hpack.Field{
        .{ .name = "transfer-encoding", .value = "chunked" },
        .{ .name = "connection", .value = "close" },
        .{ .name = "x-a", .value = "1\r\nInjected: yes" },
        .{ .name = "x-b", .value = "nul\x00" },
    };
    for (bad) |field| {
        const fields = [_]hpack.Field{field};
        try testing.expectError(error.Malformed, responseHead(&.{
            .status = 200,
            .fields = &fields,
            .content_length = null,
            .interim = false,
            .end_stream = false,
            .bodiless = false,
        }, &out));
    }
    try testing.expectError(error.Malformed, trailerSection(&.{bad[2]}, &out));
}

test "fuzz: origin — a request the parser accepts maps to fields HTTP/2 sends, or is refused" {
    const seed = @import("../../testing/bytes.zig").fuzzSeed;
    try testing.fuzz({}, fuzzRequest, .{ .corpus = &.{
        seed("GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
        seed("POST /p?q HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nConnection: x\r\nX: 1\r\n\r\nhi"),
        seed("OPTIONS * HTTP/1.1\r\nHost: a\r\nTE: trailers\r\n\r\n"),
    } });
}

test "fuzz: origin — every answer written reads back with the framing it was written with" {
    const seed = @import("../../testing/bytes.zig").fuzzSeed;
    try testing.fuzz({}, fuzzAnswer, .{ .corpus = &.{
        seed("\x00\xc8\x00" ++ "content-type\x00text/plain\x00"),
        seed("\x04\x67\x01" ++ "grpc-status\x000\x00"),
        seed("\x13\x30\x01" ++ "x\x00\x00"),
    } });
}

var fuzz_fixture: Fixture = .{};

/// Two octets of status (taken modulo the range), one of flags — interim
/// from the status, a declared length, end of stream, a HEAD — then
/// `name\0value\0` pairs, as the fields and as a trailer section.
fn fuzzAnswer(context: void, smith: *testing.Smith) !void {
    _ = context;
    var input: [1024]u8 = undefined;
    const input_len = smith.slice(&input);
    if (input_len < 3) return;
    var status: u16 = 100 + std.mem.readInt(u16, input[0..2], .big) % 500;
    if (status == 101) status = 100;
    const flags = input[2];
    var fields: [16]hpack.Field = undefined;
    var count: usize = 0;
    var pairs = std.mem.splitScalar(u8, input[3..input_len], 0);
    while (count < fields.len) {
        const name = pairs.next() orelse break;
        const value = pairs.next() orelse break;
        if (name.len == 0) continue;
        fields[count] = .{ .name = name, .value = value };
        count += 1;
    }
    const answer: Answer = .{
        .status = status,
        .fields = fields[0..count],
        .content_length = if (flags & 0x1 != 0) flags >> 4 else null,
        .interim = status < 200,
        .end_stream = status >= 200 and flags & 0x2 != 0,
        .bodiless = flags & 0x4 != 0,
    };
    var out: [2048]u8 = undefined;
    if (responseHead(&answer, &out)) |head| {
        // Whatever is written, the exchange's parser reads as written —
        // or refuses it whole; it never reads a different framing.
        const method: parser.Method = if (answer.bodiless) .head else .get;
        if (parser.parseResponseHead(out[0..head.len], true, &fuzz_fixture.response_storage, method)) |parsed| {
            assert(parsed.status == status);
            assert(parsed.head_len == head.len);
            switch (head.framing) {
                .chunked => assert(parsed.framing == .chunked),
                .length => assert(parsed.framing == .content_length),
                .none => assert(parsed.framing != .chunked and parsed.framing != .until_close),
            }
        } else |_| {}
    } else |_| {}
    if (trailerSection(fields[0..count], &out)) |len| {
        var scanner: parser.ChunkedScanner = .{};
        if (scanner.feed(out[0..len])) |fed| {
            assert(fed.done);
            assert(fed.consumed == len);
        } else |_| {}
    } else |_| {}
}

fn fuzzRequest(context: void, smith: *testing.Smith) !void {
    _ = context;
    var input: [2048]u8 = undefined;
    const input_len = smith.slice(&input);
    if (input_len == 0) return;
    const request = fuzz_fixture.request(input[0..input_len]) catch return;
    // Whatever maps is a request the session would send, or refuse whole.
    var validator = MessageValidator.init(.{ .kind = .request, .rules = .strict });
    for (request.fields) |*field| validator.field(field) catch return;
    validator.finish() catch return;
    assert(request.head_len <= input_len);
    assert(request.fields.len >= 5);
}
