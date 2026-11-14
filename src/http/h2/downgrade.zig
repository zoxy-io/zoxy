//! The h2 → h1 boundary (#275, RFC 9113 §8): a request HTTP/2 delivered,
//! written out as the HTTP/1.1 head it stands for and read back by
//! `parser.parseRequestHead` — the §7 trust boundary, unchanged.
//!
//! Re-parsing rather than re-deriving is the point. Every §7 rule — the
//! request-target's positive pchar table, the method token, exactly one
//! non-empty Host, a lone Content-Length, Transfer-Encoding's one legal
//! value — is already stated once, in `parser.zig`, against the bytes an
//! origin will read. A second statement of them here, over HTTP/2's fields,
//! would be a second boundary to keep in step with the first, and the
//! request-smuggling class lives in exactly that kind of gap. Written out
//! and parsed back, an HTTP/2 request is held to the HTTP/1.1 rules byte
//! for byte — a space in `:path` cannot split the request line, because
//! the line it splits does not parse — and the head buffer ends holding a
//! head the rest of §7 serves as if a client had sent it.
//!
//! What only HTTP/2 can say is settled before the write:
//! - `:path` is origin-form, or `*` (§8.3.1). Anything else is refused
//!   here, not left to the parser — which would read `http://other/x` as
//!   an absolute-form target whose authority outranks the `:authority`
//!   that routed.
//! - `:authority` is the Host. It replaces every `host` field — the
//!   reading §7 gave an absolute-form authority (#233), so the origin hears
//!   the name that routed, once — and it is held to that authority's
//!   charset, which also refuses the userinfo §8.3.1 forbids.
//! - `:scheme` is http or https: what an absolute-form target may name.
//! - Cookie crumbs rejoin with "; " (§8.2.3), at the first one's place.
//! - A body with no `content-length` goes upstream chunked: HTTP/2 frames
//!   its body, and HTTP/1.1 must be told how it is delimited instead. The
//!   session already made `transfer-encoding` itself malformed (§8.2.2).
//! - Extended CONNECT never gets here: SETTINGS never offer it (RFC 8441),
//!   so the session's validator refuses `:protocol` and WebSocket over
//!   HTTP/2 is refused at the stream. Plain CONNECT comes through as one,
//!   for §7's 501.

const std = @import("std");
const h2 = @import("h2");

const constants = @import("../../constants.zig");
const parser = @import("../parser.zig");
const Session = @import("Session.zig");

const hpack = h2.hpack;
const assert = std.debug.assert;

pub const Error = error{
    /// A request HTTP/1.1 cannot carry, or §7 refuses: 400.
    Malformed,
    /// The request line alone is past the head buffer: 414.
    UriTooLong,
    /// The header section is past the head buffer or `headers_max`: 431.
    HeadTooLarge,
};

/// Write `request` into `head` as the HTTP/1.1 head it stands for, and
/// parse it back. Every slice of the answer points into `head`, which is
/// the caller's to keep for the exchange — unlike the request's fields,
/// which are the session's only until its next `step`.
pub fn requestHead(
    request: *const Session.Step.Request,
    head: []u8,
    storage: *parser.HeaderStorage,
) Error!parser.RequestHead {
    assert(head.len >= 1);
    assert(head.len <= constants.head_buffer_bytes_max);
    const pseudo = try readPseudo(request.fields);
    var writer: Writer = .{ .bytes = head };
    writeRequestLine(&writer, &pseudo) catch return error.UriTooLong;
    writeFields(&writer, request, &pseudo) catch return error.HeadTooLarge;
    const parsed = parser.parseRequestHead(writer.written(), true, storage, null) catch |err| {
        return switch (err) {
            // `head_is_full` makes the parser answer a head it could not
            // finish as 414 or 431, never as one to read more of.
            error.Incomplete => unreachable,
            error.Malformed => error.Malformed,
            error.UriTooLong => error.UriTooLong,
            error.HeadTooLarge => error.HeadTooLarge,
        };
    };
    // The head ended where it was written to end: the session's strict
    // validator lets no CR or LF into a value, so the only line breaks in
    // it are the ones written here, and the first blank line is the last.
    assert(parsed.head_len == writer.len);
    assert(parsed.version == .http_1_1);
    return parsed;
}

const Pseudo = struct {
    method: []const u8,
    scheme: ?[]const u8,
    authority: ?[]const u8,
    path: ?[]const u8,
};

const PseudoName = enum { method, scheme, authority, path };

const pseudo_names = std.StaticStringMap(PseudoName).initComptime(.{
    .{ ":method", .method },
    .{ ":scheme", .scheme },
    .{ ":authority", .authority },
    .{ ":path", .path },
});

/// The pseudo-header fields, which the session's validator left leading
/// the block, each at most once and present as §8.3.1 requires. Read
/// defensively all the same: these are a client's octets, and one this
/// does not expect is a refusal rather than an assertion.
fn readPseudo(fields: []const hpack.Field) error{Malformed}!Pseudo {
    var pseudo: Pseudo = .{ .method = "", .scheme = null, .authority = null, .path = null };
    for (fields) |*field| {
        if (!isPseudo(field)) break;
        switch (pseudo_names.get(field.name) orelse return error.Malformed) {
            .method => pseudo.method = field.value,
            .scheme => pseudo.scheme = field.value,
            .authority => pseudo.authority = field.value,
            .path => pseudo.path = field.value,
        }
    }
    if (pseudo.method.len == 0) return error.Malformed;
    if (pseudo.authority) |authority| {
        if (authority.len == 0) return error.Malformed;
        if (!parser.authorityIsWellFormed(authority)) return error.Malformed;
    }
    if (pseudo.scheme) |scheme| {
        if (!isPathScheme(scheme)) return error.Malformed;
    }
    if (pseudo.path) |path| {
        if (!isOriginOrAsterisk(path)) return error.Malformed;
    } else {
        // CONNECT, the one request with no `:path` (§8.5), names its
        // authority instead — and is refused without one.
        if (pseudo.authority == null) return error.Malformed;
    }
    assert(pseudo.method.len >= 1);
    assert(pseudo.path != null or pseudo.authority != null);
    return pseudo;
}

/// http or https, case-insensitively (RFC 3986 §3.1): the schemes an
/// absolute-form target may name.
fn isPathScheme(scheme: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return true;
    return std.ascii.eqlIgnoreCase(scheme, "https");
}

/// §8.3.1: origin-form, or the asterisk-form of OPTIONS. Never absolute-
/// form, which the parser would split — and route — by its own authority.
fn isOriginOrAsterisk(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path[0] == '/') return true;
    return std.mem.eql(u8, path, "*");
}

fn isPseudo(field: *const hpack.Field) bool {
    if (field.name.len == 0) return false;
    return field.name[0] == ':';
}

/// `:method SP target SP HTTP/1.1`, the target being `:path` — or, for
/// CONNECT, the authority it names (authority-form, §8.5).
fn writeRequestLine(writer: *Writer, pseudo: *const Pseudo) error{Overflow}!void {
    assert(pseudo.method.len >= 1);
    const target = pseudo.path orelse pseudo.authority.?;
    assert(target.len >= 1);
    try writer.append(&.{ pseudo.method, " ", target, " HTTP/1.1\r\n" });
}

/// The header section: `:authority`'s Host first, then the client's fields
/// in their order — its `host` fields dropped when `:authority` replaced
/// them, its cookie crumbs as one line, its `content-length` as one line
/// in canonical decimal — then the framing HTTP/1.1 needs.
///
/// One `content-length` line however many arrived. HTTP/2 lets a client
/// repeat one that agrees (RFC 9110 §8.6, which the session's validator
/// applies), and its framing is the DATA frames, which the session already
/// holds to the number. HTTP/1.1's §7 refuses any repeat, because there the
/// header *is* the framing — so the claim goes upstream said once, as the
/// number it was read as.
fn writeFields(writer: *Writer, request: *const Session.Step.Request, pseudo: *const Pseudo) error{Overflow}!void {
    const before = writer.len;
    assert(before >= 1);
    const host_replaced = pseudo.authority != null;
    if (pseudo.authority) |authority| try writer.line("host", authority);
    var cookie_written = false;
    var length_written = false;
    for (request.fields) |*field| {
        if (isPseudo(field)) continue;
        if (host_replaced) {
            if (std.mem.eql(u8, field.name, "host")) continue;
        }
        if (std.mem.eql(u8, field.name, "cookie")) {
            if (!cookie_written) try writeCookie(writer, request.fields);
            cookie_written = true;
            continue;
        }
        if (std.mem.eql(u8, field.name, "content-length")) {
            // The session's validator read every content-length line into
            // the one number, so a field means the number is there.
            if (!length_written) try writeContentLength(writer, request.content_length.?);
            length_written = true;
            continue;
        }
        try writer.line(field.name, field.value);
    }
    if (needsChunked(request)) try writer.line("transfer-encoding", "chunked");
    try writer.append(&.{"\r\n"});
    assert(writer.len > before);
    if (length_written) assert(!needsChunked(request));
}

/// A body follows, and nothing says how long: HTTP/1.1 is told it is
/// chunked, and the relay chunks it.
fn needsChunked(request: *const Session.Step.Request) bool {
    if (request.end_stream) return false;
    return request.content_length == null;
}

fn writeContentLength(writer: *Writer, length: u64) error{Overflow}!void {
    var digits: [20]u8 = undefined; // The most a u64 takes in decimal.
    const text = std.fmt.bufPrint(&digits, "{d}", .{length}) catch unreachable;
    assert(text.len >= 1);
    try writer.line("content-length", text);
}

/// §8.2.3: the crumbs a client split for compression's sake go upstream as
/// the one field HTTP/1.1 allows, joined with "; ". An empty crumb carries
/// no cookie and is left out — joined in, it would leave a "; " at an edge
/// of the line, which HTTP/1.1 then trims as whitespace into a value
/// nobody sent.
fn writeCookie(writer: *Writer, fields: []const hpack.Field) error{Overflow}!void {
    assert(fields.len >= 1);
    try writer.append(&.{"cookie: "});
    var crumbs: u32 = 0;
    for (fields) |*field| {
        if (!std.mem.eql(u8, field.name, "cookie")) continue;
        if (field.value.len == 0) continue;
        if (crumbs >= 1) try writer.append(&.{"; "});
        try writer.append(&.{field.value});
        crumbs += 1;
    }
    assert(crumbs <= fields.len);
    try writer.append(&.{"\r\n"});
}

/// Appends into the head buffer, refusing whatever would pass its end.
const Writer = struct {
    bytes: []u8,
    len: u32 = 0,

    fn append(writer: *Writer, parts: []const []const u8) error{Overflow}!void {
        assert(writer.len <= writer.bytes.len);
        for (parts) |part| {
            if (part.len > writer.bytes.len - writer.len) return error.Overflow;
            @memcpy(writer.bytes[writer.len..][0..part.len], part);
            writer.len += @intCast(part.len);
        }
        assert(writer.len <= writer.bytes.len);
    }

    fn line(writer: *Writer, name: []const u8, value: []const u8) error{Overflow}!void {
        assert(name.len >= 1);
        try writer.append(&.{ name, ": ", value, "\r\n" });
    }

    fn written(writer: *const Writer) []const u8 {
        assert(writer.len <= writer.bytes.len);
        return writer.bytes[0..writer.len];
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const seed = @import("../../testing/bytes.zig").fuzzSeed;
const MessageValidator = h2.fields.MessageValidator;

/// A head buffer and header storage, and the session's own reading of a
/// field list — so every case is a request the session would have handed
/// over, and `content_length` is the number its validator found.
const Fixture = struct {
    head: [2048]u8 = undefined,
    storage: parser.HeaderStorage = undefined,

    fn map(fixture: *Fixture, fields: []const hpack.Field, end_stream: bool) !parser.RequestHead {
        return fixture.mapInto(fields, end_stream, fixture.head.len);
    }

    fn mapInto(fixture: *Fixture, fields: []const hpack.Field, end_stream: bool, head_len: usize) !parser.RequestHead {
        const content_length = try validated(fields);
        const request: Session.Step.Request = .{
            .stream = 1,
            .fields = fields,
            .content_length = content_length,
            .end_stream = end_stream,
        };
        return requestHead(&request, fixture.head[0..head_len], &fixture.storage);
    }
};

/// The session's verdict, which every test case must pass: these tests
/// are about what comes after it.
fn validated(fields: []const hpack.Field) !?u64 {
    var validator = MessageValidator.init(.{ .kind = .request, .rules = .strict });
    for (fields) |*field| try validator.field(field);
    try validator.finish();
    return validator.contentLength();
}

fn fieldList(fields: anytype) [fields.len]hpack.Field {
    var built: [fields.len]hpack.Field = undefined;
    inline for (fields, 0..) |pair, index| built[index] = .{ .name = pair[0], .value = pair[1] };
    return built;
}

const get = fieldList(.{
    .{ ":method", "GET" },
    .{ ":scheme", "https" },
    .{ ":authority", "example.test" },
    .{ ":path", "/a?b=1" },
    .{ "user-agent", "zoxy-test" },
});

test "downgrade: a GET becomes the HTTP/1.1 head it stands for" {
    var fixture: Fixture = .{};
    const request = try fixture.map(&get, true);
    try testing.expectEqualStrings(
        "GET /a?b=1 HTTP/1.1\r\nhost: example.test\r\nuser-agent: zoxy-test\r\n\r\n",
        fixture.head[0..request.head_len],
    );
    try testing.expectEqual(parser.Method.get, request.method);
    try testing.expectEqualStrings("/a?b=1", request.target);
    try testing.expectEqualStrings("example.test", request.host.?);
    try testing.expect(request.authority == null);
    try testing.expectEqual(parser.BodyFraming.none, request.framing);
    try testing.expect(request.keep_alive);
    try testing.expectEqual(@as(usize, 2), request.headers.len);
}

test "downgrade: :authority replaces every host field, as an absolute-form authority does (#233)" {
    var fixture: Fixture = .{};
    const fields = fieldList(.{
        .{ ":method", "GET" },            .{ ":scheme", "https" },
        .{ ":authority", "routed.test" }, .{ ":path", "/" },
        .{ "host", "other.test" },        .{ "accept", "*/*" },
        .{ "host", "third.test" },
    });
    const request = try fixture.map(&fields, true);
    try testing.expectEqualStrings("routed.test", request.host.?);
    try testing.expectEqual(@as(usize, 2), request.headers.len); // host, accept.
    try testing.expectEqualStrings("routed.test", parser.headerValue(request.headers, "host").?);
}

test "downgrade: without :authority the host field is the Host, and §7's exactly-one rule holds" {
    var fixture: Fixture = .{};
    const one = fieldList(.{ .{ ":method", "GET" }, .{ ":scheme", "http" }, .{ ":path", "/" }, .{ "host", "h.test" } });
    try testing.expectEqualStrings("h.test", (try fixture.map(&one, true)).host.?);
    const none = fieldList(.{ .{ ":method", "GET" }, .{ ":scheme", "http" }, .{ ":path", "/" } });
    try testing.expectError(error.Malformed, fixture.map(&none, true));
    const two = fieldList(.{ .{ ":method", "GET" }, .{ ":scheme", "http" }, .{ ":path", "/" }, .{ "host", "a.test" }, .{ "host", "b.test" } });
    try testing.expectError(error.Malformed, fixture.map(&two, true));
    const empty = fieldList(.{ .{ ":method", "GET" }, .{ ":scheme", "http" }, .{ ":path", "/" }, .{ "host", "" } });
    try testing.expectError(error.Malformed, fixture.map(&empty, true));
}

test "downgrade: :path is held to the HTTP/1.1 target rules, and to origin-form" {
    const refused = [_][]const u8{
        "/a b", // Would split the request line.
        "/a\\b", // An origin may read it as '/'.
        "/\xce\xb4", // Raw UTF-8: RFC 3986 wants it escaped.
        "/a\"b",
        "relative",
        // Absolute-form: the parser would let its authority outrank the
        // `:authority` that routed.
        "http://other.test/x",
        "*", // Asterisk-form is OPTIONS', not GET's.
    };
    for (refused) |path| {
        var fixture: Fixture = .{};
        const fields = fieldList(.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "a.test" }, .{ ":path", path } });
        try testing.expectError(error.Malformed, fixture.map(&fields, true));
    }
    var fixture: Fixture = .{};
    const options = fieldList(.{ .{ ":method", "OPTIONS" }, .{ ":scheme", "https" }, .{ ":authority", "a.test" }, .{ ":path", "*" } });
    const request = try fixture.map(&options, true);
    try testing.expectEqual(parser.Method.options, request.method);
    try testing.expectEqualStrings("*", request.target);
}

test "downgrade: :scheme is http or https, and :authority a Host line's charset with no userinfo" {
    const Case = struct { scheme: []const u8, authority: []const u8, ok: bool };
    const cases = [_]Case{
        .{ .scheme = "HTTPS", .authority = "a.test:8443", .ok = true },
        .{ .scheme = "http", .authority = "[::1]:80", .ok = true },
        .{ .scheme = "ftp", .authority = "a.test", .ok = false },
        .{ .scheme = "https", .authority = "user@a.test", .ok = false },
        .{ .scheme = "https", .authority = "a.test/x", .ok = false },
        .{ .scheme = "https", .authority = "a test", .ok = false },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        const fields = fieldList(.{ .{ ":method", "GET" }, .{ ":scheme", case.scheme }, .{ ":authority", case.authority }, .{ ":path", "/" } });
        if (case.ok) {
            try testing.expectEqualStrings(case.authority, (try fixture.map(&fields, true)).host.?);
        } else {
            try testing.expectError(error.Malformed, fixture.map(&fields, true));
        }
    }
}

test "downgrade: the method is a token HTTP/1.1 can read, registered or not" {
    var fixture: Fixture = .{};
    const spaced = fieldList(.{ .{ ":method", "GE T" }, .{ ":scheme", "https" }, .{ ":authority", "a.test" }, .{ ":path", "/" } });
    try testing.expectError(error.Malformed, fixture.map(&spaced, true));
    const extension = fieldList(.{ .{ ":method", "PROPFIND" }, .{ ":scheme", "https" }, .{ ":authority", "a.test" }, .{ ":path", "/" } });
    const request = try fixture.map(&extension, true);
    try testing.expectEqual(parser.Method.extension, request.method);
    try testing.expectEqualStrings("PROPFIND", request.method_token);
}

test "downgrade: CONNECT names its authority as the target, for §7's 501" {
    var fixture: Fixture = .{};
    const fields = fieldList(.{ .{ ":method", "CONNECT" }, .{ ":authority", "tunnel.test:443" } });
    const request = try fixture.map(&fields, false);
    try testing.expectEqual(parser.Method.connect, request.method);
    try testing.expectEqualStrings("tunnel.test:443", request.target);
    try testing.expectEqualStrings("tunnel.test:443", request.host.?);
}

test "downgrade: cookie crumbs rejoin with \"; \" at the first one's place" {
    var fixture: Fixture = .{};
    const fields = fieldList(.{
        .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "a.test" }, .{ ":path", "/" },
        .{ "cookie", "a=1" },  .{ "accept", "*/*" },    .{ "cookie", "b=2" },        .{ "cookie", "c=3" },
    });
    const request = try fixture.map(&fields, true);
    try testing.expectEqual(@as(usize, 3), request.headers.len); // host, cookie, accept.
    try testing.expectEqualStrings("cookie", request.headers[1].name);
    try testing.expectEqualStrings("a=1; b=2; c=3", request.headers[1].value);
    try testing.expectEqualStrings("accept", request.headers[2].name);
}

test "downgrade: an empty cookie crumb carries no cookie and is left out of the join" {
    var fixture: Fixture = .{};
    const fields = fieldList(.{
        .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "a.test" }, .{ ":path", "/" },
        .{ "cookie", "" },     .{ "cookie", "a=1" },    .{ "cookie", "" },           .{ "cookie", "b=2" },
        .{ "cookie", "" },
    });
    const request = try fixture.map(&fields, true);
    try testing.expectEqualStrings("a=1; b=2", parser.headerValue(request.headers, "cookie").?);
}

test "downgrade: a body with no content-length goes upstream chunked, one with it as declared" {
    var fixture: Fixture = .{};
    const post = fieldList(.{ .{ ":method", "POST" }, .{ ":scheme", "https" }, .{ ":authority", "a.test" }, .{ ":path", "/up" } });
    const chunked = try fixture.map(&post, false);
    try testing.expectEqual(parser.BodyFraming.chunked, chunked.framing);
    try testing.expectEqualStrings("chunked", parser.headerValue(chunked.headers, "transfer-encoding").?);
    const declared = fieldList(.{
        .{ ":method", "POST" }, .{ ":scheme", "https" },    .{ ":authority", "a.test" },
        .{ ":path", "/up" },    .{ "content-length", "5" },
    });
    const length = try fixture.map(&declared, false);
    try testing.expectEqual(parser.BodyFraming{ .content_length = 5 }, length.framing);
    try testing.expect(parser.headerValue(length.headers, "transfer-encoding") == null);
    // Lines that agree are HTTP/2's to allow (RFC 9110 §8.6), and they go
    // upstream as the one line HTTP/1.1's §7 accepts, in canonical decimal.
    const twice = fieldList(.{
        .{ ":method", "POST" }, .{ ":scheme", "https" },      .{ ":authority", "a.test" },
        .{ ":path", "/up" },    .{ "content-length", "005" }, .{ "content-length", "5" },
    });
    const once = try fixture.map(&twice, false);
    try testing.expectEqual(parser.BodyFraming{ .content_length = 5 }, once.framing);
    try testing.expectEqual(@as(usize, 2), once.headers.len); // host, content-length.
    try testing.expectEqualStrings("5", parser.headerValue(once.headers, "content-length").?);
}

test "downgrade: a pseudo-header list the validator would never pass is refused, not asserted on" {
    const lists = [_][]const hpack.Field{
        // Extended CONNECT, which this server never negotiates.
        &fieldList(.{ .{ ":method", "CONNECT" }, .{ ":protocol", "websocket" }, .{ ":authority", "a.test" } }),
        &fieldList(.{ .{ ":scheme", "https" }, .{ ":authority", "a.test" }, .{ ":path", "/" } }),
        &fieldList(.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":authority", "" }, .{ ":path", "/" } }),
        &fieldList(.{.{ ":method", "CONNECT" }}),
    };
    for (lists) |fields| {
        var buffer: [256]u8 = undefined;
        var storage: parser.HeaderStorage = undefined;
        const request: Session.Step.Request = .{ .stream = 1, .fields = fields, .content_length = null, .end_stream = true };
        try testing.expectError(error.Malformed, requestHead(&request, &buffer, &storage));
    }
}

test "downgrade: past the head buffer a request line is 414 and a header section 431" {
    var fixture: Fixture = .{};
    try testing.expectError(error.UriTooLong, fixture.mapInto(&get, true, 20));
    try testing.expectError(error.HeadTooLarge, fixture.mapInto(&get, true, 48));
    // And past `headers_max` fields, however short.
    var many: [4 + constants.headers_max]hpack.Field = undefined;
    @memcpy(many[0..4], get[0..4]);
    for (many[4..]) |*field| field.* = .{ .name = "x", .value = "y" };
    try testing.expectError(error.HeadTooLarge, fixture.map(&many, true));
}

test "downgrade: the fuzz oracle holds on the directed cases, so it is not vacuous" {
    const cookies = fieldList(.{
        .{ ":method", "POST" }, .{ ":scheme", "https" },     .{ ":authority", "a.test" }, .{ ":path", "/" },
        .{ "cookie", "a=1" },   .{ "host", "dropped.test" }, .{ "x-a", "" },              .{ "cookie", "b=2" },
    });
    const lengths = fieldList(.{
        .{ ":method", "POST" }, .{ ":scheme", "https" },      .{ ":authority", "a.test" },
        .{ ":path", "/up" },    .{ "content-length", "007" }, .{ "content-length", "7" },
    });
    const cases = [_]struct { fields: []const hpack.Field, end_stream: bool }{
        .{ .fields = &get, .end_stream = true },
        .{ .fields = &cookies, .end_stream = false },
        .{ .fields = &lengths, .end_stream = false },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        const parsed = try fixture.map(case.fields, case.end_stream);
        const request: Session.Step.Request = .{
            .stream = 1,
            .fields = case.fields,
            .content_length = try validated(case.fields),
            .end_stream = case.end_stream,
        };
        checkMapped(&request, &parsed);
    }
}

test "fuzz: downgrade — whatever the session accepts maps to exactly its fields, or is refused" {
    // The control octet: method in the low two bits, `http` at 0x04, no
    // `:authority` at 0x08, END_STREAM at 0x80. Then strings, each behind
    // its length; a field's name is picked by `octet / 32` from
    // `fuzz_names` (0x40 is `content-length`, 0x20 `cookie`).
    try testing.fuzz({}, fuzzDowngrade, .{
        .corpus = &.{
            seed("\x00"),
            seed("\x80\x06a.test\x01/"),
            seed("\x01\x03a.t\x02/x\x00\x04x-ab"),
            seed("\x12\x06a.test\x05/a?b=\x20\x03a=1\xa0\x00\x20\x03b=2"),
            seed("\x01\x06a.test\x02/u\x40\x0212"),
            seed("\x01\x06a.test\x02/u\x40\x015\x40\x0205"),
            seed("\x8b\x01*\x00\x04h.te"),
            // What found the empty crumb: cookies `/[` then ``, already in
            // `Smith`'s encoding, as the fuzzer saved it.
            "\x15\x00\x00\x00\x00\x04x-at\x02/[\x86\x01?<\x02/[\x86\x00\x04\x000",
        },
    });
}

/// Field lists built from the input — pseudo-headers from short tables
/// mixed with raw octets, so the session's validator passes often enough
/// to reach the write — and, for each one it passes, the property the
/// boundary exists for: the head parsed back carries exactly the fields
/// sent, in order and octet for octet, plus only what the mapping says it
/// adds. A field split into two lines, a Host that was not the one that
/// routed, or a header that appeared from nowhere would break the count or
/// the walk.
fn fuzzDowngrade(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input: [512]u8 = undefined;
    const input_len = smith.slice(&input);
    var source: Source = .{ .bytes = input[0..input_len] };
    var fields: [fuzz_fields_max]hpack.Field = undefined;
    const control = source.byte();
    const count = buildFields(&source, control, &fields);
    const content_length = validated(fields[0..count]) catch return;
    const request: Session.Step.Request = .{
        .stream = 1,
        .fields = fields[0..count],
        .content_length = content_length,
        .end_stream = control & 0x80 != 0,
    };
    var buffer: [2048]u8 = undefined;
    var storage: parser.HeaderStorage = undefined;
    const parsed = requestHead(&request, &buffer, &storage) catch return;
    checkMapped(&request, &parsed);
}

const Source = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn byte(source: *Source) u8 {
        if (source.offset == source.bytes.len) return 0;
        source.offset += 1;
        return source.bytes[source.offset - 1];
    }

    /// A length octet, then that many octets — or what is left.
    fn string(source: *Source) []const u8 {
        const length = @min(source.byte(), source.bytes.len - source.offset);
        source.offset += length;
        return source.bytes[source.offset - length .. source.offset];
    }
};

const fuzz_fields_max = 24;
const fuzz_names = [_][]const u8{ "host", "cookie", "content-length", "te", "accept", "x-a" };

fn buildFields(source: *Source, control: u8, fields: *[fuzz_fields_max]hpack.Field) usize {
    const methods = [_][]const u8{ "GET", "POST", "OPTIONS", "CONNECT" };
    var count: usize = 0;
    const method = methods[control & 0x3];
    fields[count] = .{ .name = ":method", .value = method };
    count += 1;
    if (!std.mem.eql(u8, method, "CONNECT")) {
        fields[count] = .{ .name = ":scheme", .value = if (control & 0x4 != 0) "http" else "https" };
        count += 1;
    }
    if (control & 0x8 == 0) {
        fields[count] = .{ .name = ":authority", .value = source.string() };
        count += 1;
    }
    if (!std.mem.eql(u8, method, "CONNECT")) {
        fields[count] = .{ .name = ":path", .value = source.string() };
        count += 1;
    }
    while (count < fields.len and source.offset < source.bytes.len) : (count += 1) {
        const pick = source.byte();
        const name = if (pick < fuzz_names.len * 32) fuzz_names[pick / 32] else source.string();
        fields[count] = .{ .name = name, .value = source.string() };
    }
    assert(count <= fields.len);
    return count;
}

/// The oracle, written apart from the mapping it checks: its own reading
/// of the pseudo-header fields, its own join of the cookie crumbs, and the
/// whole header walk against what the mapping promises — the Host that
/// routed, every other field in order and octet for octet, one cookie and
/// one content-length line, and the framing that follows.
fn checkMapped(request: *const Session.Step.Request, parsed: *const parser.RequestHead) void {
    const fields = request.fields;
    const authority = pseudoValue(fields, ":authority");
    assert(std.mem.eql(u8, parsed.method_token, pseudoValue(fields, ":method").?));
    assert(std.mem.eql(u8, parsed.target, pseudoValue(fields, ":path") orelse authority.?));
    var index: usize = 0;
    if (authority) |name| {
        assert(std.mem.eql(u8, parsed.host.?, name));
        assert(std.mem.eql(u8, parsed.headers[index].name, "host"));
        index += 1;
    }
    var cookie_seen = false;
    var length_seen = false;
    for (fields) |*field| {
        if (field.name[0] == ':') continue;
        if (authority != null and std.mem.eql(u8, field.name, "host")) continue;
        // A repeated cookie or content-length has no line of its own.
        switch (oracleKind(field.name)) {
            .cookie => if (cookie_seen) continue,
            .content_length => if (length_seen) continue,
            .other => {},
        }
        assert(index < parsed.headers.len);
        const header = parsed.headers[index];
        switch (oracleKind(field.name)) {
            .cookie => {
                cookie_seen = true;
                var joined: [2048]u8 = undefined;
                assert(std.mem.eql(u8, header.name, "cookie"));
                assert(std.mem.eql(u8, header.value, joinCookies(fields, &joined)));
            },
            .content_length => {
                length_seen = true;
                assert(std.mem.eql(u8, header.name, "content-length"));
                const value = std.fmt.parseUnsigned(u64, header.value, 10) catch unreachable;
                assert(request.content_length.? == value);
                // Canonical decimal: no leading zero but zero's own.
                if (header.value.len >= 2) assert(header.value[0] != '0');
            },
            .other => {
                assert(std.mem.eql(u8, header.name, field.name));
                assert(std.mem.eql(u8, header.value, field.value));
            },
        }
        index += 1;
    }
    checkFraming(request, parsed, index);
}

fn checkFraming(request: *const Session.Step.Request, parsed: *const parser.RequestHead, walked: usize) void {
    if (request.content_length) |length| {
        assert(parsed.framing.content_length == length);
        assert(walked == parsed.headers.len);
        return;
    }
    if (request.end_stream) {
        assert(parsed.framing == .none);
        assert(walked == parsed.headers.len);
        return;
    }
    assert(std.mem.eql(u8, parsed.headers[walked].name, "transfer-encoding"));
    assert(parsed.framing == .chunked);
    assert(walked + 1 == parsed.headers.len);
}

const OracleKind = enum { cookie, content_length, other };

fn oracleKind(name: []const u8) OracleKind {
    if (std.mem.eql(u8, name, "cookie")) return .cookie;
    if (std.mem.eql(u8, name, "content-length")) return .content_length;
    return .other;
}

fn pseudoValue(fields: []const hpack.Field, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

fn joinCookies(fields: []const hpack.Field, out: []u8) []const u8 {
    var length: usize = 0;
    for (fields) |field| {
        if (!std.mem.eql(u8, field.name, "cookie")) continue;
        if (field.value.len == 0) continue;
        if (length >= 1) {
            @memcpy(out[length..][0..2], "; ");
            length += 2;
        }
        @memcpy(out[length..][0..field.value.len], field.value);
        length += field.value.len;
    }
    return out[0..length];
}
