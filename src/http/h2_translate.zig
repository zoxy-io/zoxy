//! Translation between HTTP/2 header lists and HTTP/1.1 wire heads
//! (docs/DESIGN.md §7 Phase 5, slice 4): pseudo-headers ↔ request line and
//! Host, response status ↔ :status, connection-specific fields policed per
//! RFC 9113 §8.2.2. Pure functions over caller buffers — the sans-io half
//! of the H2-downstream / H1-upstream leg.
//!
//! Directions:
//! - `request_head`: decoded H2 request fields → a synthesized H1 request
//!   head. HPACK values are arbitrary octets, so everything that lands in
//!   the line-oriented H1 head is charset-validated here — a CR or LF in a
//!   value is a head-splitting attack, not a header.
//! - `response_block`: a parsed H1 response head → an hpack-encoded block
//!   for `h2.Connection.send_headers`, names lowercased, hop-by-hop and
//!   connection-named fields stripped.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const h1 = @import("h1.zig");
const hpack = @import("hpack.zig");

/// Reject the request — RST_STREAM(PROTOCOL_ERROR), the H2 malformed-
/// request verdict (RFC 9113 §8.1.1).
pub const TranslateError = error{Malformed};

pub const RequestHead = struct {
    /// Bytes of the synthesized head written to `out`, final CRLF included.
    head_len: usize,
    method: h1.Method,
    /// Declared request-body length, when the client sent content-length.
    content_length: ?u64,
    /// The upstream body will be sent chunked (a body follows but no
    /// length was declared — H2 needs neither, H1 needs one of the two).
    chunked: bool,
};

/// Synthesize an H1 request head from a decoded H2 header list.
/// `end_stream` is the request-head flag: no body follows. `out` must hold
/// `h2_header_list_bytes_max + 256` bytes — bounded fields can then never
/// overflow it (asserted, not errored).
pub fn request_head(
    headers: []const hpack.Header,
    end_stream: bool,
    out: []u8,
) TranslateError!RequestHead {
    assert(out.len >= constants.h2_header_list_bytes_max + 256);
    const pseudo = try scan_pseudo_headers(headers);
    const authority = pseudo.authority orelse try host_header_value(headers);

    var writer = Writer{ .out = out };
    writer.put(pseudo.method);
    writer.put(" ");
    writer.put(pseudo.path);
    writer.put(" HTTP/1.1\r\nhost: ");
    writer.put(authority);
    writer.put("\r\n");

    var content_length: ?u64 = null;
    var cookies_done = false;
    for (headers, 0..) |header, index| {
        if (is_pseudo(header.name)) continue; // ordering was validated above
        try validate_field_name(header.name);
        try validate_field_value(header.value);
        if (is_connection_specific(header.name)) {
            // "An endpoint MUST NOT generate" and receipt is malformed
            // (§8.2.2) — except te: trailers, which is dropped: the H1 leg
            // forwards no trailers.
            if (std.ascii.eqlIgnoreCase(header.name, "te") and
                std.ascii.eqlIgnoreCase(header.value, "trailers")) continue;
            return error.Malformed;
        }
        if (std.ascii.eqlIgnoreCase(header.name, "host")) continue; // authority already spoke
        if (std.ascii.eqlIgnoreCase(header.name, "cookie")) {
            if (cookies_done) continue;
            cookies_done = true;
            write_joined_cookies(&writer, headers[index..]);
            continue;
        }
        if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            if (content_length != null) return error.Malformed; // ambiguous framing
            content_length = parse_content_length(header.value) orelse return error.Malformed;
        }
        writer.put(header.name);
        writer.put(": ");
        writer.put(header.value);
        writer.put("\r\n");
    }

    // A declared body that cannot arrive is a smuggling shape (§8.1.1).
    if (end_stream and (content_length orelse 0) != 0) return error.Malformed;
    const chunked = !end_stream and content_length == null;
    if (chunked) writer.put("transfer-encoding: chunked\r\n");
    writer.put("\r\n");
    assert(writer.used > pseudo.method.len + pseudo.path.len);
    return .{
        .head_len = writer.used,
        .method = method_of(pseudo.method),
        .content_length = content_length,
        .chunked = chunked,
    };
}

/// Encode a parsed H1 response head as an hpack block for
/// `h2.Connection.send_headers`: `:status` first, then every end-to-end
/// field with its name lowercased. Failures mean the response cannot be
/// represented — the attempt fails (502), never a truncated head.
pub fn response_block(response: *const h1.Response, out: []u8) error{Unencodable}!usize {
    // Interim (1xx) responses are the relay's to swallow, not ours to encode.
    assert(response.status >= 200);
    assert(response.status <= 999);
    var status_text: [3]u8 = undefined;
    status_text[0] = '0' + @as(u8, @intCast(response.status / 100));
    status_text[1] = '0' + @as(u8, @intCast(response.status / 10 % 10));
    status_text[2] = '0' + @as(u8, @intCast(response.status % 10));
    var used = hpack.encode_header(":status", &status_text, out) catch
        return error.Unencodable;

    const connection_names = response.header("connection") orelse "";
    for (response.headers) |header| {
        if (is_hop_by_hop(header.name)) continue;
        if (token_list_names(connection_names, header.name)) continue;
        var name_buffer: [field_name_bytes_max]u8 = undefined;
        if (header.name.len > name_buffer.len) return error.Unencodable;
        const name = std.ascii.lowerString(name_buffer[0..header.name.len], header.name);
        validate_field_value(header.value) catch return error.Unencodable;
        used += hpack.encode_header(name, header.value, out[used..]) catch
            return error.Unencodable;
    }
    assert(used >= 1); // at least the :status field
    return used;
}

/// Longest response field name we will translate; longer is nonsense, not
/// traffic (bounds the lowercasing buffer).
const field_name_bytes_max = 128;

const PseudoHeaders = struct {
    method: []const u8,
    path: []const u8,
    authority: ?[]const u8,
};

/// Validate and collect the request pseudo-headers (§8.3): each at most
/// once, all before any regular field, none unknown, CONNECT unsupported.
fn scan_pseudo_headers(headers: []const hpack.Header) TranslateError!PseudoHeaders {
    var method: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    var regular_seen = false;
    for (headers) |header| {
        if (!is_pseudo(header.name)) {
            regular_seen = true;
            continue;
        }
        if (regular_seen) return error.Malformed; // pseudo after regular (§8.3)
        const target: *?[]const u8 =
            if (std.mem.eql(u8, header.name, ":method"))
                &method
            else if (std.mem.eql(u8, header.name, ":scheme"))
                &scheme
            else if (std.mem.eql(u8, header.name, ":path"))
                &path
            else if (std.mem.eql(u8, header.name, ":authority"))
                &authority
            else
                return error.Malformed; // unknown or response pseudo-header
        if (target.* != null) return error.Malformed; // duplicate
        target.* = header.value;
    }
    const method_value = method orelse return error.Malformed;
    if (!is_token(method_value)) return error.Malformed;
    // CONNECT (§8.5) omits :scheme/:path and asks for a tunnel we do not
    // provide — the H1 path answers Upgrade with 501, this is its twin.
    if (std.mem.eql(u8, method_value, "CONNECT")) return error.Malformed;
    if (scheme == null or scheme.?.len == 0) return error.Malformed;
    const path_value = path orelse return error.Malformed;
    if (path_value.len == 0 or !is_target_text(path_value)) return error.Malformed;
    if (authority) |value| try validate_authority(value);
    return .{ .method = method_value, .path = path_value, .authority = authority };
}

/// The Host fallback when :authority is absent: exactly one host header.
fn host_header_value(headers: []const hpack.Header) TranslateError![]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "host")) continue;
        if (found != null) return error.Malformed; // ambiguous target host
        found = header.value;
    }
    const value = found orelse return error.Malformed; // no target host at all
    try validate_authority(value);
    return value;
}

/// Join every cookie field into one `cookie:` line, "; "-separated —
/// undoing the split H2 clients perform for compression (§8.2.3).
fn write_joined_cookies(writer: *Writer, headers_from_first: []const hpack.Header) void {
    writer.put("cookie: ");
    var first = true;
    for (headers_from_first) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cookie")) continue;
        if (!first) writer.put("; ");
        writer.put(header.value);
        first = false;
    }
    assert(!first); // called at the first cookie field
    writer.put("\r\n");
}

/// Bounds-asserting head assembler; overflow is impossible by contract
/// (decoded fields are list-bounded, the buffer is sized past that).
const Writer = struct {
    out: []u8,
    used: usize = 0,

    fn put(writer: *Writer, bytes: []const u8) void {
        assert(writer.used + bytes.len <= writer.out.len);
        @memcpy(writer.out[writer.used..][0..bytes.len], bytes);
        writer.used += bytes.len;
    }
};

fn is_pseudo(name: []const u8) bool {
    return name.len > 0 and name[0] == ':';
}

/// Fields that describe the connection, not the message (§8.2.2 and the
/// RFC 9110 §7.6.1 hop-by-hop set): never valid inside an H2 request.
fn is_connection_specific(name: []const u8) bool {
    const names = [_][]const u8{
        "connection", "keep-alive", "proxy-connection", "transfer-encoding",
        "upgrade",    "te",
    };
    for (names) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
}

/// The response-side strip set: the request set plus trailer bookkeeping.
fn is_hop_by_hop(name: []const u8) bool {
    return is_connection_specific(name) or std.ascii.eqlIgnoreCase(name, "trailer");
}

/// Whether a `Connection` header value (a comma-separated token list)
/// names `name` — those fields are hop-by-hop too (RFC 9110 §7.6.1).
fn token_list_names(list: []const u8, name: []const u8) bool {
    assert(name.len > 0);
    var tokens = std.mem.splitScalar(u8, list, ',');
    // Bounded by the header-value length.
    while (tokens.next()) |token| {
        const trimmed = std.mem.trim(u8, token, " \t");
        if (trimmed.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(trimmed, name)) return true;
    }
    return false;
}

/// H2 field names must be lowercase tokens (§8.2.1); anything else is
/// malformed — and never allowed to reach the line-oriented H1 head.
fn validate_field_name(name: []const u8) TranslateError!void {
    if (name.len == 0) return error.Malformed;
    for (name) |byte| {
        if (byte >= 'A' and byte <= 'Z') return error.Malformed;
        if (!token_chars[byte]) return error.Malformed;
    }
}

/// HPACK values are arbitrary octets; CR, LF, and NUL are head-splitting
/// material in an H1 head and banned by RFC 9113 §8.2.1 regardless.
fn validate_field_value(value: []const u8) TranslateError!void {
    for (value) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0) return error.Malformed;
    }
}

/// An authority that is about to become a `host:` line: no userinfo
/// (§8.3.1), no whitespace or control bytes.
fn validate_authority(authority: []const u8) TranslateError!void {
    if (authority.len == 0) return error.Malformed;
    for (authority) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == '@') return error.Malformed;
    }
}

fn parse_content_length(value: []const u8) ?u64 {
    if (value.len == 0 or value.len > 19) return null; // 19 digits < 2^64
    for (value) |byte| {
        if (byte < '0' or byte > '9') return null;
    }
    return std.fmt.parseInt(u64, value, 10) catch null;
}

fn method_of(text: []const u8) h1.Method {
    const map = std.StaticStringMap(h1.Method).initComptime(.{
        .{ "GET", .get },
        .{ "HEAD", .head },
        .{ "POST", .post },
        .{ "PUT", .put },
        .{ "DELETE", .delete },
        .{ "PATCH", .patch },
        .{ "OPTIONS", .options },
        .{ "TRACE", .trace },
    });
    return map.get(text) orelse .other;
}

/// RFC 9110 token characters (kept in sync with h1.zig's table).
const token_chars: [256]bool = blk: {
    var table = [_]bool{false} ** 256;
    for ("!#$%&'*+-.^_`|~") |c| table[c] = true;
    for ('0'..'9' + 1) |c| table[c] = true;
    for ('a'..'z' + 1) |c| table[c] = true;
    for ('A'..'Z' + 1) |c| table[c] = true;
    break :blk table;
};

fn is_token(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!token_chars[c]) return false;
    }
    return true;
}

fn is_target_text(s: []const u8) bool {
    for (s) |c| {
        if (c <= 0x20 or c == 0x7f) return false;
    }
    return true;
}

// ---- tests -------------------------------------------------------------------

const testing = std.testing;

fn translate(fields: []const hpack.Header, end_stream: bool, out: []u8) !RequestHead {
    return request_head(fields, end_stream, out);
}

const get_fields = [_]hpack.Header{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":path", .value = "/a?b=c" },
    .{ .name = ":authority", .value = "zoxy.test:8443" },
    .{ .name = "accept", .value = "*/*" },
};

test "h2 translate: a GET becomes an H1 head verbatim" {
    var out: [constants.h2_header_list_bytes_max + 256]u8 = undefined;
    const head = try translate(&get_fields, true, &out);
    try testing.expectEqualStrings(
        "GET /a?b=c HTTP/1.1\r\nhost: zoxy.test:8443\r\naccept: */*\r\n\r\n",
        out[0..head.head_len],
    );
    try testing.expectEqual(h1.Method.get, head.method);
    try testing.expectEqual(@as(?u64, null), head.content_length);
    try testing.expect(!head.chunked);
    // The synthesized head parses back with our own parser.
    var headers: [8]h1.Header = undefined;
    const parsed = (try h1.parse(out[0..head.head_len], &headers)).complete;
    try testing.expectEqualStrings("zoxy.test:8443", parsed.host().?);
}

test "h2 translate: bodies choose content-length or chunked" {
    var out: [constants.h2_header_list_bytes_max + 256]u8 = undefined;
    const sized_fields = [_]hpack.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/upload" },
        .{ .name = ":authority", .value = "zoxy.test" },
        .{ .name = "content-length", .value = "12" },
    };
    const sized = try translate(&sized_fields, false, &out);
    try testing.expectEqual(@as(?u64, 12), sized.content_length);
    try testing.expect(!sized.chunked);
    const sized_head = out[0..sized.head_len];
    try testing.expect(std.mem.indexOf(u8, sized_head, "content-length: 12\r\n") != null);

    const unsized_fields = sized_fields[0..4];
    const unsized = try translate(unsized_fields, false, &out);
    try testing.expect(unsized.chunked);
    try testing.expect(
        std.mem.indexOf(u8, out[0..unsized.head_len], "transfer-encoding: chunked\r\n") != null,
    );

    // content-length with END_STREAM on the head: a body that cannot come.
    try testing.expectError(error.Malformed, translate(&sized_fields, true, &out));
    // ...but an explicit zero is fine.
    const zero_fields = sized_fields[0..4].* ++ [_]hpack.Header{
        .{ .name = "content-length", .value = "0" },
    };
    const zero = try translate(&zero_fields, true, &out);
    try testing.expectEqual(@as(?u64, 0), zero.content_length);
}

test "h2 translate: cookie fields are rejoined" {
    var out: [constants.h2_header_list_bytes_max + 256]u8 = undefined;
    const fields = get_fields ++ [_]hpack.Header{
        .{ .name = "cookie", .value = "a=1" },
        .{ .name = "x-mid", .value = "y" },
        .{ .name = "cookie", .value = "b=2" },
        .{ .name = "cookie", .value = "c=3" },
    };
    const head = try translate(&fields, true, &out);
    try testing.expect(
        std.mem.indexOf(u8, out[0..head.head_len], "cookie: a=1; b=2; c=3\r\n") != null,
    );
    // Exactly one cookie line.
    try testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, out[0..head.head_len], "cookie: "),
    );
}

test "h2 translate: authority wins over host, host is the fallback" {
    var out: [constants.h2_header_list_bytes_max + 256]u8 = undefined;
    const both = get_fields ++ [_]hpack.Header{.{ .name = "host", .value = "ignored.example" }};
    const head = try translate(&both, true, &out);
    try testing.expect(std.mem.indexOf(u8, out[0..head.head_len], "host: zoxy.test:8443") != null);
    try testing.expect(std.mem.indexOf(u8, out[0..head.head_len], "ignored.example") == null);

    const no_authority = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "fallback.example" },
    };
    const fallback = try translate(&no_authority, true, &out);
    try testing.expect(
        std.mem.indexOf(u8, out[0..fallback.head_len], "host: fallback.example\r\n") != null,
    );
    // Neither :authority nor host: nowhere to route.
    try testing.expectError(error.Malformed, translate(no_authority[0..3], true, &out));
}

test "h2 translate: malformed requests are rejected" {
    var out: [constants.h2_header_list_bytes_max + 256]u8 = undefined;
    const cases = [_][]const hpack.Header{
        // Missing :method / :path / :scheme.
        &.{ .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" } },
        &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" } },
        &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":path", .value = "/" } },
        // Duplicate pseudo, unknown pseudo, pseudo after regular.
        &(get_fields[0..4].* ++ [_]hpack.Header{.{ .name = ":method", .value = "GET" }}),
        &(get_fields[0..4].* ++ [_]hpack.Header{.{ .name = ":status", .value = "200" }}),
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = "accept", .value = "*/*" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "z" },
        },
        // CONNECT, empty path, authority with userinfo.
        &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "z" },
        },
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "" },
            .{ .name = ":authority", .value = "z" },
        },
        &(get_fields[0..3].* ++ [_]hpack.Header{.{ .name = ":authority", .value = "user@evil" }}),
        // Connection-specific fields (§8.2.2) and te beyond trailers.
        &(get_fields ++ [_]hpack.Header{.{ .name = "connection", .value = "close" }}),
        &(get_fields ++ [_]hpack.Header{.{ .name = "transfer-encoding", .value = "chunked" }}),
        &(get_fields ++ [_]hpack.Header{.{ .name = "te", .value = "gzip" }}),
        // Uppercase name, header injection via value, bad content-length.
        &(get_fields ++ [_]hpack.Header{.{ .name = "Accept-Language", .value = "en" }}),
        &(get_fields ++ [_]hpack.Header{.{ .name = "x-evil", .value = "a\r\nx-fake: 1" }}),
        &(get_fields ++ [_]hpack.Header{.{ .name = "content-length", .value = "12x" }}),
        &(get_fields ++ [_]hpack.Header{
            .{ .name = "content-length", .value = "1" },
            .{ .name = "content-length", .value = "1" },
        }),
    };
    for (cases, 0..) |fields, index| {
        testing.expectError(error.Malformed, translate(fields, false, &out)) catch |err| {
            std.debug.print("malformed case {d} did not reject\n", .{index});
            return err;
        };
    }
    // te: trailers is dropped, not fatal.
    const te_fields = get_fields ++ [_]hpack.Header{.{ .name = "te", .value = "trailers" }};
    const head = try translate(&te_fields, true, &out);
    try testing.expect(std.mem.indexOf(u8, out[0..head.head_len], "\r\nte:") == null);
}

test "h2 translate: response heads become hpack blocks" {
    var head_headers: [16]h1.Header = undefined;
    const raw = "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/html\r\n" ++
        "Content-Length: 5\r\n" ++
        "Connection: keep-alive, x-internal\r\n" ++
        "Keep-Alive: timeout=5\r\n" ++
        "X-Internal: secret\r\n" ++
        "Transfer-Encoding: identity\r\n" ++
        "Set-Cookie: session=1\r\n\r\n";
    const response = (try h1.parse_response(raw, &head_headers)).complete;

    var block: [1024]u8 = undefined;
    const block_len = try response_block(&response, &block);

    var decoder = hpack.Decoder{};
    var fields: [16]hpack.Header = undefined;
    var storage: [1024]u8 = undefined;
    const decoded = try decoder.decode(block[0..block_len], &fields, &storage);
    try testing.expectEqual(@as(usize, 4), decoded.len);
    try testing.expectEqualStrings(":status", decoded[0].name);
    try testing.expectEqualStrings("200", decoded[0].value);
    try testing.expectEqualStrings("content-type", decoded[1].name);
    try testing.expectEqualStrings("text/html", decoded[1].value);
    try testing.expectEqualStrings("content-length", decoded[2].name);
    try testing.expectEqualStrings("set-cookie", decoded[3].name);
    try testing.expectEqualStrings("session=1", decoded[3].value);
}

test "h2 translate: unrepresentable responses fail whole" {
    var head_headers: [8]h1.Header = undefined;
    const nul = "HTTP/1.1 200 OK\r\nX-Bad: a\x00b\r\n\r\n";
    const response = (try h1.parse_response(nul, &head_headers)).complete;
    var block: [1024]u8 = undefined;
    try testing.expectError(error.Unencodable, response_block(&response, &block));

    // A block that cannot fit the caller's buffer fails, never truncates.
    const long = "HTTP/1.1 200 OK\r\nX-Long: " ++ ("v" ** 200) ++ "\r\n\r\n";
    const long_response = (try h1.parse_response(long, &head_headers)).complete;
    var tiny: [16]u8 = undefined;
    try testing.expectError(error.Unencodable, response_block(&long_response, &tiny));
}
