//! Zero-copy HTTP/1.1 request-head parser. Every field is a slice into the
//! caller's input buffer — nothing is copied or allocated (docs/DESIGN.md §5).
//! The parser re-runs from the start on each call (picohttpparser style): feed
//! it the bytes received so far; `.incomplete` means "call again with more".
//! Header lines land in a caller-provided fixed array, so a request that exceeds
//! it is rejected (431) rather than growing.

const std = @import("std");
const assert = std.debug.assert;

pub const Method = enum { get, head, post, put, delete, patch, options, connect, trace, other };

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// A parsed request head. All slices point into the input buffer and are valid
/// only while that buffer is unmodified.
pub const Request = struct {
    method: Method,
    method_text: []const u8,
    target: []const u8,
    /// Minor version: 0 for HTTP/1.0, 1 for HTTP/1.1.
    version_minor: u8,
    headers: []const Header,
    /// Bytes consumed by the head, including the terminating CRLF CRLF. The
    /// body (if any) begins at `input[head_len..]`.
    head_len: usize,

    /// Case-insensitive header lookup; returns the first match.
    pub fn header(request: *const Request, name: []const u8) ?[]const u8 {
        for (request.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    pub fn host(request: *const Request) ?[]const u8 {
        return request.header("host");
    }
};

pub const ParseError = error{
    /// Syntactically invalid — respond 400.
    Malformed,
    /// More header lines than the caller's array holds — respond 431.
    TooManyHeaders,
    /// Not HTTP/1.0 or HTTP/1.1 — respond 505.
    UnsupportedVersion,
};

pub const Parsed = union(enum) {
    complete: Request,
    /// The head is not yet fully present; read more and parse again.
    incomplete,
};

/// Parse a request head out of `input`, filling `headers` with header lines.
pub fn parse(input: []const u8, headers: []Header) ParseError!Parsed {
    assert(headers.len > 0);
    var pos: usize = 0;

    const request_line = readLine(input, &pos) orelse return .incomplete;
    const line = try parseRequestLine(request_line);

    var count: usize = 0;
    while (true) {
        const header_line = readLine(input, &pos) orelse return .incomplete;
        if (header_line.len == 0) break; // blank line terminates the head
        if (count == headers.len) return error.TooManyHeaders;
        headers[count] = try parseHeader(header_line);
        count += 1;
    }

    return .{ .complete = .{
        .method = line.method,
        .method_text = line.method_text,
        .target = line.target,
        .version_minor = line.version_minor,
        .headers = headers[0..count],
        .head_len = pos,
    } };
}

const RequestLine = struct {
    method: Method,
    method_text: []const u8,
    target: []const u8,
    version_minor: u8,
};

fn parseRequestLine(line: []const u8) ParseError!RequestLine {
    const sp1 = std.mem.indexOfScalar(u8, line, ' ') orelse return error.Malformed;
    const method_text = line[0..sp1];
    if (method_text.len == 0 or !isToken(method_text)) return error.Malformed;

    const after_method = line[sp1 + 1 ..];
    const sp2 = std.mem.indexOfScalar(u8, after_method, ' ') orelse return error.Malformed;
    const target = after_method[0..sp2];
    if (target.len == 0) return error.Malformed;

    return .{
        .method = methodFromText(method_text),
        .method_text = method_text,
        .target = target,
        .version_minor = try parseVersion(after_method[sp2 + 1 ..]),
    };
}

fn parseVersion(version: []const u8) ParseError!u8 {
    const prefix = "HTTP/";
    if (!std.mem.startsWith(u8, version, prefix)) return error.Malformed;
    const v = version[prefix.len..];
    if (v.len != 3 or v[1] != '.') return error.Malformed;
    if (v[0] != '1') return error.UnsupportedVersion;
    return switch (v[2]) {
        '0' => 0,
        '1' => 1,
        else => error.UnsupportedVersion,
    };
}

fn parseHeader(line: []const u8) ParseError!Header {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.Malformed;
    const name = line[0..colon];
    // A token name with no whitespace blocks header-smuggling tricks.
    if (name.len == 0 or !isToken(name)) return error.Malformed;
    return .{ .name = name, .value = trimOws(line[colon + 1 ..]) };
}

fn methodFromText(text: []const u8) Method {
    const map = std.StaticStringMap(Method).initComptime(.{
        .{ "GET", .get },
        .{ "HEAD", .head },
        .{ "POST", .post },
        .{ "PUT", .put },
        .{ "DELETE", .delete },
        .{ "PATCH", .patch },
        .{ "OPTIONS", .options },
        .{ "CONNECT", .connect },
        .{ "TRACE", .trace },
    });
    return map.get(text) orelse .other;
}

/// Read one CRLF-terminated line, advancing `pos` past the CRLF. Returns null
/// (incomplete) if no CRLF is present yet. The returned slice excludes the CRLF.
fn readLine(input: []const u8, pos: *usize) ?[]const u8 {
    const start = pos.*;
    var i = start;
    while (i + 1 < input.len) : (i += 1) {
        if (input[i] == '\r' and input[i + 1] == '\n') {
            pos.* = i + 2;
            return input[start..i];
        }
    }
    return null;
}

/// True if every byte is a visible, non-whitespace token character.
fn isToken(s: []const u8) bool {
    for (s) |c| {
        if (c <= 0x20 or c == 0x7f) return false;
    }
    return true;
}

/// Trim optional leading/trailing whitespace (spaces and tabs) per RFC 9110 OWS.
fn trimOws(s: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = s.len;
    while (start < end and (s[start] == ' ' or s[start] == '\t')) start += 1;
    while (end > start and (s[end - 1] == ' ' or s[end - 1] == '\t')) end -= 1;
    return s[start..end];
}

// ---- tests ----------------------------------------------------------------

test "h1: parses a complete request with headers" {
    var headers: [8]Header = undefined;
    const raw = "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\nBODYBYTES";
    const parsed = try parse(raw, &headers);

    const req = parsed.complete;
    try std.testing.expectEqual(Method.get, req.method);
    try std.testing.expectEqualStrings("GET", req.method_text);
    try std.testing.expectEqualStrings("/path?q=1", req.target);
    try std.testing.expectEqual(@as(u8, 1), req.version_minor);
    try std.testing.expectEqual(@as(usize, 2), req.headers.len);
    try std.testing.expectEqualStrings("example.com", req.host().?);
    try std.testing.expectEqualStrings("*/*", req.header("accept").?);
    // Case-insensitive lookup, and body is left unconsumed.
    try std.testing.expectEqualStrings("example.com", req.header("HOST").?);
    try std.testing.expectEqualStrings("BODYBYTES", raw[req.head_len..]);
}

test "h1: trims OWS around header values" {
    var headers: [4]Header = undefined;
    const parsed = try parse("GET / HTTP/1.1\r\nHost: \t example.com \t \r\n\r\n", &headers);
    try std.testing.expectEqualStrings("example.com", parsed.complete.host().?);
}

test "h1: incomplete input asks for more" {
    var headers: [4]Header = undefined;
    try std.testing.expectEqual(Parsed.incomplete, try parse("GET / HTTP/1.1\r\nHost: x\r\n", &headers));
    try std.testing.expectEqual(Parsed.incomplete, try parse("GET / HTT", &headers));
    try std.testing.expectEqual(Parsed.incomplete, try parse("", &headers));
}

test "h1: rejects malformed requests" {
    var headers: [8]Header = undefined;
    try std.testing.expectError(error.Malformed, parse("GET\r\n\r\n", &headers));
    try std.testing.expectError(error.Malformed, parse("GET /\r\n\r\n", &headers));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/1.1\r\nBadHeader\r\n\r\n", &headers));
    try std.testing.expectError(error.Malformed, parse("GET / HTTP/1.1\r\nBad Name: v\r\n\r\n", &headers));
    try std.testing.expectError(error.Malformed, parse("GET / WHAT/1.1\r\n\r\n", &headers));
}

test "h1: rejects unsupported versions" {
    var headers: [4]Header = undefined;
    try std.testing.expectError(error.UnsupportedVersion, parse("GET / HTTP/2.0\r\n\r\n", &headers));
    try std.testing.expectError(error.UnsupportedVersion, parse("GET / HTTP/1.9\r\n\r\n", &headers));
    try std.testing.expectEqual(@as(u8, 0), (try parse("GET / HTTP/1.0\r\n\r\n", &headers)).complete.version_minor);
}

test "h1: rejects too many headers" {
    var one: [1]Header = undefined;
    try std.testing.expectError(
        error.TooManyHeaders,
        parse("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n", &one),
    );
}
