//! The Tier-0.5 gate's client (DESIGN.md §9): the smallest HTTP/1.1
//! speaker that can hold a keep-alive connection open and read a whole
//! response off it, plus the raw echo the L4 path needs.
//!
//! Deliberately not zrk (Tier 1's generator): this tier issues a counted
//! handful of requests and asserts an equality on what zoxy wrote about
//! them, so what it needs from a client is *exactness* — every response
//! read to its last body byte before the next request goes out — rather
//! than pacing, histograms or concurrency.
//!
//! It is also not a general client. Only what this origin sends is
//! parsed: a status line, headers, and a `Content-Length` body. A chunked
//! or close-framed response is a failure here, because the origin behind
//! the proxy never sends one, so seeing one means the hop invented it.

const std = @import("std");

const Io = std.Io;

const assert = std.debug.assert;

/// Response head bytes the client will read. zoxy's own head buffer
/// bounds what it can forward, so this only has to be no smaller.
const response_head_bytes_max: u32 = 8192;

/// Body bytes one response may carry. Sized for the whole gate's
/// vocabulary, not for one request, so the cap needs no per-call thought.
pub const response_body_bytes_max: u32 = 256 * 1024;

/// Header lines one response head may spend, on the same terms as the
/// origin's request cap: a bound so the parse loop cannot run forever.
const response_headers_max: u32 = 64;

pub const Response = struct {
    status: u16,
    body_bytes: u32,
    /// Whether the head carried the #175 response-filter stamp the smoke
    /// config sets unconditionally (`X-Zoxy-Smoke: 1`) — the live gate's
    /// witness that the response edit path ran on this very hop.
    edited: bool,
    /// The #178 endpoint tag the head's Set-Cookie announced, or null
    /// when no line claimed the smoke cookie's name. The reader enforces
    /// the whole minted grammar — sixteen tag bytes and the exact
    /// attributes — so a present-but-mangled stamp fails the read
    /// instead of passing as either presence or absence.
    sticky_tag: ?[16]u8,
};

/// What a request says about its connection's future. HTTP/1.1's default
/// is keep-alive, so that arm sends nothing; the other says so.
pub const Persistence = enum {
    keep_alive,
    close,

    fn header(persistence: Persistence) []const u8 {
        return switch (persistence) {
            .keep_alive => "",
            .close => "Connection: close\r\n",
        };
    }
};

pub const Client = struct {
    io: Io = undefined,
    stream: Io.net.Stream = undefined,
    reader: Io.net.Stream.Reader = undefined,
    writer: Io.net.Stream.Writer = undefined,
    read_buffer: [response_head_bytes_max]u8 = undefined,
    write_buffer: [response_head_bytes_max]u8 = undefined,
    /// Requests issued on this connection, so a caller can assert its own
    /// keep-alive arithmetic against what actually went out.
    requests: u32 = 0,
    /// The one field with a real default, and the reason the rest have
    /// one: a static slot starts closed, so `connect` can refuse to
    /// overwrite a live connection instead of leaking its socket.
    connected: bool = false,

    /// Open a connection to a loopback port. In-place through an
    /// out-pointer: both `Reader` and `Writer` hold pointers into the
    /// buffers beside them, so the struct's address has to be final
    /// before either is built.
    pub fn connect(client: *Client, io: Io, port: u16) !void {
        assert(port != 0);
        assert(!client.connected);
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        client.io = io;
        client.stream = try address.connect(io, .{ .mode = .stream });
        client.reader = client.stream.reader(io, &client.read_buffer);
        client.writer = client.stream.writer(io, &client.write_buffer);
        client.requests = 0;
        client.connected = true;
        assert(client.reader.interface.buffer.len == response_head_bytes_max);
    }

    pub fn close(client: *Client) void {
        assert(client.connected);
        client.stream.close(client.io);
        client.connected = false;
    }

    /// One request/response exchange, left on a message boundary so the
    /// next `get` on this connection is a keep-alive turnaround rather
    /// than a fresh guess about where the last response ended.
    ///
    /// `persistence` is explicit at every call site because it decides
    /// more than this connection's fate: announcing close makes zoxy
    /// *inject* a `Connection: close` into the response head (§7), which
    /// is the one thing that renders a head longer than the origin's —
    /// and therefore the only way a coalesced body excess can fail to fit
    /// beside it.
    pub fn get(
        client: *Client,
        host: []const u8,
        target: []const u8,
        persistence: Persistence,
        /// A whole `name=value` Cookie line to send, or null for none —
        /// the #178 leg's echo half. Explicit at every call site, like
        /// `persistence`, so a request's bytes are readable off it.
        cookie: ?[]const u8,
    ) !Response {
        assert(client.connected);
        assert(target.len >= 1);
        assert(target[0] == '/');
        if (cookie) |crumb| {
            assert(crumb.len >= 1);
            try client.writer.interface.print(
                "GET {s} HTTP/1.1\r\nHost: {s}\r\nCookie: {s}\r\n{s}\r\n",
                .{ target, host, crumb, persistence.header() },
            );
        } else {
            try client.writer.interface.print(
                "GET {s} HTTP/1.1\r\nHost: {s}\r\n{s}\r\n",
                .{ target, host, persistence.header() },
            );
        }
        try client.writer.interface.flush();
        client.requests += 1;
        const response = try readResponse(&client.reader.interface);
        assert(client.requests >= 1);
        return response;
    }
};

/// Read one whole response: status line, headers, then exactly the body
/// the `Content-Length` promised.
fn readResponse(reader: *Io.Reader) !Response {
    const status = try readStatus(reader);
    const head = try readHeaders(reader);
    assert(head.body_bytes <= response_body_bytes_max);
    try reader.discardAll(head.body_bytes);
    return .{
        .status = status,
        .body_bytes = head.body_bytes,
        .edited = head.edited,
        .sticky_tag = head.sticky_tag,
    };
}

/// The three-digit status off the status line. A response that does not
/// start `HTTP/1.1 ` is not this hop's output at all, so it is an error
/// rather than a status of zero.
fn readStatus(reader: *Io.Reader) !u16 {
    const prefix = "HTTP/1.1 ";
    const taken = try reader.takeDelimiter('\n');
    const line = taken orelse return error.ResponseTruncated;
    if (line.len < prefix.len + 3) return error.ResponseMalformed;
    if (!std.mem.startsWith(u8, line, prefix)) return error.ResponseMalformed;
    const digits = line[prefix.len .. prefix.len + 3];
    const status = std.fmt.parseUnsigned(u16, digits, 10) catch return error.ResponseMalformed;
    assert(status >= 100);
    assert(status <= 999);
    return status;
}

/// What the header walk found: the framing, whether the #175 stamp was
/// among the lines, and the #178 tag if a Set-Cookie announced one.
const Head = struct {
    body_bytes: u32,
    edited: bool,
    sticky_tag: ?[16]u8,
};

/// Header lines up to the blank one, returning the body length they
/// framed. A head with no `Content-Length` is an error: the origin always
/// sends one, so its absence means the hop reframed the response, which
/// is exactly the kind of thing this tier exists to notice. The #175
/// stamp and the #178 cookie are scanned for on the same walk — spelled
/// here rather than imported, like the counter names: the gate reads
/// what the binary *wrote*, so a drift must fail loudly.
fn readHeaders(reader: *Io.Reader) !Head {
    const length_name = "content-length:";
    const stamp = "x-zoxy-smoke: 1";
    var body_bytes: ?u32 = null;
    var edited = false;
    var sticky_tag: ?[16]u8 = null;
    var lines: u32 = 0;
    while (lines < response_headers_max) : (lines += 1) {
        const taken = try reader.takeDelimiter('\n');
        const line = taken orelse return error.ResponseTruncated;
        const trimmed = std.mem.trimEnd(u8, line, "\r");
        if (trimmed.len == 0) {
            const framed = body_bytes orelse return error.ResponseUnframed;
            return .{ .body_bytes = framed, .edited = edited, .sticky_tag = sticky_tag };
        }
        if (std.ascii.eqlIgnoreCase(trimmed, stamp)) {
            edited = true;
            continue;
        }
        if (try stickyTagOf(trimmed)) |tag| {
            // One announcement per response: a second line naming the
            // cookie would be the stamp path running twice.
            if (sticky_tag != null) return error.ResponseMalformed;
            sticky_tag = tag;
            continue;
        }
        if (trimmed.len <= length_name.len) continue;
        if (!std.ascii.startsWithIgnoreCase(trimmed, length_name)) continue;
        const value = std.mem.trim(u8, trimmed[length_name.len..], " \t");
        const parsed = std.fmt.parseUnsigned(u32, value, 10) catch
            return error.ResponseMalformed;
        if (parsed > response_body_bytes_max) return error.ResponseTooLarge;
        body_bytes = parsed;
    }
    assert(lines == response_headers_max);
    return error.ResponseMalformed;
}

/// The #178 tag a header line announces, null when the line is not a
/// Set-Cookie for the smoke cookie — and an error when it is one but
/// not in the whole minted grammar (`name=` plus sixteen tag bytes plus
/// the exact attributes), because a mangled stamp must fail the gate,
/// not read as present or absent. The header name is case-insensitive;
/// the cookie name is not (RFC 6265), and zoxy forwards what it minted.
fn stickyTagOf(line: []const u8) !?[16]u8 {
    const header_name = "set-cookie:";
    const cookie_prefix = "zoxy-smoke-srv=";
    const attributes = "; Path=/; HttpOnly";
    if (line.len <= header_name.len) return null;
    if (!std.ascii.startsWithIgnoreCase(line, header_name)) return null;
    const value = std.mem.trim(u8, line[header_name.len..], " \t");
    if (!std.mem.startsWith(u8, value, cookie_prefix)) return null;
    const rest = value[cookie_prefix.len..];
    if (rest.len != 16 + attributes.len) return error.ResponseMalformed;
    if (!std.mem.eql(u8, rest[16..], attributes)) return error.ResponseMalformed;
    var tag: [16]u8 = undefined;
    @memcpy(&tag, rest[0..16]);
    return tag;
}
