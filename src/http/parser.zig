//! HTTP/1.1 head parsing and body framing for the L7 data path (DESIGN.md
//! §7). hparse — the hardened zoxy-io fork, pinned by content hash in
//! build.zig.zon — parses *syntax* only; every strictness, smuggling, and
//! framing decision is made here, so the trust boundary sits at this
//! wrapper, not at the dependency. A build-time lint confines the hparse
//! import to this file.
//!
//! Nothing here allocates or copies payload bytes: heads parse zero-copy
//! into caller-owned storage over the linear head buffer, and "streaming"
//! is detect-and-retry — a partial head returns `error.Incomplete` and the
//! caller re-parses from byte 0 once more bytes arrive, bounded by
//! `constants.head_bytes_max`.
//!
//! The §7 fork hardening gate is fully cleared at the current pin: the
//! fork rejects bare-LF line terminators itself (CRLF only) and parses
//! extension methods (PROPFIND, ...) as tokens. The tests below keep both
//! behaviors witnessed through this wrapper.

const std = @import("std");
const hparse = @import("hparse");
const constants = @import("../constants.zig");

const assert = std.debug.assert;

/// Request methods. The nine registered methods parse to their tags; any
/// other RFC 9110 token (PROPFIND, MKCOL, ...) parses to `.extension`
/// with the raw bytes in `RequestHead.method_token`. Owned here (not
/// re-exported) so fork API changes stay confined to this file.
pub const Method = enum(u8) {
    get,
    post,
    head,
    put,
    delete,
    connect,
    options,
    trace,
    patch,
    extension,
};

/// HTTP/1.0 and HTTP/1.1 are served; anything else is malformed (§1
/// defers HTTP/2 and beyond).
pub const Version = enum(u1) {
    http_1_0,
    http_1_1,
};

/// One parsed header. Both slices point into the head buffer the head was
/// parsed from — zero-copy, valid only while that buffer holds this head.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Caller-owned header storage for one parsed head; the connection slot
/// embeds one of these per direction it parses.
pub const HeaderStorage = [constants.headers_max]Header;

/// How the message body is delimited (RFC 9112 §6.3). `until_close` is
/// legal only on responses; requests are always length-delimited.
pub const BodyFraming = union(enum) {
    /// No body bytes follow the head.
    none,
    /// Exactly this many body bytes follow the head.
    content_length: u64,
    /// The body is chunked; `ChunkedScanner` finds its end.
    chunked,
    /// The body runs until the origin closes (responses only). Forces the
    /// upstream connection out of reuse.
    until_close,
};

/// * `Incomplete` — the head is not finished; read more bytes and re-parse.
/// * `Malformed` — protocol violation or smuggling shape; 400 downstream,
///   teardown upstream.
/// * `UriTooLong` — the request line alone overflowed the head buffer; 414.
/// * `HeadTooLarge` — the header section overflowed the head buffer or the
///   bounded header array; 431. Load, not malice — distinct from 400 (§7).
pub const HeadError = error{
    Incomplete,
    Malformed,
    UriTooLong,
    HeadTooLarge,
};

/// A fully parsed and validated request head. All slices point into the
/// head buffer; `head_len` is where the body (or the next pipelined head)
/// begins.
pub const RequestHead = struct {
    method: Method,
    /// The method's raw token bytes ("GET", "PROPFIND", ...) — what the
    /// renderer writes into the upstream request line, whatever the tag.
    method_token: []const u8,
    target: []const u8,
    version: Version,
    headers: []const Header,
    /// Non-null whenever `version == .http_1_1` (exactly-one-Host is
    /// enforced); HTTP/1.0 may omit it.
    host: ?[]const u8,
    framing: BodyFraming,
    /// Whether the downstream connection may serve another request after
    /// this exchange, per version defaults and Connection tokens.
    keep_alive: bool,
    head_len: u32,
};

/// A fully parsed and validated response head. Same slice lifetime rules
/// as `RequestHead`.
pub const ResponseHead = struct {
    status: u16,
    /// The origin's reason phrase, forwarded verbatim by the renderer;
    /// null when the origin sent none (bare `HTTP/1.1 200\r\n`).
    status_message: ?[]const u8,
    version: Version,
    headers: []const Header,
    framing: BodyFraming,
    /// Whether the upstream connection may be parked for reuse after this
    /// exchange; always false for `until_close` framing.
    keep_alive: bool,
    head_len: u32,
};

/// Parses and validates one request head from `head`. `head_is_full` says
/// the head buffer has no room left, turning a partial parse into the 414
/// vs 431 oversize verdict instead of `error.Incomplete` (§7, §8).
pub fn parseRequestHead(
    head: []const u8,
    head_is_full: bool,
    headers_storage: *HeaderStorage,
) HeadError!RequestHead {
    assert(head.len <= constants.head_bytes_max);
    if (head_is_full) {
        assert(head.len >= 1);
    }

    var raw_method: hparse.Method = .unknown;
    var raw_method_token: ?[]const u8 = null;
    var raw_target: ?[]const u8 = null;
    var raw_version: hparse.Version = .@"1.0";
    var raw_headers: [constants.headers_max]hparse.Header = undefined;
    var raw_header_count: usize = 0;
    const head_len = hparse.parseRequest(
        head,
        &raw_method,
        &raw_method_token,
        &raw_target,
        &raw_version,
        &raw_headers,
        &raw_header_count,
    ) catch |err| switch (err) {
        // A head that cannot complete inside a full buffer is oversize,
        // not partial (§7): request line still open → 414, else 431.
        error.Incomplete => {
            if (head_is_full) {
                return oversizeRequestError(head);
            }
            return error.Incomplete;
        },
        error.Invalid => return error.Malformed,
        // The bounded header array filling up is load, not malice (§7).
        error.TooManyHeaders => return error.HeadTooLarge,
    };
    assert(head_len >= 1);
    assert(head_len <= head.len);
    assert(raw_header_count <= constants.headers_max);

    const target = raw_target.?; // A successful parse always sets the target.
    const method_token = raw_method_token.?; // Same contract as the target.
    assert(method_token.len >= 1);
    const method = methodFromRaw(raw_method);
    try validateTarget(target, method);
    const version = versionFromRaw(raw_version);

    const analysis = try analyzeHeaders(raw_headers[0..raw_header_count], headers_storage);
    // An HTTP/1.1 request must carry exactly one Host (RFC 9112 §3.2);
    // duplicates were already rejected during analysis.
    if (version == .http_1_1) {
        if (analysis.host == null) {
            return error.Malformed;
        }
    }
    const framing = try requestFraming(version, &analysis);
    assert(framing != .until_close); // Requests are always length-delimited.

    return .{
        .method = method,
        .method_token = method_token,
        .target = target,
        .version = version,
        .headers = headers_storage[0..raw_header_count],
        .host = analysis.host,
        .framing = framing,
        .keep_alive = keepAliveDefault(version, &analysis),
        .head_len = @intCast(head_len),
    };
}

/// Parses and validates one response head from `head`. Framing needs the
/// request's method (HEAD responses carry no body regardless of headers).
pub fn parseResponseHead(
    head: []const u8,
    head_is_full: bool,
    headers_storage: *HeaderStorage,
    request_method: Method,
) HeadError!ResponseHead {
    assert(head.len <= constants.head_bytes_max);
    // The proxy rejects CONNECT before dialing (§7 keeps tunnels out), so
    // a CONNECT response is unrepresentable here.
    assert(request_method != .connect);

    var raw_version: hparse.Version = .@"1.0";
    var raw_status: u16 = 0;
    var raw_status_message: ?[]const u8 = null;
    var raw_headers: [constants.headers_max]hparse.Header = undefined;
    var raw_header_count: usize = 0;
    const head_len = hparse.parseResponse(
        head,
        &raw_version,
        &raw_status,
        &raw_status_message,
        &raw_headers,
        &raw_header_count,
    ) catch |err| switch (err) {
        // No 414-class verdict on the origin side: an oversize response
        // head is simply too large, whatever line it stalled on.
        error.Incomplete => {
            if (head_is_full) {
                return error.HeadTooLarge;
            }
            return error.Incomplete;
        },
        error.Invalid => return error.Malformed,
        error.TooManyHeaders => return error.HeadTooLarge,
    };
    assert(head_len >= 1);
    assert(head_len <= head.len);
    assert(raw_header_count <= constants.headers_max);

    // hparse only checks for three digits; the status class is ours.
    if (raw_status < 100) {
        return error.Malformed;
    }
    if (raw_status > 599) {
        return error.Malformed;
    }
    const version = versionFromRaw(raw_version);

    const analysis = try analyzeHeaders(raw_headers[0..raw_header_count], headers_storage);
    const framing = try responseFraming(request_method, raw_status, version, &analysis);

    return .{
        .status = raw_status,
        .status_message = raw_status_message,
        .version = version,
        .headers = headers_storage[0..raw_header_count],
        .framing = framing,
        .keep_alive = keepAliveDefault(version, &analysis) and framing != .until_close,
        .head_len = @intCast(head_len),
    };
}

/// Incremental delimiter for chunked bodies (RFC 9112 §7.1) relayed
/// verbatim: zoxy forwards the encoded bytes untouched and only needs to
/// know where the message ends, so this scanner validates framing and
/// counts — it never decodes or copies. Feed it the exact bytes that will
/// be forwarded, in any split; whole-buffer and byte-at-a-time feeding
/// reach identical outcomes. CRLF-strict everywhere: a bare LF anywhere in
/// the framing is malformed (§7's smuggling posture).
pub const ChunkedScanner = struct {
    state: State = .size,
    /// Chunk-data bytes still to pass through in the current chunk.
    data_remaining: u64 = 0,
    /// Chunk-size value accumulating while in `.size`.
    size: u64 = 0,
    /// True once the current size line has at least one hex digit.
    size_has_digit: bool = false,
    /// Bytes consumed by the current size line, bounded by
    /// `constants.chunked_line_bytes_max`.
    line_bytes: u32 = 0,
    /// Bytes consumed by the trailer section, bounded by
    /// `constants.chunked_trailer_bytes_max`.
    trailer_bytes: u32 = 0,

    pub const State = enum(u8) {
        size,
        extension,
        size_lf,
        data,
        data_cr,
        data_lf,
        trailer_start,
        trailer_field,
        trailer_lf,
        final_lf,
        done,
    };

    pub const Progress = struct {
        consumed: u32,
        done: bool,
    };

    /// * `Malformed` — framing violation; the message end is unknowable,
    ///   so the connection is torn down.
    /// * `Oversize` — a size line or trailer section exceeded its static
    ///   bound; same teardown, distinct counter.
    pub const Error = error{ Malformed, Oversize };

    /// Consumes bytes until the message ends or `bytes` runs out. Bytes
    /// past the terminating CRLF belong to the next message (or to
    /// nothing) and are never consumed.
    pub fn feed(scanner: *ChunkedScanner, bytes: []const u8) Error!Progress {
        assert(bytes.len >= 1);
        assert(bytes.len <= std.math.maxInt(u32));
        assert(scanner.state != .done);

        var index: u32 = 0;
        while (index < bytes.len) {
            const consumed = try scanner.step(bytes[index..]);
            assert(consumed >= 1);
            index += consumed;
            assert(index <= bytes.len);
            if (scanner.state == .done) {
                break;
            }
        }
        assert(index >= 1);
        const done = scanner.state == .done;
        if (!done) {
            assert(index == bytes.len);
        }
        return .{ .consumed = index, .done = done };
    }

    /// Consumes at least one byte: a whole run of chunk data, or exactly
    /// one framing byte.
    fn step(scanner: *ChunkedScanner, bytes: []const u8) Error!u32 {
        assert(bytes.len >= 1);
        return switch (scanner.state) {
            .size, .extension, .size_lf => scanner.stepSizeLine(bytes[0]),
            .data => scanner.stepData(bytes),
            .data_cr, .data_lf => scanner.stepDataEnd(bytes[0]),
            .trailer_start, .trailer_field, .trailer_lf, .final_lf => scanner.stepTrailer(bytes[0]),
            .done => unreachable, // feed() never steps a finished scanner.
        };
    }

    fn stepSizeLine(scanner: *ChunkedScanner, byte: u8) Error!u32 {
        try scanner.countLineByte();
        switch (scanner.state) {
            .size => switch (byte) {
                '0'...'9', 'a'...'f', 'A'...'F' => {
                    // A size whose next digit would overflow u64 is a
                    // hostile stream, not a body anyone relays.
                    if (scanner.size > comptime (std.math.maxInt(u64) >> 4)) {
                        return error.Oversize;
                    }
                    scanner.size = scanner.size * 16 + hexDigitValue(byte);
                    scanner.size_has_digit = true;
                },
                ';' => {
                    if (!scanner.size_has_digit) {
                        return error.Malformed;
                    }
                    scanner.state = .extension;
                },
                '\r' => {
                    if (!scanner.size_has_digit) {
                        return error.Malformed;
                    }
                    scanner.state = .size_lf;
                },
                else => return error.Malformed,
            },
            // Extensions are forwarded, not interpreted; only the byte
            // alphabet is policed (bare LF and controls are malformed).
            .extension => switch (byte) {
                '\r' => scanner.state = .size_lf,
                else => {
                    if (!isForwardableByte(byte)) {
                        return error.Malformed;
                    }
                },
            },
            .size_lf => {
                if (byte != '\n') {
                    return error.Malformed;
                }
                if (scanner.size == 0) {
                    // last-chunk (a size of zero) ends the data phase.
                    scanner.state = .trailer_start;
                } else {
                    scanner.data_remaining = scanner.size;
                    scanner.state = .data;
                }
            },
            else => unreachable, // step() dispatched a size-line state.
        }
        return 1;
    }

    fn stepData(scanner: *ChunkedScanner, bytes: []const u8) Error!u32 {
        assert(bytes.len >= 1);
        assert(scanner.data_remaining >= 1);
        const wanted: u64 = @min(scanner.data_remaining, @as(u64, bytes.len));
        const consumed: u32 = @intCast(wanted);
        assert(consumed >= 1);
        scanner.data_remaining -= wanted;
        if (scanner.data_remaining == 0) {
            scanner.state = .data_cr;
        }
        return consumed;
    }

    fn stepDataEnd(scanner: *ChunkedScanner, byte: u8) Error!u32 {
        switch (scanner.state) {
            .data_cr => {
                if (byte != '\r') {
                    return error.Malformed;
                }
                scanner.state = .data_lf;
            },
            .data_lf => {
                if (byte != '\n') {
                    return error.Malformed;
                }
                scanner.size = 0;
                scanner.size_has_digit = false;
                scanner.line_bytes = 0;
                scanner.state = .size;
            },
            else => unreachable, // step() dispatched a data-end state.
        }
        return 1;
    }

    fn stepTrailer(scanner: *ChunkedScanner, byte: u8) Error!u32 {
        try scanner.countTrailerByte();
        switch (scanner.state) {
            .trailer_start => switch (byte) {
                '\r' => scanner.state = .final_lf,
                else => {
                    if (!isForwardableByte(byte)) {
                        return error.Malformed;
                    }
                    scanner.state = .trailer_field;
                },
            },
            .trailer_field => switch (byte) {
                '\r' => scanner.state = .trailer_lf,
                else => {
                    if (!isForwardableByte(byte)) {
                        return error.Malformed;
                    }
                },
            },
            .trailer_lf => {
                if (byte != '\n') {
                    return error.Malformed;
                }
                scanner.state = .trailer_start;
            },
            .final_lf => {
                if (byte != '\n') {
                    return error.Malformed;
                }
                scanner.state = .done;
            },
            else => unreachable, // step() dispatched a trailer state.
        }
        return 1;
    }

    fn countLineByte(scanner: *ChunkedScanner) Error!void {
        assert(scanner.line_bytes < std.math.maxInt(u32));
        scanner.line_bytes += 1;
        if (scanner.line_bytes > constants.chunked_line_bytes_max) {
            return error.Oversize;
        }
    }

    fn countTrailerByte(scanner: *ChunkedScanner) Error!void {
        assert(scanner.trailer_bytes < std.math.maxInt(u32));
        scanner.trailer_bytes += 1;
        if (scanner.trailer_bytes > constants.chunked_trailer_bytes_max) {
            return error.Oversize;
        }
    }
};

/// First value for a header name, case-insensitively, or null. For the
/// phase points and the renderer; framing decisions never use it (they
/// need duplicate detection, which `analyzeHeaders` owns).
pub fn headerValue(headers: []const Header, name: []const u8) ?[]const u8 {
    assert(name.len >= 1);
    for (headers) |header| {
        assert(header.name.len >= 1);
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            return header.value;
        }
    }
    return null;
}

/// True if a comma-separated token list (Connection, TE, ...) contains
/// `token`, case-insensitively, with optional whitespace around tokens.
pub fn tokenListHas(value: []const u8, token: []const u8) bool {
    assert(token.len >= 1);
    var tokens = std.mem.splitScalar(u8, value, ',');
    // Bounded: the iterator yields at most value.len + 1 pieces.
    while (tokens.next()) |raw_token| {
        const trimmed = std.mem.trim(u8, raw_token, " \t");
        if (trimmed.len == 0) {
            continue;
        }
        if (std.ascii.eqlIgnoreCase(trimmed, token)) {
            return true;
        }
    }
    return false;
}

/// What one validation pass over the raw headers found. The pass also
/// copies every header into the caller's storage — the copy rides the
/// walk the analysis needs anyway, so consumers never see hparse's types.
const HeaderAnalysis = struct {
    host: ?[]const u8,
    content_length: ?u64,
    /// Transfer-Encoding present and exactly "chunked".
    te_chunked: bool,
    /// Transfer-Encoding present and anything else.
    te_other: bool,
    connection_close: bool,
    connection_keep_alive: bool,
};

fn analyzeHeaders(
    raw_headers: []const hparse.Header,
    headers_storage: *HeaderStorage,
) error{Malformed}!HeaderAnalysis {
    assert(raw_headers.len <= headers_storage.len);
    var analysis = HeaderAnalysis{
        .host = null,
        .content_length = null,
        .te_chunked = false,
        .te_other = false,
        .connection_close = false,
        .connection_keep_alive = false,
    };
    for (raw_headers, 0..) |raw_header, index| {
        assert(raw_header.key.len >= 1);
        headers_storage[index] = .{ .name = raw_header.key, .value = raw_header.value };
        if (std.ascii.eqlIgnoreCase(raw_header.key, "host")) {
            // A second Host changes routing depending on who reads which —
            // a smuggling shape, like an empty one (RFC 9112 §3.2).
            if (analysis.host != null) {
                return error.Malformed;
            }
            if (raw_header.value.len == 0) {
                return error.Malformed;
            }
            analysis.host = raw_header.value;
            continue;
        }
        if (std.ascii.eqlIgnoreCase(raw_header.key, "content-length")) {
            // Duplicate Content-Length is rejected outright, identical
            // values included (§7 "duplicate/garbage Content-Length").
            if (analysis.content_length != null) {
                return error.Malformed;
            }
            analysis.content_length = try parseContentLength(raw_header.value);
            continue;
        }
        if (std.ascii.eqlIgnoreCase(raw_header.key, "transfer-encoding")) {
            // A second Transfer-Encoding header is the list form in
            // disguise; only the single exact "chunked" is ever legal
            // here, so any repeat is malformed.
            if (analysis.te_chunked or analysis.te_other) {
                return error.Malformed;
            }
            if (std.ascii.eqlIgnoreCase(raw_header.value, "chunked")) {
                analysis.te_chunked = true;
            } else {
                analysis.te_other = true;
            }
            continue;
        }
        if (std.ascii.eqlIgnoreCase(raw_header.key, "connection")) {
            // Multiple Connection headers combine as one list (RFC 9110).
            scanConnectionTokens(raw_header.value, &analysis);
            continue;
        }
    }
    assert(!(analysis.te_chunked and analysis.te_other));
    if (analysis.host) |host| {
        assert(host.len >= 1);
    }
    return analysis;
}

/// Set the persistence flags from one Connection header value in a single
/// token pass — scanning the list twice (once per token) was a measured
/// hot spot (§9). Tokens are OWS-trimmed and matched case-insensitively.
fn scanConnectionTokens(value: []const u8, analysis: *HeaderAnalysis) void {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |raw_token| {
        const token = std.mem.trim(u8, raw_token, " \t");
        if (token.len == 0) {
            continue;
        }
        if (std.ascii.eqlIgnoreCase(token, "close")) {
            analysis.connection_close = true;
        } else if (std.ascii.eqlIgnoreCase(token, "keep-alive")) {
            analysis.connection_keep_alive = true;
        }
    }
}

/// Request-side framing (RFC 9112 §6.3): length-delimited or nothing.
/// Every smuggling shape dies here, before any byte reaches an upstream.
fn requestFraming(
    version: Version,
    analysis: *const HeaderAnalysis,
) error{Malformed}!BodyFraming {
    assert(!(analysis.te_chunked and analysis.te_other));
    const te_present = analysis.te_chunked or analysis.te_other;
    if (te_present) {
        // Transfer-Encoding does not exist in HTTP/1.0.
        if (version == .http_1_0) {
            return error.Malformed;
        }
        // TE + CL is the classic smuggling shape (§7): reject, never pick.
        if (analysis.content_length != null) {
            return error.Malformed;
        }
        // Only the single exact "chunked" coding is accepted on requests
        // (RFC 9112 §6.1 lets a server reject anything else).
        if (analysis.te_other) {
            return error.Malformed;
        }
        return .chunked;
    }
    if (analysis.content_length) |length| {
        return .{ .content_length = length };
    }
    return .none;
}

/// Response-side framing (RFC 9112 §6.3), in the RFC's precedence order.
fn responseFraming(
    request_method: Method,
    status: u16,
    version: Version,
    analysis: *const HeaderAnalysis,
) error{Malformed}!BodyFraming {
    assert(status >= 100);
    assert(status <= 599);
    assert(request_method != .connect);
    const te_present = analysis.te_chunked or analysis.te_other;
    // TE + CL "ought to be handled as an error" (RFC 9112 §6.3): an origin
    // emitting the smuggling shape is torn down, not reinterpreted.
    if (te_present) {
        if (analysis.content_length != null) {
            return error.Malformed;
        }
        if (version == .http_1_0) {
            return error.Malformed;
        }
    }
    // These carry no body bytes regardless of framing headers.
    if (request_method == .head) {
        return .none;
    }
    if (status < 200) {
        return .none;
    }
    if (status == 204) {
        return .none;
    }
    if (status == 304) {
        return .none;
    }
    if (analysis.te_chunked) {
        return .chunked;
    }
    if (analysis.te_other) {
        // Chunked-not-final: the body runs to connection close
        // (RFC 9112 §6.3 item 4) and the connection leaves reuse.
        return .until_close;
    }
    if (analysis.content_length) |length| {
        return .{ .content_length = length };
    }
    return .until_close;
}

/// Persistence per version defaults and Connection tokens (RFC 9112 §9).
fn keepAliveDefault(version: Version, analysis: *const HeaderAnalysis) bool {
    return switch (version) {
        .http_1_1 => !analysis.connection_close,
        .http_1_0 => analysis.connection_keep_alive and !analysis.connection_close,
    };
}

/// A reverse proxy routes origin-form targets (§7 routes host/path);
/// asterisk-form is legal for OPTIONS. CONNECT's authority-form passes
/// through so the proxy can answer it with 501 rather than 400.
fn validateTarget(target: []const u8, method: Method) error{Malformed}!void {
    if (target.len == 0) {
        return error.Malformed;
    }
    assert(target.len >= 1);
    if (method == .connect) {
        return;
    }
    if (target[0] == '/') {
        return;
    }
    if (method == .options) {
        if (std.mem.eql(u8, target, "*")) {
            return;
        }
    }
    return error.Malformed;
}

/// 1*DIGIT (RFC 9112 §6.2): digits only — no sign, no whitespace, no
/// comma list. 19 digits bound the value below 10^19 < 2^64, so the
/// accumulation cannot overflow.
fn parseContentLength(value: []const u8) error{Malformed}!u64 {
    if (value.len == 0) {
        return error.Malformed;
    }
    if (value.len > 19) {
        return error.Malformed;
    }
    var total: u64 = 0;
    for (value) |byte| {
        if (byte < '0') {
            return error.Malformed;
        }
        if (byte > '9') {
            return error.Malformed;
        }
        total = total * 10 + (byte - '0');
    }
    assert(total < 10_000_000_000_000_000_000);
    return total;
}

/// The 414 vs 431 verdict for a request head that cannot complete inside
/// a full head buffer (§7): no line terminator at all means the request
/// line itself overflowed.
fn oversizeRequestError(head: []const u8) HeadError {
    assert(head.len >= 1);
    if (std.mem.indexOfScalar(u8, head, '\n') == null) {
        return error.UriTooLong;
    }
    return error.HeadTooLarge;
}

fn methodFromRaw(raw_method: hparse.Method) Method {
    assert(raw_method != .unknown);
    return switch (raw_method) {
        // A successful parse always overwrites the sentinel (hparse contract).
        .unknown => unreachable,
        .get => .get,
        .post => .post,
        .head => .head,
        .put => .put,
        .delete => .delete,
        .connect => .connect,
        .options => .options,
        .trace => .trace,
        .patch => .patch,
        .extension => .extension,
    };
}

fn versionFromRaw(raw_version: hparse.Version) Version {
    return switch (raw_version) {
        .@"1.0" => .http_1_0,
        .@"1.1" => .http_1_1,
    };
}

fn isForwardableByte(byte: u8) bool {
    return byte == '\t' or (byte >= ' ' and byte != 0x7f);
}

fn hexDigitValue(byte: u8) u4 {
    return switch (byte) {
        '0'...'9' => @intCast(byte - '0'),
        'a'...'f' => @intCast(byte - 'a' + 10),
        'A'...'F' => @intCast(byte - 'A' + 10),
        else => unreachable, // Caller matched a hex digit.
    };
}

// Tests. Head-parse cases go through the public wrapper only — hparse's
// own behavior is covered in its repository; what is pinned down here is
// the trust boundary's verdicts (§7).

const testing = std.testing;

fn expectRequestError(expected: HeadError, head: []const u8, head_is_full: bool) !void {
    var storage: HeaderStorage = undefined;
    try testing.expectError(expected, parseRequestHead(head, head_is_full, &storage));
}

fn expectResponseError(expected: HeadError, head: []const u8, request_method: Method) !void {
    var storage: HeaderStorage = undefined;
    try testing.expectError(
        expected,
        parseResponseHead(head, false, &storage, request_method),
    );
}

test "http parser: plain GET parses with keep-alive and no body" {
    const head = "GET /path?q=1 HTTP/1.1\r\nHost: origin.example\r\nAccept: */*\r\n\r\n";
    var storage: HeaderStorage = undefined;
    const request = try parseRequestHead(head, false, &storage);
    try testing.expectEqual(Method.get, request.method);
    try testing.expectEqualStrings("GET", request.method_token);
    try testing.expectEqualStrings("/path?q=1", request.target);
    try testing.expectEqual(Version.http_1_1, request.version);
    try testing.expectEqualStrings("origin.example", request.host.?);
    try testing.expectEqual(BodyFraming.none, request.framing);
    try testing.expect(request.keep_alive);
    try testing.expectEqual(@as(u32, head.len), request.head_len);
    try testing.expectEqual(@as(usize, 2), request.headers.len);
    try testing.expectEqualStrings("Accept", request.headers[1].name);
}

test "http parser: POST with Content-Length frames the body and marks its start" {
    const head = "POST /submit HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n";
    const message = head ++ "hello";
    var storage: HeaderStorage = undefined;
    const request = try parseRequestHead(message, false, &storage);
    try testing.expectEqual(BodyFraming{ .content_length = 5 }, request.framing);
    try testing.expectEqual(@as(u32, head.len), request.head_len);
    try testing.expectEqualStrings("hello", message[request.head_len..]);
}

test "http parser: chunked Transfer-Encoding frames the request body" {
    const head = "POST /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";
    var storage: HeaderStorage = undefined;
    const request = try parseRequestHead(head, false, &storage);
    try testing.expectEqual(BodyFraming.chunked, request.framing);
}

test "http parser: smuggling shapes are malformed before any upstream byte" {
    // TE + CL.
    try expectRequestError(
        error.Malformed,
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
        false,
    );
    // Duplicate Content-Length, identical values included.
    try expectRequestError(
        error.Malformed,
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
        false,
    );
    // Garbage Content-Length: sign, suffix, list, empty.
    try expectRequestError(
        error.Malformed,
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\n",
        false,
    );
    try expectRequestError(
        error.Malformed,
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5x\r\n\r\n",
        false,
    );
    try expectRequestError(
        error.Malformed,
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\n",
        false,
    );
    try expectRequestError(
        error.Malformed,
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length:\r\n\r\n",
        false,
    );
    // Transfer-Encoding that is not exactly "chunked".
    try expectRequestError(
        error.Malformed,
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        false,
    );
    // Duplicate Transfer-Encoding — the list form in disguise.
    try expectRequestError(
        error.Malformed,
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        false,
    );
    // Transfer-Encoding does not exist in HTTP/1.0.
    try expectRequestError(
        error.Malformed,
        "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
        false,
    );
}

test "http parser: Content-Length accepts leading zeros and the u64 maximum digits" {
    var storage: HeaderStorage = undefined;
    const zeros = try parseRequestHead(
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0123\r\n\r\n",
        false,
        &storage,
    );
    try testing.expectEqual(BodyFraming{ .content_length = 123 }, zeros.framing);
    // 20 digits can overflow u64; the parser caps at 19 outright.
    try expectRequestError(
        error.Malformed,
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n",
        false,
    );
}

test "http parser: Host is mandatory and unique on HTTP/1.1" {
    try expectRequestError(error.Malformed, "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", false);
    try expectRequestError(
        error.Malformed,
        "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        false,
    );
    try expectRequestError(error.Malformed, "GET / HTTP/1.1\r\nHost:\r\n\r\n", false);
    // HTTP/1.0 may omit Host.
    var storage: HeaderStorage = undefined;
    const request = try parseRequestHead("GET / HTTP/1.0\r\n\r\n", false, &storage);
    try testing.expectEqual(@as(?[]const u8, null), request.host);
}

test "http parser: keep-alive follows version defaults and Connection tokens" {
    const Case = struct { head: []const u8, keep_alive: bool };
    const cases = [_]Case{
        .{ .head = "GET / HTTP/1.1\r\nHost: a\r\n\r\n", .keep_alive = true },
        .{ .head = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", .keep_alive = false },
        .{ .head = "GET / HTTP/1.1\r\nHost: a\r\nConnection: Close\r\n\r\n", .keep_alive = false },
        .{ .head = "GET / HTTP/1.0\r\n\r\n", .keep_alive = false },
        .{ .head = "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", .keep_alive = true },
        // close wins over keep-alive when both tokens appear.
        .{
            .head = "GET / HTTP/1.0\r\nConnection: keep-alive, close\r\n\r\n",
            .keep_alive = false,
        },
    };
    for (cases) |case| {
        var storage: HeaderStorage = undefined;
        const request = try parseRequestHead(case.head, false, &storage);
        try testing.expectEqual(case.keep_alive, request.keep_alive);
    }
}

test "http parser: bare LF line terminators are malformed" {
    // The hardened fork rejects bare LF at parse time (§7 fork gate,
    // closed); these witness the contract through the wrapper's mapping.
    try expectRequestError(error.Malformed, "GET / HTTP/1.1\nHost: a\r\n\r\n", false);
    try expectRequestError(error.Malformed, "GET / HTTP/1.1\r\nHost: a\n\r\n", false);
    try expectRequestError(error.Malformed, "GET / HTTP/1.1\r\nHost: a\r\n\n", false);
    try expectResponseError(error.Malformed, "HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n", .get);
}

test "http parser: extension methods parse with their raw token" {
    var storage: HeaderStorage = undefined;
    const request = try parseRequestHead(
        "PROPFIND /dav HTTP/1.1\r\nHost: a\r\nDepth: 1\r\n\r\n",
        false,
        &storage,
    );
    try testing.expectEqual(Method.extension, request.method);
    try testing.expectEqualStrings("PROPFIND", request.method_token);
    try testing.expectEqualStrings("/dav", request.target);
    // Origin-form is still required: extension methods get no target
    // leniency on a reverse proxy.
    try expectRequestError(
        error.Malformed,
        "M-SEARCH * HTTP/1.1\r\nHost: a\r\n\r\n",
        false,
    );
}

test "http parser: request targets must be origin-form (or OPTIONS *)" {
    // Absolute-form belongs to forward proxies.
    try expectRequestError(
        error.Malformed,
        "GET http://other/ HTTP/1.1\r\nHost: a\r\n\r\n",
        false,
    );
    try expectRequestError(error.Malformed, "GET * HTTP/1.1\r\nHost: a\r\n\r\n", false);
    var storage: HeaderStorage = undefined;
    const options = try parseRequestHead("OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n", false, &storage);
    try testing.expectEqualStrings("*", options.target);
    // CONNECT's authority-form parses so the proxy can answer 501 itself.
    const connect = try parseRequestHead(
        "CONNECT origin:443 HTTP/1.1\r\nHost: origin\r\n\r\n",
        false,
        &storage,
    );
    try testing.expectEqual(Method.connect, connect.method);
}

test "http parser: partial heads are Incomplete until the buffer fills" {
    try expectRequestError(error.Incomplete, "GET / HTTP/1.1\r\nHost: a\r\n", false);
    try expectRequestError(error.Incomplete, "GET /still-in-the-request-line", false);
    // The same bytes in a full buffer become the oversize verdicts (§7):
    // request line still open → 414, header section open → 431.
    try expectRequestError(error.UriTooLong, "GET /still-in-the-request-line", true);
    try expectRequestError(error.HeadTooLarge, "GET / HTTP/1.1\r\nHost: a\r\n", true);
}

test "http parser: header-array overflow is 431-class, not 400" {
    const head = "GET / HTTP/1.1\r\nHost: a\r\n" ++ ("X-Filler: 1\r\n" ** constants.headers_max) ++ "\r\n";
    try expectRequestError(error.HeadTooLarge, head, false);
}

test "http parser: response heads frame per RFC 9112 §6.3 precedence" {
    var storage: HeaderStorage = undefined;
    const sized = try parseResponseHead(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        false,
        &storage,
        .get,
    );
    try testing.expectEqual(@as(u16, 200), sized.status);
    try testing.expectEqualStrings("OK", sized.status_message.?);
    try testing.expectEqual(BodyFraming{ .content_length = 2 }, sized.framing);
    try testing.expect(sized.keep_alive);

    const chunked = try parseResponseHead(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        false,
        &storage,
        .get,
    );
    try testing.expectEqual(BodyFraming.chunked, chunked.framing);

    // No framing headers at all: the body runs to close, reuse is off.
    const unframed = try parseResponseHead("HTTP/1.1 200 OK\r\n\r\n", false, &storage, .get);
    try testing.expectEqual(BodyFraming.until_close, unframed.framing);
    try testing.expect(!unframed.keep_alive);

    // Chunked-not-final also runs to close (RFC 9112 §6.3 item 4).
    const te_other = try parseResponseHead(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        false,
        &storage,
        .get,
    );
    try testing.expectEqual(BodyFraming.until_close, te_other.framing);
    try testing.expect(!te_other.keep_alive);
}

test "http parser: bodiless statuses and HEAD ignore framing headers" {
    var storage: HeaderStorage = undefined;
    const head_response = try parseResponseHead(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
        false,
        &storage,
        .head,
    );
    try testing.expectEqual(BodyFraming.none, head_response.framing);
    try testing.expect(head_response.keep_alive);

    const no_content = try parseResponseHead("HTTP/1.1 204 No Content\r\n\r\n", false, &storage, .get);
    try testing.expectEqual(BodyFraming.none, no_content.framing);
    try testing.expect(no_content.keep_alive);

    const informational = try parseResponseHead("HTTP/1.1 100 Continue\r\n\r\n", false, &storage, .post);
    try testing.expectEqual(BodyFraming.none, informational.framing);
}

test "http parser: origin smuggling shapes and alien statuses tear down" {
    try expectResponseError(
        error.Malformed,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n",
        .get,
    );
    try expectResponseError(
        error.Malformed,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n",
        .get,
    );
    try expectResponseError(error.Malformed, "HTTP/1.1 099 Weird\r\n\r\n", .get);
    try expectResponseError(error.Malformed, "HTTP/1.1 600 Weird\r\n\r\n", .get);
}

test "http parser: header helpers are case-insensitive" {
    const headers = [_]Header{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "Upgrade", .value = "h2c" },
    };
    try testing.expectEqualStrings("h2c", headerValue(&headers, "upgrade").?);
    try testing.expectEqual(@as(?[]const u8, null), headerValue(&headers, "host"));
    try testing.expect(tokenListHas(" Keep-Alive , Close", "close"));
    try testing.expect(tokenListHas("close", "CLOSE"));
    try testing.expect(!tokenListHas("closed", "close"));
    try testing.expect(!tokenListHas("", "close"));
}

// Chunked-scanner tests drive `feed` through `chunkedOutcome`, the same
// harness the fuzz oracle uses, so unit cases and fuzz share semantics.

const ChunkedOutcome = struct {
    consumed: u64,
    done: bool,
    failure: ?ChunkedScanner.Error,
};

/// Feeds `input` in pieces of at most `feed_bytes_max` and reports the
/// aggregate outcome. Split-invariance of `ChunkedScanner` means the
/// result must not depend on `feed_bytes_max`.
fn chunkedOutcome(input: []const u8, feed_bytes_max: usize) ChunkedOutcome {
    assert(feed_bytes_max >= 1);
    var scanner = ChunkedScanner{};
    var outcome = ChunkedOutcome{ .consumed = 0, .done = false, .failure = null };
    var offset: usize = 0;
    while (offset < input.len) {
        const end = @min(input.len, offset + feed_bytes_max);
        const progress = scanner.feed(input[offset..end]) catch |err| {
            outcome.failure = err;
            return outcome;
        };
        assert(progress.consumed >= 1);
        outcome.consumed += progress.consumed;
        offset += progress.consumed;
        if (progress.done) {
            outcome.done = true;
            return outcome;
        }
        // feed() consumes its whole slice unless the message ended.
        assert(offset == end);
    }
    return outcome;
}

test "chunked: a simple body scans to done at every split size" {
    const body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    for ([_]usize{ 1, 2, 3, 5, body.len }) |feed_bytes_max| {
        const outcome = chunkedOutcome(body, feed_bytes_max);
        try testing.expectEqual(@as(?ChunkedScanner.Error, null), outcome.failure);
        try testing.expect(outcome.done);
        try testing.expectEqual(@as(u64, body.len), outcome.consumed);
    }
}

test "chunked: extensions and trailers are forwarded, bounded, and end cleanly" {
    const body = "5;name=value\r\nhello\r\n0\r\nX-Trailer: yes\r\n\r\n";
    for ([_]usize{ 1, body.len }) |feed_bytes_max| {
        const outcome = chunkedOutcome(body, feed_bytes_max);
        try testing.expectEqual(@as(?ChunkedScanner.Error, null), outcome.failure);
        try testing.expect(outcome.done);
        try testing.expectEqual(@as(u64, body.len), outcome.consumed);
    }
}

test "chunked: pipelined bytes after the terminator are left unconsumed" {
    const body = "1\r\na\r\n0\r\n\r\n";
    const stream = body ++ "GET";
    const outcome = chunkedOutcome(stream, stream.len);
    try testing.expect(outcome.done);
    try testing.expectEqual(@as(u64, body.len), outcome.consumed);
}

test "chunked: framing violations are malformed" {
    const malformed_cases = [_][]const u8{
        "\r\n", // no size digit at all
        "g\r\n", // not a hex digit
        ";ext\r\n", // extension before any digit
        "5\nhello\r\n0\r\n\r\n", // bare LF after size
        "5\r\nhelloX\r\n0\r\n\r\n", // chunk data not followed by CR
        "5\r\nhello\rX0\r\n\r\n", // CR not followed by LF
        "0\r\nX-T: v\n\r\n", // bare LF inside trailer
        "0\r\n\rX", // final CR not followed by LF
    };
    for (malformed_cases) |case| {
        const outcome = chunkedOutcome(case, case.len);
        try testing.expectEqual(@as(?ChunkedScanner.Error, error.Malformed), outcome.failure);
    }
}

test "chunked: size lines and trailers hit their static bounds" {
    // A size line longer than the bound (extensions included).
    const long_line = "1;" ++ ("e" ** constants.chunked_line_bytes_max) ++ "\r\na\r\n0\r\n\r\n";
    try testing.expectEqual(
        @as(?ChunkedScanner.Error, error.Oversize),
        chunkedOutcome(long_line, long_line.len).failure,
    );
    // A chunk size that would overflow u64 (17 hex digits).
    const huge_size = "11111111111111111\r\n";
    try testing.expectEqual(
        @as(?ChunkedScanner.Error, error.Oversize),
        chunkedOutcome(huge_size, huge_size.len).failure,
    );
    // A trailer section past its bound.
    const trailer_line = "X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
    const repeats = constants.chunked_trailer_bytes_max / trailer_line.len + 1;
    const long_trailer = "0\r\n" ++ (trailer_line ** repeats) ++ "\r\n";
    try testing.expectEqual(
        @as(?ChunkedScanner.Error, error.Oversize),
        chunkedOutcome(long_trailer, long_trailer.len).failure,
    );
}

// Fuzzing (§9 gate 2): arbitrary bytes through the wrapper — parse or
// reject with no third outcome, every returned slice inside the input,
// and chunked scanning invariant under how the input is split.

fn sliceWithin(outer: []const u8, inner: []const u8) bool {
    const outer_start = @intFromPtr(outer.ptr);
    const inner_start = @intFromPtr(inner.ptr);
    return inner_start >= outer_start and
        inner_start + inner.len <= outer_start + outer.len;
}

fn checkRequestParse(input: []const u8, head_is_full: bool) void {
    var storage: HeaderStorage = undefined;
    const request = parseRequestHead(input, head_is_full, &storage) catch return;
    assert(request.head_len >= 1);
    assert(request.head_len <= input.len);
    assert(sliceWithin(input, request.target));
    assert(request.target.len >= 1);
    assert(sliceWithin(input, request.method_token));
    assert(request.method_token.len >= 1);
    if (request.host) |host| {
        assert(host.len >= 1);
        assert(sliceWithin(input, host));
    }
    if (request.version == .http_1_1) {
        assert(request.host != null);
    }
    for (request.headers) |header| {
        assert(header.name.len >= 1);
        assert(sliceWithin(input, header.name));
        assert(sliceWithin(input, header.value));
    }
    assert(request.framing != .until_close);
}

fn checkResponseParse(input: []const u8, head_is_full: bool) void {
    var storage: HeaderStorage = undefined;
    const response = parseResponseHead(input, head_is_full, &storage, .get) catch return;
    assert(response.head_len >= 1);
    assert(response.head_len <= input.len);
    assert(response.status >= 100);
    assert(response.status <= 599);
    if (response.status_message) |message| {
        assert(sliceWithin(input, message));
    }
    for (response.headers) |header| {
        assert(header.name.len >= 1);
        assert(sliceWithin(input, header.name));
        assert(sliceWithin(input, header.value));
    }
    if (response.framing == .until_close) {
        assert(!response.keep_alive);
    }
}

const fuzz_corpus_request = "POST /submit HTTP/1.1\r\nHost: origin\r\nContent-Length: 5\r\n\r\nhello";
const fuzz_corpus_extension = "PROPFIND /dav HTTP/1.1\r\nHost: origin\r\nDepth: 1\r\n\r\n";
const fuzz_corpus_response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
const fuzz_corpus_chunked = "5\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n";

test "fuzz: heads and chunked framing — parse or reject, no third outcome" {
    try std.testing.fuzz({}, fuzzParserInputs, .{
        .corpus = &.{
            fuzz_corpus_request,
            fuzz_corpus_extension,
            fuzz_corpus_response,
            fuzz_corpus_chunked,
        },
    });
}

fn fuzzParserInputs(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input_buffer: [constants.head_bytes_max]u8 = undefined;
    const input_len = smith.slice(&input_buffer);
    assert(input_len <= input_buffer.len);
    const input = input_buffer[0..input_len];

    checkRequestParse(input, false);
    checkResponseParse(input, false);
    if (input.len >= 1) {
        checkRequestParse(input, true);
        checkResponseParse(input, true);
    }

    // Split-invariance oracle: whole-buffer and byte-at-a-time feeding
    // must agree — the relay feeds recv-sized pieces, the peer picks the
    // split, and the verdict may depend on neither. Consumed counts are
    // only comparable on success: a failing feed() call reports no
    // partial progress (the connection is torn down regardless), so the
    // pre-failure tally is inherently split-dependent.
    const whole = chunkedOutcome(input, @max(input.len, 1));
    const bytewise = chunkedOutcome(input, 1);
    assert((whole.failure == null) == (bytewise.failure == null));
    if (whole.failure) |failure| {
        assert(failure == bytewise.failure.?);
    } else {
        assert(whole.consumed == bytewise.consumed);
        assert(whole.done == bytewise.done);
    }
}
