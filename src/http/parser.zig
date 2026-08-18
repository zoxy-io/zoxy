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
//! `limits.head_buffer_bytes`.
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

/// The header names a §7 decision keys off: the connection-specific set
/// that is never forwarded, the set a Connection header may not nominate
/// away, and the framing headers the analysis reads. Everything else is
/// `other`, which is almost every header on almost every request.
///
/// The point of naming them is to compare them *once*. Both the analysis
/// walk and the render walk used to re-run `std.ascii.eqlIgnoreCase` down
/// a list of literals for every header — up to four in `analyzeHeaders`
/// and the whole hop-by-hop and protected lists again in `isHopByHop`, on
/// both the request and the response head. Classifying on the walk that
/// already visits every header turns each of those into an integer test.
///
/// `render.hop_by_hop_names` and `render.protected_names` stay the
/// documented source of truth; a comptime check there pins them to
/// `hopByHop` and `protected` in both directions, so a name added to one
/// spelling and not the other fails the build rather than opening a §7
/// hole.
pub const HeaderName = enum(u8) {
    /// Any name no §7 decision special-cases.
    other,
    host,
    content_length,
    transfer_encoding,
    connection,
    keep_alive,
    proxy_connection,
    te,
    upgrade,
    /// Named so the §7 forwarded-address render can suppress inbound
    /// copies in O(1) like every other managed header, rather than
    /// comparing this spelling against every header of every request.
    x_forwarded_for,
    /// RFC 9110 §7.6.2's hop budget, which an intermediary must check
    /// and *rewrite* rather than forward (#240). Tagged for the same
    /// reason `x_forwarded_for` is: the render suppresses the inbound
    /// copy and writes the decremented one itself, so the two spellings
    /// can never both reach the origin.
    max_forwards,

    /// Connection-specific headers (RFC 9110 §7.6.1): never forwarded.
    pub fn hopByHop(tag: HeaderName) bool {
        return switch (tag) {
            .connection, .keep_alive, .proxy_connection, .te, .upgrade => true,
            // `max_forwards` is deliberately not here. It is end-to-end —
            // it travels the whole chain — and what each hop owes it is a
            // *decrement*, not removal (#240); stripping it would tell the
            // next hop the budget was never set.
            .other, .host, .content_length, .transfer_encoding, .x_forwarded_for, .max_forwards => false,
        };
    }

    /// Headers a Connection value may not nominate away — stripping them
    /// would desynchronize framing (a smuggling vector) or unroute the
    /// request.
    pub fn protected(tag: HeaderName) bool {
        return switch (tag) {
            .host, .content_length, .transfer_encoding => true,
            // Not protected: a client nominating its own `Max-Forwards`
            // away through `Connection` is asking for the budget to be
            // dropped, which loses it nothing this proxy owes it — an
            // absent budget is one no hop has to check. It desynchronizes
            // no framing and unroutes nothing, which is what this list is
            // for. What a filter must not do to it is a different rule,
            // enforced where filters are compiled.
            .other, .connection, .keep_alive, .proxy_connection, .te, .upgrade, .x_forwarded_for, .max_forwards => false,
        };
    }

    /// The canonical lowercase spelling, so the comptime check in
    /// `render` can compare the lists against the enum both ways.
    pub fn text(tag: HeaderName) []const u8 {
        return switch (tag) {
            .other => "",
            .host => "host",
            .content_length => "content-length",
            .transfer_encoding => "transfer-encoding",
            .connection => "connection",
            .keep_alive => "keep-alive",
            .proxy_connection => "proxy-connection",
            .te => "te",
            .upgrade => "upgrade",
            .x_forwarded_for => "x-forwarded-for",
            .max_forwards => "max-forwards",
        };
    }
};

/// Classify one header name, exactly as the `eqlIgnoreCase` chains it
/// replaces would have: a variant is returned only where the old compare
/// matched. Dispatching on length first means the common `other` costs
/// one integer compare instead of a walk down every literal.
pub fn classifyHeaderName(name: []const u8) HeaderName {
    assert(name.len >= 1);
    const eql = std.ascii.eqlIgnoreCase;
    const tag: HeaderName = switch (name.len) {
        2 => if (eql(name, "te")) .te else .other,
        4 => if (eql(name, "host")) .host else .other,
        7 => if (eql(name, "upgrade")) .upgrade else .other,
        12 => if (eql(name, "max-forwards")) .max_forwards else .other,
        10 => length_10: {
            if (eql(name, "connection")) break :length_10 .connection;
            if (eql(name, "keep-alive")) break :length_10 .keep_alive;
            break :length_10 .other;
        },
        14 => if (eql(name, "content-length")) .content_length else .other,
        15 => if (eql(name, "x-forwarded-for")) .x_forwarded_for else .other,
        16 => if (eql(name, "proxy-connection")) .proxy_connection else .other,
        17 => if (eql(name, "transfer-encoding")) .transfer_encoding else .other,
        else => .other,
    };
    return tag;
}

comptime {
    // Every variant must be reachable from the length arm that matches its
    // canonical spelling: one placed in the wrong arm would simply never
    // match, silently reclassifying a real header as `other` and
    // forwarding something §7 means to strip.
    //
    // Deliberately comptime. The same check written as a runtime
    // postcondition in `classifyHeaderName` cost ~540 instructions per
    // request — it is decidable here for free, and a runtime assert on a
    // fact the compiler already knows is the expensive way to be sure.
    for (@typeInfo(HeaderName).@"enum".fields) |field| {
        const tag: HeaderName = @enumFromInt(field.value);
        if (tag == .other) continue;
        assert(classifyHeaderName(tag.text()) == tag);
    }
}

/// One parsed header. Both slices point into the head buffer the head was
/// parsed from — zero-copy, valid only while that buffer holds this head.
/// `tag` is the §7 classification, assigned once during analysis.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
    tag: HeaderName,

    /// Build one, classifying the name. `tag` carries no default and this
    /// is the only constructor on purpose: a header whose tag disagreed
    /// with its name would be stripped or forwarded against what it says
    /// it is, which is a §7 hole rather than a stale field.
    pub fn init(name: []const u8, value: []const u8) Header {
        assert(name.len >= 1);
        return .{ .name = name, .value = value, .tag = classifyHeaderName(name) };
    }
};

/// Header storage for one parsed head: the mapped headers a caller reads,
/// and the raw span hparse fills on the way to them. Nothing parsed
/// survives the callback that parsed it (§7 detect-and-retry re-parses
/// from byte 0), so one of these serves a whole parse and no more.
///
/// Both arrays live in the one aggregate so that a caller lends a single
/// buffer rather than two, and so the raw span stops being a local of
/// `parseRequestHead`/`parseResponseHead` — which is what makes the
/// serving path's long-lived scratch (`Server.header_scratch`) cover the
/// whole cost. Under ReleaseSafe an `= undefined` local is 0xaa-filled on
/// every call, and §9's flamegraph put that fill at 62% of zoxy's user
/// cycles under L7 load: ~9.2 KiB per request across the four frames a
/// keep-alive exchange parses. A cold call site may still declare one on
/// the stack; the serving path may not.
pub const HeaderStorage = struct {
    headers: [constants.headers_max]Header,
    raw: [constants.headers_max]hparse.Header,
};

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
    /// The request-target in the form §7 routes and forwards. Absolute-form
    /// is split at the trust boundary (RFC 9112 §3.2.2), so this is its
    /// origin-form remainder — "/" when the target named no path, and a
    /// bare "?query" when it named only a query. Asterisk-form and
    /// CONNECT's authority-form keep their own spelling; every other
    /// admitted target begins with '/'.
    target: []const u8,
    version: Version,
    headers: []const Header,
    /// Non-null whenever `version == .http_1_1` (exactly-one-Host is
    /// enforced); HTTP/1.0 may omit it.
    host: ?[]const u8,
    /// The authority an absolute-form request line carried, verbatim and
    /// including any port — null for every other form. It *overrides*
    /// `host`: RFC 9112 §3.2.2 has the recipient ignore the Host header
    /// field and use this instead, which `routingAuthority` states once
    /// for every consumer.
    authority: ?[]const u8,
    framing: BodyFraming,
    /// Whether the downstream connection may serve another request after
    /// this exchange, per version defaults and Connection tokens.
    keep_alive: bool,
    /// Whether a Connection token names a header to strip (§7). Carried
    /// from the analysis pass so rendering need not re-split the value.
    connection_nominates_header: bool,
    head_len: u32,

    /// The authority this request names, which is what §7 routes on and
    /// what the forwarded request must carry as its `Host` — the
    /// absolute-form's when the request line carried one, the Host
    /// header's otherwise (RFC 9112 §3.2.2: a recipient MUST ignore the
    /// received Host when the target is absolute-form). Null only when
    /// an HTTP/1.0 request named neither, which routes to any-host
    /// routes alone.
    ///
    /// One function rather than an `orelse` at each of the three call
    /// sites: the router, the filter view and the renderer must agree
    /// about which name this request gave, or the origin can be sent to
    /// a vhost the policy never saw.
    pub fn routingAuthority(request: *const RequestHead) ?[]const u8 {
        return request.authority orelse request.host;
    }
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
    /// Whether a Connection token names a header to strip (§7). Carried
    /// from the analysis pass so rendering need not re-split the value.
    connection_nominates_header: bool,
    head_len: u32,
};

/// The raw request-line outputs hparse fills, written through by pointer
/// from the caller's frame.
///
/// The header array is deliberately *not* a field here. A struct whose
/// fields carry defaults is initialized with `.{}`, and that lowers to a
/// zero-fill of the whole aggregate — an `= undefined` array field
/// included, which defeats the very point of declaring it `undefined`.
/// As a field it cost a 2080-byte memset on every request — 35% of
/// zoxy's user CPU under L7 load, the top symbol in the profile; as a
/// loose local it costs nothing. `parseResponseHead` has always kept its
/// header array loose for this reason, and measured zero.
const RawRequest = struct {
    method: hparse.Method = .unknown,
    method_token: ?[]const u8 = null,
    target: ?[]const u8 = null,
    version: hparse.Version = .@"1.0",
    header_count: usize = 0,
};

/// Runs hparse over the request line and headers, mapping its verdicts
/// to head errors (§7): a head that cannot complete inside a full buffer
/// is oversize, not partial (request line still open → 414, else 431);
/// Invalid is malformed; a full header array is load, not malice.
fn parseRequestRaw(
    head: []const u8,
    head_is_full: bool,
    raw: *RawRequest,
    raw_headers: *[constants.headers_max]hparse.Header,
) HeadError!u32 {
    const head_len = hparse.parseRequest(
        head,
        &raw.method,
        &raw.method_token,
        &raw.target,
        &raw.version,
        raw_headers,
        &raw.header_count,
    ) catch |err| switch (err) {
        error.Incomplete => {
            if (head_is_full) {
                return oversizeRequestError(head);
            }
            return error.Incomplete;
        },
        error.Invalid => return error.Malformed,
        error.TooManyHeaders => return error.HeadTooLarge,
    };
    assert(head_len >= 1);
    assert(head_len <= head.len);
    assert(raw.header_count <= constants.headers_max);
    return @intCast(head_len);
}

/// Parses and validates one request head from `head`. `head_is_full` says
/// the head buffer has no room left, turning a partial parse into the 414
/// vs 431 oversize verdict instead of `error.Incomplete` (§7, §8).
pub fn parseRequestHead(
    head: []const u8,
    head_is_full: bool,
    headers_storage: *HeaderStorage,
) HeadError!RequestHead {
    assert(head.len <= constants.head_buffer_bytes_max);
    if (head_is_full) {
        assert(head.len >= 1);
    }

    var raw: RawRequest = .{};
    const head_len = try parseRequestRaw(head, head_is_full, &raw, &headers_storage.raw);

    const target = raw.target.?; // A successful parse always sets the target.
    const method_token = raw.method_token.?; // Same contract as the target.
    assert(method_token.len >= 1);
    const method = methodFromRaw(raw.method);
    const split = try validateTarget(target, method);
    const version = versionFromRaw(raw.version);

    const analysis = try analyzeHeaders(raw.header_count, headers_storage);
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
        .target = split.target,
        .version = version,
        .headers = headers_storage.headers[0..raw.header_count],
        .host = analysis.host,
        .authority = split.authority,
        .framing = framing,
        .keep_alive = keepAliveDefault(version, &analysis),
        .connection_nominates_header = analysis.connection_nominates_header,
        .head_len = head_len,
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
    assert(head.len <= constants.head_buffer_bytes_max);
    // The proxy rejects CONNECT before dialing (§7 keeps tunnels out), so
    // a CONNECT response is unrepresentable here.
    assert(request_method != .connect);

    var raw_version: hparse.Version = .@"1.0";
    var raw_status: u16 = 0;
    var raw_status_message: ?[]const u8 = null;
    var raw_header_count: usize = 0;
    const head_len = hparse.parseResponse(
        head,
        &raw_version,
        &raw_status,
        &raw_status_message,
        &headers_storage.raw,
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

    const analysis = try analyzeHeaders(raw_header_count, headers_storage);
    const framing = try responseFraming(request_method, raw_status, version, &analysis);

    return .{
        .status = raw_status,
        .status_message = raw_status_message,
        .version = version,
        .headers = headers_storage.headers[0..raw_header_count],
        .framing = framing,
        .keep_alive = keepAliveDefault(version, &analysis) and framing != .until_close,
        .connection_nominates_header = analysis.connection_nominates_header,
        .head_len = @intCast(head_len),
    };
}

/// One past the longest name `HeaderName` spells. That "one past" is what
/// makes a truncated trailer name safe to classify: a name that fills the
/// buffer is already longer than every managed spelling, so it and the
/// prefix kept for it both classify `.other` — the same answer, which is
/// why no "this name was truncated" flag is needed anywhere.
const trailer_name_bytes_max: u8 = trailer_name_bytes: {
    var longest: u8 = 0;
    for (@typeInfo(HeaderName).@"enum".fields) |field| {
        const tag: HeaderName = @enumFromInt(field.value);
        longest = @max(longest, tag.text().len);
    }
    break :trailer_name_bytes longest + 1;
};

comptime {
    // The property above, said where a reviewer can check it: every
    // managed spelling fits with a byte to spare, so "the buffer filled"
    // and "longer than any managed name" are the same statement.
    for (@typeInfo(HeaderName).@"enum".fields) |field| {
        const tag: HeaderName = @enumFromInt(field.value);
        assert(tag.text().len < trailer_name_bytes_max);
    }
}

/// Incremental delimiter for chunked bodies (RFC 9112 §7.1) relayed
/// verbatim: zoxy forwards the encoded bytes untouched and only needs to
/// know where the message ends, so this scanner validates framing and
/// counts — it never decodes or copies. Feed it the exact bytes that will
/// be forwarded, in any split; whole-buffer and byte-at-a-time feeding
/// reach identical outcomes. CRLF-strict everywhere: a bare LF anywhere in
/// the framing is malformed (§7's smuggling posture).
///
/// The trailer section is held to `trailer-section = *( field-line CRLF )`
/// (RFC 9112 §7.1.2) rather than scanned as bytes, and a field naming a
/// header §7 decides is refused (#244). Both halves are here, in the one
/// place both directions share, because the relay forwards a *prefix* of
/// what it consumed — there is no seam at which a trailer could be
/// stripped instead.
pub const ChunkedScanner = struct {
    state: State = .size,
    /// Chunk-data bytes still to pass through in the current chunk.
    data_remaining: u64 = 0,
    /// Payload bytes this message has carried so far, across every chunk
    /// (#236). Distinct from the wire bytes the caller feeds: sizes,
    /// extensions, terminators and trailers are framing, not body, and a
    /// documented byte limit that counted them would refuse a body under
    /// its own cap. The only running total either framing keeps — a
    /// `Content-Length` body is bounded by a number the head already
    /// declared, and needs none.
    body_bytes: u64 = 0,
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
    /// The trailer field name being read, kept only as far as
    /// `trailer_name_bytes_max` reaches. Reset at each field, so no name
    /// can carry into the next one.
    name_bytes: [trailer_name_bytes_max]u8 = undefined,
    name_len: u8 = 0,

    pub const State = enum(u8) {
        size,
        extension,
        size_lf,
        data,
        data_cr,
        data_lf,
        trailer_start,
        trailer_name,
        trailer_value,
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
            .trailer_start,
            .trailer_name,
            .trailer_value,
            .trailer_lf,
            .final_lf,
            => scanner.stepTrailer(bytes[0]),
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
        scanner.body_bytes += wanted;
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
                    // A trailer line starts with a field name or it ends
                    // the section; RFC 9112 §7.1.2's grammar has no third
                    // production. That is what refuses an obs-fold
                    // continuation and the empty name in `: value`.
                    if (!isTokenByte(byte)) {
                        return error.Malformed;
                    }
                    scanner.name_len = 0;
                    scanner.appendNameByte(byte);
                    scanner.state = .trailer_name;
                },
            },
            .trailer_name => switch (byte) {
                ':' => {
                    if (scanner.nameIsManaged()) {
                        return error.Malformed;
                    }
                    scanner.state = .trailer_value;
                },
                else => {
                    // A space here is `X-Bad : v`, the smuggling shape the
                    // head parser already refuses — the trailer section is
                    // held to the same syntax, not a looser one (#244).
                    if (!isTokenByte(byte)) {
                        return error.Malformed;
                    }
                    scanner.appendNameByte(byte);
                },
            },
            .trailer_value => switch (byte) {
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

    /// Keeps the trailer name as far as the buffer reaches and drops the
    /// rest, which `trailer_name_bytes_max` explains is free: the verdict
    /// on a name that long is `.other` either way.
    fn appendNameByte(scanner: *ChunkedScanner, byte: u8) void {
        assert(isTokenByte(byte));
        assert(scanner.name_len <= trailer_name_bytes_max);
        if (scanner.name_len == trailer_name_bytes_max) {
            return;
        }
        scanner.name_bytes[scanner.name_len] = byte;
        scanner.name_len += 1;
        assert(scanner.name_len <= trailer_name_bytes_max);
    }

    /// True when the trailer names a header §7 makes a decision about —
    /// protected, hop-by-hop, or one this proxy writes itself. RFC 9110
    /// §6.5.1 forbids a sender to generate any of them in a trailer (no
    /// such definition permits it), and forwarding one would hand the far
    /// side a framing, routing or address field this proxy already
    /// settled in the header section (#244).
    fn nameIsManaged(scanner: *const ChunkedScanner) bool {
        assert(scanner.name_len >= 1);
        assert(scanner.name_len <= trailer_name_bytes_max);
        return classifyHeaderName(scanner.name_bytes[0..scanner.name_len]) != .other;
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

/// The value of the named cookie in the request's Cookie header, or null
/// when the request carries none (#178). Reads the first Cookie header
/// only — RFC 6265 has user agents send exactly one — and scans its
/// `name=value` crumbs. The *name* compare is byte-exact, unlike
/// `headerValue`'s: cookie names are case-sensitive, and the only names
/// asked about are ones this proxy's own config spelled. A crumb's value
/// runs to the next `;`, so a value may contain `=` (base64 does).
pub fn cookieValue(headers: []const Header, name: []const u8) ?[]const u8 {
    assert(name.len >= 1);
    // A validated pick name is a token, so `=` cannot sit inside it and
    // split the crumb somewhere other than where this scan splits it.
    assert(std.mem.indexOfScalar(u8, name, '=') == null);
    const header = headerValue(headers, "cookie") orelse return null;
    var crumbs = std.mem.splitScalar(u8, header, ';');
    // Bounded: the iterator yields at most header.len + 1 pieces.
    while (crumbs.next()) |raw_crumb| {
        const crumb = std.mem.trim(u8, raw_crumb, " \t");
        if (crumb.len <= name.len) {
            continue;
        }
        if (crumb[name.len] != '=') {
            continue;
        }
        if (!std.mem.eql(u8, crumb[0..name.len], name)) {
            continue;
        }
        return crumb[name.len + 1 ..];
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
    /// Whether any Connection token names a header to strip, rather than
    /// only the `close`/`keep-alive` connection *options*. The render walk
    /// needs exactly this to decide whether the per-header nomination scan
    /// can be skipped, and the token pass that sets the two flags above
    /// already knows it — so it is recorded here rather than recomputed by
    /// splitting the same value a second time (§9).
    connection_nominates_header: bool,
};

/// Maps the `header_count` raw headers hparse left in `headers_storage.raw`
/// into the tagged `headers_storage.headers`, in place. The count rather
/// than a slice: both spans are fields of the one aggregate now, and
/// handing this a slice of `raw` while it writes `headers` would state an
/// aliasing relation the caller cannot check.
fn analyzeHeaders(
    header_count: usize,
    headers_storage: *HeaderStorage,
) error{Malformed}!HeaderAnalysis {
    assert(header_count <= headers_storage.headers.len);
    var analysis = HeaderAnalysis{
        .host = null,
        .content_length = null,
        .te_chunked = false,
        .te_other = false,
        .connection_close = false,
        .connection_keep_alive = false,
        .connection_nominates_header = false,
    };
    for (headers_storage.raw[0..header_count], 0..) |raw_header, index| {
        assert(raw_header.key.len >= 1);
        // The one name comparison this header will cost: every later §7
        // decision, here and in the render walk, tests the tag instead.
        const header: Header = .init(raw_header.key, raw_header.value);
        headers_storage.headers[index] = header;
        switch (header.tag) {
            .host => {
                // A second Host changes routing depending on who reads which —
                // a smuggling shape, like an empty one (RFC 9112 §3.2).
                if (analysis.host != null) {
                    return error.Malformed;
                }
                if (raw_header.value.len == 0) {
                    return error.Malformed;
                }
                analysis.host = raw_header.value;
            },
            .content_length => {
                // Duplicate Content-Length is rejected outright, identical
                // values included (§7 "duplicate/garbage Content-Length").
                if (analysis.content_length != null) {
                    return error.Malformed;
                }
                analysis.content_length = try parseDecimal(raw_header.value);
            },
            .transfer_encoding => {
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
            },
            .connection => {
                // Multiple Connection headers combine as one list (RFC 9110).
                scanConnectionTokens(raw_header.value, &analysis);
            },
            // `x_forwarded_for` and `max_forwards` join the no-analysis
            // set: their tags exist so the *render* can find them cheaply
            // (§7), and nothing about framing, routing or persistence
            // reads either here. `Max-Forwards` in particular is read
            // only for the two methods RFC 9110 §7.6.2 names, by
            // `maxForwards` below — parsing it for every request would
            // let a garbage value on a POST reject a request the spec
            // says may ignore the field entirely (#240).
            .other, .keep_alive, .proxy_connection, .te, .upgrade, .x_forwarded_for, .max_forwards => {},
        }
    }
    assert(!(analysis.te_chunked and analysis.te_other));
    if (analysis.host) |host| {
        assert(host.len >= 1);
    }
    return analysis;
}

/// Read one Connection header value in a single token pass — the
/// persistence flags *and* whether anything here nominates a header to
/// strip. Scanning the list twice (once per token) was a measured hot
/// spot (§9), and so was splitting it again in the render walk. Tokens
/// are OWS-trimmed and matched case-insensitively.
///
/// `close` and `keep-alive` are connection options, not header names —
/// `keep-alive` is itself hop-by-hop and `close` names no forwardable
/// header — so a value listing only those nominates nothing. Any other
/// token does.
fn scanConnectionTokens(value: []const u8, analysis: *HeaderAnalysis) void {
    // The value is a slice of the parsed head (an empty value is legal:
    // `Connection:` with nothing after it), so it is head-buffer bounded.
    assert(value.len <= constants.head_buffer_bytes_max);
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |raw_token| {
        const token = std.mem.trim(u8, raw_token, " \t");
        if (token.len == 0) {
            continue;
        }
        // Every non-empty token is classified below: close/keep-alive as
        // connection options, anything else as a nomination.
        assert(token.len >= 1);
        if (std.ascii.eqlIgnoreCase(token, "close")) {
            analysis.connection_close = true;
        } else if (std.ascii.eqlIgnoreCase(token, "keep-alive")) {
            analysis.connection_keep_alive = true;
        } else {
            analysis.connection_nominates_header = true;
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

/// A canonical origin-form target, split once in the trust boundary
/// (§7 path routing). `path` lives in the caller's `out` buffer; `query`
/// is the verbatim suffix of the original target — including its
/// leading `?` when present — and is opaque to the proxy.
pub const CanonicalTarget = struct {
    path: []const u8,
    query: []const u8,
};

/// The §7 canonical form: the query splits off untouched, unreserved
/// percent-escapes (RFC 3986 §2.3) are decoded and surviving escapes'
/// hex uppercased, then dot-segments are collapsed. Structure-changing
/// escapes — encoded slash, NUL, truncated or non-hex — are Malformed,
/// and so is a path that climbs above the root. Routing matches this
/// form and the renderer forwards it, so the router and the origin can
/// never disagree about which resource a request names.
///
/// The input is origin-form, or the query-only remainder an
/// absolute-form target leaves when it names no path (#233) — whose
/// empty path is the root, so the canonical form still begins with '/'.
pub fn canonicalTarget(
    target: []const u8,
    /// Caller-owned decode target, at least `target.len` wide — a slice
    /// now that head sizes are the config's (`limits.head_buffer_bytes`):
    /// the callers own buffers of that runtime size, and decoding only
    /// ever shrinks, so the length relation is the whole contract.
    out: []u8,
) error{Malformed}!CanonicalTarget {
    // validateTarget admitted only origin-form here; asterisk-form and
    // CONNECT never route by path and stay with the caller.
    assert(target.len >= 1);
    assert(target[0] == '/' or target[0] == '?');
    assert(target.len <= out.len);
    const question = std.mem.indexOfScalar(u8, target, '?');
    const raw_path = target[0 .. question orelse target.len];
    const query = target[question orelse target.len ..];
    if (raw_path.len == 0) {
        // The one target that reaches here without a path: an
        // absolute-form "http://host?q", whose empty path-abempty names
        // the root (RFC 3986 §3.3). Nothing to decode or collapse.
        assert(target[0] == '?');
        out[0] = '/';
        return .{ .path = out[0..1], .query = query };
    }
    const decoded_len = try decodeTargetPath(raw_path, out);
    const path_len = try collapseDotSegments(out[0..decoded_len]);
    // Canonicalization only ever shrinks; both stages keep the leading
    // slash, so the result is itself a valid origin-form path.
    assert(path_len >= 1);
    assert(path_len <= raw_path.len);
    assert(out[0] == '/');
    return .{ .path = out[0..path_len], .query = query };
}

/// Stage one of §7 canonicalization: percent-escapes are decoded when
/// unreserved (decoding them can never change what the path names),
/// kept with uppercased hex otherwise, and rejected when they would
/// change the path's structure — an encoded slash or NUL — or are not
/// two hex digits. Raw bytes pass through verbatim: hparse already
/// excludes controls, space, and DEL from the target charset.
fn decodeTargetPath(path: []const u8, out: []u8) error{Malformed}!u32 {
    assert(path.len >= 1);
    assert(path[0] == '/');
    assert(path.len <= out.len);
    var read: u32 = 0;
    var write: u32 = 0;
    while (read < path.len) {
        assert(write <= read);
        const byte = path[read];
        if (byte != '%') {
            out[write] = byte;
            write += 1;
            read += 1;
            continue;
        }
        if (path.len - read < 3) {
            return error.Malformed; // A truncated escape.
        }
        const high = hexNibble(path[read + 1]) orelse return error.Malformed;
        const low = hexNibble(path[read + 2]) orelse return error.Malformed;
        const value: u8 = high * 16 + low;
        if (value == 0) {
            return error.Malformed; // Encoded NUL.
        }
        if (value == '/') {
            return error.Malformed; // An encoded slash changes structure.
        }
        if (isUnreservedByte(value)) {
            out[write] = value;
            write += 1;
        } else {
            out[write] = '%';
            out[write + 1] = upperHexDigit(path[read + 1]);
            out[write + 2] = upperHexDigit(path[read + 2]);
            write += 3;
        }
        read += 3;
    }
    assert(write >= 1);
    assert(write <= path.len);
    assert(out[0] == '/');
    return write;
}

/// Stage two of §7 canonicalization, after escapes are decoded (the
/// order is the security property: `%2E%2E` must collapse exactly like
/// `..`). In-place RFC 3986 remove_dot_segments over a decoded path,
/// except stricter at the root: `..` with nothing left to pop names the
/// root's parent, which no legitimate client asks for — Malformed, not
/// the RFC's silent clamp.
fn collapseDotSegments(bytes: []u8) error{Malformed}!u32 {
    assert(bytes.len >= 1);
    assert(bytes[0] == '/');
    assert(bytes.len <= constants.head_buffer_bytes_max);
    var read: u32 = 0;
    var write: u32 = 0;
    while (read < bytes.len) {
        assert(bytes[read] == '/');
        assert(write <= read);
        var segment_end: u32 = read + 1;
        while (segment_end < bytes.len and bytes[segment_end] != '/') {
            segment_end += 1;
        }
        const segment = bytes[read + 1 .. segment_end];
        const at_end = segment_end == bytes.len;
        if (std.mem.eql(u8, segment, ".")) {
            // "/a/." is "/a/" (RFC 3986 §5.2.4): a trailing dot keeps
            // its slash; a middle one vanishes with it.
            if (at_end) {
                bytes[write] = '/';
                write += 1;
            }
        } else if (std.mem.eql(u8, segment, "..")) {
            if (write == 0) {
                return error.Malformed; // Climbs above the root.
            }
            // write > 0 implies bytes[0] == '/', so a previous slash
            // always exists.
            const previous = std.mem.lastIndexOfScalar(u8, bytes[0..write], '/').?;
            write = @intCast(previous);
            if (at_end) {
                bytes[write] = '/';
                write += 1;
            }
        } else {
            // An ordinary segment — empty included: `//a` names a
            // different resource than `/a` and is preserved (§7).
            bytes[write] = '/';
            std.mem.copyForwards(u8, bytes[write + 1 .. write + 1 + segment.len], segment);
            write += 1 + @as(u32, @intCast(segment.len));
        }
        read = segment_end;
    }
    assert(write >= 1);
    assert(bytes[0] == '/');
    return write;
}

fn hexNibble(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn upperHexDigit(byte: u8) u8 {
    assert(hexNibble(byte) != null);
    if (byte >= 'a' and byte <= 'f') {
        return byte - ('a' - 'A');
    }
    return byte;
}

/// RFC 3986 §2.3 unreserved: decoding these can never change what the
/// path names, so the canonical form always holds them raw.
fn isUnreservedByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or
        byte == '_' or byte == '~';
}

/// The §7 canonical routing form of a `Host` header value: lowercased
/// (RFC 9110 §4.2.3 host equality is case-insensitive) with the
/// authority's port stripped (a port is not part of the routing name).
/// `out` receives the lowercased bytes; the returned slice points into
/// it. Null means "unmatchable" — an empty or oversize host — which
/// meets only the any-host routes, never a match error: a Host is a
/// routing key, and a key that fits no config host simply does not match.
/// The header itself is forwarded verbatim (§7); this is the key alone.
/// Only case and port are folded; anything else (a trailing-dot FQDN,
/// say) yields a distinct key, so it can only under-match to any-host —
/// never over-match a vhost it should not reach.
pub fn canonicalHost(host: []const u8, out: *[constants.host_bytes_max]u8) ?[]const u8 {
    if (host.len == 0) {
        return null;
    }
    if (host.len > out.len) {
        return null; // Oversize: unmatchable, not malformed.
    }
    // An IPv6 literal wears brackets and its own colons, so the port (if
    // any) starts only after the ']'; a plain host has no colon before
    // its port.
    const authority_end = if (host[0] == '[')
        (std.mem.indexOfScalar(u8, host, ']') orelse return null) + 1
    else
        std.mem.indexOfScalar(u8, host, ':') orelse host.len;
    assert(authority_end <= host.len);
    if (authority_end == 0) {
        return null; // A host that is only a port (":8080") matches nothing.
    }
    for (host[0..authority_end], 0..) |byte, index| {
        out[index] = std.ascii.toLower(byte);
    }
    assert(authority_end >= 1);
    return out[0..authority_end];
}

/// What one request-target resolved to: the form §7 routes, plus the
/// authority an absolute-form one carried.
const TargetSplit = struct {
    target: []const u8,
    authority: ?[]const u8 = null,
};

/// A reverse proxy routes origin-form targets (§7 routes host/path);
/// asterisk-form is legal for OPTIONS. CONNECT's authority-form passes
/// through so the proxy can answer it with 501 rather than 400.
/// Absolute-form is split into authority and origin-form remainder here,
/// at the one boundary that sees the raw target, so nothing downstream
/// has to know the request line had two spellings (#233).
fn validateTarget(target: []const u8, method: Method) error{Malformed}!TargetSplit {
    if (target.len == 0) {
        return error.Malformed;
    }
    assert(target.len >= 1);
    if (method == .connect) {
        return .{ .target = target };
    }
    if (target[0] == '/') {
        return .{ .target = target };
    }
    if (method == .options) {
        if (std.mem.eql(u8, target, "*")) {
            return .{ .target = target };
        }
    }
    return splitAbsoluteForm(target);
}

/// The absolute-form split (RFC 9112 §3.2.2, which makes accepting the
/// form a MUST for servers): `scheme "://" authority path-abempty
/// [ "?" query ]`. Only http and https are admitted — §7 speaks those
/// two and a target naming any other scheme is a request this proxy
/// cannot honor, so it is refused at the boundary rather than routed by
/// its path alone.
///
/// The authority is returned verbatim, port included, because it becomes
/// the forwarded `Host` value; the routing key is folded from it later
/// by `canonicalHost`, exactly as a Host header's would be.
fn splitAbsoluteForm(target: []const u8) error{Malformed}!TargetSplit {
    assert(target.len >= 1);
    assert(target[0] != '/');
    const mark = std.mem.indexOf(u8, target, "://") orelse return error.Malformed;
    const scheme = target[0..mark];
    // RFC 3986 §3.1: scheme comparison is case-insensitive.
    const known = std.ascii.eqlIgnoreCase(scheme, "http") or
        std.ascii.eqlIgnoreCase(scheme, "https");
    if (!known) {
        return error.Malformed;
    }
    const rest = target[mark + 3 ..];
    const authority_end = std.mem.indexOfAny(u8, rest, "/?") orelse rest.len;
    const authority = rest[0..authority_end];
    if (authority.len == 0) {
        return error.Malformed; // A scheme naming no host routes nowhere.
    }
    if (!authorityIsWellFormed(authority)) {
        return error.Malformed;
    }
    const remainder = rest[authority_end..];
    return .{
        // "http://host" names the root, and the origin-form request line
        // this proxy forwards must say so (RFC 9112 §3.2.1). A remainder
        // that is only a query keeps its leading '?' — it cannot be given
        // a '/' without a buffer to build one in, so `canonicalTarget`
        // reads the empty path as the root instead.
        .target = if (remainder.len == 0) "/" else remainder,
        .authority = authority,
    };
}

/// Whether an absolute-form authority is one this proxy will both route
/// on and write back out as a `Host` line: a positive charset — RFC 3986
/// reg-name, IP-literal brackets, percent-escapes and the port colon.
///
/// Positive rather than a list of rejects because these bytes are
/// *emitted*, not just matched: hparse's target charset already excludes
/// CR, LF and controls, and this closes the rest of the gap. It also
/// settles two cases by construction — a userinfo prefix ("user@host",
/// which RFC 9110 §4.2.1 forbids a sender from generating) and a
/// fragment, neither of which belongs in a request-target.
///
/// A charset, deliberately, and not the RFC 3986 host grammar: `a:b:c%zz`
/// passes here despite being no host at all. That is the same latitude
/// `canonicalHost` already takes with a `Host` header — an authority is a
/// routing *key*, and a key that spells nothing matches no configured
/// host, so it reaches the any-host routes and no further. What the
/// charset is for is the byte-level guarantee the grammar would not add:
/// these bytes are written into a header line.
fn authorityIsWellFormed(authority: []const u8) bool {
    assert(authority.len >= 1);
    for (authority) |byte| {
        if (std.ascii.isAlphanumeric(byte)) {
            continue;
        }
        switch (byte) {
            '-', '.', '_', '~', '%', ':', '[', ']' => {},
            else => return false,
        }
    }
    return true;
}

/// What a request's `Max-Forwards` says, for the two methods RFC 9110
/// §7.6.2 binds an intermediary on (#240).
///
/// `absent` is the common case and the one every other method takes: the
/// field MAY be ignored elsewhere, so it is read here rather than during
/// header analysis — a garbage value on a POST must not reject a request
/// the spec never asked this proxy to look at.
///
/// `malformed` is a value that is not 1*DIGIT, or a second header of the
/// same name. The RFC does not say what to do with either, and this
/// proxy answers the way it answers every other unparseable field it
/// *does* read: a `400`, rather than a guess about which of two budgets
/// the client meant.
pub const MaxForwards = union(enum) {
    absent,
    malformed,
    hops: u64,
};

pub fn maxForwards(headers: []const Header) MaxForwards {
    assert(headers.len <= constants.headers_max);
    var found: ?u64 = null;
    for (headers) |header| {
        if (header.tag != .max_forwards) {
            continue;
        }
        if (found != null) {
            return .malformed; // Two budgets are no budget.
        }
        found = parseDecimal(header.value) catch return .malformed;
    }
    const hops = found orelse return .absent;
    // The grammar's whole range, restated where the value leaves the
    // parser: `parseDecimal` admits at most nineteen digits, and the
    // decrement downstream renders back into a slot sized for exactly
    // that. A budget wider than the grammar would overrun it.
    assert(hops < 10_000_000_000_000_000_000);
    return .{ .hops = hops };
}

/// 1*DIGIT: digits only — no sign, no whitespace, no comma list. 19
/// digits bound the value below 10^19 < 2^64, so the accumulation cannot
/// overflow.
///
/// One parser for the two fields that share the grammar: `Content-Length`
/// (RFC 9112 §6.2) and `Max-Forwards` (RFC 9110 §7.6.2). They are read at
/// different times and mean different things, but a second copy of this
/// would be a second chance to disagree about what a digit is.
fn parseDecimal(value: []const u8) error{Malformed}!u64 {
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

/// The registered method for an uppercase token, or null for anything
/// unregistered. HTTP methods are case-sensitive (RFC 9110 §9.1), so only
/// the canonical uppercase spelling matches — filters name registered
/// methods this way; an extension method (`.extension`) is not selectable
/// by token here (§7).
const method_table = .{
    .{ "GET", Method.get },         .{ "POST", Method.post },
    .{ "HEAD", Method.head },       .{ "PUT", Method.put },
    .{ "DELETE", Method.delete },   .{ "CONNECT", Method.connect },
    .{ "OPTIONS", Method.options }, .{ "TRACE", Method.trace },
    .{ "PATCH", Method.patch },
};

/// The methods this proxy will carry, as an `Allow` field value (RFC 9110
/// §10.2.1) — every registered method except the two §7 answers itself:
/// CONNECT, a §1 non-goal, and TRACE, refused as the Cross-Site Tracing
/// vector (#240). Built from the same table `methodFromToken` reads, so a
/// method added there is advertised here without a second list to keep in
/// step.
///
/// It describes *this hop*, which is the only thing a final-recipient
/// answer is entitled to describe. An extension method still forwards —
/// §7 carries whatever token it was given — so this is what the proxy
/// supports by name, not the whole of what it will pass along.
pub const allow_value = blk: {
    var value: []const u8 = "";
    for (method_table) |entry| {
        if (entry[1] == .connect or entry[1] == .trace) {
            continue;
        }
        value = if (value.len == 0) entry[0] else value ++ ", " ++ entry[0];
    }
    const frozen = value;
    break :blk frozen;
};

comptime {
    // The advertised set is the registered set minus the two refusals —
    // said as a count, so a method added to the table without a decision
    // about whether this hop offers it fails here rather than silently
    // appearing in, or vanishing from, what clients are told.
    var offered: u32 = 0;
    for (method_table) |entry| {
        if (entry[1] != .connect and entry[1] != .trace) offered += 1;
    }
    assert(offered == method_table.len - 2);
    assert(allow_value.len >= 1);
}

pub fn methodFromToken(token: []const u8) ?Method {
    inline for (method_table) |entry| {
        if (std.mem.eql(u8, token, entry[0])) {
            return entry[1];
        }
    }
    return null;
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

/// True for a byte legal in a forwarded field-value (RFC 9110): VCHAR, SP,
/// HTAB, or obs-text — never CR, LF, NUL, or another control. Public so the
/// filter config compiler validates edit values against the exact set the
/// parser enforces, one definition for both.
pub fn isForwardableByte(byte: u8) bool {
    return byte == '\t' or (byte >= ' ' and byte != 0x7f);
}

/// True for a byte legal in an RFC 9110 token — a field name, a method, a
/// `Connection` nomination. Public for the same reason
/// `isForwardableByte` is: the config compiler validates the names an
/// operator writes against the exact set the parser enforces on the wire,
/// one definition for both.
pub fn isTokenByte(byte: u8) bool {
    return switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'a'...'z', 'A'...'Z' => true,
        else => false,
    };
}

fn hexDigitValue(byte: u8) u4 {
    return @intCast(hexNibble(byte) orelse unreachable); // Caller matched a hex digit.
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

test "http parser: request targets are origin-form, OPTIONS *, or absolute-form" {
    try expectRequestError(error.Malformed, "GET * HTTP/1.1\r\nHost: a\r\n\r\n", false);
    var storage: HeaderStorage = undefined;
    const options = try parseRequestHead("OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n", false, &storage);
    try testing.expectEqualStrings("*", options.target);
    try testing.expectEqual(@as(?[]const u8, null), options.authority);
    // CONNECT's authority-form parses so the proxy can answer 501 itself,
    // and is not an absolute-form authority: it names a tunnel endpoint,
    // not the resource's origin.
    const connect = try parseRequestHead(
        "CONNECT origin:443 HTTP/1.1\r\nHost: origin\r\n\r\n",
        false,
        &storage,
    );
    try testing.expectEqual(Method.connect, connect.method);
    try testing.expectEqual(@as(?[]const u8, null), connect.authority);
}

test "http parser: absolute-form splits into authority and origin-form" {
    const Case = struct {
        line: []const u8,
        /// null means Malformed — the whole head is rejected.
        authority: ?[]const u8,
        target: []const u8 = "",
    };
    const cases = [_]Case{
        // The form RFC 9112 §3.2.2 makes a MUST, with and without a path.
        .{ .line = "GET http://api.example/v2/x", .authority = "api.example", .target = "/v2/x" },
        .{ .line = "GET https://api.example/v2/x", .authority = "api.example", .target = "/v2/x" },
        .{ .line = "GET http://api.example/", .authority = "api.example", .target = "/" },
        // An empty path names the root; the forwarded request line must
        // say "/" rather than nothing at all.
        .{ .line = "GET http://api.example", .authority = "api.example", .target = "/" },
        // A query with no path keeps its '?' — canonicalTarget reads the
        // empty path as the root, which is where the '/' appears.
        .{ .line = "GET http://api.example?q=1", .authority = "api.example", .target = "?q=1" },
        .{ .line = "GET http://api.example/a?q=1", .authority = "api.example", .target = "/a?q=1" },
        // A port travels with the authority: it is the Host value to be.
        .{ .line = "GET http://api.example:8080/x", .authority = "api.example:8080", .target = "/x" },
        // Case is the scheme's own business (RFC 3986 §3.1); the
        // authority's case is folded later, by the same `canonicalHost`
        // a Host header goes through.
        .{ .line = "GET HTTP://API.Example/x", .authority = "API.Example", .target = "/x" },
        // An IPv6 literal wears brackets and colons.
        .{ .line = "GET http://[2001:db8::1]:80/x", .authority = "[2001:db8::1]:80", .target = "/x" },
        // Rejects. A scheme §7 does not speak, whatever its path says.
        .{ .line = "GET ftp://files.example/x", .authority = null },
        .{ .line = "GET gopher://files.example/x", .authority = null },
        // A scheme with no authority routes nowhere.
        .{ .line = "GET http:///x", .authority = null },
        .{ .line = "GET http://", .authority = null },
        // Userinfo (RFC 9110 §4.2.1 forbids generating it) and a fragment
        // (no request-target carries one) both fall out of the charset.
        .{ .line = "GET http://user@api.example/x", .authority = null },
        .{ .line = "GET http://api.example#frag", .authority = null },
        // Not absolute-form at all, and not any other admitted form.
        .{ .line = "GET api.example/x", .authority = null },
        .{ .line = "GET //api.example/x", .authority = null, .target = "//api.example/x" },
    };
    for (cases) |case| {
        var storage: HeaderStorage = undefined;
        var buffer: [256]u8 = undefined;
        const head = try std.fmt.bufPrint(
            &buffer,
            "{s} HTTP/1.1\r\nHost: sent-by-the-client\r\n\r\n",
            .{case.line},
        );
        const parsed = parseRequestHead(head, false, &storage) catch |err| {
            try testing.expectEqual(@as(?[]const u8, null), case.authority);
            try testing.expectEqual(HeadError.Malformed, err);
            continue;
        };
        // "//api.example/x" is origin-form with an empty first segment:
        // admitted, no authority, and it routes by path like any other.
        if (case.authority) |authority| {
            try testing.expectEqualStrings(authority, parsed.authority.?);
            try testing.expectEqualStrings(authority, parsed.routingAuthority().?);
        } else {
            try testing.expectEqual(@as(?[]const u8, null), parsed.authority);
            try testing.expectEqualStrings("sent-by-the-client", parsed.routingAuthority().?);
        }
        try testing.expectEqualStrings(case.target, parsed.target);
    }
}

test "http parser: an absolute-form request still needs its Host on HTTP/1.1" {
    // The authority overrides the Host for routing, but RFC 9112 §3.2's
    // "a client MUST send a Host in every HTTP/1.1 request" is a separate
    // rule and this proxy still holds the client to it.
    try expectRequestError(error.Malformed, "GET http://api.example/x HTTP/1.1\r\n\r\n", false);
    var storage: HeaderStorage = undefined;
    // HTTP/1.0 may omit it, and then the authority is the only name given.
    const parsed = try parseRequestHead("GET http://api.example/x HTTP/1.0\r\n\r\n", false, &storage);
    try testing.expectEqual(@as(?[]const u8, null), parsed.host);
    try testing.expectEqualStrings("api.example", parsed.routingAuthority().?);
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
        Header.init("Content-Type", "text/plain"),
        Header.init("Upgrade", "h2c"),
    };
    try testing.expectEqualStrings("h2c", headerValue(&headers, "upgrade").?);
    try testing.expectEqual(@as(?[]const u8, null), headerValue(&headers, "host"));
    try testing.expect(tokenListHas(" Keep-Alive , Close", "close"));
    try testing.expect(tokenListHas("close", "CLOSE"));
    try testing.expect(!tokenListHas("closed", "close"));
    try testing.expect(!tokenListHas("", "close"));
}

test "http parser: cookieValue finds its crumb, byte-exactly" {
    const headers = [_]Header{
        Header.init("Host", "example"),
        Header.init("Cookie", "theme=dark; zoxy-srv=0123456789abcdef; b=1"),
    };
    try testing.expectEqualStrings(
        "0123456789abcdef",
        cookieValue(&headers, "zoxy-srv").?,
    );
    try testing.expectEqualStrings("dark", cookieValue(&headers, "theme").?);
    try testing.expectEqualStrings("1", cookieValue(&headers, "b").?);
    // Cookie *names* are case-sensitive (the header name is not): a
    // differently-cased crumb is a different cookie, RFC 6265's rule.
    try testing.expectEqual(@as(?[]const u8, null), cookieValue(&headers, "ZOXY-SRV"));
    try testing.expectEqual(@as(?[]const u8, null), cookieValue(&headers, "zoxy"));
    try testing.expectEqual(@as(?[]const u8, null), cookieValue(&headers, "srv"));

    // A value may contain `=` (base64 padding does); the crumb runs to
    // the `;`, so only the first `=` after the name splits.
    const padded = [_]Header{Header.init("cookie", "s=YWJjZA==;t=x")};
    try testing.expectEqualStrings("YWJjZA==", cookieValue(&padded, "s").?);
    try testing.expectEqualStrings("x", cookieValue(&padded, "t").?);

    // No Cookie header, an empty value, and a value-less crumb.
    const bare = [_]Header{Header.init("Host", "example")};
    try testing.expectEqual(@as(?[]const u8, null), cookieValue(&bare, "zoxy-srv"));
    const empty = [_]Header{Header.init("Cookie", "zoxy-srv=; other=1")};
    try testing.expectEqualStrings("", cookieValue(&empty, "zoxy-srv").?);
    const nameless = [_]Header{Header.init("Cookie", "zoxy-srv")};
    try testing.expectEqual(@as(?[]const u8, null), cookieValue(&nameless, "zoxy-srv"));
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

test "chunked: a trailer naming a header §7 decides is refused (#244)" {
    // Every managed name, in a spelling no header-section rule would let
    // a client choose either: `Connection` may not nominate the protected
    // three away, a filter edit may not name them, and the render writes
    // `X-Forwarded-For` and `Max-Forwards` itself. A trailer was the one
    // path to the far side that checked none of it.
    const names = [_][]const u8{
        "Content-Length",
        "transfer-encoding", // Case is not a way around it.
        "Host",
        "Connection",
        "Keep-Alive",
        "Proxy-Connection",
        "TE",
        "Upgrade",
        "X-Forwarded-For",
        "Max-Forwards",
    };
    inline for (names) |name| {
        const body = "0\r\n" ++ name ++ ": v\r\n\r\n";
        for ([_]usize{ 1, body.len }) |feed_bytes_max| {
            const outcome = chunkedOutcome(body, feed_bytes_max);
            try testing.expectEqual(
                @as(?ChunkedScanner.Error, error.Malformed),
                outcome.failure,
            );
        }
    }
}

test "chunked: a trailer field is held to the header field's syntax (#244)" {
    const refused = [_][]const u8{
        "0\r\nX-Bad : v\r\n\r\n", // Space before the colon.
        "0\r\nX-Bad\t: v\r\n\r\n", // …and the tab spelling of it.
        "0\r\nnocolon\r\n\r\n", // Not a field-line at all.
        "0\r\n: novalue\r\n\r\n", // An empty field name.
        "0\r\n X-Fold: v\r\n\r\n", // An obs-fold continuation.
        "0\r\nX(Bad): v\r\n\r\n", // A non-token byte in the name.
    };
    for (refused) |body| {
        for ([_]usize{ 1, body.len }) |feed_bytes_max| {
            const outcome = chunkedOutcome(body, feed_bytes_max);
            try testing.expectEqual(
                @as(?ChunkedScanner.Error, error.Malformed),
                outcome.failure,
            );
        }
    }
}

test "chunked: an ordinary trailer still forwards, however long its name (#244)" {
    // The right-hand case is what `trailer_name_bytes_max` is for: a name
    // past the buffer keeps only a prefix, and the prefix must classify
    // `.other` exactly as the whole name does — a truncation that could
    // collide with a managed spelling would refuse a legal trailer.
    const long_name = "X-" ++ ("a" ** (trailer_name_bytes_max * 2));
    const bodies = [_][]const u8{
        "0\r\nX-Checksum: 3f21\r\n\r\n",
        "0\r\nX-Checksum: 3f21\r\nX-Signature: ab\r\n\r\n",
        "0\r\nX-Empty:\r\n\r\n",
        "0\r\n" ++ long_name ++ ": v\r\n\r\n",
        // The managed names are the whole names, not substrings of them:
        // a longer name that merely starts with one is nobody's framing.
        "0\r\nContent-Length-Hint: 9\r\n\r\n",
        "0\r\nX-Host: a\r\n\r\n",
    };
    for (bodies) |body| {
        for ([_]usize{ 1, body.len }) |feed_bytes_max| {
            const outcome = chunkedOutcome(body, feed_bytes_max);
            try testing.expectEqual(@as(?ChunkedScanner.Error, null), outcome.failure);
            try testing.expect(outcome.done);
            try testing.expectEqual(@as(u64, body.len), outcome.consumed);
        }
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
/// The refused trailer shapes (#244), seeded beside the accepted one so
/// the fuzzer starts either side of the verdict rather than having to
/// discover a whole trailer section byte by byte.
const fuzz_corpus_chunked_trailer = "0\r\nContent-Length: 100\r\nX-Bad : v\r\n\r\n";

test "fuzz: heads and chunked framing — parse or reject, no third outcome" {
    try std.testing.fuzz({}, fuzzParserInputs, .{
        .corpus = &.{
            fuzz_corpus_request,
            fuzz_corpus_extension,
            fuzz_corpus_response,
            fuzz_corpus_chunked,
            fuzz_corpus_chunked_trailer,
        },
    });
}

fn fuzzParserInputs(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input_buffer: [constants.head_buffer_bytes_default]u8 = undefined;
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

test "canonicalTarget: table of canonical forms and rejects" {
    const Case = struct {
        target: []const u8,
        path: ?[]const u8, // null means Malformed
        query: []const u8 = "",
    };
    const cases = [_]Case{
        // Identity and query splitting; the query is verbatim, always.
        .{ .target = "/", .path = "/" },
        .{ .target = "/a/b", .path = "/a/b" },
        .{ .target = "/a?x=1", .path = "/a", .query = "?x=1" },
        .{ .target = "/a?", .path = "/a", .query = "?" },
        .{ .target = "/?a", .path = "/", .query = "?a" },
        .{ .target = "/a?%2F%zz/../", .path = "/a", .query = "?%2F%zz/../" },
        // The query-only remainder an absolute-form target leaves behind
        // (#233): an empty path names the root.
        .{ .target = "?q=1", .path = "/", .query = "?q=1" },
        .{ .target = "?", .path = "/", .query = "?" },
        // Unreserved escapes decode; others keep uppercased hex.
        .{ .target = "/%61%2D%5F%7E", .path = "/a-_~" },
        .{ .target = "/caf%c3%a9", .path = "/caf%C3%A9" },
        // A space is not unreserved: %41 decodes, %20 stays encoded —
        // no raw space can ever reach a request line.
        .{ .target = "/%41%20x", .path = "/A%20x" },
        // Dot segments collapse after decoding (the §7 order).
        .{ .target = "/a/./b", .path = "/a/b" },
        .{ .target = "/a/../b", .path = "/b" },
        .{ .target = "/a/b/..", .path = "/a/" },
        .{ .target = "/a/.", .path = "/a/" },
        .{ .target = "/./a", .path = "/a" },
        .{ .target = "/a/%2e%2e/b", .path = "/b" },
        .{ .target = "/a/%2E", .path = "/a/" },
        // Duplicate slashes are preserved; ".." still pops them.
        .{ .target = "//a", .path = "//a" },
        .{ .target = "/a//b", .path = "/a//b" },
        .{ .target = "/a/", .path = "/a/" },
        .{ .target = "/a//../b", .path = "/a/b" },
        // A leading empty segment is a real segment ".." can pop, so
        // "//.." is not a root climb — it is consistent, and consistency
        // (both router and origin see the canonical form) is the property
        // that matters, not rejection.
        .{ .target = "//../a", .path = "/a" },
        .{ .target = "//..", .path = "/" },
        // Rejects: structure-changing or malformed escapes, root climbs.
        .{ .target = "/%2F", .path = null },
        .{ .target = "/%2f", .path = null },
        .{ .target = "/%00", .path = null },
        .{ .target = "/%", .path = null },
        .{ .target = "/%A", .path = null },
        .{ .target = "/%GG", .path = null },
        .{ .target = "/..", .path = null },
        .{ .target = "/../a", .path = null },
        .{ .target = "/a/../..", .path = null },
        .{ .target = "/%2e%2e/a", .path = null },
        .{ .target = "/./..", .path = null },
    };
    for (cases) |case| {
        var out: [constants.head_buffer_bytes_default]u8 = undefined;
        const result = canonicalTarget(case.target, &out);
        if (case.path) |expected_path| {
            const canonical = try result;
            try std.testing.expectEqualStrings(expected_path, canonical.path);
            try std.testing.expectEqualStrings(case.query, canonical.query);
        } else {
            try std.testing.expectError(error.Malformed, result);
        }
    }
}

test "canonicalTarget: canonicalization is idempotent" {
    const targets = [_][]const u8{ "/a/../b", "/caf%c3%a9", "//a/./b%7e", "/a/b/.." };
    for (targets) |target| {
        var out: [constants.head_buffer_bytes_default]u8 = undefined;
        const first = try canonicalTarget(target, &out);
        var out_again: [constants.head_buffer_bytes_default]u8 = undefined;
        const second = try canonicalTarget(first.path, &out_again);
        try std.testing.expectEqualStrings(first.path, second.path);
        try std.testing.expectEqual(@as(usize, 0), second.query.len);
    }
}

test "fuzz: canonicalTarget rejects or emits the canonical form" {
    try std.testing.fuzz({}, fuzzCanonicalTarget, .{ .corpus = &.{
        "/a/../b%2e?q",
        "/%2e%2e/x",
        "/a%2Fb",
        "/a//b/./c/%7e%ZZ",
    } });
}

fn fuzzCanonicalTarget(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input_buffer: [constants.head_buffer_bytes_default]u8 = undefined;
    input_buffer[0] = '/';
    const tail_len = smith.slice(input_buffer[1..]);
    const input = input_buffer[0 .. 1 + tail_len];

    var out: [constants.head_buffer_bytes_default]u8 = undefined;
    // Reject-or-canonical, no third outcome: a reject ends the case.
    const canonical = canonicalTarget(input, &out) catch return;
    // Rooted, never grown, and the split covers the input.
    assert(canonical.path.len >= 1);
    assert(canonical.path[0] == '/');
    assert(canonical.path.len + canonical.query.len <= input.len);
    // No dot-segment survives in canonical form.
    assert(std.mem.indexOf(u8, canonical.path, "/../") == null);
    assert(std.mem.indexOf(u8, canonical.path, "/./") == null);
    assert(!std.mem.endsWith(u8, canonical.path, "/.."));
    assert(!std.mem.endsWith(u8, canonical.path, "/."));
    // The canonical form is its own canonical form.
    var out_again: [constants.head_buffer_bytes_default]u8 = undefined;
    const again = try canonicalTarget(canonical.path, &out_again);
    assert(std.mem.eql(u8, again.path, canonical.path));
    assert(again.query.len == 0);
}

test "canonicalHost: lowercase, strip port, bracket-aware" {
    const Case = struct { host: []const u8, want: ?[]const u8 };
    const cases = [_]Case{
        .{ .host = "api.example.com", .want = "api.example.com" },
        .{ .host = "API.Example.COM", .want = "api.example.com" },
        .{ .host = "api.example.com:8080", .want = "api.example.com" },
        .{ .host = "API.EXAMPLE.COM:443", .want = "api.example.com" },
        .{ .host = "localhost", .want = "localhost" },
        // IPv6 literals keep their brackets and inner colons; only a port
        // past the ']' is stripped, and the hex lowercases.
        .{ .host = "[::1]", .want = "[::1]" },
        .{ .host = "[::1]:8080", .want = "[::1]" },
        .{ .host = "[2001:DB8::1]:443", .want = "[2001:db8::1]" },
        // Unmatchable (null): empty, port-only, or an unterminated bracket.
        .{ .host = "", .want = null },
        .{ .host = ":8080", .want = null },
        .{ .host = "[::1", .want = null },
    };
    for (cases) |case| {
        var out: [constants.host_bytes_max]u8 = undefined;
        const got = canonicalHost(case.host, &out);
        if (case.want) |want| {
            try std.testing.expectEqualStrings(want, got.?);
        } else {
            try std.testing.expectEqual(@as(?[]const u8, null), got);
        }
    }
    // Oversize is unmatchable, not a crash.
    var big: [constants.host_bytes_max + 1]u8 = undefined;
    @memset(&big, 'a');
    var out: [constants.host_bytes_max]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), canonicalHost(&big, &out));
}

test "fuzz: canonicalHost is idempotent and never uppercases" {
    try std.testing.fuzz({}, fuzzCanonicalHost, .{ .corpus = &.{
        "API.Example.com:8080",
        "[2001:DB8::1]:443",
        ":onlyport",
        "a",
    } });
}

fn fuzzCanonicalHost(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input_buffer: [constants.host_bytes_max]u8 = undefined;
    const input_len = smith.slice(&input_buffer);
    const input = input_buffer[0..input_len];

    var out: [constants.host_bytes_max]u8 = undefined;
    const canonical = canonicalHost(input, &out) orelse return; // null is legal.
    // Never grows, and never yields an uppercase letter.
    assert(canonical.len >= 1);
    assert(canonical.len <= input.len);
    for (canonical) |byte| {
        assert(!std.ascii.isUpper(byte));
    }
    // Idempotent: the canonical form is its own canonical form.
    var out_again: [constants.host_bytes_max]u8 = undefined;
    const again = canonicalHost(canonical, &out_again).?;
    assert(std.mem.eql(u8, again, canonical));
}
