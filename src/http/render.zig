//! Head rendering for the L7 proxy (DESIGN.md §7): parsed heads are
//! *rendered* into a fixed staging buffer, never edited in place — the
//! zero-copy slices of the source head stay valid throughout. Rendering
//! strips hop-by-hop headers both ways (RFC 9110 §7.6.1), injects
//! `Connection: close` when the proxy will close (§2), and applies the §7
//! filter header edits that matched the request. A head that no longer
//! fits after rendering is oversize — 431 downstream, teardown upstream
//! (§7) — which now includes a head that outgrows the buffer only once the
//! edits are applied (the oversize-after-edits verdict).

const std = @import("std");
const constants = @import("../constants.zig");
const parser = @import("parser.zig");
const filter = @import("filter.zig");

const assert = std.debug.assert;

/// Header names never forwarded, beyond the Connection-nominated set
/// (RFC 9110 §7.6.1). Transfer-Encoding and Trailer are deliberately
/// absent: the body is relayed verbatim in its original framing, so its
/// framing headers must travel with it. Public so the filter compiler can
/// forbid an edit from naming a proxy-managed header (§7).
pub const hop_by_hop_names = [_][]const u8{
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "upgrade",
};

/// Header names a Connection header may NOT nominate away. Stripping
/// Content-Length or Transfer-Encoding would desynchronize the receiver
/// from the framing this proxy already committed to — a smuggling vector
/// — and stripping Host would unroute an HTTP/1.1 request. Public for the
/// same filter-edit guard as `hop_by_hop_names`.
pub const protected_names = [_][]const u8{
    "host",
    "content-length",
    "transfer-encoding",
};

/// Renders the upstream request line and end-to-end headers from a
/// parsed head. The client's version is preserved — framing decisions on
/// both hops key off the real versions — and `inject_close` announces
/// that this upstream connection will not be reused (§2). `edits` are the
/// §7 filter header mutations that matched this request: a set/remove
/// suppresses the source copies of its name, a set/add appends its
/// (config-validated, injection-safe) line — proxy-managed names can never
/// appear here, the filter compiler forbids them.
pub fn renderRequestHead(
    request: *const parser.RequestHead,
    target: parser.CanonicalTarget,
    edits: []const filter.AppliedHeaderEdit,
    inject_close: bool,
    buffer: []u8,
) error{Oversize}![]const u8 {
    // The proxy answers CONNECT with 501 itself, never forwards it (§7).
    assert(request.method != .connect);
    assert(request.method_token.len >= 1);
    // The forwarded target is the §7 canonical form the router matched on
    // (or `*` for OPTIONS), so the origin sees exactly the path we routed.
    assert(target.path.len >= 1);
    assert(edits.len <= constants.header_edits_max);
    assert(buffer.len <= std.math.maxInt(u32));

    var staging = Staging{ .buffer = buffer };
    try staging.append(request.method_token);
    try staging.append(" ");
    try staging.append(target.path);
    try staging.append(target.query);
    try staging.append(switch (request.version) {
        .http_1_0 => " HTTP/1.0\r\n",
        .http_1_1 => " HTTP/1.1\r\n",
    });
    try appendEndToEndHeaders(&staging, request.headers, edits);
    if (inject_close) {
        try staging.append("Connection: close\r\n");
    }
    try staging.append("\r\n");
    assert(staging.len >= 1);
    return staging.buffer[0..staging.len];
}

/// Renders the downstream status line and end-to-end headers. The
/// origin's version and reason phrase are preserved verbatim;
/// `inject_close` announces that the proxy will close the downstream
/// connection after this response (§2).
pub fn renderResponseHead(
    response: *const parser.ResponseHead,
    inject_close: bool,
    buffer: []u8,
) error{Oversize}![]const u8 {
    assert(response.status >= 100);
    assert(response.status <= 599);
    assert(buffer.len <= std.math.maxInt(u32));

    var staging = Staging{ .buffer = buffer };
    try staging.append(switch (response.version) {
        .http_1_0 => "HTTP/1.0 ",
        .http_1_1 => "HTTP/1.1 ",
    });
    try staging.append(&statusDigits(response.status));
    if (response.status_message) |message| {
        try staging.append(" ");
        try staging.append(message);
    }
    try staging.append("\r\n");
    // Filters are request-side only (§7); the response carries no edits.
    try appendEndToEndHeaders(&staging, response.headers, &.{});
    if (inject_close) {
        try staging.append("Connection: close\r\n");
    }
    try staging.append("\r\n");
    assert(staging.len >= 1);
    return staging.buffer[0..staging.len];
}

/// Bounded append cursor over the caller's staging buffer; overflowing
/// it is the `Oversize` verdict, never a wider write.
const Staging = struct {
    buffer: []u8,
    len: u32 = 0,

    fn append(staging: *Staging, bytes: []const u8) error{Oversize}!void {
        assert(staging.len <= staging.buffer.len);
        if (staging.buffer.len - staging.len < bytes.len) {
            return error.Oversize;
        }
        @memcpy(staging.buffer[staging.len..][0..bytes.len], bytes);
        staging.len += @intCast(bytes.len);
        assert(staging.len <= staging.buffer.len);
    }
};

/// Appends every end-to-end header as `Name: value\r\n`, preserving the
/// sender's name casing and value bytes. A §7 filter `set`/`remove` edit
/// suppresses the source copies of its name; each `set`/`add` edit then
/// appends its own line after the surviving source headers. Bounded by
/// `headers_max` and `header_edits_max`.
fn appendEndToEndHeaders(
    staging: *Staging,
    headers: []const parser.Header,
    edits: []const filter.AppliedHeaderEdit,
) error{Oversize}!void {
    assert(headers.len <= constants.headers_max);
    assert(edits.len <= constants.header_edits_max);
    // Collect the Connection header value(s) once (usually zero or one).
    // Re-finding them inside the per-header hop-by-hop test made the walk
    // O(headers²) — the render's top user-CPU cost under load (§9).
    var connection_values: [constants.headers_max][]const u8 = undefined;
    var connection_count: u32 = 0;
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "connection")) {
            connection_values[connection_count] = header.value;
            connection_count += 1;
        }
    }
    const nominations = connection_values[0..connection_count];
    // `close` and `keep-alive` are connection options, not header names —
    // `keep-alive` is already a hop-by-hop name and `close` names no
    // forwardable header — so a Connection listing only those nominates
    // nothing to strip. Detect a real nomination once here; the common
    // case then skips the per-header token scan entirely, splitting the
    // Connection value once rather than once per header (§9).
    const active_nominations =
        if (nominatesRealHeader(nominations)) nominations else nominations[0..0];

    // Only `set`/`remove` edits suppress source copies; `add` never does.
    // Decide once whether any suppressing edit exists, so a request with no
    // edits — or only `add` edits — skips the per-header suppression scan.
    var has_suppressing_edit = false;
    for (edits) |edit| {
        if (edit.kind != .add) {
            has_suppressing_edit = true;
            break;
        }
    }

    for (headers) |header| {
        assert(header.name.len >= 1);
        if (isHopByHop(header.name, active_nominations)) {
            continue;
        }
        if (has_suppressing_edit and suppressedByEdit(header.name, edits)) {
            continue;
        }
        try staging.append(header.name);
        try staging.append(": ");
        try staging.append(header.value);
        try staging.append("\r\n");
    }
    // Injected edits follow the surviving source headers; a `remove`
    // contributes no line (its whole effect is the suppression above).
    for (edits) |edit| {
        switch (edit.kind) {
            .set, .add => {
                try staging.append(edit.name);
                try staging.append(": ");
                try staging.append(edit.value);
                try staging.append("\r\n");
            },
            .remove => {},
        }
    }
}

/// True when a `set` or `remove` edit names this header, so its source
/// copies must not be forwarded (`add` never suppresses — it appends).
fn suppressedByEdit(name: []const u8, edits: []const filter.AppliedHeaderEdit) bool {
    assert(name.len >= 1);
    assert(edits.len <= constants.header_edits_max);
    for (edits) |edit| {
        switch (edit.kind) {
            .set, .remove => if (std.ascii.eqlIgnoreCase(name, edit.name)) return true,
            .add => {},
        }
    }
    return false;
}

/// True when a Connection value names a header to strip beyond the
/// standard `close`/`keep-alive` options. Splits each token list once so
/// the per-header hop-by-hop test can skip the (usually empty) nomination
/// scan in the common case.
fn nominatesRealHeader(nominations: []const []const u8) bool {
    assert(nominations.len <= constants.headers_max);
    for (nominations) |value| {
        var tokens = std.mem.splitScalar(u8, value, ',');
        while (tokens.next()) |raw_token| {
            const token = std.mem.trim(u8, raw_token, " \t");
            if (token.len == 0) {
                continue;
            }
            if (std.ascii.eqlIgnoreCase(token, "close")) {
                continue;
            }
            if (std.ascii.eqlIgnoreCase(token, "keep-alive")) {
                continue;
            }
            return true;
        }
    }
    return false;
}

/// True when the header must not be forwarded: in the static hop-by-hop
/// set, or nominated by a Connection header (RFC 9110 §7.6.1) — unless
/// it is protected (see `protected_names`). `nominations` is the set of
/// Connection values that name a real header (empty in the common
/// close/keep-alive-only case), so this is O(1) then rather than a token
/// scan per header.
fn isHopByHop(name: []const u8, nominations: []const []const u8) bool {
    assert(name.len >= 1);
    assert(nominations.len <= constants.headers_max);
    for (hop_by_hop_names) |hop_name| {
        if (std.ascii.eqlIgnoreCase(name, hop_name)) {
            return true;
        }
    }
    for (protected_names) |protected_name| {
        if (std.ascii.eqlIgnoreCase(name, protected_name)) {
            return false;
        }
    }
    for (nominations) |value| {
        if (parser.tokenListHas(value, name)) {
            return true;
        }
    }
    return false;
}

/// The three ASCII digits of a 1xx–5xx status code.
fn statusDigits(status: u16) [3]u8 {
    assert(status >= 100);
    assert(status <= 599);
    return .{
        '0' + @as(u8, @intCast(status / 100)),
        '0' + @as(u8, @intCast(status / 10 % 10)),
        '0' + @as(u8, @intCast(status % 10)),
    };
}

// Tests. The load-bearing oracle is parse → render → reparse: whatever
// zoxy accepts must render into a head zoxy itself accepts, with the
// routing- and framing-relevant fields intact and hop-by-hop gone.

const testing = std.testing;

/// Fuzz/test staging: normalization can grow a head (a missing space
/// after `:` is rendered back, one byte per header), so the oracle
/// buffer carries slack; the production staging area is exactly
/// `head_bytes_max` and overflowing it is the 431/teardown verdict.
const oracle_buffer_bytes = constants.head_bytes_max + @as(u32, constants.headers_max) + 64;

test "render: request strips hop-by-hop and nominated, keeps the rest" {
    const head = "GET /p HTTP/1.1\r\nHost: a\r\nConnection: close, X-Nominated\r\n" ++
        "Keep-Alive: timeout=5\r\nTE: trailers\r\nX-Nominated: v\r\nX-Keep: yes\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    var buffer: [oracle_buffer_bytes]u8 = undefined;

    const rendered = try renderRequestHead(&request, .{ .path = "/p", .query = "" }, &.{}, false, &buffer);
    try testing.expectEqualStrings(
        "GET /p HTTP/1.1\r\nHost: a\r\nX-Keep: yes\r\n\r\n",
        rendered,
    );

    const closed = try renderRequestHead(&request, .{ .path = "/p", .query = "" }, &.{}, true, &buffer);
    try testing.expectEqualStrings(
        "GET /p HTTP/1.1\r\nHost: a\r\nX-Keep: yes\r\nConnection: close\r\n\r\n",
        closed,
    );
}

test "render: filter edits set, add, and remove headers" {
    // set X-Env: source copy suppressed then the edit value appended; add
    // X-Trace: source copy kept and a second appended; remove Cookie:
    // source copy suppressed, nothing appended.
    const head = "GET /p HTTP/1.1\r\nHost: a\r\nX-Env: dev\r\nX-Trace: t0\r\n" ++
        "Cookie: sid=1\r\nX-Keep: yes\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    const edits = [_]filter.AppliedHeaderEdit{
        .{ .kind = .set, .name = "X-Env", .value = "prod" },
        .{ .kind = .add, .name = "X-Trace", .value = "t1" },
        .{ .kind = .remove, .name = "cookie", .value = "" },
    };
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderRequestHead(&request, .{ .path = "/p", .query = "" }, &edits, false, &buffer);
    // Surviving source headers first (Host, kept X-Trace, X-Keep), then the
    // injected set/add lines; the source X-Env and Cookie are gone.
    try testing.expectEqualStrings(
        "GET /p HTTP/1.1\r\nHost: a\r\nX-Trace: t0\r\nX-Keep: yes\r\n" ++
            "X-Env: prod\r\nX-Trace: t1\r\n\r\n",
        rendered,
    );

    // The edited head must re-parse as a valid request with the edits live.
    var reparse_storage: parser.HeaderStorage = undefined;
    const reparsed = try parser.parseRequestHead(rendered, false, &reparse_storage);
    try testing.expectEqualStrings("prod", parser.headerValue(reparsed.headers, "x-env").?);
    try testing.expectEqual(@as(?[]const u8, null), parser.headerValue(reparsed.headers, "cookie"));
}

test "render: an edit that overflows the buffer is Oversize" {
    // A head that fits on arrival but whose injected edit no longer does is
    // the §7 oversize-after-edits verdict — the same 431 as an oversize
    // source head.
    const head = "GET /p HTTP/1.1\r\nHost: a\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    const edits = [_]filter.AppliedHeaderEdit{
        .{ .kind = .add, .name = "X-Big", .value = "0123456789" },
    };
    // Room for the request line + Host, but not the appended X-Big line.
    var tight: [34]u8 = undefined;
    try testing.expectError(
        error.Oversize,
        renderRequestHead(&request, .{ .path = "/p", .query = "" }, &edits, false, &tight),
    );
}

test "render: the edited oracle skips a head that grows past head_bytes_max" {
    // Regression: `parseRequestHead`'s first statement asserts
    // `head.len <= head_bytes_max`, so an edited head rendered past that
    // ceiling (into the slack oracle buffer) would trip that assert before
    // any error could surface — a panic reachable under `--fuzz`. The oracle
    // guards on `rendered.len`; this input, a source exactly at the ceiling
    // with a no-space colon (render re-adds ": ", +1 byte) plus the fixed
    // edits, is guaranteed over it. Without the guard the call panics.
    var source: [constants.head_bytes_max]u8 = undefined;
    const prefix = "GET / HTTP/1.1\r\nHost: a\r\nX:";
    @memcpy(source[0..prefix.len], prefix);
    // Pad the value so the whole head, including the terminating CRLF, is
    // exactly head_bytes_max bytes.
    const value_end = constants.head_bytes_max - "\r\n\r\n".len;
    @memset(source[prefix.len..value_end], 'x');
    @memcpy(source[value_end..], "\r\n\r\n");

    // The source is legal (head.len == head_bytes_max is within the limit).
    var storage: parser.HeaderStorage = undefined;
    const parsed = try parser.parseRequestHead(&source, false, &storage);
    try testing.expectEqual(@as(u32, constants.head_bytes_max), parsed.head_len);
    // Confirm the edited render genuinely crosses the ceiling — otherwise
    // this test would exercise nothing. (The edit set mirrors the oracle's.)
    const edits = [_]filter.AppliedHeaderEdit{
        .{ .kind = .set, .name = "X-Fuzz-Set", .value = "s" },
        .{ .kind = .add, .name = "X-Fuzz-Add", .value = "a" },
        .{ .kind = .remove, .name = "X-Fuzz-Remove", .value = "" },
    };
    var render_buf: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderRequestHead(&parsed, .{ .path = "/", .query = "" }, &edits, false, &render_buf);
    try testing.expect(rendered.len > constants.head_bytes_max);
    // Must return cleanly instead of panicking in the reparse precondition.
    checkRequestRenderEdited(&source);
}

test "render: nominating a protected header does not strip it" {
    // `Connection: content-length` must not remove the header the proxy
    // framed the body by — stripping it would desynchronize the upstream.
    const head = "POST /u HTTP/1.1\r\nHost: a\r\nConnection: Content-Length, Host\r\n" ++
        "Content-Length: 5\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderRequestHead(&request, .{ .path = "/u", .query = "" }, &.{}, false, &buffer);
    try testing.expectEqualStrings(
        "POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n",
        rendered,
    );
}

test "render: standard Connection options do not nominate a same-named header" {
    // `close`/`keep-alive` are persistence directives (RFC 9110 §7.6.1),
    // not nominations — so the per-header token scan is skipped for them,
    // and a (bogus) header literally named "Close" is forwarded, not
    // stripped. A real nomination on the same Connection still strips
    // (covered by the strips-hop-by-hop-and-nominated test above).
    const head = "GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, close\r\n" ++
        "Close: x\r\nKeep-Alive: timeout=5\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderRequestHead(&request, .{ .path = "/", .query = "" }, &.{}, false, &buffer);
    // Connection stripped (hop-by-hop) and Keep-Alive stripped (a
    // hop-by-hop name); the "Close" header survives — close nominates
    // nothing.
    try testing.expectEqualStrings(
        "GET / HTTP/1.1\r\nHost: a\r\nClose: x\r\n\r\n",
        rendered,
    );
}

test "render: framing headers travel with the body" {
    const head = "POST /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderRequestHead(&request, .{ .path = "/u", .query = "" }, &.{}, false, &buffer);

    var reparse_storage: parser.HeaderStorage = undefined;
    const reparsed = try parser.parseRequestHead(rendered, false, &reparse_storage);
    try testing.expectEqual(parser.BodyFraming.chunked, reparsed.framing);
}

test "render: client version is preserved" {
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead("GET / HTTP/1.0\r\n\r\n", false, &storage);
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderRequestHead(&request, .{ .path = "/", .query = "" }, &.{}, false, &buffer);
    try testing.expectEqualStrings("GET / HTTP/1.0\r\n\r\n", rendered);
}

test "render: response preserves status line and strips hop-by-hop" {
    const head = "HTTP/1.1 418 I'm a teapot\r\nConnection: keep-alive\r\n" ++
        "Content-Length: 0\r\nX-Origin: yes\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const response = try parser.parseResponseHead(head, false, &storage, .get);
    var buffer: [oracle_buffer_bytes]u8 = undefined;

    const rendered = try renderResponseHead(&response, false, &buffer);
    try testing.expectEqualStrings(
        "HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\nX-Origin: yes\r\n\r\n",
        rendered,
    );

    const closed = try renderResponseHead(&response, true, &buffer);
    try testing.expectEqualStrings(
        "HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\nX-Origin: yes\r\n" ++
            "Connection: close\r\n\r\n",
        closed,
    );
}

test "render: bare status line without a reason phrase round-trips" {
    var storage: parser.HeaderStorage = undefined;
    const response = try parser.parseResponseHead("HTTP/1.0 204\r\n\r\n", false, &storage, .get);
    try testing.expectEqual(@as(?[]const u8, null), response.status_message);
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderResponseHead(&response, false, &buffer);
    try testing.expectEqualStrings("HTTP/1.0 204\r\n\r\n", rendered);
}

test "render: a head that no longer fits is Oversize" {
    const head = "GET /path HTTP/1.1\r\nHost: origin.example\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    const target = parser.CanonicalTarget{ .path = "/path", .query = "" };
    var small: [16]u8 = undefined;
    try testing.expectError(error.Oversize, renderRequestHead(&request, target, &.{}, false, &small));
}

// Fuzzing (§9 gate 2): whatever the parser accepts, the renderer must
// turn into a head the parser accepts again, with routing and framing
// intact and hop-by-hop headers gone.

fn checkRequestRender(input: []const u8) void {
    var storage: parser.HeaderStorage = undefined;
    const request = parser.parseRequestHead(input, false, &storage) catch return;
    if (request.method == .connect) {
        return; // Never rendered: the proxy answers CONNECT itself.
    }
    // Mirror the routeRequest gate (§7): an origin-form target that will
    // not canonicalize is a 400 and never reaches the renderer; OPTIONS
    // asterisk-form has no path and forwards verbatim.
    var scratch: [constants.head_bytes_max]u8 = undefined;
    const target: parser.CanonicalTarget = if (request.target[0] == '/')
        (parser.canonicalTarget(request.target, &scratch) catch return)
    else
        .{ .path = request.target, .query = "" };

    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = renderRequestHead(&request, target, &.{}, false, &buffer) catch unreachable;

    // The oracle buffer carries slack past `head_bytes_max` so normalization
    // growth never truncates the comparison; production renders into an
    // exactly-`head_bytes_max` buffer and 431s anything larger. A head that
    // grew past that ceiling here is that oversize verdict — not a reparse
    // input, and past the parser's own size precondition — so stop before it.
    if (rendered.len > constants.head_bytes_max) {
        return;
    }
    var reparse_storage: parser.HeaderStorage = undefined;
    // A rendered head failing our own parser would mean the proxy emits
    // requests it would itself reject — the oracle's core claim.
    const reparsed = parser.parseRequestHead(rendered, false, &reparse_storage) catch unreachable;
    assert(reparsed.method == request.method);
    assert(std.mem.eql(u8, reparsed.method_token, request.method_token));
    // §7 canonical forwarding: the origin sees the canonical path plus the
    // verbatim query — exactly what the router matched on.
    assert(reparsed.target.len == target.path.len + target.query.len);
    assert(std.mem.startsWith(u8, reparsed.target, target.path));
    assert(std.mem.eql(u8, reparsed.target[target.path.len..], target.query));
    assert(reparsed.version == request.version);
    assert(std.meta.eql(reparsed.framing, request.framing));
    if (request.host) |host| {
        assert(std.mem.eql(u8, reparsed.host.?, host));
    }
    for (reparsed.headers) |header| {
        for (hop_by_hop_names) |hop_name| {
            assert(!std.ascii.eqlIgnoreCase(header.name, hop_name));
        }
    }
}

/// Same oracle, but with a fixed §7 filter edit set applied: whatever the
/// parser accepts must still re-parse after a set/add/remove, with the
/// edits observably live. An edited head that outgrows the buffer is the
/// legitimate oversize-after-edits verdict (431), not an oracle failure.
fn checkRequestRenderEdited(input: []const u8) void {
    var storage: parser.HeaderStorage = undefined;
    const request = parser.parseRequestHead(input, false, &storage) catch return;
    if (request.method == .connect) {
        return;
    }
    var scratch: [constants.head_bytes_max]u8 = undefined;
    const target: parser.CanonicalTarget = if (request.target[0] == '/')
        (parser.canonicalTarget(request.target, &scratch) catch return)
    else
        .{ .path = request.target, .query = "" };

    // Names the fuzzed input cannot collide with a proxy-managed header on;
    // config forbids editing those, so the renderer never sees them.
    const edits = [_]filter.AppliedHeaderEdit{
        .{ .kind = .set, .name = "X-Fuzz-Set", .value = "s" },
        .{ .kind = .add, .name = "X-Fuzz-Add", .value = "a" },
        .{ .kind = .remove, .name = "X-Fuzz-Remove", .value = "" },
    };
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = renderRequestHead(&request, target, &edits, false, &buffer) catch return;

    // The appended edits can push an already-large head past `head_bytes_max`
    // — the oversize-after-edits verdict (431 in production, which renders
    // into an exactly-`head_bytes_max` buffer). Past that ceiling the head is
    // not a reparse input and would trip the parser's size precondition, so
    // stop; a reparse miss below is then only the benign headers-count
    // overflow (source at `headers_max` plus the appended lines).
    if (rendered.len > constants.head_bytes_max) {
        return;
    }
    var reparse_storage: parser.HeaderStorage = undefined;
    const reparsed = parser.parseRequestHead(rendered, false, &reparse_storage) catch return;
    // set always wins (its source copies are suppressed, one value
    // appended); remove is always absent; add is always present.
    assert(std.mem.eql(u8, parser.headerValue(reparsed.headers, "x-fuzz-set").?, "s"));
    assert(parser.headerValue(reparsed.headers, "x-fuzz-remove") == null);
    assert(parser.headerValue(reparsed.headers, "x-fuzz-add") != null);
    // The edits never disturb framing or routing.
    assert(std.meta.eql(reparsed.framing, request.framing));
    assert(reparsed.target.len == target.path.len + target.query.len);
}

fn checkResponseRender(input: []const u8) void {
    var storage: parser.HeaderStorage = undefined;
    const response = parser.parseResponseHead(input, false, &storage, .get) catch return;
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = renderResponseHead(&response, false, &buffer) catch unreachable;

    var reparse_storage: parser.HeaderStorage = undefined;
    const reparsed = parser.parseResponseHead(rendered, false, &reparse_storage, .get) catch unreachable;
    assert(reparsed.status == response.status);
    assert(reparsed.version == response.version);
    assert(std.meta.eql(reparsed.framing, response.framing));
    assert((reparsed.status_message == null) == (response.status_message == null));
    if (response.status_message) |message| {
        assert(std.mem.eql(u8, reparsed.status_message.?, message));
    }
}

test "fuzz: parse-render-reparse keeps routing and framing intact" {
    try std.testing.fuzz({}, fuzzRenderInputs, .{
        .corpus = &.{
            "POST /submit HTTP/1.1\r\nHost: origin\r\nContent-Length: 5\r\n\r\nhello",
            "GET /p HTTP/1.1\r\nHost: a\r\nConnection: close, X-N\r\nX-N: v\r\nTE: t\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
        },
    });
}

fn fuzzRenderInputs(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input_buffer: [constants.head_bytes_max]u8 = undefined;
    const input_len = smith.slice(&input_buffer);
    assert(input_len <= input_buffer.len);
    const input = input_buffer[0..input_len];
    checkRequestRender(input);
    checkRequestRenderEdited(input);
    checkResponseRender(input);
}
