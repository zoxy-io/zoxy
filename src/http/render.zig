//! Head rendering for the L7 proxy (DESIGN.md §7): parsed heads are
//! *rendered* into a fixed staging buffer, never edited in place — the
//! zero-copy slices of the source head stay valid throughout. Rendering
//! strips hop-by-hop headers both ways (RFC 9110 §7.6.1), injects
//! `Connection: close` when the proxy will close, and applies the filter
//! header edits that matched — the §7 request rules on the way in, the
//! #175 response rules on the way out, through one suppress-and-append
//! mechanism. A head that no longer fits after rendering is oversize:
//! 431 for a request (the client sent it), 502 for a response (the
//! origin's answer is not the client's fault) — including a head that
//! outgrows the buffer only once the edits are applied.

const std = @import("std");
const constants = @import("../constants.zig");
const parser = @import("parser.zig");
const filter = @import("filter.zig");
const shed = @import("../shed.zig");

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

/// The one header this proxy writes on the client's behalf (§7). Public
/// so `config.zig` can bar filter edits from naming it — a filter can
/// only write a constant, and one fixed address for every client is the
/// opposite of forwarding one.
pub const forwarded_for_name = "X-Forwarded-For";

/// The second header this proxy writes on the client's behalf, and for a
/// stricter reason (#240): RFC 9110 §7.6.2 requires each intermediary to
/// replace the received value with its own decrement. Public for the same
/// filter-edit guard — a rule writing a constant here would restate a
/// number this proxy computes per hop.
pub const max_forwards_name = "Max-Forwards";

/// True when `list` names `name` exactly. Comptime-only, for the check
/// below; the runtime path compares tags, not strings.
fn nameListHas(list: []const []const u8, name: []const u8) bool {
    for (list) |entry| {
        if (std.mem.eql(u8, entry, name)) return true;
    }
    return false;
}

comptime {
    // These lists and `parser.HeaderName`'s predicates are two spellings
    // of one rule, and the runtime path now reads the second. Pin them in
    // both directions so divergence is a build failure rather than a §7
    // hole: a list entry no variant claims would stop being stripped, and
    // a variant no list claims would strip a header nothing documents.
    for (hop_by_hop_names) |name| {
        assert(parser.classifyHeaderName(name).hopByHop());
    }
    for (protected_names) |name| {
        assert(parser.classifyHeaderName(name).protected());
    }
    for (@typeInfo(parser.HeaderName).@"enum".fields) |field| {
        const tag: parser.HeaderName = @enumFromInt(field.value);
        if (tag.hopByHop()) assert(nameListHas(&hop_by_hop_names, tag.text()));
        if (tag.protected()) assert(nameListHas(&protected_names, tag.text()));
        // `isHopByHop` tests hop-by-hop first, so a name in both sets
        // would be stripped despite being protected — the smuggling shape
        // `protected_names` exists to prevent. Say it, rather than leave
        // it to whoever next edits a list to notice.
        assert(!(tag.hopByHop() and tag.protected()));
    }
}

/// What one head render needs beyond its output buffer, lent by the
/// caller rather than declared per call.
///
/// The array inside is a local of `appendEndToEndHeaders` by rights —
/// nothing in it outlives the render. It is a parameter because under
/// ReleaseSafe an `= undefined` local is 0xaa-filled on every call, and
/// this one is 1 KiB filled twice per exchange (once per hop), which §9's
/// flamegraph found is most of what the render path costs. The serving
/// path lends `Server.render_scratch`; a test or a bench may still declare
/// one on the stack.
pub const HeadScratch = struct {
    /// The `Connection` header's nominated values, collected once per
    /// render. Re-finding them inside the per-header hop-by-hop test made
    /// the walk O(headers²) — the render's top user-CPU cost under load.
    connection_values: [constants.headers_max][]const u8,
};

/// Renders the upstream request line and end-to-end headers from a
/// parsed head. The client's version is preserved — framing decisions on
/// both hops key off the real versions — and `inject_close` announces
/// that this upstream connection will not be reused (§7). `edits` are the
/// §7 filter header mutations that matched this request: a set/remove
/// suppresses the source copies of its name, a set/add appends its
/// (config-validated, injection-safe) line — proxy-managed names can never
/// appear here, the filter compiler forbids them.
pub fn renderRequestHead(
    request: *const parser.RequestHead,
    target: parser.CanonicalTarget,
    edits: []const filter.AppliedHeaderEdit,
    inject_close: bool,
    /// The complete `X-Forwarded-For` value to emit, or null to leave the
    /// header exactly as it arrived (§7).
    ///
    /// Fully assembled by the time it gets here: the caller resolved the
    /// trust mode, bounded any inbound chain, formatted the observed peer
    /// and joined them. So this file has no policy left to get wrong — it
    /// suppresses the inbound copies and writes one line, through the same
    /// `appendHeaderLine` every other header uses. The split is
    /// deliberate: the trust rule is a security decision with a counter
    /// attached, and a byte-assembler should have access to neither.
    forwarded_for: ?[]const u8,
    /// The decremented `Max-Forwards` to emit, or null to leave whatever
    /// arrived exactly as it arrived (#240) — which is every request but
    /// an `OPTIONS` that carried a budget.
    ///
    /// Assembled by the caller, like `forwarded_for` and for the same
    /// reason: the check that a zero budget stops here is a §7 decision
    /// with a verdict attached, and by the time it reaches this file the
    /// only question left is where the bytes go.
    max_forwards: ?[]const u8,
    /// True when this request is a protocol upgrade this listener has
    /// agreed to carry (#180): the participating `Upgrade` travels and
    /// the proxy writes its own `Connection: upgrade`.
    keep_upgrade: bool,
    /// The caller's scratch for this render (see `HeadScratch`).
    scratch: *HeadScratch,
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
    // An absolute-form request line named its own authority, and that
    // authority is what routed (#233). RFC 9112 §3.2.2 has a recipient
    // ignore the Host header field and use it instead — so this proxy
    // writes the Host the origin will see, rather than forwarding a
    // header the router already overruled. Written here, ahead of the
    // source headers, because that is where a client would have put it;
    // the inbound copies are suppressed as the headers are walked.
    if (request.authority) |authority| {
        assert(authority.len >= 1);
        try staging.appendHeaderLine("Host", authority);
    }
    try appendEndToEndHeaders(
        &staging,
        request.headers,
        request.connection_nominates_header,
        edits,
        .{
            .forwarded_for = forwarded_for != null,
            .host = request.authority != null,
            .max_forwards = max_forwards != null,
        },
        keep_upgrade,
        scratch,
    );
    if (forwarded_for) |value| {
        assert(value.len >= 1);
        try staging.appendHeaderLine(forwarded_for_name, value);
    }
    // The hop budget RFC 9110 §7.6.2 has each intermediary decrement
    // (#240). Written here for the same reason the forwarded line is:
    // the caller did the arithmetic and the check that goes with it, and
    // this file is a byte-assembler with no business deciding either.
    if (max_forwards) |value| {
        assert(value.len >= 1);
        try staging.appendHeaderLine(max_forwards_name, value);
    }
    // A carried upgrade announces the opposite of a close: this hop is
    // continuing, in a different protocol. The two are mutually exclusive
    // by construction — an exchange that becomes a tunnel is never the
    // last one on a connection about to end — and the proxy writes this
    // line itself rather than forwarding whichever spelling arrived, so
    // what the next hop reads is exactly what this hop decided (#180).
    if (keep_upgrade) {
        assert(!inject_close);
        try staging.append("Connection: upgrade\r\n");
    }
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
/// connection after this response (§7). `edits` are the matched
/// response filters' header edits (#175), applied by the same
/// suppress-and-append machinery the request render uses — empty when
/// the listener configured none, which is most listeners; the one slot
/// past `header_edits_max` is the #178 Set-Cookie stamp, which rides
/// this same machinery rather than owning a second injection path.
/// Overflow is the caller's 502: an origin response that cannot be
/// re-rendered after edits is not the client's fault.
pub fn renderResponseHead(
    response: *const parser.ResponseHead,
    inject_close: bool,
    edits: []const filter.AppliedHeaderEdit,
    /// True when this response is the `101` completing an upgrade this
    /// proxy is carrying (#180), the mirror of the request-side flag.
    keep_upgrade: bool,
    /// The caller's scratch for this render (see `HeadScratch`).
    scratch: *HeadScratch,
    buffer: []u8,
) error{Oversize}![]const u8 {
    assert(response.status >= 100);
    assert(response.status <= 599);
    assert(edits.len <= constants.response_edits_max);
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
    try appendEndToEndHeaders(
        &staging,
        response.headers,
        response.connection_nominates_header,
        edits,
        // Every suppression is request-side: a response carries no
        // header this proxy writes on the client's behalf.
        .{},
        keep_upgrade,
        scratch,
    );
    // A carried upgrade announces the opposite of a close: this hop is
    // continuing, in a different protocol. The two are mutually exclusive
    // by construction — an exchange that becomes a tunnel is never the
    // last one on a connection about to end — and the proxy writes this
    // line itself rather than forwarding whichever spelling arrived, so
    // what the next hop reads is exactly what this hop decided (#180).
    if (keep_upgrade) {
        assert(!inject_close);
        try staging.append("Connection: upgrade\r\n");
    }
    if (inject_close) {
        try staging.append("Connection: close\r\n");
    }
    try staging.append("\r\n");
    assert(staging.len >= 1);
    return staging.buffer[0..staging.len];
}

/// Renders a #176 redirect response head into `buffer`: the status
/// line, the Location, an explicit zero length, and the close
/// announcement when the connection will not be kept. The one response
/// this proxy *originates* whose bytes are not comptime-static — the
/// Location may carry the request's own path — which is why it renders
/// here beside the other two heads rather than living in `shed.zig`.
pub fn renderRedirectHead(
    status: u16,
    location: []const u8,
    inject_close: bool,
    /// The current second as an IMF-fixdate (#234). Passed in rather than
    /// read here: this file assembles bytes and owns no clock, which is
    /// the same split `X-Forwarded-For` is written on.
    ///
    /// Unlike the static answers, a redirect is rendered per response
    /// into the connection's own head buffer, so it shares nothing and
    /// its date is always the current one — no slot, no claim.
    date: *const [shed.date_bytes]u8,
    buffer: []u8,
) error{Oversize}![]const u8 {
    assert(filter.isRedirectStatus(status));
    assert(location.len >= 1);
    assert(buffer.len <= std.math.maxInt(u32));
    var staging = Staging{ .buffer = buffer };
    try staging.append("HTTP/1.1 ");
    try staging.append(&statusDigits(status));
    try staging.append(" ");
    try staging.append(redirectReason(status));
    try staging.append("\r\nLocation: ");
    try staging.append(location);
    try staging.append("\r\nContent-Length: 0\r\nDate: ");
    try staging.append(date);
    try staging.append("\r\n");
    try staging.append(shed.server_line);
    if (inject_close) {
        try staging.append("Connection: close\r\n");
    }
    try staging.append("\r\n");
    assert(staging.len >= 1);
    return staging.buffer[0..staging.len];
}

/// The reason phrases for `filter.redirect_statuses` — a closed switch
/// on `shed.reasonPhrase`'s terms: an unlisted status is a bug at the
/// call site, not a phrase to invent.
fn redirectReason(status: u16) []const u8 {
    return switch (status) {
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        else => unreachable, // isRedirectStatus gates every caller.
    };
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

    /// Appends one `Name: value\r\n` line, reserving the whole line once.
    ///
    /// Byte-for-byte what four `append` calls emitted, and deliberately so:
    /// a head has exactly one spelling here, and a second way to write one
    /// is the kind of divergence §7 correctness is built to avoid. What
    /// changes is only the bookkeeping around the bytes. Four calls reloaded
    /// the cursor and re-checked the bound four times per header, twice of
    /// that to move a two-byte constant — the `addl $0x2` and the cursor
    /// reloads were the top instructions in this function's profile (§9).
    fn appendHeaderLine(
        staging: *Staging,
        name: []const u8,
        value: []const u8,
    ) error{Oversize}!void {
        assert(staging.len <= staging.buffer.len);
        assert(name.len >= 1);
        // `": "` and `"\r\n"`; both name and value are head-buffer bounded,
        // so the sum cannot overflow.
        const line_bytes = name.len + 2 + value.len + 2;
        if (staging.buffer.len - staging.len < line_bytes) {
            return error.Oversize;
        }
        var cursor: usize = staging.len;
        @memcpy(staging.buffer[cursor..][0..name.len], name);
        cursor += name.len;
        staging.buffer[cursor] = ':';
        staging.buffer[cursor + 1] = ' ';
        cursor += 2;
        @memcpy(staging.buffer[cursor..][0..value.len], value);
        cursor += value.len;
        staging.buffer[cursor] = '\r';
        staging.buffer[cursor + 1] = '\n';
        cursor += 2;
        staging.len = @intCast(cursor);
        assert(staging.len <= staging.buffer.len);
    }
};

/// Appends every end-to-end header as `Name: value\r\n`, preserving the
/// sender's name casing and value bytes. A §7 filter `set`/`remove` edit
/// suppresses the source copies of its name; each `set`/`add` edit then
/// appends its own line after the surviving source headers. Bounded by
/// `headers_max` and `header_edits_max`.
/// Which proxy-written headers are replacing their inbound copies on
/// this hop (§7). Each is `true` only where the caller has already
/// written, or is about to write, its own line — so the header reaches
/// the next hop exactly once and says what *this* hop decided.
const Suppress = struct {
    /// The §7 forwarded-address line: under `replace` because the inbound
    /// chain is untrusted, under `append` because the caller already
    /// folded it into the line it will write.
    forwarded_for: bool = false,
    /// The `Host` an absolute-form authority overruled (#233). RFC 9112
    /// §3.2.2 has the received Host ignored in favour of the target's
    /// authority, and a request carrying both would hand the origin the
    /// very disagreement that rule exists to settle.
    host: bool = false,
    /// The `Max-Forwards` budget this hop decrements (#240). RFC 9110
    /// §7.6.2 requires the *updated* value travel, so the received one
    /// must not travel beside it.
    max_forwards: bool = false,

    /// Whether this hop writes any of the three. Hoisted out of the
    /// header walk for the same reason `has_suppressing_edit` is: all
    /// three are off for an ordinary forwarded request — forwarding is
    /// opt-in per listener, absolute-form is rare and a hop budget rarer
    /// — and that case should cost one predictable branch for the whole
    /// walk rather than a tag dispatch on every header (§9: the render is
    /// the top user-CPU cost under load).
    fn any(suppress: Suppress) bool {
        return suppress.forwarded_for or suppress.host or suppress.max_forwards;
    }

    fn claims(suppress: Suppress, tag: parser.HeaderName) bool {
        // Only reached when `any` already said one of the three is on, so
        // the common answer here is "some *other* header" rather than
        // "nothing is suppressed at all".
        assert(suppress.any());
        return switch (tag) {
            .x_forwarded_for => suppress.forwarded_for,
            .host => suppress.host,
            .max_forwards => suppress.max_forwards,
            else => false,
        };
    }
};

fn appendEndToEndHeaders(
    staging: *Staging,
    headers: []const parser.Header,
    connection_nominates_header: bool,
    edits: []const filter.AppliedHeaderEdit,
    /// The headers this proxy writes itself on this hop, whose inbound
    /// copies must therefore not travel beside them (§7). One struct
    /// rather than a row of bools: they are the same rule three times,
    /// and three adjacent booleans at a call site is an argument swap
    /// waiting to happen.
    suppress: Suppress,
    /// True when this hop is *participating* in a protocol upgrade
    /// (#180), which is the one case where `Upgrade` must travel.
    ///
    /// It is hop-by-hop by definition, and stripping it is right for
    /// every message this proxy merely forwards — the header names what
    /// *this* connection could become, not what the next one should. A
    /// handshake the proxy has decided to carry inverts that: here the
    /// header names exactly this hop's intent, and removing it would
    /// leave an origin asked to upgrade to nothing, or a client told it
    /// succeeded without being told to what. Only the `Upgrade` header
    /// itself is exempted — a `Connection` value's other nominations
    /// still strip what they name, and the caller writes its own
    /// `Connection: upgrade` line rather than forwarding whatever
    /// spelling arrived.
    keep_upgrade: bool,
    /// The caller's scratch for this render (see `HeadScratch`).
    scratch: *HeadScratch,
) error{Oversize}!void {
    assert(headers.len <= constants.headers_max);
    // One slot past the filter budget: the #178 Set-Cookie stamp.
    assert(edits.len <= constants.response_edits_max);
    // Collect the Connection header value(s) once (usually zero or one).
    // Re-finding them inside the per-header hop-by-hop test made the walk
    // O(headers²) — the render's top user-CPU cost under load (§9).
    const active_nominations = collectNominations(
        headers,
        connection_nominates_header,
        &scratch.connection_values,
    );

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
    // The same decision for the proxy's own three, and made here for the
    // same reason: a request this hop writes none of them for skips the
    // per-header tag dispatch entirely.
    const has_suppression = suppress.any();

    for (headers) |*header| {
        assert(header.name.len >= 1);
        if (isHopByHop(header, active_nominations)) {
            // The one exemption (#180): a participating `Upgrade` on a
            // hop this proxy has agreed to carry. Everything else the
            // hop-by-hop rule names, including whatever a `Connection`
            // value nominates beside it, still goes.
            const participating = keep_upgrade and header.tag == .upgrade;
            if (!participating) continue;
        }
        if (has_suppression and suppress.claims(header.tag)) {
            continue;
        }
        if (has_suppressing_edit and suppressedByEdit(header.name, edits)) {
            continue;
        }
        try staging.appendHeaderLine(header.name, header.value);
    }
    // Injected edits follow the surviving source headers; a `remove`
    // contributes no line (its whole effect is the suppression above).
    for (edits) |edit| {
        switch (edit.kind) {
            .set, .add => try staging.appendHeaderLine(edit.name, edit.value),
            .remove => {},
        }
    }
}

/// The Connection values that actually nominate a header to strip
/// (RFC 9110 §7.6.1), gathered once so the per-header test below is O(1)
/// rather than a token scan per header — re-finding them inside that test
/// made the walk O(headers²), the render's top user-CPU cost under load
/// (§9). Empty in the common case, where Connection carries only
/// `close`/`keep-alive` and nominates nothing.
///
/// The returned slice aliases `values`, which the caller owns.
fn collectNominations(
    headers: []const parser.Header,
    connection_nominates_header: bool,
    values: *[constants.headers_max][]const u8,
) []const []const u8 {
    assert(headers.len <= constants.headers_max);
    var count: u32 = 0;
    // Captures by pointer: `parser.Header` is 40 bytes, and copying one
    // per header is the cost this classification exists to remove, not to
    // relocate.
    for (headers) |*header| {
        if (header.tag == .connection) {
            values[count] = header.value;
            count += 1;
        }
    }
    // Whether anything is nominated was settled by
    // `parser.scanConnectionTokens`, which already walked these same
    // tokens to decide keep-alive. The flag and the values it describes
    // are filled in by two different passes, joined only by this bool: a
    // nomination with no Connection header to have carried it means they
    // have desynchronized.
    if (connection_nominates_header) {
        assert(count >= 1);
        return values[0..count];
    }
    return values[0..0];
}

/// True when a `set` or `remove` edit names this header, so its source
/// copies must not be forwarded (`add` never suppresses — it appends).
fn suppressedByEdit(name: []const u8, edits: []const filter.AppliedHeaderEdit) bool {
    assert(name.len >= 1);
    // One slot past the filter budget: the #178 Set-Cookie stamp.
    assert(edits.len <= constants.response_edits_max);
    for (edits) |edit| {
        switch (edit.kind) {
            .set, .remove => if (std.ascii.eqlIgnoreCase(name, edit.name)) return true,
            .add => {},
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
fn isHopByHop(header: *const parser.Header, nominations: []const []const u8) bool {
    assert(header.name.len >= 1);
    assert(nominations.len <= constants.headers_max);
    if (header.tag.hopByHop()) {
        return true;
    }
    if (header.tag.protected()) {
        return false;
    }
    // Only a nomination can still strip this one, and only a Connection
    // value naming a real header gets here (see `active_nominations`), so
    // the token scan stays off the common path.
    for (nominations) |value| {
        if (parser.tokenListHas(value, header.name)) {
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
/// `head_buffer_bytes_default` and overflowing it is the 431/teardown verdict.
const oracle_buffer_bytes = constants.head_buffer_bytes_default + @as(u32, constants.headers_max) + 64;

/// The one `HeadScratch` the tests below lend, which is exactly the shape
/// the serving path uses: a render at a time, so one buffer serves them
/// all. File scope rather than a local per test only to keep the call
/// sites reading as the assertions they are. Referenced from tests alone,
/// so a non-test build never analyses it.
var test_head_scratch: HeadScratch = undefined;

test "render: request strips hop-by-hop and nominated, keeps the rest" {
    const head = "GET /p HTTP/1.1\r\nHost: a\r\nConnection: close, X-Nominated\r\n" ++
        "Keep-Alive: timeout=5\r\nTE: trailers\r\nX-Nominated: v\r\nX-Keep: yes\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    var buffer: [oracle_buffer_bytes]u8 = undefined;

    const rendered = try renderRequestHead(&request, .{ .path = "/p", .query = "" }, &.{}, false, null, null, false, &test_head_scratch, &buffer);
    try testing.expectEqualStrings(
        "GET /p HTTP/1.1\r\nHost: a\r\nX-Keep: yes\r\n\r\n",
        rendered,
    );

    const closed = try renderRequestHead(&request, .{ .path = "/p", .query = "" }, &.{}, true, null, null, false, &test_head_scratch, &buffer);
    try testing.expectEqualStrings(
        "GET /p HTTP/1.1\r\nHost: a\r\nX-Keep: yes\r\nConnection: close\r\n\r\n",
        closed,
    );
}

test "render: an absolute-form authority replaces the client's Host" {
    // RFC 9112 §3.2.2: the received Host is ignored and the target's
    // authority used instead — so exactly one Host reaches the origin,
    // and it is the one that routed (#233).
    const head = "GET http://api.example:8080/v2/x HTTP/1.1\r\n" ++
        "Host: stale.example\r\nX-Keep: yes\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderRequestHead(
        &request,
        .{ .path = "/v2/x", .query = "" },
        &.{},
        false,
        null,
        null,
        false,
        &test_head_scratch,
        &buffer,
    );
    try testing.expectEqualStrings(
        "GET /v2/x HTTP/1.1\r\nHost: api.example:8080\r\nX-Keep: yes\r\n\r\n",
        rendered,
    );
    // The request line is origin-form downstream, whatever form arrived.
    var reparse_storage: parser.HeaderStorage = undefined;
    const reparsed = try parser.parseRequestHead(rendered, false, &reparse_storage);
    try testing.expectEqual(@as(?[]const u8, null), reparsed.authority);
    try testing.expectEqualStrings("api.example:8080", reparsed.host.?);
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
    const rendered = try renderRequestHead(&request, .{ .path = "/p", .query = "" }, &edits, false, null, null, false, &test_head_scratch, &buffer);
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
        renderRequestHead(&request, .{ .path = "/p", .query = "" }, &edits, false, null, null, false, &test_head_scratch, &tight),
    );
}

test "render: the edited oracle skips a head that grows past head_buffer_bytes_default" {
    // Regression: `parseRequestHead`'s first statement asserts
    // `head.len <= head_buffer_bytes_default`, so an edited head rendered past that
    // ceiling (into the slack oracle buffer) would trip that assert before
    // any error could surface — a panic reachable under `--fuzz`. The oracle
    // guards on `rendered.len`; this input, a source exactly at the ceiling
    // with a no-space colon (render re-adds ": ", +1 byte) plus the fixed
    // edits, is guaranteed over it. Without the guard the call panics.
    var source: [constants.head_buffer_bytes_default]u8 = undefined;
    const prefix = "GET / HTTP/1.1\r\nHost: a\r\nX:";
    @memcpy(source[0..prefix.len], prefix);
    // Pad the value so the whole head, including the terminating CRLF, is
    // exactly head_buffer_bytes_default bytes.
    const value_end = constants.head_buffer_bytes_default - "\r\n\r\n".len;
    @memset(source[prefix.len..value_end], 'x');
    @memcpy(source[value_end..], "\r\n\r\n");

    // The source is legal (head.len == head_buffer_bytes_default is within the limit).
    var storage: parser.HeaderStorage = undefined;
    const parsed = try parser.parseRequestHead(&source, false, &storage);
    try testing.expectEqual(@as(u32, constants.head_buffer_bytes_default), parsed.head_len);
    // Confirm the edited render genuinely crosses the ceiling — otherwise
    // this test would exercise nothing. (The edit set mirrors the oracle's.)
    const edits = [_]filter.AppliedHeaderEdit{
        .{ .kind = .set, .name = "X-Fuzz-Set", .value = "s" },
        .{ .kind = .add, .name = "X-Fuzz-Add", .value = "a" },
        .{ .kind = .remove, .name = "X-Fuzz-Remove", .value = "" },
    };
    var render_buf: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderRequestHead(&parsed, .{ .path = "/", .query = "" }, &edits, false, null, null, false, &test_head_scratch, &render_buf);
    try testing.expect(rendered.len > constants.head_buffer_bytes_default);
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
    const rendered = try renderRequestHead(&request, .{ .path = "/u", .query = "" }, &.{}, false, null, null, false, &test_head_scratch, &buffer);
    try testing.expectEqualStrings(
        "POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n",
        rendered,
    );
}

test "render: a nomination on a second Connection line still strips" {
    // Connection is a list field: two header lines combine as one list
    // (RFC 9110), so the nomination flag has to accumulate across them —
    // it is set by whichever line carries a non-option token. Pins that
    // OR, which the render walk now depends on and cannot see for itself.
    const head = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n" ++
        "Connection: X-Nominated\r\nX-Nominated: v\r\nX-Keep: k\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    try testing.expect(request.connection_nominates_header);
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderRequestHead(&request, .{ .path = "/", .query = "" }, &.{}, false, null, null, false, &test_head_scratch, &buffer);
    // Both Connection lines are hop-by-hop; X-Nominated goes because the
    // second line named it; X-Keep is untouched.
    try testing.expectEqualStrings(
        "GET / HTTP/1.1\r\nHost: a\r\nX-Keep: k\r\n\r\n",
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
    const rendered = try renderRequestHead(&request, .{ .path = "/", .query = "" }, &.{}, false, null, null, false, &test_head_scratch, &buffer);
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
    const rendered = try renderRequestHead(&request, .{ .path = "/u", .query = "" }, &.{}, false, null, null, false, &test_head_scratch, &buffer);

    var reparse_storage: parser.HeaderStorage = undefined;
    const reparsed = try parser.parseRequestHead(rendered, false, &reparse_storage);
    try testing.expectEqual(parser.BodyFraming.chunked, reparsed.framing);
}

test "render: client version is preserved" {
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead("GET / HTTP/1.0\r\n\r\n", false, &storage);
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderRequestHead(&request, .{ .path = "/", .query = "" }, &.{}, false, null, null, false, &test_head_scratch, &buffer);
    try testing.expectEqualStrings("GET / HTTP/1.0\r\n\r\n", rendered);
}

test "render: response preserves status line and strips hop-by-hop" {
    const head = "HTTP/1.1 418 I'm a teapot\r\nConnection: keep-alive\r\n" ++
        "Content-Length: 0\r\nX-Origin: yes\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const response = try parser.parseResponseHead(head, false, &storage, .get);
    var buffer: [oracle_buffer_bytes]u8 = undefined;

    const rendered = try renderResponseHead(&response, false, &.{}, false, &test_head_scratch, &buffer);
    try testing.expectEqualStrings(
        "HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\nX-Origin: yes\r\n\r\n",
        rendered,
    );

    const closed = try renderResponseHead(&response, true, &.{}, false, &test_head_scratch, &buffer);
    try testing.expectEqualStrings(
        "HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\nX-Origin: yes\r\n" ++
            "Connection: close\r\n\r\n",
        closed,
    );
}

test "render: response edits suppress, replace and append (#175)" {
    const head = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n" ++
        "Server: origin/1.0\r\nX-Keep: yes\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const response = try parser.parseResponseHead(head, false, &storage, .get);
    var buffer: [oracle_buffer_bytes]u8 = undefined;

    // A remove drops the origin's copy; a set replaces it at the append
    // position; an add appends beside whatever survives — the same
    // suppress-and-append machinery the request render proved.
    const edits = [_]filter.AppliedHeaderEdit{
        .{ .kind = .remove, .name = "server", .value = "" },
        .{ .kind = .set, .name = "X-Keep", .value = "edited" },
        .{ .kind = .add, .name = "Strict-Transport-Security", .value = "max-age=63072000" },
    };
    const rendered = try renderResponseHead(&response, false, &edits, false, &test_head_scratch, &buffer);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n" ++
            "X-Keep: edited\r\n" ++
            "Strict-Transport-Security: max-age=63072000\r\n\r\n",
        rendered,
    );

    // The close injection lands after the edits, exactly as it lands
    // after the origin's own headers.
    const closed = try renderResponseHead(&response, true, &edits, false, &test_head_scratch, &buffer);
    try testing.expect(std.mem.endsWith(u8, closed, "Connection: close\r\n\r\n"));

    // Growth from edits is a real overflow: the same head with an added
    // header must report Oversize into a buffer sized for the original.
    var tight: [head.len - 1]u8 = undefined;
    try testing.expectError(
        error.Oversize,
        renderResponseHead(&response, false, &edits, false, &test_head_scratch, &tight),
    );
}

test "render: bare status line without a reason phrase round-trips" {
    var storage: parser.HeaderStorage = undefined;
    const response = try parser.parseResponseHead("HTTP/1.0 204\r\n\r\n", false, &storage, .get);
    try testing.expectEqual(@as(?[]const u8, null), response.status_message);
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = try renderResponseHead(&response, false, &.{}, false, &test_head_scratch, &buffer);
    try testing.expectEqualStrings("HTTP/1.0 204\r\n\r\n", rendered);
}

test "render: a head that no longer fits is Oversize" {
    const head = "GET /path HTTP/1.1\r\nHost: origin.example\r\n\r\n";
    var storage: parser.HeaderStorage = undefined;
    const request = try parser.parseRequestHead(head, false, &storage);
    const target = parser.CanonicalTarget{ .path = "/path", .query = "" };
    var small: [16]u8 = undefined;
    try testing.expectError(error.Oversize, renderRequestHead(&request, target, &.{}, false, null, null, false, &test_head_scratch, &small));
}

// Fuzzing (§9 gate 2): whatever the parser accepts, the renderer must
// turn into a head the parser accepts again, with routing and framing
// intact and hop-by-hop headers gone.

/// The `targetViews` gate (§7), mirrored once for all three oracles
/// below: an origin-form target that will not canonicalize is a 400 and
/// never reaches the renderer (null here), while OPTIONS asterisk-form
/// has no path and forwards verbatim.
///
/// The discriminator is the *authority*, not the target's first byte,
/// for the same reason `targetViews` uses it (#233): an absolute-form
/// target that named only a query leaves a remainder beginning with '?',
/// which is origin-form's business to canonicalize and asterisk-form's
/// to be mistaken for. Kept in one function because three copies of this
/// gate is how the oracles came to mirror a rule production no longer
/// had — and an oracle that diverges panics on input the proxy accepts.
fn oracleTarget(
    request: *const parser.RequestHead,
    scratch: []u8,
) ?parser.CanonicalTarget {
    assert(request.target.len >= 1);
    if (request.authority == null and request.target[0] != '/') {
        return .{ .path = request.target, .query = "" };
    }
    return parser.canonicalTarget(request.target, scratch) catch null;
}

fn checkRequestRender(input: []const u8) void {
    var storage: parser.HeaderStorage = undefined;
    const request = parser.parseRequestHead(input, false, &storage) catch return;
    if (request.method == .connect) {
        return; // Never rendered: the proxy answers CONNECT itself.
    }
    var scratch: [constants.head_buffer_bytes_default]u8 = undefined;
    const target = oracleTarget(&request, &scratch) orelse return;

    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = renderRequestHead(&request, target, &.{}, false, null, null, false, &test_head_scratch, &buffer) catch unreachable;

    // The oracle buffer carries slack past `head_buffer_bytes_default` so normalization
    // growth never truncates the comparison; production renders into an
    // exactly-`head_buffer_bytes_default` buffer and 431s anything larger. A head that
    // grew past that ceiling here is that oversize verdict — not a reparse
    // input, and past the parser's own size precondition — so stop before it.
    if (rendered.len > constants.head_buffer_bytes_default) {
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
    // The Host the origin reads is the name the request *routed* on, and
    // exactly one of them reaches it: the absolute-form authority where
    // the request line carried one, the client's own header otherwise
    // (#233). Stated as `routingAuthority` rather than as `request.host`,
    // which is what this asserted before absolute-form existed — an
    // oracle demanding the overruled name would forbid the override.
    if (request.routingAuthority()) |expected| {
        assert(std.mem.eql(u8, reparsed.host.?, expected));
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
    var scratch: [constants.head_buffer_bytes_default]u8 = undefined;
    const target = oracleTarget(&request, &scratch) orelse return;

    // Names the fuzzed input cannot collide with a proxy-managed header on;
    // config forbids editing those, so the renderer never sees them.
    const edits = [_]filter.AppliedHeaderEdit{
        .{ .kind = .set, .name = "X-Fuzz-Set", .value = "s" },
        .{ .kind = .add, .name = "X-Fuzz-Add", .value = "a" },
        .{ .kind = .remove, .name = "X-Fuzz-Remove", .value = "" },
    };
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = renderRequestHead(&request, target, &edits, false, null, null, false, &test_head_scratch, &buffer) catch return;

    // The appended edits can push an already-large head past `head_buffer_bytes_default`
    // — the oversize-after-edits verdict (431 in production, which renders
    // into an exactly-`head_buffer_bytes_default` buffer). Past that ceiling the head is
    // not a reparse input and would trip the parser's size precondition, so
    // stop; a reparse miss below is then only the benign headers-count
    // overflow (source at `headers_max` plus the appended lines).
    if (rendered.len > constants.head_buffer_bytes_default) {
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
    const rendered = renderResponseHead(&response, false, &.{}, false, &test_head_scratch, &buffer) catch unreachable;

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
            // Absolute-form, and the one shape of it whose remainder is
            // not origin-form (#233): the oracles' gate must read the
            // authority rather than the first byte, or this renders a
            // request line the reparse cannot accept.
            "GET http://a?q HTTP/1.1\r\nHost: a\r\n\r\n",
            "GET http://a HTTP/1.1\r\nHost: elsewhere\r\nX-Forwarded-For: 1.1.1.1\r\n\r\n",
        },
    });
}

test "render: the fuzz oracles hold for every target form the parser admits" {
    // The oracles mirror `targetViews`, and a mirror is only worth
    // something while it still matches. When these three drifted from it
    // (#233), an absolute-form target whose remainder is query-only took
    // the asterisk-form branch, rendered `GET ?q HTTP/1.1`, and panicked
    // the oracle's own reparse — on input the proxy itself handles fine.
    // Reached from here rather than from the corpus, because the corpus
    // feeds the Smith's entropy rather than arriving as an input verbatim.
    const inputs = [_][]const u8{
        "GET http://a?q HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET http://a HTTP/1.1\r\nHost: elsewhere\r\n\r\n",
        "GET http://a/p?q HTTP/1.1\r\nHost: a\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /p?q HTTP/1.1\r\nHost: a\r\n\r\n",
    };
    for (inputs) |input| {
        checkRequestRender(input);
        checkRequestRenderEdited(input);
        checkRequestRenderForwarded(input);
    }
}

fn fuzzRenderInputs(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input_buffer: [constants.head_buffer_bytes_default]u8 = undefined;
    const input_len = smith.slice(&input_buffer);
    assert(input_len <= input_buffer.len);
    const input = input_buffer[0..input_len];
    checkRequestRender(input);
    checkRequestRenderEdited(input);
    checkRequestRenderForwarded(input);
    checkResponseRender(input);
}

/// The §9 reparse oracle with a §7 forwarded line added: a rendered head
/// must still parse as one, and the header must appear exactly once
/// however many the input carried.
///
/// The forwarded path is what this diff adds to the render's output, and
/// the oracle's whole claim is that the proxy never emits a request it
/// would itself reject — so the claim has to cover it. The suppression is
/// the part worth fuzzing: an input with several inbound
/// `X-Forwarded-For` headers must leave exactly one downstream, or the
/// origin and the next hop can read different clients out of one request.
fn checkRequestRenderForwarded(input: []const u8) void {
    var storage: parser.HeaderStorage = undefined;
    const request = parser.parseRequestHead(input, false, &storage) catch return;
    if (request.method == .connect) {
        return;
    }
    var scratch: [constants.head_buffer_bytes_default]u8 = undefined;
    const target = oracleTarget(&request, &scratch) orelse return;

    // A fixed value stands in for the caller's assembled one: what varies
    // here is the *input head*, and the value's own assembly is bounded
    // and unit-tested rather than fuzzed.
    const forwarded_for = "203.0.113.9";
    var buffer: [oracle_buffer_bytes]u8 = undefined;
    const rendered = renderRequestHead(
        &request,
        target,
        &.{},
        false,
        forwarded_for,
        null,
        false,
        &test_head_scratch,
        &buffer,
    ) catch return;
    if (rendered.len > constants.head_buffer_bytes_default) {
        return;
    }
    var reparse_storage: parser.HeaderStorage = undefined;
    // `catch return`, not `unreachable`, and for a reason the byte guard
    // above does not cover: `Staging` bounds bytes, never header *count*.
    // An input already carrying `headers_max` headers, none of them an
    // inbound `X-Forwarded-For` to suppress, renders one line more than
    // the parser will accept — short in bytes, over in count. That is the
    // §7 oversize verdict, which production answers 431, not a head this
    // oracle has anything left to say about. `checkRequestRenderEdited`
    // declines for the same reason: its edits can add lines too.
    const reparsed = parser.parseRequestHead(rendered, false, &reparse_storage) catch return;
    var seen: u32 = 0;
    for (reparsed.headers) |header| {
        if (header.tag == .x_forwarded_for) {
            assert(std.mem.eql(u8, header.value, forwarded_for));
            seen += 1;
        }
    }
    assert(seen == 1);
}
