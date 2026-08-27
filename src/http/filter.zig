//! §7 "filters are data, not code": per-listener request-processing rules,
//! compiled at config load (`config.zig`) into immutable arena tables and
//! interpreted per request — never scripted, never allocating. A rule is a
//! match (a conjunction of predicates over the parsed head, in the §7
//! canonical forms so a filter and the router never disagree) and an
//! ordered action list drawn from a closed enum. Cluster selection is NOT
//! an action: the route table owns the backend decision (§7), so filters
//! never compete with routing. This module holds the compiled shapes and
//! the interpreter (`firstVerdict`, `collectForward`); the config-load
//! compiler lives in `config.zig`.

const std = @import("std");

const constants = @import("../constants.zig");
const parser = @import("parser.zig");
const router = @import("router.zig");
const shed = @import("../shed.zig");

const assert = std.debug.assert;

/// One header predicate. Lives in `router.zig` since #302 gave the route
/// table its own header dimension: two matchers judging one header have
/// to judge it identically, so the predicate belongs in the module they
/// both import — the same argument that put `prefixMatches` there.
pub const HeaderMatch = router.HeaderMatch;

/// One CIDR prefix a `client` predicate admits (#177). The address is
/// canonical for its prefix — host bits are rejected at load — so
/// containment is a masked-prefix compare, never a normalization.
pub const Cidr = struct {
    address: std.Io.net.IpAddress,
    /// Prefix bits: 0..32 for IPv4, 0..64 for IPv6 — a client's IPv6
    /// identity is its /64, the same rule `hash.key: source_ip` keys on
    /// (§7): RFC 8981 rotates the low bits on a timer, and two features
    /// must not disagree about what a client is. The loader enforces
    /// both bounds.
    prefix_len: u8,

    /// Whether `client` falls inside this prefix. Family-strict: a v4
    /// client never matches a v6 prefix or vice versa — the accept path
    /// produces no mapped forms.
    pub fn contains(cidr: *const Cidr, client: *const std.Io.net.IpAddress) bool {
        return switch (cidr.address) {
            .ip4 => |prefix| switch (client.*) {
                .ip4 => |candidate| prefixBitsMatch(
                    u32,
                    std.mem.readInt(u32, &prefix.bytes, .big),
                    std.mem.readInt(u32, &candidate.bytes, .big),
                    cidr.prefix_len,
                ),
                .ip6 => false,
            },
            .ip6 => |prefix| switch (client.*) {
                .ip4 => false,
                .ip6 => |candidate| prefixBitsMatch(
                    u64,
                    std.mem.readInt(u64, prefix.bytes[0..8], .big),
                    std.mem.readInt(u64, candidate.bytes[0..8], .big),
                    cidr.prefix_len,
                ),
            },
        };
    }
};

/// The top `prefix_len` bits of two addresses compare equal. A zero
/// prefix admits everything — handled before the shift, whose amount
/// would otherwise be the type's whole width (illegal in Zig, and the
/// mathematical answer is "no bits compared" anyway).
fn prefixBitsMatch(comptime T: type, prefix: T, candidate: T, prefix_len: u8) bool {
    const width = @bitSizeOf(T);
    assert(prefix_len <= width);
    if (prefix_len == 0) {
        return true;
    }
    assert(prefix_len >= 1);
    const shift: std.math.Log2Int(T) = @intCast(width - prefix_len);
    return (prefix >> shift) == (candidate >> shift);
}

/// A rule's match: every present predicate must hold (a conjunction). A
/// null/empty field is "any", so an all-null match is an unconditional
/// rule. Host and path prefix are already canonical (§7), compared
/// byte-for-byte against the request's canonical host/path.
pub const Match = struct {
    /// Registered methods the rule applies to; null = any method.
    methods: ?std.EnumSet(parser.Method) = null,
    host: ?[]const u8 = null,
    path_prefix: ?[]const u8 = null,
    headers: []const HeaderMatch = &.{},
    /// CIDR prefixes the connection's client address must fall inside —
    /// any-of across the list, conjoined with the rest (#177). Empty =
    /// any client. Matched against the same address every other
    /// consumer reads (§6): the observed peer, or the PROXY-announced
    /// client on a `proxy_protocol` listener — never an
    /// `X-Forwarded-For` chain, which is client-supplied text.
    clients: []const Cidr = &.{},
};

/// One header edit's name and value (value unused for a remove).
pub const HeaderEdit = struct {
    name: []const u8,
    value: []const u8,
};

/// A canonical path-prefix rewrite of the *forwarded* request only
/// (routing already chose the cluster, §7): the matched `from` prefix is
/// replaced by `to`, and the result re-canonicalized before it goes
/// upstream. Both are validated canonical at config load.
pub const Rewrite = struct {
    from: []const u8,
    to: []const u8,
};

/// A redirect verdict (#176): a closed status and where to send the
/// client. Terminal like `reject` — the request is answered, never
/// forwarded — but unlike a reject its response is rendered per
/// request: the `Location` may depend on what was asked.
pub const Redirect = struct {
    status: u16,
    target: Target,

    pub const Target = union(enum) {
        /// A fixed `Location` value, sent verbatim — for targets that do
        /// not depend on the request.
        location: []const u8,
        /// Scheme (and optionally host) replaced; the request's own
        /// canonical path and query are carried through, so the config
        /// never restates what §7 already computed.
        composed: Composed,
    };

    pub const Composed = struct {
        /// Required, never guessed: behind a TLS terminator "keep the
        /// request's scheme" is wrong exactly when it matters, since
        /// every hop this proxy sees is plaintext (§1).
        scheme: Scheme,
        /// Replacement canonical host, or null to keep the request's.
        host: ?[]const u8 = null,
    };

    pub const Scheme = enum(u1) {
        http,
        https,

        pub fn prefix(scheme: Scheme) []const u8 {
            return switch (scheme) {
                .http => "http://",
                .https => "https://",
            };
        }
    };
};

/// The statuses a `redirect` action may name — the four with distinct
/// proxy-meaningful semantics (permanent/temporary × method-preserving),
/// on `reject_statuses`' single-source rule: config rejects any other
/// value at load and the responder renders exactly this set.
pub const redirect_statuses = [_]u16{ 301, 302, 307, 308 };

pub fn isRedirectStatus(status: u16) bool {
    for (redirect_statuses) |candidate| {
        if (candidate == status) {
            return true;
        }
    }
    return false;
}

/// The closed action enum (§7): no `pick cluster` (routing owns the
/// backend), no scripting. Anything past this is a Zig function in the
/// owning phase module, added at compile time.
pub const Action = union(enum) {
    /// Answer a static status and stop (§8 static-response machinery).
    reject: u16,
    /// Answer a redirect and stop (#176): rendered per request, since
    /// its `Location` may carry the request's own path.
    redirect: Redirect,
    /// Answer a configured body and stop (#159): this proxy responding
    /// as the origin — a maintenance page, a `robots.txt`, a health
    /// target. The page is pre-rendered at load and shared with every
    /// other reference to the same body and status, so the action
    /// carries a pointer, and serving it is the static path's one send.
    respond: *const shed.StaticPage,
    /// Set (replacing any existing), add (append), or remove a header on
    /// the forwarded request, applied during the head render.
    header_set: HeaderEdit,
    header_add: HeaderEdit,
    header_remove: []const u8,
    /// Rewrite the forwarded canonical path's prefix.
    rewrite_prefix: Rewrite,
};

/// One compiled rule: match, then its ordered actions.
pub const Rule = struct {
    match: Match,
    actions: []const Action,
};

/// A header edit flattened for the renderer: the three header actions
/// collapsed to one op plus the (config-validated) name and value. The
/// renderer suppresses source copies of a `set`/`remove` name and appends
/// a line for each `set`/`add`; `value` is unused for a `remove`. This is
/// the render's input contract — `collectHeaderEdits` produces it from the
/// rules a request matched.
pub const AppliedHeaderEdit = struct {
    kind: Kind,
    name: []const u8,
    value: []const u8,

    pub const Kind = enum(u8) { set, add, remove };
};

/// A response rule's match (#175): a conjunction over the origin's
/// response, mirroring `Match`'s "every present predicate must hold" —
/// an all-empty match is an unconditional rule. There is no method, host
/// or path here: those are request facts, and a response rule runs after
/// an await against the parsed *response* head only.
pub const ResponseMatch = struct {
    /// Exact statuses the rule applies to; empty = any status.
    statuses: []const u16 = &.{},
    /// A status class (the "5xx" spelling), or null for any. Compiled to
    /// the class digit so the check is one integer divide.
    status_class: ?u8 = null,
    headers: []const HeaderMatch = &.{},
};

/// The `status_class` vocabulary (#175): the five RFC 9110 classes, field
/// names being the JSON tokens exactly as `Pick`'s are. The loader
/// resolves one to its digit; the schema emits the closed set.
pub const StatusClass = enum(u8) {
    @"1xx" = 1,
    @"2xx" = 2,
    @"3xx" = 3,
    @"4xx" = 4,
    @"5xx" = 5,
};

/// One compiled response rule (#175). The actions compile straight to
/// the renderer's `AppliedHeaderEdit` contract rather than to `Action`:
/// reject and rewrite have no meaning on the way out, so the response
/// action set is exactly the three header verbs, and the load-time
/// rejection of the other arms is what lets this skip the union.
pub const ResponseRule = struct {
    match: ResponseMatch,
    edits: []const AppliedHeaderEdit,
};

/// The parsed response head a response rule matches against: the status
/// the origin answered and its headers (zero-copy slices, the request
/// side's own `parser.Header` shape).
pub const ResponseView = struct {
    status: u16,
    headers: []const parser.Header,
};

/// One pass over the response rules (#175), gathering every matched
/// rule's edits in rule-then-action order — `collectForward`'s shape
/// minus the concerns that do not exist on the way out (no reject: it
/// ran request-side; no rewrite: there is no path). The caller sizes
/// `out` at `header_edits_max`, which config caps a listener's response
/// edits at, so a matching subset always fits. Bounded loops over
/// immutable arena data; no allocation.
pub fn collectResponseEdits(
    rules: []const ResponseRule,
    view: ResponseView,
    out: []AppliedHeaderEdit,
) []const AppliedHeaderEdit {
    assert(out.len <= constants.header_edits_max);
    var count: usize = 0;
    for (rules) |rule| {
        if (!responseMatches(rule.match, view)) {
            continue;
        }
        for (rule.edits) |edit| {
            assert(count < out.len);
            out[count] = edit;
            count += 1;
        }
    }
    assert(count <= out.len);
    return out[0..count];
}

/// Whether a response rule's conjunction holds. No assertion on the
/// status's range: it is the origin's byte sequence, and a 999 from a
/// misbehaving origin must fail predicates, not the proxy — 999/100 is
/// 9, which equals no class.
fn responseMatches(match: ResponseMatch, view: ResponseView) bool {
    assert(view.headers.len <= constants.headers_max);
    if (match.statuses.len >= 1) {
        var found = false;
        for (match.statuses) |status| {
            if (status == view.status) {
                found = true;
            }
        }
        if (!found) {
            return false;
        }
    }
    if (match.status_class) |class| {
        assert(class >= 1);
        assert(class <= 5);
        if (view.status / 100 != class) {
            return false;
        }
    }
    for (match.headers) |header_match| {
        if (!router.headerMatches(header_match, view.headers)) {
            return false;
        }
    }
    return true;
}

/// The statuses a `reject` action may name — a subset of the §8 static
/// responses that make sense as a policy verdict. This array is the single
/// source of truth: config rejects any other value at load, the proxy's
/// filter-reject dispatch matches on exactly this set, and
/// `shed.staticResponse` must support each. Extend it in one place.
pub const reject_statuses = [_]u16{ 400, 403, 404, 429 };

pub fn isRejectStatus(status: u16) bool {
    for (reject_statuses) |candidate| {
        if (candidate == status) {
            return true;
        }
    }
    return false;
}

/// The parsed head a rule matches against, in the §7 canonical forms:
/// `host` is the canonical routing host (null when absent/unmatchable),
/// `path` the canonical request path (or "/" for asterisk-form), and
/// `headers` the parsed head's headers (zero-copy slices).
pub const RequestView = struct {
    method: parser.Method,
    host: ?[]const u8,
    path: []const u8,
    headers: []const parser.Header,
    /// The connection's client address (#177), by pointer like every
    /// address here (32 bytes, past TIGER_STYLE's by-value threshold).
    /// No default: a site that forgot to wire it must not compile, or a
    /// `client` allowlist would silently judge a zero address.
    ///
    /// Null on a `unix:` listener, where there is none (#303). Nothing
    /// here has to answer for that: the loader refuses a `client` match
    /// on such a listener, so a rule that would read it cannot reach one
    /// — which `clientMatches` asserts rather than assumes.
    client: ?*const std.Io.net.IpAddress,
};

/// A terminal filter answer: the request is responded to here and never
/// forwarded. The redirect rides by pointer — it lives in the rule's
/// arena and outlives the scan, and copying its slices buys nothing.
pub const Verdict = union(enum) {
    reject: u16,
    redirect: *const Redirect,
    /// A configured body answers (#159). Distinct from `reject` even
    /// where the status is one a reject could carry: a reject is policy
    /// refusing traffic, a respond is this proxy *being* the origin,
    /// and the counters and access-log outcomes stay separable for it.
    respond: *const shed.StaticPage,
};

/// The verdict of the first matching rule that carries a terminal
/// action — `reject` or `redirect` (#176) — or null to proceed (§7).
/// Rules are evaluated top-down and actions in order, so the first
/// terminal reached wins — and because it stops the request, any
/// header/rewrite edits are then moot (they apply only to a request
/// that forwards, handled at the render). Bounded loops over immutable
/// arena data; no allocation.
pub fn firstVerdict(rules: []const Rule, view: RequestView) ?Verdict {
    assert(view.path.len >= 1);
    assert(view.path[0] == '/');
    for (rules) |rule| {
        if (!matches(rule.match, view)) {
            continue;
        }
        for (rule.actions) |*action| {
            switch (action.*) {
                .reject => |status| {
                    assert(isRejectStatus(status));
                    return .{ .reject = status };
                },
                .redirect => |*redirect| {
                    assert(isRedirectStatus(redirect.status));
                    return .{ .redirect = redirect };
                },
                .respond => |page| {
                    assert(shed.isPageStatus(page.status));
                    return .{ .respond = page };
                },
                // Edits apply at the render, only when the request
                // forwards; a terminal anywhere in a matched rule stops it.
                .header_set, .header_add, .header_remove, .rewrite_prefix => {},
            }
        }
    }
    return null;
}

/// What the render phase applies to a forwarded request: the first
/// applicable path rewrite and the header edits of every matched rule.
pub const Forward = struct {
    /// First-applicable rewrite (see `collectForward`), or null.
    rewrite: ?Rewrite,
    /// Matched rules' header edits, in rule-then-action order.
    edits: []const AppliedHeaderEdit,
};

/// One pass over the rules a request matches, producing everything the
/// render phase needs (§7): the first applicable path rewrite and every
/// matched rule's header edits. A single scan — reject is evaluated earlier
/// at routing, before any resource is acquired, so the two render-phase
/// concerns share one walk rather than two, and `matches` is evaluated once
/// per rule.
///
/// The rewrite is first-applicable-wins: the first matching rule whose
/// `rewrite_prefix.from` is a segment-prefix of the path, and it never
/// chains — a later rule matched the original path, not the rewritten one,
/// so chaining has no coherent meaning. Header edits, by contrast, gather
/// from *every* matched rule. The caller sizes `out` at `header_edits_max`,
/// which config caps a listener's total header edits at, so a matching
/// subset always fits: the write is asserted in bounds. Bounded loops over
/// immutable arena data; no allocation. Called at render (a matched reject
/// would already have stopped the request at routing, so here every matched
/// rule forwards).
pub fn collectForward(
    rules: []const Rule,
    view: RequestView,
    out: []AppliedHeaderEdit,
) Forward {
    assert(view.path.len >= 1);
    assert(view.path[0] == '/');
    assert(out.len <= constants.header_edits_max);
    var rewrite: ?Rewrite = null;
    var count: usize = 0;
    for (rules) |rule| {
        if (!matches(rule.match, view)) {
            continue;
        }
        for (rule.actions) |action| switch (action) {
            .header_set, .header_add, .header_remove => {
                assert(count < out.len);
                out[count] = appliedEdit(action);
                count += 1;
            },
            .rewrite_prefix => |candidate| {
                if (rewrite == null and router.prefixMatches(candidate.from, view.path)) {
                    rewrite = candidate;
                }
            },
            .reject, .redirect, .respond => {},
        };
    }
    assert(count <= out.len);
    return .{ .rewrite = rewrite, .edits = out[0..count] };
}

/// Flatten a header-edit action into the renderer's `AppliedHeaderEdit`.
/// The caller has already narrowed `action` to the three header kinds.
fn appliedEdit(action: Action) AppliedHeaderEdit {
    return switch (action) {
        .header_set => |e| .{ .kind = .set, .name = e.name, .value = e.value },
        .header_add => |e| .{ .kind = .add, .name = e.name, .value = e.value },
        .header_remove => |name| .{ .kind = .remove, .name = name, .value = "" },
        .reject, .redirect, .respond, .rewrite_prefix => unreachable,
    };
}

/// The forwarded path with `rewrite.from` replaced by `rewrite.to`, written
/// into `out` (§7). A segment-correct join: the segments surviving past
/// `from` are rejoined to `to` with exactly one slash, so the result never
/// gains a `//` or merges two segments — whether or not `from`/`to` are
/// slash-terminated. This matters because a slash-terminated prefix (the
/// root `/` is one, so it matches every path) leaves a suffix that does NOT
/// begin with a slash: `from="/"`, `to="/x"`, `/foo` must yield `/x/foo`,
/// never `/xfoo`; and stripping to root (`to="/"`) yields `/foo`, never the
/// distinct resource `//foo`. `from` and `to` are validated canonical at
/// load and the surviving segments are a canonical path's tail, so the join
/// is canonical by construction (canonical form preserves empty segments, so
/// a second pass would not repair a `//` the join must never create).
/// `Oversize` when a longer `to` overruns `out` — the §7 oversize verdict.
/// `collectForward` already proved the prefix matches.
pub fn rewritePath(rewrite: Rewrite, path: []const u8, out: []u8) error{Oversize}![]const u8 {
    assert(path.len >= 1);
    assert(path[0] == '/');
    assert(router.prefixMatches(rewrite.from, path));
    assert(rewrite.to.len >= 1);
    assert(rewrite.to[0] == '/');
    // An exact match forwards `to` verbatim — its own trailing slash and all.
    var rest = path[rewrite.from.len..];
    if (rest.len == 0) {
        if (rewrite.to.len > out.len) {
            return error.Oversize;
        }
        @memcpy(out[0..rewrite.to.len], rewrite.to);
        assert(out[0] == '/');
        return out[0..rewrite.to.len];
    }
    // Rejoin with exactly one boundary slash: drop the suffix's leading
    // slash when it has one (a non-slash-terminated `from` leaves it) and
    // `to`'s trailing slash when it has one (root `to="/"` collapses to the
    // empty base, so the single separator we write is the whole prefix).
    if (rest[0] == '/') {
        rest = rest[1..];
    }
    const to_base = if (rewrite.to[rewrite.to.len - 1] == '/')
        rewrite.to[0 .. rewrite.to.len - 1]
    else
        rewrite.to;
    const total = to_base.len + 1 + rest.len;
    if (total > out.len) {
        return error.Oversize;
    }
    @memcpy(out[0..to_base.len], to_base);
    out[to_base.len] = '/';
    @memcpy(out[to_base.len + 1 .. total], rest);
    assert(out[0] == '/'); // `to_base` is empty (to=="/") or starts with '/'.
    assert(total >= 1);
    return out[0..total];
}

/// Whether a rule's match — a conjunction — holds for the request. A
/// null/empty field is "any"; host and path prefix compare in the §7
/// canonical forms (the path via the router's segment-boundary match, so
/// filters and routing agree byte-for-byte).
fn matches(match: Match, view: RequestView) bool {
    assert(view.path.len >= 1);
    assert(view.path[0] == '/'); // Canonical path — callers guarantee it.
    if (match.methods) |set| {
        if (!set.contains(view.method)) {
            return false;
        }
    }
    if (match.host) |host| {
        const request_host = view.host orelse return false;
        if (!std.mem.eql(u8, host, request_host)) {
            return false;
        }
    }
    if (match.path_prefix) |prefix| {
        if (!router.prefixMatches(prefix, view.path)) {
            return false;
        }
    }
    for (match.headers) |header_match| {
        if (!router.headerMatches(header_match, view.headers)) {
            return false;
        }
    }
    if (match.clients.len >= 1) {
        if (!clientMatches(match.clients, view.client)) {
            return false;
        }
    }
    return true;
}

/// Whether any prefix admits the client (#177) — the one any-of among
/// the conjunction's predicates, because a `client` list reads as "from
/// these ranges" and a client holds exactly one address.
fn clientMatches(cidrs: []const Cidr, client: ?*const std.Io.net.IpAddress) bool {
    assert(cidrs.len >= 1);
    // A rule carrying prefixes on a listener with no client address is
    // a config the loader refuses (`ListenerUnixBindClientMatch`, #303),
    // so reaching here without one is a caller past validation — and
    // guessing an answer would be an allowlist judging a fiction.
    const observed = client.?;
    for (cidrs) |*cidr| {
        assert(cidr.prefix_len <= 64);
        if (cidr.contains(observed)) {
            return true;
        }
    }
    return false;
}

/// The client address the pre-#177 view tests pass and ignore — no rule
/// in them carries a `clients` list, so nothing reads it. The CIDR tests
/// build their own.
const test_view_client = std.Io.net.IpAddress.parseLiteral("203.0.113.9:50000") catch unreachable;

test "filter: isRejectStatus admits exactly the reject_statuses set" {
    // Every member of the single-source-of-truth set is admitted.
    for (reject_statuses) |status| {
        try std.testing.expect(isRejectStatus(status));
    }
    try std.testing.expect(!isRejectStatus(200));
    try std.testing.expect(!isRejectStatus(500));
    try std.testing.expect(!isRejectStatus(503));
    // Pin the documented set so a drift (and the proxy's matching dispatch)
    // is caught here rather than at runtime.
    try std.testing.expectEqualSlices(u16, &.{ 400, 403, 404, 429 }, &reject_statuses);
}

test "filter: firstVerdict matches on method, host, path, header" {
    const H = parser.Header;
    const rules = [_]Rule{
        // Reject a POST to /admin from a specific host with a header set.
        .{
            .match = .{
                .methods = blk: {
                    var set = std.EnumSet(parser.Method){};
                    set.insert(.post);
                    break :blk set;
                },
                .host = "api.example",
                .path_prefix = "/admin",
                .headers = &.{.{ .name = "X-Env", .kind = .equals, .value = "prod" }},
            },
            .actions = &.{.{ .reject = 403 }},
        },
    };
    const prod = [_]H{H.init("x-env", "prod")};
    const dev = [_]H{H.init("X-Env", "dev")};

    // Full match → 403.
    try std.testing.expectEqual(@as(u16, 403), firstVerdict(&rules, .{
        .method = .post,
        .host = "api.example",
        .path = "/admin/users",
        .headers = &prod,
        .client = &test_view_client,
    }).?.reject);
    // Wrong method, host, path, or header value → no reject.
    try std.testing.expectEqual(@as(?Verdict, null), firstVerdict(&rules, .{
        .method = .get, // not POST
        .host = "api.example",
        .path = "/admin",
        .headers = &prod,
        .client = &test_view_client,
    }));
    try std.testing.expectEqual(@as(?Verdict, null), firstVerdict(&rules, .{
        .method = .post,
        .host = "other.example", // wrong host
        .path = "/admin",
        .headers = &prod,
        .client = &test_view_client,
    }));
    try std.testing.expectEqual(@as(?Verdict, null), firstVerdict(&rules, .{
        .method = .post,
        .host = "api.example",
        .path = "/public", // not under /admin
        .headers = &prod,
        .client = &test_view_client,
    }));
    try std.testing.expectEqual(@as(?Verdict, null), firstVerdict(&rules, .{
        .method = .post,
        .host = "api.example",
        .path = "/admin",
        .headers = &dev, // header value mismatch
        .client = &test_view_client,
    }));
    // A segment-splitting path must not match the /admin prefix.
    try std.testing.expectEqual(@as(?Verdict, null), firstVerdict(&rules, .{
        .method = .post,
        .host = "api.example",
        .path = "/administrator",
        .headers = &prod,
        .client = &test_view_client,
    }));
}

test "filter: an all-any match is unconditional; edit-only rules never reject" {
    const rules = [_]Rule{
        .{ .match = .{}, .actions = &.{
            .{ .header_set = .{ .name = "X-Via", .value = "zoxy" } },
        } },
        .{ .match = .{ .path_prefix = "/blocked" }, .actions = &.{.{ .reject = 404 }} },
    };
    const empty: []const parser.Header = &.{};
    // The edit-only rule matches everything but does not reject.
    try std.testing.expectEqual(@as(?Verdict, null), firstVerdict(&rules, .{
        .method = .get,
        .host = null,
        .path = "/anything",
        .headers = empty,
        .client = &test_view_client,
    }));
    // The second rule rejects its prefix.
    try std.testing.expectEqual(@as(u16, 404), firstVerdict(&rules, .{
        .method = .get,
        .host = null,
        .path = "/blocked/x",
        .headers = empty,
        .client = &test_view_client,
    }).?.reject);
}

test "filter: a redirect is a terminal verdict, first one wins" {
    const rules = [_]Rule{
        // An edit-only rule matches first and must not terminate.
        .{ .match = .{}, .actions = &.{
            .{ .header_set = .{ .name = "X-Via", .value = "zoxy" } },
        } },
        .{ .match = .{ .host = "www.example" }, .actions = &.{
            .{ .redirect = .{ .status = 301, .target = .{ .composed = .{
                .scheme = .https,
                .host = "example",
            } } } },
        } },
        // A later reject on the same host must never be reached.
        .{ .match = .{ .host = "www.example" }, .actions = &.{.{ .reject = 403 }} },
    };
    const empty: []const parser.Header = &.{};
    const verdict = firstVerdict(&rules, .{
        .method = .get,
        .host = "www.example",
        .path = "/",
        .headers = empty,
        .client = &test_view_client,
    }).?;
    try std.testing.expectEqual(@as(u16, 301), verdict.redirect.status);
    try std.testing.expectEqualStrings("example", verdict.redirect.target.composed.host.?);
    // Another host sails past both terminal rules.
    try std.testing.expectEqual(@as(?Verdict, null), firstVerdict(&rules, .{
        .method = .get,
        .host = "api.example",
        .path = "/",
        .headers = empty,
        .client = &test_view_client,
    }));
}

test "filter: isRedirectStatus admits exactly the redirect_statuses set" {
    for (redirect_statuses) |status| {
        try std.testing.expect(isRedirectStatus(status));
    }
    try std.testing.expect(!isRedirectStatus(200));
    try std.testing.expect(!isRedirectStatus(303)); // See Other: no proxy semantics here.
    try std.testing.expect(!isRedirectStatus(403));
    // Pin the documented set, `reject_statuses`' own rule.
    try std.testing.expectEqualSlices(u16, &.{ 301, 302, 307, 308 }, &redirect_statuses);
}

test "filter: collectForward gathers matching rules' edits in order" {
    const rules = [_]Rule{
        // Applies to every request: stamp a via header, drop cookies.
        .{ .match = .{}, .actions = &.{
            .{ .header_set = .{ .name = "X-Via", .value = "zoxy" } },
            .{ .header_remove = "Cookie" },
        } },
        // Applies only under /api: add a second via, and a reject that
        // collectForward must skip (it is not a header edit).
        .{ .match = .{ .path_prefix = "/api" }, .actions = &.{
            .{ .header_add = .{ .name = "X-Api", .value = "1" } },
            .{ .reject = 429 },
        } },
    };
    const empty: []const parser.Header = &.{};
    var buffer: [constants.header_edits_max]AppliedHeaderEdit = undefined;

    // A /public request matches only the first rule: two edits, no rewrite.
    const public = collectForward(&rules, .{
        .method = .get,
        .host = null,
        .path = "/public",
        .headers = empty,
        .client = &test_view_client,
    }, &buffer);
    try std.testing.expectEqual(@as(?Rewrite, null), public.rewrite);
    try std.testing.expectEqual(@as(usize, 2), public.edits.len);
    try std.testing.expectEqual(AppliedHeaderEdit.Kind.set, public.edits[0].kind);
    try std.testing.expectEqualStrings("X-Via", public.edits[0].name);
    try std.testing.expectEqual(AppliedHeaderEdit.Kind.remove, public.edits[1].kind);
    try std.testing.expectEqualStrings("Cookie", public.edits[1].name);

    // A /api request matches both rules; the reject action is skipped, so
    // three header edits survive in rule-then-action order.
    const api = collectForward(&rules, .{
        .method = .get,
        .host = null,
        .path = "/api/v1",
        .headers = empty,
        .client = &test_view_client,
    }, &buffer);
    try std.testing.expectEqual(@as(usize, 3), api.edits.len);
    try std.testing.expectEqualStrings("X-Via", api.edits[0].name);
    try std.testing.expectEqualStrings("Cookie", api.edits[1].name);
    try std.testing.expectEqual(AppliedHeaderEdit.Kind.add, api.edits[2].kind);
    try std.testing.expectEqualStrings("X-Api", api.edits[2].name);
}

test "filter: collectForward picks the first applicable rewrite only" {
    const empty: []const parser.Header = &.{};
    var buffer: [constants.header_edits_max]AppliedHeaderEdit = undefined;
    const rules = [_]Rule{
        // Matches, but its rewrite's `from` is not a prefix of the path —
        // skipped, so the scan continues to the next rule.
        .{ .match = .{}, .actions = &.{
            .{ .rewrite_prefix = .{ .from = "/other", .to = "/x" } },
        } },
        // First applicable rewrite: matches and `/api` prefixes the path.
        .{ .match = .{}, .actions = &.{
            .{ .rewrite_prefix = .{ .from = "/api", .to = "/v2" } },
        } },
        // A later applicable rewrite that must never win (first wins).
        .{ .match = .{}, .actions = &.{
            .{ .rewrite_prefix = .{ .from = "/api", .to = "/v3" } },
        } },
    };
    const hit = collectForward(&rules, .{
        .method = .get,
        .host = null,
        .path = "/api/users",
        .headers = empty,
        .client = &test_view_client,
    }, &buffer);
    try std.testing.expect(hit.rewrite != null);
    try std.testing.expectEqualStrings("/api", hit.rewrite.?.from);
    try std.testing.expectEqualStrings("/v2", hit.rewrite.?.to);
    try std.testing.expectEqual(@as(usize, 0), hit.edits.len); // rewrite-only rules

    // No rewrite's `from` prefixes a /public path → null.
    const miss = collectForward(&rules, .{
        .method = .get,
        .host = null,
        .path = "/public",
        .headers = empty,
        .client = &test_view_client,
    }, &buffer);
    try std.testing.expectEqual(@as(?Rewrite, null), miss.rewrite);
}

test "filter: rewritePath is a segment-correct prefix replacement" {
    var out: [64]u8 = undefined;
    const cases = [_]struct { from: []const u8, to: []const u8, path: []const u8, want: []const u8 }{
        // Ordinary replacement, suffix carries its own slash.
        .{ .from = "/api", .to = "/v2", .path = "/api/users", .want = "/v2/users" },
        // Exact match, empty suffix → just `to`.
        .{ .from = "/api", .to = "/v2", .path = "/api", .want = "/v2" },
        // Strip a prefix to root: `to == "/"` must not double the slash.
        .{ .from = "/api", .to = "/", .path = "/api/users", .want = "/users" },
        // `to` exactly root, exact match → root.
        .{ .from = "/api", .to = "/", .path = "/api", .want = "/" },
        // A `to` that itself ends in a slash also dedups the boundary.
        .{ .from = "/api", .to = "/v2/", .path = "/api/users", .want = "/v2/users" },
        // Multi-segment from and to.
        .{ .from = "/a/b", .to = "/c/d", .path = "/a/b/e/f", .want = "/c/d/e/f" },
        // Slash-terminated `from` — the root prefix matches every path and
        // leaves a suffix that does NOT start with a slash; the join must
        // still put exactly one slash between `to` and the survivors.
        .{ .from = "/", .to = "/x", .path = "/foo", .want = "/x/foo" },
        .{ .from = "/", .to = "/x", .path = "/", .want = "/x" },
        // `to == "/"` with the root `from`: prepend nothing, keep the path.
        .{ .from = "/", .to = "/", .path = "/foo/bar", .want = "/foo/bar" },
        // An explicitly slash-terminated `from` prefix.
        .{ .from = "/api/", .to = "/v2", .path = "/api/foo", .want = "/v2/foo" },
        // Trailing slash preserved when the whole path is the prefix.
        .{ .from = "/api", .to = "/v2", .path = "/api/", .want = "/v2/" },
    };
    for (cases) |case| {
        const got = try rewritePath(
            .{ .from = case.from, .to = case.to },
            case.path,
            &out,
        );
        try std.testing.expectEqualStrings(case.want, got);
        // The result must be what canonicalization would produce — the join
        // yields canonical output directly, no second pass.
        var canon: [constants.head_buffer_bytes_default]u8 = undefined;
        const recanon = try parser.canonicalTarget(got, &canon);
        try std.testing.expectEqualStrings(got, recanon.path);
    }
}

test "filter: cidr containment is a masked prefix compare, family-strict" {
    const office: Cidr = .{
        .address = std.Io.net.IpAddress.parse("10.0.0.0", 0) catch unreachable,
        .prefix_len = 8,
    };
    const exact: Cidr = .{
        .address = std.Io.net.IpAddress.parse("192.168.1.7", 0) catch unreachable,
        .prefix_len = 32,
    };
    const any4: Cidr = .{
        .address = std.Io.net.IpAddress.parse("0.0.0.0", 0) catch unreachable,
        .prefix_len = 0,
    };
    const site6: Cidr = .{
        .address = std.Io.net.IpAddress.parse("2001:db8:1::", 0) catch unreachable,
        .prefix_len = 48,
    };

    const inside = std.Io.net.IpAddress.parseLiteral("10.255.0.1:1") catch unreachable;
    const outside = std.Io.net.IpAddress.parseLiteral("11.0.0.1:1") catch unreachable;
    const the_host = std.Io.net.IpAddress.parseLiteral("192.168.1.7:9") catch unreachable;
    const neighbor = std.Io.net.IpAddress.parseLiteral("192.168.1.8:9") catch unreachable;
    const v6_inside = std.Io.net.IpAddress.parseLiteral("[2001:db8:1:2::5]:1") catch unreachable;
    const v6_outside = std.Io.net.IpAddress.parseLiteral("[2001:db8:2::5]:1") catch unreachable;

    // The /8 boundary: the top byte decides, the rest is host space.
    try std.testing.expect(office.contains(&inside));
    try std.testing.expect(!office.contains(&outside));
    // /32 is one host exactly.
    try std.testing.expect(exact.contains(&the_host));
    try std.testing.expect(!exact.contains(&neighbor));
    // /0 admits every address of its family — and only its family:
    // the port is irrelevant and a v6 client is not a v4 one.
    try std.testing.expect(any4.contains(&inside));
    try std.testing.expect(any4.contains(&neighbor));
    try std.testing.expect(!any4.contains(&v6_inside));
    // A v6 site prefix, judged on the upper 64 bits.
    try std.testing.expect(site6.contains(&v6_inside));
    try std.testing.expect(!site6.contains(&v6_outside));
    try std.testing.expect(!site6.contains(&inside));
}

test "filter: a client predicate is any-of, conjoined with the rest" {
    const office: Cidr = .{
        .address = std.Io.net.IpAddress.parse("10.0.0.0", 0) catch unreachable,
        .prefix_len = 8,
    };
    const lab: Cidr = .{
        .address = std.Io.net.IpAddress.parse("192.168.1.0", 0) catch unreachable,
        .prefix_len = 24,
    };
    // The issue's own rule: /admin from the office ranges and nowhere
    // else — spelled as a reject of everything the allowlist misses,
    // conjoined with the path.
    const rules = [_]Rule{
        .{
            .match = .{ .path_prefix = "/admin", .clients = &.{ office, lab } },
            .actions = &.{.{ .header_set = .{ .name = "X-Office", .value = "1" } }},
        },
        .{ .match = .{ .path_prefix = "/admin" }, .actions = &.{.{ .reject = 403 }} },
    };
    const empty: []const parser.Header = &.{};
    const office_client = std.Io.net.IpAddress.parseLiteral("10.1.2.3:40000") catch unreachable;
    const lab_client = std.Io.net.IpAddress.parseLiteral("192.168.1.9:40000") catch unreachable;
    const stranger = std.Io.net.IpAddress.parseLiteral("203.0.113.9:40000") catch unreachable;

    // Everyone hits the 403 rule on /admin — it carries no client list —
    // so the reject-first scan reads it for all three; what the CIDR
    // predicate decides is whether the *first* rule matched too, visible
    // through its edit below.
    var buffer: [constants.header_edits_max]AppliedHeaderEdit = undefined;
    const from_office = collectForward(&rules, .{
        .method = .get,
        .host = null,
        .path = "/admin",
        .headers = empty,
        .client = &office_client,
    }, &buffer);
    try std.testing.expectEqual(@as(usize, 1), from_office.edits.len);
    const from_lab = collectForward(&rules, .{
        .method = .get,
        .host = null,
        .path = "/admin",
        .headers = empty,
        .client = &lab_client,
    }, &buffer);
    try std.testing.expectEqual(@as(usize, 1), from_lab.edits.len);
    const from_stranger = collectForward(&rules, .{
        .method = .get,
        .host = null,
        .path = "/admin",
        .headers = empty,
        .client = &stranger,
    }, &buffer);
    try std.testing.expectEqual(@as(usize, 0), from_stranger.edits.len);
    // Off the path, the client list alone matches nothing: conjunction.
    const off_path = collectForward(&rules, .{
        .method = .get,
        .host = null,
        .path = "/public",
        .headers = empty,
        .client = &office_client,
    }, &buffer);
    try std.testing.expectEqual(@as(usize, 0), off_path.edits.len);
}

test "filter: response rules match on status, class and headers" {
    const H = parser.Header;
    const rules = [_]ResponseRule{
        // Unconditional: every response sheds its Server header.
        .{ .match = .{}, .edits = &.{
            .{ .kind = .remove, .name = "Server", .value = "" },
        } },
        // Class-scoped: 5xx answers advertise a retry.
        .{ .match = .{ .status_class = 5 }, .edits = &.{
            .{ .kind = .set, .name = "Retry-After", .value = "1" },
        } },
        // Exact statuses and a header predicate, conjoined.
        .{ .match = .{
            .statuses = &.{ 301, 302 },
            .headers = &.{.{ .name = "Location", .kind = .contains, .value = "http:" }},
        }, .edits = &.{
            .{ .kind = .add, .name = "X-Insecure-Redirect", .value = "1" },
        } },
    };
    var out: [constants.header_edits_max]AppliedHeaderEdit = undefined;

    // A 200 matches only the unconditional rule.
    const ok = collectResponseEdits(&rules, .{ .status = 200, .headers = &.{} }, &out);
    try std.testing.expectEqual(@as(usize, 1), ok.len);
    try std.testing.expectEqualStrings("Server", ok[0].name);

    // A 503 gathers the unconditional and the class rule, in rule order.
    const shed_edits = collectResponseEdits(&rules, .{ .status = 503, .headers = &.{} }, &out);
    try std.testing.expectEqual(@as(usize, 2), shed_edits.len);
    try std.testing.expectEqualStrings("Retry-After", shed_edits[1].name);
    // The class boundaries are the RFC's: 499 is not a 5xx, 599 is.
    try std.testing.expectEqual(
        @as(usize, 1),
        collectResponseEdits(&rules, .{ .status = 499, .headers = &.{} }, &out).len,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        collectResponseEdits(&rules, .{ .status = 599, .headers = &.{} }, &out).len,
    );

    // The third rule's conjunction: status in the exact list AND the
    // header predicate. An https redirect keeps only the unconditional
    // edit; an http one gains the marker; a 303 is off the list.
    const insecure = [_]H{H.init("location", "http://x/")};
    const secure = [_]H{H.init("Location", "https://x/")};
    try std.testing.expectEqual(
        @as(usize, 2),
        collectResponseEdits(&rules, .{ .status = 301, .headers = &insecure }, &out).len,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        collectResponseEdits(&rules, .{ .status = 301, .headers = &secure }, &out).len,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        collectResponseEdits(&rules, .{ .status = 303, .headers = &insecure }, &out).len,
    );
}

test "filter: the status-class vocabulary maps each token to its digit" {
    // The enum's field names ARE the JSON tokens and its values the
    // class digits — the loader leans on both, so pin the pairing.
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(StatusClass.@"1xx"));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(StatusClass.@"2xx"));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(StatusClass.@"3xx"));
    try std.testing.expectEqual(@as(u8, 4), @intFromEnum(StatusClass.@"4xx"));
    try std.testing.expectEqual(@as(u8, 5), @intFromEnum(StatusClass.@"5xx"));
    try std.testing.expectEqual(@as(usize, 5), @typeInfo(StatusClass).@"enum".fields.len);
}

test "filter: rewritePath reports Oversize when the result would not fit" {
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.Oversize, rewritePath(
        .{ .from = "/a", .to = "/longer" },
        "/a/x",
        &tiny,
    ));
}
