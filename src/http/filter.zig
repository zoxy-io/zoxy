//! §7 "filters are data, not code": per-listener request-processing rules,
//! compiled at config load (`config.zig`) into immutable arena tables and
//! interpreted per request — never scripted, never allocating. A rule is a
//! match (a conjunction of predicates over the parsed head, in the §7
//! canonical forms so a filter and the router never disagree) and an
//! ordered action list drawn from a closed enum. Cluster selection is NOT
//! an action: the route table owns the backend decision (§7), so filters
//! never compete with routing. This module holds the compiled shapes; the
//! interpreter and the config-load compiler live in slices to come.

const std = @import("std");

const constants = @import("../constants.zig");
const parser = @import("parser.zig");
const router = @import("router.zig");

const assert = std.debug.assert;

/// A single header predicate: the named header must be present, or equal,
/// or contain the given value (case-insensitive name, per RFC 9110).
pub const HeaderMatch = struct {
    name: []const u8,
    kind: Kind,
    /// Unused for `.present`; the compared value otherwise.
    value: []const u8,

    pub const Kind = enum(u8) { present, equals, contains };
};

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

/// The closed action enum (§7): no `pick cluster` (routing owns the
/// backend), no scripting. Anything past this is a Zig function in the
/// owning phase module, added at compile time.
pub const Action = union(enum) {
    /// Answer a static status and stop (§8 static-response machinery).
    reject: u16,
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

/// The statuses a `reject` action may name — a subset of the §8 static
/// responses that make sense as a policy verdict. Config rejects any
/// other value at load, and `shed.staticResponse` must support each.
pub fn isRejectStatus(status: u16) bool {
    return switch (status) {
        400, 403, 404, 429 => true,
        else => false,
    };
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
};

/// The reject status of the first matching rule that carries a `reject`
/// action, or null to proceed (§7). Rules are evaluated top-down and
/// actions in order, so the first reject reached wins — and because a
/// matched rule's reject stops the request, any header/rewrite edits are
/// then moot (they apply only to a request that forwards, handled at the
/// render). Bounded loops over immutable arena data; no allocation.
pub fn firstReject(rules: []const Rule, view: RequestView) ?u16 {
    assert(view.path.len >= 1);
    assert(view.path[0] == '/');
    for (rules) |rule| {
        if (!matches(rule.match, view)) {
            continue;
        }
        for (rule.actions) |action| {
            switch (action) {
                .reject => |status| {
                    assert(isRejectStatus(status));
                    return status;
                },
                // Edits apply at the render, only when the request
                // forwards; a reject anywhere in a matched rule stops it.
                .header_set, .header_add, .header_remove, .rewrite_prefix => {},
            }
        }
    }
    return null;
}

/// The header edits of every rule that matches `view`, in rule-then-action
/// order, written into `out` and returned as its filled prefix (§7).
/// `reject`/`rewrite_prefix` actions are skipped — this collects only the
/// header edits the renderer applies. The caller sizes `out` at
/// `header_edits_max`, which config caps a listener's total header edits
/// at, so a matching subset always fits: the write is asserted in bounds.
/// Bounded loops over immutable arena data; no allocation. Called at render
/// (a matched reject would already have stopped the request at routing, so
/// here every matched rule forwards and its edits apply).
pub fn collectHeaderEdits(
    rules: []const Rule,
    view: RequestView,
    out: []AppliedHeaderEdit,
) []const AppliedHeaderEdit {
    assert(view.path.len >= 1);
    assert(out.len <= constants.header_edits_max);
    var count: usize = 0;
    for (rules) |rule| {
        if (!matches(rule.match, view)) {
            continue;
        }
        for (rule.actions) |action| {
            const edit: ?AppliedHeaderEdit = switch (action) {
                .header_set => |e| .{ .kind = .set, .name = e.name, .value = e.value },
                .header_add => |e| .{ .kind = .add, .name = e.name, .value = e.value },
                .header_remove => |name| .{ .kind = .remove, .name = name, .value = "" },
                .reject, .rewrite_prefix => null,
            };
            if (edit) |value| {
                assert(count < out.len);
                out[count] = value;
                count += 1;
            }
        }
    }
    assert(count <= out.len);
    return out[0..count];
}

/// The rewrite of the first matching rule whose `rewrite_prefix.from` is a
/// segment-prefix of the forwarded path, or null (§7). First-applicable
/// wins — like `firstReject`, and unlike the collected header edits — so a
/// rewrite is predictable and never chains: a later rule matches on the
/// original path, not the rewritten one, so chaining has no coherent
/// meaning. Routing already chose the cluster from this same path; the
/// rewrite changes only what is forwarded, never the route.
pub fn firstRewrite(rules: []const Rule, view: RequestView) ?Rewrite {
    assert(view.path.len >= 1);
    assert(view.path[0] == '/');
    for (rules) |rule| {
        if (!matches(rule.match, view)) {
            continue;
        }
        for (rule.actions) |action| switch (action) {
            .rewrite_prefix => |rewrite| {
                if (router.prefixMatches(rewrite.from, view.path)) {
                    return rewrite;
                }
            },
            .reject, .header_set, .header_add, .header_remove => {},
        };
    }
    return null;
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
/// `firstRewrite` already proved the prefix matches.
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
        if (!headerMatches(header_match, view.headers)) {
            return false;
        }
    }
    return true;
}

/// Whether some header satisfies the predicate. Name comparison is
/// case-insensitive (RFC 9110); `equals`/`contains` compare the value
/// byte-exact / by substring. Multiple headers of the same name each get
/// a chance — the predicate holds if any does.
fn headerMatches(header_match: HeaderMatch, headers: []const parser.Header) bool {
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, header_match.name)) {
            continue;
        }
        switch (header_match.kind) {
            .present => return true,
            .equals => if (std.mem.eql(u8, header.value, header_match.value)) return true,
            .contains => if (std.mem.indexOf(u8, header.value, header_match.value) != null) return true,
        }
    }
    return false;
}

test "filter: isRejectStatus admits the policy set only" {
    try std.testing.expect(isRejectStatus(403));
    try std.testing.expect(isRejectStatus(429));
    try std.testing.expect(!isRejectStatus(200));
    try std.testing.expect(!isRejectStatus(503));
}

test "filter: firstReject matches on method, host, path, header" {
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
    const prod = [_]H{.{ .name = "x-env", .value = "prod" }};
    const dev = [_]H{.{ .name = "X-Env", .value = "dev" }};

    // Full match → 403.
    try std.testing.expectEqual(@as(?u16, 403), firstReject(&rules, .{
        .method = .post,
        .host = "api.example",
        .path = "/admin/users",
        .headers = &prod,
    }));
    // Wrong method, host, path, or header value → no reject.
    try std.testing.expectEqual(@as(?u16, null), firstReject(&rules, .{
        .method = .get, // not POST
        .host = "api.example",
        .path = "/admin",
        .headers = &prod,
    }));
    try std.testing.expectEqual(@as(?u16, null), firstReject(&rules, .{
        .method = .post,
        .host = "other.example", // wrong host
        .path = "/admin",
        .headers = &prod,
    }));
    try std.testing.expectEqual(@as(?u16, null), firstReject(&rules, .{
        .method = .post,
        .host = "api.example",
        .path = "/public", // not under /admin
        .headers = &prod,
    }));
    try std.testing.expectEqual(@as(?u16, null), firstReject(&rules, .{
        .method = .post,
        .host = "api.example",
        .path = "/admin",
        .headers = &dev, // header value mismatch
    }));
    // A segment-splitting path must not match the /admin prefix.
    try std.testing.expectEqual(@as(?u16, null), firstReject(&rules, .{
        .method = .post,
        .host = "api.example",
        .path = "/administrator",
        .headers = &prod,
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
    try std.testing.expectEqual(@as(?u16, null), firstReject(&rules, .{
        .method = .get,
        .host = null,
        .path = "/anything",
        .headers = empty,
    }));
    // The second rule rejects its prefix.
    try std.testing.expectEqual(@as(?u16, 404), firstReject(&rules, .{
        .method = .get,
        .host = null,
        .path = "/blocked/x",
        .headers = empty,
    }));
}

test "filter: collectHeaderEdits gathers matching rules' edits in order" {
    const rules = [_]Rule{
        // Applies to every request: stamp a via header, drop cookies.
        .{ .match = .{}, .actions = &.{
            .{ .header_set = .{ .name = "X-Via", .value = "zoxy" } },
            .{ .header_remove = "Cookie" },
        } },
        // Applies only under /api: add a second via, and a reject that
        // collectHeaderEdits must skip (it is not a header edit).
        .{ .match = .{ .path_prefix = "/api" }, .actions = &.{
            .{ .header_add = .{ .name = "X-Api", .value = "1" } },
            .{ .reject = 429 },
        } },
    };
    const empty: []const parser.Header = &.{};
    var buffer: [constants.header_edits_max]AppliedHeaderEdit = undefined;

    // A /public request matches only the first rule: two edits.
    const public = collectHeaderEdits(&rules, .{
        .method = .get,
        .host = null,
        .path = "/public",
        .headers = empty,
    }, &buffer);
    try std.testing.expectEqual(@as(usize, 2), public.len);
    try std.testing.expectEqual(AppliedHeaderEdit.Kind.set, public[0].kind);
    try std.testing.expectEqualStrings("X-Via", public[0].name);
    try std.testing.expectEqual(AppliedHeaderEdit.Kind.remove, public[1].kind);
    try std.testing.expectEqualStrings("Cookie", public[1].name);

    // A /api request matches both rules; the reject action is skipped, so
    // three header edits survive in rule-then-action order.
    const api = collectHeaderEdits(&rules, .{
        .method = .get,
        .host = null,
        .path = "/api/v1",
        .headers = empty,
    }, &buffer);
    try std.testing.expectEqual(@as(usize, 3), api.len);
    try std.testing.expectEqualStrings("X-Via", api[0].name);
    try std.testing.expectEqualStrings("Cookie", api[1].name);
    try std.testing.expectEqual(AppliedHeaderEdit.Kind.add, api[2].kind);
    try std.testing.expectEqualStrings("X-Api", api[2].name);
}

test "filter: firstRewrite picks the first applicable rewrite only" {
    const empty: []const parser.Header = &.{};
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
    const hit = firstRewrite(&rules, .{
        .method = .get,
        .host = null,
        .path = "/api/users",
        .headers = empty,
    });
    try std.testing.expect(hit != null);
    try std.testing.expectEqualStrings("/api", hit.?.from);
    try std.testing.expectEqualStrings("/v2", hit.?.to);

    // No rewrite's `from` prefixes a /public path → null.
    try std.testing.expectEqual(@as(?Rewrite, null), firstRewrite(&rules, .{
        .method = .get,
        .host = null,
        .path = "/public",
        .headers = empty,
    }));
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
        var canon: [constants.head_bytes_max]u8 = undefined;
        const recanon = try parser.canonicalTarget(got, &canon);
        try std.testing.expectEqualStrings(got, recanon.path);
    }
}

test "filter: rewritePath reports Oversize when the result would not fit" {
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.Oversize, rewritePath(
        .{ .from = "/a", .to = "/longer" },
        "/a/x",
        &tiny,
    ));
}
