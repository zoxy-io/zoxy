//! §7 routing: map a request's canonical host and path to a cluster
//! through a per-listener table. Host is the outer dimension — a
//! host-specific route beats an any-host one — and path is longest-prefix
//! within that. Pure: the table is built, validated, and sorted at config
//! load (`config.zig`) so a host-specific match precedes any any-host
//! match and each group is longest-prefix-first, making a request-time
//! match a bounded linear scan over immutable arena data, never an
//! allocation on the loop. No match is a real outcome: the caller
//! answers 404 (§8).

const std = @import("std");

const constants = @import("../constants.zig");
const parser = @import("parser.zig");

const assert = std.debug.assert;

/// One header predicate. Here rather than in `filter.zig` because both
/// matchers use it since #302, and two matchers judging one header have
/// to judge it identically — the same argument that made `prefixMatches`
/// public for filters to share. `filter.HeaderMatch` aliases this.
///
/// The route table only ever builds `present` and `equals`: a substring
/// scan is a different cost on a path every request walks, and §7 draws
/// the line where a route dimension would become a second match engine.
/// The `contains` arm is the filter table's, and lives here so one
/// evaluator answers for both.
pub const HeaderMatch = struct {
    name: []const u8,
    kind: Kind,
    /// Unused for `.present`; the compared value otherwise.
    value: []const u8,

    pub const Kind = enum(u8) { present, equals, contains };
};

/// One routing rule: a canonical path prefix and the cluster it selects,
/// optionally scoped to a canonical host (`null` = any host) and to a
/// header the request must carry (`null` = any request, #302). Every key
/// is validated at config load (§7), so each compares directly against
/// the request with no per-request work.
///
/// The three are a **conjunction**: a route matches when every constraint
/// it states holds, which is how Envoy's `RouteMatch` composes its own
/// and what keeps this one table rather than two engines. What differs is
/// the tie-break — Envoy takes the first route in config order, where
/// this table is sorted at load, so config order cannot change which of
/// two differently-specific routes wins.
pub const Route = struct {
    host: ?[]const u8 = null,
    prefix: []const u8,
    header: ?HeaderMatch = null,
    cluster_index: u16,
};

/// The cluster for a request's canonical `host` (null when the request
/// carried no usable Host), canonical `path` and headers, or null when
/// nothing matches (the caller's 404, §8).
///
/// `routes` is sorted most-specific-first at config load, so the first
/// match is the answer: **host, then header, then prefix** (#302). A
/// route scoped to the request's host beats every any-host route; within
/// that group one naming a header beats one that does not; and within
/// that, the longest prefix wins.
///
/// That ordering is a decision rather than an inevitability. No peer
/// ranks routing dimensions at all — Envoy and HAProxy take the first
/// match in *config order*, Traefik sorts by rule length — and this table
/// faces the question only because it sorts, which is what makes the
/// answer independent of the order an operator happened to write the
/// rules in — for every pair these tiers can separate. Two routes that
/// share a host and a prefix while naming different headers are distinct
/// rules of equal specificity, and `config.zig` breaks that one tie by
/// config order, explicitly. Host outermost is Envoy's own nesting, where a
/// `virtual_host` is selected by domain and header matching happens on
/// the routes inside it; it also reads right for the case #302 exists
/// for, since a canary is a variant of a service, not a different one.
pub fn route(
    routes: []const Route,
    host: ?[]const u8,
    path: []const u8,
    headers: []const parser.Header,
) ?u16 {
    assert(routes.len >= 1);
    assert(path.len >= 1);
    assert(path[0] == '/');
    for (routes) |candidate| {
        if (!hostMatches(candidate.host, host)) continue;
        if (candidate.header) |header_match| {
            if (!headerMatches(header_match, headers)) continue;
        }
        if (prefixMatches(candidate.prefix, path)) {
            return candidate.cluster_index;
        }
    }
    return null;
}

/// An any-host route (`route_host == null`) matches every request. A
/// host-scoped route matches only when the request carried a host and it
/// equals the route's — so a request with no usable Host (`req_host ==
/// null`) meets only the any-host routes (§7).
fn hostMatches(route_host: ?[]const u8, req_host: ?[]const u8) bool {
    const scoped = route_host orelse return true;
    const requested = req_host orelse return false;
    return std.mem.eql(u8, scoped, requested);
}

/// A prefix matches only when it covers whole path segments: the path
/// equals the prefix, the prefix is slash-terminated, or the byte right
/// after the prefix is `/`. So `/api` matches `/api` and `/api/v1` but
/// never `/apihost` — a string prefix that splits a segment is not a
/// route. `/` is slash-terminated, so the root prefix is the catch-all.
/// Public so filters (§7) share exactly one canonical-path prefix
/// semantics with routing.
pub fn prefixMatches(prefix: []const u8, path: []const u8) bool {
    assert(prefix.len >= 1);
    assert(prefix[0] == '/');
    assert(path.len >= 1);
    assert(path[0] == '/');
    if (!std.mem.startsWith(u8, path, prefix)) {
        return false;
    }
    if (path.len == prefix.len) {
        return true;
    }
    assert(path.len > prefix.len);
    if (prefix[prefix.len - 1] == '/') {
        return true;
    }
    return path[prefix.len] == '/';
}

test "router: longest-prefix wins at segment boundaries" {
    // As config.zig will store them: sorted longest-prefix-first.
    const routes = [_]Route{
        .{ .prefix = "/api/v2", .cluster_index = 3 },
        .{ .prefix = "/api", .cluster_index = 2 },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    try std.testing.expectEqual(@as(?u16, 3), route(&routes, null, "/api/v2", &.{}));
    try std.testing.expectEqual(@as(?u16, 3), route(&routes, null, "/api/v2/x", &.{}));
    try std.testing.expectEqual(@as(?u16, 2), route(&routes, null, "/api", &.{}));
    try std.testing.expectEqual(@as(?u16, 2), route(&routes, null, "/api/v1", &.{}));
    // A segment-splitting string prefix is not a match: "/api" must not
    // capture "/apihost", so it falls through to the catch-all.
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, null, "/apihost", &.{}));
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, null, "/other", &.{}));
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, null, "/", &.{}));
}

test "router: no catch-all means no match is null (404)" {
    const routes = [_]Route{
        .{ .prefix = "/api", .cluster_index = 1 },
    };
    try std.testing.expectEqual(@as(?u16, 1), route(&routes, null, "/api", &.{}));
    try std.testing.expectEqual(@as(?u16, 1), route(&routes, null, "/api/deep/path", &.{}));
    try std.testing.expectEqual(@as(?u16, null), route(&routes, null, "/", &.{}));
    try std.testing.expectEqual(@as(?u16, null), route(&routes, null, "/apix", &.{}));
    try std.testing.expectEqual(@as(?u16, null), route(&routes, null, "/elsewhere", &.{}));
}

test "router: a slash-terminated prefix matches its whole subtree" {
    const routes = [_]Route{
        .{ .prefix = "/assets/", .cluster_index = 5 },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    try std.testing.expectEqual(@as(?u16, 5), route(&routes, null, "/assets/img.png", &.{}));
    // "/assets" (no trailing slash) is not under "/assets/"; catch-all.
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, null, "/assets", &.{}));
}

test "router: a host-specific route beats an any-host one, whatever the prefix" {
    // As config.zig sorts them: host-specific first, then longest-prefix.
    const routes = [_]Route{
        .{ .host = "a.example", .prefix = "/api", .cluster_index = 1 },
        .{ .host = "a.example", .prefix = "/", .cluster_index = 2 },
        .{ .prefix = "/deep", .cluster_index = 3 },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    // Host a.example: its own routes win, longest-prefix among them.
    try std.testing.expectEqual(@as(?u16, 1), route(&routes, "a.example", "/api/x", &.{}));
    // Host a.example, /deep/x: no host route matches except its own
    // catch-all "/", which STILL beats the longer any-host "/deep" —
    // host-specificity dominates prefix length.
    try std.testing.expectEqual(@as(?u16, 2), route(&routes, "a.example", "/deep/x", &.{}));
    try std.testing.expectEqual(@as(?u16, 2), route(&routes, "a.example", "/other", &.{}));
    // A different host falls entirely to the any-host routes.
    try std.testing.expectEqual(@as(?u16, 3), route(&routes, "b.example", "/deep/x", &.{}));
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, "b.example", "/api", &.{}));
    // No usable Host matches only any-host routes.
    try std.testing.expectEqual(@as(?u16, 3), route(&routes, null, "/deep", &.{}));
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, null, "/whatever", &.{}));
}

test "router: a host-scoped table 404s a request whose host is absent" {
    const routes = [_]Route{
        .{ .host = "only.example", .prefix = "/", .cluster_index = 1 },
    };
    try std.testing.expectEqual(@as(?u16, 1), route(&routes, "only.example", "/x", &.{}));
    // Wrong host, or no host at all: nothing any-host to fall back to.
    try std.testing.expectEqual(@as(?u16, null), route(&routes, "other.example", "/x", &.{}));
    try std.testing.expectEqual(@as(?u16, null), route(&routes, null, "/x", &.{}));
}

/// Whether some header satisfies the predicate. Name comparison is
/// case-insensitive (RFC 9110); `equals`/`contains` compare the value
/// byte-exact / by substring. Multiple headers of the same name each get
/// a chance — the predicate holds if any does.
pub fn headerMatches(header_match: HeaderMatch, headers: []const parser.Header) bool {
    assert(header_match.name.len >= 1); // A validated RFC 9110 token.
    assert(headers.len <= constants.headers_max);
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, header_match.name)) {
            continue;
        }
        switch (header_match.kind) {
            .present => return true,
            .equals => if (std.mem.eql(u8, header.value, header_match.value)) return true,
            // Config rejects an empty `contains` needle, so this is a real
            // substring test — never the always-true `indexOf(x, "")`.
            .contains => {
                assert(header_match.value.len >= 1);
                if (std.mem.indexOf(u8, header.value, header_match.value) != null) return true;
            },
        }
    }
    return false;
}

test "router: a header route is the narrower rule within its host group" {
    // The #302 order, as config.zig sorts it: host, then header, then
    // prefix. The canary rule and the rule it is a variant of share a
    // host and a prefix, so only the header tier can separate them —
    // and it must put the canary first, or a pinned client would never
    // reach it.
    const canary: HeaderMatch = .{ .name = "X-Canary", .kind = .present, .value = "" };
    const routes = [_]Route{
        .{ .host = "api.example.com", .header = canary, .prefix = "/", .cluster_index = 3 },
        .{ .host = "api.example.com", .prefix = "/", .cluster_index = 2 },
        .{ .header = canary, .prefix = "/", .cluster_index = 1 },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    const pinned = [_]parser.Header{parser.Header.init("x-canary", "1")};
    const plain: []const parser.Header = &.{};

    // Host beats header: a pinned request for the named host takes that
    // host's canary, not the any-host one.
    try std.testing.expectEqual(@as(?u16, 3), route(&routes, "api.example.com", "/", &pinned));
    // Header beats bare within a host group.
    try std.testing.expectEqual(@as(?u16, 2), route(&routes, "api.example.com", "/", plain));
    // And the any-host group repeats the rule one tier down.
    try std.testing.expectEqual(@as(?u16, 1), route(&routes, "other.example.com", "/", &pinned));
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, "other.example.com", "/", plain));
}

test "router: the three dimensions are a conjunction, not a ranking" {
    // A route states what must hold, and every stated key must hold. A
    // request matching the header but not the prefix falls through to
    // whatever does — it does not "win" on the strength of the header.
    const routes = [_]Route{
        .{
            .header = .{ .name = "X-Canary", .kind = .equals, .value = "v2" },
            .prefix = "/api",
            .cluster_index = 1,
        },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    const v2 = [_]parser.Header{parser.Header.init("X-Canary", "v2")};
    try std.testing.expectEqual(@as(?u16, 1), route(&routes, null, "/api/x", &v2));
    // Right header, wrong path.
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, null, "/other", &v2));
    // Right path, wrong value.
    const v1 = [_]parser.Header{parser.Header.init("X-Canary", "v1")};
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, null, "/api/x", &v1));
    // Right path, header absent.
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, null, "/api/x", &.{}));
}

test "router: a header name matches case-insensitively, a value does not" {
    // RFC 9110's rule for names; a value is bytes the client chose and is
    // compared as such — the same split `filters` have always used, now
    // through the same evaluator.
    const routes = [_]Route{
        .{
            .header = .{ .name = "X-Canary", .kind = .equals, .value = "Yes" },
            .prefix = "/",
            .cluster_index = 1,
        },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    const lower_name = [_]parser.Header{parser.Header.init("x-canary", "Yes")};
    try std.testing.expectEqual(@as(?u16, 1), route(&routes, null, "/", &lower_name));
    const lower_value = [_]parser.Header{parser.Header.init("X-Canary", "yes")};
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, null, "/", &lower_value));
}
