//! §7 path routing: map a canonical request path to a cluster through a
//! per-listener longest-prefix table. Pure — the table is built,
//! validated, and sorted longest-prefix-first at config load
//! (`config.zig`), so a request-time match is a bounded linear scan over
//! immutable arena data, never an allocation on the loop. No match is a
//! real outcome: the caller answers 404 (§8).

const std = @import("std");

const assert = std.debug.assert;

/// One routing rule: a canonical path prefix and the cluster it selects.
/// Prefixes are validated canonical at config load (§7), so they compare
/// directly against the canonical request path with no per-request
/// normalization.
pub const Route = struct {
    prefix: []const u8,
    cluster_index: u16,
};

/// The cluster for `path`, or null when no route matches (the caller's
/// 404, §8). `routes` is sorted longest-prefix-first, so the first prefix
/// that matches at a segment boundary is the most specific — the scan
/// stops there. `path` is the canonical request path (§7).
pub fn route(routes: []const Route, path: []const u8) ?u16 {
    assert(routes.len >= 1);
    assert(path.len >= 1);
    assert(path[0] == '/');
    for (routes) |candidate| {
        if (matches(candidate.prefix, path)) {
            return candidate.cluster_index;
        }
    }
    return null;
}

/// A prefix matches only when it covers whole path segments: the path
/// equals the prefix, the prefix is slash-terminated, or the byte right
/// after the prefix is `/`. So `/api` matches `/api` and `/api/v1` but
/// never `/apihost` — a string prefix that splits a segment is not a
/// route. `/` is slash-terminated, so the root prefix is the catch-all.
fn matches(prefix: []const u8, path: []const u8) bool {
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
    try std.testing.expectEqual(@as(?u16, 3), route(&routes, "/api/v2"));
    try std.testing.expectEqual(@as(?u16, 3), route(&routes, "/api/v2/x"));
    try std.testing.expectEqual(@as(?u16, 2), route(&routes, "/api"));
    try std.testing.expectEqual(@as(?u16, 2), route(&routes, "/api/v1"));
    // A segment-splitting string prefix is not a match: "/api" must not
    // capture "/apihost", so it falls through to the catch-all.
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, "/apihost"));
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, "/other"));
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, "/"));
}

test "router: no catch-all means no match is null (404)" {
    const routes = [_]Route{
        .{ .prefix = "/api", .cluster_index = 1 },
    };
    try std.testing.expectEqual(@as(?u16, 1), route(&routes, "/api"));
    try std.testing.expectEqual(@as(?u16, 1), route(&routes, "/api/deep/path"));
    try std.testing.expectEqual(@as(?u16, null), route(&routes, "/"));
    try std.testing.expectEqual(@as(?u16, null), route(&routes, "/apix"));
    try std.testing.expectEqual(@as(?u16, null), route(&routes, "/elsewhere"));
}

test "router: a slash-terminated prefix matches its whole subtree" {
    const routes = [_]Route{
        .{ .prefix = "/assets/", .cluster_index = 5 },
        .{ .prefix = "/", .cluster_index = 0 },
    };
    try std.testing.expectEqual(@as(?u16, 5), route(&routes, "/assets/img.png"));
    // "/assets" (no trailing slash) is not under "/assets/"; catch-all.
    try std.testing.expectEqual(@as(?u16, 0), route(&routes, "/assets"));
}
