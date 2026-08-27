//! §6 L4 SNI routing (#298): map the `server_name` a client asked for to
//! a cluster, through a per-listener table.
//!
//! §7's router one layer down and one dimension short. That one has host
//! as the outer dimension and longest path prefix within it; an L4 relay
//! parses no request, so there is no path and this table has only the
//! name. Its own type rather than a mode on `router.Route` — #305 Part 1
//! made an `l4` body and an `http` body different types precisely so this
//! could be one, which is what keeps `Route.prefix` non-optional over
//! there.
//!
//! Matching is exact, deliberately: §7's `host` dimension compares with
//! `std.mem.eql` and nothing in the tree supports a wildcard. Giving L4
//! one would mean two rules for one idea, and the two disagreeing about
//! what a host is, which is the thing #298 asked to avoid. A wildcard is
//! a change to both dimensions or to neither.
//!
//! Pure: the table is built, validated and sorted at config load
//! (`config.zig`) so a named route precedes the any-name one, making a
//! match a bounded linear scan over immutable arena data. No match is a
//! real outcome — the caller closes the connection (§6), which is the L4
//! shape of §7's 404.

const std = @import("std");

const assert = std.debug.assert;

/// One rule: the name a client must have asked for, and the cluster that
/// answers. `server_name == null` is the any-name route — it matches
/// every connection, including one whose hello carried no name at all,
/// which is §7's any-host route wearing the only dimension L4 has.
pub const Route = struct {
    server_name: ?[]const u8 = null,
    cluster_index: u16,
};

/// The cluster for a connection whose ClientHello named `server_name`
/// (null when it carried none), or null when nothing matches — the
/// caller's close.
///
/// `routes` is sorted named-first, so the first match is the most
/// specific: a route naming this client's name beats the any-name route,
/// and a client that named nothing meets only the any-name one.
pub fn route(routes: []const Route, server_name: ?[]const u8) ?u16 {
    assert(routes.len >= 1);
    for (routes) |candidate| {
        if (matches(candidate.server_name, server_name)) {
            return candidate.cluster_index;
        }
    }
    return null;
}

/// An any-name route matches everything. A named route matches only a
/// client that asked for that exact name — so a hello with no
/// `server_name` extension meets the any-name routes and no others,
/// exactly as a request with no usable `Host` meets only §7's any-host
/// routes.
fn matches(route_name: ?[]const u8, client_name: ?[]const u8) bool {
    const wanted = route_name orelse return true;
    const asked = client_name orelse return false;
    return std.mem.eql(u8, wanted, asked);
}

const testing = std.testing;

test "sni_router: a named route beats the any-name one" {
    // As config.zig stores them: named first, any-name last.
    const routes = [_]Route{
        .{ .server_name = "api.example.com", .cluster_index = 1 },
        .{ .server_name = "db.example.com", .cluster_index = 2 },
        .{ .cluster_index = 0 },
    };
    try testing.expectEqual(@as(?u16, 1), route(&routes, "api.example.com"));
    try testing.expectEqual(@as(?u16, 2), route(&routes, "db.example.com"));
    // A name nobody claimed, and a client that named nothing, both land
    // on the any-name route.
    try testing.expectEqual(@as(?u16, 0), route(&routes, "other.example.com"));
    try testing.expectEqual(@as(?u16, 0), route(&routes, null));
}

test "sni_router: matching is exact, not by suffix" {
    const routes = [_]Route{
        .{ .server_name = "example.com", .cluster_index = 1 },
        .{ .cluster_index = 0 },
    };
    // The rule §7's host dimension uses. A subdomain is a different name,
    // and nothing here reads it as one.
    try testing.expectEqual(@as(?u16, 0), route(&routes, "www.example.com"));
    try testing.expectEqual(@as(?u16, 0), route(&routes, "example.com.evil.test"));
    try testing.expectEqual(@as(?u16, 1), route(&routes, "example.com"));
}

test "sni_router: no any-name route means no match is null (close)" {
    const routes = [_]Route{
        .{ .server_name = "api.example.com", .cluster_index = 1 },
    };
    try testing.expectEqual(@as(?u16, 1), route(&routes, "api.example.com"));
    // An operator who wrote no catch-all asked for these to be closed
    // rather than sent somewhere they did not name (§6).
    try testing.expectEqual(@as(?u16, null), route(&routes, "other.example.com"));
    try testing.expectEqual(@as(?u16, null), route(&routes, null));
}
