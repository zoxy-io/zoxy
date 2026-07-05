//! Request routing: first route whose host and path-prefix match wins (Envoy
//! semantics), yielding the target cluster. Pure reads over the immutable
//! `Config` — no allocation, no shared mutable state.

const std = @import("std");
const config = @import("../config.zig");
const Config = config.Config;
const Cluster = config.Cluster;

pub const Router = struct {
    config: *const Config,

    pub fn init(cfg: *const Config) Router {
        return .{ .config = cfg };
    }

    /// Resolve a request to a cluster, or null if nothing matches.
    /// `host` is the (optional) Host header; `target` is the request target.
    pub fn route(router: Router, host: ?[]const u8, target: []const u8) ?*const Cluster {
        for (router.config.routes) |rule| {
            if (!host_matches(rule.host, host)) continue;
            if (!std.mem.startsWith(u8, target, rule.path_prefix)) continue;
            return router.config.find_cluster(rule.cluster);
        }
        return null;
    }
};

fn host_matches(pattern: []const u8, host: ?[]const u8) bool {
    if (std.mem.eql(u8, pattern, "*")) return true;
    const host_value = host orelse return false;
    return std.ascii.eqlIgnoreCase(pattern, strip_port(host_value));
}

/// Drop a trailing ":port" from a Host header value for comparison.
fn strip_port(host: []const u8) []const u8 {
    const colon = std.mem.lastIndexOfScalar(u8, host, ':') orelse return host;
    return host[0..colon];
}

// ---- tests ----------------------------------------------------------------

test "router: matches host + path prefix, first match wins" {
    const text =
        \\{
        \\  "listen": "0.0.0.0:80",
        \\  "routes": [
        \\    { "host": "api.example.com", "path_prefix": "/v1", "cluster": "api" },
        \\    { "cluster": "default" }
        \\  ],
        \\  "clusters": [
        \\    { "name": "api", "endpoints": ["127.0.0.1:9001"] },
        \\    { "name": "default", "endpoints": ["127.0.0.1:9000"] }
        \\  ]
        \\}
    ;
    var cfg = try config.parse(std.testing.allocator, text);
    defer cfg.deinit();
    const router = Router.init(&cfg);

    // Host+prefix match (port in Host header is ignored).
    try std.testing.expectEqualStrings(
        "api",
        router.route("api.example.com:8080", "/v1/users").?.name,
    );
    // Same host but non-matching prefix falls through to the wildcard route.
    try std.testing.expectEqualStrings("default", router.route("api.example.com", "/other").?.name);
    // Unknown host still matches the wildcard route.
    try std.testing.expectEqualStrings("default", router.route("elsewhere.com", "/").?.name);
    // No Host header only matches wildcard hosts.
    try std.testing.expectEqualStrings("default", router.route(null, "/anything").?.name);
}
