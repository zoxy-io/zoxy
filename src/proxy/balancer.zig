//! Load balancing across a cluster's endpoints. Phase-0 ships round-robin;
//! P2C/EWMA is Phase-2 (docs/DESIGN.md §7). State is per-worker (single-threaded,
//! share-nothing), so plain counters need no synchronization. Each cluster gets
//! its own counter — a single shared one lets traffic to one cluster skew
//! another's rotation (interleaved picks can pin a cluster to one endpoint).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const config = @import("../config.zig");
const Cluster = config.Cluster;
const Endpoint = config.Endpoint;

pub const RoundRobin = struct {
    /// One rotation counter per cluster, indexed by `Cluster.index`
    /// (reserved statically; `config.parse` enforces `clusters_max`).
    next: [constants.clusters_max]usize = @splat(0),

    /// Pick the next endpoint, cycling through the cluster. Null if the cluster
    /// has no endpoints.
    pub fn pick(rr: *RoundRobin, cluster: *const Cluster) ?*const Endpoint {
        if (cluster.endpoints.len == 0) return null;
        assert(cluster.endpoints.len > 0); // negative space: handled above
        assert(cluster.index < constants.clusters_max); // enforced by config.parse
        const counter = &rr.next[cluster.index];
        const index = counter.* % cluster.endpoints.len;
        assert(index < cluster.endpoints.len);
        counter.* +%= 1;
        return &cluster.endpoints[index];
    }
};

// ---- tests ----------------------------------------------------------------

test "balancer: round-robin cycles endpoints" {
    var cfg = try config.parse(std.testing.allocator,
        \\{
        \\  "listen": "0.0.0.0:80",
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [
        \\    { "name": "c", "endpoints": ["127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3"] }
        \\  ]
        \\}
    );
    defer cfg.deinit();
    const cluster = cfg.findCluster("c").?;

    var rr: RoundRobin = .{};
    const ports = [_]u16{ 1, 2, 3, 1, 2 };
    for (ports) |expected| {
        try std.testing.expectEqual(expected, rr.pick(cluster).?.address.port);
    }
}

test "balancer: clusters rotate independently under interleaved traffic" {
    var cfg = try config.parse(std.testing.allocator,
        \\{
        \\  "listen": "0.0.0.0:80",
        \\  "routes": [{ "cluster": "a" }],
        \\  "clusters": [
        \\    { "name": "a", "endpoints": ["127.0.0.1:1", "127.0.0.1:2"] },
        \\    { "name": "b", "endpoints": ["127.0.0.1:3", "127.0.0.1:4"] }
        \\  ]
        \\}
    );
    defer cfg.deinit();
    const a = cfg.findCluster("a").?;
    const b = cfg.findCluster("b").?;

    // With a counter shared across clusters, this alternating pattern pins "a"
    // to endpoint 1 and "b" to endpoint 4 forever. Per-cluster counters must
    // cycle both.
    var rr: RoundRobin = .{};
    const expected = [_]struct { cluster: *const Cluster, port: u16 }{
        .{ .cluster = a, .port = 1 }, .{ .cluster = b, .port = 3 },
        .{ .cluster = a, .port = 2 }, .{ .cluster = b, .port = 4 },
        .{ .cluster = a, .port = 1 }, .{ .cluster = b, .port = 3 },
    };
    for (expected) |pick| {
        try std.testing.expectEqual(pick.port, rr.pick(pick.cluster).?.address.port);
    }
}

test "balancer: empty cluster yields null" {
    var cfg = try config.parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": [] }] }
    );
    defer cfg.deinit();
    var rr: RoundRobin = .{};
    try std.testing.expect(rr.pick(cfg.findCluster("c").?) == null);
}
