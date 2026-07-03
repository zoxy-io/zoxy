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

pub const RoundRobin = struct {
    /// One rotation counter per cluster, indexed by `Cluster.index`
    /// (reserved statically; `config.parse` enforces `clusters_max`).
    next: [constants.clusters_max]usize = @splat(0),

    /// Pick the next endpoint's index, cycling through the cluster. Null if
    /// the cluster has no endpoints. An index (not a pointer) so callers can
    /// key the per-endpoint resilience state with the same value.
    pub fn pick(round_robin: *RoundRobin, cluster: *const Cluster) ?u32 {
        if (cluster.endpoints.len == 0) return null;
        assert(cluster.endpoints.len > 0); // negative space: handled above
        assert(cluster.index < constants.clusters_max); // enforced by config.parse
        const counter = &round_robin.next[cluster.index];
        const index: u32 = @intCast(counter.* % cluster.endpoints.len);
        assert(index < cluster.endpoints.len);
        counter.* +%= 1;
        return index;
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
    const cluster = cfg.find_cluster("c").?;

    var round_robin: RoundRobin = .{};
    const ports = [_]u16{ 1, 2, 3, 1, 2 };
    for (ports) |expected| {
        const index = round_robin.pick(cluster).?;
        try std.testing.expectEqual(expected, cluster.endpoints[index].address.port);
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
    const a = cfg.find_cluster("a").?;
    const b = cfg.find_cluster("b").?;

    // With a counter shared across clusters, this alternating pattern pins "a"
    // to endpoint 1 and "b" to endpoint 4 forever. Per-cluster counters must
    // cycle both.
    var round_robin: RoundRobin = .{};
    const expected = [_]struct { cluster: *const Cluster, port: u16 }{
        .{ .cluster = a, .port = 1 }, .{ .cluster = b, .port = 3 },
        .{ .cluster = a, .port = 2 }, .{ .cluster = b, .port = 4 },
        .{ .cluster = a, .port = 1 }, .{ .cluster = b, .port = 3 },
    };
    for (expected) |pick| {
        const index = round_robin.pick(pick.cluster).?;
        try std.testing.expectEqual(pick.port, pick.cluster.endpoints[index].address.port);
    }
}

test "balancer: empty cluster yields null" {
    var cfg = try config.parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": [] }] }
    );
    defer cfg.deinit();
    var round_robin: RoundRobin = .{};
    try std.testing.expect(round_robin.pick(cfg.find_cluster("c").?) == null);
}
