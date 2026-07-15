//! Upstream endpoint selection (DESIGN.md §7): the load-balancing policy
//! kept behind a seam so the serving path never hardcodes *how* an
//! endpoint is chosen — it only asks "which endpoint for this cluster?".
//! Today's policy is round-robin; the design's trajectory is round-robin
//! → P2C (§7), and that evolution lands as a change here, not in Server.
//! The policy owns whatever per-cluster state it needs — a round-robin
//! cursor now — and resolves a cluster index to the endpoint to dial.

const std = @import("std");

const config_module = @import("config.zig");

const assert = std.debug.assert;

pub const Balancer = struct {
    config: *const config_module.Config,
    /// Per-cluster round-robin cursor. u64 so it never wraps in any
    /// realistic process lifetime — a u16 wrap reset the rotation phase
    /// and double-picked one endpoint for non-power-of-two cluster sizes.
    cursors: []u64,

    /// Cursors are arena-owned and sized to the cluster count, so a pick
    /// is a bounds-checked index, never an allocation on the loop.
    pub fn init(
        balancer: *Balancer,
        arena: std.mem.Allocator,
        config: *const config_module.Config,
    ) error{OutOfMemory}!void {
        balancer.config = config;
        balancer.cursors = try arena.alloc(u64, config.clusters.len);
        @memset(balancer.cursors, 0);
    }

    /// Choose the next endpoint to dial for `cluster_index`, advancing the
    /// policy's state. Round-robin: the cursor modulo the endpoint count,
    /// then incremented — a validated config guarantees at least one
    /// endpoint, so the modulo is always defined.
    pub fn pick(balancer: *Balancer, cluster_index: u16) std.Io.net.IpAddress {
        assert(cluster_index < balancer.cursors.len);
        const cluster = &balancer.config.clusters[cluster_index];
        assert(cluster.endpoints.len >= 1);
        const endpoint_index: usize =
            @intCast(balancer.cursors[cluster_index] % cluster.endpoints.len);
        balancer.cursors[cluster_index] += 1;
        return cluster.endpoints[endpoint_index];
    }
};

test "balancer: round-robin cycles endpoints and wraps per cluster" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const c = std.Io.net.IpAddress.parseLiteral("127.0.0.1:3") catch unreachable;
    const solo = std.Io.net.IpAddress.parseLiteral("127.0.0.1:9") catch unreachable;

    const trio = [_]std.Io.net.IpAddress{ a, b, c };
    const one = [_]std.Io.net.IpAddress{solo};
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "trio", .endpoints = &trio },
        .{ .name = "one", .endpoints = &one },
    };
    const config: config_module.Config = .{
        .listeners = &.{},
        .clusters = &clusters,
        .connect_timeout_ms = 1,
        .idle_timeout_ms = 1,
        .drain_deadline_ms = 1,
        .max_lifetime_ms = 0,
    };

    var balancer: Balancer = undefined;
    try balancer.init(arena, &config);

    // Cluster 0 rotates a → b → c and wraps back to a; cluster 1 keeps
    // its own cursor and always returns its single endpoint.
    const expected = [_]std.Io.net.IpAddress{ a, b, c, a, b };
    for (expected) |want| {
        try std.testing.expectEqual(want, balancer.pick(0));
        try std.testing.expectEqual(solo, balancer.pick(1));
    }
}
