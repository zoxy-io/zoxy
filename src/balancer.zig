//! Upstream endpoint selection (DESIGN.md §7): the load-balancing policy
//! kept behind a seam so the serving path never hardcodes *how* an
//! endpoint is chosen — it only asks "which endpoint for this cluster?".
//! Two policies, selected per cluster in the config (§5 parse-once):
//! `rr` rotates a per-cluster cursor, `p2c` draws two distinct candidates
//! uniformly and leases the calmer one. P2C's load is the upstream pool's
//! per-endpoint leased count, passed in by the caller — the balancer owns
//! the draw, the pool owns the truth. A single-endpoint cluster
//! short-circuits either policy without touching its state.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const upstream = @import("net/upstream.zig");

const assert = std.debug.assert;

pub const Balancer = struct {
    config: *const config_module.Config,
    /// Per-cluster round-robin cursors, used by `.rr` clusters only.
    /// u64 so a cursor never wraps in any realistic process lifetime — a
    /// u16 wrap reset the rotation phase and double-picked one endpoint
    /// for non-power-of-two cluster sizes. Fixed at the config ceiling:
    /// 16 × 8 bytes of static state beats an arena allocation.
    cursors: [constants.clusters_max]u64,
    /// xorshift64* draw state, used by `.p2c` clusters only. Seeded from
    /// a fixed named constant, never the clock: the simulator replays
    /// every seed twice and demands byte-identical traces (§9), and load
    /// balancing needs spread, not secrecy — determinism is a feature.
    pick_state: u64,

    /// Any nonzero constant seeds xorshift64* soundly; this one is the
    /// 64-bit golden-ratio constant, chosen for being recognizable.
    const pick_seed: u64 = 0x9E3779B97F4A7C15;

    pub fn init(balancer: *Balancer, config: *const config_module.Config) void {
        assert(config.clusters.len >= 1);
        assert(config.clusters.len <= constants.clusters_max);
        balancer.config = config;
        @memset(&balancer.cursors, 0);
        balancer.pick_state = pick_seed;
        assert(balancer.pick_state != 0); // xorshift64* cycles on nonzero state.
    }

    /// A pick names the endpoint both ways: the address to dial and the
    /// index the upstream pool keys its idle lists by (§5).
    pub const Pick = struct {
        address: std.Io.net.IpAddress,
        endpoint_index: u16,
    };

    /// Choose the endpoint to dial for `cluster_index` under the
    /// cluster's configured policy. `leased_counts` is the pool's
    /// per-endpoint load table (indexed by `upstream.endpointKey`),
    /// consulted by p2c and ignored by rr. Bounded work, no allocation,
    /// and a validated config guarantees at least one endpoint.
    pub fn pick(
        balancer: *Balancer,
        cluster_index: u16,
        leased_counts: *const [upstream.endpoint_keys_max]u16,
    ) Pick {
        assert(cluster_index < balancer.config.clusters.len);
        const cluster = &balancer.config.clusters[cluster_index];
        assert(cluster.endpoints.len >= 1);
        assert(cluster.endpoints.len <= constants.endpoints_per_cluster_max);
        if (cluster.endpoints.len == 1) {
            // Neither a rotation nor a draw: single-endpoint clusters
            // stay branch-cheap and policy state is untouched.
            return .{ .address = cluster.endpoints[0], .endpoint_index = 0 };
        }
        const chosen = switch (cluster.pick) {
            .rr => balancer.pickRoundRobin(cluster_index, cluster),
            .p2c => balancer.pickPowerOfTwo(cluster_index, cluster, leased_counts),
        };
        assert(chosen < cluster.endpoints.len);
        return .{
            .address = cluster.endpoints[chosen],
            .endpoint_index = chosen,
        };
    }

    /// Strict rotation: the cursor modulo the endpoint count, then
    /// incremented — every endpoint sees exactly its share, in order.
    fn pickRoundRobin(
        balancer: *Balancer,
        cluster_index: u16,
        cluster: *const config_module.Config.Cluster,
    ) u16 {
        assert(cluster.pick == .rr);
        assert(cluster.endpoints.len >= 2); // pick() short-circuited 1.
        const chosen: u16 =
            @intCast(balancer.cursors[cluster_index] % cluster.endpoints.len);
        balancer.cursors[cluster_index] += 1;
        assert(chosen < cluster.endpoints.len);
        return chosen;
    }

    /// P2C: two distinct uniform candidates, the lower leased count
    /// wins, a tie goes to the first.
    fn pickPowerOfTwo(
        balancer: *Balancer,
        cluster_index: u16,
        cluster: *const config_module.Config.Cluster,
        leased_counts: *const [upstream.endpoint_keys_max]u16,
    ) u16 {
        assert(cluster.pick == .p2c);
        const endpoint_count = cluster.endpoints.len;
        assert(endpoint_count >= 2); // pick() short-circuited 1.
        const first: u16 = @intCast(balancer.next() % endpoint_count);
        var second: u16 = @intCast(balancer.next() % (endpoint_count - 1));
        // Skip past `first`, mapping the (n-1)-range draw onto the other
        // n-1 endpoints uniformly.
        if (second >= first) {
            second += 1;
        }
        assert(first != second);
        assert(second < endpoint_count);
        const first_load = leased_counts[upstream.endpointKey(cluster_index, first)];
        const second_load = leased_counts[upstream.endpointKey(cluster_index, second)];
        return if (second_load < first_load) second else first;
    }

    /// xorshift64* (Vigna): the full-period 64-bit shift generator with a
    /// multiplicative output scramble — plenty for candidate draws, one
    /// mul and three shifts on the pick path. The modulo bias of a draw
    /// is ≤ 2⁻⁵⁸ for the ≤ 64 endpoints a cluster may hold — negligible.
    fn next(balancer: *Balancer) u64 {
        assert(balancer.pick_state != 0);
        var x = balancer.pick_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        balancer.pick_state = x;
        assert(x != 0); // Nonzero state maps to nonzero state.
        return x *% 0x2545F4914F6CDD1D;
    }
};

const test_counts_len = upstream.endpoint_keys_max;

fn testConfig(clusters: []const config_module.Config.Cluster) config_module.Config {
    return .{
        .listeners = &.{},
        .clusters = clusters,
        .connect_timeout_ms = 1,
        .idle_timeout_ms = 1,
        .drain_deadline_ms = 1,
        .max_lifetime_ms = 0,
    };
}

test "balancer: rr cycles endpoints and wraps per cluster" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const c = std.Io.net.IpAddress.parseLiteral("127.0.0.1:3") catch unreachable;
    const trio = [_]std.Io.net.IpAddress{ a, b, c };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "trio", .endpoints = &trio, .pick = .rr },
    };
    const config = testConfig(&clusters);

    var balancer: Balancer = undefined;
    balancer.init(&config);

    // Rotation is exact whatever the load table says: rr ignores it.
    var counts = [_]u16{0} ** test_counts_len;
    counts[upstream.endpointKey(0, 0)] = 100;
    const expected = [_]u16{ 0, 1, 2, 0, 1 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &counts);
        try std.testing.expectEqual(want_index, picked.endpoint_index);
        try std.testing.expectEqual(trio[want_index], picked.address);
    }
}

test "balancer: a single-endpoint cluster short-circuits without a draw" {
    const solo = std.Io.net.IpAddress.parseLiteral("127.0.0.1:9") catch unreachable;
    const one = [_]std.Io.net.IpAddress{solo};
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "one", .endpoints = &one },
    };
    const config = testConfig(&clusters);

    var balancer: Balancer = undefined;
    balancer.init(&config);
    const state_before = balancer.pick_state;

    const counts = [_]u16{0} ** test_counts_len;
    var round: u32 = 0;
    while (round < 10) : (round += 1) {
        const picked = balancer.pick(0, &counts);
        try std.testing.expectEqual(solo, picked.address);
        try std.testing.expectEqual(@as(u16, 0), picked.endpoint_index);
    }
    // The PRNG state never advanced: no draw was spent.
    try std.testing.expectEqual(state_before, balancer.pick_state);
}

test "balancer: p2c prefers the less-loaded of its two candidates" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const c = std.Io.net.IpAddress.parseLiteral("127.0.0.1:3") catch unreachable;
    const trio = [_]std.Io.net.IpAddress{ a, b, c };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "trio", .endpoints = &trio, .pick = .p2c },
    };
    const config = testConfig(&clusters);

    var balancer: Balancer = undefined;
    balancer.init(&config);

    // Endpoint 1 is drowning; 0 and 2 are idle. Whatever pair is drawn,
    // the pick must never be the drowning endpoint: any pair containing
    // it also contains an idle endpoint that wins the comparison.
    var counts = [_]u16{0} ** test_counts_len;
    counts[upstream.endpointKey(0, 1)] = 100;
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const picked = balancer.pick(0, &counts);
        try std.testing.expect(picked.endpoint_index != 1);
    }
}

test "balancer: p2c spreads across endpoints under equal load" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const c = std.Io.net.IpAddress.parseLiteral("127.0.0.1:3") catch unreachable;
    const trio = [_]std.Io.net.IpAddress{ a, b, c };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "trio", .endpoints = &trio, .pick = .p2c },
    };
    const config = testConfig(&clusters);

    var balancer: Balancer = undefined;
    balancer.init(&config);

    // With every count equal the tie rule keeps the first candidate — a
    // uniform draw — so all endpoints must be hit over a modest run.
    const counts = [_]u16{0} ** test_counts_len;
    var hits = [_]u32{0} ** 3;
    var round: u32 = 0;
    while (round < 300) : (round += 1) {
        const picked = balancer.pick(0, &counts);
        hits[picked.endpoint_index] += 1;
    }
    for (hits) |hit_count| {
        try std.testing.expect(hit_count >= 1);
    }
}

test "balancer: same seed, same picks — the p2c draw is deterministic" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const pair = [_]std.Io.net.IpAddress{ a, b };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .p2c },
    };
    const config = testConfig(&clusters);

    var left: Balancer = undefined;
    left.init(&config);
    var right: Balancer = undefined;
    right.init(&config);

    // The simulator replays every seed twice and hashes the traces (§9);
    // two same-seed balancers must agree draw for draw.
    const counts = [_]u16{0} ** test_counts_len;
    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        try std.testing.expectEqual(
            left.pick(0, &counts).endpoint_index,
            right.pick(0, &counts).endpoint_index,
        );
    }
}

test "balancer: policies keep independent state across clusters" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const pair = [_]std.Io.net.IpAddress{ a, b };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "rotating", .endpoints = &pair, .pick = .rr },
        .{ .name = "drawing", .endpoints = &pair, .pick = .p2c },
    };
    const config = testConfig(&clusters);

    var balancer: Balancer = undefined;
    balancer.init(&config);

    // Interleaving a p2c cluster's draws must not perturb the rr
    // cluster's rotation: cursor and PRNG are separate state.
    const counts = [_]u16{0} ** test_counts_len;
    const expected = [_]u16{ 0, 1, 0, 1, 0 };
    for (expected) |want_index| {
        try std.testing.expectEqual(want_index, balancer.pick(0, &counts).endpoint_index);
        _ = balancer.pick(1, &counts);
    }
}
