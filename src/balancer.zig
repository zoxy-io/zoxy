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
    /// consulted by p2c and ignored by rr; `healthy` is the §7 health
    /// mask (same index) — the prober owns that truth the way the pool
    /// owns the load. Bounded work, no allocation, and a validated
    /// config guarantees at least one endpoint.
    pub fn pick(
        balancer: *Balancer,
        cluster_index: u16,
        leased_counts: *const [upstream.endpoint_keys_max]u16,
        healthy: *const [upstream.endpoint_keys_max]bool,
    ) Pick {
        assert(cluster_index < balancer.config.clusters.len);
        const cluster = &balancer.config.clusters[cluster_index];
        assert(cluster.endpoints.len >= 1);
        assert(cluster.endpoints.len <= constants.endpoints_per_cluster_max);
        if (cluster.endpoints.len == 1) {
            // Neither a rotation nor a draw: single-endpoint clusters
            // stay branch-cheap and policy state is untouched. The mask
            // is moot too — one endpoint ejected is the fail-open case.
            return .{ .address = cluster.endpoints[0], .endpoint_index = 0 };
        }
        var eligible: [constants.endpoints_per_cluster_max]u16 = undefined;
        const count = eligibleEndpoints(cluster_index, cluster, healthy, &eligible);
        const chosen = switch (cluster.pick) {
            .rr => balancer.pickRoundRobin(cluster_index, eligible[0..count]),
            .p2c => balancer.pickPowerOfTwo(cluster_index, eligible[0..count], leased_counts),
        };
        assert(chosen < cluster.endpoints.len);
        return .{
            .address = cluster.endpoints[chosen],
            .endpoint_index = chosen,
        };
    }

    /// The §7-eligible endpoints: the healthy ones — or, the fail-open
    /// rule, every endpoint when the whole cluster is ejected. Dialing a
    /// maybe-dead endpoint reports the outage the way it always did;
    /// routing nowhere would turn a probe verdict into an outage of its
    /// own, and a same-port TCP probe cannot know better than the dial.
    fn eligibleEndpoints(
        cluster_index: u16,
        cluster: *const config_module.Config.Cluster,
        healthy: *const [upstream.endpoint_keys_max]bool,
        eligible: *[constants.endpoints_per_cluster_max]u16,
    ) u16 {
        assert(cluster.endpoints.len >= 2); // pick() short-circuited 1.
        var count: u16 = 0;
        for (0..cluster.endpoints.len) |endpoint_index| {
            const index: u16 = @intCast(endpoint_index);
            if (healthy[upstream.endpointKey(cluster_index, index)]) {
                eligible[count] = index;
                count += 1;
            }
        }
        if (count == 0) {
            for (0..cluster.endpoints.len) |endpoint_index| {
                eligible[endpoint_index] = @intCast(endpoint_index);
            }
            count = @intCast(cluster.endpoints.len);
        }
        assert(count >= 1);
        assert(count <= cluster.endpoints.len);
        return count;
    }

    /// Strict rotation over the eligible set: the cursor modulo its
    /// size, then incremented — every eligible endpoint sees its share,
    /// in order. Ejections shift the rotation phase; the share stays
    /// exact for whatever set is eligible at each pick.
    fn pickRoundRobin(
        balancer: *Balancer,
        cluster_index: u16,
        eligible: []const u16,
    ) u16 {
        assert(balancer.config.clusters[cluster_index].pick == .rr);
        assert(eligible.len >= 1);
        const slot: u16 = @intCast(balancer.cursors[cluster_index] % eligible.len);
        balancer.cursors[cluster_index] += 1;
        assert(slot < eligible.len);
        return eligible[slot];
    }

    /// P2C over the eligible set: two distinct uniform candidates, the
    /// lower leased count wins, a tie goes to the first. A mask narrowed
    /// to one endpoint skips the draw the way a one-endpoint cluster
    /// does — no candidates to compare, no PRNG state spent.
    fn pickPowerOfTwo(
        balancer: *Balancer,
        cluster_index: u16,
        eligible: []const u16,
        leased_counts: *const [upstream.endpoint_keys_max]u16,
    ) u16 {
        assert(balancer.config.clusters[cluster_index].pick == .p2c);
        assert(eligible.len >= 1);
        if (eligible.len == 1) {
            return eligible[0];
        }
        const first_slot: u16 = @intCast(balancer.next() % eligible.len);
        var second_slot: u16 = @intCast(balancer.next() % (eligible.len - 1));
        // Skip past `first_slot`, mapping the (n-1)-range draw onto the
        // other n-1 eligible slots uniformly.
        if (second_slot >= first_slot) {
            second_slot += 1;
        }
        assert(first_slot != second_slot);
        assert(second_slot < eligible.len);
        const first = eligible[first_slot];
        const second = eligible[second_slot];
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

/// The no-prober baseline every pre-mask test picks through: all healthy,
/// exactly what `Checker.init` hands a server whose clusters never check.
const test_healthy_all = [_]bool{true} ** upstream.endpoint_keys_max;

fn testConfig(clusters: []const config_module.Config.Cluster) config_module.Config {
    return .{
        .listeners = &.{},
        .clusters = clusters,
        .connect_timeout_ms = 1,
        .idle_timeout_ms = 1,
        .drain_deadline_ms = 1,
        .max_lifetime_ms = 0,
        .request_timeout_ms = 0,
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
        const picked = balancer.pick(0, &counts, &test_healthy_all);
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
        const picked = balancer.pick(0, &counts, &test_healthy_all);
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
        const picked = balancer.pick(0, &counts, &test_healthy_all);
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
        const picked = balancer.pick(0, &counts, &test_healthy_all);
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
            left.pick(0, &counts, &test_healthy_all).endpoint_index,
            right.pick(0, &counts, &test_healthy_all).endpoint_index,
        );
    }
}

test "balancer: rr rotates over the healthy endpoints only" {
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

    // Endpoint 1 is ejected (§7): rotation covers the survivors exactly,
    // never the ejected one.
    var healthy = test_healthy_all;
    healthy[upstream.endpointKey(0, 1)] = false;
    const counts = [_]u16{0} ** test_counts_len;
    const expected = [_]u16{ 0, 2, 0, 2, 0 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &counts, &healthy);
        try std.testing.expectEqual(want_index, picked.endpoint_index);
    }
}

test "balancer: p2c never picks an ejected endpoint" {
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

    // Even the least-loaded endpoint is off the table while ejected —
    // health outranks load (§7).
    var healthy = test_healthy_all;
    healthy[upstream.endpointKey(0, 1)] = false;
    var counts = [_]u16{0} ** test_counts_len;
    counts[upstream.endpointKey(0, 0)] = 50;
    counts[upstream.endpointKey(0, 2)] = 50;
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const picked = balancer.pick(0, &counts, &healthy);
        try std.testing.expect(picked.endpoint_index != 1);
    }
}

test "balancer: p2c narrowed to one healthy endpoint spends no draw" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const pair = [_]std.Io.net.IpAddress{ a, b };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .p2c },
    };
    const config = testConfig(&clusters);

    var balancer: Balancer = undefined;
    balancer.init(&config);
    const state_before = balancer.pick_state;

    // One survivor: the pick is forced, so the PRNG must not advance —
    // the same no-draw rule as a single-endpoint cluster.
    var healthy = test_healthy_all;
    healthy[upstream.endpointKey(0, 0)] = false;
    const counts = [_]u16{0} ** test_counts_len;
    var round: u32 = 0;
    while (round < 10) : (round += 1) {
        const picked = balancer.pick(0, &counts, &healthy);
        try std.testing.expectEqual(@as(u16, 1), picked.endpoint_index);
    }
    try std.testing.expectEqual(state_before, balancer.pick_state);
}

test "balancer: a fully-ejected cluster fails open to every endpoint" {
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

    // Every endpoint ejected: the mask must not brick the cluster —
    // rotation runs over the full set as if no prober existed (§7).
    var healthy = test_healthy_all;
    healthy[upstream.endpointKey(0, 0)] = false;
    healthy[upstream.endpointKey(0, 1)] = false;
    healthy[upstream.endpointKey(0, 2)] = false;
    const counts = [_]u16{0} ** test_counts_len;
    const expected = [_]u16{ 0, 1, 2, 0, 1 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &counts, &healthy);
        try std.testing.expectEqual(want_index, picked.endpoint_index);
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
        try std.testing.expectEqual(want_index, balancer.pick(0, &counts, &test_healthy_all).endpoint_index);
        _ = balancer.pick(1, &counts, &test_healthy_all);
    }
}
