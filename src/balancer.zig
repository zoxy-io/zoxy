//! Upstream endpoint selection (DESIGN.md §7): the load-balancing policy
//! kept behind a seam so the serving path never hardcodes *how* an
//! endpoint is chosen — it only asks "which endpoint for this cluster?".
//! Three policies, selected per cluster in the config (§5 parse-once):
//! `rr` rotates a per-cluster cursor, `p2c` draws two distinct candidates
//! uniformly and leases the calmer one, `hash` sends a given client to a
//! given endpoint every time. P2C's load is the per-endpoint in-flight
//! total across both protocols — the pool's L7 leases plus the server's
//! live L4 connections — passed in by the caller as a view: the balancer
//! owns the draw, the pool and the server own the truth. A single-endpoint
//! cluster short-circuits every policy without touching its state.
//!
//! **Why `hash` is stateless, and why that is not merely a simplification.**
//! Stickiness is usually a *table*: HAProxy records client → server as
//! connections arrive. That mechanism cannot work here. zoxy scales out as
//! N independent processes behind SO_REUSEPORT (§3), the kernel picks the
//! listening socket by hashing the connection's **4-tuple** — source port
//! included — so one client's connections land on *different processes*,
//! and a per-process table would be populated by whichever process saw
//! that client first. HAProxy hit exactly this: its own manual states
//! stick-tables are per process and never shared, and its answer was to
//! abandon multi-process for threads sharing memory — an option §1 rules
//! out here. Rendezvous hashing needs no table: the endpoint is a pure
//! function of the key and the eligible set, so every process computes the
//! same answer with nothing shared. Statelessness is what makes it correct
//! under this process model, not just cheap.
//!
//! **Why rendezvous rather than a ring or Maglev.** Both of those answer
//! a lookup from a precomputed table, and a table has to be *rebuilt*
//! whenever membership changes — which here is every health-check
//! ejection and recovery (§7), on the one thread that must not stall
//! (§3). A 64-endpoint ring at any useful virtual-node count is a
//! thousands-of-entries sort per flap. Rendezvous has no table to rebuild:
//! it scans the eligible set the health mask already produced. It costs
//! O(n) instead of O(log n), which is why the endpoint ceiling matters —
//! measured at 71 ns per pick for the 64 endpoints a cluster may hold,
//! against a request this proxy serves in ~100 µs. Jump consistent hash is
//! excluded outright: it can only add or remove the *last* bucket, and an
//! ejection removes an arbitrary one.

const std = @import("std");

const config_module = @import("config.zig");
const upstream = @import("net/upstream.zig");

const assert = std.debug.assert;

/// The 64-bit finalizer every §7 hash here is built from (SplitMix64's,
/// also MurmurHash3's `fmix64`).
///
/// **Written out rather than taken from `std.hash`, deliberately.** This
/// function *is* the client-to-backend mapping: change it and every client
/// moves to a different endpoint at once. `std` makes no promise to keep a
/// hash stable across toolchain versions, and a rolling restart runs two
/// binaries side by side — so a silent change there would be a silent
/// re-shuffle here, during the exact window when half the fleet is on each
/// build. Pinned here, and pinned again by a test vector, so a remap can
/// only ever be a deliberate edit.
fn mix64(value: u64) u64 {
    var x = value;
    x ^= x >> 30;
    x *%= 0xBF58476D1CE4E5B9;
    x ^= x >> 27;
    x *%= 0x94D049BB133111EB;
    x ^= x >> 31;
    return x;
}

/// The §7 stickiness key for a client address.
///
/// IPv4 contributes all four bytes. IPv6 contributes **only the /64
/// prefix**, because the low 64 bits are the interface identifier and
/// RFC 8981 privacy addressing rotates it every few hours — hashing the
/// whole address would silently re-home most mobile clients on a timer,
/// which is the opposite of what a stickiness policy is for. A /64 is
/// also the smallest block a site is normally delegated, so it is the
/// right unit of "one client" on IPv6.
///
/// The port is excluded on both: it changes with every connection, and
/// stickiness across connections is the entire feature.
///
/// By pointer, like every address here: an `IpAddress` is 32 bytes, twice
/// the threshold TIGER_STYLE sets for by-value arguments, and this runs
/// once per pick on a `hash` cluster.
fn sourceKey(address: *const std.Io.net.IpAddress) u64 {
    return switch (address.*) {
        .ip4 => |v4| mix64(std.mem.readInt(u32, &v4.bytes, .big)),
        .ip6 => |v6| mix64(std.mem.readInt(u64, v6.bytes[0..8], .big)),
    };
}

/// An endpoint's stable identity for scoring: its address *and* port, so
/// two endpoints sharing a host are distinct, and nothing positional, so
/// the config list can grow or be reordered without remapping clients.
fn endpointId(address: *const std.Io.net.IpAddress) u64 {
    // The loader rejects a zero endpoint port (`EndpointPortZero`), and
    // this folds the port into the identity — so a zero here would mean a
    // caller reached past config validation, and two endpoints that
    // differ only in a port nobody validated would be scored as one.
    assert(address.getPort() != 0);
    return switch (address.*) {
        .ip4 => |v4| mix64(
            (@as(u64, std.mem.readInt(u32, &v4.bytes, .big)) << 16) | v4.port,
        ),
        .ip6 => |v6| mix64(mix64(std.mem.readInt(u64, v6.bytes[0..8], .big)) ^
            mix64(std.mem.readInt(u64, v6.bytes[8..16], .big) ^ v6.port)),
    };
}

pub const Balancer = struct {
    config: *const config_module.Config,
    /// Per-cluster round-robin cursors, used by `.rr` clusters only.
    /// u64 so a cursor never wraps in any realistic process lifetime — a
    /// u16 wrap reset the rotation phase and double-picked one endpoint
    /// for non-power-of-two cluster sizes. One per configured cluster.
    cursors: []u64,
    /// xorshift64* draw state, used by `.p2c` clusters only. Seeded from
    /// a fixed named constant, never the clock: the simulator replays
    /// every seed twice and demands byte-identical traces (§9), and load
    /// balancing needs spread, not secrecy — determinism is a feature.
    pick_state: u64,
    /// One stable 64-bit identity per endpoint, used by `.hash` clusters
    /// only (§7). Derived from the endpoint's *address*, never from its
    /// position in the config list: an operator appending an endpoint, or
    /// reordering the list, would otherwise remap every client at once —
    /// the exact disruption consistent hashing exists to avoid. Computed
    /// once at init because a pick would otherwise re-hash every candidate
    /// address on every request.
    endpoint_hashes: []u64,
    /// The config's endpoint index space, shared with the pool and the
    /// health checker so all three agree on what a key means.
    keys: upstream.EndpointKeys,
    /// Scratch for `pick`'s eligible-endpoint list, `keys.stride` long.
    /// It was a stack array sized by the old compile-time ceiling; with
    /// the ceiling gone the length is a runtime value, and a
    /// runtime-length stack array is exactly the dynamic allocation §5
    /// forbids — so it is allocated once at init and reused. Sound
    /// because a pick never overlaps another: the loop is single-threaded
    /// and `pick` neither suspends nor re-enters.
    eligible_scratch: []u16,

    /// Any nonzero constant seeds xorshift64* soundly; this one is the
    /// 64-bit golden-ratio constant, chosen for being recognizable.
    const pick_seed: u64 = 0x9E3779B97F4A7C15;

    pub fn init(
        balancer: *Balancer,
        arena: std.mem.Allocator,
        config: *const config_module.Config,
        keys: upstream.EndpointKeys,
    ) error{OutOfMemory}!void {
        assert(config.clusters.len >= 1);
        assert(keys.count >= 1);
        // The keys must describe *this* config. Tests and the simulator
        // build a `Config` directly, bypassing the loader, so a mismatched
        // pair would size these tables for one shape and index them for
        // another — which is what the `clusters_max` ceiling used to catch
        // here, before the tables stopped being sized by it.
        assert(keys.count == @as(u32, @intCast(config.clusters.len)) * keys.stride);
        balancer.config = config;
        balancer.keys = keys;
        balancer.cursors = try arena.alloc(u64, config.clusters.len);
        balancer.endpoint_hashes = try arena.alloc(u64, keys.count);
        balancer.eligible_scratch = try arena.alloc(u16, keys.stride);
        @memset(balancer.cursors, 0);
        balancer.pick_state = pick_seed;
        assert(balancer.pick_state != 0); // xorshift64* cycles on nonzero state.
        // Every key, not only the configured ones: a ragged config leaves
        // holes between clusters, those slots are never read, and zeroing
        // the whole table keeps "what did init leave here" a question with
        // one answer.
        @memset(balancer.endpoint_hashes, 0);
        for (config.clusters, 0..) |cluster, cluster_index| {
            // Re-checked here rather than trusted from the loader, the
            // same defense `pick` and `eligibleEndpoints` keep: this loop
            // indexes a table sized by that stride.
            assert(cluster.endpoints.len >= 1);
            assert(cluster.endpoints.len <= keys.stride);
            for (cluster.endpoints, 0..) |*address, endpoint_index| {
                const key = keys.key(@intCast(cluster_index), @intCast(endpoint_index));
                balancer.endpoint_hashes[key] = endpointId(address);
            }
        }
        assert(balancer.cursors.len == config.clusters.len);
        assert(balancer.endpoint_hashes.len == keys.count);
    }

    /// A pick names the endpoint both ways: the address to dial and the
    /// index the upstream pool keys its idle lists by (§5).
    pub const Pick = struct {
        address: std.Io.net.IpAddress,
        endpoint_index: u16,
    };

    /// Choose the endpoint to dial for `cluster_index` under the
    /// cluster's configured policy. `load` is the per-endpoint in-flight
    /// view (indexed by `upstream.endpointKey`), consulted by p2c and
    /// ignored by rr; `healthy` is the §7 health mask (same index) — the
    /// prober owns that truth the way the pool and the server own the
    /// load. Bounded work, no allocation, and a validated config
    /// guarantees at least one endpoint.
    pub fn pick(
        balancer: *Balancer,
        cluster_index: u16,
        load: *const upstream.Load,
        healthy: []const bool,
        client_address: *const std.Io.net.IpAddress,
    ) ?Pick {
        assert(cluster_index < balancer.config.clusters.len);
        const cluster = &balancer.config.clusters[cluster_index];
        assert(cluster.endpoints.len >= 1);
        assert(cluster.endpoints.len <= balancer.keys.stride);
        if (cluster.endpoints.len == 1 and cluster.max_inflight == null) {
            // Neither a rotation nor a draw: uncapped single-endpoint
            // clusters stay branch-cheap and policy state is untouched.
            // The mask is moot too — one endpoint ejected is the
            // fail-open case. A cap has to be read, so it takes the
            // general path below.
            return .{ .address = cluster.endpoints[0], .endpoint_index = 0 };
        }
        const eligible = balancer.eligible_scratch;
        const count = eligibleEndpoints(balancer.keys, cluster_index, cluster, load, healthy, eligible);
        if (count == 0) {
            // Every endpoint is at its §8 cap. Unlike the health mask
            // this does *not* fail open: an ejected cluster means "we do
            // not know, try anyway", while a capped one means "we know
            // they are full", and dialing anyway is the exact thing the
            // cap exists to stop.
            return null;
        }
        const chosen = switch (cluster.pick) {
            .rr => balancer.pickRoundRobin(cluster_index, eligible[0..count]),
            .p2c => balancer.pickPowerOfTwo(cluster_index, eligible[0..count], load),
            .hash => balancer.pickHash(cluster_index, eligible[0..count], client_address),
        };
        assert(chosen < cluster.endpoints.len);
        return .{
            .address = cluster.endpoints[chosen],
            .endpoint_index = chosen,
        };
    }

    /// The endpoints a pick may choose between, in two passes.
    ///
    /// First §7 health: the healthy ones — or, the fail-open rule, every
    /// endpoint when the whole cluster is ejected. Dialing a maybe-dead
    /// endpoint reports the outage the way it always did; routing
    /// nowhere would turn a probe verdict into an outage of its own, and
    /// a same-port TCP probe cannot know better than the dial.
    ///
    /// Then §8 capacity, over whatever survived: an endpoint already
    /// carrying its `max_inflight` is dropped. This pass **may return
    /// zero**, and that is the difference from the health pass — the
    /// caller sheds rather than dialing. The order matters too: capacity
    /// is judged over the endpoints health would have used, so a cluster
    /// that fails open still respects its caps.
    fn eligibleEndpoints(
        keys: upstream.EndpointKeys,
        cluster_index: u16,
        cluster: *const config_module.Config.Cluster,
        load: *const upstream.Load,
        healthy: []const bool,
        eligible: []u16,
    ) u16 {
        assert(cluster.endpoints.len >= 1);
        assert(cluster.endpoints.len <= eligible.len);
        var count: u16 = 0;
        for (0..cluster.endpoints.len) |endpoint_index| {
            const index: u16 = @intCast(endpoint_index);
            if (healthy[keys.key(cluster_index, index)]) {
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
        if (cluster.max_inflight) |cap| {
            assert(cap >= 1);
            var under: u16 = 0;
            for (eligible[0..count]) |index| {
                if (load.inFlight(keys.key(cluster_index, index)) < cap) {
                    eligible[under] = index;
                    under += 1;
                }
            }
            count = under;
        }
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
    /// lower in-flight total wins, a tie goes to the first. A mask narrowed
    /// to one endpoint skips the draw the way a one-endpoint cluster
    /// does — no candidates to compare, no PRNG state spent.
    fn pickPowerOfTwo(
        balancer: *Balancer,
        cluster_index: u16,
        eligible: []const u16,
        load: *const upstream.Load,
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
        // Both protocols count here (§7): an L4 dial holds no upstream
        // slot, so before this view the draw on a pure-L4 cluster read a
        // table of zeros and spread uniformly while presenting as
        // load-aware.
        const first_load = load.inFlight(balancer.keys.key(cluster_index, first));
        const second_load = load.inFlight(balancer.keys.key(cluster_index, second));
        return if (second_load < first_load) second else first;
    }

    /// Rendezvous hashing (§7): score every eligible endpoint against the
    /// client's key and take the highest. Two properties follow, and both
    /// are the point.
    ///
    /// *Stickiness*: the score depends only on the key and the endpoint's
    /// own identity, so the same client reaches the same endpoint from
    /// every process, every connection, and every restart.
    ///
    /// *Minimal disruption*: when an endpoint is ejected, only the clients
    /// whose highest score it was see any change — their next-highest
    /// takes over, and every other client's argmax is untouched. That is
    /// the 1/n optimum, and it is why the fallback needs no separate
    /// mechanism: "walk the preference order to the first healthy
    /// endpoint" and "argmax over the healthy ones" are the same
    /// computation, so this single pass is both.
    ///
    /// Spends no PRNG state: a draw would make two processes disagree,
    /// which is the one thing this policy exists to prevent.
    fn pickHash(
        balancer: *const Balancer,
        cluster_index: u16,
        eligible: []const u16,
        client_address: *const std.Io.net.IpAddress,
    ) u16 {
        assert(balancer.config.clusters[cluster_index].pick == .hash);
        assert(eligible.len >= 1);
        const key = switch (balancer.config.clusters[cluster_index].hash_key) {
            .source_ip => sourceKey(client_address),
        };
        var best = eligible[0];
        var best_score = balancer.score(key, cluster_index, best);
        for (eligible[1..]) |candidate| {
            const candidate_score = balancer.score(key, cluster_index, candidate);
            // Strictly greater, so an exact tie keeps the lower endpoint
            // index. Two 64-bit scores colliding is a ~2⁻⁶⁴ event, but
            // "improbable" is not "impossible", and two processes
            // resolving one differently would break the stickiness this
            // whole policy promises.
            if (candidate_score > best_score) {
                best_score = candidate_score;
                best = candidate;
            }
        }
        assert(best < balancer.config.clusters[cluster_index].endpoints.len);
        return best;
    }

    fn score(
        balancer: *const Balancer,
        key: u64,
        cluster_index: u16,
        endpoint_index: u16,
    ) u64 {
        // Stated here rather than borrowed from `endpointKey`'s own
        // bounds: this reads a table whose configured entries stop at the
        // cluster's endpoint count, and an index past that would score a
        // zeroed slot — a real endpoint losing to one that does not exist.
        assert(cluster_index < balancer.config.clusters.len);
        assert(endpoint_index < balancer.config.clusters[cluster_index].endpoints.len);
        const endpoint_hash =
            balancer.endpoint_hashes[balancer.keys.key(cluster_index, endpoint_index)];
        // Both operands are already avalanched, so the xor combines them
        // without structure and the final mix restores it to a uniform
        // 64-bit score.
        return mix64(key ^ endpoint_hash);
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

/// The index space every test here builds its tables against. Wider than
/// any test cluster on both axes, so a stride bug shows up as a key
/// landing in another cluster's row rather than out of bounds.
const test_keys: upstream.EndpointKeys = .init(4, 8);

/// The index space a test's own config implies — the same derivation
/// `Server.endpointKeysFor` does in production, which `init` now asserts
/// the caller got right. Tables below stay `test_keys`-sized (wider than
/// any test config) because every test indexes cluster 0, where the key
/// is the endpoint index whatever the stride is.
fn testKeysFor(config: *const config_module.Config) upstream.EndpointKeys {
    var stride: u16 = 1;
    for (config.clusters) |cluster| {
        stride = @max(stride, @as(u16, @intCast(cluster.endpoints.len)));
    }
    return .init(@intCast(config.clusters.len), stride);
}

const test_counts_len = test_keys.count;

/// The no-prober baseline every pre-mask test picks through: all healthy,
/// exactly what `Checker.init` hands a server whose clusters never check.
const test_healthy_all = [_]bool{true} ** test_keys.count;

/// The L4 half of the load view, all zero: what a pure-L7 test sees.
const test_l4_idle = [_]u16{0} ** test_keys.count;

/// A load view over an L7 lease table, for the tests that only vary
/// that half. The pair-of-tables shape is what production passes.
fn testLoad(l7: *const [test_keys.count]u16) upstream.Load {
    return .{ .l7 = l7, .l4 = &test_l4_idle };
}

/// The client address `rr`/`p2c` scenarios pass and ignore; only `.hash`
/// reads it.
const test_client = std.Io.net.IpAddress.parseLiteral("198.51.100.7:40000") catch unreachable;

fn testAddress(comptime literal: []const u8) std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral(literal) catch unreachable;
}

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

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Rotation is exact whatever the load table says: rr ignores it.
    var counts = [_]u16{0} ** test_counts_len;
    counts[test_keys.key(0, 0)] = 100;
    const expected = [_]u16{ 0, 1, 2, 0, 1 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client).?;
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

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));
    const state_before = balancer.pick_state;

    const counts = [_]u16{0} ** test_counts_len;
    var round: u32 = 0;
    while (round < 10) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client).?;
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

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Endpoint 1 is drowning; 0 and 2 are idle. Whatever pair is drawn,
    // the pick must never be the drowning endpoint: any pair containing
    // it also contains an idle endpoint that wins the comparison.
    var counts = [_]u16{0} ** test_counts_len;
    counts[test_keys.key(0, 1)] = 100;
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client).?;
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

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // With every count equal the tie rule keeps the first candidate — a
    // uniform draw — so all endpoints must be hit over a modest run.
    const counts = [_]u16{0} ** test_counts_len;
    var hits = [_]u32{0} ** 3;
    var round: u32 = 0;
    while (round < 300) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client).?;
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

    var left_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer left_arena.deinit();
    var left: Balancer = undefined;
    try left.init(left_arena.allocator(), &config, testKeysFor(&config));
    var right_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer right_arena.deinit();
    var right: Balancer = undefined;
    try right.init(right_arena.allocator(), &config, testKeysFor(&config));

    // The simulator replays every seed twice and hashes the traces (§9);
    // two same-seed balancers must agree draw for draw.
    const counts = [_]u16{0} ** test_counts_len;
    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        try std.testing.expectEqual(
            left.pick(0, &testLoad(&counts), &test_healthy_all, &test_client).?.endpoint_index,
            right.pick(0, &testLoad(&counts), &test_healthy_all, &test_client).?.endpoint_index,
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

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Endpoint 1 is ejected (§7): rotation covers the survivors exactly,
    // never the ejected one.
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, 1)] = false;
    const counts = [_]u16{0} ** test_counts_len;
    const expected = [_]u16{ 0, 2, 0, 2, 0 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client).?;
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

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Even the least-loaded endpoint is off the table while ejected —
    // health outranks load (§7).
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, 1)] = false;
    var counts = [_]u16{0} ** test_counts_len;
    counts[test_keys.key(0, 0)] = 50;
    counts[test_keys.key(0, 2)] = 50;
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client).?;
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

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));
    const state_before = balancer.pick_state;

    // One survivor: the pick is forced, so the PRNG must not advance —
    // the same no-draw rule as a single-endpoint cluster.
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, 0)] = false;
    const counts = [_]u16{0} ** test_counts_len;
    var round: u32 = 0;
    while (round < 10) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client).?;
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

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Every endpoint ejected: the mask must not brick the cluster —
    // rotation runs over the full set as if no prober existed (§7).
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, 0)] = false;
    healthy[test_keys.key(0, 1)] = false;
    healthy[test_keys.key(0, 2)] = false;
    const counts = [_]u16{0} ** test_counts_len;
    const expected = [_]u16{ 0, 1, 2, 0, 1 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client).?;
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

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Interleaving a p2c cluster's draws must not perturb the rr
    // cluster's rotation: cursor and PRNG are separate state.
    const counts = [_]u16{0} ** test_counts_len;
    const expected = [_]u16{ 0, 1, 0, 1, 0 };
    for (expected) |want_index| {
        try std.testing.expectEqual(want_index, balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client).?.endpoint_index);
        _ = balancer.pick(1, &testLoad(&counts), &test_healthy_all, &test_client);
    }
}

/// A cluster of `count` endpoints at 10.0.0.1..N, for the §7 hash tests.
fn testHashEndpoints(comptime count: u16) [count]std.Io.net.IpAddress {
    var endpoints: [count]std.Io.net.IpAddress = undefined;
    for (&endpoints, 0..) |*endpoint, index| {
        endpoint.* = .{ .ip4 = .{
            .bytes = .{ 10, 0, 0, @intCast(index + 1) },
            .port = 8080,
        } };
    }
    return endpoints;
}

/// The n-th distinct simulated client, as an IPv4 address.
fn testClientAt(index: u16) std.Io.net.IpAddress {
    return .{ .ip4 = .{
        .bytes = .{ 203, 0, @intCast(index >> 8), @intCast(index & 0xff) },
        .port = 50_000,
    } };
}

test "balancer: hash sends one client to one endpoint, every time" {
    const endpoints = testHashEndpoints(8);
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    const counts = [_]u16{0} ** test_counts_len;
    const client = testAddress("203.0.113.9:51000");
    const first = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client).?.endpoint_index;
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const again = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client).?;
        try std.testing.expectEqual(first, again.endpoint_index);
        try std.testing.expectEqual(endpoints[first], again.address);
    }
    // The load table is what p2c reads; hash must ignore it, or two
    // processes under different load would disagree about one client.
    var loaded = [_]u16{0} ** test_counts_len;
    loaded[test_keys.key(0, first)] = 10_000;
    try std.testing.expectEqual(
        first,
        balancer.pick(0, &testLoad(&loaded), &test_healthy_all, &client).?.endpoint_index,
    );
}

test "balancer: hash spends no PRNG state and needs none" {
    // A draw would make two processes disagree about the same client,
    // which is the one thing this policy exists to prevent (§3, §7).
    const endpoints = testHashEndpoints(8);
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));
    const state_before = balancer.pick_state;

    const counts = [_]u16{0} ** test_counts_len;
    var index: u16 = 0;
    while (index < 500) : (index += 1) {
        _ = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index));
    }
    try std.testing.expectEqual(state_before, balancer.pick_state);
}

test "balancer: hash spreads distinct clients across every endpoint" {
    const endpoints = testHashEndpoints(8);
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    const counts = [_]u16{0} ** test_counts_len;
    const clients: u16 = 4000;
    var hits = [_]u32{0} ** 8;
    var index: u16 = 0;
    while (index < clients) : (index += 1) {
        hits[balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index)).?.endpoint_index] += 1;
    }
    // Rendezvous gives each client an independent uniform choice, so the
    // spread is a balls-in-bins one: loose bounds, but every endpoint must
    // carry a real share — a systematically dead endpoint would mean the
    // score is not actually a function of both operands.
    const expected = clients / 8;
    for (hits) |hit_count| {
        try std.testing.expect(hit_count > expected / 2);
        try std.testing.expect(hit_count < expected * 2);
    }
}

test "balancer: ejecting an endpoint moves its clients and nobody else's" {
    // The property that makes this *consistent* hashing rather than
    // `hash % n` (§7): when the endpoint set changes, the disruption is
    // confined to the clients of the endpoint that left. Modulo hashing
    // would remap nearly everyone, and a fleet-wide remap on one backend's
    // health flap is exactly the outage this avoids.
    const endpoints = testHashEndpoints(8);
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    const counts = [_]u16{0} ** test_counts_len;
    const clients: u16 = 4000;
    var before: [clients]u16 = undefined;
    var index: u16 = 0;
    while (index < clients) : (index += 1) {
        before[index] = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index)).?.endpoint_index;
    }

    const ejected: u16 = 3;
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, ejected)] = false;

    var moved: u32 = 0;
    index = 0;
    while (index < clients) : (index += 1) {
        const after = balancer.pick(0, &testLoad(&counts), &healthy, &testClientAt(index)).?.endpoint_index;
        try std.testing.expect(after != ejected);
        if (before[index] == ejected) {
            moved += 1;
        } else {
            // Untouched: this client's endpoint is still up, so nothing
            // about the ejection may reach it.
            try std.testing.expectEqual(before[index], after);
        }
    }
    // Everyone who moved is exactly the ejected endpoint's population,
    // which is ~1/8 of the clients — the 1/n optimum.
    try std.testing.expect(moved > 0);
    try std.testing.expectEqual(moved, countOf(&before, ejected));

    // Restoring the endpoint restores every one of them, and disturbs
    // nobody: stickiness survives a flap rather than drifting with it.
    index = 0;
    while (index < clients) : (index += 1) {
        try std.testing.expectEqual(
            before[index],
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index)).?.endpoint_index,
        );
    }
}

fn countOf(picks: []const u16, wanted: u16) u32 {
    var total: u32 = 0;
    for (picks) |pick_index| {
        if (pick_index == wanted) total += 1;
    }
    return total;
}

test "balancer: two processes agree, and so do a config's reorderings" {
    // Cross-process stickiness rests on the mapping being a pure function
    // of the key and the eligible set (§3): no seeding, no arrival order,
    // no dependence on where an endpoint sits in the config list. The
    // second half is what lets an operator append or reorder endpoints
    // without re-homing every client — identity is the address, not the
    // index.
    const forward = testHashEndpoints(8);
    var reversed: [8]std.Io.net.IpAddress = undefined;
    for (forward, 0..) |endpoint, index| {
        reversed[7 - index] = endpoint;
    }
    const forward_clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &forward, .pick = .hash },
    };
    const reversed_clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &reversed, .pick = .hash },
    };
    const forward_config = testConfig(&forward_clusters);
    const reversed_config = testConfig(&reversed_clusters);

    var left_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer left_arena.deinit();
    var left: Balancer = undefined;
    try left.init(left_arena.allocator(), &forward_config, testKeysFor(&forward_config));
    var right_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer right_arena.deinit();
    var right: Balancer = undefined;
    try right.init(right_arena.allocator(), &reversed_config, testKeysFor(&reversed_config));

    const counts = [_]u16{0} ** test_counts_len;
    var index: u16 = 0;
    while (index < 1000) : (index += 1) {
        const client = testClientAt(index);
        const left_pick = left.pick(0, &testLoad(&counts), &test_healthy_all, &client).?;
        const right_pick = right.pick(0, &testLoad(&counts), &test_healthy_all, &client).?;
        // The *address* must match; the index deliberately need not, the
        // lists being permutations of each other.
        try std.testing.expectEqual(left_pick.address, right_pick.address);
    }
}

test "balancer: an IPv6 client keeps its endpoint when its /64 does" {
    // RFC 8981 privacy addressing rotates the low 64 bits every few hours.
    // Hashing the whole address would silently re-home most mobile clients
    // on that timer — a stickiness policy that expires is not one.
    const endpoints = testHashEndpoints(8);
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    const counts = [_]u16{0} ** test_counts_len;
    const first = testAddress("[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:51000");
    const rotated = testAddress("[2001:db8:1:2:1111:2222:3333:4444]:52000");
    try std.testing.expectEqual(
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &first).?.endpoint_index,
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &rotated).?.endpoint_index,
    );

    // A different /64 is a different client and must be free to land
    // elsewhere — otherwise the mask has swallowed the whole key. Scan a
    // range so the assertion does not rest on one lucky prefix.
    var differs = false;
    var prefix: u16 = 0;
    while (prefix < 64) : (prefix += 1) {
        var other = first;
        other.ip6.bytes[7] = @intCast(prefix);
        if (balancer.pick(0, &testLoad(&counts), &test_healthy_all, &other).?.endpoint_index !=
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &first).?.endpoint_index)
        {
            differs = true;
            break;
        }
    }
    try std.testing.expect(differs);
}

test "balancer: the hash is pinned, so a refactor cannot re-home the fleet" {
    // These constants ARE the client-to-backend mapping. If a change here
    // is ever intentional it is a fleet-wide remap and must be planned as
    // one; if it is unintentional this test is the only thing that says so.
    //
    // `mix64` is SplitMix64's finalizer, so feeding it the golden-ratio
    // increment reproduces that generator's published first output for
    // seed 0 — an external check, not just a value read back off our own
    // implementation.
    try std.testing.expectEqual(@as(u64, 0xE220A8397B1DCDAF), mix64(0x9E3779B97F4A7C15));
    try std.testing.expectEqual(@as(u64, 0x5692161D100B05E5), mix64(1));
    // The finalizer's fixed point. Worth pinning because it is reachable:
    // `Io.peerAddress` reports 0.0.0.0:0 when the kernel cannot name a
    // peer, so every such client hashes to key 0 and shares one endpoint.
    // Deterministic and harmless — but a property to know about rather
    // than rediscover.
    try std.testing.expectEqual(@as(u64, 0), mix64(0));
    try std.testing.expectEqual(@as(u64, 0), sourceKeyOf("0.0.0.0:0"));

    // An IPv4 key covers all four bytes; an IPv6 key covers the /64 only,
    // so these two v6 addresses must produce the *same* key.
    try std.testing.expectEqual(
        sourceKeyOf("[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:1"),
        sourceKeyOf("[2001:db8:1:2:0:0:0:1]:2"),
    );
    try std.testing.expect(
        sourceKeyOf("203.0.113.9:1") != sourceKeyOf("203.0.113.10:1"),
    );
    // The port is not part of a client's identity — a new connection from
    // the same client must not re-home it.
    try std.testing.expectEqual(
        sourceKeyOf("203.0.113.9:1"),
        sourceKeyOf("203.0.113.9:65535"),
    );
    // An endpoint's identity *does* include its port: two backends on one
    // host are two backends.
    try std.testing.expect(
        endpointIdOf("10.0.0.1:8080") != endpointIdOf("10.0.0.1:8081"),
    );
}

test "balancer: a fully ejected hash cluster still answers, deterministically" {
    // §7 fail-open: when every endpoint is ejected the mask is ignored and
    // the whole set is eligible again. Hashing must stay a pure function
    // through that transition, or a total outage would also scramble every
    // client's assignment on the way back out.
    const endpoints = testHashEndpoints(4);
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    const counts = [_]u16{0} ** test_counts_len;
    const none_healthy = [_]bool{false} ** test_keys.count;
    var index: u16 = 0;
    while (index < 500) : (index += 1) {
        const client = testClientAt(index);
        // Fail-open restores the full set, so the answer is the same one
        // the healthy cluster gives.
        try std.testing.expectEqual(
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client).?.endpoint_index,
            balancer.pick(0, &testLoad(&counts), &none_healthy, &client).?.endpoint_index,
        );
    }
}

/// `sourceKey`/`endpointId` take their address by pointer (32 bytes,
/// TIGER_STYLE's threshold), so a test needs somewhere for the temporary
/// to live. These bind it.
fn sourceKeyOf(comptime literal: []const u8) u64 {
    const address = testAddress(literal);
    return sourceKey(&address);
}

fn endpointIdOf(comptime literal: []const u8) u64 {
    const address = testAddress(literal);
    return endpointId(&address);
}

test "balancer: p2c weighs L4 connections, not only L7 leases" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const c = std.Io.net.IpAddress.parseLiteral("127.0.0.1:3") catch unreachable;
    const trio = [_]std.Io.net.IpAddress{ a, b, c };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "trio", .endpoints = &trio, .pick = .p2c },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // A pure-L4 cluster: the lease table stays empty for its whole life,
    // so before the load view this draw compared zero against zero and
    // spread uniformly while presenting as load-aware. Endpoint 1 is
    // drowning in relayed connections; any pair containing it also
    // contains a calmer endpoint, so it must never win.
    const l7_idle = [_]u16{0} ** test_counts_len;
    var l4 = [_]u16{0} ** test_counts_len;
    l4[test_keys.key(0, 1)] = 100;
    const load: upstream.Load = .{ .l7 = &l7_idle, .l4 = &l4 };
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        try std.testing.expect(balancer.pick(0, &load, &test_healthy_all, &test_client).?.endpoint_index != 1);
    }
}

test "balancer: p2c compares the sum of both protocols" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const pair = [_]std.Io.net.IpAddress{ a, b };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .p2c },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Endpoint 0 carries 5 requests and no connections; endpoint 1
    // carries 1 request and 9 connections. Reading either table alone
    // picks the wrong one — only the total (5 against 10) is the load
    // the origin actually feels.
    var l7 = [_]u16{0} ** test_counts_len;
    var l4 = [_]u16{0} ** test_counts_len;
    l7[test_keys.key(0, 0)] = 5;
    l7[test_keys.key(0, 1)] = 1;
    l4[test_keys.key(0, 1)] = 9;
    const load: upstream.Load = .{ .l7 = &l7, .l4 = &l4 };
    try std.testing.expectEqual(@as(u32, 5), load.inFlight(test_keys.key(0, 0)));
    try std.testing.expectEqual(@as(u32, 10), load.inFlight(test_keys.key(0, 1)));
    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        try std.testing.expectEqual(
            @as(u16, 0),
            balancer.pick(0, &load, &test_healthy_all, &test_client).?.endpoint_index,
        );
    }
}

test "balancer: a capped endpoint is skipped while another has room" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const pair = [_]std.Io.net.IpAddress{ a, b };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .rr, .max_inflight = 2 },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Endpoint 0 is at its cap, endpoint 1 is not. Rotation must land on
    // 1 every time — a cap narrows the eligible set, it does not shed
    // while any endpoint can still take work.
    var l7 = [_]u16{0} ** test_counts_len;
    l7[test_keys.key(0, 0)] = 2;
    const load = testLoad(&l7);
    var round: u32 = 0;
    while (round < 8) : (round += 1) {
        try std.testing.expectEqual(
            @as(u16, 1),
            balancer.pick(0, &load, &test_healthy_all, &test_client).?.endpoint_index,
        );
    }
}

test "balancer: a fully capped cluster refuses rather than failing open" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const pair = [_]std.Io.net.IpAddress{ a, b };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .p2c, .max_inflight = 3 },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Both endpoints at capacity: no pick. This is the deliberate
    // difference from the health mask, which fails *open* — an ejected
    // cluster means "we do not know", a capped one means "we know they
    // are full", and dialing anyway is what the cap exists to stop.
    var l7 = [_]u16{0} ** test_counts_len;
    l7[test_keys.key(0, 0)] = 3;
    l7[test_keys.key(0, 1)] = 3;
    try std.testing.expectEqual(
        @as(?Balancer.Pick, null),
        balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client),
    );
    // One request completes on endpoint 1 and the cluster serves again.
    l7[test_keys.key(0, 1)] = 2;
    try std.testing.expectEqual(
        @as(u16, 1),
        balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client).?.endpoint_index,
    );
}

test "balancer: the cap counts both protocols, and covers one endpoint" {
    const solo = std.Io.net.IpAddress.parseLiteral("127.0.0.1:9") catch unreachable;
    const one = [_]std.Io.net.IpAddress{solo};
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "one", .endpoints = &one, .max_inflight = 4 },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // A single-endpoint cluster takes the fast path when uncapped; with
    // a cap it must not, or the one endpoint could never be protected.
    // Three L7 requests and one L4 connection is four: at the cap.
    var l7 = [_]u16{0} ** test_counts_len;
    var l4 = [_]u16{0} ** test_counts_len;
    l7[test_keys.key(0, 0)] = 3;
    l4[test_keys.key(0, 0)] = 1;
    const load: upstream.Load = .{ .l7 = &l7, .l4 = &l4 };
    try std.testing.expectEqual(
        @as(?Balancer.Pick, null),
        balancer.pick(0, &load, &test_healthy_all, &test_client),
    );
    // Reading either table alone would leave room and dial anyway.
    try std.testing.expect(l7[test_keys.key(0, 0)] < 4);
    try std.testing.expect(l4[test_keys.key(0, 0)] < 4);
}

test "balancer: capacity is judged over the endpoints health left" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const pair = [_]std.Io.net.IpAddress{ a, b };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .rr, .max_inflight = 1 },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Endpoint 0 is ejected, so health leaves only endpoint 1 — which is
    // at its cap. The cap runs second and refuses: a cluster whose only
    // healthy endpoint is full must not be handed the request anyway.
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, 0)] = false;
    var l7 = [_]u16{0} ** test_counts_len;
    l7[test_keys.key(0, 1)] = 1;
    try std.testing.expectEqual(
        @as(?Balancer.Pick, null),
        balancer.pick(0, &testLoad(&l7), &healthy, &test_client),
    );
    // And when health fails open — every endpoint ejected — the caps
    // still apply to the whole set rather than being bypassed with it.
    healthy[test_keys.key(0, 1)] = false;
    l7[test_keys.key(0, 0)] = 1;
    try std.testing.expectEqual(
        @as(?Balancer.Pick, null),
        balancer.pick(0, &testLoad(&l7), &healthy, &test_client),
    );
}
