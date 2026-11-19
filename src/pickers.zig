//! The stock pick policies on the picker contract (#417): round-robin,
//! the power of two choices and rendezvous hashing are pickers, the same
//! shape as any picker a build lists — `pick(*P, *const Candidates,
//! *const PickInput) u16` — and the balancer runs them through that same
//! call. So the contract is
//! exactly what zoxy's own policies need, and a build may select them, or
//! call one from a picker of its own, by name (`zoxy.pickers`).
//!
//! Each reads only what the contract offers: the candidates zoxy narrowed
//! (§7), their weights, load and identities, the request view, the
//! client's address and zoxy's seeded generator. The arithmetic is the
//! one the balancer ran before the move, draw for draw, so a seed replays
//! the same picks it always did (§9).

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const extension = @import("extension.zig");
const parser = @import("http/parser.zig");
const Balancer = @import("balancer.zig").Balancer;

const assert = std.debug.assert;

const Candidates = extension.Candidates;
const PickInput = extension.PickInput;

/// Smooth weighted round-robin (nginx's): every pick adds each
/// candidate's weight to its running total, takes the largest, and
/// charges the winner the round's total — so over any window each
/// endpoint gets its share, spread rather than bunched.
///
/// The totals are the cluster's, one per endpoint, so an instance serves
/// one cluster: a second `bind` is refused rather than left to mix two
/// rotations in one table.
pub const RoundRobin = struct {
    /// One running total per endpoint of the cluster, by endpoint index.
    current: []i64 = &.{},
    bound: bool = false,

    pub fn bind(
        picker: *RoundRobin,
        cluster: *const extension.ClusterSite,
        startup: *const extension.Startup,
    ) !void {
        if (picker.bound) return error.RoundRobinServesOneCluster;
        assert(cluster.endpoints.len >= 1);
        picker.current = try startup.arena.alloc(i64, cluster.endpoints.len);
        @memset(picker.current, 0);
        picker.bound = true;
    }

    pub fn pick(picker: *RoundRobin, candidates: *const Candidates, input: *const PickInput) u16 {
        _ = input;
        const count = candidates.count();
        assert(count >= 1);
        var round_total: i64 = 0;
        var best_slot: u16 = 0;
        var best_current: i64 = std.math.minInt(i64);
        var slot: u16 = 0;
        while (slot < count) : (slot += 1) {
            const index = candidates.endpointIndex(slot);
            assert(index < picker.current.len);
            const weight: i64 = candidates.weight(slot);
            assert(weight >= 1); // A drained endpoint is never a candidate.
            picker.current[index] += weight;
            round_total += weight;
            if (picker.current[index] > best_current) {
                best_current = picker.current[index];
                best_slot = slot;
            }
        }
        assert(round_total >= count);
        picker.current[candidates.endpointIndex(best_slot)] -= round_total;
        return best_slot;
    }
};

/// The power of two choices: two candidates drawn with probability
/// proportional to weight (#174), and the one with fewer requests in
/// flight wins — a heavier endpoint is likelier to be *considered*, and
/// load still decides. A tie goes to the first draw.
pub const PowerOfTwoChoices = struct {
    pub fn pick(picker: *PowerOfTwoChoices, candidates: *const Candidates, input: *const PickInput) u16 {
        _ = picker;
        return placeByLoad(candidates, input.random);
    }
};

/// Rendezvous hashing (§7, #178): every candidate scored against the
/// request's key, the highest taken. The same key reaches the same
/// endpoint from every process and every restart, and when an endpoint
/// leaves, only the keys it held move — the 1/n optimum, with no separate
/// fallback, since "the best of what remains" is the same computation.
///
/// What it keys on is the cluster's: the client's address, a header's
/// value, or the endpoint a cookie names. A request with no usable key —
/// no such header, no cookie, a tag naming no candidate — is placed by
/// load, the right first assignment for a session about to be pinned.
pub const Rendezvous = struct {
    key: config_module.Config.Cluster.HashKey,

    pub fn pick(picker: *Rendezvous, candidates: *const Candidates, input: *const PickInput) u16 {
        assert(candidates.count() >= 1);
        const request_headers: ?[]const parser.Header = if (input.request) |request| request.headers else null;
        switch (materialOf(&picker.key, input.client, request_headers)) {
            .key => |key| return highestScore(candidates, key),
            .endpoint => |identity| {
                var slot: u16 = 0;
                while (slot < candidates.count()) : (slot += 1) {
                    if (candidates.identity(slot) == identity) return slot;
                }
                return placeByLoad(candidates, input.random);
            },
            .absent => return placeByLoad(candidates, input.random),
        }
    }
};

/// What a request gives a hash to key on.
pub const Material = union(enum) {
    /// A key to score candidates against: the client's address, or a
    /// header's value.
    key: u64,
    /// The endpoint a sticky cookie's tag names (#178).
    endpoint: u64,
    /// Nothing usable.
    absent,
};

/// The key material `key` reads from a pick: the client's address, the
/// named header's value, or the identity the named cookie's tag spells.
/// One derivation for the pick and for the proxy's response-side stamp,
/// so the two cannot disagree about what a request named.
pub fn materialOf(
    key: *const config_module.Config.Cluster.HashKey,
    client: ?*const std.Io.net.IpAddress,
    headers: ?[]const parser.Header,
) Material {
    switch (key.*) {
        // A listener with no client address cannot route to a source-IP
        // cluster: resolving refuses the pair (#303).
        .source_ip => return .{ .key = Balancer.clientKey(client.?) },
        .header => |name| {
            const value = parser.headerValue(headers orelse return .absent, name) orelse return .absent;
            if (value.len == 0) return .absent;
            return .{ .key = Balancer.bytesKey(value) };
        },
        .cookie => |name| {
            const value = parser.cookieValue(headers orelse return .absent, name) orelse return .absent;
            const identity = Balancer.parseEndpointTag(value) orelse return .absent;
            return .{ .endpoint = identity };
        },
    }
}

/// Load-aware placement: two distinct candidates drawn in proportion to
/// weight, the lighter one taken. A single candidate is taken without a
/// draw, so a set narrowed to one spends no generator state. Also where
/// an extension picker's out-of-set slot falls back (#417).
///
/// At unit weights both draws land exactly where uniform draws would —
/// the same values on the same slots — which is what kept the traces of
/// unweighted clusters unchanged when weights arrived (#174).
pub fn placeByLoad(candidates: *const Candidates, random: *extension.Random) u16 {
    const count = candidates.count();
    assert(count >= 1);
    if (count == 1) return 0;
    var total: u64 = 0;
    var slot: u16 = 0;
    while (slot < count) : (slot += 1) total += candidates.weight(slot);
    const first = weightedSlot(candidates, random.next() % total, null);
    // The second draw runs over the weight that remains once the first
    // candidate steps out, mapping onto the other n-1 slots — still
    // proportional, and never a duplicate.
    const remaining = total - candidates.weight(first);
    assert(remaining >= 1); // Two or more candidates, each weighing at least 1.
    const second = weightedSlot(candidates, random.next() % remaining, first);
    assert(first != second);
    return if (candidates.inFlight(second) < candidates.inFlight(first)) second else first;
}

/// The slot a cumulative-weight draw lands on, skipping `exclude`. `draw`
/// sits below the participating total and every participant weighs at
/// least 1, so the walk always lands.
fn weightedSlot(candidates: *const Candidates, draw: u64, exclude: ?u16) u16 {
    var remaining = draw;
    var slot: u16 = 0;
    while (slot < candidates.count()) : (slot += 1) {
        if (exclude == slot) continue;
        const weight = candidates.weight(slot);
        assert(weight >= 1);
        if (remaining < weight) return slot;
        remaining -= weight;
    }
    // Drawn modulo the participating total, so the walk cannot run off
    // the end.
    unreachable;
}

/// The candidate whose score for `key` is highest; an exact tie keeps
/// the earlier slot, which is the lower endpoint index. Two 64-bit scores
/// colliding is a 2⁻⁶⁴ event, but two processes resolving one
/// differently would break the stickiness this whole policy promises.
fn highestScore(candidates: *const Candidates, key: u64) u16 {
    var best_slot: u16 = 0;
    var best_score = score(candidates, 0, key);
    var slot: u16 = 1;
    while (slot < candidates.count()) : (slot += 1) {
        const candidate_score = score(candidates, slot, key);
        if (candidate_score > best_score) {
            best_score = candidate_score;
            best_slot = slot;
        }
    }
    assert(best_slot < candidates.count());
    return best_slot;
}

/// Weighted rendezvous by replication (#174): an endpoint's score is the
/// best of `weight` independent scores, so it holds the argmax for
/// exactly weight/total of the key space — integer-only and pinned. The
/// first replica mixes in `mix(0) == 0`, so a weight-1 endpoint scores as
/// the unweighted form did and existing clusters keep their mappings.
fn score(candidates: *const Candidates, slot: u16, key: u64) u64 {
    const identity = candidates.identity(slot);
    const weight = candidates.weight(slot);
    assert(weight >= 1);
    // Bounded per endpoint: the replica scan is the operator's own config.
    assert(weight <= constants.endpoint_weight_max);
    var best: u64 = 0;
    var replica: u32 = 0;
    while (replica < weight) : (replica += 1) {
        const candidate = Balancer.mix(key ^ identity ^ Balancer.mix(replica));
        if (candidate > best) best = candidate;
    }
    return best;
}

comptime {
    extension.assertPicker(RoundRobin);
    extension.assertPicker(PowerOfTwoChoices);
    extension.assertPicker(Rendezvous);
}

const Options = @import("Options.zig");
const Bed = @import("testing/bed.zig").Bed;
const defaults = @import("defaults.zig");

const RoundRobinBed = Bed(.{ .pickers = &.{RoundRobin} });
var test_round_robin: RoundRobin = .{};

fn loopback(port: u16) std.Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
}

/// The stock round-robin, selected by a build as its own picker: static,
/// as the resolved config points into it.
const round_robin_options: Options = .{
    .listeners = &.{.{
        .bind = .{ .ip = loopback(18180) },
        .protocol = .{ .http = .{
            .target = .{ .cluster = "origin" },
            .max_body_bytes = defaults.max_body_bytes,
            .keepalive_requests = defaults.keepalive_requests,
        } },
    }},
    .clusters = &.{.{
        .name = "origin",
        .endpoints = &.{
            .{ .address = .{ .ip = loopback(19201) } },
            .{ .address = .{ .ip = loopback(19202) } },
        },
        .pick = .{ .extension = extension.select(&.{RoundRobin}, &test_round_robin) },
    }},
    .timeouts = defaults.timeouts,
    .limits = defaults.limits,
};

fn alternate(bed: *RoundRobinBed) !void {
    const request = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    var clients: [4]*RoundRobinBed.Client = undefined;
    for (&clients) |*client| client.* = bed.request(0, request);
    try bed.run();
    for (clients) |client| try std.testing.expectEqual(@as(?u16, 200), client.status());
    // Four picks over two equal endpoints: two each, whatever order the
    // schedule delivered them in.
    try std.testing.expectEqual(@as(u32, 2), bed.answered(loopback(19201)));
    try std.testing.expectEqual(@as(u32, 2), bed.answered(loopback(19202)));
}

test "pickers: a build selects the stock round-robin like any picker (#417)" {
    // Bound once per run of the gate, and a second bind would be refused:
    // each run starts from a fresh instance.
    test_round_robin = .{};
    const bed = try std.testing.allocator.create(RoundRobinBed);
    defer std.testing.allocator.destroy(bed);
    try bed.setUp(std.testing.allocator, &round_robin_options, 3);
    defer bed.tearDown();
    try alternate(bed);
}
