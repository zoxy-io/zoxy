//! Upstream endpoint selection (DESIGN.md §7): the load-balancing policy
//! kept behind a seam so the serving path never hardcodes *how* an
//! endpoint is chosen — it only asks "which endpoint for this cluster?".
//! Three policies, selected per cluster in the config (§5 parse-once):
//! `rr` runs a smooth weighted rotation, `p2c` draws two distinct
//! weight-biased candidates and leases the calmer one, `hash` sends a
//! given client to a given endpoint every time. P2C's load is the
//! per-endpoint in-flight total across both protocols — the pool's L7
//! leases plus the server's live L4 connections — passed in by the caller
//! as a view: the balancer owns the draw, the pool and the server own the
//! truth. A single-endpoint cluster short-circuits every policy without
//! touching its state.
//!
//! **Weights (#174).** Every policy honors `Config.Cluster.weights` —
//! null means every endpoint at 1, and each unit-weight path below is
//! *bit-identical* to the unweighted algorithm it grew from, so existing
//! clusters keep their draws, their rotations and their client-to-endpoint
//! mappings. A weight of 0 drains its endpoint: it never enters the
//! eligible set, not even through fail-open — a drain is an operator's
//! statement, where an ejection is only a probe's verdict — while the
//! prober keeps probing it, so a drained endpoint's recovery is still
//! observed (§7).
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
//! **Request-derived keys (#178).** A `hash` cluster names what it keys
//! on. `source_ip` and a header value are true rendezvous keys — the
//! mapping stays a pure function of key and eligible set. A cookie is
//! not a hash at all: the client carries the *answer* — an endpoint tag
//! in the spelling `formatEndpointTag` mints — so every process reaches
//! the same endpoint by reading it, which is the table-free property
//! above achieved a second way. When the keyed material is missing
//! (first request of a cookie session, a request without the keyed
//! header) the pick places by load instead, the same weighted two-choice
//! draw `p2c` runs: cross-process agreement is not needed there, because
//! #178's contract sends a cookie assignment back to the client on the
//! response (the Set-Cookie stamp, the serving path's half of the
//! feature), and a keyless header population has no identity to be
//! sticky on in the first place.
//!
//! **Why rendezvous rather than a ring or Maglev.** Both of those answer
//! a lookup from a precomputed table, and a table has to be *rebuilt*
//! whenever membership changes — which here is every health-check
//! ejection and recovery (§7), on the one thread that must not stall
//! (§3). A 64-endpoint ring at any useful virtual-node count is a
//! thousands-of-entries sort per flap. Rendezvous has no table to rebuild:
//! it scans the eligible set the health mask already produced. It costs
//! O(n) instead of O(log n), which is why a cluster's endpoint count is a
//! cost the operator chooses: measured at 71 ns per pick at 64 endpoints,
//! against a request this proxy serves in ~100 µs. Weights scale that
//! same dial — a weighted pick scores one hash per weight point (§7,
//! `score`), so the scan is O(sum of weights), bounded per endpoint by
//! `endpoint_weight_max` and, like the endpoint count, priced by the
//! operator's own config. Jump consistent hash is excluded outright: it
//! can only add or remove the *last* bucket, and an ejection removes an
//! arbitrary one.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
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

/// The §7 stickiness key for a request-carried byte string — a `hash`
/// cluster keyed on a header value (#178). FNV-1a folded through
/// `mix64`: FNV for the bytes because it is trivially pinned (two
/// published constants), the finalizer because FNV's avalanche is weak
/// and rendezvous compares whole words. Pinned for the same reason
/// `mix64` is — this is part of the client-to-backend mapping, and a
/// `std.hash` function makes no cross-version promise, which a rolling
/// restart would turn into a silent re-shuffle.
fn bytesKeyOf(bytes: []const u8) u64 {
    assert(bytes.len >= 1); // An absent value is `.absent`, never hashed.
    var hash: u64 = 0xCBF29CE484222325;
    for (bytes) |byte| {
        hash ^= byte;
        hash *%= 0x100000001B3;
    }
    return mix64(hash);
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

/// One endpoint's §7 pick weight: the configured table's entry, or 1 —
/// the `Config.Cluster.weights` contract, read through one helper so
/// "null means unit weights" is spelled exactly once.
fn weightOf(cluster: *const config_module.Config.Cluster, endpoint_index: u16) u16 {
    assert(endpoint_index < cluster.endpoints.len);
    const weights = cluster.weights orelse return 1;
    assert(weights.len == cluster.endpoints.len);
    return weights[endpoint_index];
}

/// The weight sum over the eligible set — one weighted draw's modulus.
/// u32 room to spare: 65535 endpoints at weight 256 stays under 2²⁵.
fn totalWeight(cluster: *const config_module.Config.Cluster, eligible: []const u16) u32 {
    assert(eligible.len >= 1);
    var total: u32 = 0;
    for (eligible) |endpoint_index| {
        total += weightOf(cluster, endpoint_index);
    }
    // Every eligible endpoint weighs at least 1 — weight 0 never enters
    // the set — so the total covers the set.
    assert(total >= eligible.len);
    return total;
}

pub const Balancer = struct {
    config: *const config_module.Config,
    /// Per-endpoint smooth-WRR running totals, used by `.rr` clusters
    /// only (§7, #174). Replaced the per-cluster cursor when weights
    /// arrived, because a weighted rotation is a property of each
    /// endpoint's credit rather than of one shared position: a pick
    /// raises every eligible endpoint's entry by its weight, takes the
    /// largest, and the winner repays the round's whole sum — nginx's
    /// smooth algorithm, so weight 3 is `a,a,b,a` and never three
    /// consecutive hits. At unit weights the schedule it produces is
    /// exactly the strict rotation the cursor produced. i64 because
    /// totals dip negative by design (the winner pays the round), with
    /// magnitude bounded by one cluster's weight sum.
    rr_current: []i64,
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

    /// The request-derived half of a pick (#178): what the serving path
    /// read off the parsed head for a request-keyed `hash` cluster. Both
    /// data paths always pass the client address separately — it is the
    /// whole key for `source_ip` and for every non-hash policy, which is
    /// why those arms carry `.none` rather than an optional address.
    pub const RequestKey = union(enum) {
        /// No request-derived key applies: every non-hash policy, `hash`
        /// on `source_ip`, and every L4 dial (the loader keeps the
        /// request-keyed clusters off l4 listeners).
        none,
        /// `hash` on a header: the rendezvous key over the header value
        /// (`bytesKey`).
        key: u64,
        /// `hash` on a cookie: the endpoint identity the cookie's tag
        /// names (`parseEndpointTag`).
        endpoint: u64,
        /// The cluster is request-keyed but this request lacks usable
        /// material — no such header, no cookie, a malformed tag: place
        /// by load. On a cookie cluster the caller owes the client an
        /// announcement of the assignment (#178's Set-Cookie stamp).
        absent,
    };

    /// A cookie-borne endpoint tag (#178): the endpoint's rendezvous
    /// identity, spelled as exactly 16 lowercase hex digits. Stable
    /// across restarts, processes, and config reordering — it is
    /// `endpointId`, a function of the address alone — and it leaks the
    /// address's *hash* rather than the address, which is all a client
    /// needs returned to it and nothing an operator minds it seeing.
    pub const endpoint_tag_len: u16 = 16;

    /// Spell `identity` as the tag a Set-Cookie carries.
    pub fn formatEndpointTag(identity: u64, out: *[endpoint_tag_len]u8) void {
        const spelled = std.fmt.bufPrint(out, "{x:0>16}", .{identity}) catch unreachable;
        assert(spelled.len == endpoint_tag_len); // Zero-padded: every u64 fills the field.
    }

    /// The identity a tag spells, or null when the bytes are not exactly
    /// the spelling `formatEndpointTag` mints — length and lowercase
    /// both. The proxy never wrote a looser form, so accepting one would
    /// give a forged cookie more grammar than a real one has; a mismatch
    /// is a quiet re-pick, never an error, because a client can only
    /// choose which backend serves *itself* (#178).
    pub fn parseEndpointTag(bytes: []const u8) ?u64 {
        if (bytes.len != endpoint_tag_len) {
            return null;
        }
        assert(bytes.len == endpoint_tag_len);
        var identity: u64 = 0;
        for (bytes) |byte| {
            const digit: u4 = switch (byte) {
                '0'...'9' => @intCast(byte - '0'),
                'a'...'f' => @intCast(byte - 'a' + 10),
                else => return null,
            };
            identity = (identity << 4) | digit;
        }
        return identity;
    }

    /// The rendezvous key for a request-carried byte string — the
    /// serving path's entry to `bytesKeyOf`, kept on the struct because
    /// callers import `Balancer`, not this module.
    pub fn bytesKey(bytes: []const u8) u64 {
        return bytesKeyOf(bytes);
    }

    /// `endpointId` for one address, without an instance — what the §9
    /// gates use to compute the tag an endpoint *must* be spelled as,
    /// from nothing but its address, so an oracle can hold the running
    /// proxy to it from outside.
    pub fn addressIdentity(address: *const std.Io.net.IpAddress) u64 {
        return endpointId(address);
    }

    /// The tag identity of one configured endpoint — what a cookie for
    /// it spells (#178). Consumed by the response-side stamp, the
    /// feature's serving half, once the exchange settles on an endpoint;
    /// reading the init-computed table keeps mint and match one value.
    pub fn endpointIdentity(
        balancer: *const Balancer,
        cluster_index: u16,
        endpoint_index: u16,
    ) u64 {
        assert(cluster_index < balancer.config.clusters.len);
        assert(endpoint_index < balancer.config.clusters[cluster_index].endpoints.len);
        return balancer.endpoint_hashes[balancer.keys.key(cluster_index, endpoint_index)];
    }

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
        balancer.rr_current = try arena.alloc(i64, keys.count);
        balancer.endpoint_hashes = try arena.alloc(u64, keys.count);
        balancer.eligible_scratch = try arena.alloc(u16, keys.stride);
        @memset(balancer.rr_current, 0);
        balancer.pick_state = pick_seed;
        assert(balancer.pick_state != 0); // xorshift64* cycles on nonzero state.
        // Every key, not only the configured ones: a ragged config leaves
        // holes between clusters, those slots are never read, and zeroing
        // the whole table keeps "what did init leave here" a question with
        // one answer.
        @memset(balancer.endpoint_hashes, 0);
        for (config.clusters, 0..) |*cluster, cluster_index| {
            // Re-checked here rather than trusted from the loader, the
            // same defense `pick` and `eligibleEndpoints` keep: this loop
            // indexes a table sized by that stride.
            assert(cluster.endpoints.len >= 1);
            assert(cluster.endpoints.len <= keys.stride);
            // The #174 weights contract: parallel to the endpoints, and
            // at least one endpoint routable. The loader rejects both
            // breaches (`EndpointWeightsAllZero`); a config built by
            // hand — tests, the simulator — re-proves them here, since
            // an all-drained cluster would fail `eligibleEndpoints`'s
            // count assertion on its first pick instead of at startup.
            var weight_sum: u32 = 0;
            for (cluster.endpoints, 0..) |*address, endpoint_index| {
                const key = keys.key(@intCast(cluster_index), @intCast(endpoint_index));
                balancer.endpoint_hashes[key] = endpointId(address);
                weight_sum += weightOf(cluster, @intCast(endpoint_index));
            }
            assert(weight_sum >= 1);
            // The loader's contract (#178): a hash key other than the
            // default rides only beside `pick: hash` — `pickHash` is the
            // one reader, so anywhere else it would be silently inert.
            if (cluster.pick != .hash) {
                assert(std.meta.activeTag(cluster.hash_key) == .source_ip);
            }
            if (cluster.weights) |weights| {
                assert(weights.len == cluster.endpoints.len);
            }
        }
        assert(balancer.rr_current.len == keys.count);
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
    /// view (indexed by `upstream.endpointKey`), consulted by p2c —
    /// and by a request-keyed hash cluster placing a keyless request
    /// (#178) — and ignored by rr; `healthy` is the §7 health mask (same
    /// index) — the prober owns that truth the way the pool and the
    /// server own the load. `request_key` is what the serving path read
    /// off the parsed head for a request-keyed cluster, `.none`
    /// everywhere else. Bounded work, no allocation, and a validated
    /// config guarantees at least one endpoint.
    pub fn pick(
        balancer: *Balancer,
        cluster_index: u16,
        load: *const upstream.Load,
        healthy: []const bool,
        client_address: *const std.Io.net.IpAddress,
        request_key: RequestKey,
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
            .p2c => balancer.placeByLoad(cluster_index, eligible[0..count], load),
            .hash => balancer.pickHash(
                cluster_index,
                eligible[0..count],
                load,
                client_address,
                request_key,
            ),
        };
        assert(chosen < cluster.endpoints.len);
        return .{
            .address = cluster.endpoints[chosen],
            .endpoint_index = chosen,
        };
    }

    /// The endpoints a pick may choose between, in three passes.
    ///
    /// First the #174 drain: a weight-0 endpoint never enters the set.
    /// Unlike the health mask this is not a verdict to fail open past —
    /// it is the operator saying *stop sending here*, and the whole
    /// point of the spelling is that it holds while everything else
    /// flaps.
    ///
    /// Then §7 health over the routable set: the healthy ones — or, the
    /// fail-open rule, every routable endpoint when all of them are
    /// ejected. Dialing a maybe-dead endpoint reports the outage the way
    /// it always did; routing nowhere would turn a probe verdict into an
    /// outage of its own, and a same-port TCP probe cannot know better
    /// than the dial.
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
            if (weightOf(cluster, index) == 0) continue;
            if (healthy[keys.key(cluster_index, index)]) {
                eligible[count] = index;
                count += 1;
            }
        }
        if (count == 0) {
            for (0..cluster.endpoints.len) |endpoint_index| {
                const index: u16 = @intCast(endpoint_index);
                if (weightOf(cluster, index) == 0) continue;
                eligible[count] = index;
                count += 1;
            }
        }
        // At least one endpoint holds weight — the loader rejects an
        // all-zero cluster and `init` re-proves it — so the drain filter
        // alone can never empty the set.
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

    /// Smooth weighted rotation over the eligible set (nginx's SWRR):
    /// every eligible endpoint's running total rises by its weight, the
    /// largest total wins — a tie keeps the lowest index — and the
    /// winner repays the round's whole weight sum. "Smooth" is the
    /// property the issue asks for by name: weight 3 beside weight 1
    /// serves a,a,b,a, never three consecutive hits, because the winner
    /// goes to the back of the queue by exactly what the round was
    /// worth. At unit weights the schedule is strict rotation, in order.
    /// State survives eligibility changes: an ejected endpoint's total
    /// freezes, so a flap neither owes it rounds nor forgives them.
    fn pickRoundRobin(
        balancer: *Balancer,
        cluster_index: u16,
        eligible: []const u16,
    ) u16 {
        const cluster = &balancer.config.clusters[cluster_index];
        assert(cluster.pick == .rr);
        assert(eligible.len >= 1);
        var round_total: i64 = 0;
        var best_slot: usize = 0;
        var best_current: i64 = std.math.minInt(i64);
        for (eligible, 0..) |endpoint_index, slot| {
            const key = balancer.keys.key(cluster_index, endpoint_index);
            const weight: i64 = weightOf(cluster, endpoint_index);
            assert(weight >= 1); // weight 0 never enters the eligible set
            balancer.rr_current[key] += weight;
            round_total += weight;
            if (balancer.rr_current[key] > best_current) {
                best_current = balancer.rr_current[key];
                best_slot = slot;
            }
        }
        assert(round_total >= @as(i64, @intCast(eligible.len)));
        const chosen = eligible[best_slot];
        balancer.rr_current[balancer.keys.key(cluster_index, chosen)] -= round_total;
        return chosen;
    }

    /// P2C over the eligible set: two distinct candidates drawn with
    /// probability proportional to weight (#174) — a heavier endpoint is
    /// likelier to be *considered*; the in-flight comparison that decides
    /// the winner is untouched, so load still outranks share. A tie goes
    /// to the first. At unit weights both draws are bit-identical to the
    /// uniform ones this grew from — the same PRNG values land on the
    /// same slots — so an unweighted cluster's §9 traces are unchanged.
    /// A mask narrowed to one endpoint skips the draw the way a
    /// one-endpoint cluster does — no candidates to compare, no PRNG
    /// state spent.
    ///
    /// This is the `.p2c` policy — and also where a request-keyed hash
    /// cluster places a request whose key is missing or names nothing
    /// eligible (#178). The shared spelling is deliberate: "healthy and
    /// under-capacity, in that order" already narrowed the set, and
    /// load-aware placement is the right first assignment for a session
    /// the response is about to pin. A hash cluster therefore *can*
    /// spend PRNG state — only on the keyless picks, where two
    /// processes agreeing was never on the table.
    fn placeByLoad(
        balancer: *Balancer,
        cluster_index: u16,
        eligible: []const u16,
        load: *const upstream.Load,
    ) u16 {
        const cluster = &balancer.config.clusters[cluster_index];
        assert(cluster.pick == .p2c or cluster.pick == .hash);
        assert(eligible.len >= 1);
        if (eligible.len == 1) {
            return eligible[0];
        }
        const total = totalWeight(cluster, eligible);
        const first_slot = weightedSlot(cluster, eligible, balancer.next() % total, null);
        // The second draw runs over the weight that remains once the
        // first candidate steps out, mapping onto the other n-1 slots —
        // still proportional, and never a duplicate.
        const remaining = total - weightOf(cluster, eligible[first_slot]);
        assert(remaining >= 1); // n >= 2 eligible, each weighing >= 1
        const second_slot = weightedSlot(
            cluster,
            eligible,
            balancer.next() % remaining,
            first_slot,
        );
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

    /// The eligible slot a cumulative-weight draw lands on, skipping
    /// `exclude` — one weighted candidacy (#174). `draw` must sit below
    /// the participating weight total, and every participant weighs at
    /// least 1, so the walk always lands; at unit weights slot k is
    /// exactly draw k (with the post-exclude slots shifted by one), which
    /// is the uniform mapping the unweighted draw used.
    fn weightedSlot(
        cluster: *const config_module.Config.Cluster,
        eligible: []const u16,
        draw: u64,
        exclude: ?u16,
    ) u16 {
        assert(eligible.len >= 1);
        var remaining = draw;
        for (eligible, 0..) |endpoint_index, slot| {
            if (exclude) |excluded| {
                if (excluded == slot) continue;
            }
            const weight = weightOf(cluster, endpoint_index);
            assert(weight >= 1);
            if (remaining < weight) {
                return @intCast(slot);
            }
            remaining -= weight;
        }
        // The caller drew modulo the participating total, so the walk
        // cannot run off the end.
        unreachable;
    }

    /// Dispatch a `hash` cluster's pick by its configured key (§7,
    /// #178). `source_ip` and `header` are rendezvous over different key
    /// material; a `cookie` is not a hash of anything — the client
    /// carries the answer, honoured when its tag names an eligible
    /// endpoint. Keyless requests place by load (`placeByLoad`'s doc has
    /// the argument). The `unreachable` arms are the caller reading the
    /// wrong cluster: the L7 path derives the arm from this cluster's
    /// own key, and the loader keeps request-keyed clusters off l4
    /// listeners.
    fn pickHash(
        balancer: *Balancer,
        cluster_index: u16,
        eligible: []const u16,
        load: *const upstream.Load,
        client_address: *const std.Io.net.IpAddress,
        request_key: RequestKey,
    ) u16 {
        assert(balancer.config.clusters[cluster_index].pick == .hash);
        assert(eligible.len >= 1);
        switch (balancer.config.clusters[cluster_index].hash_key) {
            .source_ip => {
                // Both data paths pass the address and pass nothing
                // else: an L7 request need not have been parsed yet, an
                // L4 connection has nothing to parse.
                assert(std.meta.activeTag(request_key) == .none);
                return balancer.rendezvous(cluster_index, eligible, sourceKey(client_address));
            },
            .header => switch (request_key) {
                .key => |key| return balancer.rendezvous(cluster_index, eligible, key),
                .absent => return balancer.placeByLoad(cluster_index, eligible, load),
                .none, .endpoint => unreachable,
            },
            .cookie => switch (request_key) {
                .endpoint => |identity| return balancer.pickTagged(
                    cluster_index,
                    eligible,
                    load,
                    identity,
                ),
                .absent => return balancer.placeByLoad(cluster_index, eligible, load),
                .none, .key => unreachable,
            },
        }
    }

    /// The endpoint a cookie's tag names, when it is in the eligible set
    /// — otherwise place by load: a tag naming an ejected, drained,
    /// capped, or long-removed endpoint re-homes cleanly, and #178's
    /// contract owes the client a re-announcement (the response-side
    /// stamp). The scan is the eligible walk the pick already paid for;
    /// matching by identity rather than index is what lets a config grow
    /// or reorder without re-homing cookie holders, exactly
    /// `endpointId`'s contract.
    fn pickTagged(
        balancer: *Balancer,
        cluster_index: u16,
        eligible: []const u16,
        load: *const upstream.Load,
        identity: u64,
    ) u16 {
        assert(std.meta.activeTag(balancer.config.clusters[cluster_index].hash_key) == .cookie);
        assert(eligible.len >= 1);
        for (eligible) |candidate| {
            if (balancer.endpoint_hashes[balancer.keys.key(cluster_index, candidate)] == identity) {
                return candidate;
            }
        }
        return balancer.placeByLoad(cluster_index, eligible, load);
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
    /// which is the one thing keyed stickiness exists to prevent.
    fn rendezvous(
        balancer: *const Balancer,
        cluster_index: u16,
        eligible: []const u16,
        key: u64,
    ) u16 {
        assert(balancer.config.clusters[cluster_index].pick == .hash);
        assert(eligible.len >= 1);
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
        const cluster = &balancer.config.clusters[cluster_index];
        const endpoint_hash =
            balancer.endpoint_hashes[balancer.keys.key(cluster_index, endpoint_index)];
        // Weighted rendezvous by replication (#174): the endpoint's score
        // is the best of `weight` independent scores, one per replica, so
        // it holds the argmax for exactly weight/total of the key space —
        // proportional by construction, integer-only, and pinned like the
        // rest of the mapping (no float log whose libm could re-home the
        // fleet across builds). Replica 0 mixes in `mix64(0) == 0`, so a
        // weight-1 endpoint's score is byte-identical to the unweighted
        // form and existing clusters keep their client mappings. The scan
        // is bounded by `endpoint_weight_max` per endpoint; like the O(n)
        // eligible walk, its cost is chosen by the operator's own config.
        //
        // Both xor operands are already avalanched, so each combine is
        // structureless and the final mix restores uniformity.
        const weight = weightOf(cluster, endpoint_index);
        assert(weight >= 1); // weight 0 never enters the eligible set
        assert(weight <= constants.endpoint_weight_max);
        var best: u64 = 0;
        var replica: u32 = 0;
        while (replica < weight) : (replica += 1) {
            const candidate = mix64(key ^ endpoint_hash ^ mix64(replica));
            if (candidate > best) {
                best = candidate;
            }
        }
        return best;
    }

    /// xorshift64* (Vigna): the full-period 64-bit shift generator with a
    /// multiplicative output scramble — plenty for candidate draws, one
    /// mul and three shifts on the pick path. The modulo bias of a draw
    /// is ≤ 2⁻⁴⁸ even at the u16 index type's edge — negligible.
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
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?;
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
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?;
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
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?;
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
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?;
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
            left.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?.endpoint_index,
            right.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?.endpoint_index,
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
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, .none).?;
        try std.testing.expectEqual(want_index, picked.endpoint_index);
    }
}

test "balancer: rr honors weights, and the schedule is smooth" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const pair = [_]std.Io.net.IpAddress{ a, b };
    const weights = [_]u16{ 2, 1 };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "canary", .endpoints = &pair, .pick = .rr, .weights = &weights },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Two shares for endpoint 0, one for endpoint 1 — and the heavier
    // endpoint's hits are spread through the cycle (0,1,0), not bunched
    // (0,0,1): the "smooth" in smooth WRR, which is what keeps a weight-3
    // backend from taking three consecutive requests as one burst.
    const counts = [_]u16{0} ** test_counts_len;
    const expected = [_]u16{ 0, 1, 0, 0, 1, 0 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?;
        try std.testing.expectEqual(want_index, picked.endpoint_index);
    }
}

test "balancer: rr weight zero drains an endpoint, past fail-open" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const c = std.Io.net.IpAddress.parseLiteral("127.0.0.1:3") catch unreachable;
    const trio = [_]std.Io.net.IpAddress{ a, b, c };
    const weights = [_]u16{ 1, 0, 1 };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "draining", .endpoints = &trio, .pick = .rr, .weights = &weights },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // The drained endpoint never rotates in: the survivors alternate as
    // if the cluster had two endpoints.
    const counts = [_]u16{0} ** test_counts_len;
    const expected = [_]u16{ 0, 2, 0, 2 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?;
        try std.testing.expectEqual(want_index, picked.endpoint_index);
    }
    // Fail-open re-admits the ejected, never the drained: a weight of 0
    // is the operator's statement, not a probe's verdict, so even a
    // fully-ejected cluster keeps routing around it.
    const none_healthy = [_]bool{false} ** test_keys.count;
    var round: u32 = 0;
    while (round < 20) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &none_healthy, &test_client, .none).?;
        try std.testing.expect(picked.endpoint_index != 1);
    }
}

test "balancer: p2c candidacy follows weight" {
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const c = std.Io.net.IpAddress.parseLiteral("127.0.0.1:3") catch unreachable;
    const trio = [_]std.Io.net.IpAddress{ a, b, c };
    const weights = [_]u16{ 8, 1, 1 };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "weighted", .endpoints = &trio, .pick = .p2c, .weights = &weights },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Under equal load the tie rule keeps the first candidate, so the
    // pick distribution is the candidacy distribution — and candidacy is
    // the weighted draw. The 8-weight endpoint must dominate, and the
    // 1-weight endpoints must still appear: bias, not exclusion.
    const counts = [_]u16{0} ** test_counts_len;
    var hits = [_]u32{0} ** 3;
    var round: u32 = 0;
    while (round < 400) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?;
        hits[picked.endpoint_index] += 1;
    }
    try std.testing.expect(hits[0] > hits[1] + hits[2]);
    try std.testing.expect(hits[1] >= 1);
    try std.testing.expect(hits[2] >= 1);
}

test "balancer: p2c at unit weights draws exactly as the unweighted form" {
    // An explicit all-ones table and no table at all must be the same
    // policy, draw for draw: the weighted path's unit case is the
    // uniform draw this grew from, which is what keeps unweighted §9
    // traces byte-stable across the change.
    const a = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    const b = std.Io.net.IpAddress.parseLiteral("127.0.0.1:2") catch unreachable;
    const c = std.Io.net.IpAddress.parseLiteral("127.0.0.1:3") catch unreachable;
    const trio = [_]std.Io.net.IpAddress{ a, b, c };
    const unit_weights = [_]u16{ 1, 1, 1 };
    const bare_clusters = [_]config_module.Config.Cluster{
        .{ .name = "bare", .endpoints = &trio, .pick = .p2c },
    };
    const spelled_clusters = [_]config_module.Config.Cluster{
        .{ .name = "spelled", .endpoints = &trio, .pick = .p2c, .weights = &unit_weights },
    };
    const bare_config = testConfig(&bare_clusters);
    const spelled_config = testConfig(&spelled_clusters);

    var bare_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer bare_arena.deinit();
    var bare: Balancer = undefined;
    try bare.init(bare_arena.allocator(), &bare_config, testKeysFor(&bare_config));
    var spelled_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer spelled_arena.deinit();
    var spelled: Balancer = undefined;
    try spelled.init(spelled_arena.allocator(), &spelled_config, testKeysFor(&spelled_config));

    const counts = [_]u16{0} ** test_counts_len;
    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        try std.testing.expectEqual(
            bare.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?.endpoint_index,
            spelled.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?.endpoint_index,
        );
    }
    try std.testing.expectEqual(bare.pick_state, spelled.pick_state);
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
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, .none).?;
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
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, .none).?;
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
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, .none).?;
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
        try std.testing.expectEqual(want_index, balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .none).?.endpoint_index);
        _ = balancer.pick(1, &testLoad(&counts), &test_healthy_all, &test_client, .none);
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
    const first = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client, .none).?.endpoint_index;
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const again = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client, .none).?;
        try std.testing.expectEqual(first, again.endpoint_index);
        try std.testing.expectEqual(endpoints[first], again.address);
    }
    // The load table is what p2c reads; hash must ignore it, or two
    // processes under different load would disagree about one client.
    var loaded = [_]u16{0} ** test_counts_len;
    loaded[test_keys.key(0, first)] = 10_000;
    try std.testing.expectEqual(
        first,
        balancer.pick(0, &testLoad(&loaded), &test_healthy_all, &client, .none).?.endpoint_index,
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
        _ = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index), .none);
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
        hits[balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index), .none).?.endpoint_index] += 1;
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
        before[index] = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index), .none).?.endpoint_index;
    }

    const ejected: u16 = 3;
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, ejected)] = false;

    var moved: u32 = 0;
    index = 0;
    while (index < clients) : (index += 1) {
        const after = balancer.pick(0, &testLoad(&counts), &healthy, &testClientAt(index), .none).?.endpoint_index;
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
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index), .none).?.endpoint_index,
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

test "balancer: hash spreads clients in proportion to weight" {
    const endpoints = testHashEndpoints(2);
    const weights = [_]u16{ 3, 1 };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash, .weights = &weights },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Replica-max scoring holds the argmax for weight/total of the key
    // space, so a 3:1 pair splits clients ~3:1 — not the ~3.4:1 that
    // naive score *scaling* gives, which is why the replicas exist.
    const counts = [_]u16{0} ** test_counts_len;
    const clients: u16 = 4000;
    var hits = [_]u32{0} ** 2;
    var index: u16 = 0;
    while (index < clients) : (index += 1) {
        hits[balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index), .none).?.endpoint_index] += 1;
    }
    const expected_heavy = clients * 3 / 4;
    try std.testing.expect(hits[0] > expected_heavy - 400);
    try std.testing.expect(hits[0] < expected_heavy + 400);
    try std.testing.expectEqual(clients, hits[0] + hits[1]);
}

test "balancer: re-weighting an endpoint disrupts only the clients it gains" {
    // The #174 issue's open question, answered: the disruption property
    // survives weighting. Raising one endpoint's weight adds replicas to
    // its score and touches nobody else's, so the only clients who move
    // are the ones the new replicas now win — every move lands on the
    // re-weighted endpoint, and every other assignment is untouched.
    const endpoints = testHashEndpoints(8);
    const flat_clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash },
    };
    var weights = [_]u16{1} ** 8;
    weights[3] = 2;
    const weighted_clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash, .weights = &weights },
    };
    const flat_config = testConfig(&flat_clusters);
    const weighted_config = testConfig(&weighted_clusters);

    var flat_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer flat_arena.deinit();
    var flat: Balancer = undefined;
    try flat.init(flat_arena.allocator(), &flat_config, testKeysFor(&flat_config));
    var weighted_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer weighted_arena.deinit();
    var weighted: Balancer = undefined;
    try weighted.init(weighted_arena.allocator(), &weighted_config, testKeysFor(&weighted_config));

    const counts = [_]u16{0} ** test_counts_len;
    const clients: u16 = 4000;
    var moved: u32 = 0;
    var index: u16 = 0;
    while (index < clients) : (index += 1) {
        const client = testClientAt(index);
        const before = flat.pick(0, &testLoad(&counts), &test_healthy_all, &client, .none).?.endpoint_index;
        const after = weighted.pick(0, &testLoad(&counts), &test_healthy_all, &client, .none).?.endpoint_index;
        if (after != before) {
            try std.testing.expectEqual(@as(u16, 3), after);
            moved += 1;
        }
    }
    // The gained share is 2/9 - 1/8 ≈ 9.7% of clients: real movement,
    // nowhere near a reshuffle.
    try std.testing.expect(moved > 0);
    try std.testing.expect(moved < clients / 4);
}

test "balancer: hash weight zero drains an endpoint, past fail-open" {
    const endpoints = testHashEndpoints(8);
    const flat_clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash },
    };
    var weights = [_]u16{1} ** 8;
    weights[3] = 0;
    const drained_clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash, .weights = &weights },
    };
    const flat_config = testConfig(&flat_clusters);
    const drained_config = testConfig(&drained_clusters);

    var flat_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer flat_arena.deinit();
    var flat: Balancer = undefined;
    try flat.init(flat_arena.allocator(), &flat_config, testKeysFor(&flat_config));
    var drained_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer drained_arena.deinit();
    var drained: Balancer = undefined;
    try drained.init(drained_arena.allocator(), &drained_config, testKeysFor(&drained_config));

    // Draining by weight is the ejection disruption, chosen: only the
    // drained endpoint's clients move, and the mapping is what the
    // healthy-mask ejection of the same endpoint produces — the next
    // replica down the same preference order.
    const counts = [_]u16{0} ** test_counts_len;
    const none_healthy = [_]bool{false} ** test_keys.count;
    var ejected_mask = test_healthy_all;
    ejected_mask[test_keys.key(0, 3)] = false;
    var index: u16 = 0;
    while (index < 500) : (index += 1) {
        const client = testClientAt(index);
        const after = drained.pick(0, &testLoad(&counts), &test_healthy_all, &client, .none).?.endpoint_index;
        try std.testing.expect(after != 3);
        try std.testing.expectEqual(
            flat.pick(0, &testLoad(&counts), &ejected_mask, &client, .none).?.endpoint_index,
            after,
        );
        // Fail-open re-admits the ejected, never the drained.
        try std.testing.expect(
            drained.pick(0, &testLoad(&counts), &none_healthy, &client, .none).?.endpoint_index != 3,
        );
    }
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
        const left_pick = left.pick(0, &testLoad(&counts), &test_healthy_all, &client, .none).?;
        const right_pick = right.pick(0, &testLoad(&counts), &test_healthy_all, &client, .none).?;
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
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &first, .none).?.endpoint_index,
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &rotated, .none).?.endpoint_index,
    );

    // A different /64 is a different client and must be free to land
    // elsewhere — otherwise the mask has swallowed the whole key. Scan a
    // range so the assertion does not rest on one lucky prefix.
    var differs = false;
    var prefix: u16 = 0;
    while (prefix < 64) : (prefix += 1) {
        var other = first;
        other.ip6.bytes[7] = @intCast(prefix);
        if (balancer.pick(0, &testLoad(&counts), &test_healthy_all, &other, .none).?.endpoint_index !=
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &first, .none).?.endpoint_index)
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
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client, .none).?.endpoint_index,
            balancer.pick(0, &testLoad(&counts), &none_healthy, &client, .none).?.endpoint_index,
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

test "balancer: hash on a header keys on the value, not the client" {
    const endpoints = testHashEndpoints(8);
    const clusters = [_]config_module.Config.Cluster{
        .{
            .name = "sticky",
            .endpoints = &endpoints,
            .pick = .hash,
            .hash_key = .{ .header = "x-tenant" },
        },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));
    const state_before = balancer.pick_state;

    const counts = [_]u16{0} ** test_counts_len;
    const key: Balancer.RequestKey = .{ .key = Balancer.bytesKey("tenant-a") };
    const first = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, key).?.endpoint_index;
    // A different client with the same header value is the same tenant:
    // the address must contribute nothing to a header-keyed pick.
    const roaming = testAddress("198.51.100.200:41000");
    try std.testing.expectEqual(
        first,
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &roaming, key).?.endpoint_index,
    );
    // Load on the winner must not move the tenant, and no PRNG state may
    // be spent: a keyed pick is a pure function, like source_ip's.
    var loaded = [_]u16{0} ** test_counts_len;
    loaded[test_keys.key(0, first)] = 10_000;
    try std.testing.expectEqual(
        first,
        balancer.pick(0, &testLoad(&loaded), &test_healthy_all, &test_client, key).?.endpoint_index,
    );
    try std.testing.expectEqual(state_before, balancer.pick_state);

    // Distinct values are distinct tenants and must spread: a run of them
    // has to reach several endpoints, or the value is not really keying.
    var hits = [_]u32{0} ** 8;
    var tenant: u16 = 0;
    while (tenant < 64) : (tenant += 1) {
        var name_buffer: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buffer, "tenant-{d}", .{tenant}) catch unreachable;
        const tenant_key: Balancer.RequestKey = .{ .key = Balancer.bytesKey(name) };
        hits[balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, tenant_key).?.endpoint_index] += 1;
    }
    var reached: u32 = 0;
    for (hits) |hit_count| {
        if (hit_count >= 1) reached += 1;
    }
    try std.testing.expect(reached >= 4);
}

test "balancer: a request without its keyed material places by load" {
    const endpoints = testHashEndpoints(3);
    const clusters = [_]config_module.Config.Cluster{
        .{
            .name = "sticky",
            .endpoints = &endpoints,
            .pick = .hash,
            .hash_key = .{ .header = "x-tenant" },
        },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Endpoint 1 is drowning. A keyless request takes the p2c placement:
    // any candidate pair containing the drowning endpoint also contains
    // a calmer one, so it must never win — and the idle endpoints must
    // both be reached, or this is not placement but a constant.
    var counts = [_]u16{0} ** test_counts_len;
    counts[test_keys.key(0, 1)] = 100;
    var hits = [_]u32{0} ** 3;
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, .absent).?;
        hits[picked.endpoint_index] += 1;
    }
    try std.testing.expectEqual(@as(u32, 0), hits[1]);
    try std.testing.expect(hits[0] >= 1);
    try std.testing.expect(hits[2] >= 1);
}

test "balancer: a cookie tag names its endpoint through any load" {
    const endpoints = testHashEndpoints(8);
    const clusters = [_]config_module.Config.Cluster{
        .{
            .name = "sticky",
            .endpoints = &endpoints,
            .pick = .hash,
            .hash_key = .{ .cookie = "zoxy-srv" },
        },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));
    const state_before = balancer.pick_state;

    // The tag is honoured wherever the load sits — stickiness is the
    // point, and load had its say when the session was placed — and the
    // honoured path spends no PRNG state.
    const wanted: u16 = 5;
    const tagged: Balancer.RequestKey = .{ .endpoint = balancer.endpointIdentity(0, wanted) };
    var loaded = [_]u16{0} ** test_counts_len;
    loaded[test_keys.key(0, wanted)] = 10_000;
    var round: u32 = 0;
    while (round < 50) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&loaded), &test_healthy_all, &test_client, tagged).?;
        try std.testing.expectEqual(wanted, picked.endpoint_index);
        try std.testing.expectEqual(endpoints[wanted], picked.address);
    }
    try std.testing.expectEqual(state_before, balancer.pick_state);
}

test "balancer: a tag naming nothing eligible re-homes by load" {
    const endpoints = testHashEndpoints(3);
    var weights = [_]u16{1} ** 3;
    weights[2] = 0;
    const clusters = [_]config_module.Config.Cluster{
        .{
            .name = "sticky",
            .endpoints = &endpoints,
            .pick = .hash,
            .hash_key = .{ .cookie = "zoxy-srv" },
            .weights = &weights,
        },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Three ways a tag can name nothing: the endpoint was ejected (§7),
    // the endpoint was drained (#174), or the tag was forged whole. Each
    // re-homes among the eligible — "healthy and under-capacity, in that
    // order" — rather than erroring or honouring the dead letter.
    const counts = [_]u16{0} ** test_counts_len;
    var ejected_mask = test_healthy_all;
    ejected_mask[test_keys.key(0, 0)] = false;
    const ejected_tag: Balancer.RequestKey = .{ .endpoint = balancer.endpointIdentity(0, 0) };
    const drained_tag: Balancer.RequestKey = .{ .endpoint = balancer.endpointIdentity(0, 2) };
    const forged_tag: Balancer.RequestKey = .{ .endpoint = 0xDEADBEEFDEADBEEF };
    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        try std.testing.expectEqual(
            @as(u16, 1),
            balancer.pick(0, &testLoad(&counts), &ejected_mask, &test_client, ejected_tag).?.endpoint_index,
        );
        try std.testing.expect(
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, drained_tag).?.endpoint_index != 2,
        );
        try std.testing.expect(
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, forged_tag).?.endpoint_index != 2,
        );
    }
}

test "balancer: endpoint tags round-trip, and only the minted spelling parses" {
    const identities = [_]u64{ 0, 1, 0x0123456789ABCDEF, std.math.maxInt(u64) };
    for (identities) |identity| {
        var tag: [Balancer.endpoint_tag_len]u8 = undefined;
        Balancer.formatEndpointTag(identity, &tag);
        try std.testing.expectEqual(identity, Balancer.parseEndpointTag(&tag).?);
    }
    var spelled: [Balancer.endpoint_tag_len]u8 = undefined;
    Balancer.formatEndpointTag(0x0123456789ABCDEF, &spelled);
    try std.testing.expectEqualStrings("0123456789abcdef", &spelled);

    // Only the exact minted spelling: the proxy never wrote the looser
    // forms, so a parser accepting them would give a forged cookie more
    // grammar than a real one has.
    try std.testing.expectEqual(@as(?u64, null), Balancer.parseEndpointTag(""));
    try std.testing.expectEqual(@as(?u64, null), Balancer.parseEndpointTag("0123456789abcde"));
    try std.testing.expectEqual(@as(?u64, null), Balancer.parseEndpointTag("0123456789abcdef0"));
    try std.testing.expectEqual(@as(?u64, null), Balancer.parseEndpointTag("0123456789ABCDEF"));
    try std.testing.expectEqual(@as(?u64, null), Balancer.parseEndpointTag("0123456789abcdeg"));
    try std.testing.expectEqual(@as(?u64, null), Balancer.parseEndpointTag("0x23456789abcdef"));
}

test "balancer: the header key is pinned, like every mapping hash here" {
    // The FNV half is checked against the published FNV-1a vectors, the
    // way `mix64` is checked against SplitMix64's published output — an
    // external anchor, not a value read back off our own implementation.
    try std.testing.expectEqual(mix64(0xAF63DC4C8601EC8C), bytesKeyOf("a"));
    try std.testing.expectEqual(mix64(0x85944171F73967E8), bytesKeyOf("foobar"));
    try std.testing.expect(bytesKeyOf("tenant-a") != bytesKeyOf("tenant-b"));
    // Case matters: header *names* are case-insensitive, header values
    // are not, and the key covers only the value.
    try std.testing.expect(bytesKeyOf("Alice") != bytesKeyOf("alice"));
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
        try std.testing.expect(balancer.pick(0, &load, &test_healthy_all, &test_client, .none).?.endpoint_index != 1);
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
            balancer.pick(0, &load, &test_healthy_all, &test_client, .none).?.endpoint_index,
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
            balancer.pick(0, &load, &test_healthy_all, &test_client, .none).?.endpoint_index,
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
        balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, .none),
    );
    // One request completes on endpoint 1 and the cluster serves again.
    l7[test_keys.key(0, 1)] = 2;
    try std.testing.expectEqual(
        @as(u16, 1),
        balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, .none).?.endpoint_index,
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
        balancer.pick(0, &load, &test_healthy_all, &test_client, .none),
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
        balancer.pick(0, &testLoad(&l7), &healthy, &test_client, .none),
    );
    // And when health fails open — every endpoint ejected — the caps
    // still apply to the whole set rather than being bypassed with it.
    healthy[test_keys.key(0, 1)] = false;
    l7[test_keys.key(0, 0)] = 1;
    try std.testing.expectEqual(
        @as(?Balancer.Pick, null),
        balancer.pick(0, &testLoad(&l7), &healthy, &test_client, .none),
    );
}
