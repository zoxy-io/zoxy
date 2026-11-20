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
//! **Untried endpoints (#181).** A pick takes the set of endpoints this
//! request has already dialed and failed, and excludes them. It is a
//! filter on the routable set, applied *before* health — not after, or a
//! two-endpoint cluster with one ejected would have its only untried
//! candidate removed by health and then resurrected by fail-open, handing
//! the retry straight back to the endpoint that just refused. Excluding
//! first and re-running the cluster's configured policy over what remains
//! is also what keeps each policy's contract: `rr` gives the next in
//! rotation, `p2c` still compares load across a smaller set, and `hash`
//! redistributes by rendezvous — each key falling to its own next-best
//! score, which is exactly where health-check ejection would send it a few
//! seconds later. A "take the next endpoint" rule would instead stampede
//! every sticky client of the failed backend onto the same neighbor.
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
//! `pickers.score`), so the scan is O(sum of weights), bounded per endpoint by
//! `endpoint_weight_max` and, like the endpoint count, priced by the
//! operator's own config. Jump consistent hash is excluded outright: it
//! can only add or remove the *last* bucket, and an ejection removes an
//! arbitrary one.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const extension = @import("extension.zig");
const parser = @import("http/parser.zig");
const pickers = @import("pickers.zig");
const upstream = @import("net/upstream.zig");
const io_module = @import("io/io.zig");

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
fn endpointId(address: *const io_module.Address) u64 {
    return switch (address.*) {
        // The loader rejects a zero endpoint port (`EndpointPortZero`),
        // and this folds the port into the identity — so a zero here
        // would mean a caller reached past config validation, and two
        // endpoints that differ only in a port nobody validated would be
        // scored as one.
        .ip => |ip| switch (ip) {
            .ip4 => |v4| id: {
                assert(v4.port != 0);
                break :id mix64(
                    (@as(u64, std.mem.readInt(u32, &v4.bytes, .big)) << 16) | v4.port,
                );
            },
            .ip6 => |v6| id: {
                assert(v6.port != 0);
                break :id mix64(mix64(std.mem.readInt(u64, v6.bytes[0..8], .big)) ^
                    mix64(std.mem.readInt(u64, v6.bytes[8..16], .big) ^ v6.port));
            },
        },
        // A socket path carries the whole identity — there is no port to
        // fold in, and the path is what two spellings of one endpoint
        // would have to share. Folded through the same `bytesKeyOf` the
        // #178 header key uses, and through `mix64` like the IP arms, so
        // every identity in this table comes out of one finalizer and a
        // rendezvous score can compare them as whole words. Pinned for
        // the reason `mix64` is: a rolling restart must not re-shuffle
        // which client lands on which socket.
        .unix => |path| id: {
            assert(path.len >= 1); // The loader rejects an empty path.
            break :id bytesKeyOf(path);
        },
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

pub const Balancer = struct {
    config: *const config_module.Config,
    /// The stock policy each cluster picks through (§7), on the picker
    /// contract (#417): its own round-robin totals (a row of one
    /// endpoint-keyed table, i64 because a total dips negative by design
    /// when its endpoint repays a round), its own hash key, the stateless
    /// p2c — or `.extension` where a build's picker serves the cluster,
    /// which the server dispatches.
    policies: []Policy,
    /// The pick generator: p2c's draws, the keyless arm of `hash`, and
    /// every draw an extension picker makes (#417) come from this one
    /// stream. Seeded from a fixed named constant, never the clock: the
    /// simulator replays every seed twice and demands byte-identical
    /// traces (§9), and load balancing needs spread, not secrecy —
    /// determinism is a feature.
    random: extension.Random,
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
    pub fn addressIdentity(address: *const io_module.Address) u64 {
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
        // The keys must describe *this* config. Tests build a `Config`
        // directly, bypassing `resolve`, so a mismatched
        // pair would size these tables for one shape and index them for
        // another — which is what the `clusters_max` ceiling used to catch
        // here, before the tables stopped being sized by it.
        assert(keys.count == @as(u32, @intCast(config.clusters.len)) * keys.stride);
        balancer.config = config;
        balancer.keys = keys;
        balancer.policies = try policiesFor(arena, config, keys);
        balancer.endpoint_hashes = try arena.alloc(u64, keys.count);
        balancer.eligible_scratch = try arena.alloc(u16, keys.stride);
        balancer.random = .init(pick_seed);
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
            // breaches (`EndpointWeightsAllZero`); a config a test builds
            // by hand re-proves them here, since
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
            // default rides only beside `pick: hash` — the stock
            // `Rendezvous` is the one reader, so anywhere else it would be
            // silently inert.
            if (cluster.pick != .hash) {
                assert(std.meta.activeTag(cluster.hash_key) == .source_ip);
            }
            if (cluster.weights) |weights| {
                assert(weights.len == cluster.endpoints.len);
            }
            // #396's tiers are the loader's to bound; a table a test builds
            // any other way is held to the same range.
            if (cluster.priorities) |priorities| {
                assert(priorities.len == cluster.endpoints.len);
                for (priorities) |priority| assert(priority <= constants.endpoint_priority_max);
            }
        }
        assert(balancer.policies.len == config.clusters.len);
        assert(balancer.endpoint_hashes.len == keys.count);
    }

    pub const Policy = union(enum) {
        rr: pickers.RoundRobin,
        p2c: pickers.PowerOfTwoChoices,
        hash: pickers.Rendezvous,
        extension,
    };

    /// Each cluster's stock policy, built once: a round-robin's totals are
    /// its own row of one zeroed table, a hash its own key.
    fn policiesFor(
        arena: std.mem.Allocator,
        config: *const config_module.Config,
        keys: upstream.EndpointKeys,
    ) error{OutOfMemory}![]Policy {
        const totals = try arena.alloc(i64, keys.count);
        @memset(totals, 0);
        const policies = try arena.alloc(Policy, config.clusters.len);
        for (config.clusters, policies, 0..) |*cluster, *policy, cluster_index| {
            const row = keys.key(@intCast(cluster_index), 0);
            policy.* = switch (cluster.pick) {
                .rr => .{ .rr = .{ .current = totals[row..][0..cluster.endpoints.len], .bound = true } },
                .p2c => .{ .p2c = .{} },
                .hash => .{ .hash = .{ .key = cluster.hash_key } },
                .extension => .extension,
            };
        }
        assert(policies.len == config.clusters.len);
        return policies;
    }

    /// The §7 stickiness key for a client's address (`sourceKey`), for
    /// the stock `hash` picker (#417).
    pub fn clientKey(address: *const std.Io.net.IpAddress) u64 {
        return sourceKey(address);
    }

    /// The pinned avalanche finalizer every mapping here goes through.
    pub fn mix(value: u64) u64 {
        return mix64(value);
    }

    /// A pick names the endpoint both ways: the address to dial and the
    /// index the upstream pool keys its idle lists by (§5).
    pub const Pick = struct {
        address: io_module.Address,
        endpoint_index: u16,
        /// The chosen endpoint is one the health mask has ejected — the
        /// fail-open rule, or a panic (#390), sent traffic there. What a
        /// caller counts so the pick is not invisible.
        ejected: bool,
        /// The cluster was below its panic threshold when this pick ran,
        /// so health did not steer it (#390). Always false without one.
        panicked: bool,
        /// The chosen endpoint is in a #396 standby tier (priority > 0):
        /// every tier below it had nothing usable.
        standby: bool,
    };

    /// What a pick concluded. The two empty answers are different rungs
    /// and the caller must not collapse them: `capped` is §8's
    /// origin-capacity shed — every candidate is already carrying its
    /// `max_inflight`, so this proxy refuses rather than dialing — while
    /// `exhausted` is #181's retry budget running out, every routable
    /// endpoint having been dialed and failed by this one request. One
    /// answers 503 and the other 502, and an operator reading either
    /// counter is asking a different question.
    pub const Outcome = union(enum) {
        dial: Pick,
        capped,
        /// Only reachable from a retry: with nothing tried, the drain
        /// filter alone can never empty the routable set (`init` proves
        /// at least one endpoint holds weight).
        exhausted,
        /// #392: the cluster's total in-flight work is at its
        /// `max_total_inflight`. Apart from `capped` because the two are
        /// different questions — one origin full, or this cluster's share
        /// of the process spent — and an operator widens different things.
        cluster_capped,
        /// #417: the cluster selected an extension picker, and the set it
        /// chooses among is narrowed into `eligible_scratch`. The caller,
        /// which knows the build's picker types, hands `extensionCandidates`
        /// to the picker and `finishExtension` turns its slot into the dial.
        extension: Choice,
    };

    /// A narrowed set a policy chooses among: how many candidates sit at
    /// the front of `eligible_scratch`, and whether health steered them.
    pub const Choice = struct {
        count: u16,
        panicked: bool,
    };

    /// Choose the endpoint to dial for `cluster_index` under the
    /// cluster's configured policy. `load` is the per-endpoint in-flight
    /// view (indexed by `upstream.endpointKey`), consulted by p2c — and by
    /// a request-keyed hash cluster placing a keyless request (#178) —
    /// and ignored by rr; `healthy` is the §7 health mask (same index) —
    /// the prober owns that truth the way the pool and the server own the
    /// load. `request` is the request on the L7 path of a cluster whose
    /// pick reads it. `tried` names the endpoints this request already
    /// dialed and failed (#181) — empty on a first try — and they are
    /// excluded outright. Bounded work, no allocation, and a validated
    /// config guarantees at least one endpoint.
    ///
    /// The policy itself runs on the picker contract (#417): the stock
    /// pickers (`pickers.zig`) read the narrowed set as a build's picker
    /// would, so this narrows, calls, and dials what they chose.
    pub fn pick(
        balancer: *Balancer,
        cluster_index: u16,
        load: *const upstream.Load,
        healthy: []const bool,
        client_address: ?*const std.Io.net.IpAddress,
        /// The request, on the L7 path of a cluster whose pick reads it —
        /// a build's picker, or `hash` on a header or a cookie (#417).
        request: ?*const extension.Request,
        tried: []const u16,
    ) Outcome {
        assert(cluster_index < balancer.config.clusters.len);
        const cluster = &balancer.config.clusters[cluster_index];
        assert(cluster.endpoints.len >= 1);
        assert(cluster.endpoints.len <= balancer.keys.stride);
        assert(tried.len <= cluster.endpoints.len);
        // The exclusion set is the caller's to build, so its entries are
        // checked here rather than trusted: an index past this cluster
        // would exclude nothing and read as a retry that had somewhere
        // left to go, which is the quiet direction to be wrong in.
        for (tried) |index| assert(index < cluster.endpoints.len);
        const steers = healthSteers(balancer.keys, cluster_index, cluster, healthy);
        // An extension picker is called for every pick on its cluster
        // (#417), the forced one included, so it never takes this path.
        if (cluster.pick != .extension and tried.len == 0 and cluster.endpoints.len == 1 and
            cluster.max_inflight == null and cluster.max_total_inflight == null)
        {
            // Neither a rotation nor a draw: uncapped single-endpoint
            // clusters stay branch-cheap and policy state is untouched.
            // The mask is moot too — one endpoint ejected is the
            // fail-open case — read only to report `ejected` (#390). A
            // cap has to be read, so it takes the general path below — and
            // so does a retry, which must see its own exclusion rather
            // than this endpoint again.
            return .{ .dial = .{
                .address = cluster.endpoints[0],
                .endpoint_index = 0,
                .ejected = !healthy[balancer.keys.key(cluster_index, 0)],
                .panicked = !steers,
                .standby = tierOf(cluster, 0) > 0,
            } };
        }
        // A first try only. Today this is insurance rather than a live
        // exemption: a retry and a stale replay both give their lease back
        // before they re-pick, so the total never counts them twice. The
        // rule it states — a request the cap admitted is not refused by it
        // — is what has to survive if that ordering ever changes.
        if (tried.len == 0) {
            if (cluster.max_total_inflight) |cap| {
                if (clusterInFlight(balancer.keys, cluster_index, cluster, load) >= cap) return .cluster_capped;
            }
        }
        const narrowed = balancer.narrow(cluster_index, cluster, load, healthy, steers, tried);
        const set = switch (narrowed) {
            .exhausted => return .exhausted,
            .capped => return .capped,
            .choose => |set| set,
        };
        assert(set.count >= 1);
        if (balancer.policies[cluster_index] == .extension) return .{ .extension = set };
        const chosen = balancer.stockPick(cluster_index, set, load, client_address, request, tried);
        assert(!alreadyTried(tried, chosen)); // The exclusion is not advisory.
        return .{ .dial = balancer.pickOf(cluster_index, chosen, healthy, set.panicked) };
    }

    /// The endpoint the cluster's stock policy chooses from the narrowed
    /// set, through the picker contract (#417) — the same view a build's
    /// picker reads, built only for the stock arms.
    fn stockPick(
        balancer: *Balancer,
        cluster_index: u16,
        set: Choice,
        load: *const upstream.Load,
        client_address: ?*const std.Io.net.IpAddress,
        request: ?*const extension.Request,
        tried: []const u16,
    ) u16 {
        const cluster = &balancer.config.clusters[cluster_index];
        // A request-keyed hash reads its key off the request: a caller
        // that handed none would turn stickiness into load placement
        // without a word.
        if (cluster.pick == .hash and cluster.hash_key != .source_ip) assert(request != null);
        const candidates = balancer.candidatesOf(cluster_index, set.count, load);
        const input: extension.PickInput = .{
            .cluster_index = cluster_index,
            .client = client_address,
            .request = request,
            // The stock policies read no tag: a build's picker is the one
            // that does, and `Server.pickEndpoint` hands it the real one.
            .tag = 0,
            .retry = tried.len >= 1,
            .panicked = set.panicked,
            .now_ns = load.now_ns,
            .random = &balancer.random,
        };
        const slot = switch (balancer.policies[cluster_index]) {
            .rr => |*picker| picker.pick(&candidates, &input),
            .p2c => |*picker| picker.pick(&candidates, &input),
            .hash => |*picker| picker.pick(&candidates, &input),
            .extension => unreachable, // The caller hands a build's picker to the server.
        };
        assert(slot < set.count); // The stock pickers answer inside the set.
        return balancer.eligible_scratch[slot];
    }

    /// The dial for `chosen`, with what a caller counts about it.
    fn pickOf(
        balancer: *const Balancer,
        cluster_index: u16,
        chosen: u16,
        healthy: []const bool,
        panicked: bool,
    ) Pick {
        const cluster = &balancer.config.clusters[cluster_index];
        assert(chosen < cluster.endpoints.len);
        assert(balancer.keys.key(cluster_index, chosen) < healthy.len);
        return .{
            .address = cluster.endpoints[chosen],
            .endpoint_index = chosen,
            .ejected = !healthy[balancer.keys.key(cluster_index, chosen)],
            .panicked = panicked,
            .standby = tierOf(cluster, chosen) > 0,
        };
    }

    /// The set an `.extension` outcome left in `eligible_scratch`, as the
    /// picker reads it (#417). Valid until the next pick, which is after
    /// the picker returns: the loop is single-threaded and a pick never
    /// re-enters.
    pub fn extensionCandidates(
        balancer: *const Balancer,
        cluster_index: u16,
        choice: Choice,
        load: *const upstream.Load,
    ) extension.Candidates {
        assert(balancer.config.clusters[cluster_index].pick == .extension);
        assert(choice.count >= 1);
        return balancer.candidatesOf(cluster_index, choice.count, load);
    }

    /// The narrowed set as every picker reads it, stock or a build's.
    fn candidatesOf(
        balancer: *const Balancer,
        cluster_index: u16,
        count: u16,
        load: *const upstream.Load,
    ) extension.Candidates {
        const cluster = &balancer.config.clusters[cluster_index];
        assert(count >= 1);
        assert(count <= cluster.endpoints.len);
        return .{
            .endpoints = balancer.eligible_scratch[0..count],
            .cluster_index = cluster_index,
            .cluster = cluster,
            .keys = balancer.keys,
            .load = load,
            .identities = balancer.endpoint_hashes,
        };
    }

    /// What an extension pick concluded: the dial, and whether the
    /// picker's slot named no candidate.
    pub const Finished = struct {
        pick: Pick,
        fell_back: bool,
    };

    /// Turn an extension picker's `slot` into the dial (#417). A slot
    /// outside the set it was offered is the picker's bug, and has a
    /// defined outcome rather than a crash: the load-aware placement p2c
    /// runs, over the same narrowed set, so the request still goes to an
    /// endpoint every rule above allowed — and the caller counts it.
    pub fn finishExtension(
        balancer: *Balancer,
        cluster_index: u16,
        choice: Choice,
        slot: u16,
        load: *const upstream.Load,
        healthy: []const bool,
    ) Finished {
        assert(balancer.config.clusters[cluster_index].pick == .extension);
        assert(choice.count >= 1);
        const eligible = balancer.eligible_scratch[0..choice.count];
        const fell_back = slot >= choice.count;
        const candidates = balancer.candidatesOf(cluster_index, choice.count, load);
        const chosen = if (fell_back)
            eligible[pickers.placeByLoad(&candidates, &balancer.random)]
        else
            eligible[slot];
        return .{
            .pick = balancer.pickOf(cluster_index, chosen, healthy, choice.panicked),
            .fell_back = fell_back,
        };
    }

    /// What a pick chooses between, left in `eligible_scratch`, or why it
    /// cannot choose at all.
    const Narrowed = union(enum) {
        choose: Choice,
        exhausted,
        capped,
    };

    /// The candidates a pick's policy runs over: health (§7, #390), then
    /// §8 capacity (with #391's ramp), then — in a tiered cluster — the
    /// lowest #396 tier left.
    ///
    /// A tiered cluster first tries the *healthy* endpoints of every tier,
    /// whatever its panic threshold says: a usable standby is preferred to
    /// reopening an ejected primary, which is the failover's whole point.
    /// Only when no tier has a healthy endpoint with room does the
    /// ordinary path run — panic or fail-open over every tier — and its
    /// result is narrowed to the lowest tier too.
    fn narrow(
        balancer: *const Balancer,
        cluster_index: u16,
        cluster: *const config_module.Config.Cluster,
        load: *const upstream.Load,
        healthy: []const bool,
        steers: bool,
        tried: []const u16,
    ) Narrowed {
        const keys = balancer.keys;
        const eligible = balancer.eligible_scratch;
        assert(eligible.len >= cluster.endpoints.len);
        assert(tried.len <= cluster.endpoints.len);
        if (cluster.priorities) |priorities| {
            const healthy_count = healthyCandidates(keys, cluster_index, cluster, healthy, tried, eligible);
            if (healthy_count >= 1) {
                const count = underCapacity(keys, cluster_index, cluster, load, eligible[0..healthy_count]);
                if (count >= 1) return .{ .choose = .{ .count = lowestTier(priorities, eligible[0..count]), .panicked = false } };
            }
        }
        const candidates = candidateEndpoints(keys, cluster_index, cluster, healthy, steers, tried, eligible);
        if (candidates == 0) {
            // A single-endpoint cluster cannot retry, and neither can one
            // whose every routable endpoint this request has already
            // dialed. Health does not fail open past this: the endpoints
            // it would resurrect are the ones that just failed.
            assert(tried.len >= 1);
            return .exhausted;
        }
        const count = underCapacity(keys, cluster_index, cluster, load, eligible[0..candidates]);
        // Every candidate is at its §8 cap. Unlike the health mask this
        // does *not* fail open: an ejected cluster means "we do not know,
        // try anyway", while a capped one means "we know they are full",
        // and dialing anyway is the exact thing the cap exists to stop.
        if (count == 0) return .capped;
        assert(count <= candidates);
        const narrowed = if (cluster.priorities) |priorities| lowestTier(priorities, eligible[0..count]) else count;
        return .{ .choose = .{ .count = narrowed, .panicked = !steers } };
    }

    /// The routable, untried endpoints the health mask holds healthy,
    /// with no fallback — the first pass of a tiered pick (#396).
    fn healthyCandidates(
        keys: upstream.EndpointKeys,
        cluster_index: u16,
        cluster: *const config_module.Config.Cluster,
        healthy: []const bool,
        tried: []const u16,
        eligible: []u16,
    ) u16 {
        assert(cluster.endpoints.len <= eligible.len);
        var count: u16 = 0;
        for (0..cluster.endpoints.len) |endpoint_index| {
            const index: u16 = @intCast(endpoint_index);
            if (weightOf(cluster, index) == 0) continue;
            if (alreadyTried(tried, index)) continue;
            if (!healthy[keys.key(cluster_index, index)]) continue;
            eligible[count] = index;
            count += 1;
        }
        assert(count <= cluster.endpoints.len);
        return count;
    }

    /// Keep only the lowest #396 tier present in `eligible`, in place and
    /// in order, and return how many that is. Never empties the set.
    fn lowestTier(priorities: []const u8, eligible: []u16) u16 {
        assert(eligible.len >= 1);
        var lowest: u8 = std.math.maxInt(u8);
        for (eligible) |index| lowest = @min(lowest, priorities[index]);
        var kept: u16 = 0;
        for (eligible) |index| {
            if (priorities[index] != lowest) continue;
            eligible[kept] = index;
            kept += 1;
        }
        assert(kept >= 1);
        assert(kept <= eligible.len);
        return kept;
    }

    /// An endpoint's #396 tier: 0 in an untiered cluster.
    fn tierOf(cluster: *const config_module.Config.Cluster, endpoint_index: u16) u8 {
        assert(endpoint_index < cluster.endpoints.len);
        const priorities = cluster.priorities orelse return 0;
        assert(priorities.len == cluster.endpoints.len);
        return priorities[endpoint_index];
    }

    /// The endpoints a pick may choose between before capacity is read,
    /// in three passes.
    ///
    /// First the #174 drain: a weight-0 endpoint never enters the set.
    /// Unlike the health mask this is not a verdict to fail open past —
    /// it is the operator saying *stop sending here*, and the whole
    /// point of the spelling is that it holds while everything else
    /// flaps.
    ///
    /// Then #181's exclusion: an endpoint this request already dialed and
    /// failed is out, and health does not fail open past this one either.
    /// Both filters run before health for the same reason — they say
    /// *not here*, where health only says *we suspect*.
    ///
    /// Then §7 health over what remains: the healthy ones — or, the
    /// fail-open rule, all of them when every one is ejected. Dialing a
    /// maybe-dead endpoint reports the outage the way it always did;
    /// routing nowhere would turn a probe verdict into an outage of its
    /// own, and a same-port TCP probe cannot know better than the dial.
    ///
    /// #390 moves that fail-open point up. With a panic threshold the
    /// health pass is skipped outright once the healthy share of the
    /// cluster's routable weight falls below it, so four survivors of ten
    /// do not each carry two and a half times their load. Judged over the
    /// whole routable set, not this request's untried remainder: panic
    /// is the cluster's state, and a retry must not tip it.
    ///
    /// **May return zero**, but only for a request that has tried
    /// something: at least one endpoint holds weight (the loader rejects
    /// an all-zero cluster and `init` re-proves it), so the drain filter
    /// alone can never empty the set.
    fn candidateEndpoints(
        keys: upstream.EndpointKeys,
        cluster_index: u16,
        cluster: *const config_module.Config.Cluster,
        healthy: []const bool,
        steers: bool,
        tried: []const u16,
        eligible: []u16,
    ) u16 {
        assert(cluster.endpoints.len >= 1);
        assert(cluster.endpoints.len <= eligible.len);
        assert(steers or cluster.panic_threshold_percent != null);
        var count: u16 = 0;
        if (steers) {
            for (0..cluster.endpoints.len) |endpoint_index| {
                const index: u16 = @intCast(endpoint_index);
                if (weightOf(cluster, index) == 0) continue;
                if (alreadyTried(tried, index)) continue;
                if (healthy[keys.key(cluster_index, index)]) {
                    eligible[count] = index;
                    count += 1;
                }
            }
        }
        if (count == 0) {
            for (0..cluster.endpoints.len) |endpoint_index| {
                const index: u16 = @intCast(endpoint_index);
                if (weightOf(cluster, index) == 0) continue;
                if (alreadyTried(tried, index)) continue;
                eligible[count] = index;
                count += 1;
            }
        }
        assert(count >= 1 or tried.len >= 1);
        assert(count <= cluster.endpoints.len);
        return count;
    }

    /// The cluster's total in-flight work (#392): every endpoint's leases
    /// and live L4 connections, the same units `max_inflight` caps one at.
    fn clusterInFlight(
        keys: upstream.EndpointKeys,
        cluster_index: u16,
        cluster: *const config_module.Config.Cluster,
        load: *const upstream.Load,
    ) u64 {
        assert(cluster.endpoints.len >= 1);
        var total: u64 = 0;
        for (0..cluster.endpoints.len) |endpoint_index| {
            total += load.inFlight(keys.key(cluster_index, @intCast(endpoint_index)));
        }
        // `Load.inFlight` is two u16 tables summed per endpoint.
        assert(total <= @as(u64, cluster.endpoints.len) * 2 * std.math.maxInt(u16));
        return total;
    }

    /// Whether the health mask filters this cluster's picks (#390): while
    /// the healthy share of its routable weight is at or above its panic
    /// threshold. Without a threshold, always — the zero-healthy fallback
    /// in `candidateEndpoints` is then the whole rule, as it was before
    /// the key. A drained endpoint counts on neither side: weight `0` is
    /// not capacity the cluster has, healthy or not.
    fn healthSteers(
        keys: upstream.EndpointKeys,
        cluster_index: u16,
        cluster: *const config_module.Config.Cluster,
        healthy: []const bool,
    ) bool {
        const threshold = cluster.panic_threshold_percent orelse return true;
        assert(threshold >= constants.panic_threshold_percent_min);
        assert(threshold <= constants.panic_threshold_percent_max);
        var routable_weight: u64 = 0;
        var healthy_weight: u64 = 0;
        for (0..cluster.endpoints.len) |endpoint_index| {
            const index: u16 = @intCast(endpoint_index);
            const weight = weightOf(cluster, index);
            routable_weight += weight;
            if (healthy[keys.key(cluster_index, index)]) healthy_weight += weight;
        }
        // `init` proves some endpoint holds weight, so the share is defined.
        assert(routable_weight >= 1);
        assert(healthy_weight <= routable_weight);
        // Cross-multiplied, so the share needs no division or rounding:
        // healthy / routable >= threshold / percent_whole.
        return healthy_weight * percent_whole >= @as(u64, threshold) * routable_weight;
    }

    /// The whole a `panic_threshold_percent` is a part of.
    const percent_whole: u64 = 100;
    comptime {
        assert(constants.panic_threshold_percent_max < percent_whole);
    }

    /// §8 capacity over the candidates: an endpoint already carrying its
    /// `max_inflight` is dropped. This pass may empty a non-empty set,
    /// and that is the difference from the health pass — the caller sheds
    /// rather than dialing. The order matters too: capacity is judged
    /// over the endpoints health would have used, so a cluster that fails
    /// open still respects its caps.
    fn underCapacity(
        keys: upstream.EndpointKeys,
        cluster_index: u16,
        cluster: *const config_module.Config.Cluster,
        load: *const upstream.Load,
        eligible: []u16,
    ) u16 {
        assert(eligible.len >= 1);
        assert(eligible.len <= cluster.endpoints.len);
        const full_cap = cluster.max_inflight orelse return @intCast(eligible.len);
        assert(full_cap >= 1);
        var under: u16 = 0;
        for (eligible) |index| {
            const key = keys.key(cluster_index, index);
            // #391: an endpoint inside its slow-start window gets a cap
            // that ramps from 1 toward `max_inflight` as the window runs.
            const cap = if (cluster.slow_start_ms) |window_ms|
                rampedCap(full_cap, window_ms, load.restoredAt(key), load.now_ns)
            else
                full_cap;
            if (load.inFlight(key) < cap) {
                eligible[under] = index;
                under += 1;
            }
        }
        assert(under <= eligible.len);
        return under;
    }

    /// `cap` as it stands `now_ns - restored_at_ns` into a `window_ms`
    /// slow start (#391): linear from 1 at the restore to the full cap at
    /// the window's end, never 0 — a restored endpoint that could take no
    /// work at all would never show it had recovered. An endpoint never
    /// restored (`restored_at_ns == 0`) is past any window.
    pub fn rampedCap(cap: u32, window_ms: u32, restored_at_ns: u64, now_ns: u64) u32 {
        assert(cap >= 1);
        assert(window_ms >= 1);
        if (restored_at_ns == 0) return cap;
        assert(now_ns >= restored_at_ns);
        // Milliseconds, not nanoseconds: the product below is then at most
        // `endpoint_inflight_max * timeout_ms_max`, which `u64` holds with
        // room to spare — where the same product in nanoseconds would not.
        comptime assert(@as(u128, constants.endpoint_inflight_max) * constants.timeout_ms_max <
            std.math.maxInt(u64));
        const elapsed_ms = (now_ns - restored_at_ns) / std.time.ns_per_ms;
        if (elapsed_ms >= window_ms) return cap;
        const ramped: u64 = @as(u64, cap) * elapsed_ms / window_ms;
        const result: u32 = @intCast(@max(1, ramped));
        assert(result >= 1 and result <= cap);
        return result;
    }

    /// Whether this request has already dialed `endpoint_index` and had
    /// the dial fail (#181). A linear scan because the set is bounded by
    /// `constants.cluster_retries_max` and never sorted — the order it
    /// was filled in is the order the tries happened, which is what the
    /// access log and the counters describe.
    fn alreadyTried(tried: []const u16, endpoint_index: u16) bool {
        assert(tried.len <= constants.cluster_retries_max + 1);
        for (tried) |index| {
            if (index == endpoint_index) return true;
        }
        return false;
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
const test_healthy_all: [test_keys.count]bool = @splat(true);

/// The L4 half of the load view, all zero: what a pure-L7 test sees.
const test_l4_idle: [test_keys.count]u16 = @splat(0);

/// A load view over an L7 lease table, for the tests that only vary
/// that half. The pair-of-tables shape is what production passes.
fn testLoad(l7: *const [test_keys.count]u16) upstream.Load {
    return .{ .l7 = l7, .l4 = &test_l4_idle };
}

/// The client address `rr`/`p2c` scenarios pass and ignore; only `.hash`
/// reads it.
const test_client = std.Io.net.IpAddress.parseLiteral("198.51.100.7:40000") catch unreachable;

/// A first try, which is every scenario that is not about #181: nothing
/// has been dialed yet, so nothing is excluded.
const test_untried: []const u16 = &.{};

/// A *client* address for the fixtures below — the half that stays
/// IP-only: a listener still binds an IP, so a peer address is always
/// one. Endpoints use `ipEndpoint`.
fn testAddress(comptime literal: []const u8) std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral(literal) catch unreachable;
}

/// One IP endpoint from its literal, for the fixtures below. `catch
/// unreachable` is sound on a comptime literal this file wrote: an
/// unparseable one is a compile-time-visible typo, not a runtime path.
fn ipEndpoint(comptime literal: []const u8) io_module.Address {
    return .{ .ip = std.Io.net.IpAddress.parseLiteral(literal) catch unreachable };
}

fn testConfig(clusters: []const config_module.Config.Cluster) config_module.Config {
    return .{
        .listeners = &.{},
        .clusters = clusters,
        .connect_timeout_ms = 1,
        .idle_timeout_ms = 1,
        .head_timeout_ms = 1,
        .drain_deadline_ms = 1,
        .loop_watchdog_ms = 0,
        .max_lifetime_ms = 0,
        .request_timeout_ms = 0,
        .tunnel_timeout_ms = constants.tunnel_ms_default,
    };
}

test "balancer: rr cycles endpoints and wraps per cluster" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "trio", .endpoints = &trio, .pick = .rr },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Rotation is exact whatever the load table says: rr ignores it.
    var counts: [test_counts_len]u16 = @splat(0);
    counts[test_keys.key(0, 0)] = 100;
    const expected = [_]u16{ 0, 1, 2, 0, 1 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(want_index, picked.endpoint_index);
        try std.testing.expectEqual(trio[want_index], picked.address);
    }
}

test "balancer: a single-endpoint cluster short-circuits without a draw" {
    const solo = ipEndpoint("127.0.0.1:9");
    const one = [_]io_module.Address{solo};
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "one", .endpoints = &one },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));
    const state_before = balancer.random.state;

    const counts: [test_counts_len]u16 = @splat(0);
    var round: u32 = 0;
    while (round < 10) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(solo, picked.address);
        try std.testing.expectEqual(@as(u16, 0), picked.endpoint_index);
    }
    // The PRNG state never advanced: no draw was spent.
    try std.testing.expectEqual(state_before, balancer.random.state);
}

test "balancer: p2c prefers the less-loaded of its two candidates" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
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
    var counts: [test_counts_len]u16 = @splat(0);
    counts[test_keys.key(0, 1)] = 100;
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial;
        try std.testing.expect(picked.endpoint_index != 1);
    }
}

test "balancer: p2c spreads across endpoints under equal load" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
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
    const counts: [test_counts_len]u16 = @splat(0);
    var hits: [3]u32 = @splat(0);
    var round: u32 = 0;
    while (round < 300) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial;
        hits[picked.endpoint_index] += 1;
    }
    for (hits) |hit_count| {
        try std.testing.expect(hit_count >= 1);
    }
}

test "balancer: same seed, same picks — the p2c draw is deterministic" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const pair = [_]io_module.Address{ a, b };
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
    const counts: [test_counts_len]u16 = @splat(0);
    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        try std.testing.expectEqual(
            left.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial.endpoint_index,
            right.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial.endpoint_index,
        );
    }
}

test "balancer: rr rotates over the healthy endpoints only" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
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
    const counts: [test_counts_len]u16 = @splat(0);
    const expected = [_]u16{ 0, 2, 0, 2, 0 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(want_index, picked.endpoint_index);
    }
}

test "balancer: rr honors weights, and the schedule is smooth" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const pair = [_]io_module.Address{ a, b };
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
    const counts: [test_counts_len]u16 = @splat(0);
    const expected = [_]u16{ 0, 1, 0, 0, 1, 0 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(want_index, picked.endpoint_index);
    }
}

test "balancer: rr weight zero drains an endpoint, past fail-open" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
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
    const counts: [test_counts_len]u16 = @splat(0);
    const expected = [_]u16{ 0, 2, 0, 2 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(want_index, picked.endpoint_index);
    }
    // Fail-open re-admits the ejected, never the drained: a weight of 0
    // is the operator's statement, not a probe's verdict, so even a
    // fully-ejected cluster keeps routing around it.
    const none_healthy: [test_keys.count]bool = @splat(false);
    var round: u32 = 0;
    while (round < 20) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &none_healthy, &test_client, null, test_untried).dial;
        try std.testing.expect(picked.endpoint_index != 1);
    }
}

test "balancer: p2c candidacy follows weight" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
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
    const counts: [test_counts_len]u16 = @splat(0);
    var hits: [3]u32 = @splat(0);
    var round: u32 = 0;
    while (round < 400) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial;
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
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
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

    const counts: [test_counts_len]u16 = @splat(0);
    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        try std.testing.expectEqual(
            bare.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial.endpoint_index,
            spelled.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial.endpoint_index,
        );
    }
    try std.testing.expectEqual(bare.random.state, spelled.random.state);
}

test "balancer: p2c never picks an ejected endpoint" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
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
    var counts: [test_counts_len]u16 = @splat(0);
    counts[test_keys.key(0, 0)] = 50;
    counts[test_keys.key(0, 2)] = 50;
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, null, test_untried).dial;
        try std.testing.expect(picked.endpoint_index != 1);
    }
}

test "balancer: p2c narrowed to one healthy endpoint spends no draw" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const pair = [_]io_module.Address{ a, b };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .p2c },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));
    const state_before = balancer.random.state;

    // One survivor: the pick is forced, so the PRNG must not advance —
    // the same no-draw rule as a single-endpoint cluster.
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, 0)] = false;
    const counts: [test_counts_len]u16 = @splat(0);
    var round: u32 = 0;
    while (round < 10) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(@as(u16, 1), picked.endpoint_index);
    }
    try std.testing.expectEqual(state_before, balancer.random.state);
}

test "balancer: a fully-ejected cluster fails open to every endpoint" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
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
    const counts: [test_counts_len]u16 = @splat(0);
    const expected = [_]u16{ 0, 1, 2, 0, 1 };
    for (expected) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(want_index, picked.endpoint_index);
        // Fail-open lands on the ejected, and is not a panic: the
        // cluster has no threshold (#390's counters tell them apart).
        try std.testing.expect(picked.ejected and !picked.panicked);
    }
}

test "balancer: below its panic threshold a cluster picks over every routable endpoint (#390)" {
    const quad = [_]io_module.Address{
        ipEndpoint("127.0.0.1:1"), ipEndpoint("127.0.0.1:2"),
        ipEndpoint("127.0.0.1:3"), ipEndpoint("127.0.0.1:4"),
    };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "panicky", .endpoints = &quad, .pick = .rr, .panic_threshold_percent = 50 },
        .{ .name = "default", .endpoints = &quad, .pick = .rr },
    };
    const config = testConfig(&clusters);
    const keys = testKeysFor(&config);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, keys);
    const counts: [test_counts_len]u16 = @splat(0);

    // Exactly at the threshold — two of four healthy, half the weight —
    // health still steers, so rotation stays on the healthy pair.
    var healthy = test_healthy_all;
    healthy[keys.key(0, 2)] = false;
    healthy[keys.key(0, 3)] = false;
    for ([_]u16{ 0, 1, 0, 1 }) |want_index| {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(want_index, picked.endpoint_index);
        try std.testing.expect(!picked.panicked and !picked.ejected);
    }
    // One more ejection leaves a quarter of the weight healthy, under
    // half: the cluster panics, and rotation covers all four. Every pick
    // says so, and the ones landing on the ejected say that too — the
    // two flags the counters read (#390).
    healthy[keys.key(0, 1)] = false;
    var seen: [quad.len]bool = @splat(false);
    for (0..2 * quad.len) |_| {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, null, test_untried).dial;
        seen[picked.endpoint_index] = true;
        try std.testing.expect(picked.panicked);
        try std.testing.expectEqual(picked.endpoint_index != 0, picked.ejected);
    }
    for (seen) |reached| try std.testing.expect(reached);

    // The same mask on a cluster with no threshold keeps the old rule:
    // the one healthy endpoint left takes every pick.
    healthy[keys.key(1, 1)] = false;
    healthy[keys.key(1, 2)] = false;
    healthy[keys.key(1, 3)] = false;
    for (0..quad.len) |_| {
        const picked = balancer.pick(1, &testLoad(&counts), &healthy, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(@as(u16, 0), picked.endpoint_index);
        try std.testing.expect(!picked.panicked and !picked.ejected);
    }
}

test "balancer: a drained endpoint is no part of the panic share, nor of panic's picks (#390)" {
    const quad = [_]io_module.Address{
        ipEndpoint("127.0.0.1:1"), ipEndpoint("127.0.0.1:2"),
        ipEndpoint("127.0.0.1:3"), ipEndpoint("127.0.0.1:4"),
    };
    const weights = [_]u16{ 1, 1, 0, 1 };
    const clusters = [_]config_module.Config.Cluster{.{
        .name = "draining",
        .endpoints = &quad,
        .pick = .rr,
        .weights = &weights,
        .panic_threshold_percent = 60,
    }};
    const config = testConfig(&clusters);
    const keys = testKeysFor(&config);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, keys);
    const counts: [test_counts_len]u16 = @splat(0);

    // Two of the three routable endpoints are healthy: two thirds, over
    // 60 percent, so health steers. Counting the drained endpoint as
    // capacity would make it two of four, under the threshold, and
    // panic would put endpoint 3 in rotation.
    var healthy = test_healthy_all;
    healthy[keys.key(0, 3)] = false;
    for (0..8) |_| {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, null, test_untried).dial;
        try std.testing.expect(picked.endpoint_index == 0 or picked.endpoint_index == 1);
    }
    // In panic the ejected come back, and the drained still does not.
    healthy[keys.key(0, 1)] = false;
    var seen: [quad.len]bool = @splat(false);
    for (0..8) |_| {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, null, test_untried).dial;
        seen[picked.endpoint_index] = true;
    }
    try std.testing.expect(seen[0] and seen[1] and seen[3]);
    try std.testing.expect(!seen[2]);
}

test "balancer: a retry cannot tip its cluster into panic (#390)" {
    const quad = [_]io_module.Address{
        ipEndpoint("127.0.0.1:1"), ipEndpoint("127.0.0.1:2"),
        ipEndpoint("127.0.0.1:3"), ipEndpoint("127.0.0.1:4"),
    };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "retrying", .endpoints = &quad, .pick = .rr, .panic_threshold_percent = 50 },
    };
    const config = testConfig(&clusters);
    const keys = testKeysFor(&config);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, keys);
    const counts: [test_counts_len]u16 = @splat(0);

    // Half the cluster is healthy, so it steers. A retry that already
    // tried endpoint 0 has one healthy endpoint left among its untried
    // three — a third, which would panic if the share were judged over
    // the request's remainder. It is the cluster's state, so the retry
    // goes to the other healthy endpoint. Only once every healthy one is
    // tried does the zero-healthy fallback reach the ejected, as it did
    // before the threshold existed.
    var healthy = test_healthy_all;
    healthy[keys.key(0, 2)] = false;
    healthy[keys.key(0, 3)] = false;
    const tried = [_]u16{0};
    for (0..4) |_| {
        const picked = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, null, &tried).dial;
        try std.testing.expectEqual(@as(u16, 1), picked.endpoint_index);
    }
}

test "balancer: a cluster at its total cap refuses a first try, never a retry (#392)" {
    const pair = [_]io_module.Address{ ipEndpoint("127.0.0.1:1"), ipEndpoint("127.0.0.1:2") };
    const one = [_]io_module.Address{ipEndpoint("127.0.0.1:3")};
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .rr, .max_total_inflight = 3 },
        // One endpoint, no per-endpoint cap: the branch-cheap fast path,
        // which a total cap has to opt out of to be read at all.
        .{ .name = "one", .endpoints = &one, .max_total_inflight = 1 },
    };
    const config = testConfig(&clusters);
    const keys = testKeysFor(&config);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, keys);

    // Two in flight on one endpoint, none on the other: under the cap of
    // three, so a first try dials.
    var l7: [test_counts_len]u16 = @splat(0);
    l7[keys.key(0, 0)] = 2;
    try std.testing.expect(balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, null, test_untried) == .dial);
    // Three across the cluster is the cap, whichever endpoints carry it.
    l7[keys.key(0, 1)] = 1;
    try std.testing.expect(balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, null, test_untried) == .cluster_capped);
    // A retry belongs to a request the cap admitted: it is never refused
    // by it, and goes to the endpoint it has not tried.
    const tried = [_]u16{0};
    try std.testing.expectEqual(@as(u16, 1), balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, null, &tried).dial.endpoint_index);
    // The single-endpoint fast path does not skip the cap.
    l7[keys.key(1, 0)] = 1;
    try std.testing.expect(balancer.pick(1, &testLoad(&l7), &test_healthy_all, &test_client, null, test_untried) == .cluster_capped);
}

test "balancer: a slow-start cap ramps from 1 to the full cap over its window (#391)" {
    const ms = std.time.ns_per_ms;
    const back: u64 = 10_000 * ms;
    // Never restored: no window to be inside.
    try std.testing.expectEqual(@as(u32, 8), Balancer.rampedCap(8, 1_000, 0, back));
    // The instant it came back: one, never zero.
    try std.testing.expectEqual(@as(u32, 1), Balancer.rampedCap(8, 1_000, back, back));
    // Linear through the window, floored at one.
    try std.testing.expectEqual(@as(u32, 4), Balancer.rampedCap(8, 1_000, back, back + 500 * ms));
    try std.testing.expectEqual(@as(u32, 1), Balancer.rampedCap(8, 1_000, back, back + 100 * ms));
    // The window's end and past it: the configured cap.
    try std.testing.expectEqual(@as(u32, 8), Balancer.rampedCap(8, 1_000, back, back + 1_000 * ms));
    try std.testing.expectEqual(@as(u32, 8), Balancer.rampedCap(8, 1_000, back, back + 60_000 * ms));
}

test "balancer: a just-restored endpoint is capped below max_inflight until its ramp catches up (#391)" {
    const pair = [_]io_module.Address{ ipEndpoint("127.0.0.1:1"), ipEndpoint("127.0.0.1:2") };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .rr, .max_inflight = 4, .slow_start_ms = 1_000 },
    };
    const config = testConfig(&clusters);
    const keys = testKeysFor(&config);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, keys);

    // Endpoint 0 came back 250 ms ago — a quarter of the window, so its
    // cap is 1 of 4 — and already carries one request. Endpoint 1 was
    // never ejected. Every pick goes to endpoint 1 until 0's ramp rises.
    var l7: [test_counts_len]u16 = @splat(0);
    l7[keys.key(0, 0)] = 1;
    var restored: [test_keys.count]u64 = @splat(0);
    const now_ns: u64 = 20 * std.time.ns_per_s;
    restored[keys.key(0, 0)] = now_ns - 250 * std.time.ns_per_ms;
    const ramping: upstream.Load = .{ .l7 = &l7, .l4 = &test_l4_idle, .restored_at_ns = &restored, .now_ns = now_ns };
    for (0..4) |_| {
        const picked = balancer.pick(0, &ramping, &test_healthy_all, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(@as(u16, 1), picked.endpoint_index);
    }
    // Past the window the same load is under the full cap of four.
    const settled: upstream.Load = .{ .l7 = &l7, .l4 = &test_l4_idle, .restored_at_ns = &restored, .now_ns = now_ns + std.time.ns_per_s };
    var reached_zero = false;
    for (0..4) |_| {
        if (balancer.pick(0, &settled, &test_healthy_all, &test_client, null, test_untried).dial.endpoint_index == 0) reached_zero = true;
    }
    try std.testing.expect(reached_zero);
}

test "balancer: a standby tier takes traffic only when the primary tier has nothing usable (#396)" {
    const trio = [_]io_module.Address{
        ipEndpoint("127.0.0.1:1"), ipEndpoint("127.0.0.1:2"), ipEndpoint("127.0.0.1:3"),
    };
    const priorities = [_]u8{ 0, 0, 1 };
    const clusters = [_]config_module.Config.Cluster{.{
        .name = "tiered",
        .endpoints = &trio,
        .pick = .rr,
        .priorities = &priorities,
        .max_inflight = 1,
    }};
    const config = testConfig(&clusters);
    const keys = testKeysFor(&config);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, keys);

    // Both primaries usable: the standby is never picked.
    var l7: [test_counts_len]u16 = @splat(0);
    for (0..6) |_| {
        const picked = balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, null, test_untried).dial;
        try std.testing.expect(picked.endpoint_index != 2);
        try std.testing.expect(!picked.standby);
    }
    // Primaries full: the load spills to the standby, and says so.
    l7[keys.key(0, 0)] = 1;
    l7[keys.key(0, 1)] = 1;
    const spilled = balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, null, test_untried).dial;
    try std.testing.expectEqual(@as(u16, 2), spilled.endpoint_index);
    try std.testing.expect(spilled.standby);
    // Every tier full: shed, never past a cap.
    l7[keys.key(0, 2)] = 1;
    try std.testing.expect(balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, null, test_untried) == .capped);

    // Primaries ejected, standby healthy and free: the standby.
    l7 = @splat(0);
    var healthy = test_healthy_all;
    healthy[keys.key(0, 0)] = false;
    healthy[keys.key(0, 1)] = false;
    try std.testing.expectEqual(@as(u16, 2), balancer.pick(0, &testLoad(&l7), &healthy, &test_client, null, test_untried).dial.endpoint_index);
    // Nothing healthy anywhere: fail-open, to the primary tier first.
    healthy[keys.key(0, 2)] = false;
    const opened = balancer.pick(0, &testLoad(&l7), &healthy, &test_client, null, test_untried).dial;
    try std.testing.expect(opened.endpoint_index != 2);
    try std.testing.expect(opened.ejected);
    // A retry that tried both primaries goes to the standby.
    const tried = [_]u16{ 0, 1 };
    try std.testing.expectEqual(@as(u16, 2), balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, null, &tried).dial.endpoint_index);
}

test "balancer: a usable standby comes before panic reopens an ejected primary (#396, #390)" {
    const quad = [_]io_module.Address{
        ipEndpoint("127.0.0.1:1"), ipEndpoint("127.0.0.1:2"),
        ipEndpoint("127.0.0.1:3"), ipEndpoint("127.0.0.1:4"),
    };
    const priorities = [_]u8{ 0, 0, 0, 1 };
    const clusters = [_]config_module.Config.Cluster{.{
        .name = "tiered",
        .endpoints = &quad,
        .pick = .rr,
        .priorities = &priorities,
        .panic_threshold_percent = 90,
    }};
    const config = testConfig(&clusters);
    const keys = testKeysFor(&config);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, keys);

    // Two of three primaries ejected: half the cluster's weight healthy,
    // under the 90 percent threshold, so an untiered cluster would panic.
    // Here a healthy primary and a healthy standby remain, and health
    // still steers: the lowest healthy tier, never an ejected endpoint.
    var healthy = test_healthy_all;
    healthy[keys.key(0, 0)] = false;
    healthy[keys.key(0, 1)] = false;
    const l7: [test_counts_len]u16 = @splat(0);
    for (0..4) |_| {
        const picked = balancer.pick(0, &testLoad(&l7), &healthy, &test_client, null, test_untried).dial;
        try std.testing.expectEqual(@as(u16, 2), picked.endpoint_index);
        try std.testing.expect(!picked.panicked and !picked.ejected);
    }
}

test "balancer: policies keep independent state across clusters" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const pair = [_]io_module.Address{ a, b };
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
    const counts: [test_counts_len]u16 = @splat(0);
    const expected = [_]u16{ 0, 1, 0, 1, 0 };
    for (expected) |want_index| {
        try std.testing.expectEqual(want_index, balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried).dial.endpoint_index);
        _ = balancer.pick(1, &testLoad(&counts), &test_healthy_all, &test_client, null, test_untried);
    }
}

/// A cluster of `count` endpoints at 10.0.0.1..N, for the §7 hash tests.
fn testHashEndpoints(comptime count: u16) [count]io_module.Address {
    var endpoints: [count]io_module.Address = undefined;
    for (&endpoints, 0..) |*endpoint, index| {
        endpoint.* = .{ .ip = .{ .ip4 = .{
            .bytes = .{ 10, 0, 0, @intCast(index + 1) },
            .port = 8080,
        } } };
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

    const counts: [test_counts_len]u16 = @splat(0);
    const client = testAddress("203.0.113.9:51000");
    const first = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client, null, test_untried).dial.endpoint_index;
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const again = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client, null, test_untried).dial;
        try std.testing.expectEqual(first, again.endpoint_index);
        try std.testing.expectEqual(endpoints[first], again.address);
    }
    // The load table is what p2c reads; hash must ignore it, or two
    // processes under different load would disagree about one client.
    var loaded: [test_counts_len]u16 = @splat(0);
    loaded[test_keys.key(0, first)] = 10_000;
    try std.testing.expectEqual(
        first,
        balancer.pick(0, &testLoad(&loaded), &test_healthy_all, &client, null, test_untried).dial.endpoint_index,
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
    const state_before = balancer.random.state;

    const counts: [test_counts_len]u16 = @splat(0);
    var index: u16 = 0;
    while (index < 500) : (index += 1) {
        _ = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index), null, test_untried);
    }
    try std.testing.expectEqual(state_before, balancer.random.state);
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

    const counts: [test_counts_len]u16 = @splat(0);
    const clients: u16 = 4000;
    var hits: [8]u32 = @splat(0);
    var index: u16 = 0;
    while (index < clients) : (index += 1) {
        hits[balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index), null, test_untried).dial.endpoint_index] += 1;
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

    const counts: [test_counts_len]u16 = @splat(0);
    const clients: u16 = 4000;
    var before: [clients]u16 = undefined;
    var index: u16 = 0;
    while (index < clients) : (index += 1) {
        before[index] = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index), null, test_untried).dial.endpoint_index;
    }

    const ejected: u16 = 3;
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, ejected)] = false;

    var moved: u32 = 0;
    index = 0;
    while (index < clients) : (index += 1) {
        const after = balancer.pick(0, &testLoad(&counts), &healthy, &testClientAt(index), null, test_untried).dial.endpoint_index;
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
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index), null, test_untried).dial.endpoint_index,
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
    const counts: [test_counts_len]u16 = @splat(0);
    const clients: u16 = 4000;
    var hits: [2]u32 = @splat(0);
    var index: u16 = 0;
    while (index < clients) : (index += 1) {
        hits[balancer.pick(0, &testLoad(&counts), &test_healthy_all, &testClientAt(index), null, test_untried).dial.endpoint_index] += 1;
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
    var weights: [8]u16 = @splat(1);
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

    const counts: [test_counts_len]u16 = @splat(0);
    const clients: u16 = 4000;
    var moved: u32 = 0;
    var index: u16 = 0;
    while (index < clients) : (index += 1) {
        const client = testClientAt(index);
        const before = flat.pick(0, &testLoad(&counts), &test_healthy_all, &client, null, test_untried).dial.endpoint_index;
        const after = weighted.pick(0, &testLoad(&counts), &test_healthy_all, &client, null, test_untried).dial.endpoint_index;
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
    var weights: [8]u16 = @splat(1);
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
    const counts: [test_counts_len]u16 = @splat(0);
    const none_healthy: [test_keys.count]bool = @splat(false);
    var ejected_mask = test_healthy_all;
    ejected_mask[test_keys.key(0, 3)] = false;
    var index: u16 = 0;
    while (index < 500) : (index += 1) {
        const client = testClientAt(index);
        const after = drained.pick(0, &testLoad(&counts), &test_healthy_all, &client, null, test_untried).dial.endpoint_index;
        try std.testing.expect(after != 3);
        try std.testing.expectEqual(
            flat.pick(0, &testLoad(&counts), &ejected_mask, &client, null, test_untried).dial.endpoint_index,
            after,
        );
        // Fail-open re-admits the ejected, never the drained.
        try std.testing.expect(
            drained.pick(0, &testLoad(&counts), &none_healthy, &client, null, test_untried).dial.endpoint_index != 3,
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
    var reversed: [8]io_module.Address = undefined;
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

    const counts: [test_counts_len]u16 = @splat(0);
    var index: u16 = 0;
    while (index < 1000) : (index += 1) {
        const client = testClientAt(index);
        const left_pick = left.pick(0, &testLoad(&counts), &test_healthy_all, &client, null, test_untried).dial;
        const right_pick = right.pick(0, &testLoad(&counts), &test_healthy_all, &client, null, test_untried).dial;
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

    const counts: [test_counts_len]u16 = @splat(0);
    const first = testAddress("[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:51000");
    const rotated = testAddress("[2001:db8:1:2:1111:2222:3333:4444]:52000");
    try std.testing.expectEqual(
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &first, null, test_untried).dial.endpoint_index,
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &rotated, null, test_untried).dial.endpoint_index,
    );

    // A different /64 is a different client and must be free to land
    // elsewhere — otherwise the mask has swallowed the whole key. Scan a
    // range so the assertion does not rest on one lucky prefix.
    var differs = false;
    var prefix: u16 = 0;
    while (prefix < 64) : (prefix += 1) {
        var other = first;
        other.ip6.bytes[7] = @intCast(prefix);
        if (balancer.pick(0, &testLoad(&counts), &test_healthy_all, &other, null, test_untried).dial.endpoint_index !=
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &first, null, test_untried).dial.endpoint_index)
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

    const counts: [test_counts_len]u16 = @splat(0);
    const none_healthy: [test_keys.count]bool = @splat(false);
    var index: u16 = 0;
    while (index < 500) : (index += 1) {
        const client = testClientAt(index);
        // Fail-open restores the full set, so the answer is the same one
        // the healthy cluster gives.
        try std.testing.expectEqual(
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client, null, test_untried).dial.endpoint_index,
            balancer.pick(0, &testLoad(&counts), &none_healthy, &client, null, test_untried).dial.endpoint_index,
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
    const address = ipEndpoint(literal);
    return endpointId(&address);
}

/// A request carrying `headers`, for the keyed `hash` tests (#417): the
/// stock picker reads its key off the request it is handed, as a build's
/// picker would, so these tests hand it one.
fn testRequest(headers: []const parser.Header) extension.Request {
    assert(headers.len <= 4);
    return .{
        .method = .get,
        .host = null,
        .path = "/",
        .query = "",
        .headers = headers,
        .client = null,
        .client_cert_sha256 = null,
        .listener_index = 0,
        .cluster_index = 0,
        .tag = 0,
        .now_ns = 1,
    };
}

fn tenantHeader(value: []const u8) [1]parser.Header {
    assert(value.len >= 1);
    return .{.{ .name = "x-tenant", .value = value, .tag = .other }};
}

/// A `Cookie` header naming `identity` under the tests' cookie name,
/// spelled as the proxy mints it.
fn tagCookie(identity: u64, buffer: *[64]u8) [1]parser.Header {
    var tag: [Balancer.endpoint_tag_len]u8 = undefined;
    Balancer.formatEndpointTag(identity, &tag);
    const value = std.fmt.bufPrint(buffer, "theme=dark; zoxy-srv={s}", .{tag}) catch unreachable;
    assert(value.len >= Balancer.endpoint_tag_len);
    return .{.{ .name = "cookie", .value = value, .tag = .other }};
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
    const state_before = balancer.random.state;

    const counts: [test_counts_len]u16 = @splat(0);
    const tenant_a = tenantHeader("tenant-a");
    const keyed = testRequest(&tenant_a);
    const key = &keyed;
    const first = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, key, test_untried).dial.endpoint_index;
    // A different client with the same header value is the same tenant:
    // the address must contribute nothing to a header-keyed pick.
    const roaming = testAddress("198.51.100.200:41000");
    try std.testing.expectEqual(
        first,
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &roaming, key, test_untried).dial.endpoint_index,
    );
    // Load on the winner must not move the tenant, and no PRNG state may
    // be spent: a keyed pick is a pure function, like source_ip's.
    var loaded: [test_counts_len]u16 = @splat(0);
    loaded[test_keys.key(0, first)] = 10_000;
    try std.testing.expectEqual(
        first,
        balancer.pick(0, &testLoad(&loaded), &test_healthy_all, &test_client, key, test_untried).dial.endpoint_index,
    );
    try std.testing.expectEqual(state_before, balancer.random.state);

    // Distinct values are distinct tenants and must spread: a run of them
    // has to reach several endpoints, or the value is not really keying.
    var hits: [8]u32 = @splat(0);
    var tenant: u16 = 0;
    while (tenant < 64) : (tenant += 1) {
        var name_buffer: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buffer, "tenant-{d}", .{tenant}) catch unreachable;
        const tenant_header = tenantHeader(name);
        const tenant_request = testRequest(&tenant_header);
        hits[balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, &tenant_request, test_untried).dial.endpoint_index] += 1;
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
    var counts: [test_counts_len]u16 = @splat(0);
    counts[test_keys.key(0, 1)] = 100;
    var hits: [3]u32 = @splat(0);
    // A request, but not the header the cluster keys on.
    const unkeyed = testRequest(&.{});
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, &unkeyed, test_untried).dial;
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
    const state_before = balancer.random.state;

    // The tag is honoured wherever the load sits — stickiness is the
    // point, and load had its say when the session was placed — and the
    // honoured path spends no PRNG state.
    const wanted: u16 = 5;
    var cookie_buffer: [64]u8 = undefined;
    const cookie = tagCookie(balancer.endpointIdentity(0, wanted), &cookie_buffer);
    const tagged_request = testRequest(&cookie);
    const tagged = &tagged_request;
    var loaded: [test_counts_len]u16 = @splat(0);
    loaded[test_keys.key(0, wanted)] = 10_000;
    var round: u32 = 0;
    while (round < 50) : (round += 1) {
        const picked = balancer.pick(0, &testLoad(&loaded), &test_healthy_all, &test_client, tagged, test_untried).dial;
        try std.testing.expectEqual(wanted, picked.endpoint_index);
        try std.testing.expectEqual(endpoints[wanted], picked.address);
    }
    try std.testing.expectEqual(state_before, balancer.random.state);
}

test "balancer: a tag naming nothing eligible re-homes by load" {
    const endpoints = testHashEndpoints(3);
    var weights: [3]u16 = @splat(1);
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
    const counts: [test_counts_len]u16 = @splat(0);
    var ejected_mask = test_healthy_all;
    ejected_mask[test_keys.key(0, 0)] = false;
    var buffers: [3][64]u8 = undefined;
    const ejected_cookie = tagCookie(balancer.endpointIdentity(0, 0), &buffers[0]);
    const drained_cookie = tagCookie(balancer.endpointIdentity(0, 2), &buffers[1]);
    const forged_cookie = tagCookie(0xDEADBEEFDEADBEEF, &buffers[2]);
    const ejected_request = testRequest(&ejected_cookie);
    const drained_request = testRequest(&drained_cookie);
    const forged_request = testRequest(&forged_cookie);
    const ejected_tag = &ejected_request;
    const drained_tag = &drained_request;
    const forged_tag = &forged_request;
    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        try std.testing.expectEqual(
            @as(u16, 1),
            balancer.pick(0, &testLoad(&counts), &ejected_mask, &test_client, ejected_tag, test_untried).dial.endpoint_index,
        );
        try std.testing.expect(
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, drained_tag, test_untried).dial.endpoint_index != 2,
        );
        try std.testing.expect(
            balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, forged_tag, test_untried).dial.endpoint_index != 2,
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
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
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
    const l7_idle: [test_counts_len]u16 = @splat(0);
    var l4: [test_counts_len]u16 = @splat(0);
    l4[test_keys.key(0, 1)] = 100;
    const load: upstream.Load = .{ .l7 = &l7_idle, .l4 = &l4 };
    var round: u32 = 0;
    while (round < 200) : (round += 1) {
        try std.testing.expect(balancer.pick(0, &load, &test_healthy_all, &test_client, null, test_untried).dial.endpoint_index != 1);
    }
}

test "balancer: p2c compares the sum of both protocols" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const pair = [_]io_module.Address{ a, b };
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
    var l7: [test_counts_len]u16 = @splat(0);
    var l4: [test_counts_len]u16 = @splat(0);
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
            balancer.pick(0, &load, &test_healthy_all, &test_client, null, test_untried).dial.endpoint_index,
        );
    }
}

test "balancer: a capped endpoint is skipped while another has room" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const pair = [_]io_module.Address{ a, b };
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
    var l7: [test_counts_len]u16 = @splat(0);
    l7[test_keys.key(0, 0)] = 2;
    const load = testLoad(&l7);
    var round: u32 = 0;
    while (round < 8) : (round += 1) {
        try std.testing.expectEqual(
            @as(u16, 1),
            balancer.pick(0, &load, &test_healthy_all, &test_client, null, test_untried).dial.endpoint_index,
        );
    }
}

test "balancer: a fully capped cluster refuses rather than failing open" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const pair = [_]io_module.Address{ a, b };
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
    var l7: [test_counts_len]u16 = @splat(0);
    l7[test_keys.key(0, 0)] = 3;
    l7[test_keys.key(0, 1)] = 3;
    try std.testing.expectEqual(
        Balancer.Outcome.capped,
        balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, null, test_untried),
    );
    // One request completes on endpoint 1 and the cluster serves again.
    l7[test_keys.key(0, 1)] = 2;
    try std.testing.expectEqual(
        @as(u16, 1),
        balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, null, test_untried).dial.endpoint_index,
    );
}

test "balancer: the cap counts both protocols, and covers one endpoint" {
    const solo = ipEndpoint("127.0.0.1:9");
    const one = [_]io_module.Address{solo};
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
    var l7: [test_counts_len]u16 = @splat(0);
    var l4: [test_counts_len]u16 = @splat(0);
    l7[test_keys.key(0, 0)] = 3;
    l4[test_keys.key(0, 0)] = 1;
    const load: upstream.Load = .{ .l7 = &l7, .l4 = &l4 };
    try std.testing.expectEqual(
        Balancer.Outcome.capped,
        balancer.pick(0, &load, &test_healthy_all, &test_client, null, test_untried),
    );
    // Reading either table alone would leave room and dial anyway.
    try std.testing.expect(l7[test_keys.key(0, 0)] < 4);
    try std.testing.expect(l4[test_keys.key(0, 0)] < 4);
}

test "balancer: capacity is judged over the endpoints health left" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const pair = [_]io_module.Address{ a, b };
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
    var l7: [test_counts_len]u16 = @splat(0);
    l7[test_keys.key(0, 1)] = 1;
    try std.testing.expectEqual(
        Balancer.Outcome.capped,
        balancer.pick(0, &testLoad(&l7), &healthy, &test_client, null, test_untried),
    );
    // And when health fails open — every endpoint ejected — the caps
    // still apply to the whole set rather than being bypassed with it.
    healthy[test_keys.key(0, 1)] = false;
    l7[test_keys.key(0, 0)] = 1;
    try std.testing.expectEqual(
        Balancer.Outcome.capped,
        balancer.pick(0, &testLoad(&l7), &healthy, &test_client, null, test_untried),
    );
}

test "balancer: a tried endpoint is excluded from the retry" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "trio", .endpoints = &trio, .pick = .rr },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    const counts: [test_counts_len]u16 = @splat(0);
    // Whatever the rotation would have handed back, the endpoint this
    // request already dialed is not it — and the retry after that skips
    // both. Every remaining pick is still a real rotation over what is
    // left, not a fixed "next endpoint" rule.
    const first = [_]u16{0};
    const second = [_]u16{ 0, 2 };
    var round: u32 = 0;
    while (round < 6) : (round += 1) {
        const retry = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, &first).dial;
        try std.testing.expect(retry.endpoint_index != 0);
        const last = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, &second).dial;
        try std.testing.expectEqual(@as(u16, 1), last.endpoint_index);
        try std.testing.expectEqual(b, last.address);
    }
}

test "balancer: fail-open cannot resurrect the endpoint that just failed" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const pair = [_]io_module.Address{ a, b };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .rr },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Endpoint 1 is ejected, endpoint 0 was just dialed and refused. Run
    // the exclusion after health and the sequence is: health keeps {0},
    // untried removes it, the empty set fails open, and the retry goes
    // straight back to the endpoint that refused. Running it first — as
    // `candidateEndpoints` does — leaves {1}, which health then fails
    // open over, and the maybe-dead endpoint is dialed rather than none.
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, 1)] = false;
    const counts: [test_counts_len]u16 = @splat(0);
    const tried = [_]u16{0};
    const retry = balancer.pick(0, &testLoad(&counts), &healthy, &test_client, null, &tried).dial;
    try std.testing.expectEqual(@as(u16, 1), retry.endpoint_index);
    try std.testing.expectEqual(b, retry.address);
}

test "balancer: every routable endpoint tried is exhausted, never capped" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const c = ipEndpoint("127.0.0.1:3");
    const trio = [_]io_module.Address{ a, b, c };
    // Endpoint 2 is drained (#174), so the routable set is {0, 1} and
    // trying both exhausts the cluster even though an endpoint remains.
    const weights = [_]u16{ 1, 1, 0 };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "trio", .endpoints = &trio, .weights = &weights, .pick = .rr },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    const counts: [test_counts_len]u16 = @splat(0);
    const one_left = [_]u16{0};
    try std.testing.expectEqual(
        @as(u16, 1),
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, &one_left).dial.endpoint_index,
    );
    // A drain is the operator's statement and outranks the retry's need
    // for somewhere to go: endpoint 2 is not a candidate at any point.
    const both = [_]u16{ 0, 1 };
    try std.testing.expectEqual(
        Balancer.Outcome.exhausted,
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, &both),
    );
}

test "balancer: a single-endpoint cluster cannot retry" {
    const solo = ipEndpoint("127.0.0.1:9");
    const one = [_]io_module.Address{solo};
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "one", .endpoints = &one },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // The uncapped single-endpoint fast path must not answer a retry with
    // the endpoint the retry exists to avoid — it is the one short-circuit
    // that returns before the eligible set is ever built.
    const counts: [test_counts_len]u16 = @splat(0);
    const tried = [_]u16{0};
    try std.testing.expectEqual(
        Balancer.Outcome.exhausted,
        balancer.pick(0, &testLoad(&counts), &test_healthy_all, &test_client, null, &tried),
    );
}

test "balancer: a retry whose survivors are all full is capped, not exhausted" {
    const a = ipEndpoint("127.0.0.1:1");
    const b = ipEndpoint("127.0.0.1:2");
    const pair = [_]io_module.Address{ a, b };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "pair", .endpoints = &pair, .pick = .rr, .max_inflight = 2 },
    };
    const config = testConfig(&clusters);

    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    // Endpoint 0 refused; endpoint 1 is untried but at its §8 cap. The
    // two empty answers must stay apart: this is the origin carrying all
    // it agreed to (503), not the request running out of places to go.
    var l7: [test_counts_len]u16 = @splat(0);
    l7[test_keys.key(0, 1)] = 2;
    const tried = [_]u16{0};
    try std.testing.expectEqual(
        Balancer.Outcome.capped,
        balancer.pick(0, &testLoad(&l7), &test_healthy_all, &test_client, null, &tried),
    );
}

test "balancer: a hash retry lands where ejection would send the key" {
    // The property the retry design turns on (#181): re-running the
    // configured pick over the set minus what was tried gives each key
    // its own next-best score — the same redistribution health-check
    // ejection produces a few seconds later. Retry and ejection therefore
    // agree, and behavior does not shift under the operator when the
    // prober catches up. A "take the next endpoint" rule would instead
    // pile every client of the failed backend onto one neighbor.
    const endpoints = testHashEndpoints(8);
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "sticky", .endpoints = &endpoints, .pick = .hash },
    };
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    const counts: [test_counts_len]u16 = @splat(0);
    const failed: u16 = 3;
    var healthy = test_healthy_all;
    healthy[test_keys.key(0, failed)] = false;
    const tried = [_]u16{failed};

    var spread: [8]u32 = @splat(0);
    var retried: u32 = 0;
    var index: u16 = 0;
    while (index < 4000) : (index += 1) {
        const client = testClientAt(index);
        const first = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client, null, test_untried).dial;
        if (first.endpoint_index != failed) continue;
        retried += 1;
        const retry = balancer.pick(0, &testLoad(&counts), &test_healthy_all, &client, null, &tried).dial;
        const ejected = balancer.pick(0, &testLoad(&counts), &healthy, &client, null, test_untried).dial;
        try std.testing.expectEqual(ejected.endpoint_index, retry.endpoint_index);
        spread[retry.endpoint_index] += 1;
    }
    try std.testing.expect(retried > 0);
    // And the population really is redistributed rather than moved: the
    // failed endpoint's clients reach more than one survivor.
    var reached: u32 = 0;
    for (spread) |hits| {
        if (hits > 0) reached += 1;
    }
    try std.testing.expect(reached > 1);
}

test "balancer: an extension cluster is offered exactly what every rule left (#417)" {
    // Four endpoints: 1 is drained, 2 sits at its cap and 3 was dialed
    // and refused. Every rule zoxy owns has spoken before a picker is
    // asked, so the one candidate it may be offered is endpoint 0.
    const quad = [_]io_module.Address{
        ipEndpoint("127.0.0.1:1"), ipEndpoint("127.0.0.1:2"),
        ipEndpoint("127.0.0.1:3"), ipEndpoint("127.0.0.1:4"),
    };
    const weights = [_]u16{ 1, 0, 1, 1 };
    var instance: u8 = 0;
    const clusters = [_]config_module.Config.Cluster{.{
        .name = "custom",
        .endpoints = &quad,
        .weights = &weights,
        .max_inflight = 2,
        .pick = .{ .extension = .{ .index = 0, .instance = &instance } },
    }};
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    var l7: [test_keys.count]u16 = @splat(0);
    l7[2] = 2;
    const load = testLoad(&l7);
    const outcome = balancer.pick(0, &load, &test_healthy_all, &test_client, null, &.{3});
    const choice = outcome.extension;
    try std.testing.expectEqual(@as(u16, 1), choice.count);
    try std.testing.expect(!choice.panicked);

    const candidates = balancer.extensionCandidates(0, choice, &load);
    try std.testing.expectEqual(@as(u16, 1), candidates.count());
    try std.testing.expectEqual(@as(u16, 0), candidates.endpointIndex(0));
    try std.testing.expectEqual(@as(u16, 1), candidates.weight(0));
    try std.testing.expectEqual(@as(?u32, 2), candidates.capacity(0));
    try std.testing.expectEqual(@as(u32, 0), candidates.inFlight(0));
    try std.testing.expectEqual(balancer.endpointIdentity(0, 0), candidates.identity(0));

    const finished = balancer.finishExtension(0, choice, 0, &load, &test_healthy_all);
    try std.testing.expect(!finished.fell_back);
    try std.testing.expectEqual(@as(u16, 0), finished.pick.endpoint_index);
}

test "balancer: an extension slot past its set falls back to placement inside it (#417)" {
    const trio = [_]io_module.Address{
        ipEndpoint("127.0.0.1:1"), ipEndpoint("127.0.0.1:2"), ipEndpoint("127.0.0.1:3"),
    };
    var instance: u8 = 0;
    const clusters = [_]config_module.Config.Cluster{.{
        .name = "custom",
        .endpoints = &trio,
        .pick = .{ .extension = .{ .index = 0, .instance = &instance } },
    }};
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    var l7: [test_keys.count]u16 = @splat(0);
    const load = testLoad(&l7);
    var seen: [3]bool = @splat(false);
    for (0..64) |_| {
        const choice = balancer.pick(0, &load, &test_healthy_all, &test_client, null, test_untried).extension;
        try std.testing.expectEqual(@as(u16, 3), choice.count);
        // A slot inside the set is followed exactly.
        const followed = balancer.finishExtension(0, choice, 2, &load, &test_healthy_all);
        try std.testing.expect(!followed.fell_back);
        try std.testing.expectEqual(@as(u16, 2), followed.pick.endpoint_index);
        // One past it names no candidate: the dial still lands inside
        // the set, by placement rather than by the picker's word.
        const again = balancer.pick(0, &load, &test_healthy_all, &test_client, null, test_untried).extension;
        const fallen = balancer.finishExtension(0, again, again.count, &load, &test_healthy_all);
        try std.testing.expect(fallen.fell_back);
        try std.testing.expect(fallen.pick.endpoint_index < trio.len);
        seen[fallen.pick.endpoint_index] = true;
    }
    // Placement draws, so the fallback is not a fixed endpoint.
    try std.testing.expect(seen[0] and seen[1] and seen[2]);
}

test "balancer: a one-endpoint extension cluster still asks its picker (#417)" {
    // The fast path a built-in single-endpoint cluster takes would skip
    // the picker, and the contract is that every pick on its cluster
    // reaches it.
    const solo = [_]io_module.Address{ipEndpoint("127.0.0.1:1")};
    var instance: u8 = 0;
    const clusters = [_]config_module.Config.Cluster{.{
        .name = "custom",
        .endpoints = &solo,
        .pick = .{ .extension = .{ .index = 0, .instance = &instance } },
    }};
    const config = testConfig(&clusters);
    var balancer_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer balancer_arena.deinit();
    var balancer: Balancer = undefined;
    try balancer.init(balancer_arena.allocator(), &config, testKeysFor(&config));

    var l7: [test_keys.count]u16 = @splat(0);
    const load = testLoad(&l7);
    const outcome = balancer.pick(0, &load, &test_healthy_all, &test_client, null, test_untried);
    try std.testing.expect(outcome == .extension);
    try std.testing.expectEqual(@as(u16, 1), outcome.extension.count);
}
