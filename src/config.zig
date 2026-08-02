//! Strict JSON → arena-owned immutable `Config` (DESIGN.md §5): parsed
//! once at startup, never reloaded (§1 non-goal). Two stages: std.json
//! with strict options (unknown field → error, duplicate field → error)
//! into JSON-shaped structs, then validation and resolution into the
//! runtime shape — every limit gets its own error, every address is a
//! static socket literal (`IpAddress.parseLiteral` rejects hostnames, so
//! the no-DNS non-goal holds structurally). The returned `Config` may
//! reference both the arena and `json_bytes`; the caller keeps both alive
//! for the process lifetime.

const std = @import("std");

const constants = @import("constants.zig");
const router = @import("http/router.zig");
const filter = @import("http/filter.zig");
const parser = @import("http/parser.zig");
const render = @import("http/render.zig");

const assert = std.debug.assert;

pub const Config = struct {
    listeners: []const Listener,
    clusters: []const Cluster,
    connect_timeout_ms: u32,
    idle_timeout_ms: u32,
    drain_deadline_ms: u32,
    /// Absolute cap on a connection's age, regardless of activity (§6): it
    /// rides the same per-connection deadline timer as the idle timeout,
    /// clamping the activity-refreshed deadline so a continuously busy
    /// connection is still reaped. `0` disables the cap — the one timeout
    /// where zero is legal (an unbounded connection age), so it is optional
    /// in the JSON and defaults off.
    max_lifetime_ms: u32,
    /// Cap on one L7 exchange, from the moment a request head is routed to
    /// the last response byte (§8). Unlike the idle timeout it is *not*
    /// refreshed by activity, so it bounds a request that is progressing
    /// too slowly, not merely one that has stalled — the difference
    /// between shedding on time and shedding only when a resource runs
    /// out. It rides the same per-connection deadline timer, clamping it
    /// the way `max_lifetime_ms` does, and expires into the §8 request-
    /// deadline rung: `504` if no response byte has been sent, teardown
    /// otherwise. `0` disables it, so it is optional in the JSON and
    /// defaults off. L4 connections never set it.
    request_timeout_ms: u32,
    /// Pause between §7 health-probe sweeps over every `check` cluster's
    /// endpoints. Probing itself is enabled per cluster (`Cluster.check`);
    /// this only paces it, so it is optional in the JSON and defaults to
    /// HAProxy's `inter` (`constants.health_interval_ms_default`). Zero is
    /// rejected — a pause of nothing would probe in a tight loop. Each
    /// probe dials under `connect_timeout_ms`, its own budget.
    health_interval_ms: u32 = constants.health_interval_ms_default,
    /// Effective pool sizes (§5, §8). The comptime constants stay the
    /// hard, budget-asserted ceilings; config may only shrink below them
    /// — for capacity planning, and so the overload benchmark can hit
    /// the real shed rungs at loopback-feasible load. Defaulted so the
    /// test beds' literal configs keep the full pools.
    limits: Limits = .{},
    /// The admin/metrics listener's bind address (§8),
    /// or null when no `admin` block is configured — the plane stays off.
    /// A static IP:port literal like every other bind (hostnames rejected).
    admin_bind: ?std.Io.net.IpAddress = null,
    /// Where access-log lines go (§8), or null when no `access_log` block
    /// is configured — the log stays off and reserves nothing.
    access_log_sink: ?AccessLogSink = null,

    /// Where the access log writes (§8). `stdout` is the process's own
    /// standard output, inherited rather than opened, so it costs no file
    /// descriptor and carries no rotation story of its own — an operator
    /// pipes it wherever they already send this process's output. `file`
    /// is a path the io backend opens once at startup — append-only,
    /// created if absent, never truncated — costing exactly one fd
    /// (`fdsRequired`); append-only is what keeps an external
    /// copy-truncate rotation safe, every write landing at the current
    /// end wherever a rotation just put it. A tagged union so the arm
    /// that needs a parameter carries it, and the arms stay the closed
    /// set the schema names (`AccessLogSinkKind`).
    pub const AccessLogSink = union(AccessLogSinkKind) {
        stdout,
        file: []const u8,
    };

    /// The sink names the config may spell — split from `AccessLogSink`
    /// because the schema renders (and the parser matches) bare names,
    /// and only the resolved union carries a payload.
    pub const AccessLogSinkKind = enum(u1) {
        stdout,
        file,
    };

    pub const Limits = struct {
        conn_slots: u32 = constants.conn_slots_default,
        relay_buffers: u32 = constants.relay_buffers_default,
        upstream_slots: u32 = constants.upstream_slots_default,
        /// The §5 head-buffer ring: how many request heads may be in
        /// flight at once. Buffers bind only to connections with a head
        /// actually arriving or held — idle keep-alive connections hold
        /// none — so this is a concurrency limit, not a per-connection
        /// cost. The loader resolves an omitted field to conn_slots
        /// (every connection could be mid-head at once: never sheds, the
        /// same worst-case memory the inline buffers used to pin); the
        /// operator trades it down against the `l7_shed_head_buffers`
        /// wall. Zero exactly when no listener speaks http. The *struct*
        /// default is the off state, like `access_log_buffer_bytes`:
        /// hand-built (test) configs opt in explicitly, and one that
        /// serves http without doing so dies on the seam's own assert
        /// rather than silently inheriting a production-sized ring.
        head_buffers: u32 = 0,
        /// The §5 upstream head pool: how many exchanges may hold an
        /// upstream head (the render-to-park window) at once. Parked
        /// upstream connections hold none, so this bounds concurrent
        /// *exchanges in their head phase*, not open origin connections.
        /// The loader resolves an omitted field to upstream_slots (a
        /// leased slot never needs more than one head — never sheds);
        /// zero exactly when no listener speaks http, and the struct
        /// default is the off state on the same terms as `head_buffers`.
        upstream_head_buffers: u32 = 0,
        /// Bytes per head buffer, in both §5 head pools — and therefore
        /// the largest request or response head this proxy accepts: an
        /// oversize request head is 414/431, an oversize origin head
        /// tears the exchange down (§7). Operator-visible behaviour, not
        /// just a size, which is why it gets a floor (below it, ordinary
        /// requests start dying) as well as a ceiling. May be raised as
        /// well as lowered — the big-cookie/JWT case is the reason it
        /// exists. Inert when both pools are zero (an L4-only config).
        head_buffer_bytes: u32 = constants.head_buffer_bytes_default,
        /// How many eighths of the io_uring completion queue the worst-case
        /// in-flight ops may fill (§8). Unlike the pool sizes this is not a
        /// shrink: ⅞ (the compiled default, the fill the ceiling is derived
        /// at) packs the ring tightest, and lowering it reserves more burst
        /// headroom at the cost of a lower feasible conn-slot count. A value
        /// whose ring would exceed the compiled one is rejected at load.
        cq_fill_eighths: u32 = constants.cq_fill_eighths_default,
        /// Bytes per access-log staging buffer, of which there are two
        /// (§8). Larger buys more tolerance for a sink that has stalled,
        /// at a fixed memory cost; smaller drops sooner. **Zero exactly
        /// when the log is off**, which is how `accessLogBytes` reads
        /// "reserves nothing" off this one number rather than needing the
        /// sink beside it. Unlike the pool sizes it may be raised as well
        /// as lowered: it is plain memory, not a share of a budgeted ring.
        access_log_buffer_bytes: u32 = 0,
    };

    pub const Listener = struct {
        bind_address: std.Io.net.IpAddress,
        /// The §7 path-routing table, sorted longest-prefix-first and
        /// never empty. A listener configured with a single `"cluster"`
        /// resolves to one catch-all route (`prefix = "/"`); `l4`
        /// listeners always have exactly that one route (no path to
        /// match). Matched by `http/router.zig`.
        routes: []const router.Route,
        /// The §7 filter rules, in config order (evaluated top-down).
        /// Empty on the L4 path and whenever no `"filters"` were given.
        /// Compiled and interpreted by `http/filter.zig`.
        filters: []const filter.Rule = &.{},
        protocol: Protocol,
        /// How this listener tells the origin who the client is (§7), or
        /// null to leave `X-Forwarded-For` exactly as it arrived — the
        /// behavior every config had before this existed.
        ///
        /// Per *listener*, because the answer depends on what sits in
        /// front of this socket rather than on which backend serves it:
        /// the same cluster may be reachable from an edge listener that
        /// must not trust an inbound chain and an internal one that must.
        forwarded: ?Forwarded = null,
        /// Whether every connection on this listener must open with a
        /// PROXY protocol header announcing the real client (§6, #142),
        /// or null to treat first bytes as payload — the behavior of
        /// every config predating this. Per listener, like `forwarded`
        /// and for the same reason: it states what sits in front of this
        /// socket. `l4` only until the L7 receive phase exists.
        proxy_protocol: ?ProxyProtocol = null,

        /// What the listener speaks (§6, §7): `l4` relays bytes blindly,
        /// `http` runs the HTTP/1.1 reverse-proxy state machine. The
        /// JSON field is optional and defaults to `l4`, so pre-L7
        /// configs stay valid.
        pub const Protocol = enum(u1) {
            l4,
            http,
        };

        /// What to do with an inbound `X-Forwarded-For` (§7). There is no
        /// default and absence means "do nothing", because either answer
        /// is a security bug in the other's position and a proxy cannot
        /// tell from the inside which position it is in.
        pub const Forwarded = enum(u1) {
            /// State the peer this proxy actually observed, discarding
            /// whatever arrived. The correct edge behavior: an inbound
            /// chain is client-controlled there, so honoring it would let
            /// a caller choose the address every downstream allowlist,
            /// rate limiter and audit log then believes.
            replace,
            /// Extend the inbound chain with the observed peer. Correct
            /// only where every hop in front is one you control —
            /// anywhere else it is the forgery above, appended to.
            append,
        };

        /// What a listener expecting PROXY protocol does about it
        /// (#142). One arm today; a closed enum rather than a bool
        /// (`HashKey`'s shape) so a CIDR-gated variant is a new arm
        /// rather than a new mechanism. There is deliberately no arm
        /// that *sniffs*: a listener accepting header-or-raw-bytes lets
        /// any client choose the address that routing (`pick: hash`
        /// keys on `client_address`, §7) and the access log then
        /// believe, which is why the spec forbids it of receivers.
        pub const ProxyProtocol = enum(u1) {
            /// Every connection must open with a valid v1 or v2 header;
            /// anything else is closed. This makes the listener
            /// unusable by anything except the proxy configured in
            /// front of it — that is the point.
            require,
        };
    };

    pub const Cluster = struct {
        name: []const u8,
        endpoints: []const std.Io.net.IpAddress,
        /// The §7 endpoint-pick policy the balancer runs for this
        /// cluster. The JSON field is optional and defaults to `p2c`
        /// (the §7 default), with `rr` kept for strict rotation
        /// (predictable spread, cache warming, pure-L4 clusters whose
        /// load p2c cannot see).
        pick: Pick = .p2c,
        /// §7 active health checks for every endpoint in this cluster,
        /// or null when the cluster is unprobed — probing is opt-in per
        /// cluster, so absent means the balancer never skips anything
        /// here and the prober never dials it.
        check: ?Check = null,
        /// The §8 concurrency cap protecting each of this cluster's
        /// endpoints, or null for uncapped. **Per endpoint, not per
        /// cluster**: it is a statement about what one origin can carry,
        /// the same unit HAProxy's `server ... maxconn` names, so a
        /// cluster's total admitted work is this times its endpoint
        /// count. Counted against the endpoint's in-flight total —
        /// L7 requests and live L4 connections alike (§7).
        max_inflight: ?u32 = null,

        /// What a `hash` cluster keys its endpoint choice on (§7). Read
        /// only when `pick == .hash`; the loader rejects a `hash` block
        /// beside any other policy rather than leaving it inert.
        hash_key: HashKey = .source_ip,

        pub const Pick = enum(u2) {
            rr,
            p2c,
            /// Rendezvous hashing (§7): the same key always lands on the
            /// same endpoint, so a client reaches one stateful backend
            /// across connections — and, because the answer is a pure
            /// function of the key and the eligible set, every process
            /// behind SO_REUSEPORT computes it identically with nothing
            /// shared (§3).
            hash,
        };

        /// The identity a `hash` cluster is sticky on. One arm today; a
        /// closed enum rather than a bool so a request-derived key (a
        /// header, a cookie) is a new arm rather than a new mechanism.
        pub const HashKey = enum(u1) {
            /// The client's own address, which both data paths have —
            /// an L4 connection has nothing else, and an L7 request need
            /// not have been parsed yet.
            source_ip,
        };

        /// One cluster's resolved check policy (§7). Every field is
        /// settled at load: the thresholds, the per-probe budget, and —
        /// for an HTTP check — the exact request to send and the status
        /// that passes. Nothing here is decided on the loop.
        pub const Check = struct {
            /// What a probe proves. `tcp` proves the port accepts;
            /// `http` proves the application answered a chosen path with
            /// a chosen status, which a SYN/ACK cannot.
            kind: Kind = .tcp,
            /// Consecutive failures that eject, successes that restore.
            fall: u8 = constants.health_probe_fall_default,
            rise: u8 = constants.health_probe_rise_default,
            /// Budget for one whole probe — the dial for a `tcp` check,
            /// and dial + request + response for an `http` one. Defaults
            /// to `connect_timeout_ms`: a probe is at least a dial, and
            /// an operator who has tuned that has said what a
            /// too-slow origin looks like.
            timeout_ms: u32,
            /// The rest is meaningful only when `kind == .http`, and the
            /// loader rejects it otherwise rather than leaving dead
            /// fields to be misread.
            http: ?Http = null,

            pub const Kind = enum(u1) {
                tcp,
                http,
            };

            pub const Http = struct {
                /// Canonical origin-form path, validated at load exactly
                /// like a route prefix — the probe sends it verbatim.
                path: []const u8,
                /// `Host` value. Null means the endpoint's own literal,
                /// which is what a non-vhosted origin expects; a name
                /// here is what makes a vhosted origin probeable.
                host: ?[]const u8 = null,
                /// The one status that passes. A single value, not a
                /// class: an endpoint that answers 200 today and 302
                /// tomorrow has changed its meaning, and a check that
                /// shrugged at that would be reporting the wrong thing.
                expect_status: u16 = 200,
            };
        };
    };
};

pub const ValidationError = error{
    ListenersEmpty,
    ListenersOverLimit,
    ListenerBindInvalid,
    ListenerBindDuplicate,
    ListenerProtocolUnknown,
    ClusterUnknown,
    ClustersEmpty,
    ClustersOverLimit,
    ClusterNameDuplicate,
    ClusterNameEmpty,
    ClusterNameTooLong,
    ClusterPickUnknown,
    ClusterCheckTypeUnknown,
    ClusterCheckThresholdOutOfRange,
    ClusterCheckTimeoutOutOfRange,
    ClusterCheckHttpFieldOnTcp,
    ClusterCheckPathMissing,
    ClusterCheckPathTooLong,
    ClusterCheckPathNotCanonical,
    ClusterCheckHostInvalid,
    ClusterCheckStatusInvalid,
    ClusterMaxInflightOutOfRange,
    ClusterHashKeyUnknown,
    ClusterHashWithoutHashPick,
    ListenerClusterOrRoutes,
    ListenerL4Routes,
    RoutesEmpty,
    RoutePrefixNotCanonical,
    RouteHostNotCanonical,
    RouteDuplicate,
    ListenerL4Filters,
    ListenerL4Forwarded,
    ListenerForwardedModeUnknown,
    ListenerHttpProxyProtocol,
    ListenerProxyProtocolModeUnknown,
    FilterMethodEmpty,
    FilterMethodUnknown,
    FilterHeaderMatchKind,
    FilterHeaderContainsEmpty,
    FilterHeaderNameInvalid,
    FilterHeaderNameReserved,
    FilterHeaderValueInvalid,
    FilterActionsEmpty,
    FilterActionKind,
    FilterRejectStatus,
    FilterHeaderEditsOverLimit,
    EndpointsEmpty,
    EndpointsOverLimit,
    EndpointInvalid,
    EndpointPortZero,
    TimeoutZero,
    TimeoutOverLimit,
    TimeoutOrderInvalid,
    LimitConnSlotsOutOfRange,
    LimitRelayBuffersOutOfRange,
    LimitRelayBuffersOverConnSlots,
    LimitUpstreamSlotsOutOfRange,
    LimitHeadBuffersOutOfRange,
    LimitHeadBuffersOverConnSlots,
    LimitHeadBuffersWithoutHttpListener,
    LimitUpstreamHeadBuffersOutOfRange,
    LimitUpstreamHeadBuffersOverUpstreamSlots,
    LimitUpstreamHeadBuffersWithoutHttpListener,
    LimitHeadBufferBytesOutOfRange,
    LimitCqFillOutOfRange,
    LimitConnSlotsOverCqFill,
    LimitAccessLogBufferOutOfRange,
    LimitAccessLogBufferWithoutSink,
    AdminBindInvalid,
    AccessLogSinkUnknown,
    AccessLogPathMissing,
    AccessLogPathOnStdout,
};

pub const ParseError = std.json.ParseError(std.json.Scanner) || ValidationError;

pub fn parse(arena: std.mem.Allocator, json_bytes: []const u8) ParseError!Config {
    const parsed = try std.json.parseFromSliceLeaky(ConfigJson, arena, json_bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
    });

    // Timeouts first: a cluster's check budget defaults to the connect
    // timeout, so that value must already be known to be in range before
    // any check inherits it.
    try validateTimeouts(&parsed.timeouts);
    const clusters = try resolveClusters(arena, &parsed.clusters, parsed.timeouts.connect_ms);
    // Limits resolve before listeners, off the raw DTO counts: the route
    // prefixes inside `resolveListeners` are gated against the resolved
    // `head_buffer_bytes` — a prefix longer than the head can never
    // match a parsed path, and belongs refused at load, not left to 404
    // forever at runtime. The reorder moves precedences, pinned by
    // tests: emptiness still outranks everything after the clusters
    // (the limits resolver asserts a non-empty set, so the gate fires
    // first here); a bad protocol string surfaces from the count below —
    // before any bind or sink is looked at; and a bad bind, resolved
    // last, now reports after a bad access-log sink.
    if (parsed.listeners.len == 0) {
        return error.ListenersEmpty;
    }
    var http_listeners_count: u32 = 0;
    for (parsed.listeners) |listener_json| {
        if (try protocolOf(listener_json.protocol) == .http) http_listeners_count += 1;
    }
    const access_log_sink = try resolveAccessLogSink(parsed.access_log);
    const limits = try resolveLimits(
        &parsed.limits,
        @intCast(parsed.listeners.len),
        http_listeners_count,
        access_log_sink != null,
    );
    const listeners = try resolveListeners(arena, parsed.listeners, clusters, limits.head_buffer_bytes);
    const admin_bind = try resolveAdminBind(parsed.admin);

    assert(listeners.len >= 1);
    assert(clusters.len >= 1);
    return .{
        .listeners = listeners,
        .clusters = clusters,
        .connect_timeout_ms = parsed.timeouts.connect_ms,
        .idle_timeout_ms = parsed.timeouts.idle_ms,
        .drain_deadline_ms = parsed.timeouts.drain_deadline_ms,
        .max_lifetime_ms = parsed.timeouts.max_lifetime_ms,
        .request_timeout_ms = parsed.timeouts.request_ms,
        .health_interval_ms = parsed.timeouts.health_interval_ms,
        .limits = limits,
        .admin_bind = admin_bind,
        .access_log_sink = access_log_sink,
    };
}

/// Resolve the optional access log (§8): absent means off — no staging
/// buffers reserved, no lines emitted. A present block names its sink from
/// a closed set, so an unknown value fails at load rather than silently
/// logging somewhere the operator did not ask for; `path` is required by
/// exactly the sink that uses it. Both mismatches are rejected, not
/// ignored — the `ClusterCheckHttpFieldOnTcp` rule, one block over: a
/// field the named sink cannot honor describes a config the operator
/// misread, and this proxy does not start on those.
fn resolveAccessLogSink(
    access_log_json: ?AccessLogJson,
) ValidationError!?Config.AccessLogSink {
    const access_log = access_log_json orelse return null;
    const kind = std.meta.stringToEnum(Config.AccessLogSinkKind, access_log.sink) orelse
        return error.AccessLogSinkUnknown;
    switch (kind) {
        .stdout => {
            if (access_log.path != null) return error.AccessLogPathOnStdout;
            return .stdout;
        },
        .file => {
            const path = access_log.path orelse return error.AccessLogPathMissing;
            // Empty is missing, not "a file named nothing": openat would
            // reject it later and worse — at startup's end, not load time.
            if (path.len == 0) return error.AccessLogPathMissing;
            // The postcondition `openLogSinkFd` (main) leans on.
            assert(path.len >= 1);
            return .{ .file = path };
        },
    }
}

/// Resolve the optional admin/metrics listener (§8):
/// absent means the plane is off; a present `bind` must be a static IP:port
/// literal (hostnames rejected, like every other bind — DNS is a non-goal).
fn resolveAdminBind(admin_json: ?AdminJson) ValidationError!?std.Io.net.IpAddress {
    const admin = admin_json orelse return null;
    return std.Io.net.IpAddress.parseLiteral(admin.bind) catch error.AdminBindInvalid;
}

/// Resolve the effective pool sizes (§5, §8): the comptime constants are
/// the hard, budget-asserted ceilings — config may only shrink below
/// them, never grow past them, and never to zero. An unspecified
/// relay-buffer count derives from the effective conn slots (a buffer
/// beyond the slot count could never be acquired); a *specified* count
/// above them is a contradiction and fails loudly.
fn resolveLimits(
    limits_json: *const LimitsJson,
    listeners_count: u32,
    http_listeners_count: u32,
    access_log_on: bool,
) ValidationError!Config.Limits {
    assert(listeners_count >= 1);
    assert(http_listeners_count <= listeners_count);
    // Omitted limits default to the lean out-of-box sizes, not the
    // compiled ceilings (§5): a small footprint unless the operator opts
    // up. relay buffers still follow conn slots when omitted (one buffer
    // per L4 connection), capped at their own ceiling.
    const conn_slots = limits_json.conn_slots orelse constants.conn_slots_default;
    if (conn_slots < 1 or conn_slots > constants.conn_slots_max) {
        return error.LimitConnSlotsOutOfRange;
    }
    const relay_buffers = limits_json.relay_buffers orelse
        @min(constants.relay_buffers_max, conn_slots);
    if (relay_buffers < 1 or relay_buffers > constants.relay_buffers_max) {
        return error.LimitRelayBuffersOutOfRange;
    }
    if (relay_buffers > conn_slots) {
        return error.LimitRelayBuffersOverConnSlots;
    }
    const upstream_slots = limits_json.upstream_slots orelse constants.upstream_slots_default;
    if (upstream_slots < 1 or upstream_slots > constants.upstream_slots_max) {
        return error.LimitUpstreamSlotsOutOfRange;
    }
    const head_buffers = try resolveHeadBuffers(
        limits_json.head_buffers,
        conn_slots,
        http_listeners_count,
    );
    const upstream_head_buffers = try resolveUpstreamHeadBuffers(
        limits_json.upstream_head_buffers,
        upstream_slots,
        http_listeners_count,
    );
    const head_buffer_bytes = try resolveHeadBufferBytes(limits_json.head_buffer_bytes);
    // The CQ fill is the one limit an operator tightens for headroom, not a
    // pool shrink (§8): a smaller fill demands a deeper ring for the same
    // conn slots. Range-check first, then reject a fill that — with these
    // conn/upstream slots and listeners — would need a completion queue past
    // the compiled ring, so main.zig's completionQueueDepthFor never clamps.
    const cq_fill_eighths = limits_json.cq_fill_eighths orelse constants.cq_fill_eighths_default;
    if (cq_fill_eighths < constants.cq_fill_eighths_min or cq_fill_eighths > constants.cq_fill_eighths_max) {
        return error.LimitCqFillOutOfRange;
    }
    if (!constants.cqFillFits(conn_slots, upstream_slots, listeners_count, cq_fill_eighths)) {
        return error.LimitConnSlotsOverCqFill;
    }
    // Zero exactly when the log is off, so the one number says both how
    // big the staging buffers are and whether there are any (§8). A
    // deployment that sized the buffers but never named a sink has asked
    // for something contradictory, and is told so rather than quietly
    // getting no log.
    const access_log_buffer_bytes = try resolveAccessLogBuffer(
        limits_json.access_log_buffer_bytes,
        access_log_on,
    );
    assert(relay_buffers <= conn_slots);
    assert(head_buffers <= conn_slots);
    return .{
        .conn_slots = conn_slots,
        .relay_buffers = relay_buffers,
        .upstream_slots = upstream_slots,
        .head_buffers = head_buffers,
        .upstream_head_buffers = upstream_head_buffers,
        .head_buffer_bytes = head_buffer_bytes,
        .cq_fill_eighths = cq_fill_eighths,
        .access_log_buffer_bytes = access_log_buffer_bytes,
    };
}

/// The §5 head-buffer ring follows conn slots when omitted (every
/// connection could be mid-head at once — never sheds), and is zero
/// exactly when no listener speaks http: an L4-only deployment registers
/// no ring, and one that asked for buffers it cannot use is told so. A
/// ring an http deployment cannot bind from (zero) would shed every
/// request, so that is rejected too, not defaulted around.
fn resolveHeadBuffers(
    requested: ?u32,
    conn_slots: u32,
    http_listeners_count: u32,
) ValidationError!u32 {
    assert(conn_slots >= 1);
    const head_buffers = requested orelse
        (if (http_listeners_count >= 1) conn_slots else 0);
    if (head_buffers > conn_slots) {
        return error.LimitHeadBuffersOverConnSlots;
    }
    if (http_listeners_count == 0 and head_buffers >= 1) {
        return error.LimitHeadBuffersWithoutHttpListener;
    }
    if (http_listeners_count >= 1 and head_buffers == 0) {
        return error.LimitHeadBuffersOutOfRange;
    }
    assert(head_buffers <= conn_slots);
    return head_buffers;
}

/// The §5 upstream head pool, on `resolveHeadBuffers`'s exact terms with
/// upstream slots as the ceiling: a leased slot never needs more than one
/// head, so more heads than slots is waste stated as intent.
fn resolveUpstreamHeadBuffers(
    requested: ?u32,
    upstream_slots: u32,
    http_listeners_count: u32,
) ValidationError!u32 {
    assert(upstream_slots >= 1);
    const upstream_head_buffers = requested orelse
        (if (http_listeners_count >= 1) upstream_slots else 0);
    if (upstream_head_buffers > upstream_slots) {
        return error.LimitUpstreamHeadBuffersOverUpstreamSlots;
    }
    if (http_listeners_count == 0 and upstream_head_buffers >= 1) {
        return error.LimitUpstreamHeadBuffersWithoutHttpListener;
    }
    if (http_listeners_count >= 1 and upstream_head_buffers == 0) {
        return error.LimitUpstreamHeadBuffersOutOfRange;
    }
    assert(upstream_head_buffers <= upstream_slots);
    return upstream_head_buffers;
}

/// The head-buffer size (§5): a plain range, unlike its two count
/// siblings — the size is a property of the pools and of the health
/// prober's buffer, so it needs no http-listener coupling; an L4-only
/// config's value still sizes the prober. The floor is behaviour, not
/// memory: below it ordinary requests start dying as 414/431.
fn resolveHeadBufferBytes(requested: ?u32) ValidationError!u32 {
    const head_buffer_bytes = requested orelse constants.head_buffer_bytes_default;
    if (head_buffer_bytes < constants.head_buffer_bytes_min or
        head_buffer_bytes > constants.head_buffer_bytes_max)
    {
        return error.LimitHeadBufferBytesOutOfRange;
    }
    assert(head_buffer_bytes >= constants.head_buffer_bytes_min);
    assert(head_buffer_bytes <= constants.head_buffer_bytes_max);
    return head_buffer_bytes;
}

fn resolveAccessLogBuffer(
    requested: ?u32,
    access_log_on: bool,
) ValidationError!u32 {
    if (!access_log_on) {
        if (requested != null) return error.LimitAccessLogBufferWithoutSink;
        return 0;
    }
    const bytes = requested orelse constants.access_log_buffer_bytes_default;
    if (bytes < constants.access_log_buffer_bytes_min or
        bytes > constants.access_log_buffer_bytes_max)
    {
        return error.LimitAccessLogBufferOutOfRange;
    }
    return bytes;
}

// The strict parser binds JSON to these `*Json` DTOs. Each carries the
// schema metadata reflection cannot infer — prose (`schema_doc`, per-field
// `.desc`), closed vocabularies (`.enum_type`, `.int_values`, `.items`),
// and numeric bounds (`.minimum`/`.maximum`/`.min_items`/…) — co-located
// with the fields so the two never drift. `assert_meta_matches` (below)
// cross-checks metadata against the real fields at comptime, and
// `config_schema.zig` walks the same DTOs to emit the JSON Schema. Public
// so the emitter and its tests can reflect over the real wire shape.
pub const ConfigJson = struct {
    /// Editor hint only: the URL of the JSON Schema this file claims to
    /// follow (`$id` in the emitted document). Declared so an editor may add
    /// it for completion and validation without the loader rejecting the
    /// file; parsed, never read. Strictness is unharmed — a near miss like
    /// `$schemas` is still an unknown field.
    @"$schema": ?[]const u8 = null,
    listeners: []const ListenerJson,
    clusters: ClustersJson,
    /// Optional as a whole, like `limits` below and for the same reason
    /// (§5): an omitted block takes the defaults, so a working config is
    /// a listener and a cluster, and tuning is what an operator opts
    /// into.
    timeouts: TimeoutsJson = .{},
    /// Optional pool sizes and the CQ-fill headroom knob (§5, §8); absent
    /// fields take the lean defaults, not the compiled ceilings.
    limits: LimitsJson = .{},
    /// Optional admin/metrics listener (§8); absent
    /// leaves the plane off.
    admin: ?AdminJson = null,
    /// Optional access log (§8); absent leaves it off.
    access_log: ?AccessLogJson = null,

    pub const schema_doc =
        "Startup config for the zoxy L4/L7 proxy. Encodes structure, enums, " ++
        "and numeric bounds; semantic checks (canonical route prefixes/hosts, " ++
        "IP:port literal parsing, reserved header names, endpoint port != 0) " ++
        "are enforced by the loader and are not expressible in JSON Schema.";
    pub const schema_fields = .{
        .@"$schema" = .{
            .desc = "URL of the JSON Schema this config follows; an editor hint, ignored by the loader.",
        },
        .listeners = .{
            .desc = "Sockets the proxy accepts connections on.",
            .min_items = 1,
        },
        .clusters = .{ .desc = "Named upstream clusters, keyed by cluster name." },
        .timeouts = .{ .desc = "Connection lifecycle deadlines (milliseconds)." },
        .limits = .{ .desc = "Optional pool sizes and the CQ-fill headroom knob; absent fields take the lean defaults." },
        .admin = .{ .desc = "Optional admin/metrics listener; absent leaves it off." },
        .access_log = .{ .desc = "Optional per-request/per-connection JSON access log; absent leaves it off." },
    };
};

pub const AccessLogJson = struct {
    sink: []const u8,
    path: ?[]const u8 = null,

    pub const schema_doc =
        "Optional access log. When present, zoxy writes one JSON object per " ++
        "line for every HTTP exchange and every L4 connection; absent leaves " ++
        "it off and reserves nothing. Lines are dropped, and counted, rather " ++
        "than allowed to block the event loop when the sink cannot keep up.";
    pub const schema_fields = .{
        .sink = .{
            .desc = "Where lines are written. `stdout` is the process's own standard " ++
                "output; `file` appends to `path`.",
            .enum_type = Config.AccessLogSinkKind,
        },
        .path = .{
            .desc = "File the `file` sink appends to: created if absent, opened " ++
                "append-only at startup (one extra fd), never truncated — so a " ++
                "copy-truncate rotation is safe. Required by `sink:\"file\"`, " ++
                "rejected beside `stdout`, which cannot use it.",
        },
    };
};

pub const AdminJson = struct {
    bind: []const u8,

    pub const schema_doc =
        "Optional admin/metrics listener. When present, exposes the process " ++
        "counters as Prometheus exposition text on `bind`; absent leaves it off.";
    pub const schema_fields = .{
        .bind = .{ .desc = "IP:port literal to bind the admin/metrics listener (hostnames are rejected)." },
    };
};

pub const LimitsJson = struct {
    conn_slots: ?u32 = null,
    relay_buffers: ?u32 = null,
    upstream_slots: ?u32 = null,
    head_buffers: ?u32 = null,
    upstream_head_buffers: ?u32 = null,
    head_buffer_bytes: ?u32 = null,
    cq_fill_eighths: ?u32 = null,
    access_log_buffer_bytes: ?u32 = null,

    pub const schema_doc =
        "Optional pool sizes and the CQ-fill headroom knob; absent fields " ++
        "take the lean defaults. Pools may only shrink below their ceilings; " ++
        "cq_fill_eighths trades ceiling for burst headroom, never a pool size.";
    pub const schema_fields = .{
        .conn_slots = .{
            .desc = "Concurrent connection slots.",
            .minimum = 1,
            .maximum = constants.conn_slots_max,
        },
        .relay_buffers = .{
            .desc = "Relay buffer pairs (bounds concurrent L4 and L7 body relays).",
            .minimum = 1,
            .maximum = constants.relay_buffers_max,
        },
        .upstream_slots = .{
            .desc = "Shared upstream connection slots.",
            .minimum = 1,
            .maximum = constants.upstream_slots_max,
        },
        .head_buffers = .{
            .desc = "HTTP head buffers in the shared ring (bounds request heads " ++
                "in flight; idle keep-alive connections hold none). Defaults " ++
                "to conn_slots; must be 1..conn_slots with an http listener, " ++
                "0 without one.",
            .minimum = 0,
            .maximum = constants.conn_slots_max,
        },
        .upstream_head_buffers = .{
            .desc = "Upstream head buffers (bounds exchanges in their head " ++
                "phase; parked origin connections hold none). Defaults to " ++
                "upstream_slots; must be 1..upstream_slots with an http " ++
                "listener, 0 without one.",
            .minimum = 0,
            .maximum = constants.upstream_slots_max,
        },
        .head_buffer_bytes = .{
            .desc = "Bytes per head buffer in both head pools — the largest " ++
                "HTTP head accepted (oversize requests get 414/431). May be " ++
                "raised for big-cookie/JWT traffic as well as lowered.",
            .minimum = constants.head_buffer_bytes_min,
            .maximum = constants.head_buffer_bytes_max,
        },
        .cq_fill_eighths = .{
            .desc = "Eighths of the io_uring completion queue the worst-case " ++
                "in-flight ops may fill; lower reserves more burst headroom " ++
                "but lowers the feasible connection-slot ceiling.",
            .minimum = constants.cq_fill_eighths_min,
            .maximum = constants.cq_fill_eighths_max,
        },
        .access_log_buffer_bytes = .{
            .desc = "Bytes per access-log staging buffer, of which there are two; " ++
                "larger tolerates a slower sink before lines are dropped. " ++
                "Only valid alongside an `access_log` block.",
            .minimum = constants.access_log_buffer_bytes_min,
            .maximum = constants.access_log_buffer_bytes_max,
        },
    };
};

pub const ListenerJson = struct {
    bind: []const u8,
    /// Exactly one of `cluster` (sugar for a single catch-all route) or
    /// `routes` (an explicit §7 path table) must be present.
    cluster: ?[]const u8 = null,
    routes: ?[]const RouteJson = null,
    /// Optional §7 filter rules; absent means none. HTTP-only.
    filters: ?[]const FilterJson = null,
    /// Optional: absent means `l4`, keeping pre-L7 configs valid.
    protocol: []const u8 = "l4",
    /// Optional §7 client-address forwarding; absent leaves the header
    /// untouched. HTTP-only — an l4 relay has no header to carry it.
    forwarded: ?ForwardedJson = null,
    /// Optional PROXY protocol expectation (#142); absent treats first
    /// bytes as payload. L4-only until the L7 receive phase exists.
    proxy_protocol: ?ProxyProtocolJson = null,

    pub const schema_doc =
        "One accepting socket. Exactly one of `cluster` or `routes` selects " ++
        "the upstream — that fork is enforced by the loader, not this schema.";
    pub const schema_fields = .{
        .bind = .{ .desc = "IP:port literal to bind (hostnames are rejected — DNS is a non-goal)." },
        .cluster = .{ .desc = "Sugar for a single catch-all route to this cluster; mutually exclusive with routes." },
        .routes = .{
            .desc = "Explicit longest-prefix route table (http listeners only).",
            .min_items = 1,
        },
        .filters = .{
            .desc = "Request filter rules, evaluated top-down (http listeners only).",
        },
        .protocol = .{
            .desc = "What the listener speaks: l4 relays bytes blindly, http runs the reverse-proxy state machine.",
            .enum_type = Config.Listener.Protocol,
        },
        .forwarded = .{
            .desc = "Tell the origin the client's address via X-Forwarded-For " ++
                "(http listeners only); absent leaves the header untouched.",
        },
        .proxy_protocol = .{
            .desc = "Expect a PROXY protocol header (v1 or v2) ahead of every " ++
                "connection's payload (l4 listeners only); absent treats first " ++
                "bytes as payload.",
        },
    };
};

pub const ForwardedJson = struct {
    mode: []const u8,

    pub const schema_doc =
        "How this listener sets `X-Forwarded-For`. There is no default, " ++
        "because `replace` and `append` are each a security bug in the " ++
        "other's position: an inbound chain is client-controlled at the " ++
        "edge and authoritative behind a proxy you own, and zoxy cannot " ++
        "tell from the inside which side of that line it is on.";
    pub const schema_fields = .{
        .mode = .{
            .desc = "replace: state the observed peer, discarding any inbound chain " ++
                "(use at the edge). append: extend the inbound chain with the observed " ++
                "peer (use only when every hop in front is trusted).",
            .enum_type = Config.Listener.Forwarded,
        },
    };
};

pub const ProxyProtocolJson = struct {
    mode: []const u8,

    pub const schema_doc =
        "Whether this listener expects the proxy in front of it to announce " ++
        "each client with a PROXY protocol header. There is no sniffing mode " ++
        "— accepting a header only when one shows up would let any client " ++
        "pick the address that routing and logging then believe — and `mode` " ++
        "is stated even with one value today, so future modes extend a " ++
        "vocabulary rather than change what absence means.";
    pub const schema_fields = .{
        .mode = .{
            .desc = "require: every connection must open with a valid v1 or v2 " ++
                "header; anything else is closed. Only meaningful when the " ++
                "listener is reachable exclusively through the fronting proxy.",
            .enum_type = Config.Listener.ProxyProtocol,
        },
    };
};

pub const FilterJson = struct {
    match: MatchJson = .{},
    actions: []const ActionJson,

    pub const schema_doc = "One filter rule: a match predicate and the actions applied when it matches.";
    pub const schema_fields = .{
        .match = .{ .desc = "Match predicate; absent fields match anything." },
        .actions = .{
            .desc = "Actions applied in order when the rule matches.",
            .min_items = 1,
        },
    };
};

pub const MatchJson = struct {
    /// Registered method tokens (uppercase); absent = any method.
    method: ?[]const []const u8 = null,
    host: ?[]const u8 = null,
    path_prefix: ?[]const u8 = null,
    headers: ?[]const HeaderMatchJson = null,

    pub const schema_doc = "Request-match predicate; every absent field matches anything.";
    pub const schema_fields = .{
        .method = .{
            .desc = "Registered request-method tokens; absent matches any method.",
            .min_items = 1,
            .items = SchemaItems.http_method,
        },
        .host = .{ .desc = "Canonical host to match; absent matches any host." },
        .path_prefix = .{ .desc = "Canonical origin-form path prefix; must start with a slash." },
        .headers = .{
            .desc = "Header predicates; all must match.",
        },
    };
};

pub const HeaderMatchJson = struct {
    name: []const u8,
    /// Exactly one of these selects the predicate kind.
    present: ?bool = null,
    equals: ?[]const u8 = null,
    contains: ?[]const u8 = null,

    pub const schema_doc =
        "One header predicate. Exactly one of `present`/`equals`/`contains` " ++
        "selects the kind — that fork is enforced by the loader.";
    pub const schema_fields = .{
        .name = .{ .desc = "Header field name (matched case-insensitively)." },
        .present = .{
            .desc = "Matches when the header is present (present: false is rejected).",
            .const_true = true,
        },
        .equals = .{ .desc = "Matches when the header value equals this string." },
        .contains = .{
            .desc = "Matches when the header value contains this substring.",
            .min_length = 1,
        },
    };
};

/// One action object carries exactly one field (the action's kind), the
/// same "struct of optionals, validate exactly-one" shape the listener's
/// cluster/routes fork uses — no JSON union parsing.
pub const ActionJson = struct {
    reject: ?u16 = null,
    header_set: ?HeaderEditJson = null,
    header_add: ?HeaderEditJson = null,
    header_remove: ?[]const u8 = null,
    rewrite_prefix: ?RewriteJson = null,

    pub const schema_doc =
        "One filter action. Exactly one field is set — the action's kind — " ++
        "and that fork is enforced by the loader.";
    pub const schema_fields = .{
        .reject = .{
            .desc = "Reject the request with this status code.",
            .int_values = &filter.reject_statuses,
        },
        .header_set = .{ .desc = "Set (replace) a request header." },
        .header_add = .{ .desc = "Append a request header." },
        .header_remove = .{ .desc = "Remove a request header by name." },
        .rewrite_prefix = .{ .desc = "Rewrite the request path prefix before proxying." },
    };
};

pub const HeaderEditJson = struct {
    name: []const u8,
    value: []const u8,

    pub const schema_doc = "A header name/value pair for header_set / header_add.";
    pub const schema_fields = .{
        .name = .{ .desc = "Header field name." },
        .value = .{ .desc = "Header field value." },
    };
};

pub const RewriteJson = struct {
    from: []const u8,
    to: []const u8,

    pub const schema_doc = "A path-prefix rewrite: strip `from`, prepend `to`.";
    pub const schema_fields = .{
        .from = .{ .desc = "Canonical path prefix to strip; must start with a slash." },
        .to = .{ .desc = "Canonical path prefix to prepend; must start with a slash." },
    };
};

pub const RouteJson = struct {
    /// Optional §7 host scope; absent means the route matches any host.
    host: ?[]const u8 = null,
    prefix: []const u8,
    cluster: []const u8,

    pub const schema_doc = "One longest-prefix route entry.";
    pub const schema_fields = .{
        .host = .{ .desc = "Canonical host scope; absent matches any host." },
        .prefix = .{ .desc = "Canonical origin-form path prefix; must start with a slash." },
        .cluster = .{ .desc = "Name of the cluster matching requests route to." },
    };
};

pub const ClusterJson = struct {
    endpoints: []const []const u8,
    /// Optional §7 pick policy; absent means `p2c` (the design's
    /// trajectory), `rr` opts back into strict rotation.
    pick: []const u8 = "p2c",
    /// Optional §7 active health checks; absent means off, so an
    /// unprobed cluster reserves nothing and is never skipped.
    check: ?CheckJson = null,
    /// Optional §8 per-endpoint concurrency cap; absent means uncapped.
    max_inflight: ?u32 = null,
    /// Optional §7 hash-policy detail; only valid beside `"pick": "hash"`,
    /// and absent there means the default key.
    hash: ?ClusterHashJson = null,

    pub const schema_doc = "One upstream cluster: its endpoints, pick policy and health checks.";
    pub const schema_fields = .{
        .endpoints = .{
            .desc = "IP:port endpoint literals (port must be non-zero).",
            .min_items = 1,
        },
        .pick = .{
            .desc = "Endpoint-pick policy: p2c (power-of-two-choices), rr (strict " ++
                "round-robin), or hash (rendezvous hashing on a stable key, for " ++
                "client-to-backend stickiness).",
            .enum_type = Config.Cluster.Pick,
        },
        .check = .{
            .desc = "Active health checks for every endpoint in this cluster; absent leaves them off.",
        },
        .hash = .{
            .desc = "Hash-policy detail; only valid alongside \"pick\": \"hash\".",
        },
        .max_inflight = .{
            .desc = "Cap on concurrent in-flight work per endpoint; absent leaves the cluster uncapped.",
            .minimum = 1,
            .maximum = constants.endpoint_inflight_max,
        },
    };
};

/// One cluster's health-check block (§7). `type` picks what a probe
/// proves; the `http` fields are rejected under `tcp` rather than
/// ignored, so a config cannot quietly describe a check it is not
/// running.
pub const CheckJson = struct {
    type: []const u8 = "tcp",
    /// Thresholds, HAProxy's `fall`/`rise`.
    fall: u8 = constants.health_probe_fall_default,
    rise: u8 = constants.health_probe_rise_default,
    /// Budget for one whole probe; absent means `timeouts.connect_ms`.
    timeout_ms: ?u32 = null,
    /// Required for `http`, rejected for `tcp`.
    path: ?[]const u8 = null,
    /// `Host` for an `http` probe; absent sends the endpoint literal.
    host: ?[]const u8 = null,
    expect_status: u16 = 200,

    pub const schema_doc = "Active health checks for a cluster's endpoints.";
    pub const schema_fields = .{
        .type = .{
            .desc = "What a probe proves: tcp (the port accepts) or http (a path answered the expected status).",
            .enum_type = Config.Cluster.Check.Kind,
        },
        .fall = .{
            .desc = "Consecutive failed probes that eject an endpoint from balancing.",
            .minimum = 1,
            .maximum = constants.health_probe_threshold_max,
        },
        .rise = .{
            .desc = "Consecutive successful probes that restore an ejected endpoint.",
            .minimum = 1,
            .maximum = constants.health_probe_threshold_max,
        },
        .timeout_ms = .{
            .desc = "Budget for one whole probe; absent uses timeouts.connect_ms.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
        .path = .{
            .desc = "Canonical origin-form path an http probe requests; required for http, rejected for tcp.",
            .min_length = 1,
        },
        .host = .{
            .desc = "Host header an http probe sends; absent sends the endpoint's own IP:port literal.",
            .min_length = 1,
        },
        .expect_status = .{
            .desc = "The one response status an http probe accepts as healthy.",
            .minimum = 100,
            .maximum = 599,
        },
    };
};

pub const ClusterHashJson = struct {
    key: []const u8 = "source_ip",

    pub const schema_doc =
        "How a `hash` cluster identifies a client. The same key always " ++
        "selects the same endpoint, and the mapping is a pure function of " ++
        "the key and the healthy endpoint set — so every zoxy process " ++
        "behind SO_REUSEPORT agrees without sharing any state.";
    pub const schema_fields = .{
        .key = .{
            .desc = "What to hash. `source_ip` uses the client address: all four " ++
                "bytes of an IPv4 address, and the /64 prefix of an IPv6 one so " ++
                "stickiness survives privacy-address rotation (RFC 8981).",
            .enum_type = Config.Cluster.HashKey,
        },
    };
};

pub const TimeoutsJson = struct {
    /// Optional: nginx ships 60 s for the same budget and HAProxy's
    /// `timeout connect` is conventionally single-digit seconds, so a
    /// value zoxy can pick without guessing at anyone's policy. Zero
    /// stays rejected — it would fail every dial before it left.
    connect_ms: u32 = constants.connect_ms_default,
    /// Optional, same argument: nginx's `keepalive_timeout` is 75 s and
    /// its `client_header_timeout` 60 s. Zero would reap on arrival, and a
    /// value at or below `connect_ms` is rejected — the dial's handoff
    /// cannot shorten a timer that is already counting down (§4/§5).
    idle_ms: u32 = constants.idle_ms_default,
    /// Optional, and `0` means "no cap" — the drain waits for the last
    /// connection however long that takes (§8).
    ///
    /// Unlike the two above there is no convention to borrow: nginx,
    /// HAProxy and Caddy all default to waiting indefinitely, while
    /// Traefik picks 10 s and Envoy 600 s. A sixty-fold spread across
    /// mature implementations is not a default waiting to be discovered,
    /// so zoxy declines to invent one and joins the majority. The
    /// supervisor that sent the signal already owns the upper bound and
    /// enforces it with SIGKILL; an operator who wants zoxy to give up
    /// sooner than their platform does sets a number here.
    drain_deadline_ms: u32 = 0,
    /// Optional: absent or `0` means "no cap" (§6). The default keeps every
    /// pre-existing config valid and leaves max-lifetime opt-in.
    max_lifetime_ms: u32 = 0,
    /// Optional, same shape: absent or `0` means "no cap" (§8). Opt-in
    /// because a request deadline is a policy an operator sets against
    /// their own origin's latency, not a value zoxy can pick for them.
    request_ms: u32 = 0,
    /// Optional §7 health-probe pacing; absent means HAProxy's `inter`
    /// default. Unlike the two caps above, zero is rejected: probing is
    /// switched per cluster (`check`), never by zeroing its interval.
    health_interval_ms: u32 = constants.health_interval_ms_default,

    pub const schema_doc = "Connection lifecycle deadlines, in milliseconds.";
    pub const schema_fields = .{
        .connect_ms = .{
            .desc = "Per-try upstream connect budget.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
        .idle_ms = .{
            .desc = "Idle / head-read deadline; must exceed connect_ms.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
        .drain_deadline_ms = .{
            .desc = "Graceful-drain deadline on shutdown; 0 waits indefinitely.",
            .minimum = 0,
            .maximum = constants.timeout_ms_max,
        },
        .max_lifetime_ms = .{
            .desc = "Absolute connection-age cap; 0 disables it.",
            .minimum = 0,
            .maximum = constants.timeout_ms_max,
        },
        .request_ms = .{
            .desc = "Cap on one L7 exchange, not refreshed by activity; 0 disables it.",
            .minimum = 0,
            .maximum = constants.timeout_ms_max,
        },
        .health_interval_ms = .{
            .desc = "Pause between health-probe sweeps over checked clusters.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
    };
};

/// JSON object map of cluster name → cluster, parsed into an ordered list
/// so duplicate keys can be rejected in stage 2 (std.json's map types
/// silently keep the last duplicate — negative space we refuse to have).
pub const ClustersJson = struct {
    /// Every key the object carried, in order. Arena-backed and grown as
    /// the object is read: there is no ceiling on cluster count, so there
    /// is no capacity to skip past either — what used to be parsed-then-
    /// discarded past a cluster ceiling is now simply parsed.
    entries: []const Entry,

    const Entry = struct {
        name: []const u8,
        cluster: ClusterJson,
    };

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !@This() {
        var entries: std.ArrayList(Entry) = .empty;
        if (try source.next() != .object_begin) {
            return error.UnexpectedToken;
        }
        // Terminated by the object's own `}` or by the input running out,
        // which the scanner reports as an error — the same bound every
        // other array in this config now has, and the reason the old
        // `keys_seen_max` backstop is gone: with no ceiling above it, that
        // 4096 would have quietly become the new cluster limit.
        while (true) {
            const token = try source.nextAlloc(allocator, .alloc_if_needed);
            const name: []const u8 = switch (token) {
                .object_end => break,
                .string => |slice| slice,
                .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            try entries.append(allocator, .{
                .name = name,
                .cluster = try std.json.innerParse(ClusterJson, allocator, source, options),
            });
        }
        const seen = entries.items.len;
        const parsed: @This() = .{ .entries = try entries.toOwnedSlice(allocator) };
        // The postcondition every sibling resolver states: the handed-back
        // slice is every key the object carried, not a prefix of them —
        // which is exactly what the removed skip-past-capacity branch used
        // to make untrue.
        assert(parsed.entries.len == seen);
        return parsed;
    }
};

/// Marker for array-item vocabularies reflection can't infer from the
/// element type alone. `http_method` means "the items are the registered
/// HTTP method tokens", which `config_schema.zig` emits as a token enum.
pub const SchemaItems = enum { http_method };

/// The attribute keys a `schema_fields` entry may carry beyond `.desc`.
/// `assert_meta_matches` rejects any other key at comptime, so a typo'd
/// attribute is a compile error, not silently-ignored data.
const schema_attributes = [_][]const u8{
    "desc",       "minimum",    "maximum",   "min_items",  "max_items",
    "min_length", "const_true", "enum_type", "int_values", "items",
};

/// Cross-check a DTO's schema metadata against its real fields at comptime:
/// every field needs an entry (so adding a field without documenting it
/// fails the build — this is what makes schema coverage *structural* rather
/// than a runtime test that can silently pass), every entry needs a `.desc`
/// and must map to a real field, and every attribute must be a known key.
/// Run on each `dto_types` entry below and again by the schema emitter.
pub fn assert_meta_matches(comptime T: type) void {
    @setEvalBranchQuota(50_000);
    if (!@hasDecl(T, "schema_doc")) {
        @compileError(@typeName(T) ++ " is missing pub const schema_doc");
    }
    if (!@hasDecl(T, "schema_fields")) {
        @compileError(@typeName(T) ++ " is missing pub const schema_fields");
    }
    const Meta = @TypeOf(T.schema_fields);
    // Every field has a documented, described entry.
    inline for (@typeInfo(T).@"struct".fields) |field| {
        if (!@hasField(Meta, field.name)) {
            @compileError(@typeName(T) ++ "." ++ field.name ++ " has no schema_fields entry");
        }
        const entry = @field(T.schema_fields, field.name);
        if (!@hasField(@TypeOf(entry), "desc")) {
            @compileError(@typeName(T) ++ "." ++ field.name ++ " schema entry is missing .desc");
        }
    }
    // Every entry maps to a real field and carries only known attributes.
    inline for (@typeInfo(Meta).@"struct".fields) |entry_field| {
        if (!@hasField(T, entry_field.name)) {
            @compileError(@typeName(T) ++ " schema_fields entry '" ++ entry_field.name ++ "' has no matching field");
        }
        const entry = @field(T.schema_fields, entry_field.name);
        inline for (@typeInfo(@TypeOf(entry)).@"struct".fields) |attr| {
            comptime var known = false;
            inline for (schema_attributes) |name| {
                if (comptime std.mem.eql(u8, name, attr.name)) known = true;
            }
            if (!known) {
                @compileError(@typeName(T) ++ "." ++ entry_field.name ++ " has unknown schema attribute '" ++ attr.name ++ "'");
            }
        }
    }
}

/// Every plain-struct DTO the schema reflects over. `ClustersJson` is a
/// custom map, handled specially by the emitter, so it is not here. The
/// block below runs `assert_meta_matches` on each at comptime, so the
/// metadata cannot drift from the fields whether or not the emitter builds.
pub const dto_types = .{
    ConfigJson,    ListenerJson,      RouteJson,    FilterJson,
    MatchJson,     HeaderMatchJson,   ActionJson,   HeaderEditJson,
    RewriteJson,   ClusterJson,       TimeoutsJson, LimitsJson,
    AdminJson,     AccessLogJson,     CheckJson,    ClusterHashJson,
    ForwardedJson, ProxyProtocolJson,
};

comptime {
    for (dto_types) |T| assert_meta_matches(T);
}

fn resolveClusters(
    arena: std.mem.Allocator,
    clusters_json: *const ClustersJson,
    connect_timeout_ms: u32,
) ParseError![]const Config.Cluster {
    assert(connect_timeout_ms >= 1);
    if (clusters_json.entries.len < constants.clusters_min) {
        return error.ClustersEmpty;
    }
    // No upper bound: a cluster costs an arena `Config.Cluster` and a row
    // in the §7 endpoint tables, both sized from this count (§5), so how
    // many is the operator's call. `u16` is the one hard edge left — the
    // index type the endpoint key and every `cluster_index` field use.
    if (clusters_json.entries.len > std.math.maxInt(u16)) {
        return error.ClustersOverLimit;
    }

    const count: u16 = @intCast(clusters_json.entries.len);
    const clusters = try arena.alloc(Config.Cluster, count);

    // Duplicate names in O(n log n), by sorting an index permutation and
    // comparing neighbours. It was a nested scan over the entries, which
    // the 16-cluster ceiling kept to ~120 compares; with the ceiling gone
    // that same scan would cost ~2.1e9 string compares on a config at the
    // index type's edge — minutes of startup for a config whose memory
    // fits easily. Which name is reported first changes, and nothing
    // reads it: the error carries no payload.
    const order = try arena.alloc(u16, count);
    for (order, 0..) |*slot, index| slot.* = @intCast(index);
    const ByName = struct {
        entries: []const ClustersJson.Entry,
        fn lessThan(ctx: @This(), a: u16, b: u16) bool {
            return std.mem.lessThan(u8, ctx.entries[a].name, ctx.entries[b].name);
        }
    };
    std.mem.sort(u16, order, ByName{ .entries = clusters_json.entries }, ByName.lessThan);
    for (order[1..], order[0 .. order.len - 1]) |current, previous| {
        if (std.mem.eql(
            u8,
            clusters_json.entries[current].name,
            clusters_json.entries[previous].name,
        )) {
            return error.ClusterNameDuplicate;
        }
    }

    for (clusters_json.entries, 0..) |entry, index| {
        // A name is an identifier an operator writes and the access log
        // echoes (§8): bounding it is what keeps a log line's width a
        // function of `constants.zig` rather than of the config file.
        if (entry.name.len == 0) {
            return error.ClusterNameEmpty;
        }
        if (entry.name.len > constants.cluster_name_bytes_max) {
            return error.ClusterNameTooLong;
        }
        const pick = try pickOf(entry.cluster.pick);
        clusters[index] = .{
            .name = entry.name,
            .endpoints = try resolveEndpoints(arena, entry.cluster.endpoints),
            .pick = pick,
            .check = try resolveCheck(entry.cluster.check, connect_timeout_ms),
            .hash_key = try hashKeyOf(pick, entry.cluster.hash),
            .max_inflight = try resolveMaxInflight(entry.cluster.max_inflight),
        };
    }
    assert(clusters.len == count);
    return clusters;
}

fn resolveEndpoints(
    arena: std.mem.Allocator,
    endpoint_literals: []const []const u8,
) ParseError![]const std.Io.net.IpAddress {
    if (endpoint_literals.len == 0) {
        return error.EndpointsEmpty;
    }
    // No policy bound: endpoints cost an arena address each and a column
    // in the §7 endpoint tables, both sized from this count (§5). What is
    // left is the index type's own edge — `n` endpoints produce indices
    // `0..n-1`, and the largest of those must stay inside
    // `endpoint_index_max`, which `Conn` asserts sits below its
    // no-endpoint sentinel.
    if (endpoint_literals.len > @as(usize, constants.endpoint_index_max) + 1) {
        return error.EndpointsOverLimit;
    }

    const endpoints = try arena.alloc(std.Io.net.IpAddress, endpoint_literals.len);
    for (endpoint_literals, endpoints) |literal, *endpoint| {
        endpoint.* = std.Io.net.IpAddress.parseLiteral(literal) catch {
            return error.EndpointInvalid;
        };
        if (endpoint.getPort() == 0) {
            return error.EndpointPortZero;
        }
    }
    assert(endpoints.len == endpoint_literals.len);
    return endpoints;
}

fn resolveListeners(
    arena: std.mem.Allocator,
    listeners_json: []const ListenerJson,
    clusters: []const Config.Cluster,
    head_buffer_bytes: u32,
) ParseError![]const Config.Listener {
    assert(clusters.len >= 1);
    if (listeners_json.len == 0) {
        return error.ListenersEmpty;
    }
    // No policy ceiling: a listener costs two ring ops and one fd, and
    // both are checked against this config's own budget — `cqFillFits`
    // for the ring (`LimitConnSlotsOverCqFill`), `ensureFdBudget` for the
    // fds. What is left is the `u16` the listener index is stored in.
    if (listeners_json.len > std.math.maxInt(u16)) {
        return error.ListenersOverLimit;
    }

    const listeners = try arena.alloc(Config.Listener, listeners_json.len);
    for (listeners_json, 0..) |listener_json, index| {
        const bind_address = std.Io.net.IpAddress.parseLiteral(listener_json.bind) catch {
            return error.ListenerBindInvalid;
        };
        const protocol = try protocolOf(listener_json.protocol);
        listeners[index] = .{
            .bind_address = bind_address,
            .routes = try resolveRoutes(arena, &listener_json, clusters, protocol, head_buffer_bytes),
            .filters = try resolveFilters(arena, &listener_json, protocol, head_buffer_bytes),
            .protocol = protocol,
            .forwarded = try resolveForwarded(listener_json.forwarded, protocol),
            .proxy_protocol = try resolveProxyProtocol(listener_json.proxy_protocol, protocol),
        };
    }

    // Duplicate binds in O(n log n), for the reason `resolveClusters`
    // sorts its names: the nested scan this replaces was bounded by
    // `listeners_max` at 8 (~64 comparisons), and with the ceiling gone
    // it is bounded only by what `cqFillFits` admits — tens of thousands
    // at small pool sizes, which is ~8e8 comparisons at config load.
    const order = try arena.alloc(u16, listeners.len);
    for (order, 0..) |*slot, index| slot.* = @intCast(index);
    const ByBind = struct {
        listeners: []const Config.Listener,
        fn lessThan(ctx: @This(), a: u16, b: u16) bool {
            return bindOrder(ctx.listeners[a].bind_address) <
                bindOrder(ctx.listeners[b].bind_address);
        }
    };
    std.mem.sort(u16, order, ByBind{ .listeners = listeners }, ByBind.lessThan);
    for (order[1..], order[0 .. order.len - 1]) |current, previous| {
        if (std.meta.eql(
            listeners[current].bind_address,
            listeners[previous].bind_address,
        )) {
            return error.ListenerBindDuplicate;
        }
    }

    assert(listeners.len == listeners_json.len);
    assert(order.len == listeners.len);
    return listeners;
}

/// A total order over bind addresses, for the duplicate sort above. Only
/// the ordering matters, never the value: equal keys are re-checked with
/// `std.meta.eql`, so a collision costs a comparison rather than a wrong
/// verdict.
fn bindOrder(address: std.Io.net.IpAddress) u160 {
    return switch (address) {
        .ip4 => |v4| (@as(u160, 0) << 152) |
            (@as(u160, std.mem.readInt(u32, &v4.bytes, .big)) << 16) | v4.port,
        .ip6 => |v6| (@as(u160, 1) << 152) |
            (@as(u160, std.mem.readInt(u128, &v6.bytes, .big)) << 16) | v6.port,
    };
}

/// Compile a listener's §7 filter rules into immutable arena tables.
/// HTTP-only (an l4 listener has no head to match); absent = none. Match
/// keys are validated canonical so a filter and the router agree
/// byte-for-byte, and each action is validated at load, so the request-
/// time interpreter is bounded loops over trusted data.
fn resolveFilters(
    arena: std.mem.Allocator,
    listener_json: *const ListenerJson,
    protocol: Config.Listener.Protocol,
    head_buffer_bytes: u32,
) ParseError![]const filter.Rule {
    const filters_json = listener_json.filters orelse return &.{};
    // Any `filters` key on an l4 listener is a mistake — l4 relays bytes,
    // there is no head to match on — so reject it whether the array is
    // populated or (vacuously) empty, before the empty-array shortcut.
    if (protocol == .l4) {
        return error.ListenerL4Filters;
    }
    if (filters_json.len == 0) {
        return &.{};
    }
    const rules = try arena.alloc(filter.Rule, filters_json.len);
    var header_edits: u32 = 0;
    for (filters_json, rules) |rule_json, *rule| {
        rule.* = .{
            .match = try resolveMatch(arena, &rule_json.match, head_buffer_bytes),
            .actions = try resolveActions(arena, rule_json.actions, head_buffer_bytes),
        };
        header_edits += countHeaderEdits(rule.actions);
    }
    // A request applies the edits of every rule it matches, so the whole
    // table's edits bound one render's materialized set (§7). Cap the
    // total so the renderer's fixed buffer can never overflow.
    if (header_edits > constants.header_edits_max) {
        return error.FilterHeaderEditsOverLimit;
    }
    // The one bound left on this table, and the render buffer depends on
    // it — so state it positively rather than trusting the guard above.
    assert(header_edits <= constants.header_edits_max);
    assert(rules.len == filters_json.len);
    return rules;
}

/// The number of header-edit actions (set/add/remove) in a rule — the
/// reject and rewrite actions contribute no render-time header edit.
fn countHeaderEdits(actions: []const filter.Action) u32 {
    // Reached only through `resolveActions`, which rejects an empty
    // action list — so the caps this function once asserted against are
    // gone, but the shape they implied still holds.
    assert(actions.len >= 1);
    var count: u32 = 0;
    for (actions) |action| {
        switch (action) {
            .header_set, .header_add, .header_remove => count += 1,
            .reject, .rewrite_prefix => {},
        }
    }
    assert(count <= actions.len); // Edits are a subset of the actions.
    return count;
}

fn resolveMatch(
    arena: std.mem.Allocator,
    match_json: *const MatchJson,
    head_buffer_bytes: u32,
) ParseError!filter.Match {
    var match: filter.Match = .{};
    if (match_json.host) |host| {
        match.host = try validateRouteHost(host);
    }
    if (match_json.path_prefix) |prefix| {
        try validateRoutePrefix(prefix, head_buffer_bytes);
        match.path_prefix = prefix;
    }
    if (match_json.method) |tokens| {
        if (tokens.len == 0) {
            return error.FilterMethodEmpty;
        }
        var methods = std.EnumSet(parser.Method){};
        for (tokens) |token| {
            const method = parser.methodFromToken(token) orelse return error.FilterMethodUnknown;
            methods.insert(method);
        }
        match.methods = methods;
    }
    if (match_json.headers) |headers_json| {
        match.headers = try resolveHeaderMatches(arena, headers_json);
    }
    return match;
}

fn resolveHeaderMatches(
    arena: std.mem.Allocator,
    headers_json: []const HeaderMatchJson,
) ParseError![]const filter.HeaderMatch {
    const matches = try arena.alloc(filter.HeaderMatch, headers_json.len);
    for (headers_json, matches) |header_json, *match| {
        try validateHeaderName(header_json.name);
        // Exactly one predicate kind per header match.
        const set: u8 = @as(u8, @intFromBool(header_json.present != null)) +
            @intFromBool(header_json.equals != null) +
            @intFromBool(header_json.contains != null);
        assert(set <= 3); // The header match has three kind fields.
        if (set != 1) {
            return error.FilterHeaderMatchKind;
        }
        if (header_json.present) |present| {
            if (!present) {
                return error.FilterHeaderMatchKind; // "present: false" is not a predicate.
            }
            match.* = .{ .name = header_json.name, .kind = .present, .value = "" };
        } else if (header_json.equals) |value| {
            // An `equals: ""` predicate is meaningful — a header present
            // with an empty value — so the empty value is legal here.
            try validateHeaderValue(value);
            match.* = .{ .name = header_json.name, .kind = .equals, .value = value };
        } else {
            const needle = header_json.contains.?;
            // A `contains: ""` needle would match every present header
            // (`indexOf(x, "")` is always 0) — a degenerate `present` in
            // disguise. Reject it so `contains` is always a real substring.
            if (needle.len == 0) {
                return error.FilterHeaderContainsEmpty;
            }
            try validateHeaderValue(needle);
            match.* = .{ .name = header_json.name, .kind = .contains, .value = needle };
        }
    }
    assert(matches.len == headers_json.len);
    return matches;
}

fn resolveActions(
    arena: std.mem.Allocator,
    actions_json: []const ActionJson,
    head_buffer_bytes: u32,
) ParseError![]const filter.Action {
    if (actions_json.len == 0) {
        return error.FilterActionsEmpty;
    }
    assert(actions_json.len >= 1); // Past the empty guard.
    const actions = try arena.alloc(filter.Action, actions_json.len);
    for (actions_json, actions) |action_json, *action| {
        action.* = try resolveAction(&action_json, head_buffer_bytes);
    }
    assert(actions.len == actions_json.len);
    return actions;
}

fn resolveAction(action_json: *const ActionJson, head_buffer_bytes: u32) ParseError!filter.Action {
    // Exactly one action field carries the kind.
    const set: u8 = @as(u8, @intFromBool(action_json.reject != null)) +
        @intFromBool(action_json.header_set != null) +
        @intFromBool(action_json.header_add != null) +
        @intFromBool(action_json.header_remove != null) +
        @intFromBool(action_json.rewrite_prefix != null);
    assert(set <= 5); // The action object has five kind fields.
    if (set != 1) {
        return error.FilterActionKind;
    }
    if (action_json.reject) |status| {
        if (!filter.isRejectStatus(status)) {
            return error.FilterRejectStatus;
        }
        return .{ .reject = status };
    }
    if (action_json.header_set) |edit| {
        return .{ .header_set = try resolveHeaderEdit(&edit) };
    }
    if (action_json.header_add) |edit| {
        return .{ .header_add = try resolveHeaderEdit(&edit) };
    }
    if (action_json.header_remove) |name| {
        try validateEditableHeaderName(name);
        return .{ .header_remove = name };
    }
    const rewrite = action_json.rewrite_prefix.?;
    try validateRoutePrefix(rewrite.from, head_buffer_bytes);
    try validateRoutePrefix(rewrite.to, head_buffer_bytes);
    return .{ .rewrite_prefix = .{ .from = rewrite.from, .to = rewrite.to } };
}

/// Validate a name/value header edit shared by `header_set` and
/// `header_add`: an editable (non-proxy-managed) RFC 9110 token name and an
/// injection-safe field-value. Both actions carry the identical contract.
fn resolveHeaderEdit(edit: *const HeaderEditJson) ParseError!filter.HeaderEdit {
    try validateEditableHeaderName(edit.name);
    try validateHeaderValue(edit.value);
    return .{ .name = edit.name, .value = edit.value };
}

/// A header name must be a non-empty RFC 9110 token (no separators or
/// controls), so an edit or match names a real, unambiguous header.
fn validateHeaderName(name: []const u8) ParseError!void {
    if (name.len == 0) {
        return error.FilterHeaderNameInvalid;
    }
    assert(name.len >= 1); // Past the empty guard: the token scan is non-empty.
    for (name) |byte| {
        if (!isTokenByte(byte)) {
            return error.FilterHeaderNameInvalid;
        }
    }
}

/// An *edit* target must additionally not be a proxy-managed header: the
/// renderer owns hop-by-hop stripping, `Connection` injection, `Host`
/// routing, and the framing headers it committed to (§7). Letting a filter
/// set/add/remove one of those would smuggle a framing or persistence
/// change past the render's own decisions, so the compiled edit is proven
/// harmless at load. Match predicates carry no such restriction — reading
/// any header is safe.
fn validateEditableHeaderName(name: []const u8) ParseError!void {
    try validateHeaderName(name);
    assert(name.len >= 1); // A valid token; the managed lists are non-empty.
    for (render.hop_by_hop_names) |managed| {
        assert(managed.len >= 1);
        if (std.ascii.eqlIgnoreCase(name, managed)) {
            return error.FilterHeaderNameReserved;
        }
    }
    for (render.protected_names) |managed| {
        assert(managed.len >= 1);
        if (std.ascii.eqlIgnoreCase(name, managed)) {
            return error.FilterHeaderNameReserved;
        }
    }
    // Reserved unconditionally, not only on listeners that set it (§7).
    // A filter can only write a *constant*, so an edit naming this header
    // encodes one fixed address for every client — it looks like client
    // forwarding and is the opposite of it. Barring the name everywhere
    // means one mechanism owns the header, and an operator reaching for
    // the wrong one is told at load rather than believing a log full of
    // identical addresses.
    if (std.ascii.eqlIgnoreCase(name, render.forwarded_for_name)) {
        return error.FilterHeaderNameReserved;
    }
}

/// A header value must be an RFC 9110 field-value: VCHAR / SP / HTAB /
/// obs-text, and never CR, LF, NUL, or another control. A value carrying
/// CRLF would inject a header when the renderer writes it upstream
/// (slice 3), so the compiled edit is proven injection-safe at load —
/// the same "already safe" guarantee the canonical host/path keys carry.
/// An empty value is legal. Applied to emitted values and, for symmetry,
/// to the compared match values. The per-byte test is the parser's own
/// `isForwardableByte`, so a filter and the parser share one definition.
fn validateHeaderValue(value: []const u8) ParseError!void {
    for (value) |byte| {
        if (!parser.isForwardableByte(byte)) {
            return error.FilterHeaderValueInvalid;
        }
    }
}

fn isTokenByte(byte: u8) bool {
    return switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'a'...'z', 'A'...'Z' => true,
        else => false,
    };
}

/// Resolve a listener's route table (§7). `"cluster": "x"` is sugar for a
/// single catch-all route; `"routes": [...]` is the explicit table.
/// Exactly one form is required. Prefixes must already be canonical (so
/// they compare directly against the canonical request path) and unique;
/// the table is sorted longest-prefix-first for the request-time scan.
/// `l4` listeners have no path, so they take only the `cluster` form.
fn resolveRoutes(
    arena: std.mem.Allocator,
    listener_json: *const ListenerJson,
    clusters: []const Config.Cluster,
    protocol: Config.Listener.Protocol,
    head_buffer_bytes: u32,
) ParseError![]const router.Route {
    const has_cluster = listener_json.cluster != null;
    const has_routes = listener_json.routes != null;
    if (has_cluster == has_routes) {
        return error.ListenerClusterOrRoutes; // Neither, or both.
    }
    if (has_cluster) {
        const routes = try arena.alloc(router.Route, 1);
        routes[0] = .{
            .prefix = "/",
            .cluster_index = try clusterIndexOf(clusters, listener_json.cluster.?),
        };
        assert(routes.len == 1); // The sugar is always one catch-all route.
        return routes;
    }
    if (protocol == .l4) {
        return error.ListenerL4Routes; // L4 relays bytes; there is no path.
    }
    const routes_json = listener_json.routes.?;
    if (routes_json.len == 0) {
        return error.RoutesEmpty;
    }
    const routes = try arena.alloc(router.Route, routes_json.len);
    for (routes_json, 0..) |route_json, index| {
        try validateRoutePrefix(route_json.prefix, head_buffer_bytes);
        const host = if (route_json.host) |raw| try validateRouteHost(raw) else null;
        for (routes_json[0..index]) |previous| {
            // Earlier routes already passed validateRouteHost, so their raw
            // host equals its canonical form — a byte compare is sound.
            if (optionalHostEql(previous.host, host) and
                std.mem.eql(u8, previous.prefix, route_json.prefix))
            {
                return error.RouteDuplicate;
            }
        }
        routes[index] = .{
            .host = host,
            .prefix = route_json.prefix,
            .cluster_index = try clusterIndexOf(clusters, route_json.cluster),
        };
    }
    // Host-specific first, then longest-prefix-first (§7): the router's
    // linear scan then finds the most specific match first — any route
    // scoped to the request's host before any any-host route, and within a
    // group the longest prefix. Ties are rejected as duplicates above.
    std.mem.sort(router.Route, routes, {}, routeMoreSpecific);
    assert(routes.len >= 1);
    return routes;
}

fn routeMoreSpecific(_: void, left: router.Route, right: router.Route) bool {
    const left_scoped = left.host != null;
    const right_scoped = right.host != null;
    if (left_scoped != right_scoped) {
        return left_scoped; // A host-scoped route sorts before an any-host one.
    }
    return left.prefix.len > right.prefix.len;
}

fn optionalHostEql(left: ?[]const u8, right: ?[]const u8) bool {
    const left_host = left orelse return right == null;
    const right_host = right orelse return false;
    return std.mem.eql(u8, left_host, right_host);
}

/// A route host must already be in §7 canonical form (lowercased,
/// port-stripped), so a request's canonical host compares byte-for-byte
/// against it. A host canonicalization would change — mixed case, a port,
/// oversize — is rejected at load, not silently mismatched at request time.
fn validateRouteHost(host: []const u8) ParseError![]const u8 {
    if (host.len == 0 or host.len > constants.host_bytes_max) {
        return error.RouteHostNotCanonical;
    }
    var out: [constants.host_bytes_max]u8 = undefined;
    const canonical = parser.canonicalHost(host, &out) orelse {
        return error.RouteHostNotCanonical;
    };
    if (!std.mem.eql(u8, canonical, host)) {
        return error.RouteHostNotCanonical;
    }
    return host; // The config slice, already canonical.
}

/// A route prefix must be an origin-form path already in canonical form,
/// so it compares byte-for-byte against the canonicalized request path
/// (§7) — no per-request normalization, no router/backend divergence. A
/// prefix that canonicalization would change (dot-segments, decodable or
/// structure-changing escapes, a missing leading slash, a query) is
/// rejected at load, not silently mismatched at request time.
fn validateRoutePrefix(prefix: []const u8, head_buffer_bytes: u32) ParseError!void {
    assert(head_buffer_bytes >= constants.head_buffer_bytes_min);
    assert(head_buffer_bytes <= constants.head_buffer_bytes_max);
    if (prefix.len == 0 or prefix[0] != '/') {
        return error.RoutePrefixNotCanonical;
    }
    // Against the *resolved* size (`limits` resolves before listeners
    // for exactly this): a prefix longer than the configured head can
    // never match a parsed path, and belongs refused at load, not left
    // to 404 forever at runtime.
    if (prefix.len > head_buffer_bytes) {
        return error.RoutePrefixNotCanonical;
    }
    // Canonicalization only ever shrinks, so the compile-time ceiling on
    // the runtime gate above bounds the scratch. Stack is fine here:
    // this is the loader, not the serving path §5 constrains.
    var out: [constants.head_buffer_bytes_max]u8 = undefined;
    const canonical = parser.canonicalTarget(prefix, out[0..]) catch {
        return error.RoutePrefixNotCanonical;
    };
    if (canonical.query.len != 0 or !std.mem.eql(u8, canonical.path, prefix)) {
        return error.RoutePrefixNotCanonical;
    }
}

/// Resolve one cluster's §7 check block. Absent leaves the cluster
/// unprobed. Every limit gets its own error (§5), and the `http` fields
/// are rejected under `tcp` rather than ignored: a config that names a
/// path for a check that will never request it is describing something
/// the process is not doing, which is exactly the negative space this
/// loader exists to refuse.
fn resolveCheck(
    check_json: ?CheckJson,
    connect_timeout_ms: u32,
) ParseError!?Config.Cluster.Check {
    assert(connect_timeout_ms >= 1);
    const check = check_json orelse return null;
    const kind = std.meta.stringToEnum(Config.Cluster.Check.Kind, check.type) orelse
        return error.ClusterCheckTypeUnknown;
    if (check.fall < 1 or check.fall > constants.health_probe_threshold_max) {
        return error.ClusterCheckThresholdOutOfRange;
    }
    if (check.rise < 1 or check.rise > constants.health_probe_threshold_max) {
        return error.ClusterCheckThresholdOutOfRange;
    }
    const timeout_ms = check.timeout_ms orelse connect_timeout_ms;
    if (timeout_ms < 1 or timeout_ms > constants.timeout_ms_max) {
        return error.ClusterCheckTimeoutOutOfRange;
    }
    const http = switch (kind) {
        .tcp => blk: {
            // A TCP probe sends nothing and reads nothing, so every
            // HTTP-shaped field here would be inert.
            if (check.path != null or check.host != null) {
                return error.ClusterCheckHttpFieldOnTcp;
            }
            break :blk null;
        },
        .http => try resolveHttpCheck(&check),
    };
    return .{
        .kind = kind,
        .fall = check.fall,
        .rise = check.rise,
        .timeout_ms = timeout_ms,
        .http = http,
    };
}

/// The `http` half: a canonical path (validated exactly as a route
/// prefix is, so the probe sends bytes the origin's own router will
/// recognize), a bounded Host, and a status in the real range.
fn resolveHttpCheck(check: *const CheckJson) ParseError!Config.Cluster.Check.Http {
    const path = check.path orelse return error.ClusterCheckPathMissing;
    if (path.len > constants.health_check_path_bytes_max) {
        return error.ClusterCheckPathTooLong;
    }
    // The floor stands in for the resolved size here: clusters resolve
    // before `limits`, and a probe path is already capped far below the
    // smallest head buffer any config can choose (the comptime relation
    // in constants.zig), so the tighter runtime gate can never bind.
    comptime assert(constants.health_check_path_bytes_max < constants.head_buffer_bytes_min);
    validateRoutePrefix(path, constants.head_buffer_bytes_min) catch
        return error.ClusterCheckPathNotCanonical;
    if (check.host) |host| {
        if (host.len == 0 or host.len > constants.health_check_host_bytes_max) {
            return error.ClusterCheckHostInvalid;
        }
        // The value is rendered into a request head, so it must not be
        // able to inject one: no CR, LF, or NUL, the same rule the §7
        // filter header values obey.
        for (host) |byte| {
            if (byte == '\r' or byte == '\n' or byte == 0) {
                return error.ClusterCheckHostInvalid;
            }
        }
    }
    if (check.expect_status < 100 or check.expect_status > 599) {
        return error.ClusterCheckStatusInvalid;
    }
    return .{
        .path = path,
        .host = check.host,
        .expect_status = check.expect_status,
    };
}

/// Resolve the §8 per-endpoint concurrency cap. Absent leaves the
/// cluster uncapped; zero would refuse every request to an endpoint that
/// is doing nothing, and a value at or above the largest representable
/// in-flight total could never refuse anything — both are far more
/// likely a mistake than an intent, and "uncapped" already has a
/// spelling.
fn resolveMaxInflight(max_inflight: ?u32) ParseError!?u32 {
    const cap = max_inflight orelse return null;
    if (cap < 1 or cap > constants.endpoint_inflight_max) {
        return error.ClusterMaxInflightOutOfRange;
    }
    return cap;
}

/// Resolve a listener's §7 client-address forwarding: absent is off, and
/// a `forwarded` block on an `l4` listener is rejected rather than
/// ignored — a byte relay has no header to carry an address, so asking
/// for one there describes a proxy that is not running, exactly like
/// `filters` and `routes` on the same listener.
fn resolveForwarded(
    forwarded_json: ?ForwardedJson,
    protocol: Config.Listener.Protocol,
) ValidationError!?Config.Listener.Forwarded {
    const forwarded = forwarded_json orelse return null;
    if (protocol == .l4) {
        return error.ListenerL4Forwarded;
    }
    return std.meta.stringToEnum(Config.Listener.Forwarded, forwarded.mode) orelse
        error.ListenerForwardedModeUnknown;
}

/// Resolve a listener's PROXY protocol expectation (#142): absent is
/// off, and a block on an `http` listener is rejected rather than
/// ignored — the L7 path has no receive phase yet, so accepting the
/// config would state a trust boundary nothing enforces, the exact
/// silent hole the option exists to close.
fn resolveProxyProtocol(
    proxy_protocol_json: ?ProxyProtocolJson,
    protocol: Config.Listener.Protocol,
) ValidationError!?Config.Listener.ProxyProtocol {
    const proxy_protocol = proxy_protocol_json orelse return null;
    if (protocol == .http) {
        return error.ListenerHttpProxyProtocol;
    }
    return std.meta.stringToEnum(Config.Listener.ProxyProtocol, proxy_protocol.mode) orelse
        error.ListenerProxyProtocolModeUnknown;
}

/// The closed pick-policy vocabulary; anything else is its own error so
/// a typo ("pc2") fails loudly instead of silently balancing as p2c.
fn pickOf(literal: []const u8) error{ClusterPickUnknown}!Config.Cluster.Pick {
    return std.meta.stringToEnum(Config.Cluster.Pick, literal) orelse
        error.ClusterPickUnknown;
}

/// The §7 hash key for a cluster: its `hash` block's, or the default when
/// the block is absent. A block beside any *other* policy is rejected
/// rather than ignored — it reads as a request for stickiness that the
/// cluster would silently not provide, which is exactly the mistake worth
/// failing at load.
fn hashKeyOf(
    pick: Config.Cluster.Pick,
    hash_json: ?ClusterHashJson,
) ValidationError!Config.Cluster.HashKey {
    const hash = hash_json orelse return .source_ip;
    if (pick != .hash) {
        return error.ClusterHashWithoutHashPick;
    }
    return std.meta.stringToEnum(Config.Cluster.HashKey, hash.key) orelse
        error.ClusterHashKeyUnknown;
}

/// The closed protocol vocabulary; anything else is its own error so a
/// typo ("htpp") fails loudly instead of silently relaying as L4.
fn protocolOf(literal: []const u8) error{ListenerProtocolUnknown}!Config.Listener.Protocol {
    if (std.mem.eql(u8, literal, "l4")) {
        return .l4;
    }
    if (std.mem.eql(u8, literal, "http")) {
        return .http;
    }
    return error.ListenerProtocolUnknown;
}

fn clusterIndexOf(
    clusters: []const Config.Cluster,
    name: []const u8,
) error{ClusterUnknown}!u16 {
    assert(clusters.len >= 1);
    // The `@intCast` below is why: `resolveClusters` rejects a count past
    // the index type, so every position here fits the `u16` it returns.
    assert(clusters.len <= std.math.maxInt(u16));
    for (clusters, 0..) |cluster, index| {
        if (std.mem.eql(u8, cluster.name, name)) {
            return @intCast(index);
        }
    }
    return error.ClusterUnknown;
}

fn validateTimeouts(timeouts: *const TimeoutsJson) ValidationError!void {
    // Deadlines a zero would break rather than disable: a 0 ms connect or
    // idle budget reaps on arrival, and a 0 ms probe interval would probe
    // in a tight loop (§7) — probing is switched by the cluster `check`
    // flag, never by zeroing its pace. Each has a default, so absence is
    // fine here and only an explicit zero is the mistake.
    const nonzero = [_]u32{
        timeouts.connect_ms,
        timeouts.idle_ms,
        timeouts.health_interval_ms,
    };
    for (nonzero) |value| {
        if (value == 0) {
            return error.TimeoutZero;
        }
        if (value > constants.timeout_ms_max) {
            return error.TimeoutOverLimit;
        }
    }
    // The three optional caps (§6, §8): 0 means "no cap" on each — no age
    // limit, no request deadline, and a drain that waits for the last
    // connection — so only the shared ceiling is enforced.
    const optional = [_]u32{
        timeouts.max_lifetime_ms,
        timeouts.request_ms,
        timeouts.drain_deadline_ms,
    };
    for (optional) |value| {
        if (value > constants.timeout_ms_max) {
            return error.TimeoutOverLimit;
        }
    }
    // The one ordering between two configured values this loader enforces,
    // and it is a correctness bound rather than taste: a connection's first
    // deadline is armed at `connect_ms` (`Server.entryTimeoutMs`) and the
    // dial's completion re-stores it to `idle_ms`, but the physical timer
    // never moves earlier — only the stored target does (§4). So a
    // `connect_ms` at or above `idle_ms` is not shortened by the handoff:
    // the idle deadline waits out the connect-phase timer still counting
    // down, and fires late by up to `connect_ms - idle_ms`.
    //
    // Rejected rather than clamped. A clamp would answer a config zoxy
    // cannot honor with a log line, and the shipped defaults are already
    // ordered (`constants` asserts the same relation over the pair), so
    // this only ever fires on a hand-written config that was going to
    // behave differently than it reads.
    if (timeouts.connect_ms >= timeouts.idle_ms) {
        return error.TimeoutOrderInvalid;
    }
    // Postconditions: reaching here means every bound a consumer reads
    // without checking is in range, and every optional one is at most the
    // ceiling — zero included, which each consumer reads as "off" — and the
    // pair the deadline handoff depends on is ordered, which is what
    // `Server.init` asserts of any config however it was built.
    for (nonzero) |value| {
        assert(value >= 1);
        assert(value <= constants.timeout_ms_max);
    }
    for (optional) |value| {
        assert(value <= constants.timeout_ms_max);
    }
    assert(timeouts.connect_ms < timeouts.idle_ms);
}

const example_json = @embedFile("example_config");

test "config: the shipped example parses and resolves" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();

    const parsed = try expectParseOk(&arena_state, example_json);
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.clusters.len);
    // The `"cluster"` sugar resolves to one catch-all route.
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners[0].routes.len);
    try std.testing.expectEqualStrings("/", parsed.listeners[0].routes[0].prefix);
    try std.testing.expectEqual(@as(u16, 0), parsed.listeners[0].routes[0].cluster_index);
    try std.testing.expectEqual(Config.Listener.Protocol.l4, parsed.listeners[0].protocol);
    try std.testing.expectEqual(@as(u16, 8080), parsed.listeners[0].bind_address.getPort());
    try std.testing.expectEqualStrings("origin", parsed.clusters[0].name);
    try std.testing.expectEqual(@as(u16, 9000), parsed.clusters[0].endpoints[0].getPort());
    // The example's tcp check resolves with its thresholds, and its
    // omitted budget inherits the connect timeout.
    const example_check = parsed.clusters[0].check.?;
    try std.testing.expectEqual(Config.Cluster.Check.Kind.tcp, example_check.kind);
    try std.testing.expectEqual(@as(u8, 3), example_check.fall);
    try std.testing.expectEqual(@as(u8, 2), example_check.rise);
    try std.testing.expectEqual(constants.connect_ms_default, example_check.timeout_ms);
    try std.testing.expectEqual(@as(?Config.Cluster.Check.Http, null), example_check.http);
    // The example names no `timeouts` block at all, so every deadline
    // here is a default — which is the thing it is demonstrating. A
    // check's omitted budget still inherits the connect timeout, so this
    // also pins that the inheritance reads the *resolved* value rather
    // than only an explicitly configured one.
    try std.testing.expectEqual(constants.connect_ms_default, parsed.connect_timeout_ms);
    try std.testing.expectEqual(constants.idle_ms_default, parsed.idle_timeout_ms);
    try std.testing.expectEqual(constants.health_interval_ms_default, parsed.health_interval_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.drain_deadline_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.request_timeout_ms);
}

test "config: max_lifetime_ms is optional and defaults to disabled" {
    // The field is absent here — pre-existing configs stay valid and the
    // cap defaults off (§6).
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
    // The shipped example names neither optional bound, so both must land
    // disabled — the §8 request deadline is opt-in like the age cap.
    try std.testing.expectEqual(@as(u32, 0), parsed.request_timeout_ms);
}

test "config: request_ms is optional, defaults off, and shares the timeout ceiling" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
    ;
    // Absent: pre-existing configs stay valid and the §8 request deadline
    // defaults off, the same shape as max_lifetime_ms.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.request_timeout_ms);
    }
    // Explicit 0 is legal — "no cap", not a TimeoutZero.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1,\"request_ms\":0}}",
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.request_timeout_ms);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1,\"request_ms\":250}}",
        );
        try std.testing.expectEqual(@as(u32, 250), parsed.request_timeout_ms);
    }
    // The shared ceiling still binds — an optional cap is not an unbounded
    // one.
    {
        const json = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}\"timeouts\":{{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1,\"request_ms\":{d}}}}}",
            .{ head, @as(u64, constants.timeout_ms_max) + 1 },
        );
        defer std.testing.allocator.free(json);
        try expectParseError(error.TimeoutOverLimit, json);
    }
}

test "config: the whole timeouts block is optional, and every default is usable" {
    // A config that names none of them is the out-of-box shape (§5), the
    // same argument `limits` already makes: an operator opts into tuning,
    // never into a working config.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}}}
    );
    try std.testing.expectEqual(constants.connect_ms_default, parsed.connect_timeout_ms);
    try std.testing.expectEqual(constants.idle_ms_default, parsed.idle_timeout_ms);
    try std.testing.expectEqual(constants.health_interval_ms_default, parsed.health_interval_ms);
    // The three caps default off, the drain one included: nginx, HAProxy
    // and Caddy all wait indefinitely, and the supervisor that sent the
    // signal owns the upper bound.
    try std.testing.expectEqual(@as(u32, 0), parsed.drain_deadline_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.request_timeout_ms);
}

test "config: a zero drain deadline is no cap, but a zero connect or idle is still a mistake" {
    // The asymmetry is the point: 0 disables a *cap*, and there is no
    // sense in which a 0 ms dial or idle budget is a policy rather than a
    // configuration error, so those two keep rejecting it.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"drain_deadline_ms":0}}
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.drain_deadline_ms);
    }
    const rejected = [_][]const u8{
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":0}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"idle_ms":0}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"health_interval_ms":0}}
        ,
    };
    for (rejected) |json| {
        try expectParseError(error.TimeoutZero, json);
    }
}

test "config: the dial budget must sit below the idle one" {
    // The §4 handoff, stated as a load-time rule: the first deadline is
    // armed at `connect_ms` and the dial's completion re-stores it to
    // `idle_ms`, but the armed timer never moves earlier — so an idle
    // budget that does not exceed the dial budget fires late rather than
    // shortening. Equal is rejected too: it is the boundary where the
    // handoff already changes nothing.
    const rejected = [_][]const u8{
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":90000,"idle_ms":60000}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":5000,"idle_ms":5000}}
        ,
        // One field is enough to break the pair: a dial budget raised past
        // the *defaulted* idle one is the shape an operator reaches for
        // first, and it reads as tuning one number rather than as ordering
        // two.
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":90000}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"idle_ms":1000}}
        ,
    };
    for (rejected) |json| {
        try expectParseError(error.TimeoutOrderInvalid, json);
    }
    // A single millisecond of ordering is all the rule asks for, and the
    // shipped defaults clear it by an order of magnitude.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":5000,"idle_ms":5001}}
    );
    try std.testing.expectEqual(@as(u32, 5000), parsed.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 5001), parsed.idle_timeout_ms);
    try std.testing.expect(constants.connect_ms_default < constants.idle_ms_default);
}

test "config: max_lifetime_ms accepts zero (a legal zero timeout) and real values" {
    // Explicit 0 is legal — it is *not* a TimeoutZero, unlike the dial
    // and idle budgets (§6).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,"max_lifetime_ms":0}}
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,"max_lifetime_ms":1800000}}
        );
        try std.testing.expectEqual(@as(u32, 1_800_000), parsed.max_lifetime_ms);
    }
}

test "config: listener protocol defaults to l4 and accepts http" {
    // Absent field: pre-L7 configs stay valid.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(Config.Listener.Protocol.l4, parsed.listeners[0].protocol);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a","protocol":"http"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(Config.Listener.Protocol.http, parsed.listeners[0].protocol);
    }
}

test "config: explicit routes resolve, sorted longest-prefix-first" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","protocol":"http","routes":[
        \\   {"prefix":"/","cluster":"root"},
        \\   {"prefix":"/api/v2","cluster":"v2"},
        \\   {"prefix":"/api","cluster":"api"}]}],
        \\ "clusters":{"root":{"endpoints":["127.0.0.1:2"]},
        \\   "api":{"endpoints":["127.0.0.1:3"]},
        \\   "v2":{"endpoints":["127.0.0.1:4"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const routes = parsed.listeners[0].routes;
    try std.testing.expectEqual(@as(usize, 3), routes.len);
    // Descending by prefix length, whatever the config order.
    try std.testing.expectEqualStrings("/api/v2", routes[0].prefix);
    try std.testing.expectEqualStrings("/api", routes[1].prefix);
    try std.testing.expectEqualStrings("/", routes[2].prefix);
    // The cluster the router will hand back for the longest match.
    try std.testing.expectEqual(
        @as(?u16, routes[0].cluster_index),
        router.route(routes, null, "/api/v2/x"),
    );
    try std.testing.expectEqual(
        @as(?u16, routes[2].cluster_index),
        router.route(routes, null, "/elsewhere"),
    );
}

test "config: routing schema rejects malformed tables" {
    const base_clusters =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Neither cluster nor routes.
    try expectParseError(error.ListenerClusterOrRoutes, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"}]," ++ base_clusters);
    // Both cluster and routes.
    try expectParseError(error.ListenerClusterOrRoutes, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"a\"," ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // Routes on an l4 listener: there is no path to match.
    try expectParseError(error.ListenerL4Routes, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"l4\"," ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // Empty routes table.
    try expectParseError(error.RoutesEmpty, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[]}]," ++ base_clusters);
    // A non-canonical prefix (dot-segment) — would mismatch at request time.
    try expectParseError(error.RoutePrefixNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"prefix\":\"/a/../b\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // A prefix without a leading slash.
    try expectParseError(error.RoutePrefixNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"prefix\":\"api\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // Duplicate (host, prefix) — same any-host prefix twice.
    try expectParseError(error.RouteDuplicate, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"prefix\":\"/x\",\"cluster\":\"a\"}," ++
        "{\"prefix\":\"/x\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // A non-canonical host (uppercase) — would mismatch at request time.
    try expectParseError(error.RouteHostNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"host\":\"API.Example.com\",\"prefix\":\"/\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // A host carrying a port — the port is not part of the routing name.
    try expectParseError(error.RouteHostNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"host\":\"api.example.com:8080\",\"prefix\":\"/\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // An unknown cluster named by a route.
    try expectParseError(error.ClusterUnknown, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"ghost\"}]}]," ++ base_clusters);
}

test "config: host routes resolve, host-specific sorted before any-host" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","protocol":"http","routes":[
        \\   {"prefix":"/","cluster":"root"},
        \\   {"host":"api.example.com","prefix":"/","cluster":"api"},
        \\   {"host":"api.example.com","prefix":"/v2","cluster":"v2"}]}],
        \\ "clusters":{"root":{"endpoints":["127.0.0.1:2"]},
        \\   "api":{"endpoints":["127.0.0.1:3"]},
        \\   "v2":{"endpoints":["127.0.0.1:4"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const routes = parsed.listeners[0].routes;
    try std.testing.expectEqual(@as(usize, 3), routes.len);
    // Host-specific first (longest-prefix within), then any-host.
    try std.testing.expectEqualStrings("api.example.com", routes[0].host.?);
    try std.testing.expectEqualStrings("/v2", routes[0].prefix);
    try std.testing.expectEqualStrings("api.example.com", routes[1].host.?);
    try std.testing.expectEqualStrings("/", routes[1].prefix);
    try std.testing.expectEqual(@as(?[]const u8, null), routes[2].host);
    // The router hands host-specificity precedence over prefix length.
    try std.testing.expectEqual(
        @as(?u16, routes[1].cluster_index),
        router.route(routes, "api.example.com", "/other"),
    );
    try std.testing.expectEqual(
        @as(?u16, routes[2].cluster_index),
        router.route(routes, "other.example.com", "/v2"),
    );
}

test "config: filters compile into rules with matches and actions" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","protocol":"http","cluster":"a","filters":[
        \\   {"match":{"method":["GET","POST"],"path_prefix":"/admin",
        \\             "headers":[{"name":"X-Env","equals":"prod"}]},
        \\    "actions":[{"reject":403}]},
        \\   {"match":{"host":"api.example"},
        \\    "actions":[{"header_set":{"name":"X-Via","value":"zoxy"}},
        \\               {"rewrite_prefix":{"from":"/old","to":"/new"}}]}]}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const filters = parsed.listeners[0].filters;
    try std.testing.expectEqual(@as(usize, 2), filters.len);

    // Rule 0: method set + path prefix + one header-equals match, reject 403.
    const rule0 = filters[0];
    try std.testing.expect(rule0.match.methods.?.contains(.get));
    try std.testing.expect(rule0.match.methods.?.contains(.post));
    try std.testing.expect(!rule0.match.methods.?.contains(.delete));
    try std.testing.expectEqualStrings("/admin", rule0.match.path_prefix.?);
    try std.testing.expectEqual(@as(usize, 1), rule0.match.headers.len);
    try std.testing.expectEqualStrings("X-Env", rule0.match.headers[0].name);
    try std.testing.expectEqual(filter.HeaderMatch.Kind.equals, rule0.match.headers[0].kind);
    try std.testing.expectEqual(@as(usize, 1), rule0.actions.len);
    try std.testing.expectEqual(@as(u16, 403), rule0.actions[0].reject);

    // Rule 1: host match, header_set then rewrite_prefix.
    const rule1 = filters[1];
    try std.testing.expectEqualStrings("api.example", rule1.match.host.?);
    try std.testing.expectEqual(@as(?std.EnumSet(parser.Method), null), rule1.match.methods);
    try std.testing.expectEqual(@as(usize, 2), rule1.actions.len);
    try std.testing.expectEqualStrings("X-Via", rule1.actions[0].header_set.name);
    try std.testing.expectEqualStrings("/new", rule1.actions[1].rewrite_prefix.to);
}

test "config: filter schema rejects malformed rules" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\",\"cluster\":\"a\",\"filters\":[";
    // L4 listener may not carry filters.
    try expectParseError(error.ListenerL4Filters, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"l4\",\"cluster\":\"a\"," ++
        "\"filters\":[{\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // Even a vacuously empty filters array on l4 is a mistake — the key is
    // meaningless there, and an empty array must not slip past the guard.
    try expectParseError(error.ListenerL4Filters, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"l4\",\"cluster\":\"a\"," ++
        "\"filters\":[]}]," ++ tail);
    // A rule with no actions.
    try expectParseError(error.FilterActionsEmpty, head ++ "{\"actions\":[]}]}]," ++ tail);
    // An action object with no kind set.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{}]}]}]," ++ tail);
    // An action object with two kinds set.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{\"reject\":403,\"header_remove\":\"X\"}]}]}]," ++ tail);
    // A reject status outside the policy set.
    try expectParseError(error.FilterRejectStatus, head ++ "{\"actions\":[{\"reject\":503}]}]}]," ++ tail);
    // An unknown / lowercase method token.
    try expectParseError(error.FilterMethodUnknown, head ++ "{\"match\":{\"method\":[\"get\"]},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // A header match with no predicate kind.
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\"}]},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // A `contains` predicate with an empty needle: it would match every
    // present header (a degenerate `present`), so it is rejected.
    try expectParseError(error.FilterHeaderContainsEmpty, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\",\"contains\":\"\"}]},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // A non-canonical match path prefix.
    try expectParseError(error.RoutePrefixNotCanonical, head ++ "{\"match\":{\"path_prefix\":\"/a/../b\"},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // A header edit with an invalid header name.
    try expectParseError(error.FilterHeaderNameInvalid, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"Bad Name\",\"value\":\"v\"}}]}]}]," ++ tail);
    // A header value carrying CRLF — a smuggling vector when rendered.
    try expectParseError(error.FilterHeaderValueInvalid, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"X\",\"value\":\"a\\r\\nInjected: 1\"}}]}]}]," ++ tail);
    // "present: false" is not a predicate.
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\",\"present\":false}]},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // A rewrite whose target is not canonical.
    try expectParseError(error.RoutePrefixNotCanonical, head ++ "{\"actions\":[{\"rewrite_prefix\":{\"from\":\"/a\",\"to\":\"/b/../c\"}}]}]}]," ++ tail);
    // A header edit may not name a proxy-managed header — case-insensitively.
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"Host\",\"value\":\"evil\"}}]}]}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_remove\":\"content-length\"}]}]}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_add\":{\"name\":\"Connection\",\"value\":\"close\"}}]}]}]," ++ tail);
    // A matched header predicate may still name a managed header (read-only).
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"Host\"}]},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
}

test "config: a filter set over the header-edit budget is rejected" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // header_edits_max+1 header edits spread one-per-rule: neither the
    // rule count nor a rule's action count is bounded any more, so the
    // whole-table total is the only thing that caps — which is the point,
    // since that total is what the renderer's fixed buffer must hold.
    const rules = comptime blk: {
        var s: []const u8 = "";
        var edit: u16 = 0;
        while (edit < constants.header_edits_max + 1) : (edit += 1) {
            if (edit != 0) s = s ++ ",";
            s = s ++ "{\"actions\":[{\"header_remove\":\"X-Drop\"}]}";
        }
        break :blk s;
    };
    const json = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"cluster\":\"a\",\"filters\":[" ++ rules ++ "]}]," ++ tail;
    try expectParseError(error.FilterHeaderEditsOverLimit, json);
}

test "config: cluster pick policy parses, defaults to p2c, rejects typos" {
    // Explicit rr and p2c both resolve; absent defaults to p2c.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"pick":"rr"},
            \\   "b":{"endpoints":["127.0.0.1:3"],"pick":"p2c"},
            \\   "c":{"endpoints":["127.0.0.1:4"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(Config.Cluster.Pick.rr, parsed.clusters[0].pick);
        try std.testing.expectEqual(Config.Cluster.Pick.p2c, parsed.clusters[1].pick);
        try std.testing.expectEqual(Config.Cluster.Pick.p2c, parsed.clusters[2].pick);
    }
    // A typo must not silently balance as the default.
    try expectParseError(error.ClusterPickUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"pick":"pc2"}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: a check block resolves its kind, thresholds and budget" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],
        \\     "check":{"type":"tcp","fall":5,"rise":1,"timeout_ms":250}},
        \\   "b":{"endpoints":["127.0.0.1:3"],"check":{"type":"tcp"}},
        \\   "c":{"endpoints":["127.0.0.1:4"]}},
        \\ "timeouts":{"connect_ms":7,"idle_ms":8,"drain_deadline_ms":1}}
    );
    const tuned = parsed.clusters[0].check.?;
    try std.testing.expectEqual(@as(u8, 5), tuned.fall);
    try std.testing.expectEqual(@as(u8, 1), tuned.rise);
    try std.testing.expectEqual(@as(u32, 250), tuned.timeout_ms);
    // Omitted thresholds take the compiled defaults, and an omitted
    // budget inherits the connect timeout rather than inventing one.
    const defaulted = parsed.clusters[1].check.?;
    try std.testing.expectEqual(constants.health_probe_fall_default, defaulted.fall);
    try std.testing.expectEqual(constants.health_probe_rise_default, defaulted.rise);
    try std.testing.expectEqual(@as(u32, 7), defaulted.timeout_ms);
    // Absent means unprobed — the cluster the balancer never skips.
    try std.testing.expectEqual(@as(?Config.Cluster.Check, null), parsed.clusters[2].check);
}

test "config: an http check resolves its request and expected status" {
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],
            \\     "check":{"type":"http","path":"/healthz","host":"api.example",
            \\       "expect_status":204}}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        const check = parsed.clusters[0].check.?;
        try std.testing.expectEqual(Config.Cluster.Check.Kind.http, check.kind);
        const http = check.http.?;
        try std.testing.expectEqualStrings("/healthz", http.path);
        try std.testing.expectEqualStrings("api.example", http.host.?);
        try std.testing.expectEqual(@as(u16, 204), http.expect_status);
    }
    // Host is optional: absent means the endpoint's own literal (§7).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],
            \\     "check":{"type":"http","path":"/health"}}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        const http = parsed.clusters[0].check.?.http.?;
        try std.testing.expectEqual(@as(?[]const u8, null), http.host);
        try std.testing.expectEqual(@as(u16, 200), http.expect_status);
    }
}

test "config: a check block rejects every shape it cannot run" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"check":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // A typo in the vocabulary must not silently probe as tcp.
    try expectParseError(error.ClusterCheckTypeUnknown, head ++ "{\"type\":\"htp\"}" ++ tail);
    // Thresholds are counts of probes: zero would eject or restore on no
    // evidence at all, and the ceiling keeps the u8 streaks from wrapping.
    try expectParseError(error.ClusterCheckThresholdOutOfRange, head ++ "{\"fall\":0}" ++ tail);
    try expectParseError(error.ClusterCheckThresholdOutOfRange, head ++ "{\"rise\":0}" ++ tail);
    try expectParseError(error.ClusterCheckThresholdOutOfRange, head ++ "{\"fall\":65}" ++ tail);
    // A zero budget would expire before the dial was submitted.
    try expectParseError(error.ClusterCheckTimeoutOutOfRange, head ++ "{\"timeout_ms\":0}" ++ tail);
    // An http check with nothing to request is not a check.
    try expectParseError(error.ClusterCheckPathMissing, head ++ "{\"type\":\"http\"}" ++ tail);
    // A path a tcp probe would never send is a config describing
    // something the process is not doing.
    try expectParseError(
        error.ClusterCheckHttpFieldOnTcp,
        head ++ "{\"type\":\"tcp\",\"path\":\"/health\"}" ++ tail,
    );
    // The probe sends the path verbatim, so it must already be canonical
    // — the same rule a route prefix obeys (§7).
    try expectParseError(
        error.ClusterCheckPathNotCanonical,
        head ++ "{\"type\":\"http\",\"path\":\"health\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckPathNotCanonical,
        head ++ "{\"type\":\"http\",\"path\":\"/a/../b\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckPathNotCanonical,
        head ++ "{\"type\":\"http\",\"path\":\"/health?x=1\"}" ++ tail,
    );
    // A Host is rendered into a request head, so it may not carry the
    // bytes that would end one.
    try expectParseError(
        error.ClusterCheckHostInvalid,
        head ++ "{\"type\":\"http\",\"path\":\"/h\",\"host\":\"a\\r\\nX: y\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckHostInvalid,
        head ++ "{\"type\":\"http\",\"path\":\"/h\",\"host\":\"\"}" ++ tail,
    );
    // A status outside the real range can never match a response.
    try expectParseError(
        error.ClusterCheckStatusInvalid,
        head ++ "{\"type\":\"http\",\"path\":\"/h\",\"expect_status\":99}" ++ tail,
    );
}

test "config: health interval parses, defaults to inter, rejects zero" {
    // Explicit value resolves; absent means the HAProxy-inter default.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,
            \\   "health_interval_ms":250}}
        );
        try std.testing.expectEqual(@as(u32, 250), parsed.health_interval_ms);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(constants.health_interval_ms_default, parsed.health_interval_ms);
    }
    // Zero would probe in a tight loop; the cluster flag is the switch.
    try expectParseError(error.TimeoutZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,
        \\   "health_interval_ms":0}}
    );
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,
        \\   "health_interval_ms":3600001}}
    );
}

test "config: limits shrink pools below the ceilings, never past them" {
    // Partial limits: relay buffers derive from the effective conn slots.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
            \\ "limits":{"conn_slots":64}}
        );
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.conn_slots);
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.relay_buffers);
        // The *default*, which is deliberately below the ceiling: an
        // omitted `upstream_slots` must not silently reserve the c10k
        // maximum. These were the same number until the ceiling rose.
        try std.testing.expectEqual(constants.upstream_slots_default, parsed.limits.upstream_slots);
        try std.testing.expect(constants.upstream_slots_default < constants.upstream_slots_max);
        // The CQ fill defaults to ⅞ when the block omits it.
        try std.testing.expectEqual(constants.cq_fill_eighths_default, parsed.limits.cq_fill_eighths);
    }
    // Full limits resolve verbatim; absent block keeps the ceilings.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
            \\ "limits":{"conn_slots":64,"relay_buffers":8,"upstream_slots":8,"cq_fill_eighths":4}}
        );
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.conn_slots);
        try std.testing.expectEqual(@as(u32, 8), parsed.limits.relay_buffers);
        try std.testing.expectEqual(@as(u32, 8), parsed.limits.upstream_slots);
        // An l4-only config registers no head-buffer ring.
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.head_buffers);
        // A tighter fill resolves verbatim when the pools leave room for it.
        try std.testing.expectEqual(@as(u32, 4), parsed.limits.cq_fill_eighths);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a","protocol":"http"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
            \\ "limits":{"conn_slots":64,"head_buffers":16}}
        );
        // An http config follows conn slots when the ring is omitted and
        // takes the operator's number when it is not; the upstream head
        // pool follows upstream slots on the same terms.
        try std.testing.expectEqual(@as(u32, 16), parsed.limits.head_buffers);
        try std.testing.expectEqual(constants.upstream_slots_default, parsed.limits.upstream_head_buffers);
        try std.testing.expectEqual(constants.head_buffer_bytes_default, parsed.limits.head_buffer_bytes);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a","protocol":"http"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
            \\ "limits":{"conn_slots":64}}
        );
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.head_buffers);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        // An omitted `limits` block yields the lean defaults, not the
        // ceilings (§5): the out-of-box footprint is small, opt up to scale.
        try std.testing.expectEqual(constants.conn_slots_default, parsed.limits.conn_slots);
        try std.testing.expectEqual(constants.relay_buffers_default, parsed.limits.relay_buffers);
        try std.testing.expectEqual(constants.upstream_slots_default, parsed.limits.upstream_slots);
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.head_buffers);
        try std.testing.expectEqual(constants.cq_fill_eighths_default, parsed.limits.cq_fill_eighths);
    }
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"a\"}],";
    // Zero and over-ceiling both fail loudly, each with its own error.
    try expectParseError(error.LimitConnSlotsOutOfRange, head ++ tail ++ "\"limits\":{\"conn_slots\":0}}");
    try expectParseError(error.LimitConnSlotsOutOfRange, head ++ tail ++ "\"limits\":{\"conn_slots\":99999}}");
    try expectParseError(error.LimitRelayBuffersOutOfRange, head ++ tail ++ "\"limits\":{\"relay_buffers\":0}}");
    // Over-ceiling relay buffers alone hit the range check, not the
    // conn-slot contradiction — the range check has precedence.
    try expectParseError(error.LimitRelayBuffersOutOfRange, head ++ tail ++ "\"limits\":{\"relay_buffers\":99999}}");
    try expectParseError(error.LimitUpstreamSlotsOutOfRange, head ++ tail ++ "\"limits\":{\"upstream_slots\":0}}");
    try expectParseError(error.LimitUpstreamSlotsOutOfRange, head ++ tail ++ "\"limits\":{\"upstream_slots\":99999}}");
    // A specified relay-buffer count above the conn slots is a
    // contradiction, not a derivable default.
    try expectParseError(error.LimitRelayBuffersOverConnSlots, head ++ tail ++
        "\"limits\":{\"conn_slots\":4,\"relay_buffers\":8}}");
    // The head-buffer ring's three refusals (§5): more buffers than
    // connections is waste stated as intent; any buffers without an http
    // listener can never bind; an http listener with none would shed
    // every request it is configured to serve.
    const http_head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"a\",\"protocol\":\"http\"}],";
    try expectParseError(error.LimitHeadBuffersOverConnSlots, http_head ++ tail ++
        "\"limits\":{\"conn_slots\":4,\"head_buffers\":8}}");
    try expectParseError(error.LimitHeadBuffersWithoutHttpListener, head ++ tail ++
        "\"limits\":{\"head_buffers\":1}}");
    try expectParseError(error.LimitHeadBuffersOutOfRange, http_head ++ tail ++
        "\"limits\":{\"head_buffers\":0}}");
    // The upstream head pool refuses the same three shapes against its
    // own ceiling, the upstream slots.
    try expectParseError(error.LimitUpstreamHeadBuffersOverUpstreamSlots, http_head ++ tail ++
        "\"limits\":{\"upstream_slots\":2,\"upstream_head_buffers\":4}}");
    try expectParseError(error.LimitUpstreamHeadBuffersWithoutHttpListener, head ++ tail ++
        "\"limits\":{\"upstream_head_buffers\":1}}");
    try expectParseError(error.LimitUpstreamHeadBuffersOutOfRange, http_head ++ tail ++
        "\"limits\":{\"upstream_head_buffers\":0}}");
    // The size knob has a floor as well as a ceiling: below it ordinary
    // requests start dying as 414/431, which is behaviour, not memory.
    try expectParseError(error.LimitHeadBufferBytesOutOfRange, http_head ++ tail ++
        "\"limits\":{\"head_buffer_bytes\":512}}");
    try expectParseError(error.LimitHeadBufferBytesOutOfRange, http_head ++ tail ++
        "\"limits\":{\"head_buffer_bytes\":2097152}}");
    // The parse-order precedences the limits-before-listeners reorder
    // moved, pinned deliberately (see `parse`): emptiness beats a bad
    // sink; a bad protocol (even on a later listener) beats a bad bind
    // on an earlier one, because the http count reads every protocol
    // before any listener resolves.
    try expectParseError(error.ListenersEmpty,
        \\{"listeners":[],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
        \\ "access_log":{"sink":"nonsense"}}
    );
    try expectParseError(error.ListenerProtocolUnknown,
        \\{"listeners":[{"bind":"not-an-address","cluster":"a"},
        \\               {"bind":"127.0.0.1:1","cluster":"a","protocol":"gopher"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // The CQ fill has its own range [min, max] in eighths; below or above
    // fails loudly, each distinct from the pool-size errors.
    try expectParseError(error.LimitCqFillOutOfRange, head ++ tail ++ "\"limits\":{\"cq_fill_eighths\":0}}");
    try expectParseError(error.LimitCqFillOutOfRange, head ++ tail ++ "\"limits\":{\"cq_fill_eighths\":8}}");
    // A fill tighter than the ceiling was derived at cannot serve the full
    // ceiling shape — the completion queue it would need exceeds the
    // compiled ring, so the combination is rejected (§8). Both pools are
    // named at their ceiling because that is the shape the derivation
    // budgets for: the pair is pinned, so a conn slot's worst case
    // includes the upstream slot it may hold (see `conn_slots_max`).
    {
        const json = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}{s}\"limits\":{{\"conn_slots\":{d},\"upstream_slots\":{d},\"cq_fill_eighths\":{d}}}}}",
            .{
                head,
                tail,
                constants.conn_slots_max,
                constants.upstream_slots_max,
                constants.cq_fill_eighths_max - 1,
            },
        );
        defer std.testing.allocator.free(json);
        try expectParseError(error.LimitConnSlotsOverCqFill, json);
    }
}

test "config: admin block resolves a bind literal, absent leaves it off" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"a\"}],";
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}
    ;
    // Absent: the admin plane stays off.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail ++ "}");
        try std.testing.expect(parsed.admin_bind == null);
    }
    // Present: the bind resolves to the given IP:port.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tail ++ ",\"admin\":{\"bind\":\"127.0.0.1:9100\"}}",
        );
        try std.testing.expect(parsed.admin_bind != null);
        try std.testing.expectEqual(@as(u16, 9100), parsed.admin_bind.?.getPort());
    }
    // A hostname (or any non-literal) is rejected — DNS is a non-goal, like
    // every other bind.
    try expectParseError(error.AdminBindInvalid, head ++ tail ++ ",\"admin\":{\"bind\":\"localhost:9100\"}}");
    // The admin object is strict: `bind` is required and extras are rejected.
    try expectParseError(error.MissingField, head ++ tail ++ ",\"admin\":{}}");
    try expectParseError(error.UnknownField, head ++ tail ++ ",\"admin\":{\"bind\":\"127.0.0.1:9100\",\"x\":1}}");
}

test "config: unknown listener protocol fails loudly" {
    // A typo must not silently relay as L4.
    try expectParseError(error.ListenerProtocolUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a","protocol":"htpp"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: max_lifetime_ms still obeys the shared ceiling" {
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,"max_lifetime_ms":3600001}}
    );
}

fn expectParseError(expected: ParseError, json_bytes: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(expected, parse(arena_state.allocator(), json_bytes));
}

/// The success-path mirror of `expectParseError`: inits `arena_state`
/// (caller-owned, so the returned `Config`'s slices stay valid as long as
/// the caller needs them and `deinit` is the caller's to call) and parses
/// `json_bytes` from it. `arena_state` is `undefined` until this returns —
/// callers `defer arena_state.deinit()` right after declaring it, so
/// nothing fallible may run between that `defer` and this call, or an
/// early return would deinit an uninitialized arena.
fn expectParseOk(arena_state: *std.heap.ArenaAllocator, json_bytes: []const u8) !Config {
    arena_state.* = std.heap.ArenaAllocator.init(std.testing.allocator);
    return parse(arena_state.allocator(), json_bytes);
}

test "config: a table far past the old caps parses, and is bounded only by itself" {
    // Replaces the deleted oversize-input test, and covers what took its
    // place: 200 routes and 200 filters are each ~6x the caps that used
    // to reject them (`routes_max`/`filters_per_listener_max`, 32), and
    // the whole input is well past the 256 KiB `config_bytes_max` era's
    // intent. Nothing may cap it now but the operator's own file, so the
    // assertion is simply that it round-trips at full length.
    const route_count = 200;
    const json = comptime blk: {
        // 200 rounds of `comptimePrint` each cost far more than the
        // default 3000-branch budget allows.
        @setEvalBranchQuota(200_000);
        var routes: []const u8 = "";
        var filters: []const u8 = "";
        var index: u16 = 0;
        while (index < route_count) : (index += 1) {
            const n = std.fmt.comptimePrint("{d}", .{index});
            if (index != 0) {
                routes = routes ++ ",";
                filters = filters ++ ",";
            }
            routes = routes ++ "{\"prefix\":\"/p" ++ n ++ "\",\"cluster\":\"a\"}";
            // One header match and one action per rule — both counts the
            // per-rule caps used to bound. No header edits: the whole
            // table's edits still have to fit `header_edits_max`.
            filters = filters ++
                "{\"match\":{\"headers\":[{\"name\":\"X-K" ++ n ++ "\",\"present\":true}]}," ++
                "\"actions\":[{\"reject\":404}]}";
        }
        break :blk "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
            "\"routes\":[" ++ routes ++ "],\"filters\":[" ++ filters ++ "]}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    };
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state, json);
    try std.testing.expectEqual(@as(usize, route_count), parsed.listeners[0].routes.len);
    try std.testing.expectEqual(@as(usize, route_count), parsed.listeners[0].filters.len);
}

test "config: strictness rejects unknown and duplicate fields" {
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a","nope":1}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.DuplicateField,
        \\{"listeners":[],"listeners":[],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ClusterNameDuplicate,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]},"a":{"endpoints":["127.0.0.1:3"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.MissingField,
        \\{"clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: a `$schema` editor hint loads and is ignored" {
    // Editors point at the shipped schema by writing `$schema` into the
    // file; a strict loader that rejected it would make the schema asset
    // unusable for the very files it describes.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"$schema":"https://zoxy.io/schema/config.schema.json",
            \\ "listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        // Accepted, and it changed nothing about the resolved config.
        try std.testing.expectEqual(@as(usize, 1), parsed.listeners.len);
        try std.testing.expectEqual(@as(usize, 1), parsed.clusters.len);
    }
    // The hint buys no general laxity: a near miss is still unknown, and it
    // is only a root key — nested objects reject it like any other extra.
    try expectParseError(error.UnknownField,
        \\{"$schemas":"x",
        \\ "listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a","$schema":"x"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: references and addresses are validated" {
    try expectParseError(error.ClusterUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"missing"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // Hostnames are structurally unresolvable: static addresses only (§1).
    try expectParseError(error.EndpointInvalid,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["origin.internal:80"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointPortZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:0"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ListenerBindInvalid,
        \\{"listeners":[{"bind":"not-an-address","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ListenerBindDuplicate,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"},
        \\               {"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: every emptiness and limit has its own error" {
    try expectParseError(error.ListenersEmpty,
        \\{"listeners":[],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ClustersEmpty,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointsEmpty,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":[]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.TimeoutZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":0,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":3600001,"idle_ms":1,"drain_deadline_ms":1}}
    );
}

/// Builds a config with `count` listeners and the given `limits` body.
fn listenersJson(comptime count: u32, comptime limits: []const u8) []const u8 {
    var json: []const u8 = "{\"listeners\":[";
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        if (index > 0) json = json ++ ",";
        json = json ++ std.fmt.comptimePrint(
            \\{{"bind":"127.0.0.1:{d}","cluster":"a"}}
        , .{1000 + index});
    }
    return json ++ "]," ++ limits ++
        \\"clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
}

test "config: listeners are bounded by the ring budget, not by a count" {
    // Replaces the old over-`listeners_max` test. 64 listeners — 8x the
    // ceiling that used to refuse them — load fine at the default pools,
    // because what a listener actually costs is two ring ops.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state, comptime listenersJson(64, ""));
    try std.testing.expectEqual(@as(usize, 64), parsed.listeners.len);
}

test "config: listeners that overflow the ring budget are refused at load" {
    // The comptime `assert(in_flight_ops_max <= completion_queue_entries)`
    // this replaces could only ever speak about the ceilings. This is the
    // same arithmetic against a real config: conn slots at the ceiling
    // leave no room for a listener's two ops, so the pair is refused —
    // the startup rejection that the removed ceiling used to pre-empt.
    // Both pools at their ceilings leaves 3 of the 57344-op fill budget
    // spare at zero listeners — which is exactly what `conn_slots_max` is
    // derived to leave — so the second listener is already one too many.
    const at_ceiling = std.fmt.comptimePrint(
        "\"limits\":{{\"conn_slots\":{d},\"upstream_slots\":{d}}},",
        .{ constants.conn_slots_max, constants.upstream_slots_max },
    );
    try expectParseError(error.LimitConnSlotsOverCqFill, comptime listenersJson(2, at_ceiling));
    // One listener still fits, so the refusal above is the budget talking
    // and not the pools alone.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    _ = try expectParseOk(&arena_state, comptime listenersJson(1, at_ceiling));
}

var fuzz_arena_buffer: [1 << 20]u8 = undefined;

// Coverage-guided mode (`zig build test --fuzz`) is currently blocked by a
// Zig 0.16.0 toolchain bug: the bundled compiler/test_runner.zig fails to
// compile under -ffuzz (StackTrace type mismatch, line 566). The corpus
// still runs deterministically as part of `zig build test`.
/// A second corpus seed carrying the blocks the shipped example leaves to
/// their defaults. The example is the better *documentation* for having
/// dropped its `timeouts` block, but a corpus seed is judged on the token
/// vocabulary it hands the mutator, and one that never spells
/// `drain_deadline_ms` gives it no path to that branch of the parser.
const fuzz_seed_json =
    \\{"listeners":[{"bind":"127.0.0.1:8080","routes":[{"prefix":"/","cluster":"o"}],
    \\ "protocol":"http"}],
    \\ "clusters":{"o":{"endpoints":["127.0.0.1:9000"],"pick":"p2c","max_inflight":8,
    \\ "check":{"type":"http","path":"/health","expect_status":200,"timeout_ms":250}}},
    \\ "timeouts":{"connect_ms":5000,"idle_ms":60000,"drain_deadline_ms":10000,
    \\ "max_lifetime_ms":300000,"request_ms":30000,"health_interval_ms":2000},
    \\ "limits":{"conn_slots":64,"relay_buffers":32,"upstream_slots":32},
    \\ "access_log":{"sink":"file","path":"/var/log/zoxy.log"},
    \\ "admin":{"bind":"127.0.0.1:9901"}}
;
// The `file` arm here, `stdout` in `example_json` beside it: between the
// two corpus entries the mutator sees every sink spelling, including the
// `path` key only one of them may carry.

test "config: the fuzz seed carrying every block parses" {
    // It is a corpus entry, so it has to be a *valid* config — an
    // unparseable seed would still fuzz, just from a worse starting point,
    // and nothing else would say so.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state, fuzz_seed_json);
    try std.testing.expectEqual(@as(u32, 10000), parsed.drain_deadline_ms);
    try std.testing.expectEqual(@as(u32, 30000), parsed.request_timeout_ms);
}

test "fuzz: parse never panics — parse or reject, no third outcome" {
    try std.testing.fuzz({}, fuzzParse, .{ .corpus = &.{ example_json, fuzz_seed_json } });
}

fn fuzzParse(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input_buffer: [4096]u8 = undefined;
    const input_len = smith.slice(&input_buffer);
    assert(input_len <= input_buffer.len);
    const input = input_buffer[0..input_len];

    var fixed = std.heap.FixedBufferAllocator.init(&fuzz_arena_buffer);
    if (parse(fixed.allocator(), input)) |parsed| {
        // Success implies the resolved invariants hold — no third outcome.
        assert(parsed.listeners.len >= 1);
        assert(parsed.clusters.len >= 1);
        // The deadline handoff's ordering (§4/§5) is a property of every
        // config that loads, so the fuzzer checks it here rather than
        // trusting that the one rejecting branch was reached.
        assert(parsed.connect_timeout_ms < parsed.idle_timeout_ms);
        for (parsed.listeners) |listener| {
            assert(listener.routes.len >= 1);
            for (listener.routes) |route| {
                assert(route.cluster_index < parsed.clusters.len);
                assert(route.prefix.len >= 1);
                assert(route.prefix[0] == '/');
            }
        }
    } else |_| {}
}

test "config: the access-log block resolves a sink, absent leaves it off" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"a\"}],";

    // Absent: the log stays off and reserves nothing. The buffer size is
    // zero exactly then, which is how `accessLogBytes` reads "off" off one
    // number instead of needing the sink beside it (§5, §8).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail ++ "}");
        try std.testing.expect(parsed.access_log_sink == null);
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.access_log_buffer_bytes);
    }
    // Present: the sink resolves and the staging buffers take the default.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tail ++ ",\"access_log\":{\"sink\":\"stdout\"}}",
        );
        try std.testing.expect(parsed.access_log_sink.? == .stdout);
        try std.testing.expectEqual(
            constants.access_log_buffer_bytes_default,
            parsed.limits.access_log_buffer_bytes,
        );
    }
    // A file sink carries its path through to the resolved union.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tail ++ ",\"access_log\":{\"sink\":\"file\",\"path\":\"/var/log/zoxy.log\"}}",
        );
        try std.testing.expect(parsed.access_log_sink.? == .file);
        try std.testing.expectEqualStrings(
            "/var/log/zoxy.log",
            parsed.access_log_sink.?.file,
        );
        try std.testing.expectEqual(
            constants.access_log_buffer_bytes_default,
            parsed.limits.access_log_buffer_bytes,
        );
    }
    // A sized buffer alongside a sink resolves verbatim.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tail ++ ",\"access_log\":{\"sink\":\"stdout\"}," ++
                "\"limits\":{\"access_log_buffer_bytes\":65536}}",
        );
        try std.testing.expectEqual(@as(u32, 65536), parsed.limits.access_log_buffer_bytes);
    }

    // The sink vocabulary is closed: an unnamed one fails at load rather
    // than silently logging somewhere the operator did not ask for.
    try expectParseError(
        error.AccessLogSinkUnknown,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"syslog\"}}",
    );
    // The block is strict like every other: `sink` required, extras rejected.
    try expectParseError(error.MissingField, head ++ tail ++ ",\"access_log\":{}}");
    // `path` belongs to exactly the sink that uses it: beside `stdout` it
    // describes something that cannot happen, and a `file` sink without
    // one (or with an empty one) names no file at all. The
    // `ClusterCheckHttpFieldOnTcp` rule, applied here.
    try expectParseError(
        error.AccessLogPathOnStdout,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"stdout\",\"path\":\"/tmp/x\"}}",
    );
    try expectParseError(
        error.AccessLogPathMissing,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"file\"}}",
    );
    try expectParseError(
        error.AccessLogPathMissing,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"file\",\"path\":\"\"}}",
    );
    // A buffer below one worst-case line would drop lines it had room for,
    // which is the one thing a drop must never mean; above the ceiling is
    // memory nobody asked to reserve.
    try expectParseError(
        error.LimitAccessLogBufferOutOfRange,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"stdout\"}," ++
            "\"limits\":{\"access_log_buffer_bytes\":16}}",
    );
    try expectParseError(
        error.LimitAccessLogBufferOutOfRange,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"stdout\"}," ++
            "\"limits\":{\"access_log_buffer_bytes\":99999999}}",
    );
    // Sizing buffers for a log that was never turned on is a contradiction,
    // and is told so rather than quietly getting no log.
    try expectParseError(
        error.LimitAccessLogBufferWithoutSink,
        head ++ tail ++ ",\"limits\":{\"access_log_buffer_bytes\":65536}}",
    );
}

test "config: a cluster name is bounded, because the access log echoes it" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"";
    const long_name = "n" ** (constants.cluster_name_bytes_max + 1);
    const at_limit = "n" ** constants.cluster_name_bytes_max;

    // At the cap it resolves; one byte over fails. Without the bound a log
    // line's width would be a function of the config file rather than of
    // constants.zig (§8).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ at_limit ++ "\"}],\"clusters\":{\"" ++ at_limit ++
                "\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
                "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
        );
        try std.testing.expectEqual(@as(usize, constants.cluster_name_bytes_max), parsed.clusters[0].name.len);
    }
    try expectParseError(
        error.ClusterNameTooLong,
        head ++ long_name ++ "\"}],\"clusters\":{\"" ++ long_name ++
            "\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
    // An empty name names nothing and would render as `"cluster":""`.
    try expectParseError(
        error.ClusterNameEmpty,
        head ++ "\"}],\"clusters\":{\"\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
}

test "config: the hash pick policy and its key resolve, or fail loudly" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"a\"}],\"clusters\":{\"a\":{";
    const tail = "}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const endpoints = "\"endpoints\":[\"127.0.0.1:2\"]";

    // `pick: hash` with no `hash` block takes the default key, so the
    // common case needs no second line of config.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ endpoints ++ ",\"pick\":\"hash\"" ++ tail,
        );
        try std.testing.expectEqual(Config.Cluster.Pick.hash, parsed.clusters[0].pick);
        try std.testing.expectEqual(Config.Cluster.HashKey.source_ip, parsed.clusters[0].hash_key);
    }
    // Naming the key explicitly resolves to the same thing.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ endpoints ++ ",\"pick\":\"hash\",\"hash\":{\"key\":\"source_ip\"}" ++ tail,
        );
        try std.testing.expectEqual(Config.Cluster.HashKey.source_ip, parsed.clusters[0].hash_key);
    }
    // A cluster that says nothing keeps the p2c default and the default
    // key, which is inert there.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ endpoints ++ tail);
        try std.testing.expectEqual(Config.Cluster.Pick.p2c, parsed.clusters[0].pick);
    }

    // A `hash` block beside another policy is a request for stickiness the
    // cluster would silently not provide — the mistake most worth catching
    // at load rather than in production.
    try expectParseError(
        error.ClusterHashWithoutHashPick,
        head ++ endpoints ++ ",\"pick\":\"rr\",\"hash\":{\"key\":\"source_ip\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterHashWithoutHashPick,
        head ++ endpoints ++ ",\"hash\":{\"key\":\"source_ip\"}" ++ tail,
    );
    // The key vocabulary is closed, and distinct from the policy's own
    // error so a typo says which field it is in.
    try expectParseError(
        error.ClusterHashKeyUnknown,
        head ++ endpoints ++ ",\"pick\":\"hash\",\"hash\":{\"key\":\"cookie\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickUnknown,
        head ++ endpoints ++ ",\"pick\":\"hsah\"" ++ tail,
    );
    // The block is strict like every other: unknown fields are rejected
    // rather than ignored.
    try expectParseError(
        error.UnknownField,
        head ++ endpoints ++ ",\"pick\":\"hash\",\"hash\":{\"key\":\"source_ip\",\"mask\":24}" ++ tail,
    );
}

test "config: max_inflight resolves, defaults to uncapped, rejects the useless" {
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"max_inflight":64},
            \\   "b":{"endpoints":["127.0.0.1:3"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(@as(?u32, 64), parsed.clusters[0].max_inflight);
        // Absent is uncapped, which is the only spelling of "no limit".
        try std.testing.expectEqual(@as(?u32, null), parsed.clusters[1].max_inflight);
    }
    // Zero would refuse every request to an idle endpoint, and a value
    // past the largest representable load could never refuse one —
    // both are typos rather than intents (§8).
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"max_inflight":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    try expectParseError(error.ClusterMaxInflightOutOfRange, head ++ "0" ++ tail);
    try expectParseError(error.ClusterMaxInflightOutOfRange, head ++ "4294967295" ++ tail);
    // The ceiling itself is legal, and deliberately so: it is reachable
    // only if every conn and upstream slot in the process piles onto one
    // endpoint, which is a real (if extreme) shape rather than a no-op.
    {
        var buffer: [512]u8 = undefined;
        const json = try std.fmt.bufPrint(
            &buffer,
            "{s}{d}{s}",
            .{ head, constants.endpoint_inflight_max, tail },
        );
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, json);
        try std.testing.expectEqual(
            @as(?u32, constants.endpoint_inflight_max),
            parsed.clusters[0].max_inflight,
        );
    }
}

test "config: the forwarded block resolves a mode, and is http-only" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"a\"";
    const tail = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent: the header is untouched, which is what every config that
    // predates this feature must keep doing.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ ",\"protocol\":\"http\"" ++ tail);
        try std.testing.expect(parsed.listeners[0].forwarded == null);
    }
    // Both modes resolve; neither is a default.
    inline for (.{ "replace", "append" }) |mode| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ ",\"protocol\":\"http\",\"forwarded\":{\"mode\":\"" ++ mode ++ "\"}" ++ tail,
        );
        try std.testing.expectEqual(
            std.meta.stringToEnum(Config.Listener.Forwarded, mode).?,
            parsed.listeners[0].forwarded.?,
        );
    }

    // An l4 listener has no header to carry an address, so asking for one
    // describes a proxy that is not running — rejected, like `filters`.
    try expectParseError(
        error.ListenerL4Forwarded,
        head ++ ",\"forwarded\":{\"mode\":\"replace\"}" ++ tail,
    );
    try expectParseError(
        error.ListenerL4Forwarded,
        head ++ ",\"protocol\":\"l4\",\"forwarded\":{\"mode\":\"replace\"}" ++ tail,
    );
    // The mode vocabulary is closed and `mode` is required: there is no
    // safe default to fall back to, which is the whole point.
    try expectParseError(
        error.ListenerForwardedModeUnknown,
        head ++ ",\"protocol\":\"http\",\"forwarded\":{\"mode\":\"trust\"}" ++ tail,
    );
    try expectParseError(
        error.MissingField,
        head ++ ",\"protocol\":\"http\",\"forwarded\":{}" ++ tail,
    );
}

test "config: the proxy_protocol block resolves a mode, and is l4-only" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"a\"";
    const tail = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent: first bytes are payload — every config predating this.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expect(parsed.listeners[0].proxy_protocol == null);
    }
    // The one mode resolves, on the defaulted protocol and stated l4 alike.
    inline for (.{ "", ",\"protocol\":\"l4\"" }) |protocol_field| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ protocol_field ++ ",\"proxy_protocol\":{\"mode\":\"require\"}" ++ tail,
        );
        try std.testing.expectEqual(
            Config.Listener.ProxyProtocol.require,
            parsed.listeners[0].proxy_protocol.?,
        );
    }
    // The L7 path has no receive phase yet, so a block there would state
    // a trust boundary nothing enforces — rejected, not ignored.
    try expectParseError(
        error.ListenerHttpProxyProtocol,
        head ++ ",\"protocol\":\"http\",\"proxy_protocol\":{\"mode\":\"require\"}" ++ tail,
    );
    // The mode vocabulary is closed and `mode` is required; sniffing
    // ("optional") is deliberately not in it — a listener that accepts
    // header-or-raw-bytes lets any client choose its own address.
    try expectParseError(
        error.ListenerProxyProtocolModeUnknown,
        head ++ ",\"proxy_protocol\":{\"mode\":\"optional\"}" ++ tail,
    );
    try expectParseError(
        error.MissingField,
        head ++ ",\"proxy_protocol\":{}" ++ tail,
    );
}

test "config: a filter may not name the header zoxy manages" {
    // A filter edit can only write a *constant*, so naming this header
    // encodes one fixed address for every client — it looks like client
    // forwarding and is the opposite of it. Reserved unconditionally, not
    // only on listeners that set it, so one mechanism owns the header.
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\",\"cluster\":\"a\",\"filters\":[";
    const tail = "]}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    inline for (.{ "header_set", "header_add" }) |action| {
        try expectParseError(error.FilterHeaderNameReserved, head ++
            "{\"actions\":[{\"" ++ action ++
            "\":{\"name\":\"X-Forwarded-For\",\"value\":\"1.2.3.4\"}}]}" ++ tail);
    }
    // Case-insensitively, per RFC 9110 field-name comparison.
    try expectParseError(error.FilterHeaderNameReserved, head ++
        "{\"actions\":[{\"header_remove\":\"x-forwarded-for\"}]}" ++ tail);
    // A neighbouring name is still editable — the guard is the header, not
    // a prefix of it.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++
            "{\"actions\":[{\"header_set\":{\"name\":\"X-Forwarded-Proto\",\"value\":\"https\"}}]}" ++ tail);
        try std.testing.expectEqual(@as(usize, 1), parsed.listeners[0].filters.len);
    }
}
