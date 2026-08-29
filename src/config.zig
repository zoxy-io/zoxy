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
const sni_router = @import("net/sni_router.zig");
const filter = @import("http/filter.zig");
const parser = @import("http/parser.zig");
const render = @import("http/render.zig");
const shed = @import("shed.zig");
const io_module = @import("io/io.zig");
const json_schema = @import("json_schema.zig");

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
    /// Budget for reading one request head (§8, #235): from the client's
    /// first byte to a complete head, which is a slowloris's whole window.
    /// Distinct from `idle_timeout_ms`, which bounds a *quiet* connection
    /// — the two want opposite values, and one number serving both meant
    /// the head-read budget inherited whatever the keep-alive window was
    /// tuned to. Rebased down from the idle deadline at the first byte,
    /// and down again to `connect_timeout_ms` at the dial.
    ///
    /// No struct default, on the same terms as `request_timeout_ms`: the
    /// loader *derives* one from this config's own neighbours, and a flat
    /// fallback here would hand a hand-built config a ten-second head
    /// budget beside a millisecond idle window — the very inversion the
    /// loader refuses, and one nothing else would notice.
    head_timeout_ms: u32,
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
    /// Bound on one tunnel's whole life (§8, #180), replacing `idle_ms`,
    /// `request_ms` and `max_lifetime_ms` from the moment a connection
    /// becomes one. Not a fourth clock running beside them: each of those
    /// would cut a healthy session — `idle_ms` defaults to 60 s, and a
    /// WebSocket's keepalive is application-layer ping/pong this proxy
    /// cannot see, because after `101` the bytes are opaque by
    /// construction. Unlike `max_lifetime_ms` and `request_ms`, zero is
    /// **not** legal: a tunnel holds a dedicated pool slot for its whole
    /// life, and an unbounded hold on a bounded pool is the one thing
    /// that model cannot absorb. Inert when no listener allows upgrades.
    ///
    /// No struct default, deliberately, on the same terms as
    /// `request_timeout_ms`: a hand-built config that forgot this would
    /// otherwise run a real one-hour deadline nobody asked for, and a
    /// silently-inherited deadline is exactly what the absent defaults
    /// on the other caps exist to prevent.
    tunnel_timeout_ms: u32,
    /// Pause between §7 health-probe sweeps over every `check` cluster's
    /// endpoints. Probing itself is enabled per cluster (`Cluster.check`);
    /// this only paces it, so it is optional in the JSON and defaults to
    /// HAProxy's `inter` (`constants.health_interval_ms_default`). Zero is
    /// rejected — a pause of nothing would probe in a tight loop. Each
    /// probe dials under `connect_timeout_ms`, its own budget.
    ///
    /// Here and not in the cluster's `check` block beside `fall`, `rise`
    /// and `timeout_ms`, which #305 asked about. Those three are per
    /// cluster; this is not. There is one sweep and one rest timer for
    /// the whole process, pacing sweep-end to sweep-start across every
    /// checked cluster at once, and §5's closed-form probe reservation
    /// is derived from there being exactly one. A per-cluster interval
    /// would be a per-cluster prober — a different design and a
    /// different budget, not a tidier config.
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
    /// The #159 error pages: complete responses pre-rendered at load,
    /// one entry per configured status, empty when none are. Serving
    /// one is byte-for-byte the comptime-static path — one send from
    /// immutable memory, no acquisition — which is the whole point: an
    /// error page whose delivery needed a pool would fail exactly when
    /// it is needed. Configuring a status is also the opt-in for bodies
    /// on its sheds; absent, shedding costs what it does today.
    ///
    /// By pointer into the load-time render cache: a body serving a
    /// page here and a `respond` action there is rendered once and
    /// pointed at twice — #159's one-body-one-buffer contract.
    error_pages: []const *const StaticPage = &.{},
    /// The headers each access-log line records (#140), lowercased and
    /// deduplicated at load, empty when none are named. Read on the
    /// capture paths, so the request list is what an http line's
    /// `request_headers` object carries and the response list its
    /// `response_headers` — and their summed length is what widens the
    /// line bound this config's staging buffer was checked against.
    access_log_request_headers: []const []const u8 = &.{},
    access_log_response_headers: []const []const u8 = &.{},
    /// Where access-log lines go (§8), or null when no `access_log` block
    /// is configured — the log stays off and reserves nothing.
    access_log_sink: ?AccessLogSink = null,

    /// Endpoints under §7 active checks: the sum of `endpoints.len` over
    /// every cluster that set a `check` block. Both the prober's own
    /// `checked_count` and — through `constants.healthProbeConcurrency`
    /// — its ring and fd reservations are functions of this, so it is
    /// derived in one place rather than counted separately by the prober
    /// and the budget, which is exactly the drift §5 warns the closed
    /// form must not have.
    pub fn checkedEndpoints(config: *const Config) u32 {
        return checkedEndpointsOf(config.clusters);
    }

    /// The prober's effective probe count for this config (§7, #132) —
    /// what the ring and fd budgets reserve, and how many `Probe`s
    /// `health.Checker` allocates.
    pub fn healthProbes(config: *const Config) u32 {
        return constants.healthProbeConcurrency(config.checkedEndpoints());
    }

    /// Clusters that could lose an endpoint and would never notice: more
    /// than one endpoint, and neither `check` nor `passive_ejection`
    /// (§7, #230). The §5 banner states this as a fact, not a warning,
    /// and that is the point — a multi-endpoint cluster with no failure
    /// detection is legitimate behind a mesh, or when the endpoints are
    /// themselves VIPs, so warning every startup would teach operators
    /// to ignore the stream the banner and the exit tally share.
    ///
    /// Clusters with fewer than two endpoints a request could actually
    /// be sent to are excluded deliberately: there is nowhere to eject
    /// *to*, and §7 fail-open makes the ejection a no-op there, so
    /// counting them would make the number noise on exactly the configs
    /// it has nothing to say about.
    ///
    /// "Could be sent to" means weight, not list length. A weight of `0`
    /// **drains** an endpoint — it never enters the eligible set — and
    /// config is loaded once and never reloaded, so a two-endpoint
    /// cluster at weights `[1, 0]` has exactly one reachable endpoint
    /// for the life of the process. That is the single-endpoint case
    /// under a different spelling, and flagging it would be the same
    /// noise by a longer route.
    pub fn clustersWithoutFailureDetection(config: *const Config) u32 {
        var total: u32 = 0;
        for (config.clusters) |cluster| {
            if (cluster.check != null or cluster.passive_ejection != null) continue;
            if (reachableEndpoints(&cluster) < 2) continue;
            total += 1;
        }
        assert(total <= config.clusters.len);
        return total;
    }

    /// Endpoints of a cluster that any pick may return — those left
    /// undrained by a non-zero weight (§7). An absent `weights` list is
    /// the homogeneous case, where every endpoint carries weight one.
    fn reachableEndpoints(cluster: *const Cluster) u32 {
        const weights = cluster.weights orelse return @intCast(cluster.endpoints.len);
        assert(weights.len == cluster.endpoints.len);
        var reachable: u32 = 0;
        for (weights) |weight| {
            if (weight != 0) reachable += 1;
        }
        // The loader rejects an all-zero cluster, so a cluster always
        // has somewhere to send a request even if not somewhere to eject
        // to (`EndpointWeightsAllZero`).
        assert(reachable >= 1);
        return reachable;
    }

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

    /// One pre-rendered #159 page, defined beside the static-response
    /// machinery it joins (`shed.StaticPage`) because the filter table
    /// carries these too and cannot import this module.
    pub const StaticPage = shed.StaticPage;

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
        /// Bytes per relay direction (§6); a pair costs twice this, and
        /// `relay_buffers` + `tunnels` pairs are reserved. Sets how many
        /// round trips a body costs — a 256 KiB response is 16 at the
        /// 16 KiB default and 64 at 4 KiB — and, because
        /// `tls_app_chunk_bytes` rides the same number, the size of the
        /// TLS records a terminating listener emits.
        ///
        /// Lower it when concurrency matters more than bulk: the c10k
        /// ceiling multiplies this by 11457 pairs, so 4 KiB is ~90 MiB of
        /// relay pool where the default is ~358. Raising it past one TLS
        /// record is refused; see `relay_buffer_bytes_max` for why that
        /// bound is the transform's and not the RFC's.
        relay_buffer_bytes: u32 = constants.relay_buffer_bytes_default,
        /// The §4 TLS engine pool: how many sessions may be handshaking
        /// or terminated at once. An engine is ~91 KiB plus a plaintext
        /// buffer, far the largest per-connection object here, so this is
        /// the knob that decides what a TLS deployment costs in RSS. The
        /// loader resolves an omitted field to conn slots capped at
        /// `tls_engines_max`; the operator trades it down against a
        /// handshake wall, on the same terms as every other pool (§8).
        /// Zero exactly when no listener
        /// terminates TLS, and the struct default is the off state on the
        /// same terms as `head_buffers`.
        tls_engines: u32 = 0,
        /// Requests one client connection may serve before the next
        /// response announces `Connection: close` (#237); `0` is
        /// unlimited.
        ///
        /// In `limits` rather than beside a listener's policy, and the
        /// distinction is the one `max_body_bytes` draws from the other
        /// side: a body cap states what an *origin* should be asked to
        /// carry, while this bounds what one client may occupy *here*.
        /// `cq_fill_eighths` sits in this block on the same terms — not a
        /// pool size, but a knob about this process's own resources.
        keepalive_requests: u32 = constants.keepalive_requests_default,
        /// The §5 tunnel pool (#180): how many upgraded connections may be
        /// carried at once, each holding its own relay buffer and upstream
        /// socket for its whole life rather than drawing from the shared
        /// pools — which is the point, since a tunnel has the opposite
        /// shape to everything those pools are sized for.
        ///
        /// Alone among the optional pools it has **no derived default**.
        /// The others resolve to a worst case that cannot shed — every
        /// connection mid-head, every leased slot holding one head — and
        /// a count derived that way is safe because it can only be too
        /// generous. There is no such number here: how many long-lived
        /// sessions an origin fleet should carry is a capacity decision
        /// with no honest guess available from a connection count, so a
        /// listener that allows upgrades without one is rejected at load.
        /// Zero exactly when no listener allows any upgrade.
        tunnels: u32 = 0,
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
        bind_address: io_module.Address,
        /// The #303 permission bits for a `unix:` bind's socket file, or
        /// null for the umask's default. Always null on an IP bind.
        bind_mode: ?io_module.FileMode,
        /// The §7 path-routing table, sorted longest-prefix-first and
        /// never empty. A listener configured with a single `"cluster"`
        /// resolves to one catch-all route (`prefix = "/"`); `l4`
        /// listeners always have exactly that one route (no path to
        /// match). Matched by `http/router.zig`.
        routes: []const router.Route,
        /// The §6 SNI table (#298), sorted named-first and never empty on
        /// a listener that routes by name — empty on every other, which
        /// is what says the peek phase does not run. Matched by
        /// `net/sni_router.zig`.
        ///
        /// `routes` above still carries one entry for such a listener,
        /// because admission needs *a* cluster before any byte is read
        /// (`Server.listeners[i].cluster_index`). It is the any-name
        /// route's cluster where the config declared one, and the first
        /// route's otherwise; either way it is provisional, and the peek
        /// replaces it before a dial can consume it — the same
        /// admit-then-refine §7 already does when a request's path picks
        /// a different route than the listener was admitted under.
        sni_routes: []const sni_router.Route = &.{},
        /// The §7 request filter rules, in config order (evaluated top-down).
        /// Empty on the L4 path and whenever no `"request_filters"` were given.
        /// Compiled and interpreted by `http/filter.zig`.
        request_filters: []const filter.Rule = &.{},
        /// The #175 response filter rules, same discipline on the way
        /// out: empty on the L4 path and whenever no `"response_filters"`
        /// were given. Compiled by this loader, matched by
        /// `http/filter.zig`; the response re-render's application is
        /// #175's next slice — until it lands, a compiled table is
        /// carried but consulted by nothing.
        response_filters: []const filter.ResponseRule = &.{},
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
        /// Whether this listener terminates TLS, and with what (§4, #125),
        /// or null for a plaintext socket — every config predating this.
        /// Per listener, like `forwarded` and `proxy_protocol`: it states
        /// what this socket is, and the same cluster is commonly reachable
        /// from a TLS edge listener and a plaintext internal one.
        ///
        /// Inbound only. The upstream leg stays plaintext whatever this
        /// says; originating TLS to a backend is a separate decision with
        /// its own trust store, and #125 is termination.
        tls: ?Tls = null,
        /// Which protocol upgrades this listener will carry as tunnels
        /// (§7, #180). Empty by default — an `Upgrade` naming nothing
        /// here is `501`, which is what every config predating this
        /// keeps getting. Per listener, like `forwarded` and `tls`, and
        /// for the stronger version of the same reason: after `101` the
        /// stream is opaque and no filter, route or header rule on this
        /// listener applies to another byte of it, so which sockets may
        /// hand out that exemption is a property of the socket.
        upgrades: Upgrades = .{},
        /// Whether refusals name their RFC 9209 cause on the wire
        /// (#300). Per listener and off by default, on `forwarded`'s
        /// reasoning: the header states which of *this proxy's* limits a
        /// client hit, which is a diagnostic inside a mesh and a
        /// disclosure at an edge — and a proxy cannot tell from the
        /// inside which side of that line it is on.
        proxy_status: bool = false,
        /// Cap on one request's body (#236), or `0` to accept any size.
        ///
        /// Per listener rather than in `limits`, and the distinction is
        /// §5's own: `limits` sizes what this process *reserves*, and a
        /// body cap reserves nothing — it states policy, which is the
        /// footing `forwarded` and `upgrades` already stand on. One
        /// listener fronting an upload endpoint and another fronting an
        /// API want different numbers, and neither is a pool.
        max_body_bytes: u64 = constants.request_body_bytes_default,
        /// Requests one client connection may serve before the next
        /// response announces `Connection: close` (#237); `0` is
        /// unlimited.
        ///
        /// Here for the reason above, applied to the field that used to
        /// be the rule's standing exception (#305): a request count
        /// reserves nothing either. It lived in `limits` on the argument
        /// that a body cap states what an *origin* is asked to carry
        /// while this bounds what a client occupies *here* — true, and
        /// beside the point, since neither is a pool. One listener
        /// fronting long-lived browser connections and another fronting
        /// a service mesh want different numbers, which is the same
        /// shape of answer as the cap above.
        keepalive_requests: u32 = constants.keepalive_requests_default,

        /// The upgrade tokens a listener may allow, as a set rather than
        /// a list: the vocabulary is closed, so membership is a field
        /// and not an arena slice to bound.
        ///
        /// Closed deliberately, and it is the §7 "closed action enum"
        /// instinct rather than a shortcut. A token this proxy does not
        /// name is one it cannot reason about: `h2c` would tunnel HTTP/2
        /// to an origin it cannot parse, past every rule the config
        /// expresses. Adding a token is therefore a code decision, made
        /// once with its consequences understood, not a string an
        /// operator can invent.
        pub const Upgrades = struct {
            websocket: bool = false,

            /// Whether this listener allows any upgrade at all — what
            /// decides whether a `limits.tunnels` is required (§5) and
            /// whether the §7 gate has anything to consult.
            pub fn any(upgrades: Upgrades) bool {
                return upgrades.websocket;
            }
        };

        /// What the listener speaks (§6, §7): `l4` relays bytes blindly,
        /// `http` runs the HTTP/1.1 reverse-proxy state machine.
        ///
        /// Named in the config by the key the listener's settings live
        /// under, and required (#305). It was once an optional string
        /// defaulting to `l4` — a pre-L7 compatibility default that the
        /// freeze was the last chance to remove, and whose absence a
        /// reverse proxy would have kept reading as "relay blindly".
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

        /// Where this listener's certificate and key live (§4). Paths
        /// only: this loader is IO-free (§1), so it validates the shape
        /// and `main` does the reading — which is also what puts a
        /// missing or malformed certificate in the startup error that
        /// names the file, rather than in the first client's handshake.
        pub const Tls = struct {
            /// PEM certificate chain, leaf first.
            cert_path: []const u8,
            /// PEM private key for the leaf. ECDSA P-256 or P-384; any
            /// other key type is refused at load (`tls/Credentials.zig`).
            key_path: []const u8,
        };
    };

    pub const Cluster = struct {
        name: []const u8,
        endpoints: []const io_module.Address,
        /// Per-endpoint §7 pick weights, parallel to `endpoints` — or
        /// null when every endpoint carries the default weight of 1,
        /// which is what the bare-string config form says and what most
        /// clusters are, so the loader only materializes the table when
        /// some weight differs. A weight of `0` drains its endpoint:
        /// still probed (§7), never picked — the balancer treats it as
        /// administratively out, so not even fail-open reaches it.
        weights: ?[]const u16 = null,
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
        /// §7 passive ejection for this cluster (#230), or null to leave
        /// it off. Independent of `check`: the two compose rather than
        /// overlap, since real traffic is the only signal that catches a
        /// backend whose kernel still completes the handshake while the
        /// application behind it never answers — a wedged process, an
        /// exhausted thread pool, a GC stall. That is precisely what a
        /// `tcp` probe cannot see, because the backlog accepts for it.
        passive_ejection: ?PassiveEjection = null,
        /// The §8 concurrency cap protecting each of this cluster's
        /// endpoints, or null for uncapped. **Per endpoint, not per
        /// cluster**: it is a statement about what one origin can carry,
        /// the same unit HAProxy's `server ... maxconn` names, so a
        /// cluster's total admitted work is this times its endpoint
        /// count. Counted against the endpoint's in-flight total —
        /// L7 requests and live L4 connections alike (§7).
        max_inflight: ?u32 = null,

        /// How many further endpoints one request may dial after a
        /// refused or unreachable first try (#181), 0 for none — the
        /// default, and what every config predating this key keeps
        /// doing. Bounded by `cluster_retries_max`. Only the L7 path
        /// spends it: an L4 connection dials once and relays whatever
        /// the dial produced, with no request to send somewhere else.
        retries: u16 = 0,

        /// What a `hash` cluster keys its endpoint choice on (§7, #178).
        /// Read only when `pick == .hash`; the loader rejects key
        /// settings beside any other policy rather than leaving them
        /// inert — and rejects a bare `"pick": "hash"` outright, because
        /// which identity a cluster is sticky on is a decision, not a
        /// default.
        hash_key: HashKey = .source_ip,

        /// The PROXY protocol header this cluster's origins expect zoxy
        /// to open every upstream connection with (#142 send), or null
        /// for none. Per *cluster* — HAProxy's `send-proxy` unit — since
        /// it states what the origin reads, not who connects. Only `l4`
        /// listeners may route here: a pooled L7 upstream is shared
        /// across clients (§3), and a per-connection header cannot name
        /// one client — rejected at load, not silently ignored.
        proxy_protocol_send: ?ProxyProtocolSend = null,

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

        /// The identity a `hash` cluster is sticky on (#178). `header`
        /// and `cookie` read the parsed request, so clusters carrying
        /// them are unreachable from `l4` listeners — enforced where
        /// listeners resolve, the `proxy_protocol_send` precedent in
        /// the other direction.
        pub const HashKey = union(enum) {
            /// The client's own address, which both data paths have —
            /// an L4 connection has nothing else, and an L7 request need
            /// not have been parsed yet.
            source_ip,
            /// Rendezvous on the named header's value: stickiness on an
            /// identity the client states (a tenant, an API key hash) —
            /// which survives NAT, the exact place `source_ip` fails.
            /// The payload is the validated header name.
            header: []const u8,
            /// The client holds the assignment itself (#178): the named
            /// cookie carries an endpoint tag in the proxy's own minted
            /// spelling, honoured when it names a healthy,
            /// under-capacity endpoint — with the response-side stamp
            /// owing the client a (re-)announcement everywhere else.
            /// The payload is the validated cookie name.
            cookie: []const u8,
        };

        /// Which PROXY protocol version to write (#142): a closed
        /// vocabulary rather than a bool because the wire formats differ
        /// and the *origin's* parser — not zoxy — decides which it
        /// reads. v2 is what cloud load balancers speak; v1 is
        /// human-readable in a tcpdump.
        pub const ProxyProtocolSend = enum(u1) {
            v1,
            v2,
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

        /// One cluster's resolved passive-ejection policy (§7, #230):
        /// eject an endpoint that real traffic says is dead, rather than
        /// only one a probe caught.
        ///
        /// Opt-in for the same reason `check` is. It removes capacity by
        /// inference: the failure it prevents is visible and diagnosable,
        /// while the failure it can cause — ejecting a healthy backend
        /// during a blip — is subtle and worse. That is an operator's
        /// call, not a default.
        ///
        /// The two signals it acts on are the endpoint's own fault in a
        /// way a `5xx` is not: a dial that failed, and an exchange that
        /// produced no response byte before the deadline. A bad deploy
        /// answering 500s is a software bug, not an unhealthy endpoint,
        /// and conflating them would eject a whole cluster for it.
        pub const PassiveEjection = struct {
            /// Consecutive failed requests that eject. An absolute count
            /// is sufficient here where Envoy needs success-rate
            /// outlier detection, because §7 fail-open already answers
            /// the correlated-failure objection: a cluster with every
            /// endpoint ejected balances as if none were.
            fall: u8 = constants.passive_ejection_fall_default,
            /// How long an ejected endpoint stays out before traffic is
            /// admitted again to re-judge it. Passive detection needs
            /// traffic to learn anything and an ejected endpoint gets
            /// none, so recovery cannot be passive too — this cooldown
            /// is what makes it observable at all.
            recovery_ms: u32 = constants.passive_ejection_recovery_ms_default,
        };
    };
};

pub const ValidationError = error{
    ListenersEmpty,
    ListenersOverLimit,
    ListenerBindInvalid,
    /// A `unix:` bind path that is empty, past what a `sockaddr_un`
    /// carries, or carries a byte an address may not (#303).
    ListenerBindUnixPathInvalid,
    /// A `unix:` bind path that is not absolute (#303).
    ListenerBindUnixPathRelative,
    /// A `mode` on a listener whose `bind` is an IP literal (#303):
    /// there is no file to chmod.
    ListenerModeWithoutUnixBind,
    /// A `mode` that is not three or four octal digits, or that sets
    /// setuid/setgid/sticky (#303).
    ListenerModeInvalid,
    /// A `unix:` listener with a `forwarded` block (#303): there is no
    /// client address to state.
    ListenerUnixBindForwarded,
    /// A `unix:` listener with a filter matching on the client address
    /// (#303): there is none to match.
    ListenerUnixBindClientMatch,
    /// A `unix:` listener routing to a cluster that is sticky on the
    /// source IP (#303): there is none to key on.
    ListenerUnixBindSourceIpHash,
    /// A `unix:` listener routing to a cluster that announces a PROXY
    /// header upstream (#303): the header names the client's source and
    /// destination addresses, and this listener has neither.
    ListenerUnixBindClusterSend,
    ListenerBindDuplicate,
    ListenerHttpOrL4,
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
    ClusterPassiveEjectionFallOutOfRange,
    ClusterPassiveEjectionRecoveryOutOfRange,
    ClusterMaxInflightOutOfRange,
    ClusterRetriesOutOfRange,
    ClusterPickKeyMissing,
    ClusterPickKeyUnknown,
    ClusterPickKeyWithoutHash,
    ClusterPickNameMissing,
    ClusterPickNameUnexpected,
    ClusterPickNameInvalid,
    ClusterPickNameTooLong,
    ListenerL4RequestKeyedHash,
    BodiesOverLimit,
    BodyNameEmpty,
    BodyNameTooLong,
    BodyNameDuplicate,
    BodySourceMissing,
    BodySourceAmbiguous,
    BodyContentTypeInvalid,
    BodyFileUnreadable,
    BodyOverLimit,
    BodyUnknown,
    AccessLogHeadersOverLimit,
    AccessLogHeaderNameInvalid,
    AccessLogHeaderNameTooLong,
    AccessLogHeaderDuplicate,
    LimitAccessLogBufferUnderLine,
    FilterRespondStatus,
    ErrorPagesOverLimit,
    ErrorPageStatusInvalid,
    ErrorPageStatusUnknown,
    ErrorPageDuplicate,
    ListenerClusterOrRoutes,
    RoutesEmpty,
    RoutePrefixNotCanonical,
    RouteHostNotCanonical,
    RouteDuplicate,
    ListenerMaxBodyBytesOutOfRange,
    ListenerForwardedModeUnknown,
    ListenerProxyProtocolModeUnknown,
    ListenerTlsWithSniRoutes,
    RouteSniIsAddress,
    RouteHeaderMatchKind,
    LimitRelayBufferUnderSniRouting,
    ListenerTlsCertPathEmpty,
    ListenerTlsKeyPathEmpty,
    ClusterProxyProtocolSendUnknown,
    ClusterProxyProtocolOnHttpListener,
    ClusterProxyProtocolOnTlsListener,
    FilterMethodEmpty,
    FilterMethodUnknown,
    FilterHeaderMatchKind,
    FilterHeaderContainsEmpty,
    FilterHeaderNameInvalid,
    FilterHeaderNameReserved,
    FilterHeaderValueInvalid,
    FilterClientEmpty,
    FilterClientCidrInvalid,
    FilterClientPrefixInvalid,
    FilterClientPrefixTooNarrow,
    FilterClientCidrHostBits,
    FilterActionsEmpty,
    FilterActionKind,
    FilterRejectStatus,
    FilterRedirectStatus,
    FilterRedirectTarget,
    FilterRedirectSchemeUnknown,
    FilterHeaderEditsOverLimit,
    ResponseFilterStatusInvalid,
    ResponseFilterStatusClassUnknown,
    ResponseFilterStatusEmpty,
    ResponseFilterHeaderEditsOverLimit,
    EndpointsEmpty,
    EndpointsOverLimit,
    EndpointInvalid,
    EndpointPortZero,
    /// A `unix:` endpoint whose path is empty, past what a `sockaddr_un`
    /// carries, or carries a byte an address may not — a control byte, a
    /// quote or a backslash, each of which would corrupt the access log
    /// and the metrics exposition rather than one field of them (#303).
    EndpointUnixPathInvalid,
    /// A `unix:` endpoint path that is not absolute (#303).
    EndpointUnixPathRelative,
    EndpointWeightOverLimit,
    EndpointWeightsAllZero,
    TimeoutZero,
    TimeoutOverLimit,
    TimeoutOrderInvalid,
    TimeoutTunnelOutOfRange,
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
    LimitRelayBufferBytesOutOfRange,
    LimitTlsEnginesOutOfRange,
    LimitTlsEnginesOverConnSlots,
    LimitTlsEnginesWithoutTlsListener,
    LimitTunnelsRequired,
    LimitTunnelsOutOfRange,
    LimitTunnelsOverConnSlots,
    LimitTunnelsWithoutUpgrades,
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

/// How the loader reads a body's `file` source (#159). A seam rather
/// than a direct read, so the loader stays pure: `parse` below refuses
/// every file source (tests, the fuzzer and the simulator need no
/// filesystem — an `inline` body is theirs), and the binary's entry
/// point passes the one real reader through `parseWithFiles`, keeping
/// filesystem access where the config file itself is already read.
pub const FileSource = struct {
    context: ?*anyopaque = null,
    /// Read the whole file, at most `limit` bytes, into the arena.
    /// A file over the limit reports `FileTooLarge` — the loader turns
    /// it into the same `BodyOverLimit` an oversized inline body earns.
    read: *const fn (
        context: ?*anyopaque,
        arena: std.mem.Allocator,
        path: []const u8,
        limit: u32,
    ) error{ FileUnreadable, FileTooLarge, OutOfMemory }![]const u8,

    pub const none: FileSource = .{ .read = refuse };

    fn refuse(
        context: ?*anyopaque,
        arena: std.mem.Allocator,
        path: []const u8,
        limit: u32,
    ) error{ FileUnreadable, FileTooLarge, OutOfMemory }![]const u8 {
        _ = context;
        _ = arena;
        _ = limit;
        assert(path.len >= 1); // The caller validated the path shape first.
        return error.FileUnreadable;
    }
};

pub fn parse(arena: std.mem.Allocator, json_bytes: []const u8) ParseError!Config {
    return parseWithFiles(arena, json_bytes, .none);
}

pub fn parseWithFiles(
    arena: std.mem.Allocator,
    json_bytes: []const u8,
    files: FileSource,
) ParseError!Config {
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
    // first here); a listener naming neither protocol body, or both,
    // surfaces from the count below — before any bind or sink is looked
    // at; and a bad bind, resolved last, now reports after a bad
    // access-log sink.
    if (parsed.listeners.len == 0) {
        return error.ListenersEmpty;
    }
    const features = try countListenerFeatures(parsed.listeners);
    const access_log_sink = try resolveAccessLogSink(parsed.access_log);
    // Before the limits, because the named headers widen the line the
    // staging buffer has to be able to hold (#140).
    const log_headers = try resolveLogHeaders(arena, parsed.access_log);
    const limits = try resolveLimits(
        &parsed.limits,
        @intCast(parsed.listeners.len),
        features,
        access_log_sink != null,
        log_headers.count(),
        // The prober's share of the ring, which `resolveCqFill` has to
        // know before it can accept a fill (#132). Available here
        // because clusters resolve before limits do — the `check` blocks
        // are already settled by the time the budget is priced.
        constants.healthProbeConcurrency(checkedEndpointsOf(clusters)),
    );
    // Bodies before listeners (#159): a `respond` action names one, and
    // both consumers render through the same load-time cache — so the
    // table has to exist before any rule compiles. A body's own errors
    // therefore outrank a listener's, which is the honest order anyway:
    // an unreadable file is a fact about the deployment, where a bad
    // filter is a fact about a rule that may never have loaded.
    const bodies = try resolveBodies(arena, parsed.bodies, files);
    const listeners = try resolveListeners(
        arena,
        parsed.listeners,
        clusters,
        limits.head_buffer_bytes,
        bodies,
    );
    const admin_bind = try resolveAdminBind(parsed.admin);
    const error_pages = try resolveErrorPages(arena, parsed.error_pages, bodies);

    assert(listeners.len >= 1);
    assert(clusters.len >= 1);
    return .{
        .listeners = listeners,
        .clusters = clusters,
        .connect_timeout_ms = parsed.timeouts.connect_ms,
        .idle_timeout_ms = parsed.timeouts.idle_ms,
        .drain_deadline_ms = parsed.timeouts.drain_deadline_ms,
        .max_lifetime_ms = parsed.timeouts.max_lifetime_ms,
        .head_timeout_ms = resolveHeadTimeout(&parsed.timeouts),
        .request_timeout_ms = parsed.timeouts.request_ms,
        .tunnel_timeout_ms = parsed.timeouts.tunnel_ms,
        .health_interval_ms = parsed.timeouts.health_interval_ms,
        .limits = limits,
        .admin_bind = admin_bind,
        .access_log_sink = access_log_sink,
        .access_log_request_headers = log_headers.request,
        .access_log_response_headers = log_headers.response,
        .error_pages = error_pages,
    };
}

/// The #140 header lists, resolved: lowercased so the logged key is one
/// stable spelling a query need not guess at, deduplicated so a name
/// written twice renders one field, and bounded together — the two
/// lists share `access_log_headers_max`, because what the cap protects
/// (the line bound, the per-connection capture table) is the total.
const ResolvedLogHeaders = struct {
    request: []const []const u8,
    response: []const []const u8,

    fn count(headers: *const ResolvedLogHeaders) u32 {
        return @intCast(headers.request.len + headers.response.len);
    }
};

fn resolveLogHeaders(
    arena: std.mem.Allocator,
    access_log_json: ?AccessLogJson,
) ParseError!ResolvedLogHeaders {
    const access_log = access_log_json orelse return .{ .request = &.{}, .response = &.{} };
    const request_json = access_log.request_headers orelse &.{};
    const response_json = access_log.response_headers orelse &.{};
    if (request_json.len + response_json.len > constants.access_log_headers_max) {
        return error.AccessLogHeadersOverLimit;
    }
    const request = try resolveLogHeaderNames(arena, request_json);
    const response = try resolveLogHeaderNames(arena, response_json);
    // Deduplicated per direction, not across: the same name on both
    // sides is two different facts — what the client sent and what the
    // origin answered — and they land in different objects.
    assert(request.len == request_json.len);
    assert(response.len == response_json.len);
    return .{ .request = request, .response = response };
}

fn resolveLogHeaderNames(
    arena: std.mem.Allocator,
    names_json: []const []const u8,
) ParseError![]const []const u8 {
    if (names_json.len == 0) {
        return &.{};
    }
    const names = try arena.alloc([]const u8, names_json.len);
    for (names_json, 0..) |raw, index| {
        if (raw.len == 0) {
            return error.AccessLogHeaderNameInvalid;
        }
        if (raw.len > constants.access_log_header_name_bytes_max) {
            return error.AccessLogHeaderNameTooLong;
        }
        // An RFC 9110 token, like every other header name this config
        // spells — a name with a space or a colon could never match a
        // parsed header, and would render a key nothing produces.
        for (raw) |byte| {
            if (!isTokenByte(byte)) {
                return error.AccessLogHeaderNameInvalid;
            }
        }
        const lowered = try arena.alloc(u8, raw.len);
        for (raw, lowered) |byte, *slot| slot.* = std.ascii.toLower(byte);
        for (names[0..index]) |previous| {
            if (std.mem.eql(u8, previous, lowered)) {
                return error.AccessLogHeaderDuplicate;
            }
        }
        names[index] = lowered;
    }
    assert(names.len == names_json.len);
    return names;
}

/// A resolved #159 body: load-time only — consumers hold pointers to
/// pre-rendered responses, so nothing at serve time ever walks this
/// table.
///
/// `rendered` is the one-body-one-buffer contract made real: one slot
/// per page status, filled on first use, so a body named by an error
/// page and by three `respond` actions is read once, capped once, and
/// rendered once per (status, persistence) pair however many places
/// serve it. Pointers into it stay valid because every page is its own
/// arena allocation — the cache holds pointers, never inline structs
/// that a growing table could move.
const ResolvedBody = struct {
    name: []const u8,
    bytes: []const u8,
    content_type: []const u8,
    rendered: [shed.page_statuses.len]?*const Config.StaticPage = @splat(null),
};

/// Resolve the #159 `bodies` map: names bounded and unique, exactly one
/// source arm per body, bytes under `body_bytes_max` whichever arm they
/// came through, content type a forwardable header value. Absent means
/// an empty table, and every reference then fails as `BodyUnknown`.
fn resolveBodies(
    arena: std.mem.Allocator,
    bodies_json: ?BodiesJson,
    files: FileSource,
) ParseError![]ResolvedBody {
    const parsed = bodies_json orelse return &.{};
    if (parsed.entries.len > std.math.maxInt(u16)) {
        return error.BodiesOverLimit;
    }
    const bodies = try arena.alloc(ResolvedBody, parsed.entries.len);
    for (parsed.entries, 0..) |entry, index| {
        if (entry.name.len == 0) {
            return error.BodyNameEmpty;
        }
        if (entry.name.len > constants.body_name_bytes_max) {
            return error.BodyNameTooLong;
        }
        // Nested rather than sorted (the cluster-names rationale does
        // not carry): a config lists a handful of bodies, and each is
        // already paying a file read next to this compare.
        for (bodies[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, entry.name)) {
                return error.BodyNameDuplicate;
            }
        }
        bodies[index] = .{
            .name = entry.name,
            .bytes = try resolveBodyBytes(arena, &entry.body, files),
            .content_type = try resolveContentType(entry.body.content_type),
        };
        assert(bodies[index].name.len >= 1);
        assert(bodies[index].bytes.len <= constants.body_bytes_max);
    }
    assert(bodies.len == parsed.entries.len);
    return bodies;
}

/// One body's bytes through its one source arm (#159): `file` XOR
/// `inline`, the redirect target's exactly-one-fork rule. The cap
/// applies to both arms identically — where the bytes came from is not
/// what the memory statement is about.
fn resolveBodyBytes(
    arena: std.mem.Allocator,
    body_json: *const BodyJson,
    files: FileSource,
) ParseError![]const u8 {
    const has_file = body_json.file != null;
    const has_inline = body_json.@"inline" != null;
    if (!has_file and !has_inline) {
        return error.BodySourceMissing;
    }
    if (has_file and has_inline) {
        return error.BodySourceAmbiguous;
    }
    if (body_json.file) |path| {
        if (path.len == 0) {
            return error.BodyFileUnreadable;
        }
        const bytes = files.read(
            files.context,
            arena,
            path,
            constants.body_bytes_max,
        ) catch |err| switch (err) {
            error.FileUnreadable => return error.BodyFileUnreadable,
            error.FileTooLarge => return error.BodyOverLimit,
            error.OutOfMemory => return error.OutOfMemory,
        };
        assert(bytes.len <= constants.body_bytes_max);
        return bytes;
    }
    const inline_bytes = body_json.@"inline".?;
    if (inline_bytes.len > constants.body_bytes_max) {
        return error.BodyOverLimit;
    }
    // The same postcondition the file arm states: where the bytes came
    // from is not what the memory statement is about.
    assert(inline_bytes.len <= constants.body_bytes_max);
    return inline_bytes;
}

/// A body's Content-Type: non-empty and injection-safe — the same
/// forwardable-byte rule filter header values keep, since this value
/// lands on the wire inside a rendered head.
fn resolveContentType(content_type: []const u8) ParseError![]const u8 {
    if (content_type.len == 0) {
        return error.BodyContentTypeInvalid;
    }
    validateHeaderValue(content_type) catch return error.BodyContentTypeInvalid;
    assert(content_type.len >= 1);
    return content_type;
}

/// Resolve `error_pages` (#159): each entry a status from the closed
/// static set, each naming a body, each pre-rendered here — both
/// persistence variants, head lengths recorded — so serve time is the
/// comptime-static path unchanged: one send from immutable memory.
fn resolveErrorPages(
    arena: std.mem.Allocator,
    error_pages_json: ?ErrorPagesJson,
    bodies: []ResolvedBody,
) ParseError![]const *const Config.StaticPage {
    const parsed = error_pages_json orelse return &.{};
    // The closed status set bounds what can survive validation, so a
    // longer map always fails below — on an unknown status or on a
    // duplicate, and which one is not knowable from the count alone,
    // which is why this has an error of its own rather than guessing at
    // either. Ahead of the allocation, so a rejected config's arena
    // stays bounded by the vocabulary rather than by the file's length
    // (`BodiesOverLimit`'s reasoning, one resolver up).
    if (parsed.entries.len > shed.static_statuses.len) {
        return error.ErrorPagesOverLimit;
    }
    const pages = try arena.alloc(*const Config.StaticPage, parsed.entries.len);
    for (parsed.entries, 0..) |entry, index| {
        const status = std.fmt.parseUnsigned(u16, entry.status, 10) catch
            return error.ErrorPageStatusInvalid;
        // The error set, not the wider page set: `200` is a `respond`
        // action's status, and no rung raises it — a page here for one
        // would never serve.
        if (!shed.isStaticStatus(status)) {
            return error.ErrorPageStatusUnknown;
        }
        // The closed set is ten wide, so the duplicate scan is bounded
        // by it whatever the entry count claims.
        for (pages[0..index]) |previous| {
            if (previous.status == status) {
                return error.ErrorPageDuplicate;
            }
        }
        pages[index] = try pageFor(arena, bodies, entry.body, status);
        // What the serve path reads back (`configuredPage`): a head
        // that is a prefix of its own response, on both variants.
        assert(pages[index].keep_head_len <= pages[index].keep.len);
        assert(pages[index].close_head_len <= pages[index].close.len);
    }
    assert(pages.len == parsed.entries.len);
    assert(pages.len <= shed.static_statuses.len);
    return pages;
}

/// The page for one (body name, status) pair (#159), rendered on first
/// use and reused after — so a body named by an error page and by any
/// number of `respond` actions costs one pair of buffers, not one per
/// reference. Every consumer of a configured body comes through here.
fn pageFor(
    arena: std.mem.Allocator,
    bodies: []ResolvedBody,
    name: []const u8,
    status: u16,
) ParseError!*const Config.StaticPage {
    assert(shed.isPageStatus(status));
    const slot = shed.pageStatusIndex(status).?;
    const body = bodyNamed(bodies, name) orelse return error.BodyUnknown;
    if (body.rendered[slot]) |cached| {
        assert(cached.status == status);
        return cached;
    }
    const keep = try renderStaticPage(arena, status, body, .keep);
    const close = try renderStaticPage(arena, status, body, .close);
    const page = try arena.create(Config.StaticPage);
    page.* = .{
        .status = status,
        .keep = keep.bytes,
        .close = close.bytes,
        .keep_head_len = keep.head_len,
        .close_head_len = close.head_len,
        .keep_date = keep.date,
        .close_date = close.date,
    };
    // What every consumer of a page relies on, stated where every page
    // is made rather than at one call site: the head is a prefix of its
    // own response, on both variants (the serve path's HEAD slice).
    assert(page.keep_head_len <= page.keep.len);
    assert(page.close_head_len <= page.close.len);
    body.rendered[slot] = page;
    return page;
}

fn bodyNamed(bodies: []ResolvedBody, name: []const u8) ?*ResolvedBody {
    assert(bodies.len <= std.math.maxInt(u16)); // `BodiesOverLimit`'s bound.
    for (bodies) |*body| {
        assert(body.name.len >= 1); // resolveBodies rejected empty names.
        assert(body.content_type.len >= 1);
        if (std.mem.eql(u8, body.name, name)) {
            return body;
        }
    }
    return null;
}

/// One rendered #159 page: the complete response in one contiguous
/// arena buffer — status line, framing, content type, the persistence
/// announcement, then the body — with the head's length recorded so a
/// HEAD request is a prefix slice of the same buffer.
fn renderStaticPage(
    arena: std.mem.Allocator,
    status: u16,
    body: *const ResolvedBody,
    persistence: shed.Persistence,
) ParseError!struct { bytes: []const u8, head_len: u32, date: *[shed.date_bytes]u8 } {
    assert(shed.isPageStatus(status));
    assert(body.content_type.len >= 1);
    // The `Date` value is a placeholder here and a slot from here on
    // (#234): fixed-width, so the serving path patches it in place and a
    // page stays one contiguous send. Its offset is recorded rather than
    // re-derived, because the only thing that knows it is this format
    // string.
    const prefix = try std.fmt.allocPrint(
        arena,
        "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nContent-Type: {s}\r\nDate: ",
        .{ status, shed.reasonPhrase(status), body.bytes.len, body.content_type },
    );
    const rendered = try std.fmt.allocPrint(
        arena,
        "{s}{s}\r\n{s}{s}\r\n{s}",
        .{
            prefix,
            shed.date_placeholder,
            shed.server_line,
            switch (persistence) {
                .keep => "",
                .close => "Connection: close\r\n",
            },
            body.bytes,
        },
    );
    assert(rendered.len > body.bytes.len);
    const head_len: u32 = @intCast(rendered.len - body.bytes.len);
    // The slot must sit inside the *head*, or a HEAD request would be
    // sent the prefix without it.
    assert(prefix.len + shed.date_bytes <= head_len);
    return .{
        .bytes = rendered,
        .head_len = head_len,
        .date = rendered[prefix.len..][0..shed.date_bytes],
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
/// The §5 relation every per-connection pool shares: none of them may
/// out-size the connections that draw on it. Stated once, after the
/// resolvers have each enforced their own half, because a pool past this
/// is not merely wasteful — the fd and ring budgets are derived from
/// `conn_slots` on the strength of it (`fdsRequired`, `inFlightOps`), so
/// The two pools a *feature* switches on: TLS engines, reserved exactly
/// when some listener terminates, and #180's tunnels, reserved exactly
/// when some listener allows an upgrade. Their own group because both are
/// zero for a deployment that asked for neither — which is what makes
/// each feature free — and both are bounded by the conn slots above.
fn resolveFeaturePools(
    limits_json: *const LimitsJson,
    conn_slots: u32,
    tls_listeners_count: u32,
    upgrade_listeners_count: u32,
) ValidationError!struct { tls_engines: u32, tunnels: u32 } {
    const tls_engines = try resolveTlsEngines(
        limits_json.tls_engines,
        conn_slots,
        tls_listeners_count,
    );
    const tunnels = try resolveTunnels(
        limits_json.tunnels,
        conn_slots,
        upgrade_listeners_count,
    );
    return .{ .tls_engines = tls_engines, .tunnels = tunnels };
}

/// The two head pools (§5), which exist only for an HTTP listener: the
/// downstream ring and the upstream pool. Their own group because both
/// are gated on the same `http_listeners_count` and each is bounded by a
/// different slot count above.
fn resolveHeadPools(
    limits_json: *const LimitsJson,
    conn_slots: u32,
    upstream_slots: u32,
    http_listeners_count: u32,
) ValidationError!struct { head_buffers: u32, upstream_head_buffers: u32 } {
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
    return .{
        .head_buffers = head_buffers,
        .upstream_head_buffers = upstream_head_buffers,
    };
}

/// a breach here is an under-provisioned ring rather than spare memory.
fn assertPoolsFitConnSlots(
    conn_slots: u32,
    relay_buffers: u32,
    head_buffers: u32,
    tls_engines: u32,
    tunnels: u32,
) void {
    assert(relay_buffers <= conn_slots);
    assert(head_buffers <= conn_slots);
    assert(tls_engines <= conn_slots);
    assert(tunnels <= conn_slots);
}

fn resolveLimits(
    limits_json: *const LimitsJson,
    listeners_count: u32,
    features: ListenerFeatures,
    access_log_on: bool,
    log_header_count: u32,
    health_probes: u32,
) ValidationError!Config.Limits {
    assert(listeners_count >= 1);
    assert(health_probes >= 1);
    assert(health_probes <= constants.health_probe_concurrency_max);
    // Bounds are `countListenerFeatures`'s postcondition, not re-checked
    // here — restating them would be two places to keep in step.
    const slots = try resolveSlotCounts(limits_json);
    const conn_slots = slots.conn_slots;
    const relay_buffers = slots.relay_buffers;
    const upstream_slots = slots.upstream_slots;
    const head_pools = try resolveHeadPools(
        limits_json,
        conn_slots,
        upstream_slots,
        features.http,
    );
    const head_buffer_bytes = try resolveHeadBufferBytes(limits_json.head_buffer_bytes);
    const relay_buffer_bytes = try resolveRelayBufferBytes(limits_json.relay_buffer_bytes);
    // The §6 peek stages a whole ClientHello in the relay buffer's
    // client->upstream half (#298), so a listener that routes by name
    // needs a half wide enough to hold one. Refused at load, which is
    // the operator's decision either way: a buffer too small would
    // otherwise route the clients whose hellos happen to be short and
    // drop the ones offering post-quantum key shares — one config, two
    // outcomes, and nothing saying why.
    if (features.sni >= 1 and relay_buffer_bytes < constants.client_hello_bytes_max) {
        return error.LimitRelayBufferUnderSniRouting;
    }
    const feature_pools = try resolveFeaturePools(
        limits_json,
        conn_slots,
        features.tls,
        features.upgrades,
    );
    const cq_fill_eighths = try resolveCqFill(
        limits_json.cq_fill_eighths,
        conn_slots,
        upstream_slots,
        listeners_count,
        health_probes,
    );
    // Zero exactly when the log is off, so the one number says both how
    // big the staging buffers are and whether there are any (§8). A
    // deployment that sized the buffers but never named a sink has asked
    // for something contradictory, and is told so rather than quietly
    // getting no log.
    const access_log_buffer_bytes = try resolveAccessLogBuffer(
        limits_json.access_log_buffer_bytes,
        access_log_on,
        log_header_count,
    );
    assertPoolsFitConnSlots(
        conn_slots,
        relay_buffers,
        head_pools.head_buffers,
        feature_pools.tls_engines,
        feature_pools.tunnels,
    );
    return .{
        .conn_slots = conn_slots,
        .relay_buffers = relay_buffers,
        .upstream_slots = upstream_slots,
        .head_buffers = head_pools.head_buffers,
        .upstream_head_buffers = head_pools.upstream_head_buffers,
        .head_buffer_bytes = head_buffer_bytes,
        .relay_buffer_bytes = relay_buffer_bytes,
        .tls_engines = feature_pools.tls_engines,
        .tunnels = feature_pools.tunnels,
        .keepalive_requests = limits_json.keepalive_requests orelse
            constants.keepalive_requests_default,
        .cq_fill_eighths = cq_fill_eighths,
        .access_log_buffer_bytes = access_log_buffer_bytes,
    };
}

/// The three pool counts that bound the others (§5). Their own group
/// because they are the only limits resolved against nothing but the
/// compiled ceilings and each other — everything after them is gated on
/// one of these three, which is also why they come out together.
const SlotCounts = struct {
    conn_slots: u32,
    relay_buffers: u32,
    upstream_slots: u32,
};

/// Omitted limits default to the lean out-of-box sizes, not the compiled
/// ceilings (§5): a small footprint unless the operator opts up. Relay
/// buffers still follow conn slots when omitted (one buffer per L4
/// connection), capped at their own ceiling.
fn resolveSlotCounts(limits_json: *const LimitsJson) ValidationError!SlotCounts {
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
    assert(relay_buffers <= conn_slots);
    assert(conn_slots >= 1);
    return .{
        .conn_slots = conn_slots,
        .relay_buffers = relay_buffers,
        .upstream_slots = upstream_slots,
    };
}

/// The CQ fill is the one limit an operator tightens for headroom, not a
/// pool shrink (§8): a smaller fill demands a deeper ring for the same
/// conn slots. Range-check first, then reject a fill that — with these
/// conn/upstream slots and listeners — would need a completion queue past
/// the compiled ring, so main.zig's `completionQueueDepthFor` never clamps.
fn resolveCqFill(
    requested: ?u32,
    conn_slots: u32,
    upstream_slots: u32,
    listeners_count: u32,
    health_probes: u32,
) ValidationError!u32 {
    assert(conn_slots >= 1);
    assert(listeners_count >= 1);
    assert(health_probes >= 1);
    const cq_fill_eighths = requested orelse constants.cq_fill_eighths_default;
    if (cq_fill_eighths < constants.cq_fill_eighths_min or
        cq_fill_eighths > constants.cq_fill_eighths_max)
    {
        return error.LimitCqFillOutOfRange;
    }
    if (!constants.cqFillFits(
        conn_slots,
        upstream_slots,
        listeners_count,
        health_probes,
        cq_fill_eighths,
    )) {
        return error.LimitConnSlotsOverCqFill;
    }
    return cq_fill_eighths;
}

/// The §4 engine pool follows conn slots when omitted, capped at
/// `tls_engines_max` — an engine is ~91 KiB, so unlike a head buffer the
/// default cannot simply be "one each" at every conn-slot count anyone
/// might configure. Zero exactly when no listener terminates TLS: a
/// plaintext-only deployment reserves nothing, and one that asked for
/// engines it cannot use is told so rather than quietly paying for them.
/// A TLS deployment with a zero pool would shed every handshake, so that
/// is rejected too.
fn resolveTlsEngines(
    requested: ?u32,
    conn_slots: u32,
    tls_listeners_count: u32,
) ValidationError!u32 {
    assert(conn_slots >= 1);
    const tls_engines = requested orelse
        (if (tls_listeners_count >= 1) @min(constants.tls_engines_default, conn_slots) else 0);
    if (tls_engines > constants.tls_engines_max) {
        return error.LimitTlsEnginesOutOfRange;
    }
    if (tls_engines > conn_slots) {
        return error.LimitTlsEnginesOverConnSlots;
    }
    if (tls_listeners_count == 0 and tls_engines >= 1) {
        return error.LimitTlsEnginesWithoutTlsListener;
    }
    if (tls_listeners_count >= 1 and tls_engines == 0) {
        return error.LimitTlsEnginesOutOfRange;
    }
    assert(tls_engines <= conn_slots);
    return tls_engines;
}

/// The §5 tunnel pool (#180). Shaped like `resolveTlsEngines` in every
/// respect but the one that matters: **there is no derived default**.
///
/// Every other optional pool falls back to a worst case that cannot shed
/// — head buffers to conn slots because every connection could be
/// mid-head at once, engines to conn slots capped — and such a fallback
/// is safe precisely because it can only be too generous. A tunnel count
/// has no such number behind it. How many long-lived sessions an origin
/// fleet should carry is a capacity decision, and deriving it from a
/// connection count would silently promise a pool nobody sized: the
/// failure would arrive as tunnels refused under load, far from the
/// config that caused it. So a listener that allows upgrades without a
/// `limits.tunnels` is refused at load, where the operator is looking.
///
/// The `≤ conn_slots` bound is not arithmetic hygiene either — it is
/// what leaves the fd and ring budgets untouched (§5): `fdsRequired`
/// already charges two sockets per connection, which is exactly what a
/// tunnel holds, and `conn_ops_max` is 4 because one of its tying peaks
/// is a relay teardown, which is a tunnel's steady state.
fn resolveTunnels(
    requested: ?u32,
    conn_slots: u32,
    upgrade_listeners_count: u32,
) ValidationError!u32 {
    assert(conn_slots >= 1);
    const tunnels = requested orelse {
        if (upgrade_listeners_count >= 1) {
            return error.LimitTunnelsRequired;
        }
        return 0;
    };
    if (tunnels > constants.tunnels_max) {
        return error.LimitTunnelsOutOfRange;
    }
    if (tunnels > conn_slots) {
        return error.LimitTunnelsOverConnSlots;
    }
    if (upgrade_listeners_count == 0 and tunnels >= 1) {
        return error.LimitTunnelsWithoutUpgrades;
    }
    // A pool of zero beside a listener that allows upgrades would refuse
    // every one of them: the same contradiction as sizing the head ring
    // to zero on an http deployment, and rejected on the same terms.
    if (upgrade_listeners_count >= 1 and tunnels == 0) {
        return error.LimitTunnelsOutOfRange;
    }
    assert(tunnels <= conn_slots);
    return tunnels;
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

/// One relay half's size (§6). Bounded below by what a `PROXY` header and
/// a chunked size line must stage in one buffer, and above by one TLS
/// record — `transformOut` hands a whole chunk to `sendApp` as a single
/// record, so a larger buffer has no legal way across the wire.
fn resolveRelayBufferBytes(requested: ?u32) ValidationError!u32 {
    const relay_buffer_bytes = requested orelse constants.relay_buffer_bytes_default;
    if (relay_buffer_bytes < constants.relay_buffer_bytes_min or
        relay_buffer_bytes > constants.relay_buffer_bytes_max)
    {
        return error.LimitRelayBufferBytesOutOfRange;
    }
    assert(relay_buffer_bytes >= constants.relay_buffer_bytes_min);
    assert(relay_buffer_bytes <= constants.relay_buffer_bytes_max);
    return relay_buffer_bytes;
}

fn resolveAccessLogBuffer(
    requested: ?u32,
    access_log_on: bool,
    log_header_count: u32,
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
    // The static floor covers a line with no named headers; this config's
    // own line may be wider (#140), and a buffer that cannot hold one
    // would drop every line carrying its headers — a drop that means
    // arithmetic rather than backpressure, which is the one thing the
    // counter must never mean.
    const line_bytes = constants.accessLogLineBytes(log_header_count);
    if (bytes < line_bytes) {
        return error.LimitAccessLogBufferUnderLine;
    }
    assert(bytes >= line_bytes);
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
    /// Optional #159 named bodies; absent reserves nothing.
    bodies: ?BodiesJson = null,
    /// Optional #159 error pages over the closed static-status set;
    /// absent means every static stays `Content-Length: 0` — including
    /// the sheds, whose bodies this block is the deliberate opt-in for.
    error_pages: ?ErrorPagesJson = null,

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
        .bodies = .{
            .desc = "Named response bodies (file or inline, read once at " ++
                "startup), referenced by name from error_pages.",
        },
        .error_pages = .{
            .desc = "Bodies for the statuses zoxy sends itself, keyed by " ++
                "status literal, each naming a body. Configuring a status " ++
                "is the opt-in — absent, every static response stays empty, " ++
                "sheds included.",
        },
    };
};

pub const AccessLogJson = struct {
    sink: []const u8,
    path: ?[]const u8 = null,
    /// Headers to log (#140), absent meaning none — so a deployment
    /// that does not ask pays nothing, the same shape as `access_log`
    /// itself being absent.
    request_headers: ?[]const []const u8 = null,
    response_headers: ?[]const []const u8 = null,

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
            // An empty path is the same refusal as a missing one and
            // wants the same answer (#305): the loader raises
            // `AccessLogPathMissing` for both, so the schema has to
            // catch both or the row cannot go.
            .min_length = 1,
        },
        .request_headers = .{
            .desc = "Request headers to record under `request_headers` on each " ++
                "http line — an upstream's X-Request-ID or traceparent is what " ++
                "joins this log to the origin's. Names are matched " ++
                "case-insensitively and logged lowercased; absent headers are " ++
                "omitted from the line.",
            .max_items = constants.access_log_headers_max,
            .item_min_length = 1,
            .item_max_length = constants.access_log_header_name_bytes_max,
        },
        .response_headers = .{
            .desc = "Response headers to record under `response_headers`, on the " ++
                "same terms — the origin's X-Cache, say. Ignored for l4 lines, " ++
                "which have no response to read.",
            .max_items = constants.access_log_headers_max,
            .item_min_length = 1,
            .item_max_length = constants.access_log_header_name_bytes_max,
        },
    };

    /// A file sink needs somewhere to write and a stdout sink has
    /// nowhere to be given (#305). `sink` has no default, so both arms
    /// name it.
    pub const schema_variants = [_]SchemaVariants{.{
        .on = "sink",
        .branches = &.{
            .{ .value = "stdout", .forbid = &.{"path"} },
            .{ .value = "file", .require = &.{"path"} },
        },
    }};
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
    relay_buffer_bytes: ?u32 = null,
    tls_engines: ?u32 = null,
    tunnels: ?u32 = null,
    /// Optional #237 keep-alive request cap; absent means nginx's 1000,
    /// `0` is unlimited.
    keepalive_requests: ?u32 = null,
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
        .relay_buffer_bytes = .{
            .desc = "Bytes per relay direction; a pair costs twice this. Sets " ++
                "how many round trips a body costs and the size of the TLS " ++
                "records a terminating listener emits. Lower it when " ++
                "concurrency matters more than bulk throughput.",
            .minimum = constants.relay_buffer_bytes_min,
            .maximum = constants.relay_buffer_bytes_max,
        },
        .tls_engines = .{
            .desc = "Concurrent TLS sessions — handshaking or terminated. The " ++
                "largest per-connection object zoxy holds (~91 KiB plus a " ++
                "plaintext buffer), so this is what a TLS deployment's memory " ++
                "follows. Zero exactly when no listener terminates TLS.",
            .minimum = 1,
            .maximum = constants.tls_engines_max,
        },
        .keepalive_requests = .{
            .desc = "Requests one client connection may serve before the next " ++
                "response announces Connection: close; absent means 1000, " ++
                "0 is unlimited.",
            .minimum = 0,
            .maximum = std.math.maxInt(u32),
        },
        .tunnels = .{
            .desc = "Concurrent tunnelled upgrades (#180). Each holds its own relay " ++
                "buffer and upstream socket for its whole life, so tunnels never " ++
                "draw on the pools ordinary traffic shares. Required — and only " ++
                "legal — when some listener allows an upgrade; no default is " ++
                "derived, because a count of long-lived sessions is a capacity " ++
                "decision rather than something a connection count implies.",
            .minimum = 1,
            .maximum = constants.tunnels_max,
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

/// One accepting socket, as a tagged shape: what is true of every
/// listener sits at this level, and what only one protocol can mean sits
/// inside the body that names it (#305).
///
/// This used to be eleven flat fields of which seven were conditionally
/// valid on a `protocol` string — a discriminated union modeled as a
/// struct, with the discrimination left to seven loader errors that no
/// emitted schema could carry. The tag is now the body's own key, so
/// `{"l4": {"max_body_bytes": 500}}` is refused by the schema's shape
/// rather than by a rule written twice in prose, and the seven errors are
/// gone rather than reworded.
///
/// `bind` and `tls` stay out here because they are genuinely shared: an
/// address is an address, and `resolveTls` says of the other why it is
/// not a body field — "both speak over a terminated session (§4, §7)".
pub const ListenerJson = struct {
    bind: []const u8,
    /// Permission bits for a `unix:` bind's socket file, as an octal
    /// string (#303); absent leaves whatever the process umask gives.
    /// Shared like `tls` because it is a property of the socket, not of
    /// what is spoken over it — and rejected on an IP bind, which
    /// creates no file to chmod.
    mode: ?[]const u8 = null,
    /// Optional TLS termination (#125); absent is a plaintext socket.
    /// Shared, unlike everything in the bodies below.
    tls: ?TlsJson = null,
    /// Exactly one of these names what the listener speaks and carries
    /// that protocol's own fields.
    http: ?HttpListenerJson = null,
    l4: ?L4ListenerJson = null,

    pub const schema_doc =
        "One accepting socket. Exactly one of `http` or `l4` names what it " ++
        "speaks and carries that protocol's settings; `bind` and `tls` are " ++
        "shared by both.";
    pub const schema_one_of = [_][]const u8{ "http", "l4" };
    pub const schema_fields = .{
        .bind = .{
            .desc = "What to bind: an `IP:port` literal (hostnames are rejected — " ++
                "DNS is a non-goal), or `unix:` followed by the absolute path of " ++
                "a socket file to create.",
        },
        .mode = .{
            .desc = "Permission bits for a unix: socket file, as an octal string " ++
                "(\"0660\"). Absent leaves the process umask's default. Rejected " ++
                "on an IP bind, which creates no file.",
            .min_length = 1,
        },
        .tls = .{
            .desc = "Terminate TLS on this listener with the given certificate " ++
                "and key; absent is a plaintext socket. Inbound only — the " ++
                "upstream leg stays plaintext.",
        },
        .http = .{
            .desc = "Speak HTTP/1.1: run the reverse-proxy state machine, with " ++
                "routing, filters and body limits.",
        },
        .l4 = .{
            .desc = "Speak L4: relay bytes to one cluster without inspecting them.",
        },
    };
};

/// What an `http` listener carries, and nothing an `l4` one could.
pub const HttpListenerJson = struct {
    /// Exactly one of `cluster` (sugar for a single catch-all route) or
    /// `routes` (an explicit §7 path table) must be present.
    cluster: ?[]const u8 = null,
    routes: ?[]const RouteJson = null,
    /// Optional §7 request filter rules; absent means none.
    request_filters: ?[]const FilterJson = null,
    /// Optional #175 response filter rules; absent means none.
    response_filters: ?[]const ResponseFilterJson = null,
    /// Optional §7 client-address forwarding; absent leaves the header
    /// untouched.
    forwarded: ?ForwardedJson = null,
    /// Optional #180 upgrade allowlist; absent allows none, so an
    /// `Upgrade` stays the 501 it has always been.
    upgrades: ?UpgradesJson = null,
    /// The #236 request-body cap, `0` accepting any size (#305). Not
    /// optional: `null` used to mean the default and `0` no cap, which
    /// is three states for a two-state idea, and every other cap in this
    /// config — `drain_deadline_ms`, `max_lifetime_ms`, `request_ms` —
    /// already spells "no cap" as `0` with no third state to explain.
    max_body_bytes: u64 = constants.request_body_bytes_default,
    /// Whether this listener names *why* it refused, in an RFC 9209
    /// `Proxy-Status` field (#300). Absent is off.
    proxy_status: bool = false,

    pub const schema_doc =
        "An HTTP/1.1 listener's settings. Exactly one of `cluster` or " ++
        "`routes` selects the upstream.";
    pub const schema_one_of = [_][]const u8{ "cluster", "routes" };
    pub const schema_fields = .{
        .cluster = .{ .desc = "Sugar for a single catch-all route to this cluster; mutually exclusive with routes." },
        .routes = .{
            .desc = "Explicit longest-prefix route table.",
            .min_items = 1,
        },
        .request_filters = .{
            .desc = "Request filter rules, evaluated top-down.",
        },
        .response_filters = .{
            .desc = "Response filter rules — header edits on the origin's response, " ++
                "evaluated top-down.",
        },
        .forwarded = .{
            .desc = "Tell the origin the client's address via X-Forwarded-For; " ++
                "absent leaves the header untouched.",
        },
        .max_body_bytes = .{
            .desc = "Cap on one request body in bytes; 0 accepts any size, and " ++
                "absent is 1 MiB. A body over the cap is refused 413 before the " ++
                "origin is dialed where its length was declared, and the " ++
                "connection closes.",
            .minimum = 0,
            .maximum = constants.request_body_bytes_max,
        },
        .proxy_status = .{
            .desc = "Name why this proxy refused a request, in an RFC 9209 " ++
                "Proxy-Status field, so a client can tell a shed 503 from the " ++
                "origin's own. Off by default: it states internal limits on " ++
                "the wire, which an internal listener may want and an edge " ++
                "one may not.",
        },
        .upgrades = .{
            .desc = "Protocol upgrades this listener will carry as tunnels; absent " ++
                "allows none and an Upgrade stays 501. Requires limits.tunnels.",
        },
    };
};

/// The #180 upgrade allowlist, one flag per protocol this proxy can
/// recognise (#305 Part 2).
///
/// An object rather than the list of tokens this replaced, and the
/// argument is the vocabulary: §7 requires it closed — a token zoxy
/// cannot reason about must be refused by name, never ignored — and a
/// list of strings can only be closed by the loader, in rules a reader
/// of the schema never sees. As fields, the schema states the whole
/// vocabulary, `additionalProperties: false` rejects an unknown token,
/// and duplicates stop being expressible at all: the list form accepted
/// `["websocket", "websocket"]` because nothing checked, and there is no
/// spelling of that here.
pub const UpgradesJson = struct {
    websocket: bool = false,

    pub const schema_doc =
        "Which protocol upgrades this listener carries as tunnels. Absent, or " ++
        "every flag false, allows none.";
    pub const schema_fields = .{
        .websocket = .{
            .desc = "Carry a WebSocket handshake (RFC 6455) as a tunnel once the " ++
                "origin answers 101. Requires limits.tunnels.",
        },
    };

    comptime {
        // The JSON shape and the resolved one are one vocabulary. A
        // protocol added to either and forgotten on the other would let
        // the config name an upgrade the serving path cannot gate, or
        // hide one it can.
        const resolved = @typeInfo(Config.Listener.Upgrades).@"struct".fields;
        const json = @typeInfo(UpgradesJson).@"struct".fields;
        if (resolved.len != json.len) {
            @compileError("UpgradesJson and Config.Listener.Upgrades disagree on the set");
        }
        for (resolved) |field| {
            if (!@hasField(UpgradesJson, field.name)) {
                @compileError("UpgradesJson is missing " ++ field.name);
            }
        }
    }
};

/// What an `l4` listener carries. It forks on the upstream the way an
/// `http` listener does — sugar for one destination, or a table — but on
/// the only dimension a byte relay has: there is no path to match, so the
/// table is keyed by the TLS name the client asked for (#298).
pub const L4ListenerJson = struct {
    /// Exactly one of `cluster` (sugar for a single any-name route) or
    /// `routes` (an explicit §6 SNI table, #298) selects the upstream —
    /// the same fork `HttpListenerJson` has, for the same reason.
    cluster: ?[]const u8 = null,
    routes: ?[]const L4RouteJson = null,
    /// Optional PROXY protocol expectation (#142); absent treats first
    /// bytes as payload.
    proxy_protocol: ?ProxyProtocolJson = null,

    pub const schema_doc =
        "An L4 listener's settings: which cluster it relays to, and what it " ++
        "expects ahead of the payload. Exactly one of `cluster` or `routes` " ++
        "selects the upstream.";
    pub const schema_one_of = [_][]const u8{ "cluster", "routes" };
    pub const schema_fields = .{
        .cluster = .{
            .desc = "Sugar for a single any-name route to this cluster; " ++
                "mutually exclusive with routes.",
        },
        .routes = .{
            .desc = "Route by the TLS server name (SNI) the client asked for, " ++
                "without terminating: the ClientHello is read and relayed " ++
                "unchanged. Requires the full-size relay buffer, and cannot be " ++
                "combined with this listener's own tls block.",
            .min_items = 1,
        },
        .proxy_protocol = .{
            .desc = "Expect a PROXY protocol header (v1 or v2) ahead of every " ++
                "connection's payload; absent treats first bytes as payload.",
        },
    };
};

/// One §6 SNI route (#298): the name a client must have asked for, and
/// the cluster that answers it.
pub const L4RouteJson = struct {
    /// Absent is the any-name route — it answers every connection,
    /// including one whose hello named nothing. §7's any-host route,
    /// wearing the only dimension an L4 relay has.
    sni: ?[]const u8 = null,
    cluster: []const u8,

    pub const schema_doc =
        "One SNI route. `sni` absent is the catch-all: it answers any " ++
        "connection, including one whose ClientHello carried no name. A " ++
        "connection matching no route is closed.";
    pub const schema_fields = .{
        .sni = .{
            .desc = "The TLS server name to match, exactly — the same rule " ++
                "http routes match a host by, so the two cannot disagree " ++
                "about what a name is. No wildcards.",
            .min_length = 1,
        },
        .cluster = .{ .desc = "The cluster connections naming this server are relayed to." },
    };
};

pub const TlsJson = struct {
    cert: []const u8,
    key: []const u8,

    pub const schema_doc =
        "TLS termination for this listener: where its certificate chain and " ++
        "private key live. Both are read once at startup, so a missing or " ++
        "unusable file stops the proxy while the error can still name it — " ++
        "never mid-handshake against a real client. The key must be ECDSA " ++
        "P-256 or P-384: the handshake runs on the event loop, where an RSA " ++
        "signature's milliseconds would stall every other connection on it.";
    pub const schema_fields = .{
        .cert = .{
            .desc = "Path to the PEM certificate chain, leaf first.",
            .min_length = 1,
        },
        .key = .{
            .desc = "Path to the leaf's PEM private key (ECDSA P-256 or P-384).",
            .min_length = 1,
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
    /// Optional #177 client-address predicate: CIDR literals, any-of.
    client: ?[]const []const u8 = null,

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
        .client = .{
            .desc = "CIDR prefixes the connection's client address must fall inside " ++
                "(any-of): \"10.0.0.0/8\", up to /32 for IPv4 and /64 for IPv6 — a " ++
                "client's IPv6 identity is its /64, like hash source_ip. Matched " ++
                "against the observed peer (the PROXY-announced client on a " ++
                "proxy_protocol listener), never an X-Forwarded-For chain.",
            .min_items = 1,
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
        "selects the kind.";
    pub const schema_one_of = [_][]const u8{ "present", "equals", "contains" };
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
/// What a #175 response rule may do: edit headers, and nothing else.
///
/// A type of its own rather than `ActionJson` with four of its members
/// refused at load (#305). The four are request-side answers — `reject`,
/// `redirect` and `respond` decide what to send *instead* of asking the
/// origin, and `rewrite_prefix` changes what is asked — while a response
/// rule runs when the origin has already answered. Sharing the request's
/// union made those states representable and then rejected them one at
/// a time; here they cannot be written down, which is the same verdict
/// reached by the type rather than by a rule, and the schema states it
/// too.
pub const ResponseActionJson = struct {
    header_set: ?HeaderEditJson = null,
    header_add: ?HeaderEditJson = null,
    header_remove: ?[]const u8 = null,

    pub const schema_doc =
        "One response-filter action. Exactly one field is set — the edit's " ++
        "kind. Response rules edit headers only: the request-side actions " ++
        "(reject, redirect, respond, rewrite_prefix) answer instead of " ++
        "forwarding, and by the time these rules run the origin already has.";
    pub const schema_one_of = [_][]const u8{
        "header_set",
        "header_add",
        "header_remove",
    };
    pub const schema_fields = .{
        .header_set = .{ .desc = "Set (replace) a response header." },
        .header_add = .{ .desc = "Append a response header." },
        .header_remove = .{ .desc = "Remove a response header by name." },
    };

    comptime {
        // Every member must exist on the request action *and carry the
        // same type*: the two tables share `resolveHeaderEdit`, so a
        // member here the request lacks would be an edit the renderer
        // has never seen, and one whose type diverged would be the same
        // key meaning two things.
        for (@typeInfo(ResponseActionJson).@"struct".fields) |field| {
            if (!@hasField(ActionJson, field.name)) {
                @compileError("ResponseActionJson." ++ field.name ++ " is not an ActionJson field");
            }
            if (@FieldType(ActionJson, field.name) != field.type) {
                @compileError("ResponseActionJson." ++ field.name ++
                    " has a different type than ActionJson's");
            }
        }
    }
};

pub const ActionJson = struct {
    reject: ?u16 = null,
    redirect: ?RedirectJson = null,
    respond: ?RespondJson = null,
    header_set: ?HeaderEditJson = null,
    header_add: ?HeaderEditJson = null,
    header_remove: ?[]const u8 = null,
    rewrite_prefix: ?RewriteJson = null,

    pub const schema_doc =
        "One filter action. Exactly one field is set — the action's kind.";
    pub const schema_one_of = [_][]const u8{
        "reject",
        "redirect",
        "respond",
        "header_set",
        "header_add",
        "header_remove",
        "rewrite_prefix",
    };
    pub const schema_fields = .{
        .reject = .{
            .desc = "Reject the request with this status code.",
            .int_values = &filter.reject_statuses,
        },
        .redirect = .{
            .desc = "Answer the request with a redirect instead of forwarding it.",
        },
        .respond = .{
            .desc = "Answer the request from a configured body instead of " ++
                "forwarding it — this proxy as the origin.",
        },
        .header_set = .{ .desc = "Set (replace) a request header." },
        .header_add = .{ .desc = "Append a request header." },
        .header_remove = .{ .desc = "Remove a request header by name." },
        .rewrite_prefix = .{ .desc = "Rewrite the request path prefix before proxying." },
    };
};

/// A `respond` action (#159): the proxy answers from a named body
/// instead of forwarding. The status defaults to `200` — the common
/// case is serving content, and the error statuses are reachable for a
/// policy page that wants a body without a matching `error_pages`
/// entry.
pub const RespondJson = struct {
    status: u16 = 200,
    body: []const u8,

    pub const schema_doc =
        "Answer the matched request from a configured body, with the status " ++
        "given — the proxy responding as the origin, from memory.";
    pub const schema_fields = .{
        .status = .{
            .desc = "Status to answer with: 200, or one of the error statuses " ++
                "this proxy sends.",
            .int_values = &shed.page_statuses,
        },
        .body = .{
            .desc = "Name of the body to serve, from the top-level `bodies` map.",
            .min_length = 1,
        },
    };
};

/// A `redirect` action's target (#176): a fixed `location` sent
/// verbatim, or a composed one — scheme (required) and optionally host
/// replaced, the request's own canonical path and query carried through
/// so the config never restates them. Exactly one form.
pub const RedirectJson = struct {
    status: u16 = 301,
    location: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    host: ?[]const u8 = null,

    pub const schema_doc =
        "Where a redirect sends the client: a fixed `location`, or a " ++
        "composed target (`scheme` and optionally `host`) that carries the " ++
        "request's own path and query through.";
    pub const schema_fields = .{
        .status = .{
            .desc = "Redirect status: permanent/temporary x method-preserving.",
            .int_values = &filter.redirect_statuses,
        },
        .location = .{
            .desc = "Fixed Location value, sent verbatim; mutually exclusive " ++
                "with scheme/host.",
            .min_length = 1,
        },
        .scheme = .{
            .desc = "Replacement scheme for a composed target. Required there — " ++
                "never guessed, since behind a TLS terminator every hop this " ++
                "proxy sees is plaintext.",
            .enum_type = filter.Redirect.Scheme,
        },
        .host = .{
            .desc = "Replacement canonical host for a composed target; absent " ++
                "keeps the request's own.",
        },
    };
};

/// One response filter rule (#175): a match over the origin's response —
/// status and response headers; the request's facts are gone by the time
/// a response exists, which is the reason this is its own table rather
/// than a scope marker on `FilterJson` — and the header edits applied
/// when it matches. Reject and rewrite are request-side ideas, rejected
/// here by their own names.
pub const ResponseFilterJson = struct {
    match: ResponseMatchJson = .{},
    actions: []const ResponseActionJson,

    pub const schema_doc =
        "One response filter rule: a match over the origin's response and " ++
        "the header edits applied when it matches.";
    pub const schema_fields = .{
        .match = .{ .desc = "Response-match predicate; absent fields match anything." },
        .actions = .{
            .desc = "Header edits (header_set / header_add / header_remove) applied " ++
                "in order when the rule matches. The request-side actions are not " ++
                "fields here at all: by the time these rules run the origin has " ++
                "already answered.",
            .min_items = 1,
        },
    };
};

pub const ResponseMatchJson = struct {
    status: ?[]const u16 = null,
    status_class: ?[]const u8 = null,
    headers: ?[]const HeaderMatchJson = null,

    pub const schema_doc = "Response-match predicate; every absent field matches anything.";
    pub const schema_fields = .{
        .status = .{
            .desc = "Exact response status codes to match; absent matches any status.",
            .min_items = 1,
            .minimum = 100,
            .maximum = 599,
        },
        .status_class = .{
            .desc = "Response status class to match (\"1xx\" through \"5xx\"); " ++
                "absent matches any class.",
            .enum_type = filter.StatusClass,
        },
        .headers = .{ .desc = "Response-header predicates; all must match." },
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
    /// Optional #302 header scope; absent means the route matches any
    /// request. Conjoined with the other two, not ranked against them.
    header: ?RouteHeaderJson = null,
    cluster: []const u8,

    pub const schema_doc =
        "One route entry. Every key it states must hold — host, header and " ++
        "prefix are a conjunction — and the table is matched most-specific " ++
        "first: host, then header, then prefix.";
    pub const schema_fields = .{
        .host = .{ .desc = "Canonical host scope; absent matches any host." },
        .prefix = .{ .desc = "Canonical origin-form path prefix; must start with a slash." },
        .header = .{
            .desc = "Header the request must carry for this route to match; " ++
                "absent matches any request. A route naming one is the " ++
                "narrower rule and is tried before the same route without.",
        },
        .cluster = .{ .desc = "Name of the cluster matching requests route to." },
    };
};

/// A route's header predicate (#302): a pinned canary is a specific
/// client, a test account or an internal gateway's header, which endpoint
/// weights cannot express because it is not probabilistic.
///
/// Two kinds, and deliberately not the three `filters` have. `equals` is
/// one `mem.eql` on a zero-copy head slice and `present` is one lookup;
/// `contains` is a scan whose cost grows with the header a client sent,
/// on a table every request walks. §7 draws the line where a route
/// dimension would become the second match engine it refuses, and a
/// substring test is the near side of it.
pub const RouteHeaderJson = struct {
    name: []const u8,
    /// Exactly one of these selects the predicate kind.
    present: ?bool = null,
    equals: ?[]const u8 = null,

    pub const schema_doc =
        "One header predicate on a route. Exactly one of `present`/`equals` " ++
        "selects the kind. No substring or regex matching: a route's " ++
        "predicate is a bounded comparison, on a table every request walks.";
    pub const schema_one_of = [_][]const u8{ "present", "equals" };
    pub const schema_fields = .{
        .name = .{ .desc = "Header field name (matched case-insensitively)." },
        .present = .{
            .desc = "Matches when the header is present at all (present: false is rejected).",
            .const_true = true,
        },
        .equals = .{ .desc = "Matches when the header's value equals this string exactly." },
    };
};

pub const ClusterJson = struct {
    endpoints: []const EndpointJson,
    /// Optional §7 pick policy; absent means `p2c` (the design's
    /// trajectory), `rr` opts back into strict rotation, and the object
    /// form names a `hash` policy's key (#178) — a bare `"hash"` string
    /// is rejected, because what the cluster is sticky on is the
    /// operator's decision, not a default.
    pick: PickJson = .{ .policy = "p2c" },
    /// Optional §7 active health checks; absent means off, so an
    /// unprobed cluster reserves nothing and is never skipped.
    check: ?CheckJson = null,
    /// Optional §7 passive ejection (#230); absent leaves it off.
    passive_ejection: ?PassiveEjectionJson = null,
    /// Optional §8 per-endpoint concurrency cap; absent means uncapped.
    max_inflight: ?u32 = null,
    /// Optional #181 dial retries across this cluster's endpoints;
    /// absent means none, which is what every config written before the
    /// key existed asked for.
    retries: u16 = 0,
    /// Optional PROXY protocol announcement on upstream connections
    /// (#142); absent sends none. Only valid on clusters no http
    /// listener routes to.
    proxy_protocol: ?ClusterProxyProtocolJson = null,

    pub const schema_doc = "One upstream cluster: its endpoints, pick policy and health checks.";
    pub const schema_fields = .{
        .endpoints = .{
            .desc = "Endpoints: IP:port literals (port must be non-zero), each " ++
                "optionally an object adding a pick weight (#174).",
            .min_items = 1,
        },
        .pick = .{
            .desc = "Endpoint-pick policy: p2c (power-of-two-choices) or rr " ++
                "(strict round-robin) as a bare string, or an object choosing " ++
                "hash (stickiness) and naming its key.",
        },
        .check = .{
            .desc = "Active health checks for every endpoint in this cluster; absent leaves them off.",
        },
        .passive_ejection = .{
            .desc = "Eject endpoints that real traffic reports dead; absent leaves passive ejection off.",
        },
        .max_inflight = .{
            .desc = "Cap on concurrent in-flight work per endpoint; absent leaves the cluster uncapped.",
            .minimum = 1,
            .maximum = constants.endpoint_inflight_max,
        },
        .retries = .{
            .desc = "Further endpoints one request may dial after a refused or " ++
                "unreachable first try; 0 (the default) answers 502 on the first " ++
                "failure. All tries share the one connect timeout.",
            .minimum = 0,
            .maximum = constants.cluster_retries_max,
        },
        .proxy_protocol = .{
            .desc = "Announce each client to this cluster's origins with a PROXY " ++
                "protocol header on the upstream connection (l4-reachable " ++
                "clusters only); absent sends none.",
        },
    };
};

/// One cluster endpoint (#174): the bare `"IP:port"` string every config
/// has always written, or an object naming the same literal plus a pick
/// weight. Both spellings parse to this one shape — a bare string is
/// weight 1 — so the homogeneous cluster, which is most clusters, keeps
/// the cheap form and a canary is one endpoint's worth of ceremony.
pub const EndpointJson = struct {
    address: []const u8,
    weight: u32 = 1,

    pub const schema_doc =
        "One endpoint: an IP:port literal, a `unix:` socket path, or an " ++
        "object carrying either and a relative pick weight.";
    pub const schema_fields = .{
        .address = .{
            .desc = "Endpoint literal: `IP:port` (port must be non-zero), or " ++
                "`unix:` followed by the absolute path of a stream socket " ++
                "(printable ASCII, no quote or backslash).",
            .min_length = 1,
        },
        .weight = .{
            .desc = "Relative share of the cluster's traffic under every pick " ++
                "policy; endpoints default to equal (1). 0 drains the endpoint: " ++
                "still health-checked, never picked.",
            .minimum = 0,
            .maximum = constants.endpoint_weight_max,
        },
    };

    /// The object form as a plain struct, so `innerParse` reads it with
    /// the loader's own strictness (unknown fields rejected) without
    /// recursing back into `jsonParse` below.
    const ObjectForm = struct {
        address: []const u8,
        weight: u32 = 1,
    };

    comptime {
        // The two shapes are one contract: a field added to either and
        // forgotten on the other would let the schema advertise a key
        // the parser rejects, or the parser accept one the schema hides.
        const outer = @typeInfo(EndpointJson).@"struct".fields;
        const inner = @typeInfo(ObjectForm).@"struct".fields;
        assert(outer.len == inner.len);
        for (outer, inner) |a, b| {
            assert(std.mem.eql(u8, a.name, b.name));
            assert(a.type == b.type);
        }
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !EndpointJson {
        switch (try source.peekNextTokenType()) {
            .string => {
                const token = try source.nextAlloc(allocator, .alloc_if_needed);
                const literal: []const u8 = switch (token) {
                    .string, .allocated_string => |slice| slice,
                    // The peek promised a string; anything else is the
                    // scanner disagreeing with itself.
                    else => unreachable,
                };
                return .{ .address = literal, .weight = 1 };
            },
            .object_begin => {
                const object = try std.json.innerParse(ObjectForm, allocator, source, options);
                return .{ .address = object.address, .weight = object.weight };
            },
            // A number, bool, null, or nested array can never name an
            // endpoint; reject the token rather than coercing it.
            else => return error.UnexpectedToken,
        }
    }
};

/// The pick policy's two spellings (#178): the bare policy string every
/// stateless policy needs, or an object carrying the policy *and* its
/// settings — today, a `hash` policy's key. The two parse to this one
/// shape, `EndpointJson`'s pattern; a bare `"hash"` never resolves,
/// because a hash policy without a named key was the misleading default
/// this form replaced.
pub const PickJson = struct {
    policy: []const u8,
    /// Required for `hash`, rejected elsewhere: what the cluster is
    /// sticky on.
    key: ?[]const u8 = null,
    /// The header or cookie name a request-derived key reads; required
    /// there, rejected for `source_ip`.
    name: ?[]const u8 = null,

    pub const schema_doc =
        "Endpoint-pick policy: a bare policy string (p2c, rr), or an object " ++
        "selecting hash and naming what it keys on. The same key always " ++
        "selects the same endpoint, and the mapping is a pure function of " ++
        "the key and the healthy endpoint set — so every zoxy process " ++
        "behind SO_REUSEPORT agrees without sharing any state.";
    pub const schema_fields = .{
        .policy = .{
            .desc = "Pick policy: p2c (power-of-two-choices), rr (strict " ++
                "round-robin), or hash (stickiness on an explicit key).",
            .enum_type = Config.Cluster.Pick,
        },
        .key = .{
            .desc = "What a hash cluster is sticky on: source_ip (all four bytes " ++
                "of an IPv4 address, the /64 prefix of an IPv6 one — RFC 8981 " ++
                "rotation survives), header (rendezvous on the named header's " ++
                "value), or cookie (the named cookie carries the endpoint " ++
                "assignment itself, minted by zoxy — #178).",
            .enum_type = std.meta.Tag(Config.Cluster.HashKey),
        },
        .name = .{
            .desc = "The header or cookie name a request-derived key reads; " ++
                "required for those keys, rejected for source_ip.",
            .min_length = 1,
            .max_length = constants.pick_name_bytes_max,
        },
    };

    /// Two forks over one object (#305), conjoined rather than nested.
    ///
    /// `key` names what a `hash` cluster is sticky on and means nothing
    /// beside `p2c` or `rr`; `name` names the header or cookie a
    /// request-derived key reads and means nothing beside `source_ip`.
    /// Both are `oneOf`s over their own discriminator, and the second
    /// covers the keyless policies for free: with no `key` present its
    /// default arm applies, and that arm forbids `name` — which is the
    /// same verdict the first fork reaches by a different route.
    pub const schema_variants = [_]SchemaVariants{
        .{
            .on = "policy",
            .branches = &.{
                .{ .value = "p2c", .forbid = &.{ "key", "name" } },
                .{ .value = "rr", .forbid = &.{ "key", "name" } },
                .{ .value = "hash", .require = &.{"key"} },
            },
        },
        .{
            .on = "key",
            .branches = &.{
                .{ .value = "source_ip", .default = true, .forbid = &.{"name"} },
                .{ .value = "header", .require = &.{"name"} },
                .{ .value = "cookie", .require = &.{"name"} },
            },
        },
    };

    /// The object form as a plain struct, so `innerParse` reads it with
    /// the loader's own strictness (unknown fields rejected) without
    /// recursing back into `jsonParse` below.
    const ObjectForm = struct {
        policy: []const u8,
        key: ?[]const u8 = null,
        name: ?[]const u8 = null,
    };

    comptime {
        // The two shapes are one contract: a field added to either and
        // forgotten on the other would let the schema advertise a key
        // the parser rejects, or the parser accept one the schema hides.
        const outer = @typeInfo(PickJson).@"struct".fields;
        const inner = @typeInfo(ObjectForm).@"struct".fields;
        assert(outer.len == inner.len);
        for (outer, inner) |a, b| {
            assert(std.mem.eql(u8, a.name, b.name));
            assert(a.type == b.type);
        }
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !PickJson {
        switch (try source.peekNextTokenType()) {
            .string => {
                const token = try source.nextAlloc(allocator, .alloc_if_needed);
                const literal: []const u8 = switch (token) {
                    .string, .allocated_string => |slice| slice,
                    // The peek promised a string; anything else is the
                    // scanner disagreeing with itself.
                    else => unreachable,
                };
                return .{ .policy = literal };
            },
            .object_begin => {
                const object = try std.json.innerParse(ObjectForm, allocator, source, options);
                return .{ .policy = object.policy, .key = object.key, .name = object.name };
            },
            // A number, bool, null, or nested array can never name a
            // policy; reject the token rather than coercing it.
            else => return error.UnexpectedToken,
        }
    }
};

/// One named body (#159): the bytes a configured response serves, plus
/// the content type nothing will guess. Exactly one source arm — a
/// `file` read once at load (parse-once, §1: a changed file needs a
/// restart), or the `inline` string for one-liners that deserve no
/// fixture. The arm structure is the extension point: a future source
/// is a new arm here, and no consumer of a body ever changes.
pub const BodyJson = struct {
    file: ?[]const u8 = null,
    @"inline": ?[]const u8 = null,
    content_type: []const u8,

    pub const schema_doc =
        "One named response body: bytes from a file read at startup, or an " ++
        "inline string — exactly one of the two — plus the Content-Type it " ++
        "is served with. Referenced by name from error_pages (and any " ++
        "future body-serving feature), so one body is one buffer however " ++
        "many places serve it.";
    /// The fork the doc above already describes, said in a way the
    /// schema can act on (#305). It was expressible from the day
    /// `oneOf` was emitted and simply never declared, which is what the
    /// differential gate is for finding.
    pub const schema_one_of = [_][]const u8{ "file", "inline" };
    pub const schema_fields = .{
        .file = .{
            .desc = "Path to the body's file, read once at startup; a change " ++
                "needs a restart (parse-once config).",
        },
        .@"inline" = .{
            .desc = "The body's bytes, verbatim, for content small enough to " ++
                "live in the config.",
        },
        .content_type = .{
            .desc = "The Content-Type header value this body is served with; " ++
                "nothing is inferred from a filename.",
            .min_length = 1,
        },
    };
};

/// The #159 `bodies` map: named assets, keyed by name — `ClustersJson`'s
/// shape, because it is the same idea: a shared resource defined once
/// and referenced by name, so a dangling reference is a load error and
/// one body referenced twice is still one buffer.
pub const BodiesJson = struct {
    entries: []const Entry,

    const Entry = struct {
        name: []const u8,
        body: BodyJson,
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
        // Terminated by the object's own `}` or by the input running
        // out, which the scanner reports as an error — every map here
        // carries the same bound.
        // lint:unbounded-ok — the scanner's `}`/error is the bound
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
                .body = try std.json.innerParse(BodyJson, allocator, source, options),
            });
        }
        const seen = entries.items.len;
        const parsed: @This() = .{ .entries = try entries.toOwnedSlice(allocator) };
        assert(parsed.entries.len == seen);
        return parsed;
    }
};

/// The #159 `error_pages` map: status literal → body name. Small and
/// closed — the loader rejects a status this proxy never sends — so the
/// value is a bare name string, not an object waiting for fields.
pub const ErrorPagesJson = struct {
    entries: []const Entry,

    const Entry = struct {
        status: []const u8,
        body: []const u8,
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
        // which the scanner reports as an error — the same bound the other
        // maps here carry.
        // lint:unbounded-ok — the scanner's `}`/error is the bound
        while (true) {
            const token = try source.nextAlloc(allocator, .alloc_if_needed);
            const status: []const u8 = switch (token) {
                .object_end => break,
                .string => |slice| slice,
                .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            try entries.append(allocator, .{
                .status = status,
                .body = try std.json.innerParse([]const u8, allocator, source, options),
            });
        }
        const seen = entries.items.len;
        const parsed: @This() = .{ .entries = try entries.toOwnedSlice(allocator) };
        assert(parsed.entries.len == seen);
        return parsed;
    }
};

pub const ClusterProxyProtocolJson = struct {
    send: []const u8,

    pub const schema_doc =
        "What this cluster's origins expect ahead of the payload. The header " ++
        "names the connection's client, so only l4 listeners may route to a " ++
        "sending cluster — a pooled HTTP upstream is shared across clients " ++
        "and cannot carry a per-client header.";
    pub const schema_fields = .{
        .send = .{
            .desc = "PROXY protocol version to write: v1 (text) or v2 (binary — " ++
                "what cloud load balancers speak).",
            .enum_type = Config.Cluster.ProxyProtocolSend,
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

    /// A `tcp` probe sends nothing and reads nothing, so every
    /// HTTP-shaped field beside it would be inert; an `http` probe has
    /// to be told what to ask for (#305). `type` defaults to `tcp`, so
    /// that arm carries the absence too.
    pub const schema_variants = [_]SchemaVariants{.{
        .on = "type",
        .branches = &.{
            .{ .value = "tcp", .default = true, .forbid = &.{ "path", "host" } },
            .{ .value = "http", .require = &.{"path"} },
        },
    }};
};

/// One cluster's passive-ejection block (§7, #230). Two numbers and no
/// mode switch: what the signals are is settled by the design, not by
/// the operator, because the choice worth making is *whether* to remove
/// capacity by inference — not which inference to draw.
pub const PassiveEjectionJson = struct {
    fall: u8 = constants.passive_ejection_fall_default,
    recovery_ms: u32 = constants.passive_ejection_recovery_ms_default,

    pub const schema_doc =
        "Eject an endpoint that real traffic reports as dead — a failed dial, " ++
        "or an exchange that produced no response byte before the deadline. " ++
        "Absent leaves it off. Origin 5xx responses are never a signal: a bad " ++
        "deploy is a software bug, not an unhealthy endpoint.";
    pub const schema_fields = .{
        .fall = .{
            .desc = "Consecutive failed requests that eject an endpoint from balancing.",
            .minimum = 1,
            .maximum = constants.health_probe_threshold_max,
        },
        .recovery_ms = .{
            .desc = "How long an ejected endpoint stays out before traffic re-judges it.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
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
    /// Optional #235 head-read budget. Absent is *derived* rather than
    /// fixed — see `resolveHeadTimeout`, which is what keeps every config
    /// written before this field behaving exactly as it did.
    head_ms: ?u32 = null,
    /// Optional #180 tunnel lifetime; absent means an hour. Unlike the
    /// two caps above, zero is rejected — a tunnel pins a dedicated pool
    /// slot, so "no cap" is the one answer §5 cannot carry.
    tunnel_ms: u32 = constants.tunnel_ms_default,
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
        .head_ms = .{
            .desc = "Budget for reading one request head — a slowloris's window. " ++
                "Must exceed connect_ms and not exceed idle_ms.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
        .tunnel_ms = .{
            .desc = "Cap on one tunnelled upgrade's whole life, replacing the idle, " ++
                "request and lifetime deadlines once a connection becomes one. " ++
                "Zero is rejected: a tunnel holds a dedicated pool slot.",
            .minimum = constants.tunnel_ms_min,
            .maximum = constants.tunnel_ms_max,
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
        // lint:unbounded-ok — the scanner's `}`/error is the bound
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
/// HTTP method tokens", which `config_schema.zig` emits as a token
/// enum. #180's upgrade set used to be the second member; it is a flag
/// object now (#305), so the schema states its vocabulary as fields and
/// needs no item marker.
pub const SchemaItems = enum { http_method };

/// The attribute keys a `schema_fields` entry may carry beyond `.desc`.
/// `assert_meta_matches` rejects any other key at comptime, so a typo'd
/// attribute is a compile error, not silently-ignored data.
/// One arm of a discriminated block: the value of the deciding field,
/// and what that value makes required or impossible (#305).
///
/// This is the last shape of cross-field rule the loader stated in prose
/// and the schema could not — "`path` is required, but only when `sink`
/// is `file`". A `oneOf` over the discriminator carries it, so an editor
/// refuses the config before the loader has to.
pub const SchemaVariant = struct {
    /// The discriminator's value on this arm.
    value: []const u8,
    /// Fields this arm requires beyond the DTO's own required set.
    require: []const []const u8 = &.{},
    /// Fields this arm rules out, emitted as a `false` schema — which
    /// nothing satisfies, and is how the dialect says "not here".
    forbid: []const []const u8 = &.{},
    /// Whether the discriminator's *absence* selects this arm — set on
    /// the arm a config that omits the key should land on, and false
    /// everywhere else. An arm that is not the default names the
    /// discriminator in its `required`, or an absent key would satisfy
    /// every arm's `properties` vacuously, `oneOf` would see several
    /// matches, and a valid config would be rejected.
    ///
    /// Usually that is the arm matching the field's Zig default, and
    /// `assertVariantsMatch` requires exactly one wherever the field can
    /// be absent. `PickJson.key` is the case that shows what the rule
    /// actually means: its Zig default is `null`, not `"source_ip"`, and
    /// the `source_ip` arm is marked here because that is the *resolved*
    /// fallback — `resolvePick` reads an absent key as `source_ip` for
    /// the keyless policies. It stays sound because the sibling fork on
    /// `policy` independently requires `key` whenever the policy is
    /// `hash`, so the looser arm is unreachable exactly where it would
    /// have been wrong.
    default: bool = false,
};

/// A discriminated fork over one field. A DTO may declare several, each
/// independent — `pick` forks twice, on `policy` and then on `key` — and
/// they are conjoined with `allOf` so neither shadows the other.
pub const SchemaVariants = struct {
    on: []const u8,
    branches: []const SchemaVariant,
};

const schema_attributes = [_][]const u8{
    "desc",       "minimum",         "maximum",         "min_items", "max_items",
    "min_length", "max_length",      "const_true",      "enum_type", "int_values",
    "items",      "item_min_length", "item_max_length",
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
    assertOneOfMatches(T);
    assertVariantsMatch(T);
}

/// A DTO's optional `schema_one_of` — the fields of which exactly one may
/// be present — held to the shape the emitter turns into JSON Schema's
/// `oneOf`.
///
/// The checks are what make the emitted fork *true* rather than merely
/// present. A name that is not a field would emit a branch nothing can
/// satisfy; a name that is a *required* field (no Zig default) is already
/// in `required`, so every branch would match at once and `oneOf` — which
/// means exactly one — would reject every config. Both are silent in JSON
/// Schema and loud here.
/// Hold a DTO's declared forks to its real fields (#305), the way
/// `assertOneOfMatches` holds its `schema_one_of`.
///
/// The emitter takes `on`, `require` and `forbid` as strings and writes
/// them into the document; without this a typo would emit a keyword
/// naming a field that does not exist — a dead constraint that looks
/// like a live one, which is the failure `assert_meta_matches` exists to
/// prevent one screen up.
fn assertVariantsMatch(comptime T: type) void {
    if (!@hasDecl(T, "schema_variants")) return;
    for (T.schema_variants) |set| {
        if (!@hasField(T, set.on)) {
            @compileError(@typeName(T) ++ " schema_variants forks on '" ++ set.on ++
                "', which is not a field");
        }
        // A fork needs arms to choose between; one arm is a constraint
        // stated the hard way.
        if (set.branches.len < 2) {
            @compileError(@typeName(T) ++ " schema_variants on '" ++ set.on ++
                "' needs at least two branches");
        }
        var defaults = 0;
        for (set.branches) |branch| {
            if (branch.default) defaults += 1;
            if (branch.value.len == 0) {
                @compileError(@typeName(T) ++ " schema_variants on '" ++ set.on ++
                    "' has an empty branch value");
            }
            for (branch.require) |name| {
                if (!@hasField(T, name)) {
                    @compileError(@typeName(T) ++ " variant '" ++ branch.value ++
                        "' requires '" ++ name ++ "', which is not a field");
                }
                if (std.mem.eql(u8, name, set.on)) {
                    @compileError(@typeName(T) ++ " variant '" ++ branch.value ++
                        "' names its own discriminator in require");
                }
            }
            for (branch.forbid) |name| {
                if (!@hasField(T, name)) {
                    @compileError(@typeName(T) ++ " variant '" ++ branch.value ++
                        "' forbids '" ++ name ++ "', which is not a field");
                }
                if (std.mem.eql(u8, name, set.on)) {
                    @compileError(@typeName(T) ++ " variant '" ++ branch.value ++
                        "' forbids its own discriminator");
                }
                // Requiring and forbidding the same key is an arm no
                // document can satisfy — `oneOf` would then have one
                // fewer arm than it appears to.
                for (branch.require) |required| {
                    if (std.mem.eql(u8, name, required)) {
                        @compileError(@typeName(T) ++ " variant '" ++ branch.value ++
                            "' both requires and forbids '" ++ name ++ "'");
                    }
                }
            }
        }
        // Exactly one arm may absorb an absent discriminator, and only
        // when the field can *be* absent. Two would make `oneOf` see
        // both on an omitted key; none would reject a config the loader
        // accepts by default.
        const optional = @typeInfo(@FieldType(T, set.on)) == .optional or
            defaultOf(T, set.on) != null;
        if (optional and defaults != 1) {
            @compileError(@typeName(T) ++ " schema_variants on '" ++ set.on ++
                "' may be absent, so exactly one branch must be .default");
        }
        if (!optional and defaults != 0) {
            @compileError(@typeName(T) ++ " schema_variants on '" ++ set.on ++
                "' is required, so no branch may be .default");
        }
    }
}

/// Whether a field carries a Zig default, as an opaque marker — the
/// value itself is not comparable across the types this walks.
fn defaultOf(comptime T: type, comptime name: []const u8) ?void {
    for (@typeInfo(T).@"struct".fields) |field| {
        if (std.mem.eql(u8, field.name, name)) {
            return if (field.defaultValue() == null) null else {};
        }
    }
    return null;
}

fn assertOneOfMatches(comptime T: type) void {
    if (!@hasDecl(T, "schema_one_of")) return;
    const names = T.schema_one_of;
    // A fork needs two arms. One would be a plain `required` entry, which
    // the emitter already derives, and zero is not a fork at all.
    if (names.len < 2) {
        @compileError(@typeName(T) ++ " schema_one_of needs at least two fields");
    }
    inline for (names, 0..) |name, index| {
        if (!@hasField(T, name)) {
            @compileError(@typeName(T) ++ " schema_one_of names '" ++ name ++ "', which is not a field");
        }
        // A name listed twice emits two identical branches, and a config
        // setting that one field then satisfies *both* — so "exactly one"
        // would reject every valid config for this DTO. Compiles cleanly
        // and is invisible in the schema, which is the whole reason this
        // function exists.
        inline for (names[0..index]) |earlier| {
            if (comptime std.mem.eql(u8, earlier, name)) {
                @compileError(@typeName(T) ++ " schema_one_of names '" ++ name ++ "' twice");
            }
        }
        inline for (@typeInfo(T).@"struct".fields) |field| {
            if (comptime std.mem.eql(u8, field.name, name)) {
                if (comptime field.defaultValue() == null) {
                    @compileError(@typeName(T) ++ ".schema_one_of names '" ++ name ++
                        "', which is required — every arm would match and the fork would reject everything");
                }
            }
        }
    }
}

/// Every plain-struct DTO the schema reflects over. `ClustersJson` is a
/// custom map, handled specially by the emitter, so it is not here. The
/// block below runs `assert_meta_matches` on each at comptime, so the
/// metadata cannot drift from the fields whether or not the emitter builds.
pub const dto_types = .{
    ConfigJson,         ListenerJson,        RouteJson,                FilterJson,
    MatchJson,          HeaderMatchJson,     ActionJson,               HeaderEditJson,
    RewriteJson,        ClusterJson,         TimeoutsJson,             LimitsJson,
    AdminJson,          AccessLogJson,       CheckJson,                PickJson,
    ForwardedJson,      ProxyProtocolJson,   ClusterProxyProtocolJson, EndpointJson,
    ResponseFilterJson, ResponseMatchJson,   RedirectJson,             BodyJson,
    TlsJson,            PassiveEjectionJson, HttpListenerJson,         L4ListenerJson,
    L4RouteJson,        RouteHeaderJson,     ResponseActionJson,
};

comptime {
    for (dto_types) |T| assert_meta_matches(T);
}

/// Endpoints under §7 active checks in a resolved cluster table. A free
/// function rather than only a `Config` method because the loader needs
/// the count *before* the `Config` exists: `resolveCqFill` prices the
/// prober's share of the ring, and clusters are resolved by then while
/// the config is not yet assembled. `Config.checkedEndpoints` delegates
/// here so the two can never disagree.
fn checkedEndpointsOf(clusters: []const Config.Cluster) u32 {
    var total: u32 = 0;
    for (clusters) |cluster| {
        if (cluster.check == null) continue;
        // Bounded by the endpoint count the loader already accepted, and
        // every endpoint index in the tree is a `u16` per cluster.
        total += @intCast(cluster.endpoints.len);
    }
    return total;
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
    try rejectDuplicateClusterNames(arena, clusters_json.entries);

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
        const picked = try resolvePick(&entry.cluster.pick);
        const endpoints = try resolveEndpoints(arena, entry.cluster.endpoints);
        clusters[index] = .{
            .name = entry.name,
            .endpoints = endpoints.addresses,
            .weights = endpoints.weights,
            .pick = picked.pick,
            .check = try resolveCheck(entry.cluster.check, connect_timeout_ms),
            .passive_ejection = try resolvePassiveEjection(entry.cluster.passive_ejection),
            .hash_key = picked.hash_key,
            .max_inflight = try resolveMaxInflight(entry.cluster.max_inflight),
            .retries = try resolveRetries(entry.cluster.retries),
            .proxy_protocol_send = try resolveClusterProxyProtocol(entry.cluster.proxy_protocol),
        };
    }
    assert(clusters.len == count);
    return clusters;
}

/// Duplicate names in O(n log n), by sorting an index permutation and
/// comparing neighbours. It was a nested scan over the entries, which
/// the 16-cluster ceiling kept to ~120 compares; with the ceiling gone
/// that same scan would cost ~2.1e9 string compares on a config at the
/// index type's edge — minutes of startup for a config whose memory
/// fits easily. Which name is reported first changes, and nothing
/// reads it: the error carries no payload.
fn rejectDuplicateClusterNames(
    arena: std.mem.Allocator,
    entries: []const ClustersJson.Entry,
) ParseError!void {
    assert(entries.len >= 1);
    assert(entries.len <= std.math.maxInt(u16));
    const order = try arena.alloc(u16, entries.len);
    for (order, 0..) |*slot, index| slot.* = @intCast(index);
    const ByName = struct {
        entries: []const ClustersJson.Entry,
        fn lessThan(ctx: @This(), a: u16, b: u16) bool {
            return std.mem.lessThan(u8, ctx.entries[a].name, ctx.entries[b].name);
        }
    };
    std.mem.sort(u16, order, ByName{ .entries = entries }, ByName.lessThan);
    for (order[1..], order[0 .. order.len - 1]) |current, previous| {
        if (std.mem.eql(u8, entries[current].name, entries[previous].name)) {
            return error.ClusterNameDuplicate;
        }
    }
}

/// A cluster's resolved endpoint list, in the two parallel halves
/// `Config.Cluster` stores: the addresses, and the weights — null when
/// every endpoint carries weight 1, so the unweighted common case
/// allocates nothing beyond the addresses it always did.
const ResolvedEndpoints = struct {
    addresses: []const io_module.Address,
    weights: ?[]const u16,
};

/// The `unix:` prefix the #305 grammar settled on, for both `bind` and
/// `endpoints`. A prefix on the existing string rather than a tagged
/// object or a second key: the two most-written fields in any config
/// stay single scalars, nginx and HAProxy already spell a socket path
/// this way, and the prefix cannot collide with an IP literal.
pub const unix_address_prefix = "unix:";

/// One endpoint address: an IP literal, or a `unix:` path (#303).
///
/// The path is validated here and nowhere else, on §5's terms — refuse
/// at load rather than repair at runtime. Absolute, because a relative
/// path resolves against a working directory the operator did not name
/// and a service manager may change; within the `sockaddr_un` bound,
/// because the kernel would otherwise take a truncated path as a
/// *different* socket; and printable ASCII without a quote or a
/// backslash.
///
/// That last rule is the one worth arguing. An endpoint address is not
/// free-form text: it lands verbatim in every access-log line and in
/// every Prometheus label, and a quote or a control byte there does not
/// spoil one field — it invalidates the whole line and the whole scrape
/// (§8's "one uncontaminated JSON line per event"). The alternatives
/// are escaping at both renderers, which multiplies the §5 render bound
/// by six for bytes no operator will ever write, or accepting a config
/// that silently corrupts observability. POSIX permits such a path;
/// nothing that runs a service ever creates one.
fn resolveEndpointAddress(
    arena: std.mem.Allocator,
    literal: []const u8,
) ParseError!io_module.Address {
    if (std.mem.startsWith(u8, literal, unix_address_prefix)) {
        return .{ .unix = resolveUnixPath(arena, literal) catch |err| switch (err) {
            error.Relative => return error.EndpointUnixPathRelative,
            error.Invalid => return error.EndpointUnixPathInvalid,
            error.OutOfMemory => return error.OutOfMemory,
        } };
    }
    return .{ .ip = std.Io.net.IpAddress.parseLiteral(literal) catch {
        return error.EndpointInvalid;
    } };
}

/// A `unix:` literal's path, validated and arena-duped. The rules argued
/// at `resolveEndpointAddress`, applied once for both fields that take
/// the grammar — an endpoint and a listener's `bind` — so the two cannot
/// come to disagree about what a socket path is.
fn resolveUnixPath(
    arena: std.mem.Allocator,
    literal: []const u8,
) error{ Invalid, Relative, OutOfMemory }![]const u8 {
    assert(std.mem.startsWith(u8, literal, unix_address_prefix));
    const path = literal[unix_address_prefix.len..];
    if (path.len == 0 or path.len > io_module.Address.unix_path_bytes_max) {
        return error.Invalid;
    }
    if (path[0] != '/') {
        return error.Relative;
    }
    if (!io_module.Address.pathIsRenderable(path)) {
        return error.Invalid;
    }
    // Duped so the address outlives the parsed JSON document, the same
    // lifetime every other resolved string here takes.
    return try arena.dupe(u8, path);
}

/// The `mode` a `unix:` bind asks for its socket file (#303), as the
/// octal string an operator writes in every other tool.
///
/// A string rather than a JSON number, because `0660` in JSON is not
/// valid and `660` is decimal — the two spellings of the same intent
/// differ by a factor of eight, and a mode that is silently wider than
/// asked for is the failure this feature exists to avoid.
fn resolveBindMode(
    mode_json: ?[]const u8,
    bind_address: io_module.Address,
) ParseError!?io_module.FileMode {
    const text = mode_json orelse return null;
    // An IP bind creates no file, so a mode on one describes nothing.
    if (bind_address != .unix) {
        return error.ListenerModeWithoutUnixBind;
    }
    if (text.len == 0 or text.len > 4) {
        return error.ListenerModeInvalid;
    }
    var bits: u16 = 0;
    for (text) |digit| {
        if (digit < '0' or digit > '7') {
            return error.ListenerModeInvalid;
        }
        bits = bits * 8 + (digit - '0');
    }
    assert(bits <= io_module.FileMode.bits_max);
    // setuid, setgid and sticky mean nothing on a socket and everything
    // on the file it is confused with — refused rather than passed
    // through to a chmod nobody meant to write.
    if (bits & 0o7000 != 0) {
        return error.ListenerModeInvalid;
    }
    return .{ .bits = bits };
}

/// The #303 refusals: what a `unix:` listener may not also ask for,
/// because a request arriving on one has no client address to answer
/// with. Refused at load rather than answered with a sentinel — a
/// fabricated `0.0.0.0` would make `hash: source_ip` send every local
/// client to one endpoint, `match.client` compare against a fiction, and
/// `X-Forwarded-For` state an address no one connected from.
fn rejectUnixClientAddressUsers(
    listener: *const Config.Listener,
    clusters: []const Config.Cluster,
) ParseError!void {
    if (listener.forwarded != null) {
        return error.ListenerUnixBindForwarded;
    }
    for (listener.request_filters) |rule| {
        if (rule.match.clients.len >= 1) {
            return error.ListenerUnixBindClientMatch;
        }
    }
    for (listener.routes) |route| {
        try rejectUnixCluster(route.cluster_index, clusters);
    }
    // The SNI table is a *second* set of reachable clusters (#298), and
    // `routes` does not summarise it: an l4 listener with a name table
    // resolves `routes` to one provisional entry — the admitted cluster
    // — and `finishSniPeek` replaces the exchange's cluster with the
    // matched one before any dial. Checking only `routes` would hold the
    // first name to these rules and let every other name past them.
    for (listener.sni_routes) |route| {
        try rejectUnixCluster(route.cluster_index, clusters);
    }
}

/// One reachable cluster's half of the #303 refusals.
fn rejectUnixCluster(
    cluster_index: u16,
    clusters: []const Config.Cluster,
) ParseError!void {
    assert(cluster_index < clusters.len);
    const cluster = clusters[cluster_index];
    if (cluster.pick == .hash and cluster.hash_key == .source_ip) {
        return error.ListenerUnixBindSourceIpHash;
    }
    // A PROXY header announces the client's source and destination
    // addresses. On this listener there is neither: the accepted socket
    // has no peer address and no local one either, so the header could
    // only be written with fictions. Refused as a pair, the shape
    // `rejectTlsClusterSend` above already has.
    if (cluster.proxy_protocol_send != null) {
        return error.ListenerUnixBindClusterSend;
    }
}

/// A listener's `bind` (#303): the same grammar as an endpoint, and the
/// same validation, under this field's own error names — an operator
/// reading `ListenerBindUnixPathRelative` should not have to work out
/// which of the two fields the loader meant.
fn resolveBindAddress(
    arena: std.mem.Allocator,
    literal: []const u8,
) ParseError!io_module.Address {
    if (std.mem.startsWith(u8, literal, unix_address_prefix)) {
        return .{ .unix = resolveUnixPath(arena, literal) catch |err| switch (err) {
            error.Relative => return error.ListenerBindUnixPathRelative,
            error.Invalid => return error.ListenerBindUnixPathInvalid,
            error.OutOfMemory => return error.OutOfMemory,
        } };
    }
    return .{ .ip = std.Io.net.IpAddress.parseLiteral(literal) catch {
        return error.ListenerBindInvalid;
    } };
}

fn resolveEndpoints(
    arena: std.mem.Allocator,
    endpoints_json: []const EndpointJson,
) ParseError!ResolvedEndpoints {
    if (endpoints_json.len == 0) {
        return error.EndpointsEmpty;
    }
    // No policy bound: endpoints cost an arena address each and a column
    // in the §7 endpoint tables, both sized from this count (§5). What is
    // left is the index type's own edge — `n` endpoints produce indices
    // `0..n-1`, and the largest of those must stay inside
    // `endpoint_index_max`, which `Conn` asserts sits below its
    // no-endpoint sentinel.
    if (endpoints_json.len > @as(usize, constants.endpoint_index_max) + 1) {
        return error.EndpointsOverLimit;
    }

    const addresses = try arena.alloc(io_module.Address, endpoints_json.len);
    var weighted = false;
    var weight_sum: u64 = 0;
    for (endpoints_json, addresses) |entry, *address| {
        address.* = try resolveEndpointAddress(arena, entry.address);
        if (address.* == .ip and address.ip.getPort() == 0) {
            return error.EndpointPortZero;
        }
        if (entry.weight > constants.endpoint_weight_max) {
            return error.EndpointWeightOverLimit;
        }
        weighted = weighted or entry.weight != 1;
        weight_sum += entry.weight;
    }
    if (weight_sum == 0) {
        // Every endpoint at weight 0 is a cluster drained to nowhere.
        // Unlike an all-ejected cluster this does not fail open — a
        // drain is a statement, not a verdict — so the config is
        // rejected like an empty endpoint list rather than accepted as
        // one that can never answer.
        return error.EndpointWeightsAllZero;
    }
    assert(addresses.len == endpoints_json.len);
    if (!weighted) {
        return .{ .addresses = addresses, .weights = null };
    }
    const weights = try arena.alloc(u16, endpoints_json.len);
    for (endpoints_json, weights) |entry, *weight| {
        assert(entry.weight <= constants.endpoint_weight_max);
        weight.* = @intCast(entry.weight);
    }
    assert(weights.len == addresses.len);
    return .{ .addresses = addresses, .weights = weights };
}

fn resolveListeners(
    arena: std.mem.Allocator,
    listeners_json: []const ListenerJson,
    clusters: []const Config.Cluster,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
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
    for (listeners_json, listeners) |listener_json, *listener| {
        listener.* = try resolveListener(
            arena,
            &listener_json,
            clusters,
            head_buffer_bytes,
            bodies,
        );
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
            return bindLessThan(
                &ctx.listeners[a].bind_address,
                &ctx.listeners[b].bind_address,
            );
        }
    };
    std.mem.sort(u16, order, ByBind{ .listeners = listeners }, ByBind.lessThan);
    for (order[1..], order[0 .. order.len - 1]) |current, previous| {
        if (listeners[current].bind_address.eql(&listeners[previous].bind_address)) {
            return error.ListenerBindDuplicate;
        }
    }

    assert(listeners.len == listeners_json.len);
    assert(order.len == listeners.len);
    return listeners;
}

/// One listener's whole resolution — split from `resolveListeners`
/// when #159 threaded the bodies table through it and the loop body
/// pushed that function past the length limit. The duplicate-bind pass
/// stays with the caller: it is a property of the set, not of one
/// entry.
fn resolveListener(
    arena: std.mem.Allocator,
    listener_json: *const ListenerJson,
    clusters: []const Config.Cluster,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
) ParseError!Config.Listener {
    assert(clusters.len >= 1);
    assert(head_buffer_bytes >= 1);
    const bind_address = try resolveBindAddress(arena, listener_json.bind);
    const tls = try resolveTls(listener_json.tls);
    // The tag dispatches, and every field it does not carry is one this
    // arm cannot be handed (#305): the seven "this key is meaningless on
    // that protocol" errors this replaced were the loader restating a
    // shape it now simply has.
    var listener: Config.Listener = switch (try protocolOf(listener_json)) {
        .http => try resolveHttpListener(
            arena,
            bind_address,
            tls,
            &listener_json.http.?,
            clusters,
            head_buffer_bytes,
            bodies,
        ),
        .l4 => try resolveL4Listener(arena, bind_address, tls, &listener_json.l4.?, clusters),
    };
    listener.bind_mode = try resolveBindMode(listener_json.mode, bind_address);
    if (bind_address == .unix) {
        try rejectUnixClientAddressUsers(&listener, clusters);
    }
    if (listener.protocol == .http) {
        try rejectHttpClusterSend(listener.routes, clusters);
    }
    if (listener.tls != null) {
        try rejectTlsClusterSend(listener.routes, clusters);
    }
    assert(listener.routes.len >= 1);
    return listener;
}

/// An `http` listener: the routing table, both filter tables, and the
/// three §7 policies only a parsed request can mean anything to.
fn resolveHttpListener(
    arena: std.mem.Allocator,
    bind_address: io_module.Address,
    tls: ?Config.Listener.Tls,
    http_json: *const HttpListenerJson,
    clusters: []const Config.Cluster,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
) ParseError!Config.Listener {
    assert(clusters.len >= 1);
    assert(head_buffer_bytes >= 1);
    return .{
        .bind_address = bind_address,
        // Filled by `resolveListener`, which is where the `mode` field
        // and the bind it describes are both in scope.
        .bind_mode = null,
        .routes = try resolveRoutes(arena, http_json, clusters, head_buffer_bytes),
        .request_filters = try resolveRequestFilters(arena, http_json, head_buffer_bytes, bodies),
        .response_filters = try resolveResponseFilters(arena, http_json),
        .protocol = .http,
        .forwarded = try resolveForwarded(http_json.forwarded),
        .proxy_protocol = null,
        .tls = tls,
        .upgrades = try resolveUpgrades(http_json.upgrades),
        .max_body_bytes = try resolveMaxBodyBytes(http_json.max_body_bytes),
        .proxy_status = http_json.proxy_status,
    };
}

/// An `l4` listener: which cluster (or which table of them) it relays to,
/// and what it expects ahead of the payload.
///
/// Two shapes, and the second is the one that allocates. A `cluster`
/// resolves to the single any-path route every L4 listener has always
/// had. A `routes` table resolves to an SNI table beside it (#298), and
/// then `routes[0]` carries only the cluster admission needs before a
/// byte has been read — see `admittedCluster`.
fn resolveL4Listener(
    arena: std.mem.Allocator,
    bind_address: io_module.Address,
    tls: ?Config.Listener.Tls,
    l4_json: *const L4ListenerJson,
    clusters: []const Config.Cluster,
) ParseError!Config.Listener {
    assert(clusters.len >= 1);
    const has_cluster = l4_json.cluster != null;
    const has_routes = l4_json.routes != null;
    if (has_cluster == has_routes) {
        return error.ListenerClusterOrRoutes; // Neither, or both.
    }
    // Routing by name means reading the client's ClientHello and relaying
    // it on. A listener that *terminates* consumed that hello during its
    // own handshake, so there is nothing left for the peek to read —
    // the two describe different proxies and the config states one (§6).
    if (has_routes and tls != null) {
        return error.ListenerTlsWithSniRoutes;
    }
    const sni_routes: []const sni_router.Route = if (has_routes)
        try resolveSniRoutes(arena, l4_json.routes.?, clusters)
    else
        &.{};
    const routes = try resolveL4Route(arena, admittedCluster(l4_json, sni_routes), clusters);
    assert(routes.len == 1);
    const listener: Config.Listener = .{
        .bind_address = bind_address,
        // Filled by `resolveListener`, as on the http arm.
        .bind_mode = null,
        .routes = routes,
        .sni_routes = sni_routes,
        .protocol = .l4,
        .proxy_protocol = try resolveProxyProtocol(l4_json.proxy_protocol),
        .tls = tls,
        // Stated rather than defaulted: an l4 relay never measures a
        // request, so its cap is the absence of one — and the field's
        // own default is the http default, which would read here as a
        // policy this listener does not have.
        .max_body_bytes = 0,
    };
    assert((listener.sni_routes.len >= 1) == (l4_json.routes != null));
    // The four fields this initializer does not name inherit
    // `Config.Listener`'s defaults, and those defaults happen to be the
    // l4 answer too — an l4 listener has always had no filters, no
    // forwarding and no upgrades, because asking for any of them used to
    // be a rejected config and is now an unwritable one. "Happen to be"
    // is the problem: nothing else pins that coincidence, so a default
    // changed with only the http case in mind would move l4's behaviour
    // silently. These four asserts are where it would stop.
    assert(listener.request_filters.len == 0);
    assert(listener.response_filters.len == 0);
    assert(listener.forwarded == null);
    assert(!listener.upgrades.any());
    return listener;
}

/// A total order over bind addresses, for the duplicate sort above. Only
/// the ordering matters, never the value: equal keys are re-checked with
/// `std.meta.eql`, so a collision costs a comparison rather than a wrong
/// verdict.
/// A total order on bind addresses, so duplicates fall adjacent after
/// one sort. Not a single integer key any more (#303): a socket path
/// does not fit one, so the families are ordered by tag first and the
/// paths lexicographically within theirs.
fn bindLessThan(a: *const io_module.Address, b: *const io_module.Address) bool {
    const a_family: u8 = if (a.* == .ip) 0 else 1;
    const b_family: u8 = if (b.* == .ip) 0 else 1;
    if (a_family != b_family) {
        return a_family < b_family;
    }
    return switch (a.*) {
        .ip => |ip| bindOrder(ip) < bindOrder(b.ip),
        .unix => |path| std.mem.order(u8, path, b.unix) == .lt,
    };
}

fn bindOrder(address: std.Io.net.IpAddress) u160 {
    return switch (address) {
        .ip4 => |v4| (@as(u160, 0) << 152) |
            (@as(u160, std.mem.readInt(u32, &v4.bytes, .big)) << 16) | v4.port,
        .ip6 => |v6| (@as(u160, 1) << 152) |
            (@as(u160, std.mem.readInt(u128, &v6.bytes, .big)) << 16) | v6.port,
    };
}

/// Which cluster an `l4` listener admits connections under, before any
/// byte has been read (#298).
///
/// With no SNI table that is simply the configured cluster. With one it
/// is provisional and the peek replaces it: the any-name route's cluster
/// where the operator declared one, and the first route's where they did
/// not — a listener whose every route is named closes what it cannot
/// place, so nothing is ever relayed to this choice.
fn admittedCluster(
    l4_json: *const L4ListenerJson,
    sni_routes: []const sni_router.Route,
) []const u8 {
    if (l4_json.cluster) |name| {
        assert(sni_routes.len == 0);
        return name;
    }
    assert(sni_routes.len >= 1);
    const routes_json = l4_json.routes.?;
    assert(routes_json.len >= 1);
    for (routes_json) |route_json| {
        if (route_json.sni == null) return route_json.cluster;
    }
    return routes_json[0].cluster;
}

/// An `l4` listener's §6 SNI table (#298), resolved into the immutable
/// arena and sorted named-first so a match is the most specific rule that
/// fires — `router.zig`'s host dimension, one layer down.
///
/// Names are held to `validateRouteHost`, which is not a convenience: it
/// is the *same* canonical form §7's `host` routes are held to, so a name
/// written in both tables means one thing in both. Two rules for one idea
/// is what #298 asked to avoid.
fn resolveSniRoutes(
    arena: std.mem.Allocator,
    routes_json: []const L4RouteJson,
    clusters: []const Config.Cluster,
) ParseError![]const sni_router.Route {
    assert(clusters.len >= 1);
    if (routes_json.len == 0) {
        return error.RoutesEmpty;
    }
    const routes = try arena.alloc(sni_router.Route, routes_json.len);
    for (routes_json, 0..) |route_json, index| {
        const name = if (route_json.sni) |raw| try validateSniName(raw) else null;
        for (routes_json[0..index]) |previous| {
            // Earlier names already passed `validateRouteHost`, so their
            // raw form equals their canonical one and a byte compare is
            // sound. Two rules for one name is an operator asking for two
            // answers to one question, which the scan would settle by
            // position rather than by intent.
            if (optionalHostEql(previous.sni, name)) {
                return error.RouteDuplicate;
            }
        }
        routes[index] = .{
            .server_name = name,
            // `l4ClusterIndexOf`, not the bare lookup: every cluster this
            // table can reach is reachable from an l4 listener, so every
            // one of them is held to the rule the admitted cluster is.
            .cluster_index = try l4ClusterIndexOf(clusters, route_json.cluster),
        };
    }
    std.mem.sort(sni_router.Route, routes, {}, sniRouteMoreSpecific);
    assert(routes.len == routes_json.len);
    assert(routes.len >= 1);
    return routes;
}

/// An SNI route's name: §7's canonical host form, minus what RFC 6066
/// forbids.
///
/// The form check is `validateRouteHost`'s, shared deliberately — a name
/// written in an `http` route table and in an SNI one has to mean the
/// same thing, and two validators is how that stops being true.
///
/// What is *not* shared is the domain. A `Host` header may legitimately
/// be an IP literal, so `canonicalHost` accepts `1.2.3.4` and `[::1]`;
/// RFC 6066 §3 forbids a literal in `server_name` outright, so no
/// compliant ClientHello can ever carry one. Accepting such a route would
/// load a rule that is structurally dead — it could never match, and
/// nothing at runtime would say why. Refused at load instead (§5).
fn validateSniName(raw: []const u8) ParseError![]const u8 {
    const name = try validateRouteHost(raw);
    assert(name.len >= 1);
    // A bracketed literal is the IPv6 form `canonicalHost` admits; the
    // parser wants a port to answer, and the port is irrelevant here —
    // what is being asked is only whether this text is an address.
    if (name[0] == '[') return error.RouteSniIsAddress;
    var buffer: [constants.host_bytes_max + 2]u8 = undefined;
    const with_port = std.fmt.bufPrint(&buffer, "{s}:0", .{name}) catch {
        // Too long to be an address at all, and `validateRouteHost`
        // already bounded it as a name.
        return name;
    };
    if (std.Io.net.IpAddress.parseLiteral(with_port)) |_| {
        return error.RouteSniIsAddress;
    } else |_| {}
    return name;
}

/// Named before any-name, which is all the ordering this table needs:
/// there is one dimension, so specificity is only "does it name a name".
fn sniRouteMoreSpecific(_: void, left: sni_router.Route, right: sni_router.Route) bool {
    return (left.server_name != null) and (right.server_name == null);
}

/// A cluster named by an `l4` listener, by any route it has.
///
/// The reachability rule `HashKey` states — "`header` and `cookie` read
/// the parsed request, so clusters carrying them are unreachable from
/// `l4` listeners" — has to hold for *every* cluster such a listener can
/// reach, not just the one it admits under. An SNI table (#298) makes
/// that a real distinction: a named route can reach a cluster the
/// admitted route never names, and a request-keyed hash there would be a
/// pick the relay has no parsed head to compute.
fn l4ClusterIndexOf(
    clusters: []const Config.Cluster,
    cluster_name: []const u8,
) ParseError!u16 {
    assert(clusters.len >= 1);
    const cluster_index = try clusterIndexOf(clusters, cluster_name);
    assert(cluster_index < clusters.len);
    switch (clusters[cluster_index].hash_key) {
        .source_ip => {},
        .header, .cookie => return error.ListenerL4RequestKeyedHash,
    }
    return cluster_index;
}

/// An `l4` listener's one route: the whole table, because there is no
/// path to match on and therefore nothing to choose between.
///
/// The hash-key check lives here rather than beside the other cluster
/// validations because it is a property of *this pairing*, not of the
/// cluster: a request-derived hash key reads the parsed head (#178) and
/// an l4 listener never parses one. Reachability rather than
/// exclusivity, like an http route to a PROXY-sending cluster — the same
/// cluster stays valid beside any http listener.
fn resolveL4Route(
    arena: std.mem.Allocator,
    cluster_name: []const u8,
    clusters: []const Config.Cluster,
) ParseError![]const router.Route {
    assert(clusters.len >= 1);
    const cluster_index = try l4ClusterIndexOf(clusters, cluster_name);
    assert(cluster_index < clusters.len);
    const routes = try arena.alloc(router.Route, 1);
    routes[0] = .{ .prefix = "/", .cluster_index = cluster_index };
    return routes;
}

/// Compile a listener's §7 filter rules into immutable arena tables.
/// Reachable only from an `http` body, so there is no protocol to check:
/// an l4 listener has no field to put these in (#305). Absent = none.
/// Match keys are validated canonical so a filter and the router agree
/// byte-for-byte, and each action is validated at load, so the request-
/// time interpreter is bounded loops over trusted data.
fn resolveRequestFilters(
    arena: std.mem.Allocator,
    http_json: *const HttpListenerJson,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
) ParseError![]const filter.Rule {
    const filters_json = http_json.request_filters orelse return &.{};
    if (filters_json.len == 0) {
        return &.{};
    }
    const rules = try arena.alloc(filter.Rule, filters_json.len);
    var header_edits: u32 = 0;
    for (filters_json, rules) |rule_json, *rule| {
        rule.* = .{
            .match = try resolveMatch(arena, &rule_json.match, head_buffer_bytes),
            .actions = try resolveActions(arena, rule_json.actions, head_buffer_bytes, bodies),
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
            .reject, .redirect, .respond, .rewrite_prefix => {},
        }
    }
    assert(count <= actions.len); // Edits are a subset of the actions.
    return count;
}

/// Compile a listener's `response_filters` (#175): matches over the
/// origin's response, actions restricted to the three header verbs.
/// The edits compile straight to the renderer's flattened
/// `AppliedHeaderEdit` contract — there is no reject to interleave, so
/// the `Action` union has nothing to carry — and the whole table's edit
/// count is capped like the request side's, since one response applies
/// every matched rule's edits from a single fixed buffer.
fn resolveResponseFilters(
    arena: std.mem.Allocator,
    http_json: *const HttpListenerJson,
) ParseError![]const filter.ResponseRule {
    const rules_json = http_json.response_filters orelse return &.{};
    if (rules_json.len == 0) {
        return &.{};
    }
    const rules = try arena.alloc(filter.ResponseRule, rules_json.len);
    var header_edits: u32 = 0;
    for (rules_json, rules) |rule_json, *rule| {
        rule.* = .{
            .match = try resolveResponseMatch(arena, &rule_json.match),
            .edits = try resolveResponseEdits(arena, rule_json.actions),
        };
        header_edits += @intCast(rule.edits.len);
    }
    if (header_edits > constants.header_edits_max) {
        return error.ResponseFilterHeaderEditsOverLimit;
    }
    assert(header_edits <= constants.header_edits_max);
    assert(rules.len == rules_json.len);
    return rules;
}

fn resolveResponseMatch(
    arena: std.mem.Allocator,
    match_json: *const ResponseMatchJson,
) ParseError!filter.ResponseMatch {
    var match: filter.ResponseMatch = .{};
    if (match_json.status) |statuses_json| {
        // An explicitly empty list is a mistake, not "any" — absence
        // already says that, unambiguously (the `FilterMethodEmpty`
        // rule).
        if (statuses_json.len == 0) {
            return error.ResponseFilterStatusEmpty;
        }
        const statuses = try arena.alloc(u16, statuses_json.len);
        for (statuses_json, statuses) |status, *slot| {
            // The parser only ever produces 100..599 (§7), so a value
            // outside it is a rule that can never fire — a typo, told at
            // load rather than left silently inert.
            if (status < 100 or status > 599) {
                return error.ResponseFilterStatusInvalid;
            }
            slot.* = status;
        }
        match.statuses = statuses;
    }
    if (match_json.status_class) |literal| {
        const class = std.meta.stringToEnum(filter.StatusClass, literal) orelse
            return error.ResponseFilterStatusClassUnknown;
        match.status_class = @intFromEnum(class);
        // The digit contract `responseMatches` asserts on its side of
        // the seam, proven where it is produced.
        assert(match.status_class.? >= 1);
        assert(match.status_class.? <= 5);
    }
    if (match_json.headers) |headers_json| {
        match.headers = try resolveHeaderMatches(arena, headers_json);
    }
    return match;
}

/// Resolve a response rule's actions: the same `ActionJson` vocabulary
/// the request side reads — one muscle memory — with the two arms that
/// have no meaning on the way out rejected by their own names, so an
/// operator reaching for `reject` on a response is told which idea does
/// not transfer rather than handed a generic kind error.
fn resolveResponseEdits(
    arena: std.mem.Allocator,
    actions_json: []const ResponseActionJson,
) ParseError![]const filter.AppliedHeaderEdit {
    if (actions_json.len == 0) {
        return error.FilterActionsEmpty;
    }
    assert(actions_json.len >= 1); // Past the empty guard.
    const edits = try arena.alloc(filter.AppliedHeaderEdit, actions_json.len);
    for (actions_json, edits) |action_json, *edit| {
        edit.* = try resolveResponseEdit(&action_json);
    }
    assert(edits.len == actions_json.len);
    return edits;
}

fn resolveResponseEdit(action_json: *const ResponseActionJson) ParseError!filter.AppliedHeaderEdit {
    // The kind fork, which for this table is now the whole check: the
    // four request-side actions are not fields here, so a config naming
    // one is refused by the strict parser rather than by four rules
    // this function used to carry (#305).
    try requireOneResponseActionKind(action_json);
    if (action_json.header_set) |edit| {
        const resolved = try resolveHeaderEdit(&edit);
        return .{ .kind = .set, .name = resolved.name, .value = resolved.value };
    }
    if (action_json.header_add) |edit| {
        const resolved = try resolveHeaderEdit(&edit);
        return .{ .kind = .add, .name = resolved.name, .value = resolved.value };
    }
    const name = action_json.header_remove.?;
    try validateEditableHeaderName(name);
    return .{ .kind = .remove, .name = name, .value = "" };
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
    if (match_json.client) |cidr_literals| {
        match.clients = try resolveClientCidrs(arena, cidr_literals);
    }
    return match;
}

/// Compile a `client` predicate's CIDR list (#177). An explicitly empty
/// list is a mistake — absence already says "any client", unambiguously
/// (the `FilterMethodEmpty` rule).
fn resolveClientCidrs(
    arena: std.mem.Allocator,
    literals: []const []const u8,
) ParseError![]const filter.Cidr {
    if (literals.len == 0) {
        return error.FilterClientEmpty;
    }
    assert(literals.len >= 1); // Past the empty guard.
    const cidrs = try arena.alloc(filter.Cidr, literals.len);
    for (literals, cidrs) |literal, *cidr| {
        cidr.* = try resolveClientCidr(literal);
    }
    assert(cidrs.len == literals.len);
    return cidrs;
}

/// One CIDR literal to its compiled prefix. The `/len` is mandatory — a
/// bare address has no single meaning across families (an exact IPv4
/// host is /32, but an exact IPv6 *client* is its /64), so the spelling
/// that would need per-family folklore is refused instead. Host bits
/// past the prefix must be zero: `10.0.0.1/8` is a typo for either
/// `10.0.0.0/8` or `10.0.0.1/32`, and the loader cannot know which.
fn resolveClientCidr(literal: []const u8) ParseError!filter.Cidr {
    const slash = std.mem.indexOfScalar(u8, literal, '/') orelse
        return error.FilterClientCidrInvalid;
    const address_text = literal[0..slash];
    const prefix_text = literal[slash + 1 ..];
    if (prefix_text.len == 0) {
        return error.FilterClientPrefixInvalid;
    }
    const prefix_len = std.fmt.parseUnsigned(u8, prefix_text, 10) catch
        return error.FilterClientPrefixInvalid;
    const address = std.Io.net.IpAddress.parse(address_text, 0) catch
        return error.FilterClientCidrInvalid;
    switch (address) {
        .ip4 => |v4| {
            if (prefix_len > 32) {
                return error.FilterClientPrefixTooNarrow;
            }
            assert(prefix_len <= 32);
            const bits = std.mem.readInt(u32, &v4.bytes, .big);
            if (hostBitsSet(u32, bits, prefix_len)) {
                return error.FilterClientCidrHostBits;
            }
        },
        .ip6 => |v6| {
            // A client's IPv6 identity is its /64 (`hash.key:
            // source_ip`, §7): RFC 8981 rotates the interface half on a
            // timer, so a narrower prefix names bits that will not mean
            // the same client in an hour.
            if (prefix_len > 64) {
                return error.FilterClientPrefixTooNarrow;
            }
            assert(prefix_len <= 64);
            const high = std.mem.readInt(u64, v6.bytes[0..8], .big);
            const low = std.mem.readInt(u64, v6.bytes[8..16], .big);
            if (low != 0) {
                return error.FilterClientCidrHostBits;
            }
            assert(low == 0);
            if (hostBitsSet(u64, high, prefix_len)) {
                return error.FilterClientCidrHostBits;
            }
        },
    }
    // The compiled prefix `Cidr.contains` and `clientMatches` assert on
    // their side of the seam, proven where it is produced.
    assert(prefix_len <= 64 or address == .ip4);
    return .{ .address = address, .prefix_len = prefix_len };
}

/// Whether any bit below the prefix is set — the host half that a
/// canonical CIDR keeps zero.
fn hostBitsSet(comptime T: type, bits: T, prefix_len: u8) bool {
    const width = @bitSizeOf(T);
    assert(prefix_len <= width);
    if (prefix_len == 0) {
        return bits != 0;
    }
    if (prefix_len == width) {
        return false;
    }
    assert(prefix_len >= 1);
    const shift: std.math.Log2Int(T) = @intCast(prefix_len);
    const host_mask = (@as(T, std.math.maxInt(T)) >> shift);
    return (bits & host_mask) != 0;
}

/// A route's header predicate (#302), resolved into the same
/// `HeaderMatch` the filter table uses — one type, one evaluator, so two
/// matchers cannot disagree about whether a request carries a header.
///
/// Held to the same name and value rules as a filter's match, which
/// includes what those rules deliberately do *not* reject: a
/// proxy-managed name like `Content-Length` is matchable here as it is
/// there. Only an *edit* target is reserved (§7), because rewriting one
/// smuggles a framing change past the render — reading one to pick a
/// backend changes nothing, and routing runs before any edit anyway.
fn resolveRouteHeader(header_json: RouteHeaderJson) ParseError!router.HeaderMatch {
    try validateHeaderName(header_json.name);
    const set: u8 = @as(u8, @intFromBool(header_json.present != null)) +
        @intFromBool(header_json.equals != null);
    assert(set <= 2); // The route header has two kind fields.
    if (set != 1) {
        return error.RouteHeaderMatchKind;
    }
    if (header_json.present) |present| {
        if (!present) {
            return error.RouteHeaderMatchKind; // "present: false" is not a predicate.
        }
        return .{ .name = header_json.name, .kind = .present, .value = "" };
    }
    const value = header_json.equals.?;
    // An `equals: ""` predicate is meaningful — a header present with an
    // empty value — so the empty value is legal, as it is for a filter.
    try validateHeaderValue(value);
    // `headerMatches` asserts this of every predicate it is handed; the
    // name came through `validateHeaderName`, so stating it here is what
    // ties the producer to that precondition.
    assert(header_json.name.len >= 1);
    return .{ .name = header_json.name, .kind = .equals, .value = value };
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
    bodies: []ResolvedBody,
) ParseError![]const filter.Action {
    if (actions_json.len == 0) {
        return error.FilterActionsEmpty;
    }
    assert(actions_json.len >= 1); // Past the empty guard.
    const actions = try arena.alloc(filter.Action, actions_json.len);
    for (actions_json, actions) |action_json, *action| {
        action.* = try resolveAction(arena, &action_json, head_buffer_bytes, bodies);
    }
    assert(actions.len == actions_json.len);
    return actions;
}

/// Exactly one action field may carry the kind — the "exactly one of"
/// fork both action resolvers share, so a seventh kind cannot be
/// counted in one table and forgotten in the other.
/// The response table's kind fork (#305). Three members rather than the
/// request's seven, and the same verdict — a rule naming none or two
/// has no single action to apply.
fn requireOneResponseActionKind(action_json: *const ResponseActionJson) ParseError!void {
    const set: u8 = @as(u8, @intFromBool(action_json.header_set != null)) +
        @intFromBool(action_json.header_add != null) +
        @intFromBool(action_json.header_remove != null);
    assert(set <= 3); // The response action object has three kind fields.
    if (set != 1) {
        return error.FilterActionKind;
    }
    assert(set == 1);
}

fn requireOneActionKind(action_json: *const ActionJson) ParseError!void {
    const set: u8 = @as(u8, @intFromBool(action_json.reject != null)) +
        @intFromBool(action_json.redirect != null) +
        @intFromBool(action_json.respond != null) +
        @intFromBool(action_json.header_set != null) +
        @intFromBool(action_json.header_add != null) +
        @intFromBool(action_json.header_remove != null) +
        @intFromBool(action_json.rewrite_prefix != null);
    assert(set <= 7); // The action object has seven kind fields.
    if (set != 1) {
        return error.FilterActionKind;
    }
    assert(set == 1);
}

fn resolveAction(
    arena: std.mem.Allocator,
    action_json: *const ActionJson,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
) ParseError!filter.Action {
    try requireOneActionKind(action_json);
    if (action_json.reject) |status| {
        if (!filter.isRejectStatus(status)) {
            return error.FilterRejectStatus;
        }
        return .{ .reject = status };
    }
    if (action_json.redirect) |redirect_json| {
        return .{ .redirect = try resolveRedirect(&redirect_json) };
    }
    if (action_json.respond) |respond_json| {
        // The page set, not the reject set: `200` is the point of this
        // action, and an error status here is a policy page that wants
        // a body without an `error_pages` entry to match.
        if (!shed.isPageStatus(respond_json.status)) {
            return error.FilterRespondStatus;
        }
        const page = try pageFor(arena, bodies, respond_json.body, respond_json.status);
        // The precondition `firstVerdict` asserts on the far side, so
        // the compiled action and the interpreter agree at load rather
        // than on the serving path.
        assert(shed.isPageStatus(page.status));
        return .{ .respond = page };
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

/// Resolve a `redirect` action (#176). The target fork is exactly-one:
/// a fixed `location`, or a composed target whose `scheme` is required
/// — a host alone would leave the scheme guessed, and behind a TLS
/// terminator the guess is wrong exactly when it matters.
fn resolveRedirect(redirect_json: *const RedirectJson) ParseError!filter.Redirect {
    if (!filter.isRedirectStatus(redirect_json.status)) {
        return error.FilterRedirectStatus;
    }
    assert(filter.isRedirectStatus(redirect_json.status));
    const has_location = redirect_json.location != null;
    const has_composed = redirect_json.scheme != null or redirect_json.host != null;
    if (has_location == has_composed) {
        // Neither form, or both at once.
        return error.FilterRedirectTarget;
    }
    if (redirect_json.location) |location| {
        if (location.len == 0) {
            return error.FilterRedirectTarget;
        }
        // A Location is a header value the render emits verbatim: the
        // same injection-safety the header edits prove at load.
        try validateHeaderValue(location);
        return .{ .status = redirect_json.status, .target = .{ .location = location } };
    }
    const scheme_literal = redirect_json.scheme orelse {
        // Host without scheme: half a composed target.
        return error.FilterRedirectTarget;
    };
    const scheme = std.meta.stringToEnum(filter.Redirect.Scheme, scheme_literal) orelse
        return error.FilterRedirectSchemeUnknown;
    var composed: filter.Redirect.Composed = .{ .scheme = scheme };
    if (redirect_json.host) |host| {
        // Canonical like a route host: the Location's authority is a
        // name the operator writes, and the same validation keeps it
        // one the render can emit without a second look.
        composed.host = try validateRouteHost(host);
    }
    return .{ .status = redirect_json.status, .target = .{ .composed = composed } };
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
    // Reserved for the same reason and a stricter one (#240): the value
    // is not merely computed but *required* to be — RFC 9110 §7.6.2 has
    // each hop forward its own decrement, so a rule writing a constant
    // here would restate a number this proxy recomputes per request and
    // hand the next hop a budget that never counts down.
    if (std.ascii.eqlIgnoreCase(name, render.max_forwards_name)) {
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

/// The parser owns the token alphabet, so a name this config accepts and
/// a name the wire accepts can never drift apart (#244 moved the one
/// definition there, beside `isForwardableByte`).
const isTokenByte = parser.isTokenByte;

/// Resolve a listener's route table (§7). `"cluster": "x"` is sugar for a
/// single catch-all route; `"routes": [...]` is the explicit table.
/// Exactly one form is required. Prefixes must already be canonical (so
/// they compare directly against the canonical request path) and unique;
/// the table is sorted longest-prefix-first for the request-time scan.
/// `l4` listeners have no path, so they take only the `cluster` form.
fn resolveRoutes(
    arena: std.mem.Allocator,
    http_json: *const HttpListenerJson,
    clusters: []const Config.Cluster,
    head_buffer_bytes: u32,
) ParseError![]const router.Route {
    const has_cluster = http_json.cluster != null;
    const has_routes = http_json.routes != null;
    if (has_cluster == has_routes) {
        return error.ListenerClusterOrRoutes; // Neither, or both.
    }
    if (has_cluster) {
        const routes = try arena.alloc(router.Route, 1);
        routes[0] = .{
            .prefix = "/",
            .cluster_index = try clusterIndexOf(clusters, http_json.cluster.?),
        };
        assert(routes.len == 1); // The sugar is always one catch-all route.
        return routes;
    }
    const routes_json = http_json.routes.?;
    if (routes_json.len == 0) {
        return error.RoutesEmpty;
    }
    const routes = try arena.alloc(router.Route, routes_json.len);
    for (routes_json, 0..) |route_json, index| {
        try validateRoutePrefix(route_json.prefix, head_buffer_bytes);
        const host = if (route_json.host) |raw| try validateRouteHost(raw) else null;
        const header = if (route_json.header) |raw|
            try resolveRouteHeader(raw)
        else
            null;
        for (routes_json[0..index]) |previous| {
            // Earlier routes already passed validateRouteHost, so their raw
            // host equals its canonical form — a byte compare is sound.
            if (optionalHostEql(previous.host, host) and
                std.mem.eql(u8, previous.prefix, route_json.prefix) and
                // The header is part of what makes a route distinct
                // (#302): two rules sharing a host and prefix but naming
                // different headers are different rules, and only the
                // pair that agrees on all three is the same rule twice.
                routeHeaderEql(previous.header, route_json.header))
            {
                return error.RouteDuplicate;
            }
        }
        routes[index] = .{
            .host = host,
            .prefix = route_json.prefix,
            .header = header,
            .cluster_index = try clusterIndexOf(clusters, route_json.cluster),
        };
    }
    // Host, then header, then prefix (§7, #302): the router's linear scan
    // then finds the most specific match first.
    //
    // Sorted through an index permutation rather than in place, so the
    // comparator can fall back to config order *explicitly*. Since #302
    // that fallback is reachable: two routes may share a host and a
    // prefix and still be distinct rules, because they name different
    // headers — legal, not duplicates, and equally specific by every
    // tier this comparator has. Something must decide between them for a
    // request that carries both, and config order is the only thing left
    // that an operator can see and control. Leaning on `std.mem.sort`
    // being stable would get the same answer today while making it a
    // property of the standard library rather than of this table.
    const order = try arena.alloc(u16, routes.len);
    for (order, 0..) |*slot, index| slot.* = @intCast(index);
    std.mem.sort(u16, order, routes, routeOrderMoreSpecific);
    const sorted = try arena.alloc(router.Route, routes.len);
    for (order, sorted) |from, *slot| {
        assert(from < routes.len);
        slot.* = routes[from];
    }
    assert(sorted.len >= 1);
    return sorted;
}

/// The comparator over indices, so an exact tie can fall back to the
/// order the operator wrote — see `resolveRoutes` for why that fallback
/// is reachable and why it is not left to sort stability.
fn routeOrderMoreSpecific(routes: []const router.Route, left: u16, right: u16) bool {
    assert(left < routes.len);
    assert(right < routes.len);
    if (routeMoreSpecific({}, routes[left], routes[right])) return true;
    if (routeMoreSpecific({}, routes[right], routes[left])) return false;
    // Equally specific: earlier in the config wins, which is what every
    // peer proxy does for *every* route and what this table now does for
    // the one case its tiers cannot separate.
    return left < right;
}

/// Host, then header, then prefix (#302) — the order `router.route`'s
/// doc argues for, applied once here so a request-time match is a scan
/// over an already-sorted table.
fn routeMoreSpecific(_: void, left: router.Route, right: router.Route) bool {
    const left_scoped = left.host != null;
    const right_scoped = right.host != null;
    if (left_scoped != right_scoped) {
        return left_scoped; // A host-scoped route sorts before an any-host one.
    }
    const left_keyed = left.header != null;
    const right_keyed = right.header != null;
    if (left_keyed != right_keyed) {
        // Within one host group, a route naming a header is the narrower
        // rule: it answers a subset of what the same route without one
        // would. A canary pinned by header must therefore be reachable
        // past the rule it is a variant of.
        return left_keyed;
    }
    return left.prefix.len > right.prefix.len;
}

/// Whether two route header predicates are the same rule. Compared on
/// the raw DTOs rather than the resolved matches because this runs inside
/// the resolve loop, before the later route has one — and the name
/// compare is case-insensitive for the reason the matcher's is: RFC 9110
/// says `X-Canary` and `x-canary` are one header.
fn routeHeaderEql(left: ?RouteHeaderJson, right: ?RouteHeaderJson) bool {
    const left_header = left orelse return right == null;
    const right_header = right orelse return false;
    if (!std.ascii.eqlIgnoreCase(left_header.name, right_header.name)) {
        return false;
    }
    if ((left_header.present != null) != (right_header.present != null)) {
        return false;
    }
    const left_equals = left_header.equals orelse return right_header.equals == null;
    const right_equals = right_header.equals orelse return false;
    return std.mem.eql(u8, left_equals, right_equals);
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
/// Resolve one cluster's §7 passive-ejection block (#230). Absent leaves
/// it off, the same shape `check` uses: a feature nobody asked for costs
/// nothing and changes nothing.
///
/// A single-endpoint cluster is *allowed* to configure this even though
/// §7 fail-open makes the ejection a no-op there. Rejecting it would
/// punish the config that is about to grow a second endpoint, and the
/// operator's intent is unambiguous either way. The banner is where that
/// shows up as a fact, not the loader as an error.
fn resolvePassiveEjection(passive_ejection_json: ?PassiveEjectionJson) ParseError!?Config.Cluster.PassiveEjection {
    const passive_ejection = passive_ejection_json orelse return null;
    if (passive_ejection.fall < 1 or passive_ejection.fall > constants.health_probe_threshold_max) {
        return error.ClusterPassiveEjectionFallOutOfRange;
    }
    // Zero would re-admit inside the same tick that ejected, which is not
    // a fast recovery but an ejection that never happened.
    if (passive_ejection.recovery_ms < 1 or passive_ejection.recovery_ms > constants.timeout_ms_max) {
        return error.ClusterPassiveEjectionRecoveryOutOfRange;
    }
    return .{ .fall = passive_ejection.fall, .recovery_ms = passive_ejection.recovery_ms };
}

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

/// Resolve the #181 dial-retry budget. Zero is the default and means
/// "answer the first failure", so it needs no rejection; past the
/// ceiling is refused rather than clamped, because every try this
/// permits is load the surviving endpoints absorb, and an operator who
/// wrote a number the proxy will not honor should hear about it at load
/// rather than infer it from a counter.
fn resolveRetries(retries: u16) ParseError!u16 {
    if (retries > constants.cluster_retries_max) {
        return error.ClusterRetriesOutOfRange;
    }
    return retries;
}

/// Resolve a listener's #236 body cap. Absent takes the default, `0`
/// opts out, and either on an `l4` listener is refused rather than
/// ignored: a byte relay parses no request to measure, so a cap there
/// describes a proxy that is not running — the same refusal `forwarded`
/// and `upgrades` get, for the same reason.
fn resolveMaxBodyBytes(cap: u64) ValidationError!u64 {
    if (cap > constants.request_body_bytes_max) {
        return error.ListenerMaxBodyBytesOutOfRange;
    }
    return cap;
}

/// Resolve a listener's #180 upgrade allowlist. Absent allows none, so
/// an `Upgrade` keeps the `501` it has always got.
///
/// The vocabulary is `UpgradesJson`'s own fields, held to the resolved
/// set's by a comptime check there — so a protocol the proxy can carry
/// and one an operator may write cannot drift apart. Anything else is
/// refused by the strict parser rather than by a rule here (#305): a
/// config that asked to tunnel `h2c` and got silence would believe it
/// had, and after `101` there is no rule left to catch what came
/// through.
fn resolveUpgrades(
    upgrades_json: ?UpgradesJson,
) ValidationError!Config.Listener.Upgrades {
    const asked = upgrades_json orelse return .{};
    var upgrades: Config.Listener.Upgrades = .{};
    inline for (@typeInfo(UpgradesJson).@"struct".fields) |field| {
        @field(upgrades, field.name) = @field(asked, field.name);
    }
    // No rejection for "every flag false", and the shape is why. An
    // empty *list* was a meaningless spelling of a set, so it was
    // refused; a set of flags all false is the ordinary way to write
    // "not this one" — which a templated config does constantly — and
    // it already means exactly what omitting the block means. Nothing
    // §5 rests on it either: the tunnel pool keys off `any()`, so an
    // all-false block reserves nothing, same as absent.
    return upgrades;
}

/// Resolve a listener's §7 client-address forwarding: absent is off, and
/// a `forwarded` block on an `l4` listener is rejected rather than
/// ignored — a byte relay has no header to carry an address, so asking
/// for one there describes a proxy that is not running, exactly like
/// `request_filters` and `routes` on the same listener.
fn resolveForwarded(
    forwarded_json: ?ForwardedJson,
) ValidationError!?Config.Listener.Forwarded {
    const forwarded = forwarded_json orelse return null;
    return std.meta.stringToEnum(Config.Listener.Forwarded, forwarded.mode) orelse
        error.ListenerForwardedModeUnknown;
}

/// Resolve a listener's PROXY protocol expectation (#142): absent is
/// off. Reachable only from an `l4` body — the L7 path has no receive
/// phase yet, so an http listener has nowhere to state a trust boundary
/// nothing enforces, which is the silent hole the option exists to close
/// and is now closed by the shape rather than by a rejection (#305).
fn resolveProxyProtocol(
    proxy_protocol_json: ?ProxyProtocolJson,
) ValidationError!?Config.Listener.ProxyProtocol {
    const proxy_protocol = proxy_protocol_json orelse return null;
    return std.meta.stringToEnum(Config.Listener.ProxyProtocol, proxy_protocol.mode) orelse
        error.ListenerProxyProtocolModeUnknown;
}

/// A listener's TLS block, shape-checked only (§4). This loader does no
/// IO, so whether the files exist, parse, or carry a key of a type the
/// on-loop handshake can afford is `main`'s to find out — where the error
/// can name the path. What is checkable here is that a path was given at
/// all: an empty string would otherwise reach `openat` as a request to
/// open the current directory, which fails somewhere far less obvious.
/// Shared by both protocols rather than living in either body: both
/// speak over a terminated session (§4, §7).
fn resolveTls(tls_json: ?TlsJson) ValidationError!?Config.Listener.Tls {
    const tls = tls_json orelse return null;
    if (tls.cert.len == 0) return error.ListenerTlsCertPathEmpty;
    if (tls.key.len == 0) return error.ListenerTlsKeyPathEmpty;
    return .{ .cert_path = tls.cert, .key_path = tls.key };
}

/// A cluster's resolved pick: the policy, and — for `hash` — the key it
/// is sticky on, `.source_ip` (inert) everywhere else.
const ResolvedPick = struct {
    pick: Config.Cluster.Pick,
    hash_key: Config.Cluster.HashKey,
};

/// Resolve either spelling of `pick` (#178). The policy vocabulary is
/// closed — a typo ("pc2") fails loudly instead of silently balancing
/// as p2c — and so is the key's. `hash` *requires* a key, in the object
/// form: `source_ip` as a silent default was misleading (it reads as
/// "sticky" and quietly is not, behind NAT), so what the cluster keys
/// on is the operator's sentence to write. Key settings beside any
/// other policy are rejected rather than left inert — they read as a
/// request for stickiness the cluster would silently not provide.
fn resolvePick(pick_json: *const PickJson) ParseError!ResolvedPick {
    const pick = std.meta.stringToEnum(Config.Cluster.Pick, pick_json.policy) orelse
        return error.ClusterPickUnknown;
    if (pick != .hash) {
        if (pick_json.key != null or pick_json.name != null) {
            return error.ClusterPickKeyWithoutHash;
        }
        return .{ .pick = pick, .hash_key = .source_ip };
    }
    const key_literal = pick_json.key orelse return error.ClusterPickKeyMissing;
    const key = std.meta.stringToEnum(std.meta.Tag(Config.Cluster.HashKey), key_literal) orelse
        return error.ClusterPickKeyUnknown;
    switch (key) {
        .source_ip => {
            if (pick_json.name != null) {
                return error.ClusterPickNameUnexpected;
            }
            return .{ .pick = pick, .hash_key = .source_ip };
        },
        .header => return .{
            .pick = pick,
            .hash_key = .{ .header = try resolvePickName(pick_json.name) },
        },
        .cookie => return .{
            .pick = pick,
            .hash_key = .{ .cookie = try resolvePickName(pick_json.name) },
        },
    }
}

/// The header or cookie name a request-derived key reads (#178). One
/// grammar for both: an RFC 9110 token, which is also RFC 6265's
/// cookie-name grammar — and one bound, `pick_name_bytes_max`, whose
/// job is the response-side stamp: every Set-Cookie a cookie cluster
/// answers with re-speaks this name into a scratch sized by that
/// constant.
fn resolvePickName(name_json: ?[]const u8) ParseError![]const u8 {
    const name = name_json orelse return error.ClusterPickNameMissing;
    if (name.len == 0) {
        return error.ClusterPickNameInvalid;
    }
    if (name.len > constants.pick_name_bytes_max) {
        return error.ClusterPickNameTooLong;
    }
    assert(name.len >= 1);
    for (name) |byte| {
        if (!isTokenByte(byte)) {
            return error.ClusterPickNameInvalid;
        }
    }
    return name;
}

/// A cluster that sends PROXY protocol (#142) may only be reached by l4
/// listeners: a pooled L7 upstream is shared across clients (§3), and
/// the header is per *connection*, naming one client — so an http route
/// to a sending cluster describes a header that would lie, rejected
/// rather than silently not sent. Reachability, not exclusivity: the
/// same cluster stays valid for every l4 listener beside it.
fn rejectHttpClusterSend(
    routes: []const router.Route,
    clusters: []const Config.Cluster,
) ValidationError!void {
    assert(routes.len >= 1);
    for (routes) |route| {
        assert(route.cluster_index < clusters.len);
        if (clusters[route.cluster_index].proxy_protocol_send != null) {
            return error.ClusterProxyProtocolOnHttpListener;
        }
    }
}

/// The same shape for a terminating listener (§4, #125). A TLS
/// connection's client→upstream window is the engine's plaintext buffer,
/// not the relay buffer — so the send-side PROXY header, which stages
/// into the relay buffer, would be written somewhere the wire never reads
/// and the origin would receive whatever that window happened to hold.
/// Refused at load rather than sent as garbage; the two features compose
/// fine in principle and the staging fork is what has not been written.
fn rejectTlsClusterSend(
    routes: []const router.Route,
    clusters: []const Config.Cluster,
) ValidationError!void {
    assert(routes.len >= 1);
    for (routes) |route| {
        assert(route.cluster_index < clusters.len);
        if (clusters[route.cluster_index].proxy_protocol_send != null) {
            return error.ClusterProxyProtocolOnTlsListener;
        }
    }
}

/// Resolve a cluster's PROXY protocol announcement (#142): absent is
/// off, and the version vocabulary is closed. The l4-only restriction is
/// enforced where listeners resolve — reachability is a property of the
/// listener/cluster *pair*, and only that side sees both.
fn resolveClusterProxyProtocol(
    proxy_protocol_json: ?ClusterProxyProtocolJson,
) ValidationError!?Config.Cluster.ProxyProtocolSend {
    const proxy_protocol = proxy_protocol_json orelse return null;
    return std.meta.stringToEnum(
        Config.Cluster.ProxyProtocolSend,
        proxy_protocol.send,
    ) orelse error.ClusterProxyProtocolSendUnknown;
}

/// How many listeners ask for each of the four features whose pools and
/// buffers are sized before any listener resolves. Split from
/// `parseWithFiles` for the length limit, and it reads better whole: four
/// counts taken on one rule.
///
/// `tls`, `upgrades` and `sni` are **presence only**: whether a block is
/// *usable* is its own resolver's to say, later and per listener.
/// Counting on usability here would size a pool against blocks that might
/// yet be refused, and report a limits error for a config whose real
/// fault is a missing path or a token nobody recognises. `http` is the
/// exception and is validated, because the tag it reads is what says a
/// listener declared a protocol at all (#305).
const ListenerFeatures = struct {
    http: u32 = 0,
    tls: u32 = 0,
    upgrades: u32 = 0,
    /// Listeners routing by SNI (#298) — what decides whether the relay
    /// buffer has to be wide enough to stage a ClientHello.
    sni: u32 = 0,
};

fn countListenerFeatures(listeners: []const ListenerJson) ParseError!ListenerFeatures {
    assert(listeners.len >= 1);
    var features: ListenerFeatures = .{};
    for (listeners) |listener_json| {
        // The tag decides the count, so a listener that names neither
        // body or both is refused here rather than sizing a pool from a
        // protocol nobody stated (#305).
        if (try protocolOf(&listener_json) == .http) features.http += 1;
        if (listener_json.tls != null) features.tls += 1;
        if (listener_json.http) |http_json| {
            // What the pool is sized against is a listener that *allows*
            // an upgrade, not one that mentions the key. Under the list
            // form those were the same thing, because an empty list was
            // refused; under the flag object they are not — `{}` and
            // `{"websocket": false}` mean the same as absent (#305), and
            // counting them would demand a tunnel pool for a listener
            // that can never open one.
            if (http_json.upgrades) |upgrades| {
                const allowed = try resolveUpgrades(upgrades);
                if (allowed.any()) features.upgrades += 1;
            }
        }
        if (listener_json.l4) |l4_json| {
            if (l4_json.routes != null) features.sni += 1;
        }
    }
    // Every count is bounded here, at the one place that can prove it by
    // construction — one turn of the loop per listener, and no field
    // increments twice. Consumers take the struct and inherit the bound
    // rather than re-deriving it.
    assert(features.http <= listeners.len);
    assert(features.tls <= listeners.len);
    assert(features.upgrades <= listeners.len);
    assert(features.sni <= listeners.len);
    return features;
}

/// Which protocol a listener's tag names (#305). The vocabulary used to
/// be a string this compared against, where a typo ("htpp") had to be
/// caught by hand and turned into an error; it is now the body's own key,
/// so an unknown one is an unknown field the strict parser already
/// refuses and the only fault left to name here is a listener that
/// declares neither body or both.
fn protocolOf(listener_json: *const ListenerJson) error{ListenerHttpOrL4}!Config.Listener.Protocol {
    if (listener_json.http != null and listener_json.l4 != null) {
        return error.ListenerHttpOrL4;
    }
    if (listener_json.http != null) return .http;
    if (listener_json.l4 != null) return .l4;
    return error.ListenerHttpOrL4;
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

/// The #180 tunnel lifetime, which is neither of the two shapes
/// `validateTimeouts` handles in bulk.
///
/// It has no "off": a tunnel holds a dedicated pool slot for its whole
/// life, so an unbounded one is the single hold §5's model cannot
/// absorb, and `0` is therefore a value rather than a switch. It carries
/// a *floor* rather than a nonzero check, because a sub-second lifetime
/// would reap every session the instant it opened — a typo that presents
/// as the feature not working. And its ceiling is its own, above
/// `timeout_ms_max`: that bound calls an hour suspicious, which is right
/// for every other timeout and wrong for this one, where an hour is the
/// routine case and must leave somewhere to go.
fn validateTunnelTimeout(tunnel_ms: u32) ValidationError!void {
    if (tunnel_ms < constants.tunnel_ms_min) {
        return error.TimeoutTunnelOutOfRange;
    }
    if (tunnel_ms > constants.tunnel_ms_max) {
        return error.TimeoutTunnelOutOfRange;
    }
    assert(tunnel_ms >= constants.tunnel_ms_min);
    assert(tunnel_ms <= constants.tunnel_ms_max);
}

/// The #235 head-read budget when the config names none.
///
/// Derived rather than fixed, and that is what keeps every config written
/// before this field existed behaving exactly as it did. A flat ten
/// seconds would break two shapes: a config whose whole `idle_ms` is
/// smaller than the default (the head budget must never exceed the idle
/// window it tightens), and — the one that would have been a silent
/// regression rather than a load error — a config with a `connect_ms`
/// *above* ten seconds, whose dial budget would quietly have been cut to
/// the head budget, since the lazy timer cannot move later at the
/// re-base. So the default is the ten seconds clamped into the band the
/// two neighbours leave: strictly above the dial, at or below the idle.
/// `connect_ms < idle_ms` is already enforced, so that band is never
/// empty.
fn defaultHeadMs(timeouts: *const TimeoutsJson) u32 {
    assert(timeouts.connect_ms < timeouts.idle_ms);
    const floored = @max(constants.head_ms_default, timeouts.connect_ms + 1);
    const derived = @min(floored, timeouts.idle_ms);
    assert(derived > timeouts.connect_ms);
    assert(derived <= timeouts.idle_ms);
    return derived;
}

/// The resolved head budget: what the config named, or the derived
/// default. Plain `u32` rather than the usual resolver error union,
/// because `validateHeadOrder` has already held both spellings to the
/// same relations — there is no failure left for this to report, and a
/// return type that claimed one would be the wider of two that fit.
fn resolveHeadTimeout(timeouts: *const TimeoutsJson) u32 {
    const head_ms = timeouts.head_ms orelse defaultHeadMs(timeouts);
    assert(timeouts.connect_ms < head_ms);
    assert(head_ms <= timeouts.idle_ms);
    return head_ms;
}

/// The #235 head-read budget's two orderings, extracted for the length
/// limit the way `validateTunnelTimeout` was.
///
/// Both exist for the reason `connect_ms < idle_ms` does: the single lazy
/// timer only ever moves *earlier* once armed (§4). The first byte
/// re-bases the idle deadline down to the head budget, and the dial
/// re-bases the head budget down to the connect one — so a head budget
/// above `idle_ms` would never take effect, and one at or below
/// `connect_ms` would make the dial's re-base a lengthening the timer
/// cannot honour, silently cutting the dial short. Rejected rather than
/// clamped, like its sibling: a config that reads one way and behaves
/// another is what these checks exist to prevent.
fn validateHeadOrder(timeouts: *const TimeoutsJson) ValidationError!void {
    const head_ms = timeouts.head_ms orelse defaultHeadMs(timeouts);
    if (head_ms == 0 or head_ms > constants.timeout_ms_max) {
        return error.TimeoutOverLimit;
    }
    if (timeouts.connect_ms >= head_ms) {
        return error.TimeoutOrderInvalid;
    }
    if (head_ms > timeouts.idle_ms) {
        return error.TimeoutOrderInvalid;
    }
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
    // The #235 head-read budget sits between the two, and both relations
    // exist for the same reason as the one above: the single lazy timer
    // never moves *later* once armed, only earlier. The first byte
    // re-bases the idle deadline down to the head budget, and the dial
    // re-bases the head budget down to the connect one — so a head budget
    // above `idle_ms` would never take effect, and one at or below
    // `connect_ms` would make the dial's re-base a lengthening the timer
    // cannot honour. Rejected rather than clamped, like its sibling: a
    // config that reads one way and behaves another is the failure this
    // check exists to prevent.
    try validateHeadOrder(timeouts);
    try validateTunnelTimeout(timeouts.tunnel_ms);
    assertTimeoutsBounded(timeouts, &nonzero, &optional);
}

/// What reaching the end of `validateTimeouts` means, restated: every
/// bound a consumer reads without checking is in range, every optional
/// one is at most the ceiling — zero included, which each consumer reads
/// as "off" — and the three relations the deadline handoff depends on are
/// ordered. `Server.init` asserts those same relations of any config
/// however it was built, which is what covers the configs the simulator
/// and the tests hand-build past this loader entirely.
fn assertTimeoutsBounded(
    timeouts: *const TimeoutsJson,
    nonzero: []const u32,
    optional: []const u32,
) void {
    for (nonzero) |value| {
        assert(value >= 1);
        assert(value <= constants.timeout_ms_max);
    }
    for (optional) |value| {
        assert(value <= constants.timeout_ms_max);
    }
    assert(timeouts.connect_ms < timeouts.idle_ms);
    const head_ms = resolveHeadTimeout(timeouts);
    assert(timeouts.connect_ms < head_ms);
    assert(head_ms <= timeouts.idle_ms);
    assert(timeouts.tunnel_ms >= constants.tunnel_ms_min);
    assert(timeouts.tunnel_ms <= constants.tunnel_ms_max);
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
    try std.testing.expectEqual(@as(u16, 8080), parsed.listeners[0].bind_address.ip.getPort());
    try std.testing.expectEqualStrings("origin", parsed.clusters[0].name);
    try std.testing.expectEqual(@as(u16, 9000), parsed.clusters[0].endpoints[0].ip.getPort());
    // The example carries both endpoint spellings (#174): a bare literal
    // at weight 1 beside a weighted object.
    try std.testing.expectEqual(@as(u16, 9001), parsed.clusters[0].endpoints[1].ip.getPort());
    try std.testing.expectEqualSlices(u16, &.{ 1, 3 }, parsed.clusters[0].weights.?);
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
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"drain_deadline_ms":0}}
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.drain_deadline_ms);
    }
    const rejected = [_][]const u8{
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":0}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"idle_ms":0}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":90000,"idle_ms":60000}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":5000,"idle_ms":5000}}
        ,
        // One field is enough to break the pair: a dial budget raised past
        // the *defaulted* idle one is the shape an operator reaches for
        // first, and it reads as tuning one number rather than as ordering
        // two.
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":90000}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,"max_lifetime_ms":0}}
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,"max_lifetime_ms":1800000}}
        );
        try std.testing.expectEqual(@as(u32, 1_800_000), parsed.max_lifetime_ms);
    }
}

test "config: a listener's body key is what names its protocol" {
    // Each tag resolves to its `Protocol`, and that is now the whole job
    // of this test: there is no defaulted spelling left to disagree with
    // an explicit one (#305), and a listener naming neither body or both
    // is `ListenerHttpOrL4`, covered where the fork itself is tested.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(Config.Listener.Protocol.l4, parsed.listeners[0].protocol);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(Config.Listener.Protocol.http, parsed.listeners[0].protocol);
    }
}

test "config: a header route sorts between its host and its prefix" {
    // #302's central question, answered: host, then header, then prefix.
    // The table is written in the least helpful order on purpose — config
    // order must not be able to change an answer.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"routes":[
        \\   {"prefix":"/","cluster":"web"},
        \\   {"header":{"name":"X-Canary","present":true},"prefix":"/","cluster":"canary"},
        \\   {"host":"api.example.com","prefix":"/","cluster":"api"},
        \\   {"host":"api.example.com","header":{"name":"X-Canary","present":true},
        \\    "prefix":"/","cluster":"api-canary"}]}}],
        \\ "clusters":{"web":{"endpoints":["127.0.0.1:2"]},
        \\   "canary":{"endpoints":["127.0.0.1:3"]},
        \\   "api":{"endpoints":["127.0.0.1:4"]},
        \\   "api-canary":{"endpoints":["127.0.0.1:5"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const routes = parsed.listeners[0].routes;
    try std.testing.expectEqual(@as(usize, 4), routes.len);
    // Host group first, and within it the header rule ahead of the bare
    // one; then the any-host group repeating the same shape.
    try std.testing.expect(routes[0].host != null and routes[0].header != null);
    try std.testing.expect(routes[1].host != null and routes[1].header == null);
    try std.testing.expect(routes[2].host == null and routes[2].header != null);
    try std.testing.expect(routes[3].host == null and routes[3].header == null);
}

test "config: two header rules of equal specificity keep config order" {
    // The one tie #302 leaves. Same host, same prefix, different headers:
    // distinct rules, equally specific by every tier, and a request
    // carrying both matches both. The earlier one wins — stated here
    // because it is a promise the docs make, and because relying on
    // `std.mem.sort` being stable would make it std's promise instead.
    const tail = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}," ++
        "\"b\":{\"endpoints\":[\"127.0.0.1:3\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"routes\":[";
    const canary = "{\"header\":{\"name\":\"X-Canary\",\"present\":true}," ++
        "\"prefix\":\"/\",\"cluster\":\"a\"}";
    const beta = "{\"header\":{\"name\":\"X-Beta\",\"present\":true}," ++
        "\"prefix\":\"/\",\"cluster\":\"b\"}";
    const catch_all = "{\"prefix\":\"/\",\"cluster\":\"a\"}";

    // Written canary-first: the canary rule is tried first.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ canary ++ "," ++ beta ++ "," ++ catch_all ++ "]}}]," ++ tail,
        );
        const routes = parsed.listeners[0].routes;
        try std.testing.expectEqualStrings("X-Canary", routes[0].header.?.name);
        try std.testing.expectEqualStrings("X-Beta", routes[1].header.?.name);
        try std.testing.expect(routes[2].header == null);
    }
    // Written beta-first: the other way round, and nothing else moves.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ beta ++ "," ++ canary ++ "," ++ catch_all ++ "]}}]," ++ tail,
        );
        const routes = parsed.listeners[0].routes;
        try std.testing.expectEqualStrings("X-Beta", routes[0].header.?.name);
        try std.testing.expectEqualStrings("X-Canary", routes[1].header.?.name);
        try std.testing.expect(routes[2].header == null);
    }
    // And the catch-all sorts last from either spelling — the tiers still
    // decide everything they can separate, whatever the order.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ catch_all ++ "," ++ beta ++ "," ++ canary ++ "]}}]," ++ tail,
        );
        const routes = parsed.listeners[0].routes;
        try std.testing.expect(routes[0].header != null);
        try std.testing.expect(routes[1].header != null);
        try std.testing.expect(routes[2].header == null);
    }
}

test "config: a route header is a bounded predicate, held to the filter's rules" {
    const tail = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"routes\":[";

    // Exactly one kind, and `present: false` is not a predicate.
    try expectParseError(
        error.RouteHeaderMatchKind,
        head ++ "{\"header\":{\"name\":\"X-C\"},\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    try expectParseError(
        error.RouteHeaderMatchKind,
        head ++ "{\"header\":{\"name\":\"X-C\",\"present\":true,\"equals\":\"v\"}," ++
            "\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    try expectParseError(
        error.RouteHeaderMatchKind,
        head ++ "{\"header\":{\"name\":\"X-C\",\"present\":false}," ++
            "\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // `contains` is not a route predicate at all — the DTO has no such
    // field, so the strict parser refuses it rather than a rule doing so.
    try expectParseError(
        error.UnknownField,
        head ++ "{\"header\":{\"name\":\"X-C\",\"contains\":\"v\"}," ++
            "\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // A name is a token, on the filter table's rule.
    try expectParseError(
        error.FilterHeaderNameInvalid,
        head ++ "{\"header\":{\"name\":\"X Canary\",\"present\":true}," ++
            "\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // But a proxy-managed name is *matchable*, exactly as it is in a
    // filter's match: only an edit target is reserved, because rewriting
    // one smuggles a framing change past the render. Reading one to pick
    // a backend changes nothing — pinned here so the two tables cannot
    // drift on what a header name may be.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        _ = try expectParseOk(&arena_state, head ++
            "{\"header\":{\"name\":\"Content-Length\",\"present\":true}," ++
            "\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail);
    }
}

test "config: the header is part of what makes a route distinct" {
    const tail = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"routes\":[";

    // Same host and prefix, different headers: two rules, not a duplicate
    // — which is the whole point of the dimension.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++
            "{\"header\":{\"name\":\"X-C\",\"equals\":\"v1\"},\"prefix\":\"/\",\"cluster\":\"a\"}," ++
            "{\"header\":{\"name\":\"X-C\",\"equals\":\"v2\"},\"prefix\":\"/\",\"cluster\":\"a\"}," ++
            "{\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail);
        try std.testing.expectEqual(@as(usize, 3), parsed.listeners[0].routes.len);
    }
    // Agreeing on all three is the same rule written twice.
    try expectParseError(error.RouteDuplicate, head ++
        "{\"header\":{\"name\":\"X-C\",\"equals\":\"v1\"},\"prefix\":\"/\",\"cluster\":\"a\"}," ++
        "{\"header\":{\"name\":\"x-c\",\"equals\":\"v1\"},\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail);
    // And a header rule does not collide with the bare rule it varies.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++
            "{\"header\":{\"name\":\"X-C\",\"present\":true},\"prefix\":\"/\",\"cluster\":\"a\"}," ++
            "{\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail);
        try std.testing.expectEqual(@as(usize, 2), parsed.listeners[0].routes.len);
    }
}

test "config: l4 sni routes resolve, named before any-name" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"routes":[
        \\   {"cluster":"fallback"},
        \\   {"sni":"api.example.com","cluster":"api"},
        \\   {"sni":"db.example.com","cluster":"db"}]}}],
        \\ "clusters":{"fallback":{"endpoints":["127.0.0.1:2"]},
        \\   "api":{"endpoints":["127.0.0.1:3"]},
        \\   "db":{"endpoints":["127.0.0.1:4"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const routes = parsed.listeners[0].sni_routes;
    try std.testing.expectEqual(@as(usize, 3), routes.len);
    // Named first whatever the config order, so the scan's first match is
    // the most specific rule — the any-name route can only be reached by
    // a name no rule claimed.
    try std.testing.expect(routes[0].server_name != null);
    try std.testing.expect(routes[1].server_name != null);
    try std.testing.expect(routes[2].server_name == null);
    // And the listener still admits under *a* cluster before any byte is
    // read: the any-name route's, since this config declared one.
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners[0].routes.len);
}

test "config: an l4 listener without sni routes carries no table" {
    // The absence is what says the peek phase does not run, so it is
    // asserted rather than assumed: every config written before #298
    // keeps relaying without reading a byte first.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try std.testing.expectEqual(@as(usize, 0), parsed.listeners[0].sni_routes.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners[0].routes.len);
}

test "config: the l4 sni table is held to §7's own rules" {
    const tail = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"routes\":[";

    // Neither `cluster` nor `routes`, and both: the http body's fork,
    // now the l4 body's too.
    try expectParseError(
        error.ListenerClusterOrRoutes,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{}}]," ++ tail,
    );
    try expectParseError(
        error.ListenerClusterOrRoutes,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
            "\"routes\":[{\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // A name is held to the canonical form §7's `host` routes use — the
    // same rule, so one name means one thing in both tables.
    try expectParseError(
        error.RouteHostNotCanonical,
        head ++ "{\"sni\":\"API.Example.com\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    try expectParseError(
        error.RouteHostNotCanonical,
        head ++ "{\"sni\":\"api.example.com:443\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // Two rules for one name is two answers to one question.
    try expectParseError(
        error.RouteDuplicate,
        head ++ "{\"sni\":\"a.example.com\",\"cluster\":\"a\"}," ++
            "{\"sni\":\"a.example.com\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // And two any-name routes are the same mistake spelled differently.
    try expectParseError(
        error.RouteDuplicate,
        head ++ "{\"cluster\":\"a\"},{\"cluster\":\"a\"}]}}]," ++ tail,
    );
    try expectParseError(
        error.ClusterUnknown,
        head ++ "{\"sni\":\"a.example.com\",\"cluster\":\"ghost\"}]}}]," ++ tail,
    );
    // RFC 6066 §3 forbids an address in `server_name`, so a route naming
    // one could never match anything — a dead rule, refused rather than
    // loaded. A `Host` header may legitimately be a literal, which is why
    // this is the one check the two tables do not share.
    try expectParseError(
        error.RouteSniIsAddress,
        head ++ "{\"sni\":\"1.2.3.4\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    try expectParseError(
        error.RouteSniIsAddress,
        head ++ "{\"sni\":\"[::1]\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // A name that merely *contains* digits is a name.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        _ = try expectParseOk(
            &arena_state,
            head ++ "{\"sni\":\"v2.example.com\",\"cluster\":\"a\"}]}}]," ++ tail,
        );
    }
}

test "config: an l4 route cannot reach a request-keyed hash cluster" {
    // `HashKey`'s own rule: `header` and `cookie` read the parsed
    // request, and an l4 relay parses none. The admitted cluster was
    // always held to it; every cluster an SNI table can reach has to be
    // too, or a named route would resolve to a pick the relay cannot
    // compute (#298).
    const tail = "\"clusters\":{\"plain\":{\"endpoints\":[\"127.0.0.1:2\"]}," ++
        "\"keyed\":{\"endpoints\":[\"127.0.0.1:3\"]," ++
        "\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"s\"}}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    // The keyed cluster reached by a *named* route, with the any-name
    // route pointing somewhere harmless — the shape that slipped past
    // when only the admitted cluster was checked.
    try expectParseError(
        error.ListenerL4RequestKeyedHash,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"routes\":[" ++
            "{\"sni\":\"a.example.com\",\"cluster\":\"keyed\"}," ++
            "{\"cluster\":\"plain\"}]}}]," ++ tail,
    );
    // And still refused when it is the any-name route's own cluster.
    try expectParseError(
        error.ListenerL4RequestKeyedHash,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"routes\":[" ++
            "{\"cluster\":\"keyed\"}]}}]," ++ tail,
    );
}

test "config: sni routing and terminating this listener are different proxies" {
    // Routing by name reads the client's hello and relays it on; a
    // terminating listener consumed that hello during its own handshake,
    // so there is nothing left to read. The config states one (§6).
    try expectParseError(error.ListenerTlsWithSniRoutes,
        \\{"listeners":[{"bind":"127.0.0.1:1",
        \\   "tls":{"cert":"/c.pem","key":"/k.pem"},
        \\   "l4":{"routes":[{"sni":"a.example.com","cluster":"a"}]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: sni routing needs a relay buffer that can stage a hello" {
    // A half too narrow would route the clients whose hellos happen to be
    // short and drop the ones offering post-quantum key shares — one
    // config, two outcomes. Refused at load instead (§5).
    try expectParseError(error.LimitRelayBufferUnderSniRouting,
        \\{"listeners":[{"bind":"127.0.0.1:1",
        \\   "l4":{"routes":[{"sni":"a.example.com","cluster":"a"}]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "limits":{"relay_buffer_bytes":4096},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // The same narrow buffer is fine on a listener that does not peek.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    _ = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "limits":{"relay_buffer_bytes":4096},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: explicit routes resolve, sorted longest-prefix-first" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"routes":[
        \\   {"prefix":"/","cluster":"root"},
        \\   {"prefix":"/api/v2","cluster":"v2"},
        \\   {"prefix":"/api","cluster":"api"}]}}],
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
        router.route(routes, null, "/api/v2/x", &.{}),
    );
    try std.testing.expectEqual(
        @as(?u16, routes[2].cluster_index),
        router.route(routes, null, "/elsewhere", &.{}),
    );
}

test "config: routing schema rejects malformed tables" {
    const base_clusters =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Neither cluster nor routes.
    try expectParseError(error.ListenerClusterOrRoutes, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{}}]," ++ base_clusters);
    // Both cluster and routes.
    try expectParseError(error.ListenerClusterOrRoutes, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // Routes on an l4 listener: there is no path to match, and now no
    // field to ask for one in — the shape refuses what a rule used to
    // (#305), so the verdict is the strict parser's.
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{" ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // And a listener that names no protocol body at all.
    try expectParseError(error.ListenerHttpOrL4, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"}]," ++ base_clusters);
    try expectParseError(error.ListenerHttpOrL4, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"," ++
        "\"http\":{\"cluster\":\"a\"},\"l4\":{\"cluster\":\"a\"}}]," ++ base_clusters);
    // Empty routes table.
    try expectParseError(error.RoutesEmpty, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[]}}]," ++ base_clusters);
    // A non-canonical prefix (dot-segment) — would mismatch at request time.
    try expectParseError(error.RoutePrefixNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"prefix\":\"/a/../b\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // A prefix without a leading slash.
    try expectParseError(error.RoutePrefixNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"prefix\":\"api\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // Duplicate (host, prefix) — same any-host prefix twice.
    try expectParseError(error.RouteDuplicate, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"prefix\":\"/x\",\"cluster\":\"a\"}," ++
        "{\"prefix\":\"/x\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // A non-canonical host (uppercase) — would mismatch at request time.
    try expectParseError(error.RouteHostNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"host\":\"API.Example.com\",\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // A host carrying a port — the port is not part of the routing name.
    try expectParseError(error.RouteHostNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"host\":\"api.example.com:8080\",\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // An unknown cluster named by a route.
    try expectParseError(error.ClusterUnknown, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"ghost\"}]}}]," ++ base_clusters);
}

test "config: host routes resolve, host-specific sorted before any-host" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"routes":[
        \\   {"prefix":"/","cluster":"root"},
        \\   {"host":"api.example.com","prefix":"/","cluster":"api"},
        \\   {"host":"api.example.com","prefix":"/v2","cluster":"v2"}]}}],
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
        router.route(routes, "api.example.com", "/other", &.{}),
    );
    try std.testing.expectEqual(
        @as(?u16, routes[2].cluster_index),
        router.route(routes, "other.example.com", "/v2", &.{}),
    );
}

test "config: filters compile into rules with matches and actions" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a","request_filters":[
        \\   {"match":{"method":["GET","POST"],"path_prefix":"/admin",
        \\             "headers":[{"name":"X-Env","equals":"prod"}]},
        \\    "actions":[{"reject":403}]},
        \\   {"match":{"host":"api.example"},
        \\    "actions":[{"header_set":{"name":"X-Via","value":"zoxy"}},
        \\               {"rewrite_prefix":{"from":"/old","to":"/new"}}]}]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const filters = parsed.listeners[0].request_filters;
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
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"request_filters\":[";
    // An l4 listener has no field to carry filters, populated or
    // vacuously empty: the key it would need is not in the `l4` body, so
    // the strict parser refuses it before any rule could (#305).
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
        "\"request_filters\":[{\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
        "\"request_filters\":[]}}]," ++ tail);
    // A rule with no actions.
    try expectParseError(error.FilterActionsEmpty, head ++ "{\"actions\":[]}]}}]," ++ tail);
    // An action object with no kind set.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{}]}]}}]," ++ tail);
    // An action object with two kinds set.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{\"reject\":403,\"header_remove\":\"X\"}]}]}}]," ++ tail);
    // A reject status outside the policy set.
    try expectParseError(error.FilterRejectStatus, head ++ "{\"actions\":[{\"reject\":503}]}]}}]," ++ tail);
    // An unknown / lowercase method token.
    try expectParseError(error.FilterMethodUnknown, head ++ "{\"match\":{\"method\":[\"get\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A header match with no predicate kind.
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\"}]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A `contains` predicate with an empty needle: it would match every
    // present header (a degenerate `present`), so it is rejected.
    try expectParseError(error.FilterHeaderContainsEmpty, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\",\"contains\":\"\"}]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A non-canonical match path prefix.
    try expectParseError(error.RoutePrefixNotCanonical, head ++ "{\"match\":{\"path_prefix\":\"/a/../b\"},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A header edit with an invalid header name.
    try expectParseError(error.FilterHeaderNameInvalid, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"Bad Name\",\"value\":\"v\"}}]}]}}]," ++ tail);
    // A header value carrying CRLF — a smuggling vector when rendered.
    try expectParseError(error.FilterHeaderValueInvalid, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"X\",\"value\":\"a\\r\\nInjected: 1\"}}]}]}}]," ++ tail);
    // "present: false" is not a predicate.
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\",\"present\":false}]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A rewrite whose target is not canonical.
    try expectParseError(error.RoutePrefixNotCanonical, head ++ "{\"actions\":[{\"rewrite_prefix\":{\"from\":\"/a\",\"to\":\"/b/../c\"}}]}]}}]," ++ tail);
    // A header edit may not name a proxy-managed header — case-insensitively.
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"Host\",\"value\":\"evil\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_remove\":\"content-length\"}]}]}}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_add\":{\"name\":\"Connection\",\"value\":\"close\"}}]}]}}]," ++ tail);
    // The two headers this proxy writes on the client's behalf: a
    // constant here would restate a value it computes per request (§7,
    // #240).
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"X-Forwarded-For\",\"value\":\"1.2.3.4\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"max-forwards\",\"value\":\"9\"}}]}]}}]," ++ tail);
    // A matched header predicate may still name a managed header (read-only).
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"Host\"}]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
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
    const json = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"cluster\":\"a\",\"request_filters\":[" ++ rules ++ "]}}]," ++ tail;
    try expectParseError(error.FilterHeaderEditsOverLimit, json);
}

test "config: redirect actions compile in both target forms" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a","request_filters":[
        \\   {"match":{"host":"www.example.com"},
        \\    "actions":[{"redirect":{"status":308,"scheme":"https","host":"example.com"}}]},
        \\   {"actions":[{"redirect":{"scheme":"https"}}]},
        \\   {"match":{"path_prefix":"/gone"},
        \\    "actions":[{"redirect":{"status":302,"location":"https://status.example.com/"}}]}
        \\ ]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const rules = parsed.listeners[0].request_filters;
    const canonical = rules[0].actions[0].redirect;
    try std.testing.expectEqual(@as(u16, 308), canonical.status);
    try std.testing.expectEqual(filter.Redirect.Scheme.https, canonical.target.composed.scheme);
    try std.testing.expectEqualStrings("example.com", canonical.target.composed.host.?);
    // Scheme-only composed, and the status defaults to the permanent one.
    const to_https = rules[1].actions[0].redirect;
    try std.testing.expectEqual(@as(u16, 301), to_https.status);
    try std.testing.expectEqual(@as(?[]const u8, null), to_https.target.composed.host);
    const fixed = rules[2].actions[0].redirect;
    try std.testing.expectEqual(@as(u16, 302), fixed.status);
    try std.testing.expectEqualStrings("https://status.example.com/", fixed.target.location);
}

test "config: redirect validation has its own errors" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"request_filters\":[";
    // Outside the closed set — 303 changes the method's meaning and has
    // no proxy semantics here.
    try expectParseError(error.FilterRedirectStatus, head ++ "{\"actions\":[{\"redirect\":{\"status\":303,\"scheme\":\"https\"}}]}]}}]," ++ tail);
    // Neither target form, both at once, half a composed one, and an
    // empty literal: each is FilterRedirectTarget.
    try expectParseError(error.FilterRedirectTarget, head ++ "{\"actions\":[{\"redirect\":{\"status\":301}}]}]}}]," ++ tail);
    try expectParseError(error.FilterRedirectTarget, head ++ "{\"actions\":[{\"redirect\":{\"location\":\"https://x/\",\"scheme\":\"https\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterRedirectTarget, head ++ "{\"actions\":[{\"redirect\":{\"host\":\"example.com\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterRedirectTarget, head ++ "{\"actions\":[{\"redirect\":{\"location\":\"\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterRedirectSchemeUnknown, head ++ "{\"actions\":[{\"redirect\":{\"scheme\":\"ftp\"}}]}]}}]," ++ tail);
    // The composed host is a route host: canonical or refused.
    try expectParseError(error.RouteHostNotCanonical, head ++ "{\"actions\":[{\"redirect\":{\"scheme\":\"https\",\"host\":\"WWW.Example.com\"}}]}]}}]," ++ tail);
    // A literal Location is a header value the render emits verbatim:
    // injection-safety is proven at load.
    try expectParseError(error.FilterHeaderValueInvalid, head ++ "{\"actions\":[{\"redirect\":{\"location\":\"https://x/\\r\\nSet-Cookie: a\"}}]}]}}]," ++ tail);
    // Two kinds is still a kind error; a redirect on the way out is not
    // a field a response action has (#305), so the parser refuses it.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{\"redirect\":{\"scheme\":\"https\"},\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
        "\"response_filters\":[{\"actions\":[{\"redirect\":{\"scheme\":\"https\"}}]}]}}]," ++ tail);
}

test "config: client CIDR predicates compile with their prefixes" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a","request_filters":[
        \\   {"match":{"path_prefix":"/admin","client":["10.0.0.0/8","192.168.1.0/24","2001:db8::/32"]},
        \\    "actions":[{"reject":403}]},
        \\   {"match":{"client":["0.0.0.0/0","::/0"]},
        \\    "actions":[{"header_set":{"name":"X-Any","value":"1"}}]}
        \\ ]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const clients = parsed.listeners[0].request_filters[0].match.clients;
    try std.testing.expectEqual(@as(usize, 3), clients.len);
    try std.testing.expectEqual(@as(u8, 8), clients[0].prefix_len);
    try std.testing.expectEqual(@as(u8, 24), clients[1].prefix_len);
    try std.testing.expectEqual(@as(u8, 32), clients[2].prefix_len);
    // The /0 edge parses in both families: an explicit everyone, whose
    // host-bits rule still demands an all-zero address.
    const any = parsed.listeners[0].request_filters[1].match.clients;
    try std.testing.expectEqual(@as(u8, 0), any[0].prefix_len);
    try std.testing.expectEqual(@as(u8, 0), any[1].prefix_len);
    // The compiled prefixes admit and refuse — proving address bytes
    // survived the parse, not only the lengths.
    const office = std.Io.net.IpAddress.parseLiteral("10.9.8.7:1") catch unreachable;
    const stranger = std.Io.net.IpAddress.parseLiteral("11.0.0.1:1") catch unreachable;
    try std.testing.expect(clients[0].contains(&office));
    try std.testing.expect(!clients[0].contains(&stranger));
}

test "config: client CIDR validation has its own errors" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"request_filters\":[";
    // An explicitly empty list: absence already says "any client".
    try expectParseError(error.FilterClientEmpty, head ++ "{\"match\":{\"client\":[]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A bare address has no single meaning across families (an exact
    // IPv4 host is /32, an exact IPv6 client is its /64): the prefix is
    // mandatory.
    try expectParseError(error.FilterClientCidrInvalid, head ++ "{\"match\":{\"client\":[\"10.0.0.1\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.FilterClientCidrInvalid, head ++ "{\"match\":{\"client\":[\"office/8\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.FilterClientPrefixInvalid, head ++ "{\"match\":{\"client\":[\"10.0.0.0/\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.FilterClientPrefixInvalid, head ++ "{\"match\":{\"client\":[\"10.0.0.0/eight\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // Past the family's bound: /32 for v4; /64 for v6, where the low
    // half is interface identity that rotates (RFC 8981).
    try expectParseError(error.FilterClientPrefixTooNarrow, head ++ "{\"match\":{\"client\":[\"10.0.0.0/33\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.FilterClientPrefixTooNarrow, head ++ "{\"match\":{\"client\":[\"2001:db8::/65\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // Host bits set past the prefix: a typo for one of two different
    // ranges, and the loader cannot know which.
    try expectParseError(error.FilterClientCidrHostBits, head ++ "{\"match\":{\"client\":[\"10.0.0.1/8\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.FilterClientCidrHostBits, head ++ "{\"match\":{\"client\":[\"2001:db8::1/48\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
}

test "config: response filters compile into rules with matches and edits" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a","response_filters":[
        \\   {"actions":[{"header_remove":"Server"},
        \\               {"header_set":{"name":"Strict-Transport-Security","value":"max-age=63072000"}}]},
        \\   {"match":{"status_class":"5xx"},
        \\    "actions":[{"header_set":{"name":"Retry-After","value":"1"}}]},
        \\   {"match":{"status":[301,302],"headers":[{"name":"Location","contains":"http:"}]},
        \\    "actions":[{"header_add":{"name":"X-Insecure-Redirect","value":"1"}}]}
        \\ ]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const rules = parsed.listeners[0].response_filters;
    try std.testing.expectEqual(@as(usize, 3), rules.len);
    // The unconditional rule: an all-empty match, edits flattened to the
    // renderer's contract in action order — no `Action` union on the way
    // out, because there is no reject to interleave.
    try std.testing.expectEqual(@as(usize, 0), rules[0].match.statuses.len);
    try std.testing.expectEqual(@as(?u8, null), rules[0].match.status_class);
    try std.testing.expectEqual(@as(usize, 2), rules[0].edits.len);
    try std.testing.expectEqual(filter.AppliedHeaderEdit.Kind.remove, rules[0].edits[0].kind);
    try std.testing.expectEqualStrings("Server", rules[0].edits[0].name);
    try std.testing.expectEqual(filter.AppliedHeaderEdit.Kind.set, rules[0].edits[1].kind);
    // The class spelling compiles to its digit.
    try std.testing.expectEqual(@as(?u8, 5), rules[1].match.status_class);
    // Exact statuses and response-header predicates ride the request
    // side's own vocabularies.
    try std.testing.expectEqualSlices(u16, &.{ 301, 302 }, rules[2].match.statuses);
    try std.testing.expectEqual(filter.HeaderMatch.Kind.contains, rules[2].match.headers[0].kind);
    try std.testing.expectEqual(filter.AppliedHeaderEdit.Kind.add, rules[2].edits[0].kind);
    // The request-side table stays independent: none was configured.
    try std.testing.expectEqual(@as(usize, 0), parsed.listeners[0].request_filters.len);
}

test "config: response filter schema rejects what has no meaning on the way out" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"response_filters\":[";
    // The request-side actions are not fields on a response action at
    // all (#305), so naming one is the strict parser's refusal rather
    // than four rules this table used to carry — and the schema states
    // the same thing, where before it could only be discovered at load.
    inline for (.{
        "{\"reject\":403}",
        "{\"rewrite_prefix\":{\"from\":\"/a\",\"to\":\"/b\"}}",
        "{\"redirect\":{\"status\":301,\"location\":\"/x\"}}",
        "{\"respond\":{\"status\":200,\"body\":\"b\"}}",
    }) |action| {
        try expectParseError(
            error.UnknownField,
            head ++ "{\"actions\":[" ++ action ++ "]}]}}]," ++ tail,
        );
    }
    // A two-kind action is still a kind error, never a misleading arm one.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"X\",\"value\":\"y\"},\"header_remove\":\"X\"}]}]}}]," ++ tail);
    try expectParseError(error.FilterActionsEmpty, head ++ "{\"actions\":[]}]}}]," ++ tail);
    // A status the parser can never produce is a rule that can never
    // fire — a typo, told at load.
    try expectParseError(error.ResponseFilterStatusInvalid, head ++ "{\"match\":{\"status\":[99]},\"actions\":[{\"header_remove\":\"X\"}]}]}}]," ++ tail);
    try expectParseError(error.ResponseFilterStatusInvalid, head ++ "{\"match\":{\"status\":[600]},\"actions\":[{\"header_remove\":\"X\"}]}]}}]," ++ tail);
    // An explicitly empty status list is a mistake — absence already
    // says "any", unambiguously.
    try expectParseError(error.ResponseFilterStatusEmpty, head ++ "{\"match\":{\"status\":[]},\"actions\":[{\"header_remove\":\"X\"}]}]}}]," ++ tail);
    try expectParseError(error.ResponseFilterStatusClassUnknown, head ++ "{\"match\":{\"status_class\":\"6xx\"},\"actions\":[{\"header_remove\":\"X\"}]}]}}]," ++ tail);
    // The proxy-managed names hold on the way out too: hand-written
    // framing would desynchronise the relay.
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"Content-Length\",\"value\":\"0\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_remove\":\"connection\"}]}]}}]," ++ tail);
    // The same on the way out, and by the same mechanism (#305): the
    // `l4` body has no such key, populated or vacuously empty.
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
        "\"response_filters\":[{\"actions\":[{\"header_remove\":\"Server\"}]}]}}]," ++ tail);
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
        "\"response_filters\":[]}}]," ++ tail);
}

test "config: a response filter set over the header-edit budget is rejected" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Same whole-table cap as the request side, on its own error name:
    // one response applies every matched rule's edits from one fixed
    // buffer, so the total is what must fit.
    const rules = comptime blk: {
        var s: []const u8 = "";
        var edit: u16 = 0;
        while (edit < constants.header_edits_max + 1) : (edit += 1) {
            if (edit != 0) s = s ++ ",";
            s = s ++ "{\"actions\":[{\"header_remove\":\"X-Drop\"}]}";
        }
        break :blk s;
    };
    const json = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"cluster\":\"a\",\"response_filters\":[" ++ rules ++ "]}}]," ++ tail;
    try expectParseError(error.ResponseFilterHeaderEditsOverLimit, json);
}

test "config: cluster pick policy parses, defaults to p2c, rejects typos" {
    // Explicit rr and p2c both resolve; absent defaults to p2c.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"pick":"pc2"}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: a check block resolves its kind, thresholds and budget" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],
            \\     "check":{"type":"http","path":"/health"}}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        const http = parsed.clusters[0].check.?.http.?;
        try std.testing.expectEqual(@as(?[]const u8, null), http.host);
        try std.testing.expectEqual(@as(u16, 200), http.expect_status);
    }
}

test "config: the failure-detection fact counts only clusters it can be true of" {
    // What the §5 banner states (#230). The rule has two halves and both
    // are judgement calls worth pinning: detection of *either* kind
    // clears a cluster, and a single-endpoint cluster is never counted
    // however undetected it is — there is nowhere to eject to, and §7
    // fail-open makes the ejection a no-op, so counting it would put
    // noise on exactly the configs the number has nothing to say about.
    const json =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"bare"}}],
        \\ "clusters":{
        \\  "bare":{"endpoints":["127.0.0.1:2","127.0.0.1:3"]},
        \\  "alone":{"endpoints":["127.0.0.1:4"]},
        \\  "probed":{"endpoints":["127.0.0.1:5","127.0.0.1:6"],"check":{"type":"tcp"}},
        \\  "watched":{"endpoints":["127.0.0.1:7","127.0.0.1:8"],"passive_ejection":{}},
        \\  "both":{"endpoints":["127.0.0.1:9","127.0.0.1:10"],
        \\          "check":{"type":"tcp"},"passive_ejection":{}},
        \\  "drained":{"endpoints":[{"address":"127.0.0.1:11","weight":1},
        \\                          {"address":"127.0.0.1:12","weight":0}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const config = try expectParseOk(&arena_state, json);

    // Only `bare`. `alone` is single-endpoint; three have a detector of
    // one kind or the other; and `drained` has two endpoints but only
    // one a request can reach, which is the single-endpoint case wearing
    // a longer spelling — config never reloads, so that weight is final.
    try std.testing.expectEqual(@as(u32, 1), config.clustersWithoutFailureDetection());
}

test "config: a passive_ejection block rejects the thresholds it cannot act on" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"passive_ejection":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Zero would eject on no evidence; the ceiling is what keeps the u8
    // streak from wrapping, shared with the probe thresholds.
    try expectParseError(error.ClusterPassiveEjectionFallOutOfRange, head ++ "{\"fall\":0}" ++ tail);
    try expectParseError(error.ClusterPassiveEjectionFallOutOfRange, head ++ "{\"fall\":65}" ++ tail);
    // A zero cooldown re-admits in the tick that ejected — not a fast
    // recovery but an ejection that never happened.
    try expectParseError(error.ClusterPassiveEjectionRecoveryOutOfRange, head ++ "{\"recovery_ms\":0}" ++ tail);

    // The defaults are what an operator who writes `"passive_ejection":{}` gets,
    // and they are the whole point of the block being two optional
    // numbers: opting in should not require picking them.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const config = try expectParseOk(&arena_state, head ++ "{}" ++ tail);
    const passive_ejection = config.clusters[0].passive_ejection.?;
    try std.testing.expectEqual(constants.passive_ejection_fall_default, passive_ejection.fall);
    try std.testing.expectEqual(constants.passive_ejection_recovery_ms_default, passive_ejection.recovery_ms);

    // Absent is off, and off is not "defaults" — an unconfigured cluster
    // must be distinguishable from one that opted in and took them.
    const bare =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    var bare_arena: std.heap.ArenaAllocator = undefined;
    defer bare_arena.deinit();
    const bare_config = try expectParseOk(&bare_arena, bare);
    try std.testing.expect(bare_config.clusters[0].passive_ejection == null);
}

test "config: a check block rejects every shape it cannot run" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(constants.health_interval_ms_default, parsed.health_interval_ms);
    }
    // Zero would probe in a tight loop; the cluster flag is the switch.
    try expectParseError(error.TimeoutZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,
        \\   "health_interval_ms":0}}
    );
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
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
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}],";
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
    const http_head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}],";
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
    // Both ends of `relay_buffer_bytes`, on the same terms: below the floor
    // a PROXY header or a chunked size line could not be staged in one
    // buffer, and above the ceiling a relay chunk could not cross as one
    // TLS record (§4). The accepted default is exercised by every other
    // config in this file, so only the rejections need naming here.
    try expectParseError(error.LimitRelayBufferBytesOutOfRange, http_head ++ tail ++
        "\"limits\":{\"relay_buffer_bytes\":512}}");
    try expectParseError(error.LimitRelayBufferBytesOutOfRange, http_head ++ tail ++
        "\"limits\":{\"relay_buffer_bytes\":65536}}");
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
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"not-an-address","l4":{"cluster":"a"}},
        \\               {"bind":"127.0.0.1:1","gopher":{"cluster":"a"}}],
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
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}],";
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
    // A typo must not silently relay as L4. The protocol is the body's
    // own key now (#305), so a misspelled one is an unknown *field*
    // rather than an unknown token — the same loudness, one vocabulary
    // fewer to keep in step with the enum.
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","htpp":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // And the key that used to name it is gone: a config still spelling
    // `protocol` is refused rather than quietly ignored.
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","protocol":"http","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: max_lifetime_ms still obeys the shared ceiling" {
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,"max_lifetime_ms":3600001}}
    );
}

fn expectParseError(expected: ParseError, json_bytes: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(expected, parse(arena_state.allocator(), json_bytes));
    try expectSchemaAgrees(expected, json_bytes);
}

/// #305's differential gate, run on every rejection this file states.
///
/// `zig build schema` says what a config may *look* like and the loader
/// says what it may *mean*, and until this nothing checked that the two
/// agree. A config the schema admits and the loader refuses is a
/// cross-field rule that a shape could have carried instead — Part 1's
/// whole argument — so each one has to be named here with the reason it
/// stays the loader's. What the gate forbids is a *new* one appearing
/// quietly.
///
/// Riding on `expectParseError` rather than on a corpus of its own is
/// the point: there is no second list to drift, and a rejection added
/// tomorrow is graded the day it is written.
fn expectSchemaAgrees(expected: ParseError, json_bytes: []const u8) !void {
    // A malformed document is the JSON parser's verdict, not the
    // loader's, and the schema never sees one — `parseFromSlice` below
    // would fail on exactly the same bytes for exactly the same reason.
    if (!isValidationError(expected)) {
        return;
    }
    var schema = try renderedSchema();
    defer schema.deinit();
    var instance = std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        json_bytes,
        .{},
    ) catch return;
    defer instance.deinit();

    var storage: [json_schema.path_bytes_max]u8 = undefined;
    const failure = json_schema.validate(schema.value, instance.value, &storage);
    if (failure == null and schemaGapOf(expected) == null) {
        std.debug.print(
            "\nthe schema admits what the loader refuses as {t}. Either the schema " ++
                "should express it — in which case teach the emitter — or it cannot, " ++
                "in which case add it to `schema_gaps` with the reason (#305).\n",
            .{expected},
        );
        return error.TestUnexpectedResult;
    }
}

/// Why the schema cannot reject a config the loader refuses.
///
/// Not an excuse list: the categories are the argument. Seven of them
/// are closed — a schema describes documents, and no document grammar
/// can parse an address, sum a list of weights, or read another block —
/// so entries there are permanent and correct. Two are **debt** — a fork
/// or a bound the schema could carry — and both are now **empty**: the
/// forks became `SchemaVariants` and the bounds became `maxLength` and
/// its per-item form. Their counts are pinned below at zero, which is
/// the useful place to pin them: above zero the pin said how much work
/// remained, and at zero it says a new cross-field rule cannot be added
/// without either giving it a shape or arguing here why a schema cannot
/// follow.
const SchemaGap = enum {
    /// The value is text whose *meaning* only a parser knows: an address
    /// literal, a canonical path or host, a CIDR, a header-name token, a
    /// media type, an octal mode. A grammar can say "string"; it cannot
    /// say "and it parses".
    literal_syntax,
    /// A length bound on a name the schema has no place to attach one.
    /// Strictly an object *key* — `clusters`, `bodies` and `error_pages`
    /// are keyed by operator-chosen names, and a key has no schema of
    /// its own in this dialect (`propertyNames` is a keyword the emitter
    /// deliberately does not reach for, #305's closed vocabulary). A
    /// bound on a *value* is not this: it has somewhere to attach, and
    /// the emitter emits `maxLength` for it.
    name_length,
    /// A name that must exist in another block — `cluster` naming a
    /// cluster, `body` naming a body. A schema validates one document
    /// against one grammar, not a document against itself.
    cross_reference,
    /// Uniqueness judged by a key the schema cannot compute: two binds
    /// that differ as text and match as addresses, two routes that
    /// differ in spelling and match after canonicalization.
    duplicate,
    /// The filesystem answered, not the document.
    filesystem,
    /// §5 arithmetic: a limit judged against another limit, against the
    /// ring, or against whether any listener asked for the feature it
    /// sizes. Closed-form budget reasoning, and the banner is where it
    /// is explained.
    budget,
    /// A rule between two blocks the schema cannot hold at once — a
    /// listener's shape against a cluster's, or against a sibling of its
    /// own body.
    cross_block,
    /// **Debt, and currently empty.** A fork inside one block that
    /// `oneOf` could carry: a field required exactly when a sibling
    /// takes a given value. `SchemaVariants` carries these now, so a row
    /// arriving here means a fork nobody declared rather than one the
    /// emitter cannot state.
    expressible_fork,
    /// **Debt, and currently empty.** A bound the schema could carry:
    /// an array's `maxItems`, or a string's `maxLength` and its
    /// per-item form. All three are emitted, so a row here means a
    /// field whose ceiling was never written down.
    expressible_bound,
};

const SchemaGapEntry = struct { name: []const u8, gap: SchemaGap };

/// Every loader rejection the schema does not catch, measured rather
/// than guessed: the gate above prints what is missing, and this is the
/// list it printed with a reason attached to each.
///
/// One direction only, and worth stating rather than discovering. A row
/// that is *needed* is proved by the gate: remove it and the case that
/// escapes the schema fails the build. A row that has become *stale* —
/// its rule since made expressible — is not caught, and cannot be
/// cheaply: one error is raised by several cases with different JSON,
/// the schema may catch some of them and not others, so "the schema
/// rejected this case" does not mean the row is unnecessary. Deciding
/// that needs every case for an error collected before any verdict,
/// which this harness has no hook for. So a paid-off rule has to be
/// struck from here by whoever pays it off, and re-running the gate
/// with the row removed is how they check.
const schema_gaps = [_]SchemaGapEntry{
    .{ .name = "AccessLogHeaderDuplicate", .gap = .duplicate },
    .{ .name = "AccessLogHeaderNameInvalid", .gap = .literal_syntax },
    .{ .name = "AdminBindInvalid", .gap = .literal_syntax },
    .{ .name = "BodyContentTypeInvalid", .gap = .literal_syntax },
    .{ .name = "BodyFileUnreadable", .gap = .filesystem },
    .{ .name = "BodyNameEmpty", .gap = .name_length },
    .{ .name = "BodyNameTooLong", .gap = .name_length },
    .{ .name = "BodyUnknown", .gap = .cross_reference },
    .{ .name = "ClusterCheckHostInvalid", .gap = .literal_syntax },
    .{ .name = "ClusterCheckPathNotCanonical", .gap = .literal_syntax },
    .{ .name = "ClusterNameEmpty", .gap = .name_length },
    .{ .name = "ClusterNameTooLong", .gap = .name_length },
    .{ .name = "ClusterPickNameInvalid", .gap = .literal_syntax },
    .{ .name = "ClusterProxyProtocolOnHttpListener", .gap = .cross_block },
    .{ .name = "ClusterProxyProtocolOnTlsListener", .gap = .cross_block },
    .{ .name = "ClusterUnknown", .gap = .cross_reference },
    .{ .name = "EndpointInvalid", .gap = .literal_syntax },
    .{ .name = "EndpointPortZero", .gap = .literal_syntax },
    .{ .name = "EndpointUnixPathInvalid", .gap = .literal_syntax },
    .{ .name = "EndpointUnixPathRelative", .gap = .literal_syntax },
    .{ .name = "EndpointWeightsAllZero", .gap = .budget },
    .{ .name = "ErrorPageStatusInvalid", .gap = .literal_syntax },
    .{ .name = "FilterClientCidrHostBits", .gap = .literal_syntax },
    .{ .name = "FilterClientCidrInvalid", .gap = .literal_syntax },
    .{ .name = "FilterClientPrefixInvalid", .gap = .literal_syntax },
    .{ .name = "FilterClientPrefixTooNarrow", .gap = .literal_syntax },
    .{ .name = "FilterHeaderEditsOverLimit", .gap = .budget },
    .{ .name = "FilterHeaderNameInvalid", .gap = .literal_syntax },
    .{ .name = "FilterHeaderNameReserved", .gap = .literal_syntax },
    .{ .name = "FilterHeaderValueInvalid", .gap = .literal_syntax },
    .{ .name = "FilterRedirectTarget", .gap = .literal_syntax },
    .{ .name = "LimitAccessLogBufferUnderLine", .gap = .budget },
    .{ .name = "LimitAccessLogBufferWithoutSink", .gap = .budget },
    .{ .name = "LimitConnSlotsOverCqFill", .gap = .budget },
    .{ .name = "LimitHeadBuffersOutOfRange", .gap = .budget },
    .{ .name = "LimitHeadBuffersOverConnSlots", .gap = .budget },
    .{ .name = "LimitHeadBuffersWithoutHttpListener", .gap = .budget },
    .{ .name = "LimitRelayBufferUnderSniRouting", .gap = .budget },
    .{ .name = "LimitRelayBuffersOverConnSlots", .gap = .budget },
    .{ .name = "LimitTlsEnginesOverConnSlots", .gap = .budget },
    .{ .name = "LimitTlsEnginesWithoutTlsListener", .gap = .budget },
    .{ .name = "LimitTunnelsOverConnSlots", .gap = .budget },
    .{ .name = "LimitTunnelsRequired", .gap = .budget },
    .{ .name = "LimitTunnelsWithoutUpgrades", .gap = .budget },
    .{ .name = "LimitUpstreamHeadBuffersOutOfRange", .gap = .budget },
    .{ .name = "LimitUpstreamHeadBuffersOverUpstreamSlots", .gap = .budget },
    .{ .name = "LimitUpstreamHeadBuffersWithoutHttpListener", .gap = .budget },
    .{ .name = "ListenerBindDuplicate", .gap = .duplicate },
    .{ .name = "ListenerBindInvalid", .gap = .literal_syntax },
    .{ .name = "ListenerBindUnixPathInvalid", .gap = .literal_syntax },
    .{ .name = "ListenerBindUnixPathRelative", .gap = .literal_syntax },
    .{ .name = "ListenerL4RequestKeyedHash", .gap = .cross_block },
    .{ .name = "ListenerModeInvalid", .gap = .literal_syntax },
    .{ .name = "ListenerModeWithoutUnixBind", .gap = .cross_block },
    .{ .name = "ListenerTlsWithSniRoutes", .gap = .cross_block },
    .{ .name = "ListenerUnixBindClientMatch", .gap = .cross_block },
    .{ .name = "ListenerUnixBindClusterSend", .gap = .cross_block },
    .{ .name = "ListenerUnixBindForwarded", .gap = .cross_block },
    .{ .name = "ListenerUnixBindSourceIpHash", .gap = .cross_block },
    .{ .name = "ResponseFilterHeaderEditsOverLimit", .gap = .budget },
    .{ .name = "RouteDuplicate", .gap = .duplicate },
    .{ .name = "RouteHostNotCanonical", .gap = .literal_syntax },
    .{ .name = "RoutePrefixNotCanonical", .gap = .literal_syntax },
    .{ .name = "RouteSniIsAddress", .gap = .literal_syntax },
    .{ .name = "TimeoutOrderInvalid", .gap = .budget },
};

comptime {
    // 81 rows against 146 error members is ~12k comparisons, well past
    // the default budget and still trivial at compile time.
    @setEvalBranchQuota(200_000);
    // Every name here must be a real member, or a renamed error would
    // leave a row that excuses nothing and hides its successor.
    for (schema_gaps) |entry| {
        var found = false;
        for (@typeInfo(ValidationError).error_set.?) |candidate| {
            if (std.mem.eql(u8, candidate.name, entry.name)) found = true;
        }
        if (!found) @compileError("schema_gaps names no such ValidationError: " ++ entry.name);
    }
    // And no name twice, or one row would shadow a second reason.
    for (schema_gaps, 0..) |entry, index| {
        for (schema_gaps[index + 1 ..]) |other| {
            if (std.mem.eql(u8, entry.name, other.name)) {
                @compileError("schema_gaps names " ++ entry.name ++ " twice");
            }
        }
    }
}

fn schemaGapOf(expected: ParseError) ?SchemaGap {
    inline for (schema_gaps) |entry| {
        if (expected == @field(ValidationError, entry.name)) return entry.gap;
    }
    return null;
}

test "config: the schema's debt to the loader only ever falls (#305)" {
    // The measurable definition of the freeze being done, and it now
    // reads zero. Seven gap categories are closed by what a schema *is*
    // — no grammar parses an address, sums a list, resolves a name into
    // another block, computes canonical equality, reads the filesystem,
    // bounds an object key, or holds two blocks at once. These two are
    // what the emitter *could* express, and everything that was in them
    // has been expressed: the forks became `SchemaVariants`, the bounds
    // became `maxLength` and its per-item form, and two rows that looked
    // like bounds turned out to be sums and moved to `budget`.
    //
    // Zero is the interesting number to pin. Above zero it said how much
    // work was left; at zero it says a new cross-field rule cannot be
    // added without either shaping it or arguing, in this file, why a
    // schema cannot follow.
    var forks: usize = 0;
    var bounds: usize = 0;
    for (schema_gaps) |entry| {
        switch (entry.gap) {
            .expressible_fork => forks += 1,
            .expressible_bound => bounds += 1,
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 0), forks);
    try std.testing.expectEqual(@as(usize, 0), bounds);
}

/// Whether `expected` is the loader's own verdict rather than the JSON
/// parser's. `ParseError` is the union of both, and only the loader's
/// half is a claim about config *shape*.
fn isValidationError(expected: ParseError) bool {
    inline for (@typeInfo(ValidationError).error_set.?) |candidate| {
        if (expected == @field(ValidationError, candidate.name)) return true;
    }
    return false;
}

/// The rendered schema, parsed fresh for each case rather than cached.
///
/// A cache would outlive the test that filled it and every allocator
/// this suite runs under would call that a leak — which it would be. The
/// document is 60 KiB and this is a test path, so re-rendering is the
/// cheaper mistake to make.
var schema_storage: [128 * 1024]u8 = undefined;

fn renderedSchema() !std.json.Parsed(std.json.Value) {
    var writer = std.Io.Writer.fixed(&schema_storage);
    try @import("config_schema.zig").writeSchema(&writer);
    return std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        writer.buffered(),
        .{},
    );
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
    const parsed = try parse(arena_state.allocator(), json_bytes);
    try expectSchemaAccepts(json_bytes);
    return parsed;
}

/// The other half of #305's gate, and the cheaper one: whatever the
/// loader accepts, the schema must accept too.
///
/// This direction has no exemptions and never will. A schema that
/// rejects a working config is not a conservative schema — it is a lie
/// told to every editor that reads it, and the operator who believes it
/// deletes a key that was fine. `zig build schema` exists to be trusted
/// by tools that will never run the loader.
fn expectSchemaAccepts(json_bytes: []const u8) !void {
    var schema = try renderedSchema();
    defer schema.deinit();
    var instance = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        json_bytes,
        .{},
    );
    defer instance.deinit();

    var storage: [json_schema.path_bytes_max]u8 = undefined;
    if (json_schema.validate(schema.value, instance.value, &storage)) |failure| {
        std.debug.print(
            "\nthe schema rejects what the loader accepts: {s} at '{s}' (#305)\n",
            .{ @tagName(failure.reason), failure.path },
        );
        return error.TestUnexpectedResult;
    }
}

test "config: the shipped example validates against its own schema (#305)" {
    // The one config in the tree, held to the document `zig build schema`
    // hands an editor. It is the example an operator starts from, so a
    // schema that flags it would be wrong about the first file anybody
    // writes.
    try expectSchemaAccepts(@embedFile("example_config"));
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
        break :blk "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
            "\"routes\":[" ++ routes ++ "],\"request_filters\":[" ++ filters ++ "]}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    };
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state, json);
    try std.testing.expectEqual(@as(usize, route_count), parsed.listeners[0].routes.len);
    try std.testing.expectEqual(@as(usize, route_count), parsed.listeners[0].request_filters.len);
}

test "config: strictness rejects unknown and duplicate fields" {
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a","nope":1}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.DuplicateField,
        \\{"listeners":[],"listeners":[],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ClusterNameDuplicate,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\ "listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
        \\ "listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a","$schema":"x"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: references and addresses are validated" {
    try expectParseError(error.ClusterUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"missing"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // Hostnames are structurally unresolvable: static addresses only (§1).
    try expectParseError(error.EndpointInvalid,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["origin.internal:80"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointPortZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:0"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ListenerBindInvalid,
        \\{"listeners":[{"bind":"not-an-address","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ListenerBindDuplicate,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}},
        \\               {"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: endpoint weights parse in both spellings" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["10.0.0.1:8080",
        \\   {"address":"10.0.0.2:8080","weight":3},
        \\   {"address":"10.0.0.3:8080"},
        \\   {"address":"10.0.0.4:8080","weight":0}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const cluster = parsed.clusters[0];
    // The two spellings resolve to one shape: a bare string and an
    // object with no weight are both weight 1, and zero — the drain
    // spelling — is carried, not rejected, while a sibling holds weight.
    try std.testing.expectEqual(@as(usize, 4), cluster.endpoints.len);
    try std.testing.expectEqualSlices(u16, &.{ 1, 3, 1, 0 }, cluster.weights.?);
    try std.testing.expectEqual(@as(u16, 8080), cluster.endpoints[1].ip.getPort());
}

test "config: unweighted endpoints leave the weights table null" {
    // The bare form and an object spelling the default out loud say the
    // same thing, so neither materializes a table: null is the loader's
    // statement that every endpoint shares alike, and the balancer's
    // license to skip weighted arithmetic for the common case.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2",
        \\   {"address":"127.0.0.1:3","weight":1}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try std.testing.expect(parsed.clusters[0].weights == null);
}

test "config: the weight ceiling itself is a legal share" {
    // The bound is inclusive — `endpoint_weight_max` parses, one past it
    // is the error — matching the at-limit convention the name-length
    // bound establishes below.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:2","weight":256}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try std.testing.expectEqual(constants.endpoint_weight_max, parsed.clusters[0].weights.?[0]);
}

test "config: endpoint weight validation has its own errors" {
    try expectParseError(error.EndpointWeightOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:2","weight":257}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // Every weight zero is a cluster drained to nowhere — rejected like
    // an empty endpoint list, not accepted as one that can never answer.
    try expectParseError(error.EndpointWeightsAllZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:2","weight":0},
        \\   {"address":"127.0.0.1:3","weight":0}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // The object form validates its address exactly like the bare one.
    try expectParseError(error.EndpointInvalid,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"origin.internal:80","weight":2}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointPortZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:0","weight":2}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // Strictness reaches inside the object form: a typo'd key is an
    // unknown field, not a silently-dropped weight.
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:2","weigth":2}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // An endpoint is a string or an object; any other token is refused
    // rather than coerced.
    try expectParseError(error.UnexpectedToken,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[42]}},
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
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointsEmpty,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.TimeoutZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":0,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
            \\{{"bind":"127.0.0.1:{d}","l4":{{"cluster":"a"}}}}
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
    // same arithmetic against a real config: past some listener count the
    // conn slots leave no room for a listener's two ops, and the config is
    // refused — the startup rejection that the removed ceiling used to
    // pre-empt.
    //
    // Where that line falls says something about the budget worth pinning.
    // `conn_slots_max` is derived against the *worst case* the prober can
    // ask for (`health_probe_concurrency_max` probes, #132), which leaves
    // 3 ops of the 57344-op fill budget spare at zero listeners. This
    // config sets no `check` block anywhere, so its prober reserves the
    // floor of one probe and the other 45 ops are slack it may spend on
    // listeners: 24 fit, and the 25th is one too many. A config that did
    // configure 16 checked endpoints would find that slack already spent
    // and be refused at two — which is the effective-versus-ceiling split
    // (§5, §8) showing up as a real difference between two configs, not
    // an accounting detail.
    const at_ceiling = std.fmt.comptimePrint(
        "\"limits\":{{\"conn_slots\":{d},\"upstream_slots\":{d}}},",
        .{ constants.conn_slots_max, constants.upstream_slots_max },
    );
    try expectParseError(error.LimitConnSlotsOverCqFill, comptime listenersJson(25, at_ceiling));
    // Twenty-four still fit, so the refusal above is the budget talking
    // and not the pools alone.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    _ = try expectParseOk(&arena_state, comptime listenersJson(24, at_ceiling));
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
    \\{"listeners":[{"bind":"127.0.0.1:8080","http":{"routes":[{"prefix":"/","cluster":"o"}],
    \\ "request_filters":[{"match":{"client":["10.0.0.0/8"]},"actions":[{"reject":403}]},
    \\ {"match":{"path_prefix":"/old"},"actions":[{"redirect":{"status":301,"scheme":"https"}}]},
    \\ {"match":{"path_prefix":"/robots.txt"},"actions":[{"respond":{"status":200,"body":"oops"}}]}]}},
    \\ {"bind":"127.0.0.1:8443","tls":{"cert":"/c.pem","key":"/k.pem"},"l4":{"cluster":"t"}}],
    \\ "clusters":{"o":{"endpoints":["127.0.0.1:9000",
    \\ {"address":"127.0.0.1:9001","weight":3}],
    \\ "pick":{"policy":"hash","key":"cookie","name":"zoxy-srv"},"max_inflight":8,
    \\ "check":{"type":"http","path":"/health","expect_status":200,"timeout_ms":250}},
    \\ "t":{"endpoints":["127.0.0.1:9100"]}},
    \\ "timeouts":{"connect_ms":5000,"idle_ms":60000,"drain_deadline_ms":10000,
    \\ "max_lifetime_ms":300000,"request_ms":30000,"health_interval_ms":2000},
    \\ "limits":{"conn_slots":64,"relay_buffers":32,"upstream_slots":32,"tls_engines":16},
    \\ "access_log":{"sink":"file","path":"/var/log/zoxy.log"},
    \\ "bodies":{"oops":{"inline":"be right back","content_type":"text/plain"}},
    \\ "error_pages":{"503":"oops"},
    \\ "admin":{"bind":"127.0.0.1:9901"}}
;
// The `file` arm here, `stdout` in `example_json` beside it: between the
// two corpus entries the mutator sees every sink spelling, including the
// `path` key only one of them may carry — both endpoint spellings
// (#174), both pick spellings (#178: the object form with its key/name
// grammar here, the bare string in the example), and every terminal
// filter action (`reject`, `redirect` #176, `respond` #159) — so each
// grammar is a starting point rather than a shape the mutator must
// blindly discover. The `inline` body arm is the one it can reach:
// `parse` refuses `file` sources outright, since the fuzzer has no
// filesystem. The `tls` block (#125) rides here for the same reason its
// paths can be nonsense: the loader is IO-free, so what the mutator gets
// to explore is the grammar and its `tls_engines` relation, which is all
// of the TLS surface this layer owns.

test "config: the fuzz seed carrying every block parses" {
    // It is a corpus entry, so it has to be a *valid* config — an
    // unparseable seed would still fuzz, just from a worse starting point,
    // and nothing else would say so.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state, fuzz_seed_json);
    try std.testing.expectEqual(@as(u32, 10000), parsed.drain_deadline_ms);
    try std.testing.expectEqual(@as(u32, 30000), parsed.request_timeout_ms);
    try std.testing.expectEqualSlices(u16, &.{ 1, 3 }, parsed.clusters[0].weights.?);
    // The #159 grammar rides the corpus through its `inline` arm — the
    // fuzzer's `parse` has no filesystem, deliberately — and every
    // terminal action is in the seed's rule table.
    try std.testing.expectEqual(@as(usize, 1), parsed.error_pages.len);
    try std.testing.expectEqual(@as(u16, 503), parsed.error_pages[0].status);
    const rules = parsed.listeners[0].request_filters;
    try std.testing.expectEqual(@as(usize, 3), rules.len);
    try std.testing.expectEqual(@as(u16, 403), rules[0].actions[0].reject);
    try std.testing.expectEqual(@as(u16, 301), rules[1].actions[0].redirect.status);
    try std.testing.expectEqual(@as(u16, 200), rules[2].actions[0].respond.status);
    // The #125 grammar and the limit that follows it: both in the seed, so
    // the mutator has the vocabulary for either branch.
    try std.testing.expectEqualStrings("/c.pem", parsed.listeners[1].tls.?.cert_path);
    try std.testing.expectEqualStrings("/k.pem", parsed.listeners[1].tls.?.key_path);
    try std.testing.expectEqual(@as(u32, 16), parsed.limits.tls_engines);
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
        // The engine pool is zero exactly when nothing terminates TLS
        // (§4/§5), which is what lets the startup loader read "no TLS
        // anywhere" off the one number and skip reserving a libcrypto heap.
        // A config that loaded with either half of that broken would price
        // memory it cannot use, or use memory it did not price.
        var tls_listeners: u32 = 0;
        for (parsed.listeners) |listener| {
            assert(listener.routes.len >= 1);
            for (listener.routes) |route| {
                assert(route.cluster_index < parsed.clusters.len);
                assert(route.prefix.len >= 1);
                assert(route.prefix[0] == '/');
            }
            if (listener.tls) |tls| {
                tls_listeners += 1;
                assert(tls.cert_path.len >= 1);
                assert(tls.key_path.len >= 1);
            }
        }
        assert((tls_listeners >= 1) == (parsed.limits.tls_engines >= 1));
        assert(parsed.limits.tls_engines <= parsed.limits.conn_slots);
    } else |_| {}
}

test "config: the access-log block resolves a sink, absent leaves it off" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}],";

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
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"";
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
            head ++ at_limit ++ "\"}}],\"clusters\":{\"" ++ at_limit ++
                "\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
                "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
        );
        try std.testing.expectEqual(@as(usize, constants.cluster_name_bytes_max), parsed.clusters[0].name.len);
    }
    try expectParseError(
        error.ClusterNameTooLong,
        head ++ long_name ++ "\"}}],\"clusters\":{\"" ++ long_name ++
            "\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
    // An empty name names nothing and would render as `"cluster":""`.
    try expectParseError(
        error.ClusterNameEmpty,
        head ++ "\"}}],\"clusters\":{\"\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
}

test "config: pick resolves both spellings, and hash names its key" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}],\"clusters\":{\"a\":{";
    const head_http = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}],\"clusters\":{\"a\":{";
    const tail = "}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const endpoints = "\"endpoints\":[\"127.0.0.1:2\"]";

    // The object form names the key; `source_ip` stays legal on an l4
    // listener, since both data paths carry the client address.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\",\"key\":\"source_ip\"}" ++ tail,
        );
        try std.testing.expectEqual(Config.Cluster.Pick.hash, parsed.clusters[0].pick);
        try std.testing.expectEqual(
            @as(std.meta.Tag(Config.Cluster.HashKey), .source_ip),
            std.meta.activeTag(parsed.clusters[0].hash_key),
        );
    }
    // The request-derived keys carry their name through (#178).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head_http ++ endpoints ++
                ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"zoxy-srv\"}" ++ tail,
        );
        try std.testing.expectEqualStrings("zoxy-srv", parsed.clusters[0].hash_key.cookie);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head_http ++ endpoints ++
                ",\"pick\":{\"policy\":\"hash\",\"key\":\"header\",\"name\":\"x-tenant\"}" ++ tail,
        );
        try std.testing.expectEqualStrings("x-tenant", parsed.clusters[0].hash_key.header);
    }
    // The keyless policies keep the bare-string spelling, and the object
    // spelling of the same policy resolves identically.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ endpoints ++ ",\"pick\":{\"policy\":\"rr\"}" ++ tail,
        );
        try std.testing.expectEqual(Config.Cluster.Pick.rr, parsed.clusters[0].pick);
    }
    // A cluster that says nothing keeps the p2c default and the default
    // key, which is inert there.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ endpoints ++ tail);
        try std.testing.expectEqual(Config.Cluster.Pick.p2c, parsed.clusters[0].pick);
    }

    // A bare `"hash"` is the misleading spelling this grammar replaced
    // (#178): which identity the cluster is sticky on is a decision, so
    // the loader demands the object form name it.
    try expectParseError(
        error.ClusterPickKeyMissing,
        head ++ endpoints ++ ",\"pick\":\"hash\"" ++ tail,
    );
    try expectParseError(
        error.ClusterPickKeyMissing,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\"}" ++ tail,
    );
    // Key settings beside another policy are a request for stickiness
    // the cluster would silently not provide — the mistake most worth
    // catching at load rather than in production.
    try expectParseError(
        error.ClusterPickKeyWithoutHash,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"rr\",\"key\":\"source_ip\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickKeyWithoutHash,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"p2c\",\"name\":\"zoxy-srv\"}" ++ tail,
    );
    // The vocabularies are closed, each with its own error so a typo
    // says which field it is in.
    try expectParseError(
        error.ClusterPickUnknown,
        head ++ endpoints ++ ",\"pick\":\"hsah\"" ++ tail,
    );
    try expectParseError(
        error.ClusterPickUnknown,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hsah\",\"key\":\"source_ip\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickKeyUnknown,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\",\"key\":\"session\"}" ++ tail,
    );
    // The object is strict like every other: unknown fields rejected.
    try expectParseError(
        error.UnknownField,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\",\"key\":\"source_ip\",\"mask\":24}" ++ tail,
    );
    // And only strings or objects can name a policy.
    try expectParseError(
        error.UnexpectedToken,
        head ++ endpoints ++ ",\"pick\":2" ++ tail,
    );
}

test "config: a request-derived pick name is required, bounded, and a token" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}],\"clusters\":{\"a\":{";
    const tail = "}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const endpoints = "\"endpoints\":[\"127.0.0.1:2\"]";

    // `source_ip` reads nothing, so a name beside it describes a config
    // that is not what it says — rejected, not ignored.
    try expectParseError(
        error.ClusterPickNameUnexpected,
        head ++ endpoints ++
            ",\"pick\":{\"policy\":\"hash\",\"key\":\"source_ip\",\"name\":\"x\"}" ++ tail,
    );
    // `header` and `cookie` read the named field, so the name is theirs
    // to state.
    try expectParseError(
        error.ClusterPickNameMissing,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickNameMissing,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\",\"key\":\"header\"}" ++ tail,
    );
    // One grammar for both names: an RFC 9110 token, which is also RFC
    // 6265's cookie-name. A space or `=` inside a cookie name would
    // corrupt every Set-Cookie a cookie cluster answers with.
    try expectParseError(
        error.ClusterPickNameInvalid,
        head ++ endpoints ++
            ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickNameInvalid,
        head ++ endpoints ++
            ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"a=b\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickNameInvalid,
        head ++ endpoints ++
            ",\"pick\":{\"policy\":\"hash\",\"key\":\"header\",\"name\":\"bad name\"}" ++ tail,
    );
    // The bound is exact: at `pick_name_bytes_max` the name loads, one
    // past it fails — the stamp's Set-Cookie scratch is sized by it.
    const at_limit = "x" ** constants.pick_name_bytes_max;
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ endpoints ++
                ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"" ++ at_limit ++ "\"}" ++ tail,
        );
        try std.testing.expectEqual(
            @as(usize, constants.pick_name_bytes_max),
            parsed.clusters[0].hash_key.cookie.len,
        );
    }
    try expectParseError(
        error.ClusterPickNameTooLong,
        head ++ endpoints ++
            ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"" ++ at_limit ++ "x\"}" ++ tail,
    );
}

test "config: a request-keyed hash cluster is unreachable from l4" {
    const tail = "}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const cookie_cluster = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]," ++
        "\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"zoxy-srv\"}";

    // An l4 listener never parses a head, so a cookie there is a promise
    // nothing would keep — rejected as a pair, the `proxy_protocol_send`
    // rule in the other direction.
    try expectParseError(
        error.ListenerL4RequestKeyedHash,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}]," ++ cookie_cluster ++ tail,
    );
    // The same cluster behind an http listener is exactly what #178 asks
    // for.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
                cookie_cluster ++ tail,
        );
        try std.testing.expectEqualStrings("zoxy-srv", parsed.clusters[0].hash_key.cookie);
    }
}

/// A #159 stub file source: two magic paths for the two read failures,
/// anything else answers a fixed page.
const test_file_source: FileSource = .{ .read = testReadBodyFile };
const test_file_body = "<h1>maintenance</h1>\n";

fn testReadBodyFile(
    context: ?*anyopaque,
    arena: std.mem.Allocator,
    path: []const u8,
    limit: u32,
) error{ FileUnreadable, FileTooLarge, OutOfMemory }![]const u8 {
    _ = context;
    assert(limit >= 1);
    if (std.mem.eql(u8, path, "/big")) return error.FileTooLarge;
    if (std.mem.eql(u8, path, "/gone")) return error.FileUnreadable;
    return arena.dupe(u8, test_file_body);
}

const bodies_head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
    "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}},";
const bodies_tail = "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

test "config: bodies render into complete pages, both variants, HEAD as prefix" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const parsed = try parseWithFiles(
        arena_state.allocator(),
        bodies_head ++
            "\"bodies\":{\"oops\":{\"inline\":\"gone\",\"content_type\":\"text/plain\"}," ++
            "\"maint\":{\"file\":\"/etc/zoxy/maint.html\",\"content_type\":\"text/html\"}}," ++
            "\"error_pages\":{\"404\":\"oops\",\"503\":\"maint\"}," ++ bodies_tail,
        test_file_source,
    );
    try std.testing.expectEqual(@as(usize, 2), parsed.error_pages.len);

    const not_found = parsed.error_pages[0];
    try std.testing.expectEqual(@as(u16, 404), not_found.status);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n" ++
            "Content-Type: text/plain\r\n" ++ page_date ++ "\r\ngone",
        not_found.keep,
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n" ++
            "Content-Type: text/plain\r\n" ++ page_date ++ "Connection: close\r\n\r\ngone",
        not_found.close,
    );
    // The head lengths are the HEAD contract: the prefix ends exactly at
    // the blank line, whatever the variant added.
    try std.testing.expectEqual(not_found.keep.len - 4, not_found.keep_head_len);
    try std.testing.expectEqual(not_found.close.len - 4, not_found.close_head_len);

    // The file arm reads through the seam, and the page carries exactly
    // what the file held.
    const maintenance = parsed.error_pages[1];
    try std.testing.expectEqual(@as(u16, 503), maintenance.status);
    try std.testing.expect(std.mem.endsWith(u8, maintenance.keep, test_file_body));

    // Every rendered variant must parse as a complete, correctly framed
    // response — the same round-trip the comptime statics prove.
    for (parsed.error_pages) |page| {
        for ([_][]const u8{ page.keep, page.close }) |bytes| {
            var storage: parser.HeaderStorage = undefined;
            const head = try parser.parseResponseHead(bytes, false, &storage, .get);
            try std.testing.expectEqual(page.status, head.status);
        }
    }
}

test "config: a body names exactly one source, and its grammar is enforced" {
    // Neither arm, and both arms: the redirect target's exactly-one rule.
    try expectParseError(
        error.BodySourceMissing,
        bodies_head ++ "\"bodies\":{\"x\":{\"content_type\":\"text/plain\"}}," ++ bodies_tail,
    );
    try expectParseError(
        error.BodySourceAmbiguous,
        bodies_head ++
            "\"bodies\":{\"x\":{\"inline\":\"a\",\"file\":\"/b\",\"content_type\":\"text/plain\"}}," ++
            bodies_tail,
    );
    // The content type lands on the wire inside a rendered head, so the
    // injection rule is the filter values' own.
    try expectParseError(
        error.BodyContentTypeInvalid,
        bodies_head ++ "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"\"}}," ++ bodies_tail,
    );
    try expectParseError(
        error.BodyContentTypeInvalid,
        bodies_head ++
            "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"text/html\\r\\nX: 1\"}}," ++
            bodies_tail,
    );
    // Names are identifiers: non-empty, bounded, unique.
    try expectParseError(
        error.BodyNameEmpty,
        bodies_head ++ "\"bodies\":{\"\":{\"inline\":\"a\",\"content_type\":\"t/p\"}}," ++ bodies_tail,
    );
    try expectParseError(
        error.BodyNameTooLong,
        bodies_head ++ "\"bodies\":{\"" ++ ("n" ** (constants.body_name_bytes_max + 1)) ++
            "\":{\"inline\":\"a\",\"content_type\":\"t/p\"}}," ++ bodies_tail,
    );
    // `parse` without a file source refuses every file arm — the fuzzer
    // and the simulator never touch a filesystem.
    try expectParseError(
        error.BodyFileUnreadable,
        bodies_head ++ "\"bodies\":{\"x\":{\"file\":\"/any\",\"content_type\":\"t/p\"}}," ++ bodies_tail,
    );
}

test "config: error pages take only known statuses naming known bodies" {
    const one_body = "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"t/p\"}},";
    // The closed static set: a status zoxy never sends as a static is a
    // config the operator misread — 200 is not an error, 301 is the
    // redirect action's, 500 is not in the vocabulary.
    for ([_][]const u8{ "200", "301", "500" }) |status| {
        var json_buffer: [1024]u8 = undefined;
        const json = std.fmt.bufPrint(
            &json_buffer,
            "{s}{s}\"error_pages\":{{\"{s}\":\"x\"}},{s}",
            .{ bodies_head, one_body, status, bodies_tail },
        ) catch unreachable;
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        try std.testing.expectError(
            error.ErrorPageStatusUnknown,
            parse(arena_state.allocator(), json),
        );
    }
    try expectParseError(
        error.ErrorPageStatusInvalid,
        bodies_head ++ one_body ++ "\"error_pages\":{\"abc\":\"x\"}," ++ bodies_tail,
    );
    try expectParseError(
        error.ErrorPageDuplicate,
        bodies_head ++ one_body ++
            "\"error_pages\":{\"404\":\"x\",\"404\":\"x\"}," ++ bodies_tail,
    );
    // A dangling name is a load error, never an empty page.
    try expectParseError(
        error.BodyUnknown,
        bodies_head ++ one_body ++ "\"error_pages\":{\"404\":\"y\"}," ++ bodies_tail,
    );
    // A map longer than the vocabulary cannot be all-valid, and which
    // way it fails is not knowable from the count — its own error, and
    // the allocation is bounded ahead of it.
    {
        var json: std.ArrayList(u8) = .empty;
        defer json.deinit(std.testing.allocator);
        try json.appendSlice(std.testing.allocator, bodies_head ++ one_body ++ "\"error_pages\":{");
        for (0..shed.static_statuses.len + 1) |index| {
            if (index > 0) try json.append(std.testing.allocator, ',');
            var entry_buffer: [16]u8 = undefined;
            const entry = std.fmt.bufPrint(
                &entry_buffer,
                "\"{d}\":\"x\"",
                .{600 + index},
            ) catch unreachable;
            try json.appendSlice(std.testing.allocator, entry);
        }
        try json.appendSlice(std.testing.allocator, "}," ++ bodies_tail);
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        try std.testing.expectError(
            error.ErrorPagesOverLimit,
            parse(arena_state.allocator(), json.items),
        );
    }
    try expectParseError(
        error.BodyNameDuplicate,
        bodies_head ++
            "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"t/p\"}," ++
            "\"x\":{\"inline\":\"b\",\"content_type\":\"t/p\"}}," ++ bodies_tail,
    );
}

test "config: logged header names are lowercased, deduped and bounded (#140)" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}},\"access_log\":{\"sink\":\"stdout\"";
    const tail = "},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // The logged key is one stable spelling whatever the config wrote,
    // so a query does not have to guess at the casing.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(
            arena_state.allocator(),
            head ++ ",\"request_headers\":[\"X-Request-ID\",\"User-Agent\"]," ++
                "\"response_headers\":[\"X-Cache\"]" ++ tail,
        );
        try std.testing.expectEqual(@as(usize, 2), parsed.access_log_request_headers.len);
        try std.testing.expectEqualStrings("x-request-id", parsed.access_log_request_headers[0]);
        try std.testing.expectEqualStrings("user-agent", parsed.access_log_request_headers[1]);
        try std.testing.expectEqualStrings("x-cache", parsed.access_log_response_headers[0]);
    }
    // Absent lists leave the line exactly as it was.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(arena_state.allocator(), head ++ tail);
        try std.testing.expectEqual(@as(usize, 0), parsed.access_log_request_headers.len);
        try std.testing.expectEqual(@as(usize, 0), parsed.access_log_response_headers.len);
    }
    // The same name twice renders one field, so the config saying it
    // twice is a mistake worth reporting — case-insensitively, since
    // the two spellings are the same header.
    try expectParseError(
        error.AccessLogHeaderDuplicate,
        head ++ ",\"request_headers\":[\"X-Request-ID\",\"x-request-id\"]" ++ tail,
    );
    // The same name on both sides is *not* a duplicate: they are two
    // different facts, and they land in different objects.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(
            arena_state.allocator(),
            head ++ ",\"request_headers\":[\"x-trace\"],\"response_headers\":[\"x-trace\"]" ++ tail,
        );
        try std.testing.expectEqualStrings("x-trace", parsed.access_log_request_headers[0]);
        try std.testing.expectEqualStrings("x-trace", parsed.access_log_response_headers[0]);
    }
    // A name that is not a token could never match a parsed header.
    try expectParseError(
        error.AccessLogHeaderNameInvalid,
        head ++ ",\"request_headers\":[\"bad name\"]" ++ tail,
    );
    try expectParseError(
        error.AccessLogHeaderNameInvalid,
        head ++ ",\"request_headers\":[\"\"]" ++ tail,
    );
    try expectParseError(
        error.AccessLogHeaderNameTooLong,
        head ++ ",\"request_headers\":[\"" ++
            ("x" ** (constants.access_log_header_name_bytes_max + 1)) ++ "\"]" ++ tail,
    );
}

test "config: the two header lists share one cap, and widen the line (#140)" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}},\"access_log\":{\"sink\":\"stdout\"";
    const tail = "},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // The cap is the total, because what it protects — the line bound
    // and the capture table — is the total. At the cap it loads; one
    // past it does not, whichever list carries the extra.
    const gpa = std.testing.allocator;
    for ([_]u8{ constants.access_log_headers_max, constants.access_log_headers_max + 1 }) |count| {
        var json: std.ArrayList(u8) = .empty;
        defer json.deinit(gpa);
        try json.appendSlice(gpa, head ++ ",\"request_headers\":[");
        for (0..count) |index| {
            if (index > 0) try json.append(gpa, ',');
            var name_buffer: [16]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buffer, "\"x-h{d}\"", .{index}) catch unreachable;
            try json.appendSlice(gpa, name);
        }
        try json.appendSlice(gpa, "]" ++ tail);
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const outcome = parse(arena_state.allocator(), json.items);
        if (count > constants.access_log_headers_max) {
            try std.testing.expectError(error.AccessLogHeadersOverLimit, outcome);
        } else {
            const parsed = try outcome;
            try std.testing.expectEqual(@as(usize, count), parsed.access_log_request_headers.len);
        }
    }

    // A staging buffer that clears the static floor but not this
    // config's own line is refused: it would drop every line carrying
    // the headers, which is a drop that means arithmetic.
    const narrow = constants.access_log_buffer_bytes_min;
    try std.testing.expect(narrow < constants.accessLogLineBytes(1));
    var buffer_json: [512]u8 = undefined;
    const with_narrow_buffer = std.fmt.bufPrint(
        &buffer_json,
        "{s},\"request_headers\":[\"x-request-id\"]}},\"limits\":{{\"access_log_buffer_bytes\":{d}}}," ++
            "\"timeouts\":{{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}}}",
        .{ head, narrow },
    ) catch unreachable;
    try expectParseError(error.LimitAccessLogBufferUnderLine, with_narrow_buffer);
}

/// The two lines every rendered #159 page now carries (#234). The date
/// is still the placeholder here because a page is rendered at *load*,
/// before any response is served — the serving path stamps the slot, and
/// what the loader owes is a slot of exactly the right shape.
const page_date = "Date: " ++ shed.date_placeholder ++ "\r\n" ++ shed.server_line;

test "config: a respond action compiles to a page, sharing one buffer (#159)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const parsed = try parse(arena_state.allocator(),
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a",
        \\ "request_filters":[
        \\   {"match":{"path_prefix":"/robots.txt"},
        \\    "actions":[{"respond":{"status":200,"body":"robots"}}]},
        \\   {"match":{"path_prefix":"/down"},
        \\    "actions":[{"respond":{"status":503,"body":"maint"}}]},
        \\   {"match":{"path_prefix":"/also-down"},
        \\    "actions":[{"respond":{"status":503,"body":"maint"}}]}]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "bodies":{"robots":{"inline":"User-agent: *\n","content_type":"text/plain"},
        \\   "maint":{"inline":"back soon","content_type":"text/plain"}},
        \\ "error_pages":{"503":"maint"},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const rules = parsed.listeners[0].request_filters;
    try std.testing.expectEqual(@as(usize, 3), rules.len);

    // The 200 page: the action's own status, the body's content type,
    // and the complete response rendered once.
    const robots = rules[0].actions[0].respond;
    try std.testing.expectEqual(@as(u16, 200), robots.status);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 14\r\n" ++
            "Content-Type: text/plain\r\n" ++ page_date ++ "\r\nUser-agent: *\n",
        robots.keep,
    );

    // One body, one buffer: two actions and an error page naming the
    // same (body, status) all point at the *same* rendered page — the
    // load-time cache, not three copies of "back soon".
    const first_maint = rules[1].actions[0].respond;
    const second_maint = rules[2].actions[0].respond;
    try std.testing.expectEqual(first_maint, second_maint);
    try std.testing.expectEqual(first_maint, parsed.error_pages[0]);
    // A different status off the same body is a different page, and
    // shares nothing but the bytes it embeds.
    try std.testing.expect(robots != first_maint);
}

test "config: the respond action's vocabulary is closed, and request-side only" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
        "\"request_filters\":[{\"match\":{},\"actions\":[";
    const mid = "]}]}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"t/p\"}},";
    const tail = "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // 200 and the error statuses load; a status this proxy has no
    // reason phrase for does not.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(
            arena_state.allocator(),
            head ++ "{\"respond\":{\"status\":404,\"body\":\"x\"}}" ++ mid ++ tail,
        );
        try std.testing.expectEqual(
            @as(u16, 404),
            parsed.listeners[0].request_filters[0].actions[0].respond.status,
        );
    }
    try expectParseError(
        error.FilterRespondStatus,
        head ++ "{\"respond\":{\"status\":418,\"body\":\"x\"}}" ++ mid ++ tail,
    );
    // A dangling body name fails the same way an error page's does.
    try expectParseError(
        error.BodyUnknown,
        head ++ "{\"respond\":{\"status\":200,\"body\":\"nope\"}}" ++ mid ++ tail,
    );
    // Still exactly one action kind, with the new arm counted.
    try expectParseError(
        error.FilterActionKind,
        head ++ "{\"respond\":{\"body\":\"x\"},\"reject\":403}" ++ mid ++ tail,
    );
    // And it is a request-side answer: a response rule runs when the
    // origin has already answered, so replacing that answer is not an
    // edit this table has — and since #305 it is not a field there
    // either, so the parser says so rather than a rule.
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
            "\"response_filters\":[{\"actions\":[{\"respond\":{\"body\":\"x\"}}]}]}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"t/p\"}}," ++ tail,
    );
}

test "config: the body cap holds on both arms, exactly" {
    // The file arm: the reader reports over-limit, the loader speaks the
    // same verdict an oversized inline earns.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(error.BodyOverLimit, parseWithFiles(
        arena_state.allocator(),
        bodies_head ++ "\"bodies\":{\"x\":{\"file\":\"/big\",\"content_type\":\"t/p\"}}," ++ bodies_tail,
        test_file_source,
    ));
    // The inline arm, at the boundary: the cap itself loads, one past
    // fails. Built at runtime — a comptime megabyte literal costs every
    // build what this test costs one run.
    const gpa = std.testing.allocator;
    const at_limit = try gpa.alloc(u8, constants.body_bytes_max);
    defer gpa.free(at_limit);
    @memset(at_limit, 'x');
    for ([_]usize{ constants.body_bytes_max, constants.body_bytes_max + 1 }) |body_len| {
        var json: std.ArrayList(u8) = .empty;
        defer json.deinit(gpa);
        try json.appendSlice(gpa, bodies_head ++ "\"bodies\":{\"x\":{\"inline\":\"");
        try json.appendSlice(gpa, at_limit);
        if (body_len > constants.body_bytes_max) try json.append(gpa, 'x');
        try json.appendSlice(gpa, "\",\"content_type\":\"t/p\"}},\"error_pages\":{\"404\":\"x\"}," ++ bodies_tail);
        var body_arena = std.heap.ArenaAllocator.init(gpa);
        defer body_arena.deinit();
        const outcome = parse(body_arena.allocator(), json.items);
        if (body_len > constants.body_bytes_max) {
            try std.testing.expectError(error.BodyOverLimit, outcome);
        } else {
            const parsed = try outcome;
            try std.testing.expectEqual(
                constants.body_bytes_max,
                @as(u32, @intCast(parsed.error_pages[0].keep.len - parsed.error_pages[0].keep_head_len)),
            );
        }
    }
}

test "config: the body cap is two-valued, and 0 is how uncapped is spelled (#305)" {
    // `null` used to mean 1 MiB and `0` no cap — three states for a
    // two-state idea, and the odd one out in its own config:
    // `drain_deadline_ms`, `max_lifetime_ms` and `request_ms` all spell
    // "no cap" as `0` with nothing else to explain.
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"";
    const tail = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent is still the default it always was, so a config that never
    // named the key keeps its cap.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expectEqual(
            constants.request_body_bytes_default,
            parsed.listeners[0].max_body_bytes,
        );
    }
    // And `0` is uncapped, unchanged.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ ",\"max_body_bytes\":0" ++ tail);
        try std.testing.expectEqual(@as(u64, 0), parsed.listeners[0].max_body_bytes);
    }
    // The ceiling holds at its edge rather than near it.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const at_limit = std.fmt.comptimePrint(
            ",\"max_body_bytes\":{d}",
            .{constants.request_body_bytes_max},
        );
        const parsed = try expectParseOk(&arena_state, head ++ at_limit ++ tail);
        try std.testing.expectEqual(
            constants.request_body_bytes_max,
            parsed.listeners[0].max_body_bytes,
        );
    }
    try expectParseError(
        error.ListenerMaxBodyBytesOutOfRange,
        head ++ std.fmt.comptimePrint(
            ",\"max_body_bytes\":{d}",
            .{constants.request_body_bytes_max + 1},
        ) ++ tail,
    );
    // An l4 relay measures no request, so the key does not exist there —
    // the strict parser's refusal, not a rule's (#305).
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
            "\"max_body_bytes\":500}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
}

test "config: max_inflight resolves, defaults to uncapped, rejects the useless" {
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
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

test "config: an endpoint may be a Unix socket path (#303)" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[";
    const tail = "]}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Both spellings in one cluster, which is the point of a prefix on
    // the existing string rather than a second key (#305): a migration
    // moves one endpoint at a time.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"127.0.0.1:9000\",\"unix:/run/app.sock\"," ++
                "{\"address\":\"unix:/run/app2.sock\",\"weight\":3}" ++ tail,
        );
        const endpoints = parsed.clusters[0].endpoints;
        try std.testing.expectEqual(@as(usize, 3), endpoints.len);
        try std.testing.expectEqual(@as(u16, 9000), endpoints[0].ip.getPort());
        try std.testing.expectEqualStrings("/run/app.sock", endpoints[1].unix);
        // The `unix:` prefix is grammar, not part of the path: what
        // reaches the kernel is what the operator would `ls`.
        try std.testing.expectEqualStrings("/run/app2.sock", endpoints[2].unix);
        // The #174 object form is unaffected — the grammar grew at one
        // parse site and nothing that parsed before changed shape.
        try std.testing.expectEqualSlices(u16, &.{ 1, 1, 3 }, parsed.clusters[0].weights.?);
        // And the rendered spelling round-trips to what was written,
        // which is what the access log and the metrics label print.
        var scratch: [64]u8 = undefined;
        var writer = std.Io.Writer.fixed(&scratch);
        try writer.print("{f}", .{endpoints[1]});
        try std.testing.expectEqualStrings("unix:/run/app.sock", writer.buffered());
    }

    // A relative path resolves against a working directory the operator
    // did not name and a service manager may change — so it names a
    // socket nobody can point at. Refused at load (§5), not at the dial.
    try expectParseError(
        error.EndpointUnixPathRelative,
        head ++ "\"unix:run/app.sock\"" ++ tail,
    );
    // The empty path is the abstract namespace, which is out of scope
    // (#303) and would otherwise be a silent second meaning for `unix:`.
    try expectParseError(error.EndpointUnixPathInvalid, head ++ "\"unix:\"" ++ tail);
    // Past what a `sockaddr_un` carries. Refused rather than truncated:
    // a shortened path names a *different* socket, and the kernel would
    // have no way to say so.
    {
        const too_long = "/" ++ ("p" ** constants.unix_socket_path_bytes_max);
        try expectParseError(
            error.EndpointUnixPathInvalid,
            head ++ "\"unix:" ++ too_long ++ "\"" ++ tail,
        );
        // One byte shorter is the longest path that fits, and it parses
        // — the bound is a real edge, not a round number near one.
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"unix:" ++ too_long[0 .. too_long.len - 1] ++ "\"" ++ tail,
        );
        try std.testing.expectEqual(
            @as(usize, constants.unix_socket_path_bytes_max),
            parsed.clusters[0].endpoints[0].unix.len,
        );
    }
    // A zero-port rule cannot apply to a socket path, and must not be
    // reached through one: the check is on the `ip` arm only.
    try expectParseError(error.EndpointPortZero, head ++ "\"127.0.0.1:0\"" ++ tail);

    // The bytes an address may not carry. POSIX permits them in a path;
    // the access log and the metrics exposition do not — one of these
    // reaching a renderer invalidates the whole line and the whole
    // scrape, not one field, so they are refused where every other
    // §5 bound is.
    inline for (.{ "\\\"", "\\\\", "\\u0001", "\\u007f", " " }) |hostile| {
        try expectParseError(
            error.EndpointUnixPathInvalid,
            head ++ "\"unix:/run/a" ++ hostile ++ "b.sock\"" ++ tail,
        );
    }
}

test "config: a listener may bind a socket path (#303)" {
    const tail = ",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":";

    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"unix:/run/zoxy.sock\"" ++ tail,
        );
        try std.testing.expectEqualStrings("/run/zoxy.sock", parsed.listeners[0].bind_address.unix);
        // Absent leaves whatever the umask gives, which is what every
        // other tool does and what an operator's directory permissions
        // are already expressed against.
        try std.testing.expect(parsed.listeners[0].bind_mode == null);
    }
    // The same path validation as an endpoint, under this field's own
    // error names — an operator should not have to work out which of the
    // two fields the loader meant.
    try expectParseError(
        error.ListenerBindUnixPathRelative,
        head ++ "\"unix:run/zoxy.sock\"" ++ tail,
    );
    try expectParseError(error.ListenerBindUnixPathInvalid, head ++ "\"unix:\"" ++ tail);
    try expectParseError(
        error.ListenerBindUnixPathInvalid,
        head ++ "\"unix:/run/a\\\"b.sock\"" ++ tail,
    );
    // Two listeners on one path are the same duplicate an IP:port pair
    // is — and the check had to stop being a single integer key to see
    // it, since a path does not fit one.
    try expectParseError(
        error.ListenerBindDuplicate,
        "{\"listeners\":[{\"bind\":\"unix:/run/a.sock\",\"http\":{\"cluster\":\"a\"}}," ++
            "{\"bind\":\"unix:/run/a.sock\",\"http\":{\"cluster\":\"a\"}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
}

test "config: a socket file's mode is octal, and only a socket has one (#303)" {
    const tail = ",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const unix_head = "{\"listeners\":[{\"bind\":\"unix:/run/zoxy.sock\"";

    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            unix_head ++ ",\"mode\":\"0660\"" ++ tail,
        );
        try std.testing.expectEqual(@as(u16, 0o660), parsed.listeners[0].bind_mode.?.bits);
    }
    // A string, not a number: `0660` is not valid JSON and `660` is
    // decimal, and the two readings of one intent differ by a factor of
    // eight — in the direction that widens the mode.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, unix_head ++ ",\"mode\":\"660\"" ++ tail);
        try std.testing.expectEqual(@as(u16, 0o660), parsed.listeners[0].bind_mode.?.bits);
    }
    // An IP bind creates no file, so a mode on one describes nothing.
    try expectParseError(
        error.ListenerModeWithoutUnixBind,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"mode\":\"0660\"" ++ tail,
    );
    inline for (.{ "0680", "9", "", "00660", "abc" }) |bad| {
        try expectParseError(
            error.ListenerModeInvalid,
            unix_head ++ ",\"mode\":\"" ++ bad ++ "\"" ++ tail,
        );
    }
    // setuid, setgid and sticky mean nothing on a socket and everything
    // on the file it would be confused with.
    try expectParseError(
        error.ListenerModeInvalid,
        unix_head ++ ",\"mode\":\"4660\"" ++ tail,
    );
}

test "config: a unix listener refuses what needs a client address (#303)" {
    // A request arriving on a socket file has no client IP, and there is
    // no honest sentinel: a fabricated `0.0.0.0` would make each of
    // these quietly wrong rather than absent. Refused at load (§5).
    const tail = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"unix:/run/zoxy.sock\",\"http\":{\"cluster\":\"a\"";

    try expectParseError(
        error.ListenerUnixBindForwarded,
        head ++ ",\"forwarded\":{\"mode\":\"replace\"}" ++ tail,
    );
    try expectParseError(
        error.ListenerUnixBindClientMatch,
        head ++ ",\"request_filters\":[{\"match\":{\"client\":[\"10.0.0.0/8\"]}," ++
            "\"actions\":[{\"reject\":403}]}]" ++ tail,
    );
    try expectParseError(
        error.ListenerUnixBindSourceIpHash,
        "{\"listeners\":[{\"bind\":\"unix:/run/zoxy.sock\",\"http\":{\"cluster\":\"a\"}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]," ++
            "\"pick\":{\"policy\":\"hash\",\"key\":\"source_ip\"}}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
    // A hash on something the request carries is unaffected: the key is
    // in the request, not in the connection.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        _ = try expectParseOk(
            &arena_state,
            "{\"listeners\":[{\"bind\":\"unix:/run/zoxy.sock\",\"http\":{\"cluster\":\"a\"}}]," ++
                "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]," ++
                "\"pick\":{\"policy\":\"hash\",\"key\":\"header\",\"name\":\"x-tenant\"}}}," ++
                "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
        );
    }
    // An SNI table is a second set of reachable clusters (#298), and
    // the listener's `routes` does not summarise it: with a name table
    // `routes` holds one provisional entry, and `finishSniPeek` replaces
    // the exchange's cluster with the matched one before any dial. So a
    // rule that walked only `routes` would hold the *first* name to it
    // and wave every other one through — into an unwrap of the client
    // address that is not there.
    inline for (.{
        "{\"policy\":\"hash\",\"key\":\"source_ip\"}",
        "\"p2c\"",
    }, .{
        error.ListenerUnixBindSourceIpHash,
        error.ListenerUnixBindClusterSend,
    }) |pick, expected| {
        const send = if (expected == error.ListenerUnixBindClusterSend)
            ",\"proxy_protocol\":{\"send\":\"v2\"}"
        else
            "";
        try expectParseError(
            expected,
            "{\"listeners\":[{\"bind\":\"unix:/run/zoxy.sock\",\"l4\":{\"routes\":[" ++
                "{\"sni\":\"a.example\",\"cluster\":\"plain\"}," ++
                "{\"sni\":\"b.example\",\"cluster\":\"second\"}]}}]," ++
                "\"clusters\":{\"plain\":{\"endpoints\":[\"127.0.0.1:2\"]}," ++
                "\"second\":{\"endpoints\":[\"127.0.0.1:3\"],\"pick\":" ++ pick ++
                send ++ "}}," ++
                "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
        );
    }
    // And an IP listener still takes all three, which is what says the
    // rule is about the bind and not about the feature.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        _ = try expectParseOk(
            &arena_state,
            "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
                "\"forwarded\":{\"mode\":\"replace\"}" ++ tail,
        );
    }
}

test "config: proxy_status is off unless asked for, and is http-only" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"";
    const tail = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent means silent (#300): a config written before the feature
    // must not start naming this proxy's limits on the wire.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expect(!parsed.listeners[0].proxy_status);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ ",\"proxy_status\":true" ++ tail);
        try std.testing.expect(parsed.listeners[0].proxy_status);
    }
    // An l4 relay renders no HTTP response to put the field in, so the
    // key does not exist there — the strict parser is the rule (#305).
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
            "\"proxy_status\":true}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
}

test "config: the forwarded block resolves a mode, and is http-only" {
    // The head opens the `http` body, so the fields each case appends
    // land inside it — which is the whole shape (#305): `forwarded` is
    // reachable from here and from nowhere else.
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"";
    const tail = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent: the header is untouched, which is what every config that
    // predates this feature must keep doing.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expect(parsed.listeners[0].forwarded == null);
    }
    // Both modes resolve; neither is a default.
    inline for (.{ "replace", "append" }) |mode| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ ",\"forwarded\":{\"mode\":\"" ++ mode ++ "\"}" ++ tail,
        );
        try std.testing.expectEqual(
            std.meta.stringToEnum(Config.Listener.Forwarded, mode).?,
            parsed.listeners[0].forwarded.?,
        );
    }

    // An l4 listener has no header to carry an address, so asking for one
    // describes a proxy that is not running. There is no longer a rule
    // saying so — the `l4` body has no such key, so the strict parser
    // refuses it (#305), which is the same verdict one mechanism earlier.
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
            "\"forwarded\":{\"mode\":\"replace\"}}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
    // The mode vocabulary is closed and `mode` is required: there is no
    // safe default to fall back to, which is the whole point.
    try expectParseError(
        error.ListenerForwardedModeUnknown,
        head ++ ",\"forwarded\":{\"mode\":\"trust\"}" ++ tail,
    );
    try expectParseError(
        error.MissingField,
        head ++ ",\"forwarded\":{}" ++ tail,
    );
}

test "config: the proxy_protocol block resolves a mode, and is l4-only" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"";
    const tail = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent: first bytes are payload — every config predating this.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expect(parsed.listeners[0].proxy_protocol == null);
    }
    // The one mode resolves. This used to run twice — once on the
    // defaulted protocol and once on a stated `l4` — and there is no
    // longer a difference to cover: the body's key *is* the statement,
    // so there is no defaulted spelling for it to disagree with (#305).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ ",\"proxy_protocol\":{\"mode\":\"require\"}" ++ tail,
        );
        try std.testing.expectEqual(
            Config.Listener.ProxyProtocol.require,
            parsed.listeners[0].proxy_protocol.?,
        );
    }
    // The L7 path has no receive phase yet, so a block there would state
    // a trust boundary nothing enforces. The `http` body has no such key
    // (#305), so it is refused rather than ignored — the same verdict the
    // rule used to give, one mechanism earlier.
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
            "\"proxy_protocol\":{\"mode\":\"require\"}}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
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

test "config: the tls block resolves paths, and only shape-checks them" {
    // The head closes the protocol body, because `tls` is the listener's
    // and not either body's (#305) — so every case below appends at the
    // level the key actually lives on.
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}";
    const tail = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent: a plaintext socket, every config predating this.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expect(parsed.listeners[0].tls == null);
    }
    // Present on either protocol: termination is orthogonal to what the
    // terminated stream then speaks, which is why the handshake is a
    // phase ahead of the protocol rather than part of one.
    inline for (.{
        "\"l4\":{\"cluster\":\"a\"}",
        "\"http\":{\"cluster\":\"a\"}",
    }) |body| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"," ++ body ++
                ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"}" ++ tail,
        );
        const tls = parsed.listeners[0].tls.?;
        try std.testing.expectEqualStrings("/c.pem", tls.cert_path);
        try std.testing.expectEqualStrings("/k.pem", tls.key_path);
    }
    // Paths that do not exist still load: this loader does no IO (§1), and
    // `main` is where a missing file becomes an error that can name it.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        _ = try expectParseOk(
            &arena_state,
            head ++ ",\"tls\":{\"cert\":\"/nope\",\"key\":\"/nope\"}" ++ tail,
        );
    }
    // An empty path is checkable here, and worth checking: it would reach
    // `openat` as a request to open the current directory, failing
    // somewhere far less obvious than the config that asked for it.
    try expectParseError(
        error.ListenerTlsCertPathEmpty,
        head ++ ",\"tls\":{\"cert\":\"\",\"key\":\"/k.pem\"}" ++ tail,
    );
    try expectParseError(
        error.ListenerTlsKeyPathEmpty,
        head ++ ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"\"}" ++ tail,
    );
    // Both paths are required: a certificate with no key is not a
    // half-configured listener, it is one that cannot answer a handshake.
    try expectParseError(
        error.MissingField,
        head ++ ",\"tls\":{\"cert\":\"/c.pem\"}" ++ tail,
    );
    try expectParseError(
        error.MissingField,
        head ++ ",\"tls\":{\"key\":\"/k.pem\"}" ++ tail,
    );
}

test "config: a terminating listener cannot reach a PROXY-sending cluster" {
    // A TLS connection's client→upstream window is the engine's plaintext
    // buffer, not the relay buffer the send-side header stages into — so
    // the origin would receive whatever that window happened to hold
    // rather than the header. Refused at load rather than sent as garbage.
    // Reachability, not exclusivity, exactly like the http case beside it:
    // the same cluster stays valid for every plaintext listener.
    const tail = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]," ++
        "\"proxy_protocol\":{\"send\":\"v2\"}}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    try expectParseError(
        error.ClusterProxyProtocolOnTlsListener,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}," ++
            "\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"}}]," ++ tail,
    );
    // Without the tls block the same cluster is fine.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}]," ++ tail,
        );
        try std.testing.expect(parsed.clusters[0].proxy_protocol_send != null);
    }
}

test "config: tls_engines follows the tls listeners, and refuses a mismatch" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}";
    const tls_block = ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"}";
    const tail = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}";
    const close = "}";

    // No TLS listener: the pool is zero, so a plaintext deployment
    // reserves nothing for a feature it does not use.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail ++ close);
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.tls_engines);
    }
    // A TLS listener with no stated limit: conn slots, capped at the
    // engine ceiling — every connection could be mid-handshake at once.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tls_block ++ tail ++ close);
        try std.testing.expectEqual(
            @min(constants.tls_engines_default, parsed.limits.conn_slots),
            parsed.limits.tls_engines,
        );
        try std.testing.expect(parsed.limits.tls_engines >= 1);
    }
    // The default is capped by conn slots, not just by the ceiling: a
    // deployment that shrank its slots must not out-provision them.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tls_block ++ tail ++ ",\"limits\":{\"conn_slots\":4}" ++ close,
        );
        try std.testing.expectEqual(@as(u32, 4), parsed.limits.tls_engines);
    }
    // Stated explicitly, it is honored — this is the knob a TLS
    // deployment trades memory against the shed wall with.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tls_block ++ tail ++ ",\"limits\":{\"tls_engines\":16}" ++ close,
        );
        try std.testing.expectEqual(@as(u32, 16), parsed.limits.tls_engines);
    }
    // Engines nobody can use: paid for in RSS, drawn from never. Said so
    // rather than silently zeroed, because the operator asked for a thing
    // and the answer is that this config cannot use it.
    try expectParseError(
        error.LimitTlsEnginesWithoutTlsListener,
        head ++ tail ++ ",\"limits\":{\"tls_engines\":16}" ++ close,
    );
    // A TLS listener with no engines would shed every handshake — a
    // listener that accepts and then refuses everything.
    try expectParseError(
        error.LimitTlsEnginesOutOfRange,
        head ++ tls_block ++ tail ++ ",\"limits\":{\"tls_engines\":0}" ++ close,
    );
    // Past the ceiling: an engine is ~91 KiB, so this bound is what
    // stands between a typo and a gigabyte.
    try expectParseError(
        error.LimitTlsEnginesOutOfRange,
        head ++ tls_block ++ tail ++ ",\"limits\":{\"tls_engines\":100000}" ++ close,
    );
    // More engines than connections that could hold one.
    try expectParseError(
        error.LimitTlsEnginesOverConnSlots,
        head ++ tls_block ++ tail ++ ",\"limits\":{\"conn_slots\":4,\"tls_engines\":8}" ++ close,
    );
}

test "config: the cluster proxy_protocol block resolves a version, l4-reachable only" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}";
    const middle = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]";
    const tail = "}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent: no header is sent — every config predating this.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ middle ++ tail);
        try std.testing.expect(parsed.clusters[0].proxy_protocol_send == null);
    }
    // Both versions resolve on an l4-reachable cluster; neither is a default.
    inline for (.{ "v1", "v2" }) |version| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ middle ++ ",\"proxy_protocol\":{\"send\":\"" ++ version ++ "\"}" ++ tail,
        );
        try std.testing.expectEqual(
            std.meta.stringToEnum(Config.Cluster.ProxyProtocolSend, version).?,
            parsed.clusters[0].proxy_protocol_send.?,
        );
    }
    // An http listener routing to a sending cluster is rejected: a pooled
    // L7 upstream is shared across clients, so the per-connection header
    // would name one client and serve many.
    try expectParseError(
        error.ClusterProxyProtocolOnHttpListener,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}" ++ middle ++
            ",\"proxy_protocol\":{\"send\":\"v2\"}" ++ tail,
    );
    // The same cluster reached by an http listener *beside* the l4 one is
    // just as rejected — reachability poisons, not exclusivity.
    try expectParseError(
        error.ClusterProxyProtocolOnHttpListener,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}," ++
            "{\"bind\":\"127.0.0.1:3\",\"http\":{\"cluster\":\"a\"}" ++ middle ++
            ",\"proxy_protocol\":{\"send\":\"v2\"}" ++ tail,
    );
    // The version vocabulary is closed and `send` is required.
    try expectParseError(
        error.ClusterProxyProtocolSendUnknown,
        head ++ middle ++ ",\"proxy_protocol\":{\"send\":\"v3\"}" ++ tail,
    );
    try expectParseError(
        error.MissingField,
        head ++ middle ++ ",\"proxy_protocol\":{}" ++ tail,
    );
}

test "config: a filter may not name the header zoxy manages" {
    // A filter edit can only write a *constant*, so naming this header
    // encodes one fixed address for every client — it looks like client
    // forwarding and is the opposite of it. Reserved unconditionally, not
    // only on listeners that set it, so one mechanism owns the header.
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"request_filters\":[";
    const tail = "]}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
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
        try std.testing.expectEqual(@as(usize, 1), parsed.listeners[0].request_filters.len);
    }
}

test "config: retries resolves, defaults to none, rejects past the ceiling" {
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2","127.0.0.1:3"],"retries":2},
            \\   "b":{"endpoints":["127.0.0.1:4"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(@as(u16, 2), parsed.clusters[0].retries);
        // Absent is no retry, which is what every config written before
        // the key existed asked for and must keep getting (#181).
        try std.testing.expectEqual(@as(u16, 0), parsed.clusters[1].retries);
    }
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"retries":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Zero is the default rather than a typo, so it loads; past the
    // ceiling is refused rather than clamped, because a number the proxy
    // will not honor should be heard about at load.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "0" ++ tail);
        try std.testing.expectEqual(@as(u16, 0), parsed.clusters[0].retries);
    }
    {
        var buffer: [512]u8 = undefined;
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const json = try std.fmt.bufPrint(
            &buffer,
            "{s}{d}{s}",
            .{ head, constants.cluster_retries_max, tail },
        );
        const parsed = try expectParseOk(&arena_state, json);
        try std.testing.expectEqual(constants.cluster_retries_max, parsed.clusters[0].retries);
    }
    {
        var buffer: [512]u8 = undefined;
        const json = try std.fmt.bufPrint(
            &buffer,
            "{s}{d}{s}",
            .{ head, constants.cluster_retries_max + 1, tail },
        );
        try expectParseError(error.ClusterRetriesOutOfRange, json);
    }
}

test "config: the upgrade allowlist is closed, http-only, and never empty" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a",
        \\ "upgrades":
    ;
    const tail =
        \\}},{"bind":"127.0.0.1:2","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "limits":{"tunnels":16},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "{\"websocket\":true}" ++ tail);
        try std.testing.expect(parsed.listeners[0].upgrades.websocket);
        try std.testing.expect(parsed.listeners[0].upgrades.any());
        // Per listener, and the l4 one beside it allows nothing — which is
        // what every config predating the key keeps getting.
        try std.testing.expect(!parsed.listeners[1].upgrades.any());
        try std.testing.expectEqual(@as(u32, 16), parsed.limits.tunnels);
    }
    // A protocol this proxy cannot reason about is refused by name,
    // never ignored: `h2c` would tunnel HTTP/2 to an origin it cannot
    // parse, and a config that asked for it and got silence would
    // believe it had — with no rule left after 101 to catch what came
    // through. As a field rather than a token, that refusal is the
    // strict parser's and the schema's, not a rule of the loader's
    // (#305) — and a duplicate stops being expressible at all, where
    // the list form accepted `["websocket", "websocket"]` unchecked.
    try expectParseError(error.UnknownField, head ++ "{\"h2c\":true}" ++ tail);
    try expectParseError(
        error.UnknownField,
        head ++ "{\"websocket\":true,\"h2c\":true}" ++ tail,
    );
    // And "allow none" needs no rejection any more. An empty *list* was
    // a meaningless spelling of a set; a set of flags all false is the
    // ordinary way to write "not this one", means what omitting the
    // block means, and reserves nothing — so the error this used to
    // raise is gone rather than moved.
    // Without a `tunnels` limit, because an all-false block reserves
    // nothing — asking for a pool beside one is still the §5 mismatch
    // it always was, and the case below pins that too.
    const quiet_tail =
        \\}},{"bind":"127.0.0.1:2","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    inline for (.{ "{}", "{\"websocket\":false}" }) |spelling| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ spelling ++ quiet_tail);
        try std.testing.expect(!parsed.listeners[0].upgrades.any());
        // Reserves nothing, which is what says it is absence rather than
        // a listener asking for a pool it can never use (§5).
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.tunnels);
        // And it is exactly absence: a pool beside it is the same
        // mismatch omitting the block would earn.
        try expectParseError(
            error.LimitTunnelsWithoutUpgrades,
            head ++ spelling ++ tail,
        );
    }
}

test "config: upgrades are refused on an l4 listener" {
    // A byte relay parses no handshake to recognise, so there is nothing
    // here for it to allow. The `l4` body has no such key (#305), so the
    // refusal is the strict parser's rather than a rule's — a block that
    // quietly did nothing was never the alternative.
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a","upgrades":{"websocket":true}}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "limits":{"tunnels":4},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: the tunnel pool has no derived default, and binds to the allowlist" {
    const with_upgrades =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a",
        \\ "upgrades":{"websocket":true}}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}
    ;
    // Every other optional pool derives a fallback that can only be too
    // generous; a count of long-lived sessions has no such number behind
    // it, so the omission is refused where the operator is looking rather
    // than surfacing later as tunnels shed under load.
    try expectParseError(error.LimitTunnelsRequired, with_upgrades ++ "}");
    // A pool of zero beside a listener that allows upgrades would refuse
    // every one of them — the same contradiction as a zero head ring on
    // an http deployment.
    try expectParseError(
        error.LimitTunnelsOutOfRange,
        with_upgrades ++ ",\"limits\":{\"tunnels\":0}}",
    );
    // And a pool nothing can draw on is the mirror image: asked for, and
    // unusable.
    try expectParseError(error.LimitTunnelsWithoutUpgrades,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "limits":{"tunnels":8},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // Zero exactly when no listener allows an upgrade, so one number says
    // both how many tunnels there may be and whether the feature is on.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.tunnels);
    }
}

test "config: the tunnel pool may not exceed the connections that hold one" {
    // Not arithmetic hygiene: this bound is what leaves the fd and ring
    // budgets untouched by the feature (§5). A tunnel is an accepted
    // client connection, so `fdsRequired`'s two-sockets-per-connection
    // already covers its pair — but only while every tunnel has a
    // connection to be.
    var buffer: [512]u8 = undefined;
    const json = try std.fmt.bufPrint(
        &buffer,
        "{s}{d}{s}",
        .{
            \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a",
            \\ "upgrades":{"websocket":true}}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
            \\ "limits":{"conn_slots":8,"tunnels":
            ,
            @as(u32, 9),
            \\},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
            ,
        },
    );
    try expectParseError(error.LimitTunnelsOverConnSlots, json);
}

test "config: tunnel_ms defaults to an hour and has no off switch" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a",
        \\ "upgrades":{"websocket":true}}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "limits":{"tunnels":4},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1
    ;
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "}}");
        try std.testing.expectEqual(
            constants.tunnel_ms_default,
            parsed.tunnel_timeout_ms,
        );
    }
    // Zero is legal for `max_lifetime_ms` and `request_ms` and means "no
    // cap". It cannot mean that here: a tunnel pins a dedicated pool slot
    // for its whole life, and an unbounded hold on a bounded pool is the
    // one thing that model cannot absorb.
    try expectParseError(error.TimeoutTunnelOutOfRange, head ++ ",\"tunnel_ms\":0}}");
    // The floor is a floor, not a nonzero check: a sub-second lifetime
    // would reap every session on arrival, which reads as a typo.
    try expectParseError(error.TimeoutTunnelOutOfRange, head ++ ",\"tunnel_ms\":999}}");
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ ",\"tunnel_ms\":1000}}");
        try std.testing.expectEqual(constants.tunnel_ms_min, parsed.tunnel_timeout_ms);
    }
}

test "config: the head budget is derived from its neighbours, never fixed" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "timeouts":{"drain_deadline_ms":1,
    ;
    const tail = "}}";
    // The ordinary shape: the default lands as itself, an order of
    // magnitude under the idle window it tightens (#235).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"connect_ms\":5000,\"idle_ms\":60000" ++ tail,
        );
        try std.testing.expectEqual(constants.head_ms_default, parsed.head_timeout_ms);
    }
    // A config whose whole idle window is under the default keeps it: the
    // head budget tightens the idle one, so it can never exceed it. This
    // is most hand-written test configs, and every one of them predates
    // the field.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"connect_ms\":1,\"idle_ms\":2" ++ tail,
        );
        try std.testing.expectEqual(@as(u32, 2), parsed.head_timeout_ms);
    }
    // The shape a flat default would have broken *silently*: a dial budget
    // above the default. The head budget would have sat below it, and the
    // lazy timer cannot lengthen at the re-base — so the dial would have
    // been cut to ten seconds by a field the operator never set.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"connect_ms\":20000,\"idle_ms\":60000" ++ tail,
        );
        try std.testing.expect(parsed.head_timeout_ms > 20000);
    }
}

test "config: head_ms must sit strictly above the dial and at or below the idle" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "timeouts":{"drain_deadline_ms":1,"connect_ms":5000,"idle_ms":60000,"head_ms":
    ;
    const tail = "}}";
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "9000" ++ tail);
        try std.testing.expectEqual(@as(u32, 9000), parsed.head_timeout_ms);
    }
    // Both inversions are rejected rather than clamped, on the same
    // grounds as `connect_ms < idle_ms`: the single lazy timer only ever
    // moves earlier, so either one would leave the wider value quietly in
    // force and the config would behave differently than it reads.
    try expectParseError(error.TimeoutOrderInvalid, head ++ "5000" ++ tail);
    try expectParseError(error.TimeoutOrderInvalid, head ++ "4000" ++ tail);
    try expectParseError(error.TimeoutOrderInvalid, head ++ "60001" ++ tail);
    try expectParseError(error.TimeoutOverLimit, head ++ "0" ++ tail);
}
