//! `Options` → arena-owned immutable `Config` (DESIGN.md §5): resolved
//! once at startup, never reloaded (§1 non-goal). `resolve` holds a
//! build's options to every rule zoxy keeps — every limit gets its own
//! error, every name another block uses resolves, every address is a
//! static socket address, so the no-DNS non-goal holds structurally — and
//! compiles them into the runtime shape the server runs. It reads no file
//! and looks up no name: the stock binary's JSON front-end, a module of
//! its own under `src/json/`, reads both before the options exist. The
//! returned `Config` references both the arena and the options' own
//! memory; the caller keeps both for the process lifetime.

const std = @import("std");
const trust = @import("tls/trust.zig");

const constants = @import("constants.zig");
const extension_module = @import("extension.zig");
const router = @import("http/router.zig");
const sni_router = @import("net/sni_router.zig");
const filter = @import("http/filter.zig");
const parser = @import("http/parser.zig");
const render = @import("http/render.zig");
const shed = @import("shed.zig");
const io_module = @import("io/io.zig");
const Options = @import("Options.zig");
const defaults = @import("defaults.zig");
/// The ALPN vocabulary (#271). Public so the schema emitter states the
/// same closed set the loader enforces.
pub const alpn = @import("tls/alpn.zig");

const assert = std.debug.assert;
const repeat = @import("testing/bytes.zig").repeat;

pub const Config = struct {
    listeners: []const Listener,
    clusters: []const Cluster,
    connect_timeout_ms: u32,
    idle_timeout_ms: u32,
    drain_deadline_ms: u32,
    /// #311's serving-loop backstop, in milliseconds; `0` is off, which
    /// is what an absent key resolves to.
    ///
    /// Every other deadline in this file is an op the loop delivers, so
    /// none of them can bound the loop itself. This one is `alarm(2)`:
    /// the kernel raises it whatever the process is doing, and a tick the
    /// loop *does* deliver is what keeps pushing it out. So the number an
    /// operator writes here is "how long may this proxy go without
    /// completing anything before it is declared stalled and killed".
    loop_watchdog_ms: u32,
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
        /// ceiling multiplies this by 14321 pairs, so 4 KiB is ~112 MiB of
        /// relay pool where the default is ~448. Raising it past one TLS
        /// record is refused; see `relay_buffer_bytes_max` for why that
        /// bound is the transform's and not the RFC's.
        relay_buffer_bytes: u32 = constants.relay_buffer_bytes_default,
        /// The §4 TLS engine pool: how many sessions may be handshaking
        /// or terminated at once. An engine is ~92 KiB plus a plaintext
        /// buffer, far the largest per-connection object here, so this is
        /// the knob that decides what a TLS deployment costs in RSS. The
        /// loader resolves an omitted field to conn slots capped at
        /// `tls_engines_max`; the operator trades it down against a
        /// handshake wall, on the same terms as every other pool (§8).
        /// Zero exactly when no listener
        /// terminates TLS, and the struct default is the off state on the
        /// same terms as `head_buffers`.
        tls_engines: u32 = 0,
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
        /// The §5 HTTP/2 session pool and the shared stream pool its
        /// multiplexed exchanges draw from (#275). The sessions are zero
        /// exactly when no listener speaks HTTP/2 — `h2` in `tls.alpn`, or
        /// `http.h2c`. Where one does, `limits.h2_connections` defaults to
        /// `constants.h2_connections_default` (capped at conn slots). The
        /// streams are zero exactly when no listener speaks HTTP/2 or
        /// HTTP/3, which multiplex on the same pool; where one does,
        /// `limits.h2_streams` is required: a count of concurrent
        /// exchanges is a capacity decision, not something a connection
        /// count implies.
        h2_connections: u32 = 0,
        stream_slots: u32 = 0,
        /// The §5 QUIC connection pool (#449): the HTTP/3 connections
        /// served at once, each holding a TLS engine for its whole life.
        /// Zero exactly when no listener has a `quic` binding. Where one
        /// does, `limits.quic_connections` defaults to
        /// `constants.quic_connections_default`, capped at the conn slots
        /// and the engines, and may exceed neither.
        quic_connections: u32 = 0,
        /// The §5 pools an HTTP/2 origin draws on (§7): connections to
        /// `h2c` clusters' endpoints, each a client session many exchanges
        /// share, and the staging buffers those exchanges' streams hold
        /// their answers in. Zero exactly when no cluster speaks `h2c`.
        /// Where one does, the connections default to two per `h2c`
        /// endpoint and the streams to the upstream slots — every such
        /// exchange holds one of those too, so more could never be used.
        h2_origin_connections: u32 = 0,
        h2_origin_streams: u32 = 0,
        /// TLS sessions to HTTP/1.1 origins (§7, #296): one per upstream
        /// connection to a cluster with `tls` and `protocol` `http1`, held
        /// while it is leased and while it is parked. Zero exactly when no
        /// such cluster exists; sixteen per such endpoint by default,
        /// within the upstream slots and the libcrypto heap.
        upstream_tls_sessions: u32 = 0,
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
        /// The consults a build's policies may have in flight (#437):
        /// zero unless the options state some. Each holds an upstream
        /// slot while it runs, so there are never more than those.
        consult_slots: u32 = 0,
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
        /// #417's request policies on this listener, selected in code: run
        /// in order on every request after its head canonicalizes, before
        /// `request_filters` and routing. Http listeners only, and never
        /// spelled in JSON: an extension is selected in code.
        request_policies: []const extension_module.Selection = &.{},
        /// #424's response policies on this listener, selected in code:
        /// run on every response head, after the response filters.
        response_policies: []const extension_module.Selection = &.{},
        /// #425's connection policies, selected in code: run on every
        /// connection admitted here, either protocol, once its client's
        /// address is known.
        connection_policies: []const extension_module.Selection = &.{},
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
        /// Inbound only: it terminates. Originating TLS to a backend is the
        /// cluster's to say (`Cluster.tls`, §7, #296), with its own trust
        /// store, and #125 is termination.
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
        /// Whether this plaintext listener takes h2c by prior knowledge
        /// (#275, RFC 9113 §3.3): a connection opening with HTTP/2's
        /// preface speaks HTTP/2 (`http.h2c`). A TLS listener negotiates
        /// HTTP/2 by ALPN instead, and is refused the key.
        h2c: bool = false,
        /// Where this listener also serves HTTP/3 over QUIC (#449,
        /// `http.quic`), or null for nowhere. One listener, two sockets:
        /// the binding shares the listener's routes, filters, policies and
        /// certificates, so a TCP listener without `tls` is refused one.
        /// The two binds are independent — the usual shape is the same
        /// address and port on TCP and UDP.
        quic: ?Quic = null,
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
        /// `http` runs the reverse-proxy exchange — HTTP/1.1, with HTTP/2
        /// as a front end on it (#275).
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

        /// This listener's certificate and key (§4), as PEM bytes (#417):
        /// whoever builds the config reads them — the JSON loader through
        /// its file seam, a custom build from wherever it keeps them — so
        /// nothing past this point touches a filesystem. They are parsed
        /// at startup, before the first handshake, so a malformed one
        /// stops the start rather than failing a client.
        pub const Tls = struct {
            /// PEM certificate chain, leaf first.
            cert_pem: []const u8,
            /// PEM private key for the leaf: ECDSA P-256 or P-384, or RSA
            /// of 2048 to 4096 bits (#411); any other key is refused at
            /// startup (`tls/Credentials.zig`).
            key_pem: []const u8,
            /// What a startup error calls this pair: the two paths a JSON
            /// config named, or whatever the code that built it says.
            label: []const u8,
            /// What this listener offers in ALPN (#271), most preferred
            /// first: canonical `tls/alpn.zig` tokens, never the config's
            /// own spellings. `["http/1.1"]` on an `http` listener whose
            /// block named none, and empty on an `l4` one, which speaks no
            /// protocol it could name. No default: a listener built in
            /// code has to say which, rather than inherit a silence the
            /// loader never produces.
            alpn: []const []const u8,
            /// #304: the CAs a client's certificate must chain to, and
            /// whether presenting one is required. Null asks no client
            /// for a certificate — the handshake every listener had.
            client_ca: ?ClientCa = null,
            /// #297: further certificates, chosen by the server name a
            /// ClientHello asks for against each one's DNS names. The pair
            /// above stays the default — what a client that names nothing,
            /// or nothing these cover, is shown.
            certificates: []const Certificate = &.{},
        };

        /// One more certificate a listener can present (#297), in the
        /// default pair's shape.
        pub const Certificate = struct {
            cert_pem: []const u8,
            key_pem: []const u8,
            label: []const u8,
        };

        /// A listener's mutual-TLS policy (#304). Per listener, never per
        /// certificate: verifying a peer is a property of the socket, so
        /// it sits beside the credential set rather than inside it (§5).
        pub const ClientCa = struct {
            /// DER anchors, parsed at load into the config arena.
            anchors: []const []const u8,
            verify: ClientVerify,
        };

        /// `required` refuses a handshake that presents no certificate;
        /// `optional` completes it unauthenticated. Either way a
        /// certificate that *is* presented must verify (#304).
        pub const ClientVerify = enum { required, optional };

        /// A listener's QUIC binding (#449), resolved: an IP and port,
        /// because QUIC rides UDP datagrams and a socket file carries
        /// none, and the max-age its TCP responses advertise it under.
        pub const Quic = struct {
            bind_address: std.Io.net.IpAddress,
            /// The RFC 7838 `Alt-Svc` max-age in seconds, at most
            /// `constants.alt_svc_max_age_s_max`; 0 advertises nothing.
            alt_svc_max_age_s: u32,
        };
    };

    /// A slot of a cluster that takes endpoints while it serves (#428).
    pub const EndpointState = enum(u8) {
        /// An endpoint of the set, picked and probed.
        live,
        /// An endpoint that left the set: never picked or probed again,
        /// its in-flight work running to its end before the slot is free.
        draining,
        /// No endpoint: weight 0, never picked, probed or rendered.
        free,
    };

    /// The writable side of a cluster that declared `endpoint_slots`
    /// (#428): `endpoints`, `weights` and `priorities` alias these, at the
    /// declared capacity, and `states` says what each slot holds. An
    /// update writes here, on the loop thread, into slots reserved at
    /// startup — so a reader holds what it reads for one loop turn, never
    /// across one, and the `[]const` views are read-only for it alone.
    pub const Slots = struct {
        addresses: []io_module.Address,
        weights: []u16,
        priorities: []u8,
        states: []EndpointState,
    };

    pub const Cluster = struct {
        name: []const u8,
        /// The endpoints, or on a cluster with `slots`, every slot: a free
        /// one holds a placeholder no pick reaches, since its weight is 0.
        endpoints: []const io_module.Address,
        /// Room for endpoints added while serving (#428), or null for a
        /// cluster whose endpoints are fixed at startup.
        slots: ?*Slots = null,
        /// Per-endpoint §7 pick weights, parallel to `endpoints` — or
        /// null when every endpoint carries the default weight of 1,
        /// which is what the bare-string config form says and what most
        /// clusters are, so the loader only materializes the table when
        /// some weight differs. A weight of `0` drains its endpoint:
        /// still probed (§7), never picked — the balancer treats it as
        /// administratively out, so not even fail-open reaches it.
        weights: ?[]const u16 = null,
        /// #396's standby tiers, parallel to `endpoints` — or null when
        /// every endpoint is a primary (priority 0), which is every config
        /// before the key, so the table exists only where tiers do.
        priorities: ?[]const u8 = null,
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
        /// #390's panic threshold, in percent of the cluster's routable
        /// weight. While the healthy share of that weight is at or
        /// above it, health verdicts steer picks; below it, the balancer
        /// picks over every routable endpoint as if none were ejected.
        /// Null keeps the 1.0-era rule (§5, #400): fail open only when
        /// nothing is healthy — which is this same threshold at zero.
        panic_threshold_percent: ?u8 = null,
        /// The §8 concurrency cap protecting each of this cluster's
        /// endpoints, or null for uncapped. **Per endpoint, not per
        /// cluster**: it is a statement about what one origin can carry,
        /// the same unit HAProxy's `server ... maxconn` names, so a
        /// cluster's total admitted work is this times its endpoint
        /// count. Counted against the endpoint's in-flight total —
        /// L7 requests and live L4 connections alike (§7).
        max_inflight: ?u32 = null,
        /// #392's cap on the cluster's *total* in-flight work in this
        /// process — every endpoint's leases and live L4 connections
        /// summed — or null for none. A first try that finds the total
        /// at the cap is shed; a retry continues a request the cap
        /// already admitted, so it is never refused by it.
        max_total_inflight: ?u32 = null,
        /// #391's slow start: for this long after an endpoint comes back
        /// into rotation — a probe's `rise` or a passive cooldown's end —
        /// its `max_inflight` ramps linearly from 1 to the configured cap,
        /// so the first origin to recover is not handed every pick at
        /// once. Null leaves a restored endpoint at its full cap.
        slow_start_ms: ?u32 = null,

        /// How many further endpoints one request may dial after a
        /// refused or unreachable first try (#181), 0 for none — the
        /// default, and what every config predating this key keeps
        /// doing. Bounded by `cluster_retries_max`. Only the L7 path
        /// spends it: an L4 connection dials once and relays whatever
        /// the dial produced, with no request to send somewhere else.
        retries: u16 = 0,
        /// #393: how many retry dials this cluster may have in flight at
        /// once in this process, or null for no bound beyond `retries`.
        retry_budget: ?u16 = null,

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
        /// What the origins speak (§7): HTTP/1.1, each exchange leasing a
        /// pooled socket, or HTTP/2 by prior knowledge (`h2c`, RFC 9113
        /// §3.3), many exchanges sharing a connection as streams. Only
        /// `http` listeners route to an `h2c` cluster, and none that
        /// carries an upgrade: HTTP/2 has no `101`.
        protocol: Protocol = .http1,
        /// TLS to the origins (§7, #296): the name every origin must
        /// prove, which is also the SNI sent, and the anchors its chain
        /// must reach — parsed from the `ca` bundle at load. Required by
        /// `h2`; with `http1` the origins speak HTTPS; never with `h2c`.
        tls: ?Tls = null,

        pub const Protocol = enum(u2) {
            http1,
            /// HTTP/2 by prior knowledge, in the clear (RFC 9113 §3.3).
            h2c,
            /// HTTP/2 over TLS, selected in ALPN (RFC 9113 §3.2).
            h2,

            /// Whether the origins speak HTTP/2, on a shared connection.
            pub fn http2(protocol: Protocol) bool {
                return protocol != .http1;
            }
        };

        pub const Tls = struct {
            server_name: []const u8,
            anchors: []const []const u8,
        };

        pub const Pick = union(enum) {
            rr,
            p2c,
            /// Rendezvous hashing (§7): the same key always lands on the
            /// same endpoint, so a client reaches one stateful backend
            /// across connections — and, because the answer is a pure
            /// function of the key and the eligible set, every process
            /// behind SO_REUSEPORT computes it identically with nothing
            /// shared (§3).
            hash,
            /// A picker the build lists (#417), selected in code. The JSON
            /// loader never produces one: it reads only `Builtin` names, so
            /// a stock config cannot reach an extension at all.
            extension: extension_module.Selection,

            /// The policies the config may name. Apart from `Pick`'s own
            /// tag, so the loader's closed vocabulary and the schema's
            /// enum stay exactly what they were before `extension` existed.
            pub const Builtin = enum(u2) { rr, p2c, hash };

            pub fn builtin(policy: Builtin) Pick {
                return switch (policy) {
                    .rr => .rr,
                    .p2c => .p2c,
                    .hash => .hash,
                };
            }
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
            /// a chosen status, which a SYN/ACK cannot; `grpc` proves an
            /// HTTP/2 origin's application says SERVING to the standard
            /// health service (`grpc.health.v1.Health/Check`), over the
            /// cluster's own connections — TLS and all.
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
            /// The service a `grpc` probe asks about; empty asks about the
            /// server as a whole, as the health protocol defines.
            grpc_service: []const u8 = "",
            /// The build's check kind an `extension` probe runs (#436),
            /// selected in code; never spelled in JSON.
            probe: ?extension_module.Selection = null,

            pub const Kind = enum(u2) {
                tcp,
                http,
                grpc,
                extension,
            };

            /// The kinds a config may name: every one but a build's own
            /// (#436), which is selected in code. Apart from `Kind`, as
            /// `Pick.Builtin` is apart from `Pick`, so the loader's closed
            /// vocabulary and the schema's enum stay what they were before
            /// `extension` existed — the schema advertising a kind the
            /// loader refuses was 1.1.0's first cut.
            pub const Builtin = enum(u2) {
                tcp,
                http,
                grpc,

                pub fn kind(builtin: Builtin) Kind {
                    return switch (builtin) {
                        .tcp => .tcp,
                        .http => .http,
                        .grpc => .grpc,
                    };
                }

                comptime {
                    for (@typeInfo(Builtin).@"enum".field_names) |name| {
                        assert(@hasField(Kind, name));
                    }
                    assert(@typeInfo(Builtin).@"enum".field_names.len + 1 ==
                        @typeInfo(Kind).@"enum".field_names.len);
                    // And the one it leaves out is the build's own.
                    assert(!@hasField(Builtin, "extension"));
                    assert(@hasField(Kind, "extension"));
                }
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
            /// #394: the ceiling a repeatedly ejected endpoint's cooldown
            /// doubles toward, or null to keep every cooldown at
            /// `recovery_ms` — the rule before the key (§5, #400).
            recovery_ms_max: ?u32 = null,
        };

        /// Whether slot `index` holds an endpoint of the set (#428): every
        /// slot of a cluster whose endpoints are fixed does.
        pub fn liveAt(cluster: *const Cluster, index: usize) bool {
            assert(index < cluster.endpoints.len);
            const slots = cluster.slots orelse return true;
            return slots.states[index] == .live;
        }

        /// Whether slot `index` holds an endpoint at all — of the set, or
        /// draining out of it (#428).
        pub fn occupiedAt(cluster: *const Cluster, index: usize) bool {
            assert(index < cluster.endpoints.len);
            const slots = cluster.slots orelse return true;
            return slots.states[index] != .free;
        }
    };
};

pub const ValidationError = error{
    ListenersEmpty,
    ListenersOverLimit,
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
    ClusterUnknown,
    ClustersEmpty,
    ClustersOverLimit,
    ClusterNameDuplicate,
    ClusterNameEmpty,
    ClusterNameTooLong,
    ClusterCheckThresholdOutOfRange,
    ClusterCheckTimeoutOutOfRange,
    ClusterCheckPathTooLong,
    ClusterCheckPathNotCanonical,
    ClusterCheckHostInvalid,
    ClusterCheckStatusInvalid,
    /// A `service` the probe cannot carry: too long for its one-octet
    /// length, or not a printable name.
    ClusterCheckServiceInvalid,
    /// A `grpc` check on a cluster that speaks HTTP/1.1, which gRPC
    /// cannot ride.
    ClusterCheckGrpcOnHttp1,
    ClusterPassiveEjectionFallOutOfRange,
    ClusterPassiveEjectionRecoveryOutOfRange,
    ClusterPassiveEjectionRecoveryMaxBelowBase,
    ClusterMaxInflightOutOfRange,
    ClusterMaxTotalInflightOutOfRange,
    ClusterSlowStartOutOfRange,
    ClusterSlowStartWithoutMaxInflight,
    ClusterSlowStartWithoutHealth,
    ClusterPanicThresholdOutOfRange,
    ClusterPanicThresholdWithoutHealth,
    ClusterRetriesOutOfRange,
    ClusterPickNameInvalid,
    ClusterPickNameTooLong,
    ListenerL4RequestKeyedHash,
    BodiesOverLimit,
    BodyNameEmpty,
    BodyNameTooLong,
    BodyNameDuplicate,
    BodyContentTypeInvalid,
    BodyOverLimit,
    BodyUnknown,
    AccessLogHeadersOverLimit,
    AccessLogHeaderNameInvalid,
    AccessLogHeaderNameTooLong,
    AccessLogHeaderDuplicate,
    LimitAccessLogBufferUnderLine,
    FilterRespondStatus,
    ErrorPagesOverLimit,
    ErrorPageStatusUnknown,
    ErrorPageDuplicate,
    RoutesEmpty,
    RoutePrefixNotCanonical,
    RouteHostNotCanonical,
    RouteHostWildcard,
    RouteDuplicate,
    /// A route's name is empty or past `route_name_bytes_max` (#430).
    RouteNameInvalid,
    /// Two routes of one listener share a name, which a policy could not
    /// route by (#430).
    RouteNameDuplicate,
    /// A route names both a cluster and a handler (#434), or neither: it
    /// must send its requests one place.
    RouteTargetInvalid,
    /// A listener states more routes than a `u16` route index can name.
    RoutesOverLimit,
    ListenerMaxBodyBytesOutOfRange,
    ListenerTlsWithSniRoutes,
    ListenerTlsClientCaInvalid,
    RouteSniIsAddress,
    LimitRelayBufferUnderSniRouting,
    LimitRelayBufferOverTlsRecord,
    ListenerTlsCertificatesOverLimit,
    ListenerTlsAlpnEmpty,
    ListenerTlsAlpnDuplicate,
    ListenerTlsAlpnOnL4,
    ClusterProxyProtocolOnHttpListener,
    ClusterProxyProtocolOnTlsListener,
    FilterMethodEmpty,
    FilterMethodUnknown,
    FilterHeaderContainsEmpty,
    FilterHeaderNameInvalid,
    FilterHeaderNameReserved,
    FilterHeaderValueInvalid,
    FilterClientPrefixTooNarrow,
    FilterClientCidrHostBits,
    FilterActionsEmpty,
    FilterRejectStatus,
    FilterRedirectStatus,
    FilterRedirectTarget,
    FilterHeaderEditsOverLimit,
    ResponseFilterStatusInvalid,
    ResponseFilterHeaderEditsOverLimit,
    EndpointsEmpty,
    EndpointsOverLimit,
    /// `endpoint_slots` below the endpoints a cluster states, or past the
    /// endpoint index's edge (#428).
    EndpointSlotsOutOfRange,
    EndpointPortZero,
    /// A `unix:` endpoint whose path is empty, past what a `sockaddr_un`
    /// carries, or carries a byte an address may not — a control byte, a
    /// quote or a backslash, each of which would corrupt the access log
    /// and the metrics exposition rather than one field of them (#303).
    EndpointUnixPathInvalid,
    /// A `unix:` endpoint path that is not absolute (#303).
    EndpointUnixPathRelative,
    EndpointWeightOverLimit,
    EndpointPriorityOverLimit,
    EndpointWeightsAllZero,
    TimeoutZero,
    TimeoutOverLimit,
    TimeoutOrderInvalid,
    TimeoutTunnelOutOfRange,
    /// A `timeouts.loop_watchdog_ms` under `loop_watchdog_ms_min` (#311).
    /// Named apart from `TimeoutZero` because the two say different
    /// things: that one is a deadline zeroed into meaninglessness, this
    /// is a bound the mechanism cannot express — `alarm(2)` counts whole
    /// seconds, and the tick refreshing it takes half the bound.
    LoopWatchdogTooShort,
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
    LimitH2StreamsRequired,
    LimitH2StreamsOutOfRange,
    LimitH2StreamsWithoutHttp2,
    LimitH2ConnectionsOutOfRange,
    LimitH2ConnectionsOverConnSlots,
    LimitH2ConnectionsWithoutHttp2,
    ListenerH2cOnTls,
    LimitQuicConnectionsOutOfRange,
    LimitQuicConnectionsOverConnSlots,
    /// More QUIC connections than TLS engines (#449): each holds one for
    /// its whole life, so the excess could never complete a handshake.
    LimitQuicConnectionsOverTlsEngines,
    LimitQuicConnectionsWithoutQuic,
    /// A `quic` binding on a listener without `tls` (#449): QUIC is always
    /// TLS 1.3, and the binding presents the listener's certificates.
    ListenerQuicWithoutTls,
    /// A `quic` binding that advertises itself on a listener whose response
    /// filters already use every header edit (#449): its `Alt-Svc` is one
    /// edit more. A max-age of zero advertises nothing and takes none.
    ListenerQuicAltSvcOverEditLimit,
    /// A `quic` bind that is a `unix:` path (#449): QUIC rides UDP
    /// datagrams, which a socket file does not carry here.
    ListenerQuicBindNotIp,
    /// Two listeners' `quic` binds on one IP and port (#449); a TCP bind
    /// may share one, since the protocols' ports are distinct.
    ListenerQuicBindDuplicate,
    ListenerQuicAltSvcMaxAgeOutOfRange,
    LimitUpstreamH2ConnectionsOutOfRange,
    LimitUpstreamH2ConnectionsWithoutHttp2,
    LimitUpstreamH2StreamsOutOfRange,
    LimitUpstreamH2StreamsOverUpstreamSlots,
    /// More consult slots (#437) than upstream slots, which every consult
    /// holds one of: the excess could never be used.
    LimitConsultSlotsOverUpstreamSlots,
    LimitUpstreamH2StreamsWithoutHttp2,
    /// An `h2c` cluster probed by HTTP/1.1, which its origins may not
    /// speak at all: every probe would fail, and eject every endpoint.
    ClusterH2cHttpCheck,
    /// An `l4` listener reaching an HTTP/2 cluster (`h2c` or `h2`) by
    /// its `cluster` or by any SNI route: what it relays is whatever the
    /// client sent, not HTTP/2 this proxy speaks.
    ClusterH2cOnL4Listener,
    /// An `http` listener carrying an upgrade to an `h2c` cluster: the
    /// tunnel would need a `101`, which HTTP/2 does not have.
    ClusterH2cWithUpgrades,
    /// `tls` on an `h2c` cluster, which is HTTP/2 in the clear by name, or
    /// `h2` without it.
    ClusterTlsOnH2c,
    ClusterH2WithoutTls,
    ClusterRetriesOnHttp2,
    ClusterRetryBudgetOutOfRange,
    /// A retry budget on a cluster that does not retry (#393): there is
    /// nothing for it to bound. JSON's object form cannot spell one, so
    /// only options written in code reach this (#417).
    ClusterRetryBudgetWithoutRetries,
    /// An `l4` listener reaching an HTTPS cluster by its `cluster` or by
    /// any SNI route: it relays bytes, and what TLS would carry for it is
    /// not a request this proxy reads.
    ClusterTlsOnL4Listener,
    /// An upgrade to an HTTPS cluster: the tunnel's relay reads and writes
    /// the socket itself, under the TLS this proxy would have to keep.
    ClusterTlsWithUpgrades,
    /// An `http` check on an HTTPS cluster: the prober speaks plaintext,
    /// so it would probe something the traffic does not reach.
    ClusterTlsHttpCheck,
    /// A build's own check kind (#436) on a TLS cluster, for the same
    /// reason: its probe speaks over the prober's plaintext socket.
    ClusterTlsExtensionCheck,
    ClusterTlsServerNameInvalid,
    /// The bundle holds no certificate, or a block that is not one.
    ClusterTlsCaInvalid,
    /// The libcrypto heap is reserved for `tls_engines_max` sessions, and
    /// the origin connections a TLS cluster may open count against it.
    LimitUpstreamH2TlsOverEngines,
    /// HTTPS origins' sessions are the heap's third consumer (#296).
    LimitUpstreamTlsOverEngines,
    LimitUpstreamTlsSessionsOutOfRange,
    LimitUpstreamTlsSessionsOverUpstreamSlots,
    LimitUpstreamTlsSessionsWithoutTls,
    LimitCqFillOutOfRange,
    LimitConnSlotsOverCqFill,
    LimitAccessLogBufferOutOfRange,
    LimitAccessLogBufferWithoutSink,
    AccessLogPathMissing,
};

/// What `resolve` returns: a rule the options break, or an arena that
/// ran out.
pub const ResolveError = ValidationError || error{OutOfMemory};

/// Validate a build's options and compile them into the `Config` the
/// server runs (#417): every refusal zoxy makes of a config, made of the
/// options alone. It reads no file and resolves no name — the bytes and
/// addresses are the options' own — so it is one function whether a file
/// or code wrote them. The `Config` references both the arena and the
/// options' own memory; the caller keeps both for the process's life.
pub fn resolve(arena: std.mem.Allocator, options: *const Options) ResolveError!Config {
    // Timeouts first: a cluster's check budget is held to the same
    // ceiling, and its default was priced from the connect timeout.
    try validateTimeouts(&options.timeouts);
    const clusters = try resolveClusters(arena, options.clusters);
    // Emptiness outranks everything after the clusters (the limits
    // resolver asserts a non-empty set, so the gate fires first here),
    // and the count's `u16` edge is checked before anything is sized
    // from it.
    if (options.listeners.len == 0) {
        return error.ListenersEmpty;
    }
    if (options.listeners.len > std.math.maxInt(u16)) {
        return error.ListenersOverLimit;
    }
    const features = try countListenerFeatures(options.listeners);
    const access_log_sink = try resolveAccessLogSink(options.access_log);
    // Before the limits, because the named headers widen the line the
    // staging buffer has to be able to hold (#140).
    const log_headers = try resolveLogHeaders(arena, options.access_log);
    const limits = try resolveLimits(
        &options.limits,
        @intCast(options.listeners.len),
        features,
        access_log_sink != null,
        log_headers.count(),
        // The prober's share of the ring, which `resolveCqFill` has to
        // know before it can accept a fill (#132). Available here
        // because clusters resolve before limits do — the `check` blocks
        // are already settled by the time the budget is priced.
        constants.healthProbeConcurrency(checkedEndpointsOf(clusters)),
        // What the origin pools are sized for (§7, #296), known for the
        // same reason.
        .{
            .h2c_endpoints = h2cEndpointsOf(clusters),
            .h2_origin_tls = h2OriginTls(clusters),
            .upstream_tls_endpoints = upstreamTlsEndpointsOf(clusters),
        },
    );
    // Limits resolve before listeners: the route prefixes inside
    // `resolveListeners` are gated against the resolved
    // `head_buffer_bytes` — a prefix longer than the head can never match
    // a parsed path, and belongs refused at load, not left to 404 forever
    // at runtime. Bodies resolve before listeners too (#159): a `respond`
    // action names one, and both consumers render through the same
    // load-time cache, so the table has to exist before any rule compiles.
    const bodies = try resolveBodies(arena, options.bodies);
    const listeners = try resolveListeners(
        arena,
        options.listeners,
        clusters,
        limits.head_buffer_bytes,
        bodies,
    );
    const error_pages = try resolveErrorPages(arena, options.error_pages, bodies);
    assert(listeners.len == options.listeners.len);
    assert(clusters.len == options.clusters.len);
    return configOf(options, .{
        .listeners = listeners,
        .clusters = clusters,
        .limits = limits,
        .access_log_sink = access_log_sink,
        .log_headers = log_headers,
        .error_pages = error_pages,
    });
}

/// What `resolve` compiled, gathered for `configOf`.
const Resolved = struct {
    listeners: []const Config.Listener,
    clusters: []const Config.Cluster,
    limits: Config.Limits,
    access_log_sink: ?Config.AccessLogSink,
    log_headers: ResolvedLogHeaders,
    error_pages: []const *const Config.StaticPage,
};

/// The `Config` the server runs, from the options and what was compiled
/// of them — split from `resolve` for the length limit.
fn configOf(options: *const Options, resolved: Resolved) Config {
    const timeouts = &options.timeouts;
    assert(timeouts.connect_ms < timeouts.head_ms);
    assert(resolved.listeners.len >= 1);
    return .{
        .listeners = resolved.listeners,
        .clusters = resolved.clusters,
        .connect_timeout_ms = timeouts.connect_ms,
        .idle_timeout_ms = timeouts.idle_ms,
        .drain_deadline_ms = timeouts.drain_deadline_ms,
        // Absent is off, and `0` is how the rest of this struct spells
        // that — so the optional collapses here rather than travelling
        // any further. The options spell it as absence because the
        // mechanism has a floor (`loop_watchdog_ms_min`): the legal values
        // are "none" and "at least the floor", with nothing between.
        .loop_watchdog_ms = timeouts.loop_watchdog_ms orelse 0,
        .max_lifetime_ms = timeouts.max_lifetime_ms,
        .head_timeout_ms = timeouts.head_ms,
        .request_timeout_ms = timeouts.request_ms,
        .tunnel_timeout_ms = timeouts.tunnel_ms,
        .health_interval_ms = timeouts.health_interval_ms,
        .limits = resolved.limits,
        .admin_bind = if (options.admin) |admin| admin.bind else null,
        .access_log_sink = resolved.access_log_sink,
        .access_log_request_headers = resolved.log_headers.request,
        .access_log_response_headers = resolved.log_headers.response,
        .error_pages = resolved.error_pages,
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
    access_log: ?Options.AccessLog,
) ResolveError!ResolvedLogHeaders {
    const stated = access_log orelse return .{ .request = &.{}, .response = &.{} };
    const headers_count = stated.request_headers.len + stated.response_headers.len;
    if (headers_count > constants.access_log_headers_max) {
        return error.AccessLogHeadersOverLimit;
    }
    const request = try resolveLogHeaderNames(arena, stated.request_headers);
    const response = try resolveLogHeaderNames(arena, stated.response_headers);
    // Deduplicated per direction, not across: the same name on both
    // sides is two different facts — what the client sent and what the
    // origin answered — and they land in different objects.
    assert(request.len == stated.request_headers.len);
    assert(response.len == stated.response_headers.len);
    return .{ .request = request, .response = response };
}

fn resolveLogHeaderNames(
    arena: std.mem.Allocator,
    stated: []const []const u8,
) ResolveError![]const []const u8 {
    if (stated.len == 0) {
        return &.{};
    }
    const names = try arena.alloc([]const u8, stated.len);
    for (stated, 0..) |raw, index| {
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
    assert(names.len == stated.len);
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

/// Resolve the #159 bodies: names bounded and unique, bytes under
/// `body_bytes_max` wherever they came from, content type a forwardable
/// header value. None is an empty table, and every reference then fails
/// as `BodyUnknown`.
fn resolveBodies(
    arena: std.mem.Allocator,
    stated: []const Options.Body,
) ResolveError![]ResolvedBody {
    if (stated.len > std.math.maxInt(u16)) {
        return error.BodiesOverLimit;
    }
    const bodies = try arena.alloc(ResolvedBody, stated.len);
    for (stated, 0..) |entry, index| {
        if (entry.name.len == 0) {
            return error.BodyNameEmpty;
        }
        if (entry.name.len > constants.body_name_bytes_max) {
            return error.BodyNameTooLong;
        }
        // Nested rather than sorted (the cluster-names rationale does
        // not carry): a config lists a handful of bodies, and each has
        // already paid a file read or a copy next to this compare.
        for (bodies[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, entry.name)) {
                return error.BodyNameDuplicate;
            }
        }
        // The cap holds whichever way the bytes arrived: where they came
        // from is not what the memory statement is about.
        if (entry.bytes.len > constants.body_bytes_max) {
            return error.BodyOverLimit;
        }
        bodies[index] = .{
            .name = entry.name,
            .bytes = entry.bytes,
            .content_type = try resolveContentType(entry.content_type),
        };
        assert(bodies[index].name.len >= 1);
        assert(bodies[index].bytes.len <= constants.body_bytes_max);
    }
    assert(bodies.len == stated.len);
    return bodies;
}

/// A body's Content-Type: non-empty and injection-safe — the same
/// forwardable-byte rule filter header values keep, since this value
/// lands on the wire inside a rendered head.
fn resolveContentType(content_type: []const u8) ResolveError![]const u8 {
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
    stated: []const Options.ErrorPage,
    bodies: []ResolvedBody,
) ResolveError![]const *const Config.StaticPage {
    // The closed status set bounds what can survive validation, so a
    // longer list always fails below — on an unknown status or on a
    // duplicate, and which one is not knowable from the count alone,
    // which is why this has an error of its own rather than guessing at
    // either. Ahead of the allocation, so a rejected config's arena
    // stays bounded by the vocabulary rather than by the list's length
    // (`BodiesOverLimit`'s reasoning, one resolver up).
    if (stated.len > shed.static_statuses.len) {
        return error.ErrorPagesOverLimit;
    }
    const pages = try arena.alloc(*const Config.StaticPage, stated.len);
    for (stated, 0..) |entry, index| {
        // The error set, not the wider page set: `200` is a `respond`
        // action's status, and no rung raises it — a page here for one
        // would never serve.
        if (!shed.isStaticStatus(entry.status)) {
            return error.ErrorPageStatusUnknown;
        }
        // The closed set is ten wide, so the duplicate scan is bounded
        // by it whatever the entry count claims.
        for (pages[0..index]) |previous| {
            if (previous.status == entry.status) {
                return error.ErrorPageDuplicate;
            }
        }
        pages[index] = try pageFor(arena, bodies, entry.body, entry.status);
        // What the serve path reads back (`configuredPage`): a head
        // that is a prefix of its own response, on both variants.
        assert(pages[index].keep_head_len <= pages[index].keep.len);
        assert(pages[index].close_head_len <= pages[index].close.len);
    }
    assert(pages.len == stated.len);
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
) ResolveError!*const Config.StaticPage {
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
) ResolveError!struct { bytes: []const u8, head_len: u32, date: *[shed.date_bytes]u8 } {
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
/// buffers reserved, no lines emitted. The sink is a union, so a path
/// beside stdout or a file sink without one is not a shape the options
/// can state; JSON's spellings of both, and of an unknown sink, are its
/// front-end's refusals (`accessLogOf`). What is left to judge is the
/// file sink's path, which an empty string would leave naming nothing.
fn resolveAccessLogSink(
    access_log: ?Options.AccessLog,
) ValidationError!?Config.AccessLogSink {
    const stated = access_log orelse return null;
    switch (stated.sink) {
        .stdout => {},
        // Empty is missing, not "a file named nothing": openat would
        // reject it later and worse — at startup's end, not load time.
        .file => |path| if (path.len == 0) return error.AccessLogPathMissing,
    }
    // The postcondition `openLogSinkFd` (app) leans on.
    if (stated.sink == .file) assert(stated.sink.file.len >= 1);
    return stated.sink;
}

/// The pools a *feature* switches on, as `resolveFeaturePools` sizes them.
const FeaturePools = struct {
    tls_engines: u32,
    tunnels: u32,
    h2_connections: u32,
    stream_slots: u32,
    quic_connections: u32,
};

/// The pools a *feature* switches on: TLS engines, reserved exactly when
/// some listener terminates; #180's tunnels, exactly when some listener
/// allows an upgrade; #275's HTTP/2 sessions, exactly when some listener
/// speaks HTTP/2; #449's QUIC connections, exactly when some listener has
/// a `quic` binding; and the shared streams both of those multiplex on.
/// Their own group because each is zero for a deployment that asked for
/// none of it — which is what makes each feature free — and each is
/// bounded by the conn slots above or a ceiling of its own.
fn resolveFeaturePools(
    requested: *const Options.Limits,
    conn_slots: u32,
    features: ListenerFeatures,
) ValidationError!FeaturePools {
    const tls_engines = try resolveTlsEngines(
        requested.tls_engines,
        conn_slots,
        features.tls,
    );
    const tunnels = try resolveTunnels(
        requested.tunnels,
        conn_slots,
        features.upgrades,
    );
    // A listener speaking both counts twice, which is harmless: the
    // resolver asks only whether anything multiplexes at all.
    const stream_slots = try resolveStreamSlots(requested.h2_streams, features.http2 + features.quic);
    const h2_connections = try resolveH2Connections(
        requested.h2_connections,
        conn_slots,
        features.http2,
    );
    // After the engines, which every QUIC connection holds one of.
    const quic_connections = try resolveQuicConnections(
        requested.quic_connections,
        conn_slots,
        tls_engines,
        features.quic,
    );
    // A QUIC-only deployment has stream slots and no HTTP/2 session.
    assert((stream_slots == 0) == (h2_connections == 0 and quic_connections == 0));
    assert(quic_connections <= tls_engines);
    return .{
        .tls_engines = tls_engines,
        .tunnels = tunnels,
        .h2_connections = h2_connections,
        .stream_slots = stream_slots,
        .quic_connections = quic_connections,
    };
}

/// The shared stream pool HTTP/2 and HTTP/3 multiplex (#275, #449):
/// required — and only legal — where a listener speaks either, on
/// `tunnels`' reasoning: how many exchanges run at once is a capacity
/// decision, not something a connection count implies, and every one is
/// charged its ring ops (§8). The key and its errors keep HTTP/2's name,
/// which is the one the pool shipped under.
fn resolveStreamSlots(requested: ?u32, multiplexing_count: u32) ValidationError!u32 {
    const stream_slots = requested orelse {
        if (multiplexing_count >= 1) return error.LimitH2StreamsRequired;
        return 0;
    };
    if (multiplexing_count == 0) return error.LimitH2StreamsWithoutHttp2;
    if (stream_slots < 1 or stream_slots > constants.stream_slots_max) {
        return error.LimitH2StreamsOutOfRange;
    }
    assert(stream_slots >= 1);
    assert(multiplexing_count >= 1);
    return stream_slots;
}

/// The HTTP/2 session pool (#275): a session per connection speaking it,
/// defaulting to `h2_connections_default` capped at conn slots — each
/// session is a connection's — where a listener speaks HTTP/2, and zero
/// otherwise. Running short is graceful: an `h2` offer falls back to
/// HTTP/1.1, an h2c preface is turned away, an `h2`-only listener sheds.
fn resolveH2Connections(
    requested: ?u32,
    conn_slots: u32,
    http2_listeners_count: u32,
) ValidationError!u32 {
    assert(conn_slots >= 1);
    if (http2_listeners_count == 0) {
        if (requested != null) return error.LimitH2ConnectionsWithoutHttp2;
        return 0;
    }
    const h2_connections = requested orelse @min(constants.h2_connections_default, conn_slots);
    if (h2_connections < 1) return error.LimitH2ConnectionsOutOfRange;
    if (h2_connections > conn_slots) return error.LimitH2ConnectionsOverConnSlots;
    assert(h2_connections <= conn_slots);
    return h2_connections;
}

/// The QUIC connection pool (#449), shaped like `resolveH2Connections`: a
/// connection per HTTP/3 client, defaulting to `quic_connections_default`
/// where a listener has a `quic` binding, and zero otherwise. Bounded by
/// the conn slots, and by the TLS engines too — a QUIC connection holds
/// one for its whole life, so a pool past the engines would admit
/// connections that could never finish a handshake. A binding implies
/// `tls` (`countListenerFeatures`), so the engine pool is never empty
/// here and the default never zero.
fn resolveQuicConnections(
    requested: ?u32,
    conn_slots: u32,
    tls_engines: u32,
    quic_listeners_count: u32,
) ValidationError!u32 {
    assert(conn_slots >= 1);
    assert(tls_engines <= conn_slots);
    if (quic_listeners_count == 0) {
        if (requested != null) return error.LimitQuicConnectionsWithoutQuic;
        return 0;
    }
    assert(tls_engines >= 1);
    const quic_connections = requested orelse
        @min(constants.quic_connections_default, conn_slots, tls_engines);
    if (quic_connections < 1 or quic_connections > constants.quic_connections_max) {
        return error.LimitQuicConnectionsOutOfRange;
    }
    if (quic_connections > conn_slots) return error.LimitQuicConnectionsOverConnSlots;
    if (quic_connections > tls_engines) return error.LimitQuicConnectionsOverTlsEngines;
    assert(quic_connections >= 1);
    assert(quic_connections <= tls_engines);
    return quic_connections;
}

/// The two head pools (§5), which exist only for an HTTP listener: the
/// downstream ring and the upstream pool. Their own group because both
/// are gated on the same `http_listeners_count` and each is bounded by a
/// different slot count above.
fn resolveHeadPools(
    requested: *const Options.Limits,
    conn_slots: u32,
    upstream_slots: u32,
    http_listeners_count: u32,
) ValidationError!struct { head_buffers: u32, upstream_head_buffers: u32 } {
    const head_buffers = try resolveHeadBuffers(
        requested.head_buffers,
        conn_slots,
        http_listeners_count,
    );
    const upstream_head_buffers = try resolveUpstreamHeadBuffers(
        requested.upstream_head_buffers,
        upstream_slots,
        http_listeners_count,
    );
    return .{
        .head_buffers = head_buffers,
        .upstream_head_buffers = upstream_head_buffers,
    };
}

/// The §5 relation every per-connection pool shares: none of them may
/// out-size the connections that draw on it. Stated once, after the
/// resolvers have each enforced their own half, because a pool past this
/// is not merely wasteful — the fd and ring budgets are derived from
/// `conn_slots` on the strength of it (`fdsRequired`, `inFlightOps`), so
/// a breach here is an under-provisioned ring rather than spare memory.
fn assertPoolsFitConnSlots(slots: SlotCounts, head_buffers: u32, feature_pools: FeaturePools) void {
    assert(slots.relay_buffers <= slots.conn_slots);
    assert(head_buffers <= slots.conn_slots);
    assert(feature_pools.tls_engines <= slots.conn_slots);
    assert(feature_pools.tunnels <= slots.conn_slots);
    assert(feature_pools.quic_connections <= slots.conn_slots);
}

/// The relay buffer's width against what the listeners ask of it — split
/// from `resolveLimits` for the length limit.
fn rejectRelayBufferShape(features: ListenerFeatures, relay_buffer_bytes: u32) ValidationError!void {
    assert(relay_buffer_bytes >= constants.relay_buffer_bytes_min);
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
    // §4's `transformOut` encrypts a whole relay chunk into one record,
    // and RFC 8446 §5.1 caps a record's plaintext at 2^14 — so on a
    // terminating listener a buffer past `tls_app_chunk_bytes` could only
    // produce a record no conforming peer may accept. The ceiling is
    // wider than that for the plaintext deployments that can use it
    // (`relay_buffer_bytes_max`), which makes this the paired refusal:
    // the shape is legal, just not with TLS on it. Refused at load for
    // the reason the SNI check above is — the alternative is a proxy that
    // serves small bodies and tears down large ones.
    if (features.tls >= 1 and relay_buffer_bytes > constants.tls_app_chunk_bytes) {
        return error.LimitRelayBufferOverTlsRecord;
    }
}

/// Resolve the effective pool sizes (§5, §8): the comptime constants are
/// the hard, budget-asserted ceilings — config may only shrink below
/// them, never grow past them, and never to zero. An unspecified
/// relay-buffer count derives from the effective conn slots (a buffer
/// beyond the slot count could never be acquired); a *specified* count
/// above them is a contradiction and fails loudly.
fn resolveLimits(
    requested: *const Options.Limits,
    listeners_count: u32,
    features: ListenerFeatures,
    access_log_on: bool,
    log_header_count: u32,
    health_probes: u32,
    origins: OriginDemand,
) ValidationError!Config.Limits {
    assert(listeners_count >= 1);
    assert(health_probes >= 1);
    assert(health_probes <= constants.health_probe_concurrency_max);
    // Bounds are `countListenerFeatures`'s postcondition, not re-checked
    // here — restating them would be two places to keep in step.
    const slots = try resolveSlotCounts(requested);
    const conn_slots = slots.conn_slots;
    const relay_buffers = slots.relay_buffers;
    const upstream_slots = slots.upstream_slots;
    const head_pools = try resolveHeadPools(
        requested,
        conn_slots,
        upstream_slots,
        features.http,
    );
    const head_buffer_bytes = try resolveHeadBufferBytes(requested.head_buffer_bytes);
    const relay_buffer_bytes = try resolveRelayBufferBytes(requested.relay_buffer_bytes);
    try rejectRelayBufferShape(features, relay_buffer_bytes);
    const feature_pools = try resolveFeaturePools(requested, conn_slots, features);
    const origin_pools = try resolveOriginLimits(requested, upstream_slots, feature_pools.tls_engines, origins);
    const cq_fill_eighths = try resolveCqFill(
        requested.cq_fill_eighths,
        conn_slots,
        feature_pools.stream_slots,
        listeners_count,
        health_probes,
        origin_pools.connections,
        features.quic,
    );
    // Zero exactly when the log is off, so the one number says both how
    // big the staging buffers are and whether there are any (§8). A
    // deployment that sized the buffers but never named a sink has asked
    // for something contradictory, and is told so rather than quietly
    // getting no log.
    const access_log_buffer_bytes = try resolveAccessLogBuffer(
        requested.access_log_buffer_bytes,
        access_log_on,
        log_header_count,
    );
    assertPoolsFitConnSlots(slots, head_pools.head_buffers, feature_pools);
    const consult_slots = requested.consult_slots orelse 0;
    if (consult_slots > upstream_slots) return error.LimitConsultSlotsOverUpstreamSlots;
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
        .h2_connections = feature_pools.h2_connections,
        .stream_slots = feature_pools.stream_slots,
        .quic_connections = feature_pools.quic_connections,
        .h2_origin_connections = origin_pools.connections,
        .h2_origin_streams = origin_pools.streams,
        .upstream_tls_sessions = origin_pools.upstream_tls_sessions,
        .cq_fill_eighths = cq_fill_eighths,
        .access_log_buffer_bytes = access_log_buffer_bytes,
        .consult_slots = consult_slots,
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

/// Unstated limits take the lean out-of-box sizes, not the compiled
/// ceilings (§5): a small footprint unless the operator opts up. Relay
/// buffers still follow conn slots when unstated (one buffer per L4
/// connection), capped at their own ceiling.
fn resolveSlotCounts(requested: *const Options.Limits) ValidationError!SlotCounts {
    const conn_slots = requested.conn_slots orelse constants.conn_slots_default;
    if (conn_slots < 1 or conn_slots > constants.conn_slots_max) {
        return error.LimitConnSlotsOutOfRange;
    }
    const relay_buffers = requested.relay_buffers orelse
        @min(constants.relay_buffers_max, conn_slots);
    if (relay_buffers < 1 or relay_buffers > constants.relay_buffers_max) {
        return error.LimitRelayBuffersOutOfRange;
    }
    if (relay_buffers > conn_slots) {
        return error.LimitRelayBuffersOverConnSlots;
    }
    const upstream_slots = requested.upstream_slots orelse constants.upstream_slots_default;
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

/// The HTTP/2 origin pools (§7), which exist exactly when some cluster
/// speaks `h2c`: connections, two per such endpoint unless sized, and the
/// streams that may hold an answer at once — one per upstream slot unless
/// sized, and never more, since every one of those exchanges holds a slot.
fn resolveOriginPools(
    requested: *const Options.Limits,
    upstream_slots: u32,
    h2c_endpoints: u32,
) ValidationError!struct { connections: u32, streams: u32 } {
    assert(upstream_slots >= 1);
    if (h2c_endpoints == 0) {
        if (requested.upstream_h2_connections != null) return error.LimitUpstreamH2ConnectionsWithoutHttp2;
        if (requested.upstream_h2_streams != null) return error.LimitUpstreamH2StreamsWithoutHttp2;
        return .{ .connections = 0, .streams = 0 };
    }
    const connections = requested.upstream_h2_connections orelse
        @min(2 * @as(u64, h2c_endpoints), constants.h2_origin_connections_max);
    if (connections < 1 or connections > constants.h2_origin_connections_max) {
        return error.LimitUpstreamH2ConnectionsOutOfRange;
    }
    const streams = requested.upstream_h2_streams orelse upstream_slots;
    if (streams < 1 or streams > constants.upstream_slots_max) return error.LimitUpstreamH2StreamsOutOfRange;
    if (streams > upstream_slots) return error.LimitUpstreamH2StreamsOverUpstreamSlots;
    assert(streams <= upstream_slots);
    return .{ .connections = @intCast(connections), .streams = streams };
}

/// The libcrypto heap is one reservation for every TLS session this
/// process holds (§4): the listeners' engines, and the origin connections
/// where an `h2` cluster reaches its origins over TLS (§7). Zero when no
/// cluster does. HTTPS origins' sessions are the third, and are sized
/// into what is left (`resolveUpstreamTls`).
fn rejectTlsSessionsOverHeap(tls_engines: u32, h2_tls_connections: u32) ValidationError!void {
    assert(tls_engines <= constants.tls_engines_max);
    if (tls_engines + h2_tls_connections > constants.tls_engines_max) return error.LimitUpstreamH2TlsOverEngines;
}

/// What the clusters ask of the origin pools (§7, #296), known once they
/// resolve: the HTTP/2 endpoints the connections are sized for, whether
/// those connections hold TLS sessions, and the HTTPS endpoints the TLS
/// sessions are.
const OriginDemand = struct {
    h2c_endpoints: u32,
    h2_origin_tls: bool,
    upstream_tls_endpoints: u32,
};

/// The origin pools a config's clusters draw on (§7, #296): the HTTP/2
/// connections and streams, and the HTTPS sessions sized into the heap
/// room they and the listeners' engines leave.
fn resolveOriginLimits(
    requested: *const Options.Limits,
    upstream_slots: u32,
    tls_engines: u32,
    origins: OriginDemand,
) ValidationError!struct { connections: u32, streams: u32, upstream_tls_sessions: u32 } {
    const pools = try resolveOriginPools(requested, upstream_slots, origins.h2c_endpoints);
    const h2_tls_connections = if (origins.h2_origin_tls) pools.connections else 0;
    const sessions = try resolveTlsSessions(
        requested,
        upstream_slots,
        tls_engines,
        h2_tls_connections,
        origins.upstream_tls_endpoints,
    );
    assert(sessions <= upstream_slots);
    return .{ .connections = pools.connections, .streams = pools.streams, .upstream_tls_sessions = sessions };
}

/// The libcrypto heap's three consumers, in order (§4, §7, #296): the
/// listeners' engines and the `h2` origins' connections must fit, and the
/// HTTPS origins' sessions are sized into what is left. Answers those.
fn resolveTlsSessions(
    requested: *const Options.Limits,
    upstream_slots: u32,
    tls_engines: u32,
    h2_tls_connections: u32,
    upstream_tls_endpoints: u32,
) ValidationError!u32 {
    try rejectTlsSessionsOverHeap(tls_engines, h2_tls_connections);
    assert(tls_engines + h2_tls_connections <= constants.tls_engines_max);
    const heap_room = constants.tls_engines_max - tls_engines - h2_tls_connections;
    return resolveUpstreamTls(requested, upstream_slots, upstream_tls_endpoints, heap_room);
}

/// The TLS sessions HTTPS origins draw on (#296): one per upstream
/// connection to an `http1` cluster with `tls`, so within the upstream
/// slots, and within what the libcrypto heap has left after the
/// listeners' engines and the `h2` origins' connections (`heap_room`).
/// Zero exactly when no such cluster exists.
fn resolveUpstreamTls(
    requested: *const Options.Limits,
    upstream_slots: u32,
    tls_endpoints: u32,
    heap_room: u32,
) ValidationError!u32 {
    assert(upstream_slots >= 1);
    assert(heap_room <= constants.tls_engines_max);
    if (tls_endpoints == 0) {
        if (requested.upstream_tls_sessions != null) return error.LimitUpstreamTlsSessionsWithoutTls;
        return 0;
    }
    if (heap_room == 0) return error.LimitUpstreamTlsOverEngines;
    const default: u64 = @min(
        @as(u64, tls_endpoints) * constants.upstream_tls_sessions_per_endpoint,
        upstream_slots,
        heap_room,
    );
    const sessions = requested.upstream_tls_sessions orelse default;
    if (sessions < 1 or sessions > constants.upstream_tls_sessions_max) {
        return error.LimitUpstreamTlsSessionsOutOfRange;
    }
    if (sessions > upstream_slots) return error.LimitUpstreamTlsSessionsOverUpstreamSlots;
    if (sessions > heap_room) return error.LimitUpstreamTlsOverEngines;
    assert(sessions >= 1);
    return @intCast(sessions);
}

/// How many endpoints the `h2c` clusters name between them.
fn h2cEndpointsOf(clusters: []const Config.Cluster) u32 {
    var count: u32 = 0;
    for (clusters) |*cluster| {
        if (cluster.protocol.http2()) count += @intCast(cluster.endpoints.len);
    }
    return count;
}

/// Whether an `h2` cluster exists (§7): its origin connections — every
/// HTTP/2 one, since they are one pool — then hold TLS clients.
pub fn h2OriginTls(clusters: []const Config.Cluster) bool {
    for (clusters) |*cluster| {
        if (cluster.protocol == .h2) return true;
    }
    return false;
}

/// How many endpoints the HTTPS clusters — `http1` with `tls` — name
/// between them (#296): what the TLS session pool is sized for.
pub fn upstreamTlsEndpointsOf(clusters: []const Config.Cluster) u32 {
    var count: u32 = 0;
    for (clusters) |*cluster| {
        if (cluster.protocol == .http1 and cluster.tls != null) count += @intCast(cluster.endpoints.len);
    }
    return count;
}

/// Whether any cluster reaches its origins over TLS (§7, #296): the
/// libcrypto heap is then installed, whatever the listeners do.
pub fn originTls(clusters: []const Config.Cluster) bool {
    for (clusters) |*cluster| {
        if (cluster.tls != null) return true;
    }
    return false;
}

/// The CQ fill is the one limit an operator tightens for headroom, not a
/// pool shrink (§8): a smaller fill demands a deeper ring for the same
/// conn slots. Range-check first, then reject a fill that — with these
/// conn and stream slots and listeners — would need a completion queue
/// past the compiled ring, so the budget's `completionQueueDepthFor` never
/// clamps.
fn resolveCqFill(
    requested: ?u32,
    conn_slots: u32,
    stream_slots: u32,
    listeners_count: u32,
    health_probes: u32,
    origin_connections: u32,
    quic_endpoints: u32,
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
        stream_slots,
        listeners_count,
        health_probes,
        origin_connections,
        quic_endpoints,
        cq_fill_eighths,
    )) {
        return error.LimitConnSlotsOverCqFill;
    }
    return cq_fill_eighths;
}

/// The §4 engine pool follows conn slots when omitted, capped at
/// `tls_engines_max` — an engine is ~92 KiB, so unlike a head buffer the
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
    stated: []const Options.Cluster,
) ResolveError![]const Config.Cluster {
    if (stated.len < constants.clusters_min) {
        return error.ClustersEmpty;
    }
    // No upper bound: a cluster costs an arena `Config.Cluster` and a row
    // in the §7 endpoint tables, both sized from this count (§5), so how
    // many is the operator's call. `u16` is the one hard edge left — the
    // index type the endpoint key and every `cluster_index` field use.
    if (stated.len > std.math.maxInt(u16)) {
        return error.ClustersOverLimit;
    }
    const clusters = try arena.alloc(Config.Cluster, stated.len);
    try rejectDuplicateClusterNames(arena, stated);
    for (stated, clusters) |*cluster_stated, *cluster| {
        cluster.* = try resolveCluster(arena, cluster_stated);
        try rejectClusterProtocolShape(cluster);
    }
    assert(clusters.len == stated.len);
    assert(clusters.len >= constants.clusters_min);
    return clusters;
}

/// One cluster's options, judged and compiled (§7). Every refusal here
/// is one options written in code can earn as well as a file; the
/// spellings only JSON can get wrong are its front-end's (`clusterOf`).
fn resolveCluster(
    arena: std.mem.Allocator,
    stated: *const Options.Cluster,
) ResolveError!Config.Cluster {
    if (stated.name.len == 0) {
        return error.ClusterNameEmpty;
    }
    if (stated.name.len > constants.cluster_name_bytes_max) {
        return error.ClusterNameTooLong;
    }
    const picked = try resolvePick(&stated.pick);
    const endpoints = try resolveEndpoints(arena, stated.endpoints);
    const priorities = try resolvePriorities(arena, stated.endpoints);
    var cluster: Config.Cluster = .{
        .name = stated.name,
        .endpoints = endpoints.addresses,
        .weights = endpoints.weights,
        .priorities = priorities,
        .pick = picked.pick,
        .check = try resolveCheck(stated.check),
        .passive_ejection = try resolvePassiveEjection(stated.passive_ejection),
        .panic_threshold_percent = try resolvePanicThreshold(stated),
        .hash_key = picked.hash_key,
        .max_inflight = try resolveMaxInflight(stated.max_inflight),
        .max_total_inflight = try resolveMaxTotalInflight(stated.max_total_inflight),
        .slow_start_ms = try resolveSlowStart(stated),
        .retries = try resolveRetries(stated.retries.count),
        .retry_budget = try resolveRetryBudget(stated.retries),
        .proxy_protocol_send = stated.proxy_protocol_send,
        .protocol = stated.protocol,
        .tls = try resolveClusterTls(arena, stated.tls),
    };
    assert(cluster.endpoints.len == stated.endpoints.len);
    if (stated.endpoint_slots) |capacity| {
        try reserveSlots(arena, &cluster, capacity);
    }
    assert(cluster.name.len >= 1);
    return cluster;
}

/// A cluster's room for endpoints added while serving (#428): every array
/// at the declared capacity, the stated endpoints live in its first slots
/// and the rest free — weight 0, a placeholder address no pick reaches.
fn reserveSlots(arena: std.mem.Allocator, cluster: *Config.Cluster, capacity: u16) ResolveError!void {
    const stated = cluster.endpoints.len;
    assert(stated >= 1);
    if (capacity < stated) return error.EndpointSlotsOutOfRange;
    if (capacity > @as(u32, constants.endpoint_index_max) + 1) return error.EndpointSlotsOutOfRange;
    assert(capacity >= stated);
    const slots = try arena.create(Config.Slots);
    slots.* = .{
        .addresses = try arena.alloc(io_module.Address, capacity),
        .weights = try arena.alloc(u16, capacity),
        .priorities = try arena.alloc(u8, capacity),
        .states = try arena.alloc(Config.EndpointState, capacity),
    };
    @memcpy(slots.addresses[0..stated], cluster.endpoints);
    @memset(slots.addresses[stated..], free_slot_address);
    for (slots.weights[0..stated], 0..) |*weight, index| weight.* = if (cluster.weights) |weights| weights[index] else 1;
    @memset(slots.weights[stated..], 0);
    for (slots.priorities[0..stated], 0..) |*priority, index| {
        priority.* = if (cluster.priorities) |priorities| priorities[index] else 0;
    }
    @memset(slots.priorities[stated..], 0);
    @memset(slots.states[0..stated], .live);
    @memset(slots.states[stated..], .free);
    cluster.endpoints = slots.addresses;
    cluster.weights = slots.weights;
    cluster.priorities = slots.priorities;
    cluster.slots = slots;
    assert(cluster.endpoints.len == capacity);
    assert(cluster.weights.?.len == capacity);
    assert(cluster.priorities.?.len == capacity);
}

/// What a free slot holds (#428): an address nothing dials, since a free
/// slot's weight keeps every pick off it.
pub const free_slot_address: io_module.Address = .{ .ip = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } } };

/// Duplicate names in O(n log n), by sorting an index permutation and
/// comparing neighbours. It was a nested scan over the entries, which
/// the 16-cluster ceiling kept to ~120 compares; with the ceiling gone
/// that same scan would cost ~2.1e9 string compares on a config at the
/// index type's edge — minutes of startup for a config whose memory
/// fits easily. Which name is reported first changes, and nothing
/// reads it: the error carries no payload.
fn rejectDuplicateClusterNames(
    arena: std.mem.Allocator,
    stated: []const Options.Cluster,
) ResolveError!void {
    assert(stated.len >= 1);
    assert(stated.len <= std.math.maxInt(u16));
    const order = try arena.alloc(u16, stated.len);
    for (order, 0..) |*slot, index| slot.* = @intCast(index);
    const ByName = struct {
        clusters: []const Options.Cluster,
        fn lessThan(ctx: @This(), a: u16, b: u16) bool {
            return std.mem.lessThan(u8, ctx.clusters[a].name, ctx.clusters[b].name);
        }
    };
    std.mem.sort(u16, order, ByName{ .clusters = stated }, ByName.lessThan);
    for (order[1..], order[0 .. order.len - 1]) |current, previous| {
        if (std.mem.eql(u8, stated[current].name, stated[previous].name)) {
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
    address: io_module.Address,
) ResolveError!io_module.Address {
    const path = switch (address) {
        .ip => return address,
        .unix => |path| path,
    };
    const resolved: io_module.Address = .{ .unix = resolveUnixPath(arena, path) catch |err| switch (err) {
        error.Relative => return error.EndpointUnixPathRelative,
        error.Invalid => return error.EndpointUnixPathInvalid,
        error.OutOfMemory => return error.OutOfMemory,
    } };
    assert(resolved.unix.len == path.len);
    assert(resolved.unix[0] == '/');
    return resolved;
}

/// A `unix:` address's path, validated and arena-duped. The rules argued
/// at `resolveEndpointAddress`, applied once for both fields that take
/// the grammar — an endpoint and a listener's `bind` — so the two cannot
/// come to disagree about what a socket path is.
fn resolveUnixPath(
    arena: std.mem.Allocator,
    path: []const u8,
) error{ Invalid, Relative, OutOfMemory }![]const u8 {
    if (path.len == 0 or path.len > io_module.Address.unix_path_bytes_max) {
        return error.Invalid;
    }
    if (path[0] != '/') {
        return error.Relative;
    }
    if (!io_module.Address.pathIsRenderable(path)) {
        return error.Invalid;
    }
    // Duped so the address outlives whatever the options were written
    // in — a parsed JSON document, or a caller's buffer.
    return try arena.dupe(u8, path);
}

/// The permission bits a `unix:` bind asks for its socket file (#303).
/// The octal spelling is the JSON front-end's (`bindModeOf`); what any
/// mode must satisfy is judged here.
fn resolveBindMode(
    mode: ?io_module.FileMode,
    bind_address: io_module.Address,
) ResolveError!?io_module.FileMode {
    const stated = mode orelse return null;
    // An IP bind creates no file, so a mode on one describes nothing.
    if (bind_address != .unix) {
        return error.ListenerModeWithoutUnixBind;
    }
    // setuid, setgid and sticky mean nothing on a socket and everything
    // on the file it is confused with — refused rather than passed
    // through to a chmod nobody meant to write.
    if (stated.bits & ~@as(u16, 0o777) != 0) {
        return error.ListenerModeInvalid;
    }
    assert(stated.bits <= 0o777);
    assert(bind_address == .unix);
    return stated;
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
) ResolveError!void {
    if (listener.forwarded != null) {
        return error.ListenerUnixBindForwarded;
    }
    for (listener.request_filters) |rule| {
        if (rule.match.clients.len >= 1) {
            return error.ListenerUnixBindClientMatch;
        }
    }
    for (listener.routes) |route| {
        // A handler route reaches no cluster (#434).
        if (route.handler != null) continue;
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
) ResolveError!void {
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
    address: io_module.Address,
) ResolveError!io_module.Address {
    const path = switch (address) {
        .ip => return address,
        .unix => |path| path,
    };
    const resolved: io_module.Address = .{ .unix = resolveUnixPath(arena, path) catch |err| switch (err) {
        error.Relative => return error.ListenerBindUnixPathRelative,
        error.Invalid => return error.ListenerBindUnixPathInvalid,
        error.OutOfMemory => return error.OutOfMemory,
    } };
    assert(resolved.unix.len == path.len);
    assert(resolved.unix[0] == '/');
    return resolved;
}

/// A cluster's #396 tiers, materialized only where some endpoint is not a
/// primary — the `weights` rule, so an untiered cluster carries nothing.
fn resolvePriorities(
    arena: std.mem.Allocator,
    endpoints: []const Options.Cluster.Endpoint,
) ResolveError!?[]const u8 {
    assert(endpoints.len >= 1);
    var tiered = false;
    for (endpoints) |entry| {
        if (entry.priority > constants.endpoint_priority_max) return error.EndpointPriorityOverLimit;
        tiered = tiered or entry.priority != 0;
    }
    if (!tiered) return null;
    // Tiers are relative: the lowest one a cluster names is its primary,
    // so `{"priority": 1}` on every endpoint is a cluster of primaries,
    // and a pick reported `standby` always had a lower tier to pass over.
    var lowest: u8 = constants.endpoint_priority_max;
    for (endpoints) |entry| lowest = @min(lowest, entry.priority);
    var distinct = false;
    for (endpoints) |entry| distinct = distinct or entry.priority != lowest;
    if (!distinct) return null;
    const priorities = try arena.alloc(u8, endpoints.len);
    for (endpoints, priorities) |entry, *priority| priority.* = entry.priority - lowest;
    assert(priorities.len == endpoints.len);
    assert(std.mem.indexOfScalar(u8, priorities, 0) != null);
    return priorities;
}

fn resolveEndpoints(
    arena: std.mem.Allocator,
    endpoints: []const Options.Cluster.Endpoint,
) ResolveError!ResolvedEndpoints {
    if (endpoints.len == 0) {
        return error.EndpointsEmpty;
    }
    // No policy bound: endpoints cost an arena address each and a column
    // in the §7 endpoint tables, both sized from this count (§5). What is
    // left is the index type's own edge — `n` endpoints produce indices
    // `0..n-1`, and the largest of those must stay inside
    // `endpoint_index_max`, which `Conn` asserts sits below its
    // no-endpoint sentinel.
    if (endpoints.len > @as(usize, constants.endpoint_index_max) + 1) {
        return error.EndpointsOverLimit;
    }

    const addresses = try arena.alloc(io_module.Address, endpoints.len);
    var weighted = false;
    var weight_sum: u64 = 0;
    for (endpoints, addresses) |entry, *address| {
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
    assert(addresses.len == endpoints.len);
    if (!weighted) {
        return .{ .addresses = addresses, .weights = null };
    }
    const weights = try arena.alloc(u16, endpoints.len);
    for (endpoints, weights) |entry, *weight| {
        assert(entry.weight <= constants.endpoint_weight_max);
        weight.* = entry.weight;
    }
    assert(weights.len == addresses.len);
    return .{ .addresses = addresses, .weights = weights };
}

fn resolveListeners(
    arena: std.mem.Allocator,
    stated: []const Options.Listener,
    clusters: []const Config.Cluster,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
) ResolveError![]const Config.Listener {
    assert(clusters.len >= 1);
    // Both refused by `resolve` before anything was sized from the count.
    // No policy ceiling: a listener costs two ring ops and one fd, and
    // both are checked against this config's own budget — `cqFillFits`
    // for the ring (`LimitConnSlotsOverCqFill`), `ensureFdBudget` for the
    // fds. What is left is the `u16` the listener index is stored in.
    assert(stated.len >= 1);
    assert(stated.len <= std.math.maxInt(u16));

    const listeners = try arena.alloc(Config.Listener, stated.len);
    for (stated, listeners) |*listener_stated, *listener| {
        listener.* = try resolveListener(
            arena,
            listener_stated,
            clusters,
            head_buffer_bytes,
            bodies,
        );
    }
    if (tlsCertificateCount(listeners) > constants.tls_certificates_max) {
        return error.ListenerTlsCertificatesOverLimit;
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
    try rejectDuplicateQuicBinds(arena, listeners);

    assert(listeners.len == stated.len);
    assert(order.len == listeners.len);
    return listeners;
}

/// Duplicate QUIC binds (#449), sorted for the reason the TCP binds above
/// are. A set of their own: a UDP port is not a TCP one, so a binding on
/// its own listener's TCP address — the usual shape — is no duplicate.
/// Two bindings on one UDP address are, and are refused at load rather
/// than left to fail at bind, or to share datagrams between two
/// listeners' routes if the kernel let both sockets have the port.
fn rejectDuplicateQuicBinds(
    arena: std.mem.Allocator,
    listeners: []const Config.Listener,
) ResolveError!void {
    assert(listeners.len >= 1);
    assert(listeners.len <= std.math.maxInt(u16));
    var bound: u16 = 0;
    for (listeners) |*listener| bound += @intFromBool(listener.quic != null);
    if (bound <= 1) return;
    const order = try arena.alloc(u16, bound);
    var next: u16 = 0;
    for (listeners, 0..) |*listener, index| {
        if (listener.quic == null) continue;
        order[next] = @intCast(index);
        next += 1;
    }
    assert(next == bound);
    const ByQuicBind = struct {
        listeners: []const Config.Listener,
        fn lessThan(ctx: @This(), a: u16, b: u16) bool {
            return bindOrder(ctx.listeners[a].quic.?.bind_address) <
                bindOrder(ctx.listeners[b].quic.?.bind_address);
        }
    };
    std.mem.sort(u16, order, ByQuicBind{ .listeners = listeners }, ByQuicBind.lessThan);
    for (order[1..], order[0 .. order.len - 1]) |current, previous| {
        const current_bind = &listeners[current].quic.?.bind_address;
        if (current_bind.eql(&listeners[previous].quic.?.bind_address)) {
            return error.ListenerQuicBindDuplicate;
        }
    }
}

/// One listener's whole resolution — split from `resolveListeners`
/// when #159 threaded the bodies table through it and the loop body
/// pushed that function past the length limit. The duplicate-bind pass
/// stays with the caller: it is a property of the set, not of one
/// entry.
fn resolveListener(
    arena: std.mem.Allocator,
    stated: *const Options.Listener,
    clusters: []const Config.Cluster,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
) ResolveError!Config.Listener {
    assert(clusters.len >= 1);
    assert(head_buffer_bytes >= 1);
    const bind_address = try resolveBindAddress(arena, stated.bind);
    const tls = try resolveTls(arena, &stated.tls, stated.protocol);
    var listener: Config.Listener = switch (stated.protocol) {
        .http => |*http| try resolveHttpListener(
            arena,
            bind_address,
            tls,
            http,
            clusters,
            head_buffer_bytes,
            bodies,
        ),
        .l4 => |*l4| try resolveL4Listener(arena, bind_address, tls, l4, clusters),
    };
    listener.bind_mode = try resolveBindMode(stated.mode, bind_address);
    listener.connection_policies = stated.connection_policies;
    if (bind_address == .unix) {
        try rejectUnixClientAddressUsers(&listener, clusters);
    }
    if (listener.protocol == .http) {
        try rejectHttpClusterSend(listener.routes, clusters);
        try rejectUpgradeClusters(&listener, clusters);
    }
    if (listener.tls != null) {
        try rejectTlsClusterSend(listener.routes, clusters);
    }
    assert(listener.routes.len >= 1);
    assert(listener.protocol == stated.protocol);
    return listener;
}

/// An `http` listener: the routing table, both filter tables, and the
/// three §7 policies only a parsed request can mean anything to.
fn resolveHttpListener(
    arena: std.mem.Allocator,
    bind_address: io_module.Address,
    tls: ?Config.Listener.Tls,
    http: *const Options.Listener.Http,
    clusters: []const Config.Cluster,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
) ResolveError!Config.Listener {
    assert(clusters.len >= 1);
    assert(head_buffer_bytes >= 1);
    return .{
        .bind_address = bind_address,
        .bind_mode = null,
        .routes = try resolveRoutes(arena, &http.target, clusters, head_buffer_bytes),
        .request_filters = try resolveRequestFilters(arena, http.request_filters, head_buffer_bytes, bodies),
        .request_policies = http.request_policies,
        .response_policies = http.response_policies,
        .response_filters = try resolveListenerResponseFilters(arena, http),
        .protocol = .http,
        .forwarded = http.forwarded,
        .proxy_protocol = null,
        .tls = tls,
        .upgrades = http.upgrades,
        .max_body_bytes = try resolveMaxBodyBytes(http.max_body_bytes),
        .keepalive_requests = http.keepalive_requests,
        .proxy_status = http.proxy_status,
        .h2c = try resolveH2c(http.h2c, tls),
        .quic = try resolveQuic(&http.quic, &tls),
    };
}

/// h2c is HTTP/2 *without* TLS (RFC 9113 §3.3): a terminating listener
/// negotiates HTTP/2 by ALPN instead, and never sniffs a preface.
fn resolveH2c(h2c: bool, tls: ?Config.Listener.Tls) ValidationError!bool {
    // `countListenerFeatures` refused the pair before any pool was sized,
    // so the order of the two checks cannot decide which error is shown.
    if (h2c and tls != null) return error.ListenerH2cOnTls;
    assert(!h2c or tls == null);
    return h2c;
}

/// A listener's QUIC binding (#449): an IP and port, and a max-age within
/// its ceiling. QUIC is TLS 1.3 by construction, so a binding needs the
/// listener's certificates; `countListenerFeatures` refused one without
/// them before any pool was sized, which makes the check here the
/// postcondition restated, as `resolveH2c`'s is.
fn resolveQuic(
    quic: *const ?Options.Listener.Quic,
    tls: *const ?Config.Listener.Tls,
) ValidationError!?Config.Listener.Quic {
    const stated = if (quic.*) |*stated| stated else return null;
    if (tls.* == null) return error.ListenerQuicWithoutTls;
    // A datagram socket on a path would be a different transport, and one
    // no QUIC client dials.
    const bind_address = switch (stated.bind) {
        .ip => |ip| ip,
        .unix => return error.ListenerQuicBindNotIp,
    };
    if (stated.alt_svc_max_age_s > constants.alt_svc_max_age_s_max) {
        return error.ListenerQuicAltSvcMaxAgeOutOfRange;
    }
    assert(tls.* != null);
    assert(stated.alt_svc_max_age_s <= constants.alt_svc_max_age_s_max);
    return .{
        .bind_address = bind_address,
        .alt_svc_max_age_s = stated.alt_svc_max_age_s,
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
    l4: *const Options.Listener.L4,
    clusters: []const Config.Cluster,
) ResolveError!Config.Listener {
    assert(clusters.len >= 1);
    const has_routes = l4.target == .routes;
    // Routing by name means reading the client's ClientHello and relaying
    // it on. A listener that *terminates* consumed that hello during its
    // own handshake, so there is nothing left for the peek to read —
    // the two describe different proxies and the config states one (§6).
    if (has_routes and tls != null) {
        return error.ListenerTlsWithSniRoutes;
    }
    const sni_routes: []const sni_router.Route = switch (l4.target) {
        .cluster => &.{},
        .routes => |routes| try resolveSniRoutes(arena, routes, clusters),
    };
    const routes = try resolveL4Route(arena, admittedCluster(&l4.target, sni_routes), clusters);
    assert(routes.len == 1);
    const listener: Config.Listener = .{
        .bind_address = bind_address,
        // Filled by `resolveListener`, as on the http arm.
        .bind_mode = null,
        .routes = routes,
        .sni_routes = sni_routes,
        .protocol = .l4,
        .proxy_protocol = l4.proxy_protocol,
        .tls = tls,
        // Stated rather than defaulted: an l4 relay never measures a
        // request, so its cap is the absence of one — and the field's
        // own default is the http default, which would read here as a
        // policy this listener does not have.
        .max_body_bytes = 0,
    };
    assert((listener.sni_routes.len >= 1) == has_routes);
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
    target: *const Options.Listener.L4Target,
    sni_routes: []const sni_router.Route,
) []const u8 {
    switch (target.*) {
        .cluster => |name| {
            assert(sni_routes.len == 0);
            return name;
        },
        .routes => |routes| {
            assert(sni_routes.len >= 1);
            assert(routes.len == sni_routes.len);
            for (routes) |route| {
                if (route.sni == null) return route.cluster;
            }
            return routes[0].cluster;
        },
    }
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
    stated: []const Options.Listener.SniRoute,
    clusters: []const Config.Cluster,
) ResolveError![]const sni_router.Route {
    assert(clusters.len >= 1);
    if (stated.len == 0) {
        return error.RoutesEmpty;
    }
    const routes = try arena.alloc(sni_router.Route, stated.len);
    for (stated, 0..) |route_stated, index| {
        const name = if (route_stated.sni) |raw| try validateSniName(raw) else null;
        for (stated[0..index]) |previous| {
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
            .cluster_index = try l4ClusterIndexOf(clusters, route_stated.cluster),
            .connection_policies = route_stated.connection_policies,
        };
    }
    std.mem.sort(sni_router.Route, routes, {}, sniRouteMoreSpecific);
    assert(routes.len == stated.len);
    assert(routes.len >= 1);
    return routes;
}

/// Where a route sends: its cluster, or — on a handler route (#434),
/// which names none — 0, which nothing serving the route reads. Exactly
/// one of the two is stated.
fn routeClusterIndex(clusters: []const Config.Cluster, stated: *const Options.Listener.Route) ResolveError!u16 {
    assert(clusters.len >= 1);
    const names_cluster = stated.cluster.len != 0;
    if (names_cluster == (stated.handler != null)) return error.RouteTargetInvalid;
    if (stated.handler != null) return 0;
    return clusterIndexOf(clusters, stated.cluster);
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
fn validateSniName(raw: []const u8) ResolveError![]const u8 {
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
/// Every rule about what an l4 relay can reach lives here, because it has
/// to hold for *every* cluster such a listener can reach, not just the
/// one it admits under. An SNI table (#298) makes that a real
/// distinction: a named route can reach a cluster the admitted route
/// never names, and `routes` holds only the admitted one.
///
/// - `HashKey`'s rule: `header` and `cookie` read the parsed request, and
///   a request-keyed hash would be a pick the relay has no head to
///   compute.
/// - §7's protocol rule (#296): the relay forwards the client's bytes, so
///   an HTTP/2 origin would be sent whatever the client wrote, and an
///   HTTPS one's `tls` block — the name and CA this proxy verifies
///   against — would never be used.
fn l4ClusterIndexOf(
    clusters: []const Config.Cluster,
    cluster_name: []const u8,
) ResolveError!u16 {
    assert(clusters.len >= 1);
    const cluster_index = try clusterIndexOf(clusters, cluster_name);
    assert(cluster_index < clusters.len);
    const cluster = &clusters[cluster_index];
    switch (cluster.hash_key) {
        .source_ip => {},
        .header, .cookie => return error.ListenerL4RequestKeyedHash,
    }
    if (cluster.protocol.http2()) return error.ClusterH2cOnL4Listener;
    if (cluster.tls != null) return error.ClusterTlsOnL4Listener;
    return cluster_index;
}

/// An `l4` listener's one route: the whole table, because there is no
/// path to match on and therefore nothing to choose between.
///
/// The l4 checks (`l4ClusterIndexOf`) run here rather than beside the
/// other cluster validations because they are properties of *this
/// pairing*, not of the cluster: a request-derived hash key reads the
/// parsed head (#178), and an HTTP/2 or HTTPS origin needs a protocol
/// this proxy speaks, where an l4 listener parses and speaks none.
/// Reachability rather than exclusivity, like an http route to a
/// PROXY-sending cluster — the same cluster stays valid beside any http
/// listener.
fn resolveL4Route(
    arena: std.mem.Allocator,
    cluster_name: []const u8,
    clusters: []const Config.Cluster,
) ResolveError![]const router.Route {
    assert(clusters.len >= 1);
    const cluster_index = try l4ClusterIndexOf(clusters, cluster_name);
    assert(cluster_index < clusters.len);
    const routes = try arena.alloc(router.Route, 1);
    routes[0] = .{ .prefix = "/", .cluster_index = cluster_index };
    return routes;
}

/// Compile a listener's §7 filter rules into immutable arena tables.
/// Reachable only from an `http` body, so there is no protocol to check:
/// an l4 listener has no field to put these in (#305). None is none.
/// Match keys are validated canonical so a filter and the router agree
/// byte-for-byte, and each action is validated at load, so the request-
/// time interpreter is bounded loops over trusted data.
fn resolveRequestFilters(
    arena: std.mem.Allocator,
    stated: []const Options.Listener.Filter,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
) ResolveError![]const filter.Rule {
    if (stated.len == 0) {
        return &.{};
    }
    const rules = try arena.alloc(filter.Rule, stated.len);
    var header_edits: u32 = 0;
    for (stated, rules) |*rule_stated, *rule| {
        rule.* = .{
            .match = try resolveMatch(arena, &rule_stated.match, head_buffer_bytes),
            .actions = try resolveActions(arena, rule_stated.actions, head_buffer_bytes, bodies),
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
    assert(rules.len == stated.len);
    return rules;
}

/// The number of header-edit actions (set/add/remove) in a rule — the
/// reject and rewrite actions contribute no render-time header edit.
/// An `allow` contributes none either, and only ever *shortens* a
/// request's walk (#331), so the whole-table sum this feeds stays an
/// upper bound on what one render can materialize.
fn countHeaderEdits(actions: []const filter.Action) u32 {
    // Reached only through `resolveActions`, which rejects an empty
    // action list — so the caps this function once asserted against are
    // gone, but the shape they implied still holds.
    assert(actions.len >= 1);
    var count: u32 = 0;
    for (actions) |action| {
        switch (action) {
            .header_set, .header_add, .header_remove => count += 1,
            .reject, .redirect, .respond, .allow, .rewrite_prefix => {},
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
    stated: []const Options.Listener.ResponseFilter,
) ResolveError![]const filter.ResponseRule {
    if (stated.len == 0) {
        return &.{};
    }
    const rules = try arena.alloc(filter.ResponseRule, stated.len);
    var header_edits: u32 = 0;
    for (stated, rules) |*rule_stated, *rule| {
        rule.* = .{
            .match = try resolveResponseMatch(arena, &rule_stated.match),
            .edits = try resolveResponseEdits(arena, rule_stated.actions),
        };
        header_edits += @intCast(rule.edits.len);
    }
    if (header_edits > constants.header_edits_max) {
        return error.ResponseFilterHeaderEditsOverLimit;
    }
    assert(header_edits <= constants.header_edits_max);
    assert(rules.len == stated.len);
    return rules;
}

/// A listener's response rules (#175) and, on one whose QUIC binding names
/// its port and an advertisement age, the rule that advertises it (#449):
/// `Alt-Svc: h3=":<port>"; ma=<age>` on every answer relayed from an origin
/// — over TCP and HTTP/3 alike — RFC 7838's way of telling a client the
/// same origin speaks HTTP/3. Set rather than added: an origin's own
/// Alt-Svc names its alternatives, not this proxy's. After the operator's
/// rules, though a response policy's edit composes after every rule. It is
/// one of the listener's response header edits, held to the same cap. A
/// binding on port zero is given its port only when it binds, so it
/// advertises none — and the port advertised is the one bound, which a
/// port mapped in front of the proxy is not.
fn resolveListenerResponseFilters(
    arena: std.mem.Allocator,
    http: *const Options.Listener.Http,
) ResolveError![]const filter.ResponseRule {
    const stated = try resolveResponseFilters(arena, http.response_filters);
    const quic = http.quic orelse return stated;
    if (quic.alt_svc_max_age_s == 0) return stated;
    const port = switch (quic.bind) {
        .ip => |ip| ip.getPort(),
        .unix => return stated, // `resolveQuic` refuses it, by name.
    };
    if (port == 0) return stated;
    var edits_total: u32 = 0;
    for (stated) |*rule| edits_total += @intCast(rule.edits.len);
    assert(edits_total <= constants.header_edits_max); // `resolveResponseFilters` held it.
    if (edits_total + 1 > constants.header_edits_max) return error.ListenerQuicAltSvcOverEditLimit;
    assert(edits_total + 1 <= constants.header_edits_max);
    const value = try std.fmt.allocPrint(arena, "h3=\":{d}\"; ma={d}", .{ port, quic.alt_svc_max_age_s });
    const edits = try arena.alloc(filter.AppliedHeaderEdit, 1);
    edits[0] = .{ .kind = .set, .name = alt_svc_name, .value = value };
    const rules = try arena.alloc(filter.ResponseRule, stated.len + 1);
    @memcpy(rules[0..stated.len], stated);
    rules[stated.len] = .{ .match = .{}, .edits = edits };
    assert(rules[stated.len].edits.len == 1);
    return rules;
}

/// RFC 7838 §3's field.
pub const alt_svc_name = "Alt-Svc";

fn resolveResponseMatch(
    arena: std.mem.Allocator,
    match: *const Options.Listener.ResponseMatch,
) ResolveError!filter.ResponseMatch {
    var resolved: filter.ResponseMatch = .{};
    for (match.statuses) |status| {
        // The parser only ever produces 100..599 (§7), so a value outside
        // it is a rule that can never fire — a typo, told at load rather
        // than left silently inert.
        if (status < 100 or status > 599) {
            return error.ResponseFilterStatusInvalid;
        }
    }
    resolved.statuses = match.statuses;
    if (match.status_class) |class| {
        resolved.status_class = @backingInt(class);
        // The digit contract `responseMatches` asserts on its side of the
        // seam, proven where it is produced.
        assert(resolved.status_class.? >= 1);
        assert(resolved.status_class.? <= 5);
    }
    resolved.headers = try resolveHeaderMatches(arena, match.headers);
    return resolved;
}

/// Resolve a response rule's actions: the request side's three header
/// verbs, which are all a response can be given — there is no reject to
/// interleave on the way out. The other arms are not a shape the options
/// can state; JSON's spelling of one is its front-end's refusal.
fn resolveResponseEdits(
    arena: std.mem.Allocator,
    stated: []const Options.Listener.ResponseAction,
) ResolveError![]const filter.AppliedHeaderEdit {
    if (stated.len == 0) {
        return error.FilterActionsEmpty;
    }
    assert(stated.len >= 1); // Past the empty guard.
    const edits = try arena.alloc(filter.AppliedHeaderEdit, stated.len);
    for (stated, edits) |*action, *edit| {
        edit.* = try resolveResponseEdit(action);
    }
    assert(edits.len == stated.len);
    return edits;
}

fn resolveResponseEdit(action: *const Options.Listener.ResponseAction) ResolveError!filter.AppliedHeaderEdit {
    const edit: filter.AppliedHeaderEdit = switch (action.*) {
        .header_set => |*stated| blk: {
            const resolved = try resolveHeaderEdit(stated);
            break :blk .{ .kind = .set, .name = resolved.name, .value = resolved.value };
        },
        .header_add => |*stated| blk: {
            const resolved = try resolveHeaderEdit(stated);
            break :blk .{ .kind = .add, .name = resolved.name, .value = resolved.value };
        },
        .header_remove => |name| blk: {
            try validateEditableHeaderName(name);
            break :blk .{ .kind = .remove, .name = name, .value = "" };
        },
    };
    assert(edit.name.len >= 1);
    assert(edit.kind != .remove or edit.value.len == 0);
    return edit;
}

fn resolveMatch(
    arena: std.mem.Allocator,
    match: *const Options.Listener.Match,
    head_buffer_bytes: u32,
) ResolveError!filter.Match {
    var resolved: filter.Match = .{};
    if (match.host) |host| {
        resolved.host = try validateRouteHost(host);
    }
    if (match.path_prefix) |prefix| {
        try validateRoutePrefix(prefix, head_buffer_bytes);
        resolved.path_prefix = prefix;
    }
    if (match.methods) |methods| {
        // An empty set is a mistake, not "any": absence already says
        // that, unambiguously.
        if (methods.count() == 0) {
            return error.FilterMethodEmpty;
        }
        // An extension method has no single token (§7), so a rule over
        // it would hold for every method nobody registered — the token
        // vocabulary refuses it, and so does this.
        if (methods.contains(.extension)) {
            return error.FilterMethodUnknown;
        }
        resolved.methods = methods;
    }
    resolved.headers = try resolveHeaderMatches(arena, match.headers);
    resolved.clients = try resolveClientCidrs(match.clients);
    assert(resolved.headers.len == match.headers.len);
    assert(resolved.clients.len == match.clients.len);
    return resolved;
}

/// A `client` predicate's CIDR list (#177), each prefix held to the rules
/// `Cidr.contains` leans on. None is any client; the JSON spelling of an
/// explicitly empty list is its front-end's refusal (`clientCidrsOf`).
fn resolveClientCidrs(cidrs: []const filter.Cidr) ResolveError![]const filter.Cidr {
    for (cidrs) |*cidr| {
        try validateClientCidr(cidr);
    }
    return cidrs;
}

/// One client prefix, judged. Host bits past the prefix must be zero:
/// `10.0.0.1/8` is a typo for either `10.0.0.0/8` or `10.0.0.1/32`, and
/// the loader cannot know which.
fn validateClientCidr(cidr: *const filter.Cidr) ResolveError!void {
    const prefix_len = cidr.prefix_len;
    switch (cidr.address) {
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
    assert(prefix_len <= 64 or cidr.address == .ip4);
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
fn resolveRouteHeader(header: *const Options.Listener.RouteHeader) ResolveError!router.HeaderMatch {
    try validateHeaderName(header.name);
    const match: router.HeaderMatch = switch (header.predicate) {
        .present => .{ .name = header.name, .kind = .present, .value = "" },
        .equals => |value| blk: {
            // An `equals: ""` predicate is meaningful — a header present
            // with an empty value — so the empty value is legal, as it is
            // for a filter.
            try validateHeaderValue(value);
            break :blk .{ .name = header.name, .kind = .equals, .value = value };
        },
    };
    // `headerMatches` asserts this of every predicate it is handed; the
    // name came through `validateHeaderName`, so stating it here is what
    // ties the producer to that precondition.
    assert(match.name.len >= 1);
    assert(match.kind != .contains);
    return match;
}

fn resolveHeaderMatches(
    arena: std.mem.Allocator,
    stated: []const Options.Listener.HeaderMatch,
) ResolveError![]const filter.HeaderMatch {
    const matches = try arena.alloc(filter.HeaderMatch, stated.len);
    for (stated, matches) |header, *match| {
        try validateHeaderName(header.name);
        match.* = switch (header.predicate) {
            .present => .{ .name = header.name, .kind = .present, .value = "" },
            .equals => |value| blk: {
                // An `equals: ""` predicate is meaningful — a header present
                // with an empty value — so the empty value is legal here.
                try validateHeaderValue(value);
                break :blk .{ .name = header.name, .kind = .equals, .value = value };
            },
            .contains => |needle| blk: {
                // A `contains: ""` needle would match every present header
                // (`indexOf(x, "")` is always 0) — a degenerate `present` in
                // disguise. Reject it so `contains` is always a real substring.
                if (needle.len == 0) {
                    return error.FilterHeaderContainsEmpty;
                }
                try validateHeaderValue(needle);
                break :blk .{ .name = header.name, .kind = .contains, .value = needle };
            },
        };
    }
    assert(matches.len == stated.len);
    return matches;
}

fn resolveActions(
    arena: std.mem.Allocator,
    stated: []const Options.Listener.Action,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
) ResolveError![]const filter.Action {
    if (stated.len == 0) {
        return error.FilterActionsEmpty;
    }
    assert(stated.len >= 1); // Past the empty guard.
    const actions = try arena.alloc(filter.Action, stated.len);
    for (stated, actions) |*action_stated, *action| {
        action.* = try resolveAction(arena, action_stated, head_buffer_bytes, bodies);
    }
    assert(actions.len == stated.len);
    return actions;
}

fn resolveAction(
    arena: std.mem.Allocator,
    action: *const Options.Listener.Action,
    head_buffer_bytes: u32,
    bodies: []ResolvedBody,
) ResolveError!filter.Action {
    switch (action.*) {
        .reject => |status| {
            if (!filter.isRejectStatus(status)) {
                return error.FilterRejectStatus;
            }
            return .{ .reject = status };
        },
        .redirect => |*redirect| return .{ .redirect = try resolveRedirect(redirect) },
        .respond => |respond| {
            // The page set, not the reject set: `200` is the point of this
            // action, and an error status here is a policy page that wants
            // a body without an `error_pages` entry to match.
            if (!shed.isPageStatus(respond.status)) {
                return error.FilterRespondStatus;
            }
            const page = try pageFor(arena, bodies, respond.body, respond.status);
            // The precondition `firstVerdict` asserts on the far side, so
            // the compiled action and the interpreter agree at load rather
            // than on the serving path.
            assert(shed.isPageStatus(page.status));
            return .{ .respond = page };
        },
        .allow => return .allow,
        .header_set => |*edit| return .{ .header_set = try resolveHeaderEdit(edit) },
        .header_add => |*edit| return .{ .header_add = try resolveHeaderEdit(edit) },
        .header_remove => |name| {
            try validateEditableHeaderName(name);
            return .{ .header_remove = name };
        },
        .rewrite_prefix => |rewrite| {
            try validateRoutePrefix(rewrite.from, head_buffer_bytes);
            try validateRoutePrefix(rewrite.to, head_buffer_bytes);
            return .{ .rewrite_prefix = rewrite };
        },
    }
}

/// Resolve a `redirect` action (#176). The target is a fixed `location`
/// or a composed one whose scheme is stated — a host alone would leave the
/// scheme guessed, and behind a TLS terminator the guess is wrong exactly
/// when it matters. The union carries that fork; what is left is the
/// status and the values the render emits.
fn resolveRedirect(redirect: *const filter.Redirect) ResolveError!filter.Redirect {
    if (!filter.isRedirectStatus(redirect.status)) {
        return error.FilterRedirectStatus;
    }
    assert(filter.isRedirectStatus(redirect.status));
    switch (redirect.target) {
        .location => |location| {
            if (location.len == 0) {
                return error.FilterRedirectTarget;
            }
            // A Location is a header value the render emits verbatim: the
            // same injection-safety the header edits prove at load.
            try validateHeaderValue(location);
        },
        .composed => |composed| {
            // Canonical like a route host: the Location's authority is a
            // name the operator writes, and the same validation keeps it
            // one the render can emit without a second look.
            if (composed.host) |host| _ = try validateRouteHost(host);
        },
    }
    return redirect.*;
}

/// Validate a name/value header edit shared by `header_set` and
/// `header_add`: an editable (non-proxy-managed) RFC 9110 token name and an
/// injection-safe field-value. Both actions carry the identical contract.
fn resolveHeaderEdit(edit: *const filter.HeaderEdit) ResolveError!filter.HeaderEdit {
    try validateEditableHeaderName(edit.name);
    try validateHeaderValue(edit.value);
    assert(edit.name.len >= 1);
    return edit.*;
}

/// A header name must be a non-empty RFC 9110 token (no separators or
/// controls), so an edit or match names a real, unambiguous header.
fn validateHeaderName(name: []const u8) ResolveError!void {
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
fn validateEditableHeaderName(name: []const u8) ResolveError!void {
    try validateHeaderName(name);
    assert(name.len >= 1); // A valid token; the managed lists are non-empty.
    if (render.isReservedEditName(name)) return error.FilterHeaderNameReserved;
}

/// A header value must be an RFC 9110 field-value: VCHAR / SP / HTAB /
/// obs-text, and never CR, LF, NUL, or another control. A value carrying
/// CRLF would inject a header when the renderer writes it upstream
/// (slice 3), so the compiled edit is proven injection-safe at load —
/// the same "already safe" guarantee the canonical host/path keys carry.
/// An empty value is legal. Applied to emitted values and, for symmetry,
/// to the compared match values. The per-byte test is the parser's own
/// `isForwardableByte`, so a filter and the parser share one definition.
fn validateHeaderValue(value: []const u8) ResolveError!void {
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

/// Resolve an http listener's route table (§7). A `cluster` target is
/// sugar for a single catch-all route; `routes` is the explicit table.
/// Prefixes must already be canonical (so they compare directly against
/// the canonical request path) and unique; the table is sorted most
/// specific first for the request-time scan.
fn resolveRoutes(
    arena: std.mem.Allocator,
    target: *const Options.Listener.Target,
    clusters: []const Config.Cluster,
    head_buffer_bytes: u32,
) ResolveError![]const router.Route {
    const stated = switch (target.*) {
        .cluster => |name| {
            const routes = try arena.alloc(router.Route, 1);
            routes[0] = .{
                .prefix = "/",
                .cluster_index = try clusterIndexOf(clusters, name),
            };
            assert(routes.len == 1); // The sugar is always one catch-all route.
            return routes;
        },
        .routes => |routes| routes,
    };
    if (stated.len == 0) {
        return error.RoutesEmpty;
    }
    // No bound but the index type: every route index — the sort's
    // permutation, a policy's `routeNamed`, the #435 slots — is a `u16`.
    if (stated.len > std.math.maxInt(u16)) {
        return error.RoutesOverLimit;
    }
    const routes = try arena.alloc(router.Route, stated.len);
    for (stated, 0..) |route_stated, index| {
        try validateRoutePrefix(route_stated.prefix, head_buffer_bytes);
        const host = if (route_stated.host) |raw| try validateRouteHost(raw) else null;
        const header = if (route_stated.header) |*raw|
            try resolveRouteHeader(raw)
        else
            null;
        try validateRouteName(stated[0..index], route_stated.name);
        for (stated[0..index]) |previous| {
            // Earlier routes already passed validateRouteHost, so their raw
            // host equals its canonical form — a byte compare is sound.
            if (optionalHostEql(previous.host, host) and
                std.mem.eql(u8, previous.prefix, route_stated.prefix) and
                // The header is part of what makes a route distinct
                // (#302): two rules sharing a host and prefix but naming
                // different headers are different rules, and only the
                // pair that agrees on all three is the same rule twice.
                routeHeaderEql(&previous.header, &route_stated.header))
            {
                return error.RouteDuplicate;
            }
        }
        routes[index] = .{
            .host = host,
            .prefix = route_stated.prefix,
            .header = header,
            .cluster_index = try routeClusterIndex(clusters, &route_stated),
            .handler = route_stated.handler,
            .request_policies = route_stated.request_policies,
            .response_policies = route_stated.response_policies,
            .name = route_stated.name,
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

/// A route's optional name (#430): within its bound, and unique among the
/// routes of its listener stated before it.
fn validateRouteName(
    earlier: []const Options.Listener.Route,
    name: ?[]const u8,
) ValidationError!void {
    // Within the routes bound `resolveRoutes` already holds.
    assert(earlier.len < std.math.maxInt(u16));
    const given = name orelse return;
    if (given.len == 0 or given.len > constants.route_name_bytes_max) return error.RouteNameInvalid;
    for (earlier) |previous| {
        const other = previous.name orelse continue;
        if (std.mem.eql(u8, other, given)) return error.RouteNameDuplicate;
    }
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

/// Whether two route header predicates are the same rule. Compared on the
/// stated predicates rather than the resolved matches because this runs
/// inside the resolve loop, before the later route has one — and the name
/// compare is case-insensitive for the reason the matcher's is: RFC 9110
/// says `X-Canary` and `x-canary` are one header.
fn routeHeaderEql(
    left: *const ?Options.Listener.RouteHeader,
    right: *const ?Options.Listener.RouteHeader,
) bool {
    const left_header = if (left.*) |*header| header else return right.* == null;
    const right_header = if (right.*) |*header| header else return false;
    if (!std.ascii.eqlIgnoreCase(left_header.name, right_header.name)) {
        return false;
    }
    return switch (left_header.predicate) {
        .present => right_header.predicate == .present,
        .equals => |value| switch (right_header.predicate) {
            .present => false,
            .equals => |other| std.mem.eql(u8, value, other),
        },
    };
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
fn validateRouteHost(host: []const u8) ResolveError![]const u8 {
    if (host.len == 0 or host.len > constants.host_bytes_max) {
        return error.RouteHostNotCanonical;
    }
    // `*` is held for a wildcard rule this proxy does not have yet — #297
    // wants one for certificates, and §7's host dimension has to share
    // it. Read as a literal it matches no Host a client sends, and the
    // day wildcards land it would change meaning under a frozen config,
    // so it is refused before the freeze rather than reinterpreted after
    // it (#400).
    if (std.mem.indexOfScalar(u8, host, '*') != null) {
        return error.RouteHostWildcard;
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
fn validateRoutePrefix(prefix: []const u8, head_buffer_bytes: u32) ResolveError!void {
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

/// Resolve one cluster's §7 passive-ejection block (#230). Absent leaves
/// it off, the same shape `check` uses: a feature nobody asked for costs
/// nothing and changes nothing.
///
/// A single-endpoint cluster is *allowed* to configure this even though
/// §7 fail-open makes the ejection a no-op there. Rejecting it would
/// punish the config that is about to grow a second endpoint, and the
/// operator's intent is unambiguous either way. The banner is where that
/// shows up as a fact, not the loader as an error.
fn resolvePassiveEjection(stated: ?Options.Cluster.PassiveEjection) ResolveError!?Config.Cluster.PassiveEjection {
    const passive_ejection = stated orelse return null;
    if (passive_ejection.fall < 1 or passive_ejection.fall > constants.health_probe_threshold_max) {
        return error.ClusterPassiveEjectionFallOutOfRange;
    }
    // Zero would re-admit inside the same tick that ejected, which is not
    // a fast recovery but an ejection that never happened.
    if (passive_ejection.recovery_ms < 1 or passive_ejection.recovery_ms > constants.timeout_ms_max) {
        return error.ClusterPassiveEjectionRecoveryOutOfRange;
    }
    if (passive_ejection.recovery_ms_max) |max_ms| {
        if (max_ms < 1 or max_ms > constants.timeout_ms_max) {
            return error.ClusterPassiveEjectionRecoveryOutOfRange;
        }
        // A ceiling below the base would shorten the first cooldown, which
        // is the opposite of what the key is for (#394).
        if (max_ms < passive_ejection.recovery_ms) return error.ClusterPassiveEjectionRecoveryMaxBelowBase;
    }
    return .{
        .fall = passive_ejection.fall,
        .recovery_ms = passive_ejection.recovery_ms,
        .recovery_ms_max = passive_ejection.recovery_ms_max,
    };
}

/// Resolve one cluster's §7 check block. Absent leaves the cluster
/// unprobed. Every limit gets its own error (§5); the kind's own fields
/// are its union payload, so a field one kind would leave inert is not a
/// shape options can state — JSON's spelling of it is the front-end's
/// refusal (`checkOf`).
fn resolveCheck(check: ?Options.Cluster.Check) ResolveError!?Config.Cluster.Check {
    const stated = check orelse return null;
    if (stated.fall < 1 or stated.fall > constants.health_probe_threshold_max) {
        return error.ClusterCheckThresholdOutOfRange;
    }
    if (stated.rise < 1 or stated.rise > constants.health_probe_threshold_max) {
        return error.ClusterCheckThresholdOutOfRange;
    }
    if (stated.timeout_ms < 1 or stated.timeout_ms > constants.timeout_ms_max) {
        return error.ClusterCheckTimeoutOutOfRange;
    }
    var resolved: Config.Cluster.Check = .{
        .kind = stated.kind,
        .fall = stated.fall,
        .rise = stated.rise,
        .timeout_ms = stated.timeout_ms,
    };
    switch (stated.kind) {
        .tcp => {},
        .http => |*http| resolved.http = try resolveHttpCheck(http),
        .grpc => |grpc| {
            if (!grpcServiceValid(grpc.service)) return error.ClusterCheckServiceInvalid;
            resolved.grpc_service = grpc.service;
        },
        .extension => |selection| resolved.probe = selection,
    }
    assert((resolved.http != null) == (resolved.kind == .http));
    assert((resolved.probe != null) == (resolved.kind == .extension));
    assert(resolved.grpc_service.len == 0 or resolved.kind == .grpc);
    return resolved;
}

/// A gRPC service name a probe can carry: within the one-octet length
/// its request encodes, and printable — `package.Service` — so nothing an
/// origin logs from it can surprise its reader. Empty names the server.
fn grpcServiceValid(service: []const u8) bool {
    if (service.len > constants.health_check_grpc_service_bytes_max) return false;
    for (service) |byte| {
        if (byte <= ' ' or byte >= 0x7f) return false;
    }
    return true;
}

/// The `http` half: a canonical path (validated exactly as a route
/// prefix is, so the probe sends bytes the origin's own router will
/// recognize), a bounded Host, and a status in the real range.
fn resolveHttpCheck(http: *const Options.Cluster.Check.Http) ResolveError!Config.Cluster.Check.Http {
    const path = http.path;
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
    if (http.host) |host| {
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
    const expect_status = http.expect_status;
    if (expect_status < 100 or expect_status > 599) {
        return error.ClusterCheckStatusInvalid;
    }
    return .{
        .path = path,
        .host = http.host,
        .expect_status = expect_status,
    };
}

/// Resolve #390's panic threshold. Absent keeps the default rule — fail
/// open only at zero healthy — which needs no value to say.
fn resolvePanicThreshold(cluster: *const Options.Cluster) ValidationError!?u8 {
    const threshold = cluster.panic_threshold_percent orelse return null;
    // Zero is the absent rule under a second spelling, and 100 would put
    // the cluster in panic at its first ejection — health checks that
    // never steer, which is turning them off without saying so.
    if (threshold < constants.panic_threshold_percent_min or
        threshold > constants.panic_threshold_percent_max)
    {
        return error.ClusterPanicThresholdOutOfRange;
    }
    // A threshold reads the health mask; a cluster nothing ejects from
    // keeps every endpoint healthy, so the key could never act (#390).
    if (cluster.check == null and cluster.passive_ejection == null) {
        return error.ClusterPanicThresholdWithoutHealth;
    }
    assert(threshold >= constants.panic_threshold_percent_min);
    assert(threshold <= constants.panic_threshold_percent_max);
    return threshold;
}

/// Resolve #391's slow start. It ramps `max_inflight`, so a cluster with
/// no cap has nothing to ramp; and it starts at a restore, so a cluster
/// nothing ejects from never starts it. Refused in both cases rather
/// than loaded inert.
fn resolveSlowStart(cluster: *const Options.Cluster) ValidationError!?u32 {
    const window_ms = cluster.slow_start_ms orelse return null;
    if (window_ms < 1 or window_ms > constants.timeout_ms_max) return error.ClusterSlowStartOutOfRange;
    if (cluster.max_inflight == null) return error.ClusterSlowStartWithoutMaxInflight;
    if (cluster.check == null and cluster.passive_ejection == null) return error.ClusterSlowStartWithoutHealth;
    assert(window_ms >= 1);
    return window_ms;
}

/// Resolve #392's cluster-wide cap. Absent leaves it uncapped; zero would
/// refuse every first try, which is a cluster turned off rather than
/// protected.
fn resolveMaxTotalInflight(max_total_inflight: ?u32) ValidationError!?u32 {
    const cap = max_total_inflight orelse return null;
    if (cap < 1 or cap > constants.cluster_inflight_max) return error.ClusterMaxTotalInflightOutOfRange;
    assert(cap >= 1);
    return cap;
}

/// Resolve the §8 per-endpoint concurrency cap. Absent leaves the
/// cluster uncapped; zero would refuse every request to an endpoint that
/// is doing nothing, and a value at or above the largest representable
/// in-flight total could never refuse anything — both are far more
/// likely a mistake than an intent, and "uncapped" already has a
/// spelling.
fn resolveMaxInflight(max_inflight: ?u32) ResolveError!?u32 {
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
fn resolveRetries(retries: u16) ResolveError!u16 {
    if (retries > constants.cluster_retries_max) {
        return error.ClusterRetriesOutOfRange;
    }
    return retries;
}

/// Resolve #393's budget. A budget bounds retry dials, so it needs
/// retries to bound: JSON's object form cannot spell one without a count,
/// and options written in code are refused the same shape.
fn resolveRetryBudget(retries: Options.Cluster.Retries) ValidationError!?u16 {
    const budget = retries.budget orelse return null;
    if (retries.count == 0) return error.ClusterRetryBudgetWithoutRetries;
    assert(retries.count >= 1);
    if (budget < 1 or budget > constants.retry_budget_max) return error.ClusterRetryBudgetOutOfRange;
    assert(budget >= 1);
    return budget;
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

/// A listener's TLS block (§4). The pair arrives as bytes; whether they
/// parse, and carry a key of a type the on-loop handshake can afford, is
/// found out at startup, which names the pair by its label. Shared by both
/// protocols rather than living in either body: both speak over a
/// terminated session (§4, §7). The one key that differs between them is
/// `alpn`, so the protocol rides along for it.
fn resolveTls(
    arena: std.mem.Allocator,
    tls: *const ?Options.Listener.Tls,
    protocol: Config.Listener.Protocol,
) ResolveError!?Config.Listener.Tls {
    const stated = if (tls.*) |*stated| stated else return null;
    const resolved: Config.Listener.Tls = .{
        .cert_pem = stated.cert_pem,
        .key_pem = stated.key_pem,
        .label = stated.label,
        .alpn = try resolveAlpn(arena, stated.alpn, protocol),
        .client_ca = try resolveClientCa(arena, &stated.client_ca),
        .certificates = try resolveCertificates(stated.certificates),
    };
    assert(resolved.certificates.len < constants.tls_certificates_max);
    assert(protocol == .http or resolved.alpn.len == 0);
    return resolved;
}

/// A listener's #297 further certificates. The default pair counts
/// against the same ceiling, so the further ones stay strictly under it.
fn resolveCertificates(
    certificates: []const Config.Listener.Certificate,
) ResolveError![]const Config.Listener.Certificate {
    if (certificates.len >= constants.tls_certificates_max) {
        return error.ListenerTlsCertificatesOverLimit;
    }
    assert(certificates.len < constants.tls_certificates_max);
    return certificates;
}

/// Every certificate the process will load, each listener's default
/// included (#297): each holds a key on the libcrypto heap, a static
/// reservation sized for `tls_certificates_max` of them.
fn tlsCertificateCount(listeners: []const Config.Listener) u64 {
    var count: u64 = 0;
    for (listeners) |listener| {
        const tls = listener.tls orelse continue;
        count += 1 + tls.certificates.len;
    }
    assert(count <= listeners.len * @as(u64, constants.tls_certificates_max));
    return count;
}

/// A listener's #304 client CA, parsed into anchors exactly as a cluster's
/// is (§7): a bundle that holds no certificate fails here at load, not at
/// the first client's handshake.
fn resolveClientCa(
    arena: std.mem.Allocator,
    client_ca: *const ?Options.Listener.ClientCa,
) ResolveError!?Config.Listener.ClientCa {
    const stated = if (client_ca.*) |*stated| stated else return null;
    // The bound the front-end's file read imposes, held for a bundle
    // written in code too: it is what the startup arena is sized against.
    if (stated.ca_pem.len > constants.origin_ca_bytes_max) return error.ListenerTlsClientCaInvalid;
    const anchors = trust.parseAnchors(arena, stated.ca_pem) catch |err| switch (err) {
        error.AnchorsInvalid, error.AnchorsTooMany => return error.ListenerTlsClientCaInvalid,
        error.OutOfMemory => return error.OutOfMemory,
    };
    assert(anchors.len >= 1);
    assert(stated.ca_pem.len <= constants.origin_ca_bytes_max);
    return .{ .anchors = anchors, .verify = stated.verify };
}

/// A terminating listener's ALPN offer (#271), as canonical tokens. The
/// spelling of each is its front-end's to parse (`alpnOf`).
///
/// Closed, on #180's upgrade-allowlist precedent: a token is a promise the
/// serving path keeps, so a name this proxy does not speak — `h2` until
/// #275, or a spelling RFC 7301 §3.1's octet comparison would not match —
/// is refused rather than offered to a client that would then speak it at
/// a parser that cannot. An empty list is refused too: a listener that
/// speaks HTTP/1.1 offering nothing is the gap this closes, and an `l4`
/// listener, which speaks no protocol it could name, is refused the key
/// outright and offers nothing whatever it says.
fn resolveAlpn(
    arena: std.mem.Allocator,
    offer: ?[]const alpn.Protocol,
    protocol: Config.Listener.Protocol,
) ResolveError![]const []const u8 {
    const asked = offer orelse return switch (protocol) {
        .http => alpn.http_default,
        .l4 => &.{},
    };
    if (protocol == .l4) return error.ListenerTlsAlpnOnL4;
    if (asked.len == 0) return error.ListenerTlsAlpnEmpty;
    // Bounded by the input, and every pass either rejects or marks one
    // vocabulary entry seen — so past `protocols_max` passes the next one
    // must be a duplicate or an unknown, and the list is refused there.
    var seen: [alpn.protocols_max]bool = @splat(false);
    for (asked) |named| {
        if (seen[@backingInt(named)]) return error.ListenerTlsAlpnDuplicate;
        seen[@backingInt(named)] = true;
    }
    assert(asked.len >= 1);
    assert(asked.len <= alpn.protocols_max);
    const tokens = try arena.alloc([]const u8, asked.len);
    for (asked, tokens) |named, *canonical| {
        canonical.* = named.token();
    }
    return tokens;
}

/// A cluster's resolved pick: the policy, and — for `hash` — the key it
/// is sticky on, `.source_ip` (inert) everywhere else.
const ResolvedPick = struct {
    pick: Config.Cluster.Pick,
    hash_key: Config.Cluster.HashKey,
};

/// Resolve a cluster's pick (#178, #417): a built-in policy, `hash` with
/// the key it reads, or a picker the build lists. A selection the build
/// cannot serve is refused at startup, where the server meets it
/// (`Server.selectsExtensions`); what this judges is the hash key's name.
fn resolvePick(pick: *const Options.Cluster.Pick) ResolveError!ResolvedPick {
    const resolved: ResolvedPick = switch (pick.*) {
        .rr => .{ .pick = .rr, .hash_key = .source_ip },
        .p2c => .{ .pick = .p2c, .hash_key = .source_ip },
        .hash => |key| .{ .pick = .hash, .hash_key = try resolveHashKey(key) },
        .extension => |selection| .{ .pick = .{ .extension = selection }, .hash_key = .source_ip },
    };
    // Only `hash` reads a key; every other policy carries the inert one.
    assert(resolved.pick == .hash or resolved.hash_key == .source_ip);
    assert((resolved.pick == .extension) == (pick.* == .extension));
    return resolved;
}

/// What `hash` keys on: the client address needs no name, and a header
/// or cookie name meets the token grammar `validatePickName` states.
fn resolveHashKey(key: Config.Cluster.HashKey) ResolveError!Config.Cluster.HashKey {
    switch (key) {
        .source_ip => {},
        .header, .cookie => |name| {
            try validatePickName(name);
            assert(name.len >= 1);
            assert(name.len <= constants.pick_name_bytes_max);
        },
    }
    return key;
}

/// The header or cookie name a request-derived key reads (#178). One
/// grammar for both: an RFC 9110 token, which is also RFC 6265's
/// cookie-name grammar — and one bound, `pick_name_bytes_max`, whose
/// job is the response-side stamp: every Set-Cookie a cookie cluster
/// answers with re-speaks this name into a scratch sized by that
/// constant.
fn validatePickName(name: []const u8) ResolveError!void {
    if (name.len == 0) {
        return error.ClusterPickNameInvalid;
    }
    if (name.len > constants.pick_name_bytes_max) {
        return error.ClusterPickNameTooLong;
    }
    assert(name.len >= 1);
    assert(name.len <= constants.pick_name_bytes_max);
    for (name) |byte| {
        if (!isTokenByte(byte)) {
            return error.ClusterPickNameInvalid;
        }
    }
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
        if (route.handler != null) continue;
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
        if (route.handler != null) continue;
        assert(route.cluster_index < clusters.len);
        if (clusters[route.cluster_index].proxy_protocol_send != null) {
            return error.ClusterProxyProtocolOnTlsListener;
        }
    }
}

/// What a cluster's protocol allows (§7): an HTTP/2 one is probed by
/// `tcp` or `grpc`, not `http`, since that prober speaks HTTP/1.1, which
/// such an origin need not — and `grpc` probes only such a cluster; an
/// HTTPS one (`http1` with `tls`) is not probed by `http` either, since
/// the prober speaks no TLS (#296). `h2` is over TLS and `h2c` is not.
fn rejectClusterProtocolShape(cluster: *const Config.Cluster) ValidationError!void {
    if (cluster.check) |check| {
        if (cluster.protocol.http2() and check.kind == .http) return error.ClusterH2cHttpCheck;
        if (!cluster.protocol.http2() and check.kind == .grpc) return error.ClusterCheckGrpcOnHttp1;
        if (cluster.tls != null and check.kind == .http) return error.ClusterTlsHttpCheck;
        // #436: a build's kind speaks over the prober's own socket, which
        // carries no TLS either.
        if (cluster.tls != null and check.kind == .extension) return error.ClusterTlsExtensionCheck;
    }
    if (cluster.tls != null and cluster.protocol == .h2c) return error.ClusterTlsOnH2c;
    if (cluster.tls == null and cluster.protocol == .h2) return error.ClusterH2WithoutTls;
    // #181's retry lives on the HTTP/1.1 exchange's own dial. An HTTP/2
    // origin's connection is dialed by its pool, not by a request, so a
    // refused dial there is a plain `502` and a budget here would be
    // read and never spent. Refused rather than ignored, so that teaching
    // the pool to retry later is additive rather than a change of
    // meaning under a frozen config (#400).
    if (cluster.protocol.http2() and cluster.retries > 0) return error.ClusterRetriesOnHttp2;
}

/// A cluster's TLS block (§7): the name checked as a DNS name, and the CA
/// bundle parsed into anchors — a bundle that holds no certificate fails
/// here, at load, not at the first handshake.
fn resolveClusterTls(
    arena: std.mem.Allocator,
    tls: ?Options.Cluster.Tls,
) ResolveError!?Config.Cluster.Tls {
    const stated = tls orelse return null;
    if (!dnsName(stated.server_name)) return error.ClusterTlsServerNameInvalid;
    // The bound the front-end's file read imposes, held for a bundle
    // written in code too: it is what the startup arena is sized against.
    if (stated.ca_pem.len > constants.origin_ca_bytes_max) return error.ClusterTlsCaInvalid;
    const anchors = trust.parseAnchors(arena, stated.ca_pem) catch |err| switch (err) {
        error.AnchorsInvalid, error.AnchorsTooMany => return error.ClusterTlsCaInvalid,
        error.OutOfMemory => return error.OutOfMemory,
    };
    assert(anchors.len >= 1);
    assert(stated.server_name.len >= 1);
    return .{ .server_name = stated.server_name, .anchors = anchors };
}

/// A DNS name a certificate can carry: labels of letters, digits and
/// hyphens, dot-separated, none empty — no address literal, which RFC
/// 9525's DNS-ID cannot match, and no wildcard, which is a certificate's
/// to say.
fn dnsName(name: []const u8) bool {
    if (name.len == 0 or name.len > constants.host_bytes_max) return false;
    var labels = std.mem.splitScalar(u8, name, '.');
    var letters = false;
    var count: u32 = 0;
    while (labels.next()) |label| : (count += 1) {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |byte| {
            if (std.ascii.isAlphabetic(byte)) letters = true;
            if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
        }
    }
    assert(count >= 1);
    return letters;
}

/// Where an HTTP/2 or an HTTPS cluster may be routed from (§7, #296):
/// only an `http` listener — `l4ClusterIndexOf` refuses every l4 route to
/// one, SNI routes included — and only one that carries no upgrade. An
/// upgrade's tunnel begins with a `101` HTTP/2 does not have, and relays
/// the socket itself, under TLS it would have to keep.
fn rejectUpgradeClusters(
    listener: *const Config.Listener,
    clusters: []const Config.Cluster,
) ValidationError!void {
    assert(listener.protocol == .http);
    assert(listener.routes.len >= 1);
    if (!listener.upgrades.any()) return;
    for (listener.routes) |route| {
        if (route.handler != null) continue;
        assert(route.cluster_index < clusters.len);
        const cluster = &clusters[route.cluster_index];
        if (cluster.protocol.http2()) return error.ClusterH2cWithUpgrades;
        if (cluster.tls != null) return error.ClusterTlsWithUpgrades;
    }
}

/// How many listeners ask for each of the features whose pools and
/// buffers are sized before any listener resolves. Split from `resolve`
/// for the length limit, and it reads better whole: the counts taken on
/// one rule.
///
/// Each count is **presence only**: whether a block is *usable* is its own
/// resolver's to say, later and per listener. Counting on usability here
/// would size a pool against blocks that might yet be refused, and report
/// a limits error for a config whose real fault is a bad name or a
/// duplicate offer. The two rules judged here are h2c beside TLS and a
/// QUIC binding without it, because each decides whether a pool exists
/// at all.
const ListenerFeatures = struct {
    http: u32 = 0,
    tls: u32 = 0,
    upgrades: u32 = 0,
    /// Listeners routing by SNI (#298) — what decides whether the relay
    /// buffer has to be wide enough to stage a ClientHello.
    sni: u32 = 0,
    /// Listeners speaking HTTP/2 (#275) — h2c, or `h2` in `tls.alpn` —
    /// what decides whether the HTTP/2 pools exist.
    http2: u32 = 0,
    /// Listeners with a `quic` binding (#449) — what decides whether the
    /// QUIC connection pool exists, and with `http2`, the shared streams.
    quic: u32 = 0,
};

fn countListenerFeatures(listeners: []const Options.Listener) ResolveError!ListenerFeatures {
    assert(listeners.len >= 1);
    var features: ListenerFeatures = .{};
    for (listeners) |*listener| {
        if (listener.tls != null) features.tls += 1;
        switch (listener.protocol) {
            .http => |*http| {
                features.http += 1;
                // What the pool is sized against is a listener that
                // *allows* an upgrade, not one that mentions the key:
                // `{}` and `{"websocket": false}` mean the same as absent
                // (#305), and counting them would demand a tunnel pool for
                // a listener that can never open one.
                if (http.upgrades.any()) features.upgrades += 1;
                // h2c is HTTP/2 *without* TLS: refused here, before any
                // pool is sized from it, so a terminating listener asking
                // for it is told the specific thing it got wrong first.
                if (http.h2c and listener.tls != null) return error.ListenerH2cOnTls;
                if (speaksHttp2(listener, http)) features.http2 += 1;
                // QUIC is TLS 1.3 by construction, and the binding
                // presents this listener's certificates: refused here for
                // h2c's reason, so the engine pool it would draw on is
                // never sized for a listener that has none to give it.
                if (http.quic != null) {
                    if (listener.tls == null) return error.ListenerQuicWithoutTls;
                    features.quic += 1;
                }
            },
            .l4 => |*l4| {
                if (l4.target == .routes) features.sni += 1;
            },
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
    assert(features.http2 <= features.http);
    assert(features.quic <= features.http);
    assert(features.quic <= features.tls);
    return features;
}

/// An http listener speaks HTTP/2 when it takes h2c, or offers `h2` in
/// ALPN.
fn speaksHttp2(listener: *const Options.Listener, http: *const Options.Listener.Http) bool {
    assert(listener.protocol == .http);
    if (http.h2c) return true;
    const tls = listener.tls orelse return false;
    const offer = tls.alpn orelse return false;
    assert(listener.tls != null);
    return std.mem.indexOfScalar(alpn.Protocol, offer, .h2) != null;
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
fn validateHeadOrder(timeouts: *const Options.Timeouts) ValidationError!void {
    const head_ms = timeouts.head_ms;
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

fn validateTimeouts(timeouts: *const Options.Timeouts) ValidationError!void {
    // Deadlines a zero would break rather than disable: a 0 ms connect or
    // idle budget reaps on arrival, and a 0 ms probe interval would probe
    // in a tight loop (§7) — probing is switched by the cluster `check`
    // flag, never by zeroing its pace. Refused whoever wrote the options:
    // the JSON front-end fills an absent key with the stock value, so
    // only a stated zero reaches this from a file (#417).
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
    // #311's watchdog spells "off" as absence rather than zero, so what
    // is left to check is a present value against a floor the mechanism
    // imposes — `alarm(2)`'s whole seconds, halved for the tick that
    // refreshes it. A number under it is not a tighter backstop, it is a
    // bound the seam would refuse to arm.
    if (timeouts.loop_watchdog_ms) |watchdog_ms| {
        if (watchdog_ms < constants.loop_watchdog_ms_min) {
            return error.LoopWatchdogTooShort;
        }
        if (watchdog_ms > constants.timeout_ms_max) {
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
/// ordered. Stated of the typed options, so it holds whoever wrote them;
/// `Server.init` asserts the same relations of any config however it was
/// built, which is what covers the configs tests hand-build past resolving
/// entirely.
fn assertTimeoutsBounded(
    timeouts: *const Options.Timeouts,
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
    assert(timeouts.connect_ms < timeouts.head_ms);
    assert(timeouts.head_ms <= timeouts.idle_ms);
    assert(timeouts.tunnel_ms >= constants.tunnel_ms_min);
    assert(timeouts.tunnel_ms <= constants.tunnel_ms_max);
}

test "config: clusters written as options meet the loader's rules (#417)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const origin = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000");
    const base: Options.Cluster = .{
        .name = "origin",
        .endpoints = &.{.{ .address = .{ .ip = origin } }},
        .pick = .p2c,
    };
    const plain = try resolveClusters(arena, &[_]Options.Cluster{base});
    try std.testing.expectEqual(@as(usize, 1), plain.len);
    try std.testing.expect(plain[0].pick == .p2c);
    try std.testing.expectEqual(@as(?[]const u16, null), plain[0].weights);

    // A budget with no retries to bound: JSON's object form cannot spell
    // it, so it is the one cluster refusal only code can earn.
    var budgeted = base;
    budgeted.retries = .{ .budget = 4 };
    try std.testing.expectError(
        error.ClusterRetryBudgetWithoutRetries,
        resolveClusters(arena, &[_]Options.Cluster{budgeted}),
    );
    budgeted.retries.count = 1;
    const retrying = try resolveClusters(arena, &[_]Options.Cluster{budgeted});
    try std.testing.expectEqual(@as(?u16, 4), retrying[0].retry_budget);

    // The rules a file meets, met from code: a hash key's token grammar
    // and a socket path's.
    var hashed = base;
    hashed.pick = .{ .hash = .{ .header = "bad name" } };
    try std.testing.expectError(
        error.ClusterPickNameInvalid,
        resolveClusters(arena, &[_]Options.Cluster{hashed}),
    );
    var relative = base;
    relative.endpoints = &.{.{ .address = .{ .unix = "relative.sock" } }};
    try std.testing.expectError(
        error.EndpointUnixPathRelative,
        resolveClusters(arena, &[_]Options.Cluster{relative}),
    );

    // A picker the build lists passes through to the server, which is
    // where a selection it cannot serve is refused.
    var instance: u8 = 0;
    var picked = base;
    picked.pick = .{ .extension = .{ .index = 0, .instance = &instance } };
    const with_picker = try resolveClusters(arena, &[_]Options.Cluster{picked});
    try std.testing.expect(with_picker[0].pick == .extension);
    try std.testing.expect(with_picker[0].hash_key == .source_ip);
}

test "config: bodies and error pages written as options (#417)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const bodies = try resolveBodies(arena, &[_]Options.Body{.{
        .name = "busy",
        .bytes = "try again shortly",
        .content_type = "text/plain",
    }});
    const pages = try resolveErrorPages(arena, &[_]Options.ErrorPage{
        .{ .status = 503, .body = "busy" },
    }, bodies);
    try std.testing.expectEqual(@as(usize, 1), pages.len);
    try std.testing.expectEqual(@as(u16, 503), pages[0].status);
    try std.testing.expect(std.mem.endsWith(u8, pages[0].keep, "try again shortly"));
    // The rules a file meets, met from code: only a status zoxy answers
    // itself takes a page, and a page names a body that exists.
    try std.testing.expectError(error.ErrorPageStatusUnknown, resolveErrorPages(
        arena,
        &[_]Options.ErrorPage{.{ .status = 200, .body = "busy" }},
        bodies,
    ));
    try std.testing.expectError(error.BodyUnknown, resolveErrorPages(
        arena,
        &[_]Options.ErrorPage{.{ .status = 503, .body = "missing" }},
        bodies,
    ));
    // The cap moved from the inline arm to every body, whatever carried
    // its bytes in.
    const oversized = try arena.alloc(u8, constants.body_bytes_max + 1);
    @memset(oversized, 'x');
    try std.testing.expectError(error.BodyOverLimit, resolveBodies(arena, &[_]Options.Body{.{
        .name = "huge",
        .bytes = oversized,
        .content_type = "text/plain",
    }}));
}

test "config: an access log written as options (#417)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const stated: Options.AccessLog = .{
        .sink = .{ .file = "/var/log/zoxy/access.log" },
        .request_headers = &.{"X-Request-ID"},
    };
    const sink = (try resolveAccessLogSink(stated)).?;
    try std.testing.expectEqualStrings("/var/log/zoxy/access.log", sink.file);
    const headers = try resolveLogHeaders(arena, stated);
    try std.testing.expectEqualStrings("x-request-id", headers.request[0]);
    try std.testing.expectEqual(@as(usize, 0), headers.response.len);
    // An empty path is a missing one from code as from a file.
    try std.testing.expectError(
        error.AccessLogPathMissing,
        resolveAccessLogSink(.{ .sink = .{ .file = "" } }),
    );
    try std.testing.expectEqual(@as(?Config.AccessLogSink, null), try resolveAccessLogSink(null));
}

test "config: connection policies ride the listener and its SNI routes through the sort (#425)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const clusters = try resolveClusters(arena, &[_]Options.Cluster{.{
        .name = "origin",
        .endpoints = &.{.{ .address = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") } }},
        .pick = .p2c,
    }});
    var instance: u8 = 0;
    const policy: extension_module.Selection = .{ .index = 0, .instance = &instance };
    // The any-name route stated first: the sort moves the named one ahead,
    // and its policies must move with it.
    const l4: Options.Listener = .{
        .bind = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8443") },
        .connection_policies = &.{policy},
        .protocol = .{ .l4 = .{ .target = .{ .routes = &.{
            .{ .cluster = "origin" },
            .{ .sni = "api.example.com", .cluster = "origin", .connection_policies = &.{ policy, policy } },
        } } } },
    };
    const listeners = try resolveListeners(arena, &[_]Options.Listener{l4}, clusters, constants.head_buffer_bytes_min, &.{});
    try std.testing.expectEqual(@as(usize, 1), listeners[0].connection_policies.len);
    try std.testing.expectEqualStrings("api.example.com", listeners[0].sni_routes[0].server_name.?);
    try std.testing.expectEqual(@as(usize, 2), listeners[0].sni_routes[0].connection_policies.len);
    try std.testing.expectEqual(@as(usize, 0), listeners[0].sni_routes[1].connection_policies.len);
}

test "config: listeners written as options meet the loader's rules (#417)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const clusters = try resolveClusters(arena, &[_]Options.Cluster{.{
        .name = "origin",
        .endpoints = &.{.{ .address = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") } }},
        .pick = .p2c,
    }});
    const head_bytes = constants.head_buffer_bytes_min;
    var instance: u8 = 0;
    const policy: extension_module.Selection = .{ .index = 0, .instance = &instance };
    const http: Options.Listener = .{
        .bind = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") },
        .protocol = .{ .http = .{
            .target = .{ .routes = &.{
                .{ .prefix = "/", .cluster = "origin" },
                .{
                    .prefix = "/api",
                    .cluster = "origin",
                    .header = .{ .name = "X-Canary", .predicate = .present },
                    .request_policies = &.{policy},
                },
            } },
            .request_policies = &.{policy},
            .max_body_bytes = 1 << 20,
            .keepalive_requests = 1000,
        } },
    };
    const listeners = try resolveListeners(arena, &[_]Options.Listener{http}, clusters, head_bytes, &.{});
    try std.testing.expectEqual(@as(usize, 1), listeners[0].request_policies.len);
    // Sorted most specific first, each route's policies riding with it.
    try std.testing.expectEqualStrings("/api", listeners[0].routes[0].prefix);
    try std.testing.expectEqual(@as(usize, 1), listeners[0].routes[0].request_policies.len);
    try std.testing.expectEqual(@as(usize, 0), listeners[0].routes[1].request_policies.len);

    // Shapes a JSON spelling cannot reach, refused by the rules a file
    // meets: an empty method set, an empty needle, setuid on a socket,
    // an empty ALPN offer.
    var methods_empty = http;
    methods_empty.protocol.http.request_filters = &.{.{
        .match = .{ .methods = std.EnumSet(Options.Listener.Method).init(.{}) },
        .actions = &.{.allow},
    }};
    try std.testing.expectError(error.FilterMethodEmpty, resolveListeners(arena, &[_]Options.Listener{methods_empty}, clusters, head_bytes, &.{}));
    var needle_empty = http;
    needle_empty.protocol.http.request_filters = &.{.{
        .match = .{ .headers = &.{.{ .name = "x-tenant", .predicate = .{ .contains = "" } }} },
        .actions = &.{.allow},
    }};
    try std.testing.expectError(error.FilterHeaderContainsEmpty, resolveListeners(arena, &[_]Options.Listener{needle_empty}, clusters, head_bytes, &.{}));
    var setuid = http;
    setuid.bind = .{ .unix = "/run/zoxy.sock" };
    setuid.mode = .{ .bits = 0o4660 };
    try std.testing.expectError(error.ListenerModeInvalid, resolveListeners(arena, &[_]Options.Listener{setuid}, clusters, head_bytes, &.{}));
    var alpn_empty = http;
    alpn_empty.tls = .{ .cert_pem = "cert", .key_pem = "key", .label = "test", .alpn = &.{} };
    try std.testing.expectError(error.ListenerTlsAlpnEmpty, resolveListeners(arena, &[_]Options.Listener{alpn_empty}, clusters, head_bytes, &.{}));
    var alpn_twice = http;
    alpn_twice.tls = .{ .cert_pem = "cert", .key_pem = "key", .label = "test", .alpn = &.{ .h2, .h2 } };
    try std.testing.expectError(error.ListenerTlsAlpnDuplicate, resolveListeners(arena, &[_]Options.Listener{alpn_twice}, clusters, head_bytes, &.{}));

    // The rules a file's filters meet, met from code: no token names an
    // extension method, values carry no line break, managed headers stay
    // the proxy's, and an IPv6 client is no narrower than its /64.
    const rejected = [_]struct { anyerror, Options.Listener.Filter }{
        .{ error.FilterMethodUnknown, .{
            .match = .{ .methods = std.EnumSet(Options.Listener.Method).initMany(&.{.extension}) },
            .actions = &.{.allow},
        } },
        .{ error.FilterHeaderValueInvalid, .{
            .match = .{ .headers = &.{.{ .name = "x-tenant", .predicate = .{ .equals = "a\r\nb" } }} },
            .actions = &.{.allow},
        } },
        .{ error.FilterHeaderNameReserved, .{ .actions = &.{.{ .header_remove = "Content-Length" }} } },
        .{ error.FilterClientPrefixTooNarrow, .{
            .match = .{ .clients = &.{.{ .address = try std.Io.net.IpAddress.parse("2001:db8::", 0), .prefix_len = 96 }} },
            .actions = &.{.allow},
        } },
        .{ error.FilterRejectStatus, .{ .actions = &.{.{ .reject = 200 }} } },
    };
    for (rejected) |case| {
        var filtered = http;
        filtered.protocol.http.request_filters = &.{case[1]};
        try std.testing.expectError(case[0], resolveListeners(arena, &[_]Options.Listener{filtered}, clusters, head_bytes, &.{}));
    }

    // An SNI table on a terminating l4 listener: the hello it would read
    // was consumed by its own handshake.
    const sni_tls: Options.Listener = .{
        .bind = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8443") },
        .tls = .{ .cert_pem = "cert", .key_pem = "key", .label = "test" },
        .protocol = .{ .l4 = .{ .target = .{ .routes = &.{.{ .cluster = "origin" }} } } },
    };
    try std.testing.expectError(error.ListenerTlsWithSniRoutes, resolveListeners(arena, &[_]Options.Listener{sni_tls}, clusters, head_bytes, &.{}));
}

test "config: a QUIC binding written as options meets the loader's rules (#449)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const clusters = try resolveClusters(arena, &[_]Options.Cluster{.{
        .name = "origin",
        .endpoints = &.{.{ .address = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") } }},
        .pick = .p2c,
    }});
    const head_bytes = constants.head_buffer_bytes_min;
    const udp = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8443");
    const bound: Options.Listener = .{
        .bind = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8443") },
        .tls = .{ .cert_pem = "cert", .key_pem = "key", .label = "test" },
        .protocol = .{ .http = .{
            .target = .{ .cluster = "origin" },
            .max_body_bytes = 1 << 20,
            .keepalive_requests = 1000,
            .quic = .{ .bind = .{ .ip = udp } },
        } },
    };
    const listeners = try resolveListeners(arena, &[_]Options.Listener{bound}, clusters, head_bytes, &.{});
    const binding = listeners[0].quic.?;
    try std.testing.expect(binding.bind_address.eql(&udp));
    try std.testing.expectEqual(constants.alt_svc_max_age_s_default, binding.alt_svc_max_age_s);
    // Advertised on every answer (RFC 7838), set over whatever an origin
    // said: the one response rule the binding brings.
    try std.testing.expectEqual(@as(usize, 1), listeners[0].response_filters.len);
    const advertised = listeners[0].response_filters[0];
    try std.testing.expectEqual(@as(usize, 0), advertised.match.statuses.len);
    try std.testing.expectEqual(filter.AppliedHeaderEdit.Kind.set, advertised.edits[0].kind);
    try std.testing.expectEqualStrings(alt_svc_name, advertised.edits[0].name);
    try std.testing.expectEqualStrings("h3=\":8443\"; ma=86400", advertised.edits[0].value);
    // An age of zero advertises nothing; nor does a port the kernel picks.
    var silent = bound;
    silent.protocol.http.quic = .{ .bind = .{ .ip = udp }, .alt_svc_max_age_s = 0 };
    const quiet = try resolveListeners(arena, &[_]Options.Listener{silent}, clusters, head_bytes, &.{});
    try std.testing.expectEqual(@as(usize, 0), quiet[0].response_filters.len);
    var ephemeral = bound;
    ephemeral.protocol.http.quic = .{ .bind = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") } };
    const unknown = try resolveListeners(arena, &[_]Options.Listener{ephemeral}, clusters, head_bytes, &.{});
    try std.testing.expectEqual(@as(usize, 0), unknown[0].response_filters.len);
    // A listener whose own rules take every edit has none left for it.
    var edits: [constants.header_edits_max]Options.Listener.ResponseAction = undefined;
    for (&edits) |*action| action.* = .{ .header_set = .{ .name = "X-Edit", .value = "1" } };
    var full = bound;
    full.protocol.http.response_filters = &.{.{ .actions = &edits }};
    try std.testing.expectError(
        error.ListenerQuicAltSvcOverEditLimit,
        resolveListeners(arena, &[_]Options.Listener{full}, clusters, head_bytes, &.{}),
    );

    // Counted only beside TLS, which it is refused without before any
    // pool is sized — and again by its own resolver, for code that
    // resolves listeners alone.
    const features = try countListenerFeatures(&[_]Options.Listener{bound});
    try std.testing.expectEqual(@as(u32, 1), features.quic);
    try std.testing.expectEqual(@as(u32, 0), features.http2);
    var plaintext = bound;
    plaintext.tls = null;
    try std.testing.expectError(error.ListenerQuicWithoutTls, countListenerFeatures(&[_]Options.Listener{plaintext}));
    try std.testing.expectError(error.ListenerQuicWithoutTls, resolveListeners(arena, &[_]Options.Listener{plaintext}, clusters, head_bytes, &.{}));
    var socket_file = bound;
    socket_file.protocol.http.quic = .{ .bind = .{ .unix = "/run/zoxy.sock" } };
    try std.testing.expectError(error.ListenerQuicBindNotIp, resolveListeners(arena, &[_]Options.Listener{socket_file}, clusters, head_bytes, &.{}));
    var remembered = bound;
    remembered.protocol.http.quic = .{ .bind = .{ .ip = udp }, .alt_svc_max_age_s = constants.alt_svc_max_age_s_max + 1 };
    try std.testing.expectError(error.ListenerQuicAltSvcMaxAgeOutOfRange, resolveListeners(arena, &[_]Options.Listener{remembered}, clusters, head_bytes, &.{}));
    var twin = bound;
    twin.bind = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9443") };
    try std.testing.expectError(error.ListenerQuicBindDuplicate, resolveListeners(arena, &[_]Options.Listener{ bound, twin }, clusters, head_bytes, &.{}));

    // QUIC alone: the shared streams without an HTTP/2 session, and the
    // pool within the engines every connection holds one of.
    const pools = try resolveFeaturePools(&.{ .h2_streams = 8, .tls_engines = 16 }, 1024, features);
    try std.testing.expectEqual(@as(u32, 0), pools.h2_connections);
    try std.testing.expectEqual(@as(u32, 8), pools.stream_slots);
    try std.testing.expectEqual(@as(u32, 16), pools.quic_connections);
    try std.testing.expectError(
        error.LimitQuicConnectionsOverTlsEngines,
        resolveFeaturePools(&.{ .h2_streams = 8, .tls_engines = 16, .quic_connections = 17 }, 1024, features),
    );
    try std.testing.expectError(
        error.LimitQuicConnectionsOutOfRange,
        resolveFeaturePools(&.{ .h2_streams = 8, .quic_connections = constants.quic_connections_max + 1 }, 1024, features),
    );
    try std.testing.expectError(
        error.LimitH2StreamsRequired,
        resolveFeaturePools(&.{}, 1024, features),
    );
}

test "config: a route's name rides its route through the sort, and a listener's names are unique (#430)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const clusters = try resolveClusters(arena, &[_]Options.Cluster{.{
        .name = "origin",
        .endpoints = &.{.{ .address = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") } }},
        .pick = .p2c,
    }});
    const head_bytes = constants.head_buffer_bytes_min;
    const named = struct {
        fn listener(routes: []const Options.Listener.Route) !Options.Listener {
            return .{
                .bind = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") },
                .protocol = .{ .http = .{
                    .target = .{ .routes = routes },
                    .max_body_bytes = 0,
                    .keepalive_requests = 0,
                } },
            };
        }
    };
    const routes = [_]Options.Listener.Route{
        .{ .prefix = "/", .cluster = "origin", .name = "fallback" },
        .{ .prefix = "/api/v2", .cluster = "origin", .name = "api-v2" },
        .{ .prefix = "/static", .cluster = "origin" },
    };
    const listeners = try resolveListeners(arena, &[_]Options.Listener{try named.listener(&routes)}, clusters, head_bytes, &.{});
    // Sorted most specific first, and each keeps the name it was given.
    try std.testing.expectEqualStrings("/api/v2", listeners[0].routes[0].prefix);
    try std.testing.expectEqualStrings("api-v2", listeners[0].routes[0].name.?);
    try std.testing.expect(listeners[0].routes[1].name == null);
    try std.testing.expectEqualStrings("fallback", listeners[0].routes[2].name.?);
    const site: extension_module.PolicySite = .{
        .listener_index = 0,
        .route_index = null,
        .cluster_index = null,
        .clusters = &.{},
        .routes = listeners[0].routes,
    };
    try std.testing.expectEqual(@as(?u16, 0), site.routeNamed("api-v2"));
    try std.testing.expectEqual(@as(?u16, 2), site.routeNamed("fallback"));
    try std.testing.expectEqual(@as(?u16, null), site.routeNamed("static"));

    const twice = [_]Options.Listener.Route{
        .{ .prefix = "/a", .cluster = "origin", .name = "same" },
        .{ .prefix = "/b", .cluster = "origin", .name = "same" },
    };
    try std.testing.expectError(error.RouteNameDuplicate, resolveListeners(arena, &[_]Options.Listener{try named.listener(&twice)}, clusters, head_bytes, &.{}));
    const empty = [_]Options.Listener.Route{.{ .prefix = "/", .cluster = "origin", .name = "" }};
    try std.testing.expectError(error.RouteNameInvalid, resolveListeners(arena, &[_]Options.Listener{try named.listener(&empty)}, clusters, head_bytes, &.{}));
    const long_bytes: [constants.route_name_bytes_max + 1]u8 = @splat('r');
    const long = [_]Options.Listener.Route{.{ .prefix = "/", .cluster = "origin", .name = &long_bytes }};
    try std.testing.expectError(error.RouteNameInvalid, resolveListeners(arena, &[_]Options.Listener{try named.listener(&long)}, clusters, head_bytes, &.{}));
    // One past what a `u16` route index names is refused before any route
    // is read.
    const too_many = try arena.alloc(Options.Listener.Route, @as(usize, std.math.maxInt(u16)) + 1);
    @memset(too_many, .{ .prefix = "/", .cluster = "origin" });
    try std.testing.expectError(error.RoutesOverLimit, resolveListeners(arena, &[_]Options.Listener{try named.listener(too_many)}, clusters, head_bytes, &.{}));
}

test "config: endpoint slots reserve room past the stated endpoints, free and weightless (#428)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const stated: Options.Cluster = .{
        .name = "api",
        .endpoints = &.{
            .{ .address = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") } },
            .{ .address = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9001") }, .weight = 3 },
        },
        .pick = .p2c,
        .endpoint_slots = 4,
    };
    const cluster = try resolveCluster(arena, &stated);
    try std.testing.expectEqual(@as(usize, 4), cluster.endpoints.len);
    const slots = cluster.slots.?;
    try std.testing.expectEqualSlices(Config.EndpointState, &.{ .live, .live, .free, .free }, slots.states);
    try std.testing.expectEqualSlices(u16, &.{ 1, 3, 0, 0 }, cluster.weights.?);
    try std.testing.expect(cluster.liveAt(1));
    try std.testing.expect(!cluster.occupiedAt(2));

    var short = stated;
    short.endpoint_slots = 1;
    try std.testing.expectError(error.EndpointSlotsOutOfRange, resolveCluster(arena, &short));
}
