//! The composition root (DESIGN.md §3, §5, §8): owns the pools, the
//! listeners, the counters, and the drain flag; generic over the Io
//! backend so the simulator instantiates the whole serving path without
//! main. All admission decisions happen here — the ladder's single
//! choke point. Admission forks on the listener's protocol: an `l4`
//! listener runs the strict TCP relay (`net/relay.zig`), an `http`
//! listener runs the L7 state machine (`http/proxy.zig`); the shared
//! accept gate, deadline, and teardown machinery serve both, as do the
//! §8 pressure watermarks (one rule, three pools) and the deadline's
//! request-expiry verdict fork (§8: 504 when answerable, teardown
//! otherwise).

const std = @import("std");

const access_log_module = @import("access_log.zig");
const admin_module = @import("admin.zig");
const Balancer = @import("balancer.zig").Balancer;
const config_module = @import("config.zig");
const constants = @import("constants.zig");
const counters_module = @import("counters.zig");
const conn_module = @import("net/Conn.zig");
const stream_module = @import("net/Stream.zig");
const health_module = @import("net/health.zig");
const Io = @import("io/io.zig");
const Pool = @import("mem/Pool.zig").Pool;
const parser = @import("http/parser.zig");
const proxy = @import("http/proxy.zig");
const router = @import("http/router.zig");
const filter = @import("http/filter.zig");
const proxy_protocol = @import("net/proxy_protocol.zig");
const client_hello = @import("net/client_hello.zig");
const sni_router = @import("net/sni_router.zig");
const relay = @import("net/relay.zig");
const shed = @import("shed.zig");
const Credentials = @import("tls/Credentials.zig");
const Tickets = @import("tls/Tickets.zig");
const TlsEngine = @import("tls/Engine.zig");
const upstream_module = @import("net/upstream.zig");

const assert = std.debug.assert;

pub fn Server(comptime IoType: type) type {
    Io.assertIoInterface(IoType);

    return struct {
        io: *IoType,
        config: *const config_module.Config,
        conns: Pool(ConnType),
        /// The §5 stream pool (#274): one exchange per slot, and for now
        /// exactly one slot per admitted connection.
        ///
        /// Sized to `conn_slots` rather than given a limit of its own,
        /// which is the whole shape of this slice: at one stream per
        /// connection the pool cannot be exhausted independently, so it
        /// adds no shed rung and no counter, and the ring budget it
        /// re-derives comes out where it was. #173 is what makes the two
        /// counts diverge — a shared pool sized for concurrent *streams*,
        /// with `SETTINGS_MAX_CONCURRENT_STREAMS` an advertisement over
        /// it and `REFUSED_STREAM` the rung when it runs dry — and that
        /// is when it earns an operator-facing limit.
        streams: Pool(StreamType),
        relay_buffers: Pool(relay.RelayBuffer),
        /// The §5 tunnel pool (#180): relay buffers for upgraded
        /// connections, deliberately *not* the pool above.
        ///
        /// Same element, separate reservation, and the separation is the
        /// whole feature. Every other pool here is sized for concurrent
        /// activity — a keep-alive connection holds no head buffer, a
        /// parked upstream holds no head — while a tunnel pins its buffer
        /// for the connection's entire life and can never return to
        /// keep-alive. Sharing one pool between the two shapes would let
        /// long-lived sessions consume the buffers ordinary traffic sheds
        /// on, so tunnels cannot starve HTTP because they never touch
        /// what HTTP draws from. Zero exactly when no listener allows an
        /// upgrade, which is what makes the feature free to a deployment
        /// that did not ask for it.
        tunnel_buffers: Pool(relay.RelayBuffer),
        /// The shared upstream connection pool (§3, §5): leased per L7
        /// exchange today; parking joins with keep-alive.
        upstreams: upstream_module.UpstreamPool(IoType),
        /// The §5 upstream head buffers, pooled apart from the slots so a
        /// parked connection holds a socket and ~48 B of slot, never 8 KiB
        /// of head. App-side (not the seam's kernel ring) because the
        /// acquire is synchronous: a render needs the bytes now.
        upstream_head_buffers: Pool(upstream_module.HeadBuffer),
        upstream_head_pressure: bool,
        /// Live L4 relayed connections per endpoint (§7), the other half
        /// of `upstream_module.Load`. The pool cannot hold this: an L4
        /// connection leases no upstream slot, so it is the server —
        /// which owns the conn slots such a connection *does* hold —
        /// that counts them. Charged at the dial, released with the conn
        /// slot, so the two move together.
        ///
        /// `u16` for the same reason `leased_counts` is: one charge per
        /// live conn slot bounds every entry by `conn_slots_max`, which
        /// `constants` asserts fits (`conn_slots_max - 1 <= maxInt(u16)`).
        l4_inflight: []u16,
        listeners: []ListenerState,
        listeners_count: u16,
        /// One slot per listener, null where that listener is plaintext
        /// (§4). Loaded before `start` by whoever can read files — `main`
        /// in production, the harness in a test — because this file is
        /// under the Io seam and the loader is not. Empty until then, and
        /// empty for the whole process on a deployment with no `tls`
        /// block anywhere.
        tls_credentials: []const ?Credentials,
        /// The §4 TLS engine pool: one engine per session being
        /// handshaked or terminated, drawn at admission on a listener
        /// that terminates and returned at teardown. Empty — reserving
        /// nothing — when no listener does, which is the shape `Pool`'s
        /// zero-slot support exists for.
        ///
        /// A pool rather than a `Conn` field because an engine is ~132 KiB
        /// against a conn slot's ~1.7: a deployment pays for the TLS it
        /// serves concurrently, not for every slot it could admit (§5).
        tls_engines: Pool(TlsEngine),
        /// The §4 session-ticket sealing keys — two slots, rotated, and
        /// process-lifetime by design: a ticket is a bearer credential
        /// for a resumed session, so the key that opens one never reaches
        /// disk. A restart therefore costs every returning client one
        /// full handshake, which is the price of that.
        ///
        /// Sized by nothing: unlike the engine pool this is fixed state
        /// (two keys), which is what makes stateless tickets free of a
        /// per-session table (§5).
        tls_tickets: Tickets,
        /// The load-balancing policy: resolves a cluster to the endpoint to
        /// dial. Owns its own per-cluster state so the serving path never
        /// hardcodes how an endpoint is chosen (§7).
        balancer: Balancer,
        counters: counters_module.Counters,
        /// The #179 labeled breakdown beside the process totals: which
        /// backend, per cluster and endpoint. Tables sized by the loaded
        /// config's endpoint index space; every labeled witness site
        /// also moves the matching bare counter, and `reconcile` holds
        /// the partitions equal.
        labeled: counters_module.Labeled,
        /// Staging for the §8 exit tally: the
        /// full exposition — counters then labeled — no longer fits a
        /// fixed stack buffer once its length is the config's, so it is
        /// arena memory priced in the banner (`metricsBytes`).
        dump_buffer: []u8,
        draining: bool,
        /// §8 watermark state, one flag per pool: set once a pool crosses
        /// its high watermark, cleared once it drains back below the low
        /// one (hysteresis, `constants.poolPressureOn/Off`). Relay and
        /// conn pressure shorten the idle timeout so quiet connections
        /// return their buffers and slots before the wall is reached;
        /// relay pressure alone also stops honoring keep-alive
        /// (`keepAliveSuppressed` — conn-slot occupancy stays out, #57);
        /// upstream pressure shortens parked-connection deadlines so idle
        /// parked sockets free their slots for fresh dials before the
        /// 503 wall.
        relay_pressure: bool,
        conn_pressure: bool,
        upstream_pressure: bool,
        /// The head-buffer ring's watermark flag (§8). Unlike the other
        /// three it drives no timeout or keep-alive bias: an idle
        /// connection holds no head buffer, so there is no idle occupancy
        /// to evict — the only remedy for ring pressure is the shed rung
        /// itself, and the flag exists for the gauge and the engage
        /// counter an operator alerts on.
        head_pressure: bool,
        /// Ring buffers currently bound to connections: incremented at the
        /// delivery that binds one, decremented by `returnHeadBuffer` —
        /// the seam's kernel side cannot count for us, so the server is
        /// the one owner of this number (§5). `head_buffers_capacity`
        /// mirrors `limits.head_buffers`, asserted at init to equal the
        /// group the Io backend actually registered.
        head_buffers_in_use: u32,
        head_buffers_capacity: u32,
        /// The one shared lingering-close discard sink (§7): every
        /// draining connection recvs into it concurrently, which is sound
        /// precisely because no path reads it — bytes land, interleave,
        /// and die. Inline rather than arena so it is part of no budget
        /// term and can never be under-counted.
        drain_sink: [constants.drain_sink_bytes]u8,
        /// The §7 canonicalization scratches for the serving path (the
        /// balancer's `eligible_scratch` precedent): their length is the
        /// config's `head_buffer_bytes`, and a runtime-length stack array
        /// is exactly the dynamic allocation §5 forbids — allocated once
        /// at init, reused per request. Two, not one: on the checkout
        /// path the routed views still alias the target scratch while the
        /// filter rewrite writes the other. Sound because the loop is
        /// single-threaded and neither window suspends or re-enters.
        /// Empty on an L4-only config, which never canonicalizes.
        target_scratch: []u8,
        rewrite_scratch: []u8,
        /// The serving path's one header scratch, on the same terms as the
        /// two above and for a sharper reason: a `parser.HeaderStorage`
        /// local is 0xaa-filled on every call under ReleaseSafe, and §9's
        /// flamegraph put that fill at 62% of user cycles under L7 load —
        /// ~9.2 KiB per request across the four frames a keep-alive
        /// exchange parses. Lent once per parse and filled once at init.
        ///
        /// One, not two, and the argument has two halves. Across callbacks:
        /// §4 runs each to completion and never nests one inside another,
        /// so two borrows cannot interleave that way. Within a callback: no
        /// synchronous chain from a borrow site reaches a second one —
        /// `parseAndDispatch`'s borrow stays live through `routeRequest`
        /// into `beginUpstream`'s reuse path and on into
        /// `renderRequestAndStartLegs`, none of which parse again, and the
        /// paths that do parse again are the ones reached *after* an await,
        /// where §7 parses the accumulated head afresh precisely because
        /// nothing parsed survives its callback — which is also why
        /// `head_cursor` carries an offset and not a partial parse.
        /// `header_scratch_lent` makes the whole of
        /// that a checked fact rather than a reviewed one.
        ///
        /// Comptime-sized, so inline like `drain_sink`: part of no budget
        /// term, and never under-counted.
        header_scratch: parser.HeaderStorage,
        /// Whether `header_scratch` is out on loan (see the field). Only
        /// ever true inside one parse-and-consume window.
        header_scratch_lent: bool,
        /// The serving path's render scratches, on exactly the terms
        /// `header_scratch` sets out and for the same measured reason:
        /// these are the locals the render path was still filling once the
        /// parse path stopped. See `proxy.RenderScratch` for what a render
        /// borrows and why one aggregate covers both hops.
        render_scratch: proxy.RenderScratch,
        /// Whether `render_scratch` is out on loan (see the field). Only
        /// ever true inside one render-and-send window.
        render_scratch_lent: bool,
        /// The §8 static responses in writable memory, because each now
        /// carries a `Date` slot (#234). Comptime-sized and held inline:
        /// a closed status set times two persistence variants, so this is
        /// a fixed field like `drain_sink`, not a budget the config can
        /// move.
        static_responses: shed.StaticTable,
        /// The one rendering of the current second every proxy-generated
        /// response is stamped from, and the second it renders. Cached
        /// because the calendar arithmetic is per-second work and the
        /// responses that need it arrive per-request; re-rendered lazily,
        /// on the first tick of a new second.
        ///
        /// Never read by a send — only ever copied *out of*, into a
        /// response's own slot — so unlike those slots this one is safe
        /// to rewrite at any moment.
        date_line: [shed.date_bytes]u8,
        date_second: u64,
        /// The `nowNs` tick this pair was last refreshed on, which is what
        /// keeps the wall clock *off* the per-response path (§9).
        ///
        /// `nowWallNs` is deliberately precise and deliberately uncached —
        /// it exists for access-log durations, where a coarse granule
        /// would report 0 µs and a per-tick cache would give every request
        /// in one batch the same start. Neither property is worth paying
        /// for here: a `Date` is a *second*, and a shed storm answers a
        /// whole completion batch from this one line. So the wall clock is
        /// read at most once per tick — §4 guarantees `nowNs` returns one
        /// value for the whole of a tick — rather than once per response,
        /// and what a batch of responses shares is a date that is at worst
        /// one tick old.
        date_tick_ns: u64,
        /// How many static responses are on the wire right now (#234):
        /// armed and not yet fully written, counting the whole span
        /// because a partial write re-arms on the same shared bytes.
        ///
        /// This is what makes patching a `Date` in place safe rather than
        /// merely conventional. A submitted send holds a pointer the
        /// kernel may read at any point before its completion, so a patch
        /// landing underneath one could put a torn date on the wire —
        /// nginx lives with exactly that race; this does not. A stamp
        /// happens only while this reads zero, so the bytes a send was
        /// handed can never change under it. The cost is the right way
        /// round: under a sustained shed storm the date goes *stale*,
        /// never malformed.
        ///
        /// A claim, not a tally: `Conn.static_send` records who holds one,
        /// so the release is a no-op wherever nothing was taken and the
        /// conn's own release path is the backstop. A leak would freeze
        /// the date silently, which is why `isIdle` asserts a drained
        /// server holds none.
        static_sends_inflight: u32,
        /// The #140 capture table: one value slot per connection slot per
        /// named header, and the length of each. A logged value is copied
        /// out of the head buffer while it is still live (the response
        /// render writes over it, §7 rotation) and read back when the
        /// line is written, so it needs storage that survives the awaits
        /// between — per connection, because that is the unit an
        /// in-flight request belongs to.
        ///
        /// A side table rather than fields on `Conn`, and the reason is
        /// the #179 precedent: sized by the config, so a deployment that
        /// names no headers allocates nothing and every `Conn` stays the
        /// width it was. Addressed by `conns.indexOf`, which is stable
        /// across reuse.
        log_header_values: []u8,
        log_header_lens: []u16,
        /// Named headers per connection — the config's two lists summed,
        /// zero when it named none. Stored because every index into the
        /// tables above is a multiple of it.
        log_headers_per_conn: u32,
        /// Highest armed-op count any one connection has reached (§8),
        /// counting both of its slots since #274: `Conn.arm` asserts the
        /// `conn_ops_max` budget and `Stream.arm` the `stream_ops_max`
        /// one, and both record this *combined* peak — which is the
        /// number the CQ is charged per admitted connection, and so the
        /// one that must not move when ops change slots. Under runtime
        /// safety only (Debug and ReleaseSafe — the shipped build is
        /// ReleaseSafe, see docs/IMPLEMENTATION_NOTES.md "Shipping
        /// ReleaseSafe"), so a test can claim a race co-armed exactly the
        /// budgeted worst case, not merely stayed under it.
        armed_ops_peak: u8,
        /// The stream half of that peak (#274), tracked beside it because
        /// the combined number cannot distinguish the two shapes the
        /// budget rests on: `stream_ops_max` is two only because a dial
        /// and the data legs are disjoint, and a seed that ever co-armed
        /// three stream ops would be a divisor that has to move. The
        /// assert in `Stream.arm` is what fails first; this is what a
        /// test reads to claim the peak was *reached*, not merely
        /// respected.
        stream_armed_ops_peak: u8,
        /// The raw errno of the most recent kernel-pressure failure, or 0
        /// (§8). Reported as a gauge rather than a counter because it is a
        /// level — "what is failing now" — and because an errno space is
        /// far too wide for a counter each.
        last_pressure_errno: u16,
        drain_deadline_completion: IoType.Completion,
        /// The backstop behind that deadline: a teardown that cannot
        /// finish has nothing else watching it (#203, `onDrainStuck`).
        drain_stuck_completion: IoType.Completion,
        /// The one timer covering every parked upstream (§5): a parked
        /// connection holds no armed op, so this sweep compares stored
        /// deadlines against the clock and reaps overdue connections with
        /// a synchronous close. Armed only while anything is parked, so
        /// an idle process (and a quiescent simulator run) has no ticking
        /// timer.
        upstream_sweep_completion: IoType.Completion,
        upstream_sweep_armed: bool,
        /// The dedicated admin/metrics listener (§8): one
        /// reserved scrape slot off the shared pools, budgeted separately
        /// (`constants.admin_*`). Off unless a bind is set before `start`.
        admin: admin_module.Admin(IoType),
        /// The access log (§8): one JSON line per exchange and per L4
        /// connection, off unless the config names a sink. It holds one
        /// ring op and two staging buffers, both reserved unconditionally
        /// in the budgets and allocated only when it is on.
        access_log: AccessLogType,
        /// The §7 active health prober: `config.healthProbes()` probes in
        /// flight, budgeted separately (`constants.health_probe_ops_max`
        /// each). Off unless a cluster sets `check`; its `healthy` mask
        /// is what the balancer picks through.
        health: health_module.Checker(IoType),

        const Self = @This();

        pub const ConnType = conn_module.Conn(IoType);
        pub const StreamType = ConnType.StreamType;
        pub const AccessLogType = access_log_module.AccessLog(IoType);
        const Proxy = proxy.Proxy(IoType);

        /// Pool sizes are injectable so tests and the simulator can force
        /// every exhaustion rung; production passes the config's resolved
        /// `limits` (§5) — one type, so a new limit cannot silently
        /// default in a hand-written bridge.
        pub const InitOptions = config_module.Config.Limits;

        const ListenerState = struct {
            server: *Self,
            listener: IoType.Listener,
            accept_completion: IoType.Completion,
            /// Backoff timer for kernel-pressure accept failures; never
            /// armed while the accept itself is armed, so the per-listener
            /// ring budget stays one op (§8).
            retry_completion: IoType.Completion,
            cluster_index: u16,
            /// The listener's §7 route table, handed to each admitted L7
            /// connection so `routeRequest` can pick a cluster by path.
            routes: []const router.Route,
            /// The §6 SNI table (#298); empty on every listener that does
            /// not route by name, which is what says the peek never runs.
            sni_routes: []const sni_router.Route,
            /// The listener's §7 request filter rules, handed to each
            /// admitted L7 connection so `routeRequest` can evaluate
            /// policy.
            request_filters: []const filter.Rule,
            /// The listener's #175 response filter rules, handed over the
            /// same way so the response re-render can apply its edits.
            response_filters: []const filter.ResponseRule,
            /// The listener's #180 upgrade allowlist, carried for the same
            /// reason as the tables above: an admitted connection asks its
            /// own socket what it may carry.
            upgrades: config_module.Config.Listener.Upgrades,
            max_body_bytes: u64,
            /// The listener's §7 client-address forwarding mode (null = off),
            /// handed over the same way: trust depends on what is in front
            /// of this socket, so it cannot live on the cluster.
            forwarded: ?config_module.Config.Listener.Forwarded,
            /// The listener's #300 opt-in: whether the pages this proxy
            /// renders itself name why they refused. Per listener for the
            /// same reason as `forwarded` — what may be said on the wire
            /// depends on who is in front of this socket.
            proxy_status: bool,
            /// Whether this listener binds a socket file (#303), so
            /// admission knows there is no peer address to ask for.
            /// Copied like everything else here rather than reached back
            /// through the config, on `installListenerState`'s reasoning.
            unix_bind: bool,
            /// The listener's PROXY protocol expectation (#142, null =
            /// first bytes are payload). Read at admission only — the
            /// receive phase is entered before the connection has any
            /// state of its own — so nothing is copied onto the conn.
            proxy_protocol: ?config_module.Config.Listener.ProxyProtocol,
            /// Copied from config so admission forks without reaching back
            /// through the listener index (§6, §7).
            protocol: config_module.Config.Listener.Protocol,
            /// This listener's certificate chain and signing key (§4), or
            /// null on a plaintext socket. Borrowed from the startup-lived
            /// table `setTlsCredentials` handed over, and shared by every
            /// engine this listener drives — a chain and a libcrypto key
            /// are parsed once per listener, never per connection.
            credentials: ?*const Credentials,
            accepting: bool,
        };

        /// The endpoint index space this config needs (§7): one row per
        /// cluster, each `stride` wide, where `stride` is the widest
        /// cluster the operator declared. Derived from the loaded config
        /// rather than from a compiled ceiling, so the tables cost what
        /// this deployment uses.
        pub fn endpointKeysFor(
            config: *const config_module.Config,
        ) upstream_module.EndpointKeys {
            assert(config.clusters.len >= 1);
            var stride: u16 = 1;
            for (config.clusters) |cluster| {
                assert(cluster.endpoints.len >= 1);
                stride = @max(stride, @as(u16, @intCast(cluster.endpoints.len)));
            }
            assert(stride >= 1);
            return .init(@intCast(config.clusters.len), stride);
        }

        /// What the endpoint-keyed tables take from the startup arena for
        /// this config (§5) — closed-form in the config, like every pool
        /// term, so the printed budget stays a prediction rather than a
        /// measurement. Every width comes from the owning module's own
        /// element type: a table that changes type changes this number
        /// without anyone remembering to.
        ///
        /// `init` below allocates exactly these, in this order.
        pub fn endpointTableBytes(config: *const config_module.Config) u64 {
            const keys = endpointKeysFor(config);
            const count: u64 = keys.count;
            const per_key =
                @sizeOf(u32) + // UpstreamPool.idle_heads
                @sizeOf(u16) + // UpstreamPool.leased_counts
                @sizeOf(u64) + // Balancer.endpoint_hashes
                @sizeOf(i64) + // Balancer.rr_current
                @sizeOf(u16) + // Server.l4_inflight
                @sizeOf(bool) + // Checker.healthy
                @sizeOf(u8) + // Checker.fail_streaks
                @sizeOf(u8); // Checker.ok_streaks
            const scratch = @as(u64, keys.stride) * @sizeOf(u16);
            const total = count * per_key + scratch;
            assert(total > 0);
            return total;
        }

        /// What the #179 labeled metrics take from the startup arena for
        /// this config (§5): the tables and prebuilt label strings, plus
        /// the two staging buffers sized to the full exposition — the
        /// admin response (head + counters + labeled) and the dump. Its
        /// own banner term rather than a fold into the endpoint tables,
        /// because the issue's whole point is that the cost of labelling
        /// your metrics should be visible next to everything else you
        /// pay for. `init` allocates exactly this.
        pub fn metricsBytes(config: *const config_module.Config) u64 {
            assert(config.clusters.len >= 1);
            const keys = endpointKeysFor(config);
            const tables = counters_module.Labeled.tableBytes(config, keys);
            const labeled_render = counters_module.Labeled.renderBytesMaxFor(config);
            const admin_response = admin_module.response_head.len +
                counters_module.Counters.render_bytes_max + labeled_render;
            const dump_staging =
                counters_module.Counters.render_bytes_max + labeled_render;
            const total = tables + admin_response + dump_staging;
            assert(total > 0);
            return total;
        }

        pub fn init(
            server: *Self,
            arena: std.mem.Allocator,
            io: *IoType,
            config: *const config_module.Config,
            options: InitOptions,
        ) error{OutOfMemory}!void {
            assert(config.listeners.len >= 1);
            assert(config.listeners.len <= std.math.maxInt(u16));
            // The deadline handoff depends on this ordering (§4/§5): a
            // connection's first deadline is armed at the connect budget
            // and `onConnect` re-stores it to the idle one, but the armed
            // timer never moves earlier — so an idle budget at or below the
            // dial budget fires late instead of shortening at the handoff.
            // The loader rejects it (`TimeoutOrderInvalid`); asserted again
            // here because the simulator and the tests build a `Config`
            // directly and would otherwise be measuring a config production
            // cannot load.
            assert(config.connect_timeout_ms < config.idle_timeout_ms);
            // The #235 head budget sits between the two, and its relations
            // matter here more than the pair above rather than less: every
            // hand-built config now states this field, so a test or a seed
            // that inverted it would silently reproduce the failure the
            // split exists to prevent — a head read left running under the
            // wider window — with no loader in the way to say so.
            assert(config.connect_timeout_ms < config.head_timeout_ms);
            assert(config.head_timeout_ms <= config.idle_timeout_ms);
            // `Pool` permits an empty pool — that is how an unconfigured
            // feature reserves nothing (§5) — so the requirement that these
            // three are non-empty lives here, where it is true: a proxy with
            // no conn slots, no relay buffers or no upstream slots cannot
            // serve a single request. `relay_buffers` was always checked
            // here; the other two move down from `Pool.init`.
            assert(options.conn_slots >= 1);
            assert(options.relay_buffers >= 1);
            assert(options.upstream_slots >= 1);
            assert(options.relay_buffers <= options.conn_slots);
            assert(options.head_buffers <= options.conn_slots);
            // The ring the backend registered and the limits this server
            // accounts against must agree — count and unit size both — or
            // the shed rung fires at a shape no config names. A zero
            // count is the L4-only shape; the size holds regardless,
            // because the health prober's buffer follows it too.
            assert(io.bufferGroupCount() == options.head_buffers);
            assert(io.bufferGroupBytes() == options.head_buffer_bytes);
            server.io = io;
            server.config = config;
            // The static answers, and the clock they will be stamped from
            // (#234). Seeded from the real clock here rather than left at
            // the epoch, because `currentDate` now re-reads the wall clock
            // only when the `nowNs` tick advances: a table stamped by
            // `initDateSlots` before the first advance must already hold a
            // real date, not 1970. The three fields are written together
            // so the line, the second it renders and the tick it was taken
            // on cannot disagree.
            server.static_responses.init();
            server.date_tick_ns = server.io.nowNs();
            server.date_second = server.nowUnix();
            shed.formatHttpDate(server.date_second, &server.date_line);
            server.static_sends_inflight = 0;
            server.initDateSlots();
            try server.conns.init(arena, options.conn_slots);
            // One stream per connection (#274). Derived rather than
            // configured, so the pair cannot drift apart in a
            // hand-written bridge the way two limits could.
            try server.streams.init(arena, constants.streamSlotsFor(options.conn_slots));
            assert(server.streams.capacity() == server.conns.capacity());
            try server.relay_buffers.init(arena, options.relay_buffers);
            try wireRelayHalves(arena, server.relay_buffers.slots, options.relay_buffer_bytes);
            try server.initTunnelBuffers(arena, &options);
            // One index space, derived once and shared by every
            // endpoint-keyed table so they cannot disagree about a key.
            const keys = endpointKeysFor(config);
            try server.upstreams.init(arena, options.upstream_slots, keys);
            assert(options.upstream_head_buffers <= options.upstream_slots);
            try server.upstream_head_buffers.init(arena, options.upstream_head_buffers);
            try server.initHeadBuffers(arena, &options);
            try server.initTlsEngines(arena, &options);
            server.l4_inflight = try arena.alloc(u16, keys.count);
            @memset(server.l4_inflight, 0);
            server.listeners = try arena.alloc(ListenerState, config.listeners.len);
            server.listeners_count = @intCast(config.listeners.len);
            // Empty until `setTlsCredentials`, which is before `start` when
            // there is anything to hand over and never otherwise.
            server.tls_credentials = &.{};
            // Dead until `start` draws a key: `init` runs in tests that
            // never start a loop, and a sealing key drawn here would be
            // one the Io seam had not been asked for.
            server.tls_tickets.init();
            try server.balancer.init(arena, config, keys);
            try server.initMetrics(arena, config, keys);
            server.resetRuntimeState(&options);
            try server.admin.init(server, config.admin_bind, arena);
            server.access_log.init(server, config.access_log_sink, options.access_log_buffer_bytes);
            try server.access_log.reserve(arena);
            try server.health.init(arena, server, keys, options.head_buffer_bytes);
        }

        /// The §5 upstream head slab wiring and the serving path's two
        /// canonicalization scratches — split from `init` for the length
        /// limit, called once right after the upstream head pool exists.
        fn initHeadBuffers(
            server: *Self,
            arena: std.mem.Allocator,
            options: *const InitOptions,
        ) error{OutOfMemory}!void {
            assert(server.upstream_head_buffers.slots.len == options.upstream_head_buffers);
            // The pool's slab, wired once: `Pool` never touches `data`,
            // so the wiring survives every acquire/release cycle.
            const upstream_head_slab = try arena.alloc(
                u8,
                @as(usize, options.upstream_head_buffers) * options.head_buffer_bytes,
            );
            // Deliberately not faulted in: pages become resident as
            // exchanges actually use them, so the printed §5 total is a
            // ceiling RSS approaches under load, never a startup floor
            // (IMPLEMENTATION_NOTES "lazy fault-in"). Nothing reads a
            // buffer byte it did not first write, so the content of a
            // fresh page is never observed.
            for (server.upstream_head_buffers.slots, 0..) |*head_buffer, index| {
                head_buffer.data =
                    upstream_head_slab[index * options.head_buffer_bytes ..][0..options.head_buffer_bytes];
            }
            // The serving path's canonicalization scratches (see the
            // fields): sized only where a head can exist to canonicalize.
            // `headScratchBytes` is the closed form the banner prints;
            // asserting the sum here is what keeps the two from drifting.
            const scratch_bytes: usize =
                if (options.head_buffers >= 1) options.head_buffer_bytes else 0;
            server.target_scratch = try arena.alloc(u8, scratch_bytes);
            server.rewrite_scratch = try arena.alloc(u8, scratch_bytes);
            // The prober's share is one head buffer per probe. Taken from
            // the config rather than from `server.health.probes`, which
            // `Checker.init` has not sized yet at this point in startup —
            // and which is sourced from this same `healthProbes()`, so
            // the two cannot disagree.
            const health_probes = server.config.healthProbes();
            const probe_scratch_bytes: u64 =
                @as(u64, health_probes) * options.head_buffer_bytes;
            assert(server.target_scratch.len + server.rewrite_scratch.len +
                probe_scratch_bytes == headScratchBytes(options.*, health_probes));
            try server.initLogHeaders(arena, options);
        }

        /// Lend the serving path's header scratch for one parse and the
        /// window that reads it (§7: nothing parsed survives its callback,
        /// so that window ends where the callback does — hence the `defer
        /// returnHeaderScratch` at every call site).
        ///
        /// The assert is the whole safety argument. A borrow that outlives
        /// its parse was always wrong; what is new is that a *second*
        /// borrow taken while the first is live would hand two parses the
        /// same array, and the first one's `headers` slice would change
        /// under it. Nothing reaches that today, and this is what says so
        /// if something ever does.
        pub fn borrowHeaderScratch(server: *Self) *parser.HeaderStorage {
            assert(!server.header_scratch_lent);
            server.header_scratch_lent = true;
            return &server.header_scratch;
        }

        /// Return what `borrowHeaderScratch` lent. The bytes stay as the
        /// parse left them: the next borrow overwrites the prefix it fills
        /// and reads no further, which is what makes one buffer reusable
        /// without a clear between loans.
        pub fn returnHeaderScratch(server: *Self) void {
            assert(server.header_scratch_lent);
            server.header_scratch_lent = false;
        }

        /// Lend the serving path's render scratches for one head render
        /// and the send it feeds. The window ends where the callback does,
        /// same as the header scratch, and for the same §7 reason: the
        /// rendered bytes are copied into the upstream head buffer (or the
        /// client's) before this returns, so nothing here outlives it.
        ///
        /// A request render and a response render are each reached from
        /// their own completion callback and neither suspends, so the two
        /// are never live together — which is what lets one aggregate
        /// serve both hops. The assert is what says so if that changes.
        pub fn borrowRenderScratch(server: *Self) *proxy.RenderScratch {
            assert(!server.render_scratch_lent);
            server.render_scratch_lent = true;
            return &server.render_scratch;
        }

        /// Return what `borrowRenderScratch` lent (see `returnHeaderScratch`
        /// for why the bytes are left as they are).
        pub fn returnRenderScratch(server: *Self) void {
            assert(server.render_scratch_lent);
            server.render_scratch_lent = false;
        }

        /// Wire a relay pool's halves onto a slab (§5). `Pool` never
        /// touches these fields, so one pass at init holds for every
        /// acquire/release afterwards — the same contract
        /// `initHeadBuffers` relies on.
        ///
        /// Deliberately not faulted in: pages become resident as relays
        /// actually use them, so the printed §5 total stays a ceiling RSS
        /// approaches under load rather than a startup floor
        /// (IMPLEMENTATION_NOTES "lazy fault-in"). Nothing reads a byte it
        /// did not first write, so a fresh page's content is never seen.
        fn wireRelayHalves(
            arena: std.mem.Allocator,
            slots: []relay.RelayBuffer,
            relay_buffer_bytes: u32,
        ) error{OutOfMemory}!void {
            assert(relay_buffer_bytes >= constants.relay_buffer_bytes_min);
            assert(relay_buffer_bytes <= constants.relay_buffer_bytes_max);
            if (slots.len == 0) {
                return;
            }
            const half: usize = @as(usize, relay_buffer_bytes);
            const slab = try arena.alloc(u8, slots.len * 2 * half);
            for (slots, 0..) |*buffer, index| {
                const base = index * 2 * half;
                buffer.client_to_upstream = slab[base..][0..half];
                buffer.upstream_to_client = slab[base + half ..][0..half];
            }
            assert(slots[slots.len - 1].upstream_to_client.len == half);
        }

        /// The §5 tunnel pool (#180), split from `init` for the length
        /// limit like `initHeadBuffers` beside it.
        ///
        /// A second pool of the *same element* as `relay_buffers`, and the
        /// separation is the feature rather than an implementation
        /// detail: a tunnel holds its buffer for the connection's whole
        /// life, so sharing one reservation with traffic sized for
        /// concurrent activity would let long-lived sessions consume what
        /// ordinary requests shed against. Zero slots is a deployment
        /// that allows no upgrade, which is what `Pool`'s zero-slot
        /// support is for.
        fn initTunnelBuffers(
            server: *Self,
            arena: std.mem.Allocator,
            options: *const InitOptions,
        ) error{OutOfMemory}!void {
            // A tunnel is an accepted client connection holding one of
            // these, so a pool past the connections that could hold one is
            // unreachable capacity — and the fd and ring budgets are
            // derived from `conn_slots` on the strength of that bound
            // (§5), so this is the assert those budgets rest on. The
            // loader refuses the config-level version of the same rule.
            assert(options.tunnels <= options.conn_slots);
            try server.tunnel_buffers.init(arena, options.tunnels);
            assert(server.tunnel_buffers.slots.len == options.tunnels);
            try wireRelayHalves(arena, server.tunnel_buffers.slots, options.relay_buffer_bytes);
        }

        /// The §4 engine pool and the one slab its plaintext destinations
        /// carve out of. Both are empty on a deployment where no listener
        /// terminates TLS — the whole feature reserving nothing, which is
        /// what `limits.tls_engines == 0` means and what `Pool`'s
        /// zero-slot support is for.
        fn initTlsEngines(
            server: *Self,
            arena: std.mem.Allocator,
            options: *const InitOptions,
        ) error{OutOfMemory}!void {
            assert(options.tls_engines <= options.conn_slots);
            try server.tls_engines.init(arena, options.tls_engines);
            if (options.tls_engines == 0) {
                return;
            }
            // One buffer per slot, sized by the engine's own closed form —
            // the same call `main`'s banner makes, which is what keeps the
            // printed §5 total and this reservation the same number.
            // Two destinations per slot: the head (which the response head
            // renders back over) and the request body, which §7 lets run
            // concurrently with it. `plaintextBytesFor` prices the pair.
            const plaintext_bytes = TlsEngine.plaintextBytesFor(options.head_buffer_bytes);
            const head_slice_bytes = plaintext_bytes - TlsEngine.plaintext_bytes_min;
            const slab = try arena.alloc(
                u8,
                @as(usize, options.tls_engines) * plaintext_bytes,
            );
            // Not faulted in, like the upstream head slab beside it: pages
            // become resident as sessions actually use them, so the printed
            // total is a ceiling RSS approaches under load rather than a
            // startup floor. Nothing reads a byte it did not first write.
            for (server.tls_engines.slots, 0..) |*engine, index| {
                const slot = slab[index * plaintext_bytes ..][0..plaintext_bytes];
                engine.bindPlaintext(
                    slot[0..head_slice_bytes],
                    slot[head_slice_bytes..],
                    // The slice is as wide as a decrypt needs; the *limit*
                    // is the operator's, and they are different numbers
                    // whenever the config sits below the engine's floor.
                    options.head_buffer_bytes,
                );
            }
            assert(server.tls_engines.slots.len == options.tls_engines);
        }

        /// The #140 capture table, sized by the config's named headers
        /// times the stream slots that can each hold one request's
        /// worth (#274: the captures share `LogState`'s unit, and that
        /// is the slot it lives on). Both allocations are empty when no header is named,
        /// which is what makes the feature free to a deployment that
        /// does not use it.
        fn initLogHeaders(
            server: *Self,
            arena: std.mem.Allocator,
            options: *const InitOptions,
        ) error{OutOfMemory}!void {
            const per_conn = logHeadersPerConn(server.config);
            server.log_headers_per_conn = per_conn;
            // One slice per *stream* slot (#274): the captures share
            // `LogState`'s unit, and that is the slot the line lives on.
            // Pinned 1:1 to the conn count, so the reservation is the
            // number the §5 banner has always printed.
            const stream_slots = constants.streamSlotsFor(options.conn_slots);
            const slots: usize = @as(usize, stream_slots) * per_conn;
            server.log_header_values = try arena.alloc(
                u8,
                slots * constants.access_log_header_bytes_max,
            );
            server.log_header_lens = try arena.alloc(u16, slots);
            @memset(server.log_header_lens, 0);
            assert(server.log_header_values.len ==
                logHeaderBytes(server.config, stream_slots) -
                    server.log_header_lens.len * @sizeOf(u16));
        }

        /// The metrics state (§8, #179): the process totals, the labeled
        /// tables, and the dump staging sized to the full exposition.
        /// Split from `init` for the length limit; `admin.init` depends
        /// on the labeled render bound this establishes.
        fn initMetrics(
            server: *Self,
            arena: std.mem.Allocator,
            config: *const config_module.Config,
            keys: upstream_module.EndpointKeys,
        ) error{OutOfMemory}!void {
            assert(keys.count >= 1);
            server.counters = .{};
            try server.labeled.init(arena, config, keys);
            server.dump_buffer = try arena.alloc(
                u8,
                counters_module.Counters.render_bytes_max + server.labeled.render_bytes_max,
            );
            assert(server.dump_buffer.len > counters_module.Counters.render_bytes_max);
        }

        /// Every runtime scalar `init` owes a first value — the flags,
        /// levels, peaks and embedded completions. Split from `init` for
        /// the length limit; allocation-free by construction.
        fn resetRuntimeState(server: *Self, options: *const InitOptions) void {
            server.draining = false;
            server.relay_pressure = false;
            server.conn_pressure = false;
            server.upstream_pressure = false;
            server.head_pressure = false;
            server.head_buffers_in_use = 0;
            server.head_buffers_capacity = options.head_buffers;
            server.upstream_head_pressure = false;
            // Deliberately not zeroed: a discard sink's contents are never
            // read, the same argument the head buffers make (§5).
            server.drain_sink = undefined;
            // Same argument, and the reason the scratch exists: every parse
            // writes the prefix it then reads. The one fill this costs is
            // this one, at startup, instead of one per parse.
            server.header_scratch = undefined;
            server.header_scratch_lent = false;
            server.render_scratch = undefined;
            server.render_scratch_lent = false;
            server.armed_ops_peak = 0;
            server.stream_armed_ops_peak = 0;
            server.last_pressure_errno = 0;
            server.drain_deadline_completion = .{};
            server.drain_stuck_completion = .{};
            server.upstream_sweep_completion = .{};
            server.upstream_sweep_armed = false;
            assert(!server.draining);
            assert(server.head_buffers_in_use == 0);
        }

        /// Override the admin/metrics bind before `start` — the simulator
        /// and tests set it directly; production seeds it from the config's
        /// `admin` block in `init`. Must be called before `start`.
        pub fn setAdminBind(server: *Self, bind_address: std.Io.net.IpAddress) void {
            server.admin.setBind(bind_address);
        }

        /// Hand over the per-listener TLS credentials before `start` (§4).
        /// A setter rather than an `init` argument because loading them
        /// reads files, and everything below the Io seam — this file
        /// included — is written not to: `main` reads, this holds.
        ///
        /// The table must outlive the server: every engine on a listener
        /// borrows that listener's entry for the session's life.
        pub fn setTlsCredentials(server: *Self, credentials: []const ?Credentials) void {
            assert(credentials.len == server.config.listeners.len);
            server.tls_credentials = credentials;
        }

        /// This listener's credentials, or null where it is plaintext or
        /// none were handed over. Borrowed from the caller's table, so the
        /// pointer is to the entry rather than to a copy: a `Credentials`
        /// holds a libcrypto key object, and two copies pointing at one
        /// key would be two owners of something with a single `deinit`.
        fn credentialsFor(server: *Self, index: usize) ?*const Credentials {
            if (index >= server.tls_credentials.len) return null;
            if (server.tls_credentials[index]) |*entry| return entry;
            return null;
        }

        /// Draw a sealing key, which is what turns resumption on (§4).
        ///
        /// At `start` rather than `init` for the same reason the engine
        /// seeds are drawn where they are: the key has to come through the
        /// Io seam, so that a seeded run's tickets are part of what it
        /// replays (§9). Nothing here decides *whether* to draw — a
        /// deployment with no terminating listener simply never asks an
        /// engine for one, and two unused keys are 64 bytes.
        fn installTicketKey(server: *Self) void {
            var key: [Tickets.key_bytes]u8 = undefined;
            server.io.fillRandom(&key);
            server.tls_tickets.rotate(key, server.nowUnix());
            assert(server.tls_tickets.ready());
        }

        /// Replace the sealing key if it has been sealing for its whole
        /// interval (#202). Asked here, at the one place a key is used to
        /// seal, rather than on a timer — see `tls/Tickets.zig` for why
        /// that is the bound worth holding and the cheaper one to hold.
        fn maybeRotateTicketKey(server: *Self) void {
            // Reached only from the seal, which the caller has already
            // established has a key to seal with.
            assert(server.tls_tickets.ready());
            if (!server.tls_tickets.dueForRotation(
                server.nowUnix(),
                constants.tls_ticket_key_rotation_s,
            )) return;
            server.installTicketKey();
            server.counters.increment("tls_ticket_keys_rotated");
            assert(!server.tls_tickets.dueForRotation(
                server.nowUnix(),
                constants.tls_ticket_key_rotation_s,
            ));
        }

        /// The §8 wall clock in seconds, which is what a ticket's issue
        /// time and its key's sealing clock are both measured on.
        fn nowUnix(server: *const Self) u64 {
            return @divFloor(server.io.nowWallNs(), std.time.ns_per_s);
        }

        /// The current second as a `Date` value (#234). Safe to call at
        /// any moment: nothing sends these bytes, they are only ever
        /// copied into a response's own slot.
        ///
        /// Two nested caches, and the outer one is the point. The inner
        /// skips the calendar arithmetic while the second has not turned
        /// over; the outer skips the *clock read itself* while the tick
        /// has not. Without it a shed storm — the load this path exists
        /// for (§8) — would pay one precise `CLOCK_REALTIME` read per
        /// response, on the path that is otherwise one send from memory
        /// that is neither assembled nor copied. `nowNs` is the coarse,
        /// tick-cached clock §4 already refreshes once per tick, so the
        /// gate costs a load and a compare and a whole completion batch
        /// reads the wall clock once between them.
        pub fn currentDate(server: *Self) *const [shed.date_bytes]u8 {
            const tick_ns = server.io.nowNs();
            if (tick_ns != server.date_tick_ns) {
                server.date_tick_ns = tick_ns;
                const second = server.nowUnix();
                if (second != server.date_second) {
                    shed.formatHttpDate(second, &server.date_line);
                    server.date_second = second;
                }
            }
            // Both caches, stated as the cheap invariants they are — this
            // runs per response in a ReleaseSafe binary, so an assertion
            // that re-rendered the line to compare it would cost more than
            // the clock read this function exists to avoid.
            assert(server.date_tick_ns == tick_ns);
            // Seeded from a real clock at `init` and only ever moved
            // forward by one, so a zero here means a slot is about to be
            // stamped from a second nothing measured.
            assert(server.date_second >= 1);
            return &server.date_line;
        }

        /// Stamp a *shared* static response's `Date` slot — the one thing
        /// `currentDate` is not enough for, because those bytes may be
        /// under a submitted send (#234).
        ///
        /// The whole rule is the early return: with a send outstanding,
        /// the kernel may read this slot at any moment before its
        /// completion, so the response goes out carrying whatever second
        /// it was last stamped with. That is a stale `Date`, which is
        /// legal and honest; patching anyway would risk a torn one, which
        /// is neither.
        pub fn stampStaticDate(server: *Self, slot: *[shed.date_bytes]u8) void {
            if (server.static_sends_inflight != 0) {
                server.counters.increment("l7_static_date_stale");
                return;
            }
            @memcpy(slot, server.currentDate());
            // Startup stamped every slot, and nothing writes one but this,
            // so a placeholder surviving a stamp is impossible — said here
            // because it is the property the wire depends on, and the one a
            // future slot that escaped `initDateSlots` would break.
            assert(!std.mem.eql(u8, slot, shed.date_placeholder));
        }

        /// Stamp every shared `Date` slot with the second the server
        /// started (#234) — the static table's, and every #159 page the
        /// config rendered.
        ///
        /// Without this, a slot's *first* use could fall while some other
        /// static send was in flight, and `stampStaticDate` would rightly
        /// decline to patch it — putting the un-stamped placeholder on the
        /// wire, which is not a date at all. Here nothing is in flight by
        /// construction, so every slot holds a real one from the first
        /// response onward and the in-flight rule can only ever cost
        /// freshness, which is what it was chosen to cost.
        ///
        /// The pages are reached through the config rather than through a
        /// list the loader hands over, because the simulator and the
        /// directed tests build their `Config` by hand: a list would be a
        /// field they could each forget, and the walk cannot be.
        fn initDateSlots(server: *Self) void {
            // Nothing has been served yet, which is exactly what makes this
            // the one moment a slot can be written unconditionally.
            assert(server.static_sends_inflight == 0);
            const now = server.currentDate();
            server.static_responses.stampAll(now);
            for (server.config.error_pages) |page| {
                @memcpy(page.keep_date, now);
                @memcpy(page.close_date, now);
            }
            // A `respond` action's page is shared with every other
            // reference to the same body and status (#159), so a page
            // reached twice is stamped twice with the same bytes.
            for (server.config.listeners) |listener| {
                for (listener.request_filters) |rule| {
                    for (rule.actions) |action| {
                        switch (action) {
                            .respond => |page| {
                                @memcpy(page.keep_date, now);
                                @memcpy(page.close_date, now);
                            },
                            else => {},
                        }
                    }
                }
            }
        }

        /// Take the claim that says this connection's pending write is
        /// reading shared static bytes (#234). Paired with
        /// `releaseStaticSend`, which every path out of that write runs.
        pub fn claimStaticSend(server: *Self, conn: *ConnType) void {
            // One write at a time per connection (`armClientWrite`), so a
            // conn already holding one would mean two are in flight.
            assert(!conn.stream.static_send);
            conn.stream.static_send = true;
            server.static_sends_inflight += 1;
            assert(server.static_sends_inflight <= server.conns.capacity());
        }

        /// Hand back the claim, if this connection holds one. A no-op
        /// otherwise, so the paths that end a write do not each re-test
        /// what they were writing — and so the connection's own release
        /// can be the backstop for the ones that end it abruptly.
        pub fn releaseStaticSend(server: *Self, conn: *ConnType) void {
            if (!conn.stream.static_send) {
                return;
            }
            conn.stream.static_send = false;
            assert(server.static_sends_inflight >= 1);
            server.static_sends_inflight -= 1;
        }

        pub fn start(server: *Self) Io.ListenError!void {
            assert(!server.draining);
            assert(server.listeners_count >= 1);
            server.installTicketKey();
            for (server.config.listeners, 0..) |listener_config, index| {
                const state = &server.listeners[index];
                state.* = .{
                    .server = server,
                    .listener = try server.io.listen(
                        &listener_config.bind_address,
                        listener_config.bind_mode,
                    ),
                    .accept_completion = .{},
                    .retry_completion = .{},
                    // L4 has one route (the whole listener → one cluster);
                    // L7 admits under the first route and refines to the
                    // path's route once the head parses (§7).
                    .cluster_index = listener_config.routes[0].cluster_index,
                    .routes = listener_config.routes,
                    .sni_routes = listener_config.sni_routes,
                    .upgrades = listener_config.upgrades,
                    .max_body_bytes = listener_config.max_body_bytes,
                    .request_filters = listener_config.request_filters,
                    .response_filters = listener_config.response_filters,
                    .forwarded = listener_config.forwarded,
                    .proxy_status = listener_config.proxy_status,
                    .proxy_protocol = listener_config.proxy_protocol,
                    .unix_bind = listener_config.bind_address == .unix,
                    .protocol = listener_config.protocol,
                    .credentials = server.credentialsFor(index),
                    .accepting = false,
                };
                // A listener the config says terminates TLS must have
                // credentials by now: `main` loads them before `start`, and
                // starting without them would bind a socket that answers
                // every handshake with a teardown.
                assert((listener_config.tls != null) == (state.credentials != null));
                server.armAccept(state);
            }
            try server.admin.start();
            server.health.start();
            server.io.signalWait(Self, server, onSignal);
        }

        /// Drain, not just death (§8): close listeners (armed accepts
        /// cancel), let admitted work finish under one server-owned drain
        /// timer, stop when the pools drain. A per-conn deadline clamp
        /// would not work: a lazily re-armed timer never notices a
        /// deadline moving *earlier* (§4) — so stragglers are reaped by
        /// this one timer instead.
        pub fn beginDrain(server: *Self) void {
            if (server.draining) return;
            server.draining = true;
            for (server.listeners[0..server.listeners_count]) |*state| {
                server.io.listenClose(state.listener);
            }
            // The admin listener stops accepting and any in-flight scrape
            // is torn down under the same drain (§8).
            server.admin.beginDrain();
            // The prober stops too: a drain has no routing decisions left
            // for its verdicts to inform, and its armed ops must drain
            // before the loop may stop (§8).
            server.health.beginStop();
            // Parked upstreams are idle capacity; the drain sheds them
            // first (§8). Synchronous closes: no armed op to wait for.
            server.reapParked(true);
            // A zero deadline is "no cap" (§5): the drain waits for the
            // last connection however long that takes, which is what
            // nginx, HAProxy and Caddy all do by default. Whoever sent
            // the signal owns the upper bound — systemd's
            // `TimeoutStopSec`, Kubernetes' `terminationGracePeriodSeconds`
            // — and answers a drain that will not end with SIGKILL. Not
            // arming the timer is what makes that true rather than
            // merely documented.
            if (server.config.drain_deadline_ms != 0) {
                server.io.timerStart(
                    &server.drain_deadline_completion,
                    @as(u64, server.config.drain_deadline_ms) * std.time.ns_per_ms,
                    Self,
                    server,
                    onDrainDeadline,
                );
                server.armDrainWatchdog();
            } else {
                if (server.tunnel_buffers.slots.len >= 1) {
                    // A zero deadline says "wait for the last connection",
                    // and a tunnel has no message boundary to be the last
                    // thing it does — so one idle session would hold the
                    // drain open until the supervisor's SIGKILL, turning a
                    // millisecond drain into every rolling restart waiting
                    // out `TimeoutStopSec` (§8, #180). Tunnels alone are
                    // bounded here; `drain_deadline_ms` keeps its exact
                    // present meaning for every other connection, which is
                    // why this arms only when the branch above did not.
                    //
                    // The same completion the configured deadline would have
                    // used, so the ring budget is unchanged: the two are
                    // mutually exclusive by construction.
                    // Mutually exclusive with the branch above by
                    // construction, and stated so: both arm the same
                    // completion, and arming it twice would double-arm a
                    // ring op the drain then has to account for.
                    assert(server.config.drain_deadline_ms == 0);
                    server.io.timerStart(
                        &server.drain_deadline_completion,
                        @as(u64, constants.tunnel_drain_ms) * std.time.ns_per_ms,
                        Self,
                        server,
                        onTunnelDrainDeadline,
                    );
                }
            }
            server.maybeStopAfterDrain();
        }

        /// The #180 tunnel-only drain bound fired: cut the tunnels and
        /// leave everything else alone.
        ///
        /// The difference from `onDrainDeadline` is the whole point of
        /// having a second handler. That one tears down every live
        /// connection because the operator named a deadline for the
        /// drain; this one fires when they named *none*, so it may only
        /// end the connections that can never end themselves. An ordinary
        /// exchange still finishes on its own terms, and a zero
        /// `drain_deadline_ms` still means what it has always meant for
        /// it.
        fn onTunnelDrainDeadline(server: *Self, result: Io.TimerError!void) void {
            assert(server.draining);
            assert(server.config.drain_deadline_ms == 0);
            // Nothing ever cancels this timer, the same as its sibling.
            result catch unreachable;
            for (server.conns.slots) |*conn| {
                if (!server.conns.isAcquired(conn)) continue;
                if (conn.state != .relaying) continue;
                // Relaying and holding a tunnel: an L4 connection is also
                // `.relaying` and is deliberately untouched, because it
                // *can* end on its own when its peers do.
                if (conn.tunnel_buffer == null) continue;
                if (conn.isTearingDown()) continue;
                server.counters.increment("tunnels_drained");
                server.beginTeardown(conn);
            }
            server.maybeStopAfterDrain();
        }

        fn onDrainDeadline(server: *Self, result: Io.TimerError!void) void {
            assert(server.draining);
            // Nothing ever cancels the drain timer.
            result catch unreachable;
            for (server.conns.slots) |*conn| {
                if (server.conns.isAcquired(conn)) {
                    if (conn.state != .tearing_down) {
                        server.counters.increment("drained_at_deadline");
                        server.beginTeardown(conn);
                    }
                }
            }
            // Tearing a connection down does not finish it: `continueTeardown`
            // waits for every armed op, and an op the backend never delivers
            // leaves the slot unreleasable forever. The deadline above fires
            // once and skips anything already tearing down, so that state has
            // no backstop at all — the process simply never exits, and SIGTERM
            // stops meaning anything (#203).
            //
            // Waiting longer cannot help a teardown that cannot finish, so
            // this one reports rather than waits again.
            server.io.timerStart(
                &server.drain_stuck_completion,
                drain_stuck_grace_ns,
                Self,
                server,
                onDrainStuck,
            );
        }

        /// The last line of defence under the two timers above (#226).
        ///
        /// Both of them are ops the loop delivers, which makes them blind
        /// to the one failure they would most like to report: a backend
        /// that has stopped delivering has stopped delivering *them*, so
        /// the process hangs and SIGTERM stops meaning anything — with not
        /// even the diagnostic `onDrainStuck` exists to print. #203 was
        /// that shape on a real runner, and #206's simulator reproduces it
        /// on demand by stranding a timer.
        ///
        /// The seam's alarm is not an op. In production it is `alarm(2)`:
        /// the kernel raises SIGALRM whatever this process is doing, and
        /// the handler writes one line and exits without re-entering the
        /// loop. So this fires *whether or not anything else can*.
        ///
        /// Armed here rather than beside `onDrainStuck`, deliberately —
        /// that timer is started by the deadline one, so arming the
        /// watchdog there would make it depend on the very delivery it is
        /// the backstop for.
        ///
        /// Only when a deadline is configured. A zero `drain_deadline_ms`
        /// is "no cap" (§5): the operator asked for a drain that waits for
        /// the last connection however long it takes, and killing that
        /// process after a bound it never named would be this proxy
        /// overruling a configuration rather than backstopping it. Whoever
        /// declined the cap owns the SIGKILL, which is #220's lesson in
        /// the other direction.
        fn armDrainWatchdog(server: *Self) void {
            assert(server.draining);
            assert(server.config.drain_deadline_ms != 0);
            const deadline_ns = @as(u64, server.config.drain_deadline_ms) *
                std.time.ns_per_ms;
            server.io.alarmStart(
                deadline_ns + drain_stuck_grace_ns + drain_watchdog_margin_ns,
                drain_watchdog_exit_code,
            );
        }

        /// How long past the point `onDrainStuck` would have reported the
        /// watchdog waits, so a live loop always gets to say the useful
        /// thing first. Generous because the two answers are not equal: a
        /// named plane and its armed ops is worth waiting for, and this
        /// line can only ever say that nobody said anything.
        const drain_watchdog_margin_ns: u64 = 5 * std.time.ns_per_s;

        /// Distinct from `drain_stuck_exit_code` because the two describe
        /// different failures, and an operator reading a status without
        /// output has only this to go on: 4 means the drain could not
        /// finish and the process said which plane held it, 5 means the
        /// loop stopped answering and nothing could be said at all.
        pub const drain_watchdog_exit_code: u8 = 5;

        /// How long after the drain deadline a teardown gets to finish
        /// before it is called stuck. Generous against the work it covers —
        /// every torn-down connection has only its armed ops to deliver, no
        /// I/O it could still be waiting on a peer for — so reaching this is
        /// a defect rather than a slow machine.
        const drain_stuck_grace_ns: u64 = 5 * std.time.ns_per_s;

        /// Distinct from every ordinary exit so a supervisor can tell "the
        /// drain failed" from "the config was bad" without parsing output.
        pub const drain_stuck_exit_code: u8 = 4;

        /// The drain could not finish. Say what it is waiting on and stop.
        ///
        /// Exiting rather than force-releasing: a slot with an armed op is
        /// still referenced by that op, and releasing it is precisely the
        /// corruption the generation counter exists to catch (§5). The
        /// honest move is to report and go, with a status that says the
        /// drain failed — an operator's process manager gets an answer
        /// instead of a hang, and the report names the connection and the
        /// ops it is stuck on rather than leaving it to be guessed.
        fn onDrainStuck(server: *Self, result: Io.TimerError!void) void {
            assert(server.draining);
            result catch unreachable;
            // The ordinary case: everything finished inside the grace and
            // the loop is already stopping. Ask the same *four* questions
            // `maybeStopAfterDrain` does, not just the first — asking only
            // about conn slots is how the first version of this reported
            // "nothing stuck" while the admin plane held an armed accept
            // that would never be delivered (#203).
            const conns_done = server.conns.isFullyReleased();
            const admin_done = server.admin.isQuiescent();
            const log_done = server.access_log.isQuiescent();
            const health_done = server.health.isQuiescent();
            if (conns_done and admin_done and log_done and health_done) return;
            // The forensics are for an operator reading the last thing
            // this process will ever say. A gate that provokes this path
            // on purpose wants none of them: stderr from a passing step
            // makes the build runner print "failed command" under a build
            // that exited zero, which costs a reader more than the lines
            // are worth. What the gate asserts is the part with teeth —
            // that the give-up happened, with the code that names it, and
            // that the plane it blames is the one that is actually stuck.
            if (server.io.wantsOperatorDump()) {
                server.reportStuckDrain(conns_done, admin_done, log_done, health_done);
            }
            // Through the seam, not `std.process.exit`: a raw exit here
            // would be a syscall outside `src/io/` (§4), and — the reason
            // that matters — it would make this the one branch no gate
            // could ever enter, since taking the exit takes the test
            // process with it.
            server.io.abort(drain_stuck_exit_code);
        }

        /// What an operator gets from a process that is about to stop
        /// existing: which of the four planes never finished, what every
        /// still-held connection slot was waiting on, and the counters.
        /// Split from the decision above so that decision stays readable,
        /// and because a gate provoking this path wants the give-up
        /// without the forensics (`wantsOperatorDump`).
        fn reportStuckDrain(
            server: *const Self,
            conns_done: bool,
            admin_done: bool,
            log_done: bool,
            health_done: bool,
        ) void {
            assert(!(conns_done and admin_done and log_done and health_done));
            std.debug.print(
                "zoxy: drain did not finish {d}s after its deadline (#203). " ++
                    "conns={s} admin={s} access_log={s} health={s}\n",
                .{
                    drain_stuck_grace_ns / std.time.ns_per_s,
                    if (conns_done) "done" else "STUCK",
                    if (admin_done) "done" else "STUCK",
                    if (log_done) "done" else "STUCK",
                    if (health_done) "done" else "STUCK",
                },
            );
            for (server.conns.slots, 0..) |*conn, index| {
                if (!server.conns.isAcquired(conn)) continue;
                std.debug.print(
                    "  slot {d}: state={t} armed={d} " ++
                        "(c2u={} u2c={} connect={} connect_cancel={} " ++
                        "deadline={} deadline_cancel={}) tls={}\n",
                    .{
                        index,
                        conn.state,
                        conn.armedCount() + conn.stream.armedCount(),
                        conn.stream.armed.data_client_to_upstream,
                        conn.stream.armed.data_upstream_to_client,
                        conn.stream.armed.connect,
                        conn.stream.armed.connect_cancel,
                        conn.armed.deadline,
                        conn.armed.deadline_cancel,
                        conn.tls != null,
                    },
                );
            }
            server.dumpMetrics();
        }

        fn onSignal(server: *Self, signal: Io.Signal) void {
            switch (signal) {
                .terminate => server.beginDrain(),
                .reopen_log => server.access_log.requestReopen(),
            }
        }

        /// The §8 exit tally: the exact exposition the scrape serves —
        /// counters then the labeled breakdown — through the same two
        /// renderers, so the dump and the endpoint can never disagree on
        /// the wire format. Staged in the arena buffer sized for both at
        /// init; one print, so the two halves cannot interleave with
        /// other stderr writers.
        ///
        /// Blocking, and that is now a property of *where it runs* rather
        /// than a hazard (#310). SIGUSR1 used to call it from a live loop,
        /// which is what #310 was — a dump that reached 1.6 MB on a stderr
        /// pipe parked the whole proxy in one `writev`. The signal no
        /// longer carries this; `/metrics` does, framed as a response and
        /// non-blocking.
        ///
        /// The two callers left are both past the point a stall can cost
        /// anything, for two *different* reasons:
        ///
        ///   - `main` prints the final tally after `run` has returned, so
        ///     there is no loop to park and no op that could complete.
        ///   - `reportStuckDrain` runs immediately before an unconditional
        ///     `abort`: the process is already committed to a hard exit,
        ///     so there is no serving left to delay. And a stall there is
        ///     bounded rather than open-ended — the alarm watchdog
        ///     (`armDrainWatchdog`) is not an op the loop delivers, so it
        ///     fires through a blocked `writev` and ends the process.
        ///     Deliberately *not* the argument that the loop has stopped
        ///     delivering: `onDrainStuck` is itself a timer completion the
        ///     loop delivered, which is the whole reason the alarm exists
        ///     beside it (#226).
        ///
        /// Called *once* per process either way, which is what keeps the
        /// output honest: Prometheus exposition is a snapshot, so two of
        /// them concatenated repeat every series and parse as neither.
        pub fn dumpMetrics(server: *const Self) void {
            assert(server.dump_buffer.len >= counters_module.Counters.render_bytes_max);
            const snapshot = server.gauges();
            const text = server.counters.render(&snapshot, server.dump_buffer);
            const views = server.labeledViews();
            const labeled_text =
                server.labeled.render(&views, server.dump_buffer[text.len..]);
            assert(text.len + labeled_text.len <= server.dump_buffer.len);
            std.debug.print("{s}{s}", .{ text, labeled_text });
        }

        /// The live views the labeled gauges read at render time (§8,
        /// #179): the same load view the balancer picks through and the
        /// same mask the prober owns — borrowed at the moment of the
        /// scrape, so a labeled level can never drift from the truth its
        /// owner holds.
        pub fn labeledViews(server: *const Self) counters_module.Labeled.LiveViews {
            return .{
                .load = server.endpointLoad(),
                .healthy = server.health.healthy,
            };
        }

        pub fn maybeStopAfterDrain(server: *Self) void {
            if (!server.draining) return;
            if (!server.conns.isFullyReleased()) return;
            // An in-flight scrape holds no pool slot but does hold an armed
            // op and the admin fd; the loop must not stop until it drains.
            if (!server.admin.isQuiescent()) return;
            // Nor until the access log has flushed: the lines describing
            // the drain are the ones an operator is most likely to be
            // reading, and stopping the loop over an armed sink write
            // would lose exactly those (§8).
            if (!server.access_log.isQuiescent()) return;
            // Same rule for the prober's armed ops (§8).
            if (!server.health.isQuiescent()) return;
            // Every stream released ahead of the conn that owned it
            // (#274, `continueTeardown`), and the check above says every
            // conn is gone — so an outstanding stream here is the split's
            // own leak, one layer below the one this enumeration was
            // written for.
            assert(server.streams.isFullyReleased());
            assert(server.relay_buffers.isFullyReleased());
            // Trivially true until a tunnel can exist, and stated now for
            // exactly that reason: the §9 leak invariant is cheapest to
            // extend while it cannot fail, and a pool added to the server
            // but not to this enumeration is a leak nothing would report.
            assert(server.tunnel_buffers.isFullyReleased());
            // beginDrain reaped every parked slot synchronously and no
            // conn is left to lease one, so the pool must be empty.
            assert(server.upstreams.isFullyReleased());
            // Every conn released its ring buffer on the way out, so the
            // in-use count the server owns must have followed to zero —
            // and every released or parked upstream let go of its head.
            assert(server.head_buffers_in_use == 0);
            assert(server.upstream_head_buffers.isFullyReleased());
            // The drain finished, so the watchdog has nothing left to
            // watch. Unconditional: `alarmCancel` on an unarmed alarm is
            // a no-op on both sides of the seam, and the alternative is
            // this line asking the same question `armDrainWatchdog` did
            // and getting a different answer after a config reload.
            server.io.alarmCancel();
            server.io.stop();
        }

        /// Reap parked upstream connections: all of them (drain), or only
        /// those past their stored idle deadline (the sweep). Bounded by
        /// the pool capacity; closes are synchronous — a parked slot has
        /// no armed op (§5), so unpark + close + release is one step.
        fn reapParked(server: *Self, reap_all: bool) void {
            const now = server.io.nowNs();
            for (server.upstreams.slot_pool.slots) |*upstream| {
                if (!server.upstreams.slot_pool.isAcquired(upstream)) continue;
                if (!upstream.parked) continue;
                if (!reap_all and upstream.deadline_ns > now) continue;
                server.upstreams.unpark(upstream);
                server.io.closeNow(upstream.socket);
                server.releaseUpstream(upstream);
                if (!reap_all) {
                    server.counters.increment("upstream_idle_reaped");
                }
            }
        }

        /// Arm the sweep if anything is parked and it is not ticking; the
        /// half-interval keeps worst-case parked overstay under 1.5x the
        /// idle timeout. The §8 pressure bias shortens the interval
        /// lazily, at the next re-arm — an already-ticking sweep is never
        /// touched, the same never-move-earlier rule as every timer (§4).
        pub fn ensureUpstreamSweep(server: *Self) void {
            if (server.upstream_sweep_armed) return;
            if (server.upstreams.idle_count == 0) return;
            server.upstream_sweep_armed = true;
            const interval_ms = @max(server.parkedTimeoutMs() / 2, 1);
            server.io.timerStart(
                &server.upstream_sweep_completion,
                @as(u64, interval_ms) * std.time.ns_per_ms,
                Self,
                server,
                onUpstreamSweep,
            );
        }

        fn onUpstreamSweep(server: *Self, result: Io.TimerError!void) void {
            assert(server.upstream_sweep_armed);
            server.upstream_sweep_armed = false;
            // Nothing ever cancels the sweep timer.
            result catch unreachable;
            server.reapParked(false);
            server.ensureUpstreamSweep();
        }

        /// Every L4 endpoint charge has been released (§7). A scan, not a
        /// running total: a second counter would be one more thing that
        /// can disagree with the table it summarises, and this is asked
        /// only at the idle checks, never on the serving path.
        pub fn l4Released(server: *const Self) bool {
            for (server.l4_inflight) |count| {
                if (count != 0) return false;
            }
            return true;
        }

        /// The simulator's leak invariant (§9). The admin conn holds no
        /// pool slot, but a leaked armed op or an open admin fd is a leak
        /// all the same, so its quiescence is part of "idle" — and so is
        /// an endpoint left carrying a charge for a connection that ended.
        pub fn isIdle(server: *const Self) bool {
            // Every #234 claim is a connection's, so a released conn pool
            // and an outstanding claim contradict each other — and a
            // leaked one would silently freeze the `Date`. Asserted here
            // rather than merely reported, because an idle server with a
            // claim standing is a bug in the release path, not a state a
            // caller should be asked to handle.
            if (server.conns.isFullyReleased()) {
                assert(server.static_sends_inflight == 0);
            }
            return server.l4Released() and
                server.conns.isFullyReleased() and
                // Both pools drain to zero, which is the #274 half of
                // this invariant: a stream leaked without its connection
                // is exactly the bug the split makes possible.
                server.streams.isFullyReleased() and
                server.relay_buffers.isFullyReleased() and
                server.tunnel_buffers.isFullyReleased() and
                server.upstreams.isFullyReleased() and
                server.upstream_head_buffers.isFullyReleased() and
                server.head_buffers_in_use == 0 and
                server.admin.isQuiescent() and
                server.access_log.isQuiescent() and
                server.health.isQuiescent();
        }

        pub fn activeCount(server: *const Self) u32 {
            return server.conns.acquired_count;
        }

        /// Counter reconciliation (§8/§9) supplying the in-flight term
        /// from the pool the server owns, so no caller has to guess it —
        /// holds mid-scenario, not only when idle. The labeled partition
        /// identities (#179) ride along: every labeled family must sum
        /// to the process total it breaks down, under every seed the
        /// simulator runs this on.
        pub fn reconcile(server: *const Self) bool {
            server.labeled.reconciles(&server.counters);
            return server.counters.reconcile(server.activeCount());
        }

        fn armAccept(server: *Self, state: *ListenerState) void {
            assert(!state.accepting);
            assert(!server.draining);
            state.accepting = true;
            server.io.accept(
                state.listener,
                &state.accept_completion,
                ListenerState,
                state,
                onAccept,
            );
        }

        /// The accept gate (§8): re-arm before admitting — accept never
        /// pauses; exhaustion sheds the new socket, never the accept.
        fn onAccept(state: *ListenerState, result: Io.AcceptError!IoType.Socket) void {
            const server = state.server;
            assert(state.accepting);
            state.accepting = false;
            const client_socket = result catch |err| {
                if (err == error.Canceled) {
                    assert(server.draining);
                    return;
                }
                // Kernel pressure (ENFILE-class): the failed connection
                // stays in the backlog, so an immediate re-arm completes
                // instantly with the same error — a tight spin starving
                // the loop. Back off through a short timer instead; the
                // shed ladder never engages here because there is no
                // socket to shed (§8).
                server.witnessKernelPressure(.accept, err);
                if (!server.draining) {
                    server.io.timerStart(
                        &state.retry_completion,
                        @as(u64, constants.accept_retry_delay_ms) * std.time.ns_per_ms,
                        ListenerState,
                        state,
                        onAcceptRetry,
                    );
                }
                return;
            };
            server.counters.increment("accepted");
            if (server.draining) {
                // An accept completion can already be in flight when the
                // drain begins; it is shed, not served.
                server.witnessShed("shed_draining");
                shed.closeQuietly(IoType, server.io, client_socket);
                return;
            }
            server.armAccept(state);
            server.admit(state, client_socket);
        }

        fn onAcceptRetry(state: *ListenerState, result: Io.TimerError!void) void {
            const server = state.server;
            // Nothing ever cancels the retry timer; a drain begun while it
            // was pending is handled by not re-arming below.
            result catch return;
            assert(!state.accepting);
            if (!server.draining) {
                server.armAccept(state);
            }
        }

        /// The admission fork (§6, §7): every protocol shares the accept
        /// gate, the conn slot, the deadline, and teardown. They diverge in
        /// exactly two places, and this is the first — what a protocol must
        /// already hold to be admitted at all. An L4 connection relays for
        /// its whole life, so a missing relay buffer is an admission-time
        /// shed (§8), counted before `admitted`; an idle L7 connection
        /// holds a slot only — its head buffer binds at the first byte,
        /// its relay buffer per body leg (§5). The second divergence is
        /// `startProtocol`.
        fn admit(server: *Self, state: *ListenerState, client_socket: IoType.Socket) void {
            assert(!server.draining);
            const conn = server.admitConn(client_socket) orelse return;
            const buffer: ?*relay.RelayBuffer = switch (state.protocol) {
                .l4 => server.acquireRelayBuffer() orelse {
                    server.abortAdmission(conn, client_socket, "shed_relay_buffers");
                    return;
                },
                .http => null,
            };
            // The engine before the tail, so a shed here is an admission
            // rung like the relay buffer's above and never counts
            // `admitted` (§8, §9). Acquired at admission rather than at
            // the handshake's first byte because that is where a shed can
            // still be one — past `finishAdmission` the connection is in
            // the gate identity and the answer would have to be a teardown.
            const engine: ?*TlsEngine = if (state.credentials) |credentials|
                server.acquireTlsEngine(credentials) catch |err| {
                    // The two causes want opposite answers from an
                    // operator — provision more engines, or size the
                    // libcrypto heap — so they keep separate rungs (§8).
                    // This is the first rung that fires with a relay
                    // buffer already in hand — every earlier one aborts
                    // because it could not get what it needed, so
                    // `abortAdmission` has never had one to give back.
                    // Returning it here rather than teaching that function
                    // about buffers keeps the ordering visible: acquire,
                    // then acquire, then release what the failed step's
                    // predecessor took.
                    if (buffer) |acquired| {
                        server.releaseRelayBuffer(acquired);
                    }
                    // Two calls rather than a switch on the rung name:
                    // `abortAdmission` takes it comptime, which is what
                    // makes `witnessShed` check the `shed_` prefix that
                    // puts a rung in the reconcile identity (§9).
                    switch (err) {
                        error.EnginesExhausted => server.abortAdmission(
                            conn,
                            client_socket,
                            "shed_tls_engines",
                        ),
                        error.CryptoUnavailable => server.abortAdmission(
                            conn,
                            client_socket,
                            "shed_tls_crypto",
                        ),
                    }
                    return;
                }
            else
                null;
            server.finishAdmission(conn, client_socket, buffer, engine, state);
            if (state.proxy_protocol != null) {
                // The loader rejects the block on an http listener, so a
                // non-null here can only be an l4 one (#142).
                assert(state.protocol == .l4);
                server.startProxyHeaderPhase(conn);
            } else if (conn.tls != null) {
                server.startTlsPhase(conn);
            } else if (state.sni_routes.len >= 1) {
                // The config refuses this beside `tls`, so reaching here
                // means the hello is still in the client's hands (#298).
                assert(state.protocol == .l4);
                server.startSniPeekPhase(conn);
            } else {
                server.startProtocol(conn, state.protocol);
            }
        }

        /// The state a protocol's connection starts serving in, in one
        /// place so nothing else carries the mapping.
        fn entryState(protocol: config_module.Config.Listener.Protocol) ConnType.State {
            return switch (protocol) {
                .l4 => .connecting,
                .http => .l7_reading_head,
            };
        }

        /// The first deadline that connection runs under: an L4 connection
        /// is dialing, so it gets the connect budget (§8); an L7 one has
        /// said nothing yet, so it gets the *idle* window.
        ///
        /// Not the head budget, and the distinction is #235's: a connection
        /// that has connected and not spoken is quiet, not slow, and
        /// bounding it as a slowloris would reap the honest client that
        /// opened early. The slowloris clock starts where the head proves
        /// to be *fragmented* — `installHeadBudget`, on the first parse
        /// that returns Incomplete — and narrows this to the head budget
        /// or this same window, whichever is tighter. A client mid-sentence
        /// meets that or `limits.head_buffer_bytes`, whichever comes first
        /// (§7); a head that arrived whole never needed either.
        fn entryTimeoutMs(
            server: *const Self,
            protocol: config_module.Config.Listener.Protocol,
        ) u32 {
            return switch (protocol) {
                .l4 => server.config.connect_timeout_ms,
                .http => server.idleTimeoutMs(),
            };
        }

        /// Start a protocol on an admitted connection: its serving state,
        /// its first deadline, and its first op. Split from the admission
        /// tail so it is callable from either side of the fork — at
        /// admission for a fresh connection, and by any phase that runs
        /// *ahead* of the protocol and hands a live connection over when it
        /// finishes. TLS termination is the phase that will need it
        /// (§4): it is orthogonal to l4/http, so the protocol
        /// fork happens after the handshake rather than at accept.
        ///
        /// It takes the protocol as an argument rather than reading it off
        /// the slot deliberately: a field with one writer and one reader
        /// would be state kept for the caller's convenience (§1), and
        /// every caller knows the protocol without asking: admission, and
        /// the hand-over of each receive phase that can precede it — the
        /// PROXY header (#142), the TLS handshake (#125) and the SNI peek
        /// (#298).
        ///
        /// The state and deadline stores are idempotent at admission — the
        /// tail below set exactly these values from the same protocol, and
        /// `admit` reaches here through one synchronous chain, so the clock
        /// and the pressure flags `entryTimeoutMs` reads cannot have moved
        /// between the two writes — and they are load-bearing for a
        /// hand-over, which arrives in whatever state its phase ran in.
        /// Keeping them here is what makes every caller a single call.
        ///
        /// No `!draining` assert, deliberately: admission's path asserts
        /// it at `admit`, but a hand-over may legally complete mid-drain —
        /// an admitted connection finishing its work is exactly what the
        /// drain waits for (§8), so the phase proceeds to the dial and the
        /// drain timer bounds it like any other straggler.
        fn startProtocol(
            server: *Self,
            conn: *ConnType,
            protocol: config_module.Config.Listener.Protocol,
        ) void {
            assert(!conn.isTearingDown());
            // The one timer this connection ever arms is already armed
            // (§4: a state transition only ever *stores* a new deadline).
            assert(conn.armed.deadline);
            conn.state = entryState(protocol);
            server.storeDeadline(conn, server.entryTimeoutMs(protocol));
            switch (protocol) {
                .l4 => {
                    // A recv must always have a buffer posted (§6).
                    assert(conn.stream.relay_buffer != null);
                    server.armConnect(conn, conn.stream.cluster_index);
                },
                .http => {
                    // An idle L7 connection holds no relay buffer (§5).
                    assert(conn.stream.relay_buffer == null);
                    Proxy.start(server, conn);
                },
            }
        }

        /// The shared conn-slot rung (§8): both protocols shed the same
        /// way when slots run out, so the rung lives in one place.
        fn admitConn(server: *Self, client_socket: IoType.Socket) ?*ConnType {
            assert(!server.draining);
            const conn = server.conns.acquire() orelse {
                server.witnessShed("shed_conn_slots");
                shed.closeWithRst(IoType, server.io, client_socket);
                return null;
            };
            // The pair is taken together, not at the admission tail, and
            // that is what makes the 1:1 claim structural rather than a
            // property of one code path: every route that gives a conn
            // slot back gives its stream back with it, including the §8
            // rungs that abort before `finishAdmission` ever runs. Taken
            // apart, those rungs would release a slot whose stream
            // pointer was never set — and `releaseConn`'s own #234
            // backstop reads through it.
            conn.stream = server.admitStream(conn);
            server.updateConnPressure();
            return conn;
        }

        /// Witness one admission-gate shed: a connection the kernel handed us
        /// that never became `admitted`. The name is checked here because
        /// `reconcile` sums the gate identity by exactly this prefix (§9), so
        /// naming a rung is what puts it in the sum — one door for every rung,
        /// rather than the rule holding only where someone remembered it.
        fn witnessShed(server: *Self, comptime rung: []const u8) void {
            comptime assert(std.mem.startsWith(u8, rung, "shed_"));
            server.counters.increment(rung);
        }

        /// Undo an admission that cannot proceed: a connection already
        /// holding a conn slot whose protocol could not get the rest of what
        /// it needs (§8). Every rung past the slot itself ends the same three
        /// ways — return the slot with its pressure re-derived (§5), witness
        /// the rung, close the socket — and none of them ever counted
        /// `admitted`, which is what keeps the reconcile identity exact (§9).
        ///
        /// One call rather than three lines because of the pressure update:
        /// only its engage crossing carries a counter (§8), so a release that
        /// omits it leaves the flag engaged over a pool that just shrank with
        /// nothing witnessing that — every idle timeout quietly divides
        /// instead of anything failing.
        ///
        /// The close is a plain FIN, not the conn-slot rung's RST — §8's
        /// table names the RST for the slot rung alone, and `shed.zig` owns
        /// the split; every rung past the slot closes quietly.
        fn abortAdmission(
            server: *Self,
            conn: *ConnType,
            client_socket: IoType.Socket,
            comptime rung: []const u8,
        ) void {
            assert(!server.draining);
            server.releaseConn(conn);
            // Through the one door, so the gate identity's naming rule holds
            // here exactly as it does at the other rungs (§9).
            server.witnessShed(rung);
            shed.closeQuietly(IoType, server.io, client_socket);
        }

        /// What the listener decided, written onto the two slots it was
        /// decided for (§5, §7). Split from `finishAdmission` for the
        /// length limit, and the seam is the one the split of #274 made
        /// natural: the caller owns the connection's *lifecycle* — the
        /// count, the reset, the socket options, the one deadline it
        /// arms — while this owns the values a listener contributes to
        /// the connection and to the exchange starting on it.
        fn installListenerState(
            server: *Self,
            conn: *ConnType,
            buffer: ?*relay.RelayBuffer,
            listener: *const ListenerState,
        ) void {
            // The L7 path routes and filters once the head parses (§7);
            // every connection gets its listener's tables and the protocol
            // decides whether it reads them — an l4 listener resolves to
            // exactly one catch-all route and no filters, so this is one
            // rule rather than a third fork.
            conn.routes = listener.routes;
            conn.sni_routes = listener.sni_routes;
            conn.request_filters = listener.request_filters;
            conn.response_filters = listener.response_filters;
            conn.upgrades = listener.upgrades;
            conn.max_body_bytes = listener.max_body_bytes;
            conn.forwarded = listener.forwarded;
            conn.proxy_status = listener.proxy_status;
            // The exchange's starting cluster, from the same listener and
            // for the same reason as the tables above — the L7 path
            // overwrites it at routing once the head parses (§7).
            conn.stream.cluster_index = listener.cluster_index;
            // The L4 relay buffer is claimed after the conn slot, so it
            // arrives after the stream that will carry it — installed
            // here rather than threaded through `Stream.prepare`, which
            // ran at acquisition, before this buffer existed.
            //
            // Deliberately *unlike* `engine`, which is a `Conn.prepare`
            // parameter precisely so a reset cannot orphan it. The
            // asymmetry is safe because the two are claimed on opposite
            // sides of that reset: an engine is in hand before `prepare`
            // runs and would be overwritten by it, where this arrives
            // after and has nothing left to overwrite it. Null on the L7
            // path, which acquires one only when a body relay starts (§5).
            conn.stream.relay_buffer = buffer;
            // The #140 captures live in a side table addressed by pool
            // slot, so a slot's bytes outlive the connection that wrote
            // them. Clearing on acquire is what keeps them from being
            // read as this client's: a head that never parses reaches no
            // capture at all, and its line would otherwise report
            // whatever the slot's *previous* occupant sent.
            server.resetLogHeaders(conn);
            // An L4 connection is its own log unit and starts its line
            // here — the first point at which a listener has said it is
            // one. An L7 exchange starts only when its first head byte
            // lands, so an idle keep-alive connection reaped without ever
            // being asked anything owes no line. Both are gated on the log
            // being on, so a deployment without one reads no clock here.
            if (listener.protocol == .l4 and server.access_log.sink != null) {
                conn.stream.log.started_wall_ns = server.io.nowWallNs();
            }
            assert(conn.routes.len >= 1);
            assert(conn.stream.conn == conn);
        }

        /// The shared admission tail (§8 single choke point): counting,
        /// slot prepare, socket options and the one deadline timer this
        /// connection ever arms are identical across protocols — the
        /// protocol only chooses which values go in, through `entryState`
        /// and `entryTimeoutMs`. What a *listener* contributes to the two
        /// slots is `installListenerState`'s, split out for the length
        /// limit.
        fn finishAdmission(
            server: *Self,
            conn: *ConnType,
            client_socket: IoType.Socket,
            buffer: ?*relay.RelayBuffer,
            engine: ?*TlsEngine,
            listener: *const ListenerState,
        ) void {
            assert(!server.draining);
            // Whatever a listener terminates, it terminates for every
            // connection: an engine without a credentialed listener would
            // be one this slot leaks, and a credentialed listener without
            // one would serve ciphertext as if it were a request.
            assert((engine != null) == (listener.credentials != null));
            server.counters.increment("admitted");
            conn.prepare(
                server,
                client_socket,
                engine,
                entryState(listener.protocol),
                listener.protocol,
                // Asked once, here, and kept: at log time the socket may
                // already be closed (§8). A socket file has no peer to
                // ask about (#303), and the seam says so rather than
                // inventing one.
                if (listener.unix_bind)
                    null
                else
                    server.io.peerAddress(client_socket),
            );
            server.io.setNodelay(client_socket) catch |err| {
                server.witnessKernelPressure(.set_option, err);
            };
            server.installListenerState(conn, buffer, listener);
            server.storeDeadline(conn, server.entryTimeoutMs(listener.protocol));
            server.armDeadline(conn);
            assert(conn.deadline_ns > 0);
            assert(conn.armed.deadline);
        }

        /// L7 body relays acquire their buffer mid-connection (§5), so
        /// the proxy needs the acquire-with-pressure-update pair the L4
        /// admission does inline. Null is the §8 relay-buffer rung.
        pub fn acquireRelayBuffer(server: *Self) ?*relay.RelayBuffer {
            const buffer = server.relay_buffers.acquire() orelse return null;
            server.updateRelayPressure();
            return buffer;
        }

        /// Take a tunnel's relay buffer, or null when the pool is full
        /// (§8: the upgrade is refused up front with a `503`, before the
        /// handshake is forwarded, rather than admitted and torn down
        /// once it is live).
        ///
        /// No pressure recompute, unlike its sibling above, and that is
        /// the difference between a watermark and a wall. The shared
        /// pools bias idle deadlines as they fill, so ordinary traffic
        /// returns buffers sooner; there is nothing equivalent to ask of
        /// a tunnel, whose whole contract is to hold its buffer until the
        /// session ends. The pool's ceiling is the only answer it has.
        pub fn acquireTunnelBuffer(server: *Self) ?*relay.RelayBuffer {
            return server.tunnel_buffers.acquire();
        }

        /// Give one back when the tunnel closes — to the pool it came
        /// from, never the shared one.
        ///
        /// Worth being exact about what enforces that, because it is less
        /// than it looks: the two pools hold the *same* element type, so
        /// a buffer from either type-checks at either release site.
        /// `Pool.indexOf`'s bounds assert does catch a crossed release
        /// today, but only because the two reservations occupy disjoint
        /// arena ranges — a property of allocation order, not of the type
        /// system. So this is a discipline the caller keeps, backed by a
        /// check that happens to hold, rather than a guarantee. Naming it
        /// here because the slice that gives tunnels a lifecycle is the
        /// one that could get it wrong.
        pub fn releaseTunnelBuffer(server: *Self, buffer: *relay.RelayBuffer) void {
            server.tunnel_buffers.release(buffer);
        }

        /// The release pair: an L7 connection going idle on keep-alive
        /// returns its buffer so idle costs a slot + head buffer only (§5).
        pub fn releaseRelayBuffer(server: *Self, buffer: *relay.RelayBuffer) void {
            server.relay_buffers.release(buffer);
            server.updateRelayPressure();
        }

        /// Why a session could not get an engine (§4, §8). Two causes, and
        /// deliberately not one `null`: an operator's response to them
        /// differs completely, and this is the last frame where they are
        /// still distinguishable.
        pub const AcquireEngineError = error{
            /// Every engine is in use. Ordinary backpressure — the §8 wall
            /// `limits.tls_engines` names, answered by shedding, and fixed
            /// by provisioning more if the memory is there.
            EnginesExhausted,
            /// libcrypto could not serve the key derivation. Under the
            /// fixed heap (§4) that means the heap is out, which is a
            /// sizing failure rather than a load one: more engines would
            /// not help, and no amount of shedding frees it.
            CryptoUnavailable,
        };

        /// A TLS engine for one session (§4), initialized against the
        /// listener's credentials and this run's key material.
        ///
        /// Key material comes through the Io seam so the simulator's
        /// seeded stream drives it (§9): a handshake is only replayable if
        /// its randomness came from the run's seed, and nothing below this
        /// line could know that. One draw for both seeds — the seam serves
        /// a whole request or panics, so two calls would buy nothing.
        pub fn acquireTlsEngine(
            server: *Self,
            credentials: *const Credentials,
        ) AcquireEngineError!*TlsEngine {
            assert(credentials.chain.len >= 1);
            const engine = server.tls_engines.acquire() orelse
                return error.EnginesExhausted;
            var seeds: [64]u8 = undefined;
            server.io.fillRandom(&seeds);
            engine.init(&.{
                .x25519_seed = seeds[0..32].*,
                .random = seeds[32..64].*,
                .credentials = credentials,
                // Only once a key is installed: before that the engine
                // would offer resumption it could not honour, and every
                // ticket it opened would be one it never sealed.
                .tickets = if (server.tls_tickets.ready()) &server.tls_tickets else null,
                .now_unix = server.nowUnix(),
            }) catch {
                // Deriving the ephemeral keypair is the one fallible step,
                // and under the OpenSSL backend it *allocates*
                // (`EVP_PKEY_new_raw_private_key`) — from the fixed heap,
                // so this is that heap running out rather than the seed
                // being bad. Give the slot back before reporting: the
                // connection is lost either way, and a leaked engine would
                // cost every later one too.
                server.tls_engines.release(engine);
                return error.CryptoUnavailable;
            };
            assert(!engine.isConnected());
            assert(engine.plaintext.len >= TlsEngine.plaintext_bytes_min);
            return engine;
        }

        /// The release pair, at teardown. Unlike a relay buffer this is
        /// never returned mid-connection: the engine holds the session's
        /// keys, so a terminated connection needs it until it is gone.
        pub fn releaseTlsEngine(server: *Self, engine: *TlsEngine) void {
            engine.deinit();
            server.tls_engines.release(engine);
        }

        /// The ring pair (§5): the bind side is the seam's — the kernel
        /// selects the buffer, `onHeadGroupRecv` reports it here — and the
        /// return side hands the id back and clears the conn's claim, so a
        /// double return dies in the seam's ownership assert rather than
        /// as aliased receives. Both sides recompute the watermark.
        pub fn noteHeadBufferBound(server: *Self) void {
            assert(server.head_buffers_in_use < server.head_buffers_capacity);
            server.head_buffers_in_use += 1;
            server.updateHeadPressure();
        }

        pub fn returnHeadBuffer(server: *Self, conn: *ConnType) void {
            // A terminated connection's head lives in its engine, not the
            // ring (§4): it never bound a buffer, so there is none to give
            // back and no in-use count to decrement. Every site that
            // returns a buffer on the L7 path reaches here, so the fork
            // lives once rather than at each of them.
            if (conn.tls != null) {
                assert(conn.stream.head_buffer_id == StreamType.head_buffer_none);
                return;
            }
            assert(conn.stream.head_buffer_id != StreamType.head_buffer_none);
            assert(server.head_buffers_in_use >= 1);
            server.io.bufferGroupReturn(conn.stream.head_buffer_id);
            conn.stream.head_buffer_id = StreamType.head_buffer_none;
            server.head_buffers_in_use -= 1;
            server.updateHeadPressure();
        }

        /// The shared lingering-close discard target (§7) — see the field.
        pub fn drainSink(server: *Self) []u8 {
            return server.drain_sink[0..];
        }

        /// The head-sized side buffers' closed form (§5): the two serving
        /// scratches (only where a head can exist) plus one response
        /// buffer for each of the prober's concurrent probes (§7, #132) —
        /// always at least one, because the prober reserves a floor of
        /// one probe whatever the config checks. The budget banner prints
        /// this; `init` asserts its allocations sum to it, so the printed
        /// number cannot drift from what is actually reserved.
        pub fn headScratchBytes(options: InitOptions, health_probes: u32) u64 {
            assert(health_probes >= 1);
            assert(health_probes <= constants.health_probe_concurrency_max);
            const serving: u64 = if (options.head_buffers >= 1) 2 else 0;
            return (serving + health_probes) * options.head_buffer_bytes;
        }

        /// Named headers one connection can be holding values for (#140):
        /// both configured lists, since a single exchange captures from
        /// the request on the way in and the response on the way out.
        pub fn logHeadersPerConn(config: *const config_module.Config) u32 {
            const total = config.access_log_request_headers.len +
                config.access_log_response_headers.len;
            // The loader's shared cap, restated where every table sized
            // by it is about to be allocated (§9: a hand-built config —
            // a test, the simulator — never reaches the loader).
            assert(total <= constants.access_log_headers_max);
            return @intCast(total);
        }

        /// The #140 capture table's closed form — values plus their
        /// lengths — for the banner and for `initLogHeaders` to assert
        /// against. Zero for a config that names no headers.
        pub fn logHeaderBytes(config: *const config_module.Config, stream_slots: u32) u64 {
            const slots: u64 = @as(u64, stream_slots) * logHeadersPerConn(config);
            return slots * constants.access_log_header_bytes_max + slots * @sizeOf(u16);
        }

        /// One exchange's slice of the capture table: `per_conn` value
        /// slots, addressed by the *stream* pool index — stable across
        /// reuse, and the same index for the whole life of the slot
        /// holding it. Split from the capture and the read so both speak
        /// one piece of arithmetic.
        ///
        /// Keyed by the stream since #274, because these are the fields
        /// `LogState` could not hold inline and they share its unit
        /// exactly: one request on the L7 path, cleared at every
        /// turnaround. Addressing them by the conn slot while the line
        /// they belong to lives on the stream would be two units for one
        /// log entry. The count is unchanged — the pools are pinned 1:1
        /// (#274) — so the §5 budget term does not move.
        fn logHeaderSlot(server: *Self, conn: *const ConnType, index: u32) []u8 {
            assert(index < server.log_headers_per_conn);
            const stream_index = server.streams.indexOf(conn.stream);
            const slot = stream_index * server.log_headers_per_conn + index;
            assert(slot < server.log_header_lens.len);
            const bytes = constants.access_log_header_bytes_max;
            return server.log_header_values[slot * bytes ..][0..bytes];
        }

        fn logHeaderLen(server: *Self, conn: *const ConnType, index: u32) *u16 {
            assert(index < server.log_headers_per_conn);
            const stream_index = server.streams.indexOf(conn.stream);
            const slot = stream_index * server.log_headers_per_conn + index;
            assert(slot < server.log_header_lens.len);
            return &server.log_header_lens[slot];
        }

        /// Capture one direction's named headers out of a parsed head
        /// (#140), while its zero-copy slices are still live. Values are
        /// truncated to `access_log_header_bytes_max` on the same terms
        /// as `path` — the prefix is what identifies a value — and an
        /// absent header records nothing, which the render reads as
        /// "omit this key".
        ///
        /// First occurrence wins, because `parser.headerValue`'s does:
        /// what the line reports is then the same value zoxy itself read,
        /// which is the property that makes a logged header worth
        /// anything when the two disagree.
        fn captureLogHeaders(
            server: *Self,
            conn: *ConnType,
            headers: []const parser.Header,
            names: []const []const u8,
            first_index: u32,
        ) void {
            assert(first_index + names.len <= server.log_headers_per_conn);
            for (names, 0..) |name, offset| {
                const index = first_index + @as(u32, @intCast(offset));
                const slot = server.logHeaderSlot(conn, index);
                const value = parser.headerValue(headers, name) orelse {
                    server.logHeaderLen(conn, index).* = 0;
                    continue;
                };
                const captured = access_log_module.captureTruncated(slot, value);
                server.logHeaderLen(conn, index).* = @intCast(captured.len);
            }
        }

        /// One direction's captured values, paired with the names they
        /// were captured for — what a `Record` carries. The values alias
        /// the capture table, which the caller reads out before the next
        /// request touches it (the `Record` contract).
        fn loggedHeaders(
            server: *Self,
            conn: *const ConnType,
            names: []const []const u8,
            first_index: u32,
            out: *[constants.access_log_headers_max][]const u8,
        ) access_log_module.NamedHeaders {
            assert(first_index + names.len <= server.log_headers_per_conn);
            for (names, 0..) |_, offset| {
                const index = first_index + @as(u32, @intCast(offset));
                const len = server.logHeaderLen(conn, index).*;
                assert(len <= constants.access_log_header_bytes_max);
                out[offset] = server.logHeaderSlot(conn, index)[0..len];
            }
            return .{ .names = names, .values = out[0..names.len] };
        }

        /// The #140 request capture, called where the parsed head is
        /// still live (§7 rotation writes over it). A no-op for a config
        /// that names none, which is every config that did not ask.
        pub fn captureRequestLogHeaders(
            server: *Self,
            conn: *ConnType,
            headers: []const parser.Header,
        ) void {
            assert(conn.protocol == .http); // Only a parsed head has headers.
            assert(headers.len <= constants.headers_max);
            if (server.config.access_log_request_headers.len == 0) return;
            server.captureLogHeaders(
                conn,
                headers,
                server.config.access_log_request_headers,
                0,
            );
        }

        /// The response half, from the origin's parsed head — same
        /// liveness rule, one direction over.
        pub fn captureResponseLogHeaders(
            server: *Self,
            conn: *ConnType,
            headers: []const parser.Header,
        ) void {
            assert(conn.protocol == .http); // An l4 relay parses no response.
            assert(headers.len <= constants.headers_max);
            if (server.config.access_log_response_headers.len == 0) return;
            server.captureLogHeaders(
                conn,
                headers,
                server.config.access_log_response_headers,
                @intCast(server.config.access_log_request_headers.len),
            );
        }

        /// A line's worth of #140 value slices, one array per direction
        /// — the storage `loggedHeaderPair` fills and the `Record`
        /// borrows for exactly as long as the render runs.
        const LoggedHeaderValues = struct {
            request: [constants.access_log_headers_max][]const u8,
            response: [constants.access_log_headers_max][]const u8,
        };

        /// Both directions' logged headers for one line. L4 lines carry
        /// none: they have no head to have read one from, and the
        /// config's lists say nothing about relayed bytes.
        fn loggedHeaderPair(
            server: *Self,
            conn: *const ConnType,
            values: *LoggedHeaderValues,
        ) struct {
            request: access_log_module.NamedHeaders,
            response: access_log_module.NamedHeaders,
        } {
            if (conn.protocol != .http) {
                return .{ .request = .{}, .response = .{} };
            }
            const request_names = server.config.access_log_request_headers;
            return .{
                .request = server.loggedHeaders(conn, request_names, 0, &values.request),
                .response = server.loggedHeaders(
                    conn,
                    server.config.access_log_response_headers,
                    @intCast(request_names.len),
                    &values.response,
                ),
            };
        }

        /// Forget this exchange's captured values, so a kept-alive
        /// turnaround cannot report the previous request's headers on
        /// the next one's line — `LogState.reset`'s rule for the fields
        /// that live in the side table instead of on the slot.
        pub fn resetLogHeaders(server: *Self, conn: *const ConnType) void {
            assert(server.log_header_lens.len ==
                @as(usize, server.streams.capacity()) * server.log_headers_per_conn);
            var index: u32 = 0;
            while (index < server.log_headers_per_conn) : (index += 1) {
                server.logHeaderLen(conn, index).* = 0;
            }
        }

        /// The stream slot for a connection just admitted (#274).
        ///
        /// Not a shed rung, and the `orelse unreachable` is the argument
        /// rather than an omission: the pool is sized to `conn_slots`,
        /// every stream is acquired strictly after a conn slot and
        /// released strictly before one, so occupancy is equal at every
        /// point and a conn slot in hand *is* a stream slot in hand. The
        /// assert below states that equality where it is relied on, so
        /// the day #173 unpins the two counts this reads as a wall that
        /// moved rather than as a silent overdraw.
        fn admitStream(server: *Self, conn: *ConnType) *StreamType {
            assert(!server.draining);
            assert(server.streams.acquired_count < server.streams.capacity());
            const stream = server.streams.acquire() orelse unreachable;
            stream.prepare(conn);
            assert(stream.conn == conn);
            assert(stream.relay_buffer == null);
            return stream;
        }

        /// The same pair for conn slots, with `admitConn` as its acquire
        /// side: pressure follows occupancy in both directions (§5, §8), so
        /// every slot return goes through here and the flag can never
        /// outlive the occupancy that raised it.
        fn releaseConn(server: *Self, conn: *ConnType) void {
            // The backstop for the #234 claim: a static answer torn down
            // mid-write ends here like every other, and a claim that
            // outlived its connection would freeze the `Date` for the
            // life of the process.
            server.releaseStaticSend(conn);
            // §5's release rule, one level deeper (#274): the stream goes
            // back before the connection that owns it, never after — a
            // pool that outlived its owner is how a release order becomes
            // a leak.
            //
            // The stream's own set is asserted; the connection's is not,
            // and the asymmetry is real rather than an omission. An §8
            // admission rung returns the slot before `Conn.prepare` has
            // run, so `conn.armed` here may still hold the *previous*
            // occupant's bits — which is why this release site has never
            // asserted anything about the conn slot's contents.
            // `continueTeardown` is where a prepared slot is checked, and
            // it asserts both sets before it closes a single fd. The
            // stream is safe to read on either path because it is
            // prepared at acquisition, one line after the slot itself.
            assert(conn.stream.armedCount() == 0);
            assert(conn.stream.conn == conn);
            server.streams.release(conn.stream);
            server.conns.release(conn);
            assert(server.streams.acquired_count == server.conns.acquired_count);
            server.updateConnPressure();
        }

        /// Enter the §6 PROXY-protocol receive phase (#142) on an admitted
        /// L4 connection: read the fronting proxy's header before the dial,
        /// because the dial consumes `client_address` (the hash pick, §7)
        /// and the header is what makes that the real client. Runs under
        /// the connect budget `finishAdmission` already stored — the
        /// fronting proxy speaks immediately after connecting, so a silent
        /// peer is reaped on a dial-scale clock, and the hand-over's fresh
        /// connect deadline only ever moves *later*, which the lazily
        /// re-armed timer absorbs without a rebase (§4).
        fn startProxyHeaderPhase(server: *Self, conn: *ConnType) void {
            assert(!conn.isTearingDown());
            assert(conn.state == .connecting);
            assert(conn.stream.relay_buffer != null);
            assert(conn.armed.deadline);
            assert(conn.stream.head_len == 0);
            conn.state = .l4_reading_proxy_header;
            server.armProxyHeaderRecv(conn);
        }

        /// One recv into the staging window past what has accumulated.
        /// The window ends at the cap, not the buffer: a header the cap
        /// rejects should be rejected by the parser's verdict, never by
        /// outreading the staging the §5 budget assigned this phase.
        fn armProxyHeaderRecv(server: *Self, conn: *ConnType) void {
            assert(conn.state == .l4_reading_proxy_header);
            assert(conn.stream.relay_buffer != null);
            assert(conn.stream.head_len < constants.proxy_header_bytes_max);
            const staging = conn.stream.relay_buffer.?
                .client_to_upstream[0..constants.proxy_header_bytes_max];
            conn.stream.arm(&conn.stream.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                staging[conn.stream.head_len..],
                &conn.stream.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onProxyHeaderRecv,
            );
        }

        /// Accumulate and re-judge from byte 0 (detect-and-retry, §7's
        /// discipline): the parser's verdicts are monotonic, so a partial
        /// header reads `need_more` until its last byte lands.
        fn onProxyHeaderRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.stream.delivered(&conn.stream.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l4_reading_proxy_header);
            const received = result catch |err| {
                if (err == error.EndOfStream) {
                    // A peer that hangs up mid-header was not the
                    // configured proxy; same verdict as garbage bytes.
                    server.counters.increment("l4_proxy_header_invalid");
                } else {
                    server.witnessKernelPressure(.recv, err);
                }
                server.beginTeardown(conn);
                return;
            };
            assert(received >= 1);
            conn.stream.head_len += received;
            assert(conn.stream.head_len <= constants.proxy_header_bytes_max);
            const staged = conn.stream.relay_buffer.?.client_to_upstream[0..conn.stream.head_len];
            const parsed = proxy_protocol.parse(staged);
            switch (parsed) {
                .need_more => server.armProxyHeaderRecv(conn),
                .invalid => {
                    server.counters.increment("l4_proxy_header_invalid");
                    server.beginTeardown(conn);
                },
                .ok => |*header| server.finishProxyHeader(conn, header),
            }
        }

        /// The hand-over (#142): believe the header, stage any coalesced
        /// payload as the relay's opening debt, and start the protocol —
        /// `startProtocol`'s anticipated second caller.
        fn finishProxyHeader(
            server: *Self,
            conn: *ConnType,
            header: *const proxy_protocol.Header,
        ) void {
            assert(conn.state == .l4_reading_proxy_header);
            assert(header.bytes_len >= 1);
            assert(header.bytes_len <= conn.stream.head_len);
            server.counters.increment("l4_proxy_header_accepted");
            // Null keeps the observed peer (LOCAL/UNKNOWN, §6): the
            // fronting proxy's own health checks arrive that way.
            if (header.client) |client| {
                conn.client_address = client;
            }
            const leftover_len = conn.stream.head_len - header.bytes_len;
            const staging = conn.stream.relay_buffer.?.client_to_upstream;
            const leftover = staging[header.bytes_len..conn.stream.head_len];
            if (conn.tls) |engine| {
                // On a terminating listener those leftover bytes are the
                // client's first handshake record, not payload: the PROXY
                // header rides in the clear *outside* the session, so
                // everything past it already belongs to TLS. Framing them
                // as relay debt would send a ClientHello to the origin.
                assert(leftover_len <= engine.plaintext.len);
                conn.stream.head_len = 0;
                conn.stream.head_cursor.reset();
                server.startTlsPhaseWith(conn, leftover);
                return;
            }
            if (conn.sni_routes.len >= 1) {
                // The composition §6 states: the header is the outer
                // envelope, and what rode behind it is the hello the peek
                // exists to read (#298). Moved to the buffer's start so
                // the peek accumulates from byte 0 like any other entry —
                // and *not* framed as relay debt, because this connection
                // has not chosen a backend yet.
                if (leftover_len >= 1) {
                    std.mem.copyForwards(u8, staging[0..leftover_len], leftover);
                }
                conn.stream.head_len = leftover_len;
                conn.stream.head_cursor.reset();
                server.startSniPeekPhase(conn);
                return;
            }
            if (leftover_len >= 1) {
                // Payload the last recv delivered behind the header. Move
                // it to the buffer's start and frame it as the client→
                // upstream direction's debt; `Relay.start` enters the
                // pump mid-cycle on exactly this state.
                std.mem.copyForwards(u8, staging[0..leftover_len], leftover);
                // The payload is client bytes that crossed the wire — the
                // access log's `bytes_in` unit (§8) — which the relay's
                // own counting will never see; the header is metadata the
                // origin never receives, so it stays uncounted.
                conn.stream.log.bytes_in += leftover_len;
                const direction = &conn.stream.directions[
                    @intFromEnum(StreamType.Direction.client_to_upstream)
                ];
                assert(direction.phase == .idle);
                direction.phase = .receiving;
                direction.owe(leftover_len);
            }
            conn.stream.head_len = 0;
            conn.stream.head_cursor.reset();
            server.startProtocol(conn, .l4);
        }

        /// Enter the §6 SNI peek phase (#298) on an admitted L4
        /// connection whose listener routes by name: read the client's
        /// ClientHello before the dial, because the dial consumes the
        /// cluster and the name is what picks it.
        ///
        /// The PROXY-header phase's shape, under the same connect budget
        /// and for the same reason — a client that connects to a TLS
        /// service speaks immediately, so a silent one is reaped on a
        /// dial-scale clock. Ordered after that phase where both are
        /// configured: the header is the outer envelope, and the hello is
        /// the payload it wraps.
        fn startSniPeekPhase(server: *Self, conn: *ConnType) void {
            assert(!conn.isTearingDown());
            assert(conn.protocol == .l4);
            assert(conn.tls == null);
            assert(conn.sni_routes.len >= 1);
            assert(conn.stream.relay_buffer != null);
            assert(conn.armed.deadline);
            assert(conn.stream.head_len < constants.client_hello_bytes_max);
            conn.state = .l4_peeking_client_hello;
            // Judged before any recv is armed, because this phase can be
            // entered *holding* bytes: the PROXY-header phase reads past
            // its own header routinely, and what it read past is the
            // start of the hello. A client that sent both in one segment
            // is waiting on the backend's ServerHello and will send
            // nothing more, so arming a read first would stall it until
            // the deadline reaped it.
            server.judgeSniPeek(conn);
        }

        /// Parse whatever is staged and act on the verdict. The one place
        /// the three outcomes are handled, so both entries into this
        /// phase — a fresh admission and the header hand-over — and every
        /// subsequent delivery reach them the same way.
        fn judgeSniPeek(server: *Self, conn: *ConnType) void {
            assert(conn.state == .l4_peeking_client_hello);
            assert(conn.stream.relay_buffer != null);
            const staged = conn.stream.relay_buffer.?.client_to_upstream[0..conn.stream.head_len];
            switch (client_hello.parse(staged)) {
                .need_more => server.armSniPeekRecv(conn),
                .invalid => {
                    server.counters.increment("l4_sni_invalid");
                    server.beginTeardown(conn);
                },
                .ok => |hello| server.finishSniPeek(conn, hello.server_name),
            }
        }

        /// One recv into the staging window past what has accumulated.
        /// The window ends at the cap, not the buffer, on
        /// `armProxyHeaderRecv`'s rule — and the loader guarantees the
        /// half is at least that wide (`LimitRelayBufferUnderSniRouting`),
        /// so the cap is reachable rather than aspirational.
        fn armSniPeekRecv(server: *Self, conn: *ConnType) void {
            assert(conn.state == .l4_peeking_client_hello);
            assert(conn.stream.relay_buffer != null);
            assert(conn.stream.head_len < constants.client_hello_bytes_max);
            const staging = conn.stream.relay_buffer.?
                .client_to_upstream[0..constants.client_hello_bytes_max];
            conn.stream.arm(&conn.stream.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                staging[conn.stream.head_len..],
                &conn.stream.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onSniPeekRecv,
            );
        }

        /// Accumulate and re-judge from byte 0, the same detect-and-retry
        /// the PROXY header and the HTTP head both use: the parser's
        /// verdicts are monotonic, so a partial hello reads `need_more`
        /// until its last byte lands.
        fn onSniPeekRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.stream.delivered(&conn.stream.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l4_peeking_client_hello);
            const received = result catch |err| {
                if (err == error.EndOfStream) {
                    // A peer that hangs up mid-hello never said what it
                    // wanted; same verdict as bytes that were not one.
                    server.counters.increment("l4_sni_invalid");
                } else {
                    server.witnessKernelPressure(.recv, err);
                }
                server.beginTeardown(conn);
                return;
            };
            assert(received >= 1);
            conn.stream.head_len += received;
            assert(conn.stream.head_len <= constants.client_hello_bytes_max);
            server.judgeSniPeek(conn);
        }

        /// The hand-over (#298): pick the cluster from the name, frame the
        /// whole hello as the relay's opening debt, and dial.
        ///
        /// **Nothing is consumed.** The PROXY header is an envelope this
        /// proxy strips, so `finishProxyHeader` forwards only what came
        /// *after* it; a ClientHello is the client's first payload and the
        /// backend must receive every byte of it, so the debt is the whole
        /// staged run.
        fn finishSniPeek(server: *Self, conn: *ConnType, server_name: ?[]const u8) void {
            assert(conn.state == .l4_peeking_client_hello);
            assert(conn.stream.head_len >= 1);
            assert(conn.sni_routes.len >= 1);
            // Canonicalized before the lookup, exactly as §7 canonicalizes
            // a `Host` before consulting its own table: the config's names
            // are stored canonical, and a hello naming `API.Example.com`
            // asked for the same service as one naming `api.example.com`.
            var host_scratch: [constants.host_bytes_max]u8 = undefined;
            const canonical: ?[]const u8 = if (server_name) |raw|
                parser.canonicalHost(raw, &host_scratch)
            else
                null;
            const routed = sni_router.route(conn.sni_routes, canonical);
            // `absent` is a fact about the client and is counted whatever
            // the table did with it; the other two are facts about the
            // table, so they are the ones the fork picks between.
            if (server_name == null) {
                server.counters.increment("l4_sni_absent");
            } else if (routed != null) {
                server.counters.increment("l4_sni_routed");
            } else {
                server.counters.increment("l4_sni_no_route");
            }
            const cluster_index = routed orelse {
                // Nothing claimed this connection and the operator wrote
                // no catch-all, which is them saying to close it rather
                // than send it somewhere they did not name (§6).
                server.beginTeardown(conn);
                return;
            };
            // The provisional cluster admission stored is replaced here,
            // before the dial can consume it — the whole reason
            // `admittedCluster` is allowed to be provisional at all.
            conn.stream.cluster_index = cluster_index;
            // Every staged byte is payload the origin receives, so every
            // one of them counts (§8). This is where the hello differs
            // from the PROXY header rather than where it differs from the
            // rule: that header is uncounted because it is *stripped*,
            // and the rule both obey is that `bytes_in` is what crossed
            // to the backend.
            conn.stream.log.bytes_in += conn.stream.head_len;
            const direction = &conn.stream.directions[
                @intFromEnum(StreamType.Direction.client_to_upstream)
            ];
            assert(direction.phase == .idle);
            direction.phase = .receiving;
            direction.owe(conn.stream.head_len);
            // Unlike `finishProxyHeader` the bytes stay where they are:
            // nothing was stripped, so there is no prefix to move off.
            conn.stream.head_len = 0;
            conn.stream.head_cursor.reset();
            server.startProtocol(conn, .l4);
        }

        /// Enter the §4 TLS handshake phase (#125) on an admitted
        /// connection whose listener terminates. Runs *after* the PROXY
        /// header phase where both are configured — that header travels in
        /// the clear, outside the session, by the spec's own rule — and
        /// *before* the protocol, because termination is orthogonal to
        /// whether the plaintext is then relayed or proxied.
        ///
        /// Under whatever deadline admission stored: a client that
        /// connects and says nothing is a slowloris whichever phase it
        /// stalls in, and the hand-over's fresh deadline only ever moves
        /// later, which the lazily re-armed timer absorbs (§4).
        fn startTlsPhase(server: *Self, conn: *ConnType) void {
            server.startTlsPhaseWith(conn, &.{});
        }

        /// The same entry for a phase that already holds the session's
        /// first bytes: the PROXY-header phase reads past its own header
        /// routinely, and on a terminating listener what it read past is a
        /// ClientHello. Feeding them here rather than waiting for a read
        /// is not an optimization — no later read will produce them again.
        fn startTlsPhaseWith(server: *Self, conn: *ConnType, opening: []const u8) void {
            assert(!conn.isTearingDown());
            assert(conn.tls != null);
            assert(conn.armed.deadline);
            assert(!conn.tls.?.isConnected());
            assert(conn.tls_pending_len == 0);
            conn.state = .tls_handshaking;
            if (opening.len == 0) {
                server.armTlsRecv(conn);
                return;
            }
            var sink: TlsHandshakeSink = .{ .conn = conn };
            conn.tls.?.feed(opening, &sink.sink()) catch {
                server.counters.increment("tls_handshake_failed");
                server.beginTeardown(conn);
                return;
            };
            server.pumpTlsOutbound(conn);
        }

        /// One ciphertext read, straight into the engine's record buffer —
        /// there is no second buffer between the socket and reassembly.
        /// The engine bounds what it hands out, so a record split across
        /// any number of reads costs round trips and nothing else.
        fn armTlsRecv(server: *Self, conn: *ConnType) void {
            assert(conn.state == .tls_handshaking);
            assert(conn.tls != null);
            const destination = conn.tls.?.recvBuffer();
            assert(destination.len >= 1);
            conn.stream.arm(&conn.stream.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                destination,
                &conn.stream.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onTlsRecv,
            );
        }

        fn onTlsRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.stream.delivered(&conn.stream.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .tls_handshaking);
            const received = result catch |err| {
                if (err == error.EndOfStream) {
                    // A peer that hangs up mid-handshake never became a
                    // session. Counted as a failed handshake rather than as
                    // kernel pressure: nothing here is under strain, the
                    // client simply left.
                    server.counters.increment("tls_handshake_failed");
                } else {
                    server.witnessKernelPressure(.recv, err);
                }
                server.beginTeardown(conn);
                return;
            };
            assert(received >= 1);
            server.driveTlsHandshake(conn, received);
        }

        /// Feed what arrived and act on where that leaves the session.
        /// Split from the completion so the reentrancy rule is visible in
        /// one place: `pumpTlsOutbound` may complete synchronously and
        /// begin the next step, so nothing may touch `conn` after it.
        fn driveTlsHandshake(server: *Self, conn: *ConnType, received: u32) void {
            assert(conn.state == .tls_handshaking);
            const engine = conn.tls.?;
            var sink: TlsHandshakeSink = .{ .conn = conn };
            engine.received(received, &sink.sink()) catch {
                // Any protocol error is this connection's: a malformed
                // record, a bad MAC, an unacceptable parameter. The peer
                // gets a teardown rather than a diagnosis — telling it
                // which of those it was is telling an attacker.
                server.counters.increment("tls_handshake_failed");
                server.beginTeardown(conn);
                return;
            };
            // A client that closed the session mid-handshake said goodbye
            // to something that never existed. Same verdict as a FIN.
            if (engine.peerClosed()) {
                server.counters.increment("tls_handshake_failed");
                server.beginTeardown(conn);
                return;
            }
            server.pumpTlsOutbound(conn);
        }

        /// Write whatever the engine staged, then take the next step. The
        /// send's completion re-enters here, so the loop is: drain the
        /// outbox, and only once it is empty decide whether the session is
        /// up (hand over) or still handshaking (read again).
        fn pumpTlsOutbound(server: *Self, conn: *ConnType) void {
            assert(conn.state == .tls_handshaking);
            const engine = conn.tls.?;
            // A drained outbox on a connected session is exactly once per
            // handshake, and exactly the moment the post-handshake flight
            // is owed (§4). Staging it here rather than in
            // `finishTlsHandshake` keeps it inside this pump: the tickets
            // go out through the same send path as the server flight,
            // partial writes included, and the hand-over below happens on
            // a later pass once they have drained too.
            //
            // Before the send rather than after it, so this stays one
            // pass over the outbox: whatever is staged leaves through the
            // single send below, whether it is the server flight or the
            // tickets that follow it.
            if (engine.outbound().len == 0 and engine.isConnected() and !conn.tls_session_up) {
                conn.tls_session_up = true;
                // Counted *here*, not at the hand-over: the client's
                // Finished has been processed, so this handshake has
                // succeeded whatever becomes of the flight that follows
                // it. A peer that leaves while the tickets are going out
                // is a session that ended, not one that never happened.
                server.counters.increment("tls_handshakes_completed");
                if (engine.isResumed()) server.counters.increment("tls_resumed");
                _ = server.stageTlsTickets(conn);
            }
            const staged = engine.outbound();
            if (staged.len >= 1) {
                conn.stream.arm(&conn.stream.op_data_upstream_to_client, "data_upstream_to_client");
                server.io.send(
                    conn.client_socket,
                    staged,
                    &conn.stream.op_data_upstream_to_client.completion,
                    ConnType,
                    conn,
                    onTlsSent,
                );
                return;
            }
            assert(conn.tls_session_up or !engine.isConnected());
            if (engine.isConnected()) {
                server.finishTlsHandshake(conn);
            } else {
                server.armTlsRecv(conn);
            }
        }

        /// Issue this session's NewSessionTickets, returning whether any
        /// were staged.
        ///
        /// Best-effort on purpose: a deployment with no sealing key, or a
        /// suite whose resumption secret ztls will not hand over, gets a
        /// working session without resumption rather than a failed
        /// handshake. Resumption is an optimisation, and a client that is
        /// offered no ticket simply does a full handshake next time.
        fn stageTlsTickets(server: *Self, conn: *ConnType) bool {
            const engine = conn.tls.?;
            assert(engine.isConnected());
            assert(engine.outbound().len == 0);
            if (engine.tickets == null) return false;
            // Before the first seal of this handshake, so the key these
            // tickets are sealed under is never older than its interval.
            server.maybeRotateTicketKey();

            // One counter, not two: `break` leaves before the index
            // advances, so "how many were staged" and "how far the loop
            // got" are the same number and keeping both would be two
            // names for one fact.
            var issued: u8 = 0;
            while (issued < constants.tls_tickets_per_handshake) {
                // Per-ticket randomness, drawn through the seam so a
                // seeded run replays the tickets it issued (§9). The
                // sealing nonce must never repeat under one key, so it is
                // drawn fresh for each rather than derived from anything.
                var material: [Tickets.nonce_bytes + 4]u8 = undefined;
                server.io.fillRandom(&material);
                // RFC 8446 §4.6.1 wants the nonce unique per ticket
                // within a connection; the index is that, and being one
                // byte it keeps the message small.
                const ticket_nonce = [_]u8{issued};
                engine.sendSessionTicket(
                    &ticket_nonce,
                    std.mem.readInt(u32, material[Tickets.nonce_bytes..][0..4], .big),
                    material[0..Tickets.nonce_bytes].*,
                ) catch break;
                issued += 1;
                server.counters.increment("tls_tickets_issued");
            }
            if (issued == 0) return false;
            assert(engine.outbound().len >= 1);
            return true;
        }

        fn onTlsSent(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.stream.delivered(&conn.stream.op_data_upstream_to_client, "data_upstream_to_client");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .tls_handshaking);
            const sent = result catch |err| {
                // Only while the session is still being built. Past that
                // this send is the post-handshake ticket flight, and a
                // peer that leaves during it has not failed a handshake —
                // it completed one and then went away, which teardown
                // already accounts for.
                if (err == error.Reset) {
                    if (!conn.tls_session_up) {
                        server.counters.increment("tls_handshake_failed");
                    }
                } else {
                    server.witnessKernelPressure(.send, err);
                }
                server.beginTeardown(conn);
                return;
            };
            assert(sent >= 1);
            // A short send credits partially and comes back here; the
            // staged bytes never move, so the remainder is still valid.
            conn.tls.?.outboundSent(sent);
            server.pumpTlsOutbound(conn);
        }

        /// The hand-over: the session is up, so start the protocol the
        /// listener configured — `startProtocol`'s third caller, and the
        /// one its doc comment was written for.
        fn finishTlsHandshake(server: *Self, conn: *ConnType) void {
            assert(conn.state == .tls_handshaking);
            assert(conn.tls.?.isConnected());
            assert(conn.tls.?.outbound().len == 0);
            assert(conn.tls_session_up); // The pump counted it on the way here.
            // An L4 connection relays for its whole life and must hold a
            // buffer before the dial (§6); an L7 one takes its per-leg.
            // Admission already settled that, so nothing is acquired here.
            if (conn.protocol == .l4) {
                assert(conn.stream.relay_buffer != null);
                server.stageTlsPending(conn);
            }
            server.startProtocol(conn, conn.protocol);
        }

        /// Frame whatever plaintext arrived with the handshake as the
        /// relay's opening debt — the same mid-cycle entry a PROXY header's
        /// coalesced payload uses (#142), and for the same reason: those
        /// bytes crossed the wire once and no later read will produce them
        /// again.
        ///
        /// Not an edge case. A client with nothing to wait for writes its
        /// request straight after its Finished, and TCP delivers both in
        /// one segment — so a relay that only ever armed a fresh read would
        /// sit waiting for bytes it was already holding, until the idle
        /// deadline reaped a connection that had done nothing wrong.
        fn stageTlsPending(server: *Self, conn: *ConnType) void {
            _ = server;
            assert(conn.state == .tls_handshaking);
            assert(conn.protocol == .l4);
            if (conn.tls_pending_len == 0) return;
            const engine = conn.tls.?;
            assert(conn.tls_pending_len <= engine.plaintext.len);
            // At the buffer's front, which is where `sendSlice` reads a
            // TLS direction's pending window from.
            const direction = &conn.stream.directions[
                @intFromEnum(StreamType.Direction.client_to_upstream)
            ];
            assert(direction.phase == .idle);
            direction.phase = .receiving;
            direction.owe(conn.tls_pending_len);
            conn.tls_pending_len = 0;
        }

        /// Where the handshake's decrypted output goes. A handshake
        /// yields no application data of its own, so anything arriving
        /// here is the client speaking early — its request coalesced with
        /// its Finished, which is what a client that has nothing to wait
        /// for does. Kept rather than dropped: those bytes crossed the
        /// wire once and no later read will produce them again.
        const TlsHandshakeSink = struct {
            conn: *ConnType,

            fn sink(self: *TlsHandshakeSink) TlsEngine.Sink {
                return .{ .ctx = self, .appData = appData, .closed = closed };
            }

            fn appData(ctx: *anyopaque, bytes: []const u8) void {
                const self: *TlsHandshakeSink = @ptrCast(@alignCast(ctx));
                const conn = self.conn;
                const engine = conn.tls.?;
                // The engine decrypts into its own buffer and hands back a
                // slice of it, so this both *is* where the bytes already
                // are and where the protocol will look for them. Copying
                // to the front is what makes `tls_pending_len` mean "from
                // byte zero" for a protocol that never saw this phase.
                assert(conn.tls_pending_len + bytes.len <= engine.plaintext.len);
                std.mem.copyForwards(
                    u8,
                    engine.plaintext[conn.tls_pending_len..][0..bytes.len],
                    bytes,
                );
                conn.tls_pending_len += @intCast(bytes.len);
                conn.stream.log.bytes_in += bytes.len;
            }

            fn closed(ctx: *anyopaque) void {
                // Recorded on the engine, which `driveTlsHandshake` asks
                // after the feed returns. Nothing to do here: a callback
                // that tore the connection down would do it underneath the
                // engine still walking its own records.
                _ = ctx;
            }
        };

        /// Stage the PROXY header a sending cluster's origin expects
        /// (#142 send) as the client→upstream direction's front debt:
        /// written ahead of whatever payload the receive phase already
        /// framed, so `Relay.start`'s pre-owed-debt entry sends it before
        /// any relayed byte with no new state and no new op. Runs at the
        /// dial, the first moment the endpoint is settled and the last
        /// where the client socket is guaranteed answerable for its
        /// local address (the header's destination field).
        fn stageProxySendHeader(
            server: *Self,
            conn: *ConnType,
            version: config_module.Config.Cluster.ProxyProtocolSend,
        ) void {
            assert(conn.state == .connecting);
            assert(conn.stream.relay_buffer != null);
            var header_buffer: [proxy_protocol.send_bytes_max]u8 = undefined;
            // Both halves exist because the loader says so: a `unix:`
            // listener has neither a peer address nor a local one, and
            // routing one to a cluster that announces a header is
            // refused as a pair (`ListenerUnixBindClusterSend`, #303).
            const client_address = &conn.client_address.?;
            const local_address = server.io.localAddress(conn.client_socket);
            const header = switch (version) {
                .v1 => proxy_protocol.writeV1(&header_buffer, client_address, &local_address),
                .v2 => proxy_protocol.writeV2(&header_buffer, client_address, &local_address),
            };
            const direction = &conn.stream.directions[
                @intFromEnum(StreamType.Direction.client_to_upstream)
            ];
            const staging = conn.stream.relay_buffer.?.client_to_upstream;
            const framed = direction.framed_len;
            // Comptime-guaranteed in proxy_protocol: header + the largest
            // receive leftover fit the buffer half together.
            assert(header.len + framed <= staging.len);
            if (framed >= 1) {
                // Receive-phase payload sits at the front; move it over.
                // Backwards copy: the regions overlap and the move is to
                // the right.
                assert(direction.phase == .receiving);
                std.mem.copyBackwards(
                    u8,
                    staging[header.len..][0..framed],
                    staging[0..framed],
                );
            } else {
                assert(direction.phase == .idle);
                direction.phase = .receiving;
            }
            @memcpy(staging[0..header.len], header);
            direction.stageFront(@intCast(header.len));
            // Counted at the stage: a dial that fails tears the whole
            // connection down, so "staged" and "reached the wire" differ
            // only by fates the dial counters already witness.
            server.counters.increment("l4_proxy_header_sent");
        }

        fn armConnect(server: *Self, conn: *ConnType, cluster_index: u16) void {
            assert(conn.state == .connecting);
            const pick = server.balancer.pick(
                cluster_index,
                &server.endpointLoad(),
                server.health.healthy,
                if (conn.client_address) |*address| address else null,
                // L4 parses no head, so there is nothing request-derived
                // to key on — and the loader keeps request-keyed clusters
                // off l4 listeners (#178), so `.none` is exact, not a
                // shrug.
                .none,
                // An L4 connection dials once and relays whatever the
                // dial produced, so there is nothing tried to exclude
                // (#181): a failed L4 dial has no request to re-send.
                &.{},
            );
            const dial = switch (pick) {
                .dial => |chosen| chosen,
                // Unreachable with nothing tried: only a retry can run
                // the routable set empty.
                .exhausted => unreachable,
                .capped => {
                    // Every endpoint is at its §8 cap. An L4 listener has no
                    // way to say so — it relays bytes, and there is no
                    // protocol to answer in — so the ladder's L4 answer
                    // applies: close. Counted outside the gate identity,
                    // because this connection was admitted before an
                    // endpoint was ever picked (§8) — which is also why
                    // the labeled twin carries only the cluster: no
                    // endpoint was full, all of them were.
                    server.counters.increment("l4_shed_endpoint_inflight");
                    server.labeled.incrementCluster(.l4_shed_inflight, cluster_index);
                    // Nothing was armed for this dial yet — the arm below
                    // is the first — so teardown here cancels only the
                    // deadline admission left running (§5).
                    assert(!conn.stream.armed.connect);
                    server.beginTeardown(conn);
                    return;
                },
            };
            conn.stream.arm(&conn.stream.op_connect, "connect");
            // An L4 dial holds no slot to record the endpoint on, so the
            // access log takes it here — the only place that knows which
            // origin this connection is being relayed to (§8).
            conn.stream.log.endpoint_index = dial.endpoint_index;
            server.chargeEndpoint(conn, cluster_index, dial.endpoint_index);
            if (server.config.clusters[cluster_index].proxy_protocol_send) |version| {
                server.stageProxySendHeader(conn, version);
            }
            server.io.connect(
                &dial.address,
                &conn.stream.op_connect.completion,
                ConnType,
                conn,
                onConnect,
            );
        }

        fn onConnect(conn: *ConnType, result: Io.ConnectError!IoType.Socket) void {
            const server = conn.server;
            conn.stream.delivered(&conn.stream.op_connect, "connect");
            if (conn.isTearingDown()) {
                // The teardown raced the dial. A socket that arrived
                // anyway must still be shut down and closed.
                if (result) |socket| {
                    conn.stream.upstream_socket = socket;
                    server.io.shutdown(socket, .both);
                } else |_| {}
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .connecting);
            const socket = result catch |err| {
                server.counters.increment("upstream_connect_failed");
                // The labeled twin (#179): the pick did not survive the
                // await, but the charge did — `chargeEndpoint` recorded the
                // endpoint this dial was for, and the charge is released
                // only at teardown, after this line.
                assert(conn.charged_endpoint != stream_module.LogState.endpoint_none);
                server.labeled.incrementEndpoint(
                    .connect_failed,
                    server.upstreams.keys.key(conn.charged_cluster, conn.charged_endpoint),
                );
                // Refused/timed-out/unreachable arrive typed and are the
                // origin's verdict; anything else is resource pressure on
                // our side — ephemeral ports and socket memory both land
                // here — and wants the opposite response. The dial counter
                // cannot tell them apart, so witness the pressure too (§8).
                server.witnessKernelPressure(.connect, err);
                // #230's dial signal, on the same split and for the same
                // reason as the L7 path: an L4 cluster's endpoints share
                // the one health mask, so a refusing backend an operator
                // asked to have detected must be detected whichever
                // protocol found it.
                if (err != error.Unexpected) {
                    server.health.witnessPassiveFailure(
                        conn.charged_cluster,
                        conn.charged_endpoint,
                    );
                }
                server.beginTeardown(conn);
                return;
            };
            conn.stream.upstream_socket = socket;
            server.io.setNodelay(socket) catch |err| {
                server.witnessKernelPressure(.set_option, err);
            };
            conn.state = .relaying;
            server.storeDeadline(conn, server.idleTimeoutMs());
            relay.Relay(IoType).start(server, conn);
        }

        /// Teardown is a state, not an event (§5): shutdown both fds,
        /// cancel pending connect/timer (the only legal cancels, §4),
        /// then wait; the delivery that empties the armed set closes
        /// both fds synchronously and releases the slot.
        pub fn beginTeardown(server: *Self, conn: *ConnType) void {
            if (conn.isTearingDown()) return;
            assert(conn.isLive());
            conn.state = .tearing_down;
            server.io.shutdown(conn.client_socket, .both);
            if (conn.stream.upstream_socket) |socket| {
                server.io.shutdown(socket, .both);
            }
            // A dial-timeout verdict (§8) may already have a cancel in
            // flight; submitting a second would double-arm the op.
            if (conn.stream.armed.connect and !conn.stream.armed.connect_cancel) {
                server.armConnectCancel(conn);
            }
            // A dial rebase (§8) may already have this timer's cancel in
            // flight (onDeadlineRebase); submitting a second would double-arm
            // the op. Its drain routes to teardown via the isTearingDown
            // checks, so teardown needs no cancel of its own here.
            if (conn.armed.deadline and !conn.armed.deadline_cancel) {
                conn.arm(&conn.op_deadline_cancel, "deadline_cancel");
                server.io.timerCancel(
                    &conn.op_deadline.completion,
                    &conn.op_deadline_cancel.completion,
                    ConnType,
                    conn,
                    onDeadlineCancel,
                );
            }
            server.continueTeardown(conn);
        }

        /// Every pool slot this connection drew from, returned in the one
        /// order that is safe (§5). Split out of `continueTeardown` for
        /// the length limit, and it is the right seam: the caller owns
        /// *when* a release may happen — the armed-set check and the fd
        /// closes that check licenses — while this owns *what* is
        /// released and in what order. Its precondition is the caller's
        /// postcondition, restated rather than assumed.
        fn releasePooledResources(server: *Self, conn: *ConnType) void {
            assert(conn.state == .tearing_down);
            assert(conn.armedCount() == 0);
            assert(conn.stream.armedCount() == 0);
            // Both fds are shut: nothing here may reference a socket, and
            // the upstream one is the field the caller cleared.
            assert(conn.stream.upstream_socket == null);
            // The §5 tunnel buffer first, and the order matters: a live
            // tunnel's `relay_buffer` *aliases* its `tunnel_buffer`
            // (#180), so releasing the shared way would hand one pool's
            // slot to the other — which `Pool.indexOf` catches, but only
            // after the accounting is already wrong. One owner, checked
            // before the alias is read.
            if (conn.tunnel_buffer) |buffer| {
                // The alias holds only once `beginTunnel` swapped this
                // buffer in (#180). *Before* `101` the two fields are
                // distinct buffers from distinct pools — the claim, and
                // the ordinary relay buffer the exchange is still using —
                // so clearing the second on the strength of the first
                // would drop a live pool slot without releasing it. The
                // pointer compare says exactly which case this is.
                if (conn.stream.relay_buffer == buffer) {
                    conn.stream.relay_buffer = null;
                }
                server.releaseTunnelBuffer(buffer);
                conn.tunnel_buffer = null;
            }
            // An idle L7 connection holds no relay buffer (§5); only
            // release one that was actually acquired.
            if (conn.stream.relay_buffer) |buffer| {
                server.releaseRelayBuffer(buffer);
                conn.stream.relay_buffer = null;
            }
            // Same rule for the ring buffer: nothing armed references it
            // (asserted above), so the return cannot race a landing recv.
            if (conn.stream.head_buffer_id != StreamType.head_buffer_none) {
                server.returnHeadBuffer(conn);
            }
            // The leased upstream slot rides the same release rule: its
            // socket (if any) was closed by the caller, so the slot is
            // inert (§5). Parking replaces this with reuse later.
            if (conn.stream.upstream) |leased| {
                server.releaseUpstream(leased);
                conn.stream.upstream = null;
            }
            // The L4 endpoint charge rides the same rule: the socket that
            // made this connection work against an origin is closed, so
            // the origin is no longer carrying it (§7).
            server.releaseL4(conn);
            // The TLS engine, last of the per-connection resources and the
            // only one held for the whole life of the connection rather
            // than a phase of it (§4): it holds the session's keys, so
            // there is no point before now at which it could go back.
            if (conn.tls) |engine| {
                server.releaseTlsEngine(engine);
                conn.tls = null;
                conn.tls_pending_len = 0;
            }
            assert(conn.tls == null);
            assert(conn.stream.relay_buffer == null);
            assert(conn.tunnel_buffer == null);
            assert(conn.stream.upstream == null);
            assert(conn.charged_endpoint == stream_module.LogState.endpoint_none);
        }

        /// Public for the relay: a completion delivered during teardown
        /// re-enters here (§5). The delivery that empties *both* armed
        /// sets finishes the whole teardown synchronously: nothing
        /// references either fd any more, so the closes are plain
        /// syscalls — the same close-after-full-drain discipline
        /// `detachUpstream` and the parked reap already use — and the two
        /// slots release in the same call instead of waiting out two
        /// close completions. A dial completing against its own teardown
        /// still peaks at four armed ops, split two and two across the
        /// slots since #274: the `conn_ops_max + stream_ops_max` budget
        /// the CQ is sized by (§8).
        pub fn continueTeardown(server: *Self, conn: *ConnType) void {
            assert(conn.state == .tearing_down);
            // §5's release rule, one level deeper since #274: the conn
            // slot goes back when *its* armed set is empty **and** every
            // stream it owns has emptied its own. The exchange's four
            // completions live on the stream now, so a check that read
            // only this set would close both fds out from under an armed
            // recv — which is the shape of bug the rule exists to make
            // impossible, and which the sim finds on the first idle
            // timeout when it is got wrong.
            if (conn.armedCount() != 0 or conn.stream.armedCount() != 0) return;
            // Nothing armed on either slot: no op references either fd,
            // which is what makes the synchronous closes and the two
            // releases safe.
            assert(conn.armedCount() == 0);
            assert(conn.stream.armedCount() == 0);
            server.io.closeNow(conn.client_socket);
            if (conn.stream.upstream_socket) |socket| {
                server.io.closeNow(socket);
                conn.stream.upstream_socket = null;
            }
            server.releasePooledResources(conn);
            // The last chance to say anything about this connection (§8).
            // An exchange that reached a verdict already spoke and is
            // skipped by `emitted`; what is left here is everything that
            // ended without one — a client that left mid-request, a
            // truncated body, a drain straggler — and every L4 connection,
            // whose whole life is the unit being logged.
            server.logExchange(conn);
            // Which returns the stream with it (§5).
            server.releaseConn(conn);
            server.counters.increment("completed");
            server.maybeStopAfterDrain();
        }

        /// Start this connection's access-log clock, if it owes a line and
        /// has not started one (§8). The L7 path calls it when a request's
        /// first head byte lands — which is when the request begins, not
        /// when its head finishes parsing, so a slowloris's line reports
        /// the whole time it spent dribbling.
        ///
        /// Stamped whether or not an access log is configured, and that
        /// is #299's doing: the §8 latency histogram measures the same
        /// interval this starts, so gating the stamp on a sink would have
        /// left every deployment without an access log — the default —
        /// reporting no latency at all, or worse, a duration measured
        /// from zero. The cost is one `CLOCK_REALTIME` read per request
        /// where there was none: a vDSO call, against the ~25 us of loop
        /// time a request already costs at the Tier-1 band.
        pub fn beginRequest(server: *Self, conn: *ConnType) void {
            if (conn.stream.log.started_wall_ns != 0) return;
            conn.stream.log.started_wall_ns = server.io.nowWallNs();
            assert(conn.stream.log.started_wall_ns != 0);
        }

        /// Write the access-log line this connection owes, if any (§8).
        ///
        /// The caller sets `conn.stream.log.status` and `conn.stream.log.outcome` when it
        /// knows them; the defaults — status 0, outcome `aborted` — are
        /// deliberately the answer for the caller that does not, which is
        /// teardown. That is what lets one function serve both the path
        /// that decided an outcome and the path that never got one, with
        /// `emitted` deciding which of the two speaks for an exchange that
        /// took both.
        pub fn logExchange(server: *Self, conn: *ConnType) void {
            if (server.access_log.sink == null) return;
            if (conn.stream.log.emitted) return;
            // Nothing was asked of this connection: an L7 slot that idled
            // out between requests, or one reaped before its first byte.
            if (conn.stream.log.started_wall_ns == 0) return;
            conn.stream.log.emitted = true;
            const now_wall_ns = server.io.nowWallNs();
            // Both indices are pool/config positions this connection has
            // carried since routing; a stale one would name another
            // operator's backend in the line, so they are checked here
            // rather than left to Zig's bounds check to turn into a panic.
            assert(conn.stream.cluster_index < server.config.clusters.len);
            const cluster = server.config.clusters[conn.stream.cluster_index];
            if (conn.stream.log.endpoint_index != stream_module.LogState.endpoint_none) {
                assert(conn.stream.log.endpoint_index < cluster.endpoints.len);
            }
            var values: LoggedHeaderValues = undefined;
            const logged = server.loggedHeaderPair(conn, &values);
            const entry: access_log_module.Record = .{
                .kind = switch (conn.protocol) {
                    .l4 => .l4,
                    .http => .http,
                },
                .outcome = conn.stream.log.outcome,
                .started_wall_ns = conn.stream.log.started_wall_ns,
                // Saturating: the wall clock can step backwards under NTP,
                // and a duration that wrapped to eighteen quintillion
                // microseconds would be read as a stall that never happened.
                .duration_ns = now_wall_ns -| conn.stream.log.started_wall_ns,
                .client = conn.client_address,
                .upstream = if (conn.stream.log.endpoint_index == stream_module.LogState.endpoint_none)
                    null
                else
                    cluster.endpoints[conn.stream.log.endpoint_index],
                .cluster = cluster.name,
                .bytes_in = conn.stream.log.bytes_in,
                .bytes_out = conn.stream.log.bytes_out,
                .method = conn.stream.log.methodSlice(),
                .host = conn.stream.log.hostSlice(),
                .path = conn.stream.log.pathSlice(),
                .status = conn.stream.log.status,
                .upstream_reused = conn.stream.l7.upstream_was_reused,
                .upstream_replayed = conn.stream.l7.replay_used,
                .request_headers = logged.request,
                .response_headers = logged.response,
            };
            // A duration is never negative once saturated, and a line
            // always names a start: both are what `renderLine` prints
            // without checking, so they are checked here.
            assert(entry.started_wall_ns != 0);
            assert(entry.duration_ns <= now_wall_ns);
            server.access_log.record(&entry);
        }

        /// §8 kernel-pressure rung: a non-orderly op failure on a live
        /// socket is resource exhaustion (ENOBUFS/ENOMEM), which the seam
        /// collapses to Unexpected. Orderly failures (EndOfStream, Reset,
        /// Canceled) are peeled off by the caller; only Unexpected is
        /// witnessed here. Shared by every site — the accept and
        /// setNodelay ones included, so no path can reach the total
        /// without naming the op it failed on.
        ///
        /// `op` is comptime and mandatory for that reason. The errno is
        /// gone before this is called (libxev discards it), so the op is
        /// the only thing left to distinguish a full NIC queue from an
        /// exhausted fd table — and those want opposite responses.
        pub fn witnessKernelPressure(
            server: *Self,
            comptime op: counters_module.Counters.KernelPressureOp,
            err: anyerror,
        ) void {
            if (err != error.Unexpected) return;
            server.counters.increment("kernel_pressure_errors");
            server.counters.increment(comptime op.counter());
            // The seam classified this while the completion was still in
            // hand; reading it here is why the op and the cause always
            // describe the same failure. Both partition the same total.
            const pressure = server.io.lastPressure();
            switch (pressure.cause) {
                inline else => |cause| server.counters.increment(
                    comptime counters_module.Counters.causeCounter(cause),
                ),
            }
            // Kept raw so an `.other` is a lead rather than a dead end: the
            // classification names only the errnos worth acting on
            // differently, and this is how the rest stay visible.
            server.last_pressure_errno = pressure.errno;
            // The partition, checked where it is maintained rather than
            // only where `reconcile` happens to run. A site that increments
            // the total on its own leaves the two unequal, and the next
            // witness call trips here — which is how the third `setNodelay`
            // site was found still doing exactly that, on a path SimIo
            // cannot fail and so 64 sim seeds could never reach.
            assert(server.counters.kernelPressureTotal() ==
                server.counters.get("kernel_pressure_errors"));
            assert(server.counters.kernelPressureCauseTotal() ==
                server.counters.get("kernel_pressure_errors"));
        }

        /// §8 watermarks before walls: recompute one pool's pressure flag
        /// with hysteresis after an acquire/release. The engage crossing
        /// is witnessed by its counter; the wall (the pool's shed rung)
        /// still backs it up if pressure fails to relieve the load in
        /// time. One rule for all three pools.
        fn updatePressureFlag(
            server: *Self,
            flag: *bool,
            held: u32,
            capacity: u32,
            comptime counter: []const u8,
        ) void {
            assert(held <= capacity);
            // The comptime block pins the watermark shape at production
            // size only; these pin it for every injected pool size too.
            assert(constants.poolPressureOn(capacity) > constants.poolPressureOff(capacity));
            assert(constants.poolPressureOn(capacity) <= capacity);
            if (flag.*) {
                if (held <= constants.poolPressureOff(capacity)) {
                    flag.* = false;
                }
            } else if (held >= constants.poolPressureOn(capacity)) {
                flag.* = true;
                server.counters.increment(counter);
            }
        }

        fn updateRelayPressure(server: *Self) void {
            server.updatePressureFlag(
                &server.relay_pressure,
                server.relay_buffers.acquired_count,
                @intCast(server.relay_buffers.slots.len),
                "relay_pressure_engaged",
            );
        }

        fn updateConnPressure(server: *Self) void {
            server.updatePressureFlag(
                &server.conn_pressure,
                server.conns.acquired_count,
                @intCast(server.conns.slots.len),
                "conn_pressure_engaged",
            );
        }

        fn updateUpstreamPressure(server: *Self) void {
            server.updatePressureFlag(
                &server.upstream_pressure,
                server.upstreams.slot_pool.acquired_count,
                @intCast(server.upstreams.slot_pool.slots.len),
                "upstream_pressure_engaged",
            );
        }

        fn updateUpstreamHeadPressure(server: *Self) void {
            // Reachable only through an acquire or release, both of which
            // imply a nonzero pool — the watermark math needs that.
            assert(server.upstream_head_buffers.slots.len >= 1);
            server.updatePressureFlag(
                &server.upstream_head_pressure,
                server.upstream_head_buffers.acquired_count,
                @intCast(server.upstream_head_buffers.slots.len),
                "upstream_head_pressure_engaged",
            );
        }

        fn updateHeadPressure(server: *Self) void {
            // Reachable only through a bind or return, both of which imply
            // a registered ring — so the capacity the watermark math needs
            // to be nonzero always is.
            assert(server.head_buffers_capacity >= 1);
            server.updatePressureFlag(
                &server.head_pressure,
                server.head_buffers_in_use,
                server.head_buffers_capacity,
                "head_pressure_engaged",
            );
        }

        /// Any pressure an *idle* downstream connection holds capacity
        /// against (§8): it pins a conn slot, and its next body relay
        /// claims a relay buffer. Drives only the idle-timeout division —
        /// quiet connections reap sooner; serving ones are untouched.
        pub fn downstreamPressured(server: *const Self) bool {
            return server.relay_pressure or server.conn_pressure;
        }

        /// The §8 keep-alive suppression signal for the L7 render's
        /// persistence decision: relay pressure only. Conn-slot occupancy
        /// deliberately stays out — a conn pool held by *serving*
        /// connections is the steady state of a keep-alive workload, not
        /// imminent exhaustion, and closing them churns the population
        /// into synchronized reconnect waves (#57). Slot scarcity is
        /// answered by the idle-timeout division and the admit-time wall,
        /// never by closing connections that are doing work.
        pub fn keepAliveSuppressed(server: *const Self) bool {
            return server.relay_pressure;
        }

        /// The live occupancy of all three pools, read straight off them
        /// for a scrape or the exit tally (§8). The only producer of
        /// `Counters.Gauges` — nothing mirrors these levels, so nothing
        /// can disagree with the pool it reports.
        ///
        /// This is what the `*_shed_*` counters cannot show: a shed says
        /// the wall was *hit*, and by then the connection is already being
        /// answered 503. The levels show the approach, which is the only
        /// way to size `limits` before a run rather than after it.
        pub fn gauges(server: *const Self) counters_module.Counters.Gauges {
            const snapshot: counters_module.Counters.Gauges = .{
                .conn_slots_in_use = server.conns.acquired_count,
                .conn_slots_capacity = server.conns.capacity(),
                .relay_buffers_in_use = server.relay_buffers.acquired_count,
                .relay_buffers_capacity = server.relay_buffers.capacity(),
                .upstream_slots_leased = server.upstreams.leasedCount(),
                .upstream_slots_parked = server.upstreams.parkedCount(),
                .upstream_slots_capacity = server.upstreams.capacity(),
                .head_buffers_in_use = server.head_buffers_in_use,
                .head_buffers_capacity = server.head_buffers_capacity,
                .upstream_head_buffers_in_use = server.upstream_head_buffers.acquired_count,
                .upstream_head_buffers_capacity = server.upstream_head_buffers.capacity(),
                .kernel_pressure_last_errno = server.last_pressure_errno,
                .health_endpoints_checked = server.health.checked_count,
                .health_endpoints_ejectable = server.health.ejectable_count,
                .health_endpoints_unhealthy = server.health.unhealthy_count,
            };
            // Asserted at the producer, not in the renderer: a level past
            // its capacity would mean a pool miscounted, and that is a bug
            // here, not a formatting problem there.
            assert(snapshot.valid());
            return snapshot;
        }

        /// The §8 upstream-pool acquire/release pair: the pressure flag
        /// recomputes on exactly the transitions that move
        /// `acquired_count` (park/checkout do not), so the callers can
        /// never miss a crossing.
        pub fn acquireUpstream(
            server: *Self,
            cluster_index: u16,
            endpoint_index: u16,
        ) ?*upstream_module.UpstreamPool(IoType).Upstream {
            const leased = server.upstreams.acquire(cluster_index, endpoint_index) orelse return null;
            // The pool honored the request: a freshly leased slot is
            // unparked and carries the identity the pressure recompute and
            // the P2C load table now read back.
            assert(!leased.parked);
            assert(leased.cluster_index == cluster_index);
            assert(leased.endpoint_index == endpoint_index);
            server.updateUpstreamPressure();
            return leased;
        }

        /// The per-endpoint in-flight view both policies read (§7): the
        /// pool's L7 leases beside the server's L4 charges. Built at the
        /// read rather than stored, so it cannot drift from either
        /// writer.
        pub fn endpointLoad(server: *const Self) upstream_module.Load {
            return .{
                .l7 = server.upstreams.leased_counts,
                .l4 = server.l4_inflight,
            };
        }

        /// The L4 counterpart of `acquireUpstream`: a dial about to go
        /// out counts against its endpoint. The endpoint is recorded on
        /// the connection so the release cannot guess, and so a slot
        /// that never dialed releases nothing.
        /// Charge one endpoint for a connection this proxy is carrying
        /// that holds no upstream *slot* — an L4 relay, or a #180 tunnel,
        /// which after `101` is the same thing. The `max_inflight` view
        /// sums this beside the pool's L7 leases precisely because both
        /// are work the origin is carrying (§7), so a tunnel keeps being
        /// counted for its whole life without pinning a shared slot.
        pub fn chargeEndpoint(server: *Self, conn: *ConnType, cluster_index: u16, endpoint_index: u16) void {
            assert(conn.protocol == .l4 or conn.state == .l7_exchanging);
            assert(conn.charged_endpoint == stream_module.LogState.endpoint_none);
            const key = server.upstreams.keys.key(cluster_index, endpoint_index);
            server.l4_inflight[key] += 1;
            // Every charge is held by a live conn slot, so one endpoint's
            // count can never pass the conn pool's own size — the same
            // shape `leased_counts` asserts against the upstream pool, and
            // a far tighter canary for a missed release than the type's
            // ceiling would be.
            assert(server.l4_inflight[key] <= server.conns.capacity());
            conn.charged_cluster = cluster_index;
            conn.charged_endpoint = endpoint_index;
        }

        /// The release side, from the one place every L4 teardown passes
        /// through. Idempotent by the sentinel: a connection shed before
        /// its dial, or torn down twice, has nothing charged.
        fn releaseL4(server: *Self, conn: *ConnType) void {
            if (conn.charged_endpoint == stream_module.LogState.endpoint_none) return;
            const key = server.upstreams.keys.key(conn.charged_cluster, conn.charged_endpoint);
            assert(server.l4_inflight[key] >= 1);
            server.l4_inflight[key] -= 1;
            conn.charged_endpoint = stream_module.LogState.endpoint_none;
        }

        pub fn releaseUpstream(
            server: *Self,
            leased: *upstream_module.UpstreamPool(IoType).Upstream,
        ) void {
            // A parked slot must be unparked before release (its idle-list
            // links would dangle), and at least this slot is leased.
            assert(!leased.parked);
            assert(server.upstreams.leasedCount() >= 1);
            // A slot released mid-exchange — teardown, a static response,
            // a stale replay — usually still holds its head buffer; one
            // that never got one (the shed at its own head acquire) or
            // released it at park arrives here empty-handed. One
            // conditional chokepoint, so no release path can leak it.
            if (leased.head_buffer != null) {
                server.releaseUpstreamHeadBuffer(leased);
            }
            server.upstreams.release(leased);
            server.updateUpstreamPressure();
        }

        /// The §5 upstream head-buffer pair: acquired at the request-head
        /// render, released before the slot parks or with the slot itself.
        /// Both sides recompute the watermark.
        pub fn acquireUpstreamHeadBuffer(server: *Self) ?*upstream_module.HeadBuffer {
            const head_buffer = server.upstream_head_buffers.acquire() orelse return null;
            server.updateUpstreamHeadPressure();
            return head_buffer;
        }

        pub fn releaseUpstreamHeadBuffer(
            server: *Self,
            leased: *upstream_module.UpstreamPool(IoType).Upstream,
        ) void {
            const head_buffer = leased.head_buffer orelse unreachable;
            leased.head_buffer = null;
            server.upstream_head_buffers.release(head_buffer);
            server.updateUpstreamHeadPressure();
        }

        /// The idle timeout to apply now, shortened under downstream
        /// pressure so quiet connections return their buffers and slots
        /// sooner (§8). Only the idle deadline is biased — the connect
        /// deadline is a correctness bound and stays fixed. Because a
        /// timer never moves *earlier* once armed (§4), this reaches a
        /// connection at its next deadline store (activity or
        /// half-close), not retroactively; the admit-time wall covers
        /// connections that never transact again.
        pub fn idleTimeoutMs(server: *const Self) u32 {
            const configured = server.config.idle_timeout_ms;
            if (!server.downstreamPressured()) return configured;
            return @max(configured / constants.pressure_idle_divisor, 1);
        }

        /// The deadline for a connection parked from now on, further
        /// shortened under upstream pressure so idle parked sockets free
        /// their slots for fresh dials before the 503 wall (§8). It
        /// bases on `idleTimeoutMs`, so downstream pressure alone already
        /// shortens parked deadlines — a deliberate cross-pool coupling:
        /// under any pressure, idle capacity of every kind reaps sooner.
        /// Lazy like the idle bias: it reaches a connection at its next
        /// park, never retroactively.
        pub fn parkedTimeoutMs(server: *const Self) u32 {
            const base = server.idleTimeoutMs();
            if (!server.upstream_pressure) return base;
            return @max(base / constants.pressure_idle_divisor, 1);
        }

        /// Public for the relay: activity pushes the idle deadline out;
        /// only the stored value moves, never the armed timer op (§4).
        pub fn storeDeadline(server: *Self, conn: *ConnType, timeout_ms: u32) void {
            assert(timeout_ms >= 1);
            var deadline_ns = server.io.nowNs() + @as(u64, timeout_ms) * std.time.ns_per_ms;
            // Max-lifetime rides the same deadline (§6): clamp the
            // activity-driven value to the absolute age cap so a
            // continuously busy connection is still reaped. 0 disables it.
            // The clamp only ever moves the deadline *earlier*, which the
            // lazy re-arm in onDeadline handles for free — deadline_ns stays
            // <= cap, so every arm targets <= cap and the connection dies at
            // the cap even though the armed timer never moves earlier (§4).
            if (server.config.max_lifetime_ms != 0) {
                const cap_ns = conn.birth_ns +
                    @as(u64, server.config.max_lifetime_ms) * std.time.ns_per_ms;
                deadline_ns = @min(deadline_ns, cap_ns);
            }
            // The §8 request deadline rides the same timer for the same
            // reason, one exchange rather than one connection: zero while
            // no request is in flight (L4 never sets it, and a keep-alive
            // turnaround clears `l7`), so the clamp is inert outside an
            // exchange. Its arming side re-bases the armed timer, which is
            // what makes it fire *on* time rather than at the next tick.
            if (conn.stream.l7.request_deadline_ns != 0) {
                deadline_ns = @min(deadline_ns, conn.stream.l7.request_deadline_ns);
            }
            conn.deadline_ns = deadline_ns;
        }

        /// Retire this exchange's §8 request deadline. One rule, two
        /// moments that satisfy it: the deadline fires, or some other rung
        /// commits to an answer first. After either, the cap is in the past
        /// or irrelevant, and leaving it in place would clamp the very
        /// writes that deliver the answer — expiring the connection a
        /// second time before a byte of the verdict reached the client. A
        /// deadline must never cut short the delivery of the answer it
        /// caused. What is left to bound is a client that will not read:
        /// the idle timeout's job, and the keep-alive turnaround installs a
        /// fresh cap for the next request.
        ///
        /// Caller obligation, because this only retires the *cap*:
        /// `conn.deadline_ns` still stands wherever the cap clamped it, so
        /// every caller must store a fresh deadline afterwards or the
        /// retirement changes nothing that is already armed. `respond`
        /// widens to the idle budget; `expireDeadline`'s two verdict
        /// branches store their fixed grace window.
        pub fn clearRequestDeadline(conn: *ConnType) void {
            conn.stream.l7.request_deadline_ns = 0;
        }

        fn armDeadline(server: *Self, conn: *ConnType) void {
            const delay_ns = conn.deadline_ns -| server.io.nowNs();
            conn.arm(&conn.op_deadline, "deadline");
            server.io.timerStart(
                &conn.op_deadline.completion,
                delay_ns,
                ConnType,
                conn,
                onDeadline,
            );
        }

        /// Store a target and re-base only if it actually moved *earlier*
        /// — `storeDeadline` and `rebaseDeadline` as one step, for the
        /// caller that cannot prove the narrowing statically.
        ///
        /// The two callers that can prove it — the dial's per-try connect
        /// budget and the routing cap — say so by calling the pair
        /// directly. #235's head budget cannot: it is a config value
        /// compared against a window that shrinks under pressure, so
        /// whether it narrows anything is a runtime fact. Asking here
        /// keeps the cancel off the keep-alive hot path in the common
        /// case, where the head budget is already the wider of the two and
        /// §4's lazy tick-and-compare re-arms for a later target for free.
        pub fn narrowDeadline(server: *Self, conn: *ConnType, timeout_ms: u32) void {
            assert(timeout_ms >= 1);
            // A connection with no deadline stored has none to narrow:
            // every state that reaches here was given one on entry.
            assert(conn.deadline_ns != 0);
            const previous_ns = conn.deadline_ns;
            server.storeDeadline(conn, timeout_ms);
            assert(conn.deadline_ns != 0);
            // Compared against the previously *stored* target, not the
            // armed timer's — which is never recorded. That is sound for
            // this caller because nothing stores a deadline between the
            // entry window and the head budget: in `.l7_reading_head` the
            // only prior store is the idle window, and the armed timer is
            // aimed at it. Said that narrowly on purpose — "the armed
            // target is always at or before the stored one" is *not* a
            // general §4 fact, since `storeDeadline`'s max-lifetime clamp
            // can move the stored target earlier with no rebase and leave
            // `onDeadline` to self-heal a tick late. Where the two can
            // diverge, this comparison would only ever decline a cancel
            // that was unnecessary, never skip one that was needed.
            if (conn.deadline_ns >= previous_ns) return;
            server.rebaseDeadline(conn);
        }

        /// Re-base the armed deadline to the freshly stored (earlier) target
        /// (§8): the single lazy timer never moves *earlier* once armed (§4),
        /// so an L7 dial needing a tighter per-try connect budget than the
        /// head-read timer cancels it here — the one deadline cancel outside
        /// teardown. onDeadlineRebase and onDeadline re-arm at the stored
        /// target once both the cancel and the timer's Canceled have drained
        /// (so the cancel cannot match the fresh timer). A path that already
        /// delivered the timer has no armed op to re-base, so it arms fresh.
        pub fn rebaseDeadline(server: *Self, conn: *ConnType) void {
            // Three callers, all storing a target earlier than the armed
            // timer. The dial's per-try connect budget (`.l7_dialing`); the
            // request deadline installed at routing (`.l7_reading_head`,
            // §8), which must re-base here because the reuse path never
            // reaches the dial; and the #235 head budget, installed on the
            // first parse that comes back Incomplete — also from
            // `.l7_reading_head`, but a different narrowing: routing
            // tightens to the *exchange* cap, this one tightens the idle
            // window to the head read. That third one reaches here through
            // `narrowDeadline`, which is what establishes "earlier" for it
            // rather than assuming it.
            assert(conn.state == .l7_dialing or conn.state == .l7_reading_head);
            // A prior dial's rebase cancel can still be draining if the
            // exchange outran it across a keep-alive turnaround. It re-arms
            // the timer at the target this dial just stored (deadline_ns is
            // shared), so defer — a second cancel would double-arm the op.
            if (conn.armed.deadline_cancel) return;
            if (!conn.armed.deadline) {
                server.armDeadline(conn);
                return;
            }
            conn.arm(&conn.op_deadline_cancel, "deadline_cancel");
            server.io.timerCancel(
                &conn.op_deadline.completion,
                &conn.op_deadline_cancel.completion,
                ConnType,
                conn,
                onDeadlineRebase,
            );
        }

        /// Lazy tick-and-compare (§4): the stored deadline is the truth;
        /// a fire before it is due re-arms for the remainder.
        fn onDeadline(conn: *ConnType, result: Io.TimerError!void) void {
            const server = conn.server;
            conn.delivered(&conn.op_deadline, "deadline");
            if (result) |_| {
                if (conn.isTearingDown()) {
                    // Fired while the cancel was in flight — legal race;
                    // the cancel completion still arrives (§4).
                    server.continueTeardown(conn);
                    return;
                }
                // A rebase cancel (§8) in flight owns the re-arm — it is
                // still matching against this very completion, so no path
                // here may arm a fresh timer for it to find; onDeadline-
                // Rebase re-arms at the stored target once it drains.
                // Expiry is not exempt: the §6 lifetime clamp can store a
                // target already in the past, so the dial's own re-base
                // leaves the deadline due the moment this delivery lands.
                if (conn.armed.deadline_cancel) return;
                if (server.io.nowNs() >= conn.deadline_ns) {
                    server.expireDeadline(conn);
                } else {
                    server.armDeadline(conn);
                }
            } else |err| {
                assert(err == error.Canceled);
                if (conn.isTearingDown()) {
                    // The teardown waits for this delivery (and every
                    // other armed op) before it closes and releases, so
                    // the slot is still live here.
                    server.continueTeardown(conn);
                    return;
                }
                // A live Canceled means a dialUpstream rebase (§8) shortened
                // this timer to the per-try connect budget — the one deadline
                // cancel outside teardown. Re-arm at the stored target, but
                // only once the cancel op has drained, so the cancel cannot
                // match the fresh timer; otherwise onDeadlineRebase re-arms.
                if (!conn.armed.deadline_cancel) {
                    server.armDeadline(conn);
                }
            }
        }

        /// The rebase cancel's completion (§8): dialUpstream canceled the
        /// armed head-read timer so a dial could re-base the deadline to the
        /// tighter connect budget. This cancel and the timer's own Canceled
        /// delivery both land; whichever arrives second (its sibling op now
        /// free) re-arms at the stored target. Teardown overtakes both via
        /// the isTearingDown drain, leaving the timer down for the closes.
        fn onDeadlineRebase(conn: *ConnType) void {
            const server = conn.server;
            conn.delivered(&conn.op_deadline_cancel, "deadline_cancel");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            if (!conn.armed.deadline) {
                server.armDeadline(conn);
            }
        }

        /// The stored deadline is due. An L7 exchange that can still be
        /// answered gets the §8 request-deadline verdict — 504 instead of
        /// a silent teardown — with the deadline re-armed to bound the
        /// verdict's own delivery: a second expiry with the verdict still
        /// pending falls through to teardown, the escape hatch. A timed-
        /// out L7 dial earns the same verdict (RFC 9110 §15.6.5: no
        /// timely response from the upstream — a connect that never
        /// completes is exactly that) via the one connect cancel outside
        /// teardown; a refused dial keeps its prompt 502. Every other
        /// state (L4 — its PROXY-header read included, whose silent peer
        /// this is the reaper for — head read's slowloris, the
        /// static-response drain, a pending verdict) tears down as before.
        fn expireDeadline(server: *Self, conn: *ConnType) void {
            assert(!conn.isTearingDown());
            assert(!conn.armed.deadline); // Delivered; re-armed only below.
            // Both verdict branches re-arm: the caller must have drained the
            // rebase cancel first, or it could match the fresh timer (§8).
            assert(!conn.armed.deadline_cancel);
            server.counters.increment("deadline_expired");
            // Before either verdict branch stores its grace window: both
            // grace deadlines run through `storeDeadline`, which would
            // clamp them straight back to this already-expired cap.
            clearRequestDeadline(conn);
            if (conn.state == .l7_exchanging and
                conn.stream.l7.pending_verdict == .none and
                Proxy.expiryAnswerable(conn))
            {
                // The verdict grace bounds the escape hatch, not idle
                // shedding: use the fixed configured idle timeout, never the
                // pressure-biased one (which collapses toward 1ms and could
                // tear the verdict down before its forced completions land).
                server.storeDeadline(conn, server.config.idle_timeout_ms);
                server.armDeadline(conn);
                Proxy.beginExpiry(server, conn);
                return;
            }
            if (conn.state == .l7_dialing and conn.stream.l7.pending_verdict == .none) {
                // At loop-rest a dialing L7 connection always has its
                // connect in flight, no data ops, and no response byte.
                assert(conn.stream.armed.connect);
                assert(!conn.stream.armed.connect_cancel);
                assert(!conn.stream.l7.response_started);
                conn.stream.l7.pending_verdict = .gateway_timeout;
                // Same fixed grace as the exchange verdict above.
                server.storeDeadline(conn, server.config.idle_timeout_ms);
                server.armDeadline(conn);
                server.armConnectCancel(conn);
                return;
            }
            // The #235 head budget's own reap, witnessed (#258). Every
            // path above answers *something*; this one tears down
            // silently, so without a counter the budget firing and the
            // idle window firing are the same event to every oracle the
            // simulator has — which is exactly how two defects in that
            // budget reached 0.4.0.
            //
            // `head_budget_installed` is the discriminator rather than
            // the state: a connection in `.l7_reading_head` may still be
            // on the idle window, because the budget is installed at the
            // first `Incomplete` and not at the first byte.
            if (conn.state == .l7_reading_head and conn.stream.l7.head_budget_installed and
                conn.stream.l7.pending_verdict == .none)
            {
                // Gated on the verdict, not merely on the state: the
                // grace window this branch installs could in principle
                // fire again before the forced recv's completion lands,
                // and counting that would be two reaps for one. The same
                // re-entrancy the exchange and dial branches above guard,
                // guarded the same way.
                server.counters.increment("l7_head_budget_expired");
                if (Proxy.headExpiryAnswerable(conn)) {
                    // The same fixed grace the other two verdicts take:
                    // the pressure-biased window can collapse toward 1 ms
                    // and tear the verdict down before its forced
                    // completion lands.
                    server.storeDeadline(conn, server.config.idle_timeout_ms);
                    server.armDeadline(conn);
                    Proxy.beginHeadExpiry(server, conn);
                    return;
                }
            }
            server.beginTeardown(conn);
        }

        /// The connect cancel arm+submit shared by teardown and the §8
        /// dial-timeout verdict — the two paths that abort an in-flight
        /// dial (§4: the one cancel outside data-op drain). Callers guard
        /// the double-arm themselves: a verdict cancel may already be in
        /// flight when teardown starts.
        fn armConnectCancel(server: *Self, conn: *ConnType) void {
            assert(conn.stream.armed.connect);
            assert(!conn.stream.armed.connect_cancel);
            conn.stream.arm(&conn.stream.op_connect_cancel, "connect_cancel");
            server.io.connectCancel(
                &conn.stream.op_connect.completion,
                &conn.stream.op_connect_cancel.completion,
                ConnType,
                conn,
                onConnectCancel,
            );
        }

        fn onConnectCancel(conn: *ConnType) void {
            conn.stream.delivered(&conn.stream.op_connect_cancel, "connect_cancel");
            if (conn.isTearingDown()) {
                conn.server.continueTeardown(conn);
                return;
            }
            // A §8 dial-timeout cancel: the connect completion itself
            // carries the verdict (it may deliver before or after this
            // one), so there is nothing to do here. The verdict is still
            // pending, or the 504 answer is already under way.
            assert(conn.state == .l7_dialing or conn.state == .l7_responding or
                conn.state == .l7_draining_request);
            // Still dialing implies the verdict is still pending: only the
            // connect completion's divert clears it, and that divert
            // leaves .l7_dialing in the same callback.
            if (conn.state == .l7_dialing) {
                assert(conn.stream.l7.pending_verdict == .gateway_timeout);
            }
        }

        fn onDeadlineCancel(conn: *ConnType) void {
            conn.delivered(&conn.op_deadline_cancel, "deadline_cancel");
            conn.server.continueTeardown(conn);
        }
    };
}
