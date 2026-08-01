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
const health_module = @import("net/health.zig");
const Io = @import("io/io.zig");
const Pool = @import("mem/Pool.zig").Pool;
const proxy = @import("http/proxy.zig");
const router = @import("http/router.zig");
const filter = @import("http/filter.zig");
const relay = @import("net/relay.zig");
const shed = @import("shed.zig");
const upstream_module = @import("net/upstream.zig");

const assert = std.debug.assert;

pub fn Server(comptime IoType: type) type {
    Io.assertIoInterface(IoType);

    return struct {
        io: *IoType,
        config: *const config_module.Config,
        conns: Pool(ConnType),
        relay_buffers: Pool(relay.RelayBuffer),
        /// The shared upstream connection pool (§3, §5): leased per L7
        /// exchange today; parking joins with keep-alive.
        upstreams: upstream_module.UpstreamPool(IoType),
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
        /// The load-balancing policy: resolves a cluster to the endpoint to
        /// dial. Owns its own per-cluster state so the serving path never
        /// hardcodes how an endpoint is chosen (§7).
        balancer: Balancer,
        counters: counters_module.Counters,
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
        /// Highest armed-op count any one connection has reached (§8):
        /// `Conn.arm` asserts the `conn_ops_max` budget on every arm and,
        /// under runtime safety only (never in the shipped ReleaseFast
        /// build), records the peak here, so a test can claim a race
        /// co-armed exactly the budgeted worst case, not merely stayed
        /// under it.
        armed_ops_peak: u8,
        /// The raw errno of the most recent kernel-pressure failure, or 0
        /// (§8). Reported as a gauge rather than a counter because it is a
        /// level — "what is failing now" — and because an errno space is
        /// far too wide for a counter each.
        last_pressure_errno: u16,
        drain_deadline_completion: IoType.Completion,
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
        /// The §7 active health prober: one probe in flight, budgeted
        /// separately (`constants.health_probe_ops_max`). Off unless a
        /// cluster sets `check`; its `healthy` mask is what the balancer
        /// picks through.
        health: health_module.Checker(IoType),

        const Self = @This();

        pub const ConnType = conn_module.Conn(IoType);
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
            /// The listener's §7 filter rules, handed to each admitted L7
            /// connection so `routeRequest` can evaluate policy.
            filters: []const filter.Rule,
            /// The listener's §7 client-address forwarding mode (null = off),
            /// handed over the same way: trust depends on what is in front
            /// of this socket, so it cannot live on the cluster.
            forwarded: ?config_module.Config.Listener.Forwarded,
            /// Copied from config so admission forks without reaching back
            /// through the listener index (§6, §7).
            protocol: config_module.Config.Listener.Protocol,
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
                @sizeOf(u16) + // Server.l4_inflight
                @sizeOf(bool) + // Checker.healthy
                @sizeOf(u8) + // Checker.fail_streaks
                @sizeOf(u8); // Checker.ok_streaks
            const cursors = @as(u64, config.clusters.len) * @sizeOf(u64);
            const scratch = @as(u64, keys.stride) * @sizeOf(u16);
            const total = count * per_key + cursors + scratch;
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
            // The ring the backend registered and the limit this server
            // accounts against must be the same number, or the shed rung
            // fires at a size no config names. Zero is the L4-only shape.
            assert(io.bufferGroupCount() == options.head_buffers);
            server.io = io;
            server.config = config;
            try server.conns.init(arena, options.conn_slots);
            try server.relay_buffers.init(arena, options.relay_buffers);
            // One index space, derived once and shared by every
            // endpoint-keyed table so they cannot disagree about a key.
            const keys = endpointKeysFor(config);
            try server.upstreams.init(arena, options.upstream_slots, keys);
            server.l4_inflight = try arena.alloc(u16, keys.count);
            @memset(server.l4_inflight, 0);
            server.listeners = try arena.alloc(ListenerState, config.listeners.len);
            server.listeners_count = @intCast(config.listeners.len);
            try server.balancer.init(arena, config, keys);
            server.counters = .{};
            server.draining = false;
            server.relay_pressure = false;
            server.conn_pressure = false;
            server.upstream_pressure = false;
            server.head_pressure = false;
            server.head_buffers_in_use = 0;
            server.head_buffers_capacity = options.head_buffers;
            // Deliberately not zeroed: a discard sink's contents are never
            // read, the same argument the head buffers make (§5).
            server.drain_sink = undefined;
            server.armed_ops_peak = 0;
            server.last_pressure_errno = 0;
            server.drain_deadline_completion = .{};
            server.upstream_sweep_completion = .{};
            server.upstream_sweep_armed = false;
            server.admin.init(server, config.admin_bind);
            server.access_log.init(server, config.access_log_sink, options.access_log_buffer_bytes);
            try server.access_log.reserve(arena);
            try server.health.init(arena, server, keys);
        }

        /// Override the admin/metrics bind before `start` — the simulator
        /// and tests set it directly; production seeds it from the config's
        /// `admin` block in `init`. Must be called before `start`.
        pub fn setAdminBind(server: *Self, bind_address: std.Io.net.IpAddress) void {
            server.admin.setBind(bind_address);
        }

        pub fn start(server: *Self) Io.ListenError!void {
            assert(!server.draining);
            assert(server.listeners_count >= 1);
            for (server.config.listeners, 0..) |listener_config, index| {
                const state = &server.listeners[index];
                state.* = .{
                    .server = server,
                    .listener = try server.io.listen(listener_config.bind_address),
                    .accept_completion = .{},
                    .retry_completion = .{},
                    // L4 has one route (the whole listener → one cluster);
                    // L7 admits under the first route and refines to the
                    // path's route once the head parses (§7).
                    .cluster_index = listener_config.routes[0].cluster_index,
                    .routes = listener_config.routes,
                    .filters = listener_config.filters,
                    .forwarded = listener_config.forwarded,
                    .protocol = listener_config.protocol,
                    .accepting = false,
                };
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
        }

        fn onSignal(server: *Self, signal: Io.Signal) void {
            switch (signal) {
                .terminate => server.beginDrain(),
                .dump_counters => {
                    const snapshot = server.gauges();
                    server.counters.dump(&snapshot);
                },
            }
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
            assert(server.relay_buffers.isFullyReleased());
            // beginDrain reaped every parked slot synchronously and no
            // conn is left to lease one, so the pool must be empty.
            assert(server.upstreams.isFullyReleased());
            // Every conn released its ring buffer on the way out, so the
            // in-use count the server owns must have followed to zero.
            assert(server.head_buffers_in_use == 0);
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
            return server.l4Released() and
                server.conns.isFullyReleased() and
                server.relay_buffers.isFullyReleased() and
                server.upstreams.isFullyReleased() and
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
        /// holds mid-scenario, not only when idle.
        pub fn reconcile(server: *const Self) bool {
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
        /// holds a slot and head buffer only and acquires a buffer per body
        /// leg (§5). The second divergence is `startProtocol`.
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
            server.finishAdmission(conn, client_socket, buffer, state);
            server.startProtocol(conn, state.protocol);
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
        /// is dialing, so it gets the connect budget (§8); an L7 one is
        /// reading a head, so a slowloris meets the clock or
        /// `head_bytes_max`, whichever comes first (§7).
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
        /// the slot deliberately: on this branch the second caller does not
        /// exist, and a field with one writer and one reader would be state
        /// kept for a caller that is not here (§1). The phase that needs to
        /// recall a connection's protocol is the one that should decide how.
        ///
        /// The state and deadline stores are idempotent at admission — the
        /// tail below set exactly these values from the same protocol, and
        /// `admit` reaches here through one synchronous chain, so the clock
        /// and the pressure flags `entryTimeoutMs` reads cannot have moved
        /// between the two writes — and they are load-bearing for a
        /// hand-over, which arrives in whatever state its phase ran in.
        /// Keeping them here is what makes both callers a single call.
        fn startProtocol(
            server: *Self,
            conn: *ConnType,
            protocol: config_module.Config.Listener.Protocol,
        ) void {
            assert(!server.draining);
            assert(!conn.isTearingDown());
            // The one timer this connection ever arms is already armed
            // (§4: a state transition only ever *stores* a new deadline).
            assert(conn.armed.deadline);
            conn.state = entryState(protocol);
            server.storeDeadline(conn, server.entryTimeoutMs(protocol));
            switch (protocol) {
                .l4 => {
                    // A recv must always have a buffer posted (§6).
                    assert(conn.relay_buffer != null);
                    server.armConnect(conn, conn.cluster_index);
                },
                .http => {
                    // An idle L7 connection holds no relay buffer (§5).
                    assert(conn.relay_buffer == null);
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

        /// The shared admission tail (§8 single choke point): counting, slot
        /// prepare, socket options, the routing tables, and the one deadline
        /// timer this connection ever arms are identical across protocols —
        /// the protocol only chooses which values go in, through
        /// `entryState` and `entryTimeoutMs`.
        fn finishAdmission(
            server: *Self,
            conn: *ConnType,
            client_socket: IoType.Socket,
            buffer: ?*relay.RelayBuffer,
            listener: *const ListenerState,
        ) void {
            assert(!server.draining);
            server.counters.increment("admitted");
            conn.prepare(
                server,
                client_socket,
                buffer,
                entryState(listener.protocol),
                listener.cluster_index,
                listener.protocol,
                // Asked once, here, and kept: at log time the socket may
                // already be closed (§8).
                server.io.peerAddress(client_socket),
            );
            server.io.setNodelay(client_socket) catch |err| {
                server.witnessKernelPressure(.set_option, err);
            };
            // The L7 path routes and filters once the head parses (§7);
            // every connection gets its listener's tables and the protocol
            // decides whether it reads them — an l4 listener resolves to
            // exactly one catch-all route and no filters, so this is one
            // rule rather than a third fork.
            conn.routes = listener.routes;
            conn.filters = listener.filters;
            conn.forwarded = listener.forwarded;
            assert(conn.routes.len >= 1);
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

        /// The release pair: an L7 connection going idle on keep-alive
        /// returns its buffer so idle costs a slot + head buffer only (§5).
        pub fn releaseRelayBuffer(server: *Self, buffer: *relay.RelayBuffer) void {
            server.relay_buffers.release(buffer);
            server.updateRelayPressure();
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
            assert(conn.head_buffer_id != ConnType.head_buffer_none);
            assert(server.head_buffers_in_use >= 1);
            server.io.bufferGroupReturn(conn.head_buffer_id);
            conn.head_buffer_id = ConnType.head_buffer_none;
            server.head_buffers_in_use -= 1;
            server.updateHeadPressure();
        }

        /// The shared lingering-close discard target (§7) — see the field.
        pub fn drainSink(server: *Self) []u8 {
            return server.drain_sink[0..];
        }

        /// The same pair for conn slots, with `admitConn` as its acquire
        /// side: pressure follows occupancy in both directions (§5, §8), so
        /// every slot return goes through here and the flag can never
        /// outlive the occupancy that raised it.
        fn releaseConn(server: *Self, conn: *ConnType) void {
            server.conns.release(conn);
            server.updateConnPressure();
        }

        fn armConnect(server: *Self, conn: *ConnType, cluster_index: u16) void {
            assert(conn.state == .connecting);
            const pick = server.balancer.pick(
                cluster_index,
                &server.endpointLoad(),
                server.health.healthy,
                &conn.client_address,
            ) orelse {
                // Every endpoint is at its §8 cap. An L4 listener has no
                // way to say so — it relays bytes, and there is no
                // protocol to answer in — so the ladder's L4 answer
                // applies: close. Counted outside the gate identity,
                // because this connection was admitted before an endpoint
                // was ever picked (§8).
                server.counters.increment("l4_shed_endpoint_inflight");
                // Nothing was armed for this dial yet — the arm below is
                // the first — so teardown here cancels only the deadline
                // admission left running (§5).
                assert(!conn.armed.connect);
                server.beginTeardown(conn);
                return;
            };
            conn.arm(&conn.op_connect, "connect");
            // An L4 dial holds no slot to record the endpoint on, so the
            // access log takes it here — the only place that knows which
            // origin this connection is being relayed to (§8).
            conn.log.endpoint_index = pick.endpoint_index;
            server.chargeL4(conn, cluster_index, pick.endpoint_index);
            server.io.connect(
                pick.address,
                &conn.op_connect.completion,
                ConnType,
                conn,
                onConnect,
            );
        }

        fn onConnect(conn: *ConnType, result: Io.ConnectError!IoType.Socket) void {
            const server = conn.server;
            conn.delivered(&conn.op_connect, "connect");
            if (conn.isTearingDown()) {
                // The teardown raced the dial. A socket that arrived
                // anyway must still be shut down and closed.
                if (result) |socket| {
                    conn.upstream_socket = socket;
                    server.io.shutdown(socket, .both);
                } else |_| {}
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .connecting);
            const socket = result catch |err| {
                server.counters.increment("upstream_connect_failed");
                // Refused/timed-out/unreachable arrive typed and are the
                // origin's verdict; anything else is resource pressure on
                // our side — ephemeral ports and socket memory both land
                // here — and wants the opposite response. The dial counter
                // cannot tell them apart, so witness the pressure too (§8).
                server.witnessKernelPressure(.connect, err);
                server.beginTeardown(conn);
                return;
            };
            conn.upstream_socket = socket;
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
            if (conn.upstream_socket) |socket| {
                server.io.shutdown(socket, .both);
            }
            // A dial-timeout verdict (§8) may already have a cancel in
            // flight; submitting a second would double-arm the op.
            if (conn.armed.connect and !conn.armed.connect_cancel) {
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

        /// Public for the relay: a completion delivered during teardown
        /// re-enters here (§5). The delivery that empties the armed set
        /// finishes the whole teardown synchronously: nothing references
        /// either fd any more, so the closes are plain syscalls — the
        /// same close-after-full-drain discipline `detachUpstream` and
        /// the parked reap already use — and the slot releases in the
        /// same call instead of waiting out two close completions. A
        /// dial completing against its own teardown still peaks at four
        /// armed ops: the `conn_ops_max` budget the CQ is sized by (§8).
        pub fn continueTeardown(server: *Self, conn: *ConnType) void {
            assert(conn.state == .tearing_down);
            if (conn.armedCount() != 0) return;
            // Nothing armed: no op references either fd, which is what
            // makes the synchronous closes and the release safe.
            assert(conn.armedCount() == 0);
            server.io.closeNow(conn.client_socket);
            if (conn.upstream_socket) |socket| {
                server.io.closeNow(socket);
                conn.upstream_socket = null;
            }
            // An idle L7 connection holds no relay buffer (§5); only
            // release one that was actually acquired.
            if (conn.relay_buffer) |buffer| {
                server.releaseRelayBuffer(buffer);
                conn.relay_buffer = null;
            }
            // Same rule for the ring buffer: nothing armed references it
            // (asserted above), so the return cannot race a landing recv.
            if (conn.head_buffer_id != ConnType.head_buffer_none) {
                server.returnHeadBuffer(conn);
            }
            // The leased upstream slot rides the same release rule: its
            // socket (if any) was closed just above, so the slot is
            // inert (§5). Parking replaces this with reuse later.
            if (conn.upstream) |leased| {
                server.releaseUpstream(leased);
                conn.upstream = null;
            }
            // The L4 endpoint charge rides the same rule: the socket that
            // made this connection work against an origin is closed just
            // above, so the origin is no longer carrying it (§7).
            server.releaseL4(conn);
            assert(conn.relay_buffer == null);
            assert(conn.upstream == null);
            assert(conn.charged_endpoint == conn_module.LogState.endpoint_none);
            // The last chance to say anything about this connection (§8).
            // An exchange that reached a verdict already spoke and is
            // skipped by `emitted`; what is left here is everything that
            // ended without one — a client that left mid-request, a
            // truncated body, a drain straggler — and every L4 connection,
            // whose whole life is the unit being logged.
            server.logExchange(conn);
            server.releaseConn(conn);
            server.counters.increment("completed");
            server.maybeStopAfterDrain();
        }

        /// Start this connection's access-log clock, if it owes a line and
        /// has not started one (§8). The L7 path calls it when a request's
        /// first head byte lands — which is when the request begins, not
        /// when its head finishes parsing, so a slowloris's line reports
        /// the whole time it spent dribbling.
        pub fn beginLogRequest(server: *Self, conn: *ConnType) void {
            if (server.access_log.sink == null) return;
            if (conn.log.started_wall_ns != 0) return;
            conn.log.started_wall_ns = server.io.nowWallNs();
            assert(conn.log.started_wall_ns != 0);
        }

        /// Write the access-log line this connection owes, if any (§8).
        ///
        /// The caller sets `conn.log.status` and `conn.log.outcome` when it
        /// knows them; the defaults — status 0, outcome `aborted` — are
        /// deliberately the answer for the caller that does not, which is
        /// teardown. That is what lets one function serve both the path
        /// that decided an outcome and the path that never got one, with
        /// `emitted` deciding which of the two speaks for an exchange that
        /// took both.
        pub fn logExchange(server: *Self, conn: *ConnType) void {
            if (server.access_log.sink == null) return;
            if (conn.log.emitted) return;
            // Nothing was asked of this connection: an L7 slot that idled
            // out between requests, or one reaped before its first byte.
            if (conn.log.started_wall_ns == 0) return;
            conn.log.emitted = true;
            const now_wall_ns = server.io.nowWallNs();
            // Both indices are pool/config positions this connection has
            // carried since routing; a stale one would name another
            // operator's backend in the line, so they are checked here
            // rather than left to Zig's bounds check to turn into a panic.
            assert(conn.cluster_index < server.config.clusters.len);
            const cluster = server.config.clusters[conn.cluster_index];
            if (conn.log.endpoint_index != conn_module.LogState.endpoint_none) {
                assert(conn.log.endpoint_index < cluster.endpoints.len);
            }
            const entry: access_log_module.Record = .{
                .kind = switch (conn.protocol) {
                    .l4 => .l4,
                    .http => .http,
                },
                .outcome = conn.log.outcome,
                .started_wall_ns = conn.log.started_wall_ns,
                // Saturating: the wall clock can step backwards under NTP,
                // and a duration that wrapped to eighteen quintillion
                // microseconds would be read as a stall that never happened.
                .duration_ns = now_wall_ns -| conn.log.started_wall_ns,
                .client = conn.client_address,
                .upstream = if (conn.log.endpoint_index == conn_module.LogState.endpoint_none)
                    null
                else
                    cluster.endpoints[conn.log.endpoint_index],
                .cluster = cluster.name,
                .bytes_in = conn.log.bytes_in,
                .bytes_out = conn.log.bytes_out,
                .method = conn.log.methodSlice(),
                .host = conn.log.hostSlice(),
                .path = conn.log.pathSlice(),
                .status = conn.log.status,
                .upstream_reused = conn.l7.upstream_was_reused,
                .upstream_replayed = conn.l7.replay_used,
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
        /// for a scrape or a SIGUSR1 dump (§8). The only producer of
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
                .kernel_pressure_last_errno = server.last_pressure_errno,
                .health_endpoints_checked = server.health.checked_count,
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
        fn chargeL4(server: *Self, conn: *ConnType, cluster_index: u16, endpoint_index: u16) void {
            assert(conn.protocol == .l4);
            assert(conn.charged_endpoint == conn_module.LogState.endpoint_none);
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
            if (conn.charged_endpoint == conn_module.LogState.endpoint_none) return;
            const key = server.upstreams.keys.key(conn.charged_cluster, conn.charged_endpoint);
            assert(server.l4_inflight[key] >= 1);
            server.l4_inflight[key] -= 1;
            conn.charged_endpoint = conn_module.LogState.endpoint_none;
        }

        pub fn releaseUpstream(
            server: *Self,
            leased: *upstream_module.UpstreamPool(IoType).Upstream,
        ) void {
            // A parked slot must be unparked before release (its idle-list
            // links would dangle), and at least this slot is leased.
            assert(!leased.parked);
            assert(server.upstreams.leasedCount() >= 1);
            server.upstreams.release(leased);
            server.updateUpstreamPressure();
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
            if (conn.l7.request_deadline_ns != 0) {
                deadline_ns = @min(deadline_ns, conn.l7.request_deadline_ns);
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
            conn.l7.request_deadline_ns = 0;
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

        /// Re-base the armed deadline to the freshly stored (earlier) target
        /// (§8): the single lazy timer never moves *earlier* once armed (§4),
        /// so an L7 dial needing a tighter per-try connect budget than the
        /// head-read timer cancels it here — the one deadline cancel outside
        /// teardown. onDeadlineRebase and onDeadline re-arm at the stored
        /// target once both the cancel and the timer's Canceled have drained
        /// (so the cancel cannot match the fresh timer). A path that already
        /// delivered the timer has no armed op to re-base, so it arms fresh.
        pub fn rebaseDeadline(server: *Self, conn: *ConnType) void {
            // Two callers, both storing a target earlier than the armed
            // timer: the dial's per-try connect budget (`.l7_dialing`) and
            // the request deadline installed at routing (`.l7_reading_head`,
            // §8) — which must re-base here because the reuse path never
            // reaches the dial.
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
        /// state (L4, head read's slowloris, the static-response drain, a
        /// pending verdict) tears down as before.
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
                conn.l7.pending_verdict == .none and
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
            if (conn.state == .l7_dialing and conn.l7.pending_verdict == .none) {
                // At loop-rest a dialing L7 connection always has its
                // connect in flight, no data ops, and no response byte.
                assert(conn.armed.connect);
                assert(!conn.armed.connect_cancel);
                assert(!conn.l7.response_started);
                conn.l7.pending_verdict = .gateway_timeout;
                // Same fixed grace as the exchange verdict above.
                server.storeDeadline(conn, server.config.idle_timeout_ms);
                server.armDeadline(conn);
                server.armConnectCancel(conn);
                return;
            }
            server.beginTeardown(conn);
        }

        /// The connect cancel arm+submit shared by teardown and the §8
        /// dial-timeout verdict — the two paths that abort an in-flight
        /// dial (§4: the one cancel outside data-op drain). Callers guard
        /// the double-arm themselves: a verdict cancel may already be in
        /// flight when teardown starts.
        fn armConnectCancel(server: *Self, conn: *ConnType) void {
            assert(conn.armed.connect);
            assert(!conn.armed.connect_cancel);
            conn.arm(&conn.op_connect_cancel, "connect_cancel");
            server.io.connectCancel(
                &conn.op_connect.completion,
                &conn.op_connect_cancel.completion,
                ConnType,
                conn,
                onConnectCancel,
            );
        }

        fn onConnectCancel(conn: *ConnType) void {
            conn.delivered(&conn.op_connect_cancel, "connect_cancel");
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
                assert(conn.l7.pending_verdict == .gateway_timeout);
            }
        }

        fn onDeadlineCancel(conn: *ConnType) void {
            conn.delivered(&conn.op_deadline_cancel, "deadline_cancel");
            conn.server.continueTeardown(conn);
        }
    };
}
