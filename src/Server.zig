//! The composition root (DESIGN.md §3, §5, §8): owns the pools, the
//! listeners, the counters, and the drain flag; generic over the Io
//! backend so the simulator instantiates the whole serving path without
//! main. All admission decisions happen here — the ladder's single
//! choke point. Admission forks on the listener's protocol: an `l4`
//! listener runs the strict TCP relay (`net/relay.zig`), an `http`
//! listener runs the L7 state machine (`http/proxy.zig`); the shared
//! accept gate, deadline, and teardown machinery serve both. The L7
//! request path is filling in slice by slice — head ingestion and the
//! static-response rejects are in; the upstream leg follows — so a valid
//! L7 request currently tears down once its head is parsed.

const std = @import("std");

const Balancer = @import("balancer.zig").Balancer;
const config_module = @import("config.zig");
const constants = @import("constants.zig");
const counters_module = @import("counters.zig");
const conn_module = @import("net/Conn.zig");
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
        /// conn pressure bias downstream capacity — shorter idle timeouts
        /// and keep-alive no longer honored — so quiet connections return
        /// their buffers and slots before the wall is reached; upstream
        /// pressure shortens parked-connection deadlines so idle parked
        /// sockets free their slots for fresh dials before the 503 wall.
        relay_pressure: bool,
        conn_pressure: bool,
        upstream_pressure: bool,
        drain_deadline_completion: IoType.Completion,
        /// The one timer covering every parked upstream (§5): a parked
        /// connection holds no armed op, so this sweep compares stored
        /// deadlines against the clock and reaps overdue connections with
        /// a synchronous close. Armed only while anything is parked, so
        /// an idle process (and a quiescent simulator run) has no ticking
        /// timer.
        upstream_sweep_completion: IoType.Completion,
        upstream_sweep_armed: bool,

        const Self = @This();

        pub const ConnType = conn_module.Conn(IoType);
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
            /// Copied from config so admission forks without reaching back
            /// through the listener index (§6, §7).
            protocol: config_module.Config.Listener.Protocol,
            accepting: bool,
        };

        pub fn init(
            server: *Self,
            arena: std.mem.Allocator,
            io: *IoType,
            config: *const config_module.Config,
            options: InitOptions,
        ) error{OutOfMemory}!void {
            assert(config.listeners.len >= 1);
            assert(config.listeners.len <= constants.listeners_max);
            assert(options.relay_buffers >= 1);
            assert(options.relay_buffers <= options.conn_slots);
            server.io = io;
            server.config = config;
            try server.conns.init(arena, options.conn_slots);
            try server.relay_buffers.init(arena, options.relay_buffers);
            try server.upstreams.init(arena, options.upstream_slots);
            server.listeners = try arena.alloc(ListenerState, config.listeners.len);
            server.listeners_count = @intCast(config.listeners.len);
            server.balancer.init(config);
            server.counters = .{};
            server.draining = false;
            server.relay_pressure = false;
            server.conn_pressure = false;
            server.upstream_pressure = false;
            server.drain_deadline_completion = .{};
            server.upstream_sweep_completion = .{};
            server.upstream_sweep_armed = false;
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
                    .protocol = listener_config.protocol,
                    .accepting = false,
                };
                server.armAccept(state);
            }
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
            // Parked upstreams are idle capacity; the drain sheds them
            // first (§8). Synchronous closes: no armed op to wait for.
            server.reapParked(true);
            server.io.timerStart(
                &server.drain_deadline_completion,
                @as(u64, server.config.drain_deadline_ms) * std.time.ns_per_ms,
                Self,
                server,
                onDrainDeadline,
            );
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
                .dump_counters => server.counters.dump(),
            }
        }

        fn maybeStopAfterDrain(server: *Self) void {
            if (!server.draining) return;
            if (!server.conns.isFullyReleased()) return;
            assert(server.relay_buffers.isFullyReleased());
            // beginDrain reaped every parked slot synchronously and no
            // conn is left to lease one, so the pool must be empty.
            assert(server.upstreams.isFullyReleased());
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

        /// The simulator's leak invariant (§9).
        pub fn isIdle(server: *const Self) bool {
            return server.conns.isFullyReleased() and
                server.relay_buffers.isFullyReleased() and
                server.upstreams.isFullyReleased();
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
                server.counters.increment("kernel_pressure_errors");
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
                server.counters.increment("shed_draining");
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
        /// gate, the conn slot, the deadline, and teardown; they diverge
        /// only in what a fresh connection does next.
        fn admit(server: *Self, state: *ListenerState, client_socket: IoType.Socket) void {
            assert(!server.draining);
            switch (state.protocol) {
                .l4 => server.admitL4(state, client_socket),
                .http => server.admitHttp(state, client_socket),
            }
        }

        /// The shared conn-slot rung (§8): both protocols shed the same
        /// way when slots run out, so the rung lives in one place.
        fn admitConn(server: *Self, client_socket: IoType.Socket) ?*ConnType {
            assert(!server.draining);
            const conn = server.conns.acquire() orelse {
                server.counters.increment("shed_conn_slots");
                shed.closeWithRst(IoType, server.io, client_socket);
                return null;
            };
            server.updateConnPressure();
            return conn;
        }

        /// The shared admission tail (§8 single choke point): counting,
        /// slot prepare, socket options, and the first deadline are
        /// identical across protocols; only the entry state, buffer, and
        /// timeout differ.
        fn finishAdmission(
            server: *Self,
            conn: *ConnType,
            client_socket: IoType.Socket,
            buffer: ?*relay.RelayBuffer,
            state: ConnType.State,
            timeout_ms: u32,
            cluster_index: u16,
        ) void {
            assert(!server.draining);
            assert(state == .connecting or state == .l7_reading_head);
            assert(timeout_ms >= 1);
            server.counters.increment("admitted");
            conn.prepare(server, client_socket, buffer, state, cluster_index);
            server.io.setNodelay(client_socket) catch {
                server.counters.increment("kernel_pressure_errors");
            };
            server.storeDeadline(conn, timeout_ms);
            server.armDeadline(conn);
            assert(conn.deadline_ns > 0);
            assert(conn.armed.deadline);
        }

        fn admitL4(server: *Self, state: *ListenerState, client_socket: IoType.Socket) void {
            const conn = server.admitConn(client_socket) orelse return;
            const buffer = server.relay_buffers.acquire() orelse {
                server.conns.release(conn);
                server.updateConnPressure();
                server.counters.increment("shed_relay_buffers");
                shed.closeQuietly(IoType, server.io, client_socket);
                return;
            };
            server.updateRelayPressure();
            server.finishAdmission(
                conn,
                client_socket,
                buffer,
                .connecting,
                server.config.connect_timeout_ms,
                state.cluster_index,
            );
            server.armConnect(conn, state.cluster_index);
        }

        /// L7 admission (§5, §7): a slot only — an idle L7 connection
        /// holds no relay buffer, which is acquired when a body relay
        /// starts. The head-read deadline is armed so a slowloris meets
        /// the clock or `head_bytes_max` first (§7).
        fn admitHttp(server: *Self, state: *ListenerState, client_socket: IoType.Socket) void {
            const conn = server.admitConn(client_socket) orelse return;
            server.finishAdmission(
                conn,
                client_socket,
                null,
                .l7_reading_head,
                server.idleTimeoutMs(),
                state.cluster_index,
            );
            // The L7 path routes and filters once the head parses; hand it
            // the listener's tables (§7).
            conn.routes = state.routes;
            conn.filters = state.filters;
            assert(conn.routes.len >= 1);
            Proxy.start(server, conn);
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

        fn armConnect(server: *Self, conn: *ConnType, cluster_index: u16) void {
            assert(conn.state == .connecting);
            conn.arm(&conn.op_connect, "connect");
            // L4 dials hold no Upstream slot, so the load table reflects
            // L7 leases only — the P2C draw still spreads L4 dials by the
            // observed L7 load, and evenly when there is none.
            server.io.connect(
                server.balancer.pick(cluster_index, &server.upstreams.leased_counts).address,
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
            const socket = result catch {
                server.counters.increment("upstream_connect_failed");
                server.beginTeardown(conn);
                return;
            };
            conn.upstream_socket = socket;
            server.io.setNodelay(socket) catch {
                server.counters.increment("kernel_pressure_errors");
            };
            conn.state = .relaying;
            server.storeDeadline(conn, server.idleTimeoutMs());
            relay.Relay(IoType).start(server, conn);
        }

        /// Teardown is a state, not an event (§5): shutdown both fds,
        /// cancel pending connect/timer (the only legal cancels, §4),
        /// then closes once data ops drain; the last terminal completion
        /// releases the slot.
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
                conn.arm(&conn.op_connect_cancel, "connect_cancel");
                server.io.connectCancel(
                    &conn.op_connect.completion,
                    &conn.op_connect_cancel.completion,
                    ConnType,
                    conn,
                    onConnectCancel,
                );
            }
            if (conn.armed.deadline) {
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

        /// Public for the relay: a data completion delivered during
        /// teardown re-enters here (§5 — ops drain, then closes).
        pub fn continueTeardown(server: *Self, conn: *ConnType) void {
            assert(conn.isTearingDown());
            if (conn.state == .tearing_down) {
                const blocking_ops = conn.armed.connect or
                    conn.armed.data_client_to_upstream or
                    conn.armed.data_upstream_to_client;
                if (!blocking_ops) {
                    conn.state = .closing;
                    conn.arm(&conn.op_close_client, "close_client");
                    server.io.close(
                        conn.client_socket,
                        &conn.op_close_client.completion,
                        ConnType,
                        conn,
                        onCloseClient,
                    );
                    if (conn.upstream_socket) |socket| {
                        conn.arm(&conn.op_close_upstream, "close_upstream");
                        server.io.close(
                            socket,
                            &conn.op_close_upstream.completion,
                            ConnType,
                            conn,
                            onCloseUpstream,
                        );
                    }
                }
            }
            server.maybeRelease(conn);
        }

        /// §5 release rule: closes submitted and the armed-op set empty —
        /// only then does the slot go back to the pool.
        fn maybeRelease(server: *Self, conn: *ConnType) void {
            assert(conn.isTearingDown());
            if (conn.state != .closing) return;
            if (conn.armedCount() != 0) return;
            // An idle L7 connection holds no relay buffer (§5); only
            // release one that was actually acquired.
            if (conn.relay_buffer) |buffer| {
                server.relay_buffers.release(buffer);
                server.updateRelayPressure();
                conn.relay_buffer = null;
            }
            // The leased upstream slot rides the same release rule: its
            // socket (if any) was closed by this teardown's
            // close_upstream, so the slot is inert by the time the armed
            // set empties (§5). Parking replaces this with reuse later.
            if (conn.upstream) |leased| {
                server.releaseUpstream(leased);
                conn.upstream = null;
            }
            server.conns.release(conn);
            server.updateConnPressure();
            server.counters.increment("completed");
            server.maybeStopAfterDrain();
        }

        /// §8 kernel-pressure rung on the data path: a non-orderly op
        /// failure on a live socket is resource exhaustion (ENOBUFS/
        /// ENOMEM), which the seam collapses to Unexpected. Orderly
        /// failures (EndOfStream, Reset, Canceled) are peeled off by the
        /// caller; only Unexpected is witnessed here, matching the
        /// accept/connect/setNodelay sites. Shared by the L4 relay and the
        /// L7 state machine.
        pub fn witnessKernelPressure(server: *Self, err: anyerror) void {
            if (err == error.Unexpected) {
                server.counters.increment("kernel_pressure_errors");
            }
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

        /// Any pressure that downstream keep-alive holds capacity against
        /// (§8): an idle downstream connection pins a conn slot, and its
        /// next body relay claims a relay buffer. Public for the L7
        /// render's persistence decision.
        pub fn downstreamPressured(server: *const Self) bool {
            return server.relay_pressure or server.conn_pressure;
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
            server.updateUpstreamPressure();
            return leased;
        }

        pub fn releaseUpstream(
            server: *Self,
            leased: *upstream_module.UpstreamPool(IoType).Upstream,
        ) void {
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
            conn.deadline_ns = deadline_ns;
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
                if (server.io.nowNs() >= conn.deadline_ns) {
                    server.expireDeadline(conn);
                } else {
                    server.armDeadline(conn);
                }
            } else |err| {
                assert(err == error.Canceled);
                // The deadline is not a blocking op, so its Canceled
                // delivery can arrive after closes were submitted (.closing).
                assert(conn.isTearingDown());
                server.continueTeardown(conn);
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
            server.counters.increment("deadline_expired");
            if (conn.state == .l7_exchanging and
                conn.l7.pending_verdict == .none and
                Proxy.expiryAnswerable(conn))
            {
                server.storeDeadline(conn, server.idleTimeoutMs());
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
                server.storeDeadline(conn, server.idleTimeoutMs());
                server.armDeadline(conn);
                conn.arm(&conn.op_connect_cancel, "connect_cancel");
                server.io.connectCancel(
                    &conn.op_connect.completion,
                    &conn.op_connect_cancel.completion,
                    ConnType,
                    conn,
                    onConnectCancel,
                );
                return;
            }
            server.beginTeardown(conn);
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

        fn onCloseClient(conn: *ConnType) void {
            conn.delivered(&conn.op_close_client, "close_client");
            conn.server.maybeRelease(conn);
        }

        fn onCloseUpstream(conn: *ConnType) void {
            conn.delivered(&conn.op_close_upstream, "close_upstream");
            conn.server.maybeRelease(conn);
        }
    };
}
