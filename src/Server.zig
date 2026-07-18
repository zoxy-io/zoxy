//! The composition root (DESIGN.md §3, §5, §8): owns the pools, the
//! listeners, the counters, and the drain flag; generic over the Io
//! backend so the simulator instantiates the whole serving path without
//! main. All admission decisions happen here — the ladder's single
//! choke point. Slice 7 scope: full connection lifecycle (accept gate →
//! admission → upstream dial → deadline → teardown with armed-op-gated
//! release); the bidirectional relay lands in slice 8, so a connected
//! conn currently tears down immediately.

const std = @import("std");

const Balancer = @import("balancer.zig").Balancer;
const config_module = @import("config.zig");
const constants = @import("constants.zig");
const counters_module = @import("counters.zig");
const conn_module = @import("net/Conn.zig");
const Io = @import("io/io.zig");
const Pool = @import("mem/Pool.zig").Pool;
const relay = @import("net/relay.zig");
const shed = @import("shed.zig");

const assert = std.debug.assert;

pub fn Server(comptime IoType: type) type {
    Io.assertIoInterface(IoType);

    return struct {
        io: *IoType,
        config: *const config_module.Config,
        conns: Pool(ConnType),
        relay_buffers: Pool(relay.RelayBuffer),
        listeners: []ListenerState,
        listeners_count: u16,
        /// The load-balancing policy: resolves a cluster to the endpoint to
        /// dial. Owns its own per-cluster state so the serving path never
        /// hardcodes how an endpoint is chosen (§7).
        balancer: Balancer,
        counters: counters_module.Counters,
        draining: bool,
        /// §8 watermark state for the relay-buffer pool: set once the pool
        /// crosses its high watermark, cleared once it drains back below
        /// the low one (hysteresis). Biases idle timeouts shorter so quiet
        /// connections return their buffers before the wall is reached.
        relay_pressure: bool,
        drain_deadline_completion: IoType.Completion,

        const Self = @This();

        pub const ConnType = conn_module.Conn(IoType);

        /// Pool sizes are injectable so tests and the simulator can force
        /// every exhaustion rung; production uses the §5 defaults.
        pub const InitOptions = struct {
            conn_slots: u32 = constants.conn_slots_max,
            relay_buffers: u32 = constants.relay_buffers_max,
        };

        const ListenerState = struct {
            server: *Self,
            listener: IoType.Listener,
            accept_completion: IoType.Completion,
            /// Backoff timer for kernel-pressure accept failures; never
            /// armed while the accept itself is armed, so the per-listener
            /// ring budget stays one op (§8).
            retry_completion: IoType.Completion,
            cluster_index: u16,
            accepting: bool,
        };

        pub fn init(
            server: *Self,
            arena: std.mem.Allocator,
            io: *IoType,
            config: *const config_module.Config,
            options: InitOptions,
        ) error{ OutOfMemory, HttpListenersUnimplemented }!void {
            assert(config.listeners.len >= 1);
            assert(config.listeners.len <= constants.listeners_max);
            assert(options.relay_buffers >= 1);
            assert(options.relay_buffers <= options.conn_slots);
            // Phase-1 gate: until the L7 state machine lands, an http
            // listener cannot be served — refuse at startup rather than
            // silently relaying it as L4. The proxy slice removes this.
            for (config.listeners) |listener| {
                if (listener.protocol == .http) {
                    return error.HttpListenersUnimplemented;
                }
            }
            server.io = io;
            server.config = config;
            try server.conns.init(arena, options.conn_slots);
            try server.relay_buffers.init(arena, options.relay_buffers);
            server.listeners = try arena.alloc(ListenerState, config.listeners.len);
            server.listeners_count = @intCast(config.listeners.len);
            try server.balancer.init(arena, config);
            server.counters = .{};
            server.draining = false;
            server.relay_pressure = false;
            server.drain_deadline_completion = .{};
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
                    .cluster_index = listener_config.cluster_index,
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
            server.io.stop();
        }

        /// The simulator's leak invariant (§9).
        pub fn isIdle(server: *const Self) bool {
            return server.conns.isFullyReleased() and
                server.relay_buffers.isFullyReleased();
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

        fn admit(server: *Self, state: *ListenerState, client_socket: IoType.Socket) void {
            assert(!server.draining);
            const conn = server.conns.acquire() orelse {
                server.counters.increment("shed_conn_slots");
                shed.closeWithRst(IoType, server.io, client_socket);
                return;
            };
            const buffer = server.relay_buffers.acquire() orelse {
                server.conns.release(conn);
                server.counters.increment("shed_relay_buffers");
                shed.closeQuietly(IoType, server.io, client_socket);
                return;
            };
            server.counters.increment("admitted");
            server.updateRelayPressure();
            conn.prepare(server, client_socket, buffer);
            server.io.setNodelay(client_socket) catch {
                server.counters.increment("kernel_pressure_errors");
            };
            server.storeDeadline(conn, server.config.connect_timeout_ms);
            server.armDeadline(conn);
            server.armConnect(conn, state.cluster_index);
        }

        fn armConnect(server: *Self, conn: *ConnType, cluster_index: u16) void {
            assert(conn.state == .connecting);
            conn.arm(&conn.op_connect, "connect");
            server.io.connect(
                server.balancer.pick(cluster_index),
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
            assert(conn.state == .connecting or conn.state == .relaying);
            conn.state = .tearing_down;
            server.io.shutdown(conn.client_socket, .both);
            if (conn.upstream_socket) |socket| {
                server.io.shutdown(socket, .both);
            }
            if (conn.armed.connect) {
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
            server.relay_buffers.release(conn.relay_buffer);
            server.updateRelayPressure();
            server.conns.release(conn);
            server.counters.increment("completed");
            server.maybeStopAfterDrain();
        }

        /// §8 watermarks before walls: recompute the relay-buffer pressure
        /// flag with hysteresis after every acquire/release. The engage
        /// crossing is witnessed; the wall (admit-time shed) still backs it
        /// up if pressure fails to relieve the load in time.
        fn updateRelayPressure(server: *Self) void {
            const held = server.relay_buffers.acquired_count;
            const capacity: u32 = @intCast(server.relay_buffers.slots.len);
            if (server.relay_pressure) {
                if (held <= constants.relayPressureOff(capacity)) {
                    server.relay_pressure = false;
                }
            } else if (held >= constants.relayPressureOn(capacity)) {
                server.relay_pressure = true;
                server.counters.increment("relay_pressure_engaged");
            }
        }

        /// The idle timeout to apply now, shortened under relay-buffer
        /// pressure so quiet connections return their buffers sooner (§8).
        /// Only the idle deadline is biased — the connect deadline is a
        /// correctness bound and stays fixed. Because a timer never moves
        /// *earlier* once armed (§4), this reaches a connection at its next
        /// deadline store (activity or half-close), not retroactively; the
        /// admit-time wall covers connections that never transact again.
        pub fn idleTimeoutMs(server: *const Self) u32 {
            const configured = server.config.idle_timeout_ms;
            if (!server.relay_pressure) return configured;
            return @max(configured / constants.relay_pressure_idle_divisor, 1);
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
                    server.counters.increment("deadline_expired");
                    server.beginTeardown(conn);
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

        fn onConnectCancel(conn: *ConnType) void {
            conn.delivered(&conn.op_connect_cancel, "connect_cancel");
            conn.server.continueTeardown(conn);
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
