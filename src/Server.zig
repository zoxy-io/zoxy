//! The composition root (DESIGN.md §3, §5, §8): owns the pools, the
//! listeners, the counters, and the drain flag; generic over the Io
//! backend so the simulator instantiates the whole serving path without
//! main. All admission decisions happen here — the ladder's single
//! choke point. Slice 7 scope: full connection lifecycle (accept gate →
//! admission → upstream dial → deadline → teardown with armed-op-gated
//! release); the bidirectional relay lands in slice 8, so a connected
//! conn currently tears down immediately.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const counters_module = @import("counters.zig");
const conn_module = @import("net/Conn.zig");
const Io = @import("io/Io.zig");
const Pool = @import("mem/Pool.zig").Pool;
const relay = @import("net/relay.zig");
const shed = @import("shed.zig");

const assert = std.debug.assert;

pub fn Server(comptime IoType: type) type {
    Io.assertIoInterface(IoType);

    return struct {
        io: *IoType,
        cfg: *const config_module.Config,
        conns: Pool(ConnType),
        relay_buffers: Pool(relay.RelayBuffer),
        listeners: []ListenerState,
        listeners_count: u16,
        endpoints_next: []u16,
        counters: counters_module.Counters,
        draining: bool,

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
            cluster_index: u16,
            accepting: bool,
        };

        pub fn init(
            server: *Self,
            arena: std.mem.Allocator,
            io: *IoType,
            cfg: *const config_module.Config,
            options: InitOptions,
        ) error{OutOfMemory}!void {
            assert(cfg.listeners.len >= 1);
            assert(cfg.listeners.len <= constants.listeners_max);
            assert(options.relay_buffers >= 1);
            assert(options.relay_buffers <= options.conn_slots);
            server.io = io;
            server.cfg = cfg;
            try server.conns.init(arena, options.conn_slots);
            try server.relay_buffers.init(arena, options.relay_buffers);
            server.listeners = try arena.alloc(ListenerState, cfg.listeners.len);
            server.listeners_count = @intCast(cfg.listeners.len);
            server.endpoints_next = try arena.alloc(u16, cfg.clusters.len);
            @memset(server.endpoints_next, 0);
            server.counters = .{};
            server.draining = false;
        }

        pub fn start(server: *Self) Io.ListenError!void {
            assert(!server.draining);
            assert(server.listeners_count >= 1);
            for (server.cfg.listeners, 0..) |listener_config, index| {
                const state = &server.listeners[index];
                state.* = .{
                    .server = server,
                    .listener = try server.io.listen(listener_config.bind_address),
                    .accept_completion = .{},
                    .cluster_index = listener_config.cluster_index,
                    .accepting = false,
                };
                server.armAccept(state);
            }
        }

        /// Drain (§8): stop accepting. Slice 9 adds deadline clamping and
        /// the final stop; admitted work already finishes on its own.
        pub fn beginDrain(server: *Self) void {
            if (server.draining) return;
            server.draining = true;
            for (server.listeners[0..server.listeners_count]) |*state| {
                server.io.listenClose(state.listener);
            }
        }

        /// The simulator's leak invariant (§9).
        pub fn isIdle(server: *const Self) bool {
            return server.conns.isFullyReleased() and
                server.relay_buffers.isFullyReleased();
        }

        pub fn activeCount(server: *const Self) u32 {
            return server.conns.acquired_count;
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
                server.counters.increment("kernel_pressure_errors");
                if (!server.draining) {
                    server.armAccept(state);
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
            conn.prepare(server, client_socket, buffer);
            server.io.setNodelay(client_socket) catch {
                server.counters.increment("kernel_pressure_errors");
            };
            server.storeDeadline(conn, server.cfg.connect_timeout_ms);
            server.armDeadline(conn);
            server.armConnect(conn, state.cluster_index);
        }

        fn armConnect(server: *Self, conn: *ConnType, cluster_index: u16) void {
            assert(conn.state == .connecting);
            assert(cluster_index < server.cfg.clusters.len);
            const cluster = &server.cfg.clusters[cluster_index];
            const endpoint_index: usize =
                server.endpoints_next[cluster_index] % cluster.endpoints.len;
            server.endpoints_next[cluster_index] +%= 1;
            conn.arm(&conn.op_connect, "connect");
            server.io.connect(
                cluster.endpoints[endpoint_index],
                &conn.op_connect.completion,
                ConnType,
                conn,
                onConnect,
            );
        }

        fn onConnect(conn: *ConnType, result: Io.ConnectError!IoType.Socket) void {
            const server = conn.server;
            conn.delivered(&conn.op_connect, "connect");
            if (conn.state == .tearing_down) {
                // The teardown raced the dial. A socket that arrived
                // anyway must still be shut down and closed.
                if (result) |socket| {
                    conn.upstream_socket = socket;
                    conn.has_upstream = true;
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
            conn.has_upstream = true;
            server.io.setNodelay(socket) catch {
                server.counters.increment("kernel_pressure_errors");
            };
            conn.state = .relaying;
            server.storeDeadline(conn, server.cfg.idle_timeout_ms);
            // Slice 8 starts the bidirectional relay here; until then the
            // lifecycle is proven by tearing down immediately.
            server.beginTeardown(conn);
        }

        /// Teardown is a state, not an event (§5): shutdown both fds,
        /// cancel pending connect/timer (the only legal cancels, §4),
        /// then closes once data ops drain; the last terminal completion
        /// releases the slot.
        pub fn beginTeardown(server: *Self, conn: *ConnType) void {
            if (conn.state == .tearing_down) return;
            assert(conn.state == .connecting or conn.state == .relaying);
            conn.state = .tearing_down;
            server.io.shutdown(conn.client_socket, .both);
            if (conn.has_upstream) {
                server.io.shutdown(conn.upstream_socket, .both);
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

        fn continueTeardown(server: *Self, conn: *ConnType) void {
            assert(conn.state == .tearing_down);
            if (!conn.closes_submitted) {
                const blocking_ops = conn.armed.connect or
                    conn.armed.data_client_to_upstream or
                    conn.armed.data_upstream_to_client;
                if (!blocking_ops) {
                    conn.closes_submitted = true;
                    conn.arm(&conn.op_close_client, "close_client");
                    server.io.close(
                        conn.client_socket,
                        &conn.op_close_client.completion,
                        ConnType,
                        conn,
                        onCloseClient,
                    );
                    if (conn.has_upstream) {
                        conn.arm(&conn.op_close_upstream, "close_upstream");
                        server.io.close(
                            conn.upstream_socket,
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
            assert(conn.state == .tearing_down);
            if (!conn.closes_submitted) return;
            if (conn.armedCount() != 0) return;
            server.relay_buffers.release(conn.relay_buffer);
            server.conns.release(conn);
            server.counters.increment("completed");
        }

        fn storeDeadline(server: *Self, conn: *ConnType, timeout_ms: u32) void {
            assert(timeout_ms >= 1);
            conn.deadline_ns = server.io.nowNs() + @as(u64, timeout_ms) * std.time.ns_per_ms;
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
                if (conn.state == .tearing_down) {
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
                assert(conn.state == .tearing_down);
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
