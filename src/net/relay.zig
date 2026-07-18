//! Relay buffers and (slice 8) the strict recv → send → recv relay
//! (DESIGN.md §6). The buffer pair is pooled separately from connection
//! slots — buffers are sized for concurrent *relays*, not for open
//! connections (§5). On the L4 path a buffer is acquired at admission
//! and held for the connection's life: a recv must always have a buffer
//! posted, so `relay_buffers_max`, not conn slots, bounds concurrent L4
//! connections.

const std = @import("std");

const constants = @import("../constants.zig");
const conn_module = @import("Conn.zig");
const Io = @import("../io/io.zig");

const assert = std.debug.assert;

pub const RelayBuffer = struct {
    pool_next: u32,
    generation: u32,
    client_to_upstream: [constants.relay_buffer_bytes]u8,
    upstream_to_client: [constants.relay_buffer_bytes]u8,
};

comptime {
    assert(@sizeOf(RelayBuffer) >= 2 * constants.relay_buffer_bytes);
}

/// The bidirectional relay engine. Per direction: recv fills the fixed
/// buffer, the chunk is sent fully (short sends resume from the offset),
/// only then is the next recv armed — a slow side stalls the fast side
/// through TCP flow control, with no read-ahead to disable (§6). EOF
/// propagates as a FIN to the other side (half-close honored); the
/// connection tears down when both directions have finished, on any
/// error, or when the deadline fires.
pub fn Relay(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);
    const ConnType = conn_module.Conn(IoType);
    const Direction = ConnType.Direction;

    return struct {
        pub fn start(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .relaying);
            assert(conn.upstream_socket != null);
            assert(conn.directions[0].phase == .idle);
            assert(conn.directions[1].phase == .idle);
            armRecv(server, conn, .client_to_upstream);
            armRecv(server, conn, .upstream_to_client);
        }

        fn armRecv(server: *ServerType, conn: *ConnType, comptime direction: Direction) void {
            assert(conn.state == .relaying);
            const state = directionState(conn, direction);
            assert(state.phase == .idle or state.phase == .sending);
            state.phase = .receiving;
            const op = dataOp(conn, direction);
            conn.arm(op, armedBitName(direction));
            server.io.recv(
                sourceSocket(conn, direction),
                buffer(conn, direction),
                &op.completion,
                ConnType,
                conn,
                onRecvFor(direction),
            );
        }

        fn armSend(server: *ServerType, conn: *ConnType, comptime direction: Direction) void {
            assert(conn.state == .relaying);
            const state = directionState(conn, direction);
            assert(state.phase == .receiving or state.phase == .sending);
            assert(state.sent_len < state.transfer_len);
            state.phase = .sending;
            const op = dataOp(conn, direction);
            conn.arm(op, armedBitName(direction));
            server.io.send(
                targetSocket(conn, direction),
                buffer(conn, direction)[state.sent_len..state.transfer_len],
                &op.completion,
                ConnType,
                conn,
                onSendFor(direction),
            );
        }

        fn onRecv(
            comptime direction: Direction,
            conn: *ConnType,
            result: Io.RecvError!u32,
        ) void {
            const server = conn.server;
            conn.delivered(dataOp(conn, direction), armedBitName(direction));
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .relaying);
            const state = directionState(conn, direction);
            assert(state.phase == .receiving);
            const received = result catch |err| {
                if (err == error.EndOfStream) {
                    // Half-close (§6): propagate the FIN, keep the other
                    // direction relaying under the deadline.
                    state.phase = .finished;
                    server.io.shutdown(targetSocket(conn, direction), .write);
                    server.storeDeadline(conn, server.idleTimeoutMs());
                    maybeFinish(server, conn);
                    return;
                }
                server.witnessKernelPressure(err);
                server.beginTeardown(conn);
                return;
            };
            assert(received >= 1);
            assert(received <= buffer(conn, direction).len);
            state.transfer_len = received;
            state.sent_len = 0;
            armSend(server, conn, direction);
        }

        fn onSend(
            comptime direction: Direction,
            conn: *ConnType,
            result: Io.SendError!u32,
        ) void {
            const server = conn.server;
            conn.delivered(dataOp(conn, direction), armedBitName(direction));
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .relaying);
            const state = directionState(conn, direction);
            assert(state.phase == .sending);
            const sent = result catch |err| {
                server.witnessKernelPressure(err);
                server.beginTeardown(conn);
                return;
            };
            assert(sent >= 1);
            state.sent_len += sent;
            assert(state.sent_len <= state.transfer_len);
            if (state.sent_len < state.transfer_len) {
                armSend(server, conn, direction);
            } else {
                // A full exchange moved: this is activity — push the idle
                // deadline out (§6); the armed timer op is not touched.
                server.storeDeadline(conn, server.idleTimeoutMs());
                armRecv(server, conn, direction);
            }
        }

        /// Both directions drained: the orderly end of an L4 connection.
        fn maybeFinish(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .relaying);
            if (conn.directions[0].phase == .finished) {
                if (conn.directions[1].phase == .finished) {
                    server.beginTeardown(conn);
                }
            }
        }

        // The per-direction plumbing derives from one naming convention:
        // the DirectionState index, the RelayBuffer field, the op field
        // (`op_data_` + tag), and the armed bit (`data_` + tag) are all
        // keyed off the direction's tag name, so the only real branch is
        // which socket is the source (its target is the source of the
        // opposite direction).

        fn directionState(conn: *ConnType, comptime direction: Direction) *ConnType.DirectionState {
            return &conn.directions[@intFromEnum(direction)];
        }

        fn dataOp(conn: *ConnType, comptime direction: Direction) *ConnType.Op {
            return &@field(conn, "op_data_" ++ @tagName(direction));
        }

        fn armedBitName(comptime direction: Direction) []const u8 {
            return "data_" ++ @tagName(direction);
        }

        fn buffer(conn: *ConnType, comptime direction: Direction) []u8 {
            // The L4 relay always holds its buffer for the connection's
            // life (§6); it is only ever null on an idle L7 connection.
            return &@field(conn.relay_buffer.?, @tagName(direction));
        }

        fn opposite(comptime direction: Direction) Direction {
            return switch (direction) {
                .client_to_upstream => .upstream_to_client,
                .upstream_to_client => .client_to_upstream,
            };
        }

        fn sourceSocket(conn: *const ConnType, comptime direction: Direction) IoType.Socket {
            // The relay only runs in .relaying, where the upstream is set.
            return switch (direction) {
                .client_to_upstream => conn.client_socket,
                .upstream_to_client => conn.upstream_socket.?,
            };
        }

        fn targetSocket(conn: *const ConnType, comptime direction: Direction) IoType.Socket {
            return sourceSocket(conn, opposite(direction));
        }

        fn onRecvFor(comptime direction: Direction) fn (*ConnType, Io.RecvError!u32) void {
            return (struct {
                fn callback(conn: *ConnType, result: Io.RecvError!u32) void {
                    onRecv(direction, conn, result);
                }
            }).callback;
        }

        fn onSendFor(comptime direction: Direction) fn (*ConnType, Io.SendError!u32) void {
            return (struct {
                fn callback(conn: *ConnType, result: Io.SendError!u32) void {
                    onSend(direction, conn, result);
                }
            }).callback;
        }
    };
}
