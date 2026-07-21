//! Relay buffers and (slice 8) the strict recv → send → recv relay
//! (DESIGN.md §6). The buffer pair is pooled separately from connection
//! slots — buffers are sized for concurrent *relays*, not for open
//! connections (§5). On the L4 path a buffer is acquired at admission
//! and held for the connection's life: a recv must always have a buffer
//! posted, so `relay_buffers_max`, not conn slots, bounds concurrent L4
//! connections.
//!
//! The recv → send loop itself lives in `pump.zig`; this file supplies only
//! the L4 *policy* — no framing (relay runs until FIN both ways), EOF becomes
//! a half-close, and the connection tears down when both directions have
//! finished.

const std = @import("std");

const constants = @import("../constants.zig");
const conn_module = @import("Conn.zig");
const pump = @import("pump.zig");
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
        /// The L4 relay policy for one direction: no framing, EOF is a
        /// half-close, teardown once both directions finish. Instantiated
        /// once per direction so the terminal handlers know which side
        /// FIN'd.
        fn Policy(comptime direction: Direction) type {
            return struct {
                fn targetSocket(conn: *const ConnType) IoType.Socket {
                    return switch (direction) {
                        .client_to_upstream => conn.upstream_socket.?,
                        .upstream_to_client => conn.client_socket,
                    };
                }

                fn state(conn: *ConnType) *ConnType.DirectionState {
                    return &conn.directions[@intFromEnum(direction)];
                }

                pub fn beforeRecv(conn: *ConnType) void {
                    assert(conn.state == .relaying);
                    const direction_state = state(conn);
                    assert(direction_state.phase == .idle or direction_state.phase == .sending);
                    direction_state.phase = .receiving;
                }

                pub fn beforeSend(conn: *ConnType) void {
                    assert(conn.state == .relaying);
                    const direction_state = state(conn);
                    assert(direction_state.phase == .receiving or direction_state.phase == .sending);
                    direction_state.phase = .sending;
                }

                /// Completion-time re-checks: the invariants must still hold
                /// after the in-flight await, not only when the op was armed.
                pub fn onRecvEntry(conn: *ConnType) void {
                    assert(conn.state == .relaying);
                    assert(state(conn).phase == .receiving);
                }

                pub fn onSendEntry(server: *ServerType, conn: *ConnType) bool {
                    _ = server;
                    assert(conn.state == .relaying);
                    assert(state(conn).phase == .sending);
                    return false; // Relay never diverts: it has no verdict.
                }

                /// No framing: every received byte is relayed and the
                /// message never ends short of a FIN, so `done` stays false.
                pub fn feed(conn: *ConnType, chunk: []const u8) pump.FeedResult {
                    _ = conn;
                    return .{ .consumed = @intCast(chunk.len), .done = false, .malformed = false };
                }

                /// A FIN never arrives through here (relay has no length to
                /// count down); the loop only leaves on EOF or teardown.
                pub fn framingDone(conn: *ConnType) bool {
                    _ = conn;
                    return false;
                }

                pub fn onRecvError(server: *ServerType, conn: *ConnType, err: Io.RecvError) void {
                    if (err == error.EndOfStream) {
                        // Half-close (§6): propagate the FIN, keep the other
                        // direction relaying under the deadline.
                        state(conn).phase = .finished;
                        server.io.shutdown(targetSocket(conn), .write);
                        server.storeDeadline(conn, server.idleTimeoutMs());
                        maybeFinish(server, conn);
                        return;
                    }
                    server.witnessKernelPressure(err);
                    server.beginTeardown(conn);
                }

                pub fn onSendError(server: *ServerType, conn: *ConnType, err: Io.SendError) void {
                    server.witnessKernelPressure(err);
                    server.beginTeardown(conn);
                }

                /// Unreachable for L4: `feed` never yields 0 consumed bytes
                /// and never reports `done`.
                pub fn onDrained(server: *ServerType, conn: *ConnType) void {
                    _ = server;
                    _ = conn;
                    unreachable;
                }

                /// Unreachable for L4: `framingDone` is always false.
                pub fn onComplete(server: *ServerType, conn: *ConnType) void {
                    _ = server;
                    _ = conn;
                    unreachable;
                }
            };
        }

        const PumpClientToUpstream = pump.Pump(IoType, .client_to_upstream, Policy(.client_to_upstream));
        const PumpUpstreamToClient = pump.Pump(IoType, .upstream_to_client, Policy(.upstream_to_client));

        pub fn start(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .relaying);
            assert(conn.upstream_socket != null);
            assert(conn.directions[0].phase == .idle);
            assert(conn.directions[1].phase == .idle);
            PumpClientToUpstream.armRecv(server, conn);
            PumpUpstreamToClient.armRecv(server, conn);
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
    };
}
