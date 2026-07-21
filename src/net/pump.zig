//! The shared recv → send → recv body pump, factored out of `relay.zig`
//! (L4) and the two L7 body legs in `http/proxy.zig` (DESIGN.md §6, §7).
//! Every one of those sites ran the identical loop — arm a recv into a
//! fixed buffer, forward the chunk fully (short sends resume from the
//! offset), only then arm the next recv — differing solely in *policy*:
//! how a message ends (framing), what EOF and errors mean, and what "the
//! body finished" does next.
//!
//! The mechanical plumbing is keyed entirely off the direction tag, so it
//! is 100% shared: for a given `direction` the source/target sockets, the
//! `relay_buffer` field, the embedded `Op`, the armed bit, and the
//! `DirectionState` cursor all derive from `@tagName(direction)` — exactly
//! the naming convention `relay.zig` already exploited. What is left is the
//! `Policy`: a comptime struct of hooks the caller supplies.
//!
//! Required Policy decls:
//!   feed(conn, chunk) FeedResult      how many bytes belong to the message
//!   framingDone(conn) bool            is the message fully forwarded
//!   onRecvError(server, conn, err)    terminal: EOF/reset handling
//!   onSendError(server, conn, err)    terminal: send failure
//!   onDrained(server, conn)           a recv yielded 0 forwardable bytes, done
//!   onComplete(server, conn)          the whole body reached the far side
//! Optional Policy decls (skipped when absent):
//!   beforeRecv(conn) / beforeSend(conn)   pre-arm bookkeeping (flags, phase)
//!   onRecvEntry(conn)                     post-await recv invariant re-checks
//!   afterFeed(conn, received, fr)         e.g. pipelined-tail detection
//!   onSendEntry(server, conn) bool        divert a settled verdict; true = handled
//!
//! The `on*Entry` hooks fire at completion time — after `delivered`, before
//! the I/O result is unwrapped — so a Policy can re-assert the invariants
//! that must have held across the in-flight await (the pre-arm `before*`
//! hooks only see the state at submit time, not after the await). `onSend`'s
//! variant additionally returns whether it handled the completion (a §7
//! verdict divert); `onRecv` has no divert — a client-side recv cannot be
//! forced (§8) — so `onRecvEntry` is assertion-only.

const std = @import("std");

const conn_module = @import("Conn.zig");
const Io = @import("../io/io.zig");

const assert = std.debug.assert;

/// How many of a received chunk belong to the current message. `consumed`
/// < chunk.len means the message ended mid-buffer (the rest is a pipelined
/// tail); `done` means no more body follows; `malformed` fails the framing.
pub const FeedResult = struct {
    consumed: u32,
    done: bool,
    malformed: bool,
};

pub fn Pump(
    comptime IoType: type,
    comptime direction: conn_module.Conn(IoType).Direction,
    comptime Policy: type,
) type {
    const ConnType = conn_module.Conn(IoType);
    const ServerType = @import("../Server.zig").Server(IoType);
    const direction_tag = @tagName(direction);

    return struct {
        const bit = "data_" ++ direction_tag;

        fn op(conn: *ConnType) *ConnType.Op {
            return &@field(conn, "op_data_" ++ direction_tag);
        }

        fn directionState(conn: *ConnType) *ConnType.DirectionState {
            return &conn.directions[@intFromEnum(direction)];
        }

        fn buffer(conn: *ConnType) []u8 {
            return &@field(conn.relay_buffer.?, direction_tag);
        }

        fn source(conn: *const ConnType) IoType.Socket {
            return switch (direction) {
                .client_to_upstream => conn.client_socket,
                .upstream_to_client => conn.upstream_socket.?,
            };
        }

        fn target(conn: *const ConnType) IoType.Socket {
            return switch (direction) {
                .client_to_upstream => conn.upstream_socket.?,
                .upstream_to_client => conn.client_socket,
            };
        }

        pub fn armRecv(server: *ServerType, conn: *ConnType) void {
            // A direction-agnostic precondition the pump enforces itself, so
            // the shared mechanism never relies solely on the optional
            // `beforeRecv` hook: every pump reads and writes the relay buffer.
            assert(conn.relay_buffer != null);
            if (@hasDecl(Policy, "beforeRecv")) Policy.beforeRecv(conn);
            conn.arm(op(conn), bit);
            server.io.recv(
                source(conn),
                buffer(conn),
                &op(conn).completion,
                ConnType,
                conn,
                onRecv,
            );
        }

        fn onRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.delivered(op(conn), bit);
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            if (@hasDecl(Policy, "onRecvEntry")) Policy.onRecvEntry(conn);
            const received = result catch |err| return Policy.onRecvError(server, conn, err);
            assert(received >= 1);
            assert(received <= buffer(conn).len);
            const chunk = buffer(conn)[0..received];
            const fr = Policy.feed(conn, chunk);
            if (fr.malformed) {
                server.beginTeardown(conn);
                return;
            }
            if (@hasDecl(Policy, "afterFeed")) Policy.afterFeed(conn, received, fr);
            const state = directionState(conn);
            state.transfer_len = fr.consumed;
            state.sent_len = 0;
            if (fr.consumed >= 1) {
                armSend(server, conn);
            } else {
                assert(fr.done);
                Policy.onDrained(server, conn);
            }
        }

        pub fn armSend(server: *ServerType, conn: *ConnType) void {
            assert(conn.relay_buffer != null);
            if (@hasDecl(Policy, "beforeSend")) Policy.beforeSend(conn);
            const state = directionState(conn);
            assert(state.sent_len < state.transfer_len);
            conn.arm(op(conn), bit);
            server.io.send(
                target(conn),
                buffer(conn)[state.sent_len..state.transfer_len],
                &op(conn).completion,
                ConnType,
                conn,
                onSend,
            );
        }

        fn onSend(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(op(conn), bit);
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            if (@hasDecl(Policy, "onSendEntry")) {
                if (Policy.onSendEntry(server, conn)) return;
            }
            const sent = result catch |err| return Policy.onSendError(server, conn, err);
            assert(sent >= 1);
            const state = directionState(conn);
            state.sent_len += sent;
            assert(state.sent_len <= state.transfer_len);
            if (state.sent_len < state.transfer_len) {
                armSend(server, conn);
                return;
            }
            // A full chunk moved: this is activity — push the idle deadline
            // out (§6); the armed timer op is not touched.
            server.storeDeadline(conn, server.idleTimeoutMs());
            if (Policy.framingDone(conn)) {
                Policy.onComplete(server, conn);
            } else {
                armRecv(server, conn);
            }
        }
    };
}
