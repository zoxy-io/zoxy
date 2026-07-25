//! The L4 relay for a TLS-terminated connection (DESIGN.md §4, §6): the
//! same strict `recv → send → recv` discipline as `relay.zig`, with the
//! engine spliced into the client side of each direction.
//!
//! It is a *parallel* loop rather than a policy on the shared `pump.zig`
//! for one structural reason: the pump derives a direction's source
//! socket, target socket, buffer, op, and cursor from one direction tag,
//! because plain relaying recvs and sends the same bytes. TLS does not —
//! each direction transforms, and its two halves live in different
//! buffers:
//!
//!   client → upstream:  recv ciphertext (head) → decrypt → send plaintext
//!   upstream → client:  recv plaintext (relay) → encrypt → send ciphertext
//!
//! Unifying the two loops means teaching the pump that recv and send
//! buffers can differ; worth doing once TLS is proven, and deliberately
//! not attempted while the L4 and L7 paths depend on the pump unchanged
//! (PLANS.md).
//!
//! Invariants carried over from `relay.zig`: exactly one op armed per
//! direction, so the ring budget is the same; a peer's EOF half-closes
//! the far side; the connection tears down when both directions finish.

const std = @import("std");

const constants = @import("../constants.zig");
const Engine = @import("../tls/Engine.zig");
const Io = @import("../io/io.zig");

const assert = std.debug.assert;

/// Ciphertext read per step. This bounds the *read*, not the plaintext it
/// yields: ztls reassembles a record across as many reads as it takes, so
/// a client writing one 16 KiB record gets that whole record decrypted in
/// the step that completes it, however small the chunks were. The
/// destination is therefore the engine-owned inbox, sized for that burst
/// (Engine.inbox_bytes) — not the relay buffer, which is smaller.
const ciphertext_chunk_bytes = constants.relay_buffer_bytes;

comptime {
    // The chunk is read into the (otherwise idle) head buffer.
    assert(ciphertext_chunk_bytes <= constants.head_bytes_max);
    // One `feed` carries over at most one incomplete record and drains
    // whatever this chunk completes, so its plaintext is bounded by one
    // record plus the chunk. Tying the two here (§8) means a later
    // `relay_buffer_bytes` bump cannot silently reopen the overflow this
    // bound exists to prevent.
    assert(Engine.inbox_bytes >= Engine.max_plaintext_bytes + ciphertext_chunk_bytes);
}

/// Outbox room a step must find before it may stage anything. One full
/// wire record is the most a single record can produce.
const min_outbound_room = Engine.max_record_bytes;

pub fn TlsRelay(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);
    const ConnType = @import("Conn.zig").Conn(IoType);

    return struct {
        /// Both directions start together, each with one armed op.
        pub fn start(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .relaying);
            assert(conn.tls != null);
            assert(conn.upstream_socket != null);
            assert(conn.directions[0].phase == .idle);
            assert(conn.directions[1].phase == .idle);
            // Plaintext that beat the dial is already staged in the inbox
            // (Conn.tls_pending_len), so it must go out before anything
            // this direction reads next — otherwise the client's first
            // write is silently dropped or reordered.
            const pending = conn.tls_pending_len;
            assert(pending <= conn.tls.?.inbox.len);
            conn.tls_pending_len = 0;
            if (pending > 0) {
                armUpstreamSend(server, conn, 0, pending);
            } else {
                armClientRecv(server, conn);
            }
            armUpstreamRecv(server, conn);
        }

        // -- client → upstream: recv ciphertext, decrypt, send plaintext --

        fn armClientRecv(server: *ServerType, conn: *ConnType) void {
            // Reached from start (.idle), after a forwarded chunk
            // (.sending), and after a record that carried no application
            // data, where the phase is still .receiving.
            assert(conn.directions[0].phase != .finished);
            conn.directions[0].phase = .receiving;
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                conn.head[0..ciphertext_chunk_bytes],
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onClientRecv,
            );
        }

        fn onClientRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            const received = result catch |err| {
                server.witnessKernelPressure(err);
                finishDirection(server, conn, 0);
                return;
            };
            if (received == 0) { // Client FIN: half-close the far side.
                server.io.shutdown(conn.upstream_socket.?, .write);
                finishDirection(server, conn, 0);
                return;
            }
            assert(conn.state == .relaying);
            assert(received <= ciphertext_chunk_bytes);
            server.storeDeadline(conn, server.idleTimeoutMs());

            if (!hasStagingRoom(server, conn)) return;

            // Decrypt into the engine inbox. The sink fires once per
            // record, so a step's plaintext accumulates across records.
            var decrypted: Decrypted = .{ .conn = conn, .len = 0 };
            conn.tls.?.feed(conn.head[0..received], .{
                .ctx = &decrypted,
                .appData = Decrypted.append,
                .closed = Decrypted.peerClosed,
            }) catch {
                server.counters.increment("tls_relay_failed");
                server.beginTeardown(conn);
                return;
            };
            if (decrypted.closed) {
                // close_notify: the client will send no more application
                // data, so this direction is done.
                server.io.shutdown(conn.upstream_socket.?, .write);
                finishDirection(server, conn, 0);
                return;
            }
            if (decrypted.len == 0) {
                // A record that carried no application data (an alert or
                // a post-handshake message): nothing to forward.
                armClientRecv(server, conn);
                return;
            }
            armUpstreamSend(server, conn, 0, decrypted.len);
        }

        /// Accumulates decrypted application data into the engine inbox,
        /// which ztls's own record-buffer bound sizes: at most two full
        /// records can complete in one `feed`, and the inbox covers two.
        const Decrypted = struct {
            conn: *ConnType,
            len: u32,
            closed: bool = false,

            fn append(ctx: *anyopaque, bytes: []const u8) void {
                const self: *Decrypted = @ptrCast(@alignCast(ctx));
                const buffer = &self.conn.tls.?.inbox;
                assert(self.len + bytes.len <= buffer.len);
                @memcpy(buffer[self.len..][0..bytes.len], bytes);
                self.len += @intCast(bytes.len);
            }

            fn peerClosed(ctx: *anyopaque) void {
                const self: *Decrypted = @ptrCast(@alignCast(ctx));
                self.closed = true;
            }
        };

        fn armUpstreamSend(
            server: *ServerType,
            conn: *ConnType,
            sent: u32,
            total: u32,
        ) void {
            assert(sent < total);
            assert(total <= conn.tls.?.inbox.len);
            // Entered from `start` forwarding pre-relay plaintext (.idle),
            // from the decrypt step (.receiving), and from a short write
            // resuming itself (.sending).
            assert(conn.directions[0].phase != .finished);
            conn.directions[0].phase = .sending;
            conn.directions[0].sent_len = sent;
            conn.directions[0].transfer_len = total;
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.send(
                conn.upstream_socket.?,
                conn.tls.?.inbox[sent..total],
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onUpstreamSend,
            );
        }

        fn onUpstreamSend(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            const sent = result catch |err| {
                server.witnessKernelPressure(err);
                finishDirection(server, conn, 0);
                return;
            };
            assert(conn.directions[0].phase == .sending);
            const written = conn.directions[0].sent_len + sent;
            const total = conn.directions[0].transfer_len;
            assert(written <= total);
            if (written < total) { // Short write: resume from the offset.
                armUpstreamSend(server, conn, written, total);
                return;
            }
            armClientRecv(server, conn);
        }

        // -- upstream → client: recv plaintext, encrypt, send ciphertext --

        fn armUpstreamRecv(server: *ServerType, conn: *ConnType) void {
            assert(conn.directions[1].phase == .idle or
                conn.directions[1].phase == .sending);
            conn.directions[1].phase = .receiving;
            conn.arm(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.recv(
                conn.upstream_socket.?,
                &conn.relay_buffer.?.upstream_to_client,
                &conn.op_data_upstream_to_client.completion,
                ConnType,
                conn,
                onUpstreamRecv,
            );
        }

        fn onUpstreamRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            const received = result catch |err| {
                server.witnessKernelPressure(err);
                finishDirection(server, conn, 1);
                return;
            };
            if (received == 0) {
                // Origin EOF. Announce it in-protocol — a bare FIN under
                // TLS is indistinguishable from a truncation attack, so
                // the client is told the stream ended on purpose (§2).
                if (!hasStagingRoom(server, conn)) return;
                conn.tls.?.sendClose() catch {
                    finishDirection(server, conn, 1);
                    return;
                };
                armClientSend(server, conn, true);
                return;
            }
            assert(received <= conn.relay_buffer.?.upstream_to_client.len);
            if (!hasStagingRoom(server, conn)) return;
            server.storeDeadline(conn, server.idleTimeoutMs());
            conn.tls.?.sendApp(
                conn.relay_buffer.?.upstream_to_client[0..received],
            ) catch {
                server.counters.increment("tls_relay_failed");
                server.beginTeardown(conn);
                return;
            };
            armClientSend(server, conn, false);
        }

        fn armClientSend(server: *ServerType, conn: *ConnType, final: bool) void {
            assert(conn.state == .relaying);
            // Entered from the encrypt step (.receiving) and from a send
            // completion draining the rest of the outbox (.sending).
            assert(conn.directions[1].phase == .receiving or
                conn.directions[1].phase == .sending);
            const outbound = conn.tls.?.outbound();
            if (outbound.len == 0) {
                // Everything staged has gone out.
                if (final) {
                    finishDirection(server, conn, 1);
                } else {
                    armUpstreamRecv(server, conn);
                }
                return;
            }
            conn.directions[1].phase = .sending;
            // This direction sends straight from the outbox, so it has no
            // transfer cursor of its own; the field carries `final` across
            // the send instead — 1 once close_notify is staged, and the
            // completion ends the direction rather than re-arming.
            conn.directions[1].transfer_len = if (final) 1 else 0;
            conn.arm(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.send(
                conn.client_socket,
                outbound,
                &conn.op_data_upstream_to_client.completion,
                ConnType,
                conn,
                onClientSend,
            );
        }

        fn onClientSend(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            const sent = result catch |err| {
                server.witnessKernelPressure(err);
                finishDirection(server, conn, 1);
                return;
            };
            assert(conn.directions[1].phase == .sending);
            assert(sent <= conn.tls.?.outbound().len);
            // The outbox credits the write; a short send leaves the
            // remainder staged for the next step.
            conn.tls.?.outboundSent(sent);
            armClientSend(server, conn, conn.directions[1].transfer_len == 1);
        }

        /// Both directions stage into the one engine outbox, and neither
        /// waits for the other: a client KeyUpdate stages a response while
        /// `upstream → client` sits idle in a recv, and an origin write
        /// stages a record while an earlier send still drains. So every
        /// call that may stage checks first, and a peer that outruns the
        /// transport is shed rather than tripping `stage`'s bound (§8).
        /// Tears down and reports false when the room is short.
        fn hasStagingRoom(server: *ServerType, conn: *ConnType) bool {
            assert(conn.state == .relaying);
            if (conn.tls.?.outboundRoom() >= min_outbound_room) return true;
            server.counters.increment("tls_relay_failed");
            server.beginTeardown(conn);
            return false;
        }

        // -- termination --

        fn finishDirection(server: *ServerType, conn: *ConnType, comptime index: usize) void {
            assert(conn.state == .relaying);
            conn.directions[index].phase = .finished;
            if (conn.directions[0].phase == .finished and
                conn.directions[1].phase == .finished)
            {
                server.beginTeardown(conn);
            }
        }
    };
}
