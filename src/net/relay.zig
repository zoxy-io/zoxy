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
//!
//! One policy serves plain and TLS-terminated connections alike (§4). Only
//! the conn knows which it is, so the transform hooks branch on `conn.tls`
//! at runtime rather than instantiating a second pump: a terminated
//! connection relays under the identical discipline with the engine spliced
//! into the client side of each direction —
//!
//!   client → upstream:  recv ciphertext (head) → decrypt → send plaintext
//!   upstream → client:  recv plaintext (relay) → encrypt → send ciphertext
//!
//! — which is exactly what the seam exists to express. This was a parallel
//! loop (`net/tls_relay.zig`) for as long as the pump assumed a direction
//! recvs and sends the same bytes.

const std = @import("std");

const constants = @import("../constants.zig");
const conn_module = @import("Conn.zig");
const pump = @import("pump.zig");
const Engine = @import("../tls/Engine.zig");
const Io = @import("../io/io.zig");

const assert = std.debug.assert;

/// Ciphertext read per step on a terminated connection. This bounds the
/// *read*, not the plaintext it yields: ztls reassembles a record across as
/// many reads as it takes, so a client writing one 16 KiB record gets that
/// whole record decrypted in the step that completes it, however small the
/// chunks were. The destination is therefore the engine-owned staging,
/// sized for that burst — not the relay buffer, which is smaller.
const ciphertext_chunk_bytes = constants.relay_buffer_bytes;

comptime {
    // The chunk is read into the (otherwise idle) head buffer.
    assert(ciphertext_chunk_bytes <= constants.head_bytes_max);
    // One `feed` carries over at most one incomplete record and drains
    // whatever this chunk completes, so its plaintext is bounded by one
    // record plus the chunk. Tying the two here (§8) means a later
    // `relay_buffer_bytes` bump cannot silently reopen the overflow this
    // bound exists to prevent.
    assert(Engine.staging_bytes >= Engine.max_plaintext_bytes + ciphertext_chunk_bytes);
}

/// Outbox room a step must find before it may stage anything. One full
/// emitted record is the most a single step can produce.
const min_outbound_room = Engine.max_emitted_record_bytes;

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

                fn state(conn: *ConnType) *conn_module.DirectionState {
                    return &conn.directions[@intFromEnum(direction)];
                }

                pub fn beforeRecv(conn: *ConnType) void {
                    assert(conn.state == .relaying);
                    const direction_state = state(conn);
                    // A plain direction alternates strictly idle/sending →
                    // receiving. Already-`.receiving` is legal only for a
                    // transform reading on for the rest of a fragment (pump
                    // contract 3), so the exemption names that condition
                    // rather than widening the invariant for everyone.
                    assert(direction_state.phase == .idle or
                        direction_state.phase == .sending or
                        (direction == .client_to_upstream and conn.tls != null and
                            direction_state.phase == .receiving));
                    direction_state.phase = .receiving;
                }

                pub fn beforeSend(conn: *ConnType) void {
                    assert(conn.state == .relaying);
                    const direction_state = state(conn);
                    // A plain direction only ever sends what it just
                    // received. A terminated one can open with a send:
                    // plaintext from the client's Finished flight is staged
                    // before the first recv is armed (`start`), so `.idle`
                    // is legal there — and only there.
                    assert(direction_state.phase == .receiving or
                        direction_state.phase == .sending or
                        (direction == .client_to_upstream and conn.tls != null and
                            direction_state.phase == .idle));
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

                /// A relay has no length to count down, so a plain direction
                /// only ever leaves on EOF or teardown. A terminated one has
                /// a terminator per side, and both are in-band:
                ///
                /// - client → upstream: the peer's close_notify. Asking here
                ///   rather than only at `transformEnded` is what covers the
                ///   client that coalesces its last write with its goodbye —
                ///   one read, one decrypt, data *and* alert. Then the chunk
                ///   is non-empty, so `transformEnded` is never consulted,
                ///   and the direction would re-arm a recv for bytes the
                ///   client already said would never come.
                /// - upstream → client: our own close_notify. Once it is on
                ///   the wire the origin has already EOF'd and there is
                ///   nothing further to send, so re-arming a recv would spin
                ///   on an EOF that stages the alert again.
                pub fn framingDone(conn: *ConnType) bool {
                    const engine = conn.tls orelse return false;
                    return switch (direction) {
                        .client_to_upstream => engine.peerClosed(),
                        .upstream_to_client => engine.closeStaged(),
                    };
                }

                pub fn onRecvError(server: *ServerType, conn: *ConnType, err: Io.RecvError) void {
                    if (err == error.EndOfStream) {
                        // A terminated client is owed the end of stream
                        // *in protocol*: a bare FIN under TLS is
                        // indistinguishable from a truncation attack (§2),
                        // so the alert is staged and this direction ends
                        // only once it is on the wire.
                        if (direction == .upstream_to_client) {
                            if (conn.tls) |engine| {
                                // Once, and only once: `framingDone` ends
                                // this direction the moment the alert is on
                                // the wire, so arriving here with one already
                                // staged would mean the pump re-armed a recv
                                // on a stream that had ended — a second
                                // goodbye the peer never asked for.
                                assert(!engine.closeStaged());
                                if (!hasStagingRoom(server, conn)) return;
                                engine.sendClose() catch {
                                    finish(server, conn);
                                    return;
                                };
                                pumpFor(direction).armSend(server, conn);
                                return;
                            }
                        }
                        // Half-close (§6): propagate the FIN, keep the other
                        // direction relaying under the deadline.
                        server.io.shutdown(targetSocket(conn), .write);
                        server.storeDeadline(conn, server.idleTimeoutMs());
                        finish(server, conn);
                        return;
                    }
                    server.witnessKernelPressure(err);
                    server.beginTeardown(conn);
                }

                // -- the TLS transform (§4) --

                /// Ciphertext lands in the (otherwise idle) head buffer,
                /// because the engine staging is where it *decrypts to* and
                /// cannot also be the read target. The response direction
                /// receives plaintext from the origin and needs no override.
                pub fn recvBuffer(conn: *ConnType) []u8 {
                    if (direction == .client_to_upstream) {
                        if (conn.tls != null) return conn.head[0..ciphertext_chunk_bytes];
                    }
                    return &@field(conn.relay_buffer.?, @tagName(direction));
                }

                /// Decrypt into the engine staging so framing sees plaintext.
                /// Yields nothing for a record that carried no application
                /// data — a fragment, an alert, a KeyUpdate — which the pump
                /// reads on for, and nothing for close_notify, which
                /// `transformEnded` distinguishes.
                pub fn transformIn(conn: *ConnType, chunk: []u8) ?[]const u8 {
                    if (direction != .client_to_upstream) return chunk;
                    const engine = conn.tls orelse return chunk;
                    if (!hasStagingRoom(conn.server, conn)) return null;
                    var out: Decrypted = .{ .conn = conn };
                    engine.feed(chunk, .{
                        .ctx = &out,
                        .appData = Decrypted.append,
                        .closed = Decrypted.peerClosed,
                    }) catch {
                        conn.server.counters.increment("tls_relay_failed");
                        return null;
                    };
                    return engine.staging[0..out.len];
                }

                /// An empty decrypt is the end of the stream only when the
                /// peer said so in protocol.
                pub fn transformEnded(conn: *ConnType) bool {
                    if (direction != .client_to_upstream) return false;
                    const engine = conn.tls orelse return false;
                    return engine.peerClosed();
                }

                /// Encrypt the framed chunk once, before the first send.
                pub fn transformOut(conn: *ConnType, consumed: u32) bool {
                    if (direction != .upstream_to_client) return true;
                    const engine = conn.tls orelse return true;
                    if (!hasStagingRoom(conn.server, conn)) return false;
                    engine.sendApp(
                        conn.relay_buffer.?.upstream_to_client[0..consumed],
                    ) catch {
                        conn.server.counters.increment("tls_relay_failed");
                        return false;
                    };
                    return true;
                }

                /// Plaintext goes out of the staging it decrypted into;
                /// ciphertext out of the outbox, which carries its own
                /// cursor. Plain: the framed window still owed.
                pub fn sendSlice(conn: *ConnType) []const u8 {
                    const direction_state = state(conn);
                    if (conn.tls) |engine| {
                        if (direction == .upstream_to_client) return engine.outbound();
                        if (direction_state.owed() == 0) return &.{};
                        return direction_state.pending(&engine.staging);
                    }
                    if (direction_state.owed() == 0) return &.{};
                    return direction_state.pending(&@field(conn.relay_buffer.?, @tagName(direction)));
                }

                /// Credit whichever cursor tracks the wire. Only the
                /// response direction diverges: the wire carries ciphertext,
                /// which outnumbers the plaintext the debt counts, so the
                /// debt settles all at once when the outbox empties — which
                /// is the pump's contract for a transforming send.
                pub fn creditSend(conn: *ConnType, sent: u32) void {
                    const direction_state = state(conn);
                    if (direction == .upstream_to_client) {
                        if (conn.tls) |engine| {
                            engine.outboundSent(sent);
                            if (engine.outbound().len == 0 and direction_state.owed() >= 1) {
                                direction_state.credit(direction_state.owed());
                            }
                            return;
                        }
                    }
                    direction_state.credit(sent);
                }

                pub fn onSendError(server: *ServerType, conn: *ConnType, err: Io.SendError) void {
                    server.witnessKernelPressure(err);
                    server.beginTeardown(conn);
                }

                /// The client's close_notify: it will send no more
                /// application data, which is a half-close exactly like a
                /// FIN, so the far side is told with one (§6).
                fn finishPeerClosed(server: *ServerType, conn: *ConnType) void {
                    assert(direction == .client_to_upstream);
                    assert(conn.tls != null);
                    assert(conn.tls.?.peerClosed());
                    server.io.shutdown(targetSocket(conn), .write);
                    server.storeDeadline(conn, server.idleTimeoutMs());
                    finish(server, conn);
                }

                /// A transform's in-band EOF with nothing riding along: the
                /// record carried only the alert. A plain direction never
                /// arrives — `feed` never yields 0 consumed bytes and never
                /// reports `done`.
                pub fn onDrained(server: *ServerType, conn: *ConnType) void {
                    finishPeerClosed(server, conn);
                }

                /// Reached only when `framingDone` says so, which is one of
                /// the two in-band terminators: the client's goodbye with its
                /// last bytes now forwarded, or our own with the origin's EOF
                /// announced.
                pub fn onComplete(server: *ServerType, conn: *ConnType) void {
                    assert(conn.tls != null);
                    switch (direction) {
                        .client_to_upstream => finishPeerClosed(server, conn),
                        .upstream_to_client => finish(server, conn),
                    }
                }

                /// This direction is done; the connection ends when both are.
                fn finish(server: *ServerType, conn: *ConnType) void {
                    state(conn).phase = .finished;
                    maybeFinish(server, conn);
                }
            };
        }

        fn pumpFor(comptime d: Direction) type {
            return pump.Pump(IoType, d, Policy(d));
        }

        const PumpClientToUpstream = pumpFor(.client_to_upstream);
        const PumpUpstreamToClient = pumpFor(.upstream_to_client);

        /// Both directions start together, each with one armed op.
        pub fn start(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .relaying);
            assert(conn.upstream_socket != null);
            assert(conn.directions[0].phase == .idle);
            assert(conn.directions[1].phase == .idle);
            // A terminated client may have written application data in the
            // same flight as its Finished, before there was an upstream to
            // forward it to. That plaintext is already decrypted into the
            // engine staging, so it goes out as this direction's first send
            // rather than being read past — otherwise the client's first
            // write is silently dropped or reordered.
            const pending = conn.tls_pending_len;
            conn.tls_pending_len = 0;
            if (pending > 0) {
                assert(conn.tls != null);
                assert(pending <= conn.tls.?.staging.len);
                conn.directions[0].owe(pending);
                PumpClientToUpstream.armSend(server, conn);
            } else {
                PumpClientToUpstream.armRecv(server, conn);
            }
            PumpUpstreamToClient.armRecv(server, conn);
        }

        /// Both directions stage into the one engine outbox, and neither
        /// waits for the other: a client KeyUpdate stages a response while
        /// `upstream → client` sits idle in a recv, and an origin write
        /// stages a record while an earlier send still drains. So every step
        /// that may stage checks first, and a peer that outruns the
        /// transport is shed rather than tripping `stage`'s bound (§8).
        /// Tears down and reports false when the room is short.
        fn hasStagingRoom(server: *ServerType, conn: *ConnType) bool {
            assert(conn.state == .relaying);
            if (conn.tls.?.outboundRoom() >= min_outbound_room) return true;
            server.counters.increment("tls_relay_failed");
            server.beginTeardown(conn);
            return false;
        }

        /// Accumulates decrypted application data into the engine staging,
        /// whose bound the ciphertext chunk size is tied to at comptime
        /// above, so a record's plaintext always fits.
        const Decrypted = struct {
            conn: *ConnType,
            len: u32 = 0,

            fn append(ctx: *anyopaque, bytes: []const u8) void {
                const self: *Decrypted = @ptrCast(@alignCast(ctx));
                const buffer = &self.conn.tls.?.staging;
                assert(self.len + bytes.len <= buffer.len);
                @memcpy(buffer[self.len..][0..bytes.len], bytes);
                self.len += @intCast(bytes.len);
            }

            /// The engine records the close itself (`Engine.peerClosed`),
            /// which is what `transformEnded` reads once `feed` returns;
            /// nothing to do here but satisfy the sink.
            fn peerClosed(ctx: *anyopaque) void {
                _ = ctx;
            }
        };

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
