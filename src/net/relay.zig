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
const stream_module = @import("Stream.zig");
const pump = @import("pump.zig");
const TlsEngine = @import("../tls/Engine.zig");
const Io = @import("../io/io.zig");

const assert = std.debug.assert;

/// One connection's pair of relay halves. The bytes live in a slab the
/// server carves at startup, not inline here: `limits.relay_buffer_bytes`
/// is the operator's to size, so the element cannot be a comptime shape.
/// Same move `HeadBuffer` made, and for the same reason.
///
/// `Pool` never touches these fields, so the wiring survives every
/// acquire/release cycle and is done once at init.
pub const RelayBuffer = struct {
    pool_next: u32,
    generation: u32,
    client_to_upstream: []u8,
    upstream_to_client: []u8,
};

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
    const StreamType = ConnType.StreamType;
    const Direction = StreamType.Direction;

    return struct {
        /// The L4 relay policy for one direction: no framing, EOF is a
        /// half-close, teardown once both directions finish. Instantiated
        /// once per direction so the terminal handlers know which side
        /// FIN'd.
        fn Policy(comptime direction: Direction) type {
            return struct {
                fn targetSocket(conn: *const ConnType) IoType.Socket {
                    return switch (direction) {
                        .client_to_upstream => conn.stream.upstream_socket.?,
                        .upstream_to_client => conn.client_socket,
                    };
                }

                fn state(conn: *ConnType) *stream_module.DirectionState {
                    return &conn.stream.directions[@intFromEnum(direction)];
                }

                pub fn beforeRecv(conn: *ConnType) void {
                    assert(conn.state == .relaying);
                    const direction_state = state(conn);
                    // Idle on entry, sending once a send has completed —
                    // and `receiving` again when a transform yielded
                    // nothing and the pump read on for the rest of a unit
                    // it can only decode whole (a TLS record). That third
                    // arm is the pump's stated contract for a transforming
                    // policy: `beforeRecv` twice with no send between.
                    // Identity transforms never reach it, because a recv
                    // delivers at least one byte and identity forwards all
                    // of them.
                    assert(direction_state.phase != .finished);
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

                /// The access log's byte counts for an L4 connection (§8),
                /// taken on the client side of the proxy in both
                /// directions: what arrived from the client is counted as
                /// it is received, what leaves for the client as it is
                /// sent. Counting each direction on its client-facing half
                /// is what makes `bytes_in`/`bytes_out` mean the same
                /// thing here as they do on an HTTP line — bytes that
                /// crossed the wire to and from the client — rather than
                /// bytes the origin happened to see.
                pub fn afterFeed(conn: *ConnType, received: u32, fr: pump.FeedResult) void {
                    _ = received;
                    if (direction == .client_to_upstream) {
                        conn.stream.log.bytes_in += fr.consumed;
                    }
                }

                pub fn afterSend(conn: *ConnType, sent: u32) void {
                    if (direction == .upstream_to_client) {
                        conn.stream.log.bytes_out += sent;
                    }
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
                    server.witnessKernelPressure(.recv, err);
                    server.beginTeardown(conn);
                }

                pub fn onSendError(server: *ServerType, conn: *ConnType, err: Io.SendError) void {
                    server.witnessKernelPressure(.send, err);
                    server.beginTeardown(conn);
                }

                /// Reached only through a transform that said its stream
                /// ended: `feed` never yields 0 consumed bytes, so a plain
                /// relay cannot get here at all. For TLS that is the
                /// client's close_notify — it will send no more
                /// application data, which is a half-close exactly like a
                /// FIN and is told to the far side as one (§6).
                ///
                /// The distinction matters because no socket EOF need ever
                /// follow: the TCP connection stays open for the other
                /// direction, so a relay that waited for one would hold a
                /// cleanly-ended session until the idle deadline reaped it.
                pub fn onDrained(server: *ServerType, conn: *ConnType) void {
                    assert(conn.state == .relaying);
                    assert(direction == .client_to_upstream);
                    assert(conn.tls != null);
                    assert(conn.tls.?.peerClosed());
                    state(conn).phase = .finished;
                    server.io.shutdown(targetSocket(conn), .write);
                    server.storeDeadline(conn, server.idleTimeoutMs());
                    maybeFinish(server, conn);
                }

                /// Unreachable for L4: `framingDone` is always false.
                pub fn onComplete(server: *ServerType, conn: *ConnType) void {
                    _ = server;
                    _ = conn;
                    unreachable;
                }

                // -- the TLS transform (§4, #125) --
                //
                // Only the client side transforms: this is termination, so
                // the origin leg is plaintext in both directions. That
                // makes the two hooks below asymmetric on purpose — the
                // client→upstream direction decrypts what it reads, the
                // upstream→client direction encrypts what it writes, and
                // each leaves the other alone.

                /// Ciphertext reads straight into the engine's record
                /// buffer: reassembly happens there, and the plaintext
                /// destination is where it decrypts *to*, so it cannot also
                /// be the read target.
                pub fn recvBuffer(conn: *ConnType) []u8 {
                    if (direction == .client_to_upstream) {
                        if (conn.tls) |engine| return engine.recvBuffer();
                    }
                    return @field(conn.stream.relay_buffer.?, @tagName(direction));
                }

                /// Decrypt, so framing sees plaintext and never learns a
                /// transform happened. Yields nothing for a record that
                /// carried no application data — a fragment, an alert, a
                /// KeyUpdate — which the pump reads on for; and nothing for
                /// close_notify, which `transformEnded` tells apart.
                pub fn transformIn(conn: *ConnType, chunk: []u8) ?[]const u8 {
                    if (direction != .client_to_upstream) return chunk;
                    const engine = conn.tls orelse return chunk;
                    if (!hasOutboundRoom(conn.server, conn)) return null;
                    var out: Decrypted = .{ .conn = conn };
                    const sink = out.sink();
                    engine.received(chunk.len, &sink) catch {
                        conn.server.counters.increment("tls_relay_failed");
                        return null;
                    };
                    return engine.plaintext[0..out.len];
                }

                /// An empty decrypt ends the stream only when the peer said
                /// so in protocol. A close_notify is an in-band EOF that no
                /// socket EOF need follow, so without this the direction
                /// waits for bytes that will never come until the deadline
                /// reaps a connection that said a clean goodbye.
                pub fn transformEnded(conn: *ConnType) bool {
                    if (direction != .client_to_upstream) return false;
                    const engine = conn.tls orelse return false;
                    return engine.peerClosed();
                }

                /// Encrypt the framed chunk once, before the first send —
                /// a resume must not re-encrypt bytes already gone.
                /// Chunked by the pump's own buffer, which is sized at
                /// `relay_buffer_bytes` and so already within what the
                /// engine accepts in one record.
                pub fn transformOut(conn: *ConnType, consumed: u32) bool {
                    if (direction != .upstream_to_client) return true;
                    const engine = conn.tls orelse return true;
                    if (!hasOutboundRoom(conn.server, conn)) return false;
                    engine.sendApp(
                        conn.stream.relay_buffer.?.upstream_to_client[0..consumed],
                    ) catch {
                        conn.server.counters.increment("tls_relay_failed");
                        return false;
                    };
                    return true;
                }

                /// Plaintext leaves the buffer it decrypted into;
                /// ciphertext leaves the outbox, which carries its own
                /// cursor. Plain: the framed window still owed.
                pub fn sendSlice(conn: *ConnType) []const u8 {
                    const direction_state = state(conn);
                    if (conn.tls) |engine| {
                        if (direction == .upstream_to_client) return engine.outbound();
                        if (direction_state.owed() == 0) return &.{};
                        return direction_state.pending(engine.plaintext);
                    }
                    if (direction_state.owed() == 0) return &.{};
                    return direction_state.pending(@field(conn.stream.relay_buffer.?, @tagName(direction)));
                }

                /// Credit whichever cursor tracks the wire. Only the
                /// response direction diverges: the wire carries
                /// ciphertext, which outnumbers the plaintext the debt
                /// counts, so the debt settles all at once when the outbox
                /// empties — the pump's stated contract for a transforming
                /// send.
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
            };
        }

        /// The engine stages into one outbox both directions can append
        /// to, so a step must not start unless what it may produce fits.
        /// Checked rather than asserted: the room depends on how fast the
        /// far side is draining, which is the peer's business, not an
        /// invariant of ours.
        fn hasOutboundRoom(server: *ServerType, conn: *ConnType) bool {
            assert(conn.state == .relaying);
            assert(conn.tls != null);
            if (conn.tls.?.outboundRoom() >= TlsEngine.emitted_record_bytes_max) return true;
            server.counters.increment("tls_relay_failed");
            server.beginTeardown(conn);
            return false;
        }

        /// Accumulates decrypted application data into the engine's
        /// plaintext destination, whose floor covers a whole record's worth
        /// plus the read that completed it.
        ///
        /// One step drains every complete record the read finished, so both
        /// callbacks can fire in one call and their *order* is the whole
        /// meaning. Data then goodbye is a client signing off after a last
        /// write, and every one of those bytes is forwarded. Goodbye then
        /// data is a peer talking past its own close — RFC 8446 §6.1 says
        /// anything after the alert is ignored, so it is dropped here
        /// rather than relayed to an origin on a session that had ended.
        const Decrypted = struct {
            conn: *ConnType,
            len: u32 = 0,
            closed: bool = false,

            fn sink(self: *Decrypted) TlsEngine.Sink {
                return .{ .ctx = self, .appData = append, .closed = peerClosed };
            }

            fn append(ctx: *anyopaque, bytes: []const u8) void {
                const self: *Decrypted = @ptrCast(@alignCast(ctx));
                if (self.closed) return;
                const buffer = self.conn.tls.?.plaintext;
                assert(self.len + bytes.len <= buffer.len);
                @memcpy(buffer[self.len..][0..bytes.len], bytes);
                self.len += @intCast(bytes.len);
            }

            /// The engine records the close for `transformEnded` to read
            /// once the step returns; this copy is what makes the *rest of
            /// this same call* stop accepting data.
            fn peerClosed(ctx: *anyopaque) void {
                const self: *Decrypted = @ptrCast(@alignCast(ctx));
                self.closed = true;
            }
        };

        const PumpClientToUpstream = pump.Pump(IoType, .client_to_upstream, Policy(.client_to_upstream));
        const PumpUpstreamToClient = pump.Pump(IoType, .upstream_to_client, Policy(.upstream_to_client));

        pub fn start(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .relaying);
            assert(conn.stream.upstream_socket != null);
            const client_to_upstream =
                &conn.stream.directions[@intFromEnum(Direction.client_to_upstream)];
            if (client_to_upstream.owed() >= 1) {
                // Payload that arrived coalesced behind a PROXY header
                // (#142): the receive phase staged it at the buffer's
                // start and framed it as this direction's debt, so the
                // relay enters the pump mid-cycle — received, owed, not
                // yet sent — exactly where `onRecv` would stand after
                // framing. The send drains the debt, then rejoins the
                // recv loop; no byte is read ahead of it (§6).
                assert(client_to_upstream.phase == .receiving);
                PumpClientToUpstream.armSend(server, conn);
            } else {
                assert(client_to_upstream.phase == .idle);
                PumpClientToUpstream.armRecv(server, conn);
            }
            assert(conn.stream.directions[1].phase == .idle);
            PumpUpstreamToClient.armRecv(server, conn);
        }

        /// Both directions drained: the orderly end of an L4 connection.
        fn maybeFinish(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .relaying);
            if (conn.stream.directions[0].phase == .finished) {
                if (conn.stream.directions[1].phase == .finished) {
                    // The one L4 ending that is not a failure: both peers
                    // said goodbye. Every other way this connection can end
                    // — a reset, a deadline, a drain straggler — leaves the
                    // access log's default `aborted` in place (§8), so the
                    // line distinguishes a completed relay from a cut one.
                    conn.stream.log.outcome = .closed;
                    server.beginTeardown(conn);
                }
            }
        }
    };
}
