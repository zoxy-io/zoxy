//! TLS to an HTTP/1.1 origin (§7, #296): an HTTPS cluster's upstream
//! connection — `protocol` `http1` with a `tls` block — speaks TLS under the
//! exchange, which never learns it. Its upstream ops reach this file through
//! `Server`'s `upstream*` dispatch, as an `h2` cluster's reach
//! `origin_pool.zig`: the exchange sends plaintext and receives plaintext,
//! and a *session* here seals and opens the records between.
//!
//! A session rides the upstream pool slot (`Upstream.tls`): taken at the
//! dial, kept while the connection is parked, released wherever the slot is
//! (`Server.releaseUpstream`). A reused connection therefore never
//! handshakes again, and is reused only within its cluster and endpoint —
//! the pool's key — so the name and anchors it was verified against are the
//! ones the cluster still names. The connection carries no client identity
//! (server authentication only), which is what keeps reuse across clients
//! sound; client certificates to an origin (#9) would end that.
//!
//! The handshake is driven by the exchange's first op, the request head's
//! send, under `connect_ms` from its start: ALPN offers `http/1.1`, and the
//! origin may select it or nothing. A handshake that fails — a chain that
//! does not verify, another protocol, an alert, a hangup — fails that send,
//! which the exchange answers `502` on a fresh connection, as it would a
//! reset (#181 does not retry it: the dial itself succeeded).
//!
//! **The ring.** A session drives its socket with two completions of its
//! own, and hands each result to the exchange's op through a zero-delay
//! timer on the exchange's completion — never inside the call that armed
//! it (§4). No op of the exchange's is on the ring while the session holds
//! it: each socket op *stands for* one waiting exchange op, and no waiting
//! op stands behind two (`free`), so the socket ops and the deliveries
//! together never outnumber the exchange's own armed ops — the stream's
//! peak stays `stream_ops_max` (§5), which `assertRing` checks after every
//! arm and every delivery. The handshake is sequential under that rule,
//! as it is anyway: a flight out, then a read, then a flight. And an
//! exchange op is delivered only once nothing the session has in flight
//! stands for it, so an exchange that has had its ops delivered has a
//! quiescent session — the condition its park and its close assert.

const std = @import("std");

const Io = @import("../io/io.zig");
const OriginClient = @import("../tls/OriginClient.zig");
const constants = @import("../constants.zig");

const assert = std.debug.assert;

pub fn Driver(comptime IoType: type) type {
    const ConnType = @import("Conn.zig").Conn(IoType);
    const StreamType = ConnType.StreamType;
    const ServerType = @import("../Server.zig").Server(IoType);
    const Upstream = @import("upstream.zig").UpstreamPool(IoType).Upstream;

    return struct {
        pub const SendCallback = fn (*StreamType, Io.SendError!u32) void;
        pub const RecvCallback = fn (*StreamType, Io.RecvError!u32) void;

        pub const Phase = enum(u8) {
            /// Taken at a dial; the handshake waits for the first op.
            fresh,
            handshaking,
            open,
            /// Over: every op fails, and the connection is never parked.
            failed,
        };

        /// Which exchange op a socket op of the session's stands for.
        pub const Side = enum(u8) { send, recv };

        /// An op the exchange armed, held here until its result is known.
        pub const Pending = struct {
            bytes: []u8 = &.{},
            completion: ?*IoType.Completion = null,
            callback: ?*const anyopaque = null,
            delivering: bool = false,
            count: u32 = 0,
            failure: ?Failure = null,

            pub const Failure = enum(u8) { reset, end_of_stream };

            fn armed(pending: *const Pending) bool {
                return pending.callback != null;
            }

            /// Armed, and its result not yet on its way.
            fn waiting(pending: *const Pending) bool {
                return pending.armed() and !pending.delivering;
            }
        };

        pub const Session = struct {
            pool_next: u32,
            generation: u32,
            client: OriginClient,
            server: *ServerType,
            /// The exchange leasing the connection; null while it is parked.
            stream: ?*StreamType,
            socket: IoType.Socket,
            cluster_index: u16,
            phase: Phase,
            send: Pending,
            recv: Pending,
            /// The socket ops in flight, and what each stands for.
            sending: ?Side,
            receiving: ?Side,
            /// The origin's FIN came in.
            eof: bool,
            shut: bool,
            op_send: IoType.Completion,
            op_recv: IoType.Completion,
        };

        // -- the slot's life: dial, park, checkout, release ------------------

        /// A session for a fresh dial to an HTTPS cluster's endpoint, bound
        /// to the exchange's upstream slot — or false when the pool is
        /// empty, which the caller sheds.
        pub fn take(server: *ServerType, stream: *StreamType) bool {
            const upstream = stream.upstream.?;
            assert(upstream.tls == null);
            assert(server.config.clusters[upstream.cluster_index].tls != null);
            const session = server.upstream_tls.acquire() orelse return false;
            session.server = server;
            session.stream = stream;
            session.cluster_index = upstream.cluster_index;
            session.phase = .fresh;
            session.send = .{};
            session.recv = .{};
            session.sending = null;
            session.receiving = null;
            session.eof = false;
            session.shut = false;
            assert(!session.client.started);
            upstream.tls = session;
            return true;
        }

        fn sessionOf(stream: *const StreamType) *Session {
            const upstream = stream.upstream.?;
            const session: *Session = @ptrCast(@alignCast(upstream.tls.?));
            assert(session.stream == stream);
            return session;
        }

        /// Whether the connection's session is clean enough to park: open,
        /// quiescent, holding nothing the origin sent past the response — a
        /// byte the next exchange would read as the start of its own — and
        /// not closed by the origin.
        pub fn parkable(stream: *const StreamType) bool {
            const session = sessionOf(stream);
            assertQuiescent(session);
            if (session.phase != .open) return false;
            if (session.eof or session.client.closed) return false;
            return session.client.plaintext_len == 0 and session.client.records.empty();
        }

        /// The connection parks: the session stays with its slot, bound to
        /// no exchange.
        pub fn unbind(stream: *StreamType) void {
            const session = sessionOf(stream);
            assertQuiescent(session);
            assert(session.phase == .open);
            session.stream = null;
        }

        /// A parked connection is checked out: its session serves the
        /// exchange that took it.
        pub fn rebind(stream: *StreamType) void {
            const upstream = stream.upstream.?;
            const session: *Session = @ptrCast(@alignCast(upstream.tls.?));
            assert(session.stream == null);
            assert(session.phase == .open);
            assertQuiescent(session);
            session.stream = stream;
        }

        /// The slot is released (`Server.releaseUpstream`): the handshake's
        /// libcrypto state goes back to the fixed heap, and the session to
        /// its pool.
        pub fn release(server: *ServerType, upstream: *Upstream) void {
            const session: *Session = @ptrCast(@alignCast(upstream.tls.?));
            assertQuiescent(session);
            session.client.finish();
            session.stream = null;
            upstream.tls = null;
            server.upstream_tls.release(session);
        }

        fn assertQuiescent(session: *const Session) void {
            assert(session.sending == null);
            assert(session.receiving == null);
            assert(!session.send.armed());
            assert(!session.recv.armed());
        }

        // -- what the exchange arms -----------------------------------------

        pub fn send(
            server: *ServerType,
            stream: *StreamType,
            bytes: []const u8,
            completion: *IoType.Completion,
            comptime callback: SendCallback,
        ) void {
            const session = sessionOf(stream);
            assert(!session.send.armed());
            assert(bytes.len >= 1);
            session.send = .{
                .bytes = @constCast(bytes),
                .completion = completion,
                .callback = @ptrCast(&callback),
            };
            drive(server, session);
        }

        pub fn recv(
            server: *ServerType,
            stream: *StreamType,
            buffer: []u8,
            completion: *IoType.Completion,
            comptime callback: RecvCallback,
        ) void {
            const session = sessionOf(stream);
            assert(!session.recv.armed());
            assert(buffer.len >= 1);
            session.recv = .{
                .bytes = buffer,
                .completion = completion,
                .callback = @ptrCast(&callback),
            };
            drive(server, session);
        }

        /// Force what the exchange has armed to deliver, as shutting a
        /// socket down would (§8): the socket is shut, so the session's own
        /// ops complete, and every op fails once nothing stands for it.
        pub fn shutdown(server: *ServerType, stream: *StreamType) void {
            const session = sessionOf(stream);
            // An exchange arms nothing before its first op, which starts
            // the handshake: a session forced at all has a socket.
            assert(session.phase != .fresh);
            fail(server, session);
        }

        /// The exchange lets the connection go with nothing armed on it:
        /// the socket closes, and the session waits on its slot for the
        /// release.
        pub fn close(server: *ServerType, stream: *StreamType) void {
            const session = sessionOf(stream);
            assertQuiescent(session);
            server.io.closeNow(stream.upstream_socket.?);
            stream.upstream_socket = null;
            session.phase = .failed;
        }

        // -- the drive ------------------------------------------------------

        /// Move the session as far as it goes: start the handshake, decrypt
        /// what is buffered, put owed octets on the wire, seal the exchange's
        /// next record, hand over plaintext, and read when someone waits.
        fn drive(server: *ServerType, session: *Session) void {
            if (session.phase == .fresh) startHandshake(server, session);
            if (session.phase != .failed and !session.client.owes()) {
                session.client.process() catch return failTls(server, session);
            }
            if (session.phase == .handshaking) handshakeProgress(server, session);
            if (session.phase == .failed) return settleFailed(server, session);
            if (session.phase == .open) {
                sealSend(server, session);
                offerRecv(server, session);
            }
            flushOwed(server, session);
            readIfWanted(server, session);
            assertRing(session);
        }

        /// The ClientHello is owed at once, naming the cluster's server and
        /// offering `http/1.1`; the handshake runs under `connect_ms`.
        fn startHandshake(server: *ServerType, session: *Session) void {
            assert(session.phase == .fresh);
            const stream = session.stream.?;
            const tls = &server.config.clusters[session.cluster_index].tls.?;
            session.socket = stream.upstream_socket.?;
            var entropy: [64]u8 = undefined;
            server.io.fillRandom(&entropy);
            // A scalar of zeros is the one x25519 refuses; the stream is
            // random, so this never moves anything a peer could see.
            entropy[32] |= 1;
            session.client.start(&.{
                .protocol = .http1,
                .server_name = tls.server_name,
                .anchors = tls.anchors,
                .client_random = entropy[0..32].*,
                .x25519_private = entropy[32..64].*,
                .now_sec = nowSec(server),
            });
            session.phase = .handshaking;
            assert(session.client.owes());
            // No re-base: the timer armed is still the dial's own connect
            // budget, begun before this one, so it fires no later and finds
            // this deadline then (§4's lazy re-arm).
            server.storeExchangeDeadline(stream, server.config.connect_timeout_ms);
        }

        fn handshakeProgress(server: *ServerType, session: *Session) void {
            assert(session.phase == .handshaking);
            const client = &session.client;
            if (client.closed) return failTls(server, session);
            if (!client.connected) return;
            if (!client.alpnAllowsHttp1()) return failTls(server, session);
            session.phase = .open;
            server.counters.increment("upstream_tls_handshakes");
            // The handshake's budget is spent; the exchange's own goes on.
            server.storeExchangeDeadline(session.stream.?, server.idleTimeoutMs());
        }

        /// The exchange's next record, sealed once nothing else is owed.
        fn sealSend(server: *ServerType, session: *Session) void {
            assert(session.phase == .open);
            if (!session.send.waiting()) return;
            if (session.client.owes() or session.sending != null) return;
            const sealed = session.client.seal(session.send.bytes) catch return failTls(server, session);
            assert(sealed >= 1);
            assert(sealed <= session.send.bytes.len);
        }

        /// Plaintext to the exchange's waiting recv — or its end, once the
        /// origin has closed and every record before the close is read.
        fn offerRecv(server: *ServerType, session: *Session) void {
            assert(session.phase == .open);
            if (!session.recv.waiting()) return;
            // Something in flight stands for this recv: it is delivered
            // when that completes.
            if (session.sending == .recv or session.receiving == .recv) return;
            const client = &session.client;
            if (client.plaintext_len >= 1) {
                session.recv.count = client.takePlaintext(session.recv.bytes);
                return deliver(server, session, .recv);
            }
            if (client.owes()) return; // Records wait behind an owed write.
            if (client.closed or session.eof) {
                session.recv.failure = .end_of_stream;
                return deliver(server, session, .recv);
            }
        }

        /// Whether the exchange's `side` op waits with nothing in flight
        /// standing for it — so a socket op may.
        fn free(session: *const Session, side: Side) bool {
            const pending = switch (side) {
                .send => &session.send,
                .recv => &session.recv,
            };
            return pending.waiting() and session.sending != side and session.receiving != side;
        }

        /// A waiting op a new socket op may stand for: the send first.
        fn freeSide(session: *const Session) ?Side {
            if (free(session, .send)) return .send;
            if (free(session, .recv)) return .recv;
            return null;
        }

        /// Owed octets to the socket — a handshake flight, a reply the
        /// origin asked for, or the exchange's sealed record — standing for
        /// whichever waiting op is free; with none, the next op sends them.
        fn flushOwed(server: *ServerType, session: *Session) void {
            if (!session.client.owes() or session.sending != null) return;
            // The exchange's own record stands for its send, which it is.
            const side = freeSide(session) orelse return;
            session.sending = side;
            server.io.send(session.socket, session.client.wire(), &session.op_send, Session, session, onSocketSend);
            assert(session.sending != session.receiving);
        }

        /// A read, when someone waits on what it brings: the handshake, or
        /// the exchange's recv with no plaintext to give it.
        fn readIfWanted(server: *ServerType, session: *Session) void {
            if (session.receiving != null) return;
            if (session.eof or session.client.closed) return;
            if (!session.client.canReceive()) return;
            const side: Side = switch (session.phase) {
                .handshaking => freeSide(session) orelse return,
                .open => side: {
                    if (!free(session, .recv) or session.client.plaintext_len >= 1) return;
                    break :side .recv;
                },
                .fresh, .failed => return,
            };
            session.receiving = side;
            server.io.recv(session.socket, session.client.recvBuffer(), &session.op_recv, Session, session, onSocketRecv);
            assert(session.sending != session.receiving);
        }

        fn onSocketSend(session: *Session, result: Io.SendError!u32) void {
            const server = session.server;
            const side = session.sending.?;
            session.sending = null;
            const count = result catch |err| {
                server.witnessKernelPressure(.send, err);
                return fail(server, session);
            };
            if (session.phase == .failed) return settleFailed(server, session);
            assert(count >= 1);
            const plain = session.client.sent(count);
            if (plain >= 1) {
                // The exchange's sealed record is out, whole.
                assert(side == .send);
                assert(session.send.waiting());
                session.send.count = plain;
                deliver(server, session, .send);
            }
            drive(server, session);
        }

        fn onSocketRecv(session: *Session, result: Io.RecvError!u32) void {
            const server = session.server;
            assert(session.receiving != null);
            session.receiving = null;
            const count = result catch |err| switch (err) {
                error.EndOfStream => {
                    session.eof = true;
                    if (session.phase == .handshaking) return failTls(server, session);
                    return drive(server, session);
                },
                else => {
                    server.witnessKernelPressure(.recv, err);
                    return fail(server, session);
                },
            };
            if (session.phase == .failed) return settleFailed(server, session);
            assert(count >= 1);
            session.client.received(count, nowSec(server)) catch return failTls(server, session);
            drive(server, session);
        }

        // -- failure ----------------------------------------------------------

        /// TLS itself failed — the chain, the protocol, an alert, a record
        /// that did not open: counted, then over like any failure.
        fn failTls(server: *ServerType, session: *Session) void {
            server.counters.increment("upstream_tls_failed");
            fail(server, session);
        }

        /// Over: the socket shut once, so what the session has in flight
        /// completes; every exchange op fails once nothing stands for it.
        fn fail(server: *ServerType, session: *Session) void {
            session.phase = .failed;
            if (!session.shut) {
                session.shut = true;
                server.io.shutdown(session.socket, .both);
            }
            settleFailed(server, session);
        }

        fn settleFailed(server: *ServerType, session: *Session) void {
            assert(session.phase == .failed);
            if (session.send.waiting() and session.sending != .send and session.receiving != .send) {
                session.send.failure = .reset;
                deliver(server, session, .send);
            }
            if (session.recv.waiting() and session.sending != .recv and session.receiving != .recv) {
                session.recv.failure = .reset;
                deliver(server, session, .recv);
            }
            assertRing(session);
        }

        // -- delivery ---------------------------------------------------------

        fn deliver(server: *ServerType, session: *Session, side: Side) void {
            const pending = switch (side) {
                .send => &session.send,
                .recv => &session.recv,
            };
            assert(pending.waiting());
            // Nothing in flight stands for it any more.
            assert(session.sending != side and session.receiving != side);
            pending.delivering = true;
            const stream = session.stream.?;
            switch (side) {
                .send => server.io.timerStart(pending.completion.?, 0, StreamType, stream, onSendDelivered),
                .recv => server.io.timerStart(pending.completion.?, 0, StreamType, stream, onRecvDelivered),
            }
        }

        fn onSendDelivered(stream: *StreamType, result: Io.TimerError!void) void {
            result catch unreachable; // Nothing cancels a delivery.
            const session = sessionOf(stream);
            assert(session.send.delivering);
            const pending = session.send;
            session.send = .{};
            const callback: *const SendCallback = @ptrCast(@alignCast(pending.callback.?));
            if (pending.failure != null) return callback(stream, error.Reset);
            assert(pending.count >= 1);
            callback(stream, pending.count);
        }

        fn onRecvDelivered(stream: *StreamType, result: Io.TimerError!void) void {
            result catch unreachable; // Nothing cancels a delivery.
            const session = sessionOf(stream);
            assert(session.recv.delivering);
            const pending = session.recv;
            session.recv = .{};
            const callback: *const RecvCallback = @ptrCast(@alignCast(pending.callback.?));
            if (pending.failure) |failure| return switch (failure) {
                .reset => callback(stream, error.Reset),
                .end_of_stream => callback(stream, error.EndOfStream),
            };
            assert(pending.count >= 1);
            callback(stream, pending.count);
        }

        /// The stream's ring ops: the session's socket ops and the
        /// exchange's deliveries, which never exceed what the exchange's own
        /// two data ops would hold (`stream_ops_max`, §5).
        fn assertRing(session: *const Session) void {
            const on_ring = @as(u32, @intFromBool(session.sending != null)) +
                @intFromBool(session.receiving != null) +
                @intFromBool(session.send.delivering) +
                @intFromBool(session.recv.delivering);
            assert(on_ring <= constants.stream_ops_max);
        }

        fn nowSec(server: *const ServerType) i64 {
            return @intCast(server.io.nowWallNs() / std.time.ns_per_s);
        }
    };
}
