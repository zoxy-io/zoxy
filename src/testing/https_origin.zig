//! An HTTPS origin (#296): HTTP/1.1 behind TLS, serving the trust fixtures'
//! leaf for `origin.zoxy.test` through `TestTlsServer` — for the directed
//! scenarios and the simulator's HTTPS clusters alike. It reads requests as
//! the proxy forwards them: a head, then its body by the head's own framing
//! — none, a `Content-Length`, or chunked with its trailer section — one
//! request after another, pipelined or not. It answers each with
//! `response`, keeps the connection unless told to close, and records what
//! it heard for a scenario to assert on.
//!
//! It holds `conns_count_max` connections at once, reusing a slot once its
//! socket is released, and closes a dial past them all at once (`refused`):
//! a proxy redialing under an adversary needs more than a directed scenario
//! does. Test support: nothing in the server imports it.

const std = @import("std");

const Io = @import("../io/io.zig");
const constants = @import("../constants.zig");
const parser = @import("../http/parser.zig");
const TestTlsServer = @import("../tls/TestTlsServer.zig");

const assert = std.debug.assert;

pub fn HttpsOrigin(comptime IoType: type, comptime conns_count_max: u32) type {
    comptime assert(conns_count_max >= 1);
    return struct {
        io: *IoType = undefined,
        listener: IoType.Listener = undefined,
        accept_completion: IoType.Completion = .{},
        listening: bool = false,
        response: []const u8 = "",
        close_after_response: bool = false,
        /// Read every request, and answer none.
        mute: bool = false,
        /// What ALPN selects from: `http/1.1`, nothing, or a protocol the
        /// proxy did not offer.
        alpn: []const []const u8 = &.{"http/1.1"},
        tls_servers: []TestTlsServer = &.{},
        conns: [conns_max]Conn = @splat(.{}),
        accepted_count: u32 = 0,
        /// Slots in use or ever used, at most `conns_max`.
        slots_used: u32 = 0,
        /// Dials closed at once because every slot was still busy.
        refused: u32 = 0,
        requests: u32 = 0,
        requests_served: u32 = 0,
        tls_failures: u32 = 0,
        /// Forwarded bytes that were no request: a head that did not parse,
        /// or a body that broke its framing. The proxy forwards neither.
        violations: u32 = 0,
        /// Heads past what this origin's parser holds — more fields than
        /// `headers_max` once the proxy's own lines are added to a client's
        /// full set (`render.zig` names the case). Legal, and refused here
        /// by closing, as an origin with a smaller limit would.
        heads_too_large: u32 = 0,
        /// The last request's head as decrypted, and its body's length.
        last_head: [512]u8 = undefined,
        last_head_len: u32 = 0,
        last_body_len: u64 = 0,

        const Self = @This();
        pub const conns_max: u32 = conns_count_max;
        /// Plaintext waiting to be read as requests: a head at its widest,
        /// and the octets of the body that arrived with it.
        const pending_bytes_max: u32 = 24 * 1024;

        comptime {
            // An incomplete head of the default size, and more, fits.
            assert(pending_bytes_max > constants.head_buffer_bytes_default);
        }

        const Framing = union(enum) {
            none,
            content_length: u64,
            chunked: parser.ChunkedScanner,
        };

        pub const Conn = struct {
            origin: *Self = undefined,
            socket: IoType.Socket = undefined,
            tls: *TestTlsServer = undefined,
            recv_completion: IoType.Completion = .{},
            send_completion: IoType.Completion = .{},
            receiving: bool = false,
            sending: bool = false,
            failing: bool = false,
            closed: bool = false,
            /// The socket is released: closed, and no op still out on it.
            socket_closed: bool = false,
            pending: [pending_bytes_max]u8 = undefined,
            pending_len: u32 = 0,
            /// The request in flight: its body's framing once the head is
            /// read, null while the head is still arriving.
            framing: ?Framing = null,
            body_seen: u64 = 0,
            answering: bool = false,
            response_sent: u32 = 0,

            fn armRecv(conn: *Conn) void {
                if (conn.receiving or conn.closed or conn.failing or conn.answering) return;
                const buffer = conn.tls.recvBuffer();
                if (buffer.len == 0) return;
                conn.receiving = true;
                conn.origin.io.recv(conn.socket, buffer, &conn.recv_completion, Conn, conn, onRecv);
            }

            fn onRecv(conn: *Conn, result: Io.RecvError!u32) void {
                conn.receiving = false;
                const received = result catch return conn.fail();
                if (conn.failing) return conn.fail();
                conn.tls.received(received) catch return conn.fail();
                conn.advance();
            }

            /// Plaintext into requests, owed octets out, and a read again.
            fn advance(conn: *Conn) void {
                // A conn that failed reads nothing more: what is pending is
                // what failed it.
                if (conn.failing or conn.closed) return;
                var passes: u32 = 0;
                // Each pass takes every plaintext octet there is room for,
                // and `process` opens at most the records that refill it.
                while (conn.tls.plaintext_len >= 1 and !conn.answering) : (passes += 1) {
                    assert(passes < 64);
                    assert(!conn.failing);
                    const room = conn.pending[conn.pending_len..];
                    if (room.len == 0) return conn.violate();
                    const taken = conn.tls.takePlaintext(room);
                    conn.pending_len += taken;
                    conn.tls.process() catch return conn.fail();
                    conn.consume();
                    if (conn.failing) return;
                }
                conn.pushSend();
                conn.armRecv();
            }

            /// Read requests out of what is pending until one is whole —
            /// it is then answered before the next is read — or the bytes
            /// run out.
            fn consume(conn: *Conn) void {
                var passes: u32 = 0;
                while (!conn.answering and !conn.failing and conn.pending_len >= 1) : (passes += 1) {
                    assert(passes < pending_bytes_max);
                    if (conn.framing == null) {
                        if (!conn.readHead()) return;
                    }
                    if (!conn.readBody()) return;
                    conn.origin.last_body_len = conn.body_seen;
                    conn.framing = null;
                    if (conn.origin.mute) continue;
                    conn.answering = true;
                    conn.response_sent = 0;
                }
            }

            /// The head, if it is whole, taken off the front of what is
            /// pending; false while it is still arriving or did not parse.
            fn readHead(conn: *Conn) bool {
                assert(conn.framing == null);
                var storage: parser.HeaderStorage = undefined;
                const head = parser.parseRequestHead(conn.pending[0..conn.pending_len], false, &storage, null) catch |err| {
                    switch (err) {
                        error.Incomplete => {},
                        // Legal, and more than this origin holds.
                        error.HeadTooLarge => {
                            conn.origin.heads_too_large += 1;
                            conn.fail();
                        },
                        // A forwarded head is §7-canonical: anything else
                        // that does not parse is the proxy's to answer for.
                        else => conn.violate(),
                    }
                    return false;
                };
                const origin = conn.origin;
                origin.requests += 1;
                const kept: u32 = @min(head.head_len, origin.last_head.len);
                @memcpy(origin.last_head[0..kept], conn.pending[0..kept]);
                origin.last_head_len = kept;
                conn.framing = switch (head.framing) {
                    .none => .none,
                    .content_length => |length| .{ .content_length = length },
                    .chunked => .{ .chunked = .{} },
                    // The parser asserts requests are length-delimited.
                    .until_close => unreachable,
                };
                conn.body_seen = 0;
                conn.drop(head.head_len);
                assert(conn.framing != null);
                return true;
            }

            /// As much of the body as is pending, counted and dropped; true
            /// once the body is whole.
            fn readBody(conn: *Conn) bool {
                assert(conn.framing != null);
                // Through a pointer: a chunked body's scanner keeps its
                // place across deliveries, in the framing itself.
                const framing = &conn.framing.?;
                switch (framing.*) {
                    .none => return true,
                    .content_length => |length| {
                        const take: u32 = @intCast(@min(length - conn.body_seen, conn.pending_len));
                        conn.body_seen += take;
                        conn.drop(take);
                        return conn.body_seen == length;
                    },
                    .chunked => |*scanner| {
                        if (conn.pending_len == 0) return false;
                        const progress = scanner.feed(conn.pending[0..conn.pending_len]) catch {
                            conn.violate();
                            return false;
                        };
                        conn.drop(progress.consumed);
                        // The payload, not the framing around it.
                        conn.body_seen = scanner.body_bytes;
                        return progress.done;
                    },
                }
            }

            fn drop(conn: *Conn, count: u32) void {
                assert(count <= conn.pending_len);
                const rest = conn.pending_len - count;
                std.mem.copyForwards(u8, conn.pending[0..rest], conn.pending[count..conn.pending_len]);
                conn.pending_len = rest;
            }

            /// What TLS owes, or the answer's next record once nothing is.
            fn pushSend(conn: *Conn) void {
                if (conn.sending or conn.closed or conn.failing) return;
                const tls = conn.tls;
                const response = conn.origin.response;
                if (!tls.owes()) {
                    if (!conn.answering or !tls.connected) return;
                    assert(conn.response_sent < response.len);
                    _ = tls.seal(response[conn.response_sent..]) catch return conn.fail();
                }
                conn.sending = true;
                conn.origin.io.send(conn.socket, tls.wire(), &conn.send_completion, Conn, conn, onSend);
            }

            fn onSend(conn: *Conn, result: Io.SendError!u32) void {
                conn.sending = false;
                const sent = result catch return conn.fail();
                if (conn.failing) return conn.fail();
                conn.response_sent += conn.tls.sent(sent);
                if (conn.answering and conn.response_sent == conn.origin.response.len) return conn.answered();
                conn.tls.process() catch return conn.fail();
                conn.advance();
            }

            /// The answer is out: the next request, or the close.
            fn answered(conn: *Conn) void {
                assert(conn.answering);
                conn.origin.requests_served += 1;
                conn.answering = false;
                if (conn.origin.close_after_response) return conn.fail();
                conn.consume();
                conn.advance();
            }

            /// Bytes the proxy should never have forwarded.
            fn violate(conn: *Conn) void {
                conn.origin.violations += 1;
                conn.fail();
            }

            /// Shut, and closed once nothing is armed on the socket.
            fn fail(conn: *Conn) void {
                if (conn.closed) return;
                if (!conn.tls.connected and !conn.failing) conn.origin.tls_failures += 1;
                if (!conn.failing) {
                    conn.failing = true;
                    conn.origin.io.shutdown(conn.socket, .both);
                }
                if (conn.receiving or conn.sending) return;
                assert(!conn.receiving and !conn.sending);
                conn.closed = true;
                conn.socket_closed = true;
                conn.origin.io.closeNow(conn.socket);
                assert(conn.closed and conn.socket_closed);
            }
        };

        pub fn start(origin: *Self, arena: std.mem.Allocator, io: *IoType, address: std.Io.net.IpAddress) !void {
            origin.io = io;
            origin.tls_servers = try arena.alloc(TestTlsServer, conns_max);
            for (origin.tls_servers) |*server| server.started = false;
            origin.listener = try io.listen(&.{ .ip = address }, null);
            origin.listening = true;
            origin.armAccept();
        }

        fn armAccept(origin: *Self) void {
            origin.io.accept(origin.listener, &origin.accept_completion, Self, origin, onAccept);
        }

        /// A slot for the next connection: a fresh one while any is left,
        /// else one whose connection is closed and socket released.
        fn acquireSlot(origin: *Self) ?usize {
            assert(origin.slots_used <= conns_max);
            if (origin.slots_used < conns_max) {
                origin.slots_used += 1;
                return origin.slots_used - 1;
            }
            for (&origin.conns, 0..) |*conn, index| {
                if (conn.closed and conn.socket_closed) return index;
            }
            return null;
        }

        fn onAccept(origin: *Self, result: Io.AcceptError!IoType.Socket) void {
            const socket = result catch |err| {
                assert(err == error.Canceled);
                return;
            };
            const index = origin.acquireSlot() orelse {
                origin.refused += 1;
                origin.io.closeNow(socket);
                return origin.armAccept();
            };
            assert(index < conns_max);
            const conn = &origin.conns[index];
            const tls = &origin.tls_servers[index];
            tls.finish();
            origin.accepted_count += 1;
            conn.* = .{ .origin = origin, .socket = socket, .tls = tls };
            var key_share: [48]u8 = @splat(0x5a);
            key_share[47] = @truncate(origin.accepted_count);
            tls.start(origin.alpn, key_share) catch {
                origin.tls_failures += 1;
                origin.io.closeNow(socket);
                conn.closed = true;
                conn.socket_closed = true;
                return origin.armAccept();
            };
            conn.armRecv();
            origin.armAccept();
        }

        pub fn lastHead(origin: *const Self) []const u8 {
            return origin.last_head[0..origin.last_head_len];
        }

        pub fn stopListening(origin: *Self) void {
            if (!origin.listening) return;
            origin.io.listenClose(origin.listener);
            origin.listening = false;
        }

        /// Close what is still open at scenario end: the loop has stopped,
        /// so an op still out will never land.
        pub fn closeRemaining(origin: *Self) void {
            for (origin.conns[0..origin.slots_used], origin.tls_servers[0..origin.slots_used]) |*conn, *tls| {
                conn.closed = true;
                if (!conn.socket_closed) {
                    conn.socket_closed = true;
                    origin.io.closeNow(conn.socket);
                }
                tls.finish();
            }
        }
    };
}
