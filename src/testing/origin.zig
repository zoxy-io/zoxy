//! A shared scripted origin for L4 test harnesses. It accepts connections
//! and runs the same strict recv → send → recv echo the proxy relays
//! through, with per-connection misbehavior modes for the adversarial
//! paths (§9). Generic over the Io backend; both current users instantiate
//! `Origin(SimIo)`. The scripted *clients*
//! are deliberately not shared — the directed suite tracks connection
//! outcomes and drives drain races, while the sim tracks byte-exact
//! integrity under the adversary, and unifying them would force an
//! over-general abstraction.

const std = @import("std");

const Io = @import("../io/io.zig");
const proxy_protocol = @import("../net/proxy_protocol.zig");

const assert = std.debug.assert;

/// Per-connection origin behavior.
pub const Mode = enum(u8) {
    /// Echo every chunk back (strict recv → send → recv), close on FIN.
    echo,
    /// Answer the first chunk with an RST (misbehaving origin).
    reset_on_first_chunk,
    /// Read forever, never reply (drives the client's idle deadline).
    mute,
    /// Never read (drives upstream backpressure); no recv is armed.
    frozen,
};

pub fn Origin(comptime IoType: type) type {
    return struct {
        io: *IoType = undefined,
        listener: IoType.Listener = undefined,
        accept_completion: IoType.Completion = .{},
        conns: [conns_max]Conn = @splat(.{}),
        conns_count: u8 = 0,
        listening: bool = false,
        /// Default mode; overridden per connection by `mode_selector`.
        mode: Mode = .echo,
        /// Optional per-accept mode picker (the sim randomizes modes).
        mode_selector: ?*const fn (?*anyopaque) Mode = null,
        /// The #142 send half's receiving end: expect every connection to
        /// open with a PROXY protocol header, consume it before echoing,
        /// and record what it announced. An origin double must fail
        /// loudly — garbage where a header belongs is a violation the
        /// harness asserts on, never a tolerated shape.
        expect_proxy_header: bool = false,
        /// Connections whose header parsed. Echo-mode only: the
        /// misbehaving modes never parse — `reset_on_first_chunk` acts
        /// on the first delivery, `mute` reads without judging (its
        /// `header_len` never advances, so its recv window never
        /// shrinks), and `frozen` never reads.
        proxy_header_conns: u32 = 0,
        /// Connections whose opening bytes were not a valid header.
        proxy_header_violations: u32 = 0,
        /// Optional hook fired after each accept (the drain-race test
        /// starts a client from here).
        on_accept: ?*const fn (?*anyopaque) void = null,
        context: ?*anyopaque = null,

        const Self = @This();
        /// Sized for the sim's worst case: the client population plus a
        /// `check` scenario's passing probes, each of which accepts and
        /// vanishes (§7) but still consumes a slot — conns are tracked
        /// monotonically, never recycled.
        pub const conns_max: u8 = 32;
        const buffer_bytes: usize = 128;

        pub const Conn = struct {
            origin: *Self = undefined,
            socket: IoType.Socket = undefined,
            recv_completion: IoType.Completion = .{},
            send_completion: IoType.Completion = .{},
            buffer: [buffer_bytes]u8 = undefined,
            transfer_len: u32 = 0,
            sent_len: u32 = 0,
            mode: Mode = .echo,
            done: bool = false,
            /// The #142 header accumulates here until it parses; any
            /// payload that rode the same delivery follows it and is
            /// moved to `buffer` for the echo.
            header_buffer: [proxy_protocol.send_bytes_max]u8 = undefined,
            header_len: u32 = 0,
            header_done: bool = false,
            /// What the header announced (null: LOCAL/UNKNOWN), for the
            /// harness's identity oracles.
            announced: ?std.Io.net.IpAddress = null,

            fn armRecv(conn: *Conn) void {
                // While a header is owed, bytes land in its accumulator —
                // the payload behind it is extracted on completion.
                const target: []u8 =
                    if (conn.origin.expect_proxy_header and !conn.header_done)
                        conn.header_buffer[conn.header_len..]
                    else
                        conn.buffer[0..];
                conn.origin.io.recv(
                    conn.socket,
                    target,
                    &conn.recv_completion,
                    Conn,
                    conn,
                    onRecv,
                );
            }

            fn onRecv(conn: *Conn, result: Io.RecvError!u32) void {
                const io = conn.origin.io;
                const received = result catch {
                    io.closeNow(conn.socket);
                    conn.done = true;
                    return;
                };
                assert(received >= 1);
                switch (conn.mode) {
                    .echo => {
                        if (conn.origin.expect_proxy_header and !conn.header_done) {
                            conn.feedProxyHeader(received);
                            return;
                        }
                        conn.transfer_len = received;
                        conn.sent_len = 0;
                        conn.armSend();
                    },
                    .reset_on_first_chunk => {
                        // As the L7 origin double: an injected set-option
                        // fault (§9) is a process-wide one-shot and can be
                        // claimed here instead of by the server. A
                        // graceful close in place of the RST is a shape
                        // this origin already produces, so the byte-level
                        // oracles are unaffected.
                        io.setLingerRst(conn.socket) catch {};
                        io.closeNow(conn.socket);
                        conn.done = true;
                    },
                    .mute => conn.armRecv(),
                    .frozen => unreachable,
                }
            }

            /// Accumulate and judge the #142 header. Monotonic verdicts
            /// make the re-parse sound; a buffer that fills without one
            /// is a violation too, since zoxy's own writers top out at
            /// 104 bytes and anything longer was never a sent header.
            fn feedProxyHeader(conn: *Conn, received: u32) void {
                const origin = conn.origin;
                assert(origin.expect_proxy_header);
                assert(!conn.header_done);
                conn.header_len += received;
                assert(conn.header_len <= conn.header_buffer.len);
                switch (proxy_protocol.parse(conn.header_buffer[0..conn.header_len])) {
                    .need_more => {
                        if (conn.header_len == conn.header_buffer.len) {
                            conn.witnessHeaderViolation();
                            return;
                        }
                        conn.armRecv();
                    },
                    .invalid => conn.witnessHeaderViolation(),
                    .ok => |header| {
                        conn.header_done = true;
                        conn.announced = header.client;
                        origin.proxy_header_conns += 1;
                        const leftover_len = conn.header_len - header.bytes_len;
                        if (leftover_len >= 1) {
                            // Payload rode the same delivery: echo it
                            // like any chunk, from the echo buffer.
                            assert(leftover_len <= buffer_bytes);
                            std.mem.copyForwards(
                                u8,
                                conn.buffer[0..leftover_len],
                                conn.header_buffer[header.bytes_len..conn.header_len],
                            );
                            conn.transfer_len = leftover_len;
                            conn.sent_len = 0;
                            conn.armSend();
                            return;
                        }
                        conn.armRecv();
                    },
                }
            }

            fn witnessHeaderViolation(conn: *Conn) void {
                conn.origin.proxy_header_violations += 1;
                conn.origin.io.closeNow(conn.socket);
                conn.done = true;
            }

            fn armSend(conn: *Conn) void {
                assert(conn.mode == .echo);
                assert(conn.sent_len < conn.transfer_len);
                conn.origin.io.send(
                    conn.socket,
                    conn.buffer[conn.sent_len..conn.transfer_len],
                    &conn.send_completion,
                    Conn,
                    conn,
                    onSend,
                );
            }

            fn onSend(conn: *Conn, result: Io.SendError!u32) void {
                const sent = result catch {
                    conn.origin.io.closeNow(conn.socket);
                    conn.done = true;
                    return;
                };
                conn.sent_len += sent;
                assert(conn.sent_len <= conn.transfer_len);
                if (conn.sent_len < conn.transfer_len) {
                    conn.armSend();
                } else {
                    conn.armRecv();
                }
            }
        };

        pub fn start(origin: *Self, io: *IoType, address: std.Io.net.IpAddress) !void {
            origin.io = io;
            origin.listener = try io.listen(address);
            origin.listening = true;
            origin.armAccept();
        }

        fn armAccept(origin: *Self) void {
            origin.io.accept(origin.listener, &origin.accept_completion, Self, origin, onAccept);
        }

        fn onAccept(origin: *Self, result: Io.AcceptError!IoType.Socket) void {
            const socket = result catch |err| {
                assert(err == error.Canceled);
                return;
            };
            assert(origin.conns_count < origin.conns.len);
            const conn = &origin.conns[origin.conns_count];
            origin.conns_count += 1;
            conn.origin = origin;
            conn.socket = socket;
            conn.mode = if (origin.mode_selector) |select|
                select(origin.context)
            else
                origin.mode;
            if (conn.mode != .frozen) {
                conn.armRecv();
            }
            if (origin.on_accept) |hook| {
                hook(origin.context);
            }
            origin.armAccept();
        }

        pub fn stopListening(origin: *Self) void {
            if (origin.listening) {
                origin.io.listenClose(origin.listener);
                origin.listening = false;
            }
        }

        /// Close any connection still open at scenario end so the socket
        /// leak check is exact.
        pub fn closeRemaining(origin: *Self) void {
            for (origin.conns[0..origin.conns_count]) |*conn| {
                if (!conn.done) {
                    origin.io.closeNow(conn.socket);
                    conn.done = true;
                }
            }
        }
    };
}
