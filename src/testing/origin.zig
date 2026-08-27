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
const client_hello = @import("../net/client_hello.zig");
const constants = @import("../constants.zig");

const assert = std.debug.assert;

/// Per-connection origin behavior.
/// The widest opening `Conn.header_buffer` must stage. A #142 header
/// tops out at `proxy_protocol.send_bytes_max`; a #298 ClientHello is
/// larger, and the tests build a minimal one, so this is sized for the
/// shapes the harness scripts rather than for the protocol's ceiling —
/// a hello that did not fit is a violation this double reports.
const origin_header_bytes_max: usize = 256;

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
        /// #298's receiving end: expect every connection to open with a
        /// ClientHello, consume it before echoing, and record the name it
        /// asked for. The property under test is what SNI routing
        /// promises the backend — that the hello reaches it *unchanged*,
        /// because this proxy read it without terminating — so an origin
        /// double that could not parse one must fail loudly.
        expect_client_hello: bool = false,
        /// Connections whose ClientHello parsed, and the name the last
        /// one carried.
        client_hello_conns: u32 = 0,
        client_hello_name: [constants.host_bytes_max]u8 = undefined,
        client_hello_name_len: u8 = 0,
        /// Connections whose header parsed. Echo-mode only: the
        /// misbehaving modes never parse — `reset_on_first_chunk` acts
        /// on the first delivery, `mute` reads without judging (its
        /// `header_len` never advances, so its recv window never
        /// shrinks), and `frozen` never reads.
        proxy_header_conns: u32 = 0,
        /// Connections whose opening bytes were not the valid opening
        /// this double was told to expect — a #142 header, or a #298
        /// ClientHello. One counter for both because the meaning is one:
        /// the harness scripted an opening and the bytes were not it,
        /// which is a violation of the test's own premise rather than a
        /// proxy behaviour under examination.
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
            /// Wide enough for either opening this double consumes: a
            /// #142 header, or a #298 ClientHello (larger, and the one
            /// that sets the size).
            header_buffer: [origin_header_bytes_max]u8 = undefined,
            header_len: u32 = 0,
            header_done: bool = false,
            /// What the header announced (null: LOCAL/UNKNOWN), for the
            /// harness's identity oracles.
            announced: ?std.Io.net.IpAddress = null,

            fn armRecv(conn: *Conn) void {
                // While a header is owed, bytes land in its accumulator —
                // the payload behind it is extracted on completion.
                const target: []u8 =
                    if ((conn.origin.expect_proxy_header or
                        conn.origin.expect_client_hello) and !conn.header_done)
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
                        if (conn.origin.expect_client_hello and !conn.header_done) {
                            conn.feedClientHello(received);
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

            /// Accumulate and judge the #298 ClientHello, then echo what
            /// rode behind it.
            ///
            /// The record's own length is re-derived here rather than
            /// returned by the parser, and that is the parser being
            /// right: nothing is consumed on the proxy's side, so `ok`
            /// carries a name and no cursor. This origin *does* need to
            /// know where the hello ended, because it is the backend and
            /// the token starts after it — a length only a consumer
            /// needs, computed by the one consumer there is.
            fn feedClientHello(conn: *Conn, received: u32) void {
                const origin = conn.origin;
                assert(origin.expect_client_hello);
                assert(!conn.header_done);
                conn.header_len += received;
                assert(conn.header_len <= conn.header_buffer.len);
                const staged = conn.header_buffer[0..conn.header_len];
                switch (client_hello.parse(staged)) {
                    .need_more => {
                        if (conn.header_len == conn.header_buffer.len) {
                            conn.witnessHeaderViolation();
                            return;
                        }
                        conn.armRecv();
                    },
                    .invalid => conn.witnessHeaderViolation(),
                    .ok => |hello| {
                        conn.header_done = true;
                        origin.client_hello_conns += 1;
                        origin.client_hello_name_len = 0;
                        if (hello.server_name) |name| {
                            assert(name.len <= origin.client_hello_name.len);
                            @memcpy(origin.client_hello_name[0..name.len], name);
                            origin.client_hello_name_len = @intCast(name.len);
                        }
                        // Record header plus the fragment it declared.
                        const hello_len = 5 + @as(usize, std.mem.readInt(
                            u16,
                            staged[3..5],
                            .big,
                        ));
                        assert(hello_len <= conn.header_len);
                        const leftover_len = conn.header_len - hello_len;
                        if (leftover_len >= 1) {
                            assert(leftover_len <= buffer_bytes);
                            std.mem.copyForwards(
                                u8,
                                conn.buffer[0..leftover_len],
                                conn.header_buffer[hello_len..conn.header_len],
                            );
                            conn.transfer_len = @intCast(leftover_len);
                            conn.sent_len = 0;
                            conn.armSend();
                            return;
                        }
                        conn.armRecv();
                    },
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

        /// Start on a socket path instead (#303). A simulator affordance
        /// — `SimIo.listenUnix` — because what a UDS *endpoint* needs
        /// from §9 is something on the other end of the dial, and the
        /// proxy's own `bind` is still IP-only.
        pub fn startUnix(origin: *Self, io: *IoType, path: []const u8) !void {
            origin.io = io;
            origin.listener = try io.listenUnix(path);
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
