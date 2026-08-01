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

            fn armRecv(conn: *Conn) void {
                conn.origin.io.recv(
                    conn.socket,
                    &conn.buffer,
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
