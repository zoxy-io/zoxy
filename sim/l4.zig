//! The L4 population of the deterministic-simulation gate (§9): a
//! scripted echo client with a seed-derived token, generic over the Io
//! backend and shaped like its L7 sibling (`prepare`, `begin`,
//! `cancelIfStuck`, `closeIfOpen`, an `on_ended` hook, a verify-time
//! oracle). Integrity invariant: every byte received must be a prefix of
//! the token sent — the proxy may cut a stream short, but it must never
//! corrupt or reorder it.

const std = @import("std");

const zoxy = @import("zoxy");

const Io = zoxy.Io;

const assert = std.debug.assert;

pub const token_bytes_max: u8 = 48;

/// A verify-time verdict over everything the client received.
pub const ClientError = error{
    /// A byte arrived after the full token had already been echoed.
    EchoOverrun,
    /// The echoed bytes diverged from the token's prefix.
    EchoCorrupted,
};

/// Sends the token, FINs after the full echo, and treats any terminal
/// recv as the end; silent clients connect and wait to be reaped.
pub fn Client(comptime IoType: type) type {
    return struct {
        io: *IoType = undefined,
        address: std.Io.net.IpAddress = undefined,
        on_ended: ?*const fn (?*anyopaque) void = null,
        context: ?*anyopaque = null,
        connect_completion: IoType.Completion = .{},
        connect_cancel_completion: IoType.Completion = .{},
        recv_completion: IoType.Completion = .{},
        send_completion: IoType.Completion = .{},
        token: [token_bytes_max]u8 = undefined,
        token_len: u8 = 0,
        receive_buffer: [token_bytes_max]u8 = undefined,
        /// Once the echo is complete, the recv waiting on the FIN lands
        /// here; any byte that arrives is an integrity violation.
        overrun_scratch: [1]u8 = undefined,
        overrun: bool = false,
        socket: IoType.Socket = undefined,
        silent: bool = false,
        connected: bool = false,
        connect_settled: bool = false,
        cancel_requested: bool = false,
        fin_sent: bool = false,
        closed: bool = false,
        ended: bool = false,
        send_pending: bool = false,
        recv_terminal: bool = false,
        sent_len: u32 = 0,
        received_len: u32 = 0,

        const Self = @This();

        pub fn prepare(
            client: *Self,
            io: *IoType,
            address: std.Io.net.IpAddress,
            token: []const u8,
            silent: bool,
        ) void {
            assert(token.len >= 1);
            assert(token.len <= token_bytes_max);
            client.io = io;
            client.address = address;
            client.silent = silent;
            @memcpy(client.token[0..token.len], token);
            client.token_len = @intCast(token.len);
        }

        pub fn begin(client: *Self) void {
            assert(client.token_len >= 1);
            client.io.connect(
                client.address,
                &client.connect_completion,
                Self,
                client,
                onConnect,
            );
        }

        fn onConnect(client: *Self, result: Io.ConnectError!IoType.Socket) void {
            client.connect_settled = true;
            client.socket = result catch {
                client.end();
                return;
            };
            client.connected = true;
            client.armRecv();
            if (!client.silent) {
                client.armSend();
            }
        }

        fn armSend(client: *Self) void {
            assert(client.sent_len < client.token_len);
            assert(!client.send_pending);
            client.send_pending = true;
            client.io.send(
                client.socket,
                client.token[client.sent_len..client.token_len],
                &client.send_completion,
                Self,
                client,
                onSend,
            );
        }

        fn onSend(client: *Self, result: Io.SendError!u32) void {
            assert(client.send_pending);
            client.send_pending = false;
            const sent = result catch {
                client.settleIfTerminal();
                return;
            };
            client.sent_len += sent;
            assert(client.sent_len <= client.token_len);
            if (client.recv_terminal) {
                client.settleIfTerminal();
            } else if (client.sent_len < client.token_len) {
                client.armSend();
            }
        }

        fn armRecv(client: *Self) void {
            const buffer = if (client.received_len == client.token_len)
                &client.overrun_scratch
            else
                client.receive_buffer[client.received_len..client.token_len];
            client.io.recv(
                client.socket,
                buffer,
                &client.recv_completion,
                Self,
                client,
                onRecv,
            );
        }

        fn onRecv(client: *Self, result: Io.RecvError!u32) void {
            const received = result catch {
                // The §5 rule applies to the harness too: the socket may
                // only close once the concurrent send op has also settled.
                client.recv_terminal = true;
                client.settleIfTerminal();
                return;
            };
            assert(received >= 1);
            if (client.received_len == client.token_len) {
                client.overrun = true;
            } else {
                client.received_len += received;
                assert(client.received_len <= client.token_len);
                if (client.received_len == client.token_len) {
                    if (!client.fin_sent) {
                        client.fin_sent = true;
                        client.io.shutdown(client.socket, .write);
                    }
                }
            }
            client.armRecv();
        }

        /// Scenario end: a connect the adversary black-holed must still be
        /// reaped — the same seam op the proxy itself relies on (§5).
        pub fn cancelIfStuck(client: *Self) void {
            if (client.connect_settled or client.cancel_requested) return;
            client.cancel_requested = true;
            client.io.connectCancel(
                &client.connect_completion,
                &client.connect_cancel_completion,
                Self,
                client,
                onConnectCanceled,
            );
        }

        fn onConnectCanceled(client: *Self) void {
            if (!client.connect_settled) {
                client.connect_settled = true;
                client.end();
            }
        }

        fn settleIfTerminal(client: *Self) void {
            assert(client.recv_terminal or !client.send_pending);
            if (client.recv_terminal and !client.send_pending) {
                client.closeIfOpen();
                client.end();
            }
        }

        pub fn closeIfOpen(client: *Self) void {
            if (client.connected and !client.closed) {
                client.closed = true;
                client.io.closeNow(client.socket);
            }
        }

        fn end(client: *Self) void {
            if (client.ended) return;
            client.ended = true;
            if (client.on_ended) |ended| {
                ended(client.context);
            }
        }

        pub fn verifyIntegrity(client: *const Self) ClientError!void {
            if (client.overrun) return ClientError.EchoOverrun;
            assert(client.received_len <= client.token_len);
            if (!std.mem.eql(
                u8,
                client.receive_buffer[0..client.received_len],
                client.token[0..client.received_len],
            )) {
                return ClientError.EchoCorrupted;
            }
        }
    };
}
