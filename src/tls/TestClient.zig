//! A scripted TLS *client* for the gates (§9): connects over an `Io`
//! backend, drives a real ztls handshake against zoxy's server engine,
//! and records how the session ended. It lives under `src/tls/` because
//! that is the only place ztls may be named (§4) — which also makes it
//! the one TLS peer the server tests and the simulator share.
//!
//! Every input is seeded, never drawn from entropy: both keyshares and
//! the client random, so a seeded run replays a byte-exact handshake
//! (the recorded rule — a random P-256 keyshare rides in the ClientHello
//! and varies the transcript the server signs).

const std = @import("std");

const ztls = @import("ztls");

const assert = std.debug.assert;

/// Generic over the Io backend so the simulator and any socket-backed
/// test drive the same client.
pub fn TestClient(comptime IoType: type) type {
    return struct {
        io: *IoType,
        hs: ztls.ClientHandshake,
        storage: ztls.RecordBuffer.Storage,
        records: ztls.RecordBuffer,
        out: ztls.ClientHandshake.OutBuffer,
        socket: IoType.Socket,
        connect_completion: IoType.Completion,
        recv_completion: IoType.Completion,
        send_completion: IoType.Completion,
        recv_buffer: [4096]u8,
        /// Ciphertext still to write. Points into the handshake's own
        /// buffers, so it is fully written before the next engine call.
        pending_send: []const u8,
        /// Set when the session established, when the peer sent
        /// close_notify, and when the client is finished with the socket.
        handshake_done: bool,
        saw_close: bool,
        ended: bool,
        /// Runs once the client is done — how a scenario learns to wind
        /// down (drain the server, stop the origin).
        on_end: ?*const fn (ctx: ?*anyopaque) void = null,
        on_end_context: ?*anyopaque = null,

        const Self = @This();

        pub const Options = struct {
            /// Must match the certificate's SAN; the fixtures use
            /// `spike.zoxy.test`.
            host_name: []const u8,
            /// Seeds for the two keyshares and the client random.
            x25519_seed: [32]u8 = @splat(0x61),
            p256_seed: [32]u8 = @splat(0x62),
            random: [32]u8 = @splat(0x63),
        };

        /// In-place init via out-pointer: `records` borrows `storage`, so
        /// the client must not be copied afterwards.
        pub fn start(
            client: *Self,
            io: *IoType,
            address: std.Io.net.IpAddress,
            options: Options,
        ) !void {
            const x25519 = try ztls.x25519.KeyPair.generateDeterministic(
                .init(options.x25519_seed),
            );
            const p256 = try ztls.p256.KeyPair.generateDeterministic(
                .init(options.p256_seed),
            );
            client.io = io;
            client.hs = .init(.{
                .keypairs = .initWithP256(x25519, p256),
                .host_name = options.host_name,
                .now_sec = 0,
                .random = .init(options.random),
                // The test fixtures are self-signed; chain anchoring is
                // not what these gates prove.
                .insecure_no_chain_anchor = true,
            });
            client.storage = .empty;
            client.records = .init(&client.storage.buffer);
            client.out = .empty;
            client.connect_completion = .{};
            client.recv_completion = .{};
            client.send_completion = .{};
            client.pending_send = &.{};
            client.handshake_done = false;
            client.saw_close = false;
            client.ended = false;
            // Cleared here, not defaulted: callers init the client into
            // `undefined` storage, so a field this never assigns would be
            // garbage. Set the hook after `start` — no callback can run
            // before the loop does.
            client.on_end = null;
            client.on_end_context = null;
            io.connect(address, &client.connect_completion, Self, client, onConnect);
        }

        fn onConnect(client: *Self, result: anyerror!IoType.Socket) void {
            client.socket = result catch {
                client.finish();
                return;
            };
            client.pending_send = client.hs.start(&client.out.buffer) catch {
                client.finish();
                return;
            };
            client.hs.completeWrite();
            client.armSend();
        }

        fn armSend(client: *Self) void {
            assert(client.pending_send.len > 0);
            client.io.send(
                client.socket,
                client.pending_send,
                &client.send_completion,
                Self,
                client,
                onSend,
            );
        }

        fn onSend(client: *Self, result: anyerror!u32) void {
            const sent = result catch {
                client.finish();
                return;
            };
            assert(sent <= client.pending_send.len);
            client.pending_send = client.pending_send[sent..];
            if (client.pending_send.len > 0) {
                client.armSend();
                return;
            }
            client.armRecv();
        }

        fn armRecv(client: *Self) void {
            client.io.recv(
                client.socket,
                &client.recv_buffer,
                &client.recv_completion,
                Self,
                client,
                onRecv,
            );
        }

        fn onRecv(client: *Self, result: anyerror!u32) void {
            const received = result catch {
                client.finish();
                return;
            };
            if (received == 0) { // Peer FIN.
                client.finish();
                return;
            }
            client.feed(client.recv_buffer[0..received]) catch {
                client.finish();
                return;
            };
            if (client.pending_send.len > 0) {
                client.armSend();
            } else if (!client.saw_close) {
                client.armRecv();
            } else {
                client.finish();
            }
        }

        fn feed(client: *Self, wire: []const u8) !void {
            var remaining = wire;
            while (remaining.len > 0) {
                const writable = client.records.writable();
                assert(writable.len > 0);
                const take = @min(writable.len, remaining.len);
                @memcpy(writable[0..take], remaining[0..take]);
                client.records.advance(take);
                remaining = remaining[take..];
                while (try client.records.next()) |record| {
                    switch (try client.hs.handleRecord(record, &client.out.buffer)) {
                        .write => |bytes| {
                            client.pending_send = bytes;
                            client.hs.completeWrite();
                        },
                        .closed => client.saw_close = true,
                        .application_data,
                        .key_update,
                        .new_session_ticket,
                        .none,
                        => {},
                    }
                }
                if (client.hs.isConnected()) client.handshake_done = true;
            }
        }

        /// Idempotent: the socket closes once, and the scenario hook runs
        /// once, however many paths converge here.
        fn finish(client: *Self) void {
            if (client.ended) return;
            client.ended = true;
            if (client.hs.isConnected()) client.handshake_done = true;
            client.io.closeNow(client.socket);
            if (client.on_end) |hook| hook(client.on_end_context);
        }

        pub fn deinit(client: *Self) void {
            client.hs.deinit();
        }
    };
}
