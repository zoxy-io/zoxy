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
        /// Application data to send once the handshake completes, and the
        /// decrypted bytes that came back — how a test asserts the proxy
        /// carried plaintext end to end.
        app_to_send: []const u8,
        app_sent: bool,
        /// Whether the scenario asks for a post-handshake KeyUpdate, and
        /// whether it has gone out (see `Options.key_update`).
        key_update_wanted: bool,
        key_update_sent: bool,
        /// Whether the second payload (after the KeyUpdate) has gone.
        app_resent: bool,
        /// Whether the scenario asks the client to close in protocol once
        /// its echo is back, and whether that alert has gone out.
        close_after_echo: bool,
        close_sent: bool,
        /// Whether the close rides the data write (`close_with_data`), and
        /// the scratch that makes that one write: `hs` renders each record
        /// into the shared out buffer and `completeWrite` invalidates the
        /// previous one, so two records in one segment must be copied out
        /// as they are produced.
        close_with_data: bool,
        close_in_handshake: bool,
        coalesced: [2048]u8,
        coalesced_len: u32,
        app_received: [65536]u8,
        app_received_len: u32,
        /// Runs once the client is done — how a scenario learns to wind
        /// down (drain the server, stop the origin).
        on_end: ?*const fn (ctx: ?*anyopaque) void = null,
        on_end_context: ?*anyopaque = null,

        const Self = @This();

        pub const Options = struct {
            /// Must match the certificate's SAN; the fixtures use
            /// `spike.zoxy.test`.
            host_name: []const u8,
            /// Application data to send once the session is up; empty
            /// means the client only handshakes.
            app_data: []const u8 = &.{},
            /// Drive a post-handshake KeyUpdate(update_requested), then a
            /// second copy of `app_data`, once the *first* echo is back.
            ///
            /// The ordering is the whole point. A KeyUpdate sent the
            /// instant the session comes up is consumed by the server's
            /// handshake drive, which drains the outbox itself — the relay
            /// never sees it. Waiting for the first echo proves the relay
            /// is running, so the response is staged by the
            /// `client → upstream` step into an outbox only the
            /// `upstream → client` step drains; the second echo then
            /// arrives with that response still staged. That is the
            /// shared-outbox interleaving the staging-room guard exists
            /// for, and an emptiness precondition there is unsound.
            key_update: bool = false,
            /// The three `close_*` options below are mutually exclusive:
            /// they share `close_sent`, and `nextStep` checks them in a
            /// fixed order, so combining them would let the earliest one
            /// silently consume the close and the others never fire.
            ///
            /// Send close_notify once the echo is back, instead of waiting
            /// for the peer to close. That is a client saying "no more
            /// application data from me" *in protocol* — an EOF the proxy
            /// can only learn from a decrypt, never from a socket, since the
            /// TCP connection stays open for the other direction (§6).
            close_after_echo: bool = false,
            /// Send the application data and close_notify as one write, the
            /// way a client that calls write() then shutdown() does. The
            /// proxy then decrypts both out of a single read, so its final
            /// chunk is non-empty *and* the session has ended — the case an
            /// "empty decrypt means goodbye" rule misses entirely.
            close_with_data: bool = false,
            /// Close in protocol *immediately*, without waiting for the
            /// echo — so the alert rides the same flight as the client's
            /// Finished and reaches the server's handshake drive rather
            /// than its relay. A peer is free to do this, and the drive
            /// runs its sinks synchronously inside `feed`, so the session
            /// can end underneath the step that is still driving it.
            close_in_handshake: bool = false,
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
            client.app_to_send = options.app_data;
            client.app_sent = false;
            client.key_update_wanted = options.key_update;
            client.key_update_sent = false;
            client.app_resent = false;
            client.close_after_echo = options.close_after_echo;
            client.close_sent = false;
            client.close_with_data = options.close_with_data;
            client.close_in_handshake = options.close_in_handshake;
            client.coalesced_len = 0;
            client.app_received_len = 0;
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
            client.nextStep();
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
            client.nextStep();
        }

        /// What to do once nothing is left to write: send the scripted
        /// application data if the session is up and it has not gone yet,
        /// otherwise keep reading until the peer closes. Reached from both
        /// completion paths — after the Finished flight is written as well
        /// as after a record arrives — because the server has nothing to
        /// say until the client speaks, so waiting on a recv would hang.
        fn nextStep(client: *Self) void {
            if (client.pending_send.len > 0) {
                client.armSend();
                return;
            }
            // Strictly after the first echo: see `Options.key_update`.
            if (client.handshake_done and client.key_update_wanted and
                !client.key_update_sent and client.app_sent and
                client.app_received_len >= client.app_to_send.len)
            {
                client.key_update_sent = true;
                client.pending_send = client.hs.sendKeyUpdate(
                    &client.out.buffer,
                    .update_requested,
                ) catch {
                    client.finish();
                    return;
                };
                client.hs.completeWrite();
                client.armSend();
                return;
            }
            // The second payload: its echo is what arrives while the
            // KeyUpdate response is still staged.
            if (client.key_update_sent and !client.app_resent) {
                client.app_resent = true;
                client.pending_send = client.hs.sendApplicationData(
                    client.app_to_send,
                    &client.out.buffer,
                ) catch {
                    client.finish();
                    return;
                };
                client.hs.completeWrite();
                client.armSend();
                return;
            }
            if (client.handshake_done and !client.app_sent and
                client.app_to_send.len > 0)
            {
                client.app_sent = true;
                client.pending_send = client.hs.sendApplicationData(
                    client.app_to_send,
                    &client.out.buffer,
                ) catch {
                    client.finish();
                    return;
                };
                client.hs.completeWrite();
                client.armSend();
                return;
            }
            // Deliberately *not* waiting for the echo: the point is to
            // reach the server's handshake drive, not its relay.
            if (client.close_in_handshake and !client.close_sent and
                client.handshake_done)
            {
                client.close_sent = true;
                client.pending_send = client.hs.sendAlert(
                    .close_notify,
                    &client.out.buffer,
                ) catch {
                    client.finish();
                    return;
                };
                client.hs.completeWrite();
                client.armSend();
                return;
            }
            // Both other close scenarios wait for the first echo, for the same
            // reason the KeyUpdate does: anything sent before it is consumed
            // by the server's handshake drive and never reaches the relay.
            // The coalesced one sends a *second* payload with the alert
            // riding the same segment, so the relay's final decrypt yields
            // plaintext and the end of the session together.
            if (client.close_with_data and !client.close_sent and
                client.app_sent and
                client.app_received_len >= client.app_to_send.len)
            {
                client.close_sent = true;
                client.stageCoalescedClose() catch {
                    client.finish();
                    return;
                };
                client.pending_send = client.coalesced[0..client.coalesced_len];
                client.armSend();
                return;
            }
            if (client.close_after_echo and !client.close_sent and
                client.app_sent and
                client.app_received_len >= client.app_to_send.len)
            {
                client.close_sent = true;
                client.pending_send = client.hs.sendAlert(
                    .close_notify,
                    &client.out.buffer,
                ) catch {
                    client.finish();
                    return;
                };
                client.hs.completeWrite();
                client.armSend();
                return;
            }
            if (client.saw_close) {
                client.finish();
                return;
            }
            client.armRecv();
        }

        /// Render the application data and close_notify back to back into
        /// `coalesced`, so they leave in one segment and arrive in one read.
        fn stageCoalescedClose(client: *Self) !void {
            assert(client.coalesced_len == 0);
            const data = try client.hs.sendApplicationData(
                client.app_to_send,
                &client.out.buffer,
            );
            assert(data.len >= 1);
            assert(data.len <= client.coalesced.len);
            @memcpy(client.coalesced[0..data.len], data);
            client.coalesced_len = @intCast(data.len);
            client.hs.completeWrite();

            const alert = try client.hs.sendAlert(.close_notify, &client.out.buffer);
            assert(alert.len >= 1);
            assert(client.coalesced_len + alert.len <= client.coalesced.len);
            @memcpy(client.coalesced[client.coalesced_len..][0..alert.len], alert);
            client.coalesced_len += @intCast(alert.len);
            client.hs.completeWrite();
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
                        .application_data => |bytes| {
                            assert(client.app_received_len + bytes.len <=
                                client.app_received.len);
                            @memcpy(
                                client.app_received[client.app_received_len..][0..bytes.len],
                                bytes,
                            );
                            client.app_received_len += @intCast(bytes.len);
                        },
                        .key_update, .new_session_ticket, .none => {},
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
