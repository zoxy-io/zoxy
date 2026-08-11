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

const constants = @import("../constants.zig");
const parser = @import("../http/parser.zig");
const ztls = @import("ztls");

const assert = std.debug.assert;

/// What a client captures from one session and offers on the next.
/// Re-exported because ztls may not be named outside `src/tls/` (§4), and
/// a gate driving a resumption needs to hold one between two clients.
pub const SessionTicket = ztls.ClientHandshake.SessionTicket;

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
        cancel_completion: IoType.Completion,
        recv_completion: IoType.Completion,
        send_completion: IoType.Completion,
        recv_buffer: [4096]u8,
        /// Ciphertext still to write. Points into the handshake's own
        /// buffers, so it is fully written before the next engine call.
        pending_send: []const u8,
        /// Whether `socket` holds a real one. A refused dial never assigns
        /// it, so this is what stops `finish` closing a socket that does
        /// not exist.
        connected: bool,
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
        /// How this client knows the peer has answered what it last sent
        /// (`Options.exchange_end`), the payload to send once it has, and
        /// whether that one has gone.
        exchange_end: ExchangeEnd,
        followup_data: []const u8,
        followup_sent: bool,
        /// How many application payloads have gone out. The
        /// `http_response` rule counts responses against this, so a second
        /// request waits for the first response rather than for any
        /// response.
        payloads_sent: u32,
        coalesced: [2048]u8,
        coalesced_len: u32,
        app_received: [65536]u8,
        app_received_len: u32,
        /// The first NewSessionTicket this session was issued, kept so a
        /// second session can offer it back — which is the only way to
        /// test that the server's `psk_lookup` opens what it sealed.
        /// Meaningless until `ticket_captured`; a server that issues none
        /// leaves it so, and that is itself an assertable fact.
        ticket: ztls.ClientHandshake.SessionTicket,
        ticket_captured: bool,
        /// A ticket to offer at the *next* handshake, from `Options`.
        /// Borrowed from whoever captured it — normally an earlier
        /// client whose storage outlives this one.
        resume_with: ?*const ztls.ClientHandshake.SessionTicket,
        /// Runs once the client is done — how a scenario learns to wind
        /// down (drain the server, stop the origin).
        on_end: ?*const fn (ctx: ?*anyopaque) void = null,
        on_end_context: ?*anyopaque = null,

        const Self = @This();

        /// How a client decides its peer has answered — the gate every
        /// "send the next thing" step sits behind.
        pub const ExchangeEnd = enum {
            /// As many bytes back as went out. An echo's shape, and sound
            /// only where the peer returns exactly what it got: an L4
            /// relay to the echo origin, which is what this client was
            /// first written for and so what it still defaults to.
            echo,
            /// A complete HTTP/1.1 response per payload sent. What a
            /// proxied session needs and a byte count cannot give it: a
            /// response is not the length of its request, so waiting for
            /// one by size either fires early or never fires at all.
            http_response,
        };

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
            /// What counts as the peer having answered. Every gate below
            /// asks this — the KeyUpdate's ordering, the two echo-shaped
            /// closes, and `followup_data`.
            exchange_end: ExchangeEnd = .echo,
            /// A second payload, sent on the same session once the first
            /// exchange completes. This is the keep-alive turnaround: one
            /// connection, two requests, the L7 state re-entered between
            /// them. Needs `exchange_end = .http_response`, since a byte
            /// count cannot tell one response from two.
            followup_data: []const u8 = &.{},
            /// Offer this ticket in the ClientHello, resuming the session
            /// that issued it instead of running a full handshake. The
            /// storage is the caller's and must outlive the client.
            resume_with: ?*const ztls.ClientHandshake.SessionTicket = null,
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
            checkOptions(&options);
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
            client.cancel_completion = .{};
            client.connected = false;
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
            client.exchange_end = options.exchange_end;
            client.followup_data = options.followup_data;
            client.followup_sent = false;
            client.payloads_sent = 0;
            client.coalesced_len = 0;
            client.app_received_len = 0;
            client.ticket = .{};
            client.ticket_captured = false;
            client.resume_with = options.resume_with;
            io.connect(address, &client.connect_completion, Self, client, onConnect);
        }

        /// The `Options` combinations that are not merely unusual but
        /// contradictory, checked where they are cheapest to explain.
        fn checkOptions(options: *const Options) void {
            // A follow-up is gated on the peer having answered, and under
            // the echo rule that answer is "as many bytes back as went
            // out" — which two payloads and two responses cannot tell
            // apart, so the follow-up would go before the first response.
            assert(options.followup_data.len == 0 or
                options.exchange_end == .http_response);
            // The KeyUpdate and both echo-shaped closes hang off that same
            // gate and their steps run first, so combining any of them
            // with a follow-up does not suppress it — it *delays* it
            // behind an unscripted resend of `app_data`. Three requests in
            // an order nobody chose is worse than either alone, which is
            // why these are refused rather than ordered.
            assert(options.followup_data.len == 0 or !options.key_update);
            assert(options.followup_data.len == 0 or
                (!options.close_with_data and !options.close_after_echo));
            // A response's framing is read from its own headers, and HEAD
            // is the one method whose response contradicts them: a
            // Content-Length with no body behind it. A scripted HEAD would
            // make the client take the *next* response's opening bytes for
            // this one's body and mis-frame everything after, so it is
            // refused here rather than special-cased there.
            if (options.exchange_end == .http_response) {
                assert(!std.mem.startsWith(u8, options.app_data, "HEAD "));
                assert(!std.mem.startsWith(u8, options.followup_data, "HEAD "));
            }
        }

        fn onConnect(client: *Self, result: anyerror!IoType.Socket) void {
            client.socket = result catch {
                // Refused, unreachable, or the cancel above landing: no
                // socket was ever assigned, so `finish` must not close one.
                client.finish();
                return;
            };
            client.connected = true;
            // A ticket in hand means offer it: the ClientHello carries a
            // pre_shared_key extension and the server either opens it
            // (resumed) or ignores it (full handshake). Both are legal
            // outcomes of the same call, which is why the test asserts on
            // the server's counters rather than on this succeeding.
            client.pending_send = if (client.resume_with) |ticket|
                client.hs.startWithPsk(ticket, &client.out.buffer, false) catch {
                    client.finish();
                    return;
                }
            else
                client.hs.start(&client.out.buffer) catch {
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
            if (client.nextDataStep()) return;
            if (client.nextCloseStep()) return;
            if (client.saw_close) {
                client.finish();
                return;
            }
            client.armRecv();
        }

        /// The steps that put application data on the wire, in the order
        /// they may fire. True means one did and has armed its write; the
        /// caller must not fall through to another.
        fn nextDataStep(client: *Self) bool {
            // Strictly after the first echo: see `Options.key_update`.
            if (client.handshake_done and client.key_update_wanted and
                !client.key_update_sent and client.app_sent and
                client.exchangeComplete())
            {
                client.key_update_sent = true;
                client.sendKeyUpdate();
                return true;
            }
            // The second payload: its echo is what arrives while the
            // KeyUpdate response is still staged.
            if (client.key_update_sent and !client.app_resent) {
                client.app_resent = true;
                client.sendPayload(client.app_to_send);
                return true;
            }
            if (client.handshake_done and !client.app_sent and
                client.app_to_send.len > 0)
            {
                client.app_sent = true;
                client.sendPayload(client.app_to_send);
                return true;
            }
            // The keep-alive turnaround: a second request on the session
            // the first was answered on, which is how the L7 state gets
            // re-entered at all. Gated on the first response being
            // *whole* — a request sent into the middle of one would make
            // the proxy's next head start mid-body, and that is this
            // client's defect, not its peer's.
            if (client.followup_data.len > 0 and !client.followup_sent and
                client.app_sent and client.exchangeComplete())
            {
                client.followup_sent = true;
                client.sendPayload(client.followup_data);
                return true;
            }
            return false;
        }

        /// The steps that end the session in protocol. Same contract as
        /// `nextDataStep`, and reached only once no data step will fire —
        /// a goodbye is the last thing a client has to say.
        fn nextCloseStep(client: *Self) bool {
            // Deliberately *not* waiting for the echo: the point is to
            // reach the server's handshake drive, not its relay.
            if (client.close_in_handshake and !client.close_sent and
                client.handshake_done)
            {
                client.close_sent = true;
                client.sendCloseNotify();
                return true;
            }
            // Both other close scenarios wait for the peer's answer, for the
            // same reason the KeyUpdate does: anything sent before it is
            // consumed by the server's handshake drive and never reaches the
            // relay. The coalesced one sends a *second* payload with the alert
            // riding the same segment, so the relay's final decrypt yields
            // plaintext and the end of the session together.
            if (client.close_with_data and !client.close_sent and
                client.app_sent and client.exchangeComplete())
            {
                client.close_sent = true;
                client.stageCoalescedClose() catch {
                    client.finish();
                    return true;
                };
                client.pending_send = client.coalesced[0..client.coalesced_len];
                client.armSend();
                return true;
            }
            if (client.close_after_echo and !client.close_sent and
                client.app_sent and client.exchangeComplete())
            {
                client.close_sent = true;
                client.sendCloseNotify();
                return true;
            }
            return false;
        }

        /// Render one application payload and write it. The three "send
        /// the next thing" steps differ only in which bytes go, so the
        /// render / `completeWrite` / arm sequence lives here once —
        /// `completeWrite` invalidates the previous record, so getting
        /// that order wrong overwrites bytes that have not left yet.
        fn sendPayload(client: *Self, bytes: []const u8) void {
            assert(bytes.len >= 1);
            assert(client.pending_send.len == 0);
            client.payloads_sent += 1;
            client.pending_send = client.hs.sendApplicationData(
                bytes,
                &client.out.buffer,
            ) catch {
                client.finish();
                return;
            };
            client.hs.completeWrite();
            client.armSend();
        }

        /// The in-band goodbye, on the same render-then-arm sequence.
        /// Both callers set `close_sent` before calling: this is the one
        /// alert a client sends, and sending it twice is a protocol
        /// violation, not a retry.
        fn sendCloseNotify(client: *Self) void {
            assert(client.close_sent);
            assert(client.pending_send.len == 0);
            client.pending_send = client.hs.sendAlert(
                .close_notify,
                &client.out.buffer,
            ) catch {
                client.finish();
                return;
            };
            client.hs.completeWrite();
            client.armSend();
        }

        fn sendKeyUpdate(client: *Self) void {
            assert(client.key_update_sent);
            assert(client.pending_send.len == 0);
            client.pending_send = client.hs.sendKeyUpdate(
                &client.out.buffer,
                .update_requested,
            ) catch {
                client.finish();
                return;
            };
            client.hs.completeWrite();
            client.armSend();
        }

        /// Whether the peer has answered everything sent so far — the gate
        /// every follow-up step sits behind. What counts as an answer is
        /// `exchange_end`'s to say, and it has to be: an echo is exactly as
        /// long as its request, and a response is nothing of the kind.
        fn exchangeComplete(client: *const Self) bool {
            assert(client.payloads_sent >= 1);
            const back = client.app_received[0..client.app_received_len];
            return switch (client.exchange_end) {
                .echo => back.len >= client.app_to_send.len,
                .http_response => completeResponses(back) >= client.payloads_sent,
            };
        }

        /// How many complete responses have come back, and how many
        /// payloads went out to earn them — the pair a scenario oracle
        /// holds against each other.
        pub fn responsesReceived(client: *const Self) u32 {
            return completeResponses(client.app_received[0..client.app_received_len]);
        }

        pub fn requestsSent(client: *const Self) u32 {
            return client.payloads_sent;
        }

        /// Render the application data and close_notify back to back into
        /// `coalesced`, so they leave in one segment and arrive in one read.
        fn stageCoalescedClose(client: *Self) !void {
            assert(client.coalesced_len == 0);
            client.payloads_sent += 1;
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
                        .new_session_ticket => |nst| {
                            // Keep the *first* only. A server issues
                            // several and they are interchangeable, so
                            // storing one keeps this a fixed-size client
                            // and makes "the ticket" unambiguous in the
                            // test that offers it back.
                            if (!client.ticket_captured) {
                                client.ticket = client.hs.deriveSessionTicket(nst) catch
                                    continue;
                                client.ticket_captured = true;
                            }
                        },
                        .key_update, .none => {},
                    }
                }
                if (client.hs.isConnected()) client.handshake_done = true;
            }
        }

        /// Idempotent: the socket closes once, and the scenario hook runs
        /// once, however many paths converge here.
        ///
        /// The `connected` guard is not defensive bookkeeping — a refused
        /// dial reaches here with `socket` never assigned, and closing that
        /// is an assert inside the seam's own socket table. Directed tests
        /// never see it because their beds run with the adversary off; a
        /// simulation that refuses a fifth of dials (§9) sees it constantly.
        fn finish(client: *Self) void {
            if (client.ended) return;
            client.ended = true;
            if (client.hs.isConnected()) client.handshake_done = true;
            if (client.connected) client.io.closeNow(client.socket);
            if (client.on_end) |hook| hook(client.on_end_context);
        }

        /// Cancel a dial that can never complete (§9's black-holed
        /// connect), so the scenario can reap this client instead of
        /// waiting on a completion the simulator will never deliver. A
        /// no-op for every other state: an already-connected client ends
        /// through its own path, and a finished one has nothing armed.
        pub fn cancelIfStuck(client: *Self) void {
            if (client.ended) return;
            if (client.connected) return;
            client.io.connectCancel(
                &client.connect_completion,
                &client.cancel_completion,
                Self,
                client,
                onConnectCanceled,
            );
        }

        fn onConnectCanceled(client: *Self) void {
            // The dial's own completion still arrives and runs `onConnect`,
            // which finishes the client; this only unsticks it.
            assert(!client.connected);
        }

        /// True once this client is done with its socket, however it got
        /// there — what a scenario asks before deciding it may wind down.
        pub fn isEnded(client: *const Self) bool {
            return client.ended;
        }

        /// The ticket this session was issued, for a later client to offer
        /// back — null when the server issued none, which is itself a
        /// legal outcome and so a question rather than an assertion. The
        /// pointer is into this client's own storage, so whoever offers it
        /// must not outlive the one that captured it.
        pub fn capturedTicket(client: *const Self) ?*const ztls.ClientHandshake.SessionTicket {
            if (!client.ticket_captured) return null;
            return &client.ticket;
        }

        pub fn deinit(client: *Self) void {
            client.hs.deinit();
        }
    };
}

/// How many complete HTTP/1.1 responses `bytes` holds, framed by
/// `src/http/parser.zig` — the wrapper §7 puts every framing and
/// strictness decision behind. Going through it rather than scanning for
/// a `Content-Length` here is what makes this client and the simulator's
/// own L7 oracle agree on what a response *is* by construction, instead
/// of by two hand-rolled scanners staying in step.
///
/// Only the two framings that end at a known offset count. The other two
/// have no answer to the question being asked, which is "may the next
/// request go yet": an until-close response is over when the connection
/// is, by which point there is no next request to send, and a chunked
/// one needs a scanner this client has no other reason to run. Both
/// therefore count as incomplete — the client stops sending and ends the
/// way it would have anyway (its peer's close, or the scenario's
/// deadline), rather than opening a request in the middle of a body.
///
/// Scanned from the front on every call rather than carried as parse
/// state: the buffer is bounded and the scan is pure, so there is no
/// cursor to resynchronise after a record arrives split.
fn completeResponses(bytes: []const u8) u32 {
    assert(bytes.len <= constants.head_buffer_bytes_max);
    var count: u32 = 0;
    var rest = bytes;
    // Bounded by the buffer: a parsed head is at least one byte, so every
    // iteration consumes some of a slice that only shrinks.
    while (rest.len > 0) {
        var storage: parser.HeaderStorage = undefined;
        // `.get`, and `checkOptions` refuses to script a HEAD so it stays
        // true — HEAD is the one method whose response framing
        // contradicts its own headers.
        const head = parser.parseResponseHead(rest, false, &storage, .get) catch break;
        assert(head.head_len >= 1);
        const body_len: u64 = switch (head.framing) {
            .content_length => |length| length,
            .none => 0,
            .chunked, .until_close => break,
        };
        if (rest.len - head.head_len < body_len) break;
        count += 1;
        rest = rest[head.head_len + body_len ..];
    }
    assert(rest.len <= bytes.len);
    return count;
}

test "framing: a sized response counts once it is whole" {
    const head = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n";
    try std.testing.expectEqual(@as(u32, 0), completeResponses(head));
    try std.testing.expectEqual(@as(u32, 0), completeResponses(head ++ "o"));
    try std.testing.expectEqual(@as(u32, 1), completeResponses(head ++ "ok"));
    // A second response starts where the first body ended, which is the
    // whole point: the keep-alive gate counts answers, not bytes.
    try std.testing.expectEqual(@as(u32, 2), completeResponses(head ++ "ok" ++ head ++ "ok"));
    // A partial head after a complete response leaves the count at one.
    try std.testing.expectEqual(@as(u32, 1), completeResponses(head ++ "ok" ++ "HTTP/1.1 20"));
}

test "framing: a response with no body of its own completes at its head" {
    // 204 carries no body whatever its headers say, and the parser says
    // so — which is the whole reason this goes through the wrapper.
    const no_content = "HTTP/1.1 204 No Content\r\n\r\n";
    try std.testing.expectEqual(@as(u32, 1), completeResponses(no_content));
    try std.testing.expectEqual(@as(u32, 2), completeResponses(no_content ++ no_content));
}

test "framing: a response with no fixed end never completes" {
    // Chunked and until-close are both legal and neither ends at an
    // offset this client can compute; counting either would let the next
    // request go out mid-body.
    const chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    try std.testing.expectEqual(@as(u32, 0), completeResponses(chunked));
    const until_close = "HTTP/1.1 200 OK\r\n\r\nbody";
    try std.testing.expectEqual(@as(u32, 0), completeResponses(until_close));
    // Nor does anything that is not a response at all — an L4 echo of the
    // request, say, which is what the other `ExchangeEnd` is for.
    try std.testing.expectEqual(@as(u32, 0), completeResponses("GET / HTTP/1.1\r\n\r\n"));
    try std.testing.expectEqual(@as(u32, 0), completeResponses(""));
}

test "framing: the length header is read however it is spelled" {
    const lower = "HTTP/1.1 200 OK\r\ncontent-length:2\r\n\r\nok";
    try std.testing.expectEqual(@as(u32, 1), completeResponses(lower));
    // A length in the *body* is not a header, so what follows the first
    // response's 23 bytes is nothing, and the count is one rather than two.
    const nested = "HTTP/1.1 200 OK\r\nContent-Length: 23\r\n\r\nContent-Length: 999\r\n\r\n";
    try std.testing.expectEqual(@as(u32, 1), completeResponses(nested));
}
