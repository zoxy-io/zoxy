//! One listener's QUIC endpoint (#449): the UDP socket its HTTP/3 binding
//! serves on, the datagrams in flight on it both ways, and what a datagram
//! is before a connection holds it.
//!
//! A datagram is classified before anything reads it (h3's
//! `endpoint.classify`). One whose Destination Connection ID this server
//! minted names its connection's slot — the slot's pool index is the ID's
//! first four octets, the rest random — so routing is an index and a
//! compare, not a search. A client's first Initials carry its own choice
//! of ID until it hears this side's, and those are matched against the
//! handshaking connections' originals: a scan, bounded by the pool, paid
//! only on Initials. An Initial nothing holds may start a connection;
//! under pressure it is answered with a Retry first (RFC 9000 §8.1.2), so
//! the client proves its address before a connection is spent on it. An
//! unknown version earns Version Negotiation (§6), and a short header no
//! connection holds a stateless reset (§10.3).
//!
//! Sends are the endpoint's, not the connections': a fixed set of datagram
//! buffers, each in flight at most once, and a queue of the connections
//! with something to send, served in turn one send at a time. A send is one
//! datagram, or where the kernel segments (UDP GSO) a run of a
//! connection's datagrams of one size, the last of them possibly shorter:
//! one op and one trip through the stack for a whole answer's worth. A
//! connection never holds an op, so its teardown waits on nothing here.
//!
//! One process serves one UDP port (DESIGN.md §3): without SO_REUSEPORT,
//! the kernel would hash each datagram to a process, and a connection's
//! next datagram to a sibling with no state for it.

const std = @import("std");
const h3 = @import("h3");

const Runtime = @import("../../extension.zig").Runtime;
const constants = @import("../../constants.zig");
const Io = @import("../../io/io.zig");
const Connection = @import("Connection.zig");
const crypto = @import("crypto.zig");

const quic = h3.quic;
const IpAddress = std.Io.net.IpAddress;
const ConnectionId = Connection.ConnectionId;
const assert = std.debug.assert;

/// A datagram's room on the way in: past the 1452 this side advertises as
/// `max_udp_payload_size`, so an oversized one is still read whole and
/// refused by its packet's own length, never truncated into something else.
pub const receive_bytes: u32 = 2048;

/// A Retry token: when it was minted, the ID the client first chose — the
/// one the transport parameters must repeat — and a MAC over both and the
/// address it was minted for.
const token_mac_bytes: u32 = 16;
const token_bytes_max: u32 = 4 + 1 + ConnectionId.octets_max + token_mac_bytes;

comptime {
    assert(receive_bytes > Connection.Quic.datagram_octets);
    assert(constants.h3_connection_id_bytes == 8); // Four of index, four random.
}

pub fn Endpoint(comptime runtime: Runtime) type {
    const ServerType = @import("../../Server.zig").Server(runtime);
    const ConnType = @import("../../net/Conn.zig").Conn(runtime);
    const IoType = runtime.Io;

    return struct {
        const Self = @This();
        const Driver = @import("driver.zig").Driver(runtime);

        server: *ServerType,
        /// Its place in `server.quic_endpoints`, which a connection names.
        index: u16,
        /// The listener whose binding this is: its tables and certificates.
        listener_index: u16,
        socket: IoType.UdpSocket,
        receives: [constants.quic_endpoint_receives]Receive,
        sends: [constants.quic_endpoint_sends]Send,
        /// The sends not in flight, as a stack of indexes.
        sends_free: [constants.quic_endpoint_sends]u8,
        sends_free_len: u8,
        /// Connections with a datagram to send, served in turn.
        queue_head: ?*ConnType,
        queue_tail: ?*ConnType,
        /// The keys a Retry token's MAC and a stateless reset's token are
        /// derived under: drawn at startup, held for the process's life.
        token_key: [32]u8,
        reset_key: [32]u8,
        /// The drain is over for this endpoint: its receives are cancelled
        /// and, once nothing is in flight, the socket closes.
        closing: bool,
        closed: bool,
        armed: u32,
        /// The datagrams one send may carry here: the socket's segmenting
        /// limit, capped by `quic_send_segments_max`, and one after the
        /// kernel has refused a segmented send.
        segments_max: u16,

        pub const Receive = struct {
            endpoint: *Self,
            buffer: [receive_bytes]u8,
            completion: IoType.DatagramCompletion,
            cancel: IoType.Completion,
            armed: bool,
            cancel_armed: bool,
        };

        pub const Send = struct {
            endpoint: *Self,
            buffer: [constants.quic_send_segments_max * Connection.Quic.datagram_octets]u8,
            completion: IoType.DatagramCompletion,
            peer: IpAddress,
            /// The datagram size a segmented send was cut at, or zero.
            segment: u16,
            armed: bool,
        };

        /// What the budget prices per endpoint: its datagram buffers and
        /// their ops, laid out once.
        pub const bytes: u64 = @sizeOf(Self);

        /// Bind and begin receiving. In place: every op points into it.
        pub fn open(endpoint: *Self, server: *ServerType, index: u16, listener_index: u16, bind: IpAddress) Io.ListenError!void {
            endpoint.socket = try server.io.udpBind(bind);
            endpoint.server = server;
            endpoint.index = index;
            endpoint.listener_index = listener_index;
            endpoint.queue_head = null;
            endpoint.queue_tail = null;
            endpoint.closing = false;
            endpoint.closed = false;
            endpoint.armed = 0;
            endpoint.segments_max = @intCast(@min(
                constants.quic_send_segments_max,
                server.io.udpSegmentsMax(endpoint.socket),
            ));
            assert(endpoint.segments_max >= 1);
            server.io.fillRandom(&endpoint.token_key);
            server.io.fillRandom(&endpoint.reset_key);
            endpoint.sends_free_len = constants.quic_endpoint_sends;
            for (&endpoint.sends, 0..) |*send, position| {
                send.endpoint = endpoint;
                send.completion = .{};
                send.segment = 0;
                send.armed = false;
                endpoint.sends_free[position] = @intCast(position);
            }
            for (&endpoint.receives) |*receive| {
                receive.endpoint = endpoint;
                receive.completion = .{};
                receive.cancel = .{};
                receive.armed = false;
                receive.cancel_armed = false;
                endpoint.armReceive(receive);
            }
            assert(endpoint.armed == constants.quic_endpoint_receives);
        }

        /// The address the endpoint is bound to, its port resolved.
        pub fn address(endpoint: *const Self) IpAddress {
            return endpoint.server.io.udpAddress(endpoint.socket);
        }

        /// The drain reached this endpoint's last connection: its receives
        /// are cancelled, and the socket closes once nothing is in flight.
        pub fn close(endpoint: *Self) void {
            if (endpoint.closing) return;
            endpoint.closing = true;
            for (&endpoint.receives) |*receive| {
                if (!receive.armed) continue;
                assert(!receive.cancel_armed);
                receive.cancel_armed = true;
                endpoint.armed += 1;
                endpoint.server.io.datagramCancel(&receive.completion, &receive.cancel, Receive, receive, onReceiveCancel);
            }
            // At least the cancels just armed are in flight, and the last of
            // whatever is closes the socket: never here, inside the call
            // that may be some op's own completion.
            assert(endpoint.armed >= 1);
        }

        fn finishClose(endpoint: *Self) void {
            assert(endpoint.closing);
            if (endpoint.closed) return;
            if (endpoint.armed != 0) return;
            endpoint.server.io.udpClose(endpoint.socket);
            endpoint.closed = true;
            endpoint.server.maybeStopAfterDrain();
        }

        // -- receiving --

        fn armReceive(endpoint: *Self, receive: *Receive) void {
            assert(!receive.armed);
            assert(!endpoint.closing);
            receive.armed = true;
            endpoint.armed += 1;
            endpoint.server.io.recvFrom(endpoint.socket, &receive.buffer, &receive.completion, Receive, receive, onReceive);
        }

        fn onReceive(receive: *Receive, result: Io.RecvFromError!Io.Datagram) void {
            const endpoint = receive.endpoint;
            assert(receive.armed);
            receive.armed = false;
            endpoint.armed -= 1;
            if (endpoint.closing) return endpoint.finishClose();
            const datagram = result catch |err| {
                assert(err != error.Canceled); // Only a close cancels.
                endpoint.server.witnessKernelPressure(.recv, err);
                return endpoint.armReceive(receive);
            };
            assert(datagram.len <= receive.buffer.len);
            // A zero-length datagram carries no packet.
            if (datagram.len >= 1) endpoint.dispatch(receive.buffer[0..datagram.len], &datagram.peer);
            // The datagram may have ended the last connection of a drain.
            if (endpoint.closing) return endpoint.finishClose();
            endpoint.armReceive(receive);
        }

        fn onReceiveCancel(receive: *Receive) void {
            const endpoint = receive.endpoint;
            assert(receive.cancel_armed);
            receive.cancel_armed = false;
            endpoint.armed -= 1;
            endpoint.finishClose();
        }

        /// RFC 9000 §5.2: what a datagram is, and who holds it.
        fn dispatch(endpoint: *Self, datagram: []u8, peer: *const IpAddress) void {
            const server = endpoint.server;
            const classified = quic.endpoint.classify(datagram, constants.h3_connection_id_bytes);
            switch (classified.action) {
                .drop => server.counters.increment("h3_datagrams_dropped"),
                .version_negotiation => endpoint.negotiateVersion(&classified, peer),
                .route => {
                    const conn = endpoint.find(&classified.destination) orelse
                        return endpoint.statelessReset(datagram, &classified, peer);
                    endpoint.deliver(conn, datagram, peer);
                },
                .initial => {
                    const conn = endpoint.find(&classified.destination) orelse
                        endpoint.findOriginal(&classified.destination) orelse
                        return endpoint.admit(&classified, datagram, peer);
                    endpoint.deliver(conn, datagram, peer);
                },
            }
        }

        /// A connection this endpoint holds, by the ID it minted: the
        /// slot's index, then the whole ID compared.
        fn find(endpoint: *const Self, destination: *const ConnectionId) ?*ConnType {
            const server = endpoint.server;
            const octets = destination.bytes();
            if (octets.len != constants.h3_connection_id_bytes) return null;
            const index = std.mem.readInt(u32, octets[0..4], .big);
            if (index >= server.h3_owners.len) return null;
            const conn = server.h3_owners[index] orelse return null;
            const slot = conn.h3.?;
            assert(server.h3_slots.indexOf(slot) == index);
            if (slot.endpoint_index != endpoint.index) return null;
            if (!slot.local.eql(destination)) return null;
            return conn;
        }

        /// A handshaking connection by the ID its client first chose: a
        /// retransmitted first Initial, which still carries it.
        fn findOriginal(endpoint: *const Self, destination: *const ConnectionId) ?*ConnType {
            for (endpoint.server.h3_owners) |owner| {
                const conn = owner orelse continue;
                const slot = conn.h3.?;
                if (slot.endpoint_index != endpoint.index) continue;
                if (slot.quic.state != .handshaking) continue;
                if (slot.original.eql(destination)) return conn;
            }
            return null;
        }

        /// A connection's datagram, from the address it began from. One
        /// from anywhere else is dropped: this side advertises
        /// `disable_active_migration`, and validating a rebound path is a
        /// later slice (RFC 9000 §9 allows the drop).
        fn deliver(endpoint: *Self, conn: *ConnType, datagram: []u8, peer: *const IpAddress) void {
            const server = endpoint.server;
            const slot = conn.h3.?;
            if (!slot.peer.eql(peer)) return server.counters.increment("h3_migration_dropped");
            if (conn.state != .h3) return; // Tearing down: nothing is read.
            Driver.receive(server, conn, datagram);
        }

        /// An Initial nothing holds, from a client that may start a
        /// connection: Retried first under pressure, then admitted.
        fn admit(endpoint: *Self, classified: *const quic.endpoint.Datagram, datagram: []u8, peer: *const IpAddress) void {
            const server = endpoint.server;
            if (!classified.mayStart()) return server.counters.increment("h3_datagrams_dropped");
            if (server.draining) return server.counters.increment("h3_datagrams_dropped");
            var retried: ?Connection.Quic.Retried = null;
            if (classified.token.len >= 1) {
                const original = endpoint.validateToken(classified.token, peer) orelse
                    return server.counters.increment("h3_tokens_refused");
                retried = .{ .original_destination = original };
            } else if (server.quicUnderPressure()) {
                return endpoint.retry(classified, peer);
            }
            const conn = server.admitQuic(endpoint, &.{
                .destination = classified.destination,
                .retry = retried,
                .peer = peer.*,
            }) orelse return;
            Driver.start(server, conn, datagram);
        }

        // -- answers no connection gives --

        fn negotiateVersion(endpoint: *Self, classified: *const quic.endpoint.Datagram, peer: *const IpAddress) void {
            const send = endpoint.takeSend() orelse return endpoint.server.counters.increment("h3_datagrams_dropped");
            const octets = quic.endpoint.writeVersionNegotiation(&send.buffer, classified) catch {
                return endpoint.giveSend(send);
            };
            endpoint.server.counters.increment("h3_version_negotiations");
            endpoint.armSend(send, octets, 0, peer);
        }

        /// RFC 9000 §8.1.2: a Retry with a token the client returns in its
        /// next Initial, from a fresh ID the connection is then addressed
        /// by — which proves the client's address before a slot is spent.
        fn retry(endpoint: *Self, classified: *const quic.endpoint.Datagram, peer: *const IpAddress) void {
            const server = endpoint.server;
            const send = endpoint.takeSend() orelse return server.counters.increment("h3_datagrams_dropped");
            var token: [token_bytes_max]u8 = undefined;
            const minted = endpoint.mintToken(&token, &classified.destination, peer);
            var source_octets: [constants.h3_connection_id_bytes]u8 = undefined;
            server.io.fillRandom(&source_octets);
            const source = ConnectionId.init(&source_octets) catch unreachable; // Eight octets.
            var scratch: [Connection.Quic.datagram_octets]u8 = undefined;
            const octets = quic.endpoint.writeRetry(crypto.Backend, &send.buffer, &scratch, classified, source, minted) catch {
                // A fresh ID equal to the client's own: chance at 2^-64,
                // and answering nothing beats a Retry it must discard.
                return endpoint.giveSend(send);
            };
            server.counters.increment("h3_retries");
            endpoint.armSend(send, octets, 0, peer);
        }

        /// RFC 9000 §10.3: a short header no connection holds — one this
        /// server forgot, perhaps after a restart — answered so the client
        /// stops waiting. Always shorter than what triggered it, so two
        /// endpoints cannot loop.
        fn statelessReset(endpoint: *Self, datagram: []const u8, classified: *const quic.endpoint.Datagram, peer: *const IpAddress) void {
            const server = endpoint.server;
            if (datagram.len <= quic.endpoint.stateless_reset_octets_min) {
                return server.counters.increment("h3_datagrams_dropped");
            }
            const send = endpoint.takeSend() orelse return server.counters.increment("h3_datagrams_dropped");
            const token = endpoint.resetToken(&classified.destination);
            const length = @min(datagram.len - 1, constants.h3_stateless_reset_bytes_max);
            var unpredictable: [constants.h3_stateless_reset_bytes_max]u8 = undefined;
            server.io.fillRandom(unpredictable[0..length]);
            const octets = quic.endpoint.writeStatelessReset(send.buffer[0..length], &token, datagram.len, unpredictable[0..length]) catch {
                return endpoint.giveSend(send);
            };
            server.counters.increment("h3_stateless_resets");
            endpoint.armSend(send, octets, 0, peer);
        }

        // -- keys --

        /// RFC 9000 §10.3.2: a token a server can derive again from the ID
        /// alone, so it holds no table of them.
        pub fn resetToken(endpoint: *const Self, id: *const ConnectionId) [16]u8 {
            var mac: [32]u8 = undefined;
            crypto.Backend.hmacSha256(&mac, &endpoint.reset_key, id.bytes());
            return mac[0..16].*;
        }

        fn mintToken(endpoint: *const Self, target: *[token_bytes_max]u8, original: *const ConnectionId, peer: *const IpAddress) []const u8 {
            const issued: u32 = @truncate(endpoint.server.nowUnix());
            const octets = original.bytes();
            std.mem.writeInt(u32, target[0..4], issued, .big);
            target[4] = @intCast(octets.len);
            @memcpy(target[5..][0..octets.len], octets);
            const length = 5 + octets.len;
            const mac = endpoint.tokenMac(target[0..length], peer);
            @memcpy(target[length..][0..token_mac_bytes], &mac);
            assert(length + token_mac_bytes <= token_bytes_max);
            return target[0 .. length + token_mac_bytes];
        }

        /// The ID a Retry token vouches for, or null if it vouches for
        /// nothing: a forgery, another address's, or one past its life.
        fn validateToken(endpoint: *const Self, token: []const u8, peer: *const IpAddress) ?ConnectionId {
            if (token.len < 5 + token_mac_bytes) return null;
            const length: usize = token[4];
            if (length > ConnectionId.octets_max) return null;
            if (token.len != 5 + length + token_mac_bytes) return null;
            const expected = endpoint.tokenMac(token[0 .. 5 + length], peer);
            if (!constantTimeEql(&expected, token[5 + length ..][0..token_mac_bytes])) return null;
            const issued = std.mem.readInt(u32, token[0..4], .big);
            const now: u32 = @truncate(endpoint.server.nowUnix());
            if (now -% issued > constants.h3_retry_token_lifetime_s) return null;
            return ConnectionId.init(token[5..][0..length]) catch null;
        }

        /// HMAC-SHA-256 under the token key over the token's body and the
        /// address it is for, family included so an IPv4 address and the
        /// IPv6 one embedding it never share a token.
        fn tokenMac(endpoint: *const Self, body: []const u8, peer: *const IpAddress) [token_mac_bytes]u8 {
            var message: [token_bytes_max + 1 + 16 + 2]u8 = undefined;
            comptime assert(message.len <= crypto.Backend.hmac_message_bytes_max);
            @memcpy(message[0..body.len], body);
            var length = body.len;
            switch (peer.*) {
                .ip4 => |four| {
                    message[length] = 4;
                    @memcpy(message[length + 1 ..][0..4], &four.bytes);
                    std.mem.writeInt(u16, message[length + 5 ..][0..2], four.port, .big);
                    length += 7;
                },
                .ip6 => |six| {
                    message[length] = 6;
                    @memcpy(message[length + 1 ..][0..16], &six.bytes);
                    std.mem.writeInt(u16, message[length + 17 ..][0..2], six.port, .big);
                    length += 19;
                },
            }
            var mac: [32]u8 = undefined;
            crypto.Backend.hmacSha256(&mac, &endpoint.token_key, message[0..length]);
            return mac[0..token_mac_bytes].*;
        }

        // -- sending --

        /// `conn` has a datagram to send: queued once, and the queue served.
        pub fn queue(server: *ServerType, conn: *ConnType) void {
            const slot = conn.h3.?;
            const endpoint = &server.quic_endpoints[slot.endpoint_index];
            if (!conn.quic_send_queued) endpoint.append(conn);
            endpoint.pump();
        }

        fn append(endpoint: *Self, conn: *ConnType) void {
            assert(!conn.quic_send_queued);
            conn.quic_send_queued = true;
            conn.quic_send_next = null;
            if (endpoint.queue_tail) |tail| tail.quic_send_next = conn else endpoint.queue_head = conn;
            endpoint.queue_tail = conn;
        }

        /// `conn` is going: out of the queue, if it was in it.
        pub fn forget(server: *ServerType, conn: *ConnType) void {
            if (!conn.quic_send_queued) return;
            const endpoint = &server.quic_endpoints[conn.h3.?.endpoint_index];
            var link: *?*ConnType = &endpoint.queue_head;
            var previous: ?*ConnType = null;
            var visited: u32 = 0;
            while (link.*) |current| : (link = &current.quic_send_next) {
                assert(visited < server.h3_owners.len);
                visited += 1;
                if (current == conn) {
                    link.* = conn.quic_send_next;
                    if (endpoint.queue_tail == conn) endpoint.queue_tail = previous;
                    conn.quic_send_next = null;
                    conn.quic_send_queued = false;
                    return;
                }
                previous = current;
            }
            unreachable; // Queued is on the queue.
        }

        /// One datagram per queued connection in turn, while a buffer is
        /// free: a connection with more goes to the back.
        fn pump(endpoint: *Self) void {
            const server = endpoint.server;
            var rounds: u32 = 0;
            while (endpoint.queue_head) |conn| : (rounds += 1) {
                assert(rounds <= constants.quic_endpoint_sends * server.h3_owners.len + 1);
                const send = endpoint.takeSend() orelse return; // `onSent` resumes.
                endpoint.dequeue(conn);
                const slot = conn.h3.?;
                const now_ns = server.io.nowNs();
                const datagram_octets = Connection.Quic.datagram_octets;
                // A buffer of `datagram_octets` is the one `send` asks for.
                const first = slot.quic.send(send.buffer[0..datagram_octets], now_ns) catch unreachable;
                // A send moves the transport's timers: loss detection arms
                // as a packet leaves, and the closing period starts.
                defer Driver.sent(server, conn);
                // Nothing to send after all — congestion or the amplification
                // limit holds it — is not queued again in this turn: the
                // connection's next pass queues it once something moves.
                if (first == 0) {
                    endpoint.giveSend(send);
                    continue;
                }
                // Behind a full-size first datagram, the connection's next
                // ones join it while they are the same size: the kernel cuts
                // them apart (UDP GSO), and only the last may be shorter, so
                // a shorter one ends the run. Only behind a full-size one,
                // because a datagram once built is sealed and numbered, and
                // one longer than the first could neither join nor be put
                // back — none is longer than the connection's limit.
                var octets: usize = first;
                var count: u32 = 1;
                if (endpoint.segments_max > 1 and first == slot.quic.datagramLimit()) {
                    while (count < endpoint.segments_max and slot.quic.wantsSend()) {
                        const next = slot.quic.send(send.buffer[octets..][0..datagram_octets], now_ns) catch unreachable;
                        if (next == 0) break;
                        assert(next <= first);
                        octets += next;
                        count += 1;
                        if (next < first) break;
                    }
                }
                const segment: u16 = if (count > 1) @intCast(first) else 0;
                endpoint.armSend(send, octets, segment, &slot.peer);
                if (conn.state != .h3) continue;
                if (slot.quic.wantsSend()) endpoint.append(conn);
            }
        }

        fn dequeue(endpoint: *Self, conn: *ConnType) void {
            assert(endpoint.queue_head == conn);
            assert(conn.quic_send_queued);
            endpoint.queue_head = conn.quic_send_next;
            if (endpoint.queue_tail == conn) endpoint.queue_tail = null;
            conn.quic_send_next = null;
            conn.quic_send_queued = false;
        }

        fn takeSend(endpoint: *Self) ?*Send {
            if (endpoint.sends_free_len == 0) return null;
            endpoint.sends_free_len -= 1;
            const send = &endpoint.sends[endpoint.sends_free[endpoint.sends_free_len]];
            assert(!send.armed);
            return send;
        }

        fn giveSend(endpoint: *Self, send: *Send) void {
            assert(!send.armed);
            assert(endpoint.sends_free_len < constants.quic_endpoint_sends);
            const index = (@intFromPtr(send) - @intFromPtr(&endpoint.sends)) / @sizeOf(Send);
            endpoint.sends_free[endpoint.sends_free_len] = @intCast(index);
            endpoint.sends_free_len += 1;
        }

        fn armSend(endpoint: *Self, send: *Send, octets: usize, segment: u16, peer: *const IpAddress) void {
            assert(octets >= 1);
            assert(octets <= send.buffer.len);
            assert(segment == 0 or octets > segment);
            send.peer = peer.*;
            send.segment = segment;
            send.armed = true;
            endpoint.armed += 1;
            endpoint.server.io.sendTo(endpoint.socket, send.buffer[0..octets], segment, &send.peer, &send.completion, Send, send, onSent);
        }

        fn onSent(send: *Send, result: Io.SendToError!u32) void {
            const endpoint = send.endpoint;
            assert(send.armed);
            send.armed = false;
            endpoint.armed -= 1;
            endpoint.giveSend(send);
            // A datagram the kernel would not take is a packet lost, which
            // the transport's loss detection already answers for. A
            // segmented send refused is the kernel or the device saying it
            // cannot segment at all: every send after it carries one.
            _ = result catch |err| switch (err) {
                error.Unsupported => if (send.segment != 0 and endpoint.segments_max > 1) {
                    endpoint.segments_max = 1;
                    endpoint.server.counters.increment("h3_segments_refused");
                },
                else => endpoint.server.witnessKernelPressure(.send, err),
            };
            if (endpoint.closing) return endpoint.finishClose();
            endpoint.pump();
        }
    };
}

/// Equal without saying where they differ: a token compared a byte at a
/// time leaks how much of a forgery was right.
fn constantTimeEql(a: *const [token_mac_bytes]u8, b: *const [token_mac_bytes]u8) bool {
    var difference: u8 = 0;
    for (a, b) |left, right| difference |= left ^ right;
    return difference == 0;
}

test "h3 endpoint: a MAC compare is all or nothing" {
    const a: [token_mac_bytes]u8 = @splat(7);
    var b: [token_mac_bytes]u8 = @splat(7);
    try std.testing.expect(constantTimeEql(&a, &b));
    b[token_mac_bytes - 1] = 8;
    try std.testing.expect(!constantTimeEql(&a, &b));
}
