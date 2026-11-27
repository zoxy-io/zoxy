//! An HTTP/3 client over the Io seam's datagrams (#449), for zoxy's own
//! tests and the simulator's HTTP/3 clients: one QUIC connection — h3's
//! client transport with its `std.crypto` default, and zssl's QUIC client
//! for its handshake (`QuicClient`) — a few requests sent at once when the
//! handshake confirms, and their answers kept. zoxy serves HTTP/3 and
//! never dials it, so nothing on the serving path uses this.
//!
//! Its I/O is the simplest that is correct: one receive and one send in
//! flight on its own UDP socket, and a fixed tick that fires the
//! transport's timers once due — late by up to a tick, which a probe
//! timeout or an acknowledgement delay forgives. Once every answer is in,
//! it closes the connection with H3_NO_ERROR, sends that, and lets go of
//! its socket; the server reads the close and runs its own closing period.

const std = @import("std");
const h3 = @import("h3");

const Io = @import("../../io/io.zig");
const TlsEngine = @import("../../tls/Engine.zig");
const QuicClient = @import("../../tls/QuicClient.zig");
const Connection = @import("Connection.zig");

const quic = h3.quic;
const IpAddress = std.Io.net.IpAddress;
const assert = std.debug.assert;

/// Requests one client sends.
pub const requests_max: u32 = 4;
/// An answer's body kept at most; past it the octets are counted, not kept.
pub const body_bytes_max: u32 = 4096;
/// An answer's trailer sections, as `name: value` lines, at most.
pub const trailer_bytes_max: u32 = 256;
/// Its final head's fields past the pseudo-fields, the same way.
pub const head_bytes_max: u32 = 1024;
/// A request's body at most: it goes in the same write as its head, and
/// the two fit one stream's send buffer.
pub const request_body_bytes_max: u32 = 8 * 1024;
/// Header fields one request carries beside its four pseudo-fields.
pub const request_headers_max: u32 = 8;
/// A field as h3 and HPACK alike hold one.
pub const Field = h3.qpack.Field;
/// How often the transport's timers are looked at.
const tick_ns: u64 = 2 * std.time.ns_per_ms;
/// Events one read of a stream reports at most.
const events_max: u32 = 8;

pub const ClientQuic = quic.Connection(.{
    .streams_max = 16,
    .stream_receive_octets = 16 * 1024,
    .stream_send_octets = 16 * 1024,
});
const ClientHttp3 = h3.Http3(.{ .requests_max = requests_max, .unidirectional_max = 4 });

pub const Request = struct {
    method: []const u8 = "GET",
    path: []const u8 = "/",
    authority: []const u8 = "localhost",
    /// Further fields, after the pseudo-fields.
    headers: []const Field = &.{},
    body: []const u8 = &.{},
    /// A field section sent as it is, in place of the one the fields above
    /// encode to: what a test of the server's QPACK decoder sends.
    raw_section: ?[]const u8 = null,
};

pub const Answer = struct {
    status: u16 = 0,
    body: [body_bytes_max]u8 = undefined,
    body_len: u32 = 0,
    /// The stream's FIN arrived after the answer.
    finished: bool = false,
    /// The server reset the stream instead.
    reset: bool = false,
    /// Trailer sections after the final head, each field kept as a
    /// `name: value\r\n` line in arrival order; `trailers_len` counts
    /// every octet, kept or not, as `body_len` does.
    trailer_sections: u8 = 0,
    trailers: [trailer_bytes_max]u8 = undefined,
    trailers_len: u32 = 0,
    /// The final head's fields but its pseudo-fields, as `name: value\r\n`
    /// lines; `head_len` counts every octet, kept or not.
    head: [head_bytes_max]u8 = undefined,
    head_len: u32 = 0,
    /// A trailer section that did not decode as one, pseudo-fields
    /// included: recorded, so a judge cannot mistake it for none.
    trailers_malformed: bool = false,

    pub fn bodyBytes(answer: *const Answer) []const u8 {
        return answer.body[0..@min(answer.body_len, body_bytes_max)];
    }

    pub fn trailerBytes(answer: *const Answer) []const u8 {
        return answer.trailers[0..@min(answer.trailers_len, trailer_bytes_max)];
    }

    pub fn headBytes(answer: *const Answer) []const u8 {
        return answer.head[0..@min(answer.head_len, head_bytes_max)];
    }

    /// Keeps `fields` as lines in `buffer`, as far as it reaches, and
    /// counts every octet in `len` whether kept or not.
    fn appendLines(buffer: []u8, len: *u32, fields: []const Field) void {
        assert(buffer.len >= 1);
        const before = len.*;
        var kept: u32 = 0;
        for (fields) |field| {
            if (field.name.len >= 1 and field.name[0] == ':') continue;
            kept += 1;
            inline for (.{ field.name, ": ", field.value, "\r\n" }) |bytes| {
                const start = @min(len.*, buffer.len);
                const take = @min(bytes.len, buffer.len - start);
                @memcpy(buffer[start..][0..take], bytes[0..take]);
                len.* += @intCast(bytes.len);
            }
        }
        // Every kept field is at least its separator and line end.
        assert(len.* >= before + kept * 4);
    }
};

pub fn TestClient(comptime IoType: type) type {
    return struct {
        const Self = @This();

        io: *IoType,
        socket: IoType.UdpSocket,
        server: IpAddress,
        quic: ClientQuic,
        tls: QuicClient,
        http3: ClientHttp3,
        requests: []const Request,
        answers: [requests_max]Answer,
        receive_buffer: [2048]u8,
        receive_completion: IoType.DatagramCompletion,
        receive_cancel: IoType.Completion,
        receiving: bool,
        cancel_armed: bool,
        send_buffer: [ClientQuic.datagram_octets]u8,
        send_completion: IoType.DatagramCompletion,
        sending: bool,
        timer_completion: IoType.Completion,
        timing: bool,
        decode_scratch: [4096]u8,
        decode_storage: [4096]u8,
        decode_fields: [32]h3.qpack.Field,
        requested: bool,
        /// The connection is closed and its last datagram queued: what is
        /// armed is let go of, and the socket closes once nothing is.
        closing: bool,
        done: bool,
        /// When `start` ran, and when the server closed the connection with
        /// H3_NO_ERROR while this client was not closing it itself — zero
        /// if it never did. An oracle tells the age cap's close (§6), which
        /// may cut what is in flight, from one that came too early.
        started_ns: u64,
        peer_closed_ns: u64,
        /// The server refused the connection (CONNECTION_REFUSED, RFC 9000
        /// §5.2.2) rather than leaving its Initial unanswered.
        refused: bool,
        /// Once its answers are in, stop as a client whose last datagram
        /// was lost looks to the server: nothing more sent, not even the
        /// acknowledgement of what completed them, and no close. Set after
        /// `start`.
        vanishes: bool,
        /// The identifier of the server's GOAWAY, if one arrived: what tells
        /// a refused request the client may send again from one it lost.
        goaway: ?u64,
        /// The port this client's socket bound on loopback: what the
        /// server's access log names it by.
        local_port: u16,
        on_done: *const fn (*anyopaque) void,
        context: *anyopaque,

        /// Bind, begin the handshake, and send the first flight. In place:
        /// the transport is hundreds of KiB and every op points into it.
        pub fn start(
            client: *Self,
            io: *IoType,
            server: IpAddress,
            requests: []const Request,
            seed: [64]u8,
            on_done: *const fn (*anyopaque) void,
            context: *anyopaque,
        ) !void {
            assert(requests.len >= 1);
            assert(requests.len <= requests_max);
            // Field by field: the client is hundreds of KiB, and a literal of
            // it could be built on the stack before it is copied in.
            client.io = io;
            client.socket = try io.udpBind(.{ .ip4 = .loopback(0) });
            client.local_port = io.udpAddress(client.socket).getPort();
            assert(client.local_port != 0);
            client.server = server;
            client.http3 = .init(.client);
            client.requests = requests;
            client.answers = @splat(.{});
            client.receive_completion = .{};
            client.receive_cancel = .{};
            client.receiving = false;
            client.cancel_armed = false;
            client.send_completion = .{};
            client.sending = false;
            client.timer_completion = .{};
            client.timing = false;
            client.requested = false;
            client.closing = false;
            client.done = false;
            client.started_ns = io.nowNs();
            client.peer_closed_ns = 0;
            client.refused = false;
            client.vanishes = false;
            client.goaway = null;
            client.on_done = on_done;
            client.context = context;
            // The first Destination Connection ID's length, drawn from the
            // seed across RFC 9000's whole range (§7.2: at least eight
            // octets): a server's Initial handling meets every one.
            const destination_len: usize = 8 + @as(usize, seed[63] % 13);
            assert(destination_len <= quic.ConnectionId.octets_max);
            client.quic.initInPlace(.{
                .side = .client,
                .original_destination = try .init(seed[24..][0..destination_len]),
                .source = try .init(seed[8..16]),
                // The server's three streams in; the requests and this side's
                // control stream out.
                .advertised = .{
                    .max_streams_bidirectional = 0,
                    .max_streams_unidirectional = 3,
                    .streams_opened_max = @intCast(requests.len + 1),
                },
            });
            var parameters: [ClientQuic.local_transport_parameters_octets_max]u8 = undefined;
            const sink = client.engineSink();
            try client.tls.init(&.{
                .server_name = "localhost",
                .transport_parameters = try client.quic.localTransportParameters(&parameters),
                .seed = seed,
            }, &sink);
            client.armReceive();
            client.armTimer();
            client.flush();
        }

        // -- the transport --

        fn drive(client: *Self) void {
            if (client.closing) return client.flush();
            client.pumpTls() catch return client.close();
            var polled: u32 = 0;
            while (client.quic.poll()) |event| : (polled += 1) {
                assert(polled < 4096);
                switch (event) {
                    .stream_readable => |id| client.readStream(id),
                    .stream_reset => |reset| if (reset.stream < client.requests.len * 4) {
                        client.answers[@intCast(reset.stream / 4)].reset = true;
                    },
                    .closed => |closed| {
                        client.notePeerClose(closed.code, closed.application, closed.idle);
                        return client.close();
                    },
                    else => {},
                }
            }
            if (client.quic.handshakeConfirmed() and !client.requested) client.sendRequests();
            if (client.answered()) return if (client.vanishes) client.vanish() else client.close();
            client.flush();
        }

        fn pumpTls(client: *Self) !void {
            const sink = client.engineSink();
            for ([_]quic.crypto.Level{ .initial, .handshake, .one_rtt }) |level| {
                const available = client.quic.cryptoOut(level);
                if (available.len == 0) continue;
                try client.tls.deliver(Connection.engineLevel(level), available, &sink);
                client.quic.cryptoConsumed(level, available.len);
            }
        }

        fn answered(client: *const Self) bool {
            if (!client.requested) return false;
            for (client.answers[0..client.requests.len]) |*answer| {
                if (!answer.finished and !answer.reset) return false;
            }
            return true;
        }

        /// The requests, all at once, each on the next client stream, and
        /// this side's control stream before them.
        fn sendRequests(client: *Self) void {
            assert(!client.requested);
            client.requested = true;
            var control: [64]u8 = undefined;
            const control_octets = client.http3.writeControl(&control) catch unreachable; // SETTINGS fit.
            _ = client.quic.write(quic.stream_id.make(.client_unidirectional, 0), control[0..control_octets], false) catch {};
            for (client.requests, 0..) |*request, index| {
                assert(request.headers.len <= request_headers_max);
                assert(request.body.len <= request_body_bytes_max);
                var fields: [4 + request_headers_max]Field = undefined;
                fields[0] = .{ .name = ":method", .value = request.method };
                fields[1] = .{ .name = ":scheme", .value = "https" };
                fields[2] = .{ .name = ":authority", .value = request.authority };
                fields[3] = .{ .name = ":path", .value = request.path };
                @memcpy(fields[4..][0..request.headers.len], request.headers);
                var frames: [request_body_bytes_max + 2048]u8 = undefined;
                var octets = if (request.raw_section) |section| raw: {
                    const header = h3.frame.writeHeader(&frames, .headers, section.len) catch unreachable; // A short section.
                    @memcpy(frames[header..][0..section.len], section);
                    break :raw header + section.len;
                } else client.http3.writeHeaders(&frames, fields[0 .. 4 + request.headers.len]) catch unreachable; // Short fields.
                if (request.body.len >= 1) {
                    octets += ClientHttp3.writeData(frames[octets..], request.body.len) catch unreachable;
                    @memcpy(frames[octets..][0..request.body.len], request.body);
                    octets += request.body.len;
                }
                const id = quic.stream_id.make(.client_bidirectional, @intCast(index));
                _ = client.quic.write(id, frames[0..octets], true) catch {
                    client.answers[index].reset = true;
                };
            }
        }

        fn readStream(client: *Self, id: u64) void {
            var reads: u32 = 0;
            while (reads < 64) : (reads += 1) {
                var events: [events_max]h3.http3.Event = undefined;
                const read = client.http3.receive(id, client.quic.readable(id), client.quic.readableFin(id), &events) catch {
                    return client.close();
                };
                for (events[0..read.events]) |*event| client.onEvent(event);
                if (read.consumed >= 1) client.quic.consume(id, read.consumed) catch {};
                if (read.consumed == 0 and read.events == 0) return;
            }
        }

        /// Keeps a trailer section for the caller to judge, decoded under
        /// RFC 9114 §4.3's rules for one: no pseudo-field may appear.
        fn recordTrailers(client: *Self, answer: *Answer, section: []const u8) void {
            assert(section.len <= 1 << 16);
            // Saturating: a server that sends sections without end is the
            // judge's finding, not this client's crash.
            answer.trailer_sections +|= 1;
            const decoded = h3.http3_server.decodeSection(
                section,
                .{ .kind = .trailer },
                1 << 16,
                &client.decode_scratch,
                &client.decode_storage,
                &client.decode_fields,
            ) catch {
                answer.trailers_malformed = true;
                return;
            };
            // A trailer section has no pseudo-fields to skip: the decoder
            // refused the section if it carried one.
            Answer.appendLines(&answer.trailers, &answer.trailers_len, decoded.fields);
            assert(answer.trailers_len >= decoded.fields.len * 4);
        }

        fn onEvent(client: *Self, event: *const h3.http3.Event) void {
            switch (event.*) {
                .headers => |headers| {
                    const answer = client.answerFor(headers.stream) orelse return;
                    if (headers.trailers) return client.recordTrailers(answer, headers.section);
                    const decoded = h3.http3_server.decodeSection(
                        headers.section,
                        .{ .kind = .response },
                        1 << 16,
                        &client.decode_scratch,
                        &client.decode_storage,
                        &client.decode_fields,
                    ) catch return;
                    var final = false;
                    for (decoded.fields) |field| {
                        if (!std.mem.eql(u8, field.name, ":status")) continue;
                        const status = std.fmt.parseInt(u16, field.value, 10) catch 0;
                        // An interim head (RFC 9110 §15.2) is not the answer:
                        // the final one is still to come.
                        if (status >= 200) {
                            answer.status = status;
                            final = true;
                        }
                    }
                    if (final) Answer.appendLines(&answer.head, &answer.head_len, decoded.fields);
                },
                .data => |data| {
                    const answer = client.answerFor(data.stream) orelse return;
                    const room = body_bytes_max -| answer.body_len;
                    const kept = @min(room, data.payload.len);
                    @memcpy(answer.body[answer.body_len..][0..kept], data.payload[0..kept]);
                    answer.body_len += @intCast(data.payload.len);
                },
                .finished => |id| if (client.answerFor(id)) |answer| {
                    answer.finished = true;
                },
                .settings => {},
                .goaway => |identifier| client.goaway = identifier,
            }
        }

        fn answerFor(client: *Self, id: u64) ?*Answer {
            if (!quic.stream_id.kindOf(id).bidirectional()) return null;
            const index = id / 4;
            if (index >= client.requests.len) return null;
            return &client.answers[@intCast(index)];
        }

        /// Whether the server ended the connection gracefully, observed no
        /// sooner than `age_ns_min` past this client's start.
        pub fn peerClosedGracefully(client: *const Self, age_ns_min: u64) bool {
            assert(age_ns_min >= 1);
            if (client.peer_closed_ns == 0) return false;
            assert(client.peer_closed_ns >= client.started_ns);
            return client.peer_closed_ns - client.started_ns >= age_ns_min;
        }

        fn notePeerClose(client: *Self, code: u64, application: bool, idle: bool) void {
            // Its own close, or an idle timeout, is not the server's word.
            if (client.closing or idle) return;
            if (!application and code == @backingInt(quic.error_code.Transport.connection_refused)) {
                client.refused = true;
                return;
            }
            if (!application) return;
            if (code != @backingInt(quic.error_code.Application.no_error)) return;
            assert(client.peer_closed_ns == 0);
            client.peer_closed_ns = client.io.nowNs();
            assert(client.peer_closed_ns >= client.started_ns);
        }

        /// The run is ending with this client still going: close now, and
        /// let go of the socket once the close is out.
        pub fn abandon(client: *Self) void {
            if (client.done) return;
            client.close();
        }

        /// `vanishes`: closing without a close, so nothing is sent again and
        /// the socket goes once the ops in flight are in.
        fn vanish(client: *Self) void {
            assert(client.vanishes);
            assert(!client.closing);
            client.closing = true;
            client.finishIfClosed();
        }

        fn close(client: *Self) void {
            if (!client.closing) {
                client.closing = true;
                client.quic.closeApplication(@backingInt(quic.error_code.Application.no_error));
            }
            client.flush();
        }

        // -- I/O --

        fn flush(client: *Self) void {
            if (client.sending) return;
            if (client.done) return;
            if (client.closing and client.vanishes) return client.finishIfClosed();
            const octets = client.quic.send(&client.send_buffer, client.io.nowNs()) catch 0;
            if (octets == 0) return client.finishIfClosed();
            client.sending = true;
            client.io.sendTo(client.socket, client.send_buffer[0..octets], 0, &client.server, &client.send_completion, Self, client, onSent);
        }

        fn onSent(client: *Self, result: Io.SendToError!u32) void {
            assert(client.sending);
            client.sending = false;
            _ = result catch {};
            client.flush();
        }

        fn armReceive(client: *Self) void {
            assert(!client.receiving);
            client.receiving = true;
            client.io.recvFrom(client.socket, &client.receive_buffer, &client.receive_completion, Self, client, onReceive);
        }

        fn onReceive(client: *Self, result: Io.RecvFromError!Io.Datagram) void {
            assert(client.receiving);
            client.receiving = false;
            if (client.closing) return client.finishIfClosed();
            const datagram = result catch return client.close();
            if (datagram.len >= 1) {
                client.quic.receive(client.receive_buffer[0..datagram.len], client.io.nowNs()) catch {};
            }
            client.armReceive();
            client.drive();
        }

        fn armTimer(client: *Self) void {
            assert(!client.timing);
            client.timing = true;
            client.io.timerStart(&client.timer_completion, tick_ns, Self, client, onTick);
        }

        fn onTick(client: *Self, result: Io.TimerError!void) void {
            assert(client.timing);
            client.timing = false;
            _ = result catch {};
            if (client.closing) return client.finishIfClosed();
            const now = client.io.nowNs();
            if (client.quic.timeout()) |due| {
                if (due <= now) client.quic.onTimeout(now);
            }
            client.armTimer();
            client.drive();
        }

        /// The close is sent: the receive is let go of, and the socket
        /// closes once the last op is in.
        fn finishIfClosed(client: *Self) void {
            if (!client.closing) return;
            if (client.done) return;
            if (client.sending) return;
            if (client.quic.wantsSend() and !client.vanishes) return client.flush();
            if (client.receiving) {
                if (!client.cancel_armed) {
                    client.cancel_armed = true;
                    client.io.datagramCancel(&client.receive_completion, &client.receive_cancel, Self, client, onReceiveCancel);
                }
                return;
            }
            if (client.cancel_armed) return; // Its delivery comes back here.
            if (client.timing) return; // The tick's own delivery comes back here.
            client.done = true;
            client.io.udpClose(client.socket);
            client.tls.deinit();
            client.on_done(client.context);
        }

        fn onReceiveCancel(client: *Self) void {
            assert(client.cancel_armed);
            client.cancel_armed = false;
            client.finishIfClosed();
        }

        fn engineSink(client: *Self) TlsEngine.QuicSink {
            return .{
                .ctx = &client.quic,
                .crypto = sinkCrypto,
                .secret = sinkSecret,
                .transportParameters = sinkParameters,
                .connected = sinkConnected,
            };
        }
    };
}

fn sinkCrypto(ctx: *anyopaque, level: TlsEngine.QuicLevel, bytes: []const u8) error{QuicSinkRefused}!void {
    const connection: *ClientQuic = @ptrCast(@alignCast(ctx));
    connection.cryptoIn(Connection.transportLevel(level), bytes) catch return error.QuicSinkRefused;
}

fn sinkSecret(ctx: *anyopaque, given: *const TlsEngine.QuicSecret) error{QuicSinkRefused}!void {
    const connection: *ClientQuic = @ptrCast(@alignCast(ctx));
    const held = quic.crypto.Secret.init(given.bytes) catch return error.QuicSinkRefused;
    const level = Connection.transportLevel(given.level);
    const suite = Connection.suiteOf(given.suite);
    const installed = switch (given.direction) {
        .send => connection.installSecret(level, .send, &held, suite),
        .receive => connection.installSecret(level, .receive, &held, suite),
    };
    installed catch return error.QuicSinkRefused;
}

fn sinkParameters(ctx: *anyopaque, bytes: []const u8) error{QuicSinkRefused}!void {
    const connection: *ClientQuic = @ptrCast(@alignCast(ctx));
    connection.transportParametersIn(bytes) catch return error.QuicSinkRefused;
}

/// A client's handshake is confirmed by HANDSHAKE_DONE, not its own TLS
/// stack (RFC 9001 §4.1.2).
fn sinkConnected(ctx: *anyopaque) void {
    _ = ctx;
}
