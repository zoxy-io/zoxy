//! The simulation gate's HTTP/2 client (#275): h2c by prior knowledge to
//! the http listener, a few GET streams opened in its first write, and an
//! oracle over every frame that came back.
//!
//! The streams ask what the HTTP/1.1 population's `get` script asks, so
//! the same origin answers them and the same canonical bodies judge them.
//! The oracle is per stream, and holds on every seed: whatever came back
//! is whole frames, each stream is answered at most once, with a status
//! the `get` script allows and — for a 200 — a canonical body, or a prefix
//! of one on a stream that was cut short. On clean seeds it hardens: every
//! stream ends with a 200 and a whole canonical body.
//!
//! The client never acknowledges the server's SETTINGS, so its streams run
//! on the protocol's default window, as a client that has not yet heard
//! the server's does; and it closes once every stream has ended.

const std = @import("std");

const zoxy = @import("zoxy");

const canon = @import("canon.zig");
const scripts = @import("scripts.zig");

const Io = zoxy.Io;
const ResponseReader = zoxy.http.h2.ResponseReader;

const assert = std.debug.assert;

pub const ClientError = error{
    /// Octets that are not a run of whole frames — past a cut, a partial
    /// last frame is allowed.
    FramesCorrupted,
    /// A field section the client's decoder refused, or one without a
    /// `:status`.
    FieldsCorrupted,
    /// A frame on a stream this client never opened, or a second final
    /// answer on one it did.
    StreamUnexpected,
    /// A final status outside the `get` script's allowed set.
    StatusUnexpected,
    /// A 200 body that is not a canonical origin body, nor a prefix of
    /// one on a stream that was cut short.
    BodyCorrupted,
    /// A clean seed whose streams did not all end in a whole 200.
    GoldenOutcomeMissed,
    /// More octets than any legal transcript of this client holds.
    ResponseOverrun,
};

/// The bodies an origin answers `get` with, as DATA carries them: the
/// chunked one dechunked.
const canonical_bodies = [_][]const u8{
    canon.sized_body,
    "chunked-body-16b",
    canon.until_close_body,
};

/// The frame types and flags the oracle reads (RFC 9113 §6).
const frame_data: u8 = 0x0;
const frame_headers: u8 = 0x1;
const frame_rst_stream: u8 = 0x3;
const flag_end_stream: u8 = 0x1;
const flag_end_headers: u8 = 0x4;

comptime {
    // Every canonical body fits what an answer keeps of one, so a body
    // judged equal was compared whole.
    for (canonical_bodies) |body| assert(body.len <= 32);
}

pub fn Client(comptime IoType: type) type {
    return struct {
        io: *IoType = undefined,
        address: std.Io.net.IpAddress = undefined,
        on_ended: ?*const fn (?*anyopaque) void = null,
        context: ?*anyopaque = null,
        clean: bool = false,
        streams: u8 = 0,
        connect_completion: IoType.Completion = .{},
        connect_cancel_completion: IoType.Completion = .{},
        recv_completion: IoType.Completion = .{},
        send_completion: IoType.Completion = .{},
        request: [request_bytes_max]u8 = undefined,
        request_len: u32 = 0,
        sent_len: u32 = 0,
        receive_buffer: [receive_bytes_max]u8 = undefined,
        received_len: u32 = 0,
        overrun_scratch: [1]u8 = undefined,
        overrun: bool = false,
        socket: IoType.Socket = undefined,
        connected: bool = false,
        connect_settled: bool = false,
        cancel_requested: bool = false,
        satisfied: bool = false,
        closed: bool = false,
        ended: bool = false,
        send_pending: bool = false,
        recv_terminal: bool = false,

        const Self = @This();
        pub const streams_max: u8 = 4;
        const request_bytes_max: u32 = 1024;
        const receive_bytes_max: u32 = 8192;

        /// One stream's answer, as the frames told it.
        const Answer = struct {
            status: u16 = 0,
            body: [32]u8 = undefined,
            body_len: u32 = 0,
            ended: bool = false,
            reset: bool = false,
        };

        pub fn prepare(
            client: *Self,
            io: *IoType,
            address: std.Io.net.IpAddress,
            streams: u8,
            clean: bool,
        ) void {
            assert(streams >= 1);
            assert(streams <= streams_max);
            client.io = io;
            client.address = address;
            client.streams = streams;
            client.clean = clean;
            var len: u32 = 0;
            append(&client.request, &len, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            append(&client.request, &len, "\x00\x00\x00\x04\x00\x00\x00\x00\x00"); // SETTINGS.
            var index: u8 = 0;
            while (index < streams) : (index += 1) writeGet(&client.request, &len, streamId(index));
            client.request_len = len;
        }

        pub fn begin(client: *Self) void {
            assert(client.request_len >= 1);
            client.io.connect(&.{ .ip = client.address }, &client.connect_completion, Self, client, onConnect);
        }

        fn onConnect(client: *Self, result: Io.ConnectError!IoType.Socket) void {
            client.connect_settled = true;
            client.socket = result catch return client.end();
            client.connected = true;
            client.armRecv();
            client.armSend();
        }

        fn armSend(client: *Self) void {
            assert(client.sent_len < client.request_len);
            assert(!client.send_pending);
            client.send_pending = true;
            const bytes = client.request[client.sent_len..client.request_len];
            client.io.send(client.socket, bytes, &client.send_completion, Self, client, onSend);
        }

        fn onSend(client: *Self, result: Io.SendError!u32) void {
            assert(client.send_pending);
            client.send_pending = false;
            const sent = result catch return client.settleIfTerminal();
            client.sent_len += sent;
            assert(client.sent_len <= client.request_len);
            if (client.recv_terminal or client.satisfied) return client.settleIfTerminal();
            if (client.sent_len < client.request_len) client.armSend();
        }

        fn armRecv(client: *Self) void {
            const buffer: []u8 = if (client.received_len == client.receive_buffer.len)
                &client.overrun_scratch
            else
                client.receive_buffer[client.received_len..];
            client.io.recv(client.socket, buffer, &client.recv_completion, Self, client, onRecv);
        }

        fn onRecv(client: *Self, result: Io.RecvError!u32) void {
            const received = result catch {
                client.recv_terminal = true;
                return client.settleIfTerminal();
            };
            assert(received >= 1);
            if (client.received_len == client.receive_buffer.len) {
                client.overrun = true;
                client.recv_terminal = true;
                return client.settleIfTerminal();
            }
            client.received_len += received;
            assert(client.received_len <= client.receive_buffer.len);
            // Every stream ended: the client is done, and closes.
            if (allEnded(client.receive_buffer[0..client.received_len], client.streams)) {
                client.satisfied = true;
                return client.settleIfTerminal();
            }
            client.armRecv();
        }

        /// A dial the simulator black-holed can never complete: cancel it,
        /// so the scenario can reap this client (§9).
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
            assert(client.cancel_requested);
            if (client.connect_settled) return;
            client.connect_settled = true;
            client.end();
        }

        /// Close once the exchange is over — every stream ended, or the
        /// read did — and nothing of this client's is in flight but the
        /// read the close itself ends. A failed send waits for its read.
        fn settleIfTerminal(client: *Self) void {
            assert(client.recv_terminal or client.satisfied or !client.send_pending);
            if (client.send_pending) return;
            if (!client.recv_terminal and !client.satisfied) return;
            client.closeIfOpen();
            client.end();
        }

        pub fn closeIfOpen(client: *Self) void {
            if (!client.connected or client.closed) return;
            client.closed = true;
            client.io.closeNow(client.socket);
        }

        fn end(client: *Self) void {
            if (client.ended) return;
            client.ended = true;
            if (client.on_ended) |hook| hook(client.context);
        }

        /// The oracle, over everything this client received.
        pub fn verify(client: *const Self) ClientError!void {
            assert(client.streams >= 1);
            assert(client.streams <= streams_max);
            if (client.overrun) return error.ResponseOverrun;
            var answers: [streams_max]Answer = @splat(.{});
            try readAnswers(client.receive_buffer[0..client.received_len], client.streams, &answers);
            const allowed = scripts.spec(.get).allowed_statuses;
            for (answers[0..client.streams]) |*answer| {
                if (answer.status != 0 and std.mem.indexOfScalar(u16, allowed, answer.status) == null) {
                    return error.StatusUnexpected;
                }
                if (answer.status == 200) try checkBody(answer);
                if (!client.clean) continue;
                // A clean seed meets no adversary: every stream is answered,
                // whole, by its origin.
                if (answer.status != 200 or !answer.ended or answer.reset) return error.GoldenOutcomeMissed;
            }
        }

        /// A whole body is one canonical body, length and octets; one cut
        /// short is a prefix of one. Longer than every canonical body is
        /// neither, whatever its first octets.
        fn checkBody(answer: *const Answer) ClientError!void {
            assert(answer.status == 200);
            if (answer.body_len > answer.body.len) return error.BodyCorrupted;
            const body = answer.body[0..answer.body_len];
            assert(body.len == answer.body_len);
            for (canonical_bodies) |canonical| {
                if (answer.ended and std.mem.eql(u8, body, canonical)) return;
                if (!answer.ended and std.mem.startsWith(u8, canonical, body)) return;
            }
            return error.BodyCorrupted;
        }

        /// Walk the frames, decoding each field section in the order it
        /// went out, and fold them into one answer per stream.
        fn readAnswers(bytes: []const u8, streams: u8, answers: *[streams_max]Answer) ClientError!void {
            var reader: ResponseReader = undefined;
            reader.init();
            var offset: usize = 0;
            var frames: u32 = 0;
            while (bytes.len - offset >= 9) : (frames += 1) {
                assert(frames < receive_bytes_max / 9 + 1);
                const header = bytes[offset..][0..9];
                const length = std.mem.readInt(u24, header[0..3], .big);
                const id: u31 = @intCast(std.mem.readInt(u32, header[5..9], .big) & 0x7fff_ffff);
                // A partial last frame: what a cut connection leaves.
                if (bytes.len - offset - 9 < length) return;
                const payload = bytes[offset + 9 ..][0..length];
                offset += 9 + length;
                if (id == 0) continue; // The connection's own frames.
                const answer = answerFor(answers, streams, id) orelse return error.StreamUnexpected;
                try foldFrame(&reader, answer, header[3], header[4], payload);
            }
        }

        fn answerFor(answers: *[streams_max]Answer, streams: u8, id: u31) ?*Answer {
            assert(id != 0);
            assert(streams <= streams_max);
            if (id % 2 == 0) return null;
            const index = (id - 1) / 2;
            if (index >= streams) return null;
            assert(streamId(@intCast(index)) == id);
            return &answers[index];
        }

        fn foldFrame(
            reader: *ResponseReader,
            answer: *Answer,
            frame_type: u8,
            flags: u8,
            payload: []const u8,
        ) ClientError!void {
            if (answer.ended or answer.reset) return error.StreamUnexpected;
            assert(answer.body_len == 0 or answer.status != 0);
            switch (frame_type) {
                frame_headers => {
                    // A response head is small: always one frame here, so a
                    // CONTINUATION — which this server never needs — is
                    // refused loudly rather than assembled.
                    if (flags & flag_end_headers == 0) return error.FieldsCorrupted;
                    const fields = reader.decode(payload) catch return error.FieldsCorrupted;
                    const value = ResponseReader.value(fields, ":status") orelse return error.FieldsCorrupted;
                    const status = std.fmt.parseUnsigned(u16, value, 10) catch return error.FieldsCorrupted;
                    if (status < 200) return; // Interim: the final one follows.
                    if (answer.status != 0) return error.StreamUnexpected;
                    answer.status = status;
                },
                frame_data => {
                    if (answer.status == 0) return error.StreamUnexpected;
                    const room = answer.body.len -| answer.body_len;
                    const take = @min(room, payload.len);
                    @memcpy(answer.body[answer.body_len..][0..take], payload[0..take]);
                    answer.body_len += @intCast(payload.len);
                },
                frame_rst_stream => answer.reset = true,
                else => {},
            }
            if (endsStream(frame_type, flags)) answer.ended = true;
        }

        /// END_STREAM on a frame that carries it: DATA or HEADERS.
        fn endsStream(frame_type: u8, flags: u8) bool {
            const carries = frame_type == frame_data or frame_type == frame_headers;
            return carries and flags & flag_end_stream != 0;
        }

        /// Whether every stream has ended — END_STREAM or a reset — so the
        /// client has nothing left to read.
        fn allEnded(bytes: []const u8, streams: u8) bool {
            assert(streams >= 1);
            assert(streams <= streams_max);
            var ended: [streams_max]bool = @splat(false);
            var offset: usize = 0;
            while (bytes.len - offset >= 9) {
                const header = bytes[offset..][0..9];
                const length = std.mem.readInt(u24, header[0..3], .big);
                if (bytes.len - offset - 9 < length) break;
                offset += 9 + length;
                const id: u31 = @intCast(std.mem.readInt(u32, header[5..9], .big) & 0x7fff_ffff);
                if (id == 0 or id % 2 == 0 or (id - 1) / 2 >= streams) continue;
                const stops = header[3] == frame_rst_stream or endsStream(header[3], header[4]);
                if (stops) ended[(id - 1) / 2] = true;
            }
            for (ended[0..streams]) |one| {
                if (!one) return false;
            }
            return true;
        }

        fn streamId(index: u8) u31 {
            return 2 * @as(u31, index) + 1;
        }

        /// A GET for `get`'s path, every field a literal without indexing
        /// on a new name (RFC 7541 §6.2.2): no table on this side either.
        fn writeGet(out: *[request_bytes_max]u8, len: *u32, id: u31) void {
            const start = len.*;
            len.* += 9;
            const fields = [_][2][]const u8{
                .{ ":method", "GET" },
                .{ ":scheme", "http" },
                .{ ":path", "/sim" },
                .{ ":authority", "sim" },
                .{ canon.log_request_header, canon.log_request_value },
            };
            for (fields) |field| {
                append(out, len, "\x00");
                literal(out, len, field[0]);
                literal(out, len, field[1]);
            }
            const header = out[start..][0..9];
            std.mem.writeInt(u24, header[0..3], @intCast(len.* - start - 9), .big);
            header[3] = frame_headers;
            header[4] = flag_end_stream | flag_end_headers;
            std.mem.writeInt(u32, header[5..9], id, .big);
        }

        fn literal(out: *[request_bytes_max]u8, len: *u32, bytes: []const u8) void {
            assert(bytes.len < 127); // A one-octet length (RFC 7541 §5.1).
            out[len.*] = @intCast(bytes.len);
            len.* += 1;
            append(out, len, bytes);
        }

        fn append(out: *[request_bytes_max]u8, len: *u32, bytes: []const u8) void {
            assert(len.* + bytes.len <= out.len);
            @memcpy(out[len.*..][0..bytes.len], bytes);
            len.* += @intCast(bytes.len);
        }
    };
}
