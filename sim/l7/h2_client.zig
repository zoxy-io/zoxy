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
//!
//! A share of the population floods instead (#276): each `Mode` but
//! `exchange` sends one past one of the server's per-connection budgets,
//! and its oracle is the connection's end — GOAWAY(ENHANCE_YOUR_CALM) on a
//! clean seed, and on any seed nothing but a GOAWAY the server may send
//! and frames on the streams the client opened. Rapid Reset paces itself:
//! a stream opened and reset, then a PING, and the next only once its
//! PONG is back — so the stream it reset has had time to give its slot
//! back, and the budget, not the pool, is what it meets. One at a time,
//! too, because each is an access-log line, and an adversarial seed runs
//! the log's buffer at one line's room.

const std = @import("std");

const zoxy = @import("zoxy");

const canon = @import("canon.zig");
const scripts = @import("scripts.zig");

const Io = zoxy.Io;
const ResponseReader = zoxy.http.h2.ResponseReader;
const budgets = zoxy.http.h2.budgets;

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
    /// A GOAWAY with a code the server has no cause to send this client:
    /// anything but a drain's NO_ERROR, or a flood's ENHANCE_YOUR_CALM.
    GoawayUnexpected,
    /// A clean seed's flood whose connection did not end calm.
    CalmMissed,
    /// A PONG for a PING this client never sent: more than it sent, or
    /// any for a flood that sent none.
    PongUnexpected,
};

/// What a client does with its connection: the exchange the population
/// came for, or one flood per budget the server keeps (#276).
pub const Mode = enum {
    exchange,
    rapid_reset,
    ping,
    settings,
    window_update,
    ignored,
    empty_data,
    continuation,
    field_block,

    pub const floods = [_]Mode{
        .rapid_reset, .ping,       .settings,     .window_update,
        .ignored,     .empty_data, .continuation, .field_block,
    };
};

/// The bodies an origin answers `get` with, as DATA carries them: the
/// chunked one dechunked.
const canonical_bodies = [_][]const u8{
    canon.sized_body,
    "chunked-body-16b",
    canon.until_close_body,
};

/// The frame types and flags the client writes and the oracle reads
/// (RFC 9113 §6).
const frame_data: u8 = 0x0;
const frame_headers: u8 = 0x1;
const frame_priority: u8 = 0x2;
const frame_rst_stream: u8 = 0x3;
const frame_settings: u8 = 0x4;
const frame_ping: u8 = 0x6;
const frame_goaway: u8 = 0x7;
const frame_window_update: u8 = 0x8;
const frame_continuation: u8 = 0x9;
/// A type no RFC assigns, which §5.5 says to ignore.
const frame_unknown: u8 = 0xfa;
const flag_end_stream: u8 = 0x1;
const flag_ack: u8 = 0x1;
const flag_end_headers: u8 = 0x4;
const code_no_error: u32 = 0x0;
const code_refused_stream: u32 = 0x7;
const code_cancel: u32 = 0x8;
const code_enhance_your_calm: u32 = 0xb;

/// Rapid Reset's pacing: streams opened and reset per round, and rounds
/// enough to pass the budget. A round whose stream the pool refused is a
/// PING that asked for nothing, so on a starved seed the PING budget may
/// end the connection first — calm all the same.
const resets_per_round: u32 = 1;
const rounds_max: u32 = (budgets.resets_unpaid_max + resets_per_round) / resets_per_round;
/// A round is a head of five short literals, a reset and a PING: under
/// this, which `writeRounds` asserts of each.
const round_bytes_max: u32 = 128;

/// The field block bomb's size: indexed static entries, one octet each
/// and sixty against the list size (RFC 7541 §4.1) — past the head
/// budget the server advertises, which is its head buffer's size.
const bomb_fields: u32 = 1024;

comptime {
    // Every canonical body fits what an answer keeps of one, so a body
    // judged equal was compared whole.
    for (canonical_bodies) |body| assert(body.len <= 32);
    assert(rounds_max * resets_per_round > budgets.resets_unpaid_max);
    assert(bomb_fields * 60 > zoxy.constants.head_buffer_bytes_default);
}

pub fn Client(comptime IoType: type) type {
    return struct {
        io: *IoType = undefined,
        address: std.Io.net.IpAddress = undefined,
        on_ended: ?*const fn (?*anyopaque) void = null,
        context: ?*anyopaque = null,
        clean: bool = false,
        mode: Mode = .exchange,
        streams: u8 = 0,
        connect_completion: IoType.Completion = .{},
        connect_cancel_completion: IoType.Completion = .{},
        recv_completion: IoType.Completion = .{},
        send_completion: IoType.Completion = .{},
        request: [request_bytes_max]u8 = undefined,
        request_len: u32 = 0,
        sent_len: u32 = 0,
        /// How far the client may send: all of `request`, but for Rapid
        /// Reset only up to the round whose PONG it waits on.
        send_limit: u32 = 0,
        round_ends: [rounds_max]u32 = undefined,
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
        const request_bytes_max: u32 = 16 * 1024;
        /// Room for Rapid Reset's worst transcript: every round's stream
        /// answered whole before its reset arrived — which an adversary
        /// splitting a round's send can arrange — beside its PONG.
        const receive_bytes_max: u32 = 32 * 1024;

        comptime {
            // The preface, its SETTINGS, and every round.
            assert(64 + rounds_max * round_bytes_max <= request_bytes_max);
        }

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
            mode: Mode,
        ) void {
            assert(streams >= 1);
            assert(streams <= streams_max);
            client.io = io;
            client.address = address;
            client.streams = streams;
            client.clean = clean;
            client.mode = mode;
            var len: u32 = 0;
            append(&client.request, &len, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            writeFrame(&client.request, &len, frame_settings, 0, 0, "");
            switch (mode) {
                .exchange => {
                    var index: u8 = 0;
                    while (index < streams) : (index += 1) {
                        writeHead(&client.request, &len, streamId(index), "GET", flag_end_stream | flag_end_headers);
                    }
                },
                .rapid_reset => client.writeRounds(&len),
                else => writeFlood(&client.request, &len, mode),
            }
            client.request_len = len;
            client.send_limit = if (mode == .rapid_reset) client.round_ends[0] else len;
            assert(client.send_limit <= client.request_len);
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
            assert(client.sent_len < client.send_limit);
            assert(!client.send_pending);
            client.send_pending = true;
            const bytes = client.request[client.sent_len..client.send_limit];
            client.io.send(client.socket, bytes, &client.send_completion, Self, client, onSend);
        }

        fn onSend(client: *Self, result: Io.SendError!u32) void {
            assert(client.send_pending);
            client.send_pending = false;
            const sent = result catch return client.settleIfTerminal();
            client.sent_len += sent;
            assert(client.sent_len <= client.send_limit);
            if (client.recv_terminal or client.satisfied) return client.settleIfTerminal();
            if (client.sent_len < client.send_limit) client.armSend();
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
            const bytes = client.receive_buffer[0..client.received_len];
            switch (client.mode) {
                // Every stream ended: the client is done, and closes.
                .exchange => if (allEnded(bytes, client.streams)) {
                    client.satisfied = true;
                    return client.settleIfTerminal();
                },
                .rapid_reset => if (client.nextRound(@min(countPongs(bytes), rounds_max))) {
                    client.satisfied = true;
                    return client.settleIfTerminal();
                },
                // A flood waits for the server to end the connection.
                else => {},
            }
            client.armRecv();
        }

        /// Rapid Reset's next round, once `pongs` rounds are answered.
        /// True when every round is, and the budget never closed the
        /// connection: what is left is to close it.
        fn nextRound(client: *Self, pongs: u32) bool {
            assert(client.mode == .rapid_reset);
            assert(pongs <= rounds_max);
            if (pongs == rounds_max) return true;
            const limit = client.round_ends[pongs];
            assert(limit >= client.send_limit);
            client.send_limit = limit;
            if (!client.send_pending and client.sent_len < client.send_limit) client.armSend();
            return false;
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
            if (client.mode != .exchange) return client.verifyFlood();
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

        /// What a flood may hear back: whole frames; on its streams only
        /// what a server may say on a stream — field sections that decode
        /// in order, DATA, resets — and on the connection, a GOAWAY that
        /// is a drain's or the flood's verdict. On a clean seed the verdict
        /// is the end: ENHANCE_YOUR_CALM — unless the pool refused one of
        /// Rapid Reset's streams, which a reset then costs nothing for.
        fn verifyFlood(client: *const Self) ClientError!void {
            assert(client.mode != .exchange);
            const bytes = client.receive_buffer[0..client.received_len];
            var reader: ResponseReader = undefined;
            reader.init();
            var goaway: ?u32 = null;
            var refused = false;
            var offset: usize = 0;
            var frames: u32 = 0;
            while (bytes.len - offset >= 9) : (frames += 1) {
                assert(frames < receive_bytes_max / 9 + 1);
                const header = bytes[offset..][0..9];
                const length = std.mem.readInt(u24, header[0..3], .big);
                const id: u31 = @intCast(std.mem.readInt(u32, header[5..9], .big) & 0x7fff_ffff);
                if (bytes.len - offset - 9 < length) break; // A cut.
                const payload = bytes[offset + 9 ..][0..length];
                offset += 9 + length;
                if (id == 0) {
                    if (header[3] == frame_goaway) goaway = try goawayCode(payload);
                    continue;
                }
                if (id % 2 == 0 or id > client.openedMax()) return error.StreamUnexpected;
                switch (header[3]) {
                    frame_headers => _ = reader.decode(payload) catch return error.FieldsCorrupted,
                    frame_rst_stream => {
                        if (payload.len != 4) return error.FramesCorrupted;
                        if (std.mem.readInt(u32, payload[0..4], .big) == code_refused_stream) refused = true;
                    },
                    else => {},
                }
            }
            if (countPongs(bytes) > client.pongsMax()) return error.PongUnexpected;
            if (goaway) |code| {
                if (code != code_enhance_your_calm and code != code_no_error) return error.GoawayUnexpected;
            }
            if (!client.clean) return;
            if (client.mode == .rapid_reset and refused) return;
            if (goaway != code_enhance_your_calm) return error.CalmMissed;
        }

        /// The highest stream this client's flood opens: none, for one
        /// that opens no stream — PRIORITY names an idle one, and opens
        /// nothing.
        fn openedMax(client: *const Self) u31 {
            assert(client.mode != .exchange);
            return switch (client.mode) {
                .exchange => unreachable,
                .rapid_reset => @intCast(2 * rounds_max * resets_per_round - 1),
                .empty_data, .continuation, .field_block => 1,
                .ping, .settings, .window_update, .ignored => 0,
            };
        }

        /// The PONGs a flood may hear: one per PING it sent, short of the
        /// one past the budget, which the server answers by ending it.
        fn pongsMax(client: *const Self) u32 {
            assert(client.mode != .exchange);
            return switch (client.mode) {
                .rapid_reset => rounds_max,
                .ping => budgets.Unpaid.max.ping,
                else => 0,
            };
        }

        /// A GOAWAY's error code, from a payload long enough to carry one.
        fn goawayCode(payload: []const u8) ClientError!u32 {
            if (payload.len < 8) return error.FramesCorrupted;
            const code = std.mem.readInt(u32, payload[4..8], .big);
            assert(payload.len >= 8);
            return code;
        }

        /// Rapid Reset's rounds, each ending where the client next waits:
        /// streams opened and reset at once, then a PING to pace by.
        fn writeRounds(client: *Self, len: *u32) void {
            assert(client.mode == .rapid_reset);
            var id: u31 = 1;
            var round: u32 = 0;
            while (round < rounds_max) : (round += 1) {
                const round_start = len.*;
                var stream: u32 = 0;
                while (stream < resets_per_round) : (stream += 1) {
                    writeFloodHead(&client.request, len, id, "GET", flag_end_stream | flag_end_headers);
                    var code: [4]u8 = undefined;
                    std.mem.writeInt(u32, &code, code_cancel, .big);
                    writeFrame(&client.request, len, frame_rst_stream, 0, id, &code);
                    id += 2;
                }
                var opaque_data: [8]u8 = undefined;
                std.mem.writeInt(u64, &opaque_data, round, .big);
                writeFrame(&client.request, len, frame_ping, 0, 0, &opaque_data);
                assert(len.* - round_start <= round_bytes_max);
                client.round_ends[round] = len.*;
            }
            assert(id == client.openedMax() + 2);
        }

        /// One past `mode`'s budget, after the opening's SETTINGS — which
        /// counts against the SETTINGS budget too, so that flood is past
        /// it by two.
        fn writeFlood(out: *[request_bytes_max]u8, len: *u32, mode: Mode) void {
            const unpaid = budgets.Unpaid.max;
            switch (mode) {
                .exchange, .rapid_reset => unreachable,
                .ping => for (0..unpaid.ping + 1) |_| writeFrame(out, len, frame_ping, 0, 0, "pingpong"),
                .settings => for (0..unpaid.settings + 1) |_| writeFrame(out, len, frame_settings, 0, 0, ""),
                .window_update => for (0..unpaid.window_update + 1) |_| {
                    writeFrame(out, len, frame_window_update, 0, 0, "\x00\x00\x00\x01");
                },
                // PRIORITY on an idle stream, which opens nothing, and a
                // type no one assigned, in turn.
                .ignored => for (0..unpaid.ignored + 1) |index| {
                    if (index % 2 == 0) {
                        writeFrame(out, len, frame_priority, 0, 1, "\x00\x00\x00\x00\x0f");
                    } else {
                        writeFrame(out, len, frame_unknown, 0, 0, "x");
                    }
                },
                .empty_data => {
                    writeFloodHead(out, len, 1, "POST", flag_end_headers);
                    for (0..unpaid.empty_data + 1) |_| writeFrame(out, len, frame_data, 0, 1, "");
                },
                // A head left open, and empty CONTINUATIONs one past the
                // frames a block may span.
                .continuation => {
                    writeFloodHead(out, len, 1, "GET", flag_end_stream);
                    for (0..budgets.field_block_frames_max) |_| writeFrame(out, len, frame_continuation, 0, 1, "");
                },
                .field_block => writeBomb(out, len),
            }
        }

        /// A head whose block is small and whose list is not: a static
        /// table entry, indexed, `bomb_fields` times.
        fn writeBomb(out: *[request_bytes_max]u8, len: *u32) void {
            const start = len.*;
            writeFloodHead(out, len, 1, "GET", flag_end_stream | flag_end_headers);
            const head_len = len.* - start;
            const index_accept_encoding: u8 = 0x80 | 16;
            for (0..bomb_fields) |_| append(out, len, &.{index_accept_encoding});
            std.mem.writeInt(u24, out[start..][0..3], @intCast(len.* - start - 9), .big);
            assert(len.* - start == head_len + bomb_fields);
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
                if (id == 0) {
                    // The connection's own frames; a GOAWAY a drain's.
                    if (header[3] == frame_goaway and try goawayCode(payload) != code_no_error) {
                        return error.GoawayUnexpected;
                    }
                    continue;
                }
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

        /// The PING answers in `bytes`: Rapid Reset's rounds, answered.
        fn countPongs(bytes: []const u8) u32 {
            var pongs: u32 = 0;
            var offset: usize = 0;
            while (bytes.len - offset >= 9) {
                const header = bytes[offset..][0..9];
                const length = std.mem.readInt(u24, header[0..3], .big);
                if (bytes.len - offset - 9 < length) break;
                offset += 9 + length;
                if (header[3] == frame_ping and header[4] & flag_ack != 0) pongs += 1;
            }
            // Counted from what the server wrote, so a bound is the
            // oracle's verdict (`pongsMax`), not an assertion here.
            assert(offset <= bytes.len);
            return pongs;
        }

        fn streamId(index: u8) u31 {
            return 2 * @as(u31, index) + 1;
        }

        /// A request head for `get`'s path, with `method`, every field a
        /// literal without indexing on a new name (RFC 7541 §6.2.2): no
        /// table on this side either.
        fn writeHead(out: *[request_bytes_max]u8, len: *u32, id: u31, method: []const u8, flags: u8) void {
            writeHeadTraced(out, len, id, method, flags, canon.log_request_value);
        }

        /// A flood's request head: traced as one, so the access log can
        /// tell the exchanges the server ended on purpose.
        fn writeFloodHead(out: *[request_bytes_max]u8, len: *u32, id: u31, method: []const u8, flags: u8) void {
            writeHeadTraced(out, len, id, method, flags, canon.log_request_flood_value);
        }

        /// `writeHead`'s frame, carrying `trace` as the access log's
        /// correlation value.
        fn writeHeadTraced(
            out: *[request_bytes_max]u8,
            len: *u32,
            id: u31,
            method: []const u8,
            flags: u8,
            trace: []const u8,
        ) void {
            const start = len.*;
            len.* += 9;
            const fields = [_][2][]const u8{
                .{ ":method", method },
                .{ ":scheme", "http" },
                .{ ":path", "/sim" },
                .{ ":authority", "sim" },
                .{ canon.log_request_header, trace },
            };
            for (fields) |field| {
                append(out, len, "\x00");
                literal(out, len, field[0]);
                literal(out, len, field[1]);
            }
            const header = out[start..][0..9];
            std.mem.writeInt(u24, header[0..3], @intCast(len.* - start - 9), .big);
            header[3] = frame_headers;
            header[4] = flags;
            std.mem.writeInt(u32, header[5..9], id, .big);
        }

        /// One frame of `frame_type` on stream `id`: its header, then
        /// `payload` as given.
        fn writeFrame(out: *[request_bytes_max]u8, len: *u32, frame_type: u8, flags: u8, id: u31, payload: []const u8) void {
            assert(payload.len < 1 << 14);
            var header: [9]u8 = undefined;
            std.mem.writeInt(u24, header[0..3], @intCast(payload.len), .big);
            header[3] = frame_type;
            header[4] = flags;
            std.mem.writeInt(u32, header[5..9], id, .big);
            append(out, len, &header);
            append(out, len, payload);
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
