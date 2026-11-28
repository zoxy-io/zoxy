//! The simulation gate's HTTP/2 client (#275): h2c by prior knowledge to
//! the http listener, a few streams opened in its first write, and an
//! oracle over every frame that came back.
//!
//! A stream asks what the HTTP/1.1 population's `get` script asks, or
//! what its `consult_get` asks (#437), or POSTs a body to `get`'s path
//! (#373), so the same origin answers them and the same canonical bodies
//! judge them. A consult's GET parks on the listener's consulting policy
//! first, and the streams of one connection park side by side: a few of
//! them hold every consult slot a small pool has, which no pair of
//! HTTP/1.1 clients meets but by chance. A POST's body is marked, and the
//! origin checks every octet of it. Its length is declared or not, which
//! the proxy then forwards chunked. It goes in up to `body_frames_max`
//! DATA frames, one per stream per turn after every head, so a frame held
//! for its stream's room holds its siblings behind it.
//!
//! The oracle is per stream, and holds on every seed: whatever came back
//! is whole frames, each stream is answered at most once, with a status
//! its script allows and — for a 200 — a canonical body, or a prefix of
//! one on a stream that was cut short. A POST's stream may hear one frame
//! past its answer's end: the RST_STREAM(NO_ERROR) that stops a body no
//! longer wanted (RFC 9113 §8.1). On clean seeds it hardens: every stream
//! ends with a 200 and a whole canonical body, and nothing after it.
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
    /// A final status outside its script's allowed set (`scriptOf`).
    StatusUnexpected,
    /// A 200 body that is not a canonical origin body, nor a prefix of
    /// one on a stream that was cut short.
    BodyCorrupted,
    /// A clean seed whose streams did not all end in a whole 200.
    GoldenOutcomeMissed,
    /// A stream that ended whole without the trailer section (§7) its
    /// head owed, or with one its head did not.
    TrailersMismatched,
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
    /// A gRPC call answered with a 200 that is not its deadline's
    /// Trailers-Only one (§8).
    GrpcDeadlineMissed,
    /// More DATA on a stream, before this client granted any credit,
    /// than the initial window it advertised (RFC 9113 §6.9.1).
    FlowControlViolated,
    /// A client that lowered its HPACK table (RFC 7541 §4.2) heard a
    /// first field block that did not open with the size update.
    TableResizeMissed,
    /// A reset with a code the violation is not owed, nor a pool's
    /// REFUSED_STREAM.
    ResetUnexpected,
    /// A clean seed's violation that never heard the GOAWAY or the reset
    /// RFC 9113 owes it.
    ViolationUnanswered,
    /// A stream answered past the last stream a GOAWAY named. RFC 9113
    /// §6.8: the server did not act on streams past that one, so none of
    /// them may carry a status. Every seed holds this. A drain, the idle
    /// window and the #237 request cap each send such a GOAWAY.
    StreamPastGoaway,
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

    // A client breaking RFC 9113 once, in a way the server owes a stated
    // answer for (`owed`): the connection's GOAWAY, or stream 1's reset.
    settings_missing,
    idle_data,
    small_frame_size,
    bad_hpack,
    closed_data,
    window_overflow,
    short_body,

    pub const floods = [_]Mode{
        .rapid_reset, .ping,       .settings,     .window_update,
        .ignored,     .empty_data, .continuation, .field_block,
    };

    pub const violations = [_]Mode{
        .settings_missing, .idle_data,       .small_frame_size, .bad_hpack,
        .closed_data,      .window_overflow, .short_body,
    };

    /// What a violation is owed, by RFC 9113's section for it.
    pub const Owed = union(enum) {
        /// A connection error: GOAWAY with this code, and the close.
        goaway: u32,
        /// A stream error on stream 1: RST_STREAM with this code, the
        /// connection kept.
        reset: u32,
    };

    pub fn owed(mode: Mode) ?Owed {
        return switch (mode) {
            // §3.4: a preface whose first frame is not SETTINGS. §5.1: a
            // frame other than PRIORITY on an idle stream. §6.5.2: a
            // SETTINGS_MAX_FRAME_SIZE under 16,384. (A wrong preface never
            // reaches the session: the h2c listener reads it as the
            // HTTP/1.1 request line it then is, and answers 400.)
            .settings_missing, .idle_data, .small_frame_size => .{ .goaway = code_protocol_error },
            // §4.3: a field block that does not decode.
            .bad_hpack => .{ .goaway = code_compression_error },
            // §5.1: DATA on a stream half-closed (remote).
            .closed_data => .{ .reset = code_stream_closed },
            // §6.9.1: a window pushed past 2^31-1.
            .window_overflow => .{ .reset = code_flow_control_error },
            // §8.1.1: fewer body octets than `content-length` declared.
            .short_body => .{ .reset = code_protocol_error },
            else => null,
        };
    }
};

/// What an exchange client asks of its connection in its opening
/// SETTINGS (RFC 9113 §6.5.2), beside the streams it opens. A throttled
/// client advertises a stream window of `throttle_window` octets and
/// grants credit, per stream and for the connection, only once the first
/// DATA frame is back, so the server sends to the window and waits. One
/// that lowers its HPACK table owes the server's encoder a resize.
pub const Tuning = struct {
    throttle_window: ?u32 = null,
    header_table_size: ?u32 = null,

    pub fn tuned(tuning: Tuning) bool {
        return tuning.throttle_window != null or tuning.header_table_size != null;
    }
};

/// What a throttled client grants each stream, and the connection, once
/// credit is due: past any answer a stream here can carry.
const credit_increment: u32 = 1 << 16;
/// RFC 9113 §6.5.2's identifiers for the two settings a tuning names.
const setting_header_table_size: u16 = 0x1;
const setting_initial_window_size: u16 = 0x4;
/// Both settings, six octets each: the opening SETTINGS' payload at most.
const settings_bytes_max: u32 = 2 * 6;

/// What an exchange's stream asks (#373): `get`'s GET, a POST whose
/// body the origin checks octet by octet, its length declared or not, or
/// `consult_get`'s GET under `canon.consult_prefix` (#437).
pub const Ask = enum(u8) { get, post_declared, post_undeclared, consult_get, grpc_call };

/// `get`'s path, which every stream asks for but a consult's.
const get_path = "/sim";

/// One stream's request: what it asks and, for a POST, its body's length
/// and the DATA frames it is cut into, each at least one octet.
pub const Plan = struct {
    ask: Ask = .get,
    body_len: u32 = 0,
    frames: u8 = 0,
    /// A POST ends its half with a trailer section instead of DATA's
    /// END_STREAM (§7). It owes the origin none: the proxy ends the
    /// request there and carries the section no further.
    trailers: bool = false,

    pub fn carriesBody(plan: Plan) bool {
        return switch (plan.ask) {
            .get, .consult_get => false,
            .post_declared, .post_undeclared, .grpc_call => true,
        };
    }

    /// The HTTP/1.1 script whose statuses this stream may hear: a POST's
    /// is the sized POST's — `get`'s, and the #236 body cap's 413.
    pub fn scriptOf(plan: Plan) scripts.Script {
        return switch (plan.ask) {
            .get => .get,
            .consult_get => .consult_get,
            .post_declared, .post_undeclared, .grpc_call => .post_sized,
        };
    }

    /// The path this stream asks for.
    pub fn path(plan: Plan) []const u8 {
        assert(canon.consult_prefix.len >= 1);
        assert(!std.mem.startsWith(u8, get_path, canon.consult_prefix));
        return switch (plan.ask) {
            .consult_get => canon.consult_prefix,
            .grpc_call => canon.grpc_path,
            else => get_path,
        };
    }
};

/// A POST's largest body. The client never reads the server's
/// WINDOW_UPDATEs, so every stream's body together stays inside the
/// protocol's default connection window, and each inside the smallest
/// stream window the server advertises (`exchange.requestWindow`).
pub const body_bytes_max: u32 = 12 * 1024;
pub const body_frames_max: u8 = 4;

/// The bodies an origin answers `get` with, as DATA carries them: the
/// chunked one dechunked.
pub const canonical_bodies = [_][]const u8{
    canon.sized_body,
    canonical_chunked_body,
    canon.until_close_body,
};

/// The chunked body's payload, which both chunked origins answer.
pub const canonical_chunked_body = "chunked-body-16b";

comptime {
    assert(std.mem.indexOf(u8, canon.chunked_wire, canonical_chunked_body) != null);
    assert(std.mem.indexOf(u8, canon.chunked_trailers_wire, canonical_chunked_body) != null);
}

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
const code_protocol_error: u32 = 0x1;
const code_internal_error: u32 = 0x2;
const code_flow_control_error: u32 = 0x3;
const code_stream_closed: u32 = 0x5;
const code_compression_error: u32 = 0x9;
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
    assert(body_bytes_max <= 1 << 14); // The smallest frame size, and stream window.
    assert(body_frames_max >= 1);
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
        plans: [streams_max]Plan = @splat(.{}),
        /// This client's part of each body's salt, so equal bodies on two
        /// connections still differ (`bodySalt`).
        salt: u8 = 0,
        connect_completion: IoType.Completion = .{},
        connect_cancel_completion: IoType.Completion = .{},
        recv_completion: IoType.Completion = .{},
        send_completion: IoType.Completion = .{},
        request: [request_bytes_max]u8 = undefined,
        request_len: u32 = 0,
        sent_len: u32 = 0,
        /// How far the client may send: all of `request`, but for Rapid
        /// Reset only up to the round whose PONG it waits on, and for a
        /// throttled exchange only up to its held-back credit.
        send_limit: u32 = 0,
        tuning: Tuning = .{},
        /// Where a throttled exchange's credit starts in `request`.
        credit_start: u32 = 0,
        /// How much had been received when the credit was let go: every
        /// DATA octet before it was sent on the initial window alone.
        received_before_credit: ?u32 = null,
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
        const request_bytes_max: u32 = 64 * 1024;
        /// A POST's head: five short literals, a length and the mark.
        const head_bytes_max: u32 = 224;
        /// A POST's trailing HEADERS: its frame header and one literal.
        const trailers_bytes_max: u32 = 9 + 3 + canon.request_trailer_name.len + canon.request_trailer_value.len;
        /// Room for Rapid Reset's worst transcript: every round's stream
        /// answered whole before its reset arrived — which an adversary
        /// splitting a round's send can arrange — beside its PONG.
        const receive_bytes_max: u32 = 32 * 1024;

        comptime {
            // The preface, its SETTINGS, and every round.
            assert(64 + rounds_max * round_bytes_max <= request_bytes_max);
            // Or every stream's head and body, each frame's header too, with
            // a tuned SETTINGS' entries and a throttled exchange's credit.
            const stream_bytes_max = head_bytes_max + body_bytes_max + body_frames_max * 9 + trailers_bytes_max;
            const credit_bytes_max = (@as(u32, streams_max) + 1) * 13;
            assert(64 + settings_bytes_max + credit_bytes_max + @as(u32, streams_max) * stream_bytes_max <= request_bytes_max);
            // Every body inside the default connection window (RFC 9113
            // §6.9.2), which this client never sees grow.
            assert(@as(u32, streams_max) * body_bytes_max <= (1 << 16) - 1);
        }

        /// One stream's answer, as the frames told it.
        const Answer = struct {
            status: u16 = 0,
            body: [32]u8 = undefined,
            body_len: u32 = 0,
            ended: bool = false,
            reset: bool = false,
            /// A POST's RST_STREAM(NO_ERROR) after its answer ended.
            stopped: bool = false,
            /// Trailing HEADERS (§7) ended the stream: the origin's trailer
            /// section, which `checkTrailers` has already judged.
            trailers: bool = false,
            /// The final head said a trailer section is coming.
            trailers_owed: bool = false,
            /// The final head's `grpc-status`, when it carried one: a gRPC
            /// call answered Trailers-Only (§8).
            grpc_status: ?u8 = null,
        };

        /// One stream per plan. A flood counts them and asks nothing of
        /// them: its frames are its mode's. `salt` tells this client's
        /// bodies apart from every other client's: its index, say.
        pub fn prepare(
            client: *Self,
            io: *IoType,
            address: std.Io.net.IpAddress,
            plans: []const Plan,
            salt: u8,
            clean: bool,
            mode: Mode,
            tuning: Tuning,
        ) void {
            assert(plans.len >= 1);
            assert(plans.len <= streams_max);
            // A flood's SETTINGS count against the SETTINGS budget as sent.
            assert(mode == .exchange or !tuning.tuned());
            if (tuning.throttle_window) |window| assert(window >= 1);
            client.io = io;
            client.address = address;
            client.streams = @intCast(plans.len);
            @memcpy(client.plans[0..plans.len], plans);
            client.salt = salt;
            client.clean = clean;
            client.mode = mode;
            client.tuning = tuning;
            client.received_before_credit = null;
            var len: u32 = 0;
            append(&client.request, &len, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            if (mode == .settings_missing) {
                // The preface, then a PING where its SETTINGS belongs.
                writeFrame(&client.request, &len, frame_ping, 0, 0, "preface!");
            } else {
                var settings: [settings_bytes_max]u8 = undefined;
                writeFrame(&client.request, &len, frame_settings, 0, 0, settingsPayload(tuning, &settings));
            }
            switch (mode) {
                .exchange => client.writeExchange(&len),
                .rapid_reset => client.writeRounds(&len),
                .settings_missing => {},
                .idle_data, .small_frame_size, .bad_hpack, .closed_data, .window_overflow, .short_body => {
                    writeViolation(&client.request, &len, mode);
                },
                else => writeFlood(&client.request, &len, mode),
            }
            client.credit_start = len;
            if (tuning.throttle_window != null) client.writeCredit(&len);
            client.request_len = len;
            client.send_limit = if (mode == .rapid_reset) client.round_ends[0] else client.credit_start;
            assert(client.send_limit <= client.request_len);
        }

        /// The opening SETTINGS' entries a tuning asks for, six octets each.
        fn settingsPayload(tuning: Tuning, out: *[settings_bytes_max]u8) []const u8 {
            var len: usize = 0;
            if (tuning.header_table_size) |size| {
                std.mem.writeInt(u16, out[len..][0..2], setting_header_table_size, .big);
                std.mem.writeInt(u32, out[len + 2 ..][0..4], size, .big);
                len += 6;
            }
            if (tuning.throttle_window) |window| {
                std.mem.writeInt(u16, out[len..][0..2], setting_initial_window_size, .big);
                std.mem.writeInt(u32, out[len + 2 ..][0..4], window, .big);
                len += 6;
            }
            assert(len % 6 == 0);
            assert(len <= out.len);
            return out[0..len];
        }

        /// A WINDOW_UPDATE for every stream this client opened, and one for
        /// the connection: what a throttled exchange holds back.
        fn writeCredit(client: *Self, len: *u32) void {
            assert(client.mode == .exchange);
            var increment: [4]u8 = undefined;
            std.mem.writeInt(u32, &increment, credit_increment, .big);
            for (0..client.streams) |index| {
                writeFrame(&client.request, len, frame_window_update, 0, streamId(@intCast(index)), &increment);
            }
            writeFrame(&client.request, len, frame_window_update, 0, 0, &increment);
            assert(len.* - client.credit_start == (@as(u32, client.streams) + 1) * 13);
        }

        /// The whole request flight, for a client whose transport is a TLS
        /// session rather than this one's own socket: an exchange sent in
        /// one write, with no pacing to hold any of it back.
        pub fn flight(client: *const Self) []const u8 {
            assert(client.mode == .exchange);
            assert(!client.tuning.tuned());
            assert(client.send_limit == client.request_len);
            return client.request[0..client.request_len];
        }

        /// Whether every stream has ended in `received` — the TLS session's
        /// `Judge` for an exchange sent as `flight`.
        pub fn judgeComplete(context: *const anyopaque, received: []const u8) bool {
            const client: *const Self = @ptrCast(@alignCast(context));
            assert(client.mode == .exchange);
            return allEnded(received, client.streams);
        }

        /// What a TLS session heard, taken as what this client's socket
        /// would have: `verify` and the census read it from here. More than
        /// the buffer holds is an overrun, as it is on the socket.
        pub fn adoptTranscript(client: *Self, received: []const u8) void {
            assert(client.received_len == 0);
            const take = @min(received.len, client.receive_buffer.len);
            @memcpy(client.receive_buffer[0..take], received[0..take]);
            client.received_len = @intCast(take);
            client.overrun = received.len > client.receive_buffer.len;
            assert(client.received_len <= client.receive_buffer.len);
        }

        /// Streams answered whole with a `200`, for the census.
        pub fn streamsAnswered(client: *const Self) u32 {
            assert(client.streams >= 1);
            if (client.mode != .exchange) return 0;
            var answers: [streams_max]Answer = @splat(.{});
            const plans = client.plans[0..client.streams];
            _ = readAnswers(client.receive_buffer[0..client.received_len], plans, &answers) catch |err| {
                std.debug.panic("streamsAnswered after a failed verify: {s}", .{@errorName(err)});
            };
            var answered: u32 = 0;
            for (answers[0..client.streams]) |*answer| {
                answered += @intFromBool(answer.status == 200 and answer.ended and !answer.reset);
            }
            assert(answered <= client.streams);
            return answered;
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
                .exchange => {
                    if (allEnded(bytes, client.streams)) {
                        client.satisfied = true;
                        return client.settleIfTerminal();
                    }
                    if (client.send_limit < client.request_len and sawData(bytes)) client.releaseCredit();
                },
                .rapid_reset => if (client.nextRound(@min(countPongs(bytes), rounds_max))) {
                    client.satisfied = true;
                    return client.settleIfTerminal();
                },
                // A stream error is owed a reset, and the connection
                // stays: once the reset is in, there is nothing to wait for.
                .closed_data, .window_overflow, .short_body => if (heardViolation(bytes, client.mode.owed().?)) {
                    client.satisfied = true;
                    return client.settleIfTerminal();
                },
                // A flood, or a connection error, waits for the server to
                // end the connection.
                else => {},
            }
            client.armRecv();
        }

        /// A throttled exchange's first DATA is back: the server has met
        /// the window, so the credit goes out now.
        fn releaseCredit(client: *Self) void {
            assert(client.tuning.throttle_window != null);
            assert(client.received_before_credit == null);
            client.received_before_credit = client.received_len;
            client.send_limit = client.request_len;
            if (!client.send_pending and client.sent_len < client.send_limit) client.armSend();
        }

        /// Whether any whole DATA frame is among `bytes`.
        fn sawData(bytes: []const u8) bool {
            var offset: usize = 0;
            var frames: u32 = 0;
            while (bytes.len - offset >= 9) : (frames += 1) {
                assert(frames < receive_bytes_max / 9 + 1);
                const length = std.mem.readInt(u24, bytes[offset..][0..3], .big);
                if (bytes.len - offset - 9 < length) return false;
                if (bytes[offset + 3] == frame_data) return true;
                offset += 9 + length;
            }
            return false;
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

        /// Streams whose trailer section reached this client, for the
        /// census (§9). Read only once `verify` has judged this client (the
        /// census skips a seed whose drain gave up, which judges none): it
        /// walks the very bytes `verify` walked, so a failure here is a
        /// caller that broke that contract, and it says so rather than
        /// count.
        pub fn trailersHeard(client: *const Self) u32 {
            assert(client.streams >= 1);
            if (client.mode != .exchange) return 0;
            var answers: [streams_max]Answer = @splat(.{});
            const plans = client.plans[0..client.streams];
            const bytes = client.receive_buffer[0..client.received_len];
            _ = readAnswers(bytes, plans, &answers) catch |err| {
                std.debug.panic("trailersHeard after a failed verify: {s}", .{@errorName(err)});
            };
            var heard: u32 = 0;
            for (answers[0..client.streams]) |*answer| heard += @intFromBool(answer.trailers);
            assert(heard <= client.streams);
            return heard;
        }

        /// Streams that ended their half with a trailer section and were
        /// answered whole, for the census (§9); on `trailersHeard`'s terms.
        pub fn requestTrailersAnswered(client: *const Self) u32 {
            assert(client.streams >= 1);
            if (client.mode != .exchange) return 0;
            var answers: [streams_max]Answer = @splat(.{});
            const plans = client.plans[0..client.streams];
            const bytes = client.receive_buffer[0..client.received_len];
            _ = readAnswers(bytes, plans, &answers) catch |err| {
                std.debug.panic("requestTrailersAnswered after a failed verify: {s}", .{@errorName(err)});
            };
            var answered: u32 = 0;
            for (answers[0..client.streams], plans) |*answer, plan| {
                answered += @intFromBool(plan.trailers and answer.status == 200 and answer.ended and !answer.reset);
            }
            assert(answered <= client.streams);
            return answered;
        }

        /// The oracle, over everything this client received.
        pub fn verify(client: *const Self) ClientError!void {
            assert(client.streams >= 1);
            assert(client.streams <= streams_max);
            if (client.overrun) return error.ResponseOverrun;
            if (client.mode.owed()) |owed| return client.verifyViolation(owed);
            if (client.mode != .exchange) return client.verifyFlood();
            var answers: [streams_max]Answer = @splat(.{});
            const plans = client.plans[0..client.streams];
            const goaway_last = try readAnswers(client.receive_buffer[0..client.received_len], plans, &answers);
            _ = try client.windowMet();
            _ = try client.tableResized();
            for (answers[0..client.streams], plans, 0..) |*answer, plan, index| {
                const allowed = scripts.spec(plan.scriptOf()).allowed_statuses;
                if (answer.status != 0 and std.mem.indexOfScalar(u16, allowed, answer.status) == null) {
                    return error.StatusUnexpected;
                }
                if (goaway_last) |last| {
                    if (answer.status != 0 and streamId(@intCast(index)) > last) return error.StreamPastGoaway;
                }
                if (plan.ask == .grpc_call) {
                    try checkGrpcDeadline(answer);
                } else if (answer.status == 200) {
                    try checkBody(answer, client.clean);
                }
                // A whole answer carries the section its head owed and no
                // other; a cut one may end before it (reset, never ended).
                if (answer.ended and !answer.reset and answer.trailers != answer.trailers_owed) {
                    return error.TrailersMismatched;
                }
                if (!client.clean) continue;
                // A clean seed meets no adversary: every stream is answered,
                // whole, by its origin, which answers a POST only once its
                // body is in, so none is stopped — but one whose half ends
                // with trailers (§7). Its END_STREAM rides them, so the
                // answer can finish before the server has read them, and
                // RST_STREAM(NO_ERROR) then ends the half it no longer
                // wants (RFC 9113 §8.1); the trailers go no further anyway.
                if (answer.status != 200 or !answer.ended) return error.GoldenOutcomeMissed;
                if (answer.reset) return error.GoldenOutcomeMissed;
                // A gRPC call is answered at its deadline, which needs no
                // more of it, so the rest of its half may be stopped too.
                if (answer.stopped and !plan.trailers and plan.ask != .grpc_call) return error.GoldenOutcomeMissed;
            }
        }

        /// A gRPC call the origin never answers (§8) has one `200` it can
        /// hear: the proxy's own, at the call's deadline — Trailers-Only,
        /// no body, `grpc-status: 4` (DEADLINE_EXCEEDED). Any other 200 is
        /// an answer that cannot have come from anywhere.
        fn checkGrpcDeadline(answer: *const Answer) ClientError!void {
            // Trailers-Only is one HEADERS: no second section can follow it.
            assert(answer.status != 200 or !answer.trailers);
            if (answer.status != 200) return;
            if (answer.grpc_status != @as(?u8, 4)) return error.GrpcDeadlineMissed;
            if (answer.body_len != 0) return error.GrpcDeadlineMissed;
        }

        /// A throttled exchange's oracle: no stream carried more DATA before
        /// the client granted credit than the window it advertised. True
        /// when some stream met the window exactly, the server's send
        /// having stopped at it — the census's proof the wait ran.
        pub fn windowMet(client: *const Self) ClientError!bool {
            const window = client.tuning.throttle_window orelse return false;
            const seen = client.received_before_credit orelse client.received_len;
            assert(window >= 1);
            assert(seen <= client.received_len);
            const bytes = client.receive_buffer[0..seen];
            var sent: [streams_max]u32 = @splat(0);
            var offset: usize = 0;
            var frames: u32 = 0;
            while (bytes.len - offset >= 9) : (frames += 1) {
                assert(frames < receive_bytes_max / 9 + 1);
                const header = bytes[offset..][0..9];
                const length = std.mem.readInt(u24, header[0..3], .big);
                const id = std.mem.readInt(u32, header[5..9], .big) & 0x7fff_ffff;
                if (bytes.len - offset - 9 < length) break;
                offset += 9 + length;
                if (header[3] != frame_data) continue;
                // `readAnswers` refuses DATA on a stream not opened here.
                if (id == 0 or id % 2 == 0 or (id - 1) / 2 >= client.streams) continue;
                sent[(id - 1) / 2] += length;
            }
            var met = false;
            for (sent[0..client.streams]) |octets| {
                if (octets > window) return error.FlowControlViolated;
                met = met or octets == window;
            }
            return met;
        }

        /// A client that lowered its HPACK table heard the server's first
        /// field block open with a size update (RFC 7541 §6.3) no larger
        /// than it asked. True when it did, for the census.
        pub fn tableResized(client: *const Self) ClientError!bool {
            const size = client.tuning.header_table_size orelse return false;
            const bytes = client.receive_buffer[0..client.received_len];
            var offset: usize = 0;
            var frames: u32 = 0;
            while (bytes.len - offset >= 9) : (frames += 1) {
                assert(frames < receive_bytes_max / 9 + 1);
                const length = std.mem.readInt(u24, bytes[offset..][0..3], .big);
                if (bytes.len - offset - 9 < length) return false;
                const header = bytes[offset..][0..9];
                const payload = bytes[offset + 9 ..][0..length];
                offset += 9 + length;
                if (header[3] != frame_headers) continue;
                const block = fieldBlock(header[4], payload) orelse return error.FieldsCorrupted;
                if (block.len == 0 or block[0] & 0xe0 != 0x20) return error.TableResizeMissed;
                const value = hpackInteger(block, 5) orelse return error.FieldsCorrupted;
                if (value > size) return error.TableResizeMissed;
                return true;
            }
            return false;
        }

        /// A HEADERS payload's field block, past its padding and priority.
        fn fieldBlock(flags: u8, payload: []const u8) ?[]const u8 {
            const padded = flags & 0x8 != 0;
            const prioritized = flags & 0x20 != 0;
            var start: usize = 0;
            var pad: usize = 0;
            if (padded) {
                if (payload.len < 1) return null;
                pad = payload[0];
                start = 1;
            }
            if (prioritized) start += 5;
            if (start + pad > payload.len) return null;
            const block = payload[start .. payload.len - pad];
            assert(block.len <= payload.len);
            return block;
        }

        /// RFC 7541 §5.1's integer, `prefix` bits into `bytes[0]`.
        fn hpackInteger(bytes: []const u8, comptime prefix: u3) ?u32 {
            assert(bytes.len >= 1);
            const mask: u8 = (1 << prefix) - 1;
            var value: u32 = bytes[0] & mask;
            if (value < mask) return value;
            var shift: u5 = 0;
            for (bytes[1..@min(bytes.len, 5)]) |octet| {
                value += @as(u32, octet & 0x7f) << shift;
                if (octet & 0x80 == 0) return value;
                shift += 7;
            }
            return null;
        }

        /// What a tuned exchange proved, for the census: a stream filled to
        /// its window, and the HPACK resize heard. On `trailersHeard`'s
        /// terms: run only after `verify` passed.
        pub fn tuningHeard(client: *const Self) struct { window_met: bool, resized: bool } {
            assert(client.streams >= 1);
            if (client.mode != .exchange) return .{ .window_met = false, .resized = false };
            const window_met = client.windowMet() catch |err| {
                std.debug.panic("tuningHeard after a failed verify: {s}", .{@errorName(err)});
            };
            const resized = client.tableResized() catch |err| {
                std.debug.panic("tuningHeard after a failed verify: {s}", .{@errorName(err)});
            };
            return .{ .window_met = window_met, .resized = resized };
        }

        /// Streams that heard a gRPC call's deadline answered (§8), for the
        /// census; on `trailersHeard`'s terms.
        pub fn grpcDeadlinesHeard(client: *const Self) u32 {
            assert(client.streams >= 1);
            if (client.mode != .exchange) return 0;
            var answers: [streams_max]Answer = @splat(.{});
            const plans = client.plans[0..client.streams];
            const bytes = client.receive_buffer[0..client.received_len];
            _ = readAnswers(bytes, plans, &answers) catch |err| {
                std.debug.panic("grpcDeadlinesHeard after a failed verify: {s}", .{@errorName(err)});
            };
            var heard: u32 = 0;
            for (answers[0..client.streams], plans) |*answer, plan| {
                heard += @intFromBool(plan.ask == .grpc_call and answer.status == 200 and answer.grpc_status == @as(?u8, 4));
            }
            assert(heard <= client.streams);
            return heard;
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

        /// What a violation may hear back: whole frames, on stream 1 at most;
        /// a GOAWAY only with the code it is owed or a drain's NO_ERROR; a
        /// reset only with the code it is owed, REFUSED_STREAM (a pool with
        /// no room), or NO_ERROR once its response has ended (RFC 9113 §8.1:
        /// answered early, and asked to stop sending). On a clean seed, the
        /// owed answer itself.
        fn verifyViolation(client: *const Self, owed: Mode.Owed) ClientError!void {
            assert(client.mode.owed() != null);
            assert(client.received_len <= client.receive_buffer.len);
            const bytes = client.receive_buffer[0..client.received_len];
            var reader: ResponseReader = undefined;
            reader.init();
            var answered = false;
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
                const ends = header[4] & flag_end_stream != 0;
                if (id != 0 and ends and (header[3] == frame_data or header[3] == frame_headers)) answered = true;
                if (id == 0) {
                    if (header[3] != frame_goaway) continue;
                    const code = try goawayCode(payload);
                    const owed_code = switch (owed) {
                        .goaway => |goaway| goaway,
                        .reset => code_no_error,
                    };
                    if (code != owed_code and code != code_no_error) return error.GoawayUnexpected;
                    continue;
                }
                if (id % 2 == 0 or id > client.openedMax()) return error.StreamUnexpected;
                switch (header[3]) {
                    frame_headers => _ = reader.decode(payload) catch return error.FieldsCorrupted,
                    frame_rst_stream => {
                        if (payload.len != 4) return error.FramesCorrupted;
                        const code = std.mem.readInt(u32, payload[0..4], .big);
                        const owed_code = switch (owed) {
                            .reset => |reset| reset,
                            .goaway => code_refused_stream,
                        };
                        if (code == code_no_error and answered) continue;
                        // An adversarial origin can die before the breach is
                        // read, and the proxy then gives the stream up as it
                        // would any (exchange.zig's `abandon`).
                        if (!client.clean and (code == code_internal_error or code == code_cancel)) continue;
                        if (code != owed_code and code != code_refused_stream) return error.ResetUnexpected;
                    },
                    else => {},
                }
            }
            if (client.clean and !heardViolation(bytes, owed)) return error.ViolationUnanswered;
        }

        /// Whether `bytes` hold the answer a violation is owed: its GOAWAY,
        /// or stream 1's reset, with the owed code.
        fn heardViolation(bytes: []const u8, owed: Mode.Owed) bool {
            switch (owed) {
                inline else => |code| assert(code != code_no_error),
            }
            var offset: usize = 0;
            var frames: u32 = 0;
            while (bytes.len - offset >= 9) : (frames += 1) {
                assert(frames < receive_bytes_max / 9 + 1);
                const header = bytes[offset..][0..9];
                const length = std.mem.readInt(u24, header[0..3], .big);
                const id = std.mem.readInt(u32, header[5..9], .big) & 0x7fff_ffff;
                if (bytes.len - offset - 9 < length) return false;
                const payload = bytes[offset + 9 ..][0..length];
                offset += 9 + length;
                const code_at = switch (owed) {
                    .goaway => |code| if (header[3] == frame_goaway and id == 0 and length >= 8) code else continue,
                    .reset => |code| if (header[3] == frame_rst_stream and id == 1 and length == 4) code else continue,
                };
                const at: usize = if (owed == .goaway) 4 else 0;
                if (std.mem.readInt(u32, payload[at..][0..4], .big) == code_at) return true;
            }
            return false;
        }

        /// The violation this client made and heard answered, for the
        /// census: run only once `verify` passed.
        pub fn violationAnswered(client: *const Self) ?Mode {
            const owed = client.mode.owed() orelse return null;
            assert(client.received_len <= client.receive_buffer.len);
            const bytes = client.receive_buffer[0..client.received_len];
            return if (heardViolation(bytes, owed)) client.mode else null;
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
                // DATA on an idle stream opens nothing; the rest open one.
                .settings_missing, .idle_data, .small_frame_size => 0,
                .bad_hpack, .closed_data, .window_overflow, .short_body => 1,
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

        /// The one breach a violation's mode names, after a good preface.
        fn writeViolation(out: *[request_bytes_max]u8, len: *u32, mode: Mode) void {
            assert(mode.owed() != null);
            const start = len.*;
            switch (mode) {
                .idle_data => writeFrame(out, len, frame_data, flag_end_stream, 1, "x"),
                .small_frame_size => writeFrame(out, len, frame_settings, 0, 0, "\x00\x05\x00\x00\x00\x64"),
                // An indexed field at index 0, which no table holds.
                .bad_hpack => writeFrame(out, len, frame_headers, flag_end_stream | flag_end_headers, 1, "\x80"),
                .closed_data => {
                    writeFloodHead(out, len, 1, "GET", flag_end_stream | flag_end_headers);
                    writeFrame(out, len, frame_data, flag_end_stream, 1, "x");
                },
                .window_overflow => {
                    writeFloodHead(out, len, 1, "GET", flag_end_stream | flag_end_headers);
                    writeFrame(out, len, frame_window_update, 0, 1, "\x7f\xff\xff\xff");
                },
                .short_body => {
                    writeHeadTraced(out, len, 1, "POST", get_path, flag_end_headers, canon.log_request_flood_value, &.{
                        .{ "content-length", "10" },
                    });
                    writeFrame(out, len, frame_data, flag_end_stream, 1, "12345");
                },
                else => unreachable,
            }
            assert(len.* > start);
        }

        /// One past `mode`'s budget, after the opening's SETTINGS — which
        /// counts against the SETTINGS budget too, so that flood is past
        /// it by two.
        fn writeFlood(out: *[request_bytes_max]u8, len: *u32, mode: Mode) void {
            const unpaid = budgets.Unpaid.max;
            switch (mode) {
                .exchange, .rapid_reset => unreachable,
                .settings_missing, .idle_data, .small_frame_size, .bad_hpack => unreachable,
                .closed_data, .window_overflow, .short_body => unreachable,
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
        ///
        /// One cut short may also end the stream, on an adversarial seed,
        /// when it is the until-close body. That body is delimited by the
        /// origin's FIN and nothing else, so an origin whose send failed
        /// mid-body (kernel pressure on its socket) closes with the same
        /// FIN as one that finished. The proxy cannot tell them apart and
        /// must say END_STREAM, as the HTTP/1.1 client counts a cut
        /// one complete. Five nightly seeds met it (450198017 among them).
        /// Sized and chunked bodies carry their own end, so a cut one is
        /// still a reset, never END_STREAM. Their canonical bodies share no
        /// first octet with the until-close one, so only the empty prefix
        /// is ambiguous. A sized body wrongly ended at no octets reads the
        /// same as an until-close one cut at the head's last, and passes
        /// here. A clean seed meets no adversary, so its stricter rule
        /// still catches it.
        fn checkBody(answer: *const Answer, clean: bool) ClientError!void {
            assert(answer.status == 200);
            if (answer.body_len > answer.body.len) return error.BodyCorrupted;
            const body = answer.body[0..answer.body_len];
            assert(body.len == answer.body_len);
            // Trailers come after the whole body, and only the chunked
            // origin's has any (§7).
            if (answer.trailers) {
                if (!std.mem.eql(u8, body, canonical_chunked_body)) return error.BodyCorrupted;
                return;
            }
            for (canonical_bodies) |canonical| {
                if (answer.ended and std.mem.eql(u8, body, canonical)) return;
                if (!answer.ended and std.mem.startsWith(u8, canonical, body)) return;
            }
            if (clean) return error.BodyCorrupted;
            if (answer.ended and std.mem.startsWith(u8, canon.until_close_body, body)) return;
            return error.BodyCorrupted;
        }

        /// Walk the frames, decoding each field section in the order it
        /// went out, and fold them into one answer per stream. The result
        /// is the lowest last-stream identifier any GOAWAY named, or null
        /// if none came.
        fn readAnswers(bytes: []const u8, plans: []const Plan, answers: *[streams_max]Answer) ClientError!?u31 {
            var reader: ResponseReader = undefined;
            reader.init();
            var goaway_last: ?u31 = null;
            var offset: usize = 0;
            var frames: u32 = 0;
            while (bytes.len - offset >= 9) : (frames += 1) {
                assert(frames < receive_bytes_max / 9 + 1);
                const header = bytes[offset..][0..9];
                const length = std.mem.readInt(u24, header[0..3], .big);
                const id: u31 = @intCast(std.mem.readInt(u32, header[5..9], .big) & 0x7fff_ffff);
                // A partial last frame: what a cut connection leaves.
                if (bytes.len - offset - 9 < length) return goaway_last;
                const payload = bytes[offset + 9 ..][0..length];
                offset += 9 + length;
                if (id == 0) {
                    // The connection's own frames. A GOAWAY here comes from
                    // a drain, the idle window or the request cap: all
                    // NO_ERROR.
                    if (header[3] != frame_goaway) continue;
                    if (try goawayCode(payload) != code_no_error) return error.GoawayUnexpected;
                    const last: u31 = @intCast(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
                    goaway_last = @min(goaway_last orelse last, last);
                    continue;
                }
                const answer = answerFor(answers, @intCast(plans.len), id) orelse return error.StreamUnexpected;
                const plan = plans[@divExact(id - 1, 2)];
                try foldFrame(&reader, answer, plan.carriesBody(), header[3], header[4], payload);
            }
            assert(offset <= bytes.len);
            return goaway_last;
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
            carries_body: bool,
            frame_type: u8,
            flags: u8,
            payload: []const u8,
        ) ClientError!void {
            if (answer.reset or answer.stopped) return error.StreamUnexpected;
            if (answer.ended) return stopAfterAnswer(answer, carries_body, frame_type, payload);
            assert(answer.body_len == 0 or answer.status != 0);
            switch (frame_type) {
                frame_headers => {
                    // A response head is small: always one frame here, so a
                    // CONTINUATION — which this server never needs — is
                    // refused loudly rather than assembled.
                    if (flags & flag_end_headers == 0) return error.FieldsCorrupted;
                    const fields = reader.decode(payload) catch return error.FieldsCorrupted;
                    if (answer.status != 0 and ResponseReader.value(fields, ":status") == null) {
                        try checkTrailers(answer, fields, flags);
                        answer.trailers = true;
                        answer.ended = true;
                        return;
                    }
                    const value = ResponseReader.value(fields, ":status") orelse return error.FieldsCorrupted;
                    const status = std.fmt.parseUnsigned(u16, value, 10) catch return error.FieldsCorrupted;
                    if (status < 200) return; // Interim: the final one follows.
                    if (answer.status != 0) return error.StreamUnexpected;
                    // HTTP/1.1's trailer announcement stops at the mapping
                    // (§7); the origin's own field says one is owed.
                    if (ResponseReader.value(fields, "trailer") != null) return error.FieldsCorrupted;
                    answer.status = status;
                    answer.trailers_owed = ResponseReader.value(fields, canon.response_trailer_owed_header) != null;
                    if (ResponseReader.value(fields, "grpc-status")) |grpc| {
                        answer.grpc_status = std.fmt.parseUnsigned(u8, grpc, 10) catch return error.FieldsCorrupted;
                    }
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

        /// A field section after the final head is its trailers (§7): they
        /// end the stream, follow only the trailing origin's chunked 200,
        /// and carry its one field and nothing else, pseudo or otherwise.
        fn checkTrailers(answer: *const Answer, fields: []const ResponseReader.Field, flags: u8) ClientError!void {
            assert(answer.status != 0);
            assert(!answer.ended);
            if (flags & flag_end_stream == 0) return error.FieldsCorrupted;
            if (answer.status != 200) return error.StreamUnexpected;
            if (fields.len != 1) return error.FieldsCorrupted;
            if (!std.mem.eql(u8, fields[0].name, canon.response_trailer_name)) return error.FieldsCorrupted;
            if (!std.mem.eql(u8, fields[0].value, canon.response_trailer_value)) return error.FieldsCorrupted;
        }

        /// Past its answer's end, a POST's stream may hear one frame more:
        /// RST_STREAM(NO_ERROR), the server done with a body it no longer
        /// wants (RFC 9113 §8.1). Anything else, and anything on a GET's
        /// stream, whose client had ended its half, is past the stream.
        fn stopAfterAnswer(answer: *Answer, carries_body: bool, frame_type: u8, payload: []const u8) ClientError!void {
            assert(answer.ended);
            assert(!answer.reset);
            assert(!answer.stopped);
            if (!carries_body) return error.StreamUnexpected;
            if (frame_type != frame_rst_stream) return error.StreamUnexpected;
            if (payload.len != 4) return error.FramesCorrupted;
            if (std.mem.readInt(u32, payload[0..4], .big) != code_no_error) return error.StreamUnexpected;
            answer.stopped = true;
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

        /// Every stream's head, then the POSTs' DATA frames in turns, one
        /// of each body per turn: multiplexed, as a client sends them.
        fn writeExchange(client: *Self, len: *u32) void {
            assert(client.mode == .exchange);
            const plans = client.plans[0..client.streams];
            for (plans, 0..) |plan, index| {
                const id = streamId(@intCast(index));
                writeRequestHead(&client.request, len, id, client.bodySalt(id), plan);
            }
            var written: [streams_max]u32 = @splat(0);
            var turn: u8 = 0;
            while (turn < body_frames_max) : (turn += 1) {
                for (plans, 0..) |plan, index| {
                    if (turn >= plan.frames) continue;
                    const last = turn + 1 == plan.frames;
                    const size = if (last) plan.body_len - written[index] else plan.body_len / plan.frames;
                    assert(size >= 1);
                    const id = streamId(@intCast(index));
                    const ends = last and !plan.trailers;
                    writeBody(&client.request, len, id, client.bodySalt(id), written[index], size, ends);
                    written[index] += size;
                }
            }
            for (plans, written[0..plans.len]) |plan, sent| assert(sent == plan.body_len);
            for (plans, 0..) |plan, index| {
                if (plan.trailers) writeTrailers(&client.request, len, streamId(@intCast(index)));
            }
        }

        /// A request's trailer section, after its last DATA: it ends the
        /// client's half (RFC 9113 §8.1), so it carries END_STREAM.
        fn writeTrailers(out: *[request_bytes_max]u8, len: *u32, id: u31) void {
            const start = len.*;
            len.* += 9;
            append(out, len, "\x00");
            literal(out, len, canon.request_trailer_name);
            literal(out, len, canon.request_trailer_value);
            const header = out[start..][0..9];
            std.mem.writeInt(u24, header[0..3], @intCast(len.* - start - 9), .big);
            header[3] = frame_headers;
            header[4] = flag_end_stream | flag_end_headers;
            std.mem.writeInt(u32, header[5..9], id, .big);
            assert(len.* - start <= trailers_bytes_max);
        }

        /// Stream `id`'s body salt: this client's, then the stream's own.
        fn bodySalt(client: *const Self, id: u31) u32 {
            assert(id % 2 == 1);
            assert(id < 1 << 8);
            return @as(u32, client.salt) << 8 | id;
        }

        /// A stream's head: `get`'s, which ends the stream, or a POST's,
        /// whose body follows, with its length declared if the plan says
        /// so and its mark (#373) whichever way.
        fn writeRequestHead(out: *[request_bytes_max]u8, len: *u32, id: u31, salt: u32, plan: Plan) void {
            assert(plan.carriesBody() == (plan.frames >= 1));
            const start = len.*;
            if (!plan.carriesBody()) {
                writeHead(out, len, id, "GET", plan.path(), flag_end_stream | flag_end_headers);
                return;
            }
            assert(plan.frames <= body_frames_max);
            assert(plan.body_len >= plan.frames);
            assert(plan.body_len <= body_bytes_max);
            var length_bytes: [10]u8 = undefined;
            const length = std.fmt.bufPrint(&length_bytes, "{d}", .{plan.body_len}) catch unreachable;
            var mark_bytes: [24]u8 = undefined;
            const mark = std.fmt.bufPrint(&mark_bytes, "{d}.{d}", .{ plan.body_len, salt }) catch unreachable;
            const marked = [_][2][]const u8{.{ canon.request_body_header, mark }};
            const declared = [_][2][]const u8{ .{ "content-length", length }, marked[0] };
            const grpc = [_][2][]const u8{
                .{ "content-type", "application/grpc" },
                .{ "te", "trailers" },
                .{ "grpc-timeout", canon.grpc_timeout },
                marked[0],
            };
            const extra: []const [2][]const u8 = switch (plan.ask) {
                .post_declared => &declared,
                .grpc_call => &grpc,
                else => &marked,
            };
            writeHeadTraced(out, len, id, "POST", plan.path(), flag_end_headers, canon.log_request_value, extra);
            assert(len.* - start <= head_bytes_max);
        }

        /// `size` octets of stream `id`'s marked body, from `offset`, in
        /// one DATA frame: the octets `canon.requestBodyOctet` names.
        fn writeBody(out: *[request_bytes_max]u8, len: *u32, id: u31, salt: u32, offset: u32, size: u32, last: bool) void {
            assert(size >= 1);
            assert(offset + size <= body_bytes_max);
            var header: [9]u8 = undefined;
            std.mem.writeInt(u24, header[0..3], @intCast(size), .big);
            header[3] = frame_data;
            header[4] = if (last) flag_end_stream else 0;
            std.mem.writeInt(u32, header[5..9], id, .big);
            append(out, len, &header);
            assert(len.* + size <= out.len);
            for (out[len.*..][0..size], offset..) |*octet, index| {
                octet.* = canon.requestBodyOctet(salt, @intCast(index));
            }
            len.* += size;
        }

        /// A request head for `path`, with `method`, every field a
        /// literal without indexing on a new name (RFC 7541 §6.2.2): no
        /// table on this side either.
        fn writeHead(out: *[request_bytes_max]u8, len: *u32, id: u31, method: []const u8, path: []const u8, flags: u8) void {
            writeHeadTraced(out, len, id, method, path, flags, canon.log_request_value, &.{});
        }

        /// A flood's request head: traced as one, so the access log can
        /// tell the exchanges the server ended on purpose.
        fn writeFloodHead(out: *[request_bytes_max]u8, len: *u32, id: u31, method: []const u8, flags: u8) void {
            writeHeadTraced(out, len, id, method, get_path, flags, canon.log_request_flood_value, &.{});
        }

        /// `writeHead`'s frame, carrying `trace` as the access log's
        /// correlation value, and `extra` fields after it.
        fn writeHeadTraced(
            out: *[request_bytes_max]u8,
            len: *u32,
            id: u31,
            method: []const u8,
            path: []const u8,
            flags: u8,
            trace: []const u8,
            extra: []const [2][]const u8,
        ) void {
            assert(path.len >= 1);
            assert(path[0] == '/');
            const start = len.*;
            len.* += 9;
            const fields = [_][2][]const u8{
                .{ ":method", method },
                .{ ":scheme", "http" },
                .{ ":path", path },
                .{ ":authority", "sim" },
                .{ canon.log_request_header, trace },
            };
            for (fields) |field| {
                append(out, len, "\x00");
                literal(out, len, field[0]);
                literal(out, len, field[1]);
            }
            for (extra) |field| {
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
