//! One HTTP/2 server connection (RFC 9113), sans-I/O (#275).
//!
//! Bytes in, events and control frames out. The caller reads into
//! `recvBuffer`, reports the count to `received`, and calls `step` until it
//! answers `.need_input`; each event `step` returns is handled before the
//! next call, and whatever it staged is in `outbound`, which the caller sends
//! and reports to `outboundSent`. Nothing here touches a socket, a clock or
//! an allocator — the split `http/parser.zig` draws over hparse, one level
//! up: zoxy-io/h2 owns the syntax of a frame and of a field block, and this
//! owns what a *connection* does with them.
//!
//! The connection: the preface, SETTINGS both ways, PING, GOAWAY, both
//! levels of flow control, and every frame-level rule RFC 9113 states, each
//! answered as the codec classifies it — GOAWAY or RST_STREAM.
//!
//! The streams, inbound: a request head surfaces as `.request` once HPACK
//! decoded it and §8's rules accepted it (the h2 half of the downgrade: no
//! connection-specific field, pseudo-headers where and as many as defined,
//! field octets that HTTP/1.1 could carry). Its body surfaces as `.data`,
//! and the window it spent comes back only when the caller says it
//! `consume`d the octets — so a stream's window is the caller's room, not a
//! promise this side cannot keep. A malformed stream is reset without
//! disturbing its siblings, and a client's reset surfaces as `.reset`.
//!
//! Not yet: the response side — HEADERS and DATA out, and the send windows
//! that pace them. That is the next slice; until it lands, a stream ends
//! only when the caller `close`s or `resetStream`s it.

const std = @import("std");
const h2 = @import("h2");

const StreamTable = @import("StreamTable.zig");

const frame = h2.frame;
const hpack = h2.hpack;
const MessageValidator = h2.fields.MessageValidator;
const assert = std.debug.assert;

const Session = @This();

/// RFC 9113 §3.4: the client's connection preface, ahead of its SETTINGS.
pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The largest frame payload this server accepts: RFC 9113's floor, which
/// is also the value in force before any SETTINGS, so it is never sent.
pub const frame_payload_bytes_max: u32 = frame.Header.max_frame_size_min;

/// One whole frame, header included: what `inbound` must hold so that any
/// frame this server accepts can be parsed in place.
pub const frame_bytes_max: u32 = frame.Header.octets + frame_payload_bytes_max;

/// The HPACK dynamic table this side decodes against: RFC 7541's default.
/// Advertising less would not remove it — a client may send its first
/// request before it has read our SETTINGS, and RFC 9113 §6.5.3 gives the
/// new size no force until then (#173's open question 2).
pub const header_table_size: u32 = 4096;
pub const TableStorage = hpack.DynamicTable.Storage(header_table_size);

/// The largest single reply one inbound frame can cause: a PING ACK, or a
/// GOAWAY with no debug data — a header and eight payload octets. `step`
/// starts no frame without this much outbox room, which is what makes the
/// outbox a bound rather than a queue: a client that sends faster than it
/// reads stalls its own input, never this server's memory.
pub const reply_bytes_max: u32 = frame.Header.octets + frame.Header.ping_payload_octets;

/// A WINDOW_UPDATE or a RST_STREAM: what `flushPending` stages, each only
/// while `reply_bytes_max` stays in reserve behind it.
const control_bytes: u32 = frame.Header.octets + frame.Header.window_increment_octets;

const settings_entry_bytes: u32 = 6;
const settings_entries_max: u32 = 3;
const settings_bytes_max: u32 = frame.Header.octets + settings_entry_bytes * settings_entries_max;

/// The outbox must hold our SETTINGS beside one reply, which is the state
/// the first `step` can find it in.
pub const outbox_bytes_min: u32 = settings_bytes_max + reply_bytes_max;

/// RFC 9113 §6.9.2: every window starts here, and the connection's can
/// never be lowered by SETTINGS — only raised, by WINDOW_UPDATE.
pub const window_default: u31 = 65_535;
/// §6.9.1: a window past 2^31-1 is a flow-control error.
const window_max: i64 = std.math.maxInt(u31);

comptime {
    assert(preface.len == 24);
    assert(frame_bytes_max == 9 + 16_384);
    assert(reply_bytes_max == 17);
    assert(control_bytes == 13);
    assert(control_bytes <= reply_bytes_max);
    // The starting window must itself be a legal one; that each window
    // then stays at or under where it started is the three-way identity
    // `creditStream` and `creditConnection` assert.
    assert(window_default <= window_max);
}

pub const Config = struct {
    /// SETTINGS_MAX_CONCURRENT_STREAMS as advertised: derived from the
    /// stream pool, never configured (#173's open question 3). The stream
    /// table holds exactly this many.
    concurrent_streams_max: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE as advertised, and the HPACK
    /// decoder's own bound: the head budget, in RFC 7541's units.
    header_list_size_max: u32,
    /// SETTINGS_INITIAL_WINDOW_SIZE as advertised: the request-body octets
    /// a stream may have outstanding before the caller consumes them.
    /// Sent only when it differs from the default.
    initial_window_size: u31 = window_default,
};

/// Every buffer the session works in, all caller-owned and disjoint. The
/// session keeps the slices for its life; the memory is the caller's to
/// size and to keep alive, which is how a pool slot will own it.
pub const Buffers = struct {
    /// At least `frame_bytes_max`.
    inbound: []u8,
    /// Where a field block's fragments are assembled across CONTINUATION.
    /// Its length is the octet bound on one compressed block.
    block: []u8,
    /// HPACK's output. At least the advertised header list size, which is
    /// what makes every list within the advertisement decodable.
    decoded: []u8,
    /// One request's fields, as `.request` hands them over. At least
    /// `fieldsFor(header_list_size_max)`.
    fields: []hpack.Field,
    /// Exactly `concurrent_streams_max` slots.
    streams: []StreamTable.Slot,
    /// At least `outbox_bytes_min`.
    outbox: []u8,
    table: *TableStorage,
};

/// The most fields a list within `list_size_max` can carry: RFC 7541
/// §4.1 charges every field 32 octets of overhead.
pub fn fieldsFor(list_size_max: u32) u32 {
    assert(list_size_max >= 1);
    return @divFloor(list_size_max, 32);
}

/// What the caller does next.
pub const Step = union(enum) {
    /// Everything buffered was handled; read more into `recvBuffer`.
    need_input,
    /// The outbox is too full to answer the next frame, or to stage what
    /// this side owes. Send `outbound`, then `step` again before reading.
    flush_first,
    /// The connection is over. Send what `outbound` holds — the GOAWAY,
    /// if this side ended it — and close.
    closed,
    /// A stream opened with a well-formed request head.
    request: Request,
    /// A request body's octets.
    data: Data,
    /// A request's trailer section; it ends the client's half.
    trailers: Trailers,
    /// A stream ended without finishing: the client reset it, or this side
    /// did for a stream error. Either way it is gone from the table. Never
    /// raised for a stream the caller reset itself — from `resetStream` on,
    /// a stream raises nothing more.
    reset: Reset,

    /// Every borrowed slice below is valid until the next `step`.
    pub const Request = struct {
        stream: u31,
        fields: []const hpack.Field,
        content_length: ?u64,
        /// The head was the whole request: no body, no trailers follow.
        end_stream: bool,
    };
    pub const Data = struct {
        stream: u31,
        bytes: []const u8,
        end_stream: bool,
    };
    pub const Trailers = struct {
        stream: u31,
        fields: []const hpack.Field,
    };
    pub const Reset = struct {
        stream: u31,
        code: frame.ErrorCode,
    };
};

const State = enum {
    /// Before the 24 octets of `preface`.
    awaiting_preface,
    /// Preface read; the next frame must be the client's SETTINGS (§3.4).
    awaiting_settings,
    open,
    closed,
};

state: State,
config: Config,
inbound: []u8,
inbound_len: u32,
/// Octets of `inbound` the last event borrowed: handled, but compacted
/// only at the next `step`, once the caller is done with the event.
inbound_held: u32,
outbox: []u8,
outbox_len: u32,
outbox_sent: u32,
decoded: []u8,
fields: []hpack.Field,
assembler: frame.BlockAssembler,
decoder: hpack.Decoder,
streams: StreamTable,
/// The event the frame just handled produced, for `step` to return.
event: ?Step,
/// The code this side sent in its GOAWAY, or null when the connection is
/// still open or the peer was the one that went away.
closed_with: ?frame.ErrorCode,
/// Whether the client acknowledged our SETTINGS (§6.5.3). Until it has,
/// a new stream's window is the default, not ours (§6.9.2).
settings_acked: bool,
/// The client sent GOAWAY: it opens nothing more, and once its open
/// streams are done, so is the connection.
peer_going_away: bool,
/// Whether a credit or a reset is waiting for outbox room.
pending: bool,
/// The client's settings that bound what this side may send.
peer_frame_size_max: u32,
peer_initial_window_size: u31,
peer_header_table_size: u32,
peer_header_list_size_max: ?u32,
/// Connection flow control, receive side, in three parts that always sum
/// to the starting window: what the client may still send, what was
/// consumed and not yet credited back, and what is out with the caller.
recv_window: i64,
recv_unacked: u32,
recv_delivered: u32,
/// And send side: what the client's WINDOW_UPDATEs on stream 0 allow.
send_window: i64,
/// §5.1.1: the highest stream the client has opened. Identifiers only go
/// up, so every one at or below this is open or closed and every one above
/// is idle.
last_peer_stream: u31,
/// The highest stream that reached the caller as `.request` — what a
/// GOAWAY of ours names as the last one this side may have acted on.
last_accepted_stream: u31,
/// Streams answered with REFUSED_STREAM because the table was full.
streams_refused: u32,

pub fn init(session: *Session, config: Config, buffers: *const Buffers) void {
    assert(config.concurrent_streams_max >= 1);
    assert(config.header_list_size_max >= 1);
    assert(buffers.inbound.len >= frame_bytes_max);
    assert(buffers.outbox.len >= outbox_bytes_min);
    assert(buffers.decoded.len >= config.header_list_size_max);
    assert(buffers.fields.len >= fieldsFor(config.header_list_size_max));
    assert(buffers.streams.len == config.concurrent_streams_max);
    assert(buffers.block.len >= 1);
    session.* = .{
        .state = .awaiting_preface,
        .config = config,
        .inbound = buffers.inbound,
        .inbound_len = 0,
        .inbound_held = 0,
        .outbox = buffers.outbox,
        .outbox_len = 0,
        .outbox_sent = 0,
        .decoded = buffers.decoded,
        .fields = buffers.fields,
        .assembler = frame.BlockAssembler.init(buffers.block, frame.BlockAssembler.frames_max_default),
        .decoder = hpack.Decoder.init(buffers.table.table(), config.header_list_size_max),
        .streams = StreamTable.init(buffers.streams),
        .event = null,
        .closed_with = null,
        .settings_acked = false,
        .peer_going_away = false,
        .pending = false,
        .peer_frame_size_max = frame.Header.max_frame_size_min,
        .peer_initial_window_size = window_default,
        .peer_header_table_size = header_table_size,
        .peer_header_list_size_max = null,
        .recv_window = window_default,
        .recv_unacked = 0,
        .recv_delivered = 0,
        .send_window = window_default,
        .last_peer_stream = 0,
        .last_accepted_stream = 0,
        .streams_refused = 0,
    };
    // §3.4: the server's preface is a SETTINGS frame, and it may go out
    // before the client's arrives — so it is staged now, first.
    session.stageSettings();
    assert(session.outbox_len <= settings_bytes_max);
}

/// Where the next read lands. Valid only after `step` answered
/// `.need_input`: the buffer then holds at most a partial frame, so there
/// is always room past it.
pub fn recvBuffer(session: *Session) []u8 {
    assert(session.state != .closed);
    assert(session.inbound_held == 0);
    assert(session.inbound_len < session.inbound.len);
    return session.inbound[session.inbound_len..];
}

/// `count` octets landed in the buffer `recvBuffer` handed out.
pub fn received(session: *Session, count: u32) void {
    assert(count >= 1);
    assert(session.inbound_len + count <= session.inbound.len);
    session.inbound_len += count;
}

/// Handle buffered frames until one produces an event, input runs out, the
/// outbox needs draining, or the connection ends.
pub fn step(session: *Session) Step {
    assert(session.inbound_len <= session.inbound.len);
    assert(session.event == null);
    // The last event's borrow is over: the caller came back for the next.
    session.compact(session.inbound_held);
    session.inbound_held = 0;
    if (session.state == .closed) return .closed;
    if (session.pending) session.flushPending();
    // A caller reset can be the last stream after the client's GOAWAY.
    if (session.state == .closed) return .closed;
    var consumed: u32 = 0;
    // Bounded by the input: every pass consumes at least a frame header
    // (nine octets) or the preface, or returns.
    var passes: u32 = 0;
    while (passes <= session.inbound_len) : (passes += 1) {
        if (session.outboxRoom() < reply_bytes_max) {
            session.compact(consumed);
            return .flush_first;
        }
        const available = session.inbound[consumed..session.inbound_len];
        // Null is "not all here yet". A failure answers zero octets and
        // leaves the state `.closed`, which the check below turns into the
        // verdict — so zero is never mistaken for progress.
        const taken = switch (session.state) {
            .awaiting_preface => session.takePreface(available),
            .awaiting_settings, .open => session.takeFrame(available),
            .closed => unreachable, // Checked above and after every pass.
        } orelse return session.inputDrained(consumed);
        consumed += taken;
        assert(consumed <= session.inbound_len);
        // The event before the verdict: a client's reset of its last stream
        // after its GOAWAY both ends that stream and closes the connection,
        // and the caller hears of the stream first. `fail` clears any event,
        // so a connection error is never preceded by one.
        if (session.event) |event| {
            session.event = null;
            session.inbound_held = consumed;
            return event;
        }
        if (session.state == .closed) return .closed;
        assert(taken >= frame.Header.octets);
    }
    // Every pass consumed at least nine octets or returned, so the passes
    // run out only after the input has.
    unreachable;
}

/// The control frames staged and not yet sent.
pub fn outbound(session: *const Session) []const u8 {
    assert(session.outbox_sent <= session.outbox_len);
    return session.outbox[session.outbox_sent..session.outbox_len];
}

/// `count` octets of `outbound` reached the wire. Staged bytes never move,
/// so a send in flight can borrow them while `step` appends more.
pub fn outboundSent(session: *Session, count: u32) void {
    assert(count >= 1);
    assert(session.outbox_sent + count <= session.outbox_len);
    session.outbox_sent += count;
    if (session.outbox_sent == session.outbox_len) {
        session.outbox_sent = 0;
        session.outbox_len = 0;
    }
}

/// The caller is done with `count` octets of `stream`'s request body, so
/// they may be credited back to the client — at the next `step`, which is
/// where outbox room is found. The stream may have ended since the octets
/// were delivered, in which case its release already settled them.
pub fn consume(session: *Session, stream: u31, count: u32) void {
    assert(stream != 0);
    assert(count >= 1);
    const slot = session.streams.find(stream) orelse return;
    assert(slot.recv_delivered >= count);
    assert(session.recv_delivered >= count);
    slot.recv_delivered -= count;
    slot.recv_unacked += count;
    session.recv_delivered -= count;
    session.recv_unacked += count;
    session.pending = true;
}

/// End `stream` from this side with `code`: RST_STREAM goes out at the
/// next `step`. For a stream the caller cannot finish — an origin that
/// failed (INTERNAL_ERROR), a shed before any work (REFUSED_STREAM, which
/// the client may retry) — never for one it did.
pub fn resetStream(session: *Session, stream: u31, code: frame.ErrorCode) void {
    assert(stream != 0);
    assert(code != .no_error);
    const slot = session.streams.find(stream).?;
    assert(slot.state != .reset_pending);
    slot.state = .reset_pending;
    slot.reset_code = code;
    session.pending = true;
}

/// `stream` is finished on both sides: its slot goes back. After the
/// client's GOAWAY, the last one closed is the connection's end too.
pub fn close(session: *Session, stream: u31) void {
    assert(stream != 0);
    const slot = session.streams.find(stream).?;
    assert(slot.state == .half_closed_remote);
    session.releaseStream(slot);
}

fn outboxRoom(session: *const Session) u32 {
    assert(session.outbox_len <= session.outbox.len);
    return @intCast(session.outbox.len - session.outbox_len);
}

/// Every whole frame is handled. What a full outbox held back is tried
/// again now rather than at the next read, which may never come — a client
/// stalled on a credit sends nothing more — and if some of it still does
/// not fit, the caller is asked to flush. That ends: `flushPending` leaves
/// `pending` set only when its room check fails, and an empty outbox
/// (`outbox_bytes_min` against `reply_bytes_max + control_bytes`) cannot
/// fail it before a frame is staged — so every flush asked for moves at
/// least one owed frame.
fn inputDrained(session: *Session, consumed: u32) Step {
    assert(session.state != .closed);
    assert(session.event == null);
    session.compact(consumed);
    if (session.pending) session.flushPending();
    // A caller reset can be the last stream after the client's GOAWAY.
    if (session.state == .closed) return .closed;
    if (session.pending) {
        assert(session.outbox_len >= 1);
        return .flush_first;
    }
    return .need_input;
}

/// Drop the octets handled, keeping a partial frame at the front.
fn compact(session: *Session, consumed: u32) void {
    assert(consumed <= session.inbound_len);
    if (consumed == 0) return;
    const remaining = session.inbound_len - consumed;
    std.mem.copyForwards(
        u8,
        session.inbound[0..remaining],
        session.inbound[consumed..session.inbound_len],
    );
    session.inbound_len = remaining;
}

/// The 24 octets of §3.4, or null for more. Checked as they arrive, so a
/// client that is not speaking HTTP/2 is told so at its first wrong octet
/// rather than after 24 octets of something else.
fn takePreface(session: *Session, available: []const u8) ?u32 {
    assert(session.state == .awaiting_preface);
    const seen = @min(available.len, preface.len);
    if (!std.mem.eql(u8, available[0..seen], preface[0..seen])) {
        session.fail(.protocol_error);
        return 0;
    }
    if (seen < preface.len) return null;
    session.state = .awaiting_settings;
    return preface.len;
}

/// One whole frame handled, answering the octets it occupied — or null when
/// it has not all arrived. Zero means the connection failed on it.
fn takeFrame(session: *Session, available: []const u8) ?u32 {
    assert(session.state != .closed);
    const header = frame.Header.parse(available) catch return null;
    // §3.4 before anything the frame could otherwise be answered with: the
    // client's preface ends in its SETTINGS, and an acknowledgement is not
    // one. Ahead of validation, so a malformed first frame is this error
    // rather than a stream error on a connection that never opened.
    if (session.state == .awaiting_settings) {
        if (header.frame_type != .settings) {
            session.fail(.protocol_error);
            return 0;
        }
        if (header.has(.ack)) {
            session.fail(.protocol_error);
            return 0;
        }
    }
    // Our own advertised bound, ahead of everything else: it is what sizes
    // `inbound`, so a frame past it is one this side cannot even skip in
    // place. RFC 9113 §4.2 lets any frame-size error be a connection
    // error, and for these that is the only one available.
    if (header.length > frame_payload_bytes_max) {
        session.fail(.frame_size_error);
        return 0;
    }
    const total = frame.Header.octets + header.length;
    assert(total <= frame_bytes_max);
    header.validate(frame_payload_bytes_max) catch |err| {
        if (header.severity(err) == .connection) {
            session.fail(frame.Header.errorCode(err));
            return 0;
        }
        if (available.len < total) return null;
        session.streamError(header, frame.Header.errorCode(err));
        return total;
    };
    if (available.len < total) return null;
    session.handleFrame(header, available[frame.Header.octets..total]);
    return total;
}

fn handleFrame(session: *Session, header: frame.Header, bytes: []const u8) void {
    assert(bytes.len == header.length);
    // `takeFrame` let only the client's SETTINGS through before `open`.
    if (session.state == .awaiting_settings) assert(header.frame_type == .settings);
    const payload = frame.payload.parse(header, bytes) catch |err| {
        return switch (frame.payload.severity(header, err)) {
            .connection => session.fail(frame.payload.errorCode(err)),
            .stream => session.streamError(header, frame.payload.errorCode(err)),
        };
    };
    // §8.4: a client cannot push, so a PUSH_PROMISE from one is a
    // connection error before its field block is ever assembled.
    if (payload == .push_promise) return session.fail(.protocol_error);
    // Every frame goes through the assembler, not only fragments: an open
    // field block forbids all of them (§4.3), which is the rule enforced.
    const accepted = session.assembler.accept(header, &payload) catch |err| {
        return session.fail(frame.BlockAssembler.errorCode(err));
    };
    switch (accepted) {
        .fragment => {},
        .block => |*block| session.handleBlock(block),
        .passthrough => session.handleControl(header, &payload),
    }
}

fn handleControl(session: *Session, header: frame.Header, payload: *const frame.Payload) void {
    assert(session.state != .closed);
    assert(!session.assembler.isOpen());
    switch (payload.*) {
        .settings => |settings| session.handleSettings(header, settings),
        .ping => |ping| {
            if (header.has(.ack)) return; // An answer to a PING we never sent.
            session.stage(&.{ .ping = .{ .opaque_data = ping.opaque_data } }, 0, frame.Flag.ack.bit());
        },
        .goaway => session.handleGoaway(),
        .window_update => |update| session.handleWindowUpdate(header.stream_identifier, update.increment),
        .data => |data| session.handleData(header, data),
        .rst_stream => |reset| session.handlePeerReset(header.stream_identifier, reset.error_code),
        // §5.3.2's priority scheme is deprecated and this server does
        // not schedule by it, so PRIORITY is legal anywhere and read never.
        .priority => {},
        // §4.1 and §5.5: an unknown type is ignored.
        .unknown => {},
        // The assembler takes every field-block frame, and PUSH_PROMISE
        // failed the connection before it got here.
        .headers, .continuation, .push_promise => unreachable,
    }
}

/// §6.5: apply the client's settings, then acknowledge them — or take its
/// acknowledgement of ours.
fn handleSettings(session: *Session, header: frame.Header, settings: frame.payload.Settings) void {
    assert(header.stream_identifier == 0);
    if (header.has(.ack)) return session.takeSettingsAck();
    var entries = settings.iterate();
    while (entries.next()) |entry| {
        switch (entry.identifier) {
            // §6.5.2: 0 or 1. Its value is moot — a client cannot be
            // pushed to by a server that never pushes — but its range is
            // still the rule.
            .enable_push => if (entry.value > 1) return session.fail(.protocol_error),
            .initial_window_size => {
                if (entry.value > window_max) return session.fail(.flow_control_error);
                if (!session.retunePeerWindows(@intCast(entry.value))) {
                    return session.fail(.flow_control_error);
                }
            },
            .max_frame_size => {
                if (entry.value < frame.Header.max_frame_size_min) return session.fail(.protocol_error);
                if (entry.value > frame.Header.max_frame_size_max) return session.fail(.protocol_error);
                session.peer_frame_size_max = entry.value;
            },
            .header_table_size => session.peer_header_table_size = entry.value,
            .max_header_list_size => session.peer_header_list_size_max = entry.value,
            // It bounds the streams *this* side may open, and a server
            // that never pushes opens none.
            .max_concurrent_streams => {},
            // §6.5.2: an identifier this side does not know is ignored.
            _ => {},
        }
    }
    if (session.state == .awaiting_settings) session.state = .open;
    assert(session.state == .open);
    session.stage(&.{ .settings = .{ .entries = &.{} } }, 0, frame.Flag.ack.bit());
}

/// §6.9.2: a new SETTINGS_INITIAL_WINDOW_SIZE from the client moves every
/// stream's send window by the difference. Answers false when one would
/// pass 2^31-1, which is the connection's flow-control error.
fn retunePeerWindows(session: *Session, size: u31) bool {
    assert(size <= window_max);
    const delta: i64 = @as(i64, size) - @as(i64, session.peer_initial_window_size);
    session.peer_initial_window_size = size;
    for (session.streams.slots) |*slot| {
        if (slot.id == 0) continue;
        slot.send_window += delta;
        if (slot.send_window > window_max) return false;
    }
    return true;
}

/// Our SETTINGS took effect at the client (§6.5.3). If they changed the
/// stream window, every stream it opened under the old one moves to the
/// new one now (§6.9.2) — the receiver's own view catching up.
fn takeSettingsAck(session: *Session) void {
    if (session.settings_acked) return; // An ACK for a SETTINGS we sent once.
    session.settings_acked = true;
    const delta: i64 = @as(i64, session.config.initial_window_size) - window_default;
    if (delta == 0) return;
    for (session.streams.slots) |*slot| {
        if (slot.id == 0) continue;
        slot.recv_window += delta;
        assert(slot.recv_window + slot.recv_unacked + slot.recv_delivered ==
            session.config.initial_window_size);
    }
    // The credit threshold moved with the window: a smaller one may have
    // fallen below what a stream already holds unacked.
    session.pending = true;
}

/// The client opens nothing more; once what it did open is done, so is the
/// connection.
fn handleGoaway(session: *Session) void {
    assert(session.state == .open);
    session.peer_going_away = true;
    if (session.streams.used == 0) session.state = .closed;
}

fn handleWindowUpdate(session: *Session, stream: u31, increment: u31) void {
    assert(increment >= 1); // The codec refused a zero increment.
    if (stream == 0) {
        assert(session.send_window <= window_max);
        session.send_window += increment;
        if (session.send_window > window_max) session.fail(.flow_control_error);
        return;
    }
    if (isIdle(session, stream)) return session.fail(.protocol_error);
    // Closed, or reset: §6.9 lets it arrive, and it changes nothing.
    const slot = session.streams.find(stream) orelse return;
    if (slot.state == .reset_pending) return;
    slot.send_window += increment;
    if (slot.send_window > window_max) session.resetAccepted(slot, .flow_control_error);
}

/// The client's RST_STREAM: on an idle stream a connection error (§5.1),
/// on a closed one nothing, and on an open one the end of it. A stream the
/// caller already reset is closed at both ends now, so the reset it owed
/// is dropped — there is no one left to tell, on either side.
fn handlePeerReset(session: *Session, stream: u31, code: frame.ErrorCode) void {
    assert(stream != 0); // The codec refused stream 0.
    if (isIdle(session, stream)) return session.fail(.protocol_error);
    const slot = session.streams.find(stream) orelse return;
    const caller_reset = slot.state == .reset_pending;
    session.releaseStream(slot);
    if (caller_reset) return;
    session.event = .{ .reset = .{ .stream = stream, .code = code } };
}

/// DATA (§6.1). Its whole length, padding included, spends both windows.
/// Padding is credited back at once — the caller never holds it — and the
/// octets are handed over as `.data`, credited only once `consume`d.
fn handleData(session: *Session, header: frame.Header, data: frame.payload.Data) void {
    assert(header.stream_identifier != 0); // The codec refused stream 0.
    assert(data.data.len <= header.length);
    if (isIdle(session, header.stream_identifier)) return session.fail(.protocol_error);
    session.recv_window -= header.length;
    if (session.recv_window < 0) return session.fail(.flow_control_error);
    const slot = session.streams.find(header.stream_identifier) orelse {
        // A closed stream's octets: read, dropped, and the connection's
        // window given back so the siblings are not stalled by them.
        session.recv_unacked += header.length;
        session.pending = true;
        return;
    };
    switch (slot.state) {
        .open => {},
        .half_closed_remote => {
            session.recv_unacked += header.length;
            return session.resetAccepted(slot, .stream_closed); // §5.1.
        },
        .reset_pending => {
            session.recv_unacked += header.length;
            session.pending = true;
            return;
        },
    }
    slot.recv_window -= header.length;
    if (slot.recv_window < 0) {
        session.recv_unacked += header.length;
        slot.recv_unacked += header.length; // The slot's split stays whole to its release.
        return session.resetAccepted(slot, .flow_control_error);
    }
    const padding: u32 = header.length - @as(u32, @intCast(data.data.len));
    session.recv_unacked += padding;
    slot.recv_unacked += padding;
    if (padding >= 1) session.pending = true;
    session.deliverData(slot, data.data, header.has(.end_stream));
}

/// The request body's octets, past every window: §8.1.1's content-length
/// rule, then the event.
fn deliverData(session: *Session, slot: *StreamTable.Slot, bytes: []const u8, end_stream: bool) void {
    assert(slot.state == .open);
    const length: u32 = @intCast(bytes.len);
    slot.data_received += length;
    if (slot.content_length) |declared| {
        // More than declared, or less by the time the stream ends: the
        // header was a claim and the frames disagree with it. The octets
        // were never the caller's, so they go straight back to the window.
        var contradicted = slot.data_received > declared;
        if (end_stream) contradicted = contradicted or slot.data_received != declared;
        if (contradicted) {
            session.recv_unacked += length;
            slot.recv_unacked += length;
            return session.resetAccepted(slot, .protocol_error);
        }
    }
    session.recv_delivered += length;
    slot.recv_delivered += length;
    if (end_stream) slot.state = .half_closed_remote;
    if (length == 0 and !end_stream) return; // Nothing to hand over.
    session.event = .{ .data = .{ .stream = slot.id, .bytes = bytes, .end_stream = end_stream } };
}

/// A complete field block: a new stream's request, an open stream's
/// trailers, or a closed stream's late arrival.
fn handleBlock(session: *Session, block: *const frame.BlockAssembler.Block) void {
    assert(block.frame_type == .headers); // PUSH_PROMISE never got here.
    assert(block.stream_identifier != 0); // The codec refused stream 0.
    // §5.1.1: a client's streams are odd. An even one is a stream only a
    // server may open, and this server never does.
    if (block.stream_identifier % 2 == 0) return session.fail(.protocol_error);
    if (session.streams.find(block.stream_identifier)) |slot| return session.handleTrailers(slot, block);
    const opening = block.stream_identifier > session.last_peer_stream;
    // Decoded whatever becomes of the stream: the HPACK context is the
    // connection's, so a block skipped is every later block misread.
    const decoded = session.decodeBlock(block.fragment, if (opening) .request else .trailer);
    switch (decoded) {
        .connection => |code| return session.fail(code),
        .malformed, .ok => {},
    }
    // At or below the high-water mark and not open: a stream already
    // closed, whose late frames §6.4 has in flight — the trailers of a
    // request reset before its client read the reset. Ignored. (A client
    // that skipped an identifier and later opens it, which §5.1.1 makes a
    // PROTOCOL_ERROR, looks the same without per-identifier state.)
    if (!opening) return;
    session.last_peer_stream = block.stream_identifier;
    // The client's GOAWAY said it would open nothing more; this one is
    // refused rather than believed.
    if (session.peer_going_away) return session.refuse(block.stream_identifier, .refused_stream);
    switch (decoded) {
        .connection => unreachable, // Failed above.
        .malformed => session.refuse(block.stream_identifier, .protocol_error),
        .ok => |ok| session.openStream(block, ok.count, ok.content_length),
    }
}

/// A well-formed request head: claim a slot, or refuse the stream when the
/// table is full — REFUSED_STREAM, which §8.7 lets the client retry.
fn openStream(session: *Session, block: *const frame.BlockAssembler.Block, count: u32, content_length: ?u64) void {
    assert(count <= session.fields.len);
    assert(block.stream_identifier == session.last_peer_stream);
    // §8.1.1: a declared length the stream contradicted by ending with no
    // DATA at all.
    if (block.end_stream) {
        if (content_length) |declared| {
            if (declared != 0) return session.refuse(block.stream_identifier, .protocol_error);
        }
    }
    const slot = session.streams.acquire(block.stream_identifier) orelse {
        session.streams_refused += 1;
        return session.refuse(block.stream_identifier, .refused_stream);
    };
    slot.state = if (block.end_stream) .half_closed_remote else .open;
    slot.recv_window = session.streamWindow();
    slot.send_window = session.peer_initial_window_size;
    slot.content_length = content_length;
    session.last_accepted_stream = block.stream_identifier;
    session.event = .{ .request = .{
        .stream = block.stream_identifier,
        .fields = session.fields[0..count],
        .content_length = content_length,
        .end_stream = block.end_stream,
    } };
}

/// The window a stream opens with: ours once the client has acknowledged
/// it, the default until then (§6.9.2).
fn streamWindow(session: *const Session) u31 {
    if (session.settings_acked) return session.config.initial_window_size;
    return window_default;
}

/// A field block on a stream already open: trailers, which must end it
/// (§8.1), and which may arrive only while the client's half is open.
fn handleTrailers(session: *Session, slot: *StreamTable.Slot, block: *const frame.BlockAssembler.Block) void {
    assert(slot.id == block.stream_identifier);
    const decoded = session.decodeBlock(block.fragment, .trailer);
    const count = switch (decoded) {
        .connection => |code| return session.fail(code),
        .malformed => null,
        .ok => |ok| ok.count,
    };
    switch (slot.state) {
        .open => {},
        .half_closed_remote => return session.resetAccepted(slot, .stream_closed), // §5.1.
        .reset_pending => return, // Its reset is already owed.
    }
    if (!block.end_stream) return session.resetAccepted(slot, .protocol_error);
    if (count == null) return session.resetAccepted(slot, .protocol_error);
    if (slot.content_length) |declared| {
        if (slot.data_received != declared) return session.resetAccepted(slot, .protocol_error);
    }
    slot.state = .half_closed_remote;
    session.event = .{ .trailers = .{ .stream = slot.id, .fields = session.fields[0..count.?] } };
}

const Decoded = union(enum) {
    /// HPACK itself failed: the table is mid-block, and the connection
    /// ends with this code.
    connection: frame.ErrorCode,
    /// Decoded to the end, but malformed (§8.1.1): the stream's error.
    malformed,
    /// Decoded and well-formed: `fields[0..count]`.
    ok: struct { count: u32, content_length: ?u64 },
};

/// Run one field block through HPACK and §8's message rules. A malformed
/// field does not stop the decoding — the table has to see every field —
/// it only stops the keeping. Bounded by the decoder: a list past
/// `header_list_size_max` fails before its fields outnumber `fields`.
fn decodeBlock(session: *Session, fragment: []const u8, kind: MessageValidator.Kind) Decoded {
    // `.strict`, the RFC 9110 grammar in full, because every field here is
    // headed for an HTTP/1.1 parser on the other side of the proxy.
    var validator = MessageValidator.init(.{ .kind = kind, .rules = .strict });
    var iterator = session.decoder.iterate(session.decoded, fragment);
    var count: u32 = 0;
    var malformed = false;
    while (iterator.next() catch |err| return .{ .connection = decodeFailure(err) }) |field| : (count += 1) {
        assert(count < session.fields.len);
        if (malformed) continue;
        validator.field(&field) catch {
            malformed = true;
            continue;
        };
        session.fields[count] = field;
    }
    assert(count == iterator.fieldCount());
    if (malformed) return .malformed;
    validator.finish() catch return .malformed;
    return .{ .ok = .{ .count = count, .content_length = validator.contentLength() } };
}

/// Every HPACK failure ends the connection, because the decoder stops where
/// it failed and the table is left mid-block. Not every one is the client's
/// malformation: a list past the size this side advertised, or one past
/// the buffer that size bought, is a client being expensive, and RFC 9113
/// §7 names that ENHANCE_YOUR_CALM rather than COMPRESSION_ERROR.
fn decodeFailure(err: hpack.Decoder.Error) frame.ErrorCode {
    return switch (err) {
        error.HeaderListTooLarge, error.OutputTooLong => .enhance_your_calm,
        error.Incomplete,
        error.InvalidIndex,
        error.InvalidHuffman,
        error.IntegerTooLarge,
        error.CapacityTooLarge,
        error.UnexpectedSizeUpdate,
        error.TooManySizeUpdates,
        => .compression_error,
    };
}

fn isIdle(session: *const Session, stream: u31) bool {
    assert(stream != 0);
    assert(session.last_peer_stream % 2 == 1 or session.last_peer_stream == 0);
    if (stream % 2 == 0) return true;
    return stream > session.last_peer_stream;
}

/// A stream error (§5.4.2) from a frame's header or payload, once the rules
/// that outrank it have had their say. An open field block admits no other
/// frame at all (§4.3), so a malformed frame inside one is that connection
/// error. On an idle stream RST_STREAM may not be sent (§5.1), so there the
/// stream error can only be the connection's (§5.4.1 allows it): a frame
/// other than PRIORITY is a PROTOCOL_ERROR by §5.1 before it is anything
/// else; PRIORITY, which §5.1 lets an idle stream carry, keeps its own
/// code. (§3.4's SETTINGS-first rule ran in `takeFrame`.)
fn streamError(session: *Session, header: frame.Header, code: frame.ErrorCode) void {
    assert(header.stream_identifier != 0);
    assert(session.state == .open);
    if (session.assembler.isOpen()) return session.fail(.protocol_error);
    if (isIdle(session, header.stream_identifier)) {
        return session.fail(if (header.frame_type == .priority) code else .protocol_error);
    }
    // A flow-controlled frame counts against the connection's window even
    // when its stream is in error (§6.9), and it is given straight back.
    if (header.frame_type == .data) {
        session.recv_window -= header.length;
        if (session.recv_window < 0) return session.fail(.flow_control_error);
        session.recv_unacked += header.length;
        session.pending = true;
    }
    if (session.streams.find(header.stream_identifier)) |slot| {
        // A stream the caller reset already owes its RST_STREAM; a second,
        // with this code, would be one reset said twice.
        if (slot.state == .reset_pending) return;
        return session.resetAccepted(slot, code);
    }
    session.stageReset(header.stream_identifier, code);
}

/// A stream that never reached the caller: answered with RST_STREAM and
/// forgotten.
fn refuse(session: *Session, stream: u31, code: frame.ErrorCode) void {
    assert(stream != 0);
    assert(session.streams.find(stream) == null);
    session.stageReset(stream, code);
}

/// A stream the caller holds, ended by this side for a stream error: reset
/// on the wire, gone from the table, and reported so the caller lets go.
fn resetAccepted(session: *Session, slot: *StreamTable.Slot, code: frame.ErrorCode) void {
    assert(slot.id != 0);
    assert(code != .no_error);
    const stream = slot.id;
    session.stageReset(stream, code);
    session.releaseStream(slot);
    session.event = .{ .reset = .{ .stream = stream, .code = code } };
}

/// Give a slot back. What it owes the connection's window is settled: its
/// unconsumed octets are no longer the caller's to consume, and its own
/// window has nothing left to grant.
fn releaseStream(session: *Session, slot: *StreamTable.Slot) void {
    assert(slot.id != 0);
    assert(slot.recv_window + slot.recv_unacked + slot.recv_delivered == session.streamWindow());
    assert(session.recv_delivered >= slot.recv_delivered);
    session.recv_delivered -= slot.recv_delivered;
    session.recv_unacked += slot.recv_delivered;
    if (session.recv_unacked >= 1) session.pending = true;
    session.streams.release(slot);
    if (session.peer_going_away and session.streams.used == 0) session.state = .closed;
}

/// Credits and caller resets, staged as room allows while `reply_bytes_max`
/// stays in reserve for the next frame. What does not fit stays pending.
fn flushPending(session: *Session) void {
    assert(session.state != .closed);
    session.pending = false;
    for (session.streams.slots) |*slot| {
        if (slot.id == 0) continue;
        // A half-closed stream's client sends nothing more on it, so its
        // window has nothing left to grant.
        if (slot.state == .half_closed_remote) continue;
        if (session.outboxRoom() < reply_bytes_max + control_bytes) {
            session.pending = true;
            return;
        }
        if (slot.state == .reset_pending) {
            session.stageReset(slot.id, slot.reset_code);
            // What the release hands the connection's window is credited
            // below, in this same pass: not a reason to come back.
            const owed = session.pending;
            session.releaseStream(slot);
            session.pending = owed;
            if (session.state == .closed) return;
            continue;
        }
        session.creditStream(slot);
    }
    if (session.outboxRoom() < reply_bytes_max + control_bytes) {
        session.pending = true;
        return;
    }
    session.creditConnection();
}

/// A stream's credit goes back once half its window is consumed: a smaller
/// threshold would spend a frame per small read, a larger one stall the
/// client's sender behind its own window. Below it the credit stays owed
/// without keeping `pending` set — only more unacked octets can cross the
/// threshold, and whatever adds them sets `pending` itself.
fn creditStream(session: *Session, slot: *StreamTable.Slot) void {
    const window: i64 = session.streamWindow();
    assert(slot.state == .open);
    assert(slot.recv_window + slot.recv_unacked + slot.recv_delivered == window);
    if (slot.recv_unacked == 0) return;
    if (slot.recv_unacked * 2 < window) return;
    const credit: u31 = @intCast(slot.recv_unacked);
    session.stage(&.{ .window_update = .{ .increment = credit } }, slot.id, 0);
    slot.recv_window += slot.recv_unacked;
    slot.recv_unacked = 0;
}

fn creditConnection(session: *Session) void {
    assert(session.recv_window + session.recv_unacked + session.recv_delivered == window_default);
    assert(session.recv_unacked <= window_default);
    if (session.recv_unacked * 2 < window_default) return; // As `creditStream`.
    const credit: u31 = @intCast(session.recv_unacked);
    session.stage(&.{ .window_update = .{ .increment = credit } }, 0, 0);
    session.recv_window += session.recv_unacked;
    session.recv_unacked = 0;
}

fn stageReset(session: *Session, stream: u31, code: frame.ErrorCode) void {
    assert(stream != 0);
    assert(session.state != .closed);
    session.stage(&.{ .rst_stream = .{ .error_code = code } }, stream, 0);
}

/// A connection error (§5.4.1): GOAWAY, and nothing more is read.
fn fail(session: *Session, code: frame.ErrorCode) void {
    assert(session.state != .closed);
    assert(code != .no_error);
    // §6.8: the last stream this side may have acted on — the highest one
    // the caller was handed. A refused stream is one nothing happened on
    // (§8.7), so it does not count.
    session.stage(&.{ .goaway = .{
        .last_stream_identifier = session.last_accepted_stream,
        .error_code = code,
        .debug_data = &.{},
    } }, 0, 0);
    session.state = .closed;
    session.closed_with = code;
    session.event = null;
}

/// The server preface. Only what differs from RFC 9113's defaults goes
/// out: the frame size and table size are the defaults on purpose, and the
/// window is sent only when the caller chose another.
fn stageSettings(session: *Session) void {
    assert(session.outbox_len == 0);
    var bytes: [settings_entry_bytes * settings_entries_max]u8 = undefined;
    var used: u32 = 0;
    used = putSetting(&bytes, used, .max_concurrent_streams, session.config.concurrent_streams_max);
    used = putSetting(&bytes, used, .max_header_list_size, session.config.header_list_size_max);
    if (session.config.initial_window_size != window_default) {
        used = putSetting(&bytes, used, .initial_window_size, session.config.initial_window_size);
    }
    assert(used <= bytes.len);
    session.stage(&.{ .settings = .{ .entries = bytes[0..used] } }, 0, 0);
}

fn putSetting(bytes: []u8, used: u32, identifier: frame.payload.Settings.Identifier, value: u32) u32 {
    assert(used + settings_entry_bytes <= bytes.len);
    assert(used % settings_entry_bytes == 0);
    std.mem.writeInt(u16, bytes[used..][0..2], @backingInt(identifier), .big);
    std.mem.writeInt(u32, bytes[used + 2 ..][0..4], value, .big);
    return used + settings_entry_bytes;
}

/// Append one frame to the outbox. Room is a precondition: `step` holds
/// back any frame that might need more than `reply_bytes_max`,
/// `flushPending` keeps that reserve behind what it stages, and `init`
/// stages only the SETTINGS the outbox was sized for.
fn stage(session: *Session, payload: *const frame.Payload, stream: u31, flags: u8) void {
    assert(session.outbox_len <= session.outbox.len);
    const target = session.outbox[session.outbox_len..];
    // Every frame staged here is a fixed-shape control frame, rendered
    // into room checked for it — so neither of render's refusals (an
    // unknown type, a target too short) can happen.
    const written = frame.payload.render(payload, stream, flags, target) catch unreachable;
    assert(written >= frame.Header.octets);
    assert(written <= target.len);
    session.outbox_len += written;
}
