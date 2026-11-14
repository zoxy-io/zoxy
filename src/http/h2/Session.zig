//! One HTTP/2 server connection (RFC 9113), sans-I/O (#275).
//!
//! Bytes in, control frames out. The caller reads into `recvBuffer`,
//! reports the count to `received`, and calls `step` until it answers
//! `.need_input`; whatever `step` staged is in `outbound`, and the caller
//! sends it and reports progress to `outboundSent`. Nothing here touches a
//! socket, a clock or an allocator — the same split `http/parser.zig` draws
//! over hparse, one level up: zoxy-io/h2 owns the syntax of a frame and of a
//! field block, and this owns what a *connection* does with them.
//!
//! What it does today is the connection, and only the connection: the
//! preface, SETTINGS in both directions and their acknowledgement, PING,
//! GOAWAY, connection-level flow control, and every frame-level rule RFC
//! 9113 states, each violation answered as the connection error (GOAWAY) or
//! stream error (RST_STREAM) the codec classifies it as. Every stream a
//! client opens is refused with `REFUSED_STREAM` — RFC 9113 §8.7's "no
//! processing has occurred", so a client may retry it elsewhere — because
//! the streams themselves are the next slice. Refusing is still decoding:
//! each field block is run through HPACK, because the dynamic table is the
//! connection's and a block skipped would desynchronize every block after
//! it. So the connection this answers is a complete, conforming one that
//! happens to serve nothing, which is what lets it be gated on its own.

const std = @import("std");
const h2 = @import("h2");

const frame = h2.frame;
const hpack = h2.hpack;
const assert = std.debug.assert;

const Session = @This();

/// RFC 9113 §3.4: the client's connection preface, ahead of its SETTINGS.
pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The largest frame payload this server accepts: RFC 9113's floor, which
/// is also the value in force before any SETTINGS, so it is never sent.
/// The floor rather than more because it is what sizes `inbound`, and a
/// larger frame buys a client nothing a second frame does not.
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
/// GOAWAY with no debug data — both a header and eight payload octets.
/// `step` refuses to start a frame without this much outbox room, which is
/// what makes the outbox a bound rather than a queue: a client that sends
/// faster than it reads stalls its own input, never this server's memory.
pub const reply_bytes_max: u32 = frame.Header.octets + frame.Header.ping_payload_octets;

/// Our SETTINGS: two entries (see `stageSettings`).
const settings_entries: u32 = 2;
const settings_bytes: u32 = frame.Header.octets + settings_entry_bytes * settings_entries;
const settings_entry_bytes: u32 = 6;

/// The outbox must hold our SETTINGS beside one reply, which is the state
/// the first `step` can find it in.
pub const outbox_bytes_min: u32 = settings_bytes + reply_bytes_max;

/// RFC 9113 §6.9.2: every window starts here, and the connection's can
/// never be lowered by SETTINGS — only raised, by WINDOW_UPDATE.
const window_initial: i64 = 65_535;
/// §6.9.1: a window past 2^31-1 is a flow-control error.
const window_max: i64 = std.math.maxInt(u31);

comptime {
    assert(preface.len == 24);
    assert(frame_bytes_max == 9 + 16_384);
    assert(reply_bytes_max == 17);
    // The starting window must itself be a legal one. That the receive
    // window then stays at or under it is an invariant of `handleData`,
    // asserted there, not something this line could show.
    assert(window_initial <= window_max);
}

pub const Config = struct {
    /// SETTINGS_MAX_CONCURRENT_STREAMS as advertised: derived from the
    /// stream pool, never configured (#173's open question 3).
    concurrent_streams_max: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE as advertised, and the HPACK
    /// decoder's own bound: the head budget, in RFC 7541's units.
    header_list_size_max: u32,
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
    /// At least `outbox_bytes_min`.
    outbox: []u8,
    table: *TableStorage,
};

/// What the caller does next.
pub const Step = enum {
    /// Everything buffered was handled; read more into `recvBuffer`.
    need_input,
    /// The outbox is too full to answer the next frame. Send `outbound`,
    /// then `step` again before reading.
    flush_first,
    /// The connection is over. Send what `outbound` holds — the GOAWAY,
    /// if this side ended it — and close.
    closed,
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
outbox: []u8,
outbox_len: u32,
outbox_sent: u32,
decoded: []u8,
assembler: frame.BlockAssembler,
decoder: hpack.Decoder,
/// The code this side sent in its GOAWAY, or null when the connection is
/// still open or the peer was the one that went away.
closed_with: ?frame.ErrorCode,
/// Whether the client acknowledged our SETTINGS (§6.5.3).
settings_acked: bool,
/// The client's settings that bound what this side may send.
peer_frame_size_max: u32,
peer_initial_window_size: u32,
peer_header_table_size: u32,
peer_header_list_size_max: ?u32,
/// Connection flow control, receive side: what the client may still send,
/// and what it has sent that this side consumed but not yet credited back.
recv_window: i64,
recv_unacked: u32,
/// And send side: what the client's WINDOW_UPDATEs on stream 0 allow.
send_window: i64,
/// §5.1.1: the highest stream the client has opened. Identifiers only go
/// up, so every one at or below this is closed and every one above idle.
last_peer_stream: u31,
/// Streams answered with REFUSED_STREAM.
streams_refused: u32,

pub fn init(session: *Session, config: Config, buffers: *const Buffers) void {
    assert(config.concurrent_streams_max >= 1);
    assert(config.header_list_size_max >= 1);
    assert(buffers.inbound.len >= frame_bytes_max);
    assert(buffers.outbox.len >= outbox_bytes_min);
    assert(buffers.decoded.len >= config.header_list_size_max);
    assert(buffers.block.len >= 1);
    session.* = .{
        .state = .awaiting_preface,
        .config = config,
        .inbound = buffers.inbound,
        .inbound_len = 0,
        .outbox = buffers.outbox,
        .outbox_len = 0,
        .outbox_sent = 0,
        .decoded = buffers.decoded,
        .assembler = frame.BlockAssembler.init(buffers.block, frame.BlockAssembler.frames_max_default),
        .decoder = hpack.Decoder.init(buffers.table.table(), config.header_list_size_max),
        .closed_with = null,
        .settings_acked = false,
        .peer_frame_size_max = frame.Header.max_frame_size_min,
        .peer_initial_window_size = @intCast(window_initial),
        .peer_header_table_size = header_table_size,
        .peer_header_list_size_max = null,
        .recv_window = window_initial,
        .recv_unacked = 0,
        .send_window = window_initial,
        .last_peer_stream = 0,
        .streams_refused = 0,
    };
    // §3.4: the server's preface is a SETTINGS frame, and it may go out
    // before the client's arrives — so it is staged now, first.
    session.stageSettings();
    assert(session.outbox_len == settings_bytes);
}

/// Where the next read lands. Valid only after `step` answered
/// `.need_input`: the buffer then holds at most a partial frame, so there
/// is always room past it.
pub fn recvBuffer(session: *Session) []u8 {
    assert(session.state != .closed);
    assert(session.inbound_len < session.inbound.len);
    return session.inbound[session.inbound_len..];
}

/// `count` octets landed in the buffer `recvBuffer` handed out.
pub fn received(session: *Session, count: u32) void {
    assert(count >= 1);
    assert(session.inbound_len + count <= session.inbound.len);
    session.inbound_len += count;
}

/// Handle every complete frame buffered, until input runs out, the outbox
/// needs draining, or the connection ends.
pub fn step(session: *Session) Step {
    assert(session.inbound_len <= session.inbound.len);
    if (session.state == .closed) return .closed;
    var consumed: u32 = 0;
    defer session.compact(consumed);
    // Bounded by the input: every pass consumes at least a frame header
    // (nine octets) or the preface, or returns.
    var passes: u32 = 0;
    while (passes <= session.inbound_len) : (passes += 1) {
        if (session.outboxRoom() < reply_bytes_max) return .flush_first;
        const available = session.inbound[consumed..session.inbound_len];
        // Null is "not all here yet". A failure answers zero octets and
        // leaves the state `.closed`, which the check below turns into the
        // verdict — so zero is never mistaken for progress.
        const taken = switch (session.state) {
            .awaiting_preface => session.takePreface(available),
            .awaiting_settings, .open => session.takeFrame(available),
            .closed => unreachable, // Checked above and after every pass.
        } orelse return .need_input;
        consumed += taken;
        assert(consumed <= session.inbound_len);
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

fn outboxRoom(session: *const Session) u32 {
    assert(session.outbox_len <= session.outbox.len);
    return @intCast(session.outbox.len - session.outbox_len);
}

/// Drop the octets `step` handled, keeping a partial frame at the front.
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
    // Our own advertised bound, ahead of everything: it is what sizes
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
        .goaway => {
            // The client opens no more streams, and every stream it did
            // open was refused, so there is nothing left to finish.
            session.state = .closed;
        },
        .window_update => |update| session.handleWindowUpdate(header.stream_identifier, update.increment),
        .data => session.handleData(header),
        // §5.1: neither is legal on an idle stream; on a closed one both
        // are what a client may still send before it reads our reset.
        .rst_stream => session.requireNotIdle(header.stream_identifier),
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

/// §6.5: apply the client's settings, then acknowledge them.
fn handleSettings(session: *Session, header: frame.Header, settings: frame.payload.Settings) void {
    assert(header.stream_identifier == 0);
    if (header.has(.ack)) {
        session.settings_acked = true;
        return;
    }
    var entries = settings.iterate();
    while (entries.next()) |entry| {
        switch (entry.identifier) {
            // §6.5.2: 0 or 1. Its value is moot — a client cannot be
            // pushed to by a server that never pushes — but its range is
            // still the rule.
            .enable_push => if (entry.value > 1) return session.fail(.protocol_error),
            .initial_window_size => {
                if (entry.value > window_max) return session.fail(.flow_control_error);
                session.peer_initial_window_size = entry.value;
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

fn handleWindowUpdate(session: *Session, stream: u31, increment: u31) void {
    assert(increment >= 1); // The codec refused a zero increment.
    if (stream != 0) return session.requireNotIdle(stream);
    assert(session.send_window <= window_max);
    session.send_window += increment;
    if (session.send_window > window_max) session.fail(.flow_control_error);
}

/// DATA, which today only ever arrives on a stream this side refused —
/// or illegally on an idle one. It is read and dropped, but it still
/// spends the connection's window (§6.9), so the credit has to come back
/// or a client sending a body behind a refused stream would stall the
/// whole connection.
fn handleData(session: *Session, header: frame.Header) void {
    assert(header.stream_identifier != 0); // The codec refused stream 0.
    // The receive window and the credit not yet returned always sum to
    // the starting window: spending moves octets from one to the other,
    // and crediting moves them back. Which is what keeps every credit
    // under `window_max` and the window under where it started.
    assert(session.recv_window + session.recv_unacked == window_initial);
    if (isIdle(session, header.stream_identifier)) return session.fail(.protocol_error);
    // The whole length, padding included, is what flow control counts.
    session.recv_window -= header.length;
    if (session.recv_window < 0) return session.fail(.flow_control_error);
    session.recv_unacked += header.length;
    if (session.recv_unacked * 2 >= window_initial) {
        const credit: u31 = @intCast(session.recv_unacked);
        session.stage(&.{ .window_update = .{ .increment = credit } }, 0, 0);
        session.recv_window += session.recv_unacked;
        session.recv_unacked = 0;
    }
    assert(session.recv_window + session.recv_unacked == window_initial);
}

/// A complete field block. Today every one either opens a stream, which is
/// refused, or arrives on one already refused.
fn handleBlock(session: *Session, block: *const frame.BlockAssembler.Block) void {
    assert(block.frame_type == .headers); // PUSH_PROMISE never got here.
    assert(block.stream_identifier != 0); // The codec refused stream 0.
    // §5.1.1: a client's streams are odd. An even one is a stream only a
    // server may open, and this server never does.
    if (block.stream_identifier % 2 == 0) return session.fail(.protocol_error);
    // Decoded whatever becomes of the stream: the HPACK context is the
    // connection's, so a block skipped is every later block misread.
    if (session.decodeBlock(block.fragment)) |code| return session.fail(code);
    // At or below the high-water mark, the stream is one this side already
    // refused, and §6.4 has a client's frames still in flight then — the
    // trailers of a request it sent before reading our RST_STREAM. Ignored.
    //
    // Ignored too, for now, is the one case this cannot tell apart: a
    // client that skips an identifier and later opens it (5, then 3),
    // which §5.1.1 makes a PROTOCOL_ERROR. Telling them apart takes state
    // per identifier, which arrives with the streams themselves.
    if (block.stream_identifier <= session.last_peer_stream) return;
    session.last_peer_stream = block.stream_identifier;
    session.streams_refused += 1;
    session.resetStream(block.stream_identifier, .refused_stream);
}

/// Run one field block through HPACK, answering null when it decoded, or
/// the code the connection fails with when it did not. Bounded by the
/// decoder: a list past `header_list_size_max` is refused before its fields
/// can outnumber `fieldsMax`.
///
/// Every failure ends the connection, because the decoder stops where it
/// failed and the table is left mid-block. But not every failure is the
/// client's malformation: a list past the size this side advertised, or
/// one past the buffer that size bought, is a client being expensive, and
/// RFC 9113 §7 names that ENHANCE_YOUR_CALM rather than COMPRESSION_ERROR.
fn decodeBlock(session: *Session, fragment: []const u8) ?frame.ErrorCode {
    var iterator = session.decoder.iterate(session.decoded, fragment);
    var fields: u32 = 0;
    while (iterator.next() catch |err| return decodeFailure(err)) |_| : (fields += 1) {
        assert(fields <= session.decoder.fieldsMax());
    }
    assert(fields == iterator.fieldCount());
    return null;
}

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

/// §5.1: a frame that may not arrive on an idle stream. Idle is anything
/// above the high-water mark, and anything even: those are a server's to
/// open, and this one opens none.
fn requireNotIdle(session: *Session, stream: u31) void {
    assert(stream != 0);
    if (isIdle(session, stream)) session.fail(.protocol_error);
}

fn isIdle(session: *const Session, stream: u31) bool {
    assert(stream != 0);
    assert(session.last_peer_stream % 2 == 1 or session.last_peer_stream == 0);
    if (stream % 2 == 0) return true;
    return stream > session.last_peer_stream;
}

/// A stream error (§5.4.2), once the rules that outrank it have had their
/// say. Two do. An open field block admits no other frame at all (§4.3),
/// so a malformed frame inside one is that connection error, whatever its
/// own fault. And a frame other than PRIORITY on an idle stream is a
/// connection error (§5.1) before it is anything else — RST_STREAM may
/// not even name an idle stream. (The third, §3.4's SETTINGS-first rule,
/// already ran in `takeFrame`.) PRIORITY keeps its stream error on an
/// idle stream because §6.3 states it for exactly that frame.
fn streamError(session: *Session, header: frame.Header, code: frame.ErrorCode) void {
    assert(header.stream_identifier != 0);
    assert(session.state == .open);
    if (session.assembler.isOpen()) return session.fail(.protocol_error);
    if (isIdle(session, header.stream_identifier)) {
        if (header.frame_type != .priority) return session.fail(.protocol_error);
    }
    session.resetStream(header.stream_identifier, code);
}

fn resetStream(session: *Session, stream: u31, code: frame.ErrorCode) void {
    assert(stream != 0);
    assert(session.state != .closed);
    session.stage(&.{ .rst_stream = .{ .error_code = code } }, stream, 0);
}

/// A connection error (§5.4.1): GOAWAY, and nothing more is read.
fn fail(session: *Session, code: frame.ErrorCode) void {
    assert(session.state != .closed);
    assert(code != .no_error);
    // The last stream this side might have acted on (§6.8). Every stream
    // so far was refused, and a refused stream is one nothing happened on
    // (§8.7), so that is none of them.
    session.stage(&.{ .goaway = .{
        .last_stream_identifier = 0,
        .error_code = code,
        .debug_data = &.{},
    } }, 0, 0);
    session.state = .closed;
    session.closed_with = code;
}

/// The server preface. Only what differs from RFC 9113's defaults goes
/// out: the frame size, window and table size are the defaults on purpose.
fn stageSettings(session: *Session) void {
    assert(session.outbox_len == 0);
    const entries = [_]struct { frame.payload.Settings.Identifier, u32 }{
        .{ .max_concurrent_streams, session.config.concurrent_streams_max },
        .{ .max_header_list_size, session.config.header_list_size_max },
    };
    comptime assert(entries.len == settings_entries);
    var bytes: [settings_entry_bytes * settings_entries]u8 = undefined;
    for (entries, 0..) |entry, index| {
        const at = index * settings_entry_bytes;
        std.mem.writeInt(u16, bytes[at..][0..2], @backingInt(entry[0]), .big);
        std.mem.writeInt(u32, bytes[at + 2 ..][0..4], entry[1], .big);
    }
    session.stage(&.{ .settings = .{ .entries = &bytes } }, 0, 0);
}

/// Append one frame to the outbox. Room is a precondition: `step` holds
/// back any frame that might need more than `reply_bytes_max`, and `init`
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
