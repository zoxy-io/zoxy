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
//! The streams, outbound: `sendHead`, `sendData` and `sendTrailers` stage
//! the response, its field sections HPACK-encoded against the client's
//! table and checked against the same §8 rules on the way out. A field
//! block is started only when it can be finished, so the tables never fall
//! out of step and nothing lands inside one (§4.3). Body octets go out as
//! both send windows allow. A send cut short — by a window, by outbox room,
//! or by its turn — waits, and `step` hands the waiting streams `.writable`
//! round-robin as each can go on: while others wait for the room or the
//! connection's window, a stream sends one frame per turn, so N streams
//! share the socket by frame and none starves. A stream is gone once both
//! halves have ended (§5.1).
//!
//! Left to the caller, which alone knows the request: that a body adds up
//! to the `content-length` its head declared (§8.1.1 — a HEAD response
//! declares one it never sends), and whether a head is past the client's
//! advisory SETTINGS_MAX_HEADER_LIST_SIZE.

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

/// What a send leaves free in the outbox: one reply and one control frame,
/// so neither `step`'s answer to the next frame nor `flushPending`'s next
/// credit waits behind body octets.
pub const send_reserve: u32 = reply_bytes_max + control_bytes;

/// HPACK's integers, at the protocol's width: every index, length and table
/// size here fits a `u32`.
const Integer = hpack.integer.Integer(u32);

/// The most octets a field's index takes: the static table's entries plus
/// the most a `header_table_size` table holds, at the narrowest prefix any
/// representation uses (RFC 7541 §6.2.2's four bits).
const index_bytes_max: u32 = 3;

/// The table-size updates one block may start with: at most two (RFC 7541
/// §4.2), each at most `header_table_size` behind a 5-bit prefix (§6.3).
const size_updates_bytes_max: u32 = 2 * Integer.encodedLength(header_table_size, 5);

/// The HPACK encoder's arena for response blocks: RFC 7541's default, the
/// size the client's decoder starts at.
pub const EncoderStorage = hpack.Encoder.Storage(header_table_size);

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
    const index_max = hpack.static_table.entries.len + hpack.DynamicTable.entriesRequired(header_table_size);
    assert(Integer.encodedLength(index_max, 4) <= index_bytes_max);
    // An empty outbox always has room past the reserve for a frame header
    // and one octet: the floor every waiting body send is woken against.
    assert(outbox_bytes_min > send_reserve + frame.Header.octets);
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
    /// At least `outbox_bytes_min`, and what bounds a response head: a field
    /// section whose encoding could not fit it is refused.
    outbox: []u8,
    /// HPACK tables: the decoder's for requests, the encoder's for
    /// responses. Both are reset by `init`.
    table: *TableStorage,
    encoder: *EncoderStorage,
};

/// The most fields a list within `list_size_max` can carry: RFC 7541
/// §4.1 charges every field 32 octets of overhead.
pub fn fieldsFor(list_size_max: u32) u32 {
    assert(list_size_max >= 1);
    return @divFloor(list_size_max, 32);
}

/// The most streams one connection advertises (SETTINGS_MAX_CONCURRENT_
/// STREAMS): RFC 9113 §6.5.2's recommended floor, and the cap on how much
/// of the shared stream pool one client can hold (#275).
pub const concurrent_streams_advertised_max: u32 = 100;

/// The resets a session remembers (`reset_ring`): the last this many,
/// however few streams opened meanwhile — twice what one client can have
/// open, so a client's whole table reset at once, and the next, are still
/// remembered while their trailers arrive. A reset forgotten turns a late
/// trailer on it into the connection's PROTOCOL_ERROR; reaching that takes
/// this many resets in between, which a client earns by being reset that
/// often, and losing such a connection is the shed rather than the fault.
pub const reset_ring_len: u32 = 2 * concurrent_streams_advertised_max;

comptime {
    assert(reset_ring_len >= concurrent_streams_advertised_max);
    assert(reset_ring_len >= 1); // `reset_ring_next` wraps modulo it.
}

/// Why a session ended with ENHANCE_YOUR_CALM (RFC 9113 §7: "a behavior
/// that might be generating excessive load"): which of a client's per-connection
/// budgets it overran (#276). Every one is a client inside the protocol's
/// rules and expensive anyway — a malformed one gets PROTOCOL_ERROR — and
/// each has its own counter, so an operator can tell a flood from a bomb.
pub const Calm = enum {
    /// More streams reset by the client before their answers ended than
    /// answers this side finished: CVE-2023-44487's Rapid Reset.
    rapid_reset,
    /// The frames `Unpaid` counts, each past its own bound.
    ping,
    settings,
    window_update,
    ignored,
    empty_data,
    /// A field block across more frames than the assembler allows — the
    /// CONTINUATION flood, which empty fragments make cost no octets.
    continuation,
    /// A field block, or the list it decodes to, past its octet bound: an
    /// HPACK bomb, or a head too large for what this side advertised.
    field_block,
};

/// The frames a client can send that cost this side work and ask for none
/// of its own (#276), counted since the connection last did work for it —
/// a request handed to the caller, or a response frame staged. Each count
/// starts over then; past its bound, the connection ends calm. The bounds
/// are what a client using the connection could spend between two such
/// moments, with room: a PING or a SETTINGS now and then, a WINDOW_UPDATE
/// per stream and the connection's beside each, a PRIORITY per stream.
/// An acknowledgement counts with what it acknowledges: this side sends
/// one SETTINGS and no PING, so every ACK past the first asks nothing.
/// A connection a client only keeps alive — PINGs and nothing else — ends
/// after `max.ping` of them, as gRPC's servers end one for "too many pings".
pub const Unpaid = struct {
    ping: u32 = 0,
    settings: u32 = 0,
    window_update: u32 = 0,
    /// Frames read and set aside: PRIORITY, whose scheme §5.3.2
    /// deprecates and this server does not schedule by, and the types
    /// §5.5 says to ignore. Each costs a parse and nothing more, which is
    /// still a cost a client can repeat.
    ignored: u32 = 0,
    /// DATA with no octets and no END_STREAM: it spends no window, so
    /// nothing else bounds it.
    empty_data: u32 = 0,

    pub const max: Unpaid = .{
        .ping = 32,
        .settings = 16,
        // A burst of credit after a burst of DATA: one per stream, and the
        // connection's between them, twice over.
        .window_update = 4 * concurrent_streams_advertised_max,
        .ignored = 2 * concurrent_streams_advertised_max,
        .empty_data = 32,
    };

    comptime {
        for (@typeInfo(Unpaid).@"struct".field_names) |name| assert(@field(max, name) >= 1);
        // A WINDOW_UPDATE per stream and one for the connection, at once.
        assert(max.window_update >= 2 * concurrent_streams_advertised_max);
        // A PRIORITY per stream a client may open.
        assert(max.ignored >= concurrent_streams_advertised_max);
    }
};

/// The Rapid Reset budget (#276): how far the streams a client reset
/// before their answers ended may outnumber the answers that did. A
/// browser abandoning a page cancels what it had open — at most this
/// many — and pays it back as later answers complete; a client that opens
/// and resets in a loop, each reset sparing it a stream while the work it
/// asked for goes on, never does.
pub const resets_unpaid_max: u32 = concurrent_streams_advertised_max;

comptime {
    // Every stream a client may have open, abandoned at once, is in budget.
    assert(resets_unpaid_max >= concurrent_streams_advertised_max);
    assert(resets_unpaid_max >= 1);
}

/// What one session's buffers are, for a connection advertising
/// `header_list_size_max` and `concurrent_streams_max` — the unit
/// `limits.h2_connections` reserves (§5) — and how they are laid out in
/// it. One statement for both, beside `Buffers`, so the pool that carves
/// a unit, the budget that prices it, and `init` that asserts what it is
/// handed cannot drift apart.
pub const Layout = struct {
    header_list_size_max: u32,
    concurrent_streams_max: u32,

    /// Where every piece of a unit starts: the widest alignment any piece
    /// needs, so one stride serves a whole slab of units and each piece
    /// in each of them.
    pub const unit_align: u32 = @max(
        @alignOf(Session),
        @alignOf(TableStorage),
        @alignOf(EncoderStorage),
        @alignOf(hpack.Field),
        @alignOf(StreamTable.Slot),
    );

    /// A whole frame at the size this server accepts.
    pub fn inboundBytes(layout: Layout) u32 {
        _ = layout;
        return frame_bytes_max;
    }

    /// The compressed block, bounded by the list it decodes to: HPACK
    /// spends fewer octets on a field than §4.1's 32 of list accounting.
    pub fn blockBytes(layout: Layout) u32 {
        assert(layout.header_list_size_max >= 1);
        return layout.header_list_size_max;
    }

    pub fn decodedBytes(layout: Layout) u32 {
        assert(layout.header_list_size_max >= 1);
        return layout.header_list_size_max;
    }

    pub fn fieldsCount(layout: Layout) u32 {
        return fieldsFor(layout.header_list_size_max);
    }

    /// A response head's block — no more than twice the list it encodes,
    /// which covers each field's length prefixes and every CONTINUATION
    /// header — beside a whole DATA frame and the send reserve, so a head
    /// and the body after it never wait on each other for room.
    pub fn outboxBytes(layout: Layout) u32 {
        assert(layout.header_list_size_max >= 1);
        return 2 * layout.header_list_size_max + frame_bytes_max + send_reserve;
    }

    /// One unit: every piece `carve` hands out, each padded to
    /// `unit_align`, so the sum is a stride as well as a size.
    pub fn bytes(layout: Layout) u64 {
        assert(layout.concurrent_streams_max >= 1);
        assert(layout.concurrent_streams_max <= concurrent_streams_advertised_max);
        const total = padded(@sizeOf(Session)) + padded(@sizeOf(TableStorage)) +
            padded(@sizeOf(EncoderStorage)) +
            padded(@as(u64, layout.fieldsCount()) * @sizeOf(hpack.Field)) +
            padded(@as(u64, layout.concurrent_streams_max) * @sizeOf(StreamTable.Slot)) +
            padded(layout.inboundBytes()) + padded(layout.blockBytes()) +
            padded(layout.decodedBytes()) + padded(layout.outboxBytes());
        assert(total % unit_align == 0);
        assert(total > frame_bytes_max);
        return total;
    }

    pub const Carved = struct {
        session: *Session,
        buffers: Buffers,
    };

    /// One unit's pieces, in the order `bytes` prices them — the widest
    /// alignments first only by habit, since every piece starts on
    /// `unit_align` anyway — ready for `Session.init`.
    pub fn carve(layout: Layout, unit: []align(unit_align) u8) Carved {
        assert(unit.len == layout.bytes());
        var cursor: Cursor = .{ .unit = unit };
        const session = &cursor.take(Session, 1)[0];
        const table = &cursor.take(TableStorage, 1)[0];
        const encoder = &cursor.take(EncoderStorage, 1)[0];
        const buffers: Buffers = .{
            .fields = cursor.take(hpack.Field, layout.fieldsCount()),
            .streams = cursor.take(StreamTable.Slot, layout.concurrent_streams_max),
            .inbound = cursor.take(u8, layout.inboundBytes()),
            .block = cursor.take(u8, layout.blockBytes()),
            .decoded = cursor.take(u8, layout.decodedBytes()),
            .outbox = cursor.take(u8, layout.outboxBytes()),
            .table = table,
            .encoder = encoder,
        };
        assert(cursor.offset == unit.len);
        return .{ .session = session, .buffers = buffers };
    }

    fn padded(size: u64) u64 {
        return std.mem.alignForward(u64, size, unit_align);
    }

    const Cursor = struct {
        unit: []align(unit_align) u8,
        offset: usize = 0,

        fn take(cursor: *Cursor, comptime T: type, count: u32) []T {
            assert(cursor.offset % unit_align == 0);
            const size: usize = @as(usize, count) * @sizeOf(T);
            assert(cursor.offset + size <= cursor.unit.len);
            const start: [*]align(unit_align) u8 = @alignCast(cursor.unit[cursor.offset..].ptr);
            cursor.offset += @intCast(padded(size));
            const typed: [*]T = @ptrCast(start);
            return typed[0..count];
        }
    };
};

/// What the caller does next.
pub const Step = union(enum) {
    /// Everything buffered was handled, nothing staged is owed, and no
    /// waiting stream can go on; read more into `recvBuffer`.
    need_input,
    /// The outbox is too full to answer the next frame, or to stage what
    /// this side owes. Send `outbound`, then `step` again before reading.
    flush_first,
    /// The connection is over, and every stream with it: nothing more may
    /// be sent or asked on any of them. Send what `outbound` holds — the
    /// GOAWAY, if this side ended it — and close.
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
    /// A send cut short on this stream can go on: offer its next octets, or
    /// the field section that waited, again. Its turn — not offering is
    /// fine, and the next waiting stream is named at the next `step`.
    writable: Writable,

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
    pub const Writable = struct {
        stream: u31,
    };
};

/// What staging a field section came to.
pub const Sent = enum {
    /// Staged whole.
    staged,
    /// Not now: the outbox lacks room for the block. Nothing was staged;
    /// `.writable` names the stream once there is room.
    blocked,
    /// Never: fields HTTP/2 cannot carry (§8.2, §8.3.2, §8.6), or a block
    /// past what the outbox could hold empty. Nothing was staged, and the
    /// stream is the caller's to reset.
    refused,
};

/// What a body send came to.
pub const DataSent = struct {
    /// Octets of `bytes` staged. Fewer than offered means the stream waits
    /// for `.writable` before the rest.
    taken: u32,
    /// The stream's END_STREAM went out with them.
    ended: bool,
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
/// This side called `goAway` (§6.8): it accepts nothing more, and once
/// the streams it already accepted are done, so is the connection.
self_going_away: bool,
/// That GOAWAY is owed and not yet staged; `flushPending` stages it, as
/// room allows, ahead of anything else it owes.
goaway_owed: bool,
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
/// The streams this side reset most recently: the one case in which a
/// frame on a closed stream is a client's frame in flight rather than a
/// protocol error (§5.1 — "MUST ignore frames that it receives on closed
/// streams after it has sent a RST_STREAM"). A ring, so the oldest are
/// forgotten first, and a client that sends on one of those that late is
/// treated as one that never opened it.
reset_ring: [reset_ring_len]u31,
/// Where the next reset is written: the oldest remembered, once the ring
/// is full. Always below `reset_ring_len`.
reset_ring_next: u32,
/// The highest stream that reached the caller as `.request` — what a
/// GOAWAY of ours names as the last one this side may have acted on.
last_accepted_stream: u31,
/// Which budget the client overran, when this side's GOAWAY said
/// ENHANCE_YOUR_CALM; null otherwise.
calm: ?Calm,
/// The frames that asked nothing, since the connection last did work.
unpaid: Unpaid,
/// Streams the client reset before their answers ended, less the answers
/// that ended since — never below zero.
resets_unpaid: u32,
/// Streams answered with REFUSED_STREAM because the table was full.
streams_refused: u32,
/// The response blocks' encoder, and the table-size change owed at the
/// start of the next block (RFC 7541 §4.2): the lowest capacity the client
/// set since the last block, and the last one.
encoder: hpack.Encoder,
encoder_resize_low: ?u32,
encoder_resize_final: u32,
/// How many streams wait for `.writable`, and the slot the round-robin
/// looks at first.
send_waiting: u32,
send_cursor: u32,

pub fn init(session: *Session, config: Config, buffers: *const Buffers) void {
    assert(config.concurrent_streams_max >= 1);
    assert(config.header_list_size_max >= 1);
    assert(buffers.inbound.len >= frame_bytes_max);
    assert(buffers.outbox.len >= outbox_bytes_min);
    assert(buffers.decoded.len >= config.header_list_size_max);
    assert(buffers.fields.len >= fieldsFor(config.header_list_size_max));
    assert(buffers.streams.len == config.concurrent_streams_max);
    assert(buffers.block.len >= 1);
    buffers.table.* = .{};
    buffers.encoder.* = .{};
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
        .self_going_away = false,
        .goaway_owed = false,
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
        .reset_ring = @splat(0),
        .reset_ring_next = 0,
        .last_accepted_stream = 0,
        .calm = null,
        .unpaid = .{},
        .resets_unpaid = 0,
        .streams_refused = 0,
        .encoder = buffers.encoder.encoder(.dynamic),
        .encoder_resize_low = null,
        .encoder_resize_final = header_table_size,
        .send_waiting = 0,
        .send_cursor = 0,
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
/// so a send in flight can borrow them while `step` appends more. Room
/// comes back once all of it is sent, and the caller steps then, input or
/// not: a stream waiting for that room hears of it from `step`.
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
/// the client may retry) — never for one it did. NO_ERROR only once the
/// response is complete, to stop a request body nobody will read (§8.1).
pub fn resetStream(session: *Session, stream: u31, code: frame.ErrorCode) void {
    assert(stream != 0);
    const slot = session.streams.find(stream).?;
    assert(slot.state != .reset_pending);
    if (code == .no_error) assert(slot.state == .half_closed_local);
    session.unwait(slot);
    slot.state = .reset_pending;
    slot.reset_code = code;
    session.pending = true;
}

/// Whether `stream` is still sending while this side has finished: its
/// END_STREAM is staged and the client's is not in, so the request's rest
/// is arriving for an exchange that answered without it — the case
/// RST_STREAM(NO_ERROR) exists to stop (§8.1). False once the stream is
/// gone, which is where a client that had finished first leaves it — and
/// once the session is: the answer that ended a draining connection's
/// last stream closed it.
pub fn awaitingClient(session: *Session, stream: u31) bool {
    assert(stream != 0);
    if (session.state == .closed) return false;
    const slot = session.streams.find(stream) orelse return false;
    return slot.state == .half_closed_local;
}

/// What `step` stages before it reads: the RST_STREAMs, WINDOW_UPDATEs and
/// GOAWAY this side owes — without reading input or raising an event, for
/// a caller that could not take one now (`Driver.kick` under a borrow).
pub fn stagePending(session: *Session) void {
    if (session.state == .closed) return;
    assert(session.event == null);
    if (session.pending) session.flushPending();
}

/// Whether `stream` is still this side's to reset: the session holds it
/// and nothing has ended it — the client's reset, or one already said.
pub fn resettable(session: *Session, stream: u31) bool {
    assert(stream != 0);
    if (session.state == .closed) return false;
    const slot = session.streams.find(stream) orelse return false;
    return slot.state != .reset_pending;
}

/// End the connection gracefully (§6.8): GOAWAY(NO_ERROR) naming the last
/// stream the caller was handed, every stream after it refused, and the
/// connection over once the ones before it finish — a drain, not an error,
/// so `closed_with` stays null. Staged at the next `step`, which is where
/// room is found; idempotent, since a drain can be asked for twice.
pub fn goAway(session: *Session) void {
    assert(session.state != .closed);
    if (session.self_going_away) return;
    session.self_going_away = true;
    session.goaway_owed = true;
    session.pending = true;
    assert(session.goingAway());
}

/// Stage a response head on `stream`: interim ones (1xx) first, as many as
/// there are, then the final one — with END_STREAM when no body follows.
/// The fields borrow nothing past the call. After the client's half and
/// this one have both ended, the stream is gone.
pub fn sendHead(session: *Session, stream: u31, fields: []const hpack.Field, end_stream: bool) Sent {
    const slot = session.sendable(stream);
    assert(!slot.head_sent);
    const status = responseStatus(fields) orelse return .refused;
    // §8.6: HTTP/2 has no 101; and §8.1: an interim response ends nothing.
    if (status == 101) return .refused;
    const interim = status < 200;
    if (interim) assert(!end_stream);
    const sent = session.sendFields(slot, fields, .response, end_stream);
    if (sent != .staged) return sent;
    if (!interim) slot.head_sent = true;
    if (end_stream) session.endLocal(slot);
    return .staged;
}

/// Stage `stream`'s trailer section: after the final head and its body,
/// and it ends the stream (§8.1).
pub fn sendTrailers(session: *Session, stream: u31, fields: []const hpack.Field) Sent {
    const slot = session.sendable(stream);
    assert(slot.head_sent);
    const sent = session.sendFields(slot, fields, .trailer, true);
    if (sent == .staged) session.endLocal(slot);
    return sent;
}

/// Stage body octets on `stream`, after its final head: as many as both
/// windows, the client's frame size and the outbox allow — one frame only
/// while other streams wait their turn. END_STREAM goes with the last
/// octet, or alone when `bytes` is empty.
pub fn sendData(session: *Session, stream: u31, bytes: []const u8, end_stream: bool) DataSent {
    const slot = session.sendable(stream);
    assert(slot.head_sent);
    if (bytes.len == 0) assert(end_stream);
    if (bytes.len == 0) {
        if (session.sendRoom() < frame.Header.octets) {
            session.wait(slot, .room, frame.Header.octets);
            return .{ .taken = 0, .ended = false };
        }
        session.stageData(slot, &.{}, true);
        return .{ .taken = 0, .ended = true };
    }
    assert(bytes.len <= std.math.maxInt(u32));
    const length: u32 = @intCast(bytes.len);
    // Every pass stages at least one octet or stops, so the octets bound it.
    const frames_max: u32 = if (session.othersCompeting(slot)) 1 else length;
    var taken: u32 = 0;
    var frames: u32 = 0;
    while (frames < frames_max) : (frames += 1) {
        const room = session.sendRoom();
        const window = @min(slot.send_window, session.send_window);
        if (room <= frame.Header.octets or window <= 0) break;
        const count: u32 = @intCast(@min(length - taken, window, session.peer_frame_size_max, room - frame.Header.octets));
        assert(count >= 1);
        const last = taken + count == length;
        session.stageData(slot, bytes[taken..][0..count], last and end_stream);
        taken += count;
        if (last) break;
    }
    assert(taken <= length);
    const sent: DataSent = .{ .taken = taken, .ended = taken == length and end_stream };
    // An ended stream may be gone already; one with more to say waits.
    if (sent.ended) return sent;
    if (taken == length) {
        session.unwait(slot);
    } else {
        session.wait(slot, .data, 0);
    }
    return sent;
}

fn outboxRoom(session: *const Session) u32 {
    assert(session.outbox_len <= session.outbox.len);
    return @intCast(session.outbox.len - session.outbox_len);
}

/// The room a send may take: all of it but `send_reserve`.
fn sendRoom(session: *const Session) u32 {
    const room = session.outboxRoom() -| send_reserve;
    assert(room + send_reserve <= session.outbox.len);
    return room;
}

/// The slot of a stream this side may still send on: open, or with only
/// this side's half left. Anything else is the caller's error — it heard
/// the stream end, or ended it.
fn sendable(session: *Session, stream: u31) *StreamTable.Slot {
    assert(stream != 0);
    assert(session.state == .open);
    const slot = session.streams.find(stream).?;
    assert(slot.state == .open or slot.state == .half_closed_remote);
    return slot;
}

/// The three-digit `:status` a response head leads with (§8.3.2), or null
/// when it does not — a head the validator would refuse anyway, read here
/// first to tell an interim response from the final one.
fn responseStatus(fields: []const hpack.Field) ?u16 {
    if (fields.len == 0) return null;
    if (!std.mem.eql(u8, fields[0].name, ":status")) return null;
    const value = fields[0].value;
    if (value.len != 3) return null;
    if (value[0] < '1' or value[0] > '5') return null;
    const status = std.fmt.parseUnsigned(u16, value, 10) catch return null;
    assert(status >= 100);
    assert(status <= 599);
    return status;
}

/// One field section, validated as §8 wants it and staged whole — or not
/// at all, when it waits for room or can never be sent.
fn sendFields(session: *Session, slot: *StreamTable.Slot, fields: []const hpack.Field, kind: MessageValidator.Kind, end_stream: bool) Sent {
    assert(slot.state == .open or slot.state == .half_closed_remote);
    assert(kind != .request);
    if (!fieldsValid(fields, kind)) return .refused;
    const block_max = blockBound(fields);
    const needed = block_max + frame.Header.octets * framesFor(block_max, session.peer_frame_size_max);
    if (needed > session.outbox.len - send_reserve) return .refused;
    if (needed > session.sendRoom()) {
        session.wait(slot, .room, @intCast(needed));
        return .blocked;
    }
    session.unwait(slot);
    session.stageBlock(slot.id, fields, @intCast(block_max), end_stream);
    session.paid();
    return .staged;
}

/// The same `.strict` rules a request is read under: these fields are an
/// HTTP/1.1 origin's, and nothing it says reaches the client that the
/// client's own HTTP/2 stack would call malformed.
fn fieldsValid(fields: []const hpack.Field, kind: MessageValidator.Kind) bool {
    assert(kind != .request);
    assert(fields.len <= std.math.maxInt(u32));
    var validator = MessageValidator.init(.{ .kind = kind, .rules = .strict });
    for (fields) |*field| validator.field(field) catch return false;
    validator.finish() catch return false;
    return true;
}

/// An upper bound on the octets `fields` encode to, table-size updates
/// included. Only a block known to fit is started: one cut short would
/// leave the two HPACK tables out of step or another frame inside it.
fn blockBound(fields: []const hpack.Field) u64 {
    var bound: u64 = size_updates_bytes_max;
    for (fields) |*field| bound += fieldBound(field);
    assert(bound >= size_updates_bytes_max);
    return bound;
}

/// RFC 7541 §6: every representation is at most an index, a name and a
/// value, each string behind its length. Huffman coding is used only when
/// it is shorter, so the raw lengths bound the coded ones.
fn fieldBound(field: *const hpack.Field) u64 {
    assert(field.name.len <= std.math.maxInt(u32));
    assert(field.value.len <= std.math.maxInt(u32));
    const name: u32 = @intCast(field.name.len);
    const value: u32 = @intCast(field.value.len);
    return @as(u64, index_bytes_max) + Integer.encodedLength(name, 7) + name +
        Integer.encodedLength(value, 7) + value;
}

/// The frames a block of `octets` takes at `fragment_max` octets each: a
/// HEADERS, and a CONTINUATION per further fragment (§6.10).
fn framesFor(octets: u64, fragment_max: u32) u64 {
    assert(fragment_max >= frame.Header.max_frame_size_min);
    if (octets == 0) return 1;
    const frames = std.math.divCeil(u64, octets, fragment_max) catch unreachable;
    assert(frames * fragment_max >= octets);
    return frames;
}

/// Encode `fields` behind the next frame header, then spread the block
/// over as many frames as the client's frame size makes it. The room was
/// checked against `block_max`, which the encoding cannot pass.
fn stageBlock(session: *Session, stream: u31, fields: []const hpack.Field, block_max: u32, end_stream: bool) void {
    const start = session.outbox_len + frame.Header.octets;
    const target = session.outbox[start..][0..block_max];
    var written = session.encodeResize(target);
    const encoded = session.encoder.encode(target[written..], fields);
    assert(encoded.fields == fields.len); // The bound held.
    written += encoded.written;
    assert(written <= block_max);
    session.spreadBlock(stream, written, end_stream);
}

/// RFC 7541 §4.2: a table size the client changed since the last block is
/// signalled at the start of this one — the lowest it went to, then where
/// it ended. Both are clamped to the arena, so neither can be refused.
fn encodeResize(session: *Session, target: []u8) u32 {
    assert(target.len >= size_updates_bytes_max);
    const low = session.encoder_resize_low orelse return 0;
    session.encoder_resize_low = null;
    const final = session.encoder_resize_final;
    if (low == final and final == session.encoder.table.capacity) return 0;
    var written = session.encoder.encodeSizeUpdate(target, low) catch unreachable;
    if (final != low) {
        written += session.encoder.encodeSizeUpdate(target[written..], final) catch unreachable;
    }
    assert(written <= size_updates_bytes_max);
    return written;
}

/// The block sits behind one frame header; give each fragment past the
/// first its own CONTINUATION header, moving the fragments back to front
/// so none is overwritten before it moved. END_STREAM rides the HEADERS
/// frame and END_HEADERS the last (§6.2, §6.10).
fn spreadBlock(session: *Session, stream: u31, length: u32, end_stream: bool) void {
    const fragment_max = session.peer_frame_size_max;
    const frames: u32 = @intCast(framesFor(length, fragment_max));
    const first = session.outbox_len;
    var moving: u32 = frames;
    while (moving > 1) {
        moving -= 1;
        const from = first + frame.Header.octets + moving * fragment_max;
        const fragment = @min(fragment_max, length - moving * fragment_max);
        const to = from + moving * frame.Header.octets;
        std.mem.copyBackwards(u8, session.outbox[to..][0..fragment], session.outbox[from..][0..fragment]);
    }
    var index: u32 = 0;
    while (index < frames) : (index += 1) {
        const at = first + index * (frame.Header.octets + fragment_max);
        var flags: u8 = 0;
        if (index == 0 and end_stream) flags |= frame.Flag.end_stream.bit();
        if (index + 1 == frames) flags |= frame.Flag.end_headers.bit();
        const header: frame.Header = .{
            .length = @intCast(@min(fragment_max, length - index * fragment_max)),
            .frame_type = if (index == 0) .headers else .continuation,
            .flags = flags,
            .stream_identifier = stream,
        };
        _ = header.render(session.outbox[at..]) catch unreachable;
    }
    session.outbox_len += length + frames * frame.Header.octets;
    assert(session.outbox_len <= session.outbox.len - send_reserve);
}

/// One DATA frame, in room already checked, paid for from both windows.
fn stageData(session: *Session, slot: *StreamTable.Slot, bytes: []const u8, end_stream: bool) void {
    assert(bytes.len <= session.peer_frame_size_max);
    assert(frame.Header.octets + bytes.len <= session.sendRoom());
    const flags: u8 = if (end_stream) frame.Flag.end_stream.bit() else 0;
    session.stage(&.{ .data = .{ .data = bytes, .padding = null } }, slot.id, flags);
    if (bytes.len >= 1) {
        slot.send_window -= @intCast(bytes.len);
        session.send_window -= @intCast(bytes.len);
        assert(slot.send_window >= 0);
        assert(session.send_window >= 0);
        session.paid();
    }
    if (end_stream) session.endLocal(slot);
}

/// This side's END_STREAM is staged: the stream is half closed, or — the
/// client's half already over — closed, and its slot goes back.
fn endLocal(session: *Session, slot: *StreamTable.Slot) void {
    assert(slot.id != 0);
    assert(session.state == .open);
    // An answer ended: one reset before its answer is paid for.
    session.resets_unpaid -|= 1;
    session.unwait(slot);
    switch (slot.state) {
        .open => slot.state = .half_closed_local,
        .half_closed_remote => session.releaseStream(slot),
        .half_closed_local, .reset_pending => unreachable, // `sendable` refused these.
    }
}

/// The client's END_STREAM: the stream is half closed, or — this side's
/// half already over — closed, and its slot goes back.
fn endRemote(session: *Session, slot: *StreamTable.Slot) void {
    assert(slot.id != 0);
    // Only a stream whose own half is open can be waiting to send.
    if (slot.send_wait != .none) assert(slot.state == .open);
    switch (slot.state) {
        .open => slot.state = .half_closed_remote,
        .half_closed_local => session.releaseStream(slot),
        .half_closed_remote, .reset_pending => unreachable, // Answered before here.
    }
}

/// A send cut short: the stream waits for `.writable`, needing `room`
/// octets of outbox for a field block or an empty END_STREAM, or open
/// windows and room for one frame for body octets.
fn wait(session: *Session, slot: *StreamTable.Slot, wait_for: StreamTable.Slot.SendWait, room: u32) void {
    assert(wait_for != .none);
    assert((wait_for == .room) == (room >= 1));
    if (slot.send_wait == .none) session.send_waiting += 1;
    slot.send_wait = wait_for;
    slot.send_room_needed = room;
    assert(session.send_waiting <= session.streams.used);
}

fn unwait(session: *Session, slot: *StreamTable.Slot) void {
    assert(slot.id != 0);
    if (slot.send_wait == .none) return;
    assert(session.send_waiting >= 1);
    session.send_waiting -= 1;
    slot.send_wait = .none;
    slot.send_room_needed = 0;
}

/// Whether another waiting stream wants what this send would take — the
/// outbox and the connection's window, which every stream shares. One
/// stalled on its own window wants neither, so it costs the others no
/// turn: a client slow to read one stream does not throttle the rest.
fn othersCompeting(session: *const Session, slot: *const StreamTable.Slot) bool {
    const own: u32 = @intFromBool(slot.send_wait != .none);
    assert(session.send_waiting >= own);
    assert(session.send_waiting <= session.streams.used);
    if (session.send_waiting == own) return false;
    for (session.streams.slots) |*other| {
        if (other.id == 0 or other == slot) continue;
        switch (other.send_wait) {
            .none => {},
            .room => return true,
            .data => if (other.send_window > 0) return true,
        }
    }
    return false;
}

/// The scheduler: the next waiting stream, round-robin from the slot after
/// the last one named, whose send can now make progress. At most one per
/// `step`; the one named stops waiting, and offers again or not.
fn nextWritable(session: *Session) ?u31 {
    if (session.send_waiting == 0) return null;
    const slots = session.streams.slots;
    assert(session.send_cursor < slots.len);
    for (0..slots.len) |offset| {
        const index = (session.send_cursor + offset) % slots.len;
        const slot = &slots[index];
        if (slot.id == 0 or !session.canSend(slot)) continue;
        session.send_cursor = @intCast((index + 1) % slots.len);
        session.unwait(slot);
        assert(slot.send_wait == .none);
        return slot.id;
    }
    return null;
}

/// Whether what `slot` waits for is there: a frame's room, and for body
/// octets an open window on both levels — the same tests the next send
/// makes, so a stream named can go on. (A field block can wait again if
/// the client shrank its frame size in between, which adds frames to it;
/// it then waits afresh, and nothing spins.)
fn canSend(session: *const Session, slot: *const StreamTable.Slot) bool {
    assert(slot.id != 0);
    // A stream waits only while its own half is open: ending it, or a reset,
    // took it out of the queue.
    if (slot.send_wait != .none) assert(slot.state == .open or slot.state == .half_closed_remote);
    return switch (slot.send_wait) {
        .none => false,
        .room => session.sendRoom() >= slot.send_room_needed,
        .data => session.sendRoom() > frame.Header.octets and
            slot.send_window > 0 and session.send_window > 0,
    };
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
    if (session.nextWritable()) |stream| return .{ .writable = .{ .stream = stream } };
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
    const accepted = session.assembler.accept(header, &payload) catch |err| switch (err) {
        // Its bounds: a client inside §4.3's rules and expensive anyway.
        error.TooManyFrames => return session.failCalm(.continuation),
        error.BlockTooLarge => return session.failCalm(.field_block),
        error.UnexpectedContinuation,
        error.InterleavedFrame,
        => return session.fail(frame.BlockAssembler.errorCode(err)),
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
            if (!session.spend(.ping)) return;
            if (header.has(.ack)) return; // An answer to a PING we never sent.
            session.stage(&.{ .ping = .{ .opaque_data = ping.opaque_data } }, 0, frame.Flag.ack.bit());
        },
        .goaway => session.handleGoaway(),
        .window_update => |update| {
            if (!session.spend(.window_update)) return;
            session.handleWindowUpdate(header.stream_identifier, update.increment);
        },
        .data => |data| {
            // No octets, so no window spent, and no END_STREAM, so no
            // end: a frame that says nothing, and only its budget stops
            // it. One that pads is spending window, which bounds it.
            if (header.length == 0 and !header.has(.end_stream)) {
                if (!session.spend(.empty_data)) return;
            }
            session.handleData(header, data);
        },
        .rst_stream => |reset| session.handlePeerReset(header.stream_identifier, reset.error_code),
        // §5.3.2's priority scheme is deprecated and this server does
        // not schedule by it, so PRIORITY is legal anywhere and read
        // never; and §4.1 and §5.5 say an unknown type is ignored. Each
        // is still a frame parsed, and budgeted.
        .priority, .unknown => _ = session.spend(.ignored),
        // The assembler takes every field-block frame, and PUSH_PROMISE
        // failed the connection before it got here.
        .headers, .continuation, .push_promise => unreachable,
    }
}

/// §6.5: apply the client's settings, then acknowledge them — or take its
/// acknowledgement of ours.
fn handleSettings(session: *Session, header: frame.Header, settings: frame.payload.Settings) void {
    assert(header.stream_identifier == 0);
    if (!session.spend(.settings)) return;
    if (header.has(.ack)) return session.takeSettingsAck();
    // INITIAL_WINDOW_SIZE moves every stream's window, so it is applied
    // once, after the frame — a frame of nothing else would otherwise cost
    // its entries times the streams (#276). Applying the last value is
    // what applying each in turn comes to, and since every window moves by
    // the same difference, one would have passed 2^31-1 at some entry
    // exactly when one passes it at the frame's highest.
    var window_last: ?u31 = null;
    var window_highest: u31 = 0;
    var entries = settings.iterate();
    while (entries.next()) |entry| {
        switch (entry.identifier) {
            // §6.5.2: 0 or 1. Its value is moot — a client cannot be
            // pushed to by a server that never pushes — but its range is
            // still the rule.
            .enable_push => if (entry.value > 1) return session.fail(.protocol_error),
            .initial_window_size => {
                if (entry.value > window_max) return session.fail(.flow_control_error);
                const size: u31 = @intCast(entry.value);
                window_last = size;
                window_highest = @max(window_highest, size);
            },
            .max_frame_size => {
                if (entry.value < frame.Header.max_frame_size_min) return session.fail(.protocol_error);
                if (entry.value > frame.Header.max_frame_size_max) return session.fail(.protocol_error);
                session.peer_frame_size_max = entry.value;
            },
            .header_table_size => session.retuneEncoder(entry.value),
            .max_header_list_size => session.peer_header_list_size_max = entry.value,
            // It bounds the streams *this* side may open, and a server
            // that never pushes opens none.
            .max_concurrent_streams => {},
            // §6.5.2: an identifier this side does not know is ignored.
            _ => {},
        }
    }
    if (window_last) |size| {
        if (!session.retunePeerWindows(size, window_highest)) return session.fail(.flow_control_error);
    }
    if (session.state == .awaiting_settings) session.state = .open;
    assert(session.state == .open);
    session.stage(&.{ .settings = .{ .entries = &.{} } }, 0, frame.Flag.ack.bit());
}

/// §6.9.2: a new SETTINGS_INITIAL_WINDOW_SIZE from the client moves every
/// stream's send window by the difference. Answers false when one would
/// pass 2^31-1 — at `size`, or at `highest`, the largest value its frame
/// set on the way — which is the connection's flow-control error.
fn retunePeerWindows(session: *Session, size: u31, highest: u31) bool {
    assert(size <= highest);
    assert(highest <= window_max);
    const delta: i64 = @as(i64, size) - @as(i64, session.peer_initial_window_size);
    const delta_highest: i64 = @as(i64, highest) - @as(i64, session.peer_initial_window_size);
    session.peer_initial_window_size = size;
    for (session.streams.slots) |*slot| {
        if (slot.id == 0) continue;
        if (slot.send_window + delta_highest > window_max) return false;
        slot.send_window += delta;
    }
    return true;
}

/// The client's decoder bound (§6.5.2). The encoder follows it down, and
/// back up only as far as its own arena; the update goes out at the start
/// of the next block, which is after this SETTINGS' ACK on the wire.
fn retuneEncoder(session: *Session, value: u32) void {
    const capacity = @min(value, header_table_size);
    assert(capacity <= value);
    assert(capacity <= session.encoder.table.capacityMax());
    session.peer_header_table_size = value;
    session.encoder_resize_low = @min(session.encoder_resize_low orelse capacity, capacity);
    session.encoder_resize_final = capacity;
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
    if (session.streams.used == 0) session.closeIfGoneAway();
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
    // Reset before this side's answer ended: the work it asked for may
    // still be going on, and the stream it held is the client's again.
    // Charged before the release, which may close a connection that is
    // going away — the overrun is the verdict, not that close.
    if (!caller_reset and slot.state != .half_closed_local) {
        assert(session.resets_unpaid <= resets_unpaid_max);
        session.resets_unpaid += 1;
        if (session.resets_unpaid > resets_unpaid_max) return session.failCalm(.rapid_reset);
    }
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
        .open, .half_closed_local => {},
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
    assert(slot.state == .open or slot.state == .half_closed_local);
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
    const stream = slot.id;
    if (end_stream) session.endRemote(slot);
    if (length == 0 and !end_stream) return; // Nothing to hand over.
    session.event = .{ .data = .{ .stream = stream, .bytes = bytes, .end_stream = end_stream } };
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
        .connection => |err| return session.failDecode(err),
        .malformed, .ok => {},
    }
    // At or below the high-water mark and not open. A stream this side
    // reset may still have the client's trailers in flight, which §5.1
    // says to ignore; anything else — an identifier the client skipped and
    // now opens, or a closed stream it sends on again — is §5.1.1's
    // PROTOCOL_ERROR, since a client's identifiers only go up.
    if (!opening) {
        if (session.resetByUs(block.stream_identifier)) return;
        return session.fail(.protocol_error);
    }
    session.last_peer_stream = block.stream_identifier;
    // Either side's GOAWAY: the client said it would open nothing more,
    // or this side said it would accept nothing more. Refused either way —
    // REFUSED_STREAM, which tells the client nothing happened (§8.7).
    if (session.goingAway()) return session.refuse(block.stream_identifier, .refused_stream);
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
    session.paid();
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
        .connection => |err| return session.failDecode(err),
        .malformed => null,
        .ok => |ok| ok.count,
    };
    switch (slot.state) {
        .open, .half_closed_local => {},
        .half_closed_remote => return session.resetAccepted(slot, .stream_closed), // §5.1.
        .reset_pending => return, // Its reset is already owed.
    }
    if (!block.end_stream) return session.resetAccepted(slot, .protocol_error);
    if (count == null) return session.resetAccepted(slot, .protocol_error);
    if (slot.content_length) |declared| {
        if (slot.data_received != declared) return session.resetAccepted(slot, .protocol_error);
    }
    const stream = slot.id;
    session.endRemote(slot);
    session.event = .{ .trailers = .{ .stream = stream, .fields = session.fields[0..count.?] } };
}

const Decoded = union(enum) {
    /// HPACK itself failed: the table is mid-block, and the connection
    /// ends (`failDecode`).
    connection: hpack.Decoder.Error,
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
    while (iterator.next() catch |err| return .{ .connection = err }) |field| : (count += 1) {
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

/// Fail the connection for an HPACK failure: every one ends it, because
/// the decoder stops where it failed and the table is left mid-block. Not
/// every one is the client's malformation: a list past the size this side
/// advertised, or one past the buffer that size bought, is a client being
/// expensive — RFC 9113 §7's ENHANCE_YOUR_CALM rather than
/// COMPRESSION_ERROR, recorded as the field block's budget.
fn failDecode(session: *Session, err: hpack.Decoder.Error) void {
    assert(session.state != .closed);
    return switch (err) {
        error.HeaderListTooLarge, error.OutputTooLong => session.failCalm(.field_block),
        error.Incomplete,
        error.InvalidIndex,
        error.InvalidHuffman,
        error.IntegerTooLarge,
        error.CapacityTooLarge,
        error.UnexpectedSizeUpdate,
        error.TooManySizeUpdates,
        => session.fail(.compression_error),
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
    session.unwait(slot);
    assert(slot.recv_window + slot.recv_unacked + slot.recv_delivered == session.streamWindow());
    assert(session.recv_delivered >= slot.recv_delivered);
    session.recv_delivered -= slot.recv_delivered;
    session.recv_unacked += slot.recv_delivered;
    if (session.recv_unacked >= 1) session.pending = true;
    session.streams.release(slot);
    if (session.streams.used == 0) session.closeIfGoneAway();
}

/// Whether either side has said this connection takes no new streams.
fn goingAway(session: *const Session) bool {
    return session.peer_going_away or session.self_going_away;
}

/// With no stream left, a connection either side is ending is over —
/// once this side's own GOAWAY, if it owes one, is staged to say so.
fn closeIfGoneAway(session: *Session) void {
    assert(session.streams.used == 0);
    assert(session.state != .closed);
    if (session.goaway_owed) return;
    if (session.goingAway()) session.state = .closed;
}

/// Credits and caller resets, staged as room allows while `reply_bytes_max`
/// stays in reserve for the next frame. What does not fit stays pending.
fn flushPending(session: *Session) void {
    assert(session.state != .closed);
    session.pending = false;
    if (session.goaway_owed) {
        // A reply's reserve stays behind it, as behind everything here;
        // an empty outbox always has room (`outbox_bytes_min`).
        if (session.outboxRoom() < 2 * reply_bytes_max) {
            session.pending = true;
            return;
        }
        session.stageGoaway(.no_error);
        session.goaway_owed = false;
        if (session.streams.used == 0) return session.closeIfGoneAway();
    }
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
    assert(slot.state == .open or slot.state == .half_closed_local);
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
    assert(session.reset_ring_next < reset_ring_len);
    session.reset_ring[session.reset_ring_next] = stream;
    session.reset_ring_next = (session.reset_ring_next + 1) % reset_ring_len;
}

/// Whether this side reset `stream` recently enough to remember it.
fn resetByUs(session: *const Session, stream: u31) bool {
    assert(stream != 0); // The ring's empty entries never match.
    assert(stream <= session.last_peer_stream);
    for (session.reset_ring) |id| {
        if (id == stream) return true;
    }
    return false;
}

/// A connection error (§5.4.1): GOAWAY, and nothing more is read.
fn fail(session: *Session, code: frame.ErrorCode) void {
    assert(session.state != .closed);
    assert(code != .no_error);
    // A calm close names its cause, which only `failCalm` records.
    if (code == .enhance_your_calm) assert(session.calm != null);
    session.stageGoaway(code);
    session.state = .closed;
    session.closed_with = code;
    session.event = null;
}

/// A connection error for a client that overran `cause`'s budget.
fn failCalm(session: *Session, cause: Calm) void {
    assert(session.state != .closed);
    assert(session.calm == null);
    session.calm = cause;
    session.fail(.enhance_your_calm);
}

/// Count one frame against `kind`'s budget. False once the client has
/// overrun it: the connection is failing, and the frame goes unanswered.
fn spend(session: *Session, comptime kind: Calm) bool {
    assert(session.state != .closed);
    const count = &@field(session.unpaid, @tagName(kind));
    const bound = @field(Unpaid.max, @tagName(kind));
    assert(count.* <= bound);
    count.* += 1;
    if (count.* <= bound) return true;
    session.failCalm(kind);
    return false;
}

/// The connection did work for the client: every count `Unpaid` keeps
/// starts over.
fn paid(session: *Session) void {
    assert(session.state != .closed);
    session.unpaid = .{};
}

/// §6.8: GOAWAY naming the last stream this side may have acted on — the
/// highest one the caller was handed. A stream this session refused itself
/// never reached the caller (§8.7), so it does not count; one the caller
/// reset after being handed it does — the bound is conservative there, and
/// the stream's own RST_STREAM already told the client what happened.
fn stageGoaway(session: *Session, code: frame.ErrorCode) void {
    assert(session.state != .closed);
    assert(session.outboxRoom() >= reply_bytes_max);
    session.stage(&.{ .goaway = .{
        .last_stream_identifier = session.last_accepted_stream,
        .error_code = code,
        .debug_data = &.{},
    } }, 0, 0);
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
/// `flushPending` keeps that reserve behind what it stages, a send keeps
/// `send_reserve` behind what it stages, and `init` stages only the
/// SETTINGS the outbox was sized for.
fn stage(session: *Session, payload: *const frame.Payload, stream: u31, flags: u8) void {
    assert(session.outbox_len <= session.outbox.len);
    const target = session.outbox[session.outbox_len..];
    // Every frame staged here is a known type rendered into room checked
    // for it — so neither of render's refusals (an unknown type, a target
    // too short) can happen.
    const written = frame.payload.render(payload, stream, flags, target) catch unreachable;
    assert(written >= frame.Header.octets);
    assert(written <= target.len);
    session.outbox_len += written;
}
