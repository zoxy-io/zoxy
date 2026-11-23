//! An HTTP/3 request stream's exchange (#449): the request a HEADERS frame
//! delivered, run through §7 on a shared stream slot, and the answer handed
//! back to the session as frames.
//!
//! The exchange is HTTP/2's, which is HTTP/1.1's (`../h2/exchange.zig`).
//! A request's field section is decoded against QPACK's static table into
//! the same `Field`s HPACK yields, written out by `downgrade` as the
//! HTTP/1.1 head it stands for and read back by the parser, so every §7
//! rule holds byte for byte; the answer is mapped back by `response` and
//! said as HEADERS and DATA. What is here is HTTP/3's half of the client
//! side: opening a request, and the session calls the shared exchange
//! makes through `Half` — staging an answer's frames, stopping or
//! cancelling a stream, and reading more of a body once there is room.
//!
//! What fails on a stream ends the stream, never its connection: it is
//! cancelled — reset and told to stop, RFC 9114 §4.1.1 — and whatever it
//! has in flight is forced before the slot goes back.
//!
//! A request body arrives as DATA and is read only as far as its relay
//! buffer has room (`Shared.dataRoom`): the rest stays in the transport,
//! and QUIC's stream flow control holds the client to it. Each body frame
//! the origin takes makes room, and the stream is read again.

const std = @import("std");
const h3 = @import("h3");

const Runtime = @import("../../extension.zig").Runtime;
const constants = @import("../../constants.zig");
const downgrade = @import("../h2/downgrade.zig");
const H2Session = @import("../h2/Session.zig");

const Field = h3.qpack.Field;
const ApplicationCode = h3.quic.error_code.Application;
const assert = std.debug.assert;

/// Where a request's field section is decoded and an answer's encoded:
/// one per process, lent for the span of one decode or one encode, and
/// nothing borrows it past the call that filled it — `downgrade` copies a
/// request into its stream's head buffer, and the transport copies a
/// frame into its stream's send buffer.
pub const Scratch = struct {
    /// QPACK's working space for a Huffman string's expansion.
    expand: []u8,
    /// The decoded names and values a request's fields point into.
    storage: []u8,
    fields: []Field,
    /// An answer's HEADERS frame, encoded before it is written whole.
    encoded: []u8,
    /// The two halves are lent apart: a request decoded and written out,
    /// and an answer encoded, never both at once — but an answer can be
    /// staged while the request that earned it is still being opened.
    decoding: bool,
    encoding: bool,

    /// A section the client keeps to decodes within it (RFC 9114 §4.2.2).
    pub const expand_bytes: u32 = constants.h3_field_section_bytes_max;
    pub const storage_bytes: u32 = constants.h3_field_section_bytes_max;
    /// Every header the parser admits, beside the four request pseudo
    /// fields.
    pub const fields_count: u32 = @as(u32, constants.headers_max) + 4;
    /// A HEADERS frame is written whole into its stream's send buffer, so
    /// one larger could never be written at all: the encode refuses it.
    pub const encoded_bytes: u32 = constants.h3_stream_send_bytes;

    /// The closed form the budget prices.
    pub const bytes: u64 = expand_bytes + storage_bytes + encoded_bytes +
        @as(u64, fields_count) * @sizeOf(Field);

    pub fn init(arena: std.mem.Allocator) error{OutOfMemory}!Scratch {
        const scratch: Scratch = .{
            .expand = try arena.alloc(u8, expand_bytes),
            .storage = try arena.alloc(u8, storage_bytes),
            .fields = try arena.alloc(Field, fields_count),
            .encoded = try arena.alloc(u8, encoded_bytes),
            .decoding = false,
            .encoding = false,
        };
        assert(scratch.fields.len == fields_count);
        assert(scratch.expand.len + scratch.storage.len + scratch.encoded.len +
            scratch.fields.len * @sizeOf(Field) == bytes);
        return scratch;
    }

    /// A deployment that speaks no HTTP/3 reserves none.
    pub const empty: Scratch = .{
        .expand = &.{},
        .storage = &.{},
        .fields = &.{},
        .encoded = &.{},
        .decoding = false,
        .encoding = false,
    };

    fn lendDecode(scratch: *Scratch) void {
        assert(!scratch.decoding);
        assert(scratch.storage.len == storage_bytes);
        scratch.decoding = true;
    }

    fn giveBackDecode(scratch: *Scratch) void {
        assert(scratch.decoding);
        scratch.decoding = false;
    }

    fn lendEncode(scratch: *Scratch) void {
        assert(!scratch.encoding);
        assert(scratch.encoded.len == encoded_bytes);
        scratch.encoding = true;
    }

    fn giveBackEncode(scratch: *Scratch) void {
        assert(scratch.encoding);
        scratch.encoding = false;
    }
};

pub fn Half(comptime runtime: Runtime) type {
    const ServerType = @import("../../Server.zig").Server(runtime);
    const ConnType = @import("../../net/Conn.zig").Conn(runtime);
    const StreamType = ConnType.StreamType;

    return struct {
        // Declarations rather than captures, as the shared exchange's own
        // are: each names this type in its body.
        const Proxy = @import("../proxy.zig").Proxy(runtime);
        const Shared = @import("../h2/exchange.zig").Exchange(runtime);
        const Driver = @import("driver.zig").Driver(runtime);

        /// A request stream's HEADERS arrived: decoded, given a shared slot
        /// and a head buffer, written out as the HTTP/1.1 head it stands
        /// for, and §7 begun on it. `end_stream` says the section was the
        /// whole request. A slot short is H3_REQUEST_REJECTED, which the
        /// client may retry (RFC 9114 §4.1.1); a section that does not
        /// decode is QPACK's connection error, and one that is not a
        /// message is H3_MESSAGE_ERROR (§4.1.2).
        pub fn open(server: *ServerType, conn: *ConnType, id: u62, section: []const u8, end_stream: bool) void {
            assert(conn.state == .h3);
            const slot = conn.h3.?;
            const scratch = &server.h3_scratch;
            scratch.lendDecode();
            const decoded = h3.http3_server.decodeSection(
                section,
                .{ .kind = .request },
                constants.h3_field_section_bytes_max,
                scratch.expand,
                scratch.storage,
                scratch.fields,
            ) catch |err| {
                scratch.giveBackDecode();
                return refuse(server, conn, id, err);
            };
            const stream = server.acquireSharedStream(conn, .{ .h3 = id }) orelse {
                scratch.giveBackDecode();
                server.counters.increment("h3_shed_streams");
                slot.session.cancel(&slot.quic, id, .request_rejected);
                slot.drain(id);
                return;
            };
            assert(stream.h3_id == id);
            const request: downgrade.Request = .{
                .fields = decoded.fields,
                .content_length = decoded.content_length,
                .end_stream = end_stream,
            };
            // As for HTTP/2: the parse's headers live in the server's
            // scratch, which §7's front half reads through routing.
            const storage = server.borrowHeaderScratch();
            defer server.returnHeaderScratch();
            const head = downgrade.requestHead(&request, stream.h2_head.?.data, storage);
            // Written out into the stream's own head buffer: the decoded
            // fields are not read again, and the scratch goes back before
            // anything below can answer — an answer staged now, a 400 or a
            // 404, encodes through it too.
            scratch.giveBackDecode();
            const parsed = head catch |err| return Proxy.refuseH2Request(server, stream, err);
            Proxy.serveH2Request(server, stream, &parsed);
            capRequests(server, conn);
        }

        /// A field section that did not decode, or did not make a request.
        fn refuse(server: *ServerType, conn: *ConnType, id: u62, err: h3.http3_server.DecodeError) void {
            const slot = conn.h3.?;
            switch (err) {
                error.DecompressionFailed => {
                    server.counters.increment("h3_qpack_failures");
                    slot.quic.closeApplication(@backingInt(ApplicationCode.qpack_decompression_failed));
                },
                error.MessageError => {
                    server.counters.increment("h3_malformed_requests");
                    slot.session.cancel(&slot.quic, id, .message_error);
                    slot.drain(id);
                },
                // Past this side's bound, not the client's error: refused
                // as a request, before a slot was spent on it.
                error.TooLarge => {
                    server.counters.increment("l7_headers_too_large");
                    slot.session.cancel(&slot.quic, id, .excessive_load);
                    slot.drain(id);
                },
            }
        }

        /// The #237 request cap, as HTTP/2 weighs it (`Shared.capRequests`):
        /// the request that reaches it ends the connection with a GOAWAY
        /// naming the next request stream, the ones before it finish, and
        /// any after it are rejected unread. Counted only where the cap is
        /// the binding reason.
        fn capRequests(server: *ServerType, conn: *ConnType) void {
            if (conn.state != .h3) return; // Torn down while it served.
            const cap = conn.keepalive_requests;
            if (cap == 0) return; // Unlimited.
            if (conn.requests_served < cap) return;
            const slot = conn.h3.?;
            if (server.draining) return;
            if (over(conn)) return;
            if (slot.session.goaway_sent != null) return;
            Driver.goAway(server, conn);
            server.counters.increment("l7_keepalive_requests_capped");
        }

        // -- the shared exchange's client half --

        /// The connection is closing under its exchanges: nothing more can
        /// be said on any stream.
        pub fn over(conn: *const ConnType) bool {
            const slot = conn.h3.?;
            return switch (slot.quic.state) {
                .handshaking, .established => false,
                .closing, .draining => true,
            };
        }

        /// An answer's head, or its trailers: HEADERS written whole, or
        /// not now — `h3_blocked` brings it back once the transport has
        /// room — or never, for a section past a stream's send buffer or a
        /// stream the client already ended.
        pub fn sendHead(server: *ServerType, stream: *StreamType, fields: []const Field, ends: bool) H2Session.Sent {
            return writeSection(server, stream, fields, ends, false);
        }

        pub fn sendTrailers(server: *ServerType, stream: *StreamType, fields: []const Field) H2Session.Sent {
            return writeSection(server, stream, fields, true, true);
        }

        fn writeSection(
            server: *ServerType,
            stream: *StreamType,
            fields: []const Field,
            ends: bool,
            trailers: bool,
        ) H2Session.Sent {
            assert(stream.mux == .h3);
            assert(fields.len >= 1);
            const slot = stream.conn.h3.?;
            const scratch = &server.h3_scratch;
            scratch.lendEncode();
            defer scratch.giveBackEncode();
            const written = if (trailers)
                slot.session.writeTrailers(&slot.quic, stream.h3_id, fields, scratch.encoded)
            else
                slot.session.writeHeaders(&slot.quic, stream.h3_id, fields, scratch.encoded, ends);
            written catch |err| return switch (err) {
                error.WouldBlock => blocked(stream),
                error.OutputTooSmall, error.StreamState => .refused,
            };
            stream.h3_blocked = false;
            return .staged;
        }

        fn blocked(stream: *StreamType) H2Session.Sent {
            stream.h3_blocked = true;
            return .blocked;
        }

        /// As much of an answer's body as the stream takes now, as one DATA
        /// frame, ending the stream with the last of it when `ends`. Short
        /// is ordinary — the stream's credit or send buffer is spent — and
        /// waits for room; null is a stream that takes nothing ever again.
        pub fn sendData(stream: *StreamType, bytes: []const u8, ends: bool) ?H2Session.DataSent {
            assert(stream.mux == .h3);
            const slot = stream.conn.h3.?;
            const taken = slot.session.writeData(&slot.quic, stream.h3_id, bytes, ends) catch |err| switch (err) {
                // Only an empty FIN can be refused whole for room.
                error.WouldBlock => {
                    stream.h3_blocked = true;
                    return .{ .taken = 0, .ended = false };
                },
                error.OutputTooSmall, error.StreamState => return null,
            };
            assert(taken <= bytes.len);
            const ended = ends and taken == bytes.len;
            stream.h3_blocked = taken < bytes.len;
            return .{ .taken = @intCast(taken), .ended = ended };
        }

        /// The answer is whole. A client still sending its request is told
        /// it need not (RFC 9114 §4.1, STOP_SENDING(H3_NO_ERROR)), and its
        /// RESET_STREAM is what releases the stream's sequencing; one that
        /// already finished is released now.
        pub fn stopClient(stream: *StreamType) void {
            assert(stream.mux == .h3);
            const slot = stream.conn.h3.?;
            const id = stream.h3_id;
            if (slot.quic.findStream(id)) |transport| {
                if (transport.receive_state == .receiving) {
                    slot.quic.stopSending(id, @backingInt(ApplicationCode.no_error)) catch {};
                }
            }
            slot.drain(id);
        }

        /// The exchange is abandoned after it began — an origin that broke
        /// off, a body that would not frame — so both directions are
        /// cancelled with H3_INTERNAL_ERROR (RFC 9114 §8.1), the one reset
        /// the shared exchange asks for (`Shared.fail`).
        pub fn reset(stream: *StreamType) void {
            assert(stream.mux == .h3);
            const slot = stream.conn.h3.?;
            slot.session.cancel(&slot.quic, stream.h3_id, .internal_error);
            slot.drain(stream.h3_id);
        }

        /// A body frame reached the origin: its stream is read for the room,
        /// by the pass the caller's `kick` runs — never inside the body's
        /// own send completion, which goes on after this returns.
        pub fn bodyRoomOpened(stream: *StreamType) void {
            assert(stream.mux == .h3);
            assert(!stream.ending);
            stream.h3_reread = true;
        }

        pub fn kick(server: *ServerType, conn: *ConnType) void {
            Driver.kick(server, conn);
        }
    };
}

test "h3 exchange: the scratch's closed form is what it reserves" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var scratch = try Scratch.init(arena_state.allocator());
    try std.testing.expect(!scratch.decoding);
    // The halves lend apart: an answer encodes while a request decodes.
    scratch.lendDecode();
    scratch.lendEncode();
    try std.testing.expect(scratch.decoding and scratch.encoding);
    scratch.giveBackEncode();
    scratch.giveBackDecode();
    try std.testing.expectEqual(@as(usize, Scratch.encoded_bytes), scratch.encoded.len);
}
