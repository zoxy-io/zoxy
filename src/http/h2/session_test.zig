//! Directed tests and the fuzz target for `Session` (#275).
//!
//! Every frame here is built with zoxy-io/h2's own renderer and every field
//! block with a real HPACK encoder, so what the session is tested against is
//! the wire, not a second reading of it written for the test.

const std = @import("std");
const h2 = @import("h2");

const Session = @import("Session.zig");

const frame = h2.frame;
const hpack = h2.hpack;
const testing = std.testing;
const assert = std.debug.assert;

const header_list_size: u32 = 8192;

/// A session and the buffers it borrows, plus a capture of everything it
/// sent — the test's view of the wire in the other direction.
const Fixture = struct {
    inbound: [Session.frame_bytes_max]u8 = undefined,
    block: [16 * 1024]u8 = undefined,
    decoded: [header_list_size]u8 = undefined,
    outbox: [512]u8 = undefined,
    table: Session.TableStorage = .{},
    session: Session = undefined,
    sent: [64 * 1024]u8 = undefined,
    sent_len: u32 = 0,
    /// The most one send takes. A socket that takes everything is the
    /// default; a short one is how the fuzz target reaches `flush_first`.
    drain_max: u32 = std.math.maxInt(u32),

    fn init(fixture: *Fixture) void {
        fixture.initWithOutbox(fixture.outbox.len);
    }

    fn initWithOutbox(fixture: *Fixture, outbox_len: usize) void {
        assert(outbox_len <= fixture.outbox.len);
        fixture.sent_len = 0;
        fixture.table = .{};
        fixture.session.init(.{
            .concurrent_streams_max = 100,
            .header_list_size_max = header_list_size,
        }, &.{
            .inbound = &fixture.inbound,
            .block = &fixture.block,
            .decoded = &fixture.decoded,
            .outbox = fixture.outbox[0..outbox_len],
            .table = &fixture.table,
        });
    }

    /// Send everything staged, as a socket that takes it all would.
    fn drain(fixture: *Fixture) void {
        const staged = fixture.session.outbound();
        if (staged.len == 0) return;
        const take: u32 = @intCast(@min(staged.len, fixture.drain_max));
        assert(fixture.sent_len + take <= fixture.sent.len);
        @memcpy(fixture.sent[fixture.sent_len..][0..take], staged[0..take]);
        fixture.sent_len += take;
        fixture.session.outboundSent(take);
    }

    /// Hand `bytes` to the session in reads of at most `chunk`, stepping
    /// after each and draining whenever it asks. Answers the last step.
    fn feedChunked(fixture: *Fixture, bytes: []const u8, chunk: u32) Session.Step {
        assert(chunk >= 1);
        var offset: usize = 0;
        var last: Session.Step = fixture.settle();
        while (offset < bytes.len) {
            if (last == .closed) return .closed;
            const room = fixture.session.recvBuffer();
            const take = @min(room.len, chunk, bytes.len - offset);
            @memcpy(room[0..take], bytes[offset..][0..take]);
            fixture.session.received(@intCast(take));
            offset += take;
            last = fixture.settle();
        }
        return last;
    }

    fn feed(fixture: *Fixture, bytes: []const u8) Session.Step {
        return fixture.feedChunked(bytes, std.math.maxInt(u32));
    }

    /// Step until the session wants input or is done, draining between.
    /// Bounded by what the session can stage: each pass either moves at
    /// least one staged octet out or returns, and the capture's size bounds
    /// the octets there can ever be.
    fn settle(fixture: *Fixture) Session.Step {
        var passes: u32 = 0;
        while (passes <= fixture.sent.len) : (passes += 1) {
            const result = fixture.session.step();
            fixture.drain();
            if (result != .flush_first) {
                // What a short socket left behind still goes out, so the
                // capture is the whole reply whatever the drain size.
                while (fixture.session.outbound().len >= 1) fixture.drain();
                return result;
            }
        }
        unreachable;
    }

    /// The frames sent so far, after the server's own SETTINGS.
    fn replies(fixture: *const Fixture) FrameReader {
        var reader: FrameReader = .{ .bytes = fixture.sent[0..fixture.sent_len] };
        const first = reader.next().?;
        assert(first.header.frame_type == .settings);
        assert(first.header.flags == 0);
        return reader;
    }
};

const FrameReader = struct {
    bytes: []const u8,
    offset: usize = 0,

    const Frame = struct { header: frame.Header, payload: frame.Payload };

    fn next(reader: *FrameReader) ?Frame {
        if (reader.offset == reader.bytes.len) return null;
        const header = frame.Header.parse(reader.bytes[reader.offset..]) catch unreachable;
        const start = reader.offset + frame.Header.octets;
        const payload_bytes = reader.bytes[start..][0..header.length];
        reader.offset = start + header.length;
        return .{ .header = header, .payload = frame.payload.parse(header, payload_bytes) catch unreachable };
    }
};

/// One rendered frame, appended to `out`.
fn put(out: *std.ArrayList(u8), payload: frame.Payload, stream: u31, flags: u8) void {
    var buffer: [Session.frame_bytes_max]u8 = undefined;
    const written = frame.payload.render(&payload, stream, flags, &buffer) catch unreachable;
    out.appendSlice(testing.allocator, buffer[0..written]) catch unreachable;
}

/// The client's opening: preface, then an empty SETTINGS.
fn putOpening(out: *std.ArrayList(u8)) void {
    out.appendSlice(testing.allocator, Session.preface) catch unreachable;
    put(out, .{ .settings = .{ .entries = &.{} } }, 0, 0);
}

/// A frame the renderer would refuse to write: what a malformed peer sends.
fn putRaw(out: *std.ArrayList(u8), frame_type: u8, flags: u8, stream: u31, payload: []const u8) void {
    const length: u32 = @intCast(payload.len);
    var header: [frame.Header.octets]u8 = undefined;
    header[0] = @intCast(length >> 16);
    header[1] = @intCast((length >> 8) & 0xff);
    header[2] = @intCast(length & 0xff);
    header[3] = frame_type;
    header[4] = flags;
    std.mem.writeInt(u32, header[5..9], stream, .big);
    out.appendSlice(testing.allocator, &header) catch unreachable;
    out.appendSlice(testing.allocator, payload) catch unreachable;
}

fn putHeaders(out: *std.ArrayList(u8), stream: u31, block: []const u8) void {
    put(out, .{ .headers = .{ .priority = null, .fragment = block, .padding = null } }, stream, frame.Flag.end_headers.bit() | frame.Flag.end_stream.bit());
}

fn expectGoaway(fixture: *const Fixture, code: frame.ErrorCode) !void {
    var reader = fixture.replies();
    var last: ?FrameReader.Frame = null;
    while (reader.next()) |one| last = one;
    try testing.expect(last != null);
    try testing.expectEqual(frame.Type.goaway, last.?.header.frame_type);
    try testing.expectEqual(code, last.?.payload.goaway.error_code);
    try testing.expectEqual(@as(?frame.ErrorCode, code), fixture.session.closed_with);
}

const request_fields = [_]hpack.Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "example.test" },
    .{ .name = ":path", .value = "/a/long/enough/path/to/index" },
    .{ .name = "user-agent", .value = "zoxy-session-test" },
};

test "h2 session: the server preface is a SETTINGS frame, staged before any input" {
    var fixture: Fixture = .{};
    fixture.init();
    var reader: FrameReader = .{ .bytes = fixture.session.outbound() };
    const settings = reader.next().?;
    try testing.expect(reader.next() == null);
    try testing.expectEqual(frame.Type.settings, settings.header.frame_type);
    try testing.expectEqual(@as(u31, 0), settings.header.stream_identifier);
    try testing.expect(!settings.header.has(.ack));
    var entries = settings.payload.settings.iterate();
    const first = entries.next().?;
    try testing.expectEqual(frame.payload.Settings.Identifier.max_concurrent_streams, first.identifier);
    try testing.expectEqual(@as(u32, 100), first.value);
    const second = entries.next().?;
    try testing.expectEqual(frame.payload.Settings.Identifier.max_header_list_size, second.identifier);
    try testing.expectEqual(header_list_size, second.value);
    try testing.expect(entries.next() == null);
}

test "h2 session: the client's preface and SETTINGS are acknowledged, in one read or one octet at a time" {
    var opening: std.ArrayList(u8) = .empty;
    defer opening.deinit(testing.allocator);
    putOpening(&opening);
    for ([_]u32{ std.math.maxInt(u32), 1, 7 }) |chunk| {
        var fixture: Fixture = .{};
        fixture.init();
        try testing.expectEqual(Session.Step.need_input, fixture.feedChunked(opening.items, chunk));
        var reader = fixture.replies();
        const ack = reader.next().?;
        try testing.expectEqual(frame.Type.settings, ack.header.frame_type);
        try testing.expect(ack.header.has(.ack));
        try testing.expect(reader.next() == null);
    }
}

test "h2 session: a client that is not speaking HTTP/2 is refused at its first wrong octet" {
    var fixture: Fixture = .{};
    fixture.init();
    // "PRI" matches the preface for three octets and then does not, which
    // is the HTTP/1.1 client this listener might meet first.
    try testing.expectEqual(Session.Step.closed, fixture.feed("PRI / HTTP/1.1\r\n"));
    try expectGoaway(&fixture, .protocol_error);
}

test "h2 session: the first frame after the preface must be SETTINGS, and not its ACK" {
    for ([_]bool{ false, true }) |as_ack| {
        var fixture: Fixture = .{};
        fixture.init();
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(testing.allocator);
        input.appendSlice(testing.allocator, Session.preface) catch unreachable;
        if (as_ack) {
            put(&input, .{ .settings = .{ .entries = &.{} } }, 0, frame.Flag.ack.bit());
        } else {
            put(&input, .{ .ping = .{ .opaque_data = &@splat(1) } }, 0, 0);
        }
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .protocol_error);
    }
}

test "h2 session: a PING is answered with its own payload, and an ACK is not answered" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    const opaque_data: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    put(&input, .{ .ping = .{ .opaque_data = &opaque_data } }, 0, 0);
    put(&input, .{ .ping = .{ .opaque_data = &opaque_data } }, 0, frame.Flag.ack.bit());
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var reader = fixture.replies();
    _ = reader.next().?; // SETTINGS ACK
    const pong = reader.next().?;
    try testing.expectEqual(frame.Type.ping, pong.header.frame_type);
    try testing.expect(pong.header.has(.ack));
    try testing.expectEqualSlices(u8, &opaque_data, pong.payload.ping.opaque_data);
    try testing.expect(reader.next() == null);
}

test "h2 session: every stream is refused, and HPACK stays in step across them" {
    var fixture: Fixture = .{};
    fixture.init();
    // `.dynamic`, so the second block names fields the first inserted: a
    // session that skipped the first block would misread the second.
    var storage: hpack.Encoder.Storage(Session.header_table_size) = .{};
    var encoder = storage.encoder(.dynamic);
    var first_block: [512]u8 = undefined;
    const first = encoder.encode(&first_block, &request_fields);
    var second_block: [512]u8 = undefined;
    const second = encoder.encode(&second_block, &request_fields);
    try testing.expect(second.written < first.written);

    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, first_block[0..first.written]);
    putHeaders(&input, 3, second_block[0..second.written]);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(u32, 2), fixture.session.streams_refused);

    var reader = fixture.replies();
    _ = reader.next().?; // SETTINGS ACK
    for ([_]u31{ 1, 3 }) |stream| {
        const reset = reader.next().?;
        try testing.expectEqual(frame.Type.rst_stream, reset.header.frame_type);
        try testing.expectEqual(stream, reset.header.stream_identifier);
        try testing.expectEqual(frame.ErrorCode.refused_stream, reset.payload.rst_stream.error_code);
    }
    try testing.expect(reader.next() == null);
}

test "h2 session: a field block HPACK cannot decode is a COMPRESSION_ERROR" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    // Indexed field 0, which RFC 7541 §6.1 reserves.
    putHeaders(&input, 1, &.{0x80});
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
    try expectGoaway(&fixture, .compression_error);
}

test "h2 session: a stream only a server may open, or a frame on an idle stream, ends the connection" {
    const cases = [_]struct { payload: frame.Payload, stream: u31, flags: u8 }{
        .{ .payload = .{ .headers = .{ .priority = null, .fragment = &.{0x82}, .padding = null } }, .stream = 2, .flags = frame.Flag.end_headers.bit() },
        .{ .payload = .{ .data = .{ .data = "x", .padding = null } }, .stream = 5, .flags = 0 },
        .{ .payload = .{ .window_update = .{ .increment = 1 } }, .stream = 5, .flags = 0 },
        .{ .payload = .{ .rst_stream = .{ .error_code = .cancel } }, .stream = 5, .flags = 0 },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        fixture.init();
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        put(&input, case.payload, case.stream, case.flags);
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .protocol_error);
    }
}

test "h2 session: DATA behind a refused stream gives its connection credit back" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, &.{0x82}); // `:method: GET`, indexed.
    // Three full frames: past half the window after the second, which is
    // when the credit goes back, so the third spends a refilled window.
    const chunk: [Session.frame_payload_bytes_max]u8 = @splat('b');
    for (0..3) |_| put(&input, .{ .data = .{ .data = &chunk, .padding = null } }, 1, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var reader = fixture.replies();
    _ = reader.next().?; // SETTINGS ACK
    _ = reader.next().?; // RST_STREAM
    const credit = reader.next().?;
    try testing.expectEqual(frame.Type.window_update, credit.header.frame_type);
    try testing.expectEqual(@as(u31, 0), credit.header.stream_identifier);
    try testing.expectEqual(@as(u31, 2 * Session.frame_payload_bytes_max), credit.payload.window_update.increment);
    try testing.expect(reader.next() == null);
    try testing.expect(fixture.session.closed_with == null);
}

test "h2 session: the client's window may not pass 2^31-1" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    put(&input, .{ .window_update = .{ .increment = std.math.maxInt(u31) } }, 0, 0);
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
    try expectGoaway(&fixture, .flow_control_error);
}

test "h2 session: SETTINGS values outside their ranges end the connection" {
    const cases = [_]struct { identifier: u16, value: u32, code: frame.ErrorCode }{
        .{ .identifier = 0x2, .value = 2, .code = .protocol_error }, // ENABLE_PUSH
        .{ .identifier = 0x4, .value = 1 << 31, .code = .flow_control_error }, // INITIAL_WINDOW_SIZE
        .{ .identifier = 0x5, .value = 100, .code = .protocol_error }, // MAX_FRAME_SIZE
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        fixture.init();
        var entry: [6]u8 = undefined;
        std.mem.writeInt(u16, entry[0..2], case.identifier, .big);
        std.mem.writeInt(u32, entry[2..6], case.value, .big);
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(testing.allocator);
        input.appendSlice(testing.allocator, Session.preface) catch unreachable;
        put(&input, .{ .settings = .{ .entries = &entry } }, 0, 0);
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, case.code);
    }
}

test "h2 session: a frame past our frame size is refused from its header alone" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    // Nine octets announcing one more than we accept, and no payload: the
    // verdict cannot wait for octets this side has no room to hold.
    const length = Session.frame_payload_bytes_max + 1;
    input.appendSlice(testing.allocator, &.{
        @intCast(length >> 16), @intCast((length >> 8) & 0xff), @intCast(length & 0xff),
        0x0,                    0x0,                            0,
        0,                      0,                              1,
    }) catch unreachable;
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
    try expectGoaway(&fixture, .frame_size_error);
}

test "h2 session: a field block interrupted by another frame is a PROTOCOL_ERROR" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    put(&input, .{ .headers = .{ .priority = null, .fragment = &.{0x82}, .padding = null } }, 1, 0);
    put(&input, .{ .ping = .{ .opaque_data = &@splat(0) } }, 0, 0);
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
    try expectGoaway(&fixture, .protocol_error);
}

test "h2 session: a PUSH_PROMISE from a client is a PROTOCOL_ERROR" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    put(&input, .{ .push_promise = .{
        .promised_stream_identifier = 2,
        .fragment = &.{0x82},
        .padding = null,
    } }, 1, frame.Flag.end_headers.bit());
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
    try expectGoaway(&fixture, .protocol_error);
}

test "h2 session: the client's GOAWAY ends the connection, and this side sends none" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    put(&input, .{ .goaway = .{ .last_stream_identifier = 0, .error_code = .no_error, .debug_data = &.{} } }, 0, 0);
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
    try testing.expect(fixture.session.closed_with == null);
    var reader = fixture.replies();
    _ = reader.next().?; // SETTINGS ACK
    try testing.expect(reader.next() == null);
}

test "h2 session: a field block across CONTINUATION is assembled, decoded and refused" {
    var fixture: Fixture = .{};
    fixture.init();
    var storage: hpack.Encoder.Storage(Session.header_table_size) = .{};
    var encoder = storage.encoder(.dynamic);
    var block: [512]u8 = undefined;
    const encoded = encoder.encode(&block, &request_fields);
    const half = encoded.written / 2;
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    put(&input, .{ .headers = .{ .priority = null, .fragment = block[0..half], .padding = null } }, 1, frame.Flag.end_stream.bit());
    put(&input, .{ .continuation = .{ .fragment = block[half..encoded.written] } }, 1, frame.Flag.end_headers.bit());
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(u32, 1), fixture.session.streams_refused);
    try testing.expect(fixture.session.closed_with == null);
}

test "h2 session: a zero WINDOW_UPDATE is a stream error on a stream, and a connection error elsewhere" {
    const cases = [_]struct { stream: u31, goaway: bool }{
        // Stream zero: §6.9 makes it the connection's error.
        .{ .stream = 0, .goaway = true },
        // A stream this side refused: the stream's error.
        .{ .stream = 1, .goaway = false },
        // An idle stream: §5.1 outranks §6.9, and RST_STREAM may not name it.
        .{ .stream = 5, .goaway = true },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        fixture.init();
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        putHeaders(&input, 1, &.{0x82});
        putRaw(&input, 0x8, 0, case.stream, &.{ 0, 0, 0, 0 });
        const verdict = fixture.feed(input.items);
        if (case.goaway) {
            try testing.expectEqual(Session.Step.closed, verdict);
            try expectGoaway(&fixture, .protocol_error);
            continue;
        }
        try testing.expectEqual(Session.Step.need_input, verdict);
        var reader = fixture.replies();
        _ = reader.next().?; // SETTINGS ACK
        _ = reader.next().?; // The refusal of stream 1.
        const reset = reader.next().?;
        try testing.expectEqual(frame.Type.rst_stream, reset.header.frame_type);
        try testing.expectEqual(frame.ErrorCode.protocol_error, reset.payload.rst_stream.error_code);
    }
}

test "h2 session: a stream error cannot jump the SETTINGS-first or the open-block rule" {
    // PRIORITY with four octets where five are required: on its own a
    // stream error (§6.3). As the first frame, §3.4 outranks it.
    {
        var fixture: Fixture = .{};
        fixture.init();
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(testing.allocator);
        input.appendSlice(testing.allocator, Session.preface) catch unreachable;
        putRaw(&input, 0x2, 0, 1, &.{ 0, 0, 0, 0 });
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .protocol_error);
    }
    // And inside an open field block, §4.3 does: nothing may interleave.
    {
        var fixture: Fixture = .{};
        fixture.init();
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        put(&input, .{ .headers = .{ .priority = null, .fragment = &.{0x82}, .padding = null } }, 1, 0);
        putRaw(&input, 0x2, 0, 1, &.{ 0, 0, 0, 0 });
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .protocol_error);
    }
}

test "h2 session: padding is read past, and counted against the window" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    const padding: [200]u8 = @splat(0);
    put(&input, .{ .headers = .{ .priority = null, .fragment = &.{0x82}, .padding = &padding } }, 1, frame.Flag.end_headers.bit());
    // Two full frames, most of each padding: the credit has to cover the
    // padding too, or a padded body would drain the window it never got back.
    const data: [Session.frame_payload_bytes_max - 1 - padding.len]u8 = @splat('d');
    for (0..2) |_| put(&input, .{ .data = .{ .data = &data, .padding = &padding } }, 1, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var reader = fixture.replies();
    _ = reader.next().?; // SETTINGS ACK
    const reset = reader.next().?;
    try testing.expectEqual(frame.ErrorCode.refused_stream, reset.payload.rst_stream.error_code);
    const credit = reader.next().?;
    try testing.expectEqual(@as(u31, 2 * Session.frame_payload_bytes_max), credit.payload.window_update.increment);
}

test "h2 session: a full outbox stalls the client's input rather than growing" {
    // The smallest outbox the session accepts, and pings enough to need
    // several flushes: each answer is staged only once there is room.
    var fixture: Fixture = .{};
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    const pings: u32 = 32;
    for (0..pings) |_| put(&input, .{ .ping = .{ .opaque_data = &@splat(7) } }, 0, 0);
    fixture.initWithOutbox(Session.outbox_bytes_min);
    const room = fixture.session.recvBuffer();
    @memcpy(room[0..input.items.len], input.items);
    fixture.session.received(@intCast(input.items.len));
    // Undrained, the first step answers what fits and then asks.
    try testing.expectEqual(Session.Step.flush_first, fixture.session.step());
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    var reader = fixture.replies();
    _ = reader.next().?; // SETTINGS ACK
    var answered: u32 = 0;
    while (reader.next()) |pong| : (answered += 1) {
        try testing.expectEqual(frame.Type.ping, pong.header.frame_type);
    }
    try testing.expectEqual(pings, answered);
}

const empty_settings = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";

test "fuzz: h2 session — any octets, any split: answered or closed, never a third outcome" {
    // Corpus entries lead with the harness's control octet (see
    // `fuzzSession`): `0x07` supplies the opening and reads 8 at a time,
    // `0x80` makes the entry carry its own.
    try testing.fuzz({}, fuzzSession, .{ .corpus = &.{
        "\x80" ++ Session.preface ++ empty_settings,
        "\x07" ++ "\x00\x00\x08\x06\x00\x00\x00\x00\x00" ++ "pingping",
        "\x07" ++ "\x00\x00\x01\x01\x05\x00\x00\x00\x01\x82",
        "\x07" ++ "\x00\x00\x01\x01\x05\x00\x00\x00\x01\x82" ++
            "\x00\x00\x01\x00\x01\x00\x00\x00\x01x",
        "\x07" ++ "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x01",
    } });
}

fn fuzzSession(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input: [4096]u8 = undefined;
    const input_len = smith.slice(&input);
    assert(input_len <= input.len);
    var fixture: Fixture = .{};
    fixture.init();
    // The first octet is the harness's, not the session's. Its low bits
    // draw the read size, so one corpus entry reaches every chunking and
    // frame boundaries cannot matter; its top bit decides whether the
    // opening is supplied. Supplied is the common case on purpose: almost
    // every mutation of a raw input breaks the 24-octet preface, and a
    // fuzzer spending its runs there never reaches a frame. Bit six swaps
    // in the smallest outbox and a short socket, which is the only way the
    // `flush_first` path — and the room check `stage` relies on — is ever
    // under the fuzzer rather than beside it.
    const control: u8 = if (input_len >= 1) input[0] else 0;
    if (control & 0x40 != 0) {
        fixture.initWithOutbox(Session.outbox_bytes_min);
        fixture.drain_max = 1 + @as(u32, (control >> 2) % 8);
    }
    const chunk: u32 = 1 + @as(u32, control % 32);
    const body = input[@min(input_len, 1)..input_len];
    var verdict: Session.Step = .need_input;
    if (control & 0x80 == 0) {
        verdict = fixture.feedChunked(Session.preface ++ empty_settings, chunk);
        assert(verdict == .need_input);
    }
    if (verdict != .closed) verdict = fixture.feedChunked(body, chunk);
    assert(verdict == .need_input or verdict == .closed);
    // Everything that went out is whole frames: `FrameReader` refuses
    // anything else outright.
    var reader: FrameReader = .{ .bytes = fixture.sent[0..fixture.sent_len] };
    var frames: u32 = 0;
    while (reader.next()) |_| : (frames += 1) assert(frames < fixture.sent_len);
    assert(frames >= 1); // The server's SETTINGS, at least.
    if (verdict != .closed) {
        assert(fixture.session.recv_window + fixture.session.recv_unacked == 65_535);
    }
    // A closed session stays closed, and one that ended by its own hand
    // said why on the wire.
    if (verdict == .closed) {
        assert(fixture.session.step() == .closed);
        if (fixture.session.closed_with) |code| assert(code != .no_error);
    }
    assert(fixture.session.outbound().len == 0);
}
