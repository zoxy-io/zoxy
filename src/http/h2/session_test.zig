//! Directed tests and the fuzz target for `Session` (#275).
//!
//! Every frame here is built with zoxy-io/h2's own renderer and every field
//! block with a real HPACK encoder, so what the session is tested against is
//! the wire, not a second reading of it written for the test.

const std = @import("std");
const h2 = @import("h2");

const Session = @import("Session.zig");
const StreamTable = @import("StreamTable.zig");

const frame = h2.frame;
const hpack = h2.hpack;
const testing = std.testing;
const assert = std.debug.assert;

const header_list_size: u32 = 8192;
const streams_capacity: u32 = 8;

/// What the caller does with each event, standing in for the server.
const Caller = enum {
    /// Consume body octets as they arrive, and close a stream once the
    /// client's half is done — a server that answered.
    consume_and_close,
    /// Reset every stream the moment it opens — a server shedding.
    reset_on_open,
    /// Hold everything: no consume, no close.
    hold,
};

const Event = struct {
    kind: std.meta.Tag(Session.Step),
    stream: u31 = 0,
    bytes: u32 = 0,
    fields: u32 = 0,
    end_stream: bool = false,
    code: ?frame.ErrorCode = null,
};

/// A session and the buffers it borrows, a capture of everything it sent,
/// and the events it raised — the test's view of both directions.
const Fixture = struct {
    inbound: [Session.frame_bytes_max]u8 = undefined,
    block: [16 * 1024]u8 = undefined,
    decoded: [header_list_size]u8 = undefined,
    fields: [Session.fieldsFor(header_list_size)]hpack.Field = undefined,
    streams: [streams_capacity]StreamTable.Slot = undefined,
    outbox: [512]u8 = undefined,
    table: Session.TableStorage = .{},
    session: Session = undefined,
    sent: [128 * 1024]u8 = undefined,
    sent_len: u32 = 0,
    events: [256]Event = undefined,
    events_len: u32 = 0,
    caller: Caller = .consume_and_close,
    /// The most one send takes. A socket that takes everything is the
    /// default; a short one is how the fuzz target reaches `flush_first`.
    drain_max: u32 = std.math.maxInt(u32),

    const Options = struct {
        outbox_len: usize = 512,
        streams: u32 = streams_capacity,
        initial_window_size: u31 = Session.window_default,
    };

    fn init(fixture: *Fixture) void {
        fixture.initWith(.{});
    }

    fn initWith(fixture: *Fixture, options: Options) void {
        assert(options.outbox_len <= fixture.outbox.len);
        assert(options.streams <= streams_capacity);
        fixture.sent_len = 0;
        fixture.events_len = 0;
        fixture.table = .{};
        fixture.session.init(.{
            .concurrent_streams_max = options.streams,
            .header_list_size_max = header_list_size,
            .initial_window_size = options.initial_window_size,
        }, &.{
            .inbound = &fixture.inbound,
            .block = &fixture.block,
            .decoded = &fixture.decoded,
            .fields = &fixture.fields,
            .streams = fixture.streams[0..options.streams],
            .outbox = fixture.outbox[0..options.outbox_len],
            .table = &fixture.table,
        });
    }

    /// Send what is staged, as far as the socket takes it.
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

    /// Hand `bytes` over in one read, without stepping: for a test that
    /// steps by hand to hold the outbox where it wants it.
    fn receive(fixture: *Fixture, bytes: []const u8) void {
        const room = fixture.session.recvBuffer();
        assert(bytes.len <= room.len);
        @memcpy(room[0..bytes.len], bytes);
        fixture.session.received(@intCast(bytes.len));
    }

    fn feed(fixture: *Fixture, bytes: []const u8) Session.Step {
        return fixture.feedChunked(bytes, std.math.maxInt(u32));
    }

    /// Step until the session wants input or is done, draining between and
    /// answering each event the way `caller` says. Bounded by the capture:
    /// each pass moves at least one octet out, handles one event, or returns.
    fn settle(fixture: *Fixture) Session.Step {
        var passes: u32 = 0;
        while (passes <= fixture.sent.len + fixture.events.len) : (passes += 1) {
            const result = fixture.session.step();
            fixture.drain();
            switch (result) {
                .flush_first => continue,
                .need_input, .closed => {
                    while (fixture.session.outbound().len >= 1) fixture.drain();
                    return result;
                },
                else => fixture.answer(result),
            }
        }
        unreachable;
    }

    fn answer(fixture: *Fixture, event: Session.Step) void {
        var recorded: Event = .{ .kind = event };
        switch (event) {
            .request => |request| {
                recorded.stream = request.stream;
                recorded.fields = @intCast(request.fields.len);
                recorded.end_stream = request.end_stream;
                switch (fixture.caller) {
                    .consume_and_close => if (request.end_stream) fixture.session.close(request.stream),
                    .reset_on_open => fixture.session.resetStream(request.stream, .refused_stream),
                    .hold => {},
                }
            },
            .data => |data| {
                recorded.stream = data.stream;
                recorded.bytes = @intCast(data.bytes.len);
                recorded.end_stream = data.end_stream;
                if (fixture.caller == .consume_and_close) {
                    if (data.bytes.len >= 1) fixture.session.consume(data.stream, @intCast(data.bytes.len));
                    if (data.end_stream) fixture.session.close(data.stream);
                }
            },
            .trailers => |trailers| {
                recorded.stream = trailers.stream;
                recorded.fields = @intCast(trailers.fields.len);
                if (fixture.caller == .consume_and_close) fixture.session.close(trailers.stream);
            },
            .reset => |reset| {
                recorded.stream = reset.stream;
                recorded.code = reset.code;
            },
            .need_input, .flush_first, .closed => unreachable,
        }
        // The fuzz target can raise more events than a test inspects; the
        // record keeps the first ones and the answers go on regardless.
        if (fixture.events_len == fixture.events.len) return;
        fixture.events[fixture.events_len] = recorded;
        fixture.events_len += 1;
    }

    fn eventsOf(fixture: *const Fixture) []const Event {
        return fixture.events[0..fixture.events_len];
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

    /// The next frame, skipping SETTINGS ACKs — which every test's opening
    /// earns and none is about.
    fn nextSkippingAcks(reader: *FrameReader) ?Frame {
        var passes: u32 = 0;
        while (reader.next()) |one| : (passes += 1) {
            assert(passes < 64);
            if (one.header.frame_type == .settings) continue;
            return one;
        }
        return null;
    }
};

const Wire = std.ArrayList(u8);

/// One rendered frame, appended to `out`.
fn put(out: *Wire, payload: frame.Payload, stream: u31, flags: u8) void {
    var buffer: [Session.frame_bytes_max]u8 = undefined;
    const written = frame.payload.render(&payload, stream, flags, &buffer) catch unreachable;
    out.appendSlice(testing.allocator, buffer[0..written]) catch unreachable;
}

/// A frame the renderer would refuse to write: what a malformed peer sends.
fn putRaw(out: *Wire, frame_type: u8, flags: u8, stream: u31, payload: []const u8) void {
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

/// The client's opening: preface, then an empty SETTINGS.
fn putOpening(out: *Wire) void {
    out.appendSlice(testing.allocator, Session.preface) catch unreachable;
    put(out, .{ .settings = .{ .entries = &.{} } }, 0, 0);
}

fn putHeaders(out: *Wire, stream: u31, block: []const u8, end_stream: bool) void {
    const flags = frame.Flag.end_headers.bit() | if (end_stream) frame.Flag.end_stream.bit() else 0;
    put(out, .{ .headers = .{ .priority = null, .fragment = block, .padding = null } }, stream, flags);
}

fn putData(out: *Wire, stream: u31, bytes: []const u8, end_stream: bool) void {
    const flags: u8 = if (end_stream) frame.Flag.end_stream.bit() else 0;
    put(out, .{ .data = .{ .data = bytes, .padding = null } }, stream, flags);
}

/// Field blocks from a dynamic-table encoder the test keeps — so one test
/// can make blocks that lean on the ones before them.
const Blocks = struct {
    storage: hpack.Encoder.Storage(Session.header_table_size) = .{},
    encoder: hpack.Encoder = undefined,
    buffer: [1024]u8 = undefined,

    fn init(blocks: *Blocks) void {
        blocks.storage = .{};
        blocks.encoder = blocks.storage.encoder(.dynamic);
    }

    fn encode(blocks: *Blocks, fields: []const hpack.Field) []const u8 {
        const encoded = blocks.encoder.encode(&blocks.buffer, fields);
        assert(encoded.fields == fields.len);
        return blocks.buffer[0..encoded.written];
    }
};

fn expectGoaway(fixture: *const Fixture, code: frame.ErrorCode) !void {
    var reader = fixture.replies();
    var last: ?FrameReader.Frame = null;
    while (reader.next()) |one| last = one;
    try testing.expect(last != null);
    try testing.expectEqual(frame.Type.goaway, last.?.header.frame_type);
    try testing.expectEqual(code, last.?.payload.goaway.error_code);
    try testing.expectEqual(@as(?frame.ErrorCode, code), fixture.session.closed_with);
}

fn expectReset(one: ?FrameReader.Frame, stream: u31, code: frame.ErrorCode) !void {
    try testing.expect(one != null);
    try testing.expectEqual(frame.Type.rst_stream, one.?.header.frame_type);
    try testing.expectEqual(stream, one.?.header.stream_identifier);
    try testing.expectEqual(code, one.?.payload.rst_stream.error_code);
}

const request_fields = [_]hpack.Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "example.test" },
    .{ .name = ":path", .value = "/a/long/enough/path/to/index" },
    .{ .name = "user-agent", .value = "zoxy-session-test" },
};

const post_fields = [_]hpack.Field{
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "example.test" },
    .{ .name = ":path", .value = "/upload" },
};

// ---------------------------------------------------------------------------
// The connection
// ---------------------------------------------------------------------------

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
    try testing.expectEqual(streams_capacity, first.value);
    const second = entries.next().?;
    try testing.expectEqual(frame.payload.Settings.Identifier.max_header_list_size, second.identifier);
    try testing.expectEqual(header_list_size, second.value);
    // The default window is the default, so it is not said.
    try testing.expect(entries.next() == null);
}

test "h2 session: a window other than the default is advertised" {
    var fixture: Fixture = .{};
    fixture.initWith(.{ .initial_window_size = 1024 });
    var reader: FrameReader = .{ .bytes = fixture.session.outbound() };
    var entries = reader.next().?.payload.settings.iterate();
    _ = entries.next().?;
    _ = entries.next().?;
    const window = entries.next().?;
    try testing.expectEqual(frame.payload.Settings.Identifier.initial_window_size, window.identifier);
    try testing.expectEqual(@as(u32, 1024), window.value);
}

test "h2 session: the client's preface and SETTINGS are acknowledged, in one read or one octet at a time" {
    var opening: Wire = .empty;
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
    try testing.expectEqual(Session.Step.closed, fixture.feed("PRI / HTTP/1.1\r\n"));
    try expectGoaway(&fixture, .protocol_error);
}

test "h2 session: the first frame after the preface must be SETTINGS, and not its ACK" {
    for ([_]bool{ false, true }) |as_ack| {
        var fixture: Fixture = .{};
        fixture.init();
        var input: Wire = .empty;
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
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    const opaque_data: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    put(&input, .{ .ping = .{ .opaque_data = &opaque_data } }, 0, 0);
    put(&input, .{ .ping = .{ .opaque_data = &opaque_data } }, 0, frame.Flag.ack.bit());
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var reader = fixture.replies();
    const pong = reader.nextSkippingAcks().?;
    try testing.expectEqual(frame.Type.ping, pong.header.frame_type);
    try testing.expect(pong.header.has(.ack));
    try testing.expectEqualSlices(u8, &opaque_data, pong.payload.ping.opaque_data);
    try testing.expect(reader.next() == null);
}

test "h2 session: the client's window may not pass 2^31-1" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: Wire = .empty;
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
        var input: Wire = .empty;
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
    var input: Wire = .empty;
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
    var input: Wire = .empty;
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
    var input: Wire = .empty;
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
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        put(&input, case.payload, case.stream, case.flags);
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .protocol_error);
    }
}

test "h2 session: a stream error cannot jump the SETTINGS-first or the open-block rule" {
    // PRIORITY with four octets where five are required: on its own a
    // stream error (§6.3). As the first frame, §3.4 outranks it.
    {
        var fixture: Fixture = .{};
        fixture.init();
        var input: Wire = .empty;
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
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        put(&input, .{ .headers = .{ .priority = null, .fragment = &.{0x82}, .padding = null } }, 1, 0);
        putRaw(&input, 0x2, 0, 1, &.{ 0, 0, 0, 0 });
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .protocol_error);
    }
}

test "h2 session: a full outbox stalls the client's input rather than growing" {
    // The smallest outbox the session accepts, and pings enough to need
    // several flushes: each answer is staged only once there is room.
    var fixture: Fixture = .{};
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    const pings: u32 = 32;
    for (0..pings) |_| put(&input, .{ .ping = .{ .opaque_data = &@splat(7) } }, 0, 0);
    fixture.initWith(.{ .outbox_len = Session.outbox_bytes_min });
    fixture.receive(input.items);
    // Undrained, the first step answers what fits and then asks.
    try testing.expectEqual(Session.Step.flush_first, fixture.session.step());
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    var reader = fixture.replies();
    var answered: u32 = 0;
    while (reader.nextSkippingAcks()) |pong| : (answered += 1) {
        try testing.expectEqual(frame.Type.ping, pong.header.frame_type);
    }
    try testing.expectEqual(pings, answered);
}

// ---------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------

test "h2 session: a request head surfaces as an event, with its fields" {
    var fixture: Fixture = .{};
    fixture.init();
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const events = fixture.eventsOf();
    try testing.expectEqual(@as(usize, 1), events.len);
    try testing.expectEqual(.request, events[0].kind);
    try testing.expectEqual(@as(u31, 1), events[0].stream);
    try testing.expectEqual(@as(u32, request_fields.len), events[0].fields);
    try testing.expect(events[0].end_stream);
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used); // Closed by the caller.
}

test "h2 session: a request that breaks §8's rules is reset, and HPACK stays in step for the next" {
    const malformed = [_][]const hpack.Field{
        // §8.2.2: connection-specific, the downgrade-smuggling field.
        &(request_fields ++ [_]hpack.Field{.{ .name = "connection", .value = "keep-alive" }}),
        &(request_fields ++ [_]hpack.Field{.{ .name = "transfer-encoding", .value = "chunked" }}),
        // §8.2.2's one exception, and only for `trailers`.
        &(request_fields ++ [_]hpack.Field{.{ .name = "te", .value = "gzip" }}),
        // §8.2.1: an uppercase name.
        &(request_fields ++ [_]hpack.Field{.{ .name = "User-Agent", .value = "x" }}),
        // §8.3.1: no `:path`.
        request_fields[0..3],
        // A value an HTTP/1.1 parser would read as two lines.
        &(request_fields ++ [_]hpack.Field{.{ .name = "x-split", .value = "a\r\nb: c" }}),
    };
    for (malformed) |fields| {
        var fixture: Fixture = .{};
        fixture.init();
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        putHeaders(&input, 1, blocks.encode(fields), true);
        // Indexed against what the malformed block inserted: misread, had
        // that block been skipped.
        putHeaders(&input, 3, blocks.encode(&request_fields), true);
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        var reader = fixture.replies();
        try expectReset(reader.nextSkippingAcks(), 1, .protocol_error);
        try testing.expect(reader.next() == null);
        const events = fixture.eventsOf();
        try testing.expectEqual(@as(usize, 1), events.len);
        try testing.expectEqual(@as(u31, 3), events[0].stream);
    }
}

test "h2 session: past the table, a stream is refused — and its block still decoded" {
    var fixture: Fixture = .{};
    fixture.initWith(.{ .streams = 1 });
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    putHeaders(&input, 3, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(u32, 1), fixture.session.streams_refused);
    var reader = fixture.replies();
    try expectReset(reader.nextSkippingAcks(), 3, .refused_stream);
    // And once the first is closed, the next stream gets the slot — which
    // it could only decode if stream 3's block had been decoded too.
    fixture.session.close(1);
    var more: Wire = .empty;
    defer more.deinit(testing.allocator);
    putHeaders(&more, 5, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(more.items));
    const events = fixture.eventsOf();
    try testing.expectEqual(@as(usize, 2), events.len);
    try testing.expectEqual(@as(u31, 5), events[1].stream);
}

test "h2 session: a field block across CONTINUATION is assembled and surfaces whole" {
    var fixture: Fixture = .{};
    fixture.init();
    var blocks: Blocks = .{};
    blocks.init();
    const block = blocks.encode(&request_fields);
    const half = block.len / 2;
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    put(&input, .{ .headers = .{ .priority = null, .fragment = block[0..half], .padding = null } }, 1, frame.Flag.end_stream.bit());
    put(&input, .{ .continuation = .{ .fragment = block[half..] } }, 1, frame.Flag.end_headers.bit());
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const events = fixture.eventsOf();
    try testing.expectEqual(@as(usize, 1), events.len);
    try testing.expectEqual(@as(u32, request_fields.len), events[0].fields);
}

test "h2 session: a body arrives as DATA events, and trailers end it" {
    var fixture: Fixture = .{};
    fixture.init();
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&post_fields), false);
    putData(&input, 1, "hello, ", false);
    putData(&input, 1, "world", false);
    putHeaders(&input, 1, blocks.encode(&.{.{ .name = "x-checksum", .value = "42" }}), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const events = fixture.eventsOf();
    try testing.expectEqual(@as(usize, 4), events.len);
    try testing.expectEqual(.request, events[0].kind);
    try testing.expect(!events[0].end_stream);
    try testing.expectEqual(.data, events[1].kind);
    try testing.expectEqual(@as(u32, 7), events[1].bytes);
    try testing.expectEqual(.data, events[2].kind);
    try testing.expectEqual(.trailers, events[3].kind);
    try testing.expectEqual(@as(u32, 1), events[3].fields);
}

test "h2 session: content-length is a claim the DATA must keep" {
    const Case = struct { declared: []const u8, sent: []const u8, served: bool };
    const cases = [_]Case{
        .{ .declared = "5", .sent = "abcde", .served = true },
        .{ .declared = "5", .sent = "abc", .served = false },
        .{ .declared = "2", .sent = "abc", .served = false },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        fixture.init();
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        const head = post_fields ++ [_]hpack.Field{.{ .name = "content-length", .value = case.declared }};
        putHeaders(&input, 1, blocks.encode(&head), false);
        putData(&input, 1, case.sent, true);
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        const events = fixture.eventsOf();
        const last = events[events.len - 1];
        if (case.served) {
            try testing.expectEqual(.data, last.kind);
        } else {
            try testing.expectEqual(.reset, last.kind);
            try testing.expectEqual(@as(?frame.ErrorCode, .protocol_error), last.code);
        }
    }
    // A declared body the stream ends without: refused at the head.
    var fixture: Fixture = .{};
    fixture.init();
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    const head = post_fields ++ [_]hpack.Field{.{ .name = "content-length", .value = "5" }};
    putHeaders(&input, 1, blocks.encode(&head), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(usize, 0), fixture.eventsOf().len);
    var reader = fixture.replies();
    try expectReset(reader.nextSkippingAcks(), 1, .protocol_error);
}

test "h2 session: frames after the client's half closed, and trailers that do not end it, are stream errors" {
    // HEADERS, then DATA, on a half-closed(remote) stream: STREAM_CLOSED
    // either way (§5.1).
    for ([_]bool{ false, true }) |data_after| {
        var fixture: Fixture = .{};
        fixture.init();
        fixture.caller = .hold;
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        putHeaders(&input, 1, blocks.encode(&request_fields), true);
        if (data_after) {
            putData(&input, 1, "late", false);
        } else {
            putHeaders(&input, 1, blocks.encode(&.{.{ .name = "x-late", .value = "1" }}), true);
        }
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        var reader = fixture.replies();
        try expectReset(reader.nextSkippingAcks(), 1, .stream_closed);
    }
    // Trailers without END_STREAM: §8.1 makes them the last thing sent.
    var fixture: Fixture = .{};
    fixture.init();
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&post_fields), false);
    putHeaders(&input, 1, blocks.encode(&.{.{ .name = "x-checksum", .value = "1" }}), false);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var reader = fixture.replies();
    try expectReset(reader.nextSkippingAcks(), 1, .protocol_error);
}

test "h2 session: the client's reset ends its stream, and later frames on it are ignored" {
    var fixture: Fixture = .{};
    fixture.init();
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&post_fields), false);
    put(&input, .{ .rst_stream = .{ .error_code = .cancel } }, 1, 0);
    putData(&input, 1, "in flight before the reset", false);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const events = fixture.eventsOf();
    try testing.expectEqual(@as(usize, 2), events.len);
    try testing.expectEqual(.reset, events[1].kind);
    try testing.expectEqual(@as(?frame.ErrorCode, .cancel), events[1].code);
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
    try testing.expect(fixture.session.closed_with == null);
}

test "h2 session: a stream's window is ours once acknowledged, and overrunning it is its error" {
    // Before the ACK the client may still be using the default, so 2048
    // octets are fine; after it, the advertised 1024 is the bound.
    for ([_]bool{ false, true }) |acked| {
        var fixture: Fixture = .{};
        fixture.initWith(.{ .initial_window_size = 1024 });
        fixture.caller = .hold;
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        if (acked) put(&input, .{ .settings = .{ .entries = &.{} } }, 0, frame.Flag.ack.bit());
        putHeaders(&input, 1, blocks.encode(&post_fields), false);
        const body: [2048]u8 = @splat('w');
        putData(&input, 1, &body, false);
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        const events = fixture.eventsOf();
        const last = events[events.len - 1];
        if (acked) {
            try testing.expectEqual(.reset, last.kind);
            try testing.expectEqual(@as(?frame.ErrorCode, .flow_control_error), last.code);
        } else {
            try testing.expectEqual(.data, last.kind);
            try testing.expectEqual(@as(u32, 2048), last.bytes);
        }
    }
}

test "h2 session: consumed octets are credited back, to the stream and the connection" {
    var fixture: Fixture = .{};
    fixture.init();
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&post_fields), false);
    // Two full frames: past half of both windows once both are consumed.
    const chunk: [Session.frame_payload_bytes_max]u8 = @splat('c');
    putData(&input, 1, &chunk, false);
    putData(&input, 1, &chunk, false);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    // The credits go out at the next step, which is where room is found.
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    var reader = fixture.replies();
    const stream_credit = reader.nextSkippingAcks().?;
    try testing.expectEqual(frame.Type.window_update, stream_credit.header.frame_type);
    try testing.expectEqual(@as(u31, 1), stream_credit.header.stream_identifier);
    try testing.expectEqual(@as(u31, 2 * Session.frame_payload_bytes_max), stream_credit.payload.window_update.increment);
    const connection_credit = reader.nextSkippingAcks().?;
    try testing.expectEqual(@as(u31, 0), connection_credit.header.stream_identifier);
    try testing.expectEqual(@as(u31, 2 * Session.frame_payload_bytes_max), connection_credit.payload.window_update.increment);
}

test "h2 session: padding is credited at once, since the caller never holds it" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&post_fields), false);
    // Almost all padding: unconsumed data cannot be what earns the credit.
    // The most one frame may carry is 255 octets, which with its length
    // octet is 256 credited at once — so 128 frames are exactly half of
    // both windows, the threshold each credit waits for.
    const padding: [255]u8 = @splat(0);
    const frames: u32 = 128;
    for (0..frames) |_| put(&input, .{ .data = .{ .data = "d", .padding = &padding } }, 1, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    var reader = fixture.replies();
    // The padding plus its length octet, per frame, to the stream and the
    // connection both; the data octets are still the caller's.
    for ([_]u31{ 1, 0 }) |stream| {
        const credit = reader.nextSkippingAcks().?;
        try testing.expectEqual(frame.Type.window_update, credit.header.frame_type);
        try testing.expectEqual(stream, credit.header.stream_identifier);
        try testing.expectEqual(@as(u31, frames * 256), credit.payload.window_update.increment);
    }
    try testing.expect(reader.next() == null);
}

test "h2 session: a caller's reset goes out as RST_STREAM with its code" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .reset_on_open;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    var reader = fixture.replies();
    try expectReset(reader.nextSkippingAcks(), 1, .refused_stream);
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
}

test "h2 session: after the client's GOAWAY, the connection ends with its last stream" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    put(&input, .{ .goaway = .{ .last_stream_identifier = 0, .error_code = .no_error, .debug_data = &.{} } }, 0, 0);
    // A stream past the GOAWAY is refused rather than believed.
    putHeaders(&input, 3, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var reader = fixture.replies();
    try expectReset(reader.nextSkippingAcks(), 3, .refused_stream);
    fixture.session.close(1);
    try testing.expectEqual(Session.Step.closed, fixture.settle());
    try testing.expect(fixture.session.closed_with == null);
}

test "h2 session: our GOAWAY names the last stream the caller was handed" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    putHeaders(&input, 3, blocks.encode(&request_fields), true);
    putHeaders(&input, 4, &.{0x82}, true);
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
    var reader = fixture.replies();
    var last: ?FrameReader.Frame = null;
    while (reader.next()) |one| last = one;
    try testing.expectEqual(frame.Type.goaway, last.?.header.frame_type);
    try testing.expectEqual(@as(u31, 3), last.?.payload.goaway.last_stream_identifier);
}

test "h2 session: a zero WINDOW_UPDATE is a stream error on a stream, and a connection error elsewhere" {
    const cases = [_]struct { stream: u31, goaway: bool }{
        // Stream zero: §6.9 makes it the connection's error.
        .{ .stream = 0, .goaway = true },
        // An open stream: the stream's error.
        .{ .stream = 1, .goaway = false },
        // An idle stream: §5.1 outranks §6.9, and RST_STREAM may not name it.
        .{ .stream = 5, .goaway = true },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        fixture.init();
        fixture.caller = .hold;
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        putHeaders(&input, 1, blocks.encode(&request_fields), true);
        putRaw(&input, 0x8, 0, case.stream, &.{ 0, 0, 0, 0 });
        const verdict = fixture.feed(input.items);
        if (case.goaway) {
            try testing.expectEqual(Session.Step.closed, verdict);
            try expectGoaway(&fixture, .protocol_error);
            continue;
        }
        try testing.expectEqual(Session.Step.need_input, verdict);
        var reader = fixture.replies();
        try expectReset(reader.nextSkippingAcks(), 1, .protocol_error);
    }
}

test "h2 session: a malformed PRIORITY is its stream's error, and the connection's on an idle stream" {
    // Four octets where §6.3 requires five: FRAME_SIZE_ERROR. On an open
    // stream that is RST_STREAM; on an idle one RST_STREAM may not be sent
    // (§5.1), so the connection carries the error instead.
    const cases = [_]struct { stream: u31, goaway: bool }{
        .{ .stream = 1, .goaway = false },
        .{ .stream = 3, .goaway = true },
        .{ .stream = 2, .goaway = true },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        fixture.init();
        fixture.caller = .hold;
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        putHeaders(&input, 1, blocks.encode(&post_fields), false);
        putRaw(&input, 0x2, 0, case.stream, &.{ 0, 0, 0, 0 });
        const verdict = fixture.feed(input.items);
        if (case.goaway) {
            try testing.expectEqual(Session.Step.closed, verdict);
            try expectGoaway(&fixture, .frame_size_error);
            continue;
        }
        try testing.expectEqual(Session.Step.need_input, verdict);
        var reader = fixture.replies();
        try expectReset(reader.nextSkippingAcks(), 1, .frame_size_error);
        try testing.expect(reader.next() == null);
        const events = fixture.eventsOf();
        try testing.expectEqual(.reset, events[events.len - 1].kind);
    }
}

test "h2 session: once the caller resets a stream, the client's frames on it raise nothing" {
    // While the caller's RST_STREAM is owed and not yet staged, the client
    // can still name the stream: its own reset, a window that would
    // overflow, a malformed frame. None may hand the caller back a stream
    // it let go, and the reset owed is the only one said.
    const Late = enum { peer_reset, window_overflow, malformed };
    for (std.enums.values(Late)) |late| {
        var fixture: Fixture = .{};
        fixture.initWith(.{ .outbox_len = Session.outbox_bytes_min });
        fixture.caller = .hold;
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        putHeaders(&input, 1, blocks.encode(&post_fields), false);
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        // A PONG left unsent: room for the next frame's answer, too little
        // for the owed reset and its reserve.
        var ping: Wire = .empty;
        defer ping.deinit(testing.allocator);
        put(&ping, .{ .ping = .{ .opaque_data = &@splat(3) } }, 0, 0);
        fixture.receive(ping.items);
        try testing.expectEqual(Session.Step.need_input, fixture.session.step());
        try testing.expectEqual(@as(usize, Session.reply_bytes_max), fixture.session.outbound().len);
        fixture.session.resetStream(1, .cancel);
        var later: Wire = .empty;
        defer later.deinit(testing.allocator);
        switch (late) {
            .peer_reset => put(&later, .{ .rst_stream = .{ .error_code = .cancel } }, 1, 0),
            .window_overflow => put(&later, .{ .window_update = .{ .increment = std.math.maxInt(u31) } }, 1, 0),
            .malformed => putRaw(&later, 0x2, 0, 1, &.{ 0, 0, 0, 0 }),
        }
        fixture.receive(later.items);
        // The owed reset still does not fit, and says so.
        try testing.expectEqual(Session.Step.flush_first, fixture.session.step());
        // Nothing staged for it: still just the PONG.
        try testing.expectEqual(@as(usize, Session.reply_bytes_max), fixture.session.outbound().len);
        try testing.expectEqual(Session.Step.need_input, fixture.settle());
        var reader = fixture.replies();
        try testing.expectEqual(frame.Type.ping, reader.nextSkippingAcks().?.header.frame_type);
        // The client's own reset closed the stream at both ends: ours,
        // still owed, has no one left to tell.
        if (late != .peer_reset) try expectReset(reader.nextSkippingAcks(), 1, .cancel);
        try testing.expect(reader.next() == null);
        try testing.expectEqual(@as(usize, 1), fixture.eventsOf().len);
        try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
    }
}

test "h2 session: DATA on a closed stream gives its connection credit back" {
    var fixture: Fixture = .{};
    fixture.initWith(.{ .streams = 1 });
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    putHeaders(&input, 3, blocks.encode(&post_fields), false); // Refused: the table is full.
    const chunk: [Session.frame_payload_bytes_max]u8 = @splat('b');
    for (0..3) |_| putData(&input, 3, &chunk, false);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    var reader = fixture.replies();
    try expectReset(reader.nextSkippingAcks(), 3, .refused_stream);
    const credit = reader.nextSkippingAcks().?;
    try testing.expectEqual(frame.Type.window_update, credit.header.frame_type);
    try testing.expectEqual(@as(u31, 0), credit.header.stream_identifier);
    try testing.expect(fixture.session.closed_with == null);
}

// ---------------------------------------------------------------------------
// Fuzzing
// ---------------------------------------------------------------------------

const empty_settings = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";

test "fuzz: h2 session — any octets, any split: answered or closed, never a third outcome" {
    // Corpus entries lead with the harness's control octet (see
    // `fuzzSession`): `0x07` supplies the opening and reads 8 at a time,
    // `0x80` makes the entry carry its own, `0x27` also resets on open.
    try testing.fuzz({}, fuzzSession, .{ .corpus = &.{
        "\x80" ++ Session.preface ++ empty_settings,
        "\x07" ++ "\x00\x00\x08\x06\x00\x00\x00\x00\x00" ++ "pingping",
        "\x07" ++ "\x00\x00\x04\x01\x04\x00\x00\x00\x01\x82\x87\x84\x41" ++
            "\x00\x00\x03\x00\x01\x00\x00\x00\x01abc",
        "\x27" ++ "\x00\x00\x04\x01\x05\x00\x00\x00\x01\x82\x87\x84\x41",
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
    // draw the read size, so one corpus entry reaches every chunking; bit
    // five swaps in a caller that resets every stream it is handed; bit six
    // the smallest outbox and a short socket, which is the only way
    // `flush_first` — and the reserve `stage` relies on — is ever under the
    // fuzzer; bit seven makes the input carry its own opening, which a raw
    // mutation almost always breaks.
    const control: u8 = if (input_len >= 1) input[0] else 0;
    if (control & 0x40 != 0) {
        fixture.initWith(.{ .outbox_len = Session.outbox_bytes_min });
        fixture.drain_max = 1 + @as(u32, (control >> 2) % 8);
    }
    if (control & 0x20 != 0) fixture.caller = .reset_on_open;
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
    const session = &fixture.session;
    if (verdict == .closed) {
        assert(session.step() == .closed);
        if (session.closed_with) |code| assert(code != .no_error);
        return;
    }
    // The three-way identity holds at the connection, and at every stream.
    assert(session.recv_window + session.recv_unacked + session.recv_delivered == Session.window_default);
    for (session.streams.slots) |slot| {
        if (slot.id == 0) continue;
        assert(slot.recv_window + slot.recv_unacked + slot.recv_delivered == Session.window_default);
    }
    assert(session.outbound().len == 0);
    // `need_input` is never said while this side still owes a frame: the
    // client may be waiting on it before it sends anything more.
    assert(!session.pending);
}
