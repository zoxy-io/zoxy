//! Directed tests and the fuzz target for `Session` as a client: the end of
//! a connection this proxy opens to an HTTP/2 origin.
//!
//! As in `session_test.zig`, every frame the origin sends is built with
//! zoxy-io/h2's own renderer and every field block with a real HPACK
//! encoder, and what the session sends is read back with the codec.

const std = @import("std");
const h2 = @import("h2");

const Session = @import("Session.zig");
const StreamTable = @import("StreamTable.zig");

const frame = h2.frame;
const hpack = h2.hpack;
const testing = std.testing;
const seed = @import("../../testing/bytes.zig").fuzzSeed;
const assert = std.debug.assert;

const header_list_size: u32 = 8192;
const streams_capacity: u32 = 8;

const Event = struct {
    kind: std.meta.Tag(Session.Step),
    stream: u31 = 0,
    status: u16 = 0,
    interim: bool = false,
    bytes: u32 = 0,
    fields: u32 = 0,
    end_stream: bool = false,
    code: ?frame.ErrorCode = null,
};

/// A client session and the buffers it borrows, what it sent, and the
/// events it raised.
const Fixture = struct {
    inbound: [Session.frame_bytes_max]u8 = undefined,
    block: [16 * 1024]u8 = undefined,
    decoded: [header_list_size]u8 = undefined,
    fields: [Session.fieldsFor(header_list_size)]hpack.Field = undefined,
    streams: [streams_capacity]StreamTable.Slot = undefined,
    outbox: [64 * 1024]u8 = undefined,
    table: Session.TableStorage = .{},
    encoder: Session.EncoderStorage = .{},
    session: Session = undefined,
    sent: [256 * 1024]u8 = undefined,
    sent_len: u32 = 0,
    sent_dropped: u64 = 0,
    events: [64]Event = undefined,
    events_len: u32 = 0,
    /// Consume response octets as they arrive; off holds them.
    consume: bool = true,

    const Options = struct {
        outbox_len: u32 = 4096,
        streams: u32 = streams_capacity,
        initial_window_size: u31 = Session.window_default,
    };

    fn initWith(fixture: *Fixture, options: Options) void {
        assert(options.outbox_len <= fixture.outbox.len);
        assert(options.streams <= streams_capacity);
        fixture.sent_len = 0;
        fixture.sent_dropped = 0;
        fixture.events_len = 0;
        fixture.session.init(.{
            .role = .client,
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
            .encoder = &fixture.encoder,
        });
    }

    fn init(fixture: *Fixture) void {
        fixture.initWith(.{});
    }

    fn drainAll(fixture: *Fixture) u32 {
        var sent: u32 = 0;
        while (fixture.session.outbound().len >= 1) {
            const staged = fixture.session.outbound();
            const take: u32 = @intCast(staged.len);
            const kept: u32 = @min(take, fixture.sent.len - fixture.sent_len);
            @memcpy(fixture.sent[fixture.sent_len..][0..kept], staged[0..kept]);
            fixture.sent_len += kept;
            fixture.sent_dropped += take - kept;
            fixture.session.outboundSent(take);
            sent += take;
        }
        return sent;
    }

    /// Hand `bytes` over in reads of at most `chunk`, settling after each.
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

    fn settle(fixture: *Fixture) Session.Step {
        var passes: u32 = 0;
        while (passes < 1 << 20) : (passes += 1) {
            const result = fixture.session.step();
            var sent = fixture.drainAll();
            switch (result) {
                .flush_first => continue,
                .closed => return result,
                .need_input => {
                    sent += fixture.drainAll();
                    if (sent == 0) return result;
                },
                else => fixture.record(result),
            }
        }
        unreachable;
    }

    fn record(fixture: *Fixture, event: Session.Step) void {
        var recorded: Event = .{ .kind = event };
        switch (event) {
            .response => |response| {
                recorded.stream = response.stream;
                recorded.status = response.status;
                recorded.interim = response.interim;
                recorded.fields = @intCast(response.fields.len);
                recorded.end_stream = response.end_stream;
            },
            .data => |data| {
                recorded.stream = data.stream;
                recorded.bytes = @intCast(data.bytes.len);
                recorded.end_stream = data.end_stream;
                if (fixture.consume and data.bytes.len >= 1) {
                    fixture.session.consume(data.stream, @intCast(data.bytes.len));
                }
            },
            .trailers => |trailers| {
                recorded.stream = trailers.stream;
                recorded.fields = @intCast(trailers.fields.len);
            },
            .reset => |reset| {
                recorded.stream = reset.stream;
                recorded.code = reset.code;
            },
            .writable => |writable| recorded.stream = writable.stream,
            .request => unreachable, // A client session raises none.
            .need_input, .flush_first, .closed => unreachable,
        }
        if (fixture.events_len == fixture.events.len) return;
        fixture.events[fixture.events_len] = recorded;
        fixture.events_len += 1;
    }

    fn eventsOf(fixture: *const Fixture) []const Event {
        return fixture.events[0..fixture.events_len];
    }

    /// The frames sent so far, after the preface's magic.
    fn sentFrames(fixture: *const Fixture) FrameReader {
        assert(fixture.sent_dropped == 0);
        assert(std.mem.startsWith(u8, fixture.sent[0..fixture.sent_len], Session.preface));
        return .{ .bytes = fixture.sent[Session.preface.len..fixture.sent_len] };
    }

    /// Open a stream that must open.
    fn open(fixture: *Fixture, fields: []const hpack.Field, end_stream: bool) !u31 {
        try testing.expect(fixture.session.openable());
        const opened = fixture.session.openRequest(fields, end_stream, false);
        try testing.expect(opened == .stream);
        _ = fixture.drainAll();
        return opened.stream;
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

    /// The last frame sent, of any type.
    fn last(reader: *FrameReader) ?Frame {
        var found: ?Frame = null;
        var passes: u32 = 0;
        while (reader.next()) |one| : (passes += 1) {
            assert(passes < 1024);
            found = one;
        }
        return found;
    }
};

const Wire = std.ArrayList(u8);

fn put(out: *Wire, payload: frame.Payload, stream: u31, flags: u8) void {
    var buffer: [Session.frame_bytes_max]u8 = undefined;
    const written = frame.payload.render(&payload, stream, flags, &buffer) catch unreachable;
    out.appendSlice(testing.allocator, buffer[0..written]) catch unreachable;
}

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

/// The origin's preface: SETTINGS with `entries`, each an identifier and a
/// value; and its ACK of the client's.
fn putServerOpening(out: *Wire, entries: []const [2]u32) void {
    var bytes: [6 * 8]u8 = undefined;
    assert(entries.len <= 8);
    for (entries, 0..) |entry, index| {
        std.mem.writeInt(u16, bytes[index * 6 ..][0..2], @intCast(entry[0]), .big);
        std.mem.writeInt(u32, bytes[index * 6 + 2 ..][0..4], entry[1], .big);
    }
    put(out, .{ .settings = .{ .entries = bytes[0 .. entries.len * 6] } }, 0, 0);
    put(out, .{ .settings = .{ .entries = &.{} } }, 0, frame.Flag.ack.bit());
}

const setting_enable_push: u32 = 0x2;
const setting_max_concurrent_streams: u32 = 0x3;
const setting_initial_window_size: u32 = 0x4;

fn putHeaders(out: *Wire, stream: u31, block: []const u8, end_stream: bool) void {
    const flags = frame.Flag.end_headers.bit() | if (end_stream) frame.Flag.end_stream.bit() else 0;
    put(out, .{ .headers = .{ .priority = null, .fragment = block, .padding = null } }, stream, flags);
}

fn putData(out: *Wire, stream: u31, bytes: []const u8, end_stream: bool) void {
    const flags: u8 = if (end_stream) frame.Flag.end_stream.bit() else 0;
    put(out, .{ .data = .{ .data = bytes, .padding = null } }, stream, flags);
}

/// The origin's encoder: one per test, so blocks may lean on earlier ones.
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

const get_fields = [_]hpack.Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":authority", .value = "origin.test" },
    .{ .name = ":path", .value = "/" },
};

const post_fields = [_]hpack.Field{
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":authority", .value = "origin.test" },
    .{ .name = ":path", .value = "/helloworld.Greeter/SayHello" },
    .{ .name = "content-type", .value = "application/grpc" },
    .{ .name = "te", .value = "trailers" },
};

/// A client fixture that has heard the origin's SETTINGS.
fn openedWith(fixture: *Fixture, entries: []const [2]u32) !void {
    fixture.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putServerOpening(&input, entries);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
}

fn expectGoaway(fixture: *const Fixture, code: frame.ErrorCode) !void {
    var reader = fixture.sentFrames();
    const last = reader.last().?;
    try testing.expectEqual(frame.Type.goaway, last.header.frame_type);
    try testing.expectEqual(code, last.payload.goaway.error_code);
    try testing.expectEqual(@as(?frame.ErrorCode, code), fixture.session.closed_with);
}

fn expectEvent(event: Event, kind: std.meta.Tag(Session.Step), stream: u31) !void {
    try testing.expectEqual(kind, event.kind);
    try testing.expectEqual(stream, event.stream);
}

// ---------------------------------------------------------------------------
// The connection
// ---------------------------------------------------------------------------

test "h2 client: the preface's magic and SETTINGS go first, push disabled, nothing opened before the origin's" {
    var fixture: Fixture = .{};
    fixture.init();
    const staged = fixture.session.outbound();
    try testing.expect(std.mem.startsWith(u8, staged, Session.preface));
    var reader: FrameReader = .{ .bytes = staged[Session.preface.len..] };
    const settings = reader.next().?;
    try testing.expect(reader.next() == null);
    try testing.expectEqual(frame.Type.settings, settings.header.frame_type);
    try testing.expect(!settings.header.has(.ack));
    var entries = settings.payload.settings.iterate();
    const push = entries.next().?;
    try testing.expectEqual(frame.payload.Settings.Identifier.enable_push, push.identifier);
    try testing.expectEqual(@as(u32, 0), push.value);
    const list = entries.next().?;
    try testing.expectEqual(frame.payload.Settings.Identifier.max_header_list_size, list.identifier);
    try testing.expect(entries.next() == null);
    // The origin's limit is not known yet.
    try testing.expect(!fixture.session.openable());
}

test "h2 client: the origin's SETTINGS are acknowledged and its stream limit is kept" {
    var fixture: Fixture = .{};
    try openedWith(&fixture, &.{.{ setting_max_concurrent_streams, 2 }});
    var reader = fixture.sentFrames();
    _ = reader.next().?; // Its own SETTINGS.
    const ack = reader.next().?;
    try testing.expectEqual(frame.Type.settings, ack.header.frame_type);
    try testing.expect(ack.header.has(.ack));
    try testing.expectEqual(@as(u31, 1), try fixture.open(&get_fields, true));
    try testing.expectEqual(@as(u31, 3), try fixture.open(&get_fields, true));
    // Two open, two allowed.
    try testing.expect(!fixture.session.openable());
}

test "h2 client: an origin that sends something other than SETTINGS first is refused" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    put(&input, .{ .ping = .{ .opaque_data = &@splat(1) } }, 0, 0);
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
    try expectGoaway(&fixture, .protocol_error);
}

test "h2 client: an origin may not enable push, and may not push" {
    {
        var fixture: Fixture = .{};
        fixture.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putServerOpening(&input, &.{.{ setting_enable_push, 1 }});
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .protocol_error);
    }
    {
        var fixture: Fixture = .{};
        try openedWith(&fixture, &.{});
        _ = try fixture.open(&get_fields, true);
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        // PUSH_PROMISE on stream 1, promising stream 2 with an empty block.
        putRaw(&input, 0x5, frame.Flag.end_headers.bit(), 1, "\x00\x00\x00\x02");
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .protocol_error);
    }
}

// ---------------------------------------------------------------------------
// Requests and responses
// ---------------------------------------------------------------------------

test "h2 client: a request opens an odd stream, and its answer comes back head, interim first, then body" {
    var fixture: Fixture = .{};
    try openedWith(&fixture, &.{});
    const stream = try fixture.open(&get_fields, true);
    var reader = fixture.sentFrames();
    var headers: ?FrameReader.Frame = null;
    while (reader.next()) |one| {
        if (one.header.frame_type == .headers) headers = one;
    }
    try testing.expectEqual(stream, headers.?.header.stream_identifier);
    try testing.expect(headers.?.header.has(.end_stream));

    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putHeaders(&input, stream, blocks.encode(&.{.{ .name = ":status", .value = "103" }}), false);
    putHeaders(&input, stream, blocks.encode(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "5" },
    }), false);
    putData(&input, stream, "hel", false);
    putData(&input, stream, "lo", true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const events = fixture.eventsOf();
    try testing.expectEqual(@as(usize, 4), events.len);
    try expectEvent(events[0], .response, stream);
    try testing.expect(events[0].interim);
    try testing.expectEqual(@as(u16, 103), events[0].status);
    try expectEvent(events[1], .response, stream);
    try testing.expect(!events[1].interim);
    try testing.expectEqual(@as(u16, 200), events[1].status);
    try expectEvent(events[2], .data, stream);
    try expectEvent(events[3], .data, stream);
    try testing.expect(events[3].end_stream);
    // Both halves ended: the stream is gone, and its slot free.
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
    try testing.expectEqual(@as(u31, 3), try fixture.open(&get_fields, true));
}

test "h2 client: a gRPC answer ends in its trailers, and a request body goes out under the origin's window" {
    var fixture: Fixture = .{};
    try openedWith(&fixture, &.{.{ setting_initial_window_size, 4 }});
    const stream = try fixture.open(&post_fields, false);
    // Four octets of window: the rest waits for credit.
    const message = "\x00\x00\x00\x00\x02hi";
    const first = fixture.session.sendData(stream, message, true);
    try testing.expectEqual(@as(u32, 4), first.taken);
    try testing.expect(!first.ended);
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    put(&input, .{ .window_update = .{ .increment = 100 } }, stream, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try expectEvent(fixture.eventsOf()[0], .writable, stream);
    const rest = fixture.session.sendData(stream, message[4..], true);
    try testing.expect(rest.ended);
    _ = fixture.drainAll();

    var blocks: Blocks = .{};
    blocks.init();
    input.clearRetainingCapacity();
    putHeaders(&input, stream, blocks.encode(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/grpc" },
    }), false);
    putData(&input, stream, "\x00\x00\x00\x00\x02ok", false);
    putHeaders(&input, stream, blocks.encode(&.{
        .{ .name = "grpc-status", .value = "0" },
        .{ .name = "grpc-message", .value = "" },
    }), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const events = fixture.eventsOf()[1..];
    try testing.expectEqual(@as(usize, 3), events.len);
    try expectEvent(events[0], .response, stream);
    try expectEvent(events[1], .data, stream);
    try expectEvent(events[2], .trailers, stream);
    try testing.expectEqual(@as(u32, 2), events[2].fields);
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
}

test "h2 client: a HEAD's answer, a 204 and a 304 declare a length that binds no DATA" {
    for ([_][]const u8{ "200", "304" }) |status| {
        var fixture: Fixture = .{};
        try openedWith(&fixture, &.{});
        const opened_head = fixture.session.openRequest(&get_fields, true, std.mem.eql(u8, status, "200"));
        const stream = opened_head.stream;
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putHeaders(&input, stream, blocks.encode(&.{
            .{ .name = ":status", .value = status },
            .{ .name = "content-length", .value = "42" },
        }), true);
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        try expectEvent(fixture.eventsOf()[0], .response, stream);
        try testing.expect(fixture.eventsOf()[0].end_stream);
    }
}

test "h2 client: a malformed answer resets its stream alone" {
    const Case = struct { fields: []const hpack.Field, end_stream: bool, data_first: bool = false };
    const cases = [_]Case{
        // §8.6: no 101 in HTTP/2.
        .{ .fields = &.{.{ .name = ":status", .value = "101" }}, .end_stream = false },
        // §8.1: an interim head ends nothing.
        .{ .fields = &.{.{ .name = ":status", .value = "100" }}, .end_stream = true },
        // Statuses no HTTP/1.1 line could carry, or RFC 9110 defines.
        .{ .fields = &.{.{ .name = ":status", .value = "20" }}, .end_stream = true },
        .{ .fields = &.{.{ .name = ":status", .value = "600" }}, .end_stream = true },
        // A request's pseudo-header in a response.
        .{ .fields = &.{ .{ .name = ":status", .value = "200" }, .{ .name = ":path", .value = "/" } }, .end_stream = true },
        // A declared length the stream contradicts by ending.
        .{ .fields = &.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-length", .value = "3" } }, .end_stream = true },
        // DATA before any head.
        .{ .fields = &.{}, .end_stream = false, .data_first = true },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        try openedWith(&fixture, &.{});
        const stream = try fixture.open(&get_fields, true);
        const sibling = try fixture.open(&get_fields, true);
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        if (case.data_first) {
            putData(&input, stream, "x", false);
        } else {
            putHeaders(&input, stream, blocks.encode(case.fields), case.end_stream);
        }
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        const events = fixture.eventsOf();
        try testing.expectEqual(@as(usize, 1), events.len);
        try expectEvent(events[0], .reset, stream);
        try testing.expectEqual(@as(?frame.ErrorCode, .protocol_error), events[0].code);
        var reader = fixture.sentFrames();
        const last = reader.last().?;
        try testing.expectEqual(frame.Type.rst_stream, last.header.frame_type);
        try testing.expectEqual(stream, last.header.stream_identifier);
        // The sibling is untouched.
        try testing.expect(fixture.session.streams.find(sibling) != null);
        try testing.expect(fixture.session.state == .open);
    }
}

test "h2 client: a block on a stream never opened, or on an even one, is the connection's error" {
    for ([_]u31{ 3, 2 }) |stream| {
        var fixture: Fixture = .{};
        try openedWith(&fixture, &.{});
        _ = try fixture.open(&get_fields, true);
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putHeaders(&input, stream, blocks.encode(&.{.{ .name = ":status", .value = "200" }}), true);
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .protocol_error);
    }
}

test "h2 client: the origin's reset reaches the caller, and an answer to a stream the caller reset is ignored" {
    var fixture: Fixture = .{};
    try openedWith(&fixture, &.{});
    const reset_by_origin = try fixture.open(&get_fields, true);
    const reset_by_caller = try fixture.open(&get_fields, true);
    fixture.session.resetStream(reset_by_caller, .cancel);
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    put(&input, .{ .rst_stream = .{ .error_code = .refused_stream } }, reset_by_origin, 0);
    // In flight when the caller's reset went out.
    putHeaders(&input, reset_by_caller, blocks.encode(&.{.{ .name = ":status", .value = "200" }}), false);
    putData(&input, reset_by_caller, "late", true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const events = fixture.eventsOf();
    try testing.expectEqual(@as(usize, 1), events.len);
    try expectEvent(events[0], .reset, reset_by_origin);
    try testing.expectEqual(@as(?frame.ErrorCode, .refused_stream), events[0].code);
    try testing.expect(fixture.session.state == .open);
}

test "h2 client: an origin's GOAWAY refuses every stream past its last, and the connection ends with the rest" {
    var fixture: Fixture = .{};
    try openedWith(&fixture, &.{});
    const kept = try fixture.open(&get_fields, true);
    const refused_a = try fixture.open(&get_fields, true);
    const refused_b = try fixture.open(&get_fields, true);
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    put(&input, .{ .goaway = .{ .last_stream_identifier = kept, .error_code = .no_error, .debug_data = &.{} } }, 0, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const events = fixture.eventsOf();
    try testing.expectEqual(@as(usize, 2), events.len);
    try expectEvent(events[0], .reset, refused_a);
    try expectEvent(events[1], .reset, refused_b);
    try testing.expectEqual(@as(?frame.ErrorCode, .refused_stream), events[1].code);
    // Nothing more opens on a connection going away.
    try testing.expect(!fixture.session.openable());
    var blocks: Blocks = .{};
    blocks.init();
    input.clearRetainingCapacity();
    putHeaders(&input, kept, blocks.encode(&.{.{ .name = ":status", .value = "204" }}), true);
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
    try expectEvent(fixture.eventsOf()[2], .response, kept);
    try testing.expectEqual(@as(?frame.ErrorCode, null), fixture.session.closed_with);
}

test "h2 client: a refused stream's undelivered octets go back to the connection's window" {
    var fixture: Fixture = .{};
    try openedWith(&fixture, &.{});
    fixture.consume = false;
    const kept = try fixture.open(&get_fields, true);
    const refused = try fixture.open(&get_fields, true);
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    // The origin answers the stream it is about to refuse, and the caller
    // holds the octets — then the GOAWAY takes the stream from under it.
    putHeaders(&input, refused, blocks.encode(&.{.{ .name = ":status", .value = "200" }}), false);
    const chunk: [14_000]u8 = @splat('x');
    for (0..3) |_| putData(&input, refused, &chunk, false);
    put(&input, .{ .goaway = .{ .last_stream_identifier = kept, .error_code = .no_error, .debug_data = &.{} } }, 0, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const events = fixture.eventsOf();
    try expectEvent(events[events.len - 1], .reset, refused);
    const session = &fixture.session;
    try testing.expectEqual(@as(u32, 0), session.recv_delivered);
    try testing.expect(session.recv_window + session.recv_unacked == Session.window_default);
    // Past half the window: the connection's credit went out.
    var reader = fixture.sentFrames();
    var credit: u32 = 0;
    while (reader.next()) |one| {
        if (one.header.frame_type == .window_update and one.header.stream_identifier == 0) {
            credit += one.payload.window_update.increment;
        }
    }
    try testing.expectEqual(@as(u32, 3 * chunk.len), credit);
}

test "h2 client: a GOAWAY naming no stream ends a connection with none open at once" {
    var fixture: Fixture = .{};
    try openedWith(&fixture, &.{});
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    put(&input, .{ .goaway = .{ .last_stream_identifier = 0, .error_code = .no_error, .debug_data = &.{} } }, 0, 0);
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
}

test "h2 client: a head that does not fit the outbox waits, spending no identifier" {
    var fixture: Fixture = .{};
    // Room past the reserve for the POST's head (about 160 octets) once
    // the outbox is empty, and not beside the opening still staged in it.
    fixture.initWith(.{ .outbox_len = Session.send_reserve + 180 });
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putServerOpening(&input, &.{});
    // Settle without draining the client's own opening.
    const room = fixture.session.recvBuffer();
    @memcpy(room[0..input.items.len], input.items);
    fixture.session.received(@intCast(input.items.len));
    var passes: u32 = 0;
    while (fixture.session.step() != .need_input) : (passes += 1) try testing.expect(passes < 8);
    try testing.expect(fixture.session.openable());
    try testing.expect(fixture.session.openRequest(&post_fields, false, false) == .blocked);
    _ = fixture.drainAll();
    try testing.expectEqual(@as(u31, 1), (fixture.session.openRequest(&post_fields, false, false)).stream);
}

// ---------------------------------------------------------------------------
// Fuzz
// ---------------------------------------------------------------------------

const server_settings = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// `:status 200` (static index 8), and `content-length 2` as a literal on
/// its static name (index 28), on streams 1 and 3.
const response_200_1 = "\x00\x00\x04\x01\x04\x00\x00\x00\x01\x88\x0f\x0d\x01\x32";
const data_ok_1 = "\x00\x00\x02\x00\x01\x00\x00\x00\x01ok";

test "fuzz: h2 client session — any octets from an origin, any split: answered or closed" {
    try testing.fuzz({}, fuzzClient, .{
        .corpus = &.{
            seed("\x00" ++ server_settings ++ response_200_1 ++ data_ok_1),
            seed("\x13" ++ server_settings ++ "\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"),
            seed("\x07" ++ server_settings ++ "\x00\x00\x04\x03\x00\x00\x00\x00\x03\x00\x00\x00\x07"),
        },
    });
}

var fuzz_fixture: Fixture = .{};

fn fuzzClient(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input: [4096]u8 = undefined;
    const input_len = smith.slice(&input);
    assert(input_len <= input.len);
    runClient(input[0..input_len]);
}

// Origin frames drawn from a seeded PRNG, each with a type, flags, stream
// and payload from small sets that reach every handler: what the fuzz
// target sees under `zig build test`, where nothing else drives it.
test "h2 client: seeded origin frames are answered or closed, never a third outcome" {
    var prng = std.Random.DefaultPrng.init(0x7a6f7879);
    const random = prng.random();
    var input: [4096]u8 = undefined;
    for (0..4000) |_| {
        input[0] = random.int(u8);
        var len: usize = 1;
        @memcpy(input[len..][0..server_settings.len], server_settings);
        len += server_settings.len;
        const frames = random.uintLessThan(u32, 12);
        for (0..frames) |_| len = putRandomFrame(random, &input, len);
        runClient(input[0..len]);
    }
}

/// A frame of a type 0..9, flags, a stream of 0..5, and a payload: a
/// response block from `response_blocks`, a short run of octets, or a
/// stream identifier and code-sized field.
fn putRandomFrame(random: std.Random, input: []u8, start: usize) usize {
    const payload_max = 24;
    if (start + frame.Header.octets + payload_max > input.len) return start;
    // HEADERS and DATA twice as often as the rest: they carry the answers.
    const frame_type = switch (random.uintLessThan(u8, 14)) {
        10, 11 => 0x1,
        12, 13 => 0x0,
        else => |other| other,
    };
    const payload = input[start + frame.Header.octets ..];
    var length: usize = 0;
    if (frame_type == 0x1 and random.uintLessThan(u8, 4) != 0) {
        const block = response_blocks[random.uintLessThan(usize, response_blocks.len)];
        @memcpy(payload[0..block.len], block);
        length = block.len;
    } else {
        // DATA short enough, mostly, to fit a declared length of two.
        const short = frame_type == 0x0 and random.uintLessThan(u8, 4) != 0;
        length = random.uintLessThan(usize, if (short) 3 else payload_max);
        random.bytes(payload[0..length]);
    }
    const header = input[start..][0..frame.Header.octets];
    std.mem.writeInt(u24, header[0..3], @intCast(length), .big);
    header[3] = frame_type;
    // END_HEADERS mostly, END_STREAM by chance, padding and priority rarely.
    header[4] = if (random.uintLessThan(u8, 8) == 0) random.int(u8) else 0x4 | (random.int(u8) & 0x1);
    // The streams this side opens, mostly; 0, 2 and 4 now and then.
    const streams = [_]u32{ 1, 3, 5, 1, 3, 5, 1, 0, 2, 4 };
    std.mem.writeInt(u32, header[5..9], streams[random.uintLessThan(usize, streams.len)], .big);
    return start + frame.Header.octets + length;
}

/// Field blocks an origin answers with: `:status` 200, 103, 204 and an
/// invalid 20, `content-length 2`, and a trailer's `grpc-status 0`.
const response_blocks = [_][]const u8{
    "\x88",
    "\x88\x0f\x0d\x01\x32",
    "\x89",
    "\x08\x03103",
    "\x08\x0220",
    "\x00\x0bgrpc-status\x010",
};

fn runClient(input: []const u8) void {
    // The first octet is the harness's: its low nibble draws the read
    // size; bit four holds response octets rather than consuming them.
    const control: u8 = if (input.len >= 1) input[0] else 0;
    const fixture = &fuzz_fixture;
    fixture.initWith(.{});
    fixture.consume = control & 0x10 == 0;
    const chunk: u32 = 1 + @as(u32, control % 16);
    const body = input[@min(input.len, 1)..];
    // Two streams open from the start once the origin's SETTINGS are in, a
    // third (a POST, its body still to come) whenever one may open.
    var verdict = fixture.settle();
    var offset: usize = 0;
    var opened_count: u32 = 0;
    while (offset < body.len and verdict != .closed) {
        if (fixture.session.openable() and opened_count < 3) {
            const fields: []const hpack.Field = if (opened_count == 2) &post_fields else &get_fields;
            switch (fixture.session.openRequest(fields, opened_count != 2, false)) {
                .stream => opened_count += 1,
                .blocked => {},
                .refused => unreachable, // Well-formed, in an outbox that holds it.
            }
        }
        const take = @min(chunk, body.len - offset);
        verdict = fixture.feedChunked(body[offset..][0..take], chunk);
        offset += take;
    }
    assert(verdict == .need_input or verdict == .closed);
    const session = &fixture.session;
    if (verdict == .closed) {
        assert(session.step() == .closed);
        return;
    }
    // Every window stays a three-way split of where it started.
    assert(session.recv_window + session.recv_unacked + session.recv_delivered == Session.window_default);
    assert(session.streams.used <= streams_capacity);
}
