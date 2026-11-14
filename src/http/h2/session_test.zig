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
const seed = @import("../../testing/bytes.zig").fuzzSeed;
const assert = std.debug.assert;

const header_list_size: u32 = 8192;
const streams_capacity: u32 = 8;

/// What the caller does with each event, standing in for the server.
const Caller = enum {
    /// Consume body octets as they arrive and answer nothing: a server
    /// still thinking, which keeps every reply a test inspects a control
    /// frame.
    consume,
    /// Consume, and answer each request with `response_head` and `body`
    /// once the client's half is over — a server that read it all first.
    respond,
    /// Consume, and answer at the request head, while the client may still
    /// be sending its body.
    respond_early,
    /// Reset every stream the moment it opens — a server shedding.
    reset_on_open,
    /// Hold everything: no consume, no answer.
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

/// One response in progress: how far it got, so `.writable` can resume it.
const Job = struct {
    /// Zero marks a free job.
    stream: u31 = 0,
    /// Whether to send yet: at the head for `.respond_early`, at the
    /// request's end for `.respond`.
    started: bool = false,
    head_sent: bool = false,
    body_offset: u32 = 0,
};

const response_head = [_]hpack.Field{
    .{ .name = ":status", .value = "200" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "server", .value = "zoxy-session-test" },
};

/// A session and the buffers it borrows, a capture of everything it sent,
/// and the events it raised — the test's view of both directions.
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
    /// Everything sent, as far as it fits; past that it is counted and
    /// dropped, which only the fuzz target ever reaches.
    sent: [1 << 20]u8 = undefined,
    sent_len: u32 = 0,
    sent_dropped: u64 = 0,
    events: [256]Event = undefined,
    events_len: u32 = 0,
    caller: Caller = .consume,
    jobs: [streams_capacity]Job = @splat(.{}),
    /// The response body `respond` sends after `response_head`; empty sends
    /// the head alone, with END_STREAM.
    body: []const u8 = "hello",
    /// The most one send takes. A socket that takes everything is the
    /// default; a short one is how the fuzz target reaches `flush_first`.
    drain_max: u32 = std.math.maxInt(u32),

    const Options = struct {
        outbox_len: u32 = 512,
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
        fixture.sent_dropped = 0;
        fixture.events_len = 0;
        fixture.jobs = @splat(.{});
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
            .encoder = &fixture.encoder,
        });
    }

    /// Send what is staged, as far as the socket takes it. Answers the
    /// octets sent.
    fn drain(fixture: *Fixture) u32 {
        const staged = fixture.session.outbound();
        if (staged.len == 0) return 0;
        const take: u32 = @intCast(@min(staged.len, fixture.drain_max));
        const kept: u32 = @min(take, fixture.sent.len - fixture.sent_len);
        @memcpy(fixture.sent[fixture.sent_len..][0..kept], staged[0..kept]);
        fixture.sent_len += kept;
        fixture.sent_dropped += take - kept;
        fixture.session.outboundSent(take);
        return take;
    }

    fn drainAll(fixture: *Fixture) u32 {
        var sent: u32 = 0;
        while (fixture.session.outbound().len >= 1) sent += fixture.drain();
        return sent;
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
    /// answering each event the way `caller` says — and stepping again
    /// after a drain, as a server does when a send completes, since room
    /// freed is what a waiting stream may be waiting for. Each pass moves
    /// octets out, handles an event, or returns, so the bound is generous
    /// rather than tight.
    fn settle(fixture: *Fixture) Session.Step {
        var passes: u32 = 0;
        while (passes < 1 << 24) : (passes += 1) {
            const result = fixture.session.step();
            var sent = fixture.drain();
            switch (result) {
                .flush_first => continue,
                .closed => {
                    _ = fixture.drainAll();
                    return result;
                },
                .need_input => {
                    sent += fixture.drainAll();
                    if (sent == 0) return result;
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
                fixture.answerRequest(request.stream, request.end_stream);
            },
            .data => |data| {
                recorded.stream = data.stream;
                recorded.bytes = @intCast(data.bytes.len);
                recorded.end_stream = data.end_stream;
                if (fixture.caller != .hold and data.bytes.len >= 1) {
                    fixture.session.consume(data.stream, @intCast(data.bytes.len));
                }
                if (data.end_stream) fixture.requestEnded(data.stream);
            },
            .trailers => |trailers| {
                recorded.stream = trailers.stream;
                recorded.fields = @intCast(trailers.fields.len);
                fixture.requestEnded(trailers.stream);
            },
            .reset => |reset| {
                recorded.stream = reset.stream;
                recorded.code = reset.code;
                if (fixture.jobOf(reset.stream)) |job| job.* = .{};
            },
            .writable => |writable| {
                recorded.stream = writable.stream;
                if (fixture.jobOf(writable.stream)) |job| fixture.push(job);
            },
            .need_input, .flush_first, .closed => unreachable,
        }
        // The fuzz target can raise more events than a test inspects; the
        // record keeps the first ones and the answers go on regardless.
        if (fixture.events_len == fixture.events.len) return;
        fixture.events[fixture.events_len] = recorded;
        fixture.events_len += 1;
    }

    fn answerRequest(fixture: *Fixture, stream: u31, end_stream: bool) void {
        switch (fixture.caller) {
            .consume, .hold => {},
            .reset_on_open => fixture.session.resetStream(stream, .refused_stream),
            .respond, .respond_early => {
                const job = fixture.jobOf(0).?; // As many jobs as slots.
                job.* = .{ .stream = stream };
                if (fixture.caller == .respond_early or end_stream) {
                    job.started = true;
                    fixture.push(job);
                }
            },
        }
    }

    fn requestEnded(fixture: *Fixture, stream: u31) void {
        if (fixture.caller != .respond) return;
        const job = fixture.jobOf(stream) orelse return;
        if (job.started) return;
        job.started = true;
        fixture.push(job);
    }

    fn jobOf(fixture: *Fixture, stream: u31) ?*Job {
        for (&fixture.jobs) |*job| {
            if (job.stream == stream) return job;
        }
        return null;
    }

    /// Send as much of a job's response as the session takes, freeing the
    /// job once its END_STREAM is out.
    fn push(fixture: *Fixture, job: *Job) void {
        assert(job.stream != 0);
        if (!job.started) return;
        if (!job.head_sent) {
            switch (fixture.session.sendHead(job.stream, &response_head, fixture.body.len == 0)) {
                .staged => job.head_sent = true,
                .blocked => return,
                // Well formed, so the outbox is what cannot hold it: the
                // stream is the caller's to reset, as a server's would be.
                .refused => {
                    fixture.session.resetStream(job.stream, .internal_error);
                    job.* = .{};
                    return;
                },
            }
            if (fixture.body.len == 0) {
                job.* = .{};
                return;
            }
        }
        const sent = fixture.session.sendData(job.stream, fixture.body[job.body_offset..], true);
        job.body_offset += sent.taken;
        if (sent.ended) job.* = .{};
    }

    fn eventsOf(fixture: *const Fixture) []const Event {
        return fixture.events[0..fixture.events_len];
    }

    /// The frames sent so far, after the server's own SETTINGS.
    fn replies(fixture: *const Fixture) FrameReader {
        assert(fixture.sent_dropped == 0);
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
    fixture.caller = .respond;
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
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used); // Answered, so gone.
}

test "h2 session: a request that breaks §8's rules is reset, and HPACK stays in step for the next" {
    // One verdict per rule of the downgrade (#275): each of these, written
    // out as HTTP/1.1, would tell the origin something the client was not
    // entitled to say — or could not be written out at all.
    const method, const scheme, const authority, const path, const agent = request_fields;
    const malformed = [_][]const hpack.Field{
        // §8.2.2: the connection-specific fields, each a way to tell an
        // HTTP/1.1 origin how the bytes after it are framed.
        &(request_fields ++ [_]hpack.Field{.{ .name = "connection", .value = "keep-alive" }}),
        &(request_fields ++ [_]hpack.Field{.{ .name = "keep-alive", .value = "timeout=5" }}),
        &(request_fields ++ [_]hpack.Field{.{ .name = "proxy-connection", .value = "keep-alive" }}),
        &(request_fields ++ [_]hpack.Field{.{ .name = "transfer-encoding", .value = "chunked" }}),
        &(request_fields ++ [_]hpack.Field{.{ .name = "upgrade", .value = "websocket" }}),
        // §8.2.2's one exception, and only for `trailers`.
        &(request_fields ++ [_]hpack.Field{.{ .name = "te", .value = "gzip" }}),
        // §8.2.1: an uppercase name.
        &(request_fields ++ [_]hpack.Field{.{ .name = "User-Agent", .value = "x" }}),
        // §8.3.1: each pseudo-header a request must carry, missing.
        &[_]hpack.Field{ scheme, authority, path, agent },
        &[_]hpack.Field{ method, authority, path, agent },
        &[_]hpack.Field{ method, scheme, authority, agent },
        // §8.3: a pseudo-header after a regular field, a second one, and
        // one a request does not define — a response's, and an unknown.
        &[_]hpack.Field{ method, scheme, authority, agent, path },
        &[_]hpack.Field{ method, scheme, authority, path, path, agent },
        &[_]hpack.Field{ method, scheme, authority, path, .{ .name = ":status", .value = "200" } },
        &[_]hpack.Field{ method, scheme, authority, path, .{ .name = ":tenant", .value = "a" } },
        // RFC 8441's `:protocol`: extended CONNECT, which this server's
        // SETTINGS never offer — so WebSocket over HTTP/2 ends here.
        &[_]hpack.Field{
            .{ .name = ":method", .value = "CONNECT" }, .{ .name = ":protocol", .value = "websocket" },
            scheme,                                     authority,
            path,
        },
        // §8.2.1: octets an HTTP/1.1 parser reads as a line's end, or that
        // end a C string — HPACK carries any octet, HTTP/1.1's grammar
        // none of these. CRLF, either half alone, NUL; in a value, and in
        // a name, where they would split one field into two.
        &(request_fields ++ [_]hpack.Field{.{ .name = "x-split", .value = "a\r\nb: c" }}),
        &(request_fields ++ [_]hpack.Field{.{ .name = "x-split", .value = "a\nb: c" }}),
        &(request_fields ++ [_]hpack.Field{.{ .name = "x-split", .value = "a\rb: c" }}),
        &(request_fields ++ [_]hpack.Field{.{ .name = "x-split", .value = "a\x00b" }}),
        &(request_fields ++ [_]hpack.Field{.{ .name = "x-split\r\nhost", .value = "other.test" }}),
        &(request_fields ++ [_]hpack.Field{.{ .name = "x-\x00split", .value = "a" }}),
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

test "h2 session: `te: trailers`, §8.2.2's one exception, is a request like any other" {
    var fixture: Fixture = .{};
    fixture.init();
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    const fields = request_fields ++ [_]hpack.Field{.{ .name = "te", .value = "trailers" }};
    putHeaders(&input, 1, blocks.encode(&fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var reader = fixture.replies();
    try testing.expect(reader.nextSkippingAcks() == null);
    const events = fixture.eventsOf();
    try testing.expectEqual(@as(usize, 1), events.len);
    try testing.expectEqual(.request, events[0].kind);
    try testing.expectEqual(@as(u32, fields.len), events[0].fields);
}

test "h2 session: a client's identifiers only go up — a skipped one or a closed one reopened ends the connection" {
    // §5.1.1: "MUST be numerically greater than all streams that the
    // initiating endpoint has opened". Stream 1 after 3 is one the client
    // skipped; stream 1 after it was answered and gone is one it reuses.
    const Reopened = enum { skipped, reused };
    for (std.enums.values(Reopened)) |reopened| {
        var fixture: Fixture = .{};
        fixture.init();
        fixture.caller = .respond;
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        switch (reopened) {
            .skipped => putHeaders(&input, 3, blocks.encode(&request_fields), true),
            .reused => putHeaders(&input, 1, blocks.encode(&request_fields), true),
        }
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
        var again: Wire = .empty;
        defer again.deinit(testing.allocator);
        putHeaders(&again, 1, blocks.encode(&request_fields), true);
        try testing.expectEqual(Session.Step.closed, fixture.feed(again.items));
        try expectGoaway(&fixture, .protocol_error);
        // Only the first stream ever reached the caller.
        try testing.expectEqual(@as(usize, 1), fixture.eventsOf().len);
    }
}

test "h2 session: a client's frames in flight on a stream this side reset are ignored, until the reset is forgotten" {
    // §5.1: "MUST ignore frames that it receives on closed streams after
    // it has sent a RST_STREAM". The client's body and trailers were on
    // their way when the reset left; they end nothing — and the trailers'
    // block is still decoded, which the next request leans on.
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .reset_on_open;
    var blocks: Blocks = .{};
    blocks.init();
    const trailer = hpack.Field{ .name = "x-checksum", .value = "0123456789abcdef" };
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&post_fields), false);
    putData(&input, 1, "in flight", false);
    putHeaders(&input, 1, blocks.encode(&.{trailer}), true);
    putHeaders(&input, 3, blocks.encode(&(request_fields ++ [_]hpack.Field{trailer})), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(?frame.ErrorCode, null), fixture.session.closed_with);
    var reader = fixture.replies();
    try expectReset(reader.nextSkippingAcks(), 1, .refused_stream);
    try expectReset(reader.nextSkippingAcks(), 3, .refused_stream);
    const events = fixture.eventsOf();
    try testing.expectEqual(@as(usize, 2), events.len);
    try testing.expectEqual(@as(u31, 3), events[1].stream);
    // A reset is remembered for as long as the ring holds it: past that
    // many later resets, a frame on stream 1 is no longer one in flight
    // but a client reopening a stream it closed.
    var later: Wire = .empty;
    defer later.deinit(testing.allocator);
    var stream: u31 = 5;
    while (stream < 5 + 2 * Session.reset_ring_len) : (stream += 2) {
        putHeaders(&later, stream, blocks.encode(&request_fields), true);
    }
    try testing.expectEqual(Session.Step.need_input, fixture.feed(later.items));
    try testing.expectEqual(@as(?frame.ErrorCode, null), fixture.session.closed_with);
    var forgotten: Wire = .empty;
    defer forgotten.deinit(testing.allocator);
    putHeaders(&forgotten, 1, blocks.encode(&.{trailer}), true);
    try testing.expectEqual(Session.Step.closed, fixture.feed(forgotten.items));
    try expectGoaway(&fixture, .protocol_error);
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
    // And once the first is answered — both halves over, so it is gone —
    // the next stream gets the slot, which it could only decode if stream
    // 3's block had been decoded too.
    try testing.expectEqual(Session.Sent.staged, fixture.session.sendHead(1, &response_head, true));
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
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
    try testing.expectEqual(Session.Sent.staged, fixture.session.sendHead(1, &response_head, true));
    try testing.expectEqual(Session.Step.closed, fixture.settle());
    try testing.expect(fixture.session.closed_with == null);
}

test "h2 session: going away with nothing open is a GOAWAY(NO_ERROR) and the end" {
    var fixture: Fixture = .{};
    fixture.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    fixture.session.goAway();
    fixture.session.goAway(); // A drain asked for twice is one drain.
    try testing.expectEqual(Session.Step.closed, fixture.settle());
    try testing.expect(fixture.session.closed_with == null); // A drain, not an error.
    var reader = fixture.replies();
    const goaway = reader.nextSkippingAcks().?;
    try testing.expectEqual(frame.Type.goaway, goaway.header.frame_type);
    try testing.expectEqual(frame.ErrorCode.no_error, goaway.payload.goaway.error_code);
    try testing.expectEqual(@as(u31, 0), goaway.payload.goaway.last_stream_identifier);
    try testing.expect(reader.next() == null);
}

test "h2 session: going away finishes what was accepted and refuses what comes after" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&post_fields), false);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    fixture.session.goAway();
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    // A newer stream is refused; the accepted one is still served.
    var more: Wire = .empty;
    defer more.deinit(testing.allocator);
    putHeaders(&more, 3, blocks.encode(&request_fields), true);
    putData(&more, 1, "body", true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(more.items));
    var reader = fixture.replies();
    const goaway = reader.nextSkippingAcks().?;
    try testing.expectEqual(frame.Type.goaway, goaway.header.frame_type);
    try testing.expectEqual(frame.ErrorCode.no_error, goaway.payload.goaway.error_code);
    try testing.expectEqual(@as(u31, 1), goaway.payload.goaway.last_stream_identifier);
    try expectReset(reader.nextSkippingAcks(), 3, .refused_stream);
    const events = fixture.eventsOf();
    try testing.expectEqual(.data, events[events.len - 1].kind);
    // Answering the last accepted stream ends the connection.
    try testing.expectEqual(Session.Sent.staged, fixture.session.sendHead(1, &response_head, true));
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
// Responses
// ---------------------------------------------------------------------------

/// The client's half of the response blocks: its own decoder table, fed
/// each block whole, in the order the blocks went out.
const Responses = struct {
    table: Session.TableStorage = .{},
    decoder: hpack.Decoder = undefined,
    block: [64 * 1024]u8 = undefined,
    decoded: [64 * 1024]u8 = undefined,
    fields: [64]hpack.Field = undefined,

    const Block = struct {
        stream: u31,
        end_stream: bool,
        frames: u32,
        raw: []const u8,
        fields: []const hpack.Field,
    };

    fn init(responses: *Responses) void {
        responses.table = .{};
        responses.decoder = hpack.Decoder.init(responses.table.table(), responses.decoded.len);
    }

    /// The block `first` opens, with every CONTINUATION after it, decoded.
    fn read(responses: *Responses, first: ?FrameReader.Frame, reader: *FrameReader) !Block {
        try testing.expect(first != null);
        try testing.expectEqual(frame.Type.headers, first.?.header.frame_type);
        const stream = first.?.header.stream_identifier;
        var length: usize = 0;
        var frames: u32 = 1;
        var header = first.?.header;
        var fragment = first.?.payload.headers.fragment;
        // A block can be no longer than `block`, and every frame of one
        // but the last is full, so the frames are few.
        while (frames <= 64) {
            @memcpy(responses.block[length..][0..fragment.len], fragment);
            length += fragment.len;
            if (header.has(.end_headers)) break;
            const next = reader.next().?;
            try testing.expectEqual(frame.Type.continuation, next.header.frame_type);
            try testing.expectEqual(stream, next.header.stream_identifier);
            header = next.header;
            fragment = next.payload.continuation.fragment;
            frames += 1;
        } else return error.TestUnexpectedResult;
        var iterator = responses.decoder.iterate(&responses.decoded, responses.block[0..length]);
        var count: usize = 0;
        while (try iterator.next()) |field| : (count += 1) responses.fields[count] = field;
        return .{
            .stream = stream,
            .end_stream = first.?.header.has(.end_stream),
            .frames = frames,
            .raw = responses.block[0..length],
            .fields = responses.fields[0..count],
        };
    }
};

fn expectFields(expected: []const hpack.Field, actual: []const hpack.Field) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
    }
}

fn expectData(one: ?FrameReader.Frame, stream: u31, length: usize, end_stream: bool) !void {
    try testing.expect(one != null);
    try testing.expectEqual(frame.Type.data, one.?.header.frame_type);
    try testing.expectEqual(stream, one.?.header.stream_identifier);
    try testing.expectEqual(length, one.?.payload.data.data.len);
    try testing.expectEqual(end_stream, one.?.header.has(.end_stream));
}

const Setting = struct { identifier: u16, value: u32 };

fn putSettings(out: *Wire, settings: []const Setting) void {
    var bytes: [6 * 4]u8 = undefined;
    assert(settings.len <= 4);
    for (settings, 0..) |setting, index| {
        std.mem.writeInt(u16, bytes[index * 6 ..][0..2], setting.identifier, .big);
        std.mem.writeInt(u32, bytes[index * 6 + 2 ..][0..4], setting.value, .big);
    }
    put(out, .{ .settings = .{ .entries = bytes[0 .. settings.len * 6] } }, 0, 0);
}

fn putOpeningWith(out: *Wire, settings: []const Setting) void {
    out.appendSlice(testing.allocator, Session.preface) catch unreachable;
    putSettings(out, settings);
}

const setting_header_table_size: u16 = 0x1;
const setting_initial_window_size: u16 = 0x4;
const setting_max_frame_size: u16 = 0x5;

fn countEvents(fixture: *const Fixture, kind: std.meta.Tag(Session.Step), stream: u31) u32 {
    var count: u32 = 0;
    for (fixture.eventsOf()) |event| {
        if (event.kind == kind and event.stream == stream) count += 1;
    }
    return count;
}

test "h2 session: a response goes out as HEADERS then DATA, and the stream is gone once both halves end" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .respond;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var responses: Responses = .{};
    responses.init();
    var reader = fixture.replies();
    const head = try responses.read(reader.nextSkippingAcks(), &reader);
    try testing.expectEqual(@as(u31, 1), head.stream);
    try testing.expect(!head.end_stream);
    try expectFields(&response_head, head.fields);
    const body = reader.nextSkippingAcks();
    try expectData(body, 1, 5, true);
    try testing.expectEqualStrings("hello", body.?.payload.data.data);
    try testing.expect(reader.next() == null);
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
}

test "h2 session: a head-only response carries END_STREAM on its HEADERS" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .respond;
    fixture.body = "";
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var responses: Responses = .{};
    responses.init();
    var reader = fixture.replies();
    const head = try responses.read(reader.nextSkippingAcks(), &reader);
    try testing.expect(head.end_stream);
    try testing.expect(reader.next() == null);
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
}

test "h2 session: an answer before the request body is in leaves the stream half closed until it is" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .respond_early;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&post_fields), false);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(u32, 1), fixture.session.streams.used);
    try testing.expectEqual(StreamTable.Slot.State.half_closed_local, fixture.session.streams.find(1).?.state);
    // The client may still send, and be credited; its END_STREAM closes it.
    var rest: Wire = .empty;
    defer rest.deinit(testing.allocator);
    putData(&rest, 1, "the body after all", true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(rest.items));
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
    const events = fixture.eventsOf();
    try testing.expectEqual(.data, events[events.len - 1].kind);
    try testing.expect(events[events.len - 1].end_stream);
}

test "h2 session: a complete response may stop the request body with RST_STREAM(NO_ERROR)" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .respond_early;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&post_fields), false);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    fixture.session.resetStream(1, .no_error);
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    var reader = fixture.replies();
    var last: ?FrameReader.Frame = null;
    while (reader.next()) |one| last = one;
    try expectReset(last, 1, .no_error);
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
}

test "h2 session: interim heads go before the final one, and 101 is refused" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const session = &fixture.session;
    const early_hints = [_]hpack.Field{
        .{ .name = ":status", .value = "103" },
        .{ .name = "link", .value = "</style.css>; rel=preload" },
    };
    try testing.expectEqual(Session.Sent.staged, session.sendHead(1, &early_hints, false));
    try testing.expectEqual(Session.Sent.refused, session.sendHead(1, &.{.{ .name = ":status", .value = "101" }}, false));
    try testing.expectEqual(Session.Sent.staged, session.sendHead(1, &response_head, true));
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    var responses: Responses = .{};
    responses.init();
    var reader = fixture.replies();
    const interim = try responses.read(reader.nextSkippingAcks(), &reader);
    try testing.expect(!interim.end_stream);
    try expectFields(&early_hints, interim.fields);
    const final = try responses.read(reader.nextSkippingAcks(), &reader);
    try testing.expect(final.end_stream);
    try expectFields(&response_head, final.fields);
    try testing.expect(reader.next() == null);
}

test "h2 session: response fields HTTP/2 cannot carry are refused, and nothing is staged" {
    const heads = [_][]const hpack.Field{
        &.{ .{ .name = ":status", .value = "200" }, .{ .name = "connection", .value = "close" } },
        &.{ .{ .name = ":status", .value = "200" }, .{ .name = "transfer-encoding", .value = "chunked" } },
        &.{ .{ .name = ":status", .value = "200" }, .{ .name = "Content-Type", .value = "text/plain" } },
        &.{ .{ .name = ":status", .value = "200" }, .{ .name = "x-split", .value = "a\r\nb: c" } },
        &.{ .{ .name = ":status", .value = "200" }, .{ .name = ":path", .value = "/" } },
        &.{.{ .name = ":status", .value = "2000" }},
        &.{.{ .name = ":status", .value = "099" }},
        &.{.{ .name = "content-type", .value = "text/plain" }},
    };
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const session = &fixture.session;
    for (heads) |head| {
        try testing.expectEqual(Session.Sent.refused, session.sendHead(1, head, false));
        try testing.expectEqual(@as(usize, 0), session.outbound().len);
    }
    // And trailers may carry no pseudo-header at all (§8.1).
    try testing.expectEqual(Session.Sent.staged, session.sendHead(1, &response_head, false));
    _ = fixture.drainAll();
    try testing.expectEqual(Session.Sent.refused, session.sendTrailers(1, &.{.{ .name = ":status", .value = "200" }}));
    try testing.expectEqual(@as(usize, 0), session.outbound().len);
    try testing.expectEqual(@as(u32, 0), session.send_waiting);
}

test "h2 session: a field section past the client's frame size spans CONTINUATION frames" {
    var fixture: Fixture = .{};
    fixture.initWith(.{ .outbox_len = 64 * 1024 });
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    // Two values, each past one frame on its own: the block is cut at
    // octets, not at fields, and the cut lands inside a value.
    const long: [24_000]u8 = @splat('%');
    const head = [_]hpack.Field{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-first", .value = &long },
        .{ .name = "x-second", .value = &long },
    };
    try testing.expectEqual(Session.Sent.staged, fixture.session.sendHead(1, &head, true));
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    var responses: Responses = .{};
    responses.init();
    var reader = fixture.replies();
    const block = try responses.read(reader.nextSkippingAcks(), &reader);
    try testing.expect(block.frames >= 3);
    try testing.expect(block.end_stream); // On the HEADERS frame, not the last.
    try expectFields(&head, block.fields);
    try testing.expect(reader.next() == null);
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
}

test "h2 session: a block the outbox could never hold is refused; one that does not fit yet waits" {
    var fixture: Fixture = .{};
    fixture.init(); // A 512-octet outbox.
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    putHeaders(&input, 3, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const session = &fixture.session;
    const huge: [1024]u8 = @splat('h');
    try testing.expectEqual(Session.Sent.refused, session.sendHead(1, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-huge", .value = &huge },
    }, true));
    // Two blocks of 250-odd octets — `~` codes longer than a byte, so the
    // value goes out raw — and the second does not fit beside the first
    // until the first is sent.
    const wide: [230]u8 = @splat('~');
    const head = [_]hpack.Field{ .{ .name = ":status", .value = "200" }, .{ .name = "x-wide", .value = &wide } };
    try testing.expectEqual(Session.Sent.staged, session.sendHead(1, &head, true));
    try testing.expectEqual(Session.Sent.blocked, session.sendHead(3, &head, true));
    try testing.expectEqual(@as(u32, 1), session.send_waiting);
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    try testing.expectEqual(@as(u32, 1), countEvents(&fixture, .writable, 3));
    try testing.expectEqual(Session.Sent.staged, session.sendHead(3, &head, true));
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    try testing.expectEqual(@as(u32, 0), session.streams.used);
}

test "h2 session: the stream window paces the body, and the client's credit resumes it" {
    var fixture: Fixture = .{};
    fixture.initWith(.{ .outbox_len = 4096 });
    fixture.caller = .respond;
    const body: [250]u8 = @splat('b');
    fixture.body = &body;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpeningWith(&input, &.{.{ .identifier = setting_initial_window_size, .value = 100 }});
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var more: Wire = .empty;
    defer more.deinit(testing.allocator);
    put(&more, .{ .window_update = .{ .increment = 100 } }, 1, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(more.items));
    more.clearRetainingCapacity();
    put(&more, .{ .window_update = .{ .increment = 1000 } }, 1, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(more.items));
    try testing.expectEqual(@as(u32, 2), countEvents(&fixture, .writable, 1));
    var responses: Responses = .{};
    responses.init();
    var reader = fixture.replies();
    _ = try responses.read(reader.nextSkippingAcks(), &reader);
    try expectData(reader.nextSkippingAcks(), 1, 100, false);
    try expectData(reader.nextSkippingAcks(), 1, 100, false);
    try expectData(reader.nextSkippingAcks(), 1, 50, true);
    try testing.expect(reader.next() == null);
    try testing.expectEqual(@as(u32, 0), fixture.session.streams.used);
}

test "h2 session: the connection window is shared, and the streams waiting on it take turns by frame" {
    var fixture: Fixture = .{};
    fixture.initWith(.{ .outbox_len = 64 * 1024 });
    fixture.caller = .respond;
    const body: [100_000]u8 = @splat('t');
    fixture.body = &body;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    // Stream windows wide open, so the connection's 65535 is the one bound.
    putOpeningWith(&input, &.{.{ .identifier = setting_initial_window_size, .value = 1 << 20 }});
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    putHeaders(&input, 3, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(i64, 0), fixture.session.send_window);
    try testing.expectEqual(@as(u32, 2), fixture.session.send_waiting);
    const before = fixture.sent_len;
    var credit: Wire = .empty;
    defer credit.deinit(testing.allocator);
    put(&credit, .{ .window_update = .{ .increment = 4 * Session.frame_payload_bytes_max } }, 0, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(credit.items));
    // Past the update: four full frames, alternating between the streams.
    var reader: FrameReader = .{ .bytes = fixture.sent[before..fixture.sent_len] };
    var streams: [4]u31 = undefined;
    for (&streams) |*stream| {
        const one = reader.nextSkippingAcks().?;
        try testing.expectEqual(frame.Type.data, one.header.frame_type);
        try testing.expectEqual(@as(usize, Session.frame_payload_bytes_max), one.payload.data.data.len);
        stream.* = one.header.stream_identifier;
    }
    try testing.expect(reader.next() == null);
    try testing.expect(streams[0] != streams[1]);
    try testing.expectEqual(streams[0], streams[2]);
    try testing.expectEqual(streams[1], streams[3]);
}

test "h2 session: a stream stalled on its own window costs the others no turn" {
    var fixture: Fixture = .{};
    fixture.initWith(.{ .outbox_len = 64 * 1024 });
    fixture.caller = .respond;
    const body: [40_000]u8 = @splat('s');
    fixture.body = &body;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    // Both streams spend their 100 octets of window and wait; then only
    // stream 3 is credited, and stream 1 — still at zero — wants nothing
    // stream 3 would take.
    putOpeningWith(&input, &.{.{ .identifier = setting_initial_window_size, .value = 100 }});
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    putHeaders(&input, 3, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(u32, 2), fixture.session.send_waiting);
    var credit: Wire = .empty;
    defer credit.deinit(testing.allocator);
    put(&credit, .{ .window_update = .{ .increment = 40_000 } }, 3, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(credit.items));
    // One turn took the whole rest of the body, in full frames.
    try testing.expectEqual(@as(u32, 1), countEvents(&fixture, .writable, 3));
    try testing.expect(fixture.session.streams.find(3) == null);
    try testing.expectEqual(@as(u32, 1), fixture.session.send_waiting);
}

test "h2 session: a DATA frame is no larger than the client's frame size, which SETTINGS may raise" {
    for ([_]u32{ Session.frame_payload_bytes_max, 32 * 1024 }) |frame_size| {
        var fixture: Fixture = .{};
        fixture.initWith(.{ .outbox_len = 64 * 1024 });
        fixture.caller = .respond;
        const body: [40_000]u8 = @splat('f');
        fixture.body = &body;
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpeningWith(&input, &.{.{ .identifier = setting_max_frame_size, .value = frame_size }});
        putHeaders(&input, 1, blocks.encode(&request_fields), true);
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        var responses: Responses = .{};
        responses.init();
        var reader = fixture.replies();
        _ = try responses.read(reader.nextSkippingAcks(), &reader);
        var sent: usize = 0;
        while (reader.nextSkippingAcks()) |one| {
            try testing.expectEqual(frame.Type.data, one.header.frame_type);
            const length = one.payload.data.data.len;
            try testing.expectEqual(@min(frame_size, body.len - sent), length);
            sent += length;
        }
        try testing.expectEqual(body.len, sent);
    }
}

test "h2 session: SETTINGS can take a stream's window below zero, and it sends again only once credit lifts it" {
    var fixture: Fixture = .{};
    fixture.initWith(.{ .outbox_len = 4096 });
    fixture.caller = .respond;
    const body: [1000]u8 = @splat('n');
    fixture.body = &body;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpeningWith(&input, &.{.{ .identifier = setting_initial_window_size, .value = 100 }});
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    // §6.9.2: 100 sent against 100, then the setting drops by 50 — so the
    // window is -50, and 30 of credit still leaves it at -20.
    putSettings(&input, &.{.{ .identifier = setting_initial_window_size, .value = 50 }});
    put(&input, .{ .window_update = .{ .increment = 30 } }, 1, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(i64, -20), fixture.session.streams.find(1).?.send_window);
    try testing.expectEqual(@as(u32, 0), countEvents(&fixture, .writable, 1));
    var credit: Wire = .empty;
    defer credit.deinit(testing.allocator);
    put(&credit, .{ .window_update = .{ .increment = 40 } }, 1, 0);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(credit.items));
    try testing.expectEqual(@as(u32, 1), countEvents(&fixture, .writable, 1));
    var responses: Responses = .{};
    responses.init();
    var reader = fixture.replies();
    _ = try responses.read(reader.nextSkippingAcks(), &reader);
    try expectData(reader.nextSkippingAcks(), 1, 100, false);
    try expectData(reader.nextSkippingAcks(), 1, 20, false);
    try testing.expect(reader.next() == null);
}

test "h2 session: the dynamic table carries from one response to the next" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .respond;
    fixture.body = "";
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    putHeaders(&input, 3, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    var responses: Responses = .{};
    responses.init();
    var reader = fixture.replies();
    const first = try responses.read(reader.nextSkippingAcks(), &reader);
    const first_length = first.raw.len;
    const second = try responses.read(reader.nextSkippingAcks(), &reader);
    try expectFields(&response_head, second.fields);
    // Every field of the second is an index into what the first inserted.
    try testing.expect(second.raw.len < first_length);
    try testing.expectEqual(response_head.len, second.raw.len);
}

test "h2 session: the client's HEADER_TABLE_SIZE is signalled at the start of the next block" {
    const Case = struct { settings: []const Setting, lead: []const u8 };
    const cases = [_]Case{
        // Down to zero: one update, and the block indexes nothing after.
        .{ .settings = &.{.{ .identifier = setting_header_table_size, .value = 0 }}, .lead = "\x20" },
        // Down and back up between blocks: the lowest, then the last.
        .{ .settings = &.{
            .{ .identifier = setting_header_table_size, .value = 0 },
            .{ .identifier = setting_header_table_size, .value = 4096 },
        }, .lead = "\x20\x3f\xe1\x1f" },
        // Past the encoder's arena: it stays where it is, and says nothing.
        .{ .settings = &.{.{ .identifier = setting_header_table_size, .value = 65536 }}, .lead = "" },
    };
    for (cases) |case| {
        var fixture: Fixture = .{};
        fixture.init();
        fixture.caller = .respond;
        fixture.body = "";
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpeningWith(&input, case.settings);
        putHeaders(&input, 1, blocks.encode(&request_fields), true);
        putHeaders(&input, 3, blocks.encode(&request_fields), true);
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        var responses: Responses = .{};
        responses.init();
        var reader = fixture.replies();
        const first = try responses.read(reader.nextSkippingAcks(), &reader);
        try testing.expect(std.mem.startsWith(u8, first.raw, case.lead));
        try testing.expect(first.raw.len >= case.lead.len + 1);
        // A lead octet that is not itself an update: one per block, owed once.
        try testing.expect(first.raw[case.lead.len] & 0xe0 != 0x20);
        try expectFields(&response_head, first.fields);
        const second = try responses.read(reader.nextSkippingAcks(), &reader);
        try testing.expect(second.raw[0] & 0xe0 != 0x20);
        try expectFields(&response_head, second.fields);
    }
}

test "h2 session: trailers end the stream after its body" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const session = &fixture.session;
    const trailers = [_]hpack.Field{.{ .name = "grpc-status", .value = "0" }};
    try testing.expectEqual(Session.Sent.staged, session.sendHead(1, &response_head, false));
    const sent = session.sendData(1, "body", false);
    try testing.expectEqual(@as(u32, 4), sent.taken);
    try testing.expect(!sent.ended);
    try testing.expectEqual(Session.Sent.staged, session.sendTrailers(1, &trailers));
    try testing.expectEqual(@as(u32, 0), session.streams.used);
    try testing.expectEqual(Session.Step.need_input, fixture.settle());
    var responses: Responses = .{};
    responses.init();
    var reader = fixture.replies();
    _ = try responses.read(reader.nextSkippingAcks(), &reader);
    try expectData(reader.nextSkippingAcks(), 1, 4, false);
    const tail = try responses.read(reader.nextSkippingAcks(), &reader);
    try testing.expect(tail.end_stream);
    try expectFields(&trailers, tail.fields);
}

test "h2 session: a send leaves the reserve free, so the next reply never waits behind a body" {
    var fixture: Fixture = .{};
    fixture.initWith(.{ .outbox_len = 4096 });
    fixture.caller = .hold;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    const session = &fixture.session;
    try testing.expectEqual(Session.Sent.staged, session.sendHead(1, &response_head, false));
    const body: [8000]u8 = @splat('r');
    const sent = session.sendData(1, &body, true);
    try testing.expect(sent.taken < body.len);
    try testing.expect(!sent.ended);
    try testing.expectEqual(@as(usize, Session.send_reserve), session.outbox.len - session.outbox_len);
    // A PING in now is answered without a flush first: its PONG is staged
    // in the reserve, and only then is a flush asked for the next frame.
    var ping: Wire = .empty;
    defer ping.deinit(testing.allocator);
    put(&ping, .{ .ping = .{ .opaque_data = &@splat(9) } }, 0, 0);
    fixture.receive(ping.items);
    try testing.expectEqual(Session.Step.flush_first, session.step());
    const staged = session.outbound();
    var reader: FrameReader = .{ .bytes = staged[staged.len - Session.reply_bytes_max ..] };
    const pong = reader.next().?;
    try testing.expectEqual(frame.Type.ping, pong.header.frame_type);
    try testing.expect(pong.header.has(.ack));
}

// ---------------------------------------------------------------------------
// The budgets (#276)
// ---------------------------------------------------------------------------

/// The `index`th frame of a kind `Unpaid` counts, on stream 1 where it
/// needs one. Every other one is the kind's other shape: the ACK this side
/// never asked for, or a type it never heard of.
fn putUnpaid(out: *Wire, comptime kind: Session.Calm, index: usize) void {
    const ack: u8 = if (index % 2 == 1) frame.Flag.ack.bit() else 0;
    switch (kind) {
        .ping => put(out, .{ .ping = .{ .opaque_data = &@splat(7) } }, 0, ack),
        .settings => put(out, .{ .settings = .{ .entries = &.{} } }, 0, ack),
        .window_update => put(out, .{ .window_update = .{ .increment = 1 } }, 0, 0),
        .ignored => if (ack != 0) {
            putRaw(out, 0xfa, 0, 1, "an extension");
        } else {
            put(out, .{ .priority = .{ .exclusive = false, .stream_dependency = 0, .weight_octet = 15 } }, 1, 0);
        },
        .empty_data => putData(out, 1, "", false),
        else => comptime unreachable,
    }
}

/// A connection with stream 1 open at both ends — a POST the caller holds
/// — and the request that opened it the last work done.
fn openHeld(fixture: *Fixture, blocks: *Blocks) !void {
    fixture.init();
    fixture.caller = .hold;
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    putHeaders(&input, 1, blocks.encode(&post_fields), false);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(usize, 1), fixture.eventsOf().len);
}

test "h2 session: each frame that asks nothing has a budget — at it the connection serves, past it it ends calm" {
    inline for (.{ .ping, .settings, .window_update, .ignored, .empty_data }) |kind| {
        var fixture: Fixture = .{};
        var blocks: Blocks = .{};
        try openHeld(&fixture, &blocks);
        const bound = @field(Session.Unpaid.max, @tagName(kind));
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        for (0..bound) |index| putUnpaid(&input, kind, index);
        try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
        try testing.expectEqual(@as(?frame.ErrorCode, null), fixture.session.closed_with);
        var over: Wire = .empty;
        defer over.deinit(testing.allocator);
        putUnpaid(&over, kind, bound);
        try testing.expectEqual(Session.Step.closed, fixture.feed(over.items));
        try expectGoaway(&fixture, .enhance_your_calm);
        try testing.expectEqual(@as(?Session.Calm, kind), fixture.session.calm);
    }
}

test "h2 session: work done for the client starts every budget over — a request, or a response frame" {
    var fixture: Fixture = .{};
    var blocks: Blocks = .{};
    try openHeld(&fixture, &blocks);
    const bound = Session.Unpaid.max.ping;
    var pings: Wire = .empty;
    defer pings.deinit(testing.allocator);
    for (0..bound) |index| putUnpaid(&pings, .ping, index);
    // A response head staged, then a DATA frame, then a new request: each
    // is work, and after each the client may PING its whole budget again.
    try testing.expectEqual(Session.Step.need_input, fixture.feed(pings.items));
    try testing.expectEqual(Session.Sent.staged, fixture.session.sendHead(1, &response_head, false));
    try testing.expectEqual(Session.Step.need_input, fixture.feed(pings.items));
    try testing.expect(fixture.session.sendData(1, "partial", false).taken == 7);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(pings.items));
    var request: Wire = .empty;
    defer request.deinit(testing.allocator);
    putHeaders(&request, 3, blocks.encode(&request_fields), true);
    request.appendSlice(testing.allocator, pings.items) catch unreachable;
    try testing.expectEqual(Session.Step.need_input, fixture.feed(request.items));
    try testing.expectEqual(@as(?frame.ErrorCode, null), fixture.session.closed_with);
    // A frame with END_STREAM and no octets ends the client's half: not
    // the empty flood, which is one that ends nothing.
    var ended: Wire = .empty;
    defer ended.deinit(testing.allocator);
    putData(&ended, 1, "", true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(ended.items));
    try testing.expectEqual(@as(u32, 0), fixture.session.unpaid.empty_data);
}

test "h2 session: Rapid Reset — resets before the answer outrunning answers ended is the connection's end" {
    // Each GET is reset before the caller answers it; the bound's worth is
    // a browser abandoning everything it had open, one more is a loop.
    var fixture: Fixture = .{};
    fixture.init();
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    var stream: u31 = 1;
    for (0..Session.resets_unpaid_max) |_| {
        putHeaders(&input, stream, blocks.encode(&request_fields), true);
        put(&input, .{ .rst_stream = .{ .error_code = .cancel } }, stream, 0);
        stream += 2;
    }
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(Session.resets_unpaid_max, fixture.session.resets_unpaid);
    // An answer that ends pays one back, so one more reset is room again.
    var answered: Wire = .empty;
    defer answered.deinit(testing.allocator);
    putHeaders(&answered, stream, blocks.encode(&request_fields), true);
    try testing.expectEqual(Session.Step.need_input, fixture.feed(answered.items));
    try testing.expectEqual(Session.Sent.staged, fixture.session.sendHead(stream, &response_head, true));
    try testing.expectEqual(Session.resets_unpaid_max - 1, fixture.session.resets_unpaid);
    stream += 2;
    var again: Wire = .empty;
    defer again.deinit(testing.allocator);
    for (0..2) |_| {
        putHeaders(&again, stream, blocks.encode(&request_fields), true);
        put(&again, .{ .rst_stream = .{ .error_code = .cancel } }, stream, 0);
        stream += 2;
    }
    try testing.expectEqual(Session.Step.closed, fixture.feed(again.items));
    try expectGoaway(&fixture, .enhance_your_calm);
    try testing.expectEqual(@as(?Session.Calm, .rapid_reset), fixture.session.calm);
}

test "h2 session: the reset that overruns the debt is still the verdict when it closes the client's last stream after its GOAWAY" {
    // The client went away; its last stream's reset would end the
    // connection cleanly — but it is also the reset one past the budget.
    var fixture: Fixture = .{};
    fixture.init();
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    var stream: u31 = 1;
    for (0..Session.resets_unpaid_max) |_| {
        putHeaders(&input, stream, blocks.encode(&request_fields), true);
        put(&input, .{ .rst_stream = .{ .error_code = .cancel } }, stream, 0);
        stream += 2;
    }
    putHeaders(&input, stream, blocks.encode(&request_fields), true);
    put(&input, .{ .goaway = .{ .last_stream_identifier = 0, .error_code = .no_error, .debug_data = &.{} } }, 0, 0);
    put(&input, .{ .rst_stream = .{ .error_code = .cancel } }, stream, 0);
    try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
    try expectGoaway(&fixture, .enhance_your_calm);
    try testing.expectEqual(@as(?Session.Calm, .rapid_reset), fixture.session.calm);
}

test "h2 session: a reset after the answer ended costs nothing — the client stopping a body it need not send" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.caller = .respond_early;
    var blocks: Blocks = .{};
    blocks.init();
    var input: Wire = .empty;
    defer input.deinit(testing.allocator);
    putOpening(&input);
    var stream: u31 = 1;
    for (0..Session.resets_unpaid_max + 1) |_| {
        putHeaders(&input, stream, blocks.encode(&post_fields), false);
        put(&input, .{ .rst_stream = .{ .error_code = .no_error } }, stream, 0);
        stream += 2;
    }
    try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
    try testing.expectEqual(@as(u32, 0), fixture.session.resets_unpaid);
    try testing.expectEqual(@as(?frame.ErrorCode, null), fixture.session.closed_with);
}

test "h2 session: the field block's bounds end the connection calm, each under its own cause" {
    // The CONTINUATION flood: empty fragments, one past the frame bound.
    {
        var fixture: Fixture = .{};
        fixture.init();
        var blocks: Blocks = .{};
        blocks.init();
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        put(&input, .{ .headers = .{ .priority = null, .fragment = blocks.encode(&request_fields), .padding = null } }, 1, 0);
        for (0..frame.BlockAssembler.frames_max_default) |_| {
            put(&input, .{ .continuation = .{ .fragment = &.{} } }, 1, 0);
        }
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .enhance_your_calm);
        try testing.expectEqual(@as(?Session.Calm, .continuation), fixture.session.calm);
    }
    // A list past what this side advertised: the HPACK bomb's shape.
    {
        var fixture: Fixture = .{};
        fixture.init();
        var blocks: Blocks = .{};
        blocks.init();
        const large: [header_list_size]u8 = @splat('v');
        const fields = request_fields ++ [_]hpack.Field{.{ .name = "x-large", .value = &large }};
        var encoded: [header_list_size + 256]u8 = undefined;
        const block = blocks.encoder.encode(&encoded, &fields);
        assert(block.fields == fields.len);
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        putOpening(&input);
        put(&input, .{ .headers = .{ .priority = null, .fragment = encoded[0..block.written], .padding = null } }, 1, frame.Flag.end_headers.bit());
        try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
        try expectGoaway(&fixture, .enhance_your_calm);
        try testing.expectEqual(@as(?Session.Calm, .field_block), fixture.session.calm);
    }
}

test "h2 session: a SETTINGS frame moves the windows once, to its last value, and overflows at its highest" {
    // Stream 1's window is ten past the default, so 2^31-1 anywhere in a
    // frame takes it over — even with a lower value after it.
    for ([_]bool{ false, true }) |overflow| {
        var fixture: Fixture = .{};
        var blocks: Blocks = .{};
        try openHeld(&fixture, &blocks);
        var input: Wire = .empty;
        defer input.deinit(testing.allocator);
        put(&input, .{ .window_update = .{ .increment = 10 } }, 1, 0);
        const highest: u32 = if (overflow) std.math.maxInt(u31) else 100_000;
        putSettings(&input, &.{
            .{ .identifier = setting_initial_window_size, .value = 500 },
            .{ .identifier = setting_initial_window_size, .value = highest },
            .{ .identifier = setting_initial_window_size, .value = 1000 },
        });
        if (overflow) {
            try testing.expectEqual(Session.Step.closed, fixture.feed(input.items));
            try expectGoaway(&fixture, .flow_control_error);
        } else {
            try testing.expectEqual(Session.Step.need_input, fixture.feed(input.items));
            // 65,545 moved by 1000 - 65,535: the last value, applied once.
            try testing.expectEqual(@as(i64, 1010), fixture.session.streams.find(1).?.send_window);
            try testing.expectEqual(@as(u31, 1000), fixture.session.peer_initial_window_size);
        }
    }
}

// ---------------------------------------------------------------------------
// Fuzzing
// ---------------------------------------------------------------------------

const empty_settings = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// GET https://a/ on streams 1 and 3, ending the stream: `:method GET`,
/// `:scheme https` and `:path /` from the static table, and `:authority a`
/// as a literal on its static name.
const headers_get_1 = "\x00\x00\x06\x01\x05\x00\x00\x00\x01\x82\x87\x84\x01\x01a";
const headers_get_3 = "\x00\x00\x06\x01\x05\x00\x00\x00\x03\x82\x87\x84\x01\x01a";

test "fuzz: h2 session — any octets, any split: answered or closed, never a third outcome" {
    // Corpus entries lead with the harness's control octet (see
    // `fuzzSession`): `0x07` supplies the opening, reads 8 at a time and
    // answers each request, `0x80` makes the entry carry its own opening,
    // `0x27` resets every stream on open, `0x17` answers at the head, and
    // `0x4c` answers through a 128-octet outbox and a short socket. Each is
    // `seed`-encoded, so it reaches the target as written.
    try testing.fuzz({}, fuzzSession, .{
        .corpus = &.{
            seed("\x80" ++ Session.preface ++ empty_settings),
            seed("\x07" ++ "\x00\x00\x08\x06\x00\x00\x00\x00\x00" ++ "pingping"),
            seed("\x07" ++ headers_get_1 ++ "\x00\x00\x03\x00\x01\x00\x00\x00\x01abc"),
            seed("\x27" ++ headers_get_1),
            seed("\x07" ++ "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x01"),
            // Two requests, then credit on the connection and on stream 1.
            seed("\x17" ++ headers_get_1 ++ headers_get_3 ++
                "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x01\x00\x00" ++
                "\x00\x00\x04\x08\x00\x00\x00\x00\x01\x00\x01\x00\x00"),
            seed("\x4c" ++ headers_get_1 ++ headers_get_3),
            // What found the harness assuming a head can never be refused:
            // a request answered through an outbox no head fits. Already in
            // `Smith`'s encoding, as the fuzzer saved it.
            "\x26\x00\x00\x00\x5d\x00\x00\x03\x01\x04\x00\x00\x00\x01\x82\x87" ++
                "\x84\x00\x00\x00\x98\x01\x82\x87\x84\x41\x00\x15\x5f\x07\xc6\xc0" ++
                "\x8d\x8a\x5e\x4d\x53\x94\xc4\x7f\x7c\x9c",
        },
    });
}

/// The fuzz target's fixture: past a megabyte, so it lives here rather than
/// on the stack, and is re-initialized per input rather than rebuilt. The
/// client's decoder beside it reads back every response block.
var fuzz_fixture: Fixture = .{};
var fuzz_responses: Responses = .{};

/// A response body past one frame and short of a window, so the fuzzer
/// reaches both frame splitting and window waits.
const fuzz_body: [20_000]u8 = @splat('z');

fn fuzzSession(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input: [4096]u8 = undefined;
    const input_len = smith.slice(&input);
    assert(input_len <= input.len);
    // The first octet is the harness's, not the session's. Its low nibble
    // draws the read size, so one corpus entry reaches every chunking; the
    // next two bits the caller; bit six the smallest outbox and a short
    // socket, which is the only way `flush_first` — and the reserves
    // `stage` relies on — is ever under the fuzzer; bit seven makes the
    // input carry its own opening, which a raw mutation almost always
    // breaks.
    const control: u8 = if (input_len >= 1) input[0] else 0;
    const fixture = &fuzz_fixture;
    fixture.caller = switch ((control >> 4) & 0x3) {
        0 => .respond,
        1 => .respond_early,
        2 => .reset_on_open,
        else => .consume,
    };
    fixture.drain_max = std.math.maxInt(u32);
    fixture.body = &fuzz_body;
    if (control & 0x40 != 0) {
        // The smallest outbox the session takes, which no response head
        // fits — so heads are refused and the streams reset — or one a head
        // just fits, so the small frames are bodies.
        const outbox_len: u32 = if (control & 0x01 != 0) Session.outbox_bytes_min else 128;
        fixture.initWith(.{ .outbox_len = outbox_len });
        fixture.drain_max = 1 + @as(u32, (control >> 2) % 8);
        // Frames of a few octets each: a short body keeps a run short.
        fixture.body = fuzz_body[0..64];
    } else {
        fixture.initWith(.{ .outbox_len = 32 * 1024 });
    }
    const chunk: u32 = 1 + @as(u32, control % 16);
    const body = input[@min(input_len, 1)..input_len];
    var verdict: Session.Step = .need_input;
    if (control & 0x80 == 0) {
        verdict = fixture.feedChunked(Session.preface ++ empty_settings, chunk);
        assert(verdict == .need_input);
    }
    if (verdict != .closed) verdict = fixture.feedChunked(body, chunk);
    assert(verdict == .need_input or verdict == .closed);
    fuzz_responses.init();
    checkTranscript(fixture, &fuzz_responses);
    const session = &fixture.session;
    if (verdict == .closed) {
        assert(session.step() == .closed);
        if (session.closed_with) |code| assert(code != .no_error);
        return;
    }
    checkSettled(session);
}

/// What `need_input` promises once the input is spent: the windows add up,
/// nothing is owed, and no stream left waiting could go on.
fn checkSettled(session: *Session) void {
    assert(session.recv_window + session.recv_unacked + session.recv_delivered == Session.window_default);
    assert(session.send_window >= 0);
    assert(session.outbound().len == 0);
    // `need_input` is never said while this side still owes a frame: the
    // client may be waiting on it before it sends anything more.
    assert(!session.pending);
    const room = session.outbox.len - session.outbox_len - Session.send_reserve;
    var waiting: u32 = 0;
    for (session.streams.slots) |slot| {
        if (slot.id == 0) continue;
        assert(slot.recv_window + slot.recv_unacked + slot.recv_delivered == Session.window_default);
        // Nor while a waiting stream could make progress: the scheduler
        // names every one that can before it says it wants input.
        switch (slot.send_wait) {
            .none => continue,
            .room => assert(room < slot.send_room_needed),
            .data => assert(room <= frame.Header.octets or slot.send_window <= 0 or session.send_window <= 0),
        }
        waiting += 1;
    }
    assert(waiting == session.send_waiting);
}

/// Whatever the input did, every stream's outbound frames are a legal
/// sequence (§5.1, §6.2, §6.10, §8.1): a field block is whole frames with
/// nothing between them, and decodes — against a table that saw every
/// block before it, so whatever table sizes the client set, the two tables
/// stayed in step — to the head that was sent; a body follows a head,
/// nothing but a reset or a credit follows END_STREAM, and a body is the
/// response's, whole if ended.
fn checkTranscript(fixture: *const Fixture, responses: *Responses) void {
    const bytes = fixture.sent[0..fixture.sent_len];
    var block_len: usize = 0;
    var seen: [64]Seen = undefined;
    var seen_len: u32 = 0;
    var block_open: ?u31 = null;
    var offset: usize = 0;
    var frames: u32 = 0;
    while (offset + frame.Header.octets <= bytes.len) : (frames += 1) {
        assert(frames <= bytes.len);
        const header = frame.Header.parse(bytes[offset..]) catch unreachable;
        const end = offset + frame.Header.octets + header.length;
        // Only a capture cut short ends in a partial frame.
        if (end > bytes.len) break;
        const payload = frame.payload.parse(header, bytes[offset + frame.Header.octets .. end]) catch unreachable;
        offset = end;
        const fragment: []const u8 = switch (payload) {
            .headers => |headers| headers.fragment,
            .continuation => |continuation| continuation.fragment,
            else => &.{},
        };
        if (header.frame_type == .headers) block_len = 0;
        @memcpy(responses.block[block_len..][0..fragment.len], fragment);
        block_len += fragment.len;
        const block_ended = switch (header.frame_type) {
            .headers, .continuation => header.has(.end_headers),
            else => false,
        };
        if (block_ended) checkBlock(responses, responses.block[0..block_len]);
        if (block_open) |stream| {
            assert(header.frame_type == .continuation);
            assert(header.stream_identifier == stream);
        }
        switch (header.frame_type) {
            .headers, .continuation, .data => {},
            else => continue,
        }
        if (header.frame_type == .continuation) {
            assert(block_open != null);
            if (header.has(.end_headers)) block_open = null;
            continue;
        }
        if (header.frame_type == .headers and !header.has(.end_headers)) block_open = header.stream_identifier;
        const stream = seenOf(&seen, &seen_len, header.stream_identifier) orelse continue;
        assert(!stream.ended);
        if (header.frame_type == .data) {
            assert(stream.head);
            stream.data += header.length;
            assert(stream.data <= fixture.body.len);
        }
        stream.head = true;
        if (header.has(.end_stream)) {
            stream.ended = true;
            if (header.frame_type == .data) assert(stream.data == fixture.body.len);
        }
    }
    assert(fixture.sent_dropped >= 1 or offset == bytes.len);
    assert(frames >= 1); // The server's SETTINGS, at least.
}

/// One whole response block: it decodes, and to the head the fuzz caller
/// sends — the only block it sends.
fn checkBlock(responses: *Responses, block: []const u8) void {
    var iterator = responses.decoder.iterate(&responses.decoded, block);
    var count: usize = 0;
    while (iterator.next() catch unreachable) |field| : (count += 1) {
        assert(count < response_head.len);
        assert(std.mem.eql(u8, field.name, response_head[count].name));
        assert(std.mem.eql(u8, field.value, response_head[count].value));
    }
    assert(count == response_head.len);
}

const Seen = struct { id: u31, head: bool, ended: bool, data: u64 };

/// A stream's record, made at its first frame — or null once the record is
/// full, which only stops the check for streams past the first 64.
fn seenOf(seen: *[64]Seen, seen_len: *u32, id: u31) ?*Seen {
    for (seen[0..seen_len.*]) |*one| {
        if (one.id == id) return one;
    }
    if (seen_len.* == seen.len) return null;
    seen[seen_len.*] = .{ .id = id, .head = false, .ended = false, .data = 0 };
    seen_len.* += 1;
    return &seen[seen_len.* - 1];
}

test "h2 session: a layout prices what `Buffers` asks for, at the default head size" {
    const layout: Session.Layout = .{ .header_list_size_max = 8192, .concurrent_streams_max = Session.concurrent_streams_advertised_max };
    // Every buffer a session needs is at least what `init` asserts of it.
    try testing.expect(layout.inboundBytes() >= Session.frame_bytes_max);
    try testing.expect(layout.outboxBytes() >= Session.outbox_bytes_min);
    try testing.expect(layout.decodedBytes() >= layout.header_list_size_max);
    try testing.expectEqual(Session.fieldsFor(8192), layout.fieldsCount());
    // And a block a head of that size encodes to fits beside a DATA frame.
    try testing.expect(layout.outboxBytes() >= 8192 + Session.frame_bytes_max + Session.send_reserve);
    // The figure the banner prints, held to its order of magnitude: about
    // a hundred KiB a connection at defaults, which is why it is a pool.
    const bytes = layout.bytes();
    try testing.expect(bytes >= 64 * 1024);
    try testing.expect(bytes <= 160 * 1024);
}

test "h2 session: a slab of units carves into sessions that each init and serve" {
    const layout: Session.Layout = .{ .header_list_size_max = 4096, .concurrent_streams_max = 4 };
    const unit_bytes: usize = @intCast(layout.bytes());
    const units = 3;
    const slab = try testing.allocator.alignedAlloc(u8, .fromByteUnits(Session.Layout.unit_align), units * unit_bytes);
    defer testing.allocator.free(slab);
    for (0..units) |index| {
        const unit: []align(Session.Layout.unit_align) u8 = @alignCast(slab[index * unit_bytes ..][0..unit_bytes]);
        const carved = layout.carve(unit);
        // Every piece where its type can live, in every unit, not only
        // the first — the stride is what a byte-aligned slab got wrong.
        try testing.expect(std.mem.isAligned(@intFromPtr(carved.session), @alignOf(Session)));
        try testing.expect(std.mem.isAligned(@intFromPtr(carved.buffers.table), @alignOf(Session.TableStorage)));
        try testing.expect(std.mem.isAligned(@intFromPtr(carved.buffers.fields.ptr), @alignOf(hpack.Field)));
        carved.session.init(.{
            .concurrent_streams_max = layout.concurrent_streams_max,
            .header_list_size_max = layout.header_list_size_max,
        }, &carved.buffers);
        // A carved session is a working one: its SETTINGS are staged.
        try testing.expect(carved.session.outbound().len >= frame.Header.octets);
    }
}
