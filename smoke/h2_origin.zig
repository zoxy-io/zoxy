//! The live gate's HTTP/2 origin (§7): an h2c server, by prior knowledge,
//! behind the cluster the harness marks `"protocol": "h2c"` — so the
//! shipped binary's origin leg, its connection pool and the zero-delay
//! deliveries its exchanges complete through run on a real kernel, under
//! libxev, rather than only under the simulator.
//!
//! It answers every stream the way a gRPC server ends a call: a head, a
//! body, and a trailer section carrying `grpc-status` — so the leg judges
//! that trailers cross the proxy, which is the half of gRPC an HTTP/1.1
//! origin cannot exercise. Each request's head is read through the `h2`
//! package's decoder, keeping the HPACK table in step; nothing else of it
//! is needed. Request bodies are not expected, and none is read.
//!
//! The task model is `origin.zig`'s: a fixed pool blocked in `accept`,
//! woken by a connection each to stop.

const std = @import("std");
const h2 = @import("h2");

const Io = std.Io;
const frame = h2.frame;
const hpack = h2.hpack;
const assert = std.debug.assert;

/// Connections the harness can hold open against this origin at once:
/// the proxy shares one per endpoint, and may open a second while the
/// first is still dialing.
pub const serve_tasks: u8 = 4;

pub const body = "zoxy-smoke-h2-origin\n";
pub const tag_header = "x-origin-tag";
/// The HTTP/1.1 origin's own value: the access-log verdict (#140) holds
/// every origin-served line to one spelling, whichever origin served it.
pub const tag_value = "smoke-origin";
pub const trailer_name = "grpc-status";
pub const trailer_value = "0";

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const table_size: u32 = 4096;
const frame_payload_bytes_max: usize = 16 * 1024;
const frame_bytes_max: usize = frame.Header.octets + frame_payload_bytes_max;

pub const H2Origin = struct {
    io: Io,
    listener: Io.net.Server,
    port: u16,
    group: Io.Group,
    stopping: std.atomic.Value(bool),
    /// Streams answered, and connections accepted, for the leg's verdict.
    answered: std.atomic.Value(u32),
    accepted: std.atomic.Value(u32),
    /// Connections that ended on something other than the proxy closing
    /// them: a frame this origin could not read is the proxy's defect, and
    /// the leg fails on it rather than on the stall it would cause.
    protocol_errors: std.atomic.Value(u32),
    started: bool,

    pub fn start(origin: *H2Origin, io: Io) !void {
        origin.io = io;
        origin.group = .init;
        origin.stopping = .init(false);
        origin.answered = .init(0);
        origin.accepted = .init(0);
        origin.protocol_errors = .init(0);
        origin.started = false;
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        origin.listener = try address.listen(io, .{ .mode = .stream });
        origin.port = origin.listener.socket.address.getPort();
        assert(origin.port != 0);
        var index: u8 = 0;
        while (index < serve_tasks) : (index += 1) {
            try origin.group.concurrent(io, serveTask, .{origin});
        }
        origin.started = true;
    }

    /// Sound once the proxy is gone, as `Origin.stop` is.
    pub fn stop(origin: *H2Origin) void {
        assert(origin.started);
        origin.stopping.store(true, .release);
        var index: u8 = 0;
        while (index < serve_tasks) : (index += 1) {
            var address: Io.net.IpAddress = .{ .ip4 = .loopback(origin.port) };
            const stream = address.connect(origin.io, .{ .mode = .stream }) catch {
                std.debug.print("smoke: h2 origin wake {d} never connected\n", .{index});
                continue;
            };
            stream.close(origin.io);
        }
        origin.group.await(origin.io) catch {};
        origin.listener.deinit(origin.io);
        origin.started = false;
    }
};

/// One task: accept, serve the connection to its end, accept again, until
/// `stop`'s wake.
fn serveTask(origin: *H2Origin) void {
    while (true) {
        const stream = origin.listener.accept(origin.io) catch return;
        if (origin.stopping.load(.acquire)) {
            stream.close(origin.io);
            return;
        }
        _ = origin.accepted.fetchAdd(1, .monotonic);
        var connection: Connection = undefined;
        // The proxy closing the connection at its drain ends the read; any
        // other end is a frame or a preface this origin refused.
        connection.serve(origin, stream) catch |err| switch (err) {
            error.EndOfStream, error.ReadFailed, error.WriteFailed => {},
            else => {
                std.debug.print("smoke: h2 origin connection ended on {t}\n", .{err});
                _ = origin.protocol_errors.fetchAdd(1, .monotonic);
            },
        };
        stream.close(origin.io);
    }
}

const Connection = struct {
    origin: *H2Origin,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    read_buffer: [frame_bytes_max]u8,
    write_buffer: [4096]u8,
    table: hpack.DynamicTable.Storage(table_size),
    decoder: hpack.Decoder,
    decoded: [8192]u8,
    encoder_storage: hpack.Encoder.Storage(table_size),
    encoder: hpack.Encoder,
    staged: [frame_bytes_max]u8,

    /// The preface, our SETTINGS, then frames until the peer goes.
    fn serve(connection: *Connection, origin: *H2Origin, stream: Io.net.Stream) !void {
        connection.origin = origin;
        connection.reader = stream.reader(origin.io, &connection.read_buffer);
        connection.writer = stream.writer(origin.io, &connection.write_buffer);
        connection.table = .{};
        connection.decoder = hpack.Decoder.init(connection.table.table(), connection.decoded.len);
        connection.encoder_storage = .{};
        connection.encoder = connection.encoder_storage.encoder(.dynamic);
        const opening = try connection.reader.interface.takeArray(preface.len);
        if (!std.mem.eql(u8, opening, preface)) return error.NotHttp2;
        try connection.put(.{ .settings = .{ .entries = &.{} } }, 0, 0);
        try connection.writer.interface.flush();
        // Bounded by the peer: each pass reads a frame, and the proxy closes
        // the connection at its drain, which ends the read.
        while (true) {
            const keep = try connection.handleFrame();
            try connection.writer.interface.flush();
            if (!keep) return;
        }
    }

    /// One frame read and answered. False once the peer has said GOAWAY.
    fn handleFrame(connection: *Connection) !bool {
        const header_bytes = try connection.reader.interface.takeArray(frame.Header.octets);
        const header = try frame.Header.parse(header_bytes);
        if (header.length > frame_payload_bytes_max) return error.FrameTooLarge;
        const payload_bytes = try connection.reader.interface.take(header.length);
        assert(payload_bytes.len == header.length);
        const payload = try frame.payload.parse(header, payload_bytes);
        switch (payload) {
            .settings => if (!header.has(.ack)) {
                try connection.put(.{ .settings = .{ .entries = &.{} } }, 0, frame.Flag.ack.bit());
            },
            .ping => |ping| if (!header.has(.ack)) {
                try connection.put(.{ .ping = .{ .opaque_data = ping.opaque_data } }, 0, frame.Flag.ack.bit());
            },
            .headers => |headers| {
                // Whole in one frame: the proxy's heads here are small.
                if (!header.has(.end_headers)) return error.ContinuationUnexpected;
                var iterator = connection.decoder.iterate(&connection.decoded, headers.fragment);
                var fields: u32 = 0;
                while (try iterator.next()) |_| : (fields += 1) assert(fields < 256);
                if (header.has(.end_stream)) try connection.answer(header.stream_identifier);
            },
            .data => if (header.has(.end_stream)) try connection.answer(header.stream_identifier),
            .goaway => return false,
            else => {},
        }
        return true;
    }

    /// The gRPC-shaped answer: head, body, trailers ending the stream.
    fn answer(connection: *Connection, stream_identifier: u31) !void {
        assert(stream_identifier % 2 == 1);
        const stream = stream_identifier;
        try connection.putFields(stream, &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "application/grpc" },
            .{ .name = tag_header, .value = tag_value },
        }, false);
        try connection.put(.{ .data = .{ .data = body, .padding = null } }, stream, 0);
        try connection.putFields(stream, &.{.{ .name = trailer_name, .value = trailer_value }}, true);
        _ = connection.origin.answered.fetchAdd(1, .monotonic);
    }

    fn putFields(connection: *Connection, stream_identifier: u31, fields: []const hpack.Field, end_stream: bool) !void {
        assert(stream_identifier != 0);
        assert(fields.len >= 1);
        const stream = stream_identifier;
        var block: [1024]u8 = undefined;
        const encoded = connection.encoder.encode(&block, fields);
        if (encoded.fields != fields.len) return error.BlockTooLarge;
        var flags = frame.Flag.end_headers.bit();
        if (end_stream) flags |= frame.Flag.end_stream.bit();
        try connection.put(.{ .headers = .{
            .priority = null,
            .fragment = block[0..encoded.written],
            .padding = null,
        } }, stream, flags);
    }

    fn put(connection: *Connection, payload: frame.Payload, stream_identifier: u31, flags: u8) !void {
        const written = try frame.payload.render(&payload, stream_identifier, flags, &connection.staged);
        assert(written >= frame.Header.octets);
        assert(written <= connection.staged.len);
        try connection.writer.interface.writeAll(connection.staged[0..written]);
    }
};
