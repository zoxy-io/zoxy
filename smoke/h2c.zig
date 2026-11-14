//! The live gate's HTTP/2 leg (#275): h2c by prior knowledge to the
//! plaintext http listener, on the shipped binary against the real
//! origin — a few streams opened in one write, each of which must come
//! back the origin's 200, its body, and the listener's response stamp, as
//! the HTTP/1.1 load's exchanges do.
//!
//! The field sections are written as HPACK literals, which need no table
//! on this side, and read back with the `h2` package's decoder: the leg
//! judges what the binary sent, not how it chose to compress it.

const std = @import("std");
const h2 = @import("h2");

const client_module = @import("client.zig");

const Io = std.Io;
const hpack = h2.hpack;
const assert = std.debug.assert;

/// The streams the leg opens on its one connection.
pub const streams: u8 = 3;

/// What one stream came back as.
pub const Answer = struct {
    status: u16 = 0,
    body_bytes: u32 = 0,
    ended: bool = false,
    reset: bool = false,
    /// The listener's #175 response-filter stamp arrived, lowercased.
    edited: bool = false,
    /// The origin's own tag arrived, so the exchange reached it.
    origin_tagged: bool = false,
};

const frame_data: u8 = 0x0;
const frame_headers: u8 = 0x1;
const frame_rst_stream: u8 = 0x3;
const flag_end_stream: u8 = 0x1;
const flag_end_headers: u8 = 0x4;

const read_bytes_max: usize = 16 * 1024;
/// Reads before the leg calls the proxy stalled. Each returns at least an
/// octet, so this bounds a trickle; a proxy that answers part and then
/// idles holds the read open until its own idle timeout or the harness's
/// budget, either of which ends the run with the stage named.
const reads_max: u32 = 64;

/// The identifier of the leg's `index`th stream: client-initiated, so odd
/// (RFC 9113 §5.1.1), opened in order.
pub fn streamId(index: u32) u31 {
    assert(index < streams);
    const id: u31 = @intCast(2 * index + 1);
    assert(id % 2 == 1);
    return id;
}

/// Open the connection, ask, read until every stream has ended, close.
pub fn run(io: Io, port: u16, answers: *[streams]Answer) !void {
    assert(port != 0);
    var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    var stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var request_buffer: [2048]u8 = undefined;
    const request = composeRequest(&request_buffer, port);
    var write_buffer: [256]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.writeAll(request);
    try writer.interface.flush();

    var received: [read_bytes_max]u8 = undefined;
    var received_len: usize = 0;
    var read_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var reads: u32 = 0;
    while (!allEnded(received[0..received_len])) : (reads += 1) {
        if (reads == reads_max) return error.H2LegStalled;
        // Whatever has arrived, not a full buffer: the connection stays
        // open after the last stream, so a read that waits to fill would
        // wait for the proxy's idle timeout.
        reader.interface.fillMore() catch |err| switch (err) {
            error.EndOfStream => return error.H2LegClosedEarly,
            else => return err,
        };
        const chunk = reader.interface.buffered();
        assert(chunk.len >= 1);
        if (received_len + chunk.len > received.len) return error.H2LegOverrun;
        @memcpy(received[received_len..][0..chunk.len], chunk);
        received_len += chunk.len;
        reader.interface.toss(chunk.len);
    }
    assert(received_len >= 9);
    try readAnswers(received[0..received_len], answers);
}

/// The preface, an empty SETTINGS, and a GET per stream — each carrying
/// the correlation header the access log names, with the value every
/// request this gate sends carries.
fn composeRequest(out: []u8, port: u16) []const u8 {
    var len: usize = 0;
    append(out, &len, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    append(out, &len, "\x00\x00\x00\x04\x00\x00\x00\x00\x00");
    // "127.0.0.1:" and at most five digits: fifteen octets of thirty-two.
    var authority_buffer: [32]u8 = undefined;
    const authority = std.fmt.bufPrint(&authority_buffer, "127.0.0.1:{d}", .{port}) catch unreachable;
    assert(authority.len <= 15);
    var index: u8 = 0;
    while (index < streams) : (index += 1) {
        // The load's own correlation value: the log verdict holds every
        // http line to it exactly, these streams' included.
        const request_id = client_module.request_id_value;
        const start = len;
        len += 9;
        const fields = [_][2][]const u8{
            .{ ":method", "GET" },           .{ ":scheme", "http" },
            .{ ":path", "/h2" },             .{ ":authority", authority },
            .{ "x-request-id", request_id },
        };
        for (fields) |field| {
            append(out, &len, "\x00");
            literal(out, &len, field[0]);
            literal(out, &len, field[1]);
        }
        const header = out[start..][0..9];
        std.mem.writeInt(u24, header[0..3], @intCast(len - start - 9), .big);
        header[3] = frame_headers;
        header[4] = flag_end_stream | flag_end_headers;
        std.mem.writeInt(u32, header[5..9], streamId(index), .big);
    }
    // More than the preface and its SETTINGS: every stream's HEADERS too.
    assert(len > 24 + 9 + 9 * @as(usize, streams));
    return out[0..len];
}

fn literal(out: []u8, len: *usize, bytes: []const u8) void {
    assert(bytes.len < 127); // A one-octet length (RFC 7541 §5.1).
    out[len.*] = @intCast(bytes.len);
    len.* += 1;
    append(out, len, bytes);
}

fn append(out: []u8, len: *usize, bytes: []const u8) void {
    assert(len.* + bytes.len <= out.len);
    @memcpy(out[len.*..][0..bytes.len], bytes);
    len.* += bytes.len;
}

/// Whether every stream has ended — END_STREAM, or a reset.
fn allEnded(bytes: []const u8) bool {
    var ended: [streams]bool = @splat(false);
    var offset: usize = 0;
    while (bytes.len - offset >= 9) {
        const header = bytes[offset..][0..9];
        const length = std.mem.readInt(u24, header[0..3], .big);
        if (bytes.len - offset - 9 < length) break;
        offset += 9 + length;
        const index = streamIndex(header) orelse continue;
        if (header[3] == frame_rst_stream or endsStream(header[3], header[4])) ended[index] = true;
    }
    for (ended) |stream_ended| {
        if (!stream_ended) return false;
    }
    return true;
}

/// Fold every frame into its stream's answer. PADDED and PRIORITY flags
/// are not read — the binary sends neither on a response — and a head
/// split across CONTINUATION is refused rather than assembled.
fn readAnswers(bytes: []const u8, answers: *[streams]Answer) !void {
    assert(bytes.len >= 9);
    var table: hpack.DynamicTable.Storage(4096) = .{};
    var decoder = hpack.Decoder.init(table.table(), 64 * 1024);
    var decoded: [16 * 1024]u8 = undefined;
    var offset: usize = 0;
    while (bytes.len - offset >= 9) {
        const header = bytes[offset..][0..9];
        const length = std.mem.readInt(u24, header[0..3], .big);
        if (bytes.len - offset - 9 < length) return error.H2LegFrameCut;
        const payload = bytes[offset + 9 ..][0..length];
        offset += 9 + length;
        const index = streamIndex(header) orelse continue;
        const answer = &answers[index];
        switch (header[3]) {
            frame_headers => {
                if (header[4] & flag_end_headers == 0) return error.H2LegContinuation;
                try readHead(&decoder, &decoded, payload, answer);
            },
            frame_data => answer.body_bytes += @intCast(payload.len),
            frame_rst_stream => answer.reset = true,
            else => {},
        }
        if (endsStream(header[3], header[4])) answer.ended = true;
    }
    // Every frame was whole: what is left is less than a frame header.
    assert(bytes.len - offset < 9);
}

fn readHead(decoder: *hpack.Decoder, decoded: []u8, block: []const u8, answer: *Answer) !void {
    var iterator = decoder.iterate(decoded, block);
    var fields: u32 = 0;
    while (try iterator.next()) |field| : (fields += 1) {
        assert(fields < 256);
        if (std.mem.eql(u8, field.name, ":status")) {
            answer.status = try std.fmt.parseUnsigned(u16, field.value, 10);
        }
        if (std.mem.eql(u8, field.name, "x-zoxy-smoke")) answer.edited = true;
        if (std.mem.eql(u8, field.name, "x-origin-tag")) answer.origin_tagged = true;
    }
}

fn streamIndex(header: *const [9]u8) ?usize {
    const id = std.mem.readInt(u32, header[5..9], .big) & 0x7fff_ffff;
    if (id == 0 or id % 2 == 0) return null;
    const index = (id - 1) / 2;
    if (index >= streams) return null;
    assert(streamId(index) == id);
    return index;
}

fn endsStream(frame_type: u8, flags: u8) bool {
    const carries = frame_type == frame_data or frame_type == frame_headers;
    // Only those two carry END_STREAM; RST_STREAM ends a stream without it.
    assert(flag_end_stream == 0x1);
    return carries and flags & flag_end_stream != 0;
}
