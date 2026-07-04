//! Sans-io HTTP/2 server connection engine (RFC 9113), Phase 5 slice 3
//! (docs/DESIGN.md §7): the connection and stream state machines over the
//! slice-1 frame codec and slice-2 HPACK, with dual-level flow-control
//! accounting. Fed received bytes, it consumes at most one frame per call,
//! stages any control frames (SETTINGS/acks, PING acks, WINDOW_UPDATE,
//! RST_STREAM, GOAWAY) into a caller buffer, and surfaces at most one
//! `Event` — the same drive-from-completions shape as the TLS `Channel`.
//!
//! Strictly bounded: stream slots are a fixed array sized by the
//! `MAX_CONCURRENT_STREAMS` we advertise (excess opens are refused with
//! REFUSED_STREAM after their header block is still decoded — HPACK state
//! is shared and must stay in sync); header blocks accumulate into a fixed
//! buffer (the CONTINUATION-flood bound); every window and setting we
//! honor is a `constants.zig` number.
//!
//! Out of scope here (slice 4+): request semantics (pseudo-header
//! validation, H1 translation), response HEADERS/DATA emission, and drain
//! GOAWAY. `close_stream`/`reset_stream` are the hooks those layers use.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const h2_frame = @import("h2_frame.zig");
const hpack = @import("hpack.zig");

pub const ErrorCode = h2_frame.ErrorCode;

/// The most output bytes one `drive` call can stage beyond pending window
/// updates: a control ack plus a stream reset plus a closing GOAWAY.
pub const output_bytes_min: usize = 128;

pub const Event = union(enum) {
    /// A complete request head. Header slices are valid until the next call
    /// into the connection.
    request: struct { stream_id: u31, headers: []const hpack.Header, end_stream: bool },
    /// Trailers on an open stream; they always end the request body.
    trailers: struct { stream_id: u31, headers: []const hpack.Header },
    /// Request body bytes (possibly empty). `flow_bytes` — the payload
    /// including padding — is what `release_data` must eventually return.
    data: struct { stream_id: u31, bytes: []const u8, flow_bytes: u32, end_stream: bool },
    /// The client reset this stream; its slot is already freed.
    reset: struct { stream_id: u31, code: ErrorCode },
    /// The client sent GOAWAY. Streams at or below `last_stream_id` are
    /// still expected to complete.
    goaway: struct { last_stream_id: u31, code: ErrorCode },
    /// Connection-fatal failure: a GOAWAY is staged in the output — flush
    /// it, then tear the connection down. The engine ignores further input.
    fatal: struct { code: ErrorCode },
};

pub const Result = struct {
    consumed: usize,
    produced: usize,
    event: ?Event,
};

pub const Stream = struct {
    /// 0 marks a free slot; client stream ids are odd, never 0.
    id: u31 = 0,
    state: State = .open,
    /// What the client may still send us (payload bytes, padding included).
    recv_window: i64 = 0,
    /// What the peer allows us to send (slice 4 spends this).
    send_window: i64 = 0,
    /// Consumed receive bytes not yet returned via WINDOW_UPDATE.
    recv_pending: u32 = 0,

    pub const State = enum { open, half_closed_remote };
};

pub const Connection = struct {
    state: enum { preface, frames, failed } = .preface,
    /// Our SETTINGS + connection WINDOW_UPDATE go out on the first drive.
    startup_sent: bool = false,
    /// The client acknowledged our SETTINGS — our advertised initial window
    /// binds it only from then on (§6.5.3).
    settings_acked: bool = false,
    peer_settings: h2_frame.Settings = .{},
    decoder: hpack.Decoder = .{},

    /// Header-block accumulation (HEADERS + CONTINUATIONs, §4.3). While
    /// `block_stream_id` is nonzero only CONTINUATION on that stream is legal.
    block: [constants.h2_header_block_bytes_max]u8 = undefined,
    block_used: u32 = 0,
    block_stream_id: u31 = 0,
    block_end_stream: bool = false,
    block_kind: enum { request, request_refused, trailers } = .request,

    /// Decoded head of the most recent block; valid until the next decode.
    headers: [constants.headers_max]hpack.Header = undefined,
    header_storage: [constants.h2_header_list_bytes_max]u8 = undefined,

    streams: [constants.h2_streams_max]Stream = @splat(.{}),
    streams_active: u32 = 0,
    /// Highest client stream id ever started: lower unknown ids are closed
    /// (implicitly or actually), not idle (§5.1.1).
    stream_id_max_started: u31 = 0,

    /// Connection-level receive window as the client sees it. Starts at the
    /// protocol default; the startup WINDOW_UPDATE raises it to our target.
    recv_window: i64 = 65535,
    recv_pending: u32 = 0,
    /// Connection-level send window (slice 4 spends it).
    send_window: i64 = 65535,

    goaway_received: bool = false,

    /// Process input and stage control output. Consumes at most one frame
    /// (or the preface) per call; call again while it makes progress.
    /// `output` must have room for `output_bytes_min` plus whatever window
    /// updates are pending — sizing it generously costs nothing.
    pub fn drive(connection: *Connection, input: []const u8, output: []u8) Result {
        assert(output.len >= output_bytes_min);
        if (connection.state == .failed) {
            // A failed connection swallows input; the GOAWAY already went out.
            return .{ .consumed = input.len, .produced = 0, .event = null };
        }
        var produced: usize = 0;
        if (!connection.startup_sent) {
            connection.startup_sent = true;
            produced += write_startup(output);
            // Mirror the staged boost in our own accounting.
            connection.recv_window += constants.h2_connection_window_bytes - 65535;
        }
        produced += connection.flush_windows(output[produced..]);

        if (connection.state == .preface) {
            const preface_len = h2_frame.check_preface(input) catch {
                return connection.fail(.protocol_error, output, produced, input.len);
            };
            if (preface_len == null) return .{ .consumed = 0, .produced = produced, .event = null };
            connection.state = .frames;
            return .{ .consumed = preface_len.?, .produced = produced, .event = null };
        }

        const frame = h2_frame.parse_frame(input) catch |err| {
            return connection.fail(h2_frame.error_code(err), output, produced, input.len);
        } orelse return .{ .consumed = 0, .produced = produced, .event = null };
        assert(frame.wire_bytes() <= input.len);
        return connection.drive_frame(frame, output, produced);
    }

    /// Return consumed receive-window bytes after forwarding them; the next
    /// drive emits WINDOW_UPDATE once half a window accumulates. A stream
    /// that is already gone still releases the connection-level window.
    pub fn release_data(connection: *Connection, stream_id: u31, flow_bytes: u32) void {
        assert(stream_id != 0);
        assert(flow_bytes > 0);
        connection.recv_pending += flow_bytes;
        if (connection.stream_find(stream_id)) |stream| stream.recv_pending += flow_bytes;
    }

    /// The response for this stream is complete: free the slot.
    pub fn close_stream(connection: *Connection, stream_id: u31) void {
        const stream = connection.stream_find(stream_id).?;
        connection.stream_free(stream);
    }

    /// Abort a stream: stage RST_STREAM into `output` and free the slot.
    pub fn reset_stream(connection: *Connection, stream_id: u31, code: ErrorCode, output: []u8) usize {
        assert(output.len >= h2_frame.rst_stream_frame_bytes);
        const stream = connection.stream_find(stream_id).?;
        connection.stream_free(stream);
        h2_frame.write_rst_stream(stream_id, code, output[0..h2_frame.rst_stream_frame_bytes]);
        return h2_frame.rst_stream_frame_bytes;
    }

    fn drive_frame(connection: *Connection, frame: h2_frame.Frame, output: []u8, staged: usize) Result {
        const consumed = frame.wire_bytes();
        var produced = staged;
        // Mid-block, only CONTINUATION on the block's stream is legal (§4.3).
        if (connection.block_stream_id != 0 and
            (frame.header.type != .continuation or
                frame.header.stream_id != connection.block_stream_id))
        {
            return connection.fail(.protocol_error, output, produced, consumed);
        }
        switch (frame.header.type) {
            .settings => return connection.on_settings(frame, output, produced, consumed),
            .ping => {
                if (frame.header.flags & h2_frame.Flags.ack == 0) {
                    const ack = output[produced..][0..h2_frame.ping_frame_bytes];
                    h2_frame.write_ping(frame.payload[0..8], true, ack);
                    produced += h2_frame.ping_frame_bytes;
                }
                return .{ .consumed = consumed, .produced = produced, .event = null };
            },
            .goaway => {
                const goaway = h2_frame.parse_goaway(frame.payload);
                connection.goaway_received = true;
                return .{ .consumed = consumed, .produced = produced, .event = .{
                    .goaway = .{ .last_stream_id = goaway.last_stream_id, .code = goaway.code },
                } };
            },
            .window_update => return connection.on_window_update(frame, output, produced, consumed),
            .rst_stream => return connection.on_rst_stream(frame, output, produced, consumed),
            .priority => {
                // Parsed for structure, ignored for meaning (RFC 9113
                // deprecated the priority tree).
                return .{ .consumed = consumed, .produced = produced, .event = null };
            },
            .push_promise => {
                // Clients cannot push (§8.4).
                return connection.fail(.protocol_error, output, produced, consumed);
            },
            .data => return connection.on_data(frame, output, produced, consumed),
            .headers => return connection.on_headers(frame, output, produced, consumed),
            .continuation => return connection.on_continuation(frame, output, produced, consumed),
            _ => {
                // Unknown frame types are skipped (§4.1, §5.5).
                return .{ .consumed = consumed, .produced = produced, .event = null };
            },
        }
    }

    fn on_settings(connection: *Connection, frame: h2_frame.Frame, output: []u8, staged: usize, consumed: usize) Result {
        var produced = staged;
        if (frame.header.flags & h2_frame.Flags.ack != 0) {
            connection.settings_acked = true;
            return .{ .consumed = consumed, .produced = produced, .event = null };
        }
        const window_before = connection.peer_settings.initial_window_size;
        connection.peer_settings.apply(frame.payload) catch |err| {
            return connection.fail(h2_frame.error_code(err), output, produced, consumed);
        };
        // An INITIAL_WINDOW_SIZE change retunes every active stream's send
        // window by the delta — possibly below zero (§6.9.2).
        const delta = @as(i64, connection.peer_settings.initial_window_size) - window_before;
        if (delta != 0) {
            for (&connection.streams) |*stream| {
                if (stream.id == 0) continue;
                stream.send_window += delta;
                if (stream.send_window > std.math.maxInt(u31)) {
                    return connection.fail(.flow_control_error, output, produced, consumed);
                }
            }
        }
        h2_frame.write_settings_ack(output[produced..][0..h2_frame.frame_header_bytes]);
        produced += h2_frame.frame_header_bytes;
        return .{ .consumed = consumed, .produced = produced, .event = null };
    }

    fn on_window_update(connection: *Connection, frame: h2_frame.Frame, output: []u8, staged: usize, consumed: usize) Result {
        const increment = h2_frame.parse_window_update(frame.payload[0..4]) catch {
            // A zero increment: connection error on stream 0, else stream error (§6.9).
            if (frame.header.stream_id == 0) {
                return connection.fail(.protocol_error, output, staged, consumed);
            }
            return connection.reset_on_error(frame.header.stream_id, .protocol_error, output, staged, consumed);
        };
        if (frame.header.stream_id == 0) {
            connection.send_window += increment;
            if (connection.send_window > std.math.maxInt(u31)) {
                return connection.fail(.flow_control_error, output, staged, consumed);
            }
            return .{ .consumed = consumed, .produced = staged, .event = null };
        }
        if (connection.stream_find(frame.header.stream_id)) |stream| {
            stream.send_window += increment;
            if (stream.send_window > std.math.maxInt(u31)) {
                return connection.reset_on_error(stream.id, .flow_control_error, output, staged, consumed);
            }
        } else if (!connection.stream_closed(frame.header.stream_id)) {
            // Idle stream: never legal (§5.1). Closed: ignored (§5.1, §6.9).
            return connection.fail(.protocol_error, output, staged, consumed);
        }
        return .{ .consumed = consumed, .produced = staged, .event = null };
    }

    fn on_rst_stream(connection: *Connection, frame: h2_frame.Frame, output: []u8, staged: usize, consumed: usize) Result {
        const stream_id = frame.header.stream_id;
        if (connection.stream_find(stream_id)) |stream| {
            const code = h2_frame.parse_rst_stream(frame.payload[0..4]);
            connection.stream_free(stream);
            return .{ .consumed = consumed, .produced = staged, .event = .{
                .reset = .{ .stream_id = stream_id, .code = code },
            } };
        }
        if (!connection.stream_closed(stream_id)) {
            return connection.fail(.protocol_error, output, staged, consumed); // RST on idle (§6.4)
        }
        return .{ .consumed = consumed, .produced = staged, .event = null };
    }

    fn on_data(connection: *Connection, frame: h2_frame.Frame, output: []u8, staged: usize, consumed: usize) Result {
        const flow_bytes: u32 = frame.header.length;
        // Flow control counts every DATA payload byte, padding included,
        // against both windows — whatever the stream state (§6.9).
        connection.recv_window -= flow_bytes;
        if (connection.recv_window < 0) {
            return connection.fail(.flow_control_error, output, staged, consumed);
        }
        const stream = connection.stream_find(frame.header.stream_id) orelse {
            const code: ErrorCode =
                if (connection.stream_closed(frame.header.stream_id)) .stream_closed else .protocol_error;
            return connection.fail(code, output, staged, consumed);
        };
        if (stream.state != .open) {
            return connection.fail(.stream_closed, output, staged, consumed); // §5.1 half-closed (remote)
        }
        stream.recv_window -= flow_bytes;
        if (stream.recv_window < 0) {
            return connection.fail(.flow_control_error, output, staged, consumed);
        }
        const bytes = strip_padding(frame) orelse {
            return connection.fail(.protocol_error, output, staged, consumed);
        };
        const end_stream = frame.header.flags & h2_frame.Flags.end_stream != 0;
        if (end_stream) stream.state = .half_closed_remote;
        if (flow_bytes == 0 and !end_stream) {
            // Nothing to forward, nothing to release: skip the empty event.
            return .{ .consumed = consumed, .produced = staged, .event = null };
        }
        return .{ .consumed = consumed, .produced = staged, .event = .{ .data = .{
            .stream_id = stream.id,
            .bytes = bytes,
            .flow_bytes = flow_bytes,
            .end_stream = end_stream,
        } } };
    }

    fn on_headers(connection: *Connection, frame: h2_frame.Frame, output: []u8, staged: usize, consumed: usize) Result {
        assert(connection.block_stream_id == 0); // checked in drive_frame
        const stream_id = frame.header.stream_id;
        const fragment = headers_fragment(frame) orelse {
            return connection.fail(.protocol_error, output, staged, consumed);
        };
        if (stream_id % 2 == 0) {
            return connection.fail(.protocol_error, output, staged, consumed); // client ids are odd (§5.1.1)
        }
        connection.block_end_stream = frame.header.flags & h2_frame.Flags.end_stream != 0;
        if (connection.stream_find(stream_id)) |stream| {
            // A second HEADERS on a live stream is the trailers block; it
            // must end the stream, checked at decode (§8.1).
            if (stream.state != .open) {
                return connection.fail(.stream_closed, output, staged, consumed);
            }
            connection.block_kind = .trailers;
        } else if (stream_id > connection.stream_id_max_started) {
            connection.block_kind = if (connection.streams_active < constants.h2_streams_max)
                .request
            else
                // Over the advertised limit: the block still must be decoded
                // (HPACK state), then the stream is refused.
                .request_refused;
            connection.stream_id_max_started = stream_id;
        } else {
            return connection.fail(.stream_closed, output, staged, consumed); // closed stream (§5.1)
        }
        connection.block_stream_id = stream_id;
        connection.block_used = 0;
        if (!connection.block_append(fragment)) {
            return connection.fail(.enhance_your_calm, output, staged, consumed);
        }
        if (frame.header.flags & h2_frame.Flags.end_headers != 0) {
            return connection.finish_block(output, staged, consumed);
        }
        return .{ .consumed = consumed, .produced = staged, .event = null };
    }

    fn on_continuation(connection: *Connection, frame: h2_frame.Frame, output: []u8, staged: usize, consumed: usize) Result {
        if (connection.block_stream_id == 0) {
            return connection.fail(.protocol_error, output, staged, consumed); // no block in progress
        }
        assert(frame.header.stream_id == connection.block_stream_id); // checked in drive_frame
        if (!connection.block_append(frame.payload)) {
            return connection.fail(.enhance_your_calm, output, staged, consumed);
        }
        if (frame.header.flags & h2_frame.Flags.end_headers != 0) {
            return connection.finish_block(output, staged, consumed);
        }
        return .{ .consumed = consumed, .produced = staged, .event = null };
    }

    /// Decode the accumulated header block and open/refuse/trail the stream.
    fn finish_block(connection: *Connection, output: []u8, staged: usize, consumed: usize) Result {
        var produced = staged;
        const stream_id = connection.block_stream_id;
        const kind = connection.block_kind;
        const end_stream = connection.block_end_stream;
        connection.block_stream_id = 0;

        const decoded = connection.decoder.decode(
            connection.block[0..connection.block_used],
            &connection.headers,
            &connection.header_storage,
        ) catch |err| switch (err) {
            // HPACK state is unrecoverable: the connection dies (§4.3).
            error.Compression => return connection.fail(.compression_error, output, produced, consumed),
            // Bounds: the request is refused, the connection survives. The
            // decoder kept the dynamic table in sync. (431 is slice 4's call.)
            error.HeaderListTooLarge, error.TooManyHeaders => {
                h2_frame.write_rst_stream(
                    stream_id,
                    .protocol_error,
                    output[produced..][0..h2_frame.rst_stream_frame_bytes],
                );
                produced += h2_frame.rst_stream_frame_bytes;
                return .{ .consumed = consumed, .produced = produced, .event = null };
            },
        };

        switch (kind) {
            .request_refused => {
                h2_frame.write_rst_stream(
                    stream_id,
                    .refused_stream,
                    output[produced..][0..h2_frame.rst_stream_frame_bytes],
                );
                produced += h2_frame.rst_stream_frame_bytes;
                return .{ .consumed = consumed, .produced = produced, .event = null };
            },
            .request => {
                connection.stream_open(stream_id, end_stream);
                return .{ .consumed = consumed, .produced = produced, .event = .{ .request = .{
                    .stream_id = stream_id,
                    .headers = decoded,
                    .end_stream = end_stream,
                } } };
            },
            .trailers => {
                if (!end_stream) {
                    // Trailers that do not end the stream are malformed (§8.1).
                    return connection.fail(.protocol_error, output, produced, consumed);
                }
                const stream = connection.stream_find(stream_id).?;
                assert(stream.state == .open);
                stream.state = .half_closed_remote;
                return .{ .consumed = consumed, .produced = produced, .event = .{ .trailers = .{
                    .stream_id = stream_id,
                    .headers = decoded,
                } } };
            },
        }
    }

    fn block_append(connection: *Connection, fragment: []const u8) bool {
        if (fragment.len > connection.block.len - connection.block_used) return false;
        @memcpy(connection.block[connection.block_used..][0..fragment.len], fragment);
        connection.block_used += @intCast(fragment.len);
        return true;
    }

    /// Stage a GOAWAY, remember failure, and swallow the offending input.
    fn fail(connection: *Connection, code: ErrorCode, output: []u8, staged: usize, consumed: usize) Result {
        assert(connection.state != .failed);
        connection.state = .failed;
        h2_frame.write_goaway(
            connection.stream_id_max_started,
            code,
            output[staged..][0..h2_frame.goaway_frame_bytes],
        );
        return .{
            .consumed = consumed,
            .produced = staged + h2_frame.goaway_frame_bytes,
            .event = .{ .fatal = .{ .code = code } },
        };
    }

    /// A stream-level error: stage RST_STREAM, free the slot, surface reset.
    fn reset_on_error(connection: *Connection, stream_id: u31, code: ErrorCode, output: []u8, staged: usize, consumed: usize) Result {
        const stream = connection.stream_find(stream_id).?;
        connection.stream_free(stream);
        h2_frame.write_rst_stream(
            stream_id,
            code,
            output[staged..][0..h2_frame.rst_stream_frame_bytes],
        );
        return .{
            .consumed = consumed,
            .produced = staged + h2_frame.rst_stream_frame_bytes,
            .event = .{ .reset = .{ .stream_id = stream_id, .code = code } },
        };
    }

    /// Emit WINDOW_UPDATEs for windows at least half consumed.
    fn flush_windows(connection: *Connection, output: []u8) usize {
        var produced: usize = 0;
        const frame_bytes = h2_frame.window_update_frame_bytes;
        if (connection.recv_pending >= constants.h2_connection_window_bytes / 2 and
            output.len - produced >= frame_bytes + output_bytes_min)
        {
            h2_frame.write_window_update(0, @intCast(connection.recv_pending), output[produced..][0..frame_bytes]);
            connection.recv_window += connection.recv_pending;
            connection.recv_pending = 0;
            produced += frame_bytes;
        }
        for (&connection.streams) |*stream| {
            if (stream.id == 0) continue;
            if (stream.recv_pending < constants.h2_stream_window_bytes / 2) continue;
            if (output.len - produced < frame_bytes + output_bytes_min) break;
            h2_frame.write_window_update(stream.id, @intCast(stream.recv_pending), output[produced..][0..frame_bytes]);
            stream.recv_window += stream.recv_pending;
            stream.recv_pending = 0;
            produced += frame_bytes;
        }
        return produced;
    }

    fn stream_find(connection: *Connection, stream_id: u31) ?*Stream {
        assert(stream_id != 0);
        // Bounded linear scan over the fixed slots.
        for (&connection.streams) |*stream| {
            if (stream.id == stream_id) return stream;
        }
        return null;
    }

    /// A stream id with no slot is closed if it was ever started — directly
    /// or implicitly, by a higher id opening first (§5.1.1) — else idle.
    fn stream_closed(connection: *const Connection, stream_id: u31) bool {
        assert(stream_id != 0);
        return stream_id <= connection.stream_id_max_started;
    }

    fn stream_open(connection: *Connection, stream_id: u31, end_stream: bool) void {
        assert(connection.streams_active < constants.h2_streams_max);
        assert(connection.stream_find(stream_id) == null);
        for (&connection.streams) |*stream| {
            if (stream.id != 0) continue;
            stream.* = .{
                .id = stream_id,
                .state = if (end_stream) .half_closed_remote else .open,
                // Our advertised window binds the client only once it has
                // acknowledged our SETTINGS; before that, the default rules.
                .recv_window = if (connection.settings_acked)
                    constants.h2_stream_window_bytes
                else
                    65535,
                .send_window = connection.peer_settings.initial_window_size,
            };
            connection.streams_active += 1;
            return;
        }
        unreachable; // streams_active < h2_streams_max guarantees a free slot
    }

    fn stream_free(connection: *Connection, stream: *Stream) void {
        assert(stream.id != 0);
        assert(connection.streams_active > 0);
        stream.* = .{};
        connection.streams_active -= 1;
    }
};

/// Our SETTINGS plus the WINDOW_UPDATE that lifts the connection window
/// from the protocol default to the full-slots target.
fn write_startup(output: []u8) usize {
    var produced = h2_frame.write_settings(&.{
        .{ .id = .max_concurrent_streams, .value = constants.h2_streams_max },
        .{ .id = .initial_window_size, .value = constants.h2_stream_window_bytes },
        .{ .id = .max_header_list_size, .value = constants.h2_header_list_bytes_max },
    }, output);
    const boost: u31 = constants.h2_connection_window_bytes - 65535;
    h2_frame.write_window_update(0, boost, output[produced..][0..h2_frame.window_update_frame_bytes]);
    produced += h2_frame.window_update_frame_bytes;
    assert(produced <= output_bytes_min);
    return produced;
}

/// The DATA payload with padding removed (§6.1); null when malformed.
fn strip_padding(frame: h2_frame.Frame) ?[]const u8 {
    if (frame.header.flags & h2_frame.Flags.padded == 0) return frame.payload;
    if (frame.payload.len < 1) return null;
    const pad_length = frame.payload[0];
    if (pad_length >= frame.payload.len) return null;
    return frame.payload[1 .. frame.payload.len - pad_length];
}

/// The HEADERS header-block fragment: padding and the (ignored) priority
/// fields stripped (§6.2); null when malformed.
fn headers_fragment(frame: h2_frame.Frame) ?[]const u8 {
    var fragment = frame.payload;
    var pad_length: usize = 0;
    if (frame.header.flags & h2_frame.Flags.padded != 0) {
        if (fragment.len < 1) return null;
        pad_length = fragment[0];
        fragment = fragment[1..];
    }
    if (frame.header.flags & h2_frame.Flags.priority != 0) {
        if (fragment.len < 5) return null;
        fragment = fragment[5..];
    }
    if (pad_length > fragment.len) return null;
    return fragment[0 .. fragment.len - pad_length];
}

// ---- tests -------------------------------------------------------------------

const testing = std.testing;

/// Drives a Connection from the client's side: builds client frames with
/// the slice-1/2 writers and hands them over one drive() at a time.
const TestPeer = struct {
    connection: Connection = .{},
    output: [4096]u8 = undefined,
    produced: usize = 0,

    /// Feed bytes until fully consumed; collect at most one event (asserts
    /// no second event surfaces mid-buffer).
    fn feed(peer: *TestPeer, bytes: []const u8) ?Event {
        var event: ?Event = null;
        var offset: usize = 0;
        peer.produced = 0;
        while (true) {
            const result = peer.connection.drive(bytes[offset..], peer.output[peer.produced..]);
            peer.produced += result.produced;
            offset += result.consumed;
            if (result.event) |e| {
                assert(event == null);
                event = e;
            }
            if (offset == bytes.len or result.consumed == 0) break;
        }
        assert(offset == bytes.len);
        return event;
    }

    fn open(peer: *TestPeer) void {
        _ = peer.feed(h2_frame.client_preface);
        var settings: [64]u8 = undefined;
        const settings_len = h2_frame.write_settings(&.{}, &settings);
        _ = peer.feed(settings[0..settings_len]);
        var ack: [h2_frame.frame_header_bytes]u8 = undefined;
        h2_frame.write_settings_ack(&ack);
        _ = peer.feed(&ack);
    }

    fn request_bytes(stream_id: u31, end_stream: bool, out: []u8) usize {
        var block: [128]u8 = undefined;
        var block_used: usize = 0;
        block_used += hpack.encode_header(":method", "GET", block[block_used..]) catch unreachable;
        block_used += hpack.encode_header(":scheme", "https", block[block_used..]) catch unreachable;
        block_used += hpack.encode_header(":path", "/", block[block_used..]) catch unreachable;
        block_used += hpack.encode_header(":authority", "zoxy.test", block[block_used..]) catch unreachable;
        return headers_frame_bytes(stream_id, block[0..block_used], end_stream, true, out);
    }

    fn headers_frame_bytes(stream_id: u31, block: []const u8, end_stream: bool, end_headers: bool, out: []u8) usize {
        var flags: u8 = 0;
        if (end_stream) flags |= h2_frame.Flags.end_stream;
        if (end_headers) flags |= h2_frame.Flags.end_headers;
        h2_frame.write_frame_header(.{
            .length = @intCast(block.len),
            .type = .headers,
            .flags = flags,
            .stream_id = stream_id,
        }, out[0..h2_frame.frame_header_bytes]);
        @memcpy(out[h2_frame.frame_header_bytes..][0..block.len], block);
        return h2_frame.frame_header_bytes + block.len;
    }

    fn data_frame_bytes(stream_id: u31, payload: []const u8, end_stream: bool, out: []u8) usize {
        h2_frame.write_frame_header(.{
            .length = @intCast(payload.len),
            .type = .data,
            .flags = if (end_stream) h2_frame.Flags.end_stream else 0,
            .stream_id = stream_id,
        }, out[0..h2_frame.frame_header_bytes]);
        @memcpy(out[h2_frame.frame_header_bytes..][0..payload.len], payload);
        return h2_frame.frame_header_bytes + payload.len;
    }

    /// Parse the staged output into frames, returning how many of `types`
    /// matched (asserts the sequence).
    fn expect_output(peer: *TestPeer, types: []const h2_frame.FrameType) !void {
        var offset: usize = 0;
        for (types) |frame_type| {
            const frame = (try h2_frame.parse_frame(peer.output[offset..peer.produced])).?;
            try testing.expectEqual(frame_type, frame.header.type);
            offset += frame.wire_bytes();
        }
        try testing.expectEqual(peer.produced, offset);
    }
};

test "h2: connection setup exchanges settings" {
    var peer = TestPeer{};
    // First drive emits our SETTINGS and the connection window boost.
    _ = peer.feed(h2_frame.client_preface);
    try peer.expect_output(&.{ .settings, .window_update });
    const settings_frame = (try h2_frame.parse_frame(peer.output[0..peer.produced])).?;
    var advertised = h2_frame.Settings{};
    try advertised.apply(settings_frame.payload);
    try testing.expectEqual(constants.h2_streams_max, advertised.max_concurrent_streams.?);
    try testing.expectEqual(
        @as(u31, constants.h2_stream_window_bytes),
        advertised.initial_window_size,
    );

    // The client SETTINGS gets an ack; its ack of ours flips the flag.
    var buffer: [64]u8 = undefined;
    const settings_len = h2_frame.write_settings(&.{}, &buffer);
    _ = peer.feed(buffer[0..settings_len]);
    try peer.expect_output(&.{.settings});
    try testing.expect(!peer.connection.settings_acked);
    var ack: [h2_frame.frame_header_bytes]u8 = undefined;
    h2_frame.write_settings_ack(&ack);
    _ = peer.feed(&ack);
    try testing.expect(peer.connection.settings_acked);
}

test "h2: a GET request opens and half-closes a stream" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    const event = peer.feed(frame[0..TestPeer.request_bytes(1, true, &frame)]).?;
    try testing.expectEqual(@as(u31, 1), event.request.stream_id);
    try testing.expect(event.request.end_stream);
    try testing.expectEqual(@as(usize, 4), event.request.headers.len);
    try testing.expectEqualStrings(":method", event.request.headers[0].name);
    try testing.expectEqualStrings("GET", event.request.headers[0].value);
    try testing.expectEqualStrings("zoxy.test", event.request.headers[3].value);
    try testing.expectEqual(@as(u32, 1), peer.connection.streams_active);
    try testing.expectEqual(Stream.State.half_closed_remote, peer.connection.streams[0].state);

    peer.connection.close_stream(1);
    try testing.expectEqual(@as(u32, 0), peer.connection.streams_active);
}

test "h2: request body flows with padding and window accounting" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    _ = peer.feed(frame[0..TestPeer.request_bytes(1, false, &frame)]);

    const before = peer.connection.streams[0].recv_window;
    var data_len = TestPeer.data_frame_bytes(1, "hello ", false, &frame);
    const first = peer.feed(frame[0..data_len]).?;
    try testing.expectEqualStrings("hello ", first.data.bytes);
    try testing.expectEqual(@as(u32, 6), first.data.flow_bytes);
    try testing.expect(!first.data.end_stream);

    // A padded DATA frame: padding counts against flow control, not content.
    const padded = "\x03world!" ++ "\x00\x00\x00";
    data_len = TestPeer.data_frame_bytes(1, padded, true, &frame);
    frame[4] |= h2_frame.Flags.padded;
    const second = peer.feed(frame[0..data_len]).?;
    try testing.expectEqualStrings("world!", second.data.bytes);
    try testing.expectEqual(@as(u32, 10), second.data.flow_bytes);
    try testing.expect(second.data.end_stream);
    try testing.expectEqual(before - 16, peer.connection.streams[0].recv_window);
    try testing.expectEqual(
        @as(i64, constants.h2_connection_window_bytes - 16),
        peer.connection.recv_window,
    );
}

test "h2: released data flushes WINDOW_UPDATE at half a window" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    _ = peer.feed(frame[0..TestPeer.request_bytes(1, false, &frame)]);

    // Below half a stream window: nothing flushes.
    peer.connection.release_data(1, constants.h2_stream_window_bytes / 2 - 1);
    _ = peer.feed("");
    try peer.expect_output(&.{});
    // Crossing the threshold flushes the full pending amount.
    peer.connection.release_data(1, 1);
    const window_before = peer.connection.streams[0].recv_window;
    _ = peer.feed("");
    try peer.expect_output(&.{.window_update});
    const update = (try h2_frame.parse_frame(peer.output[0..peer.produced])).?;
    try testing.expectEqual(@as(u31, 1), update.header.stream_id);
    try testing.expectEqual(
        @as(u31, constants.h2_stream_window_bytes / 2),
        try h2_frame.parse_window_update(update.payload[0..4]),
    );
    try testing.expectEqual(
        window_before + constants.h2_stream_window_bytes / 2,
        peer.connection.streams[0].recv_window,
    );
    try testing.expectEqual(@as(u32, 0), peer.connection.streams[0].recv_pending);
}

test "h2: stream slots exhaust into REFUSED_STREAM and recover" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    var stream_id: u31 = 1;
    for (0..constants.h2_streams_max) |_| {
        const event = peer.feed(frame[0..TestPeer.request_bytes(stream_id, false, &frame)]);
        try testing.expect(event.? == .request);
        stream_id += 2;
    }
    try testing.expectEqual(constants.h2_streams_max, peer.connection.streams_active);

    // One more: refused, no event, connection alive, HPACK still in sync.
    const refused_id = stream_id;
    try testing.expectEqual(
        @as(?Event, null),
        peer.feed(frame[0..TestPeer.request_bytes(refused_id, false, &frame)]),
    );
    try peer.expect_output(&.{.rst_stream});
    const rst = (try h2_frame.parse_frame(peer.output[0..peer.produced])).?;
    try testing.expectEqual(refused_id, rst.header.stream_id);
    try testing.expectEqual(ErrorCode.refused_stream, h2_frame.parse_rst_stream(rst.payload[0..4]));

    // Freeing a slot admits the next stream.
    peer.connection.close_stream(1);
    stream_id += 2;
    const event = peer.feed(frame[0..TestPeer.request_bytes(stream_id, false, &frame)]);
    try testing.expect(event.? == .request);
}

test "h2: header blocks span CONTINUATION frames" {
    var peer = TestPeer{};
    peer.open();
    var block: [64]u8 = undefined;
    var block_used: usize = 0;
    block_used += try hpack.encode_header(":method", "GET", block[block_used..]);
    block_used += try hpack.encode_header(":path", "/", block[block_used..]);
    const split = block_used / 2;

    var frame: [128]u8 = undefined;
    const head_len = TestPeer.headers_frame_bytes(1, block[0..split], true, false, &frame);
    try testing.expectEqual(@as(?Event, null), peer.feed(frame[0..head_len]));

    h2_frame.write_frame_header(.{
        .length = @intCast(block_used - split),
        .type = .continuation,
        .flags = h2_frame.Flags.end_headers,
        .stream_id = 1,
    }, frame[0..h2_frame.frame_header_bytes]);
    @memcpy(frame[h2_frame.frame_header_bytes..][0 .. block_used - split], block[split..block_used]);
    const event = peer.feed(frame[0 .. h2_frame.frame_header_bytes + block_used - split]).?;
    try testing.expectEqual(@as(usize, 2), event.request.headers.len);
    try testing.expectEqualStrings(":path", event.request.headers[1].name);
}

test "h2: an interleaved frame inside a header block is fatal" {
    var peer = TestPeer{};
    peer.open();
    var block: [64]u8 = undefined;
    const block_used = try hpack.encode_header(":method", "GET", &block);
    var frame: [128]u8 = undefined;
    const head_len = TestPeer.headers_frame_bytes(1, block[0..block_used], true, false, &frame);
    _ = peer.feed(frame[0..head_len]);

    var ping: [h2_frame.ping_frame_bytes]u8 = undefined;
    h2_frame.write_ping(&([_]u8{0} ** 8), false, &ping);
    const event = peer.feed(&ping).?;
    try testing.expectEqual(ErrorCode.protocol_error, event.fatal.code);
    try peer.expect_output(&.{.goaway});
}

test "h2: oversized header blocks die of enhance_your_calm" {
    var peer = TestPeer{};
    peer.open();
    // A HEADERS then CONTINUATIONs of raw literals until the block bound.
    var block: [1024]u8 = undefined;
    var block_used: usize = 0;
    block_used += try hpack.encode_header("x-filler", "y" ** 900, block[0..]);
    var frame: [2048]u8 = undefined;
    const head_len = TestPeer.headers_frame_bytes(1, block[0..block_used], false, false, &frame);
    _ = peer.feed(frame[0..head_len]);

    var sent: usize = block_used;
    var event: ?Event = null;
    while (sent <= constants.h2_header_block_bytes_max) {
        h2_frame.write_frame_header(.{
            .length = @intCast(block_used),
            .type = .continuation,
            .flags = 0,
            .stream_id = 1,
        }, frame[0..h2_frame.frame_header_bytes]);
        @memcpy(frame[h2_frame.frame_header_bytes..][0..block_used], block[0..block_used]);
        event = peer.feed(frame[0 .. h2_frame.frame_header_bytes + block_used]);
        if (event != null) break;
        sent += block_used;
    }
    try testing.expectEqual(ErrorCode.enhance_your_calm, event.?.fatal.code);
}

test "h2: stream id rules are enforced" {
    // Even ids are fatal.
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    var event = peer.feed(frame[0..TestPeer.request_bytes(2, true, &frame)]).?;
    try testing.expectEqual(ErrorCode.protocol_error, event.fatal.code);

    // Reusing a closed (lower) id is stream_closed.
    peer = TestPeer{};
    peer.open();
    _ = peer.feed(frame[0..TestPeer.request_bytes(5, true, &frame)]);
    event = peer.feed(frame[0..TestPeer.request_bytes(3, true, &frame)]).?;
    try testing.expectEqual(ErrorCode.stream_closed, event.fatal.code);

    // DATA on an idle stream is protocol_error; after END_STREAM, stream_closed.
    peer = TestPeer{};
    peer.open();
    const data_len = TestPeer.data_frame_bytes(9, "x", false, &frame);
    event = peer.feed(frame[0..data_len]).?;
    try testing.expectEqual(ErrorCode.protocol_error, event.fatal.code);

    peer = TestPeer{};
    peer.open();
    _ = peer.feed(frame[0..TestPeer.request_bytes(1, true, &frame)]);
    const trailing = TestPeer.data_frame_bytes(1, "x", false, &frame);
    event = peer.feed(frame[0..trailing]).?;
    try testing.expectEqual(ErrorCode.stream_closed, event.fatal.code);
}

test "h2: flow-control violations are fatal" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    _ = peer.feed(frame[0..TestPeer.request_bytes(1, false, &frame)]);
    // Shrink the stream window below the next frame to trip the check.
    peer.connection.streams[0].recv_window = 3;
    const data_len = TestPeer.data_frame_bytes(1, "xxxx", false, &frame);
    const event = peer.feed(frame[0..data_len]).?;
    try testing.expectEqual(ErrorCode.flow_control_error, event.fatal.code);
    try peer.expect_output(&.{.goaway});
}

test "h2: window updates move send windows and overflow is refused" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    _ = peer.feed(frame[0..TestPeer.request_bytes(1, false, &frame)]);

    var update: [h2_frame.window_update_frame_bytes]u8 = undefined;
    h2_frame.write_window_update(0, 1000, &update);
    _ = peer.feed(&update);
    try testing.expectEqual(@as(i64, 65535 + 1000), peer.connection.send_window);
    h2_frame.write_window_update(1, 1000, &update);
    _ = peer.feed(&update);
    try testing.expectEqual(@as(i64, 65535 + 1000), peer.connection.streams[0].send_window);

    // Stream overflow resets the stream; connection overflow is fatal.
    h2_frame.write_window_update(1, std.math.maxInt(u31), &update);
    var event = peer.feed(&update).?;
    try testing.expectEqual(ErrorCode.flow_control_error, event.reset.code);
    try peer.expect_output(&.{.rst_stream});
    h2_frame.write_window_update(0, std.math.maxInt(u31), &update);
    event = peer.feed(&update).?;
    try testing.expectEqual(ErrorCode.flow_control_error, event.fatal.code);
}

test "h2: peer INITIAL_WINDOW_SIZE change retunes live streams" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    _ = peer.feed(frame[0..TestPeer.request_bytes(1, false, &frame)]);
    try testing.expectEqual(@as(i64, 65535), peer.connection.streams[0].send_window);

    var buffer: [64]u8 = undefined;
    const settings_len = h2_frame.write_settings(
        &.{.{ .id = .initial_window_size, .value = 100 }},
        &buffer,
    );
    _ = peer.feed(buffer[0..settings_len]);
    try peer.expect_output(&.{.settings}); // the ack
    // 65535 -> 100: live stream shifted by the delta (§6.9.2).
    try testing.expectEqual(@as(i64, 100), peer.connection.streams[0].send_window);
}

test "h2: client RST_STREAM frees the slot and surfaces reset" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    _ = peer.feed(frame[0..TestPeer.request_bytes(1, false, &frame)]);

    var rst: [h2_frame.rst_stream_frame_bytes]u8 = undefined;
    h2_frame.write_rst_stream(1, .cancel, &rst);
    const event = peer.feed(&rst).?;
    try testing.expectEqual(@as(u31, 1), event.reset.stream_id);
    try testing.expectEqual(ErrorCode.cancel, event.reset.code);
    try testing.expectEqual(@as(u32, 0), peer.connection.streams_active);
    // A duplicate RST on the now-closed stream is ignored.
    try testing.expectEqual(@as(?Event, null), peer.feed(&rst));
}

test "h2: ping is acked, unknown frames and priority are skipped" {
    var peer = TestPeer{};
    peer.open();
    var ping: [h2_frame.ping_frame_bytes]u8 = undefined;
    h2_frame.write_ping(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, false, &ping);
    try testing.expectEqual(@as(?Event, null), peer.feed(&ping));
    try peer.expect_output(&.{.ping});
    const ack = (try h2_frame.parse_frame(peer.output[0..peer.produced])).?;
    try testing.expect(ack.header.flags & h2_frame.Flags.ack != 0);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, ack.payload);

    var frame: [64]u8 = undefined;
    h2_frame.write_frame_header(
        .{ .length = 3, .type = @enumFromInt(0xbb), .flags = 0, .stream_id = 0 },
        frame[0..h2_frame.frame_header_bytes],
    );
    @memcpy(frame[h2_frame.frame_header_bytes..][0..3], "abc");
    try testing.expectEqual(@as(?Event, null), peer.feed(frame[0 .. h2_frame.frame_header_bytes + 3]));

    h2_frame.write_frame_header(
        .{ .length = 5, .type = .priority, .flags = 0, .stream_id = 7 },
        frame[0..h2_frame.frame_header_bytes],
    );
    @memcpy(frame[h2_frame.frame_header_bytes..][0..5], &[_]u8{ 0, 0, 0, 3, 16 });
    try testing.expectEqual(@as(?Event, null), peer.feed(frame[0 .. h2_frame.frame_header_bytes + 5]));
}

test "h2: trailers end the stream and must carry END_STREAM" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    _ = peer.feed(frame[0..TestPeer.request_bytes(1, false, &frame)]);

    var block: [64]u8 = undefined;
    const block_used = try hpack.encode_header("x-checksum", "abc123", &block);
    var trailer_len = TestPeer.headers_frame_bytes(1, block[0..block_used], true, true, &frame);
    const event = peer.feed(frame[0..trailer_len]).?;
    try testing.expectEqual(@as(u31, 1), event.trailers.stream_id);
    try testing.expectEqualStrings("x-checksum", event.trailers.headers[0].name);
    try testing.expectEqual(Stream.State.half_closed_remote, peer.connection.streams[0].state);

    // Trailers lacking END_STREAM on another stream: malformed, fatal.
    _ = peer.feed(frame[0..TestPeer.request_bytes(3, false, &frame)]);
    trailer_len = TestPeer.headers_frame_bytes(3, block[0..block_used], false, true, &frame);
    const fatal = peer.feed(frame[0..trailer_len]).?;
    try testing.expectEqual(ErrorCode.protocol_error, fatal.fatal.code);
}

test "h2: push_promise from a client and bad preface are fatal" {
    var peer = TestPeer{};
    peer.open();
    var frame: [64]u8 = undefined;
    h2_frame.write_frame_header(
        .{ .length = 4, .type = .push_promise, .flags = 0, .stream_id = 1 },
        frame[0..h2_frame.frame_header_bytes],
    );
    @memcpy(frame[h2_frame.frame_header_bytes..][0..4], &[_]u8{ 0, 0, 0, 2 });
    const event = peer.feed(frame[0 .. h2_frame.frame_header_bytes + 4]).?;
    try testing.expectEqual(ErrorCode.protocol_error, event.fatal.code);

    var http1 = TestPeer{};
    const fatal = http1.feed("GET / HTTP/1.1\r\nHost: x\r\n\r\n").?;
    try testing.expectEqual(ErrorCode.protocol_error, fatal.fatal.code);
    // After failure the engine swallows input silently.
    try testing.expectEqual(@as(?Event, null), http1.feed("more bytes"));
}

test "h2: goaway from the client surfaces and serving continues" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    _ = peer.feed(frame[0..TestPeer.request_bytes(1, false, &frame)]);

    var goaway: [h2_frame.goaway_frame_bytes]u8 = undefined;
    h2_frame.write_goaway(1, .no_error, &goaway);
    const event = peer.feed(&goaway).?;
    try testing.expectEqual(@as(u31, 1), event.goaway.last_stream_id);
    try testing.expect(peer.connection.goaway_received);
    // The live stream still works.
    const data_len = TestPeer.data_frame_bytes(1, "still here", true, &frame);
    const data = peer.feed(frame[0..data_len]).?;
    try testing.expectEqualStrings("still here", data.data.bytes);
}

test "h2: reset_stream stages RST and frees the slot" {
    var peer = TestPeer{};
    peer.open();
    var frame: [256]u8 = undefined;
    _ = peer.feed(frame[0..TestPeer.request_bytes(1, false, &frame)]);

    var out: [64]u8 = undefined;
    const produced = peer.connection.reset_stream(1, .internal_error, &out);
    const rst = (try h2_frame.parse_frame(out[0..produced])).?;
    try testing.expectEqual(h2_frame.FrameType.rst_stream, rst.header.type);
    try testing.expectEqual(ErrorCode.internal_error, h2_frame.parse_rst_stream(rst.payload[0..4]));
    try testing.expectEqual(@as(u32, 0), peer.connection.streams_active);
}
