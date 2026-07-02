//! Incremental decoder for the HTTP/1.1 chunked transfer coding (RFC 9112
//! §7.1). It transforms nothing — the proxy relays the wire bytes verbatim —
//! it only finds where the message *ends*: `feed` consumes up to and
//! including the final CRLF of the trailer section and stops there, so bytes
//! past the end (the next message on the connection) are never swallowed.
//! Fixed state, no allocation; every dimension is bounded (TigerStyle).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const ChunkedDecoder = struct {
    state: State = .chunk_size,
    /// Unconsumed data bytes of the current chunk (valid in `.chunk_data`).
    remaining: u64 = 0,
    size_digits: u8 = 0,
    extension_bytes: u32 = 0,
    trailer_bytes: u32 = 0,

    pub const State = enum {
        chunk_size,
        chunk_extension,
        chunk_size_lf,
        chunk_data,
        chunk_data_cr,
        chunk_data_lf,
        trailer_start,
        trailer_line,
        trailer_line_lf,
        final_lf,
        done,
    };

    pub fn done(decoder: *const ChunkedDecoder) bool {
        return decoder.state == .done;
    }

    /// Feed wire bytes; returns how many were consumed. Consumption stops at
    /// the end of the chunked message — call `done` to distinguish "message
    /// complete" from "need more input".
    pub fn feed(decoder: *ChunkedDecoder, bytes: []const u8) error{Malformed}!usize {
        var consumed: usize = 0;
        // Bounded: every step consumes >= 1 byte or the state is `.done`.
        while (consumed < bytes.len and decoder.state != .done) {
            consumed += try decoder.step(bytes[consumed..]);
        }
        assert(consumed <= bytes.len);
        return consumed;
    }

    fn step(decoder: *ChunkedDecoder, bytes: []const u8) error{Malformed}!usize {
        assert(bytes.len > 0);
        assert(decoder.state != .done);
        const c = bytes[0];
        switch (decoder.state) {
            .chunk_size => return decoder.stepChunkSize(c),
            .chunk_extension => {
                if (c == '\r') {
                    decoder.state = .chunk_size_lf;
                    return 1;
                }
                decoder.extension_bytes += 1;
                if (decoder.extension_bytes > constants.chunk_extension_bytes_max) {
                    return error.Malformed;
                }
                return 1;
            },
            .chunk_size_lf => {
                if (c != '\n') return error.Malformed;
                decoder.state = if (decoder.remaining == 0) .trailer_start else .chunk_data;
                decoder.size_digits = 0;
                decoder.extension_bytes = 0;
                return 1;
            },
            .chunk_data => {
                assert(decoder.remaining > 0); // zero-size chunks go to the trailer
                const n: usize = @intCast(@min(decoder.remaining, bytes.len));
                assert(n > 0);
                decoder.remaining -= n;
                if (decoder.remaining == 0) decoder.state = .chunk_data_cr;
                return n;
            },
            .chunk_data_cr => {
                if (c != '\r') return error.Malformed;
                decoder.state = .chunk_data_lf;
                return 1;
            },
            .chunk_data_lf => {
                if (c != '\n') return error.Malformed;
                decoder.state = .chunk_size;
                return 1;
            },
            .trailer_start => {
                if (c == '\r') {
                    decoder.state = .final_lf;
                    return 1;
                }
                decoder.state = .trailer_line;
                try decoder.countTrailerByte();
                return 1;
            },
            .trailer_line => {
                if (c == '\r') {
                    decoder.state = .trailer_line_lf;
                    return 1;
                }
                try decoder.countTrailerByte();
                return 1;
            },
            .trailer_line_lf => {
                if (c != '\n') return error.Malformed;
                decoder.state = .trailer_start;
                return 1;
            },
            .final_lf => {
                if (c != '\n') return error.Malformed;
                decoder.state = .done;
                return 1;
            },
            .done => unreachable, // the feed loop stops on .done (asserted above)
        }
    }

    fn stepChunkSize(decoder: *ChunkedDecoder, c: u8) error{Malformed}!usize {
        if (hexDigit(c)) |digit| {
            if (decoder.size_digits == constants.chunk_size_digits_max) return error.Malformed;
            decoder.remaining = decoder.remaining * 16 + digit;
            decoder.size_digits += 1;
            return 1;
        }
        if (decoder.size_digits == 0) return error.Malformed; // a size needs >= 1 digit
        assert(decoder.size_digits <= constants.chunk_size_digits_max);
        if (c == ';') {
            decoder.state = .chunk_extension;
            return 1;
        }
        if (c == '\r') {
            decoder.state = .chunk_size_lf;
            return 1;
        }
        return error.Malformed;
    }

    fn countTrailerByte(decoder: *ChunkedDecoder) error{Malformed}!void {
        decoder.trailer_bytes += 1;
        if (decoder.trailer_bytes > constants.trailer_bytes_max) return error.Malformed;
    }
};

fn hexDigit(c: u8) ?u64 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// ---- tests ----------------------------------------------------------------

test "chunked: decodes a message and stops exactly at its end" {
    var decoder = ChunkedDecoder{};
    const wire = "5\r\nHELLO\r\n3\r\nabc\r\n0\r\n\r\nNEXT-MESSAGE";
    const consumed = try decoder.feed(wire);
    try std.testing.expect(decoder.done());
    try std.testing.expectEqualStrings("NEXT-MESSAGE", wire[consumed..]);
}

test "chunked: handles extensions and trailers" {
    var decoder = ChunkedDecoder{};
    const wire = "4;name=value\r\nBODY\r\n0\r\nX-Trailer: yes\r\nY: 2\r\n\r\n";
    const consumed = try decoder.feed(wire);
    try std.testing.expect(decoder.done());
    try std.testing.expectEqual(wire.len, consumed);
}

test "chunked: survives byte-at-a-time delivery" {
    var decoder = ChunkedDecoder{};
    const wire = "a\r\n0123456789\r\n0\r\n\r\n";
    var consumed: usize = 0;
    for (wire) |byte| {
        consumed += try decoder.feed(&[_]u8{byte});
    }
    try std.testing.expect(decoder.done());
    try std.testing.expectEqual(wire.len, consumed);
}

test "chunked: rejects malformed input" {
    // No size digits.
    var no_digits = ChunkedDecoder{};
    try std.testing.expectError(error.Malformed, no_digits.feed("\r\n"));
    // Bad byte inside the size line.
    var bad_size = ChunkedDecoder{};
    try std.testing.expectError(error.Malformed, bad_size.feed("5x\r\n"));
    // Missing CRLF after the chunk data.
    var bad_end = ChunkedDecoder{};
    try std.testing.expectError(error.Malformed, bad_end.feed("3\r\nabcX"));
    // A size wider than u64 (17 hex digits).
    var overflow = ChunkedDecoder{};
    try std.testing.expectError(error.Malformed, overflow.feed("11111111111111111\r\n"));
}
