//! The exhaustion ladder's shed actions and static responses (DESIGN.md
//! §8). Un-admitted sheds are synchronous: the socket has no slot, so
//! there is no completion to embed and no ring op to spend — shedding
//! costs at most two direct syscalls and the accept stays armed. Admitted
//! L7 sheds answer with a comptime-rendered response from static memory.

const std = @import("std");

const assert = std.debug.assert;

/// Whether the downstream connection survives a static response. `close`
/// announces it in the response (§7: clients that pipeline into an
/// unannounced close read errors); `keep` leaves the connection serving.
pub const Persistence = enum {
    keep,
    close,
};

/// A comptime-rendered static error response (§8): sent directly from
/// static memory, never staged through the connection's head buffer —
/// whose bytes the parsed head's zero-copy slices may still reference.
/// Shedding costs one send, no allocation, no copy. The status set is
/// closed in `reasonPhrase`: an unlisted status is a compile error.
pub fn staticResponse(comptime status: u16, comptime persistence: Persistence) []const u8 {
    comptime assert(status >= 400);
    comptime assert(status <= 599);
    const bytes = comptime std.fmt.comptimePrint(
        "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\n{s}\r\n",
        .{
            status,
            reasonPhrase(status),
            switch (persistence) {
                .keep => "",
                .close => "Connection: close\r\n",
            },
        },
    );
    return bytes;
}

/// Reason phrases for the closed set of statuses the ladder (§8) and the
/// L7 state machine (§7) send.
fn reasonPhrase(comptime status: u16) []const u8 {
    comptime assert(status >= 400);
    comptime assert(status <= 599);
    return switch (status) {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        414 => "URI Too Long",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        else => @compileError("unlisted static-response status"),
    };
}

/// Conn-slots-exhausted rung: close immediately with SO_LINGER-0 so the
/// client gets an RST — an immediate signal instead of a timeout, and
/// the kernel backlog stays drained (§8).
pub fn closeWithRst(comptime IoType: type, io: *IoType, socket: IoType.Socket) void {
    // If the option fails the close must still happen: shedding never
    // blocks and never errors (§8); the peer then sees FIN, not RST.
    io.setLingerRst(socket) catch {};
    io.closeNow(socket);
}

/// Relay-buffers-exhausted rung: plain immediate close (§8 table).
pub fn closeQuietly(comptime IoType: type, io: *IoType, socket: IoType.Socket) void {
    io.closeNow(socket);
}

test "shed: static responses are exact bytes with close announced" {
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        staticResponse(503, .close),
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
        staticResponse(503, .keep),
    );
}

test "shed: every static response parses as a valid bodiless head" {
    // Round-trip through zoxy's own parser: each response must be a
    // complete, correctly framed head whose persistence matches the
    // requested one — the same verdict a strict client would reach.
    const parser = @import("http/parser.zig");
    inline for ([_]u16{ 400, 403, 404, 414, 429, 431, 501, 502, 503, 504 }) |status| {
        inline for ([_]Persistence{ .keep, .close }) |persistence| {
            const bytes = staticResponse(status, persistence);
            var storage: parser.HeaderStorage = undefined;
            const head = try parser.parseResponseHead(bytes, false, &storage, .get);
            try std.testing.expectEqual(status, head.status);
            try std.testing.expectEqual(
                parser.BodyFraming{ .content_length = 0 },
                head.framing,
            );
            try std.testing.expectEqual(persistence == .keep, head.keep_alive);
            try std.testing.expectEqual(@as(u32, @intCast(bytes.len)), head.head_len);
        }
    }
}
