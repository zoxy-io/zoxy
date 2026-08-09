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

/// The closed set of statuses the ladder (§8) and the L7 state machine
/// (§7) send as static responses — the statuses `error_pages` may
/// configure a body for (#159): a page for a status this proxy never
/// sends is a config the operator misread, refused at load.
pub const static_statuses = [_]u16{ 400, 403, 404, 413, 414, 429, 431, 501, 502, 503, 504 };

/// Every status a configured page may carry (#159): the error set
/// above, plus `200` — which no rung raises, but a `respond` filter
/// action does, this proxy answering as the origin for a `robots.txt`
/// or a health target. Closed and small on purpose: growing a closed
/// vocabulary is cheap, shrinking a documented one is not.
pub const page_statuses = [_]u16{200} ++ static_statuses;

/// One pre-rendered page (#159): both persistence variants of a
/// complete response — status line, framing, content type, body — each
/// in one contiguous arena buffer, with the head's length recorded so a
/// HEAD request sends the prefix of that same buffer. Rendered at load
/// and immutable after, so serving one is the comptime-static path
/// unchanged: one send, no assembly, no acquisition.
///
/// It lives here rather than in `config.zig` because both sides of the
/// serving path need to name the type and neither may import the
/// other: the config builds these, and `http/filter.zig` carries one
/// per `respond` action.
pub const StaticPage = struct {
    status: u16,
    keep: []const u8,
    close: []const u8,
    keep_head_len: u32,
    close_head_len: u32,
};

/// Whether `error_pages` may carry this status (#159) — membership in
/// the closed set above, the loader's half of the contract
/// `reasonPhrase` enforces at comptime for the built-in statics.
pub fn isStaticStatus(status: u16) bool {
    for (static_statuses) |candidate| {
        assert(candidate >= 400); // The set is error statuses only.
        assert(candidate <= 599);
        if (status == candidate) return true;
    }
    return false;
}

/// Whether a configured page may carry this status (#159) —
/// `isStaticStatus` widened by the statuses only a `respond` action
/// reaches. The index into `page_statuses` doubles as a body's
/// render-cache slot at load, which is why membership and position are
/// one question, answered by `pageStatusIndex` below.
pub fn isPageStatus(status: u16) bool {
    return pageStatusIndex(status) != null;
}

/// Where `status` sits in `page_statuses`, or null when it is not one.
pub fn pageStatusIndex(status: u16) ?u8 {
    assert(page_statuses.len <= std.math.maxInt(u8));
    for (page_statuses, 0..) |candidate, index| {
        assert(candidate >= 100);
        if (status == candidate) return @intCast(index);
    }
    return null;
}

/// Reason phrases for the closed static-status set. Callable at runtime
/// (#159: a configured page's status is the config's, rendered at load)
/// and in comptime context by `staticResponse`, where an unlisted
/// status is still a compile error via the `unreachable`; at runtime
/// the loader's `isStaticStatus` gate is what keeps it unreachable.
pub fn reasonPhrase(status: u16) []const u8 {
    assert(status >= 100);
    assert(status <= 599);
    return switch (status) {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Content Too Large",
        414 => "URI Too Long",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        else => unreachable,
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

test "shed: the status set is one set, comptime and runtime" {
    // `static_statuses` is what the loader accepts a page for and
    // `staticResponse` compiles a default for; a member the phrase
    // switch does not list would make one half of the contract silent.
    for (static_statuses) |status| {
        try std.testing.expect(isStaticStatus(status));
        try std.testing.expect(isPageStatus(status)); // the wider set contains it
        try std.testing.expect(reasonPhrase(status).len >= 1);
    }
    try std.testing.expect(!isStaticStatus(200));
    try std.testing.expect(!isStaticStatus(301));
    try std.testing.expect(!isStaticStatus(500));

    // 200 is the one status a page may carry that no rung raises: an
    // `error_pages` entry for it is refused, a `respond` action's is
    // exactly the point (#159).
    try std.testing.expect(isPageStatus(200));
    try std.testing.expectEqualStrings("OK", reasonPhrase(200));
    try std.testing.expect(!isPageStatus(301));
    try std.testing.expectEqual(@as(usize, static_statuses.len + 1), page_statuses.len);
    // Position is identity for the load-time render cache: every page
    // status must have one slot, and no two may share it.
    for (page_statuses, 0..) |status, index| {
        try std.testing.expectEqual(@as(?u8, @intCast(index)), pageStatusIndex(status));
    }
    try std.testing.expectEqual(@as(?u8, null), pageStatusIndex(301));
}

test "shed: every static response parses as a valid bodiless head" {
    // Round-trip through zoxy's own parser: each response must be a
    // complete, correctly framed head whose persistence matches the
    // requested one — the same verdict a strict client would reach.
    const parser = @import("http/parser.zig");
    inline for (static_statuses) |status| {
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
