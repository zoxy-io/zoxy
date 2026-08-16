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

/// The `Date` every proxy-generated response carries (#234). RFC 9110
/// §6.6.1 makes it a MUST for a server with a clock, and §4 gives this
/// one a wall clock; the responses that most want a timestamp are
/// exactly the ones §8 originates, since a shed `503` under load is what
/// an operator places against an incident timeline.
///
/// IMF-fixdate is fixed-width — always these 29 bytes, whatever the
/// date. That is the whole reason a static response can carry one: the
/// value occupies a *slot* at a comptime-known offset, patched in place,
/// so serving stays one send from memory that is neither assembled nor
/// copied per response (§8).
pub const date_bytes: u32 = 29;

/// What a rendered response holds before its first patch, and the shape
/// every patch writes back. Only ever sent if a response goes out before
/// the clock is ever read, which cannot happen: the arming path stamps
/// the slot it is about to hand to a send. Public because the #159 pages
/// are rendered by the config loader rather than here, and both
/// renderers must leave a slot of exactly one shape.
pub const date_placeholder = "Xxx, 00 Xxx 0000 00:00:00 GMT";

/// The identity this proxy puts on the responses it originates (#234).
/// Forwarded responses carry the origin's own — this names the hop that
/// answered, which is the cheapest tell that a `503` is the ladder's and
/// not the origin's (§8: they are the same three digits and opposite
/// events).
pub const server_line = "Server: zoxy\r\n";

comptime {
    assert(date_placeholder.len == date_bytes);
}

/// One static response's template: the comptime bytes, and where in them
/// the `Date` value sits. Both are properties of the status and the
/// persistence alone, so they are computed once at comptime and the
/// runtime table below only ever holds the mutable copy.
const Template = struct {
    bytes: []const u8,
    date_offset: u32,
};

/// The comptime-rendered static error response (§8), with its `Date`
/// slot still holding the placeholder. Never sent as-is — `StaticTable`
/// copies it into writable memory at startup, and the arming path stamps
/// the slot. The status set is closed in `reasonPhrase`: an unlisted
/// status is a compile error.
fn staticTemplate(comptime status: u16, comptime persistence: Persistence) Template {
    comptime assert(status >= 400);
    comptime assert(status <= 599);
    const prefix = comptime std.fmt.comptimePrint(
        "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\nDate: ",
        .{ status, reasonPhrase(status) },
    );
    const suffix = "\r\n" ++ server_line ++ switch (persistence) {
        .keep => "",
        .close => "Connection: close\r\n",
    } ++ "\r\n";
    return .{
        .bytes = prefix ++ date_placeholder ++ suffix,
        .date_offset = prefix.len,
    };
}

/// The widest static response any status and persistence can render to,
/// which is what one table slot must hold. Comptime, so the table is
/// sized by the responses themselves rather than by a guess that a new
/// status could outgrow (§5).
pub const static_response_bytes_max: u32 = blk: {
    var widest: u32 = 0;
    for (static_statuses) |status| {
        for ([_]Persistence{ .keep, .close }) |persistence| {
            const template = staticTemplate(status, persistence);
            if (template.bytes.len > widest) {
                widest = @intCast(template.bytes.len);
            }
        }
    }
    break :blk widest;
};

comptime {
    // The three numbers the table's memory rests on, related here rather
    // than trusted apart. It lives in this file and not `constants.zig`
    // because nothing may set it: it is *derived* from the responses
    // themselves, so a new status or a longer reason phrase moves it, and
    // a copy in `constants.zig` would be the thing that went stale.
    //
    // Every response must hold its own date slot, and the whole table
    // must stay small enough to be an unremarkable server field — 8 KiB
    // is a head buffer, and this is a closed set of empty responses, so
    // anything near it means a status grew a body it should not have.
    for (static_statuses) |status| {
        for ([_]Persistence{ .keep, .close }) |persistence| {
            const template = staticTemplate(status, persistence);
            assert(template.date_offset + date_bytes <= template.bytes.len);
            assert(template.bytes.len <= static_response_bytes_max);
        }
    }
    assert(static_response_bytes_max > date_bytes);
    assert(static_statuses.len * 2 * static_response_bytes_max <= 8 * 1024);
}

const templates: [static_statuses.len][2]Template = blk: {
    var table: [static_statuses.len][2]Template = undefined;
    for (static_statuses, 0..) |status, index| {
        table[index] = .{
            staticTemplate(status, .keep),
            staticTemplate(status, .close),
        };
    }
    const frozen = table;
    break :blk frozen;
};

/// One static response as the serving path takes it: the bytes to send,
/// and the slot inside them the caller stamps first.
pub const StaticResponse = struct {
    bytes: []const u8,
    date: *[date_bytes]u8,
};

/// The §8 static responses in writable memory — one copy per status and
/// persistence, held by the server rather than as a module global so two
/// servers in one process (every directed test runs two clocks) cannot
/// patch each other's dates.
///
/// This is the change #234 makes to what §8 claims: these responses stop
/// being `const` and gain a written region. What survives is the part
/// that mattered — a shed is still one send, from memory that is neither
/// acquired nor assembled nor copied per response. What is written is 29
/// bytes, at most once per response, and only when the server can prove
/// no submitted send is reading them.
pub const StaticTable = struct {
    storage: [static_statuses.len][2][static_response_bytes_max]u8,

    pub fn init(table: *StaticTable) void {
        for (&table.storage, 0..) |*variants, index| {
            for (variants, 0..) |*slot, persistence| {
                const template = templates[index][persistence];
                assert(template.bytes.len <= slot.len);
                @memcpy(slot[0..template.bytes.len], template.bytes);
            }
        }
    }

    /// Write `date` into every slot at once — what startup does, so no
    /// response can be the first user of an un-stamped one (#234).
    pub fn stampAll(table: *StaticTable, date: *const [date_bytes]u8) void {
        for (static_statuses) |status| {
            for ([_]Persistence{ .keep, .close }) |persistence| {
                @memcpy(table.get(status, persistence).date, date);
            }
        }
    }

    /// The response for one verdict. `status` is a runtime value on the
    /// filter-reject path, so membership is a lookup rather than a
    /// comptime switch — but it is still the closed set, and a status
    /// outside it is a caller that never consulted `isStaticStatus`.
    pub fn get(
        table: *StaticTable,
        status: u16,
        persistence: Persistence,
    ) StaticResponse {
        const index = staticStatusIndex(status).?;
        const template = templates[index][@intFromEnum(persistence)];
        const slot = &table.storage[index][@intFromEnum(persistence)];
        assert(template.date_offset + date_bytes <= template.bytes.len);
        return .{
            .bytes = slot[0..template.bytes.len],
            .date = slot[template.date_offset..][0..date_bytes],
        };
    }
};

/// Where `status` sits in `static_statuses`, or null when it is not one
/// — `pageStatusIndex`'s sibling, for the table above.
pub fn staticStatusIndex(status: u16) ?u8 {
    assert(static_statuses.len <= std.math.maxInt(u8));
    for (static_statuses, 0..) |candidate, index| {
        assert(candidate >= 400);
        if (status == candidate) return @intCast(index);
    }
    return null;
}

/// Render `unix_seconds` as the IMF-fixdate a `Date` header carries (RFC
/// 9110 §5.6.7): `Sun, 06 Nov 1994 08:49:37 GMT`, always exactly
/// `date_bytes` wide. Written field by field rather than through a
/// formatter, because a formatter returns an error this cannot handle —
/// the slot is the exact width, so there is nothing to fall back to, and
/// `catch unreachable` on a reachable error is what Tiger Style forbids.
pub fn formatHttpDate(unix_seconds: u64, out: *[date_bytes]u8) void {
    const weekday_names = [7][3]u8{
        "Sun".*, "Mon".*, "Tue".*, "Wed".*, "Thu".*, "Fri".*, "Sat".*,
    };
    const month_names = [12][3]u8{
        "Jan".*, "Feb".*, "Mar".*, "Apr".*, "May".*, "Jun".*,
        "Jul".*, "Aug".*, "Sep".*, "Oct".*, "Nov".*, "Dec".*,
    };
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = unix_seconds };
    const epoch_day = epoch.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();
    // Four digits is what the slot holds, and the fixed width is the
    // whole premise of patching in place.
    assert(year_day.year <= 9999);
    // 1970-01-01 was a Thursday, and an IMF-fixdate week starts on Sunday.
    const weekday: usize = @intCast((epoch_day.day + 4) % 7);
    @memcpy(out[0..3], &weekday_names[weekday]);
    out[3] = ',';
    out[4] = ' ';
    writeTwoDigits(out[5..7], @as(u32, month_day.day_index) + 1);
    out[7] = ' ';
    @memcpy(out[8..11], &month_names[month_day.month.numeric() - 1]);
    out[11] = ' ';
    writeTwoDigits(out[12..14], year_day.year / 100);
    writeTwoDigits(out[14..16], year_day.year % 100);
    out[16] = ' ';
    writeTwoDigits(out[17..19], day_seconds.getHoursIntoDay());
    out[19] = ':';
    writeTwoDigits(out[20..22], day_seconds.getMinutesIntoHour());
    out[22] = ':';
    writeTwoDigits(out[23..25], day_seconds.getSecondsIntoMinute());
    @memcpy(out[25..29], " GMT");
}

fn writeTwoDigits(out: *[2]u8, value: u32) void {
    assert(value <= 99);
    out[0] = '0' + @as(u8, @intCast(value / 10));
    out[1] = '0' + @as(u8, @intCast(value % 10));
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
    /// Each variant's `Date` slot (#234), inside its own head so the
    /// HEAD prefix carries it too. A mutable view of arena bytes the
    /// page otherwise holds as `const`: the page is immutable in every
    /// respect a reader cares about, and these 29 bytes are the one
    /// region the serving path writes.
    keep_date: *[date_bytes]u8,
    close_date: *[date_bytes]u8,
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
    var table: StaticTable = undefined;
    table.init();
    // Before any stamp the slot holds the placeholder, which is what
    // makes the offset checkable without a clock.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n" ++
            "Date: " ++ date_placeholder ++ "\r\nServer: zoxy\r\nConnection: close\r\n\r\n",
        table.get(503, .close).bytes,
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n" ++
            "Date: " ++ date_placeholder ++ "\r\nServer: zoxy\r\n\r\n",
        table.get(503, .keep).bytes,
    );
    // And a stamp lands in the response, not beside it: the slice the
    // send is handed changes under exactly those 29 bytes.
    formatHttpDate(784_111_777, table.get(503, .keep).date);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n" ++
            "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\nServer: zoxy\r\n\r\n",
        table.get(503, .keep).bytes,
    );
    // Each entry owns its own slot: stamping one leaves the rest alone.
    try std.testing.expectEqualStrings(
        date_placeholder,
        table.get(503, .close).date,
    );
}

test "shed: IMF-fixdate is fixed-width and matches the RFC's own example" {
    const Case = struct { seconds: u64, want: []const u8 };
    for ([_]Case{
        // RFC 9110 §5.6.7's example, and the two epochs the tests use.
        .{ .seconds = 784_111_777, .want = "Sun, 06 Nov 1994 08:49:37 GMT" },
        .{ .seconds = 0, .want = "Thu, 01 Jan 1970 00:00:00 GMT" },
        .{ .seconds = 1_577_836_800, .want = "Wed, 01 Jan 2020 00:00:00 GMT" },
        // A leap day, and the last second before one.
        .{ .seconds = 1_582_934_400, .want = "Sat, 29 Feb 2020 00:00:00 GMT" },
        .{ .seconds = 1_582_934_399, .want = "Fri, 28 Feb 2020 23:59:59 GMT" },
        // Every field at its widest.
        .{ .seconds = 4_102_444_799, .want = "Thu, 31 Dec 2099 23:59:59 GMT" },
    }) |case| {
        var out: [date_bytes]u8 = undefined;
        formatHttpDate(case.seconds, &out);
        try std.testing.expectEqualStrings(case.want, &out);
    }
}

test "fuzz: every renderable second formats to a well-formed fixdate" {
    try std.testing.fuzz({}, fuzzHttpDate, .{ .corpus = &.{ "\x00", "\xff\xff\xff\xff" } });
}

fn fuzzHttpDate(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    // Bounded to the four-digit years the slot can hold: 253402300800 is
    // 10000-01-01, the first second `formatHttpDate` refuses.
    const seconds = smith.valueRangeLessThan(u64, 0, 253_402_300_800);
    var out: [date_bytes]u8 = undefined;
    formatHttpDate(seconds, &out);
    // Shape alone, checked against the fixed grammar: every separator in
    // its place, every digit a digit. The values are the table above's.
    assert(out[3] == ',');
    assert(out[4] == ' ');
    assert(out[7] == ' ');
    assert(out[11] == ' ');
    assert(out[16] == ' ');
    assert(out[19] == ':');
    assert(out[22] == ':');
    assert(std.mem.eql(u8, out[25..29], " GMT"));
    for ([_]usize{ 5, 6, 12, 13, 14, 15, 17, 18, 20, 21, 23, 24 }) |index| {
        assert(std.ascii.isDigit(out[index]));
    }
    for ([_]usize{ 0, 1, 2, 8, 9, 10 }) |index| {
        assert(std.ascii.isAlphabetic(out[index]));
    }
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
    var table: StaticTable = undefined;
    table.init();
    // A real date, so the head under test is the one that ships rather
    // than the placeholder's shape.
    inline for (static_statuses) |status| {
        inline for ([_]Persistence{ .keep, .close }) |persistence| {
            formatHttpDate(1_577_836_800, table.get(status, persistence).date);
            const bytes = table.get(status, persistence).bytes;
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
