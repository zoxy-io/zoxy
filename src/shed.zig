//! The exhaustion ladder's shed actions and static responses (DESIGN.md
//! §8). Un-admitted sheds are synchronous: the socket has no slot, so
//! there is no completion to embed and no ring op to spend — shedding
//! costs at most two direct syscalls and the accept stays armed. Admitted
//! L7 sheds answer with a comptime-rendered response from static memory.

const std = @import("std");

const parser = @import("http/parser.zig");

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
fn staticTemplate(
    comptime status: u16,
    comptime persistence: Persistence,
    comptime cause: ProxyStatusCause,
) Template {
    comptime assert(status >= 400);
    comptime assert(status <= 599);
    const prefix = comptime std.fmt.comptimePrint(
        "HTTP/1.1 {d} {s}\r\nContent-Length: 0\r\nDate: ",
        .{ status, reasonPhrase(status) },
    );
    // RFC 9209's answer to the thing §8 documents having: an origin's own
    // `503` and this proxy's shed `503` are the same three digits and
    // opposite events, and until now only the access log could tell them
    // apart. Written only here, on a page this proxy renders itself — a
    // relayed response keeps whatever the hop before it wrote (§7), so
    // the List reads back as a chain rather than being overwritten.
    const status_line = if (comptime causeToken(cause)) |token|
        "Proxy-Status: " ++ proxy_status_identity ++ "; error=" ++ token ++ "\r\n"
    else
        "";
    const suffix = "\r\n" ++ server_line ++ status_line ++ switch (persistence) {
        .keep => "",
        .close => "Connection: close\r\n",
    } ++ "\r\n";
    return .{
        .bytes = prefix ++ date_placeholder ++ suffix,
        .date_offset = prefix.len,
    };
}

/// What this proxy calls itself in a `Proxy-Status` field (#300). A
/// bare token rather than a hostname: 9209 permits either, and a
/// hostname would put deployment topology on the wire for every client
/// — which is the same reason `next-hop` is deliberately not emitted.
pub const proxy_status_identity = "zoxy";

/// What a refusal is *about*, in the terms RFC 9209 registered (#300).
///
/// Keyed on the rung rather than on the status, because the two are
/// different questions: a filter's `404` and an empty routing table's
/// `404` are the same three digits and opposite causes, and a table
/// indexed by status alone would have to answer one of them wrongly.
/// The rung is comptime at every `respond` call site, so this costs a
/// template rather than a branch.
pub const ProxyStatusCause = enum {
    /// Nothing 9209 says that the status line does not. Not an absence
    /// of information — a decision, argued at `causeToken`.
    none,
    /// No route matched: this gateway does not serve what was named, and
    /// the origin was never asked.
    no_route,
    /// A §7 filter refused on policy — this proxy's rule, not the
    /// origin's answer.
    denied,
    /// Any rung of the §8 ladder: a limit of *this process* was reached.
    limit,
    /// The backend was dialed and did not answer inside the deadline.
    timeout,
};

/// The registered token each cause is named by, or null where the
/// registry has nothing to add.
///
/// The silences are the design. 9209's registry is written for what goes
/// wrong *upstream*, and several of this proxy's rungs are request-side
/// refusals: a `400`, `413`, `414` or `431` has no token but
/// `http_request_error`, which says only "something about the request" —
/// restating the status line in a field nobody can act on. A `502` is
/// left out for the opposite reason: `l7_bad_gateway` answers a refused
/// dial, a reset mid-leg and a malformed origin head at one call site,
/// and 9209 has a distinct token for each, so any single one would be
/// right by accident. So a `Proxy-Status` from zoxy always carries
/// something the status line did not.
fn causeToken(comptime cause: ProxyStatusCause) ?[]const u8 {
    return switch (cause) {
        .none => null,
        // 9209 recommends `500` for this one and this proxy answers
        // `404` — a deliberate deviation recorded in §12: the request
        // named a resource this gateway does not serve, which is the
        // client's answer rather than an internal error.
        .no_route => "destination_not_found",
        .denied => "http_request_denied",
        // Every 503 rung is one fact to a client: zoxy is full, and the
        // origin was never asked. Which pool ran out is the operator's
        // question, and the access log and the counters answer it.
        .limit => "connection_limit_reached",
        .timeout => "http_response_timeout",
    };
}

/// The cause a §8 rung refuses for, named by the rung's own counter —
/// the identity `respond` already carries, so a call site cannot state a
/// cause that disagrees with what it counted.
///
/// The shed ladder matches by prefix on purpose: every rung under it is
/// a limit of this process by construction, so a rung added later is
/// covered the day it is named rather than the day someone remembers
/// this table.
pub fn proxyStatusCauseFor(comptime rung: []const u8) ProxyStatusCause {
    if (std.mem.startsWith(u8, rung, "l7_shed_")) return .limit;
    if (std.mem.eql(u8, rung, "l7_no_route")) return .no_route;
    if (std.mem.eql(u8, rung, "l7_filtered")) return .denied;
    if (std.mem.eql(u8, rung, "l7_gateway_timeout")) return .timeout;
    return .none;
}

/// One `Proxy-Status`-bearing page: a status and the cause it was
/// refused for. A list of the pairs that actually occur rather than a
/// second dimension on the table below — of twelve statuses and four
/// causes, seven pairs are reachable, and the other forty-one would be
/// slots nothing could ever select.
const Variant = struct { status: u16, cause: ProxyStatusCause };

const proxy_status_variants = [_]Variant{
    .{ .status = 404, .cause = .no_route },
    // The §7 filter reject vocabulary (`filter.reject_statuses`), each
    // status carrying the same cause because the rung is the same one.
    .{ .status = 400, .cause = .denied },
    .{ .status = 403, .cause = .denied },
    .{ .status = 404, .cause = .denied },
    .{ .status = 429, .cause = .denied },
    .{ .status = 503, .cause = .limit },
    .{ .status = 504, .cause = .timeout },
};

comptime {
    // Every variant must be a page this table can actually serve, and
    // every one must say something: a variant for `.none` would be a
    // byte-identical copy of the plain page, and a variant for a status
    // outside the static set would be memory nothing selects.
    for (proxy_status_variants) |variant| {
        assert(causeToken(variant.cause) != null);
        assert(staticStatusIndex(variant.status) != null);
    }
    // And the list must be a set: two rows for one pair would render the
    // same page twice and leave `variantIndex` picking arbitrarily.
    for (proxy_status_variants, 0..) |variant, index| {
        for (proxy_status_variants[index + 1 ..]) |other| {
            assert(variant.status != other.status or variant.cause != other.cause);
        }
    }
}

const proxy_status_templates: [proxy_status_variants.len][2]Template = blk: {
    var table: [proxy_status_variants.len][2]Template = undefined;
    for (proxy_status_variants, 0..) |variant, index| {
        table[index] = .{
            staticTemplate(variant.status, .keep, variant.cause),
            staticTemplate(variant.status, .close, variant.cause),
        };
    }
    const frozen = table;
    break :blk frozen;
};

/// Whether a (status, cause) pair has a page to render — the check a
/// caller makes at comptime so that naming a cause the table cannot
/// serve is a compile error rather than a silent fall-back to the plain
/// page, which would look exactly like the opt-in being off.
pub fn hasVariant(comptime status: u16, comptime cause: ProxyStatusCause) bool {
    return variantIndex(status, cause) != null;
}

/// Where one (status, cause) pair sits in the variant table, or null
/// when the pair carries no field. Comptime-only: every caller knows
/// both halves at the `respond` that raised them, so selecting a page
/// costs nothing at runtime.
fn variantIndex(comptime status: u16, comptime cause: ProxyStatusCause) ?usize {
    for (proxy_status_variants, 0..) |variant, index| {
        if (variant.status == status and variant.cause == cause) return index;
    }
    return null;
}

/// The `200` this proxy answers an `OPTIONS` with when it becomes the
/// final recipient — a `Max-Forwards: 0` that stops here (RFC 9110
/// §7.6.2, #240).
///
/// It sits beside the error statuses rather than among them: the closed
/// set above is refusals, and this is the opposite — a request answered
/// on its own terms, by the hop the client asked about. `Allow` is the
/// answer's whole content, since "stop here and describe yourself" is
/// what a zero budget means, and it names this proxy rather than the
/// origin's resource because the origin was deliberately never asked.
fn optionsTemplate(comptime persistence: Persistence) Template {
    const prefix = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n" ++
        "Allow: " ++ parser.allow_value ++ "\r\nDate: ";
    const suffix = "\r\n" ++ server_line ++ switch (persistence) {
        .keep => "",
        .close => "Connection: close\r\n",
    } ++ "\r\n";
    return .{
        .bytes = prefix ++ date_placeholder ++ suffix,
        .date_offset = prefix.len,
    };
}

const options_templates: [2]Template = .{
    optionsTemplate(.keep),
    optionsTemplate(.close),
};

/// The widest static response any status and persistence can render to,
/// which is what one table slot must hold. Comptime, so the table is
/// sized by the responses themselves rather than by a guess that a new
/// status could outgrow (§5).
pub const static_response_bytes_max: u32 = blk: {
    var widest: u32 = 0;
    for (static_statuses) |status| {
        for ([_]Persistence{ .keep, .close }) |persistence| {
            const template = staticTemplate(status, persistence, .none);
            if (template.bytes.len > widest) {
                widest = @intCast(template.bytes.len);
            }
        }
    }
    // The #300 variants share the slot width: a listener's flag chooses
    // between two pages of the same status, so the slot must hold the
    // wider one.
    for (proxy_status_variants) |variant| {
        for ([_]Persistence{ .keep, .close }) |persistence| {
            const template = staticTemplate(variant.status, persistence, variant.cause);
            if (template.bytes.len > widest) {
                widest = @intCast(template.bytes.len);
            }
        }
    }
    // The OPTIONS answer shares the table's slot width, and being the one
    // response carrying an `Allow` it is the one that sets it.
    for (options_templates) |template| {
        if (template.bytes.len > widest) {
            widest = @intCast(template.bytes.len);
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
            const template = staticTemplate(status, persistence, .none);
            assert(template.date_offset + date_bytes <= template.bytes.len);
            assert(template.bytes.len <= static_response_bytes_max);
        }
    }
    for (proxy_status_variants) |variant| {
        for ([_]Persistence{ .keep, .close }) |persistence| {
            const template = staticTemplate(variant.status, persistence, variant.cause);
            assert(template.date_offset + date_bytes <= template.bytes.len);
            assert(template.bytes.len <= static_response_bytes_max);
        }
    }
    assert(static_response_bytes_max > date_bytes);
    // The bound holds the shape it always did, widened by the rows #300
    // adds — seven of the forty-eight (status, cause) pairs are
    // reachable, which is why this is a `+` and not a multiplication.
    assert((static_statuses.len + proxy_status_variants.len) * 2 *
        static_response_bytes_max <= 12 * 1024);
}

const templates: [static_statuses.len][2]Template = blk: {
    var table: [static_statuses.len][2]Template = undefined;
    for (static_statuses, 0..) |status, index| {
        table[index] = .{
            staticTemplate(status, .keep, .none),
            staticTemplate(status, .close, .none),
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
    /// The #240 `OPTIONS` final-recipient answer, in the same writable
    /// memory and under the same `Date` rule. A field of its own because
    /// it is the one static this proxy sends that is not a refusal, so it
    /// has no place in a table keyed by `static_statuses`.
    options: [2][static_response_bytes_max]u8,
    /// The #300 variants: the same pages carrying an RFC 9209 error
    /// token, for the three statuses that have one. Separate storage
    /// rather than a dimension on `storage`, because nine of twelve
    /// statuses would carry a slot nothing could ever select.
    proxy_status_storage: [proxy_status_variants.len][2][static_response_bytes_max]u8,

    pub fn init(table: *StaticTable) void {
        for (&table.storage, 0..) |*variants, index| {
            for (variants, 0..) |*slot, persistence| {
                const template = templates[index][persistence];
                assert(template.bytes.len <= slot.len);
                @memcpy(slot[0..template.bytes.len], template.bytes);
            }
        }
        for (&table.proxy_status_storage, 0..) |*variants, index| {
            for (variants, 0..) |*slot, persistence| {
                const template = proxy_status_templates[index][persistence];
                assert(template.bytes.len <= slot.len);
                @memcpy(slot[0..template.bytes.len], template.bytes);
            }
        }
        for (&table.options, 0..) |*slot, persistence| {
            const template = options_templates[persistence];
            assert(template.bytes.len <= slot.len);
            @memcpy(slot[0..template.bytes.len], template.bytes);
        }
    }

    /// The #240 answer for one persistence choice.
    pub fn getOptions(table: *StaticTable, persistence: Persistence) StaticResponse {
        const template = options_templates[@intFromEnum(persistence)];
        const slot = &table.options[@intFromEnum(persistence)];
        assert(template.date_offset + date_bytes <= template.bytes.len);
        return .{
            .bytes = slot[0..template.bytes.len],
            .date = slot[template.date_offset..][0..date_bytes],
        };
    }

    /// Write `date` into every slot at once — what startup does, so no
    /// response can be the first user of an un-stamped one (#234).
    pub fn stampAll(table: *StaticTable, date: *const [date_bytes]u8) void {
        inline for (static_statuses) |status| {
            for ([_]Persistence{ .keep, .close }) |persistence| {
                @memcpy(table.get(status, .none, persistence, false).date, date);
            }
        }
        // The #300 variants are separate storage, so "every slot" has to
        // name them: a listener that opted in must not send the template
        // date the first time it sheds. Walked through the storage rather
        // than through `get`, because the pairs are the table's own shape
        // and re-deriving them here is a second place to get it wrong.
        for (&table.proxy_status_storage, 0..) |*variants, index| {
            for (variants, 0..) |*slot, persistence| {
                const template = proxy_status_templates[index][persistence];
                assert(template.date_offset + date_bytes <= template.bytes.len);
                @memcpy(slot[template.date_offset..][0..date_bytes], date);
            }
        }
        for ([_]Persistence{ .keep, .close }) |persistence| {
            @memcpy(table.getOptions(persistence).date, date);
        }
    }

    /// The response for one verdict. `status` and `cause` are both
    /// comptime, which the whole path can afford: every caller arrives
    /// through `respond`, whose status and counter are comptime already,
    /// so both lookups fold away and a status outside the closed set is
    /// a compile error rather than a `null` unwrapped at runtime.
    ///
    /// `cause` is the rung that raised it (#300) and `proxy_status` the
    /// listener's opt-in; both are needed, and only their conjunction
    /// selects a variant — a listener that did not ask gets the plain
    /// page, and so does a rung 9209 has no token for. That fall-back
    /// is checkable rather than trusted: `hasVariant` lets the caller
    /// assert at comptime that a named cause has a page, so a rung
    /// cannot lose its token silently.
    pub fn get(
        table: *StaticTable,
        comptime status: u16,
        comptime cause: ProxyStatusCause,
        persistence: Persistence,
        proxy_status: bool,
    ) StaticResponse {
        if (proxy_status) {
            if (comptime variantIndex(status, cause)) |index| {
                const template = proxy_status_templates[index][@intFromEnum(persistence)];
                const slot = &table.proxy_status_storage[index][@intFromEnum(persistence)];
                assert(template.date_offset + date_bytes <= template.bytes.len);
                return .{
                    .bytes = slot[0..template.bytes.len],
                    .date = slot[template.date_offset..][0..date_bytes],
                };
            }
        }
        const index = comptime staticStatusIndex(status).?;
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
pub const static_statuses = [_]u16{ 400, 403, 404, 408, 413, 414, 429, 431, 501, 502, 503, 504 };

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
        408 => "Request Timeout",
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

test "shed: an opted-in listener names the cause it refused for" {
    var table: StaticTable = undefined;
    table.init();
    // The variant is the same page with one field added, in the position
    // 9209 asks for: after `Server`, before the terminator.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n" ++
            "Date: " ++ date_placeholder ++ "\r\nServer: zoxy\r\n" ++
            "Proxy-Status: zoxy; error=connection_limit_reached\r\n" ++
            "Connection: close\r\n\r\n",
        table.get(503, .limit, .close, true).bytes,
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n" ++
            "Date: " ++ date_placeholder ++ "\r\nServer: zoxy\r\n" ++
            "Proxy-Status: zoxy; error=http_response_timeout\r\n\r\n",
        table.get(504, .timeout, .keep, true).bytes,
    );
    // The whole reason the table is keyed on the rung: one status, two
    // causes, two different pages. A `404` from an empty routing table
    // and a `404` a filter chose are indistinguishable by status.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n" ++
            "Date: " ++ date_placeholder ++ "\r\nServer: zoxy\r\n" ++
            "Proxy-Status: zoxy; error=destination_not_found\r\n\r\n",
        table.get(404, .no_route, .keep, true).bytes,
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n" ++
            "Date: " ++ date_placeholder ++ "\r\nServer: zoxy\r\n" ++
            "Proxy-Status: zoxy; error=http_request_denied\r\n\r\n",
        table.get(404, .denied, .keep, true).bytes,
    );
    // A rung with no token ignores the opt-in rather than emitting an
    // empty or a redundant field: a malformed head is the request's own
    // fault and 9209 has nothing to add to the status line.
    try std.testing.expectEqualStrings(
        table.get(413, .none, .close, false).bytes,
        table.get(413, .none, .close, true).bytes,
    );
    // The variants are separate storage, so the stamp has to reach them
    // — a listener that opted in must not send the placeholder date.
    table.stampAll("Sun, 06 Nov 1994 08:49:37 GMT");
    try std.testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        table.get(404, .no_route, .keep, true).date,
    );
    // And that storage is its own: stamping the variant leaves the plain
    // page alone, which is what says one listener cannot patch another's.
    formatHttpDate(0, table.get(404, .no_route, .keep, true).date);
    try std.testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        table.get(404, .none, .keep, false).date,
    );
}

test "shed: every token this proxy emits is one the registry defines" {
    // The set is closed and small, so it is checkable rather than
    // asserted: a token invented here would be a field a client cannot
    // interpret, which is worse than the header being absent.
    const registry = [_][]const u8{
        "destination_not_found",
        "http_request_denied",
        "connection_limit_reached",
        "http_response_timeout",
    };
    var seen: usize = 0;
    inline for (@typeInfo(ProxyStatusCause).@"enum".fields) |field| {
        const cause: ProxyStatusCause = @enumFromInt(field.value);
        const token = comptime causeToken(cause) orelse continue;
        seen += 1;
        var found = false;
        for (registry) |entry| {
            if (std.mem.eql(u8, entry, token)) found = true;
        }
        try std.testing.expect(found);
    }
    try std.testing.expectEqual(registry.len, seen);
    // And every cause a rung can name has a variant to render it, or the
    // opt-in would silently fall back to the plain page on that rung.
    try std.testing.expectEqual(ProxyStatusCause.limit, proxyStatusCauseFor("l7_shed_tunnels"));
    try std.testing.expectEqual(ProxyStatusCause.no_route, proxyStatusCauseFor("l7_no_route"));
    try std.testing.expectEqual(ProxyStatusCause.denied, proxyStatusCauseFor("l7_filtered"));
    try std.testing.expectEqual(ProxyStatusCause.none, proxyStatusCauseFor("l7_bad_gateway"));
}

test "shed: static responses are exact bytes with close announced" {
    var table: StaticTable = undefined;
    table.init();
    // Before any stamp the slot holds the placeholder, which is what
    // makes the offset checkable without a clock.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n" ++
            "Date: " ++ date_placeholder ++ "\r\nServer: zoxy\r\nConnection: close\r\n\r\n",
        table.get(503, .none, .close, false).bytes,
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n" ++
            "Date: " ++ date_placeholder ++ "\r\nServer: zoxy\r\n\r\n",
        table.get(503, .none, .keep, false).bytes,
    );
    // And a stamp lands in the response, not beside it: the slice the
    // send is handed changes under exactly those 29 bytes.
    formatHttpDate(784_111_777, table.get(503, .none, .keep, false).date);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n" ++
            "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\nServer: zoxy\r\n\r\n",
        table.get(503, .none, .keep, false).bytes,
    );
    // Each entry owns its own slot: stamping one leaves the rest alone.
    try std.testing.expectEqualStrings(
        date_placeholder,
        table.get(503, .none, .close, false).date,
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
    var table: StaticTable = undefined;
    table.init();
    // A real date, so the head under test is the one that ships rather
    // than the placeholder's shape.
    inline for (static_statuses) |status| {
        inline for ([_]Persistence{ .keep, .close }) |persistence| {
            formatHttpDate(1_577_836_800, table.get(status, .none, persistence, false).date);
            const bytes = table.get(status, .none, persistence, false).bytes;
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
    // The #240 answer shares the table's memory and the same contract,
    // so it is held to the same round trip — including the `keep`
    // variant, which no directed test spells out byte for byte. It
    // differs in exactly two ways, and both are checked: a `200` rather
    // than a refusal, and an `Allow` that is the whole of what a
    // final-recipient answer has to say.
    inline for ([_]Persistence{ .keep, .close }) |persistence| {
        formatHttpDate(1_577_836_800, table.getOptions(persistence).date);
        const bytes = table.getOptions(persistence).bytes;
        var storage: parser.HeaderStorage = undefined;
        const head = try parser.parseResponseHead(bytes, false, &storage, .options);
        try std.testing.expectEqual(@as(u16, 200), head.status);
        try std.testing.expectEqual(parser.BodyFraming{ .content_length = 0 }, head.framing);
        try std.testing.expectEqual(persistence == .keep, head.keep_alive);
        try std.testing.expectEqual(@as(u32, @intCast(bytes.len)), head.head_len);
        try std.testing.expectEqualStrings(
            parser.allow_value,
            parser.headerValue(head.headers, "allow").?,
        );
    }
}
