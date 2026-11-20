//! A build's own policy answers (#431): every page its request policies
//! declare, rendered at startup in the four variants a static answer is
//! sent in — kept or closed, with the listener's `Proxy-Status` or
//! without — and priced in the banner.
//!
//! Every byte of a page is known at compile time but its `Date`, so each
//! variant is a comptime template copied once into the startup arena,
//! where the serving path stamps the slot (#234) exactly as it stamps
//! zoxy's own pages. A build whose policies declare no answers, the stock
//! binary among them, has no table and prices nothing for it.

const std = @import("std");

const constants = @import("constants.zig");
const extension = @import("extension.zig");
const parser = @import("http/parser.zig");
const shed = @import("shed.zig");

const assert = std.debug.assert;

const StaticPage = shed.StaticPage;

pub fn Table(comptime extensions: extension.Extensions) type {
    const policies = extensions.request_policies;
    return struct {
        const Self = @This();

        /// Every answer the build's policies declare, in list order.
        pub const count: u32 = blk: {
            var total: u32 = 0;
            for (policies) |Policy| total += extension.answerCount(Policy);
            break :blk total;
        };
        pub const enabled = count >= 1;

        /// The longest head any page carries — a closed, refusing variant
        /// — which an HTTP/2 stream maps through scratch sized by
        /// `head_buffer_bytes`: startup refuses a config whose head buffer
        /// is smaller.
        pub const head_bytes_max: u32 = blk: {
            @setEvalBranchQuota(1000 + 8 * @as(u64, count) * (constants.extension_answer_headers_max *
                constants.extension_answer_header_bytes_max + constants.extension_answer_body_bytes_max));
            var widest: u32 = 0;
            for (policies) |Policy| {
                if (!extension.hasAnswers(Policy)) continue;
                for (@typeInfo(@TypeOf(Policy.answers)).@"struct".field_names) |name| {
                    const answer = @field(Policy.answers, name);
                    const head = template(answer, .close, true).len - answer.body.len;
                    widest = @max(widest, head);
                }
            }
            break :blk widest;
        };

        /// How many answers the policy type listed at `policy_index`
        /// declares: what a `respond` verdict's index is held below.
        pub fn countOf(policy_index: u8) u16 {
            // A build that lists no policy evaluates none.
            if (comptime policies.len == 0) unreachable;
            assert(policy_index < policies.len);
            return counts[policy_index];
        }

        /// How many answers each policy type declares.
        const counts: [policies.len]u16 = blk: {
            var collected: [policies.len]u16 = undefined;
            for (policies, &collected) |Policy, *answers| answers.* = extension.answerCount(Policy);
            break :blk collected;
        };

        /// Where each policy type's answers start in `pages`.
        const offsets: [policies.len]u32 = blk: {
            var collected: [policies.len]u32 = undefined;
            var next: u32 = 0;
            for (policies, &collected) |Policy, *offset| {
                offset.* = next;
                next += extension.answerCount(Policy);
            }
            assert(next == count);
            break :blk collected;
        };

        /// One answer's pages: without the listener's `Proxy-Status` and
        /// with it, each kept or closed.
        pub const Pages = struct {
            plain: StaticPage,
            denied: StaticPage,
        };

        /// What `init` takes from the startup arena: the table, and every
        /// variant's bytes — what it asks for, as `Labeled`'s terms are; an
        /// arena's alignment padding is not priced.
        pub const bytes: u64 = blk: {
            @setEvalBranchQuota(1000 + 8 * @as(u64, count) * (constants.extension_answer_headers_max *
                constants.extension_answer_header_bytes_max + constants.extension_answer_body_bytes_max));
            var total: u64 = @as(u64, count) * @sizeOf(Pages);
            for (policies) |Policy| {
                if (!extension.hasAnswers(Policy)) continue;
                for (@typeInfo(@TypeOf(Policy.answers)).@"struct".field_names) |name| {
                    const answer = @field(Policy.answers, name);
                    for ([_]bool{ false, true }) |denied| {
                        total += template(answer, .keep, denied).len + template(answer, .close, denied).len;
                    }
                }
            }
            break :blk total;
        };

        pages: []Pages = &.{},

        pub fn init(table: *Self, arena: std.mem.Allocator) error{OutOfMemory}!void {
            table.* = .{};
            if (!enabled) return;
            table.pages = try arena.alloc(Pages, count);
            inline for (policies, 0..) |Policy, policy_index| {
                if (comptime extension.hasAnswers(Policy)) {
                    const names = @typeInfo(@TypeOf(Policy.answers)).@"struct".field_names;
                    inline for (names, 0..) |name, answer_index| {
                        const answer = comptime @field(Policy.answers, name);
                        table.pages[offsets[policy_index] + answer_index] = .{
                            .plain = try page(arena, answer, false),
                            .denied = try page(arena, answer, true),
                        };
                    }
                }
            }
        }

        /// The page answer `answer_index` of the policy type listed at
        /// `policy_index`, in the variant the listener asked for.
        pub fn get(table: *const Self, policy_index: u8, answer_index: u16, proxy_status: bool) *const StaticPage {
            // A build with no answers is never asked for one.
            if (comptime !enabled) unreachable;
            assert(policy_index < policies.len);
            assert(answer_index < counts[policy_index]);
            const index = offsets[policy_index] + answer_index;
            assert(index < table.pages.len);
            const pages = &table.pages[index];
            return if (proxy_status) &pages.denied else &pages.plain;
        }
    };
}

/// One answer's page in both persistence variants, copied from its
/// comptime templates into writable arena bytes.
fn page(arena: std.mem.Allocator, comptime answer: extension.Answer, comptime denied: bool) error{OutOfMemory}!StaticPage {
    const keep = try arena.dupe(u8, comptime template(answer, .keep, denied));
    const close = try arena.dupe(u8, comptime template(answer, .close, denied));
    const offset = comptime dateOffset(answer);
    assert(offset + shed.date_bytes <= keep.len - answer.body.len);
    assert(offset + shed.date_bytes <= close.len - answer.body.len);
    return .{
        .status = answer.status,
        .keep = keep,
        .close = close,
        .keep_head_len = @intCast(keep.len - answer.body.len),
        .close_head_len = @intCast(close.len - answer.body.len),
        .keep_date = keep[offset..][0..shed.date_bytes],
        .close_date = close[offset..][0..shed.date_bytes],
    };
}

/// The status line, framing, content type and the `Date` field's name:
/// everything before the slot, the same in every variant.
fn prefix(comptime answer: extension.Answer) []const u8 {
    const status: std.http.Status = @fromBackingInt(answer.status);
    const typed = if (answer.body.len == 0) "" else "Content-Type: " ++ answer.content_type ++ "\r\n";
    return std.fmt.comptimePrint(
        "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\n",
        .{ answer.status, status.phrase() orelse "", answer.body.len },
    ) ++ typed ++ "Date: ";
}

/// Where a page's `Date` slot starts: past `prefix`, which every variant
/// shares, so one offset serves all four.
fn dateOffset(comptime answer: extension.Answer) usize {
    return prefix(answer).len;
}

/// A whole page: the declared headers follow zoxy's own, then the
/// `Proxy-Status` a refusal carries where the listener sends it, then
/// the persistence the answer announces, then the body.
fn template(comptime answer: extension.Answer, comptime persistence: shed.Persistence, comptime denied: bool) []const u8 {
    comptime {
        var declared: []const u8 = "";
        for (answer.headers) |header| declared = declared ++ header.name ++ ": " ++ header.value ++ "\r\n";
        const status_line = if (denied) shed.proxyStatusLine(.denied) else "";
        const persistence_line = switch (persistence) {
            .keep => "",
            .close => "Connection: close\r\n",
        };
        return prefix(answer) ++ shed.date_placeholder ++ "\r\n" ++ shed.server_line ++ declared ++
            status_line ++ persistence_line ++ "\r\n" ++ answer.body;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const Gate = struct {
    pub const answers = .{
        .login = extension.Answer{
            .status = 302,
            .headers = &.{.{ .name = "Location", .value = "/login" }},
        },
        .maintenance = extension.Answer{
            .status = 503,
            .headers = &.{.{ .name = "Retry-After", .value = "120" }},
            .body = "back soon\n",
        },
    };

    pub fn evaluate(_: *Gate, _: *const extension.Request) extension.Verdict {
        return .proceed;
    }
};

/// Statuses without a `Location`, and one with no registered phrase.
const Edge = struct {
    pub const answers = .{
        .not_modified = extension.Answer{ .status = 304 },
        .closed_request = extension.Answer{
            .status = 499,
            .headers = &.{.{ .name = "Cache-Control", .value = "no-store" }},
            .body = "{}",
            .content_type = "application/json",
        },
    };

    pub fn evaluate(_: *Edge, _: *const extension.Request) extension.Verdict {
        return .proceed;
    }
};

const Quiet = struct {
    pub fn evaluate(_: *Quiet, _: *const extension.Request) extension.Verdict {
        return .proceed;
    }
};

test "extension answers: every variant is rendered, priced exactly, its Date a slot in the head (#431)" {
    const T = Table(.{ .request_policies = &.{ Quiet, Gate } });
    comptime assert(T.count == 2);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var counting = std.testing.FailingAllocator.init(arena_state.allocator(), .{});
    var table: T = undefined;
    try table.init(counting.allocator());
    try testing.expectEqual(T.bytes, counting.allocated_bytes);

    const maintenance = table.get(1, 1, false);
    try testing.expectEqual(@as(u16, 503), maintenance.status);
    try testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 10\r\n" ++
            "Content-Type: text/plain; charset=utf-8\r\nDate: " ++ shed.date_placeholder ++ "\r\n" ++
            "Server: zoxy\r\nRetry-After: 120\r\nConnection: close\r\n\r\nback soon\n",
        maintenance.close,
    );
    try testing.expectEqualStrings("back soon\n", maintenance.keep[maintenance.keep_head_len..]);
    try testing.expectEqualStrings(shed.date_placeholder, maintenance.keep_date);

    // A redirect without a body names no type; the refusal variant says so.
    const login = table.get(1, 0, true);
    try testing.expectEqualStrings(
        "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nDate: " ++ shed.date_placeholder ++ "\r\n" ++
            "Server: zoxy\r\nLocation: /login\r\nProxy-Status: zoxy; error=http_request_denied\r\n\r\n",
        login.keep,
    );
    try testing.expectEqual(@as(u32, @intCast(login.keep.len)), login.keep_head_len);
}

test "extension answers: a build whose policies declare none has no table (#431)" {
    const T = Table(.{ .request_policies = &.{Quiet} });
    comptime assert(!T.enabled);
    comptime assert(T.bytes == 0);
    var table: T = undefined;
    try table.init(testing.failing_allocator);
    try testing.expectEqual(@as(usize, 0), table.pages.len);
}

test "extension answers: every page parses back as the response it renders (#431)" {
    const extensions: extension.Extensions = .{ .request_policies = &.{ Gate, Edge } };
    comptime extension.assertExtensions(extensions);
    const T = Table(extensions);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var table: T = undefined;
    try table.init(arena_state.allocator());
    var storage: parser.HeaderStorage = undefined;
    for (table.pages) |*pages| {
        for ([_]*const StaticPage{ &pages.plain, &pages.denied }) |rendered| {
            for ([_][]const u8{ rendered.keep, rendered.close }) |bytes| {
                const head = try parser.parseResponseHead(bytes, true, &storage, .get);
                try testing.expectEqual(rendered.status, head.status);
                try testing.expect(head.headers.len >= 2);
            }
        }
    }
    // An unregistered status keeps its empty reason phrase, and parses.
    const unregistered = table.get(1, 1, false);
    try testing.expect(std.mem.startsWith(u8, unregistered.keep, "HTTP/1.1 499 \r\n"));
    try testing.expectEqualStrings("{}", unregistered.keep[unregistered.keep_head_len..]);
}
