//! The access log (DESIGN.md §8): one JSON object per line — an HTTP
//! exchange or an L4 connection — written to the configured sink through
//! the seam's one ring op. Off unless a config `access_log` block names a
//! sink, and then it reserves exactly two staging buffers and one ring
//! entry, both closed-form in `constants.zig` like every other budget.
//!
//! **A log line never blocks the loop, and never queues without bound.**
//! Those two rules are the whole design. The sink is a pipe the operator
//! owns, so it can stall for arbitrarily long, and a proxy that waits for
//! it would hand every client's latency to whatever is reading its logs.
//! So the write is a ring op with at most one in flight, lines accumulate
//! in the *other* buffer while it is out, the buffers swap when it lands,
//! and a line that does not fit is dropped and counted. That is §8's
//! ladder applied to logging: exhaustion sheds the newest work at a
//! well-defined point with a well-defined answer, and `access_log_dropped`
//! is the witness. Losing a log line is the correct trade against stalling
//! a data path; the counter is what keeps it from being a silent one.
//!
//! Flushing is self-clocked rather than timer-driven: a record with no
//! write in flight starts one immediately, so a quiet proxy's line reaches
//! the sink at once, and a busy one batches everything that arrived during
//! the previous write into the next. No tick hook, no flush timer, and no
//! line that can sit in a buffer waiting for company.
//!
//! `Record` and `renderLine` sit at file scope, outside the Io-generic
//! part: the wire format is what an operator's tooling parses, so it is
//! testable without standing up a backend.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const Io = @import("io/io.zig");

const assert = std.debug.assert;

/// What a line describes. The two data paths answer different questions —
/// an HTTP line is about one request, an L4 line about one connection —
/// so `kind` is what tells a consumer which fields to expect.
pub const Kind = enum(u1) {
    http,
    l4,
};

/// How the thing being logged ended. Deliberately not derivable from
/// `status`: an origin's own `503` and zoxy's shed `503` are the same
/// three digits and opposite events, and telling them apart is most of
/// what an operator reads an access log for.
pub const Outcome = enum(u8) {
    /// The origin answered and its whole response reached the client. The
    /// status is the origin's, whatever it is.
    ok,
    /// zoxy refused the request itself (§7): malformed, oversize,
    /// unroutable, unsupported, or stopped by a filter rule.
    rejected,
    /// zoxy ran out of a resource and answered `503` (§8) — a relay buffer
    /// or an upstream slot the request needed.
    shed,
    /// The exchange outlived `timeouts.request_ms` and was answered `504`
    /// (§8).
    timed_out,
    /// The upstream leg failed before any response byte and was answered
    /// `502` (§7, §8) — a refused dial, a dead origin, an unparseable
    /// response head.
    upstream_failed,
    /// No complete answer reached the client: the connection was torn
    /// down mid-request or mid-response. The client left, the deadline
    /// fired (possibly with a response already in flight, in which case
    /// the origin's status is still recorded), or a drain reaped a
    /// straggler. The default outcome, so any teardown path that skips
    /// setting a more specific one lands here too.
    aborted,
    /// L4 only: both directions drained and the connection closed cleanly.
    closed,
};

/// One line's worth of facts. Sliced fields alias the caller's storage and
/// are read out entirely by `renderLine` before it returns, so a caller may
/// point them at a connection slot it is about to release.
///
/// Past 16 bytes several times over, so it travels by `*const` (TIGER_STYLE)
/// — and because a record is built in one place and read in another, a
/// stack copy would be pure cost.
pub const Record = struct {
    kind: Kind,
    outcome: Outcome,
    /// Wall-clock nanoseconds at which the request — or, for L4, the
    /// connection — *started*. The start rather than the completion: a
    /// slow request and a fast one that began at the same moment belong
    /// next to each other when an operator is reconstructing an incident,
    /// and `duration_us` already says where each one ended.
    started_wall_ns: u64,
    duration_ns: u64,
    client: std.Io.net.IpAddress,
    /// The endpoint this request or connection was served by, or null when
    /// none was ever picked — every reject that fires before routing.
    upstream: ?std.Io.net.IpAddress,
    /// The cluster's configured name, empty when routing never chose one.
    cluster: []const u8,
    /// Bytes received from the client, and bytes sent to it. Both are
    /// what crossed the wire on this proxy's client side, so a response
    /// that failed halfway reports the half that landed.
    bytes_in: u64,
    bytes_out: u64,
    /// The request's method token as the client wrote it, truncated to
    /// `access_log_method_bytes_max`. Empty on an L4 line, and on an HTTP
    /// line whose head never parsed.
    method: []const u8 = &.{},
    /// The canonical routing host (lowercased, port-stripped, §7), empty
    /// when the request carried none or it was unusable.
    host: []const u8 = &.{},
    /// The canonical path routing matched on (§7) — not the raw target:
    /// it is the spelling the router and the origin both saw, so a log
    /// line and a route table cannot disagree about which resource was
    /// named. Truncated to `access_log_path_bytes_max` with a trailing
    /// `...`.
    path: []const u8 = &.{},
    /// The status the client was sent, or 0 when it was sent none.
    status: u16 = 0,
    /// Whether this exchange rode a parked upstream connection (§5) and
    /// whether it spent the one free stale replay (§7). Both are cheap to
    /// carry and answer the question a raised latency or an odd 502 asks
    /// first.
    upstream_reused: bool = false,
    upstream_replayed: bool = false,
};

/// Render `record` as one JSON object plus its newline into `buffer`,
/// returning the filled prefix. `error.NoSpaceLeft` means exactly one
/// thing to every caller — this line does not fit what is left — and a
/// buffer of `constants.access_log_line_bytes_max` can never see it, which
/// is what makes a drop always mean backpressure (§8) and never arithmetic.
///
/// Keys are fixed, not templated: a log format language would be a config
/// DSL (§1 non-goal), and a fixed schema is what lets a consumer index the
/// fields without discovering them first.
pub fn renderLine(record: *const Record, buffer: []u8) error{NoSpaceLeft}![]const u8 {
    assert(buffer.len >= 1);
    // The two are captured under caps that make the line bound closed-form
    // (`constants.access_log_line_bytes_max`); a caller that widened one
    // without widening the bound would turn every line into a drop.
    assert(record.path.len <= constants.access_log_path_bytes_max);
    assert(record.cluster.len <= constants.cluster_name_bytes_max);
    var writer = std.Io.Writer.fixed(buffer);
    renderInto(record, &writer) catch return error.NoSpaceLeft;
    const line = writer.buffered();
    assert(line.len >= 2);
    assert(line[0] == '{');
    assert(line[line.len - 1] == '\n');
    return line;
}

/// The fields every line carries, then the HTTP-only ones. Split from
/// `renderLine` so each stays inside the 70-line limit and so the
/// "which fields does `kind` imply" question is answered by the code
/// shape rather than by a comment.
fn renderInto(record: *const Record, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll("{\"time\":\"");
    try writeTimestamp(writer, record.started_wall_ns);
    try writer.print("\",\"kind\":\"{t}\",\"outcome\":\"{t}\"", .{
        record.kind,
        record.outcome,
    });
    try writer.print(",\"client\":\"{f}\"", .{record.client});
    if (record.kind == .http) {
        try renderHttpFields(record, writer);
    }
    // Microseconds: milliseconds lose the whole interesting range of a
    // loopback or LAN hop, and nanoseconds report a precision the clock
    // behind `duration_ns` does not have. Truncating is the right
    // direction — a duration is reported as what it *at least* was.
    try writer.print(
        ",\"duration_us\":{d}",
        .{@divFloor(record.duration_ns, std.time.ns_per_us)},
    );
    try writer.print(",\"bytes_in\":{d},\"bytes_out\":{d}", .{
        record.bytes_in,
        record.bytes_out,
    });
    try writer.writeAll(",\"cluster\":");
    try std.json.Stringify.encodeJsonString(record.cluster, .{}, writer);
    try writer.writeAll(",\"upstream\":");
    if (record.upstream) |address| {
        try writer.print("\"{f}\"", .{address});
    } else {
        // Null rather than an empty string: "no endpoint was ever picked"
        // is a different fact from "the endpoint has no address", and a
        // consumer should not have to guess which one an empty string is.
        try writer.writeAll("null");
    }
    try writer.writeAll("}\n");
}

fn renderHttpFields(record: *const Record, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    assert(record.kind == .http);
    assert(record.method.len <= constants.access_log_method_bytes_max);
    assert(record.host.len <= constants.host_bytes_max);
    try writer.writeAll(",\"method\":");
    try std.json.Stringify.encodeJsonString(record.method, .{}, writer);
    try writer.writeAll(",\"host\":");
    try std.json.Stringify.encodeJsonString(record.host, .{}, writer);
    try writer.writeAll(",\"path\":");
    try std.json.Stringify.encodeJsonString(record.path, .{}, writer);
    try writer.print(",\"status\":{d}", .{record.status});
    try writer.print(",\"upstream_reused\":{},\"upstream_replayed\":{}", .{
        record.upstream_reused,
        record.upstream_replayed,
    });
}

/// RFC 3339 UTC to the millisecond, the spelling every log pipeline reads
/// without configuration. Milliseconds because that is the resolution of
/// the coarse clock the stamp comes from (§4) — printing more digits would
/// be inventing them.
fn writeTimestamp(writer: *std.Io.Writer, wall_ns: u64) std.Io.Writer.Error!void {
    const epoch: std.time.epoch.EpochSeconds = .{
        .secs = @divFloor(wall_ns, std.time.ns_per_s),
    };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const time_of_day = epoch.getDaySeconds();
    const millis = @divFloor(wall_ns % std.time.ns_per_s, std.time.ns_per_ms);
    assert(millis < 1000);
    assert(month_day.day_index < 31);
    try writer.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        time_of_day.getHoursIntoDay(),
        time_of_day.getMinutesIntoHour(),
        time_of_day.getSecondsIntoMinute(),
        millis,
    });
}

/// Copy `source` into `target` for later logging, truncating with a
/// trailing `...` rather than dropping it. Returns the filled prefix.
///
/// Truncation is marked because an unmarked one is a lie: a path cut at
/// 256 bytes reads as a request for a resource nobody asked for, and an
/// operator matching log lines against a route table would chase it. The
/// marker costs three bytes and makes the cut self-describing.
pub fn captureTruncated(target: []u8, source: []const u8) []const u8 {
    const marker = "...";
    assert(target.len > marker.len);
    if (source.len <= target.len) {
        @memcpy(target[0..source.len], source);
        return target[0..source.len];
    }
    const kept = target.len - marker.len;
    assert(kept >= 1);
    @memcpy(target[0..kept], source[0..kept]);
    @memcpy(target[kept..][0..marker.len], marker);
    return target[0..target.len];
}

/// The sink: two staging buffers, one in-flight write, and the drop rung.
/// Generic over the Io backend like the rest of the serving path, so the
/// simulator drives it and can read back exactly what production would
/// have written (§9).
pub fn AccessLog(comptime IoType: type) type {
    const ServerType = @import("Server.zig").Server(IoType);

    return struct {
        server: *ServerType,
        /// Null when no `access_log` block was configured: the whole
        /// feature is off, `record` returns immediately, and `reserve`
        /// allocates nothing (§5 — an unconfigured feature reserves
        /// nothing).
        sink: ?config_module.Config.AccessLogSink,
        /// Bytes per staging buffer, from `limits` (§8). Zero exactly when
        /// the sink is null; the simulator shrinks it to the floor to make
        /// the drop rung reachable (§9).
        buffer_bytes: u32,
        /// Both staging buffers, empty slices while the log is off. The
        /// one at `staging` accepts appends; the other is either idle or
        /// has a write in flight over its first `flush_len` bytes.
        buffers: [constants.access_log_buffers][]u8,
        staging: u1,
        staging_len: u32,
        /// The in-flight window over `buffers[staging ^ 1]`, and how much
        /// of it the sink has taken (a short write resumes from there).
        flush_len: u32,
        flush_sent: u32,
        writing: bool,
        /// Set once a sink write fails. A broken sink is not retried: the
        /// failure that reaches here is a closed pipe or a dead file, not
        /// a transient — the ring already absorbed every would-block — so
        /// retrying would spend a syscall per line forever to lose the
        /// same lines. Every subsequent record counts as dropped, so the
        /// gap is visible in the metrics the log stopped narrating.
        broken: bool,
        completion: IoType.Completion,

        const Self = @This();

        pub fn init(
            log: *Self,
            server: *ServerType,
            sink: ?config_module.Config.AccessLogSink,
            buffer_bytes: u32,
        ) void {
            // One number, two facts: the loader keeps the size at zero
            // exactly when there is no sink, so neither can be set without
            // the other (§8).
            assert((sink == null) == (buffer_bytes == 0));
            if (sink != null) {
                assert(buffer_bytes >= constants.access_log_buffer_bytes_min);
                assert(buffer_bytes <= constants.access_log_buffer_bytes_max);
            }
            log.server = server;
            log.sink = sink;
            log.buffer_bytes = buffer_bytes;
            log.buffers = .{ &.{}, &.{} };
            log.staging = 0;
            log.staging_len = 0;
            log.flush_len = 0;
            log.flush_sent = 0;
            log.writing = false;
            log.broken = false;
            log.completion = .{};
            assert(log.isQuiescent());
        }

        /// Reserve the staging buffers, or nothing when the log is off
        /// (§5). Separate from `init` because it is the one part that
        /// allocates, and it allocates from the startup arena exactly once.
        pub fn reserve(log: *Self, arena: std.mem.Allocator) error{OutOfMemory}!void {
            assert(log.buffers[0].len == 0);
            assert(log.buffers[1].len == 0);
            if (log.sink == null) return;
            for (&log.buffers) |*buffer| {
                buffer.* = try arena.alloc(u8, log.buffer_bytes);
            }
            assert(log.buffers[0].len == log.buffer_bytes);
            assert(log.buffers[1].len == log.buffer_bytes);
        }

        /// Append one record, or drop it (§8). The only entry point the
        /// serving path uses, and it never fails: a caller settling an
        /// exchange has nothing useful to do with a logging error, so the
        /// two ways a line can be lost — no room, or a broken sink — are
        /// counted here rather than returned.
        pub fn record(log: *Self, entry: *const Record) void {
            if (log.sink == null) return;
            if (log.broken) {
                log.server.counters.increment("access_log_dropped");
                return;
            }
            const buffer = log.buffers[log.staging];
            assert(log.staging_len <= buffer.len);
            const line = renderLine(entry, buffer[log.staging_len..]) catch {
                // The staging buffer is full because the sink has not
                // drained it yet: the newest line is what gives way (§8),
                // and the counter is what says so.
                log.server.counters.increment("access_log_dropped");
                return;
            };
            assert(line.len <= constants.access_log_line_bytes_max);
            log.staging_len += @intCast(line.len);
            assert(log.staging_len <= buffer.len);
            log.server.counters.increment("access_log_lines");
            log.maybeFlush();
        }

        /// Start a write if there is something to write and nothing in
        /// flight. Called after every append and after every completion,
        /// which is what makes flushing self-clocking: no timer, and no
        /// line waiting on one.
        fn maybeFlush(log: *Self) void {
            assert(log.sink != null);
            if (log.writing) return;
            if (log.staging_len == 0) return;
            assert(!log.broken);
            // Nothing is in flight, so the other buffer's contents are
            // spent: swapping makes the lines just written the flush
            // window and hands their old buffer back for appends.
            log.flush_len = log.staging_len;
            log.flush_sent = 0;
            log.staging ^= 1;
            log.staging_len = 0;
            assert(log.flush_len >= 1);
            log.armWrite();
        }

        fn armWrite(log: *Self) void {
            assert(!log.writing);
            assert(log.flush_sent < log.flush_len);
            const buffer = log.buffers[log.staging ^ 1];
            assert(log.flush_len <= buffer.len);
            log.writing = true;
            log.server.io.logWrite(
                buffer[log.flush_sent..log.flush_len],
                &log.completion,
                Self,
                log,
                onWritten,
            );
        }

        fn onWritten(log: *Self, result: Io.LogWriteError!u32) void {
            assert(log.writing);
            log.writing = false;
            const written = result catch {
                // Deliberately *not* counted as drops: the lines in flight
                // and the ones behind them were already counted as
                // `access_log_lines` when they were accepted, and counting
                // them twice would break the identity the §9 oracle checks
                // — every loggable event is one line or one drop. This
                // counter is the witness that some accepted lines never
                // landed, and that everything after this is a drop.
                log.server.counters.increment("access_log_write_failed");
                log.broken = true;
                log.flush_len = 0;
                log.flush_sent = 0;
                log.staging_len = 0;
                log.server.maybeStopAfterDrain();
                return;
            };
            assert(written >= 1);
            log.flush_sent += written;
            assert(log.flush_sent <= log.flush_len);
            if (log.flush_sent < log.flush_len) {
                log.armWrite(); // A short write resumes (§6's rule, one sink over).
                return;
            }
            log.flush_len = 0;
            log.flush_sent = 0;
            log.maybeFlush();
            // The drain stops the loop only once the sink is quiet, so the
            // completion that empties it is the one that has to re-check.
            log.server.maybeStopAfterDrain();
        }

        /// Quiescent for the drain-stop gate (§8): nothing in flight and
        /// nothing waiting. A log the drain stopped short of flushing
        /// would lose exactly the lines describing the shutdown, which is
        /// when an operator is most likely to be reading it.
        pub fn isQuiescent(log: *const Self) bool {
            return !log.writing and log.staging_len == 0;
        }
    };
}

const testing = std.testing;

/// A record with every field set to something distinguishable, so a test
/// can assert on one field without the others being coincidentally right.
fn testRecord() Record {
    return .{
        .kind = .http,
        .outcome = .ok,
        // 2026-07-31T09:14:22.481Z
        .started_wall_ns = 1_785_489_262 * std.time.ns_per_s + 481 * std.time.ns_per_ms,
        .duration_ns = 1_873_000,
        .client = std.Io.net.IpAddress.parseLiteral("10.1.2.3:52344") catch unreachable,
        .upstream = std.Io.net.IpAddress.parseLiteral("10.0.0.7:8080") catch unreachable,
        .cluster = "api",
        .bytes_in = 142,
        .bytes_out = 4096,
        .method = "GET",
        .host = "api.example.com",
        .path = "/v1/items",
        .status = 200,
        .upstream_reused = true,
        .upstream_replayed = false,
    };
}

test "access log: an HTTP line carries every field, exactly once" {
    var buffer: [constants.access_log_line_bytes_max]u8 = undefined;
    const entry = testRecord();
    const line = try renderLine(&entry, &buffer);

    try testing.expectEqualStrings(
        "{\"time\":\"2026-07-31T09:14:22.481Z\",\"kind\":\"http\",\"outcome\":\"ok\"," ++
            "\"client\":\"10.1.2.3:52344\",\"method\":\"GET\",\"host\":\"api.example.com\"," ++
            "\"path\":\"/v1/items\",\"status\":200,\"upstream_reused\":true," ++
            "\"upstream_replayed\":false,\"duration_us\":1873,\"bytes_in\":142," ++
            "\"bytes_out\":4096,\"cluster\":\"api\",\"upstream\":\"10.0.0.7:8080\"}\n",
        line,
    );
}

test "access log: an L4 line omits the request fields and names no status" {
    var buffer: [constants.access_log_line_bytes_max]u8 = undefined;
    var entry = testRecord();
    entry.kind = .l4;
    entry.outcome = .closed;
    entry.cluster = "tcp";
    entry.upstream = try std.Io.net.IpAddress.parseLiteral("10.0.0.7:9000");
    const line = try renderLine(&entry, &buffer);

    try testing.expectEqualStrings(
        "{\"time\":\"2026-07-31T09:14:22.481Z\",\"kind\":\"l4\",\"outcome\":\"closed\"," ++
            "\"client\":\"10.1.2.3:52344\",\"duration_us\":1873,\"bytes_in\":142," ++
            "\"bytes_out\":4096,\"cluster\":\"tcp\",\"upstream\":\"10.0.0.7:9000\"}\n",
        line,
    );
    // The HTTP-only keys are absent, not empty: a consumer keying off
    // `kind` must not find a `status` on an L4 line at all.
    try testing.expect(std.mem.indexOf(u8, line, "status") == null);
    try testing.expect(std.mem.indexOf(u8, line, "method") == null);
}

test "access log: every line is valid JSON, including hostile paths" {
    // A percent-decoded canonical path may legally contain a quote, a
    // backslash, or a control byte (§7 decodes unreserved escapes and
    // rejects only the structure-changing ones), and each has to survive
    // as a JSON string rather than as a broken line the consumer drops.
    const paths = [_][]const u8{
        "/v1/items",
        "/a\"b",
        "/a\\b",
        "/a\x01b",
        "/\x00",
        "/emoji-\u{1F600}",
    };
    var buffer: [constants.access_log_line_bytes_max]u8 = undefined;
    for (paths) |path| {
        var entry = testRecord();
        entry.path = path;
        entry.host = "h\"ost";
        entry.cluster = "cl\\uster";
        const line = try renderLine(&entry, &buffer);

        const parsed = try std.json.parseFromSlice(
            std.json.Value,
            testing.allocator,
            line,
            .{},
        );
        defer parsed.deinit();
        try testing.expectEqualStrings(path, parsed.value.object.get("path").?.string);
        try testing.expectEqualStrings("h\"ost", parsed.value.object.get("host").?.string);
    }
}

test "access log: the line bound holds at every field's maximum" {
    // `access_log_line_bytes_max` is what lets `record` treat NoSpaceLeft
    // as backpressure rather than arithmetic (§8), so it must survive the
    // widest line the caps allow: full-width IPv6 on both ends, a path and
    // a host of nothing but 6-byte escapes, and every number saturated.
    var path: [constants.access_log_path_bytes_max]u8 = undefined;
    @memset(&path, '\x01');
    var host: [constants.host_bytes_max]u8 = undefined;
    @memset(&host, '\x01');
    var method: [constants.access_log_method_bytes_max]u8 = undefined;
    @memset(&method, '\x01');
    var cluster: [constants.cluster_name_bytes_max]u8 = undefined;
    @memset(&cluster, 'c');

    const entry: Record = .{
        .kind = .http,
        .outcome = .upstream_failed,
        .started_wall_ns = std.math.maxInt(u32) * std.time.ns_per_s,
        .duration_ns = std.math.maxInt(u64),
        .client = try .parseLiteral("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"),
        .upstream = try .parseLiteral("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"),
        .cluster = &cluster,
        .bytes_in = std.math.maxInt(u64),
        .bytes_out = std.math.maxInt(u64),
        .method = &method,
        .host = &host,
        .path = &path,
        .status = 999,
        .upstream_reused = true,
        .upstream_replayed = true,
    };
    var buffer: [constants.access_log_line_bytes_max]u8 = undefined;
    const line = try renderLine(&entry, &buffer);
    try testing.expect(line.len <= constants.access_log_line_bytes_max);
}

test "access log: a truncated capture says so" {
    var target: [16]u8 = undefined;
    // Short enough to fit: copied whole, no marker.
    try testing.expectEqualStrings("/short", captureTruncated(&target, "/short"));
    // Exactly the cap: still whole — the marker is for what was cut, and
    // nothing was.
    try testing.expectEqualStrings("/0123456789abcde", captureTruncated(&target, "/0123456789abcde"));
    // One byte over: the prefix survives and the cut is visible.
    try testing.expectEqualStrings("/0123456789ab...", captureTruncated(&target, "/0123456789abcdef"));
}
