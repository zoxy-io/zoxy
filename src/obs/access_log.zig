//! Per-worker access log (docs/DESIGN.md §7). Each worker owns one `AccessLog`
//! and is single-threaded, so there are no locks: records accumulate in a fixed
//! buffer and flush as a single batched write() when full. No allocation.
//!
//! (A dedicated flusher thread draining per-worker SPSC rings is a later
//! refinement; batched writes keep syscalls off the per-connection path here.)

const std = @import("std");
const linux = std.os.linux;
const assert = std.debug.assert;

pub const Outcome = enum {
    proxied,
    bad_request,
    not_found,
    too_large,
    bad_version,
    not_implemented,
    no_upstream,
    unavailable,
    aborted,

    pub fn text(outcome: Outcome) []const u8 {
        return switch (outcome) {
            .proxied => "proxied",
            .bad_request => "400",
            .not_found => "404",
            .too_large => "431",
            .bad_version => "505",
            .not_implemented => "501",
            .no_upstream => "502",
            .unavailable => "503",
            .aborted => "aborted",
        };
    }
};

pub const Entry = struct {
    method: []const u8,
    target: []const u8,
    outcome: Outcome,
    bytes_to_client: u64,
};

const target_display_max = 256;
const line_max = target_display_max + 64;

/// Format one access-log line into `out`. Never fails: an over-long target is
/// truncated so the line always fits `line_max`.
pub fn formatLine(out: []u8, entry: Entry) []const u8 {
    assert(out.len >= line_max); // the caller must give us a line-sized buffer
    const method = if (entry.method.len == 0) "-" else entry.method;
    const target = if (entry.target.len == 0)
        "-"
    else if (entry.target.len > target_display_max)
        entry.target[0..target_display_max]
    else
        entry.target;
    const line = std.fmt.bufPrint(out, "{s} {s} {s} {d}\n", .{
        method,
        target,
        entry.outcome.text(),
        entry.bytes_to_client,
    }) catch null; // out.len >= line_max (asserted) and inputs are bounded, so it fits
    assert(line != null);
    assert(line.?.len <= line_max);
    return line.?;
}

pub const AccessLog = struct {
    fd: linux.fd_t,
    used: usize = 0,
    buf: [buf_bytes]u8 = undefined,

    const buf_bytes = 16 * 1024;
    comptime {
        // A single record must always fit the buffer, so record() can flush and
        // then format unconditionally.
        assert(buf_bytes >= line_max);
    }

    pub fn record(log: *AccessLog, entry: Entry) void {
        assert(log.used <= log.buf.len);
        if (log.used + line_max > log.buf.len) log.flush();
        assert(log.used + line_max <= log.buf.len); // flush guaranteed room
        const line = formatLine(log.buf[log.used..], entry);
        log.used += line.len;
        assert(log.used <= log.buf.len);
    }

    /// Write accumulated lines with a single batched write() and reset.
    pub fn flush(log: *AccessLog) void {
        assert(log.used <= log.buf.len);
        if (log.used == 0) return;
        _ = linux.write(log.fd, &log.buf, log.used); // best-effort
        log.used = 0;
    }
};

// ---- tests ----------------------------------------------------------------

test "access_log: formats lines by outcome" {
    var buf: [line_max]u8 = undefined;
    try std.testing.expectEqualStrings(
        "GET /a proxied 12\n",
        formatLine(&buf, .{
            .method = "GET",
            .target = "/a",
            .outcome = .proxied,
            .bytes_to_client = 12,
        }),
    );
    try std.testing.expectEqualStrings(
        "- - aborted 0\n",
        formatLine(&buf, .{
            .method = "",
            .target = "",
            .outcome = .aborted,
            .bytes_to_client = 0,
        }),
    );
    try std.testing.expectEqualStrings(
        "POST /x 404 0\n",
        formatLine(&buf, .{
            .method = "POST",
            .target = "/x",
            .outcome = .not_found,
            .bytes_to_client = 0,
        }),
    );
}

test "access_log: accumulates records in the buffer" {
    var log = AccessLog{ .fd = -1 }; // not flushed in this test
    log.record(.{ .method = "GET", .target = "/a", .outcome = .proxied, .bytes_to_client = 5 });
    log.record(.{
        .method = "POST",
        .target = "/b",
        .outcome = .no_upstream,
        .bytes_to_client = 0,
    });
    const out = log.buf[0..log.used];
    try std.testing.expect(std.mem.indexOf(u8, out, "GET /a proxied 5\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "POST /b 502 0\n") != null);
}
