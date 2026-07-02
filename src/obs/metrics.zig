//! Fixed set of process-wide counters (docs/DESIGN.md §7). One shared instance
//! across all workers; increments are relaxed atomics, so there is no allocation
//! and negligible contention on the hot path. Reserved at startup, never grows.

const std = @import("std");

/// A monotonic (or up/down, for gauges) atomic counter.
pub const Counter = struct {
    value: u64 = 0,

    pub fn add(counter: *Counter, n: u64) void {
        _ = @atomicRmw(u64, &counter.value, .Add, n, .monotonic);
    }
    pub fn sub(counter: *Counter, n: u64) void {
        _ = @atomicRmw(u64, &counter.value, .Sub, n, .monotonic);
    }
    pub fn load(counter: *const Counter) u64 {
        return @atomicLoad(u64, &counter.value, .monotonic);
    }
};

pub const Metrics = struct {
    /// Downstream connections accepted.
    accepted: Counter = .{},
    /// Currently-open downstream connections (gauge).
    active: Counter = .{},
    /// Connections rejected because the pool was full (backpressure).
    rejected: Counter = .{},
    /// Requests whose head parsed and routed.
    requests: Counter = .{},
    /// 4xx responses zoxy generated (bad/oversized requests).
    client_errors: Counter = .{},
    /// 5xx responses zoxy generated (no route / upstream failure).
    upstream_errors: Counter = .{},
    /// Requests served over a pooled (reused) upstream connection.
    upstream_reused: Counter = .{},
    /// Stale pooled connections replaced by a fresh dial mid-request.
    upstream_retried: Counter = .{},
    bytes_to_upstream: Counter = .{},
    bytes_to_client: Counter = .{},

    /// Write a Prometheus-style text exposition of every counter.
    pub fn writeText(metrics: *const Metrics, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        inline for (@typeInfo(Metrics).@"struct".fields) |field| {
            const counter: *const Counter = &@field(metrics, field.name);
            try writer.print("zoxy_{s} {d}\n", .{ field.name, counter.load() });
        }
    }
};

test "metrics: counters add, sub, and load" {
    var m = Metrics{};
    m.accepted.add(3);
    m.accepted.add(1);
    m.active.add(5);
    m.active.sub(2);
    try std.testing.expectEqual(@as(u64, 4), m.accepted.load());
    try std.testing.expectEqual(@as(u64, 3), m.active.load());
    try std.testing.expectEqual(@as(u64, 0), m.rejected.load());
}

test "metrics: writeText dumps every counter" {
    var m = Metrics{};
    m.requests.add(7);
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try m.writeText(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "zoxy_requests 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "zoxy_accepted 0\n") != null);
}
