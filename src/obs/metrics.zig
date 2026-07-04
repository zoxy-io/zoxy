//! Fixed set of process-wide counters (docs/DESIGN.md §7). One shared instance
//! across all workers; increments are relaxed atomics, so there is no allocation
//! and negligible contention on the hot path. Reserved at startup, never grows.

const std = @import("std");
const constants = @import("../constants.zig");

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
    /// Connections rejected because the pool was full (backpressure) or the
    /// worker was draining when the accept completed.
    rejected: Counter = .{},
    /// Workers currently draining (gauge; nonzero means shutdown began).
    draining: Counter = .{},
    /// Connections torn down by the deadline while draining — clients or
    /// upstreams that outlived the drain limit.
    drain_forced_closes: Counter = .{},
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
    /// Upstream attempts aborted by their cluster's per-try timeout.
    per_try_timeouts: Counter = .{},
    /// Configured retries scheduled (excludes the free stale-pool replay,
    /// which `upstream_retried` counts).
    retry_attempts: Counter = .{},
    /// Retries denied by the retry budget or the max_retries breaker.
    retry_budget_exhausted: Counter = .{},
    /// Endpoints ejected by passive outlier detection.
    outlier_ejections: Counter = .{},
    /// Active health probes completed (all workers).
    health_probes: Counter = .{},
    /// Active health probes that failed (refused, reset, or timed out).
    health_probe_failures: Counter = .{},
    /// Downstream TLS handshakes completed.
    tls_handshakes: Counter = .{},
    /// Connections whose record layer was handed to the kernel (kTLS): the
    /// steady-state relay runs as plain ring ops, the channel is freed.
    tls_ktls_active: Counter = .{},
    /// Handshakes that stayed on the userspace relay: kernel/cipher refused
    /// the offload, data rode the handshake flight, or offload is off.
    tls_ktls_fallbacks: Counter = .{},
    /// Downstream TLS handshakes that failed (bad ClientHello, no shared
    /// cipher, or the TLS heap load-shed the connection at accept).
    tls_handshake_failures: Counter = .{},
    /// Requests rejected by a cluster circuit breaker (max_requests).
    breaker_requests_rejected: Counter = .{},
    /// Upstream dials rejected by a cluster circuit breaker (max_pending or
    /// max_connections).
    breaker_dials_rejected: Counter = .{},
    bytes_to_upstream: Counter = .{},
    bytes_to_client: Counter = .{},
    /// Downstream connections accepted, per worker: the kernel's
    /// SO_REUSEPORT hash distribution made visible (imbalance here means
    /// the busiest worker sets the throughput ceiling).
    worker_accepted: [constants.workers_max]Counter = @splat(.{}),

    /// Fields that are point-in-time gauges, not cumulative counters. A hot
    /// restart transfers counters to the successor so scrapes stay monotonic
    /// across the pair; gauges describe *this* process and must start at 0.
    pub const gauge_fields = [_][]const u8{ "active", "draining" };

    pub fn is_gauge(comptime field_name: []const u8) bool {
        inline for (gauge_fields) |gauge| {
            if (comptime std.mem.eql(u8, gauge, field_name)) return true;
        }
        return false;
    }

    /// Write a Prometheus-style text exposition of every counter. Array
    /// fields become labeled series, one per non-zero slot.
    pub fn write_text(metrics: *const Metrics, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        inline for (@typeInfo(Metrics).@"struct".fields) |field| {
            if (comptime field.type == Counter) {
                const counter: *const Counter = &@field(metrics, field.name);
                try writer.print("zoxy_{s} {d}\n", .{ field.name, counter.load() });
            } else {
                for (&@field(metrics, field.name), 0..) |*counter, index| {
                    const value = counter.load();
                    if (value == 0) continue; // only workers that exist
                    try writer.print(
                        "zoxy_{s}{{worker=\"{d}\"}} {d}\n",
                        .{ field.name, index, value },
                    );
                }
            }
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

test "metrics: write_text dumps every counter" {
    var m = Metrics{};
    m.requests.add(7);
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try m.write_text(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "zoxy_requests 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "zoxy_accepted 0\n") != null);
}

test "metrics: per-worker counters emit labeled series, zeros omitted" {
    var m = Metrics{};
    m.worker_accepted[0].add(3);
    m.worker_accepted[5].add(9);
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try m.write_text(&w);
    const out = w.buffered();
    const series_0 = "zoxy_worker_accepted{worker=\"0\"} 3\n";
    const series_5 = "zoxy_worker_accepted{worker=\"5\"} 9\n";
    try std.testing.expect(std.mem.indexOf(u8, out, series_0) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, series_5) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "worker=\"1\"") == null); // zero: omitted
}
