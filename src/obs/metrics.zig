//! Fixed set of process-wide counters (docs/DESIGN.md §7), sharded per worker
//! so the hot path never contends on a shared cache line: each worker writes
//! only its own `Counters` shard (single writer — the RMW below is uncontended
//! and the line stays in that core's cache in M state), and readers (the admin
//! scrape, the handoff snapshot) sum across shards. Shards are padded to the
//! cache line so no two workers' counters cohabit one line — before sharding,
//! eight `u64` counters per 64-byte line were RMW'd by every worker, and the
//! adjacent `bytes_to_*` pair was hit once per 16 KiB relay chunk from every
//! core at once. Reserved at startup, never grows.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const cache_line = @import("../mem/cache_line.zig");

/// A monotonic (or up/down, for gauges) atomic counter.
pub const Counter = struct {
    value: u64 = 0,

    pub fn add(counter: *Counter, n: u64) void {
        _ = @atomicRmw(u64, &counter.value, .Add, n, .monotonic);
    }
    pub fn sub(counter: *Counter, n: u64) void {
        _ = @atomicRmw(u64, &counter.value, .Sub, n, .monotonic);
    }
    /// Subtract and return the *previous* value — for last-one-out decisions
    /// (the shared-listener refcount).
    pub fn fetch_sub(counter: *Counter, n: u64) u64 {
        return @atomicRmw(u64, &counter.value, .Sub, n, .monotonic);
    }
    pub fn load(counter: *const Counter) u64 {
        return @atomicLoad(u64, &counter.value, .monotonic);
    }
};

/// One worker's counter set — the handle the data path writes through
/// (`ProxyServer`, `ProxyConn`, and the health checker hold a `*Counters`).
/// Process totals are sums over shards, computed by `Metrics.total`.
pub const Counters = struct {
    /// Downstream connections accepted (this shard's slot doubles as the
    /// per-worker accept-distribution series in the exposition).
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
};

pub const Metrics = struct {
    shards: [shards_count]cache_line.Padded(Counters) = @splat(.{ .value = .{} }),

    /// One shard per worker slot, plus one where a hot-restart predecessor's
    /// totals are folded (so they never pollute a worker's accept series).
    pub const shards_count = constants.workers_max + 1;
    pub const shard_adopted = constants.workers_max;

    comptime {
        // Every field is a Counter: `total`/`snapshot` iterate them uniformly.
        for (@typeInfo(Counters).@"struct".fields) |field| {
            assert(field.type == Counter);
        }
    }

    /// The shard a worker writes through. Workers beyond the shard table
    /// share the last worker slot (diagnostic accept series only).
    pub fn shard(metrics: *Metrics, index: u32) *Counters {
        assert(index < shards_count);
        return &metrics.shards[index].value;
    }

    /// Process-wide value of one counter: the sum over every shard. Read
    /// side only (scrape, handoff snapshot, drain decisions) — never on the
    /// data path.
    pub fn total(metrics: *const Metrics, comptime field_name: []const u8) u64 {
        var sum: u64 = 0;
        for (&metrics.shards) |*one_shard| { // bounded: shards_count
            sum += @field(one_shard.value, field_name).load();
        }
        return sum;
    }

    /// Write a Prometheus-style text exposition: every counter as its
    /// cross-shard total, then the per-worker accept distribution as labeled
    /// series, one per non-zero worker shard (the adopted shard is excluded
    /// — a predecessor's distribution deliberately starts over).
    pub fn write_text(metrics: *const Metrics, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        inline for (@typeInfo(Counters).@"struct".fields) |field| {
            try writer.print("zoxy_{s} {d}\n", .{ field.name, metrics.total(field.name) });
        }
        for (metrics.shards[0..constants.workers_max], 0..) |*one_shard, index| {
            const value = one_shard.value.accepted.load();
            if (value == 0) continue; // only workers that exist
            try writer.print(
                "zoxy_worker_accepted{{worker=\"{d}\"}} {d}\n",
                .{ index, value },
            );
        }
    }
};

test "metrics: counters add, sub, and load" {
    var counters = Counters{};
    counters.accepted.add(3);
    counters.accepted.add(1);
    counters.active.add(5);
    counters.active.sub(2);
    try std.testing.expectEqual(@as(u64, 4), counters.accepted.load());
    try std.testing.expectEqual(@as(u64, 3), counters.active.load());
    try std.testing.expectEqual(@as(u64, 0), counters.rejected.load());
}

test "metrics: totals sum across shards" {
    var m = Metrics{};
    m.shard(0).requests.add(7);
    m.shard(5).requests.add(2);
    m.shard(Metrics.shard_adopted).requests.add(100); // hot-restart fold
    try std.testing.expectEqual(@as(u64, 109), m.total("requests"));
    try std.testing.expectEqual(@as(u64, 0), m.total("accepted"));
}

test "metrics: shards never share a cache line" {
    var m = Metrics{};
    const first = @intFromPtr(m.shard(0));
    const second = @intFromPtr(m.shard(1));
    try std.testing.expect(second - first >= cache_line.bytes);
    try std.testing.expectEqual(@as(usize, 0), first % cache_line.bytes);
    try std.testing.expectEqual(@as(usize, 0), (second - first) % cache_line.bytes);
}

test "metrics: write_text dumps every counter" {
    var m = Metrics{};
    m.shard(0).requests.add(7);
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try m.write_text(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "zoxy_requests 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "zoxy_accepted 0\n") != null);
}

test "metrics: per-worker accepts emit labeled series, zeros and adopted omitted" {
    var m = Metrics{};
    m.shard(0).accepted.add(3);
    m.shard(5).accepted.add(9);
    m.shard(Metrics.shard_adopted).accepted.add(50); // total only, no series
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try m.write_text(&w);
    const out = w.buffered();
    const series_0 = "zoxy_worker_accepted{worker=\"0\"} 3\n";
    const series_5 = "zoxy_worker_accepted{worker=\"5\"} 9\n";
    try std.testing.expect(std.mem.indexOf(u8, out, "zoxy_accepted 62\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, series_0) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, series_5) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "worker=\"1\"") == null); // zero: omitted
    try std.testing.expect(std.mem.indexOf(u8, out, "worker=\"64\"") == null); // adopted: omitted
}
