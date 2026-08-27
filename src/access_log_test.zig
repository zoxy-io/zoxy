//! Directed access-log scenarios over SimIo (§9). The sink is a state
//! machine with a rung of its own — two staging buffers, one in-flight
//! write, and a drop when the buffers fill — and its rung is not one a
//! simulator *scenario* can reach: filling even the smallest legal buffer
//! takes dozens of lines, where a scenario emits a handful. So the sweep
//! covers the ordinary paths under schedule fuzz and these tests pin the
//! edges: the drop, the broken sink, the short-write resume, and the drain
//! that must not stop the loop over an unflushed line.
//!
//! Records are handed to `AccessLog.record` directly. The serving path's
//! job is to *build* them, which the sweep and `http_proxy_test.zig` both
//! exercise; what is under test here is what the sink does with one.

const std = @import("std");

const access_log = @import("access_log.zig");
const config_module = @import("config.zig");
const constants = @import("constants.zig");
const io_module = @import("io/io.zig");
const router = @import("http/router.zig");
const Server = @import("Server.zig").Server;
const SimIo = @import("io/SimIo.zig");

const assert = std.debug.assert;
const testing = std.testing;

const ServerSim = Server(SimIo);

fn bindAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
}
fn originAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
}

/// The same origin as an endpoint (#303): every cluster's endpoint list
/// is an address union now, and the harness dials and listens on the
/// IP arm of it.
fn originEndpoint() io_module.Address {
    return .{ .ip = originAddress() };
}

const Harness = struct {
    arena_state: std.heap.ArenaAllocator,
    sim_io: SimIo,
    endpoints: [1]io_module.Address,
    clusters: [1]config_module.Config.Cluster,
    routes: [1]router.Route,
    listeners: [1]config_module.Config.Listener,
    config: config_module.Config,
    server: ServerSim,

    /// `buffer_bytes` of zero is how a config leaves the log off; anything
    /// else turns it on at that staging size. No listeners are started:
    /// the sink is the whole subject, and an armed accept would keep the
    /// loop from ever returning.
    fn setUp(
        harness: *Harness,
        gpa: std.mem.Allocator,
        buffer_bytes: u32,
        stall_ns: u64,
    ) !void {
        try harness.setUpWithSink(gpa, buffer_bytes, stall_ns, .stdout);
    }

    /// The reopen tests need the `file` arm — SIGHUP is a no-op on any
    /// other sink. SimIo opens nothing, so the path is never touched.
    fn setUpWithSink(
        harness: *Harness,
        gpa: std.mem.Allocator,
        buffer_bytes: u32,
        stall_ns: u64,
        sink: config_module.Config.AccessLogSink,
    ) !void {
        harness.arena_state = std.heap.ArenaAllocator.init(gpa);
        errdefer harness.arena_state.deinit();
        const arena = harness.arena_state.allocator();

        // An http bed: ring on both sides of the seam, sized to the conn
        // slots below (Server.init asserts the two agree).
        try harness.sim_io.init(arena, .{
            .seed = 1,
            .adversary = .{ .partial_io = false, .log_write_stall_ns = stall_ns },
            .buffer_group_count = 4,
        });
        harness.endpoints = .{originEndpoint()};
        harness.clusters = .{.{ .name = "origin", .endpoints = &harness.endpoints }};
        harness.routes = .{.{ .prefix = "/", .cluster_index = 0 }};
        harness.listeners = .{.{
            .bind_address = bindAddress(),
            .routes = &harness.routes,
            .protocol = .http,
        }};
        harness.config = .{
            .listeners = &harness.listeners,
            .clusters = &harness.clusters,
            .connect_timeout_ms = 50,
            .idle_timeout_ms = 1000,
            .head_timeout_ms = 1000,
            .drain_deadline_ms = 1000,
            .max_lifetime_ms = 0,
            .request_timeout_ms = 0,
            .tunnel_timeout_ms = constants.tunnel_ms_default,
            .access_log_sink = if (buffer_bytes == 0) null else sink,
        };
        try harness.server.init(arena, &harness.sim_io, &harness.config, .{
            .conn_slots = 4,
            .relay_buffers = 2,
            .head_buffers = 4,
            .upstream_head_buffers = 4,
            .access_log_buffer_bytes = buffer_bytes,
        });
    }

    fn tearDown(harness: *Harness) void {
        harness.arena_state.deinit();
    }

    fn counter(harness: *const Harness, comptime name: []const u8) u64 {
        return harness.server.counters.get(name);
    }

    /// Deliver everything pending — the sink's writes and nothing else,
    /// since no listener is armed.
    fn drainSink(harness: *Harness) !void {
        try harness.sim_io.run();
    }

    fn emit(harness: *Harness, index: u32) void {
        var entry = sampleRecord();
        entry.bytes_in = index; // Distinguishable per line, for order checks.
        harness.server.access_log.record(&entry);
    }
};

fn sampleRecord() access_log.Record {
    return .{
        .kind = .http,
        .outcome = .ok,
        .started_wall_ns = 1_785_489_262 * std.time.ns_per_s,
        .duration_ns = 1000,
        .client = std.Io.net.IpAddress.parseLiteral("10.1.2.3:52344") catch unreachable,
        .upstream = .{ .ip = std.Io.net.IpAddress.parseLiteral("10.0.0.7:8080") catch unreachable },
        .cluster = "origin",
        .bytes_in = 0,
        .bytes_out = 7,
        .method = "GET",
        .host = "example.com",
        .path = "/v1/items",
        .status = 200,
    };
}

fn lineCount(sink: []const u8) u64 {
    return std.mem.count(u8, sink, "\n");
}

test "access log: a burst past the staging buffers drops, and says how much" {
    // The §8 rung. The sink is stalled for the whole burst, so both
    // buffers fill and there is nowhere for the rest to go — which must
    // cost lines, never a stalled caller.
    var harness: Harness = undefined;
    try harness.setUp(testing.allocator, constants.access_log_buffer_bytes_min, 1_000_000_000);
    defer harness.tearDown();

    const burst: u32 = 512;
    var index: u32 = 0;
    while (index < burst) : (index += 1) {
        harness.emit(index);
    }

    // Every record is one line or one drop — no third outcome, which is
    // what lets an operator read `dropped` as "this is how incomplete".
    try testing.expectEqual(
        @as(u64, burst),
        harness.counter("access_log_lines") + harness.counter("access_log_dropped"),
    );
    try testing.expect(harness.counter("access_log_dropped") > 0);
    try testing.expect(harness.counter("access_log_lines") > 0);
    // Backpressure, not a broken sink: nothing failed, the writes are
    // simply still out.
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_write_failed"));
    try testing.expect(!harness.server.access_log.isQuiescent());

    // What was accepted still reaches the sink once it drains, whole.
    try harness.drainSink();
    const sink = harness.sim_io.sinkBytes();
    try testing.expectEqual(harness.counter("access_log_lines"), lineCount(sink));
    try testing.expectEqual(@as(u8, '\n'), sink[sink.len - 1]);
    try testing.expect(harness.server.access_log.isQuiescent());
}

test "access log: lines reach the sink in order, across the buffer swap" {
    // The swap is what lets appends continue during a write, and getting
    // it backwards would reorder or duplicate whole buffers rather than
    // lose a byte — a failure no line-count check would notice.
    var harness: Harness = undefined;
    try harness.setUp(testing.allocator, constants.access_log_buffer_bytes_min, 1_000_000);
    defer harness.tearDown();

    const count: u32 = 12;
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        harness.emit(index);
        // Interleave delivery with appends so a write is in flight for
        // some of them and not for others — both sides of `maybeFlush`.
        try harness.drainSink();
    }
    try harness.drainSink();

    try testing.expectEqual(@as(u64, count), harness.counter("access_log_lines"));
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_dropped"));

    // `bytes_in` carries each record's index, so the sink must read back
    // as 0, 1, 2, … with nothing missing and nothing repeated.
    var lines = std.mem.splitScalar(u8, harness.sim_io.sinkBytes(), '\n');
    var expected: u32 = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var needle_buffer: [32]u8 = undefined;
        const needle = try std.fmt.bufPrint(&needle_buffer, "\"bytes_in\":{d},", .{expected});
        try testing.expect(std.mem.indexOf(u8, line, needle) != null);
        expected += 1;
    }
    try testing.expectEqual(count, expected);
}

test "access log: a failed sink write stops the log and is witnessed once" {
    var harness: Harness = undefined;
    try harness.setUp(testing.allocator, constants.access_log_buffer_bytes_min, 0);
    defer harness.tearDown();

    harness.sim_io.injectLogWriteError();
    harness.emit(0);
    try harness.drainSink();

    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_write_failed"));
    try testing.expect(harness.server.access_log.broken);
    // The sink is quiet — a broken log must not hold the drain open.
    try testing.expect(harness.server.access_log.isQuiescent());
    const written_before = harness.sim_io.sinkBytes().len;

    // Everything after is a drop, and nothing more is ever written: the
    // failure is a closed pipe, not a transient, so retrying would spend a
    // syscall per line to lose the same lines.
    harness.emit(1);
    harness.emit(2);
    try harness.drainSink();
    try testing.expectEqual(@as(u64, 2), harness.counter("access_log_dropped"));
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_write_failed"));
    try testing.expectEqual(written_before, harness.sim_io.sinkBytes().len);
}

test "access log: a short write resumes rather than losing its tail" {
    // The sink takes one byte at a time, so a single line needs as many
    // completions as it has bytes — the resume path, driven to its limit.
    var harness: Harness = undefined;
    try harness.setUp(testing.allocator, constants.access_log_buffer_bytes_min, 0);
    defer harness.tearDown();
    harness.sim_io.adversary.partial_io = true;

    harness.emit(0);
    harness.emit(1);
    try harness.drainSink();

    try testing.expectEqual(@as(u64, 2), harness.counter("access_log_lines"));
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_dropped"));
    const sink = harness.sim_io.sinkBytes();
    try testing.expectEqual(@as(u64, 2), lineCount(sink));
    try testing.expectEqual(@as(u8, '\n'), sink[sink.len - 1]);
}

test "access log: off reserves nothing, writes nothing, counts nothing" {
    var harness: Harness = undefined;
    try harness.setUp(testing.allocator, 0, 0);
    defer harness.tearDown();

    try testing.expect(harness.server.access_log.sink == null);
    try testing.expectEqual(@as(usize, 0), harness.server.access_log.buffers[0].len);
    try testing.expectEqual(@as(usize, 0), harness.server.access_log.buffers[1].len);

    harness.emit(0);
    try harness.drainSink();

    try testing.expectEqual(@as(usize, 0), harness.sim_io.sinkBytes().len);
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_lines"));
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_dropped"));
    // Quiescent by construction, so a disabled log can never hold a drain.
    try testing.expect(harness.server.access_log.isQuiescent());
}

test "access log: an unflushed line keeps the drain from stopping the loop" {
    // The drain's whole point is that admitted work finishes (§8), and the
    // lines describing a shutdown are the ones most likely to be read.
    var harness: Harness = undefined;
    try harness.setUp(testing.allocator, constants.access_log_buffer_bytes_min, 1_000_000);
    defer harness.tearDown();

    harness.emit(0);
    try testing.expect(!harness.server.access_log.isQuiescent());
    // Every pool is empty, so the sink is the only thing left holding the
    // drain-stop gate — which is exactly the condition being tested.
    try testing.expect(harness.server.conns.isFullyReleased());
    try testing.expect(!harness.server.isIdle());

    try harness.drainSink();
    try testing.expect(harness.server.access_log.isQuiescent());
    try testing.expect(harness.server.isIdle());
    try testing.expectEqual(@as(u64, 1), lineCount(harness.sim_io.sinkBytes()));
}

test "access log: SIGHUP reopens an idle file sink immediately" {
    var harness: Harness = undefined;
    try harness.setUpWithSink(
        testing.allocator,
        constants.access_log_buffer_bytes_min,
        0,
        .{ .file = "/virtual/access.log" },
    );
    defer harness.tearDown();

    // Nothing in flight: the swap needs no completion to wait for.
    harness.server.access_log.requestReopen();
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_reopened"));
    try testing.expectEqual(@as(u32, 1), harness.sim_io.log_reopen_count);

    // The sink still works after the swap.
    harness.emit(0);
    try harness.drainSink();
    try testing.expectEqual(@as(u64, 1), lineCount(harness.sim_io.sinkBytes()));
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_dropped"));
}

test "access log: SIGHUP under an in-flight write swaps at its completion" {
    var harness: Harness = undefined;
    try harness.setUpWithSink(
        testing.allocator,
        constants.access_log_buffer_bytes_min,
        1_000_000, // The write stalls, so the signal races it.
        .{ .file = "/virtual/access.log" },
    );
    defer harness.tearDown();

    harness.emit(0);
    try testing.expect(!harness.server.access_log.isQuiescent());
    harness.server.access_log.requestReopen();
    // Deferred: the fd under the armed write must not be closed (§8).
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_reopened"));
    try testing.expectEqual(@as(u32, 0), harness.sim_io.log_reopen_count);

    try harness.drainSink();
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_reopened"));
    try testing.expectEqual(@as(u32, 1), harness.sim_io.log_reopen_count);
    // The line that was in flight landed before the swap; nothing lost.
    try testing.expectEqual(@as(u64, 1), lineCount(harness.sim_io.sinkBytes()));
    try testing.expect(harness.server.access_log.isQuiescent());
}

test "access log: SIGHUP on a stdout sink is a no-op" {
    var harness: Harness = undefined;
    try harness.setUp(testing.allocator, constants.access_log_buffer_bytes_min, 0);
    defer harness.tearDown();

    harness.server.access_log.requestReopen();
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_reopened"));
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_reopen_failed"));
    try testing.expectEqual(@as(u32, 0), harness.sim_io.log_reopen_count);
}

test "access log: a failed reopen keeps the old sink working" {
    var harness: Harness = undefined;
    try harness.setUpWithSink(
        testing.allocator,
        constants.access_log_buffer_bytes_min,
        0,
        .{ .file = "/virtual/access.log" },
    );
    defer harness.tearDown();

    harness.sim_io.injectLogReopenError();
    harness.server.access_log.requestReopen();
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_reopen_failed"));
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_reopened"));

    // The old fd was never closed: lines keep landing where they were.
    harness.emit(0);
    try harness.drainSink();
    try testing.expectEqual(@as(u64, 1), lineCount(harness.sim_io.sinkBytes()));
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_dropped"));
}

test "access log: a successful reopen heals a broken sink" {
    var harness: Harness = undefined;
    try harness.setUpWithSink(
        testing.allocator,
        constants.access_log_buffer_bytes_min,
        0,
        .{ .file = "/virtual/access.log" },
    );
    defer harness.tearDown();

    // Break the sink the §8 way: a write fails, the log stops, drops count.
    harness.sim_io.injectLogWriteError();
    harness.emit(0);
    try harness.drainSink();
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_write_failed"));
    harness.emit(1);
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_dropped"));

    // Rotation replaces the broken fd; the replacement gets its own verdict.
    harness.server.access_log.requestReopen();
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_reopened"));
    harness.emit(2);
    try harness.drainSink();
    try testing.expectEqual(@as(u64, 1), lineCount(harness.sim_io.sinkBytes()));
    // The heal is exact: the drop count did not move again.
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_dropped"));
    try testing.expect(harness.server.access_log.isQuiescent());
}

test "access log: SIGHUP racing the failing write still rotates and heals" {
    var harness: Harness = undefined;
    try harness.setUpWithSink(
        testing.allocator,
        constants.access_log_buffer_bytes_min,
        1_000_000, // In flight when both the failure and the signal land.
        .{ .file = "/virtual/access.log" },
    );
    defer harness.tearDown();

    harness.sim_io.injectLogWriteError();
    harness.emit(0);
    harness.server.access_log.requestReopen();
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_reopened"));

    // The write fails, marks the sink broken — and the pending rotation
    // fires right there, healing it in the same completion (§8).
    try harness.drainSink();
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_write_failed"));
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_reopened"));

    harness.emit(1);
    try harness.drainSink();
    try testing.expectEqual(@as(u64, 1), lineCount(harness.sim_io.sinkBytes()));
    try testing.expectEqual(@as(u64, 0), harness.counter("access_log_dropped"));
}

test "access log: repeated SIGHUPs under one write collapse to one swap" {
    var harness: Harness = undefined;
    try harness.setUpWithSink(
        testing.allocator,
        constants.access_log_buffer_bytes_min,
        1_000_000,
        .{ .file = "/virtual/access.log" },
    );
    defer harness.tearDown();

    harness.emit(0);
    // An operator's rotation script and a stray `killall -HUP` in the
    // same window: the flag is idempotent, so the write's completion
    // performs exactly one swap — the file both signals meant.
    harness.server.access_log.requestReopen();
    harness.server.access_log.requestReopen();
    try testing.expectEqual(@as(u32, 0), harness.sim_io.log_reopen_count);

    try harness.drainSink();
    try testing.expectEqual(@as(u64, 1), harness.counter("access_log_reopened"));
    try testing.expectEqual(@as(u32, 1), harness.sim_io.log_reopen_count);
    try testing.expect(harness.server.access_log.isQuiescent());
}
