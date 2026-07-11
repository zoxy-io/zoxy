//! Every static limit in one place. Total memory, fd count, and in-flight
//! ring ops are closed-form functions of these numbers (DESIGN.md §5, §8):
//! main.zig prints the budgets at startup, and the comptime asserts below
//! keep the relationships true. Pools never grow; exhaustion sheds load.

const std = @import("std");

const assert = std.debug.assert;

/// Upper bound on configured listeners.
pub const listeners_max: u16 = 8;

/// Connection slots (`Pool(Conn)`). In Phase 0 (L4 only) concurrency is
/// bounded by `relay_buffers_max`, not this; the surplus slots are sized
/// for Phase 1 keep-alive connections, which hold no relay buffer while
/// idle (§5).
pub const conn_slots_max: u32 = 4096;

/// Relay buffer pairs (`Pool(RelayBuffer)`) — the true bound on concurrent
/// L4 connections plus, in Phase 1, active L7 relays (§5, §6).
pub const relay_buffers_max: u32 = 1024;

/// Bytes per relay direction; a `RelayBuffer` is a pair of these.
pub const relay_buffer_bytes: u32 = 16 * 1024;

/// Listen backlog for every listener.
pub const accept_backlog: u31 = 1024;

/// Backoff before re-arming an accept that failed with a kernel-pressure
/// error (ENFILE-class). The failed connection stays in the backlog, so
/// an immediate re-arm would spin the loop at full speed (§8).
pub const accept_retry_delay_ms: u32 = 10;

/// io_uring submission queue entries. libxev requires a power of two and
/// caps entries at 8191, so 4096 is the maximum usable value; the kernel
/// fixes the completion queue at twice this (§4).
pub const ring_entries: u16 = 4096;

/// Worst-case simultaneously armed ring ops for one connection: two data
/// ops (strict per-direction alternation, §6), the deadline timer, and the
/// teardown timer-cancel. Closes are submitted only after the data ops
/// have delivered, so they never raise this peak (§8).
pub const conn_ops_max: u32 = 4;

/// Completions drained per loop tick before control returns to the kernel;
/// bounds both callback batches and `Io.now_ns` staleness (§4).
pub const loop_completions_per_tick_max: u32 = 256;

/// Upper bound on the config file size read at startup.
pub const config_bytes_max: u32 = 256 * 1024;

/// Upper bound on configured clusters.
pub const clusters_max: u16 = 16;

/// Upper bound on endpoints in one cluster.
pub const endpoints_per_cluster_max: u16 = 64;

/// Upper bound on every configured timeout — one hour. A timeout above
/// this is almost certainly a units mistake in the config.
pub const timeout_ms_max: u32 = 3_600_000;

/// Worst-case in-flight ring ops (§8: the ring is pre-budgeted, not shed):
/// every admitted connection at its op peak, one armed accept per
/// listener, the single async wakeup op for signals, and the server's
/// one drain-deadline timer.
pub const in_flight_ops_max: u32 =
    relay_buffers_max * conn_ops_max + listeners_max + 1 + 1;

/// Kernel completion queue capacity (io_uring fixes CQ at 2 × SQ).
pub const completion_queue_entries: u32 = 2 * @as(u32, ring_entries);

/// Worst-case fd count (§8: fds are pre-budgeted, not shed): stdio + ring
/// + async eventfd + listeners + two sockets per admitted connection + the
/// one transient just-accepted fd an admission decision is pending on.
pub const fds_max: u32 = 3 + 1 + 1 + listeners_max + 2 * relay_buffers_max + 1;

comptime {
    assert(std.math.isPowerOfTwo(ring_entries));
    assert(ring_entries <= 4096);
    assert(relay_buffers_max <= conn_slots_max);
    assert(relay_buffers_max >= 1);
    assert(listeners_max >= 1);
    assert(in_flight_ops_max <= completion_queue_entries);
    assert(conn_slots_max - 1 <= std.math.maxInt(u16));
    assert(relay_buffer_bytes >= 512);
    assert(clusters_max >= 1);
    assert(endpoints_per_cluster_max >= 1);
    assert(loop_completions_per_tick_max >= 1);
    assert(config_bytes_max >= 1024);
    assert(timeout_ms_max >= 1000);
    assert(accept_retry_delay_ms >= 1);
}

/// Total pool memory as a closed-form function of the limits. Slot sizes
/// are runtime parameters because `Conn` is generic over the Io backend;
/// the composition site passes `@sizeOf` of the concrete types and
/// main.zig prints the result at startup (§5).
pub fn memoryBytesTotal(conn_bytes: u64, relay_buffer_pair_bytes: u64) u64 {
    assert(conn_bytes > 0);
    assert(relay_buffer_pair_bytes >= 2 * @as(u64, relay_buffer_bytes));
    const total = conn_slots_max * conn_bytes +
        relay_buffers_max * relay_buffer_pair_bytes;
    assert(total > 0);
    return total;
}

test "budgets: in-flight ops fit the completion queue with headroom" {
    try std.testing.expect(in_flight_ops_max <= completion_queue_entries);
    // Headroom is deliberate: at least a quarter of the CQ stays free for
    // completion bursts even at the worst-case armed-op count.
    try std.testing.expect(in_flight_ops_max <= completion_queue_entries * 3 / 4);
}

test "budgets: memory total matches the closed form" {
    const conn_bytes: u64 = 2048;
    const pair_bytes: u64 = 2 * @as(u64, relay_buffer_bytes);
    const expected = @as(u64, conn_slots_max) * conn_bytes +
        @as(u64, relay_buffers_max) * pair_bytes;
    try std.testing.expectEqual(expected, memoryBytesTotal(conn_bytes, pair_bytes));
}

test "budgets: fd count stays under a typical hard limit" {
    // 4096 is the common RLIMIT_NOFILE hard ceiling for unprivileged
    // processes; startup asserts against the real limit (§8), this test
    // guards the defaults against drifting past the common case.
    try std.testing.expect(fds_max <= 4096);
}
