//! Per-rung and lifecycle counters (DESIGN.md §8): written only by the
//! loop thread as relaxed atomics — one writer, any number of readers —
//! so a future metrics/admin thread reads without a data race and
//! single-writer stays intact. The simulator asserts `reconcile` under
//! every seed: work is never lost, every shed is witnessed.

const std = @import("std");

const assert = std.debug.assert;

pub const Counters = struct {
    /// Connections the kernel handed us.
    accepted: Value = Value.init(0),
    /// Connections that passed the admission gate (slot + relay buffer).
    admitted: Value = Value.init(0),
    /// Admitted connections fully torn down (slot released).
    completed: Value = Value.init(0),
    /// §8 rung: conn slots exhausted at accept → RST.
    shed_conn_slots: Value = Value.init(0),
    /// §8 rung: relay buffers exhausted at admission → close.
    shed_relay_buffers: Value = Value.init(0),
    /// §8 rung: request/idle deadline fired → teardown.
    deadline_expired: Value = Value.init(0),
    /// Upstream dial failed (refused/unreachable/canceled-by-teardown).
    upstream_connect_failed: Value = Value.init(0),
    /// §8 rung: ENOBUFS/ENOMEM-class op failures, one per treated op.
    kernel_pressure_errors: Value = Value.init(0),
    /// Accept completions that landed after the drain began (§8).
    shed_draining: Value = Value.init(0),
    /// Drain deadline tore down stragglers (§8).
    drained_at_deadline: Value = Value.init(0),

    const Value = std.atomic.Value(u64);

    /// Loop thread only — the single writer (§8).
    pub fn increment(counters: *Counters, comptime name: []const u8) void {
        const previous = @field(counters, name).fetchAdd(1, .monotonic);
        assert(previous < std.math.maxInt(u64));
    }

    pub fn get(counters: *const Counters, comptime name: []const u8) u64 {
        return @field(counters, name).load(.monotonic);
    }

    /// The §9 invariant: admitted work is completed or still active, and
    /// every accepted connection was admitted or shed — no third outcome.
    pub fn reconcile(counters: *const Counters, active_count: u32) bool {
        const admitted = counters.get("admitted");
        const completed = counters.get("completed");
        const accepted = counters.get("accepted");
        const shed = counters.get("shed_conn_slots") +
            counters.get("shed_relay_buffers") +
            counters.get("shed_draining");
        assert(completed <= admitted);
        assert(admitted <= accepted);
        const flow_holds = admitted == completed + active_count;
        const gate_holds = accepted == admitted + shed;
        return flow_holds and gate_holds;
    }
};

test "counters: reconcile holds across a lifecycle" {
    var counters: Counters = .{};
    try std.testing.expect(counters.reconcile(0));

    counters.increment("accepted");
    counters.increment("admitted");
    try std.testing.expect(counters.reconcile(1));
    try std.testing.expect(!counters.reconcile(0));

    counters.increment("completed");
    try std.testing.expect(counters.reconcile(0));

    counters.increment("accepted");
    counters.increment("shed_conn_slots");
    try std.testing.expect(counters.reconcile(0));
    try std.testing.expectEqual(@as(u64, 1), counters.get("shed_conn_slots"));
}
