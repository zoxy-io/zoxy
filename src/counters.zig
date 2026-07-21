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
    /// §8 "watermarks before walls": pool pressure engaged (false→true
    /// crossings of a pool's high watermark), one counter per pool. Not
    /// sheds — biases that precede the walls — so they stay out of
    /// `reconcile`.
    relay_pressure_engaged: Value = Value.init(0),
    conn_pressure_engaged: Value = Value.init(0),
    upstream_pressure_engaged: Value = Value.init(0),
    /// §8 rung: request/idle deadline fired → teardown.
    deadline_expired: Value = Value.init(0),
    /// Upstream dial failed (refused/unreachable/canceled-by-teardown).
    upstream_connect_failed: Value = Value.init(0),
    /// L7 reject responses (§7): a malformed head (400), an oversize
    /// request line (414) or header section (431), or an unsupported
    /// method/upgrade (501). Not sheds — the connection was admitted and
    /// answered a static response, so it completes normally and stays out
    /// of `reconcile`'s shed sum; these are pure observability.
    l7_bad_request: Value = Value.init(0),
    l7_uri_too_long: Value = Value.init(0),
    l7_headers_too_large: Value = Value.init(0),
    l7_not_implemented: Value = Value.init(0),
    /// No route matched the request's canonical path (§7), answered 404.
    /// Like the other reject counters the connection completes normally.
    l7_no_route: Value = Value.init(0),
    /// A §7 filter rule rejected the request with its policy status
    /// (403/404/429/400). A reject, not a shed — the connection completes.
    l7_filtered: Value = Value.init(0),
    /// §8 rungs at the L7 request level, answered 503: relay buffers or
    /// upstream slots exhausted when a valid request needed them. Like
    /// the reject counters these connections complete normally, so they
    /// stay out of `reconcile`'s shed sum.
    l7_shed_relay_buffers: Value = Value.init(0),
    l7_shed_upstream_slots: Value = Value.init(0),
    /// Upstream leg failed before any response byte reached the client:
    /// answered 502 (§7, §8). A spent-replay second failure lands here
    /// too — the one free §7 replay never loops.
    l7_bad_gateway: Value = Value.init(0),
    /// The §8 request-deadline verdict: the deadline expired mid-exchange
    /// with no response byte sent, answered 504. A verdict, not a shed —
    /// the connection completes normally — but every one rides a
    /// `deadline_expired`, an inequality `reconcile` asserts.
    l7_gateway_timeout: Value = Value.init(0),
    /// Completed L7 exchanges: a parsed origin response relayed back.
    l7_responses: Value = Value.init(0),
    /// Exchanges served over a parked upstream connection instead of a
    /// fresh dial — the §3 reuse win, witnessed.
    upstream_reused: Value = Value.init(0),
    /// A reused connection was stale (dead on arrival, no response byte)
    /// and its request took the one free §7 replay on a fresh dial.
    /// Every replay rides a reuse — an inequality `reconcile` asserts.
    upstream_replayed: Value = Value.init(0),
    /// Parked upstream connections reaped by the idle sweep (§5).
    upstream_idle_reaped: Value = Value.init(0),
    /// §8 rung: ENOBUFS/ENOMEM-class op failures, one per treated op —
    /// across every completion (accept, connect, setNodelay, and the relay
    /// recv/send data path).
    kernel_pressure_errors: Value = Value.init(0),
    /// Admin/metrics scrapes whose full response was written (§8, PLANS.md
    /// §243). Pure observability: the admin plane sits entirely outside
    /// `reconcile`'s accepted/admitted/shed accounting, so these never enter
    /// the gate identity.
    admin_served: Value = Value.init(0),
    /// Admin scrapes reaped by the scrape deadline before completing — a
    /// stalled or slowloris client freed from the single reserved slot (§8).
    admin_reaped: Value = Value.init(0),
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

    /// The metric-name prefix for the Prometheus exposition rendering
    /// (`render`). Every counter is exposed as `zoxy_<field>`.
    pub const metric_prefix = "zoxy_";

    /// Exact byte bound on a full `render` (§5: the caller sizes a fixed
    /// buffer to it, so rendering never allocates and never truncates).
    /// Per counter: a `# TYPE …` line plus a sample line whose value is at
    /// most `maxInt(u64)` — 20 digits. Comptime-summed over the real field
    /// set, so it tracks the counters as they are added or removed.
    pub const render_bytes_max: usize = blk: {
        const u64_digits_max = 20; // len("18446744073709551615")
        var total: usize = 0;
        for (@typeInfo(Counters).@"struct".fields) |field| {
            if (field.type != Value) continue;
            const name_len = metric_prefix.len + field.name.len;
            total += "# TYPE ".len + name_len + " counter\n".len;
            total += name_len + " ".len + u64_digits_max + "\n".len;
        }
        break :blk total;
    };

    /// Render every counter as Prometheus exposition text into a
    /// caller-owned buffer (zero-alloc, §5) — the single renderer shared by
    /// the SIGUSR1 `dump` and any future admin endpoint. The buffer must be
    /// at least `render_bytes_max`; that bound is exact, so a correctly
    /// sized caller can never truncate. Returns the filled prefix.
    pub fn render(counters: *const Counters, buffer: []u8) []const u8 {
        assert(buffer.len >= render_bytes_max);
        var cursor: usize = 0;
        inline for (@typeInfo(Counters).@"struct".fields) |field| {
            if (field.type != Value) continue;
            // The format string is fully comptime (only the value is
            // runtime), so bufPrint cannot fail for a value that fits u64
            // in a buffer sized to render_bytes_max.
            const written = std.fmt.bufPrint(
                buffer[cursor..],
                "# TYPE " ++ metric_prefix ++ field.name ++ " counter\n" ++
                    metric_prefix ++ field.name ++ " {d}\n",
                .{counters.get(field.name)},
            ) catch unreachable;
            cursor += written.len;
        }
        assert(cursor >= 1);
        assert(cursor <= render_bytes_max);
        return buffer[0..cursor];
    }

    /// Phase 0 exposure (§8): SIGUSR1 dumps the Prometheus rendering to
    /// stderr through the signal seam; the admin plane stays deferred
    /// (docs/PLANS.md). Shares `render` so the dump and a future scrape
    /// endpoint never disagree on the wire format.
    pub fn dump(counters: *const Counters) void {
        var buffer: [render_bytes_max]u8 = undefined;
        const text = counters.render(&buffer);
        assert(text.len <= buffer.len);
        std.debug.print("{s}", .{text});
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
        // Every 504 verdict rides a deadline expiry (§8) — the verdict
        // path increments both, the teardown path only the expiry.
        assert(counters.get("l7_gateway_timeout") <= counters.get("deadline_expired"));
        // Every §7 replay rides a checkout: only a reused connection's
        // early failure is blamed on staleness.
        assert(counters.get("upstream_replayed") <= counters.get("upstream_reused"));
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

test "counters: render emits Prometheus exposition for every field" {
    var counters: Counters = .{};
    counters.increment("accepted");
    counters.increment("accepted");
    counters.increment("l7_responses");

    var buffer: [Counters.render_bytes_max]u8 = undefined;
    const text = counters.render(&buffer);

    // Every counter appears exactly once as a TYPE line and a sample line,
    // and the sample carries the live value.
    try std.testing.expect(std.mem.indexOf(u8, text, "# TYPE zoxy_accepted counter\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_accepted 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_l7_responses 1\n") != null);
    // Untouched counters still render at zero — a scrape sees the whole set.
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_completed 0\n") != null);

    // One TYPE line per counter field: the rendering is complete.
    var type_lines: usize = 0;
    var search: usize = 0;
    while (std.mem.indexOfPos(u8, text, search, "# TYPE ")) |at| {
        type_lines += 1;
        search = at + "# TYPE ".len;
    }
    var field_count: usize = 0;
    inline for (@typeInfo(Counters).@"struct".fields) |field| {
        if (field.type == Counters.Value) field_count += 1;
    }
    try std.testing.expectEqual(field_count, type_lines);
}

test "counters: render bound holds at the maximum value" {
    // The render_bytes_max bound must survive every counter at maxInt(u64)
    // — the widest possible sample line — so a saturated proxy never
    // truncates or overruns the buffer.
    var counters: Counters = .{};
    inline for (@typeInfo(Counters).@"struct".fields) |field| {
        if (field.type == Counters.Value) {
            @field(counters, field.name).store(std.math.maxInt(u64), .monotonic);
        }
    }
    var buffer: [Counters.render_bytes_max]u8 = undefined;
    const text = counters.render(&buffer);
    // With every value at its 20-digit maximum, the render fills the buffer
    // exactly — proving render_bytes_max is a tight bound, not just an upper
    // one (the "exact" claim in its doc comment).
    try std.testing.expectEqual(Counters.render_bytes_max, text.len);
    try std.testing.expect(std.mem.indexOf(u8, text, "18446744073709551615\n") != null);
}
