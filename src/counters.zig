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
    /// answered a static response, so they stay out of `reconcile`'s shed
    /// sum; these are pure observability.
    ///
    /// They do not share one persistence rule, because they do not share
    /// one cause. `l7_uri_too_long` and `l7_headers_too_large` always
    /// close: the parser could not find the message boundary, so neither
    /// can the turnaround. `l7_not_implemented` answers a head that parsed
    /// cleanly and follows the general keep rule (§8). `l7_bad_request`
    /// covers both — a parser-rejected head, which closes, and a head that
    /// parsed but whose target would not canonicalize, which keeps. The
    /// counter deliberately does not split: the client sees one status,
    /// and `staticResponseResyncable` decides from the stream rather than
    /// from the status.
    l7_bad_request: Value = Value.init(0),
    l7_uri_too_long: Value = Value.init(0),
    l7_headers_too_large: Value = Value.init(0),
    l7_not_implemented: Value = Value.init(0),
    /// No route matched the request's canonical path (§7), answered 404.
    /// A valid head, so the connection keeps serving when its stream is
    /// still on a message boundary — see `l7_shed_*` below.
    l7_no_route: Value = Value.init(0),
    /// A §7 filter rule rejected the request with its policy status
    /// (403/404/429/400). A reject, not a shed; same persistence rule as
    /// `l7_no_route`.
    l7_filtered: Value = Value.init(0),
    /// §8 rungs at the L7 request level, answered 503: relay buffers or
    /// upstream slots exhausted when a valid request needed them. Like the
    /// reject counters, the connection was admitted, so these stay out of
    /// `reconcile`'s shed sum — but it does not necessarily *end* here: a
    /// shed whose client stream is still on a message boundary keeps
    /// serving (§8 "then keep or close per pressure"), so one connection
    /// can carry many of these. Counting them is not counting connections,
    /// and the ratio to `accepted` is the churn signal.
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
    /// Responses whose coalesced body excess did not fit beside the
    /// rendered head and left in a second write of its own (§7) — one
    /// extra ring round trip, paid whenever the origin's delivery fills
    /// the head buffer and the render grows the head. The client receives
    /// the same bytes either way, so this counter is the only witness
    /// that the branch ran: without it neither an operator nor a test can
    /// tell the two paths apart (#77). Pure observability, so it stays
    /// out of `reconcile`.
    l7_response_excess_sent: Value = Value.init(0),
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

    /// Live pool occupancy against capacity (§8 "watermarks before
    /// walls"). Gauges, not counters: they go both ways, and a scrape
    /// wants the level, not the history.
    ///
    /// Read from the pools at render time rather than mirrored on every
    /// acquire/release — a mirror is one missed release away from
    /// disagreeing with the pool it describes, and the pools already
    /// count what this reports. `Server.gauges` is the only producer.
    ///
    /// Why they exist: without them a scrape sees a wall only *after* it
    /// is hit. The `shed_*` and `l7_shed_*` counters fire at exhaustion
    /// and the `*_pressure_engaged` counters at the 3/4 watermark, so a
    /// pool can run at 74% forever and look identical to an idle one.
    /// The occupancy is what shows the approach.
    pub const Gauges = struct {
        conn_slots_in_use: u32,
        conn_slots_capacity: u32,
        relay_buffers_in_use: u32,
        relay_buffers_capacity: u32,
        /// Upstream slots serving a request right now. This is the level
        /// that reaches `upstream_slots_capacity` and turns a request
        /// into `l7_shed_upstream_slots` (§8).
        upstream_slots_leased: u32,
        /// Upstream slots held open for reuse (§5). Parked slots are
        /// *occupied*: leased + parked is what the wall is measured
        /// against, which is why both are reported rather than a single
        /// in-use figure.
        upstream_slots_parked: u32,
        upstream_slots_capacity: u32,

        /// The invariant every producer owes: a level never exceeds its
        /// own capacity, and the two upstream levels share one.
        pub fn valid(gauges: *const Gauges) bool {
            if (gauges.conn_slots_in_use > gauges.conn_slots_capacity) return false;
            if (gauges.relay_buffers_in_use > gauges.relay_buffers_capacity) return false;
            const upstream_in_use = @as(u64, gauges.upstream_slots_leased) +
                gauges.upstream_slots_parked;
            return upstream_in_use <= gauges.upstream_slots_capacity;
        }
    };

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
    /// Per metric: a `# TYPE …` line plus a sample line whose value is at
    /// most its type's maximum — 20 digits for a `u64` counter, 10 for a
    /// `u32` gauge. Comptime-summed over the real field sets, so it tracks
    /// both as they are added or removed.
    pub const render_bytes_max: usize = blk: {
        const u64_digits_max = 20; // len("18446744073709551615")
        const u32_digits_max = 10; // len("4294967295")
        var total: usize = 0;
        for (@typeInfo(Counters).@"struct".fields) |field| {
            if (field.type != Value) continue;
            const name_len = metric_prefix.len + field.name.len;
            total += "# TYPE ".len + name_len + " counter\n".len;
            total += name_len + " ".len + u64_digits_max + "\n".len;
        }
        for (@typeInfo(Gauges).@"struct".fields) |field| {
            assert(field.type == u32);
            const name_len = metric_prefix.len + field.name.len;
            total += "# TYPE ".len + name_len + " gauge\n".len;
            total += name_len + " ".len + u32_digits_max + "\n".len;
        }
        break :blk total;
    };

    /// Render every counter and gauge as Prometheus exposition text into a
    /// caller-owned buffer (zero-alloc, §5) — the single renderer shared by
    /// the SIGUSR1 `dump` and the admin endpoint. The buffer must be
    /// at least `render_bytes_max`; that bound is exact, so a correctly
    /// sized caller can never truncate. Returns the filled prefix.
    ///
    /// `gauges` is a snapshot the caller reads off the live pools, not
    /// state this module owns: `counters.zig` is imported by `Server.zig`,
    /// so the dependency cannot run the other way.
    pub fn render(counters: *const Counters, gauges: *const Gauges, buffer: []u8) []const u8 {
        // `gauges.valid()` is asserted where the snapshot is produced
        // (`Server.gauges`), not here: the renderer must stay able to emit
        // every field at its type's maximum, which is what makes
        // `render_bytes_max` an exactly reachable bound rather than a
        // merely sufficient one.
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
        inline for (@typeInfo(Gauges).@"struct".fields) |field| {
            // Same argument as the counter loop above, against the gauge
            // half of the bound: the format string is comptime and every
            // gauge is a u32, whose widest rendering `render_bytes_max`
            // reserves 10 digits for.
            const written = std.fmt.bufPrint(
                buffer[cursor..],
                "# TYPE " ++ metric_prefix ++ field.name ++ " gauge\n" ++
                    metric_prefix ++ field.name ++ " {d}\n",
                .{@field(gauges, field.name)},
            ) catch unreachable;
            cursor += written.len;
        }
        assert(cursor >= 1);
        assert(cursor <= render_bytes_max);
        return buffer[0..cursor];
    }

    /// Phase 0 exposure (§8): SIGUSR1 dumps the Prometheus rendering to
    /// stderr through the signal seam. Shares `render` so the dump and the
    /// scrape endpoint never disagree on the wire format.
    pub fn dump(counters: *const Counters, gauges: *const Gauges) void {
        var buffer: [render_bytes_max]u8 = undefined;
        const text = counters.render(gauges, &buffer);
        assert(text.len <= buffer.len);
        std.debug.print("{s}", .{text});
    }

    /// The §9 invariant: admitted work is completed or still active, and
    /// every accepted connection was admitted or shed — no third outcome.
    /// The prefix that makes a counter part of the gate identity below.
    /// Naming is the membership rule on purpose: every rung is witnessed
    /// through `Server.witnessShed`, which comptime-asserts the name (§8), so
    /// a new admission shed joins `shedTotal` by being named rather than by
    /// being remembered — which is what the previous hand-written sum could
    /// not promise.
    ///
    /// The `l7_shed_*` counters sit outside it deliberately: those
    /// connections were admitted and answered a 503, so they complete
    /// normally and belong to the flow identity, not the gate one.
    const shed_prefix = "shed_";

    /// How many counters the prefix selects. Comptime, so a rename that
    /// emptied the sum would fail the build instead of making the gate
    /// identity vacuously true.
    const shed_rung_count: usize = blk: {
        var count: usize = 0;
        for (@typeInfo(Counters).@"struct".fields) |field| {
            if (field.type != Value) continue;
            if (std.mem.startsWith(u8, field.name, shed_prefix)) count += 1;
        }
        break :blk count;
    };

    /// Every admission shed, summed off the field set rather than a list.
    fn shedTotal(counters: *const Counters) u64 {
        comptime assert(shed_rung_count >= 1);
        var total: u64 = 0;
        inline for (@typeInfo(Counters).@"struct".fields) |field| {
            if (field.type != Value) continue;
            if (comptime !std.mem.startsWith(u8, field.name, shed_prefix)) continue;
            total += counters.get(field.name);
        }
        return total;
    }

    pub fn reconcile(counters: *const Counters, active_count: u32) bool {
        const admitted = counters.get("admitted");
        const completed = counters.get("completed");
        const accepted = counters.get("accepted");
        const shed = counters.shedTotal();
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

/// A valid, distinguishable snapshot for the render tests.
const test_gauges: Counters.Gauges = .{
    .conn_slots_in_use = 7,
    .conn_slots_capacity = 64,
    .relay_buffers_in_use = 3,
    .relay_buffers_capacity = 32,
    .upstream_slots_leased = 5,
    .upstream_slots_parked = 11,
    .upstream_slots_capacity = 16,
};

test "counters: render emits Prometheus exposition for every field" {
    var counters: Counters = .{};
    counters.increment("accepted");
    counters.increment("accepted");
    counters.increment("l7_responses");

    var buffer: [Counters.render_bytes_max]u8 = undefined;
    const text = counters.render(&test_gauges, &buffer);

    // Every counter appears exactly once as a TYPE line and a sample line,
    // and the sample carries the live value.
    try std.testing.expect(std.mem.indexOf(u8, text, "# TYPE zoxy_accepted counter\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_accepted 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_l7_responses 1\n") != null);
    // Untouched counters still render at zero — a scrape sees the whole set.
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_completed 0\n") != null);

    // Gauges ride the same rendering, typed `gauge` — a scrape that read
    // an occupancy as a counter would chart nonsense through `rate()`.
    try std.testing.expect(std.mem.indexOf(u8, text, "# TYPE zoxy_upstream_slots_leased gauge\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_upstream_slots_leased 5\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_upstream_slots_parked 11\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_upstream_slots_capacity 16\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_conn_slots_in_use 7\n") != null);
    // No gauge is rendered as a counter, and no counter as a gauge.
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_upstream_slots_leased counter") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_accepted gauge") == null);

    // One TYPE line per counter *and* gauge field: the rendering is complete.
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
    field_count += @typeInfo(Counters.Gauges).@"struct".fields.len;
    try std.testing.expectEqual(field_count, type_lines);
}

test "counters: gauge validity is a level-against-capacity rule" {
    try std.testing.expect(test_gauges.valid());
    // Parked slots occupy the pool too: leased + parked is what the wall
    // is measured against, so a pair that fits individually but not
    // together is invalid — the case a single in-use figure would hide.
    var over = test_gauges;
    over.upstream_slots_parked = 12;
    try std.testing.expect(!over.valid());
    var conn_over = test_gauges;
    conn_over.conn_slots_in_use = conn_over.conn_slots_capacity + 1;
    try std.testing.expect(!conn_over.valid());
    var relay_over = test_gauges;
    relay_over.relay_buffers_in_use = relay_over.relay_buffers_capacity + 1;
    try std.testing.expect(!relay_over.valid());
    // A pool sitting exactly at its wall is valid — that is the state the
    // gauges exist to show.
    var full = test_gauges;
    full.upstream_slots_leased = full.upstream_slots_capacity;
    full.upstream_slots_parked = 0;
    try std.testing.expect(full.valid());
}

test "counters: render bound holds at the maximum value" {
    // The render_bytes_max bound must survive every counter at maxInt(u64)
    // and every gauge at maxInt(u32) — the widest possible sample lines —
    // so a saturated proxy never truncates or overruns the buffer.
    var counters: Counters = .{};
    inline for (@typeInfo(Counters).@"struct".fields) |field| {
        if (field.type == Counters.Value) {
            @field(counters, field.name).store(std.math.maxInt(u64), .monotonic);
        }
    }
    var gauges: Counters.Gauges = undefined;
    inline for (@typeInfo(Counters.Gauges).@"struct".fields) |field| {
        @field(gauges, field.name) = std.math.maxInt(u32);
    }
    var buffer: [Counters.render_bytes_max]u8 = undefined;
    const text = counters.render(&gauges, &buffer);
    // With every value at its type's maximum, the render fills the buffer
    // exactly — proving render_bytes_max is a tight bound, not just an upper
    // one (the "exact" claim in its doc comment). This is also why `render`
    // does not assert `gauges.valid()`: an all-maximum snapshot is not a
    // producible pool state, but it *is* the widest rendering.
    try std.testing.expectEqual(Counters.render_bytes_max, text.len);
    try std.testing.expect(std.mem.indexOf(u8, text, "18446744073709551615\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "4294967295\n") != null);
    try std.testing.expect(!gauges.valid());
}

test "counters: the gate identity sums exactly today's admission rungs" {
    // Membership is by name (`shed_prefix`), so this pins what that rule
    // currently selects: a new `shed_*` counter changes the gate identity,
    // and should change this list in the same commit that adds it. The
    // `l7_shed_*` rejects must stay out — those connections were admitted.
    const expected = [_][]const u8{
        "shed_conn_slots",
        "shed_relay_buffers",
        "shed_draining",
    };
    comptime var actual_count: usize = 0;
    inline for (@typeInfo(Counters).@"struct".fields) |field| {
        if (field.type != Counters.Value) continue;
        if (!comptime std.mem.startsWith(u8, field.name, Counters.shed_prefix)) continue;
        actual_count += 1;
        comptime var listed = false;
        inline for (expected) |name| {
            if (comptime std.mem.eql(u8, name, field.name)) listed = true;
        }
        if (!listed) {
            std.debug.print("unlisted shed counter: {s}\n", .{field.name});
            return error.UnlistedShedCounter;
        }
    }
    try std.testing.expectEqual(expected.len, actual_count);
}

test "counters: an admission shed and an L7 reject land on opposite sides" {
    var counters: Counters = .{};
    // A rung that fires before admission keeps the gate balanced on its own.
    counters.increment("accepted");
    counters.increment("shed_relay_buffers");
    try std.testing.expect(counters.reconcile(0));

    // The L7 503 is not a gate shed: its connection was admitted, so it has
    // to complete for the books to balance.
    counters.increment("accepted");
    counters.increment("admitted");
    counters.increment("l7_shed_relay_buffers");
    try std.testing.expect(!counters.reconcile(0));
    counters.increment("completed");
    try std.testing.expect(counters.reconcile(0));
}
