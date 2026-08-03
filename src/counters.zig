//! Per-rung and lifecycle counters (DESIGN.md §8): written only by the
//! loop thread as relaxed atomics — one writer, any number of readers —
//! so a future metrics/admin thread reads without a data race and
//! single-writer stays intact. The simulator asserts `reconcile` under
//! every seed: work is never lost, every shed is witnessed.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const io_module = @import("io/io.zig");
const upstream_module = @import("net/upstream.zig");

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
    /// The head-buffer ring's crossing (§5, §8). Unlike the other three
    /// this bias drives nothing — an idle connection holds no head
    /// buffer, so there is no idle occupancy a timeout could evict — and
    /// the counter is the alert an operator sizes `limits.head_buffers`
    /// by, before the wall (`l7_shed_head_buffers`) starts refusing.
    head_pressure_engaged: Value = Value.init(0),
    /// The upstream head pool's crossing, on the same no-bias terms: a
    /// parked upstream holds no head buffer, so there is nothing idle to
    /// evict — the alert for sizing `limits.upstream_head_buffers`.
    upstream_head_pressure_engaged: Value = Value.init(0),
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
    /// one cause. `l7_uri_too_long` and `l7_headers_too_large` close
    /// when the parser could not find the message boundary — their
    /// original spelling — with one #176 exception on the first: a
    /// redirect whose composed Location cannot be carried answers 414
    /// from a request that *did* parse, a clean boundary the ordinary
    /// keep-or-close decision then reads (§8). `l7_not_implemented` answers a head that parsed
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
    /// A §7 filter rule answered the request with a redirect (#176):
    /// one of the closed statuses plus a Location rendered per request.
    /// `l7_filtered`'s sibling — admitted and answered, so outside
    /// `reconcile`'s shed sum — but not folded into it: "policy refused
    /// this" and "policy sent this elsewhere" are opposite directions
    /// on a dashboard, and a redirect storm is a different diagnosis
    /// from a reject storm.
    l7_redirected: Value = Value.init(0),
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
    /// §8 rung: a client spoke while the head-buffer ring was empty —
    /// answered 503 and, uniquely among the sheds, *always* closed: the
    /// request's bytes were never read (no buffer was ever bound), so a
    /// kept connection would re-arm onto the same bytes and shed the same
    /// request forever. `respond` enforces the close at comptime.
    l7_shed_head_buffers: Value = Value.init(0),
    /// §8 rung: the upstream head pool was empty at the request-head
    /// render — answered 503 with the ordinary keep-or-close rules (the
    /// request was fully read and parsed, unlike the ring rung above).
    /// Distinct from `l7_shed_upstream_slots` the way that one is
    /// distinct from the endpoint cap: slots say the proxy ran out of
    /// connections, this says it ran out of head staging — different
    /// knobs (`upstream_slots` vs `upstream_head_buffers`), and an
    /// operator widening the wrong one fixes nothing.
    l7_shed_upstream_head_buffers: Value = Value.init(0),
    /// §8 requests answered 503 because every endpoint of their cluster
    /// was already carrying its configured `max_inflight`. Distinct from
    /// `l7_shed_upstream_slots` on purpose: that one says this proxy ran
    /// out of slots, this one says the origins were protected — opposite
    /// diagnoses, and an operator widening the wrong limit fixes neither.
    l7_shed_endpoint_inflight: Value = Value.init(0),
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
    /// §7 active health probes dispatched — one per checked endpoint per
    /// sweep. Not in the gate identity: a probe is the prober's own dial,
    /// never an accepted connection.
    health_probes_sent: Value = Value.init(0),
    /// Probes that failed: refused, unreachable, timed out under the
    /// connect budget, or kernel pressure on our side (§7). The pressure
    /// case also lands in `kernel_pressure_connect`, same as a data-path
    /// dial.
    health_probes_failed: Value = Value.init(0),
    /// Endpoints ejected from balancing after `health_probe_fall`
    /// consecutive failed probes (§7). Their parked connections are
    /// closed at the transition (§5, `health_parked_closed`).
    health_endpoint_down: Value = Value.init(0),
    /// Ejected endpoints restored to balancing after `health_probe_rise`
    /// consecutive successful probes (§7).
    health_endpoint_up: Value = Value.init(0),
    /// Parked upstream connections closed because their endpoint was
    /// ejected (§5): a parked socket to a dead origin is a stale replay
    /// waiting to be spent.
    health_parked_closed: Value = Value.init(0),
    /// Probe deadlines that fired *after* the verdict was already known —
    /// the §4 race between a timer and its own cancel, where the delivery
    /// is accounting and nothing else. Counts the race only while
    /// probing: the same shape during a stop is discarded with the rest
    /// of the prober's drain, where no verdict is waiting on it.
    ///
    /// It exists to be small. A prober that reaches its verdict and then
    /// forgets to cancel the deadline still reports every check
    /// correctly; the only thing it gets wrong is how long each probe
    /// holds the prober, and this counter is the difference between the
    /// race happening occasionally and it happening every time (#130).
    health_probe_deadline_raced: Value = Value.init(0),
    /// §8 rung: ENOBUFS/ENOMEM-class op failures, one per treated op —
    /// across every completion (accept, connect, setNodelay, and the relay
    /// recv/send data path). The total; `kernel_pressure_by_op` below
    /// partitions it.
    kernel_pressure_errors: Value = Value.init(0),
    /// The same failures split by the syscall that produced them.
    ///
    /// Why the split exists: a c10k run recorded 227,628 of these against
    /// 736,843 churned connections, and one number could not distinguish
    /// "the NIC queue is full on send" from "we are out of fds on accept"
    /// — opposite problems with opposite fixes. The op says which syscall
    /// to look at; the cause counters below say what to do about it.
    ///
    /// `kernelPressureTotal` must equal `kernel_pressure_errors` — every
    /// witness increments exactly one of these alongside the total, which
    /// `reconcile` asserts.
    kernel_pressure_accept: Value = Value.init(0),
    kernel_pressure_connect: Value = Value.init(0),
    kernel_pressure_recv: Value = Value.init(0),
    kernel_pressure_send: Value = Value.init(0),
    kernel_pressure_set_option: Value = Value.init(0),
    /// The same failures split a second way — by *why* the kernel refused,
    /// recovered from the errno the audited libxev fork now keeps on the
    /// completion (zoxy-io/libxev#2). Two partitions of one total, because
    /// the op and the cause answer different questions: the op says which
    /// syscall to look at, the cause says what to do about it.
    ///
    /// Shed load for `out_of_buffers`/`out_of_memory`; raise a limit for
    /// `fd_limit`; widen the port range or reuse connections for
    /// `address_unavailable`. Reading them off one number was the original
    /// problem — `.other` keeps that honest by never pretending to be a
    /// classification, and `kernel_pressure_last_errno` (a gauge) carries
    /// the raw value so an unlisted errno is still a lead.
    kernel_pressure_out_of_buffers: Value = Value.init(0),
    kernel_pressure_out_of_memory: Value = Value.init(0),
    kernel_pressure_fd_limit: Value = Value.init(0),
    kernel_pressure_address_unavailable: Value = Value.init(0),
    kernel_pressure_other_cause: Value = Value.init(0),
    /// Admin/metrics scrapes whose full response was written (§8).
    /// Pure observability: the admin plane sits entirely outside
    /// `reconcile`'s accepted/admitted/shed accounting, so these never enter
    /// the gate identity.
    admin_served: Value = Value.init(0),
    /// Admin scrapes reaped by the scrape deadline before completing — a
    /// stalled or slowloris client freed from the single reserved slot (§8).
    admin_reaped: Value = Value.init(0),
    /// Access-log lines rendered and accepted into a staging buffer (§8),
    /// and lines dropped because there was no room for them or the sink
    /// had already failed. Every loggable outcome increments exactly one
    /// of the two, so their sum is how many exchanges and connections the
    /// log had to describe — the identity the simulator checks.
    ///
    /// A drop is backpressure, not a bug: the sink is a pipe an operator
    /// owns, and §8's answer to a resource running out is to shed the
    /// newest work rather than to block. A nonzero `access_log_dropped`
    /// says the log is incomplete and by how much; a rising one says the
    /// sink cannot keep up with the request rate.
    access_log_lines: Value = Value.init(0),
    access_log_dropped: Value = Value.init(0),
    /// Sink writes that failed (§8). At most one is ever recorded: the
    /// first failure marks the sink broken, because what reaches here is a
    /// closed pipe or a dead file rather than a transient — the ring
    /// already absorbed every would-block. Nonzero therefore means two
    /// things at once: some already-accepted lines never reached the sink,
    /// and every line since has been counted as dropped.
    access_log_write_failed: Value = Value.init(0),
    /// SIGHUP rotations of the `file` sink that took (§8): the old fd
    /// closed between writes, the path reopened, and — when the sink had
    /// been marked broken — the break healed, because what broke was the
    /// fd this rotation just replaced.
    access_log_reopened: Value = Value.init(0),
    /// SIGHUP rotations that could not open the path (§8). The old fd is
    /// kept and lines keep landing where they already were: a failed
    /// rotation must not destroy a working log. Rising alongside a
    /// rotation schedule means the log directory has a problem the
    /// rotation tooling is not reporting.
    access_log_reopen_failed: Value = Value.init(0),
    /// §8 L4 connections closed because every endpoint of their cluster
    /// was already carrying its configured `max_inflight`. An L4 listener
    /// has no way to say "try later", so the ladder's L4 answer applies:
    /// close. Deliberately **not** `shed_`-prefixed — the connection was
    /// admitted before an endpoint could be picked, so it counts in the
    /// flow identity as an ordinary completion, and folding it into the
    /// admission-gate sum would make that identity false.
    l4_shed_endpoint_inflight: Value = Value.init(0),
    /// §7 client-address forwarding: an inbound `X-Forwarded-For` chain
    /// too long to carry, dropped so the emitted line states only the peer
    /// this proxy observed. Not an error — the bound exists because a chain
    /// is client-supplied and unbounded by the protocol — but a rising
    /// count means someone is sending chains no real topology produces,
    /// which is worth knowing.
    forwarded_chain_dropped: Value = Value.init(0),
    /// §6 PROXY protocol receive (#142): connections a `proxy_protocol`
    /// listener closed because the peer's opening bytes were not a valid
    /// header — malformed, over `proxy_header_bytes_max`, or EOF
    /// mid-header. Deliberately **not** `shed_`-prefixed, on
    /// `l4_shed_endpoint_inflight`'s exact reasoning: the connection was
    /// admitted before its header could be judged, so it counts in the
    /// flow identity as an ordinary completion. A rising count means
    /// something other than the configured fronting proxy is reaching a
    /// listener whose mode exists to refuse exactly that.
    l4_proxy_header_invalid: Value = Value.init(0),
    /// Headers a `proxy_protocol` listener accepted, address-bearing or
    /// not — `LOCAL` and `UNKNOWN` keep the observed peer, and a
    /// fronting proxy's health checks arrive exactly that way (§6).
    l4_proxy_header_accepted: Value = Value.init(0),
    /// Headers staged for a sending cluster's origin (#142 send), one
    /// per dialed L4 connection there. Counted at the stage, not the
    /// wire: a dial that fails tears the connection down whole, so the
    /// difference is exactly the fates `upstream_connect_failed` and the
    /// teardown counters already witness. Pure observability.
    l4_proxy_header_sent: Value = Value.init(0),
    /// Accept completions that landed after the drain began (§8).
    shed_draining: Value = Value.init(0),
    /// Drain deadline tore down stragglers (§8).
    drained_at_deadline: Value = Value.init(0),

    const Value = std.atomic.Value(u64);

    /// Every counter's field name, in declaration order — the one place
    /// the set is enumerated. `render` walks it, `render_bytes_max` sizes
    /// against it, `shedTotal` picks the `shed_` prefix out of it, and the
    /// §9 sweep's coverage census requires each name to have moved. A
    /// counter added above joins all four without being listed anywhere
    /// else.
    pub const names: []const []const u8 = blk: {
        var collected: []const []const u8 = &.{};
        for (@typeInfo(Counters).@"struct".fields) |field| {
            if (field.type != Value) continue;
            collected = collected ++ [_][]const u8{field.name};
        }
        break :blk collected;
    };

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
        /// Head-ring buffers bound to connections right now (§5). This is
        /// the level whose wall answers `l7_shed_head_buffers`; with the
        /// ring sized to its default (conn_slots) it cannot reach the
        /// capacity, and the *gap* between this and `conn_slots_in_use`
        /// is the density the ring buys — idle connections appear in the
        /// conn level but not here.
        head_buffers_in_use: u32,
        head_buffers_capacity: u32,
        /// Upstream head buffers held by exchanges right now (§5): the
        /// render-to-park window, so with parking healthy this sits far
        /// below the leased count — the gap is what the pool buys.
        upstream_head_buffers_in_use: u32,
        upstream_head_buffers_capacity: u32,
        /// The raw errno of the most recent kernel-pressure failure, or 0
        /// for "none since start". A gauge, not a counter: the question is
        /// which errno is failing *now*, and the `kernel_pressure_*` cause
        /// counters already carry the history. This is what keeps an
        /// `other_cause` diagnosable instead of merely counted.
        kernel_pressure_last_errno: u32,
        /// Endpoints under §7 active checks — static per config (the
        /// sum of `endpoints` over every `check` cluster). The capacity
        /// the unhealthy level below is read against.
        health_endpoints_checked: u32,
        /// Checked endpoints currently ejected from balancing (§7). A
        /// level, not a counter: `health_endpoint_down`/`_up` carry the
        /// history; a scrape wants how many are out *now*.
        health_endpoints_unhealthy: u32,

        /// The invariant every producer owes: a level never exceeds its
        /// own capacity, and the two upstream levels share one.
        pub fn valid(gauges: *const Gauges) bool {
            if (gauges.conn_slots_in_use > gauges.conn_slots_capacity) return false;
            if (gauges.relay_buffers_in_use > gauges.relay_buffers_capacity) return false;
            if (gauges.head_buffers_in_use > gauges.head_buffers_capacity) return false;
            if (gauges.upstream_head_buffers_in_use > gauges.upstream_head_buffers_capacity) return false;
            if (gauges.health_endpoints_unhealthy > gauges.health_endpoints_checked) return false;
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
        for (names) |name| {
            const name_len = metric_prefix.len + name.len;
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
        inline for (names) |name| {
            // The format string is fully comptime (only the value is
            // runtime), so bufPrint cannot fail for a value that fits u64
            // in a buffer sized to render_bytes_max.
            const written = std.fmt.bufPrint(
                buffer[cursor..],
                "# TYPE " ++ metric_prefix ++ name ++ " counter\n" ++
                    metric_prefix ++ name ++ " {d}\n",
                .{counters.get(name)},
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
        for (names) |name| {
            if (std.mem.startsWith(u8, name, shed_prefix)) count += 1;
        }
        break :blk count;
    };

    /// Every admission shed, summed off the field set rather than a list.
    fn shedTotal(counters: *const Counters) u64 {
        comptime assert(shed_rung_count >= 1);
        var total: u64 = 0;
        inline for (names) |name| {
            if (comptime !std.mem.startsWith(u8, name, shed_prefix)) continue;
            total += counters.get(name);
        }
        return total;
    }

    /// Which syscall a kernel-pressure failure came from (§8). Closed set:
    /// a new op has to name itself here and grow a counter, rather than
    /// disappearing into the total.
    pub const KernelPressureOp = enum {
        accept,
        connect,
        recv,
        send,
        set_option,

        /// The counter this op increments. A `switch` rather than a name
        /// built by concatenation, so a typo is a compile error and the
        /// mapping reads in one place.
        pub fn counter(op: KernelPressureOp) []const u8 {
            return switch (op) {
                .accept => "kernel_pressure_accept",
                .connect => "kernel_pressure_connect",
                .recv => "kernel_pressure_recv",
                .send => "kernel_pressure_send",
                .set_option => "kernel_pressure_set_option",
            };
        }
    };

    /// The counter for an `Io.Pressure.Cause`. Lives here rather than on
    /// the seam's enum so `io.zig` stays free of counter names.
    pub fn causeCounter(cause: io_module.Pressure.Cause) []const u8 {
        return switch (cause) {
            .out_of_buffers => "kernel_pressure_out_of_buffers",
            .out_of_memory => "kernel_pressure_out_of_memory",
            .fd_limit => "kernel_pressure_fd_limit",
            .address_unavailable => "kernel_pressure_address_unavailable",
            .other => "kernel_pressure_other_cause",
        };
    }

    /// The per-op split summed — equal to `kernel_pressure_errors` by
    /// construction, and asserted so in `reconcile`.
    pub fn kernelPressureTotal(counters: *const Counters) u64 {
        var total: u64 = 0;
        inline for (comptime std.enums.values(KernelPressureOp)) |op| {
            total += counters.get(comptime op.counter());
        }
        return total;
    }

    /// The per-cause split summed. The second partition of the same total,
    /// so it must agree with `kernelPressureTotal` as well as with the
    /// total itself — both asserted in `reconcile`.
    pub fn kernelPressureCauseTotal(counters: *const Counters) u64 {
        var total: u64 = 0;
        inline for (comptime std.enums.values(io_module.Pressure.Cause)) |cause| {
            total += counters.get(comptime causeCounter(cause));
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
        // A probe can only fail if it was sent; an ejection needs at least
        // one failed probe; a restore needs a prior ejection (endpoints
        // start healthy, §7).
        assert(counters.get("health_probes_failed") <= counters.get("health_probes_sent"));
        assert(counters.get("health_endpoint_down") <= counters.get("health_probes_failed"));
        assert(counters.get("health_endpoint_up") <= counters.get("health_endpoint_down"));
        // The op split partitions the total exactly: a witness that
        // incremented one without the other would make the split lie about
        // where the pressure is, which is the only thing it exists to say.
        assert(counters.kernelPressureTotal() == counters.get("kernel_pressure_errors"));
        assert(counters.kernelPressureCauseTotal() == counters.get("kernel_pressure_errors"));
        const flow_holds = admitted == completed + active_count;
        const gate_holds = accepted == admitted + shed;
        return flow_holds and gate_holds;
    }
};

/// The per-cluster and per-endpoint breakdown of the exposition (§8,
/// #179): which backend, not only how many. Same single-writer
/// relaxed-atomic discipline as `Counters`, in tables sized by the loaded
/// config's endpoint index space (`EndpointKeys`) rather than by a field
/// list — the first counter tables among the §7 endpoint-keyed state.
///
/// Each labeled family **partitions** one process total above, the
/// kernel-pressure op/cause precedent: the bare counter stays the total a
/// dashboard already reads, the labeled series say *where*, and
/// `reconciles` holds the two views equal so neither can drift — a
/// witness that moves one side without the other is a bug the simulator
/// trips on every seed, not a state.
///
/// Label cardinality is bounded by config, and that property is what
/// makes labelling safe at all: there is no user-controlled dimension —
/// no per-path, no per-status — and there must never be one. The label
/// strings are prebuilt here at init, so a scrape renders them with the
/// same zero-allocation discipline as everything else (§5).
pub const Labeled = struct {
    keys: upstream_module.EndpointKeys,
    /// Rendered `{cluster="…",endpoint="…"}` per key — empty at the
    /// ragged holes between clusters, which no render row ever reads.
    /// Cluster names are escaped (an operator identifier may hold any
    /// byte); the endpoint half is an address literal and cannot need it.
    endpoint_labels: [][]const u8,
    /// Rendered `{cluster="…"}` per cluster, for the families whose
    /// witness site cannot know an endpoint.
    cluster_labels: [][]const u8,
    /// Endpoints per cluster — the row bound every walk below shares, so
    /// a ragged config's holes are skipped by construction.
    endpoint_counts: []u16,
    /// Which clusters run §7 checks: the healthy gauge renders only
    /// where a prober actually writes a verdict.
    cluster_checked: []bool,
    /// Per-endpoint counters (`EndpointKeys`-keyed). Each partitions the
    /// like-named process total — see `reconciles`.
    connect_failed: []Value,
    responses: []Value,
    health_down: []Value,
    health_up: []Value,
    /// Per-cluster counters: the inflight sheds fire precisely because
    /// *no* endpoint could be picked, so a per-endpoint label would be an
    /// invention — the cluster is everything the witness knows.
    l7_shed_inflight: []Value,
    l4_shed_inflight: []Value,
    /// Exact byte bound on one `render` of this config — the runtime
    /// sibling of `Counters.render_bytes_max`, tight the same way, and
    /// the term the caller sizes its buffer (and the memory banner its
    /// budget) from.
    render_bytes_max: usize,

    const Value = Counters.Value;
    const metric_prefix = Counters.metric_prefix;

    const u64_digits_max = 20; // len("18446744073709551615")
    /// The inflight gauge sums two u16 tables, so its reachable maximum
    /// is 131070 — six digits, and the tightness test fills the buffer
    /// exactly because this is the true ceiling rather than a u32's.
    const inflight_digits_max = 6;
    const inflight_max: u32 = 2 * @as(u32, std.math.maxInt(u16));
    comptime {
        assert(inflight_max >= 100_000);
        assert(inflight_max < 1_000_000);
    }
    /// Healthy is a 0/1 gauge: one digit is its widest rendering.
    const healthy_digits_max = 1;

    /// The per-endpoint families, tag names matching the field they
    /// count into — `incrementEndpoint` resolves the table by tag, so a
    /// rename that split the two would not compile.
    pub const EndpointFamily = enum {
        connect_failed,
        responses,
        health_down,
        health_up,

        /// The exposition name (behind `zoxy_`). A switch, not
        /// concatenation, so the rendered vocabulary reads in one place.
        fn name(family: EndpointFamily) []const u8 {
            return switch (family) {
                .connect_failed => "endpoint_connect_failed",
                .responses => "endpoint_responses",
                .health_down => "endpoint_health_down",
                .health_up => "endpoint_health_up",
            };
        }
    };

    pub const ClusterFamily = enum {
        l7_shed_inflight,
        l4_shed_inflight,

        fn name(family: ClusterFamily) []const u8 {
            return switch (family) {
                .l7_shed_inflight => "cluster_l7_shed_inflight",
                .l4_shed_inflight => "cluster_l4_shed_inflight",
            };
        }
    };

    /// What the gauges read at render time, borrowed from their owners
    /// exactly as the balancer borrows them (§7): the pool and the
    /// server own the load, the prober owns the mask, and reading live
    /// beats mirroring — a mirror is one missed release from lying.
    pub const LiveViews = struct {
        load: upstream_module.Load,
        healthy: []const bool,
    };

    pub fn init(
        labeled: *Labeled,
        arena: std.mem.Allocator,
        config: *const config_module.Config,
        keys: upstream_module.EndpointKeys,
    ) error{OutOfMemory}!void {
        assert(config.clusters.len >= 1);
        assert(keys.count == @as(u32, @intCast(config.clusters.len)) * keys.stride);
        labeled.keys = keys;
        const cluster_count = config.clusters.len;
        labeled.endpoint_labels = try arena.alloc([]const u8, keys.count);
        labeled.cluster_labels = try arena.alloc([]const u8, cluster_count);
        labeled.endpoint_counts = try arena.alloc(u16, cluster_count);
        labeled.cluster_checked = try arena.alloc(bool, cluster_count);
        labeled.connect_failed = try allocValues(arena, keys.count);
        labeled.responses = try allocValues(arena, keys.count);
        labeled.health_down = try allocValues(arena, keys.count);
        labeled.health_up = try allocValues(arena, keys.count);
        labeled.l7_shed_inflight = try allocValues(arena, cluster_count);
        labeled.l4_shed_inflight = try allocValues(arena, cluster_count);
        // Holes stay empty — the one answer to "what did init leave
        // here", and the tripwire `incrementEndpoint` asserts against.
        @memset(labeled.endpoint_labels, "");
        for (config.clusters, 0..) |*cluster, cluster_index| {
            assert(cluster.endpoints.len >= 1);
            assert(cluster.endpoints.len <= keys.stride);
            labeled.endpoint_counts[cluster_index] = @intCast(cluster.endpoints.len);
            labeled.cluster_checked[cluster_index] = cluster.check != null;
            labeled.cluster_labels[cluster_index] = try clusterLabel(arena, cluster.name);
            for (cluster.endpoints, 0..) |*address, endpoint_index| {
                const key = keys.key(@intCast(cluster_index), @intCast(endpoint_index));
                labeled.endpoint_labels[key] =
                    try endpointLabel(arena, cluster.name, address);
            }
        }
        labeled.render_bytes_max = renderBytesMaxFor(config);
        assert(labeled.render_bytes_max >= 1);
    }

    fn allocValues(arena: std.mem.Allocator, count: usize) error{OutOfMemory}![]Value {
        assert(count >= 1);
        const values = try arena.alloc(Value, count);
        for (values) |*value| value.* = Value.init(0);
        return values;
    }

    /// Widest rendered endpoint literal: a bracketed IPv6 address with
    /// its port — 47 bytes, and truly the widest, since `parseLiteral`
    /// cannot carry a scope id and the `{f}` render omits scopes anyway.
    /// 64 is round headroom over that, not a scope allowance.
    const endpoint_literal_bytes_max = 64;

    /// Scratch wide enough for any label this config could produce: the
    /// grammar, a fully-escaped cluster name (every byte doubling), and
    /// the widest endpoint literal.
    const label_scratch_bytes = "{cluster=\"".len +
        2 * @as(usize, constants.cluster_name_bytes_max) +
        "\",endpoint=\"".len + endpoint_literal_bytes_max + "\"}".len;

    fn clusterLabel(arena: std.mem.Allocator, name: []const u8) error{OutOfMemory}![]const u8 {
        var scratch: [label_scratch_bytes]u8 = undefined;
        return try arena.dupe(u8, renderClusterLabel(&scratch, name));
    }

    fn endpointLabel(
        arena: std.mem.Allocator,
        name: []const u8,
        address: *const std.Io.net.IpAddress,
    ) error{OutOfMemory}![]const u8 {
        var scratch: [label_scratch_bytes]u8 = undefined;
        return try arena.dupe(u8, renderEndpointLabel(&scratch, name, address));
    }

    /// The label built in caller scratch — shared by `init`, which dupes
    /// it into the arena, and the config-walking budget forms
    /// (`tableBytes`, `renderBytesMaxFor`), which only measure it: one
    /// renderer, so the banner cannot price a label init did not build.
    fn renderClusterLabel(scratch: []u8, name: []const u8) []const u8 {
        assert(name.len >= 1);
        assert(name.len <= constants.cluster_name_bytes_max);
        assert(scratch.len >= label_scratch_bytes);
        var writer = std.Io.Writer.fixed(scratch);
        // The scratch is sized to the loader's own bounds just above, so
        // the fixed writer cannot fill.
        writer.writeAll("{cluster=\"") catch unreachable;
        writeEscaped(&writer, name) catch unreachable;
        writer.writeAll("\"}") catch unreachable;
        return writer.buffered();
    }

    fn renderEndpointLabel(
        scratch: []u8,
        name: []const u8,
        address: *const std.Io.net.IpAddress,
    ) []const u8 {
        assert(name.len >= 1);
        assert(name.len <= constants.cluster_name_bytes_max);
        assert(scratch.len >= label_scratch_bytes);
        var writer = std.Io.Writer.fixed(scratch);
        // Same cannot-fill argument as `renderClusterLabel`; the address
        // half is bounded by the bracketed-IPv6 term of the scratch.
        writer.writeAll("{cluster=\"") catch unreachable;
        writeEscaped(&writer, name) catch unreachable;
        writer.print("\",endpoint=\"{f}\"}}", .{address.*}) catch unreachable;
        return writer.buffered();
    }

    /// What `init` takes from the startup arena for this config (§5):
    /// the six value tables, the label slice headers and the label bytes
    /// themselves, and the two per-cluster scalars. Closed-form in the
    /// config — it renders the same labels init dupes, through the same
    /// renderer — so the banner's term is a prediction `init` then meets
    /// exactly.
    pub fn tableBytes(
        config: *const config_module.Config,
        keys: upstream_module.EndpointKeys,
    ) u64 {
        assert(config.clusters.len >= 1);
        assert(keys.count >= 1);
        const cluster_count: u64 = config.clusters.len;
        var total: u64 = 0;
        total += @as(u64, keys.count) * @sizeOf([]const u8); // endpoint_labels
        total += cluster_count * @sizeOf([]const u8); // cluster_labels
        total += cluster_count * @sizeOf(u16); // endpoint_counts
        total += cluster_count * @sizeOf(bool); // cluster_checked
        total += 4 * @as(u64, keys.count) * @sizeOf(Value); // endpoint families
        total += 2 * cluster_count * @sizeOf(Value); // cluster families
        var scratch: [label_scratch_bytes]u8 = undefined;
        for (config.clusters) |*cluster| {
            total += renderClusterLabel(&scratch, cluster.name).len;
            for (cluster.endpoints) |*address| {
                total += renderEndpointLabel(&scratch, cluster.name, address).len;
            }
        }
        assert(total >= 1);
        return total;
    }

    /// Prometheus label-value escaping: backslash, quote, newline. The
    /// loader bounds a cluster name's *length*, not its bytes, and a
    /// label that broke the exposition grammar would corrupt the whole
    /// scrape, not one line.
    fn writeEscaped(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
        for (value) |byte| {
            switch (byte) {
                '\\' => try writer.writeAll("\\\\"),
                '"' => try writer.writeAll("\\\""),
                '\n' => try writer.writeAll("\\n"),
                else => try writer.writeByte(byte),
            }
        }
    }

    /// Loop thread only — the single writer (§8), like `Counters`.
    /// `key` must name a configured endpoint: the empty-label assert is
    /// what turns "charged a hole" from a silent lost count into a bug.
    pub fn incrementEndpoint(
        labeled: *Labeled,
        comptime family: EndpointFamily,
        key: u32,
    ) void {
        assert(key < labeled.keys.count);
        assert(labeled.endpoint_labels[key].len >= 1);
        const table = @field(labeled, @tagName(family));
        const previous = table[key].fetchAdd(1, .monotonic);
        assert(previous < std.math.maxInt(u64));
    }

    pub fn incrementCluster(
        labeled: *Labeled,
        comptime family: ClusterFamily,
        cluster_index: u16,
    ) void {
        assert(cluster_index < labeled.cluster_labels.len);
        const table = @field(labeled, @tagName(family));
        const previous = table[cluster_index].fetchAdd(1, .monotonic);
        assert(previous < std.math.maxInt(u64));
    }

    /// Render every labeled family as Prometheus exposition text —
    /// `Counters.render`'s dialect, appended after it by the callers
    /// that serve both. Zero-alloc into a caller-owned buffer of at
    /// least `render_bytes_max`, a bound that is exact for the same
    /// reason the comptime one is: every row is priced at its type's
    /// widest rendering.
    pub fn render(labeled: *const Labeled, views: *const LiveViews, buffer: []u8) []const u8 {
        assert(buffer.len >= labeled.render_bytes_max);
        assert(views.load.l7.len == labeled.keys.count);
        assert(views.load.l4.len == labeled.keys.count);
        assert(views.healthy.len == labeled.keys.count);
        var writer = std.Io.Writer.fixed(buffer);
        inline for (comptime std.enums.values(EndpointFamily)) |family| {
            labeled.renderEndpointFamily(&writer, family);
        }
        inline for (comptime std.enums.values(ClusterFamily)) |family| {
            labeled.renderClusterFamily(&writer, family);
        }
        labeled.renderInflight(&writer, views);
        labeled.renderHealthy(&writer, views);
        const text = writer.buffered();
        assert(text.len >= 1);
        assert(text.len <= labeled.render_bytes_max);
        return text;
    }

    fn renderEndpointFamily(
        labeled: *const Labeled,
        writer: *std.Io.Writer,
        comptime family: EndpointFamily,
    ) void {
        const table = @field(labeled, @tagName(family));
        assert(table.len == labeled.keys.count);
        // Every write below is inside `render_bytes_max`, which `init`
        // computed over exactly these rows — the cannot-fail argument
        // `Counters.render` makes against its comptime bound.
        writer.print(
            "# TYPE {s}{s} counter\n",
            .{ metric_prefix, comptime family.name() },
        ) catch unreachable;
        for (0..labeled.endpoint_counts.len) |cluster_index| {
            for (0..labeled.endpoint_counts[cluster_index]) |endpoint_index| {
                const key = labeled.keys.key(@intCast(cluster_index), @intCast(endpoint_index));
                writer.print("{s}{s}{s} {d}\n", .{
                    metric_prefix,
                    comptime family.name(),
                    labeled.endpoint_labels[key],
                    table[key].load(.monotonic),
                }) catch unreachable;
            }
        }
    }

    fn renderClusterFamily(
        labeled: *const Labeled,
        writer: *std.Io.Writer,
        comptime family: ClusterFamily,
    ) void {
        const table = @field(labeled, @tagName(family));
        assert(table.len == labeled.cluster_labels.len);
        writer.print(
            "# TYPE {s}{s} counter\n",
            .{ metric_prefix, comptime family.name() },
        ) catch unreachable;
        for (labeled.cluster_labels, table) |label, *value| {
            writer.print("{s}{s}{s} {d}\n", .{
                metric_prefix,
                comptime family.name(),
                label,
                value.load(.monotonic),
            }) catch unreachable;
        }
    }

    /// The per-endpoint in-flight level — the §7 total the balancer
    /// compares and `max_inflight` caps, seen from the scrape. Read off
    /// the owners' live tables at render time, never mirrored.
    fn renderInflight(
        labeled: *const Labeled,
        writer: *std.Io.Writer,
        views: *const LiveViews,
    ) void {
        assert(views.load.l7.len == labeled.keys.count);
        writer.print(
            "# TYPE {s}endpoint_inflight gauge\n",
            .{metric_prefix},
        ) catch unreachable;
        for (0..labeled.endpoint_counts.len) |cluster_index| {
            for (0..labeled.endpoint_counts[cluster_index]) |endpoint_index| {
                const key = labeled.keys.key(@intCast(cluster_index), @intCast(endpoint_index));
                const level = views.load.inFlight(key);
                assert(level <= inflight_max);
                writer.print("{s}endpoint_inflight{s} {d}\n", .{
                    metric_prefix,
                    labeled.endpoint_labels[key],
                    level,
                }) catch unreachable;
            }
        }
    }

    /// The §7 verdict per checked endpoint, 1 healthy / 0 ejected. Only
    /// for clusters with a `check` block: an unprobed endpoint has no
    /// verdict, and rendering a constant 1 for it would dress "unknown"
    /// as "known good".
    fn renderHealthy(
        labeled: *const Labeled,
        writer: *std.Io.Writer,
        views: *const LiveViews,
    ) void {
        assert(views.healthy.len == labeled.keys.count);
        if (labeled.checkedClusterCount() == 0) {
            return;
        }
        assert(labeled.checkedClusterCount() >= 1);
        writer.print(
            "# TYPE {s}endpoint_healthy gauge\n",
            .{metric_prefix},
        ) catch unreachable;
        for (0..labeled.endpoint_counts.len) |cluster_index| {
            if (!labeled.cluster_checked[cluster_index]) continue;
            for (0..labeled.endpoint_counts[cluster_index]) |endpoint_index| {
                const key = labeled.keys.key(@intCast(cluster_index), @intCast(endpoint_index));
                writer.print("{s}endpoint_healthy{s} {d}\n", .{
                    metric_prefix,
                    labeled.endpoint_labels[key],
                    @intFromBool(views.healthy[key]),
                }) catch unreachable;
            }
        }
    }

    fn checkedClusterCount(labeled: *const Labeled) u16 {
        var count: u16 = 0;
        for (labeled.cluster_checked) |checked| {
            if (checked) count += 1;
        }
        assert(count <= labeled.cluster_checked.len);
        return count;
    }

    /// The exact bound `render` is held to, priced over the same rows
    /// render walks. A function of the *config* rather than of a built
    /// `Labeled`, so the memory banner can state it before `Server.init`
    /// runs — `init` stores the same number on the instance. Exact
    /// because every term is, which is what lets the tightness test
    /// prove it by filling the buffer to the last byte.
    pub fn renderBytesMaxFor(config: *const config_module.Config) usize {
        assert(config.clusters.len >= 1);
        var total: usize = 0;
        inline for (comptime std.enums.values(EndpointFamily)) |family| {
            total += typeLineLen(family.name(), "counter");
        }
        inline for (comptime std.enums.values(ClusterFamily)) |family| {
            total += typeLineLen(family.name(), "counter");
        }
        total += typeLineLen("endpoint_inflight", "gauge");
        var checked_clusters: usize = 0;
        var scratch: [label_scratch_bytes]u8 = undefined;
        for (config.clusters) |*cluster| {
            const cluster_label_len = renderClusterLabel(&scratch, cluster.name).len;
            const cluster_checked = cluster.check != null;
            inline for (comptime std.enums.values(ClusterFamily)) |family| {
                total += rowLen(family.name(), cluster_label_len, u64_digits_max);
            }
            if (cluster_checked) checked_clusters += 1;
            for (cluster.endpoints) |*address| {
                const label_len =
                    renderEndpointLabel(&scratch, cluster.name, address).len;
                inline for (comptime std.enums.values(EndpointFamily)) |family| {
                    total += rowLen(family.name(), label_len, u64_digits_max);
                }
                total += rowLen("endpoint_inflight", label_len, inflight_digits_max);
                if (cluster_checked) {
                    total += rowLen("endpoint_healthy", label_len, healthy_digits_max);
                }
            }
        }
        if (checked_clusters >= 1) {
            total += typeLineLen("endpoint_healthy", "gauge");
        }
        assert(total >= 1);
        return total;
    }

    fn typeLineLen(name: []const u8, kind: []const u8) usize {
        assert(name.len >= 1);
        assert(kind.len >= 1);
        return "# TYPE ".len + metric_prefix.len + name.len + " ".len + kind.len + "\n".len;
    }

    fn rowLen(name: []const u8, label_len: usize, digits: usize) usize {
        assert(name.len >= 1);
        assert(label_len >= "{cluster=\"\"}".len);
        assert(digits >= 1);
        return metric_prefix.len + name.len + label_len + " ".len + digits + "\n".len;
    }

    fn tableTotal(values: []const Value) u64 {
        assert(values.len >= 1);
        var total: u64 = 0;
        for (values) |*value| {
            total += value.load(.monotonic);
        }
        return total;
    }

    /// The #179 partition identities: each labeled family sums to the
    /// process total it breaks down — two views of one number, the
    /// kernel-pressure op/cause contract. Asserted rather than returned,
    /// exactly like `reconcile`'s inequalities: a witness that moved one
    /// side without the other is a bug for the simulator to trip on, not
    /// a state to report — which is why there is no `false` to return.
    pub fn reconciles(labeled: *const Labeled, counters: *const Counters) void {
        assert(tableTotal(labeled.connect_failed) == counters.get("upstream_connect_failed"));
        assert(tableTotal(labeled.responses) == counters.get("l7_responses"));
        assert(tableTotal(labeled.health_down) == counters.get("health_endpoint_down"));
        assert(tableTotal(labeled.health_up) == counters.get("health_endpoint_up"));
        assert(tableTotal(labeled.l7_shed_inflight) ==
            counters.get("l7_shed_endpoint_inflight"));
        assert(tableTotal(labeled.l4_shed_inflight) ==
            counters.get("l4_shed_endpoint_inflight"));
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
    .head_buffers_in_use = 2,
    .head_buffers_capacity = 8,
    .upstream_head_buffers_in_use = 1,
    .upstream_head_buffers_capacity = 6,
    .kernel_pressure_last_errno = 105, // ENOBUFS on Linux
    .health_endpoints_checked = 4,
    .health_endpoints_unhealthy = 1,
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

test "counters: every kernel-pressure op has its own counter, and they partition the total" {
    // The mapping must be total and injective: an op sharing a counter
    // with another would silently re-create the bucket this split exists
    // to break up.
    var counters: Counters = .{};
    var seen: [std.enums.values(Counters.KernelPressureOp).len][]const u8 = undefined;
    var index: usize = 0;
    inline for (comptime std.enums.values(Counters.KernelPressureOp)) |op| {
        const name = comptime op.counter();
        // Names an existing field: `get` would not compile otherwise, and
        // the zero read here pins that it starts clean.
        try std.testing.expectEqual(@as(u64, 0), counters.get(name));
        for (seen[0..index]) |previous| {
            try std.testing.expect(!std.mem.eql(u8, previous, name));
        }
        seen[index] = name;
        index += 1;
    }
    try std.testing.expectEqual(std.enums.values(Counters.KernelPressureOp).len, index);

    // The cause split is a second partition of the same total, so every
    // witness moves three counters together: the total, one op, one cause.
    inline for (comptime std.enums.values(io_module.Pressure.Cause)) |cause| {
        try std.testing.expectEqual(@as(u64, 0), counters.get(comptime Counters.causeCounter(cause)));
    }
    counters.increment("kernel_pressure_errors");
    counters.increment("kernel_pressure_send");
    counters.increment("kernel_pressure_out_of_buffers");
    try std.testing.expectEqual(@as(u64, 1), counters.kernelPressureTotal());
    try std.testing.expectEqual(@as(u64, 1), counters.kernelPressureCauseTotal());
    try std.testing.expect(counters.reconcile(0));

    // A total that moved without an op is exactly the old behaviour: the
    // two diverge, and `reconcile` would trip its assertion rather than
    // return false — which is why it is not called here. The sim runs
    // `reconcile` under every seed, so that assertion is the enforcement;
    // this pins the divergence it fires on.
    counters.increment("kernel_pressure_errors");
    try std.testing.expectEqual(@as(u64, 1), counters.kernelPressureTotal());
    try std.testing.expectEqual(@as(u64, 2), counters.get("kernel_pressure_errors"));
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

/// A two-cluster, deliberately ragged shape for the `Labeled` tests:
/// "api" (checked, two endpoints) beside "solo" (unchecked, one), under
/// a stride of 2 — so key (1,1) is a hole, and a walk that forgot the
/// per-cluster row bound would read it.
fn labeledTestConfig(clusters: []const config_module.Config.Cluster) config_module.Config {
    return .{
        .listeners = &.{},
        .clusters = clusters,
        .connect_timeout_ms = 1,
        .idle_timeout_ms = 1,
        .drain_deadline_ms = 1,
        .max_lifetime_ms = 0,
        .request_timeout_ms = 0,
    };
}

fn labeledTestAddress(comptime literal: []const u8) std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral(literal) catch unreachable;
}

const labeled_test_keys: upstream_module.EndpointKeys = .init(2, 2);

fn labeledTestClusters() [2]config_module.Config.Cluster {
    const api_endpoints = struct {
        const list = [_]std.Io.net.IpAddress{
            labeledTestAddress("10.0.0.1:8080"),
            labeledTestAddress("10.0.0.2:8080"),
        };
    };
    const solo_endpoints = struct {
        const list = [_]std.Io.net.IpAddress{
            labeledTestAddress("[2001:db8::1]:9000"),
        };
    };
    return .{
        .{
            .name = "api",
            .endpoints = &api_endpoints.list,
            .check = .{ .timeout_ms = 50 },
        },
        .{
            .name = "solo",
            .endpoints = &solo_endpoints.list,
        },
    };
}

test "counters: labeled init builds one label per configured endpoint" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const clusters = labeledTestClusters();
    const config = labeledTestConfig(&clusters);
    var labeled: Labeled = undefined;
    try labeled.init(arena_state.allocator(), &config, labeled_test_keys);

    try std.testing.expectEqualStrings(
        "{cluster=\"api\",endpoint=\"10.0.0.1:8080\"}",
        labeled.endpoint_labels[labeled_test_keys.key(0, 0)],
    );
    try std.testing.expectEqualStrings(
        "{cluster=\"api\",endpoint=\"10.0.0.2:8080\"}",
        labeled.endpoint_labels[labeled_test_keys.key(0, 1)],
    );
    try std.testing.expectEqualStrings("{cluster=\"solo\"}", labeled.cluster_labels[1]);
    // The IPv6 literal renders bracketed, port attached — the exact text
    // an operator grep for their own config's endpoint will match.
    try std.testing.expect(std.mem.indexOf(
        u8,
        labeled.endpoint_labels[labeled_test_keys.key(1, 0)],
        "[2001:db8::1]:9000",
    ) != null);
    // The ragged hole carries no label — and `incrementEndpoint` asserts
    // on that emptiness, so charging a hole is a crash, not a lost count.
    try std.testing.expectEqual(@as(usize, 0), labeled.endpoint_labels[labeled_test_keys.key(1, 1)].len);
    try std.testing.expectEqual(true, labeled.cluster_checked[0]);
    try std.testing.expectEqual(false, labeled.cluster_checked[1]);
}

test "counters: labeled labels escape what the exposition grammar reserves" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const endpoints = struct {
        const list = [_]std.Io.net.IpAddress{labeledTestAddress("127.0.0.1:1")};
    };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "we\"ird\\name", .endpoints = &endpoints.list },
    };
    const config = labeledTestConfig(&clusters);
    var labeled: Labeled = undefined;
    try labeled.init(arena_state.allocator(), &config, .init(1, 1));

    // A quote or backslash in a cluster name must not break the label
    // grammar: the loader bounds a name's length, never its bytes.
    try std.testing.expectEqualStrings(
        "{cluster=\"we\\\"ird\\\\name\"}",
        labeled.cluster_labels[0],
    );
}

test "counters: labeled render speaks the exposition dialect" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const clusters = labeledTestClusters();
    const config = labeledTestConfig(&clusters);
    var labeled: Labeled = undefined;
    try labeled.init(arena_state.allocator(), &config, labeled_test_keys);

    labeled.incrementEndpoint(.responses, labeled_test_keys.key(0, 1));
    labeled.incrementEndpoint(.responses, labeled_test_keys.key(0, 1));
    labeled.incrementCluster(.l7_shed_inflight, 1);

    var l7 = [_]u16{0} ** labeled_test_keys.count;
    var l4 = [_]u16{0} ** labeled_test_keys.count;
    l7[labeled_test_keys.key(0, 0)] = 3;
    l4[labeled_test_keys.key(0, 0)] = 2;
    var healthy = [_]bool{true} ** labeled_test_keys.count;
    healthy[labeled_test_keys.key(0, 1)] = false;
    const views: Labeled.LiveViews = .{
        .load = .{ .l7 = &l7, .l4 = &l4 },
        .healthy = &healthy,
    };

    const buffer = try arena_state.allocator().alloc(u8, labeled.render_bytes_max);
    const text = labeled.render(&views, buffer);

    // Counters carry their values, and untouched series render at zero —
    // a scrape sees the whole configured set, exactly like `Counters`.
    try std.testing.expect(std.mem.indexOf(u8, text, "# TYPE zoxy_endpoint_responses counter\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_endpoint_responses{cluster=\"api\",endpoint=\"10.0.0.2:8080\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_endpoint_connect_failed{cluster=\"api\",endpoint=\"10.0.0.1:8080\"} 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_cluster_l7_shed_inflight{cluster=\"solo\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_cluster_l4_shed_inflight{cluster=\"api\"} 0\n") != null);
    // The inflight gauge reads the live view: both protocols summed.
    try std.testing.expect(std.mem.indexOf(u8, text, "# TYPE zoxy_endpoint_inflight gauge\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_endpoint_inflight{cluster=\"api\",endpoint=\"10.0.0.1:8080\"} 5\n") != null);
    // Healthy renders the prober's verdict for checked endpoints only:
    // an unprobed endpoint has no verdict to dress up as a 1.
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_endpoint_healthy{cluster=\"api\",endpoint=\"10.0.0.2:8080\"} 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_endpoint_healthy{cluster=\"api\",endpoint=\"10.0.0.1:8080\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_endpoint_healthy{cluster=\"solo\"") == null);

    // One TYPE line per family: four endpoint counters, two cluster
    // counters, the inflight gauge, and healthy (a checked cluster exists).
    var type_lines: usize = 0;
    var search: usize = 0;
    while (std.mem.indexOfPos(u8, text, search, "# TYPE ")) |at| {
        type_lines += 1;
        search = at + "# TYPE ".len;
    }
    try std.testing.expectEqual(@as(usize, 8), type_lines);
}

test "counters: labeled render bound is exact at the maximum values" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const clusters = labeledTestClusters();
    const config = labeledTestConfig(&clusters);
    var labeled: Labeled = undefined;
    try labeled.init(arena_state.allocator(), &config, labeled_test_keys);

    for ([_][]Counters.Value{
        labeled.connect_failed,   labeled.responses,
        labeled.health_down,      labeled.health_up,
        labeled.l7_shed_inflight, labeled.l4_shed_inflight,
    }) |table| {
        for (table) |*value| value.store(std.math.maxInt(u64), .monotonic);
    }
    // The widest live view either owner can produce: both u16 tables
    // saturated (the inflight bound is their sum, not a u32's), and a
    // healthy verdict — "1" — on every checked endpoint.
    var l7 = [_]u16{std.math.maxInt(u16)} ** labeled_test_keys.count;
    var l4 = [_]u16{std.math.maxInt(u16)} ** labeled_test_keys.count;
    const healthy = [_]bool{true} ** labeled_test_keys.count;
    const views: Labeled.LiveViews = .{
        .load = .{ .l7 = &l7, .l4 = &l4 },
        .healthy = &healthy,
    };

    const buffer = try arena_state.allocator().alloc(u8, labeled.render_bytes_max);
    const text = labeled.render(&views, buffer);
    // Every value at its type's reachable maximum fills the buffer
    // exactly: the bound is tight, not merely sufficient — the same
    // claim `Counters.render_bytes_max` proves at comptime.
    try std.testing.expectEqual(labeled.render_bytes_max, text.len);
    try std.testing.expect(std.mem.indexOf(u8, text, "18446744073709551615\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, " 131070\n") != null);
}

test "counters: labeled render drops the healthy family with nothing checked" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const endpoints = struct {
        const list = [_]std.Io.net.IpAddress{labeledTestAddress("127.0.0.1:1")};
    };
    const clusters = [_]config_module.Config.Cluster{
        .{ .name = "quiet", .endpoints = &endpoints.list },
    };
    const config = labeledTestConfig(&clusters);
    var labeled: Labeled = undefined;
    try labeled.init(arena_state.allocator(), &config, .init(1, 1));

    var l7 = [_]u16{0};
    var l4 = [_]u16{0};
    const healthy = [_]bool{true};
    const views: Labeled.LiveViews = .{
        .load = .{ .l7 = &l7, .l4 = &l4 },
        .healthy = &healthy,
    };
    const buffer = try arena_state.allocator().alloc(u8, labeled.render_bytes_max);
    const text = labeled.render(&views, buffer);
    // No prober, no verdicts: the whole family is absent, TYPE line and
    // all, rather than a page of constant 1s meaning "unknown".
    try std.testing.expect(std.mem.indexOf(u8, text, "endpoint_healthy") == null);
    try std.testing.expect(std.mem.indexOf(u8, text, "zoxy_endpoint_inflight{cluster=\"quiet\"") != null);
}

test "counters: the labeled families partition their process totals" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const clusters = labeledTestClusters();
    const config = labeledTestConfig(&clusters);
    var labeled: Labeled = undefined;
    try labeled.init(arena_state.allocator(), &config, labeled_test_keys);
    var counters: Counters = .{};

    // Every witness moves both views of its total: the bare counter and
    // one labeled cell. The sums then agree, whatever the distribution.
    counters.increment("upstream_connect_failed");
    labeled.incrementEndpoint(.connect_failed, labeled_test_keys.key(0, 0));
    counters.increment("l7_responses");
    counters.increment("l7_responses");
    labeled.incrementEndpoint(.responses, labeled_test_keys.key(0, 1));
    labeled.incrementEndpoint(.responses, labeled_test_keys.key(1, 0));
    counters.increment("health_endpoint_down");
    labeled.incrementEndpoint(.health_down, labeled_test_keys.key(0, 0));
    counters.increment("l4_shed_endpoint_inflight");
    labeled.incrementCluster(.l4_shed_inflight, 0);
    labeled.reconciles(&counters);
}
