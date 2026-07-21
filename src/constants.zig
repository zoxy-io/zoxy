//! Every static limit in one place. Total memory, fd count, and in-flight
//! ring ops are closed-form functions of these numbers (DESIGN.md §5, §8):
//! main.zig prints the budgets at startup, and the comptime asserts below
//! keep the relationships true. Pools never grow; exhaustion sheds load.

const std = @import("std");

const assert = std.debug.assert;

/// Upper bound on configured listeners.
pub const listeners_max: u16 = 8;

/// The single dedicated admin/metrics listener (DESIGN.md §8, PLANS.md
/// §243): separate from the configured `listeners_max` so a scrape can
/// never consume a data-path listener slot, and reserved in the fd and
/// ring budgets below unconditionally — the ceiling is a comptime
/// constant, so it must cover the worst case (admin enabled) even when a
/// given config leaves it unbound.
pub const admin_listeners: u32 = 1;

/// Concurrent admin client connections — one scrape served at a time (the
/// "reserved slot", §8). It lives outside the three shared pools, so a
/// metrics scrape and the data path can never shed one another. It counts
/// once in the fd budget (its socket) and `admin_conn_ops_max` times in
/// the ring budget.
pub const admin_conns: u32 = 1;

/// Worst-case simultaneously armed ring ops for one admin client: three.
/// The admin conn carries its own idle/scrape deadline — like every other
/// network-facing socket it must not let a peer that connects and never
/// completes park the reserved slot forever (§8) — so a drain-initiated
/// teardown that races an in-flight send holds the send, the deadline,
/// and the deadline-cancel co-armed (the same lazy-timer force pattern as
/// the data path's `conn_ops_max`); a data op and the `close` never
/// coexist (close is submitted only after the data op drains), so the peak
/// is three, not four. The accept op is the listener's, budgeted in the
/// two-per-listener term.
pub const admin_conn_ops_max: u32 = 3;

/// Deadline for one admin scrape, from accept to close (§8): the reaper
/// that keeps a stalled or slowloris scrape client from pinning the single
/// reserved admin slot forever. Short — a metrics scrape is a localhost
/// round trip — and independent of the data path's `idle_timeout_ms`.
pub const admin_scrape_deadline_ms: u32 = 5_000;

/// Throwaway buffer for the admin lingering-close drain (§2): the scrape's
/// request is discarded, never inspected, so one small fixed buffer read
/// in a loop to EOF suffices — sized only to keep the read count modest.
pub const admin_drain_scratch_bytes: u32 = 512;

/// Connection slots (`Pool(Conn)`). The binding constraint is the
/// io_uring completion queue, not fds or memory (§8): every admitted
/// connection — L4 relaying or L7 in any phase — can hold up to
/// `conn_ops_max` armed ops whether or not it holds a relay buffer
/// (an L7 head read is a data op like any other), so every slot claims
/// its worst-case share of the pre-budgeted ring. With the ring at its
/// usable maximum (`ring_entries = 4096`, CQ = 8192, ¾ headroom = 6144)
/// and the parked-upstream and admin reservations carved out first, that
/// caps this at `(6144 - 23 - upstream_slots_max) / conn_ops_max = 1019` —
/// comptime-derived below (the 23 is the fixed ops: two per config and
/// admin listener [18], the admin client's op budget [3], the signal wake
/// [1], and the drain timer [1]). Keep-alive surplus beyond this ceiling
/// waits for the deeper-CQ fork lever (`IORING_SETUP_CQSIZE`,
/// docs/PLANS.md), the same prerequisite as c10k.
pub const conn_slots_max: u32 = 1019;

/// Relay buffer pairs (`Pool(RelayBuffer)`) — the bound on concurrent L4
/// connections plus active L7 body relays (§5, §6). Sized to the
/// conn-slot ceiling: the completion queue binds both (see
/// `conn_slots_max`), and a buffer beyond the slot count could never be
/// acquired.
pub const relay_buffers_max: u32 = conn_slots_max;

/// Bytes per relay direction; a `RelayBuffer` is a pair of these. Held to
/// 4 KiB: the strict recv→send→recv relay (§6) is correct at any size, so
/// the smaller buffer cuts relay-pool memory (~32 MiB → ~10 MiB even as
/// the ceiling rises to 1225) and trades throughput for more round trips
/// only on high-bandwidth-delay streams — negligible on the loopback and
/// LAN paths this proxy targets.
pub const relay_buffer_bytes: u32 = 4 * 1024;

/// §8 "watermarks before walls": each pool flips a pressure flag before
/// it hits the wall so the proxy sheds *idle* capacity before it must
/// shed *work*: relay or conn pressure shortens idle timeouts, relay
/// pressure alone stops honoring keep-alive (conn-pool occupancy is the
/// steady state of a keep-alive workload, not a crisis — #57), upstream
/// pressure reaps parked connections sooner. One rule for all three
/// pools (relay buffers, conn slots, upstream slots). Hysteresis keeps
/// a flag from flapping around a single threshold: engage at the high
/// watermark, release only after draining back to the low one. Both are
/// fractions of the *live* pool capacity, so an injected test pool and
/// the production pool obey one rule. `On` uses ceil so a full pool
/// always counts as pressured; `Off` uses floor so the gap is non-empty
/// for every capacity >= 1.
pub fn poolPressureOn(capacity: u32) u32 {
    return (capacity * 3 + 3) / 4;
}
pub fn poolPressureOff(capacity: u32) u32 {
    return capacity / 2;
}

/// Under pool pressure the idle timeout (and, for upstream pressure, the
/// parked-connection deadline) is divided by this, reaping quiet
/// connections sooner to return their resources (§8). The result is
/// clamped to >= 1 ms so `storeDeadline`'s invariant holds even when the
/// configured idle timeout is already small.
pub const pressure_idle_divisor: u32 = 4;

/// Upper bound on one L7 request or response head, including the final
/// CRLF — the size of a connection slot's head buffer (§5). A request
/// head that cannot complete inside this budget is answered 414 (request
/// line still open) or 431 (header section); an oversize origin response
/// head tears the exchange down (§7).
pub const head_bytes_max: u32 = 8 * 1024;

/// Bounded per-head header array. Overflowing it is load, not malice: it
/// maps to 431, distinguishable from malformed input's 400 (§7).
pub const headers_max: u16 = 64;

/// Upper bound on a canonical routing host (§7). A DNS name is ≤ 253
/// bytes (RFC 1035) and an `[IPv6]` authority fits well under this; a
/// Host longer than this canonicalizes to "unmatchable", so it only
/// meets the any-host routes — never malformed, just unroutable by host.
pub const host_bytes_max: u16 = 256;

/// Upper bound on one chunk-size line (hex size, extensions, CRLF) in a
/// chunked body (§7). Bounded so a hostile peer cannot stream an endless
/// size line through the relay; kept under one relay buffer so a legal
/// line never spans more than two buffer fills.
pub const chunked_line_bytes_max: u32 = 256;

/// Upper bound on a chunked trailer section, which is forwarded verbatim
/// (§7). Same bounding argument as the size line.
pub const chunked_trailer_bytes_max: u32 = 1024;

/// Shared upstream connection slots (`Pool(Upstream)`) — one pool for
/// the whole process, checked out by any request and parked per endpoint
/// on keep-alive (§3, §5). Counted in the §8 budgets below: a parked
/// upstream holds a socket (fd budget) and, once keep-alive lands, one
/// armed idle-timer op (ring budget) — both reserved now so composing
/// keep-alive does not re-cut the budgets. Sized as the largest power of
/// two the fd and CQ budgets accommodate alongside the conn-slot
/// ceiling.
pub const upstream_slots_max: u32 = 1024;

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

/// Worst-case simultaneously armed ring ops for one connection: five.
/// The peak is a teardown racing its own upstream dial — a connecting
/// conn holds connect + deadline, teardown arms connect_cancel +
/// deadline_cancel, then the dial completes while its cancel is still in
/// flight: the connect bit clears and both closes are submitted with the
/// deadline, connect_cancel, and deadline_cancel completions all still
/// outstanding. In steady relay the peak is only four (two data ops +
/// timer + cancel), but the budget must cover the teardown race (§8).
pub const conn_ops_max: u32 = 5;

/// Completions drained per loop tick before control returns to the kernel;
/// bounds both callback batches and `Io.now_ns` staleness (§4).
pub const loop_completions_per_tick_max: u32 = 256;

/// Upper bound on the config file size read at startup.
pub const config_bytes_max: u32 = 256 * 1024;

/// Upper bound on configured clusters.
pub const clusters_max: u16 = 16;

/// Lower bound on configured clusters: a config with no cluster can route
/// nowhere, so the loader rejects an empty map and the config JSON Schema
/// emits it as `minProperties`.
pub const clusters_min: u16 = 1;

/// Upper bound on endpoints in one cluster.
pub const endpoints_per_cluster_max: u16 = 64;

/// Upper bound on routes in one listener's path-routing table (§7). Config
/// data, not a runtime pool: routes are immutable arena slices, and the
/// request-time match is a bounded linear scan over at most this many.
pub const routes_max: u16 = 32;

/// §7 "filters are data" bounds — one listener's rule table and each
/// rule's shape. Config data, not pools: rules are immutable arena
/// slices and evaluation is bounded loops over at most these many, so a
/// filter set cannot make request handling unbounded.
pub const filters_per_listener_max: u16 = 32;
pub const actions_per_filter_max: u16 = 8;
pub const header_matches_per_filter_max: u16 = 8;

/// Upper bound on a listener's *total* header-edit actions (set/add/remove
/// summed across every rule). A request applies the edits of all rules it
/// matches, so the worst case — every rule matching — is the whole set;
/// this bounds the fixed buffer the renderer materializes those edits into
/// (§7). Config counts the edits across the rule table and rejects a set
/// over this, so the render buffer can never overflow.
pub const header_edits_max: u16 = 16;

/// Upper bound on every configured timeout — one hour. A timeout above
/// this is almost certainly a units mistake in the config.
pub const timeout_ms_max: u32 = 3_600_000;

/// Worst-case in-flight ring ops (§8: the ring is pre-budgeted, not shed):
/// every connection slot at its op peak (L7 slots hold armed ops with or
/// without a relay buffer, so the term is per slot, not per buffer), one
/// idle-timer op per parked upstream (§5/§8 — reserved ahead of the
/// keep-alive slice), two ops per listener — configured *and* admin — (a
/// draining listener holds its armed accept — or the accept-retry backoff
/// timer — plus the async cancel that reaps it), `admin_conn_ops_max` ops
/// per admin client (its send/deadline/teardown peak), the single async
/// wakeup op for signals, and the server's one drain-deadline timer.
pub const in_flight_ops_max: u32 =
    conn_slots_max * conn_ops_max + upstream_slots_max +
    2 * (@as(u32, listeners_max) + admin_listeners) +
    admin_conns * admin_conn_ops_max + 1 + 1;

/// Kernel maximum for an IORING_SETUP_CQSIZE completion queue
/// (IORING_MAX_CQ_ENTRIES = 2 × IORING_MAX_ENTRIES) on current kernels.
/// The upper wall on `completion_queue_entries` when the c10k lift raises
/// it — a request past this fails `Loop.init` at runtime, so the comptime
/// assert below keeps it a compile error instead.
pub const io_uring_cq_entries_max: u32 = 65536;

/// The completion queue depth zoxy requests from the kernel via
/// IORING_SETUP_CQSIZE (XevIo) and the capacity the §8 budgets are derived
/// against. Still 2 × SQ today — the kernel's own default — but now
/// requested explicitly, so the c10k lift can raise it independently of
/// `ring_entries` up to `io_uring_cq_entries_max`.
pub const completion_queue_entries: u32 = 2 * @as(u32, ring_entries);

/// Worst-case fd count (§8: fds are pre-budgeted, not shed): stdio + ring
/// + async eventfd + listeners (configured + admin) + two sockets per
/// admitted connection (client plus the exchange's upstream) + the one
/// transient just-accepted fd an admission decision is pending on + one
/// socket per in-flight admin scrape + one socket per parked upstream,
/// which belongs to no connection.
pub const fds_max: u32 =
    3 + 1 + 1 + (listeners_max + admin_listeners) +
    2 * conn_slots_max + 1 + admin_conns + upstream_slots_max;

comptime {
    assert(std.math.isPowerOfTwo(ring_entries));
    assert(ring_entries <= 4096);
    // The CQ depth is now a real kernel argument (XevIo requests it via
    // IORING_SETUP_CQSIZE), so it must be a value the kernel accepts: a
    // power of two, at least the SQ depth, and within the kernel cap.
    assert(std.math.isPowerOfTwo(completion_queue_entries));
    assert(completion_queue_entries >= ring_entries);
    assert(completion_queue_entries <= io_uring_cq_entries_max);
    assert(relay_buffers_max <= conn_slots_max);
    assert(relay_buffers_max >= 1);
    assert(listeners_max >= 1);
    assert(in_flight_ops_max <= completion_queue_entries);
    assert(conn_slots_max - 1 <= std.math.maxInt(u16));
    assert(relay_buffer_bytes >= 512);
    assert(clusters_min >= 1);
    assert(clusters_max >= clusters_min);
    assert(endpoints_per_cluster_max >= 1);
    assert(routes_max >= 1);
    assert(filters_per_listener_max >= 1);
    assert(actions_per_filter_max >= 1);
    assert(header_matches_per_filter_max >= 1);
    assert(header_edits_max >= 1);
    assert(loop_completions_per_tick_max >= 1);
    assert(config_bytes_max >= 1024);
    assert(timeout_ms_max >= 1000);
    assert(accept_retry_delay_ms >= 1);
    assert(pressure_idle_divisor >= 2);
    assert(head_bytes_max >= 1024);
    assert(headers_max >= 8);
    assert(host_bytes_max >= 1);
    assert(upstream_slots_max >= 1);
    // The upstream pool's per-endpoint leased counts are u16: a bump past
    // this ceiling would wrap them in ReleaseFast and silently corrupt
    // the P2C load signal.
    assert(upstream_slots_max <= std.math.maxInt(u16));
    assert(chunked_line_bytes_max >= 32);
    assert(chunked_line_bytes_max <= relay_buffer_bytes);
    assert(chunked_trailer_bytes_max >= chunked_line_bytes_max);
    // The watermarks must leave a hysteresis gap and never engage above
    // the pool's own capacity, checked at the production size.
    assert(poolPressureOn(relay_buffers_max) > poolPressureOff(relay_buffers_max));
    assert(poolPressureOn(relay_buffers_max) <= relay_buffers_max);
    // The conn-slot ceiling is derived, not chosen: the largest slot
    // count whose worst-case ops fit the ¾-CQ budget after the fixed
    // ops — the parked-upstream reservation and the admin listener plus
    // its one client op — are carved out (§8).
    assert(conn_slots_max == @divFloor(
        completion_queue_entries * 3 / 4 -
            2 * (@as(u32, listeners_max) + admin_listeners) -
            admin_conns * admin_conn_ops_max - 1 - 1 - upstream_slots_max,
        conn_ops_max,
    ));
    assert(admin_listeners >= 1);
    assert(admin_conns >= 1);
    assert(admin_conn_ops_max >= 1);
    assert(admin_scrape_deadline_ms >= 1);
    assert(admin_drain_scratch_bytes >= 1);
}

/// Total pool memory as a closed-form function of the *effective* pool
/// sizes (the config `limits` block may shrink them below the ceilings,
/// §5). Slot sizes are runtime parameters because `Conn` is generic over
/// the Io backend; the composition site passes `@sizeOf` of the concrete
/// types and main.zig prints the result at startup.
pub fn memoryBytesTotal(
    conn_slots: u32,
    conn_bytes: u64,
    relay_buffers: u32,
    relay_buffer_pair_bytes: u64,
    upstream_slots: u32,
    upstream_bytes: u64,
) u64 {
    assert(conn_slots >= 1);
    assert(conn_slots <= conn_slots_max);
    assert(relay_buffers >= 1);
    assert(relay_buffers <= relay_buffers_max);
    assert(upstream_slots >= 1);
    assert(upstream_slots <= upstream_slots_max);
    assert(conn_bytes > 0);
    assert(relay_buffer_pair_bytes >= 2 * @as(u64, relay_buffer_bytes));
    assert(upstream_bytes >= head_bytes_max);
    const total = @as(u64, conn_slots) * conn_bytes +
        @as(u64, relay_buffers) * relay_buffer_pair_bytes +
        @as(u64, upstream_slots) * upstream_bytes;
    assert(total > 0);
    return total;
}

test "budgets: in-flight ops fit the completion queue with headroom" {
    try std.testing.expect(in_flight_ops_max <= completion_queue_entries);
    // Headroom is deliberate: at least a quarter of the CQ stays free for
    // completion bursts even at the worst-case armed-op count.
    try std.testing.expect(in_flight_ops_max <= completion_queue_entries * 3 / 4);
}

test "pressure: relay watermarks have a hysteresis gap at every capacity" {
    // On > Off (a non-empty gap) and On <= capacity for the small pools
    // tests inject as well as the production size — no flapping, never a
    // threshold the pool cannot reach.
    for ([_]u32{ 1, 2, 3, 4, 8, relay_buffers_max }) |capacity| {
        try std.testing.expect(poolPressureOn(capacity) > poolPressureOff(capacity));
        try std.testing.expect(poolPressureOn(capacity) <= capacity);
    }
    // A full pool is always pressured; an empty pool never is.
    try std.testing.expectEqual(@as(u32, 3), poolPressureOn(4));
    try std.testing.expectEqual(@as(u32, 2), poolPressureOff(4));
}

test "budgets: memory total matches the closed form" {
    const conn_bytes: u64 = 10240;
    const pair_bytes: u64 = 2 * @as(u64, relay_buffer_bytes);
    const upstream_bytes: u64 = head_bytes_max + 64;
    // At the ceilings and at a shrunken (config-limits) shape alike.
    const expected_max = @as(u64, conn_slots_max) * conn_bytes +
        @as(u64, relay_buffers_max) * pair_bytes +
        @as(u64, upstream_slots_max) * upstream_bytes;
    try std.testing.expectEqual(expected_max, memoryBytesTotal(
        conn_slots_max,
        conn_bytes,
        relay_buffers_max,
        pair_bytes,
        upstream_slots_max,
        upstream_bytes,
    ));
    const expected_small = 64 * conn_bytes + 8 * pair_bytes + 8 * upstream_bytes;
    try std.testing.expectEqual(
        expected_small,
        memoryBytesTotal(64, conn_bytes, 8, pair_bytes, 8, upstream_bytes),
    );
}

test "budgets: fd count stays under a typical hard limit" {
    // 4096 is the common RLIMIT_NOFILE hard ceiling for unprivileged
    // processes; startup asserts against the real limit (§8), this test
    // guards the defaults against drifting past the common case.
    try std.testing.expect(fds_max <= 4096);
    try std.testing.expectEqual(@as(u32, 3078), fds_max);
}

test "budgets: conn slots sit at the completion-queue ceiling" {
    // The ¾-CQ headroom rule is what actually caps concurrent
    // connections; conn_slots_max is the largest value that still
    // satisfies it after the parked-upstream reservation, so one more
    // slot would break the budget.
    try std.testing.expect(in_flight_ops_max <= completion_queue_entries * 3 / 4);
    const one_more = (conn_slots_max + 1) * conn_ops_max + upstream_slots_max +
        2 * (@as(u32, listeners_max) + admin_listeners) +
        admin_conns * admin_conn_ops_max + 1 + 1;
    try std.testing.expect(one_more > completion_queue_entries * 3 / 4);
}
