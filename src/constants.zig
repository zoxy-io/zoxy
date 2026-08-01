//! Every static limit in one place. Total memory, fd count, and in-flight
//! ring ops are closed-form functions of these numbers (DESIGN.md §5, §8):
//! main.zig prints the budgets at startup, and the comptime asserts below
//! keep the relationships true. Pools never grow; exhaustion sheds load.

const std = @import("std");

const assert = std.debug.assert;

/// Upper bound on configured listeners.
pub const listeners_max: u16 = 8;

/// The single dedicated admin/metrics listener (DESIGN.md §8): separate
/// from the configured `listeners_max` so a scrape can
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
/// the data path's `conn_ops_max`); the `close` never joins the set —
/// the same close-after-full-drain discipline the data path's
/// `continueTeardown` follows — so the peak is three, not four. The
/// accept op is the listener's, budgeted in the two-per-listener term.
pub const admin_conn_ops_max: u32 = 3;

/// Deadline for one admin scrape, from accept to close (§8): the reaper
/// that keeps a stalled or slowloris scrape client from pinning the single
/// reserved admin slot forever. Short — a metrics scrape is a localhost
/// round trip — and independent of the data path's `idle_timeout_ms`.
pub const admin_scrape_deadline_ms: u32 = 5_000;

/// Throwaway buffer for the admin lingering-close drain (§7): the scrape's
/// request is discarded, never inspected, so one small fixed buffer read
/// in a loop to EOF suffices — sized only to keep the read count modest.
pub const admin_drain_scratch_bytes: u32 = 512;

/// Connection slots (`Pool(Conn)`). The binding constraint is the
/// io_uring completion queue, not fds or memory (§8): every admitted
/// connection — L4 relaying or L7 in any phase — can hold up to
/// `conn_ops_max` armed ops whether or not it holds a relay buffer
/// (an L7 head read is a data op like any other), so every slot claims
/// its worst-case share of the pre-budgeted ring. The ring requests the
/// deepest CQ the kernel allows (`completion_queue_entries`,
/// IORING_SETUP_CQSIZE) against the 4096 SQ, so at the largest fill a
/// config may pick (`cq_fill_eighths_default` = ⅞, 57344) with the
/// parked-upstream, admin, access-log and health-probe reservations
/// carved out first, this caps at
/// `(57344 - 27) / (conn_ops_max + 1) = 11463` —
/// comptime-derived below (the 27 is the fixed ops: two per config and
/// admin listener [18], the admin client's op budget [3], the access log's
/// in-flight sink write [1], the health prober's op budget [3], the signal
/// wake [1], and the drain timer [1]). That clears a round 10k on a
/// single ring; a deployment trades the ceiling back down for more burst
/// headroom via `limits.cq_fill_eighths` (§8).
///
/// `upstream_slots_max` is pinned to this, and the `+ 1` in the divisor
/// is that pin: on the L7 path an admitted connection that is mid-exchange
/// holds one upstream slot as well as its conn slot, and at saturation
/// every admitted connection can be mid-exchange at once. A conn ceiling
/// above the upstream ceiling is therefore capacity that cannot be served
/// — slots that admit connections the pool has no upstream for — and one
/// below it is a pool that can never be drawn down. `11463` is the
/// largest N with `N * (conn_ops_max + 1) <= 57317`, which keeps both
/// ceilings clear of a round 10k: what §1 asks for, c10k reachable on
/// either axis rather than a shape tuned for it.
///
/// It was 12282 against an upstream ceiling of 8192, which measured out
/// as ~2200 conn slots that stayed idle while the pool they depend on
/// pinned at its own ceiling; IMPLEMENTATION_NOTES.md ("The upstream pool
/// tracks connections, not requests") is the one home for those numbers.
/// The pair is still a policy choice made on the operator's behalf;
/// IMPLEMENTATION_NOTES.md ("Open questions" — pool ceilings) holds the
/// standing question of handing it to them instead.
pub const conn_slots_max: u32 = 11463;

/// Relay buffer pairs (`Pool(RelayBuffer)`) — the bound on concurrent L4
/// connections plus active L7 body relays (§5, §6). Sized to the
/// conn-slot ceiling: the completion queue binds both (see
/// `conn_slots_max`), and a buffer beyond the slot count could never be
/// acquired.
pub const relay_buffers_max: u32 = conn_slots_max;

/// Bytes per relay direction; a `RelayBuffer` is a pair of these. Held to
/// 4 KiB: the strict recv→send→recv relay (§6) is correct at any size, so
/// the smaller buffer halves relay-pool memory (8 KiB per pair, not 16) —
/// which matters now the c10k ceiling puts up to `relay_buffers_max` pairs
/// in the pool — and trades throughput for more round trips only on
/// high-bandwidth-delay streams, negligible on the loopback and LAN paths
/// this proxy targets.
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
/// keep-alive does not re-cut the budgets.
///
/// This is the *ceiling*, not the out-of-box size — `upstream_slots_default`
/// stays lean below it, the same two-layer shape conn slots have. It was
/// 1024, where ceiling and default were the same number and an operator
/// could only go *down*; at 10k connections that pool pinned and shed a
/// third of all responses. Then 8192, which still sat below
/// `conn_slots_max` — and since the pool holds one live upstream per live
/// client connection, a conn ceiling the pool cannot cover is unreachable
/// capacity. Both are measured, not guessed; IMPLEMENTATION_NOTES.md
/// ("The upstream pool was a wall, not a range" and "The upstream pool
/// tracks connections, not requests") is their one home.
///
/// Pinned to `conn_slots_max`, the same way `relay_buffers_max` is and
/// for the same reason: a slot past the conn-slot count could never be
/// acquired, and a slot short of it admits a connection nothing can
/// serve. The two trade against each other on one CQ line, so pinning
/// them collapses that line to a single divisor — `conn_ops_max + 1` ring
/// ops per admitted connection — instead of two numbers that must be
/// edited together and can silently drift apart.
pub const upstream_slots_max: u32 = conn_slots_max;

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

/// Worst-case simultaneously armed ring ops for one connection: four.
/// Two peaks tie: a teardown racing its own upstream dial holds
/// {connect, deadline, connect_cancel, deadline_cancel}, and a relay
/// teardown holds {both data ops, deadline, deadline_cancel}. Closes
/// never join either set — they are not ring ops at all:
/// `continueTeardown` closes synchronously once every armed op has
/// drained, nothing referencing the fds by then. Serializing them
/// behind the drain is what cut this budget from five (a dial
/// completing against its own cancel used to co-arm the closes with
/// the deadline and both cancels); making them synchronous then
/// removed their two completions outright. `Conn.arm` asserts the
/// budget on every arm, and the drain-vs-dial sim test pins seeds
/// that reach exactly four (§8, §9).
pub const conn_ops_max: u32 = 4;

/// Completions drained per loop tick before control returns to the kernel;
/// bounds both callback batches and `Io.now_ns` staleness (§4).
pub const loop_completions_per_tick_max: u32 = 256;

/// The largest endpoint index a cluster may produce — the index type's
/// edge, not a policy ceiling. `Conn.endpoint_none` is `maxInt(u16)` and
/// must never collide with a real index, so this sits one below it. The
/// loader rejects a cluster that would produce a larger index
/// (`EndpointsOverLimit`) and `Conn` asserts the relationship, so the two
/// halves are tied together by this constant rather than by two files
/// happening to spell `maxInt(u16)` the same way.
pub const endpoint_index_max: u16 = std.math.maxInt(u16) - 1;

/// Upper bound on a cluster's name. Names are identifiers an operator
/// writes and the access log echoes (§8), so the bound is what keeps a
/// log line's width closed-form rather than a function of the config file.
pub const cluster_name_bytes_max: u16 = 64;

/// Lower bound on configured clusters: a config with no cluster can route
/// nowhere, so the loader rejects an empty map and the config JSON Schema
/// emits it as `minProperties`.
pub const clusters_min: u16 = 1;

/// The largest in-flight total one endpoint can ever carry (§7), and so
/// the ceiling a configured `max_inflight` is validated against: one L7
/// lease per upstream slot plus one L4 charge per conn slot, since a
/// connection of either kind holds exactly one of those. A cap at or
/// above this can never refuse anything, so the loader rejects it rather
/// than letting a typo'd figure read as "unlimited" — which is what
/// omitting the field already says, unambiguously.
pub const endpoint_inflight_max: u32 = conn_slots_max + upstream_slots_max;

/// Worst-case simultaneously armed ring ops for the §7 health prober:
/// three. One probe is in flight at a time — {connect, probe deadline}
/// co-armed while dialing — and settling a verdict or draining adds one
/// cancel to whichever op is still armed ({connect, deadline,
/// connect_cancel} at the peak; a drain teardown cancels serially, never
/// both cancels at once). Reserved in the fd and ring budgets below
/// unconditionally, the same rule as `admin_conn_ops_max`: the ceiling
/// is a comptime constant, so it must cover the worst case even when no
/// cluster sets `check`.
pub const health_probe_ops_max: u32 = 3;

/// Default consecutive failed probes that eject an endpoint from
/// balancing (§7), when a cluster's `check` block omits `fall`.
/// HAProxy's `fall` default: three misses is an outage, one is a blip.
pub const health_probe_fall_default: u8 = 3;

/// Default consecutive successful probes that restore an ejected
/// endpoint (§7), when a cluster's `check` block omits `rise`.
/// HAProxy's `rise` default: recovery must prove itself twice.
pub const health_probe_rise_default: u8 = 2;

/// Upper bound on a configured `fall`/`rise`. The streak counters are
/// `u8`, so this is what keeps them from wrapping; it is also far past
/// any useful tuning — a threshold in the dozens means the *interval* is
/// the wrong knob, since detection latency is `fall × interval`.
pub const health_probe_threshold_max: u8 = 64;

/// Default `timeouts.health_interval_ms`: the pause between health-probe
/// sweeps when the config omits it (§7). HAProxy's `inter` default. What
/// bounds a single probe is the check's own `timeout_ms`, which defaults
/// to `timeouts.connect_ms`.
pub const health_interval_ms_default: u32 = 2_000;

/// Upper bound on a configured HTTP-check request path (§7). The probe
/// renders one request into a fixed buffer, so the path it may carry is
/// bounded like every other config string; a health endpoint's path is a
/// handful of bytes in practice.
pub const health_check_path_bytes_max: u16 = 256;

/// Upper bound on a configured HTTP-check `Host` value (§7). Same bound
/// as a routing host, and for the same reason — it is a DNS name.
pub const health_check_host_bytes_max: u16 = host_bytes_max;

/// The probe's rendered request buffer (§7): request line + Host +
/// the two fixed headers, all bounded by the two limits above.
pub const health_check_request_bytes_max: u32 =
    64 + health_check_path_bytes_max + health_check_host_bytes_max;

// Routes and filters carry no ceiling of their own (§7 "filters are
// data"). They are immutable arena slices allocated at exactly the
// length the config asked for, so they size nothing that a comptime
// bound could protect: what a large table costs is arena bytes and a
// longer request-time linear scan, both of which are the operator's
// call to make in their own config. The request-time loops stay bounded
// — by a length fixed at startup rather than by a constant here.
//
// `header_edits_max` below is the exception, and the difference is the
// rule: it bounds a *fixed buffer* the renderer materializes into, so
// the number must be known before the config is read.

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

/// Default `timeouts.connect_ms`: the per-try upstream dial budget when
/// the config omits it (§5). Five seconds is the conventional figure — an
/// order below nginx's 60 s `proxy_connect_timeout`, which is a read
/// timeout's worth of patience for what is only a handshake. A dial that
/// has not completed in five seconds is answered 504 and, on a
/// multi-endpoint cluster, retried elsewhere sooner.
pub const connect_ms_default: u32 = 5_000;

/// Default `timeouts.idle_ms`: the idle and head-read deadline when the
/// config omits it (§5). nginx's neighbours are `keepalive_timeout` at
/// 75 s and `client_header_timeout` at 60 s; this takes the lower of the
/// two, since the same number here also bounds a slowloris dribbling its
/// head. Shortened further under pool pressure (§8), so this is the
/// unpressured ceiling rather than what a busy proxy actually waits.
pub const idle_ms_default: u32 = 60_000;

/// Bytes of inbound `X-Forwarded-For` chain an `append` listener will
/// carry (§7). A chain grows by one address at every hop, and nothing in
/// the protocol bounds it — so a client that sends a megabyte of forged
/// hops would otherwise decide how much of this proxy's head buffer its
/// request occupies. Past this the chain is dropped entirely and the line
/// states only the observed peer, which is the `replace` behavior: the
/// fail-safe direction, since the alternative is trusting a chain
/// specifically shaped to be untrustworthy. Witnessed by
/// `forwarded_chain_dropped`.
///
/// 512 bytes carries roughly a dozen IPv6 hops, past any real topology.
pub const forwarded_chain_bytes_max: u16 = 512;

/// Scratch for formatting one client address before the port is stripped
/// (§7). Sized for the *formatted* form, not the bare one it yields:
/// `[` + 39 bytes of IPv6 + `]:` + 5 port digits is 47, and 64 leaves the
/// bound obviously sufficient rather than exactly so.
pub const forwarded_client_bytes_max: u8 = 64;

/// The whole `X-Forwarded-For` value one request may emit: the carried
/// chain, the `", "` joining it, and the observed peer. Derived rather
/// than chosen, so raising the chain bound cannot leave the buffer the
/// value is assembled in one address short.
pub const forwarded_value_bytes_max: u32 =
    @as(u32, forwarded_chain_bytes_max) + 2 + forwarded_client_bytes_max;

// -- the access log (§8) --
//
// One JSON line per L7 exchange and per L4 connection, written to the
// configured sink through the seam's one ring op. The bounds below are what
// make that a closed-form cost: two staging buffers of a fixed size, a line
// that cannot exceed a fixed width, and per-record captures that cannot
// exceed a fixed share of a connection slot.

/// Bytes per access-log staging buffer when the config does not say; there
/// are two (`access_log_buffers`), so the default reservation is twice
/// this. Two rather than one because a write is a ring op: while it is in
/// flight its bytes must not move, and the lines still arriving need
/// somewhere to go. One buffer accepts appends while the other is being
/// written, and they swap when it drains — no memmove, and no window where
/// a line has nowhere to land except the drop counter.
///
/// 32 KiB holds ~130 typical lines, which at any plausible request rate is
/// far more than one sink write takes to complete. A burst that outruns it
/// drops lines and counts them (§8's ladder: exhaustion sheds the newest
/// work), because the alternative — waiting for the sink — would make an
/// operator's log pipe able to stall the data path.
pub const access_log_buffer_bytes_default: u32 = 32 * 1024;
/// The ceiling and floor `limits.access_log_buffer_bytes` may name. The
/// floor is one line: a buffer that could not hold the widest single line
/// would drop every wide one regardless of backpressure, which is the one
/// thing the drop counter must never mean. The simulator sizes down to it
/// to force the drop rung, the same way it sizes the pools down to force
/// theirs (§9).
pub const access_log_buffer_bytes_min: u32 = access_log_line_bytes_max;
pub const access_log_buffer_bytes_max: u32 = 1024 * 1024;
pub const access_log_buffers: u32 = 2;

/// Worst-case simultaneously armed ring ops for the access log: one. The
/// sink has a single write in flight at a time by construction — the second
/// staging buffer is what absorbs everything that arrives meanwhile — so it
/// costs exactly one entry in the §8 ring budget, reserved unconditionally
/// like the admin plane's so the compiled ceiling covers a config that
/// enables it.
pub const access_log_ops_max: u32 = 1;

/// Raw bytes of a request's canonical path kept for its log line. The path
/// lives in the connection's head buffer, which the response head renders
/// over (§7 buffer rotation), so what the log reports has to be copied out
/// while it is still there. A longer path is truncated with a trailing
/// `...` rather than dropped: the prefix is what identifies the resource.
pub const access_log_path_bytes_max: u16 = 256;

/// Raw bytes of a request method token kept for its log line. Standard
/// methods are at most 7 bytes; the bound covers extension tokens (§7)
/// without letting one widen a log line without limit.
pub const access_log_method_bytes_max: u8 = 24;

/// Upper bound on one rendered access-log line, including its newline
/// (§5: the caller sizes a fixed buffer to it, so a line never has to be
/// dropped for want of room in an *empty* buffer). Derived from the field
/// caps rather than chosen, so raising one of them cannot silently make
/// the bound a lie. The `6 *` on the two text fields is JSON's worst case:
/// a control byte escapes to `\u00XX`, and a percent-decoded path may
/// legitimately contain one.
pub const access_log_line_bytes_max: u32 = blk: {
    // Every key, brace, comma, quote, and the trailing newline, with slack
    // for a field or two more before the bound has to be re-derived.
    const scaffolding = 320;
    const timestamp = 30; // "2026-07-31T09:14:22.481Z"
    // "[" + 39 bytes of IPv6 + "]:" + 5 port digits, quoted.
    const address = 48;
    const number = 20; // a u64 at its widest
    const addresses = 2; // client and upstream
    const numbers = 4; // duration, bytes in, bytes out, status
    break :blk scaffolding + timestamp + addresses * address + numbers * number +
        @as(u32, access_log_method_bytes_max) + @as(u32, cluster_name_bytes_max) +
        6 * @as(u32, host_bytes_max) + 6 * @as(u32, access_log_path_bytes_max);
};

/// Worst-case in-flight ring ops (§8: the ring is pre-budgeted, not shed):
/// every connection slot at its op peak (L7 slots hold armed ops with or
/// without a relay buffer, so the term is per slot, not per buffer), one
/// idle-timer op per parked upstream (§5/§8 — reserved ahead of the
/// keep-alive slice), two ops per listener — configured *and* admin — (a
/// draining listener holds its armed accept — or the accept-retry backoff
/// timer — plus the async cancel that reaps it), `admin_conn_ops_max` ops
/// per admin client (its send/deadline/teardown peak), the access log's one
/// in-flight sink write, `health_probe_ops_max` ops for the single
/// in-flight health probe (§7), the single async wakeup op for signals, and
/// the server's one drain-deadline timer. Closed form so it can be
/// evaluated on the *effective* pool sizes too (XevIo's per-deployment CQ),
/// not only the ceilings; the admin, access-log and health-probe
/// reservations are fixed — always covered even when a config leaves them
/// off; `in_flight_ops_max` is it at the ceilings.
pub fn inFlightOps(conn_slots: u32, upstream_slots: u32, listeners: u32) u32 {
    assert(conn_slots <= conn_slots_max);
    assert(upstream_slots <= upstream_slots_max);
    assert(listeners <= listeners_max);
    return conn_slots * conn_ops_max + upstream_slots +
        2 * (listeners + admin_listeners) +
        admin_conns * admin_conn_ops_max + access_log_ops_max +
        health_probe_ops_max + 1 + 1;
}
pub const in_flight_ops_max: u32 =
    inFlightOps(conn_slots_max, upstream_slots_max, listeners_max);

/// Kernel maximum for an IORING_SETUP_CQSIZE completion queue
/// (IORING_MAX_CQ_ENTRIES = 2 × IORING_MAX_ENTRIES) on current kernels.
/// The upper wall on any requested CQ depth — a request past this fails
/// `Loop.init` at runtime, so the comptime assert below (and `completionQueueDepthFor`'s
/// clamp) keep it out of reach.
pub const completion_queue_entries_max: u32 = 65536;

/// §8 CQ fill: in-flight ring ops may occupy at most this many eighths of
/// the completion queue; the rest stays free to absorb completion bursts.
/// ⅞ is both the default and the largest fill a config may request — it is
/// the fill the `conn_slots_max` ceiling is derived at, so no deployment
/// can demand a CQ deeper than the pools were sized for. An operator
/// trades the ceiling down for more burst headroom by lowering
/// `limits.cq_fill_eighths` toward `cq_fill_eighths_min`. ⅞ replaced the
/// original ¾ (= 6/8) once the CQSIZE lever (#61) made the CQ a real
/// kernel argument.
pub const cq_fill_eighths_default: u32 = 7;
/// The largest fill (least burst headroom) any config may request: equal to
/// the default, because the compiled ceiling reserves exactly this much —
/// asking for more would demand a ring past the c10k budget.
pub const cq_fill_eighths_max: u32 = cq_fill_eighths_default;
/// The smallest fill (most burst headroom) any config may request. At the
/// floor in-flight ops fill only ⅛ of the CQ — the most burst slack a
/// deployment can reserve, at the cost of the lowest connection ceiling.
pub const cq_fill_eighths_min: u32 = 1;

/// The CQ depth a deployment needs: its worst-case in-flight ops fit
/// within `cq_fill_eighths`/8 of the ring (invert `in_flight <= cq ×
/// eighths/8`), rounded up to a power of two and clamped to the kernel
/// range. XevIo requests this via IORING_SETUP_CQSIZE, so a small
/// deployment gets a shallow ring and only a c10k one asks for the full
/// 65536. The caller must have validated feasibility (`cqFillFits`): at
/// the max fill an in-domain conn count always fits, and a tighter fill
/// only ever asks for a *deeper* ring, so the fill postcondition holds.
pub fn completionQueueDepthFor(
    conn_slots: u32,
    upstream_slots: u32,
    listeners: u32,
    cq_fill_eighths: u32,
) u32 {
    assert(cq_fill_eighths >= cq_fill_eighths_min);
    assert(cq_fill_eighths <= cq_fill_eighths_max);
    const in_flight = inFlightOps(conn_slots, upstream_slots, listeners);
    // The shallowest ring whose fill budget covers every in-flight op;
    // eighths >= 1 is asserted above, so the divide never faults.
    const with_headroom = std.math.divCeil(u32, in_flight * 8, cq_fill_eighths) catch unreachable;
    const depth = std.math.ceilPowerOfTwo(u32, @max(with_headroom, ring_entries)) catch
        completion_queue_entries_max;
    // Explicit u32: `@min` with a comptime bound would otherwise narrow the
    // type to u17, overflowing the fill check below.
    const clamped: u32 = @min(depth, completion_queue_entries_max);
    // A power-of-two ring is a multiple of 8 (>= ring_entries), so the fill
    // budget is exact — `@divExact` pins that structurally. A feasible
    // in-domain caller keeps in_flight within it; the ring is >= the SQ.
    assert(in_flight <= @divExact(clamped, 8) * cq_fill_eighths);
    assert(std.math.isPowerOfTwo(clamped));
    assert(clamped >= ring_entries);
    return clamped;
}

/// Whether a deployment's worst-case in-flight ops fit the deepest kernel
/// CQ at the requested fill (§8) — the loader's guard before it accepts a
/// `limits.cq_fill_eighths` that asks for more headroom than the conn-slot
/// count leaves room for. The kernel CQ is a power of two, so the fill
/// budget `completion_queue_entries_max / 8 * eighths` is exact.
pub fn cqFillFits(
    conn_slots: u32,
    upstream_slots: u32,
    listeners: u32,
    cq_fill_eighths: u32,
) bool {
    assert(cq_fill_eighths >= cq_fill_eighths_min);
    assert(cq_fill_eighths <= cq_fill_eighths_max);
    const in_flight = inFlightOps(conn_slots, upstream_slots, listeners);
    // The kernel CQ max is a power of two, so its fill budget is exact.
    return in_flight <= @divExact(completion_queue_entries_max, 8) * cq_fill_eighths;
}

/// The CQ capacity the §8 ceiling budgets are derived against: the depth a
/// deployment at the compiled ceilings would request. This is the kernel
/// maximum (65536), which is exactly what makes `conn_slots_max` the c10k
/// ceiling — as deep as one ring allows, independent of `ring_entries`.
pub const completion_queue_entries: u32 =
    completionQueueDepthFor(conn_slots_max, upstream_slots_max, listeners_max, cq_fill_eighths_default);

/// The fds a deployment needs (§8: fds are pre-budgeted, not shed): stdio
/// + ring + async eventfd + listeners (configured + admin) + two sockets
/// per admitted connection (client plus the exchange's upstream) + the one
/// transient just-accepted fd an admission decision is pending on + one
/// socket per in-flight admin scrape + one socket per parked upstream,
/// which belongs to no connection + the one socket the in-flight health
/// probe may hold while dialing (§7). Closed form so `ensureFdBudget` can
/// check the *effective* size against RLIMIT_NOFILE; the admin and
/// health-probe reservations are fixed; `fds_max` is it at the ceilings.
pub fn fdsRequired(conn_slots: u32, upstream_slots: u32, listeners: u32) u32 {
    assert(conn_slots <= conn_slots_max);
    assert(upstream_slots <= upstream_slots_max);
    assert(listeners <= listeners_max);
    return 3 + 1 + 1 + (listeners + admin_listeners) +
        2 * conn_slots + 1 + admin_conns + upstream_slots + 1;
}
pub const fds_max: u32 =
    fdsRequired(conn_slots_max, upstream_slots_max, listeners_max);

/// Default effective pool sizes when the config omits a `limits` block: a
/// lean out-of-box footprint (~33 MiB of pools, well under a routine 4096
/// RLIMIT_NOFILE, a shallow ring) rather than the c10k worst case. An
/// operator opts into more concurrency — up to the compiled ceilings —
/// through the config `limits` block, and the fd budget (`fdsRequired`,
/// `ensureFdBudget`) and requested CQ depth (`completionQueueDepthFor`,
/// XevIo) then track the *effective* sizes, so a small deployment neither
/// reserves nor demands the ceiling's resources (§5, §8).
///
/// `conn_slots_default` is tuned to that ~32 MiB target against the current
/// per-slot sizes (a conn slot + its relay buffer is ~17.7 KiB, plus the
/// fixed upstream pool); it is not derived because `@sizeOf(Conn)` is not
/// available here (Conn is generic over the Io backend). main.zig prints
/// the resulting footprint at startup.
pub const conn_slots_default: u32 = 1386;
pub const relay_buffers_default: u32 = conn_slots_default;
/// Deliberately *not* `upstream_slots_max`. It used to be, which left the
/// two identical and the pool the one thing an operator could only shrink
/// — the defect the raised ceiling exists to fix. The default answers a
/// different question than the ceiling does: the ceiling is how far an
/// L7 deployment may climb, this is what an unconfigured one costs.
///
/// It sits *below* `conn_slots_default` even though a saturated L7
/// deployment needs one upstream slot per busy conn slot (see
/// `conn_slots_max`), because the out-of-box shape is bounded by the
/// stock 4096 `RLIMIT_NOFILE` rather than by admission: matching 1386
/// would put the default at 4168 fds, over that line, for capacity an
/// unconfigured proxy is not there to serve. 1313 is the largest value
/// that still clears that line — `fdsRequired(conn_slots_default, x, 1)`
/// is `2782 + x` (the health probe's reserved fd included), and that must
/// stay strictly under 4096 (the out-of-box budget stays *under* the
/// stock limit, not flush against it), so `4096 - 2782 - 1 = 1313` — the
/// default leans as far toward
/// `conn_slots_default` as the stock fd budget allows. An L4
/// deployment never leases from this pool at all — an L4 dial reads its
/// `leased_counts` for the P2C draw and holds no slot. A deployment that
/// means to fill its conn pool raises both together in `limits` — which
/// is what the ceilings exist to permit and what the c10k benchmark
/// configuration does.
pub const upstream_slots_default: u32 = 1313;

comptime {
    assert(std.math.isPowerOfTwo(ring_entries));
    assert(ring_entries <= 4096);
    // The CQ depth is now a real kernel argument (XevIo requests it via
    // IORING_SETUP_CQSIZE), so it must be a value the kernel accepts: a
    // power of two, at least the SQ depth, and within the kernel cap.
    assert(std.math.isPowerOfTwo(completion_queue_entries));
    assert(completion_queue_entries >= ring_entries);
    assert(completion_queue_entries <= completion_queue_entries_max);
    // The CQ fill bounds: at least one eighth of the ring always stays free
    // for completion bursts (max <= 7), the floor packs at least one eighth
    // (min >= 1), and the default is a value in that range. The ceiling is
    // derived at the default, so the default must equal the max.
    assert(cq_fill_eighths_min >= 1);
    assert(cq_fill_eighths_max <= 7);
    assert(cq_fill_eighths_min <= cq_fill_eighths_default);
    assert(cq_fill_eighths_default == cq_fill_eighths_max);
    // The defaults are a lean, valid subset of the ceilings.
    assert(conn_slots_default >= 1 and conn_slots_default <= conn_slots_max);
    assert(relay_buffers_default >= 1 and relay_buffers_default <= relay_buffers_max);
    assert(relay_buffers_default <= conn_slots_default);
    assert(upstream_slots_default >= 1 and upstream_slots_default <= upstream_slots_max);
    assert(relay_buffers_max <= conn_slots_max);
    assert(relay_buffers_max >= 1);
    assert(listeners_max >= 1);
    assert(in_flight_ops_max <= completion_queue_entries);
    assert(conn_slots_max - 1 <= std.math.maxInt(u16));
    assert(relay_buffer_bytes >= 512);
    assert(clusters_min >= 1);
    // The §8 cap ceiling is the largest load one endpoint can carry: one
    // L7 lease per upstream slot plus one L4 charge per conn slot, since
    // a connection of either kind holds exactly one. Asserted rather than
    // merely written that way, so a change to either pool ceiling cannot
    // silently leave a cap validated against a total nothing can reach.
    assert(endpoint_inflight_max == conn_slots_max + upstream_slots_max);
    assert(endpoint_inflight_max >= conn_slots_max);
    assert(endpoint_inflight_max >= upstream_slots_max);
    assert(header_edits_max >= 1);
    assert(loop_completions_per_tick_max >= 1);
    assert(timeout_ms_max >= 1000);
    // The two defaulted deadlines must themselves be configs the loader
    // would accept: non-zero, and under the shared ceiling.
    assert(connect_ms_default >= 1);
    assert(connect_ms_default <= timeout_ms_max);
    assert(idle_ms_default >= 1);
    assert(idle_ms_default <= timeout_ms_max);
    // The dial budget must sit below the idle one. A connection's first
    // deadline is armed at `connect_ms` (`Server.entryTimeoutMs`) and the
    // dial's completion re-stores it to `idle_ms`, but the *physical*
    // timer never moves earlier — only the stored target does (§4). So an
    // idle budget below the dial budget is not shortened by the
    // handoff; it waits out the connect-phase timer instead.
    //
    // This guards the pair above; `validateTimeouts` rejects the same
    // relation in an operator's own two values, and `Server.init` asserts
    // it of whatever config it is handed, so the ordering holds however a
    // config was built rather than only for the defaults.
    assert(connect_ms_default < idle_ms_default);
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
    // count whose worst-case ops fit the ⅞-CQ budget (at the default =
    // loosest fill) after the fixed ops — the parked-upstream reservation
    // and the admin listener plus its one client op — are carved out (§8).
    // The pair is pinned (`upstream_slots_max = conn_slots_max`), so the
    // shared CQ line has one divisor — an admitted connection costs
    // `conn_ops_max` conn ops plus the one op of the upstream slot it may
    // need — rather than one ceiling subtracting from the other.
    assert(upstream_slots_max == conn_slots_max);
    assert(conn_slots_max == @divFloor(
        @divExact(completion_queue_entries, 8) * cq_fill_eighths_default -
            2 * (@as(u32, listeners_max) + admin_listeners) -
            admin_conns * admin_conn_ops_max - access_log_ops_max -
            health_probe_ops_max - 1 - 1,
        conn_ops_max + 1,
    ));
    assert(admin_listeners >= 1);
    assert(admin_conns >= 1);
    assert(admin_conn_ops_max >= 1);
    assert(admin_scrape_deadline_ms >= 1);
    assert(admin_drain_scratch_bytes >= 1);
    // A staging buffer that could not hold the widest line would drop
    // lines it had room for — the bound exists precisely so a drop always
    // means backpressure, never arithmetic. The floor is that bound, so
    // no config can name a buffer that breaks it.
    assert(access_log_buffer_bytes_min >= access_log_line_bytes_max);
    assert(access_log_buffer_bytes_default >= access_log_buffer_bytes_min);
    assert(access_log_buffer_bytes_default <= access_log_buffer_bytes_max);
    // Two buffers exactly: the swap is what lets appends continue during
    // a write, and a third would be a queue nobody drains.
    assert(access_log_buffers == 2);
    // A carried chain plus the address appended to it must still leave a
    // head that can be rendered; both are a small fraction of the buffer
    // the whole head has to fit in.
    assert(forwarded_value_bytes_max < head_bytes_max);
    // The scratch must hold a bracketed IPv6 literal with its port, which
    // is what gets formatted before the port is stripped back off.
    assert(forwarded_client_bytes_max >= 47);
    assert(access_log_ops_max >= 1);
    assert(access_log_path_bytes_max >= 16);
    assert(access_log_method_bytes_max >= 7); // "OPTIONS", the longest standard method.
    assert(cluster_name_bytes_max >= 1);
    // The health prober's reservations and thresholds (§7): the op budget
    // covers dial + deadline + one cancel, a threshold of zero would eject
    // or restore on no evidence, and the default probe interval is a legal
    // configured timeout.
    assert(health_probe_ops_max >= 1);
    assert(health_probe_fall_default >= 1);
    assert(health_probe_rise_default >= 1);
    assert(health_probe_fall_default <= health_probe_threshold_max);
    assert(health_probe_rise_default <= health_probe_threshold_max);
    assert(health_interval_ms_default >= 1);
    assert(health_interval_ms_default <= timeout_ms_max);
    // The rendered probe request must fit its buffer whatever a config
    // names, which is what makes the render infallible (§5).
    assert(health_check_path_bytes_max >= 1);
    assert(health_check_host_bytes_max >= 1);
    assert(health_check_request_bytes_max >
        @as(u32, health_check_path_bytes_max) + health_check_host_bytes_max);
    // A probe response is parsed by the same head parser the data path
    // uses, so its buffer may never exceed what that parser accepts.
    assert(health_check_request_bytes_max <= head_bytes_max);
}

/// Total pool memory as a closed-form function of the *effective* pool
/// sizes (the config `limits` block may shrink them below the ceilings,
/// §5). Slot sizes are runtime parameters because `Conn` is generic over
/// the Io backend; the composition site passes `@sizeOf` of the concrete
/// types and main.zig prints the result at startup.
/// What the pools cost: a count and a slot size per pool. A struct rather
/// than six positional arguments because three of them are `u64` byte sizes
/// — transposing two of those compiles, runs, and silently prints the wrong
/// total, which the sanity asserts below could only sometimes catch. Named
/// fields make that particular mistake unrepresentable, and a fourth pool
/// (§4's TLS engines) is a field and a term rather than two more positions
/// at every call site.
///
/// Not `Config.Limits` plus byte sizes, though the three counts appear in
/// both: `config.zig` imports this file, so the dependency cannot run the
/// other way. `Limits` is what an operator provisions; this is what the
/// provisioning costs, and a new pool needs a field in each.
pub const PoolSizes = struct {
    conn_slots: u32,
    conn_bytes: u64,
    relay_buffers: u32,
    relay_buffer_pair_bytes: u64,
    upstream_slots: u32,
    upstream_bytes: u64,
    /// The access log's staging buffers (§8), or zero when the config
    /// leaves the log off. Not a pool — it is one fixed reservation, not a
    /// per-connection unit — but it is startup arena memory this process
    /// holds for its life, and §5's promise is that the printed total
    /// covers all of that. `accessLogBytes` is the closed form.
    access_log_bytes: u64,
    /// The endpoint-keyed tables (§7) — the pool's idle heads and lease
    /// counts, the balancer's endpoint hashes, cursors and pick scratch,
    /// the server's L4 charges, and the health checker's mask and two
    /// streak counters. Startup arena memory held for the process's life,
    /// so §5's promise covers it.
    ///
    /// Passed in rather than derived here because the per-entry widths
    /// belong to those modules' element types, not to this file: computing
    /// it from hardcoded widths would silently drift the moment one of
    /// them changed. `Server.endpointTableBytes` is the closed form.
    endpoint_table_bytes: u64,
};

/// What the access log reserves: nothing when it is off, both staging
/// buffers at the effective size when it is on (§8). `buffer_bytes` is
/// zero exactly when the log is off, so one argument carries both facts
/// and they cannot be passed inconsistently.
pub fn accessLogBytes(buffer_bytes: u32) u64 {
    if (buffer_bytes == 0) return 0;
    assert(buffer_bytes >= access_log_buffer_bytes_min);
    assert(buffer_bytes <= access_log_buffer_bytes_max);
    return @as(u64, access_log_buffers) * buffer_bytes;
}

/// By pointer: `PoolSizes` is past the 16-byte threshold TIGER_STYLE sets
/// for by-value arguments, and a stack copy of the budget buys nothing.
pub fn memoryBytesTotal(sizes: *const PoolSizes) u64 {
    assert(sizes.conn_slots >= 1);
    assert(sizes.conn_slots <= conn_slots_max);
    assert(sizes.relay_buffers >= 1);
    assert(sizes.relay_buffers <= relay_buffers_max);
    assert(sizes.upstream_slots >= 1);
    assert(sizes.upstream_slots <= upstream_slots_max);
    assert(sizes.conn_bytes > 0);
    assert(sizes.relay_buffer_pair_bytes >= 2 * @as(u64, relay_buffer_bytes));
    assert(sizes.upstream_bytes >= head_bytes_max);
    // Either the log is off and costs nothing, or it holds exactly its two
    // buffers at a size the loader validated — never some third number.
    assert(sizes.access_log_bytes % access_log_buffers == 0);
    assert(sizes.access_log_bytes == 0 or
        sizes.access_log_bytes >=
            @as(u64, access_log_buffers) * access_log_buffer_bytes_min);
    assert(sizes.access_log_bytes <=
        @as(u64, access_log_buffers) * access_log_buffer_bytes_max);
    const total = @as(u64, sizes.conn_slots) * sizes.conn_bytes +
        @as(u64, sizes.relay_buffers) * sizes.relay_buffer_pair_bytes +
        @as(u64, sizes.upstream_slots) * sizes.upstream_bytes +
        sizes.access_log_bytes + sizes.endpoint_table_bytes;
    assert(total > 0);
    return total;
}

test "budgets: in-flight ops fit the completion queue with headroom" {
    try std.testing.expect(in_flight_ops_max <= completion_queue_entries);
    // Headroom is deliberate: at least an eighth of the CQ stays free for
    // completion bursts even at the worst-case armed-op count (the default
    // = loosest fill the ceiling is derived at).
    try std.testing.expect(in_flight_ops_max <= @divExact(completion_queue_entries, 8) * cq_fill_eighths_default);
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
    // The endpoint-keyed tables (§7): like the access log, a reservation
    // that must move the total by exactly its own size and nothing else.
    const endpoint_tables: u64 = 4096;
    // At the ceilings and at a shrunken (config-limits) shape alike, with
    // the access log on at the ceiling and off below it — the term is a
    // fixed reservation, so it must move the total by exactly its own size
    // and by nothing else.
    const expected_max = @as(u64, conn_slots_max) * conn_bytes +
        @as(u64, relay_buffers_max) * pair_bytes +
        @as(u64, upstream_slots_max) * upstream_bytes +
        accessLogBytes(access_log_buffer_bytes_default) + endpoint_tables;
    try std.testing.expectEqual(expected_max, memoryBytesTotal(&.{
        .conn_slots = conn_slots_max,
        .conn_bytes = conn_bytes,
        .relay_buffers = relay_buffers_max,
        .relay_buffer_pair_bytes = pair_bytes,
        .upstream_slots = upstream_slots_max,
        .upstream_bytes = upstream_bytes,
        .access_log_bytes = accessLogBytes(access_log_buffer_bytes_default),
        .endpoint_table_bytes = endpoint_tables,
    }));
    const expected_small = 64 * conn_bytes + 8 * pair_bytes + 8 * upstream_bytes;
    try std.testing.expectEqual(expected_small, memoryBytesTotal(&.{
        .conn_slots = 64,
        .conn_bytes = conn_bytes,
        .relay_buffers = 8,
        .relay_buffer_pair_bytes = pair_bytes,
        .upstream_slots = 8,
        .upstream_bytes = upstream_bytes,
        .access_log_bytes = accessLogBytes(0),
        .endpoint_table_bytes = 0,
    }));
    // An unconfigured access log reserves nothing (§5), and a configured
    // one reserves both buffers at whatever size it was given — the term
    // tracks `limits`, not the compiled default.
    try std.testing.expectEqual(@as(u64, 0), accessLogBytes(0));
    try std.testing.expectEqual(
        @as(u64, access_log_buffers) * access_log_buffer_bytes_default,
        accessLogBytes(access_log_buffer_bytes_default),
    );
    try std.testing.expectEqual(
        @as(u64, access_log_buffers) * access_log_buffer_bytes_min,
        accessLogBytes(access_log_buffer_bytes_min),
    );
}

test "budgets: c10k ceiling fd count needs a raised NOFILE" {
    // At the c10k ceiling the fd budget is ~33k — well past the common
    // 4096 unprivileged hard limit, so a deployment that configures up to
    // the ceiling must raise RLIMIT_NOFILE (systemd LimitNOFILE / ulimit).
    // `ensureFdBudget` checks the *effective* size against the real limit
    // at startup (§8); this pins the ceiling closed form.
    try std.testing.expectEqual(@as(u32, 34406), fds_max);
    try std.testing.expect(fds_max <= 65536);
    // The out-of-box side of this is pinned by "the default deployment is
    // lean" below, not restated here.
}

test "budgets: the default deployment is lean" {
    // The out-of-box config (no `limits` block) starts under a routine
    // 4096 NOFILE and asks the kernel for a shallow ring, not the c10k
    // ceiling — operators opt up through `limits` (§5). One listener.
    try std.testing.expect(fdsRequired(conn_slots_default, upstream_slots_default, 1) < 4096);
    try std.testing.expect(
        completionQueueDepthFor(conn_slots_default, upstream_slots_default, 1, cq_fill_eighths_default) <
            completion_queue_entries,
    );
    // The effective CQ still covers the default's in-flight ops with the
    // ⅞ headroom, exactly as the ceiling does for its own.
    const depth = completionQueueDepthFor(conn_slots_default, upstream_slots_default, 1, cq_fill_eighths_default);
    try std.testing.expect(inFlightOps(conn_slots_default, upstream_slots_default, 1) <= @divExact(depth, 8) * cq_fill_eighths_default);
}

test "budgets: conn slots sit at the completion-queue ceiling" {
    // The ⅞-CQ fill rule (at the default = loosest fill) is what actually
    // caps concurrent connections; conn_slots_max is the largest value
    // that still satisfies it after the parked-upstream reservation, so
    // one more slot would break the budget.
    try std.testing.expect(in_flight_ops_max <= @divExact(completion_queue_entries, 8) * cq_fill_eighths_default);
    const one_more = (conn_slots_max + 1) * conn_ops_max + upstream_slots_max +
        2 * (@as(u32, listeners_max) + admin_listeners) +
        admin_conns * admin_conn_ops_max + access_log_ops_max +
        health_probe_ops_max + 1 + 1;
    try std.testing.expect(one_more > @divExact(completion_queue_entries, 8) * cq_fill_eighths_default);
}

test "budgets: a tighter cq fill trades ceiling for burst headroom" {
    // More headroom (fewer eighths) never asks for a shallower ring: at a
    // fixed conn count the requested CQ is monotonic in the fill.
    const loose = completionQueueDepthFor(conn_slots_default, upstream_slots_default, 1, cq_fill_eighths_max);
    const tight = completionQueueDepthFor(conn_slots_default, upstream_slots_default, 1, cq_fill_eighths_min);
    try std.testing.expect(tight >= loose);
    // The conn-slot ceiling fits only at the max fill; one eighth tighter
    // overflows even the deepest kernel CQ — the loader must reject that
    // pairing (`cqFillFits` is the guard).
    try std.testing.expect(cqFillFits(conn_slots_max, upstream_slots_max, listeners_max, cq_fill_eighths_max));
    try std.testing.expect(!cqFillFits(conn_slots_max, upstream_slots_max, listeners_max, cq_fill_eighths_max - 1));
    // The lean default still fits with plenty of room to spare, even at the
    // old ¾ (= 6/8) fill and at the tightest floor.
    try std.testing.expect(cqFillFits(conn_slots_default, upstream_slots_default, 1, 6));
    try std.testing.expect(cqFillFits(conn_slots_default, upstream_slots_default, 1, cq_fill_eighths_min));
}
