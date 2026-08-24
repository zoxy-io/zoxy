//! Every static limit in one place. Total memory, fd count, and in-flight
//! ring ops are closed-form functions of these numbers (DESIGN.md §5, §8):
//! main.zig prints the budgets at startup, and the comptime asserts below
//! keep the relationships true. Pools never grow; exhaustion sheds load.

const std = @import("std");

const assert = std.debug.assert;

/// The single dedicated admin/metrics listener (DESIGN.md §8): separate
/// from the configured listeners so a scrape can
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
/// `(57344 - 11) / (conn_ops_max + 1) = 11466` —
/// comptime-derived below (the 11 is the fixed ops: two for the admin
/// listener [2], the admin client's op budget [3], the access log's
/// in-flight sink write [1], the health prober's op budget [3], the signal
/// wake [1], and the drain timer [1]). That clears a round 10k on a
/// single ring; a deployment trades the ceiling back down for more burst
/// headroom via `limits.cq_fill_eighths` (§8).
///
/// **Configured listeners are not in that 11.** They cost two ring ops
/// each like the admin listener does, but there is no listener ceiling to
/// reserve against — so this is the ceiling at *zero* configured
/// listeners, and each one a config declares spends two ops out of the
/// same budget. `cqFillFits` refuses the combination at load
/// (`LimitConnSlotsOverCqFill`) rather than a comptime assert refusing it
/// at build time, which is the trade this ceiling now rests on: a
/// deployment wanting both the maximum conn slots and many listeners is
/// told so at startup instead of being pre-empted by a number chosen for
/// it here.
///
/// `upstream_slots_max` is pinned to this, and the `+ 1` in the divisor
/// is that pin: on the L7 path an admitted connection that is mid-exchange
/// holds one upstream slot as well as its conn slot, and at saturation
/// every admitted connection can be mid-exchange at once. A conn ceiling
/// above the upstream ceiling is therefore capacity that cannot be served
/// — slots that admit connections the pool has no upstream for — and one
/// below it is a pool that can never be drawn down. `11466` is the
/// largest N with `N * (conn_ops_max + 1) <= 57333`, which keeps both
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
pub const conn_slots_max: u32 = 11457;

/// Relay buffer pairs (`Pool(RelayBuffer)`) — the bound on concurrent L4
/// connections plus active L7 body relays (§5, §6). Sized to the
/// conn-slot ceiling: the completion queue binds both (see
/// `conn_slots_max`), and a buffer beyond the slot count could never be
/// acquired.
pub const relay_buffers_max: u32 = conn_slots_max;

/// Bytes per relay direction; a `RelayBuffer` is a pair of these. The
/// operator's to size (`limits.relay_buffer_bytes`), because the right
/// value is a property of the bodies a deployment moves and nothing here
/// knows those.
///
/// The default is one full TLS record, and that is the measurement rather
/// than a round number. §6's strict recv→send→recv relay is correct at any
/// size, so the buffer sets how many round trips a body costs — a 256 KiB
/// response is 64 of them at 4 KiB and 16 at 16 KiB — and
/// `tls_app_chunk_bytes` below rides the same number, so a small buffer
/// also emits quarter-size TLS records against RFC 8446 §5.1's 2^14
/// ceiling. Held at 4 KiB, both together cost ~40% of bulk latency
/// (IMPLEMENTATION_NOTES.md, "The relay buffer sets the TLS record size").
///
/// The price is `relay_buffers` × 2 × this, which the c10k ceiling
/// multiplies by 11457 — so a deployment moving small bodies at high
/// concurrency is exactly who should turn it down, and the knob exists
/// for them.
pub const relay_buffer_bytes_default: u32 = 16 * 1024;

/// Floor. Below this a `PROXY` header or a chunked size line could not be
/// staged in one buffer, which the asserts below pin.
pub const relay_buffer_bytes_min: u32 = 1024;

/// Ceiling, and it is an IMPLEMENTATION bound rather than a protocol one.
/// RFC 8446 §5.1 caps a RECORD at 2^14, not a buffer;
/// `ResponseBodyPolicy.transformOut` hands a whole relay chunk to
/// `Engine.sendApp` with no loop around it, so one chunk is one record and
/// a larger buffer has nowhere to go. Two things follow, and neither is
/// obvious from the number: a plaintext deployment needs no such cap and
/// would take a larger buffer happily — the limit is global because
/// `limits` is — and lifting it means chunking inside the transform, or
/// making the bound conditional on whether any listener terminates TLS.
///
/// Keeping this equal to `tls_app_chunk_bytes` is also what lets the
/// engine's outbox stay comptime-sized while the relay pool became a
/// runtime slab.
pub const relay_buffer_bytes_max: u32 = 16 * 1024;

/// Most bytes a PROXY protocol header may occupy before the listener
/// rejects the peer (#142). The bound is ours, not the spec's: a v2
/// header declares its own length in a u16, and that number is chosen by
/// a peer whose trustworthiness is exactly what the header has not yet
/// established. 512 admits every fixed address block the spec defines —
/// the largest, AF_UNIX, is 216 bytes after the 16-byte prelude — plus
/// the TLVs real senders append (AWS NLB's VPCE id); v1 bounds itself at
/// 107. Must fit the relay buffer, where the receive phase stages the
/// header and whatever payload arrived coalesced behind it.
pub const proxy_header_bytes_max: u32 = 512;

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

/// The default upper bound on one L7 request or response head, including
/// the final CRLF — the per-buffer size of both §5 head pools unless
/// `limits.head_buffer_bytes` says otherwise. A request head that cannot
/// complete inside the configured budget is answered 414 (request line
/// still open) or 431 (header section); an oversize origin response head
/// tears the exchange down (§7). The default stays 8 KiB deliberately:
/// zoxy already accepts roughly half of HAProxy's ~15 KiB usable head,
/// and shrinking further would reject heads its peers accept — the knob
/// exists to *raise* for big-cookie/JWT deployments, and to lower only
/// for operators who know their traffic.
pub const head_buffer_bytes_default: u32 = 8 * 1024;

/// The floor on `limits.head_buffer_bytes`. Below this, ordinary
/// requests start dying as 414/431 — and it is what the comptime
/// relations below hold against, so every derived buffer (the forwarded
/// chain, the health probe) fits any size an operator may choose.
pub const head_buffer_bytes_min: u32 = 1024;

/// The ceiling on `limits.head_buffer_bytes` (the precedent is
/// `access_log_buffer_bytes_max`: a size knob gets a sanity wall even
/// where a count knob gets a relation). Also the widest head the parser
/// layer must be prepared to see, whatever the config chose — its
/// bounds-guarding asserts hold against this, not the default.
pub const head_buffer_bytes_max: u32 = 1024 * 1024;

comptime {
    assert(head_buffer_bytes_min >= 1024);
    assert(head_buffer_bytes_min <= head_buffer_bytes_default);
    assert(head_buffer_bytes_default <= head_buffer_bytes_max);
}

/// The most DER a listener's certificate chain may total (§4). This is a
/// bound on what goes *on the wire*, not on what came off disk: the server
/// flight carrying the chain is staged whole before any of it is written,
/// so the engine sizes its outbound staging from this number. 8 KiB fits a
/// leaf plus two intermediates at ordinary sizes with room to spare; a
/// chain past it is refused at startup, naming the limit, rather than
/// tripping a staging assert against the first client to connect.
pub const tls_cert_chain_bytes_max: u32 = 8 * 1024;

comptime {
    // A single P-256 leaf is ~450 bytes of DER; below a kilobyte the
    // limit would reject certificates that every other proxy serves.
    assert(tls_cert_chain_bytes_max >= 1024);
    // The chain is staged whole inside one server flight, and a flight
    // travels as TLS records. Holding it to the record ceiling keeps the
    // staging buffer that carries it a fixed multiple of a record rather
    // than a number that has to be re-derived when this one moves.
    assert(tls_cert_chain_bytes_max <= tls_record_plaintext_bytes_max / 2);
}

/// The RFC 8446 §5.1 ceiling on one TLS record's plaintext: 2^14. Not a
/// choice — it is what a conforming peer may send and what ztls will
/// hand back from a single record, so every buffer the engine decrypts
/// into is sized from it.
pub const tls_record_plaintext_bytes_max: u32 = 16 * 1024;

/// The most ciphertext one TLS read takes off the socket. A cap, not a
/// capability: the engine's record buffer holds more, but what a single
/// read may deliver is what bounds a single decrypt's *output*, and that
/// output needs somewhere to land. One max record keeps a full-size
/// record a one- or two-read affair while holding the plaintext
/// destination to twice a record (§4).
pub const tls_read_chunk_bytes: u32 = tls_record_plaintext_bytes_max;

/// The most plaintext zoxy hands the engine to encrypt at once. Emitting
/// smaller records than a peer would accept is always legal — no
/// negotiation, no conformance risk — and it is what keeps the engine's
/// outbound staging a fixed size instead of a function of
/// `limits.head_buffer_bytes`, which the operator may set to 1 MiB. Set
/// to the relay buffer's size so an L4 chunk crosses in one record.
pub const tls_app_chunk_bytes: u32 = relay_buffer_bytes_max;

comptime {
    // A read that could not hold a record header plus something would
    // make progress impossible on a full-size record.
    assert(tls_read_chunk_bytes >= 1024);
    assert(tls_app_chunk_bytes >= 1024);
    // Both are plaintext quantities the record layer must be able to
    // carry; past the record ceiling neither has a legal framing.
    assert(tls_read_chunk_bytes <= tls_record_plaintext_bytes_max);
    assert(tls_app_chunk_bytes <= tls_record_plaintext_bytes_max);
}

/// The ceiling on one TLS engine's own footprint, asserted against
/// `@sizeOf(Engine)` in `src/tls/Engine.zig` (§5: a budget is a stated
/// number a thing must fit, not a number read back off whatever it grew
/// to). Measured at 132 KiB — mostly ztls's record and reassembly
/// buffers, each two max records wide — with the headroom here for a pin
/// that adds a field. A bump past this is a deliberate re-costing of the
/// engine pool, which is what tripping the assert makes it.
pub const tls_engine_bytes_max: u32 = 160 * 1024;

/// The ceiling on `limits.tls_engines` — how many TLS sessions may be
/// handshaking or terminated at once (§5). An engine is ~132 KiB plus its
/// plaintext buffer, so this is the one pool whose count an operator
/// notices in RSS: 1024 is ~170 MiB, and the ceiling exists so a typo in
/// the config cannot ask for a gigabyte. Unlike the conn-slot ceiling it
/// is not derived from the ring — an engine holds no socket and arms no
/// completion, so it costs memory and nothing else.
pub const tls_engines_max: u32 = 1024;

/// Ceiling on the §5 tunnel pool (#180): the same c10k ceiling conn slots
/// carry, and necessarily so — a tunnel is an accepted client connection
/// occupying a slot, so a pool larger than the connections that could
/// hold one describes a proxy that cannot exist. The loader rejects past
/// the *effective* `conn_slots` too; this is the comptime half, and the
/// pair is what leaves the fd and ring budgets untouched by the feature
/// (§5): `fdsRequired` already charges two sockets per connection.
pub const tunnels_max: u32 = conn_slots_max;

/// The default when a listener terminates TLS and the operator did not
/// say. Follows conn slots like the head-buffer ring does — every
/// connection could be mid-handshake at once — but capped, because
/// unlike a head buffer an engine is two orders of magnitude larger and
/// `conn_slots_max` engines is memory no box would want by accident.
/// An operator who wants more concurrent TLS than this raises it
/// deliberately, having seen the number in the startup banner.
pub const tls_engines_default: u32 = @min(tls_engines_max, conn_slots_default);

/// How many NewSessionTickets one completed handshake issues (§4).
///
/// Two, which is what haproxy and OpenSSL send and what browsers expect:
/// a client that opens several connections at once wants more than one
/// ticket to spend, and a single ticket would have all but the first of
/// them fall back to a full handshake. More than two buys nothing — the
/// resumed sessions issue their own.
pub const tls_tickets_per_handshake: u8 = 2;

/// How long a ticket stays valid, in seconds.
///
/// RFC 8446 §4.6.1 caps this at 7 days and the cap is not the interesting
/// bound: a ticket is a bearer credential for a resumed session, and the
/// sealing key that opens it lives only in memory, so the real question is
/// how long a stolen ticket is worth carrying. An hour keeps a busy
/// client's reconnects free while making yesterday's capture useless.
/// It also sits comfortably inside the two-key rotation window below.
pub const tls_ticket_lifetime_s: u32 = 60 * 60;

/// How long one sealing key may go on sealing before it is replaced
/// (#202). This interval *is* the security bound: a key that seals for
/// six hours is a key whose theft compromises at most six hours of
/// issued tickets, each of which is itself worth only an hour.
///
/// Six against the lifetime's one is deliberate on both sides. It is
/// several lifetimes, so the two slots always cover a ticket's whole
/// validity with room to spare; and it is short enough that a key stolen
/// from memory ages out the same day rather than living as long as the
/// process does.
pub const tls_ticket_key_rotation_s: u32 = 6 * 60 * 60;

comptime {
    assert(tls_tickets_per_handshake >= 1);
    // RFC 8446 §4.6.1: "Servers MUST NOT use any value greater than
    // 604800 seconds (7 days)."
    assert(tls_ticket_lifetime_s <= 7 * 24 * 60 * 60);
    // What makes two key slots enough. A key stops sealing at a rotation
    // and stops opening at the next one, so it opens for one interval
    // after its last seal; a ticket sealed in that last instant must stay
    // openable for its whole lifetime, which needs the interval to be at
    // least the lifetime. Shrink the interval below the lifetime and
    // resumption starts failing for tickets that have not expired.
    assert(tls_ticket_key_rotation_s >= tls_ticket_lifetime_s);
}

/// What one *concurrent* TLS session costs the fixed heap on top of the
/// base below: libcrypto's per-session state, live for as long as that
/// session holds an engine.
///
/// Measured 2026-08-13 (ECDSA P-256, TLS_AES_128_GCM_SHA256, 1 KiB body)
/// by reading the heap's own frontier at steady concurrency:
///
///     concurrent sessions    50     100    200    400
///     heap frontier        1024K  1280K  1792K  2752K
///
/// The marginal cost is flat — 5.12 KiB across 100→200, 4.80 KiB across
/// 200→400 — so this term is linear in the *session* count and not in the
/// handshake count: 1811 sequential handshakes moved the frontier not at
/// all, because each one's blocks return to their class before the next
/// asks. Reserved at 8 KiB rather than the measured ~5: the heap is
/// segregated-fits with no coalescing, so a class whose free list is empty
/// cannot be served out of another's, and the slack absorbs that.
pub const libcrypto_heap_bytes_per_engine: u32 = 8 * 1024;

/// What the heap costs before any session: libcrypto's one-time tables
/// plus the first handshake's distinct block footprint, which every later
/// handshake reuses off the class free lists rather than growing
/// (IMPLEMENTATION_NOTES.md). Measured at ~1 MiB — 384 KiB at startup,
/// ~960 KiB once the first handshakes settle — reserved at 2 MiB.
pub const libcrypto_heap_base_bytes: u32 = 2 * 1024 * 1024;

/// The fixed heap libcrypto allocates from (§4, `tls/libcrypto_heap.zig`),
/// reserved at startup exactly when some listener terminates TLS.
///
/// Scales with the engine pool, because the heap's occupancy does. The
/// previous fixed 4 MiB was sized against a *sequential* measurement — one
/// handshake at a time, each freeing before the next — which is true
/// serially and false concurrently, and the gap was an outage rather than
/// a rounding error: the heap ran out at ~675 concurrent sessions, and
/// because ztls retried that allocation failure forever, the process
/// livelocked at 100% CPU with every listener dark (#222).
pub fn libcryptoHeapBytes(tls_engines: u32) u32 {
    assert(tls_engines <= tls_engines_max);
    // Zero exactly when no listener terminates TLS — the same condition
    // that makes the engine pool itself free (§5).
    if (tls_engines == 0) return 0;
    return libcrypto_heap_base_bytes + tls_engines * libcrypto_heap_bytes_per_engine;
}

/// The compiled reservation: what the deepest pool a config may ask for
/// needs, so one static array covers every admissible `limits.tls_engines`
/// (the loader holds it to `tls_engines_max`).
///
/// It has to be comptime. The heap is BSS rather than arena memory because
/// `OPENSSL_cleanup` frees through our hooks from an atexit handler, after
/// `main` has returned and the arena with it (see `main.zig`) — so sizing
/// for the ceiling is what a static reservation costs, and BSS pages a
/// smaller deployment never touches never become resident.
pub const libcrypto_heap_bytes: u32 = libcryptoHeapBytes(tls_engines_max);

/// The most a certificate or key PEM file may be. A bound on a startup
/// read, so its job is only to turn "the operator pointed at the wrong
/// file" into a named error instead of an arena the size of whatever was
/// on disk. Generous: the DER inside is bounded far tighter by
/// `tls_cert_chain_bytes_max`.
pub const tls_pem_bytes_max: u32 = 256 * 1024;

comptime {
    assert(tls_engines_default >= 1);
    assert(tls_engines_default <= tls_engines_max);
    // Engines are per *connection*, so a pool deeper than the slot count
    // could never be drawn from — the same relation head buffers have.
    assert(tls_engines_max <= conn_slots_max);
    // The heap must hold more than one handshake's measured plateau, or
    // the first connection exhausts it.
    assert(libcrypto_heap_bytes >= 2 * 1024 * 1024);
    // …and every session the deepest admissible pool can hold at once, or
    // a full pool exhausts it — which is the shape of #222. Stated against
    // the per-engine term rather than against `libcryptoHeapBytes` itself:
    // the reservation *is* that call, so comparing the two would be a
    // value checked against its own definition.
    assert(libcrypto_heap_bytes > tls_engines_max * libcrypto_heap_bytes_per_engine);
    // The measured marginal cost with the no-coalescing margin on top. A
    // reservation below what was measured would be a number that had
    // stopped tracking the thing it was derived from.
    assert(libcrypto_heap_bytes_per_engine >= 5 * 1024);
    // A PEM that could not carry the DER it wraps would make the tighter
    // chain bound unreachable — base64 costs a third on top.
    assert(tls_pem_bytes_max > tls_cert_chain_bytes_max * 2);
}

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

/// Upper bound on one endpoint's configured pick weight (#174) —
/// HAProxy's own `weight` ceiling. 256 steps is a 1-in-257 canary
/// granularity, finer than any signal an operator could act on, and the
/// bound is load-bearing for the `hash` policy: a weighted rendezvous
/// pick scores one hash per weight point, so this constant is what
/// keeps that scan's cost a number an operator can read off their own
/// config rather than an open-ended loop. Zero stays *below* the bound
/// deliberately — it is the drain spelling (never picked, still probed),
/// not a share.
pub const endpoint_weight_max: u16 = 256;

/// Default cap on requests one client connection may serve (#237) —
/// nginx's `keepalive_requests`, which also ships on. `0` is unlimited.
///
/// Unlike a body cap this one zoxy *can* honestly answer, and that is
/// what earns it a default: it bounds this proxy's own slot occupancy
/// rather than stating anything about an origin. `idle_ms` reaps a
/// connection that stops speaking and `max_lifetime_ms` one that has been
/// open too long; neither bounds a connection that is *busy* — and a busy
/// connection is exactly the one holding a conn slot and, on every
/// request, a head-ring buffer and an upstream lease. §8's watermark
/// biases all aim at shedding *idle* capacity, so a population that is
/// never idle is the shape none of them reach.
///
/// A count rather than more time, because it is the bound that is fair
/// under an adversarial client: it costs the same reconnect whether a
/// client is fast or slow, where a time cap punishes the slow-but-honest
/// one and lets a fast abusive one hold its slot indefinitely.
pub const keepalive_requests_default: u32 = 1000;

/// Default cap on one request's body (#236), per listener. One MiB —
/// nginx's `client_max_body_size`, which ships on by default and is the
/// figure most application stacks are deployed assuming something in
/// front enforces.
///
/// zoxy itself is unharmed by a large body: the strict recv → send → recv
/// relay (§6) means per-connection memory is constant whatever the stream
/// size, so an unbounded upload costs one relay buffer and no more. The
/// exposure this bounds is entirely the *origin's*, which is why the
/// figure is borrowed from the reference whose default protects the same
/// thing rather than derived from anything here. `0` opts out, for a
/// listener fronting an upload endpoint that wants its origin's own limit
/// to be the only one.
pub const request_body_bytes_default: u64 = 1 << 20;

/// Ceiling on a configured request-body cap (#236) — one TiB. Not a
/// resource bound: nothing here reserves per body, and the relay carries
/// any size in constant memory (§6). It is the units-mistake bound, the
/// same job `timeout_ms_max` does for a duration — a cap above this is a
/// operator meaning MiB and writing bytes, and `0` already spells "no
/// cap" for anyone who genuinely wants none.
pub const request_body_bytes_max: u64 = 1 << 40;

/// Default budget for reading one request head (#235) — from the
/// client's first byte to a complete head, which is exactly a slowloris's
/// window (§7: "a slowloris meets the clock or `head_buffer_bytes`,
/// whichever comes first").
///
/// Ten seconds, an order of magnitude under `idle_ms`, and the split is
/// the point rather than the number. One value used to serve both this
/// and the keep-alive idle window, and they want opposite things: a head
/// read is a client mid-sentence, where nothing legitimate is slow, while
/// an idle window is a healthy connection between requests, where short
/// values churn the population into reconnects. With one knob an operator
/// tunes the one whose cost is visible — the idle window — and the
/// head-read budget silently inherits it. The conservative choice was the
/// insecure one, which is the signature of a knob that should have been
/// two.
pub const head_ms_default: u32 = 10_000;

/// Interim (`1xx`) responses one exchange may carry before the origin's
/// final answer (#232). RFC 9110 puts no cap on them, and neither nginx
/// nor HAProxy does — both loop while the status is `1xx` — but an origin
/// streaming `103 Early Hints` forever is an unbounded loop on the one
/// thread (§3), which §1 rules out. Eight is well past what a real origin
/// sends (a `100`, or a handful of `103`s naming preload targets) and far
/// short of a stall; the overrun takes the `upstreamFailed` path, the same
/// verdict an unparseable origin head earns.
pub const interim_responses_max: u8 = 8;

/// Upper bound on a cluster's configured `retries` (#181) — the extra
/// dials one request may spend after a refused or unreachable first try.
/// HAProxy's own default, and a ceiling rather than a taste: every try
/// this permits is load moved onto the endpoints that are still answering,
/// so a generous bound would make a partial outage worse at the moment the
/// cluster is least able to absorb it. It also sizes the per-connection
/// tried-endpoint set, which is why it is a constant and not open-ended:
/// the set holds the first try plus this many retries.
pub const cluster_retries_max: u16 = 3;

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

/// Worst-case simultaneously armed ring ops for **one** §7 health probe:
/// three. A probe's legs run in sequence — {connect, probe deadline}
/// co-armed while dialing — and settling a verdict or draining adds one
/// cancel to whichever op is still armed ({connect, deadline,
/// connect_cancel} at the peak; a drain teardown cancels serially, never
/// both cancels at once). The prober's own rest timer and the cancel
/// spent on it never co-arm with a probe (`.resting` and `.probing` are
/// disjoint states), so two flags cost no third op.
pub const health_probe_ops_max: u32 = 3;

/// The most probes the §7 prober keeps in flight at once (#132). The
/// serial sweep it replaces made detection time a function of endpoint
/// count — `fall × (checked_endpoints × per_probe + interval)` — and a
/// single black-holed endpoint stalled the whole sweep for its full
/// `timeout_ms`. That was defensible while `endpoints_per_cluster_max`
/// capped a deployment at 1024 endpoints; #133 removed the endpoint
/// ceilings, which left the sweep unbounded.
///
/// Sixteen because the cost is a rounding error and the benefit is the
/// whole gap: it prices 48 ring ops (16 × `health_probe_ops_max`) out of
/// the ⅞-CQ budget `conn_slots_max` is derived from, which moves that
/// ceiling from 11466 to 11457 — while turning ten black-holed endpoints
/// at a 5 s budget from 50 s of added sweep into 5 s.
pub const health_probe_concurrency_max: u32 = 16;

/// How many probes a given config's prober actually runs: one per
/// checked endpoint, capped at the ceiling. Never zero, which is what
/// keeps the reservation *unconditional* in the sense §8 already meant —
/// a config with no `check` block anywhere reserves exactly the one
/// probe's worth it always did, so nothing about an unchecked deployment
/// moved when this ceiling arrived. The ring and fd budgets take the
/// effective value (the config's), while the comptime ceilings below
/// take `health_probe_concurrency_max` (the worst case any config could
/// ask for).
///
/// That is the *pool* shape — a compiled ceiling bounding what any
/// config may ask for, with the budget then evaluated on what this one
/// did — and deliberately not the listener shape, which is the nearer
/// thing to reach for and the wrong one: listeners have no compiled
/// ceiling left at all, so `completion_queue_entries` is derived at zero
/// of them and their whole demand is met at load. This ceiling is real,
/// and `conn_slots_max` is nine slots smaller for it.
pub fn healthProbeConcurrency(checked_endpoints: u32) u32 {
    const probes = @max(1, @min(checked_endpoints, health_probe_concurrency_max));
    assert(probes >= 1);
    assert(probes <= health_probe_concurrency_max);
    assert(probes <= @max(1, checked_endpoints));
    return probes;
}

/// Default consecutive failed probes that eject an endpoint from
/// balancing (§7), when a cluster's `check` block omits `fall`.
/// HAProxy's `fall` default: three misses is an outage, one is a blip.
pub const health_probe_fall_default: u8 = 3;

/// Default consecutive successful probes that restore an ejected
/// endpoint (§7), when a cluster's `check` block omits `rise`.
/// HAProxy's `rise` default: recovery must prove itself twice.
pub const health_probe_rise_default: u8 = 2;

/// Upper bound on a configured `fall`/`rise`, and on passive ejection's
/// own `fall` (#230) — one bound because all three are streaks counted
/// in a `u8`, and this is what keeps them from wrapping. It is also far
/// past any useful tuning: a probe threshold in the dozens means the
/// *interval* is the wrong knob, since detection latency is
/// `fall × interval`.
pub const health_probe_threshold_max: u8 = 64;

/// Consecutive failed *requests* that passively eject an endpoint (§7,
/// #230), when a cluster's `passive_ejection` block omits `fall`.
/// Higher than the probe's three on purpose: a probe is one synthetic
/// request the operator chose, where this counts real traffic, which
/// carries transient failures a probe never sees. Envoy's
/// `consecutive_5xx` default is the same five.
pub const passive_ejection_fall_default: u8 = 5;

/// How long a passively-ejected endpoint stays out before traffic is let
/// back to judge it again (§7, #230), when `passive_ejection` omits
/// `recovery_ms`. Envoy's `base_ejection_time`.
///
/// Recovery is a plain cooldown rather than a half-open probation, and
/// the cost of that choice is bounded and lives here: each cooldown ends
/// with up to `fall` requests spent on an endpoint that may still be
/// dead. Thirty seconds keeps that rate negligible against any real
/// traffic level while still restoring a recovered backend promptly. A
/// cluster that wants a single request spent instead of `fall` configures
/// `check`, whose `rise` restores from probe traffic rather than real.
pub const passive_ejection_recovery_ms_default: u32 = 30_000;

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

/// Upper bound on the header or cookie name a request-keyed `hash`
/// cluster reads (#178) — the same fixed-buffer rule as
/// `header_edits_max`: the response-side stamp composes
/// `name=<tag>` plus attributes into a stack scratch, and this bound is
/// what lets that scratch be sized at comptime. 64 covers every real
/// cookie or header name with room over (`__Host-`-prefixed names
/// included).
pub const pick_name_bytes_max: u16 = 64;

/// A response render's edit ceiling (#178): the configured filter edits
/// plus the one slot the Set-Cookie stamp reserves. The renderer's
/// asserts and the proxy's edit buffers all speak this name, so the
/// reserved slot cannot drift out of any of them.
pub const response_edits_max: u16 = header_edits_max + 1;

/// Upper bound on one configured body's bytes (#159) — file or inline,
/// rejected at load. The bound is the scope boundary, not a tuning
/// knob: below it, holding the bytes in the startup arena is the cheap
/// answer (an error page whose delivery needed a pool would fail when
/// it is needed most); above it you want the kernel page cache and a
/// streaming mechanism, which is a different feature. It is also why
/// the cost statement stays honest — scale-out is N processes behind
/// SO_REUSEPORT, each holding its own copy, so 1 MiB here is N MiB on
/// the box, printed per process in the banner's config-arena term.
pub const body_bytes_max: u32 = 1024 * 1024;

/// Upper bound on a configured body's *name* (#159) — an identifier an
/// operator writes and error messages echo, bounded like
/// `cluster_name_bytes_max` and for the same reason.
pub const body_name_bytes_max: u16 = 64;

/// Upper bound on every configured timeout — one hour. A timeout above
/// this is almost certainly a units mistake in the config.
pub const timeout_ms_max: u32 = 3_600_000;

/// Ceiling on `timeouts.tunnel_ms` (#180) — the one timeout allowed past
/// `timeout_ms_max`, and deliberately. That bound exists because an
/// ordinary timeout above an hour is almost certainly a units mistake;
/// for a tunnel an hour is not a suspicious number but a routine one, so
/// reusing it would leave the default sitting *on* the ceiling with no
/// way to ask for longer. A day is the units-mistake bound for a clock
/// whose job is to outlive a working session.
pub const tunnel_ms_max: u32 = 24 * 60 * 60 * 1000;

/// Default bound on one tunnel's whole life (#180), replacing `idle_ms`,
/// `request_ms` and `max_lifetime_ms` once a connection has become one —
/// HAProxy's `timeout tunnel` in everything but spelling. An hour,
/// because what is being bounded is a session whose keepalive is
/// application-layer ping/pong this proxy cannot see: after `101` the
/// bytes are opaque by construction, so a legitimately idle WebSocket is
/// indistinguishable from an abandoned one and the only honest bound is
/// a generous one.
pub const tunnel_ms_default: u32 = 60 * 60 * 1000;

/// Floor on `timeouts.tunnel_ms`. A sub-second lifetime would reap every
/// session the instant it opened — a typo that presents as the feature
/// not working. "No cap" deliberately has no spelling here at all,
/// unlike `request_ms`: a tunnel holds a dedicated pool slot for its
/// whole life (§5), and an unbounded hold on a bounded pool is the one
/// thing that model cannot absorb.
pub const tunnel_ms_min: u32 = 1000;

/// How long a drain carries live tunnels when `drain_deadline_ms` is `0`
/// (#180, §8). Five seconds, matching the drain ladder's other steps.
///
/// It exists because a zero deadline means "wait for the last
/// connection", and a tunnel has no message boundary to finish at — one
/// idle WebSocket would hold the drain open until the supervisor's
/// SIGKILL, turning a millisecond drain into every rolling restart
/// waiting out `TimeoutStopSec`. A constant rather than a config key
/// deliberately: the alternative asks every operator to answer a
/// question raised entirely by a feature they may not use, and
/// `drain_deadline_ms` keeps its exact present meaning for every other
/// connection. When a deadline *is* configured it governs tunnels like
/// anything else and this is never armed.
pub const tunnel_drain_ms: u32 = 5000;

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
///
/// One line *of a config that names no headers* (#140). A config that
/// names some has a wider line, and the loader holds its buffer to that
/// wider bound (`LimitAccessLogBufferUnderLine`) — so the floor stays
/// the price of the feature nobody asked for, and the rest is charged
/// where it is chosen.
pub const access_log_buffer_bytes_min: u32 = accessLogLineBytes(0);
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

/// Raw bytes of one operator-named header value kept for its log line
/// (#140). The value lives in a head buffer the render writes over (§7
/// rotation), so it is copied out under this cap while it is still
/// there — `access_log_path_bytes_max`'s rule, one field over —
/// truncated with a trailing `...` rather than dropped.
pub const access_log_header_bytes_max: u16 = 256;

/// How many headers one `access_log` block may name, request and
/// response lists summed (#140). The cap is what keeps the per-line
/// bound and the per-connection capture table closed-form: both are
/// this times a per-header term. Eight covers the correlation header
/// plus the handful an operator routinely wants beside it.
pub const access_log_headers_max: u8 = 8;

/// Raw bytes of a named header's *name* — the key the line renders.
/// Bounded because the key is config text that lands in every line.
pub const access_log_header_name_bytes_max: u8 = 64;

/// Upper bound on one rendered access-log line, including its newline
/// (§5: the caller sizes a fixed buffer to it, so a line never has to be
/// dropped for want of room in an *empty* buffer). Derived from the field
/// caps rather than chosen, so raising one of them cannot silently make
/// the bound a lie. The `6 *` on the text fields is JSON's worst case:
/// a control byte escapes to `\u00XX`, and a percent-decoded path may
/// legitimately contain one.
///
/// A function of the config since #140: the named headers a line carries
/// are the operator's list, so its maximum length is theirs too. The
/// precedent is #179's metrics exposition, whose render buffer became a
/// config-derived banner term for the same reason when labels arrived.
/// `access_log_line_bytes_max` below is the compiled ceiling — the value
/// at the header cap — and is what the comptime budget asserts speak.
pub fn accessLogLineBytes(header_count: u32) u32 {
    assert(header_count <= access_log_headers_max);
    // Every key, brace, comma, quote, and the trailing newline, with slack
    // for a field or two more before the bound has to be re-derived.
    const scaffolding = 320;
    const timestamp = 30; // "2026-07-31T09:14:22.481Z"
    // "[" + 39 bytes of IPv6 + "]:" + 5 port digits, quoted.
    const address = 48;
    const number = 20; // a u64 at its widest
    const addresses = 2; // client and upstream
    const numbers = 4; // duration, bytes in, bytes out, status
    const fixed = scaffolding + timestamp + addresses * address + numbers * number +
        @as(u32, access_log_method_bytes_max) + @as(u32, cluster_name_bytes_max) +
        6 * @as(u32, host_bytes_max) + 6 * @as(u32, access_log_path_bytes_max);
    // Per named header: the quoted key, the escaped value at JSON's
    // worst case, and the `"":,` punctuation between them — plus the two
    // wrapper objects' own keys and braces, charged once per header so
    // the term stays a single multiplication.
    const per_header = @as(u32, access_log_header_name_bytes_max) +
        6 * @as(u32, access_log_header_bytes_max) + 48;
    return fixed + header_count * per_header;
}

/// The compiled ceiling: a line at the header cap. Every budget assert
/// and every test buffer speaks this, so they cover any config.
pub const access_log_line_bytes_max: u32 = accessLogLineBytes(access_log_headers_max);

/// Worst-case in-flight ring ops (§8: the ring is pre-budgeted, not shed):
/// every connection slot at its op peak (L7 slots hold armed ops with or
/// without a relay buffer, so the term is per slot, not per buffer), one
/// idle-timer op per parked upstream (§5/§8 — reserved ahead of the
/// keep-alive slice), two ops per listener — configured *and* admin — (a
/// draining listener holds its armed accept — or the accept-retry backoff
/// timer — plus the async cancel that reaps it), `admin_conn_ops_max` ops
/// per admin client (its send/deadline/teardown peak), the access log's one
/// in-flight sink write, `health_probe_ops_max` ops for each of the
/// prober's `health_probes` concurrent probes (§7), the single async
/// wakeup op for signals, and
/// the server's one drain-deadline timer. Closed form so it can be
/// evaluated on the *effective* pool sizes too (XevIo's per-deployment CQ),
/// not only the ceilings; the admin and access-log reservations are fixed
/// — always covered even when a config leaves them off — and so is the
/// health prober's floor of one probe, which is why an unchecked config
/// reserves what it always did.
///
/// There is no `in_flight_ops_max` companion any more, and its absence is
/// the shape of this whole budget now: with no listener ceiling there is
/// no "at the ceilings" point to evaluate, because the listener term is a
/// property of the config rather than of `constants.zig`. What used to be
/// `assert(in_flight_ops_max <= completion_queue_entries)` at comptime is
/// `cqFillFits` at config load (`LimitConnSlotsOverCqFill`) — the same
/// arithmetic, refused a few milliseconds later.
pub fn inFlightOps(
    conn_slots: u32,
    upstream_slots: u32,
    listeners: u32,
    health_probes: u32,
) u32 {
    assert(conn_slots <= conn_slots_max);
    assert(upstream_slots <= upstream_slots_max);
    // No policy ceiling to check against, but the argument is not
    // unbounded either: every caller sources it from a config the
    // loader has already held to the `u16` a listener index is stored in.
    assert(listeners <= std.math.maxInt(u16));
    assert(health_probes >= 1);
    assert(health_probes <= health_probe_concurrency_max);
    return conn_slots * conn_ops_max + upstream_slots +
        2 * (listeners + admin_listeners) +
        admin_conns * admin_conn_ops_max + access_log_ops_max +
        health_probes * health_probe_ops_max + 1 + 1;
}

/// Kernel maximum for an IORING_SETUP_CQSIZE completion queue
/// (IORING_MAX_CQ_ENTRIES = 2 × IORING_MAX_ENTRIES) on current kernels.
/// The upper wall on any requested CQ depth — a request past this fails
/// `Loop.init` at runtime, so the comptime assert below (and `completionQueueDepthFor`'s
/// clamp) keep it out of reach.
pub const completion_queue_entries_max: u32 = 65536;

/// The widest provided-buffer group a ring can register (the seam's
/// `recvGroup`, §5's head-buffer ring): a buf_ring's descriptor table is
/// sized by a u16 power-of-two `entries` argument, so 1 << 15 is the
/// largest capacity it can name. Fewer buffers than entries may be
/// published — the operator's count is not itself forced to a power of
/// two, only bounded by this.
pub const buffer_group_entries_max: u32 = 1 << 15;

comptime {
    // Every head-buffer count a config can reach (`limits.head_buffers`
    // ≤ conn_slots ≤ this ceiling) fits one registered group.
    assert(conn_slots_max <= buffer_group_entries_max);
}

/// The buf_ring descriptor table behind the head-buffer ring (§5): one
/// 16-byte `io_uring_buf` (ABI-fixed) per entry, entries the next power
/// of two of the published count, mmapped page-granular. Zero when no
/// ring is registered — an L4-only deployment.
pub fn bufferGroupDescriptorBytes(head_buffers: u32) u64 {
    assert(head_buffers <= buffer_group_entries_max);
    if (head_buffers == 0) return 0;
    const entries = std.math.ceilPowerOfTwo(u32, head_buffers) catch unreachable;
    const bytes = std.mem.alignForward(u64, @as(u64, entries) * 16, 4096);
    assert(bytes >= 4096);
    return bytes;
}

/// One shared discard sink for every §7 lingering-close drain (the reads
/// whose bytes are never looked at). Shared deliberately: with the head
/// buffer returned before a static response goes out (§5), a reject storm
/// must not need a buffer per draining connection, and recv targets whose
/// contents nobody reads may alias.
pub const drain_sink_bytes: u32 = 4 * 1024;

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
    health_probes: u32,
    cq_fill_eighths: u32,
) u32 {
    assert(cq_fill_eighths >= cq_fill_eighths_min);
    assert(cq_fill_eighths <= cq_fill_eighths_max);
    const in_flight = inFlightOps(conn_slots, upstream_slots, listeners, health_probes);
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
    health_probes: u32,
    cq_fill_eighths: u32,
) bool {
    assert(cq_fill_eighths >= cq_fill_eighths_min);
    assert(cq_fill_eighths <= cq_fill_eighths_max);
    const in_flight = inFlightOps(conn_slots, upstream_slots, listeners, health_probes);
    // The kernel CQ max is a power of two, so its fill budget is exact.
    return in_flight <= @divExact(completion_queue_entries_max, 8) * cq_fill_eighths;
}

/// The CQ capacity the §8 ceiling budgets are derived against: the depth a
/// deployment at the compiled ceilings would request. This is the kernel
/// maximum (65536), which is exactly what makes `conn_slots_max` the c10k
/// ceiling — as deep as one ring allows, independent of `ring_entries`.
/// Derived at *zero* configured listeners: with no listener ceiling there
/// is no worst case to reserve for, so the compiled depth covers the
/// pools and the fixed reservations, and a config's own listeners are
/// checked against it by `cqFillFits` at load. The depth clamps to the
/// kernel maximum either way, so the listener term never actually moved
/// this number — it only made it look derived from a ceiling that no
/// longer exists.
pub const completion_queue_entries: u32 =
    completionQueueDepthFor(conn_slots_max, upstream_slots_max, 0, health_probe_concurrency_max, cq_fill_eighths_default);

/// The fds a deployment needs (§8: fds are pre-budgeted, not shed): stdio
/// + ring + async eventfd + listeners (configured + admin) + two sockets
/// per admitted connection (client plus the exchange's upstream) + the one
/// transient just-accepted fd an admission decision is pending on + one
/// socket per in-flight admin scrape + one socket per parked upstream,
/// which belongs to no connection + one socket per concurrent health
/// probe, each of which may hold one while dialing (§7) + the access
/// log's file sink when the
/// config names one (§8 — the `stdout` sink is one of the three stdio
/// descriptors already counted). Closed form so `ensureFdBudget` can
/// check the *effective* size against RLIMIT_NOFILE; the admin
/// reservation is fixed, and so is the prober's floor of one probe.
///
/// No `fds_max` companion, for the reason `in_flight_ops_max` has none:
/// the listener term makes this a property of a config, not of this file.
/// `ensureFdBudget` was always the real gate — it compares this against
/// the actual RLIMIT_NOFILE — and it is now the only one.
pub fn fdsRequired(
    conn_slots: u32,
    upstream_slots: u32,
    listeners: u32,
    access_log_files: u32,
    health_probes: u32,
) u32 {
    assert(conn_slots <= conn_slots_max);
    assert(upstream_slots <= upstream_slots_max);
    assert(listeners <= std.math.maxInt(u16));
    // Zero or one: the config names at most one sink, and only its `file`
    // arm opens anything. Each file sink costs its held fd plus one
    // transient during a SIGHUP reopen — the new fd opens before the old
    // one closes, so a failed rotation keeps a working log (§8).
    assert(access_log_files <= 1);
    assert(health_probes >= 1);
    assert(health_probes <= health_probe_concurrency_max);
    return 3 + 1 + 1 + (listeners + admin_listeners) +
        2 * conn_slots + 1 + admin_conns + upstream_slots + health_probes +
        2 * access_log_files;
}

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
/// unconfigured proxy is not there to serve. 1311 is the largest value
/// that still clears that line — `fdsRequired(conn_slots_default, x, 1, 1, 1)`
/// is `2784 + x` (the health probe's reserved fd and the access log's
/// possible file sink both included, the sink at its SIGHUP-reopen worst
/// of two fds: naming a log file is not *tuning*, so the lean promise
/// must hold with one), and that must stay strictly under 4096 (the
/// out-of-box budget stays *under* the stock limit, not flush against
/// it), so `4096 - 2784 - 1 = 1311` — the default leans as far toward
/// `conn_slots_default` as the stock fd budget allows. An L4
/// deployment never leases from this pool at all — an L4 dial reads its
/// `leased_counts` for the P2C draw and holds no slot. A deployment that
/// means to fill its conn pool raises both together in `limits` — which
/// is what the ceilings exist to permit and what the c10k benchmark
/// configuration does.
pub const upstream_slots_default: u32 = 1311;

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
    assert(inFlightOps(conn_slots_max, upstream_slots_max, 0, health_probe_concurrency_max) <= completion_queue_entries);
    assert(conn_slots_max - 1 <= std.math.maxInt(u16));
    assert(relay_buffer_bytes_min >= 512);
    assert(relay_buffer_bytes_min <= relay_buffer_bytes_default);
    assert(relay_buffer_bytes_default <= relay_buffer_bytes_max);
    // The PROXY header stages in the relay buffer's client→upstream half
    // and must admit the largest header either spec version allows
    // (v2's 16-byte prelude + AF_UNIX's 216-byte block; v1's 107 line).
    assert(proxy_header_bytes_max <= relay_buffer_bytes_min);
    assert(proxy_header_bytes_max >= 16 + 216);
    assert(proxy_header_bytes_max >= 107);
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
    assert(response_edits_max == header_edits_max + 1);
    assert(body_bytes_max >= 1);
    // A body must fit the u32 lengths the render and the channel carry.
    assert(body_bytes_max <= std.math.maxInt(u32) / 2);
    assert(body_name_bytes_max >= 1);
    assert(body_name_bytes_max == cluster_name_bytes_max); // one identifier rule
    assert(pick_name_bytes_max >= 1);
    // A pick name is a header-adjacent identifier; keeping it under the
    // host bound is the sanity relation "this is a name, not a payload".
    assert(pick_name_bytes_max <= host_bytes_max);
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
    assert(headers_max >= 8);
    assert(host_bytes_max >= 1);
    assert(upstream_slots_max >= 1);
    // The upstream pool's per-endpoint leased counts are u16: a bump past
    // this ceiling would wrap them in ReleaseFast and silently corrupt
    // the P2C load signal.
    assert(upstream_slots_max <= std.math.maxInt(u16));
    assert(chunked_line_bytes_max >= 32);
    assert(chunked_line_bytes_max <= relay_buffer_bytes_min);
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
            2 * admin_listeners -
            admin_conns * admin_conn_ops_max - access_log_ops_max -
            health_probe_concurrency_max * health_probe_ops_max - 1 - 1,
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
    // An empty staging buffer must always fit one line of a config that
    // names no headers; the loader carries the same guarantee up to the
    // wider bound a config with headers earns (#140).
    assert(access_log_buffer_bytes_min >= accessLogLineBytes(0));
    assert(access_log_line_bytes_max >= access_log_buffer_bytes_min);
    assert(access_log_buffer_bytes_max >= access_log_line_bytes_max);
    assert(access_log_headers_max >= 1);
    assert(access_log_header_bytes_max >= 16);
    assert(access_log_header_name_bytes_max >= 16);
    assert(access_log_buffer_bytes_default >= access_log_buffer_bytes_min);
    assert(access_log_buffer_bytes_default <= access_log_buffer_bytes_max);
    // Two buffers exactly: the swap is what lets appends continue during
    // a write, and a third would be a queue nobody drains.
    assert(access_log_buffers == 2);
    // A carried chain plus the address appended to it must still leave a
    // head that can be rendered — inside the *smallest* head buffer an
    // operator may configure, so the relation stays comptime while the
    // size itself went runtime.
    assert(forwarded_value_bytes_max < head_buffer_bytes_min);
    // The scratch must hold a bracketed IPv6 literal with its port, which
    // is what gets formatted before the port is stripped back off.
    assert(forwarded_client_bytes_max >= 47);
    assert(access_log_ops_max >= 1);
    assert(access_log_path_bytes_max >= 16);
    assert(access_log_method_bytes_max >= 7); // "OPTIONS", the longest standard method.
    assert(cluster_name_bytes_max >= 1);
    // A weight ceiling of zero would make every cluster all-drained and
    // unloadable; one weight step is the degenerate-but-legal minimum.
    assert(endpoint_weight_max >= 1);
    // A retry cap of zero would make the config key unspellable; one
    // retry is the degenerate-but-legal minimum. The set it sizes must
    // still fit the u16 count the balancer scans it with.
    // A tunnel's clock must be a real duration, must leave headroom above
    // its default, and must outrank the ordinary ceiling it deliberately
    // escapes; the pool cannot exceed the connections that hold it.
    assert(tunnels_max <= conn_slots_max);
    assert(tunnel_ms_min >= 1);
    assert(tunnel_ms_default >= tunnel_ms_min);
    assert(tunnel_ms_max > tunnel_ms_default);
    assert(tunnel_ms_max >= timeout_ms_max);
    // The tunnel drain bound must be a real wait and must not itself be
    // the thing that makes a drain slow.
    assert(tunnel_drain_ms >= 1);
    assert(tunnel_drain_ms <= timeout_ms_max);
    // An exchange must be allowed at least one interim, or the bound
    // would forbid the `100 Continue` the feature exists to carry.
    assert(interim_responses_max >= 1);
    // The head-read budget sits between the dial budget and the idle
    // window, and both relations are what the single lazy timer needs
    // (§4): the dial re-bases the head deadline *down* to `connect_ms`,
    // and the first byte re-bases the idle deadline *down* to this — a
    // timer never moves later once armed, so an inversion either way
    // would silently leave the wider value in force.
    // The two #236/#237 client-side caps: each must be a real bound, or
    // the default would spell the "unlimited" its own zero already does.
    assert(keepalive_requests_default >= 1);
    assert(request_body_bytes_default >= 1);
    assert(request_body_bytes_default <= request_body_bytes_max);
    assert(connect_ms_default < head_ms_default);
    assert(head_ms_default <= idle_ms_default);
    assert(cluster_retries_max >= 1);
    assert(cluster_retries_max < std.math.maxInt(u16));
    // The health prober's reservations and thresholds (§7): the op budget
    // covers dial + deadline + one cancel, a threshold of zero would eject
    // or restore on no evidence, and the default probe interval is a legal
    // configured timeout.
    assert(health_probe_ops_max >= 1);
    // The concurrency ceiling is a reservation multiplier, so a zero
    // would price the prober out of existence while it still ran one
    // probe, and `healthProbeConcurrency`'s clamp would invert.
    assert(health_probe_concurrency_max >= 1);
    assert(healthProbeConcurrency(0) == 1);
    assert(healthProbeConcurrency(1) == 1);
    assert(healthProbeConcurrency(health_probe_concurrency_max) == health_probe_concurrency_max);
    assert(healthProbeConcurrency(std.math.maxInt(u32)) == health_probe_concurrency_max);
    assert(health_probe_fall_default >= 1);
    assert(health_probe_rise_default >= 1);
    assert(health_probe_fall_default <= health_probe_threshold_max);
    assert(health_probe_rise_default <= health_probe_threshold_max);
    // Passive ejection's threshold shares the bound for the same reason
    // (a `u8` streak), and its cooldown is a configurable duration like
    // any other, so it sits inside `timeout_ms_max` — the ceiling that
    // exists to catch a units mistake, not a §8 shedding rung.
    assert(passive_ejection_fall_default >= 1);
    assert(passive_ejection_fall_default <= health_probe_threshold_max);
    // Real traffic is noisier than a probe, so the passive threshold
    // should never be the *twitchier* of the two.
    assert(passive_ejection_fall_default >= health_probe_fall_default);
    assert(passive_ejection_recovery_ms_default >= 1);
    assert(passive_ejection_recovery_ms_default <= timeout_ms_max);
    assert(health_interval_ms_default >= 1);
    assert(health_interval_ms_default <= timeout_ms_max);
    // The rendered probe request must fit its buffer whatever a config
    // names, which is what makes the render infallible (§5).
    assert(health_check_path_bytes_max >= 1);
    assert(health_check_host_bytes_max >= 1);
    assert(health_check_request_bytes_max >
        @as(u32, health_check_path_bytes_max) + health_check_host_bytes_max);
    // A probe request must fit the smallest head buffer an operator may
    // configure — its response buffer follows `limits.head_buffer_bytes`
    // at init, so only the request side needs a comptime floor.
    assert(health_check_request_bytes_max <= head_buffer_bytes_min);
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
    /// The #140 per-connection capture table: the operator-named header
    /// values a line reports, held from the head they were read out of
    /// until the line is written. Zero when the config names none —
    /// which is what keeps the feature free to a deployment that did
    /// not ask for it. Config-derived like `metrics_bytes` beside it,
    /// and priced the same way: next to everything else you pay for.
    log_header_bytes: u64 = 0,
    /// The endpoint-keyed tables (§7) — the pool's idle heads and lease
    /// counts, the balancer's endpoint hashes, rotation state and pick
    /// scratch, the server's L4 charges, and the health checker's mask
    /// and two streak counters. Startup arena memory held for the
    /// process's life, so §5's promise covers it.
    ///
    /// Passed in rather than derived here because the per-entry widths
    /// belong to those modules' element types, not to this file: computing
    /// it from hardcoded widths would silently drift the moment one of
    /// them changed. `Server.endpointTableBytes` is the closed form.
    endpoint_table_bytes: u64,
    /// The #179 labeled metrics (§8): the per-endpoint/per-cluster
    /// counter tables and their prebuilt label strings, plus the two
    /// render staging buffers — the admin response and the SIGUSR1 dump
    /// — whose length became the config's when the exposition gained
    /// labels. Its own term on the issue's own argument: the cost of
    /// labelling your metrics should be visible next to everything else
    /// you pay for. `Server.metricsBytes` is the closed form.
    metrics_bytes: u64,
    /// The §5 head-buffer ring: how many buffers the deployment registered
    /// (`limits.head_buffers`; zero on an L4-only config) and the unit
    /// size of each. The total term is `count × (unit + 1)` — the slab
    /// plus the seam's one ownership byte per buffer — plus the buf_ring
    /// descriptor table (`bufferGroupDescriptorBytes`).
    head_buffers: u32,
    head_buffer_bytes: u64,
    /// The §5 upstream head pool (`limits.upstream_head_buffers`; zero on
    /// an L4-only config) and its unit size — `@sizeOf` the pool element,
    /// so the intrusive free-list header rides along like every other
    /// pool's.
    upstream_head_buffers: u32,
    upstream_head_buffer_bytes: u64,
    /// The head-sized side buffers (§5): the serving path's two
    /// canonicalization scratches (present only where a head can exist)
    /// and the health prober's response buffer (always). A fixed
    /// reservation like the access log's, in the total on the same
    /// promise; `main.zig` composes it to mirror `Server.init` exactly.
    head_scratch_bytes: u64,
    /// The §5 tunnel pool (`limits.tunnels`; zero when no listener
    /// allows an upgrade) and its unit size — the same `RelayBuffer` the
    /// shared pool holds, reserved apart from it (§5, #180). Its own
    /// term rather than folded into `relay_buffers` precisely because
    /// the two are sized for opposite shapes: that pool for concurrent
    /// activity, this one for connections that hold a buffer until they
    /// close. A reader comparing the banner's two lines is reading the
    /// trade the feature makes.
    tunnels: u32 = 0,
    tunnel_buffer_pair_bytes: u64 = 0,
    /// The §4 TLS engine pool (`limits.tls_engines`; zero when no
    /// listener terminates TLS) and its unit size — `@sizeOf(Engine)`,
    /// so the pool's own free-list header rides along like every other
    /// pool's. By far the largest per-connection unit here, which is why
    /// it prints on its own banner line rather than folding into another.
    tls_engines: u32 = 0,
    tls_engine_bytes: u64 = 0,
    /// What one engine's plaintext destination costs. Runtime-sized, not
    /// comptime: an L7 head may be up to `limits.head_buffer_bytes`, so
    /// a slot has to cover whichever of that and the engine's own floor
    /// is larger. One pool serves both protocols, so every slot is sized
    /// for the widest use any of them may be put to.
    tls_plaintext_bytes: u64 = 0,
    /// The fixed heap libcrypto allocates from (§4), reserved exactly
    /// when some listener terminates TLS. One process-wide reservation
    /// rather than a per-engine buffer, but sized *from* the engine count
    /// (`libcryptoHeapBytes`) because that is what its occupancy tracks —
    /// priced here for the same reason the access log's buffers are: §5's
    /// promise is that the printed total covers every byte this process
    /// holds for its life.
    ///
    /// Priced at the whole compiled reservation rather than this config's
    /// share of it: the storage is one static array (it must outlive the
    /// arena), so the process holds all of it whatever `tls_engines` says.
    /// `libcryptoHeapBytes` is what *derives* that array's size, at
    /// `tls_engines_max`; it is not a per-config subtotal to print.
    libcrypto_heap_bytes: u64 = 0,
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
    assert(sizes.relay_buffer_pair_bytes >= 2 * @as(u64, relay_buffer_bytes_min));
    // Once 8 KiB of head, now scalars: the slot's head moved to the §5
    // upstream head pool, whose own bound is asserted below.
    assert(sizes.upstream_bytes > 0);
    // Either the log is off and costs nothing, or it holds exactly its two
    // buffers at a size the loader validated — never some third number.
    assert(sizes.access_log_bytes % access_log_buffers == 0);
    assert(sizes.access_log_bytes == 0 or
        sizes.access_log_bytes >=
            @as(u64, access_log_buffers) * access_log_buffer_bytes_min);
    assert(sizes.access_log_bytes <=
        @as(u64, access_log_buffers) * access_log_buffer_bytes_max);
    assert(sizes.head_buffers <= buffer_group_entries_max);
    assert(sizes.head_buffers == 0 or sizes.head_buffer_bytes >= 1);
    assert(sizes.upstream_head_buffers <= sizes.upstream_slots);
    assert(sizes.upstream_head_buffers == 0 or
        sizes.upstream_head_buffer_bytes >= head_buffer_bytes_min);
    // At least the prober's one buffer, at least the smallest legal size.
    assert(sizes.head_scratch_bytes >= head_buffer_bytes_min);
    // A config has at least one cluster with one endpoint, so the
    // labeled tables and their buffers can never price at zero.
    assert(sizes.metrics_bytes > 0);
    // All-or-nothing together, like the TLS terms below and for the same
    // reason: a pool with no tunnels is a deployment that allows no
    // upgrade, and any mixture is a composition mistake rather than a
    // configuration one — `limits.tunnels` already refuses the
    // config-level version of it.
    assert(sizes.tunnels <= tunnels_max);
    assert(sizes.tunnels <= sizes.conn_slots);
    if (sizes.tunnels == 0) {
        assert(sizes.tunnel_buffer_pair_bytes == 0);
    } else {
        assert(sizes.tunnel_buffer_pair_bytes >= 2 * @as(u64, relay_buffer_bytes_min));
    }
    // The TLS terms are all-or-nothing together: a pool with no engines
    // is a plaintext deployment, which reserves no heap and no plaintext
    // buffers either. Any mixture is a composition mistake, not a
    // configuration one — `limits.tls_engines` already refuses the
    // config-level version of it.
    assert(sizes.tls_engines <= tls_engines_max);
    if (sizes.tls_engines == 0) {
        assert(sizes.tls_engine_bytes == 0);
        assert(sizes.tls_plaintext_bytes == 0);
        assert(sizes.libcrypto_heap_bytes == 0);
    } else {
        assert(sizes.tls_engine_bytes > 0);
        assert(sizes.tls_engine_bytes <= tls_engine_bytes_max);
        assert(sizes.tls_plaintext_bytes >= tls_record_plaintext_bytes_max);
        assert(sizes.libcrypto_heap_bytes == libcrypto_heap_bytes);
    }
    const total = @as(u64, sizes.conn_slots) * sizes.conn_bytes +
        @as(u64, sizes.relay_buffers) * sizes.relay_buffer_pair_bytes +
        @as(u64, sizes.upstream_slots) * sizes.upstream_bytes +
        sizes.access_log_bytes + sizes.log_header_bytes +
        sizes.endpoint_table_bytes + sizes.metrics_bytes +
        @as(u64, sizes.tunnels) * sizes.tunnel_buffer_pair_bytes +
        @as(u64, sizes.head_buffers) * (sizes.head_buffer_bytes + 1) +
        bufferGroupDescriptorBytes(sizes.head_buffers) +
        @as(u64, sizes.upstream_head_buffers) * sizes.upstream_head_buffer_bytes +
        sizes.head_scratch_bytes +
        @as(u64, sizes.tls_engines) *
            (sizes.tls_engine_bytes + sizes.tls_plaintext_bytes) +
        sizes.libcrypto_heap_bytes;
    assert(total > 0);
    return total;
}

test "budgets: in-flight ops fit the completion queue with headroom" {
    try std.testing.expect(inFlightOps(conn_slots_max, upstream_slots_max, 0, health_probe_concurrency_max) <= completion_queue_entries);
    // Headroom is deliberate: at least an eighth of the CQ stays free for
    // completion bursts even at the worst-case armed-op count (the default
    // = loosest fill the ceiling is derived at).
    try std.testing.expect(inFlightOps(conn_slots_max, upstream_slots_max, 0, health_probe_concurrency_max) <= @divExact(completion_queue_entries, 8) * cq_fill_eighths_default);
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
    const pair_bytes: u64 = 2 * @as(u64, relay_buffer_bytes_default);
    // Scalars only since the head moved to its own pool (§5).
    const upstream_bytes: u64 = 64;
    const upstream_head_bytes: u64 = head_buffer_bytes_default + 8;
    // The endpoint-keyed tables (§7): like the access log, a reservation
    // that must move the total by exactly its own size and nothing else.
    const endpoint_tables: u64 = 4096;
    // At the ceilings and at a shrunken (config-limits) shape alike, with
    // the access log on at the ceiling and off below it — the term is a
    // fixed reservation, so it must move the total by exactly its own size
    // and by nothing else.
    // The head-buffer ring's term is count × (unit + 1) — the slab plus
    // one ownership byte per buffer — plus the descriptor table, which is
    // page-granular and next-power-of-two, so a non-power-of-two count
    // pins the rounding too: 11466 → 16384 entries × 16 B = exactly 64
    // pages.
    const head_ring: u64 = @as(u64, conn_slots_max) * (head_buffer_bytes_default + 1) +
        bufferGroupDescriptorBytes(conn_slots_max);
    try std.testing.expectEqual(
        @as(u64, 16384) * 16,
        bufferGroupDescriptorBytes(conn_slots_max),
    );
    try std.testing.expectEqual(@as(u64, 0), bufferGroupDescriptorBytes(0));
    // The side buffers: two serving scratches plus the prober's one.
    const head_scratch: u64 = 3 * @as(u64, head_buffer_bytes_default);
    // A stand-in for the labeled-metrics term: any nonzero figure works,
    // since this test pins the *sum*, not the term's own closed form
    // (`Server.metricsBytes` owns that).
    const metrics: u64 = 4096;
    const expected_max = @as(u64, conn_slots_max) * conn_bytes +
        @as(u64, relay_buffers_max) * pair_bytes +
        @as(u64, upstream_slots_max) * upstream_bytes +
        accessLogBytes(access_log_buffer_bytes_default) + endpoint_tables +
        metrics +
        head_ring +
        @as(u64, upstream_slots_max) * upstream_head_bytes +
        head_scratch;
    try std.testing.expectEqual(expected_max, memoryBytesTotal(&.{
        .conn_slots = conn_slots_max,
        .conn_bytes = conn_bytes,
        .relay_buffers = relay_buffers_max,
        .relay_buffer_pair_bytes = pair_bytes,
        .upstream_slots = upstream_slots_max,
        .upstream_bytes = upstream_bytes,
        .access_log_bytes = accessLogBytes(access_log_buffer_bytes_default),
        .endpoint_table_bytes = endpoint_tables,
        .metrics_bytes = metrics,
        .head_buffers = conn_slots_max,
        .head_buffer_bytes = head_buffer_bytes_default,
        .upstream_head_buffers = upstream_slots_max,
        .upstream_head_buffer_bytes = upstream_head_bytes,
        .head_scratch_bytes = head_scratch,
    }));
    // The L4-only shape still carries the prober's one response buffer —
    // and the labeled metrics, which exist for every config (§8).
    const expected_small = 64 * conn_bytes + 8 * pair_bytes + 8 * upstream_bytes +
        metrics + head_buffer_bytes_default;
    try std.testing.expectEqual(expected_small, memoryBytesTotal(&.{
        .conn_slots = 64,
        .conn_bytes = conn_bytes,
        .relay_buffers = 8,
        .relay_buffer_pair_bytes = pair_bytes,
        .upstream_slots = 8,
        .upstream_bytes = upstream_bytes,
        .access_log_bytes = accessLogBytes(0),
        .endpoint_table_bytes = 0,
        .metrics_bytes = metrics,
        // The L4-only shape: no ring, no upstream head pool, no scratch
        // terms — but the prober's buffer is unconditional.
        .head_buffers = 0,
        .head_buffer_bytes = head_buffer_bytes_default,
        .upstream_head_buffers = 0,
        .upstream_head_buffer_bytes = head_buffer_bytes_default,
        .head_scratch_bytes = head_buffer_bytes_default,
    }));
    // Tunnels are priced only when a listener allows an upgrade, and the
    // term is the pool's own — same shape as the L4 case above plus a
    // tunnel pool, so the difference between the two totals is exactly
    // what tunnels cost and nothing else. That separability is the
    // budget half of §5's argument: a reader can see what the feature
    // costs without unpicking it from the buffers HTTP shares.
    const tunnels: u32 = 16;
    const expected_tunnels = expected_small + @as(u64, tunnels) * pair_bytes;
    try std.testing.expectEqual(expected_tunnels, memoryBytesTotal(&.{
        .conn_slots = 64,
        .conn_bytes = conn_bytes,
        .relay_buffers = 8,
        .relay_buffer_pair_bytes = pair_bytes,
        .upstream_slots = 8,
        .upstream_bytes = upstream_bytes,
        .access_log_bytes = accessLogBytes(0),
        .endpoint_table_bytes = 0,
        .metrics_bytes = metrics,
        .head_buffers = 0,
        .head_buffer_bytes = head_buffer_bytes_default,
        .upstream_head_buffers = 0,
        .upstream_head_buffer_bytes = head_buffer_bytes_default,
        .head_scratch_bytes = head_buffer_bytes_default,
        .tunnels = tunnels,
        .tunnel_buffer_pair_bytes = pair_bytes,
    }));
    // And the term really is what separates them: the difference between
    // the two totals is the pool and nothing else, which is the claim a
    // reader of the banner's tunnel line is entitled to make.
    try std.testing.expectEqual(
        @as(u64, tunnels) * pair_bytes,
        expected_tunnels - expected_small,
    );
    // TLS is priced only when a listener terminates it, and then by three
    // terms that move together: the engines, their plaintext buffers, and
    // the one process-wide libcrypto heap. Same shape as the L4 case above
    // plus TLS, so the difference between the two totals is exactly what
    // TLS costs and nothing else.
    const engines: u32 = 32;
    const engine_bytes: u64 = tls_engine_bytes_max;
    const plaintext_bytes: u64 = 32 * 1024;
    const expected_tls = expected_small +
        @as(u64, engines) * (engine_bytes + plaintext_bytes) +
        libcrypto_heap_bytes;
    try std.testing.expectEqual(expected_tls, memoryBytesTotal(&.{
        .conn_slots = 64,
        .conn_bytes = conn_bytes,
        .relay_buffers = 8,
        .relay_buffer_pair_bytes = pair_bytes,
        .upstream_slots = 8,
        .upstream_bytes = upstream_bytes,
        .access_log_bytes = accessLogBytes(0),
        .endpoint_table_bytes = 0,
        .metrics_bytes = metrics,
        .head_buffers = 0,
        .head_buffer_bytes = head_buffer_bytes_default,
        .upstream_head_buffers = 0,
        .upstream_head_buffer_bytes = head_buffer_bytes_default,
        .head_scratch_bytes = head_buffer_bytes_default,
        .tls_engines = engines,
        .tls_engine_bytes = engine_bytes,
        .tls_plaintext_bytes = plaintext_bytes,
        .libcrypto_heap_bytes = libcrypto_heap_bytes,
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
    try std.testing.expectEqual(
        @as(u32, 34395),
        fdsRequired(conn_slots_max, upstream_slots_max, 0, 0, health_probe_concurrency_max),
    );
    // A file sink is two fds — held plus the SIGHUP-reopen transient —
    // at the ceiling as everywhere.
    try std.testing.expectEqual(
        @as(u32, 34397),
        fdsRequired(conn_slots_max, upstream_slots_max, 0, 1, health_probe_concurrency_max),
    );
    try std.testing.expect(fdsRequired(conn_slots_max, upstream_slots_max, 0, 1, health_probe_concurrency_max) <= 65536);
    // The out-of-box side of this is pinned by "the default deployment is
    // lean" below, not restated here.
}

test "budgets: the default deployment is lean" {
    // The out-of-box config (no `limits` block) starts under a routine
    // 4096 NOFILE and asks the kernel for a shallow ring, not the c10k
    // ceiling — operators opt up through `limits` (§5). One listener.
    // With the one file sink a config can name included: the lean line
    // holds whether or not the access log writes to a file.
    try std.testing.expect(fdsRequired(conn_slots_default, upstream_slots_default, 1, 1, 1) < 4096);
    try std.testing.expect(
        completionQueueDepthFor(conn_slots_default, upstream_slots_default, 1, 1, cq_fill_eighths_default) <
            completion_queue_entries,
    );
    // The effective CQ still covers the default's in-flight ops with the
    // ⅞ headroom, exactly as the ceiling does for its own.
    const depth = completionQueueDepthFor(conn_slots_default, upstream_slots_default, 1, 1, cq_fill_eighths_default);
    try std.testing.expect(inFlightOps(conn_slots_default, upstream_slots_default, 1, 1) <= @divExact(depth, 8) * cq_fill_eighths_default);
}

test "budgets: conn slots sit at the completion-queue ceiling" {
    // The ⅞-CQ fill rule (at the default = loosest fill) is what actually
    // caps concurrent connections; conn_slots_max is the largest value
    // that still satisfies it after the parked-upstream reservation, so
    // one more slot would break the budget.
    try std.testing.expect(inFlightOps(conn_slots_max, upstream_slots_max, 0, health_probe_concurrency_max) <= @divExact(completion_queue_entries, 8) * cq_fill_eighths_default);
    const one_more = (conn_slots_max + 1) * conn_ops_max + upstream_slots_max +
        2 * admin_listeners +
        admin_conns * admin_conn_ops_max + access_log_ops_max +
        health_probe_concurrency_max * health_probe_ops_max + 1 + 1;
    try std.testing.expect(one_more > @divExact(completion_queue_entries, 8) * cq_fill_eighths_default);
}

test "budgets: a tighter cq fill trades ceiling for burst headroom" {
    // More headroom (fewer eighths) never asks for a shallower ring: at a
    // fixed conn count the requested CQ is monotonic in the fill.
    const loose = completionQueueDepthFor(conn_slots_default, upstream_slots_default, 1, 1, cq_fill_eighths_max);
    const tight = completionQueueDepthFor(conn_slots_default, upstream_slots_default, 1, 1, cq_fill_eighths_min);
    try std.testing.expect(tight >= loose);
    // The conn-slot ceiling fits only at the max fill; one eighth tighter
    // overflows even the deepest kernel CQ — the loader must reject that
    // pairing (`cqFillFits` is the guard).
    try std.testing.expect(cqFillFits(conn_slots_max, upstream_slots_max, 0, health_probe_concurrency_max, cq_fill_eighths_max));
    try std.testing.expect(!cqFillFits(conn_slots_max, upstream_slots_max, 0, health_probe_concurrency_max, cq_fill_eighths_max - 1));
    // The lean default still fits with plenty of room to spare, even at the
    // old ¾ (= 6/8) fill and at the tightest floor.
    try std.testing.expect(cqFillFits(conn_slots_default, upstream_slots_default, 1, 1, 6));
    try std.testing.expect(cqFillFits(conn_slots_default, upstream_slots_default, 1, 1, cq_fill_eighths_min));
}
