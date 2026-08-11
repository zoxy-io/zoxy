# zoxy — implementation notes

Measured findings, shelved experiments, and open technical questions,
recorded so they are not re-chased. The settled design lives in
[`DESIGN.md`](DESIGN.md) — bare section references (§) point there.
Planned features live as GitHub issues; this file is for threads that
carry unresolved measurement or design tradeoffs rather than a feature
request. All numbers are from the 8-core hybrid dev box over loopback
unless stated otherwise; read "Bench hygiene" at the bottom before
comparing any of them. The detailed perf write-ups from 2026-07-12 were
deliberately removed from history — this file carries the durable
conclusions.

## Open questions

Threads still being worked, carrying real tradeoffs rather than a simple
feature request. Each stays here until resolved, or promoted to a
GitHub issue once there's a concrete plan.

### TLS termination — in progress on ztls (#125)

The design settled on **no worker threads** for TLS handshakes (§3,
DESIGN.md; measured below in "TLS handshake CPU" and "TLS on the
loop"): handshakes run on the loop, ECDSA only (RSA excluded by policy —
the ~1–2 ms figure that once motivated a worker pool was an RSA number,
and ztls carries no Ed25519 CertificateVerify).

The engine is [ztls](https://github.com/mattrobenolt/ztls) — a sans-I/O
TLS 1.3 state machine in Zig over libcrypto primitives — through the
audited `zoxy-io/ztls` fork (`zoxy-tls` branch). It settled §4's reserved
C-dependency decision: the protocol layer, where TLS CVEs live, stays
auditable Zig; the constant-time primitives get the most-watched assembly
available. The fork carries four commits, each re-audited in
`build.zig.zon`; the two that are load-bearing rather than incidental:

- **RFC 6979 deterministic ECDSA nonces** (upstream mattrobenolt/ztls#82,
  still open). Without it the CertificateVerify signature — and, through
  DER integer trimming, the encrypted flight's *length* — varies run to
  run, so §9's identical-trace oracle could never assert on TLS traffic.
  Opt-in, off in production. Proven in `src/tls/spike_test.zig`, which
  also pins the negative: without the flag the same two seeded runs
  diverge, and only in the encrypted flight.
- **Server-side NewSessionTicket issuance**. Resumption is load-bearing
  twice over: a full-population reconnect storm is ~14k × ~260 µs ≈
  seconds of handshake CPU without tickets and µs-class with them, *and*
  the ticket is what answers the client's `Finished` — see "The ~45 ms
  stall, identified" below. The ticket must be emitted **after**
  processing that `Finished`, not alongside the server flight.

Session tickets are wired now, both halves: every completed handshake
issues `tls_tickets_per_handshake` of them, and an offered ticket comes
back through ztls's `psk_lookup` to `Tickets.open`. The emission lands
where the stall analysis says it must — after the client's `Finished` is
processed, staged inside the outbound pump's own loop so it rides the
same send path as the server flight.

Wiring it moved a counter, which is worth recording because the sweep is
what noticed. The ticket flight goes out while the connection is still
`tls_handshaking`, so a peer that leaves during it was being counted as
`tls_handshake_failed` — a handshake that had in fact *succeeded*. The
census caught it as a counter firing against an allowance of zero.
`tls_handshakes_completed` and `tls_resumed` are now counted where the
session comes up rather than at the hand-over, behind a `tls_session_up`
latch on the conn, and the send-error arm blames the handshake only while
that latch is unset.

Remaining:

1. **The Tier-1 bands**, whose acceptance is the close-mode rate gate PR
   #84 could not pass. The tickets above are what is expected to move it,
   and the bands are what say whether they did — nothing measured yet.

Three smaller things the reviews left open: `ResponseBodyPolicy.afterSend`
credits ciphertext to `bytes_out` where the client-write channel credits
plaintext, so a streamed TLS response over-counts; the sim's TLS http
client sends `Connection: close` and a GET, leaving the request-body leg
reachable by directed tests only; and the sealing key is drawn once at
`start` and never rotated, so the two-slot rotation `Tickets` is built
for runs with one slot live for the process. Rotation wants a timer and
the interval is a policy question (it bounds how long a stolen key is
worth having), so it is deliberately not guessed at here.

### What the live gate found

Tier 0.5 terminates real TLS from `std.crypto.tls.Client` — an
implementation sharing no code with ztls, which is the only kind whose
agreement means anything. It landed two defects that every other tier had
been green on, and both are worth recording because neither was reachable
from where the other tiers stand.

- **Every terminating process crashed at exit.** The fixed libcrypto heap
  was arena-backed; `OPENSSL_cleanup` runs from an atexit handler, after
  `main` returned and took the arena with it. Needs a *process* that
  installs the heap and then exits — which unit tests never do, the
  simulator has no process for, and the heap proof already avoids by
  installing into a static. Storage is static now.
- **A phantom access-log line per terminated keep-alive connection.** The
  log clock started on the ciphertext *delivery* rather than on the first
  decrypted byte, so the `close_notify` that ends an idle connection
  opened an entry for a request nobody made, which teardown then wrote out
  as an `aborted` exchange with no method and no bytes. Now pinned by a
  directed test, but the sim did not have it: its TLS clients close in
  protocol only after a `Connection: close` request, so no idle keep-alive
  connection was ever alerted. The reachable-counter census cannot see
  this class at all — the phantom line increments `access_log_lines`, a
  counter every run already fires.

Earlier candidates, recorded so they are not re-chased: a hardened fork
of [tls.zig](https://github.com/ianic/tls.zig) (pinned `5452baf`) was the
plan until its hardening gate — server resumption, fragmented
ClientHello (upstream #36), three post-pin fixes — proved to be most of
the work ztls had already done; **picotls** was the C fallback, rejected
for an un-hookable malloc that no zero-alloc gate could survive.
`std.crypto.tls` stays client-only (re-verified against the pinned
toolchain), which makes it a usable *test* client and nothing more.

Follow-up once TLS termination lands: **kTLS record offload**
(Linux-only) — hand the negotiated keys to the kernel
(`setsockopt(SOL_TLS)`, the fork's `Ktls.zig` payloads) so the record
layer costs zero userspace CPU and the `splice` c10k lever (below) stays
applicable to TLS traffic. Known fiddly parts: KeyUpdate/post-handshake
control messages arrive via CMSG, and session tickets must be sent
before the switchover.

### Pool ceilings — policy we choose, or a range the operator picks?

`conn_slots_max` and `upstream_slots_max` are pinned together at compile
time (11464/11464 — "The upstream pool tracks connections, not
requests" below) because they share one completion-queue budget:
`conn_slots × 4 + upstream_slots + fixed <= 57344`. That's the right
point on the line for an L7 deployment, but it's still a compile-time
policy choice — an L4-only deployment wants no upstream slots at all and
would rather spend the whole budget on conn slots, and zoxy ships
prebuilt release binaries, so a build-time knob is invisible to anyone
who installs rather than compiles.

The alternative: let the ceilings be what the types and kernel allow
(`upstream_slots_max -> maxInt(u16)`, `conn_slots_max` likewise,
independently) and let the operator name both in `limits`, rejecting an
infeasible pair at config load (`cqFillFits` already exists and already
runs unconditionally — this would stop it being shadowed by a comptime
pre-decision).

The cost was: `assert(in_flight_ops_max <= completion_queue_entries)` in
§5 (DESIGN.md) states a property of *the chosen point*; with independent
ceilings there's no chosen point, so it becomes a startup rejection
instead of a comptime assertion — a real narrowing of "budgets are
comptime-asserted" to "comptime-asserted where a budget is a property of
one constant, rejected at startup where it's a property of a
combination."

**That cost has since been paid in full, by a different change.**
Removing `listeners_max` ("Config shape is the operator's to size",
below) deleted `in_flight_ops_max` and `fds_max` outright and moved both
checks to load — `cqFillFits` and `ensureFdBudget` — so the narrowing is
shipped and DESIGN.md §5 and CLAUDE.md already say it. What is left of
this question is only the conn/upstream pair itself, and it no longer has
an invariant to spend: the wording above is the state of the code, not a
price still to be paid. Two details there are now stale — the pair reads
11466/11466, not 11464, and `SimIo` sizes its buffer from its own
`listeners_max` rather than from the deleted `in_flight_ops_max`.

Entry gate: demonstrate a workload that actually saturates the
*current* conn-slot ceiling first (the c10k runs that motivated the
upstream-ceiling work never came close — ~10k held connections against
12282 then). Take the decision before the code.

### c10k — the splice lever

Concurrent L4 connections are CQ-bound (see "The concurrency ceiling is
CQ-bound" below), and the CQSIZE lever plus the `conn_ops_max` cut have
already lifted the ceiling to 11464 connections. The one remaining lever
is **`splice`** — libxev-fork work requiring a re-audit — the only op
that removes the userspace copy while preserving §6 backpressure
naturally (a bounded pipe). Real costs: two pipes per L4 connection (+4
fds, tripling the fd budget), a `Pool(Pipe)`, a SimIo virtual-pipe
primitive, a bigger per-connection op budget against the CQ. TLS and
chunked L7 bodies fall back to copy regardless. Revisit only under
genuine CPU/memory-bandwidth saturation — the copy is not the bottleneck
today (§3's envelope; the loop profile below).

### libxev fork queue

The §4 pin policy (DESIGN.md) makes fork changes deliberate, batched
work. Landed: ring setup flags, CQSIZE (#61), per-errno surfacing on
data ops (zoxy-io/libxev#2, "libxev error surfacing is lossy — resolved
by the fork" below). Still queued, in rough value order:

1. `IORING_OP_SPLICE` (the op union is closed today) — see the c10k
   splice lever above.
2. Name the two peer-gone errnos still funneled to `error.Unexpected`
   (#106, the bug-5 shape): ENETUNREACH on connect (a routing failure,
   counted today as §8 dial pressure with only the errno gauge to say
   otherwise) and ETIMEDOUT on the data ops (a retransmission-timeout
   peer-gone verdict, same mislabel). One named error each in the fork's
   connect/read/write maps lets XevIo map them portably — cheap,
   zero-behavior-change for every other arm; batch with the next pin
   move. Worse on kqueue: the macOS backend's data-op maps name only
   CANCELED, so every dev-box data-op failure reads as §8 pressure until
   the fork names these there too.
3. Multishot **accept** — only behind a `Connection: close` storm
   workload, still unmeasured. Multishot **recv is closed**, not
   pending — see "The loop is not submission-bound" below; reopen only
   on a measured `cqes/wake` approaching 1.

### ztls fork queue

Same pin policy, same batching. Landed in `zoxy-tls`: deterministic
ECDSA nonces, `mem_hooks`, the bounded `fin_frag` wipe, NewSessionTicket
issuance (see "TLS termination" above, and build.zig.zon's audit notes).
Queued:

1. **The receive path does not enforce RFC 8446 §5.2's plaintext cap**,
   found while sizing `Engine.plaintext_bytes_min`. `RecordLayer.decrypt`
   admits any record inside `max_ciphertext_len` (2^14 + 256) and takes
   the content up to the last non-zero byte, so a non-conforming peer can
   hand a caller up to 16623 bytes where the spec allows 16384 — 239 past
   any buffer sized to the RFC. The length check exists on the *send*
   path only (`RecordLayer.encrypt`). zoxy refuses the over-long record in
   `Engine.pump` and its buffers are sized on that refusal, so nothing is
   exposed here; but a caller who trusted `max_plaintext_len` without
   checking would overflow, and `record_overflow` is the alert §5.2
   prescribes. Worth raising upstream — it is a two-line receive-side
   check, and the fix belongs where every other ztls caller inherits it.

## Loop profile at the Tier-1 band (2026-07-12)

`zig build profile` (pinned-core perf → flamegraph, §9) under load:

- Single-loop saturation ceiling ~165 k req/s (h2load `--h1 -m1`,
  connection-count-invariant) at only ~55% of its core — latency-bound
  with CPU headroom, not compute-bound. The ~45% off-CPU residue at the
  ceiling is unexplained; `perf sched` is the follow-up.
- 98.6% of cycles sit inside the one `io_uring_enter` (io_send ~79% —
  the loopback sender pays the receiver's TCP stack too). zoxy user
  code is **1.26% of cycles**: do not optimize the Zig side.
- Syscall shape: ~3.2 syscalls/request at 20 k req/s, batching to ~122
  ring ops per enter at the ceiling.
- Box tax ~12–15% of the profile: nft+conntrack ~6%, systemd BPF
  firewall ~5.6%, kernel alloc-tagging ~2.4%. An nft loopback bypass
  would clean the bench bands — environmental work, not zoxy work.

All three candidates this profile ranked have since been measured (ring
flags: landed; multishot recv: parked 2026-07-12 and **closed**
2026-07-28 once its named workload was measured and turned out not to be
submission-bound; pre-block spin: rejected — all below). Remaining wins
are environmental (nft bypass) or workload-level (`splice`/`send_zc` for
large bodies — see "Open questions" above).

## Ring setup flags — landed 2026-07-12 (196ffbf)

`SINGLE_ISSUER | COOP_TASKRUN | DEFER_TASKRUN`, exposed through the
fork's `Options.io_uring_flags` (branch `zoxy-ring-flags`, c369817).
Measured: interrupt-driven task_work eliminated (`tctx_task_work` 10.8%
→ 0, re-batched as `__io_run_local_work` in the wait path), steady loop
CPU −3.4%, p90 improved within overlapping bands, saturation unchanged.
Verify it is active: `perf -e io_uring:io_uring_create` → flags
`0x3100`. Kernels < 6.1 reject the flags; `XevIo.init` degrades to a
plain ring on EINVAL rather than refusing to start.

## Coarse deadline clock — landed (#39)

The idle-deadline refresh's `CLOCK_MONOTONIC` read was ~7% of on-CPU
under load. `XevIo.nowNs` now reads `CLOCK_MONOTONIC_COARSE` (a
vvar-page vDSO load, no TSC access): <1%. Sound because every consumer
of that clock is a second-scale deadline, so ~ms resolution is ample.
No fork change; `nowNs` documents the field-layout reach-in that the
hash pin fixes.

## CQE reaping — profiled and shelved (#40)

The pinned `zig build profile` flagged libxev's `copy_cqes` —
`memcpy`-ing completions out of the io_uring CQ into a stack array
before dispatch — at ~17% of on-CPU under load (~100 k req/s loopback),
the second-hottest symbol. Reaping in place (liburing's
`io_uring_for_each_cqe` shape: peek `cq.head` → acquire-loaded `tail`,
invoke from ring memory, `cq_advance` once) is a ~25-line fork change
and passes libxev's suite — but an A/B at a fixed ~99.8 k req/s measured
**no win**: total on-CPU samples held at ~74 k either way, the `memcpy`
symbol vanishing only to reappear inlined in the loop body. The 17% was
an attribution artifact — the `memcpy` call/setup plus the unavoidable
per-CQE touch, not removable copy work — so the pin stays put; a §4
re-audit is not spent on a non-win. Revisit only under genuine CPU
saturation with large CQE batches, never loopback. Recorded so the
profiler's headline symbol is not re-chased.

Half of that revisit condition has since been tested and the other half
found unreachable on this box — see "The loopback harness cannot
saturate zoxy" below. Under large batches the symbol gets *cheaper*, so
nothing here reopens.

## The loopback harness cannot saturate zoxy (2026-08-01)

A rate sweep looking for misspent cycles found the knee, then found the
knee is not zoxy's. L7, 64 connections, `--threads 6`, 10 s rows:

| offered | delivered | p50 | p99 | cqes/wake |
|---|---|---|---|---|
| 150 k | 149,957 | 73 µs | 14.3 ms | 27.9 |
| 200 k | 199,928 | 119 µs | 30.7 ms | 619 |
| 300 k | 208,905 | 1.63 s | 3.0 s | 670 |
| 450 k | 215,299 | 2.60 s | 5.2 s | 1439 |

Delivered flattens at ~210–215 k however hard it is pushed. What is
saturated at that point is **not the proxy**. Two `/proc` measurements,
each on its own 250 k-offered 20 s run (so they are two runs, not one
row): zoxy's dedicated core runs **57.2% busy — 51.9 points kernel, 5.2
points user**, while the whole box runs 82.7% of 8 cores = 6.62 cores
active, leaving ~6.05 cores on the other seven for nginx and zrk, i.e.
**86%**. The origin and the load generator run out of machine while zoxy
still has 43% of its core idle.

So #40's "genuine CPU saturation" is unreachable here, and no rate on
this box will make it reachable: raising the offered rate spends the
extra cycles on the load side. Reaching it needs an external origin and
generator, or a bigger box.

The "large CQE batches" half *is* reachable, and it answers the opposite
of a reopening. Comparing 100 k (13.0 cqes/wake, `--threads 2` — the
load side only, both rows delivered their offered rate) against
250 k-offered:

| | 100 k | 250 k offered |
|---|---|---|
| `copy_cqes` subtree | 13.2 / 15.9% | **6.47%** |
| `main.main` (loop body) | 12.9% | 5.8% |
| `IoUring.enter` | 4.2% | ~0% |
| http parser | ~25% | 35.7% |

Batching amortises the drain away — the `memcpy` even leaves the small-
copy path for `copyBlocksAlignedSource` — and `IoUring.enter` disappears
because a loop that always has work stops syscalling. User cycles/s is
roughly flat across the two (374 → 365 Mcyc/s), so per-request userspace
cost roughly halves, 3740 → 1714 cycles/request.

Three caveats, each of which changes what the table above means.

- **The batch depth here is the never-caught-up kind.** p50 is 1.4 s at
  250 k offered; this is the 504-per-wake signature from "A short timer
  takes over the loop's wake schedule", not efficient batching. Three
  250 k runs gave 1492 / 1013 / 669 cqes/wake at 214.5 k / 213.2 k /
  210.8 k delivered — the same offered rate, batch depth varying 2.2×.
  That independently re-confirms the existing rule: `cqes/wake` tracks
  box load and is not comparable across rows.
- **`zig build profile` samples `cpu_core/cycles/u` — userspace only.**
  Every percentage it prints is a share of ~5% of one core, not of the
  machine. "http parser 35.7%" is ~1.9% of a core; the kernel outweighs
  all of zoxy's userspace work about 10:1 and the profiler cannot see
  it. This is the easiest number in the repo to misread, and it was
  misread once before believing the `/proc` measurement above.
- Ops/req measured 4.00 flat at every rate, matching the 4.0 already
  recorded across a 156× connection sweep.

Not measured, and the honest gap: what the 51.9 points of kernel time
are actually doing. That needs kernel-mode samples, which needs a
`perf_event_paranoid` this box does not grant by default and a profiler
event without the `:u` suffix — two changes, neither of which the
userspace question above required.

## Multishot recv — measured and parked (2026-07-12), closed (2026-07-28)

Best-case echo microbench (pinned cores, ABBA, single-shot vs multishot
recv): only ~2–4% CPU and 15–20% fewer enters — does not pay for the
relay redesign it demands (buffer-group lifecycle, ENOBUFS coupling,
SimIo emulation). The libxev `recv_ms` patch and the echo harness were
erased with the perf write-ups; re-derive if ever needed: `recv_ms` op
= `RECV_MULTISHOT` + `IOSQE_BUFFER_SELECT` over a std `BufferGroup`,
`F_MORE` keeps the completion armed, `cqe_flags` carries the buffer id;
harness = pinned-core echo, single-shot vs multishot, ABBA.

That reopening condition — a recv-submission-bound workload, many
mostly-idle connections — has since been met and answered: c10k is the
workload, and it is not submission-bound ("The loop is not
submission-bound", below, 2026-07-28). Do not re-propose without a
workload whose *measured* `cqes/wake` approaches 1; the shape of the
workload is not the evidence, the batch depth is.

## Single-shot buffer-select — adopted for density, not throughput (2026-08-01)

The closure above stands on its axis, and this does not reopen it:
multishot recv chased *syscalls*, the measured workload was not
submission-bound, and nothing here changes that arithmetic. What
returned is the buffer-group *mechanism* alone, for a problem the
closure never priced: an idle L7 connection pins an 8 KiB head buffer
because the recv armed while it idles must name a destination up front
(#162 — head buffers are 62% of the default budget, held per connection
rather than per active exchange). A single-shot `IOSQE_BUFFER_SELECT`
recv — the fork's `recv_group` op, zoxy-io/libxev#3 — arms with no
buffer; the kernel binds one from the registered ring only when bytes
arrive, and returning it is a tail bump, no syscall. Op count per
request is unchanged: the closure's "forfeits most of that win" was
about the syscall win, which this deliberately does not chase.

What the closure priced as the redesign cost is now owned outright: the
buffer-group lifecycle and the ENOBUFS coupling live in the Io contract
(`recvGroup` / `bufferGroupSlice` / `bufferGroupReturn`;
`error.NoBuffers` is a §8 shed signal, never a retry), and SimIo models
the group deterministically — lowest-free-id selection, exhaustion, and
the no-consumption-on-EOF fact the fork's test pins against a real 6.18
kernel. The §6 one-armed-recv discipline and XevIo's
every-callback-disarms rule are unchanged; multishot stays closed on
its own terms (do not re-propose without measured `cqes/wake`
approaching 1).

## Head buffers left the slots (2026-08-02, #162)

Before: 21.09 MiB of the 34.2 MiB default budget — 62% — was head
buffers, inline in the conn and upstream slots, pinned for the *slot's*
life rather than the exchange's. An idle keep-alive connection held
8 KiB it needed only between first byte and turnaround; a parked origin
connection held 8 KiB that was provably dead; an L4 connection held
8 KiB the protocol cannot address. After: both heads are pooled and
memory follows request heads in flight. Three knobs
(`limits.head_buffers`, `upstream_head_buffers`, `head_buffer_bytes`)
default to the never-shedding shapes, so out of the box nothing sheds
and the total is unchanged — the wins are the idle/parked/L4 zeros and
the operator's ability to trade the counts down and the size either way.

The client side rides the seam's provided-buffer ring (`recvGroup`, the
buffer-select note above): an idle connection's armed recv carries no
buffer, the kernel binds one at the first byte, and the return is a
tail bump. The upstream side is an app pool — its first use is a
synchronous render, which a kernel ring cannot serve. Op count per
request is unchanged; poll-first arming was designed, offered, and
rejected for costing one SQE/CQE pair per request on a kernel-bound
core.

What the build actually taught, for the next pooling change:

- **The shed's keep-or-close is decided by *where* the acquire sits.**
  The upstream head acquire was planned at the render (`.l7_dialing`) —
  and the directed test immediately showed those sheds always closing:
  the §7 resync rule keeps only from `.l7_reading_head`. The acquire
  moved beside the slot acquire, and the rung behaves like its
  siblings. Place acquires where the ladder can still answer kindly.
- **The client ring's rung is the one shed that precedes the parse**, so
  it can pre-empt verdicts (400/414/501/403) that were provably
  first-answer before — four sim script oracles and a DESIGN table row
  had encoded that provability and failed honestly (seed 634). And it
  must always close: the refused bytes are unread in the socket, and a
  kept connection would re-arm onto them and shed the same request
  forever (`respond` enforces the close at comptime).
- **A delivery can carry a resource into a teardown.** The group-recv
  completion racing `beginTeardown` arrives with a kernel-bound buffer
  id; the early-return teardown path dropped it — an uncounted leak no
  drain assert could see, because the bind was never recorded. The
  `onUpstreamConnect` capture-then-release shape applies to every
  resource a completion can hand a dying connection.
- **EOF does not consume a provided buffer** — pinned by the fork's own
  test against a real 6.18 kernel and mirrored in SimIo's check order
  (reset and EOF outrank selection). The whole no-leak-at-teardown story
  rests on that fact, which is why it is a test and not a comment.

Measured (2026-08-02, Tier-1 bands, three runs each side vs `842a3e1`):
no hop-overhead regression — keep-alive L7 p50 [+20, +24] µs against
main's [+22, +23], close and large-body bands overlapping likewise.
The gate that did fire was **flat-RSS**: the kernel consumes a buf_ring
FIFO, so sustained load cycles through *every* registered buffer and
faults the whole slab (measured: RSS 10.0 → 21.2 MiB, the slab's size
exactly), where the old inline heads rode the conn pool's LIFO reuse
and only the hot slots' pages ever faulted. The fix faults both slabs
in at init — RSS now starts at the printed §5 budget (~31 MiB at the
bench shape) and stays flat, which is what the budget promise wanted
anyway. Two standing implications of the FIFO cycling: the head-write
working set is the whole ring rather than a LIFO hot set (a cache
argument for trading `head_buffers` down on small deployments), and any
future "warm buffer" reasoning about the ring is wrong by construction.

Deferred, deliberately: fuzz buffers exercise the 8 KiB default, not the
1 MiB `head_buffer_bytes_max` the parser's guards now formally span —
a capacity change, not new parsing logic, but worth a fuzz shape if the
ceiling ever earns real traffic. The banner's "access log 0 KiB" nit
(the log's 536 B/conn capture arrays living in the conn slots) also
stays open: the LogState move was cut from #162's scope on measurement —
its scalars are written unconditionally on both protocols, so moving
them buys 40 B of stride for 14 hot-path guards.

## Lazy fault-in — the floor became a ceiling (2026-08-02)

The init-time fault-in above lasted a day: it made idle RSS the full §5
total (~35 MiB at defaults), which reads as bloat in exactly the
idle/light-load column most proxy comparisons publish, while what it
protected was available more cheaply. Reversed deliberately, no knob:

- The slabs (client ring, upstream heads, scratches) are no longer
  zeroed at init. Pages fault in as exchanges use them, so the banner
  total is a **ceiling RSS approaches under load, not a startup floor**.
  Idle RSS is now dominated by what pool *headers* touch: the conn slab
  wholly (1712 B stride — headers on every page), the relay slab about
  half (8200 B stride), the separate byte slabs not at all.
- The FIFO-cycling facts above stand, with one refinement the rebuild
  measured: cycling walks every *buffer*, not every *page*. A small
  request head faults only the first page of its 8 KiB buffer, so which
  second pages are resident depends on coalescing and delivery sizes —
  a loaded process converges toward the budget, asymptotically, not to
  it on a schedule. Lazy changes when pages arrive, never whether.
- The bench's flat-RSS gate **retired with the floor** — and not for
  lack of trying: a saturating warmup (all three scenarios at the
  measured connection count, keep-alive cycling the full ring) still
  saw +2.3 MiB across the measured window, the partial-page tail above.
  A tolerance wide enough to admit legal faulting is the ceiling gate
  by another name, so the ceiling is the gate: the harness parses the
  banner's memory total (and the ring count for the warmup — outside
  view, nothing imported) and holds `RSS ≤ total + 8 MiB slack` every
  run. The warmup stays, to push RSS toward the bound so holding it is
  non-vacuous (measured at the bench shape: idle 9.8 MiB, after warmup
  18.8, after the full window 21.2, budget 35.2). The overload band
  keeps its flat check — that zoxy's whole pool budget sits inside the
  1 MiB tolerance, so only an allocation can trip it (measured flat:
  2044 → 2044 KiB).
- The trade recorded honestly: under heuristic overcommit, a
  memory-tight box now learns of a shortfall at its first traffic peak
  (OOM kill mid-serving) instead of at startup. Accepted with eyes
  open — an operator who needs the old guarantee can preallocate at the
  OS level (cgroup memory.min); zoxy no longer does it for everyone.
- SimIo keeps zeroing its slab — that was never residency, it is seed
  determinism (a replayed schedule must see identical bytes).

## The simulator runs fastest in Debug — why, not just that (2026-08-03)

That Debug beats ReleaseSafe here was measured on 2026-07-28 and
recorded where the decision lives, in `nightly-sim.yml`'s build step
(20k seeds: Debug 25 s, ReleaseSafe 88 s, ReleaseFast 3 s). Re-measured
2026-08-03 when the question came up again — 20k seeds, raw binaries,
no build overhead — it reproduces, and `perf` now says *why*, which the
original note could not:

| build | wall | instructions | cache misses |
|---|---|---|---|
| Debug (self-hosted backend) | 21.0 s | 7.73e9 | 1.88e8 |
| ReleaseSafe (LLVM) | 65.8 s | 6.84e10 | 1.68e8 |

Nearly nine times the instructions for identical work, with *fewer*
cache misses — so it is not memory traffic, which rules out the first
hypothesis (the `undefined` 0xaa fill over the harness's large
structs). The optimized build simply emits far more work per
operation; the likely cause is the safety checks LLVM materializes that
the self-hosted Debug backend does not, amplified by inlining. Not
chased past that: the verdict does not depend on the mechanism, and the
instruction ratio is the part worth knowing — it says the gap is code
generation, not the machine or the workload.

ReleaseFast is not the fallback, for the reason the workflow already
gives: it compiles `assert` out entirely, and a sweep with no
assertions checks the oracles and nothing else — §9's density is most
of what a seed is for.

So Debug is not a leftover, it is the fast mode, and the sweep's cost
is what it is: ~4.8 s for `ci`'s 4096 seeds, ~115 s for 100 000, and
~800-1060 seeds/s on the nightly's shared runners (measured across the
four shards of run 30789778589). Do not re-propose an optimize-mode
change without re-measuring this table; if the self-hosted backend's
safety coverage ever changes, that is the thing to re-check first.

## Pre-block spin — rejected (2026-07-12)

Spinning before the loop blocks: p50 +15–25 µs *worse* and CPU ×2. The
loop only blocks when its pipeline is empty and the next arrival is
~50 µs out, so the spin budget expires empty every time. Reverted; do
not re-propose.

## Hand-rolled short copy in the head render — rejected (2026-07-28)

A pinned `zig build profile` at c10k (`--protocol http --connections
10000 --rate 40000`) put 9.2% of on-CPU in `memcpy`. It splits two ways:
~6.3% is libxev's `copy_cqes` (the shelved #40 verdict above — `cq_ready`,
a single atomic load of `cq.tail`, moves in lockstep with it from 0.9% to
4.3% across runs, which is the tell that both are paying for CQ-ring
coherence traffic and not for copy work), and ~2.6% is
`render.Staging.appendHeaderLine`/`append` re-serializing the head.

The render half looked addressable: `@memcpy` lowers to a `callconv(.c)`
call into compiler_rt `memcpyFast`, and most header *names* are under 16
bytes, so the call barrier costs more than the handful of moves it
performs. Replacing it with an inline length dispatch (overlapping
fixed-width end copies below a limit, `@memcpy` above it) does exactly
what it promises — the `memcpy` calls leave `appendEndToEndHeaders`, and
`poop` on `bench/micro/l7_head_pipeline` measures **8.3–8.8% ± 0.5%
faster**.

It is still a regression, and the micro-bench is why it looked otherwise:
its heads carry 3 request and 3 response headers whose values are all
under 32 bytes, so every copy takes the inline arm. Re-run against a
realistic head (11 request headers, 8 response: User-Agent 97 B, Cookie
79 B, Authorization 64 B, X-Request-Id 36 B — 7 of 19 values over 32 B)
and the same change is **3.4% ± 0.4% slower**, bands non-overlapping. A
value past the limit pays the new dispatch *and* the call it was meant to
avoid, and the long values cost more than the short names save. Widening
the limit to 128 B (adding 32- and 64-byte arms) recovers only part of
it — still **2.1% ± 0.5% slower**.

At the proxy level it measures as nothing either way: an ABBA A/B, 6
candidate and 5 baseline 20 s runs at 10k connections, gives 3149 ± 194
cycles/request against 3193 ± 68 — overlapping bands. (One baseline run
that never reached the offered rate, 29.5k vs 39.5k req/s, was dropped.)

Two things to carry forward. First, `l7_head_pipeline`'s heads are
small enough to flatter any change that keys off header length; size the
heads to the question before trusting it. Second, this is #40's shape a
second time — a `memcpy` symbol that can be made to disappear without the
work disappearing. compiler_rt's own dispatch is already good; the call
around it is not worth beating by hand. Do not re-propose without a
workload whose header values are genuinely short.

## io_uring op upgrades — evaluated, deferred (2026-07-16)

§4's "plain ops only" holds: on the loop profile above (latency-bound,
zoxy user code ~1.3% of cycles) none of the deferred ops pays for
itself. The durable "why" for each, so it is not re-chased.

- **Multishot accept** — parked, unmeasured. Saves only the userspace
  re-arm (one SQE prep per connection), invisible under keep-alive, and
  costs a fork op plus a documented exception to XevIo's
  every-callback-disarms discipline. A Tier-0 churn A/B decides it, but
  only under a churn-heavy workload (`Connection: close` storms).
- **Multishot recv / buffer rings** — its own verdict above, parked here
  and **closed 2026-07-28** once the workload it was waiting for was
  measured. The syscall win does not pay for the relay redesign it
  demands; single-shot buffer-select would keep the strict §6 discipline
  but forfeits most of that win. Buffer-select has since been adopted
  anyway — for memory density, a different axis; see "Single-shot
  buffer-select" above. The multishot closure itself stands.
- **`send_zc`** — rejected at the deliberate 4 KiB relay buffer. Below
  ~10–32 KiB the kernel copy is cheaper than page pinning, and the extra
  notification CQE per send doubles CQE consumption, eroding the CQ
  budget that already caps concurrency (CQ-bound note below). Revisit
  only for a large-body workload with ≥16 KiB sends.
- **`splice`** — deferred; the last open c10k lever (see "Open
  questions" above). The only op that removes the userspace copy, and it
  preserves §6 backpressure naturally (a bounded pipe) — but the copy is
  not the bottleneck (§3's
  envelope; the profile above), and the costs are real: two pipes per L4
  connection (+4 fds, tripling the fd budget), a `Pool(Pipe)`, a SimIo
  virtual-pipe primitive, and a bigger per-connection op budget against
  the CQ. Shares the libxev-fork prerequisite with the CQSIZE work; TLS
  and chunked L7 bodies fall back to copy regardless. Revisit under
  genuine CPU/memory-bandwidth saturation.

## The fixed libcrypto heap plateaus — measured (2026-08-09, #125)

`src/tls/libcrypto_heap.zig` routes libcrypto's internal mallocs into one
buffer reserved at startup (`CRYPTO_set_mem_functions` through the fork's
`mem_hooks`), so §5's zero-allocation promise survives having a C library
underneath. Segregated fits: power-of-two size classes, an intrusive free
list each, a bump frontier into the shared buffer, no coalescing.

The number that matters is not the first handshake's cost but whether the
frontier **plateaus**. It only ever grows — freed blocks return to their
class list, never to the frontier — so if recycling did not work, every
handshake would claim fresh buffer and no reservation could save a
long-lived proxy. Measured by `zig build tls-heap-proof`, Debug, OpenSSL
3.6.2:

| after | frontier |
|---|---|
| credential load + 1 handshake | 1,082,752 B |
| + 16 more handshakes | 1,082,752 B (unchanged) |

So one handshake's distinct block footprint is ~1 MiB and every
subsequent handshake is free. Sabotaging `free` to drop blocks instead of
listing them takes the same run to 2,484,864 B, which is what the
plateau assertion is there to catch. The 4 MiB reservation is sized
against the plateau with room for the concurrency the frontier has not
seen yet — revisit once many handshakes are genuinely *in flight*
together, which this sequential proof does not exercise.

Two shapes of this got found rather than reasoned:

- The heap must be a static, not a caller's. `CRYPTO_set_mem_functions`
  takes bare C function pointers with nowhere to hang a context, so the
  hooks reach the heap through a module global; the earlier API took a
  `*Heap` and the proof test handed it a stack local, leaving libcrypto
  reading a dead frame the moment that test returned. `install` now takes
  the backing buffer and owns the singleton, so the mistake is unavailable.
- The proof needs its own process. The hooks must be installed before
  libcrypto's *first* allocation, and a test binary that also loads
  credentials has already allocated. Hence `zig build tls-heap-proof` as
  a separate step, gated in `ci` like everything else.

## TLS handshake CPU — measured, on-loop verdict (2026-07-24)

Decision input for TLS termination (see "Open questions" above): do
handshakes need the §3 worker pool, or can they run on the event loop
under a per-tick budget? Pure std.crypto on the pinned 0.16 toolchain, ReleaseFast,
200 iterations per primitive, pinned to a fast and a slow core:

| primitive | fast core | slow core |
|---|---|---|
| ECDSA-P256 sign (CertificateVerify) | 201 µs (worst 262) | 252 µs (worst 275) |
| ECDSA-P256 verify (client certs) | 332 µs | 444 µs |
| Ed25519 sign | 34 µs | 79 µs |
| X25519 keygen / shared secret | ~30 µs each | ~63 µs each |
| 8 × HMAC-SHA256 (resumption class) | 1.3 µs | 1.1 µs |

A full TLS 1.3 server handshake ≈ keygen + DH + cert sign: **~260 µs
(P256) / ~95 µs (Ed25519)** on the fast core, ~380 / ~205 µs on the
slow one; a PSK resumption is µs-class. One core absorbs ~3.8k full
P256 handshakes/s (~10k Ed25519). The ~1–2 ms estimate that motivated
the worker-pool design was an RSA number (RSA-2048 sign ~0.6–1 ms —
excluded by policy in 3a rather than re-measured). The worst single
uninterruptible step, ~275 µs of P256 sign, bounds the tick inflation
of an on-loop handshake budget. Bench: a scratch `zig run` harness
over std.crypto primitives (note: `std.time.Timer` and
`std.crypto.random` both relocated in 0.16 — the harness reads raw
`CLOCK_MONOTONIC` and uses `generateDeterministic` seeds).

Library survey findings from the same day, recorded so they are not
re-chased: `std.crypto.tls` is still client-only — verified in the
pinned toolchain's std tree and against upstream master; the stalled
upstream server PR (ziglang/zig#23005) is tls.zig itself. picotls
still has no allocator hook (verified against master `picotls.h`),
and its minicrypto ECDSA is uECC (~1 ms-class sign): acceptable sign
speed means the OpenSSL libcrypto backend. BearSSL's TLS 1.3 remains
unshipped. No other production-credible pure-Zig TLS 1.3 server
exists as of the scan; Geun-Oh/zigtls is aimed the right way but
0.1.0-dev — watch-list only.

## TLS on the loop — the band that retired the worker pool (2026-07-25)

Measured on the `phase-3a-ztls` branch (ztls engine, ECDSA P-256 fixture
cert, one core each side, both proxies terminating the *same* certificate
in front of the same plaintext origin, so the added pair isolates
termination cost). This is the evidence DESIGN §3 rests on when it
deletes the CPU-worker seam rather than deferring it.

Steady state — keep-alive, the shape a real HTTPS front end runs in
(three runs at branch tip `ab547a2`, bands not single numbers):

| | req/s | p50 | p90 | p99 |
|---|---|---|---|---|
| zoxy L7 + TLS | 19961–19970 | 110–122 µs | 137–174 µs | 784–1374 µs |
| haproxy https | 19960–19965 | 101–105 µs | 131–151 µs | 223–1043 µs |

Parity on rate and p50. A terminated hop on one thread is not the
bottleneck at 20k req/s, and nothing about that number wants another
thread. zoxy's tail is the worse half of the band (p99 up to ~1.4 ms
against haproxy's ~0.3 ms, and a `max` that lands on ~41.8 ms in *every*
run — see the stall below, which happens once per connection and so
amortizes away here).

Handshake-bound — `Connection: close`, one full handshake per request,
neither side resuming (zrk has no session resumption yet). Three runs,
and the third one is what explains the first two:

| offered | connections | zoxy L7 + TLS | haproxy https |
|---|---|---|---|
| 2000/s | 32 | 704 req/s | 1996 req/s |
| 2000/s | 64 | 1427 req/s | 1996 req/s |
| 500/s | 32 | 499 req/s, p50 212 µs | 499 req/s, p50 309 µs |

**The ceiling is per-connection, not per-core.** Doubling the connections
doubled the throughput, and the implied per-connection handshake cycle is
the same either way — 32 / 704 = 45.5 ms, 64 / 1427 = 44.8 ms. Below that
floor (the 500/s run, 64 ms per connection cycle) zoxy keeps up
completely, and its post-handshake exchange is *faster* than haproxy's.
So the shape is a fixed ~45 ms serialized stall per handshake connection,
load-independent, capping each connection at ~22 handshakes/s — not a
CPU wall, and not the "~1.4 ms of wall time per handshake" the first
profile's arithmetic suggested. ~40 ms is the signature magnitude of a
Nagle/delayed-ACK interaction (§4 records the same 40 ms lesson from
pooled upstream connections), and the recurring ~41.8 ms `max` in the
keep-alive runs points the same way. It is that classic; the mechanism
and the fix are the section below. The reasoning that dismissed it here —
"zoxy sets `TCP_NODELAY` on its own sockets" — was the wrong half of the
pair, and is corrected there.

Two readings to retire, both of them mine:

- **It is not the TLS-engine ceiling.** These runs have 1024 engines (the
  default now follows conn slots) and `shed_tls_engines` is **0** in
  every one of them, alongside 0 socket errors and 0 status errors. The
  earlier "13× slower than haproxy" reading *was* that bug — 261,322 of
  261,579 accepts shed at the engine rung against a 256-engine default —
  but that bug is fixed and the close-mode gap survives it unchanged
  (712 req/s before, 704 after, at the same 32 connections).
- **p50 3.2 s was not service time.** It is zrk's
  coordinated-omission-corrected wait against the offered schedule: at
  2000/s offered into a ~704/s ceiling the backlog is the measurement.
  Per-request service latency is the 500/s row.

What none of it argues for is threads. A serialized per-connection stall
is not CPU work, so a worker pool would buy exactly nothing; and where
real handshake CPU eventually binds, more cores come from
process-per-core behind SO_REUSEPORT (§3), not from threads sharing pool
memory. The in-tree levers are the stall (find it), session resumption
(stateless tickets, landed on the branch — µs-class for returning
clients), and only then anything about parallelism.

Measurement caveats worth carrying forward:

- The handshake profile shares (`zig build profile --protocol https`:
  X25519 ~25%, P-256 ECDSA ~12%, ML-KEM ~10% — zoxy and haproxy negotiate
  the same X25519MLKEM768 group against this client, so both pay it —
  `memset` 11.2%, SHA-256 in Zig 2.4%) are **user-space shares only**:
  `perf_event_paranoid` is 2 on this box, so kernel samples never enter
  the profile. They cannot be turned into a wall-time budget, which is
  how "47% crypto" turned into an arithmetic that the 64-connection run
  then falsified.
- The §9 health gates check socket and status errors, not achieved rate
  against offered, so a run delivering 704 of 2000 req/s *passed* them.
  Rate-versus-offered is not yet a gate — and it would have caught this
  on the first run.

## The ~45 ms stall, identified — nobody ACKs a silent server (2026-07-26)

The stall above is a Nagle/delayed-ACK deadlock, and zoxy's half of it is
**sending nothing between the client's `Finished` and the client's first
request**.

The sequence: the client writes `Finished`, which goes out immediately
because nothing is outstanding. It then writes the encrypted request —
and Nagle holds that second small write, because the first is still
unacknowledged. zoxy has nothing to send back, so no ACK piggybacks, and
the client waits out Linux's delayed-ACK timer. That timer caps at 40 ms.

**The earlier dismissal was the wrong half of the pair.** `TCP_NODELAY`
on zoxy's sockets governs what *zoxy* may send without waiting. What is
held here is the *client's* send, waiting on *zoxy's* ACK. Our own
NODELAY cannot touch it.

Evidence, all against the same origin:

| | first response byte |
|---|---|
| zoxy, curl (its default `TCP_NODELAY`) | 2.1 ms — faster than haproxy |
| zoxy, curl `--no-tcp-nodelay` | **42–47 ms, every request** |
| haproxy, curl `--no-tcp-nodelay` | 4.1–6.2 ms |
| zoxy plaintext, curl `--no-tcp-nodelay` | 0.2–0.8 ms |
| zoxy, `--no-tcp-nodelay`, 200 KB POST | **2.4 ms** |

The handshake phase stays at 2–5 ms in every stalling run: the gap is
entirely *after* it. The 200 KB POST is the proof of mechanism rather
than correlation — a first write larger than the loopback MSS is exempt
from Nagle, and the stall vanishes. And the load generator never sets
`TCP_NODELAY`, which is why the bands saw it and curl did not.

**It is not a zoxy bug, and not a TLS bug.** A two-small-writes probe
issued mid-connection stalls ~41 ms against *everything* — zoxy L4, zoxy
L7, haproxy, and nginx spoken to directly. What differs is reachability:
a connection's first data segment is covered by Linux's initial quickack
window, so the shape needs a pathological client on plaintext. Under
TLS 1.3 it is unavoidable — every client writes `Finished` then the
request, always past that window.

**What haproxy does differently is not an ACK policy.** It sends two
NewSessionTickets the moment the handshake completes; that segment
carries the ACK and the client's Nagle releases. Probed mid-connection,
haproxy stalls exactly as hard as zoxy.

So the fix is the message, not the socket: **emit the post-handshake
flight after processing the client's `Finished`**, which is what every
other TLS server does and what resumption wants anyway. TLS 1.3 also
permits sending it alongside the server flight — that would be legal and
would *not* fix this, because the ACK must cover the `Finished`.

`TCP_QUICKACK` was considered and rejected: it treats universal TCP
behaviour as a zoxy bug, it is Linux-only on a seam that also serves
kqueue, and it decays — making it robust means re-arming per read, a
syscall on the data path.

## Kernel socket buffers are outside the §5 budget (2026-07-26)

The startup printout is a closed form over zoxy's pools and says nothing
about the kernel memory each connection also costs. On this box the
stock defaults are `tcp_rmem` 131072 and `tcp_wmem` 16384 — 144 KiB per
socket, and an L7 connection holds two, client and upstream. Against the
1386-conn-slot default, whose printout reads **31.5 MiB of pools**, that
is **~390 MiB of kernel socket memory** — twelve times the advertised
figure, before receive autotuning, which may take `rmem` to 32 MiB per
socket. At the conn-slot ceiling — 14074 when this was measured, and
~3.9 GiB then — the same arithmetic reaches **~3.1 GiB** against ~284 MiB
of pools at the 11464 the ceiling became once the upstream pool was
pinned to it on the CQ line.

These are caps rather than committed pages — the kernel allocates as data
arrives, and `tcp_mem` bounds it globally (~3.09 GiB here). That is the
point: the bound that actually applies is the kernel's, not ours, and
crossing it means queue collapse rather than an allocation failure we
would see.

Closing it is cheap, because the options are **inherited**: measured on a
listener, an accepted socket carries the parent's `SO_RCVBUF`/`SO_SNDBUF`
(and `TCP_NODELAY`) — so one `setsockopt` at bind makes the per-socket cap
a named constant covering every accepted connection, at no per-connection
cost.

The caveat that has to ship with it: setting `SO_RCVBUF` explicitly
disables receive-window autotuning. On loopback and LAN that is free;
across a WAN a fixed small buffer caps the window and therefore
BDP-limited throughput. So this wants a `constants.zig` value with a
config override sized for the deployment, never a hardcoded shrink.

## Reading the memory hierarchy on this box (2026-07-26)

Chasing whether `Conn`'s layout costs cache misses produced one durable
tooling lesson and one settled verdict.

**`LLC-load-misses` does not count here — validate the counter first.** A
randomised pointer chase over 256 MiB, unambiguously DRAM-bound at 552
cycles per step, reports **exactly zero** LLC load misses. perf accepts
the event name and silently returns 0 rather than `<not supported>`. The
events that work are the precise ones: `mem_load_retired.l1_miss`,
`.l2_miss`, `.l3_miss` — the last reported 20,195,083 against 20,000,000
designed misses, so it is calibrated. (A first attempt at that chase
walked memory *sequentially* and was eaten by the prefetcher at 25 cycles
a step, which is exactly how a dead counter looks plausible.)

**The misses scale with connection count, not with bytes per
connection.** The 2000-connection baseline reads **2.27–2.31**
misses/request across runs; single figures below are individual runs
inside that band, not restatements of one number. Holding the offered
rate fixed and varying only concurrency, DRAM traffic goes 0.05 → 1.22 →
2.19 → 2.31 across 128 → 512 → 1000 → 2000 connections. Cutting the
`Conn` stride 4× at 2000 connections — 19.1 MB of slots down to 4.8 MB,
from over-L3 to comfortably inside a 12 MiB L3 — bought only 21%
(2.29 → 1.80). The controlled pair settles it: **512 connections at
4.9 MB take 1.22 misses; 2000 connections at 4.8 MB take 1.80.** Same
footprint, 4× the connections, 48% more DRAM traffic.

Two hypotheses died on the way, both worth not re-forming. L3 contention
with the co-resident load generator: the 12 MiB L3 is shared by cpus 0–3
only, and moving the generator to the E-cores (4–7, outside that domain)
changed the result by nothing — 2.32 against 2.27. And `align(8)` to pull
`state`/`armed` off the struct's last cache line made it *worse*, because
it split two fields that were sharing one line.

**Verdict on structure-of-arrays for `Conn`: not worth building.** The
per-completion metadata is a genuine target — `delivered()` touches nine
bytes (`generation` 4, `armed` 1, the op's `generation_at_submit` 4),
spread across three cache lines 8 KiB apart, and is 18.9% of all DRAM
misses on its own. But eliminating that share entirely takes 2.29 → 1.86
misses/request, about 240 cycles of ~3900: **~6% at 2000 connections and
nothing below ~500**. Against ~130 call sites and
breaking `Pool`'s `comptime assert(@FieldType(T, "generation") == u32)`,
which three pools share. If c10k pressure ever makes this worth
revisiting, the relay-buffer pool's free list is already 10.9% of misses
on its own and is the cheaper target.

That revisit happened — see the next section. The answer was no, by three
orders of magnitude. Do not open it a third time.

## `delivered()` at c10k — the revisit, and why it closed (2026-07-27)

The paragraph above bounded structure-of-arrays at "~6% at 2000
connections and nothing below ~500" and invited a revisit under c10k
pressure. A cloud c10k run supplied the pressure: at 10,000 connections
zoxy served 21,396 req/s at 0.758 CPU, against 44,000 req/s at 0.859 CPU
with 500 connections on the same build. **19.5 µs → 35.4 µs of CPU per
request, a 1.8× per-request penalty**, with nothing saturated anywhere —
no CFS throttling, upstream pool at 74%, origin at 24%, zero packet
drops. The working-set hypothesis fit: 500 slots touch 4.6 MiB and live
in L3, 10,000 touch 91 MiB and do not.

`bench/micro/conn_touch_scaling.zig` measures exactly that, on the real
`Conn` and the real `arm`/`delivered` pair, walked in a random
permutation (a sequential walk measures the prefetcher, not the proxy).
Median of four pinned runs, ns per arm/deliver pair:

| conns | touched | ns/op | vs 500 |
|---|---|---|---|
| 500 | 4.6 MiB | 2.81 | 1.00× |
| 1000 | 9.1 MiB | 2.76 | 0.98× |
| 2000 | 18.2 MiB | 2.87 | 1.02× |
| 5000 | 45.5 MiB | 3.34 | 1.19× |
| 10000 | 91.1 MiB | 3.97 | 1.41× |
| 14074 | 128.2 MiB | 7.18 | 2.55× |

(The last row was the conn-slot ceiling when the sweep ran; it is 11464
since the upstream pool was pinned to it on the CQ line. The bench reads
the constant, so a rerun sweeps to whatever it is now.)

The mechanism is confirmed — the knee is real and lands between 2000 and
5000 connections, where the touched set stops fitting L3. The magnitude
is what kills it. The 500 → 10,000 delta is **1.2 ns per pair**; a
keep-alive L7 request does four or five pairs (head recv, request-head
send, response-head recv, client write, body pump), so the effect is
**~5.8 ns/request against a measured 15,900 ns/request penalty —
0.04%**. Doubling it for the kernel round trip that separates a real arm
from its deliver still leaves under 0.1%.

Two methodology notes, both learned by getting them wrong first. The
bench discards a warm-up measurement: reading the first point of a run as
data absorbed the core's frequency ramp and inflated the whole curve —
before the warm-up the 10,000-connection ratio read 2.08× rather than
1.41×, which would have overstated the case for acting by 50%. And the
smallest swept point (64 connections) still reads slow despite being the
most cache-friendly; it is left in the sweep and out of the conclusions,
because a number nobody can explain is not a number to reason from.

**So the c10k penalty is essentially all outside zoxy's data
structures**, consistent with the 2026-07-12 finding that zoxy user code
is a single-digit share of cycles. At 10,000 connections it is kernel
work: TCP state for ~20,000 sockets, softirq, io_uring bookkeeping. No
`Conn` layout change reaches it.

Two harness defects surfaced doing this, both fixed in the same slice.
`bench/profile.zig` emitted no `limits` block, so every profile run above
the 1386 default spent its window at the admission wall — it was
profiling the *shed* path, and nothing in the output said so. And
`bench/micro/l7_head_pipeline.zig` had not compiled since
`renderRequestHead` grew two parameters, staying broken across four
merged slices because `bench-micro` was not in any gate. It is now a
`ci` dependency: compiled, never run, which is the cheapest thing that
would have caught it.

## Profile share is not throughput headroom — bounding a wipe (2026-07-25)

Same profile: `compiler_rt.memset` at 11.2% of zoxy's CPU, ~84% of it
traced to ztls's `secureZero` on teardown — dominated by `fin_frag`, a
16 KiB buffer reserved against a client-auth flight we never request and
wiped in full on every handshake (16386 of the 18269 bytes `deinit`
zeroed). Bounding the wipe to a high-water mark **did not change
handshake throughput**, three runs each on saturated close-mode load:

- before: 710 / 712 / 712 req/s, memset 11.2%
- after: 709 / 709 / 710 req/s, memset 10.1%

The share moves as predicted; the throughput does not, because the
handshake is bounded by asymmetric crypto (~47% of the profile), not by
the zeroing. **A symbol's share of samples is what it costs while
running, not what removing it buys** — the same number only when that
symbol is the bottleneck. The change was kept (it is correct and does
strictly less work), but it is not a lever.

Two process notes, both paid for:

- An intermediate measurement through a `.path` dependency override read
  733 / 733 req/s for code that measures 709 / 709 / 710 through the
  pinned `.url`. The build mechanism, not the code. Trust numbers from
  the shipped configuration.
- A first attempt put the high-water mark inside `ArrayBuffer` itself,
  taxing every append to benefit one buffer: 633 req/s, an 11%
  regression — caught only because the baseline had been measured three
  times and was stable to ±2 req/s. Measure the baseline's variance
  before believing a delta.

## The concurrency ceiling is CQ-bound (95d1f8f)

Concurrent L4 connections are bound by the io_uring completion queue,
not fds or memory: each admitted connection holds up to `conn_ops_max`
armed ops, the ring is pre-budgeted and never shed (§8), and in-flight
ops must stay within the configured CQ fill (`cq_fill_eighths`, ⅞ by
default). First measured before the CQSIZE lever, when libxev fixed the
CQ at 2 × SQ = 8192 and it capped `relay_buffers_max` at
`(6144 − 18) / 5 = 1225`. The finding held and drove the fork work:
`IORING_SETUP_CQSIZE` (#61) lets XevIo request the kernel maximum
(65536), lifting the ceiling to `(57344 − 23 − upstream_slots_max) / 5 =
11259` at ⅞. Serializing teardown closes behind the full armed-set
drain then cut `conn_ops_max` to 4 (the five-op teardown-vs-dial race
became structurally unreachable, proven by a pinned-seed sim test), so
`conn_slots_max` / `relay_buffers_max` ceiling at
`(57344 − 23 − upstream_slots_max) / 4` — 14074 while
`upstream_slots_max` was 1024, 12282 once it rose to 8192 (2026-07-27,
below). Pinning the upstream ceiling to the conn ceiling (2026-07-28,
below) collapsed that to one divisor, `(57344 − 23) / (4 + 1) =
**11464**`. fds bind next, not memory (`fds_max = 34408` at the ceiling,
so a c10k deployment raises `RLIMIT_NOFILE` at startup, §8).
`constants.zig` owns the arithmetic and comptime-asserts it — one line,
one divisor, so the assert is what keeps a change from silently
overcommitting the ring. The remaining ceiling lever — `splice` — is
fork work; see "Open questions" above, "c10k — the splice lever".

## The upstream pool was a wall, not a range (2026-07-27)

`upstream_slots_default` and `upstream_slots_max` were both 1024, so that
pool was the one thing an operator could only shrink — while conn slots
had the two-layer shape the design intends (1386 default, 14074 ceiling
then — 11464 now, climb through `limits`). At 10k connections the
missing range bites: the
pool pins, and every request that cannot get a slot is answered 503.

Measured on one 1-CPU box, 10k connections, same build and workload:

| | upstream 1024 | upstream 8192 |
|---|---|---|
| pool | pinned at 1024 leased | 5771/8192, never pinned |
| `l7_shed_upstream_slots` | 5,852,702 (35% of responses) | 10,576 (0.35%) |
| real req/s at high offered | decayed to 5,315 | flat ~20,000 |

Raised to 8192, which drops `conn_slots_max` to 12282 — the two are one
CQ line (`conn × 4 + upstream + 23 ≤ 57344`), so the ceiling pair is a
policy choice, not two independent numbers. Both clear 10k at this point,
which is the §1 requirement; the out-of-box footprint is byte-identical
(32,259 KiB, 3,805 fds) because only the *ceiling* moved and
`upstream_slots_default` stayed at 1024 rather than tracking it.

"Both clear 10k" was true of the numbers and wrong about the shape: 8192
still sat below the conn ceiling, and the next section is what that cost.

Note for anyone reading older benchmark numbers: every c10k run before
this date that behaved well used a **build-time `sed`** of these
constants in the bench image. Runs at the shipped 1024 are the collapse
case, not a baseline.

## The upstream pool tracks connections, not requests (2026-07-28)

The previous section sized the upstream pool against in-flight
*exchanges* — rate × latency — and reasoned that it therefore sits below
the conn-slot count. That model is wrong, and the gauges added with it
are what showed it. Two runs of the same binary (4572b4a), same `/1k`
workload, same 200→67000 ramp, one 1-CPU box:

| | 500 connections | 10,000 connections |
|---|---|---|
| sustained (achieved ≥ 90% of offered) | **44,611 req/s** | **22,481 req/s** |
| `conn_slots_in_use` peak | 500 | 10,095 of 12282 |
| `upstream_slots_leased` peak | **492** | 8,017 |
| leased + parked | ≤ ~500 | **pinned at 8192**, six scrapes |
| `l7_shed_upstream_slots` | 0 | 22,568 (0.44%) |
| `accepted` | 501 | 67,517 |
| `kernel_pressure_errors` | 0 | 0 |

Leased peak tracks the connection count, not the request rate: 492 of
500. An upstream is leased for a whole exchange and parked between
requests, so at saturation — every admitted connection mid-request —
demand is one upstream slot per conn slot. A pool below the conn ceiling
is admission capacity that cannot be served, which is exactly what the
c10k column shows: ~2200 conn slots idle while the pool they depend on
sat at its own ceiling. Hence the pinned pair, 11464/11464.

What it is *not*: the cost of concurrency. Per-request CPU at matched
offered rate is the same at both connection counts —

| offered | 500 conns | 10,000 conns |
|---|---|---|
| 9,107 | 20.4 µs | 19.6 µs |
| 12,447 | 23.6 µs | 24.2 µs |
| 15,787 | 24.9 µs | 25.7 µs |

— which is the end-to-end confirmation of the `delivered()`/SoA finding
above (0.04%). 10k connections cost nothing per request.

Nor was it the environment. At the c10k plateau the NIC carried 502
Mbit/s where the 500-connection run had carried 914 Mbit/s through the
same interface; zoxy held 78% of its 1-CPU quota with 0.17% of periods
throttled; the origin idled 3.2 of 4 cores. Worth recording for anyone
reading cloud numbers: the 2-core proxy VM showed **32% steal**, charged
straight against that quota.

One line here read, until 2026-07-28: *"past ~16k req/s the c10k run's
per-request CPU climbs 25.7 → 34.7 µs … named hypothesis, partial writes
to backed-up client sockets."* Withdrawn. The hypothesis was that a request costs
more *work* when the client backs up; on a quiet box a request costs a
flat 4.0 ring ops from 64 connections to 10,000, with no send-side term
that grows ("The loop is not submission-bound", below). The table above
still stands as measured — per-request CPU does rise with offered rate at
both connection counts — but it rises identically at 500 and at 10,000,
which is the shape of a shared environmental cost, not of a
concurrency-driven one. Partial writes were a guess at a layer the ring
counters say is not moving.

"Open questions" above ("Pool ceilings") carries the standing question
of whether the operator should pick the ceiling instead of inheriting
ours — the machinery (`cqFillFits`, `ensureFdBudget`, effective-size
pools) already exists; what it would cost is a §5 amendment, spelled out
there. Pinning narrows that question to one number rather than settling
it.

## The 503 was the only backpressure, and it was accidental (2026-07-28)

The run that verified the pinned pair did what it was built to do, and
exposed something else. Same 10k-connection ramp, same binary except the
ceilings:

| | upstream 8192 | pinned 11464 |
|---|---|---|
| `l7_shed_upstream_slots` | 22,568 | **0** |
| pool peak (leased + parked) | pinned at 8192, six scrapes | 8,749 of 11,464 |
| **sustained** | **22,481 req/s** | **22,385 req/s** |
| `accepted` | 67,517 | **220,144** |
| loadgen connect errors | 32,891 | 186,265 |
| loadgen timeouts | 58,999 | 142,478 |
| loadgen error rate | 2.2% | **6.3%** |
| errors before the knee (t<95s) | 29,299 | 16,488 |

Throughput did not move, which was the prediction: sheds were 0.44%, so
they were never the limiter. Pre-knee behaviour improved — half the
errors, and the stall that used to sit at t≈85s is gone.

Past the knee it got worse, and the mechanism is the finding. The 503
was a *fast, bounded, connection-keeping* answer. With nothing shedding,
the same request instead queues until the client's own 1 s timeout kills
it and reconnects — 3.3× the connection churn. The receipt: zoxy served
**5,001,502** responses while the loadgen counted **4,860,555**. The
140,947 gap matches the 142,478 timeouts. That work was done for callers
who had already left.

So until this run, upstream-pool exhaustion was doing double duty as
zoxy's capacity signal — and a second mechanism keyed off the same flag,
`parkedTimeoutMs`'s pressure-shortened reap, went dormant with it
(`upstream_pressure_engaged` = 2 across the whole run). Both were reading
an accident. Removing the accident was right; what it left behind was a
§8 ladder where every rung but one sheds on a resource running out, and
nothing at all bounds an exchange that is merely slow.

`timeouts.request_ms` is the answer to that: the request-deadline rung
already existed, it was simply never armed by anything but a stalled
dial. Opt-in, because how slow is too slow is a property of the
operator's origin.

## The loop is not submission-bound — multishot recv closed (2026-07-28)

The 2026-07-12 verdict parked multishot recv "until a recv-submission-
bound workload: many mostly-idle conns". c10k is that workload by shape,
so the profiler was taught to read the ring — sqes, cqes, and wakes
(voluntary context switches, the enters that *slept*) straight out of
`/proc`. Fixed 40k offered throughout, so the only variable is how idle
each connection is:

The verdict rests on a **bound**, not on a trend. Submission-bound means
roughly one op submitted and one wake per read — batch depth near 1.
Across ~15 measurements spanning 64 to 10,000 connections and settled
loads from 0.4 to 3.1, the lowest `cqes/wake` ever observed is **2.9**,
and most rows sit near 4. The enter is amortised several ways at every
point measured, so multishot's saving — the per-read re-arm — has little
left to take.

An earlier reading of this claimed more, and the retraction is the more
useful record. One sweep showed batch depth *rising* with connection
count (5.3 / 8.1 / 8.7 at 64 / 1000 / 10000) and that was written up as
the finding. A bracketed re-run does not reproduce it: the two
64-connection rows came out 3.3 and 4.2, and the 64-connection row
*exceeded* the 1000-connection row. Sorting every row of that re-run by
settled load instead:

| settled load | conns | cqes/wake |
|---|---|---|
| 1.19 | 64 | 3.3 |
| 1.76 | 1000 | 3.9 |
| 2.24 | 1000 | 4.1 |
| 3.10 | 64 | 4.2 |

Monotonic in load. Not ordered by connection count at all. The original
series ran at 0.41–0.50, close enough that a load effect and a
connection effect are indistinguishable in it — so the trend is
withdrawn, and `cqes/wake` is not usable for cross-row comparison on a
shared machine at all. What it can still support is the bound above,
which no run has come close to violating.

Two corrections this forced along the way. First, a c10k profile shows
~29% of self-time in libxev's `Readable.read` callback, and that was read
here as "what multishot attacks". It is not: multishot removes the
*submission*, not the completion or its callback. The addressable slice
sits in `IoUring.enter` and `Loop.add`, which is the ~2–4% the
2026-07-12 bench measured. Second, `cqes/wake` is **two-sided** and must
never be read without the latency beside it — see the next section, where
504 per wake means the loop never caught up, not that it batched well.

Measuring the connection-count trend properly needs a machine nobody
else is using. On a box shared with other work the signal is smaller
than the noise, and three sweeps spent proving that is enough.

Ops per request is 4.0 flat across a 156× change in connection count:
recv client head, send upstream head, recv response, send client
response. That it equals `conn_ops_max` is a coincidence of a different
quantity — the constant bounds ops *armed per slot* — but the §5 CQ
budget's arithmetic now has a measurement standing next to it.

## A short timer takes over the loop's wake schedule (2026-07-28)

`timeouts.request_ms` arms a deadline per exchange (§8). Setting it below
the *per-connection inter-request gap* is what makes that expensive, and
the cost is not the expiry — measured at 10k connections, 40k offered,
where the gap is 250 ms:

Bracketed sweep at 10k connections — three `request_ms=0` rows around the
two treatments, so drift is measured rather than assumed. CPU is perf
samples at 4 kHz over 20 s:

| row | settled load | CPU samples | req/s | p50 |
|---|---|---|---|---|
| `request_ms=0` (A) | 1.19 | 58,459 | 39,516 | 44 µs |
| `request_ms=200` | 1.35 | **38,944** | 39,479 | **51,056 µs** |
| `request_ms=0` (A′) | 1.33 | 59,895 | 39,502 | 43 µs |
| `request_ms=500` | 1.30 | 60,174 | 39,528 | 43 µs |
| `request_ms=0` (A″) | 2.25 | 59,162 | 39,577 | 45 µs |

The three baselines agree to 2.5% on CPU and 44/43/45 µs on p50, which is
what makes the rest of the table readable. `request_ms=500` is
indistinguishable from them: above the gap, nothing spurious fires.

`request_ms=200` costs **p50 43 µs → 51 ms** and **34% of CPU**, at
unchanged throughput and with zero expiries. Less CPU for worse service
is the signature of a loop that stopped sleeping rather than one doing
more work.

An earlier single run of this pair also showed throughput falling 39,075
→ 23,240, and that is **not reproduced here** — 39,479 against a 39,516
baseline. One run each, no bracketing; treat the throughput claim as
withdrawn and the latency and CPU costs as the findings. The same run
supplied the ring counters below, and its instrument has since been found
to fail on busy rows, so those carry the same single-run caveat.

From that single run, the ring counters read ops/req 4.07 → **6.51**
(+2.44) and sleeps 371,617 → 6,289, each draining 504 completions rather
than 8.7. Inferred from those, and consistent with everything above but
not directly observed: the extra ops are a timer armed per request that
fires *between* requests, finds the keep-alive turnaround has already
stored the 60 s idle deadline, and re-arms — arm, cancel, pointless fire,
which is about the 2.44 seen. Nothing in these counters watches an
individual timer, so this is the account that fits, not a sighting.

Batch depth tracks *box load* more closely than it tracks anything this
harness varies deliberately — see the section above, where sorting a
bracketed sweep by settled load orders it perfectly and sorting by
connection count does not. So the 504 figure says the loop stopped
sleeping, which the 490 ms p50 corroborates independently, but its
magnitude should not be compared against rows taken at another load.

Also inferred, from one measured (gap, threshold) pair: that the rule is
about timers generally rather than this timeout — any deadline shorter
than the loop's own wake cadence taking over its wake schedule, with
`idle_ms` exempt only because 60 s is far longer than anything else in
flight. What is measured is that 500 ms is free and 200 ms is not, at a
250 ms gap. A deployment wanting `request_ms` should keep it above the
per-connection inter-request gap it expects; the c10k benchmark's 200 ms
was below it, which is why those runs degraded.

Not measured, and the honest gap: *why* the extra ops tip the loop rather
than merely costing more. That is a question about libxev's submit/wait
policy, and answering it needs an enter count, which needs either a
syscall tracepoint (a `perf_event_paranoid` the dev box does not grant)
or a fork change.

## libxev error surfacing is lossy — resolved by the fork (2026-07-27)

The section below stood for months and is kept for the reasoning; the
wall it describes is gone. zoxy-io/libxev#2 adds
`Completion.result_errno`, recorded at the top of `invoke` *before* the
per-operation mapping runs — which is the only place the errno still
exists, since every arm's `else` hands it to `posix.unexpectedErrno` and
keeps nothing. The pin moved to b3d6b55 after re-audit: one field, one
assignment, one test, no error-set or control-flow change.

What forced it: a c10k run reported 227,628 `kernel_pressure_errors`
against 736,843 churned connections, and three runs in a row were
undiagnosable because "something failed" is not a diagnosis. The counter
is now partitioned twice over — by op (which syscall) and by cause (what
to do about it: shed load, raise a limit, widen the port range) — with
`kernel_pressure_last_errno` as a gauge so an unclassified errno stays a
lead rather than a dead end. Both partitions are asserted equal to the
total in `reconcile` and again in the witness that maintains them.

The generalization in the note below still holds and is worth keeping:
any *other* feature needing a particular errno on a data op now has the
field to read, rather than a fork to negotiate first.

## libxev error surfacing is lossy

The io_uring backend keeps only a few named errnos on data ops:
`readResult` maps CANCELED/CONNRESET/EOF and the send path maps
CANCELED/CONNRESET/PIPE — everything else, including ENOBUFS/ENOMEM,
funnels through `posix.unexpectedErrno` → `error.Unexpected` before the
seam ever sees it. The specific errno is gone at the boundary, and this
generalizes: any future feature needing a particular errno on a data op
hits the same wall (see "Open questions" above, "libxev fork queue").
What shipped instead
(0a4c0bb): a categorical witness — `relay.zig` counts a data-path
`error.Unexpected` as `kernel_pressure_errors`, matching the
accept/connect/setNodelay sites, since on an established relay socket
the orderly failures (EOF, RST) are peeled off first. SimIo grew a
one-shot `kernel_pressure` fault and a `kernel_pressure_percent`
adversary knob to exercise the rung.

## Reached is not covered — the `@panic` probe (2026-07-28, #106)

Five defects cleared 64 green sim seeds in one day (#106). One of them
sat on a path the seeds *executed*: the `write_shutdown` EPIPE branch
ran under several tests and seed 0, but the caller returned on
`isTearingDown()` before anything read the error — so its value was
unobservable, and a wrong value was green. Seed counts measure
scheduling coverage; they say nothing about whether an outcome is
asserted. kcov (`zig build coverage`) has the same blind spot: it
colors the line green because the line ran.

The thirty-second answer, now standard practice: **replace the outcome
with `@panic("probe")` and run the gate.** If `zig build ci` stays
green, the path is reached-but-unobserved — every test that "covers" it
would also pass with the behavior destroyed, and the fix is an oracle
(assert the outcome somewhere), not another seed. If the gate trips,
the panic's seed list is documentation of exactly which scenarios pin
that path. Probe before trusting, especially: error-mapping arms, catch
branches that only tear down, and any branch whose effect is a counter
nobody asserts. The probe is a temporary edit by design — nothing to
build, nothing to merge, no gate step to maintain; what lands is the
missing assertion it finds.

The related #106 question — should `else => error.Unexpected` in the
XevIo mapping arms be a Debug-mode tripwire (`unreachable`) so a
forgotten mapping announces itself? — is settled as **no**. The errno
set on live-socket ops is open, not closed: ETIMEDOUT (retransmission
timeout), EHOSTUNREACH/ENETUNREACH (ICMP feedback mid-connection) are
legal kernel answers on a data op, and a tripwire would turn network
weather into crashes. The honest fallback is what stands:
`error.Unexpected`, witnessed as §8 pressure, with the raw errno kept
by the fork (`result_errno`) and surfaced through the
`kernel_pressure_last_errno` gauge — so a mislabeled arm is a visible
lead (172 EPIPEs were how #106 bug 5 was caught), never a silent zero.
The two known peer-gone errnos still landing in the fallback are queued
fork work (see "Open questions" above, "libxev fork queue"): the fix for
a forgotten mapping is to name it, not to crash on it.

## Build mode for the simulator — Debug, and ReleaseSafe is a trap (2026-07-28)

Measured while sizing the nightly soak, 20k seeds on the dev box:
**Debug 25 s, ReleaseSafe 88 s, ReleaseFast 3 s.** ReleaseSafe being
3.5× *slower than unoptimized* is the surprise; it is unexplained and
worth its own look if anything ever wants to ship ReleaseSafe. Nothing
did at the time — release.yml built `-Doptimize=ReleaseFast` then — so
this was a simulator-workload finding, not a production one, and the
~90 k req/s bench bands were unaffected. (release.yml now ships
ReleaseSafe — see "Shipping ReleaseSafe" below — but the sim gate itself
stays on Debug regardless; that verdict doesn't change.)

The actionable half is the build mode the sim gates run under. ReleaseFast
is 8× faster than Debug and is exactly the wrong choice: it compiles
`std.debug.assert` out, and the assertions *are* most of what the sim
checks, so it would sweep eight times the seeds while verifying a
fraction of the invariants — the reached-vs-covered trap above, wearing
a performance argument as a disguise. ReleaseSafe keeps the assertions
but loses to Debug on speed, so Debug is both the strictest and the
fastest option available and there is no trade to make. Recorded so the
soak's runtime is never "optimized" by changing its build mode.

The 3.5× anomaly stayed unexplained — but it's a `sim/main.zig` seed-loop
finding, not evidence about the proxy's own request-handling code; see
"Shipping ReleaseSafe" below for what the production hot path actually
does under it.

## Shipping ReleaseSafe (2026-08-04)

`release.yml` and every build.zig target that compiles zoxy's own code
for measurement (`release_zoxy`, the Tier-0 micro binaries) moved from
ReleaseFast to ReleaseSafe. Motivation: a security review found that
`std.debug.assert` — which several bounds/invariant guards rely on as
their *only* enforcement (`mem/Pool.zig`'s double-release guard,
`net/Conn.zig`'s stale-completion generation check) — is UB-on-violation
in ReleaseFast, not a panic, contradicting TIGER_STYLE.md's "assertions
are always on" policy. No live trigger for either guard was found after
tracing every call site, so this is a hardening move, not a hotfix.
zrk/zio and the bench/profile harness binaries stayed ReleaseFast — they
generate load, they aren't the thing under test.

Given the sim finding above, the change shipped only after measuring the
actual proxy, not by assuming the sim's 3.5× applied here. Procedure:
`git worktree add` at the pre-change commit (ReleaseFast baseline),
`zig build bench -- --rate 20000 --connections 32 --seconds 5` alternated
3 rounds each between that worktree and the ReleaseSafe tree (§9 band
procedure). Steady-state (20k req/s, ~100k requests/run, the
high-volume/low-noise scenario): hop p50 zoxy L4 baseline [24,25]µs vs
ReleaseSafe [24,27]µs, zoxy L7 baseline [18,24]µs vs ReleaseSafe
[22,25]µs — bands overlap, no separation. Overload/churn band (256 conns
vs 64 slots): completed throughput baseline {5017,5009,5007} vs
ReleaseSafe {5007,5030,5007} req/s — indistinguishable. The large-body
scenario (400 req/s, 100 MiB/s, only 2000 requests/run — noisiest band)
looked separated after 2 rounds (baseline max 314µs vs ReleaseSafe min
362µs) and collapsed to full overlap by round 3 (baseline max 360µs,
ReleaseSafe min 362µs) — a clean in-session demonstration of why one or
two runs isn't enough, matching the "run-to-run variance" note below.
Confirms the prior CPU profiling (zoxy is syscall-bound, 98.6% of cycles
in `io_uring_enter`, user code 1.26%): ReleaseSafe's added checks land in
that thin user-code slice and don't move the wall-clock number. One real,
minor difference: RSS under the overload scenario sat ~1440 KiB higher
under ReleaseSafe (2128-2132 KiB baseline vs 3600-3604 KiB ReleaseSafe,
each stable across its own 3 runs) — larger static code/metadata from the
safety instrumentation, not a per-connection or growth-under-load cost
(both stayed flat across their own churn window).

## The deadline rebase cancel reaches the expiry path (#65)

Every deadline re-arm guards on `!armed.deadline_cancel` so the in-flight
rebase cancel (the one deadline cancel outside teardown, §8) cannot match
a freshly armed timer — every site except `expireDeadline`'s two verdict
branches, which `onDeadline`'s success path reached unguarded.

Reachable, and by exactly one route: `storeDeadline` writes
`min(now + timeout, birth + max_lifetime)` and every timeout is ≥ 1 ms,
so a stored target can only be in the past when the §6 lifetime cap
already is. Past the cap the dial's re-base stores an already-expired
target, and the head-read timer delivering *success* in that same batch
then finds the deadline due with the cancel still in flight. SimIo will
not stumble into it: its clock never advances inside a batch, and never
at all while any op is ready — a pending cancel always is — so the head
and the cap have to wake at the same instant by construction. 2000
undirected seeds missed it; the directed case (`http_proxy_test.zig`,
client head held back to exactly the cap) hits it at seeds 88 and 93
of 200.

Fixed by hoisting the guard over the whole success path: a due deadline
defers to `onDeadlineRebase`, which re-arms at the stored target once the
cancel drains, expiring one round-trip later. `expireDeadline` asserts
`!armed.deadline_cancel` — the directed case's oracle, and it panics
there if the guard is dropped. Nothing changes at the boundary: past the
cap the verdict's own grace clamps into the past too, so the connection
is condemned either way. What changed is that the invariant is uniform
and now asserted rather than assumed.

## Occupancy is not overload — conn-pressure keep-alive kill reverted (#57)

The v0.0.0 watermark design (#54) suppressed downstream keep-alive under
*conn-slot* pressure as well as relay pressure. Cloud bench, 2026-07-20,
CONNECTIONS=1024 against `conn_slots_max` 1020: the population sits
permanently above the ¾ engage mark (765), the flag limit-cycles between
765 and the 510 release floor, and every response rendered while engaged
announces `Connection: close` — ~500-connection synchronized
close/reconnect waves, proxy-VM accepts at ~1400/s against a ~38/s
baseline, a seconds-long coordinated-omission latency tail, zero errors
reported. The same rig at CONNECTIONS=500 (below the release floor) was
clean, isolating the flag as the cause.

Verdict (settled): conn-pool occupancy cannot distinguish a healthy
keep-alive population from imminent exhaustion — for a keep-alive
workload, high occupancy *is* the steady state, and closing serving
connections converts pressure into churn. Keep-alive suppression is now
relay-pressure only (`Server.keepAliveSuppressed`); conn-slot scarcity
is answered by the idle-timeout division plus the accept-time RST wall —
the nginx/haproxy norm: never close an established keep-alive connection
to admit a newcomer.

## The overload stall gate was counting the shed, not the stall (#82)

The Tier-1 overload band gated `read_errors + timeouts` under 1% of
completions. On this box it failed 4 runs in 5 at 2.0–6.2% (zrk v1.3.1),
and 4 in 4 at 4.8–14.2% after the v1.4.1 pin move — reproducibly, with
nothing wrong with the proxy.

The filed theory was that the queue is legitimately deeper than zrk's 2 s
wire timeout, so a slice of requests crossing it is arithmetic.
Measurement says otherwise: **`timeouts` is 0 in every failing run**, and
the run with the lowest tail (p99 642 µs, three orders inside the
timeout) failed at 2.04%. The stall rate does not track the tail at all.

What it tracks is the conn-slot wall. With `timeouts` at zero, zrk's
`connect + write + read` is the whole of its `socketErrors()`, and on the
four runs that captured zoxy's counters alongside, that total landed
within 0.1% of `shed_conn_slots` — one socket error per RST'd connection.
How it divides is pure race, and it moves run to run: across six runs the
connect share ranged 28–54%, write 43–71%, read 1.3–3.3%. Which bucket a
given connection lands in is only how far the generator got before the RST
arrived. Meanwhile zoxy witnessed no relay fault at all on those runs:
`deadline_expired`, `upstream_connect_failed`, every `kernel_pressure_*`,
`l7_bad_gateway` and `l7_gateway_timeout` all 0, with
`accepted = admitted + shed_conn_slots` balancing exactly. Causally
confirmed: raising the scenario's `conn_slots` 64 → 200, nothing else
changed, cut the shed 205k → 46k and the gate passed.

So the old gate exempted the connect share as "the shed working as
designed", ignored the write share, and failed the run on the read share.
Raising the ceiling or lowering the offered rate would both have made it
pass — by producing fewer RSTs, which is why neither was the fix.

Verdict (settled): the stall gate holds `timeouts` alone, the one
## Config shape is the operator's to size (2026-08-01)

Eight compile-time ceilings removed across four slices: `routes_max`,
`filters_per_listener_max`, `actions_per_filter_max`,
`header_matches_per_filter_max` (7e194f6), `config_bytes_max` (5f81788),
`clusters_max` and `endpoints_per_cluster_max` (10205eb, 77c8bb9), and
`listeners_max` (a991db6). A config's shape is now bounded by what the
operator writes and by what the ring and fd budgets admit at load, not by
numbers chosen on their behalf at build time.

**They were a capability ceiling, not a memory cost — that is the
finding.** Measured with a `@sizeOf` probe against the pre-change tree:
`Server` 36,160 -> 16,736 bytes, so **19,424 bytes per process** of state
a deployment below the compile ceiling never used (`UpstreamPool` 6,184
-> 80, `Balancer` 8,336 -> 72, `Checker` 12,320 -> 9,296). Against the
35,060 KiB the binary prints, that is **0.055%**. It was real resident
memory — `init` zeroed every one of those tables at startup, so the pages
were faulted in — but anyone expecting this work to reclaim memory should
read that number first. What it actually buys is that 16 clusters, 64
endpoints, 32 routes, 32 filters and 8 listeners stop being walls no
price could pass.

The eight split into four classes, and the class decided the work:

- **Bounded nothing** (routes, filters, actions, header matches). Already
  `arena.alloc(..., json.len)`. Pure deletion of config-load gates and
  JSON Schema `maxItems`.
- **Sized something** (clusters x endpoints, whose product sized seven
  endpoint-keyed tables). Needed `EndpointKeys{stride, count}` derived
  from the loaded config, and `pick`'s stack array had to become
  preallocated scratch — a runtime-length stack array is the dynamic
  allocation §5 forbids.
- **A budget input** (`listeners_max`). Not a config-shape cap at all: it
  was a term in the derivation of `conn_slots_max`,
  `completion_queue_entries`, `fds_max` and `in_flight_ops_max`. Removing
  it is what spent the comptime invariant; see the Pool ceilings question
  above.
- **Type-width guards**, which stay. `Conn.endpoint_none` is
  `maxInt(u16)`, so `constants.endpoint_index_max` bounds real indices
  and `Conn` asserts the relationship. `header_edits_max` stays too, and
  the rule it illustrates is the useful one: **a limit that sizes a fixed
  buffer must precede the config; a limit that only gates a config need
  not exist.**

### What a ceiling was quietly holding up

The recurring hazard, and the reason each slice took a review: a ceiling
does load-bearing work far from where it is declared, and removing it
exposes whatever was leaning on it.

- **`keys_seen_max = 4096`**, a loop backstop sitting *above*
  `clusters_max`. Left in place it would have become the new cluster
  limit — an undocumented wall replacing a documented one.
- **Two O(n^2) scans**, duplicate cluster names and duplicate listener
  binds. Both were harmless at 16 and 8 (~120 and ~64 compares) and cost
  ~2.1e9 and ~8e8 compares once the ceilings went — minutes of startup
  for configs whose *memory* fits easily. Both are sorted-neighbour
  compares now.
- **The admin listener.** `XevIo`'s listener table was sized by
  `listeners_max`, which silently covered `Admin.start` binding through
  the same `listen`. Sizing it to the configured count instead made every
  admin-enabled deployment fail at startup with `AddressUnavailable` — a
  full table reported as a bad address. The suite could not catch it:
  `Server(XevIo)` is instantiated only by main.zig and `admin_test` runs
  over `SimIo`. `init` now folds in `admin_listeners` itself, and a
  contract test locks it.
- **The §5 budget promise, broken twice.** Removing `config_bytes_max`
  left the config arena unbounded *and* unreported, so the startup total
  understated what the process holds; the endpoint tables then did it
  again by allocating after `printBudgets` ran. Both are now terms in the
  printed budget — the arena measured, the tables closed-form via
  `Server.endpointTableBytes`.

Every one of these was found by `tiger-style-reviewer` on the slice's own
diff, not by the gates: `zig build ci` was green for all of them.

client-visible failure that belongs to *admitted* work. Every socket
error in this band is a connection that was never admitted, already
witnessed by the 5xx status gate and the accept-RST count. A genuine
mid-exchange break is still gated by `proxiesHealthy` on the keep-alive,
close and large-body bands, where no RST wall fires and a socket error
can only be the proxy's fault. The band now prints the refused/timed-out
split every run: a threshold whose margin is invisible until it trips is
how this one sat mis-specified for a week.

## Open: the https leg wedged once on macOS (2026-08-11, #125)

The first CI run carrying the Tier-0.5 https leg wedged on the macOS
runner — the whole 30 s budget, against a run that takes about a second.
Every run since has passed there, on the same commit and on later ones,
so this is **intermittent and unexplained**, not a platform that cannot
terminate TLS. Recorded rather than waved off: an intermittently red gate
is worse than a red one, because the first instinct on seeing it green
again is to stop looking.

What is known. Linux has never reproduced it, over dozens of local runs
and every CI run. The commit before — the same TLS listener, configured
and started, but with no client connecting to it — passed macOS, so the
listener, the certificate load and the libcrypto heap install are not it;
the first macOS execution of the *handshake and exchange* path is also
its only failure. The proxy was alive and quiet, not crashed: no panic
reached its log.

What is *not* the explanation, checked: the delayed-ACK stall documented
above is bounded by a timer in the tens of milliseconds and cannot
produce a thirty-second wait; and the extra admin scrape the leg adds is
the fourth of its kind in a run whose first three already pass there.

The instrumentation to catch it next time is in: the watchdog names the
wait it died in (and, for the requests, which one), and it now SIGTERMs
the proxy and lets it drain before killing it, so the report carries the
proxy's own counters. The first wedge had neither — it said only that
thirty seconds had passed, which is what made it un-diagnosable. The
standing suspicion to test first is a lost wakeup in the kqueue path,
since the TLS legs are the one place a data op is armed outside the
provided-buffer ring, and a race there would present exactly this way.

## The live gate's measured numbers (2026-08-02, #144)

Tier 0.5 (`zig build smoke`, DESIGN.md §9) landed with these readings on a
loopback dev box; they are what its bands and equalities were set from,
and a future tightening should start here rather than from taste.

- **Whole run: 0.89 s**, of which the drain deadline is 0.3 s and the
  probe window 0.5 s. The load itself — 136 L7 exchanges, 2 L4
  connections, 15 accepted connections — is single-digit milliseconds.
  The drain deadline is the *entire* shutdown cost: an idle keep-alive
  connection is indistinguishable from one about to send a request, so
  the drain waits for it and reaps at the deadline (§8). At the stock
  2 s that alone made the gate a 2 s gate.
- **Probes: 20 in a 500 ms window at a 25 ms interval**, run after run —
  exactly what the interval implies, since a probe against a loopback
  origin costs nothing against the pacing. With the deadline-cancel in
  `health.zig`'s `settle` disabled (#130 itself), the same window
  measures **0**. The 5..60 band therefore sits four times below and
  three times above a number that has not once varied.
- **Resident set: 0 KiB of growth** across two identical load passes,
  measured at a zero-KiB tolerance before the shipped 64 KiB was chosen.
  §5's promise is exact here, not approximate; the tolerance is headroom
  for page granularity on some other kernel.
- **Upstream reuse: 135 of the run's 136 L7 exchanges** — one dial and
  135 reuses, read off the drain-time counter dump. The clients are
  driven sequentially, so the pool hands the same parked connection back
  every time; the gate itself only requires the count to be nonzero,
  since which connection the pool picks is its business and not a claim
  worth pinning.

**The finding worth keeping: filling the head buffer is not enough to
produce a response excess.** The bulk target's 32 KiB body does fill
zoxy's 8 KiB upstream head buffer, and `l7_response_excess_sent` still
read **0**. The excess rides the head write whenever
`rendered.len + excess <= head_buffer_bytes`, and the rendered head is
the origin's head *minus* hop-by-hop headers — so head plus excess comes
to exactly the buffer size and fits, 8192 <= 8192. The branch needs the
render to **grow** the head, and the only thing that grows it is the
injected `Connection: close` (`render.zig`). The gate's bulk requests
announce close for that reason alone, and the counter then reads exactly
one per request. Anyone reaching for this path in a directed test needs
both halves.

## Phase 0 baselines (2026-07-10/11)

- Debug-build zoxy over loopback (`zig build bench`, nginx origin, rate
  20 k, c=32): 20 k req/s sustained, hop +259 µs p50 (426 µs proxied vs
  167 µs direct). RSS byte-identical across ~200 k requests — the
  process-level zero-alloc witness. Clean SIGTERM drain, exit 0.
- haproxy 3.4.1 reference band in the same harness (mode tcp,
  nbthread 1 to match the single loop): zoxy hop +214 µs p50 vs haproxy
  +199 µs, p90/p99 bands overlapping — parity with the state of the art
  on this setup. Another run's pair read +128 vs +123 µs: compare within
  one run, never across runs. haproxy never gates (§9).

## Bench hygiene (hard-won)

- **Bands, not numbers.** p50 swings up to ~3× between identical
  back-to-back runs; a regression verdict needs alternating runs of
  both binaries in one session (§9 Tier 1).
- **Thermals.** The first saturation run after idle reads ~165 k req/s;
  the P-core then settles to ~117 k at identical CPU share. Only
  adjacent within-session A/B pairs are comparable; set the performance
  governor for A/Bs and restore powersave after.
- **Stale proxies.** Killing `$ZOXY_PID` does not kill an
  strace-wrapped zoxy (that pid is strace's) — stale instances stay in
  the SO_REUSEPORT group and silently absorb load from later runs.
  Before any bench: `pgrep -af zoxy` and `ss -tln` on the bench ports.
  An afternoon of tail-latency forensics was lost to this.
- **strace is unusable** for latency work (tracer writeback freezes
  tracees 8–12 ms and mangles timestamps); bpftrace on the io_uring
  tracepoints (submit/complete keyed by `user_data` = Completion
  pointer) works well.
- **Generator limits.** zrk saturates at ~25–27 k req/s on this box
  regardless of cores — use h2load (`--h1 -m1`) above that. And
  closed-loop `-m1` measures *latency*: a proxy hop lowers its req/s by
  construction; saturating zoxy's core needs high `-c` or real RTT.
- **Zig 0.16 `Child`.** `kill()` reaps; a `wait()` after it is UB
  (SEGV'd the ReleaseFast bench harness and leaked nginx onto a bench
  port — d3000f5).
