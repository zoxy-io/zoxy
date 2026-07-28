# zoxy — implementation notes

Measured findings and shelved experiments, recorded so they are not
re-chased. The settled design lives in [`DESIGN.md`](DESIGN.md) — bare
section references (§) point there — and future work in
[`PLANS.md`](PLANS.md). All numbers are from the 8-core hybrid dev box
over loopback unless stated otherwise; read "Bench hygiene" at the
bottom before comparing any of them. The detailed perf write-ups from
2026-07-12 were deliberately removed from history — this file carries
the durable conclusions.

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
flags: landed; multishot recv: parked; pre-block spin: rejected — all
below). Remaining wins are environmental (nft bypass) or workload-level
(`splice`/`send_zc` for large bodies — PLANS.md).

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

## Multishot recv — measured and parked (2026-07-12)

Best-case echo microbench (pinned cores, ABBA, single-shot vs multishot
recv): only ~2–4% CPU and 15–20% fewer enters — does not pay for the
relay redesign it demands (buffer-group lifecycle, ENOBUFS coupling,
SimIo emulation). The libxev `recv_ms` patch and the echo harness were
erased with the perf write-ups; re-derive if ever needed: `recv_ms` op
= `RECV_MULTISHOT` + `IOSQE_BUFFER_SELECT` over a std `BufferGroup`,
`F_MORE` keeps the completion armed, `cqe_flags` carries the buffer id;
harness = pinned-core echo, single-shot vs multishot, ABBA. Do not
re-propose without a recv-submission-bound workload (many mostly-idle
connections) — PLANS.md holds the standing verdict.

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
itself. The durable "why" for each, so it is not re-chased — PLANS.md
carries only the one-line revisit condition per op.

- **Multishot accept** — parked, unmeasured. Saves only the userspace
  re-arm (one SQE prep per connection), invisible under keep-alive, and
  costs a fork op plus a documented exception to XevIo's
  every-callback-disarms discipline. A Tier-0 churn A/B decides it, but
  only under a churn-heavy workload (`Connection: close` storms).
- **Multishot recv / buffer rings** — its own verdict above ("measured
  and parked"). The syscall win does not pay for the relay redesign it
  demands; single-shot buffer-select would keep the strict §6 discipline
  but forfeits most of that win.
- **`send_zc`** — rejected at the deliberate 4 KiB relay buffer. Below
  ~10–32 KiB the kernel copy is cheaper than page pinning, and the extra
  notification CQE per send doubles CQE consumption, eroding the CQ
  budget that already caps concurrency (CQ-bound note below). Revisit
  only for a large-body workload with ≥16 KiB sends.
- **`splice`** — deferred; the last open c10k lever (PLANS.md). The only
  op that removes the userspace copy, and it preserves §6 backpressure
  naturally (a bounded pipe) — but the copy is not the bottleneck (§3's
  envelope; the profile above), and the costs are real: two pipes per L4
  connection (+4 fds, tripling the fd budget), a `Pool(Pipe)`, a SimIo
  virtual-pipe primitive, and a bigger per-connection op budget against
  the CQ. Shares the libxev-fork prerequisite with the CQSIZE work; TLS
  and chunked L7 bodies fall back to copy regardless. Revisit under
  genuine CPU/memory-bandwidth saturation.

## TLS handshake CPU — measured, on-loop verdict (2026-07-24)

Decision input for Phase 3a (PLANS.md): do handshakes need the §3
worker pool, or can they run on the event loop under a per-tick
budget? Pure std.crypto on the pinned 0.16 toolchain, ReleaseFast,
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
fork work, in PLANS.md "c10k".

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

Open, and deliberately not designed for yet: past ~16k req/s the c10k
run's per-request CPU climbs 25.7 → 34.7 µs while the 500-connection
run's *falls* to 18.6 µs at 44.6k. Named hypothesis — partial writes to
backed-up client sockets costing several sends per response — but it is
a hypothesis, and this file's rule is that it stays one until measured.

PLANS.md carries the standing question of whether the operator should
pick the ceiling instead of inheriting ours — the machinery (`cqFillFits`,
`ensureFdBudget`, effective-size pools) already exists; what it would
cost is a §5 amendment, spelled out there. Pinning narrows that question
to one number rather than settling it.

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
hits the same wall (fork queue: PLANS.md). What shipped instead
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
fork work (PLANS.md, fork queue): the fix for a forgotten mapping is to
name it, not to crash on it.

## Build mode for the simulator — Debug, and ReleaseSafe is a trap (2026-07-28)

Measured while sizing the nightly soak, 20k seeds on the dev box:
**Debug 25 s, ReleaseSafe 88 s, ReleaseFast 3 s.** ReleaseSafe being
3.5× *slower than unoptimized* is the surprise; it is unexplained and
worth its own look if anything ever wants to ship ReleaseSafe. Nothing
does today — release.yml builds `-Doptimize=ReleaseFast` — so this is a
simulator-workload finding, not a production one, and the ~90 k req/s
bench bands are unaffected.

The actionable half is the build mode the sim gates run under. ReleaseFast
is 8× faster than Debug and is exactly the wrong choice: it compiles
`std.debug.assert` out, and the assertions *are* most of what the sim
checks, so it would sweep eight times the seeds while verifying a
fraction of the invariants — the reached-vs-covered trap above, wearing
a performance argument as a disguise. ReleaseSafe keeps the assertions
but loses to Debug on speed, so Debug is both the strictest and the
fastest option available and there is no trade to make. Recorded so the
soak's runtime is never "optimized" by changing its build mode.

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
