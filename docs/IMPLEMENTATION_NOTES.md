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
`conn_slots_max` / `relay_buffers_max` now ceiling at
`(57344 − 23 − upstream_slots_max) / 4 = 14074`. fds bind next, not
memory (`fds_max = 29188` at the ceiling, so a c10k deployment raises
`RLIMIT_NOFILE` at startup, §8). `constants.zig` owns the arithmetic and
comptime-asserts it. The remaining ceiling lever — `splice` — is fork
work, in PLANS.md "c10k".

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
