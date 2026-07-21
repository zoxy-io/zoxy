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

## The concurrency ceiling is CQ-bound (95d1f8f)

Concurrent L4 connections are bound by the io_uring completion queue,
not fds or memory: each admitted connection holds up to
`conn_ops_max = 5` armed ops, the ring is pre-budgeted and never shed
(§8), and in-flight ops must stay within the configured CQ fill
(`cq_fill_eighths`, ⅞ by default). First measured before the CQSIZE
lever, when libxev fixed the CQ at 2 × SQ = 8192 and it capped
`relay_buffers_max` at `(6144 − 18) / 5 = 1225`. The finding held and
drove the fork work: `IORING_SETUP_CQSIZE` (#61) lets XevIo request the
kernel maximum (65536), lifting `conn_slots_max` / `relay_buffers_max` to
`(57344 − 23 − upstream_slots_max) / 5 = 11259` at ⅞. fds bind next now,
not memory (`fds_max = 23558` at the ceiling, so a c10k deployment raises
`RLIMIT_NOFILE` at startup, §8). `constants.zig` owns the arithmetic and
comptime-asserts it. The remaining ceiling levers — `splice` (fork) and
cutting `conn_ops_max` 5 → 4 (in-tree teardown work) — are in PLANS.md,
"c10k".

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
