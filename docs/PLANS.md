# zoxy — plans

Future work, in dependency order. The settled design lives in
[`DESIGN.md`](DESIGN.md) — bare section references (§) point there —
and the measurements behind the verdicts below live in
[`IMPLEMENTATION_NOTES.md`](IMPLEMENTATION_NOTES.md). Every phase ships
behind all four gates of §9.

## Phasing

- **Phase 0 — skeleton + L4. Shipped.** `Io` seam with `XevIo` + `SimIo`,
  `Pool(T)`, `constants.zig`, config (strict JSON, arena, parse-once),
  accept gate, TCP relay, deadline timer, SIGTERM drain, the exhaustion
  ladder rungs that exist so far, all four test gates, static-memory and
  fd-budget printout. Spec-complete 2026-07-13: the kernel-pressure
  witness on the relay data path (0a4c0bb) closed the last §8 audit gap.
- **Phase 1 — L7 HTTP/1.1. Shipped.** Head parser + framing, upstream
  pool + keep-alive both sides, relay-buffer decoupling (idle costs no
  relay memory), static error responses, remaining ladder rungs. Entry
  gate: the hparse fork must clear the hardening list recorded in §7
  before this phase lands — **cleared 2026-07-18** (zoxy-io/hparse
  PR #3: CRLF-only line terminators + extension-method tokens; pin at
  65521ed). Spec-complete 2026-07-19 (PR #47) with all four §9 gates
  covering L7: the mixed-protocol simulation (golden + prefix oracles,
  retro-validated against two shipped bugs), the keep-alive-reuse
  zero-alloc gate, and the `Connection: close` Tier-1 bands.
- **Phase 1.5 — path routing. In progress.** Longest-prefix
  path → cluster tables per listener, matched on the §7 canonical path
  (decode unreserved escapes, collapse dot-segments; structure-changing
  escapes → 400) with the canonical path forwarded upstream, so the
  router and the origin cannot diverge — the settled §7 decision
  (2026-07-19). No match → the 404 static verdict. The sim gains a
  routing-correctness oracle: distinct canonical bodies per cluster
  plus path-confusion scripts (`/a/../b`, `%2e%2e`, encoded slash).
  Host rules deferred as a compatible extension of the same table.
- **Phase 2 — shedding hardening + minimal resilience.** P2C pick,
  stale-replay (a checkout that fails on first use answers 502 today),
  per-try deadline and the §8 request-deadline 504 verdict (an expired
  exchange tears down today), counter reconciliation invariants in
  the sim, overload benchmark scenario (offered load ≫ capacity: assert
  flat memory, bounded latency for admitted work, all excess shed with
  correct status). The relay-buffer pressure watermark shipped early
  (361213f); the remaining watermarks land here.
- **Phase 3 — TLS.** CPU worker pool + job queues for handshakes (§3 seam
  activates). The stack is an **open decision under the Zig-first policy**
  (§4). Leading candidate (surveyed 2026-07-12): **picotls** (h2o/picotls)
  — sans-I/O, battle-tested in H2O/quicly at Fastly, feature-complete
  (resumption, 0-RTT, HRR, client certs, ECH), injectable
  `random_bytes`/`get_time` (sim-drivable), kTLS-ready via
  `ptls_export_secret`/`update_traffic_key`, and its minicrypto backend
  even drops the system-library link for termination — but the protocol
  layer itself is C (the §4 exception swallows the whole TLS layer) and
  it mallocs internally with no allocator hook, so the zero-alloc
  promise needs link-time interposition or a documented carve-out. Last
  rung: the previous iteration's full OpenSSL/libssl recipe (sans-io BIO
  pair + fixed FFI heap, kTLS switchover) — proven by us, heaviest, and
  now likely displaced by picotls even as a fallback.

## io_uring op upgrades — evaluated, all deferred (2026-07-16)

§4's "plain ops only" policy holds: on the measured profile —
latency-bound with CPU headroom, zoxy user code ~1.3% of cycles
(IMPLEMENTATION_NOTES.md) — none of the deferred ops pays for itself.
Verdicts, so they are not re-litigated:

| op | verdict | revisit when |
|---|---|---|
| multishot accept | parked (unmeasured) | connection-churn workload (`Connection: close` storms) |
| multishot recv + buffer rings | measured, parked (2026-07-12) | recv-submission-bound workload: many mostly-idle conns |
| `send_zc` | rejected at 4 KiB buffers | large-body workload with ≥16 KiB sends |
| `splice` | deferred | genuine CPU/memory-bandwidth saturation |

- **Multishot accept** saves only the userspace re-arm (one SQE prep per
  connection), invisible under keep-alive; it also needs a fork op and a
  documented exception to XevIo's every-callback-disarms discipline.
  Decide with a Tier-0 churn A/B if a churn-heavy workload shows up.
- **Multishot recv / buffer rings.** The best-case echo microbench gave
  only ~2–4% CPU and 15–20% fewer enters — it does not pay for the relay
  redesign it demands (IMPLEMENTATION_NOTES.md). Buffer rings' real
  payoff is Phase-1 memory shape — idle keep-alive connections arming a
  recv without a dedicated posted buffer — but multishot recv *is*
  read-ahead, which the strict §6 relay exists to forbid; single-shot
  buffer-select keeps the discipline and forfeits most of the syscall
  win. Revisit only if Phase-1 idle-connection memory is measured as a
  problem.
- **`send_zc`.** Below ~10–32 KiB the kernel copy is cheaper than page
  pinning, and the extra notification CQE per send doubles CQE
  consumption — eroding the CQ budget that already caps concurrency
  (next section). At the deliberate 4 KiB relay buffer it is a strict
  loss.
- **`splice`.** The only op that removes the userspace copy, and it
  preserves §6 backpressure naturally (a bounded pipe). But the copy is
  not the bottleneck (§3's envelope; the profile above), and the costs
  are real: two pipes per L4 connection (+4 fds — the fd budget
  triples), a `Pool(Pipe)`, a SimIo virtual-pipe primitive, and a bigger
  per-connection op budget against the CQ. Shares the fork prerequisite
  with c10k below; TLS and chunked L7 bodies fall back to copy
  regardless.

## c10k — lifting the 1225-connection ceiling

Concurrent L4 connections are CQ-bound, not memory- or fd-bound:
`relay_buffers_max = (6144 − 18) / 5 = 1225` (derivation in
`constants.zig`). Two levers, both fork work:

1. **Deeper CQ** — `IORING_SETUP_CQSIZE`; libxev fixes the CQ at 2 × SQ
   today, and exposing it needs `IoUring.init_params` plumbing in the
   fork, not just a flag OR. This directly lifts the ceiling. Past it,
   fds bind next: `fds_max = 14 + 2·relay_buffers`, so true c10k (~10 k
   buffers → ~20 k fds) also raises the documented `RLIMIT_NOFILE`
   assumption.
2. **`splice`** (above) — an independent win at saturation, same
   fork/re-audit cost.

Entry gate: demonstrate a workload that actually hits the 1225 wall
before spending a fork re-audit on it.

## libxev fork queue

The §4 pin policy (audited commit, moves only after re-audit) makes fork
changes deliberate, batched work. Landed so far: `Options.io_uring_flags`
(branch `zoxy-ring-flags`, c369817 — the §4 ring setup flags). Known
queue, in rough value order:

1. `IORING_SETUP_CQSIZE` exposure (c10k lever #1).
2. Per-errno surfacing on data ops: the backend collapses ENOBUFS/ENOMEM
   — and every uncommon errno — into `error.Unexpected`
   (IMPLEMENTATION_NOTES.md), so zoxy ships a categorical
   kernel-pressure witness instead. Fork change: map
   `.NOBUFS`/`.NOMEM => error.SystemResources` and widen
   ReadError/WriteError.
3. `IORING_OP_SPLICE` (the op union is closed today).
4. Multishot accept/recv ops — only behind the workloads in the verdict
   table above.

## Deferred, revisit on evidence

- HTTP/2, HTTP/3, gRPC, WebSocket — after the L4/L7 core is proven (§1).
- Richer resilience: circuit breakers, outlier ejection, retry budgets,
  active health checks (§7).
- Hot restart + drain-to-successor (§1).
- Config DSL (§1 keeps config parse-once immutable).
- Metrics/admin plane beyond loop-written counters + the SIGUSR1 dump
  (§8).
- Dynamic DNS for upstream endpoints (§1).
- io_uring op upgrades — the verdict table above.
