# zoxy — plans

Future work, in dependency order. The settled design lives in
[`DESIGN.md`](DESIGN.md) — bare section references (§) point there —
and the measurements behind the verdicts below live in
[`IMPLEMENTATION_NOTES.md`](IMPLEMENTATION_NOTES.md). Every phase ships
behind all four gates of §9.

## Phasing

Phases 0–2.5 — skeleton + L4, L7 HTTP/1.1, path routing, host routing,
programmable filters, shedding hardening + minimal resilience, and the
admin/metrics listener — are shipped on `main` (PRs #47, #50, #51, #54,
#60, #61). Their behavior is recorded in [`DESIGN.md`](DESIGN.md); history
is in git log, not here. Two sub-items they left open are tracked below
under [Deferred, revisit on evidence](#deferred-revisit-on-evidence).

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

## c10k — the CQSIZE ceiling (splice the last lever)

Concurrent L4 connections are CQ-bound, not memory- or fd-bound (before
the CQSIZE lever the CQ was fixed at 2 × SQ, capping `relay_buffers_max`
at `(6144 − 18) / 5 = 1225`). Two in-tree levers have landed and set the
current ceiling — the CQSIZE lever (#61, `IORING_SETUP_CQSIZE` off the
fixed 2 × SQ, in-flight fill tunable via `limits.cq_fill_eighths`, ⅞
default) and the `conn_ops_max` 5 → 4 cut (teardown closes serialized
behind the full armed-set drain, #64) — putting `conn_slots_max` /
`relay_buffers_max` at 14074 at ⅞ fill, with `fds_max` 29188 (a c10k
deployment raises the documented `RLIMIT_NOFILE` at startup, §8). The
arithmetic and its history live in IMPLEMENTATION_NOTES.md.

The one remaining lever is **`splice`** (above) — an independent win at
saturation, still libxev-fork work (a re-audit); TLS and chunked L7
bodies fall back to copy regardless.

Entry gate for further ceiling work: demonstrate a workload that actually
saturates the 14074 ceiling first — the splice lever costs a re-audit,
not worth spending blind.

## libxev fork queue

The §4 pin policy (audited commit, moves only after re-audit) makes fork
changes deliberate, batched work — `Options.io_uring_flags` (the §4 ring
setup flags) and `Options.cq_entries` (the c10k CQSIZE lever, #61) landed
this way. Known queue, in rough value order:

1. Per-errno surfacing on data ops: the backend collapses ENOBUFS/ENOMEM
   — and every uncommon errno — into `error.Unexpected`
   (IMPLEMENTATION_NOTES.md), so zoxy ships a categorical
   kernel-pressure witness instead. Fork change: map
   `.NOBUFS`/`.NOMEM => error.SystemResources` and widen
   ReadError/WriteError.
2. `IORING_OP_SPLICE` (the op union is closed today).
3. Multishot accept/recv ops — only behind the workloads in the verdict
   table above.

## Deferred, revisit on evidence

- HTTP/2, HTTP/3, gRPC, WebSocket — after the L4/L7 core is proven (§1).
- Richer resilience: circuit breakers, outlier ejection, retry budgets,
  active health checks (§7).
- Hot restart + drain-to-successor (§1).
- Config DSL (§1 keeps config parse-once immutable).
- Metrics/admin plane beyond the pull-only Prometheus scrape endpoint +
  SIGUSR1 dump (Phase 2.5): a control surface (§8). Push export (OTLP /
  remote-write) is ruled out, not deferred — it wants a protobuf dep,
  outbound export buffering, and collector DNS, all against the grain.
  Single-scrape-at-a-time stays by design (a localhost round trip); lift
  only on evidence.
- P2C reuse-aware tie-break and L4 lease tracking (§7, from Phase 2's
  endpoint pick): a pick may dial fresh while the other candidate holds a
  parked conn; L4 dials hold no Upstream slot, so p2c today sees only L7
  load — a pure-L4 cluster can opt into `rr` meanwhile.
- Stale-replay idle-list reaping (§7, from Phase 2): on stale-checkout
  detection only the one checkout is disposed — a restarted origin burns
  one replay per parked conn until the sweep reaps the rest.
- Dynamic DNS for upstream endpoints (§1).
- io_uring op upgrades — the verdict table above.
- Config JSON Schema — the generator ships (`zig build schema`, reflected
  from the config definitions, released as an asset per §5). Deferred until
  there is a reason: host it at its stable `$id`
  (`https://zoxy.io/schema/config.schema.json`) and add a `"$schema"`
  pointer to `config/example.json` once it resolves; an optional
  `zoxy --schema` subcommand so the shipped binary can emit its own schema.
