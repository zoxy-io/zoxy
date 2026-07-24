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

- **Phase 3a — single-threaded TLS termination.** Settled 2026-07-24:
  **no worker threads** — handshakes run on the loop under a per-tick
  budget. Measured on the pinned toolchain (IMPLEMENTATION_NOTES.md), a
  full TLS 1.3 server handshake in pure std.crypto costs ~95 µs
  (Ed25519 cert) to ~380 µs (P256 on a slow core); resumption is
  µs-class. The ~1–2 ms figure that motivated the worker pool was an
  RSA number, so RSA certs are simply not supported — ECDSA/Ed25519
  only, a documented constraint. The worst single uninterruptible step
  (~275 µs P256 sign) bounds tick inflation; a handshake backlog past
  the budget is a shed rung like any other (§8). One core absorbs
  ~3.8k full P256 handshakes/s (~10k Ed25519), resumption effectively
  unlimited.
  The stack (surveyed 2026-07-24): a **hardened fork of
  [tls.zig](https://github.com/ianic/tls.zig)**, pinned at `5452baf` —
  the last Zig-0.16 commit; builds and tests clean on the pinned
  toolchain — pure Zig under the §4 policy like libxev and hparse.
  What makes it fit: sans-I/O `nonblock.Server` (caller buffers both
  ways) behind our own wrapper; an allocation-free handshake path
  (allocator appears only in startup cert loading — the config arena);
  injectable `rng: std.Random` and `now: Io.Timestamp`, so SimIo
  drives handshakes deterministically (§9); std.crypto primitives;
  client-cert support; and a `Ktls.zig` that already emits the
  `setsockopt(SOL_TLS)` key payloads (→ 3b). The fork's hardening
  gate, hparse-style — cleared before 3a lands:
  1. **Server-side session resumption** (NewSessionTicket issuance,
     PSK-DHE acceptance, binder verification) — the one missing hard
     requirement, and load-bearing: without tickets a full-population
     reconnect storm is ~14k × ~260 µs ≈ seconds of handshake CPU;
     with them, µs-class per connection.
  2. **Fragmented ClientHello** (upstream #36) — a real robustness gap
     the fuzz gate would find anyway.
  3. Backport the three post-pin fixes (CBC-padding overflow
     `106d10b`, dangling `alpn_protocol` `47c402a`, `d633a0f`).
  4. The server handshake under zoxy's fuzz gate, fuzzed through our
     wrapper like hparse (§9).
  Fallback if hardening proves costlier than estimated: **picotls** —
  functioning, but now two policy exceptions deep (C dependency plus
  un-hookable malloc, plus OpenSSL libcrypto for acceptable sign
  speed; verified unchanged 2026-07-24). std.crypto.tls stays
  client-only (re-verified against the pinned toolchain and upstream
  master; the stalled upstream server PR ziglang/zig#23005 *is*
  tls.zig, so the fork adopts the same code with more control).
- **Phase 3b — kTLS record offload.** Linux-only follow-up to 3a: hand
  the negotiated keys to the kernel (`setsockopt(SOL_TLS)`, the fork's
  `Ktls.zig` payloads) so the record layer costs zero userspace CPU
  and the post-handshake data path stays byte-identical to today's
  relay — which also keeps the `splice` c10k lever applicable to TLS
  traffic. The 3a userspace record path remains the portable fallback
  (macOS dev box, kernels without the TLS ULP). Known fiddly parts:
  KeyUpdate and post-handshake control messages arrive via CMSG, and
  session tickets must be sent before the switchover.
- **Phase 3c — CPU worker pool, behind an evidence gate.** The §3
  worker seam (SPMC job queue, per-worker completion rings, the §5
  parked-slot ownership rules) stays designed but inactive — it is the
  hardest remaining concurrency work in the plan, and the 3a numbers
  say it buys nothing at realistic handshake rates. Entry gate: a
  measured workload where handshake demand exceeds the on-loop budget
  within one process (sustained cold full-handshake load past
  ~4k/s/core) *and* process-per-core scale-out (§3) is not an
  acceptable answer. Until then the binary stays single-threaded.

## io_uring op upgrades — evaluated, all deferred (2026-07-16)

§4's "plain ops only" policy holds: on the measured profile —
latency-bound with CPU headroom, zoxy user code ~1.3% of cycles — none
of the deferred ops pays for itself. The measured rationale per op lives
in [`IMPLEMENTATION_NOTES.md`](IMPLEMENTATION_NOTES.md); here only the
standing revisit conditions, so the verdicts are not re-litigated:

| op | verdict | revisit when |
|---|---|---|
| multishot accept | parked (unmeasured) | connection-churn workload (`Connection: close` storms) |
| multishot recv + buffer rings | measured, parked (2026-07-12) | recv-submission-bound workload: many mostly-idle conns |
| `send_zc` | rejected at 4 KiB buffers | large-body workload with ≥16 KiB sends |
| `splice` | deferred (the last open c10k lever) | genuine CPU/memory-bandwidth saturation |

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
