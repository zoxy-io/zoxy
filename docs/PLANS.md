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

- **Phase 3a — single-threaded TLS termination.** Two settlements:
  2026-07-24, **no worker threads** — handshakes run on the loop under a
  per-tick budget (measured ~100–400 µs per full handshake in pure
  std.crypto, IMPLEMENTATION_NOTES.md; the ~1–2 ms figure that motivated
  the worker pool was an RSA number, so RSA certs are simply not
  supported); and 2026-07-25 (PR #66 spike), **the engine is ztls** —
  sans-I/O TLS 1.3 server, Zig protocol layer over libcrypto primitives,
  the §4 C-crypto exception — pinned by content hash to the zoxy-io/ztls
  fork (branch `deterministic-ecdsa` = upstream `41c24d7` plus opt-in
  RFC 6979 deterministic ECDSA nonces, mattrobenolt/ztls#82, offered
  upstream). Server certs are **ECDSA-only** on this engine (P-256/
  P-384; ztls's CertificateVerify schemes carry no Ed25519 — supersedes
  the earlier "ECDSA/Ed25519" wording), and libcrypto's assembly P-256
  sign is faster than the std.crypto numbers the budget was derived
  from, so the arithmetic holds with margin. A handshake backlog past
  the per-tick budget is a §8 shed rung like any other.
  What the spike proved (src/tls/, `zig build tls-spike`): the sans-I/O
  drive loop over static caller-owned buffers with zero wrapper
  allocation; key material injected as plain data; byte-exact
  server-flight replay under seeded inputs — the §9 property — with the
  recorded rule that *every* peer keyshare must be seeded (a random
  P-256 keyshare rides in the ClientHello and varies the signed
  transcript). Fallback if ztls's pre-alpha state proves untenable:
  ianic/tls.zig, pure Zig, pinned at `5452baf` for 0.16 — its gap is
  server-side resumption (survey verdicts in IMPLEMENTATION_NOTES.md).
  The remaining gate, in slice order — each behind all four §9 gates:
  1. **libcrypto allocation interposition** — `CRYPTO_set_mem_functions`
     into a fixed startup arena (helper lives on the fork so zoxy's tree
     declares no C symbol); the zero-alloc gate extended over a TLS
     handshake. The one slice with real unknown-unknowns.
  2. **Engine productionization** — measured per-conn footprint into
     `constants.zig` (pool-vs-embed decision), backpressure replacing
     the spike's fits-assert, the ClientHello reassembly buffer, the
     drive-API settle (sink vs pull) against `Conn`, and the ztls
     import boundary added to the lint.
  3. **Config + startup cert loading** — a per-listener `tls` block
     into the config arena; schema metadata; one cert per listener
     (SNI multi-cert deferred).
  4. **The handshake phase in the data path** — its own deadline (the
     slowloris answer), the per-tick budget + backlog + shed rung +
     counters: the §8 ladder's new row.
  5. **Data-path shim** — L4-over-TLS first (terminate, relay
     plaintext), then L7 head-read over decrypted bytes; the strict
     relay discipline is unchanged either way.
  6. **Sim + fuzz gates** — the spike client ported into the sim
     harness (both keyshares seeded), the adversary at TLS record
     granularity, golden byte-exact transcripts on clean seeds; fuzz
     raw bytes through the wrapper — never panic, alert-or-progress.
  7. **Resumption** — `psk_lookup` + ticket issuance over a static
     key table in the memory budget. Last deliberately: full handshakes
     already fit the budget; tickets are the reconnect-storm lever
     (~14k × ~260 µs ≈ seconds of handshake CPU without them).
  8. **Tier-1 TLS bench** — needs a TLS-capable load path: zrk TLS
     support is the open dependency (h2load `--h1` is the interim).
  Cross-cutting entry gate: the ztls audit per §4 (the Zig protocol
  layer read line-by-line; the C primitives trusted institutionally),
  and the pre-alpha posture — pin advances are deliberate, batched
  migrations, with upstream engagement continuing on #82.
- **Phase 3b — kTLS record offload.** Linux-only follow-up to 3a: hand
  the negotiated keys to the kernel (`setsockopt(SOL_TLS)` — ztls ships
  the struct payloads in its `ktls` module, and upstream's README
  claims kTLS offload working) so the record layer costs zero userspace CPU
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
