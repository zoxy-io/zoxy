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
- **Phase 1.5 — path routing. Shipped 2026-07-20 (PR #50).** Longest-
  prefix path → cluster tables per listener, matched on the §7 canonical
  path (decode unreserved escapes, collapse dot-segments; structure-
  changing escapes → 400) with the canonical path forwarded upstream, so
  the router and the origin cannot diverge. No match → the 404 static
  verdict. The sim fuzzes canonical forwarding (an origin oracle
  rejecting a non-canonical forward) and a path-confusion script.
- **Phase 1.6 — host routing. Shipped 2026-07-20 (PR #51).** Host is the
  route table's outer dimension (§7): an optional per-route `host`,
  matched host-specific-first then longest-prefix, so `host + path`
  composes in one table with one precedence rule. Host is matched on its
  canonical form (lowercased, port-stripped) computed in the trust
  boundary but forwarded verbatim. No-Host requests match only any-host
  routes. Cluster selection stays the route table's alone — `pick
  cluster` is not a filter action.
- **Phase 1.7 — programmable filters. Implemented 2026-07-20 (branch
  `feat/filters`).** The "filters are data,
  not code" model of §7, and the piece that finally gives the `route`
  phase seam (`http/router.zig`) and the renderer real programmable
  content — cluster selection already being the route table's alone, so
  filters never compete with routing for the backend decision. A *rule*
  is `{ match, actions }`, compiled at config load into bounded immutable
  arena tables and *interpreted* per request — never scripted, never
  allocating.
  - **Match** — a conjunction of predicates over the parsed head:
    method ∈ set, canonical host/path prefix or exact (reusing the §7
    canonical forms so a filter and the router agree byte-for-byte), and
    header present / equals / contains. Zero-copy against head-buffer
    slices; `match_predicates_max` bounds the conjunction.
  - **Actions** — a closed enum, ordered list per rule: `reject` (a
    static status from the §8 set, e.g. 403/404/429), `set`/`add`/`remove`
    header, `rewrite` a path prefix. No `pick cluster` (routing owns the
    backend), no WASM/scripting (an interpreter with unbounded fuel or an
    embedded allocator cannot satisfy §9). Anything past the enum is a
    Zig function in the owning phase module.
  - **Where it runs** — reject before the relay buffer/upstream are
    acquired (like the §8 rejects); header/path mutations applied during
    the existing head *render* (already required for hop-by-hop stripping
    and `Connection` injection), so nothing edits the head buffer in
    place and a head that no longer fits after edits is the existing
    oversize-after-edits 431. A path rewrite changes *only the forwarded
    path* — routing already chose the cluster from the original canonical
    path, so a rewrite never re-routes and never chains (first-applicable
    rule wins). Its `from`/`to` prefixes are validated canonical at load
    and the replacement is a segment-correct join, so the forwarded path
    is canonical by construction (see DESIGN.md §7).
  - **Limits** (as shipped in `constants.zig`) —
    `filters_per_listener_max`, `actions_per_filter_max`,
    `header_matches_per_filter_max`, and `header_edits_max` (the
    listener's total header edits, bounding the renderer's materialized
    edit buffer); evaluation is bounded loops, load-shed like everything
    else.
  - **Gates** — config resolve/reject tests for the rule tables; a fuzz
    oracle that a rendered head after edits still re-parses (the
    render-oracle already proves this shape for hop-by-hop edits); sim
    scripts asserting a reject fires before any dial and a header/path
    edit reaches the origin exactly once.
  - **Slices (as shipped)** — (1) rule/action config schema + validation +
    constants; (2) the match interpreter (pure, over a parsed head) +
    the `reject` action at the route phase; (3) header-edit actions woven
    into the renderer + the 431-after-edits path + a reserved-name guard
    against editing proxy-managed headers; (4) the `rewrite` action
    (forwarded path only, segment-correct join, no re-route); (5) sim +
    adversarial-cross-seed oracles.
- **Phase 2 — shedding hardening + minimal resilience. Implemented
  2026-07-20 (branch `feat/resilience`).** Six slices, each behind all
  four §9 gates:
  - **Endpoint pick** — per-cluster config `"pick": "rr" | "p2c"`
    (default p2c, the §7 trajectory; typo fails loudly). P2C draws two
    distinct uniform candidates from a fixed-seed xorshift64* (the sim
    replays every seed twice demanding identical traces — pick
    determinism is a feature) and leases the lower per-endpoint leased
    count, maintained by the upstream pool as a closed system over its
    four lease transitions. Deferred: a reuse-aware tie-break (a pick
    may dial fresh while the other candidate holds a parked conn), and
    L4 lease tracking (L4 dials hold no Upstream slot, so p2c sees only
    L7 load; a pure-L4 cluster can opt into `rr`).
  - **§8 request-deadline 504** — ops are never canceled (§5), so the
    verdict is *deferred*: mark `pending_verdict`, `shutdown(.both)` the
    upstream socket (forcing each armed op on it to complete),
    handler-top diverts funnel the forced completions into a settle that
    answers the static 504 once both data ops are free. Answerable =
    no response byte sent and no armed op on the client socket (a
    client-side body recv cannot be forced without closing the client;
    that stall stays a teardown). The deadline re-arms around the
    verdict; a second expiry falls through to teardown. A timed-out L7
    *dial* earns the same 504 (RFC 9110 §15.6.5 — the one connect
    cancel outside teardown); a refused dial keeps its prompt 502, the
    counters orthogonal.
  - **Stale-replay** — a reused checkout that fails with no response
    byte and no body-pump entered takes one free replay: dispose the
    stale slot, re-parse conn.head (§7 bytes-are-truth), re-derive the
    framing tracker (the coalesced excess feeds again), fresh pick,
    fresh dial under its own per-try connect deadline — never another
    checkout. Spent before the try begins; a second early failure is
    502. Deferred: reaping the endpoint's whole idle list on stale
    detection (the restarted-origin case burns one replay per parked
    conn until the sweep).
  - **Watermarks** — one `poolPressureOn/Off` rule (engage ceil 3/4,
    release floor 1/2) for all three pools. Relay + conn pressure =
    downstream pressure: idle timeout divides, keep-alive not honored.
    Upstream pressure: parked deadlines and the sweep interval shrink.
    Every engage crossing counted; clean sim seeds keep all watermarks
    above the client population.
  - **Config `limits`** — optional `{conn_slots, relay_buffers,
    upstream_slots}`, validated 1 ≤ n ≤ the comptime ceilings (which
    stay the budget-asserted truth); `Server.InitOptions` *is*
    `Config.Limits`.
  - **Overload benchmark** — a second zoxy shrunk to {64, 4, 8} under
    256 zrk connections: flat RSS, 2xx served AND 5xx shed witnessed,
    relay stalls < 1% (accept-RSTs exempt — they are the conn wall
    working), SIGUSR1 counter dump, clean drain. Merge-time only.
  - Counter reconciliation grew the verdict inequalities
    (`l7_gateway_timeout ≤ deadline_expired`,
    `upstream_replayed ≤ upstream_reused`), asserted by the sim under
    every seed; the sim's adversary gained blackholed dials and a
    `stale_reuse` origin mode.
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
- Config JSON Schema — the generator ships (`zig build schema`, reflected
  from the config definitions, released as an asset per §5). Deferred until
  there is a reason: host it at its stable `$id`
  (`https://zoxy.io/schema/config.schema.json`) and add a `"$schema"`
  pointer to `config/example.json` once it resolves; an optional
  `zoxy --schema` subcommand so the shipped binary can emit its own schema.
