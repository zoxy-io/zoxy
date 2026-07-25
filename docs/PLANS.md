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
- **Phase 3c — CPU worker pool: retired, not deferred** (2026-07-25).
  The §3 worker seam (SPMC job queue, per-worker completion rings, the
  §5 parked-slot ownership rules) is **removed from the design**, and
  in-process threads are now a §1 non-goal. The 3a bands settled it: a
  terminated L7-over-TLS hop runs at HAProxy parity in steady state on
  one thread, and the handshake-bound ceiling is not a CPU wall at all —
  it doubles when the connection count doubles, so a fixed ~45 ms
  per-connection stall binds it, which no thread removes
  ([IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md)). Where handshake
  CPU does eventually bind, threads only add cores, and process-per-core
  behind SO_REUSEPORT already does that without a shared-memory
  concurrency model. Re-entry is a
  from-scratch design decision, not un-commenting a seam, and needs both
  halves of a gate: a measured workload where handshake demand exceeds
  one loop within a single process *and* process-per-core scale-out is
  not an acceptable answer. The retired trade study (shared queue vs
  per-worker queues vs work stealing) is in git history. The open
  handshake-throughput work is not threads: find the ~45 ms
  per-connection stall (the engine-ceiling and CPU-saturation readings
  are both measured out — see the notes), then session resumption. Worth
  adding while there: a Tier-1 gate on achieved rate against offered,
  which the §9 error gates do not cover and which would have caught the
  stall on its first run.

## Prefactoring for Phase 3a — learned on `phase-3a-ztls` (2026-07-25)

Phase 3a was implemented end to end on the `phase-3a-ztls` branch (24
commits, ~4.8k lines) and measured (IMPLEMENTATION_NOTES.md). It works,
but it fought main's shape in five places, and each fight left a scar
worth removing *before* the TLS slices land again. Every item below is
independently landable on `main`, changes no behavior, and needs no TLS
to justify it — that is the test for being on this list. (Phase 3a's
engine survey above predates the branch's ztls decision; the branch's
own entry is authoritative on the stack until it merges.)

What the branch fought, with the evidence:

- **`pump.zig` assumes one buffer per direction**, because a plain relay
  recvs and sends the same bytes. TLS does not: each direction's two
  halves live in different buffers. The branch first wrote a parallel
  `net/tls_relay.zig` — 357 lines re-deriving the discipline
  `relay.zig` states in 164 — then added a transform seam to the pump
  for the L7 body legs, ending with *two* mechanisms for one job.
- **The direction cursor conflates framed bytes with wire bytes.**
  `DirectionState.sent_len`/`transfer_len` counts plaintext; under TLS
  the wire carries ciphertext. The branch needed a `creditSend` hook to
  keep them apart, and recorded the hazard: a wrong move here silently
  corrupts the byte stream instead of failing loudly.
- **Client-directed writes are three hand-rolled arm/credit pairs**
  (response head, response excess, static response), each with its own
  cursor field. TLS had to thread an encrypt-and-credit pair through all
  three and invent all-or-nothing credit semantics at each.
- **The head read is hardwired to recv-into-`conn.head`**, so TLS grew a
  parallel completion path, a plaintext accumulator, and a duplicated
  "431 vs 413 vs read again" decision.
- **Admission has no pre-protocol stage.** The branch inserted a TLS
  fork ahead of the `.l4`/`.http` fork, then repeated that same fork
  after the handshake and carried a `conn.tls_protocol` field solely to
  remember which way to go.

Sizes are estimates, in diff lines, for sequencing only.

### Tier A — mechanical, no behavior change

| # | slice | ~ | what it buys |
|---|---|---|---|
| A1 | Zero-slot `Pool`: relax `count >= 1`, sentinel `free_head`, one test | 20 | a pool the config never asked for reserves nothing and is permanently exhausted, so its acquire site needs no special case |
| A2 | `fillRandom` on the Io seam (`getrandom` in XevIo, scenario PRNG in SimIo), with the balancer's p2c seed routed through it | 60 | TLS needs key material through the seam; the side win is seed-replayable p2c in the simulator (§9) |
| A3 | Lint boundaries as a data table `{import, allowed_prefix, message}` | 50 | the branch's 5th positional bool touched every test call; a new dependency boundary should be one row |
| A4 | `abortAdmission(server, conn, socket, rung)` — *landed*, with `releaseConn` as the pool pairing it was missing | 30 | collapses the release + pressure + counter + close quartet that `admitL4`/`admitHttp` already repeat and `admitTls` repeated twice more |
| A5 | Split `prepare` from `startProtocol(server, conn)` — *landed* | 40 | one protocol fork, callable from accept *or* from a later phase — deletes the branch's duplicated switch and the `tls_protocol` field outright |

**What A5 leaves to the phase that hands a connection over.**
`startProtocol` stores the entry state and the entry deadline even at
admission, where the tail set exactly those values a moment earlier. The
two writes are identical there because `admit` reaches it through one
synchronous chain, so neither the per-tick clock nor the pressure flags
`entryTimeoutMs` reads can move in between. A phase handing over a live
connection arrives in a *different* tick, where those values legitimately
differ — so no single assertion covers both callers, and the safety at
admission is structural rather than asserted. **The hand-over caller owns
re-establishing that invariant and is where to assert it**; it should also
decide how a connection recalls its own protocol (a listener pointer on the
slot would subsume `routes`, `filters` and `cluster_index` — which is how
the `tls_protocol` field stays deleted). Recorded because two independent
reviews of A5 landed on it, and neither could guard it from here.

### Tier B — the structural ones, in dependency order

| # | slice | ~ | what it buys |
|---|---|---|---|
| B2 | Split the cursor: an explicit wire cursor distinct from the framed one, `assert(wire == framed)` while every policy is identity — *landed as vocabulary, not as a field; see below* | 60 | turns the silent-corruption hazard into a failed assertion. A pure refactor today |
| B1 | Pump transform seam — `recvBuffer`, `transformIn`, `transformOut`, `sendSlice`, `creditSend`, identity by default — and the loop condition becomes *"anything left to write?"* rather than *"cursor reached length"*. **Not done without B5** | 120 | TLS L4 becomes a policy; `tls_relay.zig` never gets written |
| B5 | A toy transform in the simulator: deterministic and non-identity (XOR mask, or 4-byte length re-framing) on an L4 sim listener, verified byte-exact by the token oracle under the adversary. **Lands with B1, not after it** | 150 | proves the seam *without crypto*, so TLS adds only crypto, not new mechanism risk. The de-risking slice for all of Tier B |
| B3 | One client-write channel over B2's cursor: `armClientWrite(conn, plaintext)` for all three client-directed sends | 150 | TLS changes one place, kTLS none; also settles what §8's "static responses straight from static memory" means once the bytes must be encrypted |
| B4 | Head-fill source seam: read through a source (socket today), one "head complete? → parse / 431 / 413 / read again" decision | 100 | removes the parallel TLS completion path and the duplicated limit decision |

**What B2 landed, and what it left to B1.** The row above asked for a wire
cursor *field* asserted equal to the framed one. Written out, that field
would be a byte-for-byte shadow of the credit cursor: under identity there
is no second buffer for it to count against, so the equality would be
tautological on every path rather than an independently derived check —
a mechanism no code exercises and no gate proves, which is the same
objection §1 makes to the retired worker seam. So B2 landed the
*distinction* instead: `DirectionState` speaks `owe`/`credit`/`owed`/
`pending`, the raw cursors are private to it (no call site outside
`Conn.zig` touches them), `owe` asserts the previous debt was settled, and
`pending` asserts the framed window fits the buffer it slices — a live
check the open-coded version never had.
**The honest cost: B1 now carries the wire cursor's mechanical shape as
well as the transform's**, which is the risk this row was sequenced first
to retire. What is retired is its *spread* — that shape now lands inside
four methods rather than across the seven sites that used to open-code
them. The rest of that cost is answered by fusing B5 into B1 (below): a
toy transform cannot run *before* the seam it is a policy on, but it can
land in the same slice, which is what keeps the mechanism from ever
existing unverified.

### Tier C — budget and accounting hygiene

| # | slice | ~ | what it buys |
|---|---|---|---|
| C1 | Pool descriptors as one comptime table feeding `memoryBytesTotal`, `fdsRequired`, `inFlightOpsMax`, `completionQueueDepthFor` and the startup print | 150 | the branch added positional args to five call sites; a new pool should be one row, and §5's memory table would generate itself |
| C2 | Counter groups — `admission_shed` vs `post_admission_failure` — with `reconcile` summing the first structurally | 60 | the branch had to reason that `shed_tls_engines` must precede admission while `tls_relay_buffer_unavailable` must not; make the wrong bucket unrepresentable |
| C3 | Per-resource release with explicit lifetimes instead of a fixed teardown sequence | 60 | kTLS wants the engine back at *handshake completion*, not teardown — illegal in today's shape |

### Tier D — measurement readiness

| # | slice | ~ | what it buys |
|---|---|---|---|
| D1 | Tier-1 gate on achieved rate against offered | 40 | the §9 gates check socket and status errors only, so a run delivering 704 of 2000 req/s passed them |
| D2 | A large-body band in the harness | 80 | the record layer's per-byte cost is unmeasured, and the kTLS decision (Phase 3b) depends on that number |

**Order.** Critical path to a small TLS slice: **A5 → A4 → B2 →
(B1 + B5) → B3 → B4**, with A1–A3 and Tier C as fill-in.

B1 and B5 are **one slice, not two**. The seam is what introduces a second,
wire-side cursor, and under identity there is nothing to check it against —
that is exactly what B2 could not stage (above). A toy transform cannot run
before the seam, since it *is* a policy on it, but landing it in the same
slice means the mechanism is never in the tree unverified: the identity
transforms prove the existing L4 and L7 body tests still pass unchanged (the
regression net), and the toy transform proves the wire cursor is actually
independent of the framed one — byte-exact under the adversary, with no
crypto involved. Only then do TLS transforms hook on. Extend the toy
transform to a `http` sim listener when B3 and B4 land.

**`tls_relay.zig` is not to be re-created.** Its own header records the
parallel loop as provisional — "worth doing once TLS is proven, and
deliberately not attempted while the L4 and L7 paths depend on the pump
unchanged". TLS is now proven on L4, so that deferral condition is met,
and B1 means the file never needs to exist.

**Deliberately not on this list**, because they belong to the TLS slice
itself: credentials loading, the engine pool, the libcrypto fixed heap,
the ztls lint rule, session tickets. Also left off: the `conn.head`
triple-duty cleanup (request head, response staging, handshake
ciphertext — with a comptime assert tying the handshake read size to
`head_bytes_max`). That coupling is real and fragile, but it is better
solved when the engine owns its own inbox than speculatively now.

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
