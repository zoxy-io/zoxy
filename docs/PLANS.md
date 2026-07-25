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
  What the spike proved (src/tls/, now under `zig build test`): the sans-I/O
  drive loop over static caller-owned buffers with zero wrapper
  allocation; key material injected as plain data; byte-exact
  server-flight replay under seeded inputs — the §9 property — with the
  recorded rule that *every* peer keyshare must be seeded (a random
  P-256 keyshare rides in the ClientHello and varies the signed
  transcript). Fallback if ztls's pre-alpha state proves untenable:
  ianic/tls.zig, pure Zig, pinned at `5452baf` for 0.16 — its gap is
  server-side resumption (survey verdicts in IMPLEMENTATION_NOTES.md).
  The remaining gate, in slice order — each behind all four §9 gates:
  1. **libcrypto allocation interposition** — *landed:* the fork's
     `mem_hooks` (`CRYPTO_set_mem_functions`) plus zoxy's fixed
     segregated-fits heap (`src/tls/libcrypto_heap.zig`), proven by a
     handshake-on-the-heap test (`tls-heap-proof`). The universal
     no-mmap-after-init claim rides the zero-alloc syscall gate once TLS
     joins the serving path (slices 5–6).
  2. **Engine productionization** — *landed:* the ~116 KiB footprint
     measured and the pool-not-embed decision recorded
     (IMPLEMENTATION_NOTES.md); real backpressure (a zero-progress feed
     is `error.RecordTooLarge`, never a ReleaseFast spin); the
     ClientHello reassembly buffer (ztls #36, test-verified meaningful);
     the ztls import boundary in the lint. *Deferred to slice 5* (where
     they get a first consumer): the `Pool(Engine)` and its
     `constants.zig` budget, and the drive-API settle (sink vs pull)
     against `Conn`.
  3. **Config + cert loading** — *landed:* a per-listener `tls: {cert,
     key}` block (orthogonal to `protocol`), resolved to file paths with
     schema metadata and pure path validation (the loader stays IO-free,
     §1); and `tls.Credentials` — PEM chain + key → cert-chain DER +
     libcrypto signing key + scheme, ECDSA-only (a non-ECDSA leaf is
     rejected loudly), shared per listener. The engine now borrows a
     `*const Credentials` instead of the spike's raw scalar. *Deferred to
     slice 5:* the startup file read (path → bytes) and per-listener
     Credentials construction, which happens where the engine pool
     consumes them (SNI multi-cert stays deferred).
  4. **Build wiring** — *landed:* ztls is a first-class dependency of the
     `zoxy` module, so the shipped binary and every gate link libcrypto
     (openssl moved into the CI closure). The TLS tests fold into
     `zig build test`; only `tls-heap-proof` keeps its own step, since the
     allocation hooks must precede libcrypto's first allocation and that
     needs a fresh process.
  5. **TLS engine pool + budget** — *landed:* `Pool(tls.Engine)` on the
     Server, sized by `limits.tls_engines` (default 256 ≈ 30 MiB when a
     listener terminates TLS, **zero** when none does — `Pool` now
     accepts a zero-slot, permanently-exhausted pool, so linking the
     engine costs a plain deployment nothing). The engine term joins the
     closed-form memory total and the startup printout; engines hold no
     socket and arm no ring op, so the fd and CQ budgets are untouched.
     *Deferred to slice 6:* per-listener `Credentials` built at startup
     from the config paths (the file read), and engine checkout.
  6. **Startup credentials** — *landed:* main.zig installs the fixed
     libcrypto heap (completing slice 1's wiring — nothing had called
     `install` before), reads each TLS listener's cert/key, and builds a
     per-listener `Credentials` the Server hands to its `ListenerState`.
     A missing or malformed certificate aborts startup naming the path,
     so a proxy never comes up unable to present it. Verified in the real
     binary: boots with a live cert, exits 1 on both failure paths.
  7. **The handshake phase in the data path** — its own deadline (the
     slowloris answer), the per-tick budget + backlog + shed rung +
     counters: the §8 ladder's new row. Engine checkout lands here.
  8. **Data-path shim** — L4-over-TLS first (terminate, relay
     plaintext), then L7 head-read over decrypted bytes; the strict
     relay discipline is unchanged either way.
  9. **Sim + fuzz gates** — the spike client ported into the sim
     harness (both keyshares seeded), the adversary at TLS record
     granularity, golden byte-exact transcripts on clean seeds; fuzz
     raw bytes through the wrapper — never panic, alert-or-progress.
     Also fold the slice-3 PEM/base64 cert parser (`tls/Credentials.zig`)
     into a fuzz target — new parsing over operator input, unit-tested
     for now but owed §9 fuzz coverage (the ci `--fuzz` gate is
     libcrypto-free, so this rides the TLS fuzz seam this slice builds).
  10. **Resumption** — `psk_lookup` + ticket issuance over a static
     key table in the memory budget. Last deliberately: full handshakes
     already fit the budget; tickets are the reconnect-storm lever
     (~14k × ~260 µs ≈ seconds of handshake CPU without them).
  11. **Tier-1 TLS bench** — needs a TLS-capable load path: zrk TLS
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
| A1 | Zero-slot `Pool`: relax `count >= 1`, sentinel `free_head`, one test — *landed, with the requirement moved rather than dropped* | 20 | a pool the config never asked for reserves nothing and is permanently exhausted, so its acquire site needs no special case |
| A2 | `fillRandom` on the Io seam (`getrandom` in XevIo, scenario PRNG in SimIo), with the balancer's p2c seed routed through it | 60 | ~~TLS needs key material through the seam~~ — **retired, see below** |
| A3 | Lint boundaries as a data table `{needle, confined_to, message}` — *landed* | 50 | the branch's 5th positional bool touched every test call; a new dependency boundary should be one row |
| A4 | `abortAdmission(server, conn, socket, rung)` — *landed*, with `releaseConn` as the pool pairing it was missing | 30 | collapses the release + pressure + counter + close quartet that `admitL4`/`admitHttp` already repeat and `admitTls` repeated twice more |
| A5 | Split `prepare` from `startProtocol(server, conn)` — *landed* | 40 | one protocol fork, callable from accept *or* from a later phase — deletes the branch's duplicated switch and the `tls_protocol` field outright |

**A2 is retired, not deferred.** Its two halves both fail the test this list
sets. `fillRandom` on the Io seam has no caller here at all — TLS keys and
session tickets are its only consumers, so it would be a seam method
implemented in both backends and called by nothing. And routing the balancer's
p2c seed through it contradicts a settled decision rather than improving on
it: `balancer.zig` seeds xorshift64* from a fixed named constant *on purpose*
("determinism is a feature" — the simulator replays every seed twice and
demands byte-identical traces, §9), and the spread argument for per-process
randomness does not hold either, since sibling processes behind SO_REUSEPORT
already diverge through their own lease tables. TLS brings `fillRandom` when
TLS brings a consumer for it.

**A1 landed by moving the requirement, not removing it.** Relaxing `Pool`'s
`count >= 1` on its own would have traded a live check for an absent caller's
convenience. Instead the container now permits an empty pool — a generic
container has no business insisting otherwise — and `Server.init` asserts that
its three pools are non-empty, which is where the requirement is actually
true: a proxy without conn slots, relay buffers or upstream slots cannot serve
a request. Nothing is unchecked that was checked before, and the zero-slot case
has a unit test rather than waiting for its first production user.

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
| B4 | Head-fill source seam: read through a source (socket today), one "head complete? → parse / 431 / 413 / read again" decision — *landed at ~40 lines; see below* | 100 | removes the parallel TLS completion path and the duplicated limit decision |

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
| C1 | Pool descriptors as one comptime table feeding `memoryBytesTotal`, `fdsRequired`, `inFlightOpsMax`, `completionQueueDepthFor` and the startup print — *landed as a `PoolSizes` struct; see below* | 150 | the branch added positional args to five call sites; a new pool should be one row, and §5's memory table would generate itself |
| C2 | Counter groups — `admission_shed` vs `post_admission_failure` — with `reconcile` summing the first structurally — *landed as a naming rule, not two groups* | 60 | the branch had to reason that `shed_tls_engines` must precede admission while `tls_relay_buffer_unavailable` must not; make the wrong bucket unrepresentable |
| C3 | Per-resource release with explicit lifetimes instead of a fixed teardown sequence | 60 | ~~kTLS wants the engine back at handshake completion~~ — **already true, nothing to build; see below** |

**What Tier C landed, and what it did not.** All three rows were written from
the TLS branch's diff rather than from this tree, and two of them shrank when
read against it.

- **C2 landed as a naming rule instead of two counter groups.** `reconcile`
  now sums the gate identity off the field set — every counter named `shed_*`
  — rather than a hand-written list, which is what makes A4's comptime assert
  in `abortAdmission` load-bearing: a rung joins the sum by being named, and
  the two checks are one rule read from both ends. Two groups would have been
  more machinery for the same guarantee. A test pins today's membership so a
  new `shed_*` counter has to change the gate identity deliberately (verified
  by adding one and watching it fail), and a second test pins that an
  `l7_shed_*` reject lands on the *other* side of the identity.
- **C1 landed as a `PoolSizes` struct, not a descriptor table.** The table was
  budgeted against five call sites; there are four, all in `main.zig`, and two
  of the four functions (`fdsRequired`, `inFlightOps`) take counts only — a
  TLS engine holds no socket and arms no ring op, so it never enters them.
  What is genuinely hazardous is `memoryBytesTotal`'s six positional
  arguments, three of them `u64` byte sizes: transposing two compiles, runs,
  and prints the wrong total. Named fields make that unrepresentable, and a
  fourth pool is a field plus a term. Unifying the count-only functions with
  the sizing one would have coupled things that share nothing.
- **C3 needs nothing.** The row claims a resource can only be released at
  teardown; the code already releases per-resource and early in five places —
  the relay buffer on a keep-alive turnaround and inside `respond`, the
  upstream slot when parked, detached, and at reject. Three of those guard on
  the optional (`if (conn.x) |held|`) and two unwrap it outright, because
  their preconditions already guarantee it is held; either way the lifetime is
  the resource's own, not teardown's. A TLS engine adds one more such site,
  and kTLS returning it at handshake completion is already legal. Removed
  rather than left looking pending.

### Tier D — measurement readiness

| # | slice | ~ | what it buys |
|---|---|---|---|
| D1 | Tier-1 gate on achieved rate against offered — *landed* | 40 | the §9 gates check socket and status errors only, so a run delivering 704 of 2000 req/s passed them |
| D2 | A large-body band in the harness — *landed* | 80 | the record layer's per-byte cost is unmeasured, and the kTLS decision (Phase 3b) depends on that number |

**The first large-body numbers** (2026-07-26, defaults: 256 KiB per response,
400/s, 32 connections, one core for the proxy). Every path delivered the full
offer, so the band is a latency comparison at 100 MiB/s rather than a
throughput ceiling:

| path | p50 | p99 | hop cost (p50 over direct) |
|---|---|---|---|
| direct (nginx) | 632 µs | 1140 µs | — |
| zoxy L4 | 1344 µs | 2805 µs | +712 µs |
| zoxy L7 | 1430 µs | 2719 µs | +798 µs |
| haproxy tcp | 1245 µs | 2019 µs | +613 µs |
| haproxy http | 1268 µs | 2523 µs | +636 µs |

So a 256 KiB relay costs ~100–160 µs more through zoxy than through haproxy,
~15–25% on the hop — the first per-byte figure this project has, and the
baseline the Phase-3b kTLS argument has to beat. 100 MiB/s is what the *offer*
asked for, not a ceiling; raise `--large-rate` to find one.

The rate gate is verified by making it fail, not only by watching it pass: at
`--rate 200000` the bands read L4 105101 and L7 93430 against the 90% floor and
the run goes red, naming both numbers, while the direct baseline (199811 of
200000) passes — so the gate blames the proxy, not the origin.

**Found while landing these, and not caused by them:** the overload scenario's
stall gate (`read_errors + timeouts` under 1% of completed) fails on a
developer box — 7.7% on clean `main`, 11.4% with these bands added, both
reproducible. Deep queueing is the scenario's *point* (p50 36 ms, p99 484 ms,
max 1.1 s at 20k/s offered into 64 conn slots), and zrk's 2 s wire timeout
inevitably fires for a slice of that, so a 1% ceiling looks mis-specified for a
band deliberately driven past capacity. Filed rather than adjusted here:
weakening a gate as a side effect of adding one is how gates stop meaning
anything.

**What B4 landed, and why it is small.** The row budgeted 100 lines for a
source seam. Read against the code, the head loop already had the half that
mattered: `parseAndDispatch` is the single answer to what accumulated bytes
mean — read again, 400, 414, 431, or route. What the TLS branch actually
duplicated came from the two things `armHeadRecv` hardcoded (the read target,
and through it the completion callback) plus a 413-vs-431 decision it made
*before* dispatch by re-parsing. So B4 names the read target and the fill
accounting — the two a source replaces — and writes down the rule that an
overrun discovered while filling is answered *through* the dispatch rather
than beside it. Every other state the row implied (a fragment that yields
nothing, an overrun, head bytes already staged at entry) is unreachable until
a transforming source exists, so those variants land with TLS, where they will
have a caller rather than being dormant (§1).
**If that seam should be *proven* rather than documented**, the shape is B5's:
a toy head source behind a test-only selection. It costs materially more than
B5 did — the head path sits inside the L7 state machine (routing, dial,
render) rather than at a pump's edge, so the selection has to reach into
`Proxy` instead of being a policy handed to one `Pump`.

**Order.** Critical path to a small TLS slice: **A5 → A4 → B2 →
(B1 + B5) → B3 → B4**, with A1–A3 and Tier C as fill-in.

B1 and B5 are **one unit of done, delivered as two PRs merged back to
back** (settled 2026-07-25). The seam is what introduces a second, wire-side
cursor, and under identity there is nothing to check it against — that is
exactly what B2 could not stage (above). A toy transform cannot run *before*
the seam, since it *is* a policy on it, so the order is fixed: seam, then
proof.

Two diffs rather than one because each is separately reviewable — a seam
with identity defaults, where the existing L4 and L7 body tests passing
unchanged is the regression net, then a toy transform proving the wire
cursor is genuinely independent of the framed one, byte-exact under the
adversary with no crypto involved. The honest cost of splitting: between the
two merges the seam sits on `main` with its hooks unexercised and its
failure branches unreachable. That is bounded by treating B1 as **not done
until B5 lands** — B5 opens immediately, and no TLS transform hooks on until
both are in. Extend the toy transform to a `http` sim listener when B3 and
B4 land.

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
