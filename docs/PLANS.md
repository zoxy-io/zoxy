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
  **Requirement the ~45 ms stall imposes** (IMPLEMENTATION_NOTES.md):
  the server must emit its post-handshake flight — a NewSessionTicket —
  *after* processing the client's `Finished`, not alongside the server
  flight. Both are legal TLS 1.3; only the first carries the ACK that
  releases a Nagle-held client request, and without it every terminated
  connection pays a 40 ms delayed-ACK timer once. This is why resumption
  is not merely a latency nicety on this engine, and it is the whole of
  what separates zoxy's close-mode band from haproxy's.
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
`relay_buffers_max` at `(57344 − 23 − upstream_slots_max) / 4` at ⅞ fill;
that read 14074 while `upstream_slots_max` was 1024 and 12282 once it
rose to 8192 (below). Pinning the upstream ceiling to the conn ceiling
(2026-07-28) made it one divisor — `(57344 − 23) / (4 + 1)` = **11464**,
with `fds_max` **34408** (a c10k deployment raises the documented
`RLIMIT_NOFILE` at startup, §8). The arithmetic and its history live in
IMPLEMENTATION_NOTES.md.

The one remaining lever is **`splice`** (above) — an independent win at
saturation, still libxev-fork work (a re-audit); TLS and chunked L7
bodies fall back to copy regardless.

Entry gate for further ceiling work: demonstrate a workload that actually
saturates the *current* conn-slot ceiling first — the splice lever costs
a re-audit, not worth spending blind. Note what the c10k runs of
2026-07-27 did and did not show: they saturated the **upstream** pool
comprehensively (which is why its ceiling moved, and then why it was
pinned to the conn ceiling), and never came close to the conn-slot one,
sitting at ~10k held connections against 12282 — which was the point:
those 2200 spare slots were unservable, not spare.

## Pool ceilings: policy we chose, or a range the operator picks?

**Interim taken 2026-07-27, narrowed 2026-07-28; the question below
stays open.**

The ceiling pair first moved to `upstream_slots_max = 8192` /
`conn_slots_max = 12282`, which fixed the immediate defect — the upstream
pool had *no range*, default and ceiling being the same number. The next
c10k run showed that pair was still the wrong shape: leased upstreams
track the *connection* count, so a pool below the conn ceiling makes the
top of that ceiling unservable. The upstream ceiling is now **pinned** to
the conn ceiling, and the shared CQ line has one divisor rather than two
numbers that must be edited together: `conn_slots_max =
upstream_slots_max = 11464`. `upstream_slots_default` stays at 1024, so
the out-of-box footprint is still byte-identical (32,259 KiB, 3,805 fds).
Measurements in IMPLEMENTATION_NOTES.md.

It does **not** answer the question below — it narrows it. There is now
one number, not a pair, and §1's "able to operate at c10k" holds on both
axes at once. But a ceiling chosen at compile time is still a policy
decision made on the operator's behalf. What follows is why that may be
worth changing, and what it would cost.

One correction to the cost stated here originally: raising the ceilings
does **not** balloon `SimIo`'s `ready_buffer`. That array is sized by
`in_flight_ops_max`, which is already 57,343 against a 57,344 budget — it
is the budget, near enough. Define it *as* the budget rather than as the
ceilings' product and it does not move, and
`assert(in_flight_ops_max <= completion_queue_entries)` survives as a
stronger claim: the budget we enforce fits the ring, rather than one
chosen point does.

§1 says zoxy must be *able* to operate at c10k — not that it is tuned for
it. The two-layer shape that serves that goal already exists for conn
slots: a lean default the out-of-box deployment runs at, and a higher
ceiling the operator climbs to through `limits`.

As it stood before the interim fix:

    conn_slots_default      1386     ~32 MiB out of the box
    conn_slots_max         14074     operator opts up
    upstream_slots_default  1024
    upstream_slots_max      1024     <- same number: no range at all

Upstream slots had no such range. An operator could only go *down*, and
at c10k the upstream pool is precisely the one that needs to go up. Every
c10k run that behaved did so on a build-time `sed` of the constant. The
interim fix gave that pool a range (default 1024, ceiling 8192, and
`conn_slots_max` down to 12282 to pay for it on the shared CQ line); the
follow-up pinned the ceiling to `conn_slots_max` outright, which is the
shape it should have had from the start.

Summarised: at 1024 the pool pinned, a third of all responses became 503,
and real throughput decayed to a quarter of its peak; at 8192 sheds fell
by three orders of magnitude and throughput held flat, but a full c10k
run still drove the pool to its ceiling — 0.44% of responses shed with
~2200 conn slots idle. The figures live in IMPLEMENTATION_NOTES.md ("The
upstream pool was a wall, not a range" and "The upstream pool tracks
connections, not requests") — restating them here is what let this
section drift out of date once already.

### Why a better default does not fix it, and neither does a build option

The two ceilings share one completion-queue budget — a conn slot costs
`conn_ops_max` ring ops, an upstream slot one:

    conn_slots × 4 + upstream_slots + fixed <= 57344   (⅞ of a 65536 CQ)

They are points on a line, and pinning the pair picks the diagonal of
that line rather than getting off it. The diagonal is the right point for
an L7 deployment — that is what the measurement says — but **choosing any
point at compile time is tuning for a deployment shape**, which is the
thing §1 says not to do. An L4-only deployment, for one, wants no
upstream slots at all and would rather spend the whole budget on conn
slots. A build option only moves who does the tuning; and zoxy ships
prebuilt release binaries, so a build-time knob is invisible to anyone
who installs rather than compiles.

### The shape that follows

Let the ceilings be what the *types and the kernel* allow rather than a
policy point, and let the operator pick a feasible pair:

- `upstream_slots_max` -> `maxInt(u16)` (the per-endpoint `leased_counts`
  width, already asserted), `conn_slots_max` likewise bounded by its own
  u16 slot index — independently, not against each other.
- The operator names both in `limits`; `cqFillFits` rejects an infeasible
  pair at config load. That guard already exists and already runs
  unconditionally (`LimitConnSlotsOverCqFill`), so nothing new enforces
  anything — it stops being shadowed by a comptime pre-decision.

### The §5 amendment this requires — the actual decision

`assert(in_flight_ops_max <= completion_queue_entries)` states a property
of *the chosen point*. With independent ceilings there is no chosen point
and the assertion is simply false, so it goes. §5's "the memory, fd and
ring budgets are closed-form functions of those constants,
comptime-asserted" becomes:

> comptime-asserted where a budget is a property of one constant;
> **rejected at startup** where it is a property of a *combination*.

That is the whole cost, and it is a real narrowing of a stated invariant.
What argues for paying it: the surviving check is about the configuration
actually running rather than one nobody deploys, it cannot be skipped
(the loader calls it on every start), and zoxy already refuses to start
on an inadequate `RLIMIT_NOFILE` — the same failure mode, applied to the
ring. What argues against: a compile error is unmissable, a startup
refusal is merely loud.

Everything else in §5 stays comptime: ring power-of-two, CQ within the
kernel maximum, the u16 index widths, the watermark relationships, and
`memoryBytesTotal`'s closed form.

### Known cost beyond the amendment

Nothing further, once `in_flight_ops_max` is defined as the budget (see
the correction above). `SimIo` sizes a **stack** array from it —
`var ready_buffer: [pending_ops_max]*Completion`, ~448 KB — and that is
already the budget's size, so it neither grows nor needs moving to the
arena. Production pools were never affected either: they allocate from
the *effective* config (`conns.init(arena, options.conn_slots)`), so a
ceiling drives no allocation at all.

### Entry gate

Take the decision before the code. If the answer is "ship a c10k-shaped
default instead", that is one constant and no amendment — but it makes
the lean out-of-box footprint worse for the deployments that are not
c10k, which is most of them. The question to settle is whether one binary
should span a few hundred connections through ten thousand *by
configuration*; if yes, the amendment is the price and the machinery is
already built.

## libxev fork queue

The §4 pin policy (audited commit, moves only after re-audit) makes fork
changes deliberate, batched work — `Options.io_uring_flags` (the §4 ring
setup flags) and `Options.cq_entries` (the c10k CQSIZE lever, #61) landed
this way. Known queue, in rough value order:

1. ~~Per-errno surfacing on data ops.~~ **Landed 2026-07-27**
   (zoxy-io/libxev#2, pin b3d6b55). Solved by *keeping* the errno rather
   than widening the error sets: `Completion.result_errno`, recorded at
   the top of `invoke` before the per-operation mapping discards it. No
   error set, result or control-flow change, so nothing downstream had to
   adapt. zoxy consumes it as the per-cause half of the kernel-pressure
   split (§8); the categorical witness is now two partitions of one total
   plus a raw-errno gauge. It paid for itself on its first run: 172
   "kernel pressure" events turned out to be EPIPE — clients leaving
   mid-write, miscounted because zoxy's own send adapter left
   `BrokenPipe` unnamed.
2. `IORING_OP_SPLICE` (the op union is closed today).
3. Name the two peer-gone errnos still funneled to `error.Unexpected`
   (#106, the bug-5 shape): ENETUNREACH on connect (a routing failure,
   counted today as §8 dial pressure with only the errno gauge to say
   otherwise) and ETIMEDOUT on the data ops (a retransmission-timeout
   peer-gone verdict, same mislabel). One named error each in the fork's
   connect/read/write maps lets XevIo map them portably — Unreachable
   and Reset — the exact fix the EPIPE collapse got in-tree, blocked at
   the fork boundary for these two because a switch may only name error
   members that exist. Cheap, zero-behavior-change for every other arm;
   batch with the next pin move. The contract-test decision table
   (src/io/contract_test.zig) tracks which arms gain real-socket tests
   once named.
4. Multishot accept/recv ops — only behind the workloads in the verdict
   table above. **The recv precondition is now met**: a 10k-connection
   run holds ~20k req/s at 0.8–0.9 of a 1-CPU quota with ~87% of it
   kernel time and the first non-zero CFS throttling, which is the
   "recv-submission-bound workload (many mostly-idle connections)" the
   parked verdict names. The 2–4% figure that parked it was measured on
   a best-case echo microbench, never against this. Measure before
   designing — two optimization priors were refuted by measurement the
   same day (see IMPLEMENTATION_NOTES.md).

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
- **Kernel socket buffers inside the §5 budget** — set
  `SO_RCVBUF`/`SO_SNDBUF` on each listener (accepted sockets inherit
  them, so it costs one `setsockopt` at bind) so the per-socket cap is a
  named constant like every other limit. Today the printed total omits
  memory larger than the pools it does count
  (IMPLEMENTATION_NOTES.md). Not deferred for lack of value — the
  measurement is done and the mechanism is trivial — but because the
  right *default* needs a deployment to size it against: fixing the
  buffer disables receive autotuning, which is free on a LAN and caps
  BDP-limited throughput across a WAN. Revisit with the first
  deployment that has a real network to size against, or sooner if
  `tcp_mem` pressure is ever observed.
- **`somaxconn` clamp check at startup** — the listen backlog asks for
  `accept_backlog` and the kernel silently clamps it to `somaxconn`. The
  fd budget is already asserted against `RLIMIT_NOFILE` at startup (§8);
  this deserves the same treatment rather than a silent downgrade.
- **`TCP_DEFER_ACCEPT` on http listeners** — a connection that never
  sends data then costs no conn slot or relay buffer (§7 names the
  slowloris shape; §8 is why holding no slot is the point).
  Must be per-protocol: it would break an `l4` listener fronting an
  origin that speaks first.
