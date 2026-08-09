# zoxy — bullet-proof L4/L7 proxy

An L4/L7 proxy in Zig 0.16 in the spirit of Cloudflare's Pingora, with two
hard constraints: **nothing allocates on the hot path** and **exhaustion
sheds load — it never crashes, never queues unboundedly, never allocates.**
Steady-state operation issues zero heap allocations and zero allocating
syscalls; zoxy's own memory is a startup-time function of the static
limits (the kernel's per-socket buffers are outside that form — §5).

Simplicity is prioritized over feature-richness. The coding rules live in
[`docs/TIGER_STYLE.md`](TIGER_STYLE.md). The previous iteration of this
project ([zoxy-io/zoxy@main](https://github.com/zoxy-io/zoxy)) shipped an
L7-only, share-nothing, thread-per-core proxy directly on `io_uring`; its
measured lessons — paid for with implementation time and simulator seeds —
are folded into the relevant sections below as constraints, not
suggestions, and its dead ends are not revisited.

This document is the settled design — what is shipped and how it works.
Planned features are tracked as GitHub issues; measured findings, shelved
experiments, and open technical questions live in
[`IMPLEMENTATION_NOTES.md`](IMPLEMENTATION_NOTES.md).

---

## 1. Goals and non-goals

Goals, in priority order:

1. **Bullet-proof.** No crash, no OOM, no unbounded queue — ever. Every
   resource has a static limit; hitting a limit sheds load at a well-defined
   point with a well-defined answer (§8).
2. **Zero allocation after startup.** All memory is reserved at `init`;
   the serving path allocates nothing. Enforced by a test-time gate, not
   aspired to.
3. **Minimal memory consumption.** Pools are *shared*, sized for concurrent
   *activity*, not for open-connection worst cases multiplied by core count
   (§5). Pool memory is a closed-form function of `src/constants.zig`
   (kernel socket buffers are outside it — §5).
4. **Simplicity.** One thread, one event loop, one ring, one writer for
   every pool — no worker threads, no cross-thread queues (§3). Fewer
   moving parts than the previous iteration, not more.
5. **L4 (TCP relay) and L7 (HTTP/1.1 reverse proxy)** serving, with
   keep-alive and shared upstream connection reuse.

Non-goals (deliberate, recorded so they are decisions rather than drift):

- HTTP/2, HTTP/3, gRPC, WebSocket — deferred until the L4/L7 core is proven.
- Feature parity with Envoy/NGINX. Pingora's lesson is that a small, sharp
  proxy core beats a configurable monolith.
- Caching, compression, request transformation.
- Windows/macOS *production* support. Production is Linux + `io_uring`;
  libxev's kqueue backend keeps macOS usable as a dev box only.
- Multi-process orchestration, xDS, hot restart — until operability demands
  them (the previous iteration's Phase-4 machinery is a known-good recipe
  when they do).
- **In-process worker threads and cross-thread job queues.** The design
  reserved a CPU-worker seam for TLS handshakes; measurement retired it
  (§3, settled 2026-07-25) and it is deleted, not dormant. The binary is
  single-threaded and CPU scale-out is process-per-core behind
  SO_REUSEPORT. Re-adding threads is a from-scratch decision behind a
  measured gate, not un-commenting a seam.
- Config reload. Config is parse-once immutable (§5); a change is a
  process restart — consistent with process-per-port scale-out (§3). Hot
  restart / drain-to-successor is out of scope for the same reason.
  SIGHUP is therefore free for the conventional log-rotation meaning and
  carries only that (§8): reopen the access log's file sink.
- Dynamic DNS for upstreams. Cluster endpoints are static socket
  addresses resolved once at config load (§7); re-resolution waits for a
  demonstrated need.

## 3. Topology — one thread, one loop, one ring, shared pools

The user-visible promise: *one thread owns one io_uring and every pool;
nothing else runs.*

```mermaid
flowchart LR
    subgraph loop_thread [the only thread - owns all I/O and all pools]
        A[accept gate] --> L[libxev loop on one io_uring]
        L <--> P[shared pools: conn slots, relay buffers, upstream conns]
        L <--> T[per-connection deadline timers - absolute]
    end
    C[clients] --> A
    L --> O[origin servers]
```

**The decision.** One event-loop thread owns the single `io_uring` (via
libxev) and performs *all* socket I/O — accepts, recvs, sends, connects,
timers — and *all* CPU work, TLS handshakes included. There are no other
threads: no worker pool, no job queue, no cross-thread completion rings.
The design reserved that seam for TLS handshakes on a ~1–2 ms
per-handshake estimate; that was an RSA number, so RSA server certs are
excluded by policy (ECDSA only) and measurement retired the seam
(settled 2026-07-25, IMPLEMENTATION_NOTES.md): a full ECDSA handshake is
~100–400 µs of asymmetric crypto, and a terminated L7-over-TLS hop
measured at HAProxy parity on steady-state keep-alive load — ~20k req/s,
p50 110–122 µs against its 101–105 µs, one core each, same fixture
certificate and origin. Handshake-heavy load has a lower ceiling that is
measurably *not* a CPU wall: it scales with connection count, so what
binds is a per-connection stall — since identified as a Nagle/delayed-ACK
deadlock, fix pending (IMPLEMENTATION_NOTES.md) — which no amount of
threading would remove. Where handshake CPU does eventually bind, the
levers are session resumption (µs-class for returning clients) and then
more cores — which this design buys as **N independent processes behind
SO_REUSEPORT**, never as threads sharing pool memory. Single-threaded is
a property of the design, not a phase of it; should a workload ever
demand in-process parallelism, that re-entry is a from-scratch decision,
not a resumed one.

<details>
  <summary><b>Why this is the simplest topology that satisfies the goals</b></summary>

- **Zero-alloc and single-writer become structural.** Only the loop thread
  acquires and releases pool slots, so pools need no locks, no atomics, no
  cache-line padding on the data path — plain code. The previous iteration
  spent a hardware-counter investigation earning this property; here it
  holds by construction — there is no second thread that could violate it.
- **Minimal memory.** One shared pool sized for the global limit replaces
  N per-core pools each sized for a local worst case. Idle keep-alive
  connections hold a slot — no relay buffers, no head buffer (§5) —
  memory follows *activity*, not connection count.
- **Perfect connection reuse.** Pingora's headline win over NGINX was
  sharing upstream connections across all threads; the previous iteration
  measured this as its single biggest performance lever (~3× req/s), which
  is why the upstream pool here is first-class, not an add-on (§7). With one
  loop, every upstream connection is visible to every request — maximal
  reuse with zero synchronization, better than work-stealing can do.
- **No accept balancing.** One accepting loop distributes nothing, so the
  SO_REUSEPORT small-sample imbalance that plagued the previous iteration
  (hottest worker 23% of connections; H2 made shared accepts mandatory)
  cannot exist.
- **Load shedding has one choke point.** Every admission decision happens
  on one thread with a consistent view of every pool — no cross-worker
  budget splitting, no per-worker limits that sum to surprising totals.

**Why one core is enough (back of the envelope).** A proxy is
network-bound. A relay copies each byte twice through userspace
(recv + send); at 10 GbE line rate (~1.25 GB/s) that is ~2.5 GB/s of memory
traffic against tens of GB/s of per-core bandwidth. At 100 k req/s a
request costs ~4–6 ring ops → ~500 k SQE/s, well inside a single ring's
capability, batched one submit per loop tick. The previous iteration
measured itself latency-bound with CPU headroom on the data path; the
only CPU-heavy work is the TLS handshake, measured at ~100–400 µs of
crypto with ECDSA certs and at HAProxy parity through the whole
terminated hop in steady state (IMPLEMENTATION_NOTES.md, which also
records the per-connection handshake stall that is *not* CPU — mechanism
identified, fix pending). The loop absorbs it in steps between completions, and the
worst single uninterruptible step — ~275 µs of P-256 sign — is what
bounds tick inflation. **Horizontal
scaling is N independent zoxy processes behind SO_REUSEPORT** —
share-nothing at the process boundary, where the kernel actually
isolates — not N loops, and not N worker threads, in one process.

**Why not one ring per worker.** Ring-per-worker with *shared* pools is the
hybrid to avoid: the moment several ring-owning threads acquire/release pool
slots, every pool op needs atomics or locks and the pool headers/free lists
become multi-writer cache lines — the previous iteration measured that exact
class at ~50–60× HITM snoop amplification *within a single socket*. Pingora
pays this cost with Rust async and mutex-guarded pools; in a zero-alloc,
assertion-dense Zig codebase the two coherent designs are
share-nothing-per-core (previous iteration — multiplies memory by core
count) or single-writer-shared (this one). Ring-per-worker also re-imports
the accept-balancing problem, splits shedding budgets per worker (the
previous iteration documented "budget = configured × worker count" as a
wart), and — decisively for §9 — makes execution nondeterministic, demoting
the simulator from replayable proof to stress test.

**NUMA.** A single pinned loop deliberately does not scale across sockets —
scale-out is **process-per-NUMA-node**: N independent zoxy processes, each
pinned to a node with pools faulted node-local, sharing the port via
SO_REUSEPORT (optionally eBPF/`SO_INCOMING_CPU` steering and NIC IRQ
affinity to the same node). That is the *best-case* NUMA topology — zero
cross-node cache traffic, kernel-level fault isolation — whereas in-process
ring-per-worker over shared pools is the *worst* case: pool memory homed on
one node, remote writers paying cross-node HITM on every hot-path op. The
honest cost: upstream connection reuse becomes per-process rather than
global. It stays maximal within each process, and single-node deployments —
the common case — keep the fully global reuse win.

**Why no CPU worker threads.** This section used to specify a worker
seam: one bounded SPMC job queue, per-worker SPSC completion rings, an
`xev.Async` wake, and the parked-slot ownership rules that went with it
in §5. It existed for exactly one workload — TLS handshakes — and the
TLS handshake measurements (above) took that workload away, so the seam
is **deleted, not kept dormant.** A dormant design is not free: it leaves
ownership rules in §5, a rung in §8, and a module in §10 that no code
exercises and no gate proves, and every later change has to stay
compatible with a mechanism that may never exist. What replaces it is
policy: the binary has one thread, and CPU scale-out is process-per-core
(above). The honest cost is that a sustained handshake storm cannot
borrow an idle core in-process — the answers there are resumption first,
more processes second, and neither needs a shared-memory concurrency
model. The retired trade study (one shared queue vs per-worker queues vs
work stealing, and why stealing solves a problem this design does not
have) is in git history; re-adding threads means re-deriving it against
the measurement that retired it (above).

</details>

## 4. I/O — libxev behind a thin seam

[libxev](https://github.com/mitchellh/libxev) is a proactor: work is
submitted, completions are called back — the same shape as the previous
iteration's hand-rolled TigerBeetle pattern, and the same shape as
`io_uring` itself.

**Dependency policy: Zig-first, with a scoped C exception for proven
crypto primitives.** The TIGER_STYLE zero-dependency rule takes its
recorded exceptions here, all vendored by content hash in `build.zig.zon`
as zoxy-io forks: **libxev** (this section), **hparse** (the HTTP/1.1 head
parser — as a hardened fork, §7), and **ztls** (the TLS 1.3 engine, below).
libxev and hparse are pure Zig. ztls carries the codebase's one C surface,
and takes the deliberate decision this section reserved: **battle-tested C
crypto *primitive* libraries — the libcrypto family (OpenSSL / AWS-LC /
BoringSSL) — are acceptable dependencies.** The trust split runs the right
way round: constant-time primitives want the most-watched assembly on
earth, while the protocol state machine — where TLS CVEs actually live —
stays auditable Zig behind our own wrapper.

The scope is strict. Primitives only, never a C *protocol* layer (libssl
and picotls stay out). The C binding lives inside the dependency, so
zoxy's own tree never names a C symbol and `@cImport` stays lint-forbidden
(§9) — a second C surface opened here would not be behind anyone's audited
Zig. libcrypto's internal allocations are routed to a fixed startup arena
(`CRYPTO_set_mem_functions`) so §5's zero-allocation gate keeps its teeth.
And the pinned hash is an *audited commit*, never a branch tip — libxev's
Zig 0.16 support is a self-described compatibility shim (PR #220) with
real fixes still unmerged behind it — so a pin moves only after re-audit;
for ztls that audit means the Zig protocol layer read line by line, the C
primitives trusted institutionally.

- **Caller-owned completions.** Every `xev.Completion` is embedded inline
  in the connection slot; submitting an op writes it in place. Zero
  per-operation allocation — verified property of libxev's io_uring
  backend, and the reason it fits this project at all.
- **Ring sizing is explicit.** `ring_entries` — the SQ — lives in
  `src/constants.zig` (libxev caps entries at 8191, requires a power of
  two). The completion queue is sized *independently* of the SQ through
  the audited fork's `IORING_SETUP_CQSIZE` option (`Options.cq_entries`),
  so it is not tied to the kernel's default 2 × SQ. XevIo requests
  `completionQueueDepthFor` of the *effective* config — a shallow ring
  for a small deployment, up to the kernel maximum (65536) at the c10k
  ceiling — which is exactly what decouples the concurrent-connection
  ceiling from the submission-queue depth (§5, §8). When the kernel SQ is
  full, libxev parks submissions in an intrusive userspace list bounded by
  in-flight completions — which live in pool slots — so the
  no-unbounded-queue rule holds by construction. The in-flight op budget
  that keeps CQ overflow unreachable is part of the startup printout (§8).
  How much of that CQ the in-flight ops may fill is ⅞ by default
  (`cq_fill_eighths_default` — the fill the c10k ceiling is derived at);
  `limits.cq_fill_eighths` lowers it per deployment toward ⅛ to reserve
  more burst headroom, at a lower feasible connection ceiling (§5).
- **Ring setup flags.** The ring is created with `SINGLE_ISSUER`,
  `COOP_TASKRUN`, and `DEFER_TASKRUN`: completion task-work stays on
  the loop thread and is batched at the reap point instead of
  interrupting it. Sound by construction here — the loop thread is the
  only submitter (§3), and the loop always enters the kernel waiting
  (GETEVENTS), which is where deferred task-work is flushed. Kernels
  older than 6.1 reject the flags with EINVAL; startup degrades to a
  plain ring rather than refuse to start. (Measured win:
  `IMPLEMENTATION_NOTES.md`.)
- **Backend selection.** Production: `io_uring` (Linux ≥ 5.11). Dev box:
  kqueue (macOS) — same API, same callbacks, so day-to-day development
  does not need a VM. Correctness claims are only made for Linux.
- **Our own `Io` seam on top, not `std.Io`.** The data path never names
  `xev` directly; it calls `src/io/io.zig`, a comptime-selected facade with
  two backends: `XevIo` (production) and `SimIo` (deterministic
  simulation — virtual sockets, virtual clock, seeded adversarial
  scheduler, §9). The Zig 0.16 std landscape still rules out building this
  on `std.Io` directly — `std.Io.Threaded` allocates per task, the
  evented executor has stubbed networking and offers only work-stealing
  scheduling, and `std.crypto.tls` is client-only — each re-verified
  against the pinned toolchain, not assumed from the previous iteration.
  The seam is thin — accept/recv/send/connect/shutdown/close/timer/async/
  signal, caller-owned completions — deliberately mirroring xev so it
  costs nothing in production. `signal` is how SIGTERM reaches the loop: a
  `sigaction` handler does an async-signal-safe wake (`xev.Async.notify`,
  an eventfd write) and the loop's callback starts the drain (§8) —
  never `loop.stop()`, which does not wake a blocked loop from another
  thread (libxev #173). `SimIo` delivers drain as just another scheduled
  event.
- **The data path never sees a file descriptor.** The seam hands out an
  opaque `Io.Socket` handle; the fd itself never leaves `src/io/`, so a
  direct data syscall from the data path is unrepresentable. This
  matters because libxev's io_uring backend deliberately keeps sockets
  *blocking* (non-blocking fds risk EAGAIN surfacing in completions) —
  a "quick" direct `write` could stall the whole loop. That choice is
  kept: O_NONBLOCK is never set. The control ops the design needs are
  seam methods instead — `setNodelay`, `setLingerRst` (§8's
  accept-and-RST), `shutdown(.both)` (which must bypass
  `xev.TCP.shutdown`, hardcoded to SHUT_WR, for the low-level op) —
  direct non-blocking syscalls in `XevIo`, virtual-socket state changes
  in `SimIo`, so the simulator can witness RST-on-shed and half-close
  (§9). A build-time lint enforces the boundary (§9).
- **TCP_NODELAY always.** Set on every socket via `setNodelay`, no
  config knob. Nagle's algorithm plus delayed ACK cost a warm pooled
  connection a hard 40 ms stall — invisible on a connection's first
  request, measured repeatedly on reused ones in the previous iteration.
- **Run to completion.** Callbacks never suspend (TigerStyle: assertions
  hold across the whole body). Completions are drained in bounded batches
  per loop tick; a callback may enqueue more work but never runs another
  callback inline.
- **Clock.** `Io.now_ns` is refreshed once per loop tick (the previous
  iteration measured per-callback `clock_gettime` at ~3% of data-path CPU)
  and is the seam the simulator's virtual clock replaces. The refresh
  reads the *coarse* monotonic clock — every consumer is a second-scale
  deadline, and the precise read was measured at ~7% of on-CPU
  (`IMPLEMENTATION_NOTES.md`). Anything
  computed from it may be stale by up to one tick's completion batch —
  deadline logic must stay correct under that bound, and the simulator
  makes the staleness adversarial (§9).
- **Deadlines.** One timer per connection holding an *absolute* deadline.
  A state transition only *stores* the new deadline value — the armed op
  is never touched. When the timer fires, the callback compares the
  stored deadline against `Io.now_ns`: not yet due → re-arm for the
  remainder with a fresh submit (libxev's `.rearm` return reuses the
  stale absolute time and is never used); due → the deadline action.
  A timer is canceled in exactly **two** places: teardown (§5 release
  rule) and an L7 dial that re-bases the head-read deadline *down* to the
  tighter connect budget (§8) — the lazy rule moves a deadline later for
  free but must cancel+re-arm to move it earlier. Both drain race-free:
  the cancel op and the timer's own Canceled both land, whichever is last
  re-arms at the stored target, and a teardown that overtakes an in-flight
  re-base drains it through the same `isTearingDown` checks.
  libxev cancellation is internally cancel+resubmit and consumes its own
  caller-owned completion, embedded in the slot like every other op.
- **Three seam ops exist for the access log** (§8) and for nothing else.
  `logWrite` puts the sink on the ring like every other write, so a log
  reader that stalls cannot stall the loop. `peerAddress` is asked once
  per admitted connection rather than at log time, when the socket may
  already be closed and the fd number reused. `nowWallNs` is a *second*
  clock: precise and uncached, where `now_ns` is coarse and refreshed once
  per tick. Both of those properties are wrong for a log — a line needs a
  date, which a monotonic clock cannot give, and a duration measured
  against the tick would read 0 µs for every request served inside one
  completion batch. It costs two vDSO reads per logged request, against
  `now_ns`'s one per tick, and only when a deployment turns the log on.
- **Plain ops only.** Multishot accept/recv, `send_zc`, `splice` stay
  behind measurement — the previous iteration never became CPU-bound
  without them, and this one is latency-bound with CPU headroom. Each
  has since been evaluated; verdicts, revisit conditions, and the
  measurements behind them live in
  [`IMPLEMENTATION_NOTES.md`](IMPLEMENTATION_NOTES.md). One graduation:
  single-shot buffer-select — the buffer-ring mechanism without
  multishot — carries the seam's `recvGroup` (§5's head-buffer ring),
  adopted 2026-08-01 for density rather than throughput; the notes
  record why that does not reopen the multishot closure. Every
  completion still disarms.

## 5. Memory — shared pools, fixed at startup

Every limit is a named constant in `src/constants.zig`; **zoxy's own**
memory is a closed-form function of those numbers, printed at startup.

That qualifier is load-bearing. The closed form covers what this process
allocates — the pools below, and the startup arena. It does **not** cover
the kernel's per-socket buffers, which are charged to the connection and
scale with it: on a stock Linux the defaults are 144 KiB per socket and
an L7 connection holds two, so a deployment sized at the printed default
carries an order of magnitude more socket memory than the budget names,
growing further under receive autotuning. The failure mode
is not OOM but `tcp_mem` pressure, where the kernel starts collapsing
queues — invisible to this budget, and with no counter of ours on it.
Closing that gap means setting `SO_RCVBUF`/`SO_SNDBUF` explicitly so the
per-socket cap becomes a named constant like everything else; the
measurement, the autotuning trade-off, and the revisit condition are in
[`IMPLEMENTATION_NOTES.md`](IMPLEMENTATION_NOTES.md). Per-worker
reservation — sizing a pool per core for a worst case that never co-occurs
on every core at once — multiplies memory by core count for nothing; the
previous iteration paid that cost, and shared pools sized for concurrent
*activity* rather than worst-case-per-core are the fix and the reason this
iteration exists.

Three shared pools and one kernel-fronted ring, all owned and touched
only by the loop thread:

1. **Connection slots — `Pool(Conn)`.** One contiguous object per
   connection: state machine, embedded completions (one per overlappable
   op — the previous iteration grew a field per proven race — including
   the timer-cancel completion, §4), and the deadline timer. Acquired at
   accept, released at teardown once the slot's armed-op set is empty
   (release rule below). Intrusive free list, LIFO reuse for cache
   warmth.
2. **Relay buffers — `Pool(RelayBuffer)`.** The large per-direction
   buffers for body/stream relaying, *decoupled from connection slots*.
   L7: acquired when a relay starts, **released when the connection goes
   idle on keep-alive** — an idle connection costs a slot only. L4:
   acquired at accept, held for the connection's life (a relay recv must
   always have a buffer posted). This decoupling is where shared pools
   buy their memory win: buffers are sized for concurrent *relays*, not
   for open connections.
2b. **Head buffers — the provided-buffer ring (`limits.head_buffers`).**
   The L7 request/response head buffers, decoupled from connection slots
   by the same argument as the relay buffers — but where a relay recv
   must carry a buffer, a head recv need not: the seam's `recvGroup`
   (§4, single-shot buffer-select) arms with *no* buffer, and the kernel
   binds one from the registered ring only when the client actually
   speaks. Bound at the first byte of a request, returned at the
   keep-alive turnaround, before a static response goes out, at
   teardown — and, the one held-through-a-send case, after a #176
   redirect delivers: its response renders *into* the buffer (the
   Location may carry the request's own path), so the buffer goes back
   in the write continuation instead of before the arm — so an idle
   connection holds no head bytes at all, an L4
   connection never binds one, and the ring is sized for concurrent
   *request heads*, not for open connections. Returning a buffer is a
   tail bump, no syscall. The ring empty at a client's first byte is the
   `l7_shed_head_buffers` rung (§8) — the one shed that always closes,
   because the bytes it refused are still unread in the socket. The
   server owns the in-use accounting (the kernel cannot report it) and
   the lingering-close drain discards into one shared sink, aliasing on
   purpose: recv targets nobody reads may.
3. **Upstream connections — `Pool(Upstream)` + per-endpoint idle lists.**
   Checked out by any request, parked on keep-alive, one shared pool for
   the whole process (§3: the Pingora reuse win). The slot carries ~48 B
   of scalars; its head buffer — the request-head render target and
   response-head accumulator — lives in its own pool
   (`limits.upstream_head_buffers`), acquired with the slot and released
   before the slot parks, so a parked origin connection holds a socket
   and scalars, never 8 KiB of head. App-side `Pool(HeadBuffer)` rather
   than the seam's kernel ring, because its first use is synchronous: a
   render needs the bytes now, and a kernel-selected buffer only arrives
   with a delivery. Exhaustion is the `l7_shed_upstream_head_buffers`
   rung, with the ordinary keep-or-close rules — unlike the client ring,
   this request was fully read. **A parked upstream has
   no armed op** — deliberately no per-connection poll, which would cost
   an in-flight op per idle upstream in the ring budget (§8) for a race
   that is already covered: the parked connection's deadline timer serves
   as an idle timeout (kept below typical origin keep-alive windows, so
   most origin-side closes are pre-empted), a close that slips through is
   detected at checkout and absorbed by the stale-replay rung (§7), and
   active health checks (§7) close the parked connections of an endpoint
   at its ejection — a parked socket to a dead origin is a stale replay
   waiting to be spent.

Defaults shape. **A working config is a listener and a cluster.** Every
other block — `timeouts`, `limits`, `access_log` — is optional, and so is
every field inside them, so tuning is what an operator opts into rather
than what they must supply to start. The rule for whether a field gets a
default is what zoxy can honestly answer: `connect_ms` and `idle_ms` have
conventional figures to borrow (nginx ships 60 s and 75 s for the same
budgets), so they default; `request_ms` is a policy set against a
particular origin's latency, so it defaults *off* rather than to a guess.
`drain_deadline_ms` is the interesting one — nginx, HAProxy and Caddy all
wait indefinitely by default, Traefik picks 10 s and Envoy 600 s, and a
sixty-fold spread across mature implementations is not a consensus
waiting to be found. It defaults to `0`, "no cap", and the supervisor
that sent the signal keeps the upper bound it already enforces with
`SIGKILL`. Where a zero would break rather than disable — a 0 ms dial,
idle, or probe interval — it stays rejected.

One *ordering* is enforced alongside those zeroes, and it is the only
cross-check between two configured values in the loader: `connect_ms`
must sit strictly below `idle_ms`. A connection's first deadline is
armed at the dial budget and the dial's completion re-stores it to the
idle one, but the single lazy timer never moves *earlier* once armed
(§4) — only the stored target does. So the reverse order does not
shorten at the handoff: the idle window waits out the connect-phase
timer still counting down and fires late, by up to
`connect_ms - idle_ms`. Rejected at load, not clamped (the same choice
the `limits` block makes): a clamp would answer a config zoxy cannot
honor with a log line, and one this proxy will not honor should not
start. The relation holds however a config was built — the loader
rejects it, `Server.init` asserts it, and `constants` asserts it of the
defaults the loader hands back when the block is absent.

Sizing shape. The comptime constants are the hard, budget-asserted
*ceilings*; the config `limits` block sizes the *effective* pools anywhere
from 1 up to them. An omitted block takes the lean **defaults**, so the
out-of-box footprint is small (~33 MiB) and an operator opts into more
concurrency — up to the c10k ceiling — through `limits`, never a rebuild.
The fd budget and the requested CQ depth track the effective sizes too
(§4/§8), so a small deployment neither reserves nor demands the ceiling's
resources; only a deployment that configures up toward the ceiling needs
a raised `RLIMIT_NOFILE`:

| pool | default | ceiling (c10k) | unit size |
|---|---|---|---|
| conn slots | 1386 | 11466 | ~1.7 KiB state |
| relay buffers | 1386 | 11466 | 2 × 4 KiB |
| upstream slots | 1311 | 11466 | ~48 B state |
| head buffers (ring) | = conn slots | 11466 | `head_buffer_bytes` + 1 B |
| upstream head buffers | = upstream slots | 11466 | `head_buffer_bytes` + 24 B |
| **pool memory** | **~34 MiB** | **~288 MiB** | |

`head_buffer_bytes` defaults to 8 KiB and is the largest head accepted
(oversize → 414/431, §7), with a 1 KiB floor and a 1 MiB ceiling: a size
knob is operator-visible behaviour, not only memory. Three head-sized
side buffers ride the same knob — the serving path's two
canonicalization scratches and the health prober's response buffer — and
appear in the banner as their own term.

The access log (§8) adds one fixed reservation beside the pools — two
staging buffers, 64 KiB together by default — and nothing at all when it
is off. It is in the printed total, because §5's promise is that the
total covers everything this process holds for its life, not only what is
shaped like a pool. Roughly half a kilobyte of the conn-slot state above
is its per-request capture: the method, host and path a line reports live
in the head buffer, which the response head renders over (§7) and the
turnaround returns to the ring, so they have to be copied out while they
are still there.

The labeled metrics (§8, #179) add one more reservation on the same
promise: the per-endpoint counter tables with their prebuilt label
strings, and the two render staging buffers — the admin scrape response
and the SIGUSR1 dump. The buffers stopped being comptime constants when
the exposition gained labels: the rendered text's length depends on
endpoint count, cluster-name length and address literals, none known
before config load. The term stays closed-form — `Server.metricsBytes`
prices the same labels `init` builds, through the same renderer, so the
banner's prediction is met exactly — and it is deliberately its own
line: the cost of labelling your metrics sits next to everything else
you pay for.

The config arena is in that total for the same reason — it is never
freed — but it is the one term that is **measured rather than derived**,
and the banner labels it so. There is no constant bounding a config
file's size: what the operator writes is what it costs, so the only
honest thing the budget can do is report it. Every other term is still
closed-form in `src/constants.zig`.

The ceilings sit on one completion-queue line — a conn slot costs
`conn_ops_max` ring ops, an upstream slot one — and the upstream ceiling
is **pinned to the conn ceiling**, so that line has a single divisor:
`conn_ops_max + 1` ring ops per admitted connection, 11466 of them. On
the L7 path a connection that is mid-exchange holds an upstream slot as
well as its conn slot, and at saturation every admitted connection can be
mid-exchange at once — so an upstream ceiling below the conn ceiling is
admission capacity that cannot be served, and one above it is a pool that
can never be drawn down. Both clear 10k, which is what §1 asks for: c10k
*reachable*, not a shape tuned for it.

The two moved apart twice before they were pinned: upstream slots were
1024 at both default and ceiling until 2026-07-27, which made that pool
the one thing an operator could only shrink, and then 8192 against a conn
ceiling of 12282, which left ~2200 conn slots idle while the pool they
depend on pinned. Both measurements are in IMPLEMENTATION_NOTES.md.
Whether the ceiling should be ours to choose at all is an open question,
recorded there.

The *defaults* are not pinned to each other, and deliberately: the
out-of-box shape is bounded by the stock 4096 `RLIMIT_NOFILE` rather than
by admission (matching 1386 would cost 4168 fds), so the upstream default
sits at 1311 — the largest value that still stays strictly under that
line with the access log's possible file sink counted (§8; naming a log
file is not tuning, so the lean promise holds with one) — rather than at
the conn default. An L4 deployment never touches
the upstream pool at all — an L4 dial holds no upstream slot. A
deployment that means to fill its conn pool raises both together through
`limits`.

Rules:

- **Pools never grow.** Exhaustion is a shed signal (§8), never a realloc.
- **Limit relationships are comptime-asserted where they can be** in
  `src/constants.zig` (TIGER_STYLE): e.g. `relay_buffers_max ≤
  conn_slots_max`, and the same for the defaults. Note that
  `relay_buffers` — not conn slots — is the true bound on concurrent L4
  connections plus active L7 relays (§6).

  "Where they can be" is a real qualifier, not hedging. A budget that is
  a property of one constant is asserted at build time. A budget that is
  a property of a *combination the config chooses* has no compile-time
  point to assert — there is no listener, cluster or endpoint ceiling to
  evaluate it at — so it is refused at load instead: `cqFillFits` for the
  ring (`LimitConnSlotsOverCqFill`) and `ensureFdBudget` for the fds.
  Same arithmetic, refused milliseconds later. The compiled ceilings
  `conn_slots_max`/`upstream_slots_max` are therefore stated at *zero*
  configured listeners, and each listener a config declares spends from
  the same budget.
- **The CQ fill is a headroom knob, not a pool shrink.**
  `limits.cq_fill_eighths` sets how many eighths of the completion queue
  the worst-case in-flight ops may fill: ⅞ (the default, the fill the c10k
  ceiling is derived at) packs the ring tightest, and lowering it toward ⅛
  reserves more burst headroom at the cost of a lower feasible conn-slot
  ceiling. Unlike the pool sizes it is the one `limits` field that does not
  shrink a pool; a fill whose ring would exceed the compiled one
  (`cqFillFits` false for the chosen conn/upstream slots and listeners) is
  rejected at load, not clamped (§4/§8).
- **The config arena is the only allocating region** — parse-once,
  immutable, shared read-only. (Carried verbatim; it worked.)
- **The config surface has a generated JSON Schema.** `zig build schema`
  reflects over the `*Json` parse structs and their co-located metadata
  (`src/config_schema.zig`) to emit a draft 2020-12 schema — structure,
  `required`, `additionalProperties: false` (the parser is strict), enums,
  and every numeric bound traced back to `src/constants.zig`. It is a
  release-only asset, never committed (so it cannot drift); the emitter's
  tests run under `zig build ci`, and `assert_meta_matches` fails the build
  if a field lacks schema metadata. It intentionally stops at what JSON
  Schema can express: the loader's semantic checks (canonical
  prefixes/hosts, address literals, reserved header names, port ≠ 0) and
  the "exactly one of" forks stay the loader's job, so passing the schema
  means well-shaped, not accepted. The one concession strictness makes to
  the schema is a root `$schema` key: it is a declared, optional field that
  the loader parses and ignores, so an editor can point a config at the
  document without the proxy refusing to start over the pointer. It buys no
  general laxity — `$schemas`, or a `$schema` nested inside any other
  object, is still an unknown field.
- **A slot is released only when its armed-op set is empty.** Teardown is
  where the races live — a lesson paid for in implementation time and
  simulator seeds last iteration. Every op references a completion
  embedded in the slot, and the slot header tracks which are armed.
  Teardown is a *state*, not an event: shutdown both fds — a pending recv
  never completes otherwise — cancel the timer (§4 — teardown and the §8
  dial re-base are the only cancels), then wait — the last terminal
  completion (success, error, or cancellation) empties the armed set,
  closes both fds synchronously (no op references them any more, so the
  closes need no ring completions of their own), and releases the slot. An active completion is never resubmitted (libxev's
  intrusive queues corrupt on re-enqueue) — overlapping ops on the same
  connection get their own completions instead of sharing one — and LIFO
  reuse turns a straggler completion landing in a recycled slot into
  memory corruption — so slots carry a generation counter asserted on every
  completion delivery, and the simulator asserts no completion is ever
  delivered to a freed or reused slot (§9).
- **Pool memory has exactly one owner, always.** With one thread in the
  binary (§3) there is no cross-thread handoff to get right: no parked
  slots, no ownership transfer, no flag protocol for completions that
  arrive while another thread holds a slot. Single-writer pools are a
  state the design cannot represent violating, not a rule the code has to
  remember — which is why the worker seam was deleted rather than left
  dormant (§3).

## 6. L4 data path — TCP relay

The minimal proxy:

```
accept → admit (slots? buffers?) → route by listener
       → [require? read PROXY header] → connect upstream
       → bidirectional relay → teardown on either EOF/error/deadline
```

- A listener is bound to a cluster in config; no parsing, no inspection
  *of the payload*. The one exception is opt-in and runs ahead of it: a
  `proxy_protocol` listener consumes one bounded PROXY-protocol header
  before the dial (below), and after that the relay is as blind as ever.
- Relay buffers (one per direction) are acquired at admission and held
  for the connection's life — a recv must always have a buffer posted —
  so `relay_buffers`, not connection slots, bounds concurrent L4
  connections. An L4 connection never binds a head-ring buffer.
- **Strict `recv → send → recv` per direction over one fixed buffer
  each.** The next chunk is never read until the current one is fully
  written, so a slow side stalls the fast side through TCP flow control
  and per-connection memory is constant regardless of stream size.
  (Carried: stronger than watermark schemes because there is no read-ahead
  to disable.)
- Half-close is honored (`shutdown` propagates FIN); the connection ends
  when both directions have drained or the deadline fires.
- Idle timeout and max-lifetime ride the single deadline timer.
- **Receiving PROXY protocol** (`"proxy_protocol": { "mode": "require" }`,
  #142). Behind another proxy the observed peer is that proxy, and the
  client address is a *routing input* — §7's `hash` keys on it, so an LB
  in front does not merely blur the logs, it collapses the whole fleet
  onto one endpoint. A `require` listener demands every connection open
  with a PROXY protocol header (v1 or v2 — what AWS NLB, GCP and HAProxy
  emit) announcing the real client, parsed before the dial because the
  dial consumes the address. The trust shape is `forwarded`'s (§7),
  inverted to the receive side: per listener, no default, and **no
  sniffing arm** — a listener that accepted a header only when one shows
  up would let any client choose the address that routing, the access
  log, and the origin then believe, which the spec forbids of receivers.
  `require` therefore closes any connection that does not open with a
  valid header, making the listener unusable by anything but the proxy
  configured in front of it — that is the point. A header that announces
  nothing (v1 `UNKNOWN`, v2 `LOCAL` — how a fronting balancer's own
  health checks arrive) is accepted and keeps the observed peer.
  Mechanically the phase costs nothing new: it stages in the relay
  buffer's client→upstream half (held since admission, idle until the
  relay starts), runs under the connect budget — the fronting proxy
  speaks immediately after connecting, and the hand-over's fresh dial
  deadline then only ever moves *later*, which the lazy timer absorbs
  without a rebase (§4) — re-parses from byte 0 per delivery against a
  parser whose verdicts are monotonic (a prefix of a valid header is
  never `invalid`), and enters the relay with any coalesced payload
  pre-staged as the first send. The header is bounded by
  `proxy_header_bytes_max` (512: admits both specs' largest fixed
  address blocks and real TLVs — the v2 length field is the peer's
  number, the cap is ours) and never counts toward `bytes_in`; the
  verdicts are `l4_proxy_header_accepted` / `l4_proxy_header_invalid`,
  the latter deliberately outside the `shed_` gate identity because the
  connection was admitted before it could be judged (§9). IPv4-mapped
  IPv6 announcements unwrap to the IPv4 address they are — the accept
  path's own normalization — so one client hashes one way however its
  address was conveyed.
- **Sending PROXY protocol** (a cluster's
  `"proxy_protocol": { "send": "v1"|"v2" }`, #142). The receive half's
  mirror, and its machinery pays for the whole thing: the header —
  composed by the same module's writers, pinned to the parser by
  round-trip tests so a chained zoxy always accepts what another sends —
  is prepended at the dial to the client→upstream direction's debt, and
  the relay's pre-owed-debt entry sends it before any relayed byte. No
  new state, no new op, no new memory beyond a stack buffer; the
  destination field is the client socket's local address, asked through
  the seam (`localAddress`) at the one moment it is needed. Per
  *cluster* — HAProxy's `send-proxy` unit — because it states what the
  origin reads, not who connects; and the identity it names is whatever
  zoxy believes, so behind a `require` listener the announced-in client
  is the announced-out client, one identity across the chain. The
  restriction is *reachability*, enforced at load: an http listener may
  not route to a sending cluster, because a pooled L7 upstream is shared
  across clients (§3) and a per-connection header naming one client
  would lie to every other. Two honest edges: a mixed-family pair
  (an IPv4 client on an IPv6-local socket) promotes both addresses to
  INET6 with the v4 side mapped, which receivers unwrap; and health
  probes do not send the header — the dial-only tcp check is unaffected,
  an http check against a sending cluster probes bare.

## 7. L7 data path — HTTP/1.1 reverse proxy

Same skeleton as the previous iteration (it was measured sound), simplified
where Pingora's phase model lets us:

```
accept → admit → recv head → parse (zero-copy) → route (host/path → cluster)
       → upstream checkout | connect → send head+body → parse response head
       → framed relay back → park upstream, idle downstream (keep-alive)
```

- **Zero-copy head parser: a hardened fork of
  [hparse](https://github.com/nikneym/hparse)** (pure Zig,
  SIMD-vectorized, never allocates or copies — picohttpparser-shaped
  API; "streaming" means detect-and-retry — partial input re-parses
  from byte 0, bounded by `limits.head_buffer_bytes`). Upstream was
  not adoptable as-is; the fork cleared a recorded hardening gate
  before landing:
  bounds-check the cursor (upstream dereferences one byte past
  the buffer on partial input — silent UB), accept HTAB in field values
  (RFC 9110), reject bare-LF line terminators (a smuggling ingredient),
  make header-array overflow distinguishable from malformed input (431
  vs 400), and open the closed method enum to extension tokens. The
  fork is vendored by audited commit like every dependency (§4); the
  fallback, had hardening proved costlier than rewriting, was our own
  parser behind the same wrapper. It parses into a caller-owned bounded
  header array over the linear head buffer. Oversize request-line →
  414; oversize header field or total head → 431; never grow. hparse
  parses *syntax* only — framing semantics stay ours: the incremental
  chunked decoder and every strictness/smuggling
  check in the next bullet are zoxy code (`src/http/parser.zig` wraps
  hparse and owns them), and hparse's output is fuzzed *through* that
  wrapper (§9), so the trust boundary sits at our validation, not the
  dependency's.
- **Both directions framed** (RFC 9112 §6.3). Smuggling shapes (TE+CL,
  duplicate/garbage Content-Length) → 400 before any byte reaches an
  upstream. `Upgrade` → 501 (non-goal). Hop-by-hop headers stripped both
  ways; `Connection: close` injected when the proxy will close — announced,
  not silent, or a client pipelines into the close and reads the reset as
  an error instead of a clean end.
- **Path routing on the canonical path only** (settled 2026-07-19). An
  `http` listener maps the request path to a cluster through a
  per-listener longest-prefix route table (`"routes": [{ "prefix":
  "/api", "cluster": "api" }, …]`; the existing `"cluster"` field stays
  as sugar for a single catch-all route). The table is resolved at
  config load into an immutable arena table sorted longest-prefix-first
  — matching is a bounded linear scan, never an allocation. The scan's
  bound is the table's own length, fixed once config load returns; there
  is no constant capping it, because the table sizes nothing but its own
  arena slice. No route matches → static `404` (§8). Matching
  consults only the **canonical path**, computed once in the trust
  boundary: the query splits off untouched (opaque to the proxy,
  forwarded verbatim); unreserved percent-escapes (RFC 3986 §2.3) are
  decoded and surviving escapes' hex uppercased; then dot-segments are
  collapsed. Structure-changing escapes are rejected as 400 — encoded
  slash (`%2F`), NUL (`%00`), truncated or non-hex escapes — and so is
  a path that climbs above the root. Duplicate slashes are preserved:
  `//a` names a different resource than `/a`, and consistency, not
  merging, is what makes it safe. The rendered upstream request line
  carries that same canonical path, so the router and the origin cannot
  disagree about which resource a request names — the `/api/../admin`
  confusion class dies structurally, not by backend convention.
- **Host is the route table's outer dimension** (settled 2026-07-20).
  A route gains an optional `host` (`{ "host": "api.example.com",
  "prefix": "/v2", "cluster": "v2" }`); a route with no `host` matches
  any host, exactly as today. Matching filters to the routes whose host
  equals the request's — falling back to the any-host routes when none
  does — then takes the longest prefix within that set, so a
  host-specific route always beats an any-host route and `host + path`
  composes without a second routing pass. This is the nginx `server` /
  Envoy `virtual_host` nesting (host contains routes), *not* a parallel
  host-picks-cluster path: **cluster selection is the route table's
  alone**, so there is one precedence rule to reason about. Host is
  matched on its **canonical form** — lowercased and port-stripped (RFC
  9110 §4.2.3 makes `Host` case-insensitive, and the authority's port is
  not part of the routing name) — computed once in the trust boundary
  like the path. Unlike the path, the `Host` header is **forwarded
  verbatim**: an origin virtual-host may legitimately be case- or
  port-sensitive, and the proxy has no per-origin knowledge to justify
  rewriting it — the canonical form is a routing *key*, not a
  replacement. A request with no `Host` (legal in HTTP/1.0) or an empty
  one matches only the any-host routes; config hosts must themselves be
  canonical (rejected at load otherwise), so a request host compares
  byte-for-byte against them.
- **Early responses are legal.** An origin may answer before the request
  body finishes (RFC 9110 — e.g. 413 mid-upload): the response head is
  forwarded when it arrives, and the remaining request body is drained or
  the upstream closed per its framing. The state machine plans for this
  from the start instead of assuming strict request-then-response.
- **Phases, Pingora-style but compile-time.** The request lifecycle
  exposes fixed extension points — `admit`, `route`, `upstream_pick`,
  `settle` — as plain function calls, one module per concern: admission
  in `Server.zig`, path → cluster in `http/router.zig`, endpoint pick
  in `balancer.zig`, settlement in `http/proxy.zig`. (Phase 0 sketched
  these as a single `phases.zig`; they materialized as separate seams,
  which is the same design with better boundaries.) Not a runtime
  filter chain: programmability is added by extending the owning module
  at compile time; the proxy core stays generic and small.
- **Telling the origin who the client is: `X-Forwarded-For`, and the
  trust rule is config.** A proxy is the last component that knows the
  client's address, so without this an origin's logs, allowlists and rate
  limits all see zoxy. A per-listener `forwarded` block turns it on;
  absent, the header travels exactly as it arrived, which is what every
  config predating the feature keeps doing.
  **There is deliberately no default mode**, because the two answers are
  each a security bug in the other's position and no proxy can tell from
  the inside which position it occupies. `replace` states the peer this
  proxy observed and discards whatever arrived — correct at the edge,
  where an inbound chain is client-controlled and honoring it would let a
  caller choose the address every downstream allowlist and audit log then
  believes. `append` extends the inbound chain — correct exactly when
  every hop in front is one the operator owns, and a forgery anywhere
  else. The setting lives on the *listener* rather than the cluster
  because it describes what sits in front of that socket; one cluster may
  be reachable from an edge listener that must not trust a chain and an
  internal one that must.
  The chain is **bounded** (`forwarded_chain_bytes_max`): it grows by an
  address per hop and the protocol bounds it nowhere, so a client would
  otherwise decide how much of the head buffer its request occupies. Past
  the bound the chain is dropped *whole* rather than truncated — a
  truncated chain reads as complete and is not — leaving the line stating
  only the observed peer, which is the `replace` behavior and the
  fail-safe direction. `forwarded_chain_dropped` witnesses it.
  Two supporting decisions. The header is classified in the parser like
  every other proxy-managed name, so the render suppresses inbound copies
  by tag rather than by comparing this spelling against every header of
  every request. And filter edits may not name it: a filter can only
  write a *constant*, so an edit here would encode one fixed address for
  every client — forwarding's exact opposite — and barring the name means
  one mechanism owns the header rather than two that can disagree.
- **Configurable filters/rules: filters are data, not code.**
  Zero-alloc extensibility means no plugins,
  no closures, no dynamic dispatch chains — instead, a rule is *compiled
  at config time* into bounded, immutable tables in the config arena
  (match programs over method/host/path/header slices; action lists drawn
  from a closed enum: reject-with-status, add/remove/set header, rewrite
  path prefix). The rule table, a rule's action list and a rule's header
  matches carry no static limit: each is an arena slice at exactly the
  length the config asked for, and evaluation is a bounded loop over
  that length. `header_edits_max` is the one static limit here, and the
  difference is the rule — it bounds a *fixed buffer* the renderer
  materializes the matched rules' edits into, so it must be known before
  the config is read.
  Cluster selection is deliberately *not* a filter action: the route
  table (host + path) is the single mechanism that decides which backend
  serves a request, so there is one precedence rule, not two engines
  competing.
  At request time the phase points *interpret* those tables against the
  parsed head — bounded loops over arena data, zero-copy matches on head-
  buffer slices. Mutations never edit the head buffer in place: the
  upstream head is *rendered* (already required for hop-by-hop stripping
  and `Connection` injection), so header edits are applied during
  rendering into the same fixed staging area, and a head that no longer
  fits after edits → 431. A path rewrite changes *only what is forwarded*:
  routing already chose the cluster from the original canonical path, so a
  rewrite never re-routes and never chains (first-applicable rule wins, like
  the reject verdict — a later rule matches the original path, not the
  rewritten one). Both prefixes are validated canonical at load and the
  replacement is a *segment-correct* join (stripping a prefix to root gives
  `/x`, not the distinct resource `//x`), so the forwarded path is canonical
  by construction. Evaluation cost is bounded and load-shed like
  everything else. This is nginx/HAProxy's config-rule model, not Envoy's
  runtime filter chain — WASM/scripting is explicitly out (an interpreter
  with unbounded fuel or an embedded allocator cannot satisfy the gate);
  anything beyond the closed action enum is a Zig function added to the
  owning phase module at compile time.
- **A filter can match on who is connecting** (#177, settled
  2026-08-03). `match.client` is a CIDR list, any-of across the list
  and conjoined with the rest — "/admin from the office range and
  nowhere else" is one rule with a reject beneath it. It matches the
  connection's client address, which is §6's settled principle rather
  than a new trust decision: the observed peer, or the PROXY-announced
  client on a `proxy_protocol` listener — never an `X-Forwarded-For`
  chain, because an allowlist keyed on client-supplied text is not an
  allowlist. The prefix is mandatory and bounded per family — /32 for
  IPv4, **/64 for IPv6**, the same client identity a `source_ip`-keyed
  hash pick keys on, so two features cannot disagree about what a
  client is — and host bits past the prefix are refused: `10.0.0.1/8`
  is a typo for one of two different ranges, and the loader cannot know
  which. Containment is a masked-prefix compare over the compiled
  table, family-strict; the accept and PROXY paths both normalize
  mapped v6 forms before storage.
- **A filter can answer with a redirect** (#176, settled 2026-08-03).
  `redirect` beside `reject`, closed status set `301/302/307/308` —
  the four with distinct permanent/temporary × method-preserving
  semantics — and a target in one of two forms: a fixed `location`
  sent verbatim, or a composed one, `scheme` (required) and optionally
  `host` replaced with the request's own canonical path and query
  carried through, so `www` → apex and HTTP → HTTPS are one rule each
  and the config never restates the path. The scheme is never guessed:
  behind a TLS terminator every hop this proxy sees is plaintext, and
  a guess is wrong exactly when it matters. The first terminal action
  — reject or redirect — wins, top-down. The redirect is the one
  response this proxy originates whose bytes are not comptime-static,
  so it renders into the connection's own head buffer (§5, §8) and
  holds it through the send; a composed Location the buffer cannot
  carry is `414` — the URI's own fault, answered on a clean message
  boundary the ordinary keep rule then reads — and a composed target
  on a request with no authority (HTTP/1.0, no Host) is `400`.
  `l7_redirected` counts it and the access log says `redirected`,
  deliberately apart from `l7_filtered`/`rejected`: "policy refused
  this" and "policy relocated this" are opposite directions on a
  dashboard.
- **Response filters are a second table, not a scope marker** (#175,
  settled 2026-08-03). `request_filters` (né `filters`, hard-renamed
  while no deployed config existed to break) runs before routing;
  `response_filters` runs after the origin's head parses — and its
  deciding predicate, the response's own status (`header_set` on 5xx
  only), is temporally impossible in a table evaluated before any
  response exists. That is what settled the shape: a shared table with
  a scope field would carry match fields that cannot be evaluated at
  their own application point, the exact conditionally-dead-fields
  hole this loader refuses everywhere else. A response match is a
  conjunction over exact statuses, a status class (`"1xx"`..`"5xx"`)
  and response-header predicates — the request side's own header
  vocabulary, evaluated by the same code — and the actions are exactly
  the three header verbs: reject and rewrite have no meaning on the
  way out, and the loader refuses those arms by name rather than
  ignoring them. Edits apply during the downstream re-render through
  the same suppress-and-append machinery, under the same
  `header_edits_max` bound on the table's total — the render accepts
  one slot past it (`response_edits_max`), reserved for #178's
  Set-Cookie stamp, which rides this machinery rather than owning a
  second injection path; the proxy-managed
  names (framing, hop-by-hop, `X-Forwarded-For`) stay barred by the
  same validator, since a hand-written `Content-Length` would
  desynchronise the relay. A head that no longer fits after edits is
  the response side's oversize verdict: **502, not 431** — an origin
  response the proxy cannot re-render is not the client's fault, and
  it takes the exact path the close-injection overflow already took.
  Response edits carry no counter of their own, deliberately: they
  reject nothing and shed nothing, and the render they ride is already
  witnessed by `l7_responses`. Static responses (§8's sheds and
  rejects) bypass the response render and therefore the edits — the
  simulator's client oracle holds that boundary from outside, and the
  live gate holds both directions per listener: the http leg must
  carry a configured stamp, the l4 leg must not, because byte
  transparency is that leg's whole claim.
- **Resilience is minimal by design:** per-request and per-try deadlines
  (head-read gets its own deadline, so a slowloris meets the clock or
  `limits.head_buffer_bytes`, whichever comes first; each dial — the
  first try and the replay's — runs under its own connect deadline);
  one free replay of a request that hit a stale pooled connection —
  only when the
  connection was a *reused* checkout, no response byte was received, and
  the request leg never entered the body pump, so the whole try still
  sits byte-reconstructible in the head buffer. "May have begun
  processing" is settled as "a response byte arrived or relay chunks
  flowed" — the standard replaying-proxy reading (Go/nginx/HAProxy),
  applied to non-idempotent methods too: a send that landed in the
  kernel buffer of an already-FIN'd parked connection replays, because
  the FIN-before-checkout race is overwhelmingly the real cause. The
  replay is spent before its try begins (no loop) and always dials
  fresh — the endpoint's whole idle list may be stale the same way. The
  endpoint pick is per-cluster config: `p2c` (two weight-biased
  candidates from a fixed-seed PRNG — uniform at the default weights —
  the lower **in-flight total** wins: L7 leases and live L4 connections
  summed, since both are work the origin is carrying) by default, `rr`
  for smooth weighted rotation (strict rotation at equal weights),
  `hash` for stickiness. `pick` takes two spellings (#178): the bare
  policy string for the keyless policies, or an object —
  `{ "policy": "hash", "key": …, "name": … }` — that names what a
  `hash` cluster is sticky on. A bare `"hash"` is rejected at load:
  the old source_ip default read as "sticky" and quietly was not
  behind NAT, so the key is the operator's sentence to write.
  Cluster endpoints are
  static socket addresses resolved once at config load, never on the
  loop (dynamic DNS is a non-goal, §1), each optionally weighted — two
  bullets below.
- **A pick chooses among the endpoints that are both healthy and under
  capacity**, in that order, and the two filters differ in what an empty
  result means. Health fails **open**: a cluster with every endpoint
  ejected balances as if none were. `max_inflight` (§8) fails **closed**:
  every endpoint at its cap refuses the request rather than dialing one.
  The asymmetry is the point — an ejection says *we do not know whether
  these work*, so trying beats refusing, while a cap says *we know they
  are full*, and the whole reason it exists is to not send more. Capacity
  is judged over whatever health left, so a cluster that fails open still
  respects its caps. The in-flight total both this and `p2c` read counts
  L7 leases and live L4 connections alike, which is what lets an L4-only
  deployment be protected and load-balanced at all.
- **Endpoints carry weights, and every policy honors them** (#174,
  settled 2026-08-02). An endpoint is the bare `"IP:port"` string —
  weight 1, the homogeneous common case — or `{ "address": …,
  "weight": 3 }`, bounded by `endpoint_weight_max` (256, HAProxy's own
  ceiling). Each policy absorbs the weight without changing character,
  and each unit-weight path is bit-identical to the unweighted algorithm
  it grew from, so existing clusters keep their draws, rotations and
  client mappings. `rr` runs nginx's smooth weighted rotation — weight 3
  beside weight 1 serves a,a,b,a, never three in a burst, and at unit
  weights it is exactly the strict rotation it replaced. `p2c` draws its
  two candidates in proportion to weight and leaves the in-flight
  comparison untouched: a heavier endpoint is likelier to be
  *considered*, and load still outranks share. `hash` scores one replica
  hash per weight point and keeps the best — proportional by
  construction, integer-only (no float log whose libm could re-home the
  fleet across builds) — and re-weighting an endpoint disrupts only the
  clients it gains or loses, so the 1/n property survives weighting.
  A weight of `0` **drains** its endpoint: never picked, not even
  through fail-open — a drain is an operator's statement where an
  ejection is only a probe's verdict — while the prober keeps probing
  it, so recovery is still observed. A cluster whose weights are all
  zero is rejected at load (`EndpointWeightsAllZero`) rather than
  accepted as one that can never answer.
- **`hash` is rendezvous hashing, and it is stateless because it has to
  be.** Client-to-backend stickiness is normally a *table* — the proxy
  records which server a client went to. That mechanism cannot work
  here. Scale-out is N independent processes behind SO_REUSEPORT (§3),
  and the kernel picks the listening socket by hashing the connection's
  4-tuple, source port included, so one client's connections land on
  *different processes*. A per-process table would be filled by whichever
  process saw that client first and consulted by processes that never
  did. HAProxy documents exactly this — stick-tables are per process and
  never shared, and the peers protocol cannot sync processes on one host
  — and its answer was to abandon multi-process for threads sharing
  memory, which §1 rules out here.
  So the endpoint is a *pure function* of the key and the eligible set:
  every process computes the same answer with nothing shared, which is
  what makes stickiness correct under this process model rather than
  merely cheap. The pick object's `key` names the identity. `source_ip`
  is all four bytes of an IPv4 address and the **/64 prefix** of an
  IPv6 one, since RFC 8981 privacy addressing rotates the interface
  identifier and hashing it whole would re-home mobile clients on a
  timer. `header` is rendezvous over the named header's value (a
  pinned FNV-1a folded through the same pinned finalizer — `std.hash`
  makes no cross-version promise, and a rolling restart runs two
  builds side by side): stickiness on an identity the client *states*
  — a tenant, a user id — which survives NAT, the exact place
  `source_ip` fails. `cookie` is the third key and its own bullet
  below. The request-derived keys read a parsed head, so the loader
  rejects them on clusters any `l4` listener routes to — the
  `proxy_protocol` reachability rule in the other direction — and a
  request *missing* its keyed material (no such header, first request
  of a cookie session) is placed by load instead, the same weighted
  two-choice draw `p2c` runs: cross-process agreement is not needed
  there, because a keyless population has no identity to be sticky on.
  Rendezvous rather than a ring or Maglev because both of those answer
  from a precomputed table, and a table must be *rebuilt* whenever
  membership changes — which here is every health-check ejection and
  recovery, on the one thread that must not stall (§3). Rendezvous scans
  the eligible set the health mask already produced: no table, no
  rebuild, and only the clients of an ejected endpoint move (the 1/n
  optimum — measured at 13.1% of clients for a 1-of-8 ejection). The
  cost is O(n) per pick instead of O(log n), which is why a cluster's
  endpoint count is a cost the operator chooses: 71 ns per pick at 64
  endpoints, against a request served in ~100 µs, and linear in the
  count from there. Nothing caps it — the pick simply gets slower, and
  that trade is visible where it is made. Weights turn the same dial:
  a weighted pick scores one hash per weight point, so the scan is
  O(sum of weights), bounded per endpoint by `endpoint_weight_max` and,
  like the count, priced by the operator's own config. Jump consistent
  hash is excluded outright — it can only add or remove the *last*
  bucket, and an ejection removes an arbitrary one.
  Two honest costs. Stickiness holds only while processes agree on the
  eligible set, and each probes independently (below), so a health flap
  opens a divergence window — confined, by the same 1/n property, to the
  clients of the flapping endpoint, who are already affected by it.
  And source-IP hashing balances by *client*, not by request: NAT puts
  many clients on one address, and one heavy client cannot be split —
  which is what the `cookie` key exists for, next bullet.
  It also balances by the *observed* client: behind another proxy every
  connection carries that proxy's address, so the key is one value and
  the whole cluster hashes to a single endpoint — stickiness inverted,
  not degraded. `proxy_protocol` on the listener (§6) is what makes
  `source_ip` mean the real client there.
- **Cookie stickiness: the client holds the assignment** (#178, settled
  2026-08-03). Where `source_ip` breaks — corporate NAT, CGNAT, mobile
  carriers, exactly where stickiness is most wanted — the standard
  answer is a cookie the proxy sets (HAProxy's `cookie SRV insert`),
  and it fits this design unusually well: §3's argument against a
  stickiness table is that no process can share one, and a cookie is
  the client carrying the state instead, the table-free property
  rendezvous has, achieved a second way. The named cookie holds an
  **endpoint tag**: 16 lowercase hex of the endpoint's rendezvous
  identity — a function of its address, so it is stable across
  restarts, processes and config reordering, and leaks a hash rather
  than the address. A request whose tag names a healthy,
  under-capacity endpoint goes there, whatever the load says —
  stickiness is the point, and load had its say at placement. A
  request with no usable tag is placed by load (the first request of a
  session deserves the calmest endpoint), and one naming an ejected,
  drained, capped or removed endpoint re-homes the same way. Then the
  response answers: `Set-Cookie: <name>=<tag>; Path=/; HttpOnly`, as
  one `add` edit riding the #175 render machinery (an origin's own
  Set-Cookie rides beside it), on every exchange whose request did not
  already name the endpoint that served it — and *only* those, so a
  settled session is never re-stamped. No `Secure` attribute: this
  proxy does not terminate TLS (§1), so it cannot know the
  client-facing scheme. Three counters partition a cookie cluster's
  forwarded responses — `l7_sticky_followed` / `assigned` /
  `repicked` — and a repick *rate* is the operational signal:
  endpoints flapping under a sticky population. Forgery is priced
  consciously: a tag is not signed, because a client can only choose
  which backend serves *itself*, and only from the eligible set — a
  keyed variant is a config knob for later if that ever matters. The
  tag grammar is strict (exactly the minted spelling parses), the mint
  is pinned by test vectors and re-proved by the simulator against a
  frozen literal, and the live gate round-trips assignment, echo and
  forgery against the shipped binary.
- **Active health checks** are per-cluster opt-in (a `check` block —
  HAProxy's model) so a request is not routed to an endpoint known to be
  down:

  ```json
  "api": { "endpoints": ["10.0.0.1:80"],
           "check": { "type": "http", "path": "/health",
                      "expect_status": 200, "fall": 3, "rise": 2 } }
  ```

  One prober per server sweeps every checked endpoint with a **single
  probe in flight**, budgeted like the admin plane (§8:
  `health_probe_ops_max` ring ops and one fd, reserved unconditionally).
  Sweeps pace sweep-end to sweep-start on `timeouts.health_interval_ms`;
  one probe is bounded by the check's `timeout_ms`, which defaults to
  `connect_ms`.

  What a probe proves is the operator's choice. A **`tcp`** check dials:
  a SYN/ACK passes, and refused, unreachable, timed out or kernel
  pressure (witnessed §8) fails. It proves the port accepts, which an
  origin that is listening but answering 500s also does. An **`http`**
  check therefore sends `GET <path>` and requires the configured status,
  reading the response with the data path's own head parser (§7) — so a
  probe accepts exactly the heads this proxy would forward. Its legs run
  in sequence, dial then send then recv, which is why the op budget is
  the same for both kinds.

  `fall` consecutive misses eject the endpoint from balancing and close
  its parked pooled connections (§5); `rise` consecutive passes restore
  it. Endpoints start healthy — probing demotes, it never gates startup
  — and the pick **fails open**: a cluster with every endpoint ejected
  balances as if none were, because routing nowhere would turn a probe
  verdict into an outage of its own. Circuit breakers, outlier ejection,
  retry budgets stay *deferred* — the previous iteration proved them
  buildable in this architecture; simplicity says they wait for a
  demonstrated need.

## 8. Load shedding — the exhaustion ladder

The defining behavior: **when a resource is exhausted, zoxy degrades the
newest work, keeps serving admitted work, and never allocates, blocks, or
dies.** Every ladder rung is a static decision at a single choke point on
the loop thread.

| resource exhausted | detected at | shed action |
|---|---|---|
| connection slots | accept completion | close immediately (SO_LINGER 0 → RST); accept stays armed |
| relay buffers (L4) | accept admission | close immediately |
| head buffers | a client's first byte, before the parse | static `503`, then **always close** — the refused bytes are still unread in the socket, and a kept connection would shed them forever |
| relay buffers (L7) | request admission on a kept-alive conn | static `503` from static memory, then keep or close per pressure |
| upstream slots / dial concurrency | upstream checkout | static `503` (L7), then keep or close per pressure / close (L4) |
| upstream head buffers | beside the slot, as it is obtained | static `503`, then keep or close per pressure |
| **origin capacity** — every endpoint at its `max_inflight` | endpoint pick | static `503` (L7) / close (L4) |
| request deadline | timer completion | `504` if no response byte was sent — a timed-out dial included; teardown once a response byte is on the wire or the stall is the client's own body |
| kernel memory pressure (ENOBUFS/ENOMEM from ring) | any completion | treat as that op's failure → teardown that connection; counter |

Most rungs shed on a *resource of this proxy's* running out. That was
once every rung, and it was a real gap — measured, not theorised: at
c10k the upstream pool's ceiling was the only thing saying no, and once
it was given enough headroom to stop firing (§5), nothing bounded an
overloaded exchange at all — latency grew until the *client* gave up,
and this proxy went on spending CPU answering requests whose callers had
left. The numbers are in IMPLEMENTATION_NOTES.md.

Two rungs answer on something else. One is **time** (below). The other
is the **origin's** capacity rather than this proxy's: `max_inflight`
caps the work one endpoint may carry, counted across both protocols
(§7), and refuses past it. The distinction is the point — running out of
upstream slots says *widen the pool*, while a capped endpoint says *the
backend is full*, and the two have their own counters so an operator
cannot read one as the other.

The rung that answers on **time** rather than on exhaustion is the
request deadline, and `timeouts.request_ms` is what arms it: an absolute
cap on one exchange, from the moment a request head is routed to the
last response byte. It is deliberately **not** refreshed by activity —
that is the whole difference from `idle_ms`, which bounds a stalled
exchange but never a merely slow one. It rides the same per-connection
deadline timer, clamping it the way `max_lifetime_ms` does, and is
retired the moment any rung commits to an answer, so a deadline can
never cut short the delivery of the verdict it caused. `0` (the default)
disables it: what counts as too slow is a property of the operator's
origin, not one this proxy can pick for them.

- **Static error responses.** `400`/`404`/`414`/`431`/`501`/`503`/`504`
  are comptime byte arrays sent directly from static memory — never
  staged through
  the connection's head buffer, whose bytes the parsed head's zero-copy
  slices may still reference (§7). Shedding costs one send, no
  allocation, no copy. The #176 redirect is the one proxy-originated
  response that *does* stage through the head buffer — its Location is
  per-request — and it may do so only because its render runs after
  every read of those bytes: the Location is composed first, into the
  rewrite scratch, so nothing aliases what the render overwrites (§7).
- **Those responses can carry a body, and bodies are a named table**
  (#159, settled 2026-08-03). `bodies` maps a name to bytes — a `file`
  read once at startup or an `inline` string, exactly one, plus the
  `content_type` nothing infers — and every feature that serves content
  references one *by name*: `error_pages` maps a status to a body,
  a `respond` filter action answers with one. The indirection is the
  design, not ceremony: one body is one read, one charge against the
  cap, and one rendered buffer per (body, status) however many places
  serve it, while a dangling name is a load error rather than a
  silently empty page — the `clusters` idiom, applied to the same kind
  of thing.
  Each configured page is rendered **at load** into two complete
  responses — both persistence variants, status line through body, one
  contiguous arena buffer each — with the head length recorded so a
  `HEAD` request sends that same buffer's prefix. Serving one is
  therefore the comptime path unchanged: one send from immutable
  memory, nothing acquired. That is the whole reason bodies live in
  memory rather than being spliced from a file: an admitted `503` is
  raised *because* a pool ran out, and an error page whose delivery
  needed a pipe from another bounded pool would fail exactly when it is
  needed. `body_bytes_max` caps a body and marks the scope boundary —
  below it memory is the right answer, above it the page cache and a
  streaming path are, which is a different feature. The cost is per
  process, so N workers behind `SO_REUSEPORT` hold N copies; the banner
  prints the page count beside the measured config arena that holds
  them. A changed file needs a restart, like every other parse-once
  input (§1).
  Configuring a status is the **whole opt-in**, sheds included. A `503`
  does not grow a body by default: the cost is not arena bytes but
  kernel socket-buffer bytes, which §5 explicitly leaves outside the
  closed form, multiplied by the shed rate at the moment the proxy is
  under most pressure. Writing the page down is the operator saying
  they want that, so a second `send_body_on_shed` switch would only
  override a decision the config already expresses — the reasoning that
  makes `forwarded` an absent block rather than a `mode: "off"`.
  The `respond` action is the same machinery pointed at a different
  question: a maintenance page, a `robots.txt`, a health target served
  by the balancer itself. It is terminal like `reject` and `redirect`
  and stops the request before routing acquires anything, but it is
  deliberately *not* a body on `reject`: a reject is policy refusing
  traffic and a respond is this proxy being the origin, so they keep
  separate counters (`l7_responded`) and separate access-log outcomes
  (`responded`). Its status set is the error statuses plus `200`, the
  one status no rung raises. Response filters (#175) cannot carry the
  action at all — those rules run when an origin response already
  exists, and replacing it is not an edit.
- **A shed keeps the connection when it can.** Closing is not free: it
  costs the client a handshake and this proxy an accept, a conn slot and
  an admission — so an always-closing shed is *more* expensive per
  request than the work it sheds, and a transient overshoot locks itself
  in as a reconnect loop rather than settling into a plateau. A static
  response therefore keeps the connection whenever all four hold: the
  client's byte stream is still on a message boundary (a valid head
  parsed, no declared body left to read, nothing pipelined past it), the
  client asked for keep-alive, the proxy is not draining, and relay
  pressure has not suppressed keep-alive (#57). Otherwise the lingering
  close (§7) drains the client's inbound and closes. The
  head-framing rejects — `400` malformed, `414`, `431` — can never keep:
  where the next request begins is exactly what the parser could not
  determine, so keeping would hand a smuggler a desynchronized stream.
- **Accept never pauses.** Accept-and-RST is preferred over un-arming the
  accept: the kernel backlog stays drained, clients get an immediate
  signal instead of a timeout, and there is no re-arm state machine.
  The one exception is an accept that *fails* with a kernel-pressure
  error (ENFILE-class): there is no socket to shed and the failed
  connection stays in the backlog, so an immediate re-arm would complete
  instantly with the same error — a tight spin. That path re-arms after
  a short backoff (`accept_retry_delay_ms`).
- **Watermarks before walls.** Each pool flips a `pressure` flag at its
  high watermark (ceil 3/4, released at floor 1/2 — hysteresis), one
  rule for all three: *relay-buffer* and *conn-slot* pressure are
  downstream pressure — the idle timeout divides, so idle downstream
  connections return the buffers and slots they pin. *Relay-buffer*
  pressure alone also stops honoring keep-alive, because the next
  request on a kept-alive connection claims a relay buffer. Conn-slot
  pressure never suppresses keep-alive: a conn pool held by serving
  connections is the steady state of a keep-alive workload, and closing
  them churns the whole population into synchronized reconnect waves
  (measured — IMPLEMENTATION_NOTES.md "Occupancy is not overload");
  slot scarcity is answered by the idle division and the admit-time
  RST wall, the same norm nginx and haproxy follow. *Upstream-pool*
  pressure shortens parked-connection deadlines (and the sweep
  interval), reaping idle parked sockets so their slots free for fresh
  dials. Each bias sheds *idle* capacity before the wall must shed
  *work*; each engage crossing has a counter. The head-buffer ring flips
  the same flag on the same watermarks but drives no bias at all — an
  idle connection holds no head buffer, so there is no idle occupancy a
  timeout could evict; its flag and engage counter exist for the
  operator, who sizes `limits.head_buffers` by the crossings before the
  wall starts refusing.
- **Metrics witness every shed.** Every rung has a counter, written only
  by the loop thread as a relaxed atomic — one writer, any number of
  readers. The admin plane reads them on the loop itself (§3: there is no
  second thread); the relaxed atomic costs nothing on the write side and
  keeps any out-of-loop reader race-free by construction. The simulator
  asserts counters reconcile (admitted = completed + shed + in-flight)
  under every seed. Counters live in `counters.zig` (§10); exposure is
  the admin/metrics listener's Prometheus rendering (`admin.zig`, one
  reserved scrape slot off the shared pools) plus a SIGUSR1 dump through
  the seam's `signal` primitive (§4).
- **The exposition says which backend, not only how many** (#179,
  settled 2026-08-02). Beside the process totals, labeled families:
  per-endpoint counters for dial failures, responses served and health
  transitions
  (`zoxy_endpoint_connect_failed{cluster="api",endpoint="10.0.0.1:8080"}`),
  per-*cluster* counters for the two inflight sheds — those fire
  precisely because no endpoint could be picked, so an endpoint label
  would be an invention — and two gauges read off the owners' live
  state at render time: the per-endpoint in-flight level the balancer
  compares, and the prober's healthy verdict for checked clusters
  (unprobed endpoints render nothing rather than a constant 1 dressed
  as a verdict). Each labeled family **partitions** the bare total it
  breaks down — the contract the kernel-pressure counters already keep,
  where the per-op and per-cause splits are two views of one total
  (`counters.zig`) — and `reconcile` holds the views equal under every
  simulator seed, so neither can drift. Label cardinality is bounded by config: there is
  no user-controlled dimension — no per-path, no per-status — and
  there must never be one. That bound is also what let the render
  buffer move from a comptime constant to a config-derived arena term
  with its own banner line (§5).
- **The access log is a shed rung of its own.** Counters say how much and
  how often; an access log says *which request*, and that is what an
  operator needs when one client is being served badly and the aggregates
  look fine. Optional — a config `access_log` block names a sink, and
  absent it the whole feature reserves nothing and reads no clock. The
  sink is `stdout` (inherited, no fd of its own, piped wherever the
  operator already sends this process's output) or `file` with a `path`:
  opened once at startup — append-only, created if absent, never
  truncated, two fds in `fdsRequired`'s budget (held + the reopen
  transient below). Append-only is what makes an external copy-truncate
  rotation (logrotate) safe: every write lands at the current end,
  wherever a rotation just put it. Move-based rotation is served by
  **SIGHUP**, which reopens the configured path: the new fd opens
  *first* — a rotation that cannot open its file keeps the old fd and
  counts `access_log_reopen_failed`, because a failed rotation must not
  destroy a working log — and the swap happens only between sink
  writes, never under one (a pending reopen waits for the in-flight
  write's completion, and every line accepted after the signal lands in
  the new file). The reopen itself is two synchronous syscalls on the
  loop — a priced exception to the never-block rule, accepted because
  rotation is operator-paced and rare where the async alternative is a
  fork op against a closed union (§4); a log directory that can *hang*
  (dead NFS) stalls the loop at rotation time, which is a deployment
  problem, not a proxy one. A successful reopen also heals a `broken`
  sink: what broke was the fd the rotation just replaced. On a `stdout` sink — or
  no log at all — SIGHUP is a no-op, and that is the signal's *only*
  meaning: zoxy does not reload config (§1 non-goal — the §5 pools are
  startup-fixed, so a config change is a restart). Whichever sink, it
  writes one JSON object per line: one per HTTP exchange (including every
  reject, request-level shed and verdict) and one per L4 connection,
  carrying the
  client, method, canonical host and path (§7), status, outcome,
  duration, byte counts each way, and the cluster and endpoint that
  served. `outcome` is not derivable from `status` and that is the point:
  an origin's own `503` and this proxy's shed `503` are the same three
  digits and opposite events. The two answer different questions — what
  the origin said, and whether the client got it — so `status` is
  recorded as soon as the response head is rendered (which the head
  buffer can defer past the parse), while `ok` means "the whole response
  reached the client" and is earned only when the last byte does. An exchange cut off mid-response logs its origin's status
  with outcome `aborted`; exactly one `ok` line per `zoxy_l7_responses`
  is what the §9 oracle asserts.
  **A line can also carry headers the operator names** (#140, settled
  2026-08-03), and that is what joins this log to the origin's. Nothing
  here mints an identifier: zoxy is usually not the outermost hop, a
  CDN or ingress in front almost always sets `X-Request-ID` or
  `traceparent`, and that header passes through untouched and reaches
  the backend — so logging it at both ends builds the join with nothing
  added to the wire. Minting one is postponed rather than dropped, and
  the reason it is a separate question is concrete: generating an ID
  needs entropy, this proxy has no randomness source in production, and
  obtaining one is a §4 seam decision with a §9 determinism constraint
  attached. It is also the more general feature — `User-Agent`, a
  tenant header, a CDN's ray ID, the origin's `X-Cache` — none of which
  is a correlation ID.
  `access_log.request_headers` and `response_headers` name them, absent
  lists leaving the line byte-identical to what it was. The values are
  **copied** at capture, not borrowed: the head buffer's zero-copy
  slices do not survive the awaits before the line is written (§7
  rotation), so they land in a per-connection table under
  `access_log_header_bytes_max`, truncated with a trailing `...` on
  `path`'s terms. That table is addressed by connection *slot*, so it
  is cleared when a slot is acquired as well as on each keep-alive
  turnaround — a head that never parses reaches no capture, and its
  line would otherwise report the slot's previous occupant's header,
  which is one client's correlation ID on another client's request.
  Four decisions worth stating. The fields are **nested** objects, one
  per direction: flattening would let a header called `status` shadow
  the real one, and the nesting keeps "what the client sent" visibly
  apart from "what zoxy observed". A configured header that did not
  arrive is **omitted** rather than emitted as null, so the object says
  what was there. Names are matched case-insensitively and logged
  **lowercased**, one spelling a downstream query need not guess at.
  And a repeated header logs its **first** value, because
  `parser.headerValue`'s does — what the line reports is then the value
  zoxy itself read, which is the property worth having when the two
  disagree.
  The structural consequence is that `access_log_line_bytes_max` stops
  being a comptime sum over a fixed field set: the named headers are
  the operator's list, so a line's maximum length is theirs too. It
  becomes `accessLogLineBytes(count)` — with the compiled ceiling kept
  for the budget asserts, the header-free bound kept as the staging
  floor, and the loader refusing a staging buffer that could not hold
  *this* config's line, since that drop would mean arithmetic rather
  than backpressure. That move is #179's, already argued and already
  landed: the metrics exposition's render buffer became a config-derived
  banner term for exactly this reason when labels arrived, and the
  capture table is priced in the banner the same way.
  **The unit is an admitted connection**, which is what draws the line
  between the two kinds of shed in the table above. A request-level shed
  — a `503` for relay buffers or upstream slots — belongs to a connection
  that holds a slot, so it gets a line like any other answer. An
  *admission-gate* shed does not: `shed_conn_slots`, `shed_relay_buffers`
  and `shed_draining` fire on a socket that never got a slot, so there is
  no capture state to report from, and asking the kernel for a peer
  address would put a syscall and a render on the one path this section
  keeps to "at most two direct syscalls" — the path that is hottest
  exactly when it fires. Their witness stays the counters, which is also
  the honest one: under a shed storm the log would be the highest-volume
  thing in the process, so the lines an operator most wanted would be the
  first the drop rung took.
  **A log line must never stall the data path.** The sink is a pipe or a
  filesystem the operator owns, so it can block for arbitrarily long, and
  a proxy that waited on it would hand every client's latency to whatever
  reads its logs. So the write is a ring op like every other (§4) with
  at most one in flight — one ring-budget entry, reserved unconditionally —
  lines accumulate in a second staging buffer while it is out, the two
  swap when it lands, and **a line that does not fit is dropped and
  counted.** That is this section's own rule applied to logging: the
  newest work gives way at a well-defined point, `access_log_dropped`
  is the witness, and losing a log line is the right trade against
  stalling a relay. Flushing is self-clocked rather than timer-driven — a
  record with no write in flight starts one at once — so a quiet proxy's
  line leaves immediately and a busy one batches a whole write's worth.
  A sink write that *fails* (a closed pipe) marks the sink broken rather
  than retrying: what reaches that point is not transient, since the ring
  already absorbed every would-block. The drain (below) does not stop the
  loop until the sink is quiet, because the lines describing a shutdown
  are the ones most likely to be read. The record's per-line width is
  closed-form in `src/constants.zig` like every other limit, which is why
  the head-buffer captures it needs — method, host, path — are bounded and
  truncation is marked rather than silent.
- **File descriptors are pre-budgeted, not shed.** The fd count is
  closed-form — listeners + connection slots + upstream slots + ring,
  async and signal fds — evaluated on the *effective* config
  (`fdsRequired`, so a lean deployment demands only what it uses) and
  asserted against `RLIMIT_NOFILE` at startup, next to the memory
  printout, so `EMFILE` is unreachable rather than a ladder rung.
- **The ring is pre-budgeted, not shed.** The in-flight op count is
  closed-form — per-connection ops (bounded by the strict relay
  discipline) × conn slots + parked upstreams + timers — evaluated on the
  effective config, printed at startup next to the memory and fd budgets,
  and made to fit the completion queue the ring was set up with
  (`completionQueueDepthFor` of the same effective config, §4), so CQ
  overflow — kernel-side NODROP buffering, an allocating path — is
  unreachable rather than a ladder rung. libxev surfacing
  `error.CompletionQueueOvercommitted` is therefore an invariant
  violation (assert), not load.

**Drain, not just death.** SIGTERM (delivered through the seam's
`signal` primitive, §4) → close listeners (stop accepting),
stop honoring downstream keep-alive (`Connection: close` injection), let
admitted work finish under one drain deadline (`drain_deadline_ms`), then
tear down stragglers and exit. Drain reuses the pressure machinery — it
is maximum pressure — and the zero-alloc gate runs it (§9).
By default that deadline is `0` — no cap (§5): no timer is armed, and the
drain ends when the last connection does. That is the majority behaviour
among comparable proxies, and under a supervisor that keeps its own
stopwatch — systemd's `TimeoutStopSec`, Kubernetes'
`terminationGracePeriodSeconds` — it is bounded in practice by the
`SIGKILL` that follows. Under a bare init with no such timeout it is
genuinely unbounded, and a deployment there should set a number. Setting
one means zoxy gives up *before* its platform would, which is a narrower
thing than being bounded at all.
What still bounds a straggler either way is its own per-connection
deadlines: `idle_ms` always, plus `request_ms` and `max_lifetime_ms` when
configured, and the drain's `Connection: close` injection stops an idle
keep-alive connection from waiting on a request that will never come.

## 9. Testing — required from day 0

The deterministic-simulation seam is the single highest-leverage testing
decision the previous iteration made: the data path is written against an
`Io` facade from the first commit (§4) so a seeded, adversarial,
virtual-socket backend can run the *real* code, not a mock of it. All
gates exist as `build.zig` steps from the first commit; a
feature without its gate is not done. The three deterministic gates
(simulation, fuzz, zero-alloc) plus the fd-boundary lint and the live
gate (Tier 0.5) run on every change as `zig build ci`. The benchmark gate
(Tier 1) is **run at merge, not on every change**: its verdict is a *band
comparison across runs* (§Tier 1 below), which a single shared-runner
pass cannot make — so `zig build bench` is invoked deliberately against a
real origin, and its hard invariants (RSS under the §5 banner ceiling,
clean drain, sub-1% socket-error rate) are the pass/fail part. `zig build
ci` deliberately excludes it.

What separates the live gate from the benchmark is not what it runs but
what it *claims*. Both spawn the real binary against a real origin; Tier
1 answers "how fast", which only a comparison across runs can say, while
Tier 0.5 answers "what did it do", which a single run answers in
equalities a shared runner's noise cannot move.

1. **Deterministic simulation — `zig build sim -- [seed] [iterations]
   [keep-going]`.** `keep-going` names every failing seed in the range
   (up to a cap) instead of stopping at the first, and states the range
   it actually reached: the nightly soak wants that census, because its
   blocks are keyed to the run number and a block abandoned mid-sweep is
   never revisited. `ci` omits it and keeps the first failure, fast.
   The `SimIo` backend (§4) runs the real data path against virtual
   sockets and a virtual clock under a seeded adversarial scheduler:
   partial reads/writes down to 1 byte, delayed/refused/black-holed/
   pressure-failed connects, resets at every point in every exchange,
   misbehaving origins.
   Mixed L4 and L7 clients share one server. L4 clients carry a token
   echoed into the body and verified byte-exact. L7 clients run HTTP
   request scripts — the valid shapes, the §7 reject shapes, and the
   keep-alive/pipelined/silent patterns — against scripted origins
   (sized, chunked, until-close, truncated, reset, mute, and instant
   origins that answer before the request finishes), and every byte they
   receive must be a prefix of a legal transcript. A quarter of seeds run
   clean — adversary off, origin well-behaved — hardening the L7 oracle
   from prefix-legality to each script's exact golden outcome, so a
   silently torn-down exchange that should have been answered fails the
   seed instead of passing as a cut. The origins are oracles too: no
   malformed byte (§7) ever reaches one. Invariants per seed: no slot
   leaks (all pools drain to
   zero), no deadlock, counters reconcile, every shed is witnessed, no
   completion is delivered to a freed or reused slot (slot generations
   checked on every delivery, §5). A failure prints its seed; the same
   seed replays the exact schedule.
   The access log is checked as an *equality*, not a sufficiency: every
   HTTP line is either an outcome the data path counted or an abort, and
   on a clean seed there are no aborts at all. An inequality — "at least
   as many lines as outcomes" — is satisfied by writing too many, which
   is how a phantom line per keep-alive connection once cleared 4096
   seeds.
   Those invariants gate each seed's *shape*; a **coverage census** gates
   the sweep's *reach*. Every counter is totalled across the range, and a
   sweep of at least 1024 seeds fails unless each one fired at least once
   — a rung no scenario reaches is a finding, not silence, and the gate
   cannot claim a path it never walked. Counters the simulator provably
   cannot move (an admin listener it does not configure, a fault it does
   not inject, a volume it cannot reach) are exempted by name in a table
   that says what covers them instead, and the census fails just as loudly
   when an exemption *does* fire — so widening a scenario deletes its
   entry rather than leaving a stale excuse behind. That second half also
   carries the invariants that are *supposed* to read zero: a counter
   whose whole point is to stay at zero is exempted with a reason saying
   so, and the gate then fails the moment it moves.
   `SimIo` counts deliveries per op kind for the same reason, so the
   census covers the §4 seam as well as the §8 ladder — an op no seed ever
   carries is a slice of the seam the gate has never run, and no counter's
   silence would name it.
   `zig build sim -- fuzz` runs forever on entropy-derived seeds.
2. **Fuzzing — `zig build test --fuzz`.** `std.testing.fuzz` on every
   parser edge: HTTP/1.1 head parser, chunked decoder, config parser.
   Assertion: never panic, never overrun a bound, reject-or-parse with no
   third outcome.
3. **The live gate (Tier 0.5) — `zig build smoke`.** The shipped binary,
   on a real kernel, against a real origin, on every change, in under a
   second. It exists because the deterministic gates are exhaustive
   *within* a virtual socket table and a virtual clock, and two shipped
   bugs were neither: a phantom access-log line per keep-alive connection
   (#129) and health probes idling out their whole timeout (#130). Both
   were afterwards teachable to the simulator; neither was caught by it
   first, because each had to be *known* before it could be looked for.
   The origin and the load generator are Zig inside the harness
   (`smoke/`), not nginx and zrk: a per-change gate should add no CI
   dependency, and owning the origin makes its deliveries shapeable,
   which one of the verdicts below is a property of.
   Every verdict is an equality on real output, so a shared runner's
   timing cannot move one. N requests produce exactly N access-log lines,
   with connections closed by the client and connections reaped by the
   drain both witnessed writing nothing. Both of `reconcile`'s identities
   are re-derived from a live `/metrics` scrape — rendered, written to a
   socket, framed by a close, parsed back — which puts the whole admin
   plane (§8's reserved slot, the tree's only asynchronous close op)
   under the same verdict as the arithmetic. The counters must agree with
   the log about the same exchanges. Upstream reuse (§3) must happen, and
   an origin delivery that overruns the head buffer must leave its excess
   in a second write (§7) — the one shape the sweep's census cannot
   reach, and it needs an injected `Connection: close` besides, because a
   rendered head that did not *grow* fits its excess exactly. The
   proxy's resident set must not move across two identical load passes,
   §5's promise witnessed from outside the process.
   The one exception to "equalities" is the health-probe *rate*, and it
   is the exception that proves the rule: #130 was a bug no equality
   could see, because every verdict the prober reached was correct and
   only its rate was wrong. That check is a band — loose enough that
   scheduling cannot move it, decisive because what it is aimed at runs
   two orders of magnitude slow rather than a little slow.
   Every wait in the harness is a wait on the process under test, and
   none can bound itself, so one wall-clock budget covers the run from
   outside: a wedged proxy is killed and reported rather than left to
   hang the build until CI's own timeout kills it with no diagnosis.
   `zig build ci` runs it on Linux only for now: on its first CI run the
   gate found that the macOS leg answers nothing at all to its first L7
   request (#184), which is what a live gate is for and is also a
   different piece of work from building one. `zig build smoke` runs
   everywhere regardless, and restoring the `ci` wiring on macOS is that
   issue's acceptance test.
4. **Benchmarks — [zrk](https://github.com/zoxy-io/zrk), three tiers.**
   The load generator is zrk — a pure-Zig wrk2 rewrite: *constant-throughput*
   (open-loop) pacing with coordinated-omission-corrected HdrHistogram
   latency, so a stalling proxy accrues the stall instead of hiding it.
   h2load returns only if/when HTTP/2 does.
   - **Tier 0 (micro, decision tool) —
     [poop](https://github.com/andrewrk/poop) over `bench/micro/`.**
     Standalone binaries exercising one hot function each (parser wrapper,
     pool acquire/release, relay chunking) in a fixed loop; poop A/Bs two
     builds on hardware counters — cycles, instructions, cache and branch
     misses — the "counters, not vibes" instrument the previous iteration's
     HITM investigation proved necessary. Exists from day 0 so every
     hot-path alternative is decided by measurement; **not a CI gate**
     (counter deltas on shared runners are noise) — the Tier-1 band is
     what merges are held to. hyperfine is not used: wall-time-only, and
     poop subsumes it on Linux.
   - **Tier 1 (merge gate, run on demand) — `bench/run.zig`, loopback.**
     (Tooling in Zig, per TIGER_STYLE — no shell harness.) nginx origin
     (or `--origin host:port`), direct baseline vs proxied path (L4 and
     L7, keep-alive and `Connection: close`), roles pinned to disjoint
     cores. Compare *bands* across runs, never single numbers (p50 swings
     3× between identical back-to-back runs) — which is why this is not a
     blind per-change CI step. A PR that regresses the band explains
     itself or does not merge. The run's *hard* invariants are machine-
     checked and exit non-zero: RSS under the §5 banner total plus a
     fixed slack (the closed form as a ceiling, witnessed from outside —
     the pools are lazily resident, so a saturating warmup drives RSS
     toward the bound first; the shrunken overload band still holds
     *flat* RSS, its whole budget being smaller than the tolerance), a
     clean SIGTERM drain, and a sub-1% proxied socket-error rate.
   - **Tier 2 (comparison, on demand) — same harness + HAProxy.** The dev
     shell provides `haproxy` as a Nix package; the script runs the
     identical scenario through it on the same pinned cores. No
     docker-compose: bridge/veth networking adds virtualization overhead
     to exactly the thing being measured, and Nix already gives
     reproducible binaries. Envoy/Traefik/Caddy comparisons stay out of
     the repo.
   - **Tier 3 (headline numbers) —
     [zoxy-io/benchmark](https://github.com/zoxy-io/benchmark).** The
     multi-host cloud fleet (disjoint hosts, saturation self-checks,
     HAProxy/Envoy/Traefik/Caddy). Run per release, never per PR.

5. **Zero-alloc gate.** The full serving path — including a drain — runs
   in tests under a failing/counting allocator; baseline allocation count
   must equal the final count. Steady state also asserts zero allocating
   syscalls (no mmap/brk after init) via counters.

Alongside the gates, a build-time lint asserts the fd boundary of §4:
`std.posix`/`os.linux` may be named only under `src/io/`, with an
explicit allowlist for `main.zig` startup work (the `RLIMIT_NOFILE`
assert, `sigaction`). Cheap, and it turns "no direct syscalls on the
data path" from prose into CI.

## 10. Module map (target)

```
src/
  main.zig            // startup: config → reserve pools → print memory → run loop
  Server.zig          // composition root: pools, listeners, admission, teardown;
                      // generic over Io so the simulator instantiates it whole
  constants.zig       // every static limit; pool memory is f(these)
  config.zig          // strict JSON → arena-owned immutable Config
  io/
    io.zig            // the seam: comptime backend select
    XevIo.zig         // production: libxev (io_uring / kqueue)
    SimIo.zig         // simulation: virtual sockets + clock + adversary
  mem/
    Pool.zig          // Pool(T): startup alloc, intrusive free list
  net/
    Conn.zig          // connection slot: state, completions, head-ring claim
    proxy_protocol.zig // PROXY v1/v2 parse + write: pure, round-trip-pinned (§6)
    relay.zig         // strict recv→send→recv relay (L4 + L7 bodies)
    upstream.zig      // shared upstream pool + endpoint idle lists + head pool
  http/
    parser.zig        // hparse wrapper: strictness + framing + chunked decoder
    render.zig        // §7 head rendering: hop-by-hop strip + close injection
    router.zig        // §7 path routing: canonical-path longest-prefix table
    proxy.zig         // L7 state machine over phases
  tls/
    Credentials.zig   // per-listener PEM chain + signing key, parsed once (§4)
  balancer.zig        // upstream endpoint pick: rr | p2c | hash (§7)
  shed.zig            // exhaustion ladder: decisions + static responses (incl. configured pages, #159)
  counters.zig        // per-rung counters: loop-written, relaxed-atomic reads
  admin.zig           // admin/metrics listener: one reserved scrape slot (§8)
  access_log.zig      // JSON access log: double-buffered sink, drop rung, named headers (§8)
sim/                  // simulator harness + invariants
smoke/                // the live gate (Tier 0.5): origin + client + verdicts, §9
bench/                // micro benches (poop) + loopback harness (zrk), §9
```

## 11. Key references

- [libxev](https://github.com/mitchellh/libxev) — proactor event loop,
  io_uring/kqueue backends, caller-owned completions.
- Cloudflare, [How we built Pingora](https://blog.cloudflare.com/how-we-built-pingora-the-proxy-that-connects-cloudflare-to-the-internet/)
  and [pingora-proxy phases](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/phase.md)
  — connection sharing across threads, the request-phase model.
- TigerBeetle [TIGER_STYLE](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md)
  and [A Database Without Dynamic Memory](https://tigerbeetle.com/blog/a-database-without-dynamic-memory)
  — static allocation and deterministic simulation discipline.
- [hparse](https://github.com/nikneym/hparse) — pure-Zig SIMD HTTP/1.1
  head parser (zero-alloc, zero-copy); adopted as a hardened fork
  behind the recorded gate in §7.
- [zrk](https://github.com/zoxy-io/zrk) — pure-Zig constant-throughput
  load generator (wrk2 model, coordinated-omission-corrected); the bench
  driver. [zoxy-io/benchmark](https://github.com/zoxy-io/benchmark) — the
  multi-host comparison fleet (Tier 3).
- [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) — HTTP/1.1 framing
  (§6.3) and close announcement (§9.6).
