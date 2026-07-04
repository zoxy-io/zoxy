# zoxy — zero-allocation edge proxy (design)

An L7 edge proxy in the spirit of Envoy/Linkerd, written in Zig 0.16, Linux
only, with a hard constraint: **all memory is reserved at startup; nothing
allocates on the hot path.** Steady-state operation issues zero heap
allocations and zero allocating syscalls.

This document holds the rationale and the record: the decisions that shaped
the code, what shipped, what it measured, and what was learned. The module
map and day-to-day commands live in `CLAUDE.md`; the coding rules in
`docs/TIGER_STYLE.md`.

---

## 1. Guiding decisions

Locked early because they are expensive to retrofit; all six survived contact
with the implementation.

1. **Share-nothing, thread-per-core.** One worker per CPU core, pinned. Each
   owns its listener, its io_uring loop, its pools. A connection is pinned to
   its accepting worker for its whole life → no locks on the data path. The
   only cross-worker state is metrics, and even that is sharded per worker
   (§4).
2. **io_uring via caller-owned completion callbacks** (TigerBeetle's
   `IO`/`Completion` pattern) directly on `std.os.linux.IoUring` — not fibers,
   not the `std.Io` async executor (§3). Every `Completion` is embedded inline
   in connection state → zero per-operation allocation.
3. **Zero-alloc after configuration.** Allocation is permitted during startup
   and config parsing (an arena the `Config` owns); once serving, never.
   Pool exhaustion → **reject/backpressure, never allocate, never grow**.
   Enforced, not aspired to: the test suite runs the full serving path —
   including TLS handshakes and a drain — under a `CountingAllocator` gate
   (baseline count must equal final count).
4. **Backpressure from day one.** One fixed buffer per relay direction,
   strict recv → send → recv: the next chunk is never read until the current
   one is fully written, so a slow destination stalls the source through TCP
   flow control and memory stays bounded per direction regardless of stream
   size (§5).
5. **A narrow resilience seam.** Envoy's filter-chain idea reduced, in
   callback-I/O form, to one per-worker mutable table behind a small
   admission/outcome API (`resilience.zig`) that the data path calls at fixed
   points: admit, pick, dial, settle.
6. **TigerStyle governs the code** (`docs/TIGER_STYLE.md`): static allocation,
   a limit on everything, ≥2 assertions/function, ≤70-line functions, no
   recursion, all errors handled. Not cosmetic — the callback I/O model exists
   partly *because* TigerStyle requires functions to run to completion so
   assertions hold across the whole body.

---

## 2. I/O architecture — the Completion-callback model

```
                per core (thread-per-core, share-nothing)
  ┌───────────────────────────────────────────────────────────────┐
  │  listen fd  ──io.accept──►  single-threaded callback loop     │
  │                                                               │
  │  io.recv ─► parse ─► route ─► io.connect/io.send (upstream)   │
  │   (Completion embedded in ProxyConn)    │                     │
  │   callbacks drained one-by-one from     └─ per-worker         │
  │   an intrusive `completed` FIFO            upstream pool      │
  └───────────────────────────────────────────────────────────────┘
     × getCpuCount(), each pinned via sched_setaffinity
```

- **Caller-owned `Completion`, embedded inline.** Submitting writes the op in
  place; the io_uring `user_data` *is* the `*Completion`. The generic callback
  is type-erased once, so the ring stores one `*anyopaque` + fn pointer.
- **Completions never run inline.** Reaped CQEs (batched, ≤256) go onto an
  intrusive FIFO and run one per iteration — bounded stack, and a callback can
  safely enqueue more work.
- **Concurrency is bounded by the pools, not the ring.** You cannot start more
  ops than the connections that own them; pool exhaustion is the backpressure
  signal.
- **The `IO` type is the portability seam — comptime, no vtable.**
  `io/io.zig` selects the backend by `builtin`: the real `linux.zig`, or
  `test_io.zig` — a deterministic simulation backend (virtual sockets and
  clock, seeded adversarial scheduler) that runs the *real data path* against
  misbehaving virtual clients and origins, with per-seed invariants (no
  deadlock, no leaks, every response parses). CI replays seeds 0..300; any
  failure is a replayable seed. This seam is the single highest-leverage
  testing decision in the project.
- **Plain ops only.** TigerBeetle ships on plain `prep_recv`/`prep_send`, and
  so do we. Registered buffers, buffer rings, multishot, `send_zc`, `splice`,
  and the io_uring setup flags (`SINGLE_ISSUER`/`COOP_TASKRUN`/
  `DEFER_TASKRUN`) are deferred optimizations behind measurement (§7).

Learned the hard way:

- **Teardown must `shutdown(SHUT_RDWR)` both fds before the async close.** An
  io_uring `close` does not cancel a pending `recv` on that fd; without the
  shutdown the recv never completes and the connection slot leaks (a real
  deadlock, found by the simulator).
- **A `Completion` in flight must never be resubmitted** — a double submit
  corrupts the ring (double callback, double refcount). Ops that can overlap
  (per-request close vs teardown close, per-try cancel vs teardown cancel) get
  their *own* completions; the struct grew a field per proven race, each with
  the seed that found it.
- **Cache the clock.** Per-callback vdso `clock_gettime` was ~3% of data-path
  CPU; `IO.now_ns` serves a value refreshed per loop iteration — which is also
  exactly the seam the simulator's virtual clock needs.

---

## 3. What the Zig 0.16 std landscape ruled out

Verified against the pinned toolchain (not guessed); the reasons we go direct
to the kernel:

- **`std.Io.Threaded`** is thread-per-task and allocates per task — not a
  many-connection core.
- **The evented executor (`std.Io.Uring`) has stubbed networking**: the vtable
  wires `netAccept`/`netConnectIp`/`netSend` to stubs returning
  `error.NetworkDown`. It is also a work-stealing scheduler (conflicts with
  share-nothing pinning) and hides the ring.
- **`std.Io.Reader` erases `WouldBlock`** ([ziglang/zig#25047]) — usable for
  parsing out of a buffer we filled, never for the socket edge.
- **`std.crypto.tls` is client-only** ([ziglang/zig#14171]) — TLS termination
  requires FFI (§6).
- 0.16 removed `std.Thread.Mutex` and `std.time.Timer`; their replacements
  want an `std.Io` instance the workers deliberately don't carry → a raw-futex
  mutex (`mem/futex_mutex.zig`, off the data path only) and the `IO.now_ns`
  clock seam.

---

## 4. Memory architecture

Everything is reserved once at startup; `src/constants.zig` holds every static
limit, so sizing the proxy is choosing those numbers and total memory is a
function of them.

- **`Pool(T)`**: one startup allocation + an intrusive free list; acquire and
  release never allocate; LIFO reuse keeps a released slot's lines warm. An
  `in_use` marker makes every slot classifiable (drain sweeps, diagnostics).
- **Buffers live inside `ProxyConn`** — head buffer, two relay buffers, a
  dozen named `Completion`s — one contiguous object per connection slot.
- **`config.zig` owns the only allocating arena.** Parse-time work (including
  the Maglev tables) allocates there; the result is immutable and shared
  read-only by every worker.
- **The TLS heap** (§6) extends the rule across FFI: a fixed size-class heap
  behind OpenSSL's global memory hook, reserved as
  base + per-connection × slots (measured: ~161 KiB per live TLS connection).
  Exhaustion fails that OpenSSL call → the handshake is load-shed. Never OOM,
  never growth.
- **Cache-line isolation for per-worker state** (learned 2026-07-04). Logical
  share-nothing is not physical share-nothing: the shared `Metrics` struct
  and the arrays of per-worker pool headers / access logs put multiple
  writers' data on the same cache lines. Fixed by sharding metrics per worker
  (single writer per shard, readers sum) and `mem/cache_line.zig`'s
  `Padded(T)` (over-align to `std.atomic.cache_line` = 128, covering the
  adjacent-line prefetcher). Proven with hardware counters, not vibes:
  RFO-snoop-HITM fell ~60× (metrics) and load-HITM ~50× (pool headers, under
  churn). Two lessons: **single-writer beats clever synchronization** — the
  fix removed contention rather than optimizing it; and **match the gate
  workload to the suspect line** — pool-header sharing was invisible under
  keep-alive (headers move at connection setup) and unmistakable under
  `Connection: close` churn.

---

## 5. Data path (HTTP/1.1)

```
accept → recv head → parse (zero-copy slices) → route (host/path → cluster)
       → balancer pick → upstream pool checkout | io.connect
       → forward head+body → parse response head → framed relay back
       → reuse both connections (keep-alive) | teardown
```

- **Custom zero-copy parser** (picohttpparser-style): linear buffer, bounded
  `[headers_max]Header` inline array, separate incremental chunked decoder.
  Full control over limits and smuggling hardening; no `std.Io` coupling.
  Oversize head → 431; header overflow → reject, never grow.
- **Both directions are framed** (RFC 9112 §6.3: Content-Length / lone
  chunked): each side knows where the message ends, so an upstream that
  ignores `Connection: close` cannot pin a slot, and bytes past a message end
  (a pipelined next request) are never forwarded. Smuggling shapes (TE+CL,
  duplicate/garbage Content-Length) are rejected with 400 before any byte
  reaches an upstream. `Upgrade` → 501.
- **Keep-alive on both sides.** Downstream: every request on a kept
  connection is re-parsed and re-routed; pipelined bytes slide to the front of
  the head buffer. Upstream: a framed, reusable response parks its connection
  in a bounded per-worker pool keyed by endpoint; a connection the origin
  closed while parked fails on first use *before* any response byte and is
  replayed once on a fresh dial (only when the request was fully replayable).
  Hop-by-hop headers are stripped both ways.
- **Backpressure** is §1.4 verbatim in the relay (`Pipe`): strict
  recv → send → recv over one fixed buffer per direction — stronger than
  watermark read-disable, because there is no read-ahead to disable.
- **Closing must be announced** (learned): a relayed response the proxy will
  close after gets `Connection: close` injected if the origin's head lacked
  it (RFC 9112 §9.6) — without it, clients assume keep-alive, pipeline the
  next request, and read the close as an error. Found as ~1 read error per
  request in churn benches; zrk's error counters catch protocol bugs that
  throughput numbers hide.

---

## 6. TLS — OpenSSL for the handshake, kTLS for the record layer

**Why OpenSSL** (surveyed 2026-07): it is the only mature server-side stack
whose memory we can pool and gate — `CRYPTO_set_mem_functions` routes every
allocation into our reserved heap. BoringSSL removed that hook, `rustls-ffi`
drags in the Rust allocator, and the pure-Zig options are client-only or
unaudited-minimal (recheck if TLS lands in std). Vendored via the
[allyourcodebase/openssl] build recipe — the project's one dependency beyond
the Zig toolchain, and the zero-alloc invariant survives the FFI boundary
because of the hook. **Install the hook before any other OpenSSL call**;
OpenSSL refuses it after its first allocation.

**Sans-io shape.** `tls/terminator.zig` splits policy from transport:
`Context` (an immutable SSL_CTX — identity install + cross-check at startup so
a bad cert kills boot, ALPN preferring `http/1.1`, session cache/tickets off
so one context serves every worker) and `Channel` (per-connection SSL over a
fixed-size memory-BIO pair). OpenSSL never sees a socket: ciphertext shuttles
between the pair and the ring through the connection's fixed buffers, so
run-to-completion holds and the handshake is deterministically testable down
to 1-byte adversarial delivery. SNI selects among explicit config-declared
`server_names` (exact + `*.` wildcards); absent/unmatched SNI gets the default
identity, never a fatal alert.

### kTLS design

After the handshake, the record layer moves into the kernel and the
steady-state relay becomes byte-identical to plaintext — plain `io.recv`/
`io.send` on the fd, kernel does AES-GCM, and the ~161 KiB channel is freed
mid-connection.

- **Keys without a rebuild**: `SSL_CTX_set_keylog_callback` yields the TLS 1.3
  traffic secrets; `std.crypto.tls.hkdfExpandLabel` derives key/IV (unit-tested
  against the RFC 8448 vectors); one `setsockopt(TCP_ULP "tls")` +
  `TLS_TX`/`TLS_RX` installs them. (The alternative — OpenSSL-driven
  `SSL_OP_ENABLE_KTLS` — was rejected: it requires a socket BIO at
  cipher-install time, i.e. a second I/O model in the worker, plus a vendored
  rebuild.)
- **Sequence numbers eliminated, not computed**: switch only when zero
  application-epoch records have flowed in either direction — TX trivially
  (before the first `SSL_write`), RX by checking that the wire staging, the
  BIO pair, and the SSL's internal buffer are all empty. All empty ⇒ both
  sequences are exactly 0. A client that pipelined a request into the
  handshake flight simply stays on the BIO-pair relay: **a missed switch
  costs performance, never correctness**, because the fallback is the
  already-shipped path.
- **Consequences owned**: post-switch control records (client KeyUpdate,
  close_notify) surface as recv errors → teardown; our own polite close sends
  the alert via a `TLS_SET_RECORD_TYPE` cmsg (`sendmsg` ring op). Any
  setsockopt failure falls back to the pair relay, counted
  (`zoxy_tls_ktls_active`/`_fallbacks`).
- **Measured** (A/B, R=20k c=64): latency bands identical; zoxy CPU ~10%
  lower with kTLS (copy elimination, not crypto — both sides run AES-GCM at
  native speed); TLS heap carve 11.1 → 4.9 MiB. Real clients switch 100%.

**Upstream re-encryption.** A cluster `tls` block demands an explicit
verification posture: `ca_file` + `server_name` (verified via `SSL_set1_host`,
offered as SNI), or a spelled-out `"insecure": true` — halves and mixes are
refused at parse. The TLS driver is leg-parameterized: the downstream leg's
failures tear down, the upstream leg's failures are attempt failures (502,
retryable). Upstream channels park in the connection pool alongside the fd,
but only fully quiescent (the same emptiness check as the kTLS switchover) —
leftover bytes would corrupt the next response, so closing is the safe answer.
**No upstream kTLS**: origins send session tickets as application-epoch
records, which defeats the sequence-zero rule; the upstream leg stays on the
BIO pair. Measured: double-TLS chain at 20k req/s, p50 138µs —
plaintext-level.

**TLS ≈ plaintext in steady state** (band-gated): identical throughput, p50
within a few µs. The one systematic tail (a constant ~32ms p99.9 in short
runs) was proven to be the startup handshake burst under coordinated-omission
correction, not a relay stall — it dilutes with run length. A
constant-across-runs tail is a systematic effect; a spread is variance.

HTTP/2 & HTTP/3: nothing usable in pure Zig; `nghttp2` / `quiche` FFI when
their phases arrive.

---

## 7. Build history & roadmap

Each phase shipped behind a measured gate (zrk, constant-throughput,
coordinated-omission-corrected; run *bands* compared, never single runs —
p50 on this box swings 3× between back-to-back identical runs).

### Phase 0 — minimal viable proxy (done)
Thread-per-core io_uring loop, static config, one request per connection,
counters + admin plane, the zero-alloc gate, `bench/run.sh`. ~30k req/s.

### Phase 1 — HTTP/1.1 keep-alive (done)
Response framing, downstream keep-alive, bounded upstream pool, per-request +
idle timeout split. ~30k → ~90k+ req/s sustainable; the proxied hop costs
~+400µs p50 at 60k. Connection reuse was the single biggest performance lever
in the project. War stories now encoded in code: **TCP_NODELAY** (Nagle +
delayed ACK cost warm pooled connections a hard 40ms per request — invisible
on fresh connections, so always bench the pooled path), and the
**single ticking deadline timer** (one timeout op per connection re-checks an
absolute deadline; phase transitions just move the deadline — no cancel/re-arm
races, at the cost of one tick of slop).

### Phase 2 — resilience (done)
P2C least-request balancing, active TCP health checks, passive outlier
ejection, circuit breakers, two-tier retries (free stale-pool replay +
budgeted jittered-backoff retries), per-try timeout riding the existing
ticking timer. All mutable state in one per-worker table (§1.5). Happy path
measured ~free (bands identical). Deliberate deltas from Envoy, simplicity
first: per-worker limits and budgets; endpoints start healthy; zero available
endpoints fails open and routes anyway; idle pooled fds excluded from
max_connections; per-try timeout arms only for replayable requests. The
simulator asserts every resilience counter drains to zero under every seed.

### Phase 3 — TLS (done; H2 deferred to Phase 5)
§6 end to end: FFI heap + hook, BIO-pair terminator, kTLS switchover, SNI,
upstream re-encryption. H2 was consciously deferred past operability: drain
and hot restart change how the proxy runs in production *today*, and accept
balancing is a prerequisite for H2's few-hot-connections traffic shape.

### Phase 4 — operability (done)
- **Graceful drain**: signalfd on main, per-worker socketpair pokes (a signal
  becomes an ordinary ring completion — no new IO op, and the simulator needs
  no fd), polite closes with close_notify / §9.6 injection, and no new timer:
  the drain deadline clamps each connection's existing deadline. A worker
  exits only when every slot is back and zero server ops are in flight.
- **Hot restart**: listener fds cross a unix socket in one `SCM_RIGHTS` cmsg,
  validated (`getsockname` + `SO_ACCEPTCONN`) before adoption; duplicates keep
  the accept queues alive across the pair, closing the drain RST window.
  Counter totals ride behind the header as name-keyed records
  (version-skew-tolerant; gauges reset). Lesson: **post-adoption startup
  failures are the dangerous class** — a successor that dies after adopting
  takes both processes' accept queues down; order everything fallible before
  the adopt, and every listener (admin included) carries SO_REUSEPORT so the
  restart pair can overlap.
- **Accept balancing**: the SO_REUSEPORT hash is uniform at large N but
  small-sample variance pins long-lived connections (measured: hottest worker
  23% of 64 connections; the system saturates when *it* does). Config
  `accept_mode = "shared"`: one listener, every worker holds a pending accept,
  idle workers naturally pull more (hottest ≤12/64 vs 14–15). Default stays
  `reuseport`.
- **Maglev consistent hashing**: per-cluster prime-sized tables (65,537 × u8)
  built at config time; the data path is one wyhash + one index. Availability
  is enforced at lookup by a deterministic forward walk (consistent across
  workers and time), not by table rebuild; fail-open routes to the home
  endpoint, affinity intact. Ring hash rejected: same guarantee, O(log n)
  lookups, worse balance per byte.
- **Mechanical sympathy** (post-Phase 4): metrics sharding + cache-line
  padding, gated with hardware HITM counters (§4).

### Phase 5 — HTTP/2 (planned)
Per-stream state machines, dual-level flow control into the existing
backpressure model, HPACK, multiplexed pooling with GOAWAY draining.

### Phase 6 — dynamic config (planned)
xDS-style client or simpler custom protocol; apply via RCU pointer swap
(build immutable config off-path, atomic publish) so the data path stays
lock-free.

### Deferred improvements (recorded decisions, revisit on evidence)
- io_uring setup flags (`SINGLE_ISSUER` | `COOP_TASKRUN` | `DEFER_TASKRUN`)
  and the op-level upgrades (multishot accept/recv, buffer rings, `send_zc`,
  `splice`) — deferred 2026-07-04; the proxy is not CPU-bound on the dev box.
- NUMA-aware first touch (pools are faulted on main before workers pin;
  single-socket assumption today) and the inline `?Tls` footprint in
  `ProxyConn` (~74 KiB reserved even for plaintext deployments).
- TLS density: `SSL_MODE_RELEASE_BUFFERS`, tighter BIO sizing, session
  resumption (shrinks the handshake-burst tail).
- `SO_ATTACH_REUSEPORT_EBPF` round-robin accepts (needs CAP_BPF).
- Retry-on-5xx (needs response-head re-buffering analysis), HTTP health
  probes, config endpoint weights / peak-EWMA (least-request self-adapts;
  cross-multiply hook documented in `balancer.zig`).
- Distributed tracing + Prometheus histograms — earn their complexity with
  Phase 6 or multi-hop deployments.

---

## 8. Key references

Patterns adopted:

- TigerBeetle [TIGER_STYLE](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md)
  and ["A Database Without Dynamic Memory"](https://tigerbeetle.com/blog/a-database-without-dynamic-memory)
  — the static-allocation discipline and the `IO`/`Completion` pattern
  (`src/io/` in their tree is the direct ancestor of ours).
- Envoy [life of a request](https://www.envoyproxy.io/docs/envoy/latest/intro/life_of_a_request),
  [connection pooling](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/connection_pooling),
  and [flow control](https://github.com/envoyproxy/envoy/blob/main/source/docs/flow_control.md)
  — the resilience vocabulary (breakers, outlier ejection, retry budgets) and
  the thread-per-core model.
- Linkerd [under the hood of linkerd2-proxy](https://linkerd.io/2020/07/23/under-the-hood-of-linkerds-state-of-the-art-rust-proxy-linkerd2-proxy/)
  — P2C least-request balancing.
- ["Maglev: A Fast and Reliable Software Network Load Balancer"](https://research.google/pubs/pub44824/)
  (§3.4 is the table-population algorithm) and Mitzenmacher,
  ["The Power of Two Choices in Randomized Load Balancing"](https://www.eecs.harvard.edu/~michaelm/postscripts/tpds2001.pdf).
- [picohttpparser](https://github.com/h2o/picohttpparser) and
  [karlseguin/http.zig](https://github.com/karlseguin/http.zig) — zero-copy
  parser shape and production Zig allocation patterns.

Specs and kernel interfaces:

- [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) (HTTP/1.1: §6.3 body
  framing, §9.6 close announcement), [RFC 8448](https://www.rfc-editor.org/rfc/rfc8448)
  (TLS 1.3 trace vectors, used as HKDF unit tests).
- [Kernel TLS](https://docs.kernel.org/networking/tls.html) — `TCP_ULP`,
  `TLS_TX`/`TLS_RX`, `TLS_SET_RECORD_TYPE`.

Zig 0.16 landscape (the basis of §3):

- [0.16.0 release notes](https://ziglang.org/download/0.16.0/release-notes.html);
  [ziglang/zig#25047] (Reader erases `WouldBlock`);
  [ziglang/zig#14171] (no TLS server in std).

Tooling:

- [allyourcodebase/openssl] — the vendored OpenSSL build recipe
  (`third_party/openssl`, with local duplicate-symbol fixes).
- [zrk](https://github.com/floatdrop/zrk) — constant-throughput,
  coordinated-omission-corrected load generator; every number in §7 comes
  from it.

[ziglang/zig#25047]: https://github.com/ziglang/zig/issues/25047
[ziglang/zig#14171]: https://github.com/ziglang/zig/issues/14171
[allyourcodebase/openssl]: https://github.com/allyourcodebase/openssl
