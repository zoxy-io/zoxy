# zoxy — zero-allocation edge proxy (design)

An L7 edge/mesh proxy in the spirit of Envoy/Linkerd, written in Zig 0.16, with a
hard constraint: **all memory is reserved at startup; nothing allocates on the
hot path.** Steady-state operation issues zero heap allocations and zero
allocating syscalls.

> Status: design/plan. Nothing here is built yet. Every Zig-0.16 API name below
> was gathered from release notes + `master` std (0.16 is barely tagged) and
> must be verified against the pinned toolchain before coding.

---

## 1. Guiding decisions (lock these early — expensive to retrofit)

1. **Share-nothing, thread-per-core.** N worker threads = CPU cores. Each owns
   its own listener (`SO_REUSEPORT`), its own event loop, its own memory pools.
   A connection is **pinned to its accepting worker for its whole life**. No
   shared mutable state on the data path → no locks in steady state. (Envoy and
   NGINX both do this.)
2. **io_uring via caller-owned completion callbacks** (TigerBeetle's `IO` /
   `Completion` pattern) directly on `std.os.linux.IoUring` — **not** fibers and
   **not** the new `std.Io` async executor (see §3, §I/O). Each `Completion` is
   embedded inline in the owning connection → zero per-operation allocation.
3. **Zero-alloc after configuration** (the boundary, TigerBeetle's rule).
   Allocation is *permitted during startup and (re)configuration* — the config
   parser may allocate freely, and a config reload builds a new immutable config
   off the hot path. Once the proxy is configured and serving, **no allocation on
   the data path, ever.** Concretely: fixed `Connection` pool sized to
   `connections_max`; per-connection buffers carved from a startup slab.
   Exhaustion → **reject/backpressure, never allocate**. A `FailingAllocator`
   guards the serving path in debug/test builds; startup allocators are handed a
   real `gpa` and then put away before the loop starts.
4. **Backpressure from day one.** The relay uses a strict single fixed buffer
   per direction (recv → send → recv): we never read the next chunk until the
   current one is fully written, so memory is bounded to `relay_buf_bytes` per
   direction regardless of stream size and TCP flow control throttles the peer.
   This is *stronger* than watermark read-disable (which only matters when
   reading ahead into a growable buffer); read-ahead + watermarks is a later
   throughput option we deliberately skip. Retrofitting flow control is painful,
   so it's built in; it also *is* the zero-alloc story (bounded buffers push flow
   control down to TCP).
5. **A filter/middleware seam early.** An Envoy-style filter chain (or Tower-style
   Service/Layer) so routing, auth, retries, timeouts compose cleanly.
6. **TigerStyle governs the code.** See `docs/TIGER_STYLE.md`: static allocation,
   a limit on everything, ≥2 assertions/function, ≤70-line functions, no
   recursion, callbacks-not-coroutines, all errors handled. This is not
   cosmetic — the callback I/O model (below) exists partly *because* TigerStyle
   requires functions to run to completion without suspending so assertions hold.

---

## I/O architecture — the Completion-callback model

We copy TigerBeetle's `IO`/`Completion` design (the origin of Zig's own
`std.os.linux.IoUring`). It is the proven zero-alloc answer to "async over
io_uring", and it resolves the fiber-vs-manual-loop dilemma from §3.

- **Caller-owned `Completion`, embedded inline.** Each connection statically owns
  its `recv_completion`, `send_completion`, `timeout_completion` fields. Submit
  calls write the op in place — `completion.* = .{ … }` — and never allocate. The
  io_uring `user_data` *is* the `*Completion`; the callback recovers the owning
  connection with `@fieldParentPtr`.

  ```zig
  io.recv(*Connection, conn, Connection.on_recv, &conn.recv_completion, conn.fd, conn.read_buf);
  // on_recv(conn: *Connection, c: *Completion, result: RecvError!usize) void { … }
  ```
- **Type-erase the generic callback once** (TB's `erase_types`) so the ring stores
  a single `*anyopaque` context + opaque fn-ptr. `Context` must be a pointer.
- **Completions never run inline.** Drained CQEs are pushed onto an intrusive
  `completed` FIFO and run one-per-`run_callback` — bounds stack usage, keeps
  traces clean, and lets a callback safely enqueue more work.
- **Drive with `run_for_ns(deadline)`**: skip kernel-blocking while callbacks are
  pending (they may enqueue more), else block until the next event/deadline.
  `next_tick` schedules a deferred callback with no kernel I/O (timers, retries).
- **Concurrency is bounded by a fixed `Completion` pool, not the ring.** You can
  never start more ops than you pre-allocated Completions/buffers at startup →
  the ring can't be overrun by app logic; pool exhaustion is the backpressure
  signal. Handle SQ-full defensively (flush + retry). Batch CQE reaping (≤256 at
  a time, like TB).
- **Swappable `IO` interface → deterministic testing later.** Because the data
  path talks to an `IO` interface, we can drop in a seeded mock `IO` and run a
  deterministic simulator (TigerBeetle's VOPR approach). Design for this now even
  if we build it in a later phase.
- **Kernel floor: Linux ≥ 5.11** if we adopt the `IORING_ENTER_EXT_ARG` timeout
  trick (pass the loop deadline into `io_uring_enter`, no separate timeout SQE).

### Start plain; optimize later (verified against TB `src/io/linux.zig`)
TigerBeetle itself uses **plain `prep_recv`/`prep_send`/`prep_read`/`prep_write`**
— **no** registered/fixed buffers, **no** buffer rings, **no** `send_zc`, **no**
`splice`, **no** multishot. So those are **Phase-later optimizations**, not
foundations. Ship the plain path first, measure, then reach for registered
buffers / `splice` on the relay fast path only if the envelope says it pays.

---

## 2. Concurrency & I/O model

Each core runs **its own single-threaded TigerBeetle-style callback loop** —
own `IO`, own `Completion`/buffer/connection pools, share-nothing. This is
TB's single-threaded determinism model *replicated per core*, which is also the
Envoy/NGINX thread-per-core model. No locks on the data path.

```
                per core (thread-per-core, share-nothing)
  ┌─────────────────────────────────────────────────────────────┐
  │  SO_REUSEPORT listen fd  ──io.accept──►  single-threaded loop │
  │                                                               │
  │  io.recv ─► parse ─► route ─► io.connect/io.send (upstream)   │
  │   (Completion embedded in Connection)   │                     │
  │   callbacks drained one-by-one from     └─ per-core H1 pool   │
  │   an intrusive `completed` FIFO                               │
  └─────────────────────────────────────────────────────────────┘
     × getCpuCount(), each pinned via sched_setaffinity (Linux)
```

Baseline (what we build first — matches TB's actual backend):

- **Accept:** each worker binds its *own* listen fd with `SO_REUSEPORT` set
  **before** `bind` (via `std.posix`, since `std.net.Server` doesn't expose it),
  then `io.accept(&accept_completion, …)`, re-arming in the callback. Kernel
  load-balances across workers.
- **Read/write:** plain `io.recv`/`io.send`/`io.read`/`io.write` into the
  connection's fixed buffers. Each op uses the connection's inline `Completion`.
- **Kernel floor:** Linux ≥ 5.11 (`IORING_ENTER_EXT_ARG` timeout trick).

Deferred optimizations (only if the envelope justifies — TB does **not** use
these; add behind measurement):

- `accept_multishot` / `recv_multishot` + provided **buffer rings**
  (`setup_buf_ring`, `BufferGroup`) — kernel-picked buffers, fewer re-arms
  (≥ 5.19).
- `send_zc` (zero-copy send) and **`splice`** (fd→pipe→fd) for the pure L4 relay
  fast path (≥ 6.0).
- `register_buffers` + `read_fixed`/`write_fixed`, `register_files_sparse` for
  direct descriptors. Feature-probe with `get_probe()` / `ring.features`.

### Portability seam — comptime, not a runtime `Reactor`
The `IO` type **is** the seam (TigerBeetle pattern); there is **no** separate
`Reactor` interface or vtable. `io/io.zig` selects the backend at comptime —
`switch (builtin.target.os.tag) { .linux => @import("linux.zig"), .macos =>
@import("darwin.zig"), … }` — and every backend exposes the same method set
structurally (no interface file, no runtime dispatch, fully inlined). Linux =
`std.os.linux.IoUring`; macOS/BSD dev = a kqueue backend.

- **Test substitution is also comptime:** make hot-path structs generic over the
  `IO` type so the deterministic simulator can pass `io/test_io.zig` (mock IO).
- **No runtime backend fallback.** Hard-require io_uring (Linux ≥ 5.11). If a
  runtime `--io-backend` fallback (e.g. epoll on old kernels) ever becomes a real
  requirement, add a *localized* vtable at the loop boundary then — not
  preemptively.
- We do **not** depend on libxev or `std.Io.Evented`; the TB-style `IO` layer
  replaces both. (libxev remains a reference for zero-alloc proactor design.)

---

## 3. What NOT to build on (traps confirmed by research)

- **`std.Io.Threaded`** (the only complete `std.Io` backend) is
  **thread-per-task and allocates per task** — ~10k sleeping tasks ≈ 20s, ~50k
  hits OS thread limits. Not a many-connection core.
- **The evented executor (`std.Io.Uring` / `std.Io.Kqueue`) has stubbed
  networking in 0.16.0 — verified against the pinned toolchain.** In
  `lib/std/Io/Uring.zig` the `Io` vtable wires `netListenIp`/`netAccept`/
  `netConnectIp`/`netListenUnix`/`netConnectUnix`/`netSend` to `*Unavailable`
  stubs that `return error.NetworkDown` (or `AddressFamilyUnsupported`). `bind`,
  `socket`, `getsockname` and all file/process ops are real, but **you cannot
  accept or dial a TCP connection through it today.** Don't build the data path
  on it yet. Worth tracking: its design is good (see below).
- The evented executor's *design* is promising once net ops land: `init` takes
  an **injectable `backing_allocator`**; fibers are **pooled on a per-thread
  `free_queue`** (cross-thread work-stealing), `destroy` recycles rather than
  frees, and `create` only allocates on a new concurrency high-water-mark → after
  warmup, **steady state is zero-alloc**; pool exhaustion = natural backpressure.
  Two frictions with our thesis: (a) each fiber reserves **`min_stack_size =
  60 MiB` virtual** stack (mmap/lazy-commit) → must back it with `page_allocator`
  or a capped mmap-slab, **not** a flat `FixedBufferAllocator`; high fan-out means
  large virtual reservations (watch `vm.max_map_count`/overcommit). (b) It is a
  **work-stealing scheduler** (fibers migrate cores) which conflicts with our
  share-nothing per-core pinning, and the `Io` interface **hides the ring** so
  `send_zc`/`splice`/registered-buffers/buffer-rings aren't reachable through it.
  → Plan: write handlers *colorless* against the `Io` interface but run them on a
  working backend now (manual io_uring, or `zio` — Lalinský's drop-in `std.Io`
  io_uring backend); swap to `std.Io.Uring` when its net ops land. Keep manual
  io_uring for the zero-copy data path if that control is load-bearing.
- **`std.Thread.Pool.spawn`** allocates a closure per task → never call it
  per-connection. Spawn workers **once**, run per-worker loops.
- **`std.Io.Reader` erases `error.WouldBlock` → `error.ReadFailed`**
  ([ziglang/zig#25047]). On non-blocking sockets, do the socket-edge reads with
  **`std.posix.recv`/`read` directly**, then feed the fixed buffer into a
  `std.Io.Reader` for *parsing* only.
- **TLS termination is impossible in std.** `std.crypto.tls` is **client-only**
  (no `tls.Server`, tracking issue [#14171] unstarted; no private-key/PEM
  loading). → TLS termination needs C FFI (see §6).

---

## 4. Memory architecture (the zero-alloc core)

Everything below is allocated **once** at startup from a general allocator, then
the general allocator is put away.

```
Startup budget (asserted at init):
  max_connections * (sizeof(Connection)
                     + read_buf_bytes + write_buf_bytes)
  + buffer_ring_bytes
  + route_table + cluster_table + endpoint_tables
  + config double-buffer
```

- **Connection pool:** `MemoryPoolExtra(Connection, .{ .growable = false })`
  preheated to `max_connections`, **or** a flat `[max_connections]Connection`
  slab + an intrusive free list (`std.SinglyLinkedList`, node embedded in
  `Connection`, recovered via `@fieldParentPtr`). `create()` → `OutOfMemory`
  ⇒ **close the new socket** (backpressure), never grow.
- **Per-connection buffers:** one contiguous slab `max_connections * buf_size`;
  each connection's read/write windows are slices indexed by slot (better
  locality, single allocation). Buffers live in **static/heap-slab storage, never
  as function-local arrays** (large `[N]u8` locals blow the thread stack).
- **Ring/FIFO:** per-direction linear buffer with memmove-compaction (a linear
  buffer keeps zero-copy header slices contiguous; a byte-ring breaks that).
- **Scratch per request:** `ArenaAllocator` over a `FixedBufferAllocator` over a
  fixed slab; `arena.reset(.retain_capacity)` between requests — zero-cost reuse,
  can never exceed its FBA budget.
- **Tables:** `StaticStringMap` for comptime-fixed routes; for runtime-but-bounded
  tables, `*Unmanaged` hash maps with `ensureTotalCapacity(max)` at startup, then
  **only** `putAssumeCapacity` (any growth = rehash = allocation → forbidden).
- **Cross-thread work** (rare): hand-rolled SPSC ring (`[N]T` power-of-two +
  atomic head/tail, acquire/release) or intrusive MPSC; nodes live in the items.
- **Config reload:** build a new immutable `Config` off the hot path, publish via
  `@atomicStore(*const Config, .release)`; readers `@atomicLoad(.acquire)`.
  RCU-style, lock-free; reclaim old config after a grace period. (Envoy's
  thread-local-slot swap; NGINX's fork-new-workers.)
- **The guard:** wrap the hot-path allocator in `std.testing.FailingAllocator`
  (`fail_index = 0`) in tests; run the whole request path under it. Any
  accidental allocation becomes a hard, testable failure.

Hidden-allocation watchlist: `std.http.Client` (allocates — use the *Server*
side only), `std.crypto.tls` record buffers, `std.fmt`/`std.json` string
building (use `bufPrint`, not `allocPrint`), any `HashMap.put` that rehashes.

---

## 5. Data path (HTTP/1.1 first)

```
accept → recv (provided buffer) → parse req line + headers (zero-copy slices)
       → route (host + path prefix → cluster)
       → LB pick endpoint → per-worker H1 conn pool (no pipelining)
       → forward headers+body → stream response back (encoder reverse order)
       ↕ watermark backpressure couples both directions
```

- **Parser (decided): custom zero-copy parser.** picohttpparser/swerver-style:
  linear buffer, bounded inline `[headers_max]Header` array, memmove refill,
  separate chunked state machine — parses directly out of the connection's fixed
  read buffer (fed by the io_uring read edge, sidestepping the `std.Io.Reader`
  `WouldBlock` erasure). Full control over zero-copy, limits, and smuggling
  hardening; no std.Io coupling. Reference:
  `justinGrosvenor/swerver` (explicit zero-heap, Zig 0.16),
  `karlseguin/http.zig` (production-proven allocation pattern).
- **Header limits:** `max_head_len` fits the fixed buffer; oversize → **431**.
  Bounded `max_headers`; overflow → reject, don't grow.
- **Lifetime rule:** header slices are valid only while the buffer is unmodified
  → any thread hand-off requires a copy (we avoid hand-off: connection-pinned).
- **Connection reuse (Phase 1, done):** both messages are framed per RFC 9112
  §6.3 (Content-Length / lone-chunked; close-delimited responses fall back to
  a forced close), so both sides of the proxy reuse connections. Downstream:
  an HTTP/1.1 keep-alive client keeps its connection — each request is
  re-parsed and re-routed, pipelined bytes slide to the front of the parse
  buffer, hop-by-hop headers are stripped in both directions. Upstream:
  requests are forwarded without a `Connection` header (1.1 default
  keep-alive) and a framed, close-free response parks its connection in a
  bounded per-worker, per-endpoint idle pool; a connection the upstream
  closed while parked fails on first use and is retried once on a fresh dial
  (only when the request was fully replayable from the parse buffer).
  Smuggling-shaped request framing (TE+CL, duplicate/garbage Content-Length)
  is rejected with 400 before any byte reaches an upstream. `Upgrade` is
  still refused with 501; unframeable exchanges close both sides.

---

## 6. TLS (Phase 3 — OpenSSL FFI for the handshake, kTLS for the record layer)

std cannot terminate TLS. Options, re-surveyed 2026-07:

| Path | Alloc control | Server maturity | Verdict |
|------|---------------|-----------------|---------|
| **OpenSSL** FFI | ✅ `CRYPTO_set_mem_functions` (global alloc hook) | mature | **chosen** — the only mature stack whose memory we can pool and gate; `allyourcodebase/openssl` builds on 0.16 |
| **BoringSSL** FFI | ❌ (upstream refuses hook) | mature | allocations invisible to our gate — disqualified |
| **ianic/tls.zig** | pure Zig, allocator-threaded API | TLS 1.3 only, "minimal"; no documented server SNI/ALPN | stream-owning (wants the socket), not sans-io; unaudited. Recheck when its std upstreaming ([ziglang/zig#23005], open) lands |
| `rustls-ffi` | ❌ global Rust alloc | experimental server | second FFI ecosystem for less server maturity |
| BearSSL / wolfSSL / s2n-tls | BearSSL truly static | 1.2-only+stagnant / GPL-or-commercial / needs a libcrypto anyway | each fails one hard constraint |

**Decision: OpenSSL terminates the handshake; kTLS carries the bytes.**

- *Handshake* (sans-io): ciphertext shuttles through **memory BIO pairs** —
  every real read/write stays a ring op on our fixed buffers, OpenSSL never
  sees a socket, run-to-completion holds. SNI selects the cert (from
  ClientHello), ALPN negotiates `http/1.1` (later `h2`).
- *Record layer*: after the handshake, hand the negotiated keys to the kernel
  (`setsockopt` `TLS_TX`/`TLS_RX`, kernel TLS) and the existing relay runs
  **unchanged** — plain `io.recv`/`io.send` on the same fd, kernel does
  AES-GCM. OpenSSL is out of the steady-state picture. BIO-pair relay remains
  as the fallback when the kernel/cipher combination lacks kTLS.
- *Allocation*: `CRYPTO_set_mem_functions` routes OpenSSL into a fixed arena
  reserved at startup and wired into the `CountingAllocator` gate. This is the
  invariant stated precisely: **no allocation outside pre-reserved pools** —
  OpenSSL may suballocate within its arena per handshake, and arena exhaustion
  **rejects that handshake** (load-shedding, like every other pool here),
  never OOM, never growth.
- *Testing*: the simulator keeps exercising the plaintext data path (TLS is a
  byte-transform at the edge); the BIO-pair handshake driver is pure
  bytes-in/bytes-out and gets its own deterministic unit tests (seeded RNG via
  `RAND_set_rand_method`).

### kTLS design (slice 3 — decided 2026-07-04)

Two ways to get the negotiated keys into the kernel were examined:

**A. OpenSSL-driven** (`SSL_OP_ENABLE_KTLS`): OpenSSL configures the socket
itself during the handshake. Rejected for zoxy's shape. It requires the SSL
to sit on a *socket* BIO at cipher-install time, so the handshake would run
on OpenSSL's own read/write syscalls against a non-blocking fd, driven by a
new readiness op (`IORING_OP_POLL_ADD`) — a second I/O model inside the
worker and a simulation-backend op nothing can exercise. It also needs the
vendored OpenSSL rebuilt (`OPENSSL_NO_KTLS` is defined and `ktls_meth.c`
excluded today), and the no-kTLS fallback would have to swap the SSL back
onto memory BIOs after the handshake. What it buys — OpenSSL owning
key install, sequence numbers, and control records — we can get cheaper.

**B. Sans-io + manual key install — chosen.** The handshake stays exactly
as shipped (BIO pair, every byte a ring op, deterministic tests intact):

- *Keys*: `SSL_CTX_set_keylog_callback` (present in every OpenSSL build —
  no rebuild) yields the TLS 1.3 traffic secrets per connection;
  `std.crypto.tls.hkdfExpandLabel` (public in the pinned std) derives the
  key/IV pair; a `tls12_crypto_info_*` struct goes to the kernel via
  `setsockopt(TCP_ULP "tls")` + `SOL_TLS TLS_TX`/`TLS_RX` — a synchronous
  IO-seam helper like `shutdown_socket`. Gated to the AES-GCM ciphers.
- *Sequence numbers, eliminated rather than computed*: kTLS needs the next
  record sequence per direction. Rule: switch only at handshake completion
  when **zero application-epoch records** have flowed. TX is trivially 0 —
  we switch before the first `SSL_write`. RX turned out not to need the
  originally-planned record-boundary counter: at handshake completion, any
  application-epoch byte the client sent must be sitting in exactly one of
  three places — our wire staging (unfed), the pair's read side
  (`SSL_get_rbio` + `BIO_ctrl_pending`), or buffered inside the SSL
  (`SSL_has_pending`). All three empty ⇒ sequence is exactly 0
  (`Channel.kernel_switch_eligible`); nothing to parse, nothing to
  miscount. A client whose first request rode in with the handshake flight
  simply leaves that connection on the BIO-pair relay — the fallback is
  the already-shipped path, so a missed switch costs performance, never
  correctness (tested: the early request defeats eligibility and is
  delivered intact by the userspace path).
- *Steady state*: plain `io.recv`/`io.send` on the fd; the kernel does the
  records; the relay is byte-identical to plaintext. The channel (SSL + BIO
  pair, ~161 KiB) is freed at switchover — kTLS connections cost ~zero TLS
  heap while streaming.
- *Consequences owned*: a post-switch control record (client KeyUpdate,
  client close_notify) surfaces as a `recv` error → teardown; KeyUpdate-ing
  clients degrade to reconnect (rare; measured if the fallback counter says
  otherwise). Our own polite close_notify needs one new ring op —
  `sendmsg` with a `TLS_SET_RECORD_TYPE` cmsg. Any setsockopt failure
  (module absent, old kernel, cipher mismatch) falls back to the pair relay
  and is counted (`zoxy_tls_ktls_active` / `_fallbacks` gauges).

Slices, in order: (1) IO seam — `enable_kernel_tls` + the `sendmsg` op
(done 2026-07); (2) keylog capture + HKDF derivation, unit-tested against
the RFC 8448 TLS 1.3 vectors (done 2026-07); (3) switchover eligibility
(the quiescence checks above) + per-direction kernel parameter
composition (done 2026-07); (4+5) the ProxyConn switchover and the
cmsg close_notify (done 2026-07): the decision is owed from handshake
completion and taken once the wire is idle (a pending wire send would be
double-encrypted; a pending recv would deliver kernel-decrypted plaintext
into the ciphertext staging); on switch the channel frees mid-connection
and `conn.tls` returns to null, so every downstream op is the plaintext
path on the fd; the polite close sends the alert through
`TLS_SET_RECORD_TYPE`. `tls.kernel_offload=false` in config forces the
userspace relay. Verified: curl and zrk switch 100% (7k+ churn
switchovers, zero fallbacks, zero client-visible errors); steady 20k
req/s with p50 135µs; carved heap under load dropped 11.1 → 4.9 MiB. A
client that pipelines into the Finished flight falls back and is served
identically (asserted in tests — loopback coalescing makes that path
timing-dependent, so tests assert the decision sum, plus a dedicated
delayed-request test that must switch). Remaining: (6) measurement gate —
bands vs the userspace relay, CPU per byte.

HTTP/2 & HTTP/3: nothing usable in pure Zig. H2 → `nghttp2` FFI when needed;
H3/QUIC → `quiche`/`ngtcp2`. Pure-Zig H3 is blocked on QUIC-aware TLS 1.3.

---

## 7. Phased build plan

### Phase 0 — Minimal viable proxy (done)
- Thread-per-core + `SO_REUSEPORT`, per-worker `io_uring` loop, connection-pinned.
- Static config file: listener, host/path-prefix routes, static clusters with
  inline endpoints, round-robin LB (per-cluster counters).
- HTTP/1.1: accept → parse → route → connect → segmented forward → relay both
  directions until EOF. **One request per connection** (§5): hop-by-hop headers
  stripped, `Connection: close` forced; `Upgrade` refused with 501.
- Strict bounded-buffer backpressure (recv → send → recv, §1.4).
- Whole-life connection deadline (slow-loris backstop); accept backoff on
  fd/resource exhaustion.
- Counters + admin/metrics endpoint (dedicated thread, off the data path);
  per-worker batched access log.
- **Zero-alloc harness:** the full serving path runs green under the counting
  allocator gate; `bench/run.sh` measures the proxy hop against a direct
  baseline at constant throughput.

### Phase 1 — HTTP/1.1 keep-alive (pulled forward; done)
Ends the one-request-per-connection contract. Justification: close-per-request
costs ~6× throughput on loopback (zrk, 2026-07: ~740k req/s keep-alive vs
~125k close-mode direct; ~30k proxied) — connection reuse is the single
biggest performance lever and needs no new dependencies, so it comes before
resilience.

Shipped 2026-07. Measured (zrk, loopback, 64 connections): sustainable
throughput ~30k → ~90k+ req/s; at 60k the proxied hop costs ~+400µs at the
median over nginx-direct keep-alive (509µs vs 104µs p50), with a 99.99%
upstream-pool hit rate and zero errors. Two war stories are encoded in the
code: TCP_NODELAY (Nagle + delayed ACK stalled warm pooled connections 40ms
per request — invisible on fresh connections, which sit in TCP quickack),
and the single-ticking-timer deadline design that avoids cancel/re-arm races.
- **Response framing:** parse the upstream status line + headers (zero-copy,
  same discipline as the request parser); body framing via Content-Length and
  a bounded chunked-decode state machine. Close-delimited or unframeable
  responses keep the Phase-0 forced-close behavior as the fallback.
- **Downstream keep-alive:** when a framed response completes, reset
  per-request state and re-arm for the next head on the same connection.
  Every request is re-parsed and re-routed — which also restores per-request
  routing semantics (no tunnel to smuggle through).
- **Upstream H1 pool** (`upstream_pool.zig`): per-worker, per-cluster, bounded;
  check out a live connection instead of connect-per-request, return it after
  a framed response, close on error or staleness. No pipelining.
- **Timeout split:** the whole-life deadline becomes per-request; a separate
  idle timeout reaps quiet keep-alive connections between requests.
- Hop-by-hop rewrite in both directions (requests have it; responses gain it
  once they are parsed).
- Gate (met): `bench/run.sh` with keep-alive clients holds the same constant
  rates as the direct keep-alive baseline up to ~90k req/s saturation, and
  the zero-alloc gate still holds.

### Phase 2 — Resilience (done)
- P2C weighted-least-request LB; active health checks + passive outlier
  detection; circuit breaking (max conns/pending/requests); retries with
  fully-jittered exponential backoff + retry budget; per-try timeout.

Shipped 2026-07. All mutable state lives in one per-worker table
(`resilience.zig`: per-cluster/per-endpoint counters behind a narrow
admission/outcome API — the §1.5 "filter seam" in callback-I/O form); policy
is resolved into the arena `Config` at parse (per-cluster `retry`,
`circuit_breaker`, `outlier`, `health_check`, `per_try_timeout_ms` blocks;
absent block = off). The per-try timeout rides the existing single ticking
timer and aborts an attempt by killing its single in-flight op and draining
through the op's own completion (`fail`/retry only after the drain — the op
may own the completion `fail` would reuse). Retries generalize the Phase-1
stale-pool replay: that replay stays free (same endpoint, no budget — pool
churn is not a health signal); configured retries settle the attempt as a
real failure, charge an Envoy-style budget (percent of active requests with
a floor, plus a max_retries breaker), back off with full jitter on their own
one-shot timer, and re-pick via P2C excluding the failed endpoint. The
simulator gained black-holed connects, a `never_respond` origin, and a
standing invariant that every resilience counter drains to zero.

Measured (zrk, loopback, 60k req/s constant, 64 connections, 2026-07): the
happy path costs ~nothing — one PRNG draw and a handful of per-worker
counter bumps per request. Proxied p50 across runs 243µs–1.7ms vs the
pre-Phase-2 build's 355µs–3.0ms on the same box back-to-back (run-to-run
variance dominates; no regression signal), 60k sustained, zero errors,
99.99% pool hit rate. 5000+ sim seeds green with every resilience feature
enabled.

Deliberate deltas from Envoy (simplicity first, revisit on evidence):
per-worker limits and budgets (share-nothing — cluster-wide = value x
workers); endpoints start healthy (a restarting proxy serves immediately);
zero available endpoints fails open and routes anyway (no 50% panic
threshold); idle pooled fds are excluded from max_connections (bounded
separately by `upstream_idle_max`); per-try timeout arms only for replayable
requests (streaming requests run under the overall deadline alone).
Deferred: peak-EWMA weighting and config endpoint weights (least-request
self-adapts; cross-multiply hook documented in balancer.zig), retry-on-5xx
(needs response-head re-buffering analysis), HTTP health probes (TCP connect
catches the dominant failures), ejection-time multipliers.

### Phase 3 — Protocol depth
- TLS termination (design in §6), sliced:
  1. **FFI foundation** — done 2026-07. OpenSSL vendored (`third_party/openssl`,
     patched: the upstream recipe shipped C fallbacks alongside the x86_64 asm
     that replaces them — duplicate symbols under Zig's strict linker).
     `CRYPTO_set_mem_functions` → `src/tls/heap.zig`, a fixed size-class heap
     behind a raw-futex mutex (0.16 removed `std.Thread.Mutex`); exhaustion
     fails the OpenSSL call, tests assert identity validation drains to
     baseline on success *and* error paths. Config grew an optional `tls`
     block (paths only — config stays FFI-free for the simulator); main
     validates the PEM identity via OpenSSL at startup, so a bad cert kills
     boot, not the first handshake.
  2. **BIO-pair terminator** — done 2026-07, in two halves.
     *Sans-io* (`src/tls/terminator.zig`): `Context` (SSL_CTX: identity
     install + cross-check, TLS >= 1.2, ALPN select preferring `http/1.1`
     with NOACK fallback, session cache/tickets off so every handshake is
     full and the context stays immutable across workers) and `Channel`
     (per-connection SSL over a fixed-size BIO pair; feed/drain ciphertext,
     handshake_step, read/write plaintext — a pure byte transformer, tested
     by deterministic in-memory loopback down to 1-byte adversarial
     delivery). *Data path* (`net/proxy.zig`): every downstream I/O site
     (`arm_recv_head`, the request pipe's recv, the response pipe's send,
     the fail send) branches to logical `tls_recv_start`/`tls_send_start`;
     a single `tls_progress` pump drives handshake and streaming off wire
     completions, buffered plaintext is delivered via a zero-delay yield
     timer (no recursion), and the channel frees with the slot — a TLS
     connection drains the hook heap to baseline (asserted end-to-end).
     Channel init at accept load-sheds on heap exhaustion. Verified with
     curl: TLS 1.3, ALPN `http/1.1` picked from `h2,http/1.1`, keep-alive
     and pipelined requests on one handshake.
     Follow-ups landed 2026-07-04: server-initiated closes (delivered
     response or error) flush a **close_notify** before teardown
     (`close_downstream`, bounded by the connection deadline; client-EOF
     and error teardowns stay abrupt), and a relayed response the proxy
     will close after gets **`Connection: close` injected** when the origin
     head lacked it (RFC 9112 §9.6 — without it clients assume keep-alive,
     pipeline the next request, and read our close as an error; found by
     zrk, whose churn benches went from ~1 read error per request to zero).
     The hook heap exposes gauges via /metrics (`zoxy_tls_heap_*`);
     measured churn high-water: ~10.6 MiB carved of 64 MiB at 64 concurrent
     full-handshake connections, live-block count flat across runs (no
     per-connection leakage).
     Measurement gate (2026-07-04, band procedure, R=20k c=64 ×3 alternating
     runs): steady-state TLS ≈ plaintext — throughput identical (~19.92k),
     p50 139–148µs vs 153–157µs, p99 681–788µs vs 622–675µs. The TLS p99.9
     band sat at a constant ~32.5ms vs ~5.5ms plaintext; a 30s run shrank it
     to 13.3ms (burst moved to p99.99), proving it is the *startup handshake
     burst* under coordinated-omission correction, not a steady-state stall —
     amortized by connection lifetime; session resumption would shrink the
     burst itself. Heap: ~161 KiB per live TLS connection (consistent at
     c=64/c=256), 0.9 MiB process baseline → the reservation is now derived
     at startup as base + per_connection × connections_max × workers
     (constants.zig; virtual, pages touch as connections carve). Still
     deferred: SNI multi-cert (single identity in config today; the
     servername callback is the extension point); shrinking the ~161 KiB
     per-connection cost (`SSL_MODE_RELEASE_BUFFERS`, tighter BIO sizing) if
     TLS density ever matters.
  3. **kTLS fast path** — designed 2026-07-04 (§6 "kTLS design"): sans-io
     handshake unchanged; keylog-callback secrets + `hkdfExpandLabel` install
     the keys, the zero-records-flowed eligibility rule makes sequence
     numbers trivially 0/0 (else the connection stays on the pair relay),
     and the steady-state relay becomes byte-identical to plaintext. Six
     sub-slices listed there, IO seam first.
  4. **Upstream re-encryption** — client-side TLS to origins, reusing the same
     arena + BIO/kTLS machinery; only after downstream termination is proven.
- HTTP/2 downstream+upstream: per-stream state machines, **dual-level flow
  control** (stream + connection windows) wired into the existing watermark
  system, HPACK decode/re-encode, H2 pool with multiplexing + GOAWAY draining.

### Phase 4 — Operability
- Graceful drain + hot restart (FD passing over a unix socket, à la HAProxy
  `SCM_RIGHTS`; drain via `Connection: close` / GOAWAY; transfer stats).
- **Accept balancing across workers.** Measured 2026-07 (per-worker accept
  counters, `zoxy_worker_accepted`): the SO_REUSEPORT hash is uniform at
  large N (1.14:1 over 150k accepts) but few long-lived connections pin
  small-sample variance — at 64 keep-alive connections over 8 workers the
  hottest worker drew 15/64 (23% of load, 3.75:1 max:min), and the system
  saturates when *it* does. Options: an `SO_ATTACH_REUSEPORT_EBPF` program
  (round-robin or least-loaded assignment) or a userspace acceptor handing
  fds to workers over `SCM_RIGHTS` — the same machinery hot restart needs.
  Matters most for few-hot-connections traffic (an LB tier or HTTP/2 in
  front); high-connection-count traffic self-smooths.
- Consistent-hash LB (ring-hash / Maglev). Distributed tracing (B3/W3C
  propagation) + Prometheus metrics.

### Phase 5 — Dynamic config
- xDS-style streaming client (CDS→EDS→LDS→RDS make-before-break ordering) or a
  simpler custom control-plane protocol. Apply via RCU pointer swap so the data
  path stays lock-free.

---

## 8. Proposed module layout

```
src/
  main.zig            entry: parse config, size budget, spawn workers
  config.zig          static config model + file parser; immutable Config
  io/
    io.zig            comptime-selected IO backend + Completion (TB pattern)
    linux.zig         io_uring backend on std.os.linux.IoUring
    darwin.zig        kqueue backend (dev on macOS/BSD)
    test_io.zig       deterministic seeded mock IO (for the simulator)
  net/
    listener.zig      SO_REUSEPORT socket setup (std.posix)
    connection.zig    Connection struct, pooled, buffer slices, state machine
    pool.zig          fixed Connection pool + intrusive free list
    watermark.zig     bounded buffers + ref-counted read-disable
  http/
    h1.zig            HTTP/1.1 parse/serialize (std.http.Server or custom)
    request.zig       zero-copy Head/Header views
  proxy/
    router.zig        host/path → cluster (StaticStringMap / bounded map)
    cluster.zig       cluster + endpoint tables
    balancer.zig      P2C least-request (EWMA deferred)
    upstream_pool.zig per-worker/cluster H1 connection pool
    resilience.zig    per-worker state: outlier detection, circuit breaker, retry budget
    health_check.zig  active TCP-connect probes, per worker, in-ring
  obs/
    metrics.zig       fixed counter/gauge/histogram registry
    access_log.zig    ring → flusher thread
  mem/
    slab.zig          startup slab + buffer carving
    guard.zig         FailingAllocator hot-path guard (debug/test)
```

---

## 9. Key references

- Zig: [0.16 release notes], [0.15.1 "Writergate"], `std.os.linux.IoUring`,
  [ziglang/zig#25047] (WouldBlock erasure), [#14171] (no TLS server).
- libxev (mitchellh), `justinGrosvenor/swerver`, `karlseguin/http.zig`,
  `ianic/tls.zig`, `tardy-org/zzz`.
- Envoy: life_of_a_request, threading_model, flow_control.md, connection_pooling.
- Linkerd2-proxy: under-the-hood, protocol-detection, P2C+peak-EWMA.
- TigerBeetle: "A Database Without Dynamic Memory" (static-allocation discipline).
