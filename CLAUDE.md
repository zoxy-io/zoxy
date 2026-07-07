# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

zoxy is a zero-allocation L7 edge proxy (Envoy/Linkerd spirit) in **Zig 0.16**, Linux only.
The defining constraint: **all memory is reserved up front; the request-serving path
allocates nothing.** Allocation is permitted only during startup/configuration (JSON
config parsing). Anything on the accept→parse→route→connect→relay hot path that would
allocate is a bug — and is enforced by a test-time acceptance gate.

## Commands

The toolchain is pinned by the Nix flake (`zig_0_16` + `zls` + `kcov`). The repo ships
a `.envrc`, so with **direnv + nix-direnv** the dev shell auto-loads on `cd` (one-time
`direnv allow`) and bare commands just work:

```sh
zig build              # build zig-out/bin/zoxy
zig build test         # run all tests (both test binaries)
zig build test --summary all
zig build run          # run using ./zoxy.json
zig build sim -- 0 500 # deterministic simulator: [seed] [iterations]
zig build sim -- fuzz  # random seeds forever (Ctrl-C; each seed replayable)
zig build schema       # regenerate config.schema.json from the config DTO
zig build check-config # CI gate: schema not stale + zoxy.json strict-parses
zig build adapt -- f.zoxy # lower a Zoxyfile DSL config to JSON on stdout
zig fmt --check src build.zig   # lint (CI gate)
scripts/coverage.sh    # kcov line coverage (tests + sim), HTML + cobertura
```

A simulator failure prints its seed; `zig build sim -- <seed> 1` replays that
exact schedule, faults included. CI runs seeds 0..300 on every push.

Without direnv, prefix each with `nix develop --command` (this is what CI does), or
enter the shell once with `nix develop` and drop the prefix.

**Running a single test:**

```sh
zig build test -Dtest-filter="substring of test name"
```

(Raw `zig test src/root.zig` no longer works — it bypasses the build graph and
does not link the vendored OpenSSL. `zig build test` compiles two binaries —
`mod` rooted at `src/root.zig` and the exe rooted at `src/main.zig` — because a
Zig test binary tests one module at a time. `src/root.zig` aggregates every
module's tests via its trailing `test { _ = ...; }` block, so a new source
file's tests only run once it is `_ = @import(...)`ed there.)

CI (`.github/workflows/ci.yml`) runs `zig fmt --check`, `zig build`, and
`zig build test` inside `nix develop`. Match it before pushing.

## Architecture

Data flow, one instance per CPU core, **thread-per-core share-nothing**:

```
SO_REUSEPORT listener ──io.accept──► single-threaded io_uring loop (own ring, own pools)
  io.recv ─► parse request head ─► route to cluster ─► upstream pool checkout / io.connect
           ─► framed relay both ways ─► reuse both connections (keep-alive)
```

Each worker owns its ring, its `SO_REUSEPORT` listener, and its connection pool; there
are **no locks on the data path**. `Metrics` is the only shared state, and it is sharded:
each worker writes its own cache-line-padded `Counters` shard (atomics, single writer);
readers sum across shards. Each worker has its own `AccessLog`.

### The I/O model is the load-bearing decision

I/O is **completion-based `io_uring`**, adopted from TigerBeetle: `src/io/linux.zig`
defines an `IO` struct and a `Completion` struct. Every async op takes a caller-owned
`Completion` that is **embedded inline in the connection state** — submitting an op
allocates nothing. Ops are `(comptime Context, context, comptime callback, *Completion, ...args)`;
completion is delivered by type-erased callback, never by coroutine/fiber suspension.
`src/io/io.zig` is a comptime backend seam (`switch (builtin.os.tag)`) — the `IO` *type*
is the abstraction, so there is no runtime vtable/Reactor layer.

Consequences that bite if you forget them:
- **Functions run to completion without suspending** (TigerStyle) precisely because I/O
  is callback-based — precondition assertions hold for the whole function body.
- **Teardown must `shutdown(SHUT_RDWR)` both fds before `close`.** An `io_uring` `close`
  op does **not** cancel a `recv` already pending on that fd; without the shutdown the
  pending recv never completes and the connection is never released (this was a real
  deadlock). Timer and connect ops are cancelled via `io.cancel` (cancel-by-`user_data`).

### Key modules

| Path | Role |
|------|------|
| `src/io/linux.zig` | `IO` + `Completion` over `std.os.linux.IoUring`; ops: accept/recv/send/connect/close/timeout/cancel, plus sync seam helpers (now_ns, open_tcp_socket, shutdown_socket, close_now) |
| `src/io/test_io.zig` | deterministic simulation backend: virtual sockets/clock, seeded scheduler, adversarial partial IO; selected when the root file declares `zoxy_io = .simulation` |
| `src/sim.zig` | the simulator: real data path (H1 `ProxyServer` + h2c `H2Server` side by side on shared origins) + misbehaving virtual origins/clients (H1 + multiplexed h2c), per-seed invariants (no deadlock, no leaks, every response parses + frames, per-stream integrity, graceful drain) |
| `src/net/proxy.zig` | **the data path**: `ProxyConn` (recv head→parse→route→pool checkout or connect→framed relay→reuse or teardown), `Pipe` (one framed relay direction), `ProxyServer` (accept loop + graceful drain: `begin_drain`/`drain_complete`, close-after-response, deadline clamp), hop-by-hop header handling both ways, fixed 4xx/5xx responses, per-try timeout via attempt-abort/drain, two-tier retries (free stale-pool replay + budgeted jittered-backoff retries), **the h2 ALPN handoff** (`hand_off_to_h2`: at the quiescent kTLS-decision point, an `h2`-negotiated connection's channel + fd + staged preface move to an `H2Conn`), integration + zero-alloc gate tests |
| `src/net/listener.zig` | `SO_REUSEPORT` TCP listener via raw linux syscalls (REUSEADDR+REUSEPORT set before bind) |
| `src/net/handoff.zig` | hot-restart handoff: unix socket + one `SCM_RIGHTS` cmsg carries every worker's listener fd to a successor, validated (`getsockname` + `SO_ACCEPTCONN`) before adoption; counter totals ride behind the header as name-keyed records (version-skew tolerant, gauges reset); blocking, startup/dedicated-thread only |
| `src/net/pool.zig` | generic `Pool(T)` over an **intrusive free list** (requires `T.free_next: ?*T`); exhaustion rejects, never grows |
| `src/http/h1.zig` | zero-copy HTTP/1.1 request+response parsers, RFC 9112 §6.3 body-framing decisions (smuggling shapes rejected), `BodyFramer` message-end tracker |
| `src/http/chunked.zig` | incremental chunked-coding decoder — finds message ends for the verbatim H1 relay (`feed`), or separates payload from framing for re-framing relays (`extract`, used by the H2 leg) |
| `src/http/h2_frame.zig` | sans-io HTTP/2 frame codec (Phase 5, slice 1): client preface, 9-byte header parse/write, per-type structural rules (fixed sizes, stream-id zero/nonzero, advertised frame-size bound), SETTINGS/PING/RST_STREAM/GOAWAY/WINDOW_UPDATE payloads; stream/connection semantics live in later slices |
| `src/http/hpack.zig` | HPACK (Phase 5, slice 2): decoder with fixed-reservation dynamic table + Huffman decoding (comptime tree from the RFC table), output copied into caller storage (never aliases the table), bound overruns keep decoding to hold table sync and error at the end; stateless static-table/literal encoder, no Huffman, no insertions |
| `src/http/h2.zig` | sans-io HTTP/2 server connection engine (Phase 5, slices 3–4): `Connection.drive` consumes one frame per call, stages control frames, surfaces one `Event` (request/trailers/data/reset/goaway/window_open/fatal); fixed stream slots (exhaustion → REFUSED_STREAM after the block still decodes for HPACK sync), CONTINUATION assembly with flood bound, dual-level flow accounting with half-window WINDOW_UPDATE batching; send side: `send_headers` (CONTINUATION splitting) + `send_data` (window/frame/output-capped, `window_open` retries) |
| `src/http/h2_translate.zig` | H2 ↔ H1 translation (Phase 5, slice 4): `request_head` synthesizes an H1 head from decoded H2 fields (pseudo-header validation per RFC 9113 §8.3, §8.2.2 connection-specific rejects, cookie rejoining, CR/LF/NUL value hardening, content-length vs chunked framing choice); `response_block` hpack-encodes a parsed H1 response head (`:status` first, names lowercased, hop-by-hop + Connection-named strip) |
| `src/net/h2_proxy.zig` | the H2-downstream data path (Phase 5): `H2Conn` drives the engine from ring completions (staged recv/send, one op per direction, ticking deadline scanning per-stream deadlines), pooled `StreamLeg`s run one H1 upstream transaction per stream (route→admit→pool checkout/dial→synthesized head→send-time chunk framing→response translate→window-paced DATA relay→pool checkin); WINDOW_UPDATE credit only after the upstream write (§1.4); legs release to their pool only op-quiescent (seed-1693 rule); **downstream TLS**: `H2Conn` adopts the handshaker's `terminator.Channel` and drives the userspace BIO-pair relay inline (h2c = null tls); GOAWAY drain via `begin_drain`; retries/per-try/upstream-TLS/close_notify deferred (DESIGN §7 Phase 5) |
| `src/proxy/upstream_pool.zig` | per-worker idle upstream connections, fixed slots keyed by endpoint |
| `src/config.zig` | JSON config → immutable `Config` (owns an arena); the **only** place allocation is expected. Per-cluster resilience blocks resolve into a `ResiliencePolicy` here (ms→ns, validated). **Strict**: unknown keys are rejected by a type-directed walk that names the offending path; the `Dto` + its co-located `schema_fields` metadata are the source of truth for the JSON Schema. `load_text` picks the format by path extension: `.json` parses directly, anything else runs `config_adapter` first (both `main` startup and the SIGHUP reload go through it). Endpoints are `ip4:port` / `[ip6]:port` literals or `hostname:port` — hostnames resolve here, once, through an injectable `Resolver` seam (`SystemResolver` on `std.Io` in main/reload — concurrent queue drain, per-parse hostname memo, and a `routable_fn` route-probe hook so unroutable families are dropped; counting placeholder in offline tooling, `literals_only` default); each resolved address becomes its own endpoint (sorted, bounded by `endpoints_per_cluster_max`). Malformed digits-and-dots v4 literals and unscoped link-local v6 are rejected, never resolved. `listen`/`admin` stay IPv4 |
| `src/config_schema.zig` | comptime JSON-Schema (draft 2020-12) generator reflected from `config.Dto` (docs/DESIGN.md §7 Phase 6, slice 1); `assert_meta_matches` pins descriptions to fields at comptime so the schema can't drift. Driven by the `scripts/config_tool.zig` host tool behind `zig build schema` / `check-config` |
| `src/config_adapter.zig` | Zoxyfile DSL → JSON adapter (docs/DESIGN.md §7 Phase 6, slice 3): a terse, line-oriented, `#`-commented, `{}`-blocked surface that *lowers to* the JSON `config.zig` parses (Caddy's `caddy adapt` model). Emits JSON text only; all validation stays downstream in `parse_diagnostic`, so JSON remains the single source of truth. One directive per line; `route [host] [path] -> cluster`; `ms`/`s` durations → `*_ms`. `Diagnostic` carries the syntax-error line; driven by the `config_tool adapt` host tool behind `zig build adapt` |
| `src/reload.zig` | config reload via supervised self-relaunch (docs/DESIGN.md §7 Phase 6, slice 2): **SIGHUP** re-validates the config and `fork`+`exec`s a successor that adopts the listeners through the Phase-4 handoff while this instance drains — reused, not re-implemented (no in-process swap). Requires `handoff` configured + unchanged `listen`; `main.zig` supervises (`reload_config`, `successor_alive`) |
| `src/proxy/router.zig`, `src/proxy/balancer.zig` | first-match host/path routing; P2C least-request balancing over per-worker in-flight counts and the Maglev consistent-hash pick (`pick_hashed`: deterministic forward-walk fallback, soft retry exclusion), fail-open when no endpoint is available |
| `src/proxy/maglev.zig` | Maglev lookup tables: built once at config time (prime-sized, `u8` entries), data path = one wyhash + one index; knows nothing of config or balancer |
| `src/proxy/resilience.zig` | per-worker mutable resilience state (Phase 2): request/attempt/dial/connection accounting, circuit-breaker admission, retry budget, passive outlier ejection — the narrow API the data path calls at fixed points; the sim asserts every counter drains to zero |
| `src/proxy/health_check.zig` | active TCP-connect health probes, per worker, in-ring: one ticking scheduler, bounded probe slots, streak thresholds flip `EndpointState.healthy` |
| `src/obs/metrics.zig`, `src/obs/access_log.zig` | per-worker cache-line-padded counter shards (single writer, no shared line on the data path; scrape/handoff sum across shards); fixed-buffer batched access log |
| `src/mem/guard.zig` | `CountingAllocator` — the zero-alloc acceptance gate (baseline count == final count) |
| `src/mem/cache_line.zig` | `Padded(T)` — cache-line isolation for per-worker mutable state in shared arrays (metrics shards, pool headers, access logs); neighbors never share a line |
| `src/tls/openssl.zig` | OpenSSL FFI seam (Phase 3): hand-written externs (no @cImport), the process-global `CRYPTO_set_mem_functions` hook, PEM identity validation. **Install the hook before any other OpenSSL call** — OpenSSL refuses it after its first allocation |
| `src/tls/heap.zig` | fixed-capacity size-class heap behind the memory hook — reserved at startup, exhaustion fails the OpenSSL operation (load-shedding), never grows |
| `src/mem/futex_mutex.zig` | blocking mutex over the raw Linux futex (0.16 removed `std.Thread.Mutex`); off the data path only (TLS heap, handshake-time) |
| `third_party/openssl/` | vendored allyourcodebase/openssl build recipe (MIT) with local duplicate-symbol fixes (see its README); OpenSSL *sources* still fetched by content hash. Linked into the `zoxy` module only — the simulator never sees it |
| `src/constants.zig` | **every static limit** (connections_max, buffer sizes, ring depth, timeouts, pool sizes). Sizing the proxy = choosing these; total memory is a function of them. |

### Zig 0.16 API notes (verified against the pinned toolchain, not guessed)

- Networking in `std.Io` / `std.Io.Evented` is stubbed in 0.16 — we go **direct** to
  `std.os.linux.IoUring` and raw `std.os.linux` socket syscalls, not the std net layer.
- `std.posix.close` is gone → use `std.os.linux.close`.
- `main` takes `std.process.Init`; use `init.io` for file reads / arg parsing
  (`std.Io.Dir.cwd().readFileAlloc(init.io, ...)`, `init.minimal.args.toSlice(gpa)`).
- `std.crypto.random` is gone; entropy comes through the Io interface:
  `init.io.random(&buf)` (infallible, CSPRNG) or `io.randomSecure(&buf)`
  (strict, always a syscall).
- **kcov cannot read the self-hosted Debug backend's DWARF** (finds 0 lines);
  coverage builds must pass `-fllvm` (see `scripts/coverage.sh`).
- `std.Thread.Mutex` is gone; its replacement `std.Io.Mutex` requires an `Io`
  instance the workers deliberately don't carry → use
  `src/mem/futex_mutex.zig` (raw futex, off the data path only).
- `std.time.Timer`/`Instant` are gone; the idiomatic replacement is
  `std.Io.Clock` — `std.Io.Clock.awake.now(io)` (CLOCK_MONOTONIC on Linux)
  returns an `Io.Timestamp` with `durationTo`/`fromNow` arithmetic. Our
  *data path* deliberately does not use it: no `std.Io` is threaded through
  the workers, and the deadline clock must be virtualizable, so it goes
  through our own seam (`IO.now_ns` — raw `clock_gettime` in the linux
  backend, the virtual clock in the simulator). Reach for `std.Io.Clock`
  only in code that already holds `init.io` (startup, tooling).

## Coding conventions (TigerStyle)

`docs/TIGER_STYLE.md` is authoritative; `docs/DESIGN.md` holds the rationale. The rules
that are actually enforced and easy to violate:

- **Static allocation only after `init`.** Hot paths are proven allocation-free by test.
- **≥2 assertions per function** on average — assert arguments, returns, and invariants,
  both positive space (what you expect) and negative space (what you don't). Split
  `assert(a and b)` into two.
- **Functions ≤70 lines, lines ≤100 columns, 4-space indent, `zig fmt` clean.**
- **No recursion. Put a bounded limit on every loop/queue.** All errors handled — no
  `catch unreachable` on a reachable error.
- **Explicitly-sized integers** (`u32`, `u63`, …); avoid `usize` except for real
  machine-word/index quantities.
- **Naming follows the [Zig reference convention](https://ziglang.org/documentation/master/#Names):**
  `TitleCase` for types and type-returning functions, `camelCase` for other
  functions, `snake_case` for variables/constants/fields and namespace structs.
  File names split the same way: `TitleCase.zig` for a struct-with-fields,
  `snake_case.zig` for a namespace; directories `snake_case`. No abbreviations
  (`source`/`target`, not `src`/`dest`). Units/qualifiers last (`connections_max`,
  `header_bytes_max`). Struct order: fields, then types, then methods.
- **Zero dependencies beyond the Zig toolchain, with one deliberate exception:** the
  vendored OpenSSL for TLS (docs/DESIGN.md §6). Its allocations route through the
  reserved TLS heap, so "no allocation outside pre-reserved pools" survives the FFI
  boundary. Don't add others.
