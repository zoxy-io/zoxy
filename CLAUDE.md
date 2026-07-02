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
zig fmt --check src build.zig   # lint (CI gate)
```

A simulator failure prints its seed; `zig build sim -- <seed> 1` replays that
exact schedule, faults included. CI runs seeds 0..300 on every push.

Without direnv, prefix each with `nix develop --command` (this is what CI does), or
enter the shell once with `nix develop` and drop the prefix.

**Running a single test:** the build has no test filter step, so invoke the test
binary directly with a name filter:

```sh
zig test src/root.zig --test-filter "substring of test name"
```

(`zig build test` compiles two binaries — `mod` rooted at `src/root.zig` and the
exe rooted at `src/main.zig` — because a Zig test binary tests one module at a time.
`src/root.zig` aggregates every module's tests via its trailing `test { _ = ...; }`
block, so a new source file's tests only run once it is `_ = @import(...)`ed there.)

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
are **no locks on the data path**. `Metrics` counters are the only shared state (atomics);
each worker has its own `AccessLog`.

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
| `src/sim.zig` | the simulator: real data path + misbehaving virtual origins/clients, per-seed invariants (no deadlock, no leaks, every response parses + frames) |
| `src/net/proxy.zig` | **the data path**: `ProxyConn` (recvHead→parse→route→pool checkout or connect→framed relay→reuse or teardown), `Pipe` (one framed relay direction), `ProxyServer`, hop-by-hop header handling both ways, fixed 4xx/5xx responses, stale-pooled-upstream retry, integration + zero-alloc gate tests |
| `src/net/listener.zig` | `SO_REUSEPORT` TCP listener via raw linux syscalls (REUSEADDR+REUSEPORT set before bind) |
| `src/net/pool.zig` | generic `Pool(T)` over an **intrusive free list** (requires `T.free_next: ?*T`); exhaustion rejects, never grows |
| `src/http/h1.zig` | zero-copy HTTP/1.1 request+response parsers, RFC 9112 §6.3 body-framing decisions (smuggling shapes rejected), `BodyFramer` message-end tracker |
| `src/http/chunked.zig` | incremental chunked-coding decoder — finds message ends, transforms nothing |
| `src/proxy/upstream_pool.zig` | per-worker idle upstream connections, fixed slots keyed by endpoint |
| `src/config.zig` | JSON config → immutable `Config` (owns an arena); the **only** place allocation is expected |
| `src/proxy/router.zig`, `src/proxy/balancer.zig` | first-match host/path routing; round-robin |
| `src/obs/metrics.zig`, `src/obs/access_log.zig` | atomic counters; fixed-buffer batched access log |
| `src/mem/guard.zig` | `CountingAllocator` — the zero-alloc acceptance gate (baseline count == final count) |
| `src/constants.zig` | **every static limit** (connections_max, buffer sizes, ring depth, timeouts, pool sizes). Sizing the proxy = choosing these; total memory is a function of them. |

### Zig 0.16 API notes (verified against the pinned toolchain, not guessed)

- Networking in `std.Io` / `std.Io.Evented` is stubbed in 0.16 — we go **direct** to
  `std.os.linux.IoUring` and raw `std.os.linux` socket syscalls, not the std net layer.
- `std.posix.close` is gone → use `std.os.linux.close`.
- `main` takes `std.process.Init`; use `init.io` for file reads / arg parsing
  (`std.Io.Dir.cwd().readFileAlloc(init.io, ...)`, `init.minimal.args.toSlice(gpa)`).
- `std.crypto.random` is gone; entropy comes through the Io interface:
  `init.io.random(&buf)` (infallible, CSPRNG) or `io.randomSecure(&buf)`
  (strict, always a syscall). `std.time.Timer`/`Instant` are gone too — use
  `clock_gettime(CLOCK.MONOTONIC)` directly (see `IO.now_ns`).

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
- `snake_case` for functions, variables, and **file names**. No abbreviations
  (`source`/`target`, not `src`/`dest`). Units/qualifiers last (`connections_max`,
  `header_bytes_max`). Struct order: fields, then types, then methods.
- **Zero dependencies beyond the Zig toolchain.** Any C-FFI dependency (e.g. a future
  OpenSSL TLS terminator) is a deliberate, justified exception.
