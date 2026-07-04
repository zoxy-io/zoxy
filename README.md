# zoxy

[![CI](https://github.com/floatdrop/zoxy/actions/workflows/ci.yml/badge.svg)](https://github.com/floatdrop/zoxy/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/floatdrop/zoxy/badge.svg?branch=main)](https://coveralls.io/github/floatdrop/zoxy?branch=main)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A zero-allocation L7 edge proxy in Zig, in the spirit of Envoy and Linkerd.

zoxy is built on the [TigerBeetle](https://tigerbeetle.com) I/O model — completion-based
`io_uring` with caller-owned completions — and follows [TigerStyle](docs/TIGER_STYLE.md):
**all memory is reserved at startup, and the request-serving path allocates nothing.**

> **Status: experimental, Phase 2 complete.** A working HTTP/1.1 reverse proxy with
> keep-alive on both sides, upstream pooling, and a resilience layer (P2C load
> balancing, retries, circuit breaking, outlier detection, health checks) — but not
> yet production-ready — see [Scope & roadmap](#scope--roadmap). Linux only.

## Highlights

- **Zero allocation after startup.** Config parsing allocates; once serving, the hot
  path issues no heap allocations and no allocating syscalls. Enforced by a
  [test-time acceptance gate](src/mem/guard.zig).
- **Completion-based `io_uring`.** Each connection owns its I/O completions inline
  (TigerBeetle's `IO`/`Completion` pattern), so submitting an operation allocates nothing.
- **Thread-per-core, share-nothing.** One worker per CPU, each with its own ring,
  its own `SO_REUSEPORT` listener, and its own connection pool. No locks on the data path.
- **Bounded by design.** Fixed connection pool (exhaustion rejects, never grows), fixed
  per-connection buffers, and a strict single-buffer relay that pushes flow control down to TCP.
- **Resilience without allocation.** P2C least-request balancing, budgeted retries with
  full-jitter backoff, per-try timeouts, circuit breakers, passive outlier ejection, and
  active TCP health probes — all state statically reserved per worker, all timers riding
  the same ring.
- **Zero dependencies** beyond the Zig toolchain.

## Requirements

- **Zig 0.16** (the [Nix dev shell](flake.nix) pins `zig_0_16` + `zls`).
- **Linux with `io_uring`** (kernel 5.11+).

## Build & run

With Nix (recommended):

```sh
nix develop            # zig 0.16, zls, kcov
zig build              # build zig-out/bin/zoxy
zig build test         # run the test suite
zig build sim -- 0 500 # deterministic simulator: [seed] [iterations]
zig build run          # run using ./zoxy.json
```

The simulator runs the real data path against a deterministic IO backend —
virtual sockets, a virtual clock, seeded adversarial schedules with partial
reads/writes, misbehaving origins (including ones that never respond), and
injected faults (TCP resets at any point in any exchange, refused connects,
black-holed connects that hang until cancelled). Every request carries a unique
token its origin echoes into the body, so completed responses are verified
byte-exact end to end. A failure prints its seed; `zig build sim -- <seed> 1`
replays the exact schedule, faults included. `zig build sim -- fuzz` runs
forever on entropy-derived seeds (each still individually replayable).

Or point it at a config file:

```sh
./zig-out/bin/zoxy path/to/config.json
```

zoxy logs a startup line and per-request access lines to stderr:

```
info: zoxy listening on 127.0.0.1:8080 across 8 worker(s)
GET /api/thing proxied 70
```

## Configuration

Static JSON (parsed once at startup into an immutable config). Routes are matched
in order; the first whose host (`*` or an exact, port-insensitive match) and
`path_prefix` match wins.

```json
{
  "listen": "127.0.0.1:8080",
  "admin": "127.0.0.1:9901",
  "routes": [
    { "host": "api.example.com", "path_prefix": "/v1", "cluster": "api" },
    { "cluster": "default" }
  ],
  "clusters": [
    { "name": "api", "endpoints": ["127.0.0.1:9001", "127.0.0.1:9002"] },
    { "name": "default", "endpoints": ["127.0.0.1:9000"] }
  ]
}
```

`host` defaults to `"*"` and `path_prefix` to `"/"`. Endpoints in a cluster are
load-balanced P2C least-request: two random picks, the one with fewer in-flight
requests wins, unhealthy/ejected endpoints are avoided (and when *none* is
available, zoxy fails open and routes anyway). `admin` (optional) serves
Prometheus-style counters — `curl http://127.0.0.1:9901/metrics` — on a
dedicated thread, off the data path.

### Resilience (per cluster, all optional)

```json
{
  "name": "api",
  "endpoints": ["127.0.0.1:9001", "127.0.0.1:9002"],
  "per_try_timeout_ms": 2000,
  "retry": { "max": 2, "backoff_base_ms": 25, "backoff_cap_ms": 1000,
             "budget_percent": 20, "budget_min": 3 },
  "circuit_breaker": { "max_connections": 128, "max_pending": 32,
                       "max_requests": 256, "max_retries": 16 },
  "outlier": { "consecutive_failures": 5, "ejection_ms": 30000,
               "max_ejection_percent": 50 },
  "health_check": { "interval_ms": 5000, "timeout_ms": 2000,
                    "healthy_threshold": 2, "unhealthy_threshold": 3 }
}
```

An absent block leaves that feature off; absent fields inside a present block
take the defaults shown above, except `retry.max` (required) and the
`circuit_breaker` limits (each absent limit is unbounded — the values above are
examples). Semantics:

- **`per_try_timeout_ms`** — deadline per upstream attempt (connect through the
  first response byte); expiry aborts the attempt and retries it or answers 504.
  Applies to requests that fit the proxy's buffer (streamed request bodies run
  under the overall request timeout alone).
- **`retry`** — retries connect errors, resets/EOF before any response byte, and
  per-try timeouts, with fully-jittered exponential backoff, re-picking a
  different endpoint. Only requests that can be replayed verbatim are retried,
  and never after a response byte has been forwarded. Retries in flight are
  capped by `max(budget_min, budget_percent% of active requests)`. (A pooled
  connection that went stale is replayed once for free, without this block.)
- **`circuit_breaker`** — hard concurrency caps; a breach answers 503
  immediately, nothing queues.
- **`outlier`** — passive detection: `consecutive_failures` failed attempts
  eject the endpoint for `ejection_ms`, bounded by `max_ejection_percent` of
  the cluster.
- **`health_check`** — active TCP-connect probes; result streaks flip the
  endpoint's health at the thresholds. Endpoints start healthy.

All limits and budgets are **per worker** (share-nothing — no cross-worker
coordination): a cluster-wide budget is the configured value × worker count.

## Benchmarking

```sh
bench/run.sh                 # 30k req/s for 10s over 64 connections
bench/run.sh -R 40000 -d 30s # find the saturation point
```

Stands up an nginx origin and zoxy on loopback, then drives direct baselines
(keep-alive — the honest comparison, plus `Connection: close` to show the
handshake tax) and the proxied path at the same constant rate with
[zrk](https://github.com/floatdrop/zrk), so the corrected latency of the proxy
hop is directly comparable. Falls back to closed-loop `wrk` (via nix, with a
warning) when zrk is not installed. Run-to-run variance on a busy box easily
dominates the hop cost — compare bands of several runs, not single numbers.

## Architecture

```
per core (thread-per-core, share-nothing):
  SO_REUSEPORT listener ──io.accept──► single-threaded io_uring loop
    io.recv ─► parse head ─► route ─► upstream pool / io.connect
             ─► framed relay both ways ─► reuse both connections
```

Source layout:

| Path | What |
|------|------|
| `src/io/` | `IO` + `Completion` over `std.os.linux.IoUring` (comptime backend seam) |
| `src/net/listener.zig` | `SO_REUSEPORT` TCP listener |
| `src/net/pool.zig` | fixed object pool over an intrusive free list |
| `src/net/proxy.zig` | the proxy data path (parse → route → connect → relay → retry) |
| `src/http/h1.zig` | zero-copy HTTP/1.1 request/response parsers + body framing |
| `src/config.zig`, `src/proxy/` | config, routing, P2C balancing, upstream pool, resilience state (breakers, outlier detection, retry budget), health checks |
| `src/obs/` | metrics counters + per-worker access log |
| `src/mem/guard.zig` | zero-allocation acceptance gate |

Design rationale and the Zig-0.16 findings behind these choices are in
[`docs/DESIGN.md`](docs/DESIGN.md); the coding conventions are in
[`docs/TIGER_STYLE.md`](docs/TIGER_STYLE.md).

## Scope & roadmap

**Phase 0 (done):** HTTP/1.1 proxying, static config, host/path routing,
round-robin, bounded relay with backpressure, deadlines, metrics + admin
endpoint + access log, and the zero-alloc gate.

**Phase 1 (done): HTTP/1.1 keep-alive** — both messages framed per RFC 9112
§6.3 (Content-Length / chunked, smuggling-shaped framing rejected),
downstream connection reuse with per-request re-routing, a per-worker
upstream connection pool with one-shot stale retry, hop-by-hop header
handling in both directions, and split request/idle timeouts. Measured on
loopback with [zrk](https://github.com/floatdrop/zrk): sustainable
throughput went from ~30k to ~90k+ req/s; the proxy hop costs ~+400µs at
the median vs nginx-direct.

**Phase 2 (done): resilience** — P2C least-request balancing over per-worker
in-flight counts, per-try timeouts, budgeted retries with full-jitter
exponential backoff (generalizing the Phase-1 stale-pool replay), circuit
breakers (max requests/pending/connections/retries), passive outlier ejection,
and active per-worker TCP health probes. All mutable state lives in one
statically-sized per-worker table; the simulator asserts every counter drains
to zero on every seed. Measured on loopback: the happy path costs ~nothing —
run-to-run variance dominates any difference against the pre-Phase-2 build at
60k req/s. Deferred with rationale (EWMA weighting, retry-on-5xx, HTTP
probes): see [`docs/DESIGN.md`](docs/DESIGN.md) §7.

**Later:** TLS termination (OpenSSL FFI for the handshake only, kTLS for the
record layer — see [`docs/DESIGN.md`](docs/DESIGN.md) §6), HTTP/2 and HTTP/3,
graceful drain + hot restart, and config hot-reload. The full plan is in
[`docs/DESIGN.md`](docs/DESIGN.md) §7.

## License

[MIT](LICENSE) © 2026 Vsevolod Strukchinsky
