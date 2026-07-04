# zoxy

[![CI](https://github.com/floatdrop/zoxy/actions/workflows/ci.yml/badge.svg)](https://github.com/floatdrop/zoxy/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/floatdrop/zoxy/badge.svg?branch=main)](https://coveralls.io/github/floatdrop/zoxy?branch=main)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A zero-allocation L7 edge proxy in Zig, in the spirit of Envoy and Linkerd.

zoxy is built on the [TigerBeetle](https://tigerbeetle.com) I/O model — completion-based
`io_uring` with caller-owned completions — and follows [TigerStyle](docs/TIGER_STYLE.md):
**all memory is reserved at startup, and the request-serving path allocates nothing.**

> **Status: experimental, Phase 4 operability in progress.** A working
> HTTPS/HTTP/1.1 reverse proxy: TLS termination with kernel-TLS offload, SNI
> multi-cert, verified upstream re-encryption, keep-alive and pooling on both
> sides, a resilience layer (P2C load balancing, retries, circuit breaking,
> outlier detection, health checks), and graceful drain on SIGTERM — but not
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
- **TLS on both hops, kernel-offloaded.** OpenSSL terminates the handshake sans-io
  (every byte stays a ring op); after a quiet handshake the record layer moves into
  the kernel (kTLS) and steady-state TLS runs the *plaintext* relay code path. SNI
  multi-cert, ALPN, polite close_notify, and verified re-encryption to origins with
  pooled TLS sessions. OpenSSL's allocations live in a fixed heap reserved at startup —
  exhaustion load-sheds a handshake, never OOMs.
- **Zero dependencies** beyond the Zig toolchain, with one deliberate exception: a
  vendored OpenSSL (built by the Zig build system, sources fetched by content hash)
  for the TLS handshake.

## Requirements

- **Zig 0.16** (the [Nix dev shell](flake.nix) pins `zig_0_16` + `zls`).
- **Linux with `io_uring`** (kernel 5.11+).
- Optional: the `tls` kernel module (`modprobe tls`) for kTLS offload — without it,
  TLS connections transparently stay on the userspace relay.

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

### TLS (optional)

Terminate TLS on the listener, and/or re-encrypt to a cluster's origins:

```json
{
  "listen": "0.0.0.0:443",
  "tls": {
    "certificate_file": "certs/default.pem",
    "private_key_file": "certs/default.key",
    "kernel_offload": true,
    "additional_identities": [
      { "server_names": ["other.example.com", "*.other.example.com"],
        "certificate_file": "certs/other.pem",
        "private_key_file": "certs/other.key" }
    ]
  },
  "routes": [{ "cluster": "api" }],
  "clusters": [
    { "name": "api", "endpoints": ["10.0.0.5:8443"],
      "tls": { "server_name": "api.internal", "ca_file": "certs/internal-ca.pem" } }
  ]
}
```

- **Listener `tls`** terminates TLS 1.3/1.2 (full handshakes; no resumption yet).
  ALPN negotiates `http/1.1`. `additional_identities` selects certificates by SNI
  (exact names and single-label `*.` wildcards, declared explicitly — never
  introspected from certificates); absent or unmatched SNI gets the default pair.
- **`kernel_offload`** (default `true`) hands each connection's record layer to
  the kernel after the handshake, when provably safe (record sequence zero, AES-GCM,
  `tls` module present) — otherwise that connection transparently stays on the
  userspace relay, which serves identical bytes. Closes send `close_notify` either way.
- **Cluster `tls`** re-encrypts to the origins. Verification is an explicit choice:
  `ca_file` (a PEM bundle) **and** `server_name` (required of the certificate,
  offered as SNI) — or `"insecure": true`, spelled out. A failed origin handshake
  is an attempt failure: retried per the cluster's retry policy, else an honest 502.
  Upstream TLS sessions park in the per-worker pool alongside their connections.

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
| `src/tls/` | TLS: sans-io BIO-pair terminator + SNI, the kTLS key derivation and kernel ABI, and the fixed heap behind OpenSSL's memory hook |
| `third_party/openssl/` | vendored OpenSSL build recipe (sources fetched by content hash) |
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

**Phase 3, TLS (done): termination, kTLS, re-encryption, SNI** — TLS 1.3/1.2
termination with a vendored OpenSSL used *only* for the handshake, sans-io
over memory BIO pairs so every byte stays a ring op; ALPN (`http/1.1`); SNI
multi-certificate selection; allocations routed into a fixed heap reserved
at startup (exhaustion load-sheds the handshake, never OOM). After a quiet
handshake the record layer moves into the kernel (kTLS): traffic secrets
from the keylog callback, keys via HKDF-Expand-Label (RFC 8448-verified),
installed only when the record sequence is provably zero — otherwise the
connection stays on the userspace relay, which serves identical bytes.
Steady state, a kernel-TLS connection runs the *plaintext* relay code path.
Upstream re-encryption per cluster with explicit verification (CA bundle +
required hostname, or spelled-out insecure); a refused origin certificate
feeds the retry machinery like any attempt failure; upstream TLS sessions
park in the connection pool (the origin's session tickets rule out client-
side kTLS, so that hop stays on the BIO pair). Measured: single-hop TLS ≈
plaintext at 20k req/s (p50 ~135µs); kTLS saves ~10% proxy CPU at equal
latency; the fully encrypted chain (TLS client → zoxy → TLS origin) also
holds 20k req/s at p50 ~138µs with >99.9% upstream session reuse; ~161 KiB
TLS heap per userspace connection, ~0 after the kernel switchover. Closes
are polite (close_notify in both modes). See
[`docs/DESIGN.md`](docs/DESIGN.md) §6.

**Phase 4, operability (in progress) — graceful drain done:** on SIGTERM
each worker cancels its accept and closes its listener (later connects are
refused, not silently queued), closes idle keep-alive connections politely
(close_notify/kTLS-alert aware), completes in-flight responses with
`Connection: close` injected, and force-closes stragglers at a 30s drain
deadline enforced by the existing per-connection timers — no new timer
machinery. A worker exits only when every connection slot and ring op has
drained; a second signal exits immediately. The signal reaches a worker
blocked in `io_uring_enter` as a plain recv completion on a per-worker
socketpair. Verified by the simulator (a third of iterations drain
mid-traffic, replayable), integration tests, and the zero-alloc gate
(which now drains inside it). **Hot restart done too:** a `handoff` unix
socket serves every worker's listener fd to a successor over `SCM_RIGHTS`
(validated against the configured address before adoption), then the old
process drains — the duplicated fds keep the accept queues alive across
the restart, closing the drain-only RST window. Measured: an A→B restart
under a request hammer served 928/928 with zero failures. Still to come:
transfer stats across the restart pair, accept balancing across workers,
consistent-hash LB, tracing + Prometheus polish. HTTP/2 is deliberately
deferred behind operability: it
is a large protocol surface that lands better on an operable base, and
accept balancing is a prerequisite for its few-hot-connections traffic
shape.

**Later:** HTTP/2 and HTTP/3, TLS session resumption, and config
hot-reload. The full plan is in [`docs/DESIGN.md`](docs/DESIGN.md) §7.

## License

[MIT](LICENSE) © 2026 Vsevolod Strukchinsky
