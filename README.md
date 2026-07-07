# zoxy

[![CI](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml/badge.svg)](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/zoxy-io/zoxy/badge.svg?branch=main)](https://coveralls.io/github/zoxy-io/zoxy?branch=main)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A zero-allocation L4/L7 edge proxy in Zig, in the spirit of Envoy and Linkerd.

zoxy is built on the [TigerBeetle](https://tigerbeetle.com) I/O model — completion-based
`io_uring` with caller-owned completions — and follows [TigerStyle](docs/TIGER_STYLE.md):
**all memory is reserved at startup, and the request-serving path allocates nothing.**

> **Status: experimental — HTTP/2 downstream and config schema + reload + DSL
> now done (Phases 5–6, slices 1–3).** A working HTTPS reverse proxy speaking
> **HTTP/1.1 and HTTP/2** downstream: TLS termination with kernel-TLS offload,
> SNI multi-cert and ALPN, verified upstream re-encryption, keep-alive and
> pooling on both sides, a resilience layer (P2C and Maglev consistent-hash
> balancing, retries, circuit breaking, outlier detection, health checks),
> graceful drain, zero-downtime hot restart, and a strict schema-validated
> config with live SIGHUP reload and an optional terse Zoxyfile DSL — but not
> yet production-ready — see
> [Scope & roadmap](docs/DESIGN.md#7-build-history--roadmap). Linux only.

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
- **HTTP/2 downstream, sans-io and bounded.** An own HTTP/2 core: every knob —
  concurrent streams, HPACK dynamic-table size, frame size, flow-control windows —
  is a startup-reserved constant, advertised in SETTINGS and enforced on the wire
  (a peer setting never grows past what was reserved). Negotiated by ALPN; each
  stream maps to one HTTP/1.1 upstream transaction over the existing pool, and the
  stream window *is* the relay backpressure.
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

Or point it at a config file — a [Zoxyfile](#configuration) or JSON (the
extension selects the format):

```sh
./zig-out/bin/zoxy path/to/zoxy.conf    # Zoxyfile DSL (any non-.json path)
./zig-out/bin/zoxy path/to/config.json  # JSON
```

zoxy logs a startup line and per-request access lines to stderr:

```
info: zoxy listening on 127.0.0.1:8080 across 8 worker(s)
GET /api/thing proxied 70
```

## Configuration

zoxy reads one config file at startup (parsed once into an immutable config).
The friendly surface is the **Zoxyfile** — a terse, line-oriented DSL that
*lowers to* the canonical JSON format ([below](#json-the-canonical-format)),
which stays the single source of truth. A path that does **not** end in `.json`
is parsed as a Zoxyfile. Routes are matched in order; the first whose host (`*`
or an exact, port-insensitive match) and `path_prefix` match wins.

```
# zoxy.zoxy — one directive per line, `#` comments, `{ }` blocks
listen 127.0.0.1:8080
admin  127.0.0.1:9901

route api.example.com /v1 -> api   # [host] [path] -> cluster
route -> default                   # no match tokens: any host, any path

cluster api {
    endpoints 127.0.0.1:9001 127.0.0.1:9002
}

cluster default {
    endpoints 127.0.0.1:9000
}
```

A block's opening `{` may trail its directive; its `}` sits on its own line.
Durations take a `ms`/`s` suffix (a bare number is milliseconds). In a `route`,
`host` defaults to `*` and `path_prefix` to `/`; a lone match token beginning
`/` is the path, otherwise the host. An endpoint is `ip4:port`, `[ip6]:port`,
or `hostname:port` — a hostname resolves **once at startup** (the data path
never does DNS; a SIGHUP reload re-resolves), each distinct name is looked up
once, and every resolved address becomes its own endpoint. Addresses the host
has no route for are dropped (a v4-only machine ignores AAAA answers; if
nothing survives, startup fails loudly). Link-local IPv6 (`fe80::/10`) is
rejected — no literal syntax can carry the zone a dial would need.
`listen`/`admin` are IPv4 for now. Endpoints in a
cluster are load-balanced
P2C least-request: two random picks, the one with fewer in-flight requests wins,
unhealthy/ejected endpoints are avoided (and when *none* is available, zoxy
fails open and routes anyway). `admin` (optional) serves Prometheus-style
counters — `curl http://127.0.0.1:9901/metrics` — on a dedicated thread, off the
data path. See [`examples/example.zoxy`](examples/example.zoxy) for the full
surface.

### JSON (the canonical format)

A `.json` path is parsed directly. JSON is what the Zoxyfile lowers to and what
everything downstream validates — run `zig build adapt -- path/to/config.zoxy`
to see the JSON a Zoxyfile produces. The same config, written as JSON:

```json
{
  "$schema": "./config.schema.json",
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

Parsing is **strict**: an unknown key is rejected by name, so a typo can't
silently disable a feature. A [JSON Schema](config.schema.json) is generated
from the config types (`zig build schema`) and guarded against drift in CI
(`zig build check-config`); the `$schema` key wires up editor completion and is
otherwise ignored. Both formats share this one validation path — the Zoxyfile is
only a front-end, never a second source of truth.

### Resilience (per cluster, all optional)

```
cluster api {
    endpoints 127.0.0.1:9001 127.0.0.1:9002
    lb least_request           # or: maglev [target | header <name>]
    per_try_timeout 2s
    retry {
        max 2
        backoff_base 25ms
        backoff_cap 1s
        budget_percent 20
        budget_min 3
    }
    circuit_breaker {
        max_connections 128
        max_pending 32
        max_requests 256
        max_retries 16
    }
    outlier {
        consecutive_failures 5
        ejection 30s
        max_ejection_percent 50
    }
    health_check {
        interval 5s
        timeout 2s
        healthy_threshold 2
        unhealthy_threshold 3
    }
}
```

An absent block leaves that feature off; absent fields inside a present block
take the defaults shown above, except `retry.max` (required) and the
`circuit_breaker` limits (each absent limit is unbounded — the values above are
examples). Semantics:

- **`per_try_timeout`** — deadline per upstream attempt (connect through the
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
  eject the endpoint for `ejection`, bounded by `max_ejection_percent` of
  the cluster.
- **`health_check`** — active TCP-connect probes; result streaks flip the
  endpoint's health at the thresholds. Endpoints start healthy.

All limits and budgets are **per worker** (share-nothing — no cross-worker
coordination): a cluster-wide budget is the configured value × worker count.
(In JSON these lower to `per_try_timeout_ms`, `ejection_ms`, `interval_ms`, … —
the Zoxyfile drops the `_ms` suffix and parses the unit instead.)

### TLS (optional)

Terminate TLS on the listener, and/or re-encrypt to a cluster's origins:

```
listen 0.0.0.0:443

tls {
    certificate certs/default.pem
    key certs/default.key
    kernel_offload on
    http2                      # also offer h2 in ALPN
    identity {                 # SNI-selected extra identity (repeatable)
        server_names other.example.com *.other.example.com
        certificate certs/other.pem
        key certs/other.key
    }
}

route -> api

cluster api {
    endpoints 10.0.0.5:8443
    tls {
        server_name api.internal
        ca_file certs/internal-ca.pem
    }
}
```

- **Listener `tls`** terminates TLS 1.3/1.2 (full handshakes; no resumption yet).
  ALPN offers `http/1.1`, and `http2` additionally offers `h2` — an
  h2-negotiating client is served over the HTTP/2 data path (each stream mapped to
  one HTTP/1.1 upstream transaction). An `identity` block selects a certificate by
  SNI (`server_names`: exact names and single-label `*.` wildcards, declared
  explicitly — never introspected from certificates); absent or unmatched SNI gets
  the default pair.
- **`kernel_offload`** (default `on`) hands each connection's record layer to
  the kernel after the handshake, when provably safe (record sequence zero, AES-GCM,
  `tls` module present) — otherwise that connection transparently stays on the
  userspace relay, which serves identical bytes. Closes send `close_notify` either way.
- **Cluster `tls`** re-encrypts to the origins. Verification is an explicit choice:
  `ca_file` (a PEM bundle) **and** `server_name` (required of the certificate,
  offered as SNI) — or `insecure`, spelled out. A failed origin handshake
  is an attempt failure: retried per the cluster's retry policy, else an honest 502.
  Upstream TLS sessions park in the per-worker pool alongside their connections.

## Benchmarking

```sh
bench/run.sh                 # 10s saturating run over 64 connections
bench/run.sh -c 128 -d 30s   # more connections, longer — find the ceiling
```

Stands up an nginx origin and zoxy on loopback, then drives direct baselines
(keep-alive — the honest comparison, plus `Connection: close` to show the
handshake tax) and the proxied path with
[h2load](https://nghttp2.org/documentation/h2load-howto.html) — nghttp2's
closed-loop load generator, forced to HTTP/1.1 (`--h1`) — so the proxy hop's
throughput and latency distribution are directly comparable. h2load ships in
the dev shell; the script fetches it via nix if it isn't on PATH. Run-to-run
variance on a busy box easily dominates the hop cost — compare bands of
several runs, not single numbers.

## Architecture

Design rationale and the Zig-0.16 findings behind these choices are in
[`docs/DESIGN.md`](docs/DESIGN.md); the coding conventions are in
[`docs/TIGER_STYLE.md`](docs/TIGER_STYLE.md).

## License

[MIT](LICENSE) © 2026 Vsevolod Strukchinsky
