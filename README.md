# zoxy

[![CI](https://github.com/floatdrop/zoxy/actions/workflows/ci.yml/badge.svg)](https://github.com/floatdrop/zoxy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A zero-allocation L7 edge proxy in Zig, in the spirit of Envoy and Linkerd.

zoxy is built on the [TigerBeetle](https://tigerbeetle.com) I/O model — completion-based
`io_uring` with caller-owned completions — and follows [TigerStyle](docs/TIGER_STYLE.md):
**all memory is reserved at startup, and the request-serving path allocates nothing.**

> **Status: experimental, Phase-0.** A working HTTP/1.1 reverse proxy, but not yet
> production-ready — see [Scope & roadmap](#scope--roadmap). Linux only.

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
zig build run          # run using ./zoxy.json
```

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
load-balanced round-robin. `admin` (optional) serves Prometheus-style counters —
`curl http://127.0.0.1:9901/metrics` — on a dedicated thread, off the data path.

## Benchmarking

```sh
bench/run.sh                 # 30k req/s for 10s over 64 connections
bench/run.sh -R 40000 -d 30s # find the saturation point
```

Stands up an nginx origin and zoxy on loopback, then drives both a direct
baseline (with `Connection: close`, matching zoxy's one-request-per-connection
model) and the proxied path at the same constant rate with
[zrk](https://github.com/floatdrop/zrk), so the corrected latency of the proxy
hop is directly comparable. Falls back to closed-loop `wrk` (via nix, with a
warning) when zrk is not installed.

## Architecture

```
per core (thread-per-core, share-nothing):
  SO_REUSEPORT listener ──io.accept──► single-threaded io_uring loop
    io.recv ─► parse head ─► route ─► io.connect upstream ─► relay both ways
```

Source layout:

| Path | What |
|------|------|
| `src/io/` | `IO` + `Completion` over `std.os.linux.IoUring` (comptime backend seam) |
| `src/net/listener.zig` | `SO_REUSEPORT` TCP listener |
| `src/net/pool.zig` | fixed object pool over an intrusive free list |
| `src/net/proxy.zig` | the proxy data path (parse → route → connect → relay) |
| `src/http/h1.zig` | zero-copy HTTP/1.1 request parser |
| `src/config.zig`, `src/proxy/` | config, routing, round-robin balancing |
| `src/obs/` | metrics counters + per-worker access log |
| `src/mem/guard.zig` | zero-allocation acceptance gate |

Design rationale and the Zig-0.16 findings behind these choices are in
[`docs/DESIGN.md`](docs/DESIGN.md); the coding conventions are in
[`docs/TIGER_STYLE.md`](docs/TIGER_STYLE.md).

## Scope & roadmap

**Phase 0 (done):** HTTP/1.1 with a one-request-per-connection contract
(hop-by-hop headers stripped, `Connection: close` forced), static config,
host/path routing, round-robin, bounded relay with backpressure, per-connection
deadline, metrics + admin endpoint + access log, and the zero-alloc gate.

**Phase 1 (next): HTTP/1.1 keep-alive** — response framing (Content-Length /
chunked), downstream connection reuse with per-request re-routing, and a
per-worker upstream H1 pool. Close-per-request measures ~6× slower than
keep-alive on loopback; this is the biggest single lever.

**Later:** resilience (health checks, circuit breaking, retries, P2C/EWMA),
TLS termination (planned via OpenSSL FFI), HTTP/2 and HTTP/3, graceful drain +
hot restart, and config hot-reload. The full plan is in
[`docs/DESIGN.md`](docs/DESIGN.md) §7.

## License

[MIT](LICENSE) © 2026 Vsevolod Strukchinsky
