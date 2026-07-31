# zoxy

[![CI](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml/badge.svg)](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/zoxy-io/zoxy/badge.svg?branch=main)](https://coveralls.io/github/zoxy-io/zoxy?branch=main)
[![Project stage: Experimental][project-stage-badge: Experimental]][project-stage-page]
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A zero-allocation L4/L7 edge proxy in Zig.

zoxy is built on the [TigerBeetle](https://tigerbeetle.com) I/O model — completion-based
with caller-owned completions — and follows [TigerStyle](docs/TIGER_STYLE.md):
**all memory is reserved at startup, and the request-serving path allocates nothing.**

One thread owns one `io_uring` and every pool. Scale-out is N independent
processes behind `SO_REUSEPORT`, never threads sharing memory.

- **L4** — blind TCP relay, half-close honored
- **L7** — HTTP/1.1 reverse proxy: host and longest-prefix routing, filter
  rules, keep-alive, pooled upstream connections
- **Balancing** — power-of-two-choices, round-robin, or rendezvous hashing
  for client stickiness
- **Health checks** — active TCP or HTTP probes, per cluster
- **Observability** — a Prometheus endpoint and a JSON access log
- **Bounded by construction** — every limit is a compile-time constant, and
  memory, file descriptors and ring depth are closed-form functions of them,
  printed at startup

## Quick start

The binary takes exactly one argument, the path to a JSON config:

```sh
zoxy config.json     # start the proxy
zoxy --help          # usage summary (-h)
zoxy --version       # print the version (-V)
```

Signals: `SIGTERM`/`SIGINT` drain in-flight connections and exit 0;
`SIGUSR1` dumps counters to stdout.

A minimal config — one L4 listener forwarding to one origin
([`config/example.json`](config/example.json)):

```json
{
    "listeners": [
        { "bind": "127.0.0.1:8080", "cluster": "origin", "protocol": "l4" }
    ],
    "clusters": {
        "origin": { "endpoints": ["127.0.0.1:9000"] }
    },
    "timeouts": {
        "connect_ms": 5000,
        "idle_ms": 60000,
        "drain_deadline_ms": 10000
    }
}
```

## Configuration

What follows is a tour. The **authoritative** surface — every field, enum and
numeric bound — is the JSON Schema shipped as a release asset and emitted
locally by `zig build schema`; it is generated from the parser, so it cannot
drift. The *reasoning* behind each behavior lives in
[`docs/DESIGN.md`](docs/DESIGN.md).

Config is parsed once at startup and never reloaded — a change is a process
restart, which is consistent with scaling out as independent processes.
Unknown fields are rejected rather than ignored.

### Listeners

A listener binds an address and speaks one protocol. `l4` relays bytes
without inspecting them; `http` runs the HTTP/1.1 reverse proxy.

```json
"listeners": [
    { "bind": "0.0.0.0:80",   "protocol": "http", "cluster": "web" },
    { "bind": "0.0.0.0:5432", "protocol": "l4",   "cluster": "postgres" }
]
```

Up to 8 listeners. Each is bound with `SO_REUSEPORT`, so running several
zoxy processes on the same port is the supported way to use more than one
core. Every connection — accepted and upstream alike — gets `TCP_NODELAY`
unconditionally: Nagle plus delayed ACK costs a reused keep-alive connection
a hard 40 ms stall, which is not worth a config knob.

### Routing

`"cluster"` is sugar for a single catch-all route. An `http` listener can
instead carry a route table — matched **longest-prefix within the matching
host** — of up to 32 entries:

```json
{
    "bind": "0.0.0.0:80",
    "protocol": "http",
    "routes": [
        { "host": "api.example.com", "prefix": "/v2", "cluster": "api-v2" },
        { "host": "api.example.com", "prefix": "/",   "cluster": "api" },
        { "prefix": "/static",                        "cluster": "cdn" },
        { "prefix": "/",                              "cluster": "web" }
    ]
}
```

A route with no `host` matches any host, and a host-specific route always
beats an any-host one. Matching uses the **canonical** path — percent-escapes
decoded, dot-segments collapsed — and that same canonical path is what the
origin receives, so the router and the backend cannot disagree about which
resource was named. Structure-changing escapes (`%2F`, `%00`, truncated
escapes) are rejected with `400`; no matching route is a `404`.

### Clusters and load balancing

A cluster is a named set of endpoints — static `IP:port` literals, resolved
once at load, since dynamic DNS is deliberately out of scope — plus how one
is chosen. Up to 16 clusters, 64 endpoints each.

```json
"clusters": {
    "api": {
        "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"],
        "pick": "p2c"
    }
}
```

| `pick` | behavior |
|---|---|
| `p2c` *(default)* | two uniform candidates; the one with fewer requests in flight wins |
| `rr` | strict rotation — predictable spread, useful for cache warming |
| `hash` | the same client always reaches the same endpoint |

Upstream connections are pooled process-wide and reusable by any request,
which is the single largest throughput lever in this design.

#### Sticky sessions

`pick: "hash"` is **rendezvous hashing over the healthy endpoints**, keyed on
the client address:

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "pick": "hash",
    "hash": { "key": "source_ip" }
}
```

It keeps **no table**, which is what makes it work here: the kernel spreads
one client's connections across zoxy processes by hashing the 4-tuple, so a
per-process stickiness table would be consulted by processes that never saw
that client. Being a pure function of the key and the healthy set, every
process agrees without sharing anything.

When a backend is ejected, only *its* clients move, and they all return when
it recovers. `source_ip` uses all four bytes of an IPv4 address and the /64
prefix of an IPv6 one, so stickiness survives privacy-address rotation.

The tradeoff is inherent to hashing on client address: NAT hides many clients
behind one address, and one heavy client cannot be split. Prefer `p2c` where
even load matters more than stickiness.

### Health checks

Per-cluster and opt-in. A prober dials each endpoint in turn; `fall`
consecutive failures eject it from balancing and close its pooled
connections, and `rise` consecutive successes restore it.

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "check": { "type": "http", "path": "/healthz", "expect_status": 200 }
}
```

`type` is `tcp` (the port accepts) or `http` (a path answered the expected
status). Defaults: `fall` 3, `rise` 2, `expect_status` 200, and a probe
budget of `timeouts.connect_ms` unless `timeout_ms` overrides it.
`timeouts.health_interval_ms` (default 2000) paces the gap between sweeps.

If *every* endpoint in a cluster is ejected, zoxy fails open and uses them
all — routing nowhere would turn a probe verdict into an outage of its own.

### Filters

An `http` listener can carry up to 32 rules, evaluated top-down. Each has a
match predicate — absent fields match anything — and actions applied in order.

```json
"filters": [
    {
        "match": {
            "path_prefix": "/admin",
            "headers": [{ "name": "X-Internal", "present": true }]
        },
        "actions": [{ "header_set": { "name": "X-Role", "value": "admin" } }]
    },
    {
        "match": { "path_prefix": "/admin" },
        "actions": [{ "reject": 403 }]
    },
    {
        "match": { "method": ["GET"], "host": "cdn.example.com" },
        "actions": [{ "rewrite_prefix": { "from": "/static", "to": "/" } }]
    }
]
```

Match on `method`, `host`, `path_prefix`, and header predicates
(`present` / `equals` / `contains`). Actions are `reject` with a status,
`header_set` / `header_add` / `header_remove`, and `rewrite_prefix`.

Rules compile into immutable tables at load time and are interpreted with
bounded loops — no plugins, no scripting, nothing that can allocate or run
unbounded. A rewrite changes only what is *forwarded*: routing already chose
the cluster from the original path, so a rewrite never re-routes.

### Timeouts

```json
"timeouts": {
    "connect_ms": 5000,
    "idle_ms": 60000,
    "drain_deadline_ms": 10000,
    "max_lifetime_ms": 0,
    "request_ms": 0,
    "health_interval_ms": 2000
}
```

| field | meaning |
|---|---|
| `connect_ms` **required** | per-try upstream connect budget |
| `idle_ms` **required** | idle and head-read deadline — what a slowloris meets |
| `drain_deadline_ms` **required** | how long a `SIGTERM` drain waits before reaping stragglers |
| `max_lifetime_ms` | absolute connection-age cap regardless of activity; `0` disables |
| `request_ms` | cap on one L7 exchange, **not** refreshed by activity — bounds a request that is merely slow, where `idle_ms` only bounds one that has stalled; `0` disables |
| `health_interval_ms` | pause between health-probe sweeps |

### Limits

Optional. The compiled constants are hard ceilings; this block sizes the
actual pools anywhere from 1 up to them, so a small deployment neither
reserves nor demands the ceiling's resources.

```json
"limits": {
    "conn_slots": 4096,
    "relay_buffers": 4096,
    "upstream_slots": 4096
}
```

The defaults are deliberately lean — 1386 connection slots, 1386 relay buffer
pairs, 1313 upstream slots, roughly 34 MiB of pools — sized to start under a
stock 4096 `RLIMIT_NOFILE`. The ceiling is 11463 of each. Raising the pools
raises the file-descriptor demand, which zoxy asserts against `RLIMIT_NOFILE`
at startup rather than discovering as `EMFILE` later.

`cq_fill_eighths` trades connection ceiling for `io_uring` completion-queue
burst headroom; `access_log_buffer_bytes` sizes the access log's staging
buffers.

## Observability

### Metrics

An optional listener serving Prometheus exposition text — every shed rung,
every lifecycle counter, and live pool-occupancy gauges:

```json
"admin": { "bind": "127.0.0.1:9100" }
```

One scrape is served at a time from a slot reserved outside the data-path
pools, so a scrape and a request can never shed one another. `SIGUSR1` dumps
the same rendering to stdout, which needs no listener at all.

The gauges matter as much as the counters: a `shed_*` counter only moves once
a wall is *hit*, while `zoxy_conn_slots_in_use` against
`zoxy_conn_slots_capacity` shows the approach.

### Access log

One JSON object per line — one per HTTP exchange (rejects, `503` sheds and
timeouts included) and one per L4 connection:

```json
"access_log": { "sink": "stdout" }
```

```json
{"time":"2026-07-31T09:14:22.481Z","kind":"http","outcome":"ok","client":"10.1.2.3:52344","method":"GET","host":"api.example.com","path":"/v1/items","status":200,"upstream_reused":true,"upstream_replayed":false,"duration_us":1873,"bytes_in":142,"bytes_out":4096,"cluster":"api","upstream":"10.0.0.7:8080"}
```

`outcome` is what `status` cannot tell you: an origin answering `503` and
zoxy shedding a request with `503` are the same three digits and opposite
events. It reads `ok`, `rejected`, `shed`, `timed_out`, `upstream_failed`,
`aborted`, or — for L4 — `closed`.

Logging never blocks the event loop, so a sink that stalls costs dropped
lines rather than latency; `zoxy_access_log_dropped` counts them exactly.
Rotation is the operator's: pipe stdout wherever this process's output
already goes.

## Under load

The defining behavior: **when a resource is exhausted, zoxy degrades the
newest work, keeps serving admitted work, and never allocates, blocks or
dies.** Every limit has a defined answer rather than an unbounded queue.

- **Exhaustion sheds at a defined point.** No connection slot → the socket is
  closed with an RST, so the client learns immediately instead of timing out.
  No relay buffer or upstream slot for an HTTP request → a static `503` from
  constant memory, and the connection is *kept* when the client's byte stream
  is still on a message boundary, because closing costs more than the work
  being shed.
- **Watermarks before walls.** Each pool raises a pressure flag at 3/4
  occupancy, which shortens idle timeouts so quiet connections return their
  resources before the wall is reached.
- **Accept never pauses.** The kernel backlog stays drained even while
  shedding, so clients get an immediate signal rather than a timeout.
- **`SIGTERM` drains.** Listeners close, keep-alive stops being honored,
  in-flight work finishes under `drain_deadline_ms`, then the process exits 0.
- **The budget is printed, not hoped for.** Startup prints the closed-form
  memory, file-descriptor and ring-op totals it will never exceed, and
  asserts the fd count against `RLIMIT_NOFILE` before serving anything.

[`docs/DESIGN.md`](docs/DESIGN.md) §8 documents each rung and why it answers
the way it does.

## Benchmarks

[**zoxy-io/benchmark**](https://github.com/zoxy-io/benchmark) runs unattended
every night and publishes to
[zoxy-io.github.io/benchmark](https://zoxy-io.github.io/benchmark/). It
compares zoxy against **HAProxy**, **Pingora** and **Envoy** as HTTP/1.1
reverse proxies doing the identical job — parse each request, forward it over
a pooled keep-alive upstream, stream the response back — currently under the
`c1k` profile. That repository documents the fairness rules and the fleet
topology; read the nightly report rather than any number quoted here.

## Development

### Requirements

- **Zig 0.16** (pinned by [devenv](devenv.nix): `zig_0_16` + `zls`).

With [devenv](https://devenv.sh), `.envrc` activates the same shell
automatically on `cd`:

```sh
devenv shell                    # zig 0.16, zls, kcov
zig build                       # build zig-out/bin/zoxy
zig build ci                    # the per-change gate: tests + lint + simulation
zig build test                  # unit tests
zig build sim -- 0 500          # deterministic simulator: [seed] [iterations]
zig build schema                # emit zig-out/config.schema.json
zig build run -- config/example.json
zig build bench                 # loopback bands: direct vs zoxy vs haproxy
```

Correctness rests on a deterministic simulator: the serving path is written
against an I/O seam, so a seeded adversarial backend runs the *real* code
against virtual sockets and a virtual clock — partial reads down to one byte,
resets at every point in every exchange, delayed and black-holed connects. A
failing seed prints itself and replays exactly.

> [!NOTE]
> The bench harness is always built ReleaseFast, but it measures the
> `zig-out/bin/zoxy` you last built — and plain `zig build` produces a
> Debug binary. Run `zig build -Doptimize=ReleaseFast` first before
> quoting numbers against haproxy.

## License

[MIT](LICENSE) © 2026 Vsevolod Strukchinsky

[project-stage-badge: Experimental]: https://img.shields.io/badge/Project%20Stage-Experimental-yellow.svg
[project-stage-page]: https://blog.pother.ca/project-stages/
