# zoxy

[![CI](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml/badge.svg)](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/zoxy-io/zoxy/badge.svg?branch=main)](https://coveralls.io/github/zoxy-io/zoxy?branch=main)
[![Project stage: Experimental][project-stage-badge: Experimental]][project-stage-page]
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

A release prints its bare version, `zoxy 0.0.7`. A build made from source
after that release adds what distinguishes it —
`zoxy 0.0.7 (v0.0.7-5-gabc1234)`, and `-dirty` when the tree had
uncommitted changes — so a version in a bug report is never a release's
number attached to something else. Packagers can name their own build
with `zig build -Dbuild-id=…`. The same line opens the startup banner,
which is what a bug report usually pastes.

Signals: `SIGTERM`/`SIGINT` drain in-flight connections and exit 0;
`SIGUSR1` dumps counters to stdout.

A minimal config — one L4 listener forwarding to one origin. For one with
health checks and the access log turned on, see
[`config/example.json`](config/example.json):

```json
{
    "listeners": [
        { "bind": "127.0.0.1:8080", "cluster": "origin", "protocol": "l4" }
    ],
    "clusters": {
        "origin": { "endpoints": ["127.0.0.1:9000"] }
    }
}
```

That is the whole file: every other block — `timeouts`, `limits`,
`access_log` — has defaults, so tuning is what you opt into rather than
what you start with.

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

Listener count is bounded by your config's own ring and fd budgets,
checked at startup, not by a compiled ceiling. Each is bound with
`SO_REUSEPORT`, so running several zoxy processes on the same port is
the supported way to use more than one core. Every connection —
accepted and upstream alike — gets `TCP_NODELAY` unconditionally:
Nagle plus delayed ACK costs a reused keep-alive connection a hard
40 ms stall, which is not worth a config knob.

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
is chosen. Cluster and endpoint counts are bounded by your config, not
by a compiled ceiling — the startup banner prints what the endpoint tables cost.

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
| `p2c` *(default)* | two uniform candidates; the one carrying less in-flight work wins — HTTP requests and L4 connections both count |
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

The key is the *observed* client address, so behind another proxy or LB
every connection carries that machine's address and the whole cluster
hashes to one endpoint. See
[Learning who the client is](#learning-who-the-client-is-proxy-protocol)
for how an `l4` listener recovers the real client.

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

### Protecting a backend from overload

`max_inflight` caps the concurrent work zoxy will ask of **one endpoint**.
It is the per-server unit, so a three-endpoint cluster with a cap of 100
admits up to 300 — the same shape as HAProxy's `server ... maxconn`.

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "max_inflight": 100
}
```

An endpoint at its cap is skipped, so requests keep flowing while any
endpoint has room. Only when *every* endpoint is full does zoxy refuse: an
HTTP request is answered `503` and an L4 connection is closed, since a byte
relay has no way to say "try later". Absent, a cluster is uncapped.

This is the one limit that fails **closed**, and the difference from health
checks is deliberate: an ejected cluster means *we do not know whether these
work*, so trying is better than refusing — while a capped one means *we know
they are full*, and sending more is precisely what the cap exists to prevent.

Both protocols count against the same figure: an in-flight HTTP request and
a live L4 connection are each one unit of work the backend is carrying.
`zoxy_l7_shed_endpoint_inflight` and `zoxy_l4_shed_endpoint_inflight` count
refusals — kept apart from `zoxy_l7_shed_upstream_slots`, which means zoxy
ran out of its own slots and wants a wider pool rather than a busier backend.

### Telling the origin who the client is

Without this, everything behind zoxy sees zoxy — origin logs, IP
allowlists, per-client rate limits. An `http` listener can add
`X-Forwarded-For`:

```json
{
    "bind": "0.0.0.0:80",
    "protocol": "http",
    "cluster": "web",
    "forwarded": { "mode": "replace" }
}
```

**There is no default mode, on purpose.** The two answers are each a
security bug in the other's position, and zoxy cannot tell from the
inside which position it is in:

| mode | behaviour | use when |
|---|---|---|
| `replace` | state the peer zoxy observed, discard any inbound chain | **at the edge** — an inbound chain is client-controlled there, so honouring it lets a caller pick the address your allowlists then trust |
| `append` | extend the inbound chain with the observed peer | **only behind proxies you own** — anywhere else this is the forgery above, appended to |

Omit the block and the header is passed through untouched, exactly as
before the feature existed.

The carried chain is bounded: a chain grows by an address per hop and
nothing in HTTP caps it, so past `forwarded_chain_bytes_max` (512) it is
dropped *whole* — leaving the line stating only the observed peer, which
is the safe direction, since a truncated chain reads as complete and
isn't. `zoxy_forwarded_chain_dropped` counts that.

Filters may not set `X-Forwarded-For`; the loader rejects it. A filter
can only write a constant, so it would pin one fixed address to every
client — which looks like forwarding and is the opposite of it.

### Learning who the client is (PROXY protocol)

The mirror problem: put a load balancer in front of zoxy and *zoxy* sees
only the balancer. That breaks more than logging — `pick: "hash"` keys
on the client address, so behind an LB every connection hashes alike and
the whole fleet lands on one endpoint. An `l4` listener can instead
require each connection to open with a PROXY protocol header (v1 or v2 —
what AWS NLB, GCP and HAProxy emit) announcing the real client:

```json
{
    "bind": "0.0.0.0:5432",
    "protocol": "l4",
    "cluster": "postgres",
    "proxy_protocol": { "mode": "require" }
}
```

**`require` is the only mode, on purpose.** A listener that accepted a
header *when one happens to show up* would let any client that can reach
it choose its own address — and with it its own sticky backend and its
own access-log lines. The PROXY protocol spec forbids that of receivers,
and HAProxy gates the same feature behind an explicit `accept-proxy` for
the same reason. So a `require` listener closes any connection that does
not open with a valid header: it is unusable by anything except the
proxy configured in front of it, which is the point. Turn it on only
where the listener is reachable exclusively through that proxy.

What the header announces is what zoxy believes everywhere the client
address is consumed: the hash pick, the access log's `client` field. A
header that announces nothing — v1 `UNKNOWN`, v2 `LOCAL`, the shapes a
balancer's own health checks arrive in — is accepted and keeps the
observed peer. Headers are size-capped at 512 bytes (v2 TLVs within the
cap are skipped; a declared length past it is refused at once), and
header bytes never count toward the log's `bytes_in` — only payload
does.

`zoxy_l4_proxy_header_accepted` and `zoxy_l4_proxy_header_invalid`
count the verdicts; a rising `invalid` means something that is not the
configured proxy is reaching the listener — exactly what the mode
exists to refuse. `http` listeners reject the block for now: the L7
receive phase does not exist yet.

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

The whole block is optional, and so is every field in it — the values
above are the defaults, written out. An explicit `0` disables the three
caps; for `connect_ms` and `idle_ms` it is rejected, since a zero-length
dial or idle budget is a mistake rather than a policy.

`connect_ms` must also be **strictly below** `idle_ms`, or the config is
rejected at load. A connection's first deadline is the dial budget and the
dial's completion re-stores it to the idle one, but zoxy's single timer per
connection never moves earlier once armed — so an idle budget that does not
exceed the dial budget would not take effect at the handoff and would reap
late instead. Note this bites when only *one* field is tuned: raising
`connect_ms` past the default 60 s `idle_ms` is rejected just the same.

| field | default | meaning |
|---|---|---|
| `connect_ms` | `5000` | per-try upstream connect budget |
| `idle_ms` | `60000` | idle and head-read deadline — what a slowloris meets |
| `drain_deadline_ms` | `0` | how long a `SIGTERM` drain waits before reaping stragglers; `0` waits for the last connection |
| `max_lifetime_ms` | `0` | absolute connection-age cap regardless of activity; `0` disables |
| `request_ms` | `0` | cap on one L7 exchange, **not** refreshed by activity — bounds a request that is merely slow, where `idle_ms` only bounds one that has stalled; `0` disables |
| `health_interval_ms` | `2000` | pause between health-probe sweeps |

`drain_deadline_ms` defaults to waiting indefinitely because there is no
figure to borrow: nginx, HAProxy and Caddy all wait forever by default,
Traefik picks 10 s and Envoy 600 s. Whatever sent the signal already owns
the upper bound — systemd's `TimeoutStopSec`, Kubernetes'
`terminationGracePeriodSeconds` — and ends the wait with `SIGKILL`. Set a
number here when you want zoxy to give up before your platform does.

### Limits

Optional. The compiled constants are hard ceilings; this block sizes the
actual pools anywhere from 1 up to them, so a small deployment neither
reserves nor demands the ceiling's resources.

```json
"limits": {
    "conn_slots": 4096,
    "relay_buffers": 4096,
    "upstream_slots": 4096,
    "head_buffers": 1024,
    "upstream_head_buffers": 512,
    "head_buffer_bytes": 16384
}
```

The defaults are deliberately lean — 1386 connection slots, 1386 relay buffer
pairs, 1313 upstream slots, roughly 34 MiB of pools — sized to start under a
stock 4096 `RLIMIT_NOFILE`. The ceiling is 11466 of each. Raising the pools
raises the file-descriptor demand, which zoxy asserts against `RLIMIT_NOFILE`
at startup rather than discovering as `EMFILE` later.

`head_buffers` and `upstream_head_buffers` bound *request heads in flight*
rather than open connections: idle keep-alive connections and parked origin
connections hold no head buffer, so these default to their never-shedding
ceilings (`conn_slots` and `upstream_slots`) and are the knobs a keep-alive-
heavy deployment trades down for memory. `head_buffer_bytes` sizes every head
buffer and is therefore the largest HTTP head accepted (oversize requests are
answered `414`/`431`) — raise it for big-cookie/JWT traffic, 1 KiB to 1 MiB,
default 8 KiB.

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
