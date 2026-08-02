# zoxy documentation

How to configure and operate zoxy: every block a config can carry, what the
proxy exposes while it runs, and what it does when a resource runs out.

The **authoritative** surface — every field, enum and numeric bound — is the
JSON Schema shipped as a release asset and emitted locally by `zig build
schema`. It is generated from the parser, so it cannot drift, and
[zoxy.io/config](https://zoxy.io/config/) renders the copy from the latest
release. What follows is the tour; the *reasoning* behind each behavior lives
in [DESIGN.md](DESIGN.md), which the bare `§` references point at.

## Running zoxy

The binary takes exactly one argument, the path to a JSON config:

```sh
zoxy config.json     # start the proxy
zoxy --help          # usage summary (-h)
zoxy --version       # print the version (-V)
```

A release prints its bare version, `zoxy 0.0.9`. A build made from source
after that release adds what distinguishes it —
`zoxy 0.0.9 (v0.0.9-5-gabc1234)`, and `-dirty` when the tree had uncommitted
changes — so a version in a bug report is never a release's number attached
to something else. Packagers can name their own build with
`zig build -Dbuild-id=…`. The same line opens the startup banner, which is
what a bug report usually pastes.

The banner goes to stderr, and so does the `SIGUSR1` counter dump: stdout
belongs to the access log, whose `stdout` sink must stay one uncontaminated
JSON line per event.

| signal | effect |
|---|---|
| `SIGTERM`, `SIGINT` | drain in-flight connections, then exit 0 |
| `SIGUSR1` | dump counters to stderr |
| `SIGHUP` | reopen the access log's `file` sink — rotation, and nothing else |

A completed drain prints the counters one last time on its way out, so a
process that exited cleanly leaves its final tally behind without anyone
having to have scraped it.

A config zoxy will not accept is refused before anything is bound: the
process prints `zoxy: invalid config '<path>': <reason>` and exits `1`. That
is what makes the replacement procedure below safe to run against a live
port.

A minimal config — one L4 listener forwarding to one origin:

```json title="config.json"
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
`access_log` — has defaults, so tuning is what you opt into rather than what
you start with. [`config/example.json`](../config/example.json) is the same
listener with health checks and the access log turned on.

## Replacing a running instance

There is no reload. The pools, the ring and every table are sized from the
config at startup and never grow, so nothing re-reads the file — which is why
`SIGHUP` is free to mean log rotation and only that. Hot restart is a
non-goal for the same reason ([DESIGN.md](DESIGN.md) §1).

What stands in for it is the property scale-out already rests on: every
listener is bound with `SO_REUSEPORT`, so a second process can hold the same
port as the first. Replacing a config is therefore two commands, in this
order:

<!-- figure: reuseport-handoff -->

```sh
zoxy new-config.json &   # the replacement binds the same port and starts serving
kill -TERM "$old_pid"    # the old process drains its work, then exits 0
```

Starting the replacement *first* is what makes this safe: a config zoxy
refuses never reaches a listener, so the new process exits `1` with its
reason and the old one — which was never signalled — keeps serving
throughout. Signalling first would put the port out of service for as long as
the replacement took to parse its config and fail.

Between the two commands **both configs are live.** The kernel picks a
listener per connection by hashing the 4-tuple, so a request lands on
whichever process it chose; the overlap is not a cutover but a window where
both answer. For tuning a timeout, adding an endpoint or moving a cluster
that is fine. For a change that has to take effect at a known instant —
withdrawing a route that must stop being reachable — it is the wrong tool,
and the honest procedure is to stop before you start and wear the gap.

> [!WARNING]
> The handoff is not lossless by default. Connections the old process had
> already accepted but not yet served are reset when it closes its listener,
> rather than being handed to the survivor. Linux 5.14 added
> `net.ipv4.tcp_migrate_req`, off by default, which migrates them to another
> socket in the group instead; turn it on where the handoff has to be clean.
> zoxy narrows the window on its own — accept never pauses, so the backlog is
> kept drained (§8) — but it cannot close it.

Both processes have to run as the same effective user. The kernel will not
add a socket to a `SO_REUSEPORT` group bound by a different UID, which is
what stops one user from quietly joining another's port.

How long the old process lingers is `timeouts.drain_deadline_ms`; with the
default `0` it waits for its last connection to finish. Its exit prints the
final counters, so the run it just ended is still accountable.

The same two commands are how you *add* capacity rather than replace it —
start N processes on the same port and signal none of them. That is the
supported way to use more than one core, and a replacement is just the case
where the old instance leaves afterwards.

## Configuration

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

Listener count is bounded by your config's own ring and fd budgets, checked
at startup, not by a compiled ceiling. The banner prints both, and a config
that does not fit is refused there rather than being a number to remember.

Each is bound with `SO_REUSEPORT`, so running several zoxy processes on the
same port is the supported way to use more than one core, and the way to
[replace a running instance](#replacing-a-running-instance). Every
connection — accepted and upstream alike — gets `TCP_NODELAY`
unconditionally: Nagle plus delayed ACK costs a reused keep-alive connection
a hard 40 ms stall, which is not worth a config knob.

### Routing

`"cluster"` is sugar for a single catch-all route. An `http` listener can
instead carry a route table — matched **longest-prefix within the matching
host** — of any length your config cares to write:

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

### Sticky sessions

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

> [!IMPORTANT]
> There is no default mode, on purpose. The two answers are each a security
> bug in the other's position, and zoxy cannot tell from the inside which
> position it is in.

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

> [!IMPORTANT]
> `require` is the only mode, on purpose. A listener that accepted a header
> *when one happens to show up* would let any client that can reach it choose
> its own address — and with it its own sticky backend and its own
> access-log lines.

The PROXY protocol spec forbids that of receivers, and HAProxy gates the same
feature behind an explicit `accept-proxy` for the same reason. So a `require`
listener closes any connection that does not open with a valid header: it is
unusable by anything except the proxy configured in front of it, which is the
point. Turn it on only where the listener is reachable exclusively through
that proxy.

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

An `http` listener can carry a list of rules, evaluated top-down. Each has a
match predicate — absent fields match anything — and actions applied in order.
As with routes, nothing caps the list but the file you write.

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

> [!WARNING]
> `connect_ms` must be **strictly below** `idle_ms`, or the config is
> rejected at load. A connection's first deadline is the dial budget and the
> dial's completion re-stores it to the idle one, but zoxy's single timer per
> connection never moves earlier once armed — so an idle budget that does not
> exceed the dial budget would not take effect at the handoff and would reap
> late instead. This bites when only *one* field is tuned: raising
> `connect_ms` past the default 60 s `idle_ms` is rejected just the same.

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
pairs, 1311 upstream slots, roughly 34 MiB of pools — sized to start under a
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
the same rendering to stderr, which needs no listener at all.

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

`sink` is either `stdout` — the process's own standard output, inherited
rather than opened, so it costs no file descriptor and carries no rotation
story of its own — or `file` with a `path`:

```json
"access_log": { "sink": "file", "path": "/var/log/zoxy/access.log" }
```

The file is created if absent and opened append-only at startup, never
truncated, which is exactly what makes an external copy-truncate rotation
(logrotate) safe: every write lands at the current end, wherever the rotation
just put it.

Move-based rotation is served by `SIGHUP`, which reopens the configured path.
The new fd opens *first* — a reopen that cannot open its file keeps the old
one and counts `zoxy_access_log_reopen_failed`, because a failed rotation must
not destroy a working log — and the swap happens only between writes, never
under one, so every line accepted after the signal lands in the new file.
`zoxy_access_log_reopened` counts the rotations that took, and a successful
reopen also heals a sink that had broken: what broke was the fd the rotation
just replaced. On a `stdout` sink, or with no log configured at all, `SIGHUP`
is a no-op.

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
  occupancy and lowers it again only once it has drained back to 1/2 — the gap
  is what stops the flag flapping around a single threshold. While it is
  raised, idle timeouts are cut to a quarter, so quiet connections return
  their resources before the wall is reached.
- **Accept never pauses.** The kernel backlog stays drained even while
  shedding, so clients get an immediate signal rather than a timeout.
- **`SIGTERM` drains.** Listeners close, keep-alive stops being honored,
  in-flight work finishes under `drain_deadline_ms`, then the process exits 0.
- **The budget is printed, not hoped for.** Startup prints the closed-form
  memory, file-descriptor and ring-op totals it will never exceed, and
  asserts the fd count against `RLIMIT_NOFILE` before serving anything.

[DESIGN.md](DESIGN.md) §8 documents each rung and why it answers the way it
does.

## Further reading

- [DESIGN.md](DESIGN.md) — the settled design: what is shipped and how it
  works. The bare `§` references in this document, in the source and in commit
  messages all point here.
- [TIGER_STYLE.md](TIGER_STYLE.md) — the coding rules the tree is held to:
  static allocation only, bounded loops, assertion density, explicitly-sized
  integers.
- [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md) — measured findings,
  shelved experiments and open technical questions.
- [zoxy.io/config](https://zoxy.io/config/) — every field, bound and default,
  rendered from the JSON Schema of the latest release.
