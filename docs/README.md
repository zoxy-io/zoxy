# zoxy documentation

How to run, configure and operate zoxy: starting and replacing the process,
every block a config can carry, what the proxy exposes while it runs, and
what it does when a resource runs out.

The **authoritative** surface — every field, enum and numeric bound — is the
JSON Schema shipped as a release asset and emitted locally by `zig build
schema`. It is generated from the parser, so it cannot drift, and
[zoxy.io/config](https://zoxy.io/config/) renders the copy from the latest
release. What follows is the tour; the *reasoning* behind each behavior lives
in [DESIGN.md](DESIGN.md), which the bare `§` references point at.

## Running zoxy

### The command line

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

A config zoxy will not accept is refused before anything is bound: the
process prints `zoxy: invalid config '<path>': <reason>` and exits `1`. That
is what makes the replacement procedure below safe to run against a live
port.

### Signals

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

### A minimal config

One L4 listener forwarding to one origin:

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

### Replacing a running instance

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

[Tunnels](#tunnelled-upgrades-websocket) are the exception, and they have to
be: a WebSocket has no message boundary to finish at, so "wait for the last
connection" would mean waiting for a client that may never disconnect. A
draining process refuses new upgrades with `503` and cuts the live ones — at
`drain_deadline_ms` where you set one, and five seconds in where you did not.
Without that, one idle session would hold every rolling restart open until
your supervisor's `SIGKILL`. `zoxy_tunnels_drained` counts the ones cut.

The same two commands are how you *add* capacity rather than replace it —
start N processes on the same port and signal none of them. That is the
supported way to use more than one core, and a replacement is just the case
where the old instance leaves afterwards.

## Configuration

Config is parsed once at startup and never reloaded — a change is a process
restart, which is consistent with scaling out as independent processes.
Unknown fields are rejected rather than ignored.

The sections below follow a request: what a **listener** accepts (including
whether it terminates TLS) and which **cluster** it routes to, how that
cluster picks an endpoint and protects it,
who zoxy believes the client is, the edits and canned bodies applied at the
edge, and last the process-wide `timeouts` and `limits`. Two further
process-wide blocks, `admin` and `access_log`, are documented under
[Observability](#observability) beside what they emit.

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

#### Terminating TLS

Add a `tls` block and the listener speaks TLS 1.3 instead of plaintext.
Everything else about it is unchanged: the same routes, the same cluster,
the same filters.

```json
"listeners": [
    { "bind": "0.0.0.0:443", "protocol": "http", "cluster": "web",
      "tls": { "cert": "/etc/zoxy/site.crt", "key": "/etc/zoxy/site.key" } }
]
```

Both paths are read once at startup, so a missing or unusable file stops
the proxy with an error naming the file — never mid-handshake against a
real client. `cert` is a PEM chain, leaf first; `key` is the leaf's PEM
private key.

Either protocol may terminate. The handshake runs as a phase ahead of the
protocol, so routing, filters, redirects and access logs work exactly as
they do in the clear — an `http` listener parses its request out of
decrypted bytes and encrypts its response on the way back.

> [!NOTE]
> A cluster with `proxy_protocol.send` is refused from a terminating
> listener: that header stages into the relay buffer, which is not where a
> terminated connection's wire bytes come from. The combination is
> rejected at load rather than sent to your origin as garbage.

> [!IMPORTANT]
> The key must be **ECDSA P-256 or P-384**. Handshakes run on the event
> loop, where an RSA signature's millisecond would stall every other
> connection sharing it; an ECDSA one costs about 260 µs. An RSA key is
> refused at startup rather than accepted into a latency cliff.

This is termination only — inbound. The connection zoxy opens to your
backend stays plaintext, so the backend sees exactly what it saw before.

How many TLS sessions may be in flight at once is `limits.tls_engines`,
and it is the largest single line in the startup banner's memory budget;
see [Limits](#limits).

Session resumption is on, with nothing to configure. Every completed
handshake hands the client two session tickets; a client that offers one
back resumes instead of running a full handshake, which skips the
signature entirely. The tickets are stateless — each carries its own
session sealed under a key zoxy keeps in memory — so resumption costs no
per-session memory and no lookup table, and the startup banner's budget
does not move.

Two consequences worth knowing. A restart invalidates every outstanding
ticket, because the sealing keys are never written anywhere: returning
clients pay one full handshake each and then resume again. And tickets
are not shared between processes, so during a `SO_REUSEPORT` handoff a
client may land on the process that did not issue its ticket and do a
full handshake.

> [!NOTE]
> Resumption's other job is latency, and it is the larger one on
> handshake-heavy traffic. Without a post-handshake flight, a client that
> writes its `Finished` and then its request has the second write held by
> its own Nagle, waiting for an ACK zoxy has no reason to send — a ~45 ms
> stall per connection. The ticket flight is what carries that ACK.
>
> Measured: on a `Connection: close` workload — a fresh TLS handshake per
> request, the worst case — a terminated hop runs at a p50 of 158–161 µs
> against HAProxy's 429–607 µs. On steady keep-alive traffic the two are at
> parity, ~20k req/s at a p50 within a few µs of each other. Bulk
> transfer is the one band zoxy trails on, by a third to two-fifths:
> 507–542 µs against 383–385 µs at the same 100 MiB/s.

#### Tunnelled upgrades (WebSocket)

By default any request carrying `Upgrade` is answered `501` — the same as
`CONNECT`, and what every config that does not name an allowlist keeps
getting. An `http` listener opts in by naming the tokens it will carry:

```json
"listeners": [
    { "bind": "0.0.0.0:80", "protocol": "http", "cluster": "web",
      "upgrades": ["websocket"] }
],
"limits": { "tunnels": 512 }
```

zoxy does not speak WebSocket. It forwards the handshake, recognises the
origin's `101 Switching Protocols`, and from that point relays bytes both
ways until one side closes — the same byte relay an `l4` listener runs,
entered from an HTTP exchange. Routing, filters and health checks apply to
the handshake exactly as they do to any request.

> [!IMPORTANT]
> **After `101` the connection is opaque.** Filters, routes, header rules
> and canonicalisation stop applying to every byte that follows, because
> there are no more HTTP messages to apply them to. That is why the token
> list is an allowlist and not a switch: `websocket` is the only token
> zoxy accepts, and anything else — `h2c` in particular, which would carry
> HTTP/2 to an origin zoxy cannot parse — is refused by name at load.

**`limits.tunnels` is required, and has no default.** Every other pool
derives one, because their fallbacks can only be too generous; how many
long-lived sessions your origins should carry is a capacity decision zoxy
cannot infer from a connection count, so a listener that allows an upgrade
without one is refused at startup rather than shedding later. It may not
exceed `conn_slots`.

The pool is separate from the buffers ordinary traffic uses, and that is
the point. Every other pool is sized for concurrent *activity* — an idle
keep-alive connection holds no head buffer — while a tunnel pins its relay
buffer for its whole life and never returns it. Sharing one pool would let
idle WebSockets consume what live requests need; a separate one means
tunnels cannot starve HTTP, and costs 8200 bytes each, printed in the
startup banner.

When the pool is full the upgrade is refused with `503` **before** the
handshake reaches your origin, so a refusal costs no backend connection.
`zoxy_l7_shed_tunnels` counts those; `zoxy_tunnels_established` counts the
ones that became sessions.

Two further consequences worth knowing:

- **`timeouts.tunnel_ms` replaces the other deadlines** once a connection
  becomes a tunnel. It has to: `idle_ms` defaults to 60 s and a WebSocket
  is legitimately idle for hours, its keepalive being application-level
  ping/pong zoxy cannot see through opaque bytes. Default one hour, floor
  one second, ceiling one day — and unlike `request_ms` there is no `0`
  for "no cap", because a tunnel holds a pool slot for its whole life.
- **The upgraded upstream connection leaves the keep-alive pool** and is
  never reused for another client. It still counts against the cluster's
  `max_inflight` for as long as the tunnel lives, which is honest: your
  backend really is carrying it.

The access log writes one line when the tunnel closes — `kind` `http`,
`status` `101`, the request facts that opened it, and `bytes_in`/`bytes_out`
for the whole session. A line at the handshake would name a transfer that
had not happened yet.

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
| `p2c` *(default)* | two weight-biased candidates; the one carrying less in-flight work wins — HTTP requests and L4 connections both count |
| `rr` | smooth weighted rotation — exact rotation at equal weights, predictable spread, useful for cache warming |
| `hash` | the same key always reaches the same endpoint — object form only, naming what the cluster is sticky on |

`pick` is either a bare policy string or an object carrying the policy
and its settings. `hash` takes only the object form — you name its key
explicitly (`source_ip`, `header`, or `cookie`), because which identity
a cluster is sticky on is a decision, not a default.

Upstream connections are pooled process-wide and reusable by any request,
which is the single largest throughput lever in this design.

#### Weights

An endpoint is a bare `"IP:port"` string — weight 1 — or an object adding
a relative share, up to 256:

```json
"endpoints": ["10.0.0.1:8080", { "address": "10.0.0.2:8080", "weight": 3 }]
```

Every policy honors it: a 16-core box can take four times a 4-core box's
share, a canary can start at 1-in-20 and move by editing one number, and
a pool can be drained gradually by shifting weight instead of ejecting
hosts. A weight of `0` **drains** the endpoint — still health-checked,
never picked, not even when everything else is ejected — so taking a
backend out of rotation no longer needs a restart. At least one endpoint
must hold weight, or the config is rejected.

### Sticky sessions

`pick: {"policy": "hash", ...}` keeps clients on one backend, and its
`key` names what "one client" means:

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "pick": { "policy": "hash", "key": "source_ip" }
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
behind one address, and one heavy client cannot be split. That is what the
other two keys are for — and where even load matters more than stickiness,
prefer `p2c`.

The key is the *observed* client address, so behind another proxy or LB
every connection carries that machine's address and the whole cluster
hashes to one endpoint. See
[Learning it behind another proxy](#learning-it-behind-another-proxy-proxy-protocol)
for how an `l4` listener recovers the real client.

#### Sticky on a header

```json
"pick": { "policy": "hash", "key": "header", "name": "x-tenant" }
```

Hashes the named header's value: stickiness on an identity the client
*states* — a tenant, a user id, an API key — which survives NAT. A
request without the header is placed by load like a `p2c` pick. Only
`http` listeners can route to a header- or cookie-keyed cluster; an
`l4` listener never parses a request to read one from.

#### Sticky on a cookie

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "pick": { "policy": "hash", "key": "cookie", "name": "srv_id" }
}
```

The named cookie carries the assignment itself: a 16-hex **endpoint
tag** zoxy mints from the endpoint's address, stable across restarts,
processes, and config reordering. A request with no cookie is placed on
the calmest backend and the response sets one
(`Set-Cookie: srv_id=<tag>; Path=/; HttpOnly` — no expiry, a session
cookie — plus `; Secure` when the listener terminates TLS, since that is
the case where zoxy knows the client-facing scheme is https); a request whose tag names a healthy, under-capacity backend
goes there and is **not** re-stamped; a tag naming an ejected, drained
or removed backend is re-placed and the response re-announces. This is
the strongest answer to NAT: every user behind one address carries
their own assignment.

Pick a cookie name your application does not use — zoxy adds its
Set-Cookie beside the origin's, never in place of them. The tag is not
signed: a forged cookie can only choose which of *your* backends serves
that client, never one outside the eligible set.

Three counters watch it: `zoxy_l7_sticky_followed`, `..._assigned`, and
`..._repicked` partition a cookie cluster's responses. A rising repick
rate means backends are flapping under a sticky population.

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

### Who the client is

One address is consumed everywhere it matters — the `source_ip` hash pick,
a filter's `client` match, the access log — and three blocks decide what it
is and who hears it. They sit at different scopes (a listener learns and
states it, a cluster states it to its origins) and are grouped here because
a deployment that needs one usually needs another: learn the address first,
then pass it on in whichever form the origin can read.

#### Learning it behind another proxy (PROXY protocol)

Put a load balancer in front of zoxy and *zoxy* sees only the balancer.
That breaks more than logging — a `source_ip`-keyed hash pick reads the
client address, so behind an LB every connection hashes alike and the
whole fleet lands on one endpoint. An `l4` listener can instead require
each connection to open with a PROXY protocol header (v1 or v2 — what
AWS NLB, GCP and HAProxy emit) announcing the real client:

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

#### Telling an HTTP origin (X-Forwarded-For)

The mirror problem: without this, everything *behind* zoxy sees zoxy —
origin logs, IP allowlists, per-client rate limits. An `http` listener can
add `X-Forwarded-For`:

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

#### Telling an L4 origin (PROXY protocol)

The send direction: an origin behind an `l4` relay has no header to read
an address from — the relay is the whole point — so the only way to tell
it who connected is to open the upstream connection with a PROXY
protocol header. A *cluster* opts in, because this states what its
origins expect, not who connects (the same unit as HAProxy's
`send-proxy`):

```json
"clusters": {
    "postgres": {
        "endpoints": ["10.0.0.1:5432"],
        "proxy_protocol": { "send": "v2" }
    }
}
```

`send` is `v1` (text, readable in a tcpdump) or `v2` (binary, what cloud
load balancers speak). The header names the client zoxy believes — which
behind a `require` listener is the client the *fronting* proxy
announced, so a chain of proxies carries one identity end to end.

Two consequences of the header being per *connection*:

- Only `l4` listeners may route to a sending cluster. A pooled HTTP
  upstream is shared across clients, and a header naming one client
  would lie to every other — the loader rejects the pairing outright.
  For HTTP origins, use [`forwarded`](#telling-an-http-origin-x-forwarded-for)
  instead.
- Health probes do not send the header. The dial-only `tcp` check is
  unaffected (it proves the port accepts and sends nothing), but an
  `http` check against a sending cluster probes bare — if the origin
  strictly requires the header, prefer `tcp` checks there.

`zoxy_l4_proxy_header_sent` counts headers staged, one per dialed
connection to a sending cluster.

### Filters

An `http` listener can carry `request_filters` — a list of rules evaluated
top-down against each request. Each has a match predicate — absent fields
match anything — and actions applied in order. As with routes, nothing caps
the list but the file you write.

```json
"request_filters": [
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

Match on `method`, `host`, `path_prefix`, header predicates
(`present` / `equals` / `contains`), and `client` — CIDR ranges the
connection's address must fall inside. Actions are `reject` with a status,
`redirect`, `respond` (answer from a configured body),
`header_set` / `header_add` / `header_remove`, and `rewrite_prefix`.

Rules compile into immutable tables at load time and are interpreted with
bounded loops — no plugins, no scripting, nothing that can allocate or run
unbounded. A rewrite changes only what is *forwarded*: routing already chose
the cluster from the original path, so a rewrite never re-routes.

#### Matching the client address

The standard rule — `/admin` from the office range and nowhere else — is a
`client` list on the allow rule and a reject beneath it:

```json
"request_filters": [
    { "match": { "path_prefix": "/admin",
                 "client": ["10.0.0.0/8", "192.168.1.0/24"] },
      "actions": [{ "header_set": { "name": "X-Internal", "value": "1" } }] },
    { "match": { "path_prefix": "/admin" }, "actions": [{ "reject": 403 }] }
]
```

The address matched is the one zoxy actually believes: the TCP peer, or the
[PROXY-protocol-announced client](#learning-it-behind-another-proxy-proxy-protocol)
on a listener that requires the header — never an `X-Forwarded-For` chain,
which any client can write. Prefixes run to `/32` for IPv4 and `/64` for
IPv6 (a client's IPv6 identity is its /64, the same rule sticky hashing
uses), the `/len` is mandatory, and host bits past the prefix are rejected
— `10.0.0.1/8` is a typo for one of two different ranges, and zoxy will not
guess which.

#### Redirects

The two most common edge rules are one action each — no second server
needed in front of a load balancer to answer them:

```json
"request_filters": [
    { "actions": [{ "redirect": { "status": 301, "scheme": "https" } }] },
    { "match": { "host": "www.example.com" },
      "actions": [{ "redirect": { "status": 308, "scheme": "https",
                                  "host": "example.com" } }] }
]
```

A composed target replaces the scheme (required — zoxy never guesses it,
since behind a TLS terminator every hop it sees is plaintext) and
optionally the host; the request's own path and query are carried through.
A fixed `location` is the other form, sent verbatim. Statuses are `301`,
`302`, `307`, `308`. Redirects count as `zoxy_l7_redirected` and log as
`redirected` — separate from rejects on purpose, so refused traffic and
relocated traffic never blur.

#### Response filters

`response_filters` edits the origin's response on the way out — the
routine edge work an origin you do not control cannot do for you: add
`Strict-Transport-Security`, strip `Server`, advertise a retry on 5xx.

```json
"response_filters": [
    { "actions": [
        { "header_remove": "Server" },
        { "header_set": { "name": "Strict-Transport-Security",
                          "value": "max-age=63072000" } }
    ] },
    { "match": { "status_class": "5xx" },
      "actions": [{ "header_set": { "name": "Retry-After", "value": "1" } }] }
]
```

A response rule matches on `status` (exact codes), `status_class`
(`"1xx"` through `"5xx"`), and response-header predicates — the same
`present` / `equals` / `contains` vocabulary. Its actions are the three
header verbs only: `reject` and `rewrite_prefix` are request-side ideas,
and the loader says so by name if you reach for them here.

The same guardrails hold in both directions: filters may not touch the
headers zoxy owns (`Content-Length`, `Transfer-Encoding`, `Connection`
and the hop-by-hop set, `X-Forwarded-For`), and a response head that no
longer fits after edits is answered `502` — an origin response the proxy
cannot re-render is not the client's fault. Responses zoxy generates
itself (`404`, `503`, filter rejects, a `respond` action's body) are not
origin responses and carry no edits.

### Response bodies

Every status zoxy sends itself is empty by default. `bodies` names
content once — from a file read at startup, or inline for one-liners —
and anything that serves content references it by name:

```json
"bodies": {
    "maintenance": { "file": "/etc/zoxy/503.html", "content_type": "text/html; charset=utf-8" },
    "not-found":   { "file": "/etc/zoxy/404.html", "content_type": "text/html; charset=utf-8" },
    "robots":      { "inline": "User-agent: *\nDisallow: /private\n",
                     "content_type": "text/plain" }
},
"error_pages": { "404": "not-found", "503": "maintenance" }
```

Each name is read once and rendered once, however many places serve it —
so the same maintenance page on `error_pages` and three filter rules is
one buffer, and a name that does not exist is a startup error rather
than a silently blank page. `content_type` is required: nothing is
guessed from a filename. Files are read at startup like the rest of the
config, so **changing one needs a restart**.

`error_pages` accepts only the statuses zoxy actually sends — `400`,
`403`, `404`, `414`, `429`, `431`, `501`, `502`, `503`, `504` — and a
page for anything else is refused at load.

Bodies live in memory, and that is the point rather than a shortcut: a
`503` is raised *because* something ran out, so an error page whose
delivery needed a resource would fail exactly when it is needed. The
cost is bounded and visible — capped per body, counted in the startup
banner, and paid once per worker process.

**Listing a status is the opt-in, including for sheds.** Leave `503`
out and overload behaves exactly as it does today; put it in and you
have said you want the bytes. There is no second switch, because
writing the page down is the decision.

#### Serving a body directly

```json
"request_filters": [
    { "match": { "path_prefix": "/robots.txt" },
      "actions": [{ "respond": { "status": 200, "body": "robots" } }] },
    { "match": { "host": "old.example.com" },
      "actions": [{ "respond": { "status": 503, "body": "maintenance" } }] }
]
```

`respond` answers from a body instead of forwarding — a `robots.txt`, a
maintenance window, a health target the balancer serves itself. It stops
the request like `reject` and `redirect` do, but counts as
`zoxy_l7_responded` and logs as `responded`: refusing traffic and serving
it are different facts, and neither should have to be subtracted from
the other. Statuses are `200` plus the error set.

### Timeouts

```json
"timeouts": {
    "connect_ms": 5000,
    "head_ms": 10000,
    "idle_ms": 60000,
    "drain_deadline_ms": 10000,
    "max_lifetime_ms": 0,
    "request_ms": 0,
    "tunnel_ms": 3600000,
    "health_interval_ms": 2000
}
```

The whole block is optional, and so is every field in it — the values
above are the defaults, written out. An explicit `0` disables the three
caps; for `connect_ms` and `idle_ms` it is rejected, since a zero-length
dial or idle budget is a mistake rather than a policy.

> [!WARNING]
> `connect_ms` must be **strictly below** `head_ms`, which must be at or
> below `idle_ms`, or the config is rejected at load. A connection's first deadline is the dial budget and the
> dial's completion re-stores it to the idle one, but zoxy's single timer per
> connection never moves earlier once armed — so an idle budget that does not
> exceed the dial budget would not take effect at the handoff and would reap
> late instead. This bites when only *one* field is tuned: raising
> `connect_ms` past the default 60 s `idle_ms` is rejected just the same.
> The same reasoning is why `head_ms` sits between them rather than
> beside them: it is re-based *down* from the idle deadline when the
> client's first byte lands, and *down* again to `connect_ms` at the
> dial.

| field | default | meaning |
|---|---|---|
| `connect_ms` | `5000` | per-try upstream connect budget |
| `head_ms` | derived | budget for reading one request head — what a slowloris meets. 10 s, clamped between `connect_ms` and `idle_ms` so it never changes a config that predates it |
| `idle_ms` | `60000` | how long a connection may stay quiet — between requests, or before its first byte |
| `drain_deadline_ms` | `0` | how long a `SIGTERM` drain waits before reaping stragglers; `0` waits for the last connection |
| `max_lifetime_ms` | `0` | absolute connection-age cap regardless of activity; `0` disables |
| `request_ms` | `0` | cap on one L7 exchange, **not** refreshed by activity — bounds a request that is merely slow, where `idle_ms` only bounds one that has stalled; `0` disables |
| `tunnel_ms` | `3600000` | whole life of a [tunnelled upgrade](#tunnelled-upgrades-websocket), replacing the three above once one is established; 1 s to 1 day, and `0` is **not** legal |
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
    "head_buffer_bytes": 16384,
    "tunnels": 512
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

`tls_engines` bounds *TLS sessions in flight* — handshaking or terminated —
and is zero unless some listener has a `tls` block. It is the knob that
decides what a TLS deployment costs: an engine is by far the largest
per-connection object zoxy holds, about 132 KiB plus a 32 KiB plaintext
buffer, so 1024 of them is roughly 170 MiB. It defaults to your connection
slots capped at 1024, and the startup banner prints the total either way —
lower it if that is more concurrent TLS than you serve.

`tunnels` bounds concurrent [tunnelled upgrades](#tunnelled-upgrades-websocket)
and is zero unless some listener names an `upgrades` allowlist — in which case
it is **required**, since no default can be derived for it. Each costs one
relay-buffer pair (8200 bytes), held for the tunnel's whole life rather than
for the duration of a request, which is why they are reserved apart from
`relay_buffers` instead of drawn from it.

`cq_fill_eighths` trades connection ceiling for `io_uring` completion-queue
burst headroom; `access_log_buffer_bytes` sizes the access log's staging
buffers. What zoxy does when one of these pools runs out is
[Under load](#under-load).

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

The scrape also says **which backend**, per cluster and endpoint:

```text
zoxy_endpoint_responses{cluster="api",endpoint="10.0.0.1:8080"} 4182
zoxy_endpoint_connect_failed{cluster="api",endpoint="10.0.0.2:8080"} 17
zoxy_endpoint_health_down{cluster="api",endpoint="10.0.0.2:8080"} 2
zoxy_endpoint_healthy{cluster="api",endpoint="10.0.0.2:8080"} 0
```

Dial failures, responses served and the health transitions
(`endpoint_health_down`/`_up`) carry both labels; the "every endpoint
was full" sheds carry only `cluster` (no single endpoint was full — all
of them were). Two gauges read live state: `zoxy_endpoint_inflight` is
the level the balancer compares, and `zoxy_endpoint_healthy` is the
prober's current verdict, rendered for health-checked clusters only.
Each labeled family sums to the bare process total it breaks down — an
identity the simulator asserts on every seed and the smoke gate
re-derives from a live scrape. Label cardinality is bounded by your
config — endpoints and cluster names, never request data — and the
startup banner prices what the labels and their render buffers cost.

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
`aborted`, or `closed` — the last for L4 connections and for
[tunnels](#tunnelled-upgrades-websocket), which end the way a relay ends
rather than the way an exchange does.

Logging never blocks the event loop, so a sink that stalls costs dropped
lines rather than latency; `zoxy_access_log_dropped` counts them exactly.

#### Joining this log to your origin's

By default a zoxy line and your backend's line for the same request share
no key, so a slow request cannot be attributed to a hop. Naming headers
fixes that without changing a byte on the wire:

```json
"access_log": {
    "sink": "stdout",
    "request_headers": ["X-Request-ID", "User-Agent"],
    "response_headers": ["X-Cache"]
}
```

```json
{"...":"...","status":200,"upstream_reused":true,"upstream_replayed":false,"request_headers":{"x-request-id":"7f3c…","user-agent":"curl/8.6.0"},"response_headers":{"x-cache":"HIT"},"duration_us":1873}
```

zoxy does not mint an identifier. It usually is not your outermost hop —
a CDN, cloud LB or ingress in front almost always sets `X-Request-ID` or
`traceparent`, and that header reaches your origin untouched — so logging
it at both ends is the whole join. The same mechanism is why the feature
is not trace-specific: `User-Agent` for traffic analysis, a tenant header
for multi-tenant routing, the origin's `X-Cache` on the way out.

Names are matched case-insensitively and logged lowercased, so a query
does not have to guess the spelling. A header that did not arrive is
omitted rather than logged as null. A repeated header logs its first
value — the one zoxy itself read. Values are truncated at 256 bytes with
a trailing `...`, and up to 8 headers may be named across both lists;
`response_headers` is ignored for L4 lines, which have no response to
read. Absent lists leave the line exactly as it was.

The values are held per connection for the life of a request, so naming
headers costs memory proportional to `conn_slots` — the startup banner
prints it beside everything else. Naming a lot of headers on a large
`conn_slots` is real memory, and a wider line also needs a staging
buffer that can hold one: zoxy refuses to start rather than dropping
every line that carries them.

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
- **A tunnel is refused before it costs anything.** No tunnel slot → the
  upgrade is answered `503` *before* the handshake is forwarded, so a
  refusal never spends an origin connection to produce a worse answer once
  the session is already live.
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
