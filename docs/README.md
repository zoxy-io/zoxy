# zoxy documentation

How to run, configure and operate zoxy: starting and replacing the process,
every block a config can carry, what the proxy exposes while it runs, and
what it does when a resource runs out.

The JSON Schema is the authoritative list of fields, enums and numeric
bounds. It is generated from the parser, shipped as a release asset and
emitted locally by `zig build schema`.
[zoxy.io/config](https://zoxy.io/config/) renders it for the latest release.
This document is the tour. [DESIGN.md](DESIGN.md) explains the reasoning
behind each behaviour; a bare `§` reference points there.

## Running zoxy

### The command line

The binary takes one argument, the path to a JSON config:

```sh
zoxy config.json           # start the proxy
zoxy --check config.json   # validate and price it, bind nothing (-c)
zoxy --help                # usage summary (-h)
zoxy --version             # print the version (-V)
```

A release build prints its bare version, `zoxy 0.8.2`. A build from source
after a release adds a suffix that identifies it,
`zoxy 0.8.2 (v0.8.2-5-gabc1234)`, plus `-dirty` if the tree had uncommitted
changes, so the version in a bug report names the exact build. Packagers
can name a build with `zig build -Dbuild-id=…`. The startup banner opens
with the same line.

zoxy refuses an invalid config before binding anything: it prints
`zoxy: invalid config '<path>': <reason>` and exits `1`. A valid config
whose fd budget exceeds this machine's `RLIMIT_NOFILE` hard limit is
refused the same way, but after the startup banner, so the numbers behind
the refusal are on screen next to the reason.

### Checking a config without running it

`--check` does everything a start does up to the banner: it loads the
config, opens every file it names, prices the pools and measures the fd
demand against `RLIMIT_NOFILE`. Then it exits without binding a port:

```console
$ zoxy --check config.json
zoxy 0.8.2
budgets (DESIGN.md §5/§8; closed-form except where marked):
  memory  total 47297 KiB = conn slots 1386 x 512 B + stream slots 1386 x 1552 B
          + relay buffers 1386 x 32808 B
          + upstream slots 1311 x 48 B + head buffers 0 x 8192 B (+ ring 0 B)
          + upstream head buffers 0 x 8216 B + head scratch 8192 B
          + access log 0 KiB (+ logged headers 0 B)
          + endpoint tables 29 B (1 cluster(s) x 1 wide)
          + labeled metrics 26450 B (tables, labels and render buffers)
          + tunnels 0 x 0 B (their own relay buffers, never HTTP's)
          + tls engines 0 x 0 B (+ plaintext 0 B each, libcrypto heap 0 KiB)
          + config arena 2 KiB (measured, not closed-form)
  fds     4093 required (asserted against RLIMIT_NOFILE)
  ring    4096 entries, completion queue 8192, in-flight ops <= 6869
  config  1 listener(s), 1 cluster(s), 0 error page(s), access log off
  rlimit  RLIMIT_NOFILE 1024 soft, 524288 hard (a start raises the soft limit to the fd budget)
  check   config.json: valid, and this box can start it
```

The report shows what the config will cost as well as whether it parses,
so you can run it from CI, a config-management dry run or a pre-deploy
hook. The report goes to stdout; the reason for a refusal goes to stderr,
as at startup.

| exit | meaning |
|---|---|
| `0` | the config loads and this machine can start it |
| `1` | the config is wrong: unreadable, unparseable, semantically refused, or names a file that will not load |
| `2` | the config is valid but *this machine* cannot fit it: the fd budget exceeds the `RLIMIT_NOFILE` hard limit |

CI can branch on the split: a build agent with a stock `RLIMIT_NOFILE` may
accept `2` for a config sized for production, but must never accept `1`.

`--check` does the full load, so it needs the same file permissions the
proxy would: a config naming production certificates cannot be checked on
an agent that does not hold them. It also creates an `access_log` `file`
sink if it is absent, as a start does.

### Signals

The startup banner and the exit tally go to stderr. stdout belongs to the
access log, whose `stdout` sink writes one JSON line per event. `--check`
never serves, so its report can use stdout.

| signal | effect |
|---|---|
| `SIGTERM`, `SIGINT` | drain in-flight connections, then exit 0 |
| `SIGHUP` | reopen the access log's `file` sink for rotation; nothing else |
| `SIGUSR1` | ignored |

A completed drain prints the counters once on its way out. A stuck drain
prints them too, with a diagnostic naming the plane that never finished.
Counters reach stderr only in these two cases: Prometheus exposition is a
snapshot, and two snapshots on one stream would not parse. Live counters
come from [`/metrics`](#metrics).

`SIGUSR1` is ignored explicitly because its default disposition terminates
the process.

### A minimal config

One L4 listener forwarding to one origin:

```json title="config.json"
{
    "listeners": [
        { "bind": "127.0.0.1:8080", "l4": { "cluster": "origin" } }
    ],
    "clusters": {
        "origin": { "endpoints": ["127.0.0.1:9000"] }
    }
}
```

Every other block (`timeouts`, `limits`, `access_log`) has defaults.
[`config/example.json`](../config/example.json) is the same listener with
health checks and the access log turned on.

### Replacing a running instance

There is no reload. The pools, the ring and every table are sized from the
config at startup and never grow, so nothing re-reads the file. `SIGHUP`
only rotates the log, and hot restart is a non-goal
([DESIGN.md](DESIGN.md) §1).

Instead, every listener is bound with `SO_REUSEPORT`, so a second process
can hold the same port as the first. Replacing a config takes two commands,
in this order:

<!-- figure: reuseport-handoff -->

```sh
zoxy --check new-config.json || exit 1   # refuse to proceed on a bad config
zoxy new-config.json &   # the replacement binds the same port and starts serving
kill -TERM "$old_pid"    # the old process drains its work, then exits 0
```

Start the replacement first. A refused config never reaches a listener:
the new process exits `1` with its reason, and the old one, never
signalled, keeps serving. Signalling first would leave the port unserved
for as long as the replacement took to fail. The `--check` line is
optional; it stops a bad config before it reaches the `&`.

Between the two commands both configs are live. The kernel picks a
listener for each connection by hashing the 4-tuple, so during the overlap
both processes answer. That is fine for tuning a timeout, adding an
endpoint or moving a cluster. If a change must take effect at a known
instant, such as withdrawing a route, stop the old process before starting
the new one and accept the gap.

> [!WARNING]
> The handoff is not lossless by default. When the old process closes its
> listener, connections it had accepted but not yet served are reset.
> Linux 5.14 added `net.ipv4.tcp_migrate_req` (off by default) to migrate
> them to another socket in the group; turn it on where the handoff must
> be clean. Because accept never pauses (§8), zoxy keeps the backlog
> drained, which narrows the window but cannot close it.

Both processes must run as the same effective user. The kernel will not
add a socket to a `SO_REUSEPORT` group bound by a different UID.

`timeouts.drain_deadline_ms` bounds how long the old process lingers; the
default `0` waits for its last connection to finish. Its exit prints the
final counters.

[Tunnels](#tunnelled-upgrades-websocket) are the exception. A WebSocket has
no message boundary to finish at, so a draining process refuses new
upgrades with `503` and cuts live ones at `drain_deadline_ms`, or after
five seconds if none is set. `zoxy_tunnels_drained` counts the ones cut.

The same two commands add capacity: start N processes on the same port and
signal none of them. That is the supported way to use more than one core.

## Configuration

Config is parsed once at startup and never reloaded; a change needs a
process restart. Unknown fields are rejected.

The sections below follow a request: what a **listener** accepts,
including whether it terminates TLS; which **cluster** it routes to; how
that cluster picks and protects an endpoint; who zoxy believes the client
is; the edits and canned bodies applied at the edge; and finally the
process-wide `timeouts` and `limits`. The other two process-wide blocks,
`admin` and `access_log`, are under [Observability](#observability).

### Listeners

A listener binds an address and speaks one protocol, named by the key its
settings live under. `l4` relays bytes without inspecting them. `http` runs
the HTTP reverse proxy over HTTP/1.1 and, where the listener allows it,
[HTTP/2](#http2). Exactly one of the two is required; there is no default.

`bind` and `tls` sit outside the protocol body because they apply to both.
Everything else lives inside it, so a setting for one protocol cannot be
written for the other: `max_body_bytes` on an `l4` listener is rejected,
not silently ignored.

```json
"listeners": [
    { "bind": "0.0.0.0:80",   "http": { "cluster": "web" } },
    { "bind": "0.0.0.0:5432", "l4":   { "cluster": "postgres" } }
]
```

There is no compiled ceiling on listener count. The config's own ring and
fd budgets bound it; both are checked at startup and printed in the
banner.

Each listener is bound with `SO_REUSEPORT`, so running several processes on
one port is the supported way to use more than one core and to
[replace a running instance](#replacing-a-running-instance). Every
connection, accepted or upstream, gets `TCP_NODELAY`: Nagle plus delayed
ACK would cost a reused keep-alive connection a 40 ms stall.

#### Routing an `l4` listener by TLS name (SNI)

One `:443` listener can front several TLS services without terminating any
of them. Give the `l4` body a route table keyed on server name. zoxy reads
the name from the ClientHello and relays every byte onward unchanged:

```json
{
    "bind": "0.0.0.0:443",
    "l4": {
        "routes": [
            { "sni": "api.example.com", "cluster": "api" },
            { "sni": "grpc.example.com", "cluster": "grpc" },
            { "cluster": "fallback" }
        ]
    }
}
```

zoxy holds no key material and runs no handshake. The backend completes
the TLS session with the client as if no proxy were in the path, and zoxy
never sees plaintext. Use this to front a service whose certificate the
proxy must not be able to present.

A route with no `sni` is the catch-all. It takes any connection, including
one whose hello names nothing (an IP-only client, an older stack). Without
a catch-all, a connection naming a server the table does not cover is
closed.

Matching is exact: `api.example.com` matches that name and not
`x.api.example.com`. `http` routes match a `host` by the same rule.
Neither table has wildcards, and `*` is refused at load in any host or
server name (`RouteHostWildcard`). The character is reserved, so a
wildcard rule can be added later without changing what an existing
config means.

Two combinations are refused at load:

| config | why |
|---|---|
| `routes` beside this listener's own `tls` | terminating TLS consumes the hello that SNI routing reads |
| `limits.relay_buffer_bytes` below 16 KiB | the hello is staged in the relay buffer, and one with post-quantum key shares runs past 2 KiB; a smaller buffer would route short hellos and drop long ones |

Four counters report what the table did: `zoxy_l4_sni_routed`,
`zoxy_l4_sni_absent` (the client named nothing), `zoxy_l4_sni_no_route`
(it named something no route claims) and `zoxy_l4_sni_invalid` (the
opening bytes were not a ClientHello: a plaintext client, or a handshake
this proxy could not read).

The hello must arrive in one TLS record. Every client sends it that way. A
fragmented first flight is legal but does not occur in practice, and
reassembling one would mean buffering inside a parser that reads
attacker-controlled bytes. Such a connection is counted in
`zoxy_l4_sni_invalid` and closed.

#### Terminating TLS

Add a `tls` block and the listener speaks TLS 1.3 instead of plaintext. Its
routes, cluster and filters are unchanged.

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": { "cluster": "web" },
      "tls": { "cert": "/etc/zoxy/site.crt", "key": "/etc/zoxy/site.key" } }
]
```

Both files are read once at startup. A missing or unusable file stops
startup with an error naming it, so the problem never surfaces
mid-handshake. `cert` is a PEM chain, leaf first; `key` is the leaf's PEM
private key.

Either protocol can terminate TLS. The handshake runs as a phase before the
protocol, so routing, filters, redirects and access logs work as they do
in the clear.

The key must be **ECDSA P-256 or P-384**; an RSA key is refused at
startup. Handshakes run on the event loop, where the millisecond an RSA
signature takes would stall every other connection on that loop. An ECDSA
signature costs about 260 µs.

`alpn` lists the application protocols the listener offers in ALPN
(RFC 7301), most preferred first: `http/1.1`, and `h2` for
[HTTP/2](#http2). Without it, an `http` listener offers only `http/1.1`:

```json
"tls": { "cert": "/etc/zoxy/site.crt", "key": "/etc/zoxy/site.key", "alpn": ["h2", "http/1.1"] }
```

If a client offers ALPN but names nothing the listener speaks (say, a gRPC
client offering only `h2` to a listener that offers only `http/1.1`), the
handshake fails with the `no_application_protocol` alert and
`zoxy_tls_alpn_refused` counts it. The client is never handed an HTTP/1.1
session it would then speak HTTP/2 into. A client that offers no ALPN is
unaffected. Unknown names, an empty list and a repeated name are refused
at load. An `l4` listener never parses the bytes it relays, so it offers
nothing and refuses the `alpn` key.

A terminating listener cannot route to a cluster with
`proxy_protocol.send`. That header is staged in the relay buffer, which a
terminated connection's wire bytes do not pass through, so the loader
rejects the combination instead of sending the origin garbage.

Termination is inbound only. Whether the connection zoxy opens to the
backend speaks TLS is the cluster's to say: see [HTTPS origins](#https-origins)
and [HTTP/2 to the origin](#http2-to-the-origin-and-grpc).

`limits.tls_engines` bounds how many TLS sessions may be in flight at once.
It is the largest single line in the startup banner's memory budget; see
[Limits](#limits).

Session resumption is on and has no settings. Every completed handshake
gives the client two session tickets, and a client that presents one later
resumes without a signature. Tickets are stateless, each sealed under a key
zoxy keeps in memory, so resumption costs no per-session memory and the
banner's budget does not change. A restart invalidates every outstanding
ticket, because the sealing keys are never written anywhere; each returning
client pays one full handshake, then resumes again. Tickets are not shared
between processes either, so during a `SO_REUSEPORT` handoff a client may
land on the process that did not issue its ticket and do a full handshake.

The ticket flight also carries the ACK for the client's `Finished`. Without
it, a client that writes `Finished` and then its request would have the
request held by its own Nagle for about 45 ms.

On a `Connection: close` workload, with a fresh handshake per request, a
terminated hop measures a p50 of 158–161 µs against HAProxy's 429–607 µs.
On steady keep-alive traffic the two are at parity: about 20k req/s, with
p50s within a few µs of each other. zoxy trails only on bulk transfer, by a
third to two-fifths: 507–542 µs against 383–385 µs at the same 100 MiB/s.

#### Requiring a client certificate (mutual TLS)

A terminating listener can ask every client for a certificate and verify
it against a CA bundle:

```json
{
    "bind": "0.0.0.0:443",
    "tls": {
        "cert": "/etc/zoxy/cert.pem",
        "key": "/etc/zoxy/key.pem",
        "client_ca": { "path": "/etc/zoxy/clients-ca.pem" }
    },
    "http": { "cluster": "api" }
}
```

The bundle is read and parsed at load, so a missing or empty one stops
startup with an error naming it. A client's chain must reach one of its
CAs, be valid now, and start with an end-entity certificate: a CA
certificate presented as a client is refused.

`verify` is `"required"` by default. A client that presents no
certificate is refused with the `certificate_required` alert. Set
`"verify": "optional"` to let such clients in unauthenticated while a
fleet migrates onto mutual TLS; a certificate that *is* presented must
still verify. Every refusal is counted in `zoxy_tls_client_cert_refused`,
apart from `zoxy_tls_handshake_failed`, because only issuing or trusting
certificates fixes it.

Two things are deliberately not checked. Revocation (CRLs, OCSP) is
unbounded work for a proxy that allocates nothing after startup, so issue
short-lived client certificates instead. Extended key usage is not read,
so use a CA that issues nothing but client certificates.

A verified client's identity is its certificate's SHA-256 fingerprint, the
value `openssl x509 -noout -fingerprint -sha256` prints, in lowercase hex
without colons. The origin receives it on every request as
`X-Client-Cert-SHA256`, and the access log as `client_cert_sha256`. A
client never gets to write that header: an inbound
`X-Client-Cert-SHA256` is stripped on **every** HTTP listener, mutual TLS
or not, since an origin reached through a mutual-TLS listener may be
reachable through a plaintext one too. Filters may not set or remove it.
The header rides each request rather than the pooled origin connection,
so connection reuse across clients stays sound.

#### HTTP/2

An `http` listener speaks HTTP/2 to clients in two ways. Over TLS, it
offers `h2` in `tls.alpn`. In the clear, `"h2c": true` makes it answer a
client that opens with the HTTP/2 preface (prior knowledge, RFC 9113 §3.3)
and serve HTTP/1.1 as before to one that does not; `h2c` is refused beside
`tls`. Each stream is one request and goes through the same routing,
filters, redirects and access log as an HTTP/1.1 request. The origin leg
is HTTP/1.1 unless the cluster [speaks HTTP/2](#http2-to-the-origin-and-grpc),
and a body with no length is sent to an HTTP/1.1 origin chunked.

```json
"listeners": [
    { "bind": "0.0.0.0:443", "http": { "cluster": "web" },
      "tls": { "cert": "/etc/zoxy/site.crt", "key": "/etc/zoxy/site.key",
               "alpn": ["h2", "http/1.1"] } },
    { "bind": "10.0.0.1:8080", "http": { "cluster": "web", "h2c": true } }
],
"limits": { "h2_streams": 4096 }
```

`limits.h2_streams` is required and has no default. It bounds the
requests in flight across all HTTP/2 connections, each holding its own head
buffer, and how many to carry is a capacity decision. A stream beyond the
pool is refused with `REFUSED_STREAM`, which a client retries, and counted
in `zoxy_h2_shed_streams`. One connection advertises at most 100 streams.

`limits.h2_connections` bounds how many connections speak HTTP/2 at once,
each holding a session of about 100 KiB. It defaults to 1024, at most
`conn_slots`. When none is free:

- a listener offering `h2` beside `http/1.1` offers only `http/1.1` in the
  handshake;
- an h2c preface is closed and counted in `zoxy_h2_shed_sessions`;
- a listener offering only `h2` sheds the connection at accept, before its
  handshake, and counts it in `zoxy_shed_h2_sessions`.

Both keys are refused unless a listener speaks HTTP/2.

A request body reaches its upstream through the stream's relay buffer
(`limits.relay_buffer_bytes`). A DATA frame that does not fit is held until
the stream's own send makes room. Meanwhile the connection reads nothing
else, so its other streams wait. `zoxy_h2_frames_held` counts each held
frame once. A client that sends before applying the server's window can
cause this. So can a full 16 KiB frame of a body without a
`content-length`, which overruns the default buffer by the octets its chunk
framing adds: 38 for the first frame, up to 58 behind one still in flight.

A failure on a stream ends that stream (with a reset, or a `502` or `504`
answer), never the connection. What a client can spend is bounded per
connection. Two kinds of abuse end the connection with
`GOAWAY(ENHANCE_YOUR_CALM)`, each counted in its own `zoxy_h2_calm_*`:

- resetting streams before their answers end, faster than answers end
  (Rapid Reset);
- floods of frames that ask for nothing: PING, SETTINGS, WINDOW_UPDATE,
  PRIORITY or unknown types, empty DATA, or a field block in empty
  CONTINUATIONs.

An origin's response trailers reach an HTTP/2 client as the stream's
trailing HEADERS, whether they came as a chunked body's trailer section or
as an HTTP/2 origin's trailing HEADERS. A client's request trailers go no
further.

#### Tunnelled upgrades (WebSocket)

By default any request carrying `Upgrade` is answered `501`, the same as
`CONNECT`. An `http` listener opts in by naming what it will carry:

```json
"listeners": [
    { "bind": "0.0.0.0:80", "http": { "cluster": "web",
      "upgrades": { "websocket": true } } }
],
"limits": { "tunnels": 512 }
```

The block has one flag per protocol, so the vocabulary lives in the schema
and an editor rejects `"h2c"` before the loader does. Omitting the block,
writing `{}` and setting every flag `false` all mean the same thing: allow
none, reserve nothing.

zoxy does not speak WebSocket. It forwards the handshake, recognises the
origin's `101 Switching Protocols`, and from then on relays bytes both ways
until one side closes, using the same byte relay as an `l4` listener.
Routing, filters and health checks apply to the handshake as they do to
any request.

After `101` the connection is opaque. Filters, routes, header rules and
canonicalisation stop applying, because no more HTTP messages follow. So
the block is an allowlist: `websocket` is the only token zoxy accepts.
`h2c`, which would carry HTTP/2 to an origin zoxy cannot parse, is refused
by name at load.

`limits.tunnels` is required and has no default. How many long-lived
sessions the origins should carry is a capacity decision zoxy cannot infer
from a connection count, so a listener that allows an upgrade without it is
refused at startup. It may not exceed `conn_slots`.

The tunnel pool is separate from the buffers ordinary traffic uses. Every
other pool is sized for concurrent activity (an idle keep-alive connection
holds no head buffer), but a tunnel pins its relay buffer for its whole
life. A separate pool means tunnels cannot starve HTTP. Each tunnel costs
8200 bytes, and the startup banner prints the cost.

When the pool is full, the upgrade is refused with `503` before the
handshake reaches the origin, so a refusal costs no backend connection.
`zoxy_l7_shed_tunnels` counts those; `zoxy_tunnels_established` counts the
ones that became sessions.

- `timeouts.tunnel_ms` replaces the other deadlines once a connection
  becomes a tunnel. `idle_ms` defaults to 60 s, but a WebSocket can
  legitimately sit idle for hours: its keepalive is application-level
  ping/pong, which zoxy cannot see in opaque bytes. Default one hour,
  minimum one second, maximum one day. Unlike `request_ms`, it has no `0`
  for no cap, because a tunnel holds a pool slot for its whole life.
- The upgraded upstream connection leaves the keep-alive pool and is never
  reused for another client. It still counts against the cluster's
  `max_inflight` for as long as the tunnel lives.

The access log writes one line when the tunnel closes: `kind` `http`,
`status` `101`, the details of the request that opened it, and `bytes_in`
and `bytes_out` for the whole session.

#### Bounding a request body

An `http` listener caps how large a request body it will carry. The default
is 1 MiB, as with nginx's `client_max_body_size`; `0` accepts any size:

```json
{ "bind": "0.0.0.0:80", "http": { "cluster": "api",
  "max_body_bytes": 5242880 } }
```

A large upload does not hurt zoxy: the recv → send → recv relay keeps
per-connection memory constant whatever the stream size, so an unbounded
body costs one relay buffer. The cap protects the origin, a job most
application stacks expect the proxy in front to do.

The cap is per listener, not in `limits`, because it reserves nothing. It
states policy, like `forwarded` and `upgrades`, and a listener fronting an
upload endpoint wants a different number from one fronting an API.

A declared `Content-Length` over the cap is answered `413` before the
origin is dialled, and the connection closes with the body still unread in
the socket. A chunked body announces no size, so zoxy measures it as it
arrives. If it crosses the cap before the response leg is armed, it gets
the same `413`. After that no status can be sent, so the connection is torn
down. `zoxy_l7_body_over_limit` counts the first case (the client was told
why) and `zoxy_l7_body_cut_mid_stream` the second (the client lost its
connection).

> [!IMPORTANT]
> Releases up to 0.3.0 bounded nothing. A deployment proxying uploads
> larger than 1 MiB needs `max_body_bytes` raised, or set to `0`, before
> upgrading.

### Routing

`"cluster"` is shorthand for a single catch-all route. An `http` listener
can instead carry a route table, matched **longest-prefix within the
matching host**:

```json
{
    "bind": "0.0.0.0:80",
    "http": {
        "routes": [
            { "host": "api.example.com", "prefix": "/v2", "cluster": "api-v2" },
            { "host": "api.example.com", "prefix": "/",   "cluster": "api" },
            { "prefix": "/static",                        "cluster": "cdn" },
            { "prefix": "/",                              "cluster": "web" }
        ]
    }
}
```

A route with no `host` matches any host, and a host-specific route always
beats an any-host one. A prefix matches whole path segments: `/static`
matches `/static` and `/static/app.js` but never `/staticfiles`, and `/`
matches everything. Filters' `path_prefix` uses the same rule.

Matching uses the **canonical** path (percent-escapes decoded,
dot-segments collapsed), and the origin receives that same canonical
path, so the router and the backend cannot disagree about which resource
was named. Escapes that change structure (`%2F`, `%00`, truncated
escapes) are rejected with `400`. A request that matches no route gets
`404`.

#### Pinning a canary with a header

For a percentage canary, use [endpoint weights](#weights): put the new
version's endpoints in the same cluster at a low weight, and every pick
policy honours it. A pinned canary (a specific client, a test account, an
internal gateway's header) is a route that matches a header:

```json
"routes": [
    { "header": { "name": "X-Canary", "present": true },
      "prefix": "/", "cluster": "next" },
    { "prefix": "/", "cluster": "stable" }
]
```

Use `{ "present": true }` for any value or `{ "equals": "..." }` for one.
Names match case-insensitively (RFC 9110); values do not. There is no
substring or regex matching.

**Host, then header, then prefix.** Every key a route states must match.
When several routes match, the most specific wins, in that order: a
host-scoped route beats an any-host one, and within a host group a route
naming a header beats one that does not.

```json
"routes": [
    { "host": "api.example.com", "header": { "name": "X-Canary", "present": true },
      "prefix": "/", "cluster": "api-canary" },
    { "host": "api.example.com", "prefix": "/",  "cluster": "api" },
    { "header": { "name": "X-Canary", "present": true },
      "prefix": "/", "cluster": "canary" },
    { "prefix": "/", "cluster": "web" }
]
```

Those four routes can be written in any order with the same result: the
table is sorted once at startup.

Config order decides one case. Two routes sharing a host and a prefix but
naming **different** headers are equally specific, and a request carrying
both headers matches both. The one written first wins.

A request that gains or loses the header **moves to a different cluster**,
so a `hash` pick holds within each cluster but not across the change. The
header is a routing key *and* is forwarded, so the origin sees it and can
log which side served the request.

`CONNECT` and `TRACE` are answered `501` and never reach a backend.
`CONNECT` asks the proxy to open an arbitrary destination, which is
forward-proxy behaviour. `TRACE` echoes a request back, which is the
Cross-Site Tracing vector.

`OPTIONS` honours `Max-Forwards`. At `0`, zoxy answers with `200` and an
`Allow` describing zoxy itself, and never dials a backend. Above `0`, the
request is forwarded with the value decremented. zoxy reads the field only
for `OPTIONS`, and CORS preflights carry no `Max-Forwards`, so ordinary
traffic is unaffected.

A request may name its authority in the request line itself, as in
`GET http://api.example.com/v2/x HTTP/1.1`. A client sends this form when
it thinks it is talking to a forward proxy. zoxy accepts it (RFC 9112
requires that), and the authority in the target **wins over the `Host`
header**: it is what routing and filters match, what the access log
records, and what the origin receives as `Host`. Only `http` and `https`
targets are accepted; any other scheme gets `400`.

### Clusters and load balancing

A cluster is a named set of endpoints plus a policy for choosing one.
Endpoints are static `IP:port` literals or
[`unix:` socket paths](#reaching-a-local-app-over-a-unix-socket), resolved
once at load; dynamic DNS is out of scope. Only the config bounds cluster
and endpoint counts (there is no compiled ceiling), and the startup banner
prints what the endpoint tables cost.

```json
"clusters": {
    "api": {
        "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"],
        "pick": "p2c"
    }
}
```

| `pick` | behaviour |
|---|---|
| `p2c` *(default)* | of two weight-biased candidates, the one with less in-flight work wins; HTTP requests and L4 connections both count |
| `rr` | smooth weighted rotation: exact at equal weights, with a predictable spread; useful for cache warming |
| `hash` | the same key always reaches the same endpoint |

`pick` is either a bare policy string or an object carrying the policy and
its settings. `hash` takes only the object form, which names its key
(`source_ip`, `header` or `cookie`).

Upstream connections are pooled process-wide and reusable by any request.

#### HTTP/2 to the origin, and gRPC

A cluster whose origins speak HTTP/2 by prior knowledge says so with
`"protocol": "h2c"` (the default is `http1`). Its requests then share
connections, each a stream of its own, rather than leasing one apiece:

```json
"clusters": {
    "greeter": {
        "endpoints": ["10.0.0.5:50051", "10.0.0.6:50051"],
        "protocol": "h2c"
    }
}
```

Everything before the origin is unchanged — routing, filters, edits,
`X-Forwarded-For`, the access log — and so is what either kind of client
gets back. The request is said to the origin as HTTP/2, with
`te: trailers`. An answer without a declared length comes back to an
HTTP/1.1 client chunked, so its trailer section has somewhere to go. To
an HTTP/2 client it comes back as DATA and trailing HEADERS. That is
what gRPC needs: a gRPC client over HTTP/2 (`h2c` or `h2` in ALPN on the
listener) reaches a gRPC server in an `h2c` cluster, and `grpc-status`
arrives in the trailers. A streaming call is one exchange whose two
halves run at once: the origin may answer while the request is still
arriving, and the call ends once both have. `idle_ms` bounds a silence on
it, refreshed by every message either way. `request_ms` (off by default)
caps its whole length, so a deployment carrying long-lived streams leaves
it off or sizes it for them.

A call's own deadline, `grpc-timeout`, is honored. It arms the same
per-exchange deadline `request_ms` does, and replaces it when it is
earlier or when `request_ms` is off. When it runs out before the origin
answers, zoxy answers the client with `grpc-status: 4` (DEADLINE_EXCEEDED)
and frees the origin stream. That expiry is counted in
`zoxy_l7_grpc_deadline_exceeded` and is never held against the endpoint.
The header still reaches the origin unchanged, so the server can stop
work at the same moment.

Origins behind TLS are `"protocol": "h2"`, which requires a `tls` block:

```json
"greeter": {
    "endpoints": ["10.0.0.5:443"],
    "protocol": "h2",
    "tls": { "server_name": "greeter.internal", "ca": { "path": "/etc/zoxy/internal-ca.pem" } }
}
```

Every handshake is verified, never skipped. The origin must select `h2`
in ALPN. Its chain must reach a certificate in the `ca` bundle, through
CAs only. The leaf must carry `server_name` in its subjectAltName (RFC
9525; a common name alone does not count). `server_name` is also the SNI
sent, and is configured because an endpoint address is not an identity.
The bundle is read once at load, so a missing or empty file stops the
config, not the first request. A handshake that fails is a `502` for the
requests waiting on it, counted in `zoxy_h2_origin_tls_failed`. The same
`tls` block on a cluster that speaks HTTP/1.1 makes its origins
[HTTPS origins](#https-origins).

Two pools carry it, both zero unless some cluster speaks `h2c` or `h2`.
`limits.upstream_h2_connections` bounds the origin connections, two per
`h2c` or `h2` endpoint by default. `limits.upstream_h2_streams` bounds
the requests on them at once, one per upstream slot by default and never
more; each holds a buffer for its answer. A request that finds neither is answered
`503` and counted in `zoxy_l7_shed_h2_origin_connections` or
`zoxy_l7_shed_h2_origin_streams`. An origin connection that carries
nothing for an idle window is told `GOAWAY` and closed.

What fails on an origin stream fails that request alone, as a socket
error would: a refused dial is a `502` and a silent origin a `504`. A
stream the origin resets, or refuses past its `GOAWAY`, earns the same
free replay a stale pooled connection does. An `h2c` cluster may not be
reached from an `l4` listener, nor from one carrying upgrades (HTTP/2 has
no `101`), and its health checks are `tcp` or `grpc`, not `http`: that
prober speaks HTTP/1.1. A [`grpc` check](#health-checks) asks the gRPC
health service over the cluster's own connections.

#### HTTPS origins

A cluster that speaks HTTP/1.1 reaches its origins over TLS when it has a
`tls` block. The block is the same one an `h2` cluster names:

```json
"billing": {
    "endpoints": ["10.0.0.7:443", "10.0.0.8:443"],
    "tls": { "server_name": "billing.internal", "ca": { "path": "/etc/zoxy/internal-ca.pem" } }
}
```

Verification works as it does for `h2`, and is never skipped. The chain
must reach the `ca` bundle, and the leaf must carry `server_name` in its
subjectAltName. ALPN offers `http/1.1`. An origin may select it or
nothing. One that insists on something else is refused.

A connection is verified once and then pooled like any other. It is
parked between requests, and the next request to the same endpoint of the
same cluster reuses it without a second handshake. A connection carries
no client identity, so reusing it across clients is safe. A connection
whose origin closed it, or that holds bytes past the response, is closed
instead of parked.

- **A failed handshake:** if the chain doesn't verify, the origin speaks
  another protocol, or it hangs up, the request gets a `502`. The failure
  is counted in `zoxy_upstream_tls_failed` and is not retried on another
  endpoint, because the dial itself succeeded.
- **A slow handshake:** it gets `connect_ms` from its start.
- **A reused connection the origin had closed:** it costs the request the
  usual free replay.
- **Sessions:** each pooled connection holds one session of about 110 KiB.
  `limits.upstream_tls_sessions` bounds them. The default is 16 per HTTPS
  endpoint, within `upstream_slots` and within the libcrypto heap that the
  listeners' `tls_engines` and the `h2` origins' connections also draw
  on. A new connection with no session free is answered `503`, counted in
  `zoxy_l7_shed_upstream_tls`.
- **Handshake counts:** `zoxy_upstream_tls_handshakes` counts completed
  handshakes. Compare it with the requests served to see how much reuse
  saves.

Not yet carried over TLS to the origin:
- an `http` health check (use `tcp`);
- an upgrade such as WebSocket;
- an `l4` listener routing to the cluster;
- `proxy_protocol` (it is `l4`-only anyway).

The loader refuses each of these. Client certificates to the origin are
not supported.

#### Weights

An endpoint is either a bare `"IP:port"` string (weight 1) or an object
with a relative weight, up to 256:

```json
"endpoints": ["10.0.0.1:8080", { "address": "10.0.0.2:8080", "weight": 3 }]
```

Every policy honours weights. A 16-core box can take four times a 4-core
box's share, a canary can start at 1-in-20 and move by editing one number,
and shifting weight drains a pool gradually. A weight of `0` **drains** the
endpoint: it is still health-checked but never picked, not even when
everything else is ejected. At least one endpoint must have a non-zero
weight, or the config is rejected.

#### Reaching a local app over a Unix socket

When zoxy runs on the same host as the application it fronts, an endpoint
can be a socket file instead of a loopback address:

```json
"clusters": {
    "app": {
        "endpoints": ["unix:/run/app.sock"]
    }
}
```

Three reasons to prefer it:

- **No ephemeral-port exhaustion.** A busy proxy in front of a local app
  burns through the loopback's ephemeral range, and dials start failing
  while the backend is healthy. A socket file has no port.
- **Filesystem permissions as the ACL.** A socket in a directory the app
  user owns is unreachable by anything else on the box, with no firewall
  rule.
- **Less work per byte.** No checksums, loopback routing or TCP state
  machine on the leg every request uses.

The `unix:` prefix is not part of the path; the kernel gets the path you
would `ls`. The path must be **absolute** and at most 103 bytes. A
`sockaddr_un` holds 108 bytes on Linux and 104 on macOS; 103 is the smaller
minus the terminator, so one config works on both. The path must be
printable ASCII with no quote or backslash, because the address appears
verbatim in every access-log line and Prometheus label, where one control
byte invalidates the whole line or scrape. A path that breaks any of these
rules is refused at load, never truncated: a shortened path names a
different socket.

Everything above the dial is unchanged. The two forms can mix in one
cluster, so a migration can move one endpoint at a time. Weights, `pick`,
health checks, retries and `max_inflight` work as they do on an IP
endpoint, and `hash` stickiness keys on the path. The access log, the
`endpoint` metrics label and the startup banner print the endpoint as
written, `unix:` included:

```json
{"upstream":"unix:/run/app.sock", ...}
```

A [`proxy_protocol`](#sending-proxy-protocol) send block still announces
the *client's* addresses; the header describes the connection that
arrived, not the leg it is written on.

A listener can take the same grammar; see
[accepting on a socket file](#accepting-on-a-socket-file).

The abstract namespace (a leading NUL) is out of scope: it has no
filesystem permissions.

#### Accepting on a socket file

`bind` takes the same `unix:` grammar, so a local process can reach zoxy
through a file instead of a port:

```json
{
    "bind": "unix:/run/zoxy.sock",
    "mode": "0660",
    "http": { "cluster": "app" }
}
```

The path rules are the endpoint's: absolute, at most 103 bytes, printable
ASCII with no quote or backslash. Two listeners on one path are a
duplicate, as two on one `IP:port` are.

The socket file's lifecycle:

| at startup, the path… | zoxy |
|---|---|
| does not exist | creates it |
| is a socket | removes it and creates it again, so a killed process cannot wedge every later start |
| is anything else (file, directory, symlink) | **refuses to start** and says so |

A clean stop removes the file it made. A `SIGKILL` cannot, which is what
the second row is for. The third row stops a typo in `bind` from deleting
anything; a symlink is judged as itself, not followed.

**`mode`** sets the socket's permission bits after the bind, as an octal
string. It is a string because `0660` is not valid JSON and `660` is
decimal, and the two readings differ by a factor of eight in the direction
that widens access. Without `mode`, the socket gets whatever the umask
gives, which under a typical umask is world-connectable. If the socket
itself, not its directory, is meant to be the ACL, set the field.

A request arriving on a socket file has no client IP, so the loader
refuses the four things that would need one:

| rejected | because |
|---|---|
| a `forwarded` block | `X-Forwarded-For` would state an address nobody connected from |
| a filter with `match.client` | an allowlist would have no address to compare |
| routing to a `hash` cluster keyed on `source_ip` | every local client would land on one endpoint |
| routing to a cluster with `proxy_protocol` send | the header announces source *and* destination addresses; this listener has neither |

The last two are checked against every cluster the listener can *reach*,
which on an `l4` listener includes every name in its
[SNI table](#routing-an-l4-listener-by-tls-name-sni).

Each is a startup error naming the pair. The access log records the
missing address explicitly:

```json
{"client":null, "upstream":"10.0.0.1:8080", ...}
```

Everything that does not depend on a client address is unchanged: routing,
header and path filters, `hash` on a header or cookie, TLS termination,
upgrades, body limits, timeouts and the shed ladder.

A `unix:` listener is not part of the `SO_REUSEPORT` scale-out (see
[Under load](#under-load)): two processes cannot bind one path. Run N
processes behind a TCP listener, or one process behind a socket file.

### Sticky sessions

`pick: {"policy": "hash", ...}` keeps clients on one backend, and `key`
names what "one client" means:

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "pick": { "policy": "hash", "key": "source_ip" }
}
```

It keeps **no table**. The kernel spreads one client's connections across
zoxy processes by hashing the 4-tuple, so a per-process table would be
consulted by processes that never saw that client. The pick is a pure
function of the key and the healthy set, so every process agrees without
sharing anything.

When a backend is ejected, only *its* clients move, and they return when it
recovers. `source_ip` uses all four bytes of an IPv4 address and the /64
prefix of an IPv6 one, so stickiness survives privacy-address rotation.

Hashing on client address has limits: NAT hides many clients behind one
address, and one heavy client cannot be split. The other two keys handle
that case. Where even load matters more than stickiness, use `p2c`.

The key is the *observed* client address. Behind another proxy or load
balancer, every connection carries that machine's address and the whole
cluster hashes to one endpoint; see
[Receiving PROXY protocol](#receiving-proxy-protocol) for how an `l4`
listener recovers the real client.

#### Sticky on a header

```json
"pick": { "policy": "hash", "key": "header", "name": "x-tenant" }
```

This hashes the named header's value, so stickiness follows an identity
the client states (a tenant, a user id, an API key) and survives NAT. A
request without the header is placed by load, like a `p2c` pick. Only
`http` listeners can route to a header- or cookie-keyed cluster; an `l4`
listener never parses a request.

#### Sticky on a cookie

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "pick": { "policy": "hash", "key": "cookie", "name": "srv_id" }
}
```

The named cookie carries the assignment itself: a 16-hex **endpoint tag**
that zoxy derives from the endpoint's address, stable across restarts,
processes and config reordering. A request with no cookie is placed on the
least busy backend, and the response sets the cookie
(`Set-Cookie: srv_id=<tag>; Path=/; HttpOnly`, a session cookie with no
expiry, plus `; Secure` when the listener terminates TLS). A request whose
tag names a healthy backend with spare capacity goes there and is **not**
re-stamped. A tag naming an ejected, drained or removed backend is
re-placed, and the response sets a new cookie. Every user behind one NAT
address carries their own assignment.

Pick a cookie name the application does not use; zoxy adds its
`Set-Cookie` beside the origin's, never in place of them. The tag is not
signed: a forged cookie can only choose which of *your* backends serves
that client.

Three counters partition a cookie cluster's responses:
`zoxy_l7_sticky_followed`, `..._assigned` and `..._repicked`. A rising
repick rate means backends are flapping under a sticky population.

### Health checks

Health checks are per cluster and opt-in. A prober sweeps every checked
endpoint, several at a time. `fall` consecutive failures eject an endpoint
from balancing and close its pooled connections; `rise` consecutive
successes restore it.

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "check": { "type": "http", "path": "/healthz", "expect_status": 200 }
}
```

`type` is `tcp` (the port accepts) or `http` (a path answers with the
expected status). Defaults: `fall` 3, `rise` 2, `expect_status` 200, and a
probe budget of `timeouts.connect_ms` unless `timeout_ms` overrides it.
`timeouts.health_interval_ms` (default 2000) sets the gap between sweeps.
The first sweep starts at a random point within the first interval, so
processes started together (a rollout, or several behind `SO_REUSEPORT`)
do not probe the same origins in step for as long as they run.
An `http` probe sends `host` as its `Host` header. Without it, the probe
sends the endpoint's `IP:port`, or `localhost` for a `unix:` endpoint,
whose path is not a host name. `path`, `host` and `expect_status` belong
to `http` alone, and the loader refuses them beside `tcp` or `grpc`
rather than ignoring them.

A cluster that [speaks `h2c` or `h2`](#http2-to-the-origin-and-grpc) can
use `grpc`, the standard gRPC health protocol:

```json
"grpc": {
    "endpoints": ["10.0.0.1:50051", "10.0.0.2:50051"],
    "protocol": "h2c",
    "check": { "type": "grpc", "service": "echo.Echo" }
}
```

The probe calls `grpc.health.v1.Health/Check` on a stream of the
cluster's own pooled connections, over the cluster's TLS when it has one,
and passes only on `:status` 200, a `SERVING` answer and `grpc-status: 0`.
`service` is optional; leave it out to ask about the server as a whole
(an empty string is refused, not read as "the server"). `path`, `host`
and `expect_status` do not apply. If the connection pool is full and
holds no connection to the endpoint, the probe is skipped instead of
failed, since that limit is zoxy's and says nothing about the origin.
Skipped probes are counted in `zoxy_health_probes_skipped`. If that
counter keeps rising,
`limits.upstream_h2_connections` is smaller than the cluster's endpoints
need.

If *every* endpoint in a cluster is ejected, zoxy fails open and uses them
all. Routing nowhere would turn a probe verdict into an outage.

That rule waits until nothing is healthy. If 6 of 10 equal endpoints are
ejected, the other 4 each carry two and a half times their usual load,
which is how an overloaded cluster ejects the rest. `panic_threshold_percent`
moves the fail-open point up:

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080", "10.0.0.4:8080"],
    "check": { "type": "http", "path": "/healthz" },
    "panic_threshold_percent": 50
}
```

While at least that share of the cluster's weight is healthy, health
checks steer traffic as usual. Below it, zoxy picks over every endpoint
as if none were ejected. A drained endpoint (`"weight": 0`) counts on
neither side and is never picked, a retry still skips the endpoints its
request already tried, and `max_inflight` still caps each endpoint. The
value is 1 to 99. Leave it out to fail open only at zero healthy, as
before. It requires `check` or `passive_ejection`, because without one
nothing is ever ejected. `zoxy_upstream_panic_picks` counts picks made in
panic, and `zoxy_upstream_ejected_picks` counts every pick that landed on
an ejected endpoint, at zero healthy or in panic. Both break down
[per cluster](#metrics).

### Passive ejection

A `tcp` check passes whenever the kernel accepts, and the kernel accepts
from the backlog even when the application behind it never does. A wedged
process, an exhausted thread pool or a GC-stalled backend passes that
check while every real request times out. An `http` check catches it, but
you need to know a path to probe. `passive_ejection` uses the traffic you
already have:

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "passive_ejection": { "fall": 5, "recovery_ms": 30000 }
}
```

`fall` consecutive **failed requests** eject the endpoint. A failure is a
dial that failed, or an exchange that returned no response byte before its
deadline. A `5xx` response is *not* a failure: a bad deploy answering 500s
is a software bug, and ejecting for it would take out a whole cluster. Any
response resets the count.

After `recovery_ms`, the endpoint is let back in and traffic judges it
again; if it is still dead, `fall` more failures eject it again. Passive
detection finds the failure and active checks find the recovery. To
re-test with one probe instead of `fall` real requests, configure both.

Defaults: `fall` 5, higher than a probe's 3 because real traffic carries
transient failures a probe never sees, and `recovery_ms` 30000. Ejection,
fail-open and the closing of pooled connections work as they do for active
checks.

An endpoint that keeps failing as soon as it is let back in costs `fall`
requests every `recovery_ms`. Set `recovery_ms_max` to make it wait longer
each time:

```json
"passive_ejection": { "fall": 5, "recovery_ms": 10000, "recovery_ms_max": 300000 }
```

Each passive ejection of the same endpoint doubles its cooldown, 10 s,
20 s, 40 s and so on, up to `recovery_ms_max`. An endpoint that then stays
in rotation for a whole `recovery_ms_max` starts over at `recovery_ms`. A
health check's `rise` can still bring an endpoint back early, but that
does not reset the doubling, since it shows the probe path works, not that
real traffic will. Without `recovery_ms_max` every cooldown is
`recovery_ms`, as before.

If no cluster has either kind of detection, the startup banner says so:

```
config  1 listener(s), 3 cluster(s), 0 error page(s), access log off, 1 cluster(s) without failure detection
```

The note is informational. A multi-endpoint cluster with no checks is
reasonable behind a service mesh, or when the endpoints are themselves load
balancers. A cluster is counted only when two of its endpoints are
reachable, so a single-endpoint cluster never is, and neither is one whose
second endpoint is drained with `"weight": 0`.

### Per-endpoint in-flight cap

`max_inflight` caps the concurrent work zoxy will ask of **one endpoint**.
It applies per endpoint, so a three-endpoint cluster with a cap of 100
admits up to 300, like HAProxy's `server ... maxconn`.

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "max_inflight": 100
}
```

An endpoint at its cap is skipped, so requests keep flowing while any
endpoint has room. When *every* endpoint is full, zoxy refuses: an HTTP
request is answered `503` and an L4 connection is closed, since a byte
relay has no way to say "try later". Without `max_inflight`, a cluster is
uncapped.

This is the one limit that fails **closed**. When every endpoint is
ejected, zoxy does not know whether they work, so trying beats refusing.
When every endpoint is at its cap, zoxy knows they are full.

An endpoint coming back from ejection is otherwise handed its full cap at
once, and the first to recover after an outage can take every new
request and fall over again. `slow_start_ms` ramps it instead:

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "check": { "type": "http", "path": "/healthz" },
    "max_inflight": 100,
    "slow_start_ms": 30000
}
```

For 30 s after an endpoint is restored, by a health check's `rise` or a
passive cooldown ending, its cap rises linearly from 1 to 100. Requests
that do not fit go to other endpoints, or are shed with `503` like any
capped request when none has room. `slow_start_ms` requires `max_inflight`
and `check` or `passive_ejection`. The effective cap is not exported as
its own gauge; `zoxy_endpoint_inflight` and the endpoint-cap shed
counters show the ramp at work.

Both protocols count against the same figure: an in-flight HTTP request and
a live L4 connection are each one unit of work.
`zoxy_l7_shed_endpoint_inflight` and `zoxy_l4_shed_endpoint_inflight` count
refusals. They are separate from `zoxy_l7_shed_upstream_slots`, which means
zoxy ran out of its own slots and needs a wider pool.

`max_total_inflight` caps the whole cluster instead, every endpoint
together:

```json
"reports": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
    "max_total_inflight": 64
}
```

Every cluster shares zoxy's upstream pool, so a cluster whose origins turn
slow can hold most of it and make unrelated clusters shed. With a total
cap, a new request past it is answered `503` and a new L4 connection is
closed, and the rest of the pool stays free for everyone else. A retry of
a request already admitted is never refused by it. The refusals count in
`zoxy_l7_shed_total_inflight` and `zoxy_l4_shed_total_inflight`, apart from
both the per-endpoint cap and the pool.

### Retrying a refused dial

`retries` lets an HTTP request try more endpoints when its dial is refused
or the endpoint is unreachable. Without it, one refusing endpoint in a
three-endpoint cluster fails about a third of requests for as long as it
stays in rotation, which with no health check or passive ejection is
forever.

```json
"api": {
    "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"],
    "retries": 2
}
```

A retry is safe for every method, `POST` included: a dial that failed sent
nothing, so no application saw the request. Each retry goes to an
endpoint this request has not tried yet, picked by the cluster's own
`pick` policy. All tries share one `connect_ms`, so `retries` never
lengthens how long a client can wait. A dial that times out is not
retried, because it has already spent that budget, and answers `504`.
Running out of retries or of untried endpoints answers `502`.
`zoxy_upstream_retried` and `zoxy_upstream_retries_exhausted` count both
outcomes.

Retries apply to `http1` clusters. An `h2c` or `h2` cluster refuses a
non-zero `retries` at load, because its connections are dialed by a pool
rather than by a request. An L4 connection always dials once.

### Client address

zoxy uses one client address everywhere it matters: the `source_ip` hash
pick, a filter's `client` match and the access log. Three blocks decide
what that address is and who is told it. A listener learns it and states
it; a cluster states it to its origins. A deployment that needs one block
usually needs another: learn the address first, then pass it on in a form
the origin can read.

#### Receiving PROXY protocol

Behind a load balancer, zoxy sees only the balancer. That breaks more than
logging: a `source_ip`-keyed hash pick reads the client address, so every
connection hashes alike and the whole fleet lands on one endpoint. An `l4`
listener can instead require each connection to open with a PROXY protocol
header, v1 or v2, as AWS NLB, GCP and HAProxy send:

```json
{
    "bind": "0.0.0.0:5432",
    "l4": {
        "cluster": "postgres",
        "proxy_protocol": { "mode": "require" }
    }
}
```

`require` is the only mode. A listener that accepted a header whenever one
showed up would let any client choose its own address, and with it its
sticky backend and its access-log lines. The PROXY protocol spec forbids
that for receivers, and HAProxy gates the same feature behind an explicit
`accept-proxy`. A `require` listener closes any connection that does not
open with a valid header, so only the proxy in front of it can use it. Turn
it on only where the listener is reachable exclusively through that proxy.

zoxy uses the announced address everywhere it uses the client address. A
header that announces nothing (v1 `UNKNOWN` or v2 `LOCAL`, the forms a
balancer's own health checks arrive in) is accepted and keeps the observed
peer. Headers are capped at 512 bytes: v2 TLVs within the cap are skipped,
and a declared length past it is refused at once. Header bytes never count
towards the log's `bytes_in`.

`zoxy_l4_proxy_header_accepted` and `zoxy_l4_proxy_header_invalid` count
the verdicts. A rising `invalid` means something other than the configured
proxy is reaching the listener. `http` listeners reject the block; the L7
receive phase does not exist yet.

#### X-Forwarded-For

Without this, everything *behind* zoxy sees zoxy: origin logs, IP
allowlists, per-client rate limits. An `http` listener can add
`X-Forwarded-For`:

```json
{
    "bind": "0.0.0.0:80",
    "http": {
        "cluster": "web",
        "forwarded": { "mode": "replace" }
    }
}
```

There is no default mode. Each mode is a security bug in the other's
position, and zoxy cannot tell from the inside which position it is in.

| mode | behaviour | use when |
|---|---|---|
| `replace` | state the peer zoxy observed, discard any inbound chain | **at the edge**, where the inbound chain is client-controlled and honouring it lets a caller pick the address your allowlists trust |
| `append` | extend the inbound chain with the observed peer | **only behind proxies you own**; anywhere else it extends a forged chain |

Omit the block and the header passes through untouched.

The carried chain is bounded. A chain grows by one address per hop and
nothing in HTTP caps it, so past `forwarded_chain_bytes_max` (512) zoxy
drops it *whole*, and the header states only the observed peer. A
truncated chain would read as complete. `zoxy_forwarded_chain_dropped`
counts the drops.

Filters may not set `X-Forwarded-For`; the loader rejects it. A filter can
only write a constant, which would pin one fixed address to every client.

#### Sending PROXY protocol

An origin behind an `l4` relay has no header to read an address from, so
the only way to tell it who connected is to open the upstream connection
with a PROXY protocol header. A *cluster* opts in, because the setting
states what its origins expect; HAProxy's `send-proxy` sits at the same
level:

```json
"clusters": {
    "postgres": {
        "endpoints": ["10.0.0.1:5432"],
        "proxy_protocol": { "send": "v2" }
    }
}
```

`send` is `v1` (text, readable in a tcpdump) or `v2` (binary, what cloud
load balancers speak). The header names the client zoxy believes. Behind a
`require` listener, that is the client the *fronting* proxy announced, so
a chain of proxies carries one identity end to end.

The header is per *connection*, with two consequences:

- Only `l4` listeners may route to a sending cluster. A pooled HTTP
  upstream is shared across clients, and a header naming one client would
  lie to every other, so the loader rejects the pairing. For HTTP origins,
  use [`forwarded`](#x-forwarded-for) instead.
- Health probes do not send the header. A `tcp` check is unaffected, since
  it proves the port accepts and sends nothing, but an `http` check
  against a sending cluster probes without it. If the origin strictly
  requires the header, use `tcp` checks there.

`zoxy_l4_proxy_header_sent` counts headers staged, one per dialled
connection to a sending cluster.

### Filters

An `http` listener can carry `request_filters`, a list of rules evaluated
top-down against each request. Each rule has a match predicate (an absent
field matches anything) and a list of actions applied in order. The list
has no length cap.

Order matters. The first terminal action (`reject`, `redirect`, `respond`
or `allow`) in a matching rule ends the walk, and no rule below it is read.
The first three answer the request; `allow` forwards it. Put specific rules
above general ones. [Routes](#routing) work the opposite way: they are
sorted by specificity at load.

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
        "match": { "path_prefix": "/admin", "client": ["203.0.113.0/24"] },
        "actions": [{ "reject": 403 }]
    },
    {
        "match": { "method": ["GET"], "host": "cdn.example.com" },
        "actions": [{ "rewrite_prefix": { "from": "/static", "to": "/" } }]
    }
]
```

Rules match on `method`, `host`, `path_prefix`, header predicates
(`present`, `equals`, `contains`), and `client`, a list of CIDR ranges the
connection's address must fall inside. Actions are `reject` with a status,
`redirect`, `respond` (answer from a configured body), `allow` (forward and
stop reading rules), `header_set`, `header_add`, `header_remove`, and
`rewrite_prefix`.

A rule whose actions are all edits, such as the `header_set` above or a
`rewrite_prefix`, records what the render should do, and evaluation
continues. An edit therefore never shields a request from a `reject` below
it. An `allow` does, which is how you write an allowlist; see
[matching the client address](#matching-the-client-address).

Rules compile into immutable tables at load and run in bounded loops. There
are no plugins and no scripting, and nothing can allocate or run unbounded.
A rewrite changes only what is *forwarded*: routing has already chosen the
cluster from the original path, so a rewrite never re-routes.

#### Matching the client address

`client` is a list of CIDR ranges the connection's address must fall
inside. It matches if the address is in any range on the list, and the
rest of the match must hold too. With `reject`, it refuses a range:

```json
"request_filters": [
    { "match": { "path_prefix": "/admin", "client": ["203.0.113.0/24"] },
      "actions": [{ "reject": 403 }] }
]
```

With `allow`, it admits one range and refuses everyone else. Limiting
`/admin` to the office ranges takes two rules, in this order:

```json
"request_filters": [
    { "match": { "path_prefix": "/admin",
                 "client": ["10.0.0.0/8", "192.168.1.0/24"] },
      "actions": [{ "allow": true }] },
    { "match": { "path_prefix": "/admin" }, "actions": [{ "reject": 403 }] }
]
```

`allow` neither answers nor edits. It forwards the request and stops the
walk, so the office ranges never reach the `reject` below, and everyone
else does. `true` is its only value.

> [!IMPORTANT]
> The rule that admits must be terminal. A `header_set` in its place is an
> edit, and edits do not stop the walk, so the `reject` below would still
> answer `403` to the office too. Tagging a range for the origin to judge
> is a useful idiom, but only in a rule with no rule below it:
>
> ```json
> "request_filters": [
>     { "match": { "path_prefix": "/admin", "client": ["10.0.0.0/8"] },
>       "actions": [{ "header_set": { "name": "X-Internal", "value": "1" } }] }
> ]
> ```

The address matched is the one zoxy believes: the TCP peer, or the
[PROXY-protocol-announced client](#receiving-proxy-protocol) on a listener
that requires the header. It is never taken from an `X-Forwarded-For`
chain, which any client can write. Prefixes run to `/32` for IPv4 and `/64`
for IPv6 (the same rule sticky hashing uses). The `/len` is mandatory, and
host bits past the prefix are rejected: `10.0.0.1/8` is a typo for one of
two different ranges, and zoxy will not guess which.

#### Redirects

The two most common edge rules are one action each. Both belong on the
plaintext `:80` listener. Redirecting a request that arrived over TLS to
`https://` creates a loop, and because the rule states the scheme instead
of reading it from the hop, only the config can keep the two apart.

```json
"request_filters": [
    { "match": { "host": "www.example.com" },
      "actions": [{ "redirect": { "status": 308, "scheme": "https",
                                  "host": "example.com" } }] },
    { "actions": [{ "redirect": { "status": 301, "scheme": "https" } }] }
]
```

The apex rule comes first because the rule below it matches *everything*.
In the reverse order, `www.example.com` would get the catch-all's 301 to
its own name and never reach the 308. A bare catch-all shadows every rule
below it, so a redirecting listener usually does nothing else. It still
needs a `cluster` or `routes` for the loader to check, but filters run
before routing, so nothing is ever dialled.

A composed target replaces the scheme and, optionally, the host. The scheme
is required because behind a TLS terminator every hop zoxy sees is
plaintext. The request's own path and query are carried through. The other
form is a fixed `location`, sent verbatim. Statuses are `301`, `302`, `307`
and `308`. Redirects count as `zoxy_l7_redirected` and log as `redirected`,
separately from rejects.

#### Response filters

`response_filters` edits the origin's response on the way out: add
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
(`"1xx"` through `"5xx"`), and response-header predicates with the same
`present`, `equals` and `contains` vocabulary. Its only actions are the
three header verbs. `reject`, `allow` and `rewrite_prefix` are request-side
actions, and the loader refuses them here as an unknown field
(`UnknownField`).

The same guardrails apply in both directions. Filters may not touch the
headers zoxy owns (`Content-Length`, `Transfer-Encoding`, `Connection` and
the hop-by-hop set, `X-Forwarded-For`), and a response head that no longer
fits after edits is answered `502`. Responses zoxy generates itself (`404`,
`503`, filter rejects, a `respond` action's body) are not origin responses
and get no edits.

### Response bodies

Every response zoxy generates itself has an empty body by default. `bodies`
defines content once, from a file read at startup or inline for
one-liners, and anything that serves content refers to it by name:

```json
"bodies": {
    "maintenance": { "file": "/etc/zoxy/503.html", "content_type": "text/html; charset=utf-8" },
    "not-found":   { "file": "/etc/zoxy/404.html", "content_type": "text/html; charset=utf-8" },
    "robots":      { "inline": "User-agent: *\nDisallow: /private\n",
                     "content_type": "text/plain" }
},
"error_pages": { "404": "not-found", "503": "maintenance" }
```

Each body is read and rendered once, however many places serve it, so the
same maintenance page used by `error_pages` and three filter rules is one
buffer. Referring to a name that does not exist is a startup error.
`content_type` is required; nothing is guessed from a filename. Files are
read at startup like the rest of the config, so **changing one needs a
restart**.

`error_pages` accepts only the statuses zoxy sends: `400`, `403`, `404`,
`408`, `413`, `414`, `429`, `431`, `501`, `502`, `503`, `504`. A page for
anything else is refused at load.

Every response zoxy generates *itself* (these pages, the empty defaults,
redirects) carries `Date` and `Server: zoxy`. Responses from an origin keep
the origin's own headers and gain neither, so `Server: zoxy` on a `503`
tells you the proxy raised it and the backend was never asked.

Bodies live in memory. A `503` is raised because something ran out, so an
error page that needed a resource to be delivered would fail exactly when
it is needed. The cost is capped per body, counted in the startup banner
and paid once per process.

**Listing a status opts in, including for sheds.** Leave `503` out and
overload gets an empty `503`; list it and the page is served. There is no
second switch.

#### Serving a body directly

```json
"request_filters": [
    { "match": { "path_prefix": "/robots.txt" },
      "actions": [{ "respond": { "status": 200, "body": "robots" } }] },
    { "match": { "host": "old.example.com" },
      "actions": [{ "respond": { "status": 503, "body": "maintenance" } }] }
]
```

`respond` answers from a body instead of forwarding: a `robots.txt`, a
maintenance page, a health target the balancer serves itself. Like
`reject` and `redirect`, it ends the request, but it counts as
`zoxy_l7_responded` and logs as `responded`. Statuses are `200` plus the
error statuses listed above.

### Timeouts

```json
"timeouts": {
    "connect_ms": 5000,
    "head_ms": 10000,
    "idle_ms": 60000,
    "drain_deadline_ms": 0,
    "max_lifetime_ms": 0,
    "request_ms": 0,
    "tunnel_ms": 3600000,
    "health_interval_ms": 2000
}
```

The block and every field in it are optional; the values above are the
defaults. An explicit `0` disables the three caps. For `connect_ms` and
`idle_ms`, `0` is rejected: a zero-length dial or idle budget is a mistake,
not a policy.

> [!WARNING]
> `connect_ms` must be **strictly below** `head_ms`, which must be at or
> below `idle_ms`, or the config is rejected at load. zoxy keeps one timer
> per connection and never moves it earlier once armed. The first deadline
> is the dial budget, and the dial's completion re-arms the timer to the
> idle budget, so an idle budget no longer than the dial budget would reap
> late instead of taking effect. Tuning only one field can trip this:
> raising `connect_ms` past the default 60 s `idle_ms` is rejected too.
> `head_ms` sits between them for the same reason: it is re-based down from
> the idle deadline when the client's first byte lands, and down again to
> `connect_ms` at the dial.

| field | default | meaning |
|---|---|---|
| `connect_ms` | `5000` | per-try upstream connect budget |
| `head_ms` | derived | budget for reading one request head; a slowloris gets `408`. It applies from the first byte, so a probe that connects and leaves gets no reply. 10 s, clamped between `connect_ms` and `idle_ms` so older configs behave as before |
| `idle_ms` | `60000` | how long a connection may stay quiet, between requests or before its first byte |
| `drain_deadline_ms` | `0` | how long a `SIGTERM` drain waits before reaping stragglers; `0` waits for the last connection |
| `max_lifetime_ms` | `0` | absolute connection-age cap, regardless of activity; `0` disables |
| `request_ms` | `0` | cap on one L7 exchange, **not** refreshed by activity. Bounds a slow request; `idle_ms` only bounds a stalled one. `0` disables. A gRPC call's own `grpc-timeout` caps it too, when earlier |
| `tunnel_ms` | `3600000` | whole life of a [tunnelled upgrade](#tunnelled-upgrades-websocket); replaces the three above once one is established. 1 s to 1 day; `0` is **not** allowed |
| `health_interval_ms` | `2000` | pause between health-probe sweeps |
| `loop_watchdog_ms` | absent | kill the process if its event loop completes nothing for this long. Off when absent; 2 s minimum |

`loop_watchdog_ms` is the only deadline here that is not about a
connection. The event loop delivers every other timer in this table, so
none of them can bound the loop itself. A loop stuck in a blocking call
delivers nothing, including the timer that would report it: the process is
alive, passes health checks, holds its listeners and answers nothing. This
setting gives the kernel a bound the loop cannot silence: an `alarm(2)`,
pushed out by a tick the loop must deliver, which fires only when the loop
stops. The process then writes one line to stderr and exits **6**, so a
supervisor replaces it.

It is off unless you set a value, because what counts as a stall depends on
the machine (one that swaps has longer legitimate pauses), and a false
positive restarts a healthy proxy. It matters most under `SO_REUSEPORT`:
the kernel keeps hashing new connections onto a stalled process, so a
process that exits is replaced, while one that hangs takes its share of the
group down with it.

`drain_deadline_ms` waits indefinitely by default, as nginx, HAProxy and
Caddy do; Traefik defaults to 10 s and Envoy to 600 s. Whatever sent the
signal already owns the upper bound (systemd's `TimeoutStopSec`,
Kubernetes' `terminationGracePeriodSeconds`) and ends the wait with
`SIGKILL`. Set a number here if you want zoxy to give up before your
platform does.

### Limits

The block is optional. The compiled constants are hard ceilings; this block
sizes the actual pools anywhere from 1 up to them, so a small deployment
neither reserves nor demands the ceiling's resources. The conditional keys
(`tls_engines`, `tunnels`, `h2_connections` and `h2_streams`) are left
out of the example below, because each is refused unless the feature it
sizes is configured. They are described further down.

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

The defaults are small: 1386 connection slots, 1386 relay buffer pairs and
1311 upstream slots, roughly 34 MiB of pools, sized to start under a stock
4096 `RLIMIT_NOFILE`. The ceiling is 11457 of each. Larger pools demand
more file descriptors, which zoxy asserts against `RLIMIT_NOFILE` at
startup instead of discovering as `EMFILE` later.

`head_buffers` and `upstream_head_buffers` bound *request heads in flight*,
not open connections. Idle keep-alive connections and parked origin
connections hold no head buffer, so these default to their never-shedding
ceilings (`conn_slots` and `upstream_slots`). A keep-alive-heavy deployment
can lower them to save memory. `head_buffer_bytes` sizes every head buffer,
so it is also the largest HTTP head accepted; larger requests are answered
`414` or `431`. Raise it for big-cookie or JWT traffic. 1 KiB to 1 MiB,
default 8 KiB.

`tls_engines` bounds *TLS sessions in flight*, handshaking or terminated,
and is zero unless a listener has a `tls` block. It decides what a TLS
deployment costs: an engine is the largest per-connection object zoxy
holds, about 92 KiB plus a 32 KiB plaintext buffer, so 1024 of them is
roughly 170 MiB. It defaults to `conn_slots` capped at 1024, and the
startup banner prints the total. Lower it if you serve less concurrent TLS
than that.

`tunnels` bounds concurrent
[tunnelled upgrades](#tunnelled-upgrades-websocket). It is zero unless a
listener has an `upgrades` allowlist, in which case it is **required**,
since no default can be derived for it. Each tunnel holds one relay-buffer
pair (8200 bytes) for its whole life, which is why tunnels are reserved
apart from `relay_buffers`.

`h2_connections` and `h2_streams` size [HTTP/2](#http2) and are zero
unless a listener speaks it, in which case `h2_streams` is **required**.
Each HTTP/2 connection holds a session of about 100 KiB and each stream
slot a head buffer; the banner prints both.
`upstream_h2_connections` and `upstream_h2_streams` size
[HTTP/2 to the origin](#http2-to-the-origin-and-grpc) and are zero unless
a cluster speaks `h2c` or `h2`. Both have defaults, and the banner prints
them. Over TLS, each origin connection also holds a TLS session on the
libcrypto heap. `upstream_tls_sessions` sizes the
[HTTPS origins](#https-origins)' sessions and is zero unless an `http1`
cluster has `tls`. `tls_engines`, the `h2` origin connections and the
HTTPS sessions together may not exceed the heap's 1024 sessions.

`keepalive_requests` lives on an `http` listener beside `max_body_bytes`,
not in `limits`, because it reserves nothing and states policy. It bounds
how many requests one client connection may serve: **1000 by default**,
nginx's figure; `0` is unlimited. It is the only bound that reaches a
*busy* connection. `idle_ms` reaps one that goes quiet and
`max_lifetime_ms` one that has been open too long, but neither touches a
connection that keeps sending requests, and that is the one holding a conn
slot and, on every request, a head buffer and an upstream lease. Past the
cap, the next response announces `Connection: close` (never a silent
reset) and the client reconnects. On HTTP/2 the cap counts a connection's
streams. The stream that reaches it ends the connection with
`GOAWAY(NO_ERROR)`: earlier streams finish, and any the client opened after
it are refused with `REFUSED_STREAM`, for the client to retry on a new
connection. `zoxy_l7_keepalive_requests_capped` counts each capped
connection once, and only where the cap is the *binding* reason, so a
rising count means the cap is working, not churn it happened to coincide
with.

Parked *upstream* connections are not capped, though nginx caps both. They
are shared across clients and carry the reuse the design rests on, and the
occupancy this cap bounds is a client's, not an origin's. An origin that
wants its own bound can announce it; zoxy honours what an origin says about
persistence.

`cq_fill_eighths` trades connection ceiling for `io_uring` completion-queue
burst headroom; `access_log_buffer_bytes` sizes the access log's staging
buffers. [Under load](#under-load) covers what zoxy does when one of these
pools runs out.

## Observability

### Metrics

An optional listener serves Prometheus exposition text: every shed rung,
every lifecycle counter, and live pool-occupancy gauges.

```json
"admin": { "bind": "127.0.0.1:9100" }
```

One scrape is served at a time, from a slot reserved outside the data-path
pools, so a scrape and a request can never shed each other. This listener
is the only way to read live counters; no signal prints them, because a
second snapshot on one stream invalidates the first.

Watch the gauges as well as the counters: a `shed_*` counter moves only
once a limit is hit, while `zoxy_conn_slots_in_use` against
`zoxy_conn_slots_capacity` shows the approach.

The scrape also shows **which backend**, per cluster and endpoint:

```text
zoxy_endpoint_responses{cluster="api",endpoint="10.0.0.1:8080"} 4182
zoxy_endpoint_connect_failed{cluster="api",endpoint="10.0.0.2:8080"} 17
zoxy_endpoint_health_down{cluster="api",endpoint="10.0.0.2:8080"} 2
zoxy_endpoint_healthy{cluster="api",endpoint="10.0.0.2:8080"} 0
```

Dial failures, responses served and health transitions
(`endpoint_health_down` and `_up`) carry both labels. The "every endpoint
was full" sheds carry only `cluster`, since no single endpoint was full.
So do the two pick families. `cluster_upstream_ejected_picks` counts picks
that landed on an endpoint health checks had ejected, which happens when
the cluster fails open or panics. `cluster_upstream_panic_picks` counts
picks made while the cluster was below its
[`panic_threshold_percent`](#health-checks), so a rising rate means the
cluster is in panic.
Two gauges show live state: `zoxy_endpoint_inflight` is the level the
balancer compares, and `zoxy_endpoint_healthy` is the prober's current
verdict, rendered for health-checked clusters only. Each labelled family
sums to the unlabelled process total it breaks down, an identity the
simulator asserts on every seed. The config bounds label cardinality
(endpoints and cluster names, never request data), and the startup banner
prices the labels and their render buffers.

#### Rate, Errors, Duration

Two families complete the RED triad:

```text
zoxy_cluster_responses{cluster="api",class="2xx"} 4182
zoxy_cluster_responses{cluster="api",class="5xx"} 17
zoxy_cluster_duration_seconds_bucket{cluster="api",le="0.005000000"} 3910
zoxy_cluster_duration_seconds_bucket{cluster="api",le="+Inf"} 4199
zoxy_cluster_duration_seconds_sum{cluster="api"} 12.884901888
zoxy_cluster_duration_seconds_count{cluster="api"} 4199
```

`cluster_responses` counts the status the client received, by class.
Without it, only statuses the proxy generated had counters (the `shed_`
ladder, `l7_bad_gateway`, `l7_gateway_timeout`), and an origin returning
`500` to every request showed up only in the access log.

`cluster_duration_seconds` is a standard Prometheus histogram, so
`histogram_quantile` works on it directly.

Both are labelled by **cluster**, not endpoint. Per-endpoint families are
what make a large deployment's exposition large, and per-endpoint `5xx` is
already acted on by [passive ejection](#passive-ejection). Cluster
granularity answers "which backend got slow" without multiplying the axis
that already dominates.

The bucket ladder is compiled in: eighteen boundaries, 2.5× apart, from
25 µs to 10 s. Every zoxy's histogram is therefore comparable with every
other's, and `_sum` and `_count` give an exact mean whatever the buckets
do.

Only **completed** exchanges are observed. An exchange the client cut off
mid-response is not in the histogram, so p99 measures how long serving
takes, not how long clients wait before giving up. Those exchanges show as
`outcome: aborted` in the access log. `_count` therefore equals
`zoxy_l7_responses` exactly, an identity the simulator asserts on every
seed.

### Access log

One JSON object per line: one per HTTP exchange (rejects, `503` sheds and
timeouts included) and one per L4 connection.

```json
"access_log": { "sink": "stdout" }
```

```json
{"time":"2026-07-31T09:14:22.481Z","kind":"http","outcome":"ok","client":"10.1.2.3:52344","method":"GET","host":"api.example.com","path":"/v1/items","status":200,"upstream_reused":true,"upstream_replayed":false,"duration_us":1873,"bytes_in":142,"bytes_out":4096,"cluster":"api","upstream":"10.0.0.7:8080"}
```

`outcome` tells you what `status` cannot: an origin answering `503` and
zoxy shedding a request with `503` share a status code but are opposite
events. Its values are `ok`, `rejected`, `shed`, `timed_out`,
`upstream_failed`, `aborted` and `closed`. `closed` is for L4 connections
and [tunnels](#tunnelled-upgrades-websocket), which end as a relay ends,
not as an exchange does.

A connection whose client presented a verified certificate
([mutual TLS](#requiring-a-client-certificate-mutual-tls)) adds
`"client_cert_sha256"`, the certificate's fingerprint. Lines without one
are unchanged.

Logging never blocks the event loop: a stalled sink costs dropped lines,
not latency. `zoxy_access_log_dropped` counts them exactly.

#### Logging request headers

By default, zoxy's line and the backend's line for the same request share
no key, so you cannot attribute a slow request to a hop. Naming headers to
log fixes that without changing a byte on the wire:

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

zoxy does not generate a request identifier. It is usually not the
outermost hop: a CDN, cloud load balancer or ingress in front almost always
sets `X-Request-ID` or `traceparent`, and that header reaches the origin
untouched, so logging it at both ends is all the join needs. The same
mechanism serves other uses: `User-Agent` for traffic analysis, a tenant
header for multi-tenant routing, the origin's `X-Cache` on the way out.

Names match case-insensitively and are logged in lowercase. A header that
did not arrive is omitted, not logged as null. A repeated header logs its
first value, the one zoxy itself read. Values are truncated at 256 bytes
with a trailing `...`. Up to 8 headers may be named across both lists.
`response_headers` is ignored for L4 lines, which have no response to read.
Without the lists, the line is unchanged.

The values are held per connection for the life of a request, so naming
headers costs memory proportional to `conn_slots`; the startup banner
prints it. A wider line also needs a staging buffer that can hold it. If
the buffer is too small, zoxy refuses to start instead of dropping every
line that carries headers.

`sink` is either `stdout` or `file`. `stdout` is the process's own standard
output, inherited, not opened, so it costs no file descriptor and has no
rotation of its own. `file` takes a `path`:

```json
"access_log": { "sink": "file", "path": "/var/log/zoxy/access.log" }
```

The file is created if absent and opened append-only at startup, never
truncated. That makes copy-truncate rotation (logrotate) safe: every write
lands at the current end of the file, wherever rotation just left it.

For move-based rotation, send `SIGHUP`, which reopens the configured path.
The new fd opens *first*: if the reopen cannot open its file, zoxy keeps
the old one and counts `zoxy_access_log_reopen_failed`, so a failed
rotation never destroys a working log. The swap happens only between
writes, never during one, so every line accepted after the signal lands in
the new file. `zoxy_access_log_reopened` counts successful rotations. A
successful reopen also repairs a sink that had broken, since what broke was
the fd the rotation just replaced. On a `stdout` sink, or with no log
configured, `SIGHUP` does nothing.

### Proxy-Status

The access log informs you; `Proxy-Status` informs the client. A `503` from
an overloaded zoxy and a `503` from a healthy zoxy relaying an overloaded
backend look the same on the wire, and only one of them is your problem.
Set `proxy_status` on an `http` listener and the pages zoxy renders
*itself* say which, in an RFC 9209 `Proxy-Status` field:

```json
{
    "bind": "0.0.0.0:80",
    "http": {
        "cluster": "web",
        "proxy_status": true
    }
}
```

```
HTTP/1.1 503 Service Unavailable
Content-Length: 0
Date: Wed, 01 Jan 2020 00:00:00 GMT
Server: zoxy
Proxy-Status: zoxy; error=connection_limit_reached
```

Four causes carry a token, and only those four:

| cause | status | `error=` |
|---|---|---|
| no route matched; no backend was dialled | `404` | `destination_not_found` |
| a [filter](#filters) refused on policy | the rule's status (`400`/`403`/`404`/`429`) | `http_request_denied` |
| a zoxy limit: any shed-ladder rung (slots, buffers, tunnels, per-endpoint in-flight) | `503` | `connection_limit_reached` |
| the backend was dialled and did not answer in time | `504` | `http_response_timeout` |

The token names the **cause, not the status**. A filter rejecting with
`404` and an empty routing table answering `404` share a status code but
give different advice: one means "ask someone else", the other means "you
were refused".

Everything else gets no field. A `400`, `413`, `414` or `431` that is the
request's own fault gets nothing, because RFC 9209's only fitting token
(`http_request_error`) restates the status line. A `502` is skipped for the
opposite reason: a refused dial, a reset mid-response and a malformed
origin head are three different 9209 causes that zoxy handles in one place,
so any single token would be right only by accident. A `Proxy-Status` from
zoxy therefore always says something the status line does not.

What it does not do:

- **No `next-hop`.** RFC 9209 allows naming the backend, but that would
  publish your topology to every client that can provoke an error. The
  endpoint is in the access log.
- **An upstream proxy's field survives.** `Proxy-Status` is a List, and
  zoxy sets it only on pages it renders itself. A relayed response carries
  whatever the hop before it wrote, unedited, so a chain reads back in
  order.
- **Configured error pages win.** A status you gave a body in
  `error_pages` is sent exactly as you wrote it, header included or not.
- **Forwarded responses are untouched.** An origin's own `503` is relayed
  as the origin wrote it.

> [!IMPORTANT]
> Off by default and set per listener, for the same reason as
> [`forwarded`](#x-forwarded-for): the field states which of *this
> proxy's* limits a caller hit. Inside a mesh that is a diagnostic; at an
> untrusted edge it is a capacity disclosure, and zoxy cannot tell from the
> inside which side of that line a listener is on.

## Under load

When a resource is exhausted, zoxy degrades the newest work, keeps serving
admitted work, and never allocates, blocks or dies. Every limit has a
defined answer instead of an unbounded queue.

- **Exhaustion sheds at a defined point.** No connection slot: the socket
  is closed with an RST, so the client learns immediately instead of timing
  out. No relay buffer or upstream slot for an HTTP request: a static `503`
  from constant memory. The connection is kept if the client's byte stream
  is still on a message boundary, because closing costs more than the work
  being shed.
- **A tunnel is refused before it costs anything.** No tunnel slot: the
  upgrade is answered `503` before the handshake is forwarded, so a refusal
  never spends an origin connection.
- **Watermarks before limits.** Each pool raises a pressure flag at 3/4
  occupancy and lowers it only once it has drained back to 1/2; the gap
  stops the flag flapping around a single threshold. While the flag is
  raised, idle timeouts are cut to a quarter, so quiet connections return
  their resources before the pool runs out.
- **Accept never pauses.** The kernel backlog stays drained even while
  shedding, so clients get an immediate signal instead of a timeout.
- **`SIGTERM` drains.** Listeners close, keep-alive is no longer honoured,
  in-flight work finishes under `drain_deadline_ms`, then the process exits
  0.
- **A stalled loop can exit instead of hanging.**
  `timeouts.loop_watchdog_ms` arms an `alarm(2)` that each tick the loop
  delivers pushes out, so a loop that stops delivering is ended by the
  kernel with exit **6** and one line on stderr. Off unless configured.
- **The budget is printed up front.** Startup prints the closed-form
  memory, file-descriptor and ring-op totals the process will never exceed,
  and asserts the fd count against `RLIMIT_NOFILE` before serving anything.

[DESIGN.md](DESIGN.md) §8 documents each rung and why it answers the way it
does.

## Further reading

- [DESIGN.md](DESIGN.md): the settled design, covering what has shipped and
  how it works. The bare `§` references in this document, in the source and
  in commit messages all point here.
- [TIGER_STYLE.md](TIGER_STYLE.md): the coding rules the tree is held to
  (static allocation only, bounded loops, assertion density,
  explicitly sized integers).
- [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md): measured findings,
  shelved experiments and open technical questions.
- [zoxy.io/config](https://zoxy.io/config/): every field, bound and default,
  rendered from the JSON Schema of the latest release.
