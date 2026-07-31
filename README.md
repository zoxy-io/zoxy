# zoxy

[![CI](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml/badge.svg)](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/zoxy-io/zoxy/badge.svg?branch=main)](https://coveralls.io/github/zoxy-io/zoxy?branch=main)
[![Project stage: Experimental][project-stage-badge: Experimental]][project-stage-page]
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A zero-allocation L4/L7 edge proxy in Zig.

zoxy is built on the [TigerBeetle](https://tigerbeetle.com) I/O model — completion-based
with caller-owned completions — and follows [TigerStyle](docs/TIGER_STYLE.md):
**all memory is reserved at startup, and the request-serving path allocates nothing.**

## Usage

The built binary takes exactly one argument — the path to a JSON config:

```sh
zoxy <config.json>   # start the proxy
zoxy --help          # usage summary (-h)
zoxy --version       # print the version (-V)
```

Signals: `SIGTERM`/`SIGINT` drain in-flight connections and exit 0;
`SIGUSR1` dumps counters to stdout.

A minimal config — an L4 listener forwarding to one origin
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
        "drain_deadline_ms": 10000,
        "max_lifetime_ms": 0
    },
    "access_log": { "sink": "stdout" }
}
```

The full config format — every field, enum, and numeric bound — is
described by the JSON Schema shipped as a release asset (also emitted
locally by `zig build schema`).

### Sticky sessions

A cluster picks endpoints with `p2c` (default), `rr`, or `hash` — the last
sending a given client to a given backend every time, for services that
keep per-user state:

```json
"clusters": {
    "api": {
        "endpoints": ["10.0.0.1:8080", "10.0.0.2:8080"],
        "pick": "hash",
        "hash": { "key": "source_ip" }
    }
}
```

`hash` is **rendezvous hashing over the healthy endpoints**, and it keeps
no table. That matters because zoxy scales out as independent processes
behind SO_REUSEPORT, and the kernel spreads one client's connections
across them by hashing the 4-tuple — so a per-process stickiness table
(HAProxy's stick-table model) would be consulted by processes that never
saw the client. Being a pure function of the key and the healthy set,
every process agrees without sharing anything.

When a backend is ejected by a health check, only *its* clients move; the
rest are untouched, and they all return when it recovers. `source_ip`
hashes all four bytes of an IPv4 address and the /64 prefix of an IPv6
one, so stickiness survives IPv6 privacy-address rotation.

The tradeoff is inherent to hashing on client address: NAT hides many
clients behind one address, and a single heavy client cannot be split
across backends. Use `p2c` where even load matters more than stickiness.

### Access log

The optional `access_log` block writes one JSON object per line to
stdout — one per HTTP exchange (rejects, `503` sheds and timeouts
included) and one per L4 connection:

```json
{"time":"2026-07-31T09:14:22.481Z","kind":"http","outcome":"ok","client":"10.1.2.3:52344","method":"GET","host":"api.example.com","path":"/v1/items","status":200,"upstream_reused":true,"upstream_replayed":false,"duration_us":1873,"bytes_in":142,"bytes_out":4096,"cluster":"api","upstream":"10.0.0.7:8080"}
```

`outcome` is the field `status` cannot give you: an origin answering
`503` and zoxy shedding a request with `503` are the same three digits
and opposite events. It reads `ok` (the origin answered), `rejected`,
`shed`, `timed_out`, `upstream_failed`, `aborted`, or — for L4 — `closed`.

The unit is an *admitted* connection. A connection refused at the
accept gate — no conn slot, no relay buffer, or a drain already under
way — never gets a line; those are counted by `zoxy_shed_conn_slots`,
`zoxy_shed_relay_buffers` and `zoxy_shed_draining` instead, because at
that point there is nothing to report from and a shed has to stay cheap.

Rotation is the operator's: pipe stdout wherever this process's output
already goes. Logging never blocks the event loop, so a sink that stalls
costs dropped lines rather than latency; `zoxy_access_log_dropped` counts
them exactly.

## Development

### Requirements

- **Zig 0.16** (pinned by [devenv](devenv.nix): `zig_0_16` + `zls`).

With [devenv](https://devenv.sh) `.envrc` activates the same shell automatically on `cd`):

```sh
devenv shell           # zig 0.16, zls, kcov
zig build              # build zig-out/bin/zoxy
zig build test         # run the test suite
zig build sim -- 0 500 # deterministic simulator: [seed] [iterations]
zig build run          # run using ./zoxy.json
zig build bench        # loopback bands: direct vs zoxy vs haproxy
```

> [!NOTE]
> The bench harness is always built ReleaseFast, but it measures the
> `zig-out/bin/zoxy` you last built — and plain `zig build` produces a
> Debug binary. Run `zig build -Doptimize=ReleaseFast` first before
> quoting numbers against haproxy.

## License

[MIT](LICENSE) © 2026 Vsevolod Strukchinsky

[project-stage-badge: Experimental]: https://img.shields.io/badge/Project%20Stage-Experimental-yellow.svg
[project-stage-page]: https://blog.pother.ca/project-stages/
