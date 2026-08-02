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
zoxy config.json
```

A minimal config — one L4 listener forwarding to one origin:

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
what you start with. [`config/example.json`](config/example.json) is the
same listener with health checks and the access log turned on, and
[docs/README.md](docs/README.md) documents every block.

## Documentation

- [**docs/README.md**](docs/README.md) — the manual: running the binary,
  every config block, what zoxy exposes while it runs, and how it behaves
  when a resource runs out.
- [docs/DESIGN.md](docs/DESIGN.md) — the settled design: what is shipped and
  how it works. The bare `§` references in the source and in commit messages
  point here.
- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) — the coding rules the tree is
  held to.
- [docs/IMPLEMENTATION_NOTES.md](docs/IMPLEMENTATION_NOTES.md) — measured
  findings, shelved experiments and open technical questions.
- [zoxy.io/config](https://zoxy.io/config/) — every configuration field,
  bound and default, rendered from the JSON Schema of the latest release.

## Benchmarks

[**zoxy-io/benchmark**](https://github.com/zoxy-io/benchmark) runs unattended
every night and publishes to
[zoxy-io.github.io/benchmark](https://zoxy-io.github.io/benchmark/). It
compares zoxy against **HAProxy**, **Nginx**, **Pingora** and **Envoy** as HTTP/1.1
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
zig build ci                    # the per-change gate: tests + lint + simulation + smoke
zig build test                  # unit tests
zig build sim -- 0 500          # deterministic simulator: [seed] [iterations]
zig build smoke                 # live gate: the real binary against a real origin
zig build schema                # emit zig-out/config.schema.json
zig build run -- config/example.json
zig build bench                 # loopback bands: direct vs zoxy vs haproxy
```

Correctness rests on a deterministic simulator: the serving path is written
against an I/O seam, so a seeded adversarial backend runs the *real* code
against virtual sockets and a virtual clock — partial reads down to one byte,
resets at every point in every exchange, delayed and black-holed connects. A
failing seed prints itself and replays exactly.

Beside it, a live gate runs the actual binary against an actual origin on every
change, in under a second, and asserts equalities on what it wrote: N requests
produce exactly N access-log lines, the counters scraped off `/metrics` reconcile
with each other and with the log, memory does not move across two identical load
passes, and SIGTERM drains cleanly. It is there because a virtual clock cannot
catch a bug whose only symptom is a wrong *rate*.

> [!NOTE]
> The bench harness is always built ReleaseFast, but it measures the
> `zig-out/bin/zoxy` you last built — and plain `zig build` produces a
> Debug binary. Run `zig build -Doptimize=ReleaseFast` first before
> quoting numbers against haproxy.

## License

[MIT](LICENSE) © 2026 Vsevolod Strukchinsky

[project-stage-badge: Experimental]: https://img.shields.io/badge/Project%20Stage-Experimental-yellow.svg
[project-stage-page]: https://blog.pother.ca/project-stages/
