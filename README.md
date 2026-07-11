# zoxy

[![CI](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml/badge.svg)](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/zoxy-io/zoxy/badge.svg?branch=main)](https://coveralls.io/github/zoxy-io/zoxy?branch=main)
[![Project stage: Experimental][project-stage-badge: Experimental]][project-stage-page]
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A zero-allocation L4/L7 edge proxy in Zig.

zoxy is built on the [TigerBeetle](https://tigerbeetle.com) I/O model — completion-based
with caller-owned completions — and follows [TigerStyle](docs/TIGER_STYLE.md):
**all memory is reserved at startup, and the request-serving path allocates nothing.**

## Requirements

- **Zig 0.16** (pinned by [devenv](devenv.nix): `zig_0_16` + `zls`).

## Build & run

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