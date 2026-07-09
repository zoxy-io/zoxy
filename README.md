# zoxy

[![CI](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml/badge.svg)](https://github.com/zoxy-io/zoxy/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/zoxy-io/zoxy/badge.svg?branch=main)](https://coveralls.io/github/zoxy-io/zoxy?branch=main)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A zero-allocation L4/L7 edge proxy in Zig.

zoxy is built on the [TigerBeetle](https://tigerbeetle.com) I/O model — completion-based
`io_uring` with caller-owned completions — and follows [TigerStyle](docs/TIGER_STYLE.md):
**all memory is reserved at startup, and the request-serving path allocates nothing.**

> **Status: experimental

## Requirements

- **Zig 0.16** (pinned by [devenv](devenv.nix) and the [Nix dev shell](flake.nix):
  `zig_0_16` + `zls`).
- **Linux with `io_uring`** (kernel 5.11+).
- Optional: the `tls` kernel module (`modprobe tls`) for kTLS offload — without it,
  TLS connections transparently stay on the userspace relay.

## Build & run

With [devenv](https://devenv.sh) or Nix (recommended — with direnv, `.envrc`
activates the same shell automatically on `cd`):

```sh
devenv shell           # zig 0.16, zls, kcov (or: nix develop)
zig build              # build zig-out/bin/zoxy
zig build test         # run the test suite
zig build sim -- 0 500 # deterministic simulator: [seed] [iterations]
zig build run          # run using ./zoxy.json
```

## License

[MIT](LICENSE) © 2026 Vsevolod Strukchinsky
