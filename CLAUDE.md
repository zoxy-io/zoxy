# zoxy

Bullet-proof L4/L7 proxy in Zig 0.16 (toolchain pinned via devenv/Nix;
direnv activates the shell). Read before writing code:

- [docs/DESIGN.md](docs/DESIGN.md) — the settled design. Bare § references
  in code and commits point here.
- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) — enforced coding rules:
  static allocation only, ≤ 70-line functions, assertion density ≥ 2,
  bounded loops, explicitly-sized integers, naming conventions.
- [docs/PLANS.md](docs/PLANS.md) — phasing and deferred work.
- [docs/IMPLEMENTATION_NOTES.md](docs/IMPLEMENTATION_NOTES.md) — measured
  findings and shelved experiments; do not re-litigate settled verdicts.

## Gates — run before every commit

- `zig build ci` — unit tests + fuzz corpus, boundary lint, deterministic
  simulation. A sim failure prints its seed; `zig build sim -- <seed>`
  replays the exact schedule.
- `zig fmt --check src scripts build.zig build.zig.zon` — the format gate
  (a PostToolUse hook auto-formats files as they are edited).
- `zig build bench` (Tier 1: zrk against an nginx origin) runs at merge,
  not per change — compare bands across runs, never single numbers.

## Policies

- Dependencies are audited forks pinned by content hash in build.zig.zon:
  libxev and hparse (pure Zig), ztls (Zig TLS protocol layer over
  libcrypto — the one C surface, per the §4 crypto-primitives exception).
  A pin moves only after re-audit. No C FFI in zoxy's own tree —
  `@cImport` is lint-forbidden; C bindings live only inside ztls.
- Boundaries (lint-enforced): raw syscalls and the `xev` import live only
  under `src/io/`; `hparse` is imported only by `src/http/parser.zig`;
  `ztls` only under `src/tls/` (convention until the lint learns it —
  a Phase-3a slice).
- Zero allocation after startup. Every limit is a named constant in
  `src/constants.zig`; the memory, fd, and ring budgets are closed-form
  functions of those constants, comptime-asserted.
- Workflow: small slices, one commit per slice, descriptive commit
  messages (§ references welcome). Push and open PRs only when asked.
- Before committing a slice, run the `tiger-style-reviewer` agent on the
  diff.
