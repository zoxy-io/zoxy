# zoxy

Bullet-proof L4/L7 proxy in Zig 0.16 (toolchain pinned via devenv/Nix;
direnv activates the shell). Read before writing code:

- [docs/DESIGN.md](docs/DESIGN.md) — the settled design: what's shipped
  and how it works. Bare § references in code and commits point here.
  Planned features are tracked as GitHub issues, not here.
- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) — enforced coding rules:
  static allocation only, ≤ 70-line functions, assertion density ≥ 2,
  bounded loops, explicitly-sized integers, naming conventions.
- [docs/IMPLEMENTATION_NOTES.md](docs/IMPLEMENTATION_NOTES.md) — measured
  findings, shelved experiments, and open technical questions; do not
  re-litigate settled verdicts.

## Gates — run before every commit

- `zig build ci` — unit tests + fuzz corpus, boundary lint, deterministic
  simulation. A sim failure prints its seed; `zig build sim -- <seed>`
  replays the exact schedule.
- `zig fmt --check src scripts build.zig build.zig.zon` — the format gate
  (a PostToolUse hook auto-formats files as they are edited).
- `zig build bench` (Tier 1: zrk against an nginx origin) runs at merge,
  not per change — compare bands across runs, never single numbers.

## Policies

- Dependencies are audited pure-Zig forks pinned by content hash in
  build.zig.zon (libxev, hparse). A pin moves only after re-audit. No
  C FFI — `@cImport` is lint-forbidden.
- Boundaries (lint-enforced): raw syscalls and the `xev` import live only
  under `src/io/`; `hparse` is imported only by `src/http/parser.zig`.
- Zero allocation after startup. Every limit is a named constant in
  `src/constants.zig`; the memory, fd, and ring budgets are closed-form
  functions of those constants, comptime-asserted.
- Workflow: small slices, one commit per slice, descriptive commit
  messages (§ references welcome). Push and open PRs only when asked.
- Before committing a slice, run the `tiger-style-reviewer` agent on the
  diff.
