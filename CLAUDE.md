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
  simulation, and the Tier-0.5 live gate. A sim failure prints its seed;
  `zig build sim -- <seed>` replays the exact schedule. The live gate
  (`zig build smoke` alone) runs the real binary against a real origin
  and asserts equalities on what it wrote; a failing one prints the
  proxy's own output from `.zig-cache/zoxy-smoke/`.
- `zig fmt --check src scripts smoke build.zig build.zig.zon` — the format
  gate (a PostToolUse hook auto-formats files as they are edited).
- `zig build bench` (Tier 1: zrk against an nginx origin) runs at merge,
  not per change — compare bands across runs, never single numbers.

## Policies

- Dependencies are audited forks pinned by content hash in build.zig.zon
  (libxev, hparse, ztls). A pin moves only after re-audit. libxev and
  hparse are pure Zig; ztls is the one C surface — a Zig TLS 1.3 protocol
  layer over libcrypto primitives (DESIGN.md §4's scoped exception), and
  the C binding lives inside it, so `@cImport` stays lint-forbidden here.
- Boundaries (lint-enforced): raw syscalls and the `xev` import live only
  under `src/io/`; `hparse` is imported only by `src/http/parser.zig`;
  `ztls` only under `src/tls/`.
- Zero allocation after startup. The memory, fd, and ring budgets are
  closed-form functions of `src/constants.zig` and the loaded config.
  Where a budget is a property of one constant it is comptime-asserted;
  where it is a property of a combination the config chooses — listener
  count, cluster and endpoint counts — it is rejected at startup instead
  (`cqFillFits`, `ensureFdBudget`). Config shape is the operator's to
  size; see DESIGN.md §5.
- Workflow: small slices, one commit per slice, descriptive commit
  messages (§ references welcome). Push and open PRs only when asked.
- Before committing a slice, run the `tiger-style-reviewer` agent on the
  diff.
