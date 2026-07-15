# Dev environment (https://devenv.sh): the pinned toolchain. Only two packages
# are used by CI — zig (every job) and kcov (the Linux `zig build coverage`
# job) — so everything else is developer/bench/profile tooling gated out of the
# CI closure: zls (editor LSP), nginx + haproxy (Tier-1 bench origins, §9), poop
# (Tier-0 hardware-counter A/B) and perf + flamegraph (the pinned
# `zig build profile`). CI runs none of them (`zig fmt`, `zig build`,
# `zig build ci`, `zig build coverage` only), and keeping its closure cache-only
# both trims fetch time and dodges the uncached-source-bootstrap flake that
# pkgs.linuxPackages_latest.perf triggered (the `ldexpl.c is not valid`
# coverage failure). Activated automatically by `.envrc` via direnv, or manually
# with `devenv shell`.
{ pkgs, lib, ... }:
let
  # GitHub Actions sets CI=true; a CI checkout is always fresh, so this
  # re-evaluates every run and never serves a stale (dev-tool-included) shell.
  in_ci = (builtins.getEnv "CI") == "true";
in
{
  packages =
    [
      pkgs.zig_0_16
    ]
    # kcov drives the Linux `zig build coverage` job.
    ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
      pkgs.kcov
    ]
    # Developer/bench/profile tooling — no CI command runs it.
    ++ lib.optionals (!in_ci) (
      [
        pkgs.zls
        pkgs.nginx
        pkgs.haproxy
      ]
      ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
        pkgs.poop
        pkgs.linuxPackages_latest.perf
        pkgs.flamegraph
      ]
    );
}
