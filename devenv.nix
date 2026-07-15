# Dev environment (https://devenv.sh): the pinned toolchain — zig 0.16 +
# zls, kcov (Linux, coverage), nginx (the Tier-1 bench origin, §9),
# haproxy (the Tier-1 state-of-the-art reference proxy, §9), poop
# (Tier-0 hardware-counter A/B) and perf + flamegraph for the pinned
# `zig build profile` (all Linux only). Activated automatically by
# `.envrc` via direnv, or manually with `devenv shell`.
{ pkgs, lib, ... }:
{
  packages =
    [
      pkgs.zig_0_16
      pkgs.zls
      pkgs.nginx
      pkgs.haproxy
    ]
    ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
      pkgs.kcov
      pkgs.poop
      pkgs.linuxPackages_latest.perf
      pkgs.flamegraph
    ];
}
