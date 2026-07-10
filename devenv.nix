# Dev environment (https://devenv.sh): the pinned toolchain — zig 0.16 +
# zls, kcov (Linux, coverage), nginx (the Tier-1 bench origin, §9) and
# poop (Tier-0 hardware-counter A/B, Linux only). Activated automatically
# by `.envrc` via direnv, or manually with `devenv shell`.
{ pkgs, lib, ... }:
{
  packages =
    [
      pkgs.zig_0_16
      pkgs.zls
      pkgs.nginx
    ]
    ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
      pkgs.kcov
      pkgs.poop
    ];
}
