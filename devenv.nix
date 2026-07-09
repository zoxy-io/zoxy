# Dev environment (https://devenv.sh): the same pinned toolchain the flake
# dev shell carries — zig 0.16 + zls, kcov (Linux, for scripts/coverage.sh)
# and nghttp2's h2load (the bench load generator). Activated automatically
# by `.envrc` via direnv, or manually with `devenv shell`.
{ pkgs, lib, ... }:
{
  packages =
    [
      pkgs.zig_0_16
      pkgs.zls
    ]
    ++ lib.optional pkgs.stdenv.hostPlatform.isLinux pkgs.kcov;
}
