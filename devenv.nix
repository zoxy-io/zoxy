# Dev environment (https://devenv.sh): the pinned local toolchain. Activated
# automatically by `.envrc` via direnv, or manually with `devenv shell`.
#
# CI does not use it. GitHub Actions installs Zig with mlugg/setup-zig and
# kcov from Ubuntu's archive (.github/workflows/ci.yml says why). The one
# thing the two must agree on is the compiler: build.zig.zon's
# `minimum_zig_version` is CI's pin, and it must name the release `zig_0_17`
# resolves to in devenv.lock — a lock bump that moves zig moves it too.
#
# Beyond zig: zls (editor LSP), kcov (`zig build coverage`, Linux), nginx +
# haproxy (Tier-1 bench origins, §9), poop (Tier-0 hardware-counter A/B) and
# perf + flamegraph (the pinned `zig build profile`).
{ pkgs, lib, ... }:
{
  packages =
    [
      pkgs.zig_0_17
      # OpenSSL headers and libcrypto. No `zig build` step reads them any
      # more: every build links the libcrypto Zig compiles from the vendored
      # openssl package (build.zig's `linkLibcrypto`, #279).
      pkgs.openssl.dev
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
