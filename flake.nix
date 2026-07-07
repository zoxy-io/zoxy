{
  description = "zoxy — a zero-allocation L7 edge proxy in Zig (Linux only)";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      inherit (nixpkgs) lib;

      # zoxy is Linux-only (io_uring + raw linux syscalls, see CLAUDE.md), but
      # the dev shell also covers darwin so the code can be edited there.
      linuxSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      allSystems = linuxSystems ++ [
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forSystems = systems: func: lib.genAttrs systems (system: func nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forSystems allSystems (pkgs: {
        default = pkgs.mkShell {
          packages =
            with pkgs;
            [
              zig_0_16
              zls
              nghttp2 # provides h2load, the bench load generator
            ]
            ++ lib.optional pkgs.stdenv.hostPlatform.isLinux pkgs.kcov;
        };
      });

      formatter = forSystems allSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
