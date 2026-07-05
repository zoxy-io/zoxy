{
  description = "zoxy — a zero-allocation L7 edge proxy in Zig (Linux only)";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;

      # zoxy is Linux-only (io_uring + raw linux syscalls, see CLAUDE.md).
      # The package/app/NixOS module therefore only exist on Linux; the dev
      # shell additionally covers darwin so the code can be edited there.
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
      # nix build .#zoxy / nix run .#zoxy
      packages = forSystems linuxSystems (pkgs: rec {
        zoxy = pkgs.callPackage ./nix/package.nix { };
        default = zoxy;
      });

      # A pkgs overlay so downstream flakes can `pkgs.zoxy` after adding it.
      overlays.default = final: _prev: {
        zoxy = final.callPackage ./nix/package.nix { };
      };

      # NixOS service: `services.zoxy.enable = true;`
      nixosModules.zoxy = import ./nix/module.nix self;
      nixosModules.default = self.nixosModules.zoxy;

      apps = forSystems linuxSystems (pkgs: rec {
        zoxy = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.zoxy}/bin/zoxy";
          meta.description = "Run zoxy: zoxy <config.json>";
        };
        default = zoxy;
      });

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

      # `nix flake check` boots a VM: nginx origin behind zoxy, proxied request
      # must return the origin body. Also proves the systemd unit starts — i.e.
      # the io_uring syscalls survive the sandbox's SystemCallFilter.
      checks = forSystems linuxSystems (pkgs: {
        nixos-module = pkgs.testers.nixosTest {
          name = "zoxy-nixos-module";
          nodes.machine =
            { pkgs, ... }:
            {
              imports = [ self.nixosModules.zoxy ];

              services.nginx = {
                enable = true;
                virtualHosts."origin" = {
                  listen = [
                    {
                      addr = "127.0.0.1";
                      port = 9000;
                    }
                  ];
                  locations."/".extraConfig = "return 200 'hello from origin';";
                };
              };

              services.zoxy = {
                enable = true;
                settings = {
                  listen = "127.0.0.1:8080";
                  admin = "127.0.0.1:9901";
                  routes = [ { cluster = "origin"; } ];
                  clusters = [
                    {
                      name = "origin";
                      endpoints = [ "127.0.0.1:9000" ];
                    }
                  ];
                };
              };

              environment.systemPackages = [ pkgs.curl ];
            };

          testScript = ''
            machine.wait_for_unit("nginx.service")
            machine.wait_for_unit("zoxy.service")
            machine.wait_for_open_port(9000)
            machine.wait_for_open_port(8080)
            machine.succeed("curl -sf http://127.0.0.1:8080/ | grep 'hello from origin'")
            machine.succeed("curl -sf http://127.0.0.1:9901/metrics")
          '';
        };
      });

      formatter = forSystems allSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
