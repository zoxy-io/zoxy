# NixOS module for zoxy. Wired from the flake as `nixosModules.zoxy`; the flake
# passes `self` so the service can default to the flake's own package.
#
# Usage:
#   services.zoxy = {
#     enable = true;
#     settings = {
#       listen = "0.0.0.0:8080";
#       admin = "127.0.0.1:9901";
#       routes = [ { cluster = "origin"; } ];
#       clusters = [ { name = "origin"; endpoints = [ "127.0.0.1:9000" ]; } ];
#     };
#   };
self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.zoxy;
  jsonFormat = pkgs.formats.json { };

  # A caller may hand us a ready-made config file, otherwise we render one from
  # `settings` (the schema zoxy's JSON config expects — see zoxy.json).
  configFile =
    if cfg.configFile != null then cfg.configFile else jsonFormat.generate "zoxy.json" cfg.settings;
in
{
  options.services.zoxy = {
    enable = lib.mkEnableOption "the zoxy L7 edge proxy";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.zoxy;
      defaultText = lib.literalExpression "zoxy.packages.\${system}.zoxy";
      description = "The zoxy package to run.";
    };

    settings = lib.mkOption {
      type = jsonFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          listen = "0.0.0.0:8080";
          admin = "127.0.0.1:9901";
          routes = [ { cluster = "origin"; } ];
          clusters = [ { name = "origin"; endpoints = [ "127.0.0.1:9000" ]; } ];
        }
      '';
      description = ''
        zoxy configuration, serialized to JSON and passed as the config file.
        Ignored when {option}`services.zoxy.configFile` is set. See the project
        README for the full schema.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/etc/zoxy/zoxy.json";
      description = ''
        Path to a config file to use verbatim. Overrides
        {option}`services.zoxy.settings`. Useful when the config carries TLS
        material or is managed outside Nix.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the TCP ports in {option}`services.zoxy.ports` in the firewall.";
    };

    ports = lib.mkOption {
      type = lib.types.listOf lib.types.port;
      default = [ ];
      example = [ 8080 ];
      description = ''
        TCP ports to open when {option}`services.zoxy.openFirewall` is set.
        zoxy's listen ports live inside the config, so they cannot be derived
        automatically — list here whichever should be reachable.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.configFile != null || cfg.settings != { };
        message = "services.zoxy: set either `settings` or `configFile`.";
      }
    ];

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall cfg.ports;

    systemd.services.zoxy = {
      description = "zoxy L7 edge proxy";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} ${configFile}";
        Restart = "on-failure";
        RestartSec = 1;

        # Unprivileged, per-boot user; /run/zoxy is available for e.g. the
        # hot-restart handoff socket ("handoff": "/run/zoxy/handoff.sock").
        DynamicUser = true;
        RuntimeDirectory = "zoxy";
        RuntimeDirectoryMode = "0750";

        # Binding ports < 1024 needs this; harmless otherwise.
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];

        # A busy proxy: many fds, and io_uring may pin memory.
        LimitNOFILE = 1048576;
        LimitMEMLOCK = "infinity";

        # Sandboxing. io_uring is deliberately excluded from systemd's
        # @system-service set (security history), so it is allowed explicitly —
        # without it every worker's ring setup fails.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
        RestrictRealtime = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "io_uring_setup"
          "io_uring_enter"
          "io_uring_register"
        ];
      };
    };
  };
}
