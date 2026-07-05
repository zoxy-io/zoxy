# zoxy package: a static, hermetic Zig build.
#
# The only thing zoxy fetches from the network is the vendored OpenSSL *source*
# (third_party/openssl builds it from source — see third_party/openssl/README.md
# and CLAUDE.md). Nix builds have no network, so the fetch is split out into a
# fixed-output derivation (`zigDepsCache`) that mirrors what `zig fetch` would
# put in the global cache; the real build then runs offline against it with
# `zig build --system`.
{
  lib,
  stdenv,
  stdenvNoCC,
  zig_0_16,
  cacert,
}:

let
  # The single URL dependency in the tree, declared in
  # third_party/openssl/build.zig.zon. Keep both fields in sync with it.
  # `zig fetch <url>` prints the .hash; that hash is the p/<hash> cache key.
  opensslSource = {
    url = "git+https://github.com/openssl/openssl?ref=openssl-3.3.2#fb7fab9fa6f4869eaa8fbb97e0d593159f03ffe4";
    zigHash = "N-V-__8AAB4K3gN87j2XVRV4lWznICWpINb_g79iOtl4Cl30";
  };

  # Only the files the build actually reads — keeps the source hash (and thus
  # rebuilds) independent of docs/, bench/, README, CI config, etc.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../build.zig
      ../build.zig.zon
      ../src
      ../third_party
      ../LICENSE
    ];
  };

  # Fixed-output derivation: populate a Zig package directory (the layout
  # `zig build --system` expects: one extracted <hash>/ subtree per package)
  # by fetching every URL dependency, then extracting the cached tarballs.
  #
  # `zig build --fetch` does NOT descend into a *path* dependency's manifest
  # (third_party/openssl is a path dep), so we fetch its URL dep explicitly.
  zigDepsCache = stdenvNoCC.mkDerivation {
    name = "zoxy-zig-deps";
    nativeBuildInputs = [
      zig_0_16
      cacert
    ];
    dontUnpack = true;
    dontConfigure = true;

    buildPhase = ''
      runHook preBuild
      export HOME="$TMPDIR"
      export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-global"
      # This zig's `zig fetch` insists on a build.zig in the current directory
      # even when fetching a bare URL — give it an empty one to satisfy that.
      : > build.zig
      zig fetch "${opensslSource.url}"
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      # Each cached tarball's internal root is its own <hash>/ directory, so
      # extracting at $out yields $out/<hash>/... — exactly the --system layout.
      for tarball in "$ZIG_GLOBAL_CACHE_DIR"/p/*.tar.gz; do
        tar -xf "$tarball" -C "$out"
      done
      test -d "$out/${opensslSource.zigHash}"
      runHook postInstall
    '';

    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    # Recompute after bumping the OpenSSL ref: set to lib.fakeHash, run
    # `nix build .#zoxy`, and copy the "got:" value it reports.
    outputHash = "sha256-OSNJqk2ZycD8HOaR4aSrxaya9+D5732RbWVeGTALMx0=";
  };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "zoxy";
  version = "0.0.0"; # tracks build.zig.zon .version

  inherit src;

  nativeBuildInputs = [ zig_0_16 ];

  # Drive `zig build` from an explicit buildPhase rather than zig_0_16's setup
  # hook: the hook can't express `--system <depsdir>`, which is what makes the
  # build hermetic. Opt out of every hook phase so the manual phase is the only
  # thing that runs. `zig build --prefix` installs; there is no ./configure.
  dontUseZigConfigure = true;
  dontUseZigBuild = true;
  dontUseZigCheck = true;
  dontUseZigInstall = true;
  dontConfigure = true;
  dontInstall = true;

  buildPhase = ''
    runHook preBuild
    export HOME="$TMPDIR"
    export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-global"
    mkdir -p "$ZIG_GLOBAL_CACHE_DIR"

    # --system disables fetching and resolves deps from the FOD; -Dcpu=baseline
    # keeps the binary portable across the target arch (no build-host tuning).
    zig build \
      --system "${finalAttrs.passthru.zigDepsCache}" \
      --cache-dir "$TMPDIR/zig-local" \
      --prefix "$out" \
      -Doptimize=ReleaseSafe \
      -Dcpu=baseline

    runHook postBuild
  '';

  # build.zig also installs the standalone libopenssl.a and its headers (for
  # coverage builds that bypass the build graph). OpenSSL is already statically
  # linked into the zoxy binary, so keep only bin/ in the package output.
  postBuild = ''
    rm -rf "$out/lib" "$out/include"
  '';

  passthru = { inherit zigDepsCache; };

  meta = {
    description = "Zero-allocation L7 edge proxy in Zig (io_uring, thread-per-core)";
    homepage = "https://github.com/zoxy-io/zoxy";
    license = lib.licenses.mit;
    mainProgram = "zoxy";
    platforms = lib.platforms.linux;
  };
})
