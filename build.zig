const std = @import("std");

/// Refuse to build the vendored C against a libc Zig could not find.
///
/// Everything here links libcrypto, and libcrypto is C: for a native target
/// Zig locates the host's libc headers and CRT objects by running the system
/// C compiler (`cc -E -Wp,-v -xc /dev/null`). With no `cc` on PATH that
/// detection fails — and the build DOES NOT. It reports its steps as
/// succeeding and emits binaries that die in `_start`, before `main`, on a
/// call through a null pointer. Every test in the suite "fails" as one
/// SIGSEGV with no output, which reads exactly like a bug in the code.
///
/// That cost a day of chasing a phantom, so the condition gets a message
/// instead of a mystery. Attached to libcrypto rather than to a top-level
/// step because that is the choke point every artifact goes through, and
/// because failing here leaves `zig build --help` and the steps that touch
/// no C still working.
fn guardNativeLibc(b: *std.Build, target: std.Build.ResolvedTarget, libcrypto: *std.Build.Step.Compile) void {
    // Only native builds probe the host. A cross target uses the libc Zig
    // ships for it and needs nothing from this machine.
    if (!target.query.isNative()) return;
    // An explicit libc description answers the same question `cc` would.
    if (b.graph.environ_map.get("ZIG_LIBC") != null) return;
    if (b.findProgram(&.{ "cc", "gcc", "clang" }, &.{})) |_| return else |_| {}

    libcrypto.step.dependOn(&b.addFail(
        \\no C compiler on PATH, so Zig cannot detect this machine's libc.
        \\
        \\Everything here links a libcrypto built from vendored C, and without
        \\a detected libc that link silently produces binaries which segfault
        \\in _start before main — a whole test suite dying as one SIGSEGV with
        \\no output.
        \\
        \\Build inside the pinned toolchain: `devenv shell`, or `direnv allow`
        \\once and let it load. Cross-compiling (-Dtarget=...) needs none of
        \\this, and ZIG_LIBC overrides the check if you know better.
    ).step);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The version string is single-sourced from build.zig.zon and handed to
    // the binary through a build-options module, so `zoxy --version` and the
    // package metadata can never drift apart.
    const zoxy_version = @import("build.zig.zon").version;
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", zoxy_version);
    build_options.addOption([]const u8, "build_id", resolveBuildId(b));

    // Which libxev backend `XevIo` builds against, for reproducing
    // readiness-model behaviour on a box that has io_uring (#203).
    //
    // Linux picks io_uring and macOS picks kqueue, and those are two
    // different models: io_uring *completes* operations, kqueue reports
    // *readiness* and the backend performs a synchronous syscall. Every
    // assumption zoxy makes about when an op is delivered is therefore
    // exercised on one model per platform — and the defects that live in
    // the other one surface only on a shared macOS runner, twice in
    // thirteen runs, with no way to reproduce them locally.
    //
    // epoll is the readiness model on Linux. It is not kqueue, so a green
    // run here does not clear macOS; what it buys is that a *failure*
    // here is reproducible in seconds instead of by pushing and waiting.
    const io_backend = b.option(
        IoBackend,
        "io-backend",
        "libxev backend: platform default, or epoll to exercise the readiness model on Linux",
    ) orelse .default;
    // Its own options module rather than a field on `build_options`: that
    // one is imported by `src/main.zig`, and a module reached from two
    // import paths at once is an error ("file exists in modules ... and
    // ...0"). This is the only thing the library module needs from the
    // build, so it travels alone.
    const io_options = b.addOptions();
    io_options.addOption(IoBackend, "backend", io_backend);

    // Release builds link libcrypto statically; everything else links the
    // shared one its shell provides. See `static_link` for why the
    // distinction is not cosmetic, and for why the *choice of libcrypto*
    // is made through pkg-config rather than here.
    static_link = b.option(
        bool,
        "static",
        "link the executable statically, libcrypto included (release artifacts)",
    ) orelse false;

    // libxev is pinned by content hash to the zoxy-io fork's
    // zoxy-ring-flags branch: the audited upstream snapshot plus the
    // setup-flags commit (DESIGN.md §4); see build.zig.zon. The pin moves
    // only after re-audit.
    const xev_dependency = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });
    const xev_module = xev_dependency.module("xev");

    // hparse — the hardened head-parser fork — is pinned by content hash
    // to an audited zoxy-io/hparse commit (DESIGN.md §7); the pin moves
    // only after re-audit. Only src/http/parser.zig may import it (lint-
    // enforced): that wrapper owns every strictness and framing decision.
    const hparse_dependency = b.dependency("hparse", .{
        .target = target,
        .optimize = optimize,
    });
    const hparse_module = hparse_dependency.module("hparse");

    // ztls — the TLS 1.3 engine (DESIGN.md §4) — is pinned by content hash
    // to the audited zoxy-io fork; the pin moves only after re-audit. Only
    // src/tls/ may import it (lint-enforced). It is a Zig protocol layer
    // over libcrypto primitives, which is why every build below links
    // libcrypto: the §4 crypto-primitives exception, and the codebase's one
    // C surface.
    // libcrypto, built by Zig for the *target* rather than resolved out of the
    // build machine's nix store. See build.zig.zon for why it is OpenSSL and
    // why this fork; the short version is that BoringSSL has no
    // `CRYPTO_set_mem_functions` and `tls/libcrypto_heap.zig` cannot start
    // without it.
    //
    // Two of them, because the ReleaseSafe twin below builds its own ztls at a
    // different optimize mode and the archive has to match.
    const openssl_dependency = b.dependency("openssl", .{
        .target = target,
        .optimize = optimize,
    });
    const libcrypto = openssl_dependency.artifact("openssl");
    guardNativeLibc(b, target, libcrypto);
    // Zig's C sanitizers off for the vendored C, in every mode — #283, and
    // not a preference. `sanitize_c` defaults to `.full` in Debug and
    // `.trap` in ReleaseSafe, and only the `.full` arm passes
    // `-fno-sanitize=function` (Zig's src/Compilation.zig), whose comment
    // there calls the pattern it flags "very common, and well-defined" and
    // whose handler `lib/zig/ubsan_rt.zig` leaves commented out for the same
    // reason. So the one check Zig deliberately disables is armed *only* in
    // the mode release.yml ships, as a `ud1` trap: 17242 of them in the
    // archive, 3499 of those the function check, and the first one a `tls`
    // listener reaches is `OPENSSL_sk_pop_free` calling its `free_func`
    // through a cast pointer — the idiom the check exists to flag and
    // OpenSSL has always used. v0.6.0 SIGILLs there at key load, before
    // serving anything, on every target it ships.
    //
    // `.off` rather than `.full`, and rather than dropping the one check:
    // libcrypto is built without UBSan everywhere else (0.5.1 shipped
    // nixpkgs' gcc-built one), the other 13743 traps are a crash surface on
    // attacker-reachable paths rather than a diagnostic anyone acts on, and
    // one setting for every mode is what stops the shipped artifact from
    // differing from the tested one again — which is what this bug *was*,
    // not a detail of it. Costs no Zig safety: the package gives this module
    // no root source file, so it is C and nothing else. `smoke-release`
    // below is the gate for the class.
    libcrypto.root_module.sanitize_c = .off;
    const openssl_fast_dependency = b.dependency("openssl", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseSafe,
    });
    const libcrypto_fast = openssl_fast_dependency.artifact("openssl");
    // Same reason, and this is the archive that matters most: the twin
    // linking it is the one built the way the release is.
    libcrypto_fast.root_module.sanitize_c = .off;

    // ztls asks the linker for `-lcrypto` by name and this package emits
    // `libopenssl.a`. Linking the artifact resolves every symbol, but the
    // linker must still *find* a file of that name or it fails before getting
    // there — so publish a copy under it and point the search path at it. A
    // copy rather than renaming the artifact, because the artifact's name is
    // the package's API.
    const crypto_alias = b.addWriteFiles();
    _ = crypto_alias.addCopyFile(libcrypto.getEmittedBin(), "libcrypto.a");
    const crypto_alias_dir = crypto_alias.getDirectory();
    const crypto_fast_alias = b.addWriteFiles();
    _ = crypto_fast_alias.addCopyFile(libcrypto_fast.getEmittedBin(), "libcrypto.a");
    const crypto_fast_alias_dir = crypto_fast_alias.getDirectory();

    const ztls_dependency = b.dependency("ztls", .{
        .target = target,
        .optimize = optimize,
        // We supply libcrypto, so pkg-config must not. Left on, it injects the
        // system OpenSSL's include path ahead of ours and the C import dies on
        // typedef collisions — but only where pkg-config knows about OpenSSL,
        // so it passes CI and breaks on a laptop.
        .@"crypto-pkg-config" = false,
    });
    const ztls_module = ztls_dependency.module("ztls");
    ztls_module.linkLibrary(libcrypto);

    const zoxy_module = b.addModule("zoxy", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xev", .module = xev_module },
            .{ .name = "hparse", .module = hparse_module },
            .{ .name = "ztls", .module = ztls_module },
        },
    });
    linkLibcrypto(zoxy_module, libcrypto, crypto_alias_dir);
    // `src/io/XevIo.zig` reads the backend choice from here.
    zoxy_module.addOptions("io_options", io_options);
    // The shipped example config is embedded so tests and the fuzz corpus
    // stay in sync with the file users actually copy.
    zoxy_module.addAnonymousImport("example_config", .{
        .root_source_file = b.path("config/example.json"),
    });

    const exe = b.addExecutable(.{
        .name = "zoxy",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zoxy", .module = zoxy_module },
            },
        }),
        // A release binary is handed to strangers, so it needs nothing on
        // the box it lands on. Without this the musl target still asks
        // for a musl loader, which stock Linux does not have — the
        // artifact links correctly and then refuses to start, which is
        // exactly what the 0.2.0 tag produced.
        .linkage = if (static_link) .static else null,
    });
    // src/main.zig reads its version from this module (also added to the
    // ReleaseSafe `release_zoxy` below, the other build of that same source).
    exe.root_module.addOptions("build_options", build_options);
    b.installArtifact(exe);

    const run_command = b.addRunArtifact(exe);
    run_command.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_command.addArgs(args);
    }
    const run_step = b.step("run", "Run zoxy");
    run_step.dependOn(&run_command.step);

    // The four test gates of DESIGN.md §9 exist as steps from the first
    // commit; a step whose harness has not landed yet is inert and says so
    // in its description. A feature without its gate is not done.
    const lint_exe = b.addExecutable(.{
        .name = "zoxy-lint",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/lint.zig"),
            .target = b.graph.host,
        }),
    });

    const module_tests = b.addRunArtifact(b.addTest(.{ .root_module = zoxy_module }));
    const exe_tests = b.addRunArtifact(b.addTest(.{ .root_module = exe.root_module }));
    const lint_tests = b.addRunArtifact(b.addTest(.{ .root_module = lint_exe.root_module }));
    const test_step = b.step("test", "Run unit tests (--fuzz adds the fuzz gate)");
    test_step.dependOn(&module_tests.step);
    test_step.dependOn(&exe_tests.step);
    test_step.dependOn(&lint_tests.step);

    // The fixed libcrypto heap (§4, §5): its own step, and the one TLS
    // test that cannot ride the main test binary. The allocation hooks
    // must be installed before libcrypto's *first* allocation, which only
    // a fresh process whose first libcrypto touch is the install can
    // promise — the test binary loads credentials long before it. Every
    // other TLS test runs under `zig build test`.
    const tls_heap_proof_module = b.createModule(.{
        .root_source_file = b.path("src/tls_heap_proof.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ztls", .module = ztls_module },
        },
    });
    linkLibcrypto(tls_heap_proof_module, libcrypto, crypto_alias_dir);
    const tls_heap_proof_tests = b.addRunArtifact(b.addTest(.{
        .root_module = tls_heap_proof_module,
    }));
    const tls_heap_proof_step = b.step(
        "tls-heap-proof",
        "Prove a TLS handshake runs on the fixed libcrypto heap (§4)",
    );
    tls_heap_proof_step.dependOn(&tls_heap_proof_tests.step);

    const sim_exe = b.addExecutable(.{
        .name = "zoxy-sim",
        .root_module = b.createModule(.{
            .root_source_file = b.path("sim/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zoxy", .module = zoxy_module },
            },
        }),
    });
    const sim_run = b.addRunArtifact(sim_exe);
    if (b.args) |args| {
        sim_run.addArgs(args);
    }
    const sim_step = b.step("sim", "Deterministic simulation: -- [seed] [iterations] | fuzz");
    sim_step.dependOn(&sim_run.step);

    // §5 config schema: a standalone tool renders the JSON Schema derived
    // from the config definitions (constants + the source enums), and
    // `zig build schema` installs it as zig-out/config.schema.json for the
    // release workflow to ship as an asset. Deliberately not wired into
    // `ci`: the emitter's own tests run under `test`; the file itself is a
    // release-only artifact, so nothing here needs to gate every change.
    const schema_exe = b.addExecutable(.{
        .name = "zoxy-schema",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/schema.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zoxy", .module = zoxy_module },
            },
        }),
    });
    const schema_run = b.addRunArtifact(schema_exe);
    const schema_output = schema_run.captureStdOut(.{ .basename = "config.schema.json" });
    const schema_install = b.addInstallFile(schema_output, "config.schema.json");
    const schema_step = b.step("schema", "Emit the config JSON Schema to zig-out/config.schema.json");
    schema_step.dependOn(&schema_install.step);

    // §9 Tier 0.5: the live gate — the shipped binary, on a real kernel,
    // against a real origin, on every change. It drives the *default*
    // build (the one `zig build` installs) rather than the ReleaseSafe
    // one the bench uses: its verdicts are correctness equalities on real
    // output, so what a Debug build's extra checks add is worth more here
    // than the shipped binary's code generation, which Tier 1 is the gate
    // for. That reasoning holds for what this leg *tests* and did not
    // survive #283 as a reason to test only this one — the shipped build
    // has failure modes a Debug build cannot reproduce, so `smoke-release`
    // below runs the same harness against the ReleaseSafe twin. The origin
    // and the load generator both live inside the harness (smoke/), so the
    // step needs nothing from the dev shell.
    const smoke_exe = b.addExecutable(.{
        .name = "zoxy-smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("smoke/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    // The TLS fixture, handed in rather than embedded: `@embedFile` cannot
    // escape its module root and the harness is its own module. The
    // `example_config` import above is the same shape. It stays a
    // *config* input — the harness writes both files into its work
    // directory and points the proxy at them, exactly as an operator
    // would — so nothing here links ztls or libcrypto (§4, §9).
    smoke_exe.root_module.addAnonymousImport("tls_cert_pem", .{
        .root_source_file = b.path("src/tls/testdata/cert.pem"),
    });
    smoke_exe.root_module.addAnonymousImport("tls_key_pem", .{
        .root_source_file = b.path("src/tls/testdata/key.pem"),
    });
    const smoke_run = b.addRunArtifact(smoke_exe);
    smoke_run.addArg("--zoxy");
    smoke_run.addArtifactArg(exe);
    if (b.args) |args| {
        smoke_run.addArgs(args);
    }
    const smoke_step = b.step("smoke", "Tier-0.5 live gate: the real binary against a live origin");
    smoke_step.dependOn(&smoke_run.step);

    // §9 Tier 1: the loopback band harness embeds zrk (pinned by hash) as
    // its load generator — that role stays ReleaseFast regardless of what
    // zoxy itself ships as; it isn't the thing under test, it just needs
    // to generate load fast enough not to be the bottleneck.
    const zrk_dependency = b.dependency("zrk", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    });
    // zrk embeds its load off a zio (io_uring) runtime rather than the
    // default std.Io.Threaded backend, so the harness must build its own
    // zio.Runtime to drive zrk's runner (bench/run.zig, bench/profile.zig).
    const zio_dependency = b.dependency("zio", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    });
    // The zoxy under test is ReleaseSafe — matching the shipped binary
    // (release.yml) — whatever -Doptimize says for the default install.
    // ReleaseSafe still selects the LLVM backend (Zig 0.16's default for
    // every release mode, not just ReleaseFast), so hparse's SIMD paths
    // are emitted; only a Debug/self-hosted zoxy scalarizes them and
    // would benchmark the wrong code. hparse_fast_dependency keeps its
    // name (distinguishing it from the module-tests' Debug hparse) even
    // though it's no longer the *fastest* build mode.
    const hparse_fast_dependency = b.dependency("hparse", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseSafe,
    });
    const ztls_fast_dependency = b.dependency("ztls", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseSafe,
        .@"crypto-pkg-config" = false,
    });
    ztls_fast_dependency.module("ztls").linkLibrary(libcrypto_fast);
    const zoxy_fast_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .imports = &.{
            .{ .name = "xev", .module = xev_module },
            .{ .name = "hparse", .module = hparse_fast_dependency.module("hparse") },
            .{ .name = "ztls", .module = ztls_fast_dependency.module("ztls") },
        },
    });
    linkLibcrypto(zoxy_fast_module, libcrypto_fast, crypto_fast_alias_dir);
    // The ReleaseSafe twin of the library module needs the same backend
    // choice: it is the same `src/root.zig`, so `XevIo` asks it the same
    // question.
    zoxy_fast_module.addOptions("io_options", io_options);
    const release_zoxy = b.addExecutable(.{
        .name = "zoxy-release",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .imports = &.{
                .{ .name = "zoxy", .module = zoxy_fast_module },
            },
        }),
    });
    release_zoxy.root_module.addOptions("build_options", build_options);

    // The same Tier-0.5 harness against the ReleaseSafe twin: the gate #283
    // needed and did not have. `smoke` above drives the *default* build,
    // which is Debug for every developer and every CI run, and the
    // `sanitize_c` comment on `libcrypto` above is one worked example of
    // what that leaves unwatched — a defect visible only in the mode the
    // artifact is built in, which no amount of *scenario* coverage on the
    // Debug leg could reach. So this leg runs the same requests, TLS
    // included, and what it adds is the build configuration release.yml
    // ships. Cheap: the micro binaries already make `ci` compile the
    // ReleaseSafe libcrypto, so this is a link and a run on top.
    //
    // Ordered after the Debug leg rather than beside it: both harness runs
    // are the same program and it keeps its work directory at a fixed path
    // (`.zig-cache/zoxy-smoke`), so left free to run in parallel they would
    // write each other's config and logs.
    const smoke_release_run = b.addRunArtifact(smoke_exe);
    smoke_release_run.addArg("--zoxy");
    smoke_release_run.addArtifactArg(release_zoxy);
    if (b.args) |args| {
        smoke_release_run.addArgs(args);
    }
    smoke_release_run.step.dependOn(&smoke_run.step);
    const smoke_release_step = b.step(
        "smoke-release",
        "Tier-0.5 live gate against the ReleaseSafe twin (the shipped build's configuration)",
    );
    smoke_release_step.dependOn(&smoke_release_run.step);

    // The harness itself (drives zrk against release_zoxy over the wire)
    // stays ReleaseFast for the same reason zrk/zio do above.
    const bench_exe = b.addExecutable(.{
        .name = "zoxy-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/run.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zrk", .module = zrk_dependency.module("zrk") },
                .{ .name = "zio", .module = zio_dependency.module("zio") },
            },
        }),
    });
    const bench_run = b.addRunArtifact(bench_exe);
    // Drive the ReleaseSafe zoxy, not the default-optimize install
    // artifact — a Debug zoxy scalarizes hparse and benchmarks the wrong
    // binary (§9). bench/run.zig takes it via --zoxy.
    bench_run.addArg("--zoxy");
    bench_run.addArtifactArg(release_zoxy);
    if (b.args) |args| {
        bench_run.addArgs(args);
    }
    const bench_step = b.step(
        "bench",
        "Tier-1 loopback bands: -- [--rate N] [--seconds N] [--origin host:port]",
    );
    bench_step.dependOn(&bench_run.step);

    // §9 Tier 0: micro binaries for manual poop A/B; installed, never run
    // in CI (counter deltas on shared runners are noise). They reuse the
    // ReleaseSafe `zoxy_fast_module` defined above so what gets measured
    // (SIMD parser included) matches the shipped binary, checks and all.
    const micro_step = b.step("bench-micro", "Build Tier-0 micro binaries for poop A/B");
    for ([_][]const u8{ "pool_acquire_release", "relay_chunking", "l7_head_pipeline", "conn_touch_scaling" }) |micro_name| {
        const micro_exe = b.addExecutable(.{
            .name = b.fmt("zoxy-bench-{s}", .{micro_name}),
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("bench/micro/{s}.zig", .{micro_name})),
                .target = target,
                .optimize = .ReleaseSafe,
                .imports = &.{
                    .{ .name = "zoxy", .module = zoxy_fast_module },
                },
            }),
        });
        micro_step.dependOn(&b.addInstallArtifact(micro_exe, .{}).step);
    }

    // §9 Tier 0: pinned perf + flamegraph of zoxy under load. The zoxy
    // under test is ReleaseSafe (shipped-binary fidelity); the harness
    // (bench/profile.zig) — which spawns nginx + zoxy, pins zoxy to one
    // core so the PMU and LBR call-graph stay on a single core type,
    // drives zrk load, and folds perf into a flamegraph — stays
    // ReleaseFast, same reasoning as bench_exe above. Linux-only —
    // perf/flamegraph/nginx live in the dev shell. Tooling in Zig, not
    // bash (TIGER_STYLE §Tooling).
    const profile_harness = b.addExecutable(.{
        .name = "zoxy-profile-harness",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/profile.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zrk", .module = zrk_dependency.module("zrk") },
                .{ .name = "zio", .module = zio_dependency.module("zio") },
                // For `constants` alone: the harness sizes the conn-slot
                // limit it writes into zoxy's config against the compiled
                // ceiling. Duplicating that number here would track a
                // *lowered* ceiling loudly (the config is rejected at
                // startup) but a *raised* one silently — a profile aimed at
                // the new maximum would cap below it and say nothing.
                //
                // `src/constants.zig` directly rather than the whole `zoxy`
                // module, which imports ztls: this executable also imports
                // zrk, which reaches the same ztls through ztls_std, and the
                // two instantiations differ in optimize mode — ReleaseSafe
                // for the zoxy under test, ReleaseFast for the load
                // generator. Zig treats those as two modules rooted at one
                // file and refuses to compile:
                //
                //     error: file exists in modules 'ztls' and 'ztls0'
                //     note: files must belong to only one module
                //
                // Importing a leaf that depends on nothing but `std` keeps
                // both of those optimize choices, which are deliberate, and
                // takes the shared C dependency out of the question. It only
                // became possible to hit once libcrypto stopped being one
                // system-wide shared object and became a per-configuration
                // artifact (#279).
                .{ .name = "zoxy_constants", .module = b.createModule(.{
                    .root_source_file = b.path("src/constants.zig"),
                    .target = target,
                    .optimize = .ReleaseFast,
                }) },
            },
        }),
    });
    const profile_run = b.addRunArtifact(profile_harness);
    profile_run.addArtifactArg(release_zoxy);
    if (b.args) |args| profile_run.addArgs(args);
    const profile_step = b.step(
        "profile",
        "Pinned perf + flamegraph of zoxy under load (Linux; needs the dev shell)",
    );
    profile_step.dependOn(&profile_run.step);

    const lint_run = b.addRunArtifact(lint_exe);
    lint_run.addDirectoryArg(b.path("src"));
    const lint_step = b.step("lint", "Mechanical TIGER_STYLE rules over src/: import boundaries, loop bounds, function length");
    lint_step.dependOn(&lint_run.step);

    // The per-change gates. The Tier-1 `bench` step is deliberately
    // excluded (DESIGN.md §9): its verdict is a band comparison across
    // runs, run at merge against a real origin, not a blind shared-runner
    // pass. Tier 0.5 is not excluded on those grounds and belongs here
    // for the opposite reason — its verdicts are equalities on real
    // output, which a shared runner cannot move, and it is the only gate
    // in this list that runs the binary at all.
    const ci_step = b.step("ci", "Per-change gates: test + lint + sim + smoke (bench runs at merge)");
    ci_step.dependOn(test_step);
    // A separate binary, but not a separate decision: the zero-allocation
    // promise (§5) is unbacked with a C library underneath unless this
    // passes, so it gates every change like the rest.
    ci_step.dependOn(tls_heap_proof_step);
    ci_step.dependOn(lint_step);
    ci_step.dependOn(sim_step);
    // Every platform. On its first CI run the gate found that the macOS
    // leg answered *nothing* to its first L7 request — accepted, then
    // closed with no response and no diagnostic (#184). The cause was
    // `nowWallNs` reading CLOCK_REALTIME through the Linux-kernel ABI on a
    // libc-linked build, so a garbage timespec tripped an assert on the
    // first logged request; the read now goes through `posix.system` like
    // every other syscall here. This unconditional line is that fix's
    // acceptance test — kqueue's failure modes only surface at runtime.
    ci_step.dependOn(smoke_step);
    // And once more against the configuration that ships. This list ran
    // green on the change that gave zoxy a Zig-built libcrypto (#279) and
    // on every change after it, while the release those changes produced
    // had no working TLS at all (#283) — because every gate above builds
    // at `-Doptimize`'s default and the artifact does not.
    ci_step.dependOn(smoke_release_step);
    // Compile — never run — every measurement binary. Their verdicts are
    // human-read A/Bs and profiles, so running them here would buy nothing
    // and cost minutes; but they call the same internal APIs the proxy
    // does, and nothing else in the gate does. Left ungated,
    // `l7_head_pipeline` silently stopped compiling when
    // `renderRequestHead` grew two parameters and stayed broken across four
    // merged slices — discovered only when someone next reached for it,
    // which is the worst time to find out a measurement tool is dead. A
    // build is enough to catch that, and it is the cheapest thing that is.
    ci_step.dependOn(micro_step);
    ci_step.dependOn(&bench_exe.step);
    ci_step.dependOn(&profile_harness.step);

    // Line coverage via kcov (Linux-only, in the dev shell): the unit-test
    // binary plus a simulator sweep, merged — the simulator reaches error
    // paths and race interleavings unit tests cannot.
    //
    // Gotcha: kcov 43 cannot read the DWARF line tables the self-hosted
    // x86_64 Debug backend emits (0 lines found), so both binaries are built
    // through the LLVM backend (use_llvm = true). The build graph wires the
    // module imports (xev, example_config) that a hand-rolled `zig test`
    // could not resolve.
    const cov_tests = b.addTest(.{
        .name = "coverage-tests",
        .root_module = zoxy_module,
        .use_llvm = true,
    });
    const cov_sim = b.addExecutable(.{
        .name = "coverage-sim",
        .use_llvm = true,
        .root_module = b.createModule(.{
            .root_source_file = b.path("sim/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zoxy", .module = zoxy_module },
            },
        }),
    });

    // Absolute src root: kcov filters recorded files by this prefix, and the
    // cobertura patch below rewrites it back to the repo-relative "src".
    const src_abs = b.path("src").getPath(b);
    const include_arg = b.fmt("--include-path={s}", .{src_abs});

    const kcov_tests = b.addSystemCommand(&.{"kcov"});
    kcov_tests.addArg(include_arg);
    const tests_cov = kcov_tests.addOutputDirectoryArg("cov-tests");
    kcov_tests.addArtifactArg(cov_tests);

    const kcov_sim = b.addSystemCommand(&.{"kcov"});
    kcov_sim.addArg(include_arg);
    const sim_cov = kcov_sim.addOutputDirectoryArg("cov-sim");
    kcov_sim.addArtifactArg(cov_sim);
    kcov_sim.addArgs(&.{ "0", "150" });

    const kcov_merge = b.addSystemCommand(&.{ "kcov", "--merge" });
    const merged_cov = kcov_merge.addOutputDirectoryArg("cov-merged");
    kcov_merge.addDirectoryArg(tests_cov);
    kcov_merge.addDirectoryArg(sim_cov);

    // kcov writes an absolute <source> root; Coveralls resolves each file by
    // joining source + filename before fetching from GitHub, so the root must
    // be repo-relative or every file reads "source not available".
    const patch_cov = b.addSystemCommand(&.{
        "sed",
        "-i",
        // kcov appends a trailing slash to the source root; `/*` absorbs it.
        b.fmt("s|<source>{s}/*</source>|<source>src</source>|", .{src_abs}),
    });
    patch_cov.addFileArg(merged_cov.path(b, "kcov-merged/cobertura.xml"));

    const install_cov = b.addInstallDirectory(.{
        .source_dir = merged_cov,
        .install_dir = .{ .custom = "coverage" },
        .install_subdir = "",
    });
    install_cov.step.dependOn(&patch_cov.step);

    const cov_step = b.step(
        "coverage",
        "Line coverage via kcov (Linux): unit tests + sim, merged to zig-out/coverage",
    );
    cov_step.dependOn(&install_cov.step);
}

/// Which build this binary is, beyond its release version.
///
/// A release binary's version already names one commit — the tag points at
/// exactly one — so this is empty there and `zoxy --version` stays the bare
/// `zoxy 0.0.7`. What it exists for is every *other* build: one made from
/// `main` five commits later reports the same version string as the release
/// unless something says otherwise, which turns a bug report's "0.0.7" into
/// a claim that is not true. `git describe` answers exactly that question —
/// `0.0.7-5-gabc1234`, and `-dirty` when the tree carries uncommitted
/// changes, which is otherwise unanswerable from a binary.
///
/// `-Dbuild-id=...` overrides, for a builder that has the answer but no
/// `.git` — a source tarball, or a CI checkout too shallow to describe.
/// Absent both, empty: an unknown build says nothing rather than guessing.
///
/// This is the one place the build shells out *unconditionally*. The
/// `coverage` step runs `kcov` and `sed`, but through `addSystemCommand`,
/// so those fire only when that step is asked for; this runs during
/// `build()` itself and so on every `zig build`, `test`, `sim` and `ci`.
/// That is a `git` invocation's worth of cost per invocation, and it makes
/// the *identifier* non-hermetic — deliberately, because a local build
/// that cannot say what it is is the problem being solved. Nothing about
/// the produced code depends on it, and a failure is not one: no git, no
/// repository, or a killed process all land in the `catch` below and
/// report nothing rather than breaking the build.
fn resolveBuildId(b: *std.Build) []const u8 {
    if (b.option([]const u8, "build-id", "Build identifier, e.g. git describe output")) |given| {
        return given;
    }
    // `runAllowFail` reports a non-zero exit as an error and only then
    // writes `exit_code`, so the catch is the whole failure path — reading
    // the code on success would read whatever the variable held. It is
    // initialized anyway rather than left `undefined`, because a future
    // reader tempted to check it should find a number rather than garbage.
    var exit_code: u8 = 0;
    const described = b.runAllowFail(
        &.{ "git", "describe", "--tags", "--always", "--dirty" },
        &exit_code,
        .ignore,
    ) catch return "";
    return std.mem.trim(u8, described, " \t\r\n");
}

/// ztls's C surface: the protocol layer is Zig, the primitives are
/// libcrypto's (DESIGN.md §4's crypto-primitives exception). Every module
/// that reaches `src/tls/` needs the archive and a search path that makes
/// ztls's own `-lcrypto` resolvable; they always travel together, so they
/// are set in one place rather than repeated per module.
///
/// Statically, always, and built for the target rather than found on the
/// build machine. This used to be `linkSystemLibrary("crypto")` with
/// pkg-config deciding which libcrypto that meant, which cost twice over.
/// A *release* binary handed to strangers must not want a musl-ABI
/// `libcrypto.so.3` at runtime — that shipped unnoticed the moment TLS
/// termination (#125) gave zoxy a C dependency. And pkg-config answers only
/// for the host, so every other target failed to link, which is why
/// release.yml builds natively on one runner per target and why
/// x86_64-macos has been absent since 0.2.0.
fn linkLibcrypto(
    module: *std.Build.Module,
    lib: *std.Build.Step.Compile,
    alias_dir: std.Build.LazyPath,
) void {
    module.link_libc = true;
    module.addLibraryPath(alias_dir);
    module.linkLibrary(lib);
}

/// Set from `-Dstatic` in `build`, read where the executable is declared.
/// A file global because that is the only other place it is needed and a
/// parameter would have to travel through code that does not care.
///
/// This no longer decides anything about libcrypto. It used to matter that
/// `-Dstatic` and pkg-config agreed, because pkg-config was the only lever
/// that reached **ztls's** own `linkSystemLibrary("crypto")` inside a
/// pinned dependency. `linkLibcrypto` now hands both halves the same
/// Zig-built archive, so libcrypto is static on every build and
/// `PKG_CONFIG_PATH` reaches nothing.
var static_link: bool = false;

/// The `-Dio-backend` choice. `default` is what the platform picks
/// (io_uring on Linux, kqueue on macOS); `epoll` overrides it to the
/// readiness model on Linux — see the option's own comment for why that
/// is worth being able to ask for.
const IoBackend = enum { default, epoll };
