const std = @import("std");

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

    const zoxy_module = b.addModule("zoxy", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xev", .module = xev_module },
            .{ .name = "hparse", .module = hparse_module },
        },
    });
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
    });
    // src/main.zig reads its version from this module (also added to the
    // ReleaseFast `release_zoxy` below, the other build of that same source).
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
    // build (the one `zig build` installs) rather than the ReleaseFast
    // one the bench uses: its verdicts are correctness equalities on real
    // output, so what a Debug build's extra checks add is worth more here
    // than the shipped binary's code generation, which Tier 1 is the gate
    // for. The origin and the load generator both live inside the harness
    // (smoke/), so the step needs nothing from the dev shell.
    const smoke_exe = b.addExecutable(.{
        .name = "zoxy-smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("smoke/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const smoke_run = b.addRunArtifact(smoke_exe);
    smoke_run.addArg("--zoxy");
    smoke_run.addArtifactArg(exe);
    if (b.args) |args| {
        smoke_run.addArgs(args);
    }
    const smoke_step = b.step("smoke", "Tier-0.5 live gate: the real binary against a live origin");
    smoke_step.dependOn(&smoke_run.step);

    // §9 Tier 1: the loopback band harness embeds zrk (pinned by hash),
    // and the zoxy under test is a ReleaseFast build — matching the
    // shipped binary — whatever -Doptimize says. ReleaseFast selects the
    // LLVM backend (Zig 0.16's default for release modes), so hparse's
    // SIMD paths are emitted; a Debug/self-hosted zoxy scalarizes them
    // and would benchmark the wrong code.
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
    // The ReleaseFast zoxy shared by the bench and the profiler, with its
    // own ReleaseFast hparse instance (SIMD, not scalarized).
    const hparse_fast_dependency = b.dependency("hparse", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    });
    const zoxy_fast_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{
            .{ .name = "xev", .module = xev_module },
            .{ .name = "hparse", .module = hparse_fast_dependency.module("hparse") },
        },
    });
    const release_zoxy = b.addExecutable(.{
        .name = "zoxy-release",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zoxy", .module = zoxy_fast_module },
            },
        }),
    });
    release_zoxy.root_module.addOptions("build_options", build_options);
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
    // Drive the ReleaseFast zoxy, not the default-optimize install
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
    // ReleaseFast `zoxy_fast_module` defined above so the SIMD parser is
    // what gets measured.
    const micro_step = b.step("bench-micro", "Build Tier-0 micro binaries for poop A/B");
    for ([_][]const u8{ "pool_acquire_release", "relay_chunking", "l7_head_pipeline", "conn_touch_scaling" }) |micro_name| {
        const micro_exe = b.addExecutable(.{
            .name = b.fmt("zoxy-bench-{s}", .{micro_name}),
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("bench/micro/{s}.zig", .{micro_name})),
                .target = target,
                .optimize = .ReleaseFast,
                .imports = &.{
                    .{ .name = "zoxy", .module = zoxy_fast_module },
                },
            }),
        });
        micro_step.dependOn(&b.addInstallArtifact(micro_exe, .{}).step);
    }

    // §9 Tier 0: pinned perf + flamegraph of zoxy under load. Two ReleaseFast
    // binaries — the zoxy under test (shipped-binary fidelity) and the harness
    // (bench/profile.zig) that spawns nginx + zoxy, pins zoxy to one core so
    // the PMU and LBR call-graph stay on a single core type, drives zrk load,
    // and folds perf into a flamegraph. Linux-only — perf/flamegraph/nginx
    // live in the dev shell. Tooling in Zig, not bash (TIGER_STYLE §Tooling).
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
                .{ .name = "zoxy", .module = zoxy_fast_module },
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
    const lint_step = b.step("lint", "fd-boundary lint: raw syscalls only under src/io/");
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
    ci_step.dependOn(lint_step);
    ci_step.dependOn(sim_step);
    // Linux only, for now. On its first CI run the gate found that the
    // macOS leg answers *nothing* to its first L7 request — accepted,
    // then closed with no response and no diagnostic (#184). That is a
    // finding, not a flake, and fixing zoxy's kqueue path is not this
    // step's job; `zig build smoke` still runs everywhere, which is how
    // that issue gets worked, and putting this line back is its
    // acceptance test.
    if (target.result.os.tag == .linux) {
        ci_step.dependOn(smoke_step);
    }
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
