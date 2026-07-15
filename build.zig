const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // libxev is pinned by content hash to the floatdrop fork's
    // zoxy-ring-flags branch: the audited upstream snapshot plus the
    // setup-flags commit (DESIGN.md §4); see build.zig.zon. The pin moves
    // only after re-audit.
    const xev_dependency = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });
    const xev_module = xev_dependency.module("xev");

    const zoxy_module = b.addModule("zoxy", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xev", .module = xev_module },
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

    // §9 Tier 1: the loopback band harness embeds zrk (pinned by hash)
    // and always measures ReleaseFast, whatever -Doptimize says.
    const zrk_dependency = b.dependency("zrk", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    });
    const bench_exe = b.addExecutable(.{
        .name = "zoxy-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/run.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zrk", .module = zrk_dependency.module("zrk") },
            },
        }),
    });
    const bench_run = b.addRunArtifact(bench_exe);
    bench_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        bench_run.addArgs(args);
    }
    const bench_step = b.step(
        "bench",
        "Tier-1 loopback bands: -- [--rate N] [--seconds N] [--origin host:port]",
    );
    bench_step.dependOn(&bench_run.step);

    // §9 Tier 0: micro binaries for manual poop A/B; installed, never run
    // in CI (counter deltas on shared runners are noise).
    const zoxy_fast_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{
            .{ .name = "xev", .module = xev_module },
        },
    });
    const micro_step = b.step("bench-micro", "Build Tier-0 micro binaries for poop A/B");
    for ([_][]const u8{ "pool_acquire_release", "relay_chunking" }) |micro_name| {
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
    const profile_zoxy = b.addExecutable(.{
        .name = "zoxy-profile",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zoxy", .module = zoxy_fast_module },
            },
        }),
    });
    const profile_harness = b.addExecutable(.{
        .name = "zoxy-profile-harness",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/profile.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zrk", .module = zrk_dependency.module("zrk") },
            },
        }),
    });
    const profile_run = b.addRunArtifact(profile_harness);
    profile_run.addArtifactArg(profile_zoxy);
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

    // The deterministic per-change gates. The Tier-1 `bench` step is
    // deliberately excluded (DESIGN.md §9): its verdict is a band
    // comparison across runs, run at merge against a real origin, not a
    // blind shared-runner pass.
    const ci_step = b.step("ci", "Per-change gates: test + lint + sim (bench runs at merge)");
    ci_step.dependOn(test_step);
    ci_step.dependOn(lint_step);
    ci_step.dependOn(sim_step);

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
