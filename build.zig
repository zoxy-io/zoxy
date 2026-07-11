const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // libxev is vendored by content hash at an audited commit (DESIGN.md §4);
    // the pin moves only after re-audit.
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
}
