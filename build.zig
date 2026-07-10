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

    const lint_run = b.addRunArtifact(lint_exe);
    lint_run.addDirectoryArg(b.path("src"));
    const lint_step = b.step("lint", "fd-boundary lint: raw syscalls only under src/io/");
    lint_step.dependOn(&lint_run.step);
    _ = b.step("bench", "Tier-1 loopback benchmark (inert until slice 11)");

    const ci_step = b.step("ci", "Everything CI gates on: test + lint + sim");
    ci_step.dependOn(test_step);
    ci_step.dependOn(lint_step);
    ci_step.dependOn(sim_step);
}
