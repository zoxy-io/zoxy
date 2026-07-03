const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The "zoxy" module: everything under src/ rooted at root.zig, which
    // re-exports the public components and aggregates every module's tests.
    const mod = b.addModule("zoxy", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    const exe = b.addExecutable(.{
        .name = "zoxy",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            // Keep frame pointers even in release builds: `perf record
            // --call-graph fp` then works on the production binary, and the
            // cost is a register we can spare. (DWARF unwinding needs
            // permissions perf often lacks.)
            .omit_frame_pointer = false,
            .imports = &.{
                .{ .name = "zoxy", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    // A Zig test binary tests one module at a time, hence two: the "zoxy"
    // module (all library tests via root.zig) and the executable's root.
    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // The deterministic simulator: the real data path on the simulation IO
    // backend (src/sim.zig declares `zoxy_io = .simulation`). Debug/safe
    // builds only make sense here — the asserts are the test oracle.
    const sim_exe = b.addExecutable(.{
        .name = "sim",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sim.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_sim = b.addRunArtifact(sim_exe);
    if (b.args) |args| run_sim.addArgs(args);
    const sim_step = b.step("sim", "Run the deterministic simulator (args: [seed] [iterations])");
    sim_step.dependOn(&run_sim.step);
}
