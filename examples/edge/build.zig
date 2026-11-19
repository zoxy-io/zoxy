//! A dependent of zoxy (#417): a separate package building its own proxy
//! on the library, the way a downstream program would. It depends on the
//! repository's own tree by path; CI rebuilds it against a `zig fetch` of
//! a `git archive` of HEAD instead, which is exactly what a dependent
//! receives — so a file the library needs and the package leaves out
//! fails there rather than for a stranger.
//!
//! - `zig build` — the `zoxy-edge` binary;
//! - `zig build test` — the build's extensions under the simulator
//!   (`zoxy.testing`), held to the zero-allocation gate and a replayed
//!   seed;
//! - `zig build smoke` — the binary on real sockets (`XevIo`, Linux)
//!   against live origins, drained by SIGTERM.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zoxy_dependency = b.dependency("zoxy", .{
        .target = target,
        .optimize = optimize,
    });
    const zoxy_module = zoxy_dependency.module("zoxy");

    const exe = b.addExecutable(.{
        .name = "zoxy-edge",
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

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/edge_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zoxy", .module = zoxy_module },
            },
        }),
    });
    const test_step = b.step("test", "zoxy-edge under the simulator: the zero-allocation gate and a replayed seed");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const smoke = b.addExecutable(.{
        .name = "zoxy-edge-smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("smoke/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const smoke_run = b.addRunArtifact(smoke);
    smoke_run.addArtifactArg(exe);
    // Where the proxy's own output goes, read back only on a failure.
    _ = smoke_run.addOutputFileArg("zoxy-edge-smoke.log");
    // A live run is its own point: never cached, and its verdict shown.
    smoke_run.has_side_effects = true;
    smoke_run.stdio = .inherit;
    const smoke_step = b.step("smoke", "zoxy-edge on real sockets (XevIo, Linux) against live origins");
    smoke_step.dependOn(&smoke_run.step);
}
