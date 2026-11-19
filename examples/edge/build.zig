//! A dependent of zoxy (#417): a separate package building its own proxy
//! on the library, the way a downstream program would. It depends on the
//! repository's own tree by path; CI rebuilds it against a `zig fetch` of
//! a `git archive` of HEAD instead, which is exactly what a dependent
//! receives — so a file the library needs and the package leaves out
//! fails there rather than for a stranger.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zoxy_dependency = b.dependency("zoxy", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "zoxy-edge",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zoxy", .module = zoxy_dependency.module("zoxy") },
            },
        }),
    });
    b.installArtifact(exe);
}
