//! zio's process-spawn shim doesn't PATH-search a bare argv[0] the way the
//! default std.Io.Threaded backend does — confirmed empirically: spawning
//! "nginx" unqualified returns error.FileNotFound, while its full
//! /nix/store/.../bin/nginx path spawns fine. zio's own processSpawnImpl is
//! marked `TODO: implement using our own posix_spawn/fork+exec wrapper`, so
//! this is a known gap in the pinned commit, not an environment problem
//! here. Resolve every external tool this harness shells out to against
//! $PATH ourselves before spawning, following the same bare-name convention
//! std.process.spawn documents (a path is bare when it has no '/').

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

pub fn resolve(
    arena: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    name: []const u8,
) ![]const u8 {
    assert(name.len > 0);
    if (std.mem.indexOfScalar(u8, name, '/') != null) return name;
    const path_env = environ.getPosix("PATH") orelse return error.FileNotFound;
    assert(path_env.len > 0);
    var dirs = std.mem.splitScalar(u8, path_env, ':');
    while (dirs.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = try std.fs.path.join(arena, &.{ dir, name });
        Io.Dir.accessAbsolute(io, candidate, .{ .execute = true }) catch continue;
        assert(std.mem.endsWith(u8, candidate, name));
        return candidate;
    }
    return error.FileNotFound;
}
