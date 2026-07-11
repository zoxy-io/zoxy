//! Build-time lint for the fd boundary of DESIGN.md §4/§9: raw syscall
//! surfaces (`std.posix`, `std.os`, `os.linux`) and the `xev` import may be
//! named only under `src/io/`, with an explicit allowlist for `main.zig`
//! startup work (rlimits, sigaction). `@cImport` is forbidden everywhere —
//! the codebase has no C-FFI dependency (§4). Runs as `zig build lint`
//! with the source root as its single argument.

const std = @import("std");

const assert = std.debug.assert;

/// Bounded walk: a source tree past this size is itself a lint failure —
/// raise deliberately if the project legitimately grows.
const files_max: u32 = 512;
const file_bytes_max: u32 = 1024 * 1024;

const syscall_needles = [_][]const u8{ "std.posix", "std.os", "os.linux" };

/// The only `std.posix.` members main.zig may name (rlimits + sigaction);
/// everything else — sockets, files, pipes — stays behind the Io seam.
/// These are matched as fully-qualified `std.posix.<name>` occurrences,
/// not bare words, so a comment mentioning SIGTERM or a stray
/// `std.posix.socket` cannot ride the exemption.
const main_allowed_members = [_][]const u8{
    "getrlimit",
    "setrlimit",
    "sigaction",
    "Sigaction",
    "sigemptyset",
    "SIG",
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    assert(args.len >= 1);
    if (args.len != 2) {
        std.debug.print("usage: lint <source-root>\n", .{});
        return 2;
    }

    var root = try std.Io.Dir.cwd().openDir(io, args[1], .{ .iterate = true });
    defer root.close(io);

    var violation_count: u32 = 0;
    var file_count: u32 = 0;
    var walker = try root.walk(arena);
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) {
            continue;
        }
        if (!std.mem.endsWith(u8, entry.path, ".zig")) {
            continue;
        }
        file_count += 1;
        assert(file_count <= files_max);
        violation_count += try lintFile(arena, io, root, entry.path);
    }
    assert(file_count >= 1);

    if (violation_count > 0) {
        std.debug.print("lint: {d} violation(s)\n", .{violation_count});
        return 1;
    }
    return 0;
}

fn lintFile(
    arena: std.mem.Allocator,
    io: std.Io,
    root: std.Io.Dir,
    path: []const u8,
) !u32 {
    assert(path.len > 0);
    const in_io_directory = std.mem.startsWith(u8, path, "io/") or
        std.mem.startsWith(u8, path, "io" ++ std.fs.path.sep_str);
    const is_main = std.mem.eql(u8, path, "main.zig");

    const contents = try root.readFileAlloc(io, path, arena, .limited(file_bytes_max));
    assert(contents.len < file_bytes_max);

    var violation_count: u32 = 0;
    var line_number: u32 = 0;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        line_number += 1;
        if (lintLine(line, in_io_directory, is_main)) |message| {
            std.debug.print("{s}:{d}: {s}\n", .{ path, line_number, message });
            violation_count += 1;
        }
    }
    assert(line_number >= 1);
    return violation_count;
}

/// Returns a violation message for the line, or null if the line is clean.
fn lintLine(line: []const u8, in_io_directory: bool, is_main: bool) ?[]const u8 {
    if (std.mem.indexOf(u8, line, "@cImport") != null) {
        return "@cImport is forbidden: no C-FFI dependency (DESIGN.md §4)";
    }
    if (in_io_directory) {
        return null;
    }
    if (std.mem.indexOf(u8, line, "@import(\"xev\")") != null) {
        return "xev may only be imported under src/io/ (DESIGN.md §4)";
    }
    for (syscall_needles) |needle| {
        if (std.mem.indexOf(u8, line, needle) == null) {
            continue;
        }
        if (is_main) {
            if (lineIsAllowlisted(line)) {
                return null;
            }
            return "main.zig may only use std.posix for rlimits and sigaction";
        }
        return "raw syscall surfaces live under src/io/ only (DESIGN.md §4)";
    }
    return null;
}

/// True only if every `std.posix.` occurrence on the line names an
/// allowed member — a forbidden call sharing the line with an allowed one
/// is still flagged.
fn lineIsAllowlisted(line: []const u8) bool {
    assert(line.len > 0);
    const qualifier = "std.posix.";
    var offset: usize = 0;
    var saw_qualifier = false;
    while (std.mem.indexOfPos(u8, line, offset, qualifier)) |at| {
        saw_qualifier = true;
        const member = line[at + qualifier.len ..];
        if (!startsWithAllowedMember(member)) {
            return false;
        }
        offset = at + qualifier.len;
    }
    // A line matched a syscall needle but not via `std.posix.` (e.g.
    // std.os.linux.*) — not allowlisted.
    return saw_qualifier;
}

fn startsWithAllowedMember(member: []const u8) bool {
    for (main_allowed_members) |allowed| {
        if (std.mem.startsWith(u8, member, allowed)) {
            return true;
        }
    }
    return false;
}

test "lintLine: raw syscalls flagged outside io, allowed inside" {
    try std.testing.expect(lintLine("const x = std.posix.socket();", false, false) != null);
    try std.testing.expect(lintLine("const x = std.os.linux.close(fd);", false, false) != null);
    try std.testing.expect(lintLine("const x = std.posix.socket();", true, false) == null);
    try std.testing.expect(lintLine("const clean = a + b;", false, false) == null);
}

test "lintLine: main.zig allowlist admits rlimit and sigaction only" {
    try std.testing.expect(lintLine("try std.posix.setrlimit(.NOFILE, limits);", false, true) == null);
    try std.testing.expect(lintLine("std.posix.sigaction(.TERM, &action, null);", false, true) == null);
    try std.testing.expect(lintLine("_ = std.posix.setsockopt(fd, 0, 0, &opt);", false, true) != null);
    // A comment mentioning SIG must not exempt a real forbidden call.
    try std.testing.expect(lintLine("const s = std.posix.socket(); // closed on SIGTERM", false, true) != null);
    // A forbidden call sharing a line with an allowed one is still caught.
    try std.testing.expect(lintLine("std.posix.sigaction(x); std.posix.socket();", false, true) != null);
    // std.os.linux.* is never allowlisted in main.zig.
    try std.testing.expect(lintLine("_ = std.os.linux.close(fd);", false, true) != null);
}

test "lintLine: xev import and cImport boundaries" {
    try std.testing.expect(lintLine("const xev = @import(\"xev\");", false, false) != null);
    try std.testing.expect(lintLine("const xev = @import(\"xev\");", true, false) == null);
    try std.testing.expect(lintLine("const c = @cImport({});", true, false) != null);
}
