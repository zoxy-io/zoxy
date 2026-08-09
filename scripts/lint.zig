//! Build-time lint for the fd boundary of DESIGN.md §4/§9: raw syscall
//! surfaces (`std.posix`, `std.os`, `os.linux`) and the `xev` import may be
//! named only under `src/io/`, with an explicit allowlist for `main.zig`
//! startup work (rlimits, sigaction). The `hparse` import is likewise
//! confined to `src/http/parser.zig` — the wrapper that owns the trust
//! boundary (§7) — and `ztls` to `src/tls/`, the wrapper that owns the
//! crypto boundary (§4). `@cImport` is forbidden everywhere: the codebase's
//! one C surface is inside ztls, behind its Zig protocol layer, and a
//! second one opened here would not be (§4). Runs as `zig build lint` with
//! the source root as its single argument.

const std = @import("std");

const assert = std.debug.assert;

/// Bounded walk: a source tree past this size is itself a lint failure —
/// raise deliberately if the project legitimately grows.
const files_max: u32 = 512;
const file_bytes_max: u32 = 1024 * 1024;

const syscall_needles = [_][]const u8{ "std.posix", "std.os", "os.linux" };

/// One import boundary: a needle that may appear only under `confined_to`.
/// Data rather than code, so adding a boundary is a row here instead of
/// another parameter threaded through `lintLine` and every one of its
/// tests.
const Boundary = struct {
    needle: []const u8,
    /// A path prefix (`"io/"`) or an exact file (`"http/parser.zig"`),
    /// always written with forward slashes; `pathIsUnder` normalizes. Empty
    /// means the needle is allowed nowhere.
    confined_to: []const u8,
    message: []const u8,
};

const boundaries = [_]Boundary{
    .{
        .needle = "@cImport",
        .confined_to = "",
        .message = "@cImport is forbidden: the C bindings live inside ztls (DESIGN.md §4)",
    },
    .{
        .needle = "@import(\"hparse\")",
        .confined_to = "http/parser.zig",
        .message = "hparse is imported only by src/http/parser.zig — the trust boundary (DESIGN.md §7)",
    },
    .{
        .needle = "@import(\"xev\")",
        .confined_to = "io/",
        .message = "xev may only be imported under src/io/ (DESIGN.md §4)",
    },
    .{
        .needle = "@import(\"ztls\")",
        .confined_to = "tls/",
        .message = "ztls may only be imported under src/tls/ — the crypto boundary (DESIGN.md §4)",
    },
};

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
    const contents = try root.readFileAlloc(io, path, arena, .limited(file_bytes_max));
    assert(contents.len < file_bytes_max);

    var violation_count: u32 = 0;
    var line_number: u32 = 0;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        line_number += 1;
        if (lintLine(line, path)) |message| {
            std.debug.print("{s}:{d}: {s}\n", .{ path, line_number, message });
            violation_count += 1;
        }
    }
    assert(line_number >= 1);
    return violation_count;
}

comptime {
    // Every path here — the walked one and the confinements below — is
    // compared byte-for-byte with '/' as the separator. Rather than
    // normalizing for a platform this project does not support (§1: Windows
    // is a non-goal, and the macOS dev box uses '/' too), the assumption is
    // stated and enforced: on a '\\' platform this lint would need real path
    // handling, and failing to build says so.
    assert(std.fs.path.sep == '/');
}

/// True when `path` is the file named by `confinement`, or lies under it as a
/// directory prefix. A `confinement` ending in '/' is a directory, anything
/// else an exact file; empty confines a needle to nowhere.
fn pathIsUnder(path: []const u8, confinement: []const u8) bool {
    assert(path.len > 0);
    // The confinements are written in this file, so a stray separator is a
    // typo in a table row, not untrusted input.
    assert(std.mem.indexOfScalar(u8, confinement, '\\') == null);
    if (confinement.len == 0) return false;
    if (confinement[confinement.len - 1] != '/') {
        return std.mem.eql(u8, path, confinement);
    }
    const directory = confinement[0 .. confinement.len - 1];
    assert(directory.len >= 1);
    if (!std.mem.startsWith(u8, path, directory)) return false;
    // A sibling whose name merely starts the same is not under it: the byte
    // after the directory must be the separator, never more name.
    if (path.len == directory.len) return false;
    return path[directory.len] == '/';
}

/// Returns a violation message for the line, or null if the line is clean.
fn lintLine(line: []const u8, path: []const u8) ?[]const u8 {
    assert(path.len > 0);
    const in_io_directory = pathIsUnder(path, "io/");
    for (boundaries) |boundary| {
        if (pathIsUnder(path, boundary.confined_to)) continue;
        if (std.mem.indexOf(u8, line, boundary.needle) != null) {
            return boundary.message;
        }
    }
    // The syscall surfaces are not one needle with one home: they are a set,
    // and main.zig carries a member-level allowlist rather than a path.
    if (in_io_directory) {
        return null;
    }
    const is_main = std.mem.eql(u8, path, "main.zig");
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
    try std.testing.expect(lintLine("const x = std.posix.socket();", "net/relay.zig") != null);
    try std.testing.expect(lintLine("const x = std.os.linux.close(fd);", "net/relay.zig") != null);
    try std.testing.expect(lintLine("const x = std.posix.socket();", "io/XevIo.zig") == null);
    try std.testing.expect(lintLine("const clean = a + b;", "net/relay.zig") == null);
}

test "lintLine: main.zig allowlist admits rlimit and sigaction only" {
    try std.testing.expect(lintLine("try std.posix.setrlimit(.NOFILE, limits);", "main.zig") == null);
    try std.testing.expect(lintLine("std.posix.sigaction(.TERM, &action, null);", "main.zig") == null);
    try std.testing.expect(lintLine("_ = std.posix.setsockopt(fd, 0, 0, &opt);", "main.zig") != null);
    // A comment mentioning SIG must not exempt a real forbidden call.
    try std.testing.expect(lintLine("const s = std.posix.socket(); // closed on SIGTERM", "main.zig") != null);
    // A forbidden call sharing a line with an allowed one is still caught.
    try std.testing.expect(lintLine("std.posix.sigaction(x); std.posix.socket();", "main.zig") != null);
    // std.os.linux.* is never allowlisted in main.zig.
    try std.testing.expect(lintLine("_ = std.os.linux.close(fd);", "main.zig") != null);
}

test "lintLine: xev import and cImport boundaries" {
    try std.testing.expect(lintLine("const xev = @import(\"xev\");", "Server.zig") != null);
    try std.testing.expect(lintLine("const xev = @import(\"xev\");", "io/XevIo.zig") == null);
    try std.testing.expect(lintLine("const c = @cImport({});", "io/XevIo.zig") != null);
}

test "lintLine: hparse import is confined to the http parser wrapper" {
    try std.testing.expect(lintLine("const hparse = @import(\"hparse\");", "http/parser.zig") == null);
    try std.testing.expect(lintLine("const hparse = @import(\"hparse\");", "http/proxy.zig") != null);
    // Not even src/io/ may reach around the wrapper.
    try std.testing.expect(lintLine("const hparse = @import(\"hparse\");", "io/XevIo.zig") != null);
}

test "lintLine: ztls import is confined to the TLS engine wrapper" {
    try std.testing.expect(lintLine("const ztls = @import(\"ztls\");", "tls/Engine.zig") == null);
    try std.testing.expect(lintLine("const ztls = @import(\"ztls\");", "Server.zig") != null);
    // The data path talks to `src/tls/`, never to the crypto library —
    // not even the parts that are already past a trust boundary of their own.
    try std.testing.expect(lintLine("const ztls = @import(\"ztls\");", "http/parser.zig") != null);
    try std.testing.expect(lintLine("const ztls = @import(\"ztls\");", "io/XevIo.zig") != null);
}

test "pathIsUnder: exact files, directory prefixes, and near misses" {
    try std.testing.expect(pathIsUnder("http/parser.zig", "http/parser.zig"));
    try std.testing.expect(!pathIsUnder("http/parser_test.zig", "http/parser.zig"));
    try std.testing.expect(pathIsUnder("io/XevIo.zig", "io/"));
    try std.testing.expect(pathIsUnder("io/sub/deep.zig", "io/"));
    // A sibling directory whose name merely starts the same is not under it.
    try std.testing.expect(!pathIsUnder("iommu/thing.zig", "io/"));
    try std.testing.expect(!pathIsUnder("io", "io/"));
    // An empty spec confines a needle to nowhere.
    try std.testing.expect(!pathIsUnder("anything.zig", ""));
}
