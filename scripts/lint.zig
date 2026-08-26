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

/// TIGER_STYLE's "put a limit on everything", made mechanical: `while
/// (true)` states no bound of its own, so it must carry one where a
/// reviewer can see it. Two shapes count.
///
/// An asserted counter — what `SimIo.stop` and `contract_test.initTestIo`
/// already use:
///
///     while (true) : (passes += 1) {
///         assert(passes <= pending_ops_max);
///
/// Or a bound the syntax cannot show — a JSON scanner that terminates on
/// its own `}`, the three `config.zig` object loops — which says so at the
/// site with the marker below and a reason.
///
/// The rule exists because of zoxy-io/zoxy#222: ztls's `p256.KeyPair.
/// generate` retried `while (true) ... catch continue` on the assumption
/// that its error was a once-in-2^32 bad scalar. When the error became a
/// persistent one instead (the fixed libcrypto heap full), the retry spun
/// at 100% CPU forever and took the whole event loop — both listeners and
/// the admin plane — with it. An unbounded loop is a claim that some
/// condition always eventually holds; this makes the claim reviewable
/// instead of implicit.
const unbounded_loop_needle = "while (true)";
const unbounded_loop_marker = "lint:unbounded-ok";
const unbounded_loop_message =
    "unbounded `while (true)`: assert a counter bound in the loop body, " ++
    "or mark it `lint:unbounded-ok — <why>` (TIGER_STYLE: put a limit on everything)";

/// Lines after the loop header within which the bound assertion must
/// appear. The assertion belongs at the top of the body, so this is
/// deliberately short — far enough to clear a comment between header and
/// assert, near enough that an unrelated `assert` deeper in the loop
/// cannot satisfy it by accident.
const loop_bound_lookahead_lines: u32 = 6;

/// The only `std.posix.` members main.zig may name (rlimits + sigaction);
/// everything else — sockets, files, pipes — stays behind the Io seam.
/// These are matched as fully-qualified `std.posix.<name>` occurrences,
/// not bare words, so a comment mentioning SIGTERM or a stray
/// `std.posix.socket` cannot ride the exemption.
const main_allowed_members = [_][]const u8{
    "getrlimit",
    "setrlimit",
    // The two types `getrlimit` answers in, so a reported limit can be
    // held and rendered without the value leaving the allowlist.
    "rlimit",
    "rlim_t",
    "RLIM",
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
    return violation_count + lintUnboundedLoops(contents, path) +
        lintFunctionLengths(contents, path);
}

/// Flag every `while (true)` whose bound is neither asserted nor
/// declared. A pass of its own rather than a `lintLine` rule because the
/// evidence is not on the line: the bound lives in the body below the
/// header, which is exactly why a line-at-a-time reader — human or lint —
/// missed it for as long as it did.
fn lintUnboundedLoops(contents: []const u8, path: []const u8) u32 {
    assert(path.len > 0);
    var violation_count: u32 = 0;
    var offset: usize = 0;
    while (nextUnboundedLoop(contents, offset)) |at| {
        offset = at + unbounded_loop_needle.len;
        assert(offset > at);
        std.debug.print("{s}:{d}: {s}\n", .{
            path,
            lineNumberAt(contents, at),
            unbounded_loop_message,
        });
        violation_count += 1;
    }
    return violation_count;
}

/// Offset of the next unbounded `while (true)` at or after `from`, or null
/// when the rest is clean. The decision lives here, apart from the report,
/// so a test can make it without printing a violation it went looking for
/// — the same split `lintLine` has for the boundary rules.
fn nextUnboundedLoop(contents: []const u8, from: usize) ?usize {
    assert(from <= contents.len);
    var offset = from;
    // Bounded: every iteration moves `offset` past the match it found, so
    // this runs at most once per occurrence in a file `lintFile` has
    // already held under `file_bytes_max`.
    while (std.mem.indexOfPos(u8, contents, offset, unbounded_loop_needle)) |at| {
        offset = at + unbounded_loop_needle.len;
        assert(offset > at);
        const start = lineStartOf(contents, at);
        const end = lineEndOf(contents, at);
        assert(start <= at);
        assert(end >= at);
        const line = contents[start..end];
        // A loop named in prose — this file's own doc comment above, or a
        // `// Bounded: …` note — is not a loop.
        if (lineIsComment(line)) continue;
        if (markedUnboundedOk(contents, start, line)) continue;
        if (boundAssertedWithin(contents[end..], loop_bound_lookahead_lines)) continue;
        return at;
    }
    return null;
}

/// The count without the report — what the tests below assert on.
fn countUnboundedLoops(contents: []const u8) u32 {
    var count: u32 = 0;
    var offset: usize = 0;
    while (nextUnboundedLoop(contents, offset)) |at| {
        offset = at + unbounded_loop_needle.len;
        assert(offset > at);
        count += 1;
    }
    return count;
}

/// True when the loop declares itself structurally bounded: the marker
/// sits either on the header line or on the comment line directly above
/// it. Both are accepted because the reason is what matters and it rarely
/// fits after `while (true) {` — this codebase explains a construct in the
/// block above it, which is where such a reason belongs.
fn markedUnboundedOk(contents: []const u8, start: usize, line: []const u8) bool {
    assert(start <= contents.len);
    if (std.mem.indexOf(u8, line, unbounded_loop_marker) != null) return true;
    if (start == 0) return false;
    const above_end = start - 1; // The '\n' that ended the line above.
    const above_start = lineStartOf(contents, above_end);
    assert(above_start <= above_end);
    const above = contents[above_start..above_end];
    if (!lineIsComment(above)) return false;
    return std.mem.indexOf(u8, above, unbounded_loop_marker) != null;
}

/// True when one of the next `lines_max` lines asserts an upper bound —
/// any `assert` naming a `<` relation. Deliberately shape-based rather
/// than parsing the counter out of the loop header: the point is that a
/// bound is stated near the top of the body, and every way of writing
/// `assert(n <= max)` should satisfy it.
fn boundAssertedWithin(rest: []const u8, lines_max: u32) bool {
    assert(lines_max >= 1);
    var lines = std.mem.splitScalar(u8, rest, '\n');
    var seen: u32 = 0;
    while (lines.next()) |line| {
        if (seen == lines_max) return false;
        seen += 1;
        if (std.mem.indexOf(u8, line, "assert(") == null) continue;
        // `<=` contains `<`, so the one test covers both relations.
        if (std.mem.indexOfScalar(u8, line, '<') != null) return true;
    }
    assert(seen <= lines_max);
    return false;
}

fn lineStartOf(contents: []const u8, at: usize) usize {
    assert(at < contents.len);
    const newline = std.mem.lastIndexOfScalar(u8, contents[0..at], '\n') orelse return 0;
    assert(newline < at);
    return newline + 1;
}

fn lineEndOf(contents: []const u8, at: usize) usize {
    assert(at < contents.len);
    const newline = std.mem.indexOfScalarPos(u8, contents, at, '\n') orelse return contents.len;
    assert(newline >= at);
    return newline;
}

fn lineNumberAt(contents: []const u8, at: usize) u32 {
    assert(at < contents.len);
    return @intCast(std.mem.count(u8, contents[0..at], "\n") + 1);
}

/// True when the line's first non-blank characters are `//` — a doc
/// comment, a module comment, or an ordinary one.
fn lineIsComment(line: []const u8) bool {
    const trimmed = std.mem.trimStart(u8, line, " \t");
    assert(trimmed.len <= line.len);
    return std.mem.startsWith(u8, trimmed, "//");
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

test "lintUnboundedLoops: a bare while (true) is a violation" {
    const source =
        \\fn spin() void {
        \\    while (true) {
        \\        step();
        \\    }
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 1), countUnboundedLoops(source));
}

test "lintUnboundedLoops: an asserted counter bound satisfies the rule" {
    // The `SimIo.stop` shape: counter in the continue expression, bound
    // asserted at the top of the body.
    const source =
        \\fn flush() void {
        \\    var passes: u32 = 0;
        \\    while (true) : (passes += 1) {
        \\        assert(passes <= pending_ops_max);
        \\        if (done()) break;
        \\    }
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countUnboundedLoops(source));
}

test "lintUnboundedLoops: the marker exempts a structurally-bounded loop" {
    const source =
        \\fn parse() !void {
        \\    while (true) { // lint:unbounded-ok — the scanner ends it at `}`
        \\        if (try next() == .object_end) break;
        \\    }
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countUnboundedLoops(source));
}

test "lintUnboundedLoops: the marker is accepted on the line above" {
    const source =
        \\fn parse() !void {
        \\    // lint:unbounded-ok — the scanner ends the object at `}`
        \\    while (true) {
        \\        if (try next() == .object_end) break;
        \\    }
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countUnboundedLoops(source));
    // Only *directly* above: a blank line between them breaks the pairing,
    // so a stale marker cannot drift onto an unrelated loop.
    const detached =
        \\fn parse() !void {
        \\    // lint:unbounded-ok — the scanner ends the object at `}`
        \\
        \\    while (true) {
        \\        step();
        \\    }
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 1), countUnboundedLoops(detached));
}

test "lintUnboundedLoops: prose about a loop is not a loop" {
    const source =
        \\/// Bounded, unlike a bare `while (true)`, which this is not.
        \\fn ok() void {}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countUnboundedLoops(source));
}

test "lintUnboundedLoops: an assert too far below the header does not count" {
    // The bound must be at the top of the body: an `assert` seven lines
    // down is an unrelated invariant, not this loop's limit.
    const source =
        \\while (true) {
        \\    a();
        \\    b();
        \\    c();
        \\    d();
        \\    e();
        \\    f();
        \\    assert(n <= max);
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 1), countUnboundedLoops(source));
}

test "lintUnboundedLoops: each unbounded loop in a file is counted" {
    const source =
        \\while (true) {
        \\    a();
        \\}
        \\while (true) {
        \\    b();
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 2), countUnboundedLoops(source));
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

/// TIGER_STYLE's function-length limit, made mechanical — and measured in
/// *code* lines, which is the whole point of having it here rather than
/// leaving it to review.
///
/// A physical-line limit taxes the practice this codebase is most
/// distinctive for. Measured over the tree the day this rule landed, 70
/// physical lines flagged 16 functions, 13 of them more than a third
/// comment: `dialUpstream` at 75 physical was 32 lines of code and a
/// 35-line comment justifying one assertion (#253), a comment a
/// million-seed soak paid for. A rule that says "shorten this" about that
/// function is a rule that rewards deleting the explanation. Counting
/// code alone flagged the three that were genuinely long.
const function_code_lines_max: u32 = 70;

/// How far a wrapped signature may run before its `{`. Generous: the
/// widest in the tree is nine lines, and over-running merely means this
/// pass cannot tell a type constructor from an ordinary function.
const signature_lines_max: u32 = 16;

fn lintFunctionLengths(contents: []const u8, path: []const u8) u32 {
    assert(path.len > 0);
    var violation_count: u32 = 0;
    var scan: FunctionScan = .{ .contents = contents };
    // Bounded by the line count: `next` advances past the header it
    // returned, and a file is already held under `file_bytes_max`.
    while (scan.next()) |found| {
        if (found.code_lines <= function_code_lines_max) continue;
        std.debug.print("{s}:{d}: function is {d} lines of code, limit is {d} " ++
            "(TIGER_STYLE; comments and blanks do not count)\n", .{
            path,
            found.line_number,
            found.code_lines,
            function_code_lines_max,
        });
        violation_count += 1;
    }
    return violation_count;
}

/// The count without the report — what the tests below assert on, the
/// same split `nextUnboundedLoop` has.
fn countOverlongFunctions(contents: []const u8) u32 {
    return countOverlongFunctionsAt(contents, function_code_lines_max);
}

/// The same count against an arbitrary limit. The threshold is a
/// parameter so the tests can state a fixture in five readable lines
/// instead of seventy: what they are checking is where the boundary
/// falls and what counts toward it, neither of which is a property of
/// the number 70.
fn countOverlongFunctionsAt(contents: []const u8, limit: u32) u32 {
    var count: u32 = 0;
    var scan: FunctionScan = .{ .contents = contents };
    // Bounded by the file's function count: `next` advances past each
    // header it returns.
    while (scan.next()) |found| {
        if (found.code_lines > limit) count += 1;
    }
    return count;
}

/// Walks the function bodies in one file, skipping the comptime type
/// constructors (`fn Name(...) type`) that are containers rather than
/// functions — the 70-line rule is about a body a reader must hold in
/// their head, and `fn Server(comptime IoType: type) type` is a module.
const FunctionScan = struct {
    contents: []const u8,
    line_index: u32 = 0,

    const Found = struct {
        line_number: u32,
        code_lines: u32,
    };

    fn next(scan: *FunctionScan) ?Found {
        // Bounded: every iteration advances `line_index` by at least one,
        // and the file has finitely many lines.
        while (scan.lineAt(scan.line_index)) |line| {
            const start = scan.line_index;
            scan.line_index += 1;
            const indent = headerIndent(line) orelse continue;
            if (scan.isTypeConstructor(start)) continue;
            const code_lines = scan.countBody(start, indent) orelse continue;
            return .{ .line_number = start + 1, .code_lines = code_lines };
        }
        return null;
    }

    /// The zero-based `index`th line, or null past the end.
    fn lineAt(scan: *const FunctionScan, index: u32) ?[]const u8 {
        var seen: u32 = 0;
        var offset: usize = 0;
        // Bounded by the file length: each step moves past one newline.
        while (offset <= scan.contents.len) {
            const end = std.mem.indexOfScalarPos(u8, scan.contents, offset, '\n') orelse
                scan.contents.len;
            if (seen == index) return scan.contents[offset..end];
            if (end == scan.contents.len) return null;
            seen += 1;
            offset = end + 1;
        }
        return null;
    }

    /// True when the signature starting at `start` returns `type`.
    fn isTypeConstructor(scan: *const FunctionScan, start: u32) bool {
        var offset: u32 = 0;
        while (offset < signature_lines_max) : (offset += 1) {
            const line = scan.lineAt(start + offset) orelse return false;
            const trimmed = std.mem.trimEnd(u8, line, " \t\r");
            if (!std.mem.endsWith(u8, trimmed, "{")) continue;
            return std.mem.indexOf(u8, trimmed, ") type {") != null;
        }
        return false;
    }

    /// Lines of code from the header through the closing brace at the
    /// same indent, or null when no such brace is found — a signature
    /// this pass could not follow, which it declines to judge rather than
    /// guessing.
    fn countBody(scan: *const FunctionScan, start: u32, indent: usize) ?u32 {
        var code_lines: u32 = 0;
        var offset: u32 = 0;
        // Bounded by the file's line count, which `file_bytes_max`
        // bounds in turn.
        while (scan.lineAt(start + offset)) |line| : (offset += 1) {
            if (!isBlankOrComment(line)) code_lines += 1;
            if (offset >= 1 and isCloseAt(line, indent)) return code_lines;
        }
        return null;
    }
};

/// The indent of a function header line, or null when the line is not
/// one. `fn` must open the statement: a `fn` inside a type expression or
/// a string is not a declaration this rule is about.
fn headerIndent(line: []const u8) ?usize {
    const indent = line.len - std.mem.trimStart(u8, line, " ").len;
    const rest = line[indent..];
    const body = if (std.mem.startsWith(u8, rest, "pub ")) rest["pub ".len..] else rest;
    if (!std.mem.startsWith(u8, body, "fn ")) return null;
    // A name and an open paren, so `fn` in prose cannot match.
    if (std.mem.indexOfScalar(u8, body, '(') == null) return null;
    return indent;
}

/// True for the `}` that closes a declaration opened at `indent`.
fn isCloseAt(line: []const u8, indent: usize) bool {
    if (line.len != indent + 1) return false;
    if (line[indent] != '}') return false;
    for (line[0..indent]) |byte| {
        if (byte != ' ') return false;
    }
    return true;
}

fn isBlankOrComment(line: []const u8) bool {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0) return true;
    return std.mem.startsWith(u8, trimmed, "//");
}

test "countOverlongFunctions: the boundary is exact" {
    // Three code lines: the header, one statement, the brace.
    const at_limit =
        \\fn f() void {
        \\    step();
        \\}
        \\
    ;
    const over =
        \\fn f() void {
        \\    step();
        \\    step();
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countOverlongFunctionsAt(at_limit, 3));
    try std.testing.expectEqual(@as(u32, 1), countOverlongFunctionsAt(over, 3));
}

test "countOverlongFunctions: comments and blanks do not count" {
    // The rule's whole point: explanation is not length. A physical-line
    // limit would flag this body and reward deleting the reason it works.
    const padded =
        \\fn f() void {
        \\    // Why this is correct, at length.
        \\    //
        \\    // Still explaining.
        \\
        \\    step();
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countOverlongFunctionsAt(padded, 3));
}

test "countOverlongFunctions: a comptime type constructor is not a function" {
    // `fn Server(comptime IoType: type) type` is a module, and the limit
    // is about a body a reader holds in their head.
    const constructor =
        \\fn Server(comptime IoType: type) type {
        \\    step();
        \\    step();
        \\    step();
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countOverlongFunctionsAt(constructor, 3));
}

test "countOverlongFunctions: a wrapped signature is still recognized" {
    // The `) type {` this pass looks for may be several lines below the
    // `fn`, which is how every generic in the tree is written.
    const wrapped =
        \\fn Pool(
        \\    comptime T: type,
        \\) type {
        \\    step();
        \\    step();
        \\    step();
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 0), countOverlongFunctionsAt(wrapped, 3));
}

test "countOverlongFunctions: a nested declaration is measured at its own indent" {
    const nested =
        \\    fn inner() void {
        \\        step();
        \\        step();
        \\    }
        \\
    ;
    try std.testing.expectEqual(@as(u32, 1), countOverlongFunctionsAt(nested, 3));
    try std.testing.expectEqual(@as(u32, 0), countOverlongFunctionsAt(nested, 4));
}

test "countOverlongFunctions: each overlong function in a file is counted" {
    const source =
        \\fn a() void {
        \\    step();
        \\    step();
        \\}
        \\fn b() void {
        \\    step();
        \\}
        \\fn c() void {
        \\    step();
        \\    step();
        \\}
        \\
    ;
    try std.testing.expectEqual(@as(u32, 2), countOverlongFunctionsAt(source, 3));
}
