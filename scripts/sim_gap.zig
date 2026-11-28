//! `zig build coverage`'s sim gap report (§9): the lines of src/ the unit
//! tests reach and the simulator does not.
//!
//! The merged kcov report answers "does anything run this line"; it cannot
//! answer "does the sweep go here", because a line one unit test runs reads
//! as covered whichever binary ran it. The census (sim/main.zig) answers
//! reach for counters and seam ops, which are points; this answers it for
//! lines. A line the tests run and the sim does not is one of three things,
//! and the report keeps them apart:
//!
//! - executed-never: compiled into the sim, run by no seed — a branch the
//!   sweep's scenarios do not take;
//! - unreferenced: never compiled into the sim (Zig compiles only what is
//!   referenced) though production code calls it — a feature no sim config
//!   turns on;
//! - test-helper: never compiled into the sim, and nothing outside tests and
//!   fuzz targets names it — not a gap at all, so set aside.
//!
//! A gap the sweep does not reach is set apart with its reason, as the
//! census exempts a counter: a loader line that refuses a config (the sim
//! builds only configs zoxy accepts), a function only startup code names,
//! and the functions `sim_gap_exemptions.zig` names, each with the most
//! lines it may excuse. The report fails on a serving-path gap nothing
//! explains, and on an excused function whose gap outgrew its entry — a
//! change that opens a new gap is judged, not absorbed. An entry whose
//! function the sweep now reaches whole is named for deletion. The bound
//! is a ceiling rather than an exact count because kcov attributes lines
//! differently across architectures and toolchains: the entries hold the
//! larger of what arm64 and CI's x86_64 report.
//!
//! Each failure is written to stderr as well as the report, so a run whose
//! report a failing build step does not install still says what failed.
//!
//! The last split is a heuristic. Callers are found by name across src/,
//! so two functions that share a name read as calling each other. That errs
//! toward listing a helper as a gap, never toward hiding a gap as a helper.
//! A line is attributed to the nearest `fn` declared above it, so a
//! declaration that follows a function's body is counted as part of it.
//!
//! usage: sim_gap <src-root> <sim cobertura.xml> <test cobertura.xml>...
//! The report goes to stdout.

const std = @import("std");

const assert = std.debug.assert;

/// Bounds on what one report reads: raise them deliberately when the tree
/// outgrows them, rather than reading less of it.
const files_max: u32 = 1024;
/// The lint's own bound on one source file.
const source_bytes_max: u32 = 1024 * 1024;
/// kcov's cobertura for the unit tests is ~1.5 MiB today; the rest is
/// headroom for a tree that grows.
const report_bytes_max: u32 = 64 * 1024 * 1024;
const source_lines_max: u32 = 1 << 16;
const test_reports_max: u32 = 8;

const Bucket = enum(u8) { serving, startup, outside };

/// A file (or a directory, ending in '/') of src/ that the sweep does not
/// run by construction, and why. The serving path is everything else, and
/// it is the part of the report a gap in means a scenario to widen.
const Placement = struct {
    path: []const u8,
    bucket: Bucket,
    reason: []const u8,
};

const placements = [_]Placement{
    .{ .path = "json/", .bucket = .startup, .reason = "the sim writes its Config in code, never JSON" },
    .{ .path = "app.zig", .bucket = .startup, .reason = "the process sequence around Server.init" },
    .{ .path = "budget.zig", .bucket = .startup, .reason = "the startup price, paid before Server.init" },
    .{ .path = "defaults.zig", .bucket = .startup, .reason = "the stock values the JSON front-end applies" },
    .{ .path = "dns/startup.zig", .bucket = .startup, .reason = "the first answer for a name, before Server.init" },
    .{ .path = "main.zig", .bucket = .outside, .reason = "the CLI; the sim builds a Server directly" },
    .{ .path = "io/XevIo.zig", .bucket = .outside, .reason = "the real backend; the sim runs SimIo" },
    .{
        .path = "tls/libcrypto_heap.zig",
        .bucket = .outside,
        .reason = "App installs it; the sim does not, and tls-heap-proof is its gate",
    },
};

const exemption_table = @import("sim_gap_exemptions.zig");
const Exemption = exemption_table.Exemption;
const exemptions = exemption_table.exemptions;

/// The file whose refusals are the loader's: a line of it that does no
/// more than return an error refuses a config, and the sim builds only
/// configs zoxy accepts (`config.resolve`, before `Server.init`).
const loader_path = "config.zig";
const refusal_reason = "a loader refusal: the sim builds only configs zoxy accepts";
const startup_reason = "named only from startup or outside code, which the sim does not run";

/// Code that exists to test or to simulate, beside the two patterns
/// `isHarness` matches by name (`*_test.zig`, `Test*.zig`).
const harness_paths = [_][]const u8{ "testing/", "io/SimIo.zig", "tls_heap_proof.zig" };

/// Name prefixes of the fuzz and check helpers that live outside `test`
/// blocks; each must be followed by an upper-case letter or `_`.
const helper_prefixes = [_][]const u8{ "check", "fuzz", "expect", "test" };

const Mark = packed struct(u8) {
    sim_instrumented: bool = false,
    sim_hit: bool = false,
    tests_instrumented: bool = false,
    tests_hit: bool = false,
    in_test_block: bool = false,
    padding: u3 = 0,
};

const Role = enum(u8) { sim, tests };

const Source = struct {
    path: []const u8,
    bucket: Bucket,
    lines: []const []const u8,
    /// Line `number`'s marks are at `marks[number - 1]`.
    marks: []Mark,
    /// Each line's owner: the nearest `fn` declared at or above it.
    owners: []const []const u8,
};

const Tree = struct {
    sources: std.ArrayList(Source) = .empty,
    /// How often production code names each identifier: lines in `test`
    /// blocks, in helper-named functions, and `fn` declaration lines are
    /// not counted, nor a function naming itself.
    callers: std.StringHashMapUnmanaged(u32) = .empty,
    /// The same count over serving-path files alone.
    serving_callers: std.StringHashMapUnmanaged(u32) = .empty,
    harness_seen: [harness_paths.len]bool = @splat(false),
    /// The gap lines each of `exemptions` matched: an entry is stale
    /// unless it matched exactly the count it names.
    exemptions_matched: [exemptions.len]u32 = @splat(0),
};

const Kind = enum(u8) { executed_never, unreferenced, test_helper, exempt };

const Group = struct {
    owner: []const u8,
    kind: Kind,
    numbers: std.ArrayList(u32),
    /// A loader refusal's lines, kept apart from the rest of their owner.
    refusal: bool = false,
    /// Why an `.exempt` group is set apart.
    reason: []const u8 = "",
};

const Tally = struct {
    instrumented: u32 = 0,
    sim_hit: u32 = 0,
    executed_never: u32 = 0,
    unreferenced: u32 = 0,
    test_helper: u32 = 0,
    exempt: u32 = 0,

    fn add(tally: *Tally, other: *const Tally) void {
        const before = tally.instrumented;
        tally.instrumented += other.instrumented;
        tally.sim_hit += other.sim_hit;
        tally.executed_never += other.executed_never;
        tally.unreferenced += other.unreferenced;
        tally.test_helper += other.test_helper;
        tally.exempt += other.exempt;
        assert(tally.instrumented >= before);
        assert(tally.sim_hit <= tally.instrumented);
    }

    /// What the sweep is meant to reach: helpers are set aside.
    fn lines(tally: *const Tally) u32 {
        assert(tally.test_helper <= tally.instrumented);
        return tally.instrumented - tally.test_helper;
    }

    /// The gap nothing explains: a scenario to widen, or an exemption to
    /// write.
    fn gap(tally: *const Tally) u32 {
        const total = tally.executed_never + tally.unreferenced;
        assert(total + tally.exempt <= tally.instrumented);
        return total;
    }
};

const Row = struct {
    source: *const Source,
    tally: Tally,
    groups: []Group,
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    assert(args.len >= 1);
    if (args.len < 4 or args.len > 3 + test_reports_max) {
        std.debug.print("usage: sim_gap <src-root> <sim cobertura.xml> <test cobertura.xml>...\n", .{});
        return 2;
    }

    var root = try std.Io.Dir.cwd().openDir(io, args[1], .{ .iterate = true });
    defer root.close(io);

    var tree: Tree = .{};
    try loadTree(arena, io, root, &tree);
    if (!tableHolds(&tree)) return 1;
    try applyReport(arena, io, &tree, args[2], .sim);
    for (args[3..]) |path| try applyReport(arena, io, &tree, path, .tests);

    const rows = try buildRows(arena, &tree);
    var buffer: [4096]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
    try writeReport(&file_writer.interface, rows);
    try file_writer.interface.flush();
    const explained = everyGapExplained(rows);
    return if (exemptionsHold(&tree) and explained) 0 else 1;
}

/// Every serving-path gap is swept or set apart (#487): one that is
/// neither is a scenario to widen or an exemption to write.
fn everyGapExplained(rows: []const Row) bool {
    assert(rows.len >= 1);
    var explained = true;
    for (rows) |*row| {
        if (row.source.bucket != .serving) continue;
        for (row.groups) |*group| {
            assert(group.numbers.items.len >= 1);
            if (group.kind != .executed_never and group.kind != .unreferenced) continue;
            std.debug.print("sim_gap: unexplained {s}:{s} ({t}, {d} line(s)): sweep it or exempt it\n", .{
                row.source.path, group.owner, group.kind, group.numbers.items.len,
            });
            explained = false;
        }
    }
    return explained;
}

/// Every exemption must still excuse a gap: one whose function the sweep
/// now reaches, or that no longer exists, would read as though it did.
fn exemptionsHold(tree: *const Tree) bool {
    var holds = true;
    for (exemptions, tree.exemptions_matched) |exemption, matched| {
        assert(exemption.reason.len >= 1);
        assert(exemption.lines >= 1);
        if (matched == 0) {
            std.debug.print("sim_gap: exemption {s}:{s} excuses nothing here: delete it if no " ++
                "architecture's report needs it\n", .{ exemption.path, exemption.owner });
            continue;
        }
        if (matched <= exemption.lines) continue;
        std.debug.print("sim_gap: exemption {s}:{s} allows {d} line(s) and the gap holds {d}: " ++
            "judge the new ones\n", .{ exemption.path, exemption.owner, exemption.lines, matched });
        holds = false;
    }
    return holds;
}

/// Every production `.zig` file under the root, with its test blocks and
/// owners marked, and every identifier it names counted.
fn loadTree(arena: std.mem.Allocator, io: std.Io, root: std.Io.Dir, tree: *Tree) !void {
    assert(tree.sources.items.len == 0);
    var walker = try root.walk(arena);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;
        if (harnessEntry(entry.path)) |index| {
            tree.harness_seen[index] = true;
            continue;
        }
        if (isHarness(entry.path)) continue;
        if (tree.sources.items.len >= files_max) return error.TooManyFiles;
        // The walker reuses its path buffer: the source keeps its own.
        const path = try arena.dupe(u8, entry.path);
        const contents = try root.readFileAlloc(io, path, arena, .limited(source_bytes_max));
        const source = try loadSource(arena, path, contents);
        try countCallers(arena, &tree.callers, &source);
        if (source.bucket == .serving) try countCallers(arena, &tree.serving_callers, &source);
        try tree.sources.append(arena, source);
    }
    assert(tree.sources.items.len >= 1);
    assert(tree.sources.items.len <= files_max);
}

fn loadSource(arena: std.mem.Allocator, path: []const u8, contents: []const u8) !Source {
    assert(path.len >= 1);
    const count = std.mem.countScalar(u8, contents, '\n') + 1;
    if (count > source_lines_max) return error.SourceTooLong;
    const lines = try arena.alloc([]const u8, count);
    var split = std.mem.splitScalar(u8, contents, '\n');
    for (lines) |*line| line.* = split.next().?;
    assert(split.next() == null);

    const marks = try arena.alloc(Mark, count);
    @memset(marks, .{});
    if (!markTestBlocks(lines, marks)) {
        std.debug.print("sim_gap: {s}: a test block never closes — is the file zig fmt clean?\n", .{path});
        return error.UnclosedTestBlock;
    }
    const owners = try arena.alloc([]const u8, count);
    assignOwners(lines, owners);
    return .{ .path = path, .bucket = bucketOf(path), .lines = lines, .marks = marks, .owners = owners };
}

/// Marks every line of every `test "..." { }` block, header to closing
/// brace. False when a block never closes, which zig fmt'd source cannot do.
fn markTestBlocks(lines: []const []const u8, marks: []Mark) bool {
    assert(lines.len == marks.len);
    var index: usize = 0;
    while (index < lines.len) {
        const indent = testBlockIndent(lines[index]) orelse {
            index += 1;
            continue;
        };
        const close = closingLine(lines, index, indent) orelse return false;
        assert(close > index);
        for (marks[index .. close + 1]) |*mark| mark.in_test_block = true;
        index = close + 1;
    }
    assert(index == lines.len);
    return true;
}

/// The indent of a `test` block's header line, or null for any other line.
fn testBlockIndent(line: []const u8) ?usize {
    const rest = std.mem.trimStart(u8, line, " ");
    const indent = line.len - rest.len;
    assert(indent <= line.len);
    if (!std.mem.startsWith(u8, rest, "test")) return null;
    if (rest.len > "test".len and isIdentifierByte(rest["test".len])) return null;
    if (!std.mem.endsWith(u8, std.mem.trimEnd(u8, rest, " \r"), "{")) return null;
    return indent;
}

/// The index of the line that closes the block opened at `open`: its
/// brace alone, at the header's indent.
fn closingLine(lines: []const []const u8, open: usize, indent: usize) ?usize {
    assert(open < lines.len);
    for (lines[open + 1 ..], open + 1..) |line, index| {
        const trimmed = std.mem.trimEnd(u8, line, " \r");
        if (trimmed.len != indent + 1) continue;
        if (trimmed[indent] != '}') continue;
        if (std.mem.trimStart(u8, trimmed[0..indent], " ").len != 0) continue;
        assert(index > open);
        return index;
    }
    return null;
}

fn assignOwners(lines: []const []const u8, owners: [][]const u8) void {
    assert(lines.len == owners.len);
    var current: []const u8 = "<top level>";
    for (lines, owners) |line, *owner| {
        if (fnName(line)) |name| current = name;
        owner.* = current;
    }
    assert(owners.len == 0 or owners[owners.len - 1].len >= 1);
}

/// The name a line declares as a function, or null.
fn fnName(line: []const u8) ?[]const u8 {
    var rest = std.mem.trimStart(u8, line, " ");
    inline for (.{ "pub ", "export ", "inline " }) |prefix| {
        if (std.mem.startsWith(u8, rest, prefix)) rest = rest[prefix.len..];
    }
    if (!std.mem.startsWith(u8, rest, "fn ")) return null;
    rest = rest["fn ".len..];
    var length: usize = 0;
    while (length < rest.len and isIdentifierByte(rest[length])) length += 1;
    if (length == 0) return null;
    assert(length <= rest.len);
    return rest[0..length];
}

fn countCallers(
    arena: std.mem.Allocator,
    callers: *std.StringHashMapUnmanaged(u32),
    source: *const Source,
) !void {
    assert(source.lines.len == source.marks.len);
    for (source.lines, source.marks, source.owners) |full_line, mark, owner| {
        if (mark.in_test_block) continue;
        if (fnName(full_line) != null) continue;
        if (isHelperName(owner)) continue;
        // A comment naming a function is not a caller of it.
        const line = full_line[0..codeEnd(full_line)];
        var index: usize = 0;
        while (index < line.len) {
            if (!isIdentifierByte(line[index])) {
                index += 1;
                continue;
            }
            const start = index;
            while (index < line.len and isIdentifierByte(line[index])) index += 1;
            const identifier = line[start..index];
            if (std.mem.eql(u8, identifier, owner)) continue;
            const slot = try callers.getOrPut(arena, identifier);
            if (!slot.found_existing) slot.value_ptr.* = 0;
            slot.value_ptr.* += 1;
        }
        assert(index == line.len);
    }
}

/// Where a line's code ends: at a `//` outside any string literal, or the
/// line's end. A `//` inside a literal (a URL) is code, so the count never
/// loses a caller written after one.
fn codeEnd(line: []const u8) usize {
    var quotes: u32 = 0;
    var index: usize = 0;
    while (index + 1 < line.len) : (index += 1) {
        if (line[index] == '\\') {
            index += 1;
            continue;
        }
        if (line[index] == '"') quotes += 1;
        if (quotes % 2 == 0 and line[index] == '/' and line[index + 1] == '/') {
            assert(std.mem.startsWith(u8, line[index..], "//"));
            return index;
        }
    }
    assert(quotes <= line.len);
    return line.len;
}

/// Every placement and every harness path must name something under the
/// root: an entry that matches nothing sets nothing aside while reading as
/// though it did, and outlives the file it was written for.
fn tableHolds(tree: *const Tree) bool {
    assert(tree.sources.items.len >= 1);
    var holds = true;
    for (placements) |placement| {
        assert(placement.reason.len >= 1);
        for (tree.sources.items) |*source| {
            if (pathMatches(source.path, placement.path)) break;
        } else {
            std.debug.print("sim_gap: placement {s} names no file under the root\n", .{placement.path});
            holds = false;
        }
    }
    for (harness_paths, tree.harness_seen) |path, seen| {
        if (seen) continue;
        std.debug.print("sim_gap: harness path {s} names no file under the root\n", .{path});
        holds = false;
    }
    return holds;
}

/// Folds one kcov cobertura report into the tree's marks. kcov writes one
/// element per line, so a line scan is a complete parse of what it emits.
fn applyReport(arena: std.mem.Allocator, io: std.Io, tree: *Tree, path: []const u8, role: Role) !void {
    assert(path.len >= 1);
    const contents = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(report_bytes_max));
    var current: ?*Source = null;
    var classes: u32 = 0;
    var elements = std.mem.splitScalar(u8, contents, '\n');
    while (elements.next()) |raw| {
        const element = std.mem.trimStart(u8, raw, " \t");
        if (std.mem.startsWith(u8, element, "<class ")) {
            const name = attribute(element, "filename") orelse return error.MalformedReport;
            current = try sourceFor(tree, name);
            classes += 1;
        } else if (std.mem.startsWith(u8, element, "<line ")) {
            const source = current orelse continue;
            try markLine(source, element, role);
        }
    }
    if (classes == 0) {
        std.debug.print("sim_gap: {s} names no source file\n", .{path});
        return error.EmptyReport;
    }
    assert(classes >= 1);
}

/// The loaded source kcov's `filename` names; null for harness code. A
/// production file the walk did not load means the report and the root
/// disagree, and the report would be judged against the wrong tree.
fn sourceFor(tree: *Tree, name: []const u8) !?*Source {
    assert(name.len >= 1);
    if (isHarness(name)) return null;
    for (tree.sources.items) |*source| {
        if (std.mem.eql(u8, source.path, name)) return source;
    }
    std.debug.print("sim_gap: the report names {s}, which the root does not hold\n", .{name});
    return error.UnknownSource;
}

fn markLine(source: *Source, element: []const u8, role: Role) !void {
    assert(std.mem.startsWith(u8, element, "<line "));
    const number_text = attribute(element, "number") orelse return error.MalformedReport;
    const hits_text = attribute(element, "hits") orelse return error.MalformedReport;
    const number = try std.fmt.parseInt(u32, number_text, 10);
    const hits = try std.fmt.parseInt(u64, hits_text, 10);
    if (number == 0 or number > source.marks.len) {
        std.debug.print("sim_gap: {s} has no line {d}; is the report stale?\n", .{ source.path, number });
        return error.StaleReport;
    }
    const mark = &source.marks[number - 1];
    switch (role) {
        .sim => {
            mark.sim_instrumented = true;
            if (hits > 0) mark.sim_hit = true;
        },
        .tests => {
            mark.tests_instrumented = true;
            if (hits > 0) mark.tests_hit = true;
        },
    }
    assert(!mark.sim_hit or mark.sim_instrumented);
}

/// The value of `name="..."` in one XML element.
fn attribute(element: []const u8, comptime name: []const u8) ?[]const u8 {
    const needle = " " ++ name ++ "=\"";
    const start = (std.mem.indexOf(u8, element, needle) orelse return null) + needle.len;
    const length = std.mem.indexOfScalar(u8, element[start..], '"') orelse return null;
    assert(start + length <= element.len);
    return element[start .. start + length];
}

fn buildRows(arena: std.mem.Allocator, tree: *Tree) ![]Row {
    assert(tree.sources.items.len >= 1);
    const rows = try arena.alloc(Row, tree.sources.items.len);
    for (tree.sources.items, rows) |*source, *row| {
        const groups = try groupGaps(arena, tree, source);
        row.* = .{ .source = source, .tally = tallyOf(source, groups), .groups = groups };
    }
    std.mem.sort(Row, rows, {}, rowBefore);
    assert(rows.len == tree.sources.items.len);
    return rows;
}

/// The lines the tests run and the sim does not, grouped by owner and
/// judged per group.
fn groupGaps(arena: std.mem.Allocator, tree: *Tree, source: *const Source) ![]Group {
    assert(source.marks.len == source.owners.len);
    var groups: std.ArrayList(Group) = .empty;
    const loader = std.mem.eql(u8, source.path, loader_path);
    for (source.marks, source.owners, source.lines, 1..) |mark, owner, line, number| {
        if (!isGap(mark)) continue;
        const group = try groupFor(arena, &groups, owner, loader and isRefusal(line));
        try group.numbers.append(arena, @intCast(number));
    }
    for (groups.items) |*group| judge(tree, source, group);
    std.mem.sort(Group, groups.items, {}, groupBefore);
    assert(groups.items.len <= source.marks.len);
    return groups.items;
}

/// A group's kind, and for a serving-path one set apart, its reason.
fn judge(tree: *Tree, source: *const Source, group: *Group) void {
    assert(group.numbers.items.len >= 1);
    group.kind = kindOf(tree, source, group);
    if (group.kind == .test_helper) return;
    // Only the serving path's gaps are scenarios to widen; the others are
    // set apart whole by their placement.
    if (source.bucket != .serving) return;
    if (group.refusal) return exempt(group, refusal_reason);
    for (exemptions, &tree.exemptions_matched) |exemption, *matched| {
        if (!std.mem.eql(u8, exemption.path, source.path)) continue;
        if (!std.mem.eql(u8, exemption.owner, group.owner)) continue;
        assert(matched.* == 0); // One group per owner past its refusals.
        matched.* = @intCast(group.numbers.items.len);
        return exempt(group, exemption.reason);
    }
    if (group.kind == .unreferenced and (tree.serving_callers.get(group.owner) orelse 0) == 0) {
        assert((tree.callers.get(group.owner) orelse 0) >= 1);
        return exempt(group, startup_reason);
    }
}

fn exempt(group: *Group, reason: []const u8) void {
    assert(reason.len >= 1);
    assert(group.kind != .test_helper);
    group.kind = .exempt;
    group.reason = reason;
}

/// A loader line that does no more than refuse: `return error.X;`, alone
/// or after its condition, or a switch arm whose value is that refusal
/// (`.unix => return error.X,`, `error.A => return error.B,`).
fn isRefusal(line: []const u8) bool {
    const code = std.mem.trim(u8, line, " \r");
    assert(code.len <= line.len);
    if (std.mem.startsWith(u8, code, "return error.")) return true;
    if (std.mem.startsWith(u8, code, "if (")) return std.mem.indexOf(u8, code, ") return error.") != null;
    const arm = std.mem.indexOf(u8, code, " => return error.") orelse return false;
    // The arm's own value, and nothing after it but its comma.
    return std.mem.endsWith(u8, code, ",") and std.mem.indexOfScalar(u8, code[arm..], '(') == null;
}

/// The group for `owner` (its refusals apart), opened on its first gap
/// line. The pointer is good until the next group opens.
fn groupFor(arena: std.mem.Allocator, groups: *std.ArrayList(Group), owner: []const u8, refusal: bool) !*Group {
    assert(owner.len >= 1);
    for (groups.items) |*group| {
        if (group.refusal == refusal and std.mem.eql(u8, group.owner, owner)) return group;
    }
    try groups.append(arena, .{ .owner = owner, .kind = .unreferenced, .numbers = .empty, .refusal = refusal });
    const group = &groups.items[groups.items.len - 1];
    assert(group.numbers.items.len == 0);
    return group;
}

fn kindOf(tree: *const Tree, source: *const Source, group: *const Group) Kind {
    assert(group.numbers.items.len >= 1);
    for (group.numbers.items) |number| {
        if (source.marks[number - 1].sim_instrumented) return .executed_never;
    }
    if (isHelperName(group.owner)) return .test_helper;
    const named = tree.callers.get(group.owner) orelse 0;
    assert(group.owner.len >= 1);
    return if (named == 0) .test_helper else .unreferenced;
}

fn tallyOf(source: *const Source, groups: []const Group) Tally {
    var tally: Tally = .{};
    for (source.marks) |mark| {
        if (mark.in_test_block) continue;
        if (mark.sim_instrumented or mark.tests_instrumented) tally.instrumented += 1;
        if (mark.sim_hit) tally.sim_hit += 1;
    }
    for (groups) |*group| {
        const count: u32 = @intCast(group.numbers.items.len);
        switch (group.kind) {
            .executed_never => tally.executed_never += count,
            .unreferenced => tally.unreferenced += count,
            .test_helper => tally.test_helper += count,
            .exempt => tally.exempt += count,
        }
    }
    assert(tally.sim_hit <= tally.instrumented);
    assert(tally.gap() + tally.test_helper + tally.exempt <= tally.instrumented);
    return tally;
}

fn writeReport(writer: *std.Io.Writer, rows: []const Row) !void {
    assert(rows.len >= 1);
    try writer.writeAll(
        "sim gap: lines the unit tests reach and the simulator's sweep does not.\n" ++
            "Harness code, *_test.zig, Test*.zig and inline test blocks are left out.\n\n",
    );
    try writeTotals(writer, rows);
    try writePlacements(writer);
    try writeFiles(writer, rows);
    try writeFunctions(writer, rows);
    try writeExempt(writer, rows);
}

fn writeExempt(writer: *std.Io.Writer, rows: []const Row) !void {
    assert(rows.len >= 1);
    try writer.writeAll("\n== the serving-path lines set apart, with their reasons ==\n");
    for (rows) |*row| {
        if (row.source.bucket != .serving) continue;
        for (row.groups) |*group| {
            if (group.kind != .exempt) continue;
            assert(group.reason.len >= 1);
            try writer.print("  {s}:{s} ({d}): {s}\n", .{
                row.source.path, group.owner, group.numbers.items.len, group.reason,
            });
        }
    }
}

fn writeTotals(writer: *std.Io.Writer, rows: []const Row) !void {
    assert(rows.len >= 1);
    const labels = [_][]const u8{ "serving path", "startup only", "outside the model" };
    try writer.writeAll("== totals ==\n");
    for (std.enums.values(Bucket), labels) |bucket, label| {
        var tally: Tally = .{};
        for (rows) |*row| {
            if (row.source.bucket == bucket) tally.add(&row.tally);
        }
        if (tally.lines() == 0) continue;
        try writer.print("{s}: {d} lines ({d} test-helper lines set aside)\n", .{
            label, tally.lines(), tally.test_helper,
        });
        try writer.print("  sim reaches              {d: >6} ", .{tally.sim_hit});
        try writePercent(writer, tally.sim_hit, tally.lines());
        try writer.print("\n  set apart, reasons given {d: >6} ", .{tally.exempt});
        try writePercent(writer, tally.exempt, tally.lines());
        try writer.print("\n  tests only, unexplained  {d: >6} ", .{tally.gap()});
        try writePercent(writer, tally.gap(), tally.lines());
        try writer.print("\n    executed-never         {d: >6}\n    unreferenced           {d: >6}\n", .{
            tally.executed_never, tally.unreferenced,
        });
    }
    try writer.writeAll("\n");
}

fn writePlacements(writer: *std.Io.Writer) !void {
    assert(placements.len >= 1);
    try writer.writeAll("== set apart from the serving path ==\n");
    for (placements) |placement| {
        assert(placement.reason.len >= 1);
        try writer.print("  {s: <24} {s: <8} {s}\n", .{ placement.path, @tagName(placement.bucket), placement.reason });
    }
    try writer.writeAll("\n");
}

fn writeFiles(writer: *std.Io.Writer, rows: []const Row) !void {
    assert(rows.len >= 1);
    try writer.writeAll("== serving path per file, by lines only the tests reach ==\n");
    try writer.print("{s: <34} {s: >6} {s: >6} {s: >6} {s: >6} {s: >6}\n", .{
        "file", "lines", "sim", "gap", "never", "unref",
    });
    for (rows) |*row| {
        if (row.source.bucket != .serving) continue;
        if (row.tally.lines() == 0) continue;
        try writer.print("{s: <34} {d: >6} ", .{ row.source.path, row.tally.lines() });
        try writePercent(writer, row.tally.sim_hit, row.tally.lines());
        try writer.print(" {d: >6} {d: >6} {d: >6}\n", .{
            row.tally.gap(), row.tally.executed_never, row.tally.unreferenced,
        });
    }
    try writer.writeAll("\n");
}

fn writeFunctions(writer: *std.Io.Writer, rows: []const Row) !void {
    assert(rows.len >= 1);
    try writer.writeAll("== the serving-path gap by function ==\n" ++
        "N: compiled into the sim, never executed. U: the sim never compiled it.\n");
    for (rows) |*row| {
        if (row.source.bucket != .serving) continue;
        if (row.tally.gap() == 0) continue;
        try writer.print("\n{s} ({d} lines)\n", .{ row.source.path, row.tally.gap() });
        for (row.groups) |*group| {
            if (group.kind == .test_helper or group.kind == .exempt) continue;
            const tag: u8 = if (group.kind == .executed_never) 'N' else 'U';
            try writer.print("  {c} {d: >4}  {s: <40} ", .{ tag, group.numbers.items.len, group.owner });
            try writeRanges(writer, group.numbers.items);
            try writer.writeAll("\n");
        }
    }
}

/// `part / whole` rounded to one decimal place, without floats: `  5.3%`.
fn writePercent(writer: *std.Io.Writer, part: u32, whole: u32) !void {
    assert(whole >= 1);
    assert(part <= whole);
    const permille = (@as(u64, part) * 1000 + whole / 2) / whole;
    try writer.print("{d: >3}.{d}%", .{ permille / 10, permille % 10 });
}

/// Ascending line numbers as runs: `3-5,9`.
fn writeRanges(writer: *std.Io.Writer, numbers: []const u32) !void {
    assert(numbers.len >= 1);
    var start: usize = 0;
    while (start < numbers.len) {
        var end = start;
        while (end + 1 < numbers.len and numbers[end + 1] == numbers[end] + 1) end += 1;
        if (start > 0) try writer.writeAll(",");
        if (end == start) {
            try writer.print("{d}", .{numbers[start]});
        } else {
            try writer.print("{d}-{d}", .{ numbers[start], numbers[end] });
        }
        assert(end < numbers.len);
        start = end + 1;
    }
}

/// Serving-path files with the widest gap first; ties by path, so the
/// report is the same bytes for the same coverage.
fn rowBefore(_: void, left: Row, right: Row) bool {
    assert(left.tally.gap() <= left.tally.instrumented);
    assert(right.tally.gap() <= right.tally.instrumented);
    if (left.tally.gap() != right.tally.gap()) return left.tally.gap() > right.tally.gap();
    return std.mem.lessThan(u8, left.source.path, right.source.path);
}

fn groupBefore(_: void, left: Group, right: Group) bool {
    assert(left.numbers.items.len >= 1);
    assert(right.numbers.items.len >= 1);
    if (left.numbers.items.len != right.numbers.items.len) {
        return left.numbers.items.len > right.numbers.items.len;
    }
    return std.mem.lessThan(u8, left.owner, right.owner);
}

fn isGap(mark: Mark) bool {
    if (mark.sim_hit) assert(mark.sim_instrumented);
    if (mark.tests_hit) assert(mark.tests_instrumented);
    return mark.tests_hit and !mark.sim_hit and !mark.in_test_block;
}

fn bucketOf(path: []const u8) Bucket {
    assert(path.len >= 1);
    for (placements) |placement| {
        if (pathMatches(path, placement.path)) return placement.bucket;
    }
    return .serving;
}

fn isHarness(path: []const u8) bool {
    assert(path.len >= 1);
    const base = if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| path[slash + 1 ..] else path;
    if (std.mem.endsWith(u8, base, "_test.zig")) return true;
    if (std.mem.startsWith(u8, base, "Test")) return true;
    return harnessEntry(path) != null;
}

fn harnessEntry(path: []const u8) ?usize {
    assert(path.len >= 1);
    for (harness_paths, 0..) |entry, index| {
        if (pathMatches(path, entry)) return index;
    }
    return null;
}

/// A file entry matches itself; a directory entry (ending in '/')
/// matches everything under it.
fn pathMatches(path: []const u8, entry: []const u8) bool {
    assert(entry.len >= 1);
    if (entry[entry.len - 1] == '/') return std.mem.startsWith(u8, path, entry);
    return std.mem.eql(u8, path, entry);
}

fn isHelperName(name: []const u8) bool {
    for (helper_prefixes) |prefix| {
        assert(prefix.len >= 1);
        if (name.len <= prefix.len) continue;
        if (!std.mem.startsWith(u8, name, prefix)) continue;
        const next = name[prefix.len];
        if (std.ascii.isUpper(next) or next == '_') return true;
    }
    return false;
}

fn isIdentifierByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

test "testBlockIndent: headers at any indent, and nothing that only starts with test" {
    try std.testing.expectEqual(@as(?usize, 0), testBlockIndent("test \"a\" {"));
    try std.testing.expectEqual(@as(?usize, 4), testBlockIndent("    test {"));
    try std.testing.expectEqual(@as(?usize, null), testBlockIndent("testing.expect(x) {"));
    try std.testing.expectEqual(@as(?usize, null), testBlockIndent("test \"a\" { try x(); }"));
    try std.testing.expectEqual(@as(?usize, null), testBlockIndent("    const t = 1;"));
}

test "markTestBlocks: a block is header to closing brace, and the code around it is not" {
    const lines = [_][]const u8{
        "fn a() void {}",
        "test \"b\" {",
        "    if (x) {",
        "    }",
        "}",
        "fn c() void {}",
    };
    var marks: [lines.len]Mark = @splat(.{});
    try std.testing.expect(markTestBlocks(&lines, &marks));
    const expected = [_]bool{ false, true, true, true, true, false };
    for (marks, expected) |mark, inside| try std.testing.expectEqual(inside, mark.in_test_block);
}

test "markTestBlocks: a block that never closes is refused" {
    const lines = [_][]const u8{ "test \"b\" {", "    x();" };
    var marks: [lines.len]Mark = @splat(.{});
    try std.testing.expect(!markTestBlocks(&lines, &marks));
}

test "fnName: declarations with their qualifiers, and nothing else" {
    try std.testing.expectEqualStrings("render", fnName("    pub fn render(x: u8) void {").?);
    try std.testing.expectEqualStrings("hook", fnName("pub export fn hook() void {").?);
    try std.testing.expectEqualStrings("step", fnName("inline fn step() void {").?);
    try std.testing.expectEqual(@as(?[]const u8, null), fnName("    const f = fn_table[0];"));
    try std.testing.expectEqual(@as(?[]const u8, null), fnName("    // fn render is above"));
}

test "isHelperName: a prefix counts only as the start of a word" {
    try std.testing.expect(isHelperName("checkRequestParse"));
    try std.testing.expect(isHelperName("fuzzDowngrade"));
    try std.testing.expect(isHelperName("expect_client"));
    try std.testing.expect(!isHelperName("checked"));
    try std.testing.expect(!isHelperName("testing"));
    try std.testing.expect(!isHelperName("fuzz"));
}

test "attribute: kcov's element shapes" {
    const class = "<class name=\"host_zig__0\" filename=\"dns/host.zig\" line-rate=\"1.0\">";
    try std.testing.expectEqualStrings("dns/host.zig", attribute(class, "filename").?);
    const line = "<line number=\"12\" hits=\"0\"/>";
    try std.testing.expectEqualStrings("12", attribute(line, "number").?);
    try std.testing.expectEqualStrings("0", attribute(line, "hits").?);
    try std.testing.expectEqual(@as(?[]const u8, null), attribute(line, "filename"));
}

test "writeRanges: runs collapse, singletons stay" {
    var buffer: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writeRanges(&writer, &.{ 3, 4, 5, 9, 11, 12 });
    try std.testing.expectEqualStrings("3-5,9,11-12", writer.buffered());
}

test "bucketOf and isHarness: the tables route files where the report says" {
    try std.testing.expectEqual(Bucket.startup, bucketOf("json/loader.zig"));
    try std.testing.expectEqual(Bucket.outside, bucketOf("io/XevIo.zig"));
    try std.testing.expectEqual(Bucket.serving, bucketOf("net/Conn.zig"));
    try std.testing.expect(isHarness("http/h2/session_test.zig"));
    try std.testing.expect(isHarness("tls/TestClient.zig"));
    try std.testing.expect(isHarness("testing/origin.zig"));
    try std.testing.expect(!isHarness("io/XevIo.zig"));
}

test "isRefusal: a loader line that only returns an error" {
    try std.testing.expect(isRefusal("            return error.FilterClientPrefixTooNarrow;"));
    try std.testing.expect(isRefusal("    if (dns.refresh_min_ms > max) return error.ClusterDnsRefreshOutOfRange;"));
    try std.testing.expect(!isRefusal("    const value = try resolveThing(arena) orelse return error.X;"));
    try std.testing.expect(!isRefusal("    if (x) {"));
    try std.testing.expect(!isRefusal("    errdefer arena.free(x);"));
    try std.testing.expect(isRefusal("        .unix => return error.ListenerQuicBindNotIp,"));
    try std.testing.expect(isRefusal("    error.AnchorsInvalid, error.AnchorsTooMany => return error.ClusterTlsCaInvalid,"));
    try std.testing.expect(!isRefusal("    .ip => |ip| return error.X(ip),"));
}

test "codeEnd: a comment ends the code, a URL in a literal does not" {
    try std.testing.expectEqual(@as(usize, 12), codeEnd("    call(); // see `other`"));
    try std.testing.expectEqual(@as(usize, 0), codeEnd("/// `originTls` decides"));
    // A char literal's quote flips the parity: the comment is kept, which
    // over-counts callers — the direction that never hides a gap.
    const char_quote = "    x == '\"' // `f`";
    try std.testing.expectEqual(char_quote.len, codeEnd(char_quote));
    const url = "    const u = \"http://x\"; // note";
    try std.testing.expectEqual(std.mem.indexOf(u8, url, " //").? + 1, codeEnd(url));
    try std.testing.expectEqual(@as(usize, 10), codeEnd("    a = b;"));
}
