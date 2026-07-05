//! Line-length lint for the TigerStyle 100-column hard limit
//! (docs/TIGER_STYLE.md). Fails if any file passed as an argument holds a line
//! wider than the limit. Columns are counted as Unicode scalar values, so a
//! multi-byte glyph (e.g. `§` or `↔` in a comment) counts as one column —
//! closer to display width than a raw byte count, and `zig fmt` already
//! forbids tabs, so the scalar count is a faithful column measure here.
//!
//! Run via `zig build lint`; build.zig discovers every checked source file and
//! passes its path as an argument. Kept in Zig, not shell, per the project's
//! tooling convention (docs/TIGER_STYLE.md, "Project policy").

const std = @import("std");
const assert = std.debug.assert;

const columns_max = 100;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const paths = try init.minimal.args.toSlice(gpa);
    assert(paths.len >= 1); // argv always carries the program path

    var offenders: u32 = 0;
    // paths[0] is this tool's own path; the rest are files to check.
    for (paths[1..]) |path| {
        const text = std.Io.Dir.cwd().readFileAlloc(init.io, path, gpa, .unlimited) catch |err| {
            std.log.err("lint: cannot read {s}: {s}", .{ path, @errorName(err) });
            return err;
        };
        var line_number: u32 = 0;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            line_number += 1;
            const columns = column_count(line);
            if (columns > columns_max) {
                offenders += 1;
                std.log.err("{s}:{d}: {d} columns (limit {d})", .{
                    path,
                    line_number,
                    columns,
                    columns_max,
                });
            }
        }
        assert(line_number >= 1); // even an empty file yields one (empty) line
    }

    if (offenders > 0) {
        std.log.err(
            "{d} line(s) exceed the {d}-column TigerStyle limit",
            .{ offenders, columns_max },
        );
        std.process.exit(1);
    }
}

/// Columns as Unicode scalar values; falls back to the byte length for a line
/// that is not valid UTF-8, so a broken encoding is flagged, not hidden.
fn column_count(line: []const u8) usize {
    const view = std.unicode.Utf8View.init(line) catch return line.len;
    var scalars: usize = 0;
    var it = view.iterator();
    while (it.nextCodepoint()) |_| scalars += 1;
    assert(scalars <= line.len); // every scalar spans at least one byte
    return scalars;
}
