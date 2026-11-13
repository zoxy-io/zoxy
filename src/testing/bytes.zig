//! Comptime byte patterns for the tests and the simulator.

const std = @import("std");

const assert = std.debug.assert;

/// `pattern` written out `count` times, at comptime — what `pattern ** count`
/// spelled before Zig 0.17 removed the operator. `@splat` replaces it where
/// one element repeats into a typed array; this covers byte strings, whose
/// pattern can be several bytes and whose result is concatenated with `++`.
///
/// Sentinel-terminated, like the string literal it stands in for, so every
/// site keeps the exact type `**` gave it rather than merely a compatible one.
/// `inline` because most callers are test bodies: a plain call from a
/// runtime scope is a runtime call, and its result could not feed `++`.
pub inline fn repeat(comptime pattern: []const u8, comptime count: usize) *const [pattern.len * count:0]u8 {
    return comptime written: {
        assert(pattern.len > 0);
        assert(count > 0);
        // No loop, so no branch quota to raise: a loop's backward branches
        // count against the whole calling scope, so two long fillers in
        // one test would add up past any quota sized for either alone.
        const rows: [count][pattern.len]u8 = @splat(pattern[0..pattern.len].*);
        const flat: [pattern.len * count]u8 = @bitCast(rows);
        var out: [pattern.len * count:0]u8 = undefined;
        @memcpy(out[0..flat.len], &flat);
        out[out.len] = 0;
        const final = out;
        break :written &final;
    };
}

test "repeat writes the pattern out count times, sentinel included" {
    const one = repeat("x", 3);
    comptime std.debug.assert(@TypeOf(one) == *const [3:0]u8);
    const concatenated = "/" ++ repeat("a", 2) ++ "\r\n";
    try std.testing.expectEqualStrings("/aa\r\n", concatenated);
    try std.testing.expectEqualStrings("xxx", one);
    try std.testing.expectEqual(0, one[one.len]);
    const several = repeat("ab\r\n", 2);
    try std.testing.expectEqualStrings("ab\r\nab\r\n", several);
    try std.testing.expectEqual(*const [8:0]u8, @TypeOf(several));
}
