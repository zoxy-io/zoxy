//! By convention, root.zig is the root source file when making a package.
const std = @import("std");
const Io = std.Io;

/// This is a documentation comment to explain the `printAnotherMessage` function below.
///
/// Accepting an `Io.Writer` instance is a handy way to write reusable code.
pub fn printAnotherMessage(writer: *Io.Writer) Io.Writer.Error!void {
    try writer.print("Run `zig build test` to run the tests.\n", .{});
}

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

/// The completion-based io_uring layer (docs/DESIGN.md "I/O architecture").
pub const io = @import("io/io.zig");

/// A SO_REUSEPORT TCP listener (docs/DESIGN.md §2).
pub const Listener = @import("net/listener.zig").Listener;

/// Static limits (docs/TIGER_STYLE.md: "put a limit on everything").
pub const constants = @import("constants.zig");

/// Fixed connection pool + Phase-0 echo server (docs/DESIGN.md §4).
pub const connection = @import("net/connection.zig");

test "basic add functionality" {
    try std.testing.expect(add(3, 7) == 10);
}

test {
    _ = io;
    _ = @import("net/listener.zig");
    _ = connection;
}
