//! zoxy — bullet-proof L4/L7 proxy (see docs/DESIGN.md). This module root
//! re-exports the library surface and references every source file so that
//! `zig build test` compiles and runs all tests.

const std = @import("std");

pub const constants = @import("constants.zig");
pub const Pool = @import("mem/Pool.zig").Pool;

test {
    _ = constants;
    _ = @import("mem/Pool.zig");
    _ = @import("io/xev_smoke_test.zig");
}
