//! zoxy — bullet-proof L4/L7 proxy (see docs/DESIGN.md). This module root
//! re-exports the library surface and references every source file so that
//! `zig build test` compiles and runs all tests.

const std = @import("std");

pub const config = @import("config.zig");
pub const constants = @import("constants.zig");
pub const Io = @import("io/Io.zig");
pub const Pool = @import("mem/Pool.zig").Pool;

test {
    _ = config;
    _ = constants;
    _ = Io;
    _ = @import("mem/Pool.zig");
    _ = @import("io/contract_test.zig");
    _ = @import("io/sim_io_test.zig");
    _ = @import("io/xev_smoke_test.zig");
}
