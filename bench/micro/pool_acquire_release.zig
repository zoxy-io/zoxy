//! Tier-0 micro bench (§9): the pool acquire/release hot pair in a fixed
//! loop, for poop A/B runs on hardware counters — decision tool, not a
//! CI gate. Example:
//!
//!   zig build bench-micro
//!   poop ./zig-out/bin/zoxy-bench-pool ./new/zoxy-bench-pool

const std = @import("std");

const zoxy = @import("zoxy");

const iterations: u64 = 50_000_000;
const slots: u32 = 1024;

const Item = struct {
    pool_next: u32,
    generation: u32,
    payload: [56]u8,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    var pool: zoxy.Pool(Item) = undefined;
    try pool.init(arena, slots);

    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        const item = pool.acquire() orelse unreachable;
        checksum +%= item.generation;
        pool.release(item);
    }
    // The checksum defeats dead-code elimination and doubles as a sanity
    // check: every release bumps the generation exactly once.
    std.debug.print("checksum {d}\n", .{checksum});
}
