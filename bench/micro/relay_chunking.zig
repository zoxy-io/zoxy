//! Tier-0 micro bench (§9): the relay's per-chunk byte movement — copy
//! through a RelayBuffer pair at realistic chunk sizes — for poop A/B on
//! hardware counters. Decision tool, not a CI gate.

const std = @import("std");

const zoxy = @import("zoxy");

const iterations: u64 = 200_000;
const half_bytes = zoxy.constants.relay_buffer_bytes_default;
const chunk_sizes = [_]u32{ 1, 128, 1460, half_bytes };

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    // The halves are slab-backed now (`limits.relay_buffer_bytes`), so the
    // bench carves its own pair rather than getting them inline.
    const buffer = try arena.create(zoxy.RelayBuffer);
    buffer.client_to_upstream = try arena.alloc(u8, half_bytes);
    buffer.upstream_to_client = try arena.alloc(u8, half_bytes);
    var source: [half_bytes]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().bytes(&source);

    var checksum: u64 = 0;
    var index: u64 = 0;
    while (index < iterations) : (index += 1) {
        inline for (chunk_sizes) |chunk| {
            @memcpy(buffer.client_to_upstream[0..chunk], source[0..chunk]);
            @memcpy(buffer.upstream_to_client[0..chunk], buffer.client_to_upstream[0..chunk]);
            checksum +%= buffer.upstream_to_client[chunk - 1];
        }
    }
    std.debug.print("checksum {d}\n", .{checksum});
}
