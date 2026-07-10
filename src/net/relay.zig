//! Relay buffers and (slice 8) the strict recv → send → recv relay
//! (DESIGN.md §6). The buffer pair is pooled separately from connection
//! slots — buffers are sized for concurrent *relays*, not for open
//! connections (§5). On the L4 path a buffer is acquired at admission
//! and held for the connection's life: a recv must always have a buffer
//! posted, so `relay_buffers_max`, not conn slots, bounds concurrent L4
//! connections.

const std = @import("std");

const constants = @import("../constants.zig");

const assert = std.debug.assert;

pub const RelayBuffer = struct {
    pool_next: u32,
    generation: u32,
    client_to_upstream: [constants.relay_buffer_bytes]u8,
    upstream_to_client: [constants.relay_buffer_bytes]u8,
};

comptime {
    assert(@sizeOf(RelayBuffer) >= 2 * constants.relay_buffer_bytes);
}
