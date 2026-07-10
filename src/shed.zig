//! The exhaustion ladder's shed actions (DESIGN.md §8). Un-admitted
//! sheds are synchronous: the socket has no slot, so there is no
//! completion to embed and no ring op to spend — shedding costs at most
//! two direct syscalls and the accept stays armed.

const std = @import("std");

const assert = std.debug.assert;

/// Conn-slots-exhausted rung: close immediately with SO_LINGER-0 so the
/// client gets an RST — an immediate signal instead of a timeout, and
/// the kernel backlog stays drained (§8).
pub fn closeWithRst(comptime IoType: type, io: *IoType, socket: IoType.Socket) void {
    // If the option fails the close must still happen: shedding never
    // blocks and never errors (§8); the peer then sees FIN, not RST.
    io.setLingerRst(socket) catch {};
    io.closeNow(socket);
}

/// Relay-buffers-exhausted rung: plain immediate close (§8 table).
pub fn closeQuietly(comptime IoType: type, io: *IoType, socket: IoType.Socket) void {
    io.closeNow(socket);
}
