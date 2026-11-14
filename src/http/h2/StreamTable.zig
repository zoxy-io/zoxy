//! The streams one HTTP/2 connection has open (#275): a fixed array of
//! slots the caller owns, sized by the concurrency this connection
//! advertises, looked up by identifier with a bounded scan.
//!
//! A scan rather than a map because the bound is small and stated — it is
//! SETTINGS_MAX_CONCURRENT_STREAMS — and a frame costs the scan once. The
//! protocol state lives here; the heavy per-stream resources (the `Stream`
//! slot, its relay buffer, its upstream) are the server's, drawn from pools
//! sized for concurrent activity rather than per connection.

const std = @import("std");
const h2 = @import("h2");

const assert = std.debug.assert;

const StreamTable = @This();

pub const Slot = struct {
    /// Zero marks a free slot: stream zero is the connection's, never a
    /// stream's.
    id: u31,
    state: State,
    /// Receive-side flow control, in the connection's three-way split:
    /// what the client may still send, what the caller consumed and this
    /// side has not credited back, and what was handed to the caller and
    /// not yet consumed. The three always sum to this stream's window.
    recv_window: i64,
    recv_unacked: u32,
    recv_delivered: u32,
    /// What the client's WINDOW_UPDATEs and SETTINGS allow this side to
    /// send on the stream.
    send_window: i64,
    /// The request's `content-length`, and the DATA octets seen against it
    /// (RFC 9113 §8.1.1).
    content_length: ?u64,
    data_received: u64,
    /// What a `.reset_pending` stream's RST_STREAM will say.
    reset_code: h2.frame.ErrorCode,

    pub const State = enum(u8) {
        /// The client may still send DATA and trailers.
        open,
        /// The client sent END_STREAM (§5.1); only this side has more to say.
        half_closed_remote,
        /// The caller reset it. RST_STREAM goes out when the outbox has
        /// room, and the slot is free after that.
        reset_pending,
    };

    const free: Slot = .{
        .id = 0,
        .state = .open,
        .recv_window = 0,
        .recv_unacked = 0,
        .recv_delivered = 0,
        .send_window = 0,
        .content_length = null,
        .data_received = 0,
        .reset_code = .no_error,
    };
};

slots: []Slot,
used: u32,

pub fn init(slots: []Slot) StreamTable {
    assert(slots.len >= 1);
    assert(slots.len <= std.math.maxInt(u32));
    for (slots) |*slot| slot.* = Slot.free;
    return .{ .slots = slots, .used = 0 };
}

/// The slot carrying `id`, or null when no open stream has it.
pub fn find(table: *StreamTable, id: u31) ?*Slot {
    assert(id != 0);
    assert(table.used <= table.slots.len);
    for (table.slots) |*slot| {
        if (slot.id == id) return slot;
    }
    return null;
}

/// A free slot claimed for `id`, or null when every slot is in use — the
/// answer that becomes REFUSED_STREAM. The caller fills in the rest.
pub fn acquire(table: *StreamTable, id: u31) ?*Slot {
    assert(id != 0);
    assert(table.find(id) == null);
    if (table.used == table.slots.len) return null;
    for (table.slots) |*slot| {
        if (slot.id != 0) continue;
        slot.* = Slot.free;
        slot.id = id;
        table.used += 1;
        return slot;
    }
    unreachable; // `used` below the length means a free slot exists.
}

pub fn release(table: *StreamTable, slot: *Slot) void {
    assert(slot.id != 0);
    assert(table.used >= 1);
    // This table's slot, not another connection's.
    assert(@intFromPtr(slot) >= @intFromPtr(table.slots.ptr));
    assert(@intFromPtr(slot) < @intFromPtr(table.slots.ptr + table.slots.len));
    slot.* = Slot.free;
    table.used -= 1;
}

test "stream table: acquire to the bound, find, release, reuse" {
    var storage: [2]Slot = undefined;
    var table = StreamTable.init(&storage);
    const one = table.acquire(1).?;
    const three = table.acquire(3).?;
    try std.testing.expect(table.acquire(5) == null);
    try std.testing.expectEqual(one, table.find(1).?);
    try std.testing.expectEqual(three, table.find(3).?);
    table.release(one);
    try std.testing.expect(table.find(1) == null);
    const five = table.acquire(5).?;
    try std.testing.expectEqual(one, five);
    try std.testing.expectEqual(@as(u32, 2), table.used);
}
