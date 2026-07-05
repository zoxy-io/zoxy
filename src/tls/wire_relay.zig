//! The sans-io "wire half" of a userspace TLS connection: the ciphertext staging
//! between the ring's recv/send ops and the record layer's BIO pair
//! (`terminator.Channel`, the sans-io "record half"). Owns the two wire buffers,
//! the staged/filled/sent counters, and the two in-flight flags, plus the pure
//! ciphertext-pump math.
//!
//! It holds no io, no `Completion`, and no refcount, and knows nothing of
//! fds/legs/sides/callbacks/policy — the owner (`ProxyConn.Tls` / `H2Conn`) drives
//! the ring and keeps all of that. Channel-touching methods take `channel: anytype`
//! (duck-typed on `feed_ciphertext`/`drain_ciphertext`/`pending_ciphertext`), so this
//! type is OpenSSL-free and unit-testable against a fake byte-queue channel — the
//! only coverage this code gets that is not a full TLS integration test (the
//! simulator runs plaintext only).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const WireRelay = struct {
    /// wire → BIO: ciphertext read off the socket, waiting to feed the record layer.
    wire_recv_buf: [constants.tls_bio_pair_bytes]u8 = undefined,
    wire_recv_staged: u32 = 0,
    wire_recv_in_flight: bool = false,
    /// BIO → wire: ciphertext drained from the record layer, waiting to send.
    wire_send_buf: [constants.tls_bio_pair_bytes]u8 = undefined,
    wire_send_filled: u32 = 0,
    wire_send_sent: u32 = 0,
    wire_send_in_flight: bool = false,

    /// Clear the staging state field by field. NEVER a struct assignment: that
    /// would dirty the two 18 KiB buffers even on a connection that never speaks
    /// TLS (legs live in a pool; touched pages are the cost).
    pub fn reset(wire: *WireRelay) void {
        wire.wire_recv_staged = 0;
        wire.wire_recv_in_flight = false;
        wire.wire_send_filled = 0;
        wire.wire_send_sent = 0;
        wire.wire_send_in_flight = false;
    }

    /// Adopt a coalesced ciphertext preface (the h2 handoff): seed the recv buffer
    /// with bytes already read on the donor leg, before any recv of our own.
    pub fn seed_staged(wire: *WireRelay, ciphertext: []const u8) void {
        assert(ciphertext.len <= wire.wire_recv_buf.len);
        assert(wire.wire_recv_staged == 0); // only at adoption
        @memcpy(wire.wire_recv_buf[0..ciphertext.len], ciphertext);
        wire.wire_recv_staged = @intCast(ciphertext.len);
    }

    // ---- recv side ----------------------------------------------------------

    /// The free tail of the recv buffer, where the next io.recv stages bytes. The
    /// owner guards `!staging_full()` before arming.
    pub fn recv_slot(wire: *WireRelay) []u8 {
        assert(wire.wire_recv_staged < wire.wire_recv_buf.len);
        return wire.wire_recv_buf[wire.wire_recv_staged..];
    }

    /// Record `n` bytes just read onto the wire.
    pub fn note_recv(wire: *WireRelay, n: usize) void {
        assert(n > 0); // callers route a 0-length read to EOF, not here
        wire.wire_recv_staged += @intCast(n);
        assert(wire.wire_recv_staged <= wire.wire_recv_buf.len);
    }

    pub fn begin_recv(wire: *WireRelay) void {
        assert(!wire.wire_recv_in_flight); // one recv at a time (seed-1693)
        wire.wire_recv_in_flight = true;
    }

    pub fn end_recv(wire: *WireRelay) void {
        wire.wire_recv_in_flight = false;
    }

    /// Feed staged ciphertext into the record layer's BIO, then compact any
    /// remainder to the front (the pair may take only a partial flight). Returns
    /// the bytes fed.
    pub fn feed_staged(wire: *WireRelay, channel: anytype) u32 {
        if (wire.wire_recv_staged == 0) return 0;
        const fed: u32 = @intCast(
            channel.feed_ciphertext(wire.wire_recv_buf[0..wire.wire_recv_staged]),
        );
        assert(fed <= wire.wire_recv_staged);
        if (fed == 0) return 0; // pair full: reads will drain it
        if (fed < wire.wire_recv_staged) {
            std.mem.copyForwards(
                u8,
                wire.wire_recv_buf[0 .. wire.wire_recv_staged - fed],
                wire.wire_recv_buf[fed..wire.wire_recv_staged],
            );
        }
        wire.wire_recv_staged -= fed;
        return fed;
    }

    pub fn recv_in_flight(wire: *const WireRelay) bool {
        return wire.wire_recv_in_flight;
    }

    pub fn recv_idle(wire: *const WireRelay) bool {
        return !wire.wire_recv_in_flight;
    }

    pub fn staging_full(wire: *const WireRelay) bool {
        return wire.wire_recv_staged == wire.wire_recv_buf.len;
    }

    pub fn staged_empty(wire: *const WireRelay) bool {
        return wire.wire_recv_staged == 0;
    }

    pub fn staged_bytes(wire: *const WireRelay) []const u8 {
        return wire.wire_recv_buf[0..wire.wire_recv_staged];
    }

    // ---- send side ----------------------------------------------------------

    /// Ensure the send buffer holds ciphertext to send: when the last flight fully
    /// sent, drain a fresh one from the record layer. Returns whether any bytes are
    /// pending.
    pub fn refill_send(wire: *WireRelay, channel: anytype) bool {
        if (wire.wire_send_sent == wire.wire_send_filled) {
            wire.wire_send_filled = @intCast(channel.drain_ciphertext(&wire.wire_send_buf));
            wire.wire_send_sent = 0;
        }
        return wire.wire_send_sent < wire.wire_send_filled;
    }

    /// The unsent tail of the current ciphertext flight.
    pub fn send_pending(wire: *const WireRelay) []const u8 {
        assert(wire.wire_send_sent < wire.wire_send_filled);
        return wire.wire_send_buf[wire.wire_send_sent..wire.wire_send_filled];
    }

    pub fn note_sent(wire: *WireRelay, m: usize) void {
        wire.wire_send_sent += @intCast(m);
        assert(wire.wire_send_sent <= wire.wire_send_filled);
    }

    pub fn begin_send(wire: *WireRelay) void {
        assert(!wire.wire_send_in_flight);
        wire.wire_send_in_flight = true;
    }

    pub fn end_send(wire: *WireRelay) void {
        wire.wire_send_in_flight = false;
    }

    pub fn send_in_flight(wire: *const WireRelay) bool {
        return wire.wire_send_in_flight;
    }

    pub fn send_idle(wire: *const WireRelay) bool {
        return !wire.wire_send_in_flight and wire.wire_send_sent == wire.wire_send_filled;
    }

    // ---- composites ---------------------------------------------------------

    /// No wire op pending and the record layer's pair is empty — but staged
    /// ciphertext may remain (a coalesced h2 preface). For the kTLS switch and the
    /// h2 handoff, which carry that preface across.
    pub fn drained(wire: *const WireRelay, channel: anytype) bool {
        return wire.recv_idle() and wire.send_idle() and channel.pending_ciphertext() == 0;
    }

    /// Fully quiescent: drained AND nothing staged. For parking an upstream leg.
    pub fn quiescent(wire: *const WireRelay, channel: anytype) bool {
        return wire.drained(channel) and wire.staged_empty();
    }
};

// ---- tests ------------------------------------------------------------------

/// A fake record layer for the io-free unit tests: a fixed byte queue standing in
/// for the BIO pair. `feed_ciphertext` accepts up to `cap`, returning a short count
/// when full (the real pair-full path); `drain_ciphertext` hands pending bytes back.
const FakeChannel = struct {
    buf: [64]u8 = undefined,
    len: usize = 0,
    cap: usize = 64,

    fn feed_ciphertext(channel: *FakeChannel, ciphertext: []const u8) usize {
        const take = @min(channel.cap - channel.len, ciphertext.len);
        @memcpy(channel.buf[channel.len..][0..take], ciphertext[0..take]);
        channel.len += take;
        return take;
    }

    fn drain_ciphertext(channel: *FakeChannel, out: []u8) usize {
        const give = @min(channel.len, out.len);
        @memcpy(out[0..give], channel.buf[0..give]);
        std.mem.copyForwards(u8, channel.buf[0 .. channel.len - give], channel.buf[give..channel.len]);
        channel.len -= give;
        return give;
    }

    fn pending_ciphertext(channel: *const FakeChannel) usize {
        return channel.len;
    }
};

test "wire relay: feed_staged compacts the remainder of a partial feed" {
    var channel = FakeChannel{ .cap = 10 }; // pair takes only 10 of our staged bytes
    var wire = WireRelay{};
    wire.reset();

    @memcpy(wire.recv_slot()[0..16], "0123456789ABCDEF");
    wire.note_recv(16);
    try std.testing.expectEqual(@as(u32, 16), wire.wire_recv_staged);

    const fed = wire.feed_staged(&channel);
    try std.testing.expectEqual(@as(u32, 10), fed);
    try std.testing.expectEqual(@as(u32, 6), wire.wire_recv_staged);
    // The unfed tail moved to the front, ready to retry.
    try std.testing.expectEqualStrings("ABCDEF", wire.staged_bytes());

    channel.len = 0; // pair drained: the rest fits now
    try std.testing.expectEqual(@as(u32, 6), wire.feed_staged(&channel));
    try std.testing.expect(wire.staged_empty());
    try std.testing.expectEqual(@as(u32, 0), wire.feed_staged(&channel)); // nothing left
}

test "wire relay: refill_send drains, then tracks partial sends" {
    var channel = FakeChannel{};
    @memcpy(channel.buf[0..5], "hello");
    channel.len = 5;
    var wire = WireRelay{};
    wire.reset();

    try std.testing.expect(wire.refill_send(&channel));
    try std.testing.expectEqualStrings("hello", wire.send_pending());
    try std.testing.expect(!wire.send_idle()); // bytes pending

    wire.note_sent(2); // partial write
    try std.testing.expectEqualStrings("llo", wire.send_pending());
    try std.testing.expect(wire.refill_send(&channel)); // still the same flight, no re-drain
    try std.testing.expectEqualStrings("llo", wire.send_pending());

    wire.note_sent(3);
    try std.testing.expect(!wire.refill_send(&channel)); // pair empty now
    try std.testing.expect(wire.send_idle());
}

test "wire relay: recv slot, staging-full, and seed_staged adoption" {
    var wire = WireRelay{};
    wire.reset();
    try std.testing.expect(wire.staged_empty());
    try std.testing.expectEqual(wire.wire_recv_buf.len, wire.recv_slot().len);

    var adopted = WireRelay{};
    adopted.reset();
    adopted.seed_staged("preface-bytes");
    try std.testing.expectEqualStrings("preface-bytes", adopted.staged_bytes());
    try std.testing.expect(!adopted.staged_empty());
}

test "wire relay: in-flight toggles and the quiescence predicates" {
    var channel = FakeChannel{};
    var wire = WireRelay{};
    wire.reset();

    // Idle + empty pair ⇒ drained and quiescent.
    try std.testing.expect(wire.recv_idle() and wire.send_idle());
    try std.testing.expect(wire.drained(&channel) and wire.quiescent(&channel));

    wire.begin_recv();
    try std.testing.expect(wire.recv_in_flight() and !wire.recv_idle());
    try std.testing.expect(!wire.drained(&channel));
    wire.end_recv();
    try std.testing.expect(wire.recv_idle());

    // Staged bytes break `quiescent` but not `drained` (the h2-preface case).
    adopt: {
        @memcpy(wire.recv_slot()[0..3], "abc");
        wire.note_recv(3);
        break :adopt;
    }
    try std.testing.expect(wire.drained(&channel));
    try std.testing.expect(!wire.quiescent(&channel));

    // Unsent ciphertext or a pending pair breaks send-idle / drained.
    channel.len = 4;
    try std.testing.expect(!wire.drained(&channel));
}
