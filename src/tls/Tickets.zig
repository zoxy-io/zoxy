//! Stateless TLS 1.3 session tickets (DESIGN.md §4, PLANS.md 3a).
//!
//! A resumption ticket has to carry the session's PSK back to us. The
//! obvious shape is a server-side table keyed by ticket id — and that is
//! exactly what zoxy cannot have: a table sized for concurrent sessions
//! is memory that grows with traffic, and looking one up on the handshake
//! path is state the §5 budget would have to cover. So the ticket *is*
//! the state: the PSK is sealed into the bytes handed to the client, and
//! the server keeps only the key that seals them.
//!
//! That trade is what makes resumption free of per-session memory, and it
//! moves the security question onto the sealing key: anyone holding it
//! can recover every PSK it ever sealed. Hence two slots and rotation —
//! a key stops sealing before it stops opening, so tickets stay valid
//! across a rotation while the window in which any one key matters stays
//! bounded. Keys live in memory only: a restart invalidates every
//! outstanding ticket, which costs one full handshake per returning
//! client and keeps a stolen disk worthless.
//!
//! 0-RTT is deliberately not offered (`max_early_data_size` is never
//! set), so a replayed ticket buys an attacker a resumed handshake and
//! nothing else — no replayed application data. That is why these
//! tickets are multi-use: single-use would need the very table this
//! design exists to avoid.

const std = @import("std");

const ztls = @import("ztls");

const assert = std.debug.assert;

const Tickets = @This();

/// AES-256-GCM: a 32-byte key, 12-byte nonce, 16-byte tag. Chosen over
/// ChaCha20-Poly1305 because every target that runs zoxy in production
/// has AES-NI, and this is on the handshake path.
const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;
pub const key_bytes = Aead.key_length;
pub const nonce_bytes = Aead.nonce_length;
const tag_bytes = Aead.tag_length;

/// The largest PSK any supported suite derives (SHA-384).
pub const psk_bytes_max = 48;

/// Sealed plaintext: the PSK and what is needed to use it again.
const payload_bytes = 1 + psk_bytes_max + 2 + 8;

/// A sealed ticket on the wire: which key sealed it, the nonce, the
/// ciphertext, and the tag. Fixed size — the PSK length rides *inside*
/// the sealed payload rather than shortening the ticket, so a ticket's
/// length leaks nothing about the suite negotiated.
pub const ticket_bytes = 1 + nonce_bytes + payload_bytes + tag_bytes;

comptime {
    // The wire format caps an identity at 2^16-1, and ztls's client-side
    // `SessionTicket.identity` at 256. Neither is close, but a future
    // payload change should fail here rather than at runtime.
    assert(ticket_bytes <= 256);
}

/// One sealing key and the generation that names it. `id` is carried in
/// the clear so opening picks a key instead of trying both.
const Slot = struct {
    id: u8,
    key: [key_bytes]u8,
    /// False before the first `rotate`, so a ticket cannot be opened by
    /// an uninitialised slot.
    live: bool,
};

/// Two slots: the one sealing now, and the one it replaced. Anything
/// older cannot be opened, which is what bounds a key's exposure.
slots: [2]Slot,
current: u1,
/// Monotonic generation counter, so a wrapped `id` never lets a stale
/// ticket match a fresh key.
next_id: u8,

/// Seeded, never drawn from entropy here: the caller supplies key
/// material so the simulator is deterministic and production reads it
/// from the kernel (§9). Both slots start dead; `rotate` installs the
/// first key.
pub fn init(tickets: *Tickets) void {
    tickets.slots = @splat(.{ .id = 0, .key = @splat(0), .live = false });
    tickets.current = 0;
    tickets.next_id = 1;
}

/// Install `key` as the sealing key, demoting the previous one to
/// opening-only. Called at startup and on every rotation interval.
pub fn rotate(tickets: *Tickets, key: [key_bytes]u8) void {
    const next: u1 = if (tickets.current == 0) 1 else 0;
    tickets.slots[next] = .{ .id = tickets.next_id, .key = key, .live = true };
    tickets.current = next;
    // Skip 0 on wrap: it is the id of a dead slot.
    tickets.next_id = if (tickets.next_id == 255) 1 else tickets.next_id + 1;
    assert(tickets.slots[tickets.current].live);
}

/// True once a key has been installed; false means resumption is off.
pub fn ready(tickets: *const Tickets) bool {
    return tickets.slots[tickets.current].live;
}

pub const SealError = error{ NoKey, PskTooLong };

/// Seal `psk` and its suite into `out`, returning the ticket. `now_unix`
/// is stamped in so `open` can age it out.
pub fn seal(
    tickets: *const Tickets,
    out: *[ticket_bytes]u8,
    psk: []const u8,
    suite: ztls.CipherSuite,
    now_unix: u64,
    nonce: [nonce_bytes]u8,
) SealError![]const u8 {
    if (!tickets.ready()) return error.NoKey;
    if (psk.len > psk_bytes_max) return error.PskTooLong;
    assert(psk.len >= 1);

    var payload: [payload_bytes]u8 = @splat(0);
    payload[0] = @intCast(psk.len);
    @memcpy(payload[1..][0..psk.len], psk);
    std.mem.writeInt(u16, payload[1 + psk_bytes_max ..][0..2], @intFromEnum(suite), .big);
    std.mem.writeInt(u64, payload[1 + psk_bytes_max + 2 ..][0..8], now_unix, .big);

    const slot = &tickets.slots[tickets.current];
    out[0] = slot.id;
    @memcpy(out[1..][0..nonce_bytes], &nonce);
    var tag: [tag_bytes]u8 = undefined;
    Aead.encrypt(
        out[1 + nonce_bytes ..][0..payload_bytes],
        &tag,
        &payload,
        // The key id is authenticated, so a ticket cannot be replayed
        // against a different generation by editing one byte.
        out[0..1],
        nonce,
        slot.key,
    );
    @memcpy(out[1 + nonce_bytes + payload_bytes ..][0..tag_bytes], &tag);
    return out[0..];
}

/// What a ticket yields when it opens: the PSK (borrowed from the
/// caller's storage) and the suite it belongs to.
pub const Opened = struct {
    psk: []const u8,
    suite: ztls.CipherSuite,
};

/// Recover a ticket's contents, or null if it is not ours, not intact,
/// or too old. Every failure is null on purpose: a peer learns only that
/// resumption did not happen, never why, and the caller falls back to a
/// full handshake either way.
pub fn open(
    tickets: *const Tickets,
    ticket: []const u8,
    psk_out: *[psk_bytes_max]u8,
    now_unix: u64,
    lifetime_s: u32,
) ?Opened {
    if (ticket.len != ticket_bytes) return null;
    const key_id = ticket[0];
    const slot = tickets.slotFor(key_id) orelse return null;

    var nonce: [nonce_bytes]u8 = undefined;
    @memcpy(&nonce, ticket[1..][0..nonce_bytes]);
    var tag: [tag_bytes]u8 = undefined;
    @memcpy(&tag, ticket[1 + nonce_bytes + payload_bytes ..][0..tag_bytes]);

    var payload: [payload_bytes]u8 = undefined;
    Aead.decrypt(
        &payload,
        ticket[1 + nonce_bytes ..][0..payload_bytes],
        tag,
        ticket[0..1],
        nonce,
        slot.key,
    ) catch return null;

    const psk_len = payload[0];
    if (psk_len == 0 or psk_len > psk_bytes_max) return null;
    const suite_wire = std.mem.readInt(u16, payload[1 + psk_bytes_max ..][0..2], .big);
    const suite = ztls.CipherSuite.fromWire(suite_wire) orelse return null;
    const issued = std.mem.readInt(u64, payload[1 + psk_bytes_max + 2 ..][0..8], .big);

    // Expired, or issued in the future — a clock that went backwards is
    // not a reason to honour a ticket indefinitely.
    if (now_unix < issued) return null;
    if (now_unix - issued > lifetime_s) return null;

    @memcpy(psk_out[0..psk_len], payload[1..][0..psk_len]);
    return .{ .psk = psk_out[0..psk_len], .suite = suite };
}

fn slotFor(tickets: *const Tickets, id: u8) ?*const Slot {
    for (&tickets.slots) |*slot| {
        if (slot.live and slot.id == id) return slot;
    }
    return null;
}

const testing = std.testing;

fn testKey(fill: u8) [key_bytes]u8 {
    return @splat(fill);
}

test "tickets: a sealed ticket opens to what went into it" {
    var tickets: Tickets = undefined;
    tickets.init();
    tickets.rotate(testKey(0x11));

    const psk = [_]u8{0xab} ** 32;
    var buf: [ticket_bytes]u8 = undefined;
    const ticket = try tickets.seal(&buf, &psk, .aes_128_gcm_sha256, 1000, @splat(7));

    var psk_out: [psk_bytes_max]u8 = undefined;
    const opened = tickets.open(ticket, &psk_out, 1000, 3600) orelse
        return error.TestExpectedOpen;
    try testing.expectEqualSlices(u8, &psk, opened.psk);
    try testing.expectEqual(ztls.CipherSuite.aes_128_gcm_sha256, opened.suite);
}

test "tickets: sealing needs a key" {
    var tickets: Tickets = undefined;
    tickets.init();
    var buf: [ticket_bytes]u8 = undefined;
    try testing.expectError(
        error.NoKey,
        tickets.seal(&buf, &[_]u8{0x01} ** 32, .aes_128_gcm_sha256, 0, @splat(0)),
    );
}

test "tickets: a ticket outlives one rotation and not two" {
    var tickets: Tickets = undefined;
    tickets.init();
    tickets.rotate(testKey(0x11));

    const psk = [_]u8{0xcd} ** 32;
    var buf: [ticket_bytes]u8 = undefined;
    const sealed = try tickets.seal(&buf, &psk, .aes_128_gcm_sha256, 100, @splat(1));
    var ticket: [ticket_bytes]u8 = undefined;
    @memcpy(&ticket, sealed);

    var psk_out: [psk_bytes_max]u8 = undefined;
    // One rotation: the sealing key becomes the previous key, still able
    // to open. This is the point of two slots — a client holding a
    // ticket issued a moment ago does not lose it to a rotation tick.
    tickets.rotate(testKey(0x22));
    try testing.expect(tickets.open(&ticket, &psk_out, 100, 3600) != null);

    // Two rotations: the key is gone and so is the ticket.
    tickets.rotate(testKey(0x33));
    try testing.expect(tickets.open(&ticket, &psk_out, 100, 3600) == null);
}

test "tickets: an expired ticket does not open" {
    var tickets: Tickets = undefined;
    tickets.init();
    tickets.rotate(testKey(0x44));

    var buf: [ticket_bytes]u8 = undefined;
    const ticket = try tickets.seal(&buf, &[_]u8{0x01} ** 32, .aes_128_gcm_sha256, 100, @splat(2));

    var psk_out: [psk_bytes_max]u8 = undefined;
    try testing.expect(tickets.open(ticket, &psk_out, 100 + 3600, 3600) != null);
    try testing.expect(tickets.open(ticket, &psk_out, 100 + 3601, 3600) == null);
    // A clock that ran backwards is not a licence to honour it forever.
    try testing.expect(tickets.open(ticket, &psk_out, 99, 3600) == null);
}

test "tickets: a tampered ticket does not open" {
    var tickets: Tickets = undefined;
    tickets.init();
    tickets.rotate(testKey(0x55));

    var buf: [ticket_bytes]u8 = undefined;
    const sealed = try tickets.seal(&buf, &[_]u8{0x02} ** 32, .aes_128_gcm_sha256, 0, @splat(3));
    var psk_out: [psk_bytes_max]u8 = undefined;

    // Every byte matters: the key id is authenticated data, the rest is
    // ciphertext or tag.
    for (0..ticket_bytes) |index| {
        var ticket: [ticket_bytes]u8 = undefined;
        @memcpy(&ticket, sealed);
        ticket[index] ^= 0xff;
        try testing.expect(tickets.open(&ticket, &psk_out, 0, 3600) == null);
    }
}

test "tickets: a ticket from another server does not open" {
    var mine: Tickets = undefined;
    mine.init();
    mine.rotate(testKey(0x66));
    var theirs: Tickets = undefined;
    theirs.init();
    theirs.rotate(testKey(0x77));

    var buf: [ticket_bytes]u8 = undefined;
    const ticket = try theirs.seal(&buf, &[_]u8{0x03} ** 32, .aes_128_gcm_sha256, 0, @splat(4));

    var psk_out: [psk_bytes_max]u8 = undefined;
    try testing.expect(mine.open(ticket, &psk_out, 0, 3600) == null);
}

test "tickets: a wrong-sized identity is not a ticket" {
    var tickets: Tickets = undefined;
    tickets.init();
    tickets.rotate(testKey(0x88));
    var psk_out: [psk_bytes_max]u8 = undefined;
    try testing.expect(tickets.open(&.{}, &psk_out, 0, 3600) == null);
    try testing.expect(tickets.open(&[_]u8{0} ** 8, &psk_out, 0, 3600) == null);
    try testing.expect(tickets.open(&[_]u8{0} ** 512, &psk_out, 0, 3600) == null);
}

test "tickets: a ticket's length says nothing about the suite" {
    var tickets: Tickets = undefined;
    tickets.init();
    tickets.rotate(testKey(0x99));

    var short_buf: [ticket_bytes]u8 = undefined;
    var long_buf: [ticket_bytes]u8 = undefined;
    const short = try tickets.seal(&short_buf, &[_]u8{1} ** 32, .aes_128_gcm_sha256, 0, @splat(5));
    const long = try tickets.seal(&long_buf, &[_]u8{2} ** 48, .aes_256_gcm_sha384, 0, @splat(6));
    try testing.expectEqual(short.len, long.len);
}
