//! The Phase 3a TLS engine (DESIGN.md §4, PLANS.md): the zoxy-shaped seam
//! over ztls's sans-I/O TLS 1.3 server. Static caller-owned buffers, key
//! material injected as plain data (deterministic under the simulator),
//! zero allocation in the wrapper (libcrypto's own allocations ride the
//! fixed heap of slice 1). ~180 KiB per instance (IMPLEMENTATION_NOTES.md),
//! so the serving path holds these in a shared `Pool`, not one per conn
//! slot — that pooling, the §8 handshake budget, and the drive-API
//! coupling to `Conn` land with the data-path slices (PLANS.md 3a 4–5);
//! this module is the engine those slices drive, exercised until then by
//! the spike and heap-proof tests.
//!
//! The drive shape: `feed` ciphertext in, plaintext out through `Sink`
//! (synchronous), ciphertext out through `outbound`/`outboundSent` (an
//! engine-owned outbox the transport drains at its own pace, partial
//! writes included). Wire and plaintext travel differently on purpose —
//! see `Sink`.
//!
//! Ownership rules the ztls API imposes, encoded here so callers inherit
//! them:
//! - The `Credentials` (cert chain + signing key) is shared per listener
//!   and borrowed by pointer; `setCredentials` keeps a pointer into its
//!   chain and key, so the Credentials must outlive every engine that
//!   references it (a startup-lived object, §4).
//! - Every `.write` event hands out bytes borrowed from the out buffer;
//!   `completeWrite` must be called after the bytes are consumed and
//!   before the next `handleRecord`.

const std = @import("std");

const constants = @import("../constants.zig");
const ztls = @import("ztls");

const Credentials = @import("Credentials.zig");

const assert = std.debug.assert;

const Engine = @This();

/// `Pool` slot bookkeeping (§5): the intrusive free-list link and the
/// generation counter that catches a stale reference into a recycled
/// engine. Owned by the pool, never touched by the engine itself.
pool_next: u32,
generation: u32,

hs: ztls.ServerHandshake,
record_storage: ztls.RecordBuffer.Storage,
records: ztls.RecordBuffer,
out: ztls.ServerHandshake.OutBuffer,
flight: ztls.ServerHandshake.FlightBuffer,
/// Caller-owned storage for reassembling a ClientHello fragmented across
/// records. Without it ztls rejects a fragmented ClientHello with a
/// decode_error alert (the upstream #36 robustness gap); with it the
/// engine tolerates the split. Held for the handshake's life; unused
/// after, but the engine is one object so it costs a field either way.
reassembly: ztls.ServerHandshake.Storage,
/// Ciphertext produced but not yet handed to the transport, and how much
/// of it the transport has already written. Engine-owned so it stays
/// valid across an async send (see `Sink`).
outbox: [outbox_bytes]u8,
outbox_len: u32,
outbox_sent: u32,
/// Per-connection scratch for whichever side of the transform the caller
/// does not already have a buffer for. Engine-owned because only the
/// engine knows the bound (see `staging_bytes`); the caller decides what
/// goes in it and tracks its own cursor.
///
/// Which side that is depends on the protocol, and the two never coexist
/// on one connection:
/// - L4 relay: the caller reads ciphertext into its own head buffer and
///   uses this as the *plaintext* destination its `Sink` fills.
/// - L7 proxy: plaintext accumulates in the head buffer (the parser
///   needs it contiguous across reads), so this holds the *ciphertext*
///   read from the socket before `feed` consumes it.
staging: [staging_bytes]u8,

/// What a drive step hands back *synchronously*: plaintext the caller
/// consumes before returning, and the peer's orderly close. Ciphertext
/// does **not** come through here — see `outbound`.
///
/// The asymmetry is deliberate. Decrypted bytes are consumed inside the
/// call (copied into a relay buffer, parsed as a head), so borrowing
/// ztls's buffer is safe. Ciphertext must outlive the call: it is handed
/// to an async send that completes long after `feed` returns, while
/// ztls's own buffers are valid only until the next engine call. So the
/// engine stages ciphertext in its own outbox and the caller drains it
/// at its own pace.
pub const Sink = struct {
    ctx: *anyopaque,
    /// Decrypted application data from the peer. Valid only for the
    /// duration of the callback.
    appData: *const fn (ctx: *anyopaque, bytes: []const u8) void,
    /// The peer closed the TLS session (close_notify).
    closed: *const fn (ctx: *anyopaque) void,
};

/// The largest record ztls can put on the wire. What a *peer* may send;
/// not what zoxy emits (see `max_emitted_record_bytes`).
pub const max_record_bytes = ztls.frame.max_wire_record_len;

/// The largest record zoxy itself emits.
///
/// The distinction is what shrinks the engine. Inbound buffers must cover
/// `max_record_bytes`, because a client that does not offer RFC 8449
/// `record_size_limit` may legally send a full-size record and we have to
/// accept it. Outbound buffers need cover only what *we* choose to write,
/// and emitting smaller records is always legal — no negotiation, no
/// conformance risk.
///
/// Two things bound what we write. The server flight is the certificate
/// chain (bounded at startup, `tls_cert_chain_bytes_max`) plus
/// CertificateVerify, Finished, and framing. Application records carry at
/// most a head buffer's worth, which is the largest plaintext any caller
/// hands `sendApp`.
const flight_bytes_max: usize = @as(usize, constants.tls_cert_chain_bytes_max) + 512;
const app_record_bytes_max: usize = @as(usize, constants.head_bytes_max) + 256;
pub const max_emitted_record_bytes: usize = @max(flight_bytes_max, app_record_bytes_max);

/// Ciphertext staged for the transport. Sized for the largest burst one
/// drive step can produce — a ServerHello record plus the encrypted
/// server flight — and, in steady state, one staged application record
/// while an earlier one is still draining.
const outbox_bytes: usize = 2 * max_emitted_record_bytes;

comptime {
    // The handshake burst has to fit alongside a full emitted record:
    // ServerHello and the flight are staged in the same drive step.
    assert(outbox_bytes >= server_hello_bytes_max + flight_bytes_max);
    // Emitting more than a peer must accept would be a protocol error
    // regardless of our own buffering.
    assert(max_emitted_record_bytes <= max_record_bytes);
}

/// A ServerHello record, generously: the fixed fields plus the largest
/// key share in play (X25519MLKEM768's is ~1.1 KiB).
const server_hello_bytes_max: usize = 2 * 1024;

/// Decrypted application data staged for the caller. A TLS record is
/// reassembled *inside* the engine across however many reads it takes, so
/// one `feed` can deliver a full record's plaintext at once — up to
/// `max_plaintext_len`, regardless of how small the chunks fed in were.
/// Sizing the caller's destination by the read size instead is the trap:
/// a client that writes 16 KiB in one go overflows it.
///
/// One `feed` carries over at most one incomplete record and drains
/// whatever the caller's chunk completes, so its output is bounded by one
/// record's plaintext plus that chunk — not by two whole records, which
/// is what this held before and what `tls_relay`'s comptime tie has
/// always actually required.
pub const staging_bytes: usize = max_plaintext_bytes + constants.head_bytes_max;

/// The most plaintext one record can yield — with the caller's read size,
/// what bounds a single `feed`'s output (see `staging_bytes`).
pub const max_plaintext_bytes = ztls.frame.max_plaintext_len;

pub const Config = struct {
    /// Ephemeral X25519 seed — deterministic in the simulator, from
    /// entropy in production. The engine derives the keypair.
    x25519_seed: [32]u8,
    /// ServerHello random (RFC 8446 §4.1.3) — same injection rule.
    random: [32]u8,
    /// This listener's cert chain and signing key. Borrowed, not owned:
    /// it is shared across the listener's engines and must outlive them.
    credentials: *const Credentials,
};

/// In-place init via out-pointer: `records` borrows `record_storage`,
/// so the Engine must never be copied after init (the zoxy pool-slot
/// rule).
pub fn init(engine: *Engine, config: *const Config) !void {
    assert(config.credentials.chain.len >= 1);
    const keypair = try ztls.x25519.KeyPair.generateDeterministic(
        .init(config.x25519_seed),
    );
    engine.reassembly = .empty;
    engine.hs = .init(.{
        .keypairs = .init(keypair),
        .random = .init(config.random),
        .reassembly = &engine.reassembly.buffer,
    });
    engine.hs.setCredentials(config.credentials.chain, config.credentials.signer());
    engine.record_storage = .empty;
    engine.records = .init(&engine.record_storage.buffer);
    engine.out = .empty;
    engine.flight = .empty;
    engine.outbox_len = 0;
    engine.outbox_sent = 0;
    assert(!engine.hs.isConnected());
}

/// Room left to stage. The relay drives both directions at once, so a
/// step may append while an earlier send is still in flight — safe,
/// because staged bytes never move and `outboundSent` credits off the
/// front, but only while the append fits.
pub fn outboundRoom(engine: *const Engine) usize {
    assert(engine.outbox_len <= engine.outbox.len);
    return engine.outbox.len - engine.outbox_len;
}

/// Ciphertext waiting for the transport; empty when there is nothing to
/// write. A later `feed`/`sendApp` may *append* while this slice is in
/// flight — staged bytes never move, so the in-flight region stays
/// valid; only the remainder grows.
pub fn outbound(engine: *const Engine) []const u8 {
    assert(engine.outbox_sent <= engine.outbox_len);
    return engine.outbox[engine.outbox_sent..engine.outbox_len];
}

/// Report `n` bytes written, which a short send makes a partial credit.
/// Once everything staged has gone out, the outbox resets to empty.
pub fn outboundSent(engine: *Engine, n: usize) void {
    assert(n <= engine.outbound().len);
    engine.outbox_sent += @intCast(n);
    if (engine.outbox_sent == engine.outbox_len) {
        engine.outbox_len = 0;
        engine.outbox_sent = 0;
    }
}

/// Stage ciphertext for the transport. Overflow is impossible by
/// construction — the outbox covers the largest burst one step can
/// produce, and `outboundRoom` bounds what a caller may add on top of an
/// in-flight send — so it is an invariant violation, not a runtime
/// condition to shed.
fn stage(engine: *Engine, wire: []const u8) void {
    assert(wire.len > 0);
    assert(engine.outbox_len + wire.len <= engine.outbox.len);
    @memcpy(engine.outbox[engine.outbox_len..][0..wire.len], wire);
    engine.outbox_len += @intCast(wire.len);
}

pub fn deinit(engine: *Engine) void {
    engine.hs.deinit();
}

pub fn isConnected(engine: *const Engine) bool {
    return engine.hs.isConnected();
}

/// Feed ciphertext read off the wire; sink receives whatever the
/// protocol produces (handshake flights, app data, close). Consumes all
/// of `wire`: each iteration stages a chunk into the record buffer and
/// drains every complete record, so the buffer's free space is reclaimed
/// between chunks. ztls sizes the record buffer at two max records, so a
/// single incomplete record can never fill it and `writable` stays
/// non-empty — but that is the dependency's invariant, not ours, so a
/// zero-progress step is surfaced as `error.RecordTooLarge` (a record the
/// buffer cannot stage) rather than left to spin. Any error is the
/// connection's: the caller tears down.
pub fn feed(engine: *Engine, wire: []const u8, sink: Sink) !void {
    // Staging appends, so an in-flight send is undisturbed (outboundRoom):
    // its slice sits earlier in the buffer and never moves.
    assert(engine.outboundRoom() > 0);
    var remaining = wire;
    while (remaining.len > 0) {
        const writable = engine.records.writable();
        const take = @min(writable.len, remaining.len);
        if (take == 0) return error.RecordTooLarge;
        @memcpy(writable[0..take], remaining[0..take]);
        engine.records.advance(take);
        assert(remaining.len >= take);
        remaining = remaining[take..];
        try engine.pump(sink);
    }
}

/// Encrypt application data into the outbox. Handshake must be complete.
pub fn sendApp(engine: *Engine, bytes: []const u8) !void {
    assert(engine.hs.isConnected());
    assert(engine.outboundRoom() > 0);
    const wire = try engine.hs.sendApplicationData(bytes, &engine.out.buffer);
    assert(wire.len > bytes.len); // Record header + AEAD tag overhead.
    engine.stage(wire);
    engine.hs.completeWrite();
}

/// Stage an orderly TLS close (close_notify) for the transport.
pub fn sendClose(engine: *Engine) !void {
    assert(engine.outboundRoom() > 0);
    const wire = try engine.hs.sendAlert(.close_notify, &engine.out.buffer);
    assert(wire.len > 0);
    engine.stage(wire);
    engine.hs.completeWrite();
}

fn pump(engine: *Engine, sink: Sink) !void {
    while (try engine.records.next()) |record| {
        assert(record.len > 0);
        const event = try engine.hs.handleRecord(record, &engine.out.buffer);
        switch (event) {
            .write => |wire| {
                assert(wire.len > 0);
                engine.stage(wire);
                engine.hs.completeWrite();
                if (try engine.hs.sendServerFlightBuffered(&engine.flight)) |flight_bytes| {
                    engine.stage(flight_bytes);
                    engine.hs.completeWrite();
                }
            },
            .application_data => |bytes| sink.appData(sink.ctx, bytes),
            .key_update => |ku| {
                if (ku.response) |wire| {
                    engine.stage(wire);
                    engine.hs.completeWrite();
                }
            },
            .closed => sink.closed(sink.ctx),
            .none => {},
        }
    }
}
