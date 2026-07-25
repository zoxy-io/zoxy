//! The Phase 3a TLS engine (DESIGN.md §4, PLANS.md): the zoxy-shaped seam
//! over ztls's sans-I/O TLS 1.3 server. Static caller-owned buffers, key
//! material injected as plain data (deterministic under the simulator),
//! zero allocation in the wrapper (libcrypto's own allocations ride the
//! fixed heap of slice 1). ~116 KiB per instance (IMPLEMENTATION_NOTES.md),
//! so the serving path holds these in a shared `Pool`, not one per conn
//! slot — that pooling, the §8 handshake budget, and the drive-API
//! coupling to `Conn` land with the data-path slices (PLANS.md 3a 4–5);
//! this module is the engine those slices drive, exercised until then by
//! the spike and heap-proof tests.
//!
//! Ownership rules the ztls API imposes, encoded here so callers inherit
//! them:
//! - `setCredentials` stores the chain *pointer*; the chain array must
//!   outlive the handshake — it lives in the Engine, never a temporary.
//! - `PrivateKey` wraps a libcrypto object; it must outlive the
//!   handshake and be deinit'd exactly once.
//! - Every `.write` event hands out bytes borrowed from the out buffer;
//!   `completeWrite` must be called after the bytes are consumed and
//!   before the next `handleRecord`.

const std = @import("std");

const ztls = @import("ztls");

const assert = std.debug.assert;

const Engine = @This();

hs: ztls.ServerHandshake,
/// Owns the libcrypto signing key for the handshake's lifetime.
key: ztls.signature.PrivateKey,
/// `setCredentials` keeps a pointer to this array (see header).
chain: [1][]const u8,
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

/// What a drive step asks the caller to do. Bytes borrow the engine's
/// buffers and are valid only until the next engine call.
pub const Sink = struct {
    ctx: *anyopaque,
    /// Ciphertext for the peer; the transport writes it verbatim.
    writeWire: *const fn (ctx: *anyopaque, bytes: []const u8) void,
    /// Decrypted application data from the peer.
    appData: *const fn (ctx: *anyopaque, bytes: []const u8) void,
    /// The peer closed the TLS session (close_notify).
    closed: *const fn (ctx: *anyopaque) void,
};

pub const Config = struct {
    /// Ephemeral X25519 seed — deterministic in the simulator, from
    /// entropy in production. The engine derives the keypair.
    x25519_seed: [32]u8,
    /// ServerHello random (RFC 8446 §4.1.3) — same injection rule.
    random: [32]u8,
    /// Server certificate, DER. Caller-owned, outlives the engine.
    cert_der: []const u8,
    /// Raw P-256 signing scalar for the certificate key.
    p256_scalar: [32]u8,
    /// RFC 6979 deterministic ECDSA nonce (the zoxy-io/ztls fork,
    /// mattrobenolt/ztls#82): the simulator sets this so a seeded
    /// handshake — including the CertificateVerify signature — replays
    /// byte-for-byte. Production keeps the default random nonce.
    deterministic_nonce: bool = false,
};

/// In-place init via out-pointer: `records` borrows `record_storage`,
/// so the Engine must never be copied after init (the zoxy pool-slot
/// rule).
pub fn init(engine: *Engine, config: *const Config) !void {
    assert(config.cert_der.len > 0);
    const keypair = try ztls.x25519.KeyPair.generateDeterministic(
        .init(config.x25519_seed),
    );
    engine.key = try ztls.signature.PrivateKey.fromP256Scalar(&config.p256_scalar);
    errdefer engine.key.deinit();
    engine.key.deterministic_nonce = config.deterministic_nonce;
    engine.chain = .{config.cert_der};
    engine.reassembly = .empty;
    engine.hs = .init(.{
        .keypairs = .init(keypair),
        .random = .init(config.random),
        .reassembly = &engine.reassembly.buffer,
    });
    engine.hs.setCredentials(&engine.chain, engine.key.signer());
    engine.record_storage = .empty;
    engine.records = .init(&engine.record_storage.buffer);
    engine.out = .empty;
    engine.flight = .empty;
    assert(!engine.hs.isConnected());
}

pub fn deinit(engine: *Engine) void {
    engine.hs.deinit();
    engine.key.deinit();
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

/// Encrypt and emit application data. Handshake must be complete.
pub fn sendApp(engine: *Engine, bytes: []const u8, sink: Sink) !void {
    assert(engine.hs.isConnected());
    const wire = try engine.hs.sendApplicationData(bytes, &engine.out.buffer);
    assert(wire.len > bytes.len); // Record header + AEAD tag overhead.
    sink.writeWire(sink.ctx, wire);
    engine.hs.completeWrite();
}

/// Announce an orderly TLS close (close_notify).
pub fn sendClose(engine: *Engine, sink: Sink) !void {
    const wire = try engine.hs.sendAlert(.close_notify, &engine.out.buffer);
    assert(wire.len > 0);
    sink.writeWire(sink.ctx, wire);
    engine.hs.completeWrite();
}

fn pump(engine: *Engine, sink: Sink) !void {
    while (try engine.records.next()) |record| {
        assert(record.len > 0);
        const event = try engine.hs.handleRecord(record, &engine.out.buffer);
        switch (event) {
            .write => |wire| {
                assert(wire.len > 0);
                sink.writeWire(sink.ctx, wire);
                engine.hs.completeWrite();
                if (try engine.hs.sendServerFlightBuffered(&engine.flight)) |flight_bytes| {
                    sink.writeWire(sink.ctx, flight_bytes);
                    engine.hs.completeWrite();
                }
            },
            .application_data => |bytes| sink.appData(sink.ctx, bytes),
            .key_update => |ku| {
                if (ku.response) |wire| {
                    sink.writeWire(sink.ctx, wire);
                    engine.hs.completeWrite();
                }
            },
            .closed => sink.closed(sink.ctx),
            .none => {},
        }
    }
}
