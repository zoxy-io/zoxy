//! Phase 3a spike (PLANS.md): the zoxy-shaped seam over ztls's sans-I/O
//! TLS 1.3 server. Proves the integration shape the production engine
//! would take — static caller-owned buffers, key material injected as
//! plain data (deterministic under the simulator), no allocation in the
//! wrapper — without touching the serving path. Spike scope only: the
//! production engine grows per-connection pooling, the §8 handshake
//! budget, and constants.zig sizing.
//!
//! Ownership rules learned from the ztls API and encoded here so the
//! production engine inherits them:
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
    engine.chain = .{config.cert_der};
    engine.hs = .init(.{
        .keypairs = .init(keypair),
        .random = .init(config.random),
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
/// protocol produces (handshake flights, app data, close). The spike
/// asserts the input fits the record buffer; the production engine
/// turns that into backpressure.
pub fn feed(engine: *Engine, wire: []const u8, sink: Sink) !void {
    var remaining = wire;
    while (remaining.len > 0) {
        const writable = engine.records.writable();
        assert(writable.len > 0); // Spike: input must fit; prod backpressures.
        const take = @min(writable.len, remaining.len);
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
