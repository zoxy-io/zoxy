//! A QUIC handshake's client side (#449): zssl's client in QUIC mode,
//! reporting to the same sink a server's engine reports to
//! (`Engine.QuicSink`), so whatever feeds h3 from one feeds it from the
//! other.
//!
//! zoxy serves QUIC and never dials it, so nothing on the serving path
//! uses this. It is the client the HTTP/3 tests and the simulator's
//! HTTP/3 clients handshake with — the reason it lives here, where zssl
//! may be imported, rather than beside them. It verifies no chain or name:
//! a test's chain is throwaway, and what is under test is the server. The
//! leaf's signature it does verify, and keeps the leaf's key, for a gate
//! asking which certificate a name chose (#297).

const std = @import("std");
const zssl = @import("zssl");

const Engine = @import("Engine.zig");

const assert = std.debug.assert;

const QuicClient = @This();

hs: zssl.ClientHandshake,
out: [zssl.ClientHandshake.out_bytes_min]u8,
reassembly: [reassembly_bytes]u8,
/// The handshake completed: the server's Finished verified, the client's
/// own sent.
connected: bool,
/// NewSessionTickets the server sent, counted and otherwise dropped:
/// nothing here resumes.
tickets: u32,
/// The leaf's public key, copied out once the handshake connects (#297):
/// the transport deinits `hs` when it ends, and a gate reads this after.
server_key: [zssl.peer_certificate.public_key_bytes_max]u8,
server_key_bytes: u16,

/// What a server's flight may need reassembled before the client reads it:
/// a certificate chain of a few kilobytes, with room to spare.
pub const reassembly_bytes: u32 = 16 * 1024;

pub const Config = struct {
    server_name: []const u8,
    /// This client's transport parameters, encoded (RFC 9000 §18).
    transport_parameters: []const u8,
    /// The client random, then the key share's private half: the caller's
    /// entropy, so a simulator's seed decides the handshake.
    seed: [64]u8,
};

/// In place — the handshake borrows `reassembly` — and the ClientHello
/// handed to `sink` at once.
pub fn init(client: *QuicClient, config: *const Config, sink: *const Engine.QuicSink) error{QuicSinkRefused}!void {
    assert(config.transport_parameters.len >= 1);
    assert(config.server_name.len >= 1);
    client.connected = false;
    client.tickets = 0;
    client.server_key_bytes = 0;
    client.hs = zssl.ClientHandshake.init(&.{
        .client_random = config.seed[0..32].*,
        .x25519_private = config.seed[32..64].*,
        .server_name = config.server_name,
        .alpn_protocols = Engine.quic_alpn,
        .certificate_policy = .leaf_signature,
        .reassembly = &client.reassembly,
        .quic = .{ .transport_parameters = config.transport_parameters },
    });
    const hello = client.hs.startCrypto();
    assert(hello.level == .initial);
    try sink.crypto(sink.ctx, hello.level, hello.bytes);
}

/// The public key the server's leaf carried (#297), as
/// `std.crypto.Certificate` reads one out of a leaf; null for a handshake
/// that never connected. Readable after `deinit`.
pub fn serverPublicKey(client: *const QuicClient) ?[]const u8 {
    if (client.server_key_bytes == 0) return null;
    assert(client.connected);
    return client.server_key[0..client.server_key_bytes];
}

fn keepServerKey(client: *QuicClient) void {
    assert(client.connected);
    const peer = &client.hs.peer;
    // `leaf_signature` verified it before the server's Finished could.
    assert(peer.seen and !peer.empty);
    const key = peer.publicKey();
    assert(key.len >= 1);
    assert(key.len <= client.server_key.len);
    @memcpy(client.server_key[0..key.len], key);
    client.server_key_bytes = @intCast(key.len);
}

pub fn deinit(client: *QuicClient) void {
    client.hs.deinit();
}

/// Feed the server's CRYPTO bytes received at `level`, in order: every
/// event they produce goes to `sink` before this returns.
pub fn deliver(client: *QuicClient, level: Engine.QuicLevel, bytes: []const u8, sink: *const Engine.QuicSink) !void {
    assert(bytes.len >= 1);
    var next_event = try client.hs.handleCrypto(level, bytes, &client.out);
    // Bounded: `drainCrypto` answers null once the step's events are out.
    while (next_event) |event| : (next_event = try client.hs.drainCrypto(&client.out)) {
        switch (event) {
            .crypto => |crypto| try sink.crypto(sink.ctx, crypto.level, crypto.bytes),
            .secret => |secret| try sink.secret(sink.ctx, &secret),
            .transport_parameters => |parameters| try sink.transportParameters(sink.ctx, parameters),
            .ticket => client.tickets += 1,
            .connected => {
                assert(!client.connected);
                client.connected = true;
                client.keepServerKey();
                sink.connected(sink.ctx);
            },
        }
    }
}
