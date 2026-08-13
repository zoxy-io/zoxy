//! What the ztls pin is here to prove (DESIGN.md §4), before any of the
//! data path is built on it: a full TLS 1.3 server handshake runs in
//! memory against a raw ztls client — no sockets, no allocator, caller-owned
//! buffers throughout — and with the fork's RFC 6979 nonce plus every peer
//! keyshare seeded, the server's flight is a *pure function of its seeds*.
//!
//! That last property is why the fork exists. §9's oracle is "run one seed
//! twice, hash every delivery, assert the hashes match", and a server whose
//! CertificateVerify signature varies run to run can never satisfy it — so
//! without this, TLS traffic would be the one thing the simulator could
//! carry but never assert on.

const std = @import("std");

const Credentials = @import("Credentials.zig");
const ztls = @import("ztls");

const assert = std.debug.assert;

// Throwaway self-signed fixtures (testdata/README.md): the private key is
// committed on purpose, generated for these tests and never used elsewhere.
const cert_pem = @embedFile("testdata/cert.pem");
const key_pem = @embedFile("testdata/key.pem");

/// Every seed the two peers use. Fixed here rather than drawn, because
/// "the flight is a function of these" is the claim under test — in the
/// simulator these come from `SimIo.fillRandom` (§9).
const server_x25519_seed: [32]u8 = @splat(0x42);
const server_random: [32]u8 = @splat(0x43);
const client_x25519_seed: [32]u8 = @splat(0x51);
const client_random: [32]u8 = @splat(0x52);
const client_p256_seed: [32]u8 = @splat(0x53);

/// Room for a whole server flight — ServerHello plus the encrypted
/// Certificate/CertificateVerify/Finished — with the fixture chain.
const wire_bytes_max: u32 = 8192;

/// One direction of the in-memory wire.
const Wire = struct {
    bytes: [wire_bytes_max]u8 = undefined,
    len: u32 = 0,

    fn write(wire: *Wire, chunk: []const u8) void {
        assert(wire.len + chunk.len <= wire.bytes.len);
        @memcpy(wire.bytes[wire.len..][0..chunk.len], chunk);
        wire.len += @intCast(chunk.len);
    }

    /// Mutable, because ztls decrypts records in place — the wire buffer
    /// *is* the plaintext buffer, which is how the engine keeps no second
    /// copy of anything it receives.
    fn take(wire: *Wire) []u8 {
        const bytes = wire.bytes[0..wire.len];
        wire.len = 0;
        return bytes;
    }
};

/// The raw ztls client half: fully seeded, so nothing it puts in the
/// transcript the server signs can vary between runs.
///
/// Both keyshares are seeded, not just X25519. `KeyPairs.init` would
/// generate a *random* P-256 share, and that share rides in the
/// ClientHello — hence in the transcript — so a random one makes even a
/// deterministic signature cover a different message each run.
const Client = struct {
    handshake: ztls.ClientHandshake,
    out: ztls.ClientHandshake.OutBuffer,
    storage: ztls.RecordBuffer.Storage,
    records: ztls.RecordBuffer,
    app: [256]u8 = undefined,
    app_len: u32 = 0,

    fn init(client: *Client) !void {
        const x25519 = try ztls.x25519.KeyPair.generateDeterministic(.init(client_x25519_seed));
        const p256 = try ztls.p256.KeyPair.generateDeterministic(.init(client_p256_seed));
        client.handshake = .init(.{
            .keypairs = .initWithP256(x25519, p256),
            .host_name = "spike.zoxy.test",
            .now_sec = 0,
            .random = .init(client_random),
            // The fixture is self-signed; chain anchoring is not what
            // this file proves.
            .insecure_no_chain_anchor = true,
        });
        client.out = .empty;
        client.storage = .empty;
        client.records = .init(&client.storage.buffer);
        client.app_len = 0;
    }

    fn hello(client: *Client, to_server: *Wire) !void {
        to_server.write(try client.handshake.start(&client.out.buffer));
        client.handshake.completeWrite();
    }

    /// Feed server bytes; append whatever the client emits to `to_server`.
    fn feed(client: *Client, wire: []const u8, to_server: *Wire) !void {
        var remaining = wire;
        // Bounded: every iteration copies at least one byte out of
        // `remaining` and `writable` is never empty on a drained buffer.
        while (remaining.len > 0) {
            const writable = client.records.writable();
            assert(writable.len > 0);
            const taken = @min(writable.len, remaining.len);
            @memcpy(writable[0..taken], remaining[0..taken]);
            client.records.advance(taken);
            remaining = remaining[taken..];
            while (try client.records.next()) |record| {
                try client.handleRecord(record, to_server);
            }
        }
    }

    /// `record` is mutable because ztls decrypts in place — the record
    /// buffer is the plaintext buffer, which is how the engine holds no
    /// second copy of anything.
    fn handleRecord(client: *Client, record: []u8, to_server: *Wire) !void {
        switch (try client.handshake.handleRecord(record, &client.out.buffer)) {
            .write => |bytes| {
                to_server.write(bytes);
                client.handshake.completeWrite();
            },
            .application_data => |bytes| {
                assert(client.app_len + bytes.len <= client.app.len);
                @memcpy(client.app[client.app_len..][0..bytes.len], bytes);
                client.app_len += @intCast(bytes.len);
            },
            .closed, .key_update, .new_session_ticket, .none => {},
        }
    }
};

/// The raw ztls server half. This is deliberately *not* the Engine wrapper
/// (§4) — it does not exist yet, and the point of this file is that the
/// pin underneath it behaves before anything is built on top.
const Server = struct {
    handshake: ztls.ServerHandshake,
    out: ztls.ServerHandshake.OutBuffer,
    flight: ztls.ServerHandshake.FlightBuffer,

    fn init(server: *Server, credentials: *const Credentials) !void {
        const keypair = try ztls.x25519.KeyPair.generateDeterministic(.init(server_x25519_seed));
        server.handshake = .init(.{
            .keypairs = try .init(keypair),
            .random = .init(server_random),
        });
        server.handshake.setCredentials(credentials.chain, credentials.signer());
        server.out = .empty;
        server.flight = .empty;
    }

    /// ClientHello in, the whole server flight out: ServerHello followed by
    /// the encrypted EncryptedExtensions/Certificate/CertificateVerify/
    /// Finished. This is the byte sequence the determinism claim is about.
    fn respond(server: *Server, client_hello: []u8, to_client: *Wire) !void {
        to_client.write(try server.handshake.acceptClientHello(
            client_hello,
            &server.out.buffer,
        ));
        server.handshake.completeWrite();
        to_client.write((try server.handshake.sendServerFlightBuffered(&server.flight)).?);
        // The flight is on the wire as far as this test's transport is
        // concerned, so tell ztls: it refuses a second write while one is
        // pending, which is the backpressure the real data path will owe
        // it once the transport is a socket rather than an array.
        server.handshake.completeWrite();
    }
};

fn testCredentials(arena: std.mem.Allocator, deterministic_nonce: bool) !Credentials {
    return Credentials.load(arena, cert_pem, key_pem, .{
        .deterministic_nonce = deterministic_nonce,
    });
}

/// Run one handshake to completion and hand back what the server put on
/// the wire. `out` is the caller's, because a returned slice into a stack
/// `Wire` would dangle the moment this returns.
fn serverFlight(
    credentials: *const Credentials,
    out: []u8,
) ![]const u8 {
    var server: Server = undefined;
    try server.init(credentials);
    defer server.handshake.deinit();

    var client: Client = undefined;
    try client.init();
    defer client.handshake.deinit();

    var to_server: Wire = .{};
    var to_client: Wire = .{};
    try client.hello(&to_server);
    try server.respond(to_server.take(), &to_client);

    assert(to_client.len <= out.len);
    @memcpy(out[0..to_client.len], to_client.bytes[0..to_client.len]);
    return out[0..to_client.len];
}

test "spike: a seeded handshake completes end to end" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var credentials = try testCredentials(arena_state.allocator(), false);
    defer credentials.deinit();

    var server: Server = undefined;
    try server.init(&credentials);
    defer server.handshake.deinit();

    var client: Client = undefined;
    try client.init();
    defer client.handshake.deinit();

    var to_server: Wire = .{};
    var to_client: Wire = .{};
    try client.hello(&to_server);
    try server.respond(to_server.take(), &to_client);
    try client.feed(to_client.take(), &to_server);

    // The client's Finished is what moves the server to connected — the
    // transcript point everything after (tickets, §4's resumption) hangs
    // off, so it is asserted rather than assumed.
    try server.handshake.processClientFinished(to_server.take());
    try std.testing.expect(client.handshake.isConnected());
    try std.testing.expect(server.handshake.isConnected());

    // Application data both ways, proving the keys the two sides installed
    // are the same keys and not merely both well-formed.
    const from_client = "hello-from-client";
    var request: Wire = .{};
    request.write(try client.handshake.sendApplicationData(
        from_client,
        &client.out.buffer,
    ));
    client.handshake.completeWrite();
    try std.testing.expectEqualStrings(
        from_client,
        try server.handshake.receiveApplicationData(request.take()),
    );

    const from_server = "hello-from-zoxy";
    var response: Wire = .{};
    response.write(try server.handshake.sendApplicationData(
        from_server,
        &server.out.buffer,
    ));
    server.handshake.completeWrite();
    try client.feed(response.take(), &to_server);
    try std.testing.expectEqualStrings(from_server, client.app[0..client.app_len]);
}

test "spike: identical seeds yield a byte-exact server flight" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    // One shared credential across both runs, deterministic nonce on: the
    // §9 property is that with the inputs fixed, the output is fixed.
    var credentials = try testCredentials(arena_state.allocator(), true);
    defer credentials.deinit();

    var first_storage: [wire_bytes_max]u8 = undefined;
    var second_storage: [wire_bytes_max]u8 = undefined;
    const first = try serverFlight(&credentials, &first_storage);
    const second = try serverFlight(&credentials, &second_storage);

    try std.testing.expect(first.len > 0);
    try std.testing.expectEqualSlices(u8, first, second);
}

test "spike: without the deterministic nonce the same flight diverges" {
    // Negative space, and the reason the fork carries a patch at all: with
    // libcrypto's random ECDSA nonce the CertificateVerify signature bytes
    // differ every run, and DER integer trimming makes even the *length*
    // of the encrypted flight record vary. Everything else here is
    // identical between the two runs — same seeds, same credential, same
    // code path — so a divergence can only come from the nonce.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var credentials = try testCredentials(arena_state.allocator(), false);
    defer credentials.deinit();

    var first_storage: [wire_bytes_max]u8 = undefined;
    var second_storage: [wire_bytes_max]u8 = undefined;
    const first = try serverFlight(&credentials, &first_storage);
    const second = try serverFlight(&credentials, &second_storage);

    try std.testing.expect(!std.mem.eql(u8, first, second));
    // The divergence is confined to the encrypted flight: ServerHello
    // carries only seeded material, so it must still match byte for byte.
    // If this ever fails, something *other* than the signature is varying
    // and the determinism claim above is resting on the wrong evidence.
    const server_hello_len = ztls.frame.header_len +
        std.mem.readInt(u16, first[3..5], .big);
    try std.testing.expectEqualSlices(
        u8,
        first[0..server_hello_len],
        second[0..server_hello_len],
    );
}
