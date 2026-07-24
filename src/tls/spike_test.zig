//! Phase 3a spike test (PLANS.md): a full in-memory TLS 1.3 handshake and
//! data exchange between a raw ztls client and zoxy's Engine wrapper —
//! no sockets, deterministic key material, static buffers throughout.
//! Proves: the sans-I/O drive loop shape, the data-injection seam the
//! simulator needs, credential provisioning from an embedded DER cert +
//! raw scalar, and round-trip application data + orderly close.

const std = @import("std");

const ztls = @import("ztls");
const Engine = @import("Engine.zig");

const assert = std.debug.assert;

// Throwaway self-signed spike fixtures (testdata/README.md): the private
// scalar is committed on purpose, generated for this test and never used
// anywhere else.
const cert_der = @embedFile("testdata/cert.der");
const scalar_hex = @embedFile("testdata/scalar.hex");

/// A capture buffer for one direction of the in-memory wire, plus the
/// decrypted application data and close signal a side observed.
const Capture = struct {
    wire: [8192]u8 = undefined,
    wire_len: usize = 0,
    app: [256]u8 = undefined,
    app_len: usize = 0,
    saw_close: bool = false,

    fn sink(capture: *Capture) Engine.Sink {
        return .{
            .ctx = capture,
            .writeWire = writeWire,
            .appData = appData,
            .closed = closed,
        };
    }

    fn writeWire(ctx: *anyopaque, bytes: []const u8) void {
        const capture: *Capture = @ptrCast(@alignCast(ctx));
        assert(capture.wire_len + bytes.len <= capture.wire.len);
        @memcpy(capture.wire[capture.wire_len..][0..bytes.len], bytes);
        capture.wire_len += bytes.len;
    }

    fn appData(ctx: *anyopaque, bytes: []const u8) void {
        const capture: *Capture = @ptrCast(@alignCast(ctx));
        assert(capture.app_len + bytes.len <= capture.app.len);
        @memcpy(capture.app[capture.app_len..][0..bytes.len], bytes);
        capture.app_len += bytes.len;
    }

    fn closed(ctx: *anyopaque) void {
        const capture: *Capture = @ptrCast(@alignCast(ctx));
        capture.saw_close = true;
    }

    fn take(capture: *Capture) []const u8 {
        const bytes = capture.wire[0..capture.wire_len];
        capture.wire_len = 0;
        return bytes;
    }
};

fn testScalar() [32]u8 {
    var scalar: [32]u8 = undefined;
    // The fixture is 64 hex chars checked in at generation time; a decode
    // failure means the repo itself is corrupt, not a runtime input.
    const decoded = std.fmt.hexToBytes(&scalar, scalar_hex) catch unreachable;
    assert(decoded.len == 32);
    return scalar;
}

/// Drive the raw ztls client against the Engine until the client has no
/// more bytes to deliver; returns bytes the client wants on the wire.
const Client = struct {
    hs: ztls.ClientHandshake,
    storage: ztls.RecordBuffer.Storage,
    records: ztls.RecordBuffer,
    out: ztls.ClientHandshake.OutBuffer,
    app: [256]u8 = undefined,
    app_len: usize = 0,
    saw_close: bool = false,

    fn init(client: *Client) !void {
        const keypair = try ztls.x25519.KeyPair.generateDeterministic(
            .init(@splat(0x51)),
        );
        client.hs = .init(.{
            .keypairs = .init(keypair),
            .host_name = "spike.zoxy.test",
            .now_sec = 0,
            .random = .init(@splat(0x52)),
            // The spike cert is self-signed; chain anchoring is not what
            // this test proves.
            .insecure_no_chain_anchor = true,
        });
        client.storage = .empty;
        client.records = .init(&client.storage.buffer);
        client.out = .empty;
        client.app_len = 0;
        client.saw_close = false;
    }

    /// Feed server bytes; append whatever the client emits to `capture`.
    fn feed(client: *Client, wire: []const u8, capture: *Capture) !void {
        var remaining = wire;
        while (remaining.len > 0) {
            const writable = client.records.writable();
            assert(writable.len > 0);
            const take = @min(writable.len, remaining.len);
            @memcpy(writable[0..take], remaining[0..take]);
            client.records.advance(take);
            remaining = remaining[take..];
            while (try client.records.next()) |record| {
                switch (try client.hs.handleRecord(record, &client.out.buffer)) {
                    .write => |bytes| {
                        Capture.writeWire(capture, bytes);
                        client.hs.completeWrite();
                    },
                    .application_data => |bytes| {
                        assert(client.app_len + bytes.len <= client.app.len);
                        @memcpy(client.app[client.app_len..][0..bytes.len], bytes);
                        client.app_len += bytes.len;
                    },
                    .closed => client.saw_close = true,
                    .key_update, .new_session_ticket, .none => {},
                }
            }
        }
    }
};

test "spike: full deterministic handshake, echo, and orderly close" {
    var engine: Engine = undefined;
    try engine.init(&.{
        .x25519_seed = @splat(0x42),
        .random = @splat(0x43),
        .cert_der = cert_der,
        .p256_scalar = testScalar(),
    });
    defer engine.deinit();

    var client: Client = undefined;
    try client.init();
    defer client.hs.deinit();

    var to_server: Capture = .{};
    var to_client: Capture = .{};

    // ClientHello.
    Capture.writeWire(&to_server, try client.hs.start(&client.out.buffer));
    client.hs.completeWrite();

    // Pump both directions until the handshake settles. Bounded: a TLS 1.3
    // 1-RTT handshake settles in far fewer exchanges than this.
    var rounds: u8 = 0;
    while (!(engine.isConnected() and client.hs.isConnected())) : (rounds += 1) {
        try std.testing.expect(rounds < 8);
        try engine.feed(to_server.take(), to_client.sink());
        try client.feed(to_client.take(), &to_server);
    }

    // Client → server application data.
    const client_says = "hello-from-client";
    Capture.writeWire(&to_server, try client.hs.sendApplicationData(
        client_says,
        &client.out.buffer,
    ));
    client.hs.completeWrite();
    try engine.feed(to_server.take(), to_client.sink());
    try std.testing.expectEqualStrings(client_says, to_client.app[0..to_client.app_len]);

    // Server → client application data.
    const server_says = "hello-from-zoxy-engine";
    try engine.sendApp(server_says, to_client.sink());
    try client.feed(to_client.take(), &to_server);
    try std.testing.expectEqualStrings(server_says, client.app[0..client.app_len]);

    // Orderly close from the server; the client must observe close_notify.
    try engine.sendClose(to_client.sink());
    try client.feed(to_client.take(), &to_server);
    try std.testing.expect(client.saw_close);
}

test "spike: determinism — identical seeds yield identical first flight" {
    var first: [2][]u8 = undefined;
    var storage: [2][4096]u8 = undefined;
    for (0..2) |run| {
        var engine: Engine = undefined;
        try engine.init(&.{
            .x25519_seed = @splat(0x42),
            .random = @splat(0x43),
            .cert_der = cert_der,
            .p256_scalar = testScalar(),
        });
        defer engine.deinit();

        var client: Client = undefined;
        try client.init();
        defer client.hs.deinit();

        var to_client: Capture = .{};
        var to_server: Capture = .{};
        Capture.writeWire(&to_server, try client.hs.start(&client.out.buffer));
        client.hs.completeWrite();
        try engine.feed(to_server.take(), to_client.sink());

        assert(to_client.wire_len <= storage[run].len);
        @memcpy(storage[run][0..to_client.wire_len], to_client.wire[0..to_client.wire_len]);
        first[run] = storage[run][0..to_client.wire_len];
    }
    // The sim-injection seam, as far as it goes today: same seeds give a
    // byte-identical ServerHello record (the injected random and the
    // deterministic X25519 keyshare are directly visible in it). Full-
    // flight determinism does NOT hold — libcrypto signs
    // CertificateVerify with a random nonce, so the signature bytes and
    // (via DER integer trimming) even the encrypted flight record's
    // *length* vary run to run; divergence starts at that record's
    // header. Recorded spike finding: byte-exact sim replay of TLS
    // traffic needs deterministic ECDSA (RFC 6979 — OpenSSL 3.2+
    // exposes it as the "nonce-type" EVP param; ztls does not surface it
    // yet), an upstream feature request for the production engine.
    // Compare exactly the first record: 5-byte header + u16 body length.
    try std.testing.expect(first[0].len >= 5 and first[1].len >= 5);
    const body_len = std.mem.readInt(u16, first[0][3..5], .big);
    const record_len = 5 + @as(usize, body_len);
    try std.testing.expect(first[0].len >= record_len and first[1].len >= record_len);
    try std.testing.expectEqualSlices(
        u8,
        first[0][0..record_len],
        first[1][0..record_len],
    );
}
