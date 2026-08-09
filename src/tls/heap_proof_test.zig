//! The proof behind the fixed libcrypto heap (DESIGN.md §4, §5, §9): with
//! the hooks installed first, a full TLS 1.3 handshake completes with
//! every libcrypto allocation served from our own buffer — so libcrypto
//! never calls libc malloc and issues no allocating syscall after startup.
//!
//! This is a separate build step from `zig build test` on purpose.
//! `CRYPTO_set_mem_functions` must run before libcrypto's *first*
//! allocation, so the hooks have to be the first libcrypto touch in a
//! fresh process — which a binary that also runs ordinary handshake tests
//! cannot promise. `src/tls_heap_proof.zig` is that binary's root.

const std = @import("std");

const Credentials = @import("Credentials.zig");
const heap_mod = @import("libcrypto_heap.zig");
const ztls = @import("ztls");

const assert = std.debug.assert;

// The heap's own unit tests ride this step too: the file links libcrypto
// through its ztls import, so it cannot join the CI test binary without
// dragging libcrypto's initialization in ahead of the install above.
comptime {
    _ = heap_mod;
}

const cert_pem = @embedFile("testdata/cert.pem");
const key_pem = @embedFile("testdata/key.pem");

/// 4 MiB, comfortably past a handshake's transient libcrypto working set.
/// What the production reservation should be is `used_peak`'s to say.
var heap_backing: [4 * 1024 * 1024]u8 align(16) = undefined;

const wire_bytes_max: u32 = 8192;

/// Enough sequential handshakes that a frontier which grew per handshake
/// instead of recycling would be unmistakable.
const plateau_handshakes: u8 = 16;

test "a handshake runs entirely on the fixed libcrypto heap" {
    // The first libcrypto touch in this process. If the swap is refused,
    // something allocated before us and the proof is void — fail loud
    // rather than measure a heap libcrypto is not using.
    try std.testing.expect(heap_mod.install(&heap_backing));

    // Credentials load *after* the install: `fromPem` calls libcrypto, so
    // it must ride the fixed heap like everything else.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var credentials = try Credentials.load(arena_state.allocator(), cert_pem, key_pem, .{});
    defer credentials.deinit();

    try handshake(&credentials);
    // libcrypto asked *our* heap for memory: had the hooks been bypassed
    // this would still be zero and the handshake would still have passed.
    // An existence proof, deliberately — it shows the hooks are wired and
    // a handshake works through them, not that no allocation anywhere
    // escaped to libc. That universal claim belongs to §5's zero-alloc
    // syscall gate, once TLS joins the serving path.
    const after_first = heap_mod.usedPeak();
    try std.testing.expect(after_first > 0);

    // The property a *fixed* heap actually rests on: the frontier only
    // ever grows, so if freed blocks did not come back through their size
    // classes, every handshake would claim fresh buffer and a long-lived
    // proxy would exhaust a reservation no sizing could save. Sixteen more
    // handshakes must therefore cost nothing.
    for (0..plateau_handshakes) |_| {
        try handshake(&credentials);
    }
    try std.testing.expectEqual(after_first, heap_mod.usedPeak());
}

/// One full in-memory handshake, raw ztls both sides. Its own function so
/// the plateau check above can run it repeatedly — every buffer here is a
/// local, so a handshake's whole libcrypto footprint is freed on return.
fn handshake(credentials: *const Credentials) !void {
    const server_keypair = try ztls.x25519.KeyPair.generateDeterministic(.init(@splat(0x42)));
    var server: ztls.ServerHandshake = .init(.{
        .keypairs = .init(server_keypair),
        .random = .init(@splat(0x43)),
    });
    defer server.deinit();
    server.setCredentials(credentials.chain, credentials.signer());

    const client_x25519 = try ztls.x25519.KeyPair.generateDeterministic(.init(@splat(0x51)));
    const client_p256 = try ztls.p256.KeyPair.generateDeterministic(.init(@splat(0x53)));
    var client: ztls.ClientHandshake = .init(.{
        .keypairs = .initWithP256(client_x25519, client_p256),
        .host_name = "spike.zoxy.test",
        .now_sec = 0,
        .random = .init(@splat(0x52)),
        .insecure_no_chain_anchor = true,
    });
    defer client.deinit();

    var client_out: ztls.ClientHandshake.OutBuffer = .empty;
    var server_out: ztls.ServerHandshake.OutBuffer = .empty;
    var flight: ztls.ServerHandshake.FlightBuffer = .empty;

    var to_server: Wire = .{};
    var to_client: Wire = .{};
    to_server.write(try client.start(&client_out.buffer));
    client.completeWrite();

    to_client.write(try server.acceptClientHello(to_server.take(), &server_out.buffer));
    server.completeWrite();
    to_client.write((try server.sendServerFlightBuffered(&flight)).?);
    server.completeWrite();

    try feedClient(&client, &client_out, to_client.take(), &to_server);
    try server.processClientFinished(to_server.take());

    assert(client.isConnected());
    assert(server.isConnected());
}

const Wire = struct {
    bytes: [wire_bytes_max]u8 = undefined,
    len: u32 = 0,

    fn write(wire: *Wire, chunk: []const u8) void {
        assert(wire.len + chunk.len <= wire.bytes.len);
        @memcpy(wire.bytes[wire.len..][0..chunk.len], chunk);
        wire.len += @intCast(chunk.len);
    }

    /// Mutable: ztls decrypts records in place.
    fn take(wire: *Wire) []u8 {
        const bytes = wire.bytes[0..wire.len];
        wire.len = 0;
        return bytes;
    }
};

fn feedClient(
    client: *ztls.ClientHandshake,
    out: *ztls.ClientHandshake.OutBuffer,
    server_wire: []u8,
    to_server: *Wire,
) !void {
    var storage: ztls.RecordBuffer.Storage = .empty;
    var records: ztls.RecordBuffer = .init(&storage.buffer);
    var remaining = server_wire;
    // Bounded: every iteration moves at least one byte out of `remaining`,
    // and a drained record buffer always has room for one.
    while (remaining.len > 0) {
        const writable = records.writable();
        assert(writable.len > 0);
        const taken = @min(writable.len, remaining.len);
        @memcpy(writable[0..taken], remaining[0..taken]);
        records.advance(taken);
        remaining = remaining[taken..];
        while (try records.next()) |record| {
            switch (try client.handleRecord(record, &out.buffer)) {
                .write => |bytes| {
                    to_server.write(bytes);
                    client.completeWrite();
                },
                .application_data, .closed, .key_update, .new_session_ticket, .none => {},
            }
        }
    }
}
