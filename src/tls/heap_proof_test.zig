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
const zssl = @import("zssl");

const assert = std.debug.assert;

// The heap's own unit tests ride this step too: the file links libcrypto
// through its zssl import, so it cannot join the CI test binary without
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

/// One full in-memory handshake, raw zssl both sides. Its own function so
/// the plateau check above can run it repeatedly — every buffer here is a
/// local, so a handshake's whole libcrypto footprint is freed on return.
fn handshake(credentials: *const Credentials) !void {
    var server_reassembly: [16 * 1024]u8 = undefined;
    var server_flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined;
    var server: zssl.ServerHandshake = .init(&.{
        .credentials = &credentials.inner,
        .server_random = @splat(0x43),
        .key_share_private = @splat(0x42),
        .groups = &.{zssl.client_hello.group_x25519},
        .reassembly = &server_reassembly,
        .flight = &server_flight,
    });
    defer server.deinit();

    var client_reassembly: [16 * 1024]u8 = undefined;
    var client: zssl.ClientHandshake = .init(&.{
        .client_random = @splat(0x52),
        .x25519_private = @splat(0x51),
        .server_name = "spike.zoxy.test",
        .certificate_policy = .insecure_no_verification,
        .reassembly = &client_reassembly,
    });
    defer client.deinit();

    var client_out: [zssl.ClientHandshake.out_bytes_min]u8 = undefined;
    var server_out: [zssl.ServerHandshake.out_bytes_min]u8 = undefined;

    var to_server: Wire = .{};
    var to_client: Wire = .{};
    to_server.write(client.start(&client_out));

    try feedServer(&server, &server_out, to_server.take(), &to_client);
    try feedClient(&client, &client_out, to_client.take(), &to_server);
    try feedServer(&server, &server_out, to_server.take(), &to_client);

    assert(client.state == .connected);
    assert(server.state == .connected);
}

const Wire = struct {
    bytes: [wire_bytes_max]u8 = undefined,
    len: u32 = 0,

    fn write(wire: *Wire, chunk: []const u8) void {
        assert(wire.len + chunk.len <= wire.bytes.len);
        @memcpy(wire.bytes[wire.len..][0..chunk.len], chunk);
        wire.len += @intCast(chunk.len);
    }

    /// Mutable: records are decrypted in place.
    fn take(wire: *Wire) []u8 {
        const bytes = wire.bytes[0..wire.len];
        wire.len = 0;
        return bytes;
    }
};

/// Both directions are the same loop over a different machine, so it is
/// written once and instantiated twice: the two event unions differ only
/// in arms this proof ignores.
fn feed(machine: anytype, out: []u8, peer_wire: []u8, to_peer: *Wire) !void {
    var storage: [zssl.record.wire_record_bytes_max]u8 = undefined;
    var records = zssl.record_buffer.RecordBuffer.init(&storage);
    var remaining = peer_wire;
    // Bounded: every iteration moves at least one byte out of `remaining`,
    // and a drained record buffer always has room for one.
    while (remaining.len > 0) {
        const writable = records.writable();
        assert(writable.len > 0);
        const taken = @min(writable.len, remaining.len);
        @memcpy(writable[0..taken], remaining[0..taken]);
        records.advance(taken);
        remaining = remaining[taken..];
        while (try records.next()) |wire_record| {
            // Drained to null, the same as every other zssl caller here:
            // one record may carry several post-handshake messages, and
            // the machine refuses the next record while any are pending.
            var next_event = try machine.handleRecord(wire_record, out);
            while (next_event) |event| : (next_event = try machine.drain(out)) {
                switch (event) {
                    .send => |bytes| to_peer.write(bytes),
                    // The client's `.connected` carries its flight; the
                    // server's carries nothing, which is why this is
                    // matched by shape rather than by name. Sound because
                    // Zig prunes the untaken comptime branch per
                    // instantiation, so the void-payload side never
                    // type-checks the slice arm.
                    .connected => |payload| {
                        if (@TypeOf(payload) == []const u8) to_peer.write(payload);
                    },
                    else => {},
                }
            }
        }
    }
}

fn feedClient(
    client: *zssl.ClientHandshake,
    out: []u8,
    server_wire: []u8,
    to_server: *Wire,
) !void {
    return feed(client, out, server_wire, to_server);
}

fn feedServer(
    server: *zssl.ServerHandshake,
    out: []u8,
    client_wire: []u8,
    to_client: *Wire,
) !void {
    return feed(server, out, client_wire, to_client);
}
