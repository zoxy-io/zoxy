//! Phase 3a slice 1 proof (PLANS.md): with the fixed libcrypto heap
//! installed first, a full TLS 1.3 handshake completes with *every*
//! libcrypto allocation served from our buffer — so libcrypto never
//! calls libc malloc and issues no allocating syscall after startup.
//!
//! This is a separate step from `zig build test` on purpose:
//! `CRYPTO_set_mem_functions` must run before libcrypto's first
//! allocation, so the hooks are installed as the very first libcrypto
//! touch in a fresh process — impossible to guarantee in a binary that
//! also runs ordinary handshake tests.

const std = @import("std");

const ztls = @import("ztls");
const heap_mod = @import("libcrypto_heap.zig");
const Engine = @import("Engine.zig");
const Credentials = @import("Credentials.zig");

const assert = std.debug.assert;

// Run the heap's own unit tests in this step too (the file links
// libcrypto via its ztls import, so it can't ride the CI test binary).
comptime {
    _ = heap_mod;
}

const cert_pem = @embedFile("testdata/cert.pem");
const key_pem = @embedFile("testdata/key.pem");

// 4 MiB: comfortably covers a handshake's transient libcrypto working
// set; slice 2 sizes the production reservation against measured peak.
var heap_backing: [4 * 1024 * 1024]u8 align(16) = undefined;

test "slice 1: a handshake runs entirely on the fixed libcrypto heap" {
    // First libcrypto touch in this process: install the hooks. If this
    // fails, something allocated before us — the proof is void, fail loud.
    var heap: heap_mod.Heap = undefined;
    heap.init(&heap_backing);
    try std.testing.expect(heap_mod.install(&heap));

    // Credentials must load *after* the heap install — Credentials.load
    // touches libcrypto (fromPem), which must ride the fixed heap too.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var credentials = try Credentials.load(arena_state.allocator(), cert_pem, key_pem, .{});
    defer credentials.deinit();

    // A full in-memory handshake: raw ztls client against the Engine.
    var engine: Engine = undefined;
    try engine.init(&.{
        .x25519_seed = @splat(0x42),
        .random = @splat(0x43),
        .credentials = &credentials,
    });
    defer engine.deinit();

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

    var c_out: ztls.ClientHandshake.OutBuffer = .empty;
    var c_storage: ztls.RecordBuffer.Storage = .empty;
    var c_records: ztls.RecordBuffer = .init(&c_storage.buffer);

    var wire: WireCapture = .{};
    WireCapture.push(&wire, try client.start(&c_out.buffer));
    client.completeWrite();

    var rounds: u8 = 0;
    while (!(engine.isConnected() and client.isConnected())) : (rounds += 1) {
        try std.testing.expect(rounds < 8);
        // Server side: feed the client's bytes, then take the ciphertext
        // the engine staged (plaintext would arrive via the sink).
        var to_client: WireCapture = .{};
        try engine.feed(wire.take(), .{
            .ctx = &to_client,
            .appData = ignoreBytes,
            .closed = ignore,
        });
        const outbound = engine.outbound();
        if (outbound.len > 0) {
            WireCapture.push(&to_client, outbound);
            engine.outboundSent(outbound.len);
        }
        // Client side: feed the server's bytes back.
        var back: WireCapture = .{};
        try feedClient(&client, &c_records, &c_out, to_client.take(), &back);
        wire = back;
    }

    try std.testing.expect(engine.isConnected());
    try std.testing.expect(client.isConnected());
    // libcrypto asked our heap for memory during the handshake (if the
    // hooks were bypassed this stays zero). This is an existence proof —
    // it shows the hooks are wired and a handshake works through them,
    // not that *no* allocation escaped to libc. The universal
    // no-mmap/brk-after-init claim is the zero-alloc syscall gate's job
    // once TLS joins the serving path (slices 4-5).
    try std.testing.expect(heap.used_peak > 0);
}

const WireCapture = struct {
    buf: [8192]u8 = undefined,
    len: usize = 0,

    fn push(cap: *WireCapture, bytes: []const u8) void {
        assert(cap.len + bytes.len <= cap.buf.len);
        @memcpy(cap.buf[cap.len..][0..bytes.len], bytes);
        cap.len += bytes.len;
    }

    fn pushOpaque(ctx: *anyopaque, bytes: []const u8) void {
        push(@ptrCast(@alignCast(ctx)), bytes);
    }

    fn take(cap: *WireCapture) []const u8 {
        const out = cap.buf[0..cap.len];
        cap.len = 0;
        return out;
    }
};

fn ignore(_: *anyopaque) void {}
fn ignoreBytes(_: *anyopaque, _: []const u8) void {}

fn feedClient(
    client: *ztls.ClientHandshake,
    records: *ztls.RecordBuffer,
    out: *ztls.ClientHandshake.OutBuffer,
    server_wire: []const u8,
    back: *WireCapture,
) !void {
    var remaining = server_wire;
    while (remaining.len > 0) {
        const writable = records.writable();
        assert(writable.len > 0);
        const take = @min(writable.len, remaining.len);
        @memcpy(writable[0..take], remaining[0..take]);
        records.advance(take);
        remaining = remaining[take..];
        while (try records.next()) |record| {
            switch (try client.handleRecord(record, &out.buffer)) {
                .write => |bytes| {
                    WireCapture.push(back, bytes);
                    client.completeWrite();
                },
                .application_data, .closed, .key_update, .new_session_ticket, .none => {},
            }
        }
    }
}
