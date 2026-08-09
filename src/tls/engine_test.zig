//! The engine's contract with the data path (DESIGN.md §4), driven by a
//! raw ztls client over an in-memory wire. What is pinned here is what
//! slices above this one will assume without re-checking: a handshake
//! completes, a fragmented ClientHello does not fail it, the outbox
//! survives the call that filled it and credits partial sends, and an
//! orderly close is observable from both ends.

const std = @import("std");

const constants = @import("../constants.zig");
const Credentials = @import("Credentials.zig");
const Engine = @import("Engine.zig");
const ztls = @import("ztls");

const assert = std.debug.assert;

const cert_pem = @embedFile("testdata/cert.pem");
const key_pem = @embedFile("testdata/key.pem");

/// Room for the largest record on the wire — a max-size plaintext record
/// plus its header and AEAD tag — with slack for a second alongside it.
const wire_bytes_max: u32 = 2 * Engine.record_bytes_max;
/// Room for the largest payload any test here round-trips.
const app_bytes_max: u32 = 8192;
/// A TLS 1.3 1-RTT handshake settles in far fewer exchanges; past this
/// the peers are not converging, and a test should say so rather than run.
const rounds_max: u8 = 8;

/// One direction of the in-memory wire, plus what the side observed.
const Peer = struct {
    wire: [wire_bytes_max]u8 = undefined,
    wire_len: u32 = 0,
    app: [app_bytes_max]u8 = undefined,
    app_len: u32 = 0,
    /// How many times the sink was called. A byte count alone cannot tell
    /// "one record arrived whole" from "the same bytes dribbled in one at
    /// a time", and that difference is the record layer's whole job.
    app_deliveries: u32 = 0,
    saw_close: bool = false,

    fn write(peer: *Peer, bytes: []const u8) void {
        assert(peer.wire_len + bytes.len <= peer.wire.len);
        @memcpy(peer.wire[peer.wire_len..][0..bytes.len], bytes);
        peer.wire_len += @intCast(bytes.len);
    }

    /// Mutable: ztls decrypts records in place.
    fn take(peer: *Peer) []u8 {
        const bytes = peer.wire[0..peer.wire_len];
        peer.wire_len = 0;
        return bytes;
    }

    fn sink(peer: *Peer) Engine.Sink {
        return .{ .ctx = peer, .appData = appData, .closed = closed };
    }

    fn appData(ctx: *anyopaque, bytes: []const u8) void {
        const peer: *Peer = @ptrCast(@alignCast(ctx));
        assert(peer.app_len + bytes.len <= peer.app.len);
        @memcpy(peer.app[peer.app_len..][0..bytes.len], bytes);
        peer.app_len += @intCast(bytes.len);
        peer.app_deliveries += 1;
    }

    fn closed(ctx: *anyopaque) void {
        const peer: *Peer = @ptrCast(@alignCast(ctx));
        peer.saw_close = true;
    }
};

/// The raw ztls client half, fully seeded so nothing it contributes to
/// the transcript varies between runs.
const Client = struct {
    hs: ztls.ClientHandshake,
    out: ztls.ClientHandshake.OutBuffer,
    storage: ztls.RecordBuffer.Storage,
    records: ztls.RecordBuffer,
    app: [app_bytes_max]u8 = undefined,
    app_len: u32 = 0,
    saw_close: bool = false,

    fn init(client: *Client) !void {
        const x25519 = try ztls.x25519.KeyPair.generateDeterministic(.init(@splat(0x51)));
        const p256 = try ztls.p256.KeyPair.generateDeterministic(.init(@splat(0x53)));
        client.hs = .init(.{
            .keypairs = .initWithP256(x25519, p256),
            .host_name = "spike.zoxy.test",
            .now_sec = 0,
            .random = .init(@splat(0x52)),
            .insecure_no_chain_anchor = true,
        });
        client.out = .empty;
        client.storage = .empty;
        client.records = .init(&client.storage.buffer);
        client.app_len = 0;
        client.saw_close = false;
    }

    fn hello(client: *Client, to_server: *Peer) !void {
        to_server.write(try client.hs.start(&client.out.buffer));
        client.hs.completeWrite();
    }

    fn feed(client: *Client, wire: []u8, to_server: *Peer) !void {
        var remaining = wire;
        // Bounded: each iteration moves at least one byte out of
        // `remaining`, and a drained record buffer always has room.
        while (remaining.len > 0) {
            const writable = client.records.writable();
            assert(writable.len > 0);
            const taken = @min(writable.len, remaining.len);
            @memcpy(writable[0..taken], remaining[0..taken]);
            client.records.advance(taken);
            remaining = remaining[taken..];
            while (try client.records.next()) |record| {
                switch (try client.hs.handleRecord(record, &client.out.buffer)) {
                    .write => |bytes| {
                        to_server.write(bytes);
                        client.hs.completeWrite();
                    },
                    .application_data => |bytes| {
                        assert(client.app_len + bytes.len <= client.app.len);
                        @memcpy(client.app[client.app_len..][0..bytes.len], bytes);
                        client.app_len += @intCast(bytes.len);
                    },
                    .closed => client.saw_close = true,
                    .key_update, .new_session_ticket, .none => {},
                }
            }
        }
    }

    fn send(client: *Client, bytes: []const u8, to_server: *Peer) !void {
        to_server.write(try client.hs.sendApplicationData(bytes, &client.out.buffer));
        client.hs.completeWrite();
    }
};

/// Everything one test needs, so each test's own body is the story it is
/// telling rather than six lines of setup.
const Bed = struct {
    arena_state: std.heap.ArenaAllocator,
    credentials: Credentials,
    engine: Engine,
    plaintext: [Engine.plaintext_bytes_min]u8,
    client: Client,
    to_server: Peer,
    to_client: Peer,

    fn init(bed: *Bed) !void {
        bed.arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        bed.credentials = try Credentials.load(
            bed.arena_state.allocator(),
            cert_pem,
            key_pem,
            .{},
        );
        bed.engine.bindPlaintext(&bed.plaintext);
        try bed.engine.init(&.{
            .x25519_seed = @splat(0x42),
            .random = @splat(0x43),
            .credentials = &bed.credentials,
        });
        try bed.client.init();
        bed.to_server = .{};
        bed.to_client = .{};
    }

    fn deinit(bed: *Bed) void {
        bed.engine.deinit();
        bed.client.hs.deinit();
        bed.credentials.deinit();
        bed.arena_state.deinit();
    }

    /// One server step: consume whatever the client sent, then hand the
    /// transport everything the engine staged and report it written.
    fn driveServer(bed: *Bed) !void {
        const wire = bed.to_server.take();
        if (wire.len > 0) {
            const sink = bed.to_client.sink();
            try bed.engine.feed(wire, &sink);
        }
        bed.drainOutbound();
    }

    fn drainOutbound(bed: *Bed) void {
        const staged = bed.engine.outbound();
        if (staged.len == 0) return;
        bed.to_client.write(staged);
        bed.engine.outboundSent(staged.len);
        assert(bed.engine.outbound().len == 0);
    }

    /// Pump both directions until the handshake settles.
    fn handshake(bed: *Bed) !void {
        try bed.client.hello(&bed.to_server);
        var rounds: u8 = 0;
        while (!(bed.engine.isConnected() and bed.client.hs.isConnected())) : (rounds += 1) {
            try std.testing.expect(rounds < rounds_max);
            try bed.driveServer();
            try bed.client.feed(bed.to_client.take(), &bed.to_server);
        }
        // The client's Finished still has to reach the engine: the loop
        // exits on the client believing it is connected, which happens one
        // step before the server has seen why.
        try bed.driveServer();
        try std.testing.expect(bed.engine.isConnected());
    }
};

test "engine: a handshake completes and carries application data both ways" {
    var bed: Bed = undefined;
    try bed.init();
    defer bed.deinit();
    try bed.handshake();

    try bed.client.send("hello-from-client", &bed.to_server);
    try bed.driveServer();
    try std.testing.expectEqualStrings(
        "hello-from-client",
        bed.to_client.app[0..bed.to_client.app_len],
    );

    try bed.engine.sendApp("hello-from-zoxy");
    bed.drainOutbound();
    try bed.client.feed(bed.to_client.take(), &bed.to_server);
    try std.testing.expectEqualStrings("hello-from-zoxy", bed.client.app[0..bed.client.app_len]);
}

test "engine: an orderly close is observable from both ends" {
    var bed: Bed = undefined;
    try bed.init();
    defer bed.deinit();
    try bed.handshake();

    // Server closes: the client must see close_notify, and the engine must
    // remember it said so after the bytes have left.
    try bed.engine.sendClose();
    try std.testing.expect(bed.engine.closeStaged());
    bed.drainOutbound();
    try bed.client.feed(bed.to_client.take(), &bed.to_server);
    try std.testing.expect(bed.client.saw_close);
}

test "engine: the peer's close_notify outlives the step that saw it" {
    var bed: Bed = undefined;
    try bed.init();
    defer bed.deinit();
    try bed.handshake();
    try std.testing.expect(!bed.engine.peerClosed());

    // A client close arrives as an in-band alert with no socket EOF behind
    // it. The sink reports it once; `peerClosed` is how a later read that
    // yielded nothing tells "fragment" from "stream over" (§6).
    bed.to_server.write(try bed.client.hs.sendAlert(.close_notify, &bed.client.out.buffer));
    bed.client.hs.completeWrite();
    try bed.driveServer();

    try std.testing.expect(bed.to_client.saw_close);
    try std.testing.expect(bed.engine.peerClosed());
}

// The reassembly buffer earns its field here: without it ztls answers a
// split ClientHello with a decode_error alert. An ordinary client never
// produces this; a hostile or MTU-shaped one can.
test "engine: a ClientHello fragmented across records still handshakes" {
    var bed: Bed = undefined;
    try bed.init();
    defer bed.deinit();

    var whole: Peer = .{};
    try bed.client.hello(&whole);
    refragment(whole.take(), &bed.to_server);

    var rounds: u8 = 0;
    while (!(bed.engine.isConnected() and bed.client.hs.isConnected())) : (rounds += 1) {
        try std.testing.expect(rounds < rounds_max);
        try bed.driveServer();
        try bed.client.feed(bed.to_client.take(), &bed.to_server);
    }
    try bed.driveServer();
    try std.testing.expect(bed.engine.isConnected());
}

// The outbox contract the data path depends on: ciphertext survives the
// call that produced it, and a short write is credited partially. That is
// what makes an async send safe against ztls's borrow-until-next-call
// buffers.
test "engine: the outbox survives the drive step and credits partial sends" {
    var bed: Bed = undefined;
    try bed.init();
    defer bed.deinit();

    try bed.client.hello(&bed.to_server);
    const sink = bed.to_client.sink();
    try bed.engine.feed(bed.to_server.take(), &sink);

    const staged = bed.engine.outbound();
    try std.testing.expect(staged.len > 0);
    // Copy it out, so a later engine call cannot alias what we compare.
    var expected: [wire_bytes_max]u8 = undefined;
    assert(staged.len <= expected.len);
    @memcpy(expected[0..staged.len], staged);
    const total = staged.len;

    // Drain one byte at a time: each credit shrinks the remainder from the
    // front, and the bytes never shift.
    var written: usize = 0;
    while (written < total) : (written += 1) {
        const remaining = bed.engine.outbound();
        try std.testing.expectEqual(total - written, remaining.len);
        try std.testing.expectEqualSlices(u8, expected[written..total], remaining);
        bed.engine.outboundSent(1);
    }
    try std.testing.expectEqual(@as(usize, 0), bed.engine.outbound().len);
}

// A record reassembled across many reads lands whole, so the plaintext
// destination has to cover a full record no matter how small the reads
// were. This is the case that would overflow a buffer sized by read size.
test "engine: a record split across single-byte reads still lands whole" {
    var bed: Bed = undefined;
    try bed.init();
    defer bed.deinit();
    try bed.handshake();

    var payload: [4096]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index % 251);
    try bed.client.send(&payload, &bed.to_server);

    const ciphertext = bed.to_server.take();
    try std.testing.expect(ciphertext.len > payload.len);
    const sink = bed.to_client.sink();
    for (ciphertext) |byte| {
        const destination = bed.engine.recvBuffer();
        destination[0] = byte;
        try bed.engine.received(1, &sink);
    }

    // One record in, one delivery out — not 4096 one-byte ones. This is
    // the count that makes the destination's sizing a record's worth
    // rather than a read's, and the byte total alone cannot see it.
    try std.testing.expectEqual(@as(u32, 1), bed.to_client.app_deliveries);
    try std.testing.expectEqual(payload.len, bed.to_client.app_len);
    try std.testing.expectEqualSlices(u8, &payload, bed.to_client.app[0..payload.len]);
}

// What `plaintext` is for and what its floor is sized against: a sink
// that appends into the engine's own destination, fed the largest record
// a conforming peer may send. The other tests copy into their own
// buffers, which cannot catch a floor that is too low; this one would
// overflow rather than fail politely, so it is the destination's real
// proof.
test "engine: a max-size record fits the plaintext destination" {
    var bed: Bed = undefined;
    try bed.init();
    defer bed.deinit();
    try bed.handshake();

    // The engine's own buffer, filled through the sink exactly as the data
    // path will fill it.
    var into: Into = .{ .engine = &bed.engine };

    // A conforming peer's largest single record, sent as one write. It has
    // to arrive as one delivery into a destination sized for it.
    var payload: [Engine.plaintext_record_bytes_max]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index % 251);
    try bed.client.send(&payload, &bed.to_server);

    const ciphertext = bed.to_server.take();
    // Bigger than one read: the record spans several, and still lands whole.
    try std.testing.expect(ciphertext.len > constants.tls_read_chunk_bytes);
    const sink = into.sink();
    try bed.engine.feed(ciphertext, &sink);

    try std.testing.expectEqual(@as(u32, 1), into.deliveries);
    try std.testing.expectEqual(payload.len, into.len);
    try std.testing.expectEqualSlices(u8, &payload, bed.engine.plaintext[0..into.len]);
}

/// A sink that writes into the engine's own `plaintext` buffer, the way
/// the data path does — the caller owning the cursor, the engine owning
/// the storage.
const Into = struct {
    engine: *Engine,
    len: u32 = 0,
    deliveries: u32 = 0,

    fn sink(into: *Into) Engine.Sink {
        return .{ .ctx = into, .appData = appData, .closed = closed };
    }

    fn appData(ctx: *anyopaque, bytes: []const u8) void {
        const into: *Into = @ptrCast(@alignCast(ctx));
        // No clamping: an overflow here is the floor being wrong, which is
        // exactly what this sink exists to find.
        assert(into.len + bytes.len <= into.engine.plaintext.len);
        @memcpy(into.engine.plaintext[into.len..][0..bytes.len], bytes);
        into.len += @intCast(bytes.len);
        into.deliveries += 1;
    }

    fn closed(ctx: *anyopaque) void {
        _ = ctx;
    }
};

/// A 5-byte TLS record header for a handshake (type 22) fragment.
fn handshakeRecordHeader(len: u16) [5]u8 {
    return .{ 22, 0x03, 0x03, @intCast(len >> 8), @intCast(len & 0xff) };
}

/// Re-frame one ClientHello record as two handshake records, each
/// carrying half the handshake-message body.
fn refragment(record: []const u8, out: *Peer) void {
    assert(record[0] == 22); // A handshake record.
    const body = record[5..];
    const split = body.len / 2;
    assert(split > 0);
    assert(split < body.len);
    out.write(&handshakeRecordHeader(@intCast(split)));
    out.write(body[0..split]);
    out.write(&handshakeRecordHeader(@intCast(body.len - split)));
    out.write(body[split..]);
}
