//! The engine's contract with the data path (DESIGN.md §4), driven by a
//! raw zssl client over an in-memory wire. What is pinned here is what
//! slices above this one will assume without re-checking: a handshake
//! completes, a fragmented ClientHello does not fail it, the outbox
//! survives the call that filled it and credits partial sends, and an
//! orderly close is observable from both ends.

const std = @import("std");

const constants = @import("../constants.zig");
const Credentials = @import("Credentials.zig");
const Engine = @import("Engine.zig");
const certificate_set = @import("certificate_set.zig");
const trust = @import("trust.zig");
const zssl = @import("zssl");

const assert = std.debug.assert;

const cert_pem = @embedFile("testdata/cert.pem");
const key_pem = @embedFile("testdata/key.pem");
const client_ca_pem = @embedFile("testdata/client-ca.pem");
const client_cert_pem = @embedFile("testdata/client-cert.pem");
const client_key_pem = @embedFile("testdata/client-key.pem");
const other_ca_pem = @embedFile("testdata/other-ca.pem");
const origin_cert_pem = @embedFile("testdata/origin-cert.pem");
const origin_key_pem = @embedFile("testdata/origin-key.pem");
const rsa_cert_pem = @embedFile("testdata/rsa2048-cert.pem");
const rsa_key_pem = @embedFile("testdata/rsa2048-key.pem");
/// A leaf with a 3065-bit RSA key, issued by its own throwaway CA
/// (#441): a modulus of 8k+1 bits, which std.crypto's RSA-PSS verifier
/// asserts on.
const rsa3065_ca_pem = @embedFile("testdata/rsa3065-ca.pem");
const rsa3065_issued_cert_pem = @embedFile("testdata/rsa3065-issued-cert.pem");
const rsa3065_key_pem = @embedFile("testdata/rsa3065-key.pem");
const names_ca_pem = @embedFile("testdata/names-ca.pem");
const names_client_cert_pem = @embedFile("testdata/names-client-cert.pem");
const names_client_key_pem = @embedFile("testdata/names-client-key.pem");

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

    /// Mutable: records are decrypted in place.
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

/// The raw zssl client half, fully seeded so nothing it contributes to
/// the transcript varies between runs.
const Client = struct {
    hs: zssl.ClientHandshake,
    out: [zssl.ClientHandshake.out_bytes_min]u8,
    storage: [zssl.record.wire_record_bytes_max]u8,
    reassembly: [16 * 1024]u8,
    /// The client's own Certificate and CertificateVerify, for #304's
    /// mutual-TLS tests: the chain plus ~1 KiB, as zssl asks.
    auth_flight: [zssl.Credentials.chain_bytes_max + 1024]u8,
    records: zssl.record_buffer.RecordBuffer,
    app: [app_bytes_max]u8 = undefined,
    app_len: u32 = 0,
    saw_close: bool = false,

    fn init(client: *Client) !void {
        return client.initPresenting(null);
    }

    /// `credentials` is what the client answers a CertificateRequest
    /// with (#304); null answers with an empty certificate list.
    fn initPresenting(client: *Client, credentials: ?*const zssl.Credentials) !void {
        return client.initFull(credentials, "spike.zoxy.test", null, &zssl.client_messages.signature_schemes_default);
    }

    /// The full form: what to present, which server to name (#297),
    /// optionally a verifier shown the server's chain — the one way to see
    /// which certificate the server actually sent — and which signature
    /// schemes to offer (#411), which is how a test plays a client that
    /// cannot verify one key type.
    fn initFull(
        client: *Client,
        credentials: ?*const zssl.Credentials,
        server_name: []const u8,
        chain_verifier: ?zssl.certificate_list.ChainVerifier,
        verify_schemes: []const zssl.backend.SignatureScheme,
    ) !void {
        assert(verify_schemes.len >= 1);
        client.hs = .init(&.{
            .client_random = @splat(0x52),
            .x25519_private = @splat(0x51),
            .server_name = server_name,
            // The fixture is self-signed and what these tests exercise is
            // zoxy's engine, not this client's trust decisions — except
            // where a test asks to see the chain.
            .certificate_policy = if (chain_verifier != null) .leaf_signature else .insecure_no_verification,
            .chain_verifier = chain_verifier,
            .verify_schemes = verify_schemes,
            .reassembly = &client.reassembly,
            .client_credentials = credentials,
            .client_auth_flight = if (credentials != null) &client.auth_flight else &.{},
        });
        client.records = .init(&client.storage);
        client.app_len = 0;
        client.saw_close = false;
    }

    fn hello(client: *Client, to_server: *Peer) !void {
        to_server.write(client.hs.start(&client.out));
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
            while (try client.records.next()) |wire_record| {
                // Drained to null: one record may carry several
                // post-handshake messages, and zssl refuses the next
                // record while any of them are still pending.
                var next_event = try client.hs.handleRecord(wire_record, &client.out);
                while (next_event) |event| : (next_event = try client.hs.drain(&client.out)) {
                    switch (event) {
                        // `.connected` carries the client flight, so both
                        // arms put bytes on the wire.
                        .send, .connected => |bytes| to_server.write(bytes),
                        .application_data => |bytes| {
                            assert(client.app_len + bytes.len <= client.app.len);
                            @memcpy(client.app[client.app_len..][0..bytes.len], bytes);
                            client.app_len += @intCast(bytes.len);
                        },
                        .closed => client.saw_close = true,
                        .ticket => {},
                    }
                }
            }
        }
    }

    fn send(client: *Client, bytes: []const u8, to_server: *Peer) !void {
        to_server.write(try client.hs.sendApplicationData(bytes, &client.out));
    }
};

/// A certificate chain and its key, as PEM.
const PemPair = struct { cert: []const u8, key: []const u8 };

/// Everything one test needs, so each test's own body is the story it is
/// telling rather than six lines of setup.
const Bed = struct {
    arena_state: std.heap.ArenaAllocator,
    credentials: Credentials,
    client_credentials: ?Credentials = null,
    engine: Engine,
    plaintext: [Engine.plaintext_bytes_min]u8,
    body_plaintext: [Engine.plaintext_bytes_min]u8,
    client: Client,
    to_server: Peer,
    to_client: Peer,

    fn init(bed: *Bed) !void {
        return bed.initWith(.{});
    }

    /// The deterministic-nonce tests below need the other setting, and
    /// nothing else about the bed changes with it.
    fn initWith(bed: *Bed, options: Credentials.Options) !void {
        bed.client_credentials = null;
        bed.arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        bed.credentials = try Credentials.load(
            bed.arena_state.allocator(),
            cert_pem,
            key_pem,
            options,
        );
        bed.engine.bindPlaintext(
            &bed.plaintext,
            &bed.body_plaintext,
            constants.head_buffer_bytes_default,
        );
        try bed.engine.init(&.{
            .x25519_seed = @splat(0x42),
            .random = @splat(0x43),
            .credentials = &bed.credentials,
        });
        try bed.client.init();
        bed.to_server = .{};
        bed.to_client = .{};
    }

    /// A listener asking for a client certificate (#304), against the
    /// client CA's fixtures at 2030, inside their window. `present` is
    /// whether the client answers with its certificate; `anchors_pem`
    /// is what the listener trusts.
    fn initMutual(bed: *Bed, require: bool, present: bool, anchors_pem: []const u8) !void {
        const client_pair: PemPair = .{ .cert = client_cert_pem, .key = client_key_pem };
        return bed.initMutualPresenting(require, if (present) client_pair else null, anchors_pem);
    }

    /// The same, with the pair the client presents named; null answers
    /// with an empty certificate list.
    fn initMutualPresenting(
        bed: *Bed,
        require: bool,
        presented: ?PemPair,
        anchors_pem: []const u8,
    ) !void {
        bed.arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        const arena = bed.arena_state.allocator();
        bed.credentials = try Credentials.load(arena, cert_pem, key_pem, .{});
        bed.client_credentials = if (presented) |pair|
            try Credentials.load(arena, pair.cert, pair.key, .{})
        else
            null;
        bed.engine.bindPlaintext(&bed.plaintext, &bed.body_plaintext, constants.head_buffer_bytes_default);
        try bed.engine.init(&.{
            .x25519_seed = @splat(0x42),
            .random = @splat(0x43),
            .credentials = &bed.credentials,
            .now_unix = 1_893_456_000,
            .client_auth = .{ .anchors = try trust.parseAnchors(arena, anchors_pem), .require = require },
        });
        const presenting = if (bed.client_credentials) |*credentials| &credentials.inner else null;
        try bed.client.initPresenting(presenting);
        bed.to_server = .{};
        bed.to_client = .{};
    }

    fn deinit(bed: *Bed) void {
        bed.engine.deinit();
        bed.client.hs.deinit();
        bed.credentials.deinit();
        if (bed.client_credentials) |*credentials| credentials.deinit();
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
        while (!(bed.engine.isConnected() and bed.client.hs.state == .connected)) : (rounds += 1) {
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
    bed.to_server.write(try bed.client.hs.sendClose(&bed.client.out));
    try bed.driveServer();

    try std.testing.expect(bed.to_client.saw_close);
    try std.testing.expect(bed.engine.peerClosed());
}

// The reassembly buffer earns its field here: without it a server answers a
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
    while (!(bed.engine.isConnected() and bed.client.hs.state == .connected)) : (rounds += 1) {
        try std.testing.expect(rounds < rounds_max);
        try bed.driveServer();
        try bed.client.feed(bed.to_client.take(), &bed.to_server);
    }
    try bed.driveServer();
    try std.testing.expect(bed.engine.isConnected());
}

// The outbox contract the data path depends on: ciphertext survives the
// call that produced it, and a short write is credited partially. That is
// what makes an async send safe against zssl's borrow-until-next-call
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

/// The server's first flight — ServerHello through Finished — as one
/// seeded run produces it. Everything that feeds it is fixed: the
/// engine's two seeds, the client's, and the credential.
fn seededServerFlight(out: []u8, options: Credentials.Options) ![]const u8 {
    var bed: Bed = undefined;
    try bed.initWith(options);
    defer bed.deinit();
    try bed.client.hello(&bed.to_server);
    try bed.driveServer();
    const flight = bed.to_client.wire[0..bed.to_client.wire_len];
    assert(flight.len >= 1);
    assert(flight.len <= out.len);
    @memcpy(out[0..flight.len], flight);
    return out[0..flight.len];
}

// §9's oracle is "run one seed twice, hash every delivery, assert the
// hashes match". A server whose CertificateVerify signature varies run
// to run can never satisfy it, so TLS traffic would be the one thing the
// simulator could carry but never assert on. This is that property,
// taken through the Engine the simulator actually drives.
test "engine: identical seeds yield a byte-exact server flight" {
    var first_storage: [2 * Engine.emitted_record_bytes_max]u8 = undefined;
    var second_storage: [2 * Engine.emitted_record_bytes_max]u8 = undefined;
    const first = try seededServerFlight(&first_storage, .{ .deterministic_nonce = true });
    const second = try seededServerFlight(&second_storage, .{ .deterministic_nonce = true });

    try std.testing.expect(first.len > 0);
    try std.testing.expectEqualSlices(u8, first, second);
}

// Negative space, and the reason the option exists at all: with
// libcrypto's hedged random ECDSA nonce the CertificateVerify signature
// differs every run, and DER integer trimming makes even the *length* of
// the encrypted flight vary. Everything else is identical between the two
// runs — same seeds, same credential, same code path — so a divergence
// can only come from the nonce.
test "engine: without the deterministic nonce the same flight diverges" {
    var first_storage: [2 * Engine.emitted_record_bytes_max]u8 = undefined;
    var second_storage: [2 * Engine.emitted_record_bytes_max]u8 = undefined;
    const first = try seededServerFlight(&first_storage, .{ .deterministic_nonce = false });
    const second = try seededServerFlight(&second_storage, .{ .deterministic_nonce = false });

    try std.testing.expect(!std.mem.eql(u8, first, second));
    // The divergence is confined to the encrypted flight: ServerHello
    // carries only seeded material, so it must still match byte for byte.
    // If this ever fails, something *other* than the signature is varying
    // and the determinism claim above rests on the wrong evidence.
    const server_hello_bytes = zssl.record.header_bytes +
        std.mem.readInt(u16, first[3..5], .big);
    try std.testing.expectEqualSlices(
        u8,
        first[0..server_hello_bytes],
        second[0..server_hello_bytes],
    );
}

test "engine: a client certificate the listener's CA signed completes the handshake, fingerprint kept (#304)" {
    var bed: Bed = undefined;
    try bed.initMutual(true, true, client_ca_pem);
    defer bed.deinit();
    try bed.handshake();
    var expected: [trust.fingerprint_bytes]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "F1FD192CFF76490BAF1534F777226E96DBB03D9751A657648E0955116D0D4FCB");
    try std.testing.expectEqualSlices(u8, &expected, bed.engine.clientFingerprint().?);
    try std.testing.expect(!bed.engine.clientCertRefused());
}

test "engine: no client certificate where one is required is refused with certificate_required (#304)" {
    var bed: Bed = undefined;
    try bed.initMutual(true, false, client_ca_pem);
    defer bed.deinit();
    try std.testing.expectError(error.CertificateRequired, bed.handshake());
    try std.testing.expect(bed.engine.clientFingerprint() == null);
    // The transport's answer: the alert, staged for the flush before the
    // teardown.
    bed.engine.refuseMissingCertificate();
    try std.testing.expect(bed.engine.isRefused());
    try std.testing.expect(bed.engine.outbound().len >= 1);
}

test "engine: an optional client CA lets a client without a certificate in, unauthenticated (#304)" {
    var bed: Bed = undefined;
    try bed.initMutual(false, false, client_ca_pem);
    defer bed.deinit();
    try bed.handshake();
    try std.testing.expect(bed.engine.clientFingerprint() == null);
    try std.testing.expect(!bed.engine.clientCertRefused());
}

test "engine: a client key of 8k+1 bits is refused, where it used to stop the process (#441)" {
    // The listener's CA issued this leaf, so the chain passes
    // `verifyClientChain` and zssl goes on to check the client's
    // CertificateVerify. Over a 3065-bit modulus, std.crypto's RSA-PSS
    // verifier asserts; zssl now refuses such a key before calling it
    // (zoxy-io/zssl#23).
    var bed: Bed = undefined;
    const presented: PemPair = .{ .cert = rsa3065_issued_cert_pem, .key = rsa3065_key_pem };
    try bed.initMutualPresenting(true, presented, rsa3065_ca_pem);
    defer bed.deinit();
    try std.testing.expectError(error.BadCertificate, bed.handshake());
    try std.testing.expect(!bed.engine.isConnected());
    // The chain was good: it is the key that failed, not the CA.
    try std.testing.expect(!bed.engine.clientCertRefused());
}

test "engine: a client certificate from another CA is refused, optional or not (#304)" {
    inline for (.{ true, false }) |require| {
        var bed: Bed = undefined;
        try bed.initMutual(require, true, other_ca_pem);
        defer bed.deinit();
        try std.testing.expect(std.meta.isError(bed.handshake()));
        try std.testing.expect(bed.engine.clientCertRefused());
        try std.testing.expect(bed.engine.clientFingerprint() == null);
    }
}

test "engine: the ClientHello's server name chooses among a listener's certificates (#297)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var default_credentials = try Credentials.load(arena, cert_pem, key_pem, .{});
    defer default_credentials.deinit();
    var origin_credentials = try Credentials.load(arena, origin_cert_pem, origin_key_pem, .{});
    defer origin_credentials.deinit();
    const choices = [_]certificate_set.Choice{
        .{
            .credentials = &default_credentials,
            .names = try trust.dnsNames(arena, default_credentials.chain[0]),
            .schemes = default_credentials.schemes(),
        },
        .{
            .credentials = &origin_credentials,
            .names = try trust.dnsNames(arena, origin_credentials.chain[0]),
            .schemes = origin_credentials.schemes(),
        },
    };
    // Each name gets its own certificate; one neither covers, the default.
    const cases = [_]struct { name: []const u8, chosen: usize }{
        .{ .name = "origin.zoxy.test", .chosen = 1 },
        .{ .name = "spike.zoxy.test", .chosen = 0 },
        .{ .name = "nobody.zoxy.test", .chosen = 0 },
    };
    for (cases) |case| {
        var shown: ShownLeaf = .{};
        const outcome = try chooseAndConnect(&choices, case.name, &zssl.client_messages.signature_schemes_default, &shown);
        try std.testing.expectEqual(case.chosen, outcome.chosen);
        // What the client was actually shown, not only what the engine
        // says it chose: the chosen certificate's own leaf.
        try std.testing.expectEqualSlices(u8, choices[case.chosen].credentials.chain[0], shown.leaf());
        try std.testing.expect(!outcome.rsa);
    }
}

test "engine: an RSA certificate signs only for a client that cannot take the ECDSA one (#411)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var ecdsa_credentials = try Credentials.load(arena, cert_pem, key_pem, .{});
    defer ecdsa_credentials.deinit();
    // Covers rsa.zoxy.test and spike.zoxy.test — the second the ECDSA
    // default's own name, so one name has both key types behind it.
    var rsa_credentials = try Credentials.load(arena, rsa_cert_pem, rsa_key_pem, .{});
    defer rsa_credentials.deinit();
    const choices = [_]certificate_set.Choice{
        .{
            .credentials = &ecdsa_credentials,
            .names = try trust.dnsNames(arena, ecdsa_credentials.chain[0]),
            .schemes = ecdsa_credentials.schemes(),
        },
        .{
            .credentials = &rsa_credentials,
            .names = try trust.dnsNames(arena, rsa_credentials.chain[0]),
            .schemes = rsa_credentials.schemes(),
        },
    };
    const every = &zssl.client_messages.signature_schemes_default;
    const rsa_only: []const zssl.backend.SignatureScheme = &.{.rsa_pss_rsae_sha256};
    const cases = [_]struct { name: []const u8, offers: []const zssl.backend.SignatureScheme, chosen: usize }{
        // Both verifiable: the cheaper sign, ECDSA, for the shared name.
        .{ .name = "spike.zoxy.test", .offers = every, .chosen = 0 },
        // A client that verifies RSA alone gets the RSA certificate.
        .{ .name = "spike.zoxy.test", .offers = rsa_only, .chosen = 1 },
        // A name only the RSA certificate covers.
        .{ .name = "rsa.zoxy.test", .offers = every, .chosen = 1 },
    };
    for (cases) |case| {
        var shown: ShownLeaf = .{};
        const outcome = try chooseAndConnect(&choices, case.name, case.offers, &shown);
        try std.testing.expectEqual(case.chosen, outcome.chosen);
        try std.testing.expectEqualSlices(u8, choices[case.chosen].credentials.chain[0], shown.leaf());
        try std.testing.expectEqual(case.chosen == 1, outcome.rsa);
    }
}

test "engine: a listener holding only an RSA certificate signs RSA-PSS (#411)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var rsa_credentials = try Credentials.load(arena_state.allocator(), rsa_cert_pem, rsa_key_pem, .{});
    defer rsa_credentials.deinit();
    var shown: ShownLeaf = .{};
    // No certificate set: one certificate, nothing to choose.
    const choices = [_]certificate_set.Choice{.{ .credentials = &rsa_credentials, .names = &.{}, .schemes = rsa_credentials.schemes() }};
    const outcome = try chooseAndConnect(choices[0..1], "rsa.zoxy.test", &zssl.client_messages.signature_schemes_default, &shown);
    try std.testing.expectEqual(@as(usize, 0), outcome.chosen);
    try std.testing.expect(outcome.rsa);
    try std.testing.expectEqualSlices(u8, rsa_credentials.chain[0], shown.leaf());
}

/// One handshake against a listener holding `choices` (#297, #411): the
/// default first, and a single choice meaning no set at all. The client
/// names `name` and offers `offers`, and its hello is fed seven bytes at a
/// time so the choice has to wait for the whole record. `shown` gets the
/// leaf the client was actually sent.
fn chooseAndConnect(
    choices: []const certificate_set.Choice,
    name: []const u8,
    offers: []const zssl.backend.SignatureScheme,
    shown: *ShownLeaf,
) !struct { chosen: usize, rsa: bool } {
    assert(choices.len >= 1);
    assert(offers.len >= 1);
    var engine: Engine = undefined;
    var plaintext: [Engine.plaintext_bytes_min]u8 = undefined;
    var body_plaintext: [Engine.plaintext_bytes_min]u8 = undefined;
    engine.bindPlaintext(&plaintext, &body_plaintext, constants.head_buffer_bytes_default);
    try engine.init(&.{
        .x25519_seed = @splat(0x42),
        .random = @splat(0x43),
        .credentials = choices[0].credentials,
        .certificates = if (choices.len == 1) &.{} else choices,
    });
    defer engine.deinit();
    var client: Client = undefined;
    try client.initFull(null, name, .{ .context = shown, .verify = ShownLeaf.record }, offers);
    defer client.hs.deinit();
    var to_server: Peer = .{};
    var to_client: Peer = .{};
    try client.hello(&to_server);
    var rounds: u8 = 0;
    while (!(engine.isConnected() and client.hs.state == .connected)) : (rounds += 1) {
        try std.testing.expect(rounds < rounds_max);
        const wire = to_server.take();
        var offset: usize = 0;
        while (offset < wire.len) {
            const end = @min(offset + 7, wire.len);
            try engine.feed(wire[offset..end], &to_client.sink());
            offset = end;
        }
        const staged = engine.outbound();
        if (staged.len > 0) {
            to_client.write(staged);
            engine.outboundSent(staged.len);
        }
        try client.feed(to_client.take(), &to_server);
    }
    return .{ .chosen = engine.chosenCertificate(), .rsa = engine.signedWithRsa() };
}

/// The server's leaf as a client was shown it (#297), captured by zssl's
/// chain verifier while the bytes are live.
const ShownLeaf = struct {
    bytes: [4096]u8 = undefined,
    len: usize = 0,

    fn record(context: *anyopaque, chain: zssl.certificate_list.CertificateList) bool {
        const self: *ShownLeaf = @ptrCast(@alignCast(context));
        var iterator = chain.iterator();
        const first = (iterator.next() catch return false) orelse return false;
        if (first.len > self.bytes.len) return false;
        @memcpy(self.bytes[0..first.len], first);
        self.len = first.len;
        return true;
    }

    fn leaf(self: *const ShownLeaf) []const u8 {
        return self.bytes[0..self.len];
    }
};

test "engine: a verified client's names are kept beside its fingerprint (#432)" {
    var bed: Bed = undefined;
    const presented: PemPair = .{ .cert = names_client_cert_pem, .key = names_client_key_pem };
    try bed.initMutualPresenting(true, presented, names_ca_pem);
    defer bed.deinit();
    try bed.handshake();
    try std.testing.expect(bed.engine.clientFingerprint() != null);
    const names = bed.engine.clientNames().?;
    try std.testing.expectEqual(@as(u8, 3), names.count);
    try std.testing.expectEqualStrings("spiffe://zoxy.test/ns/edge/sa/reports", names.value(0));
}

test "engine: a session with no verified client has no names (#432)" {
    var bed: Bed = undefined;
    try bed.initMutual(false, false, names_ca_pem);
    defer bed.deinit();
    try bed.handshake();
    try std.testing.expect(bed.engine.clientNames() == null);
}

/// One side of a QUIC handshake in memory (#449): the CRYPTO bytes owed
/// to the other side, per level, and what this side was handed.
const QuicSide = struct {
    owed: [3][4096]u8 = undefined,
    owed_len: [3]u32 = .{ 0, 0, 0 },
    send_secrets: [3]?[48]u8 = .{ null, null, null },
    receive_secrets: [3]?[48]u8 = .{ null, null, null },
    tickets: u8 = 0,
    peer_parameters: [64]u8 = undefined,
    peer_parameters_len: u8 = 0,
    connected: bool = false,

    fn sink(side: *QuicSide) Engine.QuicSink {
        return .{
            .ctx = side,
            .crypto = crypto,
            .secret = secret,
            .transportParameters = transportParameters,
            .connected = connectedHook,
        };
    }

    fn crypto(ctx: *anyopaque, level: Engine.QuicLevel, bytes: []const u8) error{QuicSinkRefused}!void {
        const side: *QuicSide = @ptrCast(@alignCast(ctx));
        side.owe(level, bytes);
    }

    fn owe(side: *QuicSide, level: Engine.QuicLevel, bytes: []const u8) void {
        const index = @backingInt(level);
        assert(side.owed_len[index] + bytes.len <= side.owed[index].len);
        @memcpy(side.owed[index][side.owed_len[index]..][0..bytes.len], bytes);
        side.owed_len[index] += @intCast(bytes.len);
    }

    fn secret(ctx: *anyopaque, given: *const Engine.QuicSecret) error{QuicSinkRefused}!void {
        const side: *QuicSide = @ptrCast(@alignCast(ctx));
        side.keep(given);
    }

    fn keep(side: *QuicSide, given: *const Engine.QuicSecret) void {
        assert(given.bytes.len <= 48);
        var copy: [48]u8 = @splat(0);
        @memcpy(copy[0..given.bytes.len], given.bytes);
        const index = @backingInt(given.level);
        switch (given.direction) {
            .send => side.send_secrets[index] = copy,
            .receive => side.receive_secrets[index] = copy,
        }
    }

    fn transportParameters(ctx: *anyopaque, bytes: []const u8) error{QuicSinkRefused}!void {
        const side: *QuicSide = @ptrCast(@alignCast(ctx));
        assert(bytes.len <= side.peer_parameters.len);
        @memcpy(side.peer_parameters[0..bytes.len], bytes);
        side.peer_parameters_len = @intCast(bytes.len);
    }

    fn connectedHook(ctx: *anyopaque) void {
        const side: *QuicSide = @ptrCast(@alignCast(ctx));
        side.connected = true;
    }

    /// What this side owes at `level`, taken.
    fn take(side: *QuicSide, level: Engine.QuicLevel, into: []u8) []u8 {
        const index = @backingInt(level);
        const len = side.owed_len[index];
        @memcpy(into[0..len], side.owed[index][0..len]);
        side.owed_len[index] = 0;
        return into[0..len];
    }
};

/// A QUIC handshake in memory (#449): a QUIC-mode engine, zssl's QUIC
/// client, and what each owes the other by level. The engine is the
/// server; nothing here protects packets, which is h3's job.
const QuicBed = struct {
    arena_state: std.heap.ArenaAllocator,
    credentials: Credentials,
    engine: Engine,
    plaintext: [Engine.plaintext_bytes_min]u8,
    body_plaintext: [Engine.plaintext_bytes_min]u8,
    reassembly: [16 * 1024]u8,
    client: zssl.ClientHandshake,
    client_out: [zssl.ClientHandshake.out_bytes_min]u8,
    server: QuicSide,
    client_side: QuicSide,
    /// CRYPTO bytes the server has not yet taken: a ClientHello still
    /// arriving waits here, as h3's reassembly holds it.
    unread: [4096]u8,
    unread_len: u32,

    const server_parameters = "\x04\x04\x80\x10\x00\x00";
    const client_parameters = "\x05\x04\x80\x08\x00\x00";

    /// Allocated: an engine and its buffers outgrow a test's stack.
    fn create(certificates: []const certificate_set.Choice, tickets: ?*const Tickets_) !*QuicBed {
        const bed = try std.testing.allocator.create(QuicBed);
        errdefer std.testing.allocator.destroy(bed);
        bed.arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        bed.credentials = try Credentials.load(bed.arena_state.allocator(), cert_pem, key_pem, .{});
        bed.engine.bindPlaintext(&bed.plaintext, &bed.body_plaintext, constants.head_buffer_bytes_default);
        try bed.engine.init(&.{
            .x25519_seed = @splat(0x42),
            .random = @splat(0x43),
            .credentials = if (certificates.len > 0) certificates[0].credentials else &bed.credentials,
            .certificates = certificates,
            .tickets = tickets,
            .now_unix = 1_900_000_000,
            .quic = .{ .transport_parameters = server_parameters },
        });
        bed.server = .{};
        bed.client_side = .{};
        bed.unread_len = 0;
        assert(bed.engine.isQuic());
        return bed;
    }

    fn connectAs(bed: *QuicBed, server_name: []const u8) void {
        bed.client = zssl.ClientHandshake.init(&.{
            .client_random = @splat(0x52),
            .x25519_private = @splat(0x51),
            .server_name = server_name,
            .alpn_protocols = Engine.quic_alpn,
            .certificate_policy = .insecure_no_verification,
            .reassembly = &bed.reassembly,
            .quic = .{ .transport_parameters = client_parameters },
        });
        const hello = bed.client.startCrypto();
        bed.client_side.owe(hello.level, hello.bytes);
    }

    fn destroy(bed: *QuicBed) void {
        bed.client.deinit();
        bed.engine.deinit();
        bed.credentials.deinit();
        bed.arena_state.deinit();
        std.testing.allocator.destroy(bed);
    }

    /// Hand the server `bytes` at `level` behind whatever it left
    /// untaken, keeping what it does not take for the next delivery.
    fn deliverToServer(bed: *QuicBed, level: Engine.QuicLevel, bytes: []const u8) !void {
        assert(bed.unread_len + bytes.len <= bed.unread.len);
        @memcpy(bed.unread[bed.unread_len..][0..bytes.len], bytes);
        bed.unread_len += @intCast(bytes.len);
        const sink = bed.server.sink();
        const taken = try bed.engine.quicCrypto(level, bed.unread[0..bed.unread_len], &sink);
        // All or nothing: a hello still arriving is taken none of.
        try std.testing.expect(taken == 0 or taken == bed.unread_len);
        if (taken == bed.unread_len) bed.unread_len = 0;
    }

    fn deliverToClient(bed: *QuicBed, level: Engine.QuicLevel, bytes: []const u8) !void {
        var next = try bed.client.handleCrypto(level, bytes, &bed.client_out);
        while (next) |event| : (next = try bed.client.drainCrypto(&bed.client_out)) {
            switch (event) {
                .crypto => |crypto| bed.client_side.owe(crypto.level, crypto.bytes),
                .secret => |given| bed.client_side.keep(&given),
                .transport_parameters => |body| {
                    @memcpy(bed.client_side.peer_parameters[0..body.len], body);
                    bed.client_side.peer_parameters_len = @intCast(body.len);
                },
                .ticket => bed.client_side.tickets += 1,
                .connected => bed.client_side.connected = true,
            }
        }
    }

    /// One exchange each way, every level in order.
    fn round(bed: *QuicBed) !void {
        var scratch: [4096]u8 = undefined;
        for (std.enums.values(Engine.QuicLevel)) |level| {
            const bytes = bed.client_side.take(level, &scratch);
            if (bytes.len > 0) try bed.deliverToServer(level, bytes);
        }
        for (std.enums.values(Engine.QuicLevel)) |level| {
            const bytes = bed.server.take(level, &scratch);
            if (bytes.len > 0) try bed.deliverToClient(level, bytes);
        }
    }

    fn handshake(bed: *QuicBed) !void {
        var rounds: u8 = 0;
        while (!(bed.client_side.connected and bed.server.connected)) : (rounds += 1) {
            try std.testing.expect(rounds < rounds_max);
            try bed.round();
        }
        try std.testing.expect(bed.engine.isConnected());
    }

    /// What one side sends with is what the other receives with, at both
    /// levels and both ways; and each side's transport parameters reached
    /// the other verbatim.
    fn expectAgreement(bed: *const QuicBed) !void {
        try std.testing.expectEqualStrings(client_parameters, bed.server.peer_parameters[0..bed.server.peer_parameters_len]);
        try std.testing.expectEqualStrings(server_parameters, bed.client_side.peer_parameters[0..bed.client_side.peer_parameters_len]);
        for ([_]Engine.QuicLevel{ .handshake, .application }) |level| {
            const index = @backingInt(level);
            try std.testing.expectEqualSlices(u8, &bed.server.send_secrets[index].?, &bed.client_side.receive_secrets[index].?);
            try std.testing.expectEqualSlices(u8, &bed.client_side.send_secrets[index].?, &bed.server.receive_secrets[index].?);
        }
    }
};

const Tickets_ = @import("Tickets.zig");

test "engine: QUIC mode completes a handshake at the message level, every secret agreeing (#449)" {
    const bed = try QuicBed.create(&.{}, null);
    defer bed.destroy();
    bed.connectAs("spike.zoxy.test");
    try bed.handshake();
    try bed.expectAgreement();
}

test "engine: QUIC mode chooses a certificate by name from a ClientHello delivered in pieces (#449, #297)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var default_credentials = try Credentials.load(arena, cert_pem, key_pem, .{});
    defer default_credentials.deinit();
    var origin_credentials = try Credentials.load(arena, origin_cert_pem, origin_key_pem, .{});
    defer origin_credentials.deinit();
    const choices = [_]certificate_set.Choice{
        .{ .credentials = &default_credentials, .names = try trust.dnsNames(arena, default_credentials.chain[0]), .schemes = default_credentials.schemes() },
        .{ .credentials = &origin_credentials, .names = try trust.dnsNames(arena, origin_credentials.chain[0]), .schemes = origin_credentials.schemes() },
    };
    const bed = try QuicBed.create(&choices, null);
    defer bed.destroy();
    bed.connectAs("origin.zoxy.test");
    // The hello's first half decides nothing and is taken none of; the
    // rest completes it, the name chooses, and the handshake runs.
    var scratch: [4096]u8 = undefined;
    const hello = bed.client_side.take(.initial, &scratch);
    try std.testing.expect(hello.len > 2);
    try bed.deliverToServer(.initial, hello[0 .. hello.len / 2]);
    try std.testing.expectEqual(@as(u32, @intCast(hello.len / 2)), bed.unread_len);
    try bed.deliverToServer(.initial, hello[hello.len / 2 ..]);
    try std.testing.expectEqual(@as(u32, 0), bed.unread_len);
    try bed.handshake();
    try std.testing.expectEqual(@as(usize, 1), bed.engine.chosenCertificate());
    try bed.expectAgreement();
}

test "engine: a QUIC session ticket reaches the client as an application-level message (#449)" {
    var tickets: Tickets_ = undefined;
    tickets.init();
    tickets.rotate(@splat(0x61), 1_900_000_000);
    const bed = try QuicBed.create(&.{}, &tickets);
    defer bed.destroy();
    bed.connectAs("spike.zoxy.test");
    try bed.handshake();
    const message = try bed.engine.quicSessionTicket("n", 7, @splat(0x62));
    try std.testing.expect(message.len >= 1);
    try bed.deliverToClient(.application, message);
    try std.testing.expectEqual(@as(u8, 1), bed.client_side.tickets);
}
