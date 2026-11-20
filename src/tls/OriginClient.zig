//! The client end of TLS to an origin (§7; #296): sans-I/O, like the
//! server's `Engine`, so what drives it — an `h2` cluster's pooled
//! connection (`http/h2/origin_pool.zig`), or an HTTPS cluster's upstream
//! connection (`net/upstream_tls.zig`) — keeps its one recv and one send
//! and never learns its octets were encrypted.
//!
//! It owns the zssl client handshake and every buffer the connection's TLS
//! needs — a record's worth of wire in, a record's worth out, the
//! handshake's reassembly, and decrypted application data waiting for the
//! HTTP/2 session — so a pooled slot is a whole client, wired once.
//!
//! The chain the origin presents is judged by `trust.zig` against the
//! cluster's anchors and its `server_name`, which is also the SNI it
//! sends. ALPN offers the one protocol the connection speaks — `h2`, or
//! `http/1.1` — and what the origin selects is the caller's to judge.
//!
//! One buffer of wire octets is owed to the socket at a time — a handshake
//! flight or one sealed record — and records are not read while it is,
//! since an event may borrow the same buffer. A sealed record carries the
//! session's plaintext; it is credited back to the session only once the
//! whole record is out (`sent`).

const std = @import("std");
const zssl = @import("zssl");

const trust = @import("trust.zig");
const constants = @import("../constants.zig");

const assert = std.debug.assert;

const OriginClient = @This();

/// The handshake's reassembly: the origin's certificate chain must fit.
pub const reassembly_bytes = constants.origin_tls_reassembly_bytes;

/// The most plaintext one record carries (RFC 8446 §5.1).
pub const record_plaintext_bytes_max: u32 = constants.tls_record_plaintext_bytes_max;

/// The most records one `process` reads: every one the wire buffer can
/// hold, each at least its five-octet header — so the buffer is drained
/// whole, whatever its records decrypt to, and none waits for a read.
const records_per_process_max: u32 = 2 * zssl.record.wire_record_bytes_max / 5 + 1;

/// The most events one record raises: a handshake flight's messages, or a
/// few post-handshake ones.
const events_per_record_max: u32 = 16;

/// Room for two records' plaintext: one the session is taking, one more
/// decrypted behind it.
pub const plaintext_bytes: u32 = 2 * record_plaintext_bytes_max;

/// What ALPN offers: the one protocol the connection speaks.
const alpn_h2 = [_][]const u8{"h2"};
const alpn_http1 = [_][]const u8{"http/1.1"};

pub const Protocol = enum { h2, http1 };

pub const Error = zssl.ClientHandshake.Error || zssl.record_buffer.RecordBuffer.Error || error{
    /// Two flights owed at once from one record: a peer driving the client
    /// to say more than it can stage.
    FlightOverrun,
};

handshake: zssl.ClientHandshake,
records: zssl.record_buffer.RecordBuffer,
/// Two records of wire: one being decrypted, one arriving behind it.
storage: [2 * zssl.record.wire_record_bytes_max]u8,
reassembly: [reassembly_bytes]u8,
out: [zssl.ClientHandshake.out_bytes_min]u8,
plaintext: [plaintext_bytes]u8,
plaintext_start: u32,
plaintext_len: u32,
/// Wire octets of `out` owed to the socket, and how many of them it took.
pending: []const u8,
pending_sent: u32,
/// The plaintext the owed record seals; zero for a handshake flight.
pending_plain: u32,
/// What the chain is judged against: borrowed from the config's arena.
anchors: []const []const u8,
server_name: []const u8,
/// The wall clock the next record is judged at, in seconds.
now_sec: i64,
connected: bool,
closed: bool,
started: bool,

pub const Start = struct {
    protocol: Protocol = .h2,
    server_name: []const u8,
    anchors: []const []const u8,
    client_random: [32]u8,
    x25519_private: [32]u8,
    now_sec: i64,
};

/// Begin a handshake: the ClientHello is owed to the socket at once.
pub fn start(client: *OriginClient, options: *const Start) void {
    assert(!client.started);
    assert(options.server_name.len >= 1);
    assert(options.anchors.len >= 1);
    client.anchors = options.anchors;
    client.server_name = options.server_name;
    client.now_sec = options.now_sec;
    client.plaintext_start = 0;
    client.plaintext_len = 0;
    client.connected = false;
    client.closed = false;
    client.handshake = zssl.ClientHandshake.init(&.{
        .client_random = options.client_random,
        .x25519_private = options.x25519_private,
        .server_name = options.server_name,
        .alpn_protocols = switch (options.protocol) {
            .h2 => &alpn_h2,
            .http1 => &alpn_http1,
        },
        .certificate_policy = .leaf_signature,
        .chain_verifier = .{ .context = client, .verify = verifyChain },
        .reassembly = &client.reassembly,
    });
    client.records = .init(&client.storage);
    client.pending = client.handshake.start(&client.out);
    client.pending_sent = 0;
    client.pending_plain = 0;
    client.started = true;
    assert(client.pending.len >= 1);
}

/// The handshake's libcrypto state goes back to the fixed heap.
pub fn finish(client: *OriginClient) void {
    if (!client.started) return;
    client.handshake.deinit();
    client.started = false;
}

/// The origin selected HTTP/2, the only protocol this client offered.
pub fn alpnIsH2(client: *const OriginClient) bool {
    assert(client.connected);
    const selected = client.handshake.alpnSelected() orelse return false;
    return std.mem.eql(u8, selected, "h2");
}

/// The origin selected HTTP/1.1, or nothing — an origin that predates
/// ALPN speaks HTTP/1.1 over TLS, and was offered nothing else.
pub fn alpnAllowsHttp1(client: *const OriginClient) bool {
    assert(client.connected);
    const selected = client.handshake.alpnSelected() orelse return true;
    return std.mem.eql(u8, selected, "http/1.1");
}

/// Whether a read has somewhere to land. Records are read only while
/// their plaintext has room (`process`), so whole records can wait in the
/// buffer for the session, and fill it: the read then waits too.
pub fn canReceive(client: *const OriginClient) bool {
    assert(client.started);
    const records = &client.records;
    assert(records.start <= records.used);
    return records.buffer.len - (records.used - records.start) >= 1;
}

/// Where the next read lands: behind the records buffered. Only when
/// `canReceive`.
pub fn recvBuffer(client: *OriginClient) []u8 {
    assert(client.canReceive());
    const writable = client.records.writable();
    assert(writable.len >= 1);
    return writable;
}

/// `count` octets landed; read what records they complete.
pub fn received(client: *OriginClient, count: u32, now_sec: i64) Error!void {
    assert(client.started);
    assert(count >= 1);
    client.records.advance(count);
    client.now_sec = now_sec;
    try client.process();
}

/// Read buffered records while nothing is owed to the socket and there is
/// room for a record's plaintext. Called again once either frees up.
pub fn process(client: *OriginClient) Error!void {
    assert(client.started);
    var records: u32 = 0;
    while (records < records_per_process_max and !client.owes()) : (records += 1) {
        client.compactPlaintext();
        if (plaintext_bytes - client.plaintext_len < record_plaintext_bytes_max) return;
        const record = try client.records.next() orelse return;
        var event = try client.handshake.handleRecord(record, &client.out);
        var events: u32 = 0;
        // Drained to null: zssl refuses the next record while one's events
        // are pending. Each event borrows `out`, so a second flight from
        // one record would overwrite the first — refused (`take`) rather
        // than sent half-written; an origin's back-to-back KeyUpdates in
        // one record are the one legal shape that meets it.
        while (event) |one| : (event = try client.handshake.drain(&client.out)) {
            events += 1;
            if (events > events_per_record_max) return error.FlightOverrun;
            try client.take(one);
        }
    }
    // Every record the buffer can hold was read, or the loop stopped for
    // room or an owed flight, which a later call resumes from.
    assert(records < records_per_process_max or client.records.empty());
}

fn take(client: *OriginClient, event: zssl.ClientHandshake.Event) Error!void {
    switch (event) {
        .send, .connected => |bytes| {
            if (client.owes()) return error.FlightOverrun;
            if (event == .connected) client.connected = true;
            client.pending = bytes;
            client.pending_sent = 0;
            client.pending_plain = 0;
        },
        .application_data => |bytes| {
            const free = plaintext_bytes - client.plaintext_start - client.plaintext_len;
            // A record's plaintext is bounded, and room for one was checked.
            assert(bytes.len <= free);
            @memcpy(client.plaintext[client.plaintext_start + client.plaintext_len ..][0..bytes.len], bytes);
            client.plaintext_len += @intCast(bytes.len);
        },
        .closed => client.closed = true,
        // Resumption is not offered to origins: a ticket is set aside.
        .ticket => {},
    }
}

fn compactPlaintext(client: *OriginClient) void {
    assert(client.plaintext_start + client.plaintext_len <= plaintext_bytes);
    if (client.plaintext_start == 0) return;
    std.mem.copyForwards(
        u8,
        client.plaintext[0..client.plaintext_len],
        client.plaintext[client.plaintext_start..][0..client.plaintext_len],
    );
    client.plaintext_start = 0;
}

/// Decrypted octets into `target`, as many as fit. Answers how many.
pub fn takePlaintext(client: *OriginClient, target: []u8) u32 {
    assert(target.len >= 1);
    const count: u32 = @intCast(@min(target.len, client.plaintext_len));
    @memcpy(target[0..count], client.plaintext[client.plaintext_start..][0..count]);
    client.plaintext_start += count;
    client.plaintext_len -= count;
    if (client.plaintext_len == 0) client.plaintext_start = 0;
    return count;
}

/// Seal up to a record of the session's plaintext: owed to the socket
/// now. Answers how many plaintext octets the record carries.
pub fn seal(client: *OriginClient, plaintext: []const u8) Error!u32 {
    assert(client.connected);
    assert(!client.owes());
    assert(plaintext.len >= 1);
    const count: u32 = @intCast(@min(plaintext.len, record_plaintext_bytes_max));
    client.pending = try client.handshake.sendApplicationData(plaintext[0..count], &client.out);
    client.pending_sent = 0;
    client.pending_plain = count;
    return count;
}

/// Whether wire octets are owed to the socket.
pub fn owes(client: *const OriginClient) bool {
    return client.pending_sent < client.pending.len;
}

/// What the socket is owed now.
pub fn wire(client: *const OriginClient) []const u8 {
    assert(client.owes());
    return client.pending[client.pending_sent..];
}

/// The socket took `count` of the owed octets. Answers the plaintext the
/// record carried once the whole of it is out — what the session may now
/// count as sent — and zero until then, or for a handshake flight.
pub fn sent(client: *OriginClient, count: u32) u32 {
    assert(count >= 1);
    assert(client.pending_sent + count <= client.pending.len);
    client.pending_sent += count;
    if (client.owes()) return 0;
    const plain = client.pending_plain;
    client.pending = &.{};
    client.pending_sent = 0;
    client.pending_plain = 0;
    return plain;
}

/// zssl's chain hook: the entries collected, then `trust`'s verdict.
fn verifyChain(context: *anyopaque, chain: zssl.certificate_list.CertificateList) bool {
    const client: *OriginClient = @ptrCast(@alignCast(context));
    assert(client.started);
    assert(client.anchors.len >= 1);
    var entries: [trust.chain_max][]const u8 = undefined;
    var count: u32 = 0;
    var iterator = chain.iterator();
    while (iterator.next() catch return false) |entry| {
        if (count == trust.chain_max) return false;
        entries[count] = entry;
        count += 1;
    }
    return trust.verifyChain(client.anchors, entries[0..count], client.server_name, client.now_sec);
}

// ---------------------------------------------------------------------------
// Tests: a handshake against zssl's own server, in memory.
// ---------------------------------------------------------------------------

const testing = std.testing;

const Peer = struct {
    credentials: zssl.Credentials,
    chain_storage: [zssl.Credentials.chain_bytes_max]u8,
    server: zssl.ServerHandshake,
    reassembly: [16 * 1024]u8,
    flight: [16 * 1024]u8,
    out: [zssl.record.wire_record_bytes_max]u8,
    records: zssl.record_buffer.RecordBuffer,
    storage: [zssl.record.wire_record_bytes_max]u8,
    alpn: []const []const u8,

    fn init(peer: *Peer, alpn: []const []const u8) !void {
        return peer.initServing(
            alpn,
            @embedFile("testdata/origin-cert.pem"),
            @embedFile("testdata/origin-key.pem"),
            true,
        );
    }

    /// The same, serving a named pair. An RSA key draws a fresh PSS salt
    /// per signature, so it must be loaded with `deterministic` off.
    fn initServing(
        peer: *Peer,
        alpn: []const []const u8,
        cert_pem: []const u8,
        key_pem: []const u8,
        deterministic: bool,
    ) !void {
        peer.alpn = alpn;
        peer.credentials = try zssl.Credentials.load(
            cert_pem,
            key_pem,
            &peer.chain_storage,
            deterministic,
        );
        peer.server = zssl.ServerHandshake.init(&.{
            .credentials = &peer.credentials,
            .server_random = @splat(0x6d),
            .key_share_private = @splat(0x42),
            .alpn_protocols = peer.alpn,
            .reassembly = &peer.reassembly,
            .flight = &peer.flight,
        });
        peer.records = .init(&peer.storage);
    }

    fn deinit(peer: *Peer) void {
        peer.server.deinit();
        peer.credentials.deinit();
    }

    /// Feed the server wire octets; what it answers goes to `client`.
    fn feed(peer: *Peer, client: *OriginClient, bytes: []const u8) !void {
        try peer.records.push(bytes);
        while (try peer.records.next()) |record| {
            var event = try peer.server.handleRecord(record, &peer.out);
            while (event) |one| : (event = try peer.server.drain(&peer.out)) switch (one) {
                .send => |flight| try deliver(client, flight),
                .application_data => |data| {
                    // Echo it back, sealed — copied out first, since the
                    // record it arrived in may share the buffer it is
                    // sealed into.
                    var echo: [64]u8 = undefined;
                    @memcpy(echo[0..data.len], data);
                    const sealed = try peer.server.sendApplicationData(echo[0..data.len], &peer.out);
                    try deliver(client, sealed);
                },
                else => {},
            };
        }
    }
};

fn deliver(client: *OriginClient, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const room = client.recvBuffer();
        const take_bytes = @min(room.len, bytes.len - offset);
        @memcpy(room[0..take_bytes], bytes[offset..][0..take_bytes]);
        try client.received(@intCast(take_bytes), now_2030);
        offset += take_bytes;
    }
}

/// Drain what the client owes into the server.
fn flushTo(client: *OriginClient, peer: *Peer) !void {
    var passes: u32 = 0;
    while (client.owes()) : (passes += 1) {
        try testing.expect(passes < 8);
        var copy: [zssl.record.wire_record_bytes_max]u8 = undefined;
        const bytes = client.wire();
        @memcpy(copy[0..bytes.len], bytes);
        const length: u32 = @intCast(bytes.len);
        _ = client.sent(length);
        try peer.feed(client, copy[0..length]);
        try client.process();
    }
}

const now_2030: i64 = 1_893_456_000;

fn testClient(client: *OriginClient, anchors: []const []const u8, server_name: []const u8) void {
    client.started = false;
    client.start(&.{
        .server_name = server_name,
        .anchors = anchors,
        .client_random = @splat(0x1a),
        .x25519_private = @splat(0x07),
        .now_sec = now_2030,
    });
}

test "origin client: a verified handshake selects h2, and application data crosses both ways" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const anchors = try trust.parseAnchors(arena_state.allocator(), @embedFile("testdata/origin-ca.pem"));
    const peer = try testing.allocator.create(Peer);
    defer testing.allocator.destroy(peer);
    try peer.init(&.{"h2"});
    defer peer.deinit();
    const client = try testing.allocator.create(OriginClient);
    defer testing.allocator.destroy(client);
    testClient(client, anchors, "origin.zoxy.test");
    defer client.finish();
    try flushTo(client, peer);
    try testing.expect(client.connected);
    try testing.expect(client.alpnIsH2());
    try testing.expectEqual(@as(u32, 5), try client.seal("hello"));
    try flushTo(client, peer);
    var back: [16]u8 = undefined;
    try testing.expectEqual(@as(u32, 5), client.takePlaintext(&back));
    try testing.expectEqualStrings("hello", back[0..5]);
}

test "origin client: a chain for another name, or from another anchor, aborts the handshake" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const right = try trust.parseAnchors(arena, @embedFile("testdata/origin-ca.pem"));
    const wrong = try trust.parseAnchors(arena, @embedFile("testdata/other-ca.pem"));
    const cases = [_]struct { anchors: []const []const u8, name: []const u8 }{
        .{ .anchors = right, .name = "elsewhere.zoxy.test" },
        .{ .anchors = wrong, .name = "origin.zoxy.test" },
    };
    for (cases) |case| {
        const peer = try testing.allocator.create(Peer);
        defer testing.allocator.destroy(peer);
        try peer.init(&.{"h2"});
        defer peer.deinit();
        const client = try testing.allocator.create(OriginClient);
        defer testing.allocator.destroy(client);
        testClient(client, case.anchors, case.name);
        defer client.finish();
        try testing.expectError(error.BadCertificate, flushTo(client, peer));
        try testing.expect(!client.connected);
    }
}

test "origin client: an origin key of 8k+1 bits fails the handshake, not the process (#441)" {
    // The anchor issued this leaf for this name, so the chain passes
    // `verifyChain` and zssl goes on to check the origin's
    // CertificateVerify. Over a 3065-bit modulus, std.crypto's RSA-PSS
    // verifier asserts; zssl now refuses such a key before calling it
    // (zoxy-io/zssl#23).
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const anchors_pem = @embedFile("testdata/rsa3065-ca.pem");
    const anchors = try trust.parseAnchors(arena_state.allocator(), anchors_pem);
    const peer = try testing.allocator.create(Peer);
    defer testing.allocator.destroy(peer);
    try peer.initServing(
        &.{"h2"},
        @embedFile("testdata/rsa3065-issued-cert.pem"),
        @embedFile("testdata/rsa3065-key.pem"),
        false,
    );
    defer peer.deinit();
    const client = try testing.allocator.create(OriginClient);
    defer testing.allocator.destroy(client);
    testClient(client, anchors, "rsa3065.zoxy.test");
    defer client.finish();
    try testing.expectError(error.BadCertificate, flushTo(client, peer));
    try testing.expect(!client.connected);
}

test "origin client: an origin that selects no protocol is told apart" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const anchors = try trust.parseAnchors(arena_state.allocator(), @embedFile("testdata/origin-ca.pem"));
    const peer = try testing.allocator.create(Peer);
    defer testing.allocator.destroy(peer);
    try peer.init(&.{});
    defer peer.deinit();
    const client = try testing.allocator.create(OriginClient);
    defer testing.allocator.destroy(client);
    testClient(client, anchors, "origin.zoxy.test");
    defer client.finish();
    try flushTo(client, peer);
    try testing.expect(client.connected);
    try testing.expect(!client.alpnIsH2());
}
