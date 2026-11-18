//! The server end of TLS for a test origin (§7, §9): sans-I/O over zssl's
//! `ServerHandshake`, serving `testdata/origin-cert.pem` — the leaf the
//! origin trust fixtures' CA signed for `origin.zoxy.test` — so a scenario
//! can put an HTTP/2 origin behind real TLS and hold the proxy's client to
//! its verdict. Test support: nothing in the server imports it. It lives
//! here because only this directory may import zssl.
//!
//! The shape is `OriginClient`'s from the other side: records in, a
//! decrypted backlog out, and one buffer of wire octets owed at a time.

const std = @import("std");
const zssl = @import("zssl");

const assert = std.debug.assert;

const TestTlsServer = @This();

pub const plaintext_bytes: u32 = 2 * 16 * 1024;

pub const Error = zssl.ServerHandshake.Error || zssl.record_buffer.RecordBuffer.Error ||
    zssl.Credentials.Error || error{FlightOverrun};

credentials: zssl.Credentials,
chain_storage: [zssl.Credentials.chain_bytes_max]u8,
hs: zssl.ServerHandshake,
reassembly: [16 * 1024]u8,
flight: [zssl.Credentials.chain_bytes_max + 1024]u8,
out: [zssl.record.wire_record_bytes_max]u8,
records: zssl.record_buffer.RecordBuffer,
storage: [zssl.record.wire_record_bytes_max]u8,
plaintext: [plaintext_bytes]u8,
plaintext_len: u32,
pending: []const u8,
pending_sent: u32,
pending_plain: u32,
connected: bool,
started: bool,

/// What ALPN selects from: `h2`, or nothing — an origin that will not
/// speak HTTP/2.
pub fn start(server: *TestTlsServer, alpn: []const []const u8, key_share: [48]u8) Error!void {
    assert(!server.started);
    server.credentials = try zssl.Credentials.load(
        @embedFile("testdata/origin-cert.pem"),
        @embedFile("testdata/origin-key.pem"),
        &server.chain_storage,
        true,
    );
    server.hs = zssl.ServerHandshake.init(&.{
        .credentials = &server.credentials,
        .server_random = @splat(0x6d),
        .key_share_private = key_share,
        .alpn_protocols = alpn,
        .reassembly = &server.reassembly,
        .flight = &server.flight,
    });
    server.records = .init(&server.storage);
    server.plaintext_len = 0;
    server.pending = &.{};
    server.pending_sent = 0;
    server.pending_plain = 0;
    server.connected = false;
    server.started = true;
}

pub fn finish(server: *TestTlsServer) void {
    if (!server.started) return;
    server.hs.deinit();
    server.credentials.deinit();
    server.started = false;
}

/// Where the next read lands, or nothing while whole records wait for
/// their plaintext to be taken.
pub fn recvBuffer(server: *TestTlsServer) []u8 {
    assert(server.started);
    const records = &server.records;
    if (records.buffer.len - (records.used - records.start) == 0) return &.{};
    return records.writable();
}

pub fn received(server: *TestTlsServer, count: u32) Error!void {
    assert(count >= 1);
    server.records.advance(count);
    try server.process();
}

/// Read buffered records while nothing is owed and a record's plaintext
/// fits behind what waits.
pub fn process(server: *TestTlsServer) Error!void {
    var records: u32 = 0;
    while (records < 64 and !server.owes()) : (records += 1) {
        if (plaintext_bytes - server.plaintext_len < 16 * 1024) return;
        const record = try server.records.next() orelse return;
        var event = try server.hs.handleRecord(record, &server.out);
        var events: u32 = 0;
        while (event) |one| : (event = try server.hs.drain(&server.out)) {
            events += 1;
            if (events > 16) return error.FlightOverrun;
            switch (one) {
                .send => |bytes| {
                    if (server.owes()) return error.FlightOverrun;
                    server.pending = bytes;
                    server.pending_sent = 0;
                    server.pending_plain = 0;
                },
                .connected => server.connected = true,
                .application_data => |bytes| {
                    assert(bytes.len <= plaintext_bytes - server.plaintext_len);
                    @memcpy(server.plaintext[server.plaintext_len..][0..bytes.len], bytes);
                    server.plaintext_len += @intCast(bytes.len);
                },
                else => {},
            }
        }
    }
}

pub fn takePlaintext(server: *TestTlsServer, target: []u8) u32 {
    assert(target.len >= 1);
    const count: u32 = @intCast(@min(target.len, server.plaintext_len));
    @memcpy(target[0..count], server.plaintext[0..count]);
    std.mem.copyForwards(u8, server.plaintext[0 .. server.plaintext_len - count], server.plaintext[count..server.plaintext_len]);
    server.plaintext_len -= count;
    return count;
}

pub fn seal(server: *TestTlsServer, plaintext: []const u8) Error!u32 {
    assert(server.connected);
    assert(!server.owes());
    const count: u32 = @intCast(@min(plaintext.len, 16 * 1024));
    server.pending = try server.hs.sendApplicationData(plaintext[0..count], &server.out);
    server.pending_sent = 0;
    server.pending_plain = count;
    return count;
}

pub fn owes(server: *const TestTlsServer) bool {
    return server.pending_sent < server.pending.len;
}

pub fn wire(server: *const TestTlsServer) []const u8 {
    assert(server.owes());
    return server.pending[server.pending_sent..];
}

/// Answers the plaintext a whole sealed record carried, once it is out.
pub fn sent(server: *TestTlsServer, count: u32) u32 {
    assert(server.pending_sent + count <= server.pending.len);
    server.pending_sent += count;
    if (server.owes()) return 0;
    const plain = server.pending_plain;
    server.pending = &.{};
    server.pending_sent = 0;
    server.pending_plain = 0;
    return plain;
}
