//! An HTTP/3 connection end to end in memory (#449): zoxy's TLS engine and
//! a connection slot as the server, zssl's QUIC client over an h3 client
//! transport as the client, and datagrams handed across by hand. What it
//! proves is the seam: the engine's handshake reaches h3 through the
//! slot's sink, libcrypto protects every packet the server sends, and a
//! request and its answer cross once the handshake is confirmed.

const std = @import("std");
const h3 = @import("h3");

const Connection = @import("Connection.zig");
const QuicCrypto = @import("../../tls/QuicCrypto.zig");
const TlsEngine = @import("../../tls/Engine.zig");
const QuicClient = @import("../../tls/QuicClient.zig");
const Credentials = @import("../../tls/Credentials.zig");
const constants = @import("../../constants.zig");

const quic = h3.quic;
const testing = std.testing;
const assert = std.debug.assert;

const cert_pem = @embedFile("../../tls/testdata/cert.pem");
const key_pem = @embedFile("../../tls/testdata/key.pem");

/// The client's transport: h3's own `std.crypto` backend, small windows.
const ClientQuic = quic.Connection(.{
    .streams_max = 8,
    .stream_receive_octets = 8 * 1024,
    .stream_send_octets = 8 * 1024,
});
const ClientHttp3 = h3.Http3(.{ .requests_max = 2, .unidirectional_max = 4 });

const client_destination = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_source = [_]u8{ 0x0c, 0x11, 0xe7, 0x75 };
const server_source = [_]u8{ 0x5e, 0x12, 0x7e, 0x55, 0x00, 0x01, 0x02, 0x03 };
const exchanges_max: u32 = 64;

/// The client's handshake output, into its transport: the slot's sink,
/// on the other side.
const ClientSink = struct {
    fn of(client: *ClientQuic) TlsEngine.QuicSink {
        return .{
            .ctx = client,
            .crypto = crypto,
            .secret = secret,
            .transportParameters = parameters,
            .connected = connected,
        };
    }

    fn crypto(ctx: *anyopaque, level: TlsEngine.QuicLevel, bytes: []const u8) error{QuicSinkRefused}!void {
        const client: *ClientQuic = @ptrCast(@alignCast(ctx));
        client.cryptoIn(Connection.transportLevel(level), bytes) catch return error.QuicSinkRefused;
    }

    fn secret(ctx: *anyopaque, given: *const TlsEngine.QuicSecret) error{QuicSinkRefused}!void {
        const client: *ClientQuic = @ptrCast(@alignCast(ctx));
        const held = quic.crypto.Secret.init(given.bytes) catch return error.QuicSinkRefused;
        const level = Connection.transportLevel(given.level);
        const suite = Connection.suiteOf(given.suite);
        const installed = switch (given.direction) {
            .send => client.installSecret(level, .send, &held, suite),
            .receive => client.installSecret(level, .receive, &held, suite),
        };
        installed catch return error.QuicSinkRefused;
    }

    fn parameters(ctx: *anyopaque, bytes: []const u8) error{QuicSinkRefused}!void {
        const client: *ClientQuic = @ptrCast(@alignCast(ctx));
        client.transportParametersIn(bytes) catch return error.QuicSinkRefused;
    }

    // A client's handshake is confirmed by HANDSHAKE_DONE, not by its own
    // TLS stack (RFC 9001 §4.1.2), so completion asks nothing of it.
    fn connected(ctx: *anyopaque) void {
        _ = ctx;
    }
};

/// Both ends, allocated: a slot is the better part of a megabyte.
const Bed = struct {
    arena_state: std.heap.ArenaAllocator,
    credentials: Credentials,
    engine: TlsEngine,
    plaintext: [TlsEngine.plaintext_bytes_min]u8,
    body_plaintext: [TlsEngine.plaintext_bytes_min]u8,
    slot: Connection.Slot,
    client: ClientQuic,
    client_tls: QuicClient,
    now_ns: u64,
    /// What `start` brought up, so a test failing partway tears down only
    /// that.
    engine_live: bool,
    client_tls_live: bool,

    /// Packet protection's libcrypto contexts are the process's, made at
    /// startup (`QuicCrypto.init`) and kept: a test makes them if nothing
    /// before it did, and leaves them for whatever runs next.
    fn create() !*Bed {
        _ = try QuicCrypto.ensure();
        const bed = try testing.allocator.create(Bed);
        errdefer testing.allocator.destroy(bed);
        bed.arena_state = .init(testing.allocator);
        errdefer bed.arena_state.deinit();
        bed.credentials = try Credentials.load(bed.arena_state.allocator(), cert_pem, key_pem, .{});
        bed.engine.bindPlaintext(&bed.plaintext, &bed.body_plaintext, constants.head_buffer_bytes_default);
        bed.now_ns = 1_000_000;
        bed.engine_live = false;
        bed.client_tls_live = false;
        return bed;
    }

    fn destroy(bed: *Bed) void {
        if (bed.client_tls_live) bed.client_tls.deinit();
        if (bed.engine_live) bed.engine.deinit();
        bed.credentials.deinit();
        bed.arena_state.deinit();
        testing.allocator.destroy(bed);
    }

    /// The client's first flight, and the server connection it starts.
    fn start(bed: *Bed) !void {
        bed.client = .init(.{
            .side = .client,
            .original_destination = try .init(&client_destination),
            .source = try .init(&client_source),
            // The server's three streams in; two requests and the
            // client's own three out.
            .advertised = .{ .max_streams_bidirectional = 0, .max_streams_unidirectional = 3, .streams_opened_max = 5 },
        });
        var parameters: [ClientQuic.local_transport_parameters_octets_max]u8 = undefined;
        const sink = ClientSink.of(&bed.client);
        try bed.client_tls.init(&.{
            .server_name = "localhost",
            .transport_parameters = try bed.client.localTransportParameters(&parameters),
            .seed = @splat(0x5a),
        }, &sink);
        bed.client_tls_live = true;
        var first: [ClientQuic.datagram_octets]u8 = undefined;
        const octets = try bed.client.send(&first, bed.now_ns);
        const datagram = quic.endpoint.classify(first[0..octets], Connection.connection_id_bytes);
        try testing.expectEqual(.initial, datagram.action);
        try testing.expect(datagram.mayStart());
        try bed.slot.begin(&.{
            .initial_destination = datagram.destination,
            .source = try .init(&server_source),
            .retry = null,
            .idle_timeout_ms = 30_000,
            .stateless_reset_token = @splat(0x7e),
            .endpoint_index = 0,
            .peer = .{ .ip4 = .loopback(4433) },
        });
        try bed.engine.init(&.{
            .x25519_seed = @splat(0x42),
            .random = @splat(0x43),
            .credentials = &bed.credentials,
            .now_unix = 1_900_000_000,
            .quic = .{ .transport_parameters = bed.slot.transportParameters() },
        });
        bed.engine_live = true;
        try bed.slot.quic.receive(first[0..octets], bed.now_ns);
        bed.slot.handshake(&bed.engine);
    }

    /// The client's TLS stack reads what its transport received.
    fn clientHandshake(bed: *Bed) !void {
        const sink = ClientSink.of(&bed.client);
        for ([_]quic.crypto.Level{ .initial, .handshake, .one_rtt }) |level| {
            const available = bed.client.cryptoOut(level);
            if (available.len == 0) continue;
            try bed.client_tls.deliver(Connection.engineLevel(level), available, &sink);
            bed.client.cryptoConsumed(level, available.len);
        }
    }

    /// Every datagram each side wants to send, delivered, until `done`
    /// holds. Once neither has one to send, time moves to the earlier of
    /// the two timers and it fires, as the endpoint's would: h3 discards a
    /// packet whose keys have not arrived yet (RFC 9001 §4.1.4, declined
    /// in h3 with its reason), so a coalesced flight's tail comes back on
    /// the sender's probe timeout.
    fn settle(bed: *Bed, comptime done: fn (*Bed) bool) !void {
        var rounds: u32 = 0;
        while (!done(bed)) : (rounds += 1) {
            try testing.expect(rounds < exchanges_max);
            if (bed.slot.quic.wantsSend() or bed.client.wantsSend()) {
                try bed.deliver();
                continue;
            }
            const server_due = bed.slot.quic.timeout() orelse std.math.maxInt(u64);
            const client_due = bed.client.timeout() orelse std.math.maxInt(u64);
            const due = @min(server_due, client_due);
            try testing.expect(due != std.math.maxInt(u64));
            bed.now_ns = @max(bed.now_ns, due);
            if (server_due <= bed.now_ns) bed.slot.quic.onTimeout(bed.now_ns);
            if (client_due <= bed.now_ns) bed.client.onTimeout(bed.now_ns);
        }
    }

    /// One datagram each way, whichever side has one.
    fn deliver(bed: *Bed) !void {
        var datagram: [Connection.Quic.datagram_octets]u8 = undefined;
        bed.now_ns += 1_000_000;
        const server_octets = try bed.slot.quic.send(&datagram, bed.now_ns);
        if (server_octets > 0) {
            try bed.client.receive(datagram[0..server_octets], bed.now_ns);
            try bed.clientHandshake();
        }
        const client_octets = try bed.client.send(&datagram, bed.now_ns);
        if (client_octets > 0) {
            try bed.slot.quic.receive(datagram[0..client_octets], bed.now_ns);
            bed.slot.handshake(&bed.engine);
            bed.slot.session.flush(&bed.slot.quic);
        }
    }

    fn confirmed(bed: *Bed) bool {
        return bed.slot.quic.handshakeConfirmed() and bed.client.handshakeConfirmed();
    }

    fn quiet(bed: *Bed) bool {
        return !bed.slot.quic.wantsSend() and !bed.client.wantsSend();
    }

    fn connect(bed: *Bed) !void {
        try bed.start();
        try bed.settle(confirmed);
        try testing.expect(bed.engine.isConnected());
        try testing.expect(bed.client_tls.connected);
        try testing.expect(bed.slot.quic.handshakeConfirmed());
        try testing.expect(bed.client.handshakeConfirmed());
    }
};

/// The first `stream_readable` the server's transport reports.
fn firstReadable(connection: *Connection.Quic) ?u64 {
    var polled: u32 = 0;
    while (connection.poll()) |event| : (polled += 1) {
        assert(polled < 256);
        switch (event) {
            .stream_readable => |id| if (h3.quic.stream_id.kindOf(id).bidirectional()) return id,
            else => {},
        }
    }
    return null;
}

test "h3 connection: the engine's handshake confirms both ends, through libcrypto's packet protection" {
    const bed = try Bed.create();
    defer bed.destroy();
    try bed.connect();
    // The transport parameters the client read are the ones the slot
    // encoded for the engine to carry.
    const parsed = try quic.transport_parameters.parse(bed.client.peer_parameters[0..bed.client.peer_parameters_len]);
    try testing.expectEqual(@as(u64, Connection.requests_max), parsed.initial_max_streams_bidi);
    try testing.expect(parsed.disable_active_migration);
}

test "h3 connection: a request crosses in and its answer crosses back" {
    const bed = try Bed.create();
    defer bed.destroy();
    try bed.connect();
    var client_http3: ClientHttp3 = .init(.client);
    var frames: [512]u8 = undefined;
    const octets = try client_http3.writeHeaders(&frames, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/hello" },
    });
    try testing.expectEqual(octets, try bed.client.write(0, frames[0..octets], true));
    try bed.settle(Bed.quiet);

    const id = firstReadable(&bed.slot.quic) orelse return error.TestNoRequest;
    try testing.expectEqual(@as(u64, 0), id);
    var events: [4]h3.http3.Event = undefined;
    const read = try bed.slot.session.receive(&bed.slot.quic, id, &events, 0);
    try testing.expect(read.events >= 1);
    var scratch: [1024]u8 = undefined;
    var storage: [1024]u8 = undefined;
    var list: [16]h3.qpack.Field = undefined;
    const request = try h3.http3_server.decodeSection(
        events[0].headers.section,
        .{ .kind = .request },
        constants.head_buffer_bytes_max,
        &scratch,
        &storage,
        &list,
    );
    try testing.expectEqualStrings("/hello", request.fields[3].value);
    bed.slot.session.consume(&bed.slot.quic, id, read);

    var section: [256]u8 = undefined;
    try bed.slot.session.writeHeaders(&bed.slot.quic, id, &.{.{ .name = ":status", .value = "200" }}, &section, false);
    try testing.expectEqual(@as(usize, 2), try bed.slot.session.writeData(&bed.slot.quic, id, "hi", true));
    bed.slot.session.release(id);
    try bed.settle(Bed.quiet);

    var answer: [4]h3.http3.Event = undefined;
    const response = try client_http3.receive(0, bed.client.readable(0), bed.client.readableFin(0), &answer);
    try testing.expectEqual(@as(usize, 3), response.events);
    try testing.expectEqualStrings("hi", answer[1].data.payload);
    try testing.expectEqual(@as(u64, 0), answer[2].finished);
}
