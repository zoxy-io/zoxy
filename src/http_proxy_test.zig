//! Directed L7 scenarios over SimIo (§9), separate from the L4 harness
//! in server_test.zig so neither over-generalizes the other. Covers head
//! ingestion and static-response rejects (before any dial), and the full
//! upstream leg against a scripted HTTP origin: request head + framed
//! body forwarded, response head + framed body relayed back, byte-exact
//! under 1-byte adversarial delivery. Every scenario ends with counters
//! reconciled and all pools drained.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const router = @import("http/router.zig");
const filter = @import("http/filter.zig");
const Io = @import("io/io.zig");
const parser = @import("http/parser.zig");
const Server = @import("Server.zig").Server;
const SimIo = @import("io/SimIo.zig");

const assert = std.debug.assert;

const ServerSim = Server(SimIo);

/// A scripted HTTP client: sends `request` (the adversary may split the
/// send), then reads until the peer closes, recording the response bytes
/// and whether the close was an orderly FIN or an RST — the §2 property
/// (a delivered response must end in FIN, never a data-discarding RST).
const HttpClient = struct {
    io: *SimIo = undefined,
    server: *ServerSim = undefined,
    connect_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    delay_completion: SimIo.Completion = .{},
    socket: SimIo.Socket = undefined,
    address: std.Io.net.IpAddress = undefined,
    request: []const u8 = undefined,
    /// Hold the head back this long after connecting. The scenario that
    /// needs the head to land at a chosen instant (not at once, under the
    /// frozen intra-batch clock) sets it; 0 sends immediately.
    send_delay_ms: u32 = 0,
    /// Sent on the same connection once the first response is complete —
    /// sequential keep-alive, never pipelining.
    second_request: ?[]const u8 = null,
    /// A client to start when this one finishes (upstream-reuse tests
    /// chain connections deterministically).
    next: ?*HttpClient = null,
    /// The last client begins the drain; a scenario that wants to watch
    /// the idle sweep instead arms a drain timer and clears this.
    drain_on_finish: bool = true,
    /// Close from the client side once the response is in, rather than
    /// waiting for the proxy to close. This is what an ordinary keep-alive
    /// client does — curl, a browser, any pooled HTTP client — and it is
    /// the only way to reach the read that ends an *idle* kept-alive
    /// connection, which no `Connection: close` scenario can.
    close_after_response: bool = false,
    sent_len: u32 = 0,
    send_in_flight: bool = false,
    /// Twice the proxy's head buffer: a response that fills that buffer and
    /// then grows in the render exceeds it, and the separate-excess scenario
    /// needs the whole response in one place to compare against.
    receive_buffer: [2 * constants.head_bytes_max]u8 = undefined,
    received_len: u32 = 0,
    outcome: Outcome = .pending,

    const Outcome = enum(u8) { pending, fin, reset };

    fn start(client: *HttpClient, io: *SimIo, server: *ServerSim, address: std.Io.net.IpAddress) void {
        client.io = io;
        client.server = server;
        client.address = address;
        io.connect(address, &client.connect_completion, HttpClient, client, onConnect);
    }

    fn onConnect(client: *HttpClient, result: Io.ConnectError!SimIo.Socket) void {
        client.socket = result catch unreachable;
        client.armRecv();
        if (client.send_delay_ms == 0) {
            client.armSend();
            return;
        }
        client.io.timerStart(
            &client.delay_completion,
            @as(u64, client.send_delay_ms) * std.time.ns_per_ms,
            HttpClient,
            client,
            onSendDelay,
        );
    }

    fn onSendDelay(client: *HttpClient, result: Io.TimerError!void) void {
        result catch unreachable; // Nothing cancels the client's send delay.
        // The server may have reaped the silent connection while the delay
        // ran; its socket is already closed, so there is nothing to send.
        if (client.outcome != .pending) return;
        client.armSend();
    }

    fn armSend(client: *HttpClient) void {
        assert(client.sent_len < client.request.len);
        assert(!client.send_in_flight);
        client.send_in_flight = true;
        client.io.send(
            client.socket,
            client.request[client.sent_len..],
            &client.send_completion,
            HttpClient,
            client,
            onSend,
        );
    }

    fn onSend(client: *HttpClient, result: Io.SendError!u32) void {
        client.send_in_flight = false;
        // A reject may close the connection before the whole request is
        // sent; a send failure then is expected, not an error.
        const sent = result catch {
            client.finish();
            return;
        };
        client.sent_len += sent;
        assert(client.sent_len <= client.request.len);
        if (client.sent_len < client.request.len) {
            client.armSend();
            return;
        }
        client.finish();
    }

    fn armRecv(client: *HttpClient) void {
        client.io.recv(
            client.socket,
            client.receive_buffer[client.received_len..],
            &client.recv_completion,
            HttpClient,
            client,
            onRecv,
        );
    }

    /// The peer's close ends this client — but not before its own send has
    /// drained: closing under a pending send would leave the simulator a
    /// stale handle (a §5 violation it asserts on), so whichever of the
    /// close and the send lands second finishes.
    fn finish(client: *HttpClient) void {
        if (client.outcome == .pending) return;
        if (client.send_in_flight) return;
        client.io.closeNow(client.socket);
        if (client.next) |successor| {
            client.next = null;
            successor.start(client.io, client.server, client.address);
            return;
        }
        if (client.drain_on_finish) {
            // Begin the drain so the run winds down instead of idling
            // on the armed accept — the L4 harness does the same.
            client.server.beginDrain();
        }
    }

    fn onRecv(client: *HttpClient, result: Io.RecvError!u32) void {
        const received = result catch |err| {
            client.outcome = if (err == error.Reset) .reset else .fin;
            client.finish();
            return;
        };
        assert(received >= 1);
        client.received_len += received;
        assert(client.received_len <= client.receive_buffer.len);
        client.maybeSendSecond();
        if (client.maybeCloseAfterResponse()) return;
        client.armRecv();
    }

    /// Whether the first response has fully arrived — head plus whatever
    /// body its framing declared.
    fn firstResponseComplete(client: *const HttpClient) bool {
        var storage: parser.HeaderStorage = undefined;
        const first = parser.parseResponseHead(
            client.receive_buffer[0..client.received_len],
            false,
            &storage,
            .get,
        ) catch return false; // Incomplete head: keep reading.
        const body_len: u32 = switch (first.framing) {
            .content_length => |length| @intCast(length),
            else => 0,
        };
        return client.received_len >= first.head_len + body_len;
    }

    /// Sequential keep-alive: once the first response is complete, send
    /// the queued second request on the same connection.
    fn maybeSendSecond(client: *HttpClient) void {
        const queued = client.second_request orelse return;
        if (!firstResponseComplete(client)) return;
        client.second_request = null;
        client.request = queued;
        client.sent_len = 0;
        client.armSend();
    }

    /// Hang up from this end once the exchange is done, leaving the proxy
    /// to observe the close on a connection it was keeping alive. Returns
    /// whether the client is finished, so the caller does not re-arm a
    /// read on a socket that is gone.
    fn maybeCloseAfterResponse(client: *HttpClient) bool {
        if (!client.close_after_response) return false;
        if (client.second_request != null) return false;
        if (!firstResponseComplete(client)) return false;
        // The connection ended cleanly; that this end sent the FIN rather
        // than received one is not a distinction any caller draws.
        client.outcome = .fin;
        client.finish();
        return true;
    }

    fn response(client: *const HttpClient) []const u8 {
        return client.receive_buffer[0..client.received_len];
    }
};

/// A scripted HTTP origin: reads requests (head + framed body, tracked
/// with zoxy's own parser so the test asserts on exactly what the proxy
/// forwarded) and answers each with the canned `response`. It keeps its
/// connection alive between requests — parked upstream connections come
/// back to it — unless `close_after_response` scripts the origin-side
/// close (until-close bodies, and the stale-parked scenario). Two
/// connections per scenario: the second accept serves the §7 replay's
/// fresh dial; tests that must prove reuse assert `accepted_count == 1`.
const HttpOrigin = struct {
    io: *SimIo = undefined,
    listener: SimIo.Listener = undefined,
    accept_completion: SimIo.Completion = .{},
    listening: bool = false,
    response: []const u8 = "",
    close_after_response: bool = false,
    /// Read the whole request, then never answer — the stalled origin
    /// that drives the §8 request-deadline 504 verdict.
    mute: bool = false,
    /// Stall from the Nth request onward instead of from the first:
    /// `maxInt` (the default) never stalls, `1` stalls the second and
    /// later. The only way to reach the *reuse* path with a stalled
    /// exchange — a parked upstream exists only after one was served.
    mute_after_served: u32 = std.math.maxInt(u32),
    /// Close the second accepted connection immediately: the replayed
    /// try fails too, pinning the one-replay budget (§7).
    close_second_at_accept: bool = false,
    /// The second accept serves the §7 replay's fresh dial, and a
    /// `check` scenario's probes each accept-and-vanish too — hence four
    /// slots, not two. Tests that must prove reuse assert
    /// `accepted_count == 1`.
    /// Client-driven dials (fresh, replay, post-ejection) plus one per
    /// http health probe, which accepts and hangs up but still consumes a
    /// slot — conns are tracked monotonically, never recycled. Tests that
    /// must prove reuse assert `accepted_count == 1` regardless.
    conns: [16]OConn = @splat(.{}),
    accepted_count: u32 = 0,
    requests_served: u32 = 0,

    const OConn = struct {
        origin: *HttpOrigin = undefined,
        socket: SimIo.Socket = undefined,
        recv_completion: SimIo.Completion = .{},
        send_completion: SimIo.Completion = .{},
        request_buffer: [16384]u8 = undefined,
        request_len: u32 = 0,
        /// Start of the request currently being read; earlier requests
        /// stay captured in the buffer for the tests' assertions.
        request_offset: u32 = 0,
        request_complete: bool = false,
        closed: bool = false,
        /// Total bytes expected for the current request (head + framed
        /// body), known once its head parses. 0 means not parsed yet.
        request_expected: u32 = 0,
        response_sent: u32 = 0,

        fn armRecv(oconn: *OConn) void {
            oconn.origin.io.recv(
                oconn.socket,
                oconn.request_buffer[oconn.request_len..],
                &oconn.recv_completion,
                OConn,
                oconn,
                onRecv,
            );
        }

        fn onRecv(oconn: *OConn, result: Io.RecvError!u32) void {
            const received = result catch {
                oconn.origin.io.closeNow(oconn.socket);
                oconn.closed = true;
                return;
            };
            oconn.request_len += received;
            oconn.tryAdvance();
        }

        /// Parse the head once to learn the total request size (head +
        /// content-length body — the only body shape these tests send),
        /// then read until the whole request has arrived and respond.
        fn tryAdvance(oconn: *OConn) void {
            if (oconn.request_expected == 0) {
                var storage: parser.HeaderStorage = undefined;
                const request = parser.parseRequestHead(
                    oconn.request_buffer[oconn.request_offset..oconn.request_len],
                    false,
                    &storage,
                ) catch |err| {
                    if (err == error.Incomplete) {
                        oconn.armRecv();
                        return;
                    }
                    oconn.origin.io.closeNow(oconn.socket);
                    oconn.closed = true;
                    return;
                };
                const body_length: u32 = switch (request.framing) {
                    .content_length => |length| @intCast(length),
                    else => 0,
                };
                oconn.request_expected = request.head_len + body_length;
            }
            const current_len = oconn.request_len - oconn.request_offset;
            assert(current_len <= oconn.request_expected);
            if (current_len < oconn.request_expected) {
                oconn.armRecv();
                return;
            }
            oconn.request_complete = true;
            if (oconn.origin.mute or
                oconn.origin.requests_served >= oconn.origin.mute_after_served)
            {
                // The stalled origin: request read in full, no answer, no
                // armed op — the proxy's deadline is the only way out.
                // `mute_after_served` stalls only from the Nth request on,
                // so a test can park an upstream on a served exchange and
                // then stall the *reused* one.
                return;
            }
            oconn.armSend();
        }

        fn armSend(oconn: *OConn) void {
            assert(oconn.response_sent < oconn.origin.response.len);
            oconn.origin.io.send(
                oconn.socket,
                oconn.origin.response[oconn.response_sent..],
                &oconn.send_completion,
                OConn,
                oconn,
                onSend,
            );
        }

        fn onSend(oconn: *OConn, result: Io.SendError!u32) void {
            const sent = result catch {
                oconn.origin.io.closeNow(oconn.socket);
                oconn.closed = true;
                return;
            };
            oconn.response_sent += sent;
            if (oconn.response_sent < oconn.origin.response.len) {
                oconn.armSend();
                return;
            }
            oconn.origin.requests_served += 1;
            if (oconn.origin.close_after_response) {
                oconn.origin.io.closeNow(oconn.socket);
                oconn.closed = true;
                return;
            }
            // Keep-alive: the next request appends after this one (the
            // buffer keeps every request for the tests' assertions).
            oconn.request_offset = oconn.request_len;
            oconn.request_expected = 0;
            oconn.response_sent = 0;
            oconn.armRecv();
        }
    };

    fn start(origin: *HttpOrigin, io: *SimIo, address: std.Io.net.IpAddress) !void {
        origin.io = io;
        origin.listener = try io.listen(address);
        origin.listening = true;
        origin.armAccept();
    }

    fn armAccept(origin: *HttpOrigin) void {
        origin.io.accept(origin.listener, &origin.accept_completion, HttpOrigin, origin, onAccept);
    }

    fn onAccept(origin: *HttpOrigin, result: Io.AcceptError!SimIo.Socket) void {
        const socket = result catch |err| {
            assert(err == error.Canceled);
            return;
        };
        assert(origin.accepted_count < origin.conns.len);
        const oconn = &origin.conns[origin.accepted_count];
        origin.accepted_count += 1;
        if (origin.close_second_at_accept and origin.accepted_count == 2) {
            // The replay's fresh dial meets an instant close: its try
            // fails with no response byte, and no second replay exists.
            origin.io.closeNow(socket);
            oconn.closed = true;
            return;
        }
        oconn.origin = origin;
        oconn.socket = socket;
        oconn.armRecv();
        origin.armAccept();
    }

    /// Close still-open origin-side connections at scenario end so the
    /// socket leak check is exact — their EOF delivery may race the loop
    /// stop (the L4 harness does the same).
    fn closeRemaining(origin: *HttpOrigin) void {
        for (origin.conns[0..origin.accepted_count]) |*oconn| {
            if (!oconn.closed) {
                origin.io.closeNow(oconn.socket);
                oconn.closed = true;
            }
        }
    }

    fn stopListening(origin: *HttpOrigin) void {
        if (origin.listening) {
            origin.io.listenClose(origin.listener);
            origin.listening = false;
        }
    }
};

/// Single-listener L7 harness: one http listener, a scripted origin, one
/// client.
const Http1Bed = struct {
    arena_state: std.heap.ArenaAllocator,
    sim_io: SimIo,
    endpoints: [1]std.Io.net.IpAddress,
    clusters: [1]config_module.Config.Cluster,
    routes: [1]router.Route,
    listeners: [1]config_module.Config.Listener,
    config: config_module.Config,
    server: ServerSim,
    origin: HttpOrigin,
    client: HttpClient,
    client2: HttpClient,
    drain_timer_completion: SimIo.Completion,
    origin_stop_completion: SimIo.Completion,

    const idle_timeout_ms: u32 = 1000;
    /// Deliberately 20× tighter than the idle timeout so a test can witness
    /// the §8 dial re-base: a hung L7 dial must fire 504 at this budget, not
    /// the far looser head-read/idle deadline (finding #1).
    const connect_timeout_ms: u32 = 50;

    fn bindAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
    }

    fn originAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
    }

    const Options = struct {
        seed: u64,
        partial_io: bool = false,
        /// Socket-ring size, null for SimIo's own default (§9). The default
        /// is narrower than a head buffer, so no delivery can fill one in a
        /// single read; a scenario that needs the shape production takes
        /// raises it. Independent of `partial_io`, which fragments what the
        /// ring was willing to carry.
        inbox_bytes: ?u32 = null,
        origin_response: []const u8 = "",
        origin_listens: bool = true,
        origin_closes: bool = false,
        /// The origin reads the whole request and never answers (§8 504).
        origin_mute: bool = false,
        /// The origin answers this many requests and stalls from then on,
        /// so a test can stall a *reused* upstream rather than a fresh
        /// dial. Default never stalls.
        origin_mute_after_served: u32 = std.math.maxInt(u32),
        /// The origin closes the second accepted connection at accept —
        /// the replayed try fails too, pinning the one-replay budget.
        close_second_at_accept: bool = false,
        /// Pool sizes, injectable so a test can cross the §8 watermarks.
        conn_slots: u32 = 4,
        relay_buffers: u32 = 2,
        upstream_slots: u32 = 2,
        /// The §6 absolute age cap; 0 (the default) disables it. A cap the
        /// exchange outlives clamps every stored deadline to it, so a
        /// re-based target can already be in the past.
        max_lifetime_ms: u32 = 0,
        /// The §8 per-exchange cap; 0 (the default) disables it. Unlike the
        /// age cap it starts at routing, so a test sets it against the
        /// origin's response delay rather than the connection's birth.
        request_timeout_ms: u32 = 0,
        /// Hold the client's head back this long after it connects, so it
        /// lands at a chosen instant rather than at once.
        send_delay_ms: u32 = 0,
        /// The single route's prefix; "/" is the catch-all. A narrower
        /// prefix lets a test drive the no-route 404 path (§7).
        route_prefix: []const u8 = "/",
        /// The single route's host scope; null is any-host. A canonical
        /// host lets a test drive host routing and its 404 (§7).
        route_host: ?[]const u8 = null,
        /// The listener's §7 filter rules; empty by default so existing
        /// scenarios are unfiltered. A test supplies compiled rules to
        /// drive the filter reject/edit paths.
        filters: []const filter.Rule = &.{},
        /// Turn the §8 access log on. Off by default so every existing
        /// scenario keeps paying nothing for it; a test that turns it on
        /// reads the emitted lines straight out of SimIo's virtual sink.
        access_log: bool = false,
        /// §7 active health checks on the one cluster; null by default so
        /// existing scenarios see no probe traffic.
        check: ?config_module.Config.Cluster.Check = null,
        /// §8 per-endpoint concurrency cap; null leaves the cluster
        /// uncapped, which is what every pre-existing scenario wants.
        max_inflight: ?u32 = null,
        /// Probe pacing for `check` scenarios — tight, so fall/rise fit
        /// inside a short virtual run.
        health_interval_ms: u32 = 40,
    };

    fn setUp(bed: *Http1Bed, gpa: std.mem.Allocator, options: Options) !void {
        bed.arena_state = std.heap.ArenaAllocator.init(gpa);
        errdefer bed.arena_state.deinit();
        const arena = bed.arena_state.allocator();

        var adversary: SimIo.Adversary = .{ .partial_io = options.partial_io };
        if (options.inbox_bytes) |bytes| {
            adversary.inbox_bytes = bytes;
        }
        try bed.sim_io.init(arena, .{ .seed = options.seed, .adversary = adversary });
        bed.endpoints = .{originAddress()};
        bed.clusters = .{.{ .name = "origin", .endpoints = &bed.endpoints, .check = options.check, .max_inflight = options.max_inflight }};
        bed.routes = .{.{ .host = options.route_host, .prefix = options.route_prefix, .cluster_index = 0 }};
        bed.listeners = .{.{
            .bind_address = bindAddress(),
            .routes = &bed.routes,
            .filters = options.filters,
            .protocol = .http,
        }};
        bed.config = .{
            .listeners = &bed.listeners,
            .clusters = &bed.clusters,
            .connect_timeout_ms = connect_timeout_ms,
            .idle_timeout_ms = idle_timeout_ms,
            .drain_deadline_ms = 1000,
            .max_lifetime_ms = options.max_lifetime_ms,
            .request_timeout_ms = options.request_timeout_ms,
            .access_log_sink = if (options.access_log) .stdout else null,
            .health_interval_ms = options.health_interval_ms,
        };
        try bed.server.init(arena, &bed.sim_io, &bed.config, .{
            .conn_slots = options.conn_slots,
            .relay_buffers = options.relay_buffers,
            .upstream_slots = options.upstream_slots,
            .access_log_buffer_bytes = if (options.access_log)
                constants.access_log_buffer_bytes_default
            else
                0,
        });
        try bed.server.start();
        bed.origin = .{
            .response = options.origin_response,
            .close_after_response = options.origin_closes,
            .mute = options.origin_mute,
            .mute_after_served = options.origin_mute_after_served,
            .close_second_at_accept = options.close_second_at_accept,
        };
        if (options.origin_listens) {
            try bed.origin.start(&bed.sim_io, originAddress());
        }
        bed.client = .{ .send_delay_ms = options.send_delay_ms };
        bed.client2 = .{};
        bed.drain_timer_completion = .{};
        bed.origin_stop_completion = .{};
    }

    /// A sweep-observation scenario cannot let the client drive the drain
    /// (the drain reaps parked upstreams instantly); this timer drains
    /// after the idle sweep has had time to act.
    fn armDrainTimer(bed: *Http1Bed, delay_ms: u32) void {
        bed.sim_io.timerStart(
            &bed.drain_timer_completion,
            @as(u64, delay_ms) * std.time.ns_per_ms,
            Http1Bed,
            bed,
            onDrainTimer,
        );
    }

    fn onDrainTimer(bed: *Http1Bed, result: Io.TimerError!void) void {
        result catch unreachable; // Nothing cancels the test drain timer.
        bed.server.beginDrain();
    }

    /// Stop the origin's listener mid-run at a chosen instant — how a
    /// health scenario turns a serving origin into a refusing one while
    /// probes are in flight (§7).
    fn armOriginStopTimer(bed: *Http1Bed, delay_ms: u32) void {
        bed.sim_io.timerStart(
            &bed.origin_stop_completion,
            @as(u64, delay_ms) * std.time.ns_per_ms,
            Http1Bed,
            bed,
            onOriginStopTimer,
        );
    }

    fn onOriginStopTimer(bed: *Http1Bed, result: Io.TimerError!void) void {
        result catch unreachable; // Nothing cancels the origin-stop timer.
        bed.origin.stopListening();
    }

    fn tearDown(bed: *Http1Bed) void {
        bed.arena_state.deinit();
    }

    /// Send one request and run to quiescence. The client begins the
    /// drain when it sees the connection close, so a single run winds the
    /// whole scenario down; by the time it returns the client has its
    /// outcome and the pools have drained.
    fn exchange(bed: *Http1Bed, request: []const u8) !void {
        bed.client.request = request;
        bed.client.start(&bed.sim_io, &bed.server, bindAddress());
        try bed.sim_io.run();
        bed.origin.stopListening();
    }

    fn expectDrained(bed: *Http1Bed) !void {
        bed.origin.closeRemaining();
        try std.testing.expect(bed.server.isIdle());
        try std.testing.expect(bed.server.reconcile());
        try std.testing.expect(bed.sim_io.sockets.isFullyReleased());
    }
};

test "l7: a malformed request head is answered 400 and closed with FIN" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 1 });
    defer bed.tearDown();

    // A bare LF terminator is a smuggling shape the parser rejects (§7).
    try bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_request"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: a malformed chunked body coalesced with the head is answered 400" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 7,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // The head is valid, so it is sent upstream and the response leg is
    // about to arm — but the chunk-size line coalesced behind it opens with
    // a non-hex byte, a framing violation the moment it is fed. The client
    // still gets a 400, not the bare teardown a post-arm detection forces
    // (§7): the body is validated before the response recv commits its op.
    try bed.exchange("POST /x HTTP/1.1\r\nHost: o\r\nTransfer-Encoding: chunked\r\n\r\nZ");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_request"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: oversize request line is 414, oversize header section is 431" {
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 2 });
        defer bed.tearDown();

        const long_target = "/" ++ ("a" ** 9000);
        try bed.exchange("GET " ++ long_target ++ " HTTP/1.1\r\n");

        try std.testing.expectEqualStrings(
            "HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_uri_too_long"));
        try bed.expectDrained();
    }
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 3 });
        defer bed.tearDown();

        const filler = "X-Filler: " ++ ("v" ** 200) ++ "\r\n";
        var request: [10000]u8 = undefined;
        var len: usize = 0;
        const prefix = "GET / HTTP/1.1\r\nHost: a\r\n";
        @memcpy(request[0..prefix.len], prefix);
        len += prefix.len;
        while (len + filler.len <= request.len) {
            @memcpy(request[len..][0..filler.len], filler);
            len += filler.len;
        }
        try bed.exchange(request[0..len]);

        try std.testing.expectEqualStrings(
            "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_headers_too_large"));
        try bed.expectDrained();
    }
}

/// The shared close of the two post-dial 431 arms. They answer the same
/// bytes as the head-parse 431 above, so the assertion that tells them apart
/// is the origin: it accepted a connection and never saw a request on it.
fn expectRejectedAfterDial(bed: *const Http1Bed) !void {
    try std.testing.expectEqualStrings(
        "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_headers_too_large"));
    try std.testing.expectEqual(@as(u32, 1), bed.origin.accepted_count);
    try std.testing.expectEqual(@as(u32, 0), bed.origin.requests_served);
}

test "l7: a head that fits on arrival but not after forwarding is 431" {
    // Two arms the head-parse verdicts above cannot reach: a head the parser
    // accepted, rejected only when the proxy renders what it will forward
    // (#87).
    {
        // An added header pushes an exactly-`head_bytes_max` head over.
        const rules = [_]filter.Rule{.{
            .match = .{ .path_prefix = "/api" },
            .actions = &.{.{ .header_add = .{ .name = "X-Trace", .value = "on" } }},
        }};
        const prefix = "GET /api HTTP/1.1\r\nHost: o\r\nX-Pad: ";
        const suffix = "\r\n\r\n";
        var request: [constants.head_bytes_max]u8 = undefined;
        @memcpy(request[0..prefix.len], prefix);
        @memset(request[prefix.len..][0 .. request.len - prefix.len - suffix.len], 'p');
        @memcpy(request[request.len - suffix.len ..][0..suffix.len], suffix);

        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = 5,
            .filters = &rules,
            .route_prefix = "/api",
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange(&request);

        try expectRejectedAfterDial(&bed);
        try bed.expectDrained();
    }
    {
        // A rewrite whose `to` dwarfs the prefix it replaces overruns the
        // path scratch — on a head less than half full, so nothing about the
        // arrival size is what rejects it.
        const rules = [_]filter.Rule{.{
            .match = .{},
            .actions = &.{.{ .rewrite_prefix = .{ .from = "/r", .to = "/" ++ ("b" ** 5000) } }},
        }};
        const request = "GET /r/" ++ ("c" ** 4000) ++ " HTTP/1.1\r\nHost: o\r\n\r\n";

        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = 11,
            .filters = &rules,
            .route_prefix = "/r",
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange(request);

        try expectRejectedAfterDial(&bed);
        try bed.expectDrained();
    }
}

// Both heads parse cleanly and carry no body, so the 501 keeps the
// connection (§8) — the method is refused, not the framing.
test "l7: CONNECT and Upgrade are answered 501" {
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 4 });
        defer bed.tearDown();
        try bed.exchange("CONNECT origin:443 HTTP/1.1\r\nHost: origin\r\n\r\n");
        try std.testing.expectEqualStrings(
            "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_not_implemented"));
        try bed.expectDrained();
    }
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 5 });
        defer bed.tearDown();
        try bed.exchange("GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n");
        try std.testing.expectEqualStrings(
            "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_not_implemented"));
        try bed.expectDrained();
    }
}

test "l7: OPTIONS asterisk-form is forwarded as \"*\", not as the \"/\" it matched" {
    // §7 keeps two views of a target: the *match* view, which routes and
    // filters asterisk-form as the origin root, and the *forward* view,
    // which sends "*" verbatim. They are built together from one
    // canonicalization, so nothing but this test stops the forward view
    // from silently becoming the match view — which would turn a
    // server-wide OPTIONS into a request for the root resource.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 21,
        .origin_response = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    });
    defer bed.tearDown();

    try bed.exchange("OPTIONS * HTTP/1.1\r\nHost: origin.example\r\n\r\n");

    try std.testing.expect(bed.origin.conns[0].request_complete);
    var storage: parser.HeaderStorage = undefined;
    const forwarded = try parser.parseRequestHead(
        bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
        false,
        &storage,
    );
    try std.testing.expectEqual(parser.Method.options, forwarded.method);
    try std.testing.expectEqualStrings("*", forwarded.target);
    try bed.expectDrained();
}

test "l7: a GET is proxied and the origin's response relayed back" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 6,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    });
    defer bed.tearDown();

    try bed.exchange("GET /path HTTP/1.1\r\nHost: origin.example\r\nConnection: close\r\n\r\n");

    // The client saw the origin's response, rewritten with Connection:
    // close (the proxy announces the coming close), ending in a FIN.
    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        bed.client.response(),
    );
    // The origin received the request, rewritten with Connection: close.
    try std.testing.expect(bed.origin.conns[0].request_complete);
    var storage: parser.HeaderStorage = undefined;
    const forwarded = try parser.parseRequestHead(
        bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
        false,
        &storage,
    );
    try std.testing.expectEqual(parser.Method.get, forwarded.method);
    try std.testing.expectEqualStrings("/path", forwarded.target);
    // The client asked to close, but that is hop-by-hop: the upstream
    // connection stays reusable (§5) — the client's Connection header is
    // stripped and no close is injected toward the origin.
    try std.testing.expect(forwarded.keep_alive);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: the origin sees the canonical path, query verbatim (§7)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 12,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // Dot-segments collapse, %2E decodes then collapses; the query is
    // opaque and forwarded byte-for-byte, %2F and all.
    try bed.exchange("GET /a/%2e%2e/b/./c?x=1%2F2 HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    var storage: parser.HeaderStorage = undefined;
    const forwarded = try parser.parseRequestHead(
        bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
        false,
        &storage,
    );
    // Router and origin agree on the same canonical resource: /a/.. pops
    // to /, then /b/./c collapses to /b/c; the query rides along untouched.
    try std.testing.expectEqualStrings("/b/c?x=1%2F2", forwarded.target);
    try bed.expectDrained();
}

test "l7: an unroutable path is answered 404" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 13, .route_prefix = "/api" });
    defer bed.tearDown();

    // The only route is /api; /elsewhere matches nothing, so the origin is
    // never dialed and the client gets a 404 (§7, §8). The head parsed and
    // the request has no body, so the reject keeps the connection (§8) —
    // no `Connection: close`.
    try bed.exchange("GET /elsewhere HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_no_route"));
    try std.testing.expectEqual(@as(u64, 0), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: a structure-changing escape in the path is answered 400" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 14 });
    defer bed.tearDown();

    // %2F is an encoded slash: it would change the path's structure, so
    // the canonicalizer rejects it before routing (§7). Unlike the
    // malformed-head 400 above, the *head* parsed cleanly here — only the
    // target would not canonicalize — so the byte stream is still on a
    // message boundary and the connection keeps serving (§8).
    try bed.exchange("GET /a%2Fb HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_request"));
    try bed.expectDrained();
}

test "l7: the Host header selects a host-scoped route, case- and port-insensitively" {
    // The route is scoped to a canonical host; a request whose canonical
    // Host equals it routes there, whatever the wire case or port (§7).
    const wire_hosts = [_][]const u8{ "api.example", "API.Example", "Api.Example:8080" };
    for (wire_hosts, 0..) |host, index| {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = 20 + index,
            .route_host = "api.example",
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        var request_buffer: [128]u8 = undefined;
        const request = try std.fmt.bufPrint(
            &request_buffer,
            "GET /x HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n",
            .{host},
        );
        try bed.exchange(request);

        try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
        try std.testing.expectEqualStrings(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            bed.client.response(),
        );
        // The origin got the request verbatim-Host'd (host is a routing
        // key, forwarded as sent — here the wire Host rides along).
        try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
        try bed.expectDrained();
    }
}

test "l7: a request to a host with no route is answered 404" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 24, .route_host = "api.example" });
    defer bed.tearDown();

    // The only route is scoped to api.example; another host has no
    // any-host route to fall back to, so it is 404 and never dialed (§7).
    try bed.exchange("GET /x HTTP/1.1\r\nHost: other.example\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_no_route"));
    try std.testing.expectEqual(@as(u32, 0), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: a filter reject answers its policy status before the origin is dialed" {
    // One rule: POST under /admin is 403. The origin would answer 200,
    // but the filter rejects before any dial, so the client sees 403 and
    // the origin serves nothing (§7).
    const rules = [_]filter.Rule{.{
        .match = .{
            .methods = blk: {
                var set = std.EnumSet(parser.Method){};
                set.insert(.post);
                break :blk set;
            },
            .path_prefix = "/admin",
        },
        .actions = &.{.{ .reject = 403 }},
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 27,
        .filters = &rules,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    try bed.exchange("POST /admin/users HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_filtered"));
    try std.testing.expectEqual(@as(u32, 0), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: a request the filter does not match is proxied untouched" {
    // The same /admin rule; a GET to /public matches nothing, so it routes
    // and reaches the origin normally — the filter is a no-op (§7).
    const rules = [_]filter.Rule{.{
        .match = .{ .path_prefix = "/admin", .methods = blk: {
            var set = std.EnumSet(parser.Method){};
            set.insert(.post);
            break :blk set;
        } },
        .actions = &.{.{ .reject = 403 }},
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 28,
        .filters = &rules,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    try bed.exchange("GET /public HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_filtered"));
    try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: a filter reject survives 1-byte adversarial delivery across seeds" {
    // A header-matched 429 must land whole however the head is chopped up.
    const rules = [_]filter.Rule{.{
        .match = .{ .headers = &.{.{ .name = "X-Env", .kind = .equals, .value = "prod" }} },
        .actions = &.{.{ .reject = 429 }},
    }};
    var seed: u64 = 40;
    while (seed < 44) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = seed,
            .partial_io = true,
            .filters = &rules,
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange("GET /x HTTP/1.1\r\nHost: o\r\nX-Env: prod\r\n\r\n");

        try std.testing.expectEqualStrings(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u32, 0), bed.origin.requests_served);
        try bed.expectDrained();
    }
}

test "l7: an upstream-slot shed keeps the connection, and the client's ask decides" {
    // The rung that collapsed the c10k benchmark. An empty upstream pool
    // sheds every request with 503, so this drives the wall directly.
    //
    // Both requests are answered on ONE connection: the shed is a static
    // response, not a teardown (§8 "then keep or close per pressure").
    // That is the whole point — a close costs the client a handshake and
    // the proxy an accept plus a conn slot, which is how a shed storm ends
    // up more expensive per request than the work it sheds.
    //
    // The two responses differ in exactly one header, and the difference is
    // the *client's* ask, not the status: keep-alive is kept, `Connection:
    // close` is honored (§2). One test, both spellings, so neither branch
    // can rot into the other.
    // The single upstream slot goes to a client the origin never answers,
    // so it stays leased and every other request meets the wall.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 60,
        .upstream_slots = 1,
        .origin_mute = true,
    });
    defer bed.tearDown();

    // client holds the slot and must not end the run; client2 arrives once
    // it is held, sheds twice, and winds the scenario down.
    bed.client.drain_on_finish = false;
    bed.client2.send_delay_ms = 100;
    bed.client2.request = "GET /one HTTP/1.1\r\nHost: o\r\n\r\n";
    bed.client2.second_request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    bed.client2.start(&bed.sim_io, &bed.server, Http1Bed.bindAddress());
    try bed.exchange("GET /held HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n" ++
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client2.response(),
    );
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("l7_shed_upstream_slots"));
    // Two sheds, and client2 was accepted once. This is the ratio that
    // would have caught the collapse: on the old always-close path every
    // shed cost an accept, and accept/s tracking shed/s one-for-one *was*
    // the churn loop.
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("accepted"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("admitted"));
    try bed.expectDrained();
}

test "l7: kernel pressure on a socket option is witnessed per op, on both sockets" {
    // A fresh L7 exchange sets TCP_NODELAY twice: once on the accepted
    // client socket (`Server` admission) and once on the dialled upstream
    // (`onUpstreamConnect`). The second site is the one the per-op split
    // originally shipped without — it kept incrementing the aggregate
    // counter alone — and nothing could reach it in simulation until
    // SimIo learned to fail a socket option at all.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 71,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    bed.sim_io.injectSetOptionError();
    bed.sim_io.injectSetOptionError();
    try bed.exchange("GET /x HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("kernel_pressure_set_option"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("kernel_pressure_errors"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_recv"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_send"));
    // TCP_NODELAY is best-effort (§6): failing it costs latency, never
    // correctness, so the exchange is byte-for-byte unaffected.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: a 501 keeps the connection, and the next request is served" {
    // CONNECT and Upgrade are non-goals (§1, §7), but they are *method*
    // rejects, not framing ones: the head parsed cleanly and sits on a
    // message boundary, so the connection keeps serving like any other
    // valid-head reject. Nothing was forwarded, so there is no second
    // parser to disagree with about where the message ended.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 70,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    bed.client.second_request = "GET /after HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("CONNECT o:443 HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    // The 501 keeps, and the request after it is proxied normally — the
    // connection was never lost to a method it happened not to support.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_not_implemented"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("accepted"));
    try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: a reject closes when the client pipelined the next request" {
    // Bytes past the head are a pipelined next request, which §2 does not
    // serve. Keeping the connection here would leave those bytes sitting in
    // the head buffer to be read as the *start* of the next request — the
    // desynchronization a request-smuggler wants (§7). A wide inbox carries
    // both heads in one delivery, so the trailing bytes are provably
    // present when the reject is decided.
    const rules = [_]filter.Rule{.{
        .match = .{ .path_prefix = "/admin" },
        .actions = &.{.{ .reject = 403 }},
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 62,
        .filters = &rules,
        .inbox_bytes = 4096,
    });
    defer bed.tearDown();

    try bed.exchange(
        "GET /admin HTTP/1.1\r\nHost: o\r\n\r\n" ++
            "GET /admin/two HTTP/1.1\r\nHost: o\r\n\r\n",
    );

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    // One response, and it announces the close: the second head is never
    // answered on this connection.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_filtered"));
    try bed.expectDrained();
}

test "l7: a reject closes when the body has not arrived with the head" {
    // The framing-done condition on its own. Under 1-byte delivery the head
    // completes on the read that carries its final byte, so at reject time
    // nothing is past the head — `head_len == request_head_len` — and the
    // *only* thing standing between this and a kept connection is the
    // request's own declared body, still unread on the socket.
    const rules = [_]filter.Rule{.{
        .match = .{ .path_prefix = "/admin" },
        .actions = &.{.{ .reject = 403 }},
    }};
    var seed: u64 = 63;
    while (seed < 67) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = seed,
            .partial_io = true,
            .filters = &rules,
        });
        defer bed.tearDown();

        try bed.exchange("POST /admin HTTP/1.1\r\nHost: o\r\nContent-Length: 4\r\n\r\nbody");

        try std.testing.expectEqualStrings(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try bed.expectDrained();
    }
}

test "l7: a drain closes a reject that would otherwise be kept" {
    // `beginDrain` stops accepting but leaves admitted connections serving,
    // so a reject arriving mid-drain is a connection the drain is waiting
    // on. Keeping it would park an idle connection until `drain_deadline_ms`
    // and turn a clean shutdown into a deadline-forced one — so the drain
    // is a brake on keeping, exactly as it is on the render path (§2, §8).
    //
    // The client connects at once and is admitted, then holds its head back
    // until after the drain has begun.
    const rules = [_]filter.Rule{.{
        .match = .{ .path_prefix = "/admin" },
        .actions = &.{.{ .reject = 403 }},
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 69,
        .filters = &rules,
        .send_delay_ms = 100,
    });
    defer bed.tearDown();

    bed.armDrainTimer(50);
    try bed.exchange("GET /admin HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    // The drain finished because the connection left, not because the
    // deadline shot it — the difference a kept connection would erase.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("drained_at_deadline"));
    try bed.expectDrained();
}

test "l7: relay pressure closes a reject that would otherwise be kept" {
    // §8: relay pressure is what suppresses keep-alive on the render path
    // (#57), and a reject must honor the same brake — a proxy short of
    // buffers should not be holding connections open for their next
    // request. `relay_buffers = 1` puts the watermark at one held buffer,
    // so the muted client alone engages pressure.
    //
    // Identical to the kept 403 above in every respect except the pool
    // size, so the `Connection: close` here is attributable to pressure
    // and nothing else.
    const rules = [_]filter.Rule{.{
        .match = .{ .path_prefix = "/admin" },
        .actions = &.{.{ .reject = 403 }},
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 68,
        .relay_buffers = 1,
        .origin_mute = true,
        .filters = &rules,
    });
    defer bed.tearDown();

    bed.client.drain_on_finish = false;
    bed.client2.send_delay_ms = 100;
    bed.client2.request = "GET /admin HTTP/1.1\r\nHost: o\r\n\r\n";
    bed.client2.start(&bed.sim_io, &bed.server, Http1Bed.bindAddress());
    try bed.exchange("GET /held HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expect(bed.server.counters.get("relay_pressure_engaged") >= 1);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client2.response(),
    );
    try bed.expectDrained();
}

test "l7: a reject closes when the request carries a body" {
    // A declared body is unread bytes still to come, so the stream is not
    // on a message boundary and the connection cannot resynchronize — the
    // lingering close is what drains it (§2). Robust to delivery timing:
    // if the body arrives coalesced with the head it fails the
    // nothing-past-the-head condition, and if it arrives later it fails the
    // framing-done one. Either way, close.
    //
    // Driven through the filter rung because `respond` is the single exit
    // every reject and shed leaves by, so the persistence decision cannot
    // differ between rungs — only the status does.
    const rules = [_]filter.Rule{.{
        .match = .{ .path_prefix = "/admin" },
        .actions = &.{.{ .reject = 403 }},
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 61, .filters = &rules });
    defer bed.tearDown();

    try bed.exchange("POST /admin HTTP/1.1\r\nHost: o\r\nContent-Length: 4\r\n\r\nbody");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_filtered"));
    try bed.expectDrained();
}

test "l7: filter header edits reach the origin, applied once" {
    // set X-Env: prod (client sent dev), add X-Trace, remove Cookie. The
    // origin must see exactly the edited head, and the client the origin's
    // response — the edit is invisible downstream.
    const rules = [_]filter.Rule{.{
        .match = .{ .path_prefix = "/api" },
        .actions = &.{
            .{ .header_set = .{ .name = "X-Env", .value = "prod" } },
            .{ .header_add = .{ .name = "X-Trace", .value = "on" } },
            .{ .header_remove = "Cookie" },
        },
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 29,
        .filters = &rules,
        .route_prefix = "/api",
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    try bed.exchange(
        "GET /api/v1 HTTP/1.1\r\nHost: o\r\nX-Env: dev\r\nCookie: sid=1\r\nConnection: close\r\n\r\n",
    );

    // The client got the origin's response verbatim (edits are upstream).
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    // The origin saw the edited head: X-Env replaced, X-Trace added, Cookie
    // gone, and exactly one request served.
    try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
    var storage: parser.HeaderStorage = undefined;
    const forwarded = try parser.parseRequestHead(
        bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
        false,
        &storage,
    );
    try std.testing.expectEqualStrings("prod", parser.headerValue(forwarded.headers, "x-env").?);
    try std.testing.expectEqualStrings("on", parser.headerValue(forwarded.headers, "x-trace").?);
    try std.testing.expectEqual(@as(?[]const u8, null), parser.headerValue(forwarded.headers, "cookie"));
    try bed.expectDrained();
}

test "l7: a filter rewrite changes only the forwarded path, not the route" {
    // Routing keys off the original path (/old matches the route); the
    // rewrite swaps that prefix for /new on the way out, so the origin sees
    // a path that would NOT have matched the route — proof the rewrite
    // touches only what is forwarded, never re-routes (§7). The query rides
    // along verbatim.
    const rules = [_]filter.Rule{.{
        .match = .{},
        .actions = &.{.{ .rewrite_prefix = .{ .from = "/old", .to = "/new" } }},
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 30,
        .filters = &rules,
        .route_prefix = "/old",
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    try bed.exchange("GET /old/x?q=1 HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
    var storage: parser.HeaderStorage = undefined;
    const forwarded = try parser.parseRequestHead(
        bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
        false,
        &storage,
    );
    try std.testing.expectEqualStrings("/new/x?q=1", forwarded.target);
    try bed.expectDrained();
}

test "l7: a header edit reaches the origin exactly once under adversarial delivery" {
    // The §9 "edit reaches the origin exactly once" oracle under 1-byte
    // adversarial fragmentation across seeds: no fragmentation may drop,
    // duplicate, or corrupt the injected header.
    const rules = [_]filter.Rule{.{
        .match = .{},
        .actions = &.{.{ .header_set = .{ .name = "X-Env", .value = "prod" } }},
    }};
    var seed: u64 = 50;
    while (seed < 54) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = seed,
            .partial_io = true,
            .filters = &rules,
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange("GET /x HTTP/1.1\r\nHost: o\r\nX-Env: dev\r\nConnection: close\r\n\r\n");

        try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
        var storage: parser.HeaderStorage = undefined;
        const forwarded = try parser.parseRequestHead(
            bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
            false,
            &storage,
        );
        // The client sent dev; the edit replaced it with exactly one prod.
        try std.testing.expectEqualStrings("prod", parser.headerValue(forwarded.headers, "x-env").?);
        try bed.expectDrained();
    }
}

test "l7: a path rewrite forwards the rewritten path under adversarial delivery" {
    // The §9 "path edit reaches the origin" oracle under 1-byte adversarial
    // fragmentation across seeds: the origin sees the canonical rewritten
    // path, whole, however the head was chopped up.
    const rules = [_]filter.Rule{.{
        .match = .{},
        .actions = &.{.{ .rewrite_prefix = .{ .from = "/old", .to = "/new" } }},
    }};
    var seed: u64 = 60;
    while (seed < 64) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = seed,
            .partial_io = true,
            .filters = &rules,
            .route_prefix = "/old",
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange("GET /old/x HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

        try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
        var storage: parser.HeaderStorage = undefined;
        const forwarded = try parser.parseRequestHead(
            bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
            false,
            &storage,
        );
        try std.testing.expectEqualStrings("/new/x", forwarded.target);
        try bed.expectDrained();
    }
}

test "l7: an HTTP/1.0 request with no Host matches only any-host routes" {
    // Any-host route (the default): a Host-less HTTP/1.0 request still
    // routes.
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = 25,
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();
        try bed.exchange("GET /x HTTP/1.0\r\nConnection: close\r\n\r\n");
        try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
        try bed.expectDrained();
    }
    // Host-scoped route: a Host-less request cannot match it, so 404.
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 26, .route_host = "api.example" });
        defer bed.tearDown();
        try bed.exchange("GET /x HTTP/1.0\r\n\r\n");
        try std.testing.expectEqualStrings(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_no_route"));
        try bed.expectDrained();
    }
}

test "l7: a POST body is forwarded and a sized response returned, byte-exact under the adversary" {
    var seed: u64 = 1;
    while (seed <= 12) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = seed,
            .partial_io = true,
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange("POST /submit HTTP/1.1\r\nHost: o\r\nConnection: close\r\nContent-Length: 11\r\n\r\nhello world");

        try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
        try std.testing.expectEqualStrings(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            bed.client.response(),
        );
        // The origin received the whole 11-byte body after the head.
        try std.testing.expect(bed.origin.conns[0].request_complete);
        var storage: parser.HeaderStorage = undefined;
        const forwarded = try parser.parseRequestHead(
            bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
            false,
            &storage,
        );
        const body = bed.origin.conns[0].request_buffer[forwarded.head_len..bed.origin.conns[0].request_len];
        try std.testing.expectEqualStrings("hello world", body);
        try bed.expectDrained();
    }
}

test "l7: a body coalesced with the head, larger than a relay buffer, forwards intact" {
    // The client sends head + a 6000-byte body in one shot: the excess
    // (~6 KB) exceeds a 4 KiB relay buffer, so it must be forwarded
    // straight from the 8 KiB head buffer, not copied through one.
    const body_len = 6000;
    var request: [7000]u8 = undefined;
    const head = "POST /big HTTP/1.1\r\nHost: o\r\nConnection: close\r\nContent-Length: 6000\r\n\r\n";
    @memcpy(request[0..head.len], head);
    for (request[head.len .. head.len + body_len], 0..) |*byte, index| {
        byte.* = @intCast('A' + (index % 26));
    }
    const request_len = head.len + body_len;

    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 40,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    try bed.exchange(request[0..request_len]);

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    // The origin received the whole 6000-byte body byte-for-byte.
    try std.testing.expect(bed.origin.conns[0].request_complete);
    var storage: parser.HeaderStorage = undefined;
    const forwarded = try parser.parseRequestHead(
        bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
        false,
        &storage,
    );
    const forwarded_body = bed.origin.conns[0].request_buffer[forwarded.head_len..bed.origin.conns[0].request_len];
    try std.testing.expectEqualStrings(request[head.len..request_len], forwarded_body);
    try bed.expectDrained();
}

test "l7: a coalesced excess too large to ride the rendered head is written separately" {
    // The origin's delivery fills upstream.head exactly, so the coalesced
    // body sits flush against the 8 KiB bound; the `Connection: close`
    // injection then grows the render past it and the excess cannot ride
    // along — it leaves as a second write straight from upstream.head (§7).
    // Sizes derive from the bound rather than being spelled out, so a change
    // to `head_bytes_max` fails here loudly instead of quietly sliding the
    // scenario off the branch it exists to cover (#77).
    const injected_len = "Connection: close\r\n".len;
    const body_len = 42;
    const head_len: usize = constants.head_bytes_max - body_len;
    const prefix = std.fmt.comptimePrint(
        "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nX-Pad: ",
        .{body_len},
    );
    const suffix = "\r\n\r\n";

    var response_bytes: [constants.head_bytes_max]u8 = undefined;
    @memcpy(response_bytes[0..prefix.len], prefix);
    @memset(response_bytes[prefix.len..][0 .. head_len - prefix.len - suffix.len], 'p');
    @memcpy(response_bytes[head_len - suffix.len ..][0..suffix.len], suffix);
    for (response_bytes[head_len..][0..body_len], 0..) |*byte, index| {
        byte.* = @intCast('a' + (index % 26));
    }

    // Whole deliveries only: under 1-byte adversarial delivery the head
    // parses long before the excess lands, and the excess rides the head
    // write like every other response — a different path, covered elsewhere.
    // The seeds still vary the clock jitter that orders the two head reads
    // this response needs, so the branch must not depend on their timing.
    var seed: u64 = 40;
    while (seed < 44) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = seed,
            .origin_response = &response_bytes,
        });
        defer bed.tearDown();

        try bed.exchange("GET /pad HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

        try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
        // The counter is the assertion that matters: the client receives the
        // same bytes whichever way the excess left, so nothing below would
        // fail if the branch stopped being taken.
        try std.testing.expectEqual(
            @as(u64, 1),
            bed.server.counters.get("l7_response_excess_sent"),
        );
        const response = bed.client.response();
        try std.testing.expectEqual(head_len + injected_len + body_len, response.len);
        try std.testing.expectEqualStrings(
            response_bytes[head_len..][0..body_len],
            response[response.len - body_len ..],
        );
        try bed.expectDrained();
    }
}

test "l7: the coalesced excess in the shape production delivers it" {
    // The same branch as the test above, reached the way production reaches
    // it: a 41-byte head with a body large enough that one read fills
    // upstream.head outright. The test above has to grow the *head* to 8 KiB
    // instead, because the default socket ring is half a head buffer and can
    // never hand over more than that at once — the branch is common in
    // production and unrepresentable in the simulator until a scenario opens
    // the ring (#90).
    const body_len = 9000;
    const head = std.fmt.comptimePrint(
        "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n",
        .{body_len},
    );
    const injected_len = "Connection: close\r\n".len;
    var response_bytes: [head.len + body_len]u8 = undefined;
    @memcpy(response_bytes[0..head.len], head);
    for (response_bytes[head.len..], 0..) |*byte, index| {
        byte.* = @intCast('a' + (index % 26));
    }

    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 12,
        .inbox_bytes = constants.head_bytes_max,
        .origin_response = &response_bytes,
    });
    defer bed.tearDown();

    try bed.exchange("GET /big HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("l7_response_excess_sent"),
    );
    // The body crosses the excess write and the pump behind it intact.
    const response = bed.client.response();
    try std.testing.expectEqual(head.len + injected_len + body_len, response.len);
    try std.testing.expectEqualStrings(
        response_bytes[head.len..],
        response[response.len - body_len ..],
    );
    try bed.expectDrained();
}

test "l7: a connection-close (until-close) response body relays to the client's EOF" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 20,
        // No Content-Length and no Transfer-Encoding: the body runs to
        // the origin's close (§6.3 until-close), so the origin must close.
        .origin_response = "HTTP/1.1 200 OK\r\n\r\nstreamed body bytes",
        .origin_closes = true,
    });
    defer bed.tearDown();

    try bed.exchange("GET /stream HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nstreamed body bytes",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try bed.expectDrained();
}

test "l7: an unreachable origin is answered 502" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 30, .origin_listens = false });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: kernel pressure on the upstream dial is witnessed and answered 502" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 31 });
    defer bed.tearDown();

    // The origin listens and is healthy; the dial itself fails the way a
    // kernel out of ephemeral ports fails it (§8). Refused is the
    // origin's verdict and had coverage above — this is our own
    // exhaustion, and no seed could reach its witness before the
    // connect-error injector existed (issue #106, kind B).
    bed.sim_io.setPressureCause(.address_unavailable);
    bed.sim_io.injectConnectError(Http1Bed.originAddress());

    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_errors"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_connect"));
    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("kernel_pressure_address_unavailable"),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: an origin response head the proxy cannot parse is 502" {
    // Both verdicts on the origin's head — malformed, and oversize once the
    // buffer is full — land on the same arm, and both are 502s the dial
    // succeeded into: `accepted_count` is what separates them from the
    // unreachable-origin 502 above (#87).
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = 6,
            // A status hparse rejects: three digits are the only shape.
            .origin_response = "HTTP/1.1 2x0 OK\r\n\r\n",
        });
        defer bed.tearDown();

        try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\n\r\n");

        try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
        try std.testing.expectEqualStrings(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
        try std.testing.expectEqual(@as(u32, 1), bed.origin.accepted_count);
        try bed.expectDrained();
    }
    {
        // A head that never terminates. It accumulates to `head_bytes_max`
        // over several reads, and the parser turns the last Incomplete into
        // the oversize verdict rather than asking for a read that has
        // nowhere to land.
        const unterminated = "HTTP/1.1 200 OK\r\nX-Pad: ";
        const response = unterminated ++
            ("p" ** (constants.head_bytes_max - unterminated.len));

        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 8, .origin_response = response });
        defer bed.tearDown();

        try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\n\r\n");

        try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
        try std.testing.expectEqualStrings(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
        try std.testing.expectEqual(@as(u32, 1), bed.origin.accepted_count);
        try bed.expectDrained();
    }
}

test "l7: an origin head that no longer fits once the close is injected is 502" {
    // The origin's head is legal and exactly fills upstream.head; the render
    // then has to add `Connection: close` and has nowhere to put it. The
    // proxy cannot forward a head it cannot render, so the exchange fails
    // like any other upstream failure — 502, not a truncated response (#87).
    const prefix = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Pad: ";
    const suffix = "\r\n\r\n";
    var response_bytes: [constants.head_bytes_max]u8 = undefined;
    @memcpy(response_bytes[0..prefix.len], prefix);
    @memset(
        response_bytes[prefix.len..][0 .. response_bytes.len - prefix.len - suffix.len],
        'p',
    );
    @memcpy(response_bytes[response_bytes.len - suffix.len ..][0..suffix.len], suffix);

    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 9, .origin_response = &response_bytes });
    defer bed.tearDown();

    // `Connection: close` is what forces the injection: the head is legal
    // until the proxy has to announce a close the origin did not.
    try bed.exchange("GET /pad HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
    try std.testing.expectEqual(@as(u32, 1), bed.origin.accepted_count);
    try bed.expectDrained();
}

test "l7: a hung dial fires 504 at the connect budget, not the idle timeout" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 74, .origin_listens = false });
    defer bed.tearDown();

    // A blackholed origin: the connect neither succeeds nor refuses, so
    // only the connect deadline can end the dial — the §8 request-
    // deadline verdict (RFC 9110 §15.6.5: no timely response from the
    // upstream), distinct from the refused dial's prompt 502.
    bed.sim_io.blackholeAddress(Http1Bed.originAddress());

    const start_ns = bed.sim_io.nowNs();
    try bed.exchange("GET /unreachable HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_gateway_timeout"));
    // A timeout is not a dial failure: the counters stay orthogonal.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_bad_gateway"));
    // Finding #1 (§8): the dial re-bases the head-read/idle timer to the
    // per-try connect budget, so the verdict lands at connect_timeout_ms —
    // never the 20×-looser idle_timeout_ms the head read was armed under.
    const elapsed_ms = (bed.sim_io.nowNs() - start_ns) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms >= Http1Bed.connect_timeout_ms);
    try std.testing.expect(elapsed_ms < Http1Bed.idle_timeout_ms);
    try bed.expectDrained();
}

test "l7: rejects survive 1-byte adversarial delivery across seeds" {
    var seed: u64 = 1;
    while (seed <= 15) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = seed, .partial_io = true });
        defer bed.tearDown();

        try bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");

        try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
        try std.testing.expectEqualStrings(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_request"));
        try bed.expectDrained();
    }
}

test "l7: the head-read deadline reaps a slowloris that never completes" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 7 });
    defer bed.tearDown();

    // A partial head with no terminator: the client sends it and then
    // goes silent, so only the head-read deadline can end the connection.
    try bed.exchange("GET / HTTP/1.1\r\nHost: a\r\n");

    try std.testing.expectEqual(@as(usize, 0), bed.client.response().len);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: a mute origin earns the §8 request-deadline 504 verdict" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 70, .origin_mute = true });
    defer bed.tearDown();

    // The origin reads the request and never answers: the request
    // deadline expires with no response byte sent, the armed response
    // recv is forced by the upstream shutdown, and the client is
    // answered the exact 504 static response instead of a silent close.
    try bed.exchange("GET /stalled HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_gateway_timeout"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_bad_gateway"));
    try bed.expectDrained();
}

test "l7: a client stalling its own body is torn down, never answered 504" {
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 71, .origin_response = response });
    defer bed.tearDown();

    // The client announces a 10-byte body but sends only 3: the request
    // leg parks a recv on the CLIENT socket, which no verdict can force
    // without closing the very client it would answer — the stall is the
    // client's own, so expiry stays a teardown (§8).
    try bed.exchange("POST /p HTTP/1.1\r\nHost: o\r\nContent-Length: 10\r\n\r\nabc");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqual(@as(usize, 0), bed.client.response().len);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_gateway_timeout"));
    try bed.expectDrained();
}

test "l7: a response already started forfeits the 504 — teardown only" {
    // The origin sends a complete head but only half its announced body,
    // then stalls: response_started blocks the verdict (a 504 appended
    // to a half-relayed 200 would corrupt the stream), so the expiry
    // tears down and the client sees the truncation.
    const partial = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 72, .origin_response = partial });
    defer bed.tearDown();

    try bed.exchange("GET /truncated HTTP/1.1\r\nHost: o\r\n\r\n");

    // The head and the partial body arrived — and nothing else: no 504
    // bytes were mixed into the condemned stream.
    try std.testing.expect(std.mem.indexOf(u8, bed.client.response(), "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, bed.client.response(), "504") == null);
    try std.testing.expect(std.mem.endsWith(u8, bed.client.response(), "hello"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_gateway_timeout"));
    try bed.expectDrained();
}

test "l7: a dial re-basing an already-expired deadline defers past the cancel" {
    // Issue #65 (§8): the dial's re-base cancel is matching against
    // op_deadline's own completion, so no path may arm a fresh timer on
    // it until that cancel drains — the expiry included. The §6 lifetime
    // cap is what puts expiry on that path: the head lands exactly at the
    // cap, so the dial's storeDeadline clamps to an already-past target
    // and the head-read timer — delivered success in the same batch as
    // the re-base, before the cancel — finds the deadline due with the
    // cancel still in flight. The oracle is expireDeadline's
    // `assert(!conn.armed.deadline_cancel)`: with onDeadline's guard
    // dropped, this seed panics there.
    //
    // The client's head is held back to exactly the cap so the two wake
    // at the same instant (the clock never advances mid-batch, and never
    // at all while a cancel is pending, so a re-based target can only be
    // in the past if the cap already is). Only a minority of schedules
    // then order the batch the way the race needs — seeds 88 and 93
    // today — so the sweep is the coverage: pinning one seed would let an
    // unrelated shift in the PRNG draws silently stop reaching the path.
    const cap_ms: u32 = 25;
    var seed: u64 = 1;
    while (seed <= 100) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = seed,
            .max_lifetime_ms = cap_ms,
            .send_delay_ms = cap_ms,
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange("GET /capped HTTP/1.1\r\nHost: o\r\n\r\n");

        // Past the cap every stored deadline clamps into the past, so the
        // deferred expiry lands the moment the cancel drains and the
        // verdict's own grace expires with it: the cap reaps the
        // connection either way. What this pins is the discipline on the
        // way there, not a response — the exchange is condemned before it
        // can be answered, so the close is a FIN or (with the client's
        // head still unread) an RST, and §2 constrains neither: no
        // response byte was ever delivered.
        try std.testing.expect(bed.client.outcome != .pending);
        try std.testing.expect(bed.server.counters.get("deadline_expired") >= 1);
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
        try bed.expectDrained();
    }
}

test "l7: the request deadline fires 504 ahead of the connect and idle budgets" {
    // §8's request deadline is the rung that answers on *time* rather than
    // on a resource running out. The origin here accepts and then says
    // nothing, so the dial succeeds and only a deadline can end the
    // exchange — and the one that ends it must be this one, which is set
    // tighter than either budget the connection already carries.
    const request_ms: u32 = 20;
    comptime {
        assert(request_ms < Http1Bed.connect_timeout_ms);
        assert(Http1Bed.connect_timeout_ms < Http1Bed.idle_timeout_ms);
    }

    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 61,
        .origin_mute = true,
        .request_timeout_ms = request_ms,
    });
    defer bed.tearDown();

    const start_ns = bed.sim_io.nowNs();
    try bed.exchange("GET /slow HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_gateway_timeout"));
    // The dial *worked*: this is a slow exchange, not a hung or refused
    // one, which is exactly the case no other rung covers.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_bad_gateway"));
    // The verdict lands at the request budget, well inside the connect
    // budget the dial re-bases to and nowhere near the idle timeout the
    // head read was armed under.
    const elapsed_ms = (bed.sim_io.nowNs() - start_ns) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms >= request_ms);
    try std.testing.expect(elapsed_ms < Http1Bed.connect_timeout_ms);
    try bed.expectDrained();
}

test "l7: the request deadline binds a reused upstream, which no dial re-bases" {
    // The test above cannot pin `armRequestDeadline`'s re-base: a fresh
    // dial re-bases the timer itself, so the cap would be honoured either
    // way. The reuse path is where the re-base is load-bearing — it skips
    // `dialUpstream` entirely, so the only armed timer is the idle one
    // from the keep-alive turnaround, 50× looser than the cap. Serve the
    // first request, stall the second: the second rides the parked
    // upstream and only this exchange's own deadline can end it.
    const request_ms: u32 = 20;
    comptime assert(request_ms < Http1Bed.idle_timeout_ms);

    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 62,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .origin_mute_after_served = 1,
        .request_timeout_ms = request_ms,
    });
    defer bed.tearDown();

    bed.client.second_request = "GET /two HTTP/1.1\r\nHost: o\r\n\r\n";
    const start_ns = bed.sim_io.nowNs();
    try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\n\r\n");

    // One upstream connection served both tries, so the second never
    // dialed — `accepted_count` is the oracle for that.
    try std.testing.expectEqual(@as(u32, 1), bed.origin.accepted_count);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_gateway_timeout"));
    // Honest limit of this bed, measured rather than assumed: deleting the
    // re-base in `armRequestDeadline` does not move this number. Both
    // exchanges start at ~t=0 here, so the timer request one re-based is
    // already sitting on the exact instant request two's cap wants, and
    // the lazy re-arm covers for the missing call. The case that needs it
    // — a connection idle for minutes, its timer armed a whole idle
    // timeout out, taking a request with a 200 ms cap — needs a gap
    // between the two requests that this bed cannot express (issue #106).
    const elapsed_ms = (bed.sim_io.nowNs() - start_ns) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms >= request_ms);
    try std.testing.expect(elapsed_ms < Http1Bed.idle_timeout_ms);
    try bed.expectDrained();
}

test "l7: an exchange inside the request deadline is untouched by it" {
    // Negative space for the rung above: a deadline that binds a slow
    // exchange must not touch a prompt one, and must not survive its own
    // exchange — the second request on the same connection gets a fresh
    // budget, not the remainder of the first one's.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 50,
        .origin_response = response,
        .request_timeout_ms = 500,
    });
    defer bed.tearDown();

    bed.client.second_request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\n\r\n");
    try bed.expectDrained();

    // Both exchanges completed, the second off the parked upstream — the
    // reuse path, which never reaches the dial and so is the one that
    // depends on `armRequestDeadline` arming the budget itself.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("l7_responses"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_gateway_timeout"));
}

test "l7: the §7 replay inherits the request deadline, it does not restart it" {
    // A replay is the same client request taking its one free retry, so
    // the §8 cap must ride across it. `beginReplay` rebuilds `l7` field by
    // field, which is exactly where a cap can be dropped silently — and a
    // dropped cap does not fail loudly, it just stops clamping.
    //
    // Serve request one and close behind it, so the parked upstream is
    // stale; request two checks it out, fails on first use, and replays
    // onto a fresh dial that then stalls. The only budget left is the one
    // installed when request two was routed.
    const request_ms: u32 = 20;
    comptime assert(request_ms < Http1Bed.idle_timeout_ms);

    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 63,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .origin_closes = true,
        .origin_mute_after_served = 1,
        .request_timeout_ms = request_ms,
    });
    defer bed.tearDown();

    bed.client.second_request = "GET /two HTTP/1.1\r\nHost: o\r\n\r\n";
    const start_ns = bed.sim_io.nowNs();
    try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_replayed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_gateway_timeout"));
    // The discriminator: drop `request_deadline_ns` from `beginReplay`'s
    // literal and `storeDeadline` stops clamping, so the stalled replay
    // waits out the whole idle timeout instead of this budget.
    const elapsed_ms = (bed.sim_io.nowNs() - start_ns) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms >= request_ms);
    try std.testing.expect(elapsed_ms < Http1Bed.idle_timeout_ms);
    try bed.expectDrained();
}

test "l7: the 504 verdict path allocates nothing after init" {
    // §9 zero-alloc gate for the pending-verdict machinery: the forced
    // completion, the settle, and the static 504 answer must all run
    // without an allocation. Counting run, then a failing run pinned to
    // the init count.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var bed: Http1Bed = undefined;
    try bed.setUp(failing.allocator(), .{ .seed = 73, .origin_mute = true });
    defer bed.tearDown();
    const allocations_after_init = failing.allocations;
    try bed.exchange("GET /stalled HTTP/1.1\r\nHost: o\r\n\r\n");
    try bed.expectDrained();
    // The verdict must actually have fired, or this gates nothing.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_gateway_timeout"));
    try std.testing.expectEqual(allocations_after_init, failing.allocations);

    var strict = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = allocations_after_init,
    });
    var strict_bed: Http1Bed = undefined;
    try strict_bed.setUp(strict.allocator(), .{ .seed = 73, .origin_mute = true });
    defer strict_bed.tearDown();
    try strict_bed.exchange("GET /stalled HTTP/1.1\r\nHost: o\r\n\r\n");
    try strict_bed.expectDrained();
}

test "l7: a single close-terminated exchange allocates nothing after init" {
    // §9 zero-alloc gate for the L7 upstream leg: a full proxied
    // exchange — dial, request head + body, response, forward, close —
    // under a counting allocator, then again under one that *fails* past
    // the init count.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var bed: Http1Bed = undefined;
    try bed.setUp(failing.allocator(), .{ .seed = 9, .partial_io = true, .origin_response = response });
    defer bed.tearDown();
    const allocations_after_init = failing.allocations;
    try bed.exchange("POST /p HTTP/1.1\r\nHost: o\r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc");
    try bed.expectDrained();
    try std.testing.expectEqual(allocations_after_init, failing.allocations);

    var strict = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = allocations_after_init,
    });
    var strict_bed: Http1Bed = undefined;
    try strict_bed.setUp(strict.allocator(), .{ .seed = 9, .partial_io = true, .origin_response = response });
    defer strict_bed.tearDown();
    try strict_bed.exchange("POST /p HTTP/1.1\r\nHost: o\r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc");
    try strict_bed.expectDrained();
}

test "l7: the keep-alive reuse turnaround allocates nothing after init" {
    // §9 zero-alloc gate for the §5 park/checkout/reset path: two
    // requests on one client connection reuse the parked upstream — the
    // most allocation-prone L7 lifecycle code, and the one a single
    // close-terminated exchange never touches. Counting run, then a
    // failing run pinned to the init count.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const second_request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    const first_request = "GET /one HTTP/1.1\r\nHost: o\r\n\r\n";

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var bed: Http1Bed = undefined;
    try bed.setUp(failing.allocator(), .{ .seed = 50, .origin_response = response });
    defer bed.tearDown();
    const allocations_after_init = failing.allocations;
    bed.client.second_request = second_request;
    try bed.exchange(first_request);
    try bed.expectDrained();
    // The turnaround must actually have parked and reused the upstream,
    // or this gates nothing.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(allocations_after_init, failing.allocations);

    var strict = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = allocations_after_init,
    });
    var strict_bed: Http1Bed = undefined;
    try strict_bed.setUp(strict.allocator(), .{ .seed = 50, .origin_response = response });
    defer strict_bed.tearDown();
    strict_bed.client.second_request = second_request;
    try strict_bed.exchange(first_request);
    try strict_bed.expectDrained();
}

test "l7: an http listener admits without a relay buffer" {
    // The idle L7 connection holds a slot only (§5): a reject never
    // touches the relay pool.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 8 });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\nHost: a\r\n\r\n");
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_relay_buffers"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try bed.expectDrained();
}

test "l7: downstream keep-alive serves two requests on one connection" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 50,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // First request asks to keep the connection; the second announces the
    // close, ending the scenario cleanly.
    bed.client.second_request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\n\r\n");

    // One client connection, two responses: the first without a close
    // announcement, the second with one, then FIN.
    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("l7_responses"));
    // The idle turnaround also parked and reused the upstream connection.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(@as(u32, 2), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: a parked upstream connection is reused across client connections" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 51,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // Two separate client connections, each closing downstream — the
    // upstream connection parks after the first and serves the second
    // (the origin accepting only once is asserted in its harness).
    bed.client.next = &bed.client2;
    bed.client2.request = "GET /b HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client2.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client2.response(),
    );
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    // One origin connection served both requests — the reuse witness.
    try std.testing.expectEqual(@as(u32, 1), bed.origin.accepted_count);
    try std.testing.expectEqual(@as(u32, 2), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: the idle sweep reaps a parked upstream past its deadline" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 52,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // The client must not drain (that reaps parked instantly); a timer
    // drains well after the sweep has had time to act on the idle
    // deadline.
    bed.client.drain_on_finish = false;
    bed.armDrainTimer(Http1Bed.idle_timeout_ms * 3);
    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_idle_reaped"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("upstream_reused"));
    try bed.expectDrained();
}

test "l7: ejecting an endpoint closes its parked connections" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 55,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .check = .{ .timeout_ms = Http1Bed.connect_timeout_ms },
        .health_interval_ms = 40,
    });
    defer bed.tearDown();

    // The exchange parks its upstream; then the origin stops listening,
    // the probes start missing, and the third miss ejects the endpoint —
    // which must close the parked connection on the spot (§5), long
    // before the idle sweep (interval 500ms here) would have reaped it.
    // The client must not drain (that reaps parked instantly), so a
    // timer drains after the ejection has had time to land.
    bed.client.drain_on_finish = false;
    bed.armOriginStopTimer(25);
    bed.armDrainTimer(220);
    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("health_endpoint_down"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("health_parked_closed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("upstream_idle_reaped"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(@as(u32, 1), bed.server.health.unhealthy_count);
    try bed.expectDrained();
}

test "l7: a pipelining client gets its first response, then the close" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 53,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // Both requests in one write: the second is pipelined. Pipelining is
    // unsupported — the first exchange completes and the connection
    // closes; the client recovers by retrying per RFC.
    try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\n\r\n" ++
        "GET /two HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "l7: keep-alive is honored under conn-slot pressure" {
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 90,
        .origin_response = response,
        .conn_slots = 2,
    });
    defer bed.tearDown();

    // The first client exchanges, then idles holding a conn slot but no
    // relay buffer; a timer starts the second client mid-idle, filling
    // both slots — the §8 conn watermark engages with the relay pool
    // never above one of two. Yet both keep-alive asks are honored: a
    // slot-holding connection that serves requests is the capacity
    // doing its job, and closing it would churn the population into
    // reconnect waves (#57). The conn-slot remedy is the shortened idle
    // timeout, which reaps the connections once they go quiet and
    // returns their slots.
    const starter = struct {
        fn onTimer(started: *Http1Bed, result: Io.TimerError!void) void {
            result catch unreachable; // Nothing cancels the start timer.
            started.client2.start(
                &started.sim_io,
                &started.server,
                Http1Bed.bindAddress(),
            );
        }
    };
    var start_completion: SimIo.Completion = .{};
    bed.client2.request = "GET /b HTTP/1.1\r\nHost: o\r\n\r\n";
    bed.sim_io.timerStart(
        &start_completion,
        100 * std.time.ns_per_ms,
        Http1Bed,
        &bed,
        starter.onTimer,
    );
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expect(bed.server.counters.get("conn_pressure_engaged") >= 1);
    try std.testing.expectEqual(
        @as(u64, 0),
        bed.server.counters.get("relay_pressure_engaged"),
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        bed.client.response(),
        "Connection: close",
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        bed.client2.response(),
        "Connection: close",
    ) == null);
    // The divided idle deadline — not a keep-alive kill — returned the
    // slots.
    try std.testing.expect(bed.server.counters.get("deadline_expired") >= 1);
    try std.testing.expect(!bed.server.conn_pressure); // Cleared on drain.
    try bed.expectDrained();
}

test "l7: keep-alive is not honored under relay pressure" {
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 92,
        .origin_response = response,
        .relay_buffers = 1,
    });
    defer bed.tearDown();

    // A single relay buffer: the exchange's own claim crosses the §8
    // high watermark, so the render sees relay pressure and answers the
    // keep-alive ask with an announced close — the next request on this
    // connection would claim a buffer the pool is out of.
    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expect(bed.server.counters.get("relay_pressure_engaged") >= 1);
    try std.testing.expectEqual(
        @as(u64, 0),
        bed.server.counters.get("conn_pressure_engaged"),
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        bed.client.response(),
        "Connection: close",
    ) != null);
    try std.testing.expect(!bed.server.relay_pressure); // Cleared on drain.
    try bed.expectDrained();
}

test "l7: parked deadlines shorten under upstream pressure" {
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 91,
        .origin_response = response,
    });
    defer bed.tearDown();

    // Two concurrent exchanges lease both upstream slots — the §8
    // watermark engages — so both connections park under a shortened
    // deadline (idle/4, or idle/16 while relay pressure transiently
    // overlaps) and the sweep reaps them well before the drain timer at
    // the full idle timeout. Without the bias the parked deadline would
    // be the full idle timeout and the reap count zero.
    bed.client.drain_on_finish = false;
    bed.client2.drain_on_finish = false;
    bed.armDrainTimer(Http1Bed.idle_timeout_ms);
    bed.client2.request = "GET /b HTTP/1.1\r\nHost: o\r\n\r\n";
    bed.client2.start(&bed.sim_io, &bed.server, Http1Bed.bindAddress());
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expect(bed.server.counters.get("upstream_pressure_engaged") >= 1);
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("upstream_idle_reaped"));
    try std.testing.expect(!bed.server.upstream_pressure); // Cleared by the reaps.
    try bed.expectDrained();
}

test "l7: a stale parked connection is replayed for free on a fresh dial" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 54,
        // The origin's response claims keep-alive, but it closes right
        // after — the §5 stale-parked scenario, detected on first use
        // and absorbed by the §7 free replay.
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .origin_closes = true,
    });
    defer bed.tearDown();

    bed.client.next = &bed.client2;
    bed.client2.request = "GET /b HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    // The second client's request hit the stale checkout, replayed onto
    // a fresh dial, and was served — no 502 reaches anyone.
    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client2.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client2.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_replayed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_bad_gateway"));
    // Two origin connections served the two requests: the stale one and
    // the replay's fresh dial.
    try std.testing.expectEqual(@as(u32, 2), bed.origin.accepted_count);
    try std.testing.expectEqual(@as(u32, 2), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: a replayed POST re-sends its coalesced body intact" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 55,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .origin_closes = true,
    });
    defer bed.tearDown();

    // The second request carries a body that arrives coalesced with its
    // head: the replay must re-derive the framing from the re-parse and
    // re-feed the excess — double-consuming it would corrupt the body.
    bed.client.next = &bed.client2;
    bed.client2.request = "POST /b HTTP/1.1\r\nHost: o\r\nConnection: close\r\n" ++
        "Content-Length: 5\r\n\r\nhello";
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client2.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_replayed"));
    // The replay's connection received the whole POST — head and body —
    // byte-intact.
    const replay_conn = &bed.origin.conns[1];
    try std.testing.expect(replay_conn.request_complete);
    const forwarded = replay_conn.request_buffer[0..replay_conn.request_len];
    try std.testing.expect(std.mem.startsWith(u8, forwarded, "POST /b HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, forwarded, "\r\n\r\nhello"));
    try bed.expectDrained();
}

test "l7: the replay budget is one — a second early failure answers 502" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 56,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .origin_closes = true,
        .close_second_at_accept = true,
    });
    defer bed.tearDown();

    // The stale checkout replays onto a fresh dial, which the origin
    // closes at accept: that try fails with no response byte too — but
    // the replay is spent and the fresh dial was never a reuse, so the
    // §7 rule answers 502 rather than looping.
    bed.client.next = &bed.client2;
    bed.client2.request = "GET /b HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqualStrings(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client2.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_replayed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
    try std.testing.expectEqual(@as(u32, 2), bed.origin.accepted_count);
    try bed.expectDrained();
}

test "l7: the stale replay survives 1-byte adversarial delivery across seeds" {
    var seed: u64 = 80;
    while (seed <= 83) : (seed += 1) {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = seed,
            .partial_io = true,
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            .origin_closes = true,
        });
        defer bed.tearDown();

        bed.client.next = &bed.client2;
        bed.client2.request = "GET /b HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
        try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

        try std.testing.expectEqualStrings(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            bed.client2.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_replayed"));
        try bed.expectDrained();
    }
}

test "l7: the replay path allocates nothing after init" {
    // §9 zero-alloc gate for the §7 replay: stale detection, slot
    // disposal, the re-parse, and the fresh dial must all run without an
    // allocation. Counting run, then a failing run pinned to the count.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const second_request = "GET /b HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    const first_request = "GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var bed: Http1Bed = undefined;
    try bed.setUp(failing.allocator(), .{
        .seed = 57,
        .origin_response = response,
        .origin_closes = true,
    });
    defer bed.tearDown();
    const allocations_after_init = failing.allocations;
    bed.client.next = &bed.client2;
    bed.client2.request = second_request;
    try bed.exchange(first_request);
    try bed.expectDrained();
    // The replay must actually have fired, or this gates nothing.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_replayed"));
    try std.testing.expectEqual(allocations_after_init, failing.allocations);

    var strict = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = allocations_after_init,
    });
    var strict_bed: Http1Bed = undefined;
    try strict_bed.setUp(strict.allocator(), .{
        .seed = 57,
        .origin_response = response,
        .origin_closes = true,
    });
    defer strict_bed.tearDown();
    strict_bed.client.next = &strict_bed.client2;
    strict_bed.client2.request = second_request;
    try strict_bed.exchange(first_request);
    try strict_bed.expectDrained();
}

/// The single line the §8 access log wrote during a scenario. Fails rather
/// than returning null when there is not exactly one: a test asserting on
/// "the" line must not silently read the first of several.
fn onlyAccessLogLine(bed: *const Http1Bed) ![]const u8 {
    const sink = bed.sim_io.sinkBytes();
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, sink, "\n"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("access_log_lines"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("access_log_dropped"));
    return std.mem.trimEnd(u8, sink, "\n");
}

/// The one access-log line containing `needle`, for scenarios that emit
/// several. Fails when it is not exactly one, so a needle that matched
/// every line — or none — is a test bug rather than a passing assertion.
fn accessLogLineFor(bed: *const Http1Bed, needle: []const u8) ![]const u8 {
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, bed.sim_io.sinkBytes(), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.indexOf(u8, line, needle) == null) continue;
        try std.testing.expect(found == null);
        found = line;
    }
    return found orelse error.NoSuchAccessLogLine;
}

test "l7: a proxied GET writes one access-log line naming the origin's status" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 6,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        .access_log = true,
    });
    defer bed.tearDown();

    const request = "GET /path?q=1 HTTP/1.1\r\nHost: Origin.Example:8080\r\nConnection: close\r\n\r\n";
    try bed.exchange(request);
    try bed.expectDrained();

    const line = try onlyAccessLogLine(&bed);
    // The line names what the *client* asked and what the *origin*
    // answered: the canonical routing path (query split off, §7), the
    // canonical host (lowercased and port-stripped, §7), and the origin's
    // own status under outcome `ok`.
    try std.testing.expect(std.mem.indexOf(u8, line, "\"kind\":\"http\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"outcome\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"method\":\"GET\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"path\":\"/path\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"host\":\"origin.example\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"status\":200") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"cluster\":\"origin\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"upstream\":\"127.0.0.1:9000\"") != null);
    // Byte counts are what crossed this proxy's client side: the whole
    // request head in, the rendered response head plus its body out.
    var expected: [64]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(
        u8,
        line,
        try std.fmt.bufPrint(&expected, "\"bytes_in\":{d}", .{request.len}),
    ) != null);
    const relayed = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    try std.testing.expect(std.mem.indexOf(
        u8,
        line,
        try std.fmt.bufPrint(&expected, "\"bytes_out\":{d}", .{relayed.len}),
    ) != null);
}

test "l7: a shed and an origin 503 are the same status and different outcomes" {
    // The whole reason `outcome` exists beside `status` (§8): read off the
    // three digits alone, a resource wall and an origin's own answer are
    // indistinguishable, and they call for opposite responses.
    //
    // The single upstream slot goes to a client the origin never answers,
    // so the second client's request meets the wall — the same technique
    // the shed-persistence test uses.
    var shed_bed: Http1Bed = undefined;
    try shed_bed.setUp(std.testing.allocator, .{
        .seed = 11,
        .upstream_slots = 1,
        .origin_mute = true,
        .access_log = true,
    });
    defer shed_bed.tearDown();
    shed_bed.client.drain_on_finish = false;
    shed_bed.client2.send_delay_ms = 100;
    shed_bed.client2.request = "GET /shed HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    shed_bed.client2.start(&shed_bed.sim_io, &shed_bed.server, Http1Bed.bindAddress());
    try shed_bed.exchange("GET /held HTTP/1.1\r\nHost: o\r\n\r\n");
    try shed_bed.expectDrained();

    const shed_line = try accessLogLineFor(&shed_bed, "\"path\":\"/shed\"");
    try std.testing.expect(std.mem.indexOf(u8, shed_line, "\"status\":503") != null);
    try std.testing.expect(std.mem.indexOf(u8, shed_line, "\"outcome\":\"shed\"") != null);
    // No endpoint was ever leased, so the line names none.
    try std.testing.expect(std.mem.indexOf(u8, shed_line, "\"upstream\":null") != null);
    // The held request met the deadline against a mute origin and was
    // answered 504 — a third 5xx that `status` alone cannot tell from
    // either of the two above, and that names the endpoint it was waiting
    // on, which is the one an operator would go and look at.
    const held_line = try accessLogLineFor(&shed_bed, "\"path\":\"/held\"");
    try std.testing.expect(std.mem.indexOf(u8, held_line, "\"status\":504") != null);
    try std.testing.expect(std.mem.indexOf(u8, held_line, "\"outcome\":\"timed_out\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, held_line, "\"upstream\":\"127.0.0.1:9000\"") != null);

    var origin_bed: Http1Bed = undefined;
    try origin_bed.setUp(std.testing.allocator, .{
        .seed = 11,
        .origin_response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
        .access_log = true,
    });
    defer origin_bed.tearDown();
    try origin_bed.exchange("GET /path HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    try origin_bed.expectDrained();

    const origin_line = try onlyAccessLogLine(&origin_bed);
    try std.testing.expect(std.mem.indexOf(u8, origin_line, "\"status\":503") != null);
    try std.testing.expect(std.mem.indexOf(u8, origin_line, "\"outcome\":\"ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, origin_line, "\"upstream\":\"127.0.0.1:9000\"") != null);
}

test "l7: a response cut off mid-flight logs aborted, not ok" {
    // `ok` is defined as "the whole response reached the client" (§8), so
    // it is earned at `finishExchange` and nowhere earlier. Setting it when
    // the response head is *queued* — which is what the code did until the
    // §9 log oracle became an equality — makes every exchange that dies
    // mid-response log a success that never happened, with the origin's
    // status attached to lend it weight. An operator counting
    // `outcome:"ok"` would have read more successes than
    // `zoxy_l7_responses` reports, with nothing in the line to say which
    // ones were fiction.
    //
    // The origin promises 32 bytes and sends none, so the head reaches the
    // client and the body never does; the request deadline then fires on
    // an exchange that has already started responding, which §8 answers by
    // tearing down rather than by a 504.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 12,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n",
        .request_timeout_ms = 30,
        .access_log = true,
    });
    defer bed.tearDown();

    try bed.exchange("GET /cut HTTP/1.1\r\nHost: a\r\n\r\n");
    try bed.expectDrained();

    // No exchange completed, so nothing may claim to have.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_responses"));
    const line = try onlyAccessLogLine(&bed);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"outcome\":\"aborted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"outcome\":\"ok\"") == null);
    // The status still reports what the origin said: it is a fact about
    // the origin, and the outcome is the separate fact about the client.
    try std.testing.expect(std.mem.indexOf(u8, line, "\"status\":200") != null);
}

test "l7: a reject logs the target the client actually sent" {
    // A path that will not canonicalize has no §7 spelling to report, and
    // an empty field would tell an operator investigating a 400 nothing at
    // all — so the raw target is what the line carries.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 12, .access_log = true });
    defer bed.tearDown();

    try bed.exchange("GET /a%2Fb HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    try bed.expectDrained();

    const line = try onlyAccessLogLine(&bed);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"status\":400") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"outcome\":\"rejected\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"path\":\"/a%2Fb\"") != null);
}

test "l7: each request on a kept-alive connection gets its own line" {
    // The turnaround resets the per-request accounting (§8), so two
    // requests over one connection must produce two lines with their own
    // paths and their own byte counts — not one line, and not a running
    // total carried across.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 13,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .access_log = true,
    });
    defer bed.tearDown();

    const second_request = "GET /second HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    bed.client.next = &bed.client2;
    bed.client2.request = second_request;
    try bed.exchange("GET /first HTTP/1.1\r\nHost: a\r\n\r\n");
    try bed.expectDrained();

    const sink = bed.sim_io.sinkBytes();
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("access_log_lines"));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, sink, "\n"));
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, sink, "\n"), '\n');
    const first = lines.next().?;
    const second = lines.next().?;
    try std.testing.expect(lines.next() == null);
    try std.testing.expect(std.mem.indexOf(u8, first, "\"path\":\"/first\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, second, "\"path\":\"/second\"") != null);
    // The second request's counts are its own, not the pair's.
    var expected: [64]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(
        u8,
        second,
        try std.fmt.bufPrint(&expected, "\"bytes_in\":{d},", .{second_request.len}),
    ) != null);
}

test "l7: an idle kept-alive connection closing owes no line" {
    // The read that ends an idle kept-alive connection completes in the
    // same callback as the read that starts a request, and for a while
    // this proxy could not tell them apart: every keep-alive client got a
    // second, empty line reading `aborted` with no method, no path and no
    // status — one phantom request per real one. A request begins with a
    // *byte*, and a connection the client simply closed made none.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 14,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .access_log = true,
    });
    defer bed.tearDown();

    // No `Connection: close`: the proxy keeps the connection, the client
    // reads its response and then closes, and that close must be silent.
    bed.client.close_after_response = true;
    try bed.exchange("GET /kept HTTP/1.1\r\nHost: a\r\n\r\n");
    try bed.expectDrained();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("access_log_lines"));
    const line = try onlyAccessLogLine(&bed);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"path\":\"/kept\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"outcome\":\"ok\"") != null);
}

test "health: an http probe passes on the expected status" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 61,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .check = .{
            .kind = .http,
            .timeout_ms = Http1Bed.connect_timeout_ms,
            .http = .{ .path = "/health" },
        },
        .health_interval_ms = 30,
    });
    defer bed.tearDown();

    // No client at all: the prober is the only traffic. Each probe dials,
    // sends its GET, reads the 200 and hangs up, so the endpoint stays
    // healthy and nothing is ever ejected.
    bed.armDrainTimer(110);
    try bed.sim_io.run();

    // The count is the load-bearing assertion, not just "some probes
    // ran": a probe that reaches its verdict and then idles until its
    // budget expires still passes and still reports healthy, so only the
    // *rate* catches it. At a 30ms interval inside a 110ms run a probe
    // that settles immediately gets three sweeps away; one that waits out
    // the 50ms budget manages two. That gap is the regression this pins —
    // it was a real bug, found because this assertion was `>= 2`.
    try std.testing.expect(bed.server.counters.get("health_probes_sent") >= 3);
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("health_probes_failed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("health_endpoint_down"));
    try std.testing.expect(bed.server.health.healthy[0]);
    // The origin saw real requests — an http probe that never sent one
    // would pass this test on a TCP accept alone.
    try std.testing.expect(bed.origin.accepted_count >= 2);
    try std.testing.expect(std.mem.indexOf(
        u8,
        bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
        "GET /health HTTP/1.1\r\n",
    ) != null);
    try bed.expectDrained();
}

test "health: an http probe fails on a status it was not promised" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 62,
        // The origin is listening and answering — a TCP check would call
        // this endpoint healthy. Only reading the status can tell.
        .origin_response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
        .check = .{
            .kind = .http,
            .timeout_ms = Http1Bed.connect_timeout_ms,
            .http = .{ .path = "/health" },
        },
        .health_interval_ms = 30,
    });
    defer bed.tearDown();

    bed.armDrainTimer(130);
    try bed.sim_io.run();

    try std.testing.expect(bed.server.counters.get("health_probes_failed") >= 3);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("health_endpoint_down"));
    try std.testing.expect(!bed.server.health.healthy[0]);
    try std.testing.expectEqual(@as(u32, 1), bed.server.health.unhealthy_count);
    try bed.expectDrained();
}

test "health: an http probe fails when the origin never answers" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 63,
        // Reads the request in full and says nothing: the recv leg is
        // armed with no answer coming, so only the probe's own budget
        // ends it — and a data op is never canceled (§5), so the
        // deadline must shut the socket down to force its completion.
        .origin_mute = true,
        .check = .{
            .kind = .http,
            .timeout_ms = 30,
            .http = .{ .path = "/health" },
        },
        .health_interval_ms = 30,
    });
    defer bed.tearDown();

    bed.armDrainTimer(220);
    try bed.sim_io.run();

    try std.testing.expect(bed.server.counters.get("health_probes_failed") >= 3);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("health_endpoint_down"));
    try bed.expectDrained();
}

test "l7: a request past the endpoint cap is answered 503, not sent" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 71,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        // One in flight per endpoint, and this bed has exactly one
        // endpoint: the second concurrent request has nowhere under
        // capacity to go.
        .max_inflight = 1,
        // The origin reads the first request and never answers, so that
        // request stays in flight while the second arrives.
        .origin_mute = true,
        .request_timeout_ms = 400,
    });
    defer bed.tearDown();

    bed.client.request = "GET /one HTTP/1.1\r\nHost: o\r\n\r\n";
    bed.client.start(&bed.sim_io, &bed.server, Http1Bed.bindAddress());
    bed.client2.request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    bed.client2.send_delay_ms = 40;
    bed.client2.start(&bed.sim_io, &bed.server, Http1Bed.bindAddress());
    try bed.sim_io.run();

    // The second client is refused to protect the origin — and the
    // origin must never have seen it: exactly one connection accepted.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_shed_endpoint_inflight"));
    try std.testing.expectEqual(@as(u32, 1), bed.origin.accepted_count);
    try std.testing.expect(std.mem.startsWith(u8, bed.client2.response(), "HTTP/1.1 503"));
    // The pool never ran out — that is a different rung with a different
    // fix, and confusing the two is what the separate counter prevents.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_upstream_slots"));
}
