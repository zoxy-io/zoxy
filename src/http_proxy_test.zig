//! Directed L7 scenarios over SimIo (§9), separate from the L4 harness
//! in server_test.zig so neither over-generalizes the other. Covers head
//! ingestion and static-response rejects (before any dial), and the full
//! upstream leg against a scripted HTTP origin: request head + framed
//! body forwarded, response head + framed body relayed back, byte-exact
//! under 1-byte adversarial delivery. Every scenario ends with counters
//! reconciled and all pools drained.

const std = @import("std");

const Balancer = @import("balancer.zig").Balancer;
const config_module = @import("config.zig");
const constants = @import("constants.zig");
const router = @import("http/router.zig");
const filter = @import("http/filter.zig");
const Io = @import("io/io.zig");
const parser = @import("http/parser.zig");
const Server = @import("Server.zig").Server;
const SimIo = @import("io/SimIo.zig");
const Credentials = @import("tls/Credentials.zig");
const TlsClient = @import("tls/TestClient.zig").TestClient(SimIo);

const assert = std.debug.assert;

// The throwaway self-signed fixtures (`tls/testdata/README.md`),
// embedded rather than read: this file runs under the Io seam.
const fixture_cert_pem = @embedFile("tls/testdata/cert.pem");
const fixture_key_pem = @embedFile("tls/testdata/key.pem");
/// The fixture certificate SAN a TLS client must offer.
const fixture_host_name = "spike.zoxy.test";

const ServerSim = Server(SimIo);

/// A scripted HTTP client: sends `request` (the adversary may split the
/// send), then reads until the peer closes, recording the response bytes
/// and whether the close was an orderly FIN or an RST — the §7 property
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
    receive_buffer: [2 * constants.head_buffer_bytes_default]u8 = undefined,
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
    /// From the Nth request on, answer with a bare `100 Continue` and
    /// close (#232). The sibling of `mute_after_served`, and for the same
    /// reason: it is the only way to park an upstream on a served
    /// exchange and then have the *reused* one relay an interim and die,
    /// which is the shape that decides whether a replay is legal.
    interim_then_close_after_served: u32 = std.math.maxInt(u32),
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
        /// This connection answers a bare interim and dies (#232).
        interim_then_close: bool = false,
        closed: bool = false,
        /// Total bytes expected for the current request (head + framed
        /// body), known once its head parses. 0 means not parsed yet.
        request_expected: u32 = 0,
        /// The request in flight is chunked, so its total is unknown and
        /// this connection only drains (#236).
        chunked_request: bool = false,
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
                    // A chunked body has no length to expect (#236's
                    // streaming half is the only thing that sends one
                    // here). Read whatever arrives and let the proxy's own
                    // verdict — a teardown at the cap — end the exchange;
                    // the assert below would otherwise fire on the first
                    // body byte, since nothing was expected past the head.
                    .chunked => {
                        oconn.chunked_request = true;
                        oconn.request_expected = request.head_len;
                        oconn.armRecv();
                        return;
                    },
                    else => 0,
                };
                oconn.request_expected = request.head_len + body_length;
            }
            if (oconn.chunked_request) {
                oconn.armRecv();
                return;
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
            if (oconn.origin.requests_served >= oconn.origin.interim_then_close_after_served) {
                oconn.interim_then_close = true;
            }
            oconn.armSend();
        }

        fn responseBytes(oconn: *const OConn) []const u8 {
            if (oconn.interim_then_close) return "HTTP/1.1 100 Continue\r\n\r\n";
            return oconn.origin.response;
        }

        fn armSend(oconn: *OConn) void {
            assert(oconn.response_sent < oconn.responseBytes().len);
            oconn.origin.io.send(
                oconn.socket,
                oconn.responseBytes()[oconn.response_sent..],
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
            if (oconn.response_sent < oconn.responseBytes().len) {
                oconn.armSend();
                return;
            }
            if (oconn.interim_then_close) {
                // The interim went out and the origin dies on it: the
                // client has been told to go ahead by an origin that then
                // stopped answering.
                oconn.origin.io.closeNow(oconn.socket);
                oconn.closed = true;
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
    endpoints: [2]std.Io.net.IpAddress,
    endpoints_count: u16,
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
    tls_credentials: [1]?Credentials,

    const idle_timeout_ms: u32 = 1000;
    /// Deliberately 20× tighter than the idle timeout so a test can witness
    /// the §8 dial re-base: a hung L7 dial must fire 504 at this budget, not
    /// the far looser head-read/idle deadline (finding #1).
    const connect_timeout_ms: u32 = 50;

    pub fn bindAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
    }

    fn originAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
    }

    /// An address no origin binds, so `SimIo` refuses every dial to it
    /// through its own listener lookup — the same answer a kernel gives
    /// for a port nothing is on, and the failure #181 exists to survive.
    fn refusingEndpointAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9002") catch unreachable;
    }

    const Options = struct {
        seed: u64,
        partial_io: bool = false,
        /// Terminate TLS on the one listener (#125). The bed loads the
        /// checked-in fixtures and hands them over before `start`,
        /// standing in for what `main` does — this file runs under the Io
        /// seam, where a filesystem is what does not exist.
        tls: bool = false,
        /// Socket-ring size, null for SimIo's own default (§9). The default
        /// is narrower than a head buffer, so no delivery can fill one in a
        /// single read; a scenario that needs the shape production takes
        /// raises it. Independent of `partial_io`, which fragments what the
        /// ring was willing to carry.
        inbox_bytes: ?u32 = null,
        origin_response: []const u8 = "",
        /// The #181 dial-retry budget on the bed's one cluster.
        retries: u16 = 0,
        /// The #180 upgrade allowlist and tunnel pool. Both off by
        /// default, which is the shape every pre-#180 config has.
        upgrades: config_module.Config.Listener.Upgrades = .{},
        tunnels: u32 = 0,
        /// The §8 drain deadline. The bed's default is a real one; a
        /// tunnel scenario needs the zero case, which is production's
        /// default and the one #180 had to answer for.
        drain_deadline_ms: u32 = 1000,
        /// The #235 head-read budget; absent mirrors the bed's idle window.
        head_timeout_ms: ?u32 = null,
        /// The #236 request-body cap; 0 accepts any size.
        max_body_bytes: u64 = constants.request_body_bytes_default,
        /// The #237 keep-alive request cap; 0 is unlimited.
        keepalive_requests: u32 = constants.keepalive_requests_default,
        /// Put an endpoint nothing listens on *ahead* of the origin, so
        /// the first pick of an `rr` cluster is always the one that
        /// refuses and the retry is the only way to reach the origin.
        refusing_endpoint_first: bool = false,
        origin_listens: bool = true,
        origin_closes: bool = false,
        /// The origin reads the whole request and never answers (§8 504).
        origin_mute: bool = false,
        /// The origin answers this many requests and stalls from then on,
        /// so a test can stall a *reused* upstream rather than a fresh
        /// dial. Default never stalls.
        origin_mute_after_served: u32 = std.math.maxInt(u32),
        /// From the Nth request on, the origin answers `100 Continue` and
        /// closes — the reused-upstream-dies-after-an-interim shape.
        origin_interim_then_close_after_served: u32 = std.math.maxInt(u32),
        /// The origin closes the second accepted connection at accept —
        /// the replayed try fails too, pinning the one-replay budget.
        close_second_at_accept: bool = false,
        /// Pool sizes, injectable so a test can cross the §8 watermarks.
        conn_slots: u32 = 4,
        relay_buffers: u32 = 2,
        upstream_slots: u32 = 2,
        /// The §5 head-buffer ring; null follows conn_slots (never
        /// sheds), a number drives the `l7_shed_head_buffers` rung.
        head_buffers: ?u32 = null,
        /// The §5 upstream head pool; null follows upstream_slots (never
        /// sheds), a number drives `l7_shed_upstream_head_buffers`.
        upstream_head_buffers: ?u32 = null,
        /// Bytes per head buffer — the configured largest-accepted head.
        head_buffer_bytes: u32 = constants.head_buffer_bytes_default,
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
        /// The listener's §7 request filter rules; empty by default so
        /// existing scenarios are unfiltered. A test supplies compiled
        /// rules to drive the filter reject/edit paths.
        request_filters: []const filter.Rule = &.{},
        /// The listener's #175 response filter rules; empty by default
        /// on the same terms.
        response_filters: []const filter.ResponseRule = &.{},
        /// The §7 client-address forwarding mode; null (the default)
        /// leaves `X-Forwarded-For` untouched, as every pre-existing
        /// scenario expects.
        forwarded: ?config_module.Config.Listener.Forwarded = null,
        /// Turn the §8 access log on. Off by default so every existing
        /// scenario keeps paying nothing for it; a test that turns it on
        /// reads the emitted lines straight out of SimIo's virtual sink.
        access_log: bool = false,
        /// The #140 headers each line records; empty for every
        /// pre-existing scenario, so their lines stay byte-identical.
        /// Names must already be lowercase — the loader lowercases, and
        /// a bed builds its `Config` directly.
        access_log_request_headers: []const []const u8 = &.{},
        access_log_response_headers: []const []const u8 = &.{},
        /// §7 active health checks on the one cluster; null by default so
        /// existing scenarios see no probe traffic.
        check: ?config_module.Config.Cluster.Check = null,
        /// §8 per-endpoint concurrency cap; null leaves the cluster
        /// uncapped, which is what every pre-existing scenario wants.
        max_inflight: ?u32 = null,
        /// The #159 pre-rendered error pages; empty for every
        /// pre-existing scenario, so the comptime statics keep serving.
        error_pages: []const *const config_module.Config.StaticPage = &.{},
        /// The one cluster's §7 pick policy; p2c, the config default,
        /// for every pre-existing scenario.
        pick: config_module.Config.Cluster.Pick = .p2c,
        /// What a `hash` cluster keys on (#178); `source_ip` is inert
        /// beside any other policy, matching the loader's contract.
        hash_key: config_module.Config.Cluster.HashKey = .source_ip,
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
        // One number on both sides (§5): the ring the sim registers is
        // the limit the server accounts against — Server.init asserts
        // the match, so a bed cannot drift them apart.
        const head_buffers = options.head_buffers orelse options.conn_slots;
        try bed.sim_io.init(arena, .{
            .seed = options.seed,
            .adversary = adversary,
            .buffer_group_count = head_buffers,
            .buffer_group_bytes = options.head_buffer_bytes,
        });
        bed.endpoints = if (options.refusing_endpoint_first)
            .{ refusingEndpointAddress(), originAddress() }
        else
            .{ originAddress(), originAddress() };
        bed.endpoints_count = if (options.refusing_endpoint_first) 2 else 1;
        bed.clusters = .{.{ .name = "origin", .endpoints = bed.endpoints[0..bed.endpoints_count], .check = options.check, .max_inflight = options.max_inflight, .pick = options.pick, .hash_key = options.hash_key, .retries = options.retries }};
        bed.routes = .{.{ .host = options.route_host, .prefix = options.route_prefix, .cluster_index = 0 }};
        bed.listeners = .{.{
            .bind_address = bindAddress(),
            .routes = &bed.routes,
            .request_filters = options.request_filters,
            .response_filters = options.response_filters,
            .protocol = .http,
            .upgrades = options.upgrades,
            .max_body_bytes = options.max_body_bytes,
            .forwarded = options.forwarded,
            // Paths nothing reads: the bed embeds the PEMs, so what this
            // states is only that the listener terminates.
            .tls = if (options.tls)
                .{ .cert_path = "cert.pem", .key_path = "key.pem" }
            else
                null,
        }};
        bed.config = .{
            .listeners = &bed.listeners,
            .clusters = &bed.clusters,
            // The #237 cap is read off the *config*, which is where the
            // loader puts it; `InitOptions` sizes the pools. The bed keeps
            // the rest of `limits` at its struct defaults, which is what
            // every test before this one was measuring against.
            .limits = .{ .keepalive_requests = options.keepalive_requests },
            .connect_timeout_ms = connect_timeout_ms,
            .idle_timeout_ms = idle_timeout_ms,
            // Mirrors the idle window unless a test is about the split
            // (#235): the bed's timeouts are milliseconds, so a flat
            // default would sit far above the window it must tighten.
            .head_timeout_ms = options.head_timeout_ms orelse idle_timeout_ms,
            .drain_deadline_ms = options.drain_deadline_ms,
            .max_lifetime_ms = options.max_lifetime_ms,
            .request_timeout_ms = options.request_timeout_ms,
            .tunnel_timeout_ms = constants.tunnel_ms_default,
            .access_log_sink = if (options.access_log) .stdout else null,
            .health_interval_ms = options.health_interval_ms,
            .error_pages = options.error_pages,
            .access_log_request_headers = options.access_log_request_headers,
            .access_log_response_headers = options.access_log_response_headers,
        };
        try bed.server.init(arena, &bed.sim_io, &bed.config, .{
            .conn_slots = options.conn_slots,
            .relay_buffers = options.relay_buffers,
            .upstream_slots = options.upstream_slots,
            .head_buffers = head_buffers,
            .upstream_head_buffers = options.upstream_head_buffers orelse options.upstream_slots,
            .head_buffer_bytes = options.head_buffer_bytes,
            .access_log_buffer_bytes = if (options.access_log)
                constants.access_log_buffer_bytes_default
            else
                0,
            .tls_engines = if (options.tls) options.conn_slots else 0,
            .tunnels = options.tunnels,
        });
        try bed.loadTlsCredentials(arena, options.tls);
        try bed.server.start();
        bed.origin = .{
            .response = options.origin_response,
            .close_after_response = options.origin_closes,
            .mute = options.origin_mute,
            .mute_after_served = options.origin_mute_after_served,
            .interim_then_close_after_served = options.origin_interim_then_close_after_served,
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

    /// Stand in for what `main` does before `start` (§4): this file runs
    /// under the Io seam, so it embeds the fixtures rather than reading
    /// them. Its own function for `setUp`'s length limit.
    fn loadTlsCredentials(bed: *Http1Bed, arena: std.mem.Allocator, on: bool) !void {
        bed.tls_credentials = .{null};
        if (!on) return;
        bed.tls_credentials[0] = try Credentials.load(
            arena,
            fixture_cert_pem,
            fixture_key_pem,
            // Deterministic signatures, so a seeded run replays a
            // byte-exact handshake (§9). Never set in production.
            .{ .deterministic_nonce = true },
        );
        bed.server.setTlsCredentials(&bed.tls_credentials);
    }

    fn tearDown(bed: *Http1Bed) void {
        if (bed.tls_credentials[0]) |*credentials| {
            credentials.deinit();
        }
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

/// Parses what the origin actually received as a request head, into
/// `storage` — caller-owned so the returned head's slices (into
/// `storage` and the origin's own request buffer) stay valid as long as
/// the caller needs them.
fn forwardedRequest(bed: *const Http1Bed, storage: *parser.HeaderStorage) !parser.RequestHead {
    return parser.parseRequestHead(
        bed.origin.conns[0].request_buffer[0..bed.origin.conns[0].request_len],
        false,
        storage,
    );
}

test "l7: a head that fits on arrival but not after forwarding is 431" {
    // Two arms the head-parse verdicts above cannot reach: a head the parser
    // accepted, rejected only when the proxy renders what it will forward
    // (#87).
    {
        // An added header pushes an exactly-`head_buffer_bytes_default` head over.
        const rules = [_]filter.Rule{.{
            .match = .{ .path_prefix = "/api" },
            .actions = &.{.{ .header_add = .{ .name = "X-Trace", .value = "on" } }},
        }};
        const prefix = "GET /api HTTP/1.1\r\nHost: o\r\nX-Pad: ";
        const suffix = "\r\n\r\n";
        var request: [constants.head_buffer_bytes_default]u8 = undefined;
        @memcpy(request[0..prefix.len], prefix);
        @memset(request[prefix.len..][0 .. request.len - prefix.len - suffix.len], 'p');
        @memcpy(request[request.len - suffix.len ..][0..suffix.len], suffix);

        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = 5,
            .request_filters = &rules,
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
            .request_filters = &rules,
            .route_prefix = "/r",
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange(request);

        try expectRejectedAfterDial(&bed);
        try bed.expectDrained();
    }
}

test "l7: an absolute-form target routes on its authority, not on Host" {
    // RFC 9112 §3.2.2 makes accepting absolute-form a MUST and has the
    // received Host ignored in favour of the target's authority (#233).
    // Both halves are asserted: what the policy saw, and what the origin
    // saw — they must be the same name, or the router and the origin
    // disagree about which resource was named (§7).
    {
        // The rule matches the *authority*, and the disagreeing Host is
        // the name it would have matched had the override not happened.
        const rules = [_]filter.Rule{.{
            .match = .{ .host = "api.example" },
            .actions = &.{.{ .reject = 403 }},
        }};
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{ .seed = 41, .request_filters = &rules });
        defer bed.tearDown();

        try bed.exchange("GET http://API.Example/v2/x HTTP/1.1\r\nHost: stale.example\r\n\r\n");

        // Case is folded on the way to the routing key, exactly as a Host
        // header's would be, so the mixed-case authority still matches.
        try std.testing.expectEqualStrings(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            bed.client.response(),
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_filtered"));
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_absolute_form"));
        try std.testing.expectEqual(@as(u32, 0), bed.origin.requests_served);
        try bed.expectDrained();
    }
    {
        var bed: Http1Bed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .seed = 42,
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange(
            "GET http://api.example:8080/v2/../x?q=1 HTTP/1.1\r\nHost: stale.example\r\n\r\n",
        );

        var storage: parser.HeaderStorage = undefined;
        const forwarded = try forwardedRequest(&bed, &storage);
        // Origin-form upstream, canonicalized like any other target, and
        // carrying exactly one Host — the authority, port and all.
        try std.testing.expectEqualStrings("/x?q=1", forwarded.target);
        try std.testing.expectEqualStrings("api.example:8080", forwarded.host.?);
        try std.testing.expectEqual(@as(?[]const u8, null), forwarded.authority);
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_absolute_form"));
        try bed.expectDrained();
    }
}

test "l7: an unsupported absolute-form scheme is 400" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 43 });
    defer bed.tearDown();

    // §7 speaks http and https; a target naming anything else is refused
    // at the boundary rather than routed by its path alone (#233).
    try bed.exchange("GET ftp://files.example/x HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqualStrings(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_request"));
    // The head never parsed, so nothing counted the form it was in.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_absolute_form"));
    try bed.expectDrained();
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
    const forwarded = try forwardedRequest(&bed, &storage);
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
    const forwarded = try forwardedRequest(&bed, &storage);
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
    const forwarded = try forwardedRequest(&bed, &storage);
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
        .request_filters = &rules,
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
        .request_filters = &rules,
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
            .request_filters = &rules,
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
    // close` is honored (§7). One test, both spellings, so neither branch
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

test "l7: a head-ring shed answers 503 and always closes" {
    // The §5 rung that precedes the parse: the client spoke while every
    // ring buffer was bound. Unlike every other shed this one can never
    // keep — the request's bytes were never read (no buffer was ever
    // bound), so a kept connection would re-arm onto the same bytes and
    // shed the same request forever. `respond` enforces the close at
    // comptime; this pins the wire truth of both halves: the 503, and
    // the announced close that follows it.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 61,
        .head_buffers = 1,
        .origin_mute = true,
    });
    defer bed.tearDown();

    // client binds the single ring buffer and holds it (a mute origin
    // keeps its exchange open); client2 arrives to an empty ring.
    bed.client.drain_on_finish = false;
    bed.client2.send_delay_ms = 100;
    bed.client2.request = "GET /one HTTP/1.1\r\nHost: o\r\n\r\n";
    bed.client2.start(&bed.sim_io, &bed.server, Http1Bed.bindAddress());
    try bed.exchange("GET /held HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client2.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_shed_head_buffers"));
    try bed.expectDrained();
}

test "l7: keep-alive returns the head buffer between requests" {
    // The §5 headline: an idle keep-alive connection holds no head
    // bytes. Observed through the watermark counter rather than a
    // mid-run probe: with a one-buffer ring every bind engages the
    // pressure flag (the high watermark of capacity 1 is 1) and every
    // return clears it, so two sequential keep-alive requests on one
    // connection must count exactly two engages. A ring buffer held
    // across the idle gap would count one — and shed the second
    // request besides, which the zero shed count rules out.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 62,
        .origin_response = response,
        .head_buffers = 1,
    });
    defer bed.tearDown();

    bed.client.second_request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_head_buffers"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("head_pressure_engaged"));
    try bed.expectDrained();
}

test "l7: an upstream head-pool shed keeps the connection like any post-parse rung" {
    // The §5 upstream head pool's wall, distinct from the slot wall: two
    // slots free, one head buffer — the first exchange holds it from the
    // moment its slot was obtained (a mute origin never lets it park), so
    // the second request gets a slot and sheds at the head acquire right
    // beside it. Unlike the client-side ring rung this request was fully
    // read and parsed, so the ordinary keep-or-close rules apply — pinned
    // the same way the slot-shed test pins them: two requests answered on
    // one connection, the close spelling honoring the client's own ask.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 63,
        .upstream_slots = 2,
        .upstream_head_buffers = 1,
        .origin_mute = true,
    });
    defer bed.tearDown();

    bed.client.drain_on_finish = false;
    bed.client2.send_delay_ms = 100;
    bed.client2.request = "GET /one HTTP/1.1\r\nHost: o\r\n\r\n";
    bed.client2.second_request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    bed.client2.start(&bed.sim_io, &bed.server, Http1Bed.bindAddress());
    try bed.exchange("GET /held HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_relay_buffers"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_head_buffers"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_upstream_slots"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("l7_shed_upstream_head_buffers"));
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n" ++
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client2.response(),
    );
    try bed.expectDrained();
}

test "l7: the configured head size is the accepted head size" {
    // The §5 size knob is behaviour, not just memory: at 1024 bytes a
    // request line that would sail through the 8 KiB default dies as the
    // 414 the smaller buffer makes of it, and an ordinary GET still fits.
    // The oversize half proves the wall moved down with the config; the
    // ordinary half proves it did not move below what it promises.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 64,
        .origin_response = response,
        .head_buffer_bytes = constants.head_buffer_bytes_min,
    });
    defer bed.tearDown();

    // 1100 path bytes: past the 1024 buffer with no newline in sight —
    // the request line alone overflows, which is the 414 shape.
    const oversize = "GET /" ++ ("a" ** 1100) ++ " HTTP/1.1\r\nHost: o\r\n\r\n";
    bed.client2.send_delay_ms = 50;
    bed.client2.request = oversize;
    bed.client2.start(&bed.sim_io, &bed.server, Http1Bed.bindAddress());
    try bed.exchange("GET /ok HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_uri_too_long"));
    try std.testing.expectEqualStrings(
        "HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client2.response(),
    );
    try std.testing.expect(std.mem.startsWith(u8, bed.client.response(), "HTTP/1.1 200 OK"));
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
    // Bytes past the head are a pipelined next request, which §7 does not
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
        .request_filters = &rules,
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
            .request_filters = &rules,
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
    // is a brake on keeping, exactly as it is on the render path (§7, §8).
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
        .request_filters = &rules,
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
        .request_filters = &rules,
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
    // lingering close is what drains it (§7). Robust to delivery timing:
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
    try bed.setUp(std.testing.allocator, .{ .seed = 61, .request_filters = &rules });
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
        .request_filters = &rules,
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
    const forwarded = try forwardedRequest(&bed, &storage);
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
        .request_filters = &rules,
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
    const forwarded = try forwardedRequest(&bed, &storage);
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
            .request_filters = &rules,
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange("GET /x HTTP/1.1\r\nHost: o\r\nX-Env: dev\r\nConnection: close\r\n\r\n");

        try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
        var storage: parser.HeaderStorage = undefined;
        const forwarded = try forwardedRequest(&bed, &storage);
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
            .request_filters = &rules,
            .route_prefix = "/old",
            .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        });
        defer bed.tearDown();

        try bed.exchange("GET /old/x HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

        try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
        var storage: parser.HeaderStorage = undefined;
        const forwarded = try forwardedRequest(&bed, &storage);
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
        const forwarded = try forwardedRequest(&bed, &storage);
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
    const forwarded = try forwardedRequest(&bed, &storage);
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
    // to `head_buffer_bytes_default` fails here loudly instead of quietly sliding the
    // scenario off the branch it exists to cover (#77).
    const injected_len = "Connection: close\r\n".len;
    const body_len = 42;
    const head_len: usize = constants.head_buffer_bytes_default - body_len;
    const prefix = std.fmt.comptimePrint(
        "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nX-Pad: ",
        .{body_len},
    );
    const suffix = "\r\n\r\n";

    var response_bytes: [constants.head_buffer_bytes_default]u8 = undefined;
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
        .inbox_bytes = constants.head_buffer_bytes_default,
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
        // A head that never terminates. It accumulates to `head_buffer_bytes_default`
        // over several reads, and the parser turns the last Incomplete into
        // the oversize verdict rather than asking for a read that has
        // nowhere to land.
        const unterminated = "HTTP/1.1 200 OK\r\nX-Pad: ";
        const response = unterminated ++
            ("p" ** (constants.head_buffer_bytes_default - unterminated.len));

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
    var response_bytes: [constants.head_buffer_bytes_default]u8 = undefined;
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

test "l7: a redirect composes Location from the request and keeps serving (#176)" {
    // Scheme-only composed target: the Location is the configured
    // scheme plus the request's own host, canonical path and verbatim
    // query. Keep-alive holds — a redirect is an answer, not a fault —
    // so the same connection's next request reaches the origin.
    const rules = [_]filter.Rule{
        .{ .match = .{ .path_prefix = "/old" }, .actions = &.{
            .{ .redirect = .{ .status = 301, .target = .{ .composed = .{ .scheme = .https } } } },
        } },
    };
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 31,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .request_filters = &rules,
    });
    defer bed.tearDown();

    bed.client.second_request = "GET /fresh HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /old/path?q=1 HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 301 Moved Permanently\r\n" ++
            "Location: https://o/old/path?q=1\r\n" ++
            "Content-Length: 0\r\n\r\n" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_redirected"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    // The redirected request never reached the origin; the second did.
    try std.testing.expectEqual(@as(u32, 1), bed.origin.accepted_count);
    try bed.expectDrained();
}

test "l7: a redirect can replace the host, or name a fixed target (#176)" {
    const rules = [_]filter.Rule{
        .{ .match = .{ .path_prefix = "/www" }, .actions = &.{
            .{ .redirect = .{ .status = 308, .target = .{ .composed = .{
                .scheme = .https,
                .host = "example.com",
            } } } },
        } },
        .{ .match = .{ .path_prefix = "/gone" }, .actions = &.{
            .{ .redirect = .{ .status = 302, .target = .{
                .location = "https://status.example.com/",
            } } },
        } },
    };
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 32, .request_filters = &rules });
    defer bed.tearDown();

    bed.client.second_request = "GET /gone HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /www?keep=1 HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    // The composed host replaces the request's; the literal is sent
    // verbatim, carrying nothing of the request.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 308 Permanent Redirect\r\n" ++
            "Location: https://example.com/www?keep=1\r\n" ++
            "Content-Length: 0\r\n\r\n" ++
            "HTTP/1.1 302 Found\r\n" ++
            "Location: https://status.example.com/\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("l7_redirected"));
    // Neither request touched the origin.
    try std.testing.expectEqual(@as(u32, 0), bed.origin.accepted_count);
    try bed.expectDrained();
}

test "l7: a composed redirect with no authority to compose from is 400 (#176)" {
    const rules = [_]filter.Rule{
        .{ .match = .{}, .actions = &.{
            .{ .redirect = .{ .status = 301, .target = .{ .composed = .{ .scheme = .https } } } },
        } },
    };
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{ .seed = 33, .request_filters = &rules });
    defer bed.tearDown();

    // HTTP/1.0 without Host: no replacement host on the rule and no
    // authority on the request — nothing to compose the target from.
    try bed.exchange("GET /anything HTTP/1.0\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_request"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_redirected"));
    try bed.expectDrained();
}

test "l7: a redirect whose Location cannot be carried is 414 (#176)" {
    // The request's own target is what makes the composed Location too
    // long for the head buffer: the URI's fault, the URI's status.
    const rules = [_]filter.Rule{
        .{ .match = .{}, .actions = &.{
            .{ .redirect = .{ .status = 301, .target = .{ .composed = .{ .scheme = .https } } } },
        } },
    };
    const head_buffer_bytes: u32 = 1024;
    const prefix = "GET /";
    const suffix = " HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    // A path long enough that the response head overflows the buffer,
    // while the request itself still fits it. Announcing close keeps
    // the assertion on the close spelling of the 414 — unlike the
    // parse-time 414 this one arrives on a clean message boundary, so
    // a keep-alive request would legitimately be kept.
    var request: [prefix.len + 960 + suffix.len]u8 = undefined;
    @memcpy(request[0..prefix.len], prefix);
    @memset(request[prefix.len..][0..960], 'p');
    @memcpy(request[prefix.len + 960 ..][0..suffix.len], suffix);
    comptime assert(prefix.len + 960 + suffix.len <= head_buffer_bytes);

    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 34,
        .request_filters = &rules,
        .head_buffer_bytes = head_buffer_bytes,
    });
    defer bed.tearDown();

    try bed.exchange(&request);

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_uri_too_long"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_redirected"));
    try bed.expectDrained();
}

test "l7: response filters edit the origin's head on the way out (#175)" {
    // An unconditional rule sheds the Server banner and adds HSTS; a
    // 5xx-scoped rule must stay silent on this 200. The whole rendered
    // head is pinned byte-exact: origin order minus the removed header,
    // the appended edit, then the close the request announced — proving
    // the edits land between the origin's headers and the injection.
    const rules = [_]filter.ResponseRule{
        .{ .match = .{}, .edits = &.{
            .{ .kind = .remove, .name = "Server", .value = "" },
            .{ .kind = .add, .name = "Strict-Transport-Security", .value = "max-age=63072000" },
        } },
        .{ .match = .{ .status_class = 5 }, .edits = &.{
            .{ .kind = .set, .name = "Retry-After", .value = "1" },
        } },
    };
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 21,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nServer: origin/1\r\n\r\nhi",
        .response_filters = &rules,
    });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" ++
            "Strict-Transport-Security: max-age=63072000\r\n" ++
            "Connection: close\r\n\r\nhi",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try bed.expectDrained();
}

test "l7: a 5xx-scoped response filter fires on the status that names it (#175)" {
    // The issue's own deciding case: `header_set` on 5xx only. The same
    // rule set as above, against an origin answering 503.
    const rules = [_]filter.ResponseRule{
        .{ .match = .{ .status_class = 5 }, .edits = &.{
            .{ .kind = .set, .name = "Retry-After", .value = "1" },
        } },
    };
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 22,
        .origin_response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
        .response_filters = &rules,
    });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    // The origin's 503 forwards — a response filter edits, never
    // rewrites the verdict — and the edit rides along.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n" ++
            "Retry-After: 1\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try bed.expectDrained();
}

test "l7: an origin head that no longer fits after response edits is 502 (#175)" {
    // The origin's head is legal and would render as-is; the configured
    // edit adds bytes the buffer does not have. An origin response the
    // proxy cannot re-render is not the client's fault — 502, the same
    // verdict the close-injection overflow earns (#87).
    const rules = [_]filter.ResponseRule{
        .{ .match = .{}, .edits = &.{
            .{ .kind = .add, .name = "Strict-Transport-Security", .value = "max-age=63072000" },
        } },
    };
    const prefix = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Pad: ";
    const suffix = "\r\n\r\n";
    // Ten bytes of slack: enough for the head itself, nowhere near the
    // ~46 the edit appends.
    var response_bytes: [constants.head_buffer_bytes_default - 10]u8 = undefined;
    @memcpy(response_bytes[0..prefix.len], prefix);
    @memset(
        response_bytes[prefix.len..][0 .. response_bytes.len - prefix.len - suffix.len],
        'p',
    );
    @memcpy(response_bytes[response_bytes.len - suffix.len ..][0..suffix.len], suffix);

    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 23,
        .origin_response = &response_bytes,
        .response_filters = &rules,
    });
    defer bed.tearDown();

    // Keep-alive request: no close injection, so the overflow is the
    // edit's alone.
    try bed.exchange("GET /pad HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
    try bed.expectDrained();
}

/// The #178 tag of the bed's one endpoint, spelled the way the stamp
/// spells it — through the server's own balancer, so mint and
/// expectation cannot drift.
fn bedEndpointTag(bed: *const Http1Bed) [Balancer.endpoint_tag_len]u8 {
    var tag: [Balancer.endpoint_tag_len]u8 = undefined;
    Balancer.formatEndpointTag(bed.server.balancer.endpointIdentity(0, 0), &tag);
    return tag;
}

test "l7: a sticky stamp on a terminated connection carries Secure (#125, #178)" {
    // The attribute used to ride nothing, on the reasoning that a proxy
    // which does not terminate TLS cannot know the client-facing scheme.
    // #125 falsified that. Where zoxy terminates it knows the scheme is
    // https, and a routing cookie without `Secure` is one the browser
    // hands back over plaintext to the same host.
    //
    // Neither the sweep nor any other directed test covers this: the
    // simulator's byte-exact stamp oracle runs on plaintext clients, and
    // its terminating clients only check that a response *is* one. So
    // this is the whole gate on the attribute, both halves of it.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 31,
        .tls = true,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .pick = .hash,
        .hash_key = .{ .cookie = "zoxy-srv" },
    });
    defer bed.tearDown();

    var client: TlsClient = undefined;
    try client.start(&bed.sim_io, Http1Bed.bindAddress(), .{
        .host_name = fixture_host_name,
        .app_data = "GET / HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n",
        .exchange_end = .http_response,
    });
    var wind_down: TlsWindDown = .{ .bed = &bed };
    wind_down.attach(&client);
    try bed.sim_io.run();

    // The whole response, not a substring probe: this is the only gate on
    // the attribute, and a substring would pass a reply carrying two
    // stamps — one secure, one not — or the header in the wrong place.
    // The neighbouring plaintext stamp tests compare whole responses for
    // the same reason, and the TLS bed is already used that way.
    var expected_buffer: [512]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &expected_buffer,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" ++
            "Set-Cookie: zoxy-srv={s}; Path=/; HttpOnly; Secure\r\n" ++
            "Connection: close\r\n\r\nhi",
        .{&bedEndpointTag(&bed)},
    ) catch unreachable;
    try std.testing.expectEqualStrings(
        expected,
        client.app_received[0..client.app_received_len],
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_sticky_assigned"));
}

test "l7: a cookieless request on a cookie cluster is assigned and stamped (#178)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 31,
        // The origin sets its own cookie: the stamp is an `add`, so the
        // application's Set-Cookie must ride through beside it.
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: app=1\r\n\r\nhi",
        .pick = .hash,
        .hash_key = .{ .cookie = "zoxy-srv" },
    });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    var expected_buffer: [512]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &expected_buffer,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: app=1\r\n" ++
            "Set-Cookie: zoxy-srv={s}; Path=/; HttpOnly\r\n" ++
            "Connection: close\r\n\r\nhi",
        .{&bedEndpointTag(&bed)},
    ) catch unreachable;
    try std.testing.expectEqualStrings(expected, bed.client.response());
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_sticky_assigned"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_sticky_followed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_sticky_repicked"));
    try bed.expectDrained();
}

test "l7: a request naming the endpoint it reaches is followed, not re-stamped (#178)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 32,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .pick = .hash,
        .hash_key = .{ .cookie = "zoxy-srv" },
    });
    defer bed.tearDown();

    var request_buffer: [256]u8 = undefined;
    const request = std.fmt.bufPrint(
        &request_buffer,
        "GET / HTTP/1.1\r\nHost: o\r\nCookie: theme=dark; zoxy-srv={s}\r\n" ++
            "Connection: close\r\n\r\n",
        .{&bedEndpointTag(&bed)},
    ) catch unreachable;
    try bed.exchange(request);

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    // Idempotent: the client already holds the right tag, so the
    // response must not re-speak it — a stamp on every response would
    // reset session-cookie expiry semantics the operator may layer on.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_sticky_followed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_sticky_assigned"));
    try bed.expectDrained();
}

test "l7: a well-formed tag naming no endpoint is repicked and re-stamped (#178)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 33,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .pick = .hash,
        .hash_key = .{ .cookie = "zoxy-srv" },
    });
    defer bed.tearDown();

    // Sixteen lowercase hex — the minted grammar — but no endpoint of
    // this cluster: a config that shrank, or a forgery. Either way the
    // request is served and the response re-announces.
    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\n" ++
        "Cookie: zoxy-srv=ffffffffffffffff\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    var expected_buffer: [512]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &expected_buffer,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" ++
            "Set-Cookie: zoxy-srv={s}; Path=/; HttpOnly\r\n" ++
            "Connection: close\r\n\r\nhi",
        .{&bedEndpointTag(&bed)},
    ) catch unreachable;
    try std.testing.expectEqualStrings(expected, bed.client.response());
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_sticky_repicked"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_sticky_assigned"));
    try bed.expectDrained();
}

test "l7: a malformed tag is an absent one — assigned, not repicked (#178)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 34,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .pick = .hash,
        .hash_key = .{ .cookie = "zoxy-srv" },
    });
    defer bed.tearDown();

    // Not the minted grammar (wrong length): it names nothing, so the
    // request is a first request, not a re-homing — the distinction the
    // repicked counter exists to keep clean.
    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\n" ++
        "Cookie: zoxy-srv=notatag\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_sticky_assigned"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_sticky_repicked"));
    try bed.expectDrained();
}

test "l7: a header-keyed cluster stamps nothing (#178)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 35,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .pick = .hash,
        .hash_key = .{ .header = "x-tenant" },
    });
    defer bed.tearDown();

    // The keyed header present and absent: rendezvous and the load
    // fallback both serve, and neither direction owes the client any
    // announcement — a header key is the client's own statement.
    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\nX-Tenant: acme\r\n" ++
        "Connection: close\r\n\r\n");
    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_sticky_followed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_sticky_assigned"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_sticky_repicked"));
    try bed.expectDrained();
}

/// A hand-rendered #159 page for the directed tests: exactly what the
/// loader's `renderStaticPage` produces for a 5-byte text body, so the
/// serve path's output can be pinned byte-for-byte here without a
/// loader round trip.
const test_page_body = "gone\n";
const test_not_found_keep = "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n" ++
    "Content-Type: text/plain\r\n\r\n" ++ test_page_body;
const test_not_found_close = "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n" ++
    "Content-Type: text/plain\r\nConnection: close\r\n\r\n" ++ test_page_body;
const test_not_found_page = config_module.Config.StaticPage{
    .status = 404,
    .keep = test_not_found_keep,
    .close = test_not_found_close,
    .keep_head_len = test_not_found_keep.len - test_page_body.len,
    .close_head_len = test_not_found_close.len - test_page_body.len,
};

test "l7: a configured 404 page serves where the empty static did (#159)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 41,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .route_prefix = "/api",
        .error_pages = &.{&test_not_found_page},
    });
    defer bed.tearDown();

    // No route for /nope: the 404 rides the ordinary keep rule — the
    // head parsed cleanly and announced close, so the close variant
    // answers, body and all, from immutable memory.
    try bed.exchange("GET /nope HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(test_not_found_page.close, bed.client.response());
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_no_route"));
    try bed.expectDrained();
}

test "l7: a keep-alive reject serves the page and keeps serving (#159)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 42,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .route_prefix = "/api",
        .error_pages = &.{&test_not_found_page},
    });
    defer bed.tearDown();

    // First request misses the route and earns the keep-variant page;
    // the connection stays synchronized, so the second — sent only after
    // the first response completes, sequential keep-alive rather than
    // pipelining — is served by the origin: the page rode the same
    // keep-or-close rules the empty static keeps.
    bed.client.second_request = "GET /api HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /nope HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    var expected_buffer: [512]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &expected_buffer,
        "{s}HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        .{test_not_found_page.keep},
    ) catch unreachable;
    try std.testing.expectEqualStrings(expected, bed.client.response());
    try bed.expectDrained();
}

test "l7: a HEAD request gets a page's head and none of its body (#159)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 43,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .route_prefix = "/api",
        .error_pages = &.{&test_not_found_page},
    });
    defer bed.tearDown();

    // RFC 9110's HEAD rule on the configured page: the framing headers
    // say what a GET would have carried, and no body follows — the
    // prefix slice of the same rendered buffer.
    try bed.exchange("HEAD /nope HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        test_not_found_page.close[0..test_not_found_page.close_head_len],
        bed.client.response(),
    );
    try bed.expectDrained();
}

test "l7: a filter reject wears its configured page too (#159)" {
    // `respondFilter` routes through the same `respond`, so a 403 page
    // fires for policy rejects without any per-feature wiring — the
    // point of pages living behind the one static path.
    const forbidden_body = "no\n";
    const forbidden_keep = "HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n" ++
        "Content-Type: text/plain\r\n\r\n" ++ forbidden_body;
    const forbidden_close = "HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n" ++
        "Content-Type: text/plain\r\nConnection: close\r\n\r\n" ++ forbidden_body;
    const page = config_module.Config.StaticPage{
        .status = 403,
        .keep = forbidden_keep,
        .close = forbidden_close,
        .keep_head_len = forbidden_keep.len - forbidden_body.len,
        .close_head_len = forbidden_close.len - forbidden_body.len,
    };
    const rules = [_]filter.Rule{.{
        .match = .{ .path_prefix = "/private" },
        .actions = &.{.{ .reject = 403 }},
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 44,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .request_filters = &rules,
        .error_pages = &.{&page},
    });
    defer bed.tearDown();

    try bed.exchange("GET /private HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(page.close, bed.client.response());
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_filtered"));
    try bed.expectDrained();
}

test "l7: a respond action answers from memory and never dials (#159)" {
    const robots_body = "User-agent: *\n";
    const robots_keep = "HTTP/1.1 200 OK\r\nContent-Length: 14\r\n" ++
        "Content-Type: text/plain\r\n\r\n" ++ robots_body;
    const robots_close = "HTTP/1.1 200 OK\r\nContent-Length: 14\r\n" ++
        "Content-Type: text/plain\r\nConnection: close\r\n\r\n" ++ robots_body;
    const robots_page = config_module.Config.StaticPage{
        .status = 200,
        .keep = robots_keep,
        .close = robots_close,
        .keep_head_len = robots_keep.len - robots_body.len,
        .close_head_len = robots_close.len - robots_body.len,
    };
    const rules = [_]filter.Rule{.{
        .match = .{ .path_prefix = "/robots.txt" },
        .actions = &.{.{ .respond = &robots_page }},
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 45,
        // The origin listens and would answer, so a dial that happened
        // would show up as this body instead of the configured one.
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .request_filters = &rules,
    });
    defer bed.tearDown();

    // Two requests on one connection: the first is answered from the
    // page and the connection keeps serving, the second proves the
    // origin was reachable all along — so the first not reaching it was
    // the verdict, not a broken upstream.
    bed.client.second_request = "GET /api HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /robots.txt HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    var expected_buffer: [512]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &expected_buffer,
        "{s}HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        .{robots_keep},
    ) catch unreachable;
    try std.testing.expectEqualStrings(expected, bed.client.response());
    // Answered as the origin, counted apart from refusals — and only
    // the second request ever reached an upstream.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responded"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_filtered"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
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
        // head still unread) an RST, and §7 constrains neither: no
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

/// §9 zero-alloc gate shared by every "allocates nothing after init" test
/// below: run `Scenario.run` under a counting allocator, confirm no
/// allocation past init, then rerun the identical scenario under an
/// allocator that *fails* past that same count — surviving proves the
/// hot path never asks. `Scenario.verify`, if declared, checks the
/// scenario actually exercised the path it gates; it only runs on the
/// counting pass, since the strict pass only needs to survive.
fn zeroAllocGate(comptime Scenario: type, options: Http1Bed.Options) !void {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var bed: Http1Bed = undefined;
    try bed.setUp(failing.allocator(), options);
    defer bed.tearDown();
    const allocations_after_init = failing.allocations;
    try Scenario.run(&bed);
    try bed.expectDrained();
    if (@hasDecl(Scenario, "verify")) try Scenario.verify(&bed);
    try std.testing.expectEqual(allocations_after_init, failing.allocations);

    var strict = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = allocations_after_init,
    });
    var strict_bed: Http1Bed = undefined;
    try strict_bed.setUp(strict.allocator(), options);
    defer strict_bed.tearDown();
    try Scenario.run(&strict_bed);
    try strict_bed.expectDrained();
}

test "l7: the 504 verdict path allocates nothing after init" {
    // §9 zero-alloc gate for the pending-verdict machinery: the forced
    // completion, the settle, and the static 504 answer must all run
    // without an allocation.
    const Scenario = struct {
        fn run(bed: *Http1Bed) !void {
            try bed.exchange("GET /stalled HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn verify(bed: *Http1Bed) !void {
            // The verdict must actually have fired, or this gates nothing.
            try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_gateway_timeout"));
        }
    };
    try zeroAllocGate(Scenario, .{ .seed = 73, .origin_mute = true });
}

test "l7: a single close-terminated exchange allocates nothing after init" {
    // §9 zero-alloc gate for the L7 upstream leg: a full proxied
    // exchange — dial, request head + body, response, forward, close.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const Scenario = struct {
        fn run(bed: *Http1Bed) !void {
            try bed.exchange("POST /p HTTP/1.1\r\nHost: o\r\nConnection: close\r\nContent-Length: 3\r\n\r\nabc");
        }
    };
    try zeroAllocGate(Scenario, .{ .seed = 9, .partial_io = true, .origin_response = response });
}

test "l7: the keep-alive reuse turnaround allocates nothing after init" {
    // §9 zero-alloc gate for the §5 park/checkout/reset path: two
    // requests on one client connection reuse the parked upstream — the
    // most allocation-prone L7 lifecycle code, and the one a single
    // close-terminated exchange never touches.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const Scenario = struct {
        fn run(bed: *Http1Bed) !void {
            bed.client.second_request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
            try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\n\r\n");
        }
        fn verify(bed: *Http1Bed) !void {
            // The turnaround must actually have parked and reused the
            // upstream, or this gates nothing.
            try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
        }
    };
    try zeroAllocGate(Scenario, .{ .seed = 50, .origin_response = response });
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
    // allocation.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const Scenario = struct {
        fn run(bed: *Http1Bed) !void {
            bed.client.next = &bed.client2;
            bed.client2.request = "GET /b HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
            try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");
        }
        fn verify(bed: *Http1Bed) !void {
            // The replay must actually have fired, or this gates nothing.
            try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_replayed"));
        }
    };
    try zeroAllocGate(Scenario, .{
        .seed = 57,
        .origin_response = response,
        .origin_closes = true,
    });
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

test "l7: a line reports the named headers from both directions (#140)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 46,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Cache: HIT\r\n\r\nhi",
        .access_log = true,
        .access_log_request_headers = &.{ "x-request-id", "user-agent" },
        .access_log_response_headers = &.{"x-cache"},
    });
    defer bed.tearDown();

    // The request carries the correlation header but no User-Agent: the
    // join exists with nothing added to the wire, and the header that
    // did not arrive is simply absent from the line.
    try bed.exchange("GET /path HTTP/1.1\r\nHost: o\r\nX-Request-Id: abc-123\r\n" ++
        "Connection: close\r\n\r\n");
    try bed.expectDrained();

    const line = try onlyAccessLogLine(&bed);
    try std.testing.expect(
        std.mem.indexOf(u8, line, "\"request_headers\":{\"x-request-id\":\"abc-123\"}") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, line, "\"response_headers\":{\"x-cache\":\"HIT\"}") != null,
    );
    // Matched case-insensitively (the request wrote `X-Request-Id`) and
    // logged under the one spelling the config resolved to.
    try std.testing.expect(std.mem.indexOf(u8, line, "user-agent") == null);
}

test "l7: a keep-alive turnaround does not carry the last request's headers (#140)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 47,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .access_log = true,
        .access_log_request_headers = &.{"x-request-id"},
    });
    defer bed.tearDown();

    // The first request names an ID, the second does not. The capture
    // lives in a side table the turnaround has to clear, so a stale
    // value would show up as the second line reporting the first's ID —
    // the worst possible failure for a correlation field.
    bed.client.second_request = "GET /two HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\nX-Request-Id: first\r\n\r\n");
    try bed.expectDrained();

    const first = try accessLogLineFor(&bed, "\"path\":\"/one\"");
    const second = try accessLogLineFor(&bed, "\"path\":\"/two\"");
    try std.testing.expect(
        std.mem.indexOf(u8, first, "\"request_headers\":{\"x-request-id\":\"first\"}") != null,
    );
    try std.testing.expect(std.mem.indexOf(u8, second, "\"request_headers\":{}") != null);
    try std.testing.expect(std.mem.indexOf(u8, second, "first") == null);
}

test "l7: a rejected request still reports its named headers (#140)" {
    // The correlation header earns its keep exactly when something went
    // wrong, so a line that reports a verdict must carry it too — which
    // is why the capture sits with the other request facts, ahead of
    // every rung, rather than on the path that reaches an origin.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 48,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .route_prefix = "/api",
        .access_log = true,
        .access_log_request_headers = &.{"x-request-id"},
    });
    defer bed.tearDown();

    try bed.exchange("GET /nope HTTP/1.1\r\nHost: o\r\nX-Request-Id: traced\r\n" ++
        "Connection: close\r\n\r\n");
    try bed.expectDrained();

    const line = try onlyAccessLogLine(&bed);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"outcome\":\"rejected\"") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, line, "\"request_headers\":{\"x-request-id\":\"traced\"}") != null,
    );
    // No response reached this request, so its response object is the
    // empty one the config asked for — never the previous exchange's.
    try std.testing.expect(std.mem.indexOf(u8, line, "response_headers") == null);
}

test "l7: a reused conn slot reports no previous connection's headers (#140)" {
    // The capture table is addressed by pool slot, so its bytes outlive
    // the connection that wrote them. This is the shape that makes that
    // dangerous: one connection logs a header, its slot is reused, and
    // the next connection's head never parses — so nothing overwrites
    // the slot and the reject's line would attribute one client's
    // correlation ID to a different client's request.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 50,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .conn_slots = 1,
        .relay_buffers = 1,
        .access_log = true,
        .access_log_request_headers = &.{"x-request-id"},
    });
    defer bed.tearDown();

    // Chained, not concurrent: with one slot the second must arrive
    // after the first released it, or it would be shed rather than
    // reuse the slot. Its head is a bare-LF smuggling shape, so it is
    // rejected 400 before any capture runs and nothing this client sent
    // overwrites what the slot already held.
    bed.client.drain_on_finish = false;
    bed.client2.request = "GET /two HTTP/1.1\nHost: o\r\n\r\n";
    bed.client.next = &bed.client2;
    try bed.exchange("GET /one HTTP/1.1\r\nHost: o\r\nX-Request-Id: leaked\r\n" ++
        "Connection: close\r\n\r\n");
    try bed.expectDrained();

    const rejected = try accessLogLineFor(&bed, "\"outcome\":\"rejected\"");
    try std.testing.expect(std.mem.indexOf(u8, rejected, "leaked") == null);
    try std.testing.expect(std.mem.indexOf(u8, rejected, "\"request_headers\":{}") != null);
    // The first connection's own line still carries what it sent, so
    // the fix is a clear-on-acquire and not a disabled feature.
    const served = try accessLogLineFor(&bed, "\"path\":\"/one\"");
    try std.testing.expect(
        std.mem.indexOf(u8, served, "\"request_headers\":{\"x-request-id\":\"leaked\"}") != null,
    );
}

test "l7: an oversize header value is truncated, not dropped (#140)" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 49,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        .access_log = true,
        .access_log_request_headers = &.{"x-request-id"},
    });
    defer bed.tearDown();

    var request_buffer: [2048]u8 = undefined;
    var value_buffer: [constants.access_log_header_bytes_max + 64]u8 = undefined;
    @memset(&value_buffer, 'v');
    const request = std.fmt.bufPrint(
        &request_buffer,
        "GET / HTTP/1.1\r\nHost: o\r\nX-Request-Id: {s}\r\nConnection: close\r\n\r\n",
        .{value_buffer},
    ) catch unreachable;
    try bed.exchange(request);
    try bed.expectDrained();

    // The prefix identifies the value, and the ellipsis says the rest
    // was there — `path`'s rule, one field over.
    const line = try onlyAccessLogLine(&bed);
    const marker = "\"x-request-id\":\"";
    const start = std.mem.indexOf(u8, line, marker).? + marker.len;
    const end = std.mem.indexOfScalarPos(u8, line, start, '"').?;
    try std.testing.expectEqual(
        @as(usize, constants.access_log_header_bytes_max),
        end - start,
    );
    try std.testing.expect(std.mem.endsWith(u8, line[start..end], "..."));
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

/// The `X-Forwarded-For` line the origin received, or null when none
/// reached it. Reads the forwarded head the origin actually parsed, so a
/// header suppressed by the render is genuinely absent rather than merely
/// unasserted.
fn forwardedForSeenByOrigin(bed: *const Http1Bed) !?[]const u8 {
    try std.testing.expect(bed.origin.conns[0].request_complete);
    var storage: parser.HeaderStorage = undefined;
    const head = try forwardedRequest(bed, &storage);
    var seen: ?[]const u8 = null;
    for (head.headers) |header| {
        if (header.tag != .x_forwarded_for) continue;
        // Exactly one must reach the origin: a second would let the
        // backend pick whichever it read first and disagree with the
        // next hop about who the client is.
        try std.testing.expect(seen == null);
        seen = header.value;
    }
    return seen;
}

test "l7: forwarded replace states the observed peer and discards a forged chain" {
    // The edge case, in both senses. An inbound chain is client-controlled
    // here, so honoring any part of it would let the caller choose the
    // address every downstream allowlist and audit log then believes.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 40,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        .forwarded = .replace,
    });
    defer bed.tearDown();

    try bed.exchange(
        "GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1.2.3.4, 9.9.9.9\r\n" ++
            "Connection: close\r\n\r\n",
    );
    try bed.expectDrained();

    // SimIo hands each virtual client a distinct address from the
    // TEST-NET-2 block; the port is deliberately absent from the value.
    const seen = (try forwardedForSeenByOrigin(&bed)).?;
    try std.testing.expectEqualStrings("198.51.100.1", seen);
}

test "l7: forwarded append extends the inbound chain in order" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 41,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        .forwarded = .append,
    });
    defer bed.tearDown();

    try bed.exchange(
        "GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1.2.3.4, 9.9.9.9\r\n" ++
            "Connection: close\r\n\r\n",
    );
    try bed.expectDrained();

    const seen = (try forwardedForSeenByOrigin(&bed)).?;
    try std.testing.expectEqualStrings("1.2.3.4, 9.9.9.9, 198.51.100.1", seen);
}

test "l7: repeated inbound X-Forwarded-For headers join in order" {
    // RFC 9110 makes repeated field lines equivalent to one comma-joined
    // value. Carrying only the first would silently drop hops, and the
    // origin would read a chain that is short by however many it lost.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 42,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        .forwarded = .append,
    });
    defer bed.tearDown();

    try bed.exchange(
        "GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1.1.1.1\r\n" ++
            "X-Forwarded-For: 2.2.2.2\r\nConnection: close\r\n\r\n",
    );
    try bed.expectDrained();

    const seen = (try forwardedForSeenByOrigin(&bed)).?;
    try std.testing.expectEqualStrings("1.1.1.1, 2.2.2.2, 198.51.100.1", seen);
}

test "l7: an oversize inbound chain fails safe to the observed peer, and is counted" {
    // A chain is client-supplied and the protocol bounds it nowhere, so it
    // is a place a caller could otherwise decide how much of this proxy's
    // head buffer their request occupies. Past the bound the chain is
    // dropped whole rather than truncated: a truncated chain looks
    // complete to the origin and is not, which is worse than saying less.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 43,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        .forwarded = .append,
        .inbox_bytes = constants.head_buffer_bytes_default,
    });
    defer bed.tearDown();

    // One address repeated past `forwarded_chain_bytes_max`.
    const hop = "10.0.0.1, ";
    const hops = @divFloor(constants.forwarded_chain_bytes_max, hop.len) + 2;
    var request: [constants.head_buffer_bytes_default]u8 = undefined;
    var writer = std.Io.Writer.fixed(&request);
    try writer.writeAll("GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: ");
    for (0..hops) |_| try writer.writeAll(hop);
    try writer.writeAll("10.0.0.2\r\nConnection: close\r\n\r\n");
    try bed.exchange(writer.buffered());
    try bed.expectDrained();

    const seen = (try forwardedForSeenByOrigin(&bed)).?;
    try std.testing.expectEqualStrings("198.51.100.1", seen);
    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("forwarded_chain_dropped"),
    );
}

test "l7: without a forwarded block the header travels untouched" {
    // The default must stay bit-for-bit what it was before this existed:
    // zoxy neither adds nor strips, and a client-supplied value reaches
    // the origin exactly as sent — including a forged one, which is the
    // operator's call to make by configuring a mode.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 44,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    });
    defer bed.tearDown();

    try bed.exchange(
        "GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1.2.3.4\r\n" ++
            "Connection: close\r\n\r\n",
    );
    try bed.expectDrained();

    const seen = (try forwardedForSeenByOrigin(&bed)).?;
    try std.testing.expectEqualStrings("1.2.3.4", seen);
    try std.testing.expectEqual(
        @as(u64, 0),
        bed.server.counters.get("forwarded_chain_dropped"),
    );
}

test "l7: a client that sent no chain gets a line naming only itself" {
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 45,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        .forwarded = .append,
    });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    try bed.expectDrained();

    // No stray separator: `append` with nothing to append must not emit
    // a leading comma the origin would read as an empty first hop.
    const seen = (try forwardedForSeenByOrigin(&bed)).?;
    try std.testing.expectEqualStrings("198.51.100.1", seen);
}

test "l7: a terminated listener proxies an HTTPS request end to end" {
    // The whole L7-over-TLS promise: a real ztls client sends an HTTP
    // request inside a TLS session, an origin that knows nothing about
    // TLS answers it, and the response comes back encrypted. The head is
    // parsed out of decrypted bytes and the response is encrypted on its
    // way out — both directions cross the transform.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 51,
        .tls = true,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    var client: TlsClient = undefined;
    try client.start(&bed.sim_io, Http1Bed.bindAddress(), .{
        .host_name = fixture_host_name,
        .app_data = "GET /x HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n",
    });
    var wind_down: TlsWindDown = .{ .bed = &bed };
    wind_down.attach(&client);
    try bed.sim_io.run();

    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("tls_handshakes_completed"),
    );
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("tls_relay_failed"));
    // The origin saw a plain HTTP request and its answer reached the
    // client through the record layer, byte for byte.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        client.app_received[0..client.app_received_len],
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

/// Winds a TLS scenario down once its client is done: drains the server
/// and stops the origin, so the loop reaches idle instead of sitting on
/// armed accepts. The plaintext `HttpClient` does this itself; the TLS
/// client is not one of them.
const TlsWindDown = struct {
    bed: *Http1Bed,

    fn onEnd(context: ?*anyopaque) void {
        const self: *TlsWindDown = @ptrCast(@alignCast(context.?));
        self.bed.server.beginDrain();
        self.bed.origin.stopListening();
    }

    /// Attach after `start`: no callback can run before the loop does.
    fn attach(self: *TlsWindDown, client: *TlsClient) void {
        client.on_end = onEnd;
        client.on_end_context = self;
    }
};

test "l7: a completed handshake issues its session tickets" {
    // The post-handshake flight, and the reason it exists: the ~45 ms
    // stall (IMPLEMENTATION_NOTES) is a client's second small write held
    // by its own Nagle, waiting for an ACK zoxy has no reason to send.
    // Tickets are what give it one — and they are only worth anything if
    // they go out *after* the client's Finished, which is what makes
    // "issued once the session is up" the assertion rather than "issued".
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 53,
        .tls = true,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    var client: TlsClient = undefined;
    try client.start(&bed.sim_io, Http1Bed.bindAddress(), .{
        .host_name = fixture_host_name,
        .app_data = "GET /x HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n",
    });
    var wind_down: TlsWindDown = .{ .bed = &bed };
    wind_down.attach(&client);
    try bed.sim_io.run();

    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("tls_handshakes_completed"),
    );
    try std.testing.expectEqual(
        @as(u64, constants.tls_tickets_per_handshake),
        bed.server.counters.get("tls_tickets_issued"),
    );
    // Nothing resumed: this client offered no ticket, so a count here
    // would mean the counter fires on something other than resumption.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("tls_resumed"));
    // And the flight cost the exchange nothing — the request still got
    // its answer, which is what says the tickets went out *around* the
    // hand-over rather than in place of it.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        client.app_received[0..client.app_received_len],
    );
    try bed.expectDrained();
}

/// Starts a second, resuming connection when the first one ends, and
/// winds the scenario down when *that* one does. Two connections have to
/// share a loop run — see the test — and this is the seam that lets the
/// second begin only once the first has a ticket to hand it.
const TlsResumeAfter = struct {
    bed: *Http1Bed,
    first: *TlsClient,
    second: *TlsClient,
    wind_down: *TlsWindDown,

    const request = "GET /x HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";

    fn onFirstEnd(context: ?*anyopaque) void {
        const self: *TlsResumeAfter = @ptrCast(@alignCast(context.?));
        self.second.start(&self.bed.sim_io, Http1Bed.bindAddress(), .{
            .host_name = fixture_host_name,
            .app_data = request,
            // Different seeds: a resumed handshake still runs its own
            // ephemeral key exchange (psk_dhe_ke), so reusing the first
            // session's would prove less than it appears to.
            .x25519_seed = @splat(0x71),
            .p256_seed = @splat(0x72),
            .random = @splat(0x73),
            .resume_with = &self.first.ticket,
        }) catch unreachable; // Seeded keypairs; the inputs are ours.
        self.wind_down.attach(self.second);
    }

    fn attach(self: *TlsResumeAfter, client: *TlsClient) void {
        client.on_end = onFirstEnd;
        client.on_end_context = self;
    }
};

test "l7: a ticket issued by one session resumes the next" {
    // The round trip the whole feature is: a ticket zoxy sealed, handed
    // to a client, offered back on a fresh connection, and opened by the
    // key that sealed it. Nothing short of two handshakes proves it —
    // the seal and open are unit-tested against each other, but only
    // this says the ticket survives the wire, the client's storage, and
    // ztls's pre_shared_key extension in between.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 54,
        .tls = true,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    var first: TlsClient = undefined;
    var second: TlsClient = undefined;
    var wind_down: TlsWindDown = .{ .bed = &bed };
    // Both connections in one loop run: the server reaches idle between
    // them with its accepts armed and nothing inbound, which the
    // simulator calls a deadlock — correctly, since from inside the loop
    // it is one. So the second connection is started by the first one
    // ending, the same seam the wind-down uses.
    var resumer: TlsResumeAfter = .{
        .bed = &bed,
        .first = &first,
        .second = &second,
        .wind_down = &wind_down,
    };
    try first.start(&bed.sim_io, Http1Bed.bindAddress(), .{
        .host_name = fixture_host_name,
        .app_data = TlsResumeAfter.request,
    });
    resumer.attach(&first);
    try bed.sim_io.run();

    try std.testing.expect(first.ticket_captured);

    // Two sessions, the second resumed — and the response still correct,
    // because a resumption that broke the stream would be worse than no
    // resumption at all.
    try std.testing.expectEqual(
        @as(u64, 2),
        bed.server.counters.get("tls_handshakes_completed"),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("tls_resumed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("tls_handshake_failed"));
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        second.app_received[0..second.app_received_len],
    );
    try bed.expectDrained();
}

test "l7: close_notify between requests writes no access-log line" {
    // A terminated keep-alive connection ends the way TLS says to: the
    // client answers its last response with a close_notify, and the alert
    // arrives on a connection that is idle between requests.
    //
    // The plaintext path has an EOF here too, and writes nothing for it —
    // an access-log line is a claim that a request was *made*, and nobody
    // made one. Getting this wrong is invisible from inside: the phantom
    // line is well-formed, it is merely about nothing, so it shows up as
    // an `aborted` exchange with no method, no path and no bytes. The
    // arithmetic below is the only thing that sees it.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 52,
        .tls = true,
        .access_log = true,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    var client: TlsClient = undefined;
    try client.start(&bed.sim_io, Http1Bed.bindAddress(), .{
        .host_name = fixture_host_name,
        // No `Connection: close`: the connection has to still be *open*
        // and waiting for a next request when the alert lands, which is
        // the whole state under test.
        .app_data = "GET /x HTTP/1.1\r\nHost: o\r\n\r\n",
        // The alert waits for the response, and what makes one whole is
        // its framing, not its size. The echo rule happens to fire here —
        // this response is longer than its request — but only by accident
        // of these two literals, and the state under test is precisely
        // the connection being idle *after* a complete exchange.
        .exchange_end = .http_response,
        .close_after_echo = true,
    });
    var wind_down: TlsWindDown = .{ .bed = &bed };
    wind_down.attach(&client);
    try bed.sim_io.run();

    // One request was made, so one line is owed — and exactly one.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("access_log_lines"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("access_log_dropped"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("tls_relay_failed"));
    try bed.expectDrained();
}

test "l7: a terminated head that fits with a body that does not is 413, not 431" {
    // The one L7 state only termination can reach. A plaintext read
    // cannot deliver more than the head buffer holds, but one TLS record
    // decrypts up to 16 KiB at once — so a client that sends its head and
    // a large payload in a single record overruns the buffer with bytes
    // that are *body*, not headers.
    //
    // Which answer is honest depends on what those bytes were, so the
    // parser is asked: telling a client its headers are too large when
    // its body is sends it chasing the wrong thing.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 52,
        .tls = true,
        // The floor. Also the case the head limit had to stop conflating
        // with the engine's own: this is *below* the decrypt floor, so a
        // buffer-length capacity would have admitted 32 KiB of head here.
        .head_buffer_bytes = constants.head_buffer_bytes_min,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    // A valid, small head followed by a body that will not fit — one
    // write, so the proxy decrypts both out of the same record.
    const head = "POST /x HTTP/1.1\r\nHost: o\r\nContent-Length: 4000\r\n\r\n";
    var request: [4096]u8 = undefined;
    @memcpy(request[0..head.len], head);
    @memset(request[head.len..], 'a');

    var client: TlsClient = undefined;
    try client.start(&bed.sim_io, Http1Bed.bindAddress(), .{
        .host_name = fixture_host_name,
        .app_data = &request,
    });
    var wind_down: TlsWindDown = .{ .bed = &bed };
    wind_down.attach(&client);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_body_too_large"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_headers_too_large"));
    // The client is told in terms it can act on: 413, decrypted.
    try std.testing.expect(std.mem.startsWith(
        u8,
        client.app_received[0..client.app_received_len],
        "HTTP/1.1 413 Content Too Large\r\n",
    ));
    try bed.expectDrained();
}

test "l7: a terminated listener honours the configured head limit" {
    // What the fix above is really about. The engine's plaintext buffer
    // is wider than the configured head so a record's decrypt always
    // lands; before this, that width *was* the limit, so an operator who
    // set 1 KiB to bound what this proxy accepts silently got 32 KiB.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 53,
        .tls = true,
        .head_buffer_bytes = constants.head_buffer_bytes_min,
    });
    defer bed.tearDown();

    // A header section comfortably over the 1 KiB limit and comfortably
    // under the engine's 32 KiB buffer — the window the bug lived in.
    const filler = "X-Pad: " ++ ("p" ** 2000) ++ "\r\n";
    const request = "GET /x HTTP/1.1\r\nHost: o\r\n" ++ filler ++ "\r\n";

    var client: TlsClient = undefined;
    try client.start(&bed.sim_io, Http1Bed.bindAddress(), .{
        .host_name = fixture_host_name,
        .app_data = request,
    });
    var wind_down: TlsWindDown = .{ .bed = &bed };
    wind_down.attach(&client);
    try bed.sim_io.run();

    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("l7_headers_too_large"),
    );
    try std.testing.expect(std.mem.startsWith(
        u8,
        client.app_received[0..client.app_received_len],
        "HTTP/1.1 431 ",
    ));
    try bed.expectDrained();
}

test "l7: a refused endpoint is retried onto another and the client sees the origin" {
    // #181's motivating case, end to end: one endpoint of a cluster
    // refuses while another is healthy. Without a retry every request
    // the pick sends to the refusing one is a 502, and with health
    // checks off — the default — that lasts forever rather than for a
    // detection window.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 190,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .refusing_endpoint_first = true,
        .retries = 1,
        // Strict rotation puts the refusing endpoint first, so the retry
        // is the only path to the origin rather than a coin flip.
        .pick = .rr,
    });
    defer bed.tearDown();

    try bed.exchange("GET /r HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    // The origin's own answer, not a gateway error: the client cannot
    // tell that its request took two dials, which is the whole point.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u32, 1), bed.origin.requests_served);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_retried"));
    // The recovery must be visible as a recovery. Without the retry
    // counter an operator sees `upstream_connect_failed` climbing while
    // requests succeed, and reads it as an outage.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_bad_gateway"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("upstream_retries_exhausted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try bed.expectDrained();
}

test "l7: a retry runs out of endpoints before its budget and answers 502" {
    // Both endpoints refuse and the budget still has a try left, so it
    // is the *endpoint set* that ends the request, not the count. That
    // is the exhaustion rung, and it answers 502 rather than a shed 503:
    // the origins were reachable enough to say no, which is a different
    // sentence from "all of them are full".
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 191,
        .refusing_endpoint_first = true,
        .origin_listens = false,
        .retries = 2,
        .pick = .rr,
    });
    defer bed.tearDown();

    try bed.exchange("GET /r HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    // Two dials, one retry between them, and no third: the exclusion
    // set emptied the cluster before the budget's second retry was
    // reached, so the request stopped without dialing anything twice.
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_retried"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_retries_exhausted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_endpoint_inflight"));
    try bed.expectDrained();
}

test "l7: our own dial exhaustion is not retried onto another endpoint" {
    // The split that makes the retry safe (#181): a refused or
    // unreachable dial is the *origin's* verdict, while kernel pressure
    // is ours. Another dial would meet the same wall, and §8 says shed
    // rather than spend more of a resource we have already run out of.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 192,
        .refusing_endpoint_first = true,
        .retries = 2,
        .pick = .rr,
    });
    defer bed.tearDown();

    bed.sim_io.setPressureCause(.address_unavailable);
    bed.sim_io.injectConnectError(Http1Bed.refusingEndpointAddress());

    try bed.exchange("GET /r HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    // The healthy origin sat there untried, and that is correct: the
    // dial never reached the network to have an opinion about it.
    try std.testing.expectEqual(@as(u32, 0), bed.origin.requests_served);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_connect"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("upstream_retried"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
    try bed.expectDrained();
}

test "l7: a dial that times out does not retry, because it spent the budget" {
    // The retry chain carries one connect deadline rather than arming a
    // fresh one per try, so the worst-case dial wait stays `connect_ms`
    // however many endpoints a request walks. A timed-out dial has
    // therefore already spent the budget a retry would run under, and
    // the §8 answer is the 504 the deadline decided — not a second dial
    // the client would wait through all over again.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 193,
        .refusing_endpoint_first = true,
        .retries = 2,
        .pick = .rr,
    });
    defer bed.tearDown();

    bed.sim_io.blackholeAddress(Http1Bed.refusingEndpointAddress());

    const start_ns = bed.sim_io.nowNs();
    try bed.exchange("GET /r HTTP/1.1\r\nHost: o\r\n\r\n");
    const elapsed_ms = (bed.sim_io.nowNs() - start_ns) / std.time.ns_per_ms;

    try std.testing.expectEqual(HttpClient.Outcome.fin, bed.client.outcome);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    // One budget, not one per endpoint: three tries at a fresh deadline
    // each would have kept the client waiting three times as long.
    try std.testing.expect(elapsed_ms < 2 * Http1Bed.connect_timeout_ms);
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("upstream_retried"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_gateway_timeout"));
    try bed.expectDrained();
}

test "l7: an allowed upgrade becomes a tunnel and relays both ways" {
    // #180 end to end: the handshake reaches the origin, its 101 reaches
    // the client, and the connection then carries opaque bytes in both
    // directions — the L4 relay of §6 entered from an L7 exchange.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 200,
        .origin_response = "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        .upgrades = .{ .websocket = true },
        .tunnels = 2,
    });
    defer bed.tearDown();

    try bed.exchange("GET /ws HTTP/1.1\r\nHost: o\r\n" ++
        "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");

    // The client sees the origin's own 101, with the participating pair
    // intact: stripping either would leave it told it succeeded without
    // being told to what.
    try std.testing.expect(std.mem.startsWith(
        u8,
        bed.client.response(),
        "HTTP/1.1 101 Switching Protocols\r\n",
    ));
    try std.testing.expect(std.mem.indexOf(u8, bed.client.response(), "Upgrade: websocket") != null);
    try std.testing.expect(std.mem.indexOf(u8, bed.client.response(), "Connection: upgrade") != null);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("tunnels_established"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_tunnels"));
    try bed.expectDrained();
}

test "l7: an upgrade this listener does not allow keeps its 501" {
    // The default, and what every config predating #180 keeps getting.
    // Refused here rather than at an origin that never saw a handshake.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 201,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    try bed.exchange("GET /ws HTTP/1.1\r\nHost: o\r\n" ++
        "Connection: Upgrade\r\nUpgrade: websocket\r\nConnection: close\r\n\r\n");

    try std.testing.expect(std.mem.startsWith(
        u8,
        bed.client.response(),
        "HTTP/1.1 501 Not Implemented\r\n",
    ));
    // No origin was contacted: the refusal is this proxy's own.
    try std.testing.expectEqual(@as(u32, 0), bed.origin.requests_served);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_not_implemented"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("tunnels_established"));
    try bed.expectDrained();
}

test "l7: a token the allowlist does not name is refused by name" {
    // `h2c` is the sharp case: tunnelling it would carry HTTP/2 to an
    // origin this proxy cannot parse, past every rule the config
    // expresses — and after 101 no rule of ours applies to another byte.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 202,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .upgrades = .{ .websocket = true },
        .tunnels = 2,
    });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\n" ++
        "Connection: Upgrade\r\nUpgrade: h2c\r\nConnection: close\r\n\r\n");

    try std.testing.expect(std.mem.startsWith(
        u8,
        bed.client.response(),
        "HTTP/1.1 501 Not Implemented\r\n",
    ));
    try std.testing.expectEqual(@as(u32, 0), bed.origin.requests_served);
    // The pool is untouched: a token refused at the gate claims nothing.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_tunnels"));
    try bed.expectDrained();
}

test "l7: an upgrade with no tunnel capacity is shed before the handshake" {
    // The §8 rung, and the ordering is the rung: refused up front, so no
    // origin connection is spent to produce a worse answer later.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 203,
        .origin_response = "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        .upgrades = .{ .websocket = true },
        .tunnels = 1,
    });
    defer bed.tearDown();

    // The first upgrade takes the only tunnel and holds it for the rest
    // of the run; the second arrives once it is held and finds the pool
    // empty, which is the whole point — a tunnel does not give its buffer
    // back at the end of an exchange, because it has no end of exchange.
    bed.client.drain_on_finish = false;
    bed.client2.send_delay_ms = 100;
    bed.client2.request = "GET /ws HTTP/1.1\r\nHost: o\r\n" ++
        "Connection: Upgrade\r\nUpgrade: websocket\r\nConnection: close\r\n\r\n";
    bed.client2.start(&bed.sim_io, &bed.server, Http1Bed.bindAddress());
    try bed.exchange("GET /ws HTTP/1.1\r\nHost: o\r\n" ++
        "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("tunnels_established"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_shed_tunnels"));
    try std.testing.expect(std.mem.startsWith(
        u8,
        bed.client2.response(),
        "HTTP/1.1 503 Service Unavailable\r\n",
    ));
}

test "l7: an origin that declines an upgrade gives the tunnel back" {
    // Answering an `Upgrade` with an ordinary response is legal and
    // common — an origin that does not speak WebSocket just serves the
    // request. The claim taken at the gate has to come back at that
    // moment, not at teardown: this connection is kept, and a claim left
    // held would pin a pool slot nothing is using for as long as the
    // client stays. `tunnels: 1` is what makes the leak visible — the
    // second upgrade can only be served if the first gave its slot back.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 204,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .upgrades = .{ .websocket = true },
        .tunnels = 1,
    });
    defer bed.tearDown();

    bed.client.second_request = "GET /ws HTTP/1.1\r\nHost: o\r\n" ++
        "Connection: Upgrade\r\nUpgrade: websocket\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /ws HTTP/1.1\r\nHost: o\r\n" ++
        "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");

    // Both requests were served by the origin, and neither was shed: the
    // second proves the first released its claim, since one tunnel is all
    // the pool has. A leak here would answer the second with a 503.
    try std.testing.expectEqual(@as(u32, 2), bed.origin.requests_served);
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_shed_tunnels"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("tunnels_established"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("l7_responses"));
    try bed.expectDrained();
}

test "l7: a drain with no deadline still ends, because tunnels are cut" {
    // The trap #180 had to answer (§8). `drain_deadline_ms: 0` means
    // "wait for the last connection", and a tunnel has no message
    // boundary to be the last thing it does — so without this bound one
    // idle session holds the process open until the supervisor's SIGKILL,
    // turning a millisecond drain into every rolling restart waiting out
    // TimeoutStopSec. Not an invariant breach, which is why it needed
    // stating: a zero deadline always said the supervisor owns the upper
    // bound, and it still does for every other connection.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 205,
        .origin_response = "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        .upgrades = .{ .websocket = true },
        .tunnels = 1,
        .drain_deadline_ms = 0,
    });
    defer bed.tearDown();

    // The tunnel is established and then simply sits there, exactly as an
    // idle WebSocket does; the drain arrives with it live.
    bed.client.drain_on_finish = false;
    bed.armDrainTimer(50);
    try bed.exchange("GET /ws HTTP/1.1\r\nHost: o\r\n" ++
        "Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("tunnels_established"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("tunnels_drained"));
    // The line the drain's own counter cannot say: the loop actually
    // stopped, with every pool given back (§9's leak invariant).
    try std.testing.expect(bed.server.isIdle());
    try bed.expectDrained();
}

test "l7: a 100 Continue reaches the client and the exchange goes on" {
    // The `curl -d @file` case (#232). curl sends `Expect: 100-continue`
    // for any body over 1 KiB and nginx honours it, so before this the
    // client got `100 Continue` followed by a close — the body had not
    // been pumped, so nothing could park and nothing could keep.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 300,
        .origin_response = "HTTP/1.1 100 Continue\r\n\r\n" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    try bed.exchange("POST /upload HTTP/1.1\r\nHost: o\r\n" ++
        "Expect: 100-continue\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody");

    // Both, in order: the interim the client was waiting for, then the
    // answer. An interim is relayed rather than absorbed because a `100`
    // a client never sees is the whole point of `Expect` withheld.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 100 Continue\r\n\r\n" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_interim_forwarded"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_interim_overrun"));
    try bed.expectDrained();
}

test "l7: a 103 does not settle the exchange, so no answer is left unread" {
    // The sharper half of #232. With the body already sent,
    // `request_leg == .done` and the origin's keep-alive verdict is
    // honoured — so the interim was rendered as the answer and the
    // upstream parked with the *real* response still unread in its
    // socket. The next checkout would read it as its own: one client's
    // answer delivered to another.
    //
    // Two requests over one connection is what makes that visible. If
    // the 103 settled the first exchange, the second would be served the
    // first's leftover `200` — here both must get their own.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 301,
        .origin_response = "HTTP/1.1 103 Early Hints\r\n" ++
            "Link: </s.css>; rel=preload\r\n\r\n" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    });
    defer bed.tearDown();

    bed.client.second_request = "GET /second HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /first HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqualStrings(
        "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" ++
            "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    // Two exchanges, two answers, two interims — and the origin served
    // both requests rather than one of them reading the other's reply.
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("l7_responses"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("l7_interim_forwarded"));
    try std.testing.expectEqual(@as(u32, 2), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: an origin that only ever sends interims is cut at the bound" {
    // Neither nginx nor HAProxy bounds this; zoxy must, because an
    // unbounded loop on the one thread is what §1 rules out (#232). The
    // overrun is counted apart from a malformed head: nothing was
    // malformed, the bound is what ran out.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 302,
        .origin_response = "HTTP/1.1 103 Early Hints\r\n\r\n" ** 12,
    });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(
        @as(u64, constants.interim_responses_max),
        bed.server.counters.get("l7_interim_forwarded"),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_interim_overrun"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_bad_gateway"));
    try bed.expectDrained();
}

test "l7: a 101 nobody asked for fails the exchange" {
    // `101` is a protocol switch, not a continuation, so it cannot be
    // relayed as interim — carrying on to read the next head would meet
    // bytes that are no longer HTTP. An origin sending one to a request
    // that carried no `Upgrade` is doing something it was not invited to
    // (#232, #180).
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 303,
        .origin_response = "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    });
    defer bed.tearDown();

    try bed.exchange("GET / HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqualStrings(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_interim_forwarded"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("tunnels_established"));
    try bed.expectDrained();
}

test "l7: an interim spends the free replay — the origin already spoke" {
    // The §7 replay is for a *stale* checkout: a parked connection the
    // origin closed while nobody was looking, where nothing reached an
    // application. An interim proves the opposite — the origin answered,
    // and this proxy already relayed that answer to the client (#232).
    //
    // `replayEligible`'s "a response byte arrived" test reads
    // `upstream.head_len`, which `forwardInterim` compacts back to zero,
    // so without an explicit check the guard is blind exactly here and
    // the request would be re-sent to a second origin after the first had
    // begun processing it.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 304,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        // The first request parks a reusable upstream; the second checks
        // it out, gets an interim, and loses the origin on it.
        .origin_interim_then_close_after_served = 1,
    });
    defer bed.tearDown();

    bed.client.next = &bed.client2;
    bed.client2.request = "GET /b HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n";
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    // The reuse happened and the interim reached the second client —
    // and then the exchange failed honestly instead of being replayed.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_reused"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_interim_forwarded"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("upstream_replayed"));
    // One origin connection per client: the request was never sent twice.
    try std.testing.expectEqual(@as(u32, 1), bed.origin.accepted_count);
    try bed.expectDrained();
}

test "l7: a partial head is reaped at the head budget, not the idle window" {
    // #235's whole point. One number used to serve both, and the one an
    // operator tunes is the keep-alive window — its cost is the visible
    // one — so the slowloris budget silently inherited it. Here the two
    // are an order of magnitude apart, and the connection that goes quiet
    // *mid-head* must meet the tighter of them.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 310,
        .head_timeout_ms = 100,
    });
    defer bed.tearDown();

    // A head that never finishes: the client sends a request line and a
    // header, then nothing — no blank line, so the parse never completes.
    const start_ns = bed.sim_io.nowNs();
    try bed.exchange("GET /slow HTTP/1.1\r\nHost: o\r\n");
    const elapsed_ms = (bed.sim_io.nowNs() - start_ns) / std.time.ns_per_ms;

    // Reaped on the head budget. The idle window is 1000 ms, so anything
    // near it would mean the split is not in force — which is exactly the
    // state this fix found.
    try std.testing.expect(elapsed_ms >= 100);
    try std.testing.expect(elapsed_ms < 500);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try bed.expectDrained();
}

test "l7: an idle kept connection still gets the whole idle window" {
    // The other half of the split, and the reason it is a split rather
    // than a tightening: between requests a connection is quiet and
    // healthy, and short values there churn the population into
    // reconnects. The head budget must not reach it.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 311,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .head_timeout_ms = 100,
    });
    defer bed.tearDown();

    // One exchange, then the client holds the connection open saying
    // nothing. The turnaround stores the idle window, and no head byte
    // has arrived to replace it with the tighter budget.
    const start_ns = bed.sim_io.nowNs();
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\n\r\n");
    const elapsed_ms = (bed.sim_io.nowNs() - start_ns) / std.time.ns_per_ms;

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    // Past the head budget by a wide margin, and bounded above by the
    // idle window it should actually meet: an idle connection is not a
    // slowloris, and treating it as one is the churn the split avoids.
    try std.testing.expect(elapsed_ms > 500);
    try std.testing.expect(elapsed_ms < 2000);
    try bed.expectDrained();
}

test "l7: a declared body over the cap is refused before the origin is dialed" {
    // #236. The length is in the head, so the verdict is knowable before
    // anything is spent on it — the §8 tunnel rung's own reasoning, that
    // admitting first and shedding after would spend an origin connection
    // to produce a worse answer.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 320,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .max_body_bytes = 8,
    });
    defer bed.tearDown();

    try bed.exchange("POST /upload HTTP/1.1\r\nHost: o\r\n" ++
        "Content-Length: 64\r\n\r\n" ++ ("x" ** 64));

    try std.testing.expectEqualStrings(
        "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bed.client.response(),
    );
    // No origin was contacted: the refusal is this proxy's own, decided
    // from the head alone.
    try std.testing.expectEqual(@as(u32, 0), bed.origin.requests_served);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_body_over_limit"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_body_cut_mid_stream"));
    try bed.expectDrained();
}

test "l7: a chunked body cannot slip past the cap by announcing no size" {
    // The half that decides whether the cap is protection or theatre: a
    // client that does not want to declare its length simply does not,
    // and any HTTP client can choose chunked. Caught on the scanner's own
    // payload total as it streams — by which point the response leg is
    // armed, so it is a teardown rather than a status (#236).
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 321,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .max_body_bytes = 8,
    });
    defer bed.tearDown();

    // Two 16-byte chunks: the first already passes the 8-byte cap.
    try bed.exchange("POST /upload HTTP/1.1\r\nHost: o\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "10\r\n" ++ ("x" ** 16) ++ "\r\n" ++
        "10\r\n" ++ ("y" ** 16) ++ "\r\n0\r\n\r\n");

    // Coalesced with its head, so the cap is met before the response leg
    // is armed and the client still earns a status. A body large enough
    // to stream takes the teardown instead — same rung, later verdict.
    try std.testing.expect(std.mem.startsWith(
        u8,
        bed.client.response(),
        "HTTP/1.1 413 Content Too Large\r\n",
    ));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_body_over_limit"));
    // Counted apart from a framing violation: the body was well-formed,
    // it was simply larger than this listener carries.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_bad_request"));
    try bed.expectDrained();
}

test "l7: a body under the cap, and an opted-out listener, are untouched" {
    // The cap must not reach an ordinary request, and `0` must genuinely
    // opt out — a listener fronting an upload endpoint wants its origin's
    // own limit to be the only one.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 322,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .max_body_bytes = 0,
    });
    defer bed.tearDown();

    try bed.exchange("POST /upload HTTP/1.1\r\nHost: o\r\n" ++
        "Content-Length: 64\r\nConnection: close\r\n\r\n" ++ ("x" ** 64));

    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_body_over_limit"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_body_cut_mid_stream"));
    try bed.expectDrained();
}

test "l7: a chunked body that outgrows the cap while streaming is cut" {
    // The streaming half of #236, and the one the coalesced test above
    // does *not* reach: a body small enough to arrive with its head is
    // measured before the response leg is armed, so it earns a status. A
    // body larger than the head buffer cannot be — by the time the
    // overrun is visible the response recv is armed, no status can be
    // sent (§7), and the only honest end is a teardown.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 323,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        // Above what arrives coalesced with the head, below the body.
        .max_body_bytes = 10_000,
    });
    defer bed.tearDown();

    // One 24 KiB chunk: far past the 8 KiB head buffer, so most of it
    // reaches the body pump rather than riding in with the head.
    try bed.exchange("POST /upload HTTP/1.1\r\nHost: o\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "6000\r\n" ++ ("z" ** 24576) ++ "\r\n0\r\n\r\n");

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_body_cut_mid_stream"));
    // Not the answered rung, and not a framing verdict: the body was
    // well-formed and simply outgrew what this listener carries.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_body_over_limit"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l7_bad_request"));
    try bed.expectDrained();
}

test "l7: the request cap announces its close on the last response it serves" {
    // #237. The cap has to bite where the response's persistence is
    // decided, not at the turnaround: §8's rule is that a close is
    // announced rather than silent, so the last request a connection
    // serves must be the one carrying the header that says so. A client
    // that read a reset where a status was due reports an error it cannot
    // attribute.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 330,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .keepalive_requests = 1,
    });
    defer bed.tearDown();

    // The client asks to keep the connection; the cap says this is the
    // one and only request it gets.
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("l7_keepalive_requests_capped"),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try bed.expectDrained();
}

test "l7: a connection under the cap keeps serving, and 0 is unlimited" {
    // Two requests over one connection with the cap at 2: the first must
    // keep, and the counter must stay still — a cap that fired early
    // would churn the population it exists to bound.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 331,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .keepalive_requests = 2,
    });
    defer bed.tearDown();

    bed.client.second_request = "GET /b HTTP/1.1\r\nHost: o\r\n\r\n";
    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\n\r\n");

    // First keeps, second is capped and says so.
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        bed.client.response(),
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("l7_keepalive_requests_capped"),
    );
    try std.testing.expectEqual(@as(u32, 2), bed.origin.requests_served);
    try bed.expectDrained();
}

test "l7: a client that asked to close is not counted against the cap" {
    // The counter must name the cap's own effect. A connection already
    // closing — because the client asked, or pressure or a drain decided
    // — did not need this rung, and counting it would read as churn the
    // cap caused.
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 332,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .keepalive_requests = 1,
    });
    defer bed.tearDown();

    try bed.exchange("GET /a HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n");

    try std.testing.expectEqual(
        @as(u64, 0),
        bed.server.counters.get("l7_keepalive_requests_capped"),
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l7_responses"));
    try bed.expectDrained();
}

test "l7: the request cap binds a statically-answered connection too" {
    // The hole review found: the cap first landed only on the proxied
    // response path, so a client whose every request met a filter reject,
    // a 404 or a redirect kept its conn slot indefinitely — the exact
    // population the cap exists to bound, relocated rather than fixed.
    // A static answer holds a slot exactly as firmly as a proxied one.
    const rules = [_]filter.Rule{.{
        .match = .{ .path_prefix = "/admin" },
        .actions = &[_]filter.Action{.{ .reject = 403 }},
    }};
    var bed: Http1Bed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .seed = 333,
        .origin_response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .request_filters = &rules,
        .keepalive_requests = 1,
    });
    defer bed.tearDown();

    // A rejected request never reaches an origin, so nothing on the
    // proxied path could have applied the cap to it.
    try bed.exchange("GET /admin HTTP/1.1\r\nHost: o\r\n\r\n");

    try std.testing.expect(std.mem.startsWith(
        u8,
        bed.client.response(),
        "HTTP/1.1 403 Forbidden\r\n",
    ));
    // Announced, not silent: the client is told this connection is done.
    try std.testing.expect(std.mem.indexOf(
        u8,
        bed.client.response(),
        "Connection: close",
    ) != null);
    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("l7_keepalive_requests_capped"),
    );
    try std.testing.expectEqual(@as(u32, 0), bed.origin.requests_served);
    try bed.expectDrained();
}
