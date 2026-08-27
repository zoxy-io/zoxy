//! Directed Server scenarios over SimIo (§9). With the relay in place
//! (slice 8) these prove the actual L4 promise: a client's bytes reach
//! the origin and the echo comes back byte-exact through the proxy,
//! under 1-byte partial deliveries and adversarial ordering; FINs relay
//! in both directions; idle connections meet the deadline; every §8
//! exhaustion rung is witnessed by its counter and by what the shed
//! client observes on the wire (RST vs FIN); and counters reconcile
//! with pools drained after every scenario.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const io_module = @import("io/io.zig");
const Credentials = @import("tls/Credentials.zig");
const router = @import("http/router.zig");
const sni_router = @import("net/sni_router.zig");
const Io = @import("io/io.zig");
const Server = @import("Server.zig").Server;
const SimIo = @import("io/SimIo.zig");
const origin_mod = @import("testing/origin.zig");
const TlsEngine = @import("tls/Engine.zig");
const upstream_module = @import("net/upstream.zig");

const assert = std.debug.assert;

const ServerSim = Server(SimIo);
const Origin = origin_mod.Origin(SimIo);

// The throwaway self-signed fixtures (`tls/testdata/README.md`), embedded
// rather than read: this file runs under the Io seam, where a filesystem
// is exactly what does not exist.
const fixture_cert_pem = @embedFile("tls/testdata/cert.pem");
const fixture_key_pem = @embedFile("tls/testdata/key.pem");
/// The fixture certificate's SAN. A client that offered any other name
/// would fail verification for a reason unrelated to what is under test.
const fixture_host_name = "spike.zoxy.test";
const TlsClient = @import("tls/TestClient.zig").TestClient(SimIo);

/// Winds a TLS scenario down once every client is done: drains the
/// server and stops the origin listening, so the loop can reach idle
/// instead of sitting on armed accepts forever. `Scenario` does the same
/// job for the plaintext clients; the TLS client carries its own hook
/// because it is not one of them.
const TlsWindDown = struct {
    bed: *TestBed,
    expected: u8,
    ended: u8 = 0,

    fn onEnd(context: ?*anyopaque) void {
        const self: *TlsWindDown = @ptrCast(@alignCast(context.?));
        self.ended += 1;
        assert(self.ended <= self.expected);
        if (self.ended < self.expected) return;
        self.bed.server.beginDrain();
        self.bed.scenario.origin.stopListening();
    }

    /// Attach after `start`: no callback can run before the loop does, so
    /// the hook is in place well ahead of the first completion.
    fn attach(self: *TlsWindDown, client: *TlsClient) void {
        client.on_end = onEnd;
        client.on_end_context = self;
    }
};

const echo_token = "proxied-echo-token-0123456789abc";

pub const Scenario = struct {
    io: *SimIo,
    server: *ServerSim,
    origin: Origin,
    clients: [4]Client,
    clients_count: u8,
    ended_count: u8 = 0,
    /// A client to start from the origin's first accept (the drain-race
    /// test); the shared Origin fires on_accept on every accept, so the
    /// hook makes this one-shot.
    pending_racer: ?*Client = null,
    /// The §7 L4 charge against endpoint 0 sampled the moment the origin
    /// accepted, so a test can prove the count *rises* — "it drained to
    /// zero" is satisfied just as well by never counting at all.
    l4_sample: u16 = 0,

    fn sampleL4Charge(context: ?*anyopaque) void {
        const scenario: *Scenario = @ptrCast(@alignCast(context.?));
        scenario.l4_sample = scenario.server.l4_inflight[scenario.server.upstreams.keys.key(0, 0)];
    }

    fn clientEnded(scenario: *Scenario) void {
        scenario.ended_count += 1;
        assert(scenario.ended_count <= scenario.clients_count);
        if (scenario.ended_count == scenario.clients_count) {
            scenario.server.beginDrain();
            scenario.origin.stopListening();
        }
    }

    fn outcomeCount(scenario: *const Scenario, outcome: Client.Outcome) u8 {
        var count: u8 = 0;
        for (scenario.clients[0..scenario.clients_count]) |*client| {
            if (client.outcome == outcome) count += 1;
        }
        return count;
    }

    fn startPendingRacer(context: ?*anyopaque) void {
        const scenario: *Scenario = @ptrCast(@alignCast(context.?));
        if (scenario.pending_racer) |racer| {
            scenario.pending_racer = null;
            racer.start(scenario, TestBed.bindAddress());
        }
    }
};

/// A scripted client. In `exchange` mode it sends the token, expects the
/// byte-exact echo, FINs, and waits for the proxied FIN back; otherwise
/// it connects and stays silent (idle-deadline fodder).
pub const Client = struct {
    scenario: *Scenario = undefined,
    connect_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    receive_buffer: [64]u8 = undefined,
    socket: SimIo.Socket = undefined,
    exchange: bool = false,
    /// Begin the server drain from inside this client's own connect
    /// delivery — at that instant its socket is queued and the accept is
    /// armed, so the accept "CQE" has already beaten the listener close:
    /// the §8 drain race, made deterministic.
    drain_on_connect: bool = false,
    /// Bytes sent ahead of the token — a scripted PROXY protocol header
    /// (#142) for `proxy_protocol` scenarios; empty for everyone else.
    prefix: []const u8 = "",
    prefix_sent: u32 = 0,
    sent_len: u32 = 0,
    received_len: u32 = 0,
    fin_sent: bool = false,
    send_pending: bool = false,
    terminal_outcome: ?Outcome = null,
    outcome: Outcome = .pending,

    const Outcome = enum(u8) { pending, refused, eof, reset };

    fn start(client: *Client, scenario: *Scenario, address: std.Io.net.IpAddress) void {
        client.scenario = scenario;
        scenario.io.connect(&.{ .ip = address }, &client.connect_completion, Client, client, onConnect);
    }

    fn onConnect(client: *Client, result: Io.ConnectError!SimIo.Socket) void {
        client.socket = result catch {
            client.outcome = .refused;
            client.scenario.clientEnded();
            return;
        };
        client.armRecv();
        if (client.drain_on_connect) {
            client.scenario.server.beginDrain();
        }
        if (client.exchange) {
            client.armSend();
        }
    }

    fn armSend(client: *Client) void {
        assert(!client.send_pending);
        client.send_pending = true;
        // The scripted prefix goes first, then the token — two cursors,
        // one send in flight at a time, resumed from whichever is short.
        const bytes = if (client.prefix_sent < client.prefix.len)
            client.prefix[client.prefix_sent..]
        else blk: {
            assert(client.sent_len < echo_token.len);
            break :blk echo_token[client.sent_len..];
        };
        client.scenario.io.send(
            client.socket,
            bytes,
            &client.send_completion,
            Client,
            client,
            onSend,
        );
    }

    fn onSend(client: *Client, result: Io.SendError!u32) void {
        assert(client.send_pending);
        client.send_pending = false;
        // A send error mid-teardown is legal; the recv path decides the
        // connection's fate.
        const sent = result catch {
            client.settleIfTerminal();
            return;
        };
        if (client.prefix_sent < client.prefix.len) {
            client.prefix_sent += sent;
            assert(client.prefix_sent <= client.prefix.len);
        } else {
            client.sent_len += sent;
            assert(client.sent_len <= echo_token.len);
        }
        if (client.terminal_outcome != null) {
            client.settleIfTerminal();
        } else if (client.prefix_sent < client.prefix.len or client.sent_len < echo_token.len) {
            client.armSend();
        }
    }

    fn armRecv(client: *Client) void {
        client.scenario.io.recv(
            client.socket,
            client.receive_buffer[client.received_len..],
            &client.recv_completion,
            Client,
            client,
            onRecv,
        );
    }

    fn onRecv(client: *Client, result: Io.RecvError!u32) void {
        const received = result catch |err| {
            // The §5 rule applies to the harness too: the socket may only
            // close once the concurrent send op has also settled.
            client.terminal_outcome = switch (err) {
                error.EndOfStream => .eof,
                error.Reset => .reset,
                else => .eof,
            };
            client.settleIfTerminal();
            return;
        };
        client.received_len += received;
        assert(client.received_len <= echo_token.len);
        if (client.exchange) {
            if (client.received_len == echo_token.len) {
                if (!client.fin_sent) {
                    client.fin_sent = true;
                    client.scenario.io.shutdown(client.socket, .write);
                }
            }
        }
        client.armRecv();
    }

    fn settleIfTerminal(client: *Client) void {
        if (client.terminal_outcome) |terminal| {
            if (!client.send_pending) {
                client.outcome = terminal;
                client.scenario.io.closeNow(client.socket);
                client.scenario.clientEnded();
            }
        }
    }
};

pub const TestBed = struct {
    arena_state: std.heap.ArenaAllocator,
    sim_io: SimIo,
    /// The origin at index 0, then `blackholed_endpoints` addresses no
    /// dial ever completes against (#132). Four is what the concurrency
    /// scenarios need — enough endpoints that a serial sweep and a
    /// concurrent one finish at times a test can tell apart — and it
    /// fits `SimIo`'s own `blackholed_addresses_max`.
    endpoints: [4]io_module.Address,
    endpoints_count: u16,
    clusters: [1]config_module.Config.Cluster,
    routes: [1]router.Route,
    /// The §6 SNI table (#298); empty unless a scenario asks for one, so
    /// no pre-existing case pays for a peek phase it never wanted.
    sni_routes: []const sni_router.Route,
    listeners: [1]config_module.Config.Listener,
    config: config_module.Config,
    server: ServerSim,
    scenario: Scenario,
    /// One slot, matching the one listener. Held by the bed rather than
    /// by the server because a `Credentials` owns a libcrypto key with a
    /// single `deinit`, and the server borrows what it is handed.
    tls_credentials: [1]?Credentials,

    pub const SetUpOptions = struct {
        server: ServerSim.InitOptions = .{ .conn_slots = 4, .relay_buffers = 2 },
        sim: SimIo.Options,
        origin_listens: bool = true,
        idle_timeout_ms: u32 = 1000,
        max_lifetime_ms: u32 = 0,
        connect_timeout_ms: u32 = 50,
        drain_deadline_ms: u32 = 1000,
        /// Turn the §8 access log on. Off by default so every existing
        /// scenario keeps paying nothing for it.
        access_log: bool = false,
        /// §6 SNI routes (#298). Empty by default: an l4 listener with
        /// no table relays without reading a byte first, which is what
        /// every scenario written before this expects.
        sni_routes: []const sni_router.Route = &.{},
        /// §7 active health checks on the one cluster; null by default so
        /// existing scenarios see no probe traffic.
        check: ?config_module.Config.Cluster.Check = null,
        /// §7 passive ejection on the one cluster (#230); null by default,
        /// so no pre-existing scenario can lose an endpoint under it.
        passive_ejection: ?config_module.Config.Cluster.PassiveEjection = null,
        /// §8 per-endpoint concurrency cap; null leaves the cluster
        /// uncapped, which is what every pre-existing scenario wants.
        max_inflight: ?u32 = null,
        /// Probe pacing for `check` scenarios — tight, so fall/rise fit
        /// inside a short virtual run.
        health_interval_ms: u32 = 20,
        /// Endpoints appended after the origin whose dials never complete
        /// — not refused, *silent* (#132). This is the case a `tcp` check
        /// is slowest on and a serial sweep is worst at: each one costs
        /// the check's whole `timeout_ms` before it can be called a miss.
        blackholed_endpoints: u8 = 0,
        /// The #142 receive gate on the one listener; null for everyone
        /// but the PROXY protocol scenarios.
        proxy_protocol: ?config_module.Config.Listener.ProxyProtocol = null,
        /// The #142 send gate on the one cluster; when set, the origin
        /// double expects and strips the header before echoing.
        proxy_protocol_send: ?config_module.Config.Cluster.ProxyProtocolSend = null,
        /// Terminate TLS on the one listener (#125). The bed loads the
        /// checked-in fixture credentials and hands them over before
        /// `start`, standing in for what `main` does — this file is under
        /// the Io seam, so it embeds the PEMs rather than reading them.
        /// Set `server.tls_engines` alongside; the two are checked against
        /// each other the way a real config's are.
        tls: bool = false,
    };

    pub fn bindAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") catch unreachable;
    }

    fn originAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000") catch unreachable;
    }

    /// The cluster's endpoint list: the origin, then `blackholed` more
    /// that answer nothing at all (#132). Black-holed in the backend
    /// rather than merely left unlistened, because an unlistened address
    /// is *refused* — a verdict a probe reaches in one round trip, where
    /// the case a serial sweep is worst at is the endpoint that never
    /// answers and costs the check's whole `timeout_ms`.
    fn initEndpoints(
        bed: *TestBed,
        arena: std.mem.Allocator,
        blackholed: u8,
    ) !void {
        assert(blackholed <= bed.endpoints.len - 1);
        bed.endpoints = .{ .{ .ip = originAddress() }, undefined, undefined, undefined };
        bed.endpoints_count = 1 + blackholed;
        for (bed.endpoints[1..bed.endpoints_count], 0..) |*endpoint, index| {
            const literal = try std.fmt.allocPrintSentinel(
                arena,
                "127.0.0.1:{d}",
                .{9001 + index},
                0,
            );
            // The format is fixed and every port in range renders valid,
            // unlike the allocation above, which can genuinely fail.
            endpoint.* = .{ .ip = std.Io.net.IpAddress.parseLiteral(literal) catch unreachable };
            bed.sim_io.blackholeDestination(endpoint);
        }
    }

    /// The bed's TLS credentials, loaded apart from `setUp` for the
    /// length limit — and it is the half worth naming, since the
    /// deterministic-nonce option below is a §9 property (a seeded run
    /// replays a byte-exact handshake) and never a production setting.
    fn loadCredentials(
        bed: *TestBed,
        arena: std.mem.Allocator,
        options: SetUpOptions,
        server_options: ServerSim.InitOptions,
    ) !void {
        bed.tls_credentials = .{null};
        if (options.tls) {
            assert(server_options.tls_engines >= 1);
            bed.tls_credentials[0] = try Credentials.load(
                arena,
                fixture_cert_pem,
                fixture_key_pem,
                // Deterministic signatures, so a seeded run replays a
                // byte-exact handshake — the §9 property the whole
                // simulation rests on. Never set in production.
                .{ .deterministic_nonce = true },
            );
            bed.server.setTlsCredentials(&bed.tls_credentials);
        }
    }

    pub fn setUp(bed: *TestBed, gpa: std.mem.Allocator, options: SetUpOptions) !void {
        bed.arena_state = std.heap.ArenaAllocator.init(gpa);
        errdefer bed.arena_state.deinit();
        const arena = bed.arena_state.allocator();

        // One number on both sides (§5): the ring the sim registers is
        // the limit the server accounts against — Server.init asserts the
        // match, so a bed cannot drift them apart.
        var sim_options = options.sim;
        sim_options.buffer_group_count = options.server.head_buffers;
        // The unit size has to match too, not just the count: `Server.init`
        // asserts both, because the health prober's buffer follows the head
        // size whether or not a ring was registered.
        sim_options.buffer_group_bytes = options.server.head_buffer_bytes;
        try bed.sim_io.init(arena, sim_options);
        try bed.initEndpoints(arena, options.blackholed_endpoints);
        bed.clusters = .{.{
            .name = "origin",
            .endpoints = bed.endpoints[0..bed.endpoints_count],
            .check = options.check,
            .passive_ejection = options.passive_ejection,
            .max_inflight = options.max_inflight,
            .proxy_protocol_send = options.proxy_protocol_send,
        }};
        bed.routes = .{.{ .prefix = "/", .cluster_index = 0 }};
        bed.sni_routes = options.sni_routes;
        bed.listeners = .{.{
            .bind_address = .{ .ip = bindAddress() },
            .bind_mode = null,
            .routes = &bed.routes,
            .sni_routes = bed.sni_routes,
            .protocol = .l4,
            .proxy_protocol = options.proxy_protocol,
            // Paths nothing reads: the bed embeds the PEMs, so what this
            // states is only that the listener terminates — which is what
            // `Server.start` checks its credentials against.
            .tls = if (options.tls)
                .{ .cert_path = "cert.pem", .key_path = "key.pem" }
            else
                null,
        }};
        bed.config = .{
            .listeners = &bed.listeners,
            .clusters = &bed.clusters,
            .connect_timeout_ms = options.connect_timeout_ms,
            .idle_timeout_ms = options.idle_timeout_ms,
            .head_timeout_ms = options.idle_timeout_ms,
            .drain_deadline_ms = options.drain_deadline_ms,
            .max_lifetime_ms = options.max_lifetime_ms,
            // L4 only: the §8 request deadline is an L7 exchange bound and
            // this bed never routes one.
            .request_timeout_ms = 0,
            .tunnel_timeout_ms = constants.tunnel_ms_default,
            .access_log_sink = if (options.access_log) .stdout else null,
            .health_interval_ms = options.health_interval_ms,
        };
        var server_options = options.server;
        server_options.access_log_buffer_bytes = if (options.access_log)
            constants.access_log_buffer_bytes_default
        else
            0;
        try bed.server.init(arena, &bed.sim_io, &bed.config, server_options);
        try bed.loadCredentials(arena, options, server_options);
        try bed.server.start();

        bed.scenario = .{
            .io = &bed.sim_io,
            .server = &bed.server,
            .origin = .{},
            .clients = @splat(.{}),
            .clients_count = 0,
        };
        bed.scenario.origin.on_accept = Scenario.startPendingRacer;
        bed.scenario.origin.context = &bed.scenario;
        bed.scenario.origin.expect_proxy_header = options.proxy_protocol_send != null;
        if (options.origin_listens) {
            try bed.scenario.origin.start(&bed.sim_io, originAddress());
        }
    }

    pub fn startClients(bed: *TestBed, count: u8, exchange: bool) void {
        assert(count >= 1);
        assert(count <= bed.scenario.clients.len);
        bed.scenario.clients_count = count;
        for (bed.scenario.clients[0..count]) |*client| {
            client.exchange = exchange;
            client.start(&bed.scenario, bindAddress());
        }
    }

    pub fn tearDown(bed: *TestBed) void {
        if (bed.tls_credentials[0]) |*credentials| {
            credentials.deinit();
        }
        bed.arena_state.deinit();
    }

    pub fn expectDrained(bed: *TestBed) !void {
        try std.testing.expect(bed.server.isIdle());
        try std.testing.expect(bed.server.reconcile());
        try std.testing.expect(bed.sim_io.sockets.isFullyReleased());
    }
};

test "relay: proxied echo is byte-exact under the adversary across seeds" {
    var seed: u64 = 1;
    while (seed <= 15) : (seed += 1) {
        var bed: TestBed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .sim = .{
                .seed = seed,
                .adversary = .{ .partial_io = true, .connect_delay_ns_max = 2_000_000 },
            },
        });
        defer bed.tearDown();

        bed.startClients(1, true);
        try bed.sim_io.run();

        const client = &bed.scenario.clients[0];
        try std.testing.expectEqual(Client.Outcome.eof, client.outcome);
        try std.testing.expectEqualStrings(
            echo_token,
            client.receive_buffer[0..client.received_len],
        );
        try std.testing.expectEqual(@as(u8, 1), bed.scenario.origin.conns_count);
        try std.testing.expect(bed.scenario.origin.conns[0].done);
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
        try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("deadline_expired"));
        try bed.expectDrained();
    }
}

test "relay: idle timeout reaps a silent connection" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 31 },
        .idle_timeout_ms = 50,
        // Under the idle budget, as every config must be (§5); the dial
        // completes instantly here, so what it is set to is immaterial
        // beyond clearing the ordering the loader enforces.
        .connect_timeout_ms = 10,
    });
    defer bed.tearDown();

    bed.startClients(1, false);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "relay: the max-lifetime cap reaps a connection before its idle timeout" {
    // The idle timeout is set far in the future (10 s) so it cannot be the
    // reaper; only the 40 ms lifetime cap (§6) can end the connection. The
    // discriminator is the virtual clock: if the cap fired, the run ends
    // near 40 ms, nowhere near the idle deadline.
    const idle_ms: u32 = 10_000;
    const lifetime_ms: u32 = 40;
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 41, .adversary = .{ .partial_io = false } },
        .idle_timeout_ms = idle_ms,
        .max_lifetime_ms = lifetime_ms,
    });
    defer bed.tearDown();

    const start_ns = bed.sim_io.nowNs();
    bed.startClients(1, false);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));

    // Reaped at the cap, not the idle deadline: at least the cap elapsed
    // (never early), and far short of the idle timeout.
    const elapsed_ns = bed.sim_io.nowNs() - start_ns;
    try std.testing.expect(elapsed_ns >= @as(u64, lifetime_ms) * std.time.ns_per_ms);
    try std.testing.expect(elapsed_ns < @as(u64, idle_ms) * std.time.ns_per_ms);
    try bed.expectDrained();
}

test "relay: an origin reset mid-exchange tears the connection down" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 33, .adversary = .{ .partial_io = false } } });
    defer bed.tearDown();

    bed.scenario.origin.mode = .reset_on_first_chunk;
    bed.startClients(1, true);
    try bed.sim_io.run();

    // The client observes the teardown (as FIN or the propagated reset);
    // the echo never completes but the slot is fully reclaimed.
    try std.testing.expect(bed.scenario.clients[0].outcome != .pending);
    try std.testing.expect(bed.scenario.clients[0].received_len < echo_token.len);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "relay: a kernel-pressure data-op failure is witnessed and tears down" {
    // ENOBUFS/ENOMEM on a relay recv/send surfaces as error.Unexpected;
    // the relay counts it (§8 "any completion" rung) and tears the
    // connection down. The injection is certain every batch, so at least
    // one relay data op takes the hit before the exchange completes.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{
            .seed = 2,
            .adversary = .{ .partial_io = true, .kernel_pressure_percent = 100 },
        },
    });
    defer bed.tearDown();

    bed.startClients(1, true);
    try bed.sim_io.run();

    // Witnessed on the data path, and the connection still tore down
    // cleanly — a kernel-pressure teardown is an ordinary teardown that
    // reconciles (it is a failure, not a shed).
    try std.testing.expect(bed.server.counters.get("kernel_pressure_errors") >= 1);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("shed_relay_buffers"));
    // The split must attribute this to the data path and nowhere else.
    // Paired with the accept test below, this is the discrimination the
    // single counter could not make: both scenarios used to land on one
    // number, so a run reporting 227,628 of them said nothing about
    // whether the NIC queue or the fd table was the problem.
    const data_ops = bed.server.counters.get("kernel_pressure_recv") +
        bed.server.counters.get("kernel_pressure_send");
    try std.testing.expect(data_ops >= 1);
    try std.testing.expectEqual(data_ops, bed.server.counters.get("kernel_pressure_errors"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_accept"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_connect"));
    try bed.expectDrained();
}

test "server: the pressure cause travels from the seam to its own counter" {
    // The other half of the diagnosis. The op says which syscall failed;
    // the cause says what to do about it — shed load for out-of-buffers,
    // raise a limit for fd_limit, widen the port range for
    // address_unavailable. Production recovers it from the errno the
    // audited libxev fork keeps on the completion; the sim states it.
    //
    // Driven per cause so no arm of the classification is plumbing nobody
    // exercised: all five landed on one counter before this.
    const cases = [_]struct { cause: Io.Pressure.Cause, counter: []const u8 }{
        .{ .cause = .out_of_buffers, .counter = "kernel_pressure_out_of_buffers" },
        .{ .cause = .out_of_memory, .counter = "kernel_pressure_out_of_memory" },
        .{ .cause = .fd_limit, .counter = "kernel_pressure_fd_limit" },
        .{ .cause = .address_unavailable, .counter = "kernel_pressure_address_unavailable" },
        .{ .cause = .other, .counter = "kernel_pressure_other_cause" },
    };
    // `inline`: `counters.get` names its field at comptime, so the case
    // table has to be unrolled rather than iterated.
    inline for (cases, 0..) |case, index| {
        var bed: TestBed = undefined;
        try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 60 + index } });
        defer bed.tearDown();

        bed.sim_io.setPressureCause(case.cause);
        bed.sim_io.injectSetOptionError();
        bed.startClients(1, true);
        try bed.sim_io.run();

        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_errors"));
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get(case.counter));
        // The op partition is unaffected by which cause it was: both
        // describe the same single failure.
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_set_option"));
        try bed.expectDrained();
    }
}

test "server: kernel-pressure on a socket option is witnessed and the connection serves on" {
    // The set-option path had no simulation coverage at all before this:
    // a virtual socket table never refuses an option, so every bug on it
    // was invisible under every seed — which is how a `setNodelay` site
    // shipped still bumping the aggregate counter without naming its op.
    //
    // Setting TCP_NODELAY is best-effort (§6): failing it costs latency,
    // not correctness, so the connection must still serve.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 52 } });
    defer bed.tearDown();

    bed.sim_io.injectSetOptionError();
    bed.startClients(1, true);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_errors"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_set_option"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_accept"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_recv"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_send"));
    // Best-effort means the exchange completed regardless.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    const client = &bed.scenario.clients[0];
    try std.testing.expectEqual(Client.Outcome.eof, client.outcome);
    try std.testing.expectEqualStrings(echo_token, client.receive_buffer[0..client.received_len]);
    try bed.expectDrained();
}

test "server: kernel-pressure accept failure backs off and recovers" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 51 } });
    defer bed.tearDown();

    // The next accept completes with an ENFILE-class error. The gate must
    // not spin: it backs off through the retry timer, re-arms, and then
    // serves the client that was waiting in the backlog all along.
    // ENFILE-class is what an accept actually runs out of, so the cause is
    // stated and asserted here rather than left to whatever the previous
    // completion happened to leave behind — the accept fault site shipped
    // without recording one, and nothing downstream could have noticed.
    bed.sim_io.setPressureCause(.fd_limit);
    bed.sim_io.injectAcceptError(bed.server.listeners[0].listener);
    bed.startClients(1, true);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_fd_limit"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_out_of_buffers"));

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_errors"));
    // Attributed to the accept, and to nothing on the data path — the
    // other half of the discrimination (see the relay test above).
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_accept"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_recv"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_send"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("accepted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    const client = &bed.scenario.clients[0];
    try std.testing.expectEqual(Client.Outcome.eof, client.outcome);
    try std.testing.expectEqualStrings(
        echo_token,
        client.receive_buffer[0..client.received_len],
    );
    try bed.expectDrained();
}

test "server: kernel-pressure on the upstream dial is witnessed and the conn torn down" {
    // The dial-Unexpected path had no simulation coverage before this:
    // the adversary could refuse or black-hole a dial but never fail it
    // the way a kernel out of sockets or ephemeral ports does, so the §8
    // witness on the connect op was unreachable under every seed
    // (issue #106, kind B).
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 53 } });
    defer bed.tearDown();

    // EADDRNOTAVAIL is the dial's own exhaustion shape: ephemeral ports.
    // Pins the proxy→origin dial only; the client's connect stays live.
    bed.sim_io.setPressureCause(.address_unavailable);
    bed.sim_io.injectConnectError(TestBed.originAddress());
    bed.startClients(1, true);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_errors"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("kernel_pressure_connect"));
    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("kernel_pressure_address_unavailable"),
    );
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_accept"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    // At this seed the dial fate delivers before any token byte reaches
    // the proxy-side inbox, so the teardown's close FINs; a schedule
    // that lands a byte first would RST instead (unread inbox). Either
    // way the client ends — the §8 witness above is the invariant here,
    // the wire shape is the seed's.
    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u8, 0), bed.scenario.origin.conns_count);
    try bed.expectDrained();
}

test "drain: a zero deadline waits for the straggler instead of reaping it" {
    // `drain_deadline_ms: 0` is "no cap" (§5, §8) — the shape a config
    // that names no deadline gets, and what nginx, HAProxy and Caddy all
    // do by default. `beginDrain` arms no timer at all, so the same
    // silent client the test below reaps at the deadline is left alone
    // here and leaves on its own terms.
    //
    // What bounds this in production is the supervisor that sent the
    // signal — systemd's `TimeoutStopSec`, Kubernetes'
    // `terminationGracePeriodSeconds` — which is why the drain is allowed
    // to be unbounded rather than obliged to invent a number. Here it is
    // the client closing that ends it.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 41 },
        // Short enough that the connection ends the run rather than
        // hanging the test, and far longer than the drain deadline the
        // sibling test relies on: the point is that *this* is what ends
        // it, not a drain timer.
        .idle_timeout_ms = 50,
        .connect_timeout_ms = 10,
        .drain_deadline_ms = 0,
    });
    defer bed.tearDown();

    bed.startClients(1, false);
    bed.sim_io.scheduleSignal(.terminate, bed.sim_io.nowNs() + 5_000_000);
    try bed.sim_io.run();

    // Nothing was reaped by a deadline that does not exist.
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("drained_at_deadline"));
    // And the drain still completed: the idle deadline ended the
    // connection, the pools drained, and the loop stopped.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "drain: terminate signal stops accepting and reaps stragglers at the drain deadline" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 41 }, .idle_timeout_ms = 60_000 });
    defer bed.tearDown();

    // A silent client would idle for a minute; the drain must not wait
    // for it — the server-owned drain timer reaps it instead.
    bed.startClients(1, false);
    bed.sim_io.scheduleSignal(.terminate, bed.sim_io.nowNs() + 5_000_000);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("drained_at_deadline"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "drain: an accept that raced the drain is shed quietly and witnessed" {
    // The shed_draining rung (§8): an accept whose CQE was already posted
    // when the drain closed the listener is delivered, not canceled, and
    // must be shed quietly. A holder client keeps the pools non-empty (so
    // the drain cannot stop the loop before the raced delivery); once the
    // origin sees the holder's proxied connection, the racer dials and
    // triggers the drain from inside its own connect delivery — the exact
    // instant its socket sits queued behind the armed accept.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 61 },
        .idle_timeout_ms = 60_000,
    });
    defer bed.tearDown();

    bed.scenario.clients_count = 2;
    const holder = &bed.scenario.clients[0];
    const racer = &bed.scenario.clients[1];
    racer.drain_on_connect = true;
    bed.scenario.pending_racer = racer;
    holder.start(&bed.scenario, TestBed.bindAddress());
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("accepted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("shed_draining"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("drained_at_deadline"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    // Both end with an orderly FIN: the holder at the drain deadline, the
    // raced socket via the quiet shed — never an RST (§8 table).
    try std.testing.expectEqual(@as(u8, 2), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u8, 0), bed.scenario.outcomeCount(.reset));
    try bed.expectDrained();
}

test "server: conn-slot exhaustion sheds with RST; deadline reaps the holder" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .server = .{ .conn_slots = 1, .relay_buffers = 1 },
        .sim = .{ .seed = 21 },
    });
    defer bed.tearDown();

    // Pin the proxy→origin dial only; the clients' own connects stay live.
    bed.sim_io.blackholeAddress(TestBed.originAddress());
    bed.startClients(2, false);
    try bed.sim_io.run();

    // One client held the only slot until the connect deadline reaped it
    // (orderly FIN); the other was shed at the gate with an RST.
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("accepted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("shed_conn_slots"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.reset));
    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u8, 0), bed.scenario.origin.conns_count);
    try bed.expectDrained();
}

test "server: relay-buffer exhaustion sheds with a quiet close" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .server = .{ .conn_slots = 2, .relay_buffers = 1 },
        .sim = .{ .seed = 22 },
    });
    defer bed.tearDown();

    bed.sim_io.blackholeAddress(TestBed.originAddress());
    bed.startClients(2, false);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("shed_relay_buffers"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("shed_conn_slots"));
    // Both clients end with FIN: the shed one quietly, the admitted one
    // when the deadline reaped its black-holed dial.
    try std.testing.expectEqual(@as(u8, 2), bed.scenario.outcomeCount(.eof));
    try std.testing.expectEqual(@as(u8, 0), bed.scenario.outcomeCount(.reset));
    try bed.expectDrained();
}

test "server: relay-buffer pressure engages before the wall and drains clean" {
    // Four connections hold all four relay buffers at once (their upstream
    // dials are black-holed, so each keeps its buffer until the connect
    // deadline reaps it). Crossing the 3/4 high watermark flips the
    // pressure flag exactly once; the flag clears again as the pool drains,
    // and every counter still reconciles with the pools empty.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .server = .{ .conn_slots = 4, .relay_buffers = 4 },
        .sim = .{ .seed = 71 },
    });
    defer bed.tearDown();

    bed.sim_io.blackholeAddress(TestBed.originAddress());
    bed.startClients(4, false);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 4), bed.server.counters.get("admitted"));
    try std.testing.expect(bed.server.counters.get("relay_pressure_engaged") >= 1);
    // Pressure is a transient bias, not a terminal state: it clears as the
    // pool drains back below the low watermark.
    try std.testing.expect(!bed.server.relay_pressure);
    try std.testing.expectEqual(@as(u64, 4), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "server: conn-slot pressure engages before the wall and drains clean" {
    // Four L4 connections hold all four conn slots (their dials are
    // black-holed, so each lives to its connect deadline). Crossing the
    // 3/4 high watermark flips the conn-pressure flag; it clears again
    // as the pool drains, and every counter still reconciles.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .server = .{ .conn_slots = 4, .relay_buffers = 4 },
        .sim = .{ .seed = 73 },
    });
    defer bed.tearDown();

    bed.sim_io.blackholeAddress(TestBed.originAddress());
    bed.startClients(4, false);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 4), bed.server.counters.get("admitted"));
    try std.testing.expect(bed.server.counters.get("conn_pressure_engaged") >= 1);
    // Pressure is a transient bias, not a terminal state.
    try std.testing.expect(!bed.server.conn_pressure);
    try std.testing.expectEqual(@as(u64, 4), bed.server.counters.get("completed"));
    try bed.expectDrained();
}

test "server: idle timeout shortens under pressure, is full otherwise" {
    // The pure selection rules the pressure flags drive: full timeouts
    // when relaxed; the idle timeout divides under either downstream
    // pressure (relay or conn); keep-alive suppression follows relay
    // pressure only (#57); the parked deadline divides again under
    // upstream pressure — each floored at 1 ms.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 72 },
        .idle_timeout_ms = 1000,
    });
    defer bed.tearDown();

    try std.testing.expect(!bed.server.downstreamPressured());
    try std.testing.expect(!bed.server.keepAliveSuppressed());
    try std.testing.expectEqual(@as(u32, 1000), bed.server.idleTimeoutMs());
    try std.testing.expectEqual(@as(u32, 1000), bed.server.parkedTimeoutMs());
    bed.server.relay_pressure = true;
    try std.testing.expect(bed.server.keepAliveSuppressed());
    try std.testing.expectEqual(@as(u32, 1000 / 4), bed.server.idleTimeoutMs());
    bed.server.relay_pressure = false;
    bed.server.conn_pressure = true;
    try std.testing.expect(bed.server.downstreamPressured());
    // Conn pressure divides the idle timeout but never suppresses
    // keep-alive: slot scarcity reaps quiet connections, not serving
    // ones (#57).
    try std.testing.expect(!bed.server.keepAliveSuppressed());
    try std.testing.expectEqual(@as(u32, 1000 / 4), bed.server.idleTimeoutMs());
    bed.server.conn_pressure = false;
    // Upstream pressure biases only the parked deadline, not the idle
    // timeout; under both it compounds.
    bed.server.upstream_pressure = true;
    try std.testing.expectEqual(@as(u32, 1000), bed.server.idleTimeoutMs());
    try std.testing.expectEqual(@as(u32, 1000 / 4), bed.server.parkedTimeoutMs());
    bed.server.conn_pressure = true;
    try std.testing.expectEqual(@as(u32, 1000 / 16), bed.server.parkedTimeoutMs());
    bed.server.conn_pressure = false;
    bed.server.upstream_pressure = false;
}

test "server: refused upstream tears the connection down and is counted" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .server = .{ .conn_slots = 2, .relay_buffers = 1 },
        .sim = .{ .seed = 23 },
        .origin_listens = false, // no origin: every dial is refused
    });
    defer bed.tearDown();

    bed.startClients(1, false);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
    try std.testing.expectEqual(@as(u8, 1), bed.scenario.outcomeCount(.eof));
    try bed.expectDrained();
}

test "l4: a refused dial passively ejects the endpoint it was for" {
    // #230 on the L4 path. The two "answered nothing" signals are L7
    // shapes — there is no response head to be missing from a byte relay
    // — but a *dial* fails identically whichever protocol asked for it,
    // and both protocols pick through the one health mask. An operator
    // who configures `passive_ejection` on a cluster an l4 listener
    // routes to must get detection, not a knob that quietly does
    // nothing.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .server = .{ .conn_slots = 2, .relay_buffers = 1 },
        .sim = .{ .seed = 234 },
        .origin_listens = false, // every dial is refused
        .passive_ejection = .{ .fall = 1, .recovery_ms = 60_000 },
    });
    defer bed.tearDown();

    bed.startClients(1, false);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("health_endpoint_down_passive"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("health_endpoint_down_probe"));
    try std.testing.expect(!bed.server.health.healthy[0]);
    try std.testing.expectEqual(@as(u32, 1), bed.server.health.unhealthy_count);
    // Nothing probes here, and the endpoint is still ejectable — the
    // whole point of the feature for a cluster with no `check` block.
    try std.testing.expectEqual(@as(u32, 0), bed.server.health.checked_count);
    try std.testing.expectEqual(@as(u32, 1), bed.server.health.ejectable_count);
    try bed.expectDrained();
}

test "teardown: a drain racing its own upstream dial peaks at four armed ops" {
    // The §8 worst case the ring budget must cover: the drain deadline
    // reaps a connection whose upstream dial is still in flight, teardown
    // arms both cancels on top of {connect, deadline}, and the delayed
    // dial then completes against its own cancel. Closes are synchronous
    // after the full drain (continueTeardown, not ring ops at all), so
    // the peak stays at conn_ops_max = 4 — when closes were ring ops
    // merely submitted eagerly, these exact seeds co-armed five ops
    // ({deadline, both cancels, both closes}), found by sweeping 1..400
    // against that code and pinned here so the race, not just some
    // teardown, is what every run witnesses.
    const race_seeds = [_]u64{ 40, 109, 116, 163, 211, 334 };
    for (race_seeds) |seed| {
        var bed: TestBed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .sim = .{
                .seed = seed,
                .adversary = .{ .partial_io = true, .connect_delay_ns_max = 5_000_000 },
            },
            // Connect and idle stay far out so the drain deadline — not a
            // request deadline — is what tears the dialing conn down. Both
            // are minutes past this run; the gap between them is only the
            // ordering the loader enforces (§5).
            .idle_timeout_ms = 60_000,
            .connect_timeout_ms = 30_000,
            .drain_deadline_ms = 1,
        });
        defer bed.tearDown();

        bed.startClients(1, false);
        bed.sim_io.scheduleSignal(.terminate, bed.sim_io.nowNs() + 2_000_000);
        try bed.sim_io.run();

        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("drained_at_deadline"));
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
        try std.testing.expectEqual(@as(u8, 4), bed.server.armed_ops_peak);
        // And the #274 split of that same four: {connect, connect_cancel}
        // on the stream, {deadline, deadline_cancel} on the conn. The
        // combined figure above is what the CQ is charged and is what
        // must not move; this one is why `stream_ops_max` is two rather
        // than four, pinned by the seeds that actually reach the race.
        try std.testing.expectEqual(@as(u8, 2), bed.server.stream_armed_ops_peak);
        try bed.expectDrained();
    }
}

test "relay: a completed L4 connection writes one line counting both directions" {
    // The L4 half of the §8 access log. A connection, not a request, is
    // the unit here — there is no smaller one — so the line covers the
    // whole relay: who connected, which origin served, how long it lasted,
    // and how many bytes crossed each way.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 3, .adversary = .{ .partial_io = true } },
        .access_log = true,
    });
    defer bed.tearDown();

    bed.startClients(1, true);
    try bed.sim_io.run();
    try bed.expectDrained();

    const sink = bed.sim_io.sinkBytes();
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("access_log_lines"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("access_log_dropped"));
    const line = std.mem.trimEnd(u8, sink, "\n");

    try std.testing.expect(std.mem.indexOf(u8, line, "\"kind\":\"l4\"") != null);
    // Both peers said goodbye, which is the one L4 ending that is not a
    // cut — every other way out leaves `aborted`.
    try std.testing.expect(std.mem.indexOf(u8, line, "\"outcome\":\"closed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"cluster\":\"origin\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"upstream\":\"127.0.0.1:9000\"") != null);
    // The echo scenario sends the token up and reads it back down, so both
    // counts are exactly its length — and they are *separate* counts, which
    // a single total would have hidden.
    var expected: [64]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(
        u8,
        line,
        try std.fmt.bufPrint(&expected, "\"bytes_in\":{d},", .{echo_token.len}),
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        line,
        try std.fmt.bufPrint(&expected, "\"bytes_out\":{d},", .{echo_token.len}),
    ) != null);
    // The HTTP-only fields are absent on an L4 line, not empty.
    try std.testing.expect(std.mem.indexOf(u8, line, "\"status\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"path\"") == null);
}

test "relay: a connection reaped by the idle deadline is logged as aborted" {
    // The negative space of the test above: a relay that never reached a
    // clean two-way close must not read as one. `aborted` is the default
    // precisely so every path that forgets to say otherwise says this.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 4 },
        .idle_timeout_ms = 20,
        .connect_timeout_ms = 10,
        .access_log = true,
    });
    defer bed.tearDown();

    // `exchange = false`: the client connects and then says nothing, so
    // the idle deadline is what ends it.
    bed.startClients(1, false);
    try bed.sim_io.run();
    try bed.expectDrained();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("access_log_lines"));
    const line = std.mem.trimEnd(u8, bed.sim_io.sinkBytes(), "\n");
    try std.testing.expect(std.mem.indexOf(u8, line, "\"kind\":\"l4\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"outcome\":\"aborted\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"bytes_in\":0,") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"bytes_out\":0,") != null);
}

// The announced client deliberately differs from `SimIo`'s observed peer
// (198.51.100.1:5xxxx) in *both* address and port, so the log oracle
// below cannot pass by accident.
const proxy_v1_line = "PROXY TCP4 203.0.113.7 10.0.0.1 4711 443\r\n";

/// A minimal ClientHello naming `name`, built the way `client_hello.zig`
/// builds its own fixtures — one record, empty vectors, one `server_name`
/// extension. Small on purpose: what these scenarios exercise is the
/// routing decision, and `client_hello.zig` already owns the parse.
fn sniHello(out: []u8, name: ?[]const u8) []const u8 {
    var at: usize = 0;
    const put = struct {
        fn byte(buffer: []u8, cursor: *usize, value: u8) void {
            buffer[cursor.*] = value;
            cursor.* += 1;
        }
        fn int16(buffer: []u8, cursor: *usize, value: u16) void {
            std.mem.writeInt(u16, buffer[cursor.*..][0..2], value, .big);
            cursor.* += 2;
        }
    };
    put.byte(out, &at, 0x16); // handshake record
    put.int16(out, &at, 0x0301);
    const record_len_at = at;
    put.int16(out, &at, 0);
    const body_at = at;
    put.byte(out, &at, 0x01); // client_hello
    @memset(out[at..][0..3], 0);
    at += 3;
    put.int16(out, &at, 0x0303);
    @memset(out[at..][0..32], 0); // random
    at += 32;
    put.byte(out, &at, 0); // legacy_session_id
    put.int16(out, &at, 0); // cipher_suites
    put.byte(out, &at, 0); // legacy_compression_methods
    if (name) |server_name| {
        put.int16(out, &at, @intCast(server_name.len + 9));
        put.int16(out, &at, 0); // server_name extension
        put.int16(out, &at, @intCast(server_name.len + 5));
        put.int16(out, &at, @intCast(server_name.len + 3));
        put.byte(out, &at, 0); // host_name
        put.int16(out, &at, @intCast(server_name.len));
        @memcpy(out[at..][0..server_name.len], server_name);
        at += server_name.len;
    }
    const body_len = at - body_at;
    std.mem.writeInt(u16, out[record_len_at..][0..2], @intCast(body_len), .big);
    std.mem.writeInt(u24, out[body_at + 1 ..][0..3], @intCast(body_len - 4), .big);
    return out[0..at];
}

/// The one named route these scenarios share, plus a catch-all where the
/// case wants one. Both point at cluster 0 — the bed has one, and what is
/// under test is which *verdict* the table reaches, not which backend.
const sni_named_only = [_]sni_router.Route{
    .{ .server_name = "api.example.com", .cluster_index = 0 },
};
const sni_with_catch_all = [_]sni_router.Route{
    .{ .server_name = "api.example.com", .cluster_index = 0 },
    .{ .cluster_index = 0 },
};

test "sni routing: a named hello routes, and the backend receives it unchanged" {
    // #298's whole promise in one run: the proxy reads the name without
    // terminating, picks the route, and the origin still gets a parseable
    // hello asking for the same server. Partial-io seeds split the hello
    // across deliveries, so the accumulate-and-retry loop is exercised
    // rather than the one-recv happy path.
    var seed: u64 = 1;
    while (seed <= 8) : (seed += 1) {
        var bed: TestBed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .sim = .{ .seed = seed, .adversary = .{ .partial_io = true } },
            .sni_routes = &sni_named_only,
            .access_log = true,
        });
        defer bed.tearDown();
        bed.scenario.origin.expect_client_hello = true;

        var hello_buffer: [128]u8 = undefined;
        const hello = sniHello(&hello_buffer, "api.example.com");
        bed.scenario.clients_count = 1;
        const client = &bed.scenario.clients[0];
        client.exchange = true;
        client.prefix = hello;
        client.start(&bed.scenario, TestBed.bindAddress());
        try bed.sim_io.run();
        try bed.expectDrained();

        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_sni_routed"));
        try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l4_sni_invalid"));
        // The backend parsed a hello, and it named what the client asked
        // for — which is the part termination would have destroyed.
        try std.testing.expectEqual(@as(u32, 1), bed.scenario.origin.client_hello_conns);
        try std.testing.expectEqualStrings(
            "api.example.com",
            bed.scenario.origin.client_hello_name[0..bed.scenario.origin.client_hello_name_len],
        );
        // And the token still round-trips behind it, byte-exact.
        try std.testing.expectEqualStrings(
            echo_token,
            client.receive_buffer[0..client.received_len],
        );
    }
}

test "sni routing: the PROXY header is the envelope, the hello is what it wraps" {
    // §6's stated composition, and the one shape where the two receive
    // phases meet: the header is consumed, then the hello behind it is
    // peeked and routed. Both arrive in the same segment on some seeds
    // and split across deliveries on others, so this covers the
    // hand-over that enters the peek already holding bytes as well as
    // the one that enters it empty.
    var seed: u64 = 1;
    while (seed <= 8) : (seed += 1) {
        var bed: TestBed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .sim = .{ .seed = seed, .adversary = .{ .partial_io = true } },
            .proxy_protocol = .require,
            .sni_routes = &sni_named_only,
            .access_log = true,
        });
        defer bed.tearDown();
        bed.scenario.origin.expect_client_hello = true;

        // The header, then the hello, then the token — one stream, three
        // layers, each consumed by the phase that owns it.
        var prefix_buffer: [256]u8 = undefined;
        @memcpy(prefix_buffer[0..proxy_v1_line.len], proxy_v1_line);
        var hello_buffer: [128]u8 = undefined;
        const hello = sniHello(&hello_buffer, "api.example.com");
        @memcpy(prefix_buffer[proxy_v1_line.len..][0..hello.len], hello);

        bed.scenario.clients_count = 1;
        const client = &bed.scenario.clients[0];
        client.exchange = true;
        client.prefix = prefix_buffer[0 .. proxy_v1_line.len + hello.len];
        client.start(&bed.scenario, TestBed.bindAddress());
        try bed.sim_io.run();
        try bed.expectDrained();

        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_proxy_header_accepted"));
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_sni_routed"));
        try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l4_sni_invalid"));
        // The hello reached the backend intact — the header did not.
        try std.testing.expectEqual(@as(u32, 1), bed.scenario.origin.client_hello_conns);
        try std.testing.expectEqualStrings(
            "api.example.com",
            bed.scenario.origin.client_hello_name[0..bed.scenario.origin.client_hello_name_len],
        );
        try std.testing.expectEqualStrings(
            echo_token,
            client.receive_buffer[0..client.received_len],
        );
        // And the announced client survived the second phase: a peek
        // that rebuilt the connection's state would have lost it.
        const line = std.mem.trimEnd(u8, bed.sim_io.sinkBytes(), "\n");
        try std.testing.expect(std.mem.indexOf(u8, line, "\"client\":\"203.0.113.7:4711\"") != null);
    }
}

test "sni routing: a hello naming nothing takes the any-name route" {
    // A real and common shape (an IP-only client, an old stack), and a
    // verdict rather than an error — counted apart from a named match
    // because "nobody asked" and "asked for this" are different facts.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 3 },
        .sni_routes = &sni_with_catch_all,
    });
    defer bed.tearDown();
    bed.scenario.origin.expect_client_hello = true;

    var hello_buffer: [128]u8 = undefined;
    const hello = sniHello(&hello_buffer, null);
    bed.scenario.clients_count = 1;
    const client = &bed.scenario.clients[0];
    client.exchange = true;
    client.prefix = hello;
    client.start(&bed.scenario, TestBed.bindAddress());
    try bed.sim_io.run();
    try bed.expectDrained();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_sni_absent"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l4_sni_routed"));
    try std.testing.expectEqual(@as(u32, 1), bed.scenario.origin.client_hello_conns);
}

test "sni routing: a name no route claims is closed, not guessed" {
    // The operator wrote no catch-all, which is them saying to close what
    // their table does not cover rather than send it somewhere they never
    // named (§6). Nothing reaches the origin.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 5 },
        .sni_routes = &sni_named_only,
    });
    defer bed.tearDown();

    var hello_buffer: [128]u8 = undefined;
    const hello = sniHello(&hello_buffer, "other.example.com");
    bed.scenario.clients_count = 1;
    const client = &bed.scenario.clients[0];
    client.exchange = true;
    client.prefix = hello;
    client.start(&bed.scenario, TestBed.bindAddress());
    try bed.sim_io.run();
    try bed.expectDrained();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_sni_no_route"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l4_sni_routed"));
    try std.testing.expectEqual(@as(u32, 0), bed.scenario.origin.client_hello_conns);
}

test "sni routing: opening bytes that are not a hello are refused" {
    // A plaintext client on a listener fronting TLS services. It named
    // nothing this table could match and cannot be relayed blind, so it
    // is closed — and counted where an operator can see the listener is
    // receiving traffic it was not built for.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 7 },
        .sni_routes = &sni_with_catch_all,
    });
    defer bed.tearDown();

    bed.scenario.clients_count = 1;
    const client = &bed.scenario.clients[0];
    client.exchange = true;
    client.prefix = "GET / HTTP/1.1\r\n\r\n";
    client.start(&bed.scenario, TestBed.bindAddress());
    try bed.sim_io.run();
    try bed.expectDrained();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_sni_invalid"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l4_sni_routed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l4_sni_absent"));
}

test "proxy protocol: the header is consumed, the payload relays, the client is believed" {
    // The slice-3 promise end to end: a require-listener consumes the
    // header (the origin sees the token alone, byte-exact), any payload
    // coalesced behind it relays, and `client_address` becomes the
    // announced client — witnessed through the access log, the same
    // field the §7 hash pick reads. Partial-io seeds split the header
    // across deliveries, so the accumulate-and-retry loop is exercised
    // and not just the one-recv happy path.
    var seed: u64 = 1;
    while (seed <= 15) : (seed += 1) {
        var bed: TestBed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .sim = .{
                .seed = seed,
                .adversary = .{ .partial_io = true, .connect_delay_ns_max = 2_000_000 },
            },
            .proxy_protocol = .require,
            .access_log = true,
        });
        defer bed.tearDown();

        bed.scenario.clients_count = 1;
        const client = &bed.scenario.clients[0];
        client.exchange = true;
        client.prefix = proxy_v1_line;
        client.start(&bed.scenario, TestBed.bindAddress());
        try bed.sim_io.run();
        try bed.expectDrained();

        try std.testing.expectEqual(Client.Outcome.eof, client.outcome);
        try std.testing.expectEqualStrings(
            echo_token,
            client.receive_buffer[0..client.received_len],
        );
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_proxy_header_accepted"));
        try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l4_proxy_header_invalid"));

        const line = std.mem.trimEnd(u8, bed.sim_io.sinkBytes(), "\n");
        try std.testing.expect(std.mem.indexOf(u8, line, "\"client\":\"203.0.113.7:4711\"") != null);
        // `bytes_in` counts the payload alone: the header is metadata the
        // origin never sees, whichever recv it arrived in.
        var expected: [64]u8 = undefined;
        try std.testing.expect(std.mem.indexOf(
            u8,
            line,
            try std.fmt.bufPrint(&expected, "\"bytes_in\":{d},", .{echo_token.len}),
        ) != null);
    }
}

test "proxy protocol: an UNKNOWN header is accepted and keeps the observed peer" {
    // The fronting proxy's health checks arrive exactly this way (§6):
    // a valid header that announces nothing. The relay must proceed and
    // the log must state the peer the kernel saw.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 11 },
        .proxy_protocol = .require,
        .access_log = true,
    });
    defer bed.tearDown();

    bed.scenario.clients_count = 1;
    const client = &bed.scenario.clients[0];
    client.exchange = true;
    client.prefix = "PROXY UNKNOWN\r\n";
    client.start(&bed.scenario, TestBed.bindAddress());
    try bed.sim_io.run();
    try bed.expectDrained();

    try std.testing.expectEqual(Client.Outcome.eof, client.outcome);
    try std.testing.expectEqualStrings(
        echo_token,
        client.receive_buffer[0..client.received_len],
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_proxy_header_accepted"));
    const line = std.mem.trimEnd(u8, bed.sim_io.sinkBytes(), "\n");
    try std.testing.expect(std.mem.indexOf(u8, line, "\"client\":\"198.51.100.1:50000\"") != null);
}

test "proxy protocol: a peer that does not open with the header is refused" {
    // `require`'s whole meaning: the raw token is a perfectly valid
    // payload on any other listener, and this one closes on its first
    // byte. Nothing reaches the origin; the counter names the verdict.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 7 },
        .proxy_protocol = .require,
    });
    defer bed.tearDown();

    bed.scenario.clients_count = 1;
    const client = &bed.scenario.clients[0];
    client.exchange = true; // Sends the raw token: no header anywhere.
    client.start(&bed.scenario, TestBed.bindAddress());
    try bed.sim_io.run();
    try bed.expectDrained();

    try std.testing.expect(client.outcome == .eof or client.outcome == .reset);
    try std.testing.expectEqual(@as(u32, 0), client.received_len);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_proxy_header_invalid"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l4_proxy_header_accepted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
}

test "proxy protocol: a silent peer is reaped on the connect budget" {
    // The phase runs under the connect clock, not the idle one: the
    // fronting proxy speaks immediately after connecting, so a peer
    // that says nothing is reaped on the dial-scale deadline.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 5 },
        .connect_timeout_ms = 10,
        .idle_timeout_ms = 20,
        .proxy_protocol = .require,
    });
    defer bed.tearDown();

    bed.startClients(1, false); // Connects, then says nothing.
    try bed.sim_io.run();
    try bed.expectDrained();

    const client = &bed.scenario.clients[0];
    try std.testing.expect(client.outcome == .eof or client.outcome == .reset);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("deadline_expired"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l4_proxy_header_invalid"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("l4_proxy_header_accepted"));
}

test "proxy protocol send: the origin hears who connected, and only the payload echoes" {
    // The send half end to end: a sending cluster's upstream connection
    // opens with a header naming the observed client, the origin double
    // strips and records it, and the echo stays byte-exact — so a header
    // that leaked into the payload, or payload that leaked into the
    // header, cannot hide. Partial-io seeds split the header across
    // deliveries on the origin's side of the wire.
    inline for (.{
        config_module.Config.Cluster.ProxyProtocolSend.v1,
        config_module.Config.Cluster.ProxyProtocolSend.v2,
    }) |version| {
        var seed: u64 = 1;
        while (seed <= 8) : (seed += 1) {
            var bed: TestBed = undefined;
            try bed.setUp(std.testing.allocator, .{
                .sim = .{
                    .seed = seed,
                    .adversary = .{ .partial_io = true, .connect_delay_ns_max = 2_000_000 },
                },
                .proxy_protocol_send = version,
            });
            defer bed.tearDown();

            bed.startClients(1, true);
            try bed.sim_io.run();
            try bed.expectDrained();

            const client = &bed.scenario.clients[0];
            try std.testing.expectEqual(Client.Outcome.eof, client.outcome);
            try std.testing.expectEqualStrings(
                echo_token,
                client.receive_buffer[0..client.received_len],
            );
            try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_proxy_header_sent"));
            try std.testing.expectEqual(@as(u32, 1), bed.scenario.origin.proxy_header_conns);
            try std.testing.expectEqual(@as(u32, 0), bed.scenario.origin.proxy_header_violations);
            // The announced client is the peer zoxy observed: SimIo's
            // synthetic dialer address.
            const observed: std.Io.net.IpAddress =
                .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 1 }, .port = 50_000 } };
            const announced = bed.scenario.origin.conns[0].announced.?;
            try std.testing.expect(observed.eql(&announced));
        }
    }
}

test "proxy protocol: the received identity is the sent identity — the chain holds" {
    // Both halves of #142 on one connection: the client announces
    // 203.0.113.7:4711 through the require listener, and the sending
    // cluster's origin must hear exactly that — zoxy in the middle of a
    // PROXY protocol chain, believing inward and announcing outward.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 9, .adversary = .{ .partial_io = true } },
        .proxy_protocol = .require,
        .proxy_protocol_send = .v2,
    });
    defer bed.tearDown();

    bed.scenario.clients_count = 1;
    const client = &bed.scenario.clients[0];
    client.exchange = true;
    client.prefix = proxy_v1_line;
    client.start(&bed.scenario, TestBed.bindAddress());
    try bed.sim_io.run();
    try bed.expectDrained();

    try std.testing.expectEqual(Client.Outcome.eof, client.outcome);
    try std.testing.expectEqualStrings(
        echo_token,
        client.receive_buffer[0..client.received_len],
    );
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_proxy_header_accepted"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_proxy_header_sent"));
    try std.testing.expectEqual(@as(u32, 0), bed.scenario.origin.proxy_header_violations);
    const announced_in: std.Io.net.IpAddress =
        .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 7 }, .port = 4711 } };
    const announced_out = bed.scenario.origin.conns[0].announced.?;
    try std.testing.expect(announced_in.eql(&announced_out));
}

test "health: black-holed endpoints are ejected in one probe budget, not one each" {
    // #132's sharp edge, and the one oracle in the tree that can see a
    // *detection-time* regression rather than a wrong verdict.
    //
    // Four checked endpoints: the live origin plus three that answer
    // nothing. `fall: 1` makes one miss an ejection, and a black-holed
    // dial can only miss by spending the check's whole 50 ms budget.
    //
    //   serial (pre-#132): the origin passes at once, then the three
    //     silent dials cost 50 ms *each* — the third endpoint is not
    //     ejected until ~150 ms.
    //   concurrent: all four are handed out at the sweep's start, so the
    //     three deadlines expire together and every ejection has landed
    //     by ~50 ms.
    //
    // Ending the scenario at 90 ms sits between those, so this test fails
    // against a serial prober with one endpoint ejected instead of three.
    // Every verdict is correct either way, which is exactly why a counter
    // or transcript oracle cannot tell the two apart (#258).
    //
    // `health_interval_ms` is 100 rather than the bed's tight default so
    // that exactly one sweep fits in the window: the interval paces
    // sweep-*end* to sweep-start, so a 20 ms one would open a second
    // sweep at ~70 ms and this test would quietly also be exercising the
    // mid-sweep drain that the next test exists to cover. One sweep is
    // what makes the concurrency counter below an exact number.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 132 },
        .check = .{ .timeout_ms = 50, .fall = 1 },
        .health_interval_ms = 100,
        .blackholed_endpoints = 3,
    });
    defer bed.tearDown();

    bed.sim_io.scheduleSignal(.terminate, bed.sim_io.nowNs() + 90 * std.time.ns_per_ms);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u32, 4), bed.server.health.checked_count);
    // The live origin keeps its place; the three silent ones are gone.
    try std.testing.expect(bed.server.health.healthy[0]);
    try std.testing.expect(!bed.server.health.healthy[1]);
    try std.testing.expect(!bed.server.health.healthy[2]);
    try std.testing.expect(!bed.server.health.healthy[3]);
    try std.testing.expectEqual(@as(u32, 3), bed.server.health.unhealthy_count);
    // The overlap itself, not merely its consequence: of the one sweep's
    // four hand-offs the first found the prober idle and the other three
    // each found a sibling already in flight. Exact rather than `>=`,
    // because a bound here would hide a second sweep having run.
    try std.testing.expectEqual(
        @as(u64, 3),
        bed.server.counters.get("health_probes_concurrent"),
    );
    try bed.expectDrained();
}

test "health: a drain reaches quiescence with every probe still in flight" {
    // The K-probe drain ladder (#132): `Checker.continueStop` advances
    // every probe per pass. Terminating 25 ms into a sweep whose three
    // black-holed dials each have a 50 ms budget lands the signal with
    // three connects and three deadlines armed at once.
    //
    // What this pins, precisely: that the ladder *reaches* all of them.
    // It does not pin that it drains them in parallel — the simulator
    // advances its clock until everything resolves, so a ladder that
    // walked the probes one at a time would still finish, just later, as
    // `continueStop`'s own comment says. Nor is the counter below a drain
    // assertion: `health_probes_concurrent` is stamped at hand-off, long
    // before the signal, so it states the *precondition* — that the drain
    // really did find more than one probe armed — and nothing else.
    //
    // The teardown is the oracle. A ladder that only ever advanced
    // `probes[0]` leaves its siblings' connects armed forever, and
    // `expectDrained` fails; that mutation is what substantiates this
    // test, not the `probe_count = 1` one, which is degenerate here
    // because with one probe there is no sibling to skip.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 133 },
        .check = .{ .timeout_ms = 50, .fall = 1 },
        .health_interval_ms = 20,
        .blackholed_endpoints = 3,
    });
    defer bed.tearDown();

    bed.sim_io.scheduleSignal(.terminate, bed.sim_io.nowNs() + 25 * std.time.ns_per_ms);
    try bed.sim_io.run();

    // The precondition: four probes, so the ladder had siblings to reach.
    try std.testing.expectEqual(@as(usize, 4), bed.server.health.probes.len);
    try std.testing.expectEqual(
        @as(u64, 3),
        bed.server.counters.get("health_probes_concurrent"),
    );
    // Mid-sweep: the silent dials had not reached their deadline, so the
    // drain — not a verdict — is what ended them, and nothing was ejected.
    try std.testing.expectEqual(@as(u32, 0), bed.server.health.unhealthy_count);
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("health_endpoint_down"));
    try std.testing.expect(bed.server.health.isQuiescent());
    try bed.expectDrained();
}

test "health: probes against a listening origin keep the endpoint healthy" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 71 },
        .check = .{ .timeout_ms = 50 },
        .health_interval_ms = 50,
    });
    defer bed.tearDown();

    // No clients: the prober is the only source of work. The terminate
    // signal ends the scenario the §8 way, which must leave the prober
    // quiescent and the pools untouched.
    bed.sim_io.scheduleSignal(.terminate, bed.sim_io.nowNs() + 120 * std.time.ns_per_ms);
    try bed.sim_io.run();

    // The immediate first sweep plus at least one interval-paced one,
    // all passing: no ejection, no counted failure, mask untouched.
    try std.testing.expect(bed.server.counters.get("health_probes_sent") >= 2);
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("health_probes_failed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("health_endpoint_down"));
    try std.testing.expect(bed.server.health.healthy[0]);
    try std.testing.expectEqual(@as(u32, 1), bed.server.health.checked_count);
    try std.testing.expectEqual(@as(u32, 0), bed.server.health.unhealthy_count);
    try bed.expectDrained();
}

test "health: consecutive refusals eject the endpoint" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 72 },
        .origin_listens = false,
        .check = .{ .timeout_ms = 50 },
        .health_interval_ms = 20,
    });
    defer bed.tearDown();

    // Nothing listens at the endpoint: every probe is refused. The third
    // consecutive miss (constants.health_probe_fall) ejects; later misses
    // keep counting probes but never re-eject.
    bed.sim_io.scheduleSignal(.terminate, bed.sim_io.nowNs() + 200 * std.time.ns_per_ms);
    try bed.sim_io.run();

    try std.testing.expect(bed.server.counters.get("health_probes_failed") >= 3);
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("health_endpoint_down"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("health_endpoint_up"));
    try std.testing.expect(!bed.server.health.healthy[0]);
    try std.testing.expectEqual(@as(u32, 1), bed.server.health.unhealthy_count);
    // The level reaches the scrape as a gauge, and the snapshot is valid.
    const gauges = bed.server.gauges();
    try std.testing.expectEqual(@as(u32, 1), gauges.health_endpoints_unhealthy);
    try std.testing.expectEqual(@as(u32, 1), gauges.health_endpoints_checked);
    try bed.expectDrained();
}

test "health: rise restores an ejected endpoint after passing probes" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 73 },
        .check = .{ .timeout_ms = 50 },
        .health_interval_ms = 20,
    });
    defer bed.tearDown();

    // Three injected dial faults fail exactly the first three probes —
    // ejecting the endpoint and witnessing §8 kernel pressure on the
    // probe path — then the listening origin answers, and the second
    // consecutive pass (constants.health_probe_rise) restores it.
    bed.sim_io.injectConnectError(TestBed.originAddress());
    bed.sim_io.injectConnectError(TestBed.originAddress());
    bed.sim_io.injectConnectError(TestBed.originAddress());
    bed.sim_io.scheduleSignal(.terminate, bed.sim_io.nowNs() + 160 * std.time.ns_per_ms);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 3), bed.server.counters.get("health_probes_failed"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("health_endpoint_down"));
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("health_endpoint_up"));
    try std.testing.expectEqual(@as(u64, 3), bed.server.counters.get("kernel_pressure_connect"));
    try std.testing.expect(bed.server.health.healthy[0]);
    try std.testing.expectEqual(@as(u32, 0), bed.server.health.unhealthy_count);
    try bed.expectDrained();
}

test "relay: an L4 connection charges its endpoint, and gives it back" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 12 } });
    defer bed.tearDown();

    // Sampled inside the origin's accept, which can only happen while the
    // dial that charged the endpoint is still live: the count must be up
    // by then. Without this the drain check below passes on a charge that
    // never happened.
    bed.scenario.origin.on_accept = Scenario.sampleL4Charge;
    bed.scenario.origin.context = &bed.scenario;

    bed.startClients(1, true);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u16, 1), bed.scenario.l4_sample);
    try std.testing.expectEqual(Client.Outcome.eof, bed.scenario.clients[0].outcome);
    // And back to zero afterwards — `expectDrained` asks the server, whose
    // idle check now covers the charge table for every scenario in this
    // file and every sim seed (§9).
    try std.testing.expectEqual(
        @as(u16, 0),
        bed.server.l4_inflight[bed.server.upstreams.keys.key(0, 0)],
    );
    try bed.expectDrained();
}

test "relay: a refused dial releases the endpoint charge it took" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 13 },
        // Nothing listens: the dial is charged at `armConnect` and then
        // refused, so the release rides a teardown that never relayed a
        // byte — the path where an unbalanced charge would hide.
        .origin_listens = false,
    });
    defer bed.tearDown();

    bed.startClients(1, true);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("upstream_connect_failed"));
    try std.testing.expect(bed.server.l4Released());
    try bed.expectDrained();
}

test "relay: an L4 connection past the endpoint cap is closed, not dialed" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 21 },
        // One in flight per endpoint against this bed's single endpoint.
        .max_inflight = 1,
        // Silent clients hold their charge until the idle deadline, so
        // the second one certainly meets a full endpoint rather than
        // racing the first one's completion.
        .idle_timeout_ms = 60,
    });
    defer bed.tearDown();

    bed.startClients(2, false);
    try bed.sim_io.run();

    // Exactly one was refused, and the origin only ever saw the other:
    // an L4 listener cannot say "try later", so the ladder's L4 answer
    // is a close (§8).
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("l4_shed_endpoint_inflight"));
    try std.testing.expectEqual(@as(u8, 1), bed.scenario.origin.conns_count);
    // Both were admitted and both completed: the refusal happens after
    // admission, so it must not disturb the gate identity (§8, §9).
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("completed"));
    try std.testing.expect(bed.server.reconcile());
    try bed.expectDrained();
}

test "tls: the engine pool hands out what the config provisioned, and no more" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 31 },
        .server = .{ .conn_slots = 4, .relay_buffers = 2, .tls_engines = 2 },
        .tls = true,
    });
    defer bed.tearDown();

    const credentials = &bed.tls_credentials[0].?;
    const first = try bed.server.acquireTlsEngine(credentials);
    const second = try bed.server.acquireTlsEngine(credentials);
    try std.testing.expect(first != second);
    // Exhausted at exactly the provisioned count: the wall a shed rung
    // will report is this null, not a larger pool than the banner priced.
    try std.testing.expectError(
        error.EnginesExhausted,
        bed.server.acquireTlsEngine(credentials),
    );

    // Each slot's plaintext destination is bound and sized by the engine's
    // own floor — a slot handed out unbound would fault on its first
    // decrypt, long after the mistake.
    for ([_]*TlsEngine{ first, second }) |engine| {
        try std.testing.expect(engine.plaintext.len >= TlsEngine.plaintext_bytes_min);
        try std.testing.expect(!engine.isConnected());
    }
    // Distinct buffers: two sessions decrypting into one would be a data
    // leak between connections, not merely a bug.
    try std.testing.expect(first.plaintext.ptr != second.plaintext.ptr);

    bed.server.releaseTlsEngine(first);
    const reused = try bed.server.acquireTlsEngine(credentials);
    try std.testing.expectEqual(first, reused);
    bed.server.releaseTlsEngine(reused);
    bed.server.releaseTlsEngine(second);
    try std.testing.expect(bed.server.tls_engines.isFullyReleased());
}

test "tls: two engines from one seed produce one handshake, replayed" {
    // The §9 property every TLS scenario rests on: a seeded run's key
    // material comes from the run's seed, so the same seed twice is the
    // same handshake twice. Checked at the seam that draws it, because a
    // pool that quietly used the OS CSPRNG would still pass every
    // functional test and fail every replay.
    var runs: [2][32]u8 = undefined;
    for (&runs) |*captured| {
        var bed: TestBed = undefined;
        try bed.setUp(std.testing.allocator, .{
            .sim = .{ .seed = 77 },
            .server = .{ .conn_slots = 4, .relay_buffers = 2, .tls_engines = 1 },
            .tls = true,
        });
        defer bed.tearDown();

        const engine = try bed.server.acquireTlsEngine(&bed.tls_credentials[0].?);
        // The ServerHello random is the engine's seeded input made
        // visible: it goes on the wire verbatim, so comparing it compares
        // what the peer would see.
        captured.* = engine.hs.random.data;
        bed.server.releaseTlsEngine(engine);
    }
    try std.testing.expectEqualSlices(u8, &runs[0], &runs[1]);
}

test "tls: a plaintext deployment reserves no engines at all" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 32 },
        .server = .{ .conn_slots = 4, .relay_buffers = 2 },
    });
    defer bed.tearDown();

    // Zero slots, not one held back: `limits.tls_engines` is zero exactly
    // when nothing terminates, and the pool is what makes that free (§5).
    try std.testing.expectEqual(@as(usize, 0), bed.server.tls_engines.slots.len);
    try std.testing.expect(bed.server.tls_engines.isFullyReleased());
}

test "tls: what the pool holds is what the budget priced" {
    // §5's promise is that the startup banner's total covers every byte
    // this process holds for its life. That is only true if the engine
    // pool's actual reservation equals the term `memoryBytesTotal` prices
    // it at — two numbers computed in different files from the same
    // limits, which is exactly the pair that drifts.
    const engines: u32 = 3;
    const head_bytes = constants.head_buffer_bytes_default;

    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 33 },
        .server = .{
            .conn_slots = 4,
            .relay_buffers = 2,
            .head_buffer_bytes = head_bytes,
            .tls_engines = engines,
        },
        .tls = true,
    });
    defer bed.tearDown();

    // What was actually reserved: the slots themselves, plus every slot's
    // share of the plaintext slab, read off the engines rather than
    // recomputed — a slot bound to the wrong-sized slice shows up here.
    var held: u64 = @as(u64, engines) * @sizeOf(TlsEngine);
    for (bed.server.tls_engines.slots) |*engine| {
        // Both destinations: a slot holds the head's and the body's, which
        // is what `plaintextBytesFor` prices as one number.
        held += engine.plaintext.len + engine.body_plaintext.len;
    }

    // What the budget charges for it. `memoryBytesTotal`'s TLS term with
    // the libcrypto heap left out — that one is `main`'s to reserve before
    // the server exists, so a bed that never installs it is not charged.
    const priced = @as(u64, engines) *
        (@sizeOf(TlsEngine) + TlsEngine.plaintextBytesFor(head_bytes));
    try std.testing.expectEqual(priced, held);
    try std.testing.expectEqual(@as(usize, engines), bed.server.tls_engines.slots.len);
}

test "tls: an operator's head size widens the plaintext buffer, and is priced" {
    // The one runtime input to the engine's footprint. An L7 head
    // accumulates until the parser is satisfied, so a slot has to cover
    // `limits.head_buffer_bytes` when that exceeds the engine's own floor
    // — and the banner has to charge for the same widening.
    const wide_head = TlsEngine.plaintext_bytes_min * 2;
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 34 },
        .server = .{
            .conn_slots = 4,
            .relay_buffers = 2,
            .head_buffer_bytes = wide_head,
            .tls_engines = 1,
        },
        .tls = true,
    });
    defer bed.tearDown();

    const engine = &bed.server.tls_engines.slots[0];
    // The head destination follows the operator's size; the body's keeps
    // the engine's own floor, because a body never has to hold a head.
    try std.testing.expectEqual(@as(usize, wide_head), engine.plaintext.len);
    try std.testing.expectEqual(TlsEngine.plaintext_bytes_min, engine.body_plaintext.len);
    // Distinct regions: the two legs run concurrently (§7), so a slot that
    // handed the same slice twice would let a request-body chunk clobber
    // the response head still being written out of it.
    try std.testing.expect(engine.plaintext.ptr != engine.body_plaintext.ptr);
    try std.testing.expectEqual(
        wide_head + TlsEngine.plaintext_bytes_min,
        TlsEngine.plaintextBytesFor(wide_head),
    );
}

test "tls: an L4 listener terminates, and relays the plaintext both ways" {
    // The whole promise in one scenario: a real ztls client handshakes
    // against the proxy, sends application data, and the origin — which
    // knows nothing about TLS — echoes plaintext that comes back
    // encrypted. Every byte crosses the transform twice.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 41 },
        .server = .{ .conn_slots = 4, .relay_buffers = 2, .tls_engines = 2 },
        .tls = true,
    });
    defer bed.tearDown();

    var client: TlsClient = undefined;
    try client.start(&bed.sim_io, TestBed.bindAddress(), .{
        .host_name = fixture_host_name,
        .app_data = echo_token,
        .close_after_echo = true,
    });
    var wind_down: TlsWindDown = .{ .bed = &bed, .expected = 1 };
    wind_down.attach(&client);
    try bed.sim_io.run();

    try std.testing.expectEqual(
        @as(u64, 1),
        bed.server.counters.get("tls_handshakes_completed"),
    );
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("tls_handshake_failed"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("tls_relay_failed"));
    // The payload made the full round trip in plaintext, through an
    // origin that never saw a TLS record.
    try std.testing.expectEqualStrings(
        echo_token,
        client.app_received[0..client.app_received_len],
    );
    try std.testing.expect(bed.server.reconcile());
    try bed.expectDrained();
}

test "tls: bytes that are not a handshake are counted, not mistaken for pressure" {
    // The realistic failure: something that is not a TLS client reaches a
    // terminating listener — a plaintext client on the wrong port, a
    // scanner, a health check aimed at the wrong socket. It must be a
    // counted handshake failure and a clean teardown, never §8 pressure,
    // because nothing here is under strain.
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 42 },
        .server = .{ .conn_slots = 4, .relay_buffers = 2, .tls_engines = 2 },
        .tls = true,
    });
    defer bed.tearDown();

    // The plaintext client sends `echo_token` — perfectly good bytes, and
    // not a ClientHello.
    bed.startClients(1, true);
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("tls_handshake_failed"));
    try std.testing.expectEqual(
        @as(u64, 0),
        bed.server.counters.get("tls_handshakes_completed"),
    );
    // The origin was never dialed: a session that never came up has no
    // plaintext to relay, so no backend should have heard about it.
    try std.testing.expectEqual(@as(u8, 0), bed.scenario.origin.conns_count);
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("kernel_pressure_recv"));
    try std.testing.expect(bed.server.reconcile());
    try bed.expectDrained();
}

test "tls: engine exhaustion sheds at admission, before the gate identity" {
    var bed: TestBed = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 43 },
        // One engine, two clients: the second meets the §8 wall.
        .server = .{ .conn_slots = 4, .relay_buffers = 2, .tls_engines = 1 },
        .tls = true,
        // Silent clients hold their engine to the deadline, so the second
        // certainly meets a full pool rather than racing the first's exit.
        .idle_timeout_ms = 60,
    });
    defer bed.tearDown();

    var clients: [2]TlsClient = undefined;
    var wind_down: TlsWindDown = .{ .bed = &bed, .expected = clients.len };
    for (&clients) |*client| {
        try client.start(&bed.sim_io, TestBed.bindAddress(), .{ .host_name = fixture_host_name });
        wind_down.attach(client);
    }
    try bed.sim_io.run();

    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("shed_tls_engines"));
    // A shed at admission never counted `admitted`, which is what keeps
    // the reconcile identity exact (§9) — and the libcrypto rung stays at
    // zero, because engines are what ran out, not the heap.
    try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("admitted"));
    try std.testing.expectEqual(@as(u64, 2), bed.server.counters.get("accepted"));
    try std.testing.expectEqual(@as(u64, 0), bed.server.counters.get("shed_tls_crypto"));
    // The relay buffer the shed connection had already taken went back:
    // this is the first rung that fires holding one, so a leak here would
    // cost a buffer per refused session rather than being harmless.
    try std.testing.expect(bed.server.relay_buffers.isFullyReleased());
    try std.testing.expect(bed.server.reconcile());
    try bed.expectDrained();
}
