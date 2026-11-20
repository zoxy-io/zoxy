//! A test bed for a build on the library (#417): the build's options
//! resolved, a server over the simulator (`SimIo`, §9) with the build's
//! own extensions, an HTTP origin on every endpoint address the options
//! name, and HTTP clients a test drives. Exported as `zoxy.testing`, so a
//! custom build runs its pickers and policies through the same serving
//! path, the same deterministic scheduler and the same zero-allocation
//! gate zoxy runs its own through.
//!
//! What the bed models, and what it does not:
//! - every origin answers each request head with `200` and its own
//!   address as the body, so a test reads which endpoint a pick chose
//!   from the response alone — and closes the connection, so no exchange
//!   depends on pooling; a request body is not read;
//! - listeners are plaintext HTTP bound to IP addresses — no TLS, no l4 —
//!   and endpoints are IP addresses (a `unix:` endpoint is the stock
//!   simulator's to cover);
//! - no adversary: no injected resets, faults or short reads, so the seed
//!   shapes delivery order and timer jitter, not failures;
//! - a client sends its bytes as given and closes once one response is
//!   complete; the last client to finish begins the drain, which is what
//!   ends `run` — so a bed runs once;
//! - at most `clients_max` clients, `origins_max` endpoint addresses, and
//!   `origin_conns_max` connections open on one origin; a connection past
//!   that is refused, as a full origin would.
//!
//! The gate (`expectNoAllocationAfterStartup`) runs a scenario twice under
//! one seed, and the second run must replay the first exactly — the
//! simulator's own trace of every delivery, the same in both — so a
//! picker or policy that reads a clock or keeps its own randomness fails
//! it. Both runs select the same extension instances: state an instance
//! keeps carries from the first run into the second.
//!
//! A `Bed` is the size of its fixed tables, a few hundred KiB beside the
//! server and the simulator: allocate one rather than declare it on a
//! test's stack, as the gate does.

const std = @import("std");

const config_module = @import("../config.zig");
const extension = @import("../extension.zig");
const Options = @import("../Options.zig");
const Server = @import("../Server.zig").Server;
const SimIo = @import("../io/SimIo.zig");
const Io = @import("../io/io.zig");
const constants = @import("../constants.zig");
const parser = @import("../http/parser.zig");

const assert = std.debug.assert;

/// Clients one scenario may start.
pub const clients_max = 16;
/// Distinct endpoint addresses the bed puts an origin on.
pub const origins_max = 8;
/// Connections one origin holds at once: a request's, or a probe's.
const origin_conns_max = 16;
/// The widest request head an origin reads, and the widest response a
/// client keeps — both are the bed's own small answers or the proxy's.
const origin_head_bytes_max = 1024;
const client_receive_bytes_max = 4096;
/// `255.255.255.255:65535`, or a bracketed IPv6 literal and port.
const label_bytes_max = 64;

/// The bed for a build listing `extensions`.
pub fn Bed(comptime extensions: extension.Extensions) type {
    return struct {
        const Self = @This();
        pub const runtime: extension.Runtime = .{ .Io = SimIo, .extensions = extensions };
        pub const ServerType = Server(runtime);

        arena_state: std.heap.ArenaAllocator,
        sim_io: SimIo,
        config: config_module.Config,
        server: ServerType,
        origins: [origins_max]Origin,
        origins_count: u8,
        clients: [clients_max]Client,
        clients_count: u8,
        clients_open: u8,
        ran: bool,

        comptime {
            // Every client and every origin connection is a simulated
            // socket, and so is each one the server opens for it.
            assert(2 * (clients_max + origins_max * origin_conns_max) <= SimIo.sockets_max);
        }

        /// Resolve `options`, start the server and an origin on every
        /// endpoint address, under `seed`. Everything allocates here, from
        /// `gpa`, and nothing after: the gate holds a scenario to that.
        /// The resolved config points into `options` and into the
        /// extension instances it selects, so all of them outlive the bed.
        pub fn setUp(bed: *Self, gpa: std.mem.Allocator, options: *const Options, seed: u64) !void {
            bed.arena_state = .init(gpa);
            errdefer bed.arena_state.deinit();
            const arena = bed.arena_state.allocator();
            bed.config = try config_module.resolve(arena, options);
            const limits = bed.config.limits;
            try bed.sim_io.init(arena, .{
                .seed = seed,
                // One number on both sides (§5): the ring the simulator
                // registers is the one the server accounts against.
                .buffer_group_count = limits.head_buffers,
                .buffer_group_bytes = limits.head_buffer_bytes,
            });
            try bed.server.init(arena, &bed.sim_io, &bed.config, limits);
            try bed.server.bindExtensions(&.{ .arena = arena });
            bed.clients_count = 0;
            bed.clients_open = 0;
            bed.ran = false;
            try bed.startOrigins();
            try bed.server.start();
            assert(bed.origins_count >= 1);
            assert(bed.clients_open == 0);
        }

        pub fn tearDown(bed: *Self) void {
            for (bed.origins[0..bed.origins_count]) |*origin| origin.closeRemaining();
            bed.arena_state.deinit();
        }

        /// Start a client that connects to listener `listener_index` and
        /// sends `bytes` — a whole request, as the wire carries it. The
        /// client runs with the next `run`; read its answer after.
        pub fn request(bed: *Self, listener_index: u16, bytes: []const u8) *Client {
            assert(listener_index < bed.config.listeners.len);
            assert(bed.clients_count < clients_max);
            assert(!bed.ran); // A run drains the server: a bed runs once.
            assert(bytes.len >= 1);
            const bind = bed.config.listeners[listener_index].bind_address;
            assert(bind == .ip); // The bed binds IP listeners only.
            const client = &bed.clients[bed.clients_count];
            bed.clients_count += 1;
            bed.clients_open += 1;
            client.* = .{ .bed = bed, .request = bytes };
            bed.sim_io.connect(&bind, &client.connect_completion, Client, client, Client.onConnect);
            return client;
        }

        /// Run every started client to its end, then the drain the last
        /// one began, to quiescence; the pools must be drained after.
        pub fn run(bed: *Self) !void {
            assert(bed.clients_open >= 1);
            assert(!bed.ran);
            bed.ran = true;
            try bed.sim_io.run();
            assert(bed.clients_open == 0);
            for (bed.origins[0..bed.origins_count]) |*origin| {
                origin.stopListening();
                origin.closeRemaining();
            }
            try std.testing.expect(bed.server.isIdle());
            try std.testing.expect(bed.server.reconcile());
            try std.testing.expect(bed.sim_io.sockets.isFullyReleased());
        }

        /// The simulator's trace of every delivery this run made: equal for
        /// two runs of one scenario under one seed, or something in them
        /// was not a function of what it was given (§9).
        pub fn trace(bed: *const Self) u64 {
            assert(bed.ran);
            return bed.sim_io.trace_hash;
        }

        /// A build's own counter (#435), summed over every site that
        /// selects its type: the series the metrics endpoint renders, as
        /// this run left them. Each run starts from zero, so a test reads
        /// what its own scenario counted.
        pub fn counter(
            bed: *const Self,
            comptime Extension: type,
            comptime name: extension.CounterName(Extension),
        ) u64 {
            return bed.server.extension_metrics.counterTotal(Extension, name);
        }

        /// How many requests the origin at `endpoint` answered.
        pub fn answered(bed: *const Self, endpoint: std.Io.net.IpAddress) u32 {
            for (bed.origins[0..bed.origins_count]) |*origin| {
                if (origin.address.eql(&endpoint)) return origin.answered;
            }
            return 0;
        }

        fn clientDone(bed: *Self) void {
            assert(bed.clients_open >= 1);
            bed.clients_open -= 1;
            if (bed.clients_open == 0) bed.server.beginDrain();
        }

        fn startOrigins(bed: *Self) !void {
            bed.origins_count = 0;
            for (bed.config.clusters) |*cluster| {
                for (cluster.endpoints) |*endpoint| {
                    const address = switch (endpoint.*) {
                        .ip => |ip| ip,
                        .unix => return error.BedUnixEndpoint,
                    };
                    if (bed.hasOrigin(address)) continue;
                    if (bed.origins_count == origins_max) return error.BedOriginsOverLimit;
                    const origin = &bed.origins[bed.origins_count];
                    bed.origins_count += 1;
                    try origin.start(&bed.sim_io, address);
                }
            }
            assert(bed.origins_count <= origins_max);
        }

        fn hasOrigin(bed: *const Self, address: std.Io.net.IpAddress) bool {
            for (bed.origins[0..bed.origins_count]) |*origin| {
                if (origin.address.eql(&address)) return true;
            }
            return false;
        }

        /// One client: connect, send the request, read one response, and
        /// close — or record the close the proxy chose first.
        pub const Client = struct {
            bed: *Self,
            request: []const u8,
            connect_completion: SimIo.Completion = .{},
            send_completion: SimIo.Completion = .{},
            recv_completion: SimIo.Completion = .{},
            socket: SimIo.Socket = undefined,
            sent_len: u32 = 0,
            send_in_flight: bool = false,
            receive_buffer: [client_receive_bytes_max]u8 = undefined,
            received_len: u32 = 0,
            connected: bool = false,
            /// The exchange is over from this end: answered, refused, or closed.
            ended: bool = false,
            /// Ended, its last send landed, and its socket closed.
            finished: bool = false,

            /// Everything that came back: head and body.
            pub fn response(client: *const Client) []const u8 {
                assert(client.received_len <= client.receive_buffer.len);
                return client.receive_buffer[0..client.received_len];
            }

            /// The response's status, or null when none arrived whole.
            pub fn status(client: *const Client) ?u16 {
                const response_head = client.parsedHead() orelse return null;
                return response_head.status;
            }

            /// The response's body, framed by its `Content-Length`.
            pub fn body(client: *const Client) []const u8 {
                const response_head = client.parsedHead() orelse return "";
                const end = @min(client.received_len, @as(u64, response_head.head_len) + bodyLenOf(&response_head));
                return client.receive_buffer[response_head.head_len..end];
            }

            fn parsedHead(client: *const Client) ?parser.ResponseHead {
                var storage: parser.HeaderStorage = undefined;
                const visible = @min(client.received_len, constants.head_buffer_bytes_max);
                return parser.parseResponseHead(
                    client.receive_buffer[0..visible],
                    false,
                    &storage,
                    .get,
                ) catch null;
            }

            /// Saturated at what a client can hold: a length the proxy got
            /// wrong is a short body to compare, not a panic in the bed.
            fn bodyLenOf(response_head: *const parser.ResponseHead) u32 {
                const length: u64 = switch (response_head.framing) {
                    .content_length => |length| length,
                    else => 0,
                };
                return @intCast(@min(length, client_receive_bytes_max));
            }

            fn complete(client: *const Client) bool {
                const response_head = client.parsedHead() orelse return false;
                return client.received_len >= @as(u64, response_head.head_len) + bodyLenOf(&response_head);
            }

            fn onConnect(client: *Client, result: Io.ConnectError!SimIo.Socket) void {
                client.socket = result catch {
                    client.ended = true;
                    client.finish();
                    return;
                };
                client.connected = true;
                client.armRecv();
                client.armSend();
            }

            fn armSend(client: *Client) void {
                assert(client.sent_len < client.request.len);
                assert(!client.send_in_flight);
                client.send_in_flight = true;
                client.bed.sim_io.send(
                    client.socket,
                    client.request[client.sent_len..],
                    &client.send_completion,
                    Client,
                    client,
                    onSend,
                );
            }

            fn onSend(client: *Client, result: Io.SendError!u32) void {
                client.send_in_flight = false;
                // A refusal may close before the request is all sent.
                const sent = result catch {
                    client.finish();
                    return;
                };
                client.sent_len += sent;
                assert(client.sent_len <= client.request.len);
                if (client.sent_len < client.request.len and !client.ended) {
                    client.armSend();
                    return;
                }
                client.finish();
            }

            fn armRecv(client: *Client) void {
                assert(client.received_len < client.receive_buffer.len);
                client.bed.sim_io.recv(
                    client.socket,
                    client.receive_buffer[client.received_len..],
                    &client.recv_completion,
                    Client,
                    client,
                    onRecv,
                );
            }

            fn onRecv(client: *Client, result: Io.RecvError!u32) void {
                const received = result catch {
                    client.ended = true;
                    client.finish();
                    return;
                };
                assert(received >= 1);
                client.received_len += received;
                assert(client.received_len <= client.receive_buffer.len);
                // One response is the whole exchange: hang up once it is
                // in, as an ordinary client would, rather than wait for an
                // idle sweep to end a connection kept alive.
                if (client.complete() or client.received_len == client.receive_buffer.len) {
                    client.ended = true;
                    client.finish();
                    return;
                }
                client.armRecv();
            }

            /// Whichever of the close and the last send lands second ends
            /// the client: closing under a pending send would leave the
            /// simulator a stale handle.
            fn finish(client: *Client) void {
                if (client.finished) return;
                if (!client.ended) return;
                if (client.send_in_flight) return;
                client.finished = true;
                if (client.connected) client.bed.sim_io.closeNow(client.socket);
                client.bed.clientDone();
            }
        };

        /// An origin on one endpoint address: answers every request head
        /// with `200` and the address it listens on.
        const Origin = struct {
            io: *SimIo = undefined,
            address: std.Io.net.IpAddress = undefined,
            listener: SimIo.Listener = undefined,
            accept_completion: SimIo.Completion = .{},
            listening: bool = false,
            conns: [origin_conns_max]OriginConn = @splat(.{}),
            answered: u32 = 0,
            answer: [answer_bytes_max]u8 = undefined,
            answer_len: u16 = 0,

            const answer_bytes_max = 128 + label_bytes_max;

            fn start(origin: *Origin, io: *SimIo, address: std.Io.net.IpAddress) !void {
                origin.* = .{ .io = io, .address = address };
                var label_buffer: [label_bytes_max]u8 = undefined;
                const label = std.fmt.bufPrint(&label_buffer, "{f}", .{address}) catch unreachable;
                const answer = std.fmt.bufPrint(
                    &origin.answer,
                    "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
                    .{ label.len, label },
                ) catch unreachable;
                origin.answer_len = @intCast(answer.len);
                assert(!origin.listening);
                origin.listener = try io.listen(&.{ .ip = address }, null);
                origin.listening = true;
                origin.armAccept();
                assert(origin.answer_len >= label.len);
            }

            fn armAccept(origin: *Origin) void {
                origin.io.accept(origin.listener, &origin.accept_completion, Origin, origin, onAccept);
            }

            fn onAccept(origin: *Origin, result: Io.AcceptError!SimIo.Socket) void {
                const socket = result catch |err| switch (err) {
                    // The listener closed: the run is over.
                    error.Canceled => return,
                    error.Unexpected => {
                        origin.armAccept();
                        return;
                    },
                };
                const conn = origin.freeConn() orelse {
                    // More at once than the bed holds: refuse it, as an
                    // origin out of room would.
                    origin.io.closeNow(socket);
                    origin.armAccept();
                    return;
                };
                conn.* = .{ .origin = origin, .socket = socket, .open = true };
                conn.armRecv();
                origin.armAccept();
            }

            fn freeConn(origin: *Origin) ?*OriginConn {
                for (&origin.conns) |*conn| {
                    if (!conn.open) return conn;
                }
                return null;
            }

            fn stopListening(origin: *Origin) void {
                if (!origin.listening) return;
                origin.io.listenClose(origin.listener);
                origin.listening = false;
            }

            fn closeRemaining(origin: *Origin) void {
                for (&origin.conns) |*conn| {
                    if (conn.open) conn.close();
                }
            }
        };

        const OriginConn = struct {
            origin: *Origin = undefined,
            socket: SimIo.Socket = undefined,
            recv_completion: SimIo.Completion = .{},
            send_completion: SimIo.Completion = .{},
            head: [origin_head_bytes_max]u8 = undefined,
            head_len: u16 = 0,
            sent_len: u16 = 0,
            open: bool = false,

            fn armRecv(conn: *OriginConn) void {
                assert(conn.open);
                assert(conn.head_len < conn.head.len);
                conn.origin.io.recv(
                    conn.socket,
                    conn.head[conn.head_len..],
                    &conn.recv_completion,
                    OriginConn,
                    conn,
                    onRecv,
                );
            }

            fn onRecv(conn: *OriginConn, result: Io.RecvError!u32) void {
                const received = result catch {
                    // A probe that only connects, or a proxy that gave
                    // up: nothing to answer.
                    conn.close();
                    return;
                };
                conn.head_len += @intCast(received);
                assert(conn.head_len <= conn.head.len);
                if (std.mem.indexOf(u8, conn.head[0..conn.head_len], "\r\n\r\n") == null) {
                    if (conn.head_len == conn.head.len) {
                        conn.close();
                        return;
                    }
                    conn.armRecv();
                    return;
                }
                conn.armSend();
            }

            fn armSend(conn: *OriginConn) void {
                const answer = conn.origin.answer[0..conn.origin.answer_len];
                assert(conn.sent_len < answer.len);
                conn.origin.io.send(
                    conn.socket,
                    answer[conn.sent_len..],
                    &conn.send_completion,
                    OriginConn,
                    conn,
                    onSend,
                );
            }

            fn onSend(conn: *OriginConn, result: Io.SendError!u32) void {
                const sent = result catch {
                    conn.close();
                    return;
                };
                conn.sent_len += @intCast(sent);
                assert(conn.sent_len <= conn.origin.answer_len);
                if (conn.sent_len < conn.origin.answer_len) {
                    conn.armSend();
                    return;
                }
                conn.origin.answered += 1;
                conn.close();
            }

            fn close(conn: *OriginConn) void {
                assert(conn.open);
                conn.origin.io.closeNow(conn.socket);
                conn.open = false;
            }
        };
    };
}

/// The §9 zero-allocation gate over a build's own scenario (#417): run it
/// once counting, and require that nothing past startup allocated or
/// grew; then again with every allocation and every resize past startup
/// failing, and require that it still passes — so the equality is
/// structural, not a count that happened to match — and that it replays
/// the first run's trace exactly, so the scenario is deterministic under
/// its seed. `scenario` starts requests on the bed it is handed, runs it,
/// and checks what it wants of the answers.
///
/// Startup is measured in each run rather than carried from the first:
/// how many allocations it takes depends on whether the arena's chunks
/// grew in place, which is the backing heap's to say, not the bed's.
pub fn expectNoAllocationAfterStartup(
    comptime BedType: type,
    options: *const Options,
    seed: u64,
    scenario: *const fn (bed: *BedType) anyerror!void,
) !void {
    const counted = try runGated(BedType, options, seed, scenario, .counting);
    const strict = try runGated(BedType, options, seed, scenario, .strict);
    try std.testing.expectEqual(counted.trace, strict.trace);
}

const Gated = struct {
    trace: u64,
};

const GateMode = enum { counting, strict };

fn runGated(
    comptime BedType: type,
    options: *const Options,
    seed: u64,
    scenario: *const fn (bed: *BedType) anyerror!void,
    mode: GateMode,
) !Gated {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    // On the heap rather than the stack: a bed is the size of its fixed
    // tables, and the gate's allocator is the one under test.
    const bed = try std.testing.allocator.create(BedType);
    defer std.testing.allocator.destroy(bed);
    try bed.setUp(failing.allocator(), options, seed);
    defer bed.tearDown();
    const startup_allocations = failing.allocations;
    const startup_resizes = failing.resize_index;
    if (mode == .strict) {
        // From here on, every allocation and every growth fails.
        failing.fail_index = failing.alloc_index;
        failing.resize_fail_index = failing.resize_index;
    }
    try scenario(bed);
    assert(bed.ran); // A scenario runs its bed.
    try std.testing.expectEqual(startup_allocations, failing.allocations);
    try std.testing.expectEqual(startup_resizes, failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
    return .{ .trace = bed.trace() };
}

const ScriptedPicker = @import("picker.zig").ScriptedPicker;
const ScriptedPolicy = @import("policy.zig").ScriptedPolicy;
const defaults = @import("../defaults.zig");

const TestBed = Bed(.{ .pickers = &.{ScriptedPicker}, .request_policies = &.{ScriptedPolicy} });
var test_picker: ScriptedPicker = .{ .choice = .last };
var test_policy: ScriptedPolicy = .{ .reject_prefix = "/deny" };

fn loopback(port: u16) std.Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
}

/// Static, because the resolved config points into the options' memory
/// for the bed's whole life — options built in a function's frame would
/// be gone by the time the server read them.
const test_options: Options = .{
    .listeners = &.{.{
        .bind = .{ .ip = loopback(18080) },
        .protocol = .{ .http = .{
            .target = .{ .cluster = "origin" },
            .request_policies = &.{extension.select(&.{ScriptedPolicy}, &test_policy)},
            .max_body_bytes = defaults.max_body_bytes,
            .keepalive_requests = defaults.keepalive_requests,
        } },
    }},
    .clusters = &.{.{
        .name = "origin",
        .endpoints = &.{
            .{ .address = .{ .ip = loopback(19101) } },
            .{ .address = .{ .ip = loopback(19102) } },
        },
        .pick = .{ .extension = extension.select(&.{ScriptedPicker}, &test_picker) },
    }},
    .timeouts = defaults.timeouts,
    .limits = defaults.limits,
};

fn pickAndRefuse(bed: *TestBed) !void {
    const served = bed.request(0, "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    const refused = bed.request(0, "GET /deny HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    try bed.run();
    // The picker answered the last slot, and the endpoint there answered.
    try std.testing.expectEqual(@as(?u16, 200), served.status());
    try std.testing.expectEqualStrings("127.0.0.1:19102", served.body());
    // The policy refused before any origin was dialed.
    try std.testing.expectEqual(@as(?u16, 403), refused.status());
    try std.testing.expectEqual(@as(u32, 1), bed.answered(loopback(19102)));
    try std.testing.expectEqual(@as(u32, 0), bed.answered(loopback(19101)));
}

test "Bed: a build's picker chooses and its policy refuses, through the serving path (#417)" {
    const bed = try std.testing.allocator.create(TestBed);
    defer std.testing.allocator.destroy(bed);
    try bed.setUp(std.testing.allocator, &test_options, 1);
    defer bed.tearDown();
    try pickAndRefuse(bed);
}

test "Bed: the gate holds a build's scenario to zero allocations after startup (#417)" {
    try expectNoAllocationAfterStartup(TestBed, &test_options, 7, pickAndRefuse);
}
