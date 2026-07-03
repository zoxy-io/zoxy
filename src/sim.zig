//! Deterministic simulator (docs/DESIGN.md: TigerBeetle's VOPR idea). Runs
//! the real proxy data path — ProxyServer, ProxyConn, the pools, the parsers
//! — against the simulation IO backend: virtual sockets, a virtual clock,
//! and a seeded scheduler that completes one operation at a time with
//! adversarial partial reads/writes. Virtual clients and misbehaving virtual
//! origins generate randomized workloads; the seed replays everything.
//!
//!     zig build sim                 # seeds 0..50
//!     zig build sim -- 1234 200     # seeds 1234..1434
//!     zig build sim -- fuzz         # random seeds, forever (Ctrl-C to stop)
//!
//! Each iteration draws a fault profile: no faults (half the time, so the
//! traffic-flow invariant stays strong), a drizzle of RSTs, an RST storm, or
//! connect refusals — abrupt connection death at every possible point of
//! the state machine, not just polite FINs.
//!
//! Checked invariants, every iteration:
//! - progress: the loop never deadlocks (`error.WouldBlockForever`) and
//!   never exceeds the step cap;
//! - every byte stream a client receives parses as an HTTP/1.1 response and
//!   frames correctly (RFC 9112 §6.3) — whatever the origin or network did;
//! - response integrity: every request carries a unique token that the
//!   origin echoes into the body; a completed 200 must return *this*
//!   request's token, byte-exact for length-framed bodies — catching
//!   truncation, reordering, and cross-connection contamination (stray
//!   bytes on a pooled upstream would surface here);
//! - all connection slots return to the pool, and `metrics.active` is zero,
//!   once every client is gone: no leaks under any schedule.

pub const zoxy_io = .simulation;

const std = @import("std");
const posix = std.posix;
const assert = std.debug.assert;

const io_mod = @import("io/io.zig");
const test_io = @import("io/test_io.zig"); // same file the seam selects here
const IO = io_mod.IO;
const Completion = io_mod.Completion;
const constants = @import("constants.zig");
const config_mod = @import("config.zig");
const h1 = @import("http/h1.zig");
const Router = @import("proxy/router.zig").Router;
const proxy_mod = @import("net/proxy.zig");
const ProxyServer = proxy_mod.ProxyServer;
const ConnPool = proxy_mod.ConnPool;
const Listener = @import("net/listener.zig").Listener;
const Metrics = @import("obs/metrics.zig").Metrics;
const AccessLog = @import("obs/access_log.zig").AccessLog;

const proxy_port = 8080;
const origin_ports = [_]u16{ 9001, 9002, 9003 };
const clients_max = 12;
const connection_pool_capacity = 6;
const step_cap = 500_000;
const iterations_default = 50;

/// The seed being run, for panic messages from any depth.
var current_seed: u64 = 0;

/// Every panic — including an assert deep inside proxy code, which never
/// goes through `fail` — must name the seed, or the schedule is lost.
pub const panic = std.debug.FullPanic(sim_panic);

fn sim_panic(message: []const u8, first_trace_address: ?usize) noreturn {
    std.debug.print("sim: seed {d} FAILED — replay: zig build sim -- {d} 1\n", .{
        current_seed,
        current_seed,
    });
    std.debug.defaultPanic(message, first_trace_address);
}

fn fail(comptime message: []const u8, extra: anytype) noreturn {
    std.debug.panic("sim: seed {d} FAILED: " ++ message, .{current_seed} ++ extra);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len > 1 and std.mem.eql(u8, args[1], "fuzz")) return fuzz(init.io);
    const seed_base: u64 = if (args.len > 1) try std.fmt.parseInt(u64, args[1], 10) else 0;
    const iterations: u64 =
        if (args.len > 2) try std.fmt.parseInt(u64, args[2], 10) else iterations_default;
    assert(iterations > 0);

    std.debug.print("sim: seeds {d}..{d}\n", .{ seed_base, seed_base + iterations });
    var responses_total: u64 = 0;
    var iteration: u64 = 0;
    while (iteration < iterations) : (iteration += 1) {
        responses_total += try run_iteration(seed_base + iteration);
    }
    assert(responses_total > 0); // traffic actually flowed
    std.debug.print(
        "sim: OK — {d} iterations, {d} framed responses verified\n",
        .{ iterations, responses_total },
    );
}

/// Run forever on entropy-derived seeds. Each iteration is still fully
/// deterministic from its seed — the panic handler prints it on failure.
/// (`process_io` is the process's std.Io, used once for the seed; the
/// simulation runs on its own virtual IO.)
fn fuzz(process_io: std.Io) !void {
    var entropy: [8]u8 = undefined;
    process_io.random(&entropy);
    const seed_base = std.mem.readInt(u64, &entropy, .little);
    std.debug.print("sim: fuzzing from seed base {d}\n", .{seed_base});
    var responses_total: u64 = 0;
    var iteration: u64 = 0;
    while (true) : (iteration += 1) {
        responses_total += try run_iteration(seed_base +% iteration);
        if ((iteration + 1) % 500 == 0) {
            std.debug.print("sim: fuzz {d} iterations, {d} responses verified, at seed {d}\n", .{
                iteration + 1,
                responses_total,
                seed_base +% iteration,
            });
        }
    }
}

fn run_iteration(seed: u64) !u64 {
    current_seed = seed;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var io = try IO.init_simulation(arena, seed);
    var workload = Workload{ .prng = std.Random.DefaultPrng.init(seed +% 0x9E3779B97F4A7C15) };
    io.faults = workload.fault_profile();

    // per_try_timeout (2s virtual, under the 5s request timeout) puts the
    // attempt-abort/drain machinery under every seed's schedule: black-holed
    // connects get cancelled, stalled attempts answer 504 instead of hanging
    // to the overall deadline.
    var cfg = try config_mod.parse(arena,
        \\{ "listen": "127.0.0.1:8080",
        \\  "routes": [ { "path_prefix": "/a", "cluster": "one" }, { "cluster": "two" } ],
        \\  "clusters": [
        \\    { "name": "one", "endpoints": ["127.0.0.1:9001", "127.0.0.1:9002"],
        \\      "per_try_timeout_ms": 2000,
        \\      "retry": { "max": 2, "backoff_base_ms": 50, "backoff_cap_ms": 400 } },
        \\    { "name": "two", "endpoints": ["127.0.0.1:9003"],
        \\      "per_try_timeout_ms": 2000,
        \\      "retry": { "max": 2, "backoff_base_ms": 50, "backoff_cap_ms": 400 } }
        \\  ] }
    );
    const router = Router.init(&cfg);

    const origins = try arena.alloc(Origin, origin_ports.len);
    for (origins, origin_ports) |*origin, port| {
        origin.* = .{
            .io = &io,
            .arena = arena,
            .workload = &workload,
            .listener_fd = io.open_listener(port),
        };
        origin.start();
    }

    var pool = try ConnPool.init(arena, connection_pool_capacity);
    var metrics = Metrics{};
    var access = AccessLog{ .fd = -1 }; // records accumulate, flushes are no-ops
    var server = ProxyServer.init(
        &io,
        &pool,
        Listener{ .fd = io.open_listener(proxy_port) },
        &router,
        &metrics,
        &access,
        5 * std.time.ns_per_s, // request timeout (virtual time)
        10 * std.time.ns_per_s, // idle timeout (virtual time)
    );
    // The balancer's PRNG derives from the iteration seed: same seed, same
    // P2C draws, same schedule — determinism end to end.
    server.prng = .init(seed +% 0x853C49E6748FEA9B);
    server.start();

    const clients = try arena.alloc(Client, clients_max);
    for (clients, 0..) |*client, index| {
        client.* = .{
            .io = &io,
            .workload = &workload,
            .id = @intCast(index),
            .strict_until_close = io.faults.reset_ppm == 0,
        };
        client.begin();
    }

    // Drive until every client concluded, then until the proxy reclaimed
    // every slot (teardowns, idle timeouts, pool checkins all complete).
    var steps: u64 = 0;
    while (!clients_done(clients)) : (steps += 1) {
        if (steps > step_cap) fail("hang: step cap with {d} clients unfinished", .{
            clients_unfinished(clients),
        });
        io.run_once() catch fail("deadlock while clients still running", .{});
    }
    while (pool.free_count != pool.capacity) : (steps += 1) {
        if (steps > step_cap) fail("leak: {d} slots never reclaimed", .{
            pool.capacity - pool.free_count,
        });
        io.run_once() catch {
            dump_pool(&pool);
            io.dump_pending();
            fail("leak: slot held with no pending operation", .{});
        };
    }
    server.deinit();
    if (metrics.active.load() != 0) fail("metrics.active = {d} after drain", .{
        metrics.active.load(),
    });
    // Resilience accounting must drain with the connections: a nonzero
    // counter here is a leaked increment/decrement pair somewhere on the
    // data path (the standing invariant for every Phase-2 slice).
    if (!server.resilience.is_idle()) fail("resilience counters nonzero after drain", .{});

    var responses: u64 = 0;
    for (clients) |*client| responses += client.responses_ok;
    return responses;
}

/// Diagnostic for leak failures: the state of every in-use connection slot.
fn dump_pool(pool: *ConnPool) void {
    for (pool.items) |*conn| {
        if (conn.free_next != null) continue; // parked on the free list
        std.debug.print(
            "sim: leaked conn: refs={d} closing={} timeout_armed={} downstream_fd={d} " ++
                "upstream_fd={d} " ++
                "outcome={s} request_active={} upstream_close_pending={}\n",
            .{
                conn.refs,           conn.closing,                conn.timeout_armed,
                conn.downstream_fd,  conn.upstream_fd,            @tagName(conn.outcome),
                conn.request_active, conn.upstream_close_pending,
            },
        );
    }
}

fn clients_done(clients: []Client) bool {
    for (clients) |*client| {
        if (!client.done) return false;
    }
    return true;
}

fn clients_unfinished(clients: []Client) u64 {
    var count: u64 = 0;
    for (clients) |*client| {
        if (!client.done) count += 1;
    }
    return count;
}

/// Seeded workload decisions, separate from the scheduler's PRNG.
const Workload = struct {
    prng: std.Random.DefaultPrng,

    /// Half the iterations are fault-free (keeps the traffic-flow invariant
    /// meaningful); the rest see RST drizzle, an RST storm + refusals, or
    /// black-holed connects (which exercise the per-try abort/cancel path).
    fn fault_profile(workload: *Workload) test_io.Faults {
        return switch (workload.prng.random().intRangeLessThan(u32, 0, 6)) {
            0, 1, 2 => .{},
            3 => .{ .reset_ppm = 2_000, .connect_refuse_ppm = 5_000 },
            4 => .{ .reset_ppm = 30_000, .connect_refuse_ppm = 30_000 },
            5 => .{ .reset_ppm = 2_000, .connect_blackhole_ppm = 30_000 },
            else => unreachable,
        };
    }

    fn origin_behavior(workload: *Workload) Origin.Behavior {
        const all = comptime std.enums.values(Origin.Behavior);
        return all[workload.prng.random().intRangeLessThan(usize, 0, all.len)];
    }

    fn request_kind(workload: *Workload) Client.RequestKind {
        const all = comptime std.enums.values(Client.RequestKind);
        return all[workload.prng.random().intRangeLessThan(usize, 0, all.len)];
    }

    fn requests_per_client(workload: *Workload) u32 {
        return workload.prng.random().intRangeAtMost(u32, 1, 3);
    }

    fn one_in(workload: *Workload, n: u32) bool {
        return workload.prng.random().intRangeLessThan(u32, 0, n) == 0;
    }
};

// ---- virtual origin ---------------------------------------------------------

const Origin = struct {
    io: *IO,
    arena: std.mem.Allocator,
    workload: *Workload,
    listener_fd: posix.socket_t,
    accept_completion: Completion = undefined,

    const Behavior = enum {
        framed_keep_alive,
        framed_close,
        chunked_keep_alive,
        close_delimited,
        garbage,
        premature_close,
        linger_then_stale_close,
        /// Read the request, never answer — a wedged upstream. The proxy's
        /// per-try timeout must abort the attempt and retry elsewhere (or
        /// answer 504); the overall deadline must never be the one to fire.
        never_respond,
    };

    fn start(origin: *Origin) void {
        origin.io.accept(
            *Origin,
            origin,
            on_accept,
            &origin.accept_completion,
            origin.listener_fd,
        );
    }

    fn on_accept(
        origin: *Origin,
        _: *Completion,
        result: io_mod.AcceptError!posix.socket_t,
    ) void {
        const fd = result catch return;
        const conn = origin.arena.create(OriginConn) catch fail("sim allocator exhausted", .{});
        conn.* = .{ .io = origin.io, .fd = fd, .behavior = origin.workload.origin_behavior() };
        conn.arm_recv();
        origin.start(); // keep accepting
    }
};

/// One origin-side connection: parse framed requests, answer per behavior.
const OriginConn = struct {
    io: *IO,
    fd: posix.socket_t,
    behavior: Origin.Behavior,
    buf: [4096]u8 = undefined,
    filled: usize = 0,
    headers: [16]h1.Header = undefined,
    request_end: usize = 0,
    response: []const u8 = "",
    response_buf: [192]u8 = undefined,
    sent: usize = 0,
    recv_completion: Completion = undefined,
    send_completion: Completion = undefined,
    stale_completion: Completion = undefined,
    closed: bool = false,

    fn arm_recv(conn: *OriginConn) void {
        assert(!conn.closed);
        if (conn.filled == conn.buf.len) return conn.shutdown(); // request too large: give up
        conn.io.recv(
            *OriginConn,
            conn,
            on_recv,
            &conn.recv_completion,
            conn.fd,
            conn.buf[conn.filled..],
        );
    }

    fn on_recv(conn: *OriginConn, _: *Completion, result: io_mod.RecvError!usize) void {
        if (conn.closed) return;
        const n = result catch return conn.shutdown();
        if (n == 0) return conn.shutdown(); // peer finished with us
        conn.filled += n;
        conn.try_serve();
    }

    fn try_serve(conn: *OriginConn) void {
        const parsed = h1.parse(conn.buf[0..conn.filled], &conn.headers) catch
            return conn.shutdown(); // the proxy never forwards garbage; treat as fatal here
        const request = switch (parsed) {
            .incomplete => return conn.arm_recv(),
            .complete => |request| request,
        };
        var framer = h1.BodyFramer.init(h1.request_framing(&request) catch
            return conn.shutdown());
        const body_consumed = framer.consume(conn.buf[request.head_len..conn.filled]) catch
            return conn.shutdown();
        if (!framer.is_complete()) return conn.arm_recv(); // body still arriving
        conn.request_end = request.head_len + body_consumed;
        conn.respond(request.target);
    }

    /// Answer per behavior, echoing the request target into the body so the
    /// client can verify byte-exact end-to-end integrity.
    fn respond(conn: *OriginConn, target: []const u8) void {
        assert(target.len > 0);
        const echo_len = "echo:".len + target.len;
        conn.response = switch (conn.behavior) {
            .framed_keep_alive,
            .linger_then_stale_close,
            => std.fmt.bufPrint(
                &conn.response_buf,
                "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\necho:{s}",
                .{ echo_len, target },
            ) catch unreachable, // targets are bounded by the client's buffer
            .framed_close => std.fmt.bufPrint(
                &conn.response_buf,
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {d}\r\n\r\necho:{s}",
                .{ echo_len, target },
            ) catch unreachable,
            .chunked_keep_alive => std.fmt.bufPrint(
                &conn.response_buf,
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{x}\r\necho:{s}\r\n0\r\n\r\n",
                .{ echo_len, target },
            ) catch unreachable,
            .close_delimited => std.fmt.bufPrint(
                &conn.response_buf,
                "HTTP/1.1 200 OK\r\n\r\necho:{s}",
                .{target},
            ) catch unreachable,
            .garbage => "SPROING! NOT HTTP AT ALL\r\n\r\n",
            .premature_close => return conn.shutdown(),
            // Keep reading so the proxy's abort (shutdown) is noticed and
            // the fd is released; no response ever leaves.
            .never_respond => return conn.arm_recv(),
        };
        conn.sent = 0;
        conn.arm_send();
    }

    fn arm_send(conn: *OriginConn) void {
        assert(conn.sent < conn.response.len);
        conn.io.send(
            *OriginConn,
            conn,
            on_send,
            &conn.send_completion,
            conn.fd,
            conn.response[conn.sent..],
        );
    }

    fn on_send(conn: *OriginConn, _: *Completion, result: io_mod.SendError!usize) void {
        if (conn.closed) return;
        conn.sent += result catch return conn.shutdown();
        if (conn.sent < conn.response.len) return conn.arm_send();
        switch (conn.behavior) {
            .framed_close, .close_delimited, .garbage => conn.shutdown(),
            .framed_keep_alive, .chunked_keep_alive => conn.next_request(),
            .linger_then_stale_close => {
                // Serve, then close after a virtual delay — while the proxy
                // has this connection parked in its pool: the stale-retry path.
                conn.io.timeout(
                    *OriginConn,
                    conn,
                    on_stale_close,
                    &conn.stale_completion,
                    2 * std.time.ns_per_s,
                );
            },
            .premature_close, .never_respond => unreachable, // never send a response
        }
    }

    fn on_stale_close(conn: *OriginConn, _: *Completion, _: io_mod.TimeoutError!void) void {
        if (conn.closed) return;
        conn.shutdown();
    }

    fn next_request(conn: *OriginConn) void {
        assert(conn.request_end <= conn.filled);
        const excess = conn.filled - conn.request_end;
        if (excess > 0) {
            std.mem.copyForwards(
                u8,
                conn.buf[0..excess],
                conn.buf[conn.request_end..conn.filled],
            );
        }
        conn.filled = excess;
        conn.request_end = 0;
        if (conn.filled > 0) return conn.try_serve(); // pipelined next request
        conn.arm_recv();
    }

    fn shutdown(conn: *OriginConn) void {
        if (conn.closed) return;
        conn.closed = true;
        conn.io.shutdown_socket(conn.fd);
        conn.io.close_now(conn.fd);
    }
};

// ---- virtual client ---------------------------------------------------------

const Client = struct {
    io: *IO,
    workload: *Workload,
    /// Distinguishes this client's tokens from every other client's.
    id: u32 = 0,
    /// With RST injection on, a close-delimited body can be truncated by a
    /// legitimate teardown FIN — only fault-free runs verify those bodies.
    strict_until_close: bool = true,
    fd: posix.socket_t = -1,
    requests_total: u32 = 0,
    requests_sent: u32 = 0,
    sequence: u32 = 0,
    kind: RequestKind = .get,
    method: h1.Method = .get,
    abort_mid_response: bool = false,
    expected_responses: u32 = 0,
    burst_size: u32 = 0,
    /// The target (with its unique token) each response of the current
    /// burst must echo back, in order.
    expected: [2]Target = .{ .{}, .{} },
    status: u16 = 0,
    body_start: usize = 0,
    send_buf: [512]u8 = undefined,
    send_len: usize = 0,
    sent: usize = 0,
    send_pending: bool = false,
    /// The response outran our own send (an early 400, say); the next
    /// request must wait for the in-flight send completion.
    next_request_queued: bool = false,
    recv_buf: [8192]u8 = undefined,
    filled: usize = 0,
    headers: [32]h1.Header = undefined,
    /// Set once the current response head parsed; frames its body.
    framer: ?h1.BodyFramer = null,
    body_cursor: usize = 0,
    responses_ok: u32 = 0,
    done: bool = false,
    connect_completion: Completion = undefined,
    send_completion: Completion = undefined,
    recv_completion: Completion = undefined,

    const RequestKind = enum { get, post_sized, post_chunked, pipelined_pair, garbage };

    const Target = struct {
        buf: [48]u8 = undefined,
        len: usize = 0,

        fn slice(target: *const Target) []const u8 {
            return target.buf[0..target.len];
        }
    };

    fn begin(client: *Client) void {
        client.requests_total = client.workload.requests_per_client();
        client.fd = client.io.open_tcp_socket() orelse fail("virtual fds exhausted", .{});
        client.io.connect(
            *Client,
            client,
            on_connect,
            &client.connect_completion,
            client.fd,
            .{
                .family = std.os.linux.AF.INET,
                .port = std.mem.nativeToBig(u16, proxy_port),
                .addr = 0,
            },
        );
    }

    fn on_connect(client: *Client, _: *Completion, result: io_mod.ConnectError!void) void {
        result catch return client.conclude(); // proxy backlog full: acceptable
        client.arm_recv();
        client.next_request();
    }

    fn next_request(client: *Client) void {
        assert(client.requests_sent < client.requests_total);
        client.kind = client.workload.request_kind();
        client.abort_mid_response = client.workload.one_in(8);
        const last = client.requests_sent + 1 == client.requests_total;
        client.compose(last);
        client.requests_sent += if (client.kind == .pipelined_pair) 2 else 1;
        if (client.requests_sent > client.requests_total) client.requests_total += 1;
        client.sent = 0;
        client.arm_send();
    }

    /// Build a target carrying this request's unique token.
    fn tokenize(client: *Client, index: usize, prefix: []const u8) []const u8 {
        client.sequence += 1;
        const text = std.fmt.bufPrint(
            &client.expected[index].buf,
            "{s}?token-c{d}s{d}",
            .{ prefix, client.id, client.sequence },
        ) catch unreachable; // bounded ids and sequences fit
        client.expected[index].len = text.len;
        return text;
    }

    fn compose(client: *Client, last: bool) void {
        const connection: []const u8 = if (last) "Connection: close\r\n" else "";
        client.method = if (client.kind == .post_sized or client.kind == .post_chunked)
            .post
        else
            .get;
        client.burst_size = if (client.kind == .pipelined_pair) 2 else 1;
        client.expected_responses = client.burst_size;
        const text = switch (client.kind) {
            .get => std.fmt.bufPrint(&client.send_buf, "GET {s} HTTP/1.1\r\n" ++
                "Host: sim\r\n{s}\r\n", .{ client.tokenize(0, "/a"), connection }),
            .post_sized => std.fmt.bufPrint(&client.send_buf, "POST {s} HTTP/1.1\r\n" ++
                "Host: sim\r\nContent-Length: 11\r\n{s}\r\nhello-body!", .{
                client.tokenize(0, "/b"),
                connection,
            }),
            .post_chunked => std.fmt.bufPrint(&client.send_buf, "POST {s} HTTP/1.1\r\n" ++
                "Host: sim\r\nTransfer-Encoding: chunked\r\n{s}\r\n" ++
                "6\r\nchunky\r\n0\r\n\r\n", .{ client.tokenize(0, "/a"), connection }),
            .pipelined_pair => std.fmt.bufPrint(&client.send_buf, "GET {s} HTTP/1.1\r\n" ++
                "Host: sim\r\n\r\nGET {s} HTTP/1.1\r\nHost: sim\r\n{s}\r\n", .{
                client.tokenize(0, "/a"),
                client.tokenize(1, "/b"),
                connection,
            }),
            .garbage => std.fmt.bufPrint(&client.send_buf, "GET / WHAT\r\n\r\n", .{}),
        } catch unreachable; // all variants fit the buffer by construction
        client.send_len = text.len;
        assert(client.send_len > 0);
    }

    fn arm_send(client: *Client) void {
        assert(client.sent < client.send_len);
        assert(!client.send_pending); // one send completion, one op in flight
        client.send_pending = true;
        client.io.send(
            *Client,
            client,
            on_send,
            &client.send_completion,
            client.fd,
            client.send_buf[client.sent..client.send_len],
        );
    }

    fn on_send(client: *Client, _: *Completion, result: io_mod.SendError!usize) void {
        client.send_pending = false;
        if (client.done) return;
        client.sent += result catch return client.conclude(); // proxy closed on us
        if (client.sent < client.send_len) return client.arm_send();
        if (client.next_request_queued) {
            client.next_request_queued = false;
            client.next_request();
        }
    }

    fn arm_recv(client: *Client) void {
        if (client.filled == client.recv_buf.len) fail("client response buffer overflow", .{});
        client.io.recv(
            *Client,
            client,
            on_recv,
            &client.recv_completion,
            client.fd,
            client.recv_buf[client.filled..],
        );
    }

    fn on_recv(client: *Client, _: *Completion, result: io_mod.RecvError!usize) void {
        if (client.done) return;
        const n = result catch return client.conclude();
        if (n == 0) return client.on_eof();
        client.filled += n;
        client.consume_response();
    }

    fn on_eof(client: *Client) void {
        // EOF legitimately ends a close-delimited response body.
        if (client.framer) |framer| {
            if (framer.framing == .until_close) {
                // Under RST injection a teardown FIN can truncate this body
                // mid-flight; only fault-free runs can insist on the echo.
                if (client.strict_until_close) client.verify_integrity();
                client.responses_ok += 1;
                return client.conclude();
            }
        }
        client.conclude(); // proxy closed (5xx path, rejection, timeout): acceptable
    }

    /// A completed 200 must carry *this* request's token back: byte-exact
    /// for length-framed bodies, embedded in the chunk framing otherwise.
    /// Catches truncation, response reordering, and stray bytes leaking
    /// between (pooled) connections.
    fn verify_integrity(client: *Client) void {
        if (client.status != 200) return; // proxy-generated errors echo nothing
        assert(client.burst_size >= client.expected_responses);
        const index = client.burst_size - client.expected_responses;
        assert(index < 2);
        var echo_buf: [64]u8 = undefined;
        const echo = std.fmt.bufPrint(&echo_buf, "echo:{s}", .{
            client.expected[index].slice(),
        }) catch unreachable; // targets are bounded
        const body = client.recv_buf[client.body_start..client.body_cursor];
        const intact = switch (client.framer.?.framing) {
            // The body is exactly the echo, byte for byte.
            .content_length, .until_close => std.mem.eql(u8, echo, body),
            // The wire bytes include the chunk framing around the echo.
            .chunked => std.mem.indexOf(u8, body, echo) != null,
            .none => body.len == 0,
        };
        if (!intact) fail("response integrity: expected \"{s}\", body was \"{s}\"", .{
            echo,
            body,
        });
    }

    /// Every byte stream the proxy sends must parse and frame as HTTP/1.1 —
    /// this is the core correctness invariant, checked on every response.
    fn consume_response(client: *Client) void {
        if (client.framer == null) {
            const received = client.recv_buf[0..client.filled];
            const parsed = h1.parse_response(received, &client.headers) catch
                fail("proxy emitted an unparseable response head", .{});
            const response = switch (parsed) {
                .incomplete => return client.arm_recv(),
                .complete => |response| response,
            };
            const framing = h1.response_framing(client.method, &response) catch
                fail("proxy emitted conflicting framing headers", .{});
            var framer = h1.BodyFramer.init(framing);
            const body = client.recv_buf[response.head_len..client.filled];
            const consumed = framer.consume(body) catch
                fail("proxy emitted a malformed chunked body", .{});
            client.framer = framer;
            client.status = response.status;
            client.body_start = response.head_len;
            client.body_cursor = response.head_len + consumed;
        } else {
            const fresh = client.recv_buf[client.body_cursor..client.filled];
            const consumed = client.framer.?.consume(fresh) catch
                fail("proxy emitted a malformed chunked body", .{});
            client.body_cursor += consumed;
        }
        if (!client.framer.?.is_complete()) {
            if (client.abort_mid_response) return client.conclude(); // rude client
            return client.arm_recv();
        }
        client.response_done();
    }

    fn response_done(client: *Client) void {
        client.verify_integrity();
        client.responses_ok += 1;
        client.expected_responses -= 1;
        // Slide any bytes past this response (a second pipelined response).
        const excess = client.filled - client.body_cursor;
        std.mem.copyForwards(
            u8,
            client.recv_buf[0..excess],
            client.recv_buf[client.body_cursor..client.filled],
        );
        client.filled = excess;
        client.framer = null;
        client.body_cursor = 0;
        if (client.expected_responses > 0) return client.consume_response();
        if (client.requests_sent >= client.requests_total) return client.conclude();
        client.arm_recv();
        if (client.send_pending or client.sent < client.send_len) {
            client.next_request_queued = true; // finish the in-flight send first
            return;
        }
        client.next_request();
    }

    fn conclude(client: *Client) void {
        if (client.done) return;
        client.done = true;
        if (client.fd >= 0) {
            client.io.shutdown_socket(client.fd);
            client.io.close_now(client.fd);
            client.fd = -1;
        }
    }
};
