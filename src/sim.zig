//! Deterministic simulator (docs/DESIGN.md: TigerBeetle's VOPR idea). Runs
//! the real proxy data path — ProxyServer, ProxyConn, the pools, the parsers
//! — against the simulation IO backend: virtual sockets, a virtual clock,
//! and a seeded scheduler that completes one operation at a time with
//! adversarial partial reads/writes. Virtual clients and misbehaving virtual
//! origins generate randomized workloads; the seed replays everything.
//!
//! Two proxies run each iteration on the same origins and fault profile: the
//! HTTP/1.1 ProxyServer and, alongside it, the plaintext HTTP/2 (h2c)
//! H2Server (h2 over TLS is out of reach — the sim excludes OpenSSL — but
//! h2c drives the whole engine / per-stream leg / flow-control machinery,
//! identical above the record layer). The h2c client multiplexes several
//! streams per connection, each with a GET / small POST / ~10 KiB POST /
//! deliberately-malformed request, and sometimes vanishes mid-response.
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
//! - every byte stream a client receives parses and frames correctly — an
//!   HTTP/1.1 response (RFC 9112 §6.3) for the H1 clients, a valid HTTP/2
//!   frame sequence for the h2c ones — whatever the origin or network did;
//! - response integrity: every request carries a unique token that the
//!   origin echoes into the body; a completed 200 must return *this*
//!   request's token, byte-exact for length-framed bodies — catching
//!   truncation, reordering, and cross-connection contamination (stray
//!   bytes on a pooled upstream would surface here). For h2c, `END_STREAM`
//!   is the authoritative completion signal, so the per-stream check also
//!   catches one stream's body leaking into another's;
//! - all connection slots and stream legs return to their pools, and
//!   `metrics.active` is zero, once every client is gone — for both proxies:
//!   no leaks under any schedule;
//! - graceful drain (a third of iterations, begun at a random step): both
//!   proxies stop accepting and close their listeners (backlogged connects
//!   are RST, not left hanging), every slot still drains to zero — with a
//!   drain deadline short enough that forced teardown of wedged exchanges is
//!   exercised — and each worker's exit condition (`drain_complete`) is
//!   reached with no server op abandoned.

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
const h2_frame = @import("http/h2_frame.zig");
const hpack = @import("http/hpack.zig");
const Router = @import("proxy/router.zig").Router;
const HealthChecker = @import("proxy/health_check.zig").HealthChecker;
const proxy_mod = @import("net/proxy.zig");
const ProxyServer = proxy_mod.ProxyServer;
const ConnPool = proxy_mod.ConnPool;
const h2_proxy = @import("net/h2_proxy.zig");
const H2Server = h2_proxy.H2Server;
const H2ConnPool = h2_proxy.H2ConnPool;
const H2LegPool = h2_proxy.LegPool;
const Listener = @import("net/listener.zig").Listener;
const Counters = @import("obs/metrics.zig").Counters;
const AccessLog = @import("obs/access_log.zig").AccessLog;

const proxy_port = 8080;
/// The plaintext HTTP/2 (h2c) listener, run alongside the H1 proxy on the
/// same origins and fault profile: the H2 data path — engine, per-stream
/// legs, flow control — under the seeded adversarial schedule. h2 over TLS
/// can't be simulated (the sim excludes OpenSSL); h2c exercises everything
/// above the record layer, which is identical.
const h2c_proxy_port = 8081;
const origin_ports = [_]u16{ 9001, 9002, 9003 };
const clients_max = 12;
const h2_clients_max = 6;
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
        \\      "retry": { "max": 2, "backoff_base_ms": 50, "backoff_cap_ms": 400 },
        \\      "outlier": { "consecutive_failures": 3, "ejection_ms": 3000 },
        \\      "health_check": { "interval_ms": 1000, "timeout_ms": 500 } },
        \\    { "name": "two", "endpoints": ["127.0.0.1:9003", "127.0.0.1:9002"],
        \\      "lb": { "policy": "maglev" },
        \\      "per_try_timeout_ms": 2000,
        \\      "retry": { "max": 2, "backoff_base_ms": 50, "backoff_cap_ms": 400 },
        \\      "outlier": { "consecutive_failures": 3, "ejection_ms": 3000 },
        \\      "health_check": { "interval_ms": 1000, "timeout_ms": 500 } }
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
    var metrics = Counters{};
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
    // A third of iterations drain mid-traffic. The drain deadline sits below
    // the per-try timeout (2s) so wedged exchanges (black-holed connects,
    // never-responding origins) hit the forced-teardown path, not just the
    // polite one.
    const drain_requested = workload.one_in(3);
    const drain_after_steps: u64 =
        if (drain_requested) workload.prng.random().intRangeLessThan(u64, 0, 1500) else 0;
    if (drain_requested) server.drain_timeout_ns = 1 * std.time.ns_per_s;
    server.start();

    // Active health probes run through the same virtual ring and fault
    // profile: refused/black-holed probes flip endpoints unhealthy and the
    // balancer must still route (fail-open) — under every seed's schedule.
    var health = HealthChecker.init(&io, cfg.clusters, &server.resilience, &metrics);
    health.start();

    // The h2c proxy: its own pools, metrics, and resilience (an independent
    // worker sharing the origins), so the H1 invariant checks stay clean and
    // the H2 path gets its own accounting to assert idle. MV scope: the h2c
    // server is not drained (drain is the H1 path's job this slice); its
    // clients conclude naturally and its pools must still reclaim every slot.
    var h2_conn_pool = try H2ConnPool.init(arena, constants.h2_connections_max);
    var h2_leg_pool = try H2LegPool.init(arena, constants.h2_legs_max);
    var h2_metrics = Counters{};
    var h2_access = AccessLog{ .fd = -1 };
    var h2_server = H2Server.init(
        &io,
        &h2_conn_pool,
        &h2_leg_pool,
        Listener{ .fd = io.open_listener(h2c_proxy_port) },
        &router,
        &h2_metrics,
        &h2_access,
        5 * std.time.ns_per_s,
        10 * std.time.ns_per_s,
    );
    h2_server.prng = .init(seed +% 0x2545F4914F6CDD1D);
    // The h2c drain deadline sits below the per-try timeout (as on H1) so
    // wedged streams hit the forced-teardown path within the run's step cap.
    if (drain_requested) h2_server.drain_timeout_ns = 1 * std.time.ns_per_s;
    h2_server.start();

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

    const h2_clients = try arena.alloc(H2Client, h2_clients_max);
    for (h2_clients, 0..) |*client, index| {
        client.* = .{ .io = &io, .workload = &workload, .id = @intCast(index) };
        client.begin();
    }

    // Drive until every client concluded, then until the proxy reclaimed
    // every slot (teardowns, idle timeouts, pool checkins all complete).
    var steps: u64 = 0;
    var accepted_at_drain: ?u64 = null;
    var h2_accepted_at_drain: u64 = 0;
    while (!clients_done(clients) or !h2_clients_done(h2_clients)) : (steps += 1) {
        if (drain_requested and accepted_at_drain == null and steps >= drain_after_steps) {
            server.begin_drain();
            h2_server.begin_drain(); // the h2c server drains in parallel (GOAWAY sweep)
            accepted_at_drain = metrics.accepted.load();
            h2_accepted_at_drain = h2_metrics.accepted.load();
        }
        if (steps > step_cap) {
            dump_h2(h2_clients, &h2_conn_pool, io.now_ns());
            fail("hang: step cap with {d} H1 + {d} h2c clients unfinished", .{
                clients_unfinished(clients),
                h2_clients_unfinished(h2_clients),
            });
        }
        io.run_once() catch fail("deadlock while clients still running", .{});
    }
    // Clients can all conclude before the drain step arrives: drain an idle
    // proxy then — begin_drain with nothing in flight must still complete.
    if (drain_requested and accepted_at_drain == null) {
        server.begin_drain();
        h2_server.begin_drain();
        accepted_at_drain = metrics.accepted.load();
        h2_accepted_at_drain = h2_metrics.accepted.load();
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
    if (drain_requested) {
        // The worker's exit condition: server-scoped ops (the cancelled
        // accept, its cancel, a backoff timer) must all deliver — a worker
        // never abandons a live op on ring teardown.
        while (!server.drain_complete()) : (steps += 1) {
            if (steps > step_cap) fail("drain never completed ({d} ops pending)", .{
                server.operations_pending,
            });
            io.run_once() catch {
                io.dump_pending();
                fail("drain stalled: {d} server ops pending, nothing ready", .{
                    server.operations_pending,
                });
            };
        }
        // Accepts froze at begin_drain: the cancel (or the drain branch of
        // on_accept) guarantees no connection was started after it.
        if (metrics.accepted.load() != accepted_at_drain.?) {
            fail("accepted {d} connections after drain began", .{
                metrics.accepted.load() - accepted_at_drain.?,
            });
        }
        if (metrics.draining.load() != 1) fail("draining gauge = {d}, want 1", .{
            metrics.draining.load(),
        });
    }
    server.deinit();
    if (metrics.active.load() != 0) fail("metrics.active = {d} after drain", .{
        metrics.active.load(),
    });
    // Resilience accounting must drain with the connections: a nonzero
    // counter here is a leaked increment/decrement pair somewhere on the
    // data path (the standing invariant for every Phase-2 slice).
    if (!server.resilience.is_idle()) fail("resilience counters nonzero after drain", .{});

    // The h2c server's every slot — connection and stream leg — must come
    // home, and its resilience must settle, under the same fault schedule.
    while (h2_conn_pool.free_count != h2_conn_pool.capacity or
        h2_leg_pool.free_count != h2_leg_pool.capacity) : (steps += 1)
    {
        if (steps > step_cap) fail("h2c leak: {d} conn + {d} leg slots never reclaimed", .{
            h2_conn_pool.capacity - h2_conn_pool.free_count,
            h2_leg_pool.capacity - h2_leg_pool.free_count,
        });
        io.run_once() catch {
            io.dump_pending();
            fail("h2c leak: slot held with no pending operation", .{});
        };
    }
    if (drain_requested) {
        if (!h2_server.drain_complete()) fail("h2c drain never completed", .{});
        if (h2_metrics.accepted.load() != h2_accepted_at_drain) {
            fail("h2c accepted {d} connections after drain began", .{
                h2_metrics.accepted.load() - h2_accepted_at_drain,
            });
        }
    }
    h2_server.deinit();
    if (h2_metrics.active.load() != 0)
        fail("h2c metrics.active = {d}", .{h2_metrics.active.load()});
    if (!h2_server.resilience.is_idle()) fail("h2c resilience counters nonzero", .{});

    var responses: u64 = 0;
    for (clients) |*client| responses += client.responses_ok;
    for (h2_clients) |*client| responses += client.responses_ok;
    return responses;
}

/// Diagnostic for leak failures: the state of every in-use connection slot.
fn dump_pool(pool: *ConnPool) void {
    for (pool.items) |*conn| {
        if (!conn.in_use) continue; // parked on the free list
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
    // Large enough for an h2c client's biggest (chunk-framed) upstream body
    // plus the head — exercises the proxy's request-body flow-control release.
    buf: [32 * 1024]u8 = undefined,
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

// ---- virtual h2c client -----------------------------------------------------

fn h2_clients_done(clients: []H2Client) bool {
    for (clients) |*client| {
        if (!client.done) return false;
    }
    return true;
}

fn h2_clients_unfinished(clients: []H2Client) u64 {
    var count: u64 = 0;
    for (clients) |*client| {
        if (!client.done) count += 1;
    }
    return count;
}

fn dump_h2(clients: []H2Client, pool: *H2ConnPool, now: u64) void {
    for (clients) |*c| {
        if (c.done) continue;
        std.debug.print("h2 client {d}: completed={d}/{d} sent={d}/{d} fd={d}\n", .{
            c.id, c.completed, c.stream_count, c.sent, c.send_len, c.fd,
        });
        for (c.streams[0..c.stream_count]) |*s| {
            std.debug.print("  stream {d}: status={d} complete={} body_len={d}\n", .{
                s.id, s.status, s.complete, s.body_len,
            });
        }
    }
    for (pool.items) |*conn| {
        if (!conn.in_use) continue;
        std.debug.print("h2 conn: closing={} caf={} drain_pending={} active={d} " ++
            "streams={d} refs={d} deadline={d} now={d} recv_if={} send_if={}\n", .{
            conn.closing,        conn.close_after_flush,     conn.drain_pending,
            conn.active_count,   conn.engine.streams_active, conn.refs,
            conn.deadline_ns,    now,                        conn.recv_in_flight,
            conn.send_in_flight,
        });
    }
}

/// A plaintext HTTP/2 client that opens several streams concurrently on one
/// connection — the multiplexed shape the H1 client cannot exercise. Each
/// stream carries a unique token in its `:path`; the origin echoes it back,
/// so a per-stream integrity check catches cross-stream corruption (one
/// stream's body leaking into another). Frames arrive under the sim's
/// adversarial partial-IO and RST schedule; `END_STREAM` is the authoritative
/// "this stream's body is complete" signal, so no close-delimited ambiguity.
const H2Client = struct {
    io: *IO,
    workload: *Workload,
    id: u32 = 0,
    fd: posix.socket_t = -1,
    // Holds the whole opening flight: preface + SETTINGS + up to a ~10 KiB
    // POST body (under the 16 KiB window we advertise, over the 8 KiB
    // half-window that makes the proxy release a WINDOW_UPDATE).
    send_buf: [16 * 1024]u8 = undefined,
    send_len: usize = 0,
    sent: usize = 0,
    /// Drop the connection after the first response byte — a client that
    /// vanishes mid-multiplex (the H2 twin of H1's abort_mid_response).
    abort: bool = false,
    wire: [4096]u8 = undefined,
    wire_len: usize = 0,
    decoder: hpack.Decoder = .{},
    fields: [16]hpack.Header = undefined,
    fields_storage: [512]u8 = undefined,
    streams: [3]Stream = .{ .{}, .{}, .{} },
    stream_count: u32 = 0,
    completed: u32 = 0,
    responses_ok: u32 = 0,
    done: bool = false,
    connect_completion: Completion = undefined,
    send_completion: Completion = undefined,
    recv_completion: Completion = undefined,

    const Kind = enum { get, post_small, post_large, malformed };

    const Stream = struct {
        id: u31 = 0,
        kind: Kind = .get,
        token: [48]u8 = undefined,
        token_len: usize = 0,
        status: u16 = 0,
        body: [160]u8 = undefined,
        body_len: usize = 0,
        complete: bool = false,

        fn path(stream: *const Stream) []const u8 {
            return stream.token[0..stream.token_len];
        }
    };

    fn begin(client: *H2Client) void {
        client.fd = client.io.open_tcp_socket() orelse fail("virtual fds exhausted", .{});
        client.io.connect(
            *H2Client,
            client,
            on_connect,
            &client.connect_completion,
            client.fd,
            .{
                .family = std.os.linux.AF.INET,
                .port = std.mem.nativeToBig(u16, h2c_proxy_port),
                .addr = 0,
            },
        );
    }

    fn on_connect(client: *H2Client, _: *Completion, result: io_mod.ConnectError!void) void {
        result catch return client.conclude(); // backlog full: acceptable
        client.compose();
        client.arm_recv();
        client.arm_send();
    }

    /// Build the opening flight: preface, an (empty) SETTINGS, and the stream
    /// requests staged back to back so they are all in flight at once. A
    /// large POST rides alone (its body fills the send buffer); otherwise 1–3
    /// mixed GET / small-POST / malformed streams multiplex.
    fn compose(client: *H2Client) void {
        var len: usize = 0;
        @memcpy(client.send_buf[0..h2_frame.client_preface.len], h2_frame.client_preface);
        len += h2_frame.client_preface.len;
        len += h2_frame.write_settings(&.{}, client.send_buf[len..]);
        client.abort = client.workload.one_in(8);
        const large = client.workload.one_in(4);
        client.stream_count = if (large)
            1
        else
            client.workload.prng.random().intRangeAtMost(u32, 1, 3);
        for (0..client.stream_count) |i| {
            const stream = &client.streams[i];
            stream.id = @intCast(1 + 2 * i);
            stream.kind = if (large) .post_large else client.pick_kind();
            const prefix: []const u8 = if (client.workload.prng.random().boolean()) "/a" else "/b";
            const token = std.fmt.bufPrint(&stream.token, "{s}?token-c{d}s{d}", .{
                prefix, client.id, i,
            }) catch unreachable;
            stream.token_len = token.len;
            len += encode_stream(stream, client.send_buf[len..]);
        }
        client.send_len = len;
        assert(client.send_len <= client.send_buf.len);
    }

    fn pick_kind(client: *H2Client) Kind {
        const roll = client.workload.prng.random().intRangeAtMost(u32, 0, 99);
        if (roll < 60) return .get;
        if (roll < 85) return .post_small;
        return .malformed; // bad pseudo-headers -> the proxy RSTs the stream
    }

    /// Stage one stream's HEADERS (+ DATA for a POST); returns bytes written.
    fn encode_stream(stream: *Stream, out: []u8) usize {
        const post = stream.kind == .post_small or stream.kind == .post_large;
        var block: [96]u8 = undefined;
        var block_len: usize = 0;
        block_len += encode(&block, block_len, ":method", if (post) "POST" else "GET");
        // A malformed request omits :scheme — a stream error (RST_STREAM
        // PROTOCOL_ERROR at translation), not a connection-fatal one.
        if (stream.kind != .malformed) {
            block_len += encode(&block, block_len, ":scheme", "http");
        }
        block_len += encode(&block, block_len, ":path", stream.path());
        block_len += encode(&block, block_len, ":authority", "sim");

        var len: usize = 0;
        var flags: u8 = h2_frame.Flags.end_headers;
        if (!post) flags |= h2_frame.Flags.end_stream;
        h2_frame.write_frame_header(.{
            .length = @intCast(block_len),
            .type = .headers,
            .flags = flags,
            .stream_id = stream.id,
        }, out[len..][0..h2_frame.frame_header_bytes]);
        len += h2_frame.frame_header_bytes;
        @memcpy(out[len..][0..block_len], block[0..block_len]);
        len += block_len;
        if (post) {
            const body_len: usize = if (stream.kind == .post_large) 10_000 else 8;
            h2_frame.write_frame_header(.{
                .length = @intCast(body_len),
                .type = .data,
                .flags = h2_frame.Flags.end_stream,
                .stream_id = stream.id,
            }, out[len..][0..h2_frame.frame_header_bytes]);
            len += h2_frame.frame_header_bytes;
            @memset(out[len..][0..body_len], 'x'); // the origin echoes :path, not the body
            len += body_len;
        }
        return len;
    }

    fn encode(block: []u8, offset: usize, name: []const u8, value: []const u8) usize {
        return hpack.encode_header(name, value, block[offset..]) catch unreachable;
    }

    fn arm_send(client: *H2Client) void {
        if (client.sent >= client.send_len) return;
        client.io.send(
            *H2Client,
            client,
            on_send,
            &client.send_completion,
            client.fd,
            client.send_buf[client.sent..client.send_len],
        );
    }

    fn on_send(client: *H2Client, _: *Completion, result: io_mod.SendError!usize) void {
        if (client.done) return;
        client.sent += result catch return client.conclude();
        if (client.sent < client.send_len) client.arm_send();
    }

    fn arm_recv(client: *H2Client) void {
        if (client.wire_len == client.wire.len) return client.conclude(); // stuck: give up
        client.io.recv(
            *H2Client,
            client,
            on_recv,
            &client.recv_completion,
            client.fd,
            client.wire[client.wire_len..],
        );
    }

    fn on_recv(client: *H2Client, _: *Completion, result: io_mod.RecvError!usize) void {
        if (client.done) return;
        const n = result catch return client.conclude();
        if (n == 0) return client.conclude(); // proxy closed
        client.wire_len += n;
        client.consume_frames();
        if (!client.done) client.arm_recv();
    }

    fn consume_frames(client: *H2Client) void {
        var offset: usize = 0;
        while (true) {
            const frame = (h2_frame.parse_frame(client.wire[offset..client.wire_len]) catch
                fail("h2c: proxy emitted an unparseable frame", .{})) orelse break;
            offset += frame.wire_bytes();
            client.dispatch(frame);
            if (client.done) return;
        }
        std.mem.copyForwards(
            u8,
            client.wire[0 .. client.wire_len - offset],
            client.wire[offset..client.wire_len],
        );
        client.wire_len -= offset;
    }

    fn dispatch(client: *H2Client, frame: h2_frame.Frame) void {
        switch (frame.header.type) {
            .headers => {
                const stream = client.stream_for(frame.header.stream_id) orelse return;
                const decoded = client.decoder.decode(
                    frame.payload,
                    &client.fields,
                    &client.fields_storage,
                ) catch
                    fail("h2c: proxy emitted a bad HPACK block", .{});
                if (decoded.len == 0) fail("h2c: response head with no fields", .{});
                stream.status = std.fmt.parseInt(u16, decoded[0].value, 10) catch
                    fail("h2c: response missing :status", .{});
                if (frame.header.flags & h2_frame.Flags.end_stream != 0) client.stream_end(stream);
                if (client.abort) return client.conclude(); // vanish mid-multiplex
            },
            .data => {
                const stream = client.stream_for(frame.header.stream_id) orelse return;
                assert(stream.body_len + frame.payload.len <= stream.body.len); // echo is small
                @memcpy(stream.body[stream.body_len..][0..frame.payload.len], frame.payload);
                stream.body_len += @intCast(frame.payload.len);
                if (frame.header.flags & h2_frame.Flags.end_stream != 0) client.stream_end(stream);
                if (client.abort) return client.conclude();
            },
            .rst_stream => {
                const stream = client.stream_for(frame.header.stream_id) orelse return;
                client.stream_reset(stream); // proxy aborted the stream (e.g. upstream fault)
            },
            // Draining: no new streams may open, but the ones already in
            // flight (the client opened them all up front) must still finish.
            .goaway => {},
            else => {}, // SETTINGS, WINDOW_UPDATE, PING: ignored
        }
    }

    fn stream_for(client: *H2Client, id: u31) ?*Stream {
        for (client.streams[0..client.stream_count]) |*stream| {
            if (stream.id == id) return stream;
        }
        return null;
    }

    /// A stream reached END_STREAM: a complete response. A 200 must echo this
    /// stream's own token back, byte-exact — the multiplexed integrity check.
    fn stream_end(client: *H2Client, stream: *Stream) void {
        if (stream.complete) return;
        stream.complete = true;
        client.completed += 1;
        client.responses_ok += 1;
        if (stream.status == 200) {
            var echo_buf: [64]u8 = undefined;
            const echo = std.fmt.bufPrint(
                &echo_buf,
                "echo:{s}",
                .{stream.path()},
            ) catch unreachable;
            const body = stream.body[0..stream.body_len];
            if (!std.mem.eql(u8, echo, body)) {
                fail("h2c integrity: stream {d} expected \"{s}\", body was \"{s}\"", .{
                    stream.id, echo, body,
                });
            }
        }
        client.maybe_conclude();
    }

    fn stream_reset(client: *H2Client, stream: *Stream) void {
        if (stream.complete) return;
        stream.complete = true;
        client.completed += 1; // reset is an acceptable outcome, not a response
        client.maybe_conclude();
    }

    fn maybe_conclude(client: *H2Client) void {
        if (client.completed >= client.stream_count) client.conclude();
    }

    fn conclude(client: *H2Client) void {
        if (client.done) return;
        client.done = true;
        if (client.fd >= 0) {
            client.io.shutdown_socket(client.fd);
            client.io.close_now(client.fd);
            client.fd = -1;
        }
    }
};
