//! zoxy entrypoint. Loads a static JSON config, then runs a share-nothing
//! thread-per-core reverse proxy: one worker per CPU, each with its own
//! io_uring loop, SO_REUSEPORT listener, and connection pool (docs/DESIGN.md
//! §2, §7). Config parsing allocates at startup; the serving loop does not.

const std = @import("std");
const linux = std.os.linux;
const assert = std.debug.assert;

const zoxy = @import("zoxy");
const constants = zoxy.constants;
const IO = zoxy.io.IO;
const Listener = zoxy.Listener;
const Router = zoxy.Router;
const ProxyServer = zoxy.proxy.ProxyServer;
const Pool = zoxy.proxy.ConnPool;
const Metrics = zoxy.Metrics;
const AccessLog = zoxy.AccessLog;
const Ip4Address = std.Io.net.Ip4Address;

const stderr_fd = 2;

pub fn main(init: std.process.Init) !void {
    // All allocation here is startup-only; it lives in the process arena.
    const gpa = init.arena.allocator();

    const args = try init.minimal.args.toSlice(gpa);
    const config_path = if (args.len > 1) args[1] else "zoxy.json";

    const text = std.Io.Dir.cwd().readFileAlloc(init.io, config_path, gpa, .unlimited) catch |err| {
        std.log.err("zoxy: cannot read config {s}: {s}", .{ config_path, @errorName(err) });
        return err;
    };
    var cfg = zoxy.config.parse(gpa, text) catch |err| {
        std.log.err("zoxy: invalid config {s}: {s}", .{ config_path, @errorName(err) });
        return err;
    };
    const router = Router.init(&cfg);

    const worker_count = std.Thread.getCpuCount() catch 1;
    assert(worker_count >= 1); // one worker thread is spawned even if the count fails

    // Shared counters (atomic) and per-worker access logs, reserved up front.
    var metrics: Metrics = .{};
    const accesses = try gpa.alloc(AccessLog, worker_count);
    for (accesses) |*access| access.* = .{ .fd = stderr_fd };

    // Reserve every worker's pool up front, on this thread, so worker startup
    // touches no shared allocator and the serving loop allocates nothing.
    const pools = try gpa.alloc(Pool, worker_count);
    for (pools) |*pool| pool.* = try Pool.init(gpa, constants.connections_max);

    // One entropy draw seeds every worker's PRNG (P2C draws, retry jitter);
    // each worker offsets it by its cpu index so no two draw alike.
    var seed_bytes: [8]u8 = undefined;
    init.io.random(&seed_bytes);
    const seed_base = std.mem.readInt(u64, &seed_bytes, .little);

    const threads = try gpa.alloc(std.Thread, worker_count);
    for (threads, pools, accesses, 0..) |*thread, *pool, *access, cpu| {
        thread.* = try std.Thread.spawn(
            .{},
            run_worker,
            .{ cfg.listen, pool, &router, &metrics, access, seed_base, cpu },
        );
    }

    // Admin/metrics plane: blocking, on its own detached thread, off the data
    // path. Arena-allocated so it outlives this scope.
    if (cfg.admin) |admin_address| {
        const admin = try gpa.create(zoxy.Admin);
        admin.* = zoxy.Admin.open(admin_address, &metrics) catch |err| {
            std.log.err("zoxy: cannot open admin endpoint {f}: {s}", .{
                admin_address,
                @errorName(err),
            });
            return err;
        };
        const admin_thread = try std.Thread.spawn(.{}, zoxy.Admin.run, .{admin});
        admin_thread.detach();
        std.log.info("zoxy admin/metrics on {f}", .{admin_address});
    }

    std.log.info("zoxy listening on {f} across {d} worker(s)", .{ cfg.listen, worker_count });
    for (threads) |thread| thread.join();
}

/// One share-nothing worker: its own IO ring, SO_REUSEPORT listener, and pool,
/// pinned to a core. Runs the proxy accept/relay loop forever.
fn run_worker(
    listen: Ip4Address,
    pool: *Pool,
    router: *const Router,
    metrics: *Metrics,
    access: *AccessLog,
    seed_base: u64,
    cpu: usize,
) void {
    assert(pool.capacity > 0);
    pin_to_cpu(cpu);

    var io = IO.init(constants.io_ring_entries, 0) catch |err|
        return log_worker_error("io init", err);
    defer io.deinit();

    var listener = Listener.open(listen, constants.accept_backlog) catch |err|
        return log_worker_error("listen", err);
    defer listener.close();

    var server = ProxyServer.init(
        &io,
        pool,
        listener,
        router,
        metrics,
        access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    // Workers beyond the metrics table share its last slot (diagnostic only).
    server.worker_index = @intCast(@min(cpu, constants.workers_max - 1));
    server.prng = .init(seed_base +% cpu);
    server.start();
    while (true) {
        io.run_once() catch |err| return log_worker_error("io run", err);
        access.flush(); // batched: one write per event-loop iteration, off the per-connection path
    }
}

/// Best-effort CPU pinning (Linux only). Failure is non-fatal.
fn pin_to_cpu(cpu: usize) void {
    var set = std.mem.zeroes(linux.cpu_set_t);
    const bits = @bitSizeOf(usize);
    assert(bits > 0);
    if (cpu / bits >= set.len) return; // more CPUs than the affinity mask covers
    assert(cpu / bits < set.len);
    set[cpu / bits] |= @as(usize, 1) << @intCast(cpu % bits);
    linux.sched_setaffinity(0, &set) catch {};
}

fn log_worker_error(what: []const u8, err: anyerror) void {
    std.log.err("zoxy worker {s}: {s}", .{ what, @errorName(err) });
}
