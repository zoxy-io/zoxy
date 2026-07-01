//! zoxy entrypoint. Loads a static JSON config, then runs a share-nothing
//! thread-per-core reverse proxy: one worker per CPU, each with its own
//! io_uring loop, SO_REUSEPORT listener, and connection pool (docs/DESIGN.md
//! §2, §7). Config parsing allocates at startup; the serving loop does not.

const std = @import("std");
const linux = std.os.linux;

const zoxy = @import("zoxy");
const constants = zoxy.constants;
const IO = zoxy.io.IO;
const Listener = zoxy.Listener;
const Router = zoxy.Router;
const ProxyServer = zoxy.proxy.ProxyServer;
const Pool = zoxy.proxy.ConnPool;
const Ip4Address = std.Io.net.Ip4Address;

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

    // Reserve every worker's pool up front, on this thread, so worker startup
    // touches no shared allocator and the serving loop allocates nothing.
    const pools = try gpa.alloc(Pool, worker_count);
    for (pools) |*pool| pool.* = try Pool.init(gpa, constants.connections_max);

    const threads = try gpa.alloc(std.Thread, worker_count);
    for (threads, pools, 0..) |*thread, *pool, cpu| {
        thread.* = try std.Thread.spawn(.{}, runWorker, .{ cfg.listen, pool, &router, cpu });
    }
    std.log.info("zoxy listening on {f} across {d} worker(s)", .{ cfg.listen, worker_count });
    for (threads) |thread| thread.join();
}

/// One share-nothing worker: its own IO ring, SO_REUSEPORT listener, and pool,
/// pinned to a core. Runs the proxy accept/relay loop forever.
fn runWorker(listen: Ip4Address, pool: *Pool, router: *const Router, cpu: usize) void {
    pinToCpu(cpu);

    var io = IO.init(constants.io_ring_entries, 0) catch |err| return logWorkerError("io init", err);
    defer io.deinit();

    var listener = Listener.open(listen, constants.accept_backlog) catch |err| return logWorkerError("listen", err);
    defer listener.close();

    var server = ProxyServer.init(&io, pool, listener, router, constants.connection_timeout_ns);
    server.start();
    while (true) io.run_once() catch |err| return logWorkerError("io run", err);
}

/// Best-effort CPU pinning (Linux only). Failure is non-fatal.
fn pinToCpu(cpu: usize) void {
    var set = std.mem.zeroes(linux.cpu_set_t);
    const bits = @bitSizeOf(usize);
    if (cpu / bits >= set.len) return; // more CPUs than the affinity mask covers
    set[cpu / bits] |= @as(usize, 1) << @intCast(cpu % bits);
    linux.sched_setaffinity(0, &set) catch {};
}

fn logWorkerError(what: []const u8, err: anyerror) void {
    std.log.err("zoxy worker {s}: {s}", .{ what, @errorName(err) });
}
