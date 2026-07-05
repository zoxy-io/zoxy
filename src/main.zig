//! zoxy entrypoint. Loads a static JSON config, then runs a share-nothing
//! thread-per-core reverse proxy: one worker per CPU, each with its own
//! io_uring loop, SO_REUSEPORT listener, and connection pool (docs/DESIGN.md
//! §2, §7). Config parsing allocates at startup; the serving loop does not.

const std = @import("std");
const linux = std.os.linux;
const assert = std.debug.assert;

const zoxy = @import("zoxy");
const cache_line = zoxy.cache_line;
const constants = zoxy.constants;
const IO = zoxy.io.IO;
const Listener = zoxy.Listener;
const Router = zoxy.Router;
const ProxyServer = zoxy.proxy.ProxyServer;
const Pool = zoxy.proxy.ConnPool;
const TlsLegPool = zoxy.proxy.TlsLegPool;
const H2ConnPool = zoxy.h2_proxy.H2ConnPool;
const H2LegPool = zoxy.h2_proxy.LegPool;
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
    var diagnostic: zoxy.config.Diagnostic = .{};
    var cfg = zoxy.config.parse_diagnostic(gpa, text, &diagnostic) catch |err| {
        if (diagnostic.unknown_field) |field| {
            std.log.err("zoxy: invalid config {s}: unknown field {s}", .{ config_path, field });
        } else {
            std.log.err("zoxy: invalid config {s}: {s}", .{ config_path, @errorName(err) });
        }
        return err;
    };
    const router = Router.init(&cfg);

    const worker_count = std.Thread.getCpuCount() catch 1;
    assert(worker_count >= 1); // one worker thread is spawned even if the count fails

    // TLS (docs/DESIGN.md §6): install the memory hook first — it must precede
    // any other OpenSSL call, so it runs before either context is built.
    try reserve_tls_heap(gpa, &cfg, worker_count);
    const tls_context = try build_downstream_tls(init.io, gpa, &cfg);
    const upstream_tls = try build_upstream_contexts(init.io, gpa, &cfg);

    // Graceful drain (docs/DESIGN.md §7 Phase 4): SIGTERM/SIGINT are blocked
    // BEFORE the signalfd and BEFORE any worker spawns (workers inherit the
    // mask); each worker then waits on one end of a drain socketpair.
    const signal_fd = try install_signal_fd();
    const drain_triggers = try create_drain_triggers(gpa, worker_count);

    // Shared counters (atomic), reserved before the adopt inside
    // setup_listeners so a predecessor's totals fold in (scrapes stay monotonic
    // across a hot restart; gauges start over; see Metrics.gauge_fields).
    var metrics: Metrics = .{};

    // Listeners are adopted from a predecessor before any fresh bind; pools are
    // fully reserved before any worker spawns (workers touch no shared alloc).
    const listeners = try setup_listeners(gpa, &cfg, worker_count, &metrics);
    const worker_pools =
        try reserve_worker_pools(gpa, &cfg, worker_count, tls_context, upstream_tls);

    const threads = try spawn_workers(
        gpa,
        init.io,
        &cfg,
        &router,
        &metrics,
        tls_context,
        upstream_tls,
        worker_pools,
        listeners.listeners,
        drain_triggers,
        listeners.shared_refs,
    );

    // Hot restart: serve our listener fds to a successor (started after the
    // adopt/bind above, so the fds are already in hand), then the admin plane.
    try start_handoff_server(gpa, &cfg, listeners.listeners, &metrics);
    try start_admin(gpa, &cfg, &metrics);

    std.log.info("zoxy listening on {f} across {d} worker(s)", .{ cfg.listen, worker_count });

    // Block until the first signal, poke every worker's drain trigger, join.
    try drain_and_join(threads, drain_triggers, signal_fd);
}

/// Reserve the TLS FFI heap and install the process-global memory hook when any
/// hop is TLS — the terminating listener or a re-encrypting cluster. Must run
/// before any other OpenSSL call (docs/DESIGN.md §6).
fn reserve_tls_heap(
    gpa: std.mem.Allocator,
    cfg: *const zoxy.config.Config,
    worker_count: usize,
) !void {
    var clusters_with_tls: usize = 0;
    for (cfg.clusters) |cluster| {
        if (cluster.tls != null) clusters_with_tls += 1;
    }
    if (cfg.tls == null and clusters_with_tls == 0) return;
    // Sized so every connection slot on every worker can be TLS on both hops,
    // plus every upstream-pool slot parking a TLS channel (per-connection cost
    // measured; see constants.zig). Virtual reservation: pages are touched only
    // as connections carve.
    const hops: usize = if (cfg.tls != null and clusters_with_tls > 0) 2 else 1;
    const parked: usize = if (clusters_with_tls > 0) constants.upstream_idle_max else 0;
    const tls_heap_bytes = constants.tls_heap_base_bytes +
        constants.tls_heap_per_connection_bytes * worker_count *
            (constants.connections_max * hops + parked);
    const alignment = comptime std.mem.Alignment.fromByteUnits(zoxy.tls.Heap.block_align);
    const region = try gpa.alignedAlloc(u8, alignment, tls_heap_bytes);
    try zoxy.tls.install_memory_hook(region);
}

/// Downstream termination: the shared server context — an unloadable identity
/// fails startup, not the first handshake. Immutable once built (session cache
/// and tickets off), so one instance serves every worker.
fn build_downstream_tls(
    io: std.Io,
    gpa: std.mem.Allocator,
    cfg: *const zoxy.config.Config,
) !?*const zoxy.terminator.Context {
    const tls_config = cfg.tls orelse return null;
    const context = try gpa.create(zoxy.terminator.Context);
    context.* = load_tls_identity(
        io,
        gpa,
        tls_config.certificate_file,
        tls_config.private_key_file,
    ) catch |err| {
        std.log.err("zoxy: cannot load tls identity ({s} / {s}): {s}", .{
            tls_config.certificate_file,
            tls_config.private_key_file,
            @errorName(err),
        });
        return err;
    };
    context.kernel_offload = tls_config.kernel_offload;
    // The ALPN gate (docs/DESIGN.md §7 Phase 5): offer h2, and the handshaker
    // hands `h2`-negotiating connections to the H2 data path.
    if (tls_config.http2) zoxy.terminator.enable_h2(context);
    std.log.info("zoxy tls listener: {s} (kernel_offload={}, http2={})", .{
        tls_config.certificate_file,
        tls_config.kernel_offload,
        tls_config.http2,
    });
    // SNI identities beyond the default certificate (docs/DESIGN.md §6).
    if (tls_config.additional_identities.len > 0) {
        const table = try build_sni_table(io, gpa, tls_config);
        zoxy.terminator.enable_sni(context, table);
    }
    return context;
}

/// Build the SNI table for the additional identities: one loaded context per
/// entry, keyed by its server names (docs/DESIGN.md §6).
fn build_sni_table(
    io: std.Io,
    gpa: std.mem.Allocator,
    tls_config: zoxy.config.TlsConfig,
) !*const zoxy.terminator.SniTable {
    const entries = try gpa.alloc(
        zoxy.terminator.SniTable.Entry,
        tls_config.additional_identities.len,
    );
    for (tls_config.additional_identities, entries) |identity, *entry| {
        const identity_context = try gpa.create(zoxy.terminator.Context);
        identity_context.* = load_tls_identity(
            io,
            gpa,
            identity.certificate_file,
            identity.private_key_file,
        ) catch |err| {
            std.log.err("zoxy: cannot load sni identity ({s}): {s}", .{
                identity.certificate_file,
                @errorName(err),
            });
            return err;
        };
        identity_context.kernel_offload = tls_config.kernel_offload;
        if (tls_config.http2) zoxy.terminator.enable_h2(identity_context);
        entry.* = .{
            .server_names = identity.server_names,
            .context = identity_context,
        };
        std.log.info("zoxy sni identity: {s} ({d} name(s))", .{
            identity.certificate_file,
            identity.server_names.len,
        });
    }
    const table = try gpa.create(zoxy.terminator.SniTable);
    table.* = .{ .entries = entries };
    return table;
}

/// Upstream re-encryption: one verifying client context per TLS cluster,
/// indexed by cluster position (the data path routes by cluster_index).
fn build_upstream_contexts(
    io: std.Io,
    gpa: std.mem.Allocator,
    cfg: *const zoxy.config.Config,
) ![]?*const zoxy.terminator.Context {
    const upstream_tls = try gpa.alloc(?*const zoxy.terminator.Context, cfg.clusters.len);
    for (cfg.clusters, upstream_tls) |cluster, *slot| {
        slot.* = null;
        const cluster_tls = cluster.tls orelse continue;
        const context = try gpa.create(zoxy.terminator.Context);
        context.* = build_upstream_context(io, gpa, cluster_tls) catch |err| {
            std.log.err("zoxy: cluster {s}: cannot build upstream tls: {s}", .{
                cluster.name,
                @errorName(err),
            });
            return err;
        };
        slot.* = context;
        std.log.info("zoxy cluster {s}: upstream tls ({s})", .{
            cluster.name,
            if (cluster_tls.insecure) "insecure" else cluster_tls.server_name.?,
        });
    }
    return upstream_tls;
}

/// Block SIGTERM/SIGINT in this thread (workers inherit the mask) and create
/// the signalfd that surfaces them — must run before any worker spawns.
fn install_signal_fd() !linux.fd_t {
    var signal_mask = linux.sigemptyset();
    linux.sigaddset(&signal_mask, .TERM);
    linux.sigaddset(&signal_mask, .INT);
    _ = linux.sigprocmask(linux.SIG.BLOCK, &signal_mask, null);
    const signal_fd_rc = linux.signalfd(-1, &signal_mask, linux.SFD.CLOEXEC);
    if (linux.errno(signal_fd_rc) != .SUCCESS) {
        std.log.err("zoxy: cannot create signalfd: {s}", .{@tagName(linux.errno(signal_fd_rc))});
        return error.SignalFdFailed;
    }
    return @intCast(signal_fd_rc);
}

/// One drain socketpair per worker: the worker keeps a recv pending on its end,
/// main writes the other to wake a worker blocked in io_uring_enter.
fn create_drain_triggers(gpa: std.mem.Allocator, worker_count: usize) ![][2]linux.fd_t {
    const drain_triggers = try gpa.alloc([2]linux.fd_t, worker_count);
    for (drain_triggers) |*pair| {
        var fds: [2]i32 = undefined;
        const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
        if (linux.errno(rc) != .SUCCESS) {
            std.log.err("zoxy: cannot create drain socketpair: {s}", .{@tagName(linux.errno(rc))});
            return error.SocketPairFailed;
        }
        pair.* = .{ fds[0], fds[1] };
    }
    return drain_triggers;
}

const ListenerSetup = struct {
    listeners: []Listener,
    shared_refs: ?*zoxy.Counter,
};

/// Adopt a predecessor's listeners over the handoff socket when one is running
/// (docs/DESIGN.md §7 Phase 4: the SCM_RIGHTS duplicates keep the accept queues
/// alive across the restart), fresh binds otherwise. accept_mode decides the
/// shape: `reuseport` = one listener per worker (kernel hashes); `shared` = one
/// listener with a shared refcount. Modes may mix across a hot restart: every
/// listener carries SO_REUSEPORT, so fresh binds join an adopted socket's group.
fn setup_listeners(
    gpa: std.mem.Allocator,
    cfg: *const zoxy.config.Config,
    worker_count: usize,
    metrics: *Metrics,
) !ListenerSetup {
    const unique_listener_count: usize =
        if (cfg.accept_mode == .shared) 1 else worker_count;
    var adopted_fds: [constants.workers_max]std.posix.socket_t = undefined;
    var adopted_count: usize = 0;
    if (cfg.handoff) |path| {
        adopted_count = zoxy.handoff.adopt(path, cfg.listen, &adopted_fds, metrics);
        if (adopted_count > 0) {
            std.log.info("zoxy: adopted {d} listener(s) from a predecessor", .{adopted_count});
        }
    }
    if (adopted_count > unique_listener_count) {
        // A predecessor with more listeners (more workers, or an accept-mode
        // change): nobody would ever accept from the surplus queues — close them.
        std.log.warn("zoxy: closing {d} surplus adopted listener(s)", .{
            adopted_count - unique_listener_count,
        });
        for (adopted_fds[unique_listener_count..adopted_count]) |fd| _ = linux.close(fd);
        adopted_count = unique_listener_count;
    }
    const unique_listeners = try gpa.alloc(Listener, unique_listener_count);
    for (unique_listeners, 0..) |*listener, index| {
        listener.* = if (index < adopted_count)
            Listener{ .fd = adopted_fds[index] }
        else
            Listener.open(cfg.listen, constants.accept_backlog) catch |err| {
                std.log.err("zoxy: cannot listen on {f}: {s}", .{ cfg.listen, @errorName(err) });
                return err;
            };
    }
    // Shared mode: the last draining worker closes the one listener fd.
    var shared_listener_refs: ?*zoxy.Counter = null;
    if (cfg.accept_mode == .shared) {
        const refs = try gpa.create(zoxy.Counter);
        refs.* = .{ .value = worker_count };
        shared_listener_refs = refs;
    }
    return .{ .listeners = unique_listeners, .shared_refs = shared_listener_refs };
}

const WorkerPools = struct {
    accesses: []cache_line.Padded(AccessLog),
    pools: []cache_line.Padded(Pool),
    leg_pools: []cache_line.Padded(TlsLegPool),
    h2_conn_pools: []cache_line.Padded(H2ConnPool),
    h2_leg_pools: []cache_line.Padded(H2LegPool),
    tls_sides: u32,
    http2_enabled: bool,
};

/// Reserve every worker's pool up front, on this thread, so worker startup
/// touches no shared allocator and the serving loop allocates nothing. All
/// slots are cache-line-padded: adjacent workers' mutable state (a pool header,
/// an access log's `used`) must never share a line, like the metrics shards.
fn reserve_worker_pools(
    gpa: std.mem.Allocator,
    cfg: *const zoxy.config.Config,
    worker_count: usize,
    tls_context: ?*const zoxy.terminator.Context,
    upstream_tls: []const ?*const zoxy.terminator.Context,
) !WorkerPools {
    const accesses = try gpa.alloc(cache_line.Padded(AccessLog), worker_count);
    for (accesses) |*slot| slot.value = .{ .fd = stderr_fd };

    const pools = try gpa.alloc(cache_line.Padded(Pool), worker_count);
    for (pools) |*slot| slot.value = try Pool.init(gpa, constants.connections_max);

    // TLS legs live in their own per-worker pool, sized one leg per connection
    // per TLS-speaking side — a plaintext config reserves none.
    var tls_sides: u32 = 0;
    if (tls_context != null) tls_sides += 1;
    for (upstream_tls) |slot| {
        if (slot != null) {
            tls_sides += 1;
            break;
        }
    }
    const leg_pools: []cache_line.Padded(TlsLegPool) = if (tls_sides > 0) pools: {
        const leg_pools = try gpa.alloc(cache_line.Padded(TlsLegPool), worker_count);
        for (leg_pools) |*slot| {
            slot.value = try TlsLegPool.init(gpa, constants.connections_max * tls_sides);
        }
        break :pools leg_pools;
    } else &.{};

    // HTTP/2 pools, reserved per worker only when a TLS listener offers h2
    // (docs/DESIGN.md §7 Phase 5): the pool a handoff draws from and the
    // stream-leg pool its per-stream upstream transactions use.
    const http2_enabled = if (cfg.tls) |t| t.http2 else false;
    const h2_conn_pools: []cache_line.Padded(H2ConnPool) = if (http2_enabled) pools: {
        const h2_pools = try gpa.alloc(cache_line.Padded(H2ConnPool), worker_count);
        for (h2_pools) |*slot| slot.value = try H2ConnPool.init(gpa, constants.h2_connections_max);
        break :pools h2_pools;
    } else &.{};
    const h2_leg_pools: []cache_line.Padded(H2LegPool) = if (http2_enabled) pools: {
        const h2_pools = try gpa.alloc(cache_line.Padded(H2LegPool), worker_count);
        for (h2_pools) |*slot| slot.value = try H2LegPool.init(gpa, constants.h2_legs_max);
        break :pools h2_pools;
    } else &.{};

    return .{
        .accesses = accesses,
        .pools = pools,
        .leg_pools = leg_pools,
        .h2_conn_pools = h2_conn_pools,
        .h2_leg_pools = h2_leg_pools,
        .tls_sides = tls_sides,
        .http2_enabled = http2_enabled,
    };
}

/// Seed one entropy draw for every worker's PRNG (each offsets it by its cpu
/// index) and spawn the worker threads — after all pools are reserved.
fn spawn_workers(
    gpa: std.mem.Allocator,
    io: std.Io,
    cfg: *const zoxy.config.Config,
    router: *const Router,
    metrics: *Metrics,
    tls_context: ?*const zoxy.terminator.Context,
    upstream_tls: []const ?*const zoxy.terminator.Context,
    worker_pools: WorkerPools,
    listeners: []const Listener,
    drain_triggers: []const [2]linux.fd_t,
    shared_listener_refs: ?*zoxy.Counter,
) ![]std.Thread {
    var seed_bytes: [8]u8 = undefined;
    io.random(&seed_bytes);
    const seed_base = std.mem.readInt(u64, &seed_bytes, .little);

    const pools = worker_pools.pools;
    const leg_pools = worker_pools.leg_pools;
    const h2_conn_pools = worker_pools.h2_conn_pools;
    const h2_leg_pools = worker_pools.h2_leg_pools;
    const tls_sides = worker_pools.tls_sides;
    const http2_enabled = worker_pools.http2_enabled;

    const threads = try gpa.alloc(std.Thread, pools.len);
    for (threads, pools, worker_pools.accesses, drain_triggers, 0..) |
        *thread,
        *pool_slot,
        *access_slot,
        trigger,
        cpu,
    | {
        const listener = listeners[if (cfg.accept_mode == .shared) 0 else cpu];
        const legs: ?*TlsLegPool = if (tls_sides > 0) &leg_pools[cpu].value else null;
        const h2_conns: ?*H2ConnPool = if (http2_enabled) &h2_conn_pools[cpu].value else null;
        const h2_legs: ?*H2LegPool = if (http2_enabled) &h2_leg_pools[cpu].value else null;
        thread.* = try std.Thread.spawn(
            .{},
            run_worker,
            .{
                listener,   &pool_slot.value,     router,
                metrics,    &access_slot.value,   seed_base,
                cpu,        tls_context,          upstream_tls,
                legs,       h2_conns,             h2_legs,
                trigger[0], shared_listener_refs,
            },
        );
    }
    return threads;
}

/// Hot restart: serve our listener fds to a successor on a detached thread.
/// Bound *after* the adopt in setup_listeners, so a fresh process replaces
/// (unlinks) its predecessor's socket file only once the fds are in hand.
fn start_handoff_server(
    gpa: std.mem.Allocator,
    cfg: *const zoxy.config.Config,
    listeners: []const Listener,
    metrics: *Metrics,
) !void {
    const path = cfg.handoff orelse return;
    const handoff_fd = zoxy.handoff.open_server(path) catch |err| {
        std.log.err("zoxy: cannot open handoff socket {s}: {s}", .{ path, @errorName(err) });
        return err;
    };
    const listener_fds = try gpa.alloc(std.posix.socket_t, listeners.len);
    for (listeners, listener_fds) |listener, *fd| fd.* = listener.fd;
    const handoff_thread = try std.Thread.spawn(
        .{},
        run_handoff_server,
        .{ handoff_fd, listener_fds, cfg.listen, metrics },
    );
    handoff_thread.detach();
    std.log.info("zoxy handoff socket on {s}", .{path});
}

/// Admin/metrics plane: blocking, on its own detached thread, off the data
/// path. Arena-allocated so it outlives this scope.
fn start_admin(
    gpa: std.mem.Allocator,
    cfg: *const zoxy.config.Config,
    metrics: *Metrics,
) !void {
    const admin_address = cfg.admin orelse return;
    const admin = try gpa.create(zoxy.Admin);
    admin.* = zoxy.Admin.open(admin_address, metrics) catch |err| {
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

/// Block until the first signal, poke every worker's drain trigger, then join:
/// each worker exits once its connections finish (or the drain deadline
/// force-closes the stragglers). A second signal — watched by a detached
/// thread — exits immediately.
fn drain_and_join(
    threads: []const std.Thread,
    drain_triggers: []const [2]linux.fd_t,
    signal_fd: linux.fd_t,
) !void {
    wait_for_signal(signal_fd);
    std.log.info("zoxy: draining {d} worker(s) (limit {d}ms; second signal exits now)", .{
        threads.len,
        constants.drain_timeout_ns / std.time.ns_per_ms,
    });
    for (drain_triggers) |pair| {
        const poke = [1]u8{'d'};
        _ = linux.write(pair[1], &poke, poke.len); // EOF from a failed write drains too
    }
    const watcher = try std.Thread.spawn(.{}, hard_exit_watcher, .{signal_fd});
    watcher.detach();
    for (threads) |thread| thread.join();
    std.log.info("zoxy: drained, exiting", .{});
}

/// Block until one of the masked signals is delivered to the signalfd.
fn wait_for_signal(signal_fd: linux.fd_t) void {
    var info: linux.signalfd_siginfo = undefined;
    while (true) { // bounded by delivery: reads only fail transiently (EINTR)
        const rc = linux.read(signal_fd, std.mem.asBytes(&info), @sizeOf(linux.signalfd_siginfo));
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) return; // treat a broken signalfd as a signal
        if (rc == @sizeOf(linux.signalfd_siginfo)) return;
    }
}

/// A second signal during the drain means "now": skip the joins and die.
fn hard_exit_watcher(signal_fd: linux.fd_t) void {
    wait_for_signal(signal_fd);
    std.log.warn("zoxy: second signal — exiting without drain", .{});
    linux.exit_group(1);
}

/// Serve the handoff socket until one successor takes the listeners, then
/// trigger our own drain through the normal signal path — one drain entry
/// point. Once draining, further successors are accepted-and-dropped so
/// they fall back to fresh binds instead of waiting on closing fds.
fn run_handoff_server(
    handoff_fd: std.posix.socket_t,
    listener_fds: []const std.posix.socket_t,
    listen: Ip4Address,
    metrics: *const Metrics,
) void {
    assert(listener_fds.len > 0);
    while (true) { // bounded by process lifetime: one success ends it
        if (metrics.total("draining") > 0) {
            const rc = linux.accept4(handoff_fd, null, null, linux.SOCK.CLOEXEC);
            if (linux.errno(rc) == .SUCCESS) _ = linux.close(@as(i32, @intCast(rc)));
            continue;
        }
        if (zoxy.handoff.serve_once(handoff_fd, listener_fds, listen, metrics)) break;
    }
    std.log.info("zoxy: listeners handed to a successor; draining", .{});
    _ = linux.kill(linux.getpid(), .TERM);
}

/// Build one cluster's upstream (client-role) context: read the CA bundle
/// when verification is on, or honor the explicit `insecure`.
fn build_upstream_context(
    io: std.Io,
    gpa: std.mem.Allocator,
    cluster_tls: zoxy.config.ClusterTlsConfig,
) !zoxy.terminator.Context {
    if (cluster_tls.insecure) {
        assert(cluster_tls.ca_file == null); // config.parse rejects the mix
        return zoxy.terminator.Context.init_client(.insecure);
    }
    const ca_file = cluster_tls.ca_file.?; // config.parse guarantees the pair
    const server_name = cluster_tls.server_name.?;
    assert(server_name.len > 0);
    const limit = std.Io.Limit.limited(constants.tls_pem_bytes_max);
    const bundle_pem = try std.Io.Dir.cwd().readFileAlloc(io, ca_file, gpa, limit);
    return zoxy.terminator.Context.init_client(.{ .authority = .{
        .bundle_pem = bundle_pem,
        .host = server_name,
    } });
}

/// Read a certificate/key PEM pair (startup-time, bounded) and build a
/// server context from it — parsing, cross-checking, and installing the
/// identity via the exact stack that will terminate TLS.
fn load_tls_identity(
    io: std.Io,
    gpa: std.mem.Allocator,
    certificate_file: []const u8,
    private_key_file: []const u8,
) !zoxy.terminator.Context {
    assert(certificate_file.len > 0); // config.parse rejects empty
    assert(private_key_file.len > 0);
    const limit = std.Io.Limit.limited(constants.tls_pem_bytes_max);
    const certificate_pem = try std.Io.Dir.cwd()
        .readFileAlloc(io, certificate_file, gpa, limit);
    const private_key_pem = try std.Io.Dir.cwd()
        .readFileAlloc(io, private_key_file, gpa, limit);
    return zoxy.terminator.Context.init_server(certificate_pem, private_key_pem);
}

/// One share-nothing worker: its own IO ring, SO_REUSEPORT listener, and pool,
/// pinned to a core. Runs the proxy accept/relay loop until a drain completes
/// (or forever, if no drain is ever triggered).
fn run_worker(
    listener: Listener,
    pool: *Pool,
    router: *const Router,
    metrics: *Metrics,
    access: *AccessLog,
    seed_base: u64,
    cpu: usize,
    tls_context: ?*const zoxy.terminator.Context,
    upstream_tls: []const ?*const zoxy.terminator.Context,
    tls_legs: ?*TlsLegPool,
    h2_conn_pool: ?*H2ConnPool,
    h2_leg_pool: ?*H2LegPool,
    drain_trigger_fd: std.posix.socket_t,
    listener_refs: ?*zoxy.Counter,
) void {
    assert(pool.capacity > 0);
    assert(listener.fd >= 0); // opened (or adopted) by main; never closes early
    pin_to_cpu(cpu);

    var io = IO.init(constants.io_ring_entries, 0) catch |err|
        return log_worker_error("io init", err);
    defer io.deinit();

    // The listener is owned by main (fresh bind or adopted via handoff); the
    // drain path closes this worker's use of it exactly once, via
    // `close_listener`, the moment accepting stops — a successor holding a
    // handed-off duplicate keeps the accept queue alive past that close.
    // This worker's metrics shard — the only counters it ever writes (no
    // shared cache line on the data path). Workers beyond the shard table
    // share its last worker slot (the accept series is diagnostic only).
    const counters = metrics.shard(@intCast(@min(cpu, constants.workers_max - 1)));
    var server = ProxyServer.init(
        &io,
        pool,
        listener,
        router,
        counters,
        access,
        constants.request_timeout_ns,
        constants.idle_timeout_ns,
    );
    server.prng = .init(seed_base +% cpu);
    server.tls_context = tls_context;
    server.upstream_tls_contexts = upstream_tls;
    server.tls_legs = tls_legs;
    server.h2_conn_pool = h2_conn_pool;
    server.h2_leg_pool = h2_leg_pool;
    server.drain_trigger_fd = drain_trigger_fd;
    server.listener_refs = listener_refs;
    server.start();

    // Active health checks ride the same ring; arms only when configured.
    var health = zoxy.HealthChecker.init(&io, router.config.clusters, &server.resilience, counters);
    health.start();

    while (!server.drain_complete()) {
        io.run_once() catch |err| return log_worker_error("io run", err);
        access.flush(); // batched: one write per event-loop iteration, off the per-connection path
    }
    // Drained: every connection slot is back and no server op is on the ring.
    quiesce_worker(&io, &server, &health, access);
}

/// Post-drain shutdown: stop the health checker and let its cancelled probes
/// quiesce (bounded — its tick is at most one `health_tick_ns` away), close
/// the parked upstream connections, and bring the ring down clean.
fn quiesce_worker(
    io: *IO,
    server: *ProxyServer,
    health: *zoxy.HealthChecker,
    access: *AccessLog,
) void {
    health.stop();
    while (!health.quiesced()) {
        io.run_once() catch break; // nothing pending: already quiet
    }
    server.deinit();
    access.flush();
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
