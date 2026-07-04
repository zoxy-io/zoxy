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

    // TLS (docs/DESIGN.md §6): reserve the FFI heap and install the
    // process-global memory hook (must precede any other OpenSSL call) when
    // any hop is TLS — the terminating listener or a re-encrypting cluster.
    var clusters_with_tls: usize = 0;
    for (cfg.clusters) |cluster| {
        if (cluster.tls != null) clusters_with_tls += 1;
    }
    if (cfg.tls != null or clusters_with_tls > 0) {
        // Sized so every connection slot on every worker can be TLS on both
        // hops, plus every upstream-pool slot parking a TLS channel
        // (per-connection cost measured; see constants.zig). Virtual
        // reservation: pages are touched only as connections carve.
        const hops: usize = if (cfg.tls != null and clusters_with_tls > 0) 2 else 1;
        const parked: usize = if (clusters_with_tls > 0) constants.upstream_idle_max else 0;
        const tls_heap_bytes = constants.tls_heap_base_bytes +
            constants.tls_heap_per_connection_bytes * worker_count *
                (constants.connections_max * hops + parked);
        const alignment = comptime std.mem.Alignment.fromByteUnits(zoxy.tls.Heap.block_align);
        const region = try gpa.alignedAlloc(u8, alignment, tls_heap_bytes);
        try zoxy.tls.install_memory_hook(region);
    }

    // Downstream termination: the shared server context — an unloadable
    // identity fails startup, not the first handshake. Immutable once built
    // (session cache and tickets off), so one instance serves every worker.
    var tls_context: ?*const zoxy.terminator.Context = null;
    if (cfg.tls) |tls_config| {
        const context = try gpa.create(zoxy.terminator.Context);
        context.* = load_tls_identity(
            init.io,
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
        tls_context = context;
        std.log.info("zoxy tls listener: {s} (kernel_offload={})", .{
            tls_config.certificate_file,
            tls_config.kernel_offload,
        });

        // SNI identities beyond the default certificate (docs/DESIGN.md §6).
        if (tls_config.additional_identities.len > 0) {
            const entries = try gpa.alloc(
                zoxy.terminator.SniTable.Entry,
                tls_config.additional_identities.len,
            );
            for (tls_config.additional_identities, entries) |identity, *entry| {
                const identity_context = try gpa.create(zoxy.terminator.Context);
                identity_context.* = load_tls_identity(
                    init.io,
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
            zoxy.terminator.enable_sni(context, table);
        }
    }

    // Upstream re-encryption: one verifying client context per TLS cluster,
    // indexed by cluster position (the data path routes by cluster_index).
    const upstream_tls = try gpa.alloc(?*const zoxy.terminator.Context, cfg.clusters.len);
    for (cfg.clusters, upstream_tls) |cluster, *slot| {
        slot.* = null;
        const cluster_tls = cluster.tls orelse continue;
        const context = try gpa.create(zoxy.terminator.Context);
        context.* = build_upstream_context(init.io, gpa, cluster_tls) catch |err| {
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

    // Graceful drain (docs/DESIGN.md §7 Phase 4): SIGTERM/SIGINT are blocked
    // in every thread (workers inherit this mask) and surface only through
    // the signalfd read below. Each worker gets one end of a socketpair with
    // a recv pending on its ring — writing the other end is how a signal
    // wakes a worker that is blocked in io_uring_enter.
    var signal_mask = linux.sigemptyset();
    linux.sigaddset(&signal_mask, .TERM);
    linux.sigaddset(&signal_mask, .INT);
    _ = linux.sigprocmask(linux.SIG.BLOCK, &signal_mask, null);
    const signal_fd_rc = linux.signalfd(-1, &signal_mask, linux.SFD.CLOEXEC);
    if (linux.errno(signal_fd_rc) != .SUCCESS) {
        std.log.err("zoxy: cannot create signalfd: {s}", .{@tagName(linux.errno(signal_fd_rc))});
        return error.SignalFdFailed;
    }
    const signal_fd: linux.fd_t = @intCast(signal_fd_rc);

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

    // Shared counters (atomic), reserved before the adopt below so a
    // predecessor's totals can be folded in — scrapes stay monotonic across
    // a hot restart (gauges start over; see Metrics.gauge_fields).
    var metrics: Metrics = .{};

    // Listeners are owned by main — adopted from a predecessor over the
    // handoff socket when one is running (docs/DESIGN.md §7 Phase 4: the
    // SCM_RIGHTS duplicates keep the accept queues alive across the
    // restart), fresh binds otherwise. A bind failure now fails startup
    // instead of killing a lone worker thread. accept_mode decides the
    // shape: `reuseport` = one listener per worker, kernel hashes;
    // `shared` = one listener, every worker holds a pending accept and the
    // kernel completes exactly one per connection — idle workers naturally
    // pull more. Modes may mix across a hot restart: every listener carries
    // SO_REUSEPORT, so fresh binds join an adopted socket's group.
    const unique_listener_count: usize =
        if (cfg.accept_mode == .shared) 1 else worker_count;
    var adopted_fds: [constants.workers_max]std.posix.socket_t = undefined;
    var adopted_count: usize = 0;
    if (cfg.handoff) |path| {
        adopted_count = zoxy.handoff.adopt(path, cfg.listen, &adopted_fds, &metrics);
        if (adopted_count > 0) {
            std.log.info("zoxy: adopted {d} listener(s) from a predecessor", .{adopted_count});
        }
    }
    if (adopted_count > unique_listener_count) {
        // A predecessor with more listeners (more workers, or an
        // accept-mode change): nobody would ever accept from the surplus
        // queues once it drains — close them.
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

    // Per-worker access logs, reserved up front. Cache-line-padded slots:
    // `used` moves on every request, and adjacent workers' mutable state
    // must not share a line (same rule as the metrics shards).
    const accesses = try gpa.alloc(cache_line.Padded(AccessLog), worker_count);
    for (accesses) |*slot| slot.value = .{ .fd = stderr_fd };

    // Reserve every worker's pool up front, on this thread, so worker startup
    // touches no shared allocator and the serving loop allocates nothing.
    // Padded like the access logs: a pool header (free list head/count) is
    // written on every connection acquire/release by its owning worker.
    const pools = try gpa.alloc(cache_line.Padded(Pool), worker_count);
    for (pools) |*slot| slot.value = try Pool.init(gpa, constants.connections_max);

    // One entropy draw seeds every worker's PRNG (P2C draws, retry jitter);
    // each worker offsets it by its cpu index so no two draw alike.
    var seed_bytes: [8]u8 = undefined;
    init.io.random(&seed_bytes);
    const seed_base = std.mem.readInt(u64, &seed_bytes, .little);

    const threads = try gpa.alloc(std.Thread, worker_count);
    for (threads, pools, accesses, drain_triggers, 0..) |
        *thread,
        *pool_slot,
        *access_slot,
        trigger,
        cpu,
    | {
        const listener = unique_listeners[if (cfg.accept_mode == .shared) 0 else cpu];
        thread.* = try std.Thread.spawn(
            .{},
            run_worker,
            .{
                listener,   &pool_slot.value,     &router,
                &metrics,   &access_slot.value,   seed_base,
                cpu,        tls_context,          upstream_tls,
                trigger[0], shared_listener_refs,
            },
        );
    }

    // Hot restart: serve our listener fds to a successor, then drain. Bound
    // *after* the adopt above, so a fresh process replaces (unlinks) its
    // predecessor's socket file only once the fds are already in hand.
    if (cfg.handoff) |path| {
        const handoff_fd = zoxy.handoff.open_server(path) catch |err| {
            std.log.err("zoxy: cannot open handoff socket {s}: {s}", .{ path, @errorName(err) });
            return err;
        };
        const listener_fds = try gpa.alloc(std.posix.socket_t, unique_listener_count);
        for (unique_listeners, listener_fds) |listener, *fd| fd.* = listener.fd;
        const handoff_thread = try std.Thread.spawn(
            .{},
            run_handoff_server,
            .{ handoff_fd, listener_fds, cfg.listen, &metrics },
        );
        handoff_thread.detach();
        std.log.info("zoxy handoff socket on {s}", .{path});
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

    // Block until the first SIGTERM/SIGINT, poke every worker's drain
    // trigger, then join them: each exits once its connections finish (or
    // the drain deadline force-closes the stragglers). A second signal —
    // watched by a detached thread — exits immediately.
    wait_for_signal(signal_fd);
    std.log.info("zoxy: draining {d} worker(s) (limit {d}ms; second signal exits now)", .{
        worker_count,
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
    // Drained: every connection slot is back and no server op is on the
    // ring. Quiesce the health checker (bounded: its probes are cancelled,
    // its tick is at most one `health_tick_ns` away), close the parked
    // upstream connections, and let the ring go down clean.
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
