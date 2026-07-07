//! Active health checking (Phase 2, docs/DESIGN.md §7): per-worker, in-ring
//! TCP-connect probes. Each worker probes independently — share-nothing, no
//! new threads, deterministic in the simulator; the redundancy is bounded
//! (workers x endpoints / interval) and documented. A probe is a TCP connect
//! that must complete within the policy timeout, then closes immediately;
//! streaks of probe results flip the endpoint's `healthy` flag (consumed by
//! the balancer's availability check) at the configured thresholds.
//!
//! Endpoints start healthy — a restarting proxy must serve immediately (a
//! documented delta from Envoy, which waits for a passing probe).
//!
//! One scheduler timer ticks at `health_tick_ns`: it reaps timed-out probes
//! (cancel the connect; the completion drains through the normal callback)
//! and launches due probes into a bounded slot table — never more than
//! `health_probes_inflight_max` in flight, later endpoints wait a tick.
//! Everything is statically sized; nothing allocates.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const assert = std.debug.assert;

const constants = @import("../constants.zig");
const config = @import("../config.zig");
const io_mod = @import("../io/io.zig");
const IO = io_mod.IO;
const Completion = io_mod.Completion;
const Resilience = @import("resilience.zig").Resilience;
const Counters = @import("../obs/metrics.zig").Counters;

pub const HealthChecker = struct {
    io: *IO,
    clusters: []const config.Cluster,
    resilience: *Resilience,
    metrics: *Counters,
    /// Absolute due instant per (cluster, endpoint); 0 = never probed
    /// (health checking off for that cluster).
    next_probe_ns: [constants.clusters_max][constants.endpoints_per_cluster_max]u64,
    probes: [constants.health_probes_inflight_max]Probe,
    running: bool,
    tick_pending: bool,
    tick_completion: Completion,

    const Probe = struct {
        checker: *HealthChecker = undefined,
        cluster_index: u32 = 0,
        endpoint_index: u32 = 0,
        fd: posix.socket_t = -1,
        /// Absolute instant after which the connect counts as failed.
        deadline_ns: u64 = 0,
        connect_pending: bool = false,
        /// A cancel targeting `connect_completion` is in flight; the slot is
        /// not reusable until it drains (a stale cancel could kill the next
        /// probe's connect on the reused completion).
        cancel_pending: bool = false,
        connect_completion: Completion = undefined,
        cancel_completion: Completion = undefined,

        fn busy(probe: *const Probe) bool {
            return probe.connect_pending or probe.cancel_pending;
        }
    };

    pub fn init(
        io: *IO,
        clusters: []const config.Cluster,
        resilience: *Resilience,
        metrics: *Counters,
    ) HealthChecker {
        assert(clusters.len <= constants.clusters_max); // enforced by config.parse
        return .{
            .io = io,
            .clusters = clusters,
            .resilience = resilience,
            .metrics = metrics,
            .next_probe_ns = @splat(@splat(0)),
            .probes = @splat(.{}),
            .running = false,
            .tick_pending = false,
            .tick_completion = undefined,
        };
    }

    /// Arm the scheduler if any cluster configures health checks. First
    /// probes are staggered across one interval so a restart does not
    /// thunder-herd every endpoint at once.
    pub fn start(checker: *HealthChecker) void {
        assert(!checker.running);
        assert(!checker.tick_pending);
        for (&checker.probes) |*probe| probe.checker = checker;
        const now = checker.io.now_ns();
        var checked_total: u64 = 0;
        for (checker.clusters) |*cluster| {
            if (cluster.policy.health_interval_ns == 0) continue;
            checked_total += cluster.endpoints.len;
        }
        if (checked_total == 0) return; // health checking is off everywhere
        var position: u64 = 0;
        for (checker.clusters) |*cluster| {
            const interval = cluster.policy.health_interval_ns;
            if (interval == 0) continue;
            for (cluster.endpoints, 0..) |_, endpoint_index| {
                const offset = position * interval / checked_total;
                // Clamped above 0: the simulator's clock starts at 0, and 0
                // is this table's "not health-checked" sentinel.
                checker.next_probe_ns[cluster.index][endpoint_index] = @max(now + offset, 1);
                position += 1;
            }
        }
        assert(position == checked_total);
        checker.running = true;
        checker.arm_tick();
    }

    /// Stop scheduling (graceful drain, tests): nothing re-arms, and every
    /// in-flight probe connect is cancelled so quiescence is bounded by the
    /// cancellations, not by a black-holed endpoint's SYN retries. Poll
    /// `quiesced` while driving the loop.
    pub fn stop(checker: *HealthChecker) void {
        checker.running = false;
        for (&checker.probes) |*probe| {
            if (!probe.connect_pending) continue;
            if (probe.cancel_pending) continue; // already being reaped
            probe.cancel_pending = true;
            checker.io.cancel(
                *Probe,
                probe,
                on_probe_cancel,
                &probe.cancel_completion,
                &probe.connect_completion,
            );
        }
    }

    pub fn quiesced(checker: *const HealthChecker) bool {
        if (checker.tick_pending) return false;
        for (&checker.probes) |*probe| {
            if (probe.busy()) return false;
        }
        return true;
    }

    fn arm_tick(checker: *HealthChecker) void {
        assert(checker.running);
        assert(!checker.tick_pending);
        checker.tick_pending = true;
        checker.io.timeout(
            *HealthChecker,
            checker,
            on_tick,
            &checker.tick_completion,
            constants.health_tick_ns,
        );
    }

    fn on_tick(checker: *HealthChecker, _: *Completion, _: io_mod.TimeoutError!void) void {
        checker.tick_pending = false;
        if (!checker.running) return;
        const now = checker.io.now_ns();
        checker.reap_timed_out(now);
        checker.launch_due(now);
        checker.arm_tick();
    }

    /// A probe past its deadline is a failure-in-progress: cancel the
    /// connect and let its completion record the failure.
    fn reap_timed_out(checker: *HealthChecker, now_ns: u64) void {
        for (&checker.probes) |*probe| {
            if (!probe.connect_pending) continue;
            if (now_ns < probe.deadline_ns) continue;
            if (probe.cancel_pending) continue; // already being reaped
            probe.cancel_pending = true;
            checker.io.cancel(
                *Probe,
                probe,
                on_probe_cancel,
                &probe.cancel_completion,
                &probe.connect_completion,
            );
        }
    }

    fn launch_due(checker: *HealthChecker, now_ns: u64) void {
        for (checker.clusters) |*cluster| {
            const policy = &cluster.policy;
            if (policy.health_interval_ns == 0) continue;
            for (cluster.endpoints, 0..) |*endpoint, endpoint_index| {
                const due = &checker.next_probe_ns[cluster.index][endpoint_index];
                assert(due.* != 0); // staggered at start for every checked endpoint
                if (now_ns < due.*) continue;
                const probe = checker.free_probe() orelse return; // all slots busy: next tick
                due.* = now_ns + policy.health_interval_ns;
                checker.launch(probe, cluster, @intCast(endpoint_index), endpoint.address);
            }
        }
    }

    fn free_probe(checker: *HealthChecker) ?*Probe {
        for (&checker.probes) |*probe| {
            if (!probe.busy()) return probe;
        }
        return null;
    }

    fn launch(
        checker: *HealthChecker,
        probe: *Probe,
        cluster: *const config.Cluster,
        endpoint_index: u32,
        address: std.Io.net.IpAddress,
    ) void {
        assert(!probe.busy());
        assert(cluster.policy.health_timeout_ns > 0);
        // fd pressure is our problem, not the endpoint's: skip this round
        // rather than record a bogus failure (the due instant has advanced).
        const fd = checker.io.open_tcp_socket(std.meta.activeTag(address)) orelse return;
        probe.cluster_index = @intCast(cluster.index);
        probe.endpoint_index = endpoint_index;
        probe.fd = fd;
        probe.deadline_ns = checker.io.now_ns() + cluster.policy.health_timeout_ns;
        probe.connect_pending = true;
        checker.io.connect(
            *Probe,
            probe,
            on_probe_connect,
            &probe.connect_completion,
            fd,
            io_mod.SocketAddress.from_ip(address),
        );
    }

    fn on_probe_connect(probe: *Probe, _: *Completion, result: io_mod.ConnectError!void) void {
        assert(probe.connect_pending);
        probe.connect_pending = false;
        assert(probe.fd >= 0);
        // Nothing else is ever in flight on a probe fd: close synchronously.
        probe.checker.io.close_now(probe.fd);
        probe.fd = -1;
        const success = if (result) |_| true else |_| false; // cancel arrives as an error
        // A probe cancelled by stop() says nothing about the endpoint.
        if (probe.checker.running) {
            probe.checker.record(probe.cluster_index, probe.endpoint_index, success);
        }
    }

    fn on_probe_cancel(probe: *Probe, _: *Completion, _: io_mod.CancelError!void) void {
        assert(probe.cancel_pending);
        probe.cancel_pending = false;
    }

    /// Fold a probe result into the endpoint's streaks and flip `healthy`
    /// at the thresholds. Streaks only accumulate toward a flip — the
    /// steady state stays at zero so a single blip cannot linger.
    fn record(
        checker: *HealthChecker,
        cluster_index: u32,
        endpoint_index: u32,
        success: bool,
    ) void {
        const policy = &checker.clusters[cluster_index].policy;
        assert(policy.health_interval_ns > 0); // probes only run when configured
        const endpoint = checker.resilience.endpoint_state(cluster_index, endpoint_index);
        checker.metrics.health_probes.add(1);
        if (success) {
            endpoint.probe_failures = 0;
            if (endpoint.healthy) return;
            endpoint.probe_successes += 1;
            if (endpoint.probe_successes < policy.health_threshold_healthy) return;
            endpoint.healthy = true;
            endpoint.probe_successes = 0;
        } else {
            checker.metrics.health_probe_failures.add(1);
            endpoint.probe_successes = 0;
            if (!endpoint.healthy) return;
            endpoint.probe_failures += 1;
            if (endpoint.probe_failures < policy.health_threshold_unhealthy) return;
            endpoint.healthy = false;
            endpoint.probe_failures = 0;
        }
    }
};

// ---- tests ----------------------------------------------------------------

const testing = std.testing;
const Listener = @import("../net/listener.zig").Listener;
const Ip4Address = std.Io.net.Ip4Address;

fn health_config(gpa: std.mem.Allocator, live_port: u16, dead_port: u16) !config.Config {
    var buf: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf,
        \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "c" }}],
        \\   "clusters": [{{ "name": "c",
        \\     "endpoints": ["127.0.0.1:{d}", "127.0.0.1:{d}"],
        \\     "health_check": {{ "interval_ms": 50, "timeout_ms": 40,
        \\       "healthy_threshold": 2, "unhealthy_threshold": 2 }} }}] }}
    , .{ live_port, dead_port });
    return config.parse(gpa, text);
}

test "health_check: a dead endpoint flips unhealthy, a live one stays healthy" {
    const gpa = testing.allocator;
    var io = try IO.init(64, 0);
    defer io.deinit();

    // A live listener (accepts probes) and a dead port (refuses instantly).
    var live = try Listener.open(Ip4Address.loopback(0), 8);
    defer live.close();
    var dead = try Listener.open(Ip4Address.loopback(0), 8);
    const dead_port = dead.bound_address().port;
    dead.close();

    var cfg = try health_config(gpa, live.bound_address().port, dead_port);
    defer cfg.deinit();

    var resilience = Resilience{};
    var metrics = Counters{};
    var checker = HealthChecker.init(&io, cfg.clusters, &resilience, &metrics);
    checker.start();
    try testing.expect(checker.running);

    // Both endpoints start healthy; two failed probes flip the dead one.
    try testing.expect(resilience.endpoint_state(0, 1).healthy);
    while (resilience.endpoint_state(0, 1).healthy) try io.run_once();
    try testing.expect(!resilience.endpoint_state(0, 1).healthy);
    try testing.expect(resilience.endpoint_state(0, 0).healthy); // live endpoint untouched
    try testing.expect(metrics.health_probe_failures.load() >= 2);
    try testing.expect(metrics.health_probes.load() > metrics.health_probe_failures.load());

    checker.stop();
    while (!checker.quiesced()) try io.run_once();
}

test "health_check: a recovered endpoint flips healthy after the threshold streak" {
    const gpa = testing.allocator;
    var io = try IO.init(64, 0);
    defer io.deinit();

    var live = try Listener.open(Ip4Address.loopback(0), 8);
    defer live.close();

    var cfg = try health_config(gpa, live.bound_address().port, live.bound_address().port);
    defer cfg.deinit();

    var resilience = Resilience{};
    var metrics = Counters{};
    var checker = HealthChecker.init(&io, cfg.clusters, &resilience, &metrics);
    // Simulate a previously-failed endpoint: unhealthy, mid-streak.
    resilience.endpoint_state(0, 0).healthy = false;
    checker.start();

    // Two successful probes (healthy_threshold) bring it back.
    while (!resilience.endpoint_state(0, 0).healthy) try io.run_once();
    try testing.expectEqual(@as(u16, 0), resilience.endpoint_state(0, 0).probe_successes);

    checker.stop();
    while (!checker.quiesced()) try io.run_once();
}

test "health_check: no configured cluster means the checker never arms" {
    const gpa = testing.allocator;
    var io = try IO.init(16, 0);
    defer io.deinit();

    var cfg = try config.parse(gpa,
        \\{ "listen": "0.0.0.0:0", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9"] }] }
    );
    defer cfg.deinit();

    var resilience = Resilience{};
    var metrics = Counters{};
    var checker = HealthChecker.init(&io, cfg.clusters, &resilience, &metrics);
    checker.start();
    try testing.expect(!checker.running);
    try testing.expect(checker.quiesced());
}
