//! Active TCP health checks (DESIGN.md §7, HAProxy's `check` model): one
//! prober per server sweeps every endpoint of every `check` cluster,
//! dialing each in turn under the `connect_ms` budget — a SYN/ACK is a
//! pass, anything else (refused, unreachable, timed out, kernel
//! pressure) is a fail. `health_probe_fall` consecutive fails eject an
//! endpoint from balancing and close its parked pooled connections (the
//! §5 obligation: a parked socket to a dead origin is a stale replay
//! waiting to be spent); `health_probe_rise` consecutive passes restore
//! it. Endpoints start healthy — probing demotes, never gates startup —
//! and an unchecked endpoint is permanently healthy, so the balancer
//! applies the mask unconditionally (§7 fail-open lives there, not
//! here).
//!
//! One probe is in flight at a time, which is what keeps the prober's
//! reservation closed-form (`health_probe_ops_max` ring ops, one fd,
//! §8): sweeps serialize endpoint-by-endpoint, and the interval paces
//! sweep-end to sweep-start. Cancels are serialized too — one cancel op,
//! spent on whichever armed op must die next — so the armed set never
//! exceeds the budget. The probe socket is closed synchronously in the
//! connect delivery itself and never stored: the probe wanted the
//! verdict, not a connection.

const std = @import("std");

const config_module = @import("../config.zig");
const constants = @import("../constants.zig");
const Io = @import("../io/io.zig");
const upstream = @import("upstream.zig");

const assert = std.debug.assert;

pub fn Checker(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);

    return struct {
        server: *ServerType,
        /// The §7 balancing mask, indexed by `upstream.endpointKey`. All
        /// true at start; only probed (checked) endpoints ever flip.
        healthy: [upstream.endpoint_keys_max]bool,
        /// Consecutive failed probes toward `health_probe_fall`; tracked
        /// only while the endpoint is healthy, reset by any pass.
        fail_streaks: [upstream.endpoint_keys_max]u8,
        /// Consecutive passed probes toward `health_probe_rise`; tracked
        /// only while the endpoint is ejected, reset by any fail.
        ok_streaks: [upstream.endpoint_keys_max]u8,
        /// Endpoints under checks — static after `init` (the sum of
        /// `endpoints.len` over every `check` cluster); zero leaves the
        /// prober `.off` forever.
        checked_count: u32,
        /// Checked endpoints currently ejected; the gauge level (§8).
        unhealthy_count: u32,
        state: State,
        /// The sweep cursor: the cluster and endpoint the in-flight (or
        /// next) probe targets. Valid while `.probing`.
        cursor_cluster: u16,
        cursor_endpoint: u16,
        /// The in-flight probe's outcome, decided by whichever of the
        /// dial or its deadline lands first; applied only once every
        /// armed op has drained (the §5 release discipline).
        pending_verdict: Verdict,
        armed: Armed,
        /// Ops a cancel was already spent on (never `.cancel` itself):
        /// what keeps the serialized drain from re-canceling an op whose
        /// terminal delivery is still in flight.
        canceled: Armed,
        op_rest: IoType.Completion,
        op_connect: IoType.Completion,
        op_deadline: IoType.Completion,
        /// The one cancel completion, reused across targets — legal
        /// because cancels are serialized (`armed.cancel` gates every
        /// submission).
        op_cancel: IoType.Completion,

        const Self = @This();

        pub const State = enum(u8) {
            /// Not started, or no cluster sets `check`: nothing ever arms.
            off,
            /// A sweep is running: one probe in flight at the cursor.
            probing,
            /// Between sweeps: the rest timer is armed for the interval.
            resting,
            /// Drain (§8): canceling whatever is armed, serially.
            stopping,
            /// Quiescent; never re-arms.
            stopped,
        };

        pub const Verdict = enum(u8) {
            none,
            pass,
            fail,
        };

        /// One bit per embedded op; the prober is quiescent only when
        /// clear. At most three are ever set (`health_probe_ops_max`):
        /// rest never co-arms with the probe ops, and the cancel is
        /// serialized.
        pub const Armed = packed struct(u4) {
            rest: bool = false,
            connect: bool = false,
            deadline: bool = false,
            cancel: bool = false,
        };

        pub fn init(checker: *Self, server: *ServerType) void {
            checker.server = server;
            @memset(&checker.healthy, true);
            @memset(&checker.fail_streaks, 0);
            @memset(&checker.ok_streaks, 0);
            checker.checked_count = 0;
            checker.unhealthy_count = 0;
            checker.state = .off;
            checker.cursor_cluster = 0;
            checker.cursor_endpoint = 0;
            checker.pending_verdict = .none;
            checker.armed = .{};
            checker.canceled = .{};
            checker.op_rest = .{};
            checker.op_connect = .{};
            checker.op_deadline = .{};
            checker.op_cancel = .{};
            const clusters = server.config.clusters;
            assert(clusters.len >= 1);
            assert(clusters.len <= constants.clusters_max);
            for (clusters) |cluster| {
                if (cluster.check != null) {
                    checker.checked_count += @intCast(cluster.endpoints.len);
                }
            }
            assert(checker.checked_count <= upstream.endpoint_keys_max);
            assert(checker.armedCount() == 0);
        }

        /// Begin probing, or stay `.off` when no cluster opted in. The
        /// first sweep runs now rather than an interval from now: a
        /// fresh process should learn its endpoints' state before the
        /// first interval elapses.
        pub fn start(checker: *Self) void {
            assert(checker.state == .off);
            assert(checker.armedCount() == 0);
            if (checker.checked_count == 0) return;
            checker.startSweep();
        }

        /// Drain (§8): discard any in-flight probe's verdict and cancel
        /// the armed ops, serially. `maybeStopAfterDrain` fires once the
        /// armed set empties.
        pub fn beginStop(checker: *Self) void {
            if (checker.state == .stopping or checker.state == .stopped) return;
            if (checker.state == .off) {
                assert(checker.armedCount() == 0);
                checker.state = .stopped;
                return;
            }
            // Live states always hold work: probing keeps probe ops armed,
            // resting keeps the rest timer armed.
            assert(checker.armedCount() >= 1);
            assert(checker.checked_count >= 1);
            checker.state = .stopping;
            checker.pending_verdict = .none;
            checker.continueStop();
        }

        /// The simulator's leak invariant (§9): a leaked armed op is a
        /// leak like any other. The probe socket needs no term — it is
        /// closed inside the connect delivery and never held across
        /// callbacks.
        pub fn isQuiescent(checker: *const Self) bool {
            return checker.armedCount() == 0;
        }

        pub fn armedCount(checker: *const Self) u32 {
            return @popCount(@as(u4, @bitCast(checker.armed)));
        }

        fn startSweep(checker: *Self) void {
            assert(checker.armedCount() == 0);
            assert(checker.checked_count >= 1);
            checker.state = .probing;
            checker.cursor_cluster = 0;
            checker.cursor_endpoint = 0;
            checker.probeNext();
        }

        /// Advance the cursor to the next checked endpoint and dial it,
        /// or end the sweep and rest for the interval. Bounded: the walk
        /// visits each cluster at most once past the cursor.
        fn probeNext(checker: *Self) void {
            assert(checker.state == .probing);
            assert(checker.armedCount() == 0);
            assert(checker.pending_verdict == .none);
            const clusters = checker.server.config.clusters;
            while (checker.cursor_cluster < clusters.len) {
                const cluster = &clusters[checker.cursor_cluster];
                if (cluster.check == null or checker.cursor_endpoint >= cluster.endpoints.len) {
                    checker.cursor_cluster += 1;
                    checker.cursor_endpoint = 0;
                    continue;
                }
                checker.beginProbe(cluster);
                return;
            }
            checker.rest();
        }

        /// The cluster's resolved check policy. Only a checked cluster is
        /// ever probed, so the option is settled by the walk in
        /// `probeNext` before anything here reads it.
        fn checkOf(checker: *const Self, cluster_index: u16) *const config_module.Config.Cluster.Check {
            assert(cluster_index < checker.server.config.clusters.len);
            const check = &checker.server.config.clusters[cluster_index].check;
            assert(check.* != null);
            return &check.*.?;
        }

        fn beginProbe(checker: *Self, cluster: *const config_module.Config.Cluster) void {
            assert(checker.state == .probing);
            assert(checker.armedCount() == 0);
            assert(cluster.check != null);
            assert(checker.cursor_endpoint < cluster.endpoints.len);
            assert(checker.pending_verdict == .none);
            const server = checker.server;
            const check = &cluster.check.?;
            server.counters.increment("health_probes_sent");
            checker.canceled = .{};
            // One budget covers the whole probe (§7) — the dial alone for
            // a tcp check, dial + request + response for an http one —
            // because what an operator cares about is how long an
            // endpoint may take to prove itself, not which leg was slow.
            checker.armed.deadline = true;
            server.io.timerStart(
                &checker.op_deadline,
                @as(u64, check.timeout_ms) * std.time.ns_per_ms,
                Self,
                checker,
                onProbeDeadline,
            );
            checker.armed.connect = true;
            server.io.connect(
                cluster.endpoints[checker.cursor_endpoint],
                &checker.op_connect,
                Self,
                checker,
                onProbeConnect,
            );
            assert(checker.armedCount() <= constants.health_probe_ops_max);
        }

        fn onProbeConnect(checker: *Self, result: Io.ConnectError!IoType.Socket) void {
            assert(checker.armed.connect);
            checker.armed.connect = false;
            // A socket that arrived is closed on the spot whatever the
            // state: the probe wanted the SYN/ACK verdict, not a
            // connection, and an unstored socket cannot leak (§9).
            if (result) |socket| {
                checker.server.io.closeNow(socket);
            } else |_| {}
            if (checker.state == .stopping) {
                checker.continueStop();
                return;
            }
            assert(checker.state == .probing);
            if (result) |_| {
                // First outcome wins: a dial landing after its deadline
                // already failed the probe keeps the fail — a late
                // answer is no answer (§7).
                if (checker.pending_verdict == .none) {
                    checker.pending_verdict = .pass;
                }
            } else |err| switch (err) {
                // The deadline fired first and canceled the dial; the
                // fail verdict is already pending.
                error.Canceled => assert(checker.pending_verdict == .fail),
                else => {
                    if (checker.pending_verdict == .none) {
                        checker.pending_verdict = .fail;
                    }
                    // Typed refusals are the origin's verdict; only
                    // kernel pressure on our side is witnessed (§8) —
                    // the same split the data-path dial makes.
                    checker.server.witnessKernelPressure(.connect, err);
                },
            }
            if (checker.armed.deadline and !checker.armed.cancel) {
                checker.armCancelDeadline();
            }
            checker.settle();
        }

        fn onProbeDeadline(checker: *Self, result: Io.TimerError!void) void {
            assert(checker.armed.deadline);
            checker.armed.deadline = false;
            if (checker.state == .stopping) {
                result catch {};
                checker.continueStop();
                return;
            }
            assert(checker.state == .probing);
            if (result) |_| {
                if (checker.pending_verdict == .none) {
                    // Fired first: the dial outlived its budget — the
                    // probe fails and the dial is torn down so even a
                    // black-holed endpoint reaches a terminal
                    // completion (§5).
                    checker.pending_verdict = .fail;
                    assert(checker.armed.connect);
                    if (!checker.armed.cancel) {
                        checker.armCancelConnect();
                    }
                }
                // Otherwise the fire raced its own cancel (a legal §4
                // race): the outcome is decided, this delivery is op
                // accounting only.
            } else |err| {
                assert(err == error.Canceled);
                assert(checker.pending_verdict != .none);
            }
            checker.settle();
        }

        fn onCancel(checker: *Self) void {
            assert(checker.armed.cancel);
            checker.armed.cancel = false;
            if (checker.state == .stopping) {
                checker.continueStop();
                return;
            }
            assert(checker.state == .probing);
            checker.settle();
        }

        /// The delivery that empties the armed set applies the verdict
        /// and moves the sweep along — never earlier, so no completion
        /// can land on a probe that already advanced (§5).
        fn settle(checker: *Self) void {
            assert(checker.state == .probing);
            if (checker.armedCount() != 0) return;
            assert(checker.pending_verdict != .none);
            const verdict = checker.pending_verdict;
            checker.pending_verdict = .none;
            if (verdict == .pass) {
                checker.witnessPass(checker.cursor_cluster, checker.cursor_endpoint);
            } else {
                checker.witnessFail(checker.cursor_cluster, checker.cursor_endpoint);
            }
            checker.cursor_endpoint += 1;
            checker.probeNext();
        }

        fn witnessPass(checker: *Self, cluster_index: u16, endpoint_index: u16) void {
            const rise = checker.checkOf(cluster_index).rise;
            assert(rise >= 1);
            const key = upstream.endpointKey(cluster_index, endpoint_index);
            checker.fail_streaks[key] = 0;
            if (checker.healthy[key]) {
                assert(checker.ok_streaks[key] == 0);
                return;
            }
            checker.ok_streaks[key] += 1;
            assert(checker.ok_streaks[key] <= rise);
            if (checker.ok_streaks[key] < rise) return;
            checker.ok_streaks[key] = 0;
            checker.healthy[key] = true;
            assert(checker.unhealthy_count >= 1);
            checker.unhealthy_count -= 1;
            checker.server.counters.increment("health_endpoint_up");
        }

        fn witnessFail(checker: *Self, cluster_index: u16, endpoint_index: u16) void {
            const fall = checker.checkOf(cluster_index).fall;
            assert(fall >= 1);
            checker.server.counters.increment("health_probes_failed");
            const key = upstream.endpointKey(cluster_index, endpoint_index);
            checker.ok_streaks[key] = 0;
            // Already ejected: nothing further to count — streaks resume
            // meaning only once a pass starts a recovery.
            if (!checker.healthy[key]) return;
            assert(checker.fail_streaks[key] < fall);
            checker.fail_streaks[key] += 1;
            if (checker.fail_streaks[key] < fall) return;
            checker.fail_streaks[key] = 0;
            checker.healthy[key] = false;
            checker.unhealthy_count += 1;
            assert(checker.unhealthy_count <= checker.checked_count);
            checker.server.counters.increment("health_endpoint_down");
            checker.closeParked(cluster_index, endpoint_index);
        }

        /// The §5 obligation: ejection closes the endpoint's parked
        /// pooled connections. Synchronous closes — a parked slot holds
        /// no armed op (§5), so checkout + close + release is one step,
        /// the reap discipline `Server.reapParked` set.
        fn closeParked(checker: *Self, cluster_index: u16, endpoint_index: u16) void {
            // Only an ejection reaches here: the endpoint was just marked
            // unhealthy by the caller.
            assert(!checker.healthy[upstream.endpointKey(cluster_index, endpoint_index)]);
            const server = checker.server;
            const capacity = server.upstreams.capacity();
            var reaped: u32 = 0;
            while (server.upstreams.checkout(cluster_index, endpoint_index)) |parked| {
                server.io.closeNow(parked.socket);
                server.releaseUpstream(parked);
                server.counters.increment("health_parked_closed");
                reaped += 1;
                assert(reaped <= capacity);
            }
        }

        fn rest(checker: *Self) void {
            assert(checker.state == .probing);
            assert(checker.armedCount() == 0);
            checker.state = .resting;
            checker.armed.rest = true;
            checker.server.io.timerStart(
                &checker.op_rest,
                @as(u64, checker.server.config.health_interval_ms) * std.time.ns_per_ms,
                Self,
                checker,
                onRest,
            );
        }

        fn onRest(checker: *Self, result: Io.TimerError!void) void {
            assert(checker.armed.rest);
            checker.armed.rest = false;
            if (checker.state == .stopping) {
                result catch {};
                checker.continueStop();
                return;
            }
            // The rest timer is canceled only by the drain (§4), which
            // flips `.stopping` first — a live delivery is always a fire.
            result catch unreachable;
            assert(checker.state == .resting);
            checker.startSweep();
        }

        fn armCancelDeadline(checker: *Self) void {
            assert(checker.armed.deadline);
            assert(!checker.armed.cancel);
            checker.armed.cancel = true;
            checker.canceled.deadline = true;
            checker.server.io.timerCancel(
                &checker.op_deadline,
                &checker.op_cancel,
                Self,
                checker,
                onCancel,
            );
            assert(checker.armedCount() <= constants.health_probe_ops_max);
        }

        fn armCancelConnect(checker: *Self) void {
            assert(checker.armed.connect);
            assert(!checker.armed.cancel);
            checker.armed.cancel = true;
            checker.canceled.connect = true;
            checker.server.io.connectCancel(
                &checker.op_connect,
                &checker.op_cancel,
                Self,
                checker,
                onCancel,
            );
            assert(checker.armedCount() <= constants.health_probe_ops_max);
        }

        /// One cancel at a time toward quiescence: cancel the next armed
        /// op that has not had a cancel spent on it yet, or — once every
        /// delivery has drained — stop. An op whose cancel already ran
        /// but whose own terminal delivery is still in flight is waited
        /// on, never re-canceled.
        fn continueStop(checker: *Self) void {
            assert(checker.state == .stopping);
            if (checker.armed.cancel) return;
            if (checker.armed.rest and !checker.canceled.rest) {
                checker.armed.cancel = true;
                checker.canceled.rest = true;
                checker.server.io.timerCancel(
                    &checker.op_rest,
                    &checker.op_cancel,
                    Self,
                    checker,
                    onCancel,
                );
                assert(checker.armedCount() <= constants.health_probe_ops_max);
                return;
            }
            if (checker.armed.deadline and !checker.canceled.deadline) {
                checker.armCancelDeadline();
                return;
            }
            if (checker.armed.connect and !checker.canceled.connect) {
                checker.armCancelConnect();
                return;
            }
            if (checker.armedCount() != 0) return;
            assert(checker.isQuiescent());
            checker.state = .stopped;
            checker.server.maybeStopAfterDrain();
        }
    };
}
