//! Active health checks (DESIGN.md §7, HAProxy's `check` model): one
//! prober per server sweeps every endpoint of every checked cluster,
//! probing each in turn under the check's own `timeout_ms`. What a probe
//! proves is the cluster's choice: a `tcp` check dials and takes the
//! SYN/ACK as its answer, while an `http` check goes on to send a
//! request and require the configured status — the difference between
//! knowing the port accepts and knowing the application answered.
//! Anything else (refused, unreachable, timed out, a wrong status, a
//! head that will not parse, kernel pressure) is a fail. `fall`
//! consecutive fails eject an endpoint from balancing and close its
//! parked pooled connections (the §5 obligation: a parked socket to a
//! dead origin is a stale replay waiting to be spent); `rise`
//! consecutive passes restore it. Endpoints start healthy — probing
//! demotes, never gates startup — and an unchecked endpoint is
//! permanently healthy, so the balancer applies the mask unconditionally
//! (§7 fail-open lives there, not here).
//!
//! One probe is in flight at a time, and its legs run in sequence — dial,
//! then send, then recv — which is what keeps the prober's reservation
//! closed-form whichever kind is configured (`health_probe_ops_max` ring
//! ops, one fd, §8): the peak is one leg, the deadline, and at most one
//! cancel. Sweeps serialize endpoint-by-endpoint and the interval paces
//! sweep-end to sweep-start.
//!
//! Ending a probe early depends on which leg is armed, because data ops
//! are never canceled (§4, §5). A dial takes the one legal cancel; a
//! send or recv is ended by shutting the socket down, which makes it
//! complete. So a `tcp` probe's socket is closed inside the dial's own
//! delivery and never stored — it wanted the verdict, not a connection —
//! while an `http` probe holds its socket across the data legs and
//! closes it once every armed op has drained, the same
//! release-when-quiescent rule `continueTeardown` follows.

const std = @import("std");

const config_module = @import("../config.zig");
const constants = @import("../constants.zig");
const Io = @import("../io/io.zig");
const parser = @import("../http/parser.zig");
const upstream = @import("upstream.zig");

const assert = std.debug.assert;

pub fn Checker(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);

    return struct {
        server: *ServerType,
        /// The §7 balancing mask, indexed by `upstream.EndpointKeys`. All
        /// true at start; only probed (checked) endpoints ever flip.
        healthy: []bool,
        /// Consecutive failed probes toward `health_probe_fall`; tracked
        /// only while the endpoint is healthy, reset by any pass.
        fail_streaks: []u8,
        /// Consecutive passed probes toward `health_probe_rise`; tracked
        /// only while the endpoint is ejected, reset by any fail.
        ok_streaks: []u8,
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
        /// dial, its data legs, or its deadline lands first; applied only
        /// once every armed op has drained (the §5 release discipline).
        pending_verdict: Verdict,
        /// The http probe's socket, held across its send and recv legs.
        /// Null for a tcp probe, which closes inline in the dial's own
        /// delivery — it wanted the SYN/ACK, not a connection.
        probe_socket: ?IoType.Socket,
        /// Whether this probe's socket has been shut down already. Data
        /// ops are never canceled (§4/§5): a deadline or a drain that
        /// must end an armed send or recv shuts the socket down instead,
        /// which makes the op complete — and must do so exactly once.
        probe_shutdown: bool,
        /// The rendered request, and how much of it has gone out.
        request: [constants.health_check_request_bytes_max]u8,
        request_len: u32,
        request_sent: u32,
        /// The response head as it accumulates. Sized to what the data
        /// path's own parser accepts, so a head this proxy would forward
        /// is never one the probe rejects for being too big.
        response: [constants.head_bytes_max]u8,
        response_len: u32,
        armed: Armed,
        /// Ops a cancel was already spent on (never `.cancel` itself):
        /// what keeps the serialized drain from re-canceling an op whose
        /// terminal delivery is still in flight.
        canceled: Armed,
        op_rest: IoType.Completion,
        op_connect: IoType.Completion,
        /// The http probe's two data legs. They never co-arm — the
        /// request goes out in full before a byte is read — so one
        /// completion each is the whole story.
        op_send: IoType.Completion,
        op_recv: IoType.Completion,
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
        /// rest never co-arms with a probe, the probe's own legs run one
        /// at a time (dial, then send, then recv), and the cancel is
        /// serialized — so the peak is one leg + the deadline + one
        /// cancel however far an http probe gets.
        pub const Armed = packed struct(u8) {
            rest: bool = false,
            connect: bool = false,
            send: bool = false,
            recv: bool = false,
            deadline: bool = false,
            cancel: bool = false,
            _pad: u2 = 0,
        };

        pub fn init(
            checker: *Self,
            arena: std.mem.Allocator,
            server: *ServerType,
            keys: upstream.EndpointKeys,
        ) error{OutOfMemory}!void {
            assert(keys.count >= 1);
            checker.server = server;
            checker.healthy = try arena.alloc(bool, keys.count);
            checker.fail_streaks = try arena.alloc(u8, keys.count);
            checker.ok_streaks = try arena.alloc(u8, keys.count);
            @memset(checker.healthy, true);
            @memset(checker.fail_streaks, 0);
            @memset(checker.ok_streaks, 0);
            checker.checked_count = 0;
            checker.unhealthy_count = 0;
            checker.state = .off;
            checker.cursor_cluster = 0;
            checker.cursor_endpoint = 0;
            checker.pending_verdict = .none;
            checker.probe_socket = null;
            checker.probe_shutdown = false;
            checker.request_len = 0;
            checker.request_sent = 0;
            checker.response_len = 0;
            checker.armed = .{};
            checker.canceled = .{};
            checker.op_rest = .{};
            checker.op_connect = .{};
            checker.op_send = .{};
            checker.op_recv = .{};
            checker.op_deadline = .{};
            checker.op_cancel = .{};
            const clusters = server.config.clusters;
            assert(clusters.len >= 1);
            // Same pairing check the balancer makes: `keys` must describe
            // this config, or the mask is sized for one shape and indexed
            // for another. `clusters.len <= healthy.len` does *not* say
            // that — it holds for any `stride >= 1`.
            assert(keys.count == @as(u32, @intCast(clusters.len)) * keys.stride);
            for (clusters) |cluster| {
                if (cluster.check != null) {
                    checker.checked_count += @intCast(cluster.endpoints.len);
                }
            }
            assert(checker.checked_count <= checker.healthy.len);
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
            return @popCount(@as(u8, @bitCast(checker.armed)));
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
            const http_check = checker.state == .probing and
                checker.pending_verdict == .none and
                checker.checkOf(checker.cursor_cluster).kind == .http;
            if (result) |socket| {
                if (http_check) {
                    // The http probe's dial is the beginning of the
                    // probe, not its verdict: the socket is stored and
                    // carries the request and response legs.
                    checker.probe_socket = socket;
                    checker.beginRequest(socket);
                    checker.settle();
                    return;
                }
                // A tcp probe wanted the SYN/ACK, not a connection — and
                // a socket that was never stored cannot leak (§9). The
                // same holds for a dial that lands after its own verdict
                // or into a drain: there is nothing left to send it.
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
            checker.settle();
        }

        /// Render this probe's request and start writing it. The render
        /// cannot fail: `health_check_request_bytes_max` is derived from
        /// the path and Host bounds the loader already enforced (§5).
        fn beginRequest(checker: *Self, socket: IoType.Socket) void {
            assert(checker.state == .probing);
            assert(!checker.armed.send);
            assert(!checker.armed.recv);
            const check = checker.checkOf(checker.cursor_cluster);
            assert(check.kind == .http);
            const http = check.http.?;
            const cluster = &checker.server.config.clusters[checker.cursor_cluster];
            const endpoint = cluster.endpoints[checker.cursor_endpoint];
            // `Connection: close` because the probe never reuses this
            // socket: it asks one question and hangs up, which also frees
            // the origin from parking a connection nobody will return to.
            const rendered = if (http.host) |host|
                std.fmt.bufPrint(
                    &checker.request,
                    "GET {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n",
                    .{ http.path, host },
                ) catch unreachable
            else
                std.fmt.bufPrint(
                    &checker.request,
                    "GET {s} HTTP/1.1\r\nHost: {f}\r\nConnection: close\r\n\r\n",
                    .{ http.path, endpoint },
                ) catch unreachable;
            checker.request_len = @intCast(rendered.len);
            checker.request_sent = 0;
            checker.response_len = 0;
            assert(checker.request_len >= 1);
            checker.armSend(socket);
        }

        fn armSend(checker: *Self, socket: IoType.Socket) void {
            assert(checker.state == .probing);
            assert(!checker.armed.send);
            assert(checker.request_sent < checker.request_len);
            checker.armed.send = true;
            checker.server.io.send(
                socket,
                checker.request[checker.request_sent..checker.request_len],
                &checker.op_send,
                Self,
                checker,
                onProbeSend,
            );
            assert(checker.armedCount() <= constants.health_probe_ops_max);
        }

        fn onProbeSend(checker: *Self, result: Io.SendError!u32) void {
            assert(checker.armed.send);
            checker.armed.send = false;
            if (checker.state == .stopping) {
                checker.continueStop();
                return;
            }
            assert(checker.state == .probing);
            const sent = result catch |err| {
                // Never a cancel: data ops are ended by the shutdown in
                // `endArmedLeg`, never by one (§4, §5). A Canceled here
                // would mean some path reached for a cancel op that this
                // design says does not exist for a data leg.
                assert(err != error.Canceled);
                // The origin hung up on the request, or the deadline shut
                // this socket down. Either way the probe has its answer.
                if (checker.pending_verdict == .none) {
                    checker.pending_verdict = .fail;
                    checker.server.witnessKernelPressure(.send, err);
                }
                checker.settle();
                return;
            };
            checker.request_sent += sent;
            assert(checker.request_sent <= checker.request_len);
            // A verdict already reached (the deadline fired and shut this
            // socket down) ends the probe here: arming another leg would
            // only spend an op to be told what is already known.
            if (checker.pending_verdict == .none) {
                const socket = checker.probe_socket.?;
                if (checker.request_sent < checker.request_len) {
                    // A short write is ordinary (§6): resume where it left off.
                    checker.armSend(socket);
                } else {
                    checker.armRecv(socket);
                }
            }
            checker.settle();
        }

        fn armRecv(checker: *Self, socket: IoType.Socket) void {
            assert(checker.state == .probing);
            assert(!checker.armed.recv);
            assert(checker.response_len < checker.response.len);
            checker.armed.recv = true;
            checker.server.io.recv(
                socket,
                checker.response[checker.response_len..],
                &checker.op_recv,
                Self,
                checker,
                onProbeRecv,
            );
            assert(checker.armedCount() <= constants.health_probe_ops_max);
        }

        fn onProbeRecv(checker: *Self, result: Io.RecvError!u32) void {
            assert(checker.armed.recv);
            checker.armed.recv = false;
            if (checker.state == .stopping) {
                checker.continueStop();
                return;
            }
            assert(checker.state == .probing);
            const received = result catch |err| {
                assert(err != error.Canceled); // Same rule as the send leg.
                // EOF or reset before a whole head arrived: an origin
                // that hangs up mid-status has not answered the check.
                if (checker.pending_verdict == .none) {
                    checker.pending_verdict = .fail;
                    checker.server.witnessKernelPressure(.recv, err);
                }
                checker.settle();
                return;
            };
            checker.response_len += received;
            assert(checker.response_len <= checker.response.len);
            if (checker.pending_verdict == .none) {
                checker.judgeResponse();
            }
            if (checker.pending_verdict == .none) {
                // The head is still arriving. A full buffer with no head
                // in it is the §7 oversize-head verdict, not a shortfall.
                if (checker.response_len == checker.response.len) {
                    checker.pending_verdict = .fail;
                } else {
                    checker.armRecv(checker.probe_socket.?);
                }
            }
            checker.settle();
        }

        /// Judge what has arrived so far, leaving the verdict `.none`
        /// while the head is merely incomplete. The head parser is the
        /// data path's own (§7), so a probe accepts exactly the responses
        /// this proxy would forward — and nothing it would reject.
        fn judgeResponse(checker: *Self) void {
            assert(checker.state == .probing);
            assert(checker.pending_verdict == .none);
            const expect_status = checker.checkOf(checker.cursor_cluster).http.?.expect_status;
            var storage: parser.HeaderStorage = undefined;
            const head = parser.parseResponseHead(
                checker.response[0..checker.response_len],
                false,
                &storage,
                .get,
            ) catch |err| {
                if (err == error.Incomplete) return;
                checker.pending_verdict = .fail;
                return;
            };
            checker.pending_verdict = if (head.status == expect_status) .pass else .fail;
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
                    // Fired first: the probe outlived its budget. It
                    // fails, and whatever leg is armed is forced to a
                    // terminal completion so even a black-holed endpoint
                    // or a mute origin releases the prober (§5).
                    checker.pending_verdict = .fail;
                    checker.endArmedLeg();
                } else {
                    // The fire raced its own cancel (a legal §4 race): the
                    // outcome is decided, this delivery is op accounting
                    // only. Counted because "rare race" and "the cancel is
                    // never issued" produce the same *outcomes* and differ
                    // only in how much budget each probe burns — which is
                    // exactly the shape of #130, where every probe idled
                    // out its whole `timeout_ms` and every check still
                    // reported the right verdict.
                    checker.server.counters.increment("health_probe_deadline_raced");
                }
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

        /// End whichever leg is armed, by the only means each allows: a
        /// dial takes the one legal cancel (§4), while a send or recv is
        /// never canceled (§5) — shutting the socket down is what makes
        /// it complete. Both are idempotent here, because a deadline and
        /// a drain can each reach this for the same probe.
        fn endArmedLeg(checker: *Self) void {
            // Only ever called with a leg outstanding: a deadline fires
            // against the leg it was armed beside, and the drain ladder
            // reaches here only under its own armed guard.
            assert(checker.armed.connect or checker.armed.send or checker.armed.recv);
            assert(checker.state == .probing or checker.state == .stopping);
            if (checker.armed.connect and !checker.armed.cancel and !checker.canceled.connect) {
                checker.armCancelConnect();
                return;
            }
            if ((checker.armed.send or checker.armed.recv) and !checker.probe_shutdown) {
                // A data leg exists only for an http probe, which is the
                // only kind that holds a socket to shut down.
                assert(checker.probe_socket != null);
                checker.probe_shutdown = true;
                checker.server.io.shutdown(checker.probe_socket.?, .both);
            }
        }

        /// The probe's socket, once no op can reference it. Closing is
        /// synchronous for the same reason `continueTeardown`'s is: by
        /// here the armed set is empty, so nothing is left to deliver
        /// against this fd (§5).
        fn closeProbeSocket(checker: *Self) void {
            assert(checker.armedCount() == 0);
            assert(checker.state == .probing or checker.state == .stopping);
            if (checker.probe_socket) |socket| {
                checker.server.io.closeNow(socket);
                checker.probe_socket = null;
            }
            checker.probe_shutdown = false;
        }

        /// The delivery that empties the armed set applies the verdict
        /// and moves the sweep along — never earlier, so no completion
        /// can land on a probe that already advanced (§5).
        fn settle(checker: *Self) void {
            assert(checker.state == .probing);
            // A decided probe has no use for its budget. Cancelling here
            // rather than at each verdict site is what makes every leg —
            // dial, send, recv — advance the sweep the moment it knows,
            // instead of idling until the deadline fires: an http probe
            // that answered in a microsecond must not hold the prober
            // for the whole `timeout_ms`.
            if (checker.pending_verdict != .none and
                checker.armed.deadline and !checker.armed.cancel)
            {
                checker.armCancelDeadline();
            }
            if (checker.armedCount() != 0) return;
            assert(checker.pending_verdict != .none);
            checker.closeProbeSocket();
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
            const key = checker.server.upstreams.keys.key(cluster_index, endpoint_index);
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
            const key = checker.server.upstreams.keys.key(cluster_index, endpoint_index);
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
            assert(!checker.healthy[checker.server.upstreams.keys.key(cluster_index, endpoint_index)]);
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
            // A data leg takes no cancel op at all (§5): the shutdown
            // makes it complete, and its delivery re-enters here. It
            // therefore does not `return` — the shutdown consumes no
            // completion to wait on, so the armed check below is what
            // decides whether anything is still outstanding. The guard
            // lives inside `endArmedLeg`, which is idempotent, so this
            // states only that a leg is what it is being called for.
            if (checker.armed.send or checker.armed.recv) {
                checker.endArmedLeg();
            }
            if (checker.armedCount() != 0) return;
            assert(checker.isQuiescent());
            // Nothing can reference the probe's fd once every op has
            // drained, which is what makes closing it here safe (§5).
            checker.closeProbeSocket();
            checker.state = .stopped;
            checker.server.maybeStopAfterDrain();
        }
    };
}
