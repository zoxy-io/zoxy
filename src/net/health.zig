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
//! What is per-probe and what is per-prober is drawn as a type boundary:
//! `Probe` owns a target, a verdict, a socket, the two buffers and every
//! op it may arm, while the checker owns what a sweep shares — the mask,
//! the streaks, the cursor and the rest timer. The checker holds exactly
//! one probe today, and that count is the only thing that stands between
//! this shape and a concurrent sweep (#132).
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
        /// The sweep cursor: the *next* endpoint to hand out, not the one
        /// being probed. It advances at the hand-off (`dispatchNext`) and
        /// never when a verdict lands, so an endpoint is handed out once
        /// per sweep no matter how many probes are drawing from it. Which
        /// endpoint a verdict belongs to is therefore the probe's own
        /// question, answered by `Probe.target_cluster`/`target_endpoint`
        /// rather than by reading a cursor that has already moved on.
        cursor_cluster: u16,
        cursor_endpoint: u16,
        /// The probes drawing from the cursor (§7, #132):
        /// `constants.healthProbeConcurrency` of them, so a config with
        /// two checked endpoints allocates two and only a large one pays
        /// for the ceiling. Never empty — the floor of one is what keeps
        /// the prober's reservation unconditional (§8).
        probes: []Probe,
        /// The between-sweeps timer, and the cancel the drain spends on
        /// it. Neither ever co-arms with any probe — `.resting` and
        /// `.probing` are disjoint — so these two never add to the
        /// per-probe `health_probe_ops_max` the budget reserves.
        armed_rest: bool,
        armed_rest_cancel: bool,
        /// Whether the drain has already spent its cancel on the rest
        /// timer; the same "never re-cancel an op whose delivery is still
        /// in flight" rule `Probe.canceled` keeps for the probe's ops.
        canceled_rest: bool,
        op_rest: IoType.Completion,
        op_rest_cancel: IoType.Completion,

        const Self = @This();

        pub const State = enum(u8) {
            /// Not started, or no cluster sets `check`: nothing ever arms.
            off,
            /// A sweep is running: up to `probes.len` of them in flight,
            /// each against an endpoint the cursor has already handed out.
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

        /// One probe: the endpoint it was handed, the verdict it has
        /// reached, and every op it may arm. It is the callback context
        /// for all of them, so a delivery knows which probe it belongs to
        /// without consulting the checker's cursor — which is exactly
        /// what lets the cursor run ahead of the verdicts.
        pub const Probe = struct {
            checker: *Self,
            /// The endpoint `dispatchNext` handed this probe. Valid while
            /// the probe is busy, and the key a settled verdict is
            /// applied against.
            target_cluster: u16,
            target_endpoint: u16,
            /// This probe's outcome, decided by whichever of the dial,
            /// its data legs, or its deadline lands first; applied only
            /// once every armed op has drained (the §5 release
            /// discipline).
            pending_verdict: Verdict,
            /// The http probe's socket, held across its send and recv legs.
            /// Null for a tcp probe, which closes inline in the dial's own
            /// delivery — it wanted the SYN/ACK, not a connection.
            socket: ?IoType.Socket,
            /// Whether this probe's socket has been shut down already. Data
            /// ops are never canceled (§4/§5): a deadline or a drain that
            /// must end an armed send or recv shuts the socket down instead,
            /// which makes the op complete — and must do so exactly once.
            shutdown_done: bool,
            /// The rendered request, and how much of it has gone out.
            request: [constants.health_check_request_bytes_max]u8,
            request_len: u32,
            request_sent: u32,
            /// The response head as it accumulates. Sized at init to what the
            /// data path's own parser accepts (`limits.head_buffer_bytes`),
            /// so a head this proxy would forward is never one the probe
            /// rejects for being too big — a relation that followed the size
            /// into the config.
            response: []u8,
            response_len: u32,
            armed: Armed,
            /// Ops a cancel was already spent on (never `.cancel` itself):
            /// what keeps the serialized drain from re-canceling an op whose
            /// terminal delivery is still in flight.
            canceled: Armed,
            op_connect: IoType.Completion,
            /// The http probe's two data legs. They never co-arm — the
            /// request goes out in full before a byte is read — so one
            /// completion each is the whole story.
            op_send: IoType.Completion,
            op_recv: IoType.Completion,
            op_deadline: IoType.Completion,
            /// The one cancel completion, reused across this probe's
            /// targets — legal because a probe's cancels are serialized
            /// (`armed.cancel` gates every submission).
            op_cancel: IoType.Completion,

            /// One bit per op this probe may arm; the probe is quiescent
            /// only when clear. At most three are ever set
            /// (`health_probe_ops_max`): the legs run one at a time
            /// (dial, then send, then recv), and the cancel is serialized
            /// — so the peak is one leg + the deadline + one cancel
            /// however far an http probe gets.
            pub const Armed = packed struct(u8) {
                connect: bool = false,
                send: bool = false,
                recv: bool = false,
                deadline: bool = false,
                cancel: bool = false,
                _pad: u3 = 0,
            };

            fn init(
                probe: *Probe,
                arena: std.mem.Allocator,
                checker: *Self,
                /// The probe's response buffer size — `limits.head_buffer_bytes`,
                /// so the probe accepts exactly the heads the data path does.
                response_bytes: u32,
            ) error{OutOfMemory}!void {
                assert(response_bytes >= constants.head_buffer_bytes_min);
                probe.checker = checker;
                probe.response = try arena.alloc(u8, response_bytes);
                probe.target_cluster = 0;
                probe.target_endpoint = 0;
                probe.pending_verdict = .none;
                probe.socket = null;
                probe.shutdown_done = false;
                probe.request_len = 0;
                probe.request_sent = 0;
                probe.response_len = 0;
                probe.armed = .{};
                probe.canceled = .{};
                probe.op_connect = .{};
                probe.op_send = .{};
                probe.op_recv = .{};
                probe.op_deadline = .{};
                probe.op_cancel = .{};
                assert(probe.armedCount() == 0);
            }

            fn armedCount(probe: *const Probe) u32 {
                return @popCount(@as(u8, @bitCast(probe.armed)));
            }

            /// Take the endpoint the sweep just handed out and dial it.
            fn begin(
                probe: *Probe,
                cluster: *const config_module.Config.Cluster,
                cluster_index: u16,
                endpoint_index: u16,
            ) void {
                const checker = probe.checker;
                assert(checker.state == .probing);
                assert(probe.armedCount() == 0);
                // The disjointness the op budget rests on, asserted where
                // it could break rather than argued in the field comment:
                // a probe never starts beside a live rest timer, which is
                // what keeps the peak at `health_probe_ops_max` (§8). It
                // is stated on the probe's own bits rather than on
                // `checker.armedCount() == 0`, which a concurrent sweep
                // would make false for a reason that is not a defect.
                assert(!checker.armed_rest and !checker.armed_rest_cancel);
                assert(cluster.check != null);
                assert(endpoint_index < cluster.endpoints.len);
                assert(probe.pending_verdict == .none);
                const server = checker.server;
                const check = &cluster.check.?;
                probe.target_cluster = cluster_index;
                probe.target_endpoint = endpoint_index;
                server.counters.increment("health_probes_sent");
                // The concurrency witness (#132): this probe is starting
                // beside a sibling that has not settled. Counted at the
                // hand-off, where the overlap is a fact rather than an
                // inference from timings nothing records.
                if (checker.busyProbes() >= 1) {
                    server.counters.increment("health_probes_concurrent");
                }
                probe.canceled = .{};
                // One budget covers the whole probe (§7) — the dial alone for
                // a tcp check, dial + request + response for an http one —
                // because what an operator cares about is how long an
                // endpoint may take to prove itself, not which leg was slow.
                probe.armed.deadline = true;
                server.io.timerStart(
                    &probe.op_deadline,
                    @as(u64, check.timeout_ms) * std.time.ns_per_ms,
                    Probe,
                    probe,
                    onProbeDeadline,
                );
                probe.armed.connect = true;
                server.io.connect(
                    cluster.endpoints[endpoint_index],
                    &probe.op_connect,
                    Probe,
                    probe,
                    onProbeConnect,
                );
                assert(probe.armedCount() <= constants.health_probe_ops_max);
            }

            fn onProbeConnect(probe: *Probe, result: Io.ConnectError!IoType.Socket) void {
                const checker = probe.checker;
                assert(probe.armed.connect);
                probe.armed.connect = false;
                const http_check = checker.state == .probing and
                    probe.pending_verdict == .none and
                    checker.checkOf(probe.target_cluster).kind == .http;
                if (result) |socket| {
                    if (http_check) {
                        // The http probe's dial is the beginning of the
                        // probe, not its verdict: the socket is stored and
                        // carries the request and response legs.
                        probe.socket = socket;
                        probe.beginRequest(socket);
                        probe.settle();
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
                    if (probe.pending_verdict == .none) {
                        probe.pending_verdict = .pass;
                    }
                } else |err| switch (err) {
                    // The deadline fired first and canceled the dial; the
                    // fail verdict is already pending.
                    error.Canceled => assert(probe.pending_verdict == .fail),
                    else => {
                        if (probe.pending_verdict == .none) {
                            probe.pending_verdict = .fail;
                        }
                        // Typed refusals are the origin's verdict; only
                        // kernel pressure on our side is witnessed (§8) —
                        // the same split the data-path dial makes.
                        checker.server.witnessKernelPressure(.connect, err);
                    },
                }
                probe.settle();
            }

            /// Render this probe's request and start writing it. The render
            /// cannot fail: `health_check_request_bytes_max` is derived from
            /// the path and Host bounds the loader already enforced (§5).
            fn beginRequest(probe: *Probe, socket: IoType.Socket) void {
                const checker = probe.checker;
                assert(checker.state == .probing);
                assert(!probe.armed.send);
                assert(!probe.armed.recv);
                const check = checker.checkOf(probe.target_cluster);
                assert(check.kind == .http);
                const http = check.http.?;
                const cluster = &checker.server.config.clusters[probe.target_cluster];
                const endpoint = cluster.endpoints[probe.target_endpoint];
                // `Connection: close` because the probe never reuses this
                // socket: it asks one question and hangs up, which also frees
                // the origin from parking a connection nobody will return to.
                const rendered = if (http.host) |host|
                    std.fmt.bufPrint(
                        &probe.request,
                        "GET {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n",
                        .{ http.path, host },
                    ) catch unreachable
                else
                    std.fmt.bufPrint(
                        &probe.request,
                        "GET {s} HTTP/1.1\r\nHost: {f}\r\nConnection: close\r\n\r\n",
                        .{ http.path, endpoint },
                    ) catch unreachable;
                probe.request_len = @intCast(rendered.len);
                probe.request_sent = 0;
                probe.response_len = 0;
                assert(probe.request_len >= 1);
                probe.armSend(socket);
            }

            fn armSend(probe: *Probe, socket: IoType.Socket) void {
                const checker = probe.checker;
                assert(checker.state == .probing);
                assert(!probe.armed.send);
                assert(probe.request_sent < probe.request_len);
                probe.armed.send = true;
                checker.server.io.send(
                    socket,
                    probe.request[probe.request_sent..probe.request_len],
                    &probe.op_send,
                    Probe,
                    probe,
                    onProbeSend,
                );
                assert(probe.armedCount() <= constants.health_probe_ops_max);
            }

            fn onProbeSend(probe: *Probe, result: Io.SendError!u32) void {
                const checker = probe.checker;
                assert(probe.armed.send);
                probe.armed.send = false;
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
                    if (probe.pending_verdict == .none) {
                        probe.pending_verdict = .fail;
                        checker.server.witnessKernelPressure(.send, err);
                    }
                    probe.settle();
                    return;
                };
                probe.request_sent += sent;
                assert(probe.request_sent <= probe.request_len);
                // A verdict already reached (the deadline fired and shut this
                // socket down) ends the probe here: arming another leg would
                // only spend an op to be told what is already known.
                if (probe.pending_verdict == .none) {
                    const socket = probe.socket.?;
                    if (probe.request_sent < probe.request_len) {
                        // A short write is ordinary (§6): resume where it left off.
                        probe.armSend(socket);
                    } else {
                        probe.armRecv(socket);
                    }
                }
                probe.settle();
            }

            fn armRecv(probe: *Probe, socket: IoType.Socket) void {
                const checker = probe.checker;
                assert(checker.state == .probing);
                assert(!probe.armed.recv);
                assert(probe.response_len < probe.response.len);
                probe.armed.recv = true;
                checker.server.io.recv(
                    socket,
                    probe.response[probe.response_len..],
                    &probe.op_recv,
                    Probe,
                    probe,
                    onProbeRecv,
                );
                assert(probe.armedCount() <= constants.health_probe_ops_max);
            }

            fn onProbeRecv(probe: *Probe, result: Io.RecvError!u32) void {
                const checker = probe.checker;
                assert(probe.armed.recv);
                probe.armed.recv = false;
                if (checker.state == .stopping) {
                    checker.continueStop();
                    return;
                }
                assert(checker.state == .probing);
                const received = result catch |err| {
                    assert(err != error.Canceled); // Same rule as the send leg.
                    // EOF or reset before a whole head arrived: an origin
                    // that hangs up mid-status has not answered the check.
                    if (probe.pending_verdict == .none) {
                        probe.pending_verdict = .fail;
                        checker.server.witnessKernelPressure(.recv, err);
                    }
                    probe.settle();
                    return;
                };
                probe.response_len += received;
                assert(probe.response_len <= probe.response.len);
                if (probe.pending_verdict == .none) {
                    probe.judgeResponse();
                }
                if (probe.pending_verdict == .none) {
                    // The head is still arriving. A full buffer with no head
                    // in it is the §7 oversize-head verdict, not a shortfall.
                    if (probe.response_len == probe.response.len) {
                        probe.pending_verdict = .fail;
                    } else {
                        probe.armRecv(probe.socket.?);
                    }
                }
                probe.settle();
            }

            /// Judge what has arrived so far, leaving the verdict `.none`
            /// while the head is merely incomplete. The head parser is the
            /// data path's own (§7), so a probe accepts exactly the responses
            /// this proxy would forward — and nothing it would reject.
            fn judgeResponse(probe: *Probe) void {
                assert(probe.checker.state == .probing);
                assert(probe.pending_verdict == .none);
                const expect_status = probe.checker.checkOf(probe.target_cluster).http.?.expect_status;
                var storage: parser.HeaderStorage = undefined;
                const head = parser.parseResponseHead(
                    probe.response[0..probe.response_len],
                    false,
                    &storage,
                    .get,
                ) catch |err| {
                    if (err == error.Incomplete) return;
                    probe.pending_verdict = .fail;
                    return;
                };
                probe.pending_verdict = if (head.status == expect_status) .pass else .fail;
            }

            fn onProbeDeadline(probe: *Probe, result: Io.TimerError!void) void {
                const checker = probe.checker;
                assert(probe.armed.deadline);
                probe.armed.deadline = false;
                if (checker.state == .stopping) {
                    result catch {};
                    checker.continueStop();
                    return;
                }
                assert(checker.state == .probing);
                if (result) |_| {
                    if (probe.pending_verdict == .none) {
                        // Fired first: the probe outlived its budget. It
                        // fails, and whatever leg is armed is forced to a
                        // terminal completion so even a black-holed endpoint
                        // or a mute origin releases the prober (§5).
                        probe.pending_verdict = .fail;
                        probe.endArmedLeg();
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
                    assert(probe.pending_verdict != .none);
                }
                probe.settle();
            }

            fn onProbeCancel(probe: *Probe) void {
                const checker = probe.checker;
                assert(probe.armed.cancel);
                probe.armed.cancel = false;
                if (checker.state == .stopping) {
                    checker.continueStop();
                    return;
                }
                assert(checker.state == .probing);
                probe.settle();
            }

            /// End whichever leg is armed, by the only means each allows: a
            /// dial takes the one legal cancel (§4), while a send or recv is
            /// never canceled (§5) — shutting the socket down is what makes
            /// it complete. Both are idempotent here, because a deadline and
            /// a drain can each reach this for the same probe.
            fn endArmedLeg(probe: *Probe) void {
                // Only ever called with a leg outstanding: a deadline fires
                // against the leg it was armed beside, and the drain ladder
                // reaches here only under its own armed guard.
                assert(probe.armed.connect or probe.armed.send or probe.armed.recv);
                assert(probe.checker.state == .probing or probe.checker.state == .stopping);
                if (probe.armed.connect and !probe.armed.cancel and !probe.canceled.connect) {
                    probe.armCancelConnect();
                    return;
                }
                if ((probe.armed.send or probe.armed.recv) and !probe.shutdown_done) {
                    // A data leg exists only for an http probe, which is the
                    // only kind that holds a socket to shut down.
                    assert(probe.socket != null);
                    probe.shutdown_done = true;
                    probe.checker.server.io.shutdown(probe.socket.?, .both);
                }
            }

            /// The probe's socket, once no op can reference it. Closing is
            /// synchronous for the same reason `continueTeardown`'s is: by
            /// here the armed set is empty, so nothing is left to deliver
            /// against this fd (§5).
            fn closeSocket(probe: *Probe) void {
                // This probe's own ops, not the prober's: a sibling probe
                // may still be mid-flight against a different endpoint,
                // and its armed op says nothing about this fd.
                assert(probe.armedCount() == 0);
                assert(probe.checker.state == .probing or probe.checker.state == .stopping);
                if (probe.socket) |socket| {
                    probe.checker.server.io.closeNow(socket);
                    probe.socket = null;
                }
                probe.shutdown_done = false;
            }

            /// The delivery that empties this probe's armed set applies the
            /// verdict and moves the sweep along — never earlier, so no
            /// completion can land on a probe that already advanced (§5).
            fn settle(probe: *Probe) void {
                const checker = probe.checker;
                assert(checker.state == .probing);
                // A decided probe has no use for its budget. Cancelling here
                // rather than at each verdict site is what makes every leg —
                // dial, send, recv — advance the sweep the moment it knows,
                // instead of idling until the deadline fires: an http probe
                // that answered in a microsecond must not hold the prober
                // for the whole `timeout_ms`.
                if (probe.pending_verdict != .none and
                    probe.armed.deadline and !probe.armed.cancel)
                {
                    probe.armCancelDeadline();
                }
                if (probe.armedCount() != 0) return;
                assert(probe.pending_verdict != .none);
                probe.closeSocket();
                const verdict = probe.pending_verdict;
                probe.pending_verdict = .none;
                if (verdict == .pass) {
                    checker.witnessPass(probe.target_cluster, probe.target_endpoint);
                } else {
                    checker.witnessFail(probe.target_cluster, probe.target_endpoint);
                }
                checker.dispatchNext();
            }

            fn armCancelDeadline(probe: *Probe) void {
                assert(probe.armed.deadline);
                assert(!probe.armed.cancel);
                probe.armed.cancel = true;
                probe.canceled.deadline = true;
                probe.checker.server.io.timerCancel(
                    &probe.op_deadline,
                    &probe.op_cancel,
                    Probe,
                    probe,
                    onProbeCancel,
                );
                assert(probe.armedCount() <= constants.health_probe_ops_max);
            }

            fn armCancelConnect(probe: *Probe) void {
                assert(probe.armed.connect);
                assert(!probe.armed.cancel);
                probe.armed.cancel = true;
                probe.canceled.connect = true;
                probe.checker.server.io.connectCancel(
                    &probe.op_connect,
                    &probe.op_cancel,
                    Probe,
                    probe,
                    onProbeCancel,
                );
                assert(probe.armedCount() <= constants.health_probe_ops_max);
            }

            /// This probe's rung of the drain ladder: spend a cancel on the
            /// next armed op that has not had one, and report whether the
            /// checker must now wait for a delivery. An op whose cancel
            /// already ran but whose own terminal delivery is still in
            /// flight is waited on, never re-canceled.
            fn continueStop(probe: *Probe) bool {
                assert(probe.checker.state == .stopping);
                if (probe.armed.cancel) return true;
                if (probe.armed.deadline and !probe.canceled.deadline) {
                    probe.armCancelDeadline();
                    return true;
                }
                if (probe.armed.connect and !probe.canceled.connect) {
                    probe.armCancelConnect();
                    return true;
                }
                // A data leg takes no cancel op at all (§5): the shutdown
                // makes it complete, and its delivery re-enters the ladder.
                // It therefore reports no wait — the shutdown consumes no
                // completion to wait on, so the checker's armed check is
                // what decides whether anything is still outstanding. The
                // guard lives inside `endArmedLeg`, which is idempotent, so
                // this states only that a leg is what it is being called for.
                if (probe.armed.send or probe.armed.recv) {
                    probe.endArmedLeg();
                }
                return false;
            }
        };

        pub fn init(
            checker: *Self,
            arena: std.mem.Allocator,
            server: *ServerType,
            keys: upstream.EndpointKeys,
            /// The probe's response buffer size — `limits.head_buffer_bytes`,
            /// so the probe accepts exactly the heads the data path does.
            response_bytes: u32,
        ) error{OutOfMemory}!void {
            assert(keys.count >= 1);
            assert(response_bytes >= constants.head_buffer_bytes_min);
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
            checker.armed_rest = false;
            checker.armed_rest_cancel = false;
            checker.canceled_rest = false;
            checker.op_rest = .{};
            checker.op_rest_cancel = .{};
            const probe_count = server.config.healthProbes();
            assert(probe_count >= 1);
            assert(probe_count <= constants.health_probe_concurrency_max);
            checker.probes = try arena.alloc(Probe, probe_count);
            for (checker.probes) |*probe| {
                try probe.init(arena, checker, response_bytes);
            }
            const clusters = server.config.clusters;
            assert(clusters.len >= 1);
            // Same pairing check the balancer makes: `keys` must describe
            // this config, or the mask is sized for one shape and indexed
            // for another. `clusters.len <= healthy.len` does *not* say
            // that — it holds for any `stride >= 1`.
            assert(keys.count == @as(u32, @intCast(clusters.len)) * keys.stride);
            // The config's own count, not a second walk of the same
            // clusters: the budget prices the prober from this number and
            // the prober sizes itself from it, and §5's closed form is
            // only closed while there is exactly one reading of it.
            checker.checked_count = server.config.checkedEndpoints();
            assert(checker.checked_count <= checker.healthy.len);
            // What `Server.initHeadBuffers` priced the prober's scratch
            // at, checked where the probes are actually allocated.
            assert(probe_count == constants.healthProbeConcurrency(checker.checked_count));
            // Never more probes than there are endpoints to hand them:
            // an idle probe would be a reservation nothing can spend.
            // The floor of one is the exception, and only when nothing
            // is checked at all — the prober stays `.off` then.
            assert(checker.probes.len <= @max(1, checker.checked_count));
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
            for (checker.probes) |*probe| {
                probe.pending_verdict = .none;
            }
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
            const rest_ops: u32 = @as(u32, @intFromBool(checker.armed_rest)) +
                @as(u32, @intFromBool(checker.armed_rest_cancel));
            var probe_ops: u32 = 0;
            for (checker.probes) |*probe| {
                const armed = probe.armedCount();
                assert(armed <= constants.health_probe_ops_max);
                probe_ops += armed;
            }
            // The disjointness itself, not merely a bound loose enough to
            // survive it: the rest timer and every probe are never armed
            // at the same moment, which is *why* the reservation is
            // `probes.len × health_probe_ops_max` and not that plus two.
            // A bound alone would let a co-armed rest timer hide inside
            // the slack of an idle probe (§8).
            assert(rest_ops == 0 or probe_ops == 0);
            assert(probe_ops <=
                @as(u32, @intCast(checker.probes.len)) * constants.health_probe_ops_max);
            assert(rest_ops <= 2);
            return rest_ops + probe_ops;
        }

        fn startSweep(checker: *Self) void {
            assert(checker.armedCount() == 0);
            assert(checker.checked_count >= 1);
            checker.state = .probing;
            checker.cursor_cluster = 0;
            checker.cursor_endpoint = 0;
            checker.dispatchNext();
        }

        /// One endpoint of a sweep, claimed from the cursor.
        const Target = struct {
            cluster: *const config_module.Config.Cluster,
            cluster_index: u16,
            endpoint_index: u16,
        };

        /// Claim the next checked endpoint, or null once the sweep has
        /// handed out every one. The cursor advances *here*, as part of
        /// the claim and before the caller arms anything, which is what
        /// makes it impossible for two probes to be handed the same
        /// endpoint. Bounded: the walk visits each cluster at most once
        /// past the cursor.
        fn takeNextTarget(checker: *Self) ?Target {
            assert(checker.state == .probing);
            const clusters = checker.server.config.clusters;
            while (checker.cursor_cluster < clusters.len) {
                const cluster = &clusters[checker.cursor_cluster];
                if (cluster.check == null or checker.cursor_endpoint >= cluster.endpoints.len) {
                    checker.cursor_cluster += 1;
                    checker.cursor_endpoint = 0;
                    continue;
                }
                const target: Target = .{
                    .cluster = cluster,
                    .cluster_index = checker.cursor_cluster,
                    .endpoint_index = checker.cursor_endpoint,
                };
                checker.cursor_endpoint += 1;
                return target;
            }
            return null;
        }

        /// Probes with an op still armed — the ones that own an endpoint
        /// whose verdict has not landed yet.
        fn busyProbes(checker: *const Self) u32 {
            var busy: u32 = 0;
            for (checker.probes) |*probe| {
                if (probe.armedCount() != 0) busy += 1;
            }
            assert(busy <= checker.probes.len);
            return busy;
        }

        /// Fill every idle probe from the cursor, and — once the cursor
        /// is exhausted and no probe is still working — end the sweep
        /// and rest for the interval.
        ///
        /// Resting is gated on the probes rather than on the cursor
        /// alone: a probe still in flight owns an endpoint whose verdict
        /// has not been applied, and starting the interval on top of it
        /// would pace the next sweep against a mask this one had not
        /// finished writing.
        fn dispatchNext(checker: *Self) void {
            assert(checker.state == .probing);
            // The disjointness the op reservation rests on, at the end of
            // the hand-off where it could break: a sweep never dispatches
            // beside a live rest timer.
            assert(!checker.armed_rest and !checker.armed_rest_cancel);
            var dispatched: u32 = 0;
            for (checker.probes) |*probe| {
                if (probe.armedCount() != 0) continue;
                assert(probe.pending_verdict == .none);
                const target = checker.takeNextTarget() orelse break;
                probe.begin(target.cluster, target.cluster_index, target.endpoint_index);
                // The §4 seam never delivers a completion inside the call
                // that arms it — XevIo routes a would-be-synchronous one
                // through a zero-delay timer precisely so it cannot. This
                // loop is where that guarantee earns its keep: a
                // reentrant delivery would run `settle` and then this
                // function again from inside this frame, and the next
                // iteration would arm against a state the inner call had
                // already moved to `.resting`. Stated as an assert rather
                // than trusted, because the single-probe sweep would only
                // have misbehaved locally where this one trips.
                assert(checker.state == .probing);
                dispatched += 1;
                assert(dispatched <= checker.probes.len);
            }
            if (checker.busyProbes() == 0) checker.rest();
        }

        /// The cluster's resolved check policy. Only a checked cluster is
        /// ever probed, so the option is settled by the walk in
        /// `dispatchNext` before anything here reads it.
        fn checkOf(checker: *const Self, cluster_index: u16) *const config_module.Config.Cluster.Check {
            assert(cluster_index < checker.server.config.clusters.len);
            const check = &checker.server.config.clusters[cluster_index].check;
            assert(check.* != null);
            return &check.*.?;
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
            // The labeled twin (#179): a transition always knows its
            // endpoint — the probe was addressed to it.
            checker.server.labeled.incrementEndpoint(.health_up, key);
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
            // The labeled twin (#179), same key the mask just flipped.
            checker.server.labeled.incrementEndpoint(.health_down, key);
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
            checker.armed_rest = true;
            checker.server.io.timerStart(
                &checker.op_rest,
                @as(u64, checker.server.config.health_interval_ms) * std.time.ns_per_ms,
                Self,
                checker,
                onRest,
            );
        }

        fn onRest(checker: *Self, result: Io.TimerError!void) void {
            assert(checker.armed_rest);
            checker.armed_rest = false;
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

        fn onRestCancel(checker: *Self) void {
            assert(checker.armed_rest_cancel);
            checker.armed_rest_cancel = false;
            // Nothing but the drain ever cancels the rest timer, and the
            // drain flips `.stopping` before it does.
            assert(checker.state == .stopping);
            checker.continueStop();
        }

        /// Toward quiescence: the rest timer first, then every probe's
        /// own ladder, then — once every delivery has drained — stop.
        ///
        /// The probes advance together rather than one at a time. Each
        /// owns its cancel completion, so "cancels are serialized" is a
        /// per-probe rule (`Probe.armed.cancel`) and never a per-prober
        /// one; draining them in sequence would only make a drain take
        /// as long as the slowest chain of them.
        fn continueStop(checker: *Self) void {
            assert(checker.state == .stopping);
            if (checker.armed_rest_cancel) return;
            if (checker.armed_rest and !checker.canceled_rest) {
                checker.armed_rest_cancel = true;
                checker.canceled_rest = true;
                checker.server.io.timerCancel(
                    &checker.op_rest,
                    &checker.op_rest_cancel,
                    Self,
                    checker,
                    onRestCancel,
                );
                // The rest timer and its cancel are the only ops a
                // resting prober holds, and no probe co-arms with them.
                assert(checker.armedCount() <= 2);
                return;
            }
            var outstanding = false;
            for (checker.probes) |*probe| {
                if (probe.continueStop()) outstanding = true;
            }
            if (outstanding) return;
            if (checker.armedCount() != 0) return;
            assert(checker.isQuiescent());
            // Nothing can reference a probe's fd once every op has
            // drained, which is what makes closing them here safe (§5).
            for (checker.probes) |*probe| {
                probe.closeSocket();
            }
            checker.state = .stopped;
            checker.server.maybeStopAfterDrain();
        }
    };
}
