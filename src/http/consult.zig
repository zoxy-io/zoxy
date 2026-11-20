//! A policy's consult (#437): the request a policy sends a service before
//! it decides, carried on the parked request's own upstream leg.
//!
//! The policy run stops at the policy that consulted, and its stream parks
//! in `.consulting`. The consult then runs on the stream's own ops — the
//! dial, a send, a recv, and the dial's cancel — over an upstream slot it
//! leases from the cluster's pool. So a consult is held to the ring and fd
//! reservations an exchange is: the stream arms nothing else while it
//! waits (§5, `stream_ops_max`), and the socket is a slot's. A teardown
//! forces it as it forces an exchange's legs. Its timeout is the stream's
//! deadline, narrowed to the type's `consult_timeout_ms` and clamped under
//! the request's own.
//!
//! What a consult adds is one buffer, a consult slot's: its request goes
//! out of it, and its reply comes back into it — a head within the head
//! buffer's size, a body within the type's bound. A consult dials afresh
//! and closes once answered: reusing a parked connection would need §7's
//! stale-connection replay, which a consult does not have. A body framed
//! by its length or by the origin's close is read; a chunked one is not,
//! and the reply carries its head alone, marked truncated.
//!
//! Once every leg is delivered the stream goes back to `.reading_head`,
//! and its request resumes where its policies stopped
//! (`Proxy.resumeConsulted`).

const std = @import("std");

const constants = @import("../constants.zig");
const extension = @import("../extension.zig");
const config_module = @import("../config.zig");
const conn_module = @import("../net/Conn.zig");
const Io = @import("../io/io.zig");
const parser = @import("parser.zig");

const assert = std.debug.assert;

/// The process's consult slots: one buffer each, for a consult's request
/// and then its reply. Sized at startup (`limits.consult_slots`), never
/// grown.
pub const Slots = struct {
    /// Every slot's buffer, end to end.
    buffers: []u8,
    slot_bytes: u32,
    /// The free slots, as a stack.
    free: []u16,
    free_count: u32,

    pub fn init(slots: *Slots, arena: std.mem.Allocator, count: u32, slot_bytes: u32) error{OutOfMemory}!void {
        // `slot_none` stays out of range.
        assert(count < std.math.maxInt(u16));
        assert(count == 0 or slot_bytes >= 1);
        slots.slot_bytes = slot_bytes;
        slots.buffers = try arena.alloc(u8, @as(usize, count) * slot_bytes);
        slots.free = try arena.alloc(u16, count);
        for (slots.free, 0..) |*entry, index| entry.* = @intCast(count - 1 - index);
        slots.free_count = count;
        assert(slots.busyCount() == 0);
    }

    pub fn take(slots: *Slots) ?u16 {
        assert(slots.free_count <= slots.free.len);
        if (slots.free_count == 0) return null;
        slots.free_count -= 1;
        const slot = slots.free[slots.free_count];
        assert(slot < slots.free.len);
        return slot;
    }

    pub fn give(slots: *Slots, slot: u16) void {
        assert(slot < slots.free.len);
        assert(slots.free_count < slots.free.len);
        slots.free[slots.free_count] = slot;
        slots.free_count += 1;
    }

    pub fn buffer(slots: *const Slots, slot: u16) []u8 {
        assert(slot < slots.free.len);
        assert(slots.slot_bytes >= 1);
        const start = @as(usize, slot) * slots.slot_bytes;
        return slots.buffers[start..][0..slots.slot_bytes];
    }

    pub fn busyCount(slots: *const Slots) u32 {
        assert(slots.free_count <= slots.free.len);
        return @as(u32, @intCast(slots.free.len)) - slots.free_count;
    }
};

/// One consult slot's bytes (#437): the widest request a listed type may
/// send, or the head buffer and the widest body one may read back,
/// whichever is more — and nothing in a build whose policies consult
/// nothing.
pub fn slotBytes(comptime policies: []const type, head_buffer_bytes: u32) u32 {
    if (comptime !extension.listsConsultingPolicy(policies)) return 0;
    assert(head_buffer_bytes >= constants.head_buffer_bytes_min);
    const request = comptime extension.consultRequestBytes(policies);
    const reply = head_buffer_bytes + comptime extension.consultReplyBytes(policies);
    assert(request >= 1);
    return @max(request, reply);
}

/// The slots `limits` reserve for a build's `policies`: the stated
/// count, or none in a build with nothing to use them.
pub fn slotsFor(comptime policies: []const type, limits: *const config_module.Config.Limits) u32 {
    if (comptime !extension.listsConsultingPolicy(policies)) return 0;
    assert(limits.consult_slots <= limits.upstream_slots);
    return limits.consult_slots;
}

/// Every consult slot's bytes under `limits`: §5's `consult_bytes` term.
pub fn bytesFor(comptime policies: []const type, limits: *const config_module.Config.Limits) u64 {
    const count = slotsFor(policies, limits);
    if (count == 0) return 0;
    return @as(u64, count) * slotBytes(policies, limits.head_buffer_bytes);
}

/// What a consulting type declares, read off its selection.
pub const Bounds = struct {
    request_bytes_max: u32,
    reply_bytes_max: u32,
    timeout_ms: u32,
};

/// Where the policy run stopped for a consult.
pub const Park = struct {
    position: u16,
    route_phase: bool,
    /// The route a listener policy before it chose (#430).
    chosen_route: ?u16,
};

pub fn Engine(comptime runtime: extension.Runtime) type {
    const IoType = runtime.Io;
    const ServerType = @import("../Server.zig").Server(runtime);
    const ConnType = conn_module.Conn(runtime);
    const StreamType = ConnType.StreamType;
    const UpstreamType = @import("../net/upstream.zig").UpstreamPool(IoType).Upstream;
    const Proxy = @import("proxy.zig").Proxy(runtime);
    const State = StreamType.L7State.Consult;

    return struct {
        /// Start `consult` on `stream`'s own upstream leg: true when the
        /// stream parked on it, false when it could not be made — a
        /// request past the type's bound, no consult slot, no endpoint or
        /// upstream slot to dial — which the caller answers with the
        /// type's declared failure.
        pub fn begin(
            server: *ServerType,
            stream: *StreamType,
            consult: extension.Consult,
            bounds: Bounds,
            /// The request, for a pick that reads it.
            view: *const extension.Request,
            park: Park,
        ) bool {
            assert(stream.phase == .reading_head);
            assert(stream.upstream == null);
            assert(stream.armedCount() == 0);
            assert(stream.l7.consult.slot == State.slot_none);
            if (consult.request.len > bounds.request_bytes_max) {
                server.counters.increment("l7_policy_consult_oversize");
                return false;
            }
            const slot = server.consult_slots.take() orelse {
                server.counters.increment("l7_policy_consult_slots_exhausted");
                return false;
            };
            const leased = lease(server, stream, consult.cluster_index, view) orelse {
                server.consult_slots.give(slot);
                return false;
            };
            const buffer = server.consult_slots.buffer(slot);
            assert(consult.request.len <= buffer.len);
            @memcpy(buffer[0..consult.request.len], consult.request);
            const reply_bytes_max = server.config.limits.head_buffer_bytes + bounds.reply_bytes_max;
            assert(reply_bytes_max <= buffer.len);
            stream.l7.consult = .{
                .slot = slot,
                .position = park.position,
                .route_phase = park.route_phase,
                .chosen_route = park.chosen_route,
                .request_len = @intCast(consult.request.len),
                .head_request = std.mem.startsWith(u8, consult.request, "HEAD "),
                .reply_bytes_max = reply_bytes_max,
                .body_bytes_max = bounds.reply_bytes_max,
            };
            stream.upstream = leased.upstream;
            server.counters.increment("l7_policy_consult_started");
            // The type's timeout, inside the request's: re-based while
            // still `.reading_head`, a state a re-base is legal from.
            server.storeExchangeDeadline(stream, bounds.timeout_ms);
            server.rebaseExchangeDeadline(stream);
            stream.moveTo(.consulting);
            stream.arm(&stream.op_connect, "connect");
            server.io.connect(&leased.address, &stream.op_connect.completion, StreamType, stream, onConnect);
            return true;
        }

        const Leased = struct {
            upstream: *UpstreamType,
            address: Io.Address,
        };

        /// An endpoint of the consulted cluster, by its own pick and the
        /// health mask, and a fresh upstream slot to dial it from — or
        /// null, counted, when the pick or the pool sheds. A picker that
        /// completes (#423) hears of the consult's pick on the stream's
        /// own record, free until the request's own pick.
        fn lease(server: *ServerType, stream: *StreamType, cluster_index: u16, view: *const extension.Request) ?Leased {
            assert(cluster_index < server.config.clusters.len);
            assert(extension.consultable(&server.config.clusters[cluster_index]));
            const pick = switch (server.pickEndpoint(cluster_index, view.client, &.{}, view, view.tag)) {
                .dial => |chosen| chosen,
                .capped, .cluster_capped => {
                    server.counters.increment("l7_policy_consult_shed");
                    return null;
                },
                // Nothing tried yet, so the routable set is not empty.
                .exhausted => unreachable,
                // `pickEndpoint` finishes every extension pick itself.
                .extension => unreachable,
            };
            server.witnessPick(cluster_index, &pick);
            const upstream = server.acquireUpstream(cluster_index, pick.endpoint_index) orelse {
                server.counters.increment("l7_policy_consult_shed");
                return null;
            };
            assert(upstream.endpoint_index == pick.endpoint_index);
            server.notePick(stream, cluster_index, pick.endpoint_index, false);
            return .{ .upstream = upstream, .address = pick.address };
        }

        fn onConnect(stream: *StreamType, result: Io.ConnectError!IoType.Socket) void {
            const server = stream.conn.server;
            stream.delivered(&stream.op_connect, "connect");
            // A socket that arrived is the slot's whatever comes next:
            // whoever closes the leg closes it.
            if (result) |socket| {
                stream.upstream.?.socket = socket;
                stream.upstream_socket = socket;
            } else |_| {}
            if (ServerType.exchangeEnding(stream)) {
                if (stream.upstream_socket) |socket| server.io.shutdown(socket, .both);
                return server.continueExchangeEnd(stream);
            }
            assert(stream.phase == .consulting);
            if (result) |socket| {
                if (stream.l7.consult.outcome == .none) {
                    const upstream = stream.upstream.?;
                    server.notePickConnected(stream);
                    server.disableNagle(socket, server.endpointIsUnix(upstream.cluster_index, upstream.endpoint_index));
                    return armSend(server, stream);
                }
            } else |err| {
                // A cancel is the expiry's, its outcome already decided.
                if (err != error.Canceled) server.witnessKernelPressure(.connect, err);
                fail(stream, .failed);
            }
            settle(server, stream);
        }

        fn armSend(server: *ServerType, stream: *StreamType) void {
            const state = &stream.l7.consult;
            assert(state.outcome == .none);
            assert(state.request_sent < state.request_len);
            const buffer = server.consult_slots.buffer(state.slot);
            stream.arm(&stream.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.send(
                stream.upstream_socket.?,
                buffer[state.request_sent..state.request_len],
                &stream.op_data_client_to_upstream.completion,
                StreamType,
                stream,
                onSent,
            );
        }

        fn onSent(stream: *StreamType, result: Io.SendError!u32) void {
            const server = stream.conn.server;
            stream.delivered(&stream.op_data_client_to_upstream, "data_client_to_upstream");
            if (ServerType.exchangeEnding(stream)) return server.continueExchangeEnd(stream);
            assert(stream.phase == .consulting);
            const state = &stream.l7.consult;
            const sent = result catch |err| {
                server.witnessKernelPressure(.send, err);
                fail(stream, .failed);
                return settle(server, stream);
            };
            state.request_sent += sent;
            assert(state.request_sent <= state.request_len);
            // The expiry shut the socket down under a send that landed.
            if (state.outcome != .none) return settle(server, stream);
            if (state.request_sent < state.request_len) return armSend(server, stream);
            armRecv(server, stream);
        }

        fn armRecv(server: *ServerType, stream: *StreamType) void {
            const state = &stream.l7.consult;
            assert(state.outcome == .none);
            assert(state.reply_len < state.reply_bytes_max);
            const buffer = server.consult_slots.buffer(state.slot);
            stream.arm(&stream.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.recv(
                stream.upstream_socket.?,
                buffer[state.reply_len..state.reply_bytes_max],
                &stream.op_data_upstream_to_client.completion,
                StreamType,
                stream,
                onReceived,
            );
        }

        fn onReceived(stream: *StreamType, result: Io.RecvError!u32) void {
            const server = stream.conn.server;
            stream.delivered(&stream.op_data_upstream_to_client, "data_upstream_to_client");
            if (ServerType.exchangeEnding(stream)) return server.continueExchangeEnd(stream);
            assert(stream.phase == .consulting);
            const state = &stream.l7.consult;
            const received = result catch |err| {
                // The origin's close ends a body framed by it, and fails
                // a reply that was not done.
                const ends = err == error.EndOfStream and state.outcome == .none and state.body_until_close;
                if (ends) {
                    state.body_len = state.reply_len - state.body_start;
                    state.outcome = .replied;
                } else {
                    if (err != error.EndOfStream) server.witnessKernelPressure(.recv, err);
                    fail(stream, .failed);
                }
                return settle(server, stream);
            };
            state.reply_len += received;
            assert(state.reply_len <= state.reply_bytes_max);
            if (state.outcome == .none) judge(server, stream);
            if (state.outcome == .none) return armRecv(server, stream);
            settle(server, stream);
        }

        /// Whether the reply so far is whole, judged once its head parsed
        /// by how that head frames the body.
        fn judge(server: *ServerType, stream: *StreamType) void {
            const state = &stream.l7.consult;
            assert(state.outcome == .none);
            if (state.body_start == 0) parseHead(server, stream);
            if (state.outcome != .none) return;
            if (state.body_start == 0) {
                // A head that fills the buffer and still does not parse is
                // one too large, as the parser itself would say.
                if (state.reply_len == state.reply_bytes_max) fail(stream, .failed);
                return;
            }
            const body_have = state.reply_len - state.body_start;
            if (state.body_until_close) {
                // Its bound is reached before its close: cut there.
                if (state.reply_len == state.reply_bytes_max) {
                    state.body_len = body_have;
                    state.body_truncated = true;
                    state.outcome = .replied;
                }
                return;
            }
            assert(state.body_start + state.body_len <= state.reply_bytes_max);
            if (body_have >= state.body_len) state.outcome = .replied;
        }

        /// The reply's head, once it is whole: where its body starts and
        /// how long it is to be. An interim head is not an answer.
        fn parseHead(server: *ServerType, stream: *StreamType) void {
            const state = &stream.l7.consult;
            assert(state.body_start == 0);
            const head_bytes = server.config.limits.head_buffer_bytes;
            const window: u32 = @min(state.reply_len, head_bytes);
            const buffer = server.consult_slots.buffer(state.slot);
            var storage: parser.HeaderStorage = undefined;
            const method: parser.Method = if (state.head_request) .head else .get;
            const head = parser.parseResponseHead(buffer[0..window], window == head_bytes, &storage, method) catch |err| {
                if (err != error.Incomplete) fail(stream, .failed);
                return;
            };
            if (head.status < 200) return fail(stream, .failed);
            assert(head.head_len >= 1);
            server.notePickHead(stream);
            state.status = head.status;
            state.body_start = head.head_len;
            switch (head.framing) {
                .none => state.body_len = 0,
                .content_length => |length| {
                    state.body_len = @intCast(@min(length, state.body_bytes_max));
                    state.body_truncated = length > state.body_bytes_max;
                },
                .chunked => state.body_truncated = true,
                .until_close => state.body_until_close = true,
            }
        }

        /// The first outcome stands: a leg failing after the expiry forced
        /// it keeps the expiry's.
        fn fail(stream: *StreamType, outcome: State.Outcome) void {
            assert(outcome != .none);
            assert(outcome != .replied);
            if (stream.l7.consult.outcome == .none) stream.l7.consult.outcome = outcome;
        }

        /// The stream's deadline is due while it consults: the consult's
        /// own timeout, or the request's under it. Either way its armed
        /// leg is forced — the dial by its cancel, a data leg by shutting
        /// the socket down — under a grace deadline, and the delivery
        /// settles it. The request's deadline landing inside the grace of
        /// the consult's own makes it out of time after all; any other
        /// deadline due before the delivery ends the exchange.
        pub fn expire(server: *ServerType, stream: *StreamType) void {
            assert(stream.phase == .consulting);
            const state = &stream.l7.consult;
            const request_ns = stream.l7.request_deadline_ns;
            const out_of_time = request_ns != 0 and server.io.nowNs() >= request_ns;
            if (state.outcome != .none) {
                if (!out_of_time) return server.endExchange(stream);
                // Only the consult's own timeout leaves the cap standing.
                assert(state.outcome == .timed_out);
                state.outcome = .request_expired;
                return graceOutOfTime(server, stream);
            }
            state.outcome = if (out_of_time) .request_expired else .timed_out;
            if (out_of_time) {
                graceOutOfTime(server, stream);
            } else {
                grace(server, stream);
            }
            if (stream.armed.connect) {
                assert(!stream.armed.connect_cancel);
                server.armConnectCancel(stream);
            } else {
                assert(stream.armed.data_client_to_upstream or stream.armed.data_upstream_to_client);
                server.upstreamShutdown(stream);
            }
        }

        /// A request out of time is answered as one: its cap retired
        /// first, or the grace would clamp straight back to it.
        fn graceOutOfTime(server: *ServerType, stream: *StreamType) void {
            assert(stream.l7.consult.outcome == .request_expired);
            assert(stream.l7.request_deadline_ns != 0);
            ServerType.clearRequestDeadline(stream);
            grace(server, stream);
        }

        /// The forced leg's grace: the configured idle window, as an
        /// exchange's expiry verdicts take, never the pressure-biased one.
        fn grace(server: *ServerType, stream: *StreamType) void {
            assert(stream.phase == .consulting);
            assert(stream.l7.consult.outcome != .none);
            server.storeExchangeDeadline(stream, server.config.idle_timeout_ms);
            // An admission stream's timer was delivered to get here; a
            // multiplexed one's driver re-arms its connection's after the
            // scan.
            if (stream.h2_id == 0) server.armDeadline(stream.conn);
        }

        /// Once every leg is delivered: the socket closes, the slot goes
        /// back, the consulted cluster's picker hears how the pick went,
        /// and the request resumes. A delivery that leaves another op
        /// armed — a dial and its cancel — waits for that one.
        pub fn settle(server: *ServerType, stream: *StreamType) void {
            const state = &stream.l7.consult;
            assert(stream.phase == .consulting);
            assert(state.outcome != .none);
            if (stream.armedCount() != 0) return;
            server.upstreamClose(stream);
            server.releaseUpstream(stream.upstream.?);
            stream.upstream = null;
            switch (state.outcome) {
                .none => unreachable,
                .replied => server.completePick(stream, .{ .response = state.status }),
                .failed => server.completePickFailed(stream),
                .timed_out, .request_expired => server.completePick(stream, .timed_out),
            }
            if (state.outcome == .timed_out) server.counters.increment("l7_policy_consult_timed_out");
            stream.moveTo(.reading_head);
            Proxy.resumeConsulted(server, stream);
        }
    };
}
