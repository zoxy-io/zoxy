//! The connection slot (DESIGN.md §5): one contiguous object per
//! connection — state machine, embedded completions (one per
//! overlappable op, including both cancels), the stored absolute
//! deadline, and the armed-op set that gates release. A slot returns to
//! the pool only when `armed` is empty; every completion delivery
//! asserts the slot generation recorded at submit, so a straggler into
//! a recycled slot trips an assertion instead of corrupting memory.

const std = @import("std");

const constants = @import("../constants.zig");
const parser = @import("../http/parser.zig");
const router = @import("../http/router.zig");
const filter = @import("../http/filter.zig");
const TlsEngine = @import("../tls/Engine.zig");
const relay = @import("relay.zig");
const upstream_module = @import("upstream.zig");

const assert = std.debug.assert;

/// Strict recv → send → recv per direction (§6): exactly one data op in
/// flight per direction, phase says which; per-connection memory stays
/// constant regardless of stream size. Nothing here depends on the Io
/// backend, so it lives at file scope rather than being re-instantiated
/// per `Conn(IoType)` — which is also what makes it unit-testable.
///
/// The two counts are one debt, kept in the units *framing* works in:
/// `framed_len` is what framing assigned to this message out of the last
/// recv, and `credited_len` is how much of that the target has accepted —
/// a short send resumes from there. Today every send writes those same
/// bytes, so the debt is settled in the units it was incurred and
/// `pending` can slice one buffer with both cursors.
///
/// A *transforming* direction breaks that symmetry, and §4's TLS
/// termination is the one coming: the wire would carry ciphertext, which is
/// neither the same bytes nor the same count, so it has to keep its own
/// wire cursor and credit this debt only once a whole framed chunk is out.
/// Naming the debt apart from the wire is what keeps that a change to
/// `credit` and `pending` rather than a change at every call site — and
/// until then, that the two are the same bytes is what `pending` asserts.
pub const DirectionState = struct {
    phase: Phase = .idle,
    /// Bytes framing assigned to this message from the last recv.
    framed_len: u32 = 0,
    /// How many of those the target has accepted.
    credited_len: u32 = 0,

    pub const Phase = enum(u8) { idle, receiving, sending, finished };

    /// Framing chose `len` bytes of what the last recv delivered: a fresh
    /// debt, nothing credited yet. Zero is legal — framing may end a
    /// message without forwarding a byte.
    ///
    /// The previous debt must be settled first. That is the strict
    /// recv → send → recv discipline (§6) stated as a precondition rather
    /// than left to the call sites: overwriting an unsettled debt is
    /// precisely how a direction would forget bytes it still owed the
    /// target, and losing them silently is the failure mode this vocabulary
    /// exists to make loud.
    pub fn owe(state: *DirectionState, len: u32) void {
        assert(state.owed() == 0);
        state.framed_len = len;
        state.credited_len = 0;
    }

    /// The target accepted `len` more of the debt.
    pub fn credit(state: *DirectionState, len: u32) void {
        assert(len >= 1);
        state.credited_len += len;
        assert(state.credited_len <= state.framed_len);
    }

    /// What the target has not accepted yet.
    pub fn owed(state: *const DirectionState) u32 {
        assert(state.credited_len <= state.framed_len);
        return state.framed_len - state.credited_len;
    }

    /// The window of `buffer` still owed: what a send arms, and what a
    /// short send resumes from. `buffer` starts where this direction's
    /// framed bytes start — the relay buffer on a body leg, past the head
    /// on an excess leg (§7).
    pub fn pending(state: *const DirectionState, buffer: []const u8) []const u8 {
        assert(state.owed() >= 1);
        assert(state.framed_len <= buffer.len);
        return buffer[state.credited_len..state.framed_len];
    }
};

/// One client-directed write in flight (§7, §8): the plaintext still to
/// deliver, and where control goes once it is all out.
///
/// Three writes on the L7 path go to the client outside the body pump — the
/// rendered response head, the body excess that arrived coalesced with it,
/// and a static error response — and they differ only in which bytes they
/// carry and what happens next. One channel for all three means one cursor,
/// one short-write resume, one teardown interlock, and (§4) one place for a
/// transforming client side to turn plaintext into wire bytes. The body pump
/// is the fourth client-directed writer and carries that same seam of its
/// own (`pump.zig`).
pub const ClientWrite = struct {
    /// Shrunk from the front as bytes leave, so a resume is the same code
    /// whether they live in static memory (§8), the head buffer, or an
    /// upstream head. Empty means no write is in flight.
    pending: []const u8 = &.{},
    then: Then = .lingering_close,

    /// What the channel does when `pending` empties.
    pub const Then = enum(u8) {
        /// The rendered response head is out: forward any coalesced body
        /// excess, else move on to the body pump.
        response_excess,
        /// The coalesced excess is out: the body pump, or the exchange ends.
        response_body,
        /// A static response is out: the lingering close (§2, §8).
        lingering_close,
    };
};

pub fn Conn(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);
    const UpstreamType = upstream_module.UpstreamPool(IoType).Upstream;

    return struct {
        pool_next: u32,
        generation: u32,
        server: *ServerType,
        state: State,
        client_socket: IoType.Socket,
        /// Null until the upstream dial completes; making the socket and
        /// its presence one field means an unset upstream can never be
        /// read as a live fd handle.
        upstream_socket: ?IoType.Socket,
        /// Held for the L4 connection's life; on the L7 path it is null
        /// until a body relay starts and again once the connection goes
        /// idle on keep-alive — an idle L7 connection costs a slot and
        /// head buffer only (§5).
        relay_buffer: ?*relay.RelayBuffer,
        /// The TLS engine terminating this connection (§4), checked out
        /// of the shared pool at admission and returned at teardown. Null
        /// on a plain-TCP connection, which is every connection on a
        /// listener without credentials.
        tls: ?*TlsEngine,
        /// Absolute deadline; state transitions only store a new value —
        /// the armed timer op is never touched (§4).
        deadline_ns: u64,
        /// Admission timestamp. The max-lifetime cap is `birth_ns +
        /// max_lifetime_ms`; `storeDeadline` clamps every deadline to it so
        /// an always-active connection is still reaped (§6).
        birth_ns: u64,
        armed: Armed,
        directions: [2]DirectionState,
        /// L7 request/response head bytes accumulate here across recv
        /// retries (§5, §7); idle on L4 connections, which relay through
        /// the relay buffer only. Parsing is detect-and-retry from byte 0
        /// (§7), so these bytes stay the single source of truth: nothing
        /// parsed is stored across callbacks, and a re-parse after an
        /// await costs one bounded scan instead of 2 KiB of per-slot
        /// header storage. Deliberately not zeroed at admission — bytes
        /// past `head_len` are never read.
        head: [constants.head_bytes_max]u8,
        /// Bytes of `head` filled so far; the head's end is found by
        /// parsing, the body (or a pipelined next head) follows it.
        head_len: u32,
        /// The client-directed write in flight, if any (§7, §8) — see
        /// `ClientWrite`. Idle on the L4 path, which relays through the pump.
        client_write: ClientWrite,
        /// The cluster to dial. Seeded from the listener at admission; on
        /// the L7 path `routeRequest` overwrites it with the request
        /// path's cluster once the head parses (§7).
        cluster_index: u16,
        /// The listener's §7 route table, never empty — an l4 listener
        /// resolves to the one catch-all route it can never consult, since
        /// it has no path to match. Set once at admission and constant for
        /// the connection's life, so it survives keep-alive turnarounds.
        routes: []const router.Route,
        /// The listener's §7 filter rules, same lifetime as `routes`
        /// (empty on L4 and when no filters are configured).
        filters: []const filter.Rule,
        /// The leased upstream slot during an L7 exchange; released at
        /// teardown alongside the conn slot (§5). Null outside exchanges
        /// and on the whole L4 path.
        upstream: ?*UpstreamType,
        /// L7 exchange bookkeeping (§7); reset per exchange.
        l7: L7State,

        op_data_client_to_upstream: Op,
        op_data_upstream_to_client: Op,
        op_connect: Op,
        op_connect_cancel: Op,
        op_close_client: Op,
        op_close_upstream: Op,
        op_deadline: Op,
        op_deadline_cancel: Op,

        const Self = @This();

        pub const State = enum(u8) {
            /// TLS termination (§4): ciphertext in, handshake flights out,
            /// until the engine reports the session established. Entered
            /// at admission on a listener that carries credentials, before
            /// any protocol state — TLS is orthogonal to l4/http.
            tls_handshaking,
            // L4 relay states.
            connecting,
            relaying,
            // L7 states (§7): `l7_reading_head` accumulates and re-parses
            // the request head (detect-and-retry); `l7_dialing` awaits the
            // upstream connect; `l7_exchanging` runs the two legs (request
            // out, response back — each with its own sub-state in `l7`);
            // `l7_responding` writes a static error response (§8); and
            // `l7_draining_request` half-closes the write side after a
            // response and drains the client's remaining input so the
            // close does not RST away that response (§2 lingering close).
            l7_reading_head,
            l7_dialing,
            l7_exchanging,
            l7_responding,
            l7_draining_request,
            /// Teardown begun: sockets shut down, pending ops draining,
            /// closes not yet submitted.
            tearing_down,
            /// Closes submitted; the slot releases when the armed set
            /// empties (§5). Splitting this from `tearing_down` lets an
            /// assertion tell "still draining ops" from "awaiting closes".
            closing,
        };

        /// True once teardown has begun, in either teardown phase.
        pub fn isTearingDown(conn: *const Self) bool {
            return conn.state == .tearing_down or conn.state == .closing;
        }

        /// True in any pre-teardown serving state — the states from which
        /// `beginTeardown` is a legal transition.
        pub fn isLive(conn: *const Self) bool {
            return switch (conn.state) {
                .tls_handshaking,
                .connecting,
                .relaying,
                .l7_reading_head,
                .l7_dialing,
                .l7_exchanging,
                .l7_responding,
                .l7_draining_request,
                => true,
                .tearing_down, .closing => false,
            };
        }

        /// How a message body is delimited and how much of it remains —
        /// the §7 framing verdicts turned into countdown state the pumps
        /// consume chunk by chunk.
        pub const Framing = union(enum) {
            none,
            /// Body bytes still to relay.
            content_length: u64,
            /// The scanner owns the end-of-message detection.
            chunked: parser.ChunkedScanner,
            /// Responses only: the body runs to the origin's EOF.
            until_close,
        };

        /// Per-leg progress of an L7 exchange (§7). The request leg sends
        /// the rendered head, then pumps the framed body client → origin;
        /// the response leg starts as soon as the request head is on the
        /// wire (early responses are legal, §7) and mirrors it back.
        pub const L7State = struct {
            request_leg: Leg = .idle,
            response_leg: Leg = .idle,
            request_method: parser.Method = .get,
            request_framing: Framing = .none,
            response_framing: Framing = .none,
            /// Bytes of `head` consumed by the request head; body excess
            /// received with it sits at [request_head_len..head_len].
            request_head_len: u32 = 0,
            /// Bytes of `upstream.head` consumed by the response head;
            /// body excess received with it sits at [marker..head_len].
            response_head_len_marker: u32 = 0,
            /// Length of the rendered request head being sent into
            /// upstream.head, and the cursor over it (short sends resume).
            /// The response head has no pair here: it goes out through the
            /// client-write channel, which owns its own cursor
            /// (`ClientWrite`).
            rendered_request_len: u32 = 0,
            request_head_sent: u32 = 0,
            /// Response body bytes that arrived coalesced with the response
            /// head and did not fit in `conn.head` beside the rendered head:
            /// they follow it from `upstream.head[response_head_len_marker..]`
            /// as the channel's next write. Zero when the excess rode along
            /// with the head, or when there was none.
            response_excess_len: u32 = 0,
            /// True once the request head has been forwarded off conn.head
            /// (head sent and any coalesced body excess drained), so the
            /// response head may render into conn.head (§7 buffer rotation).
            request_head_vacated: bool = false,
            /// The origin's head parsed while conn.head was still occupied;
            /// render it once `request_head_vacated`.
            response_render_pending: bool = false,
            /// True once any response byte reached the client — the §8
            /// verdict split between answering 502 and plain teardown.
            response_started: bool = false,
            /// A verdict decided while data ops were still armed, acted on
            /// when the last one settles: ops are never canceled (§5), they
            /// are *forced* — the upstream socket is shut down and each
            /// armed op completes with an error its handler diverts on.
            pending_verdict: PendingVerdict = .none,
            /// The armed request-leg op is a recv on the CLIENT socket
            /// (the body pump). Such an op cannot be forced without closing
            /// the client the verdict would answer, so expiry stays a
            /// teardown then — the stall is the client's own body (§8).
            request_op_on_client: bool = false,
            /// The client's persistence ask (RFC 9112 §9), captured at
            /// routing; the render-time decision may still announce close
            /// (pressure, drain, §8).
            client_keep_alive: bool = false,
            /// What the rendered response told the client. The connection
            /// honors its own announcement: a keep-alive answer keeps
            /// serving, an announced close closes (§2).
            downstream_close_announced: bool = true,
            /// The origin's persistence verdict from its response head;
            /// parking requires it (§5).
            upstream_reusable: bool = false,
            /// The client sent bytes past the request's framing — a
            /// pipelined next request. Pipelining is unsupported: the
            /// exchange completes and the connection closes, dropping the
            /// early bytes (§2 note; clients recover per RFC).
            client_pipelined: bool = false,
            /// This try runs over a checked-out parked connection (§5) —
            /// the precondition for the §7 stale replay: only a *reused*
            /// connection's early failure is blamed on staleness.
            upstream_was_reused: bool = false,
            /// The request leg entered the body pump: relay-buffer chunks
            /// flowed and were overwritten, so the try is no longer
            /// reconstructible from conn.head — replay is off the table.
            request_body_pumped: bool = false,
            /// The one free replay is spent (§7): a failure on the replay
            /// try answers 502 like any other, never a second replay.
            replay_used: bool = false,

            pub const Leg = enum(u8) {
                idle,
                sending_head,
                awaiting_head,
                /// Forwarding body bytes that arrived coalesced with the
                /// head, sent straight from the head buffer (§7) so a body
                /// larger than a relay buffer is never copied through one.
                sending_body_excess,
                pumping_body,
                done,
            };

            /// The deferred verdicts: the §8 request-deadline 504 and the
            /// §7 stale-replay retry, both settled once the last armed
            /// data op is forced to completion.
            pub const PendingVerdict = enum(u8) {
                none,
                gateway_timeout,
                replay,
            };
        };

        pub const Direction = enum(u1) {
            client_to_upstream,
            upstream_to_client,
        };

        /// One bit per embedded op; release requires all clear (§5).
        pub const Armed = packed struct(u8) {
            data_client_to_upstream: bool = false,
            data_upstream_to_client: bool = false,
            connect: bool = false,
            connect_cancel: bool = false,
            close_client: bool = false,
            close_upstream: bool = false,
            deadline: bool = false,
            deadline_cancel: bool = false,
        };

        pub const Op = struct {
            completion: IoType.Completion = .{},
            generation_at_submit: u32 = 0,
        };

        /// Admission-time reset. `pool_next` and `generation` are owned
        /// by the pool and deliberately untouched. `buffer` is the L4
        /// relay buffer, or null on the L7 path (§5); `state` is the
        /// protocol's entry state (`.connecting` for L4, `.l7_reading_head`
        /// for L7).
        pub fn prepare(
            conn: *Self,
            server: *ServerType,
            client_socket: IoType.Socket,
            buffer: ?*relay.RelayBuffer,
            state: State,
            cluster_index: u16,
        ) void {
            assert(state == .connecting or state == .l7_reading_head or
                state == .tls_handshaking);
            conn.server = server;
            conn.state = state;
            conn.client_socket = client_socket;
            conn.upstream_socket = null;
            conn.relay_buffer = buffer;
            conn.tls = null; // admitTls checks one out after prepare.
            conn.deadline_ns = 0;
            conn.birth_ns = server.io.nowNs();
            conn.armed = .{};
            conn.directions = .{ .{}, .{} };
            conn.head_len = 0;
            conn.client_write = .{};
            conn.cluster_index = cluster_index;
            // Placeholders until the admission tail installs the
            // listener's real tables (§7); L4 never reads them.
            conn.routes = &.{};
            conn.filters = &.{};
            conn.upstream = null;
            conn.l7 = .{};
            conn.op_data_client_to_upstream = .{};
            conn.op_data_upstream_to_client = .{};
            conn.op_connect = .{};
            conn.op_connect_cancel = .{};
            conn.op_close_client = .{};
            conn.op_close_upstream = .{};
            conn.op_deadline = .{};
            conn.op_deadline_cancel = .{};
            assert(conn.state == state);
            assert(conn.armedCount() == 0);
            assert(conn.head_len == 0);
            assert(conn.client_write.pending.len == 0);
            assert(conn.upstream == null);
            assert(conn.l7.request_leg == .idle);
        }

        /// Records the arm in the op and the armed set; call immediately
        /// before submitting through the seam. Enforces the §8
        /// per-connection ring-op budget at the arm site — the CQ is
        /// sized as `conn_ops_max` per slot, so exceeding it here is the
        /// invariant violation the ring budget makes unreachable.
        pub fn arm(conn: *Self, op: *Op, comptime bit: []const u8) void {
            assert(!@field(conn.armed, bit));
            op.generation_at_submit = conn.generation;
            @field(conn.armed, bit) = true;
            assert(conn.armedCount() <= constants.conn_ops_max);
            // Test-only watermark: tracked wherever the budget assert
            // above is live (Debug, ReleaseSafe), never in the shipped
            // ReleaseFast build, so the hot path pays nothing in
            // production for what only a test reads.
            if (std.debug.runtime_safety) {
                conn.server.armed_ops_peak =
                    @max(conn.server.armed_ops_peak, conn.armedCount());
            }
        }

        /// Every delivery passes through here first: the generation
        /// recorded at submit must still match, and the bit must be set —
        /// a straggler into a recycled slot fails loudly (§5).
        pub fn delivered(conn: *Self, op: *const Op, comptime bit: []const u8) void {
            assert(op.generation_at_submit == conn.generation);
            assert(@field(conn.armed, bit));
            @field(conn.armed, bit) = false;
        }

        pub fn armedCount(conn: *const Self) u8 {
            return @popCount(@as(u8, @bitCast(conn.armed)));
        }
    };
}

test "direction: a framed chunk is owed until credited, then settled" {
    var state: DirectionState = .{};
    const buffer = "0123456789";

    state.owe(6);
    try std.testing.expectEqual(@as(u32, 6), state.owed());
    try std.testing.expectEqualStrings("012345", state.pending(buffer));

    // A short send: what is left is the tail, resumed from the credit.
    state.credit(2);
    try std.testing.expectEqual(@as(u32, 4), state.owed());
    try std.testing.expectEqualStrings("2345", state.pending(buffer));

    state.credit(4);
    try std.testing.expectEqual(@as(u32, 0), state.owed());
}

test "direction: a settled debt is the precondition for the next one" {
    var state: DirectionState = .{};
    state.owe(4);
    state.credit(4);
    try std.testing.expectEqual(@as(u32, 0), state.owed());

    // Only now may the next chunk be owed, and it starts from zero rather
    // than from where the last one ended — every framed chunk is its own
    // debt over the same buffer. `owe` asserts that settlement, so the
    // recv → send → recv discipline (§6) cannot be skipped quietly.
    state.owe(3);
    try std.testing.expectEqual(@as(u32, 3), state.owed());
    try std.testing.expectEqualStrings("abc", state.pending("abcdef"));
}

test "direction: framing may end a message owing nothing" {
    var state: DirectionState = .{};
    state.owe(0);
    // Nothing to forward, so nothing arms a send — `pending` asserts a
    // non-empty debt precisely because a zero one must not reach a send
    // (the seam's `bytes.len >= 1` contract, §4).
    try std.testing.expectEqual(@as(u32, 0), state.owed());
}
