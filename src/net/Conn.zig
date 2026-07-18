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
const relay = @import("relay.zig");
const upstream_module = @import("upstream.zig");

const assert = std.debug.assert;

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
        /// The static error response still to be written to the client
        /// while in `.l7_responding` (§8): a slice into comptime static
        /// memory, shrunk from the front as bytes are sent. Empty
        /// otherwise; idle on the L4 path.
        response_pending: []const u8,
        /// The listener's cluster; the L7 path routes and dials after the
        /// head parses, long after admission (§7).
        cluster_index: u16,
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
            /// Length of the rendered head being sent (request leg: into
            /// upstream.head; response leg: into conn.head).
            rendered_request_len: u32 = 0,
            rendered_response_len: u32 = 0,
            /// Send cursors over the rendered heads (short sends resume).
            request_head_sent: u32 = 0,
            response_head_sent: u32 = 0,
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
        };

        pub const Direction = enum(u1) {
            client_to_upstream,
            upstream_to_client,
        };

        /// Strict recv → send → recv per direction (§6): exactly one data
        /// op in flight per direction, phase says which; per-connection
        /// memory stays constant regardless of stream size.
        pub const DirectionState = struct {
            phase: Phase = .idle,
            /// Bytes filled by the last recv.
            transfer_len: u32 = 0,
            /// Bytes of the transfer already sent (short sends resume).
            sent_len: u32 = 0,

            pub const Phase = enum(u8) { idle, receiving, sending, finished };
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
            assert(state == .connecting or state == .l7_reading_head);
            conn.server = server;
            conn.state = state;
            conn.client_socket = client_socket;
            conn.upstream_socket = null;
            conn.relay_buffer = buffer;
            conn.deadline_ns = 0;
            conn.birth_ns = server.io.nowNs();
            conn.armed = .{};
            conn.directions = .{ .{}, .{} };
            conn.head_len = 0;
            conn.response_pending = &.{};
            conn.cluster_index = cluster_index;
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
            assert(conn.response_pending.len == 0);
            assert(conn.upstream == null);
            assert(conn.l7.request_leg == .idle);
        }

        /// Records the arm in the op and the armed set; call immediately
        /// before submitting through the seam.
        pub fn arm(conn: *Self, op: *Op, comptime bit: []const u8) void {
            assert(!@field(conn.armed, bit));
            op.generation_at_submit = conn.generation;
            @field(conn.armed, bit) = true;
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
