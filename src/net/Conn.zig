//! The connection slot (DESIGN.md §5): one contiguous object per
//! connection — state machine, embedded completions (one per
//! overlappable op, including both cancels), the stored absolute
//! deadline, and the armed-op set that gates release. A slot returns to
//! the pool only when `armed` is empty; every completion delivery
//! asserts the slot generation recorded at submit, so a straggler into
//! a recycled slot trips an assertion instead of corrupting memory.

const std = @import("std");

const constants = @import("../constants.zig");
const relay = @import("relay.zig");

const assert = std.debug.assert;

pub fn Conn(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);

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
        relay_buffer: *relay.RelayBuffer,
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
            connecting,
            relaying,
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
        /// by the pool and deliberately untouched.
        pub fn prepare(
            conn: *Self,
            server: *ServerType,
            client_socket: IoType.Socket,
            buffer: *relay.RelayBuffer,
        ) void {
            conn.server = server;
            conn.state = .connecting;
            conn.client_socket = client_socket;
            conn.upstream_socket = null;
            conn.relay_buffer = buffer;
            conn.deadline_ns = 0;
            conn.birth_ns = server.io.nowNs();
            conn.armed = .{};
            conn.directions = .{ .{}, .{} };
            conn.head_len = 0;
            conn.op_data_client_to_upstream = .{};
            conn.op_data_upstream_to_client = .{};
            conn.op_connect = .{};
            conn.op_connect_cancel = .{};
            conn.op_close_client = .{};
            conn.op_close_upstream = .{};
            conn.op_deadline = .{};
            conn.op_deadline_cancel = .{};
            assert(conn.state == .connecting);
            assert(conn.armedCount() == 0);
            assert(conn.head_len == 0);
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
