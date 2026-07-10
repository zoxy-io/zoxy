//! The connection slot (DESIGN.md §5): one contiguous object per
//! connection — state machine, embedded completions (one per
//! overlappable op, including both cancels), the stored absolute
//! deadline, and the armed-op set that gates release. A slot returns to
//! the pool only when `armed` is empty; every completion delivery
//! asserts the slot generation recorded at submit, so a straggler into
//! a recycled slot trips an assertion instead of corrupting memory.

const std = @import("std");

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
        upstream_socket: IoType.Socket,
        has_upstream: bool,
        closes_submitted: bool,
        relay_buffer: *relay.RelayBuffer,
        /// Absolute deadline; state transitions only store a new value —
        /// the armed timer op is never touched (§4).
        deadline_ns: u64,
        armed: Armed,

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
            tearing_down,
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
            conn.upstream_socket = undefined;
            conn.has_upstream = false;
            conn.closes_submitted = false;
            conn.relay_buffer = buffer;
            conn.deadline_ns = 0;
            conn.armed = .{};
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
