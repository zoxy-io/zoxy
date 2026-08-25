//! The stream slot (DESIGN.md §5): one *exchange*, drawn from a pool of
//! its own rather than inlined into the connection slot that carries it.
//!
//! Today a connection **is** an exchange — one request at a time, its
//! state inlined into `Conn` — and this slice (#274) draws the seam
//! without yet moving anything through it. Every admitted connection
//! acquires exactly one stream and holds it for the connection's life, so
//! the two pools have equal capacity and equal occupancy and nothing
//! observable changes. What it buys is §5's release rule and its
//! generation discipline replicated one layer down, proven under the
//! existing sweep before #173 puts N streams on a connection and makes
//! them load-bearing: a straggling completion into a recycled *stream* is
//! the same bug as one into a recycled slot, and it has to fail the same
//! way.
//!
//! The 1:1 cap is also what holds the ring budget still. `conn_ops_max`
//! becomes a conn share plus a stream share whose sum at one stream per
//! connection is exactly what it was, so the CQ ceiling and the printed
//! fd form do not move — an equality sharp enough that a changed banner
//! means the split took something with it that it should not have.

const std = @import("std");

const constants = @import("../constants.zig");

const assert = std.debug.assert;

/// `ConnType` is a parameter rather than an import, and that is load
/// bearing: `Conn` names this type for its own field, so importing back
/// would make the two generics mutually re-entrant — Zig memoizes an
/// instantiation only once it completes, so a cycle re-evaluates both
/// sides until the comptime branch quota gives out. `Conn` already
/// stands in one such cycle with `Server`; a third participant is what
/// makes it exponential. Passing the type in leaves exactly one
/// instantiation of each, and `Conn.StreamType` is the one name for it.
pub fn Stream(comptime IoType: type, comptime ConnType: type) type {
    return struct {
        /// Pool bookkeeping (`mem/Pool.zig`): owned by the pool, and
        /// deliberately untouched by `prepare` — the same rule
        /// `Conn.prepare` states about its own pair, and what makes the
        /// generation a straggler can be caught by survive a reset.
        pool_next: u32,
        generation: u32,
        /// The connection this stream runs on. Installed at acquisition
        /// and constant for the stream's life: a stream never migrates
        /// between connections here, and does not under #173 either —
        /// RFC 9113 identifiers are scoped to one connection.
        ///
        /// A back-pointer rather than a lookup because it is what the
        /// completion handlers will read. The Io seam takes a typed
        /// userdata pointer, so an op moved onto a stream (slice 2)
        /// arrives as `*Stream` and reaches everything else through
        /// exactly this field.
        conn: *ConnType,
        /// The exchange's armed set (§5). The connection's own deadline
        /// pair stays on `Conn`: a deadline is the *connection's* clock,
        /// and it outlives any one exchange on it. Everything here is the
        /// exchange's — the dial, its cancel, and the two data legs — so
        /// this is the set that has to empty before the stream slot goes
        /// back, one level below the rule that governs the conn slot.
        armed: Armed,
        op_data_client_to_upstream: Op,
        op_data_upstream_to_client: Op,
        op_connect: Op,
        op_connect_cancel: Op,

        const Self = @This();

        /// One bit per embedded op; the stream releases only with all
        /// clear, and its connection only once that has happened (§5).
        ///
        /// The peak is two, not four, and the disjointness is why: a dial
        /// and its cancel belong to `.connecting`/`.l7_dialing`, the data
        /// pair to `.relaying`/`.l7_exchanging`, and no state arms one
        /// kind while the other is outstanding. `constants.stream_ops_max`
        /// is that claim as a number, and `arm` below is where it fails if
        /// it is ever wrong.
        pub const Armed = packed struct(u4) {
            data_client_to_upstream: bool = false,
            data_upstream_to_client: bool = false,
            connect: bool = false,
            connect_cancel: bool = false,
        };

        /// The same shape `Conn.Op` has, and deliberately its own type:
        /// the generation recorded here is the *stream's*, so a straggler
        /// into a recycled stream trips `delivered` even when the
        /// connection under it was never recycled at all (§5).
        pub const Op = struct {
            completion: IoType.Completion = .{},
            generation_at_submit: u32 = 0,
        };

        /// Acquisition-time reset, mirroring `Conn.prepare`. The pool
        /// pair above stays untouched; everything else a stream will
        /// carry gets its value here as the fields arrive.
        pub fn prepare(stream: *Self, conn: *ConnType) void {
            stream.conn = conn;
            stream.armed = .{};
            stream.op_data_client_to_upstream = .{};
            stream.op_data_upstream_to_client = .{};
            stream.op_connect = .{};
            stream.op_connect_cancel = .{};
            assert(stream.armedCount() == 0);
        }

        /// Records the arm in the op and the armed set; call immediately
        /// before submitting through the seam. The mirror of `Conn.arm`,
        /// enforcing this half of the §8 ring budget at its own arm site:
        /// the CQ is sized as `conn_ops_max` per conn slot plus
        /// `stream_ops_max` per stream slot, so exceeding either here is
        /// the invariant violation the budget makes unreachable.
        pub fn arm(stream: *Self, op: *Op, comptime bit: []const u8) void {
            assert(!@field(stream.armed, bit));
            op.generation_at_submit = stream.generation;
            @field(stream.armed, bit) = true;
            assert(stream.armedCount() <= constants.stream_ops_max);
            // The combined per-connection peak, tracked at both arm sites
            // so it reads the same number it always did (§8): what the CQ
            // is charged for an admitted connection did not change when
            // the ops moved, and a peak that quietly grew would say the
            // split took something with it.
            if (std.debug.runtime_safety) {
                const server = stream.conn.server;
                server.armed_ops_peak = @max(
                    server.armed_ops_peak,
                    stream.conn.armedCount() + stream.armedCount(),
                );
                server.stream_armed_ops_peak =
                    @max(server.stream_armed_ops_peak, stream.armedCount());
            }
        }

        /// Every delivery passes through here first: the generation
        /// recorded at submit must still match, and the bit must be set —
        /// a straggler into a recycled stream fails loudly (§5).
        pub fn delivered(stream: *Self, op: *const Op, comptime bit: []const u8) void {
            assert(op.generation_at_submit == stream.generation);
            assert(@field(stream.armed, bit));
            @field(stream.armed, bit) = false;
        }

        pub fn armedCount(stream: *const Self) u8 {
            return @popCount(@as(u4, @bitCast(stream.armed)));
        }
    };
}
