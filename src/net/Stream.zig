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

const assert = std.debug.assert;

/// `ConnType` is a parameter rather than an import, and that is load
/// bearing: `Conn` names this type for its own field, so importing back
/// would make the two generics mutually re-entrant — Zig memoizes an
/// instantiation only once it completes, so a cycle re-evaluates both
/// sides until the comptime branch quota gives out. `Conn` already
/// stands in one such cycle with `Server`; a third participant is what
/// makes it exponential. Passing the type in leaves exactly one
/// instantiation of each, and `Conn.StreamType` is the one name for it.
pub fn Stream(comptime ConnType: type) type {
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

        const Self = @This();

        /// Acquisition-time reset, mirroring `Conn.prepare`. The pool
        /// pair above stays untouched; everything else a stream will
        /// carry gets its value here as the fields arrive.
        pub fn prepare(stream: *Self, conn: *ConnType) void {
            stream.conn = conn;
        }
    };
}
