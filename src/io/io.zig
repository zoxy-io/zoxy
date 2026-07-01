//! Comptime-selected IO backend. The `IO` type *is* the portability seam — no
//! runtime `Reactor` vtable (see docs/DESIGN.md §2). Phase-0 is Linux-only;
//! `darwin.zig` (kqueue) and `test_io.zig` (deterministic mock) plug in here.

const builtin = @import("builtin");

const impl = switch (builtin.os.tag) {
    .linux => @import("linux.zig"),
    else => @compileError("zoxy currently supports Linux (io_uring) only"),
};

pub const IO = impl.IO;
pub const Completion = impl.Completion;

pub const AcceptError = impl.AcceptError;
pub const RecvError = impl.RecvError;
pub const SendError = impl.SendError;
pub const ConnectError = impl.ConnectError;
pub const CloseError = impl.CloseError;
pub const TimeoutError = impl.TimeoutError;
pub const CancelError = impl.CancelError;

test {
    _ = impl;
}
