//! Comptime-selected IO backend. The `IO` type *is* the portability seam — no
//! runtime `Reactor` vtable (see docs/DESIGN.md §2). The deterministic
//! simulator opts in by declaring `pub const zoxy_io = .simulation;` in its
//! root source file (src/sim.zig); everything else gets the OS backend.

const builtin = @import("builtin");
const root = @import("root");

const simulation = @hasDecl(root, "zoxy_io") and root.zoxy_io == .simulation;

const impl = if (simulation)
    @import("test_io.zig")
else switch (builtin.os.tag) {
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
pub const KernelTlsError = impl.KernelTlsError;

test {
    _ = impl;
}
