//! The Io seam (DESIGN.md §4): the data path never names xev or an fd —
//! it is generic over a backend type that satisfies this contract
//! (`assertIoInterface`). Two backends exist: `XevIo` (production, libxev
//! on io_uring — slice 6) and `SimIo` (deterministic simulation: virtual
//! sockets, virtual clock, seeded adversarial scheduler — §9).
//!
//! Contract shape, mirrored by both backends (callbacks are comptime fn
//! parameters in last position and run to completion, §4):
//!
//!   Socket, Listener, Completion                        (types)
//!   listen(io, address) ListenError!Listener            (sync)
//!   listenerAddress(io, listener) IpAddress             (effective bound address)
//!   listenClose(io, listener) void                      (sync; cancels accept)
//!   accept(io, listener, c, U, u, cb(u, AcceptError!Socket))
//!   connect(io, address, c, U, u, cb(u, ConnectError!Socket))
//!   recv(io, socket, buffer, c, U, u, cb(u, RecvError!u32))
//!   send(io, socket, bytes, c, U, u, cb(u, SendError!u32))
//!   close(io, socket, c, U, u, cb(u))
//!   timerStart(io, c, delay_ns, U, u, cb(u, TimerError!void))
//!   timerCancel(io, timer_c, cancel_c, U, u, cb(u))     (the one legal cancel)
//!   signalWait(io, U, u, cb(u, Signal))                 (persistent waiter)
//!   setNodelay / setLingerRst (io, socket) SetOptionError!void   (sync)
//!   shutdown(io, socket, how) void                      (sync control op)
//!   closeNow(io, socket) void                           (sync; un-admitted sheds)
//!   nowNs(io) u64                                       (per-tick clock, §4)
//!   run(io) RunError!void, stop(io) void

const std = @import("std");

pub const SimIo = @import("SimIo.zig");
pub const XevIo = @import("XevIo.zig");

/// Signals the loop reacts to, delivered through the seam so the
/// simulator can inject drain as just another scheduled event (§4).
pub const Signal = enum(u8) {
    terminate,
    dump_counters,
};

pub const ShutdownHow = enum(u8) {
    write,
    both,
};

pub const ListenError = error{
    AddressInUse,
    AddressUnavailable,
    Unexpected,
};

pub const AcceptError = error{
    /// The listener was closed while the accept was armed (drain, §8).
    Canceled,
    Unexpected,
};

pub const ConnectError = error{
    Refused,
    Unreachable,
    Canceled,
    Unexpected,
};

pub const RecvError = error{
    /// Orderly FIN from the peer — half-close is a normal relay event (§6).
    EndOfStream,
    Reset,
    Canceled,
    Unexpected,
};

pub const SendError = error{
    Reset,
    Canceled,
    Unexpected,
};

pub const TimerError = error{
    /// The one legal cancel: teardown (§4).
    Canceled,
};

pub const SetOptionError = error{
    Unexpected,
};

pub const RunError = error{
    /// SimIo only: pending work exists but nothing can ever become ready —
    /// a liveness bug in the scenario or the data path (§9 invariant).
    Deadlock,
    Unexpected,
};

/// Comptime contract check: every backend passes through here at the
/// composition site, so a drifted backend fails to compile with a named
/// missing declaration instead of a template soup error.
pub fn assertIoInterface(comptime IoType: type) void {
    comptime {
        const required_decls = [_][]const u8{
            "Socket",
            "Listener",
            "Completion",
            "listen",
            "listenerAddress",
            "listenClose",
            "accept",
            "connect",
            "recv",
            "send",
            "close",
            "timerStart",
            "timerCancel",
            "signalWait",
            "setNodelay",
            "setLingerRst",
            "shutdown",
            "closeNow",
            "nowNs",
            "run",
            "stop",
        };
        for (required_decls) |decl_name| {
            if (!@hasDecl(IoType, decl_name)) {
                @compileError("Io backend " ++ @typeName(IoType) ++
                    " is missing required decl: " ++ decl_name);
            }
        }
    }
}

test "assertIoInterface: both backends satisfy the contract" {
    comptime assertIoInterface(SimIo);
    comptime assertIoInterface(XevIo);
}
