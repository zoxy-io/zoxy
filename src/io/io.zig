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
//!   connectCancel(io, connect_c, cancel_c, U, u, cb(u))  (teardown of a
//!       pending connect — a black-holed dial must still reach a terminal
//!       completion or its slot could never be released, §5)
//!   recv(io, socket, buffer, c, U, u, cb(u, RecvError!u32))
//!   send(io, socket, bytes, c, U, u, cb(u, SendError!u32))
//!   close(io, socket, c, U, u, cb(u))
//!   logWrite(io, bytes, c, U, u, cb(u, LogWriteError!u32))   (§8 access log)
//!   timerStart(io, c, delay_ns, U, u, cb(u, TimerError!void))
//!   timerCancel(io, timer_c, cancel_c, U, u, cb(u))     (the one legal cancel)
//!   signalWait(io, U, u, cb(u, Signal))                 (persistent waiter)
//!   setNodelay / setLingerRst (io, socket) SetOptionError!void   (sync)
//!   shutdown(io, socket, how) void                      (sync control op)
//!   closeNow(io, socket) void                           (sync; un-admitted sheds)
//!   peerAddress(io, socket) IpAddress                   (sync; who connected)
//!   nowNs(io) u64                                       (per-tick clock, §4)
//!   nowWallNs(io) u64                                   (epoch clock, §8 log)
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
    /// The bind address is not assigned to this host.
    AddressUnavailable,
    /// Privileged port without the capability, or similar permission wall.
    AccessDenied,
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
    /// The connection is gone and this write can never land: the peer's
    /// RST (ECONNRESET) *and* our own half-close (EPIPE) both arrive here.
    /// One case because they want one response — stop writing, tear down —
    /// and because keeping them apart tempted the send adapter into
    /// leaving EPIPE unnamed, where it fell through to `Unexpected` and
    /// spent months being counted as §8 kernel pressure.
    Reset,
    Canceled,
    Unexpected,
};

pub const TimerError = error{
    /// The one legal cancel: teardown (§4).
    Canceled,
};

/// The access-log sink's only failure (§8). One error rather than a set,
/// because there is exactly one response to any of them: the sink is
/// declared broken, the failure is counted, and further lines are dropped.
/// An operator's log pipe closing (EPIPE) and a full disk are the same
/// event to a proxy whose job is not to log — a distinction nobody could
/// act on differently from inside the loop.
pub const LogWriteError = error{
    Unexpected,
};

pub const SetOptionError = error{
    Unexpected,
};

/// Why the most recent op failed with `error.Unexpected`, as much as the
/// backend can tell (§8). `Unexpected` is the right shape for *control
/// flow* — no caller should switch on twenty errnos — but it is the wrong
/// shape for an operator, who needs to know whether to shed load or widen
/// a limit. This carries that answer alongside the error rather than
/// widening every error set with cases nobody branches on.
///
/// A backend-neutral cause rather than a raw errno because the numbers are
/// platform-specific and the *response* is not: "out of buffers" means the
/// same thing wherever it comes from. The raw errno rides along anyway, so
/// a cause of `.other` is still diagnosable.
pub const Pressure = struct {
    cause: Cause,
    /// The platform errno, or 0 when the backend could not supply one.
    /// Reported as a gauge so an `.other` is never a dead end.
    errno: u16,

    pub const Cause = enum {
        /// ENOBUFS — socket buffer memory. Shed load.
        out_of_buffers,
        /// ENOMEM — kernel allocation. Shed load.
        out_of_memory,
        /// EMFILE/ENFILE — the fd table, per-process or system-wide.
        /// Raise the limit; shedding does not help if the fds are leaked.
        fd_limit,
        /// EADDRNOTAVAIL — the ephemeral port range is exhausted. Widen
        /// the range or reuse connections; unrelated to memory.
        address_unavailable,
        /// Outside the set worth acting on differently. Not a failure to
        /// classify — read `errno` to see which one.
        other,
    };

    pub const none: Pressure = .{ .cause = .other, .errno = 0 };
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
            "connectCancel",
            "recv",
            "send",
            "close",
            "logWrite",
            "timerStart",
            "timerCancel",
            "signalWait",
            "setNodelay",
            "setLingerRst",
            "shutdown",
            "closeNow",
            "peerAddress",
            "lastPressure",
            "nowNs",
            "nowWallNs",
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
