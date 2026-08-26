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
//!   recvGroup(io, socket, c, U, u, cb(u, RecvGroupError!GroupRecv))
//!       (a recv that carries no buffer: the backend binds one from its
//!       provided-buffer group only when data arrives, so an armed idle
//!       socket pins no memory — §5's head-buffer ring rides on this)
//!   bufferGroupSlice(io, buffer_id) []u8               (sync; the bytes)
//!   bufferGroupReturn(io, buffer_id) void              (sync; no syscall)
//!   bufferGroupCount(io) u32                           (sync; the group's
//!       capacity — what the caller's own accounting must agree with)
//!   bufferGroupBytes(io) u32                           (sync; one buffer's
//!       size — what the caller's own limits must agree with)
//!   send(io, socket, bytes, c, U, u, cb(u, SendError!u32))
//!   close(io, socket, c, U, u, cb(u))
//!   logWrite(io, bytes, c, U, u, cb(u, LogWriteError!u32))   (§8 access log)
//!   logReopen(io) LogReopenError!void                   (sync; §8 rotation,
//!       file sink only — swap the sink fd between writes, never under one)
//!   timerStart(io, c, delay_ns, U, u, cb(u, TimerError!void))
//!   timerCancel(io, timer_c, cancel_c, U, u, cb(u))     (the one legal cancel)
//!   alarmStart(io, after_ns, exit_code) void            (sync; §8's drain
//!       watchdog — a deadline with no completion, so it survives a loop
//!       that has stopped delivering. Takes the process down itself.
//!       `after_ns` is at least a second: production is `alarm(2)`, whose
//!       granularity is whole seconds, and both sides enforce the floor so
//!       a caller cannot ask the simulator for a bound production would
//!       silently round.)
//!   alarmCancel(io) void                                (sync)
//!   signalWait(io, U, u, cb(u, Signal))                 (persistent waiter)
//!   setNodelay / setLingerRst (io, socket) SetOptionError!void   (sync)
//!   shutdown(io, socket, how) void                      (sync control op)
//!   closeNow(io, socket) void                           (sync; un-admitted sheds)
//!   peerAddress(io, socket) IpAddress                   (sync; who connected)
//!   localAddress(io, socket) IpAddress                  (sync; this end —
//!       what the peer connected *to*, §6's send-header destination)
//!   fillRandom(io, buffer) void                         (sync; key material —
//!       the OS CSPRNG in production, the scenario's seeded stream in the
//!       simulator, which is what makes a handshake replayable at all)
//!   lastPressure(io) Pressure                           (classified cause
//!       of the op just delivered, §8)
//!   nowNs(io) u64                                       (per-tick clock, §4)
//!   nowWallNs(io) u64                                   (epoch clock, §8 log)
//!   run(io) RunError!void, stop(io) void
//!   abort(io, code) void                                (give up on this
//!       process — a real exit in production, a recorded fact in the
//!       simulator, so the one path a caller takes when it cannot
//!       continue is not the one path no gate can enter, §8/#206)
//!   wantsOperatorDump(io) bool                          (whether a
//!       give-up should also spend the whole counter set on stderr)

const std = @import("std");

pub const SimIo = @import("SimIo.zig");
pub const XevIo = @import("XevIo.zig");

/// Signals the loop reacts to, delivered through the seam so the
/// simulator can inject drain as just another scheduled event (§4).
pub const Signal = enum(u8) {
    terminate,
    /// SIGHUP: reopen the access log's file sink (§8 rotation). This is
    /// the *only* meaning SIGHUP carries — zoxy does not reload config
    /// (§1 non-goal: the §5 pools are startup-fixed, so a config change
    /// is a restart), and claiming the signal for the log says so.
    reopen_log,
};

pub const ShutdownHow = enum(u8) {
    /// Force an armed *recv* to completion while the connection stays
    /// writable (#247). The write half is untouched, which is the whole
    /// point: a verdict that must answer cannot shut the socket it is
    /// answering on.
    read,
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

/// What a `recvGroup` delivers on success: the byte count and which of the
/// backend's provided buffers the bytes landed in. The id is the caller's
/// claim ticket — `bufferGroupSlice` to read, `bufferGroupReturn` to give
/// it back — and stays valid until returned.
pub const GroupRecv = struct {
    len: u32,
    buffer_id: u16,
};

/// `RecvError` plus the one failure a bufferless receive exists to report.
pub const RecvGroupError = error{
    EndOfStream,
    Reset,
    Canceled,
    /// Data arrived and the buffer group was empty. Backpressure, not a
    /// fault: the bytes are still in the socket, and the §8 answer is a
    /// shed — a caller that instead re-arms without returning a buffer
    /// first spins on the same bytes forever.
    NoBuffers,
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

/// The file sink's reopen failing (§8 rotation). One error for the same
/// reason `LogWriteError` has one: there is exactly one response — keep
/// the old fd, count `access_log_reopen_failed`, and keep writing where
/// the lines were already landing. A reopen can only be asked of a
/// `file` sink; the backends assert that, they do not error on it.
pub const LogReopenError = error{
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

/// The largest buffer one `fillRandom` may ask for. Linux's `getrandom`
/// promises short-read-free, uninterruptible service only up to 256 bytes;
/// rather than write a partial-fill loop no caller needs, the promise is a
/// precondition both backends assert. Key material comes a key at a time.
pub const random_bytes_max: u32 = 256;

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
            "recvGroup",
            "bufferGroupSlice",
            "bufferGroupReturn",
            "bufferGroupCount",
            "bufferGroupBytes",
            "send",
            "close",
            "logWrite",
            "logReopen",
            "timerStart",
            "timerCancel",
            "alarmStart",
            "alarmCancel",
            "signalWait",
            "setNodelay",
            "setLingerRst",
            "shutdown",
            "closeNow",
            "peerAddress",
            "localAddress",
            "fillRandom",
            "lastPressure",
            "nowNs",
            "nowWallNs",
            "run",
            "stop",
            "abort",
            "wantsOperatorDump",
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
