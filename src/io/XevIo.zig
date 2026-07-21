//! Production Io backend (DESIGN.md §4): thin adapters over libxev's
//! io_uring loop. Discipline enforced here, not hoped for elsewhere:
//! every callback returns `.disarm` and re-submission is always explicit
//! (except the internal signal wait, where `.rearm` is the documented
//! xev pattern); timer re-arm is a fresh run, never `.rearm` (stale
//! absolute expiry); timer cancel consumes its second caller-owned
//! completion; sockets stay *blocking* — libxev's deliberate io_uring
//! choice — so data I/O must go through the ring, and only the sync
//! control ops below touch the fd directly. `CompletionQueueOvercommitted`
//! is an invariant violation (§8: the budget makes it unreachable).

const std = @import("std");
const xev = @import("xev");

const constants = @import("../constants.zig");
const Io = @import("io.zig");

const assert = std.debug.assert;
const posix = std.posix;
const linux = std.os.linux;

const XevIo = @This();

/// kqueue (macOS, local bench runs) dispatches `.close` ops to a thread
/// pool — io_uring closes inside the ring, so Linux never spawns a thread.
/// Pool threads only perform the blocking syscall; completion callbacks
/// still run on the loop thread, so the single-threaded discipline holds.
const close_needs_thread_pool = xev.backend == .kqueue;

loop: xev.Loop,
timer: xev.Timer,
notifier: xev.Async,
thread_pool: if (close_needs_thread_pool) xev.ThreadPool else void,
notifier_completion: xev.Completion,
signal_mask: std.atomic.Value(u8),
signal_callback: ?*const fn (?*anyopaque, Io.Signal) void,
signal_userdata: ?*anyopaque,
listeners: []ListenerEntry,
listeners_count: u16,

pub const Socket = enum(i32) { _ };

pub const Listener = struct {
    index: u16,
};

pub const Completion = xev.Completion;

const ListenerEntry = struct {
    fd: posix.socket_t,
    address: std.Io.net.IpAddress,
    armed_accept: ?*xev.Completion,
    cancel_completion: xev.Completion,
    open: bool,
};

pub fn init(io: *XevIo, arena: std.mem.Allocator) !void {
    if (comptime close_needs_thread_pool) {
        io.thread_pool = xev.ThreadPool.init(.{});
    }
    errdefer if (comptime close_needs_thread_pool) {
        io.thread_pool.shutdown();
        io.thread_pool.deinit();
    };
    io.loop = try initLoop(
        if (comptime close_needs_thread_pool) &io.thread_pool else null,
    );
    errdefer io.loop.deinit();
    io.notifier = try xev.Async.init();
    errdefer io.notifier.deinit();
    io.timer = try xev.Timer.init();
    errdefer io.timer.deinit();
    io.listeners = try arena.alloc(ListenerEntry, constants.listeners_max);
    io.listeners_count = 0;
    io.notifier_completion = .{};
    io.signal_mask = std.atomic.Value(u8).init(0);
    io.signal_callback = null;
    io.signal_userdata = null;
    // cached_now is undefined until the first tick; ops armed before
    // run() (accepts, timers at startup) must see a sane clock.
    io.loop.update_now();
}

/// Build the event loop with zoxy's ring discipline (§3, §4, §8). Split
/// from `init` so the setup — the fast-ring flags, the deep CQ, and the
/// old-kernel degrade — stays under the function-length limit.
fn initLoop(thread_pool: ?*xev.ThreadPool) !xev.Loop {
    // SINGLE_ISSUER + COOP_TASKRUN + DEFER_TASKRUN: completion task-work
    // stays on the loop thread and is batched at the GETEVENTS reap point
    // instead of interrupting it (measured 2026-07-12: eliminates the
    // ~10.7% of loop cycles spent in interrupt-driven task_work at the
    // Tier-1 steady band, ~-3.4% loop CPU). Sound by construction here:
    // the loop thread is the only submitter (§3), and the loop only runs
    // .until_done, which always enters the kernel with GETEVENTS (the
    // fork's Options doc records that DEFER_TASKRUN contract). Kernels
    // older than 6.1 reject these flags with EINVAL; degrade to a plain
    // ring rather than refuse to start.
    const fast_ring_flags: u32 = if (comptime xev.backend == .io_uring)
        std.os.linux.IORING_SETUP_SINGLE_ISSUER |
            std.os.linux.IORING_SETUP_COOP_TASKRUN |
            std.os.linux.IORING_SETUP_DEFER_TASKRUN
    else
        0;
    // Request the completion queue we actually budget against
    // (IORING_SETUP_CQSIZE via the fork) rather than trusting the kernel's
    // default CQ = 2 × SQ to coincide: the §8 budgets — and `conn_slots_max`
    // — are derived from `completion_queue_entries`, so the ring must be
    // sized to it, not to twice the submission queue. Today the two are
    // equal (2 × 4096) so this is inert; it is the seam the c10k lift turns
    // on by raising `completion_queue_entries` past 2 × `ring_entries`.
    // CQSIZE lands in 5.5, older than the 6.1 the fast flags need, so it
    // survives the plain-ring degrade below.
    const completion_queue_depth: u32 = if (comptime xev.backend == .io_uring)
        constants.completion_queue_entries
    else
        0;
    // The fork requires a CQSIZE request to be at least the SQ depth (0
    // means "kernel default"); constants.zig comptime-asserts the ceiling.
    assert(completion_queue_depth == 0 or completion_queue_depth >= constants.ring_entries);
    return xev.Loop.init(.{
        .entries = constants.ring_entries,
        .io_uring_flags = fast_ring_flags,
        .cq_entries = completion_queue_depth,
        .thread_pool = thread_pool,
    }) catch |err| retry: {
        // Only the io_uring backend rejects these setup flags
        // (EINVAL -> ArgumentsInvalid on kernels < 6.1). On other
        // backends fast_ring_flags is 0 and Loop.init's error set has
        // no ArgumentsInvalid member, so this prong must be pruned at
        // comptime rather than referenced unconditionally. The deeper CQ
        // is kept on the retry — CQSIZE predates the flags that failed.
        if (comptime xev.backend == .io_uring) switch (err) {
            error.ArgumentsInvalid => break :retry try xev.Loop.init(.{
                .entries = constants.ring_entries,
                .cq_entries = completion_queue_depth,
                .thread_pool = thread_pool,
            }),
            else => {},
        };
        return err;
    };
}

/// Test-only teardown; production never exits except through drain.
pub fn deinit(io: *XevIo) void {
    for (io.listeners[0..io.listeners_count]) |*entry| {
        assert(!entry.open or entry.armed_accept == null);
        if (entry.open) {
            closeFd(entry.fd);
        }
    }
    io.timer.deinit();
    io.notifier.deinit();
    io.loop.deinit();
    if (comptime close_needs_thread_pool) {
        io.thread_pool.shutdown();
        io.thread_pool.deinit();
    }
}

pub fn listen(io: *XevIo, address: std.Io.net.IpAddress) Io.ListenError!Listener {
    assert(io.listeners_count <= constants.listeners_max);
    if (io.listeners_count == constants.listeners_max) {
        return error.AddressUnavailable;
    }
    const tcp = xev.TCP.init(address) catch return error.Unexpected;
    // SO_REUSEPORT before bind is what makes horizontal scale-out real
    // (§1, §3): N independent zoxy processes bind the same port and the
    // kernel load-balances new connections across them, with share-nothing
    // isolation at the process boundary. The intra-process accept imbalance
    // that made SO_REUSEPORT a liability in the previous iteration (§2)
    // cannot arise here — each process still has exactly one accepting loop,
    // so the kernel balances between processes, never between contending
    // loops. Must precede bind; libxev sets SO_REUSEADDR inside bind, so the
    // two options compose. On the io_uring kernels zoxy targets REUSEPORT is
    // always available, so a failure here is genuinely unexpected.
    const reuse: i32 = 1;
    posix.setsockopt(
        tcp.fd,
        posix.SOL.SOCKET,
        posix.SO.REUSEPORT,
        std.mem.asBytes(&reuse),
    ) catch {
        closeFd(tcp.fd);
        return error.Unexpected;
    };
    tcp.bind(address) catch |err| {
        closeFd(tcp.fd);
        // Distinct failures get distinct diagnoses: "address in use" sends
        // an operator hunting for a conflicting process, which is exactly
        // wrong for a missing host address or a privileged port.
        return switch (err) {
            error.AddressInUse => error.AddressInUse,
            error.AddressNotAvailable => error.AddressUnavailable,
            error.AccessDenied => error.AccessDenied,
            else => error.Unexpected,
        };
    };
    tcp.listen(constants.accept_backlog) catch {
        closeFd(tcp.fd);
        return error.Unexpected;
    };
    var effective = address;
    effective.setPort(boundPort(tcp.fd) catch {
        closeFd(tcp.fd);
        return error.Unexpected;
    });
    assert(effective.getPort() != 0);

    const index = io.listeners_count;
    io.listeners[index] = .{
        .fd = tcp.fd,
        .address = effective,
        .armed_accept = null,
        .cancel_completion = .{},
        .open = true,
    };
    io.listeners_count += 1;
    return .{ .index = index };
}

pub fn listenerAddress(io: *const XevIo, listener: Listener) std.Io.net.IpAddress {
    const entry = io.listenerEntryConst(listener);
    assert(entry.open);
    return entry.address;
}

/// Sync listener close (drain, §8). The armed accept — if any — must be
/// reaped through an async cancel: an io_uring op holds its own file
/// reference, so closing the fd alone would leave the accept in flight
/// forever and the drain would never finish.
pub fn listenClose(io: *XevIo, listener: Listener) void {
    const entry = io.listenerEntry(listener);
    assert(entry.open);
    if (entry.armed_accept) |accept_completion| {
        loopCancel(
            &io.loop,
            accept_completion,
            &entry.cancel_completion,
            void,
            null,
            onCancelReaped,
        );
    }
    closeFd(entry.fd);
    entry.open = false;
}

pub fn accept(
    io: *XevIo,
    listener: Listener,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.AcceptError!Socket) void,
) void {
    const entry = io.listenerEntry(listener);
    assert(entry.open);
    assert(entry.armed_accept == null);
    entry.armed_accept = completion;
    const tcp = xev.TCP.initFd(entry.fd);
    tcp.accept(&io.loop, completion, Userdata, userdata, (struct {
        fn adapter(
            context: ?*Userdata,
            loop: *xev.Loop,
            accept_completion: *xev.Completion,
            result: xev.AcceptError!xev.TCP,
        ) xev.CallbackAction {
            const io_inner: *XevIo = @fieldParentPtr("loop", loop);
            io_inner.clearArmedAccept(accept_completion);
            callback(context.?, if (result) |conn|
                @as(Socket, @enumFromInt(conn.fd))
            else |err| switch (err) {
                error.Canceled => error.Canceled,
                else => error.Unexpected,
            });
            return .disarm;
        }
    }).adapter);
}

pub fn connect(
    io: *XevIo,
    address: std.Io.net.IpAddress,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.ConnectError!Socket) void,
) void {
    const tcp = xev.TCP.init(address) catch {
        // Kernel pressure (§8): report as this op's failure, delivered
        // asynchronously via a zero-delay timer so callbacks never run
        // inline with submission.
        io.timer.run(&io.loop, completion, 0, Userdata, userdata, (struct {
            fn adapter(
                context: ?*Userdata,
                loop: *xev.Loop,
                timer_completion: *xev.Completion,
                result: xev.Timer.RunError!void,
            ) xev.CallbackAction {
                _ = loop;
                _ = timer_completion;
                result catch {};
                callback(context.?, error.Unexpected);
                return .disarm;
            }
        }).adapter);
        return;
    };
    tcp.connect(&io.loop, completion, address, Userdata, userdata, (struct {
        fn adapter(
            context: ?*Userdata,
            loop: *xev.Loop,
            connect_completion: *xev.Completion,
            socket: xev.TCP,
            result: xev.ConnectError!void,
        ) xev.CallbackAction {
            _ = loop;
            _ = connect_completion;
            if (result) |_| {
                callback(context.?, @as(Socket, @enumFromInt(socket.fd)));
            } else |err| {
                closeFd(socket.fd);
                // Widened to anyerror: each xev backend exposes a different
                // ConnectError set (io_uring says TimedOut, kqueue says
                // ConnectionTimedOut), and a switch may only name members.
                callback(context.?, switch (@as(anyerror, err)) {
                    error.ConnectionRefused => error.Refused,
                    // A routing failure and a dial timeout are both "the
                    // endpoint could not be reached" — distinct from
                    // kernel-pressure/unknown (Unexpected), so upstream
                    // health logic (deferred, docs/PLANS.md) can tell
                    // them apart.
                    error.HostUnreachable => error.Unreachable,
                    error.TimedOut, error.ConnectionTimedOut => error.Unreachable,
                    error.Canceled => error.Canceled,
                    else => error.Unexpected,
                });
            }
            return .disarm;
        }
    }).adapter);
}

/// Teardown of a pending connect (§5): IORING_OP_ASYNC_CANCEL on the
/// connect op, so even a black-holed dial reaches a terminal completion
/// (error.Canceled) and its slot can be released.
pub fn connectCancel(
    io: *XevIo,
    connect_completion: *Completion,
    cancel_completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata) void,
) void {
    loopCancel(&io.loop, connect_completion, cancel_completion, Userdata, userdata, (struct {
        fn adapter(
            context: ?*Userdata,
            loop: *xev.Loop,
            inner_completion: *xev.Completion,
            result: xev.CancelError!void,
        ) xev.CallbackAction {
            _ = loop;
            _ = inner_completion;
            // NotFound: the connect already completed — a legal race.
            result catch {};
            callback(context.?);
            return .disarm;
        }
    }).adapter);
}

pub fn recv(
    io: *XevIo,
    socket: Socket,
    buffer: []u8,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.RecvError!u32) void,
) void {
    assert(buffer.len >= 1);
    const tcp = xev.TCP.initFd(@intFromEnum(socket));
    tcp.read(&io.loop, completion, .{ .slice = buffer }, Userdata, userdata, (struct {
        fn adapter(
            context: ?*Userdata,
            loop: *xev.Loop,
            read_completion: *xev.Completion,
            tcp_inner: xev.TCP,
            read_buffer: xev.ReadBuffer,
            result: xev.ReadError!usize,
        ) xev.CallbackAction {
            _ = loop;
            _ = read_completion;
            _ = tcp_inner;
            _ = read_buffer;
            // anyerror: kqueue's ReadError has no ConnectionResetByPeer.
            callback(context.?, if (result) |n|
                @as(u32, @intCast(n))
            else |err| switch (@as(anyerror, err)) {
                error.EOF => error.EndOfStream,
                error.ConnectionResetByPeer => error.Reset,
                error.Canceled => error.Canceled,
                else => error.Unexpected,
            });
            return .disarm;
        }
    }).adapter);
}

pub fn send(
    io: *XevIo,
    socket: Socket,
    bytes: []const u8,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.SendError!u32) void,
) void {
    assert(bytes.len >= 1);
    const tcp = xev.TCP.initFd(@intFromEnum(socket));
    tcp.write(&io.loop, completion, .{ .slice = bytes }, Userdata, userdata, (struct {
        fn adapter(
            context: ?*Userdata,
            loop: *xev.Loop,
            write_completion: *xev.Completion,
            tcp_inner: xev.TCP,
            write_buffer: xev.WriteBuffer,
            result: xev.WriteError!usize,
        ) xev.CallbackAction {
            _ = loop;
            _ = write_completion;
            _ = tcp_inner;
            _ = write_buffer;
            // anyerror: kqueue's WriteError has no ConnectionResetByPeer.
            callback(context.?, if (result) |n|
                @as(u32, @intCast(n))
            else |err| switch (@as(anyerror, err)) {
                error.ConnectionResetByPeer => error.Reset,
                error.Canceled => error.Canceled,
                else => error.Unexpected,
            });
            return .disarm;
        }
    }).adapter);
}

pub fn close(
    io: *XevIo,
    socket: Socket,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata) void,
) void {
    const tcp = xev.TCP.initFd(@intFromEnum(socket));
    tcp.close(&io.loop, completion, Userdata, userdata, (struct {
        fn adapter(
            context: ?*Userdata,
            loop: *xev.Loop,
            close_completion: *xev.Completion,
            tcp_inner: xev.TCP,
            result: xev.CloseError!void,
        ) xev.CallbackAction {
            _ = loop;
            _ = close_completion;
            _ = tcp_inner;
            // Close failures carry no actionable signal; the fd is gone
            // either way.
            result catch {};
            callback(context.?);
            return .disarm;
        }
    }).adapter);
}

pub fn timerStart(
    io: *XevIo,
    completion: *Completion,
    delay_ns: u64,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.TimerError!void) void,
) void {
    // Round up: a deadline may fire late, never early (§4).
    const delay_ms = std.math.divCeil(u64, delay_ns, std.time.ns_per_ms) catch unreachable;
    io.timer.run(&io.loop, completion, delay_ms, Userdata, userdata, (struct {
        fn adapter(
            context: ?*Userdata,
            loop: *xev.Loop,
            timer_completion: *xev.Completion,
            result: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            _ = loop;
            _ = timer_completion;
            callback(context.?, if (result) |_| {} else |err| switch (err) {
                error.Canceled => error.Canceled,
                error.Unexpected => @panic("kernel timer op failed"),
            });
            return .disarm;
        }
    }).adapter);
}

pub fn timerCancel(
    io: *XevIo,
    timer_completion: *Completion,
    cancel_completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata) void,
) void {
    io.timer.cancel(&io.loop, timer_completion, cancel_completion, Userdata, userdata, (struct {
        fn adapter(
            context: ?*Userdata,
            loop: *xev.Loop,
            inner_completion: *xev.Completion,
            result: xev.Timer.CancelError!void,
        ) xev.CallbackAction {
            _ = loop;
            _ = inner_completion;
            // NotFound means the timer already fired — a legal race (§4).
            result catch {};
            callback(context.?);
            return .disarm;
        }
    }).adapter);
}

pub fn signalWait(
    io: *XevIo,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.Signal) void,
) void {
    assert(io.signal_callback == null);
    io.signal_userdata = userdata;
    io.signal_callback = (struct {
        fn erased(context: ?*anyopaque, signal: Io.Signal) void {
            callback(@ptrCast(@alignCast(context.?)), signal);
        }
    }).erased;
    io.notifier.wait(&io.loop, &io.notifier_completion, XevIo, io, onNotifierWake);
}

/// Async-signal-safe: an atomic bitmask store plus an eventfd write.
/// This is the only function in the codebase legal to call from a
/// sigaction handler (§4).
pub fn notifySignalFromHandler(io: *XevIo, signal: Io.Signal) void {
    _ = io.signal_mask.fetchOr(signalBit(signal), .release);
    io.notifier.notify() catch {};
}

pub fn setNodelay(io: *XevIo, socket: Socket) Io.SetOptionError!void {
    _ = io;
    const enable: i32 = 1;
    posix.setsockopt(
        @intFromEnum(socket),
        posix.IPPROTO.TCP,
        posix.TCP.NODELAY,
        std.mem.asBytes(&enable),
    ) catch return error.Unexpected;
}

pub fn setLingerRst(io: *XevIo, socket: Socket) Io.SetOptionError!void {
    _ = io;
    const value: posix.linger = .{ .onoff = 1, .linger = 0 };
    posix.setsockopt(
        @intFromEnum(socket),
        posix.SOL.SOCKET,
        posix.SO.LINGER,
        std.mem.asBytes(&value),
    ) catch return error.Unexpected;
}

pub fn shutdown(io: *XevIo, socket: Socket, how: Io.ShutdownHow) void {
    _ = io;
    const posix_how: i32 = switch (how) {
        .write => posix.SHUT.WR,
        .both => posix.SHUT.RDWR,
    };
    const rc = posix.system.shutdown(@intFromEnum(socket), posix_how);
    const errno = posix.errno(rc);
    // NOTCONN: the peer tore the connection down first — a legal race.
    assert(errno == .SUCCESS or errno == .NOTCONN);
}

pub fn closeNow(io: *XevIo, socket: Socket) void {
    _ = io;
    closeFd(@intFromEnum(socket));
}

pub fn nowNs(io: *XevIo) u64 {
    // The io_uring backend does NOT refresh cached_now each tick — the tick
    // only marks it `now_outdated` and refreshes lazily (in loop.now() or
    // when a timer is armed). Reading the field raw would return the time
    // of the last timer submission, arbitrarily stale, so deadlines set on
    // activity would never actually move (DESIGN.md §4). Refresh here when
    // stale — but with CLOCK_MONOTONIC_COARSE, not update_now()'s plain
    // CLOCK_MONOTONIC. Every consumer of this clock is a second-scale
    // deadline (idle/connect/drain/max-lifetime), so ~ms resolution is ample,
    // and the coarse read is a vvar-page vDSO load with no TSC access — the
    // flamegraph (§9) showed the monotonic read at ~7% of on-CPU under load,
    // and coarse is several times cheaper. Writing cached_now + clearing the
    // flag mirrors update_now() exactly, so the §4 once-per-tick invariant
    // still holds (every nowNs within a tick returns the same value) and
    // libxev's own timer_next shares this value for the rest of the tick; the
    // hash pin (build.zig.zon) fixes the field layout reached into. Coarse and
    // precise are the same monotonic timeline, so a tick that arms a timer
    // before any nowNs (update_now writes precise) then reads nowNs differs by
    // at most one coarse granule (~ms) — absorbed by second-scale deadlines
    // and the §4 lazy re-arm. The kqueue backend (macOS bench runs) has no
    // now_outdated flag: its tick refreshes cached_now, so raw is safe.
    if (comptime @hasField(@FieldType(xev.Loop, "flags"), "now_outdated")) {
        if (io.loop.flags.now_outdated) {
            var ts: linux.timespec = undefined;
            if (posix.errno(linux.clock_gettime(linux.CLOCK.MONOTONIC_COARSE, &ts)) == .SUCCESS) {
                io.loop.cached_now = ts;
                io.loop.flags.now_outdated = false;
            }
        }
    }
    const cached = io.loop.cached_now;
    return @as(u64, @intCast(cached.sec)) * std.time.ns_per_s +
        @as(u64, @intCast(cached.nsec));
}

pub fn run(io: *XevIo) Io.RunError!void {
    // anyerror: CompletionQueueOvercommitted exists only on io_uring.
    io.loop.run(.until_done) catch |err| switch (@as(anyerror, err)) {
        error.CompletionQueueOvercommitted => @panic(
            "ring budget violated: completion queue overcommitted (DESIGN.md §8)",
        ),
        else => return error.Unexpected,
    };
}

pub fn stop(io: *XevIo) void {
    io.loop.stop();
}

fn onNotifierWake(
    context: ?*XevIo,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.Async.WaitError!void,
) xev.CallbackAction {
    _ = loop;
    _ = completion;
    result catch @panic("signal eventfd wait failed");
    const io = context.?;
    const mask = io.signal_mask.swap(0, .acquire);
    const callback = io.signal_callback orelse return .rearm;
    if (mask & signalBit(.terminate) != 0) {
        callback(io.signal_userdata, .terminate);
    }
    if (mask & signalBit(.dump_counters) != 0) {
        callback(io.signal_userdata, .dump_counters);
    }
    // The internal signal wait is the one legitimate `.rearm`: an eventfd
    // read has no stale-time hazard, unlike timers.
    return .rearm;
}

/// Portable stand-in for the io_uring backend's `Loop.cancel` helper.
/// The kqueue backend (macOS, local bench runs) implements the same
/// `.cancel` op and `Result.cancel` plumbing but never grew the
/// convenience wrapper, so we build the completion by hand — the exact
/// body of io_uring's `Loop.cancel`.
fn loopCancel(
    loop: *xev.Loop,
    c: *xev.Completion,
    c_cancel: *xev.Completion,
    comptime Userdata: type,
    userdata: ?*Userdata,
    comptime cb: *const fn (
        ud: ?*Userdata,
        l: *xev.Loop,
        c: *xev.Completion,
        r: xev.CancelError!void,
    ) xev.CallbackAction,
) void {
    c_cancel.* = .{
        .op = .{
            .cancel = .{
                .c = c,
            },
        },
        .userdata = userdata,
        .callback = (struct {
            fn callback(
                ud: ?*anyopaque,
                l_inner: *xev.Loop,
                c_inner: *xev.Completion,
                r: xev.Result,
            ) xev.CallbackAction {
                return @call(.always_inline, cb, .{
                    @as(?*Userdata, if (Userdata == void) null else @ptrCast(@alignCast(ud))),
                    l_inner,
                    c_inner,
                    if (r.cancel) |_| {} else |err| err,
                });
            }
        }).callback,
    };
    loop.add(c_cancel);
}

fn onCancelReaped(
    context: ?*void,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.CancelError!void,
) xev.CallbackAction {
    _ = context;
    _ = loop;
    _ = completion;
    // NotFound: the accept completed before the cancel landed. Fine —
    // either way its CQE has been or will be delivered.
    result catch {};
    return .disarm;
}

fn signalBit(signal: Io.Signal) u8 {
    const shift: u3 = @intCast(@intFromEnum(signal));
    return @as(u8, 1) << shift;
}

fn clearArmedAccept(io: *XevIo, completion: *xev.Completion) void {
    for (io.listeners[0..io.listeners_count]) |*entry| {
        if (entry.armed_accept == completion) {
            entry.armed_accept = null;
            return;
        }
    }
    unreachable; // Every accept completion belongs to a listener entry.
}

fn listenerEntry(io: *XevIo, listener: Listener) *ListenerEntry {
    assert(listener.index < io.listeners_count);
    return &io.listeners[listener.index];
}

fn listenerEntryConst(io: *const XevIo, listener: Listener) *const ListenerEntry {
    assert(listener.index < io.listeners_count);
    return &io.listeners[listener.index];
}

/// Reads the kernel-assigned port back from an ephemeral bind. Handles
/// both address families (IPv4/IPv6 share the family/port prefix). Public
/// for the raw-libxev smoke test, which lives under src/io/ too.
pub fn boundPort(fd: posix.socket_t) error{Unexpected}!u16 {
    var bound: posix.sockaddr.in6 = undefined;
    var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in6);
    const rc = posix.system.getsockname(fd, @ptrCast(&bound), &bound_len);
    if (posix.errno(rc) != .SUCCESS) {
        return error.Unexpected;
    }
    // sockaddr.in and sockaddr.in6 share the family/port prefix layout.
    const family_port: *const posix.sockaddr.in = @ptrCast(&bound);
    assert(family_port.family == posix.AF.INET or family_port.family == posix.AF.INET6);
    return std.mem.bigToNative(u16, family_port.port);
}

fn closeFd(fd: posix.socket_t) void {
    const rc = posix.system.close(fd);
    const errno = posix.errno(rc);
    assert(errno == .SUCCESS or errno == .INTR);
}
