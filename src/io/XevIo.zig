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
const Io = @import("Io.zig");

const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;

const XevIo = @This();

loop: xev.Loop,
timer: xev.Timer,
notifier: xev.Async,
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
    io.loop = try xev.Loop.init(.{ .entries = constants.ring_entries });
    errdefer io.loop.deinit();
    io.notifier = try xev.Async.init();
    errdefer io.notifier.deinit();
    io.timer = try xev.Timer.init();
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
}

pub fn listen(io: *XevIo, address: std.Io.net.IpAddress) Io.ListenError!Listener {
    assert(io.listeners_count <= constants.listeners_max);
    if (io.listeners_count == constants.listeners_max) {
        return error.AddressUnavailable;
    }
    const tcp = xev.TCP.init(address) catch return error.Unexpected;
    tcp.bind(address) catch {
        closeFd(tcp.fd);
        return error.AddressInUse;
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
        io.loop.cancel(
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
                callback(context.?, switch (err) {
                    error.ConnectionRefused => error.Refused,
                    error.Canceled => error.Canceled,
                    else => error.Unexpected,
                });
            }
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
            callback(context.?, if (result) |n|
                @as(u32, @intCast(n))
            else |err| switch (err) {
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
            callback(context.?, if (result) |n|
                @as(u32, @intCast(n))
            else |err| switch (err) {
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
        linux.IPPROTO.TCP,
        linux.TCP.NODELAY,
        std.mem.asBytes(&enable),
    ) catch return error.Unexpected;
}

pub fn setLingerRst(io: *XevIo, socket: Socket) Io.SetOptionError!void {
    _ = io;
    const value: linux.linger = .{ .onoff = 1, .linger = 0 };
    posix.setsockopt(
        @intFromEnum(socket),
        linux.SOL.SOCKET,
        linux.SO.LINGER,
        std.mem.asBytes(&value),
    ) catch return error.Unexpected;
}

pub fn shutdown(io: *XevIo, socket: Socket, how: Io.ShutdownHow) void {
    _ = io;
    const linux_how: i32 = switch (how) {
        .write => linux.SHUT.WR,
        .both => linux.SHUT.RDWR,
    };
    const rc = linux.shutdown(@intFromEnum(socket), linux_how);
    const errno = posix.errno(rc);
    // NOTCONN: the peer tore the connection down first — a legal race.
    assert(errno == .SUCCESS or errno == .NOTCONN);
}

pub fn closeNow(io: *XevIo, socket: Socket) void {
    _ = io;
    closeFd(@intFromEnum(socket));
}

pub fn nowNs(io: *const XevIo) u64 {
    // libxev refreshes cached_now once per loop tick — exactly the §4
    // clock semantics; callbacks in one batch all see the same value.
    const cached = io.loop.cached_now;
    return @as(u64, @intCast(cached.sec)) * std.time.ns_per_s +
        @as(u64, @intCast(cached.nsec));
}

pub fn run(io: *XevIo) Io.RunError!void {
    io.loop.run(.until_done) catch |err| switch (err) {
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
    return @as(u8, 1) << @intFromEnum(signal);
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

fn boundPort(fd: posix.socket_t) error{Unexpected}!u16 {
    var bound: linux.sockaddr.in6 = undefined;
    var bound_len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    const rc = linux.getsockname(fd, @ptrCast(&bound), &bound_len);
    if (posix.errno(rc) != .SUCCESS) {
        return error.Unexpected;
    }
    // sockaddr.in and sockaddr.in6 share the family/port prefix layout.
    const family_port: *const linux.sockaddr.in = @ptrCast(&bound);
    assert(family_port.family == linux.AF.INET or family_port.family == linux.AF.INET6);
    return std.mem.bigToNative(u16, family_port.port);
}

fn closeFd(fd: posix.socket_t) void {
    const rc = linux.close(fd);
    const errno = posix.errno(rc);
    assert(errno == .SUCCESS or errno == .INTR);
}
