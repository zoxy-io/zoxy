//! Deterministic simulation backend for the Io seam (DESIGN.md §4, §9):
//! virtual sockets, a virtual clock, and a seeded adversarial scheduler
//! running the real data path single-threaded with no real fds. All
//! nondeterminism flows from one PRNG, so a seed replays its exact
//! schedule byte for byte. The adversary delivers completions in
//! PRNG-permuted bounded batches without refreshing the clock mid-batch
//! (making §4's one-tick staleness adversarial by construction), splits
//! reads and writes down to one byte, delays/refuses/black-holes
//! connects, and injects resets between batches.
//!
//! Socket handles carry a generation; any use of a stale handle after
//! close trips an assertion — the §5 release rule enforced in the sim.

const std = @import("std");

const constants = @import("../constants.zig");
const Io = @import("Io.zig");
const Pool = @import("../mem/Pool.zig").Pool;

const assert = std.debug.assert;

const SimIo = @This();

const sockets_max: u16 = 1024;
const listeners_max: u16 = 32;
const accept_queue_max: u16 = 64;
const inbox_bytes: u32 = 4096;
const pending_ops_max: u32 = constants.in_flight_ops_max;
const pending_signals_max: u8 = 8;
/// The clock starts at one virtual second, not zero, so code that would
/// misbehave at t=0 gets caught.
const clock_start_ns: u64 = 1_000_000_000;
const jitter_ns_max: u64 = 1_000_000;
const never_ns: u64 = std.math.maxInt(u64);
const peer_none: u16 = std.math.maxInt(u16);
/// Ports the simulator hands out for port-zero binds.
const ephemeral_port_base: u16 = 40_000;

sockets: Pool(SocketEntry),
listeners: []ListenerEntry,
listeners_count: u16,
pending: []*Completion,
pending_count: u32,
pending_signals: [pending_signals_max]PendingSignal,
pending_signals_count: u8,
signal_callback: ?*const fn (?*anyopaque, Io.Signal) void,
signal_userdata: ?*anyopaque,
now_ns_value: u64,
prng: std.Random.DefaultPrng,
adversary: Adversary,
stopped: bool,
dump_on_deadlock: bool,
/// FNV-1a over every delivery; two runs of one seed must end equal (§9).
trace_hash: u64,
blackholed_addresses: [blackholed_addresses_max]std.Io.net.IpAddress,
blackholed_count: u8,

const blackholed_addresses_max: u8 = 4;

pub const Adversary = struct {
    /// Bias deliveries toward 1-byte and full-length reads/writes.
    partial_io: bool = true,
    connect_delay_ns_max: u64 = 0,
    connect_refuse_percent: u8 = 0,
    connect_blackhole_percent: u8 = 0,
    /// Chance per batch to reset one random live connection.
    reset_percent: u8 = 0,
    batch_max: u32 = constants.loop_completions_per_tick_max,
};

pub const Options = struct {
    seed: u64,
    adversary: Adversary = .{},
    /// Print pending-op forensics when a deadlock is detected. Tests
    /// that deliberately provoke a deadlock turn this off.
    dump_on_deadlock: bool = true,
};

pub const Socket = packed struct(u32) {
    index: u16,
    generation: u16,
};

pub const Listener = struct {
    index: u16,
};

pub const Completion = struct {
    op: Op = .none,
    ready_at_ns: u64 = 0,
    pending_index: u32 = 0,
    userdata: ?*anyopaque = null,
    callback: ErasedCallback = undefined,
    state: State = .dead,

    pub const State = enum(u8) { dead, pending };
};

const Op = union(enum) {
    none,
    accept: struct { listener_index: u16 },
    connect: struct { address: std.Io.net.IpAddress, fate: ConnectFate, canceled: bool },
    recv: struct { socket: Socket, buffer: []u8 },
    send: struct { socket: Socket, bytes: []const u8 },
    close: struct { socket: Socket },
    timer: struct { fire_at_ns: u64, canceled: bool },
    timer_cancel: struct { target: *Completion },
    connect_cancel: struct { target: *Completion },
};

const ConnectFate = enum(u8) { succeed, refuse, blackhole };

const Result = union(enum) {
    accept: Io.AcceptError!Socket,
    connect: Io.ConnectError!Socket,
    recv: Io.RecvError!u32,
    send: Io.SendError!u32,
    close: void,
    timer: Io.TimerError!void,
    timer_cancel: void,
    connect_cancel: void,
};

const ErasedCallback = *const fn (?*anyopaque, *const Result) void;
const ResultTag = std.meta.Tag(Result);

/// Builds the type-erased trampoline for an op whose completion carries a
/// value: it asserts the delivered Result matches `tag` and forwards the
/// projected value to the typed `callback`. Collapses the otherwise
/// identical per-op trampolines into one shape.
fn erasedResult(
    comptime Userdata: type,
    comptime tag: ResultTag,
    comptime callback: anytype,
) ErasedCallback {
    return (struct {
        fn erased(context: ?*anyopaque, result: *const Result) void {
            assert(result.* == tag);
            const userdata: *Userdata = @ptrCast(@alignCast(context.?));
            callback(userdata, @field(result.*, @tagName(tag)));
        }
    }).erased;
}

/// The trampoline for an op whose completion carries no value (close and
/// the two cancels): assert the tag, then invoke the value-less callback.
fn erasedVoid(
    comptime Userdata: type,
    comptime tag: ResultTag,
    comptime callback: anytype,
) ErasedCallback {
    return (struct {
        fn erased(context: ?*anyopaque, result: *const Result) void {
            assert(result.* == tag);
            const userdata: *Userdata = @ptrCast(@alignCast(context.?));
            callback(userdata);
        }
    }).erased;
}

const PendingSignal = struct {
    signal: Io.Signal,
    at_ns: u64,
};

const SocketEntry = struct {
    pool_next: u32,
    generation: u32,
    peer: u16,
    fin_received: bool,
    read_shutdown: bool,
    write_shutdown: bool,
    reset: bool,
    linger_rst: bool,
    nodelay: bool,
    inbox: Ring,
};

const ListenerEntry = struct {
    address: std.Io.net.IpAddress,
    active: bool,
    accept_queue: [accept_queue_max]Socket,
    accept_queue_len: u16,
    /// Injected kernel-pressure accept failures still to deliver
    /// (`injectAcceptError`) — the ENFILE-class path XevIo can hit but a
    /// virtual socket table never would.
    pending_accept_errors: u8,
    /// A socket whose accept "CQE" was already posted when the listener
    /// closed (§9: the drain race) — delivered to the armed accept as a
    /// success even though the listener is no longer active.
    raced_socket: ?Socket,
};

const Ring = struct {
    bytes: [inbox_bytes]u8,
    head: u32,
    count: u32,

    fn freeSpace(ring: *const Ring) u32 {
        assert(ring.count <= inbox_bytes);
        return inbox_bytes - ring.count;
    }

    fn push(ring: *Ring, source: []const u8) u32 {
        const n: u32 = @min(@as(u32, @intCast(source.len)), ring.freeSpace());
        assert(n <= source.len);
        var written: u32 = 0;
        while (written < n) : (written += 1) {
            ring.bytes[(ring.head + ring.count + written) % inbox_bytes] = source[written];
        }
        ring.count += n;
        assert(ring.count <= inbox_bytes);
        return n;
    }

    fn pop(ring: *Ring, target: []u8) u32 {
        const n: u32 = @min(@as(u32, @intCast(target.len)), ring.count);
        assert(n <= target.len);
        var read: u32 = 0;
        while (read < n) : (read += 1) {
            target[read] = ring.bytes[(ring.head + read) % inbox_bytes];
        }
        ring.head = (ring.head + n) % inbox_bytes;
        ring.count -= n;
        return n;
    }
};

/// In-place init; `arena` follows the production shape — this is the
/// simulator's only allocation point, everything after is zero-alloc.
pub fn init(io: *SimIo, arena: std.mem.Allocator, options: Options) error{OutOfMemory}!void {
    // Validate the adversary knobs at the misuse site: a bad value would
    // otherwise surface as an opaque arithmetic/uintLessThan panic deep in
    // a delivery, seeds away from the caller that set it.
    assert(@as(u16, options.adversary.connect_refuse_percent) +
        options.adversary.connect_blackhole_percent <= 100);
    assert(options.adversary.reset_percent <= 100);
    assert(options.adversary.batch_max >= 1);

    io.listeners = try arena.alloc(ListenerEntry, listeners_max);
    io.pending = try arena.alloc(*Completion, pending_ops_max);
    try io.sockets.init(arena, sockets_max);
    io.listeners_count = 0;
    io.pending_count = 0;
    io.pending_signals = undefined;
    io.pending_signals_count = 0;
    io.signal_callback = null;
    io.signal_userdata = null;
    io.now_ns_value = clock_start_ns;
    io.prng = std.Random.DefaultPrng.init(options.seed);
    io.adversary = options.adversary;
    io.stopped = false;
    io.dump_on_deadlock = options.dump_on_deadlock;
    io.trace_hash = std.hash.Fnv1a_64.init().value;
    io.blackholed_addresses = undefined;
    io.blackholed_count = 0;
    assert(io.sockets.isFullyReleased());
}

/// Targeted scenario control: every connect to this address black-holes
/// (never completes), regardless of the percent knobs. Directed tests
/// use this to pin one dial while the adversary stays off the harness's
/// own connects.
pub fn blackholeAddress(io: *SimIo, address: std.Io.net.IpAddress) void {
    assert(io.blackholed_count < blackholed_addresses_max);
    io.blackholed_addresses[io.blackholed_count] = address;
    io.blackholed_count += 1;
}

pub fn listen(io: *SimIo, address: std.Io.net.IpAddress) Io.ListenError!Listener {
    assert(io.listeners_count <= listeners_max);
    if (io.listeners_count == listeners_max) {
        return error.AddressUnavailable;
    }
    var effective = address;
    if (effective.getPort() == 0) {
        effective.setPort(ephemeral_port_base + io.listeners_count);
    }
    for (io.listeners[0..io.listeners_count]) |*existing| {
        if (existing.active and std.meta.eql(existing.address, effective)) {
            return error.AddressInUse;
        }
    }
    const index = io.listeners_count;
    io.listeners[index] = .{
        .address = effective,
        .active = true,
        .accept_queue = undefined,
        .accept_queue_len = 0,
        .pending_accept_errors = 0,
        .raced_socket = null,
    };
    io.listeners_count += 1;
    return .{ .index = index };
}

pub fn listenerAddress(io: *const SimIo, listener: Listener) std.Io.net.IpAddress {
    assert(listener.index < io.listeners_count);
    const entry = &io.listeners[listener.index];
    assert(entry.address.getPort() != 0);
    return entry.address;
}

/// Sync close of a listener (drain, §8): the armed accept — if any —
/// delivers `error.Canceled` on the next tick; queued-but-unaccepted
/// sockets are reset, as a kernel dropping its backlog would.
pub fn listenClose(io: *SimIo, listener: Listener) void {
    assert(listener.index < io.listeners_count);
    const entry = &io.listeners[listener.index];
    assert(entry.active);
    entry.active = false;
    // The drain race (§9): if an accept op is armed and a connection is
    // already queued, the kernel would have posted the accept CQE before
    // any cancel could land — that socket is *delivered*, not canceled.
    // The rest of the backlog resets, as a kernel dropping it would.
    var queue_start: u16 = 0;
    if (entry.accept_queue_len > 0 and io.hasArmedAccept(listener.index)) {
        assert(entry.raced_socket == null);
        entry.raced_socket = entry.accept_queue[0];
        queue_start = 1;
    }
    for (entry.accept_queue[queue_start..entry.accept_queue_len]) |queued| {
        io.closeEntryWithReset(queued);
    }
    entry.accept_queue_len = 0;
}

fn hasArmedAccept(io: *const SimIo, listener_index: u16) bool {
    for (io.pending[0..io.pending_count]) |completion| {
        switch (completion.op) {
            .accept => |op| if (op.listener_index == listener_index) return true,
            else => {},
        }
    }
    return false;
}

pub fn accept(
    io: *SimIo,
    listener: Listener,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.AcceptError!Socket) void,
) void {
    assert(completion.state == .dead);
    assert(listener.index < io.listeners_count);
    completion.* = .{
        .op = .{ .accept = .{ .listener_index = listener.index } },
        .userdata = userdata,
        .callback = erasedResult(Userdata, .accept, callback),
    };
    io.enqueue(completion);
}

pub fn connect(
    io: *SimIo,
    address: std.Io.net.IpAddress,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.ConnectError!Socket) void,
) void {
    assert(completion.state == .dead);
    const random = io.prng.random();
    const roll = random.uintLessThan(u8, 100);
    var fate: ConnectFate = .succeed;
    if (io.isBlackholed(address)) {
        fate = .blackhole;
    } else if (roll < io.adversary.connect_blackhole_percent) {
        fate = .blackhole;
    } else if (roll < io.adversary.connect_blackhole_percent + io.adversary.connect_refuse_percent) {
        fate = .refuse;
    }
    const delay_ns = if (io.adversary.connect_delay_ns_max == 0)
        0
    else
        random.uintAtMost(u64, io.adversary.connect_delay_ns_max);
    completion.* = .{
        .op = .{ .connect = .{ .address = address, .fate = fate, .canceled = false } },
        .ready_at_ns = if (fate == .blackhole) never_ns else io.now_ns_value + delay_ns,
        .userdata = userdata,
        .callback = erasedResult(Userdata, .connect, callback),
    };
    io.enqueue(completion);
}

pub fn recv(
    io: *SimIo,
    socket: Socket,
    buffer: []u8,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.RecvError!u32) void,
) void {
    assert(completion.state == .dead);
    assert(buffer.len >= 1);
    _ = io.socketEntry(socket);
    completion.* = .{
        .op = .{ .recv = .{ .socket = socket, .buffer = buffer } },
        .userdata = userdata,
        .callback = erasedResult(Userdata, .recv, callback),
    };
    io.enqueue(completion);
}

pub fn send(
    io: *SimIo,
    socket: Socket,
    bytes: []const u8,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.SendError!u32) void,
) void {
    assert(completion.state == .dead);
    assert(bytes.len >= 1);
    const entry = io.socketEntry(socket);
    assert(!entry.write_shutdown);
    completion.* = .{
        .op = .{ .send = .{ .socket = socket, .bytes = bytes } },
        .userdata = userdata,
        .callback = erasedResult(Userdata, .send, callback),
    };
    io.enqueue(completion);
}

pub fn close(
    io: *SimIo,
    socket: Socket,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata) void,
) void {
    assert(completion.state == .dead);
    _ = io.socketEntry(socket);
    completion.* = .{
        .op = .{ .close = .{ .socket = socket } },
        .userdata = userdata,
        .callback = erasedVoid(Userdata, .close, callback),
    };
    io.enqueue(completion);
}

pub fn timerStart(
    io: *SimIo,
    completion: *Completion,
    delay_ns: u64,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.TimerError!void) void,
) void {
    assert(completion.state == .dead);
    assert(delay_ns < never_ns - io.now_ns_value);
    completion.* = .{
        .op = .{ .timer = .{ .fire_at_ns = io.now_ns_value + delay_ns, .canceled = false } },
        .userdata = userdata,
        .callback = erasedResult(Userdata, .timer, callback),
    };
    io.enqueue(completion);
}

/// The one legal cancel (§4): the pending timer delivers error.Canceled,
/// the cancel op delivers through its own completion. Canceling an
/// already-fired timer is legal — the cancel still completes.
pub fn timerCancel(
    io: *SimIo,
    timer_completion: *Completion,
    cancel_completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata) void,
) void {
    assert(cancel_completion.state == .dead);
    assert(timer_completion != cancel_completion);
    if (timer_completion.state == .pending) {
        assert(timer_completion.op == .timer);
    }
    cancel_completion.* = .{
        .op = .{ .timer_cancel = .{ .target = timer_completion } },
        .userdata = userdata,
        .callback = erasedVoid(Userdata, .timer_cancel, callback),
    };
    io.enqueue(cancel_completion);
}

/// Teardown of a pending connect (§5): even a black-holed dial must
/// reach a terminal completion (error.Canceled), or the slot owning the
/// connect op could never be released. Canceling an already-completed
/// connect is legal — the cancel still delivers.
pub fn connectCancel(
    io: *SimIo,
    connect_completion: *Completion,
    cancel_completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata) void,
) void {
    assert(cancel_completion.state == .dead);
    assert(connect_completion != cancel_completion);
    if (connect_completion.state == .pending) {
        assert(connect_completion.op == .connect);
    }
    cancel_completion.* = .{
        .op = .{ .connect_cancel = .{ .target = connect_completion } },
        .userdata = userdata,
        .callback = erasedVoid(Userdata, .connect_cancel, callback),
    };
    io.enqueue(cancel_completion);
}

/// Persistent waiter: every delivered signal invokes the callback; it
/// stays armed. One waiter per loop (the Server).
pub fn signalWait(
    io: *SimIo,
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
}

pub fn setNodelay(io: *SimIo, socket: Socket) Io.SetOptionError!void {
    io.socketEntry(socket).nodelay = true;
}

pub fn setLingerRst(io: *SimIo, socket: Socket) Io.SetOptionError!void {
    io.socketEntry(socket).linger_rst = true;
}

pub fn shutdown(io: *SimIo, socket: Socket, how: Io.ShutdownHow) void {
    const entry = io.socketEntry(socket);
    if (!entry.write_shutdown) {
        entry.write_shutdown = true;
        if (entry.peer != peer_none) {
            io.peerEntry(entry).fin_received = true;
        }
    }
    if (how == .both) {
        entry.read_shutdown = true;
    }
}

/// Sync close for un-admitted sheds (§8): no slot, no completion, no ring
/// op. Honors a prior setLingerRst by resetting the peer.
pub fn closeNow(io: *SimIo, socket: Socket) void {
    io.closeEntry(socket);
}

pub fn nowNs(io: *SimIo) u64 {
    assert(io.now_ns_value >= clock_start_ns);
    return io.now_ns_value;
}

pub fn stop(io: *SimIo) void {
    io.stopped = true;
}

/// Schedule a signal delivery — drain is just another scheduled event (§4).
pub fn injectSignal(io: *SimIo, signal: Io.Signal) void {
    io.scheduleSignal(signal, io.now_ns_value);
}

/// Targeted scenario control: the next accept delivery on this listener
/// fails with error.Unexpected — the kernel-pressure (ENFILE-class) path
/// production can hit but a virtual socket table never would (§9).
pub fn injectAcceptError(io: *SimIo, listener: Listener) void {
    assert(listener.index < io.listeners_count);
    const entry = &io.listeners[listener.index];
    assert(entry.active);
    assert(entry.pending_accept_errors < std.math.maxInt(u8));
    entry.pending_accept_errors += 1;
}

pub fn scheduleSignal(io: *SimIo, signal: Io.Signal, at_ns: u64) void {
    assert(io.pending_signals_count < pending_signals_max);
    assert(at_ns >= io.now_ns_value);
    // A signal with no waiter can never be delivered: deliverDueSignals
    // would skip it while it still blocks the clean-exit return and pins
    // earliestWakeNs, tripping the wake assert in run() far from here.
    // Fail at the misuse site instead (the Server arms its waiter in
    // start(), so this holds in-tree).
    assert(io.signal_callback != null);
    io.pending_signals[io.pending_signals_count] = .{ .signal = signal, .at_ns = at_ns };
    io.pending_signals_count += 1;
}

/// Runs until every pending op has delivered, `stop` is called, or
/// nothing can ever become ready (Deadlock — a liveness bug, §9).
pub fn run(io: *SimIo) Io.RunError!void {
    io.stopped = false;
    // Hoisted out of the loop: collectReady overwrites the prefix it
    // returns, so the undefined init is never observed, and a ~32 KiB
    // buffer need not be re-stacked (and Debug-0xAA-filled) each tick.
    var ready_buffer: [pending_ops_max]*Completion = undefined;
    while (!io.stopped) {
        io.deliverDueSignals();
        const ready = io.collectReady(&ready_buffer);
        if (ready.len == 0) {
            if (io.pending_count == 0 and io.pending_signals_count == 0) {
                io.reclaimRacedSockets();
                return;
            }
            const wake_ns = io.earliestWakeNs();
            if (wake_ns == never_ns) {
                if (io.dump_on_deadlock) {
                    io.dumpPendingOps();
                }
                return error.Deadlock;
            }
            assert(wake_ns > io.now_ns_value);
            io.now_ns_value = wake_ns + io.prng.random().uintAtMost(u64, jitter_ns_max);
            continue;
        }
        io.deliverBatch(ready);
        io.maybeInjectReset();
    }
    // The loop was stopped (a completed drain). A raced accept whose CQE
    // beat the listener close but was never delivered before stop() is an
    // accepted-but-unshed fd — reclaimed at process exit in production, so
    // model that here rather than flagging it as an operational leak.
    io.reclaimRacedSockets();
}

fn reclaimRacedSockets(io: *SimIo) void {
    for (io.listeners[0..io.listeners_count]) |*entry| {
        if (entry.raced_socket) |socket| {
            entry.raced_socket = null;
            io.closeEntry(socket);
        }
    }
}

/// Deadlock forensics: what is stuck, on which socket, in which state.
fn dumpPendingOps(io: *const SimIo) void {
    std.debug.print("SimIo deadlock: {d} pending op(s) can never become ready\n", .{
        io.pending_count,
    });
    for (io.pending[0..io.pending_count]) |completion| {
        switch (completion.op) {
            .recv => |op| std.debug.print(
                "  recv socket={d} gen={d}\n",
                .{ op.socket.index, op.socket.generation },
            ),
            .send => |op| std.debug.print(
                "  send socket={d} gen={d} len={d}\n",
                .{ op.socket.index, op.socket.generation, op.bytes.len },
            ),
            .accept => |op| std.debug.print("  accept listener={d}\n", .{op.listener_index}),
            .connect => |op| std.debug.print("  connect fate={s}\n", .{@tagName(op.fate)}),
            else => std.debug.print("  {s}\n", .{@tagName(completion.op)}),
        }
    }
}

fn enqueue(io: *SimIo, completion: *Completion) void {
    assert(io.pending_count < pending_ops_max);
    assert(completion.op != .none);
    io.pending[io.pending_count] = completion;
    completion.pending_index = io.pending_count;
    completion.state = .pending;
    io.pending_count += 1;
}

fn unlink(io: *SimIo, completion: *Completion) void {
    assert(io.pending_count >= 1);
    const index = completion.pending_index;
    assert(io.pending[index] == completion);
    const last = io.pending[io.pending_count - 1];
    io.pending[index] = last;
    last.pending_index = index;
    io.pending_count -= 1;
    completion.state = .dead;
}

fn collectReady(io: *SimIo, buffer: []*Completion) []*Completion {
    assert(buffer.len >= io.pending_count);
    var count: u32 = 0;
    for (io.pending[0..io.pending_count]) |completion| {
        if (io.opReady(completion)) {
            buffer[count] = completion;
            count += 1;
        }
    }
    return buffer[0..count];
}

fn opReady(io: *SimIo, completion: *Completion) bool {
    assert(completion.state == .pending);
    return switch (completion.op) {
        .none => unreachable,
        .accept => |op| ready: {
            const entry = &io.listeners[op.listener_index];
            break :ready !entry.active or entry.accept_queue_len > 0 or
                entry.pending_accept_errors > 0;
        },
        .connect => |op| op.canceled or io.now_ns_value >= completion.ready_at_ns,
        .recv => |op| ready: {
            const entry = io.socketEntry(op.socket);
            break :ready entry.reset or entry.inbox.count > 0 or
                entry.read_shutdown or entry.fin_received;
        },
        .send => |op| ready: {
            const entry = io.socketEntry(op.socket);
            if (entry.reset or entry.write_shutdown or entry.peer == peer_none) {
                break :ready true;
            }
            break :ready io.peerEntry(entry).inbox.freeSpace() > 0;
        },
        .close, .timer_cancel, .connect_cancel => true,
        .timer => |op| op.canceled or io.now_ns_value >= op.fire_at_ns,
    };
}

fn deliverBatch(io: *SimIo, ready: []*Completion) void {
    assert(ready.len >= 1);
    const random = io.prng.random();
    const cap: u32 = @intCast(@min(ready.len, io.adversary.batch_max));
    const batch_len = 1 + random.uintLessThan(u32, cap);
    random.shuffle(*Completion, ready);
    // The clock deliberately does not advance inside the batch: every
    // callback sees the same, possibly stale, now (§4).
    for (ready[0..batch_len]) |completion| {
        if (completion.state != .pending) continue;
        if (!io.opReady(completion)) continue;
        io.deliverOne(completion);
    }
}

fn deliverOne(io: *SimIo, completion: *Completion) void {
    io.unlink(completion);
    const result: Result = switch (completion.op) {
        .none => unreachable,
        .accept => |op| .{ .accept = io.finishAccept(op.listener_index) },
        .connect => |op| .{
            .connect = if (op.canceled) error.Canceled else io.finishConnect(op.address, op.fate),
        },
        .recv => |op| .{ .recv = io.finishRecv(op.socket, op.buffer) },
        .send => |op| .{ .send = io.finishSend(op.socket, op.bytes) },
        .close => |op| close: {
            io.closeEntry(op.socket);
            break :close .{ .close = {} };
        },
        .timer => |op| .{ .timer = if (op.canceled) error.Canceled else {} },
        .timer_cancel => |op| cancel: {
            if (op.target.state == .pending) {
                assert(op.target.op == .timer);
                op.target.op.timer.canceled = true;
            }
            break :cancel .{ .timer_cancel = {} };
        },
        .connect_cancel => |op| cancel: {
            if (op.target.state == .pending) {
                assert(op.target.op == .connect);
                op.target.op.connect.canceled = true;
            }
            break :cancel .{ .connect_cancel = {} };
        },
    };
    io.traceMix(completion, &result);
    completion.callback(completion.userdata, &result);
}

fn finishAccept(io: *SimIo, listener_index: u16) Io.AcceptError!Socket {
    const entry = &io.listeners[listener_index];
    if (entry.raced_socket) |socket| {
        // The drain race: this accept's CQE beat the listener close.
        entry.raced_socket = null;
        return socket;
    }
    if (!entry.active) {
        return error.Canceled;
    }
    if (entry.pending_accept_errors > 0) {
        entry.pending_accept_errors -= 1;
        return error.Unexpected;
    }
    assert(entry.accept_queue_len >= 1);
    const socket = entry.accept_queue[0];
    std.mem.copyForwards(
        Socket,
        entry.accept_queue[0 .. entry.accept_queue_len - 1],
        entry.accept_queue[1..entry.accept_queue_len],
    );
    entry.accept_queue_len -= 1;
    return socket;
}

fn finishConnect(
    io: *SimIo,
    address: std.Io.net.IpAddress,
    fate: ConnectFate,
) Io.ConnectError!Socket {
    assert(fate != .blackhole);
    if (fate == .refuse) {
        return error.Refused;
    }
    const listener = io.findListener(address) orelse return error.Refused;
    if (listener.accept_queue_len == accept_queue_max) {
        return error.Refused;
    }
    const client_entry = io.sockets.acquire() orelse unreachable;
    const server_entry = io.sockets.acquire() orelse unreachable;
    initSocketEntry(client_entry);
    initSocketEntry(server_entry);
    client_entry.peer = @intCast(io.sockets.indexOf(server_entry));
    server_entry.peer = @intCast(io.sockets.indexOf(client_entry));
    listener.accept_queue[listener.accept_queue_len] = io.socketHandle(server_entry);
    listener.accept_queue_len += 1;
    return io.socketHandle(client_entry);
}

fn finishRecv(io: *SimIo, socket: Socket, buffer: []u8) Io.RecvError!u32 {
    const entry = io.socketEntry(socket);
    if (entry.reset) {
        return error.Reset;
    }
    if (entry.inbox.count > 0 and !entry.read_shutdown) {
        const available: u32 = @min(@as(u32, @intCast(buffer.len)), entry.inbox.count);
        const n = io.partialLen(available);
        const popped = entry.inbox.pop(buffer[0..n]);
        assert(popped == n);
        assert(n >= 1);
        return n;
    }
    assert(entry.read_shutdown or entry.fin_received);
    return error.EndOfStream;
}

fn finishSend(io: *SimIo, socket: Socket, bytes: []const u8) Io.SendError!u32 {
    const entry = io.socketEntry(socket);
    if (entry.reset) {
        return error.Reset;
    }
    if (entry.write_shutdown) {
        // A send that was already in flight when the teardown shut the
        // write side down (§2: shutdown flushes pending ops); the kernel
        // answers EPIPE.
        return error.Unexpected;
    }
    if (entry.peer == peer_none) {
        // The peer fully closed: real TCP answers a send with RST.
        entry.reset = true;
        return error.Reset;
    }
    const peer = io.peerEntry(entry);
    const free = peer.inbox.freeSpace();
    assert(free >= 1);
    const wanted: u32 = @min(@as(u32, @intCast(bytes.len)), free);
    const n = io.partialLen(wanted);
    const pushed = peer.inbox.push(bytes[0..n]);
    assert(pushed == n);
    assert(n >= 1);
    return n;
}

fn deliverDueSignals(io: *SimIo) void {
    if (io.signal_callback == null) return;
    var index: u8 = 0;
    while (index < io.pending_signals_count) {
        const pending_signal = io.pending_signals[index];
        if (pending_signal.at_ns <= io.now_ns_value) {
            io.pending_signals[index] = io.pending_signals[io.pending_signals_count - 1];
            io.pending_signals_count -= 1;
            io.mix(@as(u64, @intFromEnum(pending_signal.signal)) +% 0x5349474e);
            io.signal_callback.?(io.signal_userdata, pending_signal.signal);
        } else {
            index += 1;
        }
    }
}

fn earliestWakeNs(io: *const SimIo) u64 {
    var earliest: u64 = never_ns;
    for (io.pending[0..io.pending_count]) |completion| {
        const wake = switch (completion.op) {
            .connect => completion.ready_at_ns,
            .timer => |op| op.fire_at_ns,
            else => never_ns,
        };
        earliest = @min(earliest, wake);
    }
    for (io.pending_signals[0..io.pending_signals_count]) |pending_signal| {
        earliest = @min(earliest, pending_signal.at_ns);
    }
    return earliest;
}

fn maybeInjectReset(io: *SimIo) void {
    if (io.adversary.reset_percent == 0) return;
    const random = io.prng.random();
    if (random.uintLessThan(u8, 100) >= io.adversary.reset_percent) return;
    if (io.sockets.acquired_count == 0) return;

    var probe: u8 = 0;
    while (probe < 8) : (probe += 1) {
        const index = random.uintLessThan(u16, sockets_max);
        const entry = &io.sockets.slots[index];
        if (io.sockets.isAcquired(entry) and entry.peer != peer_none) {
            entry.reset = true;
            io.peerEntry(entry).reset = true;
            io.mix(@as(u64, index) +% 0x52535421);
            return;
        }
    }
}

fn partialLen(io: *SimIo, available: u32) u32 {
    assert(available >= 1);
    if (!io.adversary.partial_io) return available;
    const random = io.prng.random();
    return switch (random.uintLessThan(u8, 4)) {
        0 => 1,
        1, 2 => available,
        else => 1 + random.uintLessThan(u32, available),
    };
}

fn socketEntry(io: *SimIo, socket: Socket) *SocketEntry {
    assert(socket.index < sockets_max);
    const entry = &io.sockets.slots[socket.index];
    assert(io.sockets.isAcquired(entry));
    assert(@as(u16, @truncate(entry.generation)) == socket.generation);
    return entry;
}

fn peerEntry(io: *SimIo, entry: *const SocketEntry) *SocketEntry {
    assert(entry.peer != peer_none);
    assert(entry.peer < sockets_max);
    const peer = &io.sockets.slots[entry.peer];
    assert(io.sockets.isAcquired(peer));
    return peer;
}

fn socketHandle(io: *SimIo, entry: *SocketEntry) Socket {
    return .{
        .index = @intCast(io.sockets.indexOf(entry)),
        .generation = @truncate(entry.generation),
    };
}

fn isBlackholed(io: *const SimIo, address: std.Io.net.IpAddress) bool {
    for (io.blackholed_addresses[0..io.blackholed_count]) |blackholed| {
        if (std.meta.eql(blackholed, address)) {
            return true;
        }
    }
    return false;
}

fn findListener(io: *SimIo, address: std.Io.net.IpAddress) ?*ListenerEntry {
    for (io.listeners[0..io.listeners_count]) |*entry| {
        if (entry.active and std.meta.eql(entry.address, address)) {
            return entry;
        }
    }
    return null;
}

fn initSocketEntry(entry: *SocketEntry) void {
    entry.peer = peer_none;
    entry.fin_received = false;
    entry.read_shutdown = false;
    entry.write_shutdown = false;
    entry.reset = false;
    entry.linger_rst = false;
    entry.nodelay = false;
    entry.inbox.head = 0;
    entry.inbox.count = 0;
}

fn closeEntry(io: *SimIo, socket: Socket) void {
    const entry = io.socketEntry(socket);
    if (entry.peer != peer_none) {
        const peer = io.peerEntry(entry);
        // Unread inbox data or SO_LINGER-0 means the peer sees a reset,
        // exactly as real TCP behaves; otherwise an orderly FIN.
        if (entry.linger_rst or entry.inbox.count > 0) {
            peer.reset = true;
        } else {
            peer.fin_received = true;
        }
        peer.peer = peer_none;
    }
    io.sockets.release(entry);
}

fn closeEntryWithReset(io: *SimIo, socket: Socket) void {
    const entry = io.socketEntry(socket);
    entry.linger_rst = true;
    io.closeEntry(socket);
}

fn traceMix(io: *SimIo, completion: *const Completion, result: *const Result) void {
    io.mix(@intFromEnum(completion.op));
    io.mix(@intFromEnum(result.*));
    const detail: u64 = switch (result.*) {
        .recv => |r| if (r) |n| n else |err| 1000 + @intFromError(err),
        .send => |r| if (r) |n| n else |err| 2000 + @intFromError(err),
        .accept => |r| if (r) |s| @as(u32, @bitCast(s)) else |err| 3000 + @intFromError(err),
        .connect => |r| if (r) |s| @as(u32, @bitCast(s)) else |err| 4000 + @intFromError(err),
        .timer => |r| if (r) |_| 5000 else |err| 5001 + @intFromError(err),
        .close => 6000,
        .timer_cancel => 7000,
        .connect_cancel => 8000,
    };
    io.mix(detail);
}

fn mix(io: *SimIo, value: u64) void {
    // Fold each delivery into the run's trace hash. std's FNV-1a owns the
    // constants so a mistyped prime/basis can't silently degrade mixing;
    // the hash only ever compares a seed against itself, so the byte order
    // is immaterial.
    var hasher = std.hash.Fnv1a_64{ .value = io.trace_hash };
    hasher.update(std.mem.asBytes(&value));
    io.trace_hash = hasher.value;
}
