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

const builtin = @import("builtin");
const std = @import("std");
/// Which libxev backend this build talks to. The platform's own choice
/// unless `-Dio-backend=epoll` asks otherwise — see build.zig, but the
/// short version is that io_uring and kqueue are different *models*
/// (completion versus readiness), each platform exercises exactly one,
/// and epoll is the only way to run the other one on a box that has
/// io_uring. Comptime, so a build is one backend and the conditionals
/// below fold away.
const xev_root = @import("xev");
const xev = switch (@import("io_options").backend) {
    .default => xev_root,
    .epoll => xev_root.Epoll,
};

const constants = @import("../constants.zig");
const Io = @import("io.zig");

const assert = std.debug.assert;
const posix = std.posix;
const linux = std.os.linux;

const XevIo = @This();

/// kqueue (macOS, local bench runs) dispatches `.close` ops — and the
/// access log's file writes — to a thread pool; io_uring performs both
/// inside the ring, so Linux never spawns a thread. Pool threads only
/// perform the blocking syscall; completion callbacks still run on the
/// loop thread, so the single-threaded discipline holds.
const needs_thread_pool = xev.backend != .io_uring;
/// Whether the provided-buffer group is the kernel's (a registered
/// buf_ring the fork's `recv_group` op selects from) or an app-side
/// emulation. Only io_uring has the real thing; everywhere else the
/// buffer binds at arm time — correct and testable on the macOS dev box,
/// but the idle-socket density win is the io_uring deployment's alone.
const uses_buf_ring = xev.backend == .io_uring;
/// The one buffer group this backend registers (§5's head-buffer ring).
const buffer_group_id: u16 = 0;

/// Whether cancelling an armed accept makes the backend deliver that
/// accept's completion.
///
/// Asked of the backend's own error set rather than of its name, because
/// the error set is the backend *stating* the answer: a backend that can
/// deliver a cancelled accept has `Canceled` in `AcceptError`, and one
/// that cannot does not. io_uring and kqueue both name it. epoll does
/// not — libxev implements its `.cancel` as `stop_completion`, which
/// drops the op without calling anything back, so a caller waiting for
/// its accept waits forever (#203) and the seam owes the delivery.
///
/// Keying this on `backend == .io_uring` instead was a real regression:
/// it put *kqueue* on the synthesized path, changing behaviour on a
/// shipped platform on the strength of an inference from epoll, and
/// macOS CI hung. The rule is now that this only ever changes what a
/// backend does when that backend has said, in its types, that it cannot
/// do the other thing.
///
/// What the error set promises is *conditional*, and `listenClose` pays
/// that condition: kqueue delivers the cancel only for an accept it has
/// already submitted. See `submitPending`, which is how it pays it.
const delivers_accept_cancel = reportsCanceled(xev.AcceptError);

/// Whether a libxev error set can report a cancelled op at all.
///
/// It is not universal, and that is the point of asking: io_uring and
/// kqueue both name `Canceled` on an accept, and epoll does not — its
/// accept has no cancel to report. Anything that maps such an error has
/// to ask rather than assume, or it fails to compile on the backend that
/// cannot.
fn reportsCanceled(comptime Set: type) bool {
    for (@typeInfo(Set).error_set.?) |candidate| {
        if (std.mem.eql(u8, candidate.name, "Canceled")) return true;
    }
    return false;
}

/// `Canceled` where the backend has it, `Unexpected` for everything else
/// — including, on a backend without it, the cancel that cannot arrive.
fn mapAcceptError(err: xev.AcceptError) Io.AcceptError {
    if (comptime reportsCanceled(xev.AcceptError)) {
        return switch (err) {
            error.Canceled => error.Canceled,
            else => error.Unexpected,
        };
    }
    return error.Unexpected;
}
/// Which door the OS CSPRNG is behind. Linux has the `getrandom` syscall;
/// Darwin publishes no stable syscall ABI, so `fillRandom` goes through
/// libSystem there. Keyed on the OS, not on `xev.backend` — the event
/// backend and the entropy source are unrelated choices.
const uses_getrandom_syscall = builtin.os.tag == .linux;
/// How many times `fillRandom` retries an interrupted `getrandom` before
/// declaring the entropy source broken. Generous: EINTR needs an unseeded
/// pool *and* a signal, so even one retry is already the unusual path.
const getrandom_attempts_max: u8 = 16;

/// The access-log sink's `stdout` arm (§8): the process's own stdout,
/// inherited, never opened and never closed — already one of the three
/// stdio descriptors `fdsRequired` reserves, so it costs nothing. The
/// `file` arm is `openLogSink`'s fd instead, counted by `fdsRequired`'s
/// `access_log_files` term.
pub const log_sink_stdout: posix.fd_t = 1;

loop: xev.Loop,
timer: xev.Timer,
notifier: xev.Async,
/// Where `logWrite` sends its bytes (§8): `log_sink_stdout`, or the file
/// fd the caller obtained from `openLogSink`. Held until `logReopen`
/// swaps it or the process exits — never closed under a write, which is
/// what the access log's swap-between-completions discipline guarantees.
log_sink_fd: posix.fd_t,
/// The path behind a `file` sink, or null for stdout — what `logReopen`
/// opens again at rotation (§8). Config-arena memory, process lifetime.
log_sink_path: ?[]const u8,
thread_pool: if (needs_thread_pool) xev_root.ThreadPool else void,
notifier_completion: xev.Completion,
signal_mask: std.atomic.Value(u8),
signal_callback: ?*const fn (?*anyopaque, Io.Signal) void,
signal_userdata: ?*anyopaque,
listeners: []ListenerEntry,
listeners_count: u16,
/// The classified cause of the most recent op failure (§8). Written by the
/// callback adapters from the forked `Completion.result_errno` just before
/// they hand `error.Unexpected` to the caller, and read by the witness in
/// the same callback — the loop is single-threaded and callbacks do not
/// nest, so "most recent" is "the one being delivered".
last_pressure: Io.Pressure,
/// The provided-buffer group's slab: `group_count × group_bytes`, arena-
/// allocated at init. On io_uring every buffer is published to the
/// registered buf_ring and the kernel owns selection; the app touches the
/// ring again only to return an id (a tail bump, no syscall).
group_slab: []u8,
group_count: u32,
group_bytes: u32,
group_br: if (uses_buf_ring) ?*align(std.heap.page_size_min) linux.io_uring_buf_ring else void,
group_mask: if (uses_buf_ring) u16 else void,
/// Emulation only (non-io_uring): the free ids as a stack, filled so the
/// pop order starts at 0 — the same lowest-first shape SimIo picks, so a
/// test reading ids behaves alike over all three backends.
group_free: if (uses_buf_ring) void else []u16,
group_free_len: if (uses_buf_ring) void else u32,
/// True from the delivery that handed an id out until its return — on
/// both arms. The kernel cannot observe a double return (it would just
/// republish the id and let two receives alias one buffer, silently), so
/// the seam tracks ownership itself and makes the corruption an assert.
group_checked_out: []bool,

pub const Socket = enum(i32) { _ };

pub const Listener = struct {
    index: u16,
};

/// Which libxev backend this build selected. Exported so a test can ask
/// the seam rather than re-deriving it from the platform: with
/// `-Dio-backend`, `@import("xev").backend` and the one `XevIo` actually
/// talks to are no longer the same answer.
pub const backend = xev.backend;

pub const Completion = xev.Completion;

const ListenerEntry = struct {
    fd: posix.socket_t,
    address: std.Io.net.IpAddress,
    armed_accept: ?*xev.Completion,
    cancel_completion: xev.Completion,
    open: bool,
    /// Who to tell when a `listenClose` orphans an armed accept, on the
    /// backends that will not tell them itself (`delivers_accept_cancel`).
    /// Type-erased because `accept` is generic over its userdata and this
    /// has to outlive that call — the seam owes the delivery, so the seam
    /// keeps what it needs to make it.
    orphan_callback: ?*const fn (*anyopaque, Io.AcceptError!Socket) void,
    orphan_userdata: ?*anyopaque,
};

/// `cq_entries` is the completion-queue depth to request for this
/// deployment (`constants.completionQueueDepthFor` of the effective config,
/// §8) — the io_uring backend sizes its ring to it; other backends ignore it.
pub fn init(
    io: *XevIo,
    arena: std.mem.Allocator,
    cq_entries: u32,
    /// Configured data-path listeners — the config's own count, *not*
    /// including the admin listener (§5). There is no compiled ceiling to
    /// size this against any more.
    ///
    /// The admin reservation is added here rather than asked of the
    /// caller, the same way `fdsRequired`, `inFlightOps` and
    /// `completionQueueDepthFor` all fold in `admin_listeners`
    /// internally. That is not tidiness: sizing this array to exactly the
    /// configured count leaves `Admin.start` — which binds through this
    /// same `listen` — with nowhere to go, and it fails as
    /// `AddressUnavailable`, which reads as a bad bind rather than a full
    /// table. Every admin-enabled deployment hits it, and nothing in the
    /// test suite would: `Server(XevIo)` is instantiated only by main.
    configured_listeners: u32,
    /// The provided-buffer group (§5's head-buffer ring): how many
    /// buffers, how wide each. Zero count is a group nobody registered —
    /// legal, and what an L4-only deployment gets; arming `recvGroup`
    /// against it is asserted misuse.
    buffer_group_count: u32,
    buffer_group_bytes: u32,
    /// The §8 access-log sink `logWrite` targets: `log_sink_stdout`, or
    /// the fd `openLogSink` returned. A parameter rather than opened here
    /// so the caller owning the config error report also owns the path.
    log_sink_fd: posix.fd_t,
    /// The path that fd came from — non-null exactly for a `file` sink —
    /// kept so `logReopen` can open it again at rotation (§8).
    log_sink_path: ?[]const u8,
) !void {
    assert(configured_listeners <= std.math.maxInt(u16) - constants.admin_listeners);
    // Stdout or a real opened file — never a sentinel, never closed-over.
    assert(log_sink_fd >= 0);
    // The path travels with exactly the fd that came from it: a file
    // sink's fd without its path would make `logReopen` unanswerable.
    assert((log_sink_path != null) == (log_sink_fd != log_sink_stdout));
    const listeners = configured_listeners + constants.admin_listeners;
    assert(listeners >= 1);
    if (comptime needs_thread_pool) {
        io.thread_pool = xev_root.ThreadPool.init(.{});
    }
    errdefer if (comptime needs_thread_pool) {
        io.thread_pool.shutdown();
        io.thread_pool.deinit();
    };
    io.loop = try initLoop(
        cq_entries,
        if (comptime needs_thread_pool) &io.thread_pool else null,
    );
    errdefer io.loop.deinit();
    io.notifier = try xev.Async.init();
    errdefer io.notifier.deinit();
    io.timer = try xev.Timer.init();
    errdefer io.timer.deinit();
    io.listeners = try arena.alloc(ListenerEntry, listeners);
    io.listeners_count = 0;
    io.log_sink_fd = log_sink_fd;
    io.log_sink_path = log_sink_path;
    io.last_pressure = Io.Pressure.none;
    io.notifier_completion = .{};
    io.signal_mask = std.atomic.Value(u8).init(0);
    io.signal_callback = null;
    io.signal_userdata = null;
    try io.initBufferGroup(arena, buffer_group_count, buffer_group_bytes);
    // cached_now is undefined until the first tick; ops armed before
    // run() (accepts, timers at startup) must see a sane clock.
    io.loop.update_now();
}

/// Set up the provided-buffer group: slab from the arena, published to a
/// kernel buf_ring on io_uring, to the app-side free stack elsewhere.
/// Split from `init` the way `initLoop` is — for the length limit, and
/// because the two backends' setup shares nothing but the slab.
fn initBufferGroup(io: *XevIo, arena: std.mem.Allocator, count: u32, bytes: u32) !void {
    assert(bytes >= 1);
    assert(count <= constants.buffer_group_entries_max);
    io.group_slab = try arena.alloc(u8, @as(usize, count) * bytes);
    // Deliberately not faulted in. The kernel consumes the ring FIFO, so
    // sustained load cycles every registered buffer and the slab converges
    // toward fully resident regardless — but it gets there by being
    // *used* (a small head faults only its buffer's first page), and an
    // idle or lightly loaded process keeps its pages unmapped. The
    // printed §5 total is a ceiling RSS approaches, not a startup floor,
    // and the bench holds it as one (IMPLEMENTATION_NOTES "lazy
    // fault-in").
    io.group_checked_out = try arena.alloc(bool, count);
    @memset(io.group_checked_out, false);
    io.group_count = count;
    io.group_bytes = bytes;
    if (comptime uses_buf_ring) {
        io.group_br = null;
        io.group_mask = 0;
        if (count == 0) return;
        const entries: u16 = @intCast(std.math.ceilPowerOfTwo(u32, count) catch unreachable);
        const br = linux.IoUring.setup_buf_ring(
            io.loop.ring.fd,
            entries,
            buffer_group_id,
            .{ .inc = false },
        ) catch |err| switch (err) {
            // EINVAL with known-good arguments: the kernel predates
            // IORING_REGISTER_PBUF_RING (5.19). No silent downgrade — a
            // deployment that asked for head buffers gets the density it
            // asked for or a refusal it can read at startup.
            error.ArgumentsInvalid => return error.BufferRingUnsupported,
            else => return err,
        };
        linux.IoUring.buf_ring_init(br);
        io.group_mask = linux.IoUring.buf_ring_mask(entries);
        var index: u16 = 0;
        while (index < count) : (index += 1) {
            linux.IoUring.buf_ring_add(br, io.sliceForId(index), index, io.group_mask, index);
        }
        linux.IoUring.buf_ring_advance(br, @intCast(count));
        io.group_br = br;
    } else {
        io.group_free = try arena.alloc(u16, count);
        var index: u32 = 0;
        // Filled descending so the stack pops lowest-first — the same
        // shape SimIo picks, so a test reading ids behaves alike over
        // every backend.
        while (index < count) : (index += 1) {
            io.group_free[index] = @intCast(count - 1 - index);
        }
        io.group_free_len = count;
    }
}

/// Build the event loop with zoxy's ring discipline (§3, §4, §8). Split
/// from `init` so the setup — the fast-ring flags, the deep CQ, and the
/// old-kernel degrade — stays under the function-length limit.
fn initLoop(cq_entries: u32, thread_pool: ?*xev_root.ThreadPool) !xev.Loop {
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
    // Request the completion queue this deployment needs
    // (IORING_SETUP_CQSIZE via the fork) rather than trusting the kernel's
    // default CQ = 2 × SQ to coincide with the budget: the caller passes
    // `completionQueueDepthFor` of the effective config, so a small
    // deployment gets a shallow ring and a c10k one the full 65536,
    // independent of the SQ. CQSIZE lands in 5.5, older than the 6.1 the
    // fast flags need, so it survives the plain-ring degrade below.
    assert(cq_entries <= constants.completion_queue_entries_max);
    const completion_queue_depth: u32 = if (comptime xev.backend == .io_uring)
        cq_entries
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
    if (comptime uses_buf_ring) {
        if (io.group_br) |br| {
            const entries: u16 = @intCast(std.math.ceilPowerOfTwo(u32, io.group_count) catch unreachable);
            linux.IoUring.free_buf_ring(io.loop.ring.fd, br, entries, buffer_group_id);
        }
    }
    for (io.listeners[0..io.listeners_count]) |*entry| {
        assert(!entry.open or entry.armed_accept == null);
        if (entry.open) {
            closeFd(entry.fd);
        }
    }
    io.timer.deinit();
    io.notifier.deinit();
    io.loop.deinit();
    if (comptime needs_thread_pool) {
        io.thread_pool.shutdown();
        io.thread_pool.deinit();
    }
}

pub fn listen(io: *XevIo, address: std.Io.net.IpAddress) Io.ListenError!Listener {
    assert(io.listeners_count <= io.listeners.len);
    if (io.listeners_count == io.listeners.len) {
        return error.AddressUnavailable;
    }
    const tcp = xev.TCP.init(address) catch return error.Unexpected;
    // SO_REUSEPORT before bind is what makes horizontal scale-out real
    // (§1, §3): N independent zoxy processes bind the same port and the
    // kernel load-balances new connections across them, with share-nothing
    // isolation at the process boundary. The intra-process accept imbalance
    // that made SO_REUSEPORT a liability in the previous iteration (§3)
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
        .orphan_callback = null,
        .orphan_userdata = null,
    };
    io.listeners_count += 1;
    return .{ .index = index };
}

pub fn listenerAddress(io: *const XevIo, listener: Listener) std.Io.net.IpAddress {
    const entry = io.listenerEntryConst(listener);
    assert(entry.open);
    return entry.address;
}

/// Hand the backend every op still queued, so an op armed during this
/// tick is one the backend has actually taken.
///
/// libxev submits at the top of a tick and never inside its callback
/// loop, so an accept armed from a callback is still queued when a
/// `listenClose` later in that same tick cancels it — and cancelling a
/// queued op only marks it dead: no completion, no callback, and a drain
/// waiting on that accept waits forever (#203). The admin plane arms
/// exactly that way, re-arming from `maybeFinish` in the same tick a
/// signal's `beginDrain` can close the listener in.
///
/// Safe to call from inside a callback, which is the whole point: this
/// fires no callbacks of its own — it is a syscall, not a tick — so it
/// cannot re-enter the caller mid-drain, the hazard that forces the
/// synthesized delivery in `listenClose` to be asynchronous.
fn submitPending(loop: *xev.Loop) void {
    // What a failed submit costs is the backend's to say, and they do not
    // say the same thing: io_uring fails before touching its queue, so
    // the ops are merely still queued — the state this path was in before
    // it called here at all — while kqueue says plainly that some events
    // may be lost. Neither is worse than not calling this, which is the
    // exposure #203 is, and both are exceptional by the backends' own
    // account. All but one: `CompletionQueueOvercommitted` is the §8
    // budget violated rather than a submit that did not happen, and it
    // panics for the same reason `run` panics on it.
    //
    // anyerror: that error exists only on io_uring's error set.
    loop.submit() catch |err| switch (@as(anyerror, err)) {
        error.CompletionQueueOvercommitted => @panic(
            "ring budget violated: completion queue overcommitted (DESIGN.md §8)",
        ),
        else => {},
    };
}

/// Sync listener close (drain, §8). The armed accept — if any — must be
/// reaped through an async cancel: an io_uring op holds its own file
/// reference, so closing the fd alone would leave the accept in flight
/// forever and the drain would never finish.
pub fn listenClose(io: *XevIo, listener: Listener) void {
    const entry = io.listenerEntry(listener);
    assert(entry.open);
    if (entry.armed_accept) |accept_completion| {
        if (comptime delivers_accept_cancel) {
            // What the backend promises about a cancelled accept it owes
            // only for an accept it has already taken (#203) — so make
            // sure it has taken this one before cancelling it.
            submitPending(&io.loop);
            loopCancel(
                &io.loop,
                accept_completion,
                &entry.cancel_completion,
                void,
                null,
                onCancelReaped,
            );
        } else {
            // The backend will not tell the caller, so the seam does —
            // on the next tick rather than from inside this call. A
            // synchronous callback here would re-enter the caller from
            // the middle of its own drain: `Server.beginDrain` closes
            // every listener in a loop, and the admin's accept callback
            // runs `maybeStopAfterDrain`, which may stop the loop. A
            // zero-delay timer keeps the delivery asynchronous, which is
            // the shape every caller is already written against.
            //
            // The listener's own cancel completion carries it: this arm
            // never submits a cancel, so it is free, and one delivery per
            // `listenClose` is exactly one use of it.
            entry.armed_accept = null;
            io.timer.run(
                &io.loop,
                &entry.cancel_completion,
                0,
                ListenerEntry,
                entry,
                onOrphanedAccept,
            );
        }
    }
    closeFd(entry.fd);
    entry.open = false;
}

/// Deliver the `Canceled` an armed accept is owed when its listener
/// closed and the backend dropped the op without a word (#203).
fn onOrphanedAccept(
    entry: ?*ListenerEntry,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Timer.RunError!void,
) xev.CallbackAction {
    // Nothing cancels this timer: it is armed once per `listenClose` and
    // the listener does not reopen.
    result catch unreachable;
    const listener_entry = entry.?;
    assert(listener_entry.armed_accept == null); // Cleared at the close.
    const callback = listener_entry.orphan_callback.?;
    const userdata = listener_entry.orphan_userdata.?;
    listener_entry.orphan_callback = null;
    listener_entry.orphan_userdata = null;
    callback(userdata, error.Canceled);
    return .disarm;
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
    if (comptime !delivers_accept_cancel) {
        // Kept only so `listenClose` can make the delivery the backend
        // will not. Erased through a shim rather than stored generically:
        // one entry serves every `accept` on this listener, and they all
        // share the caller's type.
        entry.orphan_userdata = userdata;
        entry.orphan_callback = (struct {
            fn erased(context: *anyopaque, result: Io.AcceptError!Socket) void {
                callback(@ptrCast(@alignCast(context)), result);
            }
        }).erased;
    }
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
            io_inner.recordPressure(accept_completion);
            callback(context.?, if (result) |conn|
                @as(Socket, @enumFromInt(conn.fd))
            else |err|
                mapAcceptError(err));
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
            const io_inner: *XevIo = @fieldParentPtr("loop", loop);
            io_inner.recordPressure(connect_completion);
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
                    // health logic (deferred) can tell them apart.
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
            const io_inner: *XevIo = @fieldParentPtr("loop", loop);
            io_inner.recordPressure(read_completion);
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

/// A recv that carries no buffer (§5's head-buffer ring). On io_uring the
/// fork's `recv_group` op lets the kernel bind one at delivery time; on
/// other backends the free stack binds one here at arm time — same
/// contract, no density win, which only the io_uring deployment claims.
pub fn recvGroup(
    io: *XevIo,
    socket: Socket,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.RecvGroupError!Io.GroupRecv) void,
) void {
    assert(io.group_count >= 1);
    if (comptime uses_buf_ring) {
        assert(io.group_br != null);
        completion.* = .{
            .op = .{ .recv_group = .{
                .fd = @intFromEnum(socket),
                .group_id = buffer_group_id,
                .max_len = io.group_bytes,
            } },
            .userdata = userdata,
            .callback = (struct {
                fn adapter(
                    context: ?*anyopaque,
                    loop: *xev.Loop,
                    inner: *xev.Completion,
                    result: xev.Result,
                ) xev.CallbackAction {
                    const io_inner: *XevIo = @fieldParentPtr("loop", loop);
                    io_inner.recordPressure(inner);
                    const typed: *Userdata = @ptrCast(@alignCast(context.?));
                    callback(typed, if (result.recv_group) |n| ok: {
                        // Bytes delivered ⇒ the kernel selected a buffer
                        // and said so in the cqe flags; trust its word
                        // over any assumption (the fork pins this).
                        const id = inner.bufferId() orelse unreachable;
                        assert(n >= 1);
                        assert(!io_inner.group_checked_out[id]);
                        io_inner.group_checked_out[id] = true;
                        break :ok Io.GroupRecv{ .len = @intCast(n), .buffer_id = id };
                    } else |err| switch (err) {
                        error.EOF => error.EndOfStream,
                        error.ConnectionResetByPeer => error.Reset,
                        error.Canceled => error.Canceled,
                        error.NoBuffers => error.NoBuffers,
                        else => error.Unexpected,
                    });
                    return .disarm;
                }
            }).adapter,
        };
        io.loop.add(completion);
    } else {
        io.recvGroupEmulated(socket, completion, Userdata, userdata, callback);
    }
}

/// The non-io_uring arm of `recvGroup`: bind a free buffer now and issue a
/// classic recv into it; with none free, deliver NoBuffers through a
/// zero-delay timer so exhaustion still arrives as a completion, never
/// re-entrantly from inside the arm call.
fn recvGroupEmulated(
    io: *XevIo,
    socket: Socket,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.RecvGroupError!Io.GroupRecv) void,
) void {
    if (io.group_free_len == 0) {
        io.timer.run(&io.loop, completion, 0, Userdata, userdata, (struct {
            fn adapter(
                context: ?*Userdata,
                loop: *xev.Loop,
                timer_completion: *xev.Completion,
                result: xev.Timer.RunError!void,
            ) xev.CallbackAction {
                _ = loop;
                _ = timer_completion;
                result catch @panic("zero-delay timer failed");
                callback(context.?, error.NoBuffers);
                return .disarm;
            }
        }).adapter);
        return;
    }
    io.group_free_len -= 1;
    const id = io.group_free[io.group_free_len];
    const tcp = xev.TCP.initFd(@intFromEnum(socket));
    tcp.read(&io.loop, completion, .{ .slice = io.sliceForId(id) }, Userdata, userdata, (struct {
        fn adapter(
            context: ?*Userdata,
            loop: *xev.Loop,
            read_completion: *xev.Completion,
            tcp_inner: xev.TCP,
            read_buffer: xev.ReadBuffer,
            result: xev.ReadError!usize,
        ) xev.CallbackAction {
            const io_inner: *XevIo = @fieldParentPtr("loop", loop);
            io_inner.recordPressure(read_completion);
            _ = tcp_inner;
            // The id rides back in the buffer itself: its offset in the
            // slab is the id, so nothing per-op has to store it.
            const bound: u16 = @intCast(@divExact(
                @intFromPtr(read_buffer.slice.ptr) - @intFromPtr(io_inner.group_slab.ptr),
                io_inner.group_bytes,
            ));
            callback(context.?, if (result) |n| ok: {
                assert(n >= 1);
                assert(!io_inner.group_checked_out[bound]);
                io_inner.group_checked_out[bound] = true;
                break :ok Io.GroupRecv{ .len = @intCast(n), .buffer_id = bound };
            } else |err| refund: {
                // No bytes ⇒ no consumption, matching the kernel twin:
                // the buffer goes back before the error is delivered.
                io_inner.group_free[io_inner.group_free_len] = bound;
                io_inner.group_free_len += 1;
                // anyerror: kqueue's ReadError has no ConnectionResetByPeer.
                break :refund switch (@as(anyerror, err)) {
                    error.EOF => error.EndOfStream,
                    error.ConnectionResetByPeer => error.Reset,
                    error.Canceled => error.Canceled,
                    else => error.Unexpected,
                };
            });
            return .disarm;
        }
    }).adapter);
}

/// The bytes behind a `GroupRecv.buffer_id`, valid until returned.
pub fn bufferGroupSlice(io: *XevIo, buffer_id: u16) []u8 {
    // Only the holder of a delivered id may read it — the same ownership
    // assert SimIo makes, backed here by the seam's own tracking.
    assert(io.group_checked_out[buffer_id]);
    return io.sliceForId(buffer_id);
}

fn sliceForId(io: *XevIo, buffer_id: u16) []u8 {
    assert(buffer_id < io.group_count);
    return io.group_slab[@as(usize, buffer_id) * io.group_bytes ..][0..io.group_bytes];
}

/// The group's capacity — what a caller's own in-use accounting must
/// agree with, asserted at the composition site rather than trusted.
pub fn bufferGroupCount(io: *const XevIo) u32 {
    return io.group_count;
}

/// One buffer's size, on the same asserted-not-trusted terms.
pub fn bufferGroupBytes(io: *const XevIo) u32 {
    return io.group_bytes;
}

/// Give a selected buffer back to the group: on io_uring two stores and an
/// atomic tail bump — no syscall — republishing the id to the kernel; on
/// the emulation, a push onto the free stack.
pub fn bufferGroupReturn(io: *XevIo, buffer_id: u16) void {
    assert(buffer_id < io.group_count);
    // A double return would republish the id and let two receives alias
    // one buffer — corruption the kernel delivers silently, so it must
    // die here instead.
    assert(io.group_checked_out[buffer_id]);
    io.group_checked_out[buffer_id] = false;
    if (comptime uses_buf_ring) {
        const br = io.group_br orelse unreachable;
        linux.IoUring.buf_ring_add(br, io.sliceForId(buffer_id), buffer_id, io.group_mask, 0);
        linux.IoUring.buf_ring_advance(br, 1);
    } else {
        assert(io.group_free_len < io.group_count);
        io.group_free[io.group_free_len] = buffer_id;
        io.group_free_len += 1;
    }
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
            const io_inner: *XevIo = @fieldParentPtr("loop", loop);
            io_inner.recordPressure(write_completion);
            _ = tcp_inner;
            _ = write_buffer;
            // anyerror: kqueue's WriteError has no ConnectionResetByPeer.
            callback(context.?, if (result) |n|
                @as(u32, @intCast(n))
            else |err| switch (@as(anyerror, err)) {
                error.ConnectionResetByPeer => error.Reset,
                // EPIPE. The peer is gone and this write can never land —
                // the same verdict as a reset, and emphatically not the §8
                // kernel-pressure rung it used to fall into. libxev maps
                // the errno for us (`.PIPE => error.BrokenPipe`); naming it
                // here is what was missing, and it made ordinary client
                // disconnects read as resource exhaustion.
                error.BrokenPipe => error.Reset,
                error.Canceled => error.Canceled,
                else => error.Unexpected,
            });
            return .disarm;
        }
    }).adapter);
}

/// Open the §8 access log's `file` sink: append-only, created if absent,
/// never truncated. `O_APPEND` rather than a positioned write, for two
/// reasons that both bite later if skipped: the ring's write op targets
/// the fd's own position (the fork submits offset −1), and append-only is
/// what makes an external copy-truncate rotation safe — every write lands
/// at the current end, wherever a rotation just put it. Standalone and
/// synchronous: one open at startup before the loop exists, under
/// src/io/ because fds are made only here (§4's boundary); the caller
/// owns the error report, since it owns the path the operator wrote.
pub fn openLogSink(path: []const u8) !posix.fd_t {
    assert(path.len >= 1);
    // 0644: the operator's tooling reads the log; only this process
    // writes it. The umask tightens it further if the deployment says so.
    return posix.openat(posix.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .APPEND = true,
        .CLOEXEC = true,
    }, 0o644);
}

/// Give back an `openLogSink` fd the caller will not write through.
///
/// A serving process never does — it holds its sink for the process's
/// life — so this exists for `--check` (#301), the one mode that opens
/// the sink solely to learn whether it opens. Asking it about the
/// inherited stdout is asserted misuse: that fd was not this seam's to
/// hand out and is not its to close.
pub fn closeLogSink(fd: posix.fd_t) void {
    assert(fd != log_sink_stdout);
    assert(fd >= 0);
    closeFd(fd);
}

/// Reopen the `file` sink at its configured path (§8 rotation): open the
/// new fd *first* — on failure the old one stays and the caller keeps
/// writing where lines were already landing — then close the old and
/// swap. Legal only between log writes: the caller (the access log's
/// swap-between-completions discipline) is what guarantees no in-flight
/// op holds the fd being closed. Asking this of a stdout sink is
/// asserted misuse — stdout has no path to reopen.
///
/// Deliberately synchronous on the live loop, unlike every data-path op
/// and unlike the rule `logWrite` states below — a priced exception, not
/// an oversight: rotation is operator-initiated and rare (per day, not
/// per request), the pair costs two metadata syscalls on the filesystem
/// the operator chose for their logs, and the async alternative is a
/// fork op (`IORING_OP_OPENAT` — the op union is closed, §4 pin policy)
/// plus a swap state machine, bought for an event that happens less
/// often than a health probe. What the trade accepts: a log directory on
/// a *hung* filesystem (NFS with a dead server) stalls the loop for the
/// open's duration at rotation time. An operator whose log directory can
/// hang has a deployment problem no proxy can absorb.
pub fn logReopen(io: *XevIo) Io.LogReopenError!void {
    const path = io.log_sink_path orelse unreachable;
    assert(io.log_sink_fd != log_sink_stdout);
    const new_fd = openLogSink(path) catch return error.Unexpected;
    assert(new_fd >= 0);
    closeFd(io.log_sink_fd);
    io.log_sink_fd = new_fd;
}

/// Write one batch of access-log bytes to the sink (§8). A ring op, not a
/// direct `write`: the sink is whatever the operator pointed stdout at, or
/// a file on whatever filesystem they named, and a pipe whose reader has
/// stalled — or a disk that is busy — would block the whole loop for as
/// long as it stays stalled, the one thing this proxy must never do. Through
/// the ring the kernel punts a would-block write to its own worker and the
/// loop keeps serving; the caller's staging buffer absorbs the interval and
/// drops when it cannot (§8's ladder, applied to logging).
///
/// `xev.File` rather than `xev.TCP`: the io_uring backend submits `send`
/// for a TCP write, which a non-socket fd answers with ENOTSOCK.
pub fn logWrite(
    io: *XevIo,
    bytes: []const u8,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.LogWriteError!u32) void,
) void {
    assert(bytes.len >= 1);
    const file = xev.File.initFd(io.log_sink_fd);
    file.write(&io.loop, completion, .{ .slice = bytes }, Userdata, userdata, (struct {
        fn adapter(
            context: ?*Userdata,
            loop: *xev.Loop,
            write_completion: *xev.Completion,
            file_inner: xev.File,
            write_buffer: xev.WriteBuffer,
            result: xev.WriteError!usize,
        ) xev.CallbackAction {
            const io_inner: *XevIo = @fieldParentPtr("loop", loop);
            // The sink's failures are not §8 kernel pressure and must not be
            // witnessed as it, but a classified cause left over from an
            // earlier op would be read as this one's — clear it, the same
            // honest reset `setNodelay` performs when it has no completion
            // to classify from.
            io_inner.recordPressure(write_completion);
            _ = file_inner;
            _ = write_buffer;
            callback(context.?, if (result) |n|
                @as(u32, @intCast(n))
            else |_|
                error.Unexpected);
            return .disarm;
        }
    }).adapter);
}

/// Who is on the other end of an accepted socket (§8 access log). A
/// `getpeername` rather than the sockaddr libxev's accept op fills:
/// that field is a bare `posix.sockaddr`, 16 bytes, so the kernel
/// truncates every IPv6 peer into it. One syscall per admitted connection
/// — against the accept's ring op, the `setNodelay` setsockopt, and the
/// dial that follows it, an unmeasurable addition on a path that runs once
/// per connection, never per request.
pub fn peerAddress(io: *XevIo, socket: Socket) std.Io.net.IpAddress {
    _ = io;
    return addressOf(@intFromEnum(socket), posix.system.getpeername);
}

/// This end of the pair: the address the peer connected *to*, which is
/// the destination a §6 send header states. Same syscall trade as
/// `peerAddress`, and asked at the one site that needs it rather than
/// stored — the socket is live for the whole call by construction.
pub fn localAddress(io: *XevIo, socket: Socket) std.Io.net.IpAddress {
    _ = io;
    return addressOf(@intFromEnum(socket), posix.system.getsockname);
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

/// The exit code the alarm handler will use, and whether `main` has
/// installed the handler that reads it. Module-level because a signal
/// handler takes no arguments: the whole point of this watchdog is that
/// nothing between the kernel and the exit is the loop's (#226).
var alarm_exit_code = std.atomic.Value(u8).init(0);
var alarm_handler_installed = std.atomic.Value(bool).init(false);

/// §8's drain watchdog (#226): a deadline that is not a completion.
///
/// Every other bound in this proxy is an op — `timerStart` submits one and
/// the loop delivers it — which makes them all useless against the one
/// failure they would most like to report. `Server.onDrainStuck` is a
/// timer, so a backend that has stopped delivering has stopped delivering
/// the thing that would have said so, and the process hangs with no
/// diagnostic (#203 was the shape; #206's simulator can strand it on
/// demand).
///
/// `alarm(2)` answers a different question: the kernel raises SIGALRM
/// whatever this process is doing, and the handler exits without ever
/// re-entering the loop. Coarse — whole seconds — which is right for a
/// backstop measured in them, and the informative report still comes from
/// `onDrainStuck` when the loop is alive to produce one.
pub fn alarmStart(io: *XevIo, after_ns: u64, exit_code: u8) void {
    _ = io;
    assert(exit_code != 0); // A give-up is never a success.
    assert(after_ns >= std.time.ns_per_s);
    // Without the handler, SIGALRM's default action terminates the
    // process silently — the hang would become a death with even less to
    // say than before. `main` installs it before the loop ever runs; a
    // caller arming this without one is a wiring bug, not a fallback.
    assert(alarm_handler_installed.load(.acquire));
    const seconds = (after_ns + std.time.ns_per_s - 1) / std.time.ns_per_s;
    assert(seconds >= 1);
    assert(seconds <= std.math.maxInt(c_uint));
    alarm_exit_code.store(exit_code, .release);
    _ = std.c.alarm(@intCast(seconds));
}

/// Disarm: the drain finished, so the watchdog has nothing left to watch.
/// `alarm(0)` cancels whatever was pending, which is exactly the contract.
pub fn alarmCancel(io: *XevIo) void {
    _ = io;
    alarm_exit_code.store(0, .release);
    _ = std.c.alarm(0);
}

/// Called by `main` once its SIGALRM handler is installed, so `alarmStart`
/// can refuse to arm a signal nothing is listening for.
pub fn alarmHandlerInstalled() void {
    alarm_handler_installed.store(true, .release);
}

/// The watchdog firing: one `write` and one `_exit`, both async-signal-
/// safe, and deliberately nothing else. The rich report — which plane is
/// stuck, which ops it is waiting on — belongs to `onDrainStuck`, which
/// runs in the loop and can read the state safely; reaching *here* means
/// the loop never got there, so all this can honestly say is that it
/// didn't.
///
/// The body lives on this side of the seam because `write` and `_exit`
/// are syscalls and those live here (§4); `main` owns only the sigaction
/// that points at it.
pub fn onAlarmFromHandler() noreturn {
    const message = "zoxy: drain watchdog fired, the event loop stopped " ++
        "delivering (DESIGN.md §8, #226)\n";
    _ = std.c.write(2, message.ptr, message.len);
    const code = alarm_exit_code.load(.acquire);
    // Armed with a non-zero code, so a zero here would mean the alarm
    // outlived its `alarmCancel` — exiting 0 on a wedged drain is the one
    // outcome worse than exiting late.
    std.c._exit(if (code == 0) 1 else code);
}

/// Async-signal-safe: an atomic bitmask store plus an eventfd write. One
/// of the two functions in the codebase legal to call from a sigaction
/// handler (§4) — `onAlarmFromHandler` is the other, and the pair differ
/// in the one way that matters: this hands the signal to the loop, that
/// one gives up on the loop entirely.
pub fn notifySignalFromHandler(io: *XevIo, signal: Io.Signal) void {
    _ = io.signal_mask.fetchOr(signalBit(signal), .release);
    io.notifier.notify() catch {};
}

/// The classified cause of the op currently being delivered (§8). Valid
/// only inside a completion callback: the adapters set it immediately
/// before invoking the caller, so anything reading it later sees a stale
/// answer. `Server.witnessKernelPressure` reads it in the callback, which
/// is the only place it means anything.
pub fn lastPressure(io: *const XevIo) Io.Pressure {
    return io.last_pressure;
}

/// Classify the completion's recorded errno into a cause the operator can
/// act on. The errno itself rides along, so a `.other` is still a lead
/// rather than a dead end.
///
/// `result_errno` comes from the audited fork (zoxy-io/libxev#2): libxev's
/// own mapping funnels every unnamed errno through `posix.unexpectedErrno`
/// and keeps nothing, so without that field this classification would have
/// no input at all.
fn recordPressure(io: *XevIo, completion: *const Completion) void {
    // io_uring only: `result_errno` is the audited fork's field, and the
    // fork touched only that backend. kqueue keeps macOS usable as a dev
    // box (§4) and must build, so it reports unclassified rather than
    // guessing — the same honest fallback `setNodelay` uses when it has no
    // completion to read. If macOS ever needs the classification, the
    // kqueue backend needs the field first.
    if (comptime xev.backend != .io_uring) {
        io.last_pressure = Io.Pressure.none;
        return;
    }
    const errno = completion.result_errno;
    io.last_pressure = .{
        .cause = switch (errno) {
            .NOBUFS => .out_of_buffers,
            .NOMEM => .out_of_memory,
            .MFILE, .NFILE => .fd_limit,
            .ADDRNOTAVAIL => .address_unavailable,
            else => .other,
        },
        .errno = @intFromEnum(errno),
    };
}

pub fn setNodelay(io: *XevIo, socket: Socket) Io.SetOptionError!void {
    const enable: i32 = 1;
    posix.setsockopt(
        @intFromEnum(socket),
        posix.IPPROTO.TCP,
        posix.TCP.NODELAY,
        std.mem.asBytes(&enable),
    ) catch {
        // Synchronous, so there is no completion to read: `setsockopt`
        // already mapped the errno to a Zig error and kept nothing either.
        // Reported as unclassified rather than guessed at.
        io.last_pressure = Io.Pressure.none;
        return error.Unexpected;
    };
}

comptime {
    // `recordPressure` reaches for a field only the io_uring backend has.
    // Pinning that here means a kqueue build fails at this assertion with
    // a reason, rather than at the field access with a bare "no field
    // named result_errno" three call layers away.
    if (xev.backend == .io_uring) {
        assert(@hasField(Completion, "result_errno"));
    }
}

pub fn setLingerRst(io: *XevIo, socket: Socket) Io.SetOptionError!void {
    const value: posix.linger = .{ .onoff = 1, .linger = 0 };
    posix.setsockopt(
        @intFromEnum(socket),
        posix.SOL.SOCKET,
        posix.SO.LINGER,
        std.mem.asBytes(&value),
    ) catch {
        // Same reasoning as `setNodelay`: synchronous, no completion, so
        // unclassified rather than guessed. Symmetric on purpose — today
        // the only caller swallows this error (§8 shedding never blocks),
        // but a future one that witnesses it must not read the *previous*
        // failure's cause.
        io.last_pressure = Io.Pressure.none;
        return error.Unexpected;
    };
}

pub fn shutdown(io: *XevIo, socket: Socket, how: Io.ShutdownHow) void {
    _ = io;
    const posix_how: i32 = switch (how) {
        .read => posix.SHUT.RD,
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

/// Key material for the TLS engine (§4): the OS CSPRNG, read here because
/// `src/io/` is the only place a raw syscall may live. Production
/// randomness is never derived from the clock or a seed — SimIo alone
/// substitutes a deterministic stream, and only so the simulator can
/// replay a handshake byte-for-byte (§9).
///
/// A CSPRNG that cannot answer is not a condition to degrade around, so
/// this panics rather than hand back weak key material: every caller is a
/// key or a nonce, and there is no such thing as serving one badly.
pub fn fillRandom(io: *XevIo, buffer: []u8) void {
    _ = io;
    assert(buffer.len > 0);
    assert(buffer.len <= Io.random_bytes_max);
    if (uses_getrandom_syscall) {
        // Bounded, per TIGER_STYLE: EINTR is only reachable before the
        // kernel pool is seeded, where the call blocks and a signal can cut
        // it short. A pool that stays unseeded across this many attempts is
        // a boot the proxy cannot serve from anyway.
        for (0..getrandom_attempts_max) |_| {
            const rc = linux.getrandom(buffer.ptr, buffer.len, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    // At or under `random_bytes_max` a seeded pool fills the
                    // whole request, so a short answer is a broken promise,
                    // not a case to loop around.
                    assert(rc == buffer.len);
                    return;
                },
                .INTR => continue,
                else => |err| std.debug.panic("getrandom failed: {t}", .{err}),
            }
        }
        std.debug.panic(
            "getrandom interrupted {d} times",
            .{getrandom_attempts_max},
        );
    } else {
        // Darwin publishes no stable syscall interface; libSystem's CSPRNG
        // is the supported door and cannot fail — it aborts internally
        // rather than return unseeded bytes, which is this function's own
        // policy already.
        std.c.arc4random_buf(buffer.ptr, buffer.len);
    }
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

/// Wall-clock nanoseconds since the Unix epoch, for the access log (§8) —
/// both a line's timestamp and, read again at the end, its duration.
///
/// A second clock beside `nowNs`, deliberately, and on the opposite side of
/// both of that one's trade-offs. It is *precise*, not coarse: `nowNs`
/// feeds second-scale deadlines where a millisecond granule is free, while
/// a duration quantized to the coarse granule would report 0 µs for every
/// request a loopback or LAN hop actually serves. And it is *not* cached
/// per tick: a cached read would give every request in one completion batch
/// the same start and end, which is the same failure a second time.
///
/// The cost is bounded by being rare — two vDSO reads per *logged request*,
/// against `nowNs`'s one per tick — and it is paid only when an operator
/// turned the log on. Deriving durations from a wall clock does mean an NTP
/// step lands in whichever line spans it; the saturating subtraction at the
/// call site keeps that a wrong number rather than a wrapped one.
pub fn nowWallNs(io: *XevIo) u64 {
    _ = io;
    var ts: posix.timespec = undefined;
    // The read stands on its own line, never inside the assert: an
    // assertion argument is not the place for the syscall the function
    // exists to make. CLOCK_REALTIME with a valid pointer has no failure
    // mode on a running kernel — EFAULT and EINVAL are both unreachable
    // from here — so the result is an invariant, asserted rather than
    // absorbed into a zero stamp that would date every line to 1970 and
    // report a fifty-year duration. Same shape as `shutdown` and `closeFd`:
    // the read goes through `posix.system`, so its return convention matches
    // the `posix.errno` that checks it — on kqueue that is libc's -1 sentinel,
    // on io_uring the raw kernel value. A bare `linux.clock_gettime` here
    // would pair a kernel-ABI return (a positive errno, never -1) with a
    // libc-ABI `posix.errno`, which reads .SUCCESS and lets a garbage
    // timespec through — the macOS live-gate panic of #184.
    const rc = posix.system.clock_gettime(posix.CLOCK.REALTIME, &ts);
    assert(posix.errno(rc) == .SUCCESS);
    assert(ts.sec >= 0);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s +
        @as(u64, @intCast(ts.nsec));
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

/// Always: this process's stderr is an operator's, and a give-up is the
/// last thing it will ever say. Only the simulator has a reason to answer
/// otherwise.
pub fn wantsOperatorDump(io: *const XevIo) bool {
    _ = io;
    return true;
}

/// Give up on this process: the caller has found a state it cannot
/// recover from and has already said what it was (§8's drain backstop is
/// the one caller). Behind the seam because a raw process exit is a
/// syscall, and those live here — but also because a caller that exits
/// directly can never be gated: the simulator would lose the process it
/// is running the scenario in, so the one path that matters would be the
/// one no test could enter.
///
/// Not `noreturn`, though this one never returns: the signature is the
/// seam's, and the simulator's implementation has to come back so the
/// scenario it is running can be asked what happened.
pub fn abort(io: *XevIo, code: u8) void {
    assert(code != 0); // A give-up is never a success.
    _ = io;
    std.process.exit(code);
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
    if (mask & signalBit(.reopen_log) != 0) {
        callback(io.signal_userdata, .reopen_log);
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
    const port = addressOf(fd, posix.system.getsockname).getPort();
    // Both failure modes land here as zero: a getsockname that did not
    // succeed, and a socket that is somehow still unbound. Neither is a
    // port a listener may serve on, and the caller's answer to both is
    // the same — refuse to start.
    if (port == 0) {
        return error.Unexpected;
    }
    return port;
}

/// What a socket reports for one end of its address pair, decoded into the
/// seam's address type. `getter` is `getsockname` or `getpeername`; the two
/// differ only in which end they name, and sharing the decode is what keeps
/// the family fork written once.
///
/// A failure yields `address_unknown` rather than an error: the only caller
/// that can fail meaningfully is `boundPort` (which reads the zero port
/// back as one), and the other — the access log — asks about a peer that
/// may already have reset, where "unknown" is the honest answer and there
/// is nothing an access-log line could do with an error anyway.
fn addressOf(fd: posix.socket_t, comptime getter: anytype) std.Io.net.IpAddress {
    var storage: posix.sockaddr.in6 = undefined;
    var length: posix.socklen_t = @sizeOf(posix.sockaddr.in6);
    const rc = getter(fd, @ptrCast(&storage), &length);
    if (posix.errno(rc) != .SUCCESS) {
        return address_unknown;
    }
    // sockaddr.in and sockaddr.in6 share the family/port prefix layout.
    const family_port: *const posix.sockaddr.in = @ptrCast(&storage);
    const port = std.mem.bigToNative(u16, family_port.port);
    if (family_port.family == posix.AF.INET) {
        assert(length >= @sizeOf(posix.sockaddr.in));
        return .{ .ip4 = .{
            .bytes = @bitCast(family_port.addr),
            .port = port,
        } };
    }
    assert(family_port.family == posix.AF.INET6);
    assert(length >= @sizeOf(posix.sockaddr.in6));
    // `fromIp6` unwraps an IPv4-mapped address back to the IPv4 one it
    // is, so a client reaching a dual-stack listener is logged as the
    // address it dialed from rather than as `::ffff:a.b.c.d`. The scope
    // is dropped: it names a local interface, not the peer.
    return .fromIp6(.{
        .port = port,
        .bytes = storage.addr,
        .flow = storage.flowinfo,
        .interface = .none,
    });
}

/// The answer when a socket cannot name an end of its pair. Distinguishable
/// in a log line — no real peer connects from port 0 — without needing an
/// optional at every consumer.
const address_unknown: std.Io.net.IpAddress = .{
    .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 },
};

fn closeFd(fd: posix.socket_t) void {
    const rc = posix.system.close(fd);
    const errno = posix.errno(rc);
    assert(errno == .SUCCESS or errno == .INTR);
}
