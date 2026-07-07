//! Deterministic simulation IO backend (docs/DESIGN.md: "swappable IO ->
//! deterministic testing"; TigerBeetle's VOPR idea). Same API surface as the
//! io_uring backend, but nothing touches the kernel: sockets are in-memory
//! byte pipes, the clock is virtual, and every completion is chosen by a
//! seeded PRNG — one pending operation at a time, with adversarial partial
//! reads and writes. A given seed replays the exact same schedule.
//!
//! Faithfulness notes (these catch real bug classes):
//! - Completing an op advances the virtual clock a little; when nothing is
//!   ready the clock jumps to the earliest timer. No timers and nothing
//!   ready means the system is stuck: `error.WouldBlockForever`.
//! - `close`/`close_now` do NOT complete ops already pending on the fd —
//!   exactly like io_uring — so a missing `shutdown_socket` before close
//!   surfaces as a detected deadlock instead of passing silently.
//! - A send blocks (stays pending) while the peer's buffer is full: bounded
//!   buffers push backpressure exactly like TCP flow control.
//! - Socket slots are never reused within one IO instance, so a stale fd is
//!   a hang or an assert, never a silent redirect.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const assert = std.debug.assert;

const SocketAddress = @import("socket_address.zig").SocketAddress;

/// Virtual fds start here — accidentally passing one to a real syscall (or a
/// real fd to us) trips range asserts instead of corrupting something.
const fd_base: posix.socket_t = 1000;
// Cumulative sockets per iteration (slots are never reused — see the module
// comment). Bumped when the h2c workload joined the H1 one: ~50% more
// clients, each fanning out per-stream upstream dials.
const socket_max = 8192;
const socket_buffer_bytes = 4096;
const accept_queue_max = 16;
const candidates_max = 1024;

pub const AcceptError = error{
    ConnectionAborted,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    Canceled,
    Unexpected,
};

pub const RecvError = error{
    ConnectionResetByPeer,
    ConnectionRefused,
    SystemResources,
    Canceled,
    Unexpected,
};

pub const SendError = error{
    BrokenPipe,
    ConnectionResetByPeer,
    SystemResources,
    Canceled,
    Unexpected,
};

pub const ConnectError = error{
    ConnectionRefused,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    NetworkUnreachable,
    Canceled,
    Unexpected,
};

pub const CloseError = error{Unexpected};

pub const TimeoutError = error{ Canceled, Unexpected };

pub const CancelError = error{Unexpected};

pub const KernelTlsError = error{ UpgradeUnsupported, ParametersRejected };

/// Fault-injection knobs. Probabilities are per million, evaluated once per
/// eligible operation completion with the scheduler's PRNG — a seed replays
/// its faults exactly.
pub const Faults = struct {
    /// A stream recv/send completes with ECONNRESET instead of its normal
    /// result, and the connection is dead in both directions from then on —
    /// a TCP RST: peer crash, middlebox state timeout, close with unread
    /// data, SO_LINGER(0).
    reset_ppm: u32 = 0,
    /// A connect completes with ECONNREFUSED even though the listener
    /// exists — a transiently unreachable upstream.
    connect_refuse_ppm: u32 = 0,
    /// A connect black-holes (a dropped SYN): nothing happens until the
    /// virtual TCP handshake timeout, then it completes with ETIMEDOUT —
    /// unless a cancel reaps it first (the per-try-timeout path).
    connect_blackhole_ppm: u32 = 0,
};

/// How long a black-holed connect hangs before ETIMEDOUT (virtual time) —
/// the kernel's SYN-retry give-up, far beyond any sane per-try timeout.
pub const connect_blackhole_timeout_ns: u64 = 60 * std.time.ns_per_s;

const Operation = union(enum) {
    accept: struct { socket: posix.socket_t },
    recv: struct { socket: posix.socket_t, buffer: []u8 },
    send: struct { socket: posix.socket_t, buffer: []const u8 },
    connect: struct {
        socket: posix.socket_t,
        addr: SocketAddress,
        /// Nonzero for a black-holed connect: not ready before this instant,
        /// then fails ETIMEDOUT (decided once, at submit).
        hung_until_ns: u64 = 0,
    },
    close: struct { fd: posix.fd_t },
    timeout: struct { expires_at_ns: u64 },
    cancel: struct { target: u64 },
};

const ErasedCallback = *const fn (
    context: *anyopaque,
    completion: *Completion,
    result: *const anyopaque,
) void;

pub const Completion = struct {
    operation: Operation,
    context: *anyopaque = undefined,
    callback: ErasedCallback = undefined,
    /// Result in cqe.res convention: >= 0 success, negative is `-errno`.
    result: i32 = 0,
    retries: u32 = 0,
    next: ?*Completion = null,
};

const CompletionQueue = struct {
    head: ?*Completion = null,
    tail: ?*Completion = null,
    count: u32 = 0,

    fn push(queue: *CompletionQueue, completion: *Completion) void {
        assert(completion.next == null);
        if (queue.tail) |tail| tail.next = completion else queue.head = completion;
        queue.tail = completion;
        queue.count += 1;
    }

    fn pop(queue: *CompletionQueue) ?*Completion {
        const completion = queue.head orelse return null;
        queue.head = completion.next;
        if (queue.head == null) queue.tail = null;
        completion.next = null;
        assert(queue.count > 0);
        queue.count -= 1;
        return completion;
    }

    fn remove(queue: *CompletionQueue, completion: *Completion) bool {
        var previous: ?*Completion = null;
        var current = queue.head;
        while (current) |node| : ({
            previous = current;
            current = node.next;
        }) {
            if (node != completion) continue;
            if (previous) |p| p.next = node.next else queue.head = node.next;
            if (queue.tail == node) queue.tail = previous;
            node.next = null;
            assert(queue.count > 0);
            queue.count -= 1;
            return true;
        }
        return false;
    }
};

const Socket = struct {
    state: State = .free,
    /// Listener: the bound port; streams: 0.
    port: u16 = 0,
    accept_queue: [accept_queue_max]posix.socket_t = undefined,
    accept_queue_len: u32 = 0,
    /// Stream peer fd; -1 when unconnected or the peer is fully gone.
    peer_fd: posix.socket_t = -1,
    /// Bytes readable on this fd (written by the peer). Linear, compacted.
    buffer: [socket_buffer_bytes]u8 = undefined,
    buffer_len: usize = 0,
    /// The peer sent FIN (or vanished): reads drain the buffer, then 0.
    remote_closed: bool = false,
    /// The connection took an (injected) RST: every op fails ECONNRESET.
    reset: bool = false,
    read_shutdown: bool = false,
    write_shutdown: bool = false,

    /// `.closed` keeps the stream's flags alive: like io_uring (where ops
    /// hold a file reference), ops pending at close time still complete if a
    /// shutdown woke them — and still hang if it did not.
    const State = enum { free, listener, stream, closed };
};

pub const IO = struct {
    prng: std.Random.DefaultPrng,
    now: u64 = 0,
    faults: Faults = .{},
    sockets: []Socket,
    /// Next never-used slot (slots are not reused; see the module comment).
    socket_count: u32 = 0,
    pending: CompletionQueue = .{},
    completed: CompletionQueue = .{},

    /// The socket table is too large for the stack; the caller provides the
    /// allocator (simulation is not the zero-alloc serving path).
    pub fn init_simulation(gpa: std.mem.Allocator, seed: u64) !IO {
        const sockets = try gpa.alloc(Socket, socket_max);
        for (sockets) |*socket| socket.* = .{};
        return .{ .prng = std.Random.DefaultPrng.init(seed), .sockets = sockets };
    }

    pub fn deinit_simulation(io: *IO, gpa: std.mem.Allocator) void {
        gpa.free(io.sockets);
        io.* = undefined;
    }

    // ---- virtual sockets ---------------------------------------------------

    fn allocate(io: *IO, state: Socket.State) posix.socket_t {
        assert(state != .free);
        assert(io.socket_count < socket_max); // simulation ran out of fd slots
        const index = io.socket_count;
        io.socket_count += 1;
        io.sockets[index].state = state;
        return fd_base + @as(posix.socket_t, @intCast(index));
    }

    fn socket_at(io: *IO, fd: posix.socket_t) *Socket {
        assert(fd >= fd_base);
        assert(fd < fd_base + @as(posix.socket_t, @intCast(io.socket_count)));
        return &io.sockets[@intCast(fd - fd_base)];
    }

    pub fn open_listener(io: *IO, port: u16) posix.socket_t {
        assert(port != 0);
        const fd = io.allocate(.listener);
        io.socket_at(fd).port = port;
        return fd;
    }

    pub fn open_tcp_socket(io: *IO, family: std.Io.net.IpAddress.Family) ?posix.socket_t {
        _ = family; // virtual sockets are family-agnostic
        return io.allocate(.stream);
    }

    pub fn set_tcp_no_delay(io: *IO, fd: posix.socket_t) void {
        _ = io.socket_at(fd); // range check only; the virtual wire has no Nagle
    }

    pub fn now_ns(io: *IO) u64 {
        return io.now;
    }

    /// Wakes everything pending on the fd (reads see EOF, writes see EPIPE)
    /// and FINs the peer — mirrors shutdown(SHUT_RDWR).
    pub fn shutdown_socket(io: *IO, fd: posix.socket_t) void {
        const socket = io.socket_at(fd);
        assert(socket.state == .stream);
        socket.read_shutdown = true;
        socket.write_shutdown = true;
        if (socket.peer_fd >= 0) io.socket_at(socket.peer_fd).remote_closed = true;
    }

    /// Closes the fd and FINs the peer. Ops already pending on the fd are
    /// NOT woken by the close itself — exactly like an io_uring close — so a
    /// missing shutdown becomes a detectable hang; ops a *prior* shutdown
    /// woke still complete (in-flight io_uring ops hold a file reference, so
    /// close ordering must not strand them).
    pub fn close_now(io: *IO, fd: posix.socket_t) void {
        const socket = io.socket_at(fd);
        assert(socket.state != .free); // double close
        assert(socket.state != .closed); // double close
        if (socket.state == .listener) {
            // Queued-but-unaccepted connections die with the listener (the
            // kernel resets them); their peers see the close. Inlined stream
            // close per entry — no recursion (TigerStyle).
            for (socket.accept_queue[0..socket.accept_queue_len]) |queued_fd| {
                const queued = io.socket_at(queued_fd);
                assert(queued.state == .stream); // queued fds were never accepted
                if (queued.peer_fd >= 0) {
                    const peer = io.socket_at(queued.peer_fd);
                    peer.remote_closed = true;
                    peer.peer_fd = -1;
                }
                queued.state = .closed;
                queued.peer_fd = -1;
            }
            socket.* = .{ .state = .free };
            return;
        }
        if (socket.peer_fd >= 0) {
            const peer = io.socket_at(socket.peer_fd);
            peer.remote_closed = true;
            peer.peer_fd = -1; // writes there now fail
        }
        socket.state = .closed; // flags stay; the slot is never reused
        socket.peer_fd = -1;
    }

    /// The virtual kernel has no TLS ULP: every upgrade attempt fails, so a
    /// simulated proxy always stays on the userspace relay (kTLS is
    /// exercised by the linux-backend tests in tls/kernel.zig).
    pub fn enable_kernel_tls(
        io: *IO,
        fd: posix.socket_t,
        transmit_info: []const u8,
        receive_info: []const u8,
    ) KernelTlsError!void {
        assert(transmit_info.len >= 40); // same contract as the linux backend
        assert(receive_info.len >= 40);
        _ = io.socket_at(fd); // range check
        return error.UpgradeUnsupported;
    }

    // ---- submission (same shape as the io_uring backend) -------------------

    pub fn accept(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (Context, *Completion, AcceptError!posix.socket_t) void,
        completion: *Completion,
        socket: posix.socket_t,
    ) void {
        io.submit(Context, context, AcceptError!posix.socket_t, callback, completion, .{
            .accept = .{ .socket = socket },
        });
    }

    pub fn recv(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (Context, *Completion, RecvError!usize) void,
        completion: *Completion,
        socket: posix.socket_t,
        buffer: []u8,
    ) void {
        assert(buffer.len > 0);
        io.submit(Context, context, RecvError!usize, callback, completion, .{
            .recv = .{ .socket = socket, .buffer = buffer },
        });
    }

    pub fn send(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (Context, *Completion, SendError!usize) void,
        completion: *Completion,
        socket: posix.socket_t,
        buffer: []const u8,
    ) void {
        assert(buffer.len > 0);
        io.submit(Context, context, SendError!usize, callback, completion, .{
            .send = .{ .socket = socket, .buffer = buffer },
        });
    }

    /// sendmsg(2) parity: the virtual wire has no record types, so the
    /// control message is irrelevant and the payload (a single segment —
    /// all zoxy needs) is submitted as a plain send.
    pub fn send_message(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (Context, *Completion, SendError!usize) void,
        completion: *Completion,
        socket: posix.socket_t,
        message: *const linux.msghdr_const,
    ) void {
        assert(message.iovlen == 1); // multi-segment is unused; extend when needed
        const segment = message.iov[0];
        assert(segment.len > 0);
        io.submit(Context, context, SendError!usize, callback, completion, .{
            .send = .{ .socket = socket, .buffer = segment.base[0..segment.len] },
        });
    }

    pub fn connect(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (Context, *Completion, ConnectError!void) void,
        completion: *Completion,
        socket: posix.socket_t,
        addr: SocketAddress,
    ) void {
        const hung_until_ns: u64 = if (io.roll(io.faults.connect_blackhole_ppm))
            io.now + connect_blackhole_timeout_ns
        else
            0;
        io.submit(Context, context, ConnectError!void, callback, completion, .{
            .connect = .{ .socket = socket, .addr = addr, .hung_until_ns = hung_until_ns },
        });
    }

    pub fn close(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (Context, *Completion, CloseError!void) void,
        completion: *Completion,
        fd: posix.fd_t,
    ) void {
        io.submit(Context, context, CloseError!void, callback, completion, .{
            .close = .{ .fd = fd },
        });
    }

    pub fn timeout(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (Context, *Completion, TimeoutError!void) void,
        completion: *Completion,
        nanoseconds: u63,
    ) void {
        io.submit(Context, context, TimeoutError!void, callback, completion, .{
            .timeout = .{ .expires_at_ns = io.now + nanoseconds },
        });
    }

    pub fn cancel(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (Context, *Completion, CancelError!void) void,
        completion: *Completion,
        target: *const Completion,
    ) void {
        io.submit(Context, context, CancelError!void, callback, completion, .{
            .cancel = .{ .target = @intFromPtr(target) },
        });
    }

    fn submit(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime Result: type,
        comptime callback: fn (Context, *Completion, Result) void,
        completion: *Completion,
        operation: Operation,
    ) void {
        comptime assert(@typeInfo(Context) == .pointer);
        // Re-submitting a completion that is still in flight silently
        // truncates intrusive queues (and corrupts a real ring the same
        // way) — catch the guilty call site loudly instead.
        assert(!io.in_queue(&io.pending, completion));
        assert(!io.in_queue(&io.completed, completion));
        completion.* = .{
            .operation = operation,
            .context = @ptrCast(context),
            .callback = erase(Context, Result, callback),
        };
        io.pending.push(completion);
    }

    fn in_queue(io: *IO, queue: *const CompletionQueue, completion: *const Completion) bool {
        _ = io;
        var current = queue.head;
        while (current) |node| : (current = node.next) {
            if (node == completion) return true;
        }
        return false;
    }

    // ---- the deterministic scheduler ---------------------------------------

    /// Complete exactly one pending operation, chosen at random among those
    /// that are ready; jump the clock to the next timer when nothing is.
    pub fn run_once(io: *IO) !void {
        var candidates: [candidates_max]*Completion = undefined;
        var count = io.gather_ready(&candidates);
        if (count == 0) {
            const earliest = io.earliest_timer() orelse return error.WouldBlockForever;
            assert(earliest >= io.now);
            io.now = earliest;
            count = io.gather_ready(&candidates);
            assert(count > 0); // the due timer at least
        }
        const pick = candidates[io.prng.random().intRangeLessThan(usize, 0, count)];
        const removed = io.pending.remove(pick);
        assert(removed);
        // Every completion costs a little virtual time.
        io.now += 1 + io.prng.random().intRangeLessThan(u64, 0, 10 * std.time.ns_per_us);
        pick.result = io.perform(pick);
        io.completed.push(pick);
        io.run_completed();
    }

    pub fn run_until_done(io: *IO, done: *const bool) !void {
        while (!done.*) try io.run_once();
    }

    fn gather_ready(io: *IO, candidates: *[candidates_max]*Completion) usize {
        var count: usize = 0;
        var current = io.pending.head;
        while (current) |completion| : (current = completion.next) {
            if (!io.ready(completion)) continue;
            assert(count < candidates_max); // more ready ops than the table holds
            candidates[count] = completion;
            count += 1;
        }
        return count;
    }

    fn earliest_timer(io: *const IO) ?u64 {
        var earliest: ?u64 = null;
        var current = io.pending.head;
        while (current) |completion| : (current = completion.next) {
            const expires_at_ns: u64 = switch (completion.operation) {
                .timeout => |op| op.expires_at_ns,
                // A black-holed connect is a de-facto timer: the clock must
                // be able to reach its ETIMEDOUT (or nothing else may wake).
                .connect => |op| if (op.hung_until_ns != 0) op.hung_until_ns else continue,
                else => continue,
            };
            if (earliest == null or expires_at_ns < earliest.?) earliest = expires_at_ns;
        }
        return earliest;
    }

    fn ready(io: *IO, completion: *Completion) bool {
        switch (completion.operation) {
            .accept => |op| {
                const listener = io.socket_at(op.socket);
                return listener.state == .listener and listener.accept_queue_len > 0;
            },
            .recv => |op| {
                const socket = io.socket_at(op.socket);
                if (socket.state != .stream and socket.state != .closed) return false;
                if (socket.reset) return true; // fails ECONNRESET now
                return socket.buffer_len > 0 or socket.remote_closed or socket.read_shutdown;
            },
            .send => |op| {
                const socket = io.socket_at(op.socket);
                if (socket.state != .stream and socket.state != .closed) return false;
                if (socket.reset) return true; // fails ECONNRESET now
                if (socket.write_shutdown or socket.peer_fd < 0) return true; // fails now
                const peer = io.socket_at(socket.peer_fd);
                return peer.buffer_len < peer.buffer.len; // room to make progress
            },
            .connect => |op| return io.now >= op.hung_until_ns,
            .close => return true,
            .timeout => |op| return io.now >= op.expires_at_ns,
            .cancel => return true,
        }
    }

    fn perform(io: *IO, completion: *Completion) i32 {
        switch (completion.operation) {
            .accept => |op| return io.perform_accept(op.socket),
            .recv => |op| {
                if (io.reset_hit(op.socket)) return -@as(i32, @intFromEnum(linux.E.CONNRESET));
                return io.perform_recv(op.socket, op.buffer);
            },
            .send => |op| {
                if (io.reset_hit(op.socket)) return -@as(i32, @intFromEnum(linux.E.CONNRESET));
                return io.perform_send(op.socket, op.buffer);
            },
            .connect => |op| {
                // A black-holed connect ran out its virtual SYN retries.
                if (op.hung_until_ns != 0) return -@as(i32, @intFromEnum(linux.E.TIMEDOUT));
                if (io.roll(io.faults.connect_refuse_ppm)) {
                    return -@as(i32, @intFromEnum(linux.E.CONNREFUSED));
                }
                return io.perform_connect(op.socket, op.addr);
            },
            .close => |op| {
                io.close_now(op.fd);
                return 0;
            },
            .timeout => return -@as(i32, @intFromEnum(linux.E.TIME)), // normal expiry
            .cancel => |op| return io.perform_cancel(op.target),
        }
    }

    /// True when this op dies by RST: either the connection is already
    /// reset, or the injection coin lands — which kills both directions
    /// (the peer's next op fails too, exactly like a real RST).
    fn reset_hit(io: *IO, fd: posix.socket_t) bool {
        const socket = io.socket_at(fd);
        if (socket.state != .stream) return false; // closed fds fail their own way
        if (socket.reset) return true;
        if (!io.roll(io.faults.reset_ppm)) return false;
        socket.reset = true;
        if (socket.peer_fd >= 0) io.socket_at(socket.peer_fd).reset = true;
        return true;
    }

    fn roll(io: *IO, ppm: u32) bool {
        if (ppm == 0) return false;
        assert(ppm <= 1_000_000);
        return io.prng.random().intRangeLessThan(u32, 0, 1_000_000) < ppm;
    }

    fn perform_accept(io: *IO, listener_fd: posix.socket_t) i32 {
        const listener = io.socket_at(listener_fd);
        assert(listener.state == .listener);
        assert(listener.accept_queue_len > 0);
        const fd = listener.accept_queue[0];
        listener.accept_queue_len -= 1;
        std.mem.copyForwards(
            posix.socket_t,
            listener.accept_queue[0..listener.accept_queue_len],
            listener.accept_queue[1 .. listener.accept_queue_len + 1],
        );
        assert(fd >= fd_base);
        return fd;
    }

    fn perform_recv(io: *IO, fd: posix.socket_t, buffer: []u8) i32 {
        const socket = io.socket_at(fd);
        assert(socket.state == .stream or socket.state == .closed);
        if (socket.buffer_len == 0) {
            assert(socket.remote_closed or socket.read_shutdown);
            return 0; // EOF
        }
        // Adversarial partial read: 1..=available bytes, capped by the buffer.
        const available = @min(socket.buffer_len, buffer.len);
        const n = io.prng.random().intRangeAtMost(usize, 1, available);
        @memcpy(buffer[0..n], socket.buffer[0..n]);
        std.mem.copyForwards(
            u8,
            socket.buffer[0 .. socket.buffer_len - n],
            socket.buffer[n..socket.buffer_len],
        );
        socket.buffer_len -= n;
        return @intCast(n);
    }

    fn perform_send(io: *IO, fd: posix.socket_t, buffer: []const u8) i32 {
        const socket = io.socket_at(fd);
        assert(socket.state == .stream or socket.state == .closed);
        if (socket.write_shutdown) return -@as(i32, @intFromEnum(linux.E.PIPE));
        if (socket.peer_fd < 0) return -@as(i32, @intFromEnum(linux.E.PIPE));
        const peer = io.socket_at(socket.peer_fd);
        assert(peer.state == .stream);
        const space = peer.buffer.len - peer.buffer_len;
        assert(space > 0); // ready() gates on room
        // Adversarial partial write: 1..=what fits.
        const n = io.prng.random().intRangeAtMost(usize, 1, @min(buffer.len, space));
        @memcpy(peer.buffer[peer.buffer_len..][0..n], buffer[0..n]);
        peer.buffer_len += n;
        return @intCast(n);
    }

    fn perform_connect(io: *IO, fd: posix.socket_t, addr: SocketAddress) i32 {
        const socket = io.socket_at(fd);
        assert(socket.state == .stream);
        assert(socket.peer_fd < 0); // never connected twice
        // The virtual network keys listeners by port alone: both families
        // land on the same wire, which is exactly what the sim wants.
        const port = addr.port();
        const listener_fd = io.find_listener(port) orelse
            return -@as(i32, @intFromEnum(linux.E.CONNREFUSED));
        const listener = io.socket_at(listener_fd);
        if (listener.accept_queue_len == accept_queue_max) {
            return -@as(i32, @intFromEnum(linux.E.CONNREFUSED)); // backlog full
        }
        const server_fd = io.allocate(.stream);
        const server = io.socket_at(server_fd);
        server.peer_fd = fd;
        socket.peer_fd = server_fd;
        listener.accept_queue[listener.accept_queue_len] = server_fd;
        listener.accept_queue_len += 1;
        return 0;
    }

    fn find_listener(io: *IO, port: u16) ?posix.socket_t {
        for (io.sockets[0..io.socket_count], 0..) |*socket, index| {
            if (socket.state != .listener) continue;
            if (socket.port != port) continue;
            return fd_base + @as(posix.socket_t, @intCast(index));
        }
        return null;
    }

    fn perform_cancel(io: *IO, target: u64) i32 {
        var current = io.pending.head;
        while (current) |completion| : (current = completion.next) {
            if (@intFromPtr(completion) != target) continue;
            const removed = io.pending.remove(completion);
            assert(removed);
            completion.result = -@as(i32, @intFromEnum(linux.E.CANCELED));
            io.completed.push(completion);
            return 0;
        }
        return -@as(i32, @intFromEnum(linux.E.NOENT)); // nothing to cancel
    }

    /// Diagnostic: what is pending and why it is not ready.
    pub fn dump_pending(io: *IO) void {
        var current = io.pending.head;
        while (current) |completion| : (current = completion.next) {
            switch (completion.operation) {
                .accept => |op| std.debug.print("  pending accept fd={d}\n", .{op.socket}),
                .recv => |op| {
                    const socket = io.socket_at(op.socket);
                    std.debug.print(
                        "  pending recv fd={d} state={s} buffered={d} remote_closed={} " ++
                            "read_shutdown={}\n",
                        .{
                            op.socket,            @tagName(socket.state), socket.buffer_len,
                            socket.remote_closed, socket.read_shutdown,
                        },
                    );
                },
                .send => |op| {
                    const socket = io.socket_at(op.socket);
                    std.debug.print(
                        "  pending send fd={d} state={s} peer={d} write_shutdown={}\n",
                        .{
                            op.socket,
                            @tagName(socket.state),
                            socket.peer_fd,
                            socket.write_shutdown,
                        },
                    );
                },
                .connect => |op| std.debug.print("  pending connect fd={d}\n", .{op.socket}),
                .close => |op| std.debug.print("  pending close fd={d}\n", .{op.fd}),
                .timeout => |op| std.debug.print(
                    "  pending timeout expires_at={d} now={d}\n",
                    .{ op.expires_at_ns, io.now },
                ),
                .cancel => std.debug.print("  pending cancel\n", .{}),
            }
        }
    }

    // ---- result delivery (mirrors the io_uring backend) ---------------------

    fn run_completed(io: *IO) void {
        var maybe = io.completed.pop();
        while (maybe) |completion| : (maybe = io.completed.pop()) {
            io.complete(completion);
        }
    }

    fn complete(io: *IO, completion: *Completion) void {
        _ = io;
        switch (completion.operation) {
            .accept => {
                const result = decode_accept(completion.result);
                completion.callback(completion.context, completion, &result);
            },
            .recv => {
                const result = decode_recv(completion.result);
                completion.callback(completion.context, completion, &result);
            },
            .send => {
                const result = decode_send(completion.result);
                completion.callback(completion.context, completion, &result);
            },
            .connect => {
                const result = decode_connect(completion.result);
                completion.callback(completion.context, completion, &result);
            },
            .close => {
                const result: CloseError!void = {};
                completion.callback(completion.context, completion, &result);
            },
            .timeout => {
                const result = decode_timeout(completion.result);
                completion.callback(completion.context, completion, &result);
            },
            .cancel => {
                const result = decode_cancel(completion.result);
                completion.callback(completion.context, completion, &result);
            },
        }
    }
};

fn to_errno(result: i32) posix.E {
    assert(result < 0);
    return @enumFromInt(@as(u16, @intCast(-result)));
}

fn decode_accept(result: i32) AcceptError!posix.socket_t {
    if (result >= 0) return @intCast(result);
    return switch (to_errno(result)) {
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

fn decode_recv(result: i32) RecvError!usize {
    if (result >= 0) return @intCast(result);
    return switch (to_errno(result)) {
        .CONNRESET => error.ConnectionResetByPeer,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

fn decode_send(result: i32) SendError!usize {
    if (result >= 0) return @intCast(result);
    return switch (to_errno(result)) {
        .PIPE => error.BrokenPipe,
        .CONNRESET => error.ConnectionResetByPeer,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

fn decode_connect(result: i32) ConnectError!void {
    if (result >= 0) return;
    return switch (to_errno(result)) {
        .CONNREFUSED => error.ConnectionRefused,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

fn decode_timeout(result: i32) TimeoutError!void {
    if (result >= 0) return;
    return switch (to_errno(result)) {
        .TIME => {}, // normal expiry
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

fn decode_cancel(result: i32) CancelError!void {
    if (result >= 0) return;
    return switch (to_errno(result)) {
        .NOENT, .ALREADY => {},
        else => error.Unexpected,
    };
}

fn erase(
    comptime Context: type,
    comptime Result: type,
    comptime callback: fn (Context, *Completion, Result) void,
) ErasedCallback {
    return &struct {
        fn erased(context: *anyopaque, completion: *Completion, result: *const anyopaque) void {
            const typed_context: Context = @ptrCast(@alignCast(context));
            const typed_result: *const Result = @ptrCast(@alignCast(result));
            callback(typed_context, completion, typed_result.*);
        }
    }.erased;
}

// ---- tests ------------------------------------------------------------------

const TestPeer = struct {
    io: *IO,
    fd: posix.socket_t = -1,
    recv_buf: [64]u8 = undefined,
    received: usize = 0,
    sent: usize = 0,
    message: []const u8 = "",
    fin_after_send: bool = true,
    eof: bool = false,
    accept_c: Completion = undefined,
    recv_c: Completion = undefined,
    send_c: Completion = undefined,
    connect_c: Completion = undefined,

    fn on_accept(peer: *TestPeer, _: *Completion, result: AcceptError!posix.socket_t) void {
        peer.fd = result catch unreachable;
        peer.arm_recv();
    }
    fn arm_recv(peer: *TestPeer) void {
        const tail = peer.recv_buf[peer.received..];
        peer.io.recv(*TestPeer, peer, on_recv, &peer.recv_c, peer.fd, tail);
    }
    fn on_recv(peer: *TestPeer, _: *Completion, result: RecvError!usize) void {
        const n = result catch unreachable;
        if (n == 0) {
            peer.eof = true;
            return;
        }
        peer.received += n;
        peer.arm_recv();
    }
    fn on_connect(peer: *TestPeer, _: *Completion, result: ConnectError!void) void {
        result catch unreachable;
        peer.arm_send();
    }
    fn arm_send(peer: *TestPeer) void {
        peer.io.send(*TestPeer, peer, on_send, &peer.send_c, peer.fd, peer.message[peer.sent..]);
    }
    fn on_send(peer: *TestPeer, _: *Completion, result: SendError!usize) void {
        peer.sent += result catch unreachable;
        if (peer.sent < peer.message.len) return peer.arm_send();
        if (peer.fin_after_send) peer.io.shutdown_socket(peer.fd); // FIN: receiver sees EOF
    }
};

test "test_io: listen/connect/accept/send/recv round-trip, deterministically" {
    const gpa = std.testing.allocator;
    // The same seed must produce the identical byte-delivery schedule.
    var transcripts: [2]usize = undefined;
    for (&transcripts) |*transcript| {
        var io = try IO.init_simulation(gpa, 42);
        defer io.deinit_simulation(gpa);

        const listener = io.open_listener(8080);
        var server = TestPeer{ .io = &io };
        io.accept(*TestPeer, &server, TestPeer.on_accept, &server.accept_c, listener);

        var client = TestPeer{ .io = &io, .message = "hello, deterministic world!" };
        client.fd = io.open_tcp_socket(.ip4).?;
        const target = SocketAddress{ .in = .{
            .family = linux.AF.INET,
            .port = std.mem.nativeToBig(u16, 8080),
            .addr = 0,
        } };
        io.connect(*TestPeer, &client, TestPeer.on_connect, &client.connect_c, client.fd, target);

        var steps: usize = 0;
        while (!server.eof) : (steps += 1) {
            try std.testing.expect(steps < 10_000); // progress, not a hang
            try io.run_once();
        }
        try std.testing.expectEqualStrings(client.message, server.recv_buf[0..server.received]);
        transcript.* = steps;
    }
    try std.testing.expectEqual(transcripts[0], transcripts[1]);
}

test "test_io: close without shutdown leaves a pending recv hanging" {
    const gpa = std.testing.allocator;
    var io = try IO.init_simulation(gpa, 7);
    defer io.deinit_simulation(gpa);

    const listener = io.open_listener(9090);
    var server = TestPeer{ .io = &io };
    io.accept(*TestPeer, &server, TestPeer.on_accept, &server.accept_c, listener);

    // The client never FINs, so nothing external will wake the server's recv.
    var client = TestPeer{ .io = &io, .message = "x", .fin_after_send = false };
    client.fd = io.open_tcp_socket(.ip4).?;
    io.connect(*TestPeer, &client, TestPeer.on_connect, &client.connect_c, client.fd, .{ .in = .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, 9090),
        .addr = 0,
    } });
    while (server.received < 1) try io.run_once();

    // The server arms another recv, then closes its own fd without shutdown:
    // the close does not complete that recv — io_uring semantics — and with
    // no timers the loop reports the deadlock instead of spinning.
    io.close_now(server.fd);
    try std.testing.expectError(error.WouldBlockForever, io.run_once());
}

test "test_io: an injected RST fails ops on both ends of the connection" {
    const gpa = std.testing.allocator;
    var io = try IO.init_simulation(gpa, 11);
    defer io.deinit_simulation(gpa);

    // Error-tolerant harness: faults are the expected outcome here.
    const Harness = struct {
        io: *IO,
        fd: posix.socket_t = -1,
        reset_seen: bool = false,
        accept_c: Completion = undefined,
        connect_c: Completion = undefined,
        send_c: Completion = undefined,
        recv_c: Completion = undefined,
        buf: [16]u8 = undefined,

        fn on_accept(h: *@This(), _: *Completion, result: AcceptError!posix.socket_t) void {
            h.fd = result catch unreachable;
        }
        fn on_connect(_: *@This(), _: *Completion, result: ConnectError!void) void {
            result catch unreachable;
        }
        fn on_send(h: *@This(), _: *Completion, result: SendError!usize) void {
            _ = result catch |err| {
                h.reset_seen = h.reset_seen or err == error.ConnectionResetByPeer;
                return;
            };
        }
        fn on_recv(h: *@This(), _: *Completion, result: RecvError!usize) void {
            _ = result catch |err| {
                h.reset_seen = h.reset_seen or err == error.ConnectionResetByPeer;
                return;
            };
        }
    };

    const listener = io.open_listener(7070);
    var server = Harness{ .io = &io };
    var client = Harness{ .io = &io };
    io.accept(*Harness, &server, Harness.on_accept, &server.accept_c, listener);
    client.fd = io.open_tcp_socket(.ip4).?;
    io.connect(*Harness, &client, Harness.on_connect, &client.connect_c, client.fd, .{ .in = .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, 7070),
        .addr = 0,
    } });
    while (server.fd < 0) try io.run_once();

    // Every eligible op now takes the RST.
    io.faults = .{ .reset_ppm = 1_000_000 };
    io.send(*Harness, &client, Harness.on_send, &client.send_c, client.fd, "doomed");
    io.recv(*Harness, &server, Harness.on_recv, &server.recv_c, server.fd, &server.buf);
    while (!client.reset_seen or !server.reset_seen) try io.run_once();
    try std.testing.expect(client.reset_seen);
    try std.testing.expect(server.reset_seen); // the RST killed both directions
}

test "test_io: injected connect refusal reaches the callback" {
    const gpa = std.testing.allocator;
    var io = try IO.init_simulation(gpa, 12);
    defer io.deinit_simulation(gpa);
    io.faults = .{ .connect_refuse_ppm = 1_000_000 };

    _ = io.open_listener(6060); // exists, but the fault wins
    const Harness = struct {
        refused: bool = false,
        fn on_connect(h: *@This(), _: *Completion, result: ConnectError!void) void {
            result catch |err| {
                h.refused = err == error.ConnectionRefused;
                return;
            };
        }
    };
    var h = Harness{};
    var connect_c: Completion = undefined;
    const fd = io.open_tcp_socket(.ip4).?;
    io.connect(*Harness, &h, Harness.on_connect, &connect_c, fd, .{ .in = .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, 6060),
        .addr = 0,
    } });
    while (!h.refused) try io.run_once();
    try std.testing.expect(h.refused);
}

test "test_io: timers fire in virtual time order" {
    const gpa = std.testing.allocator;
    var io = try IO.init_simulation(gpa, 3);
    defer io.deinit_simulation(gpa);

    const Harness = struct {
        fired: [2]bool = .{ false, false },
        order_first: ?usize = null,
        fn on_late(h: *@This(), _: *Completion, _: TimeoutError!void) void {
            h.fired[1] = true;
            if (h.order_first == null) h.order_first = 1;
        }
        fn on_early(h: *@This(), _: *Completion, _: TimeoutError!void) void {
            h.fired[0] = true;
            if (h.order_first == null) h.order_first = 0;
        }
    };
    var h = Harness{};
    var late_c: Completion = undefined;
    var early_c: Completion = undefined;
    io.timeout(*Harness, &h, Harness.on_late, &late_c, 50 * std.time.ns_per_ms);
    io.timeout(*Harness, &h, Harness.on_early, &early_c, 10 * std.time.ns_per_ms);

    while (!h.fired[0] or !h.fired[1]) try io.run_once();
    try std.testing.expectEqual(@as(?usize, 0), h.order_first); // the earlier deadline first
    try std.testing.expect(io.now >= 50 * std.time.ns_per_ms);
}
