//! Completion-based, zero-allocation IO over io_uring (TigerBeetle's `IO` /
//! `Completion` pattern; see docs/DESIGN.md "I/O architecture").
//!
//! The caller owns every `Completion` and embeds it inline in long-lived,
//! statically-allocated state. Submitting an operation writes it in place — no
//! allocation ever happens here after `init`. The io_uring `user_data` is the
//! `*Completion`; completions are reaped into an intrusive `completed` queue and
//! their callbacks run one-by-one, off the reap path, to keep the stack bounded.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const assert = std.debug.assert;

const IoUring = linux.IoUring;

/// Maximum completions copied out of the ring per reap. Batching amortizes the
/// enter() syscall (TigerStyle: "amortize costs by batching").
const cqes_batch_max = 256;

/// Retries for an `io_uring_enter` interrupted by a signal (EINTR). A signal
/// landing mid-submit is routine and must not kill the worker; the bound keeps
/// the retry loop finite (TigerStyle: "put a limit on everything").
const submit_retries_max = 8;

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

/// The kind of io_uring operation, plus the parameters that must stay alive
/// until completion. Stored inline in the caller's `Completion`.
const Operation = union(enum) {
    accept: struct { socket: posix.socket_t },
    recv: struct { socket: posix.socket_t, buffer: []u8 },
    send: struct { socket: posix.socket_t, buffer: []const u8 },
    connect: struct { socket: posix.socket_t, addr: linux.sockaddr.in },
    close: struct { fd: posix.fd_t },
    timeout: struct { expires: linux.kernel_timespec },
    /// Cancel the in-flight operation whose completion is at `target` (its
    /// io_uring user_data). Cancelling a non-existent op completes with ENOENT.
    cancel: struct { target: u64 },
};

/// Type-erased callback stored in a `Completion`. `result` points at the typed
/// error union produced by `complete`.
const ErasedCallback = *const fn (
    context: *anyopaque,
    completion: *Completion,
    result: *const anyopaque,
) void;

pub const Completion = struct {
    operation: Operation,
    context: *anyopaque = undefined,
    callback: ErasedCallback = undefined,
    /// Raw `cqe.res`, filled before the callback runs. Negative is `-errno`.
    result: i32 = 0,
    /// Intrusive link for the `completed` queue. Non-null only while queued.
    next: ?*Completion = null,
};

/// Intrusive FIFO of ready completions. Nodes live inside the completions
/// themselves, so pushing/popping never allocates.
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
};

pub const IO = struct {
    ring: IoUring,
    completed: CompletionQueue = .{},
    /// Operations prepared into the SQ but not yet submitted to the kernel.
    queued: u32 = 0,
    /// Operations submitted and awaiting completion.
    in_kernel: u32 = 0,

    /// `entries` is the io_uring queue depth; must be a power of two.
    pub fn init(entries: u16, flags: u32) !IO {
        assert(entries > 0);
        assert(std.math.isPowerOfTwo(entries));
        return .{ .ring = try IoUring.init(entries, flags) };
    }

    pub fn deinit(io: *IO) void {
        io.ring.deinit();
        io.* = undefined;
    }

    // ---- submission -------------------------------------------------------

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

    pub fn connect(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (Context, *Completion, ConnectError!void) void,
        completion: *Completion,
        socket: posix.socket_t,
        addr: linux.sockaddr.in,
    ) void {
        io.submit(Context, context, ConnectError!void, callback, completion, .{
            .connect = .{ .socket = socket, .addr = addr },
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
            .timeout = .{ .expires = .{
                .sec = @intCast(nanoseconds / std.time.ns_per_s),
                .nsec = @intCast(nanoseconds % std.time.ns_per_s),
            } },
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
        completion.* = .{
            .operation = operation,
            .context = @ptrCast(context),
            .callback = erase(Context, Result, callback),
        };
        io.enqueue(completion);
    }

    fn enqueue(io: *IO, completion: *Completion) void {
        completion.next = null;
        io.prep(completion) catch |err| switch (err) {
            error.SubmissionQueueFull => {
                io.flush_submissions();
                // flush_submissions() drains the SQ to the kernel, so prep() now
                // has room for this one entry.
                const has_room = if (io.prep(completion)) |_| true else |_| false;
                assert(has_room);
            },
        };
        io.queued += 1;
    }

    fn prep(io: *IO, completion: *Completion) error{SubmissionQueueFull}!void {
        const user_data: u64 = @intFromPtr(completion);
        switch (completion.operation) {
            .accept => |op| _ = try io.ring.accept(user_data, op.socket, null, null, 0),
            .recv => |op| _ = try io.ring.recv(user_data, op.socket, .{ .buffer = op.buffer }, 0),
            .send => |op| _ = try io.ring.send(user_data, op.socket, op.buffer, 0),
            .connect => |*op| _ = try io.ring.connect(
                user_data,
                op.socket,
                @ptrCast(&op.addr),
                @sizeOf(linux.sockaddr.in),
            ),
            .close => |op| _ = try io.ring.close(user_data, op.fd),
            .timeout => |*op| _ = try io.ring.timeout(user_data, &op.expires, 0, 0),
            .cancel => |op| _ = try io.ring.cancel(user_data, op.target, 0),
        }
    }

    // ---- driving the loop -------------------------------------------------

    /// Submit queued work and run every ready callback without blocking.
    pub fn tick(io: *IO) !void {
        io.flush_submissions();
        try io.reap(0);
        io.run_completed();
    }

    /// Submit queued work, then process one batch of completions — blocking for
    /// at least one if none are already ready. Returns `error.WouldBlockForever`
    /// if there is nothing in flight to wait on (a caller bug).
    pub fn run_once(io: *IO) !void {
        io.flush_submissions();
        if (io.queued == 0 and io.in_kernel == 0 and io.completed.count == 0) {
            return error.WouldBlockForever;
        }
        // Only block in the kernel when no callbacks are ready to run; a callback
        // may enqueue more work (TigerBeetle's run_for_ns rule).
        try io.reap(if (io.completed.count == 0) 1 else 0);
        io.run_completed();
    }

    /// Drive the loop until `done.*` is set.
    pub fn run_until_done(io: *IO, done: *const bool) !void {
        while (!done.*) try io.run_once();
    }

    fn flush_submissions(io: *IO) void {
        if (io.queued == 0) return;
        assert(io.queued > 0);
        var attempt: u32 = 0;
        const submitted = while (attempt < submit_retries_max) : (attempt += 1) {
            break io.ring.submit() catch |err| switch (err) {
                error.SignalInterrupt => continue, // EINTR is routine; retry
                else => std.debug.panic("io: submit: {s}", .{@errorName(err)}),
            };
        } else std.debug.panic(
            "io: submit: interrupted {d} times in a row",
            .{submit_retries_max},
        );
        assert(submitted <= io.queued);
        io.queued -= submitted;
        io.in_kernel += submitted;
    }

    fn reap(io: *IO, wait_nr: u32) !void {
        var cqes: [cqes_batch_max]linux.io_uring_cqe = undefined;
        var wait = wait_nr;
        while (true) {
            const count = try io.ring.copy_cqes(&cqes, wait);
            if (count == 0) break;
            for (cqes[0..count]) |cqe| {
                const completion: *Completion = @ptrFromInt(cqe.user_data);
                completion.result = cqe.res;
                io.completed.push(completion);
            }
            assert(io.in_kernel >= count);
            io.in_kernel -= count;
            wait = 0; // only the first batch may block
            if (count < cqes.len) break; // CQ drained
        }
    }

    fn run_completed(io: *IO) void {
        // Callbacks may enqueue new SQEs (added to the SQ, not this queue), so
        // draining a snapshot of `completed` terminates.
        var maybe = io.completed.pop();
        while (maybe) |completion| : (maybe = io.completed.pop()) {
            io.complete(completion);
        }
    }

    fn complete(io: *IO, completion: *Completion) void {
        // Retry transient interruptions without notifying the caller.
        if (completion.result < 0) {
            const e = to_errno(completion.result);
            if (e == .INTR or e == .AGAIN) return io.enqueue(completion);
        }
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
                const result = decode_close(completion.result);
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

// ---- result decoding ------------------------------------------------------

fn to_errno(result: i32) posix.E {
    assert(result < 0);
    return @enumFromInt(@as(u16, @intCast(-result)));
}

fn decode_accept(result: i32) AcceptError!posix.socket_t {
    if (result >= 0) return @intCast(result);
    return switch (to_errno(result)) {
        .CONNABORTED => error.ConnectionAborted,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => error.SystemResources,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

fn decode_recv(result: i32) RecvError!usize {
    if (result >= 0) return @intCast(result); // 0 == peer closed (EOF)
    return switch (to_errno(result)) {
        .CONNRESET => error.ConnectionResetByPeer,
        .CONNREFUSED => error.ConnectionRefused,
        .NOBUFS, .NOMEM => error.SystemResources,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

fn decode_send(result: i32) SendError!usize {
    if (result >= 0) return @intCast(result);
    return switch (to_errno(result)) {
        .PIPE => error.BrokenPipe,
        .CONNRESET => error.ConnectionResetByPeer,
        .NOBUFS, .NOMEM => error.SystemResources,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

fn decode_connect(result: i32) ConnectError!void {
    if (result >= 0) return;
    return switch (to_errno(result)) {
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .TIMEDOUT => error.ConnectionTimedOut,
        .NETUNREACH, .HOSTUNREACH => error.NetworkUnreachable,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

fn decode_close(result: i32) CloseError!void {
    if (result >= 0) return;
    return error.Unexpected;
}

fn decode_timeout(result: i32) TimeoutError!void {
    if (result >= 0) return; // count reached
    return switch (to_errno(result)) {
        .TIME => {}, // normal expiry
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

fn decode_cancel(result: i32) CancelError!void {
    if (result >= 0) return;
    return switch (to_errno(result)) {
        .NOENT, .ALREADY => {}, // nothing to cancel / already completing — fine
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

// ---- tests ----------------------------------------------------------------

test "io: socketpair send/recv round-trip" {
    var io = try IO.init(8, 0);
    defer io.deinit();

    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
    try std.testing.expectEqual(@as(usize, 0), rc);
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    const Harness = struct {
        recv_buf: [64]u8 = undefined,
        recv_len: usize = 0,
        sent: bool = false,
        received: bool = false,

        fn on_send(h: *@This(), _: *Completion, result: SendError!usize) void {
            const n = result catch unreachable;
            assert(n == "hello".len);
            h.sent = true;
        }
        fn on_recv(h: *@This(), _: *Completion, result: RecvError!usize) void {
            h.recv_len = result catch unreachable;
            h.received = true;
        }
    };

    var h = Harness{};
    var recv_completion: Completion = undefined;
    var send_completion: Completion = undefined;

    io.recv(*Harness, &h, Harness.on_recv, &recv_completion, fds[1], &h.recv_buf);
    io.send(*Harness, &h, Harness.on_send, &send_completion, fds[0], "hello");

    var spins: usize = 0;
    while (!(h.sent and h.received)) : (spins += 1) {
        if (spins > 1000) return error.TestTimedOut;
        io.flush_submissions();
        try io.reap(1);
        io.run_completed();
    }

    try std.testing.expectEqualStrings("hello", h.recv_buf[0..h.recv_len]);
}
