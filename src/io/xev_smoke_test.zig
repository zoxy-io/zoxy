//! Smoke tests pinning the exact libxev 0.16 API shapes that `XevIo`
//! (slice 6) wraps: loop init at our ring size, timer fire + fresh-run
//! re-arm + cancel through a second completion, async wakeup, and a TCP
//! loopback echo across accept/connect/read/write/close. Every callback
//! returns `.disarm` and submits follow-up work explicitly — the exact
//! discipline the production backend uses (DESIGN.md §4). This file lives
//! under `src/io/`, the only place allowed to name xev and raw syscalls.

const std = @import("std");
const xev = @import("xev");

const XevIo = @import("XevIo.zig");

const assert = std.debug.assert;

/// Mirrors the production `ring_entries` (constants.zig lands in slice 2).
/// The value proves libxev accepts our ring size, not just its default.
const ring_entries: u16 = 4096;

const echo_token = "zoxy-smoke-token";

test "loop: init at ring_entries and run empty" {
    var loop = try xev.Loop.init(.{ .entries = ring_entries });
    defer loop.deinit();

    try loop.run(.no_wait);
}

test "timer: fires, fresh-run re-arm, cancel completes both sides" {
    var loop = try xev.Loop.init(.{ .entries = ring_entries });
    defer loop.deinit();

    const timer = try xev.Timer.init();
    defer timer.deinit();

    var context: TimerContext = .{};
    var completion: xev.Completion = .{};

    timer.run(&loop, &completion, 1, TimerContext, &context, TimerContext.onFire);
    try loop.run(.until_done);
    try std.testing.expectEqual(@as(u32, 1), context.fired_count);

    // Re-arm is always a fresh `run` — never a `.rearm` return, which would
    // reuse the stale absolute expiry and fire immediately (DESIGN.md §4).
    timer.run(&loop, &completion, 1, TimerContext, &context, TimerContext.onFire);
    try loop.run(.until_done);
    try std.testing.expectEqual(@as(u32, 2), context.fired_count);

    // Teardown-style cancel: the armed timer completes with error.Canceled
    // and the cancel op consumes its own second caller-owned completion
    // (DESIGN.md §4 — the one legal cancel).
    var cancel_completion: xev.Completion = .{};
    timer.run(&loop, &completion, 60_000, TimerContext, &context, TimerContext.onFire);
    timer.cancel(
        &loop,
        &completion,
        &cancel_completion,
        TimerContext,
        &context,
        TimerContext.onCancel,
    );
    try loop.run(.until_done);
    try std.testing.expectEqual(@as(u32, 2), context.fired_count);
    try std.testing.expectEqual(@as(u32, 1), context.canceled_count);
    try std.testing.expectEqual(@as(u32, 1), context.cancel_ok_count);
    try std.testing.expectEqual(@as(u32, 0), context.cancel_error_count);
}

test "async: notify wakes an armed wait" {
    var loop = try xev.Loop.init(.{ .entries = ring_entries });
    defer loop.deinit();

    var notifier = try xev.Async.init();
    defer notifier.deinit();

    var context: AsyncContext = .{};
    var completion: xev.Completion = .{};
    notifier.wait(&loop, &completion, AsyncContext, &context, AsyncContext.onWake);
    try notifier.notify();
    try loop.run(.until_done);
    try std.testing.expectEqual(@as(u32, 1), context.woken_count);
    try std.testing.expectEqual(@as(u32, 0), context.wake_error_count);
}

test "tcp: loopback echo across the full watcher surface" {
    var loop = try xev.Loop.init(.{ .entries = ring_entries });
    defer loop.deinit();

    var address = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const listener = try xev.TCP.init(address);
    try listener.bind(address);
    try listener.listen(1);
    address.setPort(try XevIo.boundPort(listener.fd));
    assert(address.getPort() != 0);

    const client = try xev.TCP.init(address);

    var echo: EchoContext = .{ .listener = listener, .client = client };
    listener.accept(&loop, &echo.completion_accept, EchoContext, &echo, EchoContext.onAccept);
    client.connect(
        &loop,
        &echo.completion_connect,
        address,
        EchoContext,
        &echo,
        EchoContext.onConnect,
    );

    try loop.run(.until_done);

    try std.testing.expect(!echo.failed);
    try std.testing.expect(echo.accept_ok);
    try std.testing.expect(echo.connect_ok);
    try std.testing.expectEqualStrings(echo_token, echo.server_buffer[0..echo.server_read_len]);
    try std.testing.expectEqualStrings(echo_token, echo.client_buffer[0..echo.client_read_len]);
    try std.testing.expectEqual(@as(u32, 3), echo.close_count);
}

const TimerContext = struct {
    fired_count: u32 = 0,
    canceled_count: u32 = 0,
    cancel_ok_count: u32 = 0,
    cancel_error_count: u32 = 0,

    fn onFire(
        context: ?*TimerContext,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        const timer_context = context.?;
        if (result) |_| {
            timer_context.fired_count += 1;
        } else |err| {
            assert(err == error.Canceled);
            timer_context.canceled_count += 1;
        }
        return .disarm;
    }

    fn onCancel(
        context: ?*TimerContext,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Timer.CancelError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        const timer_context = context.?;
        if (result) |_| {
            timer_context.cancel_ok_count += 1;
        } else |_| {
            timer_context.cancel_error_count += 1;
        }
        return .disarm;
    }
};

const AsyncContext = struct {
    woken_count: u32 = 0,
    wake_error_count: u32 = 0,

    fn onWake(
        context: ?*AsyncContext,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        const async_context = context.?;
        if (result) |_| {
            async_context.woken_count += 1;
        } else |_| {
            async_context.wake_error_count += 1;
        }
        return .disarm;
    }
};

/// Drives one full echo exchange. Close is only initiated once both the
/// server write and the client read have delivered their completions, so no
/// socket is ever closed with an op still in flight — the straggler
/// discipline of DESIGN.md §5 in miniature.
const EchoContext = struct {
    listener: xev.TCP,
    client: xev.TCP,
    server_conn: ?xev.TCP = null,

    completion_accept: xev.Completion = .{},
    completion_connect: xev.Completion = .{},
    completion_client_write: xev.Completion = .{},
    completion_client_read: xev.Completion = .{},
    completion_server_read: xev.Completion = .{},
    completion_server_write: xev.Completion = .{},
    completion_close_client: xev.Completion = .{},
    completion_close_server_conn: xev.Completion = .{},
    completion_close_listener: xev.Completion = .{},

    server_buffer: [64]u8 = undefined,
    client_buffer: [64]u8 = undefined,

    accept_ok: bool = false,
    connect_ok: bool = false,
    server_read_len: usize = 0,
    server_write_done: bool = false,
    client_read_len: usize = 0,
    closing: bool = false,
    close_count: u32 = 0,
    failed: bool = false,

    fn onAccept(
        context: ?*EchoContext,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.AcceptError!xev.TCP,
    ) xev.CallbackAction {
        _ = completion;
        const echo = context.?;
        assert(echo.server_conn == null);
        const conn = result catch return echo.fail();
        echo.accept_ok = true;
        echo.server_conn = conn;
        conn.read(
            loop,
            &echo.completion_server_read,
            .{ .slice = &echo.server_buffer },
            EchoContext,
            echo,
            EchoContext.onServerRead,
        );
        return .disarm;
    }

    fn onConnect(
        context: ?*EchoContext,
        loop: *xev.Loop,
        completion: *xev.Completion,
        socket: xev.TCP,
        result: xev.ConnectError!void,
    ) xev.CallbackAction {
        _ = completion;
        const echo = context.?;
        assert(!echo.connect_ok);
        result catch return echo.fail();
        echo.connect_ok = true;
        socket.write(
            loop,
            &echo.completion_client_write,
            .{ .slice = echo_token },
            EchoContext,
            echo,
            EchoContext.onClientWrite,
        );
        return .disarm;
    }

    fn onClientWrite(
        context: ?*EchoContext,
        loop: *xev.Loop,
        completion: *xev.Completion,
        socket: xev.TCP,
        buffer: xev.WriteBuffer,
        result: xev.WriteError!usize,
    ) xev.CallbackAction {
        _ = completion;
        _ = buffer;
        const echo = context.?;
        const written = result catch return echo.fail();
        assert(written == echo_token.len);
        socket.read(
            loop,
            &echo.completion_client_read,
            .{ .slice = &echo.client_buffer },
            EchoContext,
            echo,
            EchoContext.onClientRead,
        );
        return .disarm;
    }

    fn onServerRead(
        context: ?*EchoContext,
        loop: *xev.Loop,
        completion: *xev.Completion,
        socket: xev.TCP,
        buffer: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        _ = completion;
        _ = buffer;
        const echo = context.?;
        const read_len = result catch return echo.fail();
        assert(read_len > 0);
        assert(read_len <= echo.server_buffer.len);
        echo.server_read_len = read_len;
        socket.write(
            loop,
            &echo.completion_server_write,
            .{ .slice = echo.server_buffer[0..read_len] },
            EchoContext,
            echo,
            EchoContext.onServerWrite,
        );
        return .disarm;
    }

    fn onServerWrite(
        context: ?*EchoContext,
        loop: *xev.Loop,
        completion: *xev.Completion,
        socket: xev.TCP,
        buffer: xev.WriteBuffer,
        result: xev.WriteError!usize,
    ) xev.CallbackAction {
        _ = completion;
        _ = socket;
        _ = buffer;
        const echo = context.?;
        const written = result catch return echo.fail();
        assert(written == echo.server_read_len);
        echo.server_write_done = true;
        echo.maybeBeginClose(loop);
        return .disarm;
    }

    fn onClientRead(
        context: ?*EchoContext,
        loop: *xev.Loop,
        completion: *xev.Completion,
        socket: xev.TCP,
        buffer: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        _ = completion;
        _ = socket;
        _ = buffer;
        const echo = context.?;
        const read_len = result catch return echo.fail();
        assert(read_len > 0);
        assert(read_len <= echo.client_buffer.len);
        echo.client_read_len = read_len;
        echo.maybeBeginClose(loop);
        return .disarm;
    }

    fn onClose(
        context: ?*EchoContext,
        loop: *xev.Loop,
        completion: *xev.Completion,
        socket: xev.TCP,
        result: xev.CloseError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = socket;
        const echo = context.?;
        result catch return echo.fail();
        echo.close_count += 1;
        assert(echo.close_count <= 3);
        return .disarm;
    }

    fn maybeBeginClose(echo: *EchoContext, loop: *xev.Loop) void {
        if (echo.server_write_done) {
            if (echo.client_read_len > 0) {
                assert(!echo.closing);
                echo.closing = true;
                const server_conn = echo.server_conn.?;
                echo.client.close(
                    loop,
                    &echo.completion_close_client,
                    EchoContext,
                    echo,
                    EchoContext.onClose,
                );
                server_conn.close(
                    loop,
                    &echo.completion_close_server_conn,
                    EchoContext,
                    echo,
                    EchoContext.onClose,
                );
                echo.listener.close(
                    loop,
                    &echo.completion_close_listener,
                    EchoContext,
                    echo,
                    EchoContext.onClose,
                );
            }
        }
    }

    fn fail(echo: *EchoContext) xev.CallbackAction {
        echo.failed = true;
        return .disarm;
    }
};
