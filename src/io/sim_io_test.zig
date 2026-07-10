//! SimIo-specific scenario tests (§9): half-close both ways, reset
//! visibility, refused connects, timer ordering and cancellation, signal
//! injection, deadlock detection, and the same-seed ⇒ same-trace
//! determinism claim. The generic echo exchange lives in
//! contract_test.zig and runs against both backends; the determinism
//! test below reuses it. The harness plays both client and origin
//! through the seam itself — virtual origins are just more seam users.

const std = @import("std");

const contract = @import("contract_test.zig");
const Io = @import("Io.zig");
const SimIo = @import("SimIo.zig");

const assert = std.debug.assert;

fn testAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral("127.0.0.1:9100") catch unreachable;
}

fn runEchoScenario(seed: u64, adversary: SimIo.Adversary) !u64 {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{ .seed = seed, .adversary = adversary });

    var scenario: contract.EchoScenario(SimIo) = .{ .io = &sim_io };
    try scenario.start(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0"));
    try sim_io.run();
    try scenario.verify();
    try std.testing.expect(sim_io.sockets.isFullyReleased());
    return sim_io.trace_hash;
}

test "sim: same seed same trace, different seed different trace" {
    const adversary: SimIo.Adversary = .{ .partial_io = true, .connect_delay_ns_max = 1_000_000 };
    const first = try runEchoScenario(42, adversary);
    const second = try runEchoScenario(42, adversary);
    const third = try runEchoScenario(43, adversary);
    try std.testing.expectEqual(first, second);
    try std.testing.expect(first != third);
}

/// Establishes one connected virtual pair, then returns control so tests
/// can act on it synchronously between `run` calls.
const PairScenario = struct {
    io: *SimIo,
    listener: SimIo.Listener = undefined,
    accept_completion: SimIo.Completion = .{},
    connect_completion: SimIo.Completion = .{},
    client: SimIo.Socket = undefined,
    server: SimIo.Socket = undefined,
    ready_count: u8 = 0,

    fn establish(pair: *PairScenario) !void {
        pair.listener = try pair.io.listen(testAddress());
        pair.io.accept(pair.listener, &pair.accept_completion, PairScenario, pair, onAccept);
        pair.io.connect(testAddress(), &pair.connect_completion, PairScenario, pair, onConnect);
        try pair.io.run();
        assert(pair.ready_count == 2);
        pair.io.listenClose(pair.listener);
    }

    fn onAccept(pair: *PairScenario, result: Io.AcceptError!SimIo.Socket) void {
        pair.server = result catch unreachable;
        pair.ready_count += 1;
    }

    fn onConnect(pair: *PairScenario, result: Io.ConnectError!SimIo.Socket) void {
        pair.client = result catch unreachable;
        pair.ready_count += 1;
    }
};

const RecvProbe = struct {
    result: ?(Io.RecvError!u32) = null,
    completion: SimIo.Completion = .{},
    buffer: [64]u8 = undefined,

    fn onRecv(probe: *RecvProbe, result: Io.RecvError!u32) void {
        assert(probe.result == null);
        probe.result = result;
    }
};

test "sim: linger-rst close is seen as a reset by the peer" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{ .seed = 7 });

    var pair: PairScenario = .{ .io = &sim_io };
    try pair.establish();

    try sim_io.setLingerRst(pair.client);
    sim_io.closeNow(pair.client);

    var probe: RecvProbe = .{};
    sim_io.recv(pair.server, &probe.buffer, &probe.completion, RecvProbe, &probe, RecvProbe.onRecv);
    try sim_io.run();
    try std.testing.expectError(error.Reset, probe.result.?);

    sim_io.closeNow(pair.server);
    try std.testing.expect(sim_io.sockets.isFullyReleased());
}

test "sim: half-close delivers data then EndOfStream, reverse path stays open" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{ .seed = 11, .adversary = .{ .partial_io = false } });

    var pair: PairScenario = .{ .io = &sim_io };
    try pair.establish();

    var send_probe: SendProbe = .{};
    sim_io.send(pair.client, "abc", &send_probe.completion, SendProbe, &send_probe, SendProbe.onSend);
    try sim_io.run();
    try std.testing.expectEqual(@as(u32, 3), try send_probe.result.?);
    sim_io.shutdown(pair.client, .write);

    var probe: RecvProbe = .{};
    sim_io.recv(pair.server, &probe.buffer, &probe.completion, RecvProbe, &probe, RecvProbe.onRecv);
    try sim_io.run();
    try std.testing.expectEqual(@as(u32, 3), try probe.result.?);
    try std.testing.expectEqualStrings("abc", probe.buffer[0..3]);

    probe.result = null;
    sim_io.recv(pair.server, &probe.buffer, &probe.completion, RecvProbe, &probe, RecvProbe.onRecv);
    try sim_io.run();
    try std.testing.expectError(error.EndOfStream, probe.result.?);

    // The reverse direction is still open after the forward FIN.
    send_probe.result = null;
    sim_io.send(pair.server, "xy", &send_probe.completion, SendProbe, &send_probe, SendProbe.onSend);
    try sim_io.run();
    try std.testing.expectEqual(@as(u32, 2), try send_probe.result.?);

    sim_io.closeNow(pair.client);
    sim_io.closeNow(pair.server);
    try std.testing.expect(sim_io.sockets.isFullyReleased());
}

const SendProbe = struct {
    result: ?(Io.SendError!u32) = null,
    completion: SimIo.Completion = .{},

    fn onSend(probe: *SendProbe, result: Io.SendError!u32) void {
        assert(probe.result == null);
        probe.result = result;
    }
};

test "sim: connect to an unlistened address is refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{ .seed = 3 });

    var probe: ConnectProbe = .{};
    sim_io.connect(testAddress(), &probe.completion, ConnectProbe, &probe, ConnectProbe.onConnect);
    try sim_io.run();
    try std.testing.expectError(error.Refused, probe.result.?);
    try std.testing.expect(sim_io.sockets.isFullyReleased());
}

const ConnectProbe = struct {
    result: ?(Io.ConnectError!SimIo.Socket) = null,
    completion: SimIo.Completion = .{},

    fn onConnect(probe: *ConnectProbe, result: Io.ConnectError!SimIo.Socket) void {
        assert(probe.result == null);
        probe.result = result;
    }
};

test "sim: timers fire in virtual-time order; cancel completes both sides" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{ .seed = 5 });

    var probe: TimerProbe = .{};
    sim_io.timerStart(&probe.first, 5_000_000, TimerProbe, &probe, TimerProbe.onFirst);
    sim_io.timerStart(&probe.second, 10_000_000, TimerProbe, &probe, TimerProbe.onSecond);
    sim_io.timerStart(&probe.doomed, 60_000_000_000, TimerProbe, &probe, TimerProbe.onDoomed);
    sim_io.timerCancel(&probe.doomed, &probe.cancel, TimerProbe, &probe, TimerProbe.onCancel);
    try sim_io.run();

    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, probe.fired_order[0..probe.fired_count]);
    try std.testing.expect(probe.doomed_canceled);
    try std.testing.expect(probe.cancel_done);
}

const TimerProbe = struct {
    first: SimIo.Completion = .{},
    second: SimIo.Completion = .{},
    doomed: SimIo.Completion = .{},
    cancel: SimIo.Completion = .{},
    fired_order: [4]u8 = undefined,
    fired_count: u8 = 0,
    doomed_canceled: bool = false,
    cancel_done: bool = false,

    fn record(probe: *TimerProbe, tag: u8) void {
        assert(probe.fired_count < probe.fired_order.len);
        probe.fired_order[probe.fired_count] = tag;
        probe.fired_count += 1;
    }

    fn onFirst(probe: *TimerProbe, result: Io.TimerError!void) void {
        result catch unreachable;
        probe.record(1);
    }

    fn onSecond(probe: *TimerProbe, result: Io.TimerError!void) void {
        result catch unreachable;
        probe.record(2);
    }

    fn onDoomed(probe: *TimerProbe, result: Io.TimerError!void) void {
        if (result) |_| unreachable else |err| {
            assert(err == error.Canceled);
            probe.doomed_canceled = true;
        }
    }

    fn onCancel(probe: *TimerProbe) void {
        probe.cancel_done = true;
    }
};

test "sim: signals are delivered at their scheduled virtual time" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{ .seed = 9 });

    var probe: SignalProbe = .{ .io = &sim_io };
    sim_io.signalWait(SignalProbe, &probe, SignalProbe.onSignal);
    sim_io.scheduleSignal(.terminate, sim_io.nowNs() + 5_000_000);
    try sim_io.run();
    try std.testing.expectEqual(@as(u8, 1), probe.terminate_count);
    try std.testing.expect(probe.seen_at_ns >= 5_000_000);
}

const SignalProbe = struct {
    io: *SimIo,
    terminate_count: u8 = 0,
    seen_at_ns: u64 = 0,

    fn onSignal(probe: *SignalProbe, signal: Io.Signal) void {
        assert(signal == .terminate);
        probe.terminate_count += 1;
        probe.seen_at_ns = probe.io.nowNs();
    }
};

test "sim: a recv that can never complete is a detected deadlock" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{ .seed = 13 });

    var pair: PairScenario = .{ .io = &sim_io };
    try pair.establish();

    var probe: RecvProbe = .{};
    sim_io.recv(pair.server, &probe.buffer, &probe.completion, RecvProbe, &probe, RecvProbe.onRecv);
    try std.testing.expectError(error.Deadlock, sim_io.run());
    try std.testing.expectEqual(@as(?(Io.RecvError!u32), null), probe.result);
}
