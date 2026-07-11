//! The two-backend contract suite (§9): one generic echo scenario runs
//! byte-identically against `SimIo` (virtual sockets, adversarial
//! scheduling) and `XevIo` (real loopback through io_uring). A sim that
//! is kinder than the kernel proves nothing — this file is what keeps
//! the two backends semantically aligned.

const std = @import("std");
const xev = @import("xev");

const Io = @import("io.zig");
const SimIo = @import("SimIo.zig");
const XevIo = @import("XevIo.zig");

const assert = std.debug.assert;

pub const echo_token = "echo-contract-token-0123456789abcdef";

/// Client sends the token, server echoes it back and FINs, client sees
/// EndOfStream and closes both ends plus the listener. Every send and
/// recv loops on partial completions, so 1-byte adversarial deliveries
/// and real short writes take the same paths.
pub fn EchoScenario(comptime IoType: type) type {
    Io.assertIoInterface(IoType);

    return struct {
        io: *IoType,
        listener: IoType.Listener = undefined,
        accept_completion: IoType.Completion = .{},
        connect_completion: IoType.Completion = .{},
        client: Peer = .{},
        server: Peer = .{},
        failed: bool = false,

        const Scenario = @This();

        const Peer = struct {
            socket: IoType.Socket = undefined,
            recv_completion: IoType.Completion = .{},
            send_completion: IoType.Completion = .{},
            received: [128]u8 = undefined,
            received_len: u32 = 0,
            sent_len: u32 = 0,
            eof: bool = false,
        };

        pub fn start(scenario: *Scenario, bind_address: std.Io.net.IpAddress) !void {
            scenario.listener = try scenario.io.listen(bind_address);
            scenario.io.accept(
                scenario.listener,
                &scenario.accept_completion,
                Scenario,
                scenario,
                onAccept,
            );
            scenario.io.connect(
                scenario.io.listenerAddress(scenario.listener),
                &scenario.connect_completion,
                Scenario,
                scenario,
                onConnect,
            );
        }

        pub fn verify(scenario: *const Scenario) !void {
            try std.testing.expect(!scenario.failed);
            try std.testing.expect(scenario.client.eof);
            try std.testing.expectEqualStrings(
                echo_token,
                scenario.server.received[0..scenario.server.received_len],
            );
            try std.testing.expectEqualStrings(
                echo_token,
                scenario.client.received[0..scenario.client.received_len],
            );
        }

        fn onAccept(scenario: *Scenario, result: Io.AcceptError!IoType.Socket) void {
            scenario.server.socket = result catch return scenario.fail();
            scenario.armServerRecv();
        }

        fn onConnect(scenario: *Scenario, result: Io.ConnectError!IoType.Socket) void {
            scenario.client.socket = result catch return scenario.fail();
            scenario.armClientSend();
        }

        fn armClientSend(scenario: *Scenario) void {
            assert(scenario.client.sent_len < echo_token.len);
            scenario.io.send(
                scenario.client.socket,
                echo_token[scenario.client.sent_len..],
                &scenario.client.send_completion,
                Scenario,
                scenario,
                onClientSend,
            );
        }

        fn onClientSend(scenario: *Scenario, result: Io.SendError!u32) void {
            const n = result catch return scenario.fail();
            scenario.client.sent_len += n;
            assert(scenario.client.sent_len <= echo_token.len);
            if (scenario.client.sent_len < echo_token.len) {
                scenario.armClientSend();
            } else {
                scenario.armClientRecv();
            }
        }

        fn armServerRecv(scenario: *Scenario) void {
            scenario.io.recv(
                scenario.server.socket,
                scenario.server.received[scenario.server.received_len..],
                &scenario.server.recv_completion,
                Scenario,
                scenario,
                onServerRecv,
            );
        }

        fn onServerRecv(scenario: *Scenario, result: Io.RecvError!u32) void {
            const n = result catch return scenario.fail();
            scenario.server.received_len += n;
            assert(scenario.server.received_len <= echo_token.len);
            if (scenario.server.received_len < echo_token.len) {
                scenario.armServerRecv();
            } else {
                scenario.armServerSend();
            }
        }

        fn armServerSend(scenario: *Scenario) void {
            assert(scenario.server.sent_len < scenario.server.received_len);
            scenario.io.send(
                scenario.server.socket,
                scenario.server.received[scenario.server.sent_len..scenario.server.received_len],
                &scenario.server.send_completion,
                Scenario,
                scenario,
                onServerSend,
            );
        }

        fn onServerSend(scenario: *Scenario, result: Io.SendError!u32) void {
            const n = result catch return scenario.fail();
            scenario.server.sent_len += n;
            assert(scenario.server.sent_len <= scenario.server.received_len);
            if (scenario.server.sent_len < scenario.server.received_len) {
                scenario.armServerSend();
            } else {
                // Echo done: announce the close with a FIN (§6 half-close).
                scenario.io.shutdown(scenario.server.socket, .write);
            }
        }

        fn armClientRecv(scenario: *Scenario) void {
            scenario.io.recv(
                scenario.client.socket,
                scenario.client.received[scenario.client.received_len..],
                &scenario.client.recv_completion,
                Scenario,
                scenario,
                onClientRecv,
            );
        }

        fn onClientRecv(scenario: *Scenario, result: Io.RecvError!u32) void {
            const n = result catch |err| {
                if (err != error.EndOfStream) return scenario.fail();
                scenario.client.eof = true;
                scenario.io.closeNow(scenario.client.socket);
                scenario.io.closeNow(scenario.server.socket);
                scenario.io.listenClose(scenario.listener);
                return;
            };
            scenario.client.received_len += n;
            assert(scenario.client.received_len <= echo_token.len);
            scenario.armClientRecv();
        }

        fn fail(scenario: *Scenario) void {
            scenario.failed = true;
            scenario.io.stop();
        }
    };
}

test "contract: echo on SimIo under the adversary" {
    var seed: u64 = 1;
    while (seed <= 20) : (seed += 1) {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();

        var sim_io: SimIo = undefined;
        try sim_io.init(arena_state.allocator(), .{
            .seed = seed,
            .adversary = .{ .partial_io = true, .connect_delay_ns_max = 5_000_000 },
        });

        var scenario: EchoScenario(SimIo) = .{ .io = &sim_io };
        try scenario.start(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0"));
        try sim_io.run();
        try scenario.verify();
        try std.testing.expect(sim_io.sockets.isFullyReleased());
    }
}

test "contract: echo on XevIo over real loopback" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try xev_io.init(arena_state.allocator());
    defer xev_io.deinit();

    var scenario: EchoScenario(XevIo) = .{ .io = &xev_io };
    try scenario.start(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0"));
    try xev_io.run();
    try scenario.verify();
}

test "xevio: nowNs refreshes a stale clock instead of returning a frozen value" {
    // Regression for the stale-cached_now bug (review finding 1): the
    // io_uring backend only marks the clock outdated per tick and refreshes
    // it lazily, so nowNs must refresh when the flag is set rather than
    // returning the time of the last timer arm. The monotonic clock strictly
    // advances between two update_now syscalls, so a correct nowNs returns a
    // larger value on the second read; the buggy version returned the frozen
    // cached_now unchanged.
    //
    // io_uring-only: other backends (kqueue on macOS) refresh cached_now
    // every tick and have no now_outdated flag to simulate staleness with.
    if (comptime !@hasField(@FieldType(xev.Loop, "flags"), "now_outdated")) {
        return error.SkipZigTest;
    }
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try xev_io.init(arena_state.allocator());
    defer xev_io.deinit();

    const first = xev_io.nowNs();
    // Simulate a tick elapsing without a timer being armed — exactly the
    // relay-activity case where the old code left the clock frozen.
    xev_io.loop.flags.now_outdated = true;
    const second = xev_io.nowNs();
    try std.testing.expect(second > first);
}

test "xevio: bind failures are diagnosed distinctly, not all AddressInUse" {
    // Regression for the bind-error collapse (review finding 5): an
    // address that is not assigned to this host (TEST-NET-3, RFC 5737)
    // must report AddressUnavailable — "address in use" would send an
    // operator hunting for a conflicting process that does not exist.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try xev_io.init(arena_state.allocator());
    defer xev_io.deinit();

    const unavailable = std.Io.net.IpAddress.parseLiteral("203.0.113.1:0") catch unreachable;
    try std.testing.expectError(error.AddressUnavailable, xev_io.listen(unavailable));
}
