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
    try xev_io.init(arena_state.allocator(), 0);
    defer xev_io.deinit();

    var scenario: EchoScenario(XevIo) = .{ .io = &xev_io };
    try scenario.start(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0"));
    try xev_io.run();
    try scenario.verify();
}

test "contract: XevIo requests a nonzero IORING_SETUP_CQSIZE depth" {
    // The CQSIZE passthrough (§8, the c10k lever): a nonzero cq_entries must
    // be accepted end-to-end. 16384 is deeper than the kernel's default
    // 2 × 4096, so on io_uring the ring is actually sized to the request;
    // on kqueue the field is ignored and this is a plain init smoke test.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try xev_io.init(arena_state.allocator(), 16384);
    defer xev_io.deinit();

    if (comptime xev.backend == .io_uring) {
        try std.testing.expect(xev_io.loop.ring.cq.cqes.len >= 16384);
    }
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
    try xev_io.init(arena_state.allocator(), 0);
    defer xev_io.deinit();

    // Force a coarse refresh for the baseline too — init() seeds cached_now
    // with a precise read, and the coarse clock lags precise by up to a tick,
    // so comparing across the two sources would spuriously fail.
    xev_io.loop.flags.now_outdated = true;
    const first = xev_io.nowNs();
    // Poison the cache with an obviously-stale value and mark it outdated —
    // exactly the relay-activity case where the old code left the clock
    // frozen. A correct nowNs must refresh *past* the poison; asserting the
    // poison is gone (rather than strict advancement between two reads) also
    // holds for the coarse clock, whose two rapid reads can read equal.
    xev_io.loop.cached_now = .{ .sec = 0, .nsec = 0 };
    xev_io.loop.flags.now_outdated = true;
    const second = xev_io.nowNs();
    try std.testing.expect(second >= first);
}

/// A connected loopback pair and nothing else: the EPIPE test needs two
/// live ends, and `EchoScenario` closes its own when it finishes.
const Pair = struct {
    io: *XevIo,
    accept_completion: XevIo.Completion = .{},
    connect_completion: XevIo.Completion = .{},
    client: ?XevIo.Socket = null,
    server: ?XevIo.Socket = null,

    fn onAccept(pair: *Pair, result: Io.AcceptError!XevIo.Socket) void {
        pair.server = result catch null;
    }

    fn onConnect(pair: *Pair, result: Io.ConnectError!XevIo.Socket) void {
        pair.client = result catch null;
    }
};

test "xevio: a send after our own write shutdown is Reset, not kernel pressure" {
    // Regression for the EPIPE collapse. libxev maps the errno for us
    // (`.PIPE => error.BrokenPipe`), but the send adapter named only
    // ConnectionResetByPeer and Canceled, so BrokenPipe fell into
    // `else => error.Unexpected` — and `witnessKernelPressure` counts
    // Unexpected as the §8 resource rung. A c10k run reported 227,628
    // "kernel pressure" events that were, every one of them, a peer that
    // had left mid-write.
    //
    // This lives here rather than in the simulator because the simulator
    // cannot reach it: SimIo models a gone peer as `error.Reset` directly
    // and never exercises XevIo's mapping at all, so only a real socket
    // proves the arm. EPIPE is made deterministic by shutting down our own
    // write side first — no race with a peer's close.
    //
    // io_uring only. `IORING_OP_WRITE` reports EPIPE through the
    // completion; the kqueue backend writes with a synchronous `write(2)`,
    // which raises SIGPIPE first — and nothing installs a handler for it,
    // so on a macOS dev box this scenario would terminate the test binary
    // rather than fail it. Skipping is honest: the arm under test is the
    // io_uring adapter's, and the kqueue path never reaches it.
    if (comptime xev.backend != .io_uring) return error.SkipZigTest;

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try xev_io.init(arena_state.allocator(), 0);
    defer xev_io.deinit();

    // A connected loopback pair through the seam's own API — the echo
    // scenario closes both ends when it finishes, so this needs its own.
    var pair: Pair = .{ .io = &xev_io };
    const listener = try xev_io.listen(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0"));
    xev_io.accept(listener, &pair.accept_completion, Pair, &pair, Pair.onAccept);
    xev_io.connect(
        xev_io.listenerAddress(listener),
        &pair.connect_completion,
        Pair,
        &pair,
        Pair.onConnect,
    );
    try xev_io.run();
    const client = pair.client orelse return error.ConnectNeverCompleted;
    // Stated positively like its sibling: defaulting this to `client` would
    // defer a double close, which trips `closeFd`'s errno assertion instead
    // of reporting that the accept never landed.
    const server = pair.server orelse return error.AcceptNeverCompleted;
    defer xev_io.closeNow(client);
    defer xev_io.closeNow(server);
    xev_io.listenClose(listener);

    // Half-close our own write side, then write: the kernel answers EPIPE,
    // deterministically — no race with the peer's close.
    const socket = client;
    xev_io.shutdown(socket, .write);

    var outcome: ?Io.SendError!u32 = null;
    var completion: XevIo.Completion = .{};
    xev_io.send(socket, "after-shutdown", &completion, @TypeOf(outcome), &outcome, (struct {
        fn onSend(state: *?Io.SendError!u32, result: Io.SendError!u32) void {
            state.* = result;
        }
    }).onSend);
    try xev_io.run();

    const result = outcome orelse return error.SendNeverCompleted;
    // The verdict that matters: a peer that is gone, not a kernel short of
    // resources. `Unexpected` here is what put ordinary disconnects on the
    // pressure rung.
    try std.testing.expectError(error.Reset, result);
}

test "xevio: bind failures are diagnosed distinctly, not all AddressInUse" {
    // Regression for the bind-error collapse (review finding 5): an
    // address that is not assigned to this host (TEST-NET-3, RFC 5737)
    // must report AddressUnavailable — "address in use" would send an
    // operator hunting for a conflicting process that does not exist.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try xev_io.init(arena_state.allocator(), 0);
    defer xev_io.deinit();

    const unavailable = std.Io.net.IpAddress.parseLiteral("203.0.113.1:0") catch unreachable;
    try std.testing.expectError(error.AddressUnavailable, xev_io.listen(unavailable));
}

test "xevio: SO_REUSEPORT lets two listeners share one port" {
    // Process-per-port scale-out (§1, §3): several zoxy instances bind the
    // same port and the kernel load-balances across them. Proven in-process
    // by binding two listeners to one concrete port — without SO_REUSEPORT
    // the second bind fails EADDRINUSE. SO_REUSEADDR alone (which libxev
    // sets inside bind) does not permit two live listeners on one port, so
    // this test fails if the REUSEPORT option is dropped.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try xev_io.init(arena_state.allocator(), 0);
    defer xev_io.deinit();

    // First listener takes an ephemeral port; read the concrete port back.
    const first = try xev_io.listen(
        std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable,
    );
    const port = xev_io.listenerAddress(first).getPort();
    try std.testing.expect(port != 0);

    // A second listener on the very same port must also succeed.
    var shared = std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable;
    shared.setPort(port);
    const second = try xev_io.listen(shared);
    try std.testing.expectEqual(port, xev_io.listenerAddress(second).getPort());
}
