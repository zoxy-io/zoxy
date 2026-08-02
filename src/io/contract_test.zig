//! The two-backend contract suite (§9): one generic echo scenario runs
//! byte-identically against `SimIo` (virtual sockets, adversarial
//! scheduling) and `XevIo` (real loopback through io_uring). A sim that
//! is kinder than the kernel proves nothing — this file is what keeps
//! the two backends semantically aligned.
//!
//! It is also the home of seam-translation coverage (issue #106, kind D):
//! `SimIo` is a different backend and never runs XevIo's errno mapping,
//! so every named arm there is either pinned here on a real socket or
//! has a written verdict below — decided per arm, never by omission.
//!
//!   listen  AddressInUse       tested: the squatted-port test.
//!   listen  AddressUnavailable tested: the TEST-NET-3 bind test.
//!   listen  AccessDenied       tested, environment-guarded: the
//!           privileged-port test skips where the port is grantable.
//!   accept  Canceled           tested: the listener-close cancel test.
//!   connect Refused            tested: the closed-port dial test.
//!   connect Canceled           tested: the stuck-dial cancel test.
//!   connect Unreachable        not tested: EHOSTUNREACH needs a
//!           packet-dropping route (root-only netns setup) and the
//!           TimedOut spelling needs seconds of dropped SYNs; the map is
//!           a straight rename of the fork's named errors and the §8
//!           dial-deadline behavior above it is sim-covered. Revisit if
//!           a netns harness ever lands.
//!   recv    EndOfStream        tested: the echo scenario's FIN path.
//!   recv    Reset              tested on io_uring: the linger-RST recv
//!           test. The kqueue backend cannot pass it — its data-op maps
//!           name only CANCELED, so an RST lands as Unexpected there
//!           (found by this test's first macOS CI run; fork queue).
//!   send    Reset (EPIPE)      tested: the write-shutdown send test.
//!   send    Reset (ECONNRESET) not tested directly: pinning the errno
//!           needs a send already blocked when the RST lands — an
//!           unread-data close races the submission otherwise. The arm
//!           shares its map target with EPIPE and its errno with the
//!           recv test's pin, so a regression cannot change what the
//!           caller observes.
//!   recv/send Canceled         unreachable through the seam today: no
//!           caller cancels a data op (§5 cancels connects and timers
//!           only); the arms stay mapped for a future drain that does.
//!   *       else => Unexpected the honest fallback: witnessed as §8
//!           pressure with the raw errno kept by the fork
//!           (`result_errno`). Two known peer-gone errnos still land
//!           there — ENETUNREACH on connect, ETIMEDOUT on the data ops —
//!           because the fork leaves them unnamed; naming them is queued
//!           in docs/IMPLEMENTATION_NOTES.md ("Open questions" — libxev
//!           fork queue).

const std = @import("std");
const xev = @import("xev");

const Io = @import("io.zig");
const SimIo = @import("SimIo.zig");
const XevIo = @import("XevIo.zig");

const assert = std.debug.assert;
const posix = std.posix;

const init_attempts_max: u8 = 5;

/// Every test builds its ring through this. io_uring ring teardown is
/// deferred in the kernel, so on a saturated box (the parallel ci
/// graph) freed rings outlive their test long enough that a fresh
/// io_uring_setup transiently hits the per-user accounting ceiling —
/// ENOMEM with gigabytes free. Measured 2026-07-28 on the 8 MiB-memlock
/// dev box: twelve sequential rings never fail, the parallel gate
/// failed about half its runs at around the tenth. A bounded retry
/// with a short pause is the honest answer to a transient; production
/// creates one ring at startup and must keep failing loudly.
/// `listeners_reserved` is what the old `listeners_max` used to supply
/// implicitly: contract tests bind a handful of sockets, so a small fixed
/// reservation covers every scenario here.
const listeners_reserved: u32 = 8;
/// Every test ring registers a small provided-buffer group, sized so the
/// group tests can exhaust it on purpose while the rest never notice it.
const buffer_group_count: u32 = 2;
const buffer_group_bytes: u32 = 512;

fn initTestIo(xev_io: *XevIo, arena: std.mem.Allocator, cq_entries: u32) !void {
    var attempt: u8 = 1;
    while (true) : (attempt += 1) {
        assert(attempt <= init_attempts_max);
        if (XevIo.init(
            xev_io,
            arena,
            cq_entries,
            listeners_reserved,
            buffer_group_count,
            buffer_group_bytes,
            XevIo.log_sink_stdout,
            null,
        )) |_| {
            return;
        } else |err| {
            if (err != error.SystemResources) return err;
            if (attempt == init_attempts_max) return err;
        }
        // The pause is what lets the kernel's deferred frees land; the
        // phenomenon (and the branch) is io_uring-only.
        if (comptime xev.backend == .io_uring) {
            const pause: std.os.linux.timespec = .{
                .sec = 0,
                .nsec = 20 * std.time.ns_per_ms,
            };
            _ = std.os.linux.nanosleep(&pause, null);
        }
    }
}

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
    try initTestIo(&xev_io, arena_state.allocator(), 0);
    defer xev_io.deinit();

    var scenario: EchoScenario(XevIo) = .{ .io = &xev_io };
    try scenario.start(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0"));
    try xev_io.run();
    try scenario.verify();
}

/// The provided-buffer group contract, one story over any backend: a
/// group-recv binds a buffer only when data arrives; a mid-message
/// continuation is a classic recv into the bound buffer; exhaustion is
/// `NoBuffers` delivered as a completion; a returned buffer is selectable
/// again; and EOF consumes nothing. Driven under the SimIo adversary
/// (splits every delivery) and over XevIo's real loopback alike.
fn GroupContract(comptime IoType: type) type {
    Io.assertIoInterface(IoType);
    return struct {
        io: *IoType,
        accept_completion: IoType.Completion = .{},
        connect_completion: IoType.Completion = .{},
        op_completion: IoType.Completion = .{},
        accepted: ?IoType.Socket = null,
        connected: ?IoType.Socket = null,
        sent: ?u32 = null,
        group: ?(Io.RecvGroupError!Io.GroupRecv) = null,
        classic: ?(Io.RecvError!u32) = null,

        const Contract = @This();
        const payload = "0123456789abcdefghijklmnopqrstuvwxyz-ok!";

        fn onAccept(c: *Contract, result: Io.AcceptError!IoType.Socket) void {
            c.accepted = result catch null;
        }
        fn onConnect(c: *Contract, result: Io.ConnectError!IoType.Socket) void {
            c.connected = result catch null;
        }
        fn onSend(c: *Contract, result: Io.SendError!u32) void {
            c.sent = result catch 0;
        }
        fn onGroup(c: *Contract, result: Io.RecvGroupError!Io.GroupRecv) void {
            c.group = result;
        }
        fn onClassic(c: *Contract, result: Io.RecvError!u32) void {
            c.classic = result;
        }

        fn pair(c: *Contract, listener: IoType.Listener) !struct { IoType.Socket, IoType.Socket } {
            c.accepted = null;
            c.connected = null;
            c.accept_completion = .{};
            c.connect_completion = .{};
            c.io.accept(listener, &c.accept_completion, Contract, c, onAccept);
            c.io.connect(
                c.io.listenerAddress(listener),
                &c.connect_completion,
                Contract,
                c,
                onConnect,
            );
            try c.io.run();
            return .{
                c.connected orelse return error.ConnectNeverCompleted,
                c.accepted orelse return error.AcceptNeverCompleted,
            };
        }

        /// Send the whole payload, looping on the short writes both the
        /// adversary and a real kernel may deal.
        fn sendAll(c: *Contract, socket: IoType.Socket) !void {
            var offset: u32 = 0;
            while (offset < payload.len) {
                c.sent = null;
                c.op_completion = .{};
                c.io.send(socket, payload[offset..], &c.op_completion, Contract, c, onSend);
                try c.io.run();
                const n = c.sent orelse return error.SendNeverCompleted;
                if (n == 0) return error.SendFailed;
                offset += n;
            }
        }

        /// Group-recv the payload's first bytes, then continue with
        /// classic recvs into the bound buffer — the §5 head-read shape.
        fn recvWholePayload(c: *Contract, socket: IoType.Socket) !u16 {
            c.group = null;
            c.op_completion = .{};
            c.io.recvGroup(socket, &c.op_completion, Contract, c, onGroup);
            try c.io.run();
            const first = try (c.group orelse return error.RecvNeverCompleted);
            try std.testing.expect(first.len >= 1);
            const buffer = c.io.bufferGroupSlice(first.buffer_id);
            var total: u32 = first.len;
            while (total < payload.len) {
                c.classic = null;
                c.op_completion = .{};
                c.io.recv(socket, buffer[total..], &c.op_completion, Contract, c, onClassic);
                try c.io.run();
                total += try (c.classic orelse return error.RecvNeverCompleted);
            }
            try std.testing.expectEqualSlices(u8, payload, buffer[0..payload.len]);
            return first.buffer_id;
        }

        /// One armed group-recv, one delivery, whatever it carries.
        fn recvOnce(c: *Contract, socket: IoType.Socket) !Io.RecvGroupError!Io.GroupRecv {
            c.group = null;
            c.op_completion = .{};
            c.io.recvGroup(socket, &c.op_completion, Contract, c, onGroup);
            try c.io.run();
            return c.group orelse return error.RecvNeverCompleted;
        }
    };
}

/// The story needs a group of exactly two 512-byte buffers — what the
/// XevIo test harness registers, and what the SimIo variant passes.
fn runGroupContract(comptime IoType: type, io: *IoType) !void {
    const Contract = GroupContract(IoType);
    var c: Contract = .{ .io = io };
    const listener = try io.listen(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0"));

    // Selection, and the classic-recv continuation into the bound buffer.
    const client_a, const server_a = try c.pair(listener);
    try c.sendAll(client_a);
    const id_a = try c.recvWholePayload(server_a);

    // Second delivery binds the other buffer; the group is now empty.
    const client_b, const server_b = try c.pair(listener);
    try c.sendAll(client_b);
    const id_b = try c.recvWholePayload(server_b);
    try std.testing.expect(id_a != id_b);

    // Exhaustion: data waiting, group empty — NoBuffers as a completion.
    const client_c, const server_c = try c.pair(listener);
    try c.sendAll(client_c);
    try std.testing.expectError(error.NoBuffers, try c.recvOnce(server_c));

    // Return one buffer and the same bytes deliver into it: with exactly
    // one buffer in the group, every backend must select it.
    io.bufferGroupReturn(id_a);
    const retry = try (try c.recvOnce(server_c));
    try std.testing.expectEqual(id_a, retry.buffer_id);
    try std.testing.expect(retry.len >= 1);
    io.bufferGroupReturn(retry.buffer_id);
    io.bufferGroupReturn(id_b);

    // EOF consumes nothing: after the peer closes, both buffers must
    // still be selectable — two concurrent data deliveries prove it.
    io.closeNow(client_a);
    const eof = try c.recvOnce(server_a);
    try std.testing.expectError(error.EndOfStream, eof);
    try c.sendAll(client_b);
    const after_b = try (try c.recvOnce(server_b));
    try c.sendAll(client_c);
    const after_c = try (try c.recvOnce(server_c));
    try std.testing.expect(after_b.buffer_id != after_c.buffer_id);
    io.bufferGroupReturn(after_b.buffer_id);
    io.bufferGroupReturn(after_c.buffer_id);

    io.closeNow(server_a);
    for ([_]IoType.Socket{ client_b, server_b, client_c, server_c }) |socket| {
        io.closeNow(socket);
    }
    io.listenClose(listener);
}

test "contract: the provided-buffer group on SimIo under the adversary" {
    var seed: u64 = 1;
    while (seed <= 10) : (seed += 1) {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();

        var sim_io: SimIo = undefined;
        try sim_io.init(arena_state.allocator(), .{
            .seed = seed,
            .adversary = .{ .partial_io = true, .connect_delay_ns_max = 5_000_000 },
            .buffer_group_count = 2,
            .buffer_group_bytes = 512,
        });
        try runGroupContract(SimIo, &sim_io);
        try std.testing.expect(sim_io.sockets.isFullyReleased());
        try std.testing.expectEqual(@as(u32, 0), sim_io.group_in_use);
    }
}

test "contract: the provided-buffer group on XevIo over real loopback" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try initTestIo(&xev_io, arena_state.allocator(), 0);
    defer xev_io.deinit();
    try runGroupContract(XevIo, &xev_io);
}

test "contract: XevIo requests a nonzero IORING_SETUP_CQSIZE depth" {
    // The CQSIZE passthrough (§8, the c10k lever): a nonzero cq_entries must
    // be accepted end-to-end. 16384 is deeper than the kernel's default
    // 2 × 4096, so on io_uring the ring is actually sized to the request;
    // on kqueue the field is ignored and this is a plain init smoke test.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try initTestIo(&xev_io, arena_state.allocator(), 16384);
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
    try initTestIo(&xev_io, arena_state.allocator(), 0);
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

const ConnectedPair = struct {
    listener: XevIo.Listener,
    client: XevIo.Socket,
    server: XevIo.Socket,
};

/// Establish a connected loopback pair through the seam's own API. The
/// `Pair` completions have both delivered when this returns, so the
/// stack-local scaffolding can die here.
fn connectPair(xev_io: *XevIo) !ConnectedPair {
    var pair: Pair = .{ .io = xev_io };
    const listener = try xev_io.listen(
        std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable,
    );
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
    const server = pair.server orelse return error.AcceptNeverCompleted;
    assert(client != server);
    assert(xev_io.listenerAddress(listener).getPort() != 0);
    return .{ .listener = listener, .client = client, .server = server };
}

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
    try initTestIo(&xev_io, arena_state.allocator(), 0);
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
    try initTestIo(&xev_io, arena_state.allocator(), 0);
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
    try initTestIo(&xev_io, arena_state.allocator(), 0);
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

/// Sync close for fds the tests create outside the seam (a squatter, a
/// backlog filler). Mirrors XevIo's own closeFd discipline, INTR
/// tolerance included.
fn closeRawFd(fd: posix.socket_t) void {
    const rc = posix.system.close(fd);
    const errno = posix.errno(rc);
    assert(errno == .SUCCESS or errno == .INTR);
}

/// A raw loopback sockaddr for the one test that must dial outside the
/// seam (the backlog filler's blocking connect).
fn loopbackSockaddr(port: u16) posix.sockaddr.in {
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
}

test "xevio: a port squatted without SO_REUSEPORT is AddressInUse" {
    // The AddressInUse arm of the listen map. zoxy's own listeners share
    // ports via SO_REUSEPORT, so producing a genuine conflict needs a
    // squatter that did NOT set it — then the REUSEPORT bind fails
    // EADDRINUSE, and the diagnosis must say "in use", not "unavailable".
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try initTestIo(&xev_io, arena_state.allocator(), 0);
    defer xev_io.deinit();

    // xev.TCP.init sets no REUSEPORT (XevIo.listen adds it separately),
    // which is exactly the squatter this conflict needs.
    const squat_address = std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable;
    const squatter = try xev.TCP.init(squat_address);
    defer closeRawFd(squatter.fd);
    try squatter.bind(squat_address);
    try squatter.listen(1);
    const port = try XevIo.boundPort(squatter.fd);
    assert(port != 0);

    var shared = std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable;
    shared.setPort(port);
    try std.testing.expectError(error.AddressInUse, xev_io.listen(shared));
}

test "xevio: binding a privileged port without the capability is AccessDenied" {
    // The AccessDenied arm of the listen map: port 1 needs
    // CAP_NET_BIND_SERVICE. Where the environment grants low ports anyway
    // (root, or a container with ip_unprivileged_port_start=0) there is
    // nothing to prove — skip rather than fail, but never accept a third
    // diagnosis: a wrong arm here sends an operator hunting for a
    // conflicting process that does not exist.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try initTestIo(&xev_io, arena_state.allocator(), 0);
    defer xev_io.deinit();

    const privileged = std.Io.net.IpAddress.parseLiteral("127.0.0.1:1") catch unreachable;
    if (xev_io.listen(privileged)) |listener| {
        xev_io.listenClose(listener);
        return error.SkipZigTest;
    } else |err| {
        try std.testing.expectEqual(Io.ListenError.AccessDenied, err);
    }
}

test "xevio: a dial to a closed loopback port is Refused" {
    // The Refused arm of the connect map: bind an ephemeral port to learn
    // a concrete number, close it, dial it. The kernel answers RST —
    // ECONNREFUSED is the origin's verdict (§8), never the pressure rung.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try initTestIo(&xev_io, arena_state.allocator(), 0);
    defer xev_io.deinit();

    const listener = try xev_io.listen(
        std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable,
    );
    const address = xev_io.listenerAddress(listener);
    assert(address.getPort() != 0);
    xev_io.listenClose(listener);

    var outcome: ?(Io.ConnectError!XevIo.Socket) = null;
    var completion: XevIo.Completion = .{};
    xev_io.connect(address, &completion, @TypeOf(outcome), &outcome, (struct {
        fn onConnect(
            state: *?(Io.ConnectError!XevIo.Socket),
            result: Io.ConnectError!XevIo.Socket,
        ) void {
            state.* = result;
        }
    }).onConnect);
    try xev_io.run();

    const result = outcome orelse return error.ConnectNeverCompleted;
    try std.testing.expectError(error.Refused, result);
}

/// The drain-shaped closer for the accept-cancel test: production closes
/// listeners from inside the running loop (a signal's callback), and the
/// cancel contract only holds for an accept the ring has actually seen —
/// a listenClose before run() would close the fd under an unsubmitted op.
const DrainCloser = struct {
    io: *XevIo,
    listener: XevIo.Listener,
    timer_completion: XevIo.Completion = .{},

    fn onTimer(closer: *DrainCloser, result: Io.TimerError!void) void {
        // The only TimerError is Canceled, and nothing cancels this timer.
        result catch unreachable;
        closer.io.listenClose(closer.listener);
    }
};

test "xevio: closing a listener cancels its armed accept" {
    // The Canceled arm of the accept map — the §8 drain contract on a
    // real ring: an io_uring op holds its own file reference, so
    // listenClose must reap the armed accept through an async cancel and
    // the accept must terminate with error.Canceled — never hang, never
    // invent a socket.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try initTestIo(&xev_io, arena_state.allocator(), 0);
    defer xev_io.deinit();

    const listener = try xev_io.listen(
        std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable,
    );
    var outcome: ?(Io.AcceptError!XevIo.Socket) = null;
    var completion: XevIo.Completion = .{};
    xev_io.accept(listener, &completion, @TypeOf(outcome), &outcome, (struct {
        fn onAccept(
            state: *?(Io.AcceptError!XevIo.Socket),
            result: Io.AcceptError!XevIo.Socket,
        ) void {
            state.* = result;
        }
    }).onAccept);
    var closer: DrainCloser = .{ .io = &xev_io, .listener = listener };
    xev_io.timerStart(&closer.timer_completion, 0, DrainCloser, &closer, DrainCloser.onTimer);
    try xev_io.run();

    const result = outcome orelse return error.AcceptNeverCompleted;
    try std.testing.expectError(error.Canceled, result);
}

test "xevio: a recv against a linger-RST close is Reset, with the errno pinned" {
    // The ConnectionResetByPeer arm of the read map, deterministic by
    // construction: the close(2) below fires the RST before run() ever
    // submits the recv, so the op completes with ECONNRESET — the peer's
    // verdict (error.Reset), never EOF and never the §8 pressure rung.
    //
    // io_uring only: the arm under test is the io_uring adapter's. The
    // kqueue backend's data-op maps name only CANCELED, so on the macOS
    // dev box the RST arrives as error.Unexpected — the same
    // peer-gone-as-pressure gap the fork queue tracks
    // (docs/IMPLEMENTATION_NOTES.md, "Open questions"), which this test
    // would otherwise report as its own failure.
    if (comptime xev.backend != .io_uring) return error.SkipZigTest;

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try initTestIo(&xev_io, arena_state.allocator(), 0);
    defer xev_io.deinit();

    const pair = try connectPair(&xev_io);
    defer xev_io.closeNow(pair.client);
    xev_io.listenClose(pair.listener);

    var outcome: ?(Io.RecvError!u32) = null;
    var buffer: [16]u8 = undefined;
    var completion: XevIo.Completion = .{};
    xev_io.recv(pair.client, &buffer, &completion, @TypeOf(outcome), &outcome, (struct {
        fn onRecv(state: *?(Io.RecvError!u32), result: Io.RecvError!u32) void {
            state.* = result;
        }
    }).onRecv);
    try xev_io.setLingerRst(pair.server);
    xev_io.closeNow(pair.server);
    try xev_io.run();

    const result = outcome orelse return error.RecvNeverCompleted;
    try std.testing.expectError(error.Reset, result);
    // Pin WHICH arm fired: the errno the fork kept must be the reset,
    // so this cannot silently start passing via a future EOF mapping.
    if (comptime xev.backend == .io_uring) {
        try std.testing.expectEqual(posix.E.CONNRESET, completion.result_errno);
    }
}

test "xevio: canceling a stuck dial delivers Canceled and releases the op" {
    // The Canceled arm of the connect map — the §5 reap for a black-holed
    // dial, built from loopback parts: a raw listener with a zero backlog
    // whose only queue slot a raw filler already holds. The victim's SYN
    // is dropped by the full accept queue, so the dial pends in
    // retransmission until the cancel terminates it.
    //
    // io_uring only: the arm under test is the io_uring adapter's, and
    // BSD accept-queue overflow answers RST where Linux drops — the
    // pending-dial premise does not hold on the kqueue dev box.
    if (comptime xev.backend != .io_uring) return error.SkipZigTest;

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try initTestIo(&xev_io, arena_state.allocator(), 0);
    defer xev_io.deinit();

    const stuck_address = std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable;
    const stuck_listener = try xev.TCP.init(stuck_address);
    defer closeRawFd(stuck_listener.fd);
    try stuck_listener.bind(stuck_address);
    try stuck_listener.listen(0);
    const port = try XevIo.boundPort(stuck_listener.fd);
    assert(port != 0);

    // Blocking connect: returns established, occupying the single slot.
    const filler = try xev.TCP.init(stuck_address);
    defer closeRawFd(filler.fd);
    var filler_sockaddr = loopbackSockaddr(port);
    const rc = std.os.linux.connect(
        filler.fd,
        @ptrCast(&filler_sockaddr),
        @sizeOf(posix.sockaddr.in),
    );
    if (posix.errno(rc) != .SUCCESS) return error.FillerConnectFailed;

    var address = std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable;
    address.setPort(port);
    var outcome: ?(Io.ConnectError!XevIo.Socket) = null;
    var connect_completion: XevIo.Completion = .{};
    xev_io.connect(address, &connect_completion, @TypeOf(outcome), &outcome, (struct {
        fn onConnect(
            state: *?(Io.ConnectError!XevIo.Socket),
            result: Io.ConnectError!XevIo.Socket,
        ) void {
            state.* = result;
        }
    }).onConnect);
    var canceled = false;
    var cancel_completion: XevIo.Completion = .{};
    xev_io.connectCancel(&connect_completion, &cancel_completion, bool, &canceled, (struct {
        fn onCanceled(state: *bool) void {
            state.* = true;
        }
    }).onCanceled);
    try xev_io.run();

    try std.testing.expect(canceled);
    const result = outcome orelse return error.ConnectNeverCompleted;
    try std.testing.expectError(error.Canceled, result);
}

test "xevio: the listener table reserves a slot for the admin listener" {
    // Regression for slice 4 of the operator-sized-limits change, which
    // sized this table to exactly the *configured* listener count. The
    // admin listener binds through the same `listen`, so every
    // admin-enabled deployment failed to start with `AddressUnavailable`
    // — a full table reported as a bad address. Nothing caught it:
    // `Server(XevIo)` is instantiated only by main.zig, and admin_test
    // runs over SimIo.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    // One configured listener; capacity must be that plus the admin slot.
    // No buffer group — the zero-count arm must also keep init working.
    try XevIo.init(&xev_io, arena_state.allocator(), 0, 1, 0, 1, XevIo.log_sink_stdout, null);
    defer xev_io.deinit();

    const loopback = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:0");
    const configured = try xev_io.listen(loopback);
    _ = configured;
    // The admin listener: this is the bind that used to fail.
    const admin = try xev_io.listen(loopback);
    _ = admin;

    // And the reservation is exactly one — not open-ended.
    try std.testing.expectError(error.AddressUnavailable, xev_io.listen(loopback));
}
