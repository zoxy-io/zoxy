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
        if (comptime XevIo.backend == .io_uring) {
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

/// How many draws the fill contract takes. Every byte position must be
/// written by at least one of them; a backend that left a position alone
/// would have to draw the sentinel there `random_draws` times running,
/// which at 1/256 per draw is not a flake anyone will meet.
const random_draws: u8 = 8;
const random_sentinel: u8 = 0xAA;

/// What `fillRandom` owes its callers, whichever backend answers: every
/// byte of the request is written, and two draws do not repeat. Key
/// material is the one thing the data path cannot check for itself — a
/// stuck source produces a handshake that looks perfectly well-formed.
fn runRandomContract(comptime IoType: type, io: *IoType) !void {
    var draws: [random_draws][Io.random_bytes_max]u8 = @splat(@splat(random_sentinel));
    for (&draws) |*draw| {
        io.fillRandom(draw[0..]);
    }

    // Every position written by someone.
    for (0..Io.random_bytes_max) |index| {
        var untouched = true;
        for (&draws) |*draw| {
            if (draw[index] != random_sentinel) untouched = false;
        }
        try std.testing.expect(!untouched);
    }

    // No two draws alike: a source that answers once and then repeats
    // would satisfy the check above and still be useless.
    for (0..random_draws) |first| {
        for (first + 1..random_draws) |second| {
            try std.testing.expect(!std.mem.eql(u8, &draws[first], &draws[second]));
        }
    }

    // A short request writes exactly what was asked for and nothing past it.
    var bounded: [Io.random_bytes_max]u8 = @splat(random_sentinel);
    io.fillRandom(bounded[0..1]);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{random_sentinel} ** (Io.random_bytes_max - 1),
        bounded[1..],
    );
}

test "contract: fillRandom on SimIo" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{ .seed = 7 });
    try runRandomContract(SimIo, &sim_io);
}

test "contract: fillRandom on XevIo" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try initTestIo(&xev_io, arena_state.allocator(), 0);
    defer xev_io.deinit();
    try runRandomContract(XevIo, &xev_io);
}

// `abort` is the one seam decl this file cannot run on both backends,
// and the asymmetry is the point rather than a gap: XevIo's *is* a
// process exit, so calling it would take the test runner with it. What
// holds it to the contract is the compile-time `required_decls` check
// (`assertIoInterface`) plus `Server.onDrainStuck`'s single caller,
// which is gated on SimIo in `admin_test.zig` (the stuck-drain test).
// Recorded here with the other per-arm verdicts above, so it is decided
// rather than omitted.
test "simio: abort records the code and stops the loop" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{ .seed = 11 });
    try std.testing.expectEqual(@as(?u8, null), sim_io.abortedWith());

    sim_io.abort(4);
    try std.testing.expectEqual(@as(?u8, 4), sim_io.abortedWith());
    // Stopped, so `run` returns rather than draining what is left: a
    // process that has given up does not take another tick.
    try sim_io.run();
    try std.testing.expectEqual(@as(?u8, 4), sim_io.abortedWith());
}

const DroppedAccept = struct {
    io: *SimIo,
    completion: SimIo.Completion = .{},
    outcome: ?(Io.AcceptError!SimIo.Socket) = null,

    fn onAccept(self: *DroppedAccept, result: Io.AcceptError!SimIo.Socket) void {
        assert(self.outcome == null);
        self.outcome = result;
    }
};

// #206's whole point, in the shape #203 took: an accept the backend
// took and then never delivered, so the op stays armed for the rest of
// the process's life and whatever is waiting on it waits forever.
test "simio: a dropped accept is never delivered, where a live one is" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    // The control first: closing a listener completes its armed accept
    // with Canceled, which is what every backend the seam supports does
    // and what the rest of this simulator has always modelled.
    var live_io: SimIo = undefined;
    try live_io.init(arena_state.allocator(), .{ .seed = 3 });
    var live: DroppedAccept = .{ .io = &live_io };
    const live_listener = try live_io.listen(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9301"));
    live_io.accept(live_listener, &live.completion, DroppedAccept, &live, DroppedAccept.onAccept);
    live_io.listenClose(live_listener);
    try live_io.run();
    try std.testing.expectError(error.Canceled, live.outcome.?);

    // Now the same sequence with the accept dropped. The close still
    // happens; the completion never comes. `run` has nothing left that
    // can become ready and nothing that ever will, which is a deadlock —
    // and a deadlock is exactly what a hung process looks like from
    // inside, so this is the outcome the gate wants to see.
    var stuck_io: SimIo = undefined;
    try stuck_io.init(arena_state.allocator(), .{
        .seed = 3,
        // The hang is the assertion, so its forensics are noise here.
        .dump_on_deadlock = false,
    });
    var stuck: DroppedAccept = .{ .io = &stuck_io };
    const stuck_listener = try stuck_io.listen(try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9301"));
    stuck_io.accept(
        stuck_listener,
        &stuck.completion,
        DroppedAccept,
        &stuck,
        DroppedAccept.onAccept,
    );
    // What the sweep picks a kind to strand from (`sim/Harness.zig`):
    // armed now, and *not* armed once taken, so a later pick cannot spend
    // itself on ops that are already stranded.
    try std.testing.expect(stuck_io.hasPendingOp(.accept));
    try std.testing.expect(!stuck_io.hasPendingOp(.recv));
    try std.testing.expectEqual(@as(u32, 1), stuck_io.dropPendingOps(.accept));
    try std.testing.expect(!stuck_io.hasPendingOp(.accept));
    stuck_io.listenClose(stuck_listener);
    try std.testing.expectError(error.Deadlock, stuck_io.run());
    try std.testing.expect(stuck.outcome == null);

    // And dropping what is not armed is a no-op that says so, so a
    // scenario can tell "I dropped it" from "there was nothing to drop".
    try std.testing.expectEqual(@as(u32, 0), stuck_io.dropPendingOps(.recv));
}

const StrandedTimer = struct {
    io: *SimIo,
    completion: SimIo.Completion = .{},
    fired: bool = false,

    fn onTimer(self: *StrandedTimer, result: Io.TimerError!void) void {
        result catch return;
        self.fired = true;
    }
};

// #206: the one shape §8's drain backstop cannot catch, pinned so it
// breaks loudly if it ever stops being true.
//
// `Server.onDrainStuck` is a timer. A backend that strands timers strands
// that one too, so the process has nothing left to notice with and the
// run ends in the simulator's deadlock rather than in a diagnostic. The
// sweep therefore does not draw `.timer` (see `sim/Harness.zig`), which
// would otherwise fail honest seeds — this is where the limitation lives
// instead of only in a comment. Covering it for real needs a watchdog
// that is not a timer, which is a design question and not a gate.
test "simio: a stranded timer has nothing left to report it" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{
        .seed = 17,
        // The deadlock is the assertion; its forensics are noise here.
        .dump_on_deadlock = false,
    });

    var watchdog: StrandedTimer = .{ .io = &sim_io };
    sim_io.timerStart(
        &watchdog.completion,
        std.time.ns_per_s,
        StrandedTimer,
        &watchdog,
        StrandedTimer.onTimer,
    );
    try std.testing.expectEqual(@as(u32, 1), sim_io.dropPendingOps(.timer));

    try std.testing.expectError(error.Deadlock, sim_io.run());
    // Stated as an assertion rather than left implicit: the watchdog
    // never ran, so whatever it was watching went unreported.
    try std.testing.expect(!watchdog.fired);
    try std.testing.expectEqual(@as(?u8, null), sim_io.abortedWith());
}

const LatchedCancel = struct {
    timer: SimIo.Completion = .{},
    cancel: SimIo.Completion = .{},
    timer_delivered: bool = false,
    cancel_delivered: bool = false,

    fn onTimer(self: *LatchedCancel, result: Io.TimerError!void) void {
        result catch {};
        self.timer_delivered = true;
    }

    fn onCancel(self: *LatchedCancel) void {
        self.cancel_delivered = true;
    }
};

// #206's second strand, pinned: `armDropNext` waits for an op that is in
// no table yet — the cancel a teardown arms once the drain is already
// under way — where `dropPendingOps` can only take what is armed now.
//
// The end state is what makes it the #203 shape. The cancel never lands,
// so the caller's armed set never empties and its slot is never released;
// the timer it was cancelling completes on its own schedule, so nothing
// about the run *looks* stuck from the inside. Only a backstop that
// notices the drain never finished can report it.
test "simio: a latched cancel is stranded when it is finally submitted" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{
        .seed = 23,
        // The deadlock is the assertion; its forensics are noise here.
        .dump_on_deadlock = false,
    });

    var state: LatchedCancel = .{};
    sim_io.timerStart(
        &state.timer,
        std.time.ns_per_ms,
        LatchedCancel,
        &state,
        LatchedCancel.onTimer,
    );
    // Armed while the only pending op is one the latch is not waiting for:
    // nothing is taken until the cancel below is submitted.
    sim_io.armDropNext(&[_]SimIo.OpKind{ .timer_cancel, .connect_cancel });
    try std.testing.expectEqual(@as(?SimIo.OpKind, null), sim_io.droppedNextOp());

    sim_io.timerCancel(&state.timer, &state.cancel, LatchedCancel, &state, LatchedCancel.onCancel);
    try std.testing.expectEqual(@as(?SimIo.OpKind, .timer_cancel), sim_io.droppedNextOp());

    try std.testing.expectError(error.Deadlock, sim_io.run());
    // The cancel never delivered, so whoever armed it still counts it as
    // in flight — and the timer it named ran to completion instead of
    // being cancelled, which is why nothing else looks wrong.
    try std.testing.expect(!state.cancel_delivered);
    try std.testing.expect(state.timer_delivered);
}

// #202: some bounds are measured in hours against scenarios that run for
// a virtual second. XevIo has no counterpart and needs none — this is
// scenario control like `injectLogWriteError`, not a seam decl.
test "simio: a wall-clock step leaves the monotonic clock alone" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var sim_io: SimIo = undefined;
    try sim_io.init(arena_state.allocator(), .{ .seed = 13 });
    const mono_before = sim_io.nowNs();
    const wall_before = sim_io.nowWallNs();

    const step_ns: u64 = 6 * 60 * 60 * std.time.ns_per_s;
    sim_io.advanceWallClock(step_ns);

    // The asymmetry is the point: moving the monotonic clock instead
    // would fire every armed deadline at once, which is a different
    // scenario and not a useful one.
    try std.testing.expectEqual(mono_before, sim_io.nowNs());
    try std.testing.expectEqual(wall_before + step_ns, sim_io.nowWallNs());

    // Steps accumulate rather than replace, so a scenario can cross a
    // bound twice.
    sim_io.advanceWallClock(step_ns);
    try std.testing.expectEqual(wall_before + 2 * step_ns, sim_io.nowWallNs());
    try std.testing.expectEqual(mono_before, sim_io.nowNs());
}

test "simio: one seed replays one key stream, and a different seed does not" {
    // The §9 property TLS rides on: a seeded run's handshake is byte-exact,
    // which is only true if the key material replays with everything else.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var first: SimIo = undefined;
    var again: SimIo = undefined;
    var other: SimIo = undefined;
    try first.init(arena, .{ .seed = 42 });
    try again.init(arena, .{ .seed = 42 });
    try other.init(arena, .{ .seed = 43 });

    var first_bytes: [64]u8 = undefined;
    var again_bytes: [64]u8 = undefined;
    var other_bytes: [64]u8 = undefined;
    first.fillRandom(&first_bytes);
    again.fillRandom(&again_bytes);
    other.fillRandom(&other_bytes);

    try std.testing.expectEqualSlices(u8, &first_bytes, &again_bytes);
    try std.testing.expect(!std.mem.eql(u8, &first_bytes, &other_bytes));
}

test "simio: drawing key material does not move the adversary's stream" {
    // Why `key_prng` is its own stream: if TLS drew from `prng`, adding one
    // handshake would re-roll every later scheduling decision in the
    // scenario — silently re-rolling the sweep's non-TLS coverage while the
    // sweep still reported green.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var undrawn: SimIo = undefined;
    var drawn: SimIo = undefined;
    try undrawn.init(arena, .{ .seed = 11 });
    try drawn.init(arena, .{ .seed = 11 });

    var key_bytes: [32]u8 = undefined;
    drawn.fillRandom(&key_bytes);

    try std.testing.expectEqual(
        undrawn.prng.random().int(u64),
        drawn.prng.random().int(u64),
    );
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

    if (comptime XevIo.backend == .io_uring) {
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
    if (comptime XevIo.backend != .io_uring) return error.SkipZigTest;

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
    if (comptime XevIo.backend != .io_uring) return error.SkipZigTest;

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

/// The same-tick drain shape (#203): an accept armed inside one callback
/// and the listener closed inside another, with no loop submission in
/// between. That is the admin plane's own sequence — `onAccept` re-arms,
/// and the signal completion's `beginDrain` runs later in the same tick's
/// batch — and it is the shape `DrainCloser` above deliberately does not
/// have, because there the accept is submitted before the close.
const SameTickDrain = struct {
    io: *XevIo,
    listener: XevIo.Listener,
    arm_timer: XevIo.Completion = .{},
    close_timer: XevIo.Completion = .{},
    accept_completion: XevIo.Completion = .{},
    outcome: ?(Io.AcceptError!XevIo.Socket) = null,
    armed: bool = false,
    closed: bool = false,

    fn onArm(drain: *SameTickDrain, result: Io.TimerError!void) void {
        // The only TimerError is Canceled, and nothing cancels this timer.
        result catch unreachable;
        // The close must not have run first, or the test is asserting
        // about a listener that was already gone.
        assert(!drain.closed);
        drain.io.accept(
            drain.listener,
            &drain.accept_completion,
            SameTickDrain,
            drain,
            onAccept,
        );
        drain.armed = true;
    }

    fn onClose(drain: *SameTickDrain, result: Io.TimerError!void) void {
        result catch unreachable;
        assert(drain.armed);
        drain.io.listenClose(drain.listener);
        drain.closed = true;
    }

    fn onAccept(drain: *SameTickDrain, result: Io.AcceptError!XevIo.Socket) void {
        assert(drain.outcome == null);
        drain.outcome = result;
    }
};

test "xevio: closing a listener cancels an accept armed in the same tick" {
    // #203: the accept above is armed from outside the loop, so the
    // backend has submitted it by the time the close lands. The admin
    // plane's is not — it is re-armed from `onAccept` and the drain runs
    // in the same tick — and a backend that only delivers a cancelled
    // accept it has already submitted orphans that one. Same contract as
    // the test above, one tick earlier.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var xev_io: XevIo = undefined;
    try initTestIo(&xev_io, arena_state.allocator(), 0);
    defer xev_io.deinit();

    const listener = try xev_io.listen(
        std.Io.net.IpAddress.parseLiteral("127.0.0.1:0") catch unreachable,
    );
    var drain: SameTickDrain = .{ .io = &xev_io, .listener = listener };
    // Both at zero: one tick's timer batch runs both callbacks, with no
    // submission between them — which is the whole point.
    xev_io.timerStart(&drain.arm_timer, 0, SameTickDrain, &drain, SameTickDrain.onArm);
    xev_io.timerStart(&drain.close_timer, 0, SameTickDrain, &drain, SameTickDrain.onClose);
    try xev_io.run();

    const result = drain.outcome orelse return error.AcceptNeverCompleted;
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
    if (comptime XevIo.backend != .io_uring) return error.SkipZigTest;

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
    if (comptime XevIo.backend == .io_uring) {
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
    if (comptime XevIo.backend != .io_uring) return error.SkipZigTest;

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
