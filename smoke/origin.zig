//! The live origin behind the Tier-0.5 gate (DESIGN.md §9): a real
//! HTTP/1.1 server on real kernel sockets, served out of the harness
//! process itself by a fixed pool of blocking accept tasks.
//!
//! It is Zig rather than nginx on purpose. Tier 1 spawns nginx because a
//! *band* wants a production-grade origin to measure against; a
//! per-change gate wants the opposite trade. nginx in the CI closure is a
//! new dependency to fetch on every run — devenv.nix keeps that closure
//! to zig plus kcov deliberately — and the gate's verdicts are equalities
//! on zoxy's own output, which no property of the origin's C makes truer.
//! Owning the origin also makes its *deliveries* something the gate can
//! shape, which some of what this tier reaches (a response filling zoxy's
//! head buffer, §7) is a property of.
//!
//! Concurrency is a fixed pool, not a task per connection: the harness's
//! load is a handful of connections it declares up front, so the bound is
//! a static number rather than a policy, and `serve_tasks` is asserted
//! against that load at startup. Each task blocks in `accept` for its
//! whole life; `stop` sets the flag and then wakes every task with a
//! connection of its own, which is what makes shutdown a matter of
//! counting rather than of cancelling a blocking syscall.

const std = @import("std");

const Io = std.Io;

const assert = std.debug.assert;

/// Connections the origin can carry at once. Every parked upstream
/// connection holds a task blocked in `read` until zoxy closes it, so
/// this is a *residency* bound, not a throughput one: it must exceed the
/// harness's peak open-connection count, which `start` asserts.
pub const serve_tasks: u8 = 16;

/// What an ordinary request is answered with. Small on purpose: these
/// bodies price nothing — the gate counts exchanges, it does not time
/// them.
pub const body = "zoxy-smoke-origin\n";

/// The one target answered differently, and the body it carries. This is
/// the shape the simulator cannot build (§9's census exempts
/// `l7_response_excess_sent` because no seed raises the adversary's recv
/// cap that far): a single delivery large enough that the origin's head
/// and the front of its body reach zoxy together and overrun the head
/// buffer, so the excess has to leave in a write of its own.
///
/// It has to exceed the head buffer the harness's config leaves at its
/// default, which smoke/main.zig asserts against its own copy of that
/// number — a drift there fails this gate loudly (the excess count is an
/// equality) rather than quietly stopping to exercise the branch. Written
/// in one call, so the kernel hands it over coalesced.
pub const large_path = "/large";
pub const large_body_bytes: u32 = 32 * 1024;

/// Requests one connection may serve before the origin closes it. A
/// bound, not a policy (TIGER_STYLE): the harness sends two orders of
/// magnitude fewer, so reaching it means the peer is looping.
const requests_per_connection_max: u32 = 4096;

/// Head bytes one request may spend. zoxy's own head buffer is the real
/// limit in front of this; a request that overruns here is a broken peer,
/// answered by dropping the connection.
const request_head_bytes_max: u32 = 2048;

/// Both responses, rendered once at comptime — a target picks one, and
/// nothing else about a request changes a byte of it, so there is nothing
/// to format per exchange.
const response = renderResponse(body);
const large_response = renderResponse(&large_body);

/// A fixed non-uniform fill. Nothing here compresses or dedupes, but a
/// constant byte would make an accidental short read look identical to a
/// correct one in a dump.
const large_body: [large_body_bytes]u8 = blk: {
    @setEvalBranchQuota(8 * large_body_bytes);
    var bytes: [large_body_bytes]u8 = undefined;
    for (&bytes, 0..) |*byte, index| byte.* = @truncate(index);
    break :blk bytes;
};

/// The header this origin tags every response with, so the live gate
/// can name it in `access_log.response_headers` and then find its value
/// in the written log (#140) — the response half of the join, from an
/// origin that is not the proxy.
pub const tag_header = "X-Origin-Tag";
pub const tag_value = "smoke-origin";

fn renderResponse(comptime payload: []const u8) []const u8 {
    return "HTTP/1.1 200 OK\r\n" ++
        std.fmt.comptimePrint("Content-Length: {d}\r\n", .{payload.len}) ++
        "Content-Type: application/octet-stream\r\n" ++
        tag_header ++ ": " ++ tag_value ++ "\r\n" ++
        "\r\n" ++
        payload;
}

comptime {
    // The pool must be able to hold more than one connection or the
    // origin serializes zoxy's data path behind its health probes.
    assert(serve_tasks >= 2);
    assert(requests_per_connection_max >= 1);
    assert(request_head_bytes_max >= 64);
    // The head this origin sends must be a small fraction of the body
    // behind it, or "the delivery filled the head buffer" would be a
    // claim about the head rather than about the body's front.
    assert(large_response.len > large_body_bytes);
    assert(large_response.len - large_body_bytes < 1024);
}

/// One serve task's storage. Static, indexed by task, so a task's buffers
/// do not ride its thread stack.
const TaskBuffers = struct {
    read: [request_head_bytes_max]u8 = undefined,
    /// Sized for the larger response, so either leaves in a single write
    /// — which is the whole point of the large one.
    write: [large_response.len]u8 = undefined,
};

pub const Origin = struct {
    io: Io,
    listener: Io.net.Server,
    /// The kernel-assigned port, read back after `listen` — the harness
    /// never picks it, so it cannot collide with anything.
    port: u16,
    group: Io.Group,
    /// Set by `stop` before it wakes the tasks; every task checks it on
    /// the accept it wakes from.
    stopping: std.atomic.Value(bool),
    /// Requests answered, for the harness's own report. Written by every
    /// task, so it is atomic like every other cross-task field here.
    served: std.atomic.Value(u32),
    buffers: [serve_tasks]TaskBuffers,
    started: bool,

    /// Bind a loopback port, read back which one the kernel gave, and put
    /// every task into `accept`. In-place init through an out-pointer: the
    /// tasks take `*Origin`, so the address has to be the final one.
    ///
    /// `connections_peak` is what the harness will hold open at once,
    /// asserted against the pool here rather than discovered as a hang.
    pub fn start(origin: *Origin, io: Io, connections_peak: u8) !void {
        assert(connections_peak >= 1);
        assert(connections_peak < serve_tasks);
        origin.io = io;
        origin.group = .init;
        origin.stopping = .init(false);
        origin.served = .init(0);
        origin.started = false;
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        origin.listener = try address.listen(io, .{ .mode = .stream });
        origin.port = origin.listener.socket.address.getPort();
        // A kernel-assigned port is never zero; a zero here would mean the
        // harness went on to write ":0" into zoxy's config.
        assert(origin.port != 0);
        var index: u8 = 0;
        while (index < serve_tasks) : (index += 1) {
            try origin.group.concurrent(io, serveTask, .{ origin, index });
        }
        origin.started = true;
    }

    /// Stop accepting and join every task. Sound only once the proxy is
    /// gone: a task serving a parked upstream connection is blocked in
    /// `read` until its peer closes, and nothing here can hurry that.
    ///
    /// The wake is one connection per task rather than a cancellation:
    /// each task consumes at most one — it returns from the accept that
    /// takes it — so `serve_tasks` connections retire the pool however
    /// the tasks are distributed between `accept` and a live exchange.
    pub fn stop(origin: *Origin) void {
        assert(origin.started);
        assert(!origin.stopping.load(.acquire));
        origin.stopping.store(true, .release);
        var index: u8 = 0;
        while (index < serve_tasks) : (index += 1) {
            if (!origin.wake()) {
                // A wake that never lands leaves one task in `accept`
                // forever, and the `await` below would wait for it. Say
                // so here rather than let the harness's own wall-clock
                // budget report it as an unexplained hang.
                std.debug.print("smoke: origin wake {d} never connected\n", .{index});
            }
        }
        // The tasks take no cancellation, so the only way this returns is
        // every one of them having left its accept loop.
        origin.group.await(origin.io) catch {};
        origin.listener.deinit(origin.io);
        origin.started = false;
    }

    /// One task's wake: a connection it will accept and immediately drop.
    /// Retried, because the alternative to a landed wake is a task that
    /// never returns — a loopback connect to a listening socket fails
    /// only under fd or backlog pressure, both of which pass.
    fn wake(origin: *Origin) bool {
        assert(origin.stopping.load(.acquire));
        const attempts_max: u8 = 4;
        var attempt: u8 = 0;
        while (attempt < attempts_max) : (attempt += 1) {
            var address: Io.net.IpAddress = .{ .ip4 = .loopback(origin.port) };
            const stream = address.connect(origin.io, .{ .mode = .stream }) catch continue;
            stream.close(origin.io);
            return true;
        }
        assert(attempt == attempts_max);
        return false;
    }
};

/// One task's whole life: accept, serve to the connection's end, accept
/// again. Every exit is a return, never an error propagated to a caller —
/// the task has none, and a failed connection is the peer's problem, not
/// the origin's.
///
/// The loop is unbounded and terminates for exactly two reasons, which is
/// why it may be: `stop` sets the flag and sends this task a connection
/// of its own, or the listener is gone and `accept` fails. Both are
/// reachable only from `stop`, and each retires exactly one task.
fn serveTask(origin: *Origin, index: u8) void {
    assert(index < serve_tasks);
    const buffers = &origin.buffers[index];
    while (true) {
        const stream = origin.listener.accept(origin.io) catch return;
        if (origin.stopping.load(.acquire)) {
            // The wake `stop` sent, or a straggler that raced it: either
            // way this task is done, having consumed exactly one.
            stream.close(origin.io);
            return;
        }
        serveConnection(origin, stream, buffers);
        stream.close(origin.io);
    }
}

/// Answer requests on one connection until the peer stops asking. Keep-
/// alive is the point: it is what lets zoxy park an upstream connection
/// and reuse it (§3, §5), which is a live shape the simulator's scripted
/// origins do not stand in for.
fn serveConnection(origin: *Origin, stream: Io.net.Stream, buffers: *TaskBuffers) void {
    assert(buffers.read.len == request_head_bytes_max);
    var reader = stream.reader(origin.io, &buffers.read);
    var writer = stream.writer(origin.io, &buffers.write);
    var served: u32 = 0;
    while (served < requests_per_connection_max) : (served += 1) {
        const large = readRequestHead(&reader.interface) orelse return;
        // One `writeAll` into a buffer that holds the whole thing, then
        // one flush: the large response has to reach the kernel as a
        // single write or the delivery it exists to provoke is split
        // before zoxy ever sees it.
        writer.interface.writeAll(if (large) large_response else response) catch return;
        writer.interface.flush() catch return;
        _ = origin.served.fetchAdd(1, .monotonic);
    }
}

/// Read one request head. Only its target matters — one of two responses
/// is chosen by it and nothing else in the head changes a byte — so the
/// answer is whether that target was the large one. Null means the
/// connection is over: an orderly close between requests (what a proxy
/// draining its parked connections looks like), a reset, or a head this
/// origin will not read past.
///
/// No body is read, because none is ever sent: the harness issues GETs
/// and zoxy's health probes are GETs, so a request with a body would be a
/// desync this origin should not paper over.
fn readRequestHead(reader: *Io.Reader) ?bool {
    assert(reader.buffer.len == request_head_bytes_max);
    var large = false;
    var lines: u32 = 0;
    // Every legal head is bounded by its own blank line; the cap is the
    // header count a broken peer could otherwise dribble forever. Two
    // bytes is the shortest a line can be, so no legal head reaches it.
    const lines_max = @divFloor(request_head_bytes_max, 2);
    while (lines < lines_max) : (lines += 1) {
        // A read error, a head line longer than the buffer, and a close
        // between requests are one answer here: this connection is over.
        const taken = reader.takeDelimiter('\n') catch return null;
        const line = taken orelse return null;
        assert(line.len <= request_head_bytes_max);
        // The blank line ends the head. Both spellings are accepted: what
        // arrives here is zoxy's rendering, and the gate is not the place
        // to re-litigate its CRLF discipline (§7 already does).
        if (line.len == 0) return large;
        if (line.len == 1 and line[0] == '\r') return large;
        if (lines == 0) large = requestsLarge(line);
    }
    assert(lines == lines_max);
    return null;
}

/// Does this request line ask for `large_path`? Matched on the target
/// alone, and only as a whole word: `/largest` is an ordinary target, and
/// answering it with 32 KiB would make a typo in the harness look like a
/// proxy bug.
fn requestsLarge(request_line: []const u8) bool {
    assert(request_line.len >= 1);
    const target_start = (std.mem.indexOfScalar(u8, request_line, ' ') orelse return false) + 1;
    if (target_start >= request_line.len) return false;
    const rest = request_line[target_start..];
    const target_end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    return std.mem.eql(u8, rest[0..target_end], large_path);
}
