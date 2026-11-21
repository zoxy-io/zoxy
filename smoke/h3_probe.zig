//! The live gate's HTTP/3 client (#449): zoxy's own test client
//! (`zoxy.http.h3.TestClient`) over the real io_uring backend, against the
//! shipped binary's QUIC binding. A process of its own, so the harness
//! itself still links nothing of zssl or libcrypto: it spawns this as it
//! spawns the proxy, and judges the one line this prints.
//!
//! Independent HTTP/3 implementations are the merge tier's — h3spec, and
//! curl over ngtcp2 by hand. What this adds is the every-change claim: the
//! shipped build, on a real kernel, serves an HTTP/3 request end to end —
//! datagrams, the handshake, the session, the origin and back — and the
//! ReleaseSafe twin does too.

const std = @import("std");
const zoxy = @import("zoxy");

const TestClient = zoxy.http.h3.TestClient;
const XevIo = zoxy.XevIo;
const Client = TestClient.TestClient(XevIo);

const assert = std.debug.assert;

/// Requests the probe sends, all on one connection: the harness's own
/// `h3_requests`, which it reads back off the verdict line.
const requests_count: u32 = 3;
/// What the run may take before the probe gives up and says so: a
/// handshake and three answers on loopback take milliseconds, and the
/// harness's whole-run watchdog is 30 s.
const deadline_ns: u64 = 5 * std.time.ns_per_s;
/// The smoke origin's answer to every request (smoke/origin.zig).
const origin_body = "zoxy-smoke-origin\n";

var io: XevIo = undefined;
var client: Client = undefined;
var deadline: XevIo.Completion = .{};
var timed_out = false;

/// The correlation header every request the gate sends carries, which the
/// access log must report (#140; `smoke/client.zig`'s, lowercased as HTTP/3
/// requires).
const request_id: []const TestClient.Field = &.{.{ .name = "x-request-id", .value = "smoke-req-1" }};

/// The terminating listener routes by host `127.0.0.1` (smoke/main.zig).
const requests = [_]TestClient.Request{
    .{ .path = "/h3/one", .authority = "127.0.0.1", .headers = request_id },
    .{ .path = "/h3/two", .authority = "127.0.0.1", .headers = request_id },
    .{ .path = "/h3/three", .authority = "127.0.0.1", .headers = request_id },
};

comptime {
    assert(requests.len == requests_count);
    assert(requests_count <= TestClient.requests_max);
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3 or !std.mem.eql(u8, args[1], "--port")) {
        std.debug.print("usage: zoxy-smoke-h3 --port <quic port>\n", .{});
        return 2;
    }
    const port = try std.fmt.parseInt(u16, args[2], 10);
    assert(port != 0);
    // No listener of its own, no head ring, no access log: a client.
    try io.init(arena, zoxy.constants.ring_entries, 0, 0, zoxy.constants.head_buffer_bytes_min, XevIo.log_sink_stdout, null);
    var seed: [64]u8 = undefined;
    io.fillRandom(&seed);
    seed[32] |= 1; // A key share's private half may not be zero.
    try client.start(&io, .{ .ip4 = .loopback(port) }, &requests, seed, onDone, &client);
    io.timerStart(&deadline, deadline_ns, Client, &client, onDeadline);
    try io.run();
    return verdict();
}

fn onDone(context: *anyopaque) void {
    assert(context == @as(*anyopaque, &client));
    assert(client.done);
    io.stop();
}

fn onDeadline(owner: *Client, result: zoxy.Io.TimerError!void) void {
    assert(owner == &client);
    // Nothing cancels the deadline: the loop stops with it still armed.
    result catch unreachable;
    if (client.done) return;
    timed_out = true;
    io.stop();
}

/// One line: `h3: ok N` when every answer is a whole 200 with the origin's
/// body, and what went wrong otherwise.
fn verdict() u8 {
    if (timed_out) {
        std.debug.print("h3: FAIL no answer within {d} s\n", .{deadline_ns / std.time.ns_per_s});
        return 1;
    }
    // The loop stops on the deadline or on the client's end, and the
    // deadline keeps it from running dry before either.
    assert(client.done);
    assert(client.answers.len >= requests_count);
    for (client.answers[0..requests_count], 0..) |*answer, index| {
        if (answer.status != 200 or !answer.finished) {
            std.debug.print("h3: FAIL request {d} answered {d} (finished: {})\n", .{ index, answer.status, answer.finished });
            return 1;
        }
        if (!std.mem.eql(u8, answer.bodyBytes(), origin_body)) {
            std.debug.print("h3: FAIL request {d} carried {d} body bytes, not the origin's\n", .{ index, answer.body_len });
            return 1;
        }
    }
    std.debug.print("h3: ok {d}\n", .{requests_count});
    return 0;
}
