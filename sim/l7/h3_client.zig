//! The simulation gate's HTTP/3 client (#449): QUIC to the terminating
//! listener's binding, a few requests sent once the handshake confirms,
//! and the per-stream oracle HTTP/2's exchange population holds.
//!
//! A stream asks what an HTTP/2 stream asks (`H2Plan`): `get`'s GET,
//! `consult_get`'s, or a marked POST whose length is declared or not, so
//! the same origin answers it and the same canonical bodies judge it. Its
//! transport is zoxy's own test client (`zoxy.http.h3.TestClient`) — h3's
//! client connection over the seam's datagrams, and zssl's QUIC client for
//! its handshake — because a QUIC client written here would be a second
//! implementation to trust. What this adds is the plans, the requests they
//! become, and the oracle. The seam's datagram adversary is what this
//! population meets that no other does: datagrams dropped, duplicated,
//! delayed past their successors, corrupted, and sent from a rebound port.
//!
//! The oracle is per stream, and holds on every seed: an answer carries a
//! status its script allows and, for a 200, a canonical body — or, on a
//! stream cut short, a prefix of one. On clean seeds it hardens: every
//! stream ends in a 200 and a whole canonical body.

const std = @import("std");
const zoxy = @import("zoxy");
const canon = @import("canon.zig");
const scripts = @import("scripts.zig");
const h2_client = @import("h2_client.zig");

const TestClient = zoxy.http.h3.TestClient;
const assert = std.debug.assert;

pub const Plan = h2_client.Plan;
/// Requests one client sends, each on its own stream.
const requests_max: u8 = TestClient.requests_max;
/// A POST's largest body: it goes in the same write as its head.
pub const body_bytes_max: u32 = TestClient.request_body_bytes_max;

pub const ClientError = error{
    /// A final status outside its script's allowed set.
    StatusUnexpected,
    /// A 200 body that is not a canonical origin body, nor a prefix of one
    /// on a stream that was cut short.
    BodyCorrupted,
    /// A clean seed whose streams did not all end in a whole 200.
    GoldenOutcomeMissed,
};

/// `<length>.<salt>` at its widest, and a length's digits.
const mark_bytes_max: u32 = 24;
const length_bytes_max: u32 = 10;

pub fn Client(comptime IoType: type) type {
    const Transport = TestClient.TestClient(IoType);

    return struct {
        const Self = @This();
        /// Requests one client sends, as `H2Client.streams_max` names its own.
        pub const streams_max: u8 = requests_max;

        transport: Transport,
        io: *IoType,
        address: std.Io.net.IpAddress,
        plans: [requests_max]Plan,
        streams: u8,
        salt: u32,
        clean: bool,
        seed: [64]u8,
        requests: [requests_max]TestClient.Request,
        headers: [requests_max][3]TestClient.Field,
        marks: [requests_max][mark_bytes_max]u8,
        lengths: [requests_max][length_bytes_max]u8,
        bodies: [requests_max][body_bytes_max]u8,
        began: bool,
        ended: bool,
        on_ended: ?*const fn (?*anyopaque) void,
        context: ?*anyopaque,

        /// Its streams' requests, built now: they borrow this client's
        /// storage for the whole run.
        pub fn prepare(
            client: *Self,
            io: *IoType,
            address: std.Io.net.IpAddress,
            plans: []const Plan,
            salt: u32,
            clean: bool,
            seed: [64]u8,
        ) void {
            assert(plans.len >= 1);
            assert(plans.len <= requests_max);
            client.io = io;
            client.address = address;
            client.streams = @intCast(plans.len);
            client.salt = salt;
            client.clean = clean;
            client.seed = seed;
            client.began = false;
            client.ended = false;
            client.on_ended = null;
            client.context = null;
            for (plans, 0..) |plan, index| {
                client.plans[index] = plan;
                client.requests[index] = client.requestFor(@intCast(index));
            }
        }

        /// The HTTP/3 request stream `index` makes of its plan: traced as
        /// the HTTP/2 population's are, and a POST's body marked with its
        /// length and this client's salt, which the origin checks octet by
        /// octet.
        fn requestFor(client: *Self, index: u8) TestClient.Request {
            const plan = client.plans[index];
            const headers = &client.headers[index];
            headers[0] = .{ .name = canon.log_request_header, .value = canon.log_request_value };
            if (!plan.carriesBody()) {
                return .{ .method = "GET", .path = plan.path(), .headers = headers[0..1] };
            }
            assert(plan.body_len >= 1);
            assert(plan.body_len <= body_bytes_max);
            const salt = client.salt * requests_max + index;
            const mark = std.fmt.bufPrint(&client.marks[index], "{d}.{d}", .{ plan.body_len, salt }) catch unreachable;
            headers[1] = .{ .name = canon.request_body_header, .value = mark };
            var count: usize = 2;
            if (plan.ask == .post_declared) {
                const length = std.fmt.bufPrint(&client.lengths[index], "{d}", .{plan.body_len}) catch unreachable;
                headers[2] = .{ .name = "content-length", .value = length };
                count = 3;
            }
            const body = client.bodies[index][0..plan.body_len];
            for (body, 0..) |*octet, position| octet.* = canon.requestBodyOctet(salt, @intCast(position));
            return .{ .method = "POST", .path = plan.path(), .headers = headers[0..count], .body = body };
        }

        pub fn begin(client: *Self) void {
            assert(!client.began);
            client.began = true;
            client.transport.start(
                client.io,
                client.address,
                client.requests[0..client.streams],
                client.seed,
                onDone,
                client,
            ) catch return client.end(); // No socket to bind: nothing ran.
        }

        fn onDone(context: *anyopaque) void {
            const client: *Self = @ptrCast(@alignCast(context));
            client.end();
        }

        fn end(client: *Self) void {
            if (client.ended) return;
            client.ended = true;
            if (client.on_ended) |hook| hook(client.context);
        }

        /// The scenario is over with this client still going — a handshake
        /// the adversary starved, an answer that never came: it closes now,
        /// and lets go of its socket once the close is out.
        pub fn cancelIfStuck(client: *Self) void {
            if (client.ended) return;
            if (!client.began) return;
            client.transport.abandon();
        }

        /// The run has ended. The server stops the loop once its own drain
        /// is done, so a client still closing — its close sent, a tick or
        /// its receive's cancel still to deliver — is left as it is: its
        /// socket has nothing armed against the server, and the simulator
        /// it was bound on is the seed's alone. A clean seed's golden
        /// outcome is what demands every answer arrived (`verify`).
        pub fn closeIfOpen(client: *Self) void {
            if (!client.began) return;
            if (client.transport.done) assert(client.ended);
        }

        /// The oracle, over every answer that came back. `max_lifetime_ns`
        /// is the age cap (§6), zero when none is set: a hard end that cuts
        /// whatever its connection has in flight, on a clean seed as on any.
        pub fn verify(client: *const Self, max_lifetime_ns: u64) ClientError!void {
            assert(client.streams >= 1);
            assert(client.streams <= requests_max);
            // The one cut a clean seed allows: the server's graceful close,
            // seen no sooner than the cap past this client's start. That is a
            // lower bound on the cap's own close, not the close itself: the
            // connection is born a handshake later, and this client cannot see
            // when. A close inside that handshake's width passes too; one
            // before it does not.
            const capped = max_lifetime_ns != 0 and client.began and
                client.transport.peerClosedGracefully(max_lifetime_ns);
            for (client.plans[0..client.streams], client.transport.answers[0..client.streams]) |plan, *answer| {
                const allowed = scripts.spec(plan.scriptOf()).allowed_statuses;
                if (answer.status != 0 and std.mem.indexOfScalar(u16, allowed, answer.status) == null) {
                    return error.StatusUnexpected;
                }
                if (answer.status == 200) try checkBody(answer, client.clean);
                if (!client.clean or capped) continue;
                if (answer.status != 200) return error.GoldenOutcomeMissed;
                if (!answer.finished) return error.GoldenOutcomeMissed;
            }
        }

        /// A 200's body is a canonical one — whole once the stream ended,
        /// a prefix of one on a stream cut short — as HTTP/2's oracle has
        /// it (`h2_client.checkBody`).
        fn checkBody(answer: *const TestClient.Answer, clean: bool) ClientError!void {
            assert(answer.status == 200);
            if (answer.body_len > TestClient.body_bytes_max) return error.BodyCorrupted;
            const body = answer.bodyBytes();
            for (h2_client.canonical_bodies) |canonical| {
                if (answer.finished and std.mem.eql(u8, body, canonical)) return;
                if (!answer.finished and std.mem.startsWith(u8, canonical, body)) return;
            }
            if (clean) return error.BodyCorrupted;
            if (answer.finished and std.mem.startsWith(u8, canon.until_close_body, body)) return;
            return error.BodyCorrupted;
        }
    };
}
