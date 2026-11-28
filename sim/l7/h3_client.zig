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
    /// An origin's 200 arrived with no interim head, on a seed whose
    /// origin prefixes one to every answer (#232).
    InterimUnrelayed,
    /// A trailer section (§7) other than the trailing origin's one field,
    /// after anything but its whole chunked 200, or more than one.
    TrailersCorrupted,
    /// A stream that finished whole without the trailer section its head
    /// owed, or with one it did not; or a head that carried HTTP/1.1's
    /// `Trailer` announcement across the mapping.
    TrailersMismatched,
    /// A violator's request was answered, as if it had been one.
    ViolationAnswered,
    /// A violator's stream was reset, or its connection closed, with a
    /// code other than the one RFC 9114 or RFC 9204 owes it.
    ViolationCodeUnexpected,
    /// A clean seed's violator never heard its owed answer.
    ViolationUnanswered,
    /// A session keyed under a suite its hello did not offer, or — on a
    /// clean seed — a narrowed offer that never keyed one at all.
    SuiteUnoffered,
};

/// What a client's QUIC hello offers: every suite, AES-128-GCM first, or
/// one alone — which is how the sweep keys sessions under the two the
/// server's preference never picks (RFC 8446 §B.4, RFC 9001 §5).
pub const SuiteOffer = enum(u8) {
    every,
    chacha20_only,
    aes256_only,

    pub const narrowed = [_]SuiteOffer{ .chacha20_only, .aes256_only };

    /// The suite a narrowed offer keys under; null for `every`.
    pub fn only(offer: SuiteOffer) ?TestClient.CipherSuite {
        return switch (offer) {
            .every => null,
            .chacha20_only => .chacha20_poly1305_sha256,
            .aes256_only => .aes_256_gcm_sha384,
        };
    }

    /// The hello's list: static, since the handshake keeps the slice.
    fn list(offer: SuiteOffer) []const TestClient.CipherSuite {
        return switch (offer) {
            .every => TestClient.offer_default,
            .chacha20_only => &[_]TestClient.CipherSuite{.chacha20_poly1305_sha256},
            .aes256_only => &[_]TestClient.CipherSuite{.aes_256_gcm_sha384},
        };
    }
};

/// An HTTP/3 client that breaks the rules once, on its first stream, and
/// what each is owed (`owed`). Every other stream it opens is an ordinary
/// one: a stream error leaves them to be answered, a connection error
/// may cut them.
pub const Violation = enum(u8) {
    none,
    /// A field name with an uppercase letter (RFC 9114 §4.2): malformed, so
    /// that stream is reset with H3_MESSAGE_ERROR (§4.1.2).
    malformed_field,
    /// A field section naming a dynamic table entry the server never
    /// offered (RFC 9204 §2.2): QPACK_DECOMPRESSION_FAILED closes the
    /// connection.
    qpack_failure,
    /// DATA before any HEADERS on a request stream (RFC 9114 §4.1):
    /// H3_FRAME_UNEXPECTED closes the connection.
    frame_unexpected,

    pub const violations = [_]Violation{ .malformed_field, .qpack_failure, .frame_unexpected };

    pub const Owed = union(enum) {
        /// The violating stream's reset, with this code.
        reset: u64,
        /// The connection's close, with this application code.
        close: u64,
    };

    pub fn owed(violation: Violation) ?Owed {
        return switch (violation) {
            .none => null,
            .malformed_field => .{ .reset = TestClient.code_message_error },
            .qpack_failure => .{ .close = TestClient.code_qpack_decompression_failed },
            .frame_unexpected => .{ .close = TestClient.code_frame_unexpected },
        };
    }
};

const malformed_fields = [_]TestClient.Field{.{ .name = "X-Upper", .value = "1" }};
/// HEADERS whose one representation is the dynamic table's entry 0, in a
/// table of no capacity.
const undecodable_section = [_]u8{ 0x00, 0x00, 0x80 };
/// A DATA frame of one octet, where the request's HEADERS must come first.
const data_first = [_]u8{ 0x00, 0x01, 'x' };

/// The trailing origin's section as the test client keeps it.
const canonical_trailer_line = canon.response_trailer_name ++ ": " ++ canon.response_trailer_value ++ "\r\n";

/// A POST's trailer section, when its plan ends with one (§7): the proxy
/// ends the request there and carries it no further.
const request_trailers = [_]TestClient.Field{
    .{ .name = canon.request_trailer_name, .value = canon.request_trailer_value },
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
        /// The name its hello asks for (#297).
        server_name: []const u8,
        plans: [requests_max]Plan,
        streams: u8,
        salt: u32,
        clean: bool,
        /// Set by the harness after `prepare`: the seed's origin prefixes an
        /// interim `100` to every answer (#232).
        interim_owed: bool,
        /// Set by the harness after `prepare` (`breakRules`).
        violation: Violation,
        /// Set by the harness after `prepare`.
        suite_offer: SuiteOffer,
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
            server_name: []const u8,
        ) void {
            assert(plans.len >= 1);
            assert(plans.len <= requests_max);
            assert(server_name.len >= 1);
            client.io = io;
            client.address = address;
            client.server_name = server_name;
            client.streams = @intCast(plans.len);
            client.salt = salt;
            client.clean = clean;
            client.interim_owed = false;
            client.violation = .none;
            client.suite_offer = .every;
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

        /// The HTTP/3 request stream `index` makes of its plan: traced
        /// with HTTP/3's own value (`canon.log_request_h3_value`), so the
        /// access log's clean-seed rule can tell its aborts apart, and a
        /// POST's body marked with its length and this client's salt, which
        /// the origin checks octet by octet.
        fn requestFor(client: *Self, index: u8) TestClient.Request {
            const plan = client.plans[index];
            // gRPC calls are HTTP/2's alone in the sweep (`prepareH2Client`).
            assert(plan.ask != .grpc_call);
            const headers = &client.headers[index];
            headers[0] = .{ .name = canon.log_request_header, .value = canon.log_request_h3_value };
            if (plan.ask == .not_modified) {
                headers[1] = .{ .name = "if-none-match", .value = canon.not_modified_etag };
                return .{ .method = "GET", .path = plan.path(), .headers = headers[0..2] };
            }
            if (!plan.carriesBody()) {
                return .{ .method = plan.method(), .path = plan.path(), .headers = headers[0..1] };
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
            const trailers: []const TestClient.Field = if (plan.trailers) &request_trailers else &.{};
            return .{ .method = "POST", .path = plan.path(), .headers = headers[0..count], .body = body, .trailers = trailers };
        }

        pub fn begin(client: *Self) void {
            assert(!client.began);
            client.began = true;
            client.transport.startOffering(
                client.io,
                client.address,
                client.requests[0..client.streams],
                client.seed,
                client.server_name,
                client.suite_offer.list(),
                onDone,
                client,
            ) catch return client.end(); // No socket to bind: nothing ran.
        }

        /// Break the rules once, on the first stream, in `violation`'s way:
        /// its request is replaced, and the rest are sent as planned.
        pub fn breakRules(client: *Self, violation: Violation) void {
            assert(!client.began);
            assert(client.violation == .none);
            client.violation = violation;
            client.requests[0] = switch (violation) {
                .none => return,
                .malformed_field => .{ .method = "GET", .path = "/sim", .headers = &malformed_fields },
                .qpack_failure => .{ .raw_section = &undecodable_section },
                .frame_unexpected => .{ .raw_stream = &data_first },
            };
        }

        /// The violation this client's run answered as owed, for the census
        /// (§9); read once `verify` has passed.
        pub fn violationAnswered(client: *const Self) ?Violation {
            const owed = client.violation.owed() orelse return null;
            assert(client.violation != .none);
            if (!heardOwed(&client.transport, owed)) return null;
            return client.violation;
        }

        /// The public key of the leaf the server showed, or null before
        /// one arrived (#297).
        pub fn serverPublicKey(client: *const Self) ?[]const u8 {
            return client.transport.serverPublicKey();
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
            try client.verifySuite();
            const owed = client.violation.owed();
            if (owed) |violation| try client.verifyViolation(violation);
            // A connection error may cut what else was in flight.
            const cut_allowed = if (owed) |violation| violation == .close else false;
            for (client.plans[0..client.streams], client.transport.answers[0..client.streams], 0..) |plan, *answer, index| {
                if (owed != null and index == 0) continue; // Judged above.
                const allowed = scripts.spec(plan.scriptOf()).allowed_statuses;
                if (answer.status != 0 and std.mem.indexOfScalar(u16, allowed, answer.status) == null) {
                    return error.StatusUnexpected;
                }
                try checkTrailers(answer);
                try checkTrailersOwed(answer);
                const bodiless = answer.status == 304 or plan.ask == .head_only;
                if (bodiless and answer.body_len != 0) return error.BodyCorrupted;
                // The origin's HEAD 200 says the length a GET would carry
                // (RFC 9110 §9.3.2), and the proxy relays it.
                if (plan.ask == .head_only and answer.status == 200) {
                    const length = headLine(answer.headBytes(), "content-length") orelse return error.BodyCorrupted;
                    if (!std.mem.eql(u8, length, "32")) return error.BodyCorrupted;
                }
                if (answer.status == 200 and !bodiless) try checkBody(answer, client.clean);
                // A 204 has no content to frame (RFC 9110 §15.3.5, §8.6).
                if (answer.status == 204) {
                    const framed = headLine(answer.headBytes(), "content-length") != null;
                    if (answer.body_len != 0 or framed) return error.BodyCorrupted;
                }
                // An interim precedes the final head on the wire, so no cut
                // removes it from a 200 that arrived.
                if (client.interim_owed and answer.status == 200 and plan.originAnswers() and answer.interims == 0) {
                    return error.InterimUnrelayed;
                }
                if (!client.clean or capped or cut_allowed) continue;
                if (answer.status != scripts.spec(plan.scriptOf()).golden_status) return error.GoldenOutcomeMissed;
                if (!answer.finished) return error.GoldenOutcomeMissed;
            }
        }

        /// Whole bodiless answers heard, in `canon.bodiless_answers`' order,
        /// for the census (§9); read once `verify` has passed.
        pub fn bodilessHeard(client: *const Self) [canon.bodiless_answers.len]u32 {
            assert(client.streams >= 1);
            var heard: [canon.bodiless_answers.len]u32 = @splat(0);
            for (client.plans[0..client.streams], client.transport.answers[0..client.streams]) |plan, *answer| {
                if (!answer.finished) continue;
                heard[0] += @intFromBool(answer.status == 204);
                heard[1] += @intFromBool(answer.status == 200 and plan.ask == .head_only);
                heard[2] += @intFromBool(answer.status == 304);
            }
            assert(heard[0] + heard[1] + heard[2] <= client.streams);
            return heard;
        }

        /// Origin 200s heard behind an interim, on a seed that owed one,
        /// for the census (§9); read once `verify` has passed.
        pub fn interimsHeard(client: *const Self) u32 {
            assert(client.streams >= 1);
            if (!client.interim_owed) return 0;
            var heard: u32 = 0;
            for (client.transport.answers[0..client.streams]) |*answer| {
                heard += @intFromBool(answer.status == 200 and answer.interims >= 1);
            }
            assert(heard <= client.streams);
            return heard;
        }

        /// A narrowed offer keys the session under its one suite, and a clean
        /// seed's session must have keyed (zssl refuses any other: §4.1.3).
        fn verifySuite(client: *const Self) ClientError!void {
            assert(client.began or client.transport.negotiatedSuite() == null);
            const offered = client.suite_offer.only() orelse return;
            if (client.transport.negotiatedSuite()) |keyed| {
                if (keyed != offered) return error.SuiteUnoffered;
                return;
            }
            if (client.clean) return error.SuiteUnoffered;
        }

        /// The suite a narrowed offer keyed this client's session under,
        /// for the census; null for a default offer or no session.
        pub fn narrowedSuiteKeyed(client: *const Self) ?SuiteOffer {
            if (client.suite_offer == .every) return null;
            const keyed = client.transport.negotiatedSuite() orelse return null;
            assert(keyed == client.suite_offer.only().?);
            return client.suite_offer;
        }

        /// A violator's first stream: never answered as a request, and, where
        /// the server said anything, the code it is owed. Off a clean seed a
        /// stream the adversary cut is also reset H3_REQUEST_CANCELLED, or
        /// H3_INTERNAL_ERROR when an adversarial origin died first, and a
        /// stream shed for want of a shared stream or its head
        /// H3_REQUEST_REJECTED (§8's ladder): both are acquired before the
        /// fields are judged as a message (exchange.zig's `open`), so a shed
        /// stream's breach is never read, and RFC 9114 §4.1.1 lets a server
        /// reject a request it did not process. The nightly sweep met that
        /// on 8 seeds in 612000001..616000000. A clean seed's pools never
        /// shed, and it must hear the owed answer itself.
        fn verifyViolation(client: *const Self, owed: Violation.Owed) ClientError!void {
            assert(client.violation != .none);
            assert(std.meta.eql(owed, client.violation.owed().?));
            const answer = &client.transport.answers[0];
            if (answer.status != 0) return error.ViolationAnswered;
            switch (owed) {
                .reset => |code| if (answer.reset_code) |got| {
                    const excused = !client.clean and (got == TestClient.code_request_cancelled or
                        got == TestClient.code_internal_error or got == TestClient.code_request_rejected);
                    if (got != code and !excused) return error.ViolationCodeUnexpected;
                },
                .close => |code| if (client.transport.peer_close) |close| {
                    const drained = close.application and close.code == TestClient.code_no_error;
                    if (close.application and close.code != code and !drained) return error.ViolationCodeUnexpected;
                },
            }
            if (client.clean and !heardOwed(&client.transport, owed)) return error.ViolationUnanswered;
        }

        /// Whether the owed answer itself arrived: the reset with its code,
        /// or the application close with its own.
        fn heardOwed(transport: *const Transport, owed: Violation.Owed) bool {
            assert(transport.requests.len >= 1);
            assert(transport.requests.len <= transport.answers.len);
            return switch (owed) {
                .reset => |code| transport.answers[0].reset_code == code,
                .close => |code| if (transport.peer_close) |close| close.application and close.code == code else false,
            };
        }

        /// Streams whose trailer section reached this client, for the
        /// census (§9); read once `verify` has passed.
        pub fn trailersHeard(client: *const Self) u32 {
            assert(client.streams >= 1);
            var heard: u32 = 0;
            for (client.transport.answers[0..client.streams]) |*answer| {
                heard += @intFromBool(answer.trailer_sections == 1);
            }
            assert(heard <= client.streams);
            return heard;
        }

        /// Streams that ended with a trailer section and were answered
        /// whole, for the census (§9); read once `verify` has passed.
        pub fn requestTrailersAnswered(client: *const Self) u32 {
            assert(client.streams >= 1);
            var answered: u32 = 0;
            for (client.plans[0..client.streams], client.transport.answers[0..client.streams]) |plan, *answer| {
                answered += @intFromBool(plan.trailers and answer.status == 200 and answer.finished and !answer.reset);
            }
            assert(answered <= client.streams);
            return answered;
        }

        /// Trailers come once, after the whole chunked body, and say the
        /// trailing origin's one field (§7): HTTP/3 carries the section
        /// the origin's chunked framing ended with as trailing HEADERS.
        fn checkTrailers(answer: *const TestClient.Answer) ClientError!void {
            if (answer.trailer_sections == 0) return;
            assert(answer.trailerBytes().len <= TestClient.trailer_bytes_max);
            if (answer.trailers_malformed) return error.TrailersCorrupted;
            if (answer.trailer_sections != 1) return error.TrailersCorrupted;
            if (answer.status != 200) return error.TrailersCorrupted;
            if (answer.body_len != h2_client.canonical_chunked_body.len) return error.TrailersCorrupted;
            if (!std.mem.eql(u8, answer.bodyBytes(), h2_client.canonical_chunked_body)) return error.TrailersCorrupted;
            if (answer.trailers_len != canonical_trailer_line.len) return error.TrailersCorrupted;
            if (!std.mem.eql(u8, answer.trailerBytes(), canonical_trailer_line)) return error.TrailersCorrupted;
        }

        /// A whole answer carries the section its head owed and no other,
        /// and its head never HTTP/1.1's announcement (§7), as HTTP/2's
        /// oracle has it.
        fn checkTrailersOwed(answer: *const TestClient.Answer) ClientError!void {
            assert(answer.head_len <= TestClient.head_bytes_max);
            const head = answer.headBytes();
            if (headLine(head, "trailer") != null) return error.TrailersMismatched;
            if (!answer.finished or answer.reset) return;
            const owed = if (headLine(head, canon.response_trailer_owed_header)) |value| std.mem.eql(u8, value, "1") else false;
            if (owed != (answer.trailer_sections >= 1)) return error.TrailersMismatched;
        }

        /// The value of the head line named `name`, as the test client keeps
        /// the head: `name: value` lines, names lower-case as HTTP/3 has them.
        fn headLine(head: []const u8, name: []const u8) ?[]const u8 {
            assert(name.len >= 1);
            var lines = std.mem.splitSequence(u8, head, "\r\n");
            while (lines.next()) |line| {
                if (line.len < name.len + 2) continue;
                if (!std.mem.eql(u8, line[0..name.len], name)) continue;
                if (!std.mem.eql(u8, line[name.len..][0..2], ": ")) continue;
                return line[name.len + 2 ..];
            }
            return null;
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
