//! The script-driven HTTP client of the simulation gate (§9), generic
//! over the Io backend. Sends its script's request bytes, reads until
//! the expected responses complete (or the connection dies), and
//! verifies the oracles at scenario end.
//!
//! Oracles, not expectations: the client asserts that whatever bytes it
//! got back are a prefix of some legal transcript — parseable heads,
//! statuses drawn from its script's allowed set, 200-bodies matching the
//! origin's canonical wire bytes. On clean seeds (adversary off, origin
//! well-behaved) the oracle hardens to exact: the scripted outcome must
//! happen, byte-for-byte — a silently torn-down exchange that should
//! have been answered is a failure, not an accepted cut.
//!
//! Every script-specific bound lives in the `scripts.Spec` table; this
//! file contains no per-script branches, so a new script changes the
//! table and nothing here.

const std = @import("std");

const zoxy = @import("zoxy");

const canon = @import("canon.zig");
const scripts = @import("scripts.zig");

const Io = zoxy.Io;
const parser = zoxy.http.parser;
const Script = scripts.Script;
const Spec = scripts.Spec;

const assert = std.debug.assert;

/// A verify-time verdict over everything the client received.
pub const ClientError = error{
    /// Received bytes that no legal transcript starts with.
    ResponseCorrupted,
    /// A complete response carried a status outside the script's set.
    ResponseStatusUnexpected,
    /// A `101` reached the client without the participating
    /// `Upgrade`/`Connection` pair §7 exists to let through (#180).
    UpgradePairMissing,
    /// A 200 body diverged from every canonical origin body.
    ResponseBodyCorrupted,
    /// More response bytes than any legal transcript contains.
    ResponseOverrun,
    /// A clean seed did not produce the script's exact golden outcome.
    GoldenOutcomeMissed,
    /// A proxied 200 arrived without the #175 response-filter stamp the
    /// harness configures unconditionally: the edit path did not run.
    ResponseEditMissing,
    /// A 301 without the exact Location the harness's one redirect rule
    /// composes (#176): the per-request render carried the wrong target.
    RedirectLocationWrong,
    /// A response carried an edit it must not: the stamp on a static
    /// (which bypasses the response render), or the 5xx rule's edit
    /// anywhere (the scripted origin answers no 5xx) — either way a
    /// predicate fired where it could not have.
    ResponseEditForged,
    /// A sticky seed's proxied 200 arrived without the exact #178
    /// Set-Cookie stamp the drawn cookie cluster owes it — every routed
    /// request but `sticky_follow`'s is assigned or repicked, and the
    /// one endpoint's tag is pinned, so the whole value is demanded.
    StickyStampMissing,
    /// The #178 stamp where it must not be: on `sticky_follow`'s 200
    /// (the request already named the endpoint — idempotence is the
    /// contract), on a static, or on any response of a seed that never
    /// drew a cookie cluster.
    StickyStampForged,
};

/// What the connection under the responses was, which two of the
/// oracles below need and no script can describe: the same request over a
/// terminated listener earns a different stamp from the same render.
pub const Connection = struct {
    /// The seed drew the #178 cookie-keyed cluster, so every routed 200
    /// owes the stamp.
    sticky: bool,
    /// The client reached the proxy over a listener that terminates TLS,
    /// so that stamp owes `Secure` (#125).
    terminated: bool = false,
};

pub fn Client(comptime IoType: type) type {
    return struct {
        io: *IoType = undefined,
        address: std.Io.net.IpAddress = undefined,
        on_ended: ?*const fn (?*anyopaque) void = null,
        context: ?*anyopaque = null,
        script: Script = .get,
        /// Clean seeds harden the prefix oracle to the exact golden
        /// outcome — nothing may be cut, shed, or silently torn down.
        clean: bool = false,
        /// This client's listener allows the #180 upgrade token, which
        /// decides what its handshake script is *entitled* to: the `101`
        /// and a tunnel, or the `501` every config had before the
        /// feature. A property of the listener rather than the script,
        /// which is why it rides the client and not the spec.
        upgrades: bool = false,
        /// The seed drew the #178 cookie-keyed http cluster, so the
        /// stamp oracle runs over every parsed response head.
        sticky: bool = false,
        connect_completion: IoType.Completion = .{},
        connect_cancel_completion: IoType.Completion = .{},
        recv_completion: IoType.Completion = .{},
        send_completion: IoType.Completion = .{},
        request: [request_bytes_max]u8 = undefined,
        request_len: u32 = 0,
        receive_buffer: [receive_bytes_max]u8 = undefined,
        received_len: u32 = 0,
        /// Bytes past the buffer land here; any arrival is an overrun.
        overrun_scratch: [1]u8 = undefined,
        overrun: bool = false,
        socket: IoType.Socket = undefined,
        connected: bool = false,
        connect_settled: bool = false,
        cancel_requested: bool = false,
        script_satisfied: bool = false,
        /// The keep-alive pair's second request has been appended.
        second_sent: bool = false,
        closed: bool = false,
        ended: bool = false,
        send_pending: bool = false,
        recv_terminal: bool = false,
        sent_len: u32 = 0,

        const Self = @This();
        /// Room for the oversize-URI script, which must overflow the
        /// proxy's 8 KiB head buffer to earn its 414.
        pub const request_bytes_max: u32 = 9216;
        pub const receive_bytes_max: u32 = 4096;
        const responses_max: u8 = 4;

        comptime {
            // Every script's wire bytes must fit the request buffer —
            // including the second GET a reusable first exchange appends.
            for (std.enums.values(Script)) |script| {
                const entry = scripts.spec(script);
                var needed = entry.request.len;
                if (entry.second_request_when_reusable) {
                    needed += scripts.get_request.len;
                }
                assert(needed <= request_bytes_max);
                // The walker's fixed response arrays must cover the cap.
                assert(entry.transcript_cap <= responses_max);
            }
        }

        pub fn prepare(
            client: *Self,
            io: *IoType,
            address: std.Io.net.IpAddress,
            script: Script,
            clean: bool,
            upgrades: bool,
            sticky: bool,
        ) void {
            client.io = io;
            client.address = address;
            client.script = script;
            client.clean = clean;
            client.upgrades = upgrades;
            client.sticky = sticky;
            const bytes = scripts.spec(script).request;
            assert(bytes.len <= client.request.len);
            @memcpy(client.request[0..bytes.len], bytes);
            client.request_len = @intCast(bytes.len);
        }

        pub fn begin(client: *Self) void {
            // An empty request is the silent script's shape: it expects
            // no response, only the head-read deadline's reap.
            if (client.request_len == 0) {
                assert(scripts.spec(client.script).expected_responses == 0);
            }
            client.io.connect(
                client.address,
                &client.connect_completion,
                Self,
                client,
                onConnect,
            );
        }

        fn onConnect(client: *Self, result: Io.ConnectError!IoType.Socket) void {
            client.connect_settled = true;
            client.socket = result catch {
                client.end();
                return;
            };
            client.connected = true;
            client.armRecv();
            if (client.request_len >= 1) {
                client.armSend();
            }
        }

        fn armSend(client: *Self) void {
            assert(client.sent_len < client.request_len);
            assert(!client.send_pending);
            client.send_pending = true;
            client.io.send(
                client.socket,
                client.request[client.sent_len..client.request_len],
                &client.send_completion,
                Self,
                client,
                onSend,
            );
        }

        fn onSend(client: *Self, result: Io.SendError!u32) void {
            assert(client.send_pending);
            client.send_pending = false;
            const sent = result catch {
                client.settleIfTerminal();
                return;
            };
            client.sent_len += sent;
            assert(client.sent_len <= client.request_len);
            if (client.recv_terminal or client.script_satisfied) {
                client.settleIfTerminal();
            } else if (client.sent_len < client.request_len) {
                client.armSend();
            }
        }

        fn armRecv(client: *Self) void {
            const buffer: []u8 = if (client.received_len == client.receive_buffer.len)
                &client.overrun_scratch
            else
                client.receive_buffer[client.received_len..];
            client.io.recv(
                client.socket,
                buffer,
                &client.recv_completion,
                Self,
                client,
                onRecv,
            );
        }

        fn onRecv(client: *Self, result: Io.RecvError!u32) void {
            const received = result catch {
                client.recv_terminal = true;
                client.settleIfTerminal();
                return;
            };
            assert(received >= 1);
            if (client.received_len == client.receive_buffer.len) {
                client.overrun = true;
                client.armRecv();
                return;
            }
            client.received_len += received;
            assert(client.received_len <= client.receive_buffer.len);
            const walk = walkResponses(
                client.receive_buffer[0..client.received_len],
                scripts.spec(client.script),
                .{ .sticky = client.sticky },
            );
            client.maybeSendSecondRequest(&walk);
            if (walk.violation == null and walk.complete_count >= responsesTarget(client.script, &walk)) {
                // The script's transcript is fully in hand: close from
                // this side — the proxy honors keep-alive, so waiting for
                // its FIN would hang until the drain.
                client.script_satisfied = true;
                client.settleIfTerminal();
                return;
            }
            client.armRecv();
        }

        /// The first exchange settled as a reusable success: a 200 that
        /// did not announce close.
        fn firstExchangeReusable(walk: *const Walk) bool {
            assert(walk.complete_count >= 1);
            return walk.statuses[0] == 200 and walk.keep_alives[0];
        }

        /// A second-request script's follow-up starts only after the
        /// first 200 settles reusable — the §5 parked-connection checkout
        /// under schedule fuzz.
        fn maybeSendSecondRequest(client: *Self, walk: *const Walk) void {
            if (!scripts.spec(client.script).second_request_when_reusable) return;
            if (client.second_sent) return;
            if (walk.violation != null) return;
            if (walk.complete_count != 1) return;
            if (!firstExchangeReusable(walk)) return;
            // A complete first response implies the proxy consumed the
            // whole first request, so the send op has settled.
            assert(!client.send_pending);
            assert(client.sent_len == client.request_len);
            const second = scripts.get_request;
            assert(client.request_len + second.len <= client.request.len);
            @memcpy(client.request[client.request_len..][0..second.len], second);
            client.request_len += @intCast(second.len);
            client.second_sent = true;
            client.armSend();
        }

        /// How many responses the script still legally expects, given
        /// what has arrived: a second-request script degrades to a single
        /// exchange when its first response refuses reuse (an error
        /// status, or an announced close under pressure or drain).
        fn responsesTarget(script: Script, walk: *const Walk) u8 {
            const entry = scripts.spec(script);
            if (!entry.second_request_when_reusable) return entry.expected_responses;
            if (walk.complete_count >= 1 and !firstExchangeReusable(walk)) {
                return 1;
            }
            return entry.expected_responses;
        }

        /// Scenario end: a connect the adversary black-holed must still
        /// be reaped, the same seam the proxy relies on (§5).
        pub fn cancelIfStuck(client: *Self) void {
            if (client.connect_settled or client.cancel_requested) return;
            client.cancel_requested = true;
            client.io.connectCancel(
                &client.connect_completion,
                &client.connect_cancel_completion,
                Self,
                client,
                onConnectCanceled,
            );
        }

        fn onConnectCanceled(client: *Self) void {
            if (!client.connect_settled) {
                client.connect_settled = true;
                client.end();
            }
        }

        fn settleIfTerminal(client: *Self) void {
            assert(client.recv_terminal or client.script_satisfied or !client.send_pending);
            if (client.send_pending) return;
            if (client.recv_terminal or client.script_satisfied) {
                client.closeIfOpen();
                client.end();
            }
        }

        pub fn closeIfOpen(client: *Self) void {
            if (client.connected and !client.closed) {
                client.closed = true;
                client.io.closeNow(client.socket);
            }
        }

        fn end(client: *Self) void {
            if (client.ended) return;
            client.ended = true;
            if (client.on_ended) |ended| {
                ended(client.context);
            }
        }

        /// The §9 verdict over everything received. Adversarial seeds get
        /// the prefix oracle; clean seeds additionally demand the exact
        /// golden outcome — count, status, and byte coverage all pinned,
        /// so a shed, a wrong verdict, or a silent teardown fails the
        /// seed instead of passing as a "cut".
        pub fn verify(client: *const Self) ClientError!void {
            assert(client.received_len <= client.receive_buffer.len);
            if (client.overrun) return ClientError.ResponseOverrun;
            const bytes = client.receive_buffer[0..client.received_len];
            const entry = scripts.spec(client.script);
            const walk = walkResponses(bytes, entry, .{ .sticky = client.sticky });
            if (walk.violation) |violation| return violation;
            assert(walk.offset <= client.received_len);
            if (client.clean) {
                if (walk.complete_count != entry.expected_responses) {
                    return ClientError.GoldenOutcomeMissed;
                }
                if (walk.offset != client.received_len) {
                    return ClientError.GoldenOutcomeMissed;
                }
                // A handshake earns the `101` only where the listener
                // allows the token; everywhere else it earns the refusal
                // the spec's own golden cannot name, because which of the
                // two is right is the listener's fact (#180).
                const golden: u16 = if (client.script == .upgrade_request and !client.upgrades)
                    501
                else
                    entry.golden_status;
                for (walk.statuses[0..walk.complete_count]) |status| {
                    if (status != golden) {
                        return ClientError.GoldenOutcomeMissed;
                    }
                }
                // §7: a pipelined first response must announce the close
                // that follows it.
                if (entry.golden_first_announces_close and walk.keep_alives[0]) {
                    return ClientError.GoldenOutcomeMissed;
                }
            }
        }

        pub const Walk = struct {
            complete_count: u8,
            offset: u32,
            statuses: [responses_max]u16,
            /// Per-response persistence verdicts (§7): version defaults
            /// plus Connection tokens, as the parser computed them.
            keep_alives: [responses_max]bool,
            violation: ?ClientError,
        };

        /// Walk the received bytes as a sequence of responses, validating
        /// each complete one: parseable head, status in the script's set,
        /// 200-bodies matching a canonical origin body. A partial tail is
        /// a legal prefix (the adversary cuts mid-anything); bytes that
        /// can never extend to a legal transcript — or one complete
        /// response more than the transcript contains — are a violation.
        pub fn walkResponses(bytes: []const u8, entry: Spec, connection: Connection) Walk {
            var walk = Walk{
                .complete_count = 0,
                .offset = 0,
                .statuses = @splat(0),
                .keep_alives = @splat(false),
                .violation = null,
            };
            while (walk.complete_count < responses_max) {
                assert(walk.offset <= bytes.len);
                if (walk.offset == bytes.len) return walk;
                var storage: parser.HeaderStorage = undefined;
                const response = parser.parseResponseHead(
                    bytes[walk.offset..],
                    false,
                    &storage,
                    entry.method,
                ) catch |err| {
                    if (err == error.Incomplete and tailAnchored(bytes[walk.offset..])) {
                        return walk;
                    }
                    walk.violation = ClientError.ResponseCorrupted;
                    return walk;
                };
                if (std.mem.indexOfScalar(u16, entry.allowed_statuses, response.status) == null) {
                    walk.violation = ClientError.ResponseStatusUnexpected;
                    return walk;
                }
                if (responseEditViolation(entry, &response)) |violation| {
                    walk.violation = violation;
                    return walk;
                }
                if (stickyViolation(connection, entry, &response)) |violation| {
                    walk.violation = violation;
                    return walk;
                }
                // The #176 oracle: `filter_redirect` is the only script
                // that earns a 301, its rule composes from the request's
                // own host and canonical path, and both are fixed — so
                // every 301 must carry exactly the canonical Location.
                if (response.status == 301) {
                    if (!headerEquals(response.headers, "Location", canon.redirect_location)) {
                        walk.violation = ClientError.RedirectLocationWrong;
                        return walk;
                    }
                }
                // The #180 oracle, and the mirror of the redirect check
                // above: §7 lets the participating `Upgrade` survive
                // hop-by-hop stripping precisely so the client is told
                // *what* it was upgraded to, and the proxy writes its own
                // `Connection: upgrade` rather than echoing whatever
                // arrived. A status check alone cannot see either — a
                // render that dropped or corrupted the pair would still
                // produce a `101` and pass — so the headers are demanded
                // by name, byte for byte.
                if (response.status == 101) {
                    if (!headerEquals(response.headers, "upgrade", "websocket") or
                        !headerEquals(response.headers, "connection", "upgrade"))
                    {
                        walk.violation = ClientError.UpgradePairMissing;
                        return walk;
                    }
                }
                const body = bytes[walk.offset + response.head_len ..];
                const verdict = walkBody(response, body, entry) orelse return walk;
                if (verdict.violation) |violation| {
                    walk.violation = violation;
                    return walk;
                }
                assert(verdict.body_len <= body.len);
                walk.statuses[walk.complete_count] = response.status;
                walk.keep_alives[walk.complete_count] = response.keep_alive;
                walk.complete_count += 1;
                walk.offset += response.head_len + verdict.body_len;
                // A complete response beyond the script's transcript is a
                // duplication bug, not a legal prefix.
                if (walk.complete_count > entry.transcript_cap) {
                    walk.violation = ClientError.ResponseOverrun;
                    return walk;
                }
            }
            return walk;
        }

        /// The #175 oracle over one parsed response head: every 200 is
        /// proxied through the response render, so it must carry the
        /// harness's unconditional stamp; every legal non-200 here is a
        /// static that bypasses that render, so the stamp on one means a
        /// static grew filter edits; and the 5xx rule's edit anywhere
        /// means the class predicate fired on a class the origin never
        /// answers. Distinguishes the two render paths from outside the
        /// process, under every schedule the adversary produces.
        fn responseEditViolation(entry: Spec, response: *const parser.ResponseHead) ?ClientError {
            assert(response.status >= 100);
            assert(response.headers.len <= zoxy.constants.headers_max);
            const stamped = headerEquals(
                response.headers,
                canon.response_edit_name,
                canon.response_edit_value,
            );
            // A #159 page is a static however good its status looks: it
            // is sent from immutable memory and never crosses the
            // response render, so the stamp on one would mean a
            // configured body had grown filter edits.
            const from_memory = pageBodyFor(entry, response.status) != null;
            if (response.status == 200 and !from_memory) {
                if (!stamped) {
                    return ClientError.ResponseEditMissing;
                }
            } else {
                if (stamped) {
                    return ClientError.ResponseEditForged;
                }
            }
            if (headerPresent(response.headers, canon.response_never_name)) {
                return ClientError.ResponseEditForged;
            }
            return null;
        }

        /// The #178 oracle over one parsed head. On a sticky seed the
        /// drawn cookie cluster serves every routed request, so every
        /// proxied 200 owes the client the exact pinned stamp — except
        /// `sticky_follow`'s, whose request already named the endpoint
        /// (idempotence is the contract). A non-200 here is a static or
        /// a per-request redirect, neither of which runs the response
        /// render's stamp path, so the cookie's *name* appearing at all
        /// is forged — and on a seed that drew no cookie cluster, so is
        /// any appearance anywhere. Like `responseEditViolation`, this
        /// distinguishes the render paths from outside the process,
        /// under every schedule the adversary produces.
        fn stickyViolation(
            connection: Connection,
            entry: Spec,
            response: *const parser.ResponseHead,
        ) ?ClientError {
            assert(response.status >= 100);
            assert(response.headers.len <= zoxy.constants.headers_max);
            const named = stickyNamePresent(response.headers);
            if (!connection.sticky) {
                if (named) return ClientError.StickyStampForged;
                return null;
            }
            // Same rule as the #175 stamp, one mechanism over: a page
            // reaches no origin and runs no response render, so a
            // cookie on one would be the stamp path firing for an
            // exchange that never happened.
            if (response.status != 200 or pageBodyFor(entry, response.status) != null) {
                if (named) return ClientError.StickyStampForged;
                return null;
            }
            if (entry.sticky_request_pinned) {
                if (named) return ClientError.StickyStampForged;
                return null;
            }
            // The one place the two populations differ, and the reason
            // this oracle needs to know which it is serving: where zoxy
            // terminated, the render knows the client-facing scheme is
            // https and the stamp carries `Secure` (#125).
            const expected = if (connection.terminated)
                canon.sticky_set_cookie_value_secure
            else
                canon.sticky_set_cookie_value;
            if (!headerEquals(response.headers, "set-cookie", expected)) {
                return ClientError.StickyStampMissing;
            }
            return null;
        }

        /// Any Set-Cookie line claiming the #178 name, whatever its
        /// value — the must-not-appear direction's test, looser than
        /// the exact-value demand so a wrong-tag stamp cannot pass as
        /// absent.
        fn stickyNamePresent(headers: []const parser.Header) bool {
            assert(headers.len <= zoxy.constants.headers_max);
            const prefix = canon.sticky_cookie_name ++ "=";
            for (headers) |header| {
                if (!std.ascii.eqlIgnoreCase(header.name, "set-cookie")) continue;
                if (std.mem.startsWith(u8, header.value, prefix)) return true;
            }
            return false;
        }

        fn headerEquals(headers: []const parser.Header, name: []const u8, value: []const u8) bool {
            assert(name.len >= 1);
            assert(headers.len <= zoxy.constants.headers_max);
            for (headers) |header| {
                if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
                if (std.mem.eql(u8, header.value, value)) return true;
            }
            return false;
        }

        fn headerPresent(headers: []const parser.Header, name: []const u8) bool {
            assert(name.len >= 1);
            assert(headers.len <= zoxy.constants.headers_max);
            for (headers) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, name)) return true;
            }
            return false;
        }

        /// Every legal response starts "HTTP/1."; a partial tail that
        /// already diverges from that anchor can never extend into one.
        fn tailAnchored(tail: []const u8) bool {
            assert(tail.len >= 1);
            const anchor = "HTTP/1.";
            const check_len = @min(tail.len, anchor.len);
            assert(check_len >= 1);
            return std.mem.eql(u8, tail[0..check_len], anchor[0..check_len]);
        }

        /// The #159 body a configured page carries for this (script,
        /// status), or null when the response is not one. Two pages are
        /// configured by the harness: `403` — the status a filter
        /// reject earns, so every 403 in the sweep is one — and the
        /// `200` the `/respond` rule answers, which reaches no origin.
        ///
        /// This doubles as "answered from memory": a page is a static,
        /// so it bypasses the response render and therefore *both*
        /// response-side mechanisms — the #175 stamp and the #178
        /// cookie. The three oracles below all key off this one
        /// predicate, so the sweep cannot come to disagree with itself
        /// about which responses were rendered.
        fn pageBodyFor(entry: Spec, status: u16) ?[]const u8 {
            assert(status >= 100);
            assert(status <= 599);
            if (status == 403) {
                // Blanket by status, mirroring the server: a configured
                // page answers *any* path that raises 403, not only the
                // `/reject` rule that raises one today.
                assert(canon.error_page_body.len >= 1);
                return canon.error_page_body;
            }
            if (status == 200 and entry.respond_page) {
                assert(canon.respond_body.len >= 1);
                return canon.respond_body;
            }
            return null;
        }

        const BodyVerdict = struct {
            body_len: u32,
            violation: ?ClientError,
        };

        /// Null means the body is still incomplete (a legal partial
        /// tail); otherwise the verdict carries the wire length consumed
        /// and any corruption found. Framings are pinned before any byte
        /// comparison: a 200 carries exactly one canonical body per
        /// framing (the proxy relays body wire bytes verbatim), and
        /// every legal non-200 is a static with Content-Length 0 — so a
        /// corrupted length fails even before its body arrives.
        fn walkBody(response: parser.ResponseHead, body: []const u8, entry: Spec) ?BodyVerdict {
            // A `101` is bodiless by status, not by header (#180): the
            // bytes after it are the tunnel's, and belong to no response
            // at all. The framing arm below reads `.none` as corruption
            // because until upgrades existed nothing legal could carry
            // it — every canonical 200 has a body and every static an
            // explicit `Content-Length: 0`.
            if (response.status == 101) {
                return .{ .body_len = 0, .violation = null };
            }
            const page_body = pageBodyFor(entry, response.status);
            switch (response.framing) {
                .content_length => |length| {
                    // A configured page's body, byte-exact (#159): it is
                    // rendered once at load, so any drift here is the
                    // static path corrupting immutable memory.
                    if (page_body) |expected| {
                        if (length != expected.len) {
                            return .{ .body_len = 0, .violation = ClientError.ResponseBodyCorrupted };
                        }
                        return prefixVerdict(body, expected, @intCast(length));
                    }
                    if (response.status == 200) {
                        if (length != canon.sized_body.len) {
                            return .{ .body_len = 0, .violation = ClientError.ResponseBodyCorrupted };
                        }
                        return prefixVerdict(body, canon.sized_body, @intCast(length));
                    }
                    if (length != 0) {
                        return .{ .body_len = 0, .violation = ClientError.ResponseBodyCorrupted };
                    }
                    return .{ .body_len = 0, .violation = null };
                },
                // A page is always Content-Length framed — the loader
                // renders it that way — so either streaming framing on
                // one is the render inventing a shape.
                .chunked => {
                    if (response.status != 200 or page_body != null) {
                        return .{ .body_len = 0, .violation = ClientError.ResponseCorrupted };
                    }
                    return prefixVerdict(body, canon.chunked_wire, canon.chunked_wire.len);
                },
                .until_close => {
                    if (response.status != 200 or page_body != null) {
                        return .{ .body_len = 0, .violation = ClientError.ResponseCorrupted };
                    }
                    // The FIN delimits this body, so it is transcript-
                    // final: bytes beyond the canonical body — or past
                    // where the close must fall — are corruption, and
                    // whatever arrived counts as the (possibly cut)
                    // complete response.
                    if (body.len > canon.until_close_body.len) {
                        return .{ .body_len = 0, .violation = ClientError.ResponseBodyCorrupted };
                    }
                    const have: u32 = @intCast(body.len);
                    if (!std.mem.eql(u8, body[0..have], canon.until_close_body[0..have])) {
                        return .{ .body_len = have, .violation = ClientError.ResponseBodyCorrupted };
                    }
                    return .{ .body_len = have, .violation = null };
                },
                // No canonical 200 is bodiless, and the statics carry an
                // explicit Content-Length: 0.
                .none => return .{
                    .body_len = 0,
                    .violation = ClientError.ResponseCorrupted,
                },
            }
        }

        /// Verdict for a wire-exact canonical body: the received prefix
        /// must match byte-for-byte; short is incomplete (null), full is
        /// complete at exactly `wire_len`.
        fn prefixVerdict(body: []const u8, canonical: []const u8, wire_len: u32) ?BodyVerdict {
            assert(canonical.len == wire_len);
            const have: u32 = @intCast(@min(body.len, canonical.len));
            if (!std.mem.eql(u8, body[0..have], canonical[0..have])) {
                return .{ .body_len = have, .violation = ClientError.ResponseBodyCorrupted };
            }
            if (body.len < wire_len) return null;
            return .{ .body_len = wire_len, .violation = null };
        }
    };
}
