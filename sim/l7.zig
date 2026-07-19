//! L7 pieces of the deterministic-simulation gate (§9): an HTTP/1.1
//! scripted origin and a script-driven client, both generic over the Io
//! backend. The sim mixes these with the L4 population in one scenario so
//! the shared pools feel cross-protocol pressure.
//!
//! Oracles, not expectations: the origin asserts the §7 promise that no
//! malformed byte is ever forwarded upstream (every request it receives
//! must parse, every body must satisfy its own framing); the client
//! asserts that whatever bytes it got back are a prefix of some legal
//! transcript — parseable heads, statuses drawn from its script's allowed
//! set, 200-bodies matching the origin's canonical wire bytes. On clean
//! seeds (adversary off, origin well-behaved) the oracle hardens to
//! exact: the scripted outcome must happen, byte-for-byte — a silently
//! torn-down exchange that should have been answered is a failure, not
//! an accepted cut.

const std = @import("std");

const zoxy = @import("zoxy");

const Io = zoxy.Io;
const parser = zoxy.http.parser;

const assert = std.debug.assert;

/// The canonical 200 the well-behaved origin serves: body bytes are fixed
/// so the client can detect corruption without correlating connections.
pub const sized_body = "canonical-sized-response-body-00";
pub const sized_head = "HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n";
const sized_response = sized_head ++ sized_body;

comptime {
    assert(sized_body.len == 32);
}

/// Per-connection origin behavior. Slice 1 ships the well-behaved mode;
/// the misbehavior matrix (early, oversize, truncated, ...) follows.
pub const OriginMode = enum(u8) {
    /// Parse each request, wait for its full body, answer the canonical
    /// sized 200, keep the connection open for reuse (§5 parking).
    sized,
};

/// What the origin verifies about every byte the proxy forwards (§7):
/// heads parse, bodies satisfy their own framing. A violation here means
/// the proxy relayed something it was built to reject.
pub fn HttpOrigin(comptime IoType: type) type {
    return struct {
        io: *IoType = undefined,
        listener: IoType.Listener = undefined,
        accept_completion: IoType.Completion = .{},
        conns: [conns_max]Conn = @splat(.{}),
        conns_count: u8 = 0,
        listening: bool = false,
        /// Optional per-accept mode picker (the sim randomizes modes).
        mode_selector: ?*const fn (?*anyopaque) OriginMode = null,
        context: ?*anyopaque = null,
        /// Count of §7 violations observed: a malformed forwarded head,
        /// a body that broke its framing. Checked by the harness verify.
        violations: u32 = 0,

        const Self = @This();
        pub const conns_max: u8 = 32;
        const request_buffer_bytes: u32 = 16384;

        const Phase = enum(u8) { head, body, respond };
        const FramingTag = enum(u8) { none, content_length, chunked };

        pub const Conn = struct {
            origin: *Self = undefined,
            socket: IoType.Socket = undefined,
            recv_completion: IoType.Completion = .{},
            send_completion: IoType.Completion = .{},
            /// Every request stays captured; the current one starts at
            /// `request_offset` and parses from there.
            request_buffer: [request_buffer_bytes]u8 = undefined,
            request_len: u32 = 0,
            request_offset: u32 = 0,
            phase: Phase = .head,
            framing_tag: FramingTag = .none,
            content_remaining: u64 = 0,
            chunk_scanner: parser.ChunkedScanner = .{},
            mode: OriginMode = .sized,
            response_sent: u32 = 0,
            requests_served: u32 = 0,
            done: bool = false,

            fn armRecv(conn: *Conn) void {
                assert(!conn.done);
                assert(conn.request_len < conn.request_buffer.len);
                conn.origin.io.recv(
                    conn.socket,
                    conn.request_buffer[conn.request_len..],
                    &conn.recv_completion,
                    Conn,
                    conn,
                    onRecv,
                );
            }

            fn onRecv(conn: *Conn, result: Io.RecvError!u32) void {
                const received = result catch {
                    // Peer closed or scenario teardown: not a violation.
                    conn.close();
                    return;
                };
                assert(received >= 1);
                conn.request_len += received;
                assert(conn.request_len <= conn.request_buffer.len);
                conn.advance();
            }

            /// Drive head → body → respond over the buffered bytes; arms
            /// a recv when more are needed. No loop: each phase either
            /// falls through or returns, and a finished response re-enters
            /// from `onSend` for any already-buffered next request.
            fn advance(conn: *Conn) void {
                if (conn.phase == .head) {
                    if (!conn.parseHead()) return;
                }
                if (conn.phase == .body) {
                    if (!conn.consumeBody()) return;
                }
                assert(conn.phase == .respond);
                conn.beginRespond();
            }

            /// Returns true when the head is parsed and the phase moved
            /// on; false when it armed a recv or closed on a violation.
            fn parseHead(conn: *Conn) bool {
                assert(conn.phase == .head);
                const bytes = conn.request_buffer[conn.request_offset..conn.request_len];
                if (bytes.len == 0) {
                    conn.recvMoreOrViolation();
                    return false;
                }
                var storage: parser.HeaderStorage = undefined;
                const request = parser.parseRequestHead(bytes, false, &storage) catch |err| {
                    if (err == error.Incomplete and conn.request_len < conn.request_buffer.len) {
                        conn.armRecv();
                        return false;
                    }
                    // §7: the proxy never forwards a malformed head — and
                    // never one bigger than its own 8 KiB cap, so a full
                    // origin buffer is a violation too, not a shortfall.
                    conn.origin.violations += 1;
                    conn.close();
                    return false;
                };
                switch (request.framing) {
                    .none => conn.framing_tag = .none,
                    .content_length => |length| {
                        conn.framing_tag = .content_length;
                        conn.content_remaining = length;
                    },
                    .chunked => {
                        conn.framing_tag = .chunked;
                        conn.chunk_scanner = .{};
                    },
                    // The parser asserts requests are length-delimited.
                    .until_close => unreachable,
                }
                conn.request_offset += request.head_len;
                assert(conn.request_offset <= conn.request_len);
                conn.phase = .body;
                return true;
            }

            /// Returns true when the body completed and the phase moved
            /// on; false when it armed a recv or closed on a violation.
            fn consumeBody(conn: *Conn) bool {
                assert(conn.phase == .body);
                const bytes = conn.request_buffer[conn.request_offset..conn.request_len];
                switch (conn.framing_tag) {
                    .none => {},
                    .content_length => {
                        const take: u32 = @intCast(@min(conn.content_remaining, bytes.len));
                        conn.content_remaining -= take;
                        conn.request_offset += take;
                        if (conn.content_remaining > 0) {
                            conn.recvMoreOrViolation();
                            return false;
                        }
                    },
                    .chunked => {
                        if (bytes.len == 0) {
                            conn.recvMoreOrViolation();
                            return false;
                        }
                        const progress = conn.chunk_scanner.feed(bytes) catch {
                            // §7: forwarded chunked bytes always satisfy
                            // their own framing.
                            conn.origin.violations += 1;
                            conn.close();
                            return false;
                        };
                        conn.request_offset += progress.consumed;
                        if (!progress.done) {
                            conn.recvMoreOrViolation();
                            return false;
                        }
                    },
                }
                assert(conn.request_offset <= conn.request_len);
                conn.phase = .respond;
                return true;
            }

            /// A request still incomplete with the buffer full is
            /// forwarded excess the scripts never produce — a violation,
            /// not a capacity shortfall; otherwise read on.
            fn recvMoreOrViolation(conn: *Conn) void {
                assert(conn.phase == .head or conn.phase == .body);
                if (conn.request_len == conn.request_buffer.len) {
                    conn.origin.violations += 1;
                    conn.close();
                    return;
                }
                conn.armRecv();
            }

            fn beginRespond(conn: *Conn) void {
                assert(conn.phase == .respond);
                conn.response_sent = 0;
                conn.armSend();
            }

            fn armSend(conn: *Conn) void {
                assert(conn.response_sent < sized_response.len);
                conn.origin.io.send(
                    conn.socket,
                    sized_response[conn.response_sent..],
                    &conn.send_completion,
                    Conn,
                    conn,
                    onSend,
                );
            }

            fn onSend(conn: *Conn, result: Io.SendError!u32) void {
                const sent = result catch {
                    conn.close();
                    return;
                };
                conn.response_sent += sent;
                assert(conn.response_sent <= sized_response.len);
                if (conn.response_sent < sized_response.len) {
                    conn.armSend();
                    return;
                }
                // Keep-alive: the next request parses from the new offset
                // (its bytes may already be buffered).
                conn.requests_served += 1;
                conn.phase = .head;
                conn.advance();
            }

            fn close(conn: *Conn) void {
                if (conn.done) return;
                conn.done = true;
                conn.origin.io.closeNow(conn.socket);
            }
        };

        pub fn start(origin: *Self, io: *IoType, address: std.Io.net.IpAddress) !void {
            origin.io = io;
            origin.listener = try io.listen(address);
            origin.listening = true;
            origin.armAccept();
        }

        fn armAccept(origin: *Self) void {
            origin.io.accept(origin.listener, &origin.accept_completion, Self, origin, onAccept);
        }

        fn onAccept(origin: *Self, result: Io.AcceptError!IoType.Socket) void {
            const socket = result catch |err| {
                assert(err == error.Canceled);
                return;
            };
            assert(origin.conns_count < origin.conns.len);
            const conn = &origin.conns[origin.conns_count];
            origin.conns_count += 1;
            conn.origin = origin;
            conn.socket = socket;
            conn.mode = if (origin.mode_selector) |select|
                select(origin.context)
            else
                .sized;
            conn.armRecv();
            origin.armAccept();
        }

        pub fn stopListening(origin: *Self) void {
            if (origin.listening) {
                origin.io.listenClose(origin.listener);
                origin.listening = false;
            }
        }

        /// Close any connection still open at scenario end so the socket
        /// leak check is exact.
        pub fn closeRemaining(origin: *Self) void {
            for (origin.conns[0..origin.conns_count]) |*conn| {
                conn.close();
            }
        }
    };
}

/// The client's request scripts. Slice 1 ships the valid single-exchange
/// pair; the adversarial matrix (malformed, oversize, CONNECT, keep-alive,
/// pipelined, silent) follows.
pub const Script = enum(u8) {
    /// A bodyless GET; expects one canonical 200.
    get,
    /// A POST with a 24-byte sized body; expects one canonical 200.
    post_sized,
};

/// A verify-time verdict over everything the client received.
pub const ClientError = error{
    /// Received bytes that no legal transcript starts with.
    ResponseCorrupted,
    /// A complete response carried a status outside the script's set.
    ResponseStatusUnexpected,
    /// A 200 body diverged from every canonical origin body.
    ResponseBodyCorrupted,
    /// More response bytes than any legal transcript contains.
    ResponseOverrun,
    /// A clean seed did not produce the script's exact golden outcome.
    GoldenOutcomeMissed,
};

/// A script-driven HTTP client over the sim's virtual sockets. Sends its
/// script's request bytes, reads until the expected responses complete
/// (or the connection dies), and verifies the §9 oracles at scenario end.
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

        const post_body = "request-body-24-bytes-ab";
        comptime {
            assert(post_body.len == 24);
        }

        pub fn prepare(
            client: *Self,
            io: *IoType,
            address: std.Io.net.IpAddress,
            script: Script,
            clean: bool,
        ) void {
            client.io = io;
            client.address = address;
            client.script = script;
            client.clean = clean;
            const bytes: []const u8 = switch (script) {
                .get => "GET /sim HTTP/1.1\r\nHost: sim\r\n\r\n",
                .post_sized => "POST /sim HTTP/1.1\r\nHost: sim\r\n" ++
                    "Content-Length: 24\r\n\r\n" ++ post_body,
            };
            assert(bytes.len <= client.request.len);
            @memcpy(client.request[0..bytes.len], bytes);
            client.request_len = @intCast(bytes.len);
        }

        pub fn begin(client: *Self) void {
            assert(client.request_len >= 1);
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
            client.armSend();
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
                client.script,
            );
            if (walk.violation == null and walk.complete_count >= expectedResponses(client.script)) {
                // The script's transcript is fully in hand: close from
                // this side — the proxy honors keep-alive, so waiting for
                // its FIN would hang until the drain.
                client.script_satisfied = true;
                client.settleIfTerminal();
                return;
            }
            client.armRecv();
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
            const walk = walkResponses(bytes, client.script);
            if (walk.violation) |violation| return violation;
            assert(walk.offset <= client.received_len);
            if (client.clean) {
                if (walk.complete_count != expectedResponses(client.script)) {
                    return ClientError.GoldenOutcomeMissed;
                }
                if (walk.offset != client.received_len) {
                    return ClientError.GoldenOutcomeMissed;
                }
                for (walk.statuses[0..walk.complete_count]) |status| {
                    if (status != goldenStatus(client.script)) {
                        return ClientError.GoldenOutcomeMissed;
                    }
                }
            }
        }

        const Walk = struct {
            complete_count: u8,
            offset: u32,
            statuses: [responses_max]u16,
            violation: ?ClientError,
        };

        /// Walk the received bytes as a sequence of responses, validating
        /// each complete one: parseable head, status in the script's set,
        /// 200-bodies matching a canonical origin body. A partial tail is
        /// a legal prefix (the adversary cuts mid-anything); bytes that
        /// can never extend to a legal transcript — or one complete
        /// response more than the transcript contains — are a violation.
        fn walkResponses(bytes: []const u8, script: Script) Walk {
            var walk = Walk{
                .complete_count = 0,
                .offset = 0,
                .statuses = @splat(0),
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
                    methodOf(script),
                ) catch |err| {
                    if (err == error.Incomplete and tailAnchored(bytes[walk.offset..])) {
                        return walk;
                    }
                    walk.violation = ClientError.ResponseCorrupted;
                    return walk;
                };
                if (!statusAllowed(script, response.status)) {
                    walk.violation = ClientError.ResponseStatusUnexpected;
                    return walk;
                }
                const body = bytes[walk.offset + response.head_len ..];
                const verdict = walkBody(response, body) orelse return walk;
                if (verdict.violation) |violation| {
                    walk.violation = violation;
                    return walk;
                }
                assert(verdict.body_len <= body.len);
                walk.statuses[walk.complete_count] = response.status;
                walk.complete_count += 1;
                walk.offset += response.head_len + verdict.body_len;
                // A complete response beyond the script's transcript is a
                // duplication bug, not a legal prefix.
                if (walk.complete_count > expectedResponses(script)) {
                    walk.violation = ClientError.ResponseOverrun;
                    return walk;
                }
            }
            return walk;
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

        const BodyVerdict = struct {
            body_len: u32,
            violation: ?ClientError,
        };

        /// Null means the body is still incomplete (a legal partial
        /// tail); otherwise the verdict carries the wire length consumed
        /// and any corruption found. Framings are pinned before any byte
        /// comparison: the canonical 200 is Content-Length 32, every
        /// legal non-200 is a static with Content-Length 0 — so a
        /// corrupted length fails even before its body arrives.
        fn walkBody(response: parser.ResponseHead, body: []const u8) ?BodyVerdict {
            switch (response.framing) {
                .content_length => |length| {
                    if (response.status == 200) {
                        if (length != sized_body.len) {
                            return .{ .body_len = 0, .violation = ClientError.ResponseBodyCorrupted };
                        }
                        const have: u32 = @intCast(@min(@as(u64, body.len), length));
                        if (!std.mem.eql(u8, body[0..have], sized_body[0..have])) {
                            return .{ .body_len = have, .violation = ClientError.ResponseBodyCorrupted };
                        }
                        if (body.len < length) return null;
                        return .{ .body_len = @intCast(length), .violation = null };
                    }
                    if (length != 0) {
                        return .{ .body_len = 0, .violation = ClientError.ResponseBodyCorrupted };
                    }
                    return .{ .body_len = 0, .violation = null };
                },
                // No legal transcript uses these framings yet: the sized
                // origin frames by length and the statics are
                // Content-Length 0. The misbehavior matrix widens this.
                .none, .chunked, .until_close => return .{
                    .body_len = 0,
                    .violation = ClientError.ResponseCorrupted,
                },
            }
        }

        fn expectedResponses(script: Script) u8 {
            return switch (script) {
                .get, .post_sized => 1,
            };
        }

        /// The exact status a clean seed's script must produce.
        fn goldenStatus(script: Script) u16 {
            return switch (script) {
                .get, .post_sized => 200,
            };
        }

        fn methodOf(script: Script) parser.Method {
            return switch (script) {
                .get => .get,
                .post_sized => .post,
            };
        }

        /// Statuses a script may legally see. Valid requests meet the
        /// canonical 200, the §8 rungs (503), or an upstream that the
        /// adversary killed (502) — anything else is a proxy bug.
        fn statusAllowed(script: Script, status: u16) bool {
            return switch (script) {
                .get, .post_sized => status == 200 or status == 502 or status == 503,
            };
        }
    };
}
