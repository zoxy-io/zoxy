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
const constants = zoxy.constants;

const assert = std.debug.assert;

/// The canonical 200s the origin serves: bodies are fixed so the client
/// can detect corruption without correlating connections. The proxy
/// relays body wire bytes verbatim, so the client prefix-checks the raw
/// framed forms.
pub const sized_body = "canonical-sized-response-body-00";
pub const sized_head = "HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n";
const sized_response = sized_head ++ sized_body;
pub const chunked_wire = "10\r\nchunked-body-16b\r\n0\r\n\r\n";
pub const chunked_head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
const chunked_response = chunked_head ++ chunked_wire;
pub const until_close_body = "until-close-stream";
pub const until_close_head = "HTTP/1.1 200 OK\r\n\r\n";
const until_close_response = until_close_head ++ until_close_body;
const truncated_response = sized_head ++ sized_body[0..16];

/// A parseable head that cannot survive the render: 8190 bytes fits the
/// proxy's 8 KiB response buffer, but no Content-Length and no
/// Transfer-Encoding makes it until-close framing, which forces a
/// Connection: close injection — and 8190 plus that header overflows
/// 8192. Sent at accept time, it races the request legs into the
/// deferred-render path (§7 buffer rotation) and must die as a clean
/// 502 or teardown, never a crash.
const oversize_head = "HTTP/1.1 200 OK\r\nx-pad: " ++ ("p" ** 8162) ++ "\r\n\r\n";

comptime {
    assert(sized_body.len == 32);
    assert(chunked_wire[0] == '1' and chunked_wire[1] == '0');
    assert(chunked_wire.len == 4 + 16 + 2 + 5);
    assert(oversize_head.len == 8190);
}

/// Per-connection origin behavior: the well-behaved framings, then the
/// misbehavior matrix (§9 adversarial-origin coverage). Clean seeds pin
/// every connection to `sized`.
pub const OriginMode = enum(u8) {
    /// Parse each request, wait for its full body, answer the canonical
    /// sized 200, keep the connection open for reuse (§5 parking).
    sized,
    /// As `sized`, with the chunked canonical 200.
    chunked,
    /// Answer the until-close canonical 200 and close after it: the FIN
    /// delimits the body, and the connection is never reusable.
    until_close,
    /// Send the sized head but only half its body, then close: a
    /// truncated length-delimited response the proxy must cut, never
    /// repair.
    truncated,
    /// RST on the first forwarded byte.
    reset,
    /// Read forever, never answer: the proxy's idle deadline reaps the
    /// exchange.
    mute,
    /// Answer the canonical 200 at accept time — before any request
    /// byte — then only drain. Early responses are legal (§7) and race
    /// the request legs' buffer rotation.
    instant_sized,
    /// Send the oversize-after-edits head at accept time, then drain:
    /// the render-failure race into the deferred-render path.
    instant_oversize,
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
            /// What this connection answers with, per its mode.
            response_bytes: []const u8 = sized_response,
            /// Close right after the response: until-close and truncated
            /// bodies are delimited by the FIN itself.
            close_after_response: bool = false,
            /// Instant and mute modes never answer parsed requests; any
            /// forwarded bytes are read and discarded.
            drain_only: bool = false,
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
                if (conn.mode == .reset) {
                    conn.origin.io.setLingerRst(conn.socket) catch unreachable;
                    conn.close();
                    return;
                }
                conn.request_len += received;
                assert(conn.request_len <= conn.request_buffer.len);
                conn.advance();
            }

            /// The drain loop for instant and mute modes: forwarded bytes
            /// are legal but never answered — recv into the front of the
            /// buffer and discard, so it can never fill.
            fn armDrainRecv(conn: *Conn) void {
                assert(!conn.done);
                assert(conn.drain_only);
                conn.origin.io.recv(
                    conn.socket,
                    conn.request_buffer[0..],
                    &conn.recv_completion,
                    Conn,
                    conn,
                    onDrainRecv,
                );
            }

            fn onDrainRecv(conn: *Conn, result: Io.RecvError!u32) void {
                assert(conn.drain_only);
                _ = result catch {
                    conn.close();
                    return;
                };
                conn.armDrainRecv();
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

            /// True when `target` is already in §7 canonical form:
            /// re-canonicalizing leaves the path unchanged and the query
            /// verbatim, so path + query reproduces the target exactly.
            /// OPTIONS asterisk-form has no path and is trivially canonical.
            fn targetIsCanonical(conn: *Conn, target: []const u8) bool {
                _ = conn;
                assert(target.len >= 1);
                if (target[0] != '/') {
                    return true;
                }
                var canon_buf: [constants.head_bytes_max]u8 = undefined;
                const canonical = parser.canonicalTarget(target, &canon_buf) catch {
                    return false;
                };
                assert(canonical.path.len >= 1);
                assert(canonical.path[0] == '/');
                if (canonical.path.len + canonical.query.len != target.len) {
                    return false;
                }
                assert(canonical.path.len <= target.len);
                if (!std.mem.startsWith(u8, target, canonical.path)) {
                    return false;
                }
                return std.mem.eql(u8, target[canonical.path.len..], canonical.query);
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
                // §7 canonical forwarding: the proxy sends the canonical
                // path the router matched on, so what the origin receives
                // must already be canonical — re-canonicalizing is a no-op.
                // A raw dot-segment or decodable escape here would mean the
                // router and the origin could disagree about the resource.
                if (!conn.targetIsCanonical(request.target)) {
                    conn.origin.violations += 1;
                    conn.close();
                    return false;
                }
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
                assert(conn.response_sent < conn.response_bytes.len);
                conn.origin.io.send(
                    conn.socket,
                    conn.response_bytes[conn.response_sent..],
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
                assert(conn.response_sent <= conn.response_bytes.len);
                if (conn.response_sent < conn.response_bytes.len) {
                    conn.armSend();
                    return;
                }
                conn.requests_served += 1;
                if (conn.close_after_response) {
                    // The FIN is the delimiter (until-close), or the
                    // truncation itself (truncated).
                    conn.close();
                    return;
                }
                if (conn.drain_only) {
                    // Instant modes answered at accept; whatever the
                    // proxy still forwards is read and dropped.
                    conn.armDrainRecv();
                    return;
                }
                // Keep-alive: the next request parses from the new offset
                // (its bytes may already be buffered).
                conn.phase = .head;
                conn.advance();
            }

            /// Wire a fresh connection per its mode: pick the response,
            /// decide whether the FIN delimits it, and for the instant
            /// modes answer now — before any request byte arrives.
            fn beginMode(conn: *Conn) void {
                assert(!conn.done);
                assert(conn.phase == .head);
                switch (conn.mode) {
                    .sized, .reset => conn.armRecv(),
                    .chunked => {
                        conn.response_bytes = chunked_response;
                        conn.armRecv();
                    },
                    .until_close => {
                        conn.response_bytes = until_close_response;
                        conn.close_after_response = true;
                        conn.armRecv();
                    },
                    .truncated => {
                        conn.response_bytes = truncated_response;
                        conn.close_after_response = true;
                        conn.armRecv();
                    },
                    .mute => {
                        conn.drain_only = true;
                        conn.armDrainRecv();
                    },
                    .instant_sized => {
                        conn.drain_only = true;
                        conn.phase = .respond;
                        conn.beginRespond();
                    },
                    .instant_oversize => {
                        conn.response_bytes = oversize_head;
                        conn.drain_only = true;
                        conn.phase = .respond;
                        conn.beginRespond();
                    },
                }
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
            conn.beginMode();
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

/// The client's request scripts: the valid shapes, the §7 reject shapes
/// (each pinned to its exact verdict on clean seeds), and the connection
/// patterns (keep-alive reuse, pipelining, silence).
pub const Script = enum(u8) {
    /// A bodyless GET; expects one canonical 200.
    get,
    /// A POST with a 24-byte sized body; expects one canonical 200.
    post_sized,
    /// A POST with a 6000-byte sized body: bigger than one virtual-socket
    /// push, so the body spans multiple deliveries — the excess-forward
    /// and body-pump paths race the response leg for the head buffer
    /// (§7 buffer rotation), which is where a misbehaving instant origin
    /// meets the deferred render.
    post_big,
    /// A POST with a valid chunked body; expects one canonical 200.
    post_chunked,
    /// A chunked POST whose first body byte violates chunk framing —
    /// the silent-teardown-instead-of-400 shape (§7): clean seeds
    /// demand the 400.
    post_chunked_malformed,
    /// A bare-LF head terminator (smuggling shape); 400.
    malformed_head,
    /// A request line alone overflowing the proxy's 8 KiB head buffer;
    /// 414.
    oversize_uri,
    /// CONNECT is a §1 non-goal; 501.
    connect_method,
    /// Two sequential GETs on one connection: the §5 parking/checkout
    /// path — the second is sent only after the first 200 settles
    /// reusable.
    keepalive_pair,
    /// Two GETs in one send: the proxy answers the first, announces
    /// close (§2), and never serves the second.
    pipelined,
    /// Connects and sends nothing: the head-read deadline reaps it;
    /// any response byte is a violation.
    silent,
    /// A GET whose path only reaches the routable resource after
    /// canonicalization — an encoded `..` that collapses a segment away
    /// (`/deep/%2e%2e/sim` → `/sim`). It must route and forward exactly as
    /// `/sim` would; the origin's canonical oracle catches a raw-path
    /// forward, and a router matching raw bytes would route it elsewhere.
    confusion,
    /// A GET under `/reject`: a §7 filter rejects it with 403 before any
    /// resource is acquired or origin dialed. The golden outcome is exactly
    /// that 403, and the origin must never see the request.
    filter_reject,
    /// A GET under `/edit`: a §7 filter adds a header to the forwarded
    /// request. It routes and succeeds (200); the origin's §7 oracle proves
    /// the edited head still forwards canonical.
    filter_edit,
    /// A GET under `/rewrite`: a §7 filter rewrites the forwarded path to
    /// `/sim`. It routes on the original path and succeeds (200); the
    /// origin sees a canonical rewritten path, never `//`-merged.
    filter_rewrite,
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

        const post_body = "request-body-24-bytes-ab";
        const get_request = "GET /sim HTTP/1.1\r\nHost: sim\r\n\r\n";
        /// Deterministic 6000-byte body for `post_big`, cycled so the
        /// origin-side §7 oracle can spot any reordering.
        const big_body = blk: {
            @setEvalBranchQuota(30_000);
            var bytes: [6000]u8 = undefined;
            for (&bytes, 0..) |*byte, index| {
                byte.* = 'a' + @as(u8, @intCast(index % 26));
            }
            const frozen = bytes;
            break :blk frozen;
        };
        comptime {
            assert(post_body.len == 24);
            assert(big_body.len == 6000);
        }

        fn requestBytes(script: Script) []const u8 {
            return switch (script) {
                .get => get_request,
                .post_sized => "POST /sim HTTP/1.1\r\nHost: sim\r\n" ++
                    "Content-Length: 24\r\n\r\n" ++ post_body,
                .post_big => "POST /big HTTP/1.1\r\nHost: sim\r\n" ++
                    "Content-Length: 6000\r\n\r\n" ++ big_body,
                .post_chunked => "POST /sim HTTP/1.1\r\nHost: sim\r\n" ++
                    "Transfer-Encoding: chunked\r\n\r\n" ++ "8\r\nabcdefgh\r\n0\r\n\r\n",
                // "Z" is no chunk-size digit: the framing violation is in
                // the first body byte, coalesced with the head.
                .post_chunked_malformed => "POST /sim HTTP/1.1\r\nHost: sim\r\n" ++
                    "Transfer-Encoding: chunked\r\n\r\nZ",
                // A bare LF terminating the request line (§7 smuggling
                // shape).
                .malformed_head => "GET /sim HTTP/1.1\nHost: sim\r\n\r\n",
                // The request line alone must overflow the proxy's 8 KiB
                // head buffer with no newline in sight: 414, not 431.
                .oversize_uri => "GET /" ++ ("a" ** 8500) ++ " HTTP/1.1\r\nHost: sim\r\n\r\n",
                .connect_method => "CONNECT origin:443 HTTP/1.1\r\nHost: origin\r\n\r\n",
                // The second GET is appended at run time, only after the
                // first 200 settles reusable.
                .keepalive_pair => get_request,
                .pipelined => get_request ++ get_request,
                .silent => "",
                // Canonicalizes to /sim (the `/deep` segment is popped by
                // the decoded `..`), so it routes and forwards as /sim.
                .confusion => "GET /deep/%2e%2e/sim HTTP/1.1\r\nHost: sim\r\n\r\n",
                // §7 filter scripts: a distinct path per action so the
                // listener's rules fire only for these, never the others.
                .filter_reject => "GET /reject HTTP/1.1\r\nHost: sim\r\n\r\n",
                .filter_edit => "GET /edit HTTP/1.1\r\nHost: sim\r\n\r\n",
                .filter_rewrite => "GET /rewrite HTTP/1.1\r\nHost: sim\r\n\r\n",
            };
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
            const bytes = requestBytes(script);
            assert(bytes.len <= client.request.len);
            @memcpy(client.request[0..bytes.len], bytes);
            client.request_len = @intCast(bytes.len);
        }

        pub fn begin(client: *Self) void {
            assert(client.request_len >= 1 or client.script == .silent);
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
                client.script,
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

        /// The keep-alive pair's second exchange starts only after the
        /// first 200 settles reusable — the §5 parked-connection checkout
        /// under schedule fuzz.
        fn maybeSendSecondRequest(client: *Self, walk: *const Walk) void {
            if (client.script != .keepalive_pair or client.second_sent) return;
            if (walk.violation != null) return;
            if (walk.complete_count != 1) return;
            if (!firstExchangeReusable(walk)) return;
            // A complete first response implies the proxy consumed the
            // whole first request, so the send op has settled.
            assert(!client.send_pending);
            assert(client.sent_len == client.request_len);
            const second = get_request;
            assert(client.request_len + second.len <= client.request.len);
            @memcpy(client.request[client.request_len..][0..second.len], second);
            client.request_len += @intCast(second.len);
            client.second_sent = true;
            client.armSend();
        }

        /// How many responses the script still legally expects, given
        /// what has arrived: the keep-alive pair degrades to a single
        /// exchange when its first response refuses reuse (an error
        /// status, or an announced close under pressure or drain).
        fn responsesTarget(script: Script, walk: *const Walk) u8 {
            const static_target = expectedResponses(script);
            if (script != .keepalive_pair) return static_target;
            if (walk.complete_count >= 1 and !firstExchangeReusable(walk)) {
                return 1;
            }
            return static_target;
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
                // §2: a pipelined first response must announce the close
                // that follows it.
                if (client.script == .pipelined and walk.keep_alives[0]) {
                    return ClientError.GoldenOutcomeMissed;
                }
            }
        }

        const Walk = struct {
            complete_count: u8,
            offset: u32,
            statuses: [responses_max]u16,
            /// Per-response persistence verdicts (§2): version defaults
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
        fn walkResponses(bytes: []const u8, script: Script) Walk {
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
                walk.keep_alives[walk.complete_count] = response.keep_alive;
                walk.complete_count += 1;
                walk.offset += response.head_len + verdict.body_len;
                // A complete response beyond the script's transcript is a
                // duplication bug, not a legal prefix.
                if (walk.complete_count > transcriptCap(script)) {
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
        /// comparison: a 200 carries exactly one canonical body per
        /// framing (the proxy relays body wire bytes verbatim), and
        /// every legal non-200 is a static with Content-Length 0 — so a
        /// corrupted length fails even before its body arrives.
        fn walkBody(response: parser.ResponseHead, body: []const u8) ?BodyVerdict {
            switch (response.framing) {
                .content_length => |length| {
                    if (response.status == 200) {
                        if (length != sized_body.len) {
                            return .{ .body_len = 0, .violation = ClientError.ResponseBodyCorrupted };
                        }
                        return prefixVerdict(body, sized_body, @intCast(length));
                    }
                    if (length != 0) {
                        return .{ .body_len = 0, .violation = ClientError.ResponseBodyCorrupted };
                    }
                    return .{ .body_len = 0, .violation = null };
                },
                .chunked => {
                    if (response.status != 200) {
                        return .{ .body_len = 0, .violation = ClientError.ResponseCorrupted };
                    }
                    return prefixVerdict(body, chunked_wire, chunked_wire.len);
                },
                .until_close => {
                    if (response.status != 200) {
                        return .{ .body_len = 0, .violation = ClientError.ResponseCorrupted };
                    }
                    // The FIN delimits this body, so it is transcript-
                    // final: bytes beyond the canonical body — or past
                    // where the close must fall — are corruption, and
                    // whatever arrived counts as the (possibly cut)
                    // complete response.
                    if (body.len > until_close_body.len) {
                        return .{ .body_len = 0, .violation = ClientError.ResponseBodyCorrupted };
                    }
                    const have: u32 = @intCast(body.len);
                    if (!std.mem.eql(u8, body[0..have], until_close_body[0..have])) {
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

        fn expectedResponses(script: Script) u8 {
            return switch (script) {
                .get, .post_sized, .post_big, .post_chunked, .confusion => 1,
                .post_chunked_malformed, .malformed_head => 1,
                .oversize_uri, .connect_method, .pipelined => 1,
                .filter_reject, .filter_edit, .filter_rewrite => 1,
                .keepalive_pair => 2,
                .silent => 0,
            };
        }

        /// The most complete responses ANY legal transcript can contain —
        /// the walker's surplus bound. Pipelined admits one more than the
        /// clean expectation: when adversarial fragmentation lands exactly
        /// on the request boundary, the proxy never observes the pipelined
        /// bytes and legally serves both requests as plain keep-alive.
        /// The clean tier still pins pipelined to exactly one (detection
        /// is deterministic there).
        fn transcriptCap(script: Script) u8 {
            return switch (script) {
                .pipelined => 2,
                else => expectedResponses(script),
            };
        }

        /// The exact status a clean seed's script must produce. Silent
        /// never produces one; its zero-response transcript makes the
        /// value unread.
        fn goldenStatus(script: Script) u16 {
            return switch (script) {
                .get, .post_sized, .post_big, .post_chunked, .keepalive_pair, .pipelined, .confusion => 200,
                // The edit and rewrite scripts route and succeed; only the
                // reject script's golden verdict is its 403.
                .filter_edit, .filter_rewrite => 200,
                .filter_reject => 403,
                .post_chunked_malformed, .malformed_head => 400,
                .oversize_uri => 414,
                .connect_method => 501,
                .silent => 0,
            };
        }

        /// The method context for response parsing (HEAD-shaped body
        /// rules). CONNECT maps to GET: the parser refuses to represent a
        /// CONNECT response (the proxy rejects the method before dialing),
        /// and the 501 static carries no body either way.
        fn methodOf(script: Script) parser.Method {
            return switch (script) {
                .post_sized, .post_big, .post_chunked, .post_chunked_malformed => .post,
                .get, .malformed_head, .oversize_uri, .confusion => .get,
                .connect_method, .keepalive_pair, .pipelined, .silent => .get,
                .filter_reject, .filter_edit, .filter_rewrite => .get,
            };
        }

        /// Statuses a script may legally see. Valid requests meet the
        /// canonical 200, the §8 rungs (503), or an upstream that the
        /// adversary killed (502); parse verdicts precede routing, so the
        /// reject scripts admit exactly their own verdict — and a silent
        /// client may see nothing at all.
        fn statusAllowed(script: Script, status: u16) bool {
            // Every script that dials may also see the §8 request-deadline
            // verdict: a mute or stalled origin (adversarial delivery can
            // stall any of them) earns a 504 once the deadline expires with
            // no response byte sent. Clean seeds pin the origin to `sized`
            // and never stall, so `goldenStatus` still demands exact
            // outcomes there.
            return switch (script) {
                .get, .post_sized, .post_big, .post_chunked, .keepalive_pair, .pipelined, .confusion => //
                status == 200 or status == 502 or status == 503 or status == 504,
                // Edit and rewrite route and forward like a plain GET, so
                // the §8 rungs and a killed dial can precede the 200.
                .filter_edit, .filter_rewrite => //
                status == 200 or status == 502 or status == 503 or status == 504,
                // A reject is answered before any resource is acquired or
                // origin dialed, so no §8 rung or dial failure can precede
                // it — the only complete verdict is the 403.
                .filter_reject => status == 403,
                // The head routes and forwards before its body is
                // validated, so several outcomes can precede the 400: the §8
                // rungs, a killed dial, and — the subtlety — an early origin
                // response. An instant origin answers 200 before the proxy
                // ever pumps the malformed body (which it then contains,
                // never forwarding it: the origin's §7 oracle still holds).
                // Clean seeds pin the origin to `sized`, so they never race
                // it and `goldenStatus` still demands the exact 400 there.
                .post_chunked_malformed => //
                status == 400 or status == 200 or status == 502 or status == 503 or status == 504,
                .malformed_head => status == 400,
                .oversize_uri => status == 414,
                .connect_method => status == 501,
                .silent => false,
            };
        }
    };
}
