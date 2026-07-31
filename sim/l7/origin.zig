//! The scripted HTTP/1.1 origin of the simulation gate (§9), generic
//! over the Io backend. An oracle, not an expectation: it asserts the §7
//! promise that no malformed byte is ever forwarded upstream — every
//! request it receives must parse, every body must satisfy its own
//! framing, every forwarded target must already be canonical. A
//! violation here means the proxy relayed something it was built to
//! reject.

const std = @import("std");

const zoxy = @import("zoxy");

const canon = @import("canon.zig");
const scripts = @import("scripts.zig");

const Io = zoxy.Io;
const parser = zoxy.http.parser;
const constants = zoxy.constants;

const assert = std.debug.assert;

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
    /// Answer the sized keep-alive 200, then close: the proxy parks on
    /// the head's promise, the FIN lands while parked, and the next
    /// checkout meets the §5 stale connection — the §7 replay's shape.
    stale_reuse,
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
        /// Sized for the worst case: client-driven dials (fresh, replay,
        /// post-ejection) plus a `check` scenario's passing probes, each
        /// of which accepts and vanishes (§7) but still consumes a slot —
        /// conns are tracked monotonically, never recycled.
        pub const conns_max: u8 = 64;
        const request_buffer_bytes: u32 = 16384;

        const Phase = enum(u8) { head, body, respond };
        const FramingTag = enum(u8) { none, content_length, chunked };

        comptime {
            // What `compact` makes true, checked rather than trusted:
            // the buffer measures one request, so every script's wire
            // bytes must fit it. Add a script past this and the gate
            // fails at compile time instead of surfacing as a
            // one-in-200k `OriginSawMalformedBytes`.
            //
            // One request is the whole bound. A recv can coalesce this
            // request's tail with the next one's opening bytes, which
            // `compact` carries over — but only a later exchange can
            // supply those, and §5 checkout is exclusive, so the proxy
            // cannot forward the next request until this response has
            // fully arrived, which is after `compact` ran. Hence the
            // carry-over is empty in practice, and the largest
            // forwarded script (`post_big`, 6055 bytes) leaves 10 KiB
            // spare even if it were not.
            for (std.enums.values(scripts.Script)) |script| {
                assert(scripts.spec(script).request.len <= request_buffer_bytes);
            }
        }

        pub const Conn = struct {
            origin: *Self = undefined,
            socket: IoType.Socket = undefined,
            recv_completion: IoType.Completion = .{},
            send_completion: IoType.Completion = .{},
            /// Received and not yet consumed; the current request starts
            /// at `request_offset` and parses from there. Compacted at
            /// each keep-alive boundary, so this bounds one request, not
            /// a reused connection's lifetime.
            request_buffer: [request_buffer_bytes]u8 = undefined,
            request_len: u32 = 0,
            request_offset: u32 = 0,
            phase: Phase = .head,
            framing_tag: FramingTag = .none,
            content_remaining: u64 = 0,
            chunk_scanner: parser.ChunkedScanner = .{},
            mode: OriginMode = .sized,
            /// What this connection answers with, per its mode.
            response_bytes: []const u8 = canon.sized_response,
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
                    // An injected set-option fault (§9) can land here
                    // rather than on the server: the injector is a
                    // process-wide one-shot, and this double shares the
                    // seam. Absorbing it costs the scenario an RST and
                    // leaves a graceful close — a shape this origin
                    // already produces in other modes, so every client
                    // oracle still holds.
                    conn.origin.io.setLingerRst(conn.socket) catch {};
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

            /// Drop what the answered requests consumed, so the buffer
            /// measures the request in flight rather than everything the
            /// connection ever carried. §5 parking reuses one upstream
            /// connection across exchanges, and the reuse count is
            /// unbounded: without this, enough `post_big` forwards
            /// (6055 bytes each) fill any buffer, and the oracle reads
            /// that well-framed traffic as forwarded excess — failing
            /// the seed on the proxy's own good behavior. Seed 3064744
            /// was three of them on one connection.
            fn compact(conn: *Conn) void {
                assert(conn.phase == .head);
                assert(conn.request_offset >= 1);
                assert(conn.request_offset <= conn.request_len);
                const remaining = conn.request_len - conn.request_offset;
                // Shifting left, so forwards: every destination write
                // lands before that offset is read as a source.
                std.mem.copyForwards(
                    u8,
                    conn.request_buffer[0..remaining],
                    conn.request_buffer[conn.request_offset..conn.request_len],
                );
                conn.request_len = remaining;
                conn.request_offset = 0;
                // A served request consumed at least its head, so the
                // compacted buffer always has room for `armRecv`.
                assert(conn.request_len < conn.request_buffer.len);
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
                // Keep-alive: the next request parses from the front
                // again (its bytes may already be buffered).
                conn.phase = .head;
                conn.compact();
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
                    .stale_reuse => {
                        // The keep-alive head parks the proxy's side; the
                        // close after responding is the staleness itself.
                        conn.close_after_response = true;
                        conn.armRecv();
                    },
                    .chunked => {
                        conn.response_bytes = canon.chunked_response;
                        conn.armRecv();
                    },
                    .until_close => {
                        conn.response_bytes = canon.until_close_response;
                        conn.close_after_response = true;
                        conn.armRecv();
                    },
                    .truncated => {
                        conn.response_bytes = canon.truncated_response;
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
                        conn.response_bytes = canon.oversize_head;
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
