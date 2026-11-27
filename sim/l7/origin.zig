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
    /// As `chunked`, with a trailer section after the last chunk (§7): a
    /// field every client must hear, relayed verbatim to HTTP/1.1 and as
    /// trailing HEADERS to HTTP/2 and HTTP/3.
    chunked_trailers,
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
    /// Answer `100 Continue` and then the canonical sized 200 (#232).
    /// An interim is not the answer: a proxy that settles on one closes
    /// on a client still sending its body, or parks an upstream with the
    /// real response unread and hands it to the next client.
    interim_then_sized,
    /// Answer `103 Early Hints` past the proxy's own bound and never
    /// answer at all — the unbounded-`1xx` origin neither nginx nor
    /// HAProxy bounds, which the one-thread design has to.
    interim_flood,
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
        /// Marked bodies (#373) that did not arrive as their client sent
        /// them: a framing at odds with the mark, or an octet out of
        /// place. Checked by the harness verify.
        body_mismatches: u32 = 0,
        /// Marked bodies that arrived whole: the census's proof that the
        /// check above ever ran.
        bodies_verified: u32 = 0,
        /// Chunked request bodies whose trailer section was not what
        /// their head owed (§7): one missing, one that should not have
        /// come, or the wrong bytes. Checked by the harness verify.
        trailer_mismatches: u32 = 0,
        /// Owed trailer sections that arrived exactly: the census's proof
        /// that HTTP/1.1's relay of a request's trailers was walked.
        trailers_verified: u32 = 0,
        /// The hops the scripts claim in their own forwarded-for lines:
        /// all a §7 chain may hold besides the observed client.
        forwarded_hops: []const []const u8 = &.{},
        /// The client the proxy observed, as `bareAddress` writes it — set
        /// by the harness for the seed's address family.
        observed_client: []const u8 = "",
        /// Chains that held anything else, or the observed client
        /// anywhere but last. Checked by the harness verify.
        forwarded_mismatches: u32 = 0,
        /// Chains that ended in an IPv6 observed client, read exactly.
        forwarded_ip6_verified: u32 = 0,
        /// The fingerprint a verified client's requests carry (#304), as
        /// the header spells it, and the requests that carried it. Any
        /// other value — a client's own forgery, or another client's — or
        /// the header twice, counts as a forwarded-for mismatch does.
        client_cert_sha256: []const u8 = "",
        client_certs_verified: u32 = 0,
        client_cert_mismatches: u32 = 0,
        /// Where a chunked body is dechunked for its trailer check, so
        /// the wire it is read from stays as it came for the mark check.
        scratch: [request_buffer_bytes]u8 = undefined,

        const Self = @This();
        /// Sized for the HTTP/1.1 worst case: client-driven dials (fresh,
        /// replay, post-ejection) plus a `check` scenario's passing
        /// probes, each of which accepts and vanishes (§7) but still
        /// consumes a slot. Fresh slots are handed out first, so such a
        /// seed reuses none while it stays inside that sizing. Past them,
        /// `acquireConn` reuses a slot the origin is done with: a Rapid
        /// Reset client (#276) opens and resets a stream per round for
        /// `resets_unpaid_max + 1` rounds (101), and each round can cost
        /// one dial — more than this whole slab from one client, while
        /// few of them are live at once.
        pub const conns_max: u8 = 64;
        pub const request_buffer_bytes: u32 = 16384;

        const Phase = enum(u8) { head, body, respond };
        const FramingTag = enum(u8) { none, content_length, chunked };
        /// A request body's mark (#373): what its client sent, and where
        /// in the buffer the forwarded body starts.
        const MarkedBody = struct { length: u32, salt: u32, start: u32 };

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
            /// The request in flight's body mark, if it carries one.
            marked: ?MarkedBody = null,
            /// Where the request in flight's body starts in the buffer.
            body_start: u32 = 0,
            /// The request in flight's head said a trailer section comes.
            trailer_owed: bool = false,
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
                var canon_buf: [constants.head_buffer_bytes_default]u8 = undefined;
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

            /// The §7 promise an absolute-form request must not weaken
            /// (#233): the forwarded request line is origin-form, and the
            /// single `Host` it carries is the name that routed. A proxy
            /// that forwarded the client's target verbatim would fail the
            /// first test; one that routed on the authority but forwarded
            /// the Host beside it would fail the second, which is the
            /// disagreement RFC 9112 §3.2.2 exists to settle.
            fn forwardedNamesOneAuthority(conn: *Conn, request: *const parser.RequestHead) bool {
                _ = conn;
                if (request.authority != null) {
                    return false;
                }
                const host = request.host orelse return true;
                return !std.mem.eql(u8, host, canon.overridden_host);
            }

            /// RFC 9110 §7.6.2 seen from the far end (#240): whatever
            /// budget a request arrived with, the one this origin reads
            /// is a hop shorter — and a `TRACE` never arrives at all,
            /// because §7 answers it rather than forwarding it.
            ///
            /// The exact value is checkable because one script sends the
            /// header and the numbers are canon's: a proxy forwarding it
            /// verbatim shows the sent value, one dropping it shows none,
            /// and either is a rule this hop did not apply.
            fn forwardedSpentAHop(conn: *Conn, request: *const parser.RequestHead) bool {
                _ = conn;
                if (request.method == .trace) {
                    return false;
                }
                const budget = parser.headerValue(request.headers, "max-forwards") orelse
                    return true;
                return std.mem.eql(u8, budget, canon.max_forwards_forwarded);
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
                const request = parser.parseRequestHead(bytes, false, &storage, null) catch |err| {
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
                // A forwarded `Upgrade` means the proxy agreed to carry a
                // handshake (#180), so answer it the way an origin that
                // speaks the protocol would: `101`, and then the bytes
                // are opaque — no further request will ever parse out of
                // this connection, so it drains from here.
                //
                // Decided from the request rather than from a drawn mode,
                // because that is what a real origin does and because it
                // keeps a clean seed deterministic: the same request gets
                // the same answer whatever the schedule.
                if (parser.headerValue(request.headers, "upgrade") != null) {
                    conn.response_bytes = canon.switching_response;
                    conn.drain_only = true;
                }
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
                // #233: whatever form a client used to name the resource,
                // the origin is spoken to in origin-form, and the Host it
                // reads is the authority that routed — never the one an
                // absolute-form request line overruled. Checked for every
                // script because only one can produce either shape, which
                // makes a blanket check an exact one.
                if (!conn.forwardedNamesOneAuthority(&request)) {
                    conn.origin.violations += 1;
                    conn.close();
                    return false;
                }
                if (!conn.forwardedSpentAHop(&request)) {
                    conn.origin.violations += 1;
                    conn.close();
                    return false;
                }
                if (!conn.forwardedForValid(&request)) {
                    conn.origin.forwarded_mismatches += 1;
                    conn.close();
                    return false;
                }
                if (!conn.clientCertValid(&request)) {
                    conn.origin.client_cert_mismatches += 1;
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
                conn.body_start = conn.request_offset;
                conn.trailer_owed = if (parser.headerValue(request.headers, canon.request_trailer_owed_header)) |value|
                    std.mem.eql(u8, value, "1")
                else
                    false;
                conn.marked = null;
                if (parser.headerValue(request.headers, canon.request_body_header)) |value| {
                    conn.marked = markedBody(value, &request, conn.request_offset) orelse {
                        conn.origin.body_mismatches += 1;
                        conn.close();
                        return false;
                    };
                }
                conn.phase = .body;
                return true;
            }

            /// Every element of every `X-Forwarded-For` line is a hop a
            /// script claimed or the observed client, and the client, if
            /// there, ends the last line (§7): `append` puts it after the
            /// chain, `replace` alone. A client address rendered any other
            /// way — an IPv6 one bracketed, a port left on — is neither.
            fn forwardedForValid(conn: *Conn, request: *const parser.RequestHead) bool {
                const origin = conn.origin;
                assert(origin.observed_client.len >= 1);
                var client_seen = false;
                for (request.headers) |header| {
                    if (!std.ascii.eqlIgnoreCase(header.name, "x-forwarded-for")) continue;
                    var elements = std.mem.splitSequence(u8, header.value, ", ");
                    while (elements.next()) |element| {
                        if (client_seen) return false;
                        if (std.mem.eql(u8, element, origin.observed_client)) {
                            client_seen = true;
                            continue;
                        }
                        if (!isScriptHop(origin.forwarded_hops, element)) return false;
                    }
                }
                const ip6 = std.mem.indexOfScalar(u8, origin.observed_client, ':') != null;
                if (client_seen and ip6) origin.forwarded_ip6_verified += 1;
                // A chain with no client is only ever hops a script named.
                assert(client_seen or origin.forwarded_hops.len >= 1);
                return true;
            }

            /// `X-Client-Cert-SHA256` once at most, and then the verified
            /// client's own: the proxy strips every inbound copy and sets
            /// the one it verified (§4).
            fn clientCertValid(conn: *Conn, request: *const parser.RequestHead) bool {
                const origin = conn.origin;
                assert(origin.client_cert_sha256.len == 64);
                var seen: u32 = 0;
                for (request.headers) |header| {
                    if (!std.ascii.eqlIgnoreCase(header.name, "x-client-cert-sha256")) continue;
                    seen += 1;
                    if (!std.mem.eql(u8, header.value, origin.client_cert_sha256)) return false;
                }
                if (seen > 1) return false;
                origin.client_certs_verified += seen;
                assert(seen <= 1);
                return true;
            }

            fn isScriptHop(hops: []const []const u8, element: []const u8) bool {
                assert(hops.len >= 1);
                for (hops) |hop| {
                    if (std.mem.eql(u8, hop, element)) return true;
                }
                return false;
            }

            /// The mark's `<length>.<salt>`, if the request's framing can
            /// carry that body: chunked, or the very length declared. One
            /// with no body framing at all lost its body on the way.
            fn markedBody(value: []const u8, request: *const parser.RequestHead, body_start: u32) ?MarkedBody {
                const dot = std.mem.indexOfScalar(u8, value, '.') orelse return null;
                const length = std.fmt.parseUnsigned(u32, value[0..dot], 10) catch return null;
                const salt = std.fmt.parseUnsigned(u32, value[dot + 1 ..], 10) catch return null;
                switch (request.framing) {
                    .none => return null,
                    .content_length => |declared| if (declared != length) return null,
                    .chunked => {},
                    .until_close => unreachable, // Requests are length-delimited.
                }
                assert(body_start >= request.head_len);
                return .{ .length = length, .salt = salt, .start = body_start };
            }

            /// Whether a marked body arrived as its client sent it: every
            /// octet, in order, and no more, dechunked first when the
            /// proxy chunked it. Dechunked in place: the body is consumed,
            /// and nothing reads its wire again.
            fn bodyMatches(conn: *Conn, marked: MarkedBody) bool {
                assert(conn.phase == .body);
                assert(marked.start <= conn.request_offset);
                const wire = conn.request_buffer[marked.start..conn.request_offset];
                const body = switch (conn.framing_tag) {
                    .none => unreachable, // `markedBody` refused it.
                    .content_length => wire,
                    .chunked => body: {
                        var scanner: parser.ChunkedScanner = .{};
                        const dechunked = scanner.dechunk(wire) catch return false;
                        if (!dechunked.done) return false;
                        if (dechunked.consumed != wire.len) return false;
                        break :body wire[0..dechunked.payload_len];
                    },
                };
                if (body.len != marked.length) return false;
                for (body, 0..) |octet, index| {
                    if (octet != canon.requestBodyOctet(marked.salt, @intCast(index))) return false;
                }
                return true;
            }

            /// A whole request's trailer section is what its head owed (§7):
            /// exactly the canonical one where the head says one comes,
            /// none where it does not. A length-delimited body has nowhere
            /// to carry one, so it may not be owed one. Dechunked from a
            /// copy, so the mark check after it reads the wire as it came.
            fn trailersMatch(conn: *Conn) bool {
                assert(conn.phase == .body);
                assert(conn.body_start <= conn.request_offset);
                if (conn.framing_tag != .chunked) return !conn.trailer_owed;
                const wire = conn.request_buffer[conn.body_start..conn.request_offset];
                const copy = conn.origin.scratch[0..wire.len];
                @memcpy(copy, wire);
                // `consumeBody`'s scanner already passed these octets as a
                // whole chunked body, and this is the same scanner: either
                // failure below is a framing violation, so it is counted as
                // one rather than as a trailer that came wrong.
                var scanner: parser.ChunkedScanner = .{};
                const dechunked = scanner.dechunk(copy) catch {
                    conn.origin.violations += 1;
                    return false;
                };
                if (!dechunked.done) {
                    conn.origin.violations += 1;
                    return false;
                }
                assert(dechunked.trailer_len <= dechunked.consumed);
                const section = copy[dechunked.consumed - dechunked.trailer_len .. dechunked.consumed];
                const expected = if (conn.trailer_owed) canon.request_trailer_section else canon.empty_trailer_section;
                if (!std.mem.eql(u8, section, expected)) return false;
                if (conn.trailer_owed) conn.origin.trailers_verified += 1;
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
                const violations_before = conn.origin.violations;
                if (!conn.trailersMatch()) {
                    if (conn.origin.violations == violations_before) conn.origin.trailer_mismatches += 1;
                    conn.close();
                    return false;
                }
                if (conn.marked) |marked| {
                    if (!conn.bodyMatches(marked)) {
                        conn.origin.body_mismatches += 1;
                        conn.close();
                        return false;
                    }
                    conn.origin.bodies_verified += 1;
                }
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
                    .interim_then_sized => {
                        conn.response_bytes = canon.interim_continue ++ canon.sized_response;
                        conn.armRecv();
                    },
                    .interim_flood => {
                        // Never answers: the proxy's own bound is what
                        // ends this, which is the whole point of the mode.
                        conn.response_bytes = zoxy.testing.repeat(
                            canon.interim_hints,
                            zoxy.constants.interim_responses_max + 2,
                        );
                        conn.drain_only = true;
                        conn.armRecv();
                    },
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
                    .chunked_trailers => {
                        conn.response_bytes = canon.chunked_trailers_response;
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
            origin.listener = try io.listen(&.{ .ip = address }, null);
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
            const conn = origin.acquireConn();
            conn.origin = origin;
            conn.socket = socket;
            conn.mode = if (origin.mode_selector) |select|
                select(origin.context)
            else
                .sized;
            conn.beginMode();
            origin.armAccept();
        }

        /// The slot an accepted connection takes: a fresh one while any
        /// remain, then one the origin closed with neither of its ops
        /// still pending, so nothing the loop delivers can reach it again.
        /// An op dropped by a stranding seed (#206) never completes, and
        /// its slot is never reused. `closeRemaining` reads only what is
        /// still open, so a reused slot loses no record.
        fn acquireConn(origin: *Self) *Conn {
            assert(origin.conns_count <= origin.conns.len);
            if (origin.conns_count < origin.conns.len) {
                const conn = &origin.conns[origin.conns_count];
                origin.conns_count += 1;
                assert(!conn.done);
                return conn;
            }
            for (&origin.conns) |*conn| {
                if (!conn.done) continue;
                if (conn.recv_completion.state == .pending) continue;
                if (conn.send_completion.state == .pending) continue;
                conn.* = .{};
                return conn;
            }
            @panic("sim origin: more connections live at once than conns_max");
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
