//! The L7 HTTP/1.1 reverse-proxy state machine (DESIGN.md §7). Generic
//! over the Io backend and driven by the Server's helpers (pools,
//! counters, deadline, teardown), exactly as `net/relay.zig` drives the
//! L4 path — L7 lives here, never inlined into the L4 relay.
//!
//! Lifecycle: `l7_reading_head` accumulates the request head and
//! re-parses from byte 0 on each recv (§7 detect-and-retry); verdicts
//! answer comptime static responses (§8) with a lingering close (§7). A
//! valid request acquires its relay buffer and upstream slot (both §8
//! rungs, 503), dials (`l7_dialing`), then `l7_exchanging` runs two
//! semi-independent legs over the two data ops: the request leg sends
//! the rendered head from the upstream slot's staging buffer and pumps
//! the framed body client → origin; the response leg arms as soon as the
//! request head is on the wire — early responses are legal (§7) and
//! waiting for the body to finish first can deadlock both windows — and
//! mirrors head + framed body back. A finished exchange settles both
//! sides independently: the upstream connection parks on its endpoint's
//! idle list when the origin allowed reuse (checked out again by any
//! later request — §3's shared-pool win), and the downstream connection
//! honors what its rendered response announced (§7), going idle at the
//! cost of a slot + head buffer only (§5). Pipelining is unsupported
//! (first response, then an announced close). A stale checkout takes one
//! free replay on a fresh dial (§7), and an expired exchange or dial
//! that can still be answered gets the §8 request-deadline 504 verdict.
//!
//! Buffer ownership rotates, never overlaps: conn.head holds the request
//! head until it is rendered, then stages the rendered response head;
//! upstream.head stages the rendered request head, then accumulates the
//! response head; the relay-buffer halves carry only framed body bytes.
//! Head-adjacent excess never enters a relay half — it is forwarded
//! straight from the head buffer holding it, so a coalesced body larger
//! than a half is never squeezed through one.

const std = @import("std");

const access_log = @import("../access_log.zig");
const Balancer = @import("../balancer.zig").Balancer;
const config_module = @import("../config.zig");
const constants = @import("../constants.zig");
const conn_module = @import("../net/Conn.zig");
const pump = @import("../net/pump.zig");
const relay = @import("../net/relay.zig");
const Io = @import("../io/io.zig");
const parser = @import("parser.zig");
const render = @import("render.zig");
const router = @import("router.zig");
const filter = @import("filter.zig");
const shed = @import("../shed.zig");
const TlsEngine = @import("../tls/Engine.zig");

const assert = std.debug.assert;

/// One address without its port, which is the only shape an
/// `X-Forwarded-For` element may take (§7).
///
/// Formatted through the address type's own rendering and then stripped,
/// rather than written out here, so an IPv6 address gets std's canonical
/// `::` compression instead of a second spelling of it that could
/// disagree with the one every other zoxy output uses.
///
/// At file scope, outside `Proxy(IoType)`: it depends on no backend, and
/// the bracket handling is the fiddly part worth testing directly rather
/// than only through a scenario whose clients happen to be IPv4.
fn bareAddress(
    address: *const std.Io.net.IpAddress,
    scratch: *[constants.forwarded_client_bytes_max]u8,
) []const u8 {
    // The scratch is sized for the widest formatting — a bracketed IPv6
    // literal with its port — which `constants.zig` asserts.
    const text = std.fmt.bufPrint(scratch, "{f}", .{address.*}) catch unreachable;
    assert(text.len >= 1);
    if (text[0] == '[') {
        // IPv6 is bracketed *because* it carries a port; the brackets
        // exist to delimit it, so both come off together.
        const close = std.mem.indexOfScalar(u8, text, ']') orelse unreachable;
        assert(close >= 2);
        return text[1..close];
    }
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse unreachable;
    assert(colon >= 1);
    return text[0..colon];
}

pub fn Proxy(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);
    const ConnType = conn_module.Conn(IoType);
    const UpstreamType = @import("../net/upstream.zig").UpstreamPool(IoType).Upstream;
    const Framing = ConnType.Framing;

    return struct {
        /// Entry from admission: the slot is prepared in `.l7_reading_head`
        /// with the head-read deadline armed; begin reading the request
        /// head from the client.
        pub fn start(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_reading_head);
            assert(conn.head_len == 0);
            assert(conn.head_buffer_id == ConnType.head_buffer_none);
            if (conn.tls != null) {
                // Plaintext the handshake's last flight carried in with it
                // is already in the head buffer, at its front — a client
                // with nothing to wait for sends its request straight
                // after its Finished and TCP delivers both together. It
                // may be a whole request, so parse before reading: a fresh
                // read would wait on bytes already in hand.
                if (conn.tls_pending_len >= 1) {
                    const capacity = headBytes(server, conn).len;
                    const pending = conn.tls_pending_len;
                    conn.tls_pending_len = 0;
                    server.beginLogRequest(conn);
                    // The handshake phase collects whatever the last
                    // flight carried without knowing what the protocol
                    // will make of it, so it can hold more than an L7
                    // head may be. Same answer as an oversize read: fill
                    // to the limit and let the dispatch say which of 413
                    // or 431 it earned.
                    if (pending > capacity) {
                        fillHead(conn, @intCast(capacity), capacity);
                        answerHeadOverflow(server, conn);
                        return;
                    }
                    fillHead(conn, pending, capacity);
                    parseAndDispatch(server, conn);
                    return;
                }
                armTlsHeadRecv(server, conn);
                return;
            }
            armHeadGroupRecv(server, conn);
        }

        /// One ciphertext read for a terminated connection, straight into
        /// the engine's record buffer. The bufferless `recvGroup` arm has
        /// no analogue here: a terminated connection already holds an
        /// engine, so an idle one is not saving a buffer by waiting.
        fn armTlsHeadRecv(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_reading_head);
            assert(conn.tls != null);
            const destination = conn.tls.?.recvBuffer();
            assert(destination.len >= 1);
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                destination,
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onTlsHeadRecv,
            );
        }

        fn onTlsHeadRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_reading_head);
            const received = result catch |err| {
                // A client that leaves before finishing its head has
                // nothing to be answered; the §7 head deadline handles the
                // one that stalls instead. The witness counts only kernel
                // pressure, so an orderly close passes through it.
                server.witnessKernelPressure(.recv, err);
                server.beginTeardown(conn);
                return;
            };
            assert(received >= 1);
            var head: HeadPlaintext = .{ .server = server, .conn = conn };
            const sink = head.sink();
            conn.tls.?.received(received, &sink) catch {
                server.counters.increment("tls_relay_failed");
                server.beginTeardown(conn);
                return;
            };
            if (head.appended >= 1) {
                // A request begins with its first *plaintext* byte, on the
                // plaintext path's own rule (§8) — not with the delivery
                // that carried it. A record can decrypt to no application
                // data at all: a KeyUpdate, an alert, or the close_notify
                // that ends an idle keep-alive connection. Starting the
                // clock on the delivery opens a log entry for a request
                // nobody made, which teardown then writes out as an
                // aborted exchange with no method and no bytes.
                server.beginLogRequest(conn);
                conn.log.bytes_in += head.appended;
            }
            if (conn.tls.?.peerClosed()) {
                // An in-band EOF mid-head: the client said it will send no
                // more, and a partial head is not a request. Same verdict
                // as a socket close on the plaintext path.
                server.beginTeardown(conn);
                return;
            }
            if (head.overflowed) {
                answerHeadOverflow(server, conn);
                return;
            }
            if (conn.head_len == 0) {
                // A record carrying no application data — a KeyUpdate, an
                // alert, a fragment. Nothing parsed; read again.
                armTlsHeadRecv(server, conn);
                return;
            }
            parseAndDispatch(server, conn);
        }

        /// One record decrypted to more head bytes than the buffer holds.
        /// Which answer is honest depends on what those bytes *were*, so
        /// ask the parser: a head that completes inside the buffer means
        /// the overflow was body, and calling that "header fields too
        /// large" would send the client chasing the wrong thing.
        ///
        /// This is the case the head-fill seam's contract was written for
        /// — a source that can overrun records the surplus and lets the
        /// dispatch answer it, rather than growing a second ladder.
        fn answerHeadOverflow(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_reading_head);
            assert(conn.tls != null);
            var storage: parser.HeaderStorage = undefined;
            if (parser.parseRequestHead(
                headBytes(server, conn)[0..conn.head_len],
                true,
                &storage,
            )) |_| {
                // The head completed inside the buffer, so what overran it
                // was payload.
                respond(server, conn, 413, "l7_body_too_large");
            } else |err| switch (err) {
                // The same three verdicts `parseAndDispatch` gives, and
                // for the same reasons: a head that overran is still a
                // head, and answering 431 for a malformed one or an
                // oversize request line sends the client after the wrong
                // thing. `Incomplete` is unreachable — the parser converts
                // it to an oversize verdict once the buffer is full, which
                // is exactly the state this function is called in.
                //
                // Only the 431 and the 413 above are covered: reaching the
                // other two needs a malformed or long-request-line head
                // that *also* overruns in one record, which no test builds
                // yet. They mirror the dispatch above rather than deciding
                // anything new, which is why they are written this way and
                // not left collapsed.
                error.Malformed => respond(server, conn, 400, "l7_bad_request"),
                error.UriTooLong => respond(server, conn, 414, "l7_uri_too_long"),
                error.HeadTooLarge,
                error.Incomplete,
                => respond(server, conn, 431, "l7_headers_too_large"),
            }
        }

        /// Where a terminated connection's decrypted head bytes land: the
        /// head buffer, past what has already accumulated. Fills what fits
        /// and records the rest, which is the seam's stated contract for a
        /// source that can produce more than there is room for.
        const HeadPlaintext = struct {
            server: *ServerType,
            conn: *ConnType,
            appended: u32 = 0,
            overflowed: bool = false,
            closed: bool = false,

            fn sink(self: *HeadPlaintext) TlsEngine.Sink {
                return .{ .ctx = self, .appData = append, .closed = peerClosed };
            }

            fn append(ctx: *anyopaque, bytes: []const u8) void {
                const self: *HeadPlaintext = @ptrCast(@alignCast(ctx));
                // RFC 8446 §6.1: anything after a close_notify is ignored.
                if (self.closed) return;
                const buffer = headBytes(self.server, self.conn);
                const room = buffer.len - self.conn.head_len;
                const take: u32 = @intCast(@min(room, bytes.len));
                if (take < bytes.len) self.overflowed = true;
                if (take == 0) return;
                @memcpy(buffer[self.conn.head_len..][0..take], bytes[0..take]);
                fillHead(self.conn, take, buffer.len);
                self.appended += take;
            }

            fn peerClosed(ctx: *anyopaque) void {
                const self: *HeadPlaintext = @ptrCast(@alignCast(ctx));
                self.closed = true;
            }
        };

        // -- the head-fill seam: the *request* head (§4, §7) --
        //
        // The head accumulates until it parses (§7 detect-and-retry), and
        // three things make that loop work: where a read lands, how what
        // arrived becomes head bytes, and what those bytes mean. Only the
        // first two are a *source's* business, and they are named below, so a
        // source that does not read plaintext off the socket — §4's TLS
        // termination reads ciphertext and decrypts into the head — replaces
        // exactly those two. Unlike `pump.zig`'s transform seam these are
        // plain functions, not `@hasDecl` hooks on a policy: there is one
        // source today, and the second one arrives inside `Proxy` rather than
        // being handed in, so a policy parameter would buy nothing.
        //
        // Scoped to the request head deliberately. The origin's *response*
        // head accumulates the same way in `onResponseHeadRecv`, into the
        // upstream slot's buffer, and does not need a source: §4's TLS
        // termination applies to the client side only, so the upstream leg
        // stays plaintext (kTLS on the origin side, if it ever comes, would
        // revisit this).
        //
        // The third stays `parseAndDispatch`, the single answer to "what do
        // these bytes mean": read again, 400, 414, 431, or route. That matters
        // most for a source that can overrun the buffer, which a plaintext
        // read cannot: a transform decoding a whole record at once may yield
        // more head bytes than the buffer holds, and whether that is a 431
        // (the head itself is too large) or a 413 (the head fits and the
        // payload behind it does not) is a question about the *parsed* head.
        // Such a source records the overrun and lets the dispatch answer it,
        // rather than deciding first and growing a second copy of the ladder.

        /// The head bytes this connection holds — the ring buffer bound at
        /// the delivery that started the request (§5). Asserting the hold
        /// here means every read of head content states its precondition.
        fn headBytes(server: *ServerType, conn: *ConnType) []u8 {
            // A terminated connection accumulates its head in the engine's
            // own plaintext buffer, not the ring (§4). It has to: a ring
            // buffer binds only on a `recvGroup` delivery, and a request
            // that arrived inside the handshake's last flight has no later
            // delivery to bind one with. The engine's buffer is sized for
            // whichever is wider, a head or a record's decrypt.
            // Sliced to the *configured* head size, not the buffer's own
            // length: the buffer is wider so a record's decrypt always has
            // somewhere to land, and a deployment that lowered
            // `limits.head_buffer_bytes` to bound what it accepts must get
            // that number back rather than the floor.
            if (conn.tls) |engine| return engine.plaintext[0..engine.head_bytes];
            assert(conn.head_buffer_id != ConnType.head_buffer_none);
            return server.io.bufferGroupSlice(conn.head_buffer_id);
        }

        /// The upstream head bytes this exchange holds (§5): acquired at
        /// the request-head render, released before the slot parks or
        /// with the slot. Asserting the claim here means every read of
        /// upstream head content states its precondition.
        fn upstreamHeadBytes(upstream: *UpstreamType) []u8 {
            assert(upstream.head_buffer != null);
            return upstream.head_buffer.?.data;
        }

        /// Where a head continuation read lands: the free space after what
        /// has already accumulated in the bound buffer.
        fn headRecvBuffer(server: *ServerType, conn: *ConnType) []u8 {
            const bytes = headBytes(server, conn);
            // Parsing turns a full buffer into an oversize verdict before
            // we ever get here, so there is always room to read into.
            assert(conn.head_len < bytes.len);
            return bytes[conn.head_len..];
        }

        /// Account for bytes that became head bytes. Named because a
        /// transforming source appends a different count than the socket
        /// delivered, and this is where that difference belongs.
        ///
        /// The bound is a precondition, not a clamp: a source that can produce
        /// more head bytes than there is room for — a decrypted record is up
        /// to 16 KiB against an 8 KiB head — fills what fits, records the
        /// surplus, and lets `parseAndDispatch` answer it. Handing an overrun
        /// to this function is a bug, and asserts as one. `capacity` is the
        /// bound buffer's own length, passed because the size is the
        /// config's now, not this file's to name.
        fn fillHead(conn: *ConnType, appended: u32, capacity: usize) void {
            assert(appended >= 1);
            assert(conn.head_len + appended <= capacity);
            conn.head_len += appended;
        }

        /// The idle arm (§5): a recv that carries no buffer. Fresh
        /// connections and kept-alive turnarounds both wait here, holding
        /// nothing — the ring binds a buffer only when the client actually
        /// speaks.
        fn armHeadGroupRecv(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_reading_head);
            assert(conn.head_buffer_id == ConnType.head_buffer_none);
            assert(conn.head_len == 0);
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recvGroup(
                conn.client_socket,
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onHeadGroupRecv,
            );
        }

        /// The continuation arm: the head is partway parsed, the buffer is
        /// bound, read the rest into it (§7 detect-and-retry).
        fn armHeadRecv(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_reading_head);
            // Resolved before the arm, so the source's own bound is checked
            // before any state changes.
            const into = headRecvBuffer(server, conn);
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                into,
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onHeadRecv,
            );
        }

        fn onHeadGroupRecv(conn: *ConnType, result: Io.RecvGroupError!Io.GroupRecv) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                // The teardown raced the client's first byte (§5): the
                // kernel may already have bound a ring buffer for the
                // delivery, and dropping it here would leak that buffer
                // for the process's life — uncounted, so no drain assert
                // could ever notice. Straight back to the ring, not
                // through `returnHeadBuffer`: the bind was never recorded,
                // so there is no in-use count to decrement. The same
                // capture-then-release shape `onUpstreamConnect` uses for
                // a socket that arrived into a teardown.
                if (result) |bound| {
                    server.io.bufferGroupReturn(bound.buffer_id);
                } else |_| {}
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_reading_head);
            assert(conn.head_buffer_id == ConnType.head_buffer_none);
            const bound = result catch |err| switch (err) {
                error.NoBuffers => {
                    // The client spoke and the ring is empty: §8's newest
                    // work sheds. `respond` force-closes this counter at
                    // comptime (its `may_keep`) — the unread bytes sit in
                    // the socket, and a kept connection would re-arm onto
                    // them and shed the same request forever.
                    respond(server, conn, 503, "l7_shed_head_buffers");
                    return;
                },
                else => {
                    // A client that closes or resets before speaking simply
                    // leaves — there is nothing to answer, and (pinned by
                    // the seam's contract) no buffer was consumed for it.
                    // The witness filters internally: only Unexpected
                    // (kernel pressure) is counted.
                    server.witnessKernelPressure(.recv, err);
                    server.beginTeardown(conn);
                    return;
                },
            };
            assert(bound.len >= 1);
            conn.head_buffer_id = bound.buffer_id;
            server.noteHeadBufferBound();
            // A request begins with its first byte, and only with a byte:
            // started here rather than before the unwrap above, because
            // the read that ends an *idle* kept-alive connection completes
            // in this same callback with EOF, and starting a request there
            // would owe the log a line for a request nobody made. Nor at
            // the parse: a slowloris that dribbles for the whole head-read
            // deadline must report the time it spent doing it (§8).
            server.beginLogRequest(conn);
            conn.log.bytes_in += bound.len;
            fillHead(conn, bound.len, headBytes(server, conn).len);
            parseAndDispatch(server, conn);
        }

        fn onHeadRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_reading_head);
            const received = result catch |err| {
                // A client that closes or resets mid-head simply leaves —
                // there is nothing to answer. The §7 head-read deadline
                // handles the slowloris that stalls instead of closing.
                // The witness filters internally: only Unexpected (kernel
                // pressure) is counted, so orderly EndOfStream/Reset pass
                // through it uncounted.
                server.witnessKernelPressure(.recv, err);
                server.beginTeardown(conn);
                return;
            };
            assert(received >= 1);
            // The request already began at the group delivery that bound
            // the buffer; this is more of the same head.
            assert(conn.head_buffer_id != ConnType.head_buffer_none);
            assert(conn.head_len >= 1);
            conn.log.bytes_in += received;
            fillHead(conn, received, headBytes(server, conn).len);
            parseAndDispatch(server, conn);
        }

        /// Re-parse the accumulated head from byte 0 (§7). Incomplete and
        /// room left → read more; oversize or malformed → the matching
        /// static reject; a valid head → routing.
        fn parseAndDispatch(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_reading_head);
            const bytes = headBytes(server, conn);
            const head = bytes[0..conn.head_len];
            const head_is_full = conn.head_len == bytes.len;

            var storage: parser.HeaderStorage = undefined;
            const request = parser.parseRequestHead(head, head_is_full, &storage) catch |err| switch (err) {
                error.Incomplete => {
                    // A full buffer never yields Incomplete — the parser
                    // converts it to the oversize verdicts below — so here
                    // there is room to read more.
                    assert(!head_is_full);
                    if (conn.tls != null) {
                        armTlsHeadRecv(server, conn);
                    } else {
                        armHeadRecv(server, conn);
                    }
                    return;
                },
                error.Malformed => return respond(server, conn, 400, "l7_bad_request"),
                error.UriTooLong => return respond(server, conn, 414, "l7_uri_too_long"),
                error.HeadTooLarge => return respond(server, conn, 431, "l7_headers_too_large"),
            };
            routeRequest(server, conn, &request);
        }

        /// The §7 canonical routing keys for `request`: the canonical host
        /// (null when absent/unmatchable → any-host routes only) and both
        /// target views (`views.match` is what routes and filters see —
        /// the canonical path, or "/" for OPTIONS asterisk-form, which
        /// names the whole server). A target that will not canonicalize is
        /// BadPath (400). Canonicalized once, so every consumer of either
        /// view sees the same bytes and they cannot disagree.
        const RequestKeys = struct {
            host: ?[]const u8,
            /// Both §7 target views, canonicalized once and carried to every
            /// consumer — routing and filter matching read `match`, rendering
            /// reads `forward`. Recomputing either meant decoding and
            /// dot-segment-collapsing the whole path again (§9).
            ///
            /// For origin-form these alias the caller's scratch and so live
            /// exactly as long as that frame; asterisk-form's `forward`
            /// aliases the head buffer, which outlives it, and its `match`
            /// is a static literal. Treat the shortest of the three as the
            /// lifetime.
            views: TargetViews,
        };

        fn requestKeys(
            request: *const parser.RequestHead,
            scratch: []u8,
            host_scratch: *[constants.host_bytes_max]u8,
        ) error{BadPath}!RequestKeys {
            assert(request.target.len >= 1);
            const host: ?[]const u8 = if (request.host) |raw|
                parser.canonicalHost(raw, host_scratch)
            else
                null;
            const views = try targetViews(request, scratch);
            assert(views.match.len >= 1);
            assert(views.forward.path.len >= 1);
            return .{ .host = host, .views = views };
        }

        /// Both §7 views of a target, from one canonicalization.
        ///
        /// They differ in exactly one case, and this is the only place that
        /// case is written: OPTIONS asterisk-form matches and routes as the
        /// origin root but is forwarded as `*`. Origin-form canonicalizes,
        /// and both views are then the same bytes.
        ///
        /// Canonicalizing decodes percent-escapes and collapses dot
        /// segments over the whole path, so it is done once and both
        /// consumers read the result (§9). The slices alias `scratch`.
        const TargetViews = struct {
            match: []const u8,
            forward: parser.CanonicalTarget,
            /// Whether the target was origin-form. Recorded by the one
            /// function that distinguishes the two forms, so no consumer
            /// re-derives it and they cannot disagree about which they hold.
            origin_form: bool,
        };

        fn targetViews(
            request: *const parser.RequestHead,
            scratch: []u8,
        ) error{BadPath}!TargetViews {
            assert(request.target.len >= 1);
            if (request.target[0] != '/') {
                // validateTarget admitted only asterisk-form here.
                assert(request.method == .options);
                return .{
                    .match = "/",
                    .forward = .{ .path = request.target, .query = "" },
                    .origin_form = false,
                };
            }
            const canonical = parser.canonicalTarget(request.target, scratch) catch {
                return error.BadPath;
            };
            return .{ .match = canonical.path, .forward = canonical, .origin_form = true };
        }

        /// Answer a §7 filter reject with its runtime policy status — each
        /// a closed-set static response, all counted as one filter reject.
        fn respondFilter(server: *ServerType, conn: *ConnType, status: u16) void {
            assert(filter.isRejectStatus(status));
            // `respond` needs a comptime status to select its static
            // response, so bridge the runtime status by matching it against
            // the same closed set `filter.isRejectStatus` guards — one
            // source of truth, no hand-kept switch to drift out of sync.
            inline for (filter.reject_statuses) |candidate| {
                if (status == candidate) {
                    return respond(server, conn, candidate, "l7_filtered");
                }
            }
            unreachable;
        }

        /// The forwarded target and header edits after applying the
        /// listener's §7 filters to `request` — `base` unchanged and no
        /// edits when the listener has no filters (the common path pays
        /// nothing). Routing already chose the cluster from `base.path`; a
        /// rewrite changes only the forwarded path here, never the route,
        /// and first-applicable wins. The match view mirrors `requestKeys`:
        /// canonical host, and the canonical path (origin-form, aliasing
        /// `base.path`) or "/" (OPTIONS asterisk-form) — so the rules that
        /// fire are exactly those the reject phase saw. `Oversize` when a
        /// rewrite's longer `to` overruns the path scratch (§7, 431).
        const Forwarded = struct {
            target: parser.CanonicalTarget,
            edits: []const filter.AppliedHeaderEdit,
        };
        fn planForward(
            conn: *const ConnType,
            request: *const parser.RequestHead,
            views: *const TargetViews,
            host_scratch: *[constants.host_bytes_max]u8,
            rewrite_scratch: []u8,
            edit_buffer: *[constants.header_edits_max]filter.AppliedHeaderEdit,
        ) error{Oversize}!Forwarded {
            const base = views.forward;
            assert(base.path.len >= 1);
            if (conn.request_filters.len == 0) {
                return .{ .target = base, .edits = &.{} };
            }
            // The canonical *host* is still recomputed here, unlike the
            // target views above. It is not threaded from the route phase
            // because on the dial path that phase's `host_scratch` died
            // with its frame at the connect await, so this path would need
            // to rebuild it regardless — and unlike the target, nothing
            // else is asking for one canonical spelling of it.
            const host: ?[]const u8 = if (request.host) |raw|
                parser.canonicalHost(raw, host_scratch)
            else
                null;
            // The match view comes from `targetViews`, the one place the
            // asterisk-matches-as-root rule is written — deriving it here
            // too was a second copy of that rule to keep in step.
            assert(views.match.len >= 1);
            assert(views.match[0] == '/');
            const view = filter.RequestView{
                .method = request.method,
                .host = host,
                .path = views.match,
                .headers = request.headers,
                .client = &conn.client_address,
            };
            // One scan yields both the rewrite and the header edits (§7).
            const forward = filter.collectForward(conn.request_filters, view, edit_buffer);
            // Rewrite only origin-form targets; asterisk-form names no path.
            var target = base;
            if (views.origin_form) {
                if (forward.rewrite) |rewrite| {
                    target.path = try filter.rewritePath(rewrite, base.path, rewrite_scratch);
                }
            }
            return .{ .target = target, .edits = forward.edits };
        }

        /// What the parsed head says about the request itself, recorded on
        /// the conn before any rung can reject it. `respond` reads these to
        /// decide whether the client's byte stream is still synchronized
        /// enough to keep the connection (§8 "then keep or close"), so they
        /// must land ahead of *every* reject that answers a valid head —
        /// the 501s included. Those reject the method, not the framing: a
        /// CONNECT or Upgrade head parsed cleanly and sits on a message
        /// boundary like any other, and since a 501 forwards nothing there
        /// is no second parser to disagree with about where it ends. What
        /// the client does next is either another request (served) or
        /// tunnel bytes (400, closed) — never a smuggled one.
        ///
        /// A malformed or oversize head never reaches here, so it never
        /// sets these: `request_head_len` staying 0 is exactly what marks a
        /// stream whose message boundary the parser could not find.
        fn recordRequestFacts(server: *ServerType, conn: *ConnType, request: *const parser.RequestHead) void {
            assert(conn.state == .l7_reading_head);
            assert(request.head_len >= 1);
            // Once per request: `resetForNextRequest` and
            // `resumeAfterStaticResponse` both clear `l7` on the turnaround,
            // so a second recording would mean a head was routed twice.
            assert(conn.l7.request_head_len == 0);
            conn.l7.request_method = request.method;
            conn.l7.request_framing = framingFromParsed(request.framing);
            conn.l7.request_head_len = request.head_len;
            conn.l7.client_keep_alive = request.keep_alive;
            // Copied out now because the head buffer is not the log's to
            // read later: the response head renders over it (§7 buffer
            // rotation), and by the exchange's settle these bytes are gone.
            conn.log.captureMethod(request.method_token);
            // The #140 named headers, on the same terms and for the same
            // reason — and here rather than deeper, so every line that
            // reports a parsed request carries them, rejects included.
            server.captureRequestLogHeaders(conn, request.headers);
        }

        /// Start this exchange's §8 deadline, if the deployment set one.
        /// Storing the cap is not enough on its own: the armed timer is the
        /// idle one this connection has carried since its last turnaround,
        /// due far later, and the lazy re-arm only ever fires *at* the armed
        /// target (§4) — so a cap stored under it would be noticed one idle
        /// timeout late, which is the whole failure it exists to prevent.
        /// Re-base once, here, and every later `storeDeadline` on this
        /// exchange clamps under a timer already due on time.
        fn armRequestDeadline(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_reading_head);
            assert(conn.l7.request_deadline_ns == 0);
            if (server.config.request_timeout_ms == 0) return;
            const now_ns = server.io.nowNs();
            conn.l7.request_deadline_ns = now_ns +
                @as(u64, server.config.request_timeout_ms) * std.time.ns_per_ms;
            assert(conn.l7.request_deadline_ns > now_ns);
            server.storeDeadline(conn, server.idleTimeoutMs());
            server.rebaseDeadline(conn);
        }

        /// Record what this request asked for, before any rung can reject
        /// it (§8): every reject, shed and verdict below reports the same
        /// spelling the router matched on, and the head buffer these bytes
        /// live in is gone by the time the line is written (§7 rotation).
        ///
        /// `path` is the canonical view when there is one and the raw
        /// target when there is not — the 400 case, where no canonical
        /// spelling exists and the raw one is both the honest answer and
        /// the useful one, since a 400 line is read to find out what was
        /// actually asked for.
        fn captureTarget(conn: *ConnType, host: ?[]const u8, path: []const u8) void {
            assert(conn.state == .l7_reading_head);
            assert(path.len >= 1);
            conn.log.capturePath(path);
            if (host) |canonical| {
                assert(canonical.len >= 1);
                conn.log.captureHost(canonical);
            }
        }

        /// Policy gate, then the exchange's admission: tunnels and
        /// upgrades are non-goals (§1, §7) — 501; the canonical path
        /// selects a cluster (400 if it will not canonicalize, 404 if no
        /// route matches, §7/§8); a routable request then claims its
        /// relay buffer and upstream slot (§8 rungs, 503) and dials.
        fn routeRequest(server: *ServerType, conn: *ConnType, request: *const parser.RequestHead) void {
            assert(conn.state == .l7_reading_head);
            assert(request.head_len <= conn.head_len);
            recordRequestFacts(server, conn, request);
            armRequestDeadline(server, conn);
            if (request.method == .connect) {
                return respond(server, conn, 501, "l7_not_implemented");
            }
            if (parser.headerValue(request.headers, "upgrade")) |token| {
                if (!admitUpgrade(server, conn, token)) return;
            }

            // §7: canonicalize the host and path once, then apply filters
            // and routing to that one view before acquiring any resource,
            // so a bad path, a policy reject, or an unrouted host/path is
            // answered cheaply. The target scratch is the server's (§5):
            // its length is the config's `head_buffer_bytes` now, and a
            // runtime-length stack array is exactly the dynamic allocation
            // §5 forbids. Sound because uses never overlap — the loop is
            // single-threaded, and the window (through routing into the
            // checkout path's render) neither suspends nor re-enters.
            const scratch = server.target_scratch;
            var host_scratch: [constants.host_bytes_max]u8 = undefined;
            const keys = requestKeys(request, scratch, &host_scratch) catch {
                captureTarget(conn, null, request.target);
                return respond(server, conn, 400, "l7_bad_request");
            };
            captureTarget(conn, keys.host, keys.views.match);
            // §7 filters run before routing: a terminal verdict — reject
            // or redirect (#176) — stops the request whether or not it
            // would have routed.
            if (filter.firstVerdict(conn.request_filters, .{
                .method = request.method,
                .host = keys.host,
                .path = keys.views.match,
                .headers = request.headers,
                .client = &conn.client_address,
            })) |verdict| {
                switch (verdict) {
                    .reject => |status| return respondFilter(server, conn, status),
                    .redirect => |redirect| {
                        return respondRedirect(server, conn, redirect, keys.host, keys.views.forward);
                    },
                    .respond => |page| return respondWithPage(server, conn, page),
                }
            }
            conn.cluster_index = router.route(conn.routes, keys.host, keys.views.match) orelse {
                return respond(server, conn, 404, "l7_no_route");
            };

            conn.relay_buffer = server.acquireRelayBuffer() orelse {
                return respond(server, conn, 503, "l7_shed_relay_buffers");
            };
            beginUpstream(server, conn, request, &keys.views);
        }

        /// The request-derived half of this exchange's pick (#178): what
        /// the routed cluster's hash key reads off the parsed head —
        /// `.none` for every cluster that keys on nothing or on the
        /// address. Derived while the head is live: at routing on the
        /// first try, and from the replay's re-parse on the second, the
        /// same source-of-truth rule the replay applies to the framing.
        fn requestKeyFor(
            server: *const ServerType,
            conn: *const ConnType,
            request: *const parser.RequestHead,
        ) Balancer.RequestKey {
            assert(conn.cluster_index < server.config.clusters.len);
            assert(request.head_len >= 1);
            const cluster = &server.config.clusters[conn.cluster_index];
            if (cluster.pick != .hash) {
                return .none;
            }
            switch (cluster.hash_key) {
                .source_ip => return .none,
                .header => |name| {
                    const value = parser.headerValue(request.headers, name) orelse
                        return .absent;
                    if (value.len == 0) {
                        return .absent;
                    }
                    return .{ .key = Balancer.bytesKey(value) };
                },
                .cookie => |name| {
                    const value = parser.cookieValue(request.headers, name) orelse
                        return .absent;
                    const identity = Balancer.parseEndpointTag(value) orelse
                        return .absent;
                    return .{ .endpoint = identity };
                },
            }
        }

        /// Decide an `Upgrade` request's fate before a byte of it is
        /// forwarded (#180). True means it may proceed as a would-be
        /// tunnel; false means this function already answered.
        ///
        /// Two refusals saying different things. A token the listener
        /// does not allow is `501` — the answer every `Upgrade` got
        /// before this existed, and the honest one: it fails *here*, with
        /// a status meaning what happened, rather than at an origin that
        /// never saw a handshake. A token it does allow but no capacity
        /// to carry is `503`, and the ordering *is* the §8 rung: checking
        /// before the handshake is forwarded is what makes a refusal cost
        /// nothing, where admitting first and shedding later would spend
        /// an origin connection to produce a worse answer.
        ///
        /// The token must match whole and alone. RFC 9110 lets `Upgrade`
        /// carry a comma-separated list with versions; anything but a
        /// single token this proxy knows is refused rather than parsed
        /// generously, because after `101` no rule of ours applies to
        /// another byte and a loose reading here is the one thing that
        /// cannot be taken back.
        fn admitUpgrade(server: *ServerType, conn: *ConnType, token: []const u8) bool {
            assert(conn.state == .l7_reading_head);
            assert(conn.tunnel_buffer == null);
            assert(!conn.l7.upgrade_requested);
            if (!conn.upgrades.websocket or !std.ascii.eqlIgnoreCase(token, "websocket")) {
                respond(server, conn, 501, "l7_not_implemented");
                return false;
            }
            conn.tunnel_buffer = server.acquireTunnelBuffer() orelse {
                respond(server, conn, 503, "l7_shed_tunnels");
                return false;
            };
            conn.l7.upgrade_requested = true;
            return true;
        }

        /// Picks a live endpoint under the §8 per-endpoint inflight cap
        /// and outside what this request has already tried (#181), or
        /// answers and returns null. Shared by all three dial paths — the
        /// first try, the §7 replay and the retry — so neither the cap's
        /// shed nor the exhaustion 502 can drift between them.
        ///
        /// The two null answers are different rungs and are counted apart:
        /// every candidate at its cap sheds 503, while every routable
        /// endpoint already tried answers 502. Only a retry can reach the
        /// second, since the exclusion set is empty until a dial fails.
        fn pickEndpointOrShed(
            server: *ServerType,
            conn: *ConnType,
            request_key: Balancer.RequestKey,
        ) ?Balancer.Pick {
            const outcome = server.balancer.pick(
                conn.cluster_index,
                &server.endpointLoad(),
                server.health.healthy,
                &conn.client_address,
                request_key,
                conn.l7.tried[0..conn.l7.tried_count],
            );
            switch (outcome) {
                .dial => |chosen| return chosen,
                .exhausted => {
                    // Every routable endpoint refused this request (#181).
                    // 502 rather than 503: the origins were reachable
                    // enough to say no, which is a different sentence from
                    // "they are full", and the shed rungs must not absorb
                    // it. A first try cannot land here — the routable set
                    // is non-empty until something has been tried.
                    assert(conn.l7.tried_count >= 1);
                    server.counters.increment("upstream_retries_exhausted");
                    respond(server, conn, 502, "l7_bad_gateway");
                    return null;
                },
                .capped => {
                    // The labeled twin (#179) carries only the cluster:
                    // this fires precisely because no endpoint could be
                    // picked — all of them were full, so an endpoint
                    // label would be an invention.
                    server.labeled.incrementCluster(.l7_shed_inflight, conn.cluster_index);
                    respond(server, conn, 503, "l7_shed_endpoint_inflight");
                    return null;
                },
            }
        }

        /// Route resolved and a relay buffer held: choose an endpoint and
        /// get onto it, by reuse when the pool has one parked and by a
        /// fresh dial otherwise. Split from `routeRequest` because the
        /// two halves answer different questions — *where does this
        /// request go* and *how does it get there* — and the first was
        /// already at the length limit.
        fn beginUpstream(
            server: *ServerType,
            conn: *ConnType,
            request: *const parser.RequestHead,
            views: *const TargetViews,
        ) void {
            assert(conn.state == .l7_reading_head);
            assert(conn.relay_buffer != null);
            // The §3 reuse win: a parked connection to the picked endpoint
            // beats a fresh dial. A close that slipped through while it
            // was parked surfaces as a failure on first use — absorbed by
            // the §7 free replay (`upstreamFailed`).
            //
            // The §8 cap binds the reuse path too, deliberately: checking
            // out a parked connection starts a request the origin has to
            // serve, which is the thing being bounded — the saved
            // handshake does not make it free.
            const request_key = requestKeyFor(server, conn, request);
            // The head bytes are gone by the response render (§7 buffer
            // rotation), so the render's half of #178 — "did the request
            // already name the endpoint it got?" — is recorded now.
            conn.l7.sticky_cookie = switch (request_key) {
                .endpoint => |identity| identity,
                else => null,
            };
            const pick = pickEndpointOrShed(server, conn, request_key) orelse return;
            if (server.upstreams.checkout(conn.cluster_index, pick.endpoint_index)) |parked| {
                server.counters.increment("upstream_reused");
                // Recorded once the slot is actually held, never at the
                // pick: a request shed for want of a slot contacted no
                // origin, and a line claiming one would send an operator
                // looking at a backend that never saw the request (§8).
                conn.log.endpoint_index = pick.endpoint_index;
                conn.upstream = parked;
                conn.upstream_socket = parked.socket;
                parked.head_len = 0;
                // A parked slot released its head buffer before parking;
                // the exchange re-acquires here, still in
                // `.l7_reading_head` so a shed keeps (the checked-out
                // socket is closed with the slot — the shed costs a
                // parked origin connection, not a client one).
                if (!acquireUpstreamHeadOrShed(server, conn)) return;
                conn.l7.upstream_was_reused = true;
                conn.state = .l7_dialing;
                // No await happened: this runs in the same callback as the
                // parse whose result is still live, so the reuse path —
                // the hot one — skips the re-parse the dial path needs,
                // and hands over the canonical target it already built
                // rather than having it decoded and collapsed again.
                renderRequestAndStartLegs(server, conn, request, views);
                return;
            }
            dialUpstream(server, conn, pick, .fresh);
        }

        /// Acquire the exchange's upstream head buffer (§5) — the render
        /// target and response-head accumulator — or shed. Called at the
        /// two places a slot is obtained, deliberately *before* the state
        /// leaves `.l7_reading_head` on the request path: the resync rule
        /// keeps a shed connection only from there, and this rung earns
        /// the same keep its slot sibling gets. (The §7 replay re-dials
        /// from `.l7_exchanging`, where a shed closes — the stream is
        /// mid-exchange and cannot be trusted kept.) On the shed path
        /// `respond` has already released the slot the caller just
        /// obtained, so the caller only returns.
        fn acquireUpstreamHeadOrShed(server: *ServerType, conn: *ConnType) bool {
            const upstream = conn.upstream.?;
            assert(upstream.head_buffer == null);
            upstream.head_buffer = server.acquireUpstreamHeadBuffer() orelse {
                respond(server, conn, 503, "l7_shed_upstream_head_buffers");
                return false;
            };
            return true;
        }

        /// Whether a dial opens its own connect budget or continues one
        /// already running.
        ///
        /// `fresh` is the §7 rule — each try, the first and the stale
        /// replay's, runs under its own `connect_ms`. `carried` is
        /// #181's: a retry chain is one client waiting for one answer, so
        /// every dial in it shares the budget the first one armed. That
        /// keeps the worst-case dial wait at `connect_ms` however many
        /// endpoints the request walks, and it is why a *timed-out* dial
        /// does not retry — the budget it would retry under is the budget
        /// it just spent, so there is nothing left to try with. The two
        /// answers to the "does a retry multiply the client's wait"
        /// question, and this picks the one that says no.
        const DialBudget = enum { fresh, carried };

        /// Acquire a fresh slot and dial `pick` under the connect deadline
        /// (§8) — shared by the first try (`routeRequest`), the §7 stale
        /// replay (`beginReplay`) and the #181 retry (`beginRetry`), so
        /// every try dials identically but for its budget.
        fn dialUpstream(
            server: *ServerType,
            conn: *ConnType,
            pick: Balancer.Pick,
            budget: DialBudget,
        ) void {
            // `.l7_dialing` is a retry re-entering: the state never left
            // the dial, because nothing about this request reached an
            // origin and there is no exchange to be in.
            assert(conn.state == .l7_reading_head or conn.state == .l7_dialing or
                conn.state == .l7_exchanging);
            if (conn.state == .l7_dialing) assert(budget == .carried);
            assert(conn.upstream == null);
            assert(conn.upstream_socket == null);
            conn.upstream = server.acquireUpstream(conn.cluster_index, pick.endpoint_index) orelse {
                return respond(server, conn, 503, "l7_shed_upstream_slots");
            };
            if (!acquireUpstreamHeadOrShed(server, conn)) return;
            // The slot is held, so this try really is going to this
            // endpoint — whether or not the dial ends up succeeding. A
            // replay overwrites it, naming the endpoint that served (§7).
            conn.log.endpoint_index = pick.endpoint_index;
            conn.state = .l7_dialing;
            // The head-read/idle timer is already armed; re-base it to the
            // tighter per-try connect budget so a hung origin fires the §8
            // 504 at connect_timeout, not idle_timeout (§4: the lazy timer
            // never moves earlier on its own). A carried budget leaves the
            // running deadline exactly where the first dial put it, so the
            // expiry still fires on time and still finds this connection
            // dialing — whichever endpoint it is dialing by then.
            if (budget == .fresh) {
                server.storeDeadline(conn, server.config.connect_timeout_ms);
                server.rebaseDeadline(conn);
            } else {
                // Stated rather than assumed: the budget being carried is
                // only a budget if it is still running. It must be, since
                // a fired deadline reaches `onUpstreamConnect` as a
                // pending verdict and answers 504 before any failure could
                // ask to retry — but a future path that disarmed it would
                // otherwise leave this dial with no clock at all.
                assert(conn.armed.deadline);
            }
            conn.arm(&conn.op_connect, "connect");
            server.io.connect(
                pick.address,
                &conn.op_connect.completion,
                ConnType,
                conn,
                onUpstreamConnect,
            );
        }

        fn onUpstreamConnect(conn: *ConnType, result: Io.ConnectError!IoType.Socket) void {
            const server = conn.server;
            conn.delivered(&conn.op_connect, "connect");
            if (conn.isTearingDown()) {
                // The teardown raced the dial (§5): a socket that arrived
                // anyway must still be shut down and closed.
                if (result) |socket| {
                    conn.upstream_socket = socket;
                    server.io.shutdown(socket, .both);
                } else |_| {}
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_dialing);
            if (conn.l7.pending_verdict != .none) {
                // The §8 dial-timeout verdict: the deadline canceled this
                // connect. Whatever the result — the expected Canceled, a
                // genuine failure, or a success that raced the cancel —
                // the dial is condemned; a socket that arrived anyway is
                // attached so respond's upstream disposal closes it.
                assert(conn.l7.pending_verdict == .gateway_timeout);
                conn.l7.pending_verdict = .none;
                if (result) |socket| {
                    conn.upstream.?.socket = socket;
                    conn.upstream_socket = socket;
                } else |_| {}
                respond(server, conn, 504, "l7_gateway_timeout");
                return;
            }
            const socket = result catch |err| {
                server.counters.increment("upstream_connect_failed");
                // The labeled twin (#179): the pick did not survive the
                // await, but the leased slot did — it still names the
                // endpoint this dial was for, and `respond`'s disposal
                // releases it only after this line.
                assert(conn.upstream != null);
                server.labeled.incrementEndpoint(.connect_failed, server.upstreams.keys.key(
                    conn.upstream.?.cluster_index,
                    conn.upstream.?.endpoint_index,
                ));
                // Same split as the L4 dial: the origin's verdict arrives
                // typed, our own resource exhaustion does not (§8).
                server.witnessKernelPressure(.connect, err);
                if (retryEligible(server, conn, err)) {
                    beginRetry(server, conn);
                    return;
                }
                respond(server, conn, 502, "l7_bad_gateway");
                return;
            };
            conn.upstream.?.socket = socket;
            conn.upstream_socket = socket;
            server.io.setNodelay(socket) catch |err| {
                server.witnessKernelPressure(.set_option, err);
            };
            renderAndStartLegs(server, conn);
        }

        /// Whether a failed dial may be sent to another endpoint (#181).
        ///
        /// Two of the four `ConnectError`s qualify, and the split is the
        /// feature's whole safety argument. `Refused` and `Unreachable`
        /// are the *origin's* verdict: the request reached no application,
        /// nothing was processed, nothing was observed — so §7's settled
        /// reading of "may have begun processing" ("a response byte
        /// arrived or relay chunks flowed") is unambiguously not met, and
        /// re-sending is safe for every method including POST, with no
        /// idempotency analysis and no knob about which methods may
        /// replay. `Unexpected` is *our* resource exhaustion, already
        /// witnessed as kernel pressure by the caller: another dial would
        /// meet the same wall and §8 says shed rather than retry.
        /// `Canceled` is the dial deadline, which arrives through
        /// `pending_verdict` above and never reaches here — and could not
        /// retry anyway, having spent the budget a retry would carry.
        fn retryEligible(
            server: *const ServerType,
            conn: *const ConnType,
            err: Io.ConnectError,
        ) bool {
            assert(conn.state == .l7_dialing);
            assert(conn.upstream != null);
            // Exhaustive rather than an `else`, so a fifth connect error
            // is a compile error here — a decision to make once, not a
            // default to inherit silently.
            switch (err) {
                error.Refused, error.Unreachable => {},
                error.Canceled, error.Unexpected => return false,
            }
            const budget = server.config.clusters[conn.cluster_index].retries;
            assert(budget <= constants.cluster_retries_max);
            assert(conn.l7.retries_used <= budget);
            return conn.l7.retries_used < budget;
        }

        /// Spend one retry: record the endpoint that refused, give its
        /// slot back, and dial an untried one from the same client bytes.
        ///
        /// Cheaper than the §7 replay, and for a structural reason — a
        /// dial that never connected sent nothing, so there is no stale
        /// socket to shut down, no framing to rebuild and no per-try state
        /// to reset. The head still holds the request exactly as it
        /// arrived (the render happens after the connect completes), so
        /// the re-parse here is the same one the replay does, for the same
        /// reason: only the bytes survive an await, and they are unchanged.
        fn beginRetry(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_dialing);
            assert(conn.upstream_socket == null); // A failed dial produced none.
            assert(!conn.armed.data_client_to_upstream);
            assert(!conn.armed.data_upstream_to_client);
            const failed = conn.upstream.?;
            assert(conn.l7.tried_count < conn.l7.tried.len);
            conn.l7.tried[conn.l7.tried_count] = failed.endpoint_index;
            conn.l7.tried_count += 1;
            // Released before the re-pick, not after: the endpoint's
            // in-flight total is what `p2c` and the §8 cap read, and
            // leaving a dead dial counted there would make the retry
            // avoid a busy endpoint on the strength of work nobody is
            // doing. The slot is re-acquired in the same callback, so the
            // pool cannot have been emptied in between.
            server.releaseUpstream(failed);
            conn.upstream = null;
            var storage: parser.HeaderStorage = undefined;
            const request = parser.parseRequestHead(
                headBytes(server, conn)[0..conn.head_len],
                false,
                &storage,
            ) catch unreachable;
            // Re-derived rather than remembered, like the replay's
            // framing: same bytes, same key. A cookie cluster's #178
            // announcement still names whichever endpoint finally serves,
            // because `sticky_cookie` records what the *client* asked for
            // and that has not changed.
            const request_key = requestKeyFor(server, conn, &request);
            const pick = pickEndpointOrShed(server, conn, request_key) orelse return;
            assert(pick.endpoint_index != conn.l7.tried[conn.l7.tried_count - 1]);
            conn.l7.retries_used += 1;
            server.counters.increment("upstream_retried");
            dialUpstream(server, conn, pick, .carried);
        }

        /// The fresh-dial completion path: the head bytes are re-parsed —
        /// only the bytes survive an await (§7), and they are unchanged,
        /// so this cannot fail — then the legs begin. The checkout path
        /// calls `renderRequestAndStartLegs` directly instead.
        fn renderAndStartLegs(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_dialing);
            var storage: parser.HeaderStorage = undefined;
            // The same bytes parsed successfully in routeRequest (§7:
            // bytes are the single source of truth), so a failure here is
            // an invariant violation, not an input condition.
            const request = parser.parseRequestHead(
                headBytes(server, conn)[0..conn.head_len],
                false,
                &storage,
            ) catch unreachable;
            assert(request.head_len == conn.l7.request_head_len);
            // Only this path pays for canonicalization twice, and it has
            // to: routeRequest's use of the shared scratch ended with its
            // frame at the dial — which is also why reusing the same
            // server-owned scratch here cannot overlap it.
            // Same bytes routeRequest already canonicalized, so this cannot
            // fail — the §7 single-source-of-truth rule again.
            const views = targetViews(&request, server.target_scratch) catch unreachable;
            renderRequestAndStartLegs(server, conn, &request, &views);
        }

        /// Render the request head into the upstream slot's staging
        /// buffer and start both legs.
        fn renderRequestAndStartLegs(
            server: *ServerType,
            conn: *ConnType,
            request: *const parser.RequestHead,
            /// The §7 target views the router matched on: `forward` is the
            /// base the origin sees unless a filter rewrites it, `match` is
            /// the view the filters run against — the same one the reject
            /// and route phases used, so the rules that fire here are
            /// exactly the rules that fired there.
            ///
            /// Passed in rather than recomputed: canonicalizing decodes and
            /// collapses the whole path, and the caller already did it
            /// (§9). Origin-form aliases the caller's stack scratch, so both
            /// are read out entirely before this returns.
            views: *const TargetViews,
        ) void {
            assert(conn.state == .l7_dialing);
            assert(request.head_len == conn.l7.request_head_len);
            assert(views.forward.path.len >= 1);
            assert(views.match.len >= 1);
            const upstream = conn.upstream.?;
            // Acquired back when the slot was obtained (`acquireUpstreamHeadOrShed`),
            // while the state still allowed a kept shed; by render time it
            // is a held invariant, not a question.
            assert(upstream.head_buffer != null);
            // Apply the listener's filters (empty when none): a rewrite of
            // the forwarded path and any header edits, against the same
            // canonical view the reject/route phase used.
            var host_scratch: [constants.host_bytes_max]u8 = undefined;
            var edit_buffer: [constants.header_edits_max]filter.AppliedHeaderEdit = undefined;
            // The rewrite scratch is the server's, distinct from the
            // target scratch: on the checkout path the routed views still
            // alias that one while the rewrite runs.
            const plan = planForward(
                conn,
                request,
                views,
                &host_scratch,
                server.rewrite_scratch,
                &edit_buffer,
            ) catch {
                // A rewritten path too long to forward: the §7 oversize
                // verdict, answered like an oversize head.
                return respond(server, conn, 431, "l7_headers_too_large");
            };
            var forwarded_scratch: [constants.forwarded_value_bytes_max]u8 = undefined;
            const forwarded = planForwarded(server, conn, request, &forwarded_scratch);
            // No close announcement upstream (the `false` below): the
            // connection is a parking candidate (§5), and stripping the
            // client's Connection header already made persistence the wire
            // default.
            const rendered = render.renderRequestHead(
                request,
                plan.target,
                plan.edits,
                false,
                forwarded,
                // The participating `Upgrade` travels only when this
                // listener agreed to carry it (#180); the gate already
                // refused every other spelling.
                conn.l7.upgrade_requested,
                upstreamHeadBytes(upstream),
            ) catch {
                // Valid on arrival but no longer fits after edits: the §7
                // oversize-after-edits verdict.
                return respond(server, conn, 431, "l7_headers_too_large");
            };
            assert(rendered.len >= 1);
            conn.l7.rendered_request_len = @intCast(rendered.len);
            conn.l7.request_head_sent = 0;
            conn.state = .l7_exchanging;
            conn.l7.request_leg = .sending_head;
            server.storeDeadline(conn, server.idleTimeoutMs());
            armRequestHeadSend(server, conn);
        }

        /// Resolve this listener's §7 client-address forwarding into the
        /// bytes the render will write, or null when the listener leaves
        /// `X-Forwarded-For` alone.
        ///
        /// **The trust decision is made here and only here.** `replace`
        /// carries no chain, so an inbound one — which at the edge is
        /// whatever the client felt like claiming — reaches the origin
        /// nowhere. `append` carries it, which is correct exactly when
        /// every hop in front is one the operator owns, and a forgery
        /// otherwise. zoxy cannot tell those apart from the inside, which
        /// is why this reads a configured mode rather than a heuristic.
        ///
        /// The result aliases `scratch`, which belongs to the caller's
        /// frame, so it must be consumed before that frame returns — and
        /// it is: the render runs on the next line.
        fn planForwarded(
            server: *ServerType,
            conn: *const ConnType,
            request: *const parser.RequestHead,
            scratch: *[constants.forwarded_value_bytes_max]u8,
        ) ?[]const u8 {
            const mode = conn.forwarded orelse return null;
            var len: u32 = switch (mode) {
                .replace => 0,
                .append => appendInboundChain(server, request, scratch),
            };
            assert(len <= constants.forwarded_chain_bytes_max);
            if (len >= 1) {
                @memcpy(scratch[len..][0..2], ", ");
                len += 2;
            }
            var client_scratch: [constants.forwarded_client_bytes_max]u8 = undefined;
            const client = bareAddress(&conn.client_address, &client_scratch);
            assert(client.len >= 1);
            // The scratch is the chain bound plus a separator plus the
            // widest address, so a chain that fit leaves room for these.
            assert(len + client.len <= scratch.len);
            @memcpy(scratch[len..][0..client.len], client);
            len += @intCast(client.len);
            assert(len >= 1);
            return scratch[0..len];
        }

        /// Copy the inbound chain an `append` listener carries forward
        /// into the front of `scratch`, returning its length: every
        /// `X-Forwarded-For` the client sent, joined in order, because RFC
        /// 9110 makes repeated field lines equivalent to one comma-joined
        /// value and keeping only the first would silently lose hops.
        ///
        /// Bounded, and the bound fails *safe*: a chain past
        /// `forwarded_chain_bytes_max` is discarded entirely rather than
        /// truncated, leaving the caller to state the observed peer alone.
        /// A truncated chain would read as complete to the origin and is
        /// not, which is worse than saying less.
        fn appendInboundChain(
            server: *ServerType,
            request: *const parser.RequestHead,
            scratch: *[constants.forwarded_value_bytes_max]u8,
        ) u32 {
            assert(request.headers.len <= constants.headers_max);
            var len: u32 = 0;
            for (request.headers) |*header| {
                if (header.tag != .x_forwarded_for) continue;
                if (header.value.len == 0) continue;
                const separator: []const u8 = if (len == 0) "" else ", ";
                // Against the *chain* bound, not the scratch: the tail of
                // the buffer is reserved for the separator and address
                // this chain is about to be joined with.
                if (len + separator.len + header.value.len > constants.forwarded_chain_bytes_max) {
                    server.counters.increment("forwarded_chain_dropped");
                    return 0;
                }
                @memcpy(scratch[len..][0..separator.len], separator);
                len += @intCast(separator.len);
                @memcpy(scratch[len..][0..header.value.len], header.value);
                len += @intCast(header.value.len);
            }
            assert(len <= constants.forwarded_chain_bytes_max);
            return len;
        }

        fn armRequestHeadSend(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .sending_head);
            const l7 = &conn.l7;
            assert(l7.request_head_sent < l7.rendered_request_len);
            l7.request_op_on_client = false; // A send on the upstream socket.
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.send(
                conn.upstream_socket.?,
                upstreamHeadBytes(conn.upstream.?)[l7.request_head_sent..l7.rendered_request_len],
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onRequestHeadSent,
            );
        }

        fn onRequestHeadSent(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .sending_head);
            if (conn.l7.pending_verdict != .none) {
                settlePendingVerdict(server, conn);
                return;
            }
            const sent = result catch |err| {
                server.witnessKernelPressure(.send, err);
                upstreamFailed(server, conn);
                return;
            };
            assert(sent >= 1);
            conn.l7.request_head_sent += sent;
            assert(conn.l7.request_head_sent <= conn.l7.rendered_request_len);
            if (conn.l7.request_head_sent < conn.l7.rendered_request_len) {
                armRequestHeadSend(server, conn);
                return;
            }
            // Head on the wire. Validate the request-body prefix that
            // arrived coalesced with the head before the response leg
            // commits its recv op: a body that already violates its own
            // framing is answered 400 while both data ops are still free
            // (§7). Once the response recv is armed that op is gone, and an
            // op is never canceled (§5) — so a malformed body found later
            // can only tear down. Checking here keeps the 400 reachable.
            const excess = headBytes(server, conn)[conn.l7.request_head_len..conn.head_len];
            const feed = feedFraming(&conn.l7.request_framing, excess);
            if (feed.malformed) {
                respond(server, conn, 400, "l7_bad_request");
                return;
            }
            // The response leg starts recving now — before the request body
            // finishes — so an early response cannot wedge both TCP windows
            // (§7). Its render into conn.head waits until the request head
            // vacates that buffer.
            startResponseLeg(server, conn);
            forwardRequestExcess(server, conn, feed);
        }

        /// Forward the body bytes that arrived coalesced with the head
        /// straight from conn.head (§7): a body larger than a relay buffer
        /// is never squeezed through one, and conn.head is freed for the
        /// response head exactly when the last excess byte leaves it. The
        /// framing was already advanced and validated by the caller.
        fn forwardRequestExcess(server: *ServerType, conn: *ConnType, feed: FeedResult) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .sending_head);
            assert(!feed.malformed);
            const excess = headBytes(server, conn)[conn.l7.request_head_len..conn.head_len];
            if (feed.consumed < excess.len) {
                conn.l7.client_pipelined = true;
            }
            const direction = &conn.directions[0];
            direction.owe(feed.consumed);
            conn.l7.request_leg = .sending_body_excess;
            if (direction.owed() >= 1) {
                armRequestExcessSend(server, conn);
            } else {
                requestHeadVacated(server, conn);
            }
        }

        fn armRequestExcessSend(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .sending_body_excess);
            const direction = &conn.directions[0];
            const base = conn.l7.request_head_len;
            conn.l7.request_op_on_client = false; // A send on the upstream socket.
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.send(
                conn.upstream_socket.?,
                direction.pending(headBytes(server, conn)[base..]),
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onRequestExcessSent,
            );
        }

        fn onRequestExcessSent(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .sending_body_excess);
            if (conn.l7.pending_verdict != .none) {
                settlePendingVerdict(server, conn);
                return;
            }
            const sent = result catch |err| {
                server.witnessKernelPressure(.send, err);
                upstreamFailed(server, conn);
                return;
            };
            assert(sent >= 1);
            const direction = &conn.directions[0];
            direction.credit(sent);
            if (direction.owed() >= 1) {
                armRequestExcessSend(server, conn);
                return;
            }
            requestHeadVacated(server, conn);
        }

        /// The request head has fully left conn.head: release any origin
        /// response that was waiting to render there, then continue the
        /// request body from the socket (or finish it if the excess
        /// carried the whole body).
        fn requestHeadVacated(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .sending_body_excess);
            conn.l7.request_head_vacated = true;
            if (conn.l7.response_render_pending) {
                conn.l7.response_render_pending = false;
                beginResponseForward(server, conn);
                // A deferred render that fails (oversize/malformed origin
                // head) answers 502 (.l7_responding) or tears down — either
                // way it leaves .l7_exchanging, and the request leg must not
                // keep pumping into a connection that is already closing (§7).
                if (conn.state != .l7_exchanging) return;
            }
            if (framingDoneOf(&conn.l7.request_framing)) {
                conn.l7.request_leg = .done;
            } else {
                conn.l7.request_leg = .pumping_body;
                // Relay chunks will flow and be overwritten: from here the
                // try is no longer reconstructible — no replay (§7).
                conn.l7.request_body_pumped = true;
                armRequestBodyRecv(server, conn);
            }
        }

        /// The request leg's body pump (client → origin, §7). Framed by the
        /// request's own framing; a client-side recv cannot be forced, so a
        /// pending verdict makes the arm illegal and a settled verdict on a
        /// send diverts. A short body tail past the framing is a pipelined
        /// next request (§7 note). Failures doom the exchange: a recv EOF is
        /// a truncated request (teardown), a send failure is the origin
        /// giving out (`upstreamFailed`).
        const RequestBodyPolicy = struct {
            // -- the TLS transform, client side (§4) --
            //
            // The request leg reads from the client, so on a terminated
            // connection it decrypts; the response leg below encrypts.
            // The upstream halves of both stay plaintext, which is what
            // termination means.

            /// Ciphertext reads into the engine's record buffer, as it
            /// does everywhere else the client speaks.
            pub fn recvBuffer(conn: *ConnType) []u8 {
                if (conn.tls) |engine| return engine.recvBuffer();
                return &conn.relay_buffer.?.client_to_upstream;
            }

            /// Decrypt so framing — chunked decoding, content-length
            /// countdown — sees the body it was told to expect.
            pub fn transformIn(conn: *ConnType, chunk: []u8) ?[]const u8 {
                const engine = conn.tls orelse return chunk;
                var out: BodyPlaintext = .{ .conn = conn };
                const sink = out.sink();
                engine.received(chunk.len, &sink) catch {
                    conn.server.counters.increment("tls_relay_failed");
                    return null;
                };
                return engine.body_plaintext[0..out.len];
            }

            /// A close_notify mid-body is the client saying it will send
            /// no more — framing then decides whether what arrived was a
            /// complete body or a truncated one.
            pub fn transformEnded(conn: *ConnType) bool {
                const engine = conn.tls orelse return false;
                return engine.peerClosed();
            }

            /// The framed window lives wherever the transform put it.
            pub fn sendSlice(conn: *ConnType) []const u8 {
                const state = &conn.directions[
                    @intFromEnum(ConnType.Direction.client_to_upstream)
                ];
                if (state.owed() == 0) return &.{};
                if (conn.tls) |engine| return state.pending(engine.body_plaintext);
                return state.pending(&conn.relay_buffer.?.client_to_upstream);
            }

            pub fn beforeRecv(conn: *ConnType) void {
                assert(conn.state == .l7_exchanging);
                assert(conn.l7.request_leg == .pumping_body);
                // A client-side recv is never armed under a pending verdict:
                // expiry is unanswerable then, and a verdict arms nothing.
                assert(conn.l7.pending_verdict == .none);
                // A recv on the CLIENT socket: an expiry cannot force it, so
                // the deadline verdict is unanswerable while this op is armed.
                conn.l7.request_op_on_client = true;
            }

            pub fn beforeSend(conn: *ConnType) void {
                assert(conn.state == .l7_exchanging);
                conn.l7.request_op_on_client = false; // A send on the upstream socket.
            }

            /// Completion-time re-checks (post-await): a client-side body
            /// recv is never armed under a pending verdict — expiry is
            /// unanswerable then — so none can have arrived during the await.
            pub fn onRecvEntry(conn: *ConnType) void {
                assert(conn.state == .l7_exchanging);
                assert(conn.l7.request_leg == .pumping_body);
                assert(conn.l7.pending_verdict == .none);
            }

            pub fn feed(conn: *ConnType, chunk: []const u8) pump.FeedResult {
                return feedFraming(&conn.l7.request_framing, chunk);
            }

            pub fn afterFeed(conn: *ConnType, received: u32, fr: pump.FeedResult) void {
                // Body bytes this request owns, counted where framing said
                // which they were: a pipelined tail belongs to the *next*
                // request, so it must not land on this one's line (§8).
                conn.log.bytes_in += fr.consumed;
                if (fr.consumed < received) {
                    // Bytes past the body are a pipelined next request; the
                    // connection will close after this exchange (§7 note).
                    conn.l7.client_pipelined = true;
                }
            }

            pub fn framingDone(conn: *ConnType) bool {
                return framingDoneOf(&conn.l7.request_framing);
            }

            pub fn onRecvError(server: *ServerType, conn: *ConnType, err: Io.RecvError) void {
                // EOF mid-body is a truncated request; any failure here
                // dooms the exchange in the client's own direction.
                server.witnessKernelPressure(.recv, err);
                server.beginTeardown(conn);
            }

            pub fn onSendError(server: *ServerType, conn: *ConnType, err: Io.SendError) void {
                server.witnessKernelPressure(.send, err);
                upstreamFailed(server, conn);
            }

            pub fn onDrained(server: *ServerType, conn: *ConnType) void {
                _ = server;
                conn.l7.request_leg = .done;
                // The delivered recv was the flag's referent; keep the
                // flag self-descriptive now that no request op is armed.
                conn.l7.request_op_on_client = false;
            }

            pub fn onComplete(server: *ServerType, conn: *ConnType) void {
                _ = server;
                conn.l7.request_leg = .done;
            }

            pub fn onSendEntry(server: *ServerType, conn: *ConnType) bool {
                assert(conn.state == .l7_exchanging);
                assert(conn.l7.request_leg == .pumping_body);
                if (conn.l7.pending_verdict != .none) {
                    settlePendingVerdict(server, conn);
                    return true;
                }
                return false;
            }
        };

        /// Where a terminated connection's decrypted body bytes land: the
        /// engine's plaintext buffer, which is also where `sendSlice`
        /// reads the framed window from.
        const BodyPlaintext = struct {
            conn: *ConnType,
            len: u32 = 0,
            closed: bool = false,

            fn sink(self: *BodyPlaintext) TlsEngine.Sink {
                return .{ .ctx = self, .appData = append, .closed = peerClosed };
            }

            fn append(ctx: *anyopaque, bytes: []const u8) void {
                const self: *BodyPlaintext = @ptrCast(@alignCast(ctx));
                // RFC 8446 §6.1: anything after a close_notify is ignored.
                if (self.closed) return;
                const buffer = self.conn.tls.?.body_plaintext;
                assert(self.len + bytes.len <= buffer.len);
                @memcpy(buffer[self.len..][0..bytes.len], bytes);
                self.len += @intCast(bytes.len);
            }

            fn peerClosed(ctx: *anyopaque) void {
                const self: *BodyPlaintext = @ptrCast(@alignCast(ctx));
                self.closed = true;
            }
        };

        const RequestBodyPump = pump.Pump(IoType, .client_to_upstream, RequestBodyPolicy);
        const armRequestBodyRecv = RequestBodyPump.armRecv;

        fn startResponseLeg(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .idle);
            assert(conn.upstream.?.head_len == 0);
            conn.l7.response_leg = .awaiting_head;
            armResponseHeadRecv(server, conn);
        }

        fn armResponseHeadRecv(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .awaiting_head);
            const upstream = conn.upstream.?;
            assert(upstream.head_len < upstreamHeadBytes(upstream).len);
            conn.arm(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.recv(
                conn.upstream_socket.?,
                upstreamHeadBytes(upstream)[upstream.head_len..],
                &conn.op_data_upstream_to_client.completion,
                ConnType,
                conn,
                onResponseHeadRecv,
            );
        }

        fn onResponseHeadRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .awaiting_head);
            if (conn.l7.pending_verdict != .none) {
                settlePendingVerdict(server, conn);
                return;
            }
            const received = result catch |err| {
                server.witnessKernelPressure(.recv, err);
                upstreamFailed(server, conn);
                return;
            };
            assert(received >= 1);
            const upstream = conn.upstream.?;
            upstream.head_len += received;
            assert(upstream.head_len <= upstreamHeadBytes(upstream).len);
            parseResponseAndDispatch(server, conn);
        }

        /// Detect-and-retry over the origin's head, mirroring the request
        /// side; any verdict other than "valid" or "more bytes" dooms the
        /// upstream leg (an origin is configured, not adversarial, but §7
        /// framing strictness applies to it all the same).
        fn parseResponseAndDispatch(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            const upstream = conn.upstream.?;
            const head = upstreamHeadBytes(upstream)[0..upstream.head_len];
            const head_is_full = upstream.head_len == upstreamHeadBytes(upstream).len;

            var storage: parser.HeaderStorage = undefined;
            const response = parser.parseResponseHead(
                head,
                head_is_full,
                &storage,
                conn.l7.request_method,
            ) catch |err| switch (err) {
                error.Incomplete => {
                    assert(!head_is_full);
                    armResponseHeadRecv(server, conn);
                    return;
                },
                error.Malformed, error.UriTooLong, error.HeadTooLarge => {
                    upstreamFailed(server, conn);
                    return;
                },
            };
            // The render reuses conn.head, so it must wait until the
            // request head has vacated that buffer (§7 buffer rotation);
            // record the head boundary so the deferred render agrees.
            conn.l7.response_head_len_marker = response.head_len;
            if (conn.l7.request_head_vacated) {
                // conn.head is already free, so render straight from the
                // parse we just did — no second parse of the same bytes.
                // This is the common path: the request head vacates long
                // before the origin answers.
                renderResponse(server, conn, &response);
            } else {
                conn.l7.response_render_pending = true;
            }
        }

        /// Deferred render path: the origin answered before the request
        /// head vacated conn.head, so the first parse's stack storage is
        /// gone and the bytes must be re-parsed (unchanged, §7 single
        /// source of truth, so it cannot fail). The common path renders
        /// from the first parse via `renderResponse` and never gets here.
        fn beginResponseForward(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .awaiting_head);
            assert(conn.l7.request_head_vacated);
            const upstream = conn.upstream.?;
            var storage: parser.HeaderStorage = undefined;
            const response = parser.parseResponseHead(
                upstreamHeadBytes(upstream)[0..upstream.head_len],
                false,
                &storage,
                conn.l7.request_method,
            ) catch unreachable;
            assert(response.head_len == conn.l7.response_head_len_marker);
            renderResponse(server, conn, &response);
        }

        /// The §8 persistence decision, made once and honored: keep the
        /// client's connection unless pipelining, pressure, or drain says
        /// otherwise — then announce whatever was decided (§7).
        ///
        /// Only relay pressure suppresses keep-alive: the next request on
        /// this connection would claim a relay buffer the pool is running
        /// out of. Conn-slot pressure deliberately does not reach here
        /// (`keepAliveSuppressed`, #57) — under slot scarcity this serving
        /// connection *is* the population, and closing it trades one
        /// briefly-free slot for a reconnect wave. An until-close body
        /// forces the close unconditionally: the FIN is the only thing
        /// delimiting the relayed body for the client, exactly as it
        /// delimited it for us.
        fn downstreamKeepAlive(
            server: *const ServerType,
            conn: *const ConnType,
            response: *const parser.ResponseHead,
        ) bool {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .awaiting_head);
            return conn.l7.client_keep_alive and
                !conn.l7.client_pipelined and !server.draining and
                !server.keepAliveSuppressed() and response.framing != .until_close;
        }

        /// Render the origin's head into conn.head (free once the request
        /// head has vacated it) and forward the coalesced body excess
        /// straight from upstream.head — never copied through a relay
        /// buffer, so an oversized coalesced body is fine.
        /// The #175 response edits for this exchange, gathered into the
        /// caller's buffer: matched against the status and headers the
        /// origin actually answered, and consumed by the render in the
        /// same frame — the request side's `edit_buffer` discipline,
        /// isolated here the way `planForward` isolates its half.
        fn responseEdits(
            conn: *const ConnType,
            response: *const parser.ResponseHead,
            out: []filter.AppliedHeaderEdit,
        ) []const filter.AppliedHeaderEdit {
            assert(out.len == constants.header_edits_max);
            assert(conn.state == .l7_exchanging);
            return filter.collectResponseEdits(conn.response_filters, .{
                .status = response.status,
                .headers = response.headers,
            }, out);
        }

        /// The #178 verdict for this exchange, decided at the response
        /// render — the one moment that knows both what the request's
        /// cookie named (`sticky_cookie`, recorded at routing) and which
        /// endpoint actually served (a replay may have moved it since
        /// the pick). `.none` on every cluster that is not cookie-keyed.
        const StickyVerdict = enum(u2) { none, followed, assigned, repicked };

        fn stickyVerdict(server: *const ServerType, conn: *const ConnType) StickyVerdict {
            assert(conn.state == .l7_exchanging);
            assert(conn.cluster_index < server.config.clusters.len);
            const cluster = &server.config.clusters[conn.cluster_index];
            switch (cluster.hash_key) {
                .source_ip, .header => return .none,
                .cookie => {},
            }
            // An exchange rendering a response holds an upstream, so the
            // endpoint was recorded when its slot was (§8).
            assert(conn.log.endpoint_index != conn_module.LogState.endpoint_none);
            const served = server.balancer.endpointIdentity(
                conn.cluster_index,
                conn.log.endpoint_index,
            );
            const carried = conn.l7.sticky_cookie orelse return .assigned;
            if (carried == served) {
                return .followed;
            }
            return .repicked;
        }

        /// The Set-Cookie attributes every #178 stamp carries. `Path=/`
        /// because the assignment is per *backend*, not per resource;
        /// `HttpOnly` because no script has business reading a routing
        /// tag. No `Max-Age`: a session cookie, HAProxy's default for the
        /// same feature.
        ///
        /// `Secure` rides a terminated connection and only that one. It
        /// used to ride nothing, on the reasoning that a proxy which does
        /// not terminate TLS cannot know the client-facing scheme — true
        /// when it was written and falsified by the very issue it cited
        /// (#125). Where zoxy terminates, it knows: the scheme is https,
        /// and a routing cookie without `Secure` is one the browser will
        /// hand back over plaintext to the same host, which is the
        /// downgrade the attribute exists to stop.
        ///
        /// Still absent on a plaintext listener rather than always
        /// present, because there the original reasoning holds intact —
        /// something in front may have terminated TLS, and `Secure` on a
        /// cookie the client can only ever return over http is a cookie
        /// it will never return at all.
        const sticky_attributes = "; Path=/; HttpOnly";
        const sticky_attributes_secure = sticky_attributes ++ "; Secure";
        const sticky_value_bytes_max = constants.pick_name_bytes_max + 1 +
            Balancer.endpoint_tag_len + sticky_attributes_secure.len;

        /// This render's full edit set: the #175 filter edits, plus —
        /// when the verdict owes the client an announcement — the #178
        /// stamp in the one buffer slot reserved past the filter budget.
        /// The stamp is an `add`, so an origin's own Set-Cookie lines
        /// ride beside it untouched. The composed value lives in the
        /// caller's scratch: it must survive exactly until the render
        /// consumes it, in the same frame.
        fn responseEditsWithStamp(
            server: *const ServerType,
            conn: *const ConnType,
            response: *const parser.ResponseHead,
            verdict: StickyVerdict,
            buffer: *[constants.response_edits_max]filter.AppliedHeaderEdit,
            scratch: *[sticky_value_bytes_max]u8,
        ) []const filter.AppliedHeaderEdit {
            const edits = responseEdits(conn, response, buffer[0..constants.header_edits_max]);
            assert(edits.len <= constants.header_edits_max);
            switch (verdict) {
                .none, .followed => return edits,
                .assigned, .repicked => {},
            }
            const name = switch (server.config.clusters[conn.cluster_index].hash_key) {
                .cookie => |name| name,
                // The verdict said cookie cluster; the config cannot
                // have changed under it (§5 parse-once).
                .source_ip, .header => unreachable,
            };
            assert(name.len >= 1);
            assert(name.len <= constants.pick_name_bytes_max);
            var len: u32 = 0;
            @memcpy(scratch[0..name.len], name);
            len += @intCast(name.len);
            scratch[len] = '=';
            len += 1;
            // Through the one mint (`formatEndpointTag`), so the tag the
            // stamp announces is byte-identical to the tag the next
            // request's parse will match.
            Balancer.formatEndpointTag(
                server.balancer.endpointIdentity(conn.cluster_index, conn.log.endpoint_index),
                scratch[len..][0..Balancer.endpoint_tag_len],
            );
            len += Balancer.endpoint_tag_len;
            // The connection's own termination, not the listener's
            // config: what `Secure` claims is how *this* client reached
            // us, and that is what `conn.tls` answers.
            const attributes = if (conn.tls != null)
                sticky_attributes_secure
            else
                sticky_attributes;
            @memcpy(scratch[len..][0..attributes.len], attributes);
            len += @intCast(attributes.len);
            // Exactly the four pieces, no gaps: the value the render
            // emits is the whole composition.
            assert(len == name.len + 1 + Balancer.endpoint_tag_len + attributes.len);
            // And the attributes the predicate chose are the ones on the
            // wire. The length check above cannot say that — it reuses
            // the same binding the copy did, so it holds just as well
            // under an inverted predicate. This reads the bytes back.
            if (conn.tls != null) {
                assert(std.mem.endsWith(u8, scratch[0..len], sticky_attributes_secure));
            } else {
                assert(!std.mem.endsWith(u8, scratch[0..len], sticky_attributes_secure));
            }
            buffer[edits.len] = .{ .kind = .add, .name = "Set-Cookie", .value = scratch[0..len] };
            return buffer[0 .. edits.len + 1];
        }

        /// Count the #178 verdict — only after the render commits, so a
        /// 502'd or replayed render try cannot double-count, and the
        /// three counters partition exactly the forwarded responses of
        /// cookie clusters (their doc's contract).
        fn creditSticky(server: *ServerType, verdict: StickyVerdict) void {
            switch (verdict) {
                .none => {},
                .followed => server.counters.increment("l7_sticky_followed"),
                .assigned => server.counters.increment("l7_sticky_assigned"),
                .repicked => server.counters.increment("l7_sticky_repicked"),
            }
        }

        /// The origin agreed: render its `101` to the client, with every
        /// trailing byte it arrived with, and hand the connection to the
        /// relay once the client has it (#180).
        ///
        /// The trailing bytes are why this cannot reuse the response
        /// machinery. There, excess past the head is fed through the
        /// framing tracker and forwarded as *body*; here the response is
        /// bodiless by status and the bytes past the head are the origin's
        /// first frames — payload of a protocol this proxy does not read.
        /// So they are copied verbatim behind the rendered head, and the
        /// head buffer is what bounds them: an origin that sent more than
        /// fits is not a client error but an origin this proxy cannot
        /// carry, answered like any other unrenderable head.
        fn renderUpgradeAccepted(
            server: *ServerType,
            conn: *ConnType,
            response: *const parser.ResponseHead,
        ) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.upgrade_requested);
            assert(response.status == 101);
            assert(conn.tunnel_buffer != null);
            const upstream = conn.upstream.?;
            // No edits and no sticky stamp: #175 and #178 both describe a
            // response an origin *served*, and this one only announces
            // that serving has stopped being HTTP. A `Set-Cookie` naming
            // the endpoint of a session about to become opaque would be a
            // statement about a request that no longer exists.
            const rendered = render.renderResponseHead(
                response,
                false,
                &.{},
                true,
                headBytes(server, conn),
            ) catch {
                upstreamFailed(server, conn);
                return;
            };
            assert(rendered.len >= 1);
            const trailing = upstreamHeadBytes(upstream)[response.head_len..upstream.head_len];
            if (rendered.len + trailing.len > headBytes(server, conn).len) {
                upstreamFailed(server, conn);
                return;
            }
            @memcpy(headBytes(server, conn)[rendered.len..][0..trailing.len], trailing);
            const head_write_len: u32 = @intCast(rendered.len + trailing.len);
            conn.l7.response_leg = .sending_head;
            conn.l7.response_started = true;
            conn.log.status = response.status;
            server.captureResponseLogHeaders(conn, response.headers);
            armClientWrite(server, conn, headBytes(server, conn)[0..head_write_len], .tunnel_start);
        }

        /// The handshake reached the client, so this connection stops
        /// speaking HTTP and starts relaying (#180).
        ///
        /// What changes hands here is the whole point of the feature. The
        /// shared relay buffer, the head buffer and the *upstream slot*
        /// all go back to the pools ordinary traffic draws on — a tunnel
        /// that kept them would be the starvation §5 refuses — while the
        /// origin socket stays open and the endpoint stays charged, now
        /// the way an L4 connection charges it (`chargeEndpoint`). Slot
        /// and socket are separable, and separating them is what lets a
        /// tunnel be counted against `max_inflight` for its whole life
        /// without pinning capacity ordinary exchanges shed against.
        ///
        /// Client bytes that arrived behind the handshake are staged into
        /// the tunnel buffer and framed as this direction's debt, exactly
        /// as a payload behind a PROXY header is (#142) — so `Relay.start`
        /// sends them before it reads another byte, and a client that
        /// pipelined its first frame is not left waiting for an echo of
        /// something this proxy dropped.
        fn beginTunnel(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.upgrade_requested);
            assert(conn.upstream_socket != null);
            assert(!conn.armed.data_client_to_upstream);
            assert(!conn.armed.data_upstream_to_client);
            assert(conn.l7.request_head_len <= conn.head_len);
            const pipelined = conn.head_len - conn.l7.request_head_len;
            // `tunnel_buffer` stays set: it is what marks which pool this
            // buffer belongs to. `relay_buffer` only *aliases* it, so the
            // relay reads one field like every other connection while the
            // release paths still know where to give it back — the two
            // pools hold the same element type, so nothing but this marker
            // could tell them apart.
            const buffer = conn.tunnel_buffer.?;
            // Staged before the head buffer goes back, since that is where
            // the client's own trailing bytes still live.
            if (pipelined >= 1) {
                assert(pipelined <= buffer.client_to_upstream.len);
                @memcpy(
                    buffer.client_to_upstream[0..pipelined],
                    headBytes(server, conn)[conn.l7.request_head_len..conn.head_len],
                );
            }
            const leased = conn.upstream.?;
            const cluster_index = leased.cluster_index;
            const endpoint_index = leased.endpoint_index;
            server.releaseUpstream(leased);
            conn.upstream = null;
            // Both held for certain here, unlike at the static-response
            // rungs where either may never have been acquired: this runs
            // only after a rendered head went out, which needed the head
            // buffer, and every routed exchange holds a relay buffer.
            assert(conn.relay_buffer != null);
            assert(conn.head_buffer_id != ConnType.head_buffer_none);
            server.releaseRelayBuffer(conn.relay_buffer.?);
            server.returnHeadBuffer(conn);
            conn.head_len = 0;
            conn.relay_buffer = buffer;
            conn.directions = .{ .{}, .{} };
            // Charged while this is still an exchange, so the charge and
            // the slot it replaces never both count the same work: the
            // release above gave the lease back, and this takes its place
            // in the same view (§7) before anything can read it.
            server.chargeEndpoint(conn, cluster_index, endpoint_index);
            conn.state = .relaying;
            if (pipelined >= 1) {
                const direction = &conn.directions[0];
                direction.phase = .receiving;
                direction.owe(pipelined);
            }
            server.counters.increment("tunnels_established");
            // The tunnel's own clock replaces the three that would each
            // cut a healthy session (§8). Stored, not re-based: a rebase
            // exists to pull a deadline *earlier* than the armed timer,
            // and this one moves the other way — the armed timer fires at
            // the exchange's old target, reads the later stored one and
            // re-arms, which is how the L4 relay start hands over too.
            server.storeDeadline(conn, server.config.tunnel_timeout_ms);
            relay.Relay(IoType).start(server, conn);
        }

        fn renderResponse(
            server: *ServerType,
            conn: *ConnType,
            response: *const parser.ResponseHead,
        ) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .awaiting_head);
            assert(conn.l7.request_head_vacated);
            const upstream = conn.upstream.?;
            // `101` on a carried upgrade is terminal, not interim (#180),
            // and diverts before any of the ordinary response machinery
            // below. Two reasons it cannot share that path: the framing
            // tracker reads a sub-200 status as bodiless and would consume
            // none of the trailing bytes, when for a tunnel every trailing
            // byte is payload; and the state machine would treat the
            // exchange as complete and go read another request, which is
            // the desynchronisation §7 exists to prevent. An unrequested
            // `101` is *not* diverted — an origin cannot upgrade a
            // connection this proxy never asked to upgrade.
            if (conn.l7.upgrade_requested and response.status == 101) {
                return renderUpgradeAccepted(server, conn, response);
            }
            // The origin declined. Answering an upgrade request with an
            // ordinary response is legal and common — an origin that does
            // not speak WebSocket just serves the request — and the
            // exchange from here is an ordinary one, so the tunnel claimed
            // at the gate goes back *now* rather than at teardown. This
            // connection is very likely kept: `conn.l7` resets at the
            // turnaround while the claim lives on the connection, so
            // holding it would pin a pool slot nothing is using for as
            // long as the client stays, and a second `Upgrade` over the
            // same connection would find one already held.
            if (conn.l7.upgrade_requested) {
                conn.l7.upgrade_requested = false;
                releaseTunnelClaim(server, conn);
            }

            const keep_downstream = downstreamKeepAlive(server, conn, response);
            conn.l7.downstream_close_announced = !keep_downstream;
            conn.l7.upstream_reusable = response.keep_alive;
            const verdict = stickyVerdict(server, conn);
            var edit_buffer: [constants.response_edits_max]filter.AppliedHeaderEdit = undefined;
            var cookie_scratch: [sticky_value_bytes_max]u8 = undefined;
            const rendered = render.renderResponseHead(
                response,
                !keep_downstream,
                responseEditsWithStamp(server, conn, response, verdict, &edit_buffer, &cookie_scratch),
                false,
                headBytes(server, conn),
            ) catch {
                // The head no longer fits — after the #175 edits or the
                // #178 stamp, or never did: an origin response the proxy
                // cannot re-render is not the client's fault, so 502,
                // the same verdict an unparseable origin head earns.
                upstreamFailed(server, conn);
                return;
            };
            assert(rendered.len >= 1);
            conn.l7.response_framing = framingFromParsed(response.framing);

            // Feed the framing tracker over the body excess that arrived
            // coalesced with the head.
            const excess = upstreamHeadBytes(upstream)[response.head_len..upstream.head_len];
            const feed = feedFraming(&conn.l7.response_framing, excess);
            if (feed.malformed) {
                upstreamFailed(server, conn);
                return;
            }
            // The common small response arrives from the origin in one
            // piece; forward it in one piece too. Appending the excess to
            // the rendered head trades a bounded memcpy for a whole ring
            // round trip per response. The fallback writes the head, then
            // the excess from upstream.head as the channel's next write.
            var head_write_len: u32 = @intCast(rendered.len);
            if (rendered.len + feed.consumed <= headBytes(server, conn).len) {
                @memcpy(
                    headBytes(server, conn)[rendered.len..][0..feed.consumed],
                    excess[0..feed.consumed],
                );
                head_write_len = @intCast(rendered.len + feed.consumed);
                conn.l7.response_excess_len = 0; // It rides the head write.
            } else {
                conn.l7.response_excess_len = feed.consumed;
            }

            conn.l7.response_leg = .sending_head;
            // Committed to answering: no verdict may intervene from here (§7).
            conn.l7.response_started = true;
            // Credited only here, at the point of no return — the
            // malformed-excess bail above can still discard a rendered
            // head, and a discarded try must not count (`l7_redirected`'s
            // placement rule).
            creditSticky(server, verdict);
            // What the origin said, so a line can report it even if the
            // exchange never finishes. Whether the client *got* it is a
            // separate fact, and `outcome` stays `aborted` until
            // `finishExchange` earns `ok` (§8).
            conn.log.status = response.status;
            // The #140 response headers, captured here for the same
            // reason and at the same moment: the origin's head is live
            // now, and this render is what writes over it.
            server.captureResponseLogHeaders(conn, response.headers);
            armClientWrite(server, conn, headBytes(server, conn)[0..head_write_len], .response_excess);
        }

        // -- the client-write channel (§7, §8) --
        //
        // Every client-directed send outside the body pump goes through this
        // one pair: the rendered response head, the body excess that arrived
        // coalesced with it, and the static error responses. They differ only
        // in their bytes and their continuation, which is what
        // `Conn.ClientWrite` holds — so the cursor, the short-write resume,
        // the teardown interlock and the error handling exist once each.
        // Under a transforming client side (§4) this is also the single place
        // these three writers turn plaintext into wire bytes.

        fn armClientWrite(
            server: *ServerType,
            conn: *ConnType,
            bytes: []const u8,
            then: conn_module.ClientWrite.Then,
        ) void {
            assert(bytes.len >= 1);
            assert(conn.state == .l7_exchanging or conn.state == .l7_responding);
            // One write at a time: the channel is the only writer of this op,
            // and a previous write either drained or ended in teardown.
            assert(conn.client_write.pending.len == 0);
            conn.client_write = .{ .pending = bytes, .then = then };
            resumeClientWrite(server, conn);
        }

        fn resumeClientWrite(server: *ServerType, conn: *ConnType) void {
            assert(conn.client_write.pending.len >= 1);
            const bytes = if (conn.tls != null)
                (stageClientCiphertext(server, conn) orelse return)
            else
                conn.client_write.pending;
            assert(bytes.len >= 1);
            conn.arm(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.send(
                conn.client_socket,
                bytes,
                &conn.op_data_upstream_to_client.completion,
                ConnType,
                conn,
                onClientWritten,
            );
        }

        /// What must hold before each continuation runs. Its own function
        /// because these are the channel's whole invariant — one writer
        /// set both the bytes and the `then`, so a mismatch here means
        /// they disagreed — and because `onClientWritten` was over the
        /// length limit with them inline.
        fn assertWriteContinuation(
            conn: *const ConnType,
            then: conn_module.ClientWrite.Then,
        ) void {
            switch (then) {
                // The handshake is out and nothing has been relayed yet:
                // still the exchange, still no verdict, and the tunnel
                // buffer claimed at the gate is still in hand (#180).
                .tunnel_start => {
                    assert(conn.state == .l7_exchanging);
                    assert(conn.l7.pending_verdict == .none);
                    assert(conn.l7.upgrade_requested);
                    assert(conn.tunnel_buffer != null);
                },
                .response_excess, .response_body => {
                    // `response_started` blocks a verdict, so none can be
                    // pending once response bytes are flowing (negative
                    // space).
                    assert(conn.state == .l7_exchanging);
                    assert(conn.l7.pending_verdict == .none);
                },
                // The two static-response endings share one state:
                // `respond` is the only writer of either, and always sets
                // it.
                .lingering_close, .next_request => assert(conn.state == .l7_responding),
                // The redirect pair likewise — and the buffer it rendered
                // into is still held, which is the pair's whole reason.
                // *Held*, not bound: a terminated connection renders into
                // its engine's plaintext buffer and never binds a ring
                // buffer at all (§4), so the ring claim is the plaintext
                // path's form of the same invariant rather than the
                // invariant itself.
                .redirect_next_request, .redirect_lingering_close => {
                    assert(conn.state == .l7_responding);
                    if (conn.tls == null) {
                        assert(conn.head_buffer_id != ConnType.head_buffer_none);
                    }
                },
            }
        }

        /// Account for `sent` bytes leaving the client-directed channel,
        /// and say whether anything is still owed. Split from
        /// `onClientWritten` for the length limit, and because the two
        /// paths measure in different units: a plaintext write's cursor
        /// counts the bytes the socket took, while a terminated one's
        /// counts *plaintext* — the wire carries more, so the chunk
        /// advances only once all of its ciphertext is gone, and the
        /// access log reports what the client's application received
        /// rather than what the record layer wrapped it in.
        fn creditClientWrite(conn: *ConnType, sent: u32) bool {
            const write = &conn.client_write;
            if (conn.tls) |engine| {
                engine.outboundSent(sent);
                if (engine.outbound().len >= 1) return true; // Short send.
                assert(write.staged >= 1);
                assert(write.staged <= write.pending.len);
                conn.log.bytes_out += write.staged;
                write.pending = write.pending[write.staged..];
                write.staged = 0;
                return write.pending.len > 0;
            }
            assert(sent <= write.pending.len);
            conn.log.bytes_out += sent;
            write.pending = write.pending[sent..];
            return write.pending.len > 0;
        }

        /// Encrypt the next chunk of a terminated connection's response,
        /// or hand back what an earlier chunk still has in flight. Null
        /// means the connection is already tearing down.
        ///
        /// Chunked because the outbox is a fixed size and `pending` is not
        /// — a rendered head, a configured error page or a coalesced body
        /// excess can each be a whole head buffer, up to 1 MiB if the
        /// operator said so. Emitting several smaller records is always
        /// legal and is what keeps the engine's footprint answerable at
        /// compile time (§5).
        fn stageClientCiphertext(server: *ServerType, conn: *ConnType) ?[]const u8 {
            const engine = conn.tls.?;
            const write = &conn.client_write;
            const staged = engine.outbound();
            if (staged.len >= 1) {
                // A short send: the remainder of a chunk already encrypted.
                assert(write.staged >= 1);
                return staged;
            }
            assert(write.staged == 0);
            const chunk: u32 = @intCast(@min(
                write.pending.len,
                constants.tls_app_chunk_bytes,
            ));
            assert(chunk >= 1);
            engine.sendApp(write.pending[0..chunk]) catch {
                server.counters.increment("tls_relay_failed");
                server.beginTeardown(conn);
                return null;
            };
            write.staged = chunk;
            const wire = engine.outbound();
            assert(wire.len >= 1);
            return wire;
        }

        fn onClientWritten(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_exchanging or conn.state == .l7_responding);
            const write = &conn.client_write;
            const sent = result catch |err| {
                // The client is gone; there is no one left to answer.
                server.witnessKernelPressure(.send, err);
                server.beginTeardown(conn);
                return;
            };
            assert(sent >= 1);
            if (creditClientWrite(conn, sent)) {
                resumeClientWrite(server, conn); // More to write (§6).
                return;
            }
            assertWriteContinuation(conn, write.then);
            switch (write.then) {
                // The origin's `101` has reached the client, so the HTTP
                // conversation on this connection is over (#180).
                .tunnel_start => beginTunnel(server, conn),
                .response_excess => sendResponseExcess(server, conn),
                .response_body => {
                    assert(conn.l7.response_leg == .sending_body_excess);
                    afterResponseExcess(server, conn);
                },
                // A static answer is fully delivered. Log it here rather
                // than where the verdict was decided, so the byte count
                // includes the answer, and before either continuation runs
                // — the keep path resets what the line reports, and the
                // close path hands the connection to a drain (§8).
                .lingering_close => {
                    server.logExchange(conn);
                    beginLingeringClose(server, conn);
                },
                .next_request => {
                    server.logExchange(conn);
                    resumeAfterStaticResponse(server, conn);
                },
                // A #176 redirect is fully delivered: return the head
                // buffer it rendered into — held through the send, unlike
                // a static answer's — then the static pair's own endings,
                // whose continuations assert the buffer is gone.
                .redirect_lingering_close => {
                    server.returnHeadBuffer(conn);
                    server.logExchange(conn);
                    beginLingeringClose(server, conn);
                },
                .redirect_next_request => {
                    server.returnHeadBuffer(conn);
                    server.logExchange(conn);
                    resumeAfterStaticResponse(server, conn);
                },
            }
        }

        /// The rendered head is on the wire. Any body excess that arrived
        /// coalesced with it but did not fit beside it follows straight from
        /// `upstream.head`; otherwise the body pump takes over.
        fn sendResponseExcess(server: *ServerType, conn: *ConnType) void {
            assert(conn.l7.response_leg == .sending_head);
            const excess_len = conn.l7.response_excess_len;
            if (excess_len == 0) {
                afterResponseExcess(server, conn);
                return;
            }
            conn.l7.response_leg = .sending_body_excess;
            server.counters.increment("l7_response_excess_sent");
            const base = conn.l7.response_head_len_marker;
            // These are bytes the origin actually delivered past its head —
            // the bound `DirectionState.pending` used to check for this write
            // before the channel owned the cursor.
            assert(base + excess_len <= conn.upstream.?.head_len);
            armClientWrite(
                server,
                conn,
                upstreamHeadBytes(conn.upstream.?)[base..][0..excess_len],
                .response_body,
            );
        }

        /// The head and its coalesced excess are on the wire; finish if the
        /// body ended there, else pump the remaining body from the origin.
        fn afterResponseExcess(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            conn.l7.response_leg = .pumping_body;
            if (framingDoneOf(&conn.l7.response_framing)) {
                finishExchange(server, conn);
            } else {
                armResponseBodyRecv(server, conn);
            }
        }

        /// The response leg's body pump (origin → client, §7). Framed by the
        /// origin's response framing; the first response byte already
        /// reached the client, so no verdict can be pending (a 504/replay is
        /// off the table once bytes flow). An `until_close` body ends on the
        /// origin's EOF; any other framing's EOF is a truncation the client
        /// must see, and every failure tears down.
        const ResponseBodyPolicy = struct {
            // -- the TLS transform, client side (§4) --
            //
            // This leg reads plaintext from the origin and writes to the
            // client, so only the write half transforms. The recv side
            // needs no override at all.

            /// Encrypt the framed chunk once, before the first send — a
            /// resume must not re-encrypt bytes already gone. The chunk is
            /// bounded by the relay buffer, which is already within what
            /// one record carries.
            pub fn transformOut(conn: *ConnType, consumed: u32) bool {
                const engine = conn.tls orelse return true;
                if (engine.outboundRoom() < TlsEngine.emitted_record_bytes_max) {
                    conn.server.counters.increment("tls_relay_failed");
                    return false;
                }
                engine.sendApp(
                    conn.relay_buffer.?.upstream_to_client[0..consumed],
                ) catch {
                    conn.server.counters.increment("tls_relay_failed");
                    return false;
                };
                return true;
            }

            pub fn sendSlice(conn: *ConnType) []const u8 {
                if (conn.tls) |engine| return engine.outbound();
                const state = &conn.directions[
                    @intFromEnum(ConnType.Direction.upstream_to_client)
                ];
                if (state.owed() == 0) return &.{};
                return state.pending(&conn.relay_buffer.?.upstream_to_client);
            }

            /// Ciphertext outnumbers the plaintext the debt counts, so the
            /// debt settles all at once when the outbox drains — the
            /// pump's contract for a transforming send.
            pub fn creditSend(conn: *ConnType, sent: u32) void {
                const state = &conn.directions[
                    @intFromEnum(ConnType.Direction.upstream_to_client)
                ];
                if (conn.tls) |engine| {
                    engine.outboundSent(sent);
                    if (engine.outbound().len == 0 and state.owed() >= 1) {
                        state.credit(state.owed());
                    }
                    return;
                }
                state.credit(sent);
            }

            pub fn beforeRecv(conn: *ConnType) void {
                assert(conn.state == .l7_exchanging);
                assert(conn.l7.response_leg == .pumping_body);
                assert(conn.l7.pending_verdict == .none); // response_started.
            }

            /// Completion-time re-checks (post-await): once a response byte
            /// has reached the client no verdict can be pending, so the
            /// invariant must still hold after the await.
            pub fn onRecvEntry(conn: *ConnType) void {
                assert(conn.state == .l7_exchanging);
                assert(conn.l7.response_leg == .pumping_body);
                assert(conn.l7.pending_verdict == .none); // response_started.
            }

            pub fn feed(conn: *ConnType, chunk: []const u8) pump.FeedResult {
                return feedFraming(&conn.l7.response_framing, chunk);
            }

            /// Response body bytes that reached the client. The head and
            /// any coalesced excess are counted by the client-write
            /// channel; between them every byte this proxy sends the
            /// client is counted exactly once (§8).
            pub fn afterSend(conn: *ConnType, sent: u32) void {
                conn.log.bytes_out += sent;
            }

            pub fn framingDone(conn: *ConnType) bool {
                return framingDoneOf(&conn.l7.response_framing);
            }

            pub fn onRecvError(server: *ServerType, conn: *ConnType, err: Io.RecvError) void {
                if (err == error.EndOfStream) {
                    if (conn.l7.response_framing == .until_close) {
                        // The origin's EOF is this framing's terminator.
                        finishExchange(server, conn);
                        return;
                    }
                    // Truncated inside a length-delimited body: the client
                    // must see the truncation too, so tear down.
                }
                server.witnessKernelPressure(.recv, err);
                server.beginTeardown(conn);
            }

            pub fn onSendError(server: *ServerType, conn: *ConnType, err: Io.SendError) void {
                server.witnessKernelPressure(.send, err);
                server.beginTeardown(conn);
            }

            pub fn onDrained(server: *ServerType, conn: *ConnType) void {
                finishExchange(server, conn);
            }

            pub fn onComplete(server: *ServerType, conn: *ConnType) void {
                finishExchange(server, conn);
            }

            pub fn onSendEntry(server: *ServerType, conn: *ConnType) bool {
                _ = server;
                assert(conn.state == .l7_exchanging);
                assert(conn.l7.response_leg == .pumping_body);
                assert(conn.l7.pending_verdict == .none); // response_started.
                return false;
            }
        };

        const ResponseBodyPump = pump.Pump(IoType, .upstream_to_client, ResponseBodyPolicy);
        const armResponseBodyRecv = ResponseBodyPump.armRecv;

        /// The response reached the client in full: settle both sides.
        /// The upstream connection parks for reuse when the origin allowed
        /// it and the request went out completely (§5); the downstream
        /// connection honors what its response announced (§7). An early
        /// response with the request still in flight forfeits both — the
        /// two byte streams are no longer alignable.
        fn finishExchange(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_started);
            conn.l7.response_leg = .done;
            server.counters.increment("l7_responses");
            // The labeled twin (#179): the slot is still attached here —
            // park and detach run below — and it names the endpoint that
            // actually served, which is what "requests per backend" means.
            assert(conn.upstream != null);
            server.labeled.incrementEndpoint(.responses, server.upstreams.keys.key(
                conn.upstream.?.cluster_index,
                conn.upstream.?.endpoint_index,
            ));
            // The whole response reached the client: the line goes out
            // now, before the turnaround below clears what it reports.
            // This is also the only place `ok` is earned — nothing between
            // the response head being queued and this point may claim it,
            // which is what keeps one `ok` line per `l7_responses`.
            assert(conn.log.outcome == .aborted);
            conn.log.outcome = .ok;
            server.logExchange(conn);

            const request_complete = conn.l7.request_leg == .done;
            if (conn.l7.upstream_reusable and request_complete and !server.draining) {
                parkUpstream(server, conn);
            }
            const keep_downstream = !conn.l7.downstream_close_announced and
                request_complete and !server.draining;
            if (keep_downstream) {
                detachUpstream(server, conn);
                resetForNextRequest(server, conn);
            } else {
                // A still-attached upstream closes with the teardown.
                server.beginTeardown(conn);
            }
        }

        /// Park the leased upstream on its endpoint's idle list (§5): the
        /// socket stays open with no armed op, the stored deadline hands
        /// reaping to the Server's sweep, and the conn detaches so its
        /// teardown cannot close a connection it no longer owns. Under
        /// upstream pressure the parked deadline shortens (§8 watermarks)
        /// so idle parked sockets free their slots before the 503 wall.
        fn parkUpstream(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            const upstream = conn.upstream.?;
            assert(!upstream.parked);
            // The exchange's head bytes go back before the slot parks
            // (§5): the response leg is settled, so the client-write
            // channel no longer references them — asserted, because the
            // excess write sends straight from this buffer.
            assert(conn.client_write.pending.len == 0);
            server.releaseUpstreamHeadBuffer(upstream);
            server.upstreams.park(upstream);
            upstream.deadline_ns = server.io.nowNs() +
                @as(u64, server.parkedTimeoutMs()) * std.time.ns_per_ms;
            server.ensureUpstreamSweep();
            conn.upstream = null;
            conn.upstream_socket = null;
        }

        /// Close and release an upstream that did not park while the conn
        /// itself lives on. The socket has no armed op at this point (both
        /// data ops settled with the exchange), so the close is
        /// synchronous, like the parked-reap path.
        fn detachUpstream(server: *ServerType, conn: *ConnType) void {
            assert(!conn.armed.data_client_to_upstream);
            assert(!conn.armed.data_upstream_to_client);
            if (conn.upstream) |leased| {
                server.io.closeNow(conn.upstream_socket.?);
                server.releaseUpstream(leased);
                conn.upstream = null;
                conn.upstream_socket = null;
            }
            assert(conn.upstream_socket == null);
        }

        /// Keep-alive turnaround (§5): the relay buffer goes back to its
        /// pool — an idle connection costs a slot and head buffer only —
        /// the exchange state resets, and the next head read begins under
        /// a fresh idle deadline.
        fn resetForNextRequest(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.upstream == null);
            // The exchange is fully settled: no data or dial ops in flight.
            // The lazy deadline timer stays armed across the turnaround (§4),
            // and a dial rebase (§8) cancel may still be draining if the
            // exchange outran it — both re-establish the next idle deadline.
            assert(!conn.armed.data_client_to_upstream);
            assert(!conn.armed.data_upstream_to_client);
            assert(!conn.armed.connect);
            assert(!conn.armed.connect_cancel);
            assert(conn.armed.deadline or conn.armed.deadline_cancel);
            // The channel's cursor lives on the conn, not in `l7`, so the
            // reset below does not wipe it: assert it drained instead of
            // trusting the control flow that got us here.
            assert(conn.client_write.pending.len == 0);
            server.releaseRelayBuffer(conn.relay_buffer.?);
            conn.relay_buffer = null;
            beginNextRequest(server, conn);
        }

        /// The turnaround itself, shared by the two paths that reach it: an
        /// exchange that completed (`resetForNextRequest`) and a static
        /// response that kept its connection (`resumeAfterStaticResponse`).
        /// One home so a new per-request field cannot be cleared on one path
        /// and left stale on the other — which on the resync rule's inputs
        /// would be a §7 bug, not a cosmetic one.
        ///
        /// The preconditions stay with the callers: they differ (one has an
        /// exchange to have settled, the other never had one), and only they
        /// can state why they hold.
        fn beginNextRequest(server: *ServerType, conn: *ConnType) void {
            assert(conn.relay_buffer == null);
            assert(conn.upstream == null);
            assert(conn.client_write.pending.len == 0);
            // The exchange that just ended has spoken for itself, so its
            // accounting resets with the rest of the per-request state
            // (§8). The captures are left in place: their lengths are what
            // gate every read, and this zeroes those.
            assert(conn.log.emitted or conn.log.started_wall_ns == 0);
            // The request's head buffer goes back to the ring before the
            // idle wait begins — an idle connection holds no head bytes
            // (§5). Conditional because the static-response path already
            // returned it (`releaseForStaticResponse`); the completed-
            // exchange path still holds it here.
            if (conn.head_buffer_id != ConnType.head_buffer_none) {
                server.returnHeadBuffer(conn);
            }
            conn.head_len = 0;
            conn.l7 = .{};
            conn.log.reset();
            // The #140 captures live in the server's side table, not on
            // `log`, so they need clearing beside it — or the next
            // request's line would report this one's headers.
            server.resetLogHeaders(conn);
            conn.directions = .{ .{}, .{} };
            conn.state = .l7_reading_head;
            server.storeDeadline(conn, server.idleTimeoutMs());
            // Through `start` rather than straight to the group arm: a
            // terminated connection reads ciphertext into its engine and
            // never binds a ring buffer at all (§4), and the preconditions
            // `start` asserts are exactly what this function has just
            // re-established. Arming the bufferless recv unconditionally
            // is what made a TLS keep-alive's *second* request bind a ring
            // buffer the head path then ignored — found by the §9 sweep,
            // which reaches a second request where a directed test with one
            // `Connection: close` client never could.
            start(server, conn);
        }

        /// Whether an expired exchange can still be answered 504 (§8): no
        /// response byte sent, and no armed op held on the *client* socket
        /// — a client-side recv cannot be forced without closing the very
        /// client the verdict would answer, and a stalled request body is
        /// the client's own stall anyway. In the deferred-render window an
        /// origin response may already sit parsed but unsent; it is
        /// discarded — no byte of it reached the client, and the exchange
        /// it belonged to could not complete regardless.
        pub fn expiryAnswerable(conn: *const ConnType) bool {
            assert(conn.state == .l7_exchanging);
            if (conn.l7.response_started) {
                return false;
            }
            if (conn.armed.data_client_to_upstream and conn.l7.request_op_on_client) {
                return false;
            }
            return true;
        }

        /// Begin the §8 request-deadline verdict. Ops are never canceled
        /// (§5) — they are *forced*: shutting the upstream socket down
        /// makes each armed op on it complete with an error its handler
        /// diverts to `settlePendingVerdict`. In `.l7_exchanging` at least
        /// one data op is always armed (each leg holds its op while it
        /// waits), so the verdict always settles in a forced completion,
        /// never inline here.
        pub fn beginExpiry(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.pending_verdict == .none);
            assert(expiryAnswerable(conn));
            assert(conn.armed.data_client_to_upstream or
                conn.armed.data_upstream_to_client);
            conn.l7.pending_verdict = .gateway_timeout;
            server.io.shutdown(conn.upstream_socket.?, .both);
        }

        /// A completion landed with a verdict pending: once the last data
        /// op settles, act on it. The forced op's result — error or a
        /// racing data delivery already in flight — is deliberately
        /// ignored, the exchange is condemned either way; and because the
        /// divert runs before any error handling, a forced EPIPE never
        /// pollutes the kernel-pressure witness.
        fn settlePendingVerdict(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.pending_verdict != .none);
            if (conn.armed.data_client_to_upstream or
                conn.armed.data_upstream_to_client)
            {
                return; // The sibling's forced completion re-enters here.
            }
            const verdict = conn.l7.pending_verdict;
            conn.l7.pending_verdict = .none;
            switch (verdict) {
                .none => unreachable,
                .gateway_timeout => respond(server, conn, 504, "l7_gateway_timeout"),
                .replay => beginReplay(server, conn),
            }
        }

        /// Whether a failed try may take the one free §7 replay: the
        /// connection was a checkout (only a *reused* connection's early
        /// failure is blamed on staleness — a fresh dial's failure is the
        /// origin's own), the replay is unspent, no response byte was
        /// received, and the request leg never entered the body pump — the
        /// whole try (head, and any body that arrived coalesced with it)
        /// then still sits intact in conn.head, byte-for-byte
        /// reconstructible. Once relay-buffer chunks flowed they were
        /// overwritten and the origin may have consumed them: no replay.
        /// This covers the dominant real case — a GET whose head send
        /// landed in the kernel buffer while the parked origin's FIN was
        /// already in flight, surfacing as EOF at the response recv with
        /// the request leg already done.
        fn replayEligible(conn: *const ConnType) bool {
            assert(conn.state == .l7_exchanging);
            if (!conn.l7.upstream_was_reused) {
                return false;
            }
            if (conn.l7.replay_used) {
                return false;
            }
            if (conn.l7.response_started) {
                return false;
            }
            if (conn.upstream.?.head_len != 0) {
                return false; // A response byte arrived: the origin spoke.
            }
            if (conn.l7.request_body_pumped) {
                return false; // Relay chunks flowed; not reconstructible.
            }
            assert(conn.l7.request_leg != .idle);
            assert(conn.l7.request_leg != .pumping_body); // Implied by the flag.
            return true;
        }

        /// Take the one free replay: dispose the stale connection and run
        /// the fresh-dial try from the same client bytes. The verdict is
        /// already cleared; the caller (settle) proved both data ops free.
        fn beginReplay(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.pending_verdict == .none);
            assert(conn.l7.replay_used); // Spent before the try began.
            // A replay always precedes any #181 retry, never follows one:
            // it needs a *reused* checkout, and a retry only ever dials
            // fresh. So the rebuild below defaulting the tried set to
            // empty is the truth, not a reset.
            assert(conn.l7.tried_count == 0);
            assert(!conn.armed.data_client_to_upstream);
            assert(!conn.armed.data_upstream_to_client);
            assert(!conn.l7.response_started);
            assert(conn.relay_buffer != null); // Retained across the replay.
            const stale = conn.upstream.?;
            assert(stale.head_len == 0);
            server.io.closeNow(conn.upstream_socket.?);
            server.releaseUpstream(stale);
            conn.upstream = null;
            conn.upstream_socket = null;
            server.counters.increment("upstream_replayed");
            // Rebuild the per-try state from the §7 source of truth — the
            // client's bytes, intact in conn.head (the eligible legs sent
            // only from it). The same bytes parsed at routing, so this
            // cannot fail; the framing tracker MUST re-derive from the
            // parse — the coalesced excess was already fed once and will
            // be fed again on the fresh try.
            var storage: parser.HeaderStorage = undefined;
            const request = parser.parseRequestHead(
                headBytes(server, conn)[0..conn.head_len],
                false,
                &storage,
            ) catch unreachable;
            assert(request.head_len == conn.l7.request_head_len);
            conn.l7 = .{
                .request_method = conn.l7.request_method,
                .request_framing = framingFromParsed(request.framing),
                .request_head_len = conn.l7.request_head_len,
                .client_keep_alive = conn.l7.client_keep_alive,
                .replay_used = true,
                // The §8 cap rides across too: a replay is the *same*
                // client-visible request taking its one free retry, not a
                // new exchange, so it must not win itself a fresh budget.
                // Dropping it here would silently uncap the rest of the
                // exchange, since `storeDeadline` stops clamping at zero.
                .request_deadline_ns = conn.l7.request_deadline_ns,
                // upstream_was_reused stays default-false: the replay try
                // is a fresh dial, and a second early failure answers 502.
            };
            conn.directions = .{ .{}, .{} };
            // A fresh pick and a fresh dial — never another checkout (§7):
            // the endpoint's whole idle list may be stale the same way.
            //
            // The replay is a fresh try against the same cluster, so it
            // meets the same §8 cap; its budget is already spent (§7), so
            // a cap hit here answers rather than replaying again — and
            // the same request key (#178), re-derived from the re-parse
            // exactly like the framing: same bytes, same key.
            const request_key = requestKeyFor(server, conn, &request);
            conn.l7.sticky_cookie = switch (request_key) {
                .endpoint => |identity| identity,
                else => null,
            };
            const pick = pickEndpointOrShed(server, conn, request_key) orelse return;
            dialUpstream(server, conn, pick, .fresh);
        }

        /// The upstream leg failed. A stale checkout takes its one free
        /// replay (§7); otherwise answer 502 only when the client has
        /// seen no response byte and both data ops are free — the static
        /// response and its lingering drain need them, and ops are never
        /// canceled (§5). Otherwise the only honest outcome is teardown: a
        /// half-sent response cannot be repaired, and an armed op holds the
        /// completion the answer would need.
        fn upstreamFailed(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.pending_verdict == .none); // Handlers divert first.
            if (replayEligible(conn)) {
                conn.l7.pending_verdict = .replay;
                conn.l7.replay_used = true; // Spent now: a loop is impossible.
                // Force the sibling op, if armed (the response recv during
                // an excess send); settle acts immediately when both are
                // already free (the head-send failure case).
                server.io.shutdown(conn.upstream_socket.?, .both);
                settlePendingVerdict(server, conn);
                return;
            }
            if (conn.l7.response_started or conn.armed.data_client_to_upstream or
                conn.armed.data_upstream_to_client)
            {
                server.beginTeardown(conn);
                return;
            }
            respond(server, conn, 502, "l7_bad_gateway");
        }

        /// Whether a static response can be followed by the *next* request
        /// on this connection instead of the lingering close — the keep
        /// half of §8's "static 503 … then keep or close per pressure".
        ///
        /// It is a question about the client's byte stream, not about the
        /// status: the connection may keep serving only when the stream
        /// sits exactly on a message boundary. Three conditions, each
        /// ruling out a way it might not:
        ///
        ///   - the request declares no body left to read. A declared body
        ///     is unread bytes still to come; draining it is what the
        ///     lingering close is for.
        ///   - the client sent nothing past the head. Trailing bytes are a
        ///     pipelined next request, which §7 does not serve — and
        ///     leaving them buffered to be read as the *start* of the next
        ///     request is the desynchronization §7 exists to prevent.
        ///
        /// Reading `.l7_reading_head` keeps every mid-exchange caller
        /// (502, 504, the post-edit 431, the malformed-body 400) on the
        /// close path: by then a request head has gone to the origin and
        /// the two streams are no longer alignable.
        ///
        /// A head that never parsed — the 400/414/431 rejects, which answer
        /// bytes the parser could not frame — needs no test of its own:
        /// `request_head_len` is still 0 there while `head_len` is at least
        /// the byte that triggered the parse, so the boundary check below
        /// already refuses it. That is asserted rather than re-tested,
        /// because a second guard for it would be a branch no input can
        /// reach and no test can pin. `recordRequestFacts` is what makes
        /// that marker trustworthy: it runs for every valid head and only
        /// for a valid head.
        fn staticResponseResyncable(conn: *const ConnType) bool {
            if (conn.state != .l7_reading_head) return false;
            // `fillHead` never appends zero bytes and every reject from
            // this state follows a fill, so an unparsed head cannot tie
            // with `request_head_len`'s zero.
            assert(conn.head_len >= 1);
            assert(conn.l7.request_head_len <= conn.head_len);
            if (!framingDoneOf(&conn.l7.request_framing)) return false;
            return conn.head_len == conn.l7.request_head_len;
        }

        /// Everything a static response no longer needs, returned before
        /// the answer goes out rather than at teardown (§5, §8).
        ///
        /// The relay buffer: the response comes from static memory and the
        /// lingering drain discards into the shared sink, so a reject or
        /// 503 storm holding buffers for the whole drain window would pin
        /// the L4 admissions those buffers gate. The upstream slot: a still-attached one — a
        /// failed dial with no socket, an oversize-after-edit reject, a
        /// malformed body — would otherwise ride the same window. Both
        /// data ops are free at every caller, so nothing is armed on the
        /// upstream socket and the close is synchronous, like `detach`.
        fn releaseForStaticResponse(server: *ServerType, conn: *ConnType) void {
            assert(!conn.armed.data_client_to_upstream);
            assert(!conn.armed.data_upstream_to_client);
            // The head buffer too: the answer is static memory and the
            // lingering drain discards into the shared sink, so nothing
            // past this point reads or writes head bytes — and a reject
            // storm holding ring buffers for its drain windows would
            // starve the very requests the 503s are protecting. Conditional
            // because the NoBuffers rung answers without ever holding one.
            // `head_len` deliberately survives the return: it is a count,
            // not buffer content, and the §7 resync rule still reads it to
            // decide keep-or-close; `beginNextRequest` zeroes it.
            if (conn.head_buffer_id != ConnType.head_buffer_none) {
                server.returnHeadBuffer(conn);
            }
            if (conn.relay_buffer) |buffer| {
                server.releaseRelayBuffer(buffer);
                conn.relay_buffer = null;
            }
            // The tunnel this request asked for and did not get (#180).
            // A live tunnel never reaches here — it answers no static
            // response — so this is always an unspent claim.
            assert(conn.state != .relaying);
            releaseTunnelClaim(server, conn);
            if (conn.upstream) |leased| {
                if (conn.upstream_socket) |socket| {
                    server.io.closeNow(socket);
                }
                server.releaseUpstream(leased);
                conn.upstream = null;
                conn.upstream_socket = null;
            }
            assert(conn.relay_buffer == null);
            assert(conn.upstream == null);
            assert(conn.upstream_socket == null);
        }

        /// Undo an unspent tunnel claim (#180): the gate takes a buffer
        /// before the handshake is forwarded, and every ending other than
        /// the origin's `101` has to give it back.
        ///
        /// One chokepoint because the claim outlives `conn.l7`. The
        /// per-exchange state resets at every keep-alive turnaround, but
        /// this lives on the connection, so a path that forgot would pin a
        /// pool slot no session is using for as long as the client stays —
        /// and the next `Upgrade` on that connection would meet a claim
        /// already held. A no-op when nothing is claimed, so callers do
        /// not each re-test it.
        fn releaseTunnelClaim(server: *ServerType, conn: *ConnType) void {
            const buffer = conn.tunnel_buffer orelse return;
            assert(conn.relay_buffer != buffer); // Not yet swapped in: no live tunnel here.
            server.releaseTunnelBuffer(buffer);
            conn.tunnel_buffer = null;
        }

        /// Answer a comptime static error response, then keep the
        /// connection or close it (§8). Legal from head reading (rejects),
        /// dialing (502), and the exchange (upstream failures) — every
        /// caller guarantees both data ops are free, because the send and
        /// the lingering drain need them.
        fn respond(
            server: *ServerType,
            conn: *ConnType,
            comptime status: u16,
            comptime counter: []const u8,
        ) void {
            assert(conn.state == .l7_reading_head or conn.state == .l7_dialing or
                conn.state == .l7_exchanging);
            assert(!conn.armed.data_client_to_upstream);
            assert(!conn.armed.data_upstream_to_client);
            assert(!conn.l7.response_started);
            releaseForStaticResponse(server, conn);
            // A rung committed to an answer: retire the §8 request deadline
            // so it cannot expire the connection out from under the write
            // that delivers it (`clearRequestDeadline` owns the rule).
            // Retiring the *cap* is only half of it — `conn.deadline_ns` is
            // still standing wherever the cap clamped it, and the armed
            // timer is still aimed there, so widen it back to the idle
            // budget that owns a slow-reading client. No arm: whatever
            // timer is already out re-arms itself for the remainder once it
            // sees the later target (§4's lazy tick-and-compare).
            ServerType.clearRequestDeadline(conn);
            server.storeDeadline(conn, server.idleTimeoutMs());
            server.counters.increment(counter);
            // What the line will say, recorded here where the verdict is
            // made; it is written once the response is on the wire, so the
            // byte count includes the answer itself (§8).
            conn.log.status = status;
            conn.log.outcome = comptime outcomeOfCounter(counter);
            // §8's "then keep or close per pressure". Closing is not free:
            // it costs the client a fresh handshake and this proxy a fresh
            // accept, conn slot and admission — which is how a shed storm
            // becomes *more* expensive per request than the work it is
            // shedding, and how a transient overshoot locks itself in as a
            // reconnect loop. Keeping is one send.
            //
            // The same three brakes the render-time persistence decision
            // honors apply here (§7, §8): the client's own ask, the drain,
            // and relay pressure — a proxy shedding buffers should not also
            // be holding connections open for their next request.
            // The head-shed rung can never keep, structurally: nothing was
            // read (the ring was empty, so no buffer was ever bound), the
            // request's bytes wait unread in the socket, and a kept
            // connection would re-arm onto those same bytes and shed them
            // forever. Comptime, so the resync rule — whose asserts require
            // at least one byte read — is never consulted on that rung.
            const may_keep = comptime !std.mem.eql(u8, counter, "l7_shed_head_buffers");
            const keep = may_keep and staticResponseResyncable(conn) and
                conn.l7.client_keep_alive and
                !server.draining and
                !server.keepAliveSuppressed();
            conn.state = .l7_responding;
            armStaticAnswer(server, conn, status, keep);
        }

        /// Send one static answer: the #159 configured page for this
        /// status when the config carries one, the comptime-rendered
        /// default otherwise — both straight from immutable memory (§8):
        /// the channel carries the slice and never copies it, so a shed
        /// still costs one send. The persistence choice is the caller's
        /// and must match what happens after the send — an announced
        /// close that kept serving, or a kept connection the client was
        /// told to stop using, are both §7 violations. A HEAD request
        /// gets a configured page's head-only prefix (same buffer, same
        /// framing headers, RFC 9110's HEAD rule); the defaults carry
        /// `Content-Length: 0`, where whole and prefix are one slice.
        ///
        /// The method is only *known* where a head parsed. On the rungs
        /// that answer without one — the head-buffer shed (nothing was
        /// ever read), a malformed head, an oversize URI — the method
        /// reads as the reset default and an actual `HEAD` would be sent
        /// a body it must not read. That cannot desync anything, and the
        /// assert below is why: an unparsed head leaves
        /// `request_head_len` at zero, `staticResponseResyncable`
        /// refuses to keep on that, and a closing connection has no next
        /// response for stray bytes to be mistaken for — the client
        /// discards them with the FIN.
        fn armStaticAnswer(
            server: *ServerType,
            conn: *ConnType,
            comptime status: u16,
            keep: bool,
        ) void {
            assert(conn.state == .l7_responding);
            assert(!conn.l7.response_started);
            // Keeping implies the head parsed (§7 resync), which is what
            // makes the HEAD decision below sound wherever it matters.
            if (keep) {
                assert(conn.l7.request_head_len >= 1);
            }
            if (configuredPage(server, status)) |page| {
                return armPageWrite(server, conn, page, keep);
            }
            if (keep) {
                armClientWrite(server, conn, shed.staticResponse(status, .keep), .next_request);
            } else {
                armClientWrite(server, conn, shed.staticResponse(status, .close), .lingering_close);
            }
        }

        /// Send one pre-rendered #159 page: the persistence variant the
        /// caller decided, whole for a GET and head-only for a HEAD —
        /// the prefix of that same buffer, so the framing headers still
        /// describe what a GET would have carried (RFC 9110) and the
        /// send count is unchanged. Shared by the configured statics
        /// and the `respond` action, so the two cannot drift on the
        /// HEAD rule or on the continuation.
        fn armPageWrite(
            server: *ServerType,
            conn: *ConnType,
            page: *const config_module.Config.StaticPage,
            keep: bool,
        ) void {
            assert(conn.state == .l7_responding);
            assert(page.keep_head_len <= page.keep.len);
            assert(page.close_head_len <= page.close.len);
            const head_only = conn.l7.request_method == .head;
            const bytes = if (keep)
                (if (head_only) page.keep[0..page.keep_head_len] else page.keep)
            else
                (if (head_only) page.close[0..page.close_head_len] else page.close);
            assert(bytes.len >= 1);
            const then: conn_module.ClientWrite.Then =
                if (keep) .next_request else .lingering_close;
            armClientWrite(server, conn, bytes, then);
        }

        /// Answer a matched `respond` action from its configured body
        /// (#159): this proxy as the origin, not a refusal. Reached
        /// from routing like the other terminal verdicts, so nothing is
        /// acquired yet and the answer is the static path's one send.
        fn respondWithPage(
            server: *ServerType,
            conn: *ConnType,
            page: *const config_module.Config.StaticPage,
        ) void {
            assert(conn.state == .l7_reading_head);
            // `respond`'s own contract: both data ops free, so the send
            // and any lingering drain have their completions.
            assert(!conn.armed.data_client_to_upstream);
            assert(!conn.armed.data_upstream_to_client);
            assert(!conn.l7.response_started);
            // A terminal verdict runs before routing acquires anything,
            // which is what keeps it clear of every rung past the head
            // ring (the redirect's precondition, same phase).
            assert(conn.relay_buffer == null);
            assert(conn.upstream == null);
            // The page is immutable arena memory, never the connection's
            // head buffer — so this answer releases before the send like
            // every other static one, rather than holding through it the
            // way the #176 redirect must (it renders into that buffer).
            // The continuations below are the plain static pair for the
            // same reason, and they assert the buffer is already gone.
            releaseForStaticResponse(server, conn);
            ServerType.clearRequestDeadline(conn);
            server.storeDeadline(conn, server.idleTimeoutMs());
            server.counters.increment("l7_responded");
            conn.log.status = page.status;
            conn.log.outcome = .responded;
            // The same three brakes every static answer honors (§7, §8):
            // the client's own ask, the drain, and relay pressure.
            const keep = staticResponseResyncable(conn) and
                conn.l7.client_keep_alive and
                !server.draining and
                !server.keepAliveSuppressed();
            conn.state = .l7_responding;
            armPageWrite(server, conn, page, keep);
        }

        /// The #159 page configured for `status`, or null for the
        /// comptime default. A linear scan: the table is bounded by the
        /// closed static-status set (ten), and this runs only on the
        /// verdict paths — never per proxied byte.
        fn configuredPage(server: *const ServerType, status: u16) ?*const config_module.Config.StaticPage {
            for (server.config.error_pages) |page| {
                assert(page.keep_head_len <= page.keep.len);
                assert(page.close_head_len <= page.close.len);
                if (page.status == status) {
                    return page;
                }
            }
            return null;
        }

        /// The #176 Location for a redirect verdict. A literal target is
        /// the config's own arena slice; a composed one is built in the
        /// rewrite scratch — free at routing time, and consumed before
        /// this frame returns, the same single-threaded no-suspend
        /// argument the canonicalization scratches make (§7) — from the
        /// configured scheme, the replacement or request host, and the
        /// request's canonical path with its verbatim query.
        fn composeLocation(
            server: *ServerType,
            redirect: *const filter.Redirect,
            request_host: ?[]const u8,
            forward: parser.CanonicalTarget,
        ) error{ Oversize, NoHost }![]const u8 {
            assert(filter.isRedirectStatus(redirect.status));
            switch (redirect.target) {
                .location => |literal| {
                    assert(literal.len >= 1); // Config rejects an empty literal.
                    return literal;
                },
                .composed => |composed| {
                    const host = composed.host orelse request_host orelse {
                        // No replacement host and the request carried no
                        // usable authority: there is nothing to compose
                        // the target from.
                        return error.NoHost;
                    };
                    assert(host.len >= 1);
                    const scheme = composed.scheme.prefix();
                    const out = server.rewrite_scratch;
                    const total = scheme.len + host.len + forward.path.len + forward.query.len;
                    if (total > out.len) {
                        return error.Oversize;
                    }
                    var cursor: usize = 0;
                    @memcpy(out[cursor..][0..scheme.len], scheme);
                    cursor += scheme.len;
                    @memcpy(out[cursor..][0..host.len], host);
                    cursor += host.len;
                    @memcpy(out[cursor..][0..forward.path.len], forward.path);
                    cursor += forward.path.len;
                    @memcpy(out[cursor..][0..forward.query.len], forward.query);
                    cursor += forward.query.len;
                    assert(cursor == total);
                    return out[0..total];
                },
            }
        }

        /// Answer a #176 redirect verdict. `respond`'s discipline with
        /// one structural difference: the bytes cannot come from static
        /// memory — the Location may carry the request's own path — so
        /// the response is rendered into the connection's head buffer,
        /// whose request bytes are done being read once the Location is
        /// composed (into the rewrite scratch, never aliasing what it
        /// copies). The buffer is therefore *held* through the send,
        /// unlike a static answer, and returned by the redirect write
        /// continuations before the connection resumes or drains.
        fn respondRedirect(
            server: *ServerType,
            conn: *ConnType,
            redirect: *const filter.Redirect,
            request_host: ?[]const u8,
            forward: parser.CanonicalTarget,
        ) void {
            assert(conn.state == .l7_reading_head);
            // The same contract `respond` states: both data ops free, so
            // the send and any lingering drain have their completions.
            assert(!conn.armed.data_client_to_upstream);
            assert(!conn.armed.data_upstream_to_client);
            assert(!conn.l7.response_started);
            // Routing has acquired nothing yet: a redirect never touches
            // the relay or upstream pools, which is what keeps it out of
            // every shed rung past the head ring.
            assert(conn.relay_buffer == null);
            assert(conn.upstream == null);
            const location = composeLocation(server, redirect, request_host, forward) catch |err|
                switch (err) {
                    // The request's own target made the Location too long
                    // to carry: the URI's fault, the URI's status.
                    error.Oversize => return respond(server, conn, 414, "l7_uri_too_long"),
                    // A composed target with no authority to compose from
                    // (HTTP/1.0 without Host): the request lacks what the
                    // answer requires.
                    error.NoHost => return respond(server, conn, 400, "l7_bad_request"),
                };
            // The same three brakes `respond` honors, decided before the
            // render because the close is announced inside it (§7).
            const keep = staticResponseResyncable(conn) and
                conn.l7.client_keep_alive and
                !server.draining and
                !server.keepAliveSuppressed();
            const rendered = render.renderRedirectHead(
                redirect.status,
                location,
                !keep,
                headBytes(server, conn),
            ) catch {
                // The Location fit the scratch but head + Location does
                // not fit the buffer: same fault, same status.
                return respond(server, conn, 414, "l7_uri_too_long");
            };
            ServerType.clearRequestDeadline(conn);
            server.storeDeadline(conn, server.idleTimeoutMs());
            server.counters.increment("l7_redirected");
            conn.log.status = redirect.status;
            conn.log.outcome = .redirected;
            conn.state = .l7_responding;
            if (keep) {
                armClientWrite(server, conn, rendered, .redirect_next_request);
            } else {
                armClientWrite(server, conn, rendered, .redirect_lingering_close);
            }
        }

        /// The access-log outcome a `respond` rung reports (§8), keyed off
        /// the counter it already names so the two cannot drift: a rung
        /// that grows a counter must place it here or fail to compile.
        ///
        /// The split is the one an operator acts on, not the one HTTP's
        /// status classes make. `503` covers both a resource wall and,
        /// from an origin, a perfectly ordinary answer; `502` and `504`
        /// each name a distinct failure of the upstream leg; everything
        /// else in the list is this proxy refusing the request on its own
        /// terms. Reading those apart from the status alone is impossible,
        /// which is why `outcome` exists at all.
        fn outcomeOfCounter(comptime counter: []const u8) access_log.Outcome {
            const rejects = [_][]const u8{
                "l7_bad_request",
                "l7_uri_too_long",
                "l7_headers_too_large",
                // A rejection like its 431 sibling, and for the same
                // reason: the client sent more than this proxy accepts.
                // Which of the two it earns is a question about the
                // parsed head, not about the outcome.
                "l7_body_too_large",
                "l7_not_implemented",
                "l7_no_route",
                "l7_filtered",
            };
            for (rejects) |name| {
                if (std.mem.eql(u8, counter, name)) return .rejected;
            }
            if (std.mem.eql(u8, counter, "l7_shed_relay_buffers")) return .shed;
            if (std.mem.eql(u8, counter, "l7_shed_upstream_slots")) return .shed;
            if (std.mem.eql(u8, counter, "l7_shed_head_buffers")) return .shed;
            if (std.mem.eql(u8, counter, "l7_shed_upstream_head_buffers")) return .shed;
            // A capped endpoint is a shed like any other from the
            // client's side: the request was refused to protect the
            // origin, and the line should read the same as the rungs
            // that refuse to protect this proxy (§8).
            if (std.mem.eql(u8, counter, "l7_shed_endpoint_inflight")) return .shed;
            // A refused tunnel reads to a client like any other shed
            // (#180): admitted, answered, refused for a resource. Which
            // resource changes what an operator widens, not what the line
            // says happened.
            if (std.mem.eql(u8, counter, "l7_shed_tunnels")) return .shed;
            if (std.mem.eql(u8, counter, "l7_bad_gateway")) return .upstream_failed;
            if (std.mem.eql(u8, counter, "l7_gateway_timeout")) return .timed_out;
            @compileError("static-response counter with no access-log outcome: " ++ counter);
        }

        /// The static response is out and the stream is still synchronized:
        /// serve the next request on this connection (§7, §8). `respond`
        /// already released the relay buffer and any attached upstream, so
        /// this is `resetForNextRequest` minus the exchange it never had.
        fn resumeAfterStaticResponse(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_responding);
            assert(conn.client_write.pending.len == 0);
            // `respond` frees all three before the send, so a kept
            // connection carries nothing into its next request (§5).
            assert(conn.head_buffer_id == ConnType.head_buffer_none);
            assert(conn.relay_buffer == null);
            assert(conn.upstream == null);
            assert(conn.upstream_socket == null);
            assert(!conn.armed.data_client_to_upstream);
            assert(!conn.armed.data_upstream_to_client);
            // The same OR `resetForNextRequest` needs, for the same reason,
            // and it is not this request's doing: a *previous* request on
            // this connection may have dialed, re-based its deadline (§8),
            // and completed before the rebase's cancel drained. That
            // straggler survives `beginNextRequest` — which touches `l7` and
            // the state, never the armed bits — so the next request can be
            // rejected while `deadline` has already cleared and only
            // `deadline_cancel` is still outstanding. Either one
            // re-establishes the idle deadline (§4); requiring `deadline`
            // specifically would fire on ordinary keep-alive traffic.
            assert(conn.armed.deadline or conn.armed.deadline_cancel);
            beginNextRequest(server, conn);
        }

        /// A client can still be sending its request — a body, or the rest
        /// of an oversize head — when we answer an error. Closing then
        /// would RST and discard the response we just sent (§7). Instead
        /// half-close the write side (the client sees our response and
        /// FIN) and drain the client's remaining input to EOF before the
        /// teardown; the head-read deadline bounds a client that never
        /// stops sending.
        fn beginLingeringClose(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_responding);
            conn.state = .l7_draining_request;
            server.io.shutdown(conn.client_socket, .write);
            armDrainRecv(server, conn);
        }

        fn armDrainRecv(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_draining_request);
            // The head buffer went back to the ring with the rest of the
            // static response's holdings, so the discard lands in the
            // server's one shared sink — recv targets whose contents
            // nobody reads may alias, and a reject storm drains through
            // 4 KiB total instead of 8 KiB per draining connection (§5).
            assert(conn.head_buffer_id == ConnType.head_buffer_none);
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                server.drainSink(),
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onDrainRecv,
            );
        }

        fn onDrainRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_draining_request);
            _ = result catch |err| {
                // EOF or error: the client's inbound is drained, so the
                // close is a clean FIN, not a data-discarding RST. Kernel
                // pressure on the drain recv is still witnessed (§8) —
                // this op fires most during a reject storm under load.
                server.witnessKernelPressure(.recv, err);
                server.beginTeardown(conn);
                return;
            };
            // More bytes to discard; keep draining under the deadline.
            armDrainRecv(server, conn);
        }

        const FeedResult = pump.FeedResult;

        /// Advance a framing tracker over `bytes`, reporting how many of
        /// them belong to the message. Consumed < bytes.len means the
        /// message ended mid-chunk; the rest is pipelined data, dropped
        /// while every exchange closes its connection.
        fn feedFraming(framing: *Framing, bytes: []const u8) FeedResult {
            assert(bytes.len <= constants.head_buffer_bytes_max);
            switch (framing.*) {
                .none => return .{ .consumed = 0, .done = true, .malformed = false },
                .content_length => |*remaining| {
                    const consumed: u32 = @intCast(@min(remaining.*, bytes.len));
                    remaining.* -= consumed;
                    return .{
                        .consumed = consumed,
                        .done = remaining.* == 0,
                        .malformed = false,
                    };
                },
                .chunked => |*scanner| {
                    if (bytes.len == 0) {
                        return .{ .consumed = 0, .done = false, .malformed = false };
                    }
                    const progress = scanner.feed(bytes) catch {
                        return .{ .consumed = 0, .done = false, .malformed = true };
                    };
                    return .{
                        .consumed = progress.consumed,
                        .done = progress.done,
                        .malformed = false,
                    };
                },
                .until_close => return .{
                    .consumed = @intCast(bytes.len),
                    .done = false,
                    .malformed = false,
                },
            }
        }

        fn framingDoneOf(framing: *const Framing) bool {
            return switch (framing.*) {
                .none => true,
                .content_length => |remaining| remaining == 0,
                .chunked => |scanner| scanner.state == .done,
                .until_close => false,
            };
        }

        fn framingFromParsed(parsed: parser.BodyFraming) Framing {
            return switch (parsed) {
                .none => .none,
                .content_length => |length| .{ .content_length = length },
                .chunked => .{ .chunked = .{} },
                .until_close => .until_close,
            };
        }
    };
}

test "forwarded: an address renders bare — no port, no brackets" {
    // The value must be a plain X-Forwarded-For list element. A port would
    // make it one no reader parses; brackets are IPv6-with-port syntax and
    // have no meaning once the port is gone.
    var scratch: [constants.forwarded_client_bytes_max]u8 = undefined;
    const cases = [_]struct { literal: []const u8, bare: []const u8 }{
        .{ .literal = "203.0.113.9:51000", .bare = "203.0.113.9" },
        .{ .literal = "10.0.0.1:1", .bare = "10.0.0.1" },
        // Compression is std's, not a second implementation of it.
        .{ .literal = "[2001:db8::1]:443", .bare = "2001:db8::1" },
        .{ .literal = "[::1]:80", .bare = "::1" },
        // The widest form the scratch has to hold.
        .{
            .literal = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
            .bare = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        },
    };
    for (cases) |case| {
        const address = try std.Io.net.IpAddress.parseLiteral(case.literal);
        try std.testing.expectEqualStrings(case.bare, bareAddress(&address, &scratch));
    }
}
