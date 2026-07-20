//! The L7 HTTP/1.1 reverse-proxy state machine (DESIGN.md §7). Generic
//! over the Io backend and driven by the Server's helpers (pools,
//! counters, deadline, teardown), exactly as `net/relay.zig` drives the
//! L4 path — L7 lives here, never inlined into the L4 relay.
//!
//! Lifecycle: `l7_reading_head` accumulates the request head and
//! re-parses from byte 0 on each recv (§7 detect-and-retry); verdicts
//! answer comptime static responses (§8) with a lingering close (§2). A
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
//! honors what its rendered response announced (§2), going idle at the
//! cost of a slot + head buffer only (§5). Pipelining is unsupported
//! (first response, then an announced close); the stale-checkout free
//! replay and the §8 504 deadline verdict are Phase 2 (docs/PLANS.md).
//!
//! Buffer ownership rotates, never overlaps: conn.head holds the request
//! head until it is rendered, then stages the rendered response head;
//! upstream.head stages the rendered request head, then accumulates the
//! response head; the relay-buffer halves carry only framed body bytes
//! (head-adjacent excess is copied across once at each pump start).

const std = @import("std");

const constants = @import("../constants.zig");
const conn_module = @import("../net/Conn.zig");
const Io = @import("../io/io.zig");
const parser = @import("parser.zig");
const render = @import("render.zig");
const router = @import("router.zig");
const filter = @import("filter.zig");
const shed = @import("../shed.zig");

const assert = std.debug.assert;

pub fn Proxy(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);
    const ConnType = conn_module.Conn(IoType);
    const Framing = ConnType.Framing;

    return struct {
        /// Entry from admission: the slot is prepared in `.l7_reading_head`
        /// with the head-read deadline armed; begin reading the request
        /// head from the client.
        pub fn start(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_reading_head);
            assert(conn.head_len == 0);
            armHeadRecv(server, conn);
        }

        fn armHeadRecv(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_reading_head);
            // Parsing turns a full buffer into an oversize verdict before
            // we ever get here, so there is always room to read into.
            assert(conn.head_len < constants.head_bytes_max);
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                conn.head[conn.head_len..],
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onHeadRecv,
            );
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
                // A client that closes or resets before finishing its head
                // simply leaves — there is nothing to answer. The §7
                // head-read deadline handles the slowloris that stalls
                // instead of closing. The witness filters internally: only
                // Unexpected (kernel pressure) is counted, so orderly
                // EndOfStream/Reset pass through it uncounted.
                server.witnessKernelPressure(err);
                server.beginTeardown(conn);
                return;
            };
            assert(received >= 1);
            conn.head_len += received;
            assert(conn.head_len <= constants.head_bytes_max);
            parseAndDispatch(server, conn);
        }

        /// Re-parse the accumulated head from byte 0 (§7). Incomplete and
        /// room left → read more; oversize or malformed → the matching
        /// static reject; a valid head → routing.
        fn parseAndDispatch(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_reading_head);
            const head = conn.head[0..conn.head_len];
            const head_is_full = conn.head_len == constants.head_bytes_max;

            var storage: parser.HeaderStorage = undefined;
            const request = parser.parseRequestHead(head, head_is_full, &storage) catch |err| switch (err) {
                error.Incomplete => {
                    // A full buffer never yields Incomplete — the parser
                    // converts it to the oversize verdicts below — so here
                    // there is room to read more.
                    assert(!head_is_full);
                    armHeadRecv(server, conn);
                    return;
                },
                error.Malformed => return respond(server, conn, 400, "l7_bad_request"),
                error.UriTooLong => return respond(server, conn, 414, "l7_uri_too_long"),
                error.HeadTooLarge => return respond(server, conn, 431, "l7_headers_too_large"),
            };
            routeRequest(server, conn, &request);
        }

        /// The §7 canonical routing keys for `request`: the canonical host
        /// (null when absent/unmatchable → any-host routes only) and the
        /// canonical path — or "/" for OPTIONS asterisk-form, which names
        /// the whole server. A target that will not canonicalize is
        /// BadPath (400). One canonical view, shared by both filter
        /// matching and routing, so they never disagree.
        const RequestKeys = struct { host: ?[]const u8, path: []const u8 };

        fn requestKeys(
            request: *const parser.RequestHead,
            scratch: *[constants.head_bytes_max]u8,
            host_scratch: *[constants.host_bytes_max]u8,
        ) error{BadPath}!RequestKeys {
            assert(request.target.len >= 1);
            const host: ?[]const u8 = if (request.host) |raw|
                parser.canonicalHost(raw, host_scratch)
            else
                null;
            if (request.target[0] != '/') {
                // validateTarget admitted only asterisk-form here.
                assert(request.method == .options);
                return .{ .host = host, .path = "/" };
            }
            const canonical = parser.canonicalTarget(request.target, scratch) catch {
                return error.BadPath;
            };
            return .{ .host = host, .path = canonical.path };
        }

        /// Answer a §7 filter reject with its runtime policy status — each
        /// a closed-set static response, all counted as one filter reject.
        fn respondFilter(server: *ServerType, conn: *ConnType, status: u16) void {
            assert(filter.isRejectStatus(status));
            switch (status) {
                400 => respond(server, conn, 400, "l7_filtered"),
                403 => respond(server, conn, 403, "l7_filtered"),
                404 => respond(server, conn, 404, "l7_filtered"),
                429 => respond(server, conn, 429, "l7_filtered"),
                else => unreachable,
            }
        }

        /// The canonical bytes to forward for `request` (§7): origin-form
        /// canonicalizes, OPTIONS asterisk-form passes through. routeRequest
        /// already proved canonicalization succeeds, so this cannot fail —
        /// the same bytes are the single source of truth.
        fn effectiveTarget(
            request: *const parser.RequestHead,
            scratch: *[constants.head_bytes_max]u8,
        ) parser.CanonicalTarget {
            assert(request.target.len >= 1);
            if (request.target[0] != '/') {
                return .{ .path = request.target, .query = "" };
            }
            return parser.canonicalTarget(request.target, scratch) catch unreachable;
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
            base: parser.CanonicalTarget,
            host_scratch: *[constants.host_bytes_max]u8,
            rewrite_scratch: *[constants.head_bytes_max]u8,
            edit_buffer: *[constants.header_edits_max]filter.AppliedHeaderEdit,
        ) error{Oversize}!Forwarded {
            assert(base.path.len >= 1);
            if (conn.filters.len == 0) {
                return .{ .target = base, .edits = &.{} };
            }
            const host: ?[]const u8 = if (request.host) |raw|
                parser.canonicalHost(raw, host_scratch)
            else
                null;
            const origin_form = request.target[0] == '/';
            const match_path: []const u8 = if (origin_form) base.path else "/";
            assert(match_path.len >= 1);
            assert(match_path[0] == '/');
            const view = filter.RequestView{
                .method = request.method,
                .host = host,
                .path = match_path,
                .headers = request.headers,
            };
            // Rewrite only origin-form targets; asterisk-form names no path.
            var target = base;
            if (origin_form) {
                if (filter.firstRewrite(conn.filters, view)) |rewrite| {
                    target.path = try filter.rewritePath(rewrite, base.path, rewrite_scratch);
                }
            }
            const edits = filter.collectHeaderEdits(conn.filters, view, edit_buffer);
            return .{ .target = target, .edits = edits };
        }

        /// Policy gate, then the exchange's admission: tunnels and
        /// upgrades are non-goals (§1, §7) — 501; the canonical path
        /// selects a cluster (400 if it will not canonicalize, 404 if no
        /// route matches, §7/§8); a routable request then claims its
        /// relay buffer and upstream slot (§8 rungs, 503) and dials.
        fn routeRequest(server: *ServerType, conn: *ConnType, request: *const parser.RequestHead) void {
            assert(conn.state == .l7_reading_head);
            assert(request.head_len <= conn.head_len);
            if (request.method == .connect) {
                return respond(server, conn, 501, "l7_not_implemented");
            }
            if (parser.headerValue(request.headers, "upgrade") != null) {
                return respond(server, conn, 501, "l7_not_implemented");
            }

            // §7: canonicalize the host and path once, then apply filters
            // and routing to that one view before acquiring any resource,
            // so a bad path, a policy reject, or an unrouted host/path is
            // answered cheaply.
            var scratch: [constants.head_bytes_max]u8 = undefined;
            var host_scratch: [constants.host_bytes_max]u8 = undefined;
            const keys = requestKeys(request, &scratch, &host_scratch) catch {
                return respond(server, conn, 400, "l7_bad_request");
            };
            // §7 filters run before routing: a policy reject stops the
            // request whether or not it would have routed.
            if (filter.firstReject(conn.filters, .{
                .method = request.method,
                .host = keys.host,
                .path = keys.path,
                .headers = request.headers,
            })) |status| {
                return respondFilter(server, conn, status);
            }
            conn.cluster_index = router.route(conn.routes, keys.host, keys.path) orelse {
                return respond(server, conn, 404, "l7_no_route");
            };

            conn.relay_buffer = server.acquireRelayBuffer() orelse {
                return respond(server, conn, 503, "l7_shed_relay_buffers");
            };
            conn.l7.request_method = request.method;
            conn.l7.request_framing = framingFromParsed(request.framing);
            conn.l7.request_head_len = request.head_len;
            conn.l7.client_keep_alive = request.keep_alive;

            // The §3 reuse win: a parked connection to the picked endpoint
            // beats a fresh dial. A close that slipped through while it
            // was parked surfaces as a failure on first use — answered
            // 502 until Phase 2's free replay (docs/PLANS.md).
            const pick = server.balancer.pick(conn.cluster_index);
            if (server.upstreams.checkout(conn.cluster_index, pick.endpoint_index)) |parked| {
                server.counters.increment("upstream_reused");
                conn.upstream = parked;
                conn.upstream_socket = parked.socket;
                parked.head_len = 0;
                conn.state = .l7_dialing;
                // No await happened: this runs in the same callback as the
                // parse whose result is still live, so the reuse path —
                // the hot one — skips the re-parse the dial path needs.
                renderRequestAndStartLegs(server, conn, request);
                return;
            }
            conn.upstream = server.upstreams.acquire(conn.cluster_index, pick.endpoint_index) orelse {
                return respond(server, conn, 503, "l7_shed_upstream_slots");
            };
            conn.state = .l7_dialing;
            server.storeDeadline(conn, server.config.connect_timeout_ms);
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
            const socket = result catch {
                server.counters.increment("upstream_connect_failed");
                respond(server, conn, 502, "l7_bad_gateway");
                return;
            };
            conn.upstream.?.socket = socket;
            conn.upstream_socket = socket;
            server.io.setNodelay(socket) catch {
                server.counters.increment("kernel_pressure_errors");
            };
            renderAndStartLegs(server, conn);
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
                conn.head[0..conn.head_len],
                false,
                &storage,
            ) catch unreachable;
            assert(request.head_len == conn.l7.request_head_len);
            renderRequestAndStartLegs(server, conn, &request);
        }

        /// Render the request head into the upstream slot's staging
        /// buffer and start both legs.
        fn renderRequestAndStartLegs(
            server: *ServerType,
            conn: *ConnType,
            request: *const parser.RequestHead,
        ) void {
            assert(conn.state == .l7_dialing);
            assert(request.head_len == conn.l7.request_head_len);
            const upstream = conn.upstream.?;
            // The §7 canonical target the router matched on is the base the
            // origin sees, unless a filter rewrites the forwarded path.
            var scratch: [constants.head_bytes_max]u8 = undefined;
            const base = effectiveTarget(request, &scratch);
            // Apply the listener's filters (empty when none): a rewrite of
            // the forwarded path and any header edits, against the same
            // canonical view the reject/route phase used.
            var host_scratch: [constants.host_bytes_max]u8 = undefined;
            var rewrite_scratch: [constants.head_bytes_max]u8 = undefined;
            var edit_buffer: [constants.header_edits_max]filter.AppliedHeaderEdit = undefined;
            const plan = planForward(
                conn,
                request,
                base,
                &host_scratch,
                &rewrite_scratch,
                &edit_buffer,
            ) catch {
                // A rewritten path too long to forward: the §7 oversize
                // verdict, answered like an oversize head.
                return respond(server, conn, 431, "l7_headers_too_large");
            };
            // No close announcement upstream: the connection is a parking
            // candidate (§5), and stripping the client's Connection header
            // already made persistence the wire default.
            const rendered = render.renderRequestHead(request, plan.target, plan.edits, false, &upstream.head) catch {
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

        fn armRequestHeadSend(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .sending_head);
            const l7 = &conn.l7;
            assert(l7.request_head_sent < l7.rendered_request_len);
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.send(
                conn.upstream_socket.?,
                conn.upstream.?.head[l7.request_head_sent..l7.rendered_request_len],
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
            const sent = result catch |err| {
                server.witnessKernelPressure(err);
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
            const excess = conn.head[conn.l7.request_head_len..conn.head_len];
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
            const excess = conn.head[conn.l7.request_head_len..conn.head_len];
            if (feed.consumed < excess.len) {
                conn.l7.client_pipelined = true;
            }
            const direction = &conn.directions[0];
            direction.transfer_len = feed.consumed;
            direction.sent_len = 0;
            conn.l7.request_leg = .sending_body_excess;
            if (feed.consumed >= 1) {
                armRequestExcessSend(server, conn);
            } else {
                requestHeadVacated(server, conn);
            }
        }

        fn armRequestExcessSend(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .sending_body_excess);
            const direction = &conn.directions[0];
            assert(direction.sent_len < direction.transfer_len);
            const base = conn.l7.request_head_len;
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.send(
                conn.upstream_socket.?,
                conn.head[base + direction.sent_len .. base + direction.transfer_len],
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
            const sent = result catch |err| {
                server.witnessKernelPressure(err);
                upstreamFailed(server, conn);
                return;
            };
            assert(sent >= 1);
            const direction = &conn.directions[0];
            direction.sent_len += sent;
            assert(direction.sent_len <= direction.transfer_len);
            if (direction.sent_len < direction.transfer_len) {
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
            if (framingDone(&conn.l7.request_framing)) {
                conn.l7.request_leg = .done;
            } else {
                conn.l7.request_leg = .pumping_body;
                armRequestBodyRecv(server, conn);
            }
        }

        fn armRequestBodyRecv(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .pumping_body);
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                &conn.relay_buffer.?.client_to_upstream,
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onRequestBodyRecv,
            );
        }

        fn onRequestBodyRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .pumping_body);
            const received = result catch |err| {
                // EOF mid-body is a truncated request; any failure here
                // dooms the exchange in the client's own direction.
                server.witnessKernelPressure(err);
                server.beginTeardown(conn);
                return;
            };
            assert(received >= 1);
            const chunk = conn.relay_buffer.?.client_to_upstream[0..received];
            const feed = feedFraming(&conn.l7.request_framing, chunk);
            if (feed.malformed) {
                server.beginTeardown(conn);
                return;
            }
            if (feed.consumed < received) {
                // Bytes past the body are a pipelined next request; the
                // connection will close after this exchange (§2 note).
                conn.l7.client_pipelined = true;
            }
            const direction = &conn.directions[0];
            direction.transfer_len = feed.consumed;
            direction.sent_len = 0;
            if (feed.consumed >= 1) {
                armRequestBodySend(server, conn);
            } else {
                assert(feed.done);
                conn.l7.request_leg = .done;
            }
        }

        fn armRequestBodySend(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            const direction = &conn.directions[0];
            assert(direction.sent_len < direction.transfer_len);
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.send(
                conn.upstream_socket.?,
                conn.relay_buffer.?.client_to_upstream[direction.sent_len..direction.transfer_len],
                &conn.op_data_client_to_upstream.completion,
                ConnType,
                conn,
                onRequestBodySent,
            );
        }

        fn onRequestBodySent(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .pumping_body);
            const sent = result catch |err| {
                server.witnessKernelPressure(err);
                upstreamFailed(server, conn);
                return;
            };
            assert(sent >= 1);
            const direction = &conn.directions[0];
            direction.sent_len += sent;
            assert(direction.sent_len <= direction.transfer_len);
            if (direction.sent_len < direction.transfer_len) {
                armRequestBodySend(server, conn);
                return;
            }
            // A full chunk moved: activity refreshes the deadline (§6).
            server.storeDeadline(conn, server.idleTimeoutMs());
            if (framingDone(&conn.l7.request_framing)) {
                conn.l7.request_leg = .done;
            } else {
                armRequestBodyRecv(server, conn);
            }
        }

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
            assert(upstream.head_len < constants.head_bytes_max);
            conn.arm(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.recv(
                conn.upstream_socket.?,
                upstream.head[upstream.head_len..],
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
            const received = result catch |err| {
                server.witnessKernelPressure(err);
                upstreamFailed(server, conn);
                return;
            };
            assert(received >= 1);
            const upstream = conn.upstream.?;
            upstream.head_len += received;
            assert(upstream.head_len <= constants.head_bytes_max);
            parseResponseAndDispatch(server, conn);
        }

        /// Detect-and-retry over the origin's head, mirroring the request
        /// side; any verdict other than "valid" or "more bytes" dooms the
        /// upstream leg (an origin is configured, not adversarial, but §7
        /// framing strictness applies to it all the same).
        fn parseResponseAndDispatch(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            const upstream = conn.upstream.?;
            const head = upstream.head[0..upstream.head_len];
            const head_is_full = upstream.head_len == constants.head_bytes_max;

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
                upstream.head[0..upstream.head_len],
                false,
                &storage,
                conn.l7.request_method,
            ) catch unreachable;
            assert(response.head_len == conn.l7.response_head_len_marker);
            renderResponse(server, conn, &response);
        }

        /// Render the origin's head into conn.head (free once the request
        /// head has vacated it) and forward the coalesced body excess
        /// straight from upstream.head — never copied through a relay
        /// buffer, so an oversized coalesced body is fine.
        fn renderResponse(
            server: *ServerType,
            conn: *ConnType,
            response: *const parser.ResponseHead,
        ) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .awaiting_head);
            assert(conn.l7.request_head_vacated);
            const upstream = conn.upstream.?;

            // The §8 persistence decision, made once and honored: honor
            // the client's ask unless pipelining, pressure, or drain says
            // otherwise — then announce whatever was decided (§2). An
            // until-close body forces the close unconditionally: the FIN
            // is the only thing delimiting the relayed body for the
            // client, exactly as it delimited it for us.
            const keep_downstream = conn.l7.client_keep_alive and
                !conn.l7.client_pipelined and !server.draining and
                !server.relay_pressure and response.framing != .until_close;
            conn.l7.downstream_close_announced = !keep_downstream;
            conn.l7.upstream_reusable = response.keep_alive;
            const rendered = render.renderResponseHead(
                response,
                !keep_downstream,
                &conn.head,
            ) catch {
                upstreamFailed(server, conn);
                return;
            };
            assert(rendered.len >= 1);
            conn.l7.rendered_response_len = @intCast(rendered.len);
            conn.l7.response_head_sent = 0;
            conn.l7.response_framing = framingFromParsed(response.framing);

            // Feed the framing tracker over the body excess that arrived
            // coalesced with the head.
            const excess = upstream.head[response.head_len..upstream.head_len];
            const feed = feedFraming(&conn.l7.response_framing, excess);
            if (feed.malformed) {
                upstreamFailed(server, conn);
                return;
            }
            const direction = &conn.directions[1];
            direction.sent_len = 0;
            // The common small response arrives from the origin in one
            // piece; forward it in one piece too. Appending the excess to
            // the rendered head trades a bounded memcpy for a whole ring
            // round trip per response. The fallback sends the same bytes
            // as head, then excess from upstream.head.
            if (rendered.len + feed.consumed <= conn.head.len) {
                @memcpy(
                    conn.head[rendered.len..][0..feed.consumed],
                    excess[0..feed.consumed],
                );
                conn.l7.rendered_response_len = @intCast(rendered.len + feed.consumed);
                direction.transfer_len = 0;
            } else {
                direction.transfer_len = feed.consumed;
            }

            conn.l7.response_leg = .sending_head;
            armResponseHeadSend(server, conn);
        }

        fn armResponseHeadSend(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .sending_head);
            const l7 = &conn.l7;
            assert(l7.response_head_sent < l7.rendered_response_len);
            l7.response_started = true;
            conn.arm(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.send(
                conn.client_socket,
                conn.head[l7.response_head_sent..l7.rendered_response_len],
                &conn.op_data_upstream_to_client.completion,
                ConnType,
                conn,
                onResponseHeadSent,
            );
        }

        fn onResponseHeadSent(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .sending_head);
            const sent = result catch |err| {
                // The client is gone; nothing to answer anyone.
                server.witnessKernelPressure(err);
                server.beginTeardown(conn);
                return;
            };
            assert(sent >= 1);
            conn.l7.response_head_sent += sent;
            assert(conn.l7.response_head_sent <= conn.l7.rendered_response_len);
            if (conn.l7.response_head_sent < conn.l7.rendered_response_len) {
                armResponseHeadSend(server, conn);
                return;
            }
            // Head on the wire; forward the coalesced body excess straight
            // from upstream.head, then pump the rest from the socket.
            const direction = &conn.directions[1];
            if (direction.transfer_len >= 1) {
                conn.l7.response_leg = .sending_body_excess;
                armResponseExcessSend(server, conn);
            } else {
                afterResponseExcess(server, conn);
            }
        }

        fn armResponseExcessSend(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .sending_body_excess);
            const direction = &conn.directions[1];
            assert(direction.sent_len < direction.transfer_len);
            const base = conn.l7.response_head_len_marker;
            conn.arm(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.send(
                conn.client_socket,
                conn.upstream.?.head[base + direction.sent_len .. base + direction.transfer_len],
                &conn.op_data_upstream_to_client.completion,
                ConnType,
                conn,
                onResponseExcessSent,
            );
        }

        fn onResponseExcessSent(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .sending_body_excess);
            const sent = result catch |err| {
                server.witnessKernelPressure(err);
                server.beginTeardown(conn);
                return;
            };
            assert(sent >= 1);
            const direction = &conn.directions[1];
            direction.sent_len += sent;
            assert(direction.sent_len <= direction.transfer_len);
            if (direction.sent_len < direction.transfer_len) {
                armResponseExcessSend(server, conn);
                return;
            }
            afterResponseExcess(server, conn);
        }

        /// The head and its coalesced excess are on the wire; finish if the
        /// body ended there, else pump the remaining body from the origin.
        fn afterResponseExcess(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            conn.l7.response_leg = .pumping_body;
            if (framingDone(&conn.l7.response_framing)) {
                finishExchange(server, conn);
            } else {
                armResponseBodyRecv(server, conn);
            }
        }

        fn armResponseBodyRecv(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .pumping_body);
            conn.arm(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.recv(
                conn.upstream_socket.?,
                &conn.relay_buffer.?.upstream_to_client,
                &conn.op_data_upstream_to_client.completion,
                ConnType,
                conn,
                onResponseBodyRecv,
            );
        }

        fn onResponseBodyRecv(conn: *ConnType, result: Io.RecvError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .pumping_body);
            const received = result catch |err| {
                if (err == error.EndOfStream) {
                    if (conn.l7.response_framing == .until_close) {
                        // The origin's EOF is this framing's terminator.
                        finishExchange(server, conn);
                        return;
                    }
                    // Truncated inside a length-delimited body: the client
                    // must see the truncation too, so tear down.
                }
                server.witnessKernelPressure(err);
                server.beginTeardown(conn);
                return;
            };
            assert(received >= 1);
            const chunk = conn.relay_buffer.?.upstream_to_client[0..received];
            const feed = feedFraming(&conn.l7.response_framing, chunk);
            if (feed.malformed) {
                server.beginTeardown(conn);
                return;
            }
            const direction = &conn.directions[1];
            direction.transfer_len = feed.consumed;
            direction.sent_len = 0;
            if (feed.consumed >= 1) {
                armResponseBodySend(server, conn);
            } else {
                assert(feed.done);
                finishExchange(server, conn);
            }
        }

        fn armResponseBodySend(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            const direction = &conn.directions[1];
            assert(direction.sent_len < direction.transfer_len);
            conn.arm(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.send(
                conn.client_socket,
                conn.relay_buffer.?.upstream_to_client[direction.sent_len..direction.transfer_len],
                &conn.op_data_upstream_to_client.completion,
                ConnType,
                conn,
                onResponseBodySent,
            );
        }

        fn onResponseBodySent(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .pumping_body);
            const sent = result catch |err| {
                server.witnessKernelPressure(err);
                server.beginTeardown(conn);
                return;
            };
            assert(sent >= 1);
            const direction = &conn.directions[1];
            direction.sent_len += sent;
            assert(direction.sent_len <= direction.transfer_len);
            if (direction.sent_len < direction.transfer_len) {
                armResponseBodySend(server, conn);
                return;
            }
            server.storeDeadline(conn, server.idleTimeoutMs());
            if (framingDone(&conn.l7.response_framing)) {
                finishExchange(server, conn);
            } else {
                armResponseBodyRecv(server, conn);
            }
        }

        /// The response reached the client in full: settle both sides.
        /// The upstream connection parks for reuse when the origin allowed
        /// it and the request went out completely (§5); the downstream
        /// connection honors what its response announced (§2). An early
        /// response with the request still in flight forfeits both — the
        /// two byte streams are no longer alignable.
        fn finishExchange(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_started);
            conn.l7.response_leg = .done;
            server.counters.increment("l7_responses");

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
        /// teardown cannot close a connection it no longer owns.
        fn parkUpstream(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            const upstream = conn.upstream.?;
            assert(!upstream.parked);
            server.upstreams.park(upstream);
            upstream.deadline_ns = server.io.nowNs() +
                @as(u64, server.idleTimeoutMs()) * std.time.ns_per_ms;
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
                server.upstreams.release(leased);
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
            assert(conn.armedCount() <= 1); // Only the deadline timer.
            server.releaseRelayBuffer(conn.relay_buffer.?);
            conn.relay_buffer = null;
            conn.head_len = 0;
            conn.l7 = .{};
            conn.directions = .{ .{}, .{} };
            conn.state = .l7_reading_head;
            server.storeDeadline(conn, server.idleTimeoutMs());
            armHeadRecv(server, conn);
        }

        /// The upstream leg failed. Answer 502 only when the client has
        /// seen no response byte and both data ops are free — the static
        /// response and its lingering drain need them, and ops are never
        /// canceled (§5). Otherwise the only honest outcome is teardown: a
        /// half-sent response cannot be repaired, and an armed op holds the
        /// completion the answer would need.
        fn upstreamFailed(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            if (conn.l7.response_started or conn.armed.data_client_to_upstream or
                conn.armed.data_upstream_to_client)
            {
                server.beginTeardown(conn);
                return;
            }
            respond(server, conn, 502, "l7_bad_gateway");
        }

        /// Answer a comptime static error response, then close (§8). Legal
        /// from head reading (rejects), dialing (502), and the exchange
        /// (upstream failures) — every caller guarantees both data ops are
        /// free, because the send and the lingering drain need them.
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
            // The static response and its lingering drain read/write only
            // conn.head, never a relay buffer; free any held one now so a
            // reject or 503 storm cannot pin buffers — and the L4 admissions
            // they gate — for the whole drain window (§5, §8).
            if (conn.relay_buffer) |buffer| {
                server.releaseRelayBuffer(buffer);
                conn.relay_buffer = null;
            }
            // A still-attached upstream (a failed dial with no socket, an
            // oversize-after-edit reject, a malformed body) closes and frees
            // its slot now instead of riding the whole lingering drain (§5).
            // Both data ops are free (asserted above), so nothing is armed on
            // the upstream socket and the close is synchronous, like detach.
            if (conn.upstream) |leased| {
                if (conn.upstream_socket) |socket| {
                    server.io.closeNow(socket);
                }
                server.upstreams.release(leased);
                conn.upstream = null;
                conn.upstream_socket = null;
            }
            server.counters.increment(counter);
            conn.state = .l7_responding;
            conn.response_pending = shed.staticResponse(status, .close);
            assert(conn.response_pending.len >= 1);
            armResponseSend(server, conn);
        }

        fn armResponseSend(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_responding);
            assert(conn.response_pending.len >= 1);
            conn.arm(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.send(
                conn.client_socket,
                conn.response_pending,
                &conn.op_data_upstream_to_client.completion,
                ConnType,
                conn,
                onResponseSent,
            );
        }

        fn onResponseSent(conn: *ConnType, result: Io.SendError!u32) void {
            const server = conn.server;
            conn.delivered(&conn.op_data_upstream_to_client, "data_upstream_to_client");
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            assert(conn.state == .l7_responding);
            const sent = result catch |err| {
                server.witnessKernelPressure(err);
                server.beginTeardown(conn);
                return;
            };
            assert(sent >= 1);
            assert(sent <= conn.response_pending.len);
            conn.response_pending = conn.response_pending[sent..];
            if (conn.response_pending.len > 0) {
                // Short send: resume from the new front of the slice (§6).
                armResponseSend(server, conn);
            } else {
                // Response delivered; close it out without RST (§2).
                beginLingeringClose(server, conn);
            }
        }

        /// A client can still be sending its request — a body, or the rest
        /// of an oversize head — when we answer an error. Closing then
        /// would RST and discard the response we just sent (§2). Instead
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
            // The head buffer is scratch now — recv into it and discard.
            conn.arm(&conn.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                conn.head[0..],
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
                server.witnessKernelPressure(err);
                server.beginTeardown(conn);
                return;
            };
            // More bytes to discard; keep draining under the deadline.
            armDrainRecv(server, conn);
        }

        const FeedResult = struct {
            consumed: u32,
            done: bool,
            malformed: bool,
        };

        /// Advance a framing tracker over `bytes`, reporting how many of
        /// them belong to the message. Consumed < bytes.len means the
        /// message ended mid-chunk; the rest is pipelined data, dropped
        /// while every exchange closes its connection.
        fn feedFraming(framing: *Framing, bytes: []const u8) FeedResult {
            assert(bytes.len <= constants.head_bytes_max);
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

        fn framingDone(framing: *const Framing) bool {
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
