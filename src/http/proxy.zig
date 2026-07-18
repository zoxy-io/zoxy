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
//! mirrors head + framed body back. Every exchange currently ends in
//! teardown with `Connection: close` announced both ways; keep-alive
//! parking replaces that in the next slice, which also refines the
//! deadline verdict into §8's 504 (today an expired exchange tears down).
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

        /// Policy gate, then the exchange's admission: tunnels and
        /// upgrades are non-goals (§1, §7) — 501; a routable request
        /// claims its relay buffer and upstream slot (§8 rungs, 503) and
        /// dials the balancer's pick for the listener's cluster.
        fn routeRequest(server: *ServerType, conn: *ConnType, request: *const parser.RequestHead) void {
            assert(conn.state == .l7_reading_head);
            assert(request.head_len <= conn.head_len);
            if (request.method == .connect) {
                return respond(server, conn, 501, "l7_not_implemented");
            }
            if (parser.headerValue(request.headers, "upgrade") != null) {
                return respond(server, conn, 501, "l7_not_implemented");
            }

            conn.relay_buffer = server.acquireRelayBuffer() orelse {
                return respond(server, conn, 503, "l7_shed_relay_buffers");
            };
            const pick = server.balancer.pick(conn.cluster_index);
            conn.upstream = server.upstreams.acquire(conn.cluster_index, pick.endpoint_index) orelse {
                return respond(server, conn, 503, "l7_shed_upstream_slots");
            };

            conn.l7.request_method = request.method;
            conn.l7.request_framing = framingFromParsed(request.framing);
            conn.l7.request_head_len = request.head_len;
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

        /// Re-parse the request head — the bytes are unchanged, so this
        /// cannot fail — and render it into the upstream slot's staging
        /// buffer; then both legs begin.
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

            const upstream = conn.upstream.?;
            const rendered = render.renderRequestHead(&request, true, &upstream.head) catch {
                // Valid on arrival but no longer fits with the close
                // announcement rendered in: the §7 oversize-after-edits
                // verdict.
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
            // Head on the wire: the response leg starts recving now —
            // before the request body finishes — so an early response
            // cannot wedge both TCP windows (§7). Its render into conn.head
            // waits until the request head vacates that buffer.
            startResponseLeg(server, conn);
            drainRequestExcess(server, conn);
        }

        /// Forward the body bytes that arrived coalesced with the head
        /// straight from conn.head (§7): a body larger than a relay buffer
        /// is never squeezed through one, and conn.head is freed for the
        /// response head exactly when the last excess byte leaves it.
        fn drainRequestExcess(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.request_leg == .sending_head);
            const excess = conn.head[conn.l7.request_head_len..conn.head_len];
            const feed = feedFraming(&conn.l7.request_framing, excess);
            if (feed.malformed) {
                // The body prefix already violates its own framing; nothing
                // has been answered yet, so 400 is still legal.
                respondOrTeardown(server, conn, 400, "l7_bad_request");
                return;
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
            // Bytes past the body belong to a pipelined next request;
            // without keep-alive they are dropped with the connection.
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
                beginResponseForward(server, conn);
            } else {
                conn.l7.response_render_pending = true;
            }
        }

        /// Render the origin's head into conn.head (free once the request
        /// head has vacated it) and forward the coalesced body excess
        /// straight from upstream.head — never copied through a relay
        /// buffer, so an oversized coalesced body is fine.
        fn beginResponseForward(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_leg == .awaiting_head);
            assert(conn.l7.request_head_vacated);
            const upstream = conn.upstream.?;
            // The same bytes parsed successfully already (§7 single source
            // of truth), so this re-parse cannot fail.
            var storage: parser.HeaderStorage = undefined;
            const response = parser.parseResponseHead(
                upstream.head[0..upstream.head_len],
                false,
                &storage,
                conn.l7.request_method,
            ) catch unreachable;
            assert(response.head_len == conn.l7.response_head_len_marker);

            const rendered = render.renderResponseHead(&response, true, &conn.head) catch {
                upstreamFailed(server, conn);
                return;
            };
            assert(rendered.len >= 1);
            conn.l7.rendered_response_len = @intCast(rendered.len);
            conn.l7.response_head_sent = 0;
            conn.l7.response_framing = framingFromParsed(response.framing);

            // Feed the framing tracker over the excess now; the bytes are
            // forwarded from upstream.head after the head is sent.
            const excess = upstream.head[response.head_len..upstream.head_len];
            const feed = feedFraming(&conn.l7.response_framing, excess);
            if (feed.malformed) {
                upstreamFailed(server, conn);
                return;
            }
            const direction = &conn.directions[1];
            direction.transfer_len = feed.consumed;
            direction.sent_len = 0;

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

        /// The response reached the client in full. Without keep-alive the
        /// exchange ends the connection — the close was announced in both
        /// rendered heads (§2) — and the request leg, done or not, ends
        /// with it (an early response ends the exchange, §7).
        fn finishExchange(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .l7_exchanging);
            assert(conn.l7.response_started);
            conn.l7.response_leg = .done;
            server.counters.increment("l7_responses");
            server.beginTeardown(conn);
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

        /// 400/503 with the request-body pump possibly armed: prefer the
        /// response when the op is free, teardown otherwise.
        fn respondOrTeardown(
            server: *ServerType,
            conn: *ConnType,
            comptime status: u16,
            comptime counter: []const u8,
        ) void {
            if (conn.armed.data_client_to_upstream or conn.armed.data_upstream_to_client) {
                server.counters.increment(counter);
                server.beginTeardown(conn);
                return;
            }
            respond(server, conn, status, counter);
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
