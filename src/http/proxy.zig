//! The L7 HTTP/1.1 reverse-proxy state machine (DESIGN.md §7). Generic
//! over the Io backend and driven by the Server's helpers (pools,
//! counters, deadline, teardown), exactly as `net/relay.zig` drives the
//! L4 path — L7 lives here, never inlined into the L4 relay.
//!
//! This slice covers head ingestion and the static-response rejects: an
//! L7 connection reads its request head into the slot's head buffer,
//! re-parsing from byte 0 on each recv (§7 detect-and-retry), and either
//! answers a comptime static error response (§8) or — for a valid,
//! supported request — reaches the point where the upstream leg begins.
//! That leg (dial/checkout, forward, response relay, keep-alive) lands in
//! the following slices; until then a valid request tears down after its
//! head is parsed, so no request is mis-served in the interim.
//!
//! Parsed heads are never stored across a callback: parsing writes into a
//! stack-local header array and only scalar verdicts survive, so the head
//! bytes stay the single source of truth (§7) and the slot carries no
//! 1 KiB of header storage.

const std = @import("std");

const constants = @import("../constants.zig");
const conn_module = @import("../net/Conn.zig");
const Io = @import("../io/io.zig");
const parser = @import("parser.zig");
const shed = @import("../shed.zig");

const assert = std.debug.assert;

pub fn Proxy(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);
    const ConnType = conn_module.Conn(IoType);

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
                // instead of closing.
                if (err != error.EndOfStream) {
                    server.witnessKernelPressure(err);
                }
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
                error.Malformed => return reject(server, conn, 400, "l7_bad_request"),
                error.UriTooLong => return reject(server, conn, 414, "l7_uri_too_long"),
                error.HeadTooLarge => return reject(server, conn, 431, "l7_headers_too_large"),
            };
            routeRequest(server, conn, &request);
        }

        /// Policy gate before the upstream leg. Tunnels and protocol
        /// upgrades are non-goals (§1, §7) — 501. Anything else is a
        /// valid, routable request; the upstream leg takes over from here
        /// in the next slice, so for now the exchange ends cleanly.
        fn routeRequest(server: *ServerType, conn: *ConnType, request: *const parser.RequestHead) void {
            assert(conn.state == .l7_reading_head);
            if (request.method == .connect) {
                return reject(server, conn, 501, "l7_not_implemented");
            }
            if (parser.headerValue(request.headers, "upgrade") != null) {
                return reject(server, conn, 501, "l7_not_implemented");
            }
            server.beginTeardown(conn);
        }

        /// Answer a comptime static error response, then close (§8). Every
        /// reject announces the close, so the connection does not survive.
        fn reject(
            server: *ServerType,
            conn: *ConnType,
            comptime status: u16,
            comptime counter: []const u8,
        ) void {
            assert(conn.state == .l7_reading_head);
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
            _ = result catch {
                // EOF or error: the client's inbound is drained, so the
                // close is a clean FIN, not a data-discarding RST.
                server.beginTeardown(conn);
                return;
            };
            // More bytes to discard; keep draining under the deadline.
            armDrainRecv(server, conn);
        }
    };
}
