//! One HTTP/3 connection's place in the server (#449): its slot driven by
//! the datagrams its endpoint hands it and by its timer, its events handed
//! to the exchanges they belong to, and what it wants sent handed back to
//! the endpoint.
//!
//! A pass is strict, as HTTP/2's drive is: the handshake carried, every
//! event the transport raised handed on, answers that were cut short for
//! room offered again, request bodies that have room read into, and the
//! session's own streams flushed — then, once the pass is over, the
//! connection's datagrams queued on its endpoint and its timer aimed at the
//! first thing due. Nothing an exchange does inside a pass sends or reads:
//! `kick` and `reread` are deferred to the pass's end, so a read's borrowed
//! octets are never moved under it, and the teardown a pass decides on
//! waits for the pass to be over before it can release the slot.
//!
//! h3 raises no event when a stream gets room to write, so an answer the
//! transport cut short (`Stream.h3_blocked`) is offered again after every
//! datagram; at most `h3_requests_max` of them, each a cheap no-op until
//! credit or an acknowledgement opens room.

const std = @import("std");
const h3 = @import("h3");

const Runtime = @import("../../extension.zig").Runtime;
const constants = @import("../../constants.zig");
const Connection = @import("Connection.zig");

const assert = std.debug.assert;
const stream_id = h3.quic.stream_id;
const ApplicationCode = h3.quic.error_code.Application;

/// Events one `session.receive` reports at most: a request's HEADERS, its
/// DATA frames and its end, more of them on another read of the stream.
const events_max: u32 = 16;
/// Events one pass polls at most: the transport's queue is fixed, and an
/// event it could not queue is reported as `overflowed` rather than lost.
const polls_max: u32 = 4096;

pub fn Driver(comptime runtime: Runtime) type {
    const ServerType = @import("../../Server.zig").Server(runtime);
    const ConnType = @import("../../net/Conn.zig").Conn(runtime);

    return struct {
        const Shared = @import("../h2/exchange.zig").Exchange(runtime);
        const Half = @import("exchange.zig").Half(runtime);
        const Endpoint = @import("Endpoint.zig").Endpoint(runtime);

        /// The connection speaks HTTP/3 from its first datagram: the slot
        /// begun and its engine bound by the endpoint that admitted it.
        pub fn start(server: *ServerType, conn: *ConnType, first: []u8) void {
            assert(conn.h3 != null);
            assert(conn.tls != null);
            conn.enter(.h3);
            const stream = conn.stream;
            stream.log = .{};
            stream.l7 = .{};
            stream.head_cursor.reset();
            assert(stream.phase == .none);
            // No drain admits a connection, so none is owed a GOAWAY yet.
            assert(!server.draining);
            receive(server, conn, first);
        }

        /// A datagram for this connection, from the address it began from.
        pub fn receive(server: *ServerType, conn: *ConnType, bytes: []u8) void {
            assert(conn.state == .h3);
            const slot = conn.h3.?;
            slot.quic.receive(bytes, server.io.nowNs()) catch |err| {
                // An authenticated peer broke a rule; a packet that does not
                // open is discarded inside, never an error (RFC 9000 §12.2).
                server.counters.increment("h3_protocol_errors");
                slot.quic.close(Connection.Quic.errorCode(err));
            };
            pass(server, conn);
        }

        /// The connection's timer is due. It serves the transport's own
        /// timers — loss detection, the acknowledgement delay, the idle
        /// timeout — and every exchange's deadline, so what is due is
        /// found by looking, as HTTP/2's `expire` does.
        pub fn expire(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .h3);
            assert(!conn.armed.deadline); // Delivered; re-armed only below.
            const slot = conn.h3.?;
            const now = server.io.nowNs();
            // The age cap: a hard end, open or not (§6), said as a close.
            if (server.lifetimeOver(conn)) {
                if (!Half.over(conn)) {
                    server.counters.increment("deadline_expired");
                    slot.quic.closeApplication(@backingInt(ApplicationCode.no_error));
                }
            }
            if (slot.quic.timeout()) |due| {
                if (due <= now) slot.quic.onTimeout(now);
            } else if (slot.quic.state == .handshaking and now >= unheardDeadline(server, conn)) {
                // Its window is past and it has still heard nothing it could
                // open: nothing ever will happen on it, and it holds a slot.
                // A closed transport without a timer is `settle`'s teardown.
                assert(conn.h2_streams == null);
                server.counters.increment("deadline_expired");
                return server.beginTeardown(conn);
            }
            slot.driving = true;
            expireExchanges(server, conn, now);
            slot.driving = false;
            pass(server, conn);
            if (conn.state != .h3) return;
            // `settle` re-based it if anything moved earlier; otherwise the
            // timer this delivery spent is armed again here.
            if (conn.armed.deadline) return;
            if (conn.armed.deadline_cancel) return;
            server.armDeadline(conn);
        }

        /// When a connection whose transport has heard nothing it could open
        /// — an Initial the network corrupted, or a spoofed one — is given
        /// up: one idle window from its birth.
        fn unheardDeadline(server: *const ServerType, conn: *const ConnType) u64 {
            assert(conn.birth_ns != 0);
            return conn.birth_ns + @as(u64, server.idleTimeoutMs()) * std.time.ns_per_ms;
        }

        /// Each exchange past its deadline gets §8's verdict. Taken before
        /// each is offered it: an expiry can end its own exchange.
        fn expireExchanges(server: *ServerType, conn: *ConnType, now: u64) void {
            const streams_max = conn.multiplexedMax();
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| {
                assert(visited < streams_max);
                visited += 1;
                cursor = stream.h2_next;
                if (stream.ending or stream.deadline_ns == 0) continue;
                if (now < stream.deadline_ns) continue;
                server.counters.increment("deadline_expired");
                ServerType.Proxy.expireExchange(server, stream);
            }
        }

        /// The server is draining (§8), or the request cap was reached: a
        /// GOAWAY naming the next request stream, the requests below it
        /// finished, nothing new taken — and the connection closed once the
        /// last of them is (`settle`). One whose handshake never confirmed
        /// has no control stream to say it on, and is closed outright.
        pub fn beginDrain(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .h3);
            goAway(server, conn);
            kick(server, conn);
        }

        pub fn goAway(server: *const ServerType, conn: *ConnType) void {
            const slot = conn.h3.?;
            if (Half.over(conn)) return;
            if (slot.session.goaway_sent != null) return;
            slot.goaway_ns = @max(server.io.nowNs(), 1);
            slot.session.goaway(&slot.quic, null) catch |err| switch (err) {
                error.HandshakeIncomplete => slot.quic.closeApplication(@backingInt(ApplicationCode.no_error)),
                // The connection is already closing, or the control stream
                // has no room for a second GOAWAY, which a drain never asks.
                else => {},
            };
        }

        /// What an exchange staged outside a pass goes out: a pass already
        /// running sends it when it ends. A request body that has room again
        /// (`Stream.h3_reread`) needs its stream read, which only a pass does,
        /// so then the kick is one.
        pub fn kick(server: *ServerType, conn: *ConnType) void {
            if (conn.state != .h3) return; // Torn down: nothing goes out.
            const slot = conn.h3.?;
            if (slot.driving) return;
            if (rereadOwed(conn)) return pass(server, conn);
            slot.session.flush(&slot.quic);
            settle(server, conn);
        }

        fn rereadOwed(conn: *const ConnType) bool {
            const streams_max = conn.multiplexedMax();
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| : (cursor = stream.h2_next) {
                assert(visited < streams_max);
                visited += 1;
                if (stream.h3_reread) return true;
            }
            return false;
        }

        /// A datagram of this connection's left its endpoint: the transport's
        /// timers moved — loss detection arms as a packet leaves, and a
        /// close's closing period starts with its first send.
        pub fn sent(server: *ServerType, conn: *ConnType) void {
            if (conn.state != .h3) return;
            const slot = conn.h3.?;
            if (slot.driving) return; // The pass's own `settle` aims it.
            refreshDeadline(server, conn);
        }

        /// One pass, then what it decided: sent, timed, or torn down.
        fn pass(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .h3);
            const slot = conn.h3.?;
            assert(!slot.driving);
            slot.driving = true;
            slot.handshake(conn.tls.?);
            pollEvents(server, conn);
            resumeBlocked(server, conn);
            rereadStreams(server, conn);
            slot.session.flush(&slot.quic);
            slot.driving = false;
            settle(server, conn);
        }

        /// After a pass or a kick: a drained connection closed, its
        /// datagrams queued, its timer aimed — or, once the transport is
        /// done with its closing period, the connection torn down.
        fn settle(server: *ServerType, conn: *ConnType) void {
            const slot = conn.h3.?;
            assert(!slot.driving);
            if (conn.isTearingDown()) return server.continueTeardown(conn);
            if (slot.quic.isClosed()) return server.beginTeardown(conn);
            // Outside every read, so a drained stream's octets are dropped
            // here and never inside the read that borrowed them.
            slot.discardDrains();
            closeIfDrained(server, conn);
            if (slot.quic.wantsSend()) Endpoint.queue(server, conn);
            if (conn.state != .h3) return;
            refreshDeadline(server, conn);
        }

        /// A connection told to go away closes once its last exchange is
        /// done (RFC 9114 §5.2), with H3_NO_ERROR — and once the client has
        /// heard everything this side said (`Slot.allHeard`), its probes go
        /// unanswered (`Slot.unanswered`), or an idle window after the
        /// GOAWAY passes, whichever is first. A request stream
        /// whose HEADERS had not yet arrived whole has no exchange, and is
        /// cut with it, which §5.2 allows: the client retries what it never
        /// heard an answer to.
        ///
        /// A closing endpoint sends CONNECTION_CLOSE and nothing else (RFC
        /// 9000 §10.2.1). Closing as soon as the last exchange was done
        /// dropped whatever of the connection's last words the client had
        /// not yet heard: the tail of an answer that had only been handed
        /// to the transport, or the GOAWAY itself. The client saw a clean
        /// close with a request in flight and no word it could send it
        /// again — zrk's one read error per capped connection, exactly
        /// 1,000 on the benchmark's c1k-h3. Every acknowledgement settles
        /// the connection, so the close follows the one that empties it.
        ///
        /// A client that has gone is not waited for (#475). It sends its last
        /// acknowledgement and its close once, and when that datagram is
        /// lost nothing else ever arrives, so the wait ends once the
        /// transport's probes have gone unanswered, a few PTOs in. Waiting
        /// out the idle window held the whole slot a minute: on the
        /// benchmark's c1k-h3, enough of them to fill the pool at the
        /// request cap and refuse the clients replacing them. The idle
        /// window still bounds a client that withholds the credit an answer
        /// needs, which leaves nothing in flight to probe with.
        fn closeIfDrained(server: *ServerType, conn: *ConnType) void {
            const slot = conn.h3.?;
            if (slot.session.goaway_sent == null) return;
            if (conn.h2_streams != null) return;
            if (Half.over(conn)) return;
            assert(slot.goaway_ns != 0);
            const waiting = !slot.allHeard() and !slot.unanswered();
            if (waiting and server.io.nowNs() < lingerDeadline(server, slot)) return;
            slot.quic.closeApplication(@backingInt(ApplicationCode.no_error));
            assert(Half.over(conn));
        }

        /// The latest a connection that sent a GOAWAY waits for its client
        /// to hear everything before it closes anyway.
        fn lingerDeadline(server: *const ServerType, slot: *const Connection.Slot) u64 {
            assert(slot.goaway_ns != 0);
            const idle_ms = server.idleTimeoutMs();
            assert(idle_ms >= 1);
            return slot.goaway_ns + @as(u64, idle_ms) * std.time.ns_per_ms;
        }

        /// Aim the connection's one timer at the first of the transport's
        /// own timer, its exchanges' deadlines and its age cap. Earlier
        /// than the armed target re-bases it; later is found lazily (§4).
        fn refreshDeadline(server: *ServerType, conn: *ConnType) void {
            const slot = conn.h3.?;
            // A transport that turned closing starts its closing period only
            // once a clock sees that state: its next send, receive or
            // `onTimeout`. One with nothing it may send — no keys yet, or an
            // address the amplification limit holds — gets no send, so the
            // clock is given here. Without it the transport has no timer, the
            // target falls back to an unheard window already past, and the
            // timer fires at the same instant forever.
            if (Half.over(conn) and slot.quic.timeout() == null) {
                slot.quic.onTimeout(server.io.nowNs());
            }
            // Only a transport that has ended is without one once closing.
            if (Half.over(conn) and !slot.quic.isClosed()) assert(slot.quic.timeout() != null);
            // A transport that has never opened a packet has armed no timer
            // of its own: one idle window from the connection's birth, which
            // nothing it is sent can push later (`expire`).
            var deadline_ns: u64 = slot.quic.timeout() orelse unheardDeadline(server, conn);
            const streams_max = conn.multiplexedMax();
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| : (cursor = stream.h2_next) {
                assert(visited < streams_max);
                visited += 1;
                if (stream.ending) continue;
                if (stream.deadline_ns != 0) deadline_ns = @min(deadline_ns, stream.deadline_ns);
            }
            // The age cap, until it has been said: once the connection is
            // closing, a cap in the past would keep the timer due through the
            // whole closing period.
            if (server.config.max_lifetime_ms != 0) {
                if (!Half.over(conn)) {
                    const cap = conn.birth_ns + @as(u64, server.config.max_lifetime_ms) * std.time.ns_per_ms;
                    deadline_ns = @min(deadline_ns, cap);
                }
            }
            // The linger bound of `closeIfDrained`, while it is what the
            // close waits on: with an exchange left, it waits on that, and a
            // bound in the past would keep the timer due until it ended.
            if (slot.goaway_ns != 0 and conn.h2_streams == null and !Half.over(conn)) {
                deadline_ns = @min(deadline_ns, lingerDeadline(server, slot));
            }
            // A target always exists: the transport's, or the unheard window.
            assert(deadline_ns != 0);
            assert(deadline_ns >= conn.birth_ns);
            // A re-base is a cancel and a fresh arm on the ring, and QUIC
            // moves its deadline on nearly every packet: at 2k req/s on 200
            // connections the old test, against the stored target, re-based
            // 5.2 times a request, and io_uring's timeout removal was 13% of
            // the process. Two things keep most of them off the ring.
            //
            // The comparison is with where the timer is armed, not with the
            // stored target: a target that moved later left the timer where
            // it was (§4), so a new one between the two still fires in time
            // from it. And a target only slightly earlier is left to the
            // timer already armed, which then fires late by at most a
            // sixteenth of what it had left to wait — the loss timer, which
            // most of these are, is re-derived on every acknowledgement and
            // drifts earlier by microseconds as the RTT estimate settles.
            // Together: 1.6 re-bases a request, one of them the move off the
            // idle timer that has to happen.
            const target_ns = @max(deadline_ns, 1);
            const earlier = if (conn.armed.deadline and !conn.armed.deadline_cancel) blk: {
                const slack_ns = (conn.deadline_armed_ns -| server.io.nowNs()) / 16;
                break :blk target_ns + slack_ns < conn.deadline_armed_ns;
            } else target_ns < conn.deadline_ns;
            conn.deadline_ns = target_ns;
            if (earlier) server.rebaseTimer(conn);
        }

        // -- events --

        fn pollEvents(server: *ServerType, conn: *ConnType) void {
            const slot = conn.h3.?;
            var polled: u32 = 0;
            while (slot.quic.poll()) |event| : (polled += 1) {
                assert(polled < polls_max);
                switch (event) {
                    .handshake_confirmed => server.counters.increment("h3_handshakes"),
                    .stream_readable => |id| readStream(server, conn, id),
                    .stream_reset => |reset| onReset(server, conn, reset.stream),
                    .stream_stopped => |stopped| onStopped(server, conn, stopped.stream),
                    .packets_lost => |count| server.counters.incrementBy("h3_packets_lost", count),
                    .closed => |closed| onClosed(server, conn, closed.idle),
                    .overflowed => {
                        server.counters.increment("h3_events_overflowed");
                        rereadAll(conn);
                        readNewRequests(server, conn);
                    },
                    .stream_delivered, .key_updated => {},
                }
            }
        }

        /// Read what a stream has, as far as its exchange can take a body:
        /// in as many reads as that takes, because the transport raises no
        /// second event for octets left unread. A new request stream is read
        /// for its HEADERS alone, and its body waits for the exchange it
        /// opens.
        fn readStream(server: *ServerType, conn: *ConnType, id: u64) void {
            const slot = conn.h3.?;
            var reads: u32 = 0;
            // Bounded: a read that consumes nothing and reports nothing ends
            // the loop, and the stream's receive buffer bounds the rest.
            while (reads <= constants.h3_stream_receive_bytes) : (reads += 1) {
                if (Half.over(conn)) return;
                // Asked each turn: an exchange its own read just answered —
                // a static answer, staged inside the open — let the stream go
                // mid-loop, and what is left of it is not the session's.
                if (slot.draining(id)) return slot.discard(id);
                var events: [events_max]h3.http3.Event = undefined;
                const room = readRoom(conn, id);
                const read = slot.session.receive(&slot.quic, id, &events, room) catch {
                    // The session closed the connection with the code RFC
                    // 9114 names.
                    server.counters.increment("h3_protocol_errors");
                    return;
                };
                for (events[0..read.events], 0..) |*event, index| {
                    onEvent(server, conn, id, event, events[index + 1 .. read.events]);
                }
                slot.session.consume(&slot.quic, id, read);
                // Nothing new was read: what it reported, if anything, was
                // the stream's end, which a read past its FIN reports again.
                // A peer's control or QPACK stream is consumed by the session
                // itself, and always reads as nothing here.
                if (read.consumed == 0) return;
            }
            // Every read that goes on consumed an octet of a buffer that
            // cannot refill inside this loop, which is this side's only turn.
            unreachable;
        }

        /// How much request body a read of `id` may report. A stream with no
        /// exchange is read for its HEADERS alone, whatever else arrived on
        /// it — streams arrive out of order, so one the session has not seen
        /// may be below one it has. One whose exchange ended while its
        /// request was still arriving was told to stop (`Half.stopClient`,
        /// `Half.reset`), and the client's RESET_STREAM releases what is left.
        fn readRoom(conn: *ConnType, id: u64) u64 {
            // A control or QPACK stream is the session's to read whole.
            if (!stream_id.kindOf(id).bidirectional()) return std.math.maxInt(u64);
            const stream = Shared.findH3(conn, @intCast(id)) orelse return 0;
            return Shared.dataRoomAtOnce(stream);
        }

        fn onEvent(server: *ServerType, conn: *ConnType, id: u64, event: *const h3.http3.Event, rest: []const h3.http3.Event) void {
            switch (event.*) {
                .headers => |headers| {
                    if (headers.trailers) return onEnd(server, conn, id, false);
                    // The section was the whole request when the stream's
                    // end came with it: what decides whether a body with no
                    // declared length is framed for the origin at all.
                    const ends = rest.len >= 1 and rest[0] == .finished;
                    Half.open(server, conn, @intCast(id), headers.section, ends);
                },
                .data => |data| onData(server, conn, id, data.payload),
                .finished => onEnd(server, conn, id, true),
                .settings, .goaway => {},
            }
        }

        fn onData(server: *ServerType, conn: *ConnType, id: u64, payload: []const u8) void {
            // An empty DATA frame is legal (RFC 9114 §7.2.1) and says nothing.
            if (payload.len == 0) return;
            const stream = Shared.findH3(conn, @intCast(id)) orelse return; // Dropped.
            if (ServerType.Proxy.readsHandlerBody(stream)) {
                return ServerType.Proxy.takeHandlerData(server, stream, payload, false);
            }
            if (Shared.dataRoom(stream) == 0) return; // Ended under the read.
            // The read was bounded by the room, so the buffer takes it all —
            // or the body cap refuses it, which ends the exchange and says it
            // took everything.
            const taken = Shared.takeData(server, stream, payload, false);
            assert(taken == payload.len);
        }

        /// The request's body is over: its trailers, or its FIN. A stream
        /// whose exchange already answered and let go is released from the
        /// session now that both halves are done.
        fn onEnd(server: *ServerType, conn: *ConnType, id: u64, finished: bool) void {
            const slot = conn.h3.?;
            const stream = Shared.findH3(conn, @intCast(id)) orelse {
                if (finished) slot.session.release(id);
                return;
            };
            Shared.endBody(server, stream);
        }

        /// The client reset a request stream: its exchange ends unanswered.
        fn onReset(server: *ServerType, conn: *ConnType, id: u64) void {
            const slot = conn.h3.?;
            if (!stream_id.kindOf(id).bidirectional()) return;
            slot.session.release(id);
            if (slot.draining(id)) slot.drained(id);
            const stream = Shared.findH3(conn, @intCast(id)) orelse return;
            server.endSharedStream(stream);
        }

        /// The client asked this side to stop sending: the answer is
        /// unwanted, so the request is cancelled both ways and its exchange
        /// ends.
        fn onStopped(server: *ServerType, conn: *ConnType, id: u64) void {
            const slot = conn.h3.?;
            if (!stream_id.kindOf(id).bidirectional()) return;
            const stream = Shared.findH3(conn, @intCast(id)) orelse return;
            slot.session.cancel(&slot.quic, id, .request_cancelled);
            slot.drain(id);
            server.endSharedStream(stream);
        }

        /// The connection closed — the client's CONNECTION_CLOSE, this
        /// side's, or the idle timer: no exchange can answer any more. The
        /// teardown follows once the transport's closing period is over.
        fn onClosed(server: *ServerType, conn: *ConnType, idle: bool) void {
            if (idle) server.counters.increment("h3_idle_closed");
            const streams_max = conn.multiplexedMax();
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| {
                assert(visited < streams_max);
                visited += 1;
                cursor = stream.h2_next;
                if (!stream.ending) server.endSharedStream(stream);
            }
        }

        // -- deferred work --

        /// Answers the transport cut short, offered again.
        fn resumeBlocked(server: *ServerType, conn: *ConnType) void {
            const streams_max = conn.multiplexedMax();
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| {
                assert(visited < streams_max);
                visited += 1;
                cursor = stream.h2_next; // `answer` can give the slot back.
                if (!stream.h3_blocked) continue;
                if (stream.ending) continue;
                stream.h3_blocked = false;
                Shared.answer(server, stream);
            }
        }

        /// Request bodies with room again, read.
        fn rereadStreams(server: *ServerType, conn: *ConnType) void {
            const streams_max = conn.multiplexedMax();
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| {
                assert(visited < streams_max);
                visited += 1;
                cursor = stream.h2_next;
                if (!stream.h3_reread) continue;
                stream.h3_reread = false;
                if (stream.ending) continue;
                readStream(server, conn, stream.h3_id);
            }
        }

        /// Events were dropped — a `stream_readable` among them, perhaps for a
        /// request no exchange holds yet. Every request stream a client could
        /// have opened past the last one seen is read for its HEADERS, which
        /// costs nothing on one that does not exist.
        fn readNewRequests(server: *ServerType, conn: *ConnType) void {
            const slot = conn.h3.?;
            const first = slot.session.next_request;
            var index: u64 = 0;
            while (index < constants.h3_requests_max) : (index += 1) {
                if (Half.over(conn)) return;
                readStream(server, conn, first + index * stream_id.kind_count);
            }
        }

        /// Events were dropped: every request stream is read again, which
        /// costs nothing on one with nothing new.
        fn rereadAll(conn: *ConnType) void {
            const streams_max = conn.multiplexedMax();
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| : (cursor = stream.h2_next) {
                assert(visited < streams_max);
                visited += 1;
                stream.h3_reread = true;
            }
        }

        comptime {
            assert(events_max >= 4);
            assert(polls_max >= events_max);
        }
    };
}
