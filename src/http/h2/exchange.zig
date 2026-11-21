//! An HTTP/2 stream's exchange (#275): the request a `.request` event
//! delivered, run through §7 on a shared stream slot, and the answer the
//! exchange gives handed back to the session as frames.
//!
//! The exchange itself is the HTTP/1.1 one, unchanged. Its request is the
//! head `downgrade.zig` writes out and the HTTP/1.1 parser reads back, so
//! admission, the filters and routing see exactly what they would have
//! from a socket; its answer is the HTTP/1.1 response it renders, read back
//! by `response.zig` and said again as a field section and DATA. What this
//! adds is only the client half's plumbing: where the request comes from,
//! where the answer goes, and what ends the stream.
//!
//! A shared stream's client half never touches a socket — the session's
//! outbox is where its bytes go, and the connection's driver sends them
//! (`Driver.kick`, for what an origin's completion staged). Its upstream
//! half is the HTTP/1.1 one's, ops and all, on the stream's own upstream
//! socket; the response body is pumped here rather than sent, its framing
//! undone so DATA carries the payload alone. An answer the session cannot
//! take whole (its outbox, or the client's window, is short) waits for the
//! session's `.writable`, which names the stream that may go on.
//!
//! What fails on a stream ends the stream, never its connection: it is
//! reset, and whatever it has in flight is forced and waited for before
//! the slot goes back (`Server.endSharedStream`).
//!
//! A request body arrives as DATA and goes to the origin through the relay
//! buffer's client half, framed for HTTP/1.1 as it leaves — chunked when it
//! declared no length — one send at a time. Its octets are credited back to
//! the client only once they are sent, and the window a stream advertises
//! is what the buffer holds, so a client cannot outrun it; one that sends
//! before it has heard that window is held, connection and all, until the
//! body's next send makes room (`Driver.offerHeld`).

const std = @import("std");
const h2 = @import("h2");

const Runtime = @import("../../extension.zig").Runtime;
const constants = @import("../../constants.zig");
const parser = @import("../parser.zig");
const Session = @import("Session.zig");
const downgrade = @import("downgrade.zig");
const response = @import("response.zig");
const render = @import("../render.zig");
const Io = @import("../../io/io.zig");

const hpack = h2.hpack;
const assert = std.debug.assert;

/// Where a rendered head is mapped to the field section HTTP/2 sends
/// (`response.Out`): room for every header the parser admits and the
/// `:status` before them, for the lowercased names of a head as long as a
/// head buffer, and for the parse that reads the head back — its own, not
/// the server's header scratch, which the request's §7 pass holds while a
/// static answer is mapped inside it. One per process, lent for the span
/// of one mapping: the session copies a staged field section out, so
/// nothing borrows it past the call that filled it.
pub const Scratch = struct {
    fields: []hpack.Field,
    bytes: []u8,
    headers: parser.HeaderStorage,
    lent: bool,

    pub const fields_count: u32 = @as(u32, constants.headers_max) + 1;

    /// What `init` reserves at `head_buffer_bytes` — the closed form the
    /// budget prices (`Server.headScratchBytes`).
    pub fn bytesFor(head_buffer_bytes: u32) u64 {
        assert(head_buffer_bytes >= constants.head_buffer_bytes_min);
        return @as(u64, fields_count) * @sizeOf(hpack.Field) + head_buffer_bytes;
    }

    pub fn init(arena: std.mem.Allocator, head_buffer_bytes: u32) error{OutOfMemory}!Scratch {
        assert(head_buffer_bytes >= constants.head_buffer_bytes_min);
        const scratch: Scratch = .{
            .fields = try arena.alloc(hpack.Field, fields_count),
            .bytes = try arena.alloc(u8, head_buffer_bytes),
            .headers = undefined,
            .lent = false,
        };
        assert(scratch.fields.len * @sizeOf(hpack.Field) + scratch.bytes.len ==
            bytesFor(head_buffer_bytes));
        return scratch;
    }

    /// A deployment that speaks no HTTP/2 reserves none.
    pub const empty: Scratch = .{ .fields = &.{}, .bytes = &.{}, .headers = undefined, .lent = false };

    fn lend(scratch: *Scratch) response.Out {
        assert(!scratch.lent);
        assert(scratch.fields.len == fields_count);
        scratch.lent = true;
        return .{ .fields = scratch.fields, .bytes = scratch.bytes };
    }

    fn giveBack(scratch: *Scratch) void {
        assert(scratch.lent);
        scratch.lent = false;
    }
};

/// What a chunked request body's gathered payload must leave behind it:
/// its chunk's CRLF, and then either the last chunk or the next frame's
/// headroom — whichever is wider — so the frame it becomes never ends past
/// the buffer, nor leaves the next payload's start there (#275). Either,
/// not both: a frame carrying the last chunk has no next payload, and
/// `frameAndSend` keeps no headroom after it.
pub const chunk_tail_bytes: u32 = @intCast(render.chunk_suffix.len +
    @max(render.chunk_prefix_bytes_max, render.last_chunk.len));

/// What framing costs a request body in its buffer at worst: a frame in
/// flight (its size line and CRLF), and behind it the next payload's
/// headroom and `chunk_tail_bytes`. A window of the rest always fits.
pub const body_framing_bytes: u32 = 2 * render.chunk_prefix_bytes_max +
    @as(u32, render.chunk_suffix.len) + chunk_tail_bytes;

/// The request-body window a stream advertises (#275): what a relay buffer
/// holds beside `body_framing_bytes`, so a client honouring it never sends
/// a stream more than its buffer can take — capped at the protocol's
/// default, which a client may spend before it hears ours (RFC 9113
/// §6.9.2), and is held to then (`Driver.offerHeld`).
///
/// Never less than one frame of the size every endpoint must take (§4.2,
/// #277): a window under it leaves a client no way to send one, and a
/// client that sends one anyway — h2spec's 4.2/1 — overruns it. Past the
/// buffer's room the frame is held, which waits this connection's other
/// streams behind it until it drains: 58 octets at the default buffer,
/// and the price of configuring one smaller than a frame.
pub fn requestWindow(relay_buffer_bytes: u32) u31 {
    assert(relay_buffer_bytes > body_framing_bytes);
    const room = relay_buffer_bytes - body_framing_bytes;
    const window = @min(@max(room, Session.frame_payload_bytes_max), Session.window_default);
    assert(window >= Session.frame_payload_bytes_max);
    return @intCast(window);
}

comptime {
    // The last chunk fits where the next frame's headroom would.
    assert(chunk_tail_bytes >= render.chunk_suffix.len + render.last_chunk.len);
    // Any legal relay buffer leaves a window.
    assert(constants.relay_buffer_bytes_min > body_framing_bytes);
    // One frame fits under the protocol's default window, which caps it.
    assert(Session.frame_payload_bytes_max <= Session.window_default);
}

pub fn Exchange(comptime runtime: Runtime) type {
    const ServerType = @import("../../Server.zig").Server(runtime);
    const ConnType = @import("../../net/Conn.zig").Conn(runtime);
    const StreamType = ConnType.StreamType;

    return struct {
        // A declaration rather than a capture above: `Proxy(runtime)` names
        // this type in its own body, so evaluating it eagerly here would be
        // a type whose definition needs itself.
        const Proxy = @import("../proxy.zig").Proxy(runtime);
        const Driver = @import("Connection.zig").Driver(runtime);
        const H3Half = @import("../h3/exchange.zig").Half(runtime);

        /// A stream opened with a well-formed request: a shared slot and a
        /// head buffer for it, its request written out as the HTTP/1.1
        /// head it stands for, and §7 begun on that — or REFUSED_STREAM
        /// when there is no slot to run it on, which the client may retry.
        pub fn open(server: *ServerType, conn: *ConnType, request: *const Session.Step.Request) void {
            assert(conn.state == .h2);
            const session = conn.h2.?.session;
            const stream = server.acquireSharedStream(conn, .{ .h2 = request.stream }) orelse {
                server.counters.increment("h2_shed_streams");
                session.resetStream(request.stream, .refused_stream);
                return;
            };
            assert(stream.h2_id == request.stream);
            // The parse's headers live in the scratch, and §7 reads them
            // through routing — so the borrow spans the whole front half,
            // as it does for a head read off a socket.
            const storage = server.borrowHeaderScratch();
            defer server.returnHeaderScratch();
            const neutral: downgrade.Request = .{
                .fields = request.fields,
                .content_length = request.content_length,
                .end_stream = request.end_stream,
            };
            const head = downgrade.requestHead(&neutral, stream.h2_head.?.data, storage) catch |err| {
                return Proxy.refuseH2Request(server, stream, err);
            };
            Proxy.serveH2Request(server, stream, &head);
            // The stream may be answered and gone by now; the connection is
            // what the cap reads.
            capRequests(server, conn);
        }

        /// The #237 request cap on a multiplexed connection, settled as
        /// #173's answer 4. It counts the connection's streams, and the
        /// stream that reaches it ends the connection with GOAWAY(NO_ERROR)
        /// naming that stream, which is HTTP/2's way of saying
        /// `Connection: close`. The streams before it finish. Any the client
        /// opens after it are refused with REFUSED_STREAM, and since they
        /// were never processed, the client may retry them on a new
        /// connection (RFC 9113 §8.7).
        ///
        /// HTTP/1.1 weighs the cap at the answer. Here it is weighed as each
        /// stream is opened, once §7 has it, because a stream's answer ends
        /// only that stream. Siblings admitted earlier can answer after the cap is
        /// reached, so weighing it at the answer would count it once per
        /// sibling and still close nothing.
        ///
        /// It is counted only where the cap is the binding reason, as on
        /// HTTP/1.1. A connection that is already ending did not need this
        /// rung: one draining, one whose client sent its own GOAWAY, one
        /// closing, or one this side already told.
        fn capRequests(server: *ServerType, conn: *ConnType) void {
            if (conn.state != .h2) return; // Torn down while it served.
            assert(conn.h2 != null);
            const cap = conn.keepalive_requests;
            if (cap == 0) return; // Unlimited.
            if (conn.requests_served < cap) return;
            const slot = conn.h2.?;
            const session = slot.session;
            if (slot.closing or server.draining) return;
            if (session.state == .closed) return;
            if (session.goingAway()) return;
            session.goAway();
            assert(session.self_going_away);
            server.counters.increment("l7_keepalive_requests_capped");
        }

        /// Hand the session what the exchange's answer has left to say: its
        /// head, once, then its body — END_STREAM with the last of it.
        /// Called where the HTTP/1.1 path would arm a send
        /// (`Proxy.armClientWrite`), and again from `.writable` for an
        /// answer the session could not take whole. An interim head goes
        /// alone, and the final one is still to come after it.
        ///
        /// The session may have ended the connection while the origin was
        /// answering: a flood's verdict, or a protocol error. Its GOAWAY is
        /// going out, and the teardown behind it takes every stream, but
        /// until then the connection is not tearing down, so this stream's
        /// ops still deliver. Nothing more can be said on it, so the
        /// exchange ends here, unanswered, as the client's reset would end
        /// it.
        pub fn answer(server: *ServerType, stream: *StreamType) void {
            const conn = stream.conn;
            const mux = stream.mux;
            assert(stream.muxed());
            if (sessionOver(stream)) return server.endSharedStream(stream);
            assert(!stream.ending);
            // The answer can finish the stream and give its slot back, so
            // only the connection is read after it.
            stage(server, stream);
            kick(server, conn, mux);
        }

        /// `answer`'s staging, without the send: the caller kicks.
        fn stage(server: *ServerType, stream: *StreamType) void {
            assert(stream.muxed());
            assert(stream.phase == .responding or stream.phase == .exchanging);
            assert(!stream.h2_ended);
            if (!stream.h2_head_staged) {
                if (!stageHead(server, stream)) return;
            }
            const write = &stream.client_write;
            const ends = answerEnds(stream);
            // A trailer section ends the stream in DATA's place (§8.1).
            const trailers_owed = ends and trailersOwed(stream);
            if (write.pending.len >= 1 or (ends and !trailers_owed and !stream.h2_ended)) {
                const sent = sendData(stream, write.pending, ends and !trailers_owed) orelse
                    return fail(server, stream);
                assert(sent.taken <= write.pending.len);
                write.pending = write.pending[sent.taken..];
                stream.log.bytes_out += sent.taken;
                stream.h2_ended = sent.ended;
                // The client took body octets: activity, as a send's
                // completion is on the HTTP/1.1 path (§6).
                if (sent.taken >= 1) server.storeExchangeDeadline(stream, server.idleTimeoutMs());
                // Cut short by the window or the outbox: `.writable` resumes.
                if (write.pending.len >= 1) return;
                if (ends and !trailers_owed and !sent.ended) return;
            }
            if (trailers_owed and !stream.h2_ended) {
                if (!stageTrailers(server, stream)) return;
            }
            Proxy.h2WriteDelivered(server, stream);
        }

        /// The answer's trailer section has a field to say: the origin's
        /// chunked body ended with more than the closing CRLF. Asked only
        /// once the answer ends — its framing done, the section whole — and
        /// it asserts as much: a section still arriving is not owed yet.
        fn trailersOwed(stream: *const StreamType) bool {
            assert(stream.muxed());
            const section = stream.h2_trailers;
            if (section.len == 0) return false;
            assert(section.len >= 2);
            assert(stream.l7.response_framing == .chunked);
            assert(stream.l7.response_framing.chunked.state == .done);
            return section.len > 2;
        }

        /// Stage the origin's trailer section as trailing HEADERS, with
        /// END_STREAM (RFC 9113 §8.1). False when the answer cannot go on
        /// now: the session has no room for it yet, or the section is one
        /// HTTP/2 cannot carry, which ends the exchange as a head would.
        fn stageTrailers(server: *ServerType, stream: *StreamType) bool {
            assert(stream.h2_head_staged);
            assert(stream.client_write.pending.len == 0);
            const out = server.h2_scratch.lend();
            defer server.h2_scratch.giveBack();
            const fields = response.trailerFields(stream.h2_trailers, &out) catch {
                fail(server, stream);
                return false;
            };
            assert(fields.len >= 1);
            switch (sendTrailers(server, stream, fields)) {
                .staged => {},
                .blocked => return false,
                .refused => {
                    fail(server, stream);
                    return false;
                },
            }
            stream.h2_ended = true;
            stream.log.bytes_out += stream.h2_trailers.len;
            return true;
        }

        /// The trailer section octets one feed of the response body met,
        /// `fed.trailer_len` of them at the tail of what it consumed from
        /// `bytes`: the section's start, or its continuation — which a read
        /// into the relay buffer behind the part already moved to its
        /// front (`pumpBody`) makes contiguous with it.
        pub fn keepTrailers(stream: *StreamType, bytes: []u8, fed: *const Proxy.PayloadFeed) void {
            assert(stream.muxed());
            assert(fed.trailer_len <= fed.feed.consumed);
            if (fed.trailer_len == 0) return;
            const tail = bytes[fed.feed.consumed - fed.trailer_len .. fed.feed.consumed];
            const kept = stream.h2_trailers;
            if (kept.len == 0) {
                stream.h2_trailers = tail;
                return;
            }
            assert(kept.ptr + kept.len == tail.ptr);
            stream.h2_trailers = kept.ptr[0 .. kept.len + tail.len];
            assert(stream.h2_trailers.len <= constants.chunked_trailer_bytes_max);
        }

        /// Whether what the answer has left ends the stream: a static answer
        /// always; a proxied one once nothing of its body is left to come —
        /// no excess still to hand over, and the origin's framing done.
        fn answerEnds(stream: *const StreamType) bool {
            assert(stream.muxed());
            assert(stream.phase == .responding or stream.phase == .exchanging);
            return switch (stream.client_write.then) {
                .lingering_close, .next_request => true,
                .redirect_lingering_close, .redirect_next_request => true,
                .response_excess => stream.l7.response_excess_len == 0 and Proxy.framingDone(stream),
                .response_body => Proxy.framingDone(stream),
                .interim_sent => false,
                .tunnel_start => unreachable, // No upgrade reaches HTTP/2.
            };
        }

        /// Map the rendered head at the front of the answer and stage it,
        /// with END_STREAM when nothing follows it. False when the answer
        /// cannot go on now: the session has no room for it yet, or the
        /// head is one HTTP/2 cannot carry, which ends the exchange.
        fn stageHead(server: *ServerType, stream: *StreamType) bool {
            const write = &stream.client_write;
            assert(write.pending.len >= 1);
            const method = stream.l7.request_method;
            const out = server.h2_scratch.lend();
            defer server.h2_scratch.giveBack();
            const mapped = response.responseHead(write.pending, method, &server.h2_scratch.headers, &out) catch {
                fail(server, stream);
                return false;
            };
            assert(mapped.interim == (write.then == .interim_sent));
            // A HEAD's answer carries the head a GET's would, and no body
            // whatever the head declares (RFC 9110 §9.3.2).
            const body = if (method == .head) write.pending[0..0] else write.pending[mapped.head_len..];
            const ends = body.len == 0 and answerEnds(stream) and !trailersOwed(stream);
            switch (sendHead(server, stream, mapped.fields, ends)) {
                .staged => {},
                .blocked => return false,
                .refused => {
                    fail(server, stream);
                    return false;
                },
            }
            // An interim head ends nothing: the final one is the next write.
            stream.h2_head_staged = !mapped.interim;
            stream.h2_ended = ends;
            stream.log.bytes_out += mapped.head_len;
            write.pending = body;
            // The field section is copied out, `Date` and all, so the
            // shared static bytes are read no further than their body —
            // which carries no stamp (#234).
            server.releaseStaticSend(stream);
            return true;
        }

        /// The response body's rest (§7's response leg): read from the
        /// origin into the relay buffer, its HTTP/1.1 framing undone, and
        /// handed over as DATA — the next read only once the session has
        /// taken it all, as the HTTP/1.1 pump waits for its send (§6).
        ///
        /// A trailer section begun and not yet whole moves to the buffer's
        /// front first, and the read lands behind it, so the section stays
        /// one run however the origin split it. The scanner bounds it below
        /// `chunked_trailer_bytes_max`; a section that fills the buffer
        /// before it ends is one the scanner refuses at its next octet, and
        /// that verdict is given here instead of reading for it.
        pub fn pumpBody(server: *ServerType, stream: *StreamType) void {
            assert(stream.phase == .exchanging);
            assert(stream.l7.response_leg == .pumping_body);
            assert(stream.client_write.pending.len == 0);
            const buffer = stream.relay_buffer.?.upstream_to_client;
            const kept = stream.h2_trailers;
            assert(kept.len <= constants.chunked_trailer_bytes_max);
            if (kept.len == buffer.len) return fail(server, stream);
            std.mem.copyForwards(u8, buffer[0..kept.len], kept);
            stream.h2_trailers = buffer[0..kept.len];
            stream.arm(&stream.op_data_upstream_to_client, "data_upstream_to_client");
            server.upstreamRecv(stream, buffer[kept.len..], &stream.op_data_upstream_to_client.completion, onBodyRecv);
        }

        fn onBodyRecv(stream: *StreamType, result: Io.RecvError!u32) void {
            const server = stream.conn.server;
            stream.delivered(&stream.op_data_upstream_to_client, "data_upstream_to_client");
            if (server.exchangeOver(stream)) return;
            assert(stream.phase == .exchanging);
            assert(stream.l7.response_leg == .pumping_body);
            // No verdict can be pending: the response began, which is what
            // makes an expiry end the stream rather than answer it.
            assert(stream.l7.pending_verdict == .none);
            const received = result catch |err| {
                // An until-close body is delimited by the origin's FIN, and
                // only that one: its framing is done, and END_STREAM alone
                // says so. Any other framing's EOF is a body cut short.
                if (err == error.EndOfStream and stream.l7.response_framing == .until_close) {
                    stream.l7.response_framing = .none;
                    stream.client_write = .{ .pending = &.{}, .then = .response_body };
                    return answer(server, stream);
                }
                server.witnessKernelPressure(.recv, err);
                return fail(server, stream);
            };
            assert(received >= 1);
            // The origin is still sending: activity (§6).
            server.storeExchangeDeadline(stream, server.idleTimeoutMs());
            // The read landed behind a trailer section already begun.
            const chunk = stream.relay_buffer.?.upstream_to_client[stream.h2_trailers.len..][0..received];
            const fed = Proxy.payloadFraming(&stream.l7.response_framing, chunk, true);
            if (fed.feed.malformed) return fail(server, stream);
            keepTrailers(stream, chunk, &fed);
            // Octets past the body: the origin said more than its framing
            // allowed, and the connection cannot be trusted with another.
            if (fed.feed.consumed < received) stream.l7.upstream_reusable = false;
            stream.client_write = .{ .pending = chunk[0..fed.forward_len], .then = .response_body };
            answer(server, stream);
        }

        /// The answer is staged whole, END_STREAM with it. A client still
        /// sending its request is told to stop — RST_STREAM(NO_ERROR),
        /// RFC 9113 §8.1 — and the slot goes back.
        pub fn finish(server: *ServerType, stream: *StreamType) void {
            assert(stream.client_write.pending.len == 0);
            assert(stream.log.emitted or server.access_log.sink == null);
            assert(stream.h2_ended);
            stopClient(stream);
            if (stream.armedCount() == 0) return server.releaseSharedStream(stream);
            // An op the answer did not wait for is still out — a timed-out
            // dial's cancel, when the 504 came from the connect's own
            // completion — and the slot waits for it, as an ending one does.
            server.endSharedStream(stream);
        }

        /// The exchange cannot finish: reset the stream with `code` — if
        /// the session still holds it — and end the exchange, which gives
        /// the slot back once whatever it has in flight delivers. Its line
        /// says it was aborted.
        pub fn abandon(server: *ServerType, stream: *StreamType, code: h2.frame.ErrorCode) void {
            assert(code != .no_error);
            assert(stream.muxed());
            const conn = stream.conn;
            const mux = stream.mux;
            resetClient(stream, code);
            server.endSharedStream(stream);
            kick(server, conn, mux);
        }

        /// The exchange failed after it began (an origin that broke off, a
        /// body that would not frame): INTERNAL_ERROR (RFC 9113 §7), which
        /// says nothing about whether the request was processed.
        pub fn fail(server: *ServerType, stream: *StreamType) void {
            assert(stream.muxed());
            assert(!stream.ending);
            abandon(server, stream, .internal_error);
        }

        // -- the client half, by protocol (#449) --
        //
        // Everything above and below is the exchange; these are the few
        // calls that ask the session it answers through, HTTP/2's or
        // HTTP/3's. HTTP/2's arms are its session's calls as they were.

        /// The session can say nothing more: the connection is ending under
        /// the exchange.
        fn sessionOver(stream: *const StreamType) bool {
            return switch (stream.mux) {
                .none => unreachable,
                .h2 => stream.conn.h2.?.session.state == .closed,
                .h3 => H3Half.over(stream.conn),
            };
        }

        fn sendHead(server: *ServerType, stream: *StreamType, fields: []const hpack.Field, ends: bool) Session.Sent {
            return switch (stream.mux) {
                .none => unreachable,
                .h2 => stream.conn.h2.?.session.sendHead(stream.h2_id, fields, ends),
                .h3 => H3Half.sendHead(server, stream, fields, ends),
            };
        }

        /// Null when the stream cannot take body octets at all, which ends
        /// the exchange; HTTP/2's session always answers.
        fn sendData(stream: *StreamType, bytes: []const u8, ends: bool) ?Session.DataSent {
            return switch (stream.mux) {
                .none => unreachable,
                .h2 => stream.conn.h2.?.session.sendData(stream.h2_id, bytes, ends),
                .h3 => H3Half.sendData(stream, bytes, ends),
            };
        }

        fn sendTrailers(server: *ServerType, stream: *StreamType, fields: []const hpack.Field) Session.Sent {
            return switch (stream.mux) {
                .none => unreachable,
                .h2 => stream.conn.h2.?.session.sendTrailers(stream.h2_id, fields),
                .h3 => H3Half.sendTrailers(server, stream, fields),
            };
        }

        /// The answer is whole: a client still sending its request is told
        /// to stop (RFC 9113 §8.1's RST_STREAM(NO_ERROR), RFC 9114 §4.1's
        /// STOP_SENDING(H3_NO_ERROR)).
        fn stopClient(stream: *StreamType) void {
            switch (stream.mux) {
                .none => unreachable,
                .h2 => {
                    const session = stream.conn.h2.?.session;
                    if (session.awaitingClient(stream.h2_id)) session.resetStream(stream.h2_id, .no_error);
                },
                .h3 => H3Half.stopClient(stream),
            }
        }

        /// The exchange is abandoned: the stream reset, if the session still
        /// holds it.
        fn resetClient(stream: *StreamType, code: h2.frame.ErrorCode) void {
            switch (stream.mux) {
                .none => unreachable,
                .h2 => {
                    const session = stream.conn.h2.?.session;
                    if (session.resettable(stream.h2_id)) session.resetStream(stream.h2_id, code);
                },
                // HTTP/3 maps the one code the exchange resets with.
                .h3 => {
                    assert(code == .internal_error);
                    H3Half.reset(stream);
                },
            }
        }

        /// `octets` of the request body reached the origin: HTTP/2 credits
        /// them back to the client's window; HTTP/3's stream is read for
        /// the room they left, its flow control having held the rest.
        fn creditClient(stream: *StreamType, octets: u32) void {
            switch (stream.mux) {
                .none => unreachable,
                .h2 => if (octets >= 1) stream.conn.h2.?.session.consume(stream.h2_id, octets),
                .h3 => H3Half.bodyRoomOpened(stream),
            }
        }

        /// What the exchange staged goes out.
        fn kick(server: *ServerType, conn: *ConnType, mux: StreamType.Mux) void {
            switch (mux) {
                .none => unreachable,
                .h2 => Driver.kick(server, conn),
                .h3 => H3Half.kick(server, conn),
            }
        }

        // -- the request body --

        /// Request body octets for `data.stream`, taken into its buffer as
        /// far as there is room. Answers how many were taken: the driver
        /// holds the rest of the frame — and the connection's input with it
        /// — until the body's next send makes room, which in steady state
        /// the window each stream advertises means it never has to. An
        /// exchange not forwarding a body — answered by §7, or ending — has
        /// its octets consumed and dropped, so the client's window opens.
        pub fn onData(server: *ServerType, conn: *ConnType, data: *const Session.Step.Data) u32 {
            assert(conn.state == .h2);
            const length: u32 = @intCast(data.bytes.len);
            const stream = find(conn, data.stream) orelse return drop(conn, data);
            // A handler route's body (#434) is kept beside its head, all of
            // it at once, so its window is credited now.
            if (Proxy.readsHandlerBody(stream)) {
                if (length >= 1) conn.h2.?.session.consume(data.stream, length);
                Proxy.takeHandlerData(server, stream, data.bytes, data.end_stream);
                return length;
            }
            if (!forwarding(stream)) return drop(conn, data);
            return takeData(server, stream, data.bytes, data.end_stream);
        }

        /// What the request body's buffer can take now on an exchange that
        /// forwards one — how much DATA an HTTP/3 stream is read for (#449),
        /// its flow control holding the rest at the client — or zero on one
        /// that does not.
        pub fn dataRoom(stream: *const StreamType) u32 {
            assert(stream.muxed());
            // A handler route takes its whole body beside its head, and past
            // the head buffer's room answers 413 itself (#434).
            if (Proxy.readsHandlerBody(stream)) return std.math.maxInt(u32);
            if (!forwarding(stream)) return 0;
            const body = &stream.h2_body;
            if (body.payload_start >= headroom(stream)) return bodyRoom(stream);
            // A chunked body before its first payload: its headroom is not
            // yet reserved, which `bodyRoom` asserts it is. A declared one's
            // headroom is zero, so it never reaches here.
            assert(body.payload_start == 0);
            assert(body.payload_len == 0);
            const capacity: u32 = @intCast(stream.relay_buffer.?.client_to_upstream.len);
            const tail: u32 = if (stream.l7.request_framing == .chunked) chunk_tail_bytes else 0;
            assert(capacity > headroom(stream) + tail);
            return capacity - headroom(stream) - tail;
        }

        /// What one HTTP/3 read may report at once (#449): `dataRoom`, less
        /// what framing the first of it takes from the rest. A chunked body
        /// whose leg is pumping and has no frame in flight frames its first
        /// payload as it lands, and that frame's size line and CRLF come out
        /// of the room the rest of the read was counted against — once,
        /// since every payload after it gathers behind the frame in flight.
        pub fn dataRoomAtOnce(stream: *const StreamType) u32 {
            const room = dataRoom(stream);
            if (stream.l7.request_framing != .chunked) return room;
            if (stream.h2_body.inFlight()) return room;
            const framing: u32 = render.chunk_prefix_bytes_max + @as(u32, render.chunk_suffix.len);
            return room -| framing;
        }

        /// Request body octets into a forwarding exchange's buffer, as far as
        /// there is room: HTTP/2's DATA and HTTP/3's alike (#449). Answers
        /// how many were taken.
        pub fn takeData(server: *ServerType, stream: *StreamType, bytes: []const u8, end_stream: bool) u32 {
            assert(stream.muxed());
            assert(forwarding(stream));
            const conn = stream.conn;
            const length: u32 = @intCast(bytes.len);
            const body = &stream.h2_body;
            // The first payload sits where a frame's starts: past room for
            // its chunk size line, which goes in front of it when it is sent.
            // Zero is that place for a declared length, so setting it again
            // there changes nothing.
            if (body.payload_start == 0) body.payload_start = headroom(stream);
            const take = @min(bodyRoom(stream), length);
            assert(take <= length);
            const buffer = stream.relay_buffer.?.client_to_upstream;
            @memcpy(buffer[body.payload_start + body.payload_len ..][0..take], bytes[0..take]);
            body.payload_len += take;
            assert(body.payload_start + body.payload_len <= buffer.len);
            body.total += take;
            stream.log.bytes_in += take;
            if (conn.max_body_bytes != 0 and body.total > conn.max_body_bytes) {
                // The listener's cap (#236), on a body that declared no
                // length: the stream is reset, the connection serves on.
                server.counters.increment("l7_body_cut_mid_stream");
                fail(server, stream);
                return length;
            }
            if (take == length and end_stream) body.client_ended = true;
            if (stream.l7.request_leg == .pumping_body) frameAndSend(server, stream);
            return take;
        }

        /// The request's end with no more of its body: HTTP/2's trailers or
        /// END_STREAM on empty DATA, HTTP/3's trailers or FIN (#449).
        pub fn endBody(server: *ServerType, stream: *StreamType) void {
            assert(stream.muxed());
            // A trailer section ends a handler route's body too (#434).
            if (Proxy.readsHandlerBody(stream)) return Proxy.takeHandlerData(server, stream, &.{}, true);
            if (!forwarding(stream)) return;
            stream.h2_body.client_ended = true;
            if (stream.l7.request_leg == .pumping_body) frameAndSend(server, stream);
        }

        /// The request's trailer section ends the client's half. It is not
        /// carried: the chunked body's last chunk goes out with none
        /// (#275). An origin's, the other way, are (`stageTrailers`).
        pub fn onTrailers(server: *ServerType, conn: *ConnType, trailers: *const Session.Step.Trailers) void {
            assert(conn.state == .h2);
            const stream = find(conn, trailers.stream) orelse return;
            endBody(server, stream);
        }

        /// Octets for an exchange that will not forward them, consumed.
        fn drop(conn: *ConnType, data: *const Session.Step.Data) u32 {
            const length: u32 = @intCast(data.bytes.len);
            assert(length == data.bytes.len);
            if (length >= 1) conn.h2.?.session.consume(data.stream, length);
            return length;
        }

        /// The exchange forwards a request body: its upstream half runs,
        /// and the client's half is still arriving.
        ///
        /// Not once the §8 deadline has condemned it. `beginExpiry` shut
        /// its upstream down to force its ops, and it answers 504 once
        /// they settle, so a frame held for its room until then must not
        /// be sent on that socket. Another stream's answer can drive the
        /// session in that window, which is how a soak seed met it
        /// (456163385). A pending replay is not condemned: its try is
        /// rebuilt, so what gathers still goes.
        fn forwarding(stream: *const StreamType) bool {
            assert(stream.muxed());
            if (stream.ending) return false;
            if (stream.l7.pending_verdict == .gateway_timeout) return false;
            if (stream.phase != .dialing and stream.phase != .exchanging) return false;
            if (stream.l7.request_framing == .none) return false;
            return !stream.h2_body.client_ended;
        }

        /// A chunked body's headroom: room before the payload for its size
        /// line, written there when the payload goes.
        fn headroom(stream: *const StreamType) u32 {
            return if (stream.l7.request_framing == .chunked) render.chunk_prefix_bytes_max else 0;
        }

        /// What the buffer can take behind the payload already gathered,
        /// leaving the chunk suffix and the last chunk their room.
        fn bodyRoom(stream: *const StreamType) u32 {
            const body = &stream.h2_body;
            const capacity: u32 = @intCast(stream.relay_buffer.?.client_to_upstream.len);
            const tail: u32 = if (stream.l7.request_framing == .chunked) chunk_tail_bytes else 0;
            const used = body.payload_start + body.payload_len + tail;
            assert(body.payload_start >= headroom(stream));
            assert(body.payload_start + body.payload_len <= capacity);
            return capacity -| used;
        }

        /// The request head is out (§7's request leg): what the body has
        /// gathered goes, and the rest follows as it arrives.
        pub fn forwardBody(server: *ServerType, stream: *StreamType) void {
            assert(stream.l7.request_leg == .pumping_body);
            assert(stream.l7.request_framing != .none);
            // The head's completions settle a pending verdict before they
            // come here, so a condemned exchange never begins its body.
            assert(stream.l7.pending_verdict == .none);
            const body = &stream.h2_body;
            if (body.payload_start == 0) body.payload_start = headroom(stream);
            assert(!body.inFlight());
            frameAndSend(server, stream);
        }

        /// Send what the body has gathered, if nothing is in flight: one
        /// chunk — its size line before it, CRLF after, the last chunk too
        /// once the client's half has ended — or a declared-length body's
        /// bare octets. The next payload gathers past it.
        fn frameAndSend(server: *ServerType, stream: *StreamType) void {
            const body = &stream.h2_body;
            assert(stream.l7.request_leg == .pumping_body);
            if (body.inFlight()) return;
            if (body.payload_len == 0 and !body.client_ended) return;
            const chunked = stream.l7.request_framing == .chunked;
            const buffer = stream.relay_buffer.?.client_to_upstream;
            var start = body.payload_start;
            var end = body.payload_start + body.payload_len;
            if (chunked and body.payload_len >= 1) {
                var prefix_storage: [render.chunk_prefix_bytes_max]u8 = undefined;
                const prefix = render.chunkPrefix(body.payload_len, &prefix_storage);
                assert(prefix.len <= start);
                start -= @intCast(prefix.len);
                @memcpy(buffer[start..][0..prefix.len], prefix);
                @memcpy(buffer[end..][0..render.chunk_suffix.len], render.chunk_suffix);
                end += @intCast(render.chunk_suffix.len);
            }
            if (chunked and body.client_ended) {
                @memcpy(buffer[end..][0..render.last_chunk.len], render.last_chunk);
                end += @intCast(render.last_chunk.len);
            }
            assert(start <= end);
            assert(end <= buffer.len);
            // A declared length, met: nothing is left to frame or send.
            if (start == end) return bodyForwarded(stream);
            body.frame_start = start;
            body.frame_end = end;
            body.frame_sent = 0;
            body.frame_payload = body.payload_len;
            body.frame_last = body.client_ended;
            // `bodyRoom` kept room behind the payload for the next frame's
            // size line or for the last chunk, not for both. A last frame
            // has no next one, so its headroom is not kept. The last chunk
            // may have taken that room, and a payload that filled the
            // buffer and ended the body would have put the next frame's
            // start past the buffer's end.
            body.payload_start = if (body.frame_last) end else end + headroom(stream);
            body.payload_len = 0;
            if (body.frame_last) assert(body.payload_start == end);
            assert(body.payload_start <= buffer.len);
            stream.l7.request_body_pumped = true;
            armBodySend(server, stream);
        }

        fn armBodySend(server: *ServerType, stream: *StreamType) void {
            const body = &stream.h2_body;
            assert(body.inFlight());
            assert(body.frame_start + body.frame_sent < body.frame_end);
            // A send on the upstream socket, never a read of the client's.
            stream.l7.request_op_on_client = false;
            stream.arm(&stream.op_data_client_to_upstream, "data_client_to_upstream");
            server.upstreamSend(
                stream,
                stream.relay_buffer.?.client_to_upstream[body.frame_start + body.frame_sent .. body.frame_end],
                &stream.op_data_client_to_upstream.completion,
                onBodySent,
            );
        }

        fn onBodySent(stream: *StreamType, result: Io.SendError!u32) void {
            const conn = stream.conn;
            const server = conn.server;
            stream.delivered(&stream.op_data_client_to_upstream, "data_client_to_upstream");
            if (server.exchangeOver(stream)) return;
            assert(stream.phase == .exchanging);
            assert(stream.l7.request_leg == .pumping_body);
            // A verdict forced this send's completion: it is settled here,
            // as the HTTP/1.1 body pump settles it (§8).
            if (stream.l7.pending_verdict != .none) return Proxy.settleVerdict(server, stream);
            const sent = result catch |err| {
                server.witnessKernelPressure(.send, err);
                return Proxy.failUpstream(server, stream);
            };
            const body = &stream.h2_body;
            body.frame_sent += sent;
            assert(body.frame_start + body.frame_sent <= body.frame_end);
            if (body.frame_start + body.frame_sent < body.frame_end) return armBodySend(server, stream);
            // The frame is out: its payload is the client's to send again.
            const mux = stream.mux;
            const credited = body.frame_payload;
            const last = body.frame_last;
            compactBody(stream);
            if (last) {
                bodyForwarded(stream);
            } else {
                frameAndSend(server, stream);
            }
            // HTTP/2: the window update goes out, and a frame held for room
            // is offered again. HTTP/3: the room is read into.
            creditClient(stream, credited);
            kick(server, conn, mux);
        }

        /// The frame in flight is gone: what gathered behind it moves to
        /// the front, where the next frame's payload starts.
        fn compactBody(stream: *StreamType) void {
            const body = &stream.h2_body;
            const buffer = stream.relay_buffer.?.client_to_upstream;
            const front = headroom(stream);
            assert(body.payload_start >= front);
            assert(body.payload_start + body.payload_len <= buffer.len);
            std.mem.copyForwards(u8, buffer[front..][0..body.payload_len], buffer[body.payload_start..][0..body.payload_len]);
            body.payload_start = front;
            body.frame_start = 0;
            body.frame_end = 0;
            body.frame_sent = 0;
            body.frame_payload = 0;
            body.frame_last = false;
        }

        /// The whole body reached the origin: the request leg is done.
        fn bodyForwarded(stream: *StreamType) void {
            assert(stream.h2_body.client_ended);
            assert(!stream.h2_body.inFlight());
            assert(stream.h2_body.payload_len == 0);
            stream.l7.request_leg = .done;
        }

        /// The response is whole while the request is still on its way: the
        /// client is told to stop sending (RST_STREAM(NO_ERROR), RFC 9113
        /// §8.1), and the exchange ends — a body send in flight forced, its
        /// upstream not one to park.
        pub fn finishAhead(server: *ServerType, stream: *StreamType) void {
            const conn = stream.conn;
            const mux = stream.mux;
            assert(stream.h2_ended);
            assert(stream.l7.request_leg != .done);
            stopClient(stream);
            server.endSharedStream(stream);
            kick(server, conn, mux);
        }

        /// The client reset a stream, or the session did for a stream error:
        /// it is gone from the session, and its exchange ends unanswered.
        pub fn onReset(server: *ServerType, conn: *ConnType, reset: *const Session.Step.Reset) void {
            assert(conn.state == .h2);
            // The session raises a reset only for a stream it delivered as
            // `.request` and the exchange has not let go of.
            const stream = find(conn, reset.stream).?;
            assert(stream.conn == conn);
            server.endSharedStream(stream);
        }

        /// An answer cut short can go on.
        pub fn onWritable(server: *ServerType, conn: *ConnType, id: u31) void {
            assert(conn.state == .h2);
            // Only a cut-short answer waits on the session, and it is the
            // exchange's until it ends.
            const stream = find(conn, id).?;
            assert(stream.phase == .responding or stream.phase == .exchanging);
            // A stream ending was reset first, and a reset one waits for
            // nothing: the session names no stream it has let go of.
            assert(!stream.ending);
            answer(server, stream);
        }

        /// The exchange on stream `id`, if this connection is running one.
        /// A scan of at most the advertised concurrency, once per event.
        pub fn find(conn: *ConnType, id: u31) ?*StreamType {
            assert(id != 0);
            assert(conn.h2 != null);
            const streams_max = conn.multiplexedMax();
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| : (cursor = stream.h2_next) {
                assert(visited < streams_max);
                visited += 1;
                if (stream.h2_id == id) return stream;
            }
            return null;
        }

        /// The exchange on HTTP/3 request stream `id` (#449), if this
        /// connection is running one: the same scan, by QUIC's identifier.
        pub fn findH3(conn: *ConnType, id: u62) ?*StreamType {
            assert(conn.h3 != null);
            const streams_max = conn.multiplexedMax();
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| : (cursor = stream.h2_next) {
                assert(visited < streams_max);
                visited += 1;
                assert(stream.mux == .h3);
                if (stream.h3_id == id) return stream;
            }
            return null;
        }
    };
}
