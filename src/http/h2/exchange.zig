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
/// the buffer, nor leaves the next payload's start there (#275).
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
pub fn requestWindow(relay_buffer_bytes: u32) u31 {
    assert(relay_buffer_bytes > body_framing_bytes);
    const window = @min(relay_buffer_bytes - body_framing_bytes, Session.window_default);
    assert(window >= 1);
    return @intCast(window);
}

comptime {
    // The last chunk fits where the next frame's headroom would.
    assert(chunk_tail_bytes >= render.chunk_suffix.len + render.last_chunk.len);
    // Any legal relay buffer leaves a window.
    assert(constants.relay_buffer_bytes_min > body_framing_bytes);
}

pub fn Exchange(comptime IoType: type) type {
    const ServerType = @import("../../Server.zig").Server(IoType);
    const ConnType = @import("../../net/Conn.zig").Conn(IoType);
    const StreamType = ConnType.StreamType;

    return struct {
        // A declaration rather than a capture above: `Proxy(IoType)` names
        // this type in its own body, so evaluating it eagerly here would be
        // a type whose definition needs itself.
        const Proxy = @import("../proxy.zig").Proxy(IoType);
        const Driver = @import("Connection.zig").Driver(IoType);

        /// A stream opened with a well-formed request: a shared slot and a
        /// head buffer for it, its request written out as the HTTP/1.1
        /// head it stands for, and §7 begun on that — or REFUSED_STREAM
        /// when there is no slot to run it on, which the client may retry.
        pub fn open(server: *ServerType, conn: *ConnType, request: *const Session.Step.Request) void {
            assert(conn.state == .h2);
            const session = conn.h2.?.session;
            const stream = server.acquireSharedStream(conn, request.stream) orelse {
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
            const head = downgrade.requestHead(request, stream.h2_head.?.data, storage) catch |err| {
                return Proxy.refuseH2Request(server, stream, err);
            };
            Proxy.serveH2Request(server, stream, &head);
        }

        /// Hand the session what the exchange's answer has left to say: its
        /// head, once, then its body — END_STREAM with the last of it.
        /// Called where the HTTP/1.1 path would arm a send
        /// (`Proxy.armClientWrite`), and again from `.writable` for an
        /// answer the session could not take whole. An interim head goes
        /// alone, and the final one is still to come after it.
        pub fn answer(server: *ServerType, stream: *StreamType) void {
            const conn = stream.conn;
            // The answer can finish the stream and give its slot back, so
            // only the connection is read after it.
            stage(server, stream);
            Driver.kick(server, conn);
        }

        /// `answer`'s staging, without the send: the caller kicks.
        fn stage(server: *ServerType, stream: *StreamType) void {
            const session = stream.conn.h2.?.session;
            assert(stream.h2_id != 0);
            assert(stream.phase == .responding or stream.phase == .exchanging);
            assert(!stream.h2_ended);
            if (!stream.h2_head_staged) {
                if (!stageHead(server, stream, session)) return;
            }
            const write = &stream.client_write;
            const ends = answerEnds(stream);
            if (write.pending.len >= 1 or (ends and !stream.h2_ended)) {
                const sent = session.sendData(stream.h2_id, write.pending, ends);
                assert(sent.taken <= write.pending.len);
                write.pending = write.pending[sent.taken..];
                stream.log.bytes_out += sent.taken;
                stream.h2_ended = sent.ended;
                // The client took body octets: activity, as a send's
                // completion is on the HTTP/1.1 path (§6).
                if (sent.taken >= 1) server.storeExchangeDeadline(stream, server.idleTimeoutMs());
                // Cut short by the window or the outbox: `.writable` resumes.
                if (write.pending.len >= 1) return;
                if (ends and !sent.ended) return;
            }
            Proxy.h2WriteDelivered(server, stream);
        }

        /// Whether what the answer has left ends the stream: a static answer
        /// always; a proxied one once nothing of its body is left to come —
        /// no excess still to hand over, and the origin's framing done.
        fn answerEnds(stream: *const StreamType) bool {
            assert(stream.h2_id != 0);
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
        fn stageHead(server: *ServerType, stream: *StreamType, session: *Session) bool {
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
            const ends = body.len == 0 and answerEnds(stream);
            switch (session.sendHead(stream.h2_id, mapped.fields, ends)) {
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
        pub fn pumpBody(server: *ServerType, stream: *StreamType) void {
            assert(stream.phase == .exchanging);
            assert(stream.l7.response_leg == .pumping_body);
            assert(stream.client_write.pending.len == 0);
            stream.arm(&stream.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.recv(
                stream.upstream_socket.?,
                stream.relay_buffer.?.upstream_to_client,
                &stream.op_data_upstream_to_client.completion,
                StreamType,
                stream,
                onBodyRecv,
            );
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
            const chunk = stream.relay_buffer.?.upstream_to_client[0..received];
            const fed = Proxy.payloadFraming(&stream.l7.response_framing, chunk, true);
            if (fed.feed.malformed) return fail(server, stream);
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
            const session = stream.conn.h2.?.session;
            assert(stream.client_write.pending.len == 0);
            assert(stream.log.emitted or server.access_log.sink == null);
            assert(stream.h2_ended);
            if (session.awaitingClient(stream.h2_id)) {
                session.resetStream(stream.h2_id, .no_error);
            }
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
            const session = stream.conn.h2.?.session;
            assert(code != .no_error);
            assert(stream.h2_id != 0);
            const conn = stream.conn;
            if (session.resettable(stream.h2_id)) session.resetStream(stream.h2_id, code);
            server.endSharedStream(stream);
            Driver.kick(server, conn);
        }

        /// The exchange failed after it began (an origin that broke off, a
        /// body that would not frame): INTERNAL_ERROR (RFC 9113 §7), which
        /// says nothing about whether the request was processed.
        pub fn fail(server: *ServerType, stream: *StreamType) void {
            assert(stream.h2_id != 0);
            assert(!stream.ending);
            abandon(server, stream, .internal_error);
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
            if (!forwarding(stream)) return drop(conn, data);
            const body = &stream.h2_body;
            // The first payload sits where a frame's starts: past room for
            // its chunk size line, which goes in front of it when it is sent.
            // Zero is that place for a declared length, so setting it again
            // there changes nothing.
            if (body.payload_start == 0) body.payload_start = headroom(stream);
            const take = @min(bodyRoom(stream), length);
            assert(take <= length);
            const buffer = stream.relay_buffer.?.client_to_upstream;
            @memcpy(buffer[body.payload_start + body.payload_len ..][0..take], data.bytes[0..take]);
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
            if (take == length and data.end_stream) body.client_ended = true;
            if (stream.l7.request_leg == .pumping_body) frameAndSend(server, stream);
            return take;
        }

        /// The request's trailer section ends the client's half. It is not
        /// carried: the chunked body's last chunk goes out with none, as
        /// an origin's trailers do not come back either (#275).
        pub fn onTrailers(server: *ServerType, conn: *ConnType, trailers: *const Session.Step.Trailers) void {
            assert(conn.state == .h2);
            const stream = find(conn, trailers.stream) orelse return;
            if (!forwarding(stream)) return;
            stream.h2_body.client_ended = true;
            if (stream.l7.request_leg == .pumping_body) frameAndSend(server, stream);
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
        fn forwarding(stream: *const StreamType) bool {
            assert(stream.h2_id != 0);
            if (stream.ending) return false;
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
            body.payload_start = end + headroom(stream);
            body.payload_len = 0;
            // `bodyRoom` kept the next frame's headroom behind this one.
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
            server.io.send(
                stream.upstream_socket.?,
                stream.relay_buffer.?.client_to_upstream[body.frame_start + body.frame_sent .. body.frame_end],
                &stream.op_data_client_to_upstream.completion,
                StreamType,
                stream,
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
            if (body.frame_payload >= 1) conn.h2.?.session.consume(stream.h2_id, body.frame_payload);
            const last = body.frame_last;
            compactBody(stream);
            if (last) {
                bodyForwarded(stream);
            } else {
                frameAndSend(server, stream);
            }
            // The window update goes out, and a frame held for room is
            // offered again.
            Driver.kick(server, conn);
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
            const session = conn.h2.?.session;
            assert(stream.h2_ended);
            assert(stream.l7.request_leg != .done);
            if (session.awaitingClient(stream.h2_id)) session.resetStream(stream.h2_id, .no_error);
            server.endSharedStream(stream);
            Driver.kick(server, conn);
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
            const streams_max = conn.h2.?.session.config.concurrent_streams_max;
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| : (cursor = stream.h2_next) {
                assert(visited < streams_max);
                visited += 1;
                if (stream.h2_id == id) return stream;
            }
            return null;
        }
    };
}
