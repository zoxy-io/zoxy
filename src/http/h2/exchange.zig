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
//! the slot goes back (`Server.endSharedStream`). A request with a body is
//! refused with REFUSED_STREAM before anything is acquired for it (RFC
//! 9113 §8.7: no processing has occurred, so the client may retry) until
//! request bodies are forwarded.

const std = @import("std");
const h2 = @import("h2");

const constants = @import("../../constants.zig");
const parser = @import("../parser.zig");
const Session = @import("Session.zig");
const downgrade = @import("downgrade.zig");
const response = @import("response.zig");
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
            server.releaseSharedStream(stream);
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

        /// Request body octets, for an exchange that has none to forward
        /// them to yet: every exchange here is answered by §7 itself or
        /// refused, so the octets are read and dropped — consumed, so the
        /// client's window opens again while the answer goes out.
        pub fn discardData(conn: *ConnType, data: *const Session.Step.Data) void {
            assert(conn.state == .h2);
            assert(find(conn, data.stream) != null);
            if (data.bytes.len == 0) return;
            conn.h2.?.session.consume(data.stream, @intCast(data.bytes.len));
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
