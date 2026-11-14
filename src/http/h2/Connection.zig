//! One HTTP/2 connection's I/O (#275): the sans-I/O `Session` given a
//! socket, a clock and a place in the server's lifecycle. `Session` decides
//! what the connection says; this moves the octets, and nothing else.
//!
//! It runs on the connection's admission stream — the one every connection
//! is admitted with (#274) — whose two data ops become the socket's one
//! recv and one send. That stream runs no exchange of its own on an HTTP/2
//! connection (its phase stays `.none`), which is what keeps §8's ring
//! charge per admitted connection exactly where it was: the multiplexed
//! exchanges draw their own streams from the shared pool, charged apart.
//!
//! The cycle is strict, as the L4 pump's is: at most one recv and one send
//! in flight, the session stepped after each completes until it asks for
//! input, for a flush, or is done. Plaintext reaches the session from a
//! backlog before the socket is read again — an h2c connection's opening
//! octets, which the HTTP/1.1 head read already pulled into a head buffer
//! when the preface was recognized there, or a terminated connection's
//! decrypted records.
//!
//! Over TLS (RFC 9113 §3.2, `h2` selected in ALPN) the same two ops carry
//! ciphertext. A read lands in the engine's record buffer and decrypts into
//! the engine's plaintext buffer, which becomes the backlog; a send seals
//! the session's staged octets a record's worth at a time and carries the
//! engine's outbox. Nothing about the session changes: it never learns its
//! octets were encrypted.
//!
//! What a stream becomes is the next slice's: until the exchange runs on a
//! shared stream, every request is refused with REFUSED_STREAM (RFC 9113
//! §8.7, "no processing has occurred"), so this is a conforming HTTP/2
//! connection that serves nothing — gated on its own before the exchange
//! is wired through it.

const std = @import("std");

const Session = @import("Session.zig");
const Io = @import("../../io/io.zig");
const TlsEngine = @import("../../tls/Engine.zig");
const constants = @import("../../constants.zig");

const assert = std.debug.assert;

/// RFC 9113 §3.4's client preface, for the h2c sniff that hands a
/// connection here.
pub const preface = Session.preface;

/// The session pool's element (§5): one carved unit — the session and its
/// buffers, laid out once at `Server.init` — and this connection's place
/// in the I/O cycle around it.
pub const Slot = struct {
    pool_next: u32,
    generation: u32,
    /// What `Session.Layout.carve` made of this slot's unit of the slab.
    /// Wired once, never moved; `Session.init` resets it per connection.
    session: *Session,
    buffers: Session.Buffers,
    /// Plaintext not yet handed to the session, borrowed from where it
    /// landed: an h2c connection's opening octets from the head buffer that
    /// read them, which goes back once this is empty, or a terminated
    /// connection's decrypted records from the engine's plaintext buffer,
    /// which the next read decrypts into — so it is read only once this
    /// is empty.
    backlog: []const u8,
    /// Octets the send in flight carries — of `session.outbound()`, or of
    /// the engine's outbox over TLS; zero when none is.
    sending: u32,
    receiving: bool,
    /// The session is done: once what it staged is sent — its GOAWAY, if
    /// it ended the connection — the connection is torn down.
    closing: bool,

    /// Back to the state a fresh connection finds it in. The carve stays:
    /// it is the slab's layout, not the connection's.
    pub fn reset(slot: *Slot) void {
        slot.backlog = &.{};
        slot.sending = 0;
        slot.receiving = false;
        slot.closing = false;
        assert(slot.buffers.inbound.len >= Session.frame_bytes_max);
    }
};

pub fn Driver(comptime IoType: type) type {
    const ServerType = @import("../../Server.zig").Server(IoType);
    const ConnType = @import("../../net/Conn.zig").Conn(IoType);
    const StreamType = ConnType.StreamType;

    return struct {
        /// The most session steps one completion runs before it must have
        /// returned: each consumes a frame, answers a stream, or returns,
        /// so the real bound is the input; this is the one asserted.
        const drive_passes_max: u32 = 1 << 20;

        /// h2c by prior knowledge (RFC 9113 §3.3): `stream`'s head buffer
        /// begins with the preface, so the connection speaks HTTP/2 from
        /// its first octet, and those octets are the session's opening.
        /// A connection that cannot get a session is closed — it said it
        /// speaks HTTP/2, and HTTP/1.1 has no answer it would read.
        pub fn startH2c(server: *ServerType, stream: *StreamType, opening: []const u8) void {
            const conn = stream.conn;
            assert(conn.tls == null);
            assert(conn.h2c);
            assert(opening.len >= Session.preface.len);
            const slot = server.acquireH2Session() orelse {
                server.counters.increment("h2_shed_sessions");
                server.beginTeardown(conn);
                return;
            };
            assert(conn.h2 == null);
            conn.h2 = slot;
            begin(server, conn);
            slot.backlog = opening;
            // Admitted before a drain, speaking after it: `beginDrain` only
            // reached the connections already speaking HTTP/2, so this one
            // is owed its GOAWAY now, before it can open anything.
            if (server.draining) slot.session.goAway();
            drive(server, conn);
        }

        /// HTTP/2 over TLS (RFC 9113 §3.2): the handshake selected `h2`.
        /// The listener offers it only with a session reserved at admission
        /// (`Server.acquireTlsAdmission`), so this one has a session, and
        /// whatever plaintext the client sent behind its Finished — its
        /// preface, often — is the session's opening.
        pub fn startTls(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .tls_handshaking);
            const engine = conn.tls.?;
            assert(engine.alpnSelected().? == .h2);
            assert(engine.outbound().len == 0); // The handshake's flight is out.
            const slot = conn.h2.?;
            begin(server, conn);
            assert(conn.tls_pending_len <= engine.plaintext.len);
            slot.backlog = engine.plaintext[0..conn.tls_pending_len];
            conn.tls_pending_len = 0;
            // As for h2c: a drain that began during the handshake found no
            // HTTP/2 connection here to tell.
            if (server.draining) slot.session.goAway();
            drive(server, conn);
        }

        /// The server is draining (§8): end gracefully — GOAWAY(NO_ERROR),
        /// the streams already accepted finished, nothing new taken.
        pub fn beginDrain(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .h2);
            const slot = conn.h2.?;
            if (slot.closing) return;
            slot.session.goAway();
            drive(server, conn);
        }

        /// The connection becomes an HTTP/2 one, on the session the caller
        /// put in `conn.h2`: the session reset, the admission stream's
        /// HTTP/1.1 bookkeeping cleared — an h2c head read that recognized
        /// the preface began a request that never was, and left a log line
        /// and a head budget behind it.
        fn begin(server: *ServerType, conn: *ConnType) void {
            const slot = conn.h2.?;
            slot.reset();
            conn.enter(.h2);
            const stream = conn.stream;
            stream.log = .{};
            stream.l7 = .{};
            stream.head_cursor.reset();
            server.counters.increment("h2_connections");
            slot.session.init(server.h2SessionConfig(), &slot.buffers);
            // The idle window, not the head budget a slow preface earned:
            // an HTTP/2 connection is idle between frames, and §4's lazy
            // timer moves later on its own.
            server.storeDeadline(conn, server.idleTimeoutMs());
            assert(stream.phase == .none);
        }

        /// Step the session until it waits on the socket, then make sure
        /// it is waiting on the right thing: a read when it wants input
        /// and has no backlog, a send when it has something staged.
        fn drive(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .h2);
            const slot = conn.h2.?;
            var passes: u32 = 0;
            while (true) : (passes += 1) {
                assert(passes < drive_passes_max);
                switch (slot.session.step()) {
                    .need_input => {
                        if (slot.backlog.len >= 1) {
                            feedBacklog(server, conn, slot);
                            continue;
                        }
                        flush(server, conn, slot);
                        if (conn.isTearingDown()) return; // A seal failed.
                        if (slot.receiving) return;
                        if (recvRoom(conn)) return armRecv(server, conn, slot);
                        // The outbox is short of what a read may stage, so
                        // it holds ciphertext — which `flush` just sent —
                        // and the send's completion comes back here.
                        assert(slot.sending >= 1);
                        return;
                    },
                    // The outbox is full: the send completion steps again.
                    .flush_first => return flush(server, conn, slot),
                    .closed => return close(server, conn, slot),
                    // No exchange runs on a shared stream yet (#275's next
                    // slice), so a request is refused before it is worked
                    // on — REFUSED_STREAM, which the client may retry.
                    .request => |request| slot.session.resetStream(request.stream, .refused_stream),
                    // A refused stream raises nothing after its reset, and
                    // nothing here sends a body to wait on.
                    .data, .trailers, .reset, .writable => unreachable,
                }
            }
        }

        /// As much of the backlog as the session has room for, now; the
        /// head buffer it borrows goes back once it is all handed over.
        fn feedBacklog(server: *ServerType, conn: *ConnType, slot: *Slot) void {
            assert(slot.backlog.len >= 1);
            const room = slot.session.recvBuffer();
            const take = @min(room.len, slot.backlog.len);
            assert(take >= 1);
            @memcpy(room[0..take], slot.backlog[0..take]);
            slot.session.received(@intCast(take));
            slot.backlog = slot.backlog[take..];
            if (slot.backlog.len == 0 and conn.stream.head_buffer_id != StreamType.head_buffer_none) {
                server.returnHeadBuffer(conn);
            }
        }

        /// Whether a read may be armed: over TLS, decrypting may stage a
        /// KeyUpdate's answer behind a record still going out, and the
        /// engine demands room for that up front — the gate the L7 and L4
        /// paths put on their reads too.
        fn recvRoom(conn: *const ConnType) bool {
            assert(conn.state == .h2);
            assert(conn.h2 != null);
            const engine = conn.tls orelse return true;
            return engine.outboundRoom() >= TlsEngine.emitted_record_bytes_max;
        }

        fn armRecv(server: *ServerType, conn: *ConnType, slot: *Slot) void {
            assert(!slot.receiving);
            assert(slot.backlog.len == 0);
            assert(recvRoom(conn));
            const stream = conn.stream;
            slot.receiving = true;
            stream.arm(&stream.op_data_client_to_upstream, "data_client_to_upstream");
            server.io.recv(
                conn.client_socket,
                if (conn.tls) |engine| engine.recvBuffer() else slot.session.recvBuffer(),
                &stream.op_data_client_to_upstream.completion,
                StreamType,
                stream,
                onRecv,
            );
        }

        fn onRecv(stream: *StreamType, result: Io.RecvError!u32) void {
            const conn = stream.conn;
            const server = conn.server;
            stream.delivered(&stream.op_data_client_to_upstream, "data_client_to_upstream");
            // The slot is the connection's until teardown releases it, which
            // waits for this very delivery — so the op's flag is cleared
            // before anything else, teardown included.
            const slot = conn.h2.?;
            assert(slot.receiving);
            slot.receiving = false;
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            const received = result catch |err| {
                // The client left, or the kernel refused: either way the
                // connection is over, and what it had open with it.
                server.witnessKernelPressure(.recv, err);
                server.beginTeardown(conn);
                return;
            };
            assert(received >= 1);
            if (conn.tls) |engine| {
                if (!decrypt(server, conn, slot, engine, received)) return;
            } else {
                slot.session.received(received);
            }
            server.storeDeadline(conn, server.idleTimeoutMs());
            drive(server, conn);
        }

        /// A terminated connection's read landed in the engine's record
        /// buffer: what it decrypts to becomes the backlog. False when it
        /// ended the connection instead.
        fn decrypt(
            server: *ServerType,
            conn: *ConnType,
            slot: *Slot,
            engine: *TlsEngine,
            received: u32,
        ) bool {
            assert(slot.backlog.len == 0); // The buffer below is free.
            var plaintext: Plaintext = .{ .engine = engine };
            const sink = plaintext.sink();
            engine.received(received, &sink) catch {
                server.counters.increment("tls_relay_failed");
                server.beginTeardown(conn);
                return false;
            };
            // The client's close_notify: it will write no more. Nothing it
            // opened is being served — every stream is refused — so there
            // is nothing left to answer, and the connection ends as a
            // socket EOF would end it.
            if (engine.peerClosed()) {
                server.beginTeardown(conn);
                return false;
            }
            slot.backlog = engine.plaintext[0..plaintext.len];
            return true;
        }

        /// One send in flight at a time, carrying whatever is staged: the
        /// session never moves staged octets, so the slice stays valid
        /// while it appends more behind them.
        fn flush(server: *ServerType, conn: *ConnType, slot: *Slot) void {
            if (slot.sending >= 1) return;
            const staged = if (conn.tls) |engine|
                seal(server, conn, slot, engine)
            else
                slot.session.outbound();
            if (staged.len == 0) return;
            const stream = conn.stream;
            slot.sending = @intCast(staged.len);
            stream.arm(&stream.op_data_upstream_to_client, "data_upstream_to_client");
            server.io.send(
                conn.client_socket,
                staged,
                &stream.op_data_upstream_to_client.completion,
                StreamType,
                stream,
                onSend,
            );
        }

        fn onSend(stream: *StreamType, result: Io.SendError!u32) void {
            const conn = stream.conn;
            const server = conn.server;
            stream.delivered(&stream.op_data_upstream_to_client, "data_upstream_to_client");
            const slot = conn.h2.?;
            assert(slot.sending >= 1);
            const carried = slot.sending;
            slot.sending = 0; // As `onRecv`'s flag: before teardown can look.
            if (conn.isTearingDown()) {
                server.continueTeardown(conn);
                return;
            }
            const sent = result catch |err| {
                server.witnessKernelPressure(.send, err);
                server.beginTeardown(conn);
                return;
            };
            assert(sent >= 1);
            assert(sent <= carried);
            if (conn.tls) |engine| {
                engine.outboundSent(sent);
            } else {
                slot.session.outboundSent(sent);
            }
            if (slot.closing) return close(server, conn, slot);
            // Room came back, which is what a session waiting to flush, or
            // a stream waiting to send, was waiting for.
            drive(server, conn);
        }

        /// The session is over: send what it staged — its GOAWAY, if it
        /// ended the connection — and then end the connection.
        fn close(server: *ServerType, conn: *ConnType, slot: *Slot) void {
            slot.closing = true;
            flush(server, conn, slot);
            if (conn.isTearingDown()) return; // A seal failed.
            if (slot.sending >= 1) return; // `onSend` comes back here.
            assert(slot.session.outbound().len == 0);
            if (conn.tls) |engine| assert(engine.outbound().len == 0);
            server.beginTeardown(conn);
        }

        /// What a terminated connection sends next: ciphertext already
        /// staged — a short send's remainder, or a KeyUpdate's answer — or
        /// else the session's next record's worth, sealed now. Sealed
        /// octets are spent as far as the session is concerned: the record
        /// carries them from here, so its outbox can take more while the
        /// record is in flight. Empty when there is nothing to send, and
        /// when sealing failed, which tears the connection down.
        fn seal(server: *ServerType, conn: *ConnType, slot: *Slot, engine: *TlsEngine) []const u8 {
            assert(slot.sending == 0);
            if (engine.outbound().len >= 1) return engine.outbound();
            const plaintext = slot.session.outbound();
            if (plaintext.len == 0) return &.{};
            const chunk: u32 = @intCast(@min(plaintext.len, constants.tls_app_chunk_bytes));
            engine.sendApp(plaintext[0..chunk]) catch {
                server.counters.increment("tls_relay_failed");
                server.beginTeardown(conn);
                return &.{};
            };
            slot.session.outboundSent(chunk);
            assert(engine.outbound().len > chunk); // A record's header and tag.
            return engine.outbound();
        }

        /// Where a read's decrypted records land: the engine's plaintext
        /// buffer, from its front, which the backlog then borrows. One read
        /// decrypts at most what it completes plus the record it carried
        /// over — `TlsEngine.plaintext_bytes_min`, which the buffer is at
        /// least — so it always fits.
        const Plaintext = struct {
            engine: *TlsEngine,
            len: u32 = 0,

            fn sink(self: *Plaintext) TlsEngine.Sink {
                return .{ .ctx = self, .appData = append, .closed = closed };
            }

            fn append(ctx: *anyopaque, bytes: []const u8) void {
                const self: *Plaintext = @ptrCast(@alignCast(ctx));
                // RFC 8446 §6.1: anything after a close_notify is ignored,
                // and `decrypt` ends the connection on one anyway.
                if (self.engine.peerClosed()) return;
                const buffer = self.engine.plaintext;
                assert(self.len + bytes.len <= buffer.len);
                std.mem.copyForwards(u8, buffer[self.len..][0..bytes.len], bytes);
                self.len += @intCast(bytes.len);
            }

            fn closed(ctx: *anyopaque) void {
                // Recorded on the engine, which `decrypt` asks once the
                // records are walked; ending the connection here would do
                // it underneath the engine still walking them.
                _ = ctx;
            }
        };
    };
}
