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
//! What a stream becomes is `exchange.zig`'s: a request runs §7 on a
//! shared stream slot, and its answer comes back through the session. This
//! file only hands each stream event to the exchange it belongs to.

const std = @import("std");

const Session = @import("Session.zig");
const Exchange = @import("exchange.zig");
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
    /// The connection's own idle window (#275), apart from the deadlines
    /// of the exchanges it multiplexes: the connection's timer is aimed at
    /// whichever of them is first (`Server.storeH2IdleDeadline`).
    idle_deadline_ns: u64,
    /// A `drive` pass is running: what an exchange stages now is flushed
    /// when the pass ends, and `kick` must not start a second one inside it.
    driving: bool,
    /// A DATA frame's octets its exchange had no room for yet (#275): the
    /// session's, borrowed until its next step — so the session is neither
    /// stepped nor read into until the exchange has taken them all, which
    /// is a stream's backpressure on its whole connection. Only before the
    /// client applies this side's window can a stream be sent more than its
    /// buffer holds (RFC 9113 §6.9.2), so in steady state this stays null.
    /// While it is not, nothing else on the connection is read — the
    /// exchange's next send, bounded by its deadline, is what frees it.
    held: ?Session.Step.Data,

    /// Back to the state a fresh connection finds it in. The carve stays:
    /// it is the slab's layout, not the connection's.
    pub fn reset(slot: *Slot) void {
        slot.backlog = &.{};
        slot.sending = 0;
        slot.receiving = false;
        slot.closing = false;
        slot.idle_deadline_ns = 0;
        slot.driving = false;
        slot.held = null;
        assert(slot.buffers.inbound.len >= Session.frame_bytes_max);
    }
};

pub fn Driver(comptime IoType: type) type {
    const ServerType = @import("../../Server.zig").Server(IoType);
    const ConnType = @import("../../net/Conn.zig").Conn(IoType);
    const StreamType = ConnType.StreamType;
    const ExchangeType = Exchange.Exchange(IoType);

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

        /// The connection's timer is due. It serves the connection's own
        /// idle window and every multiplexed exchange's deadline (#275), so
        /// what is due is found by looking: each exchange past its deadline
        /// gets §8's verdict, and the connection itself expires only once
        /// its window is past with nothing open — or its lifetime is up,
        /// open or not. A connection with exchanges in flight is not idle,
        /// so its window starts over. The timer is re-armed at what is next.
        pub fn expire(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .h2);
            assert(!conn.armed.deadline); // Delivered; re-armed only below.
            const slot = conn.h2.?;
            const now = server.io.nowNs();
            const idle_due = now >= slot.idle_deadline_ns;
            if (idle_due and (conn.h2_streams == null or server.lifetimeOver(conn))) {
                server.counters.increment("deadline_expired");
                return server.beginTeardown(conn);
            }
            if (idle_due) server.storeH2IdleDeadline(conn);
            // A pass, as far as `kick` can tell: an expiry that resets its
            // stream stages a frame, and a session stepped now could end
            // other streams, or the connection, under this scan. What the
            // expiries staged goes out in one pass after it.
            slot.driving = true;
            const streams_max = slot.session.config.concurrent_streams_max;
            var cursor = conn.h2_streams;
            var visited: u32 = 0;
            while (cursor) |stream| {
                assert(visited < streams_max);
                visited += 1;
                // Taken first: an expiry can end its own exchange and give
                // the slot back — its own, and no other.
                cursor = stream.h2_next;
                if (stream.ending or stream.deadline_ns == 0) continue;
                if (now < stream.deadline_ns) continue;
                server.counters.increment("deadline_expired");
                ServerType.Proxy.expireExchange(server, stream);
            }
            slot.driving = false;
            assert(conn.state == .h2);
            ServerType.refreshH2Deadline(conn);
            if (!conn.armed.deadline and !conn.armed.deadline_cancel) server.armDeadline(conn);
            kick(server, conn);
        }

        /// An exchange staged frames from outside a `drive` pass — an
        /// origin's completion answered its stream, or ended it — so step
        /// the session and send them. Inside a pass, the pass sends them.
        pub fn kick(server: *ServerType, conn: *ConnType) void {
            // Torn down: nothing goes out. Still the caller's slot to read —
            // a teardown releases it only once its armed set is empty, and
            // a speaking connection always has its read armed.
            if (conn.state != .h2) return;
            assert(conn.h2 != null);
            const slot = conn.h2.?;
            if (slot.driving) return;
            if (slot.closing) return; // `close` is already sending its last.
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
            server.storeH2IdleDeadline(conn);
            assert(stream.phase == .none);
        }

        /// Step the session until it waits on the socket, then make sure
        /// it is waiting on the right thing: a read when it wants input
        /// and has no backlog, a send when it has something staged.
        fn drive(server: *ServerType, conn: *ConnType) void {
            assert(conn.state == .h2);
            const slot = conn.h2.?;
            assert(!slot.driving);
            slot.driving = true;
            defer slot.driving = false;
            // A frame held for room goes first: the session cannot step past
            // it, and while it waits, what is staged still goes out.
            if (!offerHeld(server, conn, slot)) return flush(server, conn, slot);
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
                    .request => |request| ExchangeType.open(server, conn, &request),
                    .data => |data| {
                        slot.held = data;
                        if (!offerHeld(server, conn, slot)) return flush(server, conn, slot);
                    },
                    .trailers => |trailers| ExchangeType.onTrailers(server, conn, &trailers),
                    .reset => |reset| ExchangeType.onReset(server, conn, &reset),
                    .writable => |writable| ExchangeType.onWritable(server, conn, writable.stream),
                }
                // What fails on a stream ends the stream, never the
                // connection: an exchange resets, and the session goes on.
                assert(!conn.isTearingDown());
            }
        }

        /// Hand the held frame's octets to their exchange, as many as it has
        /// room for. True once none are held — the session may step on.
        fn offerHeld(server: *ServerType, conn: *ConnType, slot: *Slot) bool {
            const held = slot.held orelse return true;
            assert(slot.session.state != .closed);
            const taken = ExchangeType.onData(server, conn, &held);
            assert(taken <= held.bytes.len);
            if (taken == held.bytes.len) {
                slot.held = null;
                return true;
            }
            slot.held = .{
                .stream = held.stream,
                .bytes = held.bytes[taken..],
                .end_stream = held.end_stream,
            };
            return false;
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
                server.returnHeadBuffer(conn.stream);
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
            server.storeH2IdleDeadline(conn);
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
            // The client's close_notify: it will write no more. HTTP/2 has
            // no half-closed connection — a client done with one says
            // GOAWAY first (RFC 9113 §6.8) — so this ends the connection,
            // and whatever it had open with it, as a socket EOF would.
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
