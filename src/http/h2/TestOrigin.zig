//! An HTTP/2 origin for the scenarios outside `src/http/h2/` (§7, §9): h2c
//! by prior knowledge, on `Session`'s server role, answering every stream
//! with a scripted head, body and trailer section once the request has
//! ended — and recording what it was asked, so a scenario can assert what
//! an origin reached over HTTP/2 actually heard. Test support: nothing in
//! the server imports it. It lives here because only this directory may
//! import `h2`, and its fields cross the boundary as plain pairs.

const std = @import("std");
const h2 = @import("h2");

const Session = @import("Session.zig");
const StreamTable = @import("StreamTable.zig");
const Io = @import("../../io/io.zig");
const TestTlsServer = @import("../../tls/TestTlsServer.zig");

const hpack = h2.hpack;
const assert = std.debug.assert;

/// A field as a scenario writes it.
pub const Pair = [2][]const u8;

/// Four connections: what a directed scenario dials.
pub fn TestOrigin(comptime IoType: type) type {
    return TestOriginSized(IoType, 4);
}

/// `TestOrigin` holding `conns_max` connections at once — a sweep whose
/// proxy redials under an adversary needs more than a scenario does — and
/// reusing a slot once its connection is closed and its socket released.
/// A dial past them all is closed at once and counted (`refused`).
pub fn TestOriginSized(comptime IoType: type, comptime conns_max_value: u32) type {
    comptime assert(conns_max_value >= 1);
    return struct {
        io: *IoType = undefined,
        listener: IoType.Listener = undefined,
        accept_completion: IoType.Completion = .{},
        listening: bool = false,
        conns: [conns_max]Conn = @splat(.{}),
        accepted_count: u32 = 0,
        /// Slots in use or ever used, at most `conns_max`.
        slots_used: u32 = 0,
        /// Dials closed at once because every slot was still busy.
        refused: u32 = 0,
        /// Requests no job was free for, so never answered: a muted or
        /// unended stream holds a job until its stream is reset.
        requests_dropped: u32 = 0,

        // -- the script --
        status: []const u8 = "200",
        headers: []const Pair = &.{},
        body: []const u8 = "",
        trailers: []const Pair = &.{},
        /// Read every request, and answer none.
        mute: bool = false,
        /// Read every request whose path begins with this, and answer none
        /// of those: a call left to its deadline beside streams that are
        /// answered. Empty mutes nothing.
        mute_path_prefix: []const u8 = "",
        /// Answer with the head and the body, and never end the stream.
        stall_after_body: bool = false,
        /// Answer at the request's head — the head and the body while the
        /// request is still arriving — and end only once it has: a
        /// bidirectional call's shape.
        answer_at_head: bool = false,
        /// Terminate TLS in front of the session, serving the origin trust
        /// fixtures' leaf, and select from `tls_alpn` — `h2`, or nothing.
        tls: bool = false,
        tls_alpn: []const []const u8 = &.{"h2"},
        tls_servers: []TestTlsServer = &.{},
        /// Handshakes that failed on this side.
        tls_failures: u32 = 0,
        /// Refuse every stream past the first with GOAWAY naming it, the
        /// shape of an origin draining under a client.
        goaway_after_first: bool = false,

        // -- what it heard --
        requests: u32 = 0,
        answered: u32 = 0,
        /// The last request's pseudo-headers and a few fields, as received.
        last_method: Text = .{},
        last_path: Text = .{},
        last_authority: Text = .{},
        last_te: Text = .{},
        last_content_type: Text = .{},
        /// Its body's octets, and the first of them.
        last_body: Text = .{},
        last_body_len: u64 = 0,

        const Self = @This();
        pub const conns_max: u32 = conns_max_value;
        const streams_max: u32 = 16;
        const layout: Session.Layout = .{ .header_list_size_max = 8192, .concurrent_streams_max = streams_max };

        pub const Text = struct {
            bytes: [128]u8 = undefined,
            len: usize = 0,

            pub fn slice(text: *const Text) []const u8 {
                return text.bytes[0..text.len];
            }

            fn set(text: *Text, value: []const u8) void {
                text.len = @min(value.len, text.bytes.len);
                @memcpy(text.bytes[0..text.len], value[0..text.len]);
            }

            fn append(text: *Text, value: []const u8) void {
                const take = @min(value.len, text.bytes.len - text.len);
                @memcpy(text.bytes[text.len..][0..take], value[0..take]);
                text.len += take;
            }
        };

        const Job = struct {
            stream: u31 = 0,
            started: bool = false,
            request_ended: bool = false,
            head_sent: bool = false,
            body_offset: usize = 0,
            /// Its path is under `mute_path_prefix`: it is never answered.
            muted: bool = false,
        };

        pub const Conn = struct {
            origin: *Self = undefined,
            socket: IoType.Socket = undefined,
            recv_completion: IoType.Completion = .{},
            send_completion: IoType.Completion = .{},
            session: *Session = undefined,
            buffers: Session.Buffers = undefined,
            receiving: bool = false,
            sending: u32 = 0,
            closed: bool = false,
            /// The socket is released: `closed` and no op still out on it.
            socket_closed: bool = false,
            jobs: [streams_max]Job = @splat(.{}),
            tls: ?*TestTlsServer = null,

            fn drive(conn: *Conn) void {
                if (conn.closed) return;
                var rounds: u32 = 0;
                while (rounds < 64) : (rounds += 1) {
                    const waiting = conn.stepAll();
                    const tls = conn.tls orelse break;
                    if (!waiting or tls.plaintext_len == 0) break;
                    const taken = tls.takePlaintext(conn.session.recvBuffer());
                    conn.session.received(taken);
                    tls.process() catch return conn.tlsFailed();
                }
                conn.flush();
                if (conn.session.state == .closed and conn.sending == 0) return conn.close();
                if (!conn.receiving and conn.session.state != .closed) conn.armRecv();
            }

            fn tlsFailed(conn: *Conn) void {
                conn.origin.tls_failures += 1;
                conn.close();
            }

            /// Step until the session waits; true when it waits for input.
            fn stepAll(conn: *Conn) bool {
                var passes: u32 = 0;
                while (passes < 1 << 16) : (passes += 1) {
                    const step = conn.session.step();
                    switch (step) {
                        .need_input => return true,
                        .flush_first, .closed => return false,
                        .request => |request| conn.onRequest(&request),
                        .data => |data| {
                            if (data.bytes.len >= 1) conn.session.consume(data.stream, @intCast(data.bytes.len));
                            conn.origin.last_body_len += data.bytes.len;
                            conn.origin.last_body.append(data.bytes);
                            if (data.end_stream) conn.requestEnded(data.stream);
                        },
                        .trailers => |trailers| conn.requestEnded(trailers.stream),
                        .reset => |reset| if (conn.jobOf(reset.stream)) |job| {
                            job.* = .{};
                        },
                        .writable => |writable| if (conn.jobOf(writable.stream)) |job| conn.push(job),
                        .response => unreachable, // A server session raises none.
                    }
                }
                return false;
            }

            fn onRequest(conn: *Conn, request: *const Session.Step.Request) void {
                const origin = conn.origin;
                origin.requests += 1;
                origin.last_body = .{};
                origin.last_body_len = 0;
                origin.last_te = .{};
                origin.last_content_type = .{};
                for (request.fields) |*field| {
                    const value = field.value;
                    if (std.mem.eql(u8, field.name, ":method")) origin.last_method.set(value);
                    if (std.mem.eql(u8, field.name, ":path")) origin.last_path.set(value);
                    if (std.mem.eql(u8, field.name, ":authority")) origin.last_authority.set(value);
                    if (std.mem.eql(u8, field.name, "te")) origin.last_te.set(value);
                    if (std.mem.eql(u8, field.name, "content-type")) origin.last_content_type.set(value);
                }
                if (origin.goaway_after_first and origin.requests == 1) conn.session.goAway();
                const job = conn.jobOf(0) orelse { // As many jobs as streams.
                    origin.requests_dropped += 1;
                    return;
                };
                job.* = .{ .stream = request.stream, .muted = origin.mutes(request) };
                if (origin.answer_at_head and !origin.mute and !job.muted) {
                    job.started = true;
                    conn.push(job);
                }
                if (request.end_stream) conn.requestEnded(request.stream);
            }

            /// The request is whole: answer it — or, for one answered at its
            /// head, push again, deliberately, to send the end that was held.
            fn requestEnded(conn: *Conn, stream: u31) void {
                const job = conn.jobOf(stream) orelse return;
                job.request_ended = true;
                if (conn.origin.mute or job.muted) return;
                job.started = true;
                conn.push(job);
            }

            fn jobOf(conn: *Conn, stream: u31) ?*Job {
                for (&conn.jobs) |*job| {
                    if (job.stream == stream) return job;
                }
                return null;
            }

            /// As much of the scripted answer as the session takes.
            fn push(conn: *Conn, job: *Job) void {
                const origin = conn.origin;
                assert(job.stream != 0);
                if (!job.started) return;
                var fields: [32]hpack.Field = undefined;
                // A bidirectional answer ends only after the request has.
                const holds = origin.answer_at_head and !job.request_ended;
                if (!job.head_sent) {
                    fields[0] = .{ .name = ":status", .value = origin.status };
                    for (origin.headers, 1..) |pair, index| fields[index] = .{ .name = pair[0], .value = pair[1] };
                    const head = fields[0 .. origin.headers.len + 1];
                    const ends = origin.body.len == 0 and origin.trailers.len == 0 and !holds;
                    switch (conn.session.sendHead(job.stream, head, ends)) {
                        .staged => job.head_sent = true,
                        .blocked => return,
                        .refused => unreachable, // The scenario's own script.
                    }
                    if (ends) return conn.finished(job);
                }
                if (job.body_offset < origin.body.len) {
                    const ends = origin.trailers.len == 0 and !origin.stall_after_body and !holds;
                    const sent = conn.session.sendData(job.stream, origin.body[job.body_offset..], ends);
                    job.body_offset += sent.taken;
                    if (job.body_offset < origin.body.len) return;
                    if (sent.ended) return conn.finished(job);
                }
                if (origin.stall_after_body or holds) return;
                if (origin.trailers.len == 0) {
                    // A body-less answer whose head did not end the stream.
                    const sent = conn.session.sendData(job.stream, &.{}, true);
                    if (sent.ended) conn.finished(job);
                    return;
                }
                for (origin.trailers, 0..) |pair, index| fields[index] = .{ .name = pair[0], .value = pair[1] };
                switch (conn.session.sendTrailers(job.stream, fields[0..origin.trailers.len])) {
                    .staged => conn.finished(job),
                    .blocked => {},
                    .refused => unreachable,
                }
            }

            fn finished(conn: *Conn, job: *Job) void {
                conn.origin.answered += 1;
                job.* = .{};
            }

            fn flush(conn: *Conn) void {
                if (conn.sending != 0 or conn.closed) return;
                if (conn.tls) |tls| {
                    if (!tls.owes() and tls.connected) {
                        const staged = conn.session.outbound();
                        if (staged.len >= 1) _ = tls.seal(staged) catch return conn.tlsFailed();
                    }
                    if (!tls.owes()) return;
                    const wire = tls.wire();
                    conn.sending = @intCast(wire.len);
                    conn.origin.io.send(conn.socket, wire, &conn.send_completion, Conn, conn, onSend);
                    return;
                }
                const staged = conn.session.outbound();
                if (staged.len == 0) return;
                conn.sending = @intCast(staged.len);
                conn.origin.io.send(conn.socket, staged, &conn.send_completion, Conn, conn, onSend);
            }

            fn onSend(conn: *Conn, result: Io.SendError!u32) void {
                conn.sending = 0;
                if (conn.closed) return conn.releaseIfSettled();
                const sent = result catch return conn.close();
                if (conn.tls) |tls| {
                    const plain = tls.sent(sent);
                    if (plain >= 1) conn.session.outboundSent(plain);
                    tls.process() catch return conn.tlsFailed();
                } else {
                    conn.session.outboundSent(sent);
                }
                conn.drive();
            }

            fn armRecv(conn: *Conn) void {
                const buffer = if (conn.tls) |tls| tls.recvBuffer() else conn.session.recvBuffer();
                if (buffer.len == 0) return; // Records wait for the session.
                conn.receiving = true;
                conn.origin.io.recv(conn.socket, buffer, &conn.recv_completion, Conn, conn, onRecv);
            }

            fn onRecv(conn: *Conn, result: Io.RecvError!u32) void {
                conn.receiving = false;
                if (conn.closed) return conn.releaseIfSettled();
                const received = result catch return conn.close();
                if (conn.tls) |tls| {
                    tls.received(received) catch return conn.tlsFailed();
                } else {
                    conn.session.received(received);
                }
                conn.drive();
            }

            fn close(conn: *Conn) void {
                if (conn.closed) return;
                conn.closed = true;
                if (conn.tls) |tls| tls.finish();
                // An op still out holds the socket; it delivers into a
                // closed conn, is dropped, and the last one releases it.
                if (conn.receiving or conn.sending != 0) {
                    conn.origin.io.shutdown(conn.socket, .both);
                    return;
                }
                conn.releaseIfSettled();
            }

            /// Close the socket of a closed conn once no op is out on it.
            fn releaseIfSettled(conn: *Conn) void {
                assert(conn.closed);
                if (conn.receiving or conn.sending != 0) return;
                if (conn.socket_closed) return;
                conn.socket_closed = true;
                conn.origin.io.closeNow(conn.socket);
            }
        };

        /// Listen on `address`, the sessions' buffers carved from `arena`.
        /// Listen on `address`: an IP port, or a socket path for a
        /// scenario whose endpoint is one (#303).
        pub fn start(origin: *Self, arena: std.mem.Allocator, io: *IoType, address: *const Io.Address) !void {
            origin.io = io;
            if (origin.tls) {
                origin.tls_servers = try arena.alloc(TestTlsServer, conns_max);
                for (origin.tls_servers) |*server| server.started = false;
            }
            const unit: usize = @intCast(layout.bytes());
            const slab = try arena.alignedAlloc(u8, .fromByteUnits(Session.Layout.unit_align), conns_max * unit);
            for (&origin.conns, 0..) |*conn, index| {
                const piece: []align(Session.Layout.unit_align) u8 = @alignCast(slab[index * unit ..][0..unit]);
                const carved = layout.carve(piece);
                conn.session = carved.session;
                conn.buffers = carved.buffers;
            }
            origin.listener = try io.listen(address, null);
            origin.listening = true;
            origin.armAccept();
        }

        fn armAccept(origin: *Self) void {
            origin.io.accept(origin.listener, &origin.accept_completion, Self, origin, onAccept);
        }

        /// Whether `request`'s path is one this origin leaves unanswered.
        fn mutes(origin: *const Self, request: *const Session.Step.Request) bool {
            if (origin.mute_path_prefix.len == 0) return false;
            for (request.fields) |*field| {
                if (!std.mem.eql(u8, field.name, ":path")) continue;
                return std.mem.startsWith(u8, field.value, origin.mute_path_prefix);
            }
            assert(request.fields.len >= 1);
            return false;
        }

        /// A slot for the next connection: a fresh one while any is left,
        /// else one whose connection is closed and socket released.
        fn acquireSlot(origin: *Self) ?usize {
            assert(origin.slots_used <= conns_max);
            if (origin.slots_used < conns_max) {
                origin.slots_used += 1;
                return origin.slots_used - 1;
            }
            for (&origin.conns, 0..) |*conn, index| {
                if (conn.closed and conn.socket_closed) return index;
            }
            return null;
        }

        fn onAccept(origin: *Self, result: Io.AcceptError!IoType.Socket) void {
            const socket = result catch return;
            const index = origin.acquireSlot() orelse {
                origin.refused += 1;
                origin.io.closeNow(socket);
                return origin.armAccept();
            };
            assert(index < conns_max);
            const conn = &origin.conns[index];
            origin.accepted_count += 1;
            const session = conn.session;
            const buffers = conn.buffers;
            conn.* = .{ .origin = origin, .socket = socket, .session = session, .buffers = buffers };
            if (origin.tls) {
                const tls = &origin.tls_servers[index];
                var key_share: [48]u8 = @splat(0x93);
                key_share[47] = @truncate(origin.accepted_count);
                tls.start(origin.tls_alpn, key_share) catch {
                    origin.tls_failures += 1;
                    conn.closed = true;
                    conn.socket_closed = true;
                    origin.io.closeNow(socket);
                    return origin.armAccept();
                };
                conn.tls = tls;
            }
            conn.session.init(.{
                .concurrent_streams_max = streams_max,
                .header_list_size_max = layout.header_list_size_max,
            }, &conn.buffers);
            conn.drive();
            origin.armAccept();
        }

        pub fn stopListening(origin: *Self) void {
            if (!origin.listening) return;
            origin.io.listenClose(origin.listener);
            origin.listening = false;
        }

        /// Close what is still open, so a scenario's socket accounting is
        /// exact.
        pub fn closeRemaining(origin: *Self) void {
            for (origin.conns[0..origin.slots_used]) |*conn| {
                if (conn.tls) |tls| tls.finish();
                conn.closed = true;
                // The loop has stopped: an op still out will never land.
                if (conn.socket_closed) continue;
                conn.socket_closed = true;
                origin.io.closeNow(conn.socket);
            }
        }
    };
}
