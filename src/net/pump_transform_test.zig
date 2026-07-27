//! The transform seam under a real, non-identity transform (§4, §6, §9).
//!
//! `pump.zig`'s transform hooks are identity for every production policy,
//! and identity proves nothing about the property they exist for: that the
//! bytes on the wire can be a different count, in a different buffer, from
//! the bytes framing measured. This file is the seam's first real user —
//! deterministic and crypto-free — so those mechanics are exercised before
//! TLS depends on them (PLANS.md, B1 + B5).
//!
//! The toy mirrors TLS's shape: the *client* side of the connection speaks
//! frames (`[u16 big-endian length][payload]`) while framing and the upstream
//! side see plain payload bytes.
//!
//!   client → upstream: read frames into a scratch, un-frame into the relay
//!                      buffer, forward the payload
//!   upstream → client: read payload into the relay buffer, frame it into a
//!                      scratch, write that frame in capped windows
//!
//! Three properties identity cannot pin, and this does:
//!
//!   1. the read lands somewhere other than the relay buffer (`recvBuffer`),
//!      so the buffer framing reads is not the buffer the socket filled;
//!   2. the wire carries two bytes per frame that the framed count never
//!      sees, so `sendSlice`/`creditSend` must keep their own cursor and the
//!      framed debt is settled only when that cursor drains — the contract
//!      `onSend` asserts;
//!   3. a transform may yield *nothing* from a read (a frame split across
//!      deliveries) without that meaning end of message.
//!
//! The oracle is byte-exactness in both directions under the adversary's
//! 1-byte deliveries across a spread of seeds: the payload must reach the
//! origin whole, and the origin's echo must come back framed and whole. The
//! scratch lives here rather than on `Conn` — a slot does not grow a field
//! for a test, and issue #75 is about the one it already has.

const std = @import("std");

const config_module = @import("../config.zig");
const conn_module = @import("Conn.zig");
const pump = @import("pump.zig");
const router = @import("../http/router.zig");
const server_module = @import("../Server.zig");
const Io = @import("../io/io.zig");
const SimIo = @import("../io/SimIo.zig");

const assert = std.debug.assert;

const ServerSim = server_module.Server(SimIo);
const ConnSim = conn_module.Conn(SimIo);
const Direction = ConnSim.Direction;

/// `[u16 big-endian length][payload]` — the smallest framing with a real
/// header, so every frame puts two bytes on the wire that framing never
/// counts.
const header_bytes: u32 = 2;
/// Cap on what one send may write, so a frame always needs several sends and
/// the transform's cursor has to survive the resumes.
const wire_window_max: u32 = 7;
/// Largest payload one frame may carry, and so the bound on both scratch
/// buffers. Past it is a transform *failure*, not an assertion.
const payload_max: u32 = 64;

/// Exactly `payload_max` bytes, so the origin's echo — framed in one chunk
/// whenever a read delivers it whole — drives the outbound scratch to its
/// exact bound rather than staying comfortably inside it.
const payload = "toy-transform-payload-0123456789abcdefghijklmnopqrstuvwxyz012345";
/// The client sends the payload as three frames, so the un-framer meets a
/// stream of them rather than one message.
const client_frames = [_]u32{ 10, 10, payload.len - 20 };

comptime {
    assert(payload.len == payload_max);
    // A frame must outgrow one send window, or the wire cursor is never
    // exercised across a resume.
    assert(header_bytes + payload.len > wire_window_max);
}

/// The transform's buffers. One connection per scenario, so one instance;
/// `setUp` resets it and `armPumps` asserts it is clean.
var scratch: Scratch = .{};

const Scratch = struct {
    /// Frame bytes read from the client, kept across reads until a frame is
    /// whole — the fragment case that makes `transformIn` yield nothing.
    inbound: [payload_max + header_bytes]u8 = undefined,
    inbound_len: u32 = 0,
    /// The peer's end marker has arrived: an EOF stated *inside* the
    /// transform, which no socket EOF need follow — the read side is over
    /// while the connection stays open for the other direction.
    inbound_ended: bool = false,
    /// Which terminal the marker reached. The two are not interchangeable —
    /// one is reported by `transformEnded`, the other by `framingDone` —
    /// so a test asserts it exercised the one it is named for rather than
    /// passing on its sibling's path.
    ended_via_drain: bool = false,
    ended_via_complete: bool = false,
    /// The frame staged for the client, under the wire cursor the framed
    /// debt is not allowed to share.
    outbound: [payload_max + header_bytes]u8 = undefined,
    outbound_len: u32 = 0,
    outbound_sent: u32 = 0,

    fn isClean(self: *const Scratch) bool {
        return self.inbound_len == 0 and self.outbound_len == 0 and
            self.outbound_sent == 0 and !self.inbound_ended and
            !self.ended_via_drain and !self.ended_via_complete;
    }
};

/// Everything both directions share: the L4 shape — no framing of its own,
/// EOF is a half-close, teardown once both directions finish.
fn Base(comptime direction: Direction) type {
    return struct {
        fn state(conn: *ConnSim) *conn_module.DirectionState {
            return &conn.directions[@intFromEnum(direction)];
        }

        fn targetSocket(conn: *const ConnSim) SimIo.Socket {
            return switch (direction) {
                .client_to_upstream => conn.upstream_socket.?,
                .upstream_to_client => conn.client_socket,
            };
        }

        /// Unlike the production L4 policy this admits `.receiving` twice in
        /// a row: a transform that yielded no whole frame re-arms the read
        /// with no send in between (pump.zig).
        pub fn beforeRecv(conn: *ConnSim) void {
            assert(conn.state == .relaying);
            state(conn).phase = .receiving;
        }

        pub fn beforeSend(conn: *ConnSim) void {
            assert(conn.state == .relaying);
            const direction_state = state(conn);
            assert(direction_state.phase == .receiving or direction_state.phase == .sending);
            direction_state.phase = .sending;
        }

        /// Framing sees payload bytes and relays all of them, exactly as the
        /// L4 policy does: the transform is invisible here, which is the
        /// seam's whole point.
        pub fn feed(conn: *ConnSim, chunk: []const u8) pump.FeedResult {
            _ = conn;
            assert(chunk.len >= 1);
            return .{ .consumed = @intCast(chunk.len), .done = false, .malformed = false };
        }

        pub fn framingDone(conn: *ConnSim) bool {
            _ = conn;
            return false;
        }

        /// This direction is over: propagate the FIN and end the connection
        /// once both directions have. Reached from a socket EOF and — on the
        /// read side — from the transform's own end marker, which is the
        /// point: an in-band EOF must land exactly where a real one does.
        fn finish(server: *ServerSim, conn: *ConnSim) void {
            assert(conn.state == .relaying);
            // Negative space behind the comment above: a direction ends
            // once. Reaching here twice would mean a socket EOF and an
            // in-band one both claimed the same side.
            assert(state(conn).phase != .finished);
            state(conn).phase = .finished;
            server.io.shutdown(targetSocket(conn), .write);
            if (conn.directions[0].phase == .finished and
                conn.directions[1].phase == .finished)
            {
                server.beginTeardown(conn);
            }
        }

        pub fn onRecvError(server: *ServerSim, conn: *ConnSim, err: Io.RecvError) void {
            if (err == error.EndOfStream) {
                finish(server, conn);
                return;
            }
            server.beginTeardown(conn);
        }

        pub fn onSendError(server: *ServerSim, conn: *ConnSim, err: Io.SendError) void {
            server.witnessKernelPressure(.send, err);
            server.beginTeardown(conn);
        }

        pub fn onDrained(server: *ServerSim, conn: *ConnSim) void {
            _ = server;
            _ = conn;
            unreachable; // `feed` consumes every byte it is given.
        }

        pub fn onComplete(server: *ServerSim, conn: *ConnSim) void {
            _ = server;
            _ = conn;
            unreachable; // `framingDone` is always false.
        }
    };
}

/// Client → upstream: the *read* side transforms. Frames land in the
/// scratch; the relay buffer receives the un-framed payload, so the read
/// cannot land there.
const ToUpstreamPolicy = struct {
    const base = Base(.client_to_upstream);

    pub const beforeRecv = base.beforeRecv;
    pub const beforeSend = base.beforeSend;
    pub const feed = base.feed;
    pub const onRecvError = base.onRecvError;
    pub const onSendError = base.onSendError;

    /// The end marker arrived with no whole frame in front of it, so there
    /// is nothing to forward first.
    pub fn transformEnded(conn: *ConnSim) bool {
        _ = conn;
        return scratch.inbound_ended;
    }

    /// …and the same marker arriving *behind* a frame, in one read. The
    /// chunk was non-empty, so `transformEnded` was never asked; this is
    /// where the pump learns the stream ended, once the bytes that shared
    /// the read with the marker are on their way.
    pub fn framingDone(conn: *ConnSim) bool {
        _ = conn;
        return scratch.inbound_ended;
    }

    /// Both terminals mean the marker was seen; they differ only in whether
    /// anything rode with it. Exactly one fires, exactly once — which is
    /// what makes the coverage flags evidence rather than decoration, so it
    /// is asserted rather than left to the tests to notice.
    pub fn onDrained(server: *ServerSim, conn: *ConnSim) void {
        assert(scratch.inbound_ended);
        assert(!scratch.ended_via_drain and !scratch.ended_via_complete);
        scratch.ended_via_drain = true;
        base.finish(server, conn);
    }

    pub fn onComplete(server: *ServerSim, conn: *ConnSim) void {
        assert(scratch.inbound_ended);
        assert(!scratch.ended_via_drain and !scratch.ended_via_complete);
        scratch.ended_via_complete = true;
        base.finish(server, conn);
    }

    /// After whatever fragment the last read left, never the relay buffer.
    pub fn recvBuffer(conn: *ConnSim) []u8 {
        _ = conn;
        // A whole frame always fits, so the scratch cannot fill without a
        // frame completing and freeing it.
        assert(scratch.inbound_len < scratch.inbound.len);
        return scratch.inbound[scratch.inbound_len..];
    }

    /// Un-frame every whole frame that has arrived, into the relay buffer.
    /// An empty result means "no whole frame yet"; null means the peer
    /// framed something illegal, which is this connection's failure and not
    /// an invariant violation (§8).
    pub fn transformIn(conn: *ConnSim, chunk: []u8) ?[]const u8 {
        assert(chunk.len >= 1);
        scratch.inbound_len += @intCast(chunk.len);
        assert(scratch.inbound_len <= scratch.inbound.len);
        const out = &conn.relay_buffer.?.client_to_upstream;
        var out_len: u32 = 0;
        // Bounded by the scratch: each turn either consumes a whole frame or
        // breaks out.
        while (scratch.inbound_len >= header_bytes) {
            const need = std.mem.readInt(u16, scratch.inbound[0..2], .big);
            if (need > payload_max) return null;
            if (need == 0) {
                // The end marker. Frames already un-framed in this same call
                // are returned and forwarded; anything *behind* the marker is
                // dropped, because the stream ended there. Which side of it
                // a byte falls on is the whole distinction the two hooks
                // below exist to report.
                //
                // Dropped, not merely left unread: nothing re-arms this
                // direction once the marker lands, so the leftovers would be
                // inert here — but this scratch stands in for a buffer that
                // lives on a pooled slot, where carrying a dead peer's bytes
                // into the next connection is the bug the pattern must not
                // teach (§5).
                scratch.inbound_ended = true;
                scratch.inbound_len = 0;
                break;
            }
            const frame_len = header_bytes + @as(u32, need);
            if (scratch.inbound_len < frame_len) break; // a fragment; read on
            if (out_len + need > out.len) return null;
            @memcpy(out[out_len..][0..need], scratch.inbound[header_bytes..frame_len]);
            out_len += need;
            const rest = scratch.inbound_len - frame_len;
            std.mem.copyForwards(
                u8,
                scratch.inbound[0..rest],
                scratch.inbound[frame_len..scratch.inbound_len],
            );
            scratch.inbound_len = rest;
        }
        return out[0..out_len];
    }
};

/// Upstream → client: the *write* side transforms. Framing measures payload
/// bytes in the relay buffer; the wire carries a header on top, under its
/// own cursor.
const ToClientPolicy = struct {
    const base = Base(.upstream_to_client);

    pub const beforeRecv = base.beforeRecv;
    pub const beforeSend = base.beforeSend;
    pub const feed = base.feed;
    pub const framingDone = base.framingDone;
    pub const onRecvError = base.onRecvError;
    pub const onSendError = base.onSendError;
    pub const onDrained = base.onDrained;
    pub const onComplete = base.onComplete;

    /// Frame the chunk once, before the first send. A payload the frame
    /// cannot carry fails the connection — the seam's fallible path, and the
    /// reason `transformOut` returns a bool rather than asserting.
    pub fn transformOut(conn: *ConnSim, consumed: u32) bool {
        assert(consumed >= 1);
        // The previous frame left the wire before this one is staged: this
        // runs exactly once per framed chunk.
        assert(scratch.outbound_len == scratch.outbound_sent);
        if (consumed > payload_max) return false;
        const body = conn.relay_buffer.?.upstream_to_client[0..consumed];
        std.mem.writeInt(u16, scratch.outbound[0..2], @intCast(consumed), .big);
        @memcpy(scratch.outbound[header_bytes..][0..consumed], body);
        scratch.outbound_len = header_bytes + consumed;
        scratch.outbound_sent = 0;
        return true;
    }

    /// The staged frame under its own cursor, capped so a frame takes several
    /// sends. Empty once drained, which is how the pump asks "anything left
    /// to write?".
    pub fn sendSlice(conn: *ConnSim) []const u8 {
        _ = conn;
        const left = scratch.outbound_len - scratch.outbound_sent;
        if (left == 0) return &.{};
        return scratch.outbound[scratch.outbound_sent..][0..@min(left, wire_window_max)];
    }

    /// Credit the wire cursor; settle the framed debt only when the whole
    /// frame is out, because a partly written frame has delivered no payload
    /// the caller may account for.
    pub fn creditSend(conn: *ConnSim, sent: u32) void {
        assert(sent >= 1);
        scratch.outbound_sent += sent;
        assert(scratch.outbound_sent <= scratch.outbound_len);
        if (scratch.outbound_sent < scratch.outbound_len) return;
        const direction_state = &conn.directions[@intFromEnum(Direction.upstream_to_client)];
        direction_state.credit(direction_state.owed());
    }
};

const PumpToUpstream = pump.Pump(SimIo, .client_to_upstream, ToUpstreamPolicy);
const PumpToClient = pump.Pump(SimIo, .upstream_to_client, ToClientPolicy);

/// Frame `payload` into `out` as `client_frames` dictates, returning the
/// bytes written. Shared by the client's own wire and by the tests that
/// append an end marker behind it.
fn frameInto(out: []u8) u32 {
    var offset: u32 = 0;
    var written: u32 = 0;
    for (client_frames) |chunk| {
        assert(written + header_bytes + chunk <= out.len);
        std.mem.writeInt(u16, out[written..][0..2], @intCast(chunk), .big);
        @memcpy(out[written + header_bytes ..][0..chunk], payload[offset..][0..chunk]);
        written += header_bytes + chunk;
        offset += chunk;
    }
    assert(offset == payload.len);
    return written;
}

/// The client peer: writes pre-framed bytes, expects framed bytes back, then
/// FINs and waits for the proxied FIN.
const Client = struct {
    harness: *Harness = undefined,
    socket: SimIo.Socket = undefined,
    connect_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    wire: [payload.len + client_frames.len * header_bytes]u8 = undefined,
    wire_len: u32 = 0,
    sent_len: u32 = 0,
    /// Sized for the worst framing the adversary can provoke: one frame per
    /// delivered byte, so a header per payload byte.
    received: [payload.len * (1 + header_bytes)]u8 = undefined,
    received_len: u32 = 0,
    unframed: [payload.len]u8 = undefined,
    unframed_len: u32 = 0,
    /// Overrides the framed payload with raw bytes, for the illegal-frame
    /// case; empty means send `wire`.
    raw: []const u8 = &.{},
    fin_sent: bool = false,
    eof: bool = false,
    reset: bool = false,

    fn frameUp(client: *Client) void {
        client.wire_len = frameInto(&client.wire);
    }

    fn outgoing(client: *const Client) []const u8 {
        if (client.raw.len > 0) return client.raw;
        return client.wire[0..client.wire_len];
    }

    fn armSend(client: *Client) void {
        const bytes = client.outgoing();
        assert(client.sent_len < bytes.len);
        client.harness.io.send(
            client.socket,
            bytes[client.sent_len..],
            &client.send_completion,
            Client,
            client,
            onSend,
        );
    }

    fn armRecv(client: *Client) void {
        client.harness.io.recv(
            client.socket,
            client.received[client.received_len..],
            &client.recv_completion,
            Client,
            client,
            onRecv,
        );
    }

    fn onSend(client: *Client, result: Io.SendError!u32) void {
        const sent = result catch {
            client.reset = true;
            return;
        };
        client.sent_len += sent;
        assert(client.sent_len <= client.outgoing().len);
        if (client.sent_len < client.outgoing().len) client.armSend();
    }

    fn onRecv(client: *Client, result: Io.RecvError!u32) void {
        const received = result catch |err| {
            if (err == error.EndOfStream) client.eof = true else client.reset = true;
            return;
        };
        client.received_len += received;
        client.unframe();
        if (client.unframed_len >= payload.len and !client.fin_sent) {
            // The whole payload came back framed: FIN, then wait for the
            // proxied FIN so teardown is observed rather than assumed.
            client.fin_sent = true;
            client.harness.io.shutdown(client.socket, .write);
        }
        if (client.received_len < client.received.len) client.armRecv();
    }

    /// Strip whatever whole frames have arrived; the leftover stays in place
    /// because `received_len` only grows.
    fn unframe(client: *Client) void {
        var offset: u32 = 0;
        client.unframed_len = 0;
        while (offset + header_bytes <= client.received_len) {
            const need = std.mem.readInt(u16, client.received[offset..][0..2], .big);
            const end = offset + header_bytes + need;
            if (end > client.received_len) break;
            @memcpy(client.unframed[client.unframed_len..][0..need], client.received[offset + header_bytes .. end]);
            client.unframed_len += need;
            offset = end;
        }
    }
};

/// The origin peer: a plain echo, or a canned answer for the oversize case.
const Origin = struct {
    harness: *Harness = undefined,
    socket: SimIo.Socket = undefined,
    accept_completion: SimIo.Completion = .{},
    send_completion: SimIo.Completion = .{},
    recv_completion: SimIo.Completion = .{},
    buffer: [payload_max * 8]u8 = undefined,
    received_len: u32 = 0,
    echoed_len: u32 = 0,
    /// Sent unprompted on accept instead of echoing; empty means echo.
    canned: []const u8 = &.{},
    canned_sent: u32 = 0,
    eof: bool = false,

    fn armRecv(origin: *Origin) void {
        origin.harness.io.recv(
            origin.socket,
            origin.buffer[origin.received_len..],
            &origin.recv_completion,
            Origin,
            origin,
            onRecv,
        );
    }

    fn armEcho(origin: *Origin) void {
        assert(origin.echoed_len < origin.received_len);
        origin.harness.io.send(
            origin.socket,
            origin.buffer[origin.echoed_len..origin.received_len],
            &origin.send_completion,
            Origin,
            origin,
            onSent,
        );
    }

    fn armCanned(origin: *Origin) void {
        assert(origin.canned_sent < origin.canned.len);
        origin.harness.io.send(
            origin.socket,
            origin.canned[origin.canned_sent..],
            &origin.send_completion,
            Origin,
            origin,
            onCannedSent,
        );
    }

    fn onRecv(origin: *Origin, result: Io.RecvError!u32) void {
        const received = result catch |err| {
            if (err == error.EndOfStream) {
                origin.eof = true;
                origin.harness.io.shutdown(origin.socket, .write);
            }
            return;
        };
        origin.received_len += received;
        if (origin.canned.len > 0) {
            origin.armRecv();
            return;
        }
        origin.armEcho();
    }

    fn onSent(origin: *Origin, result: Io.SendError!u32) void {
        const sent = result catch return;
        origin.echoed_len += sent;
        if (origin.echoed_len < origin.received_len) {
            origin.armEcho();
            return;
        }
        origin.armRecv();
    }

    fn onCannedSent(origin: *Origin, result: Io.SendError!u32) void {
        const sent = result catch return;
        origin.canned_sent += sent;
        if (origin.canned_sent < origin.canned.len) origin.armCanned();
    }
};

const Harness = struct {
    arena_state: std.heap.ArenaAllocator = undefined,
    io: SimIo = undefined,
    server: ServerSim = undefined,
    routes: [1]router.Route = undefined,
    listeners: [1]config_module.Config.Listener = undefined,
    clusters: [1]config_module.Config.Cluster = undefined,
    endpoints: [1]std.Io.net.IpAddress = undefined,
    config: config_module.Config = undefined,

    client_listener: SimIo.Listener = undefined,
    origin_listener: SimIo.Listener = undefined,
    accept_completion: SimIo.Completion = .{},
    connect_completion: SimIo.Completion = .{},
    /// The proxy's two ends: accepted from the client, dialed to the origin.
    proxy_client_socket: SimIo.Socket = undefined,
    proxy_upstream_socket: SimIo.Socket = undefined,

    conn: ?*ConnSim = null,
    client: Client = .{},
    origin: Origin = .{},

    const Options = struct {
        sim: SimIo.Options,
        /// Raw client bytes instead of the framed payload.
        client_raw: []const u8 = &.{},
        /// Origin answers with this, unprompted, instead of echoing.
        origin_canned: []const u8 = &.{},
    };

    fn clientAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:19300") catch unreachable;
    }

    fn originAddress() std.Io.net.IpAddress {
        return std.Io.net.IpAddress.parseLiteral("127.0.0.1:19301") catch unreachable;
    }

    fn setUp(bed: *Harness, gpa: std.mem.Allocator, options: Options) !void {
        scratch = .{};
        bed.* = .{};
        bed.arena_state = std.heap.ArenaAllocator.init(gpa);
        errdefer bed.arena_state.deinit();
        const arena = bed.arena_state.allocator();

        try bed.io.init(arena, options.sim);
        bed.endpoints = .{originAddress()};
        bed.clusters = .{.{ .name = "origin", .endpoints = &bed.endpoints }};
        bed.routes = .{.{ .prefix = "/", .cluster_index = 0 }};
        bed.listeners = .{.{
            .bind_address = clientAddress(),
            .routes = &bed.routes,
            .protocol = .l4,
        }};
        bed.config = .{
            .listeners = &bed.listeners,
            .clusters = &bed.clusters,
            .connect_timeout_ms = 1000,
            .idle_timeout_ms = 5000,
            .drain_deadline_ms = 1000,
            .max_lifetime_ms = 0,
            .request_timeout_ms = 0,
        };
        // The Server owns the pools, the clock and teardown. Its own
        // listeners stay unbound: this scenario drives the pump directly, so
        // the sockets are the harness's own rather than admission's.
        try bed.server.init(arena, &bed.io, &bed.config, .{ .conn_slots = 2, .relay_buffers = 1 });

        bed.client.harness = bed;
        bed.client.raw = options.client_raw;
        bed.client.frameUp();
        bed.origin.harness = bed;
        bed.origin.canned = options.origin_canned;

        bed.client_listener = try bed.io.listen(clientAddress());
        bed.origin_listener = try bed.io.listen(originAddress());
        bed.io.accept(bed.client_listener, &bed.accept_completion, Harness, bed, onProxyAccepted);
        bed.io.accept(bed.origin_listener, &bed.origin.accept_completion, Origin, &bed.origin, onOriginAccepted);
        bed.io.connect(clientAddress(), &bed.client.connect_completion, Client, &bed.client, onClientConnected);
    }

    fn tearDown(bed: *Harness) void {
        bed.io.listenClose(bed.client_listener);
        bed.io.listenClose(bed.origin_listener);
        bed.arena_state.deinit();
    }

    fn onProxyAccepted(bed: *Harness, result: Io.AcceptError!SimIo.Socket) void {
        bed.proxy_client_socket = result catch unreachable;
        bed.io.connect(originAddress(), &bed.connect_completion, Harness, bed, onProxyDialed);
    }

    fn onProxyDialed(bed: *Harness, result: Io.ConnectError!SimIo.Socket) void {
        bed.proxy_upstream_socket = result catch unreachable;
        bed.armPumps();
    }

    fn onClientConnected(client: *Client, result: Io.ConnectError!SimIo.Socket) void {
        client.socket = result catch unreachable;
        client.armRecv();
        client.armSend();
    }

    fn onOriginAccepted(origin: *Origin, result: Io.AcceptError!SimIo.Socket) void {
        origin.socket = result catch unreachable;
        if (origin.canned.len > 0) {
            origin.armCanned();
            origin.armRecv();
            return;
        }
        origin.armRecv();
    }

    /// A conn from the real pool, prepared as admission would minus what this
    /// scenario does not exercise (no accept gate, no dial, no deadline
    /// timer — so teardown's deadline-cancel interleaving is not covered
    /// here). Both `accepted` and `admitted` are counted by hand, since the
    /// reconcile identity (§9) reads them together.
    fn armPumps(bed: *Harness) void {
        assert(bed.conn == null);
        assert(scratch.isClean());
        const conn = bed.server.conns.acquire().?;
        const buffer = bed.server.relay_buffers.acquire().?;
        // The accept gate and the admission tail are not exercised here, so
        // their counters are set by hand: `reconcile` (§9) checks
        // completed <= admitted <= accepted, and this connection did pass
        // through both in spirit.
        bed.server.counters.increment("accepted");
        bed.server.counters.increment("admitted");
        conn.prepare(&bed.server, bed.proxy_client_socket, buffer, .connecting, 0);
        conn.upstream_socket = bed.proxy_upstream_socket;
        conn.state = .relaying;
        bed.conn = conn;
        bed.server.storeDeadline(conn, 5_000);
        PumpToUpstream.armRecv(&bed.server, conn);
        PumpToClient.armRecv(&bed.server, conn);
    }

    /// Every scenario ends the same way: the connection is gone, both pools
    /// are back, and the books balance.
    fn expectSettled(bed: *Harness) !void {
        try std.testing.expect(bed.server.conns.isFullyReleased());
        try std.testing.expect(bed.server.relay_buffers.isFullyReleased());
        try std.testing.expectEqual(@as(u64, 1), bed.server.counters.get("completed"));
        try std.testing.expect(bed.server.reconcile());
    }
};

test "transform: framed client bytes relay byte-exact in both directions" {
    for (1..16) |seed| {
        var bed: Harness = undefined;
        try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = seed } });
        defer bed.tearDown();

        try bed.io.run();

        // The origin saw payload bytes only: the framing never reached it.
        try std.testing.expectEqualStrings(payload, bed.origin.buffer[0..bed.origin.received_len]);
        // The client got them back framed, and un-framing returns the
        // payload byte-for-byte.
        try std.testing.expectEqualStrings(payload, bed.client.unframed[0..bed.client.unframed_len]);
        // The wire carried more bytes than framing ever counted — the
        // property an identity transform cannot exhibit.
        try std.testing.expect(bed.client.received_len > bed.client.unframed_len);
        try std.testing.expect(bed.client.eof);
        try bed.expectSettled();
    }
}

// A transform can end its stream *in band* — the peer says so inside the
// framing, and no socket EOF need follow, because the connection stays open
// for the other direction. The pump cannot tell that from a fragment on its
// own (both yield no framed bytes), so the policy answers `transformEnded`.
// Get it wrong and nothing fails: the direction re-arms a read and waits for
// bytes that will never come, until a deadline reaps a peer that said a
// clean goodbye. `deadline_expired == 0` is what pins that.
test "transform: an end marker alone ends the direction, not the deadline" {
    // The marker and nothing else, so the transform yields no framed bytes
    // and `transformEnded` is the only thing that can distinguish this from
    // a fragment — whatever the adversary does with a two-byte delivery.
    const marker = [_]u8{ 0, 0 };
    for (1..8) |seed| {
        var bed: Harness = undefined;
        try bed.setUp(std.testing.allocator, .{
            .sim = .{ .seed = seed },
            .client_raw = &marker,
        });
        defer bed.tearDown();

        try bed.io.run();

        // The marker reached the origin as a FIN, never as bytes.
        try std.testing.expectEqual(@as(u32, 0), bed.origin.received_len);
        try std.testing.expect(bed.origin.eof);
        try std.testing.expect(scratch.ended_via_drain);
        try std.testing.expect(!scratch.ended_via_complete);
        try std.testing.expectEqual(
            @as(u64, 0),
            bed.server.counters.get("deadline_expired"),
        );
        try bed.expectSettled();
    }
}

// The same marker riding the same read as the last frame — write() then
// shutdown(), which is what a peer actually does. Now the chunk is *not*
// empty, so `transformEnded` is never consulted and `framingDone` has to
// report it instead, after the bytes that shared the read are forwarded.
// Two ways to fail, and this pins both: forward the frame and then hang
// waiting on a stream that ended, or notice the marker and drop the frame
// that came with it — which shows up as a short payload at the origin.
test "transform: an end marker coalesced with a frame loses neither" {
    for (1..8) |seed| {
        var wire: [payload.len + client_frames.len * header_bytes + header_bytes]u8 = undefined;
        const framed = frameInto(&wire);
        std.mem.writeInt(u16, wire[framed..][0..2], 0, .big);

        var bed: Harness = undefined;
        try bed.setUp(std.testing.allocator, .{
            // Whole deliveries, so the coalescing is arithmetic rather than
            // luck of the seed. 72 bytes go out in one send (three frames,
            // 70, plus the marker) against a 66-byte scratch, so the reads
            // are a deterministic 66 then 6: the first ends mid-frame-3, and
            // the second carries that frame's last bytes *and* the marker.
            // So a completed frame and the marker share a read — which is
            // the case at issue — on the second one, not the first.
            .sim = .{ .seed = seed, .adversary = .{ .partial_io = false } },
            .client_raw = wire[0 .. framed + header_bytes],
        });
        defer bed.tearDown();

        try bed.io.run();

        try std.testing.expectEqualStrings(payload, bed.origin.buffer[0..bed.origin.received_len]);
        try std.testing.expect(bed.origin.eof);
        try std.testing.expect(scratch.ended_via_complete);
        try std.testing.expect(!scratch.ended_via_drain);
        try std.testing.expectEqual(
            @as(u64, 0),
            bed.server.counters.get("deadline_expired"),
        );
        try bed.expectSettled();
    }
}

test "transform: a frame the peer framed illegally sheds the connection" {
    // A length past what the transform can carry: `transformIn` answers null
    // and the pump tears the connection down (§8) instead of asserting.
    var illegal: [header_bytes + 4]u8 = undefined;
    std.mem.writeInt(u16, illegal[0..2], @intCast(payload_max + 1), .big);
    @memset(illegal[header_bytes..], 'x');

    var bed: Harness = undefined;
    try bed.setUp(std.testing.allocator, .{ .sim = .{ .seed = 7 }, .client_raw = &illegal });
    defer bed.tearDown();

    try bed.io.run();

    // Nothing was forwarded, and the client's connection is gone.
    try std.testing.expectEqual(@as(u32, 0), bed.origin.received_len);
    try std.testing.expect(bed.client.eof or bed.client.reset);
    try bed.expectSettled();
}

test "transform: a chunk too large to stage sheds the connection" {
    // Whole deliveries, so the origin's answer arrives in one chunk and the
    // framed length really does exceed what one frame can carry.
    const oversize = "z" ** (payload_max + 1);

    var bed: Harness = undefined;
    try bed.setUp(std.testing.allocator, .{
        .sim = .{ .seed = 11, .adversary = .{ .partial_io = false } },
        .origin_canned = oversize,
    });
    defer bed.tearDown();

    try bed.io.run();

    // `transformOut` refused to stage it, so no frame reached the client.
    try std.testing.expectEqual(@as(u32, 0), bed.client.unframed_len);
    try bed.expectSettled();
}
