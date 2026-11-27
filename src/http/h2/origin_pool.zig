//! HTTP/2 to an origin (§7): a cluster that speaks `h2c` is reached over a
//! pooled connection that many exchanges share, each on a stream of its
//! own, rather than over a socket leased to one exchange at a time.
//!
//! The exchange does not learn it. Its upstream half is the HTTP/1.1 one,
//! ops and all: it sends a rendered request head and a framed body, and
//! receives a response head and a framed body. What it sends to and
//! receives from is a *leg* — this file's per-exchange state on the
//! stream slot — instead of a socket, and every upstream op the exchange
//! arms goes through `Server`'s `upstream*` dispatch to one of the four
//! here: `send`, `recv`, `shutdown`, `detach`. That keeps §7 stated once.
//! The request head is read back by `origin.requestFields` and opened as a
//! stream; the body's octets are unframed into DATA. The answer is written
//! out by `origin.responseHead` as the HTTP/1.1 head it stands for, the
//! exchange parses that like any origin's, and its DATA and trailers come
//! back framed for it — chunked when the origin declared no length, so a
//! trailer section reaches the client (#275's trailing HEADERS for an
//! HTTP/2 one, the chunked trailer section for an HTTP/1.1 one).
//!
//! A leg's op completes on the exchange's own completion, through a
//! zero-delay timer, never inside the call that armed it: whatever an
//! exchange arms delivers on a later tick, as a socket op would, so the
//! ring charge per exchange is the one it always had (§8).
//!
//! What arrives for a stream is staged in a buffer of the leg's own, so a
//! connection is never held for one stream's slow client: the stream's
//! receive window is what the buffer holds behind a head, and a DATA
//! frame's octets are copied out of the session at once. They are credited
//! back as the exchange reads them.
//!
//! The connection is the server driver's mirror (`Connection.zig`): one
//! recv and one send in flight, the session stepped after each until it
//! waits, and a timer for the dial's budget and the idle window. An origin
//! that fails it — a refused dial, a reset, a GOAWAY past a stream, a
//! protocol error — fails every leg it carried, and each leg's exchange
//! decides what that means, exactly as a socket error would tell it.

const std = @import("std");
const h2 = @import("h2");

const Runtime = @import("../../extension.zig").Runtime;
const Session = @import("Session.zig");
const origin = @import("origin.zig");
const parser = @import("../parser.zig");
const render = @import("../render.zig");
const constants = @import("../../constants.zig");
const Io = @import("../../io/io.zig");
const OriginClient = @import("../../tls/OriginClient.zig");
const config_module = @import("../../config.zig");

const hpack = h2.hpack;
const assert = std.debug.assert;

/// A leg's staging buffer (§5): a head, the stream's window of payload, and
/// the last chunk with a trailer section. `Pool(Staging)` hands them out;
/// `data` is wired once into the pool's slab.
pub const Staging = struct {
    pool_next: u32,
    generation: u32,
    data: []u8,
};

/// The trailer section and the last chunk ahead of it.
const end_text_bytes_max: u32 = constants.chunked_trailer_bytes_max + "0\r\n".len;

/// The most session steps one drive round runs: each consumes a frame,
/// hands over an event, or returns, so the input is the real bound.
const drive_steps_max: u32 = 1 << 20;

/// The most rounds one drive runs. A round is asked for again by a kick
/// from inside the last one, which at most ends the connection, or — over
/// TLS — by decrypted octets fed to the session. Those are at most the
/// client's backlog and its two buffered records, 64 KiB, and a round
/// either fills the session's frame buffer, which then holds a whole
/// frame it consumes, or empties the backlog: two rounds per 16 KiB frame
/// at worst, with room to spare.
const drive_rounds_max: u32 = 64;

comptime {
    const plaintext_max = OriginClient.plaintext_bytes + 2 * OriginClient.record_plaintext_bytes_max;
    assert(drive_rounds_max > 2 * (plaintext_max / Session.frame_payload_bytes_max) + 2);
}

/// What one leg's buffer holds at most: a response head, a window of
/// payload, and the end of a chunked body.
pub fn stagingBytes(head_buffer_bytes: u32, window: u31) u32 {
    assert(head_buffer_bytes >= constants.head_buffer_bytes_min);
    assert(window >= 1);
    return head_buffer_bytes + window + end_text_bytes_max;
}

/// The window a stream to an origin advertises: what a relay buffer
/// carries in one read, capped at the protocol's default — the exchange
/// takes the payload a read at a time, so more would only wait here.
pub fn streamWindow(relay_buffer_bytes: u32) u31 {
    assert(relay_buffer_bytes >= constants.relay_buffer_bytes_min);
    return @intCast(@min(relay_buffer_bytes, Session.window_default));
}

/// The exchange's side of one stream to an origin: on the stream slot, and
/// zero-valued on every exchange that leases a socket instead. Pointers are
/// erased here so the stream slot need not name the backend; `Mux` casts
/// them back.
pub const Leg = struct {
    phase: Phase = .detached,
    /// The connection carrying it, and the next leg on that connection —
    /// a stream slot, erased.
    slot: ?*anyopaque = null,
    next: ?*anyopaque = null,
    staging: ?*Staging = null,
    /// The stream's identifier, once its head is staged.
    id: u31 = 0,
    /// What of the request body is still to be unframed into DATA.
    body: Body = .none,
    /// The request was a HEAD: its answer carries no body.
    bodiless: bool = false,
    /// END_STREAM is staged on the request side, or owed as soon as there
    /// is room for it.
    request_ended: bool = false,
    end_owed: bool = false,
    /// The answer's framing in the staged text, from its final head.
    framing: origin.Framing = .none,
    /// The staged octets, in order: head text, then payload, then the end.
    start: u32 = 0,
    head_text: u32 = 0,
    payload: u32 = 0,
    end_text: u32 = 0,
    send: Pending = .{},
    recv: Pending = .{},

    pub const Phase = enum(u8) {
        /// Not on an origin connection: the exchange leases a socket.
        detached,
        /// On one, its request head not yet a stream.
        waiting,
        open,
        /// The origin, or its connection, ended it: every op fails.
        failed,
    };

    pub const Body = union(enum) {
        none,
        length: u64,
        chunked: parser.ChunkedScanner,
    };

    /// An op the exchange armed: where its octets are, the completion it
    /// armed, the callback it named, and — once known — its result, which
    /// a zero-delay timer on that completion carries back.
    pub const Pending = struct {
        bytes: []u8 = &.{},
        completion: ?*anyopaque = null,
        callback: ?*const anyopaque = null,
        delivering: bool = false,
        count: u32 = 0,
        failed: bool = false,

        pub fn armed(pending: *const Pending) bool {
            return pending.callback != null;
        }
    };

    pub fn attached(leg: *const Leg) bool {
        return leg.phase != .detached;
    }

    fn staged(leg: *const Leg) u32 {
        return leg.head_text + leg.payload + leg.end_text;
    }
};

/// A gRPC health probe's stream on an origin connection (§7): the
/// `grpc.health.v1.Health/Check` call a `grpc` check makes, riding the
/// same pool the cluster's exchanges do — so it proves what they need, an
/// HTTP/2 connection (over TLS for `h2`, verified) and an application that
/// answers SERVING. Lives in the prober's probe slot; the verdict comes
/// back on the probe's own completion, through a zero-delay timer, as a
/// leg's does.
pub const ProbeLeg = struct {
    phase: Phase = .idle,
    slot: ?*anyopaque = null,
    next: ?*ProbeLeg = null,
    id: u31 = 0,
    /// `:authority`: the cluster's TLS name, or the endpoint's literal —
    /// what an `http` probe's `Host` defaults to — rendered into
    /// `authority_storage`. A slice into the leg itself, so a `ProbeLeg`
    /// stays where the prober put it: it is never copied while it is busy.
    authority: []const u8 = "",
    authority_storage: [constants.health_check_grpc_authority_bytes_max]u8 = undefined,
    /// The request message: the five-octet gRPC frame prefix and a
    /// `HealthCheckRequest` naming the service, when one is named.
    body: [5 + 2 + service_bytes_max]u8 = undefined,
    body_len: u32 = 0,
    /// Octets of `body` staged; the last carried END_STREAM.
    body_offset: u32 = 0,
    status_ok: bool = false,
    /// The response message's first octets: enough for the status field.
    payload: [constants.health_check_grpc_response_bytes_max]u8 = undefined,
    payload_len: u32 = 0,
    verdict: Verdict = .fail,
    completion: ?*anyopaque = null,
    callback: ?*const fn (*anyopaque, Verdict) void = null,
    context: ?*anyopaque = null,

    pub const Phase = enum(u8) { idle, waiting, open, delivering };

    pub const Verdict = enum(u8) {
        /// SERVING, said whole: `:status` 200, the message, `grpc-status` 0.
        pass,
        /// Anything else: no connection, a reset, another status, another
        /// message, no trailers.
        fail,
        /// No verdict: the pool had no connection to the endpoint and no
        /// room for one — this proxy's limit, which says nothing of the
        /// origin, and so must not eject it.
        skipped,
    };

    pub const service_bytes_max: u32 = constants.health_check_grpc_service_bytes_max;

    /// The cluster's TLS name — the one its certificate is verified
    /// against — or the endpoint's own literal; a socket path names no
    /// host, so `localhost` stands in for it.
    fn authorize(leg: *ProbeLeg, cluster: *const config_module.Config.Cluster, endpoint_index: u16) void {
        assert(endpoint_index < cluster.endpoints.len);
        if (cluster.tls) |*tls| {
            leg.authority = tls.server_name;
            return;
        }
        leg.authority = switch (cluster.endpoints[endpoint_index]) {
            // `ip_literal_bytes_max` is the longest literal; the test
            // below holds it to std's own spelling.
            .ip => |*ip| std.fmt.bufPrint(&leg.authority_storage, "{f}", .{ip.*}) catch unreachable,
            .unix => "localhost",
        };
        assert(leg.authority.len >= 1);
        assert(leg.authority.len <= constants.health_check_grpc_authority_bytes_max);
    }

    /// The request message: a `HealthCheckRequest` with field 1 (`service`)
    /// when one is named, empty otherwise, behind its frame prefix.
    fn compose(leg: *ProbeLeg, service: []const u8) void {
        assert(service.len <= service_bytes_max);
        const message_len: u32 = if (service.len == 0) 0 else @intCast(2 + service.len);
        leg.body[0] = 0; // Not compressed.
        std.mem.writeInt(u32, leg.body[1..5], message_len, .big);
        if (service.len >= 1) {
            leg.body[5] = 0x0a; // Field 1, length-delimited.
            leg.body[6] = @intCast(service.len);
            @memcpy(leg.body[7..][0..service.len], service);
        }
        leg.body_len = 5 + message_len;
        assert(leg.body_len <= leg.body.len);
        leg.body_offset = 0;
    }

    /// The response said SERVING: a frame holding a `HealthCheckResponse`
    /// whose field 1 (`status`) is 1, and nothing else.
    fn serving(leg: *const ProbeLeg) bool {
        assert(leg.payload_len <= leg.payload.len);
        // Strictly more is kept than a SERVING message is, so a longer
        // message cannot be cut down to look like one.
        comptime assert(constants.health_check_grpc_response_bytes_max > 7);
        const payload = leg.payload[0..leg.payload_len];
        if (payload.len != 7) return false;
        if (payload[0] != 0) return false;
        if (std.mem.readInt(u32, payload[1..5], .big) != 2) return false;
        return payload[5] == 0x08 and payload[6] == 1;
    }
};

pub fn Mux(comptime runtime: Runtime) type {
    const IoType = runtime.Io;
    const ServerType = @import("../../Server.zig").Server(runtime);
    const ConnType = @import("../../net/Conn.zig").Conn(runtime);
    const StreamType = ConnType.StreamType;

    return struct {
        const Self = @This();

        pub const SendCallback = fn (*StreamType, Io.SendError!u32) void;
        pub const RecvCallback = fn (*StreamType, Io.RecvError!u32) void;

        /// One connection to an origin endpoint: a carved session unit and
        /// the I/O around it, pooled (§5).
        pub const Slot = struct {
            pool_next: u32,
            generation: u32,
            /// Set at each dial; a completion finds its server through it.
            server: *ServerType,
            session: *Session,
            buffers: Session.Buffers,
            /// This slot's TLS client, wired once where some cluster speaks
            /// `h2` (null otherwise), and whether this connection uses it.
            tls: ?*OriginClient,
            tls_active: bool,
            socket: IoType.Socket,
            state: State,
            cluster_index: u16,
            endpoint_index: u16,
            /// The legs it carries, first-opened first: the order their
            /// heads become streams in.
            legs: ?*StreamType,
            legs_count: u32,
            /// The health probes riding it.
            probes: ?*ProbeLeg,
            probes_count: u32,
            sending: u32,
            receiving: bool,
            driving: bool,
            /// A kick landed while a drive ran: it runs another round.
            drive_again: bool,
            socket_open: bool,
            /// The dial's budget while connecting, the idle window after.
            deadline_ns: u64,
            /// The close has cancelled the timer once (§8, #206). A cancel that
            /// completes while the timer still has not delivered is not sent
            /// again: a timer whose completion is lost would otherwise turn every
            /// cancel's completion into the next cancel, a spin no virtual time
            /// passes in, so the drain's own backstop could never fire.
            timer_cancel_sent: bool = false,
            op_io: IoType.Completion,
            op_send: IoType.Completion,
            op_timer: IoType.Completion,
            op_cancel: IoType.Completion,
            armed: Armed,

            pub const State = enum(u8) { free, connecting, handshaking, open, closing };

            pub const Armed = packed struct(u8) {
                connect: bool = false,
                recv: bool = false,
                send: bool = false,
                timer: bool = false,
                cancel: bool = false,
                _: u3 = 0,

                fn any(armed: Armed) bool {
                    return armed.connect or armed.recv or armed.send or armed.timer or armed.cancel;
                }
            };

            pub fn reset(slot: *Slot) void {
                slot.state = .free;
                slot.legs = null;
                slot.legs_count = 0;
                slot.probes = null;
                slot.probes_count = 0;
                slot.sending = 0;
                slot.receiving = false;
                slot.driving = false;
                slot.drive_again = false;
                slot.socket_open = false;
                slot.tls_active = false;
                slot.deadline_ns = 0;
                slot.timer_cancel_sent = false;
                slot.armed = .{};
                assert(slot.buffers.inbound.len >= Session.frame_bytes_max);
            }
        };

        /// What `attach` came to.
        pub const Attached = enum {
            /// On a connection already open: a request on it is a reused
            /// connection's, which earns §7's free replay when it fails.
            reused,
            /// On a connection still being dialed, perhaps for this one.
            fresh,
            /// Shed: no connection to the endpoint has room and none is
            /// free to dial, or no staging buffer is left.
            shed_connections,
            shed_streams,
        };

        // -- the leg: what the exchange arms -------------------------------

        /// Put `stream`'s exchange on a connection to its endpoint: the
        /// least loaded one with room, or a new one dialed now.
        pub fn attach(server: *ServerType, stream: *StreamType, cluster_index: u16, endpoint_index: u16) Attached {
            const leg = &stream.h2_origin;
            assert(!leg.attached());
            assert(stream.upstream != null);
            const staging = server.h2_origin_staging.acquire() orelse return .shed_streams;
            const found = pickSlot(server, cluster_index, endpoint_index, .free);
            const slot = found orelse dial(server, cluster_index, endpoint_index) orelse {
                server.h2_origin_staging.release(staging);
                return .shed_connections;
            };
            leg.* = .{ .phase = .waiting, .slot = slot, .staging = staging };
            link(slot, stream);
            return if (found != null and slot.state == .open) .reused else .fresh;
        }

        /// The exchange sends: the rendered head first, which becomes the
        /// stream, then body octets, unframed into DATA.
        pub fn send(server: *ServerType, stream: *StreamType, bytes: []const u8, completion: *IoType.Completion, comptime callback: SendCallback) void {
            const leg = &stream.h2_origin;
            assert(leg.attached());
            assert(!leg.send.armed());
            assert(bytes.len >= 1);
            leg.send = .{
                .bytes = @constCast(bytes),
                .completion = completion,
                .callback = @ptrCast(&callback),
            };
            if (leg.phase == .failed) return deliverSend(server, stream, true);
            const slot = slotOf(leg);
            if (leg.phase == .open) pushBody(server, slot, stream);
            kick(server, slot);
        }

        /// The exchange reads: staged head text, payload, the end — as much
        /// as is there, or once something is.
        pub fn recv(server: *ServerType, stream: *StreamType, buffer: []u8, completion: *IoType.Completion, comptime callback: RecvCallback) void {
            const leg = &stream.h2_origin;
            assert(leg.attached());
            assert(!leg.recv.armed());
            assert(buffer.len >= 1);
            leg.recv = .{
                .bytes = buffer,
                .completion = completion,
                .callback = @ptrCast(&callback),
            };
            offerRecv(server, stream);
            if (leg.phase != .failed) kick(server, slotOf(leg));
        }

        /// Force what the exchange has armed to deliver, as shutting a
        /// socket down would (§8): an op still waiting fails now. The
        /// stream is reset if the origin still holds it, and the leg fails.
        pub fn shutdown(server: *ServerType, stream: *StreamType) void {
            const leg = &stream.h2_origin;
            assert(leg.attached());
            if (leg.phase == .failed) {
                forcePending(server, stream);
                return;
            }
            const slot = slotOf(leg);
            fail(server, slot, stream, .cancel);
            kick(server, slot);
        }

        /// The exchange is done with its upstream — answered, or ended —
        /// and nothing of it is armed: the stream is reset if it is not over,
        /// the staging buffer goes back, and the leg is off its connection.
        pub fn detach(server: *ServerType, stream: *StreamType) void {
            const leg = &stream.h2_origin;
            assert(leg.attached());
            assert(!leg.send.armed());
            assert(!leg.recv.armed());
            if (leg.phase != .failed) {
                const slot = slotOf(leg);
                resetIfOpen(slot, leg, .cancel);
                unlink(slot, stream);
                kick(server, slot);
                settleIdle(server, slot);
            }
            if (leg.staging) |staging| server.h2_origin_staging.release(staging);
            leg.* = .{};
        }

        /// Whether a connection must have a stream free (`.free`), or may be
        /// full (`.any`) — a probe waits there for a stream to end.
        const Room = enum { free, any };

        /// The least loaded connection to the endpoint that can take one
        /// more stream, if any — or, for `.any`, that will.
        fn pickSlot(server: *ServerType, cluster_index: u16, endpoint_index: u16, room: Room) ?*Slot {
            assert(cluster_index < server.config.clusters.len);
            assert(endpoint_index < server.config.clusters[cluster_index].endpoints.len);
            var best: ?*Slot = null;
            for (server.h2_origins.slots) |*slot| {
                if (!server.h2_origins.isAcquired(slot)) continue;
                if (slot.cluster_index != cluster_index or slot.endpoint_index != endpoint_index) continue;
                if (slot.state != .connecting and slot.state != .handshaking and slot.state != .open) continue;
                if (slot.state == .open and slot.session.goingAway()) continue;
                const carried = slot.legs_count + slot.probes_count;
                if (room == .free and carried >= server.h2OriginSessionConfig().concurrent_streams_max) continue;
                if (best == null or carried < best.?.legs_count + best.?.probes_count) best = slot;
            }
            return best;
        }

        fn slotOf(leg: *const Leg) *Slot {
            assert(leg.phase != .detached and leg.phase != .failed);
            return @ptrCast(@alignCast(leg.slot.?));
        }

        fn nextOf(stream: *const StreamType) ?*StreamType {
            assert(stream.h2_origin.phase != .detached);
            const next = stream.h2_origin.next orelse return null;
            const typed: *StreamType = @ptrCast(@alignCast(next));
            assert(typed != stream);
            return typed;
        }

        /// Appended, so the list is in the order heads arrive in.
        fn link(slot: *Slot, stream: *StreamType) void {
            assert(stream.h2_origin.next == null);
            slot.legs_count += 1;
            if (slot.legs == null) {
                slot.legs = stream;
                return;
            }
            var cursor = slot.legs.?;
            var visited: u32 = 0;
            while (nextOf(cursor)) |next| : (visited += 1) {
                assert(visited < slot.legs_count);
                cursor = next;
            }
            cursor.h2_origin.next = stream;
        }

        fn unlink(slot: *Slot, stream: *StreamType) void {
            assert(slot.legs_count >= 1);
            slot.legs_count -= 1;
            const next = nextOf(stream);
            stream.h2_origin.next = null;
            if (slot.legs == stream) {
                slot.legs = next;
                return;
            }
            var cursor = slot.legs.?;
            var visited: u32 = 0;
            while (nextOf(cursor)) |candidate| : (visited += 1) {
                assert(visited <= slot.legs_count);
                if (candidate == stream) {
                    cursor.h2_origin.next = next;
                    return;
                }
                cursor = candidate;
            }
            unreachable; // Only a linked leg is unlinked.
        }

        fn find(slot: *Slot, id: u31) ?*StreamType {
            assert(id != 0);
            var cursor = slot.legs;
            var visited: u32 = 0;
            while (cursor) |stream| : (cursor = nextOf(stream)) {
                assert(visited < slot.legs_count);
                visited += 1;
                if (stream.h2_origin.id == id) return stream;
            }
            return null;
        }

        // -- health probes (§7) ----------------------------------------------

        /// Ask the endpoint's application whether it is SERVING, on a
        /// connection to it — the least loaded with room, or a new one.
        /// The verdict comes back through `callback` on `completion`.
        pub fn probe(
            server: *ServerType,
            leg: *ProbeLeg,
            cluster_index: u16,
            endpoint_index: u16,
            service: []const u8,
            completion: *IoType.Completion,
            context: *anyopaque,
            callback: *const fn (*anyopaque, ProbeLeg.Verdict) void,
        ) void {
            assert(leg.phase == .idle);
            assert(service.len <= ProbeLeg.service_bytes_max);
            const cluster = &server.config.clusters[cluster_index];
            assert(cluster.protocol.http2());
            leg.* = .{
                .phase = .waiting,
                .completion = completion,
                .callback = callback,
                .context = context,
            };
            leg.authorize(cluster, endpoint_index);
            leg.compose(service);
            // The pool full, a probe waits on a full connection to its
            // endpoint for a stream, rather than failing for a limit of
            // this proxy's; with none at all, it has no verdict.
            const slot = pickSlot(server, cluster_index, endpoint_index, .free) orelse
                dial(server, cluster_index, endpoint_index) orelse
                pickSlot(server, cluster_index, endpoint_index, .any) orelse
                return deliverProbe(server, leg, .skipped);
            leg.slot = slot;
            leg.next = slot.probes;
            slot.probes = leg;
            slot.probes_count += 1;
            kick(server, slot);
        }

        /// The prober's budget ran out, or it is stopping: the probe fails
        /// now, its stream reset if it has one.
        pub fn cancelProbe(server: *ServerType, leg: *ProbeLeg) void {
            // Delivered already, or on its way: the verdict stands.
            if (leg.phase != .waiting and leg.phase != .open) return;
            assert(leg.slot != null);
            const slot: *Slot = @ptrCast(@alignCast(leg.slot.?));
            assert(slot.probes_count >= 1);
            finishProbe(server, slot, leg, .fail);
            assert(leg.phase == .delivering);
            kick(server, slot);
        }

        fn findProbe(slot: *Slot, id: u31) ?*ProbeLeg {
            assert(id != 0);
            var cursor = slot.probes;
            var visited: u32 = 0;
            while (cursor) |leg| : (cursor = leg.next) {
                assert(visited < slot.probes_count);
                visited += 1;
                if (leg.phase == .open and leg.id == id) return leg;
            }
            return null;
        }

        fn openWaitingProbes(server: *ServerType, slot: *Slot) void {
            var cursor = slot.probes;
            var visited: u32 = 0;
            while (cursor) |leg| {
                assert(visited < slot.probes_count);
                visited += 1;
                cursor = leg.next;
                if (leg.phase != .waiting) continue;
                if (!slot.session.openable()) return;
                const cluster = &server.config.clusters[slot.cluster_index];
                const fields = [_]hpack.Field{
                    .{ .name = ":method", .value = "POST" },
                    .{ .name = ":scheme", .value = if (cluster.tls != null) "https" else "http" },
                    .{ .name = ":authority", .value = leg.authority },
                    .{ .name = ":path", .value = "/grpc.health.v1.Health/Check" },
                    .{ .name = "content-type", .value = "application/grpc" },
                    .{ .name = "te", .value = "trailers" },
                };
                switch (slot.session.openRequest(&fields, false, false)) {
                    .stream => |id| {
                        leg.id = id;
                        leg.phase = .open;
                        sendProbeBody(slot, leg);
                    },
                    .blocked => return,
                    .refused => finishProbe(server, slot, leg, .fail),
                }
            }
        }

        /// The request message, as far as the windows and the outbox
        /// allow; the rest waits for `.writable`.
        fn sendProbeBody(slot: *Slot, leg: *ProbeLeg) void {
            assert(leg.phase == .open);
            assert(leg.body_offset <= leg.body_len);
            if (leg.body_offset == leg.body_len) return;
            const sent = slot.session.sendData(leg.id, leg.body[leg.body_offset..leg.body_len], true);
            leg.body_offset += sent.taken;
            // END_STREAM goes with the last octet, so all of it is sent once
            // the stream's half has ended.
            assert(sent.ended == (leg.body_offset == leg.body_len));
        }

        fn onProbeResponse(server: *ServerType, slot: *Slot, leg: *ProbeLeg, response: *const Session.Step.Response) void {
            assert(leg.phase == .open);
            if (response.interim) return;
            leg.status_ok = response.status == 200;
            // A trailers-only answer carries its `grpc-status` here, and no
            // message: whatever it says, it did not say SERVING.
            if (response.end_stream or !leg.status_ok) finishProbe(server, slot, leg, .fail);
        }

        /// The response message's octets, as far as `payload` holds them:
        /// a longer one is not the one a SERVING answer is, and the rest is
        /// credited back unread.
        fn onProbeData(server: *ServerType, slot: *Slot, leg: *ProbeLeg, data: *const Session.Step.Data) void {
            assert(leg.phase == .open);
            assert(leg.payload_len <= leg.payload.len);
            const length: u32 = @intCast(data.bytes.len);
            if (length >= 1) {
                const take: u32 = @min(length, @as(u32, leg.payload.len) - leg.payload_len);
                @memcpy(leg.payload[leg.payload_len..][0..take], data.bytes[0..take]);
                leg.payload_len += take;
                slot.session.consume(data.stream, length);
            }
            // A gRPC answer ends on its trailers; one that ends on DATA did
            // not carry a status.
            if (data.end_stream) finishProbe(server, slot, leg, .fail);
        }

        fn onProbeTrailers(server: *ServerType, slot: *Slot, leg: *ProbeLeg, trailers: *const Session.Step.Trailers) void {
            assert(leg.phase == .open);
            var ok = false;
            for (trailers.fields) |*field| {
                if (std.mem.eql(u8, field.name, "grpc-status")) ok = std.mem.eql(u8, field.value, "0");
            }
            const passed = ok and leg.status_ok and leg.serving();
            finishProbe(server, slot, leg, if (passed) .pass else .fail);
        }

        /// The probe is decided: off its connection, its stream reset if
        /// the origin still holds it, and the verdict on its way.
        fn finishProbe(server: *ServerType, slot: *Slot, leg: *ProbeLeg, verdict: ProbeLeg.Verdict) void {
            assert(leg.phase == .waiting or leg.phase == .open);
            assert(leg.slot == @as(?*anyopaque, slot));
            if (leg.phase == .open and slot.session.state != .closed and slot.session.resettable(leg.id)) {
                slot.session.resetStream(leg.id, .cancel);
            }
            unlinkProbe(slot, leg);
            assert(leg.slot == null);
            deliverProbe(server, leg, verdict);
            settleIdle(server, slot);
        }

        fn unlinkProbe(slot: *Slot, leg: *ProbeLeg) void {
            assert(slot.probes_count >= 1);
            if (slot.probes == leg) {
                slot.probes = leg.next;
            } else {
                var cursor = slot.probes.?;
                var visited: u32 = 0;
                while (cursor.next) |next| : (cursor = next) {
                    assert(visited < slot.probes_count);
                    visited += 1;
                    if (next == leg) {
                        cursor.next = leg.next;
                        break;
                    }
                }
            }
            leg.next = null;
            leg.slot = null;
            slot.probes_count -= 1;
        }

        fn deliverProbe(server: *ServerType, leg: *ProbeLeg, verdict: ProbeLeg.Verdict) void {
            assert(leg.phase != .idle and leg.phase != .delivering);
            assert(leg.slot == null);
            leg.phase = .delivering;
            leg.verdict = verdict;
            const completion: *IoType.Completion = @ptrCast(@alignCast(leg.completion.?));
            server.io.timerStart(completion, 0, ProbeLeg, leg, onProbeDelivered);
            assert(leg.phase == .delivering);
        }

        fn onProbeDelivered(leg: *ProbeLeg, result: Io.TimerError!void) void {
            result catch unreachable; // Nothing cancels a delivery.
            assert(leg.phase == .delivering);
            assert(leg.slot == null);
            leg.phase = .idle;
            leg.callback.?(leg.context.?, leg.verdict);
        }

        /// The connection is over: every probe on it fails.
        fn failProbes(server: *ServerType, slot: *Slot) void {
            const count = slot.probes_count;
            var passes: u32 = 0;
            while (slot.probes) |leg| : (passes += 1) {
                assert(passes < count);
                unlinkProbe(slot, leg);
                deliverProbe(server, leg, .fail);
            }
            assert(slot.probes_count == 0);
        }

        // -- the request -------------------------------------------------

        /// Open the waiting legs whose heads have arrived, in order, while
        /// the session can open a stream.
        fn openWaiting(server: *ServerType, slot: *Slot) void {
            assert(slot.state == .open);
            openWaitingProbes(server, slot);
            var cursor = slot.legs;
            var visited: u32 = 0;
            while (cursor) |stream| {
                assert(visited < slot.legs_count);
                visited += 1;
                // Taken first: a refused head fails its leg, and unlinks it.
                cursor = nextOf(stream);
                const leg = &stream.h2_origin;
                if (leg.phase != .waiting or !leg.send.armed() or leg.send.delivering) continue;
                if (!slot.session.openable()) return;
                if (!openOne(server, slot, stream)) return;
            }
        }

        /// One head, mapped and staged. False when the outbox has no room
        /// for it yet, which waits for the next send's completion.
        fn openOne(server: *ServerType, slot: *Slot, stream: *StreamType) bool {
            const leg = &stream.h2_origin;
            const head = leg.send.bytes;
            assert(head.len >= 1);
            const scratch = &server.h2_origin_scratch;
            const request = origin.requestFields(head, "http", &scratch.headers, &.{
                .fields = scratch.fields,
                .bytes = scratch.bytes,
            }) catch {
                server.counters.increment("h2_origin_refused_heads");
                fail(server, slot, stream, .internal_error);
                return true;
            };
            // The exchange sends its rendered head whole, and alone.
            assert(request.head_len == head.len);
            const end_stream = request.framing == .none;
            switch (slot.session.openRequest(request.fields, end_stream, request.bodiless)) {
                .stream => |id| {
                    leg.id = id;
                    leg.phase = .open;
                    // #423: the exchange's request can go out now, on a
                    // connection it found open or one dialed for it.
                    server.notePickConnected(stream);
                    leg.request_ended = end_stream;
                    leg.bodiless = request.bodiless;
                    leg.body = switch (request.framing) {
                        .none => .none,
                        .content_length => |length| .{ .length = length },
                        .chunked => .{ .chunked = .{} },
                        .until_close => unreachable, // A request's never is.
                    };
                    leg.send.count = @intCast(head.len);
                    deliverSend(server, stream, false);
                    return true;
                },
                .blocked => return false,
                .refused => {
                    server.counters.increment("h2_origin_refused_heads");
                    fail(server, slot, stream, .internal_error);
                    return true;
                },
            }
        }

        /// Body octets the exchange offered, unframed as far as both
        /// windows and the outbox allow; the send completes with what was
        /// taken, or waits for `.writable` when nothing could be.
        fn pushBody(server: *ServerType, slot: *Slot, stream: *StreamType) void {
            const leg = &stream.h2_origin;
            assert(leg.phase == .open);
            if (leg.end_owed) endBody(slot, leg);
            if (!leg.send.armed() or leg.send.delivering) return;
            assert(!leg.request_ended or leg.end_owed);
            const taken = frameBody(slot, leg, leg.send.bytes) catch {
                fail(server, slot, stream, .internal_error);
                return;
            };
            if (leg.end_owed) endBody(slot, leg);
            if (taken == 0) return;
            leg.send.count = taken;
            deliverSend(server, stream, false);
        }

        /// What of `bytes` went out as DATA, framing included in the count.
        fn frameBody(slot: *Slot, leg: *Leg, bytes: []const u8) error{Malformed}!u32 {
            assert(bytes.len >= 1);
            switch (leg.body) {
                .none => return error.Malformed, // No body was declared.
                .length => |*remaining| {
                    const take: u32 = @intCast(@min(remaining.*, bytes.len));
                    if (take == 0) return error.Malformed;
                    const sent = slot.session.sendData(leg.id, bytes[0..take], take == remaining.*);
                    remaining.* -= sent.taken;
                    if (sent.ended) leg.request_ended = true;
                    return sent.taken;
                },
                .chunked => |*scanner| return frameChunked(slot, leg, scanner, bytes),
            }
        }

        /// A chunked body: chunk data goes as DATA, the framing around it is
        /// consumed, and the last chunk owes END_STREAM. A request's trailer
        /// section goes no further, as on an HTTP/2 client's (§7).
        fn frameChunked(slot: *Slot, leg: *Leg, scanner: *parser.ChunkedScanner, bytes: []const u8) error{Malformed}!u32 {
            var index: u32 = 0;
            while (index < bytes.len) {
                if (scanner.state == .done) break;
                if (scanner.state != .data) {
                    _ = scanner.feed(bytes[index..][0..1]) catch return error.Malformed;
                    index += 1;
                    if (scanner.state == .done) leg.end_owed = true;
                    continue;
                }
                const run: u32 = @intCast(@min(scanner.data_remaining, bytes.len - index));
                const sent = slot.session.sendData(leg.id, bytes[index..][0..run], false);
                if (sent.taken >= 1) {
                    const fed = scanner.feed(bytes[index..][0..sent.taken]) catch unreachable;
                    assert(fed.consumed == sent.taken);
                    index += sent.taken;
                }
                if (sent.taken < run) break;
            }
            assert(index <= bytes.len);
            return index;
        }

        fn endBody(slot: *Slot, leg: *Leg) void {
            assert(leg.end_owed);
            assert(!leg.request_ended);
            const sent = slot.session.sendData(leg.id, &.{}, true);
            if (!sent.ended) return;
            leg.end_owed = false;
            leg.request_ended = true;
        }

        // -- the answer --------------------------------------------------

        fn onResponse(server: *ServerType, slot: *Slot, response: *const Session.Step.Response) void {
            const stream = find(slot, response.stream) orelse return;
            const leg = &stream.h2_origin;
            assert(leg.phase == .open);
            // Heads come before any payload, and their text is held to what
            // the exchange's head buffer can read: the rest of the buffer is
            // the window's, and the end's.
            assert(leg.payload == 0 and leg.end_text == 0);
            const head_room = server.h2_origin_head_bytes -| leg.head_text;
            const free = stagingTail(leg);
            const head = origin.responseHead(&.{
                .status = response.status,
                .fields = response.fields,
                .content_length = response.content_length,
                .interim = response.interim,
                .end_stream = response.end_stream,
                .bodiless = leg.bodiless,
            }, free[0..@min(free.len, head_room)]) catch {
                server.counters.increment("h2_origin_refused_answers");
                return fail(server, slot, stream, .internal_error);
            };
            leg.head_text += head.len;
            if (!response.interim) leg.framing = head.framing;
            offerRecv(server, stream);
        }

        fn onData(server: *ServerType, slot: *Slot, data: *const Session.Step.Data) void {
            const stream = find(slot, data.stream) orelse return;
            const leg = &stream.h2_origin;
            assert(leg.phase == .open);
            const length: u32 = @intCast(data.bytes.len);
            if (length >= 1) {
                if (leg.framing == .none) {
                    // An answer that can carry no body: its octets go back.
                    slot.session.consume(data.stream, length);
                } else {
                    const tail = stagingTail(leg);
                    // The window is what the buffer holds behind a head.
                    assert(length <= tail.len);
                    @memcpy(tail[0..length], data.bytes);
                    leg.payload += length;
                }
            }
            if (data.end_stream) stageEnd(leg, &.{}) catch unreachable; // No fields.
            offerRecv(server, stream);
        }

        fn onTrailers(server: *ServerType, slot: *Slot, trailers: *const Session.Step.Trailers) void {
            const stream = find(slot, trailers.stream) orelse return;
            const leg = &stream.h2_origin;
            assert(leg.phase == .open);
            stageEnd(leg, trailers.fields) catch {
                server.counters.increment("h2_origin_refused_answers");
                return fail(server, slot, stream, .internal_error);
            };
            offerRecv(server, stream);
        }

        /// The origin's END_STREAM: a chunked answer's last chunk, with the
        /// trailer section if one came. A declared length ends on its own
        /// count, and a section has no place in it, so it is dropped.
        fn stageEnd(leg: *Leg, fields: []const hpack.Field) origin.Error!void {
            assert(leg.phase == .open);
            assert(leg.end_text == 0); // The origin ends a stream once.
            if (leg.framing != .chunked) return;
            const tail = stagingTail(leg);
            const written = try origin.trailerSection(fields, tail);
            leg.end_text += written;
        }

        /// The buffer's room behind what is staged, the staged run moved to
        /// the front first when it is not there.
        fn stagingTail(leg: *Leg) []u8 {
            const data = leg.staging.?.data;
            const staged = leg.staged();
            assert(leg.start + staged <= data.len);
            if (leg.start != 0) {
                std.mem.copyForwards(u8, data[0..staged], data[leg.start..][0..staged]);
                leg.start = 0;
            }
            return data[staged..];
        }

        /// Hand the exchange's armed read what is staged, if anything is or
        /// the leg failed.
        fn offerRecv(server: *ServerType, stream: *StreamType) void {
            const leg = &stream.h2_origin;
            assert(leg.attached());
            assert(leg.staging != null);
            if (!leg.recv.armed() or leg.recv.delivering) return;
            const copied = copyOut(stream, leg.recv.bytes);
            if (copied >= 1) {
                leg.recv.count = copied;
                return deliverRecv(server, stream, false);
            }
            if (leg.phase == .failed) deliverRecv(server, stream, true);
        }

        /// The next run of staged text into `buffer`: head text alone, then
        /// payload — a chunk of it, when the answer is chunked — then the
        /// end. Payload taken is credited back to the origin.
        fn copyOut(stream: *StreamType, buffer: []u8) u32 {
            const leg = &stream.h2_origin;
            assert(buffer.len >= 1);
            assert(leg.start + leg.staged() <= leg.staging.?.data.len);
            if (leg.staged() == 0) return 0;
            const data = leg.staging.?.data;
            if (leg.head_text >= 1) {
                const count: u32 = @intCast(@min(leg.head_text, buffer.len));
                @memcpy(buffer[0..count], data[leg.start..][0..count]);
                leg.head_text -= count;
                leg.start += count;
                return count;
            }
            if (leg.payload >= 1) return copyPayload(stream, buffer);
            const count: u32 = @intCast(@min(leg.end_text, buffer.len));
            @memcpy(buffer[0..count], data[leg.start..][0..count]);
            leg.end_text -= count;
            leg.start += count;
            return count;
        }

        fn copyPayload(stream: *StreamType, buffer: []u8) u32 {
            const leg = &stream.h2_origin;
            const data = leg.staging.?.data;
            assert(leg.payload >= 1);
            const overhead: u32 = if (leg.framing == .chunked)
                render.chunk_prefix_bytes_max + render.chunk_suffix.len
            else
                0;
            // Every buffer an exchange reads into is a head or a relay
            // buffer's half: far wider than one chunk's framing.
            assert(buffer.len > overhead);
            const take: u32 = @intCast(@min(leg.payload, buffer.len - overhead));
            var written: u32 = 0;
            if (leg.framing == .chunked) {
                var prefix_storage: [render.chunk_prefix_bytes_max]u8 = undefined;
                const prefix = render.chunkPrefix(take, &prefix_storage);
                @memcpy(buffer[0..prefix.len], prefix);
                written = @intCast(prefix.len);
            }
            @memcpy(buffer[written..][0..take], data[leg.start..][0..take]);
            written += take;
            if (leg.framing == .chunked) {
                @memcpy(buffer[written..][0..render.chunk_suffix.len], render.chunk_suffix);
                written += render.chunk_suffix.len;
            }
            leg.payload -= take;
            leg.start += take;
            // Credited: the window opens by what the exchange has taken —
            // on a session still open to take it.
            if (leg.phase == .open) {
                const slot = slotOf(leg);
                if (slot.session.state != .closed) slot.session.consume(leg.id, take);
            }
            assert(written <= buffer.len);
            return written;
        }

        // -- delivery ----------------------------------------------------

        fn deliverSend(server: *ServerType, stream: *StreamType, failed: bool) void {
            const leg = &stream.h2_origin;
            assert(leg.send.armed());
            assert(!leg.send.delivering);
            leg.send.delivering = true;
            leg.send.failed = failed;
            const completion: *IoType.Completion = @ptrCast(@alignCast(leg.send.completion.?));
            server.io.timerStart(completion, 0, StreamType, stream, onSendDelivered);
        }

        fn deliverRecv(server: *ServerType, stream: *StreamType, failed: bool) void {
            const leg = &stream.h2_origin;
            assert(leg.recv.armed());
            assert(!leg.recv.delivering);
            leg.recv.delivering = true;
            leg.recv.failed = failed;
            const completion: *IoType.Completion = @ptrCast(@alignCast(leg.recv.completion.?));
            server.io.timerStart(completion, 0, StreamType, stream, onRecvDelivered);
        }

        fn onSendDelivered(stream: *StreamType, result: Io.TimerError!void) void {
            result catch unreachable; // Nothing cancels a delivery.
            const leg = &stream.h2_origin;
            assert(leg.send.delivering);
            const pending = leg.send;
            leg.send = .{};
            // Function pointers are 4-aligned on aarch64: the erased pointer says 1.
            const callback: *const SendCallback = @ptrCast(@alignCast(pending.callback.?));
            if (pending.failed) return callback(stream, error.Reset);
            assert(pending.count >= 1);
            callback(stream, pending.count);
        }

        fn onRecvDelivered(stream: *StreamType, result: Io.TimerError!void) void {
            result catch unreachable; // Nothing cancels a delivery.
            const leg = &stream.h2_origin;
            assert(leg.recv.delivering);
            const pending = leg.recv;
            leg.recv = .{};
            const callback: *const RecvCallback = @ptrCast(@alignCast(pending.callback.?));
            if (pending.failed) return callback(stream, error.Reset);
            assert(pending.count >= 1);
            callback(stream, pending.count);
        }

        /// The leg is over for the origin: reset if the session still holds
        /// its stream, off its connection, and every op it has armed — or
        /// arms from now on — fails.
        fn fail(server: *ServerType, slot: *Slot, stream: *StreamType, code: h2.frame.ErrorCode) void {
            const leg = &stream.h2_origin;
            assert(leg.phase == .waiting or leg.phase == .open);
            resetIfOpen(slot, leg, code);
            unlink(slot, stream);
            leg.phase = .failed;
            leg.slot = null;
            forcePending(server, stream);
            settleIdle(server, slot);
        }

        fn resetIfOpen(slot: *Slot, leg: *const Leg, code: h2.frame.ErrorCode) void {
            assert(code != .no_error);
            assert(slot.state != .free);
            if (leg.phase != .open) return;
            if (slot.session.state == .closed) return;
            if (!slot.session.resettable(leg.id)) return;
            slot.session.resetStream(leg.id, code);
        }

        /// Ops armed on a failed leg deliver their failure — those already
        /// carrying a result are left to deliver it.
        fn forcePending(server: *ServerType, stream: *StreamType) void {
            const leg = &stream.h2_origin;
            assert(leg.phase == .failed);
            if (leg.send.armed() and !leg.send.delivering) deliverSend(server, stream, true);
            if (leg.recv.armed() and !leg.recv.delivering) offerRecv(server, stream);
        }

        // -- the connection ------------------------------------------------

        /// A new connection to the endpoint, dialing — or null when the pool
        /// is empty.
        fn dial(server: *ServerType, cluster_index: u16, endpoint_index: u16) ?*Slot {
            const slot = server.h2_origins.acquire() orelse return null;
            slot.reset();
            assert(slot.legs_count == 0);
            assert(!slot.armed.any());
            slot.server = server;
            slot.state = .connecting;
            slot.cluster_index = cluster_index;
            slot.endpoint_index = endpoint_index;
            server.counters.increment("h2_origin_connections");
            const address = &server.config.clusters[cluster_index].endpoints[endpoint_index];
            slot.armed.connect = true;
            server.io.connect(address, &slot.op_io, Slot, slot, onConnect);
            armTimer(server, slot, server.config.connect_timeout_ms);
            return slot;
        }

        fn onConnect(slot: *Slot, result: Io.ConnectError!IoType.Socket) void {
            const server = serverOf(slot);
            assert(slot.armed.connect);
            slot.armed.connect = false;
            if (slot.state == .closing) {
                if (result) |socket| {
                    slot.socket = socket;
                    slot.socket_open = true;
                } else |_| {}
                return continueClose(server, slot);
            }
            assert(slot.state == .connecting);
            const socket = result catch |err| {
                server.counters.increment("h2_origin_connect_failed");
                server.witnessKernelPressure(.connect, err);
                if (err != error.Unexpected) {
                    server.health.witnessPassiveFailure(slot.cluster_index, slot.endpoint_index);
                }
                return close(server, slot);
            };
            slot.socket = socket;
            slot.socket_open = true;
            server.disableNagle(socket, server.endpointIsUnix(slot.cluster_index, slot.endpoint_index));
            if (server.config.clusters[slot.cluster_index].tls) |*tls| return startTls(server, slot, tls);
            openSession(server, slot);
        }

        /// The connection speaks HTTP/2 from here: the session's preface
        /// and SETTINGS are staged, and the idle window starts.
        fn openSession(server: *ServerType, slot: *Slot) void {
            assert(slot.state == .connecting or slot.state == .handshaking);
            assert(slot.socket_open);
            slot.state = .open;
            slot.session.init(server.h2OriginSessionConfig(), &slot.buffers);
            slot.deadline_ns = server.io.nowNs() + @as(u64, server.idleTimeoutMs()) * std.time.ns_per_ms;
            drive(server, slot);
        }

        /// TLS first (RFC 9113 §3.2): the ClientHello goes out, offering
        /// `h2` and naming the cluster's server, and the session waits for
        /// the handshake — under the dial's budget still.
        fn startTls(server: *ServerType, slot: *Slot, tls: *const config_module.Config.Cluster.Tls) void {
            assert(slot.state == .connecting);
            const client = slot.tls.?;
            var entropy: [64]u8 = undefined;
            server.io.fillRandom(&entropy);
            // A scalar of zeros is the one x25519 refuses; the stream is
            // random, so this never moves anything a peer could see.
            entropy[32] |= 1;
            client.start(&.{
                .server_name = tls.server_name,
                .anchors = tls.anchors,
                .client_random = entropy[0..32].*,
                .x25519_private = entropy[32..64].*,
                .now_sec = nowSec(server),
            });
            slot.tls_active = true;
            slot.state = .handshaking;
            flush(server, slot);
            armRecv(server, slot);
        }

        fn nowSec(server: *const ServerType) i64 {
            return @intCast(server.io.nowWallNs() / std.time.ns_per_s);
        }

        /// The handshake moved: once it is done, the origin must have
        /// selected `h2` — the session opens; until then, owed flights go
        /// out and the next records are read.
        fn handshakeProgress(server: *ServerType, slot: *Slot) void {
            assert(slot.state == .handshaking);
            const client = slot.tls.?;
            if (client.closed) return tlsFailed(server, slot);
            if (client.connected) {
                if (!client.alpnIsH2()) return tlsFailed(server, slot);
                return openSession(server, slot);
            }
            flush(server, slot);
            if (!slot.receiving and client.canReceive()) armRecv(server, slot);
        }

        /// The handshake or a record failed — a chain that did not verify,
        /// no `h2`, a record that did not open: the connection is over, and
        /// counted against its endpoint as a refused dial would be.
        fn tlsFailed(server: *ServerType, slot: *Slot) void {
            assert(slot.tls_active);
            server.counters.increment("h2_origin_tls_failed");
            server.health.witnessPassiveFailure(slot.cluster_index, slot.endpoint_index);
            close(server, slot);
        }

        fn serverOf(slot: *Slot) *ServerType {
            assert(slot.state != .free);
            return slot.server;
        }

        /// Step the session until it waits, hand each event to its leg,
        /// open what waits, and keep a read and a send where they belong.
        /// A kick from inside a drive — a leg failing as its head is
        /// opened, which may leave the connection idle and owe a GOAWAY —
        /// asks that drive for another round rather than starting a second
        /// one under it, so nothing it reads is changed beneath it.
        fn kick(server: *ServerType, slot: *Slot) void {
            assert(slot.state != .free);
            if (slot.state != .open) return;
            if (slot.driving) {
                slot.drive_again = true;
                return;
            }
            drive(server, slot);
        }

        fn drive(server: *ServerType, slot: *Slot) void {
            assert(slot.state == .open);
            assert(!slot.driving);
            slot.driving = true;
            var rounds: u32 = 0;
            var tls_failed = false;
            while (rounds < drive_rounds_max) : (rounds += 1) {
                slot.drive_again = false;
                const waiting = stepEvents(server, slot);
                if (slot.session.state == .closed) break;
                // Decrypted octets waiting for room the session just made.
                if (waiting and slot.tls_active) {
                    const fed = feedPlaintext(slot) catch blk: {
                        tls_failed = true;
                        break :blk false;
                    };
                    if (tls_failed) break;
                    if (fed) slot.drive_again = true;
                }
                openWaiting(server, slot);
                if (!slot.drive_again) break;
            }
            assert(rounds < drive_rounds_max);
            slot.driving = false;
            assert(slot.state == .open);
            if (tls_failed) return tlsFailed(server, slot);
            if (slot.session.state == .closed) {
                failLegs(server, slot);
                flush(server, slot);
                if (slot.sending == 0) close(server, slot);
                return;
            }
            flush(server, slot);
            if (slot.tls_active and slot.tls.?.closed and slot.tls.?.plaintext_len == 0) {
                // The origin's close_notify: what it said is all read.
                return close(server, slot);
            }
            if (!slot.receiving and recvRoom(slot)) armRecv(server, slot);
        }

        /// Hand the session decrypted octets, as many as its buffer takes,
        /// and decrypt what records are buffered behind them. True when it
        /// took some, so the drive steps again.
        fn feedPlaintext(slot: *Slot) OriginClient.Error!bool {
            assert(slot.tls_active);
            const client = slot.tls.?;
            try client.process();
            if (client.plaintext_len == 0) return false;
            const taken = client.takePlaintext(slot.session.recvBuffer());
            assert(taken >= 1);
            slot.session.received(taken);
            try client.process();
            return true;
        }

        /// Whether a read has somewhere to land: over TLS, the record buffer
        /// may be full of records waiting for the session to take their
        /// plaintext, and a read then waits for that.
        fn recvRoom(slot: *Slot) bool {
            if (!slot.tls_active) return true;
            return slot.tls.?.canReceive();
        }

        /// Step the session until it waits, each event to its leg. True when
        /// it waits for input — the one state in which more may be fed it.
        fn stepEvents(server: *ServerType, slot: *Slot) bool {
            assert(slot.driving);
            var steps: u32 = 0;
            while (steps < drive_steps_max) : (steps += 1) {
                const step = slot.session.step();
                switch (step) {
                    // Only a completed send makes room; this waits for it.
                    .flush_first => {
                        flush(server, slot);
                        return false;
                    },
                    .need_input => return true,
                    .closed => return false,
                    .response => |*response| if (findProbe(slot, response.stream)) |leg| {
                        onProbeResponse(server, slot, leg, response);
                    } else onResponse(server, slot, response),
                    .data => |*data| if (findProbe(slot, data.stream)) |leg| {
                        onProbeData(server, slot, leg, data);
                    } else onData(server, slot, data),
                    .trailers => |*trailers| if (findProbe(slot, trailers.stream)) |leg| {
                        onProbeTrailers(server, slot, leg, trailers);
                    } else onTrailers(server, slot, trailers),
                    .reset => |reset| if (findProbe(slot, reset.stream)) |leg| {
                        finishProbe(server, slot, leg, .fail);
                    } else onReset(server, slot, reset.stream),
                    .writable => |writable| if (find(slot, writable.stream)) |stream| {
                        pushBody(server, slot, stream);
                    } else if (findProbe(slot, writable.stream)) |leg| {
                        sendProbeBody(slot, leg);
                    },
                    .request => unreachable, // A client session raises none.
                }
            }
            // Every step consumes a frame or hands over an event: the input
            // runs out long before this does.
            unreachable;
        }

        fn onReset(server: *ServerType, slot: *Slot, id: u31) void {
            assert(slot.driving);
            const stream = find(slot, id) orelse return;
            const leg = &stream.h2_origin;
            assert(leg.phase == .open);
            server.counters.increment("h2_origin_streams_reset");
            // Already gone from the session: nothing more to reset.
            unlink(slot, stream);
            leg.phase = .failed;
            leg.slot = null;
            forcePending(server, stream);
            settleIdle(server, slot);
        }

        /// The connection is over: every leg on it fails.
        fn failLegs(server: *ServerType, slot: *Slot) void {
            const count = slot.legs_count;
            var passes: u32 = 0;
            while (slot.legs) |stream| : (passes += 1) {
                assert(passes < count);
                const leg = &stream.h2_origin;
                unlink(slot, stream);
                leg.phase = .failed;
                leg.slot = null;
                forcePending(server, stream);
            }
            assert(slot.legs_count == 0);
            failProbes(server, slot);
        }

        fn flush(server: *ServerType, slot: *Slot) void {
            assert(slot.state != .free);
            if (slot.sending != 0) return;
            if (!slot.socket_open or slot.state == .closing) return;
            if (slot.tls_active) return flushTls(server, slot);
            const staged = slot.session.outbound();
            if (staged.len == 0) return;
            assert(!slot.armed.send);
            slot.sending = @intCast(staged.len);
            slot.armed.send = true;
            server.io.send(slot.socket, staged, &slot.op_send, Slot, slot, onSend);
        }

        /// Over TLS: what the client owes first — a handshake flight, or a
        /// record already sealed — else a record of the session's staged
        /// octets, sealed now.
        fn flushTls(server: *ServerType, slot: *Slot) void {
            assert(slot.tls_active);
            assert(slot.sending == 0);
            const client = slot.tls.?;
            if (!client.owes() and slot.state == .open) {
                const staged = slot.session.outbound();
                if (staged.len >= 1) _ = client.seal(staged) catch return tlsFailed(server, slot);
            }
            if (!client.owes()) return;
            const wire = client.wire();
            assert(!slot.armed.send);
            slot.sending = @intCast(wire.len);
            slot.armed.send = true;
            server.io.send(slot.socket, wire, &slot.op_send, Slot, slot, onSend);
        }

        fn onSend(slot: *Slot, result: Io.SendError!u32) void {
            const server = serverOf(slot);
            assert(slot.armed.send);
            slot.armed.send = false;
            slot.sending = 0;
            if (slot.state == .closing) return continueClose(server, slot);
            const sent = result catch |err| {
                server.witnessKernelPressure(.send, err);
                return close(server, slot);
            };
            assert(sent >= 1);
            if (slot.tls_active) return onTlsSent(server, slot, sent);
            slot.session.outboundSent(sent);
            if (slot.session.state == .closed and slot.session.outbound().len == 0) return close(server, slot);
            drive(server, slot);
        }

        /// Wire octets out over TLS: a whole sealed record credits the
        /// session with the plaintext it carried. A handshake's flight out,
        /// records held behind it are read now.
        fn onTlsSent(server: *ServerType, slot: *Slot, sent: u32) void {
            const client = slot.tls.?;
            const plain = client.sent(sent);
            if (plain >= 1) slot.session.outboundSent(plain);
            if (slot.state == .handshaking) {
                client.process() catch return tlsFailed(server, slot);
                return handshakeProgress(server, slot);
            }
            assert(slot.state == .open);
            if (slot.session.state == .closed and slot.session.outbound().len == 0 and !client.owes()) {
                return close(server, slot);
            }
            drive(server, slot);
        }

        fn armRecv(server: *ServerType, slot: *Slot) void {
            assert(!slot.receiving);
            assert(slot.socket_open);
            assert(recvRoom(slot));
            const buffer = if (slot.tls_active) slot.tls.?.recvBuffer() else slot.session.recvBuffer();
            slot.receiving = true;
            slot.armed.recv = true;
            server.io.recv(slot.socket, buffer, &slot.op_io, Slot, slot, onRecv);
        }

        fn onRecv(slot: *Slot, result: Io.RecvError!u32) void {
            const server = serverOf(slot);
            assert(slot.armed.recv);
            slot.armed.recv = false;
            slot.receiving = false;
            if (slot.state == .closing) return continueClose(server, slot);
            const received = result catch |err| {
                if (err != error.EndOfStream) server.witnessKernelPressure(.recv, err);
                return close(server, slot);
            };
            assert(received >= 1);
            if (slot.tls_active) {
                slot.tls.?.received(received, nowSec(server)) catch return tlsFailed(server, slot);
                if (slot.state == .handshaking) return handshakeProgress(server, slot);
            }
            // Closed while this read was out: what arrived is past its last
            // word, and its GOAWAY's send closes it, or this does.
            if (slot.session.state == .closed) {
                if (slot.sending == 0) close(server, slot);
                return;
            }
            // Over TLS the octets went to the client; the drive feeds the
            // session what they decrypted to.
            if (!slot.tls_active) slot.session.received(received);
            drive(server, slot);
        }

        // -- deadlines -----------------------------------------------------

        fn armTimer(server: *ServerType, slot: *Slot, delay_ms: u32) void {
            assert(!slot.armed.timer);
            slot.deadline_ns = server.io.nowNs() + @as(u64, delay_ms) * std.time.ns_per_ms;
            slot.armed.timer = true;
            server.io.timerStart(&slot.op_timer, @as(u64, delay_ms) * std.time.ns_per_ms, Slot, slot, onTimer);
        }

        /// The dial's budget, or the idle window: a dial past its budget is
        /// cancelled, which fails the connection; an open one with nothing on
        /// it past its window is told GOAWAY and closed. Otherwise the timer
        /// waits for the next.
        fn onTimer(slot: *Slot, result: Io.TimerError!void) void {
            const server = serverOf(slot);
            assert(slot.armed.timer);
            slot.armed.timer = false;
            if (slot.state == .closing) return continueClose(server, slot);
            result catch unreachable; // Only a close cancels it, handled above.
            const now = server.io.nowNs();
            if (slot.state == .connecting or slot.state == .handshaking) {
                server.counters.increment("h2_origin_connect_failed");
                server.health.witnessPassiveFailure(slot.cluster_index, slot.endpoint_index);
                return close(server, slot);
            }
            assert(slot.state == .open);
            if (slot.legs_count == 0 and slot.probes_count == 0 and now >= slot.deadline_ns) {
                server.counters.increment("h2_origin_idle_closed");
                return goAway(server, slot);
            }
            if (slot.legs_count >= 1 or slot.probes_count >= 1) {
                slot.deadline_ns = now + @as(u64, server.idleTimeoutMs()) * std.time.ns_per_ms;
            }
            const delay_ns = slot.deadline_ns -| now;
            slot.armed.timer = true;
            server.io.timerStart(&slot.op_timer, @max(delay_ns, std.time.ns_per_ms), Slot, slot, onTimer);
        }

        /// A leg left: a connection with none is idle from now, and one the
        /// drain is waiting for is ended.
        fn settleIdle(server: *ServerType, slot: *Slot) void {
            assert(slot.state != .free);
            assert(slot.legs_count == 0 or slot.legs != null);
            if (slot.legs_count >= 1 or slot.probes_count >= 1) return;
            if (slot.state != .open) return;
            slot.deadline_ns = server.io.nowNs() + @as(u64, server.idleTimeoutMs()) * std.time.ns_per_ms;
            if (server.draining) goAway(server, slot);
        }

        /// End gracefully (RFC 9113 §6.8): GOAWAY, and the close once it is
        /// out — the session closes as soon as it is staged, having no
        /// stream left.
        fn goAway(server: *ServerType, slot: *Slot) void {
            assert(slot.state == .open);
            assert(slot.legs_count == 0);
            assert(slot.probes_count == 0);
            if (slot.session.state == .closed) return;
            slot.session.goAway();
            kick(server, slot);
        }

        /// Fail what it carries and wind the connection down: its socket
        /// shut so its ops deliver, its timer cancelled, and the slot back
        /// once nothing is armed.
        fn close(server: *ServerType, slot: *Slot) void {
            assert(slot.state != .free);
            if (slot.state == .closing) return;
            failLegs(server, slot);
            slot.state = .closing;
            if (slot.socket_open) server.io.shutdown(slot.socket, .both);
            if (slot.armed.connect and !slot.armed.cancel) {
                slot.armed.cancel = true;
                server.io.connectCancel(&slot.op_io, &slot.op_cancel, Slot, slot, onCancel);
            }
            continueClose(server, slot);
        }

        fn onCancel(slot: *Slot) void {
            const server = serverOf(slot);
            assert(slot.armed.cancel);
            assert(slot.state == .closing);
            slot.armed.cancel = false;
            continueClose(server, slot);
        }

        /// Release once nothing is armed. One cancel at a time rides
        /// `op_cancel`: the dial's first, then the timer's.
        fn continueClose(server: *ServerType, slot: *Slot) void {
            assert(slot.state == .closing);
            if (slot.armed.any()) {
                // A timer still armed with nothing cancelling it: cancel it
                // now that the connect's own cancel is done — once. If the
                // timer still has not delivered when that cancel has, the
                // close waits on the timer's own completion.
                if (slot.armed.timer and !slot.armed.cancel and !slot.timer_cancel_sent) {
                    slot.timer_cancel_sent = true;
                    slot.armed.cancel = true;
                    server.io.timerCancel(&slot.op_timer, &slot.op_cancel, Slot, slot, onCancel);
                }
                assert(slot.timer_cancel_sent or !slot.armed.timer or slot.armed.cancel);
                return;
            }
            if (slot.socket_open) server.io.closeNow(slot.socket);
            slot.socket_open = false;
            // The handshake's libcrypto state goes back to the fixed heap.
            if (slot.tls_active) slot.tls.?.finish();
            assert(slot.legs_count == 0);
            assert(slot.probes_count == 0);
            slot.reset();
            server.h2_origins.release(slot);
            // A drain may have been waiting on this connection alone.
            server.maybeStopAfterDrain();
        }

        /// The drain (§8): connections with nothing on them end now, and the
        /// rest as their last leg leaves.
        pub fn beginDrain(server: *ServerType) void {
            assert(server.draining);
            for (server.h2_origins.slots) |*slot| {
                if (!server.h2_origins.isAcquired(slot)) continue;
                if (slot.legs_count >= 1 or slot.probes_count >= 1) continue;
                switch (slot.state) {
                    .open => goAway(server, slot),
                    .connecting, .handshaking => close(server, slot),
                    .closing, .free => {},
                }
            }
        }
    };
}

test "probe leg: the longest endpoint literal std spells is the bound the authority holds" {
    const longest = try std.Io.net.IpAddress.parseLiteral("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535");
    var storage: [constants.health_check_grpc_authority_bytes_max + 1]u8 = undefined;
    const text = try std.fmt.bufPrint(&storage, "{f}", .{longest});
    try std.testing.expectEqual(@as(usize, constants.ip_literal_bytes_max), text.len);
    // A scope never reaches an endpoint: the literal parser refuses one.
    try std.testing.expectError(error.InvalidAddress, std.Io.net.IpAddress.parseLiteral("[fe80::1%1]:65535"));
}

test "probe leg: the request names the service, and only SERVING said whole passes" {
    var leg: ProbeLeg = .{};
    leg.compose("");
    try std.testing.expectEqualStrings("\x00\x00\x00\x00\x00", leg.body[0..leg.body_len]);
    leg.compose("a.B");
    try std.testing.expectEqualStrings("\x00\x00\x00\x00\x05\x0a\x03a.B", leg.body[0..leg.body_len]);

    const cases = [_]struct { payload: []const u8, serving: bool }{
        .{ .payload = "\x00\x00\x00\x00\x02\x08\x01", .serving = true },
        // NOT_SERVING, UNKNOWN, a compressed frame, a longer message.
        .{ .payload = "\x00\x00\x00\x00\x02\x08\x02", .serving = false },
        .{ .payload = "\x00\x00\x00\x00\x00", .serving = false },
        .{ .payload = "\x01\x00\x00\x00\x02\x08\x01", .serving = false },
        .{ .payload = "\x00\x00\x00\x00\x04\x08\x01\x10\x01", .serving = false },
        .{ .payload = "", .serving = false },
    };
    for (cases) |case| {
        leg.payload_len = @intCast(case.payload.len);
        @memcpy(leg.payload[0..case.payload.len], case.payload);
        try std.testing.expectEqual(case.serving, leg.serving());
    }
}
