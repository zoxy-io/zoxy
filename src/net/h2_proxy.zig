//! The HTTP/2-downstream data path (docs/DESIGN.md §7 Phase 5, slice 4):
//! `H2Conn` drives the sans-io engine (`http/h2.zig`) from ring completions
//! — staged downstream recv/send buffers, one in-flight op per direction —
//! and each request stream checks out a pooled `StreamLeg` that runs one
//! H1 transaction upstream: synthesized head (`http/h2_translate.zig`),
//! chunk-framed request body, response head translated back into HEADERS,
//! body re-framed into window-paced DATA frames.
//!
//! Flow control is the §1.4 backpressure model, per the phase plan:
//! - client → upstream: DATA payloads queue in the leg (bounded by the
//!   stream window we advertised); `release_data` — the WINDOW_UPDATE
//!   source — fires only as the upstream write completes. A slow origin
//!   closes exactly that stream's window.
//! - upstream → client: strict recv → send: the next origin read arms only
//!   after the previous payload fully entered the downstream staging, and
//!   `send_data` accepts only what the client's windows allow. An unwilling
//!   client stalls exactly its stream, one leg buffer deep.
//!
//! Deliberately at "Phase 1 maturity", like H1 was before Phase 2 (the
//! same follow-up path applies): no retry tiers, no per-try timeout —
//! an attempt failure before the first response byte answers the stream
//! with 502/504, after it resets the stream. Upstream TLS re-encryption
//! is still not wired for H2 legs (clusters demanding it answer 502).
//!
//! Downstream reaches here two ways: over TLS via
//! `ProxyServer.hand_off_to_h2` (a terminated connection that negotiated
//! `h2` in ALPN moves its channel + fd here), or plaintext h2c via
//! `H2Server` (the simulator's driver — it excludes OpenSSL, so h2c is
//! its only route in).

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const assert = std.debug.assert;

const io_mod = @import("../io/io.zig");
const IO = io_mod.IO;
const Completion = io_mod.Completion;
const Listener = @import("listener.zig").Listener;
const constants = @import("../constants.zig");
const config = @import("../config.zig");
const h1 = @import("../http/h1.zig");
const chunked_coding = @import("../http/chunked.zig");
const h2 = @import("../http/h2.zig");
const h2_frame = @import("../http/h2_frame.zig");
const hpack = @import("../http/hpack.zig");
const h2_translate = @import("../http/h2_translate.zig");
const terminator = @import("../tls/terminator.zig");
const WireRelay = @import("../tls/wire_relay.zig").WireRelay;
const maglev = @import("../proxy/maglev.zig");
const balancer = @import("../proxy/balancer.zig");
const resilience_mod = @import("../proxy/resilience.zig");
const Resilience = resilience_mod.Resilience;
const Router = @import("../proxy/router.zig").Router;
const UpstreamPool = @import("../proxy/upstream_pool.zig").UpstreamPool;
const Counters = @import("../obs/metrics.zig").Counters;
const access_log = @import("../obs/access_log.zig");
const AccessLog = access_log.AccessLog;
const Ip4Address = std.Io.net.Ip4Address;

pub const H2ConnPool = @import("pool.zig").Pool(H2Conn);
pub const LegPool = @import("pool.zig").Pool(StreamLeg);

/// Free downstream staging required before the engine may run: its own
/// worst case (a control ack + GOAWAY + every stream's WINDOW_UPDATE) plus
/// headroom for the event handler's small emissions (a fail head, an RST).
const drive_reserve: usize =
    h2.output_bytes_min + (constants.h2_streams_max + 1) * h2_frame.window_update_frame_bytes + 512;

/// Smallest DATA payload worth staging downstream; below this the leg waits
/// for the send buffer to drain rather than trickling tiny frames.
const send_data_reserve: usize = h2_frame.frame_header_bytes + 256;

const policy_default = config.ResiliencePolicy{};

/// A stream's synthesized terminal answer, deferred when staging is full.
const Answer = enum { none, bad_gateway, gateway_timeout, reset };

/// One H1 transaction upstream on behalf of one H2 stream. Pooled per
/// worker (`LegPool`); exhaustion answers the stream 503 — bounded
/// concurrency across every H2 connection, never growth.
pub const StreamLeg = struct {
    conn: *H2Conn,
    stream_id: u31,
    upstream_fd: posix.socket_t,

    // Upstream-bound bytes: the synthesized head at [0..head_len], then a
    // queue of raw request-body bytes at [queue_start..queue_filled] —
    // chunk framing is applied at send time, so the queue is bounded by
    // the stream window, not by an adversarial frame count.
    request_buf: [request_buf_bytes]u8,
    head_len: u32,
    head_sent: u32,
    queue_start: u32,
    queue_sent: u32,
    queue_filled: u32,
    /// Raw bytes drained upstream but not yet released as window credit.
    release_owed: u32,
    request_chunked: bool,
    /// Declared content-length still expected from the client (checked so a
    /// short or long body never reaches the origin misframed).
    content_remaining: u64,
    body_ended: bool,
    /// The terminal "0\r\n\r\n" chunk went out — the request is forwarded.
    request_forwarded: bool,
    chunk_stage: enum { idle, header, payload, trailer, terminal },
    chunk_scratch: [24]u8,
    chunk_scratch_len: u32,
    chunk_scratch_sent: u32,
    chunk_payload_len: u32,
    upstream_send_active: bool,

    // Origin-bound response: head accumulates at the front, then the relay
    // consumes the buffer as framed body.
    response_buf: [constants.relay_buf_bytes]u8,
    response_filled: u32,
    /// Framing bytes consumed (chunk decode / length countdown cursor).
    response_consumed: u32,
    /// The current payload span (aliases `response_buf`) and its send cursor.
    span_start: u32,
    span_end: u32,
    response_state: enum { head, relaying, done },
    response_framer: h1.BodyFramer,
    response_decoder: chunked_coding.ChunkedDecoder,
    upstream_recv_active: bool,
    /// The message ended and every payload byte was staged; END_STREAM is
    /// owed (possibly as a bare empty DATA frame).
    fin_owed: bool,
    fin_sent: bool,
    /// Bytes arrived past the response end — the connection is tainted.
    response_overflow: bool,
    upstream_reusable: bool,
    /// A response byte arrived (failures now reset instead of answering).
    response_started: bool,
    /// Waiting for downstream staging space (resumed on send drain).
    staging_blocked: bool,
    /// A synthesized answer is owed once staging has room.
    pending_answer: Answer,
    /// The upstream close is in flight on `close_completion`.
    close_pending: bool,
    /// A cancel of the pending connect is in flight (`connect_cancel_completion`);
    /// the upstream fd stays open until the connect resolves, then closes.
    connect_cancel_pending: bool,
    /// Detached from the connection: release to the pool once the last
    /// in-flight op drains. A leg with ring ops pending must NEVER be
    /// released — a reused completion corrupts the ring (the H1 seed-1693
    /// lesson, applied here by construction).
    orphaned: bool,

    // Routing and accounting (the H1 fixed points, minus the retry tiers).
    endpoint_address: Ip4Address,
    cluster_index: u32,
    endpoint_index: u32,
    policy: *const config.ResiliencePolicy,
    request_admitted: bool,
    attempt_open: bool,
    dial_pending: bool,
    upstream_accounted: bool,
    upstream_pooled: bool,
    /// Absolute deadline for the whole exchange (the conn's ticking timer
    /// enforces it); 0 = leg idle.
    deadline_ns: u64,
    method: h1.Method,
    /// Method/path copies for the access log (the head buffer outlives them,
    /// but bounded copies keep the log independent of buffer reuse).
    log_method: [16]u8,
    log_method_len: u8,
    log_target: [64]u8,
    log_target_len: u8,

    connect_completion: Completion,
    connect_cancel_completion: Completion,
    send_completion: Completion,
    recv_completion: Completion,
    close_completion: Completion,

    free_next: ?*StreamLeg,
    in_use: bool,

    /// Head plus a full stream window of raw body (flow control bounds the
    /// unreleased bytes to the window we advertised).
    pub const request_buf_bytes: usize =
        constants.h2_header_list_bytes_max + 512 + constants.h2_stream_window_bytes;

    fn reset(leg: *StreamLeg, conn: *H2Conn, stream_id: u31) void {
        assert(leg.in_use);
        assert(leg.free_next == null);
        leg.conn = conn;
        leg.stream_id = stream_id;
        leg.upstream_fd = -1;
        leg.head_len = 0;
        leg.head_sent = 0;
        leg.queue_start = 0;
        leg.queue_sent = 0;
        leg.queue_filled = 0;
        leg.release_owed = 0;
        leg.request_chunked = false;
        leg.content_remaining = 0;
        leg.body_ended = false;
        leg.request_forwarded = false;
        leg.chunk_stage = .idle;
        leg.chunk_scratch_len = 0;
        leg.chunk_scratch_sent = 0;
        leg.chunk_payload_len = 0;
        leg.upstream_send_active = false;
        leg.response_filled = 0;
        leg.response_consumed = 0;
        leg.span_start = 0;
        leg.span_end = 0;
        leg.response_state = .head;
        leg.response_framer = h1.BodyFramer.init(.none);
        leg.response_decoder = .{};
        leg.upstream_recv_active = false;
        leg.fin_owed = false;
        leg.fin_sent = false;
        leg.response_overflow = false;
        leg.upstream_reusable = false;
        leg.response_started = false;
        leg.staging_blocked = false;
        leg.pending_answer = .none;
        leg.close_pending = false;
        leg.connect_cancel_pending = false;
        leg.orphaned = false;
        leg.endpoint_address = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 };
        leg.cluster_index = 0;
        leg.endpoint_index = 0;
        leg.policy = &policy_default;
        leg.request_admitted = false;
        leg.attempt_open = false;
        leg.dial_pending = false;
        leg.upstream_accounted = false;
        leg.upstream_pooled = false;
        leg.deadline_ns = 0;
        leg.log_method_len = 0;
        leg.log_target_len = 0;
    }

    fn queue_unsent(leg: *const StreamLeg) u32 {
        assert(leg.queue_sent <= leg.queue_filled);
        return leg.queue_filled - leg.queue_sent;
    }
};

pub const H2Conn = struct {
    io: *IO,
    pool: *H2ConnPool,
    legs: *LegPool,
    router: *const Router,
    resilience: *Resilience,
    upstream_pool: *UpstreamPool,
    metrics: *Counters,
    access: *AccessLog,
    random: std.Random,

    downstream_fd: posix.socket_t,
    closing: bool,
    /// Tear down once the staged output (a GOAWAY) has drained.
    close_after_flush: bool,
    refs: u32,
    engine: h2.Connection,

    /// Streams with live legs, densely packed (order irrelevant).
    active_legs: [constants.h2_streams_max]?*StreamLeg,
    active_count: u32,

    recv_buf: [constants.h2_recv_buf_bytes]u8,
    recv_filled: usize,
    recv_in_flight: bool,

    send_buf: [constants.h2_send_buf_bytes]u8,
    send_sent: usize,
    send_filled: usize,
    send_in_flight: bool,

    /// Downstream TLS (h2 over TLS): the terminated channel, adopted
    /// post-handshake from the H1 `ProxyConn` that ran the handshake and
    /// read `h2` off ALPN. When non-null every downstream op is a ciphertext
    /// op on the wire buffers below, feeding/draining the channel between
    /// them and `recv_buf`/`send_buf` — the same BIO-pair relay ProxyConn
    /// runs, adapted to H2's symmetric buffered model. Null = h2c (plaintext).
    tls: ?terminator.Channel,
    /// The ciphertext <-> ring staging: the same BIO-pair relay ProxyConn
    /// runs. When `tls` above is null (h2c plaintext), `wire` stays idle.
    wire: WireRelay,
    /// A TLS close_notify or wire EOF arrived — teardown after the drain.
    tls_eof: bool,
    tls_wire_recv_completion: Completion,
    tls_wire_send_completion: Completion,

    idle_timeout_ns: u63,
    request_timeout_ns: u63,
    /// Drain-to-forced-teardown bound; clamps the deadline at `begin_drain`
    /// (the simulator shrinks it to force the deadline path within a run).
    drain_timeout_ns: u63,
    /// Connection-level deadline: idle cutoff, refreshed on client bytes.
    deadline_ns: u64,
    timeout_armed: bool,
    /// Draining, but the GOAWAY could not be staged yet (send buffer full);
    /// retried when the staging drains.
    drain_pending: bool,

    recv_completion: Completion,
    send_completion: Completion,
    close_completion: Completion,
    timeout_completion: Completion,
    timeout_cancel_completion: Completion,

    free_next: ?*H2Conn,
    in_use: bool,

    pub fn start(
        conn: *H2Conn,
        io: *IO,
        pool: *H2ConnPool,
        legs: *LegPool,
        router: *const Router,
        resilience: *Resilience,
        upstream_pool: *UpstreamPool,
        metrics: *Counters,
        access: *AccessLog,
        random: std.Random,
        downstream_fd: posix.socket_t,
        request_timeout_ns: u63,
        idle_timeout_ns: u63,
        drain_timeout_ns: u63,
        /// The terminated TLS channel when this is an adopted h2-over-TLS
        /// connection (the H1 handshaker read `h2` off ALPN); null = h2c.
        tls: ?terminator.Channel,
        /// Ciphertext the handshaker had already read past the handshake
        /// (a coalesced client preface) — seeded into the wire buffer so the
        /// first `tls_service` decrypts it. Empty for h2c.
        staged_ciphertext: []const u8,
    ) void {
        assert(downstream_fd >= 0);
        assert(staged_ciphertext.len <= constants.tls_bio_pair_bytes);
        assert(tls != null or staged_ciphertext.len == 0);
        conn.io = io;
        conn.pool = pool;
        conn.legs = legs;
        conn.router = router;
        conn.resilience = resilience;
        conn.upstream_pool = upstream_pool;
        conn.metrics = metrics;
        conn.access = access;
        conn.random = random;
        conn.downstream_fd = downstream_fd;
        conn.closing = false;
        conn.close_after_flush = false;
        conn.refs = 0;
        conn.engine = .{};
        conn.active_legs = @splat(null);
        conn.active_count = 0;
        conn.recv_filled = 0;
        conn.recv_in_flight = false;
        conn.send_sent = 0;
        conn.send_filled = 0;
        conn.send_in_flight = false;
        conn.tls = tls;
        conn.wire.reset();
        if (staged_ciphertext.len > 0) conn.wire.seed_staged(staged_ciphertext);
        conn.tls_eof = false;
        conn.request_timeout_ns = request_timeout_ns;
        conn.idle_timeout_ns = idle_timeout_ns;
        conn.drain_timeout_ns = drain_timeout_ns;
        conn.timeout_armed = false;
        conn.drain_pending = false;
        conn.metrics.active.add(1);
        conn.set_deadline(idle_timeout_ns);
        conn.arm_timeout();
        conn.process(); // stages our SETTINGS + window boost (flush sends them)
        if (conn.tls != null) conn.tls_service() else conn.arm_recv();
    }

    // ---- downstream receive -> engine --------------------------------------

    fn arm_recv(conn: *H2Conn) void {
        assert(!conn.closing);
        assert(!conn.recv_in_flight);
        assert(conn.recv_filled < conn.recv_buf.len); // a full frame always fits
        conn.recv_in_flight = true;
        conn.retain();
        conn.io.recv(
            *H2Conn,
            conn,
            on_recv,
            &conn.recv_completion,
            conn.downstream_fd,
            conn.recv_buf[conn.recv_filled..],
        );
    }

    fn on_recv(conn: *H2Conn, _: *Completion, result: io_mod.RecvError!usize) void {
        defer conn.release_ref();
        conn.recv_in_flight = false;
        if (conn.closing) return;
        const n = result catch return conn.teardown();
        if (n == 0) return conn.teardown(); // client hangup ends every stream
        conn.recv_filled += n;
        assert(conn.recv_filled <= conn.recv_buf.len);
        // Client activity resets the idle clock — except under drain, whose
        // clamped deadline must never move out again.
        if (!conn.engine.draining() and !conn.drain_pending) {
            conn.set_deadline(conn.idle_timeout_ns);
        }
        conn.process();
        if (conn.closing or conn.close_after_flush) return;
        if (!conn.recv_in_flight and conn.recv_filled < conn.recv_buf.len) conn.arm_recv();
    }

    /// Run the engine over the staged input until it stops making progress
    /// (input exhausted, a partial frame, or staging backpressure).
    fn process(conn: *H2Conn) void {
        assert(!conn.closing);
        var consumed: usize = 0;
        // Bounded: every productive iteration consumes input, and the event
        // budget per frame is one.
        var budget: u32 = @intCast(conn.recv_filled + 16);
        while (budget > 0) : (budget -= 1) {
            if (conn.close_after_flush) break;
            if (conn.send_free() < drive_reserve) break; // resumed on send drain
            const result = conn.engine.drive(
                conn.recv_buf[consumed..conn.recv_filled],
                conn.send_buf[conn.send_filled..],
            );
            conn.send_filled += result.produced;
            consumed += result.consumed;
            if (result.event) |event| conn.handle_event(event);
            if (result.consumed == 0 and result.produced == 0 and result.event == null) break;
        }
        assert(consumed <= conn.recv_filled);
        if (consumed > 0) {
            std.mem.copyForwards(
                u8,
                conn.recv_buf[0 .. conn.recv_filled - consumed],
                conn.recv_buf[consumed..conn.recv_filled],
            );
            conn.recv_filled -= consumed;
        }
        conn.flush_send();
    }

    fn handle_event(conn: *H2Conn, event: h2.Event) void {
        switch (event) {
            .request => |request| conn.begin_stream(
                request.stream_id,
                request.headers,
                request.end_stream,
            ),
            .trailers => |trailers| {
                // Trailer fields are dropped (the H1 leg forwards none);
                // what matters is that the body ended.
                if (conn.leg_for(trailers.stream_id)) |leg| {
                    leg.body_ended = true;
                    conn.pump_upstream_send(leg);
                }
            },
            .data => |data| conn.on_request_data(data),
            .reset => |reset| {
                if (conn.leg_for(reset.stream_id)) |leg| conn.leg_abort(leg);
                conn.maybe_finish_drain();
            },
            .window_open => |window| conn.pump_blocked_streams(window.stream_id),
            .goaway => {}, // informational: the client opens nothing new
            .fatal => {
                // The engine staged its GOAWAY; flush, then tear down.
                conn.metrics.client_errors.add(1);
                conn.close_after_flush = true;
            },
        }
    }

    fn on_request_data(conn: *H2Conn, data: anytype) void {
        const leg = conn.leg_for(data.stream_id) orelse {
            // The stream died on our side (leg failure) but the engine slot
            // lives until the reset drains; the bytes are void — release the
            // window immediately so accounting stays whole.
            if (data.flow_bytes > 0) conn.engine.release_data(data.stream_id, data.flow_bytes);
            return;
        };
        assert(!leg.body_ended);
        // Padding is never forwarded: its window credit returns at once.
        const padding: u32 = data.flow_bytes - @as(u32, @intCast(data.bytes.len));
        if (padding > 0) conn.engine.release_data(leg.stream_id, padding);
        if (data.bytes.len > 0) {
            // Room is guaranteed by flow control: unreleased bytes never
            // exceed the stream window the queue is sized for.
            assert(leg.queue_filled + data.bytes.len <= leg.request_buf.len);
            @memcpy(leg.request_buf[leg.queue_filled..][0..data.bytes.len], data.bytes);
            leg.queue_filled += @intCast(data.bytes.len);
            if (leg.content_remaining > 0) {
                if (data.bytes.len > leg.content_remaining) return conn.leg_answer(leg, .reset);
                leg.content_remaining -= data.bytes.len;
            }
        }
        if (data.end_stream) {
            if (leg.content_remaining != 0) return conn.leg_answer(leg, .reset); // short body
            leg.body_ended = true;
        }
        conn.pump_upstream_send(leg);
    }

    // ---- stream start: route, admit, dial -----------------------------------

    fn begin_stream(
        conn: *H2Conn,
        stream_id: u31,
        headers: []const hpack.Header,
        end_stream: bool,
    ) void {
        conn.metrics.requests.add(1);
        const leg = conn.legs.acquire() orelse {
            conn.metrics.rejected.add(1);
            return conn.answer_without_leg(stream_id, response_block_503);
        };
        leg.reset(conn, stream_id);
        conn.leg_attach(leg);
        leg.deadline_ns = conn.io.now_ns() + conn.request_timeout_ns;

        const head = h2_translate.request_head(
            headers,
            end_stream,
            leg.request_buf[0..h2_translate_head_capacity],
        ) catch {
            // Malformed per RFC 9113 §8.1.1: a stream error, not a page.
            conn.leg_detach(leg);
            conn.stage_reset(stream_id, .protocol_error);
            return;
        };
        leg.head_len = @intCast(head.head_len);
        leg.queue_start = leg.head_len;
        leg.queue_sent = leg.head_len;
        leg.queue_filled = leg.head_len;
        leg.method = head.method;
        leg.request_chunked = head.chunked;
        leg.content_remaining = head.content_length orelse 0;
        leg.body_ended = end_stream;
        copy_bounded(&leg.log_method, &leg.log_method_len, field_value(headers, ":method"));
        copy_bounded(&leg.log_target, &leg.log_target_len, field_value(headers, ":path"));

        // Translation validated the pseudo-headers: :path is present.
        const target = field_value(headers, ":path").?;
        const cluster = conn.router.route(field_value(headers, ":authority"), target) orelse
            return conn.leg_answer_early(leg, response_block_404);
        leg.cluster_index = @intCast(cluster.index);
        leg.policy = &cluster.policy;
        if (!conn.resilience.admit_request(leg.cluster_index, leg.policy)) {
            conn.metrics.breaker_requests_rejected.add(1);
            return conn.leg_answer_early(leg, response_block_503);
        }
        conn.resilience.request_start(leg.cluster_index);
        leg.request_admitted = true;
        const endpoint_index = conn.pick_endpoint(leg, cluster, headers) orelse
            return conn.leg_answer_early(leg, response_block_503);
        leg.endpoint_address = cluster.endpoints[endpoint_index].address;
        // Upstream TLS re-encryption is not wired for H2 legs yet (module doc).
        if (cluster.tls != null) return conn.leg_answer_early(leg, response_block_502);
        leg.attempt_open = true;
        leg.endpoint_index = endpoint_index;
        conn.resilience.attempt_start(leg.cluster_index, endpoint_index);
        conn.leg_begin_attempt(leg);
    }

    fn pick_endpoint(
        conn: *H2Conn,
        leg: *StreamLeg,
        cluster: *const config.Cluster,
        headers: []const hpack.Header,
    ) ?u32 {
        const state = conn.resilience.cluster_state(leg.cluster_index);
        const now_ns = conn.io.now_ns();
        if (cluster.maglev_table.len > 0) {
            const key: ?[]const u8 = switch (cluster.hash_on) {
                .target => field_value(headers, ":path"),
                .header => field_value(headers, cluster.hash_header),
            };
            if (key != null and key.?.len > 0) {
                const hash = maglev.hash_key(key.?);
                return balancer.pick_hashed(cluster, state, hash, now_ns, null);
            }
        }
        return balancer.pick_least_request(cluster, state, conn.random, now_ns, null);
    }

    fn leg_begin_attempt(conn: *H2Conn, leg: *StreamLeg) void {
        assert(leg.attempt_open);
        assert(leg.upstream_fd < 0);
        if (conn.upstream_pool.checkout(leg.endpoint_address)) |parked| {
            // H2 legs never park TLS channels (no re-encryption yet), but an
            // H1 conn sharing the worker pool may have; wrong kind → dial.
            if (parked.channel) |channel| {
                channel.deinit();
                conn.io.close_now(parked.fd);
                return conn.leg_connect(leg);
            }
            leg.upstream_fd = parked.fd;
            leg.upstream_pooled = true;
            leg.upstream_accounted = true;
            conn.resilience.connection_open(leg.cluster_index);
            conn.metrics.upstream_reused.add(1);
            conn.pump_upstream_send(leg);
            conn.leg_arm_response_recv(leg);
            return;
        }
        conn.leg_connect(leg);
    }

    fn leg_connect(conn: *H2Conn, leg: *StreamLeg) void {
        assert(leg.upstream_fd < 0);
        leg.upstream_pooled = false;
        if (!conn.resilience.admit_dial(leg.cluster_index, leg.policy)) {
            conn.metrics.breaker_dials_rejected.add(1);
            // Load shedding, not an endpoint-health signal (the H1 rule):
            // settle the attempt as aborted via the early-answer path.
            return conn.leg_answer_early(leg, response_block_503);
        }
        leg.upstream_fd = conn.io.open_tcp_socket() orelse
            return conn.leg_answer(leg, .bad_gateway);
        leg.upstream_accounted = true;
        conn.resilience.connection_open(leg.cluster_index);
        leg.dial_pending = true;
        conn.resilience.dial_start(leg.cluster_index);
        conn.retain();
        conn.io.connect(
            *StreamLeg,
            leg,
            on_leg_connect,
            &leg.connect_completion,
            leg.upstream_fd,
            sockaddr_in(leg.endpoint_address),
        );
    }

    fn on_leg_connect(leg: *StreamLeg, _: *Completion, result: io_mod.ConnectError!void) void {
        const conn = leg.conn;
        defer conn.release_ref();
        assert(leg.dial_pending);
        leg.dial_pending = false;
        conn.resilience.dial_finish(leg.cluster_index);
        if (leg.orphaned) {
            // Disposed mid-dial: the connect has now resolved (or was
            // cancelled), so run the fd close that leg_dispose_upstream
            // deferred, then release once everything is quiescent.
            conn.leg_dispose_upstream(leg); // dial_pending is false now: closes the fd
            return conn.leg_maybe_release(leg);
        }
        if (conn.closing) return;
        // The client connection went fatal (engine `.failed`, GOAWAY staged,
        // teardown pending): the engine will reject any stream op, so a leg
        // completion must not drive it — settle and dispose quietly instead.
        // Found by the simulator, seed 8.
        if (conn.close_after_flush) return conn.leg_abort(leg);
        result catch return conn.leg_answer(leg, .bad_gateway);
        conn.pump_upstream_send(leg);
        conn.leg_arm_response_recv(leg);
    }

    // ---- request direction: prime + chunk-framed body -----------------------

    /// One in-flight upstream send: head remainder first, then body from the
    /// queue (chunk-framed at send time when the request has no declared
    /// length), then the terminal chunk. A bounded stage loop, no recursion.
    fn pump_upstream_send(conn: *H2Conn, leg: *StreamLeg) void {
        if (conn.closing or leg.orphaned or leg.upstream_send_active) return;
        if (leg.upstream_fd < 0 or leg.dial_pending) return;
        if (leg.head_sent < leg.head_len) {
            return conn.leg_send(leg, leg.request_buf[leg.head_sent..leg.head_len]);
        }
        var stages: u8 = 4; // idle -> header -> payload -> trailer transitions
        while (stages > 0) : (stages -= 1) {
            switch (leg.chunk_stage) {
                .header, .trailer, .terminal => {
                    if (leg.chunk_scratch_sent < leg.chunk_scratch_len) {
                        return conn.leg_send(
                            leg,
                            leg.chunk_scratch[leg.chunk_scratch_sent..leg.chunk_scratch_len],
                        );
                    }
                    if (leg.chunk_stage == .terminal) {
                        leg.chunk_stage = .idle;
                        leg.request_forwarded = true;
                        return conn.leg_maybe_finish(leg);
                    }
                    leg.chunk_stage = if (leg.chunk_stage == .header) .payload else .idle;
                },
                .payload => {
                    assert(leg.chunk_payload_len > 0);
                    const chunk = leg.request_buf[leg.queue_sent..][0..leg.chunk_payload_len];
                    return conn.leg_send(leg, chunk);
                },
                .idle => {
                    const unsent = leg.queue_unsent();
                    if (unsent > 0) {
                        if (!leg.request_chunked) {
                            return conn.leg_send(
                                leg,
                                leg.request_buf[leg.queue_sent..leg.queue_filled],
                            );
                        }
                        leg.chunk_payload_len = unsent;
                        const header = std.fmt.bufPrint(
                            &leg.chunk_scratch,
                            "{x}\r\n",
                            .{unsent},
                        ) catch unreachable; // 24 bytes hold any u32 in hex + CRLF
                        leg.chunk_scratch_len = @intCast(header.len);
                        leg.chunk_scratch_sent = 0;
                        leg.chunk_stage = .header;
                        continue;
                    }
                    if (leg.body_ended and !leg.request_forwarded) {
                        if (leg.request_chunked) {
                            const terminal = "0\r\n\r\n";
                            @memcpy(leg.chunk_scratch[0..terminal.len], terminal);
                            leg.chunk_scratch_len = terminal.len;
                            leg.chunk_scratch_sent = 0;
                            leg.chunk_stage = .terminal;
                            continue;
                        }
                        leg.request_forwarded = true;
                        return conn.leg_maybe_finish(leg);
                    }
                    return; // nothing to send until more DATA arrives
                },
            }
        }
        unreachable; // every path above sends, finishes, or returns in 4 stages
    }

    fn leg_send(conn: *H2Conn, leg: *StreamLeg, bytes: []const u8) void {
        assert(bytes.len > 0);
        assert(!leg.upstream_send_active);
        leg.upstream_send_active = true;
        conn.retain();
        conn.io.send(
            *StreamLeg,
            leg,
            on_leg_sent,
            &leg.send_completion,
            leg.upstream_fd,
            bytes,
        );
    }

    fn on_leg_sent(leg: *StreamLeg, _: *Completion, result: io_mod.SendError!usize) void {
        const conn = leg.conn;
        defer conn.release_ref();
        leg.upstream_send_active = false;
        if (leg.orphaned) return conn.leg_maybe_release(leg);
        if (conn.closing) return;
        if (conn.close_after_flush) return conn.leg_abort(leg); // engine .failed (seed 8)
        const m = result catch return conn.leg_upstream_failed(leg);
        conn.metrics.bytes_to_upstream.add(m);
        if (leg.head_sent < leg.head_len) {
            leg.head_sent += @intCast(m);
            assert(leg.head_sent <= leg.head_len);
        } else if (leg.chunk_stage == .header or leg.chunk_stage == .trailer or
            leg.chunk_stage == .terminal)
        {
            leg.chunk_scratch_sent += @intCast(m);
            assert(leg.chunk_scratch_sent <= leg.chunk_scratch_len);
        } else {
            // Raw or chunk-payload body bytes drained: release their window.
            leg.queue_sent += @intCast(m);
            assert(leg.queue_sent <= leg.queue_filled);
            conn.leg_release_flow(leg, @intCast(m));
            if (leg.chunk_stage == .payload) {
                leg.chunk_payload_len -= @intCast(m);
                if (leg.chunk_payload_len == 0) {
                    const crlf = "\r\n";
                    @memcpy(leg.chunk_scratch[0..crlf.len], crlf);
                    leg.chunk_scratch_len = crlf.len;
                    leg.chunk_scratch_sent = 0;
                    leg.chunk_stage = .trailer;
                }
            }
            if (leg.queue_sent == leg.queue_filled) {
                // Fully drained: rewind the queue to the head boundary.
                leg.queue_sent = leg.queue_start;
                leg.queue_filled = leg.queue_start;
            }
        }
        conn.pump_upstream_send(leg);
    }

    /// WINDOW_UPDATE credit follows the upstream write — the §1.4 rule.
    fn leg_release_flow(conn: *H2Conn, leg: *StreamLeg, released: u32) void {
        assert(released > 0);
        conn.engine.release_data(leg.stream_id, released);
        conn.pump_engine(); // flush any WINDOW_UPDATE the release matured
    }

    /// Run the engine with no input so staged credit (window updates) and
    /// other pending control output reach the wire.
    fn pump_engine(conn: *H2Conn) void {
        if (conn.closing or conn.close_after_flush) return;
        if (conn.send_free() < drive_reserve) return; // send drain re-runs this
        const result = conn.engine.drive("", conn.send_buf[conn.send_filled..]);
        assert(result.consumed == 0);
        assert(result.event == null);
        conn.send_filled += result.produced;
        conn.flush_send();
    }

    // ---- response direction: head, translate, window-paced DATA -------------

    fn leg_arm_response_recv(conn: *H2Conn, leg: *StreamLeg) void {
        assert(!leg.upstream_recv_active);
        assert(leg.upstream_fd >= 0);
        if (leg.response_state == .head) {
            if (leg.response_filled == leg.response_buf.len) {
                return conn.leg_upstream_failed(leg); // head larger than the buffer
            }
        } else {
            // Relay reads start only once the buffer fully drained downstream.
            assert(leg.response_filled == 0);
        }
        leg.upstream_recv_active = true;
        conn.retain();
        conn.io.recv(
            *StreamLeg,
            leg,
            on_leg_recv,
            &leg.recv_completion,
            leg.upstream_fd,
            leg.response_buf[leg.response_filled..],
        );
    }

    fn on_leg_recv(leg: *StreamLeg, _: *Completion, result: io_mod.RecvError!usize) void {
        const conn = leg.conn;
        defer conn.release_ref();
        leg.upstream_recv_active = false;
        if (leg.orphaned) return conn.leg_maybe_release(leg);
        if (conn.closing) return;
        if (conn.close_after_flush) return conn.leg_abort(leg); // engine .failed (seed 8)
        const n = result catch return conn.leg_upstream_failed(leg);
        if (n == 0) return conn.leg_upstream_eof(leg);
        leg.response_started = true;
        leg.response_filled += @intCast(n);
        assert(leg.response_filled <= leg.response_buf.len);
        switch (leg.response_state) {
            .head => conn.leg_process_response_head(leg),
            .relaying => conn.leg_forward_body(leg),
            .done => unreachable, // nothing is armed after the fin
        }
    }

    fn leg_process_response_head(conn: *H2Conn, leg: *StreamLeg) void {
        var headers: [constants.headers_max]h1.Header = undefined;
        const parsed = h1.parse_response(
            leg.response_buf[0..leg.response_filled],
            &headers,
        ) catch return conn.leg_answer(leg, .bad_gateway);
        const response = switch (parsed) {
            .incomplete => return conn.leg_arm_response_recv(leg),
            .complete => |response| response,
        };
        if (response.status < 200) {
            // Interim response: swallow it and wait for the real one.
            const rest = leg.response_filled - response.head_len;
            std.mem.copyForwards(
                u8,
                leg.response_buf[0..rest],
                leg.response_buf[response.head_len..leg.response_filled],
            );
            leg.response_filled = @intCast(rest);
            leg.response_state = .head;
            if (rest == 0) return conn.leg_arm_response_recv(leg);
            return conn.leg_process_response_head(leg);
        }
        const framing = h1.response_framing(leg.method, &response) catch
            return conn.leg_answer(leg, .bad_gateway);
        const connection_value = response.header("connection") orelse "";
        leg.upstream_reusable = framing != .until_close and
            response.status >= 200 and
            response.version_minor == 1 and
            !token_list_names(connection_value, "close");
        leg.response_framer = h1.BodyFramer.init(framing);
        leg.response_decoder = .{};

        var block: [constants.h2_header_list_bytes_max + 128]u8 = undefined;
        const block_len = h2_translate.response_block(&response, &block) catch
            return conn.leg_answer(leg, .bad_gateway);
        const head_only = leg.response_framer.is_complete() and
            response.head_len == leg.response_filled;
        if (!conn.stage_headers(leg.stream_id, block[0..block_len], head_only)) {
            // No staging room for the head right now — a rare, transient
            // condition. Treat as an attempt failure rather than buffering
            // a parsed-head continuation state.
            return conn.leg_answer(leg, .bad_gateway);
        }
        leg.response_state = .relaying;
        if (head_only) {
            leg.fin_owed = true;
            leg.fin_sent = true;
            leg.response_filled = 0;
            return conn.leg_maybe_finish(leg);
        }
        // The body prefix behind the head relays from the same buffer.
        leg.response_consumed = @intCast(response.head_len);
        leg.span_start = leg.response_consumed;
        leg.span_end = leg.span_start;
        conn.leg_forward_body(leg);
    }

    /// Stage as much framed response body as the windows and staging allow;
    /// re-armed by window_open, send drain, and upstream reads.
    fn leg_forward_body(conn: *H2Conn, leg: *StreamLeg) void {
        assert(leg.response_state == .relaying);
        leg.staging_blocked = false;
        // Bounded: each iteration either stages payload, consumes framing
        // bytes, or returns.
        var budget: u32 = @intCast(leg.response_buf.len + 16);
        while (budget > 0) : (budget -= 1) {
            if (conn.closing) return;
            if (leg.span_start < leg.span_end) {
                if (conn.send_free() < send_data_reserve) {
                    leg.staging_blocked = true;
                    return; // send drain resumes this leg
                }
                const span = leg.response_buf[leg.span_start..leg.span_end];
                // END_STREAM always travels as a final bare DATA frame in
                // `leg_response_end` — one 9-byte frame buys never having to
                // prove "this span is the message's last payload byte" here.
                const sent = conn.engine.send_data(
                    leg.stream_id,
                    span,
                    false,
                    conn.send_buf[conn.send_filled..],
                );
                conn.send_filled += sent.produced;
                if (sent.accepted == 0) return; // window-blocked: window_open resumes
                conn.metrics.bytes_to_client.add(sent.accepted);
                leg.span_start += sent.accepted;
                conn.flush_send();
                continue;
            }
            // The span drained; find the next one in the raw bytes.
            const raw = leg.response_buf[leg.response_consumed..leg.response_filled];
            if (raw.len == 0) {
                if (leg.response_framer.is_complete()) return conn.leg_response_end(leg);
                leg.response_filled = 0;
                leg.response_consumed = 0;
                leg.span_start = 0;
                leg.span_end = 0;
                if (!leg.upstream_recv_active) conn.leg_arm_response_recv(leg);
                return;
            }
            if (leg.response_framer.is_complete()) {
                // Bytes past the message end: never forwarded, taints reuse.
                leg.response_overflow = true;
                leg.response_consumed = leg.response_filled;
                continue;
            }
            if (!conn.leg_next_span(leg, raw)) return;
        }
        unreachable; // the budget covers every byte of the buffer plus slack
    }

    /// Locate the next payload span in `raw` (framing-specific), advancing
    /// span_start/span_end/response_consumed. Returns false when mid-relay
    /// corruption has already reset the stream and the caller must stop.
    fn leg_next_span(conn: *H2Conn, leg: *StreamLeg, raw: []const u8) bool {
        switch (leg.response_framer.framing) {
            .chunked => {
                const extracted = leg.response_decoder.extract(raw) catch {
                    conn.leg_answer(leg, .reset); // mid-relay corruption
                    return false;
                };
                if (leg.response_decoder.done()) {
                    // Mirror the shared framer state (BodyFramer owns a
                    // decoder we bypassed for payload extraction).
                    leg.response_framer.decoder = leg.response_decoder;
                }
                leg.span_start = leg.response_consumed +
                    @as(u32, @intCast(@intFromPtr(extracted.payload.ptr) -
                        @intFromPtr(raw.ptr)));
                leg.span_end = leg.span_start + @as(u32, @intCast(extracted.payload.len));
                leg.response_consumed += @intCast(extracted.consumed);
            },
            .content_length, .until_close, .none => {
                const n = leg.response_framer.consume(raw) catch {
                    conn.leg_answer(leg, .reset);
                    return false;
                };
                leg.span_start = leg.response_consumed;
                leg.span_end = leg.response_consumed + @as(u32, @intCast(n));
                leg.response_consumed += @intCast(n);
                if (n == 0) {
                    leg.response_overflow = true;
                    leg.response_consumed = leg.response_filled;
                }
            },
        }
        return true;
    }

    fn leg_response_end(conn: *H2Conn, leg: *StreamLeg) void {
        assert(leg.response_framer.is_complete());
        if (!leg.fin_sent) {
            if (conn.send_free() < send_data_reserve) {
                leg.staging_blocked = true;
                return;
            }
            const sent = conn.engine.send_data(
                leg.stream_id,
                "",
                true,
                conn.send_buf[conn.send_filled..],
            );
            conn.send_filled += sent.produced;
            assert(sent.complete); // a bare END_STREAM never blocks
            leg.fin_owed = true;
            leg.fin_sent = true;
            conn.flush_send();
        }
        leg.response_state = .done;
        conn.leg_maybe_finish(leg);
    }

    /// A close-delimited response ends at EOF; everything else dying early
    /// is an upstream failure.
    fn leg_upstream_eof(conn: *H2Conn, leg: *StreamLeg) void {
        if (leg.response_state == .relaying and
            leg.response_framer.framing == .until_close and
            leg.span_start == leg.span_end and
            leg.response_consumed == leg.response_filled)
        {
            leg.response_framer.framing = .none; // EOF terminated the message
            leg.upstream_reusable = false;
            return conn.leg_response_end(leg);
        }
        conn.leg_upstream_failed(leg);
    }

    // ---- stream completion and failure ---------------------------------------

    /// The exchange is over when the response went out in full and the
    /// request side is quiet; park or drop the upstream, log, free the slot.
    fn leg_maybe_finish(conn: *H2Conn, leg: *StreamLeg) void {
        if (!(leg.fin_sent and leg.response_state == .done)) return;
        if (leg.upstream_send_active or leg.upstream_recv_active) return;
        conn.settle_leg(leg, .success);
        if (leg.upstream_fd >= 0) {
            const poolable = leg.upstream_reusable and
                !leg.response_overflow and
                leg.request_forwarded;
            if (poolable) {
                conn.upstream_pool.checkin(conn.io, leg.endpoint_address, leg.upstream_fd, null);
                leg.upstream_fd = -1;
                conn.leg_account_drop(leg);
            } else {
                conn.leg_dispose_upstream(leg);
            }
        }
        conn.access.record(.{
            .method = leg.log_method[0..leg.log_method_len],
            .target = leg.log_target[0..leg.log_target_len],
            .outcome = .proxied,
            .bytes_to_client = 0,
        });
        conn.engine.close_stream(leg.stream_id);
        conn.leg_detach(leg);
        conn.maybe_finish_drain();
    }

    /// An upstream fault: answer 502/504 if no response byte was forwarded,
    /// else reset the stream (the head already went downstream).
    fn leg_upstream_failed(conn: *H2Conn, leg: *StreamLeg) void {
        if (leg.response_state == .head and !leg.response_started) {
            return conn.leg_answer(leg, .bad_gateway);
        }
        conn.leg_answer(leg, .reset);
    }

    /// Synthesize the stream's terminal answer, deferring when the staging
    /// buffer has no room right now (send drain retries via pending_answer).
    fn leg_answer(conn: *H2Conn, leg: *StreamLeg, answer: Answer) void {
        assert(answer != .none);
        conn.settle_leg(leg, if (answer == .reset) .aborted else .failure);
        conn.leg_dispose_upstream(leg);
        leg.pending_answer = answer;
        conn.leg_try_answer(leg);
    }

    fn leg_try_answer(conn: *H2Conn, leg: *StreamLeg) void {
        assert(leg.pending_answer != .none);
        if (conn.send_free() < 128) {
            leg.staging_blocked = true;
            return; // send drain retries
        }
        const stream_id = leg.stream_id;
        const answer = leg.pending_answer;
        conn.leg_detach(leg); // in-flight leg ops drain into the orphaned leg
        switch (answer) {
            .none => unreachable,
            .reset => conn.stage_reset(stream_id, .internal_error),
            .bad_gateway => conn.answer_without_leg(stream_id, response_block_502),
            .gateway_timeout => conn.answer_without_leg(stream_id, response_block_504),
        }
        conn.maybe_finish_drain();
    }

    /// A synthesized HEADERS answer on a stream with no (or no longer a)
    /// leg: 404/502/503/504 as a complete head-only response.
    fn answer_without_leg(conn: *H2Conn, stream_id: u31, block: []const u8) void {
        assert(conn.send_free() >= 128); // drive_reserve covers event-time answers
        conn.metrics.upstream_errors.add(1);
        conn.send_filled += conn.engine.send_headers(
            stream_id,
            block,
            true,
            conn.send_buf[conn.send_filled..],
        );
        conn.engine.close_stream(stream_id);
        conn.flush_send();
    }

    /// Route/admission rejections before any upstream work: settle what was
    /// opened, then answer.
    fn leg_answer_early(conn: *H2Conn, leg: *StreamLeg, block: []const u8) void {
        const stream_id = leg.stream_id;
        conn.settle_leg(leg, .aborted);
        assert(leg.upstream_fd < 0);
        conn.leg_detach(leg);
        conn.answer_without_leg(stream_id, block);
        conn.maybe_finish_drain();
    }

    fn stage_reset(conn: *H2Conn, stream_id: u31, code: h2.ErrorCode) void {
        assert(conn.send_free() >= h2_frame.rst_stream_frame_bytes);
        conn.metrics.upstream_errors.add(1);
        conn.send_filled += conn.engine.reset_stream(
            stream_id,
            code,
            conn.send_buf[conn.send_filled..],
        );
        conn.flush_send();
    }

    fn stage_headers(conn: *H2Conn, stream_id: u31, block: []const u8, end_stream: bool) bool {
        const worst = block.len + 2 * h2_frame.frame_header_bytes;
        if (conn.send_free() < worst) return false;
        conn.send_filled += conn.engine.send_headers(
            stream_id,
            block,
            end_stream,
            conn.send_buf[conn.send_filled..],
        );
        conn.flush_send();
        return true;
    }

    /// The client reset the stream (or the connection is dying): drop the
    /// upstream and settle without touching the engine slot (already gone).
    fn leg_abort(conn: *H2Conn, leg: *StreamLeg) void {
        conn.settle_leg(leg, .aborted);
        conn.leg_dispose_upstream(leg);
        conn.leg_detach(leg);
    }

    /// Resilience settle, exactly once per leg (flag-guarded like H1).
    fn settle_leg(conn: *H2Conn, leg: *StreamLeg, outcome: resilience_mod.AttemptOutcome) void {
        leg.deadline_ns = 0;
        if (leg.attempt_open) {
            leg.attempt_open = false;
            const ejected = conn.resilience.attempt_finish(
                leg.cluster_index,
                leg.endpoint_index,
                outcome,
                leg.policy,
                endpoint_count(conn.router, leg.cluster_index),
                conn.io.now_ns(),
            );
            if (ejected) conn.metrics.outlier_ejections.add(1);
        }
        if (leg.request_admitted) {
            leg.request_admitted = false;
            conn.resilience.request_finish(leg.cluster_index);
        }
    }

    fn leg_dispose_upstream(conn: *H2Conn, leg: *StreamLeg) void {
        if (leg.upstream_fd < 0) return;
        if (leg.dial_pending) {
            // A pending connect must be cancelled, not closed: `ready` keeps a
            // queued connect selectable even after its fd is closed, so a
            // straight close would let it fire on a closed socket. Cancel it
            // and defer the fd close to on_leg_connect, which always fires
            // (even for a cancelled op). Found by the simulator, seed 17.
            if (!leg.connect_cancel_pending) {
                leg.connect_cancel_pending = true;
                conn.retain();
                conn.io.cancel(
                    *StreamLeg,
                    leg,
                    on_leg_connect_cancel,
                    &leg.connect_cancel_completion,
                    &leg.connect_completion,
                );
            }
            return; // the fd stays open until the connect resolves
        }
        assert(!leg.close_pending); // one close per leg lifetime (then release)
        conn.io.shutdown_socket(leg.upstream_fd);
        leg.close_pending = true;
        conn.retain();
        conn.io.close(
            *StreamLeg,
            leg,
            on_leg_closed,
            &leg.close_completion,
            leg.upstream_fd,
        );
        leg.upstream_fd = -1;
        conn.leg_account_drop(leg);
    }

    fn on_leg_closed(leg: *StreamLeg, _: *Completion, _: io_mod.CloseError!void) void {
        const conn = leg.conn;
        leg.close_pending = false;
        if (leg.orphaned) conn.leg_maybe_release(leg);
        conn.release_ref();
    }

    fn on_leg_connect_cancel(leg: *StreamLeg, _: *Completion, _: io_mod.CancelError!void) void {
        const conn = leg.conn;
        leg.connect_cancel_pending = false;
        if (leg.orphaned) conn.leg_maybe_release(leg);
        conn.release_ref();
    }

    fn leg_account_drop(conn: *H2Conn, leg: *StreamLeg) void {
        if (!leg.upstream_accounted) return;
        leg.upstream_accounted = false;
        conn.resilience.connection_close(leg.cluster_index);
    }

    // ---- leg registry ---------------------------------------------------------

    fn leg_attach(conn: *H2Conn, leg: *StreamLeg) void {
        assert(conn.active_count < conn.active_legs.len);
        for (&conn.active_legs) |*slot| {
            if (slot.* != null) continue;
            slot.* = leg;
            conn.active_count += 1;
            return;
        }
        unreachable; // active_count < len guarantees a free slot
    }

    /// Remove the leg from the connection; it returns to the worker pool
    /// only when its last in-flight op drains (never with a completion
    /// still in the ring — a reused completion corrupts the ring).
    fn leg_detach(conn: *H2Conn, leg: *StreamLeg) void {
        // The fd is gone, unless a mid-dial disposal deferred its close to
        // the connect completion (then a connect-cancel is in flight).
        assert(leg.upstream_fd < 0 or leg.connect_cancel_pending);
        assert(!leg.orphaned);
        for (&conn.active_legs) |*slot| {
            if (slot.* != leg) continue;
            slot.* = null;
            assert(conn.active_count > 0);
            conn.active_count -= 1;
            leg.orphaned = true;
            conn.leg_maybe_release(leg);
            return;
        }
        unreachable; // detach of an unattached leg
    }

    fn leg_maybe_release(conn: *H2Conn, leg: *StreamLeg) void {
        assert(leg.orphaned);
        if (leg.dial_pending or leg.upstream_send_active or
            leg.upstream_recv_active or leg.close_pending or
            leg.connect_cancel_pending) return;
        assert(leg.upstream_fd < 0); // the deferred close ran before release
        leg.orphaned = false;
        conn.legs.release(leg);
    }

    fn leg_for(conn: *H2Conn, stream_id: u31) ?*StreamLeg {
        assert(stream_id != 0);
        for (&conn.active_legs) |slot| {
            const leg = slot orelse continue;
            if (leg.stream_id == stream_id) return leg;
        }
        return null;
    }

    fn pump_blocked_streams(conn: *H2Conn, stream_id: u31) void {
        for (&conn.active_legs) |slot| {
            const leg = slot orelse continue;
            if (stream_id != 0 and leg.stream_id != stream_id) continue;
            if (leg.pending_answer != .none) {
                conn.leg_try_answer(leg);
            } else if (leg.response_state == .relaying) {
                conn.leg_forward_body(leg);
            } else if (leg.response_state == .done and !leg.fin_sent) {
                conn.leg_response_end(leg);
            }
        }
    }

    // ---- downstream send staging ---------------------------------------------

    fn send_free(conn: *const H2Conn) usize {
        assert(conn.send_filled >= conn.send_sent);
        assert(conn.send_filled <= conn.send_buf.len);
        return conn.send_buf.len - conn.send_filled;
    }

    fn flush_send(conn: *H2Conn) void {
        if (conn.tls != null) return conn.tls_flush_send();
        if (conn.closing or conn.send_in_flight) return;
        if (conn.send_sent == conn.send_filled) {
            conn.send_sent = 0;
            conn.send_filled = 0;
            if (conn.close_after_flush) conn.teardown();
            return;
        }
        conn.send_in_flight = true;
        conn.retain();
        conn.io.send(
            *H2Conn,
            conn,
            on_send,
            &conn.send_completion,
            conn.downstream_fd,
            conn.send_buf[conn.send_sent..conn.send_filled],
        );
    }

    fn on_send(conn: *H2Conn, _: *Completion, result: io_mod.SendError!usize) void {
        defer conn.release_ref();
        conn.send_in_flight = false;
        if (conn.closing) return;
        const m = result catch return conn.teardown();
        conn.send_sent += m;
        assert(conn.send_sent <= conn.send_filled);
        if (conn.send_sent < conn.send_filled) return conn.flush_send();
        conn.send_sent = 0;
        conn.send_filled = 0;
        if (conn.close_after_flush) return conn.teardown();
        conn.resume_after_send();
    }

    /// The send staging drained: let everyone who was blocked on it make
    /// progress — a pending drain GOAWAY, matured window updates, blocked
    /// relays, buffered input, and the next downstream read.
    fn resume_after_send(conn: *H2Conn) void {
        if (conn.closing or conn.close_after_flush) return;
        if (conn.drain_pending) conn.try_stage_drain();
        conn.pump_engine();
        conn.pump_blocked_streams(0);
        if (conn.tls != null) {
            // tls_service re-pumps plaintext (send room freed lets the
            // engine consume more), processes, and re-arms the wire read.
            conn.tls_service();
            return;
        }
        if (conn.recv_filled > 0) conn.process();
        if (!conn.recv_in_flight and !conn.closing and !conn.close_after_flush and
            conn.recv_filled < conn.recv_buf.len)
        {
            conn.arm_recv();
        }
        conn.flush_send();
    }

    // ---- downstream TLS relay (h2 over TLS) ------------------------------------
    //
    // The BIO-pair relay, mirroring ProxyConn's proven driver but simpler:
    // the handshake is already done (adopted post-ALPN), there is one leg
    // (downstream), and the logical endpoints are fixed — the "plaintext in"
    // target is always `recv_buf`'s tail, the "plaintext out" source always
    // `send_buf[send_sent..send_filled]`. Backpressure is unchanged: the
    // plaintext staging buffers are the boundary; the wire buffers are fixed
    // scratch drained across completions.

    /// Feed staged wire ciphertext into the channel; a partial feed compacts
    /// the remainder forward. Returns bytes fed (0 = pair full or nothing).
    fn tls_feed_staged(conn: *H2Conn) u32 {
        return conn.wire.feed_staged(&conn.tls.?);
    }

    /// Decrypt available ciphertext into `recv_buf`, drive the engine, and
    /// keep going while either makes progress — then arm the next wire read.
    fn tls_service(conn: *H2Conn) void {
        if (conn.closing) return;
        // Bounded: each pass either pumps plaintext or the engine consumes,
        // else it breaks; the recv buffer and the wire staging are finite.
        var budget: u32 = @intCast(conn.recv_buf.len / 64 + 16);
        while (budget > 0) : (budget -= 1) {
            var pumped = conn.tls_feed_staged() > 0;
            var reads: u32 = @intCast(conn.recv_buf.len / 16 + 16);
            while (conn.recv_filled < conn.recv_buf.len and reads > 0) : (reads -= 1) {
                switch (conn.tls.?.read_plaintext(conn.recv_buf[conn.recv_filled..])) {
                    .bytes => |n| {
                        conn.recv_filled += n;
                        pumped = true;
                    },
                    .closed => {
                        conn.tls_eof = true;
                        break;
                    },
                    .want_io => {
                        if (conn.tls_feed_staged() > 0) {
                            pumped = true;
                            continue;
                        }
                        break;
                    },
                    .failed => return conn.teardown(),
                }
            }
            const before = conn.recv_filled;
            conn.process(); // consumes recv_buf, stages+encrypts+sends via flush
            if (conn.closing) return;
            const consumed = before - conn.recv_filled;
            if (!pumped and consumed == 0) break;
            if (conn.tls_eof) break;
        }
        // Client activity resets the idle clock — never under drain.
        if (!conn.engine.draining() and !conn.drain_pending) {
            conn.set_deadline(conn.idle_timeout_ns);
        }
        if (conn.tls_eof) return conn.teardown(); // TLS EOF ends every stream
        conn.tls_arm_wire_recv();
    }

    fn tls_arm_wire_recv(conn: *H2Conn) void {
        if (conn.closing) return;
        if (conn.wire.recv_in_flight()) return;
        // Staging full means the pair is full too; reads make the room and
        // this re-arms on the next service pass.
        if (conn.wire.staging_full()) return;
        conn.wire.begin_recv();
        conn.retain();
        conn.io.recv(
            *H2Conn,
            conn,
            on_tls_wire_recv,
            &conn.tls_wire_recv_completion,
            conn.downstream_fd,
            conn.wire.recv_slot(),
        );
    }

    fn on_tls_wire_recv(conn: *H2Conn, _: *Completion, result: io_mod.RecvError!usize) void {
        defer conn.release_ref();
        conn.wire.end_recv();
        if (conn.closing) return;
        const n = result catch return conn.teardown();
        if (n == 0) {
            conn.tls_eof = true;
            return conn.teardown(); // wire EOF without close_notify: abrupt end
        }
        conn.wire.note_recv(n);
        conn.tls_service();
    }

    /// Encrypt as much staged plaintext as the pair accepts, then push
    /// ciphertext to the wire. The reset+resume happens in the wire-send
    /// completion (no synchronous recursion), exactly like the plaintext
    /// `on_send`.
    fn tls_flush_send(conn: *H2Conn) void {
        if (conn.closing) return;
        var budget: u32 = 64; // bounded: each pass consumes plaintext or breaks
        while (conn.send_sent < conn.send_filled and budget > 0) : (budget -= 1) {
            switch (conn.tls.?.write_plaintext(conn.send_buf[conn.send_sent..conn.send_filled])) {
                .bytes => |c| conn.send_sent += c,
                .want_io => break, // pair full: drain to the wire, come back
                .failed => return conn.teardown(),
            }
        }
        conn.tls_flush_wire_send();
        if (conn.tls_send_drained()) {
            conn.send_sent = 0;
            conn.send_filled = 0;
            if (conn.close_after_flush) conn.teardown();
        }
    }

    /// Every staged plaintext byte encrypted, all ciphertext sent, wire idle.
    fn tls_send_drained(conn: *const H2Conn) bool {
        return conn.send_sent == conn.send_filled and
            conn.tls.?.pending_ciphertext() == 0 and
            conn.wire.send_idle();
    }

    /// Keep exactly one wire send in flight while ciphertext is pending,
    /// refilling the staging buffer from the pair between sends.
    fn tls_flush_wire_send(conn: *H2Conn) void {
        if (conn.closing) return;
        if (conn.wire.send_in_flight()) return;
        if (!conn.wire.refill_send(&conn.tls.?)) return; // nothing pending
        conn.wire.begin_send();
        conn.retain();
        conn.io.send(
            *H2Conn,
            conn,
            on_tls_wire_send,
            &conn.tls_wire_send_completion,
            conn.downstream_fd,
            conn.wire.send_pending(),
        );
    }

    fn on_tls_wire_send(conn: *H2Conn, _: *Completion, result: io_mod.SendError!usize) void {
        defer conn.release_ref();
        conn.wire.end_send();
        if (conn.closing) return;
        const m = result catch return conn.teardown();
        conn.wire.note_sent(m);
        // Drained a bit: encrypt more (the pair freed room) and keep sending.
        conn.tls_flush_send();
        if (conn.closing) return;
        if (conn.tls_send_drained()) {
            conn.send_sent = 0;
            conn.send_filled = 0;
            if (conn.close_after_flush) return conn.teardown();
            conn.resume_after_send();
        }
    }

    // ---- graceful drain (docs/DESIGN.md §7 Phase 4, extended to H2) ------------

    /// Announce the drain (GOAWAY naming the highest served stream), clamp
    /// the deadline, and close once every live stream settles. In-flight
    /// exchanges complete; raced-in streams above the GOAWAY id are refused
    /// by the engine so clients retry elsewhere.
    pub fn begin_drain(conn: *H2Conn) void {
        if (conn.closing or conn.close_after_flush) return;
        // The deadline clamp bounds the drain whatever clients and origins
        // do — the existing ticking timer enforces it (the H1 rule).
        const drain_deadline = conn.io.now_ns() + conn.drain_timeout_ns;
        if (drain_deadline < conn.deadline_ns) conn.deadline_ns = drain_deadline;
        conn.drain_pending = true;
        conn.try_stage_drain();
    }

    fn try_stage_drain(conn: *H2Conn) void {
        assert(conn.drain_pending);
        if (conn.send_free() < h2_frame.goaway_frame_bytes) return; // send drain retries
        conn.drain_pending = false;
        conn.send_filled += conn.engine.begin_drain(conn.send_buf[conn.send_filled..]);
        conn.flush_send();
        conn.maybe_finish_drain();
    }

    /// A draining connection closes when its last stream settles (engine
    /// slots and legs both empty).
    fn maybe_finish_drain(conn: *H2Conn) void {
        if (!conn.engine.draining()) return;
        if (conn.closing or conn.close_after_flush) return;
        if (conn.engine.streams_active > 0 or conn.active_count > 0) return;
        conn.close_after_flush = true;
        conn.flush_send();
    }

    // ---- deadline -------------------------------------------------------------

    fn set_deadline(conn: *H2Conn, timeout_ns: u63) void {
        assert(timeout_ns > 0);
        conn.deadline_ns = conn.io.now_ns() + timeout_ns;
    }

    fn arm_timeout(conn: *H2Conn) void {
        assert(!conn.timeout_armed);
        conn.retain();
        conn.timeout_armed = true;
        conn.io.timeout(
            *H2Conn,
            conn,
            on_timeout,
            &conn.timeout_completion,
            constants.timeout_tick_ns,
        );
    }

    fn on_timeout(conn: *H2Conn, _: *Completion, _: io_mod.TimeoutError!void) void {
        defer conn.release_ref();
        conn.timeout_armed = false;
        if (conn.closing) return;
        const now = conn.io.now_ns();
        if (now >= conn.deadline_ns) return conn.teardown();
        // Per-stream deadlines ride the same tick — but only while the engine
        // is live: fatal-pending (`close_after_flush`) tears down via the send
        // flush, and answering a stream would drive the `.failed` engine.
        for (&conn.active_legs) |slot| {
            if (conn.close_after_flush) break;
            const leg = slot orelse continue;
            if (leg.deadline_ns != 0 and now >= leg.deadline_ns) {
                conn.metrics.upstream_errors.add(1);
                conn.leg_answer(leg, .gateway_timeout);
            }
        }
        conn.arm_timeout();
    }

    // ---- lifetime --------------------------------------------------------------

    fn retain(conn: *H2Conn) void {
        conn.refs += 1;
    }

    fn release_ref(conn: *H2Conn) void {
        assert(conn.refs > 0);
        conn.refs -= 1;
        if (conn.closing and conn.refs == 0) {
            // Quiescent: no wire op can touch the channel. Its SSL + BIO
            // pair return to the TLS heap with the slot.
            if (conn.tls) |channel| {
                channel.deinit();
                conn.tls = null;
            }
            conn.metrics.active.sub(1);
            conn.pool.release(conn);
        }
    }

    fn teardown(conn: *H2Conn) void {
        if (conn.closing) return;
        conn.closing = true;
        // Every live stream aborts; upstream fds shutdown+close so pending
        // ops complete and the refcount drains (the H1 teardown rule).
        for (&conn.active_legs) |slot| {
            const leg = slot orelse continue;
            conn.leg_abort(leg);
        }
        assert(conn.active_count == 0);
        if (conn.timeout_armed) {
            conn.timeout_armed = false;
            conn.retain();
            conn.io.cancel(
                *H2Conn,
                conn,
                on_cancel,
                &conn.timeout_cancel_completion,
                &conn.timeout_completion,
            );
        }
        if (conn.downstream_fd >= 0) {
            conn.io.shutdown_socket(conn.downstream_fd);
            conn.retain();
            conn.io.close(
                *H2Conn,
                conn,
                on_closed,
                &conn.close_completion,
                conn.downstream_fd,
            );
            conn.downstream_fd = -1;
        }
    }

    fn on_cancel(conn: *H2Conn, _: *Completion, _: io_mod.CancelError!void) void {
        conn.release_ref();
    }

    fn on_closed(conn: *H2Conn, _: *Completion, _: io_mod.CloseError!void) void {
        conn.release_ref();
    }
};

/// Accept loop for a plaintext h2c listener — the simulator's H2 driver.
/// (TLS-ALPN `h2` never arrives here; it reaches `H2Conn` via
/// `ProxyServer.hand_off_to_h2`. The sim excludes OpenSSL, so h2c is the
/// only way to exercise the whole engine / leg / flow-control path.)
pub const H2Server = struct {
    io: *IO,
    pool: *H2ConnPool,
    legs: *LegPool,
    listener: Listener,
    router: *const Router,
    metrics: *Counters,
    access: *AccessLog,
    resilience: Resilience,
    upstream_pool: UpstreamPool,
    prng: std.Random.DefaultPrng,
    request_timeout_ns: u63,
    idle_timeout_ns: u63,
    /// Drain-to-forced-teardown bound handed to each connection; the sim
    /// shrinks it. Defaults to the global constant (production).
    drain_timeout_ns: u63 = constants.drain_timeout_ns,
    /// Once draining: no new connections accepted, live ones GOAWAY-drained.
    draining: bool = false,
    listener_closed: bool = false,
    accept_completion: Completion = undefined,

    pub fn init(
        io: *IO,
        pool: *H2ConnPool,
        legs: *LegPool,
        listener: Listener,
        router: *const Router,
        metrics: *Counters,
        access: *AccessLog,
        request_timeout_ns: u63,
        idle_timeout_ns: u63,
    ) H2Server {
        return .{
            .io = io,
            .pool = pool,
            .legs = legs,
            .listener = listener,
            .router = router,
            .metrics = metrics,
            .access = access,
            .resilience = .{},
            .upstream_pool = .{},
            .prng = std.Random.DefaultPrng.init(0),
            .request_timeout_ns = request_timeout_ns,
            .idle_timeout_ns = idle_timeout_ns,
        };
    }

    pub fn deinit(server: *H2Server) void {
        server.upstream_pool.drain(server.io);
    }

    pub fn start(server: *H2Server) void {
        server.io.accept(
            *H2Server,
            server,
            on_accept,
            &server.accept_completion,
            server.listener.fd,
        );
    }

    /// Sweep every live connection into graceful drain (GOAWAY + clamped
    /// deadline) and stop accepting new ones. Idempotent. The pending accept
    /// is left in flight (it holds no slot); a connection that races it is
    /// refused in on_accept.
    pub fn begin_drain(server: *H2Server) void {
        if (!server.draining) {
            server.draining = true;
            // Close the listener now: this also FINs connections queued in the
            // accept backlog but never accepted (they would otherwise hang,
            // never accepted and never closed). The pending accept op is left
            // dangling — harmless, it can never become ready on a dead
            // listener. A queued connection getting RST beats one accepted
            // then immediately GOAWAY'd. (The ALPN-handoff path drains via
            // ProxyServer, which owns its own listener lifecycle.)
            if (!server.listener_closed) {
                server.listener_closed = true;
                server.io.close_now(server.listener.fd);
            }
        }
        for (server.pool.items) |*conn| {
            if (!conn.in_use) continue;
            conn.begin_drain();
        }
    }

    /// Drained when every connection slot and stream leg is back and no new
    /// connection was accepted after the drain began.
    pub fn drain_complete(server: *const H2Server) bool {
        if (!server.draining) return false;
        if (server.pool.free_count != server.pool.capacity) return false;
        if (server.legs.free_count != server.legs.capacity) return false;
        return true;
    }

    fn on_accept(
        server: *H2Server,
        _: *Completion,
        result: io_mod.AcceptError!posix.socket_t,
    ) void {
        const fd = result catch return if (!server.draining) server.start();
        if (server.draining) {
            // Refused-at-accept beats accepted-then-GOAWAY'd; do not re-arm.
            server.metrics.rejected.add(1);
            server.io.close_now(fd);
            return;
        }
        const conn = server.pool.acquire() orelse {
            server.metrics.rejected.add(1);
            server.io.close_now(fd);
            return server.start();
        };
        server.metrics.accepted.add(1);
        conn.start(
            server.io,
            server.pool,
            server.legs,
            server.router,
            &server.resilience,
            &server.upstream_pool,
            server.metrics,
            server.access,
            server.prng.random(),
            fd,
            server.request_timeout_ns,
            server.idle_timeout_ns,
            server.drain_timeout_ns,
            null, // h2c: plaintext listener
            "",
        );
        server.start();
    }
};

// ---- shared helpers -------------------------------------------------------

const h2_translate_head_capacity = constants.h2_header_list_bytes_max + 256;

comptime {
    assert(StreamLeg.request_buf_bytes >= h2_translate_head_capacity);
}

/// Pre-encoded head-only answers (hpack literal blocks, stateless).
const response_block_404 = "\x8d"; // :status 404 — static table index 13
const response_block_502 = "\x48\x03\x35\x30\x32"; // :status literal "502"
const response_block_503 = "\x48\x03\x35\x30\x33";
const response_block_504 = "\x48\x03\x35\x30\x34";

fn field_value(headers: []const hpack.Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) return header.value;
    }
    return null;
}

fn copy_bounded(target: anytype, target_len: *u8, value: ?[]const u8) void {
    const source = value orelse "";
    const n = @min(source.len, target.len);
    @memcpy(target[0..n], source[0..n]);
    target_len.* = @intCast(n);
}

fn token_list_names(list: []const u8, name: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, list, ',');
    while (tokens.next()) |token| {
        const trimmed = std.mem.trim(u8, token, " \t");
        if (trimmed.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(trimmed, name)) return true;
    }
    return false;
}

fn endpoint_count(router: *const Router, cluster_index: u32) u32 {
    return @intCast(router.config.clusters[cluster_index].endpoints.len);
}

fn sockaddr_in(address: Ip4Address) linux.sockaddr.in {
    return .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, address.port),
        .addr = @bitCast(address.bytes),
    };
}

// ---- tests ----------------------------------------------------------------

const testing = std.testing;
const guard = @import("../mem/guard.zig");

/// Minimal H1 origin on the test IO loop (a lean twin of proxy.zig's):
/// accepts one connection, answers each time `respond_after` shows up in
/// the bytes received since the last response.
const TestOrigin = struct {
    io: *IO,
    listener: Listener,
    response: []const u8,
    respond_after: []const u8 = "\r\n\r\n",
    fd: posix.socket_t = -1,
    request_buf: [2048]u8 = undefined,
    request_len: usize = 0,
    served_mark: usize = 0,
    sent: usize = 0,
    accept_c: Completion = undefined,
    recv_c: Completion = undefined,
    send_c: Completion = undefined,

    fn start(origin: *TestOrigin) void {
        origin.io.accept(*TestOrigin, origin, on_accept, &origin.accept_c, origin.listener.fd);
    }
    fn on_accept(o: *TestOrigin, _: *Completion, result: io_mod.AcceptError!posix.socket_t) void {
        o.fd = result catch return;
        o.arm_recv();
    }
    fn arm_recv(o: *TestOrigin) void {
        o.io.recv(*TestOrigin, o, on_recv, &o.recv_c, o.fd, o.request_buf[o.request_len..]);
    }
    fn on_recv(o: *TestOrigin, _: *Completion, result: io_mod.RecvError!usize) void {
        const n = result catch return;
        if (n == 0) return;
        o.request_len += n;
        const unserved = o.request_buf[o.served_mark..o.request_len];
        if (std.mem.indexOf(u8, unserved, o.respond_after) == null) return o.arm_recv();
        o.sent = 0;
        o.arm_send();
    }
    fn arm_send(o: *TestOrigin) void {
        o.io.send(*TestOrigin, o, on_send, &o.send_c, o.fd, o.response[o.sent..]);
    }
    fn on_send(o: *TestOrigin, _: *Completion, result: io_mod.SendError!usize) void {
        o.sent += result catch return;
        if (o.sent < o.response.len) return o.arm_send();
        o.served_mark = o.request_len;
        o.arm_recv(); // linger: pooled upstream connections carry the next request
    }
};

/// An HTTP/2 client on a real socket: stages preface + SETTINGS + one
/// request (optionally with a body), then parses server frames until the
/// stream ends. Control frames are ignored; RST_STREAM fails the exchange.
const H2TestClient = struct {
    io: *IO,
    fd: posix.socket_t,
    out_buf: [2048]u8 = undefined,
    out_len: usize = 0,
    out_sent: usize = 0,
    in_buf: [8192]u8 = undefined,
    in_len: usize = 0,
    decoder: hpack.Decoder = .{},
    fields: [16]hpack.Header = undefined,
    fields_storage: [1024]u8 = undefined,
    status: u16 = 0,
    header_count: usize = 0,
    body: [512]u8 = undefined,
    body_len: usize = 0,
    done: bool = false,
    reset: bool = false,
    saw_goaway: bool = false,
    send_c: Completion = undefined,
    recv_c: Completion = undefined,

    fn stage(client: *H2TestClient, bytes: []const u8) void {
        @memcpy(client.out_buf[client.out_len..][0..bytes.len], bytes);
        client.out_len += bytes.len;
    }

    fn stage_request(client: *H2TestClient, path: []const u8, end_stream: bool) void {
        var block: [256]u8 = undefined;
        var block_len: usize = 0;
        block_len += hpack.encode_header(
            ":method",
            if (end_stream) "GET" else "POST",
            block[block_len..],
        ) catch unreachable;
        block_len += hpack.encode_header(":scheme", "http", block[block_len..]) catch unreachable;
        block_len += hpack.encode_header(":path", path, block[block_len..]) catch unreachable;
        block_len += hpack.encode_header(
            ":authority",
            "origin",
            block[block_len..],
        ) catch unreachable;
        var flags: u8 = h2_frame.Flags.end_headers;
        if (end_stream) flags |= h2_frame.Flags.end_stream;
        h2_frame.write_frame_header(.{
            .length = @intCast(block_len),
            .type = .headers,
            .flags = flags,
            .stream_id = 1,
        }, client.out_buf[client.out_len..][0..h2_frame.frame_header_bytes]);
        client.out_len += h2_frame.frame_header_bytes;
        client.stage(block[0..block_len]);
    }

    fn stage_data(client: *H2TestClient, payload: []const u8, end_stream: bool) void {
        h2_frame.write_frame_header(.{
            .length = @intCast(payload.len),
            .type = .data,
            .flags = if (end_stream) h2_frame.Flags.end_stream else 0,
            .stream_id = 1,
        }, client.out_buf[client.out_len..][0..h2_frame.frame_header_bytes]);
        client.out_len += h2_frame.frame_header_bytes;
        client.stage(payload);
    }

    fn go(client: *H2TestClient) void {
        client.io.recv(*H2TestClient, client, on_recv, &client.recv_c, client.fd, &client.in_buf);
        client.arm_send();
    }
    fn arm_send(client: *H2TestClient) void {
        client.io.send(
            *H2TestClient,
            client,
            on_send,
            &client.send_c,
            client.fd,
            client.out_buf[client.out_sent..client.out_len],
        );
    }
    fn on_send(client: *H2TestClient, _: *Completion, result: io_mod.SendError!usize) void {
        client.out_sent += result catch return;
        if (client.out_sent < client.out_len) client.arm_send();
    }
    fn on_recv(client: *H2TestClient, _: *Completion, result: io_mod.RecvError!usize) void {
        const n = result catch 0;
        if (n == 0) {
            client.done = true;
            return;
        }
        client.in_len += n;
        client.consume_frames();
        if (!client.done) {
            client.io.recv(
                *H2TestClient,
                client,
                on_recv,
                &client.recv_c,
                client.fd,
                client.in_buf[client.in_len..],
            );
        }
    }
    fn consume_frames(client: *H2TestClient) void {
        var offset: usize = 0;
        while (true) {
            const frame = (h2_frame.parse_frame(client.in_buf[offset..client.in_len]) catch {
                client.reset = true;
                client.done = true;
                break;
            }) orelse break;
            offset += frame.wire_bytes();
            switch (frame.header.type) {
                .headers => {
                    const decoded = client.decoder.decode(
                        frame.payload,
                        &client.fields,
                        &client.fields_storage,
                    ) catch unreachable;
                    client.header_count = decoded.len;
                    client.status = std.fmt.parseInt(u16, decoded[0].value, 10) catch 0;
                    if (frame.header.flags & h2_frame.Flags.end_stream != 0) client.done = true;
                },
                .data => {
                    @memcpy(
                        client.body[client.body_len..][0..frame.payload.len],
                        frame.payload,
                    );
                    client.body_len += frame.payload.len;
                    if (frame.header.flags & h2_frame.Flags.end_stream != 0) client.done = true;
                },
                .rst_stream => {
                    client.reset = true;
                    client.done = true;
                },
                .goaway => client.saw_goaway = true,
                else => {}, // SETTINGS, WINDOW_UPDATE, PING: ignored
            }
        }
        std.mem.copyForwards(
            u8,
            client.in_buf[0 .. client.in_len - offset],
            client.in_buf[offset..client.in_len],
        );
        client.in_len -= offset;
    }
};

const TestHarness = struct {
    io: IO,
    cfg: config.Config,
    router: Router,
    pool: H2ConnPool,
    legs: LegPool,
    metrics: Counters,
    access: AccessLog,
    server: H2Server,
    listener: Listener,

    fn init(harness: *TestHarness, gpa: std.mem.Allocator, origin_port: u16) !void {
        harness.io = try IO.init(64, 0);
        var json_buf: [256]u8 = undefined;
        const cfg_text = try std.fmt.bufPrint(&json_buf,
            \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
            \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
        , .{origin_port});
        harness.cfg = try config.parse(gpa, cfg_text);
        harness.router = Router.init(&harness.cfg);
        harness.pool = try H2ConnPool.init(gpa, 2);
        harness.legs = try LegPool.init(gpa, 4);
        harness.metrics = Counters{};
        harness.access = AccessLog{ .fd = -1 };
        harness.listener = try Listener.open(Ip4Address.loopback(0), 8);
        harness.server = H2Server.init(
            &harness.io,
            &harness.pool,
            &harness.legs,
            harness.listener,
            &harness.router,
            &harness.metrics,
            &harness.access,
            constants.request_timeout_ns,
            constants.idle_timeout_ns,
        );
        harness.server.start();
    }

    fn deinit(harness: *TestHarness, gpa: std.mem.Allocator) void {
        harness.server.deinit();
        // A drained server already closed its listener fd; don't double-close.
        if (!harness.server.listener_closed) harness.listener.close();
        harness.legs.deinit(gpa);
        harness.pool.deinit(gpa);
        harness.cfg.deinit();
        harness.io.deinit();
    }

    /// Wait until every conn slot and leg is home — nothing leaked.
    fn settle(harness: *TestHarness) !void {
        while (harness.pool.free_count != harness.pool.capacity or
            harness.legs.free_count != harness.legs.capacity)
        {
            try harness.io.run_once();
        }
    }
};

fn connect_loopback(port: u16) !posix.socket_t {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    try testing.expect(linux.errno(rc) == .SUCCESS);
    const fd: posix.socket_t = @intCast(rc);
    const sa = sockaddr_in(Ip4Address.loopback(port));
    try testing.expect(
        linux.errno(linux.connect(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) == .SUCCESS,
    );
    return fd;
}

test "h2_proxy: relays a GET end to end and pools the upstream" {
    const gpa = testing.allocator;
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();

    var harness: TestHarness = undefined;
    try harness.init(gpa, origin_listener.bound_address().port);
    defer harness.deinit(gpa);

    var origin = TestOrigin{
        .io = &harness.io,
        .listener = origin_listener,
        .response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHELLO",
    };
    origin.start();

    const fd = try connect_loopback(harness.listener.bound_address().port);
    var client = H2TestClient{ .io = &harness.io, .fd = fd };
    client.stage(h2_frame.client_preface);
    var settings: [64]u8 = undefined;
    client.stage(settings[0..h2_frame.write_settings(&.{}, &settings)]);
    client.stage_request("/hello", true);
    client.go();

    try harness.io.run_until_done(&client.done);
    try testing.expect(!client.reset);
    try testing.expectEqual(@as(u16, 200), client.status);
    try testing.expectEqualStrings("HELLO", client.body[0..client.body_len]);

    // The origin saw a synthesized H1 head: request line, lowercased host.
    const seen = origin.request_buf[0..origin.request_len];
    try testing.expect(std.mem.startsWith(u8, seen, "GET /hello HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, seen, "host: origin\r\n") != null);

    // The reusable upstream was parked; the client hangup reclaims the slot.
    try testing.expectEqual(@as(u32, 1), harness.server.upstream_pool.count);
    _ = linux.close(fd);
    try harness.settle();
    try testing.expect(harness.server.resilience.is_idle());
}

test "h2_proxy: streams a request body upstream as chunked" {
    const gpa = testing.allocator;
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();

    var harness: TestHarness = undefined;
    try harness.init(gpa, origin_listener.bound_address().port);
    defer harness.deinit(gpa);

    var origin = TestOrigin{
        .io = &harness.io,
        .listener = origin_listener,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .respond_after = "0\r\n\r\n", // the terminal chunk of the converted body
    };
    origin.start();

    const fd = try connect_loopback(harness.listener.bound_address().port);
    var client = H2TestClient{ .io = &harness.io, .fd = fd };
    client.stage(h2_frame.client_preface);
    var settings: [64]u8 = undefined;
    client.stage(settings[0..h2_frame.write_settings(&.{}, &settings)]);
    client.stage_request("/upload", false); // POST, no content-length
    client.stage_data("chunk-one:", false);
    client.stage_data("chunk-two", true);
    client.go();

    try harness.io.run_until_done(&client.done);
    try testing.expect(!client.reset);
    try testing.expectEqual(@as(u16, 200), client.status);
    try testing.expectEqualStrings("ok", client.body[0..client.body_len]);

    // The DATA frames crossed as chunked coding with a terminal chunk.
    const seen = origin.request_buf[0..origin.request_len];
    try testing.expect(std.mem.indexOf(u8, seen, "transfer-encoding: chunked\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, seen, "chunk-one:") != null);
    try testing.expect(std.mem.indexOf(u8, seen, "chunk-two") != null);
    try testing.expect(std.mem.endsWith(u8, seen, "0\r\n\r\n"));

    _ = linux.close(fd);
    try harness.settle();
    try testing.expect(harness.server.resilience.is_idle());
}

test "h2_proxy: an unreachable upstream answers the stream 502" {
    const gpa = testing.allocator;
    // Grab a port, then free it: nobody listens there.
    var dead_listener = try Listener.open(Ip4Address.loopback(0), 1);
    const dead_port = dead_listener.bound_address().port;
    dead_listener.close();

    var harness: TestHarness = undefined;
    try harness.init(gpa, dead_port);
    defer harness.deinit(gpa);

    const fd = try connect_loopback(harness.listener.bound_address().port);
    var client = H2TestClient{ .io = &harness.io, .fd = fd };
    client.stage(h2_frame.client_preface);
    var settings: [64]u8 = undefined;
    client.stage(settings[0..h2_frame.write_settings(&.{}, &settings)]);
    client.stage_request("/", true);
    client.go();

    try harness.io.run_until_done(&client.done);
    try testing.expect(!client.reset); // a clean 502 head, not an RST
    try testing.expectEqual(@as(u16, 502), client.status);
    try testing.expectEqual(@as(usize, 0), client.body_len);

    _ = linux.close(fd);
    try harness.settle();
    try testing.expect(harness.server.resilience.is_idle());
}

test "h2_proxy: drain announces GOAWAY, completes in-flight streams, then closes" {
    const gpa = testing.allocator;
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();

    var harness: TestHarness = undefined;
    try harness.init(gpa, origin_listener.bound_address().port);
    defer harness.deinit(gpa);

    var origin = TestOrigin{
        .io = &harness.io,
        .listener = origin_listener,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        .respond_after = "0\r\n\r\n", // waits for the whole chunked body
    };
    origin.start();

    // An in-flight POST: head forwarded, body still owed when drain begins.
    const busy_fd = try connect_loopback(harness.listener.bound_address().port);
    defer _ = linux.close(busy_fd);
    var busy = H2TestClient{ .io = &harness.io, .fd = busy_fd };
    busy.stage(h2_frame.client_preface);
    var settings: [64]u8 = undefined;
    busy.stage(settings[0..h2_frame.write_settings(&.{}, &settings)]);
    busy.stage_request("/upload", false);
    busy.go();
    while (origin.request_len == 0) try harness.io.run_once();

    // An idle connection alongside it.
    const idle_fd = try connect_loopback(harness.listener.bound_address().port);
    defer _ = linux.close(idle_fd);
    var idle = H2TestClient{ .io = &harness.io, .fd = idle_fd };
    idle.stage(h2_frame.client_preface);
    idle.stage(settings[0..h2_frame.write_settings(&.{}, &settings)]);
    idle.go();
    while (harness.pool.free_count != harness.pool.capacity - 2) try harness.io.run_once();

    harness.server.begin_drain();

    // The idle connection gets GOAWAY and closes immediately (EOF ends it).
    try harness.io.run_until_done(&idle.done);
    try testing.expect(idle.saw_goaway);
    try testing.expectEqual(@as(u16, 0), idle.status); // no stream, no response

    // The busy stream still completes: finish the body, read the response.
    busy.stage_data("late body", true);
    busy.arm_send();
    try harness.io.run_until_done(&busy.done);
    try testing.expect(busy.saw_goaway);
    try testing.expect(!busy.reset);
    try testing.expectEqual(@as(u16, 200), busy.status);
    try testing.expectEqualStrings("ok", busy.body[0..busy.body_len]);

    // Both connections close themselves; every slot comes home.
    try harness.settle();
    try testing.expect(harness.server.resilience.is_idle());
}

// ---- h2 over TLS -----------------------------------------------------------

const openssl = @import("../tls/openssl.zig");
const install_tls_test_hook = openssl.install_memory_hook_for_tests;
const test_certificate_pem = @embedFile("../tls/testdata/certificate.pem");
const test_private_key_pem = @embedFile("../tls/testdata/private_key.pem");

/// Complete both channels' handshakes in memory (no sockets), shuttling
/// ciphertext directly between the pair — the transport-agnostic setup for
/// the data phase that follows over a real socket.
fn handshake_in_memory(client: *terminator.Channel, server: *terminator.Channel) !void {
    var scratch: [constants.tls_bio_pair_bytes]u8 = undefined;
    _ = client.handshake_step(); // ClientHello
    var rounds: u32 = 0;
    while (rounds < 40) : (rounds += 1) {
        const moved = move_ciphertext(client, server, &scratch) +
            move_ciphertext(server, client, &scratch);
        _ = client.handshake_step();
        _ = server.handshake_step();
        if (client.handshake_done() and server.handshake_done()) return;
        if (moved == 0) break;
    }
    return error.HandshakeStalled;
}

fn move_ciphertext(from: *terminator.Channel, to: *terminator.Channel, scratch: []u8) usize {
    const drained = from.drain_ciphertext(scratch);
    if (drained == 0) return 0;
    const fed = to.feed_ciphertext(scratch[0..drained]);
    assert(fed == drained); // an empty pair always accepts a flight
    return drained;
}

/// An h2 client speaking TLS on a real socket: it wraps the plaintext frame
/// staging in `terminator.Channel` encrypt/decrypt, otherwise mirroring the
/// plaintext H2TestClient's frame handling.
const TlsH2Client = struct {
    io: *IO,
    fd: posix.socket_t,
    channel: terminator.Channel,
    plain_out: [2048]u8 = undefined,
    plain_out_len: usize = 0,
    plain_out_encrypted: usize = 0,
    wire_out: [constants.tls_bio_pair_bytes]u8 = undefined,
    wire_out_filled: usize = 0,
    wire_out_sent: usize = 0,
    send_in_flight: bool = false,
    wire_in: [constants.tls_bio_pair_bytes]u8 = undefined,
    recv_in_flight: bool = false,
    frames: H2FrameSink = .{},
    send_c: Completion = undefined,
    recv_c: Completion = undefined,

    fn stage(client: *TlsH2Client, bytes: []const u8) void {
        @memcpy(client.plain_out[client.plain_out_len..][0..bytes.len], bytes);
        client.plain_out_len += bytes.len;
    }

    fn go(client: *TlsH2Client) void {
        client.pump();
    }

    /// Encrypt staged plaintext, flush ciphertext, decrypt incoming frames,
    /// re-arm the wire read — the client-side twin of the server relay.
    fn pump(client: *TlsH2Client) void {
        var budget: u32 = 32;
        while (client.plain_out_encrypted < client.plain_out_len and budget > 0) : (budget -= 1) {
            switch (client.channel.write_plaintext(
                client.plain_out[client.plain_out_encrypted..client.plain_out_len],
            )) {
                .bytes => |c| client.plain_out_encrypted += c,
                .want_io => break,
                .failed => return,
            }
        }
        var read_budget: u32 = 64;
        while (read_budget > 0) : (read_budget -= 1) {
            var plain: [1024]u8 = undefined;
            switch (client.channel.read_plaintext(&plain)) {
                .bytes => |n| client.frames.feed(plain[0..n]),
                .closed => {
                    client.frames.done = true;
                    break;
                },
                .want_io, .failed => break,
            }
        }
        client.flush_wire();
        client.arm_wire_recv();
    }

    fn flush_wire(client: *TlsH2Client) void {
        if (client.send_in_flight) return;
        if (client.wire_out_sent == client.wire_out_filled) {
            client.wire_out_filled = client.channel.drain_ciphertext(&client.wire_out);
            client.wire_out_sent = 0;
            if (client.wire_out_filled == 0) return;
        }
        client.send_in_flight = true;
        client.io.send(
            *TlsH2Client,
            client,
            on_send,
            &client.send_c,
            client.fd,
            client.wire_out[client.wire_out_sent..client.wire_out_filled],
        );
    }
    fn on_send(client: *TlsH2Client, _: *Completion, result: io_mod.SendError!usize) void {
        client.send_in_flight = false;
        client.wire_out_sent += result catch return;
        client.pump();
    }
    fn arm_wire_recv(client: *TlsH2Client) void {
        if (client.recv_in_flight or client.frames.done) return;
        client.recv_in_flight = true;
        client.io.recv(*TlsH2Client, client, on_recv, &client.recv_c, client.fd, &client.wire_in);
    }
    fn on_recv(client: *TlsH2Client, _: *Completion, result: io_mod.RecvError!usize) void {
        client.recv_in_flight = false;
        const n = result catch 0;
        if (n == 0) {
            client.frames.done = true;
            return;
        }
        const fed = client.channel.feed_ciphertext(client.wire_in[0..n]);
        assert(fed == n);
        client.pump();
    }
};

/// Parses server frames out of a decrypted plaintext stream — the framing
/// half of both H2 test clients, factored out.
const H2FrameSink = struct {
    buf: [8192]u8 = undefined,
    len: usize = 0,
    decoder: hpack.Decoder = .{},
    fields: [16]hpack.Header = undefined,
    fields_storage: [1024]u8 = undefined,
    status: u16 = 0,
    body: [512]u8 = undefined,
    body_len: usize = 0,
    done: bool = false,
    reset: bool = false,

    fn feed(sink: *H2FrameSink, plain: []const u8) void {
        @memcpy(sink.buf[sink.len..][0..plain.len], plain);
        sink.len += plain.len;
        var offset: usize = 0;
        while (true) {
            const frame = (h2_frame.parse_frame(sink.buf[offset..sink.len]) catch {
                sink.reset = true;
                sink.done = true;
                break;
            }) orelse break;
            offset += frame.wire_bytes();
            switch (frame.header.type) {
                .headers => {
                    const decoded = sink.decoder.decode(
                        frame.payload,
                        &sink.fields,
                        &sink.fields_storage,
                    ) catch unreachable;
                    sink.status = std.fmt.parseInt(u16, decoded[0].value, 10) catch 0;
                    if (frame.header.flags & h2_frame.Flags.end_stream != 0) sink.done = true;
                },
                .data => {
                    @memcpy(sink.body[sink.body_len..][0..frame.payload.len], frame.payload);
                    sink.body_len += frame.payload.len;
                    if (frame.header.flags & h2_frame.Flags.end_stream != 0) sink.done = true;
                },
                .rst_stream => {
                    sink.reset = true;
                    sink.done = true;
                },
                else => {},
            }
        }
        std.mem.copyForwards(u8, sink.buf[0 .. sink.len - offset], sink.buf[offset..sink.len]);
        sink.len -= offset;
    }
};

/// Setup for adopting a TLS-terminated h2 connection into an H2Conn without
/// the H1 handshaker (that path is exercised in proxy.zig): everything the
/// H2Conn needs, plus a socketpair carrying ciphertext to a TlsH2Client.
const TlsHarness = struct {
    io: IO,
    cfg: config.Config,
    router: Router,
    pool: H2ConnPool,
    legs: LegPool,
    resilience: Resilience,
    upstream_pool: UpstreamPool,
    metrics: Counters,
    access: AccessLog,
    prng: std.Random.DefaultPrng,
    server_ctx: terminator.Context,
    client_ctx: terminator.Context,

    fn init(harness: *TlsHarness, gpa: std.mem.Allocator, origin_port: u16) !void {
        install_tls_test_hook();
        harness.io = try IO.init(64, 0);
        var json_buf: [256]u8 = undefined;
        const cfg_text = try std.fmt.bufPrint(&json_buf,
            \\{{ "listen": "0.0.0.0:0", "routes": [{{ "cluster": "o" }}],
            \\   "clusters": [{{ "name": "o", "endpoints": ["127.0.0.1:{d}"] }}] }}
        , .{origin_port});
        harness.cfg = try config.parse(gpa, cfg_text);
        harness.router = Router.init(&harness.cfg);
        harness.pool = try H2ConnPool.init(gpa, 2);
        harness.legs = try LegPool.init(gpa, 4);
        harness.resilience = .{};
        harness.upstream_pool = .{};
        harness.metrics = Counters{};
        harness.access = AccessLog{ .fd = -1 };
        harness.prng = std.Random.DefaultPrng.init(1);
        harness.server_ctx = try terminator.Context.init_server(
            test_certificate_pem,
            test_private_key_pem,
        );
        terminator.enable_h2(&harness.server_ctx);
        harness.client_ctx = try terminator.Context.init_client(.insecure);
    }

    fn deinit(harness: *TlsHarness, gpa: std.mem.Allocator) void {
        harness.upstream_pool.drain(&harness.io);
        harness.server_ctx.deinit();
        harness.client_ctx.deinit();
        harness.legs.deinit(gpa);
        harness.pool.deinit(gpa);
        harness.cfg.deinit();
        harness.io.deinit();
    }

    /// Adopt a handshaken server channel + fd into a fresh H2Conn, exactly
    /// as the ProxyConn handoff will.
    fn adopt(
        harness: *TlsHarness,
        fd: posix.socket_t,
        channel: terminator.Channel,
        staged: []const u8,
    ) void {
        const conn = harness.pool.acquire().?;
        conn.start(
            &harness.io,
            &harness.pool,
            &harness.legs,
            &harness.router,
            &harness.resilience,
            &harness.upstream_pool,
            &harness.metrics,
            &harness.access,
            harness.prng.random(),
            fd,
            constants.request_timeout_ns,
            constants.idle_timeout_ns,
            constants.drain_timeout_ns,
            channel,
            staged,
        );
    }

    fn settle(harness: *TlsHarness) !void {
        while (harness.pool.free_count != harness.pool.capacity or
            harness.legs.free_count != harness.legs.capacity)
        {
            try harness.io.run_once();
        }
    }
};

/// A connected AF_UNIX stream pair for the ciphertext transport.
fn socket_pair() ![2]posix.socket_t {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    try testing.expect(linux.errno(rc) == .SUCCESS);
    return fds;
}

/// Build both channels, negotiate ALPN=h2 via an in-memory handshake.
fn tls_h2_channels(harness: *TlsHarness) !struct {
    server: terminator.Channel,
    client: terminator.Channel,
} {
    var server = try terminator.Channel.init(&harness.server_ctx);
    errdefer server.deinit();
    var client = try terminator.Channel.init(&harness.client_ctx);
    errdefer client.deinit();
    const alpn_offer = "\x02h2\x08http/1.1";
    try testing.expectEqual(
        @as(c_int, 0),
        openssl.SSL_set_alpn_protos(client.ssl, alpn_offer, alpn_offer.len),
    );
    try handshake_in_memory(&client, &server);
    try testing.expectEqualStrings("h2", server.alpn_selected().?);
    return .{ .server = server, .client = client };
}

test "h2_proxy: terminates h2 over TLS end to end" {
    const gpa = testing.allocator;
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();

    var harness: TlsHarness = undefined;
    try harness.init(gpa, origin_listener.bound_address().port);
    defer harness.deinit(gpa);

    var origin = TestOrigin{
        .io = &harness.io,
        .listener = origin_listener,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO",
    };
    origin.start();

    const channels = try tls_h2_channels(&harness);
    const pair = try socket_pair();
    harness.adopt(pair[1], channels.server, "");

    var client = TlsH2Client{ .io = &harness.io, .fd = pair[0], .channel = channels.client };
    defer client.channel.deinit();
    client.stage(h2_frame.client_preface);
    var settings: [64]u8 = undefined;
    client.stage(settings[0..h2_frame.write_settings(&.{}, &settings)]);
    stage_tls_request(&client, "/hello");
    client.go();

    try harness.io.run_until_done(&client.frames.done);
    try testing.expect(!client.frames.reset);
    try testing.expectEqual(@as(u16, 200), client.frames.status);
    try testing.expectEqualStrings("HELLO", client.frames.body[0..client.frames.body_len]);
    try testing.expect(std.mem.startsWith(
        u8,
        origin.request_buf[0..origin.request_len],
        "GET /hello HTTP/1.1\r\n",
    ));

    _ = linux.close(pair[0]);
    try harness.settle();
    try testing.expect(harness.resilience.is_idle());
}

test "h2_proxy: h2 over TLS with a preface coalesced into the handshake flight" {
    const gpa = testing.allocator;
    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();

    var harness: TlsHarness = undefined;
    try harness.init(gpa, origin_listener.bound_address().port);
    defer harness.deinit(gpa);

    var origin = TestOrigin{
        .io = &harness.io,
        .listener = origin_listener,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
    };
    origin.start();

    var channels = try tls_h2_channels(&harness);
    // The client encrypts its whole opening flight *before* the transport
    // exists — the coalesced-preface case that defeats a kTLS switch. Those
    // ciphertext bytes are handed to the H2Conn as `staged`, exactly as the
    // H1 handshaker would have read them past the handshake.
    var opening: [512]u8 = undefined;
    var opening_len: usize = 0;
    @memcpy(opening[0..h2_frame.client_preface.len], h2_frame.client_preface);
    opening_len += h2_frame.client_preface.len;
    var settings: [64]u8 = undefined;
    const settings_len = h2_frame.write_settings(&.{}, &settings);
    @memcpy(opening[opening_len..][0..settings_len], settings[0..settings_len]);
    opening_len += settings_len;
    opening_len += encode_tls_request(opening[opening_len..], "/coalesced");
    try testing.expectEqual(
        terminator.Channel.WriteResult{ .bytes = opening_len },
        channels.client.write_plaintext(opening[0..opening_len]),
    );
    var staged: [constants.tls_bio_pair_bytes]u8 = undefined;
    const staged_len = channels.client.drain_ciphertext(&staged);
    try testing.expect(staged_len > 0);
    try testing.expectEqual(@as(usize, 0), channels.client.pending_ciphertext());

    const pair = try socket_pair();
    harness.adopt(pair[1], channels.server, staged[0..staged_len]);

    var client = TlsH2Client{ .io = &harness.io, .fd = pair[0], .channel = channels.client };
    defer client.channel.deinit();
    client.go(); // nothing to send: the request already rode the staged bytes

    try harness.io.run_until_done(&client.frames.done);
    try testing.expect(!client.frames.reset);
    try testing.expectEqual(@as(u16, 200), client.frames.status);
    try testing.expectEqualStrings("hi", client.frames.body[0..client.frames.body_len]);
    try testing.expect(std.mem.startsWith(
        u8,
        origin.request_buf[0..origin.request_len],
        "GET /coalesced HTTP/1.1\r\n",
    ));

    _ = linux.close(pair[0]);
    try harness.settle();
    try testing.expect(harness.resilience.is_idle());
}

fn stage_tls_request(client: *TlsH2Client, path: []const u8) void {
    var frame: [256]u8 = undefined;
    client.stage(frame[0..encode_tls_request(&frame, path)]);
}

/// Encode a HEADERS frame (GET, END_STREAM|END_HEADERS) for `path`.
fn encode_tls_request(out: []u8, path: []const u8) usize {
    var block: [128]u8 = undefined;
    var block_len: usize = 0;
    block_len += hpack.encode_header(":method", "GET", block[block_len..]) catch unreachable;
    block_len += hpack.encode_header(":scheme", "https", block[block_len..]) catch unreachable;
    block_len += hpack.encode_header(":path", path, block[block_len..]) catch unreachable;
    block_len += hpack.encode_header(":authority", "origin", block[block_len..]) catch unreachable;
    h2_frame.write_frame_header(.{
        .length = @intCast(block_len),
        .type = .headers,
        .flags = h2_frame.Flags.end_headers | h2_frame.Flags.end_stream,
        .stream_id = 1,
    }, out[0..h2_frame.frame_header_bytes]);
    @memcpy(out[h2_frame.frame_header_bytes..][0..block_len], block[0..block_len]);
    return h2_frame.frame_header_bytes + block_len;
}

test "h2_proxy: the H2 serving path allocates nothing after startup (zero-alloc gate)" {
    var counting = guard.CountingAllocator{ .backing = testing.allocator };
    const gpa = counting.allocator();

    var origin_listener = try Listener.open(Ip4Address.loopback(0), 8);
    defer origin_listener.close();

    var harness: TestHarness = undefined;
    try harness.init(gpa, origin_listener.bound_address().port);
    defer harness.deinit(gpa);

    var origin = TestOrigin{
        .io = &harness.io,
        .listener = origin_listener,
        .response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO",
    };
    origin.start();

    const fd = try connect_loopback(harness.listener.bound_address().port);
    defer _ = linux.close(fd);
    var client = H2TestClient{ .io = &harness.io, .fd = fd };
    client.stage(h2_frame.client_preface);
    var settings: [64]u8 = undefined;
    client.stage(settings[0..h2_frame.write_settings(&.{}, &settings)]);
    client.stage_request("/", true);

    // Snapshot after every startup allocation (config, pools) is done.
    const baseline = counting.allocation_count();
    client.go();
    try harness.io.run_until_done(&client.done);
    try testing.expectEqual(@as(u16, 200), client.status);
    try testing.expectEqualStrings("HELLO", client.body[0..client.body_len]);

    // accept -> preface -> HPACK -> route -> dial -> translate -> relay:
    // none of it may touch the allocator.
    try testing.expectEqual(baseline, counting.allocation_count());
}
