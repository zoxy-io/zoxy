//! The connection slot (DESIGN.md §5): one contiguous object per
//! connection — state machine, embedded completions (one per
//! overlappable op, including both cancels), the stored absolute
//! deadline, and the armed-op set that gates release. A slot returns to
//! the pool only when `armed` is empty; every completion delivery
//! asserts the slot generation recorded at submit, so a straggler into
//! a recycled slot trips an assertion instead of corrupting memory.

const std = @import("std");

const access_log = @import("../access_log.zig");
const config_module = @import("../config.zig");
const constants = @import("../constants.zig");
const parser = @import("../http/parser.zig");
const router = @import("../http/router.zig");
const filter = @import("../http/filter.zig");
const relay = @import("relay.zig");
const TlsEngine = @import("../tls/Engine.zig");
const upstream_module = @import("upstream.zig");

const assert = std.debug.assert;

/// Strict recv → send → recv per direction (§6): exactly one data op in
/// flight per direction, phase says which; per-connection memory stays
/// constant regardless of stream size. Nothing here depends on the Io
/// backend, so it lives at file scope rather than being re-instantiated
/// per `Conn(IoType)` — which is also what makes it unit-testable.
///
/// The two counts are one debt, kept in the units *framing* works in:
/// `framed_len` is what framing assigned to this message out of the last
/// recv, and `credited_len` is how much of that the target has accepted —
/// a short send resumes from there. Today every send writes those same
/// bytes, so the debt is settled in the units it was incurred and
/// `pending` can slice one buffer with both cursors.
///
/// A *transforming* direction breaks that symmetry, and §4's TLS
/// termination is the one coming: the wire would carry ciphertext, which is
/// neither the same bytes nor the same count, so it has to keep its own
/// wire cursor and credit this debt only once a whole framed chunk is out.
/// Naming the debt apart from the wire is what keeps that a change to
/// `credit` and `pending` rather than a change at every call site — and
/// until then, that the two are the same bytes is what `pending` asserts.
pub const DirectionState = struct {
    phase: Phase = .idle,
    /// Bytes framing assigned to this message from the last recv.
    framed_len: u32 = 0,
    /// How many of those the target has accepted.
    credited_len: u32 = 0,

    pub const Phase = enum(u8) { idle, receiving, sending, finished };

    /// Framing chose `len` bytes of what the last recv delivered: a fresh
    /// debt, nothing credited yet. Zero is legal — framing may end a
    /// message without forwarding a byte.
    ///
    /// The previous debt must be settled first. That is the strict
    /// recv → send → recv discipline (§6) stated as a precondition rather
    /// than left to the call sites: overwriting an unsettled debt is
    /// precisely how a direction would forget bytes it still owed the
    /// target, and losing them silently is the failure mode this vocabulary
    /// exists to make loud.
    pub fn owe(state: *DirectionState, len: u32) void {
        assert(state.owed() == 0);
        state.framed_len = len;
        state.credited_len = 0;
    }

    /// Grow the debt from the *front* (#142 send): `len` new bytes now
    /// sit ahead of everything framed, nothing credited yet. Legal only
    /// before the first credit — prepending to a partially-sent window
    /// would resend bytes already gone — which in practice means at the
    /// pre-relay staging sites, where the caller has just moved the
    /// framed bytes over and written the new ones in front.
    pub fn stageFront(state: *DirectionState, len: u32) void {
        assert(len >= 1);
        assert(state.credited_len == 0);
        state.framed_len += len;
        assert(state.owed() == state.framed_len);
    }

    /// The target accepted `len` more of the debt.
    pub fn credit(state: *DirectionState, len: u32) void {
        assert(len >= 1);
        state.credited_len += len;
        assert(state.credited_len <= state.framed_len);
    }

    /// What the target has not accepted yet.
    pub fn owed(state: *const DirectionState) u32 {
        assert(state.credited_len <= state.framed_len);
        return state.framed_len - state.credited_len;
    }

    /// The window of `buffer` still owed: what a send arms, and what a
    /// short send resumes from. `buffer` starts where this direction's
    /// framed bytes start — the relay buffer on a body leg, past the head
    /// on an excess leg (§7).
    pub fn pending(state: *const DirectionState, buffer: []const u8) []const u8 {
        assert(state.owed() >= 1);
        assert(state.framed_len <= buffer.len);
        return buffer[state.credited_len..state.framed_len];
    }
};

/// One client-directed write in flight (§7, §8): the plaintext still to
/// deliver, and where control goes once it is all out.
///
/// Three writes on the L7 path go to the client outside the body pump — the
/// rendered response head, the body excess that arrived coalesced with it,
/// and a static error response — and they differ only in which bytes they
/// carry and what happens next. One channel for all three means one cursor,
/// one short-write resume, one teardown interlock, and (§4) one place for a
/// transforming client side to turn plaintext into wire bytes. The body pump
/// is the fourth client-directed writer and carries that same seam of its
/// own (`pump.zig`).
pub const ClientWrite = struct {
    /// Shrunk from the front as bytes leave, so a resume is the same code
    /// whether they live in static memory (§8), the head buffer, or an
    /// upstream head. Empty means no write is in flight.
    pending: []const u8 = &.{},
    then: Then = .lingering_close,
    /// How much of `pending`'s front the engine has already encrypted
    /// into its outbox (§4), zero on a plaintext connection. The cursor
    /// above counts plaintext, because that is what the writers framed and
    /// what the access log means by `bytes_out`; the wire carries more.
    /// So `pending` advances only when the chunk that produced the
    /// ciphertext has fully gone out — never per byte the socket took.
    staged: u32 = 0,

    /// What the channel does when `pending` empties.
    pub const Then = enum(u8) {
        /// The rendered response head is out: forward any coalesced body
        /// excess, else move on to the body pump.
        response_excess,
        /// The coalesced excess is out: the body pump, or the exchange ends.
        response_body,
        /// A static response is out: the lingering close (§7, §8).
        lingering_close,
        /// A static response is out and the client's byte stream is still
        /// synchronized: serve the next request on this connection (§7,
        /// §8). The keep half of the ladder's "then keep or close per
        /// pressure" — see `proxy.staticResponseResyncable` for what
        /// earns it.
        next_request,
        /// A #176 redirect is out. The two arms mirror the static pair
        /// above with one extra obligation: the redirect rendered into
        /// the connection's head buffer and *held* it through the send
        /// — a static answer returns it before arming — so the buffer
        /// goes back to the ring here, before the continuation whose
        /// asserts require it gone.
        redirect_next_request,
        redirect_lingering_close,
    };
};

/// What an access-log line needs that is not still on the connection when
/// the line is written (DESIGN.md §8). The head buffer is the reason this
/// exists: it holds the request head only until the response head renders
/// over it (§7 buffer rotation), so a line emitted at settle time would
/// find the method, host and path it is supposed to report already gone.
/// Each is therefore copied out — bounded, truncation marked — while it is
/// still there.
///
/// One instance per connection, covering one *request* on the L7 path
/// (`reset` runs at every keep-alive turnaround) and the whole connection
/// on the L4 path, which has no smaller unit. The arrays are deliberately
/// not cleared by `reset`: the lengths beside them gate every read, so
/// clearing 500-odd bytes per request would be work for an invariant that
/// already holds — the same argument `Conn.head` makes.
pub const LogState = struct {
    /// Wall-clock nanoseconds at which this request — or, on L4, this
    /// connection — began. Zero means nothing is in flight, which is what
    /// keeps an idle keep-alive connection reaped by its deadline from
    /// emitting a line about a request nobody made; it is also why nothing
    /// sets it while the log is off, so a disabled log reads no clock.
    ///
    /// Wall-clock rather than the monotonic deadline clock because a line
    /// needs both a date and a duration, and one precise read at each end
    /// answers both — where `Io.now_ns` is coarse and cached per tick (§4),
    /// which would report 0 µs for every request served inside one batch.
    started_wall_ns: u64 = 0,
    /// Bytes read from the client and written to it, for this request.
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,
    /// The endpoint the balancer picked (§7), or `endpoint_none` before
    /// one was — every reject that fires ahead of routing.
    endpoint_index: u16 = endpoint_none,
    /// The status this request was answered with; 0 until one is decided.
    status: u16 = 0,
    outcome: access_log.Outcome = .aborted,
    /// Set once this request's line has been written, so the teardown
    /// fallback cannot emit a second one for an exchange that already
    /// reported its own outcome.
    emitted: bool = false,
    method_len: u8 = 0,
    host_len: u16 = 0,
    path_len: u16 = 0,
    method: [constants.access_log_method_bytes_max]u8 = undefined,
    host: [constants.host_bytes_max]u8 = undefined,
    path: [constants.access_log_path_bytes_max]u8 = undefined,

    /// No endpoint has been picked. `maxInt` rather than a separate flag:
    /// the loader rejects a cluster declaring more than `maxInt(u16)`
    /// endpoints (`EndpointsOverLimit`), so a real index stops at
    /// `maxInt(u16) - 1` and the sentinel can never collide with one.
    /// That bound used to be `endpoints_per_cluster_max`; with the policy
    /// ceiling gone, the index type is what is left holding it up.
    pub const endpoint_none: u16 = std.math.maxInt(u16);

    comptime {
        // A relationship, not a restatement: the loader bounds real
        // indices by `endpoint_index_max`, and this is what makes that
        // bound the right one. Widening either past the other is a
        // compile error rather than a sentinel that means two things.
        assert(constants.endpoint_index_max < endpoint_none);
    }

    /// Start a fresh request's accounting. Only the scalars: the three
    /// captures are read through their lengths, which this zeroes.
    pub fn reset(state: *LogState) void {
        state.started_wall_ns = 0;
        state.bytes_in = 0;
        state.bytes_out = 0;
        state.endpoint_index = endpoint_none;
        state.status = 0;
        state.outcome = .aborted;
        state.emitted = false;
        state.method_len = 0;
        state.host_len = 0;
        state.path_len = 0;
    }

    pub fn methodSlice(state: *const LogState) []const u8 {
        return state.method[0..state.method_len];
    }

    pub fn hostSlice(state: *const LogState) []const u8 {
        return state.host[0..state.host_len];
    }

    pub fn pathSlice(state: *const LogState) []const u8 {
        return state.path[0..state.path_len];
    }

    pub fn captureMethod(state: *LogState, token: []const u8) void {
        state.method_len = @intCast(access_log.captureTruncated(&state.method, token).len);
    }

    pub fn captureHost(state: *LogState, host: []const u8) void {
        state.host_len = @intCast(access_log.captureTruncated(&state.host, host).len);
    }

    pub fn capturePath(state: *LogState, path: []const u8) void {
        state.path_len = @intCast(access_log.captureTruncated(&state.path, path).len);
    }
};

pub fn Conn(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);
    const UpstreamType = upstream_module.UpstreamPool(IoType).Upstream;

    return struct {
        pool_next: u32,
        generation: u32,
        server: *ServerType,
        state: State,
        client_socket: IoType.Socket,
        /// Null until the upstream dial completes; making the socket and
        /// its presence one field means an unset upstream can never be
        /// read as a live fd handle.
        upstream_socket: ?IoType.Socket,
        /// Held for the L4 connection's life; on the L7 path it is null
        /// until a body relay starts and again once the connection goes
        /// idle on keep-alive — an idle L7 connection costs a slot and
        /// head buffer only (§5).
        relay_buffer: ?*relay.RelayBuffer,
        /// Absolute deadline; state transitions only store a new value —
        /// the armed timer op is never touched (§4).
        deadline_ns: u64,
        /// Admission timestamp. The max-lifetime cap is `birth_ns +
        /// max_lifetime_ms`; `storeDeadline` clamps every deadline to it so
        /// an always-active connection is still reaped (§6).
        birth_ns: u64,
        armed: Armed,
        directions: [2]DirectionState,
        /// The §5 head-ring buffer this connection holds, or
        /// `head_buffer_none`. Bound by the seam at the delivery that
        /// starts a request (`recvGroup`) and returned at the keep-alive
        /// turnaround, before a static response goes out, or at teardown —
        /// so an idle connection holds no head bytes at all, and an L4
        /// connection never binds one. The bytes live in the ring's slab
        /// (`bufferGroupSlice`); everything the old inline array promised
        /// still holds of them: request/response head accumulates across
        /// recv retries, parsing is detect-and-retry from byte 0 (§7), the
        /// buffer's content stays the single source of truth while held,
        /// and nothing zeroes it — bytes past `head_len` are never read.
        head_buffer_id: u16,
        /// Bytes of the held head buffer filled so far; the head's end is
        /// found by parsing, the body (or a pipelined next head) follows
        /// it. A count, not content: it survives the buffer's return at a
        /// static response, because the §7 resync rule still reads it to
        /// decide keep-or-close; `beginNextRequest` zeroes it. The
        /// `l4_reading_proxy_header` phase (#142) counts the same way
        /// over its own staging — the relay buffer's client→upstream
        /// half — and zeroes it at hand-over, so the relay starts clean
        /// and the L7 meaning is never mixed with the L4 one.
        head_len: u32,
        /// This connection's TLS session (§4), or null on a plaintext
        /// listener — which is every connection on a deployment without a
        /// `tls` block, and what makes the whole feature cost nothing
        /// there. Drawn from the §5 engine pool at admission and returned
        /// at teardown: unlike a relay buffer it is never handed back
        /// mid-connection, because it holds the session's keys and a
        /// terminated connection needs them until it is gone.
        ///
        /// Its presence is what every transforming path branches on, so
        /// it is the connection's answer to "are my wire bytes my
        /// plaintext bytes".
        tls: ?*TlsEngine,
        /// Plaintext the handshake's last flight carried in with it,
        /// waiting in `tls.?.plaintext` for the protocol that is about to
        /// start. Common rather than exotic: a client that writes its
        /// request immediately after its Finished lands both in one
        /// segment, and a protocol that only ever armed a fresh read
        /// would wait for bytes already in hand.
        tls_pending_len: u32,
        /// Whether this session's handshake has completed (§4) — the
        /// client's Finished processed and the session usable.
        ///
        /// Set once, and it has to be a latch rather than a question
        /// asked of the engine, for two reasons. The pump reaches
        /// "connected with an empty outbox" a second time once the
        /// post-handshake ticket flight has gone out, and without a latch
        /// it would issue a fresh pair every time and never hand over to
        /// the protocol. And it is what separates a handshake that failed
        /// from a session that came up and then lost its peer while those
        /// tickets were still going out — the same send error, two
        /// different things to count.
        tls_session_up: bool,
        /// The client-directed write in flight, if any (§7, §8) — see
        /// `ClientWrite`. Idle on the L4 path, which relays through the pump.
        client_write: ClientWrite,
        /// The cluster to dial. Seeded from the listener at admission; on
        /// the L7 path `routeRequest` overwrites it with the request
        /// path's cluster once the head parses (§7).
        cluster_index: u16,
        /// The listener's §7 route table, never empty — an l4 listener
        /// resolves to the one catch-all route it can never consult, since
        /// it has no path to match. Set once at admission and constant for
        /// the connection's life, so it survives keep-alive turnarounds.
        routes: []const router.Route,
        /// The listener's §7 request filter rules, same lifetime as
        /// `routes` (empty on L4 and when no request filters are
        /// configured).
        request_filters: []const filter.Rule,
        /// The listener's #175 response filter rules, same lifetime:
        /// matched against the origin's parsed response head at the
        /// re-render (empty on L4 and when none are configured).
        response_filters: []const filter.ResponseRule,
        /// The listener's §7 client-address forwarding mode, same lifetime
        /// as `routes`; null leaves `X-Forwarded-For` untouched.
        forwarded: ?config_module.Config.Listener.Forwarded,
        /// The leased upstream slot during an L7 exchange; released at
        /// teardown alongside the conn slot (§5). Null outside exchanges
        /// and on the whole L4 path.
        upstream: ?*UpstreamType,
        /// The endpoint this L4 connection is charged against in the
        /// server's per-endpoint in-flight table (§7), or `endpoint_none`
        /// when it is charged against none — every L7 connection, and
        /// every L4 one shed before it dialed. Separate from
        /// `log.endpoint_index`, which the access log still needs after
        /// the charge is released; this one is the release's own
        /// bookkeeping, and clearing it is what makes the release
        /// exactly-once.
        charged_endpoint: u16,
        /// The cluster half of that key. `cluster_index` cannot serve:
        /// the L7 path overwrites it per request at routing, so a key
        /// built from it at teardown need not be the key charged.
        charged_cluster: u16,
        /// L7 exchange bookkeeping (§7); reset per exchange.
        l7: L7State,
        /// What this connection speaks (§6, §7). Read only by the access
        /// log, at teardown, to decide which kind of line a connection
        /// owes — an unanswered HTTP request, or the L4 connection itself.
        /// `startProtocol` used to argue that a stored protocol would be
        /// state with no reader; the log is that reader.
        protocol: config_module.Config.Listener.Protocol,
        /// Who connected, read once at admission through the seam (§8).
        /// Kept rather than asked for at log time: by then the socket may
        /// already be closed, and `getpeername` on a closed fd names
        /// whoever inherited the number.
        client_address: std.Io.net.IpAddress,
        /// Access-log capture (§8); per request on the L7 path, per
        /// connection on the L4 one.
        log: LogState,

        op_data_client_to_upstream: Op,
        op_data_upstream_to_client: Op,
        op_connect: Op,
        op_connect_cancel: Op,
        op_deadline: Op,
        op_deadline_cancel: Op,

        const Self = @This();

        /// "This connection holds no head-ring buffer." Out of range by
        /// construction: a group never publishes more than
        /// `buffer_group_entries_max` ids, and the comptime check below
        /// keeps the sentinel above every real one.
        pub const head_buffer_none: u16 = std.math.maxInt(u16);

        comptime {
            assert(constants.buffer_group_entries_max <= head_buffer_none);
        }

        pub const State = enum(u8) {
            // L4 relay states.
            /// Reading the PROXY protocol header a `proxy_protocol`
            /// listener requires (#142), staged in the relay buffer's
            /// client→upstream half and accumulated in `head_len`.
            /// Runs *before* `.connecting`, necessarily: the dial
            /// consumes `client_address` (the hash pick, §7), and the
            /// header is what makes that address the real client's.
            l4_reading_proxy_header,
            /// Running the TLS handshake a terminating listener requires
            /// (§4, #125). Like the PROXY header phase it runs *before*
            /// the protocol rather than inside it — termination is
            /// orthogonal to whether the terminated stream is then relayed
            /// or proxied — so `startProtocol` is what it hands over to.
            /// Ordered after the PROXY header, which travels in the clear
            /// outside the TLS session by the spec's own rule.
            tls_handshaking,
            connecting,
            relaying,
            // L7 states (§7): `l7_reading_head` accumulates and re-parses
            // the request head (detect-and-retry); `l7_dialing` awaits the
            // upstream connect; `l7_exchanging` runs the two legs (request
            // out, response back — each with its own sub-state in `l7`);
            // `l7_responding` writes a static error response (§8); and
            // `l7_draining_request` half-closes the write side after a
            // response and drains the client's remaining input so the
            // close does not RST away that response (§7 lingering close).
            l7_reading_head,
            l7_dialing,
            l7_exchanging,
            l7_responding,
            l7_draining_request,
            /// Teardown begun: sockets shut down, pending ops draining.
            /// The delivery that empties the armed set closes both fds
            /// synchronously and releases the slot (§5) — there is no
            /// second phase, because with nothing armed nothing can
            /// straggle into the closes.
            tearing_down,
        };

        /// True once teardown has begun.
        pub fn isTearingDown(conn: *const Self) bool {
            return conn.state == .tearing_down;
        }

        /// True in any pre-teardown serving state — the states from which
        /// `beginTeardown` is a legal transition.
        pub fn isLive(conn: *const Self) bool {
            return switch (conn.state) {
                .l4_reading_proxy_header,
                .tls_handshaking,
                .connecting,
                .relaying,
                .l7_reading_head,
                .l7_dialing,
                .l7_exchanging,
                .l7_responding,
                .l7_draining_request,
                => true,
                .tearing_down => false,
            };
        }

        /// How a message body is delimited and how much of it remains —
        /// the §7 framing verdicts turned into countdown state the pumps
        /// consume chunk by chunk.
        pub const Framing = union(enum) {
            none,
            /// Body bytes still to relay.
            content_length: u64,
            /// The scanner owns the end-of-message detection.
            chunked: parser.ChunkedScanner,
            /// Responses only: the body runs to the origin's EOF.
            until_close,
        };

        /// Per-leg progress of an L7 exchange (§7). The request leg sends
        /// the rendered head, then pumps the framed body client → origin;
        /// the response leg starts as soon as the request head is on the
        /// wire (early responses are legal, §7) and mirrors it back.
        pub const L7State = struct {
            request_leg: Leg = .idle,
            response_leg: Leg = .idle,
            request_method: parser.Method = .get,
            request_framing: Framing = .none,
            response_framing: Framing = .none,
            /// Bytes of `head` consumed by the request head; body excess
            /// received with it sits at [request_head_len..head_len].
            request_head_len: u32 = 0,
            /// Bytes of `upstream.head` consumed by the response head;
            /// body excess received with it sits at [marker..head_len].
            response_head_len_marker: u32 = 0,
            /// Length of the rendered request head being sent into
            /// upstream.head, and the cursor over it (short sends resume).
            /// The response head has no pair here: it goes out through the
            /// client-write channel, which owns its own cursor
            /// (`ClientWrite`).
            rendered_request_len: u32 = 0,
            request_head_sent: u32 = 0,
            /// Response body bytes that arrived coalesced with the response
            /// head and did not fit in `conn.head` beside the rendered head:
            /// they follow it from `upstream.head[response_head_len_marker..]`
            /// as the channel's next write. Zero when the excess rode along
            /// with the head, or when there was none.
            response_excess_len: u32 = 0,
            /// Absolute cap on this exchange, set at routing from
            /// `request_timeout_ms` (§8); `storeDeadline` clamps every
            /// deadline to it, so unlike the idle timeout no activity can
            /// push it out. `0` when the timeout is disabled. It lives in
            /// `l7` rather than beside `birth_ns` precisely so the
            /// per-request lifetime is structural: every keep-alive
            /// turnaround clears `l7` wholesale, so the cap cannot outlive
            /// the exchange that set it even if a rung forgets to retire
            /// it. Rungs that answer early *do* retire it explicitly, via
            /// `Server.clearRequestDeadline`. The §7 replay is the one
            /// place `l7` is rebuilt mid-exchange, so it carries this field
            /// across by hand — a replay is the same request retrying, not
            /// a new one earning a fresh budget.
            request_deadline_ns: u64 = 0,
            /// The endpoint identity this request's stickiness cookie
            /// named (#178), or null when the cluster is not
            /// cookie-keyed or the request carried nothing usable.
            /// Recorded at routing — the head bytes are gone by the
            /// response render (§7 buffer rotation), and the render is
            /// exactly who asks: it compares this against the endpoint
            /// that actually served, and stamps a Set-Cookie on any
            /// mismatch. The replay rebuild re-derives it from its
            /// re-parse, like the framing.
            sticky_cookie: ?u64 = null,
            /// True once the request head has been forwarded off conn.head
            /// (head sent and any coalesced body excess drained), so the
            /// response head may render into conn.head (§7 buffer rotation).
            request_head_vacated: bool = false,
            /// The origin's head parsed while conn.head was still occupied;
            /// render it once `request_head_vacated`.
            response_render_pending: bool = false,
            /// True once any response byte reached the client — the §8
            /// verdict split between answering 502 and plain teardown.
            response_started: bool = false,
            /// A verdict decided while data ops were still armed, acted on
            /// when the last one settles: ops are never canceled (§5), they
            /// are *forced* — the upstream socket is shut down and each
            /// armed op completes with an error its handler diverts on.
            pending_verdict: PendingVerdict = .none,
            /// The armed request-leg op is a recv on the CLIENT socket
            /// (the body pump). Such an op cannot be forced without closing
            /// the client the verdict would answer, so expiry stays a
            /// teardown then — the stall is the client's own body (§8).
            request_op_on_client: bool = false,
            /// The client's persistence ask (RFC 9112 §9), captured at
            /// routing; the render-time decision may still announce close
            /// (pressure, drain, §8).
            client_keep_alive: bool = false,
            /// What the rendered response told the client. The connection
            /// honors its own announcement: a keep-alive answer keeps
            /// serving, an announced close closes (§7).
            downstream_close_announced: bool = true,
            /// The origin's persistence verdict from its response head;
            /// parking requires it (§5).
            upstream_reusable: bool = false,
            /// The client sent bytes past the request's framing — a
            /// pipelined next request. Pipelining is unsupported: the
            /// exchange completes and the connection closes, dropping the
            /// early bytes (§7 note; clients recover per RFC).
            client_pipelined: bool = false,
            /// This try runs over a checked-out parked connection (§5) —
            /// the precondition for the §7 stale replay: only a *reused*
            /// connection's early failure is blamed on staleness.
            upstream_was_reused: bool = false,
            /// The request leg entered the body pump: relay-buffer chunks
            /// flowed and were overwritten, so the try is no longer
            /// reconstructible from conn.head — replay is off the table.
            request_body_pumped: bool = false,
            /// The one free replay is spent (§7): a failure on the replay
            /// try answers 502 like any other, never a second replay.
            replay_used: bool = false,

            pub const Leg = enum(u8) {
                idle,
                sending_head,
                awaiting_head,
                /// Forwarding body bytes that arrived coalesced with the
                /// head, sent straight from the head buffer (§7) so a body
                /// larger than a relay buffer is never copied through one.
                sending_body_excess,
                pumping_body,
                done,
            };

            /// The deferred verdicts: the §8 request-deadline 504 and the
            /// §7 stale-replay retry, both settled once the last armed
            /// data op is forced to completion.
            pub const PendingVerdict = enum(u8) {
                none,
                gateway_timeout,
                replay,
            };
        };

        pub const Direction = enum(u1) {
            client_to_upstream,
            upstream_to_client,
        };

        /// One bit per embedded op; release requires all clear (§5).
        /// Closes carry no bit: they are synchronous syscalls once this
        /// set is empty, never ring ops (`Server.continueTeardown`).
        pub const Armed = packed struct(u6) {
            data_client_to_upstream: bool = false,
            data_upstream_to_client: bool = false,
            connect: bool = false,
            connect_cancel: bool = false,
            deadline: bool = false,
            deadline_cancel: bool = false,
        };

        pub const Op = struct {
            completion: IoType.Completion = .{},
            generation_at_submit: u32 = 0,
        };

        /// Admission-time reset. `pool_next` and `generation` are owned
        /// by the pool and deliberately untouched. `buffer` is the L4
        /// relay buffer, or null on the L7 path (§5); `state` is the
        /// protocol's entry state (`.connecting` for L4, `.l7_reading_head`
        /// for L7).
        pub fn prepare(
            conn: *Self,
            server: *ServerType,
            client_socket: IoType.Socket,
            buffer: ?*relay.RelayBuffer,
            engine: ?*TlsEngine,
            state: State,
            cluster_index: u16,
            protocol: config_module.Config.Listener.Protocol,
            client_address: std.Io.net.IpAddress,
        ) void {
            assert(state == .connecting or state == .l7_reading_head);
            conn.server = server;
            conn.state = state;
            conn.client_socket = client_socket;
            conn.upstream_socket = null;
            conn.relay_buffer = buffer;
            conn.deadline_ns = 0;
            conn.birth_ns = server.io.nowNs();
            conn.armed = .{};
            conn.directions = .{ .{}, .{} };
            conn.head_buffer_id = head_buffer_none;
            conn.head_len = 0;
            // A parameter, not a field the caller installs afterwards: a
            // slot is recycled across listeners, so a caller that acquired
            // an engine and then let this reset it would leak one per
            // connection.
            conn.tls = engine;
            conn.tls_pending_len = 0;
            conn.tls_session_up = false;
            conn.client_write = .{};
            conn.cluster_index = cluster_index;
            // Placeholders until the admission tail installs the
            // listener's real tables (§7); L4 never reads them.
            conn.routes = &.{};
            conn.request_filters = &.{};
            conn.response_filters = &.{};
            conn.forwarded = null;
            conn.upstream = null;
            conn.charged_endpoint = LogState.endpoint_none;
            conn.charged_cluster = 0;
            conn.l7 = .{};
            conn.protocol = protocol;
            conn.client_address = client_address;
            // The field defaults are `reset`'s values; a recycled slot
            // needs both the scalars and the (unread) capture arrays, and
            // this sets them in one write.
            conn.log = .{};
            // An L4 connection is its own log unit and starts here; an L7
            // one starts a request only when its first head byte lands, so
            // an idle keep-alive connection that is reaped without ever
            // being asked anything owes no line. Both are gated on the log
            // being on, so a deployment without one reads no clock here.
            if (protocol == .l4 and server.access_log.sink != null) {
                conn.log.started_wall_ns = server.io.nowWallNs();
            }
            conn.op_data_client_to_upstream = .{};
            conn.op_data_upstream_to_client = .{};
            conn.op_connect = .{};
            conn.op_connect_cancel = .{};
            conn.op_deadline = .{};
            conn.op_deadline_cancel = .{};
            assert(conn.state == state);
            assert(conn.armedCount() == 0);
            assert(conn.head_len == 0);
            assert(conn.client_write.pending.len == 0);
            assert(conn.upstream == null);
            assert(conn.l7.request_leg == .idle);
            assert(!conn.log.emitted);
            assert(conn.log.bytes_in == 0);
        }

        /// Records the arm in the op and the armed set; call immediately
        /// before submitting through the seam. Enforces the §8
        /// per-connection ring-op budget at the arm site — the CQ is
        /// sized as `conn_ops_max` per slot, so exceeding it here is the
        /// invariant violation the ring budget makes unreachable.
        pub fn arm(conn: *Self, op: *Op, comptime bit: []const u8) void {
            assert(!@field(conn.armed, bit));
            op.generation_at_submit = conn.generation;
            @field(conn.armed, bit) = true;
            assert(conn.armedCount() <= constants.conn_ops_max);
            // Test-only *reader*, not test-only *cost*: tracked wherever
            // the budget assert above is live (Debug, ReleaseSafe) — the
            // shipped build is ReleaseSafe, so this compare-and-max runs
            // in production now, same cost class as the assert next to
            // it; only the counter's only reader is a test.
            if (std.debug.runtime_safety) {
                conn.server.armed_ops_peak =
                    @max(conn.server.armed_ops_peak, conn.armedCount());
            }
        }

        /// Every delivery passes through here first: the generation
        /// recorded at submit must still match, and the bit must be set —
        /// a straggler into a recycled slot fails loudly (§5).
        pub fn delivered(conn: *Self, op: *const Op, comptime bit: []const u8) void {
            assert(op.generation_at_submit == conn.generation);
            assert(@field(conn.armed, bit));
            @field(conn.armed, bit) = false;
        }

        pub fn armedCount(conn: *const Self) u8 {
            return @popCount(@as(u6, @bitCast(conn.armed)));
        }
    };
}

test "direction: a framed chunk is owed until credited, then settled" {
    var state: DirectionState = .{};
    const buffer = "0123456789";

    state.owe(6);
    try std.testing.expectEqual(@as(u32, 6), state.owed());
    try std.testing.expectEqualStrings("012345", state.pending(buffer));

    // A short send: what is left is the tail, resumed from the credit.
    state.credit(2);
    try std.testing.expectEqual(@as(u32, 4), state.owed());
    try std.testing.expectEqualStrings("2345", state.pending(buffer));

    state.credit(4);
    try std.testing.expectEqual(@as(u32, 0), state.owed());
}

test "direction: a settled debt is the precondition for the next one" {
    var state: DirectionState = .{};
    state.owe(4);
    state.credit(4);
    try std.testing.expectEqual(@as(u32, 0), state.owed());

    // Only now may the next chunk be owed, and it starts from zero rather
    // than from where the last one ended — every framed chunk is its own
    // debt over the same buffer. `owe` asserts that settlement, so the
    // recv → send → recv discipline (§6) cannot be skipped quietly.
    state.owe(3);
    try std.testing.expectEqual(@as(u32, 3), state.owed());
    try std.testing.expectEqualStrings("abc", state.pending("abcdef"));
}

test "direction: framing may end a message owing nothing" {
    var state: DirectionState = .{};
    state.owe(0);
    // Nothing to forward, so nothing arms a send — `pending` asserts a
    // non-empty debt precisely because a zero one must not reach a send
    // (the seam's `bytes.len >= 1` contract, §4).
    try std.testing.expectEqual(@as(u32, 0), state.owed());
}
