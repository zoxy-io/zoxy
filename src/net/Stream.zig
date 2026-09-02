//! The stream slot (DESIGN.md §5): one *exchange*, drawn from a pool of
//! its own rather than inlined into the connection slot that carries it.
//!
//! Today a connection **is** an exchange — one request at a time, its
//! state inlined into `Conn` — and this slice (#274) draws the seam
//! without yet moving anything through it. Every admitted connection
//! acquires exactly one stream and holds it for the connection's life, so
//! the two pools have equal capacity and equal occupancy and nothing
//! observable changes. What it buys is §5's release rule and its
//! generation discipline replicated one layer down, proven under the
//! existing sweep before #173 puts N streams on a connection and makes
//! them load-bearing: a straggling completion into a recycled *stream* is
//! the same bug as one into a recycled slot, and it has to fail the same
//! way.
//!
//! The 1:1 cap is also what holds the ring budget still. `conn_ops_max`
//! becomes a conn share plus a stream share whose sum at one stream per
//! connection is exactly what it was, so the CQ ceiling and the printed
//! fd form do not move — an equality sharp enough that a changed banner
//! means the split took something with it that it should not have.

const std = @import("std");

const access_log = @import("../access_log.zig");
const constants = @import("../constants.zig");
const parser = @import("../http/parser.zig");
const relay = @import("relay.zig");
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
        /// An interim `1xx` reached the client and the exchange is
        /// *not* over (#232): go back to reading the origin's next
        /// response head, which may already be buffered behind it.
        interim_sent,
        /// The origin's `101` is out and the client has it, so the HTTP
        /// conversation on this connection is over (#180): hand the
        /// connection to the relay. Deliberately *after* the head reaches
        /// the client rather than at the parse — a tunnel that started
        /// relaying before its handshake landed would interleave frame
        /// bytes with the head that announces them.
        tunnel_start,
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
    /// Monotonic nanoseconds at which this request — or, on L4, this
    /// connection — began: `Io.nowNs`, the per-tick clock (§4). Zero means
    /// nothing is in flight, which is what keeps an idle keep-alive
    /// connection reaped by its deadline from emitting a line about a
    /// request nobody made, and what `logExchange` and `observeExchange`
    /// both check before they measure anything.
    ///
    /// This is the stamp every *duration* is taken from — the §8 histogram
    /// (#299) and the access log alike. Monotonic, so an NTP step cannot
    /// land inside a measured interval, and per-tick, so it is free: the
    /// tick has already read the clock by the time any exchange asks. That
    /// it is shared across a completion batch is the one thing it gives up,
    /// and it is affordable here because both consumers measure an interval
    /// that *spans* ticks — an exchange with an upstream round trip in it
    /// cannot begin and end inside one batch. The set of sites that could
    /// answer in one tick is exactly the set that never reaches these two:
    /// `finishExchange` asserts an upstream, and a locally-answered reject
    /// or `respond` has none.
    ///
    /// Always set, unlike `started_wall_ns` — reading it costs no syscall,
    /// so there is nothing for a guard to save.
    started_ns: u64 = 0,
    /// Wall-clock nanoseconds at which the same moment fell on the
    /// operator's calendar — the *date* a log line prints, and nothing
    /// else. Set only when a sink is configured, so a deployment with the
    /// log off reads no wall clock; `logExchange` returns early in that
    /// case, which is what keeps "a line is being written" and "this is
    /// non-zero" the same condition.
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
        state.started_ns = 0;
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

/// `ConnType` is a parameter rather than an import, and that is load
/// bearing: `Conn` names this type for its own field, so importing back
/// would make the two generics mutually re-entrant — Zig memoizes an
/// instantiation only once it completes, so a cycle re-evaluates both
/// sides until the comptime branch quota gives out. `Conn` already
/// stands in one such cycle with `Server`; a third participant is what
/// makes it exponential. Passing the type in leaves exactly one
/// instantiation of each, and `Conn.StreamType` is the one name for it.
pub fn Stream(comptime IoType: type, comptime ConnType: type) type {
    const UpstreamType = upstream_module.UpstreamPool(IoType).Upstream;

    return struct {
        /// Pool bookkeeping (`mem/Pool.zig`): owned by the pool, and
        /// deliberately untouched by `prepare` — the same rule
        /// `Conn.prepare` states about its own pair, and what makes the
        /// generation a straggler can be caught by survive a reset.
        pool_next: u32,
        generation: u32,
        /// The connection this stream runs on. Installed at acquisition
        /// and constant for the stream's life: a stream never migrates
        /// between connections here, and does not under #173 either —
        /// RFC 9113 identifiers are scoped to one connection.
        ///
        /// A back-pointer rather than a lookup because it is what the
        /// completion handlers will read. The Io seam takes a typed
        /// userdata pointer, so an op moved onto a stream (slice 2)
        /// arrives as `*Stream` and reaches everything else through
        /// exactly this field.
        conn: *ConnType,
        /// The exchange's armed set (§5). The connection's own deadline
        /// pair stays on `Conn`: a deadline is the *connection's* clock,
        /// and it outlives any one exchange on it. Everything here is the
        /// exchange's — the dial, its cancel, and the two data legs — so
        /// this is the set that has to empty before the stream slot goes
        /// back, one level below the rule that governs the conn slot.
        armed: Armed,
        op_data_client_to_upstream: Op,
        op_data_upstream_to_client: Op,
        op_connect: Op,
        op_connect_cancel: Op,
        /// Held for the L4 connection's life; on the L7 path it is null
        /// until a body relay starts and again once the connection goes
        /// idle on keep-alive — an idle L7 connection costs a slot and
        /// head buffer only (§5).
        relay_buffer: ?*relay.RelayBuffer,
        /// Whether this connection's pending client write is reading the
        /// server's shared static response memory (#234) — the claim that
        /// holds the `Date` stamp off those bytes while a send may be
        /// reading them. False for every other write, including the #176
        /// redirect, which renders into this connection's own head buffer
        /// and so shares nothing.
        static_send: bool,
        directions: [2]DirectionState,
        /// The §5 head-ring buffer this connection holds, or
        /// `head_buffer_none`. Bound by the seam at the delivery that
        /// starts a request (`recvGroup`) and returned at the keep-alive
        /// turnaround, before a static response goes out, or at teardown —
        /// so an idle connection holds no head bytes at all, and an L4
        /// connection never binds one. The bytes live in the ring's slab
        /// (`bufferGroupSlice`); everything the old inline array promised
        /// still holds of them: request/response head accumulates across
        /// recv retries, parsing is detect-and-retry — carried forward by
        /// `head_cursor` rather than restarted at byte 0 (§7) — the
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
        /// Carries a partial head parse across recv retries, so a head that
        /// arrives in pieces is parsed once rather than re-parsed from byte 0
        /// on every arrival (§7). Zeroed wherever `head_len` is, because the
        /// two describe the same head; see `http.parser.HeadCursor` for why
        /// the quadratic version was a denial of service and not merely
        /// wasteful.
        head_cursor: parser.HeadCursor = .{},
        /// The client-directed write in flight, if any (§7, §8) — see
        /// `ClientWrite`. Idle on the L4 path, which relays through the pump.
        client_write: ClientWrite,
        /// Null until the upstream dial completes; making the socket and
        /// its presence one field means an unset upstream can never be
        /// read as a live fd handle.
        upstream_socket: ?IoType.Socket,
        /// The cluster to dial. Seeded from the listener at admission; on
        /// the L7 path `routeRequest` overwrites it with the request
        /// path's cluster once the head parses (§7).
        cluster_index: u16,
        /// The leased upstream slot during an L7 exchange; released at
        /// teardown alongside the conn slot (§5). Null outside exchanges
        /// and on the whole L4 path.
        upstream: ?*UpstreamType,
        /// L7 exchange bookkeeping (§7); reset per exchange.
        l7: L7State,

        /// Access-log capture (§8) — and the seam #274 exists to draw.
        ///
        /// One line covers one *request* on the L7 path and one whole
        /// *connection* on the L4 path, which has no smaller unit. That
        /// was already true when this lived on the conn slot, but it was
        /// true by convention: `reset` was called at each keep-alive
        /// turnaround, and a path that forgot would report the previous
        /// request's method on the next request's line (#129). Here the
        /// unit is structural — a line belongs to the exchange that owns
        /// this slot — and on the L4 path the exchange simply lasts as
        /// long as the connection does.
        log: LogState,

        const Self = @This();

        /// "This exchange holds no head-ring buffer." Out of range by
        /// construction: a group never publishes more than
        /// `buffer_group_entries_max` ids, and the comptime check below
        /// keeps the sentinel above every real one.
        pub const head_buffer_none: u16 = std.math.maxInt(u16);

        comptime {
            assert(constants.buffer_group_entries_max <= head_buffer_none);
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
            /// Whether this request's #235 head budget is already
            /// installed. Set on the first parse that comes back
            /// `Incomplete` — the moment a client is provably mid-sentence
            /// — and read so the *next* fragment does not install it
            /// again: a budget a dribbling client could push out by
            /// dribbling would bound nothing at all.
            ///
            /// In `l7` rather than on the connection because the budget is
            /// one head's, and the wholesale clear at every keep-alive
            /// turnaround is what makes the next request earn its own.
            ///
            /// Unlike `request_deadline_ns` above, the §7 replay does *not*
            /// carry this across its rebuild, and does not need to: a
            /// replay runs from `.l7_exchanging` and moves to
            /// `.l7_dialing`, so it never re-enters the `.l7_reading_head`
            /// state `installHeadBudget` asserts on. There is no second
            /// head to budget, so a flag reset to false is inert rather
            /// than a budget silently reissued.
            head_budget_installed: bool = false,
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
            /// This request asked for an upgrade the listener allows, and
            /// a tunnel buffer is held for it (#180). What makes `101`
            /// terminal rather than interim on the response path, and what
            /// tells the render to let the participating
            /// `Connection`/`Upgrade` pair travel.
            upgrade_requested: bool = false,
            /// Interim `1xx` responses this exchange has already relayed
            /// (#232). Per exchange, not per connection: the bound is
            /// about one origin answering one request, and a keep-alive
            /// turnaround clears `l7` wholesale, so it cannot leak into
            /// the next request even if a path forgets to reset it.
            interims_seen: u8 = 0,
            /// The endpoints this request dialed and had refused or found
            /// unreachable (#181), in the order it tried them — the
            /// exclusion set the next pick runs over. Sized for the first
            /// try plus every retry the largest configured budget allows,
            /// so it is a fixed field like everything else on this
            /// connection and never grows.
            tried: [constants.cluster_retries_max + 1]u16 = @splat(0),
            /// How many of `tried` are written. Every entry past it is
            /// stale from an earlier request on this connection and must
            /// not be read.
            tried_count: u16 = 0,
            /// Retries spent against the cluster's budget. Equal to
            /// `tried_count` between hops, since a retry records the
            /// endpoint that failed and spends a retry to leave it in the
            /// same step — and one *behind* it in the terminal state where
            /// the endpoint set ran out first, because that last failure
            /// is recorded and then answered rather than retried.
            retries_used: u16 = 0,

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
                /// The #235 head budget expired on a client mid-sentence,
                /// and it is owed a `408` (#247). The odd one out: the
                /// armed op it waits on is a recv on the **client**
                /// socket, so the force is a read-half shutdown rather
                /// than the upstream teardown the other two use — the
                /// connection has to survive writable to carry the
                /// answer.
                request_timeout,
            };
        };

        /// Which leg of the exchange, and the index into `directions`.
        pub const Direction = enum(u1) {
            client_to_upstream,
            upstream_to_client,
        };

        /// One bit per embedded op; the stream releases only with all
        /// clear, and its connection only once that has happened (§5).
        ///
        /// The peak is two, not four, and the disjointness is why: a dial
        /// and its cancel belong to `.connecting`/`.l7_dialing`, the data
        /// pair to `.relaying`/`.l7_exchanging`, and no state arms one
        /// kind while the other is outstanding. `constants.stream_ops_max`
        /// is that claim as a number, and `arm` below is where it fails if
        /// it is ever wrong.
        pub const Armed = packed struct(u4) {
            data_client_to_upstream: bool = false,
            data_upstream_to_client: bool = false,
            connect: bool = false,
            connect_cancel: bool = false,
        };

        /// The same shape `Conn.Op` has, and deliberately its own type:
        /// the generation recorded here is the *stream's*, so a straggler
        /// into a recycled stream trips `delivered` even when the
        /// connection under it was never recycled at all (§5).
        pub const Op = struct {
            completion: IoType.Completion = .{},
            generation_at_submit: u32 = 0,
        };

        /// Acquisition-time reset, mirroring `Conn.prepare`. The pool
        /// pair above stays untouched; everything the exchange carries
        /// gets its value here.
        ///
        /// The exchange starts holding no relay buffer. On the L7 path
        /// one is acquired only when a body relay starts and given back at
        /// the keep-alive turnaround (§5) — an idle L7 connection costs a
        /// slot and a head buffer, no more — and on the L4 path the
        /// admission tail installs the one it claimed.
        pub fn prepare(stream: *Self, conn: *ConnType) void {
            stream.conn = conn;
            stream.armed = .{};
            stream.op_data_client_to_upstream = .{};
            stream.op_data_upstream_to_client = .{};
            stream.op_connect = .{};
            stream.op_connect_cancel = .{};
            stream.relay_buffer = null;
            // The claim is the server's counter to release, and
            // `releaseConn` has already done so by the time a slot is
            // handed out again — this only states the invariant the reset
            // inherits.
            stream.static_send = false;
            stream.directions = .{ .{}, .{} };
            stream.head_buffer_id = head_buffer_none;
            stream.head_len = 0;
            stream.head_cursor.reset();
            stream.client_write = .{};
            stream.upstream_socket = null;
            stream.upstream = null;
            stream.l7 = .{};
            // The listener's, and so not known until the admission tail
            // resolves one (`finishAdmission`); on the L7 path `routeRequest`
            // overwrites it per request anyway (§7).
            stream.cluster_index = 0;
            // The field defaults are `reset`'s values; a recycled slot
            // needs both the scalars and the (unread) capture arrays, and
            // this sets them in one write. The clock stays at zero: an L4
            // exchange starts its line in the admission tail, once a
            // listener says it is one, and an L7 exchange only when its
            // first head byte lands.
            stream.log = .{};
            assert(stream.armedCount() == 0);
            assert(stream.relay_buffer == null);
            assert(stream.head_len == 0);
            assert(stream.client_write.pending.len == 0);
            assert(stream.upstream == null);
            assert(stream.l7.request_leg == .idle);
            assert(!stream.log.emitted);
            assert(stream.log.bytes_in == 0);
            assert(stream.log.started_ns == 0);
            assert(stream.log.started_wall_ns == 0);
        }

        /// Records the arm in the op and the armed set; call immediately
        /// before submitting through the seam. The mirror of `Conn.arm`,
        /// enforcing this half of the §8 ring budget at its own arm site:
        /// the CQ is sized as `conn_ops_max` per conn slot plus
        /// `stream_ops_max` per stream slot, so exceeding either here is
        /// the invariant violation the budget makes unreachable.
        pub fn arm(stream: *Self, op: *Op, comptime bit: []const u8) void {
            assert(!@field(stream.armed, bit));
            op.generation_at_submit = stream.generation;
            @field(stream.armed, bit) = true;
            assert(stream.armedCount() <= constants.stream_ops_max);
            // The combined per-connection peak, tracked at both arm sites
            // so it reads the same number it always did (§8): what the CQ
            // is charged for an admitted connection did not change when
            // the ops moved, and a peak that quietly grew would say the
            // split took something with it.
            if (std.debug.runtime_safety) {
                const server = stream.conn.server;
                server.armed_ops_peak = @max(
                    server.armed_ops_peak,
                    stream.conn.armedCount() + stream.armedCount(),
                );
                server.stream_armed_ops_peak =
                    @max(server.stream_armed_ops_peak, stream.armedCount());
            }
        }

        /// Every delivery passes through here first: the generation
        /// recorded at submit must still match, and the bit must be set —
        /// a straggler into a recycled stream fails loudly (§5).
        pub fn delivered(stream: *Self, op: *const Op, comptime bit: []const u8) void {
            assert(op.generation_at_submit == stream.generation);
            assert(@field(stream.armed, bit));
            @field(stream.armed, bit) = false;
        }

        pub fn armedCount(stream: *const Self) u8 {
            return @popCount(@as(u4, @bitCast(stream.armed)));
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
