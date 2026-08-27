//! The connection slot (DESIGN.md §5): one contiguous object per
//! connection — state machine, embedded completions (one per
//! overlappable op, including both cancels), the stored absolute
//! deadline, and the armed-op set that gates release. A slot returns to
//! the pool only when `armed` is empty; every completion delivery
//! asserts the slot generation recorded at submit, so a straggler into
//! a recycled slot trips an assertion instead of corrupting memory.

const std = @import("std");

const config_module = @import("../config.zig");
const constants = @import("../constants.zig");
const router = @import("../http/router.zig");
const sni_router = @import("sni_router.zig");
const filter = @import("../http/filter.zig");
const relay = @import("relay.zig");
const stream_module = @import("Stream.zig");
const TlsEngine = @import("../tls/Engine.zig");

const assert = std.debug.assert;

pub fn Conn(comptime IoType: type) type {
    const ServerType = @import("../Server.zig").Server(IoType);

    return struct {
        pool_next: u32,
        generation: u32,
        server: *ServerType,
        /// The §5 stream slot carrying this connection's exchange
        /// (#274). Exactly one for now, held for the connection's life,
        /// which is what keeps the ring budget where it was; #173 turns
        /// this into the set a multiplexed connection owns.
        ///
        /// Not optional: a connection without a stream could not run an
        /// exchange at all, and the 1:1 cap means the acquire past the
        /// conn slot's own rung can never fail — `admitStream` states
        /// that argument where it is made.
        stream: *StreamType,
        state: State,
        client_socket: IoType.Socket,
        /// The §5 tunnel buffer this connection has claimed (#180), held
        /// from the moment its upgrade request is admitted until the
        /// tunnel closes — or until the exchange fails before `101`, in
        /// which case the disposal paths give it back like any other
        /// resource.
        ///
        /// A field of its own rather than an early swap into
        /// `relay_buffer`, because the exchange carrying the handshake is
        /// still an ordinary L7 exchange that may need an ordinary relay
        /// buffer. The two coexist for exactly the window between the
        /// upgrade being admitted and the origin answering; at `101` the
        /// shared one goes back and this one takes its place.
        tunnel_buffer: ?*relay.RelayBuffer,
        /// Absolute deadline; state transitions only store a new value —
        /// the armed timer op is never touched (§4).
        deadline_ns: u64,
        /// Admission timestamp. The max-lifetime cap is `birth_ns +
        /// max_lifetime_ms`; `storeDeadline` clamps every deadline to it so
        /// an always-active connection is still reaped (§6).
        birth_ns: u64,
        armed: Armed,
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
        /// The listener's §7 route table, never empty — an l4 listener
        /// resolves to the one catch-all route it can never consult, since
        /// it has no path to match. Set once at admission and constant for
        /// the connection's life, so it survives keep-alive turnarounds.
        routes: []const router.Route,
        /// The listener's §6 SNI table (#298), borrowed like `routes` and
        /// empty on every connection whose listener does not route by
        /// name — which is what says the peek phase never runs.
        sni_routes: []const sni_router.Route,
        /// The listener's §7 request filter rules, same lifetime as
        /// `routes` (empty on L4 and when no request filters are
        /// configured).
        /// The listener's #180 upgrade allowlist, handed over at
        /// admission like the filter tables beside it, so the gate asks
        /// what *this* socket allows rather than consulting the config.
        upgrades: config_module.Config.Listener.Upgrades,
        /// The listener's #236 request-body cap, handed over at admission
        /// like the tables beside it; `0` accepts any size.
        max_body_bytes: u64,
        /// Requests this connection has served, for the #237 cap. On the
        /// connection rather than in `l7`, which resets at every
        /// turnaround — the whole point is a total that survives them.
        requests_served: u32,
        request_filters: []const filter.Rule,
        /// The listener's #175 response filter rules, same lifetime:
        /// matched against the origin's parsed response head at the
        /// re-render (empty on L4 and when none are configured).
        response_filters: []const filter.ResponseRule,
        /// The listener's §7 client-address forwarding mode, same lifetime
        /// as `routes`; null leaves `X-Forwarded-For` untouched.
        forwarded: ?config_module.Config.Listener.Forwarded,
        /// Whether this listener names an RFC 9209 cause on the refusals
        /// it renders itself (#300), carried like the modes above so a
        /// shed asks its own socket rather than the listener index.
        proxy_status: bool,
        /// The endpoint this L4 connection is charged against in the
        /// server's per-endpoint in-flight table (§7), or `endpoint_none`
        /// when it is charged against none — every L7 connection, and
        /// every L4 one shed before it dialed. Separate from the
        /// exchange's `stream.log.endpoint_index`, which the access log
        /// still needs after the charge is released; this one is the release's own
        /// bookkeeping, and clearing it is what makes the release
        /// exactly-once.
        charged_endpoint: u16,
        /// The cluster half of that key. The exchange's `cluster_index`
        /// cannot serve — it is readable at release time, on the stream
        /// this connection still holds, but it is the wrong value: the
        /// L7 path overwrites it per request at routing (and again per
        /// retry and replay), so a key built from it at teardown need not
        /// be the key that was charged.
        charged_cluster: u16,
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

        op_deadline: Op,
        op_deadline_cancel: Op,

        const Self = @This();

        /// This connection's stream slot type (#274). Declared here
        /// rather than beside `ServerType` above because `Stream` is
        /// parameterized by the connection it points back at — see its
        /// own docstring for why that is a parameter and not an import.
        pub const StreamType = stream_module.Stream(IoType, Self);

        pub const State = enum(u8) {
            // L4 relay states.
            /// Reading the PROXY protocol header a `proxy_protocol`
            /// listener requires (#142), staged in the relay buffer's
            /// client→upstream half and accumulated in `head_len`.
            /// Runs *before* `.connecting`, necessarily: the dial
            /// consumes `client_address` (the hash pick, §7), and the
            /// header is what makes that address the real client's.
            l4_reading_proxy_header,
            /// Reading the client's ClientHello to learn which backend it
            /// asked for (§6, #298), staged in the relay buffer's
            /// client→upstream half and accumulated in `head_len`.
            ///
            /// After the PROXY header, which is the outer envelope, and
            /// before `.connecting`, necessarily: the dial needs the
            /// cluster and the name is what picks it. Nothing is consumed
            /// — unlike that header, these bytes are the client's first
            /// payload and enter the relay as its opening debt, so the
            /// backend receives the hello it would have received without
            /// this proxy in the path.
            ///
            /// Never reached on a listener that terminates: the config
            /// refuses that pairing, because a handshake consumes the
            /// hello this phase exists to read.
            l4_peeking_client_hello,
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
            // L7 states (§7): `l7_reading_head` accumulates the request
            // head and retries the parse, resuming the search where the
            // last read left off; `l7_dialing` awaits the
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
                .l4_peeking_client_hello,
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

        /// One bit per embedded op; release requires all clear (§5) —
        /// and, since #274, requires the same of every stream this
        /// connection owns. Closes carry no bit: they are synchronous
        /// syscalls once both sets are empty, never ring ops
        /// (`Server.continueTeardown`).
        ///
        /// What is left here is the connection's own clock. The dial and
        /// the two data legs are the *exchange's* and live on `Stream`;
        /// a deadline outlives any one exchange on the connection, which
        /// is exactly the line the split draws.
        pub const Armed = packed struct(u2) {
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
            engine: ?*TlsEngine,
            state: State,
            protocol: config_module.Config.Listener.Protocol,
            client_address: std.Io.net.IpAddress,
        ) void {
            assert(state == .connecting or state == .l7_reading_head);
            conn.server = server;
            // Deliberately not set here: the slot's stream was acquired
            // with the slot itself (`admitConn`) and is already paired.
            // A reset that installed one would be a reset that could
            // orphan the one already held.
            conn.state = state;
            conn.client_socket = client_socket;
            conn.tunnel_buffer = null;
            conn.deadline_ns = 0;
            conn.birth_ns = server.io.nowNs();
            conn.armed = .{};
            // A parameter, not a field the caller installs afterwards: a
            // slot is recycled across listeners, so a caller that acquired
            // an engine and then let this reset it would leak one per
            // connection.
            conn.tls = engine;
            conn.tls_pending_len = 0;
            conn.tls_session_up = false;
            // Placeholders until the admission tail installs the
            // listener's real tables (§7); L4 never reads them.
            conn.routes = &.{};
            conn.sni_routes = &.{};
            conn.request_filters = &.{};
            conn.response_filters = &.{};
            conn.upgrades = .{};
            conn.max_body_bytes = 0;
            conn.requests_served = 0;
            conn.forwarded = null;
            conn.proxy_status = false;
            conn.charged_endpoint = stream_module.LogState.endpoint_none;
            conn.charged_cluster = 0;
            conn.protocol = protocol;
            conn.client_address = client_address;
            conn.op_deadline = .{};
            conn.op_deadline_cancel = .{};
            assert(conn.state == state);
            // The pairing this slice rests on, stated where it is made:
            // the stream the caller acquired is the one that points back
            // here, so the two slots are each other's and neither can be
            // read through the wrong partner (§5).
            assert(conn.stream.conn == conn);
            assert(conn.armedCount() == 0);
            assert(conn.stream.armedCount() == 0);
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
            //
            // The *combined* count since #274, and that is the point: the
            // CQ is charged per admitted connection, so what this peaks at
            // must be what it peaked at before the ops moved. `Stream.arm`
            // samples the same sum from its own side.
            if (std.debug.runtime_safety) {
                conn.server.armed_ops_peak = @max(
                    conn.server.armed_ops_peak,
                    conn.armedCount() + conn.stream.armedCount(),
                );
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
            return @popCount(@as(u2, @bitCast(conn.armed)));
        }
    };
}
