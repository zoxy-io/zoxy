//! The extension seam (#417): what a build adds to zoxy's serving path.
//!
//! A custom build is configured in code and never with JSON, and so are
//! its extensions: the build lists their types here, and its options
//! select instances of them. Nothing in a config file names one — the
//! stock binary's JSON cannot reach this seam at all.
//!
//! Every part of the serving path is generic over a `Runtime`, the one
//! comptime value that says what a server is built from. The stock
//! binary's runtime has empty lists, and an empty list compiles every
//! extension call out of it.
//!
//! **What an extension owes the proxy.** Its serving calls run on the one
//! loop thread, between completions (§3), so each one must:
//!
//! - run to completion synchronously, with every loop bounded;
//! - allocate nothing: no serving call is handed an allocator, and
//!   whatever an instance needs it holds already, or took from the
//!   startup arena while it was bound;
//! - be deterministic given its inputs and its own state — no wall clock
//!   and no private randomness, since the simulator replays every seed
//!   twice and demands byte-identical traces (§9);
//! - make no syscall and do no I/O;
//! - read the views it is given only during the call: they alias head
//!   buffers and scratch that the next completion reuses.
//!
//! zoxy asserts what it can see of that from its side of the seam — the
//! slot a picker returns, the status a policy rejects with — and owns
//! everything around the call: dialing, pooling, retries and accounting.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const filter = @import("http/filter.zig");
const router = @import("http/router.zig");
const io_module = @import("io/io.zig");
const parser = @import("http/parser.zig");
const upstream = @import("net/upstream.zig");
const Balancer = @import("balancer.zig").Balancer;

const assert = std.debug.assert;

/// The extension types one build carries, as comptime lists. A cluster or
/// a listener selects an *instance* of one of these in code; a type the
/// build does not list cannot be selected.
pub const Extensions = struct {
    /// Endpoint pickers a cluster may select (§7).
    pickers: []const type = &.{},
    /// Request policies a listener or a route may select (§7).
    request_policies: []const type = &.{},
    /// Response policies a listener or a route may select (#424): they
    /// read the origin's response head and edit it on its way out.
    response_policies: []const type = &.{},
};

/// What a server is built from: the Io backend (§4) and the build's
/// extensions. A struct *value* rather than a type, so a server reads as
/// `Server(.{ .Io = SimIo })` — and Zig memoizes a generic on a comptime
/// value, so every part instantiating `Server(runtime)` with the same
/// runtime gets the same type.
pub const Runtime = struct {
    Io: type,
    extensions: Extensions = .{},
};

/// The most types one list may hold: a selection names its type by a `u8`.
pub const list_types_max = std.math.maxInt(u8) + 1;

/// One extension instance selected in code: which of the build's listed
/// types it is, and the instance itself, type-erased the way a context
/// pointer beside a function pointer is. Built by `select`, which
/// checks the type against the build's list at compile time, so `index`
/// always names the type `instance` points at.
pub const Selection = struct {
    index: u8,
    instance: *anyopaque,
};

/// Select `instance` from `list` — a build's `pickers` or its
/// `request_policies`. A compile error unless `instance` is a mutable
/// pointer to a type the list names: the instance carries the extension's
/// state, and the serving call mutates it.
pub fn select(comptime list: []const type, instance: anytype) Selection {
    const info = @typeInfo(@TypeOf(instance));
    comptime assert(list.len <= list_types_max);
    if (info != .pointer or info.pointer.size != .one or info.pointer.attrs.@"const") {
        @compileError("select takes a mutable pointer to an extension instance, not " ++
            @typeName(@TypeOf(instance)));
    }
    const Instance = info.pointer.child;
    inline for (list, 0..) |Listed, index| {
        if (comptime Listed == Instance) {
            return .{ .index = index, .instance = instance };
        }
    }
    @compileError(@typeName(Instance) ++ " is not in this build's list of extensions");
}

/// What every startup call is handed. Startup is the one time an
/// extension may allocate: what it takes from `arena` lives as long as the
/// process and is measured with the rest of startup (§5).
pub const Startup = struct {
    arena: std.mem.Allocator,
};

/// One request, as an extension sees it: the §7 canonical routing keys
/// and the parsed head, valid only for the call it is passed to.
pub const Request = struct {
    method: parser.Method,
    /// The canonical host — lowercased, no port — or null when the
    /// request named none that routing can match.
    host: ?[]const u8,
    /// The canonical path the route table and the filters match: decoded
    /// where safe, dot-segments collapsed, `/` for an asterisk-form OPTIONS.
    path: []const u8,
    /// The query, verbatim and without its `?`; empty when there is none.
    query: []const u8,
    /// The parsed header lines, names and values as the client sent them.
    headers: []const parser.Header,
    /// The client's address, or null on a `unix:` listener, which has none.
    client: ?*const std.Io.net.IpAddress,
    /// The verified client certificate's SHA-256 in lowercase hex, when
    /// the listener asked for one and the client presented it (#304).
    client_cert_sha256: ?[]const u8,
    /// The same certificate's URI and DNS subjectAltNames (#432): the
    /// identity it names — a SPIFFE ID, a host — which survives a reissue
    /// where the fingerprint does not. Empty with no verified client.
    client_cert_names: ClientCertNames = .{},
    /// The listener the request arrived on, by config index.
    listener_index: u16,
    /// The cluster the route chose, or null before routing has run.
    cluster_index: ?u16,
    /// What an earlier phase worked out about this request (#433): the
    /// tag the last policy to set one left, or zero while none has. A
    /// policy sets it with `proceed_with`. Every later view of the same
    /// request carries it — the next policy's, the route phase's, a
    /// picker's on the first try and on a retry — and the access log
    /// records it as `tag`.
    tag: u64,
    /// The loop's monotonic clock (§4), the value `PickInput.now_ns`
    /// would read at the same moment (#429): what a policy times a window
    /// or refills a token bucket by. Still no wall clock — a seed replays
    /// every reading.
    now_ns: u64,
    /// The evaluating policy's own counters and gauges at the site it is
    /// evaluated for (#435). Empty for a type that declares none, and in
    /// the request a picker is shown, whose are `PickInput.metrics`.
    metrics: Metrics = .{},
};

/// A verified client certificate's names, as a policy reads them (#432).
pub const ClientCertNames = struct {
    /// URI and DNS subjectAltNames, in the leaf's order.
    names: []const ClientCertName = &.{},
    /// The leaf named more than a connection keeps
    /// (`client_cert_names_max` names in `client_cert_names_bytes_max`
    /// bytes): `names` are the leaf's own, but not all of them. A policy
    /// that authorizes on the absence of a name must refuse on this.
    truncated: bool = false,
};

pub const ClientCertName = struct {
    kind: Kind,
    /// A URI as the leaf states it; a DNS name lowercased.
    value: []const u8,

    pub const Kind = enum { uri, dns };
};

/// The picker contract (§7). A picker type declares
///
///     pub fn pick(self: *P, candidates: *const Candidates, input: *const PickInput) u16
///
/// returning a slot in `0..candidates.count()`, and may declare
///
///     pub fn bind(self: *P, cluster: *const ClusterSite, startup: *const Startup) !void
///
/// which zoxy calls once at startup for each cluster that selects the
/// instance, before any pick. A bind may refuse, and that stops the start.
///
/// The endpoints a pick may choose between, already narrowed by zoxy
/// (§7): drained and already-tried endpoints are out, health and panic
/// have steered, every endpoint at its ramped `max_inflight` is out, and
/// in a tiered cluster only the lowest usable tier is left. Never empty.
/// A slot indexes this set, not the cluster.
pub const Candidates = struct {
    /// zoxy's own: the narrowed endpoints' indices into the cluster,
    /// in config order. Read through the methods.
    endpoints: []const u16,
    cluster_index: u16,
    cluster: *const config_module.Config.Cluster,
    keys: upstream.EndpointKeys,
    load: *const upstream.Load,
    identities: []const u64,

    pub fn count(candidates: *const Candidates) u16 {
        assert(candidates.endpoints.len >= 1);
        assert(candidates.endpoints.len <= candidates.cluster.endpoints.len);
        return @intCast(candidates.endpoints.len);
    }

    /// The candidate's index into its cluster's endpoints.
    pub fn endpointIndex(candidates: *const Candidates, slot: u16) u16 {
        assert(slot < candidates.endpoints.len);
        const index = candidates.endpoints[slot];
        assert(index < candidates.cluster.endpoints.len);
        return index;
    }

    /// A stable identity derived from the endpoint's address alone:
    /// the same in every process and across restarts and config
    /// reorders — the identity a sticky cookie's tag spells (#178).
    pub fn identity(candidates: *const Candidates, slot: u16) u64 {
        const key = candidates.keys.key(candidates.cluster_index, candidates.endpointIndex(slot));
        assert(key < candidates.identities.len);
        return candidates.identities[key];
    }

    /// The endpoint's weight, 1 to 256 (#174). A drained endpoint
    /// (weight 0) is never a candidate.
    pub fn weight(candidates: *const Candidates, slot: u16) u16 {
        const index = candidates.endpointIndex(slot);
        const weights = candidates.cluster.weights orelse return 1;
        assert(weights[index] >= 1);
        return weights[index];
    }

    /// The endpoint's in-flight work: HTTP/1.1 leases, HTTP/2 legs and
    /// live L4 connections (§7).
    pub fn inFlight(candidates: *const Candidates, slot: u16) u32 {
        const key = candidates.keys.key(candidates.cluster_index, candidates.endpointIndex(slot));
        assert(key < candidates.load.l7.len);
        return candidates.load.inFlight(key);
    }

    /// The endpoint's in-flight cap as it stands now — `max_inflight`,
    /// ramped while a restored endpoint is inside its slow start
    /// (#391) — or null for an uncapped cluster. Every candidate is
    /// under its cap, or it would not be one.
    pub fn capacity(candidates: *const Candidates, slot: u16) ?u32 {
        const cap = candidates.cluster.max_inflight orelse return null;
        assert(cap >= 1);
        const key = candidates.keys.key(candidates.cluster_index, candidates.endpointIndex(slot));
        const window_ms = candidates.cluster.slow_start_ms orelse return cap;
        return Balancer.rampedCap(cap, window_ms, candidates.load.restoredAt(key), candidates.load.now_ns);
    }

    /// The address zoxy will dial if this slot is chosen.
    pub fn address(candidates: *const Candidates, slot: u16) *const io_module.Address {
        const index = candidates.endpointIndex(slot);
        assert(index < candidates.cluster.endpoints.len);
        return &candidates.cluster.endpoints[index];
    }
};

/// What one pick is for.
pub const PickInput = struct {
    cluster_index: u16,
    /// The client's address, or null on a `unix:` listener.
    client: ?*const std.Io.net.IpAddress,
    /// The request on the L7 path; null for an L4 connection, which
    /// has none.
    request: ?*const Request,
    /// Whether this pick replaces a dial that failed (#181). The
    /// endpoints it tried are already out of `Candidates`.
    retry: bool,
    /// Whether the cluster sat below its panic threshold, or had
    /// nothing healthy, so health did not steer (#390).
    panicked: bool,
    /// The loop's monotonic clock (§4).
    now_ns: u64,
    /// zoxy's own seeded generator, for a picker that wants randomness
    /// and must stay deterministic (§9): draw what the pick needs, in
    /// order, and a seed replays every draw. The stock policies draw from
    /// it too — p2c twice per pick — so it is one stream, not one per
    /// picker.
    random: *Random,
    /// The picker's own counters and gauges for this cluster (#435);
    /// empty for a type that declares none.
    metrics: Metrics = .{},
};

/// zoxy's pick generator (§9): xorshift64* (Vigna), the full-period
/// 64-bit shift generator with a multiplicative output scramble — plenty
/// for candidate draws, one multiply and three shifts on the pick path.
/// Seeded once per process; the modulo bias of a draw is at most 2⁻⁴⁸
/// even at the `u16` index type's edge.
pub const Random = struct {
    state: u64,

    pub fn init(seed: u64) Random {
        assert(seed != 0); // xorshift64* cycles on a nonzero state.
        return .{ .state = seed };
    }

    pub fn next(random: *Random) u64 {
        assert(random.state != 0);
        var x = random.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        random.state = x;
        assert(x != 0); // A nonzero state maps to a nonzero state.
        return x *% 0x2545F4914F6CDD1D;
    }
};

/// How one pick turned out (#423). A picker may declare
///
///     pub fn complete(self: *P, done: *const Completion) void
///
/// and zoxy calls it exactly once for every pick it made for a cluster
/// that selects the instance, once that pick's outcome is final: a retry
/// or a replay is a pick of its own, and the attempt it replaces has
/// already completed. The same obligations as `pick` hold — the loop
/// thread, run to completion, no allocation, no clock, no I/O — and the
/// times are the loop clock's, the one `PickInput.now_ns` reads.
pub const Completion = struct {
    cluster_index: u16,
    /// The endpoint picked, by index into its cluster, and its stable
    /// identity: what `Candidates.endpointIndex` and `identity` named.
    endpoint_index: u16,
    identity: u64,
    /// Whether this pick replaced a dial that failed (#181).
    retry: bool,
    /// When the pick was made.
    picked_ns: u64,
    /// When this attempt had a connection to send on: its dial completed,
    /// a parked connection was taken, or its stream opened on an HTTP/2
    /// origin's connection. Null when none ever was.
    connected_ns: ?u64,
    /// When the origin's response head arrived — time to first byte, read
    /// against `picked_ns`. Null when none did.
    head_ns: ?u64,
    /// When the outcome became final.
    done_ns: u64,
    outcome: Outcome,
    /// The request's tag (#433), zero when it carried none and on L4.
    tag: u64,
    /// An L4 connection's bytes from its client and to it, as its access
    /// log line counts them — what the relay carried. Zero on L7.
    bytes_from_client: u64 = 0,
    bytes_to_client: u64 = 0,
    /// The picker's own counters and gauges for this cluster (#435).
    metrics: Metrics = .{},

    pub const Outcome = union(enum) {
        /// The origin answered, and the whole response reached the
        /// client: its final status.
        response: u16,
        /// An L4 connection's relay ran and closed, from either end or
        /// by its idle deadline: the ordinary end of a connection that
        /// carried bytes rather than an exchange.
        closed,
        /// The attempt never had a connection to send on: the dial was
        /// refused, unreachable, or cut short, or an HTTP/2 origin's
        /// connection it waited on failed to open.
        connect_failed,
        /// The deadline ran out before the origin answered (`504`, or the
        /// client's own gRPC deadline): in the dial, or after it. On L4,
        /// the dial's own deadline.
        timed_out,
        /// The exchange failed on the origin's side once connected: a
        /// reset, a hangup, a response cut short.
        failed,
        /// The parked connection taken for this attempt had gone stale;
        /// the request is replayed on a pick of its own (§7). Not the
        /// endpoint's verdict.
        stale,
        /// The pick was made, but this proxy had no resource left to dial
        /// with (§8): the origin never heard of the request.
        shed,
        /// The exchange ended on this proxy's or the client's side
        /// before the origin's answer was whole: the client left, the
        /// request broke a rule mid-flight, or a drain ended it — on L4,
        /// a connection torn down before its dial completed. Its
        /// `done_ns` may be when the stream was given back, later than
        /// the attempt really ended: not a latency to steer by.
        aborted,
    };
};

/// Whether `Picker` declares the optional `complete`.
pub fn pickerCompletes(comptime Picker: type) bool {
    return @hasDecl(Picker, "complete");
}

/// Whether any picker the build lists completes: in a build where none
/// does, the bookkeeping behind `Completion` compiles out.
pub fn completes(comptime extensions: Extensions) bool {
    inline for (extensions.pickers) |Picker| {
        if (comptime pickerCompletes(Picker)) return true;
    }
    return false;
}

/// The cluster a `bind` is called for.
pub const ClusterSite = struct {
    index: u16,
    name: []const u8,
    endpoints: []const io_module.Address,
};

/// The request-policy contract (§7). A policy type declares
///
///     pub fn evaluate(self: *P, request: *const Request) Verdict
///
/// and may declare
///
///     pub fn bind(self: *P, site: *const PolicySite, startup: *const Startup) !void
///
/// which zoxy calls once at startup for each listener and each route that
/// selects the instance. A listener's policies run once per request, after
/// its head parses and canonicalizes and before the request filters and
/// routing; a route's run once the route is chosen, before the request
/// takes any resource. Each list runs in order and the first reject wins.
/// A retry or a replay re-picks without re-routing, so neither phase ever
/// evaluates one request twice.
pub const Verdict = union(enum) {
    /// Hand the request on: to the filters and the route table at the
    /// listener phase, to the dial at the route phase.
    proceed,
    /// Hand the request on as `proceed` does, with what the policy adds
    /// to it (#433).
    proceed_with: Proceed,
    /// Answer with this status from server memory, before any resource
    /// is taken or origin dialed — the filter reject's answer (§8).
    reject: RejectStatus,
    /// Answer with one of the policy type's own `answers` (#431), by its
    /// index there: built with `respond`, which names it. Served and
    /// counted as a reject is, from the page rendered at startup.
    respond: u16,
};

/// What a policy adds to a request it hands on.
pub const Proceed = struct {
    /// The request's tag from here on (#433), or null to leave the one
    /// it arrived with. The later write wins: a route's policy may
    /// overwrite what a listener's set, and reads the current tag in
    /// `Request.tag` if it would rather keep it. A tag set before a
    /// later policy rejects stays the request's, and the rejected line
    /// records it. Zero clears it: zero is no tag, as before any was set.
    tag: ?u64 = null,
    /// The route the request takes (#430): an index into the listener's
    /// table, resolved at `bind` with `PolicySite.routeNamed`. It replaces
    /// the table's match, not the steps before it — the listener's filters
    /// still run — and the chosen route's own policies run as if the table
    /// had matched it. Its host, header and prefix are not asked of the
    /// request: a policy that routes past a host-scoped route, which may
    /// be a tenant's boundary, answers for that itself. The later choice
    /// wins. An index the listener has no
    /// route at, or a choice made at the route phase, when the route is
    /// already chosen, leaves the table's match standing and is counted
    /// (`l7_policy_route_fallback`).
    route: ?u16 = null,
    /// Header edits to the request on its way upstream (#424), the
    /// request filters' three. They apply in the order their deciders
    /// ran: a listener's policies' before the filters', a route's after,
    /// and a later `set` or `remove` of a name overrides what came before
    /// it. Copied when the verdict is read, so a value may live in the
    /// policy's own scratch — up to `edits_per_verdict_max` of them, their
    /// names and values within the type's declared `edit_bytes_max`; more,
    /// or a type that declared none, is the build's bug, and the seam
    /// asserts on it. A name zoxy writes itself, or a value that is not a
    /// field value, is refused with a `400` (`l7_policy_edit_refused`): a
    /// value from the request must never become a header of zoxy's, or
    /// two.
    edits: []const Edit = &.{},
};

/// One header edit a policy asks of a request it hands on (#424).
pub const Edit = union(enum) {
    /// Every copy of the name replaced by this one line.
    set: Header,
    /// This line, beside whatever copies there are.
    add: Header,
    /// Every copy of the name removed.
    remove: []const u8,

    pub const Header = struct {
        name: []const u8,
        value: []const u8,
    };

    /// The bytes the edit's name and value take, as copied.
    pub fn bytes(edit: Edit) u32 {
        return switch (edit) {
            .set, .add => |header| @intCast(header.name.len + header.value.len),
            .remove => |name| @intCast(name.len),
        };
    }
};

/// The most edits one verdict carries (#424).
pub const edits_per_verdict_max = constants.policy_edits_per_verdict_max;

/// The bytes `Policy`'s verdicts may copy, at most, per request: its
/// declared `edit_bytes_max`, or zero for a type that edits nothing.
pub fn editBytesOf(comptime Policy: type) u32 {
    if (!@hasDecl(Policy, "edit_bytes_max")) return 0;
    return Policy.edit_bytes_max;
}

/// The origin's response head, as a response policy sees it (#424):
/// valid only for the call, like every view.
pub const Response = struct {
    status: u16,
    /// The parsed header lines, names and values as the origin sent them.
    headers: []const parser.Header,
    /// The listener, route and cluster the request took.
    listener_index: u16,
    route_index: u16,
    cluster_index: u16,
    /// The request's tag (#433), as its policies left it.
    tag: u64,
    /// The loop's monotonic clock (§4).
    now_ns: u64,
};

/// What a response policy does to the head it read (#424): edits, the
/// request filters' three, applied with the response filters' in the
/// order their deciders run on the way out — the route's policies', the
/// filters', the listener's policies' — under a request edit's rules and
/// bounds. A refused edit fails the exchange as an unrenderable origin
/// head does: a `502`.
pub const ResponseVerdict = struct {
    edits: []const Edit = &.{},
};

/// How a request a policy let through ended (#429). A policy may declare
///
///     pub fn complete(self: *P, done: *const RequestCompletion) void
///
/// and zoxy calls it exactly once for every request it handed on —
/// `proceed` or `proceed_with` — when that exchange ends, whatever ended
/// it: the origin's whole response, a later policy's reject, a filter, no
/// route, a shed, a timeout. A policy that rejected gets none. It is the
/// moment the access-log line is written, and an upgrade completes at its
/// `101`. What a limiter counts up as a request passes, it counts down
/// here. The obligations are `evaluate`'s.
pub const RequestCompletion = struct {
    /// The site this policy ran at: the listener, and the route when it
    /// was one of the route's.
    listener_index: u16,
    route_index: ?u16,
    /// The cluster routing chose, or null when the request never routed.
    cluster_index: ?u16,
    /// The request's tag (#433), as it ended.
    tag: u64,
    /// The status the request's line reports — what the client was
    /// sent, or was being sent when the exchange ended — or zero when
    /// there was none.
    status: u16,
    outcome: Outcome,
    /// The loop clock when the request began — its first head byte — and
    /// when it ended.
    started_ns: u64,
    done_ns: u64,
    /// This policy's own counters and gauges at its site (#435).
    metrics: Metrics = .{},

    /// What the request's access-log line says happened (§8).
    pub const Outcome = enum {
        /// The origin's response, whole.
        ok,
        /// Refused: a policy, a filter, no route, or a head this proxy
        /// would not take.
        rejected,
        /// A filter's redirect.
        redirected,
        /// Answered by this proxy on the origin's behalf.
        responded,
        shed,
        timed_out,
        upstream_failed,
        /// The client left, or a drain ended it, before an answer.
        aborted,
    };
};

/// Whether `Policy` declares the optional `complete`.
pub fn policyCompletes(comptime Policy: type) bool {
    return @hasDecl(Policy, "complete");
}

/// Whether any request policy the build lists completes.
pub fn policiesComplete(comptime extensions: Extensions) bool {
    inline for (extensions.request_policies) |Policy| {
        if (comptime policyCompletes(Policy)) return true;
    }
    return false;
}

/// One answer a request policy may give instead of handing a request on
/// (#431): a challenge, a maintenance notice, a redirect to a login page.
/// A policy type declares its answers by name,
///
///     pub const answers = .{
///         .login = extension.Answer{
///             .status = 401,
///             .headers = &.{.{ .name = "WWW-Authenticate", .value = "Bearer" }},
///         },
///     };
///
/// and zoxy renders every one into a static page at startup, priced in
/// the banner. Wholly static: nothing in a page depends on the request.
/// The headers that frame a response and that say who sent it —
/// `Content-Length`, `Connection` and the rest, `Date`, `Server`,
/// `Proxy-Status`, and `Content-Type`, which `content_type` sets — stay
/// zoxy's own, and declaring one is a compile error.
pub const Answer = struct {
    /// 300 to 599. A redirect names its target in a `Location` header.
    status: u16,
    headers: []const Header = &.{},
    body: []const u8 = "",
    /// Sent when the body is not empty.
    content_type: []const u8 = "text/plain; charset=utf-8",

    pub const Header = struct {
        name: []const u8,
        value: []const u8,
    };
};

/// The verdict that answers with `Policy`'s answer `name` (#431). The
/// name is checked against `Policy.answers` at compile time.
pub fn respond(comptime Policy: type, comptime name: AnswerName(Policy)) Verdict {
    comptime assert(hasAnswers(Policy));
    const index: u16 = @backingInt(name);
    comptime assert(index < answerCount(Policy));
    return .{ .respond = index };
}

/// Whether `Policy` declares answers of its own.
pub fn hasAnswers(comptime Policy: type) bool {
    return @hasDecl(Policy, "answers");
}

/// `Policy`'s answers, by name.
pub fn AnswerName(comptime Policy: type) type {
    return std.meta.FieldEnum(@TypeOf(Policy.answers));
}

/// How many answers `Policy` declares; zero for one that declares none.
pub fn answerCount(comptime Policy: type) u16 {
    if (!hasAnswers(Policy)) return 0;
    return @typeInfo(@TypeOf(Policy.answers)).@"struct".field_names.len;
}

/// The headers an answer may not declare: what frames the response,
/// what governs the connection, and what says who answered.
const answer_reserved_headers = [_][]const u8{
    "content-length",   "transfer-encoding", "connection",   "keep-alive",
    "proxy-connection", "upgrade",           "te",           "trailer",
    "date",             "server",            "content-type", "proxy-status",
};

/// Refuse, at compile time, answers zoxy could not serve as written: a
/// status outside 300..599, a redirect without its `Location`, a header
/// that is zoxy's own or that would split the head, or anything past
/// its bound.
pub fn assertAnswers(comptime Policy: type) void {
    @setEvalBranchQuota(64 * constants.extension_answers_per_type_max *
        (constants.extension_answer_headers_max * constants.extension_answer_header_bytes_max +
            constants.extension_answer_body_bytes_max) + 1000);
    const name = @typeName(Policy);
    const info = @typeInfo(@TypeOf(Policy.answers));
    if (info != .@"struct") @compileError(name ++ ".answers must be a struct literal of name = extension.Answer");
    if (info.@"struct".field_names.len > constants.extension_answers_per_type_max) {
        @compileError(name ++ " declares more answers than extension_answers_per_type_max");
    }
    for (info.@"struct".field_names) |answer_name| {
        const where = name ++ ".answers." ++ answer_name;
        if (@TypeOf(@field(Policy.answers, answer_name)) != Answer) {
            @compileError(where ++ " must be an extension.Answer");
        }
        assertAnswer(where, @field(Policy.answers, answer_name));
    }
}

fn assertAnswer(comptime where: []const u8, comptime answer: Answer) void {
    if (answer.status < 300 or answer.status > 599) @compileError(where ++ ".status must be 300 to 599");
    if (answer.headers.len > constants.extension_answer_headers_max) {
        @compileError(where ++ " declares more headers than extension_answer_headers_max");
    }
    if (answer.body.len > constants.extension_answer_body_bytes_max) {
        @compileError(where ++ ".body is longer than extension_answer_body_bytes_max");
    }
    if (answer.content_type.len == 0 or !answerValueValid(answer.content_type)) {
        @compileError(where ++ ".content_type must be one line");
    }
    // RFC 9110 §15.4: a 304 carries no content, so no body to frame.
    if (answer.status == 304 and answer.body.len != 0) @compileError(where ++ " is a 304 with a body");
    var located = false;
    for (answer.headers) |header| {
        if (!answerHeaderNameValid(header.name)) @compileError(where ++ ": `" ++ header.name ++ "` is not a header name");
        if (!answerValueValid(header.value)) @compileError(where ++ ": `" ++ header.name ++ "`'s value must be one line");
        if (header.name.len + header.value.len > constants.extension_answer_header_bytes_max) {
            @compileError(where ++ ": `" ++ header.name ++ "` is longer than extension_answer_header_bytes_max");
        }
        for (answer_reserved_headers) |reserved| {
            if (std.ascii.eqlIgnoreCase(header.name, reserved)) {
                @compileError(where ++ ": `" ++ header.name ++ "` is zoxy's own header");
            }
        }
        if (std.ascii.eqlIgnoreCase(header.name, "location")) located = true;
    }
    if (redirectNeedsLocation(answer.status) and !located) {
        @compileError(where ++ " is a redirect without a `Location`");
    }
}

/// The redirects whose target RFC 9110 §15.4 says `Location` names: a
/// 300's choices, a 304 and the unused 305 and 306 name none.
fn redirectNeedsLocation(comptime status: u16) bool {
    return switch (status) {
        301, 302, 303, 307, 308 => true,
        else => false,
    };
}

/// A token (RFC 9110 §5.6.2): what a field name is.
fn answerHeaderNameValid(comptime text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| {
        const ok = std.ascii.isAlphanumeric(byte) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", byte) != null;
        if (!ok) return false;
    }
    return true;
}

/// A field value both protocols read as written (RFC 9110 §5.5, RFC 9113
/// §8.2.1): visible characters, spaces and tabs within, and neither at
/// either end — which HTTP/2 forbids and HTTP/1.1 parsers trim.
fn answerValueValid(comptime text: []const u8) bool {
    for (text) |byte| {
        const control = byte < 0x20 or byte == 0x7f;
        if (control and byte != '\t') return false;
    }
    if (text.len == 0) return true;
    const edges = [_]u8{ text[0], text[text.len - 1] };
    for (edges) |edge| {
        if (edge == ' ' or edge == '\t') return false;
    }
    return true;
}

/// The statuses a policy may refuse with: the static reject set a filter
/// rule may use (§8), so every one is a page the proxy already serves.
pub const RejectStatus = enum(u16) {
    bad_request = 400,
    forbidden = 403,
    not_found = 404,
    too_many_requests = 429,
};

comptime {
    for (std.enums.values(RejectStatus)) |status| {
        assert(filter.isRejectStatus(@backingInt(status)));
    }
    assert(std.enums.values(RejectStatus).len == filter.reject_statuses.len);
}

/// Where a policy is bound: a listener, or one of its routes.
pub const PolicySite = struct {
    listener_index: u16,
    /// The route's index in its listener's table, or null for the
    /// listener itself.
    route_index: ?u16,
    /// The cluster the route sends to; null for the listener.
    cluster_index: ?u16,
    /// The listener's route table, as routing reads it — sorted by
    /// specificity, so an index is not the order the options stated the
    /// routes in. Read through `routeNamed`.
    routes: []const router.Route,

    /// The index of the listener's route named `name` (#430): what a
    /// policy resolves once, at `bind`, and routes by. Null when no route
    /// of this listener carries that name. An empty name is the caller's
    /// bug: no route can carry one (`RouteNameInvalid`).
    pub fn routeNamed(site: *const PolicySite, name: []const u8) ?u16 {
        assert(name.len >= 1);
        // `RoutesOverLimit` holds a listener's table to a `u16` index.
        assert(site.routes.len <= std.math.maxInt(u16));
        for (site.routes, 0..) |route, index| {
            const named = route.name orelse continue;
            if (std.mem.eql(u8, named, name)) return @intCast(index);
        }
        return null;
    }
};

/// Refuse, at compile time, a picker type that does not meet `pick`'s
/// contract — with a message naming what is wrong, rather than an error
/// deep inside the dispatch that calls it.
pub fn assertPicker(comptime Picker: type) void {
    const name = @typeName(Picker);
    if (!@hasDecl(Picker, "pick")) {
        @compileError(name ++ " is listed as a picker but declares no `pub fn pick`");
    }
    const pick_fn = @typeInfo(@TypeOf(Picker.pick)).@"fn";
    const pick_ok = pick_fn.param_types.len == 3 and
        pick_fn.param_types[0] == *Picker and
        pick_fn.param_types[1] == *const Candidates and
        pick_fn.param_types[2] == *const PickInput and
        pick_fn.return_type == u16;
    if (!pick_ok) {
        @compileError(name ++ ".pick must be `fn (*" ++ name ++
            ", *const extension.Candidates, *const extension.PickInput) u16`");
    }
    if (@hasDecl(Picker, "bind")) {
        assertBind(Picker, ClusterSite);
    }
    if (pickerCompletes(Picker)) {
        const complete_fn = @typeInfo(@TypeOf(Picker.complete)).@"fn";
        const complete_ok = complete_fn.param_types.len == 2 and
            complete_fn.param_types[0] == *Picker and
            complete_fn.param_types[1] == *const Completion and
            complete_fn.return_type == void;
        if (!complete_ok) {
            @compileError(name ++ ".complete must be `fn (*" ++ name ++
                ", *const extension.Completion) void`");
        }
    }
}

/// Refuse, at compile time, a response-policy type that does not meet its
/// contract (#424): `evaluate(*P, *const Response) ResponseVerdict`, an
/// optional `bind` like a request policy's, and an optional
/// `edit_bytes_max` within its bound.
pub fn assertResponsePolicy(comptime Policy: type) void {
    const name = @typeName(Policy);
    if (!@hasDecl(Policy, "evaluate")) {
        @compileError(name ++ " is listed as a response policy but declares no `pub fn evaluate`");
    }
    const evaluate_fn = @typeInfo(@TypeOf(Policy.evaluate)).@"fn";
    const evaluate_ok = evaluate_fn.param_types.len == 2 and
        evaluate_fn.param_types[0] == *Policy and
        evaluate_fn.param_types[1] == *const Response and
        evaluate_fn.return_type == ResponseVerdict;
    if (!evaluate_ok) {
        @compileError(name ++ ".evaluate must be `fn (*" ++ name ++
            ", *const extension.Response) extension.ResponseVerdict`");
    }
    if (@hasDecl(Policy, "bind")) assertBind(Policy, PolicySite);
    if (@hasDecl(Policy, "edit_bytes_max")) {
        const bound: u32 = Policy.edit_bytes_max;
        if (bound == 0 or bound > constants.policy_edit_bytes_max) {
            @compileError(name ++ ".edit_bytes_max must be 1 to policy_edit_bytes_max");
        }
    }
    // A response policy's metrics would need sites of their own (#435).
    if (isMetered(Policy)) @compileError(name ++ " is a response policy, which declares no metrics yet");
}

/// Refuse, at compile time, a request-policy type that does not meet
/// `evaluate`'s contract.
pub fn assertRequestPolicy(comptime Policy: type) void {
    const name = @typeName(Policy);
    if (!@hasDecl(Policy, "evaluate")) {
        @compileError(name ++ " is listed as a request policy but declares no `pub fn evaluate`");
    }
    const evaluate_fn = @typeInfo(@TypeOf(Policy.evaluate)).@"fn";
    const evaluate_ok = evaluate_fn.param_types.len == 2 and
        evaluate_fn.param_types[0] == *Policy and
        evaluate_fn.param_types[1] == *const Request and
        evaluate_fn.return_type == Verdict;
    if (!evaluate_ok) {
        @compileError(name ++ ".evaluate must be `fn (*" ++ name ++
            ", *const extension.Request) extension.Verdict`");
    }
    if (@hasDecl(Policy, "bind")) {
        assertBind(Policy, PolicySite);
    }
    if (hasAnswers(Policy)) assertAnswers(Policy);
    if (@hasDecl(Policy, "edit_bytes_max")) {
        const bound: u32 = Policy.edit_bytes_max;
        if (bound == 0 or bound > constants.policy_edit_bytes_max) {
            @compileError(name ++ ".edit_bytes_max must be 1 to policy_edit_bytes_max");
        }
    }
    if (policyCompletes(Policy)) {
        const complete_fn = @typeInfo(@TypeOf(Policy.complete)).@"fn";
        const complete_ok = complete_fn.param_types.len == 2 and
            complete_fn.param_types[0] == *Policy and
            complete_fn.param_types[1] == *const RequestCompletion and
            complete_fn.return_type == void;
        if (!complete_ok) {
            @compileError(name ++ ".complete must be `fn (*" ++ name ++
                ", *const extension.RequestCompletion) void`");
        }
    }
}

/// The optional startup half of either contract: `bind(*T, *const Site,
/// *const Startup) !void`.
fn assertBind(comptime T: type, comptime Site: type) void {
    const name = @typeName(T);
    const bind_fn = @typeInfo(@TypeOf(T.bind)).@"fn";
    const returns = @typeInfo(bind_fn.return_type orelse void);
    const bind_ok = bind_fn.param_types.len == 3 and
        bind_fn.param_types[0] == *T and
        bind_fn.param_types[1] == *const Site and
        bind_fn.param_types[2] == *const Startup and
        returns == .error_union and returns.error_union.payload == void;
    if (!bind_ok) {
        @compileError(name ++ ".bind must be `fn (*" ++ name ++ ", *const " ++
            @typeName(Site) ++ ", *const extension.Startup) !void`");
    }
}

/// Refuse a build whose lists break the seam: a type listed twice would
/// make a selection's index ambiguous, and every listed type must meet
/// its contract.
pub fn assertExtensions(comptime extensions: Extensions) void {
    comptime assert(extensions.pickers.len <= list_types_max);
    comptime assert(extensions.request_policies.len <= list_types_max);
    comptime assert(extensions.response_policies.len <= list_types_max);
    inline for (extensions.response_policies, 0..) |Policy, index| {
        assertResponsePolicy(Policy);
        inline for (extensions.response_policies[index + 1 ..]) |Later| {
            if (Policy == Later) @compileError(@typeName(Policy) ++ " is listed twice as a response policy");
        }
    }
    const families = metered(extensions);
    inline for (families, 0..) |Family, index| {
        assertMetrics(Family);
        inline for (families[index + 1 ..]) |Later| {
            if (std.mem.eql(u8, Family.metrics_prefix, Later.metrics_prefix)) {
                @compileError(@typeName(Family) ++ " and " ++ @typeName(Later) ++
                    " declare the same metrics_prefix \"" ++ Family.metrics_prefix ++ "\"");
            }
            assertSeriesApart(Family, Later);
        }
    }
    inline for (extensions.pickers, 0..) |Picker, index| {
        assertPicker(Picker);
        inline for (extensions.pickers[index + 1 ..]) |Later| {
            if (Picker == Later) @compileError(@typeName(Picker) ++ " is listed twice as a picker");
        }
    }
    inline for (extensions.request_policies, 0..) |Policy, index| {
        assertRequestPolicy(Policy);
        inline for (extensions.request_policies[index + 1 ..]) |Later| {
            if (Policy == Later) @compileError(@typeName(Policy) ++ " is listed twice as a request policy");
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics (#435)
// ---------------------------------------------------------------------------

// A build's own counters and gauges. A type may declare
//
//     pub const metrics_prefix = "tenant_guard";
//     pub const counters = .{ .refused = "Requests this guard refused." };
//     pub const gauges = .{ .tenants = "Tenants in the guard's table." };
//
// Each name becomes the series `zoxy_ext_<prefix>_<name>`, rendered on
// the metrics endpoint beside zoxy's own with its help text, once for
// every site that selects the type: a picker's cluster, a listener its
// policies run on, or a route. zoxy reserves the slots at startup and
// hands a site's into every serving call made for it, as
// `PickInput.metrics` and `Request.metrics`; every instance of the type
// at that site shares them. A counter only grows. A gauge is a level the
// type sets.

/// What every extension series name starts with: reserved, so no name a
/// build declares can collide with one of zoxy's own.
pub const metric_prefix = "zoxy_ext_";

pub const metric_name_bytes_max = constants.extension_metric_name_bytes_max;
pub const metric_help_bytes_max = constants.extension_metric_help_bytes_max;
pub const metrics_per_type_max = constants.extension_metrics_per_type_max;

/// One serving call's slots: its type's counters and gauges at the site
/// the call is for, in declaration order. Read and written through the
/// methods, which name a slot by the type's own declaration.
pub const Metrics = struct {
    counters: []u64 = &.{},
    gauges: []u64 = &.{},

    /// Count `delta` more of `Extension`'s counter `name`.
    pub fn add(
        metrics: Metrics,
        comptime Extension: type,
        comptime name: CounterName(Extension),
        delta: u64,
    ) void {
        metrics.assertOf(Extension);
        const cell = &metrics.counters[@backingInt(name)];
        // A counter that wrapped would read as one that went quiet.
        assert(cell.* <= std.math.maxInt(u64) - delta);
        cell.* += delta;
    }

    /// Set `Extension`'s gauge `name` to `level`.
    pub fn set(
        metrics: Metrics,
        comptime Extension: type,
        comptime name: GaugeName(Extension),
        level: u64,
    ) void {
        metrics.assertOf(Extension);
        metrics.gauges[@backingInt(name)] = level;
    }

    /// A counter's total at this site, for a type that reads its own.
    pub fn counter(metrics: Metrics, comptime Extension: type, comptime name: CounterName(Extension)) u64 {
        metrics.assertOf(Extension);
        return metrics.counters[@backingInt(name)];
    }

    /// A gauge's level at this site.
    pub fn gauge(metrics: Metrics, comptime Extension: type, comptime name: GaugeName(Extension)) u64 {
        metrics.assertOf(Extension);
        return metrics.gauges[@backingInt(name)];
    }

    /// The slots are `Extension`'s: one per declared counter and gauge.
    /// Slots of another site or kind with the same shape cannot be told
    /// apart here, but zoxy never hands a call any slots but its own.
    fn assertOf(metrics: Metrics, comptime Extension: type) void {
        assert(metrics.counters.len == counterCount(Extension));
        assert(metrics.gauges.len == gaugeCount(Extension));
    }
};

/// Whether `Extension` declares counters or gauges.
pub fn isMetered(comptime Extension: type) bool {
    return @hasDecl(Extension, "counters") or @hasDecl(Extension, "gauges");
}

/// `Extension`'s counters, by name.
pub fn CounterName(comptime Extension: type) type {
    return std.meta.FieldEnum(@TypeOf(declaredCounters(Extension)));
}

/// `Extension`'s gauges, by name.
pub fn GaugeName(comptime Extension: type) type {
    return std.meta.FieldEnum(@TypeOf(declaredGauges(Extension)));
}

pub fn counterCount(comptime Extension: type) u32 {
    return @typeInfo(@TypeOf(declaredCounters(Extension))).@"struct".field_names.len;
}

pub fn gaugeCount(comptime Extension: type) u32 {
    return @typeInfo(@TypeOf(declaredGauges(Extension))).@"struct".field_names.len;
}

/// `Extension.counters`, or the empty declaration.
pub fn declaredCounters(comptime Extension: type) @TypeOf(if (@hasDecl(Extension, "counters")) Extension.counters else .{}) {
    return if (@hasDecl(Extension, "counters")) Extension.counters else .{};
}

/// `Extension.gauges`, or the empty declaration.
pub fn declaredGauges(comptime Extension: type) @TypeOf(if (@hasDecl(Extension, "gauges")) Extension.gauges else .{}) {
    return if (@hasDecl(Extension, "gauges")) Extension.gauges else .{};
}

/// The build's metered types, each once, pickers first: the families the
/// metrics endpoint renders, in this order. A type listed both as a
/// picker and as a policy is one family.
pub fn metered(comptime extensions: Extensions) []const type {
    comptime {
        var families: []const type = &.{};
        for (extensions.pickers ++ extensions.request_policies) |Listed| {
            if (!isMetered(Listed)) continue;
            for (families) |Family| {
                if (Family == Listed) break;
            } else families = families ++ [_]type{Listed};
        }
        assert(families.len <= 2 * list_types_max);
        return families;
    }
}

/// `Extension`'s index in `metered(extensions)`.
pub fn familyIndex(comptime extensions: Extensions, comptime Extension: type) u16 {
    comptime {
        assert(isMetered(Extension));
        for (metered(extensions), 0..) |Family, index| {
            if (Family == Extension) return index;
        }
        unreachable;
    }
}

/// Refuse, at compile time, a metered type whose declarations would not
/// render as exposition text: a prefix or a name outside
/// `[a-z][a-z0-9_]*`, one past its bound, help that is not one line, or
/// a name declared both as a counter and as a gauge.
pub fn assertMetrics(comptime Extension: type) void {
    // Every byte of every name and help text is checked once, and each
    // counter's name is looked up among the gauges: bounded by the limits.
    @setEvalBranchQuota(4 * metrics_per_type_max * (metric_name_bytes_max + metric_help_bytes_max + metrics_per_type_max) + 1000);
    const name = @typeName(Extension);
    if (!@hasDecl(Extension, "metrics_prefix")) {
        @compileError(name ++ " declares counters or gauges but no `pub const metrics_prefix`");
    }
    if (!metricNameValid(Extension.metrics_prefix)) {
        @compileError(name ++ ".metrics_prefix must match [a-z][a-z0-9_]* and be at most " ++
            std.fmt.comptimePrint("{d}", .{metric_name_bytes_max}) ++ " bytes");
    }
    assertDeclared(Extension, declaredCounters(Extension), "counters");
    assertDeclared(Extension, declaredGauges(Extension), "gauges");
    for (@typeInfo(@TypeOf(declaredCounters(Extension))).@"struct".field_names) |counter_name| {
        if (@hasField(@TypeOf(declaredGauges(Extension)), counter_name)) {
            @compileError(name ++ " declares " ++ counter_name ++ " both as a counter and as a gauge");
        }
    }
}

/// Distinct prefixes do not make distinct series: `a` with `b_c` and
/// `a_b` with `c` both spell `zoxy_ext_a_b_c`, and one metric with two
/// `# HELP` lines is not exposition. Refuse the pair at compile time.
fn assertSeriesApart(comptime First: type, comptime Second: type) void {
    @setEvalBranchQuota(16 * metrics_per_type_max * metrics_per_type_max * metric_name_bytes_max + 1000);
    for (seriesSuffixes(First)) |first| {
        for (seriesSuffixes(Second)) |second| {
            if (std.mem.eql(u8, first, second)) {
                @compileError(@typeName(First) ++ " and " ++ @typeName(Second) ++
                    " both declare the series " ++ metric_prefix ++ first);
            }
        }
    }
}

/// Every series `Extension` declares, as `<prefix>_<name>`.
fn seriesSuffixes(comptime Extension: type) []const []const u8 {
    var suffixes: []const []const u8 = &.{};
    for (@typeInfo(@TypeOf(declaredCounters(Extension))).@"struct".field_names) |name| {
        suffixes = suffixes ++ [_][]const u8{Extension.metrics_prefix ++ "_" ++ name};
    }
    for (@typeInfo(@TypeOf(declaredGauges(Extension))).@"struct".field_names) |name| {
        suffixes = suffixes ++ [_][]const u8{Extension.metrics_prefix ++ "_" ++ name};
    }
    return suffixes;
}

fn assertDeclared(comptime Extension: type, comptime declared: anytype, comptime kind: []const u8) void {
    const name = @typeName(Extension);
    const info = @typeInfo(@TypeOf(declared));
    if (info != .@"struct") {
        @compileError(name ++ "." ++ kind ++ " must be a struct literal of name = \"help\"");
    }
    if (info.@"struct".field_names.len > metrics_per_type_max) {
        @compileError(name ++ " declares more " ++ kind ++ " than metrics_per_type_max");
    }
    for (info.@"struct".field_names) |metric_name| {
        if (!metricNameValid(metric_name)) {
            @compileError(name ++ "." ++ kind ++ "." ++ metric_name ++ " must match [a-z][a-z0-9_]*");
        }
        const help: []const u8 = @field(declared, metric_name);
        if (!metricHelpValid(help)) {
            @compileError(name ++ "." ++ kind ++ "." ++ metric_name ++
                "'s help must be one line, without a backslash, and at most " ++
                std.fmt.comptimePrint("{d}", .{metric_help_bytes_max}) ++ " bytes");
        }
    }
}

/// `[a-z][a-z0-9_]*`, and short enough: a Prometheus name the exposition
/// writes as it is, with nothing to escape.
fn metricNameValid(comptime text: []const u8) bool {
    if (text.len == 0 or text.len > metric_name_bytes_max) return false;
    if (!std.ascii.isLower(text[0])) return false;
    for (text) |byte| {
        if (!(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '_')) return false;
    }
    return true;
}

/// One line with nothing a `# HELP` line would have to escape.
fn metricHelpValid(comptime text: []const u8) bool {
    if (text.len == 0 or text.len > metric_help_bytes_max) return false;
    for (text) |byte| {
        if (byte == '\n' or byte == '\\') return false;
    }
    return true;
}

test "extension: equal runtimes name the same server" {
    // The whole serving path re-instantiates its siblings from the one
    // runtime it was given, so two spellings of the same value must
    // produce one type — or a connection's server would not be the
    // server that admitted it.
    const Probe = struct {
        fn Built(comptime runtime: Runtime) type {
            return struct {
                pub const io = runtime.Io;
            };
        }
    };
    const Io = struct {};
    const Picker = struct {};
    const first = Probe.Built(.{ .Io = Io, .extensions = .{ .pickers = &.{Picker} } });
    const second = Probe.Built(.{ .Io = Io, .extensions = .{ .pickers = &.{Picker} } });
    comptime assert(first == second);
    comptime assert(Probe.Built(.{ .Io = Io }) == Probe.Built(.{ .Io = Io, .extensions = .{} }));
    comptime assert(first != Probe.Built(.{ .Io = Io }));
}

test "extension: select names the listed type of the instance it is given" {
    const First = struct {
        calls: u32 = 0,
        pub fn pick(instance: *@This(), candidates: *const Candidates, input: *const PickInput) u16 {
            _ = candidates;
            _ = input;
            instance.calls += 1;
            return 0;
        }
    };
    const Second = struct {
        pub fn pick(instance: *@This(), candidates: *const Candidates, input: *const PickInput) u16 {
            _ = instance;
            _ = candidates;
            _ = input;
            return 0;
        }
    };
    const pickers: []const type = &.{ First, Second };
    comptime assertExtensions(.{ .pickers = pickers });
    var first: First = .{};
    var second: Second = .{};
    const of_first = select(pickers, &first);
    const of_second = select(pickers, &second);
    try std.testing.expectEqual(@as(u8, 0), of_first.index);
    try std.testing.expectEqual(@as(u8, 1), of_second.index);
    try std.testing.expect(of_first.instance == @as(*anyopaque, &first));
    try std.testing.expect(of_second.instance == @as(*anyopaque, &second));
}

test "extension: each metered type is one family, pickers first (#435)" {
    const Both = struct {
        pub const metrics_prefix = "both";
        pub const counters = .{ .calls = "Calls made." };
        pub fn pick(_: *@This(), _: *const Candidates, _: *const PickInput) u16 {
            return 0;
        }
        pub fn evaluate(_: *@This(), _: *const Request) Verdict {
            return .proceed;
        }
    };
    const Quiet = struct {
        pub fn evaluate(_: *@This(), _: *const Request) Verdict {
            return .proceed;
        }
    };
    const Gauged = struct {
        pub const metrics_prefix = "gauged";
        pub const gauges = .{ .level = "A level." };
        pub fn evaluate(_: *@This(), _: *const Request) Verdict {
            return .proceed;
        }
    };
    const extensions: Extensions = .{ .pickers = &.{Both}, .request_policies = &.{ Quiet, Both, Gauged } };
    comptime assertExtensions(extensions);
    const families = comptime metered(extensions);
    comptime assert(families.len == 2);
    comptime assert(families[0] == Both);
    comptime assert(families[1] == Gauged);
    comptime assert(familyIndex(extensions, Gauged) == 1);
    comptime assert(!isMetered(Quiet));
    comptime assert(counterCount(Gauged) == 0 and gaugeCount(Gauged) == 1);
    comptime assert(counterCount(Both) == 1 and gaugeCount(Both) == 0);

    var counters: [1]u64 = @splat(0);
    const metrics: Metrics = .{ .counters = &counters };
    metrics.add(Both, .calls, 2);
    try std.testing.expectEqual(@as(u64, 2), metrics.counter(Both, .calls));
}
