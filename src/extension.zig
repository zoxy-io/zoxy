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
/// types it is, and the instance itself, type-erased the way
/// `config.FileSource` carries its context. Built by `select`, which
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
    /// The listener the request arrived on, by config index.
    listener_index: u16,
    /// The cluster the route chose, or null before routing has run.
    cluster_index: ?u16,
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
    /// A fresh draw from zoxy's own seeded generator, for a picker
    /// that wants randomness and must stay deterministic (§9).
    entropy: u64,
};

/// The cluster a `bind` is called for.
pub const ClusterSite = struct {
    index: u16,
    name: []const u8,
    endpoints: []const io_module.Address,
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
    inline for (extensions.pickers, 0..) |Picker, index| {
        assertPicker(Picker);
        inline for (extensions.pickers[index + 1 ..]) |Later| {
            if (Picker == Later) @compileError(@typeName(Picker) ++ " is listed twice as a picker");
        }
    }
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
