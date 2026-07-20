//! Strict JSON → arena-owned immutable `Config` (DESIGN.md §5): parsed
//! once at startup, never reloaded (§1 non-goal). Two stages: std.json
//! with strict options (unknown field → error, duplicate field → error)
//! into JSON-shaped structs, then validation and resolution into the
//! runtime shape — every limit gets its own error, every address is a
//! static socket literal (`IpAddress.parseLiteral` rejects hostnames, so
//! the no-DNS non-goal holds structurally). The returned `Config` may
//! reference both the arena and `json_bytes`; the caller keeps both alive
//! for the process lifetime.

const std = @import("std");

const constants = @import("constants.zig");
const router = @import("http/router.zig");
const filter = @import("http/filter.zig");
const parser = @import("http/parser.zig");
const render = @import("http/render.zig");

const assert = std.debug.assert;

pub const Config = struct {
    listeners: []const Listener,
    clusters: []const Cluster,
    connect_timeout_ms: u32,
    idle_timeout_ms: u32,
    drain_deadline_ms: u32,
    /// Absolute cap on a connection's age, regardless of activity (§6): it
    /// rides the same per-connection deadline timer as the idle timeout,
    /// clamping the activity-refreshed deadline so a continuously busy
    /// connection is still reaped. `0` disables the cap — the one timeout
    /// where zero is legal (an unbounded connection age), so it is optional
    /// in the JSON and defaults off.
    max_lifetime_ms: u32,
    /// Effective pool sizes (§5, §8). The comptime constants stay the
    /// hard, budget-asserted ceilings; config may only shrink below them
    /// — for capacity planning, and so the overload benchmark can hit
    /// the real shed rungs at loopback-feasible load. Defaulted so the
    /// test beds' literal configs keep the full pools.
    limits: Limits = .{},

    pub const Limits = struct {
        conn_slots: u32 = constants.conn_slots_max,
        relay_buffers: u32 = constants.relay_buffers_max,
        upstream_slots: u32 = constants.upstream_slots_max,
    };

    pub const Listener = struct {
        bind_address: std.Io.net.IpAddress,
        /// The §7 path-routing table, sorted longest-prefix-first and
        /// never empty. A listener configured with a single `"cluster"`
        /// resolves to one catch-all route (`prefix = "/"`); `l4`
        /// listeners always have exactly that one route (no path to
        /// match). Matched by `http/router.zig`.
        routes: []const router.Route,
        /// The §7 filter rules, in config order (evaluated top-down).
        /// Empty on the L4 path and whenever no `"filters"` were given.
        /// Compiled and interpreted by `http/filter.zig`.
        filters: []const filter.Rule = &.{},
        protocol: Protocol,

        /// What the listener speaks (§6, §7): `l4` relays bytes blindly,
        /// `http` runs the HTTP/1.1 reverse-proxy state machine. The
        /// JSON field is optional and defaults to `l4`, so pre-L7
        /// configs stay valid.
        pub const Protocol = enum(u1) {
            l4,
            http,
        };
    };

    pub const Cluster = struct {
        name: []const u8,
        endpoints: []const std.Io.net.IpAddress,
        /// The §7 endpoint-pick policy the balancer runs for this
        /// cluster. The JSON field is optional and defaults to `p2c` —
        /// the design's trajectory (§7: round-robin → P2C) — with `rr`
        /// kept for strict rotation (predictable spread, cache warming).
        pick: Pick = .p2c,

        pub const Pick = enum(u1) {
            rr,
            p2c,
        };
    };
};

pub const ValidationError = error{
    ConfigTooLarge,
    ListenersEmpty,
    ListenersOverLimit,
    ListenerBindInvalid,
    ListenerBindDuplicate,
    ListenerProtocolUnknown,
    ClusterUnknown,
    ClustersEmpty,
    ClustersOverLimit,
    ClusterNameDuplicate,
    ClusterPickUnknown,
    ListenerClusterOrRoutes,
    ListenerL4Routes,
    RoutesEmpty,
    RoutesOverLimit,
    RoutePrefixNotCanonical,
    RouteHostNotCanonical,
    RouteDuplicate,
    ListenerL4Filters,
    FiltersOverLimit,
    FilterMethodEmpty,
    FilterMethodUnknown,
    FilterHeaderMatchesOverLimit,
    FilterHeaderMatchKind,
    FilterHeaderContainsEmpty,
    FilterHeaderNameInvalid,
    FilterHeaderNameReserved,
    FilterHeaderValueInvalid,
    FilterActionsEmpty,
    FilterActionsOverLimit,
    FilterActionKind,
    FilterRejectStatus,
    FilterHeaderEditsOverLimit,
    EndpointsEmpty,
    EndpointsOverLimit,
    EndpointInvalid,
    EndpointPortZero,
    TimeoutZero,
    TimeoutOverLimit,
    LimitConnSlotsOutOfRange,
    LimitRelayBuffersOutOfRange,
    LimitRelayBuffersOverConnSlots,
    LimitUpstreamSlotsOutOfRange,
};

pub const ParseError = std.json.ParseError(std.json.Scanner) || ValidationError;

pub fn parse(arena: std.mem.Allocator, json_bytes: []const u8) ParseError!Config {
    if (json_bytes.len > constants.config_bytes_max) {
        return error.ConfigTooLarge;
    }

    const parsed = try std.json.parseFromSliceLeaky(ConfigJson, arena, json_bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
    });

    const clusters = try resolveClusters(arena, &parsed.clusters);
    const listeners = try resolveListeners(arena, parsed.listeners, clusters);
    try validateTimeouts(&parsed.timeouts);
    const limits = try resolveLimits(&parsed.limits);

    assert(listeners.len >= 1);
    assert(clusters.len >= 1);
    return .{
        .listeners = listeners,
        .clusters = clusters,
        .connect_timeout_ms = parsed.timeouts.connect_ms,
        .idle_timeout_ms = parsed.timeouts.idle_ms,
        .drain_deadline_ms = parsed.timeouts.drain_deadline_ms,
        .max_lifetime_ms = parsed.timeouts.max_lifetime_ms,
        .limits = limits,
    };
}

/// Resolve the effective pool sizes (§5, §8): the comptime constants are
/// the hard, budget-asserted ceilings — config may only shrink below
/// them, never grow past them, and never to zero. An unspecified
/// relay-buffer count derives from the effective conn slots (a buffer
/// beyond the slot count could never be acquired); a *specified* count
/// above them is a contradiction and fails loudly.
fn resolveLimits(limits_json: *const LimitsJson) ValidationError!Config.Limits {
    const conn_slots = limits_json.conn_slots orelse constants.conn_slots_max;
    if (conn_slots < 1 or conn_slots > constants.conn_slots_max) {
        return error.LimitConnSlotsOutOfRange;
    }
    const relay_buffers = limits_json.relay_buffers orelse
        @min(constants.relay_buffers_max, conn_slots);
    if (relay_buffers < 1 or relay_buffers > constants.relay_buffers_max) {
        return error.LimitRelayBuffersOutOfRange;
    }
    if (relay_buffers > conn_slots) {
        return error.LimitRelayBuffersOverConnSlots;
    }
    const upstream_slots = limits_json.upstream_slots orelse constants.upstream_slots_max;
    if (upstream_slots < 1 or upstream_slots > constants.upstream_slots_max) {
        return error.LimitUpstreamSlotsOutOfRange;
    }
    assert(relay_buffers <= conn_slots);
    return .{
        .conn_slots = conn_slots,
        .relay_buffers = relay_buffers,
        .upstream_slots = upstream_slots,
    };
}

const ConfigJson = struct {
    listeners: []const ListenerJson,
    clusters: ClustersJson,
    timeouts: TimeoutsJson,
    /// Optional pool shrinks (§5, §8); absent fields keep the comptime
    /// ceilings.
    limits: LimitsJson = .{},
};

const LimitsJson = struct {
    conn_slots: ?u32 = null,
    relay_buffers: ?u32 = null,
    upstream_slots: ?u32 = null,
};

const ListenerJson = struct {
    bind: []const u8,
    /// Exactly one of `cluster` (sugar for a single catch-all route) or
    /// `routes` (an explicit §7 path table) must be present.
    cluster: ?[]const u8 = null,
    routes: ?[]const RouteJson = null,
    /// Optional §7 filter rules; absent means none. HTTP-only.
    filters: ?[]const FilterJson = null,
    /// Optional: absent means `l4`, keeping pre-L7 configs valid.
    protocol: []const u8 = "l4",
};

const FilterJson = struct {
    match: MatchJson = .{},
    actions: []const ActionJson,
};

const MatchJson = struct {
    /// Registered method tokens (uppercase); absent = any method.
    method: ?[]const []const u8 = null,
    host: ?[]const u8 = null,
    path_prefix: ?[]const u8 = null,
    headers: ?[]const HeaderMatchJson = null,
};

const HeaderMatchJson = struct {
    name: []const u8,
    /// Exactly one of these selects the predicate kind.
    present: ?bool = null,
    equals: ?[]const u8 = null,
    contains: ?[]const u8 = null,
};

/// One action object carries exactly one field (the action's kind), the
/// same "struct of optionals, validate exactly-one" shape the listener's
/// cluster/routes fork uses — no JSON union parsing.
const ActionJson = struct {
    reject: ?u16 = null,
    header_set: ?HeaderEditJson = null,
    header_add: ?HeaderEditJson = null,
    header_remove: ?[]const u8 = null,
    rewrite_prefix: ?RewriteJson = null,
};

const HeaderEditJson = struct {
    name: []const u8,
    value: []const u8,
};

const RewriteJson = struct {
    from: []const u8,
    to: []const u8,
};

const RouteJson = struct {
    /// Optional §7 host scope; absent means the route matches any host.
    host: ?[]const u8 = null,
    prefix: []const u8,
    cluster: []const u8,
};

const ClusterJson = struct {
    endpoints: []const []const u8,
    /// Optional §7 pick policy; absent means `p2c` (the design's
    /// trajectory), `rr` opts back into strict rotation.
    pick: []const u8 = "p2c",
};

const TimeoutsJson = struct {
    connect_ms: u32,
    idle_ms: u32,
    drain_deadline_ms: u32,
    /// Optional: absent or `0` means "no cap" (§6). The default keeps every
    /// pre-existing config valid and leaves max-lifetime opt-in.
    max_lifetime_ms: u32 = 0,
};

/// JSON object map of cluster name → cluster, parsed into a bounded array
/// so duplicate keys can be rejected in stage 2 (std.json's map types
/// silently keep the last duplicate — negative space we refuse to have).
/// Bodies past the capacity are skipped but counted, so the over-limit
/// error stays distinct from a syntax error.
const ClustersJson = struct {
    entries: [constants.clusters_max]Entry,
    seen_count: u32,

    const Entry = struct {
        name: []const u8,
        cluster: ClusterJson,
    };

    /// Hard ceiling on keys consumed before giving up entirely — a bound
    /// on the bound (an adversarial config cannot spin this loop).
    const keys_seen_max: u32 = 4096;

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !@This() {
        var clusters: @This() = .{ .entries = undefined, .seen_count = 0 };
        if (try source.next() != .object_begin) {
            return error.UnexpectedToken;
        }
        while (true) {
            const token = try source.nextAlloc(allocator, .alloc_if_needed);
            const name: []const u8 = switch (token) {
                .object_end => break,
                .string => |slice| slice,
                .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            if (clusters.seen_count < constants.clusters_max) {
                clusters.entries[clusters.seen_count] = .{
                    .name = name,
                    .cluster = try std.json.innerParse(ClusterJson, allocator, source, options),
                };
            } else {
                try source.skipValue();
            }
            clusters.seen_count += 1;
            if (clusters.seen_count > keys_seen_max) {
                return error.UnexpectedToken;
            }
        }
        assert(clusters.seen_count <= keys_seen_max);
        return clusters;
    }
};

fn resolveClusters(
    arena: std.mem.Allocator,
    clusters_json: *const ClustersJson,
) ParseError![]const Config.Cluster {
    if (clusters_json.seen_count == 0) {
        return error.ClustersEmpty;
    }
    if (clusters_json.seen_count > constants.clusters_max) {
        return error.ClustersOverLimit;
    }

    const count: u16 = @intCast(clusters_json.seen_count);
    const clusters = try arena.alloc(Config.Cluster, count);
    for (clusters_json.entries[0..count], 0..) |entry, index| {
        for (clusters_json.entries[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, entry.name)) {
                return error.ClusterNameDuplicate;
            }
        }
        clusters[index] = .{
            .name = entry.name,
            .endpoints = try resolveEndpoints(arena, entry.cluster.endpoints),
            .pick = try pickOf(entry.cluster.pick),
        };
    }
    assert(clusters.len == count);
    return clusters;
}

fn resolveEndpoints(
    arena: std.mem.Allocator,
    endpoint_literals: []const []const u8,
) ParseError![]const std.Io.net.IpAddress {
    if (endpoint_literals.len == 0) {
        return error.EndpointsEmpty;
    }
    if (endpoint_literals.len > constants.endpoints_per_cluster_max) {
        return error.EndpointsOverLimit;
    }

    const endpoints = try arena.alloc(std.Io.net.IpAddress, endpoint_literals.len);
    for (endpoint_literals, endpoints) |literal, *endpoint| {
        endpoint.* = std.Io.net.IpAddress.parseLiteral(literal) catch {
            return error.EndpointInvalid;
        };
        if (endpoint.getPort() == 0) {
            return error.EndpointPortZero;
        }
    }
    assert(endpoints.len == endpoint_literals.len);
    return endpoints;
}

fn resolveListeners(
    arena: std.mem.Allocator,
    listeners_json: []const ListenerJson,
    clusters: []const Config.Cluster,
) ParseError![]const Config.Listener {
    assert(clusters.len >= 1);
    if (listeners_json.len == 0) {
        return error.ListenersEmpty;
    }
    if (listeners_json.len > constants.listeners_max) {
        return error.ListenersOverLimit;
    }

    const listeners = try arena.alloc(Config.Listener, listeners_json.len);
    for (listeners_json, 0..) |listener_json, index| {
        const bind_address = std.Io.net.IpAddress.parseLiteral(listener_json.bind) catch {
            return error.ListenerBindInvalid;
        };
        for (listeners[0..index]) |previous| {
            if (std.meta.eql(previous.bind_address, bind_address)) {
                return error.ListenerBindDuplicate;
            }
        }
        const protocol = try protocolOf(listener_json.protocol);
        listeners[index] = .{
            .bind_address = bind_address,
            .routes = try resolveRoutes(arena, &listener_json, clusters, protocol),
            .filters = try resolveFilters(arena, &listener_json, protocol),
            .protocol = protocol,
        };
    }
    assert(listeners.len == listeners_json.len);
    return listeners;
}

/// Compile a listener's §7 filter rules into immutable arena tables.
/// HTTP-only (an l4 listener has no head to match); absent = none. Match
/// keys are validated canonical so a filter and the router agree
/// byte-for-byte, and each action is validated at load, so the request-
/// time interpreter is bounded loops over trusted data.
fn resolveFilters(
    arena: std.mem.Allocator,
    listener_json: *const ListenerJson,
    protocol: Config.Listener.Protocol,
) ParseError![]const filter.Rule {
    const filters_json = listener_json.filters orelse return &.{};
    // Any `filters` key on an l4 listener is a mistake — l4 relays bytes,
    // there is no head to match on — so reject it whether the array is
    // populated or (vacuously) empty, before the empty-array shortcut.
    if (protocol == .l4) {
        return error.ListenerL4Filters;
    }
    if (filters_json.len == 0) {
        return &.{};
    }
    if (filters_json.len > constants.filters_per_listener_max) {
        return error.FiltersOverLimit;
    }
    const rules = try arena.alloc(filter.Rule, filters_json.len);
    var header_edits: u32 = 0;
    for (filters_json, rules) |rule_json, *rule| {
        rule.* = .{
            .match = try resolveMatch(arena, &rule_json.match),
            .actions = try resolveActions(arena, rule_json.actions),
        };
        header_edits += countHeaderEdits(rule.actions);
    }
    // A request applies the edits of every rule it matches, so the whole
    // table's edits bound one render's materialized set (§7). Cap the
    // total so the renderer's fixed buffer can never overflow.
    if (header_edits > constants.header_edits_max) {
        return error.FilterHeaderEditsOverLimit;
    }
    assert(rules.len == filters_json.len);
    assert(rules.len <= constants.filters_per_listener_max);
    return rules;
}

/// The number of header-edit actions (set/add/remove) in a rule — the
/// reject and rewrite actions contribute no render-time header edit.
fn countHeaderEdits(actions: []const filter.Action) u32 {
    assert(actions.len <= constants.actions_per_filter_max);
    var count: u32 = 0;
    for (actions) |action| {
        switch (action) {
            .header_set, .header_add, .header_remove => count += 1,
            .reject, .rewrite_prefix => {},
        }
    }
    assert(count <= actions.len); // Edits are a subset of the actions.
    return count;
}

fn resolveMatch(
    arena: std.mem.Allocator,
    match_json: *const MatchJson,
) ParseError!filter.Match {
    var match: filter.Match = .{};
    if (match_json.host) |host| {
        match.host = try validateRouteHost(host);
    }
    if (match_json.path_prefix) |prefix| {
        try validateRoutePrefix(prefix);
        match.path_prefix = prefix;
    }
    if (match_json.method) |tokens| {
        if (tokens.len == 0) {
            return error.FilterMethodEmpty;
        }
        var methods = std.EnumSet(parser.Method){};
        for (tokens) |token| {
            const method = parser.methodFromToken(token) orelse return error.FilterMethodUnknown;
            methods.insert(method);
        }
        match.methods = methods;
    }
    if (match_json.headers) |headers_json| {
        match.headers = try resolveHeaderMatches(arena, headers_json);
    }
    return match;
}

fn resolveHeaderMatches(
    arena: std.mem.Allocator,
    headers_json: []const HeaderMatchJson,
) ParseError![]const filter.HeaderMatch {
    if (headers_json.len > constants.header_matches_per_filter_max) {
        return error.FilterHeaderMatchesOverLimit;
    }
    const matches = try arena.alloc(filter.HeaderMatch, headers_json.len);
    for (headers_json, matches) |header_json, *match| {
        try validateHeaderName(header_json.name);
        // Exactly one predicate kind per header match.
        const set: u8 = @as(u8, @intFromBool(header_json.present != null)) +
            @intFromBool(header_json.equals != null) +
            @intFromBool(header_json.contains != null);
        assert(set <= 3); // The header match has three kind fields.
        if (set != 1) {
            return error.FilterHeaderMatchKind;
        }
        if (header_json.present) |present| {
            if (!present) {
                return error.FilterHeaderMatchKind; // "present: false" is not a predicate.
            }
            match.* = .{ .name = header_json.name, .kind = .present, .value = "" };
        } else if (header_json.equals) |value| {
            // An `equals: ""` predicate is meaningful — a header present
            // with an empty value — so the empty value is legal here.
            try validateHeaderValue(value);
            match.* = .{ .name = header_json.name, .kind = .equals, .value = value };
        } else {
            const needle = header_json.contains.?;
            // A `contains: ""` needle would match every present header
            // (`indexOf(x, "")` is always 0) — a degenerate `present` in
            // disguise. Reject it so `contains` is always a real substring.
            if (needle.len == 0) {
                return error.FilterHeaderContainsEmpty;
            }
            try validateHeaderValue(needle);
            match.* = .{ .name = header_json.name, .kind = .contains, .value = needle };
        }
    }
    assert(matches.len == headers_json.len);
    return matches;
}

fn resolveActions(
    arena: std.mem.Allocator,
    actions_json: []const ActionJson,
) ParseError![]const filter.Action {
    if (actions_json.len == 0) {
        return error.FilterActionsEmpty;
    }
    if (actions_json.len > constants.actions_per_filter_max) {
        return error.FilterActionsOverLimit;
    }
    const actions = try arena.alloc(filter.Action, actions_json.len);
    for (actions_json, actions) |action_json, *action| {
        action.* = try resolveAction(&action_json);
    }
    assert(actions.len == actions_json.len);
    assert(actions.len <= constants.actions_per_filter_max);
    return actions;
}

fn resolveAction(action_json: *const ActionJson) ParseError!filter.Action {
    // Exactly one action field carries the kind.
    const set: u8 = @as(u8, @intFromBool(action_json.reject != null)) +
        @intFromBool(action_json.header_set != null) +
        @intFromBool(action_json.header_add != null) +
        @intFromBool(action_json.header_remove != null) +
        @intFromBool(action_json.rewrite_prefix != null);
    assert(set <= 5); // The action object has five kind fields.
    if (set != 1) {
        return error.FilterActionKind;
    }
    if (action_json.reject) |status| {
        if (!filter.isRejectStatus(status)) {
            return error.FilterRejectStatus;
        }
        return .{ .reject = status };
    }
    if (action_json.header_set) |edit| {
        return .{ .header_set = try resolveHeaderEdit(&edit) };
    }
    if (action_json.header_add) |edit| {
        return .{ .header_add = try resolveHeaderEdit(&edit) };
    }
    if (action_json.header_remove) |name| {
        try validateEditableHeaderName(name);
        return .{ .header_remove = name };
    }
    const rewrite = action_json.rewrite_prefix.?;
    try validateRoutePrefix(rewrite.from);
    try validateRoutePrefix(rewrite.to);
    return .{ .rewrite_prefix = .{ .from = rewrite.from, .to = rewrite.to } };
}

/// Validate a name/value header edit shared by `header_set` and
/// `header_add`: an editable (non-proxy-managed) RFC 9110 token name and an
/// injection-safe field-value. Both actions carry the identical contract.
fn resolveHeaderEdit(edit: *const HeaderEditJson) ParseError!filter.HeaderEdit {
    try validateEditableHeaderName(edit.name);
    try validateHeaderValue(edit.value);
    return .{ .name = edit.name, .value = edit.value };
}

/// A header name must be a non-empty RFC 9110 token (no separators or
/// controls), so an edit or match names a real, unambiguous header.
fn validateHeaderName(name: []const u8) ParseError!void {
    if (name.len == 0) {
        return error.FilterHeaderNameInvalid;
    }
    assert(name.len >= 1); // Past the empty guard: the token scan is non-empty.
    for (name) |byte| {
        if (!isTokenByte(byte)) {
            return error.FilterHeaderNameInvalid;
        }
    }
}

/// An *edit* target must additionally not be a proxy-managed header: the
/// renderer owns hop-by-hop stripping, `Connection` injection, `Host`
/// routing, and the framing headers it committed to (§7). Letting a filter
/// set/add/remove one of those would smuggle a framing or persistence
/// change past the render's own decisions, so the compiled edit is proven
/// harmless at load. Match predicates carry no such restriction — reading
/// any header is safe.
fn validateEditableHeaderName(name: []const u8) ParseError!void {
    try validateHeaderName(name);
    assert(name.len >= 1); // A valid token; the managed lists are non-empty.
    for (render.hop_by_hop_names) |managed| {
        assert(managed.len >= 1);
        if (std.ascii.eqlIgnoreCase(name, managed)) {
            return error.FilterHeaderNameReserved;
        }
    }
    for (render.protected_names) |managed| {
        assert(managed.len >= 1);
        if (std.ascii.eqlIgnoreCase(name, managed)) {
            return error.FilterHeaderNameReserved;
        }
    }
}

/// A header value must be an RFC 9110 field-value: VCHAR / SP / HTAB /
/// obs-text, and never CR, LF, NUL, or another control. A value carrying
/// CRLF would inject a header when the renderer writes it upstream
/// (slice 3), so the compiled edit is proven injection-safe at load —
/// the same "already safe" guarantee the canonical host/path keys carry.
/// An empty value is legal. Applied to emitted values and, for symmetry,
/// to the compared match values. The per-byte test is the parser's own
/// `isForwardableByte`, so a filter and the parser share one definition.
fn validateHeaderValue(value: []const u8) ParseError!void {
    for (value) |byte| {
        if (!parser.isForwardableByte(byte)) {
            return error.FilterHeaderValueInvalid;
        }
    }
}

fn isTokenByte(byte: u8) bool {
    return switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'a'...'z', 'A'...'Z' => true,
        else => false,
    };
}

/// Resolve a listener's route table (§7). `"cluster": "x"` is sugar for a
/// single catch-all route; `"routes": [...]` is the explicit table.
/// Exactly one form is required. Prefixes must already be canonical (so
/// they compare directly against the canonical request path) and unique;
/// the table is sorted longest-prefix-first for the request-time scan.
/// `l4` listeners have no path, so they take only the `cluster` form.
fn resolveRoutes(
    arena: std.mem.Allocator,
    listener_json: *const ListenerJson,
    clusters: []const Config.Cluster,
    protocol: Config.Listener.Protocol,
) ParseError![]const router.Route {
    const has_cluster = listener_json.cluster != null;
    const has_routes = listener_json.routes != null;
    if (has_cluster == has_routes) {
        return error.ListenerClusterOrRoutes; // Neither, or both.
    }
    if (has_cluster) {
        const routes = try arena.alloc(router.Route, 1);
        routes[0] = .{
            .prefix = "/",
            .cluster_index = try clusterIndexOf(clusters, listener_json.cluster.?),
        };
        assert(routes.len == 1); // The sugar is always one catch-all route.
        return routes;
    }
    if (protocol == .l4) {
        return error.ListenerL4Routes; // L4 relays bytes; there is no path.
    }
    const routes_json = listener_json.routes.?;
    if (routes_json.len == 0) {
        return error.RoutesEmpty;
    }
    if (routes_json.len > constants.routes_max) {
        return error.RoutesOverLimit;
    }
    const routes = try arena.alloc(router.Route, routes_json.len);
    for (routes_json, 0..) |route_json, index| {
        try validateRoutePrefix(route_json.prefix);
        const host = if (route_json.host) |raw| try validateRouteHost(raw) else null;
        for (routes_json[0..index]) |previous| {
            // Earlier routes already passed validateRouteHost, so their raw
            // host equals its canonical form — a byte compare is sound.
            if (optionalHostEql(previous.host, host) and
                std.mem.eql(u8, previous.prefix, route_json.prefix))
            {
                return error.RouteDuplicate;
            }
        }
        routes[index] = .{
            .host = host,
            .prefix = route_json.prefix,
            .cluster_index = try clusterIndexOf(clusters, route_json.cluster),
        };
    }
    // Host-specific first, then longest-prefix-first (§7): the router's
    // linear scan then finds the most specific match first — any route
    // scoped to the request's host before any any-host route, and within a
    // group the longest prefix. Ties are rejected as duplicates above.
    std.mem.sort(router.Route, routes, {}, routeMoreSpecific);
    assert(routes.len >= 1);
    assert(routes.len <= constants.routes_max);
    return routes;
}

fn routeMoreSpecific(_: void, left: router.Route, right: router.Route) bool {
    const left_scoped = left.host != null;
    const right_scoped = right.host != null;
    if (left_scoped != right_scoped) {
        return left_scoped; // A host-scoped route sorts before an any-host one.
    }
    return left.prefix.len > right.prefix.len;
}

fn optionalHostEql(left: ?[]const u8, right: ?[]const u8) bool {
    const left_host = left orelse return right == null;
    const right_host = right orelse return false;
    return std.mem.eql(u8, left_host, right_host);
}

/// A route host must already be in §7 canonical form (lowercased,
/// port-stripped), so a request's canonical host compares byte-for-byte
/// against it. A host canonicalization would change — mixed case, a port,
/// oversize — is rejected at load, not silently mismatched at request time.
fn validateRouteHost(host: []const u8) ParseError![]const u8 {
    if (host.len == 0 or host.len > constants.host_bytes_max) {
        return error.RouteHostNotCanonical;
    }
    var out: [constants.host_bytes_max]u8 = undefined;
    const canonical = parser.canonicalHost(host, &out) orelse {
        return error.RouteHostNotCanonical;
    };
    if (!std.mem.eql(u8, canonical, host)) {
        return error.RouteHostNotCanonical;
    }
    return host; // The config slice, already canonical.
}

/// A route prefix must be an origin-form path already in canonical form,
/// so it compares byte-for-byte against the canonicalized request path
/// (§7) — no per-request normalization, no router/backend divergence. A
/// prefix that canonicalization would change (dot-segments, decodable or
/// structure-changing escapes, a missing leading slash, a query) is
/// rejected at load, not silently mismatched at request time.
fn validateRoutePrefix(prefix: []const u8) ParseError!void {
    if (prefix.len == 0 or prefix[0] != '/') {
        return error.RoutePrefixNotCanonical;
    }
    if (prefix.len > constants.head_bytes_max) {
        return error.RoutePrefixNotCanonical;
    }
    var out: [constants.head_bytes_max]u8 = undefined;
    const canonical = parser.canonicalTarget(prefix, &out) catch {
        return error.RoutePrefixNotCanonical;
    };
    if (canonical.query.len != 0 or !std.mem.eql(u8, canonical.path, prefix)) {
        return error.RoutePrefixNotCanonical;
    }
}

/// The closed pick-policy vocabulary; anything else is its own error so
/// a typo ("pc2") fails loudly instead of silently balancing as p2c.
fn pickOf(literal: []const u8) error{ClusterPickUnknown}!Config.Cluster.Pick {
    if (std.mem.eql(u8, literal, "rr")) {
        return .rr;
    }
    if (std.mem.eql(u8, literal, "p2c")) {
        return .p2c;
    }
    return error.ClusterPickUnknown;
}

/// The closed protocol vocabulary; anything else is its own error so a
/// typo ("htpp") fails loudly instead of silently relaying as L4.
fn protocolOf(literal: []const u8) error{ListenerProtocolUnknown}!Config.Listener.Protocol {
    if (std.mem.eql(u8, literal, "l4")) {
        return .l4;
    }
    if (std.mem.eql(u8, literal, "http")) {
        return .http;
    }
    return error.ListenerProtocolUnknown;
}

fn clusterIndexOf(
    clusters: []const Config.Cluster,
    name: []const u8,
) error{ClusterUnknown}!u16 {
    assert(clusters.len >= 1);
    assert(clusters.len <= constants.clusters_max);
    for (clusters, 0..) |cluster, index| {
        if (std.mem.eql(u8, cluster.name, name)) {
            return @intCast(index);
        }
    }
    return error.ClusterUnknown;
}

fn validateTimeouts(timeouts: *const TimeoutsJson) ValidationError!void {
    // The three lifecycle timeouts are correctness bounds — a 0 ms connect,
    // idle, or drain deadline would reap instantly, so zero is a mistake.
    const required = [_]u32{ timeouts.connect_ms, timeouts.idle_ms, timeouts.drain_deadline_ms };
    for (required) |value| {
        if (value == 0) {
            return error.TimeoutZero;
        }
        if (value > constants.timeout_ms_max) {
            return error.TimeoutOverLimit;
        }
    }
    // max_lifetime_ms is the one optional bound (§6): 0 means "no cap", so
    // only the shared ceiling is enforced — zero stays legal.
    if (timeouts.max_lifetime_ms > constants.timeout_ms_max) {
        return error.TimeoutOverLimit;
    }
}

const example_json = @embedFile("example_config");

test "config: the shipped example parses and resolves" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    const parsed = try parse(arena_state.allocator(), example_json);
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.clusters.len);
    // The `"cluster"` sugar resolves to one catch-all route.
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners[0].routes.len);
    try std.testing.expectEqualStrings("/", parsed.listeners[0].routes[0].prefix);
    try std.testing.expectEqual(@as(u16, 0), parsed.listeners[0].routes[0].cluster_index);
    try std.testing.expectEqual(Config.Listener.Protocol.l4, parsed.listeners[0].protocol);
    try std.testing.expectEqual(@as(u16, 8080), parsed.listeners[0].bind_address.getPort());
    try std.testing.expectEqualStrings("origin", parsed.clusters[0].name);
    try std.testing.expectEqual(@as(u16, 9000), parsed.clusters[0].endpoints[0].getPort());
    try std.testing.expectEqual(@as(u32, 5000), parsed.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 60000), parsed.idle_timeout_ms);
    try std.testing.expectEqual(@as(u32, 10000), parsed.drain_deadline_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
}

test "config: max_lifetime_ms is optional and defaults to disabled" {
    // The field is absent here — pre-existing configs stay valid and the
    // cap defaults off (§6).
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const parsed = try parse(arena_state.allocator(),
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
}

test "config: max_lifetime_ms accepts zero (the one legal zero timeout) and real values" {
    // Explicit 0 is legal — it is *not* a TimeoutZero, unlike the other
    // three timeouts (§6).
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(arena_state.allocator(),
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1,"max_lifetime_ms":0}}
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
    }
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(arena_state.allocator(),
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1,"max_lifetime_ms":1800000}}
        );
        try std.testing.expectEqual(@as(u32, 1_800_000), parsed.max_lifetime_ms);
    }
}

test "config: listener protocol defaults to l4 and accepts http" {
    // Absent field: pre-L7 configs stay valid.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(arena_state.allocator(),
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(Config.Listener.Protocol.l4, parsed.listeners[0].protocol);
    }
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(arena_state.allocator(),
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a","protocol":"http"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(Config.Listener.Protocol.http, parsed.listeners[0].protocol);
    }
}

test "config: explicit routes resolve, sorted longest-prefix-first" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const parsed = try parse(arena_state.allocator(),
        \\{"listeners":[{"bind":"127.0.0.1:1","protocol":"http","routes":[
        \\   {"prefix":"/","cluster":"root"},
        \\   {"prefix":"/api/v2","cluster":"v2"},
        \\   {"prefix":"/api","cluster":"api"}]}],
        \\ "clusters":{"root":{"endpoints":["127.0.0.1:2"]},
        \\   "api":{"endpoints":["127.0.0.1:3"]},
        \\   "v2":{"endpoints":["127.0.0.1:4"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    const routes = parsed.listeners[0].routes;
    try std.testing.expectEqual(@as(usize, 3), routes.len);
    // Descending by prefix length, whatever the config order.
    try std.testing.expectEqualStrings("/api/v2", routes[0].prefix);
    try std.testing.expectEqualStrings("/api", routes[1].prefix);
    try std.testing.expectEqualStrings("/", routes[2].prefix);
    // The cluster the router will hand back for the longest match.
    try std.testing.expectEqual(
        @as(?u16, routes[0].cluster_index),
        router.route(routes, null, "/api/v2/x"),
    );
    try std.testing.expectEqual(
        @as(?u16, routes[2].cluster_index),
        router.route(routes, null, "/elsewhere"),
    );
}

test "config: routing schema rejects malformed tables" {
    const base_clusters =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    ;
    // Neither cluster nor routes.
    try expectParseError(error.ListenerClusterOrRoutes, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"}]," ++ base_clusters);
    // Both cluster and routes.
    try expectParseError(error.ListenerClusterOrRoutes, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"a\"," ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // Routes on an l4 listener: there is no path to match.
    try expectParseError(error.ListenerL4Routes, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"l4\"," ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // Empty routes table.
    try expectParseError(error.RoutesEmpty, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[]}]," ++ base_clusters);
    // A non-canonical prefix (dot-segment) — would mismatch at request time.
    try expectParseError(error.RoutePrefixNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"prefix\":\"/a/../b\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // A prefix without a leading slash.
    try expectParseError(error.RoutePrefixNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"prefix\":\"api\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // Duplicate (host, prefix) — same any-host prefix twice.
    try expectParseError(error.RouteDuplicate, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"prefix\":\"/x\",\"cluster\":\"a\"}," ++
        "{\"prefix\":\"/x\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // A non-canonical host (uppercase) — would mismatch at request time.
    try expectParseError(error.RouteHostNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"host\":\"API.Example.com\",\"prefix\":\"/\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // A host carrying a port — the port is not part of the routing name.
    try expectParseError(error.RouteHostNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"host\":\"api.example.com:8080\",\"prefix\":\"/\",\"cluster\":\"a\"}]}]," ++ base_clusters);
    // An unknown cluster named by a route.
    try expectParseError(error.ClusterUnknown, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"ghost\"}]}]," ++ base_clusters);
}

test "config: host routes resolve, host-specific sorted before any-host" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const parsed = try parse(arena_state.allocator(),
        \\{"listeners":[{"bind":"127.0.0.1:1","protocol":"http","routes":[
        \\   {"prefix":"/","cluster":"root"},
        \\   {"host":"api.example.com","prefix":"/","cluster":"api"},
        \\   {"host":"api.example.com","prefix":"/v2","cluster":"v2"}]}],
        \\ "clusters":{"root":{"endpoints":["127.0.0.1:2"]},
        \\   "api":{"endpoints":["127.0.0.1:3"]},
        \\   "v2":{"endpoints":["127.0.0.1:4"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    const routes = parsed.listeners[0].routes;
    try std.testing.expectEqual(@as(usize, 3), routes.len);
    // Host-specific first (longest-prefix within), then any-host.
    try std.testing.expectEqualStrings("api.example.com", routes[0].host.?);
    try std.testing.expectEqualStrings("/v2", routes[0].prefix);
    try std.testing.expectEqualStrings("api.example.com", routes[1].host.?);
    try std.testing.expectEqualStrings("/", routes[1].prefix);
    try std.testing.expectEqual(@as(?[]const u8, null), routes[2].host);
    // The router hands host-specificity precedence over prefix length.
    try std.testing.expectEqual(
        @as(?u16, routes[1].cluster_index),
        router.route(routes, "api.example.com", "/other"),
    );
    try std.testing.expectEqual(
        @as(?u16, routes[2].cluster_index),
        router.route(routes, "other.example.com", "/v2"),
    );
}

test "config: filters compile into rules with matches and actions" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const parsed = try parse(arena_state.allocator(),
        \\{"listeners":[{"bind":"127.0.0.1:1","protocol":"http","cluster":"a","filters":[
        \\   {"match":{"method":["GET","POST"],"path_prefix":"/admin",
        \\             "headers":[{"name":"X-Env","equals":"prod"}]},
        \\    "actions":[{"reject":403}]},
        \\   {"match":{"host":"api.example"},
        \\    "actions":[{"header_set":{"name":"X-Via","value":"zoxy"}},
        \\               {"rewrite_prefix":{"from":"/old","to":"/new"}}]}]}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    const filters = parsed.listeners[0].filters;
    try std.testing.expectEqual(@as(usize, 2), filters.len);

    // Rule 0: method set + path prefix + one header-equals match, reject 403.
    const rule0 = filters[0];
    try std.testing.expect(rule0.match.methods.?.contains(.get));
    try std.testing.expect(rule0.match.methods.?.contains(.post));
    try std.testing.expect(!rule0.match.methods.?.contains(.delete));
    try std.testing.expectEqualStrings("/admin", rule0.match.path_prefix.?);
    try std.testing.expectEqual(@as(usize, 1), rule0.match.headers.len);
    try std.testing.expectEqualStrings("X-Env", rule0.match.headers[0].name);
    try std.testing.expectEqual(filter.HeaderMatch.Kind.equals, rule0.match.headers[0].kind);
    try std.testing.expectEqual(@as(usize, 1), rule0.actions.len);
    try std.testing.expectEqual(@as(u16, 403), rule0.actions[0].reject);

    // Rule 1: host match, header_set then rewrite_prefix.
    const rule1 = filters[1];
    try std.testing.expectEqualStrings("api.example", rule1.match.host.?);
    try std.testing.expectEqual(@as(?std.EnumSet(parser.Method), null), rule1.match.methods);
    try std.testing.expectEqual(@as(usize, 2), rule1.actions.len);
    try std.testing.expectEqualStrings("X-Via", rule1.actions[0].header_set.name);
    try std.testing.expectEqualStrings("/new", rule1.actions[1].rewrite_prefix.to);
}

test "config: filter schema rejects malformed rules" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\",\"cluster\":\"a\",\"filters\":[";
    // L4 listener may not carry filters.
    try expectParseError(error.ListenerL4Filters, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"l4\",\"cluster\":\"a\"," ++
        "\"filters\":[{\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // Even a vacuously empty filters array on l4 is a mistake — the key is
    // meaningless there, and an empty array must not slip past the guard.
    try expectParseError(error.ListenerL4Filters, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"l4\",\"cluster\":\"a\"," ++
        "\"filters\":[]}]," ++ tail);
    // A rule with no actions.
    try expectParseError(error.FilterActionsEmpty, head ++ "{\"actions\":[]}]}]," ++ tail);
    // An action object with no kind set.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{}]}]}]," ++ tail);
    // An action object with two kinds set.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{\"reject\":403,\"header_remove\":\"X\"}]}]}]," ++ tail);
    // A reject status outside the policy set.
    try expectParseError(error.FilterRejectStatus, head ++ "{\"actions\":[{\"reject\":503}]}]}]," ++ tail);
    // An unknown / lowercase method token.
    try expectParseError(error.FilterMethodUnknown, head ++ "{\"match\":{\"method\":[\"get\"]},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // A header match with no predicate kind.
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\"}]},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // A `contains` predicate with an empty needle: it would match every
    // present header (a degenerate `present`), so it is rejected.
    try expectParseError(error.FilterHeaderContainsEmpty, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\",\"contains\":\"\"}]},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // A non-canonical match path prefix.
    try expectParseError(error.RoutePrefixNotCanonical, head ++ "{\"match\":{\"path_prefix\":\"/a/../b\"},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // A header edit with an invalid header name.
    try expectParseError(error.FilterHeaderNameInvalid, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"Bad Name\",\"value\":\"v\"}}]}]}]," ++ tail);
    // A header value carrying CRLF — a smuggling vector when rendered.
    try expectParseError(error.FilterHeaderValueInvalid, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"X\",\"value\":\"a\\r\\nInjected: 1\"}}]}]}]," ++ tail);
    // "present: false" is not a predicate.
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\",\"present\":false}]},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
    // A rewrite whose target is not canonical.
    try expectParseError(error.RoutePrefixNotCanonical, head ++ "{\"actions\":[{\"rewrite_prefix\":{\"from\":\"/a\",\"to\":\"/b/../c\"}}]}]}]," ++ tail);
    // A header edit may not name a proxy-managed header — case-insensitively.
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"Host\",\"value\":\"evil\"}}]}]}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_remove\":\"content-length\"}]}]}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_add\":{\"name\":\"Connection\",\"value\":\"close\"}}]}]}]," ++ tail);
    // A matched header predicate may still name a managed header (read-only).
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"Host\"}]},\"actions\":[{\"reject\":403}]}]}]," ++ tail);
}

test "config: a filter set over the header-edit budget is rejected" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    ;
    // One header_edits_max+1 header edits spread one-per-rule (each rule
    // stays under actions_per_filter_max): the whole-table total is what
    // the renderer's fixed buffer must hold, so it is the total that caps.
    const rules = comptime blk: {
        var s: []const u8 = "";
        var edit: u16 = 0;
        while (edit < constants.header_edits_max + 1) : (edit += 1) {
            if (edit != 0) s = s ++ ",";
            s = s ++ "{\"actions\":[{\"header_remove\":\"X-Drop\"}]}";
        }
        break :blk s;
    };
    const json = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"protocol\":\"http\"," ++
        "\"cluster\":\"a\",\"filters\":[" ++ rules ++ "]}]," ++ tail;
    try expectParseError(error.FilterHeaderEditsOverLimit, json);
}

test "config: cluster pick policy parses, defaults to p2c, rejects typos" {
    // Explicit rr and p2c both resolve; absent defaults to p2c.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(arena_state.allocator(),
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"pick":"rr"},
            \\   "b":{"endpoints":["127.0.0.1:3"],"pick":"p2c"},
            \\   "c":{"endpoints":["127.0.0.1:4"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(Config.Cluster.Pick.rr, parsed.clusters[0].pick);
        try std.testing.expectEqual(Config.Cluster.Pick.p2c, parsed.clusters[1].pick);
        try std.testing.expectEqual(Config.Cluster.Pick.p2c, parsed.clusters[2].pick);
    }
    // A typo must not silently balance as the default.
    try expectParseError(error.ClusterPickUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"pick":"pc2"}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
}

test "config: limits shrink pools below the ceilings, never past them" {
    // Partial limits: relay buffers derive from the effective conn slots.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(arena_state.allocator(),
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1},
            \\ "limits":{"conn_slots":64}}
        );
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.conn_slots);
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.relay_buffers);
        try std.testing.expectEqual(constants.upstream_slots_max, parsed.limits.upstream_slots);
    }
    // Full limits resolve verbatim; absent block keeps the ceilings.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(arena_state.allocator(),
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1},
            \\ "limits":{"conn_slots":64,"relay_buffers":8,"upstream_slots":8}}
        );
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.conn_slots);
        try std.testing.expectEqual(@as(u32, 8), parsed.limits.relay_buffers);
        try std.testing.expectEqual(@as(u32, 8), parsed.limits.upstream_slots);
    }
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(arena_state.allocator(),
            \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(constants.conn_slots_max, parsed.limits.conn_slots);
        try std.testing.expectEqual(constants.relay_buffers_max, parsed.limits.relay_buffers);
        try std.testing.expectEqual(constants.upstream_slots_max, parsed.limits.upstream_slots);
    }
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1},
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"cluster\":\"a\"}],";
    // Zero and over-ceiling both fail loudly, each with its own error.
    try expectParseError(error.LimitConnSlotsOutOfRange, head ++ tail ++ "\"limits\":{\"conn_slots\":0}}");
    try expectParseError(error.LimitConnSlotsOutOfRange, head ++ tail ++ "\"limits\":{\"conn_slots\":99999}}");
    try expectParseError(error.LimitRelayBuffersOutOfRange, head ++ tail ++ "\"limits\":{\"relay_buffers\":0}}");
    // Over-ceiling relay buffers alone hit the range check, not the
    // conn-slot contradiction — the range check has precedence.
    try expectParseError(error.LimitRelayBuffersOutOfRange, head ++ tail ++ "\"limits\":{\"relay_buffers\":99999}}");
    try expectParseError(error.LimitUpstreamSlotsOutOfRange, head ++ tail ++ "\"limits\":{\"upstream_slots\":0}}");
    try expectParseError(error.LimitUpstreamSlotsOutOfRange, head ++ tail ++ "\"limits\":{\"upstream_slots\":99999}}");
    // A specified relay-buffer count above the conn slots is a
    // contradiction, not a derivable default.
    try expectParseError(error.LimitRelayBuffersOverConnSlots, head ++ tail ++
        "\"limits\":{\"conn_slots\":4,\"relay_buffers\":8}}");
}

test "config: unknown listener protocol fails loudly" {
    // A typo must not silently relay as L4.
    try expectParseError(error.ListenerProtocolUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a","protocol":"htpp"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
}

test "config: max_lifetime_ms still obeys the shared ceiling" {
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1,"max_lifetime_ms":3600001}}
    );
}

fn expectParseError(expected: ParseError, json_bytes: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(expected, parse(arena_state.allocator(), json_bytes));
}

test "config: strictness rejects unknown and duplicate fields" {
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a","nope":1}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.DuplicateField,
        \\{"listeners":[],"listeners":[],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ClusterNameDuplicate,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]},"a":{"endpoints":["127.0.0.1:3"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.MissingField,
        \\{"clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
}

test "config: references and addresses are validated" {
    try expectParseError(error.ClusterUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"missing"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    // Hostnames are structurally unresolvable: static addresses only (§1).
    try expectParseError(error.EndpointInvalid,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["origin.internal:80"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointPortZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:0"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ListenerBindInvalid,
        \\{"listeners":[{"bind":"not-an-address","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ListenerBindDuplicate,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"},
        \\               {"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
}

test "config: every emptiness and limit has its own error" {
    try expectParseError(error.ListenersEmpty,
        \\{"listeners":[],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ClustersEmpty,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointsEmpty,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":[]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.TimeoutZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":0,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","cluster":"a"}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":3600001,"idle_ms":1,"drain_deadline_ms":1}}
    );
}

test "config: listeners over the limit" {
    comptime var over_limit_json: []const u8 =
        \\{"listeners":[
    ;
    comptime {
        var index: u32 = 0;
        while (index <= constants.listeners_max) : (index += 1) {
            if (index > 0) over_limit_json = over_limit_json ++ ",";
            over_limit_json = over_limit_json ++ std.fmt.comptimePrint(
                \\{{"bind":"127.0.0.1:{d}","cluster":"a"}}
            , .{1000 + index});
        }
        over_limit_json = over_limit_json ++
            \\],"clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":1,"drain_deadline_ms":1}}
        ;
    }
    try expectParseError(error.ListenersOverLimit, over_limit_json);
}

test "config: oversized input is rejected before parsing" {
    const oversized = [_]u8{' '} ** (constants.config_bytes_max + 1);
    try expectParseError(error.ConfigTooLarge, &oversized);
}

var fuzz_arena_buffer: [1 << 20]u8 = undefined;

// Coverage-guided mode (`zig build test --fuzz`) is currently blocked by a
// Zig 0.16.0 toolchain bug: the bundled compiler/test_runner.zig fails to
// compile under -ffuzz (StackTrace type mismatch, line 566). The corpus
// still runs deterministically as part of `zig build test`.
test "fuzz: parse never panics — parse or reject, no third outcome" {
    try std.testing.fuzz({}, fuzzParse, .{ .corpus = &.{example_json} });
}

fn fuzzParse(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input_buffer: [4096]u8 = undefined;
    const input_len = smith.slice(&input_buffer);
    assert(input_len <= input_buffer.len);
    const input = input_buffer[0..input_len];

    var fixed = std.heap.FixedBufferAllocator.init(&fuzz_arena_buffer);
    if (parse(fixed.allocator(), input)) |parsed| {
        // Success implies the resolved invariants hold — no third outcome.
        assert(parsed.listeners.len >= 1);
        assert(parsed.clusters.len >= 1);
        for (parsed.listeners) |listener| {
            assert(listener.routes.len >= 1);
            assert(listener.routes.len <= constants.routes_max);
            for (listener.routes) |route| {
                assert(route.cluster_index < parsed.clusters.len);
                assert(route.prefix.len >= 1);
                assert(route.prefix[0] == '/');
            }
        }
    } else |_| {}
}
