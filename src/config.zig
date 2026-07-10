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

const assert = std.debug.assert;

pub const Config = struct {
    listeners: []const Listener,
    clusters: []const Cluster,
    connect_timeout_ms: u32,
    idle_timeout_ms: u32,
    drain_deadline_ms: u32,

    pub const Listener = struct {
        bind_address: std.Io.net.IpAddress,
        cluster_index: u16,
    };

    pub const Cluster = struct {
        name: []const u8,
        endpoints: []const std.Io.net.IpAddress,
    };
};

pub const ValidationError = error{
    ConfigTooLarge,
    ListenersEmpty,
    ListenersOverLimit,
    ListenerBindInvalid,
    ListenerBindDuplicate,
    ClusterUnknown,
    ClustersEmpty,
    ClustersOverLimit,
    ClusterNameDuplicate,
    EndpointsEmpty,
    EndpointsOverLimit,
    EndpointInvalid,
    EndpointPortZero,
    TimeoutZero,
    TimeoutOverLimit,
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

    assert(listeners.len >= 1);
    assert(clusters.len >= 1);
    return .{
        .listeners = listeners,
        .clusters = clusters,
        .connect_timeout_ms = parsed.timeouts.connect_ms,
        .idle_timeout_ms = parsed.timeouts.idle_ms,
        .drain_deadline_ms = parsed.timeouts.drain_deadline_ms,
    };
}

const ConfigJson = struct {
    listeners: []const ListenerJson,
    clusters: ClustersJson,
    timeouts: TimeoutsJson,
};

const ListenerJson = struct {
    bind: []const u8,
    cluster: []const u8,
};

const ClusterJson = struct {
    endpoints: []const []const u8,
};

const TimeoutsJson = struct {
    connect_ms: u32,
    idle_ms: u32,
    drain_deadline_ms: u32,
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
        listeners[index] = .{
            .bind_address = bind_address,
            .cluster_index = try clusterIndexOf(clusters, listener_json.cluster),
        };
    }
    assert(listeners.len == listeners_json.len);
    return listeners;
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
    const values = [_]u32{ timeouts.connect_ms, timeouts.idle_ms, timeouts.drain_deadline_ms };
    for (values) |value| {
        if (value == 0) {
            return error.TimeoutZero;
        }
        if (value > constants.timeout_ms_max) {
            return error.TimeoutOverLimit;
        }
    }
}

const example_json = @embedFile("example_config");

test "config: the shipped example parses and resolves" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    const parsed = try parse(arena_state.allocator(), example_json);
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.clusters.len);
    try std.testing.expectEqual(@as(u16, 0), parsed.listeners[0].cluster_index);
    try std.testing.expectEqual(@as(u16, 8080), parsed.listeners[0].bind_address.getPort());
    try std.testing.expectEqualStrings("origin", parsed.clusters[0].name);
    try std.testing.expectEqual(@as(u16, 9000), parsed.clusters[0].endpoints[0].getPort());
    try std.testing.expectEqual(@as(u32, 5000), parsed.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 60000), parsed.idle_timeout_ms);
    try std.testing.expectEqual(@as(u32, 10000), parsed.drain_deadline_ms);
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
            assert(listener.cluster_index < parsed.clusters.len);
        }
    } else |_| {}
}
