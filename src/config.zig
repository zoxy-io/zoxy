//! Static proxy configuration. Parsed once at startup (allocation is allowed
//! here — the *serving* path is what must not allocate; docs/DESIGN.md §1). The
//! resulting `Config` is immutable and owns all its strings/slices in an arena.
//! Format is JSON (std-only, zero external deps).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Ip4Address = std.Io.net.Ip4Address;

pub const Endpoint = struct {
    address: Ip4Address,
};

/// Sentinel for an unconfigured circuit-breaker limit: never trips.
pub const limit_none: u32 = std.math.maxInt(u32);

/// A cluster's resolved resilience settings (Phase 2, docs/DESIGN.md §7).
/// Defaults mean "feature off"; a present JSON block enables the feature with
/// per-field defaults from `constants`. All durations are pre-converted to
/// nanoseconds at parse time so the data path never does unit math. All
/// limits are per worker (share-nothing): a cluster-wide budget is the
/// configured value times the worker count.
pub const ResiliencePolicy = struct {
    /// Configured retry attempts after the first try; 0 = retries off (the
    /// built-in one-shot stale-pooled-connection replay stays either way).
    retry_max: u8 = 0,
    retry_backoff_base_ns: u63 = constants.retry_backoff_base_ns_default,
    retry_backoff_cap_ns: u63 = constants.retry_backoff_cap_ns_default,
    retry_budget_percent: u8 = constants.retry_budget_percent_default,
    retry_budget_min: u32 = constants.retry_budget_min_default,

    /// Deadline per upstream attempt (connect + time to first response
    /// byte); 0 = disabled. Enforced by the per-connection ticking timer,
    /// so it must be at least `constants.timeout_tick_ns`.
    per_try_timeout_ns: u63 = 0,

    // Circuit breaker (per worker): `limit_none` = unbounded.
    max_connections: u32 = limit_none,
    max_pending: u32 = limit_none,
    max_requests: u32 = limit_none,
    max_retries: u32 = limit_none,

    /// Passive outlier detection; 0 = off.
    outlier_consecutive_failures: u32 = 0,
    outlier_ejection_ns: u63 = constants.outlier_ejection_ns_default,
    outlier_ejection_percent_max: u8 = constants.outlier_ejection_percent_max_default,

    /// Active TCP health probes; 0 interval = off.
    health_interval_ns: u63 = 0,
    health_timeout_ns: u63 = constants.health_timeout_ns_default,
    health_threshold_healthy: u16 = constants.health_threshold_healthy_default,
    health_threshold_unhealthy: u16 = constants.health_threshold_unhealthy_default,
};

pub const Cluster = struct {
    name: []const u8,
    endpoints: []const Endpoint,
    /// Position within `Config.clusters`; always < `clusters_max`. Keys the
    /// per-cluster balancer state, which is reserved statically per worker.
    index: usize,
    policy: ResiliencePolicy,
};

pub const Route = struct {
    /// "*" matches any Host.
    host: []const u8,
    /// Matched as a prefix of the request target; "/" matches everything.
    path_prefix: []const u8,
    cluster: []const u8,
};

/// TLS termination identity (Phase 3, docs/DESIGN.md §6): file paths only.
/// This module stays FFI-free (the simulator imports it); reading and
/// validating the PEM files happens at startup in main via `tls/openssl.zig`.
pub const TlsConfig = struct {
    certificate_file: []const u8,
    private_key_file: []const u8,
    /// Hand completed handshakes to kernel TLS (docs/DESIGN.md §6); off
    /// forces every connection onto the userspace relay (ops escape hatch).
    kernel_offload: bool = true,
};

pub const Config = struct {
    gpa: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    listen: Ip4Address,
    /// Address of the admin/metrics endpoint; null disables it.
    admin: ?Ip4Address,
    /// TLS termination on the listener; null = plaintext.
    tls: ?TlsConfig,
    routes: []const Route,
    clusters: []const Cluster,

    pub fn deinit(config: Config) void {
        config.arena.deinit();
        config.gpa.destroy(config.arena);
    }

    pub fn find_cluster(config: Config, name: []const u8) ?*const Cluster {
        for (config.clusters) |*cluster| {
            if (std.mem.eql(u8, cluster.name, name)) return cluster;
        }
        return null;
    }
};

pub const ParseError = error{
    InvalidAddress,
    UnknownCluster,
    NoClusters,
    TooManyClusters,
    TooManyEndpoints,
    InvalidLimit,
    InvalidTls,
} || std.json.ParseError(std.json.Scanner) || std.mem.Allocator.Error;

/// JSON shape mirrored 1:1 for decoding, then lowered into `Config`.
const Dto = struct {
    listen: []const u8,
    admin: ?[]const u8 = null,
    tls: ?TlsDto = null,
    routes: []const RouteDto,
    clusters: []const ClusterDto,

    const TlsDto = struct {
        certificate_file: []const u8,
        private_key_file: []const u8,
        kernel_offload: bool = true,
    };
    const RouteDto = struct {
        host: []const u8 = "*",
        path_prefix: []const u8 = "/",
        cluster: []const u8,
    };
    const ClusterDto = struct {
        name: []const u8,
        endpoints: []const []const u8,
        retry: ?RetryDto = null,
        circuit_breaker: ?CircuitBreakerDto = null,
        outlier: ?OutlierDto = null,
        health_check: ?HealthCheckDto = null,
        per_try_timeout_ms: u32 = 0,
    };
    // Absent per-field values fall back to `constants` defaults during
    // lowering (kept out of the DTO so the defaults live in one place).
    const RetryDto = struct {
        max: u8,
        backoff_base_ms: ?u32 = null,
        backoff_cap_ms: ?u32 = null,
        budget_percent: ?u8 = null,
        budget_min: ?u32 = null,
    };
    const CircuitBreakerDto = struct {
        max_connections: ?u32 = null,
        max_pending: ?u32 = null,
        max_requests: ?u32 = null,
        max_retries: ?u32 = null,
    };
    const OutlierDto = struct {
        consecutive_failures: ?u32 = null,
        ejection_ms: ?u32 = null,
        max_ejection_percent: ?u8 = null,
    };
    const HealthCheckDto = struct {
        interval_ms: ?u32 = null,
        timeout_ms: ?u32 = null,
        healthy_threshold: ?u16 = null,
        unhealthy_threshold: ?u16 = null,
    };
};

pub fn parse(gpa: std.mem.Allocator, text: []const u8) ParseError!Config {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    // Decode into the DTO with a throwaway arena, then dupe what we keep.
    const parsed = try std.json.parseFromSlice(Dto, gpa, text, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const dto = parsed.value;

    // Balancer state is reserved statically, one counter per cluster index.
    if (dto.clusters.len > constants.clusters_max) return error.TooManyClusters;
    const clusters = try a.alloc(Cluster, dto.clusters.len);
    assert(clusters.len == dto.clusters.len);
    assert(clusters.len <= constants.clusters_max);
    for (dto.clusters, clusters, 0..) |dc, *cluster, index| {
        // Per-endpoint resilience state is reserved statically per worker.
        if (dc.endpoints.len > constants.endpoints_per_cluster_max) return error.TooManyEndpoints;
        const endpoints = try a.alloc(Endpoint, dc.endpoints.len);
        for (dc.endpoints, endpoints) |text_addr, *endpoint| {
            endpoint.* = .{ .address = try parse_address(text_addr) };
        }
        cluster.* = .{
            .name = try a.dupe(u8, dc.name),
            .endpoints = endpoints,
            .index = index,
            .policy = try resolve_policy(&dc),
        };
    }

    const routes = try a.alloc(Route, dto.routes.len);
    assert(routes.len == dto.routes.len);
    for (dto.routes, routes) |dr, *route| {
        route.* = .{
            .host = try a.dupe(u8, dr.host),
            .path_prefix = try a.dupe(u8, dr.path_prefix),
            .cluster = try a.dupe(u8, dr.cluster),
        };
    }

    // Validate every route references a real cluster before we commit.
    for (routes) |route| {
        if (find_cluster_in(clusters, route.cluster) == null) return error.UnknownCluster;
    }

    const tls: ?TlsConfig = if (dto.tls) |dt| lower: {
        if (dt.certificate_file.len == 0) return error.InvalidTls;
        if (dt.private_key_file.len == 0) return error.InvalidTls;
        break :lower .{
            .certificate_file = try a.dupe(u8, dt.certificate_file),
            .private_key_file = try a.dupe(u8, dt.private_key_file),
            .kernel_offload = dt.kernel_offload,
        };
    } else null;

    return .{
        .gpa = gpa,
        .arena = arena,
        .listen = try parse_address(dto.listen),
        .admin = if (dto.admin) |text_addr| try parse_address(text_addr) else null,
        .tls = tls,
        .routes = routes,
        .clusters = clusters,
    };
}

/// Lower a cluster's optional resilience blocks into a resolved policy:
/// absent block = feature off; absent field = `constants` default; every
/// configured value validated here so the data path can assert, not check.
fn resolve_policy(dc: *const Dto.ClusterDto) error{InvalidLimit}!ResiliencePolicy {
    var policy: ResiliencePolicy = .{};
    if (dc.retry) |retry| {
        if (retry.max == 0 or retry.max > constants.retry_attempts_max) return error.InvalidLimit;
        const percent = retry.budget_percent orelse constants.retry_budget_percent_default;
        if (percent == 0 or percent > 100) return error.InvalidLimit;
        policy.retry_max = retry.max;
        policy.retry_budget_percent = percent;
        policy.retry_budget_min = retry.budget_min orelse constants.retry_budget_min_default;
        if (retry.backoff_base_ms) |ms| policy.retry_backoff_base_ns = ms_to_ns(ms);
        if (retry.backoff_cap_ms) |ms| policy.retry_backoff_cap_ns = ms_to_ns(ms);
        if (policy.retry_backoff_base_ns == 0) return error.InvalidLimit;
        if (policy.retry_backoff_cap_ns < policy.retry_backoff_base_ns) return error.InvalidLimit;
    }
    if (dc.per_try_timeout_ms > 0) {
        policy.per_try_timeout_ns = ms_to_ns(dc.per_try_timeout_ms);
        // Enforced by the ticking timer; a deadline under one tick would
        // always be late by more than its own length.
        if (policy.per_try_timeout_ns < constants.timeout_tick_ns) return error.InvalidLimit;
    }
    if (dc.circuit_breaker) |breaker| {
        policy.max_connections = breaker.max_connections orelse limit_none;
        policy.max_pending = breaker.max_pending orelse limit_none;
        policy.max_requests = breaker.max_requests orelse limit_none;
        policy.max_retries = breaker.max_retries orelse limit_none;
        const limits = [_]u32{
            policy.max_connections, policy.max_pending,
            policy.max_requests,    policy.max_retries,
        };
        for (limits) |limit| if (limit == 0) return error.InvalidLimit;
    }
    if (dc.outlier) |outlier| {
        const failures = outlier.consecutive_failures orelse
            constants.outlier_consecutive_failures_default;
        const percent = outlier.max_ejection_percent orelse
            constants.outlier_ejection_percent_max_default;
        if (failures == 0 or percent == 0 or percent > 100) return error.InvalidLimit;
        policy.outlier_consecutive_failures = failures;
        policy.outlier_ejection_percent_max = percent;
        if (outlier.ejection_ms) |ms| policy.outlier_ejection_ns = ms_to_ns(ms);
        if (policy.outlier_ejection_ns == 0) return error.InvalidLimit;
    }
    if (dc.health_check) |health| return resolve_health(policy, &health);
    return policy;
}

fn resolve_health(
    base: ResiliencePolicy,
    health: *const Dto.HealthCheckDto,
) error{InvalidLimit}!ResiliencePolicy {
    var policy = base;
    assert(policy.health_interval_ns == 0); // health is resolved exactly once
    policy.health_interval_ns = if (health.interval_ms) |ms|
        ms_to_ns(ms)
    else
        constants.health_interval_ns_default;
    if (health.timeout_ms) |ms| policy.health_timeout_ns = ms_to_ns(ms);
    policy.health_threshold_healthy = health.healthy_threshold orelse
        constants.health_threshold_healthy_default;
    policy.health_threshold_unhealthy = health.unhealthy_threshold orelse
        constants.health_threshold_unhealthy_default;
    if (policy.health_interval_ns == 0 or policy.health_timeout_ns == 0) return error.InvalidLimit;
    if (policy.health_threshold_healthy == 0) return error.InvalidLimit;
    if (policy.health_threshold_unhealthy == 0) return error.InvalidLimit;
    return policy;
}

/// Config durations are milliseconds; the data path runs on nanoseconds.
/// u32 milliseconds always fit a u63 nanosecond count (2^32 * 10^6 < 2^63).
fn ms_to_ns(ms: u32) u63 {
    return @as(u63, ms) * std.time.ns_per_ms;
}

fn find_cluster_in(clusters: []const Cluster, name: []const u8) ?*const Cluster {
    for (clusters) |*cluster| {
        if (std.mem.eql(u8, cluster.name, name)) return cluster;
    }
    return null;
}

/// Parse "host:port" (IPv4) into an address.
fn parse_address(text: []const u8) error{InvalidAddress}!Ip4Address {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.InvalidAddress;
    assert(colon < text.len); // lastIndexOfScalar returns an in-bounds index
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.InvalidAddress;
    return Ip4Address.parse(text[0..colon], port) catch return error.InvalidAddress;
}

// ---- tests ----------------------------------------------------------------

const test_config =
    \\{
    \\  "listen": "0.0.0.0:8080",
    \\  "routes": [
    \\    { "host": "api.example.com", "path_prefix": "/v1", "cluster": "api" },
    \\    { "cluster": "default" }
    \\  ],
    \\  "clusters": [
    \\    { "name": "api", "endpoints": ["127.0.0.1:9001", "127.0.0.1:9002"] },
    \\    { "name": "default", "endpoints": ["127.0.0.1:9000"] }
    \\  ]
    \\}
;

test "config: parses listen, routes, clusters" {
    var config = try parse(std.testing.allocator, test_config);
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 8080), config.listen.port);
    try std.testing.expectEqual(@as(usize, 2), config.routes.len);
    try std.testing.expectEqual(@as(usize, 2), config.clusters.len);

    // Defaults are applied for the second route.
    try std.testing.expectEqualStrings("*", config.routes[1].host);
    try std.testing.expectEqualStrings("/", config.routes[1].path_prefix);

    const api = config.find_cluster("api").?;
    try std.testing.expectEqual(@as(usize, 2), api.endpoints.len);
    try std.testing.expectEqual(@as(u16, 9002), api.endpoints[1].address.port);
    try std.testing.expect(config.find_cluster("nope") == null);
}

test "config: admin endpoint is optional and parses when present" {
    var without = try parse(std.testing.allocator, test_config);
    defer without.deinit();
    try std.testing.expect(without.admin == null);

    var with = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "admin": "127.0.0.1:9901",
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    );
    defer with.deinit();
    try std.testing.expectEqual(@as(u16, 9901), with.admin.?.port);
}

test "config: tls block is optional, parses paths, rejects empty ones" {
    var without = try parse(std.testing.allocator, test_config);
    defer without.deinit();
    try std.testing.expect(without.tls == null);

    var with = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:443",
        \\  "tls": { "certificate_file": "cert.pem", "private_key_file": "key.pem" },
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    );
    defer with.deinit();
    try std.testing.expectEqualStrings("cert.pem", with.tls.?.certificate_file);
    try std.testing.expectEqualStrings("key.pem", with.tls.?.private_key_file);

    try std.testing.expectError(error.InvalidTls, parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:443",
        \\  "tls": { "certificate_file": "", "private_key_file": "key.pem" },
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    ));
}

test "config: rejects a route to an unknown cluster" {
    const bad =
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "ghost" }], "clusters": [] }
    ;
    try std.testing.expectError(error.UnknownCluster, parse(std.testing.allocator, bad));
}

test "config: rejects more clusters than clusters_max" {
    var buf: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try w.print("{{ \"listen\": \"0.0.0.0:80\", \"routes\": [], \"clusters\": [", .{});
    var i: usize = 0;
    while (i < constants.clusters_max + 1) : (i += 1) {
        if (i > 0) try w.print(",", .{});
        try w.print("{{ \"name\": \"c{d}\", \"endpoints\": [] }}", .{i});
    }
    try w.print("] }}", .{});
    try std.testing.expectError(
        error.TooManyClusters,
        parse(std.testing.allocator, w.buffered()),
    );
}

test "config: rejects an invalid address" {
    const bad =
        \\{ "listen": "not-an-address", "routes": [], "clusters": [] }
    ;
    try std.testing.expectError(error.InvalidAddress, parse(std.testing.allocator, bad));
}

test "config: absent resilience blocks mean every feature is off" {
    var config = try parse(std.testing.allocator, test_config);
    defer config.deinit();

    const policy = config.find_cluster("api").?.policy;
    try std.testing.expectEqual(@as(u8, 0), policy.retry_max);
    try std.testing.expectEqual(@as(u63, 0), policy.per_try_timeout_ns);
    try std.testing.expectEqual(limit_none, policy.max_connections);
    try std.testing.expectEqual(limit_none, policy.max_pending);
    try std.testing.expectEqual(limit_none, policy.max_requests);
    try std.testing.expectEqual(limit_none, policy.max_retries);
    try std.testing.expectEqual(@as(u32, 0), policy.outlier_consecutive_failures);
    try std.testing.expectEqual(@as(u63, 0), policy.health_interval_ns);
}

test "config: resilience blocks resolve fields, defaults, and ms to ns" {
    var config = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"],
        \\    "retry": { "max": 3, "backoff_base_ms": 50 },
        \\    "per_try_timeout_ms": 2000,
        \\    "circuit_breaker": { "max_requests": 128 },
        \\    "outlier": { "consecutive_failures": 7 },
        \\    "health_check": { "interval_ms": 1000 } }] }
    );
    defer config.deinit();

    const policy = config.find_cluster("c").?.policy;
    try std.testing.expectEqual(@as(u8, 3), policy.retry_max);
    try std.testing.expectEqual(@as(u63, 50 * std.time.ns_per_ms), policy.retry_backoff_base_ns);
    // Absent fields inside a present block fall back to constants defaults.
    try std.testing.expectEqual(
        constants.retry_backoff_cap_ns_default,
        policy.retry_backoff_cap_ns,
    );
    try std.testing.expectEqual(
        constants.retry_budget_percent_default,
        policy.retry_budget_percent,
    );
    try std.testing.expectEqual(constants.retry_budget_min_default, policy.retry_budget_min);
    try std.testing.expectEqual(@as(u63, 2 * std.time.ns_per_s), policy.per_try_timeout_ns);
    try std.testing.expectEqual(@as(u32, 128), policy.max_requests);
    try std.testing.expectEqual(limit_none, policy.max_connections);
    try std.testing.expectEqual(@as(u32, 7), policy.outlier_consecutive_failures);
    try std.testing.expectEqual(constants.outlier_ejection_ns_default, policy.outlier_ejection_ns);
    try std.testing.expectEqual(@as(u63, 1 * std.time.ns_per_s), policy.health_interval_ns);
    try std.testing.expectEqual(constants.health_timeout_ns_default, policy.health_timeout_ns);
    try std.testing.expectEqual(
        constants.health_threshold_healthy_default,
        policy.health_threshold_healthy,
    );
}

test "config: rejects more endpoints than endpoints_per_cluster_max" {
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try w.print(
        \\{{ "listen": "0.0.0.0:80", "routes": [],
        \\   "clusters": [{{ "name": "c", "endpoints": [
    , .{});
    var i: usize = 0;
    while (i < constants.endpoints_per_cluster_max + 1) : (i += 1) {
        if (i > 0) try w.print(",", .{});
        try w.print("\"127.0.0.1:{d}\"", .{9000 + i});
    }
    try w.print("] }}] }}", .{});
    try std.testing.expectError(
        error.TooManyEndpoints,
        parse(std.testing.allocator, w.buffered()),
    );
}

test "config: rejects out-of-range resilience limits" {
    const cases = [_][]const u8{
        // retry.max of zero (omit the block to disable) and beyond the cap
        \\"retry": { "max": 0 }
        ,
        \\"retry": { "max": 6 }
        ,
        // budget percent beyond 100
        \\"retry": { "max": 1, "budget_percent": 101 }
        ,
        // backoff cap below base
        \\"retry": { "max": 1, "backoff_base_ms": 100, "backoff_cap_ms": 50 }
        ,
        // per-try below one timer tick (1s)
        \\"per_try_timeout_ms": 500
        ,
        // zero-valued breaker limit (omit the field for unbounded)
        \\"circuit_breaker": { "max_requests": 0 }
        ,
        // zero outlier threshold / over-100 ejection share
        \\"outlier": { "consecutive_failures": 0 }
        ,
        \\"outlier": { "max_ejection_percent": 101 }
        ,
        // zero health interval / thresholds
        \\"health_check": { "interval_ms": 0 }
        ,
        \\"health_check": { "healthy_threshold": 0 }
        ,
    };
    for (cases) |case| {
        var buf: [1024]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try w.print(
            \\{{ "listen": "0.0.0.0:80", "routes": [],
            \\   "clusters": [{{ "name": "c", "endpoints": [], {s} }}] }}
        , .{case});
        try std.testing.expectError(
            error.InvalidLimit,
            parse(std.testing.allocator, w.buffered()),
        );
    }
}
