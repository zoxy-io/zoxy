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

/// Upstream re-encryption for one cluster (docs/DESIGN.md §6): connect to
/// its endpoints over TLS. Verification posture is explicit — a private CA
/// bundle plus the hostname to require (and offer as SNI), or `insecure`.
/// FFI-free (paths only): main loads and builds the client context.
pub const ClusterTlsConfig = struct {
    /// Certificate hostname requirement + SNI; null only when insecure.
    server_name: ?[:0]const u8,
    /// PEM bundle path for the trust store; null only when insecure.
    ca_file: ?[]const u8,
    insecure: bool,
};

pub const Cluster = struct {
    name: []const u8,
    endpoints: []const Endpoint,
    /// Position within `Config.clusters`; always < `clusters_max`. Keys the
    /// per-cluster balancer state, which is reserved statically per worker.
    index: usize,
    policy: ResiliencePolicy,
    /// Re-encrypt traffic to this cluster's endpoints; null = plaintext.
    tls: ?ClusterTlsConfig,
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
/// One additional server identity, selected when the client's SNI matches
/// any of its names (exact, or single-label "*." wildcards).
pub const TlsIdentity = struct {
    server_names: []const []const u8,
    certificate_file: []const u8,
    private_key_file: []const u8,
};

pub const TlsConfig = struct {
    certificate_file: []const u8,
    private_key_file: []const u8,
    /// Hand completed handshakes to kernel TLS (docs/DESIGN.md §6); off
    /// forces every connection onto the userspace relay (ops escape hatch).
    kernel_offload: bool = true,
    /// SNI identities beyond the default certificate; absent or unmatched
    /// SNI gets the default.
    additional_identities: []const TlsIdentity = &.{},
};

pub const Config = struct {
    gpa: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    listen: Ip4Address,
    /// Address of the admin/metrics endpoint; null disables it.
    admin: ?Ip4Address,
    /// Unix-socket path for hot-restart listener handoff (docs/DESIGN.md §7
    /// Phase 4); null disables hot restart.
    handoff: ?[]const u8,
    /// How accepted connections spread across workers (docs/DESIGN.md §7
    /// Phase 4). `reuseport`: one SO_REUSEPORT listener per worker, the
    /// kernel hashes — uniform at scale, but few long-lived connections pin
    /// small-sample variance. `shared`: one listener, every worker holds a
    /// pending accept — idle workers naturally pull more.
    accept_mode: AcceptMode,
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
    InvalidHandoff,
    InvalidAcceptMode,
} || std.json.ParseError(std.json.Scanner) || std.mem.Allocator.Error;

pub const AcceptMode = enum { reuseport, shared };

/// JSON shape mirrored 1:1 for decoding, then lowered into `Config`.
const Dto = struct {
    listen: []const u8,
    admin: ?[]const u8 = null,
    handoff: ?[]const u8 = null,
    accept_mode: []const u8 = "reuseport",
    tls: ?TlsDto = null,
    routes: []const RouteDto,
    clusters: []const ClusterDto,

    const TlsDto = struct {
        certificate_file: []const u8,
        private_key_file: []const u8,
        kernel_offload: bool = true,
        additional_identities: []const TlsIdentityDto = &.{},
    };
    const TlsIdentityDto = struct {
        server_names: []const []const u8,
        certificate_file: []const u8,
        private_key_file: []const u8,
    };
    const ClusterTlsDto = struct {
        server_name: ?[]const u8 = null,
        ca_file: ?[]const u8 = null,
        insecure: bool = false,
    };
    const RouteDto = struct {
        host: []const u8 = "*",
        path_prefix: []const u8 = "/",
        cluster: []const u8,
    };
    const ClusterDto = struct {
        name: []const u8,
        endpoints: []const []const u8,
        tls: ?ClusterTlsDto = null,
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
            .tls = try lower_cluster_tls(a, dc.tls),
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
        // The default identity counts toward the identity limit.
        if (dt.additional_identities.len + 1 > constants.tls_identities_max) {
            return error.InvalidTls;
        }
        const identities = try a.alloc(TlsIdentity, dt.additional_identities.len);
        for (dt.additional_identities, identities) |di, *identity| {
            if (di.server_names.len == 0) return error.InvalidTls;
            if (di.certificate_file.len == 0) return error.InvalidTls;
            if (di.private_key_file.len == 0) return error.InvalidTls;
            const names = try a.alloc([]const u8, di.server_names.len);
            for (di.server_names, names) |name, *duped| {
                if (name.len == 0) return error.InvalidTls;
                duped.* = try a.dupe(u8, name);
            }
            identity.* = .{
                .server_names = names,
                .certificate_file = try a.dupe(u8, di.certificate_file),
                .private_key_file = try a.dupe(u8, di.private_key_file),
            };
        }
        break :lower .{
            .certificate_file = try a.dupe(u8, dt.certificate_file),
            .private_key_file = try a.dupe(u8, dt.private_key_file),
            .kernel_offload = dt.kernel_offload,
            .additional_identities = identities,
        };
    } else null;

    return .{
        .gpa = gpa,
        .arena = arena,
        .listen = try parse_address(dto.listen),
        .admin = if (dto.admin) |text_addr| try parse_address(text_addr) else null,
        .handoff = if (dto.handoff) |path| blk: {
            // Must fit sockaddr_un.path as a NUL-terminated string.
            const path_max = @typeInfo(
                @FieldType(std.os.linux.sockaddr.un, "path"),
            ).array.len - 1;
            if (path.len == 0 or path.len > path_max) return error.InvalidHandoff;
            break :blk try a.dupe(u8, path);
        } else null,
        .accept_mode = std.meta.stringToEnum(AcceptMode, dto.accept_mode) orelse
            return error.InvalidAcceptMode,
        .tls = tls,
        .routes = routes,
        .clusters = clusters,
    };
}

/// An upstream TLS block must pick a verification posture explicitly:
/// either a CA bundle *and* the hostname to require, or a spelled-out
/// `"insecure": true` — a silently-unverified default would be a trap.
fn lower_cluster_tls(
    a: std.mem.Allocator,
    dto: ?Dto.ClusterTlsDto,
) (error{InvalidTls} || std.mem.Allocator.Error)!?ClusterTlsConfig {
    const dt = dto orelse return null;
    if (dt.insecure) {
        // Verification fields are contradictory next to `insecure`.
        if (dt.ca_file != null or dt.server_name != null) return error.InvalidTls;
        return .{ .server_name = null, .ca_file = null, .insecure = true };
    }
    const server_name = dt.server_name orelse return error.InvalidTls;
    const ca_file = dt.ca_file orelse return error.InvalidTls;
    if (server_name.len == 0 or ca_file.len == 0) return error.InvalidTls;
    return .{
        .server_name = try a.dupeZ(u8, server_name),
        .ca_file = try a.dupe(u8, ca_file),
        .insecure = false,
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

test "config: handoff path is optional, parses, and rejects the unfittable" {
    var without = try parse(std.testing.allocator, test_config);
    defer without.deinit();
    try std.testing.expect(without.handoff == null);

    var with = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "handoff": "/run/zoxy-handoff.sock",
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    );
    defer with.deinit();
    try std.testing.expectEqualStrings("/run/zoxy-handoff.sock", with.handoff.?);

    // Empty and longer-than-sockaddr_un paths are refused at parse time.
    const empty = parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "handoff": "",
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    );
    try std.testing.expectError(error.InvalidHandoff, empty);

    const long_path = "/tmp/" ++ "x" ** 120;
    var buf: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf,
        \\{{ "listen": "0.0.0.0:80", "handoff": "{s}",
        \\  "routes": [{{ "cluster": "c" }}],
        \\  "clusters": [{{ "name": "c", "endpoints": ["127.0.0.1:9000"] }}] }}
    , .{long_path});
    try std.testing.expectError(error.InvalidHandoff, parse(std.testing.allocator, text));
}

test "config: accept_mode defaults to reuseport, parses shared, rejects junk" {
    var default_mode = try parse(std.testing.allocator, test_config);
    defer default_mode.deinit();
    try std.testing.expectEqual(AcceptMode.reuseport, default_mode.accept_mode);

    var shared = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "accept_mode": "shared",
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    );
    defer shared.deinit();
    try std.testing.expectEqual(AcceptMode.shared, shared.accept_mode);

    const junk = parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "accept_mode": "round_robin",
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    );
    try std.testing.expectError(error.InvalidAcceptMode, junk);
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

test "config: tls additional identities parse and validate" {
    var parsed = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:443",
        \\  "tls": { "certificate_file": "cert.pem", "private_key_file": "key.pem",
        \\    "additional_identities": [
        \\      { "server_names": ["other.test", "*.other.test"],
        \\        "certificate_file": "other.pem", "private_key_file": "other_key.pem" } ] },
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    );
    defer parsed.deinit();
    const identities = parsed.tls.?.additional_identities;
    try std.testing.expectEqual(@as(usize, 1), identities.len);
    try std.testing.expectEqualStrings("other.test", identities[0].server_names[0]);
    try std.testing.expectEqualStrings("*.other.test", identities[0].server_names[1]);
    try std.testing.expectEqualStrings("other.pem", identities[0].certificate_file);

    // An identity without names has nothing to match: refused.
    try std.testing.expectError(error.InvalidTls, parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:443",
        \\  "tls": { "certificate_file": "cert.pem", "private_key_file": "key.pem",
        \\    "additional_identities": [
        \\      { "server_names": [], "certificate_file": "o.pem",
        \\        "private_key_file": "ok.pem" } ] },
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    ));
}

test "config: cluster tls block demands an explicit verification posture" {
    var verified = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"],
        \\    "tls": { "server_name": "origin.internal", "ca_file": "ca.pem" } }] }
    );
    defer verified.deinit();
    const tls = verified.clusters[0].tls.?;
    try std.testing.expectEqualStrings("origin.internal", tls.server_name.?);
    try std.testing.expectEqualStrings("ca.pem", tls.ca_file.?);
    try std.testing.expect(!tls.insecure);

    var insecure = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"],
        \\    "tls": { "insecure": true } }] }
    );
    defer insecure.deinit();
    try std.testing.expect(insecure.clusters[0].tls.?.insecure);

    // Neither posture chosen (or half of one) is a refusal, not a default.
    try std.testing.expectError(error.InvalidTls, parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"], "tls": {} }] }
    ));
    try std.testing.expectError(error.InvalidTls, parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"],
        \\    "tls": { "server_name": "origin.internal" } }] }
    ));
    // Contradiction: verification material next to insecure.
    try std.testing.expectError(error.InvalidTls, parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"],
        \\    "tls": { "insecure": true, "ca_file": "ca.pem" } }] }
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
