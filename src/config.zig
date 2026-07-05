//! Static proxy configuration. Parsed once at startup (allocation is allowed
//! here — the *serving* path is what must not allocate; docs/DESIGN.md §1). The
//! resulting `Config` is immutable and owns all its strings/slices in an arena.
//! Format is JSON (std-only, zero external deps).

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const maglev = @import("proxy/maglev.zig");
const Ip4Address = std.Io.net.Ip4Address;

/// The Zoxyfile DSL → JSON adapter (docs/DESIGN.md §7 Phase 6, slice 3). A
/// human-authored surface that lowers to the JSON this module parses; reached
/// via `load_text` on a non-`.json` path. JSON stays the single source of truth.
pub const adapter = @import("config_adapter.zig");

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
    /// What the consistent hash keys on (`lb` block; meaningful only when
    /// `maglev_table` is non-empty).
    hash_on: HashOn,
    /// Header name for `hash_on = .header`; empty otherwise. A request
    /// missing the header falls back to P2C for that request.
    hash_header: []const u8,
    /// Maglev lookup table (endpoint indices), built here at parse time —
    /// the one place allocation is allowed. Empty = P2C least-request.
    maglev_table: []const u8,
};

pub const HashOn = enum { target, header };

/// Balancing policy for a cluster's `lb` block. The accepted policy strings
/// are these enum names — sourced here so both the parser (`lower_lb`) and the
/// generated JSON Schema draw the value set from one place.
pub const LbPolicy = enum { least_request, maglev };

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
    /// Offer HTTP/2 in ALPN (docs/DESIGN.md §7 Phase 5). When a client
    /// negotiates `h2`, the handshaker hands the connection to the H2 data
    /// path; everything else stays HTTP/1.1. Off by default.
    http2: bool = false,
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
    InvalidLb,
} || std.json.ParseError(std.json.Scanner) || std.mem.Allocator.Error;

pub const AcceptMode = enum { reuseport, shared };

/// A JSON Schema `pattern`/example hint for "host:port" IPv4 address strings
/// (validated for real by `parse_address`; the pattern is a docs/editor hint).
const hostport_pattern = "^(\\d{1,3}\\.){3}\\d{1,3}:\\d{1,5}$";

/// JSON shape mirrored 1:1 for decoding, then lowered into `Config`. Public so
/// `config_schema.zig` can reflect over it to emit the JSON Schema. Each struct
/// carries `schema_doc` (object prose) and `schema_fields` (per-field docs);
/// `assert_meta_matches` cross-checks the metadata against the fields at
/// comptime, so the two can never drift.
pub const Dto = struct {
    @"$schema": ?[]const u8 = null,
    listen: []const u8,
    admin: ?[]const u8 = null,
    handoff: ?[]const u8 = null,
    accept_mode: []const u8 = "reuseport",
    tls: ?TlsDto = null,
    routes: []const RouteDto,
    clusters: []const ClusterDto,

    pub const schema_doc = "Static zoxy proxy configuration, parsed once at startup.";
    pub const schema_fields = .{
        .@"$schema" = .{ .desc = "JSON Schema URL for editor completion; ignored by zoxy." },
        .listen = .{
            .desc = "Address the proxy accepts connections on.",
            .format = "hostport",
            .pattern = hostport_pattern,
            .example = "0.0.0.0:8080",
        },
        .admin = .{
            .desc = "Address of the admin/metrics endpoint; null disables it.",
            .format = "hostport",
            .pattern = hostport_pattern,
            .example = "127.0.0.1:9901",
        },
        .handoff = .{
            .desc = "Unix-socket path for hot-restart listener handoff; null disables it.",
            .example = "/run/zoxy-handoff.sock",
        },
        .accept_mode = .{
            .desc = "How accepted connections spread across workers.",
            .enum_type = AcceptMode,
            .enum_docs = .{
                .reuseport = "One SO_REUSEPORT listener per worker; the kernel hashes.",
                .shared = "One listener; every worker holds a pending accept.",
            },
        },
        .tls = .{ .desc = "TLS termination on the listener; null = plaintext." },
        .routes = .{ .desc = "Host/path routing rules, evaluated first-match-wins." },
        .clusters = .{ .desc = "Upstream clusters that routes target." },
    };

    pub const TlsDto = struct {
        certificate_file: []const u8,
        private_key_file: []const u8,
        kernel_offload: bool = true,
        http2: bool = false,
        additional_identities: []const TlsIdentityDto = &.{},

        pub const schema_doc = "TLS termination identity and options for the listener.";
        pub const schema_fields = .{
            .certificate_file = .{
                .desc = "Path to the PEM certificate (chain) for the default identity.",
                .example = "cert.pem",
            },
            .private_key_file = .{
                .desc = "Path to the PEM private key for the default identity.",
                .example = "key.pem",
            },
            .kernel_offload = .{
                .desc = "Hand completed handshakes to kernel TLS; off forces the userspace relay.",
            },
            .http2 = .{
                .desc = "Offer HTTP/2 in ALPN; h2-negotiating clients use the HTTP/2 data path.",
            },
            .additional_identities = .{
                .desc = "Extra SNI-selected server identities beyond the default certificate.",
            },
        };
    };
    pub const TlsIdentityDto = struct {
        server_names: []const []const u8,
        certificate_file: []const u8,
        private_key_file: []const u8,

        pub const schema_doc =
            "An additional TLS identity, selected when the client's SNI matches.";
        pub const schema_fields = .{
            .server_names = .{
                .desc = "SNI names this identity serves (exact, or single-label \"*.\" wildcards).",
            },
            .certificate_file = .{ .desc = "Path to this identity's PEM certificate (chain)." },
            .private_key_file = .{ .desc = "Path to this identity's PEM private key." },
        };
    };
    pub const ClusterTlsDto = struct {
        server_name: ?[]const u8 = null,
        ca_file: ?[]const u8 = null,
        insecure: bool = false,

        pub const schema_doc =
            "Upstream re-encryption for a cluster; pick a verification posture explicitly.";
        pub const schema_fields = .{
            .server_name = .{
                .desc = "Certificate hostname to require and offer as SNI; " ++
                    "required unless insecure.",
            },
            .ca_file = .{ .desc = "PEM trust-store bundle path; required unless insecure." },
            .insecure = .{
                .desc = "Skip upstream verification; mutually exclusive with server_name/ca_file.",
            },
        };
    };
    pub const RouteDto = struct {
        host: []const u8 = "*",
        path_prefix: []const u8 = "/",
        cluster: []const u8,

        pub const schema_doc =
            "A routing rule: match a host and path prefix, forward to a cluster.";
        pub const schema_fields = .{
            .host = .{
                .desc = "Host to match; \"*\" matches any Host header.",
                .example = "api.example.com",
            },
            .path_prefix = .{
                .desc = "Prefix matched against the request target; \"/\" matches everything.",
                .example = "/v1",
            },
            .cluster = .{ .desc = "Name of the cluster to route matching requests to." },
        };
    };
    pub const ClusterDto = struct {
        name: []const u8,
        endpoints: []const []const u8,
        tls: ?ClusterTlsDto = null,
        lb: ?LbDto = null,
        retry: ?RetryDto = null,
        circuit_breaker: ?CircuitBreakerDto = null,
        outlier: ?OutlierDto = null,
        health_check: ?HealthCheckDto = null,
        per_try_timeout_ms: u32 = 0,

        pub const schema_doc = "An upstream cluster: endpoints plus optional resilience policy.";
        pub const schema_fields = .{
            .name = .{ .desc = "Unique cluster name referenced by routes." },
            .endpoints = .{ .desc = "Upstream endpoint addresses, each host:port." },
            .tls = .{ .desc = "Re-encrypt traffic to this cluster's endpoints; null = plaintext." },
            .lb = .{ .desc = "Load-balancing policy; absent = P2C least-request." },
            .retry = .{ .desc = "Retry policy for failed attempts; absent = retries off." },
            .circuit_breaker = .{ .desc = "Per-worker admission limits; absent = unbounded." },
            .outlier = .{ .desc = "Passive outlier ejection; absent = off." },
            .health_check = .{ .desc = "Active TCP health probes; absent = off." },
            .per_try_timeout_ms = .{
                .desc = "Deadline per upstream attempt (connect to first byte); 0 = disabled.",
                .units = "milliseconds",
            },
        };
    };
    // Absent per-field values fall back to `constants` defaults during
    // lowering (kept out of the DTO so the defaults live in one place).
    pub const LbDto = struct {
        policy: []const u8,
        hash: []const u8 = "target",
        header: ?[]const u8 = null,

        pub const schema_doc = "Load-balancer selection for a cluster.";
        pub const schema_fields = .{
            .policy = .{
                .desc = "Balancing policy.",
                .enum_type = LbPolicy,
                .enum_docs = .{
                    .least_request = "Power-of-two-choices least-request over in-flight counts.",
                    .maglev = "Maglev consistent hashing (see hash); falls back to least-request.",
                },
            },
            .hash = .{
                .desc = "What the consistent hash keys on (maglev only).",
                .enum_type = HashOn,
                .enum_docs = .{
                    .target = "Hash the request target.",
                    .header = "Hash a named request header (see header).",
                },
            },
            .header = .{
                .desc = "Header name to hash on when hash = header.",
                .example = "x-user-id",
            },
        };
    };
    pub const RetryDto = struct {
        max: u8,
        backoff_base_ms: ?u32 = null,
        backoff_cap_ms: ?u32 = null,
        budget_percent: ?u8 = null,
        budget_min: ?u32 = null,

        pub const schema_doc =
            "Retry policy: bounded attempts with jittered exponential backoff and a budget.";
        pub const schema_fields = .{
            .max = .{
                .desc = "Retry attempts after the first try.",
                .minimum = 1,
                .maximum = constants.retry_attempts_max,
            },
            .backoff_base_ms = .{
                .desc = "Base backoff before the first retry (jittered exponential).",
                .units = "milliseconds",
                .minimum = 1,
            },
            .backoff_cap_ms = .{
                .desc = "Maximum backoff between retries (must be >= backoff_base_ms).",
                .units = "milliseconds",
                .minimum = 1,
            },
            .budget_percent = .{
                .desc = "Retry budget as a percent of active requests.",
                .minimum = 1,
                .maximum = 100,
            },
            .budget_min = .{
                .desc = "Minimum concurrent retries allowed regardless of the budget percent.",
            },
        };
    };
    pub const CircuitBreakerDto = struct {
        max_connections: ?u32 = null,
        max_pending: ?u32 = null,
        max_requests: ?u32 = null,
        max_retries: ?u32 = null,

        pub const schema_doc = "Per-worker circuit-breaker admission limits.";
        pub const schema_fields = .{
            .max_connections = .{
                .desc = "Max concurrent upstream connections per worker.",
                .minimum = 1,
            },
            .max_pending = .{
                .desc = "Max requests queued awaiting a connection per worker.",
                .minimum = 1,
            },
            .max_requests = .{
                .desc = "Max concurrent upstream requests per worker.",
                .minimum = 1,
            },
            .max_retries = .{ .desc = "Max concurrent retries per worker.", .minimum = 1 },
        };
    };
    pub const OutlierDto = struct {
        consecutive_failures: ?u32 = null,
        ejection_ms: ?u32 = null,
        max_ejection_percent: ?u8 = null,

        pub const schema_doc = "Passive outlier detection: eject endpoints that fail repeatedly.";
        pub const schema_fields = .{
            .consecutive_failures = .{
                .desc = "Consecutive attempt failures before an endpoint is ejected.",
                .minimum = 1,
            },
            .ejection_ms = .{
                .desc = "How long an ejected endpoint stays out.",
                .units = "milliseconds",
                .minimum = 1,
            },
            .max_ejection_percent = .{
                .desc = "Ceiling on the ejected share of a cluster.",
                .minimum = 1,
                .maximum = 100,
            },
        };
    };
    pub const HealthCheckDto = struct {
        interval_ms: ?u32 = null,
        timeout_ms: ?u32 = null,
        healthy_threshold: ?u16 = null,
        unhealthy_threshold: ?u16 = null,

        pub const schema_doc = "Active TCP health probing for a cluster's endpoints.";
        pub const schema_fields = .{
            .interval_ms = .{
                .desc = "Interval between active TCP-connect probes.",
                .units = "milliseconds",
                .minimum = 1,
            },
            .timeout_ms = .{
                .desc = "Per-probe connect timeout.",
                .units = "milliseconds",
                .minimum = 1,
            },
            .healthy_threshold = .{
                .desc = "Consecutive successes to mark an endpoint healthy.",
                .minimum = 1,
            },
            .unhealthy_threshold = .{
                .desc = "Consecutive failures to mark an endpoint unhealthy.",
                .minimum = 1,
            },
        };
    };
};

/// The attribute keys a `schema_fields` entry may carry — the vocabulary the
/// generator reads. A key outside this set would be silently ignored (dropping
/// the annotation or widening a constraint), so `assert_meta_matches` rejects it.
const schema_attributes = .{
    "desc",      "format",    "pattern", "units",
    "enum_type", "enum_docs", "example", "minimum",
    "maximum",
};

/// Cross-check a DTO struct's `schema_fields` metadata against its actual fields
/// at comptime, so the JSON Schema (shape *and* prose) can never drift from the
/// parsed shape: (1) every field has exactly one metadata entry and vice versa;
/// (2) every entry carries a `.desc`; (3) every attribute key is in
/// `schema_attributes` (a typo like `.minimu` is a compile error, not a silent
/// drop). Called from the container-scope block below (every build) and
/// per-object by the generator (catches a nested struct missing from the list).
pub fn assert_meta_matches(comptime T: type) void {
    @setEvalBranchQuota(50_000); // the attribute-vocabulary cross-check is string-compare heavy
    const meta = T.schema_fields;
    inline for (@typeInfo(T).@"struct".fields) |field| {
        if (!@hasField(@TypeOf(meta), field.name)) {
            @compileError(@typeName(T) ++ ": schema_fields missing '" ++ field.name ++ "'");
        }
    }
    inline for (@typeInfo(@TypeOf(meta)).@"struct".fields) |meta_field| {
        if (!@hasField(T, meta_field.name)) {
            @compileError(@typeName(T) ++ ": schema_fields has stray '" ++ meta_field.name ++ "'");
        }
        const entry = @field(meta, meta_field.name);
        if (!@hasField(@TypeOf(entry), "desc")) {
            @compileError(@typeName(T) ++ "." ++ meta_field.name ++ ": entry needs a .desc");
        }
        inline for (@typeInfo(@TypeOf(entry)).@"struct".fields) |attribute| {
            comptime var known = false;
            inline for (schema_attributes) |name| {
                if (comptime std.mem.eql(u8, attribute.name, name)) known = true;
            }
            if (!known) @compileError(@typeName(T) ++ "." ++ meta_field.name ++
                ": unknown schema attribute '" ++ attribute.name ++ "'");
        }
    }
}

/// Every DTO struct, checked on every build (config.zig is always compiled).
pub const dto_types = .{
    Dto,                   Dto.TlsDto,     Dto.TlsIdentityDto, Dto.ClusterTlsDto,
    Dto.RouteDto,          Dto.ClusterDto, Dto.LbDto,          Dto.RetryDto,
    Dto.CircuitBreakerDto, Dto.OutlierDto, Dto.HealthCheckDto,
};

comptime {
    for (dto_types) |T| assert_meta_matches(T);
}

/// Longest config field path rendered in an unknown-field error.
const config_path_bytes_max: usize = 256;
/// Loop bounds for the strict-field walk (TigerStyle: bound every loop). Keys or
/// array items past these fall through to the strict `parseFromValue`, which
/// still rejects the unknown — just without the pretty path.
const object_keys_max: u32 = 128;
const array_items_max: u32 = 1024;

/// Accumulates a dotted/indexed JSON path (e.g. `clusters[2].circuit_breaker`)
/// into a caller-owned fixed buffer; silently truncates at the buffer end.
const PathBuilder = struct {
    buf: []u8,
    len: usize = 0,

    fn mark(self: *const PathBuilder) usize {
        return self.len;
    }
    fn rewind(self: *PathBuilder, to: usize) void {
        assert(to <= self.len);
        self.len = to;
    }
    fn push_key(self: *PathBuilder, name: []const u8) void {
        if (self.len != 0) self.push_byte('.');
        self.push_bytes(name);
    }
    fn push_index(self: *PathBuilder, index: usize) void {
        var digits: [24]u8 = undefined;
        const text = std.fmt.bufPrint(&digits, "[{d}]", .{index}) catch return;
        self.push_bytes(text);
    }
    fn push_byte(self: *PathBuilder, byte: u8) void {
        if (self.len >= self.buf.len) return;
        self.buf[self.len] = byte;
        self.len += 1;
    }
    fn push_bytes(self: *PathBuilder, bytes: []const u8) void {
        assert(self.len <= self.buf.len);
        const take = @min(bytes.len, self.buf.len - self.len);
        @memcpy(self.buf[self.len..][0..take], bytes[0..take]);
        self.len += take;
    }
    fn path(self: *const PathBuilder) []const u8 {
        assert(self.len <= self.buf.len);
        return self.buf[0..self.len];
    }
};

fn field_known(comptime T: type, key: []const u8) bool {
    inline for (@typeInfo(T).@"struct".fields) |field| {
        if (std.mem.eql(u8, field.name, key)) return true;
    }
    return false;
}

/// Walk a decoded JSON object against DTO struct `T`, returning the path of the
/// first key `T` does not declare, or null. Comptime-monomorphized per DTO type
/// (Dto → ClusterDto → ClusterTlsDto …): each level is a distinct function over
/// a distinct type and no type contains itself, so the descent is statically
/// bounded at the DTO's nesting depth — it terminates and is not runtime
/// recursion (the same shape as the comptime parsers elsewhere in the tree).
fn check_object(comptime T: type, value: std.json.Value, pb: *PathBuilder) ?[]const u8 {
    if (value != .object) return null; // shape mismatches are parseFromValue's job
    var seen: u32 = 0;
    var it = value.object.iterator();
    while (it.next()) |entry| : (seen += 1) {
        if (seen >= object_keys_max) break;
        if (!field_known(T, entry.key_ptr.*)) {
            pb.push_key(entry.key_ptr.*);
            return pb.path();
        }
    }
    inline for (@typeInfo(T).@"struct".fields) |field| {
        if (value.object.get(field.name)) |child| {
            const at = pb.mark();
            pb.push_key(field.name);
            if (check_value(field.type, child, pb)) |bad| return bad;
            pb.rewind(at);
        }
    }
    return null;
}

fn check_value(comptime T: type, value: std.json.Value, pb: *PathBuilder) ?[]const u8 {
    switch (@typeInfo(T)) {
        .optional => |opt| return if (value == .null) null else check_value(opt.child, value, pb),
        .@"struct" => return check_object(T, value, pb),
        .pointer => |ptr| {
            if (ptr.size != .slice) return null;
            if (@typeInfo(ptr.child) != .@"struct") return null; // strings, []const []const u8
            if (value != .array) return null;
            for (value.array.items, 0..) |item, index| {
                if (index >= array_items_max) break;
                const at = pb.mark();
                pb.push_index(index);
                if (check_object(ptr.child, item, pb)) |bad| return bad;
                pb.rewind(at);
            }
            return null;
        },
        else => return null,
    }
}

/// Returns the path of the first unknown config key (into `buf`), or null when
/// every key maps to a DTO field. Backs the strict rejection in `parse`.
pub fn find_unknown_field(root: std.json.Value, buf: []u8) ?[]const u8 {
    var pb = PathBuilder{ .buf = buf };
    return check_object(Dto, root, &pb);
}

/// Surfaced from `parse_diagnostic`: on `error.UnknownField`, `unknown_field`
/// is the offending dotted path (`clusters[2].circuit_breaker`), backed by
/// `path_buf`. Kept caller-owned so the library never logs on the parse path.
pub const Diagnostic = struct {
    unknown_field: ?[]const u8 = null,
    path_buf: [config_path_bytes_max]u8 = undefined,
    /// Set when `load_text` fails adapting a DSL (non-`.json`) file before any
    /// JSON parse: the 1-based source line and a short message. Left zero/null
    /// for JSON inputs and for JSON-parse failures (use `unknown_field` there).
    adapt_line: u32 = 0,
    adapt_message: ?[]const u8 = null,
};

/// Errors from `load_text`: JSON parse errors plus DSL adapt errors.
pub const LoadError = ParseError || adapter.Error;

/// Load a config from file `text`, choosing the format by `path` extension: a
/// `.json` path parses directly; anything else is treated as the Zoxyfile DSL
/// and adapted to JSON first (docs/DESIGN.md §7 Phase 6, slice 3). Diagnostics
/// route through `diag`: `adapt_*` for a DSL syntax error, `unknown_field` for
/// a JSON key error. Startup/reload only — the transient JSON is allocator-owned
/// and freed here once parsed (the `Config` keeps its own arena copy).
pub fn load_text(
    gpa: std.mem.Allocator,
    path: []const u8,
    text: []const u8,
    diag: *Diagnostic,
) LoadError!Config {
    if (std.mem.endsWith(u8, path, ".json")) return parse_diagnostic(gpa, text, diag);
    var adapt_diag: adapter.Diagnostic = .{};
    const json = adapter.to_json(gpa, text, &adapt_diag) catch |err| {
        diag.adapt_line = adapt_diag.line;
        diag.adapt_message = adapt_diag.message;
        return err;
    };
    defer gpa.free(json);
    return parse_diagnostic(gpa, json, diag);
}

/// Parse without surfacing a diagnostic — the library stays quiet. Callers that
/// want the offending field path (main, the config tool) use `parse_diagnostic`.
pub fn parse(gpa: std.mem.Allocator, text: []const u8) ParseError!Config {
    var diag: Diagnostic = .{};
    return parse_diagnostic(gpa, text, &diag);
}

pub fn parse_diagnostic(
    gpa: std.mem.Allocator,
    text: []const u8,
    diag: *Diagnostic,
) ParseError!Config {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    // Decode to a dynamic tree first so a misspelled key can be reported with
    // its full path — std.json's UnknownField error carries none. Then decode
    // strictly into the DTO (rejecting unknowns again, defense in depth) and
    // dupe what we keep into the arena.
    const tree = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
    defer tree.deinit();
    if (find_unknown_field(tree.value, &diag.path_buf)) |bad_path| {
        diag.unknown_field = bad_path;
        return error.UnknownField;
    }
    const parsed = try std.json.parseFromValue(Dto, gpa, tree.value, .{});
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
            .hash_on = .target,
            .hash_header = "",
            .maglev_table = &.{},
        };
        try lower_lb(a, &dc, cluster);
    }

    const routes = try lower_routes(a, dto.routes, clusters);
    const tls = try lower_tls(a, dto.tls);

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

fn lower_routes(
    a: std.mem.Allocator,
    dto_routes: []const Dto.RouteDto,
    clusters: []const Cluster,
) ParseError![]Route {
    const routes = try a.alloc(Route, dto_routes.len);
    assert(routes.len == dto_routes.len);
    for (dto_routes, routes) |dr, *route| {
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
    return routes;
}

fn lower_tls(a: std.mem.Allocator, dto_tls: ?Dto.TlsDto) ParseError!?TlsConfig {
    const dt = dto_tls orelse return null;
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
    return .{
        .certificate_file = try a.dupe(u8, dt.certificate_file),
        .private_key_file = try a.dupe(u8, dt.private_key_file),
        .kernel_offload = dt.kernel_offload,
        .http2 = dt.http2,
        .additional_identities = identities,
    };
}

/// An `lb` block selects the balancing policy; absent means P2C
/// least-request. `maglev` builds the cluster's consistent-hash lookup
/// table right here — config time is the one place allocation is allowed —
/// keyed on the request target or a named header. Every knob is validated
/// strictly: hash options on a `least_request` block are refused rather
/// than ignored.
fn lower_lb(
    a: std.mem.Allocator,
    dc: *const Dto.ClusterDto,
    cluster: *Cluster,
) (error{InvalidLb} || std.mem.Allocator.Error)!void {
    const lb = dc.lb orelse return;
    assert(cluster.maglev_table.len == 0); // lowered exactly once per cluster
    const policy = std.meta.stringToEnum(LbPolicy, lb.policy) orelse return error.InvalidLb;
    if (policy == .least_request) {
        // The default spelled out; hash knobs belong to maglev only.
        if (lb.header != null) return error.InvalidLb;
        if (!std.mem.eql(u8, lb.hash, "target")) return error.InvalidLb;
        return;
    }
    assert(policy == .maglev);
    if (cluster.endpoints.len == 0) return error.InvalidLb; // nothing to hash onto
    if (std.mem.eql(u8, lb.hash, "target")) {
        if (lb.header != null) return error.InvalidLb;
        cluster.hash_on = .target;
    } else if (std.mem.eql(u8, lb.hash, "header")) {
        const header = lb.header orelse return error.InvalidLb;
        if (header.len == 0) return error.InvalidLb;
        cluster.hash_on = .header;
        cluster.hash_header = try a.dupe(u8, header);
    } else {
        return error.InvalidLb;
    }
    var addresses: [constants.endpoints_per_cluster_max]Ip4Address = undefined;
    for (cluster.endpoints, addresses[0..cluster.endpoints.len]) |endpoint, *address| {
        address.* = endpoint.address;
    }
    const table = try a.alloc(u8, constants.maglev_table_entries);
    maglev.build(addresses[0..cluster.endpoints.len], table);
    cluster.maglev_table = table;
    assert(cluster.maglev_table.len == constants.maglev_table_entries);
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

test "config: lb block — maglev builds a table, knobs validated strictly" {
    var plain = try parse(std.testing.allocator, test_config);
    defer plain.deinit();
    try std.testing.expectEqual(@as(usize, 0), plain.clusters[0].maglev_table.len);

    var target_hashed = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "lb": { "policy": "maglev" },
        \\    "endpoints": ["127.0.0.1:9000", "127.0.0.1:9001"] }] }
    );
    defer target_hashed.deinit();
    const hashed = &target_hashed.clusters[0];
    try std.testing.expectEqual(constants.maglev_table_entries, hashed.maglev_table.len);
    try std.testing.expectEqual(HashOn.target, hashed.hash_on);
    for (hashed.maglev_table) |entry| try std.testing.expect(entry < 2);

    var header_hashed = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c",
        \\    "lb": { "policy": "maglev", "hash": "header", "header": "x-user-id" },
        \\    "endpoints": ["127.0.0.1:9000"] }] }
    );
    defer header_hashed.deinit();
    try std.testing.expectEqual(HashOn.header, header_hashed.clusters[0].hash_on);
    try std.testing.expectEqualStrings("x-user-id", header_hashed.clusters[0].hash_header);

    // Strict knobs: unknown policy, unknown hash, header-hash without a
    // header name, and a header name on a target hash are all refused.
    const cases = [_][]const u8{
        \\"lb": { "policy": "ring_of_power" }
        ,
        \\"lb": { "policy": "maglev", "hash": "cookie" }
        ,
        \\"lb": { "policy": "maglev", "hash": "header" }
        ,
        \\"lb": { "policy": "maglev", "header": "x-user-id" }
        ,
        \\"lb": { "policy": "least_request", "header": "x-user-id" }
        ,
    };
    for (cases) |case| {
        var buf: [512]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf,
            \\{{ "listen": "0.0.0.0:80", "routes": [{{ "cluster": "c" }}],
            \\  "clusters": [{{ "name": "c", {s},
            \\    "endpoints": ["127.0.0.1:9000"] }}] }}
        , .{case});
        try std.testing.expectError(error.InvalidLb, parse(std.testing.allocator, text));
    }
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
    try std.testing.expect(!with.tls.?.http2); // off unless asked

    var with_h2 = try parse(std.testing.allocator,
        \\{ "listen": "0.0.0.0:443",
        \\  "tls": { "certificate_file": "cert.pem", "private_key_file": "key.pem",
        \\    "http2": true },
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    );
    defer with_h2.deinit();
    try std.testing.expect(with_h2.tls.?.http2);

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

test "config: strict parsing rejects an unknown field" {
    const bad =
        \\{ "listen": "0.0.0.0:80", "typo_here": 1, "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    ;
    try std.testing.expectError(error.UnknownField, parse(std.testing.allocator, bad));
}

test "config: strict parsing accepts a known $schema key" {
    var config = try parse(std.testing.allocator,
        \\{ "$schema": "./config.schema.json", "listen": "0.0.0.0:80",
        \\  "routes": [{ "cluster": "c" }],
        \\  "clusters": [{ "name": "c", "endpoints": ["127.0.0.1:9000"] }] }
    );
    defer config.deinit();
    try std.testing.expectEqual(@as(u16, 80), config.listen.port);
}

test "config: find_unknown_field names the offending path" {
    const Case = struct { json: []const u8, path: []const u8 };
    const cases = [_]Case{
        .{
            .json =
            \\{ "listen": "0.0.0.0:80", "nope": 1, "routes": [], "clusters": [] }
            ,
            .path = "nope",
        },
        .{
            .json =
            \\{ "listen": "0.0.0.0:80", "routes": [{ "cluster": "c", "hostt": "*" }],
            \\  "clusters": [] }
            ,
            .path = "routes[0].hostt",
        },
        .{
            .json =
            \\{ "listen": "0.0.0.0:80", "routes": [],
            \\  "clusters": [{ "name": "c", "endpoints": [],
            \\    "circuit_breaker": { "max_requsts": 1 } }] }
            ,
            .path = "clusters[0].circuit_breaker.max_requsts",
        },
    };
    for (cases) |case| {
        var tree = try std.json.parseFromSlice(
            std.json.Value,
            std.testing.allocator,
            case.json,
            .{},
        );
        defer tree.deinit();
        var buf: [config_path_bytes_max]u8 = undefined;
        const found = find_unknown_field(tree.value, &buf);
        try std.testing.expect(found != null);
        try std.testing.expectEqualStrings(case.path, found.?);
    }

    // A fully valid document has no unknown field.
    var ok = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        test_config,
        .{},
    );
    defer ok.deinit();
    var buf: [config_path_bytes_max]u8 = undefined;
    try std.testing.expect(find_unknown_field(ok.value, &buf) == null);
}

test "config: load_text parses a .json path directly" {
    var diag: Diagnostic = .{};
    var config = try load_text(std.testing.allocator, "zoxy.json", test_config, &diag);
    defer config.deinit();
    try std.testing.expect(config.find_cluster("api") != null);
}

test "config: load_text adapts a Zoxyfile DSL end to end" {
    var diag: Diagnostic = .{};
    var config = try load_text(std.testing.allocator, "zoxy.zoxy",
        \\listen 0.0.0.0:8080
        \\route api.example.com /v1 -> api
        \\route -> web
        \\cluster api {
        \\    endpoints 127.0.0.1:9001 127.0.0.1:9002
        \\    lb maglev header x-user-id
        \\    per_try_timeout 1500ms
        \\    retry {
        \\        max 3
        \\        backoff_base 25ms
        \\    }
        \\    outlier {
        \\        consecutive_failures 5
        \\        ejection 30s
        \\    }
        \\}
        \\cluster web {
        \\    endpoints 127.0.0.1:9000
        \\}
    , &diag);
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 8080), config.listen.port);
    // Routes survive the round trip in order, with the arrow forms lowered.
    try std.testing.expectEqual(@as(usize, 2), config.routes.len);
    try std.testing.expectEqualStrings("api.example.com", config.routes[0].host);
    try std.testing.expectEqualStrings("/v1", config.routes[0].path_prefix);
    try std.testing.expectEqualStrings("api", config.routes[0].cluster);
    try std.testing.expectEqualStrings("*", config.routes[1].host);
    try std.testing.expectEqualStrings("web", config.routes[1].cluster);

    const api = config.find_cluster("api").?;
    try std.testing.expectEqual(@as(usize, 2), api.endpoints.len);
    // maglev header hashing resolved a lookup table and the header name.
    try std.testing.expect(api.maglev_table.len > 0);
    try std.testing.expectEqualStrings("x-user-id", api.hash_header);
    // Durations lowered ms→ns through the JSON `*_ms` fields.
    try std.testing.expectEqual(@as(u8, 3), api.policy.retry_max);
    const base_ns = api.policy.retry_backoff_base_ns;
    try std.testing.expectEqual(@as(u63, 25 * std.time.ns_per_ms), base_ns);
    try std.testing.expectEqual(@as(u63, 1500 * std.time.ns_per_ms), api.policy.per_try_timeout_ns);
    try std.testing.expectEqual(@as(u32, 5), api.policy.outlier_consecutive_failures);
    try std.testing.expectEqual(@as(u63, 30 * std.time.ns_per_s), api.policy.outlier_ejection_ns);
}

test "config: load_text surfaces a DSL syntax error with a line" {
    var diag: Diagnostic = .{};
    const result = load_text(std.testing.allocator, "zoxy.zoxy",
        \\listen 0.0.0.0:80
        \\route -> c
        \\cluster c {
        \\    frobnicate 1
        \\}
    , &diag);
    try std.testing.expectError(error.UnknownDirective, result);
    try std.testing.expect(diag.adapt_message != null);
    try std.testing.expectEqual(@as(u32, 4), diag.adapt_line);
}

test "config: load_text still reports JSON unknown fields on a .json path" {
    var diag: Diagnostic = .{};
    const result = load_text(std.testing.allocator, "zoxy.json",
        \\{ "listen": "0.0.0.0:80", "routes": [], "clusters": [],
        \\  "handofff": "/x" }
    , &diag);
    try std.testing.expectError(error.UnknownField, result);
    try std.testing.expect(diag.unknown_field != null);
}
