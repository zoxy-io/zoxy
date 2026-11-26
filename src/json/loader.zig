//! The stock binary's JSON front-end (#417, DESIGN.md §5): strict JSON →
//! `zoxy.Options`. Two stages: std.json with strict options (unknown
//! field → error, duplicate field → error) into JSON-shaped DTOs, then a
//! translation that parses every spelling — address and CIDR literals,
//! policy and mode strings, the key forks a JSON object spells a union
//! with — applies zoxy's stock values where a key is absent
//! (`zoxy.defaults`), and reads the files the config names through a
//! seam. Every rule options written in code could break too is the
//! library's (`zoxy.config.resolve`); what is refused here is what only a
//! spelling can get wrong.
//!
//! A module of its own, created rather than added in build.zig, so a
//! build on the library cannot import it: a custom build is configured in
//! code. The returned options reference both the arena and `json_bytes`;
//! the caller keeps both for the process lifetime.

const std = @import("std");
const zoxy = @import("zoxy");

const config_module = zoxy.config;
const Config = config_module.Config;
const Options = zoxy.Options;
const defaults = zoxy.defaults;
const constants = zoxy.constants;
const extension_module = zoxy.extension;
const filter = zoxy.http.filter;
const parser = zoxy.http.parser;
const render = zoxy.http.render;
const router = zoxy.http.router;
const shed = zoxy.shed;
const trust = zoxy.tls.trust;
const io_module = zoxy.Io;
const dns_host = zoxy.dns.host;
const dns_endpoints = zoxy.dns.endpoints;
const json_schema = @import("validator.zig");
/// The ALPN vocabulary (#271). Public so the schema emitter states the
/// same closed set the loader enforces.
pub const alpn = config_module.alpn;
const unix_address_prefix = config_module.unix_address_prefix;
const resolve = config_module.resolve;
const h2OriginTls = config_module.h2OriginTls;
const originTls = config_module.originTls;
const upstreamTlsEndpointsOf = config_module.upstreamTlsEndpointsOf;

const assert = std.debug.assert;
const repeat = zoxy.testing.repeat;

/// The refusals only a JSON spelling can earn (#417): a string no
/// vocabulary holds, a fork named twice or not at all, a literal that does
/// not parse, a file that cannot be read. Options written in code cannot
/// state any of these, so the library's `resolve` never returns one.
pub const SpellingError = error{
    ListenerBindInvalid,
    /// A `quic` bind that is neither an `IP:port` literal nor `unix:` and
    /// a path (#449); the path form parses, and the library refuses it.
    ListenerQuicBindInvalid,
    ListenerHttpOrL4,
    ClusterPickUnknown,
    ClusterCheckTypeUnknown,
    ClusterCheckHttpFieldOnTcp,
    ClusterCheckPathMissing,
    /// `path` or `host` beside a `grpc` check, which asks a fixed path.
    ClusterCheckHttpFieldOnGrpc,
    /// `service` beside a check that is not `grpc`.
    ClusterCheckServiceWithoutGrpc,
    ClusterPickKeyMissing,
    ClusterPickKeyUnknown,
    ClusterPickKeyWithoutHash,
    ClusterPickNameMissing,
    ClusterPickNameUnexpected,
    BodySourceMissing,
    BodySourceAmbiguous,
    BodyFileUnreadable,
    ErrorPageStatusInvalid,
    ListenerClusterOrRoutes,
    ListenerForwardedModeUnknown,
    ListenerProxyProtocolModeUnknown,
    ListenerTlsClientVerifyUnknown,
    ListenerTlsClientCaUnreadable,
    RouteHeaderMatchKind,
    ListenerTlsCertPathEmpty,
    ListenerTlsKeyPathEmpty,
    /// A listener's certificate or key file that the file seam could not
    /// read, or that is past `tls_pem_bytes_max` (#417).
    ListenerTlsFileUnreadable,
    ListenerTlsCertificatesEmpty,
    ListenerTlsAlpnUnknown,
    ClusterProxyProtocolSendUnknown,
    ClusterProtocolUnknown,
    FilterHeaderMatchKind,
    FilterClientEmpty,
    FilterClientCidrInvalid,
    FilterClientPrefixInvalid,
    FilterActionKind,
    FilterRedirectSchemeUnknown,
    ResponseFilterStatusClassUnknown,
    ResponseFilterStatusEmpty,
    EndpointInvalid,
    /// A name no address answered for, in the family the endpoint asked
    /// (#480): the name source answered, not the document.
    EndpointNameUnresolved,
    /// `family` beside an address that is no name (#480): an address has
    /// one family already, and the key would sit there inert.
    EndpointFamilyWithoutName,
    EndpointFamilyUnknown,
    ClusterTlsCaUnreadable,
    AdminBindInvalid,
    AccessLogSinkUnknown,
    AccessLogPathOnStdout,
};

/// Everything a JSON config can be refused for short of a malformed
/// document: its spellings, and every rule the options it spells are held
/// to.
pub const ValidationError = SpellingError || config_module.ValidationError;

pub const ParseError = std.json.ParseError(std.json.Scanner) || ValidationError;

/// How the JSON front-end reads the files a config names (#159, #417):
/// bodies, certificates, CA bundles. A seam rather than a direct read, so
/// the front-end stays pure: `parse` below refuses every file source
/// (tests, the fuzzer and the simulator need no filesystem — an `inline`
/// body is theirs), and the binary passes the one real reader to
/// `optionsFromJson`, keeping filesystem access where the config file
/// itself is already read. `resolve` reads no file at all: the options
/// carry bytes.
pub const FileSource = struct {
    context: ?*anyopaque = null,
    /// Read the whole file, at most `limit` bytes, into the arena.
    /// A file over the limit reports `FileTooLarge` — the front-end
    /// turns it into the same `BodyOverLimit` an oversized inline body
    /// earns.
    read: *const fn (
        context: ?*anyopaque,
        arena: std.mem.Allocator,
        path: []const u8,
        limit: u32,
    ) error{ FileUnreadable, FileTooLarge, OutOfMemory }![]const u8,

    pub const none: FileSource = .{ .read = refuse };

    fn refuse(
        context: ?*anyopaque,
        arena: std.mem.Allocator,
        path: []const u8,
        limit: u32,
    ) error{ FileUnreadable, FileTooLarge, OutOfMemory }![]const u8 {
        _ = context;
        _ = arena;
        _ = limit;
        assert(path.len >= 1); // The caller validated the path shape first.
        return error.FileUnreadable;
    }
};

/// How the JSON front-end resolves the names a config's endpoints give
/// (#480), once, at load: a seam for the reason `FileSource` is one. The
/// binary passes the system's resolver; `parse` and the fuzzer refuse
/// every name. What the options carry is addresses, so `resolve` looks up
/// no name.
pub const NameSource = struct {
    context: ?*anyopaque = null,
    /// The addresses `host` has in `family`, each with `port`, allocated
    /// in the arena — at least one, or `NameUnresolved`. `host` is in the
    /// canonical form `dns.host` gives. An address outside `family`, or
    /// on another port, breaks the contract the loader asserts.
    lookup: *const fn (
        context: ?*anyopaque,
        arena: std.mem.Allocator,
        host: []const u8,
        port: u16,
        family: dns_host.Family,
    ) error{ NameUnresolved, OutOfMemory }![]const std.Io.net.IpAddress,

    pub const none: NameSource = .{ .lookup = refuse };

    fn refuse(
        context: ?*anyopaque,
        arena: std.mem.Allocator,
        host: []const u8,
        port: u16,
        family: dns_host.Family,
    ) error{ NameUnresolved, OutOfMemory }![]const std.Io.net.IpAddress {
        _ = context;
        _ = arena;
        _ = family;
        assert(dns_host.isCanonical(host)); // The caller canonicalized it.
        assert(port != 0);
        return error.NameUnresolved;
    }
};

pub fn parse(arena: std.mem.Allocator, json_bytes: []const u8) ParseError!Config {
    return parseWithFiles(arena, json_bytes, .none);
}

pub fn parseWithFiles(
    arena: std.mem.Allocator,
    json_bytes: []const u8,
    files: FileSource,
) ParseError!Config {
    return parseWithSources(arena, json_bytes, files, .none);
}

pub fn parseWithSources(
    arena: std.mem.Allocator,
    json_bytes: []const u8,
    files: FileSource,
    names: NameSource,
) ParseError!Config {
    const options = try optionsFromJson(arena, json_bytes, files, names);
    return resolve(arena, &options);
}

/// The stock binary's front-end (#417): a JSON config read into the
/// options the library resolves. Every spelling is translated before
/// anything is judged, so a fault only JSON can have — a literal that
/// does not parse, a key named twice or not at all, a file that cannot be
/// read — outranks every rule the options are held to, whichever blocks
/// the two sit in. The options reference both the arena and `json_bytes`.
pub fn optionsFromJson(
    arena: std.mem.Allocator,
    json_bytes: []const u8,
    files: FileSource,
    names: NameSource,
) ParseError!Options {
    const parsed = try std.json.parseFromSliceLeaky(ConfigJson, arena, json_bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
    });
    return optionsOf(arena, &parsed, files, names);
}

/// The JSON front-end's whole translation (#417): every block's spellings
/// parsed into options, zoxy's stock values applied where the file is
/// silent, and the files it names read through the seam. Nothing is judged
/// here that options written in code could also get wrong.
fn optionsOf(
    arena: std.mem.Allocator,
    parsed: *const ConfigJson,
    files: FileSource,
    names: NameSource,
) ParseError!Options {
    // A cluster's check budget defaults to the connect timeout, so the
    // timeouts translate first.
    const timeouts = timeoutsOf(&parsed.timeouts);
    const clusters = try clustersOf(arena, &parsed.clusters, timeouts.connect_ms, files, names);
    const listeners = try listenersOf(arena, parsed.listeners, files);
    const options: Options = .{
        .listeners = listeners,
        .clusters = clusters,
        .timeouts = timeouts,
        .limits = limitsOf(&parsed.limits),
        .access_log = try accessLogOf(parsed.access_log),
        .bodies = try bodiesOf(arena, parsed.bodies, files),
        .admin = try adminOf(parsed.admin),
        .error_pages = try errorPagesOf(arena, parsed.error_pages),
    };
    assert(options.listeners.len == parsed.listeners.len);
    assert(options.clusters.len == parsed.clusters.entries.len);
    return options;
}

/// The JSON front-end's clusters (#417): each entry's spellings parsed
/// into options, with the stock values for what the file left out, a CA
/// bundle read through the file seam and its endpoints' names resolved
/// through the name seam (#480). Nothing is judged here that a cluster
/// written in code could also get wrong — that is `resolveClusters`'.
fn clustersOf(
    arena: std.mem.Allocator,
    clusters_json: *const ClustersJson,
    connect_ms: u32,
    files: FileSource,
    names: NameSource,
) ParseError![]const Options.Cluster {
    const clusters = try arena.alloc(Options.Cluster, clusters_json.entries.len);
    for (clusters_json.entries, clusters) |*entry, *cluster| {
        cluster.* = try clusterOf(arena, entry, connect_ms, files, names);
    }
    assert(clusters.len == clusters_json.entries.len);
    return clusters;
}

fn clusterOf(
    arena: std.mem.Allocator,
    entry: *const ClustersJson.Entry,
    connect_ms: u32,
    files: FileSource,
    names: NameSource,
) ParseError!Options.Cluster {
    const cluster_json = &entry.cluster;
    const cluster: Options.Cluster = .{
        .name = entry.name,
        .endpoints = try endpointsOf(arena, cluster_json.endpoints, names),
        .pick = try pickOf(&cluster_json.pick),
        .protocol = try clusterProtocolOf(cluster_json.protocol),
        .check = try checkOf(cluster_json.check, connect_ms),
        .passive_ejection = passiveEjectionOf(cluster_json.passive_ejection),
        .panic_threshold_percent = cluster_json.panic_threshold_percent,
        .max_inflight = cluster_json.max_inflight,
        .max_total_inflight = cluster_json.max_total_inflight,
        .slow_start_ms = cluster_json.slow_start_ms,
        .retries = .{ .count = cluster_json.retries.count, .budget = cluster_json.retries.budget },
        .proxy_protocol_send = try proxyProtocolSendOf(cluster_json.proxy_protocol),
        .tls = try clusterTlsOf(arena, cluster_json.tls, files),
    };
    // A name may stand for several addresses, and two entries for one
    // address, so the counts agree only on a cluster that names none; a
    // name answers with one address at least, or refuses the load.
    if (cluster_json.endpoints.len >= 1) assert(cluster.endpoints.len >= 1);
    assert(cluster.name.len == entry.name.len);
    return cluster;
}

/// An address as JSON spells it (#303): `unix:` and a path, or an IP
/// literal (`parseLiteral` rejects hostnames, so nothing here resolves
/// one). Only the spelling is judged — a path's own rules are the
/// library's, which an address written in code meets as well.
fn addressOf(literal: []const u8) ?io_module.Address {
    if (std.mem.startsWith(u8, literal, unix_address_prefix)) {
        const path = literal[unix_address_prefix.len..];
        assert(path.len + unix_address_prefix.len == literal.len);
        return .{ .unix = path };
    }
    const ip = std.Io.net.IpAddress.parseLiteral(literal) catch return null;
    // `parseLiteral` takes no hostname, so nothing here ever resolved one.
    assert(literal.len >= 1);
    return .{ .ip = ip };
}

/// An endpoint's address as JSON spells it (#303, #480): an address, or
/// a DNS name and the port its addresses take.
const SpelledAddress = union(enum) {
    address: io_module.Address,
    name: Name,

    const Name = struct {
        /// Canonical (`dns.host`), in the arena.
        host: []const u8,
        port: u16,
    };
};

/// `literal` as an address, or as `host:port` with a DNS name — or null
/// when it is neither. A name's port is the text after its last colon,
/// so an unbracketed IPv6 literal, whose host part keeps colons, is no
/// name and earns the address's refusal.
fn spelledAddressOf(arena: std.mem.Allocator, literal: []const u8) ParseError!?SpelledAddress {
    if (addressOf(literal)) |address| return .{ .address = address };
    const colon = std.mem.lastIndexOfScalar(u8, literal, ':') orelse return null;
    const port = std.fmt.parseInt(u16, literal[colon + 1 ..], 10) catch return null;
    var buffer: [constants.dns_host_bytes_max]u8 = undefined;
    const host = dns_host.canonical(&buffer, literal[0..colon]) orelse return null;
    assert(host.len >= 1);
    // The library's rule for an address, held to a name's port too: a
    // name resolves to addresses, and every one of them carries it.
    if (port == 0) return error.EndpointPortZero;
    return .{ .name = .{ .host = try arena.dupe(u8, host), .port = port } };
}

/// A cluster's endpoints in either JSON form (#174), each name's addresses
/// in its place (#480): the literal parsed, a name resolved through the
/// seam, and the port, weights and tiers left to `resolveEndpoints`. A
/// cluster that names a host keeps each address once
/// (`dns.endpoints.mergeDuplicates`), as its set is kept once it serves.
fn endpointsOf(
    arena: std.mem.Allocator,
    endpoints_json: []const EndpointJson,
    names: NameSource,
) ParseError![]const Options.Cluster.Endpoint {
    var endpoints: std.ArrayList(Options.Cluster.Endpoint) = try .initCapacity(arena, endpoints_json.len);
    var named = false;
    for (endpoints_json) |*entry| {
        const spelled = try spelledAddressOf(arena, entry.address) orelse return error.EndpointInvalid;
        // A weight past a `u16` is past the ceiling too, and earns the
        // ceiling's refusal; the schema's `maximum` refuses it first.
        const weight = std.math.cast(u16, entry.weight) orelse return error.EndpointWeightOverLimit;
        switch (spelled) {
            .address => |address| {
                if (entry.family != null) return error.EndpointFamilyWithoutName;
                try endpoints.append(arena, .{ .address = address, .weight = weight, .priority = entry.priority });
            },
            .name => |name| {
                named = true;
                try appendNamed(arena, &endpoints, entry, &name, weight, names);
            },
        }
    }
    // Every entry gave one endpoint at least: an address one, a name its
    // answers, or the load stopped above.
    assert(endpoints.items.len >= endpoints_json.len);
    if (!named) return endpoints.items;
    const kept = dns_endpoints.mergeDuplicates(Options.Cluster.Endpoint, endpoints.items);
    assert(kept >= 1);
    return endpoints.items[0..kept];
}

/// The addresses `name` resolves to, in `dns.endpoints` order, each an
/// endpoint with its entry's weight and tier.
fn appendNamed(
    arena: std.mem.Allocator,
    endpoints: *std.ArrayList(Options.Cluster.Endpoint),
    entry: *const EndpointJson,
    name: *const SpelledAddress.Name,
    weight: u16,
    names: NameSource,
) ParseError!void {
    assert(dns_host.isCanonical(name.host));
    assert(name.port != 0);
    const family = try familyOf(entry.family);
    const answered = names.lookup(names.context, arena, name.host, name.port, family) catch |err| switch (err) {
        error.NameUnresolved => return error.EndpointNameUnresolved,
        error.OutOfMemory => return error.OutOfMemory,
    };
    assert(answered.len >= 1);
    // The source's order is not the set's.
    const addresses = try arena.dupe(std.Io.net.IpAddress, answered);
    dns_endpoints.sortAddresses(addresses);
    for (addresses) |*address| {
        assert(family.admits(address));
        assert(address.getPort() == name.port);
        try endpoints.append(arena, .{ .address = .{ .ip = address.* }, .weight = weight, .priority = entry.priority });
    }
}

/// An endpoint's `family` (#480): A records alone where it is absent.
fn familyOf(family_json: ?[]const u8) ValidationError!dns_host.Family {
    const spelled = family_json orelse return .ipv4;
    return std.meta.stringToEnum(dns_host.Family, spelled) orelse error.EndpointFamilyUnknown;
}

/// Either JSON spelling of `pick` (#178). The policy vocabulary is closed
/// — a typo ("pc2") fails loudly instead of silently balancing as p2c —
/// and so is the key's. `hash` *requires* a key, in the object form:
/// `source_ip` as a silent default was misleading (it reads as "sticky"
/// and quietly is not, behind NAT), so what the cluster keys on is the
/// operator's sentence to write. Key settings beside any other policy are
/// refused rather than left inert — they read as a request for stickiness
/// the cluster would silently not provide.
fn pickOf(pick_json: *const PickJson) ParseError!Options.Cluster.Pick {
    const policy = std.meta.stringToEnum(Config.Cluster.Pick.Builtin, pick_json.policy) orelse
        return error.ClusterPickUnknown;
    switch (policy) {
        .rr, .p2c => {
            if (pick_json.key != null or pick_json.name != null) {
                return error.ClusterPickKeyWithoutHash;
            }
            return if (policy == .rr) .rr else .p2c;
        },
        .hash => {},
    }
    const key_literal = pick_json.key orelse return error.ClusterPickKeyMissing;
    const key = std.meta.stringToEnum(std.meta.Tag(Config.Cluster.HashKey), key_literal) orelse
        return error.ClusterPickKeyUnknown;
    const hash_key: Config.Cluster.HashKey = switch (key) {
        .source_ip => if (pick_json.name != null) return error.ClusterPickNameUnexpected else .source_ip,
        .header => .{ .header = pick_json.name orelse return error.ClusterPickNameMissing },
        .cookie => .{ .cookie = pick_json.name orelse return error.ClusterPickNameMissing },
    };
    // A name travels exactly when the key reads one.
    assert((hash_key == .source_ip) == (pick_json.name == null));
    assert(policy == .hash);
    return .{ .hash = hash_key };
}

/// A cluster's §7 check as JSON spells it: the kind named by a string,
/// the http fields refused under any other kind rather than ignored — a
/// config that names a path for a check that will never request it is
/// describing something the process is not doing — and the stock values
/// for what is absent: the thresholds, a `200` verdict, and the connect
/// timeout as one probe's budget.
fn checkOf(check_json: ?CheckJson, connect_ms: u32) ParseError!?Options.Cluster.Check {
    const check = check_json orelse return null;
    // The JSON vocabulary: a build's own kind (#436) is selected in code,
    // so `extension` is as unknown here as a misspelling.
    const kind = std.meta.stringToEnum(Config.Cluster.Check.Builtin, check.type) orelse
        return error.ClusterCheckTypeUnknown;
    if (kind != .grpc and check.service != null) return error.ClusterCheckServiceWithoutGrpc;
    const http_fields = check.path != null or check.host != null or check.expect_status != null;
    const stated: Options.Cluster.Check.Kind = switch (kind) {
        .tcp => if (http_fields) return error.ClusterCheckHttpFieldOnTcp else .tcp,
        .http => .{ .http = .{
            .path = check.path orelse return error.ClusterCheckPathMissing,
            .host = check.host,
            .expect_status = check.expect_status orelse defaults.check.expect_status,
        } },
        // The health protocol fixes the path and the verdict (a SERVING
        // answer, not a status), and the authority is the cluster's.
        .grpc => blk: {
            if (http_fields) return error.ClusterCheckHttpFieldOnGrpc;
            // Absent asks about the server; an empty name would be a
            // second spelling of that, and the schema's `minLength`
            // refuses it.
            if (check.service) |named| {
                if (named.len == 0) return error.ClusterCheckServiceInvalid;
            }
            break :blk .{ .grpc = .{ .service = check.service orelse "" } };
        },
    };
    assert(stated == kind.kind());
    return .{
        .kind = stated,
        .fall = check.fall,
        .rise = check.rise,
        .timeout_ms = check.timeout_ms orelse connect_ms,
    };
}

fn passiveEjectionOf(
    passive_ejection_json: ?PassiveEjectionJson,
) ?Options.Cluster.PassiveEjection {
    const passive_ejection = passive_ejection_json orelse return null;
    return .{
        .fall = passive_ejection.fall,
        .recovery_ms = passive_ejection.recovery_ms,
        .recovery_ms_max = passive_ejection.recovery_ms_max,
    };
}

/// A cluster's origin protocol (§7): the closed vocabulary, which the
/// schema states too.
fn clusterProtocolOf(protocol: []const u8) ValidationError!Config.Cluster.Protocol {
    return std.meta.stringToEnum(Config.Cluster.Protocol, protocol) orelse error.ClusterProtocolUnknown;
}

/// A cluster's PROXY protocol announcement (#142): absent is off, and the
/// version vocabulary is closed. The l4-only restriction is enforced where
/// listeners resolve — reachability is a property of the listener/cluster
/// *pair*, and only that side sees both.
fn proxyProtocolSendOf(
    proxy_protocol_json: ?ClusterProxyProtocolJson,
) ValidationError!?Config.Cluster.ProxyProtocolSend {
    const proxy_protocol = proxy_protocol_json orelse return null;
    return std.meta.stringToEnum(
        Config.Cluster.ProxyProtocolSend,
        proxy_protocol.send,
    ) orelse error.ClusterProxyProtocolSendUnknown;
}

/// A cluster's CA bundle, read through the front-end's file seam (§7):
/// the JSON names a path, and the options carry the bytes.
fn clusterTlsOf(
    arena: std.mem.Allocator,
    tls_json: ?ClusterTlsJson,
    files: FileSource,
) ParseError!?Options.Cluster.Tls {
    const tls = tls_json orelse return null;
    if (tls.ca.path.len == 0) return error.ClusterTlsCaUnreadable;
    const pem = files.read(files.context, arena, tls.ca.path, constants.origin_ca_bytes_max) catch |err| switch (err) {
        error.FileUnreadable, error.FileTooLarge => return error.ClusterTlsCaUnreadable,
        error.OutOfMemory => return error.OutOfMemory,
    };
    assert(pem.len <= constants.origin_ca_bytes_max);
    assert(tls.ca.path.len >= 1);
    return .{ .server_name = tls.server_name, .ca_pem = pem };
}

/// The JSON front-end's #159 bodies: exactly one source arm per body —
/// `file` XOR `inline`, the redirect target's exactly-one-fork rule — and
/// a file read through the seam under the same cap the library holds every
/// body to, so an oversized file is refused before it is read whole.
fn bodiesOf(
    arena: std.mem.Allocator,
    bodies_json: ?BodiesJson,
    files: FileSource,
) ParseError![]const Options.Body {
    const parsed = bodies_json orelse return &.{};
    // The library's bound, stated ahead of the reads too, so a table that
    // will be refused is refused before it costs a file read per entry.
    if (parsed.entries.len > std.math.maxInt(u16)) {
        return error.BodiesOverLimit;
    }
    const bodies = try arena.alloc(Options.Body, parsed.entries.len);
    for (parsed.entries, bodies) |*entry, *body| {
        body.* = .{
            .name = entry.name,
            .bytes = try bodyBytesOf(arena, &entry.body, files),
            .content_type = entry.body.content_type,
        };
    }
    assert(bodies.len == parsed.entries.len);
    return bodies;
}

/// One body's bytes through its one source arm. A file is read under the
/// cap, so an oversized one is refused without being read whole; an inline
/// body is passed through, and `resolveBodies` holds it to the same cap.
fn bodyBytesOf(
    arena: std.mem.Allocator,
    body_json: *const BodyJson,
    files: FileSource,
) ParseError![]const u8 {
    const has_file = body_json.file != null;
    const has_inline = body_json.@"inline" != null;
    if (!has_file and !has_inline) {
        return error.BodySourceMissing;
    }
    if (has_file and has_inline) {
        return error.BodySourceAmbiguous;
    }
    const path = body_json.file orelse return body_json.@"inline".?;
    if (path.len == 0) {
        return error.BodyFileUnreadable;
    }
    const bytes = files.read(
        files.context,
        arena,
        path,
        constants.body_bytes_max,
    ) catch |err| switch (err) {
        error.FileUnreadable => return error.BodyFileUnreadable,
        error.FileTooLarge => return error.BodyOverLimit,
        error.OutOfMemory => return error.OutOfMemory,
    };
    assert(!has_inline);
    assert(bytes.len <= constants.body_bytes_max);
    return bytes;
}

/// The JSON front-end's `error_pages`: a map keyed by status, so the key
/// is text that has to parse as one. Which statuses may carry a page is
/// the library's rule.
fn errorPagesOf(
    arena: std.mem.Allocator,
    error_pages_json: ?ErrorPagesJson,
) ParseError![]const Options.ErrorPage {
    const parsed = error_pages_json orelse return &.{};
    // The library's bound, ahead of the key parse, so a map the closed
    // status set cannot hold is told so by its size, as it always was.
    if (parsed.entries.len > shed.static_statuses.len) {
        return error.ErrorPagesOverLimit;
    }
    const pages = try arena.alloc(Options.ErrorPage, parsed.entries.len);
    for (parsed.entries, pages) |entry, *page| {
        page.* = .{
            .status = std.fmt.parseUnsigned(u16, entry.status, 10) catch
                return error.ErrorPageStatusInvalid,
            .body = entry.body,
        };
    }
    assert(pages.len == parsed.entries.len);
    return pages;
}

/// The JSON front-end's access log (§8): the sink named by a string, and
/// `path` required by the file sink and refused beside stdout — the fork
/// the schema states too. Absent lists record no header.
fn accessLogOf(access_log_json: ?AccessLogJson) ValidationError!?Options.AccessLog {
    const access_log = access_log_json orelse return null;
    const kind = std.meta.stringToEnum(Config.AccessLogSinkKind, access_log.sink) orelse
        return error.AccessLogSinkUnknown;
    const sink: Options.AccessLog.Sink = switch (kind) {
        .stdout => if (access_log.path != null) return error.AccessLogPathOnStdout else .stdout,
        .file => .{ .file = access_log.path orelse return error.AccessLogPathMissing },
    };
    assert(@as(Config.AccessLogSinkKind, sink) == kind);
    assert((sink == .file) == (access_log.path != null));
    return .{
        .sink = sink,
        .request_headers = access_log.request_headers orelse &.{},
        .response_headers = access_log.response_headers orelse &.{},
    };
}

/// The JSON front-end's admin listener (§8): a present `bind` must be a
/// static IP:port literal (hostnames rejected, like every other bind).
fn adminOf(admin_json: ?AdminJson) ValidationError!?Options.Admin {
    const admin = admin_json orelse return null;
    const bind = std.Io.net.IpAddress.parseLiteral(admin.bind) catch
        return error.AdminBindInvalid;
    return .{ .bind = bind };
}

/// The JSON front-end's listeners (#417): each one's spellings parsed into
/// options — the bind literal, the protocol body its key chose, the mode's
/// octal string, the strings and forks inside — and its TLS files read
/// through the seam. Nothing is judged here that a listener written in
/// code could also get wrong; that is `resolveListeners`'.
fn listenersOf(
    arena: std.mem.Allocator,
    listeners_json: []const ListenerJson,
    files: FileSource,
) ParseError![]const Options.Listener {
    const listeners = try arena.alloc(Options.Listener, listeners_json.len);
    for (listeners_json, listeners) |*listener_json, *listener| {
        listener.* = try listenerOf(arena, listener_json, files);
    }
    assert(listeners.len == listeners_json.len);
    return listeners;
}

fn listenerOf(
    arena: std.mem.Allocator,
    listener_json: *const ListenerJson,
    files: FileSource,
) ParseError!Options.Listener {
    const bind = addressOf(listener_json.bind) orelse return error.ListenerBindInvalid;
    // The key decides the body, so a listener that names neither body or
    // both is refused before anything inside either is read (#305).
    const kind = try protocolOf(listener_json);
    const tls = try tlsOf(arena, &listener_json.tls, files);
    const protocol: Options.Listener.Protocol = switch (kind) {
        .http => .{ .http = try httpOf(arena, &listener_json.http.?) },
        .l4 => .{ .l4 = try l4Of(arena, &listener_json.l4.?) },
    };
    const listener: Options.Listener = .{
        .bind = bind,
        .mode = try bindModeOf(listener_json.mode),
        .tls = tls,
        .protocol = protocol,
    };
    assert(listener.protocol == kind);
    assert((listener.tls != null) == (listener_json.tls != null));
    return listener;
}

/// The `mode` a `unix:` bind asks for its socket file (#303), as the octal
/// string an operator writes in every other tool.
///
/// A string rather than a JSON number, because `0660` in JSON is not valid
/// and `660` is decimal — the two spellings of the same intent differ by a
/// factor of eight, and a mode that is silently wider than asked for is
/// the failure this feature exists to avoid. Which bits a mode may set is
/// the library's rule (`resolveBindMode`).
fn bindModeOf(mode_json: ?[]const u8) ParseError!?io_module.FileMode {
    const text = mode_json orelse return null;
    if (text.len == 0 or text.len > 4) {
        return error.ListenerModeInvalid;
    }
    var bits: u16 = 0;
    for (text) |digit| {
        if (digit < '0' or digit > '7') {
            return error.ListenerModeInvalid;
        }
        bits = bits * 8 + (digit - '0');
    }
    // Four octal digits reach exactly the file system's vocabulary.
    assert(bits <= io_module.FileMode.bits_max);
    assert(text.len >= 1);
    return .{ .bits = bits };
}

/// A listener's TLS block as JSON spells it (§4): the certificate and key
/// read through the file seam (#417), so a file that is missing, unreadable
/// or past `tls_pem_bytes_max` fails the load and names the path; the ALPN
/// tokens parsed; the client CA's verify mode named and its bundle read;
/// and the further pairs read like the default one.
fn tlsOf(
    arena: std.mem.Allocator,
    tls_json: *const ?TlsJson,
    files: FileSource,
) ParseError!?Options.Listener.Tls {
    const tls = if (tls_json.*) |*tls| tls else return null;
    const pair = try readCertificatePair(arena, tls.cert, tls.key, files);
    const stated: Options.Listener.Tls = .{
        .cert_pem = pair.cert_pem,
        .key_pem = pair.key_pem,
        .label = pair.label,
        .alpn = try alpnOf(arena, tls.alpn),
        .client_ca = try clientCaOf(arena, &tls.client_ca, files),
        .certificates = try certificatesOf(arena, tls.certificates, files),
    };
    assert(stated.cert_pem.len >= 1);
    assert(stated.key_pem.len >= 1);
    return stated;
}

/// The ALPN offer's tokens, parsed against the closed vocabulary (#271): a
/// name this proxy does not speak is refused rather than offered to a
/// client that would then speak it at a parser that cannot.
fn alpnOf(
    arena: std.mem.Allocator,
    alpn_json: ?[]const []const u8,
) ParseError!?[]const alpn.Protocol {
    const tokens = alpn_json orelse return null;
    const offer = try arena.alloc(alpn.Protocol, tokens.len);
    for (tokens, offer) |token, *named| {
        named.* = alpn.Protocol.fromToken(token) orelse return error.ListenerTlsAlpnUnknown;
    }
    assert(offer.len == tokens.len);
    return offer;
}

/// A listener's #304 client CA as JSON spells it: the verify mode named
/// from a closed set, and the bundle read through the file seam.
fn clientCaOf(
    arena: std.mem.Allocator,
    client_ca_json: *const ?ClientCaJson,
    files: FileSource,
) ParseError!?Options.Listener.ClientCa {
    const client_ca = if (client_ca_json.*) |*client_ca| client_ca else return null;
    const verify = std.meta.stringToEnum(Config.Listener.ClientVerify, client_ca.verify) orelse
        return error.ListenerTlsClientVerifyUnknown;
    if (client_ca.path.len == 0) return error.ListenerTlsClientCaUnreadable;
    const pem = files.read(files.context, arena, client_ca.path, constants.origin_ca_bytes_max) catch |err| switch (err) {
        error.FileUnreadable, error.FileTooLarge => return error.ListenerTlsClientCaUnreadable,
        error.OutOfMemory => return error.OutOfMemory,
    };
    assert(pem.len <= constants.origin_ca_bytes_max);
    assert(client_ca.path.len >= 1);
    return .{ .ca_pem = pem, .verify = verify };
}

/// A listener's #297 further certificates, each read like the default
/// pair. An explicitly empty list is a mistake rather than "none" —
/// absence already says that — and a list the ceiling refuses is refused
/// before its files are read.
fn certificatesOf(
    arena: std.mem.Allocator,
    certificates_json: ?[]const CertificateJson,
    files: FileSource,
) ParseError![]const Config.Listener.Certificate {
    const entries = certificates_json orelse return &.{};
    if (entries.len == 0) return error.ListenerTlsCertificatesEmpty;
    if (entries.len >= constants.tls_certificates_max) return error.ListenerTlsCertificatesOverLimit;
    const certificates = try arena.alloc(Config.Listener.Certificate, entries.len);
    for (entries, certificates) |entry, *certificate| {
        certificate.* = try readCertificatePair(arena, entry.cert, entry.key, files);
    }
    assert(certificates.len >= 1);
    assert(certificates.len < constants.tls_certificates_max);
    return certificates;
}

/// An http listener's body as JSON spells it: exactly one of `cluster` or
/// `routes`, and the strings and forks inside the filters.
fn httpOf(
    arena: std.mem.Allocator,
    http_json: *const HttpListenerJson,
) ParseError!Options.Listener.Http {
    const has_cluster = http_json.cluster != null;
    const has_routes = http_json.routes != null;
    if (has_cluster == has_routes) {
        return error.ListenerClusterOrRoutes; // Neither, or both.
    }
    const target: Options.Listener.Target = if (http_json.cluster) |name|
        .{ .cluster = name }
    else
        .{ .routes = try routesOf(arena, http_json.routes.?) };
    assert((target == .routes) == has_routes);
    return .{
        .target = target,
        .request_filters = try filtersOf(arena, http_json.request_filters orelse &.{}),
        .response_filters = try responseFiltersOf(arena, http_json.response_filters orelse &.{}),
        .forwarded = try forwardedOf(&http_json.forwarded),
        .upgrades = upgradesOf(http_json.upgrades),
        .max_body_bytes = http_json.max_body_bytes,
        .keepalive_requests = http_json.keepalive_requests,
        .proxy_status = http_json.proxy_status,
        .h2c = http_json.h2c,
        .quic = try quicOf(&http_json.quic),
    };
}

/// An http listener's QUIC binding as JSON spells it (#449): the bind
/// literal in the grammar every other bind has, so a `unix:` path parses
/// here and earns the library's own refusal, which code meets too.
fn quicOf(quic_json: *const ?QuicJson) ParseError!?Options.Listener.Quic {
    const quic = if (quic_json.*) |*quic| quic else return null;
    const bind = addressOf(quic.bind) orelse return error.ListenerQuicBindInvalid;
    assert(quic.bind.len >= 1);
    return .{ .bind = bind, .alt_svc_max_age_s = quic.alt_svc_max_age_s };
}

fn routesOf(
    arena: std.mem.Allocator,
    routes_json: []const RouteJson,
) ParseError![]const Options.Listener.Route {
    const routes = try arena.alloc(Options.Listener.Route, routes_json.len);
    for (routes_json, routes) |*route_json, *route| {
        route.* = .{
            .host = route_json.host,
            .prefix = route_json.prefix,
            .header = if (route_json.header) |*header| try routeHeaderOf(header) else null,
            .cluster = route_json.cluster,
        };
    }
    assert(routes.len == routes_json.len);
    return routes;
}

/// A route's header predicate (#302) as JSON spells it: exactly one of
/// `present: true` or `equals`.
fn routeHeaderOf(header_json: *const RouteHeaderJson) ParseError!Options.Listener.RouteHeader {
    const set: u8 = @as(u8, @intFromBool(header_json.present != null)) +
        @intFromBool(header_json.equals != null);
    assert(set <= 2); // The route header has two kind fields.
    if (set != 1) {
        return error.RouteHeaderMatchKind;
    }
    if (header_json.present) |present| {
        if (!present) {
            return error.RouteHeaderMatchKind; // "present: false" is not a predicate.
        }
        return .{ .name = header_json.name, .predicate = .present };
    }
    return .{ .name = header_json.name, .predicate = .{ .equals = header_json.equals.? } };
}

fn filtersOf(
    arena: std.mem.Allocator,
    filters_json: []const FilterJson,
) ParseError![]const Options.Listener.Filter {
    const rules = try arena.alloc(Options.Listener.Filter, filters_json.len);
    for (filters_json, rules) |*rule_json, *rule| {
        rule.* = .{
            .match = try matchOf(arena, &rule_json.match),
            .actions = try actionsOf(arena, rule_json.actions),
        };
    }
    assert(rules.len == filters_json.len);
    return rules;
}

fn matchOf(arena: std.mem.Allocator, match_json: *const MatchJson) ParseError!Options.Listener.Match {
    const match: Options.Listener.Match = .{
        .methods = if (match_json.method) |tokens| try methodsOf(tokens) else null,
        .host = match_json.host,
        .path_prefix = match_json.path_prefix,
        .headers = try headerMatchesOf(arena, match_json.headers orelse &.{}),
        .clients = if (match_json.client) |literals| try clientCidrsOf(arena, literals) else &.{},
    };
    assert((match.methods != null) == (match_json.method != null));
    return match;
}

/// A filter's method tokens: an explicitly empty list is a mistake, not
/// "any" — absence already says that, unambiguously — and the vocabulary
/// is the parser's.
fn methodsOf(tokens: []const []const u8) ParseError!std.EnumSet(parser.Method) {
    if (tokens.len == 0) {
        return error.FilterMethodEmpty;
    }
    var methods = std.EnumSet(parser.Method){};
    for (tokens) |token| {
        const method = parser.methodFromToken(token) orelse return error.FilterMethodUnknown;
        methods.insert(method);
    }
    assert(methods.count() >= 1);
    assert(methods.count() <= tokens.len);
    return methods;
}

fn headerMatchesOf(
    arena: std.mem.Allocator,
    headers_json: []const HeaderMatchJson,
) ParseError![]const Options.Listener.HeaderMatch {
    const matches = try arena.alloc(Options.Listener.HeaderMatch, headers_json.len);
    for (headers_json, matches) |header_json, *match| {
        // Exactly one predicate kind per header match; which one is
        // `headerPredicateOf`'s.
        const set: u8 = @as(u8, @intFromBool(header_json.present != null)) +
            @intFromBool(header_json.equals != null) +
            @intFromBool(header_json.contains != null);
        assert(set <= 3); // The header match has three kind fields.
        if (set != 1) {
            return error.FilterHeaderMatchKind;
        }
        match.* = .{ .name = header_json.name, .predicate = try headerPredicateOf(&header_json) };
    }
    assert(matches.len == headers_json.len);
    return matches;
}

/// The one kind a header match names, past the exactly-one count.
fn headerPredicateOf(header_json: *const HeaderMatchJson) ParseError!Options.Listener.HeaderMatch.Predicate {
    if (header_json.present) |present| {
        if (!present) {
            return error.FilterHeaderMatchKind; // "present: false" is not a predicate.
        }
        assert(header_json.equals == null);
        return .present;
    }
    if (header_json.equals) |value| {
        assert(header_json.contains == null);
        return .{ .equals = value };
    }
    return .{ .contains = header_json.contains.? };
}

/// A `client` predicate's CIDR literals (#177). An explicitly empty list
/// is a mistake — absence already says "any client", unambiguously (the
/// `FilterMethodEmpty` rule).
fn clientCidrsOf(
    arena: std.mem.Allocator,
    literals: []const []const u8,
) ParseError![]const filter.Cidr {
    if (literals.len == 0) {
        return error.FilterClientEmpty;
    }
    const cidrs = try arena.alloc(filter.Cidr, literals.len);
    for (literals, cidrs) |literal, *cidr| {
        cidr.* = try clientCidrOf(literal);
    }
    assert(cidrs.len == literals.len);
    return cidrs;
}

/// One CIDR literal, parsed. The `/len` is mandatory — a bare address has
/// no single meaning across families (an exact IPv4 host is /32, but an
/// exact IPv6 *client* is its /64), so the spelling that would need
/// per-family folklore is refused instead. Whether the prefix is one a
/// client can be matched by is the library's (`validateClientCidr`).
fn clientCidrOf(literal: []const u8) ParseError!filter.Cidr {
    const slash = std.mem.indexOfScalar(u8, literal, '/') orelse
        return error.FilterClientCidrInvalid;
    const address_text = literal[0..slash];
    const prefix_text = literal[slash + 1 ..];
    if (prefix_text.len == 0) {
        return error.FilterClientPrefixInvalid;
    }
    const prefix_len = std.fmt.parseUnsigned(u8, prefix_text, 10) catch
        return error.FilterClientPrefixInvalid;
    const address = std.Io.net.IpAddress.parse(address_text, 0) catch
        return error.FilterClientCidrInvalid;
    assert(slash < literal.len);
    assert(prefix_text.len >= 1);
    return .{ .address = address, .prefix_len = prefix_len };
}

fn actionsOf(
    arena: std.mem.Allocator,
    actions_json: []const ActionJson,
) ParseError![]const Options.Listener.Action {
    const actions = try arena.alloc(Options.Listener.Action, actions_json.len);
    for (actions_json, actions) |*action_json, *action| {
        action.* = try actionOf(action_json);
    }
    assert(actions.len == actions_json.len);
    return actions;
}

/// One action as JSON spells it: an object with exactly one kind field.
fn actionOf(action_json: *const ActionJson) ParseError!Options.Listener.Action {
    try requireOneActionKind(action_json);
    if (action_json.reject) |status| return .{ .reject = status };
    if (action_json.redirect) |redirect_json| return .{ .redirect = try redirectOf(&redirect_json) };
    if (action_json.respond) |respond_json| {
        return .{ .respond = .{ .status = respond_json.status, .body = respond_json.body } };
    }
    if (action_json.allow) |allow| {
        // `allow: false` is the same non-predicate `present: false` is: a
        // key that names an action and then unsays it. Refused rather
        // than read as "not allow", which is not an action either.
        if (!allow) {
            return error.FilterActionKind;
        }
        return .allow;
    }
    if (action_json.header_set) |edit| return .{ .header_set = .{ .name = edit.name, .value = edit.value } };
    if (action_json.header_add) |edit| return .{ .header_add = .{ .name = edit.name, .value = edit.value } };
    if (action_json.header_remove) |name| return .{ .header_remove = name };
    const rewrite = action_json.rewrite_prefix.?;
    return .{ .rewrite_prefix = .{ .from = rewrite.from, .to = rewrite.to } };
}

/// A `redirect` action's target as JSON spells it (#176): exactly one of a
/// fixed `location` or a composed target, whose `scheme` is required and
/// named from a closed set.
fn redirectOf(redirect_json: *const RedirectJson) ParseError!filter.Redirect {
    const has_location = redirect_json.location != null;
    const has_composed = redirect_json.scheme != null or redirect_json.host != null;
    if (has_location == has_composed) {
        // Neither form, or both at once.
        return error.FilterRedirectTarget;
    }
    if (redirect_json.location) |location| {
        return .{ .status = redirect_json.status, .target = .{ .location = location } };
    }
    const scheme_literal = redirect_json.scheme orelse {
        // Host without scheme: half a composed target.
        return error.FilterRedirectTarget;
    };
    const scheme = std.meta.stringToEnum(filter.Redirect.Scheme, scheme_literal) orelse
        return error.FilterRedirectSchemeUnknown;
    assert(has_composed);
    assert(!has_location);
    return .{
        .status = redirect_json.status,
        .target = .{ .composed = .{ .scheme = scheme, .host = redirect_json.host } },
    };
}

fn responseFiltersOf(
    arena: std.mem.Allocator,
    filters_json: []const ResponseFilterJson,
) ParseError![]const Options.Listener.ResponseFilter {
    const rules = try arena.alloc(Options.Listener.ResponseFilter, filters_json.len);
    for (filters_json, rules) |*rule_json, *rule| {
        rule.* = .{
            .match = try responseMatchOf(arena, &rule_json.match),
            .actions = try responseActionsOf(arena, rule_json.actions),
        };
    }
    assert(rules.len == filters_json.len);
    return rules;
}

fn responseMatchOf(
    arena: std.mem.Allocator,
    match_json: *const ResponseMatchJson,
) ParseError!Options.Listener.ResponseMatch {
    var match: Options.Listener.ResponseMatch = .{};
    if (match_json.status) |statuses| {
        // An explicitly empty list is a mistake, not "any" — absence
        // already says that, unambiguously (the `FilterMethodEmpty` rule).
        if (statuses.len == 0) {
            return error.ResponseFilterStatusEmpty;
        }
        match.statuses = statuses;
    }
    if (match_json.status_class) |literal| {
        match.status_class = std.meta.stringToEnum(filter.StatusClass, literal) orelse
            return error.ResponseFilterStatusClassUnknown;
    }
    match.headers = try headerMatchesOf(arena, match_json.headers orelse &.{});
    assert((match.status_class != null) == (match_json.status_class != null));
    return match;
}

fn responseActionsOf(
    arena: std.mem.Allocator,
    actions_json: []const ResponseActionJson,
) ParseError![]const Options.Listener.ResponseAction {
    const actions = try arena.alloc(Options.Listener.ResponseAction, actions_json.len);
    for (actions_json, actions) |*action_json, *action| {
        action.* = try responseActionOf(action_json);
    }
    assert(actions.len == actions_json.len);
    return actions;
}

/// One response action as JSON spells it. The kind fork is the whole check
/// for this table: the request-side actions are not fields here, so a
/// config naming one is refused by the strict parser rather than by rules
/// this front-end would have to carry (#305).
fn responseActionOf(action_json: *const ResponseActionJson) ParseError!Options.Listener.ResponseAction {
    try requireOneResponseActionKind(action_json);
    if (action_json.header_set) |edit| return .{ .header_set = .{ .name = edit.name, .value = edit.value } };
    if (action_json.header_add) |edit| return .{ .header_add = .{ .name = edit.name, .value = edit.value } };
    return .{ .header_remove = action_json.header_remove.? };
}

/// Client-address forwarding as JSON spells it (§7): absent is off, and
/// the mode is named from a closed set.
fn forwardedOf(forwarded_json: *const ?ForwardedJson) ValidationError!?Config.Listener.Forwarded {
    const forwarded = if (forwarded_json.*) |*forwarded| forwarded else return null;
    return std.meta.stringToEnum(Config.Listener.Forwarded, forwarded.mode) orelse
        error.ListenerForwardedModeUnknown;
}

/// The #180 upgrade allowlist as JSON spells it: absent allows none, so an
/// `Upgrade` keeps the `501` it has always got.
///
/// The vocabulary is `UpgradesJson`'s own fields, held to the resolved
/// set's by a comptime check there — so a protocol the proxy can carry and
/// one an operator may write cannot drift apart. Anything else is refused
/// by the strict parser rather than by a rule here (#305): a config that
/// asked to tunnel `h2c` and got silence would believe it had, and after
/// `101` there is no rule left to catch what came through.
fn upgradesOf(upgrades_json: ?UpgradesJson) Config.Listener.Upgrades {
    const asked = upgrades_json orelse return .{};
    var upgrades: Config.Listener.Upgrades = .{};
    inline for (@typeInfo(UpgradesJson).@"struct".field_names) |name| {
        @field(upgrades, name) = @field(asked, name);
    }
    return upgrades;
}

/// An l4 listener's body as JSON spells it: exactly one of `cluster` or
/// `routes`, and the PROXY protocol mode named from a closed set.
fn l4Of(arena: std.mem.Allocator, l4_json: *const L4ListenerJson) ParseError!Options.Listener.L4 {
    const has_cluster = l4_json.cluster != null;
    const has_routes = l4_json.routes != null;
    if (has_cluster == has_routes) {
        return error.ListenerClusterOrRoutes; // Neither, or both.
    }
    const target: Options.Listener.L4Target = if (l4_json.cluster) |name|
        .{ .cluster = name }
    else
        .{ .routes = try sniRoutesOf(arena, l4_json.routes.?) };
    assert((target == .routes) == has_routes);
    return .{ .target = target, .proxy_protocol = try proxyProtocolOf(&l4_json.proxy_protocol) };
}

fn sniRoutesOf(
    arena: std.mem.Allocator,
    routes_json: []const L4RouteJson,
) ParseError![]const Options.Listener.SniRoute {
    const routes = try arena.alloc(Options.Listener.SniRoute, routes_json.len);
    for (routes_json, routes) |route_json, *route| {
        route.* = .{ .sni = route_json.sni, .cluster = route_json.cluster };
    }
    assert(routes.len == routes_json.len);
    return routes;
}

/// A listener's PROXY protocol expectation as JSON spells it (#142):
/// absent is off, and the mode is named from a closed set. Reachable only
/// from an `l4` body — the L7 path has no receive phase yet, so an http
/// listener has nowhere to state a trust boundary nothing enforces, which
/// the shape now closes rather than a rejection (#305).
fn proxyProtocolOf(
    proxy_protocol_json: *const ?ProxyProtocolJson,
) ValidationError!?Config.Listener.ProxyProtocol {
    const proxy_protocol = if (proxy_protocol_json.*) |*proxy_protocol| proxy_protocol else return null;
    return std.meta.stringToEnum(Config.Listener.ProxyProtocol, proxy_protocol.mode) orelse
        error.ListenerProxyProtocolModeUnknown;
}

/// The limits a config states only in code: the consult slots (#437),
/// which only a build's own policies can use.
const code_only_limits = [_][]const u8{"consult_slots"};

/// The JSON front-end's limits (#417): the same nullable members, copied
/// across. Absence already means "zoxy's rule" on both sides, so there is
/// no stock value to apply here — the rule lives in the resolvers below,
/// where options written in code meet it too.
fn limitsOf(limits_json: *const LimitsJson) Options.Limits {
    // One vocabulary in two places, but for the members only code can
    // state. The count pins the name sets equal less those (the loop
    // below fails to compile on a JSON member the options lack, and the
    // count catches the reverse), and the type check keeps a member from
    // quietly widening on one side only.
    comptime assert(@typeInfo(LimitsJson).@"struct".field_names.len + code_only_limits.len ==
        @typeInfo(Options.Limits).@"struct".field_names.len);
    inline for (code_only_limits) |name| {
        comptime assert(@hasField(Options.Limits, name));
        comptime assert(!@hasField(LimitsJson, name));
    }
    var limits: Options.Limits = .{};
    inline for (@typeInfo(LimitsJson).@"struct".field_names) |name| {
        comptime assert(@FieldType(LimitsJson, name) == @FieldType(Options.Limits, name));
        @field(limits, name) = @field(limits_json, name);
    }
    return limits;
}

/// The JSON front-end's timeouts (#417): the stock values where a key
/// is absent, the derived head budget among them, and nothing judged —
/// every refusal is `validateTimeouts`', made of the options alone.
fn timeoutsOf(timeouts_json: *const TimeoutsJson) Options.Timeouts {
    const timeouts: Options.Timeouts = .{
        .connect_ms = timeouts_json.connect_ms,
        .idle_ms = timeouts_json.idle_ms,
        .head_ms = timeouts_json.head_ms orelse
            defaults.headMs(timeouts_json.connect_ms, timeouts_json.idle_ms),
        .tunnel_ms = timeouts_json.tunnel_ms,
        .health_interval_ms = timeouts_json.health_interval_ms,
        .request_ms = timeouts_json.request_ms,
        .max_lifetime_ms = timeouts_json.max_lifetime_ms,
        .drain_deadline_ms = timeouts_json.drain_deadline_ms,
        .loop_watchdog_ms = timeouts_json.loop_watchdog_ms,
    };
    // A stated budget always wins over the derived one, and the derived
    // one fills only an absent key.
    if (timeouts_json.head_ms) |stated| assert(timeouts.head_ms == stated);
    assert(timeouts.idle_ms == timeouts_json.idle_ms);
    return timeouts;
}

/// The response table's kind fork (#305). Three members rather than the
/// request's eight, and the same verdict — a rule naming none or two
/// has no single action to apply.
fn requireOneResponseActionKind(action_json: *const ResponseActionJson) ParseError!void {
    const set: u8 = @as(u8, @intFromBool(action_json.header_set != null)) +
        @intFromBool(action_json.header_add != null) +
        @intFromBool(action_json.header_remove != null);
    assert(set <= 3); // The response action object has three kind fields.
    if (set != 1) {
        return error.FilterActionKind;
    }
    assert(set == 1);
}

/// Exactly one action field may carry the kind — the "exactly one of"
/// fork both action translators share, so an eighth kind cannot be
/// counted in one table and forgotten in the other.
fn requireOneActionKind(action_json: *const ActionJson) ParseError!void {
    const set: u8 = @as(u8, @intFromBool(action_json.reject != null)) +
        @intFromBool(action_json.redirect != null) +
        @intFromBool(action_json.respond != null) +
        @intFromBool(action_json.allow != null) +
        @intFromBool(action_json.header_set != null) +
        @intFromBool(action_json.header_add != null) +
        @intFromBool(action_json.header_remove != null) +
        @intFromBool(action_json.rewrite_prefix != null);
    assert(set <= 8); // The action object has eight kind fields.
    if (set != 1) {
        return error.FilterActionKind;
    }
    assert(set == 1);
}

/// One certificate and key, read through the file seam (#417) — an empty
/// path refused first, since it would reach `openat` as a request to open
/// the current directory — and labelled with both paths for the startup
/// error that names them if the PEM inside turns out to be unusable.
fn readCertificatePair(
    arena: std.mem.Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    files: FileSource,
) ParseError!Config.Listener.Certificate {
    if (cert_path.len == 0) return error.ListenerTlsCertPathEmpty;
    if (key_path.len == 0) return error.ListenerTlsKeyPathEmpty;
    const pair: Config.Listener.Certificate = .{
        .cert_pem = try readListenerPem(arena, files, cert_path),
        .key_pem = try readListenerPem(arena, files, key_path),
        .label = try std.fmt.allocPrint(arena, "'{s}' + '{s}'", .{ cert_path, key_path }),
    };
    assert(pair.label.len > cert_path.len + key_path.len);
    return pair;
}

fn readListenerPem(arena: std.mem.Allocator, files: FileSource, path: []const u8) ParseError![]const u8 {
    assert(path.len >= 1);
    const pem = files.read(files.context, arena, path, constants.tls_pem_bytes_max) catch |err| switch (err) {
        error.FileUnreadable, error.FileTooLarge => return error.ListenerTlsFileUnreadable,
        error.OutOfMemory => return error.OutOfMemory,
    };
    // An empty file holds no certificate and no key: refused with the
    // unreadable ones, so a loaded pair is never empty.
    if (pem.len == 0) return error.ListenerTlsFileUnreadable;
    assert(pem.len <= constants.tls_pem_bytes_max);
    return pem;
}

/// Which protocol a listener's tag names (#305). The vocabulary used to
/// be a string this compared against, where a typo ("htpp") had to be
/// caught by hand and turned into an error; it is now the body's own key,
/// so an unknown one is an unknown field the strict parser already
/// refuses and the only fault left to name here is a listener that
/// declares neither body or both.
fn protocolOf(listener_json: *const ListenerJson) error{ListenerHttpOrL4}!Config.Listener.Protocol {
    if (listener_json.http != null and listener_json.l4 != null) {
        return error.ListenerHttpOrL4;
    }
    if (listener_json.http != null) return .http;
    if (listener_json.l4 != null) return .l4;
    return error.ListenerHttpOrL4;
}

// The strict parser binds JSON to these `*Json` DTOs. Each carries the
// schema metadata reflection cannot infer — prose (`schema_doc`, per-field
// `.desc`), closed vocabularies (`.enum_type`, `.int_values`, `.items`),
// and numeric bounds (`.minimum`/`.maximum`/`.min_items`/…) — co-located
// with the fields so the two never drift. `assert_meta_matches` (below)
// cross-checks metadata against the real fields at comptime, and
// `schema.zig` walks the same DTOs to emit the JSON Schema. Public
// so the emitter and its tests can reflect over the real wire shape.
pub const ConfigJson = struct {
    /// Editor hint only: the URL of the JSON Schema this file claims to
    /// follow (`$id` in the emitted document). Declared so an editor may add
    /// it for completion and validation without the loader rejecting the
    /// file; parsed, never read. Strictness is unharmed — a near miss like
    /// `$schemas` is still an unknown field.
    @"$schema": ?[]const u8 = null,
    listeners: []const ListenerJson,
    clusters: ClustersJson,
    /// Optional as a whole, like `limits` below and for the same reason
    /// (§5): an omitted block takes the defaults, so a working config is
    /// a listener and a cluster, and tuning is what an operator opts
    /// into.
    timeouts: TimeoutsJson = .{},
    /// Optional pool sizes and the CQ-fill headroom knob (§5, §8); absent
    /// fields take the lean defaults, not the compiled ceilings.
    limits: LimitsJson = .{},
    /// Optional admin/metrics listener (§8); absent
    /// leaves the plane off.
    admin: ?AdminJson = null,
    /// Optional access log (§8); absent leaves it off.
    access_log: ?AccessLogJson = null,
    /// Optional #159 named bodies; absent reserves nothing.
    bodies: ?BodiesJson = null,
    /// Optional #159 error pages over the closed static-status set;
    /// absent means every static stays `Content-Length: 0` — including
    /// the sheds, whose bodies this block is the deliberate opt-in for.
    error_pages: ?ErrorPagesJson = null,

    pub const schema_doc =
        "Startup configuration for zoxy, the L4/L7 proxy. This schema checks " ++
        "structure, allowed values and numeric ranges. Rules JSON Schema " ++
        "cannot express are enforced by the loader when zoxy starts: route " ++
        "hosts and path prefixes must already be canonical (a lowercase host " ++
        "without a port or a `*`, which is reserved for wildcards; a path " ++
        "without dot segments, a query, or " ++
        "percent-escapes that normalization would change), IP:port addresses " ++
        "must be valid literals, endpoint ports must be non-zero, and filters " ++
        "may not edit headers zoxy manages itself, such as Host, Connection, " ++
        "Content-Length and X-Forwarded-For.";
    pub const schema_fields = .{
        .@"$schema" = .{
            .desc = "URL of the JSON Schema this config follows; an editor hint, ignored by the loader.",
        },
        .listeners = .{
            .desc = "Sockets the proxy accepts connections on.",
            .min_items = 1,
        },
        .clusters = .{ .desc = "Named upstream clusters, keyed by cluster name." },
        .timeouts = .{ .desc = "Connection lifecycle deadlines (milliseconds)." },
        .limits = .{ .desc = "Optional pool sizes and completion-queue headroom; omitted fields take lean defaults." },
        .admin = .{ .desc = "Optional admin/metrics listener; absent leaves it off." },
        .access_log = .{ .desc = "Optional per-request/per-connection JSON access log; absent leaves it off." },
        .bodies = .{
            .desc = "Named response bodies (file or inline, read once at " ++
                "startup), referenced by name from error_pages.",
        },
        .error_pages = .{
            .desc = "Bodies for the statuses zoxy sends itself, keyed by " ++
                "status code, each naming a body. Only listed statuses get " ++
                "a body. Without this block, every such response is empty, " ++
                "including load-shedding responses.",
        },
    };
};

pub const AccessLogJson = struct {
    sink: []const u8,
    path: ?[]const u8 = null,
    /// Headers to log (#140), absent meaning none — so a deployment
    /// that does not ask pays nothing, the same shape as `access_log`
    /// itself being absent.
    request_headers: ?[]const []const u8 = null,
    response_headers: ?[]const []const u8 = null,

    pub const schema_doc =
        "Optional access log: one JSON object per line for every HTTP " ++
        "exchange and every L4 connection. Absent leaves it off and reserves " ++
        "nothing. When the sink cannot keep up, lines are dropped and " ++
        "counted rather than blocking the event loop.";
    pub const schema_fields = .{
        .sink = .{
            .desc = "Where lines are written: `stdout` (the process's standard " ++
                "output) or `file` (appends to `path`).",
            .enum_type = Config.AccessLogSinkKind,
        },
        .path = .{
            .desc = "File the `file` sink appends to. It is created if missing, " ++
                "opened append-only at startup (one extra fd) and never " ++
                "truncated, so copy-truncate rotation is safe. Required with " ++
                "`sink: \"file\"`, rejected with `stdout`.",
            // An empty path is the same refusal as a missing one and
            // wants the same answer (#305): the loader raises
            // `AccessLogPathMissing` for both, so the schema has to
            // catch both or the row cannot go.
            .min_length = 1,
        },
        .request_headers = .{
            .desc = "Request headers to record under `request_headers` on each " ++
                "http line, such as X-Request-ID or traceparent to join this " ++
                "log to the origin's. Names match case-insensitively and are " ++
                "logged in lowercase; a header the request lacks is left out " ++
                "of its line.",
            .max_items = constants.access_log_headers_max,
            .item_min_length = 1,
            .item_max_length = constants.access_log_header_name_bytes_max,
        },
        .response_headers = .{
            .desc = "Response headers to record under `response_headers`, on the " ++
                "same terms (for example the origin's X-Cache). Ignored for l4 " ++
                "lines, which have no response.",
            .max_items = constants.access_log_headers_max,
            .item_min_length = 1,
            .item_max_length = constants.access_log_header_name_bytes_max,
        },
    };

    /// A file sink needs somewhere to write and a stdout sink has
    /// nowhere to be given (#305). `sink` has no default, so both arms
    /// name it.
    pub const schema_variants = [_]SchemaVariants{.{
        .on = "sink",
        .branches = &.{
            .{ .value = "stdout", .forbid = &.{"path"} },
            .{ .value = "file", .require = &.{"path"} },
        },
    }};
};

pub const AdminJson = struct {
    bind: []const u8,

    pub const schema_doc =
        "Optional admin/metrics listener. When present, it serves the process " ++
        "counters in Prometheus text format on `bind`; absent leaves it off.";
    pub const schema_fields = .{
        .bind = .{ .desc = "IP:port literal to bind the admin/metrics listener (hostnames are rejected)." },
    };
};

pub const LimitsJson = struct {
    conn_slots: ?u32 = null,
    relay_buffers: ?u32 = null,
    upstream_slots: ?u32 = null,
    head_buffers: ?u32 = null,
    upstream_head_buffers: ?u32 = null,
    head_buffer_bytes: ?u32 = null,
    relay_buffer_bytes: ?u32 = null,
    tls_engines: ?u32 = null,
    tunnels: ?u32 = null,
    /// The #275 HTTP/2 pools: sessions (defaulted where HTTP/2 is spoken)
    /// and the shared streams they multiplex (required there).
    ///
    /// The keys are named for the side and the protocol they size, and
    /// differ from the resolved fields for a reason (#400): `h2_streams`
    /// resolves into `Config.Limits.stream_slots`, but the banner's
    /// "stream slots" is that number *plus* one per conn slot, so a key
    /// spelled `stream_slots` printed back as a different figure under
    /// its own name. The origin side wears `upstream_`, like
    /// `upstream_slots` and `upstream_tls_sessions` beside it.
    h2_connections: ?u32 = null,
    h2_streams: ?u32 = null,
    /// The #449 QUIC connection pool: defaulted where a listener has a
    /// `quic` binding, and only legal there. Its streams are `h2_streams`',
    /// the pool HTTP/2 and HTTP/3 share, so the key keeps HTTP/2's name.
    quic_connections: ?u32 = null,
    /// The §7 HTTP/2 origin pools: connections to `h2c` and `h2` clusters
    /// and the streams on them that can hold an answer. Both defaulted,
    /// and only legal where some cluster speaks HTTP/2.
    upstream_h2_connections: ?u32 = null,
    upstream_h2_streams: ?u32 = null,
    /// TLS sessions to HTTP/1.1 origins (#296): defaulted, and only legal
    /// where some `http1` cluster has `tls`.
    upstream_tls_sessions: ?u32 = null,
    cq_fill_eighths: ?u32 = null,
    access_log_buffer_bytes: ?u32 = null,

    pub const schema_doc =
        "Optional pool sizes and completion-queue headroom; omitted fields " ++
        "take lean defaults. A pool can be set at or below its ceiling, " ++
        "never above. cq_fill_eighths trades ceiling for burst headroom and " ++
        "never changes a pool size.";
    pub const schema_fields = .{
        .conn_slots = .{
            .desc = "Concurrent connection slots.",
            .minimum = 1,
            .maximum = constants.conn_slots_max,
        },
        .relay_buffers = .{
            .desc = "Relay buffer pairs; bounds concurrent L4 and L7 body relays.",
            .minimum = 1,
            .maximum = constants.relay_buffers_max,
        },
        .upstream_slots = .{
            .desc = "Shared upstream connection slots.",
            .minimum = 1,
            .maximum = constants.upstream_slots_max,
        },
        .head_buffers = .{
            .desc = "HTTP head buffers; bounds request heads in flight (idle " ++
                "keep-alive connections hold none). Defaults to conn_slots; " ++
                "must be 1..conn_slots with an http listener, 0 without one.",
            .minimum = 0,
            .maximum = constants.conn_slots_max,
        },
        .upstream_head_buffers = .{
            .desc = "Upstream head buffers; bounds exchanges in their head " ++
                "phase (idle pooled origin connections hold none). Defaults " ++
                "to upstream_slots; must be 1..upstream_slots with an http " ++
                "listener, 0 without one.",
            .minimum = 0,
            .maximum = constants.upstream_slots_max,
        },
        .head_buffer_bytes = .{
            .desc = "Bytes per head buffer in both head pools, and so the " ++
                "largest HTTP head accepted (oversize requests get 414 or " ++
                "431). Raise it for traffic with large cookies or JWTs.",
            .minimum = constants.head_buffer_bytes_min,
            .maximum = constants.head_buffer_bytes_max,
        },
        .relay_buffer_bytes = .{
            .desc = "Bytes per relay direction; a pair costs twice this. It " ++
                "sets how many round trips a body takes and the size of the " ++
                "TLS records a terminating listener sends. Lower it when " ++
                "concurrency matters more than bulk throughput. A listener " ++
                "that terminates TLS caps it at one record's plaintext " ++
                "(16 KiB); values above that are for plaintext deployments.",
            .minimum = constants.relay_buffer_bytes_min,
            .maximum = constants.relay_buffer_bytes_max,
        },
        .tls_engines = .{
            .desc = "Concurrent TLS sessions, handshaking or terminated. Each " ++
                "is the largest per-connection object zoxy holds (about " ++
                "92 KiB plus a plaintext buffer), so a TLS deployment's " ++
                "memory follows this number. Zero exactly when no listener " ++
                "terminates TLS.",
            .minimum = 1,
            .maximum = constants.tls_engines_max,
        },
        .tunnels = .{
            .desc = "Concurrent tunnelled upgrades. Each holds its own relay " ++
                "buffer and upstream socket for its whole life, so tunnels never " ++
                "draw on the pools ordinary traffic shares. Required when some " ++
                "listener allows an upgrade and rejected otherwise; there is no " ++
                "default.",
            .minimum = 1,
            .maximum = constants.tunnels_max,
        },
        .h2_connections = .{
            .desc = "Concurrent HTTP/2 connections, each holding its own session " ++
                "(about 100 KiB). Allowed only when some listener speaks HTTP/2 " ++
                "(h2 in tls.alpn, or http.h2c); defaults to 1024, at most " ++
                "conn_slots. With none free, an h2 offer falls back to HTTP/1.1, " ++
                "an h2c preface is turned away, and an h2-only listener refuses " ++
                "the connection at accept.",
            .minimum = 1,
            .maximum = constants.conn_slots_max,
        },
        .h2_streams = .{
            .desc = "Concurrent HTTP/2 and HTTP/3 streams across all " ++
                "connections, each with its own head buffer. Required when " ++
                "some listener speaks HTTP/2 or has an http.quic binding, and " ++
                "rejected otherwise. An HTTP/2 stream beyond the pool is " ++
                "refused with REFUSED_STREAM, which clients retry. One HTTP/2 " ++
                "connection advertises at most 100.",
            .minimum = 1,
            .maximum = constants.stream_slots_max,
        },
        .quic_connections = .{
            .desc = "Concurrent HTTP/3 connections, each holding its own " ++
                "connection state and a TLS engine for its whole life. Allowed " ++
                "only when some listener has an http.quic binding; defaults to " ++
                "64, and may exceed neither conn_slots nor tls_engines.",
            .minimum = 1,
            .maximum = constants.quic_connections_max,
        },
        .upstream_h2_connections = .{
            .desc = "Connections to the endpoints of HTTP/2 clusters (h2c or h2), " ++
                "each carrying many exchanges as streams. Only allowed when some " ++
                "cluster speaks HTTP/2; defaults to two per HTTP/2 endpoint. A " ++
                "request with no connection to carry it is answered 503.",
            .minimum = 1,
            .maximum = constants.h2_origin_connections_max,
        },
        .upstream_h2_streams = .{
            .desc = "Exchanges on HTTP/2 origin connections at once, each holding " ++
                "a buffer for its answer: a head, a relay buffer's window and a " ++
                "trailer section. Only allowed when some cluster speaks HTTP/2; " ++
                "defaults to upstream_slots and may not exceed it.",
            .minimum = 1,
            .maximum = constants.upstream_slots_max,
        },
        .upstream_tls_sessions = .{
            .desc = "TLS sessions to HTTPS origins (http1 clusters with tls), one " ++
                "per connection, kept while it is parked for reuse. Only allowed " ++
                "when such a cluster exists; defaults to 16 per such endpoint, " ++
                "within upstream_slots. A request with no session free is " ++
                "answered 503.",
            .minimum = 1,
            .maximum = constants.upstream_tls_sessions_max,
        },
        .cq_fill_eighths = .{
            .desc = "How many eighths of the io_uring completion queue the " ++
                "worst-case in-flight operations may fill. Lower values reserve " ++
                "more burst headroom but lower the highest feasible conn_slots.",
            .minimum = constants.cq_fill_eighths_min,
            .maximum = constants.cq_fill_eighths_max,
        },
        .access_log_buffer_bytes = .{
            .desc = "Bytes per access-log staging buffer (there are two). A " ++
                "larger buffer tolerates a slower sink before lines are " ++
                "dropped. Only valid with an `access_log` block.",
            .minimum = constants.access_log_buffer_bytes_min,
            .maximum = constants.access_log_buffer_bytes_max,
        },
    };
};

/// One accepting socket, as a tagged shape: what is true of every
/// listener sits at this level, and what only one protocol can mean sits
/// inside the body that names it (#305).
///
/// This used to be eleven flat fields of which seven were conditionally
/// valid on a `protocol` string — a discriminated union modeled as a
/// struct, with the discrimination left to seven loader errors that no
/// emitted schema could carry. The tag is now the body's own key, so
/// `{"l4": {"max_body_bytes": 500}}` is refused by the schema's shape
/// rather than by a rule written twice in prose, and the seven errors are
/// gone rather than reworded.
///
/// `bind` and `tls` stay out here because they are genuinely shared: an
/// address is an address, and `resolveTls` says of the other why it is
/// not a body field — "both speak over a terminated session (§4, §7)".
pub const ListenerJson = struct {
    bind: []const u8,
    /// Permission bits for a `unix:` bind's socket file, as an octal
    /// string (#303); absent leaves whatever the process umask gives.
    /// Shared like `tls` because it is a property of the socket, not of
    /// what is spoken over it — and rejected on an IP bind, which
    /// creates no file to chmod.
    mode: ?[]const u8 = null,
    /// Optional TLS termination (#125); absent is a plaintext socket.
    /// Shared, unlike everything in the bodies below.
    tls: ?TlsJson = null,
    /// Exactly one of these names what the listener speaks and carries
    /// that protocol's own fields.
    http: ?HttpListenerJson = null,
    l4: ?L4ListenerJson = null,

    pub const schema_doc =
        "One listening socket. Exactly one of `http` or `l4` sets what it " ++
        "speaks and holds that protocol's settings; `bind` and `tls` apply " ++
        "to both.";
    pub const schema_one_of = [_][]const u8{ "http", "l4" };
    pub const schema_fields = .{
        .bind = .{
            .desc = "Address to bind: an `IP:port` literal (hostnames are " ++
                "rejected), or `unix:` followed by the absolute path of a " ++
                "socket file to create.",
        },
        .mode = .{
            .desc = "Permission bits for a `unix:` socket file, as an octal " ++
                "string (\"0660\"). Absent leaves the process umask's default. " ++
                "Rejected on an IP bind, which creates no file.",
            .min_length = 1,
        },
        .tls = .{
            .desc = "Terminate TLS on this listener with the given certificate " ++
                "and key; absent is a plaintext socket. Inbound only: TLS to " ++
                "the origins is the cluster's own tls block.",
        },
        .http = .{
            .desc = "Speak HTTP as a reverse proxy, with routing, filters and " ++
                "body limits: HTTP/1.1, plus HTTP/2 over TLS (h2 in tls.alpn) " ++
                "or in the clear (http.h2c), and HTTP/3 over QUIC (http.quic).",
        },
        .l4 = .{
            .desc = "Speak L4: relay bytes to a cluster without parsing them as " ++
                "HTTP. One cluster, or one chosen by the TLS server name the " ++
                "client asked for (routes).",
        },
    };
};

/// What an `http` listener carries, and nothing an `l4` one could.
pub const HttpListenerJson = struct {
    /// Exactly one of `cluster` (sugar for a single catch-all route) or
    /// `routes` (an explicit §7 path table) must be present.
    cluster: ?[]const u8 = null,
    routes: ?[]const RouteJson = null,
    /// Optional §7 request filter rules; absent means none.
    request_filters: ?[]const FilterJson = null,
    /// Optional #175 response filter rules; absent means none.
    response_filters: ?[]const ResponseFilterJson = null,
    /// Optional §7 client-address forwarding; absent leaves the header
    /// untouched.
    forwarded: ?ForwardedJson = null,
    /// Optional #180 upgrade allowlist; absent allows none, so an
    /// `Upgrade` stays the 501 it has always been.
    upgrades: ?UpgradesJson = null,
    /// The #236 request-body cap, `0` accepting any size (#305). Not
    /// optional: `null` used to mean the default and `0` no cap, which
    /// is three states for a two-state idea, and every other cap in this
    /// config — `drain_deadline_ms`, `max_lifetime_ms`, `request_ms` —
    /// already spells "no cap" as `0` with no third state to explain.
    max_body_bytes: u64 = defaults.max_body_bytes,
    /// The #237 keep-alive request cap, `0` serving any number. Beside
    /// `max_body_bytes` on §5's placement rule: it reserves nothing, so
    /// it is policy on the thing it governs, not a `limits` entry (#399).
    keepalive_requests: u32 = defaults.keepalive_requests,
    /// Whether this listener names *why* it refused, in an RFC 9209
    /// `Proxy-Status` field (#300). Absent is off.
    proxy_status: bool = false,
    /// h2c by prior knowledge (#275); plaintext listeners only.
    h2c: bool = false,
    /// Optional #449 QUIC binding; absent serves no HTTP/3. TLS listeners
    /// only, since QUIC is TLS 1.3 and presents this listener's
    /// certificates.
    quic: ?QuicJson = null,

    pub const schema_doc =
        "An HTTP listener's settings. Exactly one of `cluster` or " ++
        "`routes` selects the upstream.";
    pub const schema_one_of = [_][]const u8{ "cluster", "routes" };
    pub const schema_fields = .{
        .cluster = .{ .desc = "Shorthand for a single catch-all route to this cluster; mutually exclusive with routes." },
        .routes = .{
            .desc = "Explicit longest-prefix route table.",
            .min_items = 1,
        },
        .request_filters = .{
            .desc = "Request filter rules, evaluated top-down.",
        },
        .response_filters = .{
            .desc = "Response filter rules that edit headers on the origin's " ++
                "response, evaluated top-down.",
        },
        .forwarded = .{
            .desc = "Tell the origin the client's address via X-Forwarded-For; " ++
                "absent leaves the header untouched.",
        },
        .max_body_bytes = .{
            .desc = "Cap on one request body in bytes; 0 accepts any size, and " ++
                "absent is 1 MiB. A body over the cap is refused with 413 and " ++
                "the connection closes; when its length was declared, this " ++
                "happens before the origin is dialed.",
            .minimum = 0,
            .maximum = constants.request_body_bytes_max,
        },
        .keepalive_requests = .{
            .desc = "Requests one client connection may serve before the next " ++
                "response announces Connection: close (on HTTP/2, streams " ++
                "before GOAWAY); absent is 1000, and 0 is unlimited.",
            .minimum = 0,
            .maximum = std.math.maxInt(u32),
        },
        .proxy_status = .{
            .desc = "Say why zoxy refused a request in an RFC 9209 Proxy-Status " ++
                "field, so a client can tell a load-shedding 503 from the " ++
                "origin's own. Off by default because it reveals internal " ++
                "limits to clients: useful on an internal listener, less so " ++
                "at the edge.",
        },
        .upgrades = .{
            .desc = "Protocol upgrades this listener carries as tunnels. Absent " ++
                "allows none, and an Upgrade request gets 501. Requires " ++
                "limits.tunnels.",
        },
        .h2c = .{
            .desc = "Also speak HTTP/2 to a client that opens with the HTTP/2 " ++
                "preface (h2c with prior knowledge, RFC 9113 §3.3); HTTP/1.1 " ++
                "clients are still served. Plaintext only: a TLS listener offers " ++
                "h2 in tls.alpn instead. Requires limits.h2_streams.",
        },
        .quic = .{
            .desc = "Also serve HTTP/3 over QUIC on this UDP address (RFC 9114), " ++
                "with the listener's routes, policies and certificates. Requires " ++
                "tls, and limits.h2_streams, the stream pool HTTP/3 shares with " ++
                "HTTP/2. The listener's TCP responses advertise it in Alt-Svc.",
        },
    };
};

/// An http listener's #449 QUIC binding: where HTTP/3 is served, and how
/// long the TCP side's advertisement of it lasts. Its own object rather
/// than a bare bind, because the advertisement is a property of the
/// binding and not of the listener.
pub const QuicJson = struct {
    bind: []const u8,
    /// RFC 7838's `ma`, in seconds; the stock value where absent.
    alt_svc_max_age_s: u32 = constants.alt_svc_max_age_s_default,

    pub const schema_doc =
        "A UDP binding that serves HTTP/3 over QUIC beside the listener's " ++
        "TCP socket, sharing everything the listener states.";
    pub const schema_fields = .{
        .bind = .{
            .desc = "UDP address to serve HTTP/3 on: an `IP:port` literal " ++
                "(hostnames and `unix:` paths are rejected). It may be the " ++
                "listener's own bind, since UDP ports are not TCP ones; two " ++
                "listeners' quic bindings may not share one.",
        },
        .alt_svc_max_age_s = .{
            .desc = "Seconds a client may remember the Alt-Svc advertisement " ++
                "of this binding, which every answer the listener relays from " ++
                "an origin carries (RFC 7838 ma); it takes one of the " ++
                "listener's response header edits. Absent is a day; 0 " ++
                "advertises nothing.",
            .minimum = 0,
            .maximum = constants.alt_svc_max_age_s_max,
        },
    };
};

/// The #180 upgrade allowlist, one flag per protocol this proxy can
/// recognise (#305 Part 2).
///
/// An object rather than the list of tokens this replaced, and the
/// argument is the vocabulary: §7 requires it closed — a token zoxy
/// cannot reason about must be refused by name, never ignored — and a
/// list of strings can only be closed by the loader, in rules a reader
/// of the schema never sees. As fields, the schema states the whole
/// vocabulary, `additionalProperties: false` rejects an unknown token,
/// and duplicates stop being expressible at all: the list form accepted
/// `["websocket", "websocket"]` because nothing checked, and there is no
/// spelling of that here.
pub const UpgradesJson = struct {
    websocket: bool = false,

    pub const schema_doc =
        "Which protocol upgrades this listener carries as tunnels. Absent, or " ++
        "every flag false, allows none.";
    pub const schema_fields = .{
        .websocket = .{
            .desc = "Allow WebSocket upgrades (RFC 6455): once the origin " ++
                "answers 101, the connection is carried as a tunnel. Requires " ++
                "limits.tunnels.",
        },
    };

    comptime {
        // The JSON shape and the resolved one are one vocabulary. A
        // protocol added to either and forgotten on the other would let
        // the config name an upgrade the serving path cannot gate, or
        // hide one it can.
        const resolved = @typeInfo(Config.Listener.Upgrades).@"struct".field_names;
        const json = @typeInfo(UpgradesJson).@"struct".field_names;
        if (resolved.len != json.len) {
            @compileError("UpgradesJson and Config.Listener.Upgrades disagree on the set");
        }
        for (resolved) |name| {
            if (!@hasField(UpgradesJson, name)) {
                @compileError("UpgradesJson is missing " ++ name);
            }
        }
    }
};

/// What an `l4` listener carries. It forks on the upstream the way an
/// `http` listener does — sugar for one destination, or a table — but on
/// the only dimension a byte relay has: there is no path to match, so the
/// table is keyed by the TLS name the client asked for (#298).
pub const L4ListenerJson = struct {
    /// Exactly one of `cluster` (sugar for a single any-name route) or
    /// `routes` (an explicit §6 SNI table, #298) selects the upstream —
    /// the same fork `HttpListenerJson` has, for the same reason.
    cluster: ?[]const u8 = null,
    routes: ?[]const L4RouteJson = null,
    /// Optional PROXY protocol expectation (#142); absent treats first
    /// bytes as payload.
    proxy_protocol: ?ProxyProtocolJson = null,

    pub const schema_doc =
        "An L4 listener's settings: which cluster it relays to, and what it " ++
        "expects before the payload. Exactly one of `cluster` or `routes` " ++
        "selects the upstream.";
    pub const schema_one_of = [_][]const u8{ "cluster", "routes" };
    pub const schema_fields = .{
        .cluster = .{
            .desc = "Shorthand for a single route that matches any server name; " ++
                "mutually exclusive with routes.",
        },
        .routes = .{
            .desc = "Route by the TLS server name (SNI) the client asked for, " ++
                "without terminating TLS: the ClientHello is read and relayed " ++
                "unchanged. Requires the full-size relay buffer, and cannot be " ++
                "combined with this listener's own tls block.",
            .min_items = 1,
        },
        .proxy_protocol = .{
            .desc = "Expect a PROXY protocol header (v1 or v2) before each " ++
                "connection's payload; absent treats the first bytes as payload.",
        },
    };
};

/// One §6 SNI route (#298): the name a client must have asked for, and
/// the cluster that answers it.
pub const L4RouteJson = struct {
    /// Absent is the any-name route — it answers every connection,
    /// including one whose hello named nothing. §7's any-host route,
    /// wearing the only dimension an L4 relay has.
    sni: ?[]const u8 = null,
    cluster: []const u8,

    pub const schema_doc =
        "One SNI route. Without `sni` it is the catch-all: it answers any " ++
        "connection, including one whose ClientHello carried no name. A " ++
        "connection matching no route is closed.";
    pub const schema_fields = .{
        .sni = .{
            .desc = "The TLS server name to match exactly, by the same rule " ++
                "http routes use to match a host. No wildcards.",
            .min_length = 1,
        },
        .cluster = .{ .desc = "The cluster that connections naming this server are relayed to." },
    };
};

pub const TlsJson = struct {
    cert: []const u8,
    key: []const u8,
    alpn: ?[]const []const u8 = null,
    /// #304: verify clients against these CAs; absent asks none.
    client_ca: ?ClientCaJson = null,
    /// #297: more certificates, chosen by the client's server name.
    certificates: ?[]const CertificateJson = null,

    pub const schema_doc =
        "TLS termination for this listener: where its certificate chain and " ++
        "private key live. Both are read once at startup, so a missing or " ++
        "unusable file stops startup with an error naming it, rather than " ++
        "failing a client's handshake later. The key may be ECDSA P-256 or " ++
        "P-384, or RSA of 2048 to 4096 bits; an RSA signature costs the event " ++
        "loop ~0.5 ms at 2048 bits and ~2.4 ms at 4096, where P-256 costs ~15 µs, " ++
        "so a listener holding both signs ECDSA for every client that can verify it.";
    pub const schema_fields = .{
        .cert = .{
            .desc = "Path to the PEM certificate chain, leaf first.",
            .min_length = 1,
        },
        .key = .{
            .desc = "Path to the leaf's PEM private key (ECDSA P-256 or P-384, or RSA 2048 to 4096 bits).",
            .min_length = 1,
        },
        .alpn = .{
            .desc = "Application protocols to offer in ALPN (RFC 7301), most " ++
                "preferred first. Absent offers `http/1.1` on an `http` listener; " ++
                "rejected on an `l4` listener, which names no protocol. A client " ++
                "whose ALPN offer names none of these is refused with " ++
                "`no_application_protocol`.",
            .min_items = 1,
            .max_items = alpn.protocols_max,
            .items = SchemaItems.alpn_protocol,
        },
        .client_ca = .{
            .desc = "Ask every client for a certificate and verify it against " ++
                "these CAs (mutual TLS). Absent asks none.",
        },
        .certificates = .{
            .desc = "More certificates for this listener, each chosen when a " ++
                "client's server name (SNI) matches one of its DNS names: an exact " ++
                "name first, then a one-label wildcard. `cert` and `key` above stay " ++
                "the default, shown to a client that names nothing or nothing " ++
                "these cover.",
            .min_items = 1,
            .max_items = constants.tls_certificates_max - 1,
        },
    };
};

/// One more certificate a listener can present (#297).
pub const CertificateJson = struct {
    cert: []const u8,
    key: []const u8,

    pub const schema_doc =
        "A certificate chain and its key, chosen by the client's server name " ++
        "against the DNS names in the certificate's subjectAltName.";
    pub const schema_fields = .{
        .cert = .{
            .desc = "Path to the PEM certificate chain, leaf first.",
            .min_length = 1,
        },
        .key = .{
            .desc = "Path to the leaf's PEM private key (ECDSA P-256 or P-384, or RSA 2048 to 4096 bits).",
            .min_length = 1,
        },
    };
};

/// A listener's #304 client-certificate policy: one CA bundle, and
/// whether a client must present a certificate at all.
pub const ClientCaJson = struct {
    path: []const u8,
    verify: []const u8 = @tagName(defaults.client_verify),

    pub const schema_doc =
        "Mutual TLS: the CA bundle a client's certificate must chain to. " ++
        "Revocation is not checked; issue short-lived client certificates, " ++
        "from a CA that issues nothing but client certificates.";
    pub const schema_fields = .{
        .path = .{
            .desc = "Path to a PEM bundle of the CA certificates to trust, read once at load.",
            .min_length = 1,
        },
        .verify = .{
            .desc = "required (the default) refuses a client that presents no " ++
                "certificate; optional lets it in unauthenticated, for migrating " ++
                "a fleet onto mutual TLS. A certificate that is presented must " ++
                "verify either way.",
            .enum_type = Config.Listener.ClientVerify,
        },
    };
};

pub const ForwardedJson = struct {
    mode: []const u8,

    pub const schema_doc =
        "How this listener sets `X-Forwarded-For`. There is no default: an " ++
        "inbound chain is client-controlled at the edge but trustworthy " ++
        "behind a proxy you own, and zoxy cannot tell which position it is " ++
        "in, so choosing the wrong mode is a security bug.";
    pub const schema_fields = .{
        .mode = .{
            .desc = "replace: set the header to the observed peer, discarding any inbound " ++
                "chain (use at the edge). append: add the observed peer to the " ++
                "inbound chain (use only when every hop in front is trusted).",
            .enum_type = Config.Listener.Forwarded,
        },
    };
};

pub const ProxyProtocolJson = struct {
    mode: []const u8,

    pub const schema_doc =
        "Whether this listener expects the proxy in front of it to announce " ++
        "each client with a PROXY protocol header. There is no optional " ++
        "mode: accepting a header only when one is present would let any " ++
        "client choose the address that routing and logging trust.";
    pub const schema_fields = .{
        .mode = .{
            .desc = "require: every connection must open with a valid v1 or v2 " ++
                "header; anything else is closed. Only meaningful when the " ++
                "listener can be reached solely through the proxy in front of it.",
            .enum_type = Config.Listener.ProxyProtocol,
        },
    };
};

pub const FilterJson = struct {
    match: MatchJson = .{},
    actions: []const ActionJson,

    pub const schema_doc = "One filter rule: a match predicate and the actions applied when it matches.";
    pub const schema_fields = .{
        .match = .{ .desc = "Match predicate; absent fields match anything." },
        .actions = .{
            .desc = "Actions applied in order when the rule matches.",
            .min_items = 1,
        },
    };
};

pub const MatchJson = struct {
    /// Registered method tokens (uppercase); absent = any method.
    method: ?[]const []const u8 = null,
    host: ?[]const u8 = null,
    path_prefix: ?[]const u8 = null,
    headers: ?[]const HeaderMatchJson = null,
    /// Optional #177 client-address predicate: CIDR literals, any-of.
    client: ?[]const []const u8 = null,

    pub const schema_doc = "Request-match predicate; every absent field matches anything.";
    pub const schema_fields = .{
        .method = .{
            .desc = "Registered request-method tokens; absent matches any method.",
            .min_items = 1,
            .items = SchemaItems.http_method,
        },
        .host = .{ .desc = "Canonical host to match; absent matches any host." },
        .path_prefix = .{
            .desc = "Canonical origin-form path prefix; must start with a slash. " ++
                "Matches whole path segments: /api matches /api and /api/v1, " ++
                "never /apihost.",
        },
        .headers = .{
            .desc = "Header predicates; all must match.",
        },
        .client = .{
            .desc = "CIDR prefixes such as \"10.0.0.0/8\"; matches when the client " ++
                "address falls inside any of them. Up to /32 for IPv4 and /64 " ++
                "for IPv6, since an IPv6 client is identified by its /64, as " ++
                "with hash source_ip. Matched against the observed peer (the " ++
                "PROXY-announced client on a proxy_protocol listener), never an " ++
                "X-Forwarded-For chain.",
            .min_items = 1,
        },
    };
};

pub const HeaderMatchJson = struct {
    name: []const u8,
    /// Exactly one of these selects the predicate kind.
    present: ?bool = null,
    equals: ?[]const u8 = null,
    contains: ?[]const u8 = null,

    pub const schema_doc =
        "One header predicate. Exactly one of `present`, `equals` or " ++
        "`contains` selects the kind.";
    pub const schema_one_of = [_][]const u8{ "present", "equals", "contains" };
    pub const schema_fields = .{
        .name = .{ .desc = "Header field name (matched case-insensitively)." },
        .present = .{
            .desc = "Matches when the header is present (present: false is rejected).",
            .const_true = true,
        },
        .equals = .{ .desc = "Matches when the header value equals this string." },
        .contains = .{
            .desc = "Matches when the header value contains this substring.",
            .min_length = 1,
        },
    };
};

/// One action object carries exactly one field (the action's kind), the
/// same "struct of optionals, validate exactly-one" shape the listener's
/// cluster/routes fork uses — no JSON union parsing.
/// What a #175 response rule may do: edit headers, and nothing else.
///
/// A type of its own rather than `ActionJson` with five of its members
/// refused at load (#305). The five are request-side decisions — `reject`,
/// `redirect` and `respond` decide what to send *instead* of asking the
/// origin, `allow` decides to ask it after all (#331), and
/// `rewrite_prefix` changes what is asked — while a response
/// rule runs when the origin has already answered. Sharing the request's
/// union made those states representable and then rejected them one at
/// a time; here they cannot be written down, which is the same verdict
/// reached by the type rather than by a rule, and the schema states it
/// too.
pub const ResponseActionJson = struct {
    header_set: ?HeaderEditJson = null,
    header_add: ?HeaderEditJson = null,
    header_remove: ?[]const u8 = null,

    pub const schema_doc =
        "One response-filter action: set exactly one field, which names the " ++
        "edit. Response rules only edit headers. The request-side actions " ++
        "(reject, redirect, respond, allow, rewrite_prefix) are not " ++
        "available, because the origin has already answered.";
    pub const schema_one_of = [_][]const u8{
        "header_set",
        "header_add",
        "header_remove",
    };
    pub const schema_fields = .{
        .header_set = .{ .desc = "Set (replace) a response header." },
        .header_add = .{ .desc = "Append a response header." },
        .header_remove = .{ .desc = "Remove a response header by name." },
    };

    comptime {
        // Every member must exist on the request action *and carry the
        // same type*: the two tables share `resolveHeaderEdit`, so a
        // member here the request lacks would be an edit the renderer
        // has never seen, and one whose type diverged would be the same
        // key meaning two things.
        const info = @typeInfo(ResponseActionJson).@"struct";
        for (info.field_names, info.field_types) |name, FieldType| {
            if (!@hasField(ActionJson, name)) {
                @compileError("ResponseActionJson." ++ name ++ " is not an ActionJson field");
            }
            if (@FieldType(ActionJson, name) != FieldType) {
                @compileError("ResponseActionJson." ++ name ++
                    " has a different type than ActionJson's");
            }
        }
    }
};

pub const ActionJson = struct {
    reject: ?u16 = null,
    redirect: ?RedirectJson = null,
    respond: ?RespondJson = null,
    /// #331's terminal, spelled `{"allow": true}`: an action with no
    /// payload still needs a value in this "struct of optionals, exactly
    /// one set" shape, and `true` is the only one it may carry —
    /// `allow: false` names no action, exactly as `present: false` names
    /// no predicate.
    allow: ?bool = null,
    header_set: ?HeaderEditJson = null,
    header_add: ?HeaderEditJson = null,
    header_remove: ?[]const u8 = null,
    rewrite_prefix: ?RewriteJson = null,

    pub const schema_doc =
        "One filter action: set exactly one field, which names the action.";
    pub const schema_one_of = [_][]const u8{
        "reject",
        "redirect",
        "respond",
        "allow",
        "header_set",
        "header_add",
        "header_remove",
        "rewrite_prefix",
    };
    pub const schema_fields = .{
        .reject = .{
            .desc = "Reject the request with this status code.",
            .int_values = &filter.reject_statuses,
        },
        .redirect = .{
            .desc = "Answer the request with a redirect instead of forwarding it.",
        },
        .respond = .{
            .desc = "Answer the request with a configured body instead of " ++
                "forwarding it.",
        },
        .allow = .{
            .desc = "Forward the request and stop evaluating rules; it neither " ++
                "answers nor edits. Use it to write an allowlist: an allow rule " ++
                "matching the admitted traffic, then a reject for everything " ++
                "else (allow: false is rejected).",
            .const_true = true,
        },
        .header_set = .{ .desc = "Set (replace) a request header." },
        .header_add = .{ .desc = "Append a request header." },
        .header_remove = .{ .desc = "Remove a request header by name." },
        .rewrite_prefix = .{ .desc = "Rewrite the request path prefix before proxying." },
    };
};

/// A `respond` action (#159): the proxy answers from a named body
/// instead of forwarding. The status defaults to `200` — the common
/// case is serving content, and the error statuses are reachable for a
/// policy page that wants a body without a matching `error_pages`
/// entry.
pub const RespondJson = struct {
    status: u16 = defaults.respond_status,
    body: []const u8,

    pub const schema_doc =
        "Answer the matched request with a configured body and the given " ++
        "status, served from memory without contacting the origin.";
    pub const schema_fields = .{
        .status = .{
            .desc = "Status to answer with: 200, or one of the error statuses " ++
                "this proxy sends.",
            .int_values = &shed.page_statuses,
        },
        .body = .{
            .desc = "Name of the body to serve, from the top-level `bodies` map.",
            .min_length = 1,
        },
    };
};

/// A `redirect` action's target (#176): a fixed `location` sent
/// verbatim, or a composed one — scheme (required) and optionally host
/// replaced, the request's own canonical path and query carried through
/// so the config never restates them. Exactly one form.
pub const RedirectJson = struct {
    status: u16 = defaults.redirect_status,
    location: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    host: ?[]const u8 = null,

    pub const schema_doc =
        "Where a redirect sends the client: a fixed `location`, or a " ++
        "composed target (`scheme` and optionally `host`) that keeps the " ++
        "request's own path and query.";
    pub const schema_fields = .{
        .status = .{
            .desc = "Redirect status: permanent or temporary, each with or " ++
                "without method preservation.",
            .int_values = &filter.redirect_statuses,
        },
        .location = .{
            .desc = "Fixed Location value, sent verbatim; mutually exclusive " ++
                "with scheme and host.",
            .min_length = 1,
        },
        .scheme = .{
            .desc = "Replacement scheme for a composed target, and required for " ++
                "one. It is never guessed: behind a TLS terminator, every hop " ++
                "zoxy sees is plaintext.",
            .enum_type = filter.Redirect.Scheme,
        },
        .host = .{
            .desc = "Replacement canonical host for a composed target; absent " ++
                "keeps the request's own.",
        },
    };
};

/// One response filter rule (#175): a match over the origin's response —
/// status and response headers; the request's facts are gone by the time
/// a response exists, which is the reason this is its own table rather
/// than a scope marker on `FilterJson` — and the header edits applied
/// when it matches. Reject and rewrite are request-side ideas, rejected
/// here by their own names.
pub const ResponseFilterJson = struct {
    match: ResponseMatchJson = .{},
    actions: []const ResponseActionJson,

    pub const schema_doc =
        "One response filter rule: a match over the origin's response and " ++
        "the header edits applied when it matches.";
    pub const schema_fields = .{
        .match = .{ .desc = "Response-match predicate; absent fields match anything." },
        .actions = .{
            .desc = "Header edits (header_set, header_add, header_remove) applied " ++
                "in order when the rule matches. Request-side actions are not " ++
                "available, because the origin has already answered.",
            .min_items = 1,
        },
    };
};

pub const ResponseMatchJson = struct {
    status: ?[]const u16 = null,
    status_class: ?[]const u8 = null,
    headers: ?[]const HeaderMatchJson = null,

    pub const schema_doc = "Response-match predicate; every absent field matches anything.";
    pub const schema_fields = .{
        .status = .{
            .desc = "Exact response status codes to match; absent matches any status.",
            .min_items = 1,
            .minimum = 100,
            .maximum = 599,
        },
        .status_class = .{
            .desc = "Response status class to match (\"1xx\" through \"5xx\"); " ++
                "absent matches any class.",
            .enum_type = filter.StatusClass,
        },
        .headers = .{ .desc = "Response-header predicates; all must match." },
    };
};

pub const HeaderEditJson = struct {
    name: []const u8,
    value: []const u8,

    pub const schema_doc = "A header name and value for header_set or header_add.";
    pub const schema_fields = .{
        .name = .{ .desc = "Header field name." },
        .value = .{ .desc = "Header field value." },
    };
};

pub const RewriteJson = struct {
    from: []const u8,
    to: []const u8,

    pub const schema_doc = "A path-prefix rewrite: strip `from`, prepend `to`.";
    pub const schema_fields = .{
        .from = .{ .desc = "Canonical path prefix to strip; must start with a slash." },
        .to = .{ .desc = "Canonical path prefix to prepend; must start with a slash." },
    };
};

pub const RouteJson = struct {
    /// Optional §7 host scope; absent means the route matches any host.
    host: ?[]const u8 = null,
    prefix: []const u8,
    /// Optional #302 header scope; absent means the route matches any
    /// request. Conjoined with the other two, not ranked against them.
    header: ?RouteHeaderJson = null,
    cluster: []const u8,

    pub const schema_doc =
        "One route entry. A request must match every key the route sets " ++
        "(host, header and prefix), and the table is matched most specific " ++
        "first: host, then header, then prefix.";
    pub const schema_fields = .{
        .host = .{ .desc = "Canonical host scope; absent matches any host." },
        .prefix = .{
            .desc = "Canonical origin-form path prefix; must start with a slash. " ++
                "Matches whole path segments: /api matches /api and /api/v1, " ++
                "never /apihost.",
        },
        .header = .{
            .desc = "Header the request must carry for this route to match; " ++
                "absent matches any request. A route with a header is tried " ++
                "before the same route without one.",
        },
        .cluster = .{ .desc = "Name of the cluster that matching requests are routed to." },
    };
};

/// A route's header predicate (#302): a pinned canary is a specific
/// client, a test account or an internal gateway's header, which endpoint
/// weights cannot express because it is not probabilistic.
///
/// Two kinds, and deliberately not the three `filters` have. `equals` is
/// one `mem.eql` on a zero-copy head slice and `present` is one lookup;
/// `contains` is a scan whose cost grows with the header a client sent,
/// on a table every request walks. §7 draws the line where a route
/// dimension would become the second match engine it refuses, and a
/// substring test is the near side of it.
pub const RouteHeaderJson = struct {
    name: []const u8,
    /// Exactly one of these selects the predicate kind.
    present: ?bool = null,
    equals: ?[]const u8 = null,

    pub const schema_doc =
        "One header predicate on a route. Exactly one of `present` or " ++
        "`equals` selects the kind. Routes do not support substring or " ++
        "regex matching.";
    pub const schema_one_of = [_][]const u8{ "present", "equals" };
    pub const schema_fields = .{
        .name = .{ .desc = "Header field name (matched case-insensitively)." },
        .present = .{
            .desc = "Matches when the header is present (present: false is rejected).",
            .const_true = true,
        },
        .equals = .{ .desc = "Matches when the header's value equals this string exactly." },
    };
};

pub const ClusterJson = struct {
    endpoints: []const EndpointJson,
    /// Optional §7 pick policy; absent means `p2c` (the design's
    /// trajectory), `rr` opts back into strict rotation, and the object
    /// form names a `hash` policy's key (#178) — a bare `"hash"` string
    /// is rejected, because what the cluster is sticky on is the
    /// operator's decision, not a default.
    pick: PickJson = .{ .policy = @tagName(defaults.pick) },
    /// Optional §7 active health checks; absent means off, so an
    /// unprobed cluster reserves nothing and is never skipped.
    check: ?CheckJson = null,
    /// Optional §7 passive ejection (#230); absent leaves it off.
    passive_ejection: ?PassiveEjectionJson = null,
    /// Optional #390 panic threshold; absent fails open only at zero
    /// healthy, as every config before the key did.
    panic_threshold_percent: ?u8 = null,
    /// Optional §8 per-endpoint concurrency cap; absent means uncapped.
    max_inflight: ?u32 = null,
    /// Optional #392 cap on the cluster's total in-flight work.
    max_total_inflight: ?u32 = null,
    /// Optional #391 recovery ramp for `max_inflight`.
    slow_start_ms: ?u32 = null,
    /// Optional #181 dial retries across this cluster's endpoints, as a
    /// bare count or `{count, budget}` (#393); absent means none, which is
    /// what every config written before the key existed asked for.
    retries: RetriesJson = .{ .count = 0 },
    /// Optional PROXY protocol announcement on upstream connections
    /// (#142); absent sends none. Only valid on clusters no http
    /// listener routes to.
    proxy_protocol: ?ClusterProxyProtocolJson = null,
    /// Optional §7 origin protocol; absent is HTTP/1.1.
    protocol: []const u8 = "http1",
    /// TLS to the origins: required by `h2`, optional with `http1`
    /// (#296), refused with `h2c`.
    tls: ?ClusterTlsJson = null,

    pub const schema_doc = "One upstream cluster: its endpoints, pick policy and health checks.";
    pub const schema_fields = .{
        .endpoints = .{
            .desc = "Endpoints: IP:port literals (port must be non-zero), " ++
                "name:port with a DNS name resolved once at startup, or `unix:` " ++
                "socket paths, each optionally written as an object that adds a " ++
                "pick weight. A cluster that names a host keeps each address once.",
            .min_items = 1,
        },
        .pick = .{
            .desc = "Endpoint-pick policy: p2c (power of two choices) or rr " ++
                "(strict round-robin) as a bare string, or an object that " ++
                "selects hash (sticky) and names its key.",
        },
        .check = .{
            .desc = "Active health checks for every endpoint in this cluster; absent leaves them off.",
        },
        .passive_ejection = .{
            .desc = "Eject endpoints that real traffic reports dead; absent leaves passive ejection off.",
        },
        .panic_threshold_percent = .{
            .desc = "Percent of the cluster's routable weight that must be healthy " ++
                "for health checks to steer traffic. Below it, zoxy picks over " ++
                "every routable endpoint as if none were ejected, so a cluster " ++
                "that has lost most of its capacity spreads load rather than " ++
                "piling it onto the few survivors. Absent fails open only when " ++
                "no endpoint is healthy. Requires check or passive_ejection.",
            .minimum = constants.panic_threshold_percent_min,
            .maximum = constants.panic_threshold_percent_max,
        },
        .max_inflight = .{
            .desc = "Cap on concurrent in-flight work per endpoint; absent leaves the cluster uncapped.",
            .minimum = 1,
            .maximum = constants.endpoint_inflight_max,
        },
        .slow_start_ms = .{
            .desc = "For this long after an endpoint returns from ejection, raise its " ++
                "max_inflight linearly from 1 to the configured cap, so the first " ++
                "origin to recover is not handed every new request at once. " ++
                "Requires max_inflight, and check or passive_ejection. Absent, a " ++
                "restored endpoint takes its full cap at once.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
        .max_total_inflight = .{
            .desc = "Cap on this cluster's total in-flight work in this process, all " ++
                "endpoints together: HTTP requests (pending dials included) and " ++
                "L4 connections. A new request past it is answered 503, a new L4 " ++
                "connection closed, so one slow cluster cannot take the upstream " ++
                "pool every other cluster shares. Retries of an admitted request " ++
                "are never refused by it. Absent leaves it uncapped.",
            .minimum = 1,
            .maximum = constants.cluster_inflight_max,
        },
        .retries = .{
            .desc = "How many more endpoints an HTTP request may dial after a " ++
                "refused or unreachable first try; 0 (the default) answers 502 " ++
                "on the first failure. All tries share one connect timeout. " ++
                "Applies to http1 clusters: an h2c or h2 cluster refuses a " ++
                "non-zero value, and an L4 connection always dials once. The " ++
                "object form adds a budget on this cluster's retry dials in flight.",
        },
        .proxy_protocol = .{
            .desc = "Announce each client to this cluster's origins with a PROXY " ++
                "protocol header on the upstream connection (only on clusters " ++
                "no http listener routes to); absent sends none.",
        },
        .protocol = .{
            .desc = "What the origins speak: http1 (the default; each exchange " ++
                "leases a pooled connection), h2c (HTTP/2 by prior knowledge) or " ++
                "h2 (HTTP/2 over TLS, which needs `tls`). Over HTTP/2, exchanges " ++
                "share connections as streams and an answer's trailers reach the " ++
                "client, which gRPC needs. Only http listeners without upgrades " ++
                "may route to an HTTP/2 cluster.",
            .enum_type = Config.Cluster.Protocol,
        },
        .tls = .{
            .desc = "TLS to this cluster's origins: the name each must prove and " ++
                "the CA bundle its chain must reach. Required by protocol h2; " ++
                "with http1, the origins speak HTTPS. Not allowed with h2c.",
        },
    };
};

pub const ClusterTlsJson = struct {
    server_name: []const u8,
    ca: ClusterTlsCaJson,

    pub const schema_doc = "TLS to a cluster's origins: every chain is verified, never skipped.";
    pub const schema_fields = .{
        .server_name = .{
            .desc = "The DNS name every origin's certificate must carry in its " ++
                "subjectAltName, also sent as SNI. An endpoint address is not an " ++
                "identity, so the name is configured.",
            .min_length = 1,
            .max_length = constants.host_bytes_max,
        },
        .ca = .{ .desc = "The trust anchors an origin's chain must reach." },
    };
};

pub const ClusterTlsCaJson = struct {
    path: []const u8,

    pub const schema_doc = "A PEM bundle of the CA certificates to trust, read once at load.";
    pub const schema_fields = .{
        .path = .{ .desc = "Path to the PEM bundle.", .min_length = 1 },
    };
};

/// The one reader behind every short spelling (§5, #400): a bare scalar
/// that stands for the common case, or the object it abbreviates. Each
/// spelling type names its scalar (`short_token`), its object
/// (`ObjectForm`, a plain struct `innerParse` reads with the loader's own
/// strictness without recursing back into `jsonParse`), and the two
/// conversions; this does the token work once, where `EndpointJson` and
/// `PickJson` used to carry a copy each.
fn parseShortForm(
    comptime T: type,
    allocator: std.mem.Allocator,
    source: anytype,
    options: std.json.ParseOptions,
) !T {
    comptime assertSameShape(T, T.ObjectForm);
    switch (try source.peekNextTokenType()) {
        .object_begin => {
            const object = try std.json.innerParse(T.ObjectForm, allocator, source, options);
            return try T.fromObject(object);
        },
        inline .string, .number => |kind| {
            // A scalar of the other kind can never be this field's short
            // spelling; refused rather than coerced.
            if (kind != T.short_token) return error.UnexpectedToken;
            const token = try source.nextAlloc(allocator, .alloc_if_needed);
            const literal: []const u8 = switch (token) {
                .string, .allocated_string, .number, .allocated_number => |slice| slice,
                // The peek promised this kind; anything else is the
                // scanner disagreeing with itself.
                else => unreachable,
            };
            return T.fromShort(literal);
        },
        // A bool, null, or array can never be a short spelling.
        else => return error.UnexpectedToken,
    }
}

/// The two shapes of one spelling are one contract: a field added to either
/// and forgotten on the other would let the schema advertise a key the
/// parser rejects, or the parser accept one the schema hides.
fn assertSameShape(comptime Outer: type, comptime Inner: type) void {
    const outer = @typeInfo(Outer).@"struct";
    const inner = @typeInfo(Inner).@"struct";
    assert(outer.field_names.len == inner.field_names.len);
    for (outer.field_names, inner.field_names) |a, b| {
        assert(std.mem.eql(u8, a, b));
    }
    for (outer.field_types, inner.field_types) |a, b| {
        assert(a == b);
    }
}

/// A cluster's #181 retries in its two spellings (#393, placed by §5's
/// #400 record): the bare count every config has written, or an object
/// carrying the count and a cluster-wide budget on retry dials in flight.
/// The object form is for clusters that retry, so its `count` starts at
/// 1; the bare `0` stays the default and the one way to say "none".
pub const RetriesJson = struct {
    count: u16,
    budget: ?u16 = null,

    pub const schema_doc =
        "Retries with a budget: how many more endpoints one request may dial, " ++
        "and how many retry dials this cluster may have in flight at once.";
    pub const schema_fields = .{
        .count = .{
            .desc = "How many more endpoints a request may dial after a refused or " ++
                "unreachable first try.",
            .minimum = 1,
            .maximum = constants.cluster_retries_max,
        },
        .budget = .{
            .desc = "Retry dials this cluster may have in flight at once, in this " ++
                "process. A refused dial that finds the budget spent is answered " ++
                "502 rather than retried, so a correlated failure cannot double " ++
                "the load on the endpoints still answering. Absent is unbounded.",
            .minimum = 1,
            .maximum = constants.retry_budget_max,
        },
    };

    const ObjectForm = struct {
        count: u16,
        budget: ?u16 = null,
    };

    const short_token: std.json.TokenType = .number;

    fn fromShort(literal: []const u8) error{ InvalidNumber, Overflow }!RetriesJson {
        const count = std.fmt.parseInt(u16, literal, 10) catch |err| switch (err) {
            error.Overflow => return error.Overflow,
            error.InvalidCharacter => return error.InvalidNumber,
        };
        return .{ .count = count };
    }

    /// The object form is for clusters that retry: `{"count": 0}` would be
    /// the bare `0` spelled long, and a budget beside it would bound
    /// nothing, so the long form starts at 1 — as its schema says.
    fn fromObject(object: ObjectForm) error{InvalidNumber}!RetriesJson {
        if (object.count == 0) return error.InvalidNumber;
        return .{ .count = object.count, .budget = object.budget };
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !RetriesJson {
        return parseShortForm(RetriesJson, allocator, source, options);
    }
};

/// One cluster endpoint (#174): the bare `"IP:port"` string every config
/// has always written, or an object naming the same literal plus a pick
/// weight. Both spellings parse to this one shape — a bare string is
/// weight 1 — so the homogeneous cluster, which is most clusters, keeps
/// the cheap form and a canary is one endpoint's worth of ceremony.
pub const EndpointJson = struct {
    address: []const u8,
    weight: u32 = 1,
    /// #396's standby tier: 0, the default and what a bare string means,
    /// is the primary.
    priority: u8 = 0,
    /// #480's family of a name's addresses: absent takes A records alone,
    /// and an address refuses it.
    family: ?[]const u8 = null,

    pub const schema_doc =
        "One endpoint: an IP:port literal, a DNS name and port, a `unix:` " ++
        "socket path, or an object carrying any of them with a relative pick " ++
        "weight and a standby tier.";
    pub const schema_fields = .{
        .address = .{
            .desc = "Endpoint literal: `IP:port` (port must be non-zero), " ++
                "`name:port` with a DNS name resolved once at startup into one " ++
                "endpoint per address, or `unix:` followed by the absolute path " ++
                "of a stream socket (printable ASCII, no quote or backslash).",
            .min_length = 1,
        },
        .weight = .{
            .desc = "Relative share of the cluster's traffic under every pick " ++
                "policy; the default is 1, so endpoints share equally. 0 drains " ++
                "the endpoint: it is still health-checked but never picked.",
            .minimum = 0,
            .maximum = constants.endpoint_weight_max,
        },
        .priority = .{
            .desc = "Standby tier: 0 (the default) is the primary. A request goes " ++
                "to the lowest tier with an endpoint that is healthy and under its " ++
                "max_inflight, so a higher tier takes traffic only when every tier " ++
                "below it is ejected, drained or full. The pick policy runs within " ++
                "the chosen tier.",
            .minimum = 0,
            .maximum = constants.endpoint_priority_max,
        },
        .family = .{
            .desc = "Which of a DNS name's addresses become endpoints: ipv4 (the " ++
                "default; A records), ipv6 (AAAA records) or any (both). Only " ++
                "beside a name.",
            .enum_type = dns_host.Family,
        },
    };

    /// The object form as a plain struct, so `innerParse` reads it with
    /// the loader's own strictness (unknown fields rejected) without
    /// recursing back into `jsonParse` below.
    const ObjectForm = struct {
        address: []const u8,
        weight: u32 = 1,
        priority: u8 = 0,
        family: ?[]const u8 = null,
    };

    const short_token: std.json.TokenType = .string;

    fn fromShort(literal: []const u8) error{}!EndpointJson {
        return .{ .address = literal, .weight = 1, .priority = 0, .family = null };
    }

    fn fromObject(object: ObjectForm) error{}!EndpointJson {
        return .{
            .address = object.address,
            .weight = object.weight,
            .priority = object.priority,
            .family = object.family,
        };
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !EndpointJson {
        return parseShortForm(EndpointJson, allocator, source, options);
    }
};

/// The pick policy's two spellings (#178): the bare policy string every
/// stateless policy needs, or an object carrying the policy *and* its
/// settings — today, a `hash` policy's key. The two parse to this one
/// shape, `EndpointJson`'s pattern; a bare `"hash"` never resolves,
/// because a hash policy without a named key was the misleading default
/// this form replaced.
pub const PickJson = struct {
    policy: []const u8,
    /// Required for `hash`, rejected elsewhere: what the cluster is
    /// sticky on.
    key: ?[]const u8 = null,
    /// The header or cookie name a request-derived key reads; required
    /// there, rejected for `source_ip`.
    name: ?[]const u8 = null,

    pub const schema_doc =
        "Endpoint-pick policy: a bare policy string (p2c, rr), or an object " ++
        "selecting hash and naming what it keys on. With hash, the same key " ++
        "always selects the same endpoint for a given set of healthy " ++
        "endpoints, so every zoxy process behind SO_REUSEPORT agrees " ++
        "without sharing any state.";
    pub const schema_fields = .{
        .policy = .{
            .desc = "Pick policy: p2c (power of two choices), rr (strict " ++
                "round-robin), or hash (sticky on an explicit key).",
            .enum_type = Config.Cluster.Pick.Builtin,
        },
        .key = .{
            .desc = "What a hash cluster is sticky on: source_ip (the whole IPv4 " ++
                "address, or the /64 prefix of an IPv6 one, which survives RFC " ++
                "8981 address rotation), header (rendezvous hashing on the named " ++
                "header's value), or cookie (the named cookie, set by zoxy, " ++
                "carries the endpoint assignment itself).",
            .enum_type = std.meta.Tag(Config.Cluster.HashKey),
        },
        .name = .{
            .desc = "The header or cookie name a request-derived key reads; " ++
                "required for those keys, rejected for source_ip.",
            .min_length = 1,
            .max_length = constants.pick_name_bytes_max,
        },
    };

    /// Two forks over one object (#305), conjoined rather than nested.
    ///
    /// `key` names what a `hash` cluster is sticky on and means nothing
    /// beside `p2c` or `rr`; `name` names the header or cookie a
    /// request-derived key reads and means nothing beside `source_ip`.
    /// Both are `oneOf`s over their own discriminator, and the second
    /// covers the keyless policies for free: with no `key` present its
    /// default arm applies, and that arm forbids `name` — which is the
    /// same verdict the first fork reaches by a different route.
    pub const schema_variants = [_]SchemaVariants{
        .{
            .on = "policy",
            .branches = &.{
                .{ .value = "p2c", .forbid = &.{ "key", "name" } },
                .{ .value = "rr", .forbid = &.{ "key", "name" } },
                .{ .value = "hash", .require = &.{"key"} },
            },
        },
        .{
            .on = "key",
            .branches = &.{
                .{ .value = "source_ip", .default = true, .forbid = &.{"name"} },
                .{ .value = "header", .require = &.{"name"} },
                .{ .value = "cookie", .require = &.{"name"} },
            },
        },
    };

    /// The object form as a plain struct, so `innerParse` reads it with
    /// the loader's own strictness (unknown fields rejected) without
    /// recursing back into `jsonParse` below.
    const ObjectForm = struct {
        policy: []const u8,
        key: ?[]const u8 = null,
        name: ?[]const u8 = null,
    };

    const short_token: std.json.TokenType = .string;

    fn fromShort(literal: []const u8) error{}!PickJson {
        return .{ .policy = literal };
    }

    fn fromObject(object: ObjectForm) error{}!PickJson {
        return .{ .policy = object.policy, .key = object.key, .name = object.name };
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !PickJson {
        return parseShortForm(PickJson, allocator, source, options);
    }
};

/// One named body (#159): the bytes a configured response serves, plus
/// the content type nothing will guess. Exactly one source arm — a
/// `file` read once at load (parse-once, §1: a changed file needs a
/// restart), or the `inline` string for one-liners that deserve no
/// fixture. The arm structure is the extension point: a future source
/// is a new arm here, and no consumer of a body ever changes.
pub const BodyJson = struct {
    file: ?[]const u8 = null,
    @"inline": ?[]const u8 = null,
    content_type: []const u8,

    pub const schema_doc =
        "One named response body: exactly one of a `file` read at startup " ++
        "or an `inline` string, plus the Content-Type it is served with. " ++
        "Referenced by name from error_pages, so a body served in several " ++
        "places is still stored once.";
    /// The fork the doc above already describes, said in a way the
    /// schema can act on (#305). It was expressible from the day
    /// `oneOf` was emitted and simply never declared, which is what the
    /// differential gate is for finding.
    pub const schema_one_of = [_][]const u8{ "file", "inline" };
    pub const schema_fields = .{
        .file = .{
            .desc = "Path to the body's file, read once at startup; changing " ++
                "the file takes a restart.",
        },
        .@"inline" = .{
            .desc = "The body's bytes, verbatim, for content small enough to " ++
                "keep in the config.",
        },
        .content_type = .{
            .desc = "The Content-Type header value this body is served with; " ++
                "nothing is inferred from a filename.",
            .min_length = 1,
        },
    };
};

/// The #159 `bodies` map: named assets, keyed by name — `ClustersJson`'s
/// shape, because it is the same idea: a shared resource defined once
/// and referenced by name, so a dangling reference is a load error and
/// one body referenced twice is still one buffer.
pub const BodiesJson = struct {
    entries: []const Entry,

    const Entry = struct {
        name: []const u8,
        body: BodyJson,
    };

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !@This() {
        var entries: std.ArrayList(Entry) = .empty;
        if (try source.next() != .object_begin) {
            return error.UnexpectedToken;
        }
        // Terminated by the object's own `}` or by the input running
        // out, which the scanner reports as an error — every map here
        // carries the same bound.
        // lint:unbounded-ok — the scanner's `}`/error is the bound
        while (true) {
            const token = try source.nextAlloc(allocator, .alloc_if_needed);
            const name: []const u8 = switch (token) {
                .object_end => break,
                .string => |slice| slice,
                .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            try entries.append(allocator, .{
                .name = name,
                .body = try std.json.innerParse(BodyJson, allocator, source, options),
            });
        }
        const seen = entries.items.len;
        const parsed: @This() = .{ .entries = try entries.toOwnedSlice(allocator) };
        assert(parsed.entries.len == seen);
        return parsed;
    }
};

/// The #159 `error_pages` map: status literal → body name. Small and
/// closed — the loader rejects a status this proxy never sends — so the
/// value is a bare name string, not an object waiting for fields.
pub const ErrorPagesJson = struct {
    entries: []const Entry,

    const Entry = struct {
        status: []const u8,
        body: []const u8,
    };

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !@This() {
        var entries: std.ArrayList(Entry) = .empty;
        if (try source.next() != .object_begin) {
            return error.UnexpectedToken;
        }
        // Terminated by the object's own `}` or by the input running out,
        // which the scanner reports as an error — the same bound the other
        // maps here carry.
        // lint:unbounded-ok — the scanner's `}`/error is the bound
        while (true) {
            const token = try source.nextAlloc(allocator, .alloc_if_needed);
            const status: []const u8 = switch (token) {
                .object_end => break,
                .string => |slice| slice,
                .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            try entries.append(allocator, .{
                .status = status,
                .body = try std.json.innerParse([]const u8, allocator, source, options),
            });
        }
        const seen = entries.items.len;
        const parsed: @This() = .{ .entries = try entries.toOwnedSlice(allocator) };
        assert(parsed.entries.len == seen);
        return parsed;
    }
};

pub const ClusterProxyProtocolJson = struct {
    send: []const u8,

    pub const schema_doc =
        "What this cluster's origins expect before the payload. The header " ++
        "names the connection's client, so only l4 listeners may route to a " ++
        "cluster that sends one: a pooled HTTP upstream connection is shared " ++
        "across clients and cannot carry a per-client header.";
    pub const schema_fields = .{
        .send = .{
            .desc = "PROXY protocol version to send: v1 (text) or v2 (binary, " ++
                "the one cloud load balancers use).",
            .enum_type = Config.Cluster.ProxyProtocolSend,
        },
    };
};

/// One cluster's health-check block (§7). `type` picks what a probe
/// proves; the `http` fields are rejected under `tcp` and `grpc`, and
/// `service` under all but `grpc`, rather than ignored, so a config
/// cannot quietly describe a check it is not running.
pub const CheckJson = struct {
    type: []const u8 = @tagName(defaults.check.kind),
    /// Thresholds, HAProxy's `fall`/`rise`.
    fall: u8 = defaults.check.fall,
    rise: u8 = defaults.check.rise,
    /// Budget for one whole probe; absent means `timeouts.connect_ms`.
    timeout_ms: ?u32 = null,
    /// Required for `http`, rejected for `tcp` and `grpc`.
    path: ?[]const u8 = null,
    /// `Host` for an `http` probe; absent sends the endpoint literal, or
    /// `localhost` for a `unix:` endpoint, whose path names no host.
    host: ?[]const u8 = null,
    /// The status an `http` probe accepts; absent is 200. Optional so
    /// that naming it under `tcp` or `grpc`, where nothing reads a
    /// status, is refused like the other `http` fields rather than
    /// parsed and ignored (#400).
    expect_status: ?u16 = null,
    /// The service a `grpc` probe asks about; absent asks about the
    /// server. An empty name is refused rather than read as absence:
    /// absence is how the server is asked for, and one spelling is
    /// what the schema's `minLength` already says.
    service: ?[]const u8 = null,

    pub const schema_doc = "Active health checks for a cluster's endpoints.";
    pub const schema_fields = .{
        .type = .{
            .desc = "What a probe checks: tcp (the port accepts a connection), http (a request for `path` gets the expected status) or grpc (an HTTP/2 cluster's grpc.health.v1 service answers SERVING).",
            .enum_type = Config.Cluster.Check.Builtin,
        },
        .fall = .{
            .desc = "Consecutive failed probes that eject an endpoint from balancing.",
            .minimum = 1,
            .maximum = constants.health_probe_threshold_max,
        },
        .rise = .{
            .desc = "Consecutive successful probes that restore an ejected endpoint.",
            .minimum = 1,
            .maximum = constants.health_probe_threshold_max,
        },
        .timeout_ms = .{
            .desc = "Budget for one whole probe; absent uses timeouts.connect_ms.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
        .path = .{
            .desc = "Canonical origin-form path an http probe requests; required for http, rejected for tcp and grpc.",
            .min_length = 1,
        },
        .host = .{
            .desc = "Host header an http probe sends; absent sends the endpoint's " ++
                "own IP:port literal, or localhost for a unix: endpoint.",
            .min_length = 1,
        },
        .expect_status = .{
            .desc = "The only response status an http probe accepts as healthy; " ++
                "absent is 200. Rejected for tcp and grpc.",
            .minimum = 100,
            .maximum = 599,
        },
        .service = .{
            .desc = "The service a grpc probe asks grpc.health.v1.Health/Check about. If absent, the probe asks about the server as a whole.",
            .min_length = 1,
            .max_length = constants.health_check_grpc_service_bytes_max,
        },
    };

    /// A `tcp` probe sends nothing and reads nothing, so every
    /// HTTP-shaped field beside it would be inert; an `http` probe has
    /// to be told what to ask for (#305), and a `grpc` one asks a path
    /// the protocol fixes. `type` defaults to `tcp`, so that arm carries
    /// the absence too.
    pub const schema_variants = [_]SchemaVariants{.{
        .on = "type",
        .branches = &.{
            .{ .value = "tcp", .default = true, .forbid = &.{ "path", "host", "expect_status", "service" } },
            .{ .value = "http", .require = &.{"path"}, .forbid = &.{"service"} },
            .{ .value = "grpc", .forbid = &.{ "path", "host", "expect_status" } },
        },
    }};
};

/// One cluster's passive-ejection block (§7, #230). Two numbers and no
/// mode switch: what the signals are is settled by the design, not by
/// the operator, because the choice worth making is *whether* to remove
/// capacity by inference — not which inference to draw.
pub const PassiveEjectionJson = struct {
    fall: u8 = defaults.passive_ejection.fall,
    recovery_ms: u32 = defaults.passive_ejection.recovery_ms,
    /// Optional #394 cooldown ceiling; absent keeps the cooldown fixed.
    recovery_ms_max: ?u32 = null,

    pub const schema_doc =
        "Eject an endpoint that real traffic shows is dead: a failed dial, " ++
        "or an exchange with no response byte before its deadline. Absent " ++
        "leaves it off. Origin 5xx responses never count, since a bad deploy " ++
        "is not an unhealthy endpoint.";
    pub const schema_fields = .{
        .fall = .{
            .desc = "Consecutive failed requests that eject an endpoint from balancing.",
            .minimum = 1,
            .maximum = constants.health_probe_threshold_max,
        },
        .recovery_ms = .{
            .desc = "How long an ejected endpoint stays out before real traffic tests it again.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
        .recovery_ms_max = .{
            .desc = "Double the cooldown on each passive ejection of the same endpoint, " ++
                "up to this many milliseconds, so a flapping origin stays out longer " ++
                "each time. An endpoint that then stays in rotation this long starts " ++
                "over at recovery_ms. Absent keeps every cooldown at recovery_ms; " ++
                "must be at least recovery_ms.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
    };
};

pub const TimeoutsJson = struct {
    /// Optional: nginx ships 60 s for the same budget and HAProxy's
    /// `timeout connect` is conventionally single-digit seconds, so a
    /// value zoxy can pick without guessing at anyone's policy. Zero
    /// stays rejected — it would fail every dial before it left.
    connect_ms: u32 = defaults.timeouts.connect_ms,
    /// Optional, same argument: nginx's `keepalive_timeout` is 75 s and
    /// its `client_header_timeout` 60 s. Zero would reap on arrival, and a
    /// value at or below `connect_ms` is rejected — the dial's handoff
    /// cannot shorten a timer that is already counting down (§4/§5).
    idle_ms: u32 = defaults.timeouts.idle_ms,
    /// Optional, and `0` means "no cap" — the drain waits for the last
    /// connection however long that takes (§8).
    ///
    /// Unlike the two above there is no convention to borrow: nginx,
    /// HAProxy and Caddy all default to waiting indefinitely, while
    /// Traefik picks 10 s and Envoy 600 s. A sixty-fold spread across
    /// mature implementations is not a default waiting to be discovered,
    /// so zoxy declines to invent one and joins the majority. The
    /// supervisor that sent the signal already owns the upper bound and
    /// enforces it with SIGKILL; an operator who wants zoxy to give up
    /// sooner than their platform does sets a number here.
    drain_deadline_ms: u32 = 0,
    /// Optional: absent or `0` means "no cap" (§6). The default keeps every
    /// pre-existing config valid and leaves max-lifetime opt-in.
    max_lifetime_ms: u32 = 0,
    /// Optional, same shape: absent or `0` means "no cap" (§8). Opt-in
    /// because a request deadline is a policy an operator sets against
    /// their own origin's latency, not a value zoxy can pick for them.
    request_ms: u32 = 0,
    /// Optional #311 serving-loop watchdog. **Absent is off**, and that
    /// is why it is optional rather than a `0` like the two caps above:
    /// the mechanism has a floor — `alarm(2)` is whole seconds and the
    /// tick that refreshes it is half the bound — so the legal values are
    /// "none" and "at least `loop_watchdog_ms_min`", with nothing in
    /// between. Absence carries the "none" and the minimum carries the
    /// rest, which is one rule a schema states exactly; a zero would have
    /// needed a fork to say the same thing.
    ///
    /// Opt-in for #226's reason in the other direction: the process this
    /// kills is one an operator has no other way to notice, but a bound
    /// nobody named is a restart this proxy chose on their behalf.
    loop_watchdog_ms: ?u32 = null,
    /// Optional #235 head-read budget. Absent is *derived* rather than
    /// fixed — see `defaults.headMs`, which is what keeps every config
    /// written before this field behaving exactly as it did.
    head_ms: ?u32 = null,
    /// Optional #180 tunnel lifetime; absent means an hour. Unlike the
    /// two caps above, zero is rejected — a tunnel pins a dedicated pool
    /// slot, so "no cap" is the one answer §5 cannot carry.
    tunnel_ms: u32 = defaults.timeouts.tunnel_ms,
    /// Optional §7 health-probe pacing; absent means HAProxy's `inter`
    /// default. Unlike the two caps above, zero is rejected: probing is
    /// switched per cluster (`check`), never by zeroing its interval.
    health_interval_ms: u32 = defaults.timeouts.health_interval_ms,

    pub const schema_doc = "Connection lifecycle deadlines, in milliseconds.";
    pub const schema_fields = .{
        .connect_ms = .{
            .desc = "Per-try upstream connect budget.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
        .idle_ms = .{
            .desc = "How long a connection may stay quiet, between requests or " ++
                "before its first byte; must exceed connect_ms and be at least head_ms.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
        .drain_deadline_ms = .{
            .desc = "Graceful-drain deadline on shutdown; 0 waits indefinitely.",
            .minimum = 0,
            .maximum = constants.timeout_ms_max,
        },
        .loop_watchdog_ms = .{
            .desc = "Serving-loop watchdog: kill this process if the event " ++
                "loop completes nothing for this long. Absent is off.",
            .minimum = constants.loop_watchdog_ms_min,
            .maximum = constants.timeout_ms_max,
        },
        .max_lifetime_ms = .{
            .desc = "Maximum connection age; 0 disables it.",
            .minimum = 0,
            .maximum = constants.timeout_ms_max,
        },
        .head_ms = .{
            .desc = "Time allowed to read one request head, which bounds a " ++
                "slowloris attack. Must exceed connect_ms and not exceed idle_ms.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
        .tunnel_ms = .{
            .desc = "Maximum lifetime of a tunnelled upgrade. Once a connection " ++
                "becomes a tunnel, this replaces its idle, request and lifetime " ++
                "deadlines. Zero is rejected because a tunnel holds a dedicated " ++
                "pool slot.",
            .minimum = constants.tunnel_ms_min,
            .maximum = constants.tunnel_ms_max,
        },
        .request_ms = .{
            .desc = "Maximum duration of one L7 exchange, not reset by activity; 0 disables it.",
            .minimum = 0,
            .maximum = constants.timeout_ms_max,
        },
        .health_interval_ms = .{
            .desc = "Pause between health-probe sweeps over checked clusters.",
            .minimum = 1,
            .maximum = constants.timeout_ms_max,
        },
    };
};

/// JSON object map of cluster name → cluster, parsed into an ordered list
/// so duplicate keys can be rejected in stage 2 (std.json's map types
/// silently keep the last duplicate — negative space we refuse to have).
pub const ClustersJson = struct {
    /// Every key the object carried, in order. Arena-backed and grown as
    /// the object is read: there is no ceiling on cluster count, so there
    /// is no capacity to skip past either — what used to be parsed-then-
    /// discarded past a cluster ceiling is now simply parsed.
    entries: []const Entry,

    const Entry = struct {
        name: []const u8,
        cluster: ClusterJson,
    };

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !@This() {
        var entries: std.ArrayList(Entry) = .empty;
        if (try source.next() != .object_begin) {
            return error.UnexpectedToken;
        }
        // Terminated by the object's own `}` or by the input running out,
        // which the scanner reports as an error — the same bound every
        // other array in this config now has, and the reason the old
        // `keys_seen_max` backstop is gone: with no ceiling above it, that
        // 4096 would have quietly become the new cluster limit.
        // lint:unbounded-ok — the scanner's `}`/error is the bound
        while (true) {
            const token = try source.nextAlloc(allocator, .alloc_if_needed);
            const name: []const u8 = switch (token) {
                .object_end => break,
                .string => |slice| slice,
                .allocated_string => |slice| slice,
                else => return error.UnexpectedToken,
            };
            try entries.append(allocator, .{
                .name = name,
                .cluster = try std.json.innerParse(ClusterJson, allocator, source, options),
            });
        }
        const seen = entries.items.len;
        const parsed: @This() = .{ .entries = try entries.toOwnedSlice(allocator) };
        // The postcondition every sibling resolver states: the handed-back
        // slice is every key the object carried, not a prefix of them —
        // which is exactly what the removed skip-past-capacity branch used
        // to make untrue.
        assert(parsed.entries.len == seen);
        return parsed;
    }
};

/// Marker for array-item vocabularies reflection can't infer from the
/// element type alone. `http_method` means "the items are the registered
/// HTTP method tokens", which `schema.zig` emits as a token
/// enum. #180's upgrade set used to be the second member; it is a flag
/// object now (#305), so the schema states its vocabulary as fields and
/// needs no item marker. `alpn_protocol` is #271's closed ALPN vocabulary,
/// emitted as its wire tokens rather than its Zig names.
pub const SchemaItems = enum { http_method, alpn_protocol };

/// The attribute keys a `schema_fields` entry may carry beyond `.desc`.
/// `assert_meta_matches` rejects any other key at comptime, so a typo'd
/// attribute is a compile error, not silently-ignored data.
/// One arm of a discriminated block: the value of the deciding field,
/// and what that value makes required or impossible (#305).
///
/// This is the last shape of cross-field rule the loader stated in prose
/// and the schema could not — "`path` is required, but only when `sink`
/// is `file`". A `oneOf` over the discriminator carries it, so an editor
/// refuses the config before the loader has to.
pub const SchemaVariant = struct {
    /// The discriminator's value on this arm.
    value: []const u8,
    /// Fields this arm requires beyond the DTO's own required set.
    require: []const []const u8 = &.{},
    /// Fields this arm rules out, emitted as a `false` schema — which
    /// nothing satisfies, and is how the dialect says "not here".
    forbid: []const []const u8 = &.{},
    /// Whether the discriminator's *absence* selects this arm — set on
    /// the arm a config that omits the key should land on, and false
    /// everywhere else. An arm that is not the default names the
    /// discriminator in its `required`, or an absent key would satisfy
    /// every arm's `properties` vacuously, `oneOf` would see several
    /// matches, and a valid config would be rejected.
    ///
    /// Usually that is the arm matching the field's Zig default, and
    /// `assertVariantsMatch` requires exactly one wherever the field can
    /// be absent. `PickJson.key` is the case that shows what the rule
    /// actually means: its Zig default is `null`, not `"source_ip"`, and
    /// the `source_ip` arm is marked here because that is the *resolved*
    /// fallback — `resolvePick` reads an absent key as `source_ip` for
    /// the keyless policies. It stays sound because the sibling fork on
    /// `policy` independently requires `key` whenever the policy is
    /// `hash`, so the looser arm is unreachable exactly where it would
    /// have been wrong.
    default: bool = false,
};

/// A discriminated fork over one field. A DTO may declare several, each
/// independent — `pick` forks twice, on `policy` and then on `key` — and
/// they are conjoined with `allOf` so neither shadows the other.
pub const SchemaVariants = struct {
    on: []const u8,
    branches: []const SchemaVariant,
};

const schema_attributes = [_][]const u8{
    "desc",       "minimum",         "maximum",         "min_items", "max_items",
    "min_length", "max_length",      "const_true",      "enum_type", "int_values",
    "items",      "item_min_length", "item_max_length",
};

/// Cross-check a DTO's schema metadata against its real fields at comptime:
/// every field needs an entry (so adding a field without documenting it
/// fails the build — this is what makes schema coverage *structural* rather
/// than a runtime test that can silently pass), every entry needs a `.desc`
/// and must map to a real field, and every attribute must be a known key.
/// Run on each `dto_types` entry below and again by the schema emitter.
pub fn assert_meta_matches(comptime T: type) void {
    @setEvalBranchQuota(50_000);
    if (!@hasDecl(T, "schema_doc")) {
        @compileError(@typeName(T) ++ " is missing pub const schema_doc");
    }
    if (!@hasDecl(T, "schema_fields")) {
        @compileError(@typeName(T) ++ " is missing pub const schema_fields");
    }
    const Meta = @TypeOf(T.schema_fields);
    // Every field has a documented, described entry.
    inline for (@typeInfo(T).@"struct".field_names) |name| {
        if (!@hasField(Meta, name)) {
            @compileError(@typeName(T) ++ "." ++ name ++ " has no schema_fields entry");
        }
        const entry = @field(T.schema_fields, name);
        if (!@hasField(@TypeOf(entry), "desc")) {
            @compileError(@typeName(T) ++ "." ++ name ++ " schema entry is missing .desc");
        }
    }
    // Every entry maps to a real field and carries only known attributes.
    inline for (@typeInfo(Meta).@"struct".field_names) |entry_name| {
        if (!@hasField(T, entry_name)) {
            @compileError(@typeName(T) ++ " schema_fields entry '" ++ entry_name ++ "' has no matching field");
        }
        const entry = @field(T.schema_fields, entry_name);
        inline for (@typeInfo(@TypeOf(entry)).@"struct".field_names) |attr_name| {
            comptime var known = false;
            inline for (schema_attributes) |name| {
                if (comptime std.mem.eql(u8, name, attr_name)) known = true;
            }
            if (!known) {
                @compileError(@typeName(T) ++ "." ++ entry_name ++ " has unknown schema attribute '" ++ attr_name ++ "'");
            }
        }
    }
    assertOneOfMatches(T);
    assertVariantsMatch(T);
}

/// A DTO's optional `schema_one_of` — the fields of which exactly one may
/// be present — held to the shape the emitter turns into JSON Schema's
/// `oneOf`.
///
/// The checks are what make the emitted fork *true* rather than merely
/// present. A name that is not a field would emit a branch nothing can
/// satisfy; a name that is a *required* field (no Zig default) is already
/// in `required`, so every branch would match at once and `oneOf` — which
/// means exactly one — would reject every config. Both are silent in JSON
/// Schema and loud here.
/// Hold a DTO's declared forks to its real fields (#305), the way
/// `assertOneOfMatches` holds its `schema_one_of`.
///
/// The emitter takes `on`, `require` and `forbid` as strings and writes
/// them into the document; without this a typo would emit a keyword
/// naming a field that does not exist — a dead constraint that looks
/// like a live one, which is the failure `assert_meta_matches` exists to
/// prevent one screen up.
fn assertVariantsMatch(comptime T: type) void {
    if (!@hasDecl(T, "schema_variants")) return;
    for (T.schema_variants) |set| {
        if (!@hasField(T, set.on)) {
            @compileError(@typeName(T) ++ " schema_variants forks on '" ++ set.on ++
                "', which is not a field");
        }
        // A fork needs arms to choose between; one arm is a constraint
        // stated the hard way.
        if (set.branches.len < 2) {
            @compileError(@typeName(T) ++ " schema_variants on '" ++ set.on ++
                "' needs at least two branches");
        }
        var default_branches = 0;
        for (set.branches) |branch| {
            if (branch.default) default_branches += 1;
            if (branch.value.len == 0) {
                @compileError(@typeName(T) ++ " schema_variants on '" ++ set.on ++
                    "' has an empty branch value");
            }
            for (branch.require) |name| {
                if (!@hasField(T, name)) {
                    @compileError(@typeName(T) ++ " variant '" ++ branch.value ++
                        "' requires '" ++ name ++ "', which is not a field");
                }
                if (std.mem.eql(u8, name, set.on)) {
                    @compileError(@typeName(T) ++ " variant '" ++ branch.value ++
                        "' names its own discriminator in require");
                }
            }
            for (branch.forbid) |name| {
                if (!@hasField(T, name)) {
                    @compileError(@typeName(T) ++ " variant '" ++ branch.value ++
                        "' forbids '" ++ name ++ "', which is not a field");
                }
                if (std.mem.eql(u8, name, set.on)) {
                    @compileError(@typeName(T) ++ " variant '" ++ branch.value ++
                        "' forbids its own discriminator");
                }
                // Requiring and forbidding the same key is an arm no
                // document can satisfy — `oneOf` would then have one
                // fewer arm than it appears to.
                for (branch.require) |required| {
                    if (std.mem.eql(u8, name, required)) {
                        @compileError(@typeName(T) ++ " variant '" ++ branch.value ++
                            "' both requires and forbids '" ++ name ++ "'");
                    }
                }
            }
        }
        // Exactly one arm may absorb an absent discriminator, and only
        // when the field can *be* absent. Two would make `oneOf` see
        // both on an omitted key; none would reject a config the loader
        // accepts by default.
        const optional = @typeInfo(@FieldType(T, set.on)) == .optional or
            defaultOf(T, set.on) != null;
        if (optional and default_branches != 1) {
            @compileError(@typeName(T) ++ " schema_variants on '" ++ set.on ++
                "' may be absent, so exactly one branch must be .default");
        }
        if (!optional and default_branches != 0) {
            @compileError(@typeName(T) ++ " schema_variants on '" ++ set.on ++
                "' is required, so no branch may be .default");
        }
    }
}

/// Whether a field carries a Zig default, as an opaque marker — the
/// value itself is not comparable across the types this walks.
fn defaultOf(comptime T: type, comptime name: []const u8) ?void {
    const info = @typeInfo(T).@"struct";
    for (info.field_names, info.field_attrs) |field_name, attrs| {
        if (std.mem.eql(u8, field_name, name)) {
            return if (attrs.default_value_ptr == null) null else {};
        }
    }
    return null;
}

fn assertOneOfMatches(comptime T: type) void {
    if (!@hasDecl(T, "schema_one_of")) return;
    const names = T.schema_one_of;
    // A fork needs two arms. One would be a plain `required` entry, which
    // the emitter already derives, and zero is not a fork at all.
    if (names.len < 2) {
        @compileError(@typeName(T) ++ " schema_one_of needs at least two fields");
    }
    inline for (names, 0..) |name, index| {
        if (!@hasField(T, name)) {
            @compileError(@typeName(T) ++ " schema_one_of names '" ++ name ++ "', which is not a field");
        }
        // A name listed twice emits two identical branches, and a config
        // setting that one field then satisfies *both* — so "exactly one"
        // would reject every valid config for this DTO. Compiles cleanly
        // and is invisible in the schema, which is the whole reason this
        // function exists.
        inline for (names[0..index]) |earlier| {
            if (comptime std.mem.eql(u8, earlier, name)) {
                @compileError(@typeName(T) ++ " schema_one_of names '" ++ name ++ "' twice");
            }
        }
        const info = @typeInfo(T).@"struct";
        inline for (info.field_names, info.field_attrs) |field_name, attrs| {
            if (comptime std.mem.eql(u8, field_name, name)) {
                if (comptime attrs.default_value_ptr == null) {
                    @compileError(@typeName(T) ++ ".schema_one_of names '" ++ name ++
                        "', which is required — every arm would match and the fork would reject everything");
                }
            }
        }
    }
}

/// Every plain-struct DTO the schema reflects over. `ClustersJson` is a
/// custom map, handled specially by the emitter, so it is not here. The
/// block below runs `assert_meta_matches` on each at comptime, so the
/// metadata cannot drift from the fields whether or not the emitter builds.
pub const dto_types = .{
    ConfigJson,         ListenerJson,        RouteJson,                FilterJson,
    MatchJson,          HeaderMatchJson,     ActionJson,               HeaderEditJson,
    RewriteJson,        ClusterJson,         TimeoutsJson,             LimitsJson,
    AdminJson,          AccessLogJson,       CheckJson,                PickJson,
    ForwardedJson,      ProxyProtocolJson,   ClusterProxyProtocolJson, EndpointJson,
    ResponseFilterJson, ResponseMatchJson,   RedirectJson,             BodyJson,
    TlsJson,            PassiveEjectionJson, HttpListenerJson,         L4ListenerJson,
    L4RouteJson,        RouteHeaderJson,     ResponseActionJson,       ClusterTlsJson,
    ClusterTlsCaJson,   CertificateJson,
};

comptime {
    for (dto_types) |T| assert_meta_matches(T);
}

const example_json = @embedFile("example_config");

test "config: the shipped example parses and resolves" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();

    const parsed = try expectParseOk(&arena_state, example_json);
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.clusters.len);
    // The `"cluster"` sugar resolves to one catch-all route.
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners[0].routes.len);
    try std.testing.expectEqualStrings("/", parsed.listeners[0].routes[0].prefix);
    try std.testing.expectEqual(@as(u16, 0), parsed.listeners[0].routes[0].cluster_index);
    try std.testing.expectEqual(Config.Listener.Protocol.l4, parsed.listeners[0].protocol);
    try std.testing.expectEqual(@as(u16, 8080), parsed.listeners[0].bind_address.ip.getPort());
    try std.testing.expectEqualStrings("origin", parsed.clusters[0].name);
    try std.testing.expectEqual(@as(u16, 9000), parsed.clusters[0].endpoints[0].ip.getPort());
    // The example carries both endpoint spellings (#174): a bare literal
    // at weight 1 beside a weighted object.
    try std.testing.expectEqual(@as(u16, 9001), parsed.clusters[0].endpoints[1].ip.getPort());
    try std.testing.expectEqualSlices(u16, &.{ 1, 3 }, parsed.clusters[0].weights.?);
    // The example's tcp check resolves with its thresholds, and its
    // omitted budget inherits the connect timeout.
    const example_check = parsed.clusters[0].check.?;
    try std.testing.expectEqual(Config.Cluster.Check.Kind.tcp, example_check.kind);
    try std.testing.expectEqual(@as(u8, 3), example_check.fall);
    try std.testing.expectEqual(@as(u8, 2), example_check.rise);
    try std.testing.expectEqual(constants.connect_ms_default, example_check.timeout_ms);
    try std.testing.expectEqual(@as(?Config.Cluster.Check.Http, null), example_check.http);
    // The example names no `timeouts` block at all, so every deadline
    // here is a default — which is the thing it is demonstrating. A
    // check's omitted budget still inherits the connect timeout, so this
    // also pins that the inheritance reads the *resolved* value rather
    // than only an explicitly configured one.
    try std.testing.expectEqual(constants.connect_ms_default, parsed.connect_timeout_ms);
    try std.testing.expectEqual(constants.idle_ms_default, parsed.idle_timeout_ms);
    try std.testing.expectEqual(constants.health_interval_ms_default, parsed.health_interval_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.drain_deadline_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.request_timeout_ms);
}

test "config: max_lifetime_ms is optional and defaults to disabled" {
    // The field is absent here — pre-existing configs stay valid and the
    // cap defaults off (§6).
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
    // The shipped example names neither optional bound, so both must land
    // disabled — the §8 request deadline is opt-in like the age cap.
    try std.testing.expectEqual(@as(u32, 0), parsed.request_timeout_ms);
}

test "config: request_ms is optional, defaults off, and shares the timeout ceiling" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
    ;
    // Absent: pre-existing configs stay valid and the §8 request deadline
    // defaults off, the same shape as max_lifetime_ms.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.request_timeout_ms);
    }
    // Explicit 0 is legal — "no cap", not a TimeoutZero.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1,\"request_ms\":0}}",
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.request_timeout_ms);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1,\"request_ms\":250}}",
        );
        try std.testing.expectEqual(@as(u32, 250), parsed.request_timeout_ms);
    }
    // The shared ceiling still binds — an optional cap is not an unbounded
    // one.
    {
        const json = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}\"timeouts\":{{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1,\"request_ms\":{d}}}}}",
            .{ head, @as(u64, constants.timeout_ms_max) + 1 },
        );
        defer std.testing.allocator.free(json);
        try expectParseError(error.TimeoutOverLimit, json);
    }
}

test "config: the whole timeouts block is optional, and every default is usable" {
    // A config that names none of them is the out-of-box shape (§5), the
    // same argument `limits` already makes: an operator opts into tuning,
    // never into a working config.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}}}
    );
    try std.testing.expectEqual(constants.connect_ms_default, parsed.connect_timeout_ms);
    try std.testing.expectEqual(constants.idle_ms_default, parsed.idle_timeout_ms);
    try std.testing.expectEqual(constants.health_interval_ms_default, parsed.health_interval_ms);
    // The three caps default off, the drain one included: nginx, HAProxy
    // and Caddy all wait indefinitely, and the supervisor that sent the
    // signal owns the upper bound.
    try std.testing.expectEqual(@as(u32, 0), parsed.drain_deadline_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
    try std.testing.expectEqual(@as(u32, 0), parsed.request_timeout_ms);
}

test "config: a zero drain deadline is no cap, but a zero connect or idle is still a mistake" {
    // The asymmetry is the point: 0 disables a *cap*, and there is no
    // sense in which a 0 ms dial or idle budget is a policy rather than a
    // configuration error, so those two keep rejecting it.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"drain_deadline_ms":0}}
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.drain_deadline_ms);
    }
    const rejected = [_][]const u8{
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":0}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"idle_ms":0}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"health_interval_ms":0}}
        ,
    };
    for (rejected) |json| {
        try expectParseError(error.TimeoutZero, json);
    }
}

test "config: the dial budget must sit below the idle one" {
    // The §4 handoff, stated as a load-time rule: the first deadline is
    // armed at `connect_ms` and the dial's completion re-stores it to
    // `idle_ms`, but the armed timer never moves earlier — so an idle
    // budget that does not exceed the dial budget fires late rather than
    // shortening. Equal is rejected too: it is the boundary where the
    // handoff already changes nothing.
    const rejected = [_][]const u8{
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":90000,"idle_ms":60000}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":5000,"idle_ms":5000}}
        ,
        // One field is enough to break the pair: a dial budget raised past
        // the *defaulted* idle one is the shape an operator reaches for
        // first, and it reads as tuning one number rather than as ordering
        // two.
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":90000}}
        ,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"idle_ms":1000}}
        ,
    };
    for (rejected) |json| {
        try expectParseError(error.TimeoutOrderInvalid, json);
    }
    // A single millisecond of ordering is all the rule asks for, and the
    // shipped defaults clear it by an order of magnitude.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":5000,"idle_ms":5001}}
    );
    try std.testing.expectEqual(@as(u32, 5000), parsed.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 5001), parsed.idle_timeout_ms);
    try std.testing.expect(constants.connect_ms_default < constants.idle_ms_default);
}

test "config: max_lifetime_ms accepts zero (a legal zero timeout) and real values" {
    // Explicit 0 is legal — it is *not* a TimeoutZero, unlike the dial
    // and idle budgets (§6).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,"max_lifetime_ms":0}}
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.max_lifetime_ms);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,"max_lifetime_ms":1800000}}
        );
        try std.testing.expectEqual(@as(u32, 1_800_000), parsed.max_lifetime_ms);
    }
}

test "config: the loop watchdog is absent-is-off, floored, and capped" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{
    ;
    const tail = "}}";
    // Absent is off, and off is the `0` the resolved config spells it
    // with — the whole reason the JSON side is optional instead (#311).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expectEqual(@as(u32, 0), parsed.loop_watchdog_ms);
    }
    // Present and at the floor: the smallest bound the mechanism can
    // express, since `alarm(2)` counts whole seconds and the tick that
    // refreshes it takes half.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ std.fmt.comptimePrint(
                "\"loop_watchdog_ms\":{d}",
                .{constants.loop_watchdog_ms_min},
            ) ++ tail,
        );
        try std.testing.expectEqual(constants.loop_watchdog_ms_min, parsed.loop_watchdog_ms);
    }
    // One millisecond under it is refused rather than rounded. A bound
    // the seam would not arm is a backstop an operator believes they have
    // and do not, which is worse than the hang it was meant to catch.
    try expectParseError(error.LoopWatchdogTooShort, head ++ std.fmt.comptimePrint(
        "\"loop_watchdog_ms\":{d}",
        .{constants.loop_watchdog_ms_min - 1},
    ) ++ tail);
    // Zero is refused by the same rule, and deliberately: it is the
    // spelling of "off" everywhere else in this block, and accepting it
    // here would make one key mean off two ways.
    try expectParseError(error.LoopWatchdogTooShort, head ++ "\"loop_watchdog_ms\":0" ++ tail);
    // And the shared units-mistake ceiling still applies.
    try expectParseError(error.TimeoutOverLimit, head ++ std.fmt.comptimePrint(
        "\"loop_watchdog_ms\":{d}",
        .{constants.timeout_ms_max + 1},
    ) ++ tail);
}

test "config: a listener's body key is what names its protocol" {
    // Each tag resolves to its `Protocol`, and that is now the whole job
    // of this test: there is no defaulted spelling left to disagree with
    // an explicit one (#305), and a listener naming neither body or both
    // is `ListenerHttpOrL4`, covered where the fork itself is tested.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(Config.Listener.Protocol.l4, parsed.listeners[0].protocol);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(Config.Listener.Protocol.http, parsed.listeners[0].protocol);
    }
}

test "config: a header route sorts between its host and its prefix" {
    // #302's central question, answered: host, then header, then prefix.
    // The table is written in the least helpful order on purpose — config
    // order must not be able to change an answer.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"routes":[
        \\   {"prefix":"/","cluster":"web"},
        \\   {"header":{"name":"X-Canary","present":true},"prefix":"/","cluster":"canary"},
        \\   {"host":"api.example.com","prefix":"/","cluster":"api"},
        \\   {"host":"api.example.com","header":{"name":"X-Canary","present":true},
        \\    "prefix":"/","cluster":"api-canary"}]}}],
        \\ "clusters":{"web":{"endpoints":["127.0.0.1:2"]},
        \\   "canary":{"endpoints":["127.0.0.1:3"]},
        \\   "api":{"endpoints":["127.0.0.1:4"]},
        \\   "api-canary":{"endpoints":["127.0.0.1:5"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const routes = parsed.listeners[0].routes;
    try std.testing.expectEqual(@as(usize, 4), routes.len);
    // Host group first, and within it the header rule ahead of the bare
    // one; then the any-host group repeating the same shape.
    try std.testing.expect(routes[0].host != null and routes[0].header != null);
    try std.testing.expect(routes[1].host != null and routes[1].header == null);
    try std.testing.expect(routes[2].host == null and routes[2].header != null);
    try std.testing.expect(routes[3].host == null and routes[3].header == null);
}

test "config: two header rules of equal specificity keep config order" {
    // The one tie #302 leaves. Same host, same prefix, different headers:
    // distinct rules, equally specific by every tier, and a request
    // carrying both matches both. The earlier one wins — stated here
    // because it is a promise the docs make, and because relying on
    // `std.mem.sort` being stable would make it std's promise instead.
    const tail = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}," ++
        "\"b\":{\"endpoints\":[\"127.0.0.1:3\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"routes\":[";
    const canary = "{\"header\":{\"name\":\"X-Canary\",\"present\":true}," ++
        "\"prefix\":\"/\",\"cluster\":\"a\"}";
    const beta = "{\"header\":{\"name\":\"X-Beta\",\"present\":true}," ++
        "\"prefix\":\"/\",\"cluster\":\"b\"}";
    const catch_all = "{\"prefix\":\"/\",\"cluster\":\"a\"}";

    // Written canary-first: the canary rule is tried first.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ canary ++ "," ++ beta ++ "," ++ catch_all ++ "]}}]," ++ tail,
        );
        const routes = parsed.listeners[0].routes;
        try std.testing.expectEqualStrings("X-Canary", routes[0].header.?.name);
        try std.testing.expectEqualStrings("X-Beta", routes[1].header.?.name);
        try std.testing.expect(routes[2].header == null);
    }
    // Written beta-first: the other way round, and nothing else moves.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ beta ++ "," ++ canary ++ "," ++ catch_all ++ "]}}]," ++ tail,
        );
        const routes = parsed.listeners[0].routes;
        try std.testing.expectEqualStrings("X-Beta", routes[0].header.?.name);
        try std.testing.expectEqualStrings("X-Canary", routes[1].header.?.name);
        try std.testing.expect(routes[2].header == null);
    }
    // And the catch-all sorts last from either spelling — the tiers still
    // decide everything they can separate, whatever the order.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ catch_all ++ "," ++ beta ++ "," ++ canary ++ "]}}]," ++ tail,
        );
        const routes = parsed.listeners[0].routes;
        try std.testing.expect(routes[0].header != null);
        try std.testing.expect(routes[1].header != null);
        try std.testing.expect(routes[2].header == null);
    }
}

test "config: a route header is a bounded predicate, held to the filter's rules" {
    const tail = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"routes\":[";

    // Exactly one kind, and `present: false` is not a predicate.
    try expectParseError(
        error.RouteHeaderMatchKind,
        head ++ "{\"header\":{\"name\":\"X-C\"},\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    try expectParseError(
        error.RouteHeaderMatchKind,
        head ++ "{\"header\":{\"name\":\"X-C\",\"present\":true,\"equals\":\"v\"}," ++
            "\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    try expectParseError(
        error.RouteHeaderMatchKind,
        head ++ "{\"header\":{\"name\":\"X-C\",\"present\":false}," ++
            "\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // `contains` is not a route predicate at all — the DTO has no such
    // field, so the strict parser refuses it rather than a rule doing so.
    try expectParseError(
        error.UnknownField,
        head ++ "{\"header\":{\"name\":\"X-C\",\"contains\":\"v\"}," ++
            "\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // A name is a token, on the filter table's rule.
    try expectParseError(
        error.FilterHeaderNameInvalid,
        head ++ "{\"header\":{\"name\":\"X Canary\",\"present\":true}," ++
            "\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // But a proxy-managed name is *matchable*, exactly as it is in a
    // filter's match: only an edit target is reserved, because rewriting
    // one smuggles a framing change past the render. Reading one to pick
    // a backend changes nothing — pinned here so the two tables cannot
    // drift on what a header name may be.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        _ = try expectParseOk(&arena_state, head ++
            "{\"header\":{\"name\":\"Content-Length\",\"present\":true}," ++
            "\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail);
    }
}

test "config: the header is part of what makes a route distinct" {
    const tail = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"routes\":[";

    // Same host and prefix, different headers: two rules, not a duplicate
    // — which is the whole point of the dimension.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++
            "{\"header\":{\"name\":\"X-C\",\"equals\":\"v1\"},\"prefix\":\"/\",\"cluster\":\"a\"}," ++
            "{\"header\":{\"name\":\"X-C\",\"equals\":\"v2\"},\"prefix\":\"/\",\"cluster\":\"a\"}," ++
            "{\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail);
        try std.testing.expectEqual(@as(usize, 3), parsed.listeners[0].routes.len);
    }
    // Agreeing on all three is the same rule written twice.
    try expectParseError(error.RouteDuplicate, head ++
        "{\"header\":{\"name\":\"X-C\",\"equals\":\"v1\"},\"prefix\":\"/\",\"cluster\":\"a\"}," ++
        "{\"header\":{\"name\":\"x-c\",\"equals\":\"v1\"},\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail);
    // And a header rule does not collide with the bare rule it varies.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++
            "{\"header\":{\"name\":\"X-C\",\"present\":true},\"prefix\":\"/\",\"cluster\":\"a\"}," ++
            "{\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ tail);
        try std.testing.expectEqual(@as(usize, 2), parsed.listeners[0].routes.len);
    }
}

test "config: l4 sni routes resolve, named before any-name" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"routes":[
        \\   {"cluster":"fallback"},
        \\   {"sni":"api.example.com","cluster":"api"},
        \\   {"sni":"db.example.com","cluster":"db"}]}}],
        \\ "clusters":{"fallback":{"endpoints":["127.0.0.1:2"]},
        \\   "api":{"endpoints":["127.0.0.1:3"]},
        \\   "db":{"endpoints":["127.0.0.1:4"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const routes = parsed.listeners[0].sni_routes;
    try std.testing.expectEqual(@as(usize, 3), routes.len);
    // Named first whatever the config order, so the scan's first match is
    // the most specific rule — the any-name route can only be reached by
    // a name no rule claimed.
    try std.testing.expect(routes[0].server_name != null);
    try std.testing.expect(routes[1].server_name != null);
    try std.testing.expect(routes[2].server_name == null);
    // And the listener still admits under *a* cluster before any byte is
    // read: the any-name route's, since this config declared one.
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners[0].routes.len);
}

test "config: an l4 listener without sni routes carries no table" {
    // The absence is what says the peek phase does not run, so it is
    // asserted rather than assumed: every config written before #298
    // keeps relaying without reading a byte first.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try std.testing.expectEqual(@as(usize, 0), parsed.listeners[0].sni_routes.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.listeners[0].routes.len);
}

test "config: the l4 sni table is held to §7's own rules" {
    const tail = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"routes\":[";

    // Neither `cluster` nor `routes`, and both: the http body's fork,
    // now the l4 body's too.
    try expectParseError(
        error.ListenerClusterOrRoutes,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{}}]," ++ tail,
    );
    try expectParseError(
        error.ListenerClusterOrRoutes,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
            "\"routes\":[{\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // A name is held to the canonical form §7's `host` routes use — the
    // same rule, so one name means one thing in both tables.
    try expectParseError(
        error.RouteHostNotCanonical,
        head ++ "{\"sni\":\"API.Example.com\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    try expectParseError(
        error.RouteHostNotCanonical,
        head ++ "{\"sni\":\"api.example.com:443\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // `*` is reserved, so a wildcard can arrive after the freeze without
    // changing what a 1.0.0 config meant by it (#400).
    try expectParseError(
        error.RouteHostWildcard,
        head ++ "{\"sni\":\"*.example.com\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // Two rules for one name is two answers to one question.
    try expectParseError(
        error.RouteDuplicate,
        head ++ "{\"sni\":\"a.example.com\",\"cluster\":\"a\"}," ++
            "{\"sni\":\"a.example.com\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // And two any-name routes are the same mistake spelled differently.
    try expectParseError(
        error.RouteDuplicate,
        head ++ "{\"cluster\":\"a\"},{\"cluster\":\"a\"}]}}]," ++ tail,
    );
    try expectParseError(
        error.ClusterUnknown,
        head ++ "{\"sni\":\"a.example.com\",\"cluster\":\"ghost\"}]}}]," ++ tail,
    );
    // RFC 6066 §3 forbids an address in `server_name`, so a route naming
    // one could never match anything — a dead rule, refused rather than
    // loaded. A `Host` header may legitimately be a literal, which is why
    // this is the one check the two tables do not share.
    try expectParseError(
        error.RouteSniIsAddress,
        head ++ "{\"sni\":\"1.2.3.4\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    try expectParseError(
        error.RouteSniIsAddress,
        head ++ "{\"sni\":\"[::1]\",\"cluster\":\"a\"}]}}]," ++ tail,
    );
    // A name that merely *contains* digits is a name.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        _ = try expectParseOk(
            &arena_state,
            head ++ "{\"sni\":\"v2.example.com\",\"cluster\":\"a\"}]}}]," ++ tail,
        );
    }
}

test "config: an l4 route cannot reach a request-keyed hash cluster" {
    // `HashKey`'s own rule: `header` and `cookie` read the parsed
    // request, and an l4 relay parses none. The admitted cluster was
    // always held to it; every cluster an SNI table can reach has to be
    // too, or a named route would resolve to a pick the relay cannot
    // compute (#298).
    const tail = "\"clusters\":{\"plain\":{\"endpoints\":[\"127.0.0.1:2\"]}," ++
        "\"keyed\":{\"endpoints\":[\"127.0.0.1:3\"]," ++
        "\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"s\"}}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    // The keyed cluster reached by a *named* route, with the any-name
    // route pointing somewhere harmless — the shape that slipped past
    // when only the admitted cluster was checked.
    try expectParseError(
        error.ListenerL4RequestKeyedHash,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"routes\":[" ++
            "{\"sni\":\"a.example.com\",\"cluster\":\"keyed\"}," ++
            "{\"cluster\":\"plain\"}]}}]," ++ tail,
    );
    // And still refused when it is the any-name route's own cluster.
    try expectParseError(
        error.ListenerL4RequestKeyedHash,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"routes\":[" ++
            "{\"cluster\":\"keyed\"}]}}]," ++ tail,
    );
}

test "config: an sni table reaches only clusters an l4 relay can speak to" {
    // §7's protocol rule on #298's terms: an l4 listener relays bytes, so
    // an HTTP/2 origin would be sent whatever the client wrote, and an
    // HTTPS one's `tls` block (the name and CA this proxy verifies
    // against) would never be used. The admitted cluster was always held
    // to that; a named route reaches clusters it never names, and every
    // one of them has to be held to it too.
    const routes = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"routes\":[" ++
        "{\"sni\":\"a.example.com\",\"cluster\":\"origin\"}," ++
        "{\"cluster\":\"plain\"}]}}],";
    const plain = "\"plain\":{\"endpoints\":[\"127.0.0.1:2\"]}";
    const timeouts = "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    try expectParseError(error.ClusterH2cOnL4Listener, routes ++ "\"clusters\":{" ++ plain ++
        ",\"origin\":{\"endpoints\":[\"127.0.0.1:3\"],\"protocol\":\"h2c\"}}," ++ timeouts);
    try expectH2ParseError(error.ClusterTlsOnL4Listener, routes ++ "\"clusters\":{" ++ plain ++
        ",\"origin\":{\"endpoints\":[\"127.0.0.1:3\"]," ++
        "\"tls\":{\"server_name\":\"origin.zoxy.test\",\"ca\":{\"path\":\"/ca.pem\"}}}}," ++ timeouts);
    try expectH2ParseError(error.ClusterH2cOnL4Listener, routes ++ "\"clusters\":{" ++ plain ++
        ",\"origin\":{\"endpoints\":[\"127.0.0.1:3\"],\"protocol\":\"h2\"," ++
        "\"tls\":{\"server_name\":\"origin.zoxy.test\",\"ca\":{\"path\":\"/ca.pem\"}}}}," ++ timeouts);
}

test "config: sni routing and terminating this listener are different proxies" {
    // Routing by name reads the client's hello and relays it on; a
    // terminating listener consumed that hello during its own handshake,
    // so there is nothing left to read. The config states one (§6).
    try expectParseError(error.ListenerTlsWithSniRoutes,
        \\{"listeners":[{"bind":"127.0.0.1:1",
        \\   "tls":{"cert":"/c.pem","key":"/k.pem"},
        \\   "l4":{"routes":[{"sni":"a.example.com","cluster":"a"}]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: sni routing needs a relay buffer that can stage a hello" {
    // A half too narrow would route the clients whose hellos happen to be
    // short and drop the ones offering post-quantum key shares — one
    // config, two outcomes. Refused at load instead (§5).
    try expectParseError(error.LimitRelayBufferUnderSniRouting,
        \\{"listeners":[{"bind":"127.0.0.1:1",
        \\   "l4":{"routes":[{"sni":"a.example.com","cluster":"a"}]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "limits":{"relay_buffer_bytes":4096},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // The same narrow buffer is fine on a listener that does not peek.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    _ = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "limits":{"relay_buffer_bytes":4096},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: a relay buffer past one record is refused only with TLS on it" {
    // `transformOut` encrypts a whole chunk into one record, so a
    // terminating listener cannot carry a buffer wider than
    // `tls_app_chunk_bytes` — the ceiling above it exists for the
    // plaintext deployments that can use it (§4, §6).
    try expectParseError(error.LimitRelayBufferOverTlsRecord,
        \\{"listeners":[{"bind":"127.0.0.1:1",
        \\   "tls":{"cert":"/c.pem","key":"/k.pem"},
        \\   "http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "limits":{"relay_buffer_bytes":32768},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // The same width is what the ceiling is for, with no listener
    // terminating: this is the shape the large-body band runs.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const config = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "limits":{"relay_buffer_bytes":32768},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try std.testing.expectEqual(@as(u32, 32768), config.limits.relay_buffer_bytes);
}

test "config: explicit routes resolve, sorted longest-prefix-first" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"routes":[
        \\   {"prefix":"/","cluster":"root"},
        \\   {"prefix":"/api/v2","cluster":"v2"},
        \\   {"prefix":"/api","cluster":"api"}]}}],
        \\ "clusters":{"root":{"endpoints":["127.0.0.1:2"]},
        \\   "api":{"endpoints":["127.0.0.1:3"]},
        \\   "v2":{"endpoints":["127.0.0.1:4"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
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
        router.route(routes, null, "/api/v2/x", &.{}),
    );
    try std.testing.expectEqual(
        @as(?u16, routes[2].cluster_index),
        router.route(routes, null, "/elsewhere", &.{}),
    );
}

test "config: routing schema rejects malformed tables" {
    const base_clusters =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Neither cluster nor routes.
    try expectParseError(error.ListenerClusterOrRoutes, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{}}]," ++ base_clusters);
    // Both cluster and routes.
    try expectParseError(error.ListenerClusterOrRoutes, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // Routes on an l4 listener: there is no path to match, and now no
    // field to ask for one in — the shape refuses what a rule used to
    // (#305), so the verdict is the strict parser's.
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{" ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // And a listener that names no protocol body at all.
    try expectParseError(error.ListenerHttpOrL4, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"}]," ++ base_clusters);
    try expectParseError(error.ListenerHttpOrL4, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"," ++
        "\"http\":{\"cluster\":\"a\"},\"l4\":{\"cluster\":\"a\"}}]," ++ base_clusters);
    // Empty routes table.
    try expectParseError(error.RoutesEmpty, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[]}}]," ++ base_clusters);
    // A non-canonical prefix (dot-segment) — would mismatch at request time.
    try expectParseError(error.RoutePrefixNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"prefix\":\"/a/../b\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // A prefix without a leading slash.
    try expectParseError(error.RoutePrefixNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"prefix\":\"api\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // Duplicate (host, prefix) — same any-host prefix twice.
    try expectParseError(error.RouteDuplicate, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"prefix\":\"/x\",\"cluster\":\"a\"}," ++
        "{\"prefix\":\"/x\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // A non-canonical host (uppercase) — would mismatch at request time.
    try expectParseError(error.RouteHostNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"host\":\"API.Example.com\",\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // A host carrying a port — the port is not part of the routing name.
    try expectParseError(error.RouteHostNotCanonical, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"host\":\"api.example.com:8080\",\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // A wildcard, anywhere in the name: `*` is reserved, not a literal
    // (#400). Filter hosts and redirect hosts share this validator.
    try expectParseError(error.RouteHostWildcard, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"host\":\"*.example.com\",\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    try expectParseError(error.RouteHostWildcard, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"host\":\"api.*\",\"prefix\":\"/\",\"cluster\":\"a\"}]}}]," ++ base_clusters);
    // An unknown cluster named by a route.
    try expectParseError(error.ClusterUnknown, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"routes\":[{\"prefix\":\"/\",\"cluster\":\"ghost\"}]}}]," ++ base_clusters);
}

test "config: host routes resolve, host-specific sorted before any-host" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"routes":[
        \\   {"prefix":"/","cluster":"root"},
        \\   {"host":"api.example.com","prefix":"/","cluster":"api"},
        \\   {"host":"api.example.com","prefix":"/v2","cluster":"v2"}]}}],
        \\ "clusters":{"root":{"endpoints":["127.0.0.1:2"]},
        \\   "api":{"endpoints":["127.0.0.1:3"]},
        \\   "v2":{"endpoints":["127.0.0.1:4"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
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
        router.route(routes, "api.example.com", "/other", &.{}),
    );
    try std.testing.expectEqual(
        @as(?u16, routes[2].cluster_index),
        router.route(routes, "other.example.com", "/v2", &.{}),
    );
}

test "config: filters compile into rules with matches and actions" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a","request_filters":[
        \\   {"match":{"method":["GET","POST"],"path_prefix":"/admin",
        \\             "headers":[{"name":"X-Env","equals":"prod"}]},
        \\    "actions":[{"reject":403}]},
        \\   {"match":{"host":"api.example"},
        \\    "actions":[{"header_set":{"name":"X-Via","value":"zoxy"}},
        \\               {"rewrite_prefix":{"from":"/old","to":"/new"}}]}]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const filters = parsed.listeners[0].request_filters;
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

test "config: an allow rule compiles into the terminal that answers nothing" {
    // The #331 allowlist, in the spelling the README carries: the rule
    // that admits, then the reject the admitted range never reaches.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a","request_filters":[
        \\   {"match":{"path_prefix":"/admin","client":["203.0.113.0/24"]},
        \\    "actions":[{"allow":true}]},
        \\   {"match":{"path_prefix":"/admin"},"actions":[{"reject":403}]}]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const rules = parsed.listeners[0].request_filters;
    try std.testing.expectEqual(@as(usize, 2), rules.len);
    try std.testing.expectEqual(@as(usize, 1), rules[0].actions.len);
    try std.testing.expectEqual(filter.Action.allow, rules[0].actions[0]);
    try std.testing.expectEqual(@as(u8, 24), rules[0].match.clients[0].prefix_len);
    try std.testing.expectEqual(@as(u16, 403), rules[1].actions[0].reject);
    // The compiled table is what the interpreter reads, so assert the
    // verdict rather than only the shape: the named range forwards, and
    // everyone else is refused by the rule beneath.
    const admitted = std.Io.net.IpAddress.parseLiteral("203.0.113.7:40000") catch unreachable;
    const stranger = std.Io.net.IpAddress.parseLiteral("198.51.100.7:40000") catch unreachable;
    try std.testing.expectEqual(@as(?filter.Verdict, null), filter.firstVerdict(rules, .{
        .method = .get,
        .host = null,
        .path = "/admin",
        .headers = &.{},
        .client = &admitted,
    }));
    try std.testing.expectEqual(@as(u16, 403), filter.firstVerdict(rules, .{
        .method = .get,
        .host = null,
        .path = "/admin",
        .headers = &.{},
        .client = &stranger,
    }).?.reject);
}

test "config: filter schema rejects malformed rules" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"request_filters\":[";
    // An l4 listener has no field to carry filters, populated or
    // vacuously empty: the key it would need is not in the `l4` body, so
    // the strict parser refuses it before any rule could (#305).
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
        "\"request_filters\":[{\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
        "\"request_filters\":[]}}]," ++ tail);
    // A rule with no actions.
    try expectParseError(error.FilterActionsEmpty, head ++ "{\"actions\":[]}]}}]," ++ tail);
    // An action object with no kind set.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{}]}]}}]," ++ tail);
    // An action object with two kinds set.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{\"reject\":403,\"header_remove\":\"X\"}]}]}}]," ++ tail);
    // `allow` carries a value only because this shape needs one, and
    // `true` is the whole of it: `false` names an action and unsays it
    // (#331), the way `present: false` names no predicate.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{\"allow\":false}]}]}}]," ++ tail);
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{\"allow\":true,\"reject\":403}]}]}}]," ++ tail);
    // A reject status outside the policy set.
    try expectParseError(error.FilterRejectStatus, head ++ "{\"actions\":[{\"reject\":503}]}]}}]," ++ tail);
    // An unknown / lowercase method token.
    try expectParseError(error.FilterMethodUnknown, head ++ "{\"match\":{\"method\":[\"get\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A header match with no predicate kind.
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\"}]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A `contains` predicate with an empty needle: it would match every
    // present header (a degenerate `present`), so it is rejected.
    try expectParseError(error.FilterHeaderContainsEmpty, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\",\"contains\":\"\"}]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A non-canonical match path prefix.
    try expectParseError(error.RoutePrefixNotCanonical, head ++ "{\"match\":{\"path_prefix\":\"/a/../b\"},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A header edit with an invalid header name.
    try expectParseError(error.FilterHeaderNameInvalid, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"Bad Name\",\"value\":\"v\"}}]}]}}]," ++ tail);
    // A header value carrying CRLF — a smuggling vector when rendered.
    try expectParseError(error.FilterHeaderValueInvalid, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"X\",\"value\":\"a\\r\\nInjected: 1\"}}]}]}}]," ++ tail);
    // "present: false" is not a predicate.
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"X\",\"present\":false}]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A rewrite whose target is not canonical.
    try expectParseError(error.RoutePrefixNotCanonical, head ++ "{\"actions\":[{\"rewrite_prefix\":{\"from\":\"/a\",\"to\":\"/b/../c\"}}]}]}}]," ++ tail);
    // A header edit may not name a proxy-managed header — case-insensitively.
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"Host\",\"value\":\"evil\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_remove\":\"content-length\"}]}]}}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_add\":{\"name\":\"Connection\",\"value\":\"close\"}}]}]}}]," ++ tail);
    // The two headers this proxy writes on the client's behalf: a
    // constant here would restate a value it computes per request (§7,
    // #240).
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"X-Forwarded-For\",\"value\":\"1.2.3.4\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"max-forwards\",\"value\":\"9\"}}]}]}}]," ++ tail);
    // A matched header predicate may still name a managed header (read-only).
    try expectParseError(error.FilterHeaderMatchKind, head ++ "{\"match\":{\"headers\":[{\"name\":\"Host\"}]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
}

test "config: a filter set over the header-edit budget is rejected" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // header_edits_max+1 header edits spread one-per-rule: neither the
    // rule count nor a rule's action count is bounded any more, so the
    // whole-table total is the only thing that caps — which is the point,
    // since that total is what the renderer's fixed buffer must hold.
    const rules = comptime blk: {
        var s: []const u8 = "";
        var edit: u16 = 0;
        while (edit < constants.header_edits_max + 1) : (edit += 1) {
            if (edit != 0) s = s ++ ",";
            s = s ++ "{\"actions\":[{\"header_remove\":\"X-Drop\"}]}";
        }
        break :blk s;
    };
    const json = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"cluster\":\"a\",\"request_filters\":[" ++ rules ++ "]}}]," ++ tail;
    try expectParseError(error.FilterHeaderEditsOverLimit, json);
}

test "config: redirect actions compile in both target forms" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a","request_filters":[
        \\   {"match":{"host":"www.example.com"},
        \\    "actions":[{"redirect":{"status":308,"scheme":"https","host":"example.com"}}]},
        \\   {"actions":[{"redirect":{"scheme":"https"}}]},
        \\   {"match":{"path_prefix":"/gone"},
        \\    "actions":[{"redirect":{"status":302,"location":"https://status.example.com/"}}]}
        \\ ]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const rules = parsed.listeners[0].request_filters;
    const canonical = rules[0].actions[0].redirect;
    try std.testing.expectEqual(@as(u16, 308), canonical.status);
    try std.testing.expectEqual(filter.Redirect.Scheme.https, canonical.target.composed.scheme);
    try std.testing.expectEqualStrings("example.com", canonical.target.composed.host.?);
    // Scheme-only composed, and the status defaults to the permanent one.
    const to_https = rules[1].actions[0].redirect;
    try std.testing.expectEqual(@as(u16, 301), to_https.status);
    try std.testing.expectEqual(@as(?[]const u8, null), to_https.target.composed.host);
    const fixed = rules[2].actions[0].redirect;
    try std.testing.expectEqual(@as(u16, 302), fixed.status);
    try std.testing.expectEqualStrings("https://status.example.com/", fixed.target.location);
}

test "config: redirect validation has its own errors" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"request_filters\":[";
    // Outside the closed set — 303 changes the method's meaning and has
    // no proxy semantics here.
    try expectParseError(error.FilterRedirectStatus, head ++ "{\"actions\":[{\"redirect\":{\"status\":303,\"scheme\":\"https\"}}]}]}}]," ++ tail);
    // Neither target form, both at once, half a composed one, and an
    // empty literal: each is FilterRedirectTarget.
    try expectParseError(error.FilterRedirectTarget, head ++ "{\"actions\":[{\"redirect\":{\"status\":301}}]}]}}]," ++ tail);
    try expectParseError(error.FilterRedirectTarget, head ++ "{\"actions\":[{\"redirect\":{\"location\":\"https://x/\",\"scheme\":\"https\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterRedirectTarget, head ++ "{\"actions\":[{\"redirect\":{\"host\":\"example.com\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterRedirectTarget, head ++ "{\"actions\":[{\"redirect\":{\"location\":\"\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterRedirectSchemeUnknown, head ++ "{\"actions\":[{\"redirect\":{\"scheme\":\"ftp\"}}]}]}}]," ++ tail);
    // The composed host is a route host: canonical or refused.
    try expectParseError(error.RouteHostNotCanonical, head ++ "{\"actions\":[{\"redirect\":{\"scheme\":\"https\",\"host\":\"WWW.Example.com\"}}]}]}}]," ++ tail);
    try expectParseError(error.RouteHostWildcard, head ++ "{\"actions\":[{\"redirect\":{\"scheme\":\"https\",\"host\":\"*.example.com\"}}]}]}}]," ++ tail);
    // So is a filter's `match.host`, on the same reserved `*` (#400).
    try expectParseError(error.RouteHostWildcard, head ++ "{\"match\":{\"host\":\"*.example.com\"},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A literal Location is a header value the render emits verbatim:
    // injection-safety is proven at load.
    try expectParseError(error.FilterHeaderValueInvalid, head ++ "{\"actions\":[{\"redirect\":{\"location\":\"https://x/\\r\\nSet-Cookie: a\"}}]}]}}]," ++ tail);
    // Two kinds is still a kind error; a redirect on the way out is not
    // a field a response action has (#305), so the parser refuses it.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{\"redirect\":{\"scheme\":\"https\"},\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
        "\"response_filters\":[{\"actions\":[{\"redirect\":{\"scheme\":\"https\"}}]}]}}]," ++ tail);
}

test "config: client CIDR predicates compile with their prefixes" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a","request_filters":[
        \\   {"match":{"path_prefix":"/admin","client":["10.0.0.0/8","192.168.1.0/24","2001:db8::/32"]},
        \\    "actions":[{"reject":403}]},
        \\   {"match":{"client":["0.0.0.0/0","::/0"]},
        \\    "actions":[{"header_set":{"name":"X-Any","value":"1"}}]}
        \\ ]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const clients = parsed.listeners[0].request_filters[0].match.clients;
    try std.testing.expectEqual(@as(usize, 3), clients.len);
    try std.testing.expectEqual(@as(u8, 8), clients[0].prefix_len);
    try std.testing.expectEqual(@as(u8, 24), clients[1].prefix_len);
    try std.testing.expectEqual(@as(u8, 32), clients[2].prefix_len);
    // The /0 edge parses in both families: an explicit everyone, whose
    // host-bits rule still demands an all-zero address.
    const any = parsed.listeners[0].request_filters[1].match.clients;
    try std.testing.expectEqual(@as(u8, 0), any[0].prefix_len);
    try std.testing.expectEqual(@as(u8, 0), any[1].prefix_len);
    // The compiled prefixes admit and refuse — proving address bytes
    // survived the parse, not only the lengths.
    const office = std.Io.net.IpAddress.parseLiteral("10.9.8.7:1") catch unreachable;
    const stranger = std.Io.net.IpAddress.parseLiteral("11.0.0.1:1") catch unreachable;
    try std.testing.expect(clients[0].contains(&office));
    try std.testing.expect(!clients[0].contains(&stranger));
}

test "config: client CIDR validation has its own errors" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"request_filters\":[";
    // An explicitly empty list: absence already says "any client".
    try expectParseError(error.FilterClientEmpty, head ++ "{\"match\":{\"client\":[]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // A bare address has no single meaning across families (an exact
    // IPv4 host is /32, an exact IPv6 client is its /64): the prefix is
    // mandatory.
    try expectParseError(error.FilterClientCidrInvalid, head ++ "{\"match\":{\"client\":[\"10.0.0.1\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.FilterClientCidrInvalid, head ++ "{\"match\":{\"client\":[\"office/8\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.FilterClientPrefixInvalid, head ++ "{\"match\":{\"client\":[\"10.0.0.0/\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.FilterClientPrefixInvalid, head ++ "{\"match\":{\"client\":[\"10.0.0.0/eight\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // Past the family's bound: /32 for v4; /64 for v6, where the low
    // half is interface identity that rotates (RFC 8981).
    try expectParseError(error.FilterClientPrefixTooNarrow, head ++ "{\"match\":{\"client\":[\"10.0.0.0/33\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.FilterClientPrefixTooNarrow, head ++ "{\"match\":{\"client\":[\"2001:db8::/65\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    // Host bits set past the prefix: a typo for one of two different
    // ranges, and the loader cannot know which.
    try expectParseError(error.FilterClientCidrHostBits, head ++ "{\"match\":{\"client\":[\"10.0.0.1/8\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
    try expectParseError(error.FilterClientCidrHostBits, head ++ "{\"match\":{\"client\":[\"2001:db8::1/48\"]},\"actions\":[{\"reject\":403}]}]}}]," ++ tail);
}

test "config: response filters compile into rules with matches and edits" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a","response_filters":[
        \\   {"actions":[{"header_remove":"Server"},
        \\               {"header_set":{"name":"Strict-Transport-Security","value":"max-age=63072000"}}]},
        \\   {"match":{"status_class":"5xx"},
        \\    "actions":[{"header_set":{"name":"Retry-After","value":"1"}}]},
        \\   {"match":{"status":[301,302],"headers":[{"name":"Location","contains":"http:"}]},
        \\    "actions":[{"header_add":{"name":"X-Insecure-Redirect","value":"1"}}]}
        \\ ]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const rules = parsed.listeners[0].response_filters;
    try std.testing.expectEqual(@as(usize, 3), rules.len);
    // The unconditional rule: an all-empty match, edits flattened to the
    // renderer's contract in action order — no `Action` union on the way
    // out, because there is no reject to interleave.
    try std.testing.expectEqual(@as(usize, 0), rules[0].match.statuses.len);
    try std.testing.expectEqual(@as(?u8, null), rules[0].match.status_class);
    try std.testing.expectEqual(@as(usize, 2), rules[0].edits.len);
    try std.testing.expectEqual(filter.AppliedHeaderEdit.Kind.remove, rules[0].edits[0].kind);
    try std.testing.expectEqualStrings("Server", rules[0].edits[0].name);
    try std.testing.expectEqual(filter.AppliedHeaderEdit.Kind.set, rules[0].edits[1].kind);
    // The class spelling compiles to its digit.
    try std.testing.expectEqual(@as(?u8, 5), rules[1].match.status_class);
    // Exact statuses and response-header predicates ride the request
    // side's own vocabularies.
    try std.testing.expectEqualSlices(u16, &.{ 301, 302 }, rules[2].match.statuses);
    try std.testing.expectEqual(filter.HeaderMatch.Kind.contains, rules[2].match.headers[0].kind);
    try std.testing.expectEqual(filter.AppliedHeaderEdit.Kind.add, rules[2].edits[0].kind);
    // The request-side table stays independent: none was configured.
    try std.testing.expectEqual(@as(usize, 0), parsed.listeners[0].request_filters.len);
}

test "config: response filter schema rejects what has no meaning on the way out" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"response_filters\":[";
    // The request-side actions are not fields on a response action at
    // all (#305), so naming one is the strict parser's refusal rather
    // than four rules this table used to carry — and the schema states
    // the same thing, where before it could only be discovered at load.
    inline for (.{
        "{\"reject\":403}",
        "{\"allow\":true}",
        "{\"rewrite_prefix\":{\"from\":\"/a\",\"to\":\"/b\"}}",
        "{\"redirect\":{\"status\":301,\"location\":\"/x\"}}",
        "{\"respond\":{\"status\":200,\"body\":\"b\"}}",
    }) |action| {
        try expectParseError(
            error.UnknownField,
            head ++ "{\"actions\":[" ++ action ++ "]}]}}]," ++ tail,
        );
    }
    // A two-kind action is still a kind error, never a misleading arm one.
    try expectParseError(error.FilterActionKind, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"X\",\"value\":\"y\"},\"header_remove\":\"X\"}]}]}}]," ++ tail);
    try expectParseError(error.FilterActionsEmpty, head ++ "{\"actions\":[]}]}}]," ++ tail);
    // A status the parser can never produce is a rule that can never
    // fire — a typo, told at load.
    try expectParseError(error.ResponseFilterStatusInvalid, head ++ "{\"match\":{\"status\":[99]},\"actions\":[{\"header_remove\":\"X\"}]}]}}]," ++ tail);
    try expectParseError(error.ResponseFilterStatusInvalid, head ++ "{\"match\":{\"status\":[600]},\"actions\":[{\"header_remove\":\"X\"}]}]}}]," ++ tail);
    // An explicitly empty status list is a mistake — absence already
    // says "any", unambiguously.
    try expectParseError(error.ResponseFilterStatusEmpty, head ++ "{\"match\":{\"status\":[]},\"actions\":[{\"header_remove\":\"X\"}]}]}}]," ++ tail);
    try expectParseError(error.ResponseFilterStatusClassUnknown, head ++ "{\"match\":{\"status_class\":\"6xx\"},\"actions\":[{\"header_remove\":\"X\"}]}]}}]," ++ tail);
    // The proxy-managed names hold on the way out too: hand-written
    // framing would desynchronise the relay.
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_set\":{\"name\":\"Content-Length\",\"value\":\"0\"}}]}]}}]," ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++ "{\"actions\":[{\"header_remove\":\"connection\"}]}]}}]," ++ tail);
    // The same on the way out, and by the same mechanism (#305): the
    // `l4` body has no such key, populated or vacuously empty.
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
        "\"response_filters\":[{\"actions\":[{\"header_remove\":\"Server\"}]}]}}]," ++ tail);
    try expectParseError(error.UnknownField, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
        "\"response_filters\":[]}}]," ++ tail);
}

test "config: a response filter set over the header-edit budget is rejected" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Same whole-table cap as the request side, on its own error name:
    // one response applies every matched rule's edits from one fixed
    // buffer, so the total is what must fit.
    const rules = comptime blk: {
        var s: []const u8 = "";
        var edit: u16 = 0;
        while (edit < constants.header_edits_max + 1) : (edit += 1) {
            if (edit != 0) s = s ++ ",";
            s = s ++ "{\"actions\":[{\"header_remove\":\"X-Drop\"}]}";
        }
        break :blk s;
    };
    const json = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
        "\"cluster\":\"a\",\"response_filters\":[" ++ rules ++ "]}}]," ++ tail;
    try expectParseError(error.ResponseFilterHeaderEditsOverLimit, json);
}

test "config: cluster pick policy parses, defaults to p2c, rejects typos" {
    // Explicit rr and p2c both resolve; absent defaults to p2c.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"pick":"rr"},
            \\   "b":{"endpoints":["127.0.0.1:3"],"pick":"p2c"},
            \\   "c":{"endpoints":["127.0.0.1:4"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expect(parsed.clusters[0].pick == .rr);
        try std.testing.expect(parsed.clusters[1].pick == .p2c);
        try std.testing.expect(parsed.clusters[2].pick == .p2c);
    }
    // A typo must not silently balance as the default.
    try expectParseError(error.ClusterPickUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"pick":"pc2"}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: a check block resolves its kind, thresholds and budget" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],
        \\     "check":{"type":"tcp","fall":5,"rise":1,"timeout_ms":250}},
        \\   "b":{"endpoints":["127.0.0.1:3"],"check":{"type":"tcp"}},
        \\   "c":{"endpoints":["127.0.0.1:4"]}},
        \\ "timeouts":{"connect_ms":7,"idle_ms":8,"drain_deadline_ms":1}}
    );
    const tuned = parsed.clusters[0].check.?;
    try std.testing.expectEqual(@as(u8, 5), tuned.fall);
    try std.testing.expectEqual(@as(u8, 1), tuned.rise);
    try std.testing.expectEqual(@as(u32, 250), tuned.timeout_ms);
    // Omitted thresholds take the compiled defaults, and an omitted
    // budget inherits the connect timeout rather than inventing one.
    const defaulted = parsed.clusters[1].check.?;
    try std.testing.expectEqual(constants.health_probe_fall_default, defaulted.fall);
    try std.testing.expectEqual(constants.health_probe_rise_default, defaulted.rise);
    try std.testing.expectEqual(@as(u32, 7), defaulted.timeout_ms);
    // Absent means unprobed — the cluster the balancer never skips.
    try std.testing.expectEqual(@as(?Config.Cluster.Check, null), parsed.clusters[2].check);
}

test "config: an http check resolves its request and expected status" {
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],
            \\     "check":{"type":"http","path":"/healthz","host":"api.example",
            \\       "expect_status":204}}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        const check = parsed.clusters[0].check.?;
        try std.testing.expectEqual(Config.Cluster.Check.Kind.http, check.kind);
        const http = check.http.?;
        try std.testing.expectEqualStrings("/healthz", http.path);
        try std.testing.expectEqualStrings("api.example", http.host.?);
        try std.testing.expectEqual(@as(u16, 204), http.expect_status);
    }
    // Host is optional: absent means the endpoint's own literal (§7).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],
            \\     "check":{"type":"http","path":"/health"}}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        const http = parsed.clusters[0].check.?.http.?;
        try std.testing.expectEqual(@as(?[]const u8, null), http.host);
        try std.testing.expectEqual(@as(u16, 200), http.expect_status);
    }
}

test "config: the failure-detection fact counts only clusters it can be true of" {
    // What the §5 banner states (#230). The rule has two halves and both
    // are judgement calls worth pinning: detection of *either* kind
    // clears a cluster, and a single-endpoint cluster is never counted
    // however undetected it is — there is nowhere to eject to, and §7
    // fail-open makes the ejection a no-op, so counting it would put
    // noise on exactly the configs the number has nothing to say about.
    const json =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"bare"}}],
        \\ "clusters":{
        \\  "bare":{"endpoints":["127.0.0.1:2","127.0.0.1:3"]},
        \\  "alone":{"endpoints":["127.0.0.1:4"]},
        \\  "probed":{"endpoints":["127.0.0.1:5","127.0.0.1:6"],"check":{"type":"tcp"}},
        \\  "watched":{"endpoints":["127.0.0.1:7","127.0.0.1:8"],"passive_ejection":{}},
        \\  "both":{"endpoints":["127.0.0.1:9","127.0.0.1:10"],
        \\          "check":{"type":"tcp"},"passive_ejection":{}},
        \\  "drained":{"endpoints":[{"address":"127.0.0.1:11","weight":1},
        \\                          {"address":"127.0.0.1:12","weight":0}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const config = try expectParseOk(&arena_state, json);

    // Only `bare`. `alone` is single-endpoint; three have a detector of
    // one kind or the other; and `drained` has two endpoints but only
    // one a request can reach, which is the single-endpoint case wearing
    // a longer spelling — config never reloads, so that weight is final.
    try std.testing.expectEqual(@as(u32, 1), config.clustersWithoutFailureDetection());
}

test "config: a passive_ejection block rejects the thresholds it cannot act on" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"passive_ejection":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Zero would eject on no evidence; the ceiling is what keeps the u8
    // streak from wrapping, shared with the probe thresholds.
    try expectParseError(error.ClusterPassiveEjectionFallOutOfRange, head ++ "{\"fall\":0}" ++ tail);
    try expectParseError(error.ClusterPassiveEjectionFallOutOfRange, head ++ "{\"fall\":65}" ++ tail);
    // A zero cooldown re-admits in the tick that ejected — not a fast
    // recovery but an ejection that never happened.
    try expectParseError(error.ClusterPassiveEjectionRecoveryOutOfRange, head ++ "{\"recovery_ms\":0}" ++ tail);
    // #394's ceiling: never below the cooldown it grows from, and
    // absent unless named — a fixed cooldown, as every config had.
    try expectParseError(
        error.ClusterPassiveEjectionRecoveryMaxBelowBase,
        head ++ "{\"recovery_ms\":5000,\"recovery_ms_max\":4999}" ++ tail,
    );
    {
        var backoff_arena: std.heap.ArenaAllocator = undefined;
        defer backoff_arena.deinit();
        const backoff = try expectParseOk(&backoff_arena, head ++ "{\"recovery_ms\":1000,\"recovery_ms_max\":60000}" ++ tail);
        try std.testing.expectEqual(@as(?u32, 60_000), backoff.clusters[0].passive_ejection.?.recovery_ms_max);
    }

    // The defaults are what an operator who writes `"passive_ejection":{}` gets,
    // and they are the whole point of the block being two optional
    // numbers: opting in should not require picking them.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const config = try expectParseOk(&arena_state, head ++ "{}" ++ tail);
    const passive_ejection = config.clusters[0].passive_ejection.?;
    try std.testing.expectEqual(constants.passive_ejection_fall_default, passive_ejection.fall);
    try std.testing.expectEqual(constants.passive_ejection_recovery_ms_default, passive_ejection.recovery_ms);

    // Absent is off, and off is not "defaults" — an unconfigured cluster
    // must be distinguishable from one that opted in and took them.
    const bare =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    var bare_arena: std.heap.ArenaAllocator = undefined;
    defer bare_arena.deinit();
    const bare_config = try expectParseOk(&bare_arena, bare);
    try std.testing.expect(bare_config.clusters[0].passive_ejection == null);
}

test "config: a check block rejects every shape it cannot run" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"check":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // A typo in the vocabulary must not silently probe as tcp.
    try expectParseError(error.ClusterCheckTypeUnknown, head ++ "{\"type\":\"htp\"}" ++ tail);
    // Nor may a file name a build's own kind (#436), which is selected in
    // code: to JSON it is as unknown as the typo.
    try expectParseError(error.ClusterCheckTypeUnknown, head ++ "{\"type\":\"extension\"}" ++ tail);
    // Thresholds are counts of probes: zero would eject or restore on no
    // evidence at all, and the ceiling keeps the u8 streaks from wrapping.
    try expectParseError(error.ClusterCheckThresholdOutOfRange, head ++ "{\"fall\":0}" ++ tail);
    try expectParseError(error.ClusterCheckThresholdOutOfRange, head ++ "{\"rise\":0}" ++ tail);
    try expectParseError(error.ClusterCheckThresholdOutOfRange, head ++ "{\"fall\":65}" ++ tail);
    // A zero budget would expire before the dial was submitted.
    try expectParseError(error.ClusterCheckTimeoutOutOfRange, head ++ "{\"timeout_ms\":0}" ++ tail);
    // An http check with nothing to request is not a check.
    try expectParseError(error.ClusterCheckPathMissing, head ++ "{\"type\":\"http\"}" ++ tail);
    // A path a tcp probe would never send is a config describing
    // something the process is not doing.
    try expectParseError(
        error.ClusterCheckHttpFieldOnTcp,
        head ++ "{\"type\":\"tcp\",\"path\":\"/health\"}" ++ tail,
    );
    // The probe sends the path verbatim, so it must already be canonical
    // — the same rule a route prefix obeys (§7).
    try expectParseError(
        error.ClusterCheckPathNotCanonical,
        head ++ "{\"type\":\"http\",\"path\":\"health\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckPathNotCanonical,
        head ++ "{\"type\":\"http\",\"path\":\"/a/../b\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckPathNotCanonical,
        head ++ "{\"type\":\"http\",\"path\":\"/health?x=1\"}" ++ tail,
    );
    // A Host is rendered into a request head, so it may not carry the
    // bytes that would end one.
    try expectParseError(
        error.ClusterCheckHostInvalid,
        head ++ "{\"type\":\"http\",\"path\":\"/h\",\"host\":\"a\\r\\nX: y\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckHostInvalid,
        head ++ "{\"type\":\"http\",\"path\":\"/h\",\"host\":\"\"}" ++ tail,
    );
    // A status outside the real range can never match a response.
    try expectParseError(
        error.ClusterCheckStatusInvalid,
        head ++ "{\"type\":\"http\",\"path\":\"/h\",\"expect_status\":99}" ++ tail,
    );
    // A grpc probe asks the path the health protocol fixes, and only it
    // carries a service name.
    try expectParseError(
        error.ClusterCheckHttpFieldOnGrpc,
        head ++ "{\"type\":\"grpc\",\"path\":\"/health\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckServiceWithoutGrpc,
        head ++ "{\"type\":\"http\",\"path\":\"/h\",\"service\":\"a\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckServiceWithoutGrpc,
        head ++ "{\"service\":\"a\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckServiceInvalid,
        head ++ "{\"type\":\"grpc\",\"service\":\"a b\"}" ++ tail,
    );
    // One past the one-octet length the request message encodes.
    const long_service: [constants.health_check_grpc_service_bytes_max + 1]u8 = @splat('s');
    try expectParseError(
        error.ClusterCheckServiceInvalid,
        head ++ "{\"type\":\"grpc\",\"service\":\"" ++ long_service ++ "\"}" ++ tail,
    );
    // Absence asks about the server; an empty name was a second spelling
    // of it that the loader took and the schema refused (#400).
    try expectParseError(
        error.ClusterCheckServiceInvalid,
        head ++ "{\"type\":\"grpc\",\"service\":\"\"}" ++ tail,
    );
    // A status is an http probe's verdict alone: a tcp probe reads
    // nothing, and a grpc one is judged on SERVING. Named beside either,
    // it used to be parsed and ignored, and never range-checked (#400).
    try expectParseError(
        error.ClusterCheckHttpFieldOnTcp,
        head ++ "{\"expect_status\":204}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckHttpFieldOnTcp,
        head ++ "{\"type\":\"tcp\",\"expect_status\":9999}" ++ tail,
    );
    try expectParseError(
        error.ClusterCheckHttpFieldOnGrpc,
        head ++ "{\"type\":\"grpc\",\"expect_status\":204}" ++ tail,
    );
}

test "config: health interval parses, defaults to inter, rejects zero" {
    // Explicit value resolves; absent means the HAProxy-inter default.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,
            \\   "health_interval_ms":250}}
        );
        try std.testing.expectEqual(@as(u32, 250), parsed.health_interval_ms);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(constants.health_interval_ms_default, parsed.health_interval_ms);
    }
    // Zero would probe in a tight loop; the cluster flag is the switch.
    try expectParseError(error.TimeoutZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,
        \\   "health_interval_ms":0}}
    );
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,
        \\   "health_interval_ms":3600001}}
    );
}

test "config: limits shrink pools below the ceilings, never past them" {
    // Partial limits: relay buffers derive from the effective conn slots.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
            \\ "limits":{"conn_slots":64}}
        );
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.conn_slots);
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.relay_buffers);
        // The *default*, which is deliberately below the ceiling: an
        // omitted `upstream_slots` must not silently reserve the c10k
        // maximum. These were the same number until the ceiling rose.
        try std.testing.expectEqual(constants.upstream_slots_default, parsed.limits.upstream_slots);
        try std.testing.expect(constants.upstream_slots_default < constants.upstream_slots_max);
        // The CQ fill defaults to ⅞ when the block omits it.
        try std.testing.expectEqual(constants.cq_fill_eighths_default, parsed.limits.cq_fill_eighths);
    }
    // Full limits resolve verbatim; absent block keeps the ceilings.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
            \\ "limits":{"conn_slots":64,"relay_buffers":8,"upstream_slots":8,"cq_fill_eighths":4}}
        );
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.conn_slots);
        try std.testing.expectEqual(@as(u32, 8), parsed.limits.relay_buffers);
        try std.testing.expectEqual(@as(u32, 8), parsed.limits.upstream_slots);
        // An l4-only config registers no head-buffer ring.
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.head_buffers);
        // A tighter fill resolves verbatim when the pools leave room for it.
        try std.testing.expectEqual(@as(u32, 4), parsed.limits.cq_fill_eighths);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
            \\ "limits":{"conn_slots":64,"head_buffers":16}}
        );
        // An http config follows conn slots when the ring is omitted and
        // takes the operator's number when it is not; the upstream head
        // pool follows upstream slots on the same terms.
        try std.testing.expectEqual(@as(u32, 16), parsed.limits.head_buffers);
        try std.testing.expectEqual(constants.upstream_slots_default, parsed.limits.upstream_head_buffers);
        try std.testing.expectEqual(constants.head_buffer_bytes_default, parsed.limits.head_buffer_bytes);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
            \\ "limits":{"conn_slots":64}}
        );
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.head_buffers);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        // An omitted `limits` block yields the lean defaults, not the
        // ceilings (§5): the out-of-box footprint is small, opt up to scale.
        try std.testing.expectEqual(constants.conn_slots_default, parsed.limits.conn_slots);
        try std.testing.expectEqual(constants.relay_buffers_default, parsed.limits.relay_buffers);
        try std.testing.expectEqual(constants.upstream_slots_default, parsed.limits.upstream_slots);
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.head_buffers);
        try std.testing.expectEqual(constants.cq_fill_eighths_default, parsed.limits.cq_fill_eighths);
    }
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}],";
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
    // The head-buffer ring's three refusals (§5): more buffers than
    // connections is waste stated as intent; any buffers without an http
    // listener can never bind; an http listener with none would shed
    // every request it is configured to serve.
    const http_head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}],";
    try expectParseError(error.LimitHeadBuffersOverConnSlots, http_head ++ tail ++
        "\"limits\":{\"conn_slots\":4,\"head_buffers\":8}}");
    try expectParseError(error.LimitHeadBuffersWithoutHttpListener, head ++ tail ++
        "\"limits\":{\"head_buffers\":1}}");
    try expectParseError(error.LimitHeadBuffersOutOfRange, http_head ++ tail ++
        "\"limits\":{\"head_buffers\":0}}");
    // The upstream head pool refuses the same three shapes against its
    // own ceiling, the upstream slots.
    try expectParseError(error.LimitUpstreamHeadBuffersOverUpstreamSlots, http_head ++ tail ++
        "\"limits\":{\"upstream_slots\":2,\"upstream_head_buffers\":4}}");
    try expectParseError(error.LimitUpstreamHeadBuffersWithoutHttpListener, head ++ tail ++
        "\"limits\":{\"upstream_head_buffers\":1}}");
    try expectParseError(error.LimitUpstreamHeadBuffersOutOfRange, http_head ++ tail ++
        "\"limits\":{\"upstream_head_buffers\":0}}");
    // The size knob has a floor as well as a ceiling: below it ordinary
    // requests start dying as 414/431, which is behaviour, not memory.
    try expectParseError(error.LimitHeadBufferBytesOutOfRange, http_head ++ tail ++
        "\"limits\":{\"head_buffer_bytes\":512}}");
    try expectParseError(error.LimitHeadBufferBytesOutOfRange, http_head ++ tail ++
        "\"limits\":{\"head_buffer_bytes\":2097152}}");
    // Both ends of `relay_buffer_bytes`, on the same terms: below the floor
    // a PROXY header or a chunked size line could not be staged in one
    // buffer, and above the ceiling a relay chunk could not cross as one
    // TLS record (§4). The accepted default is exercised by every other
    // config in this file, so only the rejections need naming here.
    try expectParseError(error.LimitRelayBufferBytesOutOfRange, http_head ++ tail ++
        "\"limits\":{\"relay_buffer_bytes\":512}}");
    try expectParseError(error.LimitRelayBufferBytesOutOfRange, http_head ++ tail ++
        "\"limits\":{\"relay_buffer_bytes\":65536}}");
    // The precedences the options split set (#417), pinned deliberately
    // (see `optionsFromJson`): every spelling only JSON can get wrong
    // outranks every rule the options are held to, so an unknown sink
    // beats an empty listener list — while among the rules, emptiness
    // still beats a sink the options state badly. A bad protocol key
    // (even on a later listener) beats a bad bind on an earlier one,
    // because the strict parser reads every key before anything is
    // translated.
    try expectParseError(error.AccessLogSinkUnknown,
        \\{"listeners":[],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
        \\ "access_log":{"sink":"nonsense"}}
    );
    try expectParseError(error.ListenersEmpty,
        \\{"listeners":[],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1},
        \\ "access_log":{"sink":"file","path":""}}
    );
    // Across blocks too: a cluster's unknown protocol outranks timeouts
    // the options are refused for, though the timeouts judge first.
    try expectParseError(error.ClusterProtocolUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"protocol":"gopher"}},
        \\ "timeouts":{"connect_ms":0}}
    );
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"not-an-address","l4":{"cluster":"a"}},
        \\               {"bind":"127.0.0.1:1","gopher":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // The CQ fill has its own range [min, max] in eighths; below or above
    // fails loudly, each distinct from the pool-size errors.
    try expectParseError(error.LimitCqFillOutOfRange, head ++ tail ++ "\"limits\":{\"cq_fill_eighths\":0}}");
    try expectParseError(error.LimitCqFillOutOfRange, head ++ tail ++ "\"limits\":{\"cq_fill_eighths\":8}}");
    // A fill tighter than the ceiling was derived at cannot serve the full
    // ceiling shape — the completion queue it would need exceeds the
    // compiled ring, so the combination is rejected (§8). Both pools are
    // named at their ceiling because that is the shape the derivation
    // budgets for: the pair is pinned, so a conn slot's worst case
    // includes the upstream slot it may hold (see `conn_slots_max`).
    {
        const json = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}{s}\"limits\":{{\"conn_slots\":{d},\"upstream_slots\":{d},\"cq_fill_eighths\":{d}}}}}",
            .{
                head,
                tail,
                constants.conn_slots_max,
                constants.upstream_slots_max,
                constants.cq_fill_eighths_max - 1,
            },
        );
        defer std.testing.allocator.free(json);
        try expectParseError(error.LimitConnSlotsOverCqFill, json);
    }
}

test "config: admin block resolves a bind literal, absent leaves it off" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}],";
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}
    ;
    // Absent: the admin plane stays off.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail ++ "}");
        try std.testing.expect(parsed.admin_bind == null);
    }
    // Present: the bind resolves to the given IP:port.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tail ++ ",\"admin\":{\"bind\":\"127.0.0.1:9100\"}}",
        );
        try std.testing.expect(parsed.admin_bind != null);
        try std.testing.expectEqual(@as(u16, 9100), parsed.admin_bind.?.getPort());
    }
    // A hostname (or any non-literal) is rejected, like every other bind.
    try expectParseError(error.AdminBindInvalid, head ++ tail ++ ",\"admin\":{\"bind\":\"localhost:9100\"}}");
    // The admin object is strict: `bind` is required and extras are rejected.
    try expectParseError(error.MissingField, head ++ tail ++ ",\"admin\":{}}");
    try expectParseError(error.UnknownField, head ++ tail ++ ",\"admin\":{\"bind\":\"127.0.0.1:9100\",\"x\":1}}");
}

test "config: unknown listener protocol fails loudly" {
    // A typo must not silently relay as L4. The protocol is the body's
    // own key now (#305), so a misspelled one is an unknown *field*
    // rather than an unknown token — the same loudness, one vocabulary
    // fewer to keep in step with the enum.
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","htpp":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // And the key that used to name it is gone: a config still spelling
    // `protocol` is refused rather than quietly ignored.
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","protocol":"http","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: max_lifetime_ms still obeys the shared ceiling" {
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1,"max_lifetime_ms":3600001}}
    );
}

fn expectParseError(expected: ParseError, json_bytes: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(expected, parseWithFiles(arena_state.allocator(), json_bytes, TestCaFiles.source));
    try expectSchemaAgrees(expected, json_bytes);
}

/// #305's differential gate, run on every rejection this file states.
///
/// `zig build schema` says what a config may *look* like and the loader
/// says what it may *mean*, and until this nothing checked that the two
/// agree. A config the schema admits and the loader refuses is a
/// cross-field rule that a shape could have carried instead — Part 1's
/// whole argument — so each one has to be named here with the reason it
/// stays the loader's. What the gate forbids is a *new* one appearing
/// quietly.
///
/// Riding on `expectParseError` rather than on a corpus of its own is
/// the point: there is no second list to drift, and a rejection added
/// tomorrow is graded the day it is written.
fn expectSchemaAgrees(expected: ParseError, json_bytes: []const u8) !void {
    // A malformed document is the JSON parser's verdict, not the
    // loader's, and the schema never sees one — `parseFromSlice` below
    // would fail on exactly the same bytes for exactly the same reason.
    if (!isValidationError(expected)) {
        return;
    }
    var schema = try renderedSchema();
    defer schema.deinit();
    var instance = std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        json_bytes,
        .{},
    ) catch return;
    defer instance.deinit();

    var storage: [json_schema.path_bytes_max]u8 = undefined;
    const failure = json_schema.validate(schema.value, instance.value, &storage);
    if (failure == null and schemaGapOf(expected) == null) {
        std.debug.print(
            "\nthe schema admits what the loader refuses as {t}. Either the schema " ++
                "should express it — in which case teach the emitter — or it cannot, " ++
                "in which case add it to `schema_gaps` with the reason (#305).\n",
            .{expected},
        );
        return error.TestUnexpectedResult;
    }
}

/// Why the schema cannot reject a config the loader refuses.
///
/// Not an excuse list: the categories are the argument. Seven of them
/// are closed — a schema describes documents, and no document grammar
/// can parse an address, sum a list of weights, or read another block —
/// so entries there are permanent and correct. Two are **debt** — a fork
/// or a bound the schema could carry — and both are now **empty**: the
/// forks became `SchemaVariants` and the bounds became `maxLength` and
/// its per-item form. Their counts are pinned below at zero, which is
/// the useful place to pin them: above zero the pin said how much work
/// remained, and at zero it says a new cross-field rule cannot be added
/// without either giving it a shape or arguing here why a schema cannot
/// follow.
const SchemaGap = enum {
    /// The value is text whose *meaning* only a parser knows: an address
    /// literal, a canonical path or host, a CIDR, a header-name token, a
    /// media type, an octal mode. A grammar can say "string"; it cannot
    /// say "and it parses".
    literal_syntax,
    /// A length bound on a name the schema has no place to attach one.
    /// Strictly an object *key* — `clusters`, `bodies` and `error_pages`
    /// are keyed by operator-chosen names, and a key has no schema of
    /// its own in this dialect (`propertyNames` is a keyword the emitter
    /// deliberately does not reach for, #305's closed vocabulary). A
    /// bound on a *value* is not this: it has somewhere to attach, and
    /// the emitter emits `maxLength` for it.
    name_length,
    /// A name that must exist in another block — `cluster` naming a
    /// cluster, `body` naming a body. A schema validates one document
    /// against one grammar, not a document against itself.
    cross_reference,
    /// Uniqueness judged by a key the schema cannot compute: two binds
    /// that differ as text and match as addresses, two routes that
    /// differ in spelling and match after canonicalization.
    duplicate,
    /// The filesystem answered, not the document.
    filesystem,
    /// A resolver answered, not the document (#480): a name that does not
    /// resolve on this box may resolve on the next.
    name_lookup,
    /// §5 arithmetic: a limit judged against another limit, against the
    /// ring, or against whether any listener asked for the feature it
    /// sizes. Closed-form budget reasoning, and the banner is where it
    /// is explained.
    budget,
    /// A rule between two blocks the schema cannot hold at once — a
    /// listener's shape against a cluster's, or against a sibling of its
    /// own body.
    cross_block,
    /// **Debt, and currently empty.** A fork inside one block that
    /// `oneOf` could carry: a field required exactly when a sibling
    /// takes a given value. `SchemaVariants` carries these now, so a row
    /// arriving here means a fork nobody declared rather than one the
    /// emitter cannot state.
    expressible_fork,
    /// **Debt, and currently empty.** A bound the schema could carry:
    /// an array's `maxItems`, or a string's `maxLength` and its
    /// per-item form. All three are emitted, so a row here means a
    /// field whose ceiling was never written down.
    expressible_bound,
};

const SchemaGapEntry = struct { name: []const u8, gap: SchemaGap };

/// Every loader rejection the schema does not catch, measured rather
/// than guessed: the gate above prints what is missing, and this is the
/// list it printed with a reason attached to each.
///
/// One direction only, and worth stating rather than discovering. A row
/// that is *needed* is proved by the gate: remove it and the case that
/// escapes the schema fails the build. A row that has become *stale* —
/// its rule since made expressible — is not caught, and cannot be
/// cheaply: one error is raised by several cases with different JSON,
/// the schema may catch some of them and not others, so "the schema
/// rejected this case" does not mean the row is unnecessary. Deciding
/// that needs every case for an error collected before any verdict,
/// which this harness has no hook for. So a paid-off rule has to be
/// struck from here by whoever pays it off, and re-running the gate
/// with the row removed is how they check.
const schema_gaps = [_]SchemaGapEntry{
    .{ .name = "AccessLogHeaderDuplicate", .gap = .duplicate },
    .{ .name = "AccessLogHeaderNameInvalid", .gap = .literal_syntax },
    .{ .name = "AdminBindInvalid", .gap = .literal_syntax },
    .{ .name = "BodyContentTypeInvalid", .gap = .literal_syntax },
    .{ .name = "BodyFileUnreadable", .gap = .filesystem },
    .{ .name = "BodyNameEmpty", .gap = .name_length },
    .{ .name = "BodyNameTooLong", .gap = .name_length },
    .{ .name = "BodyUnknown", .gap = .cross_reference },
    .{ .name = "ClusterCheckHostInvalid", .gap = .literal_syntax },
    .{ .name = "ClusterCheckPathNotCanonical", .gap = .literal_syntax },
    .{ .name = "ClusterNameEmpty", .gap = .name_length },
    .{ .name = "ClusterNameTooLong", .gap = .name_length },
    .{ .name = "ClusterPickNameInvalid", .gap = .literal_syntax },
    .{ .name = "ClusterProxyProtocolOnHttpListener", .gap = .cross_block },
    .{ .name = "ClusterProxyProtocolOnTlsListener", .gap = .cross_block },
    .{ .name = "ClusterUnknown", .gap = .cross_reference },
    .{ .name = "EndpointFamilyWithoutName", .gap = .literal_syntax },
    .{ .name = "EndpointInvalid", .gap = .literal_syntax },
    .{ .name = "EndpointNameUnresolved", .gap = .name_lookup },
    .{ .name = "EndpointPortZero", .gap = .literal_syntax },
    .{ .name = "EndpointUnixPathInvalid", .gap = .literal_syntax },
    .{ .name = "EndpointUnixPathRelative", .gap = .literal_syntax },
    .{ .name = "EndpointWeightsAllZero", .gap = .budget },
    .{ .name = "ErrorPageStatusInvalid", .gap = .literal_syntax },
    .{ .name = "FilterClientCidrHostBits", .gap = .literal_syntax },
    .{ .name = "FilterClientCidrInvalid", .gap = .literal_syntax },
    .{ .name = "FilterClientPrefixInvalid", .gap = .literal_syntax },
    .{ .name = "FilterClientPrefixTooNarrow", .gap = .literal_syntax },
    .{ .name = "FilterHeaderEditsOverLimit", .gap = .budget },
    .{ .name = "FilterHeaderNameInvalid", .gap = .literal_syntax },
    .{ .name = "FilterHeaderNameReserved", .gap = .literal_syntax },
    .{ .name = "FilterHeaderValueInvalid", .gap = .literal_syntax },
    .{ .name = "FilterRedirectTarget", .gap = .literal_syntax },
    .{ .name = "LimitAccessLogBufferUnderLine", .gap = .budget },
    .{ .name = "LimitAccessLogBufferWithoutSink", .gap = .budget },
    .{ .name = "LimitConnSlotsOverCqFill", .gap = .budget },
    .{ .name = "LimitHeadBuffersOutOfRange", .gap = .budget },
    .{ .name = "LimitHeadBuffersOverConnSlots", .gap = .budget },
    .{ .name = "LimitH2ConnectionsOverConnSlots", .gap = .budget },
    .{ .name = "LimitH2ConnectionsWithoutHttp2", .gap = .budget },
    .{ .name = "LimitHeadBuffersWithoutHttpListener", .gap = .budget },
    .{ .name = "LimitRelayBufferOverTlsRecord", .gap = .budget },
    .{ .name = "LimitRelayBufferUnderSniRouting", .gap = .budget },
    .{ .name = "LimitRelayBuffersOverConnSlots", .gap = .budget },
    .{ .name = "LimitH2StreamsRequired", .gap = .budget },
    .{ .name = "LimitH2StreamsWithoutHttp2", .gap = .budget },
    .{ .name = "LimitTlsEnginesOverConnSlots", .gap = .budget },
    .{ .name = "LimitTlsEnginesWithoutTlsListener", .gap = .budget },
    .{ .name = "LimitTunnelsOverConnSlots", .gap = .budget },
    .{ .name = "LimitTunnelsRequired", .gap = .budget },
    .{ .name = "LimitTunnelsWithoutUpgrades", .gap = .budget },
    .{ .name = "LimitUpstreamHeadBuffersOutOfRange", .gap = .budget },
    .{ .name = "LimitUpstreamHeadBuffersOverUpstreamSlots", .gap = .budget },
    .{ .name = "LimitUpstreamHeadBuffersWithoutHttpListener", .gap = .budget },
    .{ .name = "ListenerBindDuplicate", .gap = .duplicate },
    .{ .name = "ListenerBindInvalid", .gap = .literal_syntax },
    .{ .name = "ListenerBindUnixPathInvalid", .gap = .literal_syntax },
    .{ .name = "ListenerBindUnixPathRelative", .gap = .literal_syntax },
    .{ .name = "ListenerH2cOnTls", .gap = .cross_block },
    .{ .name = "ListenerQuicWithoutTls", .gap = .cross_block },
    .{ .name = "ListenerQuicAltSvcOverEditLimit", .gap = .budget },
    .{ .name = "ListenerQuicBindInvalid", .gap = .literal_syntax },
    .{ .name = "ListenerQuicBindNotIp", .gap = .literal_syntax },
    .{ .name = "ListenerQuicBindDuplicate", .gap = .duplicate },
    .{ .name = "LimitQuicConnectionsWithoutQuic", .gap = .budget },
    .{ .name = "LimitQuicConnectionsOverConnSlots", .gap = .budget },
    .{ .name = "LimitQuicConnectionsOverTlsEngines", .gap = .budget },
    .{ .name = "LimitUpstreamH2ConnectionsWithoutHttp2", .gap = .budget },
    .{ .name = "LimitUpstreamH2StreamsWithoutHttp2", .gap = .budget },
    .{ .name = "LimitUpstreamH2StreamsOverUpstreamSlots", .gap = .budget },
    .{ .name = "ClusterH2cHttpCheck", .gap = .cross_block },
    .{ .name = "ClusterCheckGrpcOnHttp1", .gap = .cross_block },
    .{ .name = "ClusterCheckServiceInvalid", .gap = .literal_syntax },
    .{ .name = "ClusterH2cOnL4Listener", .gap = .cross_block },
    .{ .name = "ClusterH2cWithUpgrades", .gap = .cross_block },
    .{ .name = "ClusterTlsOnH2c", .gap = .cross_block },
    .{ .name = "ClusterRetriesOnHttp2", .gap = .cross_block },
    .{ .name = "ClusterPanicThresholdWithoutHealth", .gap = .cross_block },
    .{ .name = "ClusterSlowStartWithoutMaxInflight", .gap = .cross_block },
    .{ .name = "ClusterSlowStartWithoutHealth", .gap = .cross_block },
    .{ .name = "ClusterTlsOnL4Listener", .gap = .cross_block },
    .{ .name = "ClusterTlsWithUpgrades", .gap = .cross_block },
    .{ .name = "ClusterTlsHttpCheck", .gap = .cross_block },
    .{ .name = "LimitUpstreamTlsOverEngines", .gap = .budget },
    .{ .name = "LimitUpstreamTlsSessionsOverUpstreamSlots", .gap = .budget },
    .{ .name = "LimitUpstreamTlsSessionsWithoutTls", .gap = .budget },
    .{ .name = "ClusterH2WithoutTls", .gap = .cross_block },
    .{ .name = "ClusterTlsServerNameInvalid", .gap = .literal_syntax },
    .{ .name = "ClusterTlsCaUnreadable", .gap = .filesystem },
    .{ .name = "ClusterTlsCaInvalid", .gap = .filesystem },
    .{ .name = "ListenerTlsClientCaUnreadable", .gap = .filesystem },
    .{ .name = "ListenerTlsFileUnreadable", .gap = .filesystem },
    .{ .name = "ListenerTlsClientCaInvalid", .gap = .filesystem },
    .{ .name = "ListenerTlsCertificatesOverLimit", .gap = .budget },
    .{ .name = "LimitUpstreamH2TlsOverEngines", .gap = .budget },
    .{ .name = "ListenerL4RequestKeyedHash", .gap = .cross_block },
    .{ .name = "ListenerModeInvalid", .gap = .literal_syntax },
    .{ .name = "ListenerModeWithoutUnixBind", .gap = .cross_block },
    .{ .name = "ListenerTlsAlpnDuplicate", .gap = .duplicate },
    .{ .name = "ListenerTlsAlpnOnL4", .gap = .cross_block },
    .{ .name = "ListenerTlsWithSniRoutes", .gap = .cross_block },
    .{ .name = "ListenerUnixBindClientMatch", .gap = .cross_block },
    .{ .name = "ListenerUnixBindClusterSend", .gap = .cross_block },
    .{ .name = "ListenerUnixBindForwarded", .gap = .cross_block },
    .{ .name = "ListenerUnixBindSourceIpHash", .gap = .cross_block },
    .{ .name = "ResponseFilterHeaderEditsOverLimit", .gap = .budget },
    .{ .name = "RouteDuplicate", .gap = .duplicate },
    .{ .name = "RouteHostNotCanonical", .gap = .literal_syntax },
    .{ .name = "RouteHostWildcard", .gap = .literal_syntax },
    .{ .name = "RoutePrefixNotCanonical", .gap = .literal_syntax },
    .{ .name = "RouteSniIsAddress", .gap = .literal_syntax },
    .{ .name = "TimeoutOrderInvalid", .gap = .budget },
    .{ .name = "ClusterPassiveEjectionRecoveryMaxBelowBase", .gap = .budget },
};

comptime {
    // 81 rows against 146 error members is ~12k comparisons, well past
    // the default budget and still trivial at compile time.
    @setEvalBranchQuota(200_000);
    // Every name here must be a real member, or a renamed error would
    // leave a row that excuses nothing and hides its successor.
    for (schema_gaps) |entry| {
        var found = false;
        for (@typeInfo(ValidationError).error_set.error_names.?) |candidate| {
            if (std.mem.eql(u8, candidate, entry.name)) found = true;
        }
        if (!found) @compileError("schema_gaps names no such ValidationError: " ++ entry.name);
    }
    // And no name twice, or one row would shadow a second reason.
    for (schema_gaps, 0..) |entry, index| {
        for (schema_gaps[index + 1 ..]) |other| {
            if (std.mem.eql(u8, entry.name, other.name)) {
                @compileError("schema_gaps names " ++ entry.name ++ " twice");
            }
        }
    }
}

fn schemaGapOf(expected: ParseError) ?SchemaGap {
    inline for (schema_gaps) |entry| {
        if (expected == @field(ValidationError, entry.name)) return entry.gap;
    }
    return null;
}

test "config: the schema's debt to the loader only ever falls (#305)" {
    // The measurable definition of the freeze being done, and it now
    // reads zero. Seven gap categories are closed by what a schema *is*
    // — no grammar parses an address, sums a list, resolves a name into
    // another block, computes canonical equality, reads the filesystem,
    // bounds an object key, or holds two blocks at once. These two are
    // what the emitter *could* express, and everything that was in them
    // has been expressed: the forks became `SchemaVariants`, the bounds
    // became `maxLength` and its per-item form, and two rows that looked
    // like bounds turned out to be sums and moved to `budget`.
    //
    // Zero is the interesting number to pin. Above zero it said how much
    // work was left; at zero it says a new cross-field rule cannot be
    // added without either shaping it or arguing, in this file, why a
    // schema cannot follow.
    var forks: usize = 0;
    var bounds: usize = 0;
    for (schema_gaps) |entry| {
        switch (entry.gap) {
            .expressible_fork => forks += 1,
            .expressible_bound => bounds += 1,
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 0), forks);
    try std.testing.expectEqual(@as(usize, 0), bounds);
}

/// Whether `expected` is the loader's own verdict rather than the JSON
/// parser's. `ParseError` is the union of both, and only the loader's
/// half is a claim about config *shape*.
fn isValidationError(expected: ParseError) bool {
    inline for (@typeInfo(ValidationError).error_set.error_names.?) |candidate| {
        if (expected == @field(ValidationError, candidate)) return true;
    }
    return false;
}

/// The rendered schema, parsed fresh for each case rather than cached.
///
/// A cache would outlive the test that filled it and every allocator
/// this suite runs under would call that a leak — which it would be. The
/// document is 60 KiB and this is a test path, so re-rendering is the
/// cheaper mistake to make.
var schema_storage: [128 * 1024]u8 = undefined;

fn renderedSchema() !std.json.Parsed(std.json.Value) {
    var writer = std.Io.Writer.fixed(&schema_storage);
    try @import("schema.zig").writeSchema(&writer);
    return std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        writer.buffered(),
        .{},
    );
}

/// The success-path mirror of `expectParseError`: inits `arena_state`
/// (caller-owned, so the returned `Config`'s slices stay valid as long as
/// the caller needs them and `deinit` is the caller's to call) and parses
/// `json_bytes` from it. `arena_state` is `undefined` until this returns —
/// callers `defer arena_state.deinit()` right after declaring it, so
/// nothing fallible may run between that `defer` and this call, or an
/// early return would deinit an uninitialized arena.
fn expectParseOk(arena_state: *std.heap.ArenaAllocator, json_bytes: []const u8) !Config {
    arena_state.* = std.heap.ArenaAllocator.init(std.testing.allocator);
    const parsed = try parseWithFiles(arena_state.allocator(), json_bytes, TestCaFiles.source);
    try expectSchemaAccepts(json_bytes);
    return parsed;
}

/// The other half of #305's gate, and the cheaper one: whatever the
/// loader accepts, the schema must accept too.
///
/// This direction has no exemptions and never will. A schema that
/// rejects a working config is not a conservative schema — it is a lie
/// told to every editor that reads it, and the operator who believes it
/// deletes a key that was fine. `zig build schema` exists to be trusted
/// by tools that will never run the loader.
fn expectSchemaAccepts(json_bytes: []const u8) !void {
    var schema = try renderedSchema();
    defer schema.deinit();
    var instance = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        json_bytes,
        .{},
    );
    defer instance.deinit();

    var storage: [json_schema.path_bytes_max]u8 = undefined;
    if (json_schema.validate(schema.value, instance.value, &storage)) |failure| {
        std.debug.print(
            "\nthe schema rejects what the loader accepts: {s} at '{s}' (#305)\n",
            .{ @tagName(failure.reason), failure.path },
        );
        return error.TestUnexpectedResult;
    }
}

test "config: the shipped example validates against its own schema (#305)" {
    // The one config in the tree, held to the document `zig build schema`
    // hands an editor. It is the example an operator starts from, so a
    // schema that flags it would be wrong about the first file anybody
    // writes.
    try expectSchemaAccepts(@embedFile("example_config"));
}

test "config: a table far past the old caps parses, and is bounded only by itself" {
    // Replaces the deleted oversize-input test, and covers what took its
    // place: 200 routes and 200 filters are each ~6x the caps that used
    // to reject them (`routes_max`/`filters_per_listener_max`, 32), and
    // the whole input is well past the 256 KiB `config_bytes_max` era's
    // intent. Nothing may cap it now but the operator's own file, so the
    // assertion is simply that it round-trips at full length.
    const route_count = 200;
    const json = comptime blk: {
        // 200 rounds of `comptimePrint` each cost far more than the
        // default 3000-branch budget allows.
        @setEvalBranchQuota(200_000);
        var routes: []const u8 = "";
        var filters: []const u8 = "";
        var index: u16 = 0;
        while (index < route_count) : (index += 1) {
            const n = std.fmt.comptimePrint("{d}", .{index});
            if (index != 0) {
                routes = routes ++ ",";
                filters = filters ++ ",";
            }
            routes = routes ++ "{\"prefix\":\"/p" ++ n ++ "\",\"cluster\":\"a\"}";
            // One header match and one action per rule — both counts the
            // per-rule caps used to bound. No header edits: the whole
            // table's edits still have to fit `header_edits_max`.
            filters = filters ++
                "{\"match\":{\"headers\":[{\"name\":\"X-K" ++ n ++ "\",\"present\":true}]}," ++
                "\"actions\":[{\"reject\":404}]}";
        }
        break :blk "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{" ++
            "\"routes\":[" ++ routes ++ "],\"request_filters\":[" ++ filters ++ "]}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    };
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state, json);
    try std.testing.expectEqual(@as(usize, route_count), parsed.listeners[0].routes.len);
    try std.testing.expectEqual(@as(usize, route_count), parsed.listeners[0].request_filters.len);
}

test "config: strictness rejects unknown and duplicate fields" {
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a","nope":1}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.DuplicateField,
        \\{"listeners":[],"listeners":[],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ClusterNameDuplicate,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]},"a":{"endpoints":["127.0.0.1:3"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.MissingField,
        \\{"clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: a `$schema` editor hint loads and is ignored" {
    // Editors point at the shipped schema by writing `$schema` into the
    // file; a strict loader that rejected it would make the schema asset
    // unusable for the very files it describes.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"$schema":"https://zoxy.io/schema/config.schema.json",
            \\ "listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        // Accepted, and it changed nothing about the resolved config.
        try std.testing.expectEqual(@as(usize, 1), parsed.listeners.len);
        try std.testing.expectEqual(@as(usize, 1), parsed.clusters.len);
    }
    // The hint buys no general laxity: a near miss is still unknown, and it
    // is only a root key — nested objects reject it like any other extra.
    try expectParseError(error.UnknownField,
        \\{"$schemas":"x",
        \\ "listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a","$schema":"x"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: references and addresses are validated" {
    try expectParseError(error.ClusterUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"missing"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // A name resolves through the name seam (#480), which `parse`'s
    // refuses: a name it cannot answer stops the load.
    try expectParseError(error.EndpointNameUnresolved,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["origin.internal:80"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointPortZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:0"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ListenerBindInvalid,
        \\{"listeners":[{"bind":"not-an-address","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ListenerBindDuplicate,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}},
        \\               {"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: endpoint weights parse in both spellings" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["10.0.0.1:8080",
        \\   {"address":"10.0.0.2:8080","weight":3},
        \\   {"address":"10.0.0.3:8080"},
        \\   {"address":"10.0.0.4:8080","weight":0}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const cluster = parsed.clusters[0];
    // The two spellings resolve to one shape: a bare string and an
    // object with no weight are both weight 1, and zero — the drain
    // spelling — is carried, not rejected, while a sibling holds weight.
    try std.testing.expectEqual(@as(usize, 4), cluster.endpoints.len);
    try std.testing.expectEqualSlices(u16, &.{ 1, 3, 1, 0 }, cluster.weights.?);
    try std.testing.expectEqual(@as(u16, 8080), cluster.endpoints[1].ip.getPort());
}

test "config: unweighted endpoints leave the weights table null" {
    // The bare form and an object spelling the default out loud say the
    // same thing, so neither materializes a table: null is the loader's
    // statement that every endpoint shares alike, and the balancer's
    // license to skip weighted arithmetic for the common case.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2",
        \\   {"address":"127.0.0.1:3","weight":1}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try std.testing.expect(parsed.clusters[0].weights == null);
}

/// The names the endpoint tests resolve (#480), answering as a resolver
/// does: every address the name has in the family asked, in an order of
/// its own — the loader's to put right.
const TestNames = struct {
    const Entry = struct { host: []const u8, literals: []const []const u8 };

    const table = [_]Entry{
        .{ .host = "api.test", .literals = &.{ "10.0.0.2", "10.0.0.1" } },
        .{ .host = "dual.test", .literals = &.{ "fd00::1", "10.0.0.3" } },
        .{ .host = "six.test", .literals = &.{"fd00::2"} },
        .{ .host = "one.test", .literals = &.{"10.0.0.1"} },
    };

    const source: NameSource = .{ .lookup = lookup };

    fn lookup(
        context: ?*anyopaque,
        arena: std.mem.Allocator,
        host: []const u8,
        port: u16,
        family: dns_host.Family,
    ) error{ NameUnresolved, OutOfMemory }![]const std.Io.net.IpAddress {
        assert(context == null);
        assert(port != 0);
        const entry = for (&table) |*entry| {
            if (std.mem.eql(u8, entry.host, host)) break entry;
        } else return error.NameUnresolved;
        var addresses: std.ArrayList(std.Io.net.IpAddress) = .empty;
        for (entry.literals) |literal| {
            const address = std.Io.net.IpAddress.parse(literal, port) catch unreachable;
            if (family.admits(&address)) try addresses.append(arena, address);
        }
        if (addresses.items.len == 0) return error.NameUnresolved;
        return addresses.items;
    }
};

fn expectNamesParseOk(arena_state: *std.heap.ArenaAllocator, json_bytes: []const u8) !Config {
    arena_state.* = std.heap.ArenaAllocator.init(std.testing.allocator);
    const parsed = try parseWithSources(arena_state.allocator(), json_bytes, TestCaFiles.source, TestNames.source);
    try expectSchemaAccepts(json_bytes);
    return parsed;
}

fn expectEndpoint(endpoint: io_module.Address, literal: []const u8) !void {
    const expected: io_module.Address = .{ .ip = try std.Io.net.IpAddress.parseLiteral(literal) };
    try std.testing.expect(endpoint.eql(&expected));
}

test "config: a name is resolved at load into one endpoint per address (#480)" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectNamesParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"API.Test.:8080","weight":3,"priority":1},
        \\   "dual.test:80", {"address":"dual.test:81","family":"any"},
        \\   {"address":"six.test:82","family":"ipv6"}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const cluster = parsed.clusters[0];
    // Sorted, whatever the resolver's order; A records alone by default;
    // both families when asked, IPv4 first.
    try std.testing.expectEqual(@as(usize, 6), cluster.endpoints.len);
    try expectEndpoint(cluster.endpoints[0], "10.0.0.1:8080");
    try expectEndpoint(cluster.endpoints[1], "10.0.0.2:8080");
    try expectEndpoint(cluster.endpoints[2], "10.0.0.3:80");
    try expectEndpoint(cluster.endpoints[3], "10.0.0.3:81");
    try expectEndpoint(cluster.endpoints[4], "[fd00::1]:81");
    try expectEndpoint(cluster.endpoints[5], "[fd00::2]:82");
    // Each address takes its entry's weight and tier.
    try std.testing.expectEqualSlices(u16, &.{ 3, 3, 1, 1, 1, 1 }, cluster.weights.?);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 0, 0, 0, 0 }, cluster.priorities.?);
}

test "config: a cluster that names a host keeps each address once (#480)" {
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    // `one.test` is 10.0.0.1, which a literal states too: one endpoint,
    // holding the stronger claim — the primary tier over a standby, and
    // at one tier the higher weight.
    const parsed = try expectNamesParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"10.0.0.1:80","priority":1},
        \\   {"address":"one.test:80","weight":2}, "api.test:80", "10.0.0.9:80"]},
        \\  "b":{"endpoints":["10.0.0.1:80","10.0.0.1:80"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const named = parsed.clusters[0];
    try std.testing.expectEqual(@as(usize, 3), named.endpoints.len);
    try expectEndpoint(named.endpoints[0], "10.0.0.1:80");
    try expectEndpoint(named.endpoints[1], "10.0.0.2:80");
    try expectEndpoint(named.endpoints[2], "10.0.0.9:80");
    try std.testing.expectEqualSlices(u16, &.{ 2, 1, 1 }, named.weights.?);
    try std.testing.expect(named.priorities == null);
    // A cluster of addresses alone is as it was: what it states, it has.
    try std.testing.expectEqual(@as(usize, 2), parsed.clusters[1].endpoints.len);
}

test "config: a name's refusals are its own (#480)" {
    // A name no address answers for: the resolver's verdict, not the
    // document's — `--check` exits 2 on it.
    try expectParseError(error.EndpointNameUnresolved,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["origin.internal:80"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // An address has its family already.
    try expectParseError(error.EndpointFamilyWithoutName,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:2","family":"ipv4"}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointFamilyWithoutName,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"unix:/run/a.sock","family":"any"}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointFamilyUnknown,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"api.test:2","family":"inet"}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // A name's port is an address's: nonzero.
    try expectParseError(error.EndpointPortZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["api.test:0"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // No name: a mistyped address, an unbracketed IPv6 literal, an empty
    // label, a missing port.
    inline for (.{ "10.0.0.256:80", "::1:80", "api..test:80", "api.test", "api.test:http" }) |literal| {
        try expectParseError(error.EndpointInvalid,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["
        ++ literal ++
            \\"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
    }
}

test "config: the weight ceiling itself is a legal share" {
    // The bound is inclusive — `endpoint_weight_max` parses, one past it
    // is the error — matching the at-limit convention the name-length
    // bound establishes below.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:2","weight":256}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try std.testing.expectEqual(constants.endpoint_weight_max, parsed.clusters[0].weights.?[0]);
}

test "config: endpoint weight validation has its own errors" {
    try expectParseError(error.EndpointWeightOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:2","weight":257}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // Every weight zero is a cluster drained to nowhere — rejected like
    // an empty endpoint list, not accepted as one that can never answer.
    try expectParseError(error.EndpointWeightsAllZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:2","weight":0},
        \\   {"address":"127.0.0.1:3","weight":0}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // The object form validates its address exactly like the bare one.
    try expectParseError(error.EndpointInvalid,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"origin internal:80","weight":2}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointPortZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:0","weight":2}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // Strictness reaches inside the object form: a typo'd key is an
    // unknown field, not a silently-dropped weight.
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[{"address":"127.0.0.1:2","weigth":2}]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // An endpoint is a string or an object; any other token is refused
    // rather than coerced.
    try expectParseError(error.UnexpectedToken,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[42]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: every emptiness and limit has its own error" {
    try expectParseError(error.ListenersEmpty,
        \\{"listeners":[],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.ClustersEmpty,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.EndpointsEmpty,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":[]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    try expectParseError(error.TimeoutZero,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":0,"idle_ms":1,"drain_deadline_ms":1}}
    );
    try expectParseError(error.TimeoutOverLimit,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":3600001,"idle_ms":1,"drain_deadline_ms":1}}
    );
}

/// Builds a config with `count` listeners and the given `limits` body.
fn listenersJson(comptime count: u32, comptime limits: []const u8) []const u8 {
    var json: []const u8 = "{\"listeners\":[";
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        if (index > 0) json = json ++ ",";
        json = json ++ std.fmt.comptimePrint(
            \\{{"bind":"127.0.0.1:{d}","l4":{{"cluster":"a"}}}}
        , .{1000 + index});
    }
    return json ++ "]," ++ limits ++
        \\"clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
}

test "config: listeners are bounded by the ring budget, not by a count" {
    // Replaces the old over-`listeners_max` test. 64 listeners — 8x the
    // ceiling that used to refuse them — load fine at the default pools,
    // because what a listener actually costs is two ring ops.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectParseOk(&arena_state, comptime listenersJson(64, ""));
    try std.testing.expectEqual(@as(usize, 64), parsed.listeners.len);
}

test "config: listeners that overflow the ring budget are refused at load" {
    // The comptime `assert(in_flight_ops_max <= completion_queue_entries)`
    // this replaces could only ever speak about the ceilings. This is the
    // same arithmetic against a real config: past some listener count the
    // conn slots leave no room for a listener's two ops, and the config is
    // refused — the startup rejection that the removed ceiling used to
    // pre-empt.
    //
    // Where that line falls says something about the budget worth pinning.
    // `conn_slots_max` is derived against the *worst case* the prober can
    // ask for (`health_probe_concurrency_max` probes, #132), which leaves
    // 2 ops of the 57344-op fill budget spare at zero listeners. This
    // config sets no `check` block anywhere, so its prober reserves the
    // floor of one probe and the other 45 ops are slack it may spend on
    // listeners: 23 fit, and the 24th is one too many. A config that did
    // configure 16 checked endpoints would find that slack already spent
    // and be refused at two — which is the effective-versus-ceiling split
    // (§5, §8) showing up as a real difference between two configs, not
    // an accounting detail.
    //
    // The pair moved by one when #311's loop-watchdog tick joined the
    // fixed reservations, and that is the reservation being visible
    // rather than a number drifting: one more op at zero listeners is one
    // fewer listener at the ceiling, and this test is where the budget
    // says so out loud.
    const at_ceiling = std.fmt.comptimePrint(
        "\"limits\":{{\"conn_slots\":{d},\"upstream_slots\":{d}}},",
        .{ constants.conn_slots_max, constants.upstream_slots_max },
    );
    try expectParseError(error.LimitConnSlotsOverCqFill, comptime listenersJson(24, at_ceiling));
    // Twenty-three still fit, so the refusal above is the budget talking
    // and not the pools alone.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    _ = try expectParseOk(&arena_state, comptime listenersJson(23, at_ceiling));
}

// Coverage-guided mode (`zig build test --fuzz`) is not a gate. Zig 0.16.0
// could not build it at all (its bundled test runner failed to compile
// under -ffuzz); 0.17's can, and its first run tripped the parser's
// cursor-against-one-shot oracle on a head with no terminator — so it
// stays a manual tool until `HeadCursor` and that oracle agree on what
// `Incomplete` means. The corpus still runs deterministically as part of
// `zig build test`.
var fuzz_arena_buffer: [1 << 20]u8 = undefined;

/// A second corpus seed carrying the blocks the shipped example leaves to
/// their defaults. The example is the better *documentation* for having
/// dropped its `timeouts` block, but a corpus seed is judged on the token
/// vocabulary it hands the mutator, and one that never spells
/// `drain_deadline_ms` gives it no path to that branch of the parser.
const fuzz_seed_json =
    \\{"listeners":[{"bind":"127.0.0.1:8080","http":{"routes":[{"prefix":"/","cluster":"o"}],
    \\ "request_filters":[{"match":{"path_prefix":"/admin","client":["10.0.0.0/8"]},"actions":[{"allow":true}]},
    \\ {"match":{"path_prefix":"/admin"},"actions":[{"reject":403}]},
    \\ {"match":{"path_prefix":"/old"},"actions":[{"redirect":{"status":301,"scheme":"https"}}]},
    \\ {"match":{"path_prefix":"/robots.txt"},"actions":[{"respond":{"status":200,"body":"oops"}}]}]}},
    \\ {"bind":"127.0.0.1:8443","tls":{"cert":"/c.pem","key":"/k.pem"},"l4":{"cluster":"t"}}],
    \\ "clusters":{"o":{"endpoints":["127.0.0.1:9000",
    \\ {"address":"127.0.0.1:9001","weight":3}],
    \\ "pick":{"policy":"hash","key":"cookie","name":"zoxy-srv"},"max_inflight":8,
    \\ "check":{"type":"http","path":"/health","expect_status":200,"timeout_ms":250},
    \\ "panic_threshold_percent":50},
    \\ "t":{"endpoints":["127.0.0.1:9100",{"address":"dual.test:9100","family":"any"},"api.test:9100"]}},
    \\ "timeouts":{"connect_ms":5000,"idle_ms":60000,"drain_deadline_ms":10000,
    \\ "max_lifetime_ms":300000,"request_ms":30000,"health_interval_ms":2000},
    \\ "limits":{"conn_slots":64,"relay_buffers":32,"upstream_slots":32,"tls_engines":16},
    \\ "access_log":{"sink":"file","path":"/var/log/zoxy.log"},
    \\ "bodies":{"oops":{"inline":"be right back","content_type":"text/plain"}},
    \\ "error_pages":{"503":"oops"},
    \\ "admin":{"bind":"127.0.0.1:9901"}}
;
// The `file` arm here, `stdout` in `example_json` beside it: between the
// two corpus entries the mutator sees every sink spelling, including the
// `path` key only one of them may carry — both endpoint spellings
// (#174), both pick spellings (#178: the object form with its key/name
// grammar here, the bare string in the example), and every terminal
// filter action (`reject`, `redirect` #176, `respond` #159, `allow`
// #331, whose `true` is the one value it may carry) — so each
// grammar is a starting point rather than a shape the mutator must
// blindly discover. The `inline` body arm is the one it can reach:
// `parse` refuses `file` sources outright, since the fuzzer has no
// filesystem. The `tls` block (#125) rides here too: the fuzz target
// reads through in-memory fixtures that answer any `.pem` or `.key`
// path, so what the mutator gets to explore is the grammar and its
// `tls_engines` relation, which is all of the TLS surface this layer owns.

test "config: the fuzz seed carrying every block parses" {
    // It is a corpus entry, so it has to be a *valid* config — an
    // unparseable seed would still fuzz, just from a worse starting point,
    // and nothing else would say so.
    var arena_state: std.heap.ArenaAllocator = undefined;
    defer arena_state.deinit();
    const parsed = try expectNamesParseOk(&arena_state, fuzz_seed_json);
    try std.testing.expectEqual(@as(u32, 10000), parsed.drain_deadline_ms);
    // The #480 grammar: a name in both spellings, one with its family,
    // resolved through the test names the fuzz target resolves through.
    try std.testing.expectEqual(@as(usize, 5), parsed.clusters[1].endpoints.len);
    try std.testing.expectEqual(@as(u32, 30000), parsed.request_timeout_ms);
    try std.testing.expectEqualSlices(u16, &.{ 1, 3 }, parsed.clusters[0].weights.?);
    // The #159 grammar rides the corpus through its `inline` arm — the
    // fuzzer's `parse` has no filesystem, deliberately — and every
    // terminal action is in the seed's rule table.
    try std.testing.expectEqual(@as(usize, 1), parsed.error_pages.len);
    try std.testing.expectEqual(@as(u16, 503), parsed.error_pages[0].status);
    const rules = parsed.listeners[0].request_filters;
    try std.testing.expectEqual(@as(usize, 4), rules.len);
    // The #331 allowlist pair leads: the terminal that answers nothing,
    // over the reject it shields the named range from.
    try std.testing.expectEqual(filter.Action.allow, rules[0].actions[0]);
    try std.testing.expectEqual(@as(u16, 403), rules[1].actions[0].reject);
    try std.testing.expectEqual(@as(u16, 301), rules[2].actions[0].redirect.status);
    try std.testing.expectEqual(@as(u16, 200), rules[3].actions[0].respond.status);
    // The #125 grammar and the limit that follows it: both in the seed, so
    // the mutator has the vocabulary for either branch.
    try std.testing.expectEqualStrings("'/c.pem' + '/k.pem'", parsed.listeners[1].tls.?.label);
    try std.testing.expectEqual(@as(u32, 16), parsed.limits.tls_engines);
}

test "fuzz: parse never panics — parse or reject, no third outcome" {
    try std.testing.fuzz({}, fuzzParse, .{ .corpus = &.{ example_json, fuzz_seed_json } });
}

fn fuzzParse(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    var input_buffer: [4096]u8 = undefined;
    const input_len = smith.slice(&input_buffer);
    assert(input_len <= input_buffer.len);
    const input = input_buffer[0..input_len];

    var fixed = std.heap.FixedBufferAllocator.init(&fuzz_arena_buffer);
    // The in-memory fixtures, not a filesystem: a listener's certificate
    // pair is read at load (#417), and a source refusing every file would
    // stop each TLS mutation there, short of everything resolved after it.
    // And the test names, so a mutated name walks resolution, ordering
    // and the merge (#480) rather than stopping at the first lookup.
    if (parseWithSources(fixed.allocator(), input, TestCaFiles.source, TestNames.source)) |parsed| {
        // Success implies the resolved invariants hold — no third outcome.
        assert(parsed.listeners.len >= 1);
        assert(parsed.clusters.len >= 1);
        // The deadline handoff's ordering (§4/§5) is a property of every
        // config that loads, so the fuzzer checks it here rather than
        // trusting that the one rejecting branch was reached.
        assert(parsed.connect_timeout_ms < parsed.idle_timeout_ms);
        // The engine pool is zero exactly when nothing terminates TLS
        // (§4/§5), which is what lets the startup loader read "no TLS
        // anywhere" off the one number and skip reserving a libcrypto heap.
        // A config that loaded with either half of that broken would price
        // memory it cannot use, or use memory it did not price.
        var tls_listeners: u32 = 0;
        // The QUIC pool is zero exactly when no listener binds QUIC, and
        // each binding is on a terminating listener (#449).
        var quic_listeners: u32 = 0;
        for (parsed.listeners) |listener| {
            assert(listener.routes.len >= 1);
            if (listener.quic != null) {
                quic_listeners += 1;
                assert(listener.tls != null);
            }
            for (listener.routes) |route| {
                assert(route.cluster_index < parsed.clusters.len);
                assert(route.prefix.len >= 1);
                assert(route.prefix[0] == '/');
            }
            if (listener.tls) |tls| {
                tls_listeners += 1;
                assert(tls.cert_pem.len >= 1);
                assert(tls.key_pem.len >= 1);
                assert(tls.label.len >= 1);
            }
        }
        assert((tls_listeners >= 1) == (parsed.limits.tls_engines >= 1));
        assert(parsed.limits.tls_engines <= parsed.limits.conn_slots);
        assert((quic_listeners >= 1) == (parsed.limits.quic_connections >= 1));
        assert(parsed.limits.quic_connections <= parsed.limits.tls_engines);
    } else |_| {}
}

test "config: the access-log block resolves a sink, absent leaves it off" {
    const tail =
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}
    ;
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}],";

    // Absent: the log stays off and reserves nothing. The buffer size is
    // zero exactly then, which is how `accessLogBytes` reads "off" off one
    // number instead of needing the sink beside it (§5, §8).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail ++ "}");
        try std.testing.expect(parsed.access_log_sink == null);
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.access_log_buffer_bytes);
    }
    // Present: the sink resolves and the staging buffers take the default.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tail ++ ",\"access_log\":{\"sink\":\"stdout\"}}",
        );
        try std.testing.expect(parsed.access_log_sink.? == .stdout);
        try std.testing.expectEqual(
            constants.access_log_buffer_bytes_default,
            parsed.limits.access_log_buffer_bytes,
        );
    }
    // A file sink carries its path through to the resolved union.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tail ++ ",\"access_log\":{\"sink\":\"file\",\"path\":\"/var/log/zoxy.log\"}}",
        );
        try std.testing.expect(parsed.access_log_sink.? == .file);
        try std.testing.expectEqualStrings(
            "/var/log/zoxy.log",
            parsed.access_log_sink.?.file,
        );
        try std.testing.expectEqual(
            constants.access_log_buffer_bytes_default,
            parsed.limits.access_log_buffer_bytes,
        );
    }
    // A sized buffer alongside a sink resolves verbatim.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tail ++ ",\"access_log\":{\"sink\":\"stdout\"}," ++
                "\"limits\":{\"access_log_buffer_bytes\":65536}}",
        );
        try std.testing.expectEqual(@as(u32, 65536), parsed.limits.access_log_buffer_bytes);
    }

    // The sink vocabulary is closed: an unnamed one fails at load rather
    // than silently logging somewhere the operator did not ask for.
    try expectParseError(
        error.AccessLogSinkUnknown,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"syslog\"}}",
    );
    // The block is strict like every other: `sink` required, extras rejected.
    try expectParseError(error.MissingField, head ++ tail ++ ",\"access_log\":{}}");
    // `path` belongs to exactly the sink that uses it: beside `stdout` it
    // describes something that cannot happen, and a `file` sink without
    // one (or with an empty one) names no file at all. The
    // `ClusterCheckHttpFieldOnTcp` rule, applied here.
    try expectParseError(
        error.AccessLogPathOnStdout,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"stdout\",\"path\":\"/tmp/x\"}}",
    );
    try expectParseError(
        error.AccessLogPathMissing,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"file\"}}",
    );
    try expectParseError(
        error.AccessLogPathMissing,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"file\",\"path\":\"\"}}",
    );
    // A buffer below one worst-case line would drop lines it had room for,
    // which is the one thing a drop must never mean; above the ceiling is
    // memory nobody asked to reserve.
    try expectParseError(
        error.LimitAccessLogBufferOutOfRange,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"stdout\"}," ++
            "\"limits\":{\"access_log_buffer_bytes\":16}}",
    );
    try expectParseError(
        error.LimitAccessLogBufferOutOfRange,
        head ++ tail ++ ",\"access_log\":{\"sink\":\"stdout\"}," ++
            "\"limits\":{\"access_log_buffer_bytes\":99999999}}",
    );
    // Sizing buffers for a log that was never turned on is a contradiction,
    // and is told so rather than quietly getting no log.
    try expectParseError(
        error.LimitAccessLogBufferWithoutSink,
        head ++ tail ++ ",\"limits\":{\"access_log_buffer_bytes\":65536}}",
    );
}

test "config: a cluster name is bounded, because the access log echoes it" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"";
    const long_name = repeat("n", constants.cluster_name_bytes_max + 1);
    const at_limit = repeat("n", constants.cluster_name_bytes_max);

    // At the cap it resolves; one byte over fails. Without the bound a log
    // line's width would be a function of the config file rather than of
    // constants.zig (§8).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ at_limit ++ "\"}}],\"clusters\":{\"" ++ at_limit ++
                "\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
                "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
        );
        try std.testing.expectEqual(@as(usize, constants.cluster_name_bytes_max), parsed.clusters[0].name.len);
    }
    try expectParseError(
        error.ClusterNameTooLong,
        head ++ long_name ++ "\"}}],\"clusters\":{\"" ++ long_name ++
            "\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
    // An empty name names nothing and would render as `"cluster":""`.
    try expectParseError(
        error.ClusterNameEmpty,
        head ++ "\"}}],\"clusters\":{\"\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
}

test "config: pick resolves both spellings, and hash names its key" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}],\"clusters\":{\"a\":{";
    const head_http = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}],\"clusters\":{\"a\":{";
    const tail = "}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const endpoints = "\"endpoints\":[\"127.0.0.1:2\"]";

    // The object form names the key; `source_ip` stays legal on an l4
    // listener, since both data paths carry the client address.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\",\"key\":\"source_ip\"}" ++ tail,
        );
        try std.testing.expect(parsed.clusters[0].pick == .hash);
        try std.testing.expectEqual(
            @as(std.meta.Tag(Config.Cluster.HashKey), .source_ip),
            std.meta.activeTag(parsed.clusters[0].hash_key),
        );
    }
    // The request-derived keys carry their name through (#178).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head_http ++ endpoints ++
                ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"zoxy-srv\"}" ++ tail,
        );
        try std.testing.expectEqualStrings("zoxy-srv", parsed.clusters[0].hash_key.cookie);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head_http ++ endpoints ++
                ",\"pick\":{\"policy\":\"hash\",\"key\":\"header\",\"name\":\"x-tenant\"}" ++ tail,
        );
        try std.testing.expectEqualStrings("x-tenant", parsed.clusters[0].hash_key.header);
    }
    // The keyless policies keep the bare-string spelling, and the object
    // spelling of the same policy resolves identically.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ endpoints ++ ",\"pick\":{\"policy\":\"rr\"}" ++ tail,
        );
        try std.testing.expect(parsed.clusters[0].pick == .rr);
    }
    // A cluster that says nothing keeps the p2c default and the default
    // key, which is inert there.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ endpoints ++ tail);
        try std.testing.expect(parsed.clusters[0].pick == .p2c);
    }

    // A bare `"hash"` is the misleading spelling this grammar replaced
    // (#178): which identity the cluster is sticky on is a decision, so
    // the loader demands the object form name it.
    try expectParseError(
        error.ClusterPickKeyMissing,
        head ++ endpoints ++ ",\"pick\":\"hash\"" ++ tail,
    );
    try expectParseError(
        error.ClusterPickKeyMissing,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\"}" ++ tail,
    );
    // Key settings beside another policy are a request for stickiness
    // the cluster would silently not provide — the mistake most worth
    // catching at load rather than in production.
    try expectParseError(
        error.ClusterPickKeyWithoutHash,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"rr\",\"key\":\"source_ip\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickKeyWithoutHash,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"p2c\",\"name\":\"zoxy-srv\"}" ++ tail,
    );
    // The vocabularies are closed, each with its own error so a typo
    // says which field it is in.
    try expectParseError(
        error.ClusterPickUnknown,
        head ++ endpoints ++ ",\"pick\":\"hsah\"" ++ tail,
    );
    try expectParseError(
        error.ClusterPickUnknown,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hsah\",\"key\":\"source_ip\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickKeyUnknown,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\",\"key\":\"session\"}" ++ tail,
    );
    // The object is strict like every other: unknown fields rejected.
    try expectParseError(
        error.UnknownField,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\",\"key\":\"source_ip\",\"mask\":24}" ++ tail,
    );
    // And only strings or objects can name a policy.
    try expectParseError(
        error.UnexpectedToken,
        head ++ endpoints ++ ",\"pick\":2" ++ tail,
    );
}

test "config: a request-derived pick name is required, bounded, and a token" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}],\"clusters\":{\"a\":{";
    const tail = "}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const endpoints = "\"endpoints\":[\"127.0.0.1:2\"]";

    // `source_ip` reads nothing, so a name beside it describes a config
    // that is not what it says — rejected, not ignored.
    try expectParseError(
        error.ClusterPickNameUnexpected,
        head ++ endpoints ++
            ",\"pick\":{\"policy\":\"hash\",\"key\":\"source_ip\",\"name\":\"x\"}" ++ tail,
    );
    // `header` and `cookie` read the named field, so the name is theirs
    // to state.
    try expectParseError(
        error.ClusterPickNameMissing,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickNameMissing,
        head ++ endpoints ++ ",\"pick\":{\"policy\":\"hash\",\"key\":\"header\"}" ++ tail,
    );
    // One grammar for both names: an RFC 9110 token, which is also RFC
    // 6265's cookie-name. A space or `=` inside a cookie name would
    // corrupt every Set-Cookie a cookie cluster answers with.
    try expectParseError(
        error.ClusterPickNameInvalid,
        head ++ endpoints ++
            ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickNameInvalid,
        head ++ endpoints ++
            ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"a=b\"}" ++ tail,
    );
    try expectParseError(
        error.ClusterPickNameInvalid,
        head ++ endpoints ++
            ",\"pick\":{\"policy\":\"hash\",\"key\":\"header\",\"name\":\"bad name\"}" ++ tail,
    );
    // The bound is exact: at `pick_name_bytes_max` the name loads, one
    // past it fails — the stamp's Set-Cookie scratch is sized by it.
    const at_limit = repeat("x", constants.pick_name_bytes_max);
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ endpoints ++
                ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"" ++ at_limit ++ "\"}" ++ tail,
        );
        try std.testing.expectEqual(
            @as(usize, constants.pick_name_bytes_max),
            parsed.clusters[0].hash_key.cookie.len,
        );
    }
    try expectParseError(
        error.ClusterPickNameTooLong,
        head ++ endpoints ++
            ",\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"" ++ at_limit ++ "x\"}" ++ tail,
    );
}

test "config: a request-keyed hash cluster is unreachable from l4" {
    const tail = "}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const cookie_cluster = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]," ++
        "\"pick\":{\"policy\":\"hash\",\"key\":\"cookie\",\"name\":\"zoxy-srv\"}";

    // An l4 listener never parses a head, so a cookie there is a promise
    // nothing would keep — rejected as a pair, the `proxy_protocol_send`
    // rule in the other direction.
    try expectParseError(
        error.ListenerL4RequestKeyedHash,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}]," ++ cookie_cluster ++ tail,
    );
    // The same cluster behind an http listener is exactly what #178 asks
    // for.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
                cookie_cluster ++ tail,
        );
        try std.testing.expectEqualStrings("zoxy-srv", parsed.clusters[0].hash_key.cookie);
    }
}

/// A #159 stub file source: two magic paths for the two read failures,
/// anything else answers a fixed page.
const test_file_source: FileSource = .{ .read = testReadBodyFile };
const test_file_body = "<h1>maintenance</h1>\n";

fn testReadBodyFile(
    context: ?*anyopaque,
    arena: std.mem.Allocator,
    path: []const u8,
    limit: u32,
) error{ FileUnreadable, FileTooLarge, OutOfMemory }![]const u8 {
    _ = context;
    assert(limit >= 1);
    if (std.mem.eql(u8, path, "/big")) return error.FileTooLarge;
    if (std.mem.eql(u8, path, "/gone")) return error.FileUnreadable;
    return arena.dupe(u8, test_file_body);
}

const bodies_head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
    "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}},";
const bodies_tail = "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

test "config: bodies render into complete pages, both variants, HEAD as prefix" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const parsed = try parseWithFiles(
        arena_state.allocator(),
        bodies_head ++
            "\"bodies\":{\"oops\":{\"inline\":\"gone\",\"content_type\":\"text/plain\"}," ++
            "\"maint\":{\"file\":\"/etc/zoxy/maint.html\",\"content_type\":\"text/html\"}}," ++
            "\"error_pages\":{\"404\":\"oops\",\"503\":\"maint\"}," ++ bodies_tail,
        test_file_source,
    );
    try std.testing.expectEqual(@as(usize, 2), parsed.error_pages.len);

    const not_found = parsed.error_pages[0];
    try std.testing.expectEqual(@as(u16, 404), not_found.status);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n" ++
            "Content-Type: text/plain\r\n" ++ page_date ++ "\r\ngone",
        not_found.keep,
    );
    try std.testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n" ++
            "Content-Type: text/plain\r\n" ++ page_date ++ "Connection: close\r\n\r\ngone",
        not_found.close,
    );
    // The head lengths are the HEAD contract: the prefix ends exactly at
    // the blank line, whatever the variant added.
    try std.testing.expectEqual(not_found.keep.len - 4, not_found.keep_head_len);
    try std.testing.expectEqual(not_found.close.len - 4, not_found.close_head_len);

    // The file arm reads through the seam, and the page carries exactly
    // what the file held.
    const maintenance = parsed.error_pages[1];
    try std.testing.expectEqual(@as(u16, 503), maintenance.status);
    try std.testing.expect(std.mem.endsWith(u8, maintenance.keep, test_file_body));

    // Every rendered variant must parse as a complete, correctly framed
    // response — the same round-trip the comptime statics prove.
    for (parsed.error_pages) |page| {
        for ([_][]const u8{ page.keep, page.close }) |bytes| {
            var storage: parser.HeaderStorage = undefined;
            const head = try parser.parseResponseHead(bytes, false, &storage, .get);
            try std.testing.expectEqual(page.status, head.status);
        }
    }
}

test "config: a body names exactly one source, and its grammar is enforced" {
    // Neither arm, and both arms: the redirect target's exactly-one rule.
    try expectParseError(
        error.BodySourceMissing,
        bodies_head ++ "\"bodies\":{\"x\":{\"content_type\":\"text/plain\"}}," ++ bodies_tail,
    );
    try expectParseError(
        error.BodySourceAmbiguous,
        bodies_head ++
            "\"bodies\":{\"x\":{\"inline\":\"a\",\"file\":\"/b\",\"content_type\":\"text/plain\"}}," ++
            bodies_tail,
    );
    // The content type lands on the wire inside a rendered head, so the
    // injection rule is the filter values' own.
    try expectParseError(
        error.BodyContentTypeInvalid,
        bodies_head ++ "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"\"}}," ++ bodies_tail,
    );
    try expectParseError(
        error.BodyContentTypeInvalid,
        bodies_head ++
            "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"text/html\\r\\nX: 1\"}}," ++
            bodies_tail,
    );
    // Names are identifiers: non-empty, bounded, unique.
    try expectParseError(
        error.BodyNameEmpty,
        bodies_head ++ "\"bodies\":{\"\":{\"inline\":\"a\",\"content_type\":\"t/p\"}}," ++ bodies_tail,
    );
    try expectParseError(
        error.BodyNameTooLong,
        bodies_head ++ "\"bodies\":{\"" ++ repeat("n", constants.body_name_bytes_max + 1) ++
            "\":{\"inline\":\"a\",\"content_type\":\"t/p\"}}," ++ bodies_tail,
    );
    // `parse` without a file source refuses every file arm — the fuzzer
    // and the simulator never touch a filesystem.
    try expectParseError(
        error.BodyFileUnreadable,
        bodies_head ++ "\"bodies\":{\"x\":{\"file\":\"/any\",\"content_type\":\"t/p\"}}," ++ bodies_tail,
    );
}

test "config: error pages take only known statuses naming known bodies" {
    const one_body = "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"t/p\"}},";
    // The closed static set: a status zoxy never sends as a static is a
    // config the operator misread — 200 is not an error, 301 is the
    // redirect action's, 500 is not in the vocabulary.
    for ([_][]const u8{ "200", "301", "500" }) |status| {
        var json_buffer: [1024]u8 = undefined;
        const json = std.fmt.bufPrint(
            &json_buffer,
            "{s}{s}\"error_pages\":{{\"{s}\":\"x\"}},{s}",
            .{ bodies_head, one_body, status, bodies_tail },
        ) catch unreachable;
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        try std.testing.expectError(
            error.ErrorPageStatusUnknown,
            parse(arena_state.allocator(), json),
        );
    }
    try expectParseError(
        error.ErrorPageStatusInvalid,
        bodies_head ++ one_body ++ "\"error_pages\":{\"abc\":\"x\"}," ++ bodies_tail,
    );
    try expectParseError(
        error.ErrorPageDuplicate,
        bodies_head ++ one_body ++
            "\"error_pages\":{\"404\":\"x\",\"404\":\"x\"}," ++ bodies_tail,
    );
    // A dangling name is a load error, never an empty page.
    try expectParseError(
        error.BodyUnknown,
        bodies_head ++ one_body ++ "\"error_pages\":{\"404\":\"y\"}," ++ bodies_tail,
    );
    // A map longer than the vocabulary cannot be all-valid, and which
    // way it fails is not knowable from the count — its own error, and
    // the allocation is bounded ahead of it.
    {
        var json: std.ArrayList(u8) = .empty;
        defer json.deinit(std.testing.allocator);
        try json.appendSlice(std.testing.allocator, bodies_head ++ one_body ++ "\"error_pages\":{");
        for (0..shed.static_statuses.len + 1) |index| {
            if (index > 0) try json.append(std.testing.allocator, ',');
            var entry_buffer: [16]u8 = undefined;
            const entry = std.fmt.bufPrint(
                &entry_buffer,
                "\"{d}\":\"x\"",
                .{600 + index},
            ) catch unreachable;
            try json.appendSlice(std.testing.allocator, entry);
        }
        try json.appendSlice(std.testing.allocator, "}," ++ bodies_tail);
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        try std.testing.expectError(
            error.ErrorPagesOverLimit,
            parse(arena_state.allocator(), json.items),
        );
    }
    try expectParseError(
        error.BodyNameDuplicate,
        bodies_head ++
            "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"t/p\"}," ++
            "\"x\":{\"inline\":\"b\",\"content_type\":\"t/p\"}}," ++ bodies_tail,
    );
}

test "config: logged header names are lowercased, deduped and bounded (#140)" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}},\"access_log\":{\"sink\":\"stdout\"";
    const tail = "},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // The logged key is one stable spelling whatever the config wrote,
    // so a query does not have to guess at the casing.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(
            arena_state.allocator(),
            head ++ ",\"request_headers\":[\"X-Request-ID\",\"User-Agent\"]," ++
                "\"response_headers\":[\"X-Cache\"]" ++ tail,
        );
        try std.testing.expectEqual(@as(usize, 2), parsed.access_log_request_headers.len);
        try std.testing.expectEqualStrings("x-request-id", parsed.access_log_request_headers[0]);
        try std.testing.expectEqualStrings("user-agent", parsed.access_log_request_headers[1]);
        try std.testing.expectEqualStrings("x-cache", parsed.access_log_response_headers[0]);
    }
    // Absent lists leave the line exactly as it was.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(arena_state.allocator(), head ++ tail);
        try std.testing.expectEqual(@as(usize, 0), parsed.access_log_request_headers.len);
        try std.testing.expectEqual(@as(usize, 0), parsed.access_log_response_headers.len);
    }
    // The same name twice renders one field, so the config saying it
    // twice is a mistake worth reporting — case-insensitively, since
    // the two spellings are the same header.
    try expectParseError(
        error.AccessLogHeaderDuplicate,
        head ++ ",\"request_headers\":[\"X-Request-ID\",\"x-request-id\"]" ++ tail,
    );
    // The same name on both sides is *not* a duplicate: they are two
    // different facts, and they land in different objects.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(
            arena_state.allocator(),
            head ++ ",\"request_headers\":[\"x-trace\"],\"response_headers\":[\"x-trace\"]" ++ tail,
        );
        try std.testing.expectEqualStrings("x-trace", parsed.access_log_request_headers[0]);
        try std.testing.expectEqualStrings("x-trace", parsed.access_log_response_headers[0]);
    }
    // A name that is not a token could never match a parsed header.
    try expectParseError(
        error.AccessLogHeaderNameInvalid,
        head ++ ",\"request_headers\":[\"bad name\"]" ++ tail,
    );
    try expectParseError(
        error.AccessLogHeaderNameInvalid,
        head ++ ",\"request_headers\":[\"\"]" ++ tail,
    );
    try expectParseError(
        error.AccessLogHeaderNameTooLong,
        head ++ ",\"request_headers\":[\"" ++
            repeat("x", constants.access_log_header_name_bytes_max + 1) ++ "\"]" ++ tail,
    );
}

test "config: the two header lists share one cap, and widen the line (#140)" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}},\"access_log\":{\"sink\":\"stdout\"";
    const tail = "},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // The cap is the total, because what it protects — the line bound
    // and the capture table — is the total. At the cap it loads; one
    // past it does not, whichever list carries the extra.
    const gpa = std.testing.allocator;
    for ([_]u8{ constants.access_log_headers_max, constants.access_log_headers_max + 1 }) |count| {
        var json: std.ArrayList(u8) = .empty;
        defer json.deinit(gpa);
        try json.appendSlice(gpa, head ++ ",\"request_headers\":[");
        for (0..count) |index| {
            if (index > 0) try json.append(gpa, ',');
            var name_buffer: [16]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buffer, "\"x-h{d}\"", .{index}) catch unreachable;
            try json.appendSlice(gpa, name);
        }
        try json.appendSlice(gpa, "]" ++ tail);
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const outcome = parse(arena_state.allocator(), json.items);
        if (count > constants.access_log_headers_max) {
            try std.testing.expectError(error.AccessLogHeadersOverLimit, outcome);
        } else {
            const parsed = try outcome;
            try std.testing.expectEqual(@as(usize, count), parsed.access_log_request_headers.len);
        }
    }

    // A staging buffer that clears the static floor but not this
    // config's own line is refused: it would drop every line carrying
    // the headers, which is a drop that means arithmetic.
    const narrow = constants.access_log_buffer_bytes_min;
    try std.testing.expect(narrow < constants.accessLogLineBytes(1));
    var buffer_json: [512]u8 = undefined;
    const with_narrow_buffer = std.fmt.bufPrint(
        &buffer_json,
        "{s},\"request_headers\":[\"x-request-id\"]}},\"limits\":{{\"access_log_buffer_bytes\":{d}}}," ++
            "\"timeouts\":{{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}}}",
        .{ head, narrow },
    ) catch unreachable;
    try expectParseError(error.LimitAccessLogBufferUnderLine, with_narrow_buffer);
}

/// The two lines every rendered #159 page now carries (#234). The date
/// is still the placeholder here because a page is rendered at *load*,
/// before any response is served — the serving path stamps the slot, and
/// what the loader owes is a slot of exactly the right shape.
const page_date = "Date: " ++ shed.date_placeholder ++ "\r\n" ++ shed.server_line;

test "config: a respond action compiles to a page, sharing one buffer (#159)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const parsed = try parse(arena_state.allocator(),
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a",
        \\ "request_filters":[
        \\   {"match":{"path_prefix":"/robots.txt"},
        \\    "actions":[{"respond":{"status":200,"body":"robots"}}]},
        \\   {"match":{"path_prefix":"/down"},
        \\    "actions":[{"respond":{"status":503,"body":"maint"}}]},
        \\   {"match":{"path_prefix":"/also-down"},
        \\    "actions":[{"respond":{"status":503,"body":"maint"}}]}]}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"]}},
        \\ "bodies":{"robots":{"inline":"User-agent: *\n","content_type":"text/plain"},
        \\   "maint":{"inline":"back soon","content_type":"text/plain"}},
        \\ "error_pages":{"503":"maint"},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    const rules = parsed.listeners[0].request_filters;
    try std.testing.expectEqual(@as(usize, 3), rules.len);

    // The 200 page: the action's own status, the body's content type,
    // and the complete response rendered once.
    const robots = rules[0].actions[0].respond;
    try std.testing.expectEqual(@as(u16, 200), robots.status);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\nContent-Length: 14\r\n" ++
            "Content-Type: text/plain\r\n" ++ page_date ++ "\r\nUser-agent: *\n",
        robots.keep,
    );

    // One body, one buffer: two actions and an error page naming the
    // same (body, status) all point at the *same* rendered page — the
    // load-time cache, not three copies of "back soon".
    const first_maint = rules[1].actions[0].respond;
    const second_maint = rules[2].actions[0].respond;
    try std.testing.expectEqual(first_maint, second_maint);
    try std.testing.expectEqual(first_maint, parsed.error_pages[0]);
    // A different status off the same body is a different page, and
    // shares nothing but the bytes it embeds.
    try std.testing.expect(robots != first_maint);
}

test "config: the respond action's vocabulary is closed, and request-side only" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
        "\"request_filters\":[{\"match\":{},\"actions\":[";
    const mid = "]}]}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"t/p\"}},";
    const tail = "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // 200 and the error statuses load; a status this proxy has no
    // reason phrase for does not.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parse(
            arena_state.allocator(),
            head ++ "{\"respond\":{\"status\":404,\"body\":\"x\"}}" ++ mid ++ tail,
        );
        try std.testing.expectEqual(
            @as(u16, 404),
            parsed.listeners[0].request_filters[0].actions[0].respond.status,
        );
    }
    try expectParseError(
        error.FilterRespondStatus,
        head ++ "{\"respond\":{\"status\":418,\"body\":\"x\"}}" ++ mid ++ tail,
    );
    // A dangling body name fails the same way an error page's does.
    try expectParseError(
        error.BodyUnknown,
        head ++ "{\"respond\":{\"status\":200,\"body\":\"nope\"}}" ++ mid ++ tail,
    );
    // Still exactly one action kind, with the new arm counted.
    try expectParseError(
        error.FilterActionKind,
        head ++ "{\"respond\":{\"body\":\"x\"},\"reject\":403}" ++ mid ++ tail,
    );
    // And it is a request-side answer: a response rule runs when the
    // origin has already answered, so replacing that answer is not an
    // edit this table has — and since #305 it is not a field there
    // either, so the parser says so rather than a rule.
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
            "\"response_filters\":[{\"actions\":[{\"respond\":{\"body\":\"x\"}}]}]}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"bodies\":{\"x\":{\"inline\":\"a\",\"content_type\":\"t/p\"}}," ++ tail,
    );
}

test "config: the body cap holds on both arms, exactly" {
    // The file arm: the reader reports over-limit, the loader speaks the
    // same verdict an oversized inline earns.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(error.BodyOverLimit, parseWithFiles(
        arena_state.allocator(),
        bodies_head ++ "\"bodies\":{\"x\":{\"file\":\"/big\",\"content_type\":\"t/p\"}}," ++ bodies_tail,
        test_file_source,
    ));
    // The inline arm, at the boundary: the cap itself loads, one past
    // fails. Built at runtime — a comptime megabyte literal costs every
    // build what this test costs one run.
    const gpa = std.testing.allocator;
    const at_limit = try gpa.alloc(u8, constants.body_bytes_max);
    defer gpa.free(at_limit);
    @memset(at_limit, 'x');
    for ([_]usize{ constants.body_bytes_max, constants.body_bytes_max + 1 }) |body_len| {
        var json: std.ArrayList(u8) = .empty;
        defer json.deinit(gpa);
        try json.appendSlice(gpa, bodies_head ++ "\"bodies\":{\"x\":{\"inline\":\"");
        try json.appendSlice(gpa, at_limit);
        if (body_len > constants.body_bytes_max) try json.append(gpa, 'x');
        try json.appendSlice(gpa, "\",\"content_type\":\"t/p\"}},\"error_pages\":{\"404\":\"x\"}," ++ bodies_tail);
        var body_arena = std.heap.ArenaAllocator.init(gpa);
        defer body_arena.deinit();
        const outcome = parse(body_arena.allocator(), json.items);
        if (body_len > constants.body_bytes_max) {
            try std.testing.expectError(error.BodyOverLimit, outcome);
        } else {
            const parsed = try outcome;
            try std.testing.expectEqual(
                constants.body_bytes_max,
                @as(u32, @intCast(parsed.error_pages[0].keep.len - parsed.error_pages[0].keep_head_len)),
            );
        }
    }
}

test "config: the body cap is two-valued, and 0 is how uncapped is spelled (#305)" {
    // `null` used to mean 1 MiB and `0` no cap — three states for a
    // two-state idea, and the odd one out in its own config:
    // `drain_deadline_ms`, `max_lifetime_ms` and `request_ms` all spell
    // "no cap" as `0` with nothing else to explain.
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"";
    const tail = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent is still the default it always was, so a config that never
    // named the key keeps its cap.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expectEqual(
            constants.request_body_bytes_default,
            parsed.listeners[0].max_body_bytes,
        );
    }
    // And `0` is uncapped, unchanged.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ ",\"max_body_bytes\":0" ++ tail);
        try std.testing.expectEqual(@as(u64, 0), parsed.listeners[0].max_body_bytes);
    }
    // The ceiling holds at its edge rather than near it.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const at_limit = std.fmt.comptimePrint(
            ",\"max_body_bytes\":{d}",
            .{constants.request_body_bytes_max},
        );
        const parsed = try expectParseOk(&arena_state, head ++ at_limit ++ tail);
        try std.testing.expectEqual(
            constants.request_body_bytes_max,
            parsed.listeners[0].max_body_bytes,
        );
    }
    try expectParseError(
        error.ListenerMaxBodyBytesOutOfRange,
        head ++ std.fmt.comptimePrint(
            ",\"max_body_bytes\":{d}",
            .{constants.request_body_bytes_max + 1},
        ) ++ tail,
    );
    // An l4 relay measures no request, so the key does not exist there —
    // the strict parser's refusal, not a rule's (#305).
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
            "\"max_body_bytes\":500}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
}

test "config: the keep-alive cap is the http listener's, and reaches it (#399)" {
    // The value has to arrive on `Config.Listener`, because that is the
    // copy `Server` hands each connection. #305's leaf pass moved the
    // read there and left the key in `limits`, so for four releases the
    // documented spelling was refused and the accepted one went unread —
    // and the proxy tests, which set the listener directly, could not
    // tell. Asserting the resolved listener is what they skip.
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"";
    // The root object left open, so the negative case below can add a
    // sibling block without slicing a closing brace back off.
    const tail_open = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}";
    const tail = tail_open ++ "}";
    const cases = [_]struct { field: []const u8, expected: u32 }{
        .{ .field = "", .expected = constants.keepalive_requests_default },
        .{ .field = ",\"keepalive_requests\":5", .expected = 5 },
        .{ .field = ",\"keepalive_requests\":0", .expected = 0 },
    };
    comptime assert(constants.keepalive_requests_default != 5);
    comptime assert(constants.keepalive_requests_default != 0);
    inline for (cases) |case| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ case.field ++ tail);
        try std.testing.expectEqual(case.expected, parsed.listeners[0].keepalive_requests);
    }
    // The old home is gone rather than kept as a second spelling: a key
    // that parsed and did nothing is the bug, not a compatibility shim.
    try expectParseError(
        error.UnknownField,
        head ++ tail_open ++ ",\"limits\":{\"keepalive_requests\":5}}",
    );
    // An l4 relay counts no requests, so the key does not exist there.
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
            "\"keepalive_requests\":5}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
}

test "config: a panic threshold resolves where health can eject, and nowhere else (#390)" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2","127.0.0.1:3"],
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Either detector is enough: both write the one mask it reads.
    inline for (.{ "\"check\":{\"type\":\"tcp\"},", "\"passive_ejection\":{}," }) |detector| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ detector ++ "\"panic_threshold_percent\":50" ++ tail);
        try std.testing.expectEqual(@as(?u8, 50), parsed.clusters[0].panic_threshold_percent);
    }
    // Absent is the default rule, fail open at zero healthy, and needs
    // no value to say it.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "\"check\":{\"type\":\"tcp\"}" ++ tail);
        try std.testing.expectEqual(@as(?u8, null), parsed.clusters[0].panic_threshold_percent);
    }
    // Zero is that default spelled twice; 100 panics at the first
    // ejection, which is health checks that never steer.
    const checked = head ++ "\"check\":{\"type\":\"tcp\"},\"panic_threshold_percent\":";
    try expectParseError(error.ClusterPanicThresholdOutOfRange, checked ++ "0" ++ tail);
    try expectParseError(error.ClusterPanicThresholdOutOfRange, checked ++ "100" ++ tail);
    // Nothing ejects from an unchecked cluster, so the key could never act.
    try expectParseError(
        error.ClusterPanicThresholdWithoutHealth,
        head ++ "\"panic_threshold_percent\":50" ++ tail,
    );
}

test "config: slow start needs a cap to ramp and something to restore from (#391)" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++
            "\"max_inflight\":8,\"passive_ejection\":{},\"slow_start_ms\":30000" ++ tail);
        try std.testing.expectEqual(@as(?u32, 30_000), parsed.clusters[0].slow_start_ms);
    }
    try expectParseError(error.ClusterSlowStartWithoutMaxInflight, head ++ "\"passive_ejection\":{},\"slow_start_ms\":1000" ++ tail);
    try expectParseError(error.ClusterSlowStartWithoutHealth, head ++ "\"max_inflight\":8,\"slow_start_ms\":1000" ++ tail);
    try expectParseError(error.ClusterSlowStartOutOfRange, head ++ "\"max_inflight\":8,\"passive_ejection\":{},\"slow_start_ms\":0" ++ tail);
}

test "config: an endpoint may name a standby tier (#396)" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Untiered: no table at all, every config before the key.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "[\"127.0.0.1:2\",{\"address\":\"127.0.0.1:3\",\"priority\":0}]" ++ tail);
        try std.testing.expect(parsed.clusters[0].priorities == null);
    }
    // A bare string is a primary beside a standby.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "[\"127.0.0.1:2\",{\"address\":\"127.0.0.1:3\",\"priority\":1}]" ++ tail);
        try std.testing.expectEqualSlices(u8, &.{ 0, 1 }, parsed.clusters[0].priorities.?);
    }
    try expectParseError(error.EndpointPriorityOverLimit, head ++ "[{\"address\":\"127.0.0.1:3\",\"priority\":8}]" ++ tail);
    // Relative: the lowest tier named is the primary, so one tier
    // everywhere is no tiering, and 2-over-1 is 1-over-0.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++
            "[{\"address\":\"127.0.0.1:2\",\"priority\":1},{\"address\":\"127.0.0.1:3\",\"priority\":1}]" ++ tail);
        try std.testing.expect(parsed.clusters[0].priorities == null);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++
            "[{\"address\":\"127.0.0.1:2\",\"priority\":2},{\"address\":\"127.0.0.1:3\",\"priority\":1}]" ++ tail);
        try std.testing.expectEqualSlices(u8, &.{ 1, 0 }, parsed.clusters[0].priorities.?);
    }
}

test "config: retries take a bare count or an object with a budget (#393)" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2","127.0.0.1:3"],"retries":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // The bare count every config has written, unchanged.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "2" ++ tail);
        try std.testing.expectEqual(@as(u16, 2), parsed.clusters[0].retries);
        try std.testing.expectEqual(@as(?u16, null), parsed.clusters[0].retry_budget);
    }
    // The long form, with and without a budget.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "{\"count\":2,\"budget\":8}" ++ tail);
        try std.testing.expectEqual(@as(u16, 2), parsed.clusters[0].retries);
        try std.testing.expectEqual(@as(?u16, 8), parsed.clusters[0].retry_budget);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "{\"count\":1}" ++ tail);
        try std.testing.expectEqual(@as(u16, 1), parsed.clusters[0].retries);
    }
    // The long form is for clusters that retry: `{"count": 0}` is the
    // bare `0` spelled long, refused as the number it cannot be there.
    try expectParseError(error.InvalidNumber, head ++ "{\"count\":0,\"budget\":4}" ++ tail);
    try expectParseError(error.ClusterRetryBudgetOutOfRange, head ++ "{\"count\":1,\"budget\":0}" ++ tail);
    try expectParseError(error.ClusterRetriesOutOfRange, head ++ "{\"count\":9}" ++ tail);
    // Neither a string nor a bool is a count.
    try expectParseError(error.UnexpectedToken, head ++ "\"2\"" ++ tail);
}

test "config: max_total_inflight resolves, defaults to uncapped, rejects the useless (#392)" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"max_total_inflight":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "512" ++ tail);
        try std.testing.expectEqual(@as(?u32, 512), parsed.clusters[0].max_total_inflight);
    }
    // Zero turns the cluster off rather than protecting it.
    try expectParseError(error.ClusterMaxTotalInflightOutOfRange, head ++ "0" ++ tail);
    try expectParseError(error.ClusterMaxTotalInflightOutOfRange, head ++ "16777217" ++ tail);
}

test "config: max_inflight resolves, defaults to uncapped, rejects the useless" {
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"max_inflight":64},
            \\   "b":{"endpoints":["127.0.0.1:3"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(@as(?u32, 64), parsed.clusters[0].max_inflight);
        // Absent is uncapped, which is the only spelling of "no limit".
        try std.testing.expectEqual(@as(?u32, null), parsed.clusters[1].max_inflight);
    }
    // Zero would refuse every request to an idle endpoint, and a value
    // past the largest representable load could never refuse one —
    // both are typos rather than intents (§8).
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"max_inflight":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    try expectParseError(error.ClusterMaxInflightOutOfRange, head ++ "0" ++ tail);
    try expectParseError(error.ClusterMaxInflightOutOfRange, head ++ "4294967295" ++ tail);
    // The ceiling itself is legal, and deliberately so: it is reachable
    // only if every conn and upstream slot in the process piles onto one
    // endpoint, which is a real (if extreme) shape rather than a no-op.
    {
        var buffer: [512]u8 = undefined;
        const json = try std.fmt.bufPrint(
            &buffer,
            "{s}{d}{s}",
            .{ head, constants.endpoint_inflight_max, tail },
        );
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, json);
        try std.testing.expectEqual(
            @as(?u32, constants.endpoint_inflight_max),
            parsed.clusters[0].max_inflight,
        );
    }
}

test "config: an endpoint may be a Unix socket path (#303)" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[";
    const tail = "]}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Both spellings in one cluster, which is the point of a prefix on
    // the existing string rather than a second key (#305): a migration
    // moves one endpoint at a time.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"127.0.0.1:9000\",\"unix:/run/app.sock\"," ++
                "{\"address\":\"unix:/run/app2.sock\",\"weight\":3}" ++ tail,
        );
        const endpoints = parsed.clusters[0].endpoints;
        try std.testing.expectEqual(@as(usize, 3), endpoints.len);
        try std.testing.expectEqual(@as(u16, 9000), endpoints[0].ip.getPort());
        try std.testing.expectEqualStrings("/run/app.sock", endpoints[1].unix);
        // The `unix:` prefix is grammar, not part of the path: what
        // reaches the kernel is what the operator would `ls`.
        try std.testing.expectEqualStrings("/run/app2.sock", endpoints[2].unix);
        // The #174 object form is unaffected — the grammar grew at one
        // parse site and nothing that parsed before changed shape.
        try std.testing.expectEqualSlices(u16, &.{ 1, 1, 3 }, parsed.clusters[0].weights.?);
        // And the rendered spelling round-trips to what was written,
        // which is what the access log and the metrics label print.
        var scratch: [64]u8 = undefined;
        var writer = std.Io.Writer.fixed(&scratch);
        try writer.print("{f}", .{endpoints[1]});
        try std.testing.expectEqualStrings("unix:/run/app.sock", writer.buffered());
    }

    // A relative path resolves against a working directory the operator
    // did not name and a service manager may change — so it names a
    // socket nobody can point at. Refused at load (§5), not at the dial.
    try expectParseError(
        error.EndpointUnixPathRelative,
        head ++ "\"unix:run/app.sock\"" ++ tail,
    );
    // The empty path is the abstract namespace, which is out of scope
    // (#303) and would otherwise be a silent second meaning for `unix:`.
    try expectParseError(error.EndpointUnixPathInvalid, head ++ "\"unix:\"" ++ tail);
    // Past what a `sockaddr_un` carries. Refused rather than truncated:
    // a shortened path names a *different* socket, and the kernel would
    // have no way to say so.
    {
        const too_long = "/" ++ repeat("p", constants.unix_socket_path_bytes_max);
        try expectParseError(
            error.EndpointUnixPathInvalid,
            head ++ "\"unix:" ++ too_long ++ "\"" ++ tail,
        );
        // One byte shorter is the longest path that fits, and it parses
        // — the bound is a real edge, not a round number near one.
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"unix:" ++ too_long[0 .. too_long.len - 1] ++ "\"" ++ tail,
        );
        try std.testing.expectEqual(
            @as(usize, constants.unix_socket_path_bytes_max),
            parsed.clusters[0].endpoints[0].unix.len,
        );
    }
    // A zero-port rule cannot apply to a socket path, and must not be
    // reached through one: the check is on the `ip` arm only.
    try expectParseError(error.EndpointPortZero, head ++ "\"127.0.0.1:0\"" ++ tail);

    // The bytes an address may not carry. POSIX permits them in a path;
    // the access log and the metrics exposition do not — one of these
    // reaching a renderer invalidates the whole line and the whole
    // scrape, not one field, so they are refused where every other
    // §5 bound is.
    inline for (.{ "\\\"", "\\\\", "\\u0001", "\\u007f", " " }) |hostile| {
        try expectParseError(
            error.EndpointUnixPathInvalid,
            head ++ "\"unix:/run/a" ++ hostile ++ "b.sock\"" ++ tail,
        );
    }
}

test "config: a listener may bind a socket path (#303)" {
    const tail = ",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":";

    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"unix:/run/zoxy.sock\"" ++ tail,
        );
        try std.testing.expectEqualStrings("/run/zoxy.sock", parsed.listeners[0].bind_address.unix);
        // Absent leaves whatever the umask gives, which is what every
        // other tool does and what an operator's directory permissions
        // are already expressed against.
        try std.testing.expect(parsed.listeners[0].bind_mode == null);
    }
    // The same path validation as an endpoint, under this field's own
    // error names — an operator should not have to work out which of the
    // two fields the loader meant.
    try expectParseError(
        error.ListenerBindUnixPathRelative,
        head ++ "\"unix:run/zoxy.sock\"" ++ tail,
    );
    try expectParseError(error.ListenerBindUnixPathInvalid, head ++ "\"unix:\"" ++ tail);
    try expectParseError(
        error.ListenerBindUnixPathInvalid,
        head ++ "\"unix:/run/a\\\"b.sock\"" ++ tail,
    );
    // Two listeners on one path are the same duplicate an IP:port pair
    // is — and the check had to stop being a single integer key to see
    // it, since a path does not fit one.
    try expectParseError(
        error.ListenerBindDuplicate,
        "{\"listeners\":[{\"bind\":\"unix:/run/a.sock\",\"http\":{\"cluster\":\"a\"}}," ++
            "{\"bind\":\"unix:/run/a.sock\",\"http\":{\"cluster\":\"a\"}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
}

test "config: a socket file's mode is octal, and only a socket has one (#303)" {
    const tail = ",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const unix_head = "{\"listeners\":[{\"bind\":\"unix:/run/zoxy.sock\"";

    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            unix_head ++ ",\"mode\":\"0660\"" ++ tail,
        );
        try std.testing.expectEqual(@as(u16, 0o660), parsed.listeners[0].bind_mode.?.bits);
    }
    // A string, not a number: `0660` is not valid JSON and `660` is
    // decimal, and the two readings of one intent differ by a factor of
    // eight — in the direction that widens the mode.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, unix_head ++ ",\"mode\":\"660\"" ++ tail);
        try std.testing.expectEqual(@as(u16, 0o660), parsed.listeners[0].bind_mode.?.bits);
    }
    // An IP bind creates no file, so a mode on one describes nothing.
    try expectParseError(
        error.ListenerModeWithoutUnixBind,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"mode\":\"0660\"" ++ tail,
    );
    inline for (.{ "0680", "9", "", "00660", "abc" }) |bad| {
        try expectParseError(
            error.ListenerModeInvalid,
            unix_head ++ ",\"mode\":\"" ++ bad ++ "\"" ++ tail,
        );
    }
    // setuid, setgid and sticky mean nothing on a socket and everything
    // on the file it would be confused with.
    try expectParseError(
        error.ListenerModeInvalid,
        unix_head ++ ",\"mode\":\"4660\"" ++ tail,
    );
}

test "config: a unix listener refuses what needs a client address (#303)" {
    // A request arriving on a socket file has no client IP, and there is
    // no honest sentinel: a fabricated `0.0.0.0` would make each of
    // these quietly wrong rather than absent. Refused at load (§5).
    const tail = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"unix:/run/zoxy.sock\",\"http\":{\"cluster\":\"a\"";

    try expectParseError(
        error.ListenerUnixBindForwarded,
        head ++ ",\"forwarded\":{\"mode\":\"replace\"}" ++ tail,
    );
    try expectParseError(
        error.ListenerUnixBindClientMatch,
        head ++ ",\"request_filters\":[{\"match\":{\"client\":[\"10.0.0.0/8\"]}," ++
            "\"actions\":[{\"reject\":403}]}]" ++ tail,
    );
    try expectParseError(
        error.ListenerUnixBindSourceIpHash,
        "{\"listeners\":[{\"bind\":\"unix:/run/zoxy.sock\",\"http\":{\"cluster\":\"a\"}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]," ++
            "\"pick\":{\"policy\":\"hash\",\"key\":\"source_ip\"}}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
    // A hash on something the request carries is unaffected: the key is
    // in the request, not in the connection.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        _ = try expectParseOk(
            &arena_state,
            "{\"listeners\":[{\"bind\":\"unix:/run/zoxy.sock\",\"http\":{\"cluster\":\"a\"}}]," ++
                "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]," ++
                "\"pick\":{\"policy\":\"hash\",\"key\":\"header\",\"name\":\"x-tenant\"}}}," ++
                "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
        );
    }
    // An SNI table is a second set of reachable clusters (#298), and
    // the listener's `routes` does not summarise it: with a name table
    // `routes` holds one provisional entry, and `finishSniPeek` replaces
    // the exchange's cluster with the matched one before any dial. So a
    // rule that walked only `routes` would hold the *first* name to it
    // and wave every other one through — into an unwrap of the client
    // address that is not there.
    inline for (.{
        "{\"policy\":\"hash\",\"key\":\"source_ip\"}",
        "\"p2c\"",
    }, .{
        error.ListenerUnixBindSourceIpHash,
        error.ListenerUnixBindClusterSend,
    }) |pick, expected| {
        const send = if (expected == error.ListenerUnixBindClusterSend)
            ",\"proxy_protocol\":{\"send\":\"v2\"}"
        else
            "";
        try expectParseError(
            expected,
            "{\"listeners\":[{\"bind\":\"unix:/run/zoxy.sock\",\"l4\":{\"routes\":[" ++
                "{\"sni\":\"a.example\",\"cluster\":\"plain\"}," ++
                "{\"sni\":\"b.example\",\"cluster\":\"second\"}]}}]," ++
                "\"clusters\":{\"plain\":{\"endpoints\":[\"127.0.0.1:2\"]}," ++
                "\"second\":{\"endpoints\":[\"127.0.0.1:3\"],\"pick\":" ++ pick ++
                send ++ "}}," ++
                "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
        );
    }
    // And an IP listener still takes all three, which is what says the
    // rule is about the bind and not about the feature.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        _ = try expectParseOk(
            &arena_state,
            "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
                "\"forwarded\":{\"mode\":\"replace\"}" ++ tail,
        );
    }
}

test "config: proxy_status is off unless asked for, and is http-only" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"";
    const tail = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent means silent (#300): a config written before the feature
    // must not start naming this proxy's limits on the wire.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expect(!parsed.listeners[0].proxy_status);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ ",\"proxy_status\":true" ++ tail);
        try std.testing.expect(parsed.listeners[0].proxy_status);
    }
    // An l4 relay renders no HTTP response to put the field in, so the
    // key does not exist there — the strict parser is the rule (#305).
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
            "\"proxy_status\":true}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
}

test "config: the forwarded block resolves a mode, and is http-only" {
    // The head opens the `http` body, so the fields each case appends
    // land inside it — which is the whole shape (#305): `forwarded` is
    // reachable from here and from nowhere else.
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"";
    const tail = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent: the header is untouched, which is what every config that
    // predates this feature must keep doing.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expect(parsed.listeners[0].forwarded == null);
    }
    // Both modes resolve; neither is a default.
    inline for (.{ "replace", "append" }) |mode| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ ",\"forwarded\":{\"mode\":\"" ++ mode ++ "\"}" ++ tail,
        );
        try std.testing.expectEqual(
            std.meta.stringToEnum(Config.Listener.Forwarded, mode).?,
            parsed.listeners[0].forwarded.?,
        );
    }

    // An l4 listener has no header to carry an address, so asking for one
    // describes a proxy that is not running. There is no longer a rule
    // saying so — the `l4` body has no such key, so the strict parser
    // refuses it (#305), which is the same verdict one mechanism earlier.
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
            "\"forwarded\":{\"mode\":\"replace\"}}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
    // The mode vocabulary is closed and `mode` is required: there is no
    // safe default to fall back to, which is the whole point.
    try expectParseError(
        error.ListenerForwardedModeUnknown,
        head ++ ",\"forwarded\":{\"mode\":\"trust\"}" ++ tail,
    );
    try expectParseError(
        error.MissingField,
        head ++ ",\"forwarded\":{}" ++ tail,
    );
}

test "config: the proxy_protocol block resolves a mode, and is l4-only" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"";
    const tail = "}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent: first bytes are payload — every config predating this.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expect(parsed.listeners[0].proxy_protocol == null);
    }
    // The one mode resolves. This used to run twice — once on the
    // defaulted protocol and once on a stated `l4` — and there is no
    // longer a difference to cover: the body's key *is* the statement,
    // so there is no defaulted spelling for it to disagree with (#305).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ ",\"proxy_protocol\":{\"mode\":\"require\"}" ++ tail,
        );
        try std.testing.expectEqual(
            Config.Listener.ProxyProtocol.require,
            parsed.listeners[0].proxy_protocol.?,
        );
    }
    // The L7 path has no receive phase yet, so a block there would state
    // a trust boundary nothing enforces. The `http` body has no such key
    // (#305), so it is refused rather than ignored — the same verdict the
    // rule used to give, one mechanism earlier.
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
            "\"proxy_protocol\":{\"mode\":\"require\"}}}]," ++
            "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
            "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}",
    );
    // The mode vocabulary is closed and `mode` is required; sniffing
    // ("optional") is deliberately not in it — a listener that accepts
    // header-or-raw-bytes lets any client choose its own address.
    try expectParseError(
        error.ListenerProxyProtocolModeUnknown,
        head ++ ",\"proxy_protocol\":{\"mode\":\"optional\"}" ++ tail,
    );
    try expectParseError(
        error.MissingField,
        head ++ ",\"proxy_protocol\":{}" ++ tail,
    );
}

test "config: the tls block resolves paths, and only shape-checks them" {
    // The head closes the protocol body, because `tls` is the listener's
    // and not either body's (#305) — so every case below appends at the
    // level the key actually lives on.
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}";
    const tail = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent: a plaintext socket, every config predating this.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail);
        try std.testing.expect(parsed.listeners[0].tls == null);
    }
    // Present on either protocol: termination is orthogonal to what the
    // terminated stream then speaks, which is why the handshake is a
    // phase ahead of the protocol rather than part of one.
    inline for (.{
        "\"l4\":{\"cluster\":\"a\"}",
        "\"http\":{\"cluster\":\"a\"}",
    }) |body| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"," ++ body ++
                ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"}" ++ tail,
        );
        const tls = parsed.listeners[0].tls.?;
        // The pair arrives read (#417), labelled with both paths for any
        // startup error that has to name it.
        try std.testing.expectEqualStrings(zoxy.tls.testdata.cert_pem, tls.cert_pem);
        try std.testing.expectEqualStrings(zoxy.tls.testdata.cert_pem, tls.key_pem);
        try std.testing.expectEqualStrings("'/c.pem' + '/k.pem'", tls.label);
    }
    // A path the file seam cannot read stops the load: the loader reads
    // through it, and nothing downstream touches a filesystem (#417).
    try expectParseError(
        error.ListenerTlsFileUnreadable,
        head ++ ",\"tls\":{\"cert\":\"/nope\",\"key\":\"/k.pem\"}" ++ tail,
    );
    try expectParseError(
        error.ListenerTlsFileUnreadable,
        head ++ ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/nope\"}" ++ tail,
    );
    // An empty path is checkable here, and worth checking: it would reach
    // `openat` as a request to open the current directory, failing
    // somewhere far less obvious than the config that asked for it.
    try expectParseError(
        error.ListenerTlsCertPathEmpty,
        head ++ ",\"tls\":{\"cert\":\"\",\"key\":\"/k.pem\"}" ++ tail,
    );
    try expectParseError(
        error.ListenerTlsKeyPathEmpty,
        head ++ ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"\"}" ++ tail,
    );
    // Both paths are required: a certificate with no key is not a
    // half-configured listener, it is one that cannot answer a handshake.
    try expectParseError(
        error.MissingField,
        head ++ ",\"tls\":{\"cert\":\"/c.pem\"}" ++ tail,
    );
    try expectParseError(
        error.MissingField,
        head ++ ",\"tls\":{\"key\":\"/k.pem\"}" ++ tail,
    );
}

test "config: a terminating listener cannot reach a PROXY-sending cluster" {
    // A TLS connection's client→upstream window is the engine's plaintext
    // buffer, not the relay buffer the send-side header stages into — so
    // the origin would receive whatever that window happened to hold
    // rather than the header. Refused at load rather than sent as garbage.
    // Reachability, not exclusivity, exactly like the http case beside it:
    // the same cluster stays valid for every plaintext listener.
    const tail = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]," ++
        "\"proxy_protocol\":{\"send\":\"v2\"}}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    try expectParseError(
        error.ClusterProxyProtocolOnTlsListener,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}," ++
            "\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"}}]," ++ tail,
    );
    // Without the tls block the same cluster is fine.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}]," ++ tail,
        );
        try std.testing.expect(parsed.clusters[0].proxy_protocol_send != null);
    }
}

test "config: tls.alpn offers what the listener speaks, and only that (#271)" {
    const tail = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const http = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}";
    const l4 = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}";
    const tls_head = ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"";

    // Absent on an `http` listener: HTTP/1.1, said rather than left for a
    // client to infer from silence — the gap #271 closes by default.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, http ++ tls_head ++ "}" ++ tail);
        const offer = parsed.listeners[0].tls.?.alpn;
        try std.testing.expectEqual(@as(usize, 1), offer.len);
        try std.testing.expectEqualStrings("http/1.1", offer[0]);
    }
    // Absent on an `l4` listener: nothing, because a relay names no
    // protocol it could promise.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, l4 ++ tls_head ++ "}" ++ tail);
        try std.testing.expectEqual(@as(usize, 0), parsed.listeners[0].tls.?.alpn.len);
    }
    // Spelled out, it resolves to the canonical token — the static one,
    // not the config's own copy.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            http ++ tls_head ++ ",\"alpn\":[\"http/1.1\"]}" ++ tail,
        );
        const offer = parsed.listeners[0].tls.?.alpn;
        try std.testing.expectEqual(@as(usize, 1), offer.len);
        try std.testing.expectEqual(alpn.Protocol.http_1_1.token().ptr, offer[0].ptr);
    }
    // A name this proxy does not speak. RFC 7301 §3.1 compares octets, so
    // case counts: `HTTP/1.1` is not `http/1.1`.
    try expectParseError(error.ListenerTlsAlpnUnknown, http ++ tls_head ++ ",\"alpn\":[\"HTTP/1.1\"]}" ++ tail);
    try expectParseError(error.ListenerTlsAlpnUnknown, http ++ tls_head ++ ",\"alpn\":[\"h2c\"]}" ++ tail);
    // Offering nothing is the silence this closes, not a spelling of it.
    try expectParseError(error.ListenerTlsAlpnEmpty, http ++ tls_head ++ ",\"alpn\":[]}" ++ tail);
    // A name twice is a preference order that says nothing.
    try expectParseError(
        error.ListenerTlsAlpnDuplicate,
        http ++ tls_head ++ ",\"alpn\":[\"http/1.1\",\"http/1.1\"]}" ++ tail,
    );
    // And on an `l4` listener the key is refused outright, whatever it
    // names: the relay would be promising a protocol it never parses.
    try expectParseError(
        error.ListenerTlsAlpnOnL4,
        l4 ++ tls_head ++ ",\"alpn\":[\"http/1.1\"]}" ++ tail,
    );
}

test "config: an h2c cluster is reached over HTTP/2, sizes the origin pools, and only http listeners route to it (§7)" {
    const http = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}],";
    const timeouts = "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}";
    const h2c = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\",\"127.0.0.1:3\"],\"protocol\":\"h2c\"}},";
    const plain = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}},";
    // Defaults: two connections per h2c endpoint, a stream per upstream slot.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, http ++ h2c ++ timeouts ++ "}");
        try std.testing.expectEqual(Config.Cluster.Protocol.h2c, parsed.clusters[0].protocol);
        try std.testing.expectEqual(@as(u32, 4), parsed.limits.h2_origin_connections);
        try std.testing.expectEqual(parsed.limits.upstream_slots, parsed.limits.h2_origin_streams);
    }
    // Sized, and absent where nothing speaks h2c — the default protocol.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const sized = try expectParseOk(&arena_state, http ++ h2c ++ timeouts ++
            ",\"limits\":{\"upstream_h2_connections\":1,\"upstream_h2_streams\":8}}");
        try std.testing.expectEqual(@as(u32, 1), sized.limits.h2_origin_connections);
        try std.testing.expectEqual(@as(u32, 8), sized.limits.h2_origin_streams);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const none = try expectParseOk(&arena_state, http ++ plain ++ timeouts ++ "}");
        try std.testing.expectEqual(Config.Cluster.Protocol.http1, none.clusters[0].protocol);
        try std.testing.expectEqual(@as(u32, 0), none.limits.h2_origin_connections);
        try std.testing.expectEqual(@as(u32, 0), none.limits.h2_origin_streams);
    }
    try expectParseError(error.LimitUpstreamH2ConnectionsWithoutHttp2, http ++ plain ++ timeouts ++
        ",\"limits\":{\"upstream_h2_connections\":2}}");
    try expectParseError(error.LimitUpstreamH2StreamsWithoutHttp2, http ++ plain ++ timeouts ++
        ",\"limits\":{\"upstream_h2_streams\":2}}");
    try expectParseError(error.LimitUpstreamH2StreamsOverUpstreamSlots, http ++ h2c ++ timeouts ++
        ",\"limits\":{\"upstream_slots\":4,\"upstream_h2_streams\":5}}");
    try expectParseError(error.ClusterProtocolUnknown, http ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"],\"protocol\":\"h3\"}}," ++ timeouts ++ "}");
    // The prober speaks HTTP/1.1, which an h2c origin need not.
    try expectParseError(error.ClusterH2cHttpCheck, http ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"],\"protocol\":\"h2c\"," ++
        "\"check\":{\"type\":\"http\",\"path\":\"/health\"}}}," ++ timeouts ++ "}");
    // gRPC rides HTTP/2: its health service is not one an HTTP/1.1
    // origin can answer.
    try expectParseError(error.ClusterCheckGrpcOnHttp1, http ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]," ++
        "\"check\":{\"type\":\"grpc\"}}}," ++ timeouts ++ "}");
    // An l4 listener relays bytes; an upgrade's tunnel needs a 101.
    try expectParseError(error.ClusterH2cOnL4Listener, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}]," ++ h2c ++ timeouts ++ "}");
    try expectParseError(error.ClusterH2cWithUpgrades, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"," ++
        "\"upgrades\":{\"websocket\":true}}}]," ++ h2c ++ timeouts ++ ",\"limits\":{\"tunnels\":4}}");
}

/// The files the loader tests name, served the way `main` reads them: a
/// CA bundle by its path, a listener's certificate or key by its suffix
/// (#417), and nothing anywhere else — so every other file arm is
/// refused exactly as `parse`'s own source refuses it.
const TestCaFiles = struct {
    fn read(
        context: ?*anyopaque,
        arena: std.mem.Allocator,
        path: []const u8,
        limit: u32,
    ) error{ FileUnreadable, FileTooLarge, OutOfMemory }![]const u8 {
        _ = context;
        assert(limit >= 1);
        const bytes: []const u8 = if (std.mem.eql(u8, path, "/ca.pem"))
            zoxy.tls.testdata.origin_ca_pem
        else if (std.mem.eql(u8, path, "/client-ca.pem"))
            zoxy.tls.testdata.client_ca_pem
        else if (std.mem.eql(u8, path, "/garbage.pem"))
            "not a certificate"
            // Refused by name, ahead of the suffix rule below that would
            // otherwise serve them: the tests' stand-ins for a missing file.
        else if (std.mem.eql(u8, path, "/nope") or std.mem.eql(u8, path, "/missing.pem"))
            return error.FileUnreadable
        else if (std.mem.endsWith(u8, path, ".pem") or std.mem.endsWith(u8, path, ".key"))
            zoxy.tls.testdata.cert_pem
        else
            return error.FileUnreadable;
        assert(bytes.len <= limit);
        return try arena.dupe(u8, bytes);
    }

    const source: FileSource = .{ .read = read };
};

fn expectH2ParseError(expected: ParseError, json_bytes: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(expected, parseWithFiles(arena_state.allocator(), json_bytes, TestCaFiles.source));
}

test "config: a listener may hold more certificates, counted across the process (#297)" {
    const tail = "\"http\":{\"cluster\":\"a\"}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"";
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++
            ",\"certificates\":[{\"cert\":\"/a.pem\",\"key\":\"/ak.pem\"},{\"cert\":\"/b.pem\",\"key\":\"/bk.pem\"}]}," ++ tail);
        const tls = parsed.listeners[0].tls.?;
        // The pair above stays the default; the list is what SNI chooses among.
        try std.testing.expectEqualStrings("'/c.pem' + '/k.pem'", tls.label);
        try std.testing.expectEqual(@as(usize, 2), tls.certificates.len);
        try std.testing.expectEqualStrings("'/b.pem' + '/bk.pem'", tls.certificates[1].label);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "}," ++ tail);
        try std.testing.expectEqual(@as(usize, 0), parsed.listeners[0].tls.?.certificates.len);
    }
    try expectParseError(error.ListenerTlsCertificatesEmpty, head ++ ",\"certificates\":[]}," ++ tail);
    try expectParseError(error.ListenerTlsCertPathEmpty, head ++ ",\"certificates\":[{\"cert\":\"\",\"key\":\"/k\"}]}," ++ tail);
    // A further pair is read like the default one (#417).
    try expectParseError(error.ListenerTlsFileUnreadable, head ++ ",\"certificates\":[{\"cert\":\"/nope\",\"key\":\"/k.pem\"}]}," ++ tail);
    try expectParseError(error.ListenerTlsKeyPathEmpty, head ++ ",\"certificates\":[{\"cert\":\"/c\",\"key\":\"\"}]}," ++ tail);
    // The ceiling is the process's, each listener's default included: two
    // listeners of 129 is over where either alone is not.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const half = constants.tls_certificates_max / 2;
    var list: std.ArrayList(u8) = .empty;
    for (0..half) |index| try list.print(arena, "{s}{{\"cert\":\"/{d}.pem\",\"key\":\"/{d}.key\"}}", .{ if (index == 0) "" else ",", index, index });
    const listener = "\"tls\":{{\"cert\":\"/c.pem\",\"key\":\"/k.pem\",\"certificates\":[{s}]}},\"http\":{{\"cluster\":\"a\"}}";
    const one = try std.fmt.allocPrint(arena, "{{\"listeners\":[{{\"bind\":\"127.0.0.1:1\"," ++ listener ++ "}}]," ++
        "\"clusters\":{{\"a\":{{\"endpoints\":[\"127.0.0.1:2\"]}}}},\"timeouts\":{{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}}}", .{list.items});
    {
        var ok_state: std.heap.ArenaAllocator = undefined;
        defer ok_state.deinit();
        _ = try expectParseOk(&ok_state, one);
    }
    const two = try std.fmt.allocPrint(arena, "{{\"listeners\":[{{\"bind\":\"127.0.0.1:1\"," ++ listener ++ "}},{{\"bind\":\"127.0.0.1:3\"," ++ listener ++ "}}]," ++
        "\"clusters\":{{\"a\":{{\"endpoints\":[\"127.0.0.1:2\"]}}}},\"timeouts\":{{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}}}", .{ list.items, list.items });
    try expectParseError(error.ListenerTlsCertificatesOverLimit, two);
}

test "config: a listener's client_ca is read at load, required unless it says optional (#304)" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"";
    const tail = "},\"http\":{\"cluster\":\"a\"}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    inline for (.{
        .{ ",\"client_ca\":{\"path\":\"/client-ca.pem\"}", Config.Listener.ClientVerify.required },
        .{ ",\"client_ca\":{\"path\":\"/client-ca.pem\",\"verify\":\"optional\"}", Config.Listener.ClientVerify.optional },
    }) |case| {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parseWithFiles(arena_state.allocator(), head ++ case[0] ++ tail, TestCaFiles.source);
        const client_ca = parsed.listeners[0].tls.?.client_ca.?;
        try std.testing.expectEqual(case[1], client_ca.verify);
        try std.testing.expectEqual(@as(usize, 1), client_ca.anchors.len);
    }
    // Absent asks no client for a certificate, as every listener did.
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parseWithFiles(arena_state.allocator(), head ++ tail, TestCaFiles.source);
        try std.testing.expect(parsed.listeners[0].tls.?.client_ca == null);
    }
    try expectH2ParseError(error.ListenerTlsClientVerifyUnknown, head ++ ",\"client_ca\":{\"path\":\"/client-ca.pem\",\"verify\":\"maybe\"}" ++ tail);
    try expectH2ParseError(error.ListenerTlsClientCaUnreadable, head ++ ",\"client_ca\":{\"path\":\"/missing.pem\"}" ++ tail);
    try expectH2ParseError(error.ListenerTlsClientCaInvalid, head ++ ",\"client_ca\":{\"path\":\"/garbage.pem\"}" ++ tail);
}

test "config: an h2 cluster names the server its origins prove and the CA they reach, read at load (§7)" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}]," ++
        "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"],";
    const tail = "}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";
    const tls = "\"tls\":{\"server_name\":\"origin.zoxy.test\",\"ca\":{\"path\":\"/ca.pem\"}}";
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parseWithFiles(arena_state.allocator(), head ++ "\"protocol\":\"h2\"," ++ tls ++ tail, TestCaFiles.source);
        const cluster = parsed.clusters[0];
        try std.testing.expectEqual(Config.Cluster.Protocol.h2, cluster.protocol);
        try std.testing.expectEqualStrings("origin.zoxy.test", cluster.tls.?.server_name);
        try std.testing.expectEqual(@as(usize, 1), cluster.tls.?.anchors.len);
        try std.testing.expect(originTls(parsed.clusters));
        try std.testing.expect(parsed.limits.h2_origin_connections >= 1);
    }
    // h2 is TLS's, and h2c is not.
    try expectH2ParseError(error.ClusterH2WithoutTls, head ++ "\"protocol\":\"h2\"" ++ tail);
    try expectH2ParseError(error.ClusterTlsOnH2c, head ++ "\"protocol\":\"h2c\"," ++ tls ++ tail);
    // A name that is no DNS name, a bundle that cannot be read, or holds
    // no certificate.
    inline for (.{ "", "10.0.0.1", "bad_name.test", "-a.test", "a..test" }) |name| {
        try expectH2ParseError(error.ClusterTlsServerNameInvalid, head ++ "\"protocol\":\"h2\"," ++
            "\"tls\":{\"server_name\":\"" ++ name ++ "\",\"ca\":{\"path\":\"/ca.pem\"}}" ++ tail);
    }
    try expectH2ParseError(error.ClusterTlsCaUnreadable, head ++ "\"protocol\":\"h2\"," ++
        "\"tls\":{\"server_name\":\"origin.zoxy.test\",\"ca\":{\"path\":\"/missing.pem\"}}" ++ tail);
    try expectH2ParseError(error.ClusterTlsCaInvalid, head ++ "\"protocol\":\"h2\"," ++
        "\"tls\":{\"server_name\":\"origin.zoxy.test\",\"ca\":{\"path\":\"/garbage.pem\"}}" ++ tail);
    // The libcrypto heap holds every TLS session: listeners' and origins'.
    try expectH2ParseError(error.LimitUpstreamH2TlsOverEngines, head ++ "\"protocol\":\"h2\"," ++ tls ++
        "}},\"limits\":{\"upstream_h2_connections\":4096}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}");
}

test "config: an HTTPS cluster verifies its origins over HTTP/1.1, sized and refused where TLS cannot go (#296)" {
    const listener = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}}],";
    const cluster_head = "\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\",\"127.0.0.1:3\"],";
    const tls = "\"tls\":{\"server_name\":\"origin.zoxy.test\",\"ca\":{\"path\":\"/ca.pem\"}}";
    const timeouts = "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}";
    const https = listener ++ cluster_head ++ tls ++ "}}," ++ timeouts;
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parseWithFiles(arena_state.allocator(), https ++ "}", TestCaFiles.source);
        try std.testing.expectEqual(Config.Cluster.Protocol.http1, parsed.clusters[0].protocol);
        try std.testing.expect(parsed.clusters[0].tls != null);
        try std.testing.expect(originTls(parsed.clusters));
        try std.testing.expect(!h2OriginTls(parsed.clusters));
        // Sixteen per endpoint, within the upstream slots; no HTTP/2 pool.
        try std.testing.expectEqual(@as(u32, 2), upstreamTlsEndpointsOf(parsed.clusters));
        try std.testing.expectEqual(
            @min(2 * constants.upstream_tls_sessions_per_endpoint, parsed.limits.upstream_slots),
            parsed.limits.upstream_tls_sessions,
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.h2_origin_connections);
    }
    {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const parsed = try parseWithFiles(arena_state.allocator(), https ++
            ",\"limits\":{\"upstream_tls_sessions\":3}}", TestCaFiles.source);
        try std.testing.expectEqual(@as(u32, 3), parsed.limits.upstream_tls_sessions);
    }
    // The prober speaks no TLS; an l4 listener and a tunnel would carry the
    // socket around the session.
    try expectH2ParseError(error.ClusterTlsHttpCheck, listener ++ cluster_head ++ tls ++
        ",\"check\":{\"type\":\"http\",\"path\":\"/health\"}}}," ++ timeouts ++ "}");
    try expectH2ParseError(error.ClusterTlsOnL4Listener, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"," ++
        "\"l4\":{\"cluster\":\"a\"}}]," ++ cluster_head ++ tls ++ "}}," ++ timeouts ++ "}");
    try expectH2ParseError(error.ClusterTlsWithUpgrades, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"," ++
        "\"http\":{\"cluster\":\"a\",\"upgrades\":{\"websocket\":true}}}]," ++ cluster_head ++ tls ++
        "}}," ++ timeouts ++ ",\"limits\":{\"tunnels\":4}}");
    // The session pool is the HTTPS clusters', within the slots and the heap.
    try expectH2ParseError(error.LimitUpstreamTlsSessionsWithoutTls, listener ++ cluster_head ++
        "\"protocol\":\"http1\"}}," ++ timeouts ++ ",\"limits\":{\"upstream_tls_sessions\":2}}");
    try expectH2ParseError(error.LimitUpstreamTlsSessionsOverUpstreamSlots, https ++
        ",\"limits\":{\"upstream_slots\":4,\"upstream_tls_sessions\":5}}");
    try expectH2ParseError(error.LimitUpstreamTlsOverEngines, "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"," ++
        "\"http\":{\"cluster\":\"a\"},\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"}}]," ++
        cluster_head ++ tls ++ "}}," ++ timeouts ++
        ",\"limits\":{\"tls_engines\":1000,\"upstream_slots\":1024,\"upstream_tls_sessions\":100}}");
}

test "config: a listener speaking HTTP/2 sizes its pools, and only one does (#275)" {
    const tail_head = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}";
    const plain = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"";
    const tls_h2 = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}," ++
        "\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\",\"alpn\":[\"h2\",\"http/1.1\"]}";
    const tls_h2_only = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}," ++
        "\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\",\"alpn\":[\"h2\"]}";
    const streams = ",\"limits\":{\"h2_streams\":64}}";

    // h2c on a plaintext listener: the stream pool is required, and the
    // session pool defaults, capped at conn slots.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, plain ++ ",\"h2c\":true}" ++ tail_head ++ streams);
        try std.testing.expect(parsed.listeners[0].h2c);
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.stream_slots);
        try std.testing.expectEqual(
            @min(constants.h2_connections_default, parsed.limits.conn_slots),
            parsed.limits.h2_connections,
        );
    }
    // `h2` in ALPN — beside HTTP/1.1, or alone, which sheds at accept when
    // no session is free rather than being refused here.
    inline for (.{ tls_h2, tls_h2_only }) |listener| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, listener ++ tail_head ++ streams);
        try std.testing.expectEqual(alpn.Protocol.h2.token().ptr, parsed.listeners[0].tls.?.alpn[0].ptr);
        try std.testing.expect(parsed.limits.h2_connections >= 1);
    }
    // A stream count is a capacity decision, never guessed.
    try expectParseError(error.LimitH2StreamsRequired, plain ++ ",\"h2c\":true}" ++ tail_head ++ "}");
    try expectParseError(error.LimitH2StreamsRequired, tls_h2 ++ tail_head ++ "}");
    try expectParseError(
        error.LimitH2StreamsOutOfRange,
        plain ++ ",\"h2c\":true}" ++ tail_head ++ ",\"limits\":{\"h2_streams\":0}}",
    );
    // Both pools are refused where nothing speaks HTTP/2.
    try expectParseError(error.LimitH2StreamsWithoutHttp2, plain ++ "}" ++ tail_head ++ streams);
    try expectParseError(
        error.LimitH2ConnectionsWithoutHttp2,
        plain ++ "}" ++ tail_head ++ ",\"limits\":{\"h2_connections\":4}}",
    );
    // A session per connection, at most.
    try expectParseError(
        error.LimitH2ConnectionsOverConnSlots,
        plain ++ ",\"h2c\":true}" ++ tail_head ++
            ",\"limits\":{\"conn_slots\":4,\"h2_connections\":5,\"h2_streams\":8}}",
    );
    try expectParseError(
        error.LimitH2ConnectionsOutOfRange,
        plain ++ ",\"h2c\":true}" ++ tail_head ++ ",\"limits\":{\"h2_connections\":0,\"h2_streams\":8}}",
    );
    // h2c is HTTP/2 without TLS: a terminating listener offers h2 instead —
    // and is told so first, with the stream pool sized or not.
    const h2c_on_tls = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"h2c\":true}," ++
        "\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"}" ++ tail_head;
    try expectParseError(error.ListenerH2cOnTls, h2c_on_tls ++ streams);
    try expectParseError(error.ListenerH2cOnTls, h2c_on_tls ++ "}");
}

test "config: a quic binding serves HTTP/3 beside its listener, sizing its pool and sharing the streams (#449)" {
    const tail_head = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}";
    const http = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"";
    const tls = ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"}";
    const quic = ",\"quic\":{\"bind\":\"127.0.0.1:1\"}}";
    const streams = ",\"limits\":{\"h2_streams\":64}}";

    // On its own listener's TCP address, which a UDP port does not clash
    // with: a QUIC-only deployment has the shared streams and no HTTP/2
    // session, and the pool defaults within the engines.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, http ++ quic ++ tls ++ tail_head ++ streams);
        const binding = parsed.listeners[0].quic.?;
        const expected = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:1");
        try std.testing.expect(binding.bind_address.eql(&expected));
        try std.testing.expectEqual(constants.alt_svc_max_age_s_default, binding.alt_svc_max_age_s);
        try std.testing.expectEqual(@as(u32, 64), parsed.limits.stream_slots);
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.h2_connections);
        try std.testing.expectEqual(
            @min(constants.quic_connections_default, parsed.limits.conn_slots, parsed.limits.tls_engines),
            parsed.limits.quic_connections,
        );
    }
    // Absent, nothing is reserved for it.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, http ++ "}" ++ tls ++ tail_head ++ "}");
        try std.testing.expect(parsed.listeners[0].quic == null);
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.quic_connections);
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.stream_slots);
    }
    // Beside HTTP/2 on one listener the two share one stream pool; the
    // default is capped by a smaller engine pool, and a stated count and
    // a zero max-age are taken as they are.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, http ++
            ",\"quic\":{\"bind\":\"[::1]:443\",\"alt_svc_max_age_s\":0}}" ++
            ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\",\"alpn\":[\"h2\",\"http/1.1\"]}" ++
            tail_head ++ ",\"limits\":{\"h2_streams\":8,\"tls_engines\":16}}");
        comptime assert(constants.quic_connections_default > 16);
        try std.testing.expectEqual(@as(u32, 16), parsed.limits.quic_connections);
        try std.testing.expect(parsed.limits.h2_connections >= 1);
        try std.testing.expectEqual(@as(u32, 8), parsed.limits.stream_slots);
        try std.testing.expectEqual(@as(u32, 0), parsed.listeners[0].quic.?.alt_svc_max_age_s);
    }
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, http ++ quic ++ tls ++ tail_head ++
            ",\"limits\":{\"h2_streams\":8,\"quic_connections\":3}}");
        try std.testing.expectEqual(@as(u32, 3), parsed.limits.quic_connections);
    }

    // QUIC is TLS 1.3, and is told so first, with the streams sized or not.
    try expectParseError(error.ListenerQuicWithoutTls, http ++ quic ++ tail_head ++ streams);
    try expectParseError(error.ListenerQuicWithoutTls, http ++ quic ++ tail_head ++ "}");
    // HTTP/3's requests are the shared streams', a capacity decision.
    try expectParseError(error.LimitH2StreamsRequired, http ++ quic ++ tls ++ tail_head ++ "}");
    // The pool is refused where nothing binds QUIC, and held to the conn
    // slots and to the engines every connection holds one of.
    try expectParseError(
        error.LimitQuicConnectionsWithoutQuic,
        http ++ "}" ++ tls ++ tail_head ++ ",\"limits\":{\"quic_connections\":4}}",
    );
    try expectParseError(
        error.LimitQuicConnectionsOutOfRange,
        http ++ quic ++ tls ++ tail_head ++ ",\"limits\":{\"h2_streams\":8,\"quic_connections\":0}}",
    );
    try expectParseError(
        error.LimitQuicConnectionsOverConnSlots,
        http ++ quic ++ tls ++ tail_head ++
            ",\"limits\":{\"conn_slots\":4,\"h2_streams\":8,\"quic_connections\":5}}",
    );
    try expectParseError(
        error.LimitQuicConnectionsOverTlsEngines,
        http ++ quic ++ tls ++ tail_head ++
            ",\"limits\":{\"tls_engines\":4,\"h2_streams\":8,\"quic_connections\":5}}",
    );
    // The bind is an IP literal: a hostname does not parse, and a socket
    // file parses and carries no datagram.
    try expectParseError(
        error.ListenerQuicBindInvalid,
        http ++ ",\"quic\":{\"bind\":\"localhost:443\"}}" ++ tls ++ tail_head ++ streams,
    );
    try expectParseError(
        error.ListenerQuicBindNotIp,
        http ++ ",\"quic\":{\"bind\":\"unix:/run/zoxy.sock\"}}" ++ tls ++ tail_head ++ streams,
    );
    // Pools are sized on a binding's presence, as on every feature's
    // (`countListenerFeatures`): a missing stream pool outranks a bind
    // that is refused once the listener itself resolves.
    try expectParseError(
        error.LimitH2StreamsRequired,
        http ++ ",\"quic\":{\"bind\":\"unix:/run/zoxy.sock\"}}" ++ tls ++ tail_head ++ "}",
    );
    try expectParseError(error.ListenerQuicAltSvcMaxAgeOutOfRange, http ++ std.fmt.comptimePrint(
        ",\"quic\":{{\"bind\":\"127.0.0.1:1\",\"alt_svc_max_age_s\":{d}}}}}",
        .{constants.alt_svc_max_age_s_max + 1},
    ) ++ tls ++ tail_head ++ streams);
    // An http body's key only: a relay has no HTTP/3 to serve.
    try expectParseError(
        error.UnknownField,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"," ++
            "\"quic\":{\"bind\":\"127.0.0.1:1\"}}" ++ tls ++ tail_head ++ "}",
    );
}

test "config: two listeners' quic bindings may not share a UDP address (#449)" {
    const tail = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}," ++
        "\"limits\":{\"h2_streams\":8}}";
    const tls = ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"}";
    const first = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\"," ++
        "\"http\":{\"cluster\":\"a\",\"quic\":{\"bind\":\"127.0.0.1:443\"}}" ++ tls;
    const second_at = "},{\"bind\":\"127.0.0.1:443\",\"http\":{\"cluster\":\"a\",\"quic\":{\"bind\":";

    // A UDP port is not a TCP one: the second listener's TCP bind is the
    // first one's UDP bind, and its own UDP bind is free.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, first ++ second_at ++ "\"127.0.0.1:444\"}}" ++ tls ++ tail);
        try std.testing.expect(parsed.listeners[0].quic != null);
        try std.testing.expect(parsed.listeners[1].quic != null);
        try std.testing.expect(parsed.limits.quic_connections >= 1);
    }
    try expectParseError(error.ListenerQuicBindDuplicate, first ++ second_at ++ "\"127.0.0.1:443\"}}" ++ tls ++ tail);
    // Equal as addresses, not as text.
    try expectParseError(
        error.ListenerQuicBindDuplicate,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"quic\":{\"bind\":\"[::1]:443\"}}" ++ tls ++
            "},{\"bind\":\"127.0.0.1:3\",\"http\":{\"cluster\":\"a\",\"quic\":{\"bind\":\"[0:0::1]:443\"}}" ++ tls ++ tail,
    );
}

test "config: tls_engines follows the tls listeners, and refuses a mismatch" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}";
    const tls_block = ",\"tls\":{\"cert\":\"/c.pem\",\"key\":\"/k.pem\"}";
    const tail = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}";
    const close = "}";

    // No TLS listener: the pool is zero, so a plaintext deployment
    // reserves nothing for a feature it does not use.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tail ++ close);
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.tls_engines);
    }
    // A TLS listener with no stated limit: conn slots, capped at the
    // engine ceiling — every connection could be mid-handshake at once.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ tls_block ++ tail ++ close);
        try std.testing.expectEqual(
            @min(constants.tls_engines_default, parsed.limits.conn_slots),
            parsed.limits.tls_engines,
        );
        try std.testing.expect(parsed.limits.tls_engines >= 1);
    }
    // The default is capped by conn slots, not just by the ceiling: a
    // deployment that shrank its slots must not out-provision them.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tls_block ++ tail ++ ",\"limits\":{\"conn_slots\":4}" ++ close,
        );
        try std.testing.expectEqual(@as(u32, 4), parsed.limits.tls_engines);
    }
    // Stated explicitly, it is honored — this is the knob a TLS
    // deployment trades memory against the shed wall with.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ tls_block ++ tail ++ ",\"limits\":{\"tls_engines\":16}" ++ close,
        );
        try std.testing.expectEqual(@as(u32, 16), parsed.limits.tls_engines);
    }
    // Engines nobody can use: paid for in RSS, drawn from never. Said so
    // rather than silently zeroed, because the operator asked for a thing
    // and the answer is that this config cannot use it.
    try expectParseError(
        error.LimitTlsEnginesWithoutTlsListener,
        head ++ tail ++ ",\"limits\":{\"tls_engines\":16}" ++ close,
    );
    // A TLS listener with no engines would shed every handshake — a
    // listener that accepts and then refuses everything.
    try expectParseError(
        error.LimitTlsEnginesOutOfRange,
        head ++ tls_block ++ tail ++ ",\"limits\":{\"tls_engines\":0}" ++ close,
    );
    // Past the ceiling: an engine is ~92 KiB, so this bound is what
    // stands between a typo and a gigabyte.
    try expectParseError(
        error.LimitTlsEnginesOutOfRange,
        head ++ tls_block ++ tail ++ ",\"limits\":{\"tls_engines\":100000}" ++ close,
    );
    // More engines than connections that could hold one.
    try expectParseError(
        error.LimitTlsEnginesOverConnSlots,
        head ++ tls_block ++ tail ++ ",\"limits\":{\"conn_slots\":4,\"tls_engines\":8}" ++ close,
    );
}

test "config: the cluster proxy_protocol block resolves a version, l4-reachable only" {
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}";
    const middle = "}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]";
    const tail = "}},\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    // Absent: no header is sent — every config predating this.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ middle ++ tail);
        try std.testing.expect(parsed.clusters[0].proxy_protocol_send == null);
    }
    // Both versions resolve on an l4-reachable cluster; neither is a default.
    inline for (.{ "v1", "v2" }) |version| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ middle ++ ",\"proxy_protocol\":{\"send\":\"" ++ version ++ "\"}" ++ tail,
        );
        try std.testing.expectEqual(
            std.meta.stringToEnum(Config.Cluster.ProxyProtocolSend, version).?,
            parsed.clusters[0].proxy_protocol_send.?,
        );
    }
    // An http listener routing to a sending cluster is rejected: a pooled
    // L7 upstream is shared across clients, so the per-connection header
    // would name one client and serve many.
    try expectParseError(
        error.ClusterProxyProtocolOnHttpListener,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\"}" ++ middle ++
            ",\"proxy_protocol\":{\"send\":\"v2\"}" ++ tail,
    );
    // The same cluster reached by an http listener *beside* the l4 one is
    // just as rejected — reachability poisons, not exclusivity.
    try expectParseError(
        error.ClusterProxyProtocolOnHttpListener,
        "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"l4\":{\"cluster\":\"a\"}}," ++
            "{\"bind\":\"127.0.0.1:3\",\"http\":{\"cluster\":\"a\"}" ++ middle ++
            ",\"proxy_protocol\":{\"send\":\"v2\"}" ++ tail,
    );
    // The version vocabulary is closed and `send` is required.
    try expectParseError(
        error.ClusterProxyProtocolSendUnknown,
        head ++ middle ++ ",\"proxy_protocol\":{\"send\":\"v3\"}" ++ tail,
    );
    try expectParseError(
        error.MissingField,
        head ++ middle ++ ",\"proxy_protocol\":{}" ++ tail,
    );
}

test "config: a filter may not name the header zoxy manages" {
    // A filter edit can only write a *constant*, so naming this header
    // encodes one fixed address for every client — it looks like client
    // forwarding and is the opposite of it. Reserved unconditionally, not
    // only on listeners that set it, so one mechanism owns the header.
    const head = "{\"listeners\":[{\"bind\":\"127.0.0.1:1\",\"http\":{\"cluster\":\"a\",\"request_filters\":[";
    const tail = "]}}],\"clusters\":{\"a\":{\"endpoints\":[\"127.0.0.1:2\"]}}," ++
        "\"timeouts\":{\"connect_ms\":1,\"idle_ms\":2,\"drain_deadline_ms\":1}}";

    inline for (.{ "header_set", "header_add" }) |action| {
        try expectParseError(error.FilterHeaderNameReserved, head ++
            "{\"actions\":[{\"" ++ action ++
            "\":{\"name\":\"X-Forwarded-For\",\"value\":\"1.2.3.4\"}}]}" ++ tail);
    }
    // Case-insensitively, per RFC 9110 field-name comparison.
    try expectParseError(error.FilterHeaderNameReserved, head ++
        "{\"actions\":[{\"header_remove\":\"x-forwarded-for\"}]}" ++ tail);
    // The verified client's identity is the proxy's to write (#304).
    try expectParseError(error.FilterHeaderNameReserved, head ++
        "{\"actions\":[{\"header_set\":{\"name\":\"X-Client-Cert-SHA256\",\"value\":\"00\"}}]}" ++ tail);
    try expectParseError(error.FilterHeaderNameReserved, head ++
        "{\"actions\":[{\"header_remove\":\"x-client-cert-sha256\"}]}" ++ tail);
    // A neighbouring name is still editable — the guard is the header, not
    // a prefix of it.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++
            "{\"actions\":[{\"header_set\":{\"name\":\"X-Forwarded-Proto\",\"value\":\"https\"}}]}" ++ tail);
        try std.testing.expectEqual(@as(usize, 1), parsed.listeners[0].request_filters.len);
    }
}

test "config: retries resolves, defaults to none, rejects past the ceiling and on HTTP/2" {
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:2","127.0.0.1:3"],"retries":2},
            \\   "b":{"endpoints":["127.0.0.1:4"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(@as(u16, 2), parsed.clusters[0].retries);
        // Absent is no retry, which is what every config written before
        // the key existed asked for and must keep getting (#181).
        try std.testing.expectEqual(@as(u16, 0), parsed.clusters[1].retries);
    }
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"retries":
    ;
    const tail =
        \\}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    // Zero is the default rather than a typo, so it loads; past the
    // ceiling is refused rather than clamped, because a number the proxy
    // will not honor should be heard about at load.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "0" ++ tail);
        try std.testing.expectEqual(@as(u16, 0), parsed.clusters[0].retries);
    }
    {
        var buffer: [512]u8 = undefined;
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const json = try std.fmt.bufPrint(
            &buffer,
            "{s}{d}{s}",
            .{ head, constants.cluster_retries_max, tail },
        );
        const parsed = try expectParseOk(&arena_state, json);
        try std.testing.expectEqual(constants.cluster_retries_max, parsed.clusters[0].retries);
    }
    {
        var buffer: [512]u8 = undefined;
        const json = try std.fmt.bufPrint(
            &buffer,
            "{s}{d}{s}",
            .{ head, constants.cluster_retries_max + 1, tail },
        );
        try expectParseError(error.ClusterRetriesOutOfRange, json);
    }
    // An HTTP/2 cluster's connections are dialed by its pool, never by a
    // request, so a retry budget there would be read and never spent:
    // refused rather than ignored (#400). Zero is the default and loads.
    const h2c_head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:2"],"protocol":"h2c","retries":
    ;
    try expectParseError(error.ClusterRetriesOnHttp2, h2c_head ++ "1" ++ tail);
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, h2c_head ++ "0" ++ tail);
        try std.testing.expectEqual(@as(u16, 0), parsed.clusters[0].retries);
    }
}

test "config: the upgrade allowlist is closed, http-only, and never empty" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a",
        \\ "upgrades":
    ;
    const tail =
        \\}},{"bind":"127.0.0.1:2","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "limits":{"tunnels":16},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "{\"websocket\":true}" ++ tail);
        try std.testing.expect(parsed.listeners[0].upgrades.websocket);
        try std.testing.expect(parsed.listeners[0].upgrades.any());
        // Per listener, and the l4 one beside it allows nothing — which is
        // what every config predating the key keeps getting.
        try std.testing.expect(!parsed.listeners[1].upgrades.any());
        try std.testing.expectEqual(@as(u32, 16), parsed.limits.tunnels);
    }
    // A protocol this proxy cannot reason about is refused by name,
    // never ignored: `h2c` would tunnel HTTP/2 to an origin it cannot
    // parse, and a config that asked for it and got silence would
    // believe it had — with no rule left after 101 to catch what came
    // through. As a field rather than a token, that refusal is the
    // strict parser's and the schema's, not a rule of the loader's
    // (#305) — and a duplicate stops being expressible at all, where
    // the list form accepted `["websocket", "websocket"]` unchecked.
    try expectParseError(error.UnknownField, head ++ "{\"h2c\":true}" ++ tail);
    try expectParseError(
        error.UnknownField,
        head ++ "{\"websocket\":true,\"h2c\":true}" ++ tail,
    );
    // And "allow none" needs no rejection any more. An empty *list* was
    // a meaningless spelling of a set; a set of flags all false is the
    // ordinary way to write "not this one", means what omitting the
    // block means, and reserves nothing — so the error this used to
    // raise is gone rather than moved.
    // Without a `tunnels` limit, because an all-false block reserves
    // nothing — asking for a pool beside one is still the §5 mismatch
    // it always was, and the case below pins that too.
    const quiet_tail =
        \\}},{"bind":"127.0.0.1:2","l4":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    ;
    inline for (.{ "{}", "{\"websocket\":false}" }) |spelling| {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ spelling ++ quiet_tail);
        try std.testing.expect(!parsed.listeners[0].upgrades.any());
        // Reserves nothing, which is what says it is absence rather than
        // a listener asking for a pool it can never use (§5).
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.tunnels);
        // And it is exactly absence: a pool beside it is the same
        // mismatch omitting the block would earn.
        try expectParseError(
            error.LimitTunnelsWithoutUpgrades,
            head ++ spelling ++ tail,
        );
    }
}

test "config: upgrades are refused on an l4 listener" {
    // A byte relay parses no handshake to recognise, so there is nothing
    // here for it to allow. The `l4` body has no such key (#305), so the
    // refusal is the strict parser's rather than a rule's — a block that
    // quietly did nothing was never the alternative.
    try expectParseError(error.UnknownField,
        \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a","upgrades":{"websocket":true}}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "limits":{"tunnels":4},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
}

test "config: the tunnel pool has no derived default, and binds to the allowlist" {
    const with_upgrades =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a",
        \\ "upgrades":{"websocket":true}}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}
    ;
    // Every other optional pool derives a fallback that can only be too
    // generous; a count of long-lived sessions has no such number behind
    // it, so the omission is refused where the operator is looking rather
    // than surfacing later as tunnels shed under load.
    try expectParseError(error.LimitTunnelsRequired, with_upgrades ++ "}");
    // A pool of zero beside a listener that allows upgrades would refuse
    // every one of them — the same contradiction as a zero head ring on
    // an http deployment.
    try expectParseError(
        error.LimitTunnelsOutOfRange,
        with_upgrades ++ ",\"limits\":{\"tunnels\":0}}",
    );
    // And a pool nothing can draw on is the mirror image: asked for, and
    // unusable.
    try expectParseError(error.LimitTunnelsWithoutUpgrades,
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "limits":{"tunnels":8},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
    );
    // Zero exactly when no listener allows an upgrade, so one number says
    // both how many tunnels there may be and whether the feature is on.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state,
            \\{"listeners":[{"bind":"127.0.0.1:1","l4":{"cluster":"a"}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
        );
        try std.testing.expectEqual(@as(u32, 0), parsed.limits.tunnels);
    }
}

test "config: the tunnel pool may not exceed the connections that hold one" {
    // Not arithmetic hygiene: this bound is what leaves the fd and ring
    // budgets untouched by the feature (§5). A tunnel is an accepted
    // client connection, so `fdsRequired`'s two-sockets-per-connection
    // already covers its pair — but only while every tunnel has a
    // connection to be.
    var buffer: [512]u8 = undefined;
    const json = try std.fmt.bufPrint(
        &buffer,
        "{s}{d}{s}",
        .{
            \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a",
            \\ "upgrades":{"websocket":true}}}],
            \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
            \\ "limits":{"conn_slots":8,"tunnels":
            ,
            @as(u32, 9),
            \\},
            \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1}}
            ,
        },
    );
    try expectParseError(error.LimitTunnelsOverConnSlots, json);
}

test "config: tunnel_ms defaults to an hour and has no off switch" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a",
        \\ "upgrades":{"websocket":true}}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "limits":{"tunnels":4},
        \\ "timeouts":{"connect_ms":1,"idle_ms":2,"drain_deadline_ms":1
    ;
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "}}");
        try std.testing.expectEqual(
            constants.tunnel_ms_default,
            parsed.tunnel_timeout_ms,
        );
    }
    // Zero is legal for `max_lifetime_ms` and `request_ms` and means "no
    // cap". It cannot mean that here: a tunnel pins a dedicated pool slot
    // for its whole life, and an unbounded hold on a bounded pool is the
    // one thing that model cannot absorb.
    try expectParseError(error.TimeoutTunnelOutOfRange, head ++ ",\"tunnel_ms\":0}}");
    // The floor is a floor, not a nonzero check: a sub-second lifetime
    // would reap every session on arrival, which reads as a typo.
    try expectParseError(error.TimeoutTunnelOutOfRange, head ++ ",\"tunnel_ms\":999}}");
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ ",\"tunnel_ms\":1000}}");
        try std.testing.expectEqual(constants.tunnel_ms_min, parsed.tunnel_timeout_ms);
    }
}

test "config: the head budget is derived from its neighbours, never fixed" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "timeouts":{"drain_deadline_ms":1,
    ;
    const tail = "}}";
    // The ordinary shape: the default lands as itself, an order of
    // magnitude under the idle window it tightens (#235).
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"connect_ms\":5000,\"idle_ms\":60000" ++ tail,
        );
        try std.testing.expectEqual(constants.head_ms_default, parsed.head_timeout_ms);
    }
    // A config whose whole idle window is under the default keeps it: the
    // head budget tightens the idle one, so it can never exceed it. This
    // is most hand-written test configs, and every one of them predates
    // the field.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"connect_ms\":1,\"idle_ms\":2" ++ tail,
        );
        try std.testing.expectEqual(@as(u32, 2), parsed.head_timeout_ms);
    }
    // The shape a flat default would have broken *silently*: a dial budget
    // above the default. The head budget would have sat below it, and the
    // lazy timer cannot lengthen at the re-base — so the dial would have
    // been cut to ten seconds by a field the operator never set.
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(
            &arena_state,
            head ++ "\"connect_ms\":20000,\"idle_ms\":60000" ++ tail,
        );
        try std.testing.expect(parsed.head_timeout_ms > 20000);
    }
}

test "config: head_ms must sit strictly above the dial and at or below the idle" {
    const head =
        \\{"listeners":[{"bind":"127.0.0.1:1","http":{"cluster":"a"}}],
        \\ "clusters":{"a":{"endpoints":["127.0.0.1:9"]}},
        \\ "timeouts":{"drain_deadline_ms":1,"connect_ms":5000,"idle_ms":60000,"head_ms":
    ;
    const tail = "}}";
    {
        var arena_state: std.heap.ArenaAllocator = undefined;
        defer arena_state.deinit();
        const parsed = try expectParseOk(&arena_state, head ++ "9000" ++ tail);
        try std.testing.expectEqual(@as(u32, 9000), parsed.head_timeout_ms);
    }
    // Both inversions are rejected rather than clamped, on the same
    // grounds as `connect_ms < idle_ms`: the single lazy timer only ever
    // moves earlier, so either one would leave the wider value quietly in
    // force and the config would behave differently than it reads.
    try expectParseError(error.TimeoutOrderInvalid, head ++ "5000" ++ tail);
    try expectParseError(error.TimeoutOrderInvalid, head ++ "4000" ++ tail);
    try expectParseError(error.TimeoutOrderInvalid, head ++ "60001" ++ tail);
    try expectParseError(error.TimeoutOverLimit, head ++ "0" ++ tail);
}
