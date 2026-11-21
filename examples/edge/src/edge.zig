//! zoxy-edge's proxy (#417): what this build adds to zoxy, and the options
//! it runs, stated in code. Nothing here reads a file or names JSON — the
//! stock binary's front-end is not a module this package can import, and
//! it needs none: the endpoints arrive from its command line, which is
//! the "discovery" a build does before its options exist.
//!
//! The build lists two picker types, two request policies, a response
//! policy, a connection policy and a handler:
//!
//! - `LeastInFlight` picks the endpoint with the fewest requests in
//!   flight. One instance serves both the `api` and `search` clusters, so
//!   what it counts is shared between them. It hears how each pick turned
//!   out (#423) and keeps the last time to the origin's first byte.
//! - `PathAffinity` hashes the request path to an endpoint, so one path
//!   keeps landing on one endpoint while the set holds still — the
//!   `static` cluster's cache affinity.
//! - `TenantGuard`, on the listener, answers a request that names no
//!   tenant with a `401` challenge of its own (#431), before the filters
//!   and the routing run. One it lets on carries its tenant as the
//!   request's tag (#433), which the access log records, and upstream in
//!   `x-edge-tenant`, set by the edge (#424) so a client cannot forge
//!   it; and it counts the request in flight until it completes (#429).
//! - `ReadOnly`, on the `/static` route, refuses anything but a read once
//!   the route is chosen and before any connection is taken for it.
//! - `SecurityHeaders`, on the listener's way out (#424), sets the
//!   headers a browser-facing edge owes every response an origin sends,
//!   and drops the one that names the origin's software.
//! - `ConnectionCap`, on the listener (#425), holds the client
//!   connections open at once to a cap. One past it is closed before a
//!   byte of it is read, which no request policy could do: they meet a
//!   connection only once a head arrives.
//! - `EndpointsControl`, the edge's control plane (#434), answers on a
//!   listener of its own, which the operator binds where only operators
//!   reach. A `PUT` of a new application endpoint list replaces the
//!   `api` and `search` clusters' sets while the edge serves (#428): an
//!   endpoint that stays keeps its connections and health, one that
//!   leaves drains, one that arrives takes a free slot.
//!
//! Each obeys the contract every extension does: run to completion, no
//! allocation, no clock, no syscall, nothing kept from a view past the
//! call — so the simulator replays a seed exactly with them in it.
//!
//! `LeastInFlight`, `TenantGuard` and `ConnectionCap` also count what they
//! do in series of their own (#435), which the metrics endpoint renders
//! once per cluster and per listener:
//! `zoxy_ext_least_in_flight_picks{cluster="api"}`.

const std = @import("std");

const zoxy = @import("zoxy");

const assert = std.debug.assert;

pub const extensions: zoxy.Extensions = .{
    .handlers = &.{EndpointsControl},
    .pickers = &.{ LeastInFlight, PathAffinity },
    .request_policies = &.{ TenantGuard, ReadOnly },
    .response_policies = &.{SecurityHeaders},
    .connection_policies = &.{ConnectionCap},
};

pub const App = zoxy.App(extensions);

/// The header a request names its tenant in.
pub const tenant_header = "x-tenant";
/// The header the edge forwards the tenant upstream in: set by
/// `TenantGuard`, which replaces any copy the client sent.
pub const tenant_forward_header = "x-edge-tenant";
/// The longest tenant name `TenantGuard` lets on.
pub const tenant_bytes_max = 64;
/// The most endpoints one list names: on the command line, and in a
/// control-plane update. The application clusters keep this many slots.
pub const endpoints_max = 16;
/// The clusters that draw on the application's endpoints, which the
/// control plane updates together.
pub const app_clusters = [_][]const u8{ "api", "search" };

/// The endpoint with the fewest requests in flight; among equals, the one
/// offered first, so the choice is a function of what zoxy offered.
pub const LeastInFlight = struct {
    /// Clusters that selected this instance.
    clusters: u16 = 0,

    pub const metrics_prefix = "least_in_flight";
    pub const counters = .{
        .picks = "Picks the least-in-flight picker made.",
        .completed = "Picks whose outcome was final.",
        .failed = "Picks that ended in a failed dial, a timeout or an origin failure.",
    };
    pub const gauges = .{
        .chosen_in_flight = "Requests in flight at the endpoint the last pick chose.",
        .head_us = "Microseconds from the last answered pick to its response head.",
    };

    pub fn bind(
        picker: *LeastInFlight,
        cluster: *const zoxy.extension.ClusterSite,
        startup: *const zoxy.extension.Startup,
    ) !void {
        _ = startup;
        assert(cluster.endpoints.len >= 1);
        picker.clusters += 1;
    }

    pub fn pick(
        picker: *LeastInFlight,
        candidates: *const zoxy.extension.Candidates,
        input: *const zoxy.extension.PickInput,
    ) u16 {
        assert(picker.clusters >= 1);
        const count = candidates.count();
        assert(count >= 1);
        var best: u16 = 0;
        var slot: u16 = 1;
        while (slot < count) : (slot += 1) {
            if (candidates.inFlight(slot) < candidates.inFlight(best)) best = slot;
        }
        assert(best < count);
        // Per cluster: zoxy hands each cluster's pick that cluster's slots.
        input.metrics.add(LeastInFlight, .picks, 1);
        input.metrics.set(LeastInFlight, .chosen_in_flight, candidates.inFlight(best));
        return best;
    }

    /// How a pick turned out (#423), once per pick, once it is final: a
    /// latency-steering picker would fold `head_ns - picked_ns` into a
    /// per-endpoint average here; this one keeps the last.
    pub fn complete(picker: *LeastInFlight, done: *const zoxy.extension.Completion) void {
        assert(picker.clusters >= 1);
        assert(done.done_ns >= done.picked_ns);
        done.metrics.add(LeastInFlight, .completed, 1);
        switch (done.outcome) {
            .connect_failed, .timed_out, .failed => done.metrics.add(LeastInFlight, .failed, 1),
            else => {},
        }
        const head_ns = done.head_ns orelse return;
        assert(head_ns >= done.picked_ns);
        done.metrics.set(LeastInFlight, .head_us, (head_ns - done.picked_ns) / std.time.ns_per_us);
    }
};

/// One path, one endpoint: FNV-1a over the canonical path, modulo the
/// endpoints offered. An L4 connection has no path, so it takes the first.
pub const PathAffinity = struct {
    picks: u64 = 0,

    pub fn pick(
        picker: *PathAffinity,
        candidates: *const zoxy.extension.Candidates,
        input: *const zoxy.extension.PickInput,
    ) u16 {
        const count = candidates.count();
        assert(count >= 1);
        picker.picks += 1;
        const request = input.request orelse return 0;
        const slot: u16 = @intCast(std.hash.Fnv1a_64.hash(request.path) % count);
        assert(slot < count);
        return slot;
    }
};

/// A request names its tenant, or is answered with a challenge before
/// anything else looks at it. One it lets on is tagged with its tenant,
/// forwards it in a header the edge sets, and is counted until it ends.
pub const TenantGuard = struct {
    /// The header a request names its tenant in.
    header: []const u8 = tenant_header,
    /// Requests let on that have not completed: what a concurrency limit
    /// counts up on the way in and back down in `complete`.
    in_flight: u32 = 0,
    /// The last verdict's edit. A verdict outlives `evaluate`, so its
    /// edits live here rather than on the stack; zoxy copies them as it
    /// reads the verdict, before the next request's call.
    edits: [1]zoxy.extension.Edit = undefined,

    pub const metrics_prefix = "tenant_guard";
    pub const counters = .{
        .refused = "Requests answered with the tenant challenge.",
        .completed = "Requests let on whose exchange has ended.",
    };
    pub const gauges = .{ .in_flight = "Requests let on whose exchange has not yet ended." };

    /// Its own answer (#431), rendered once at startup: the static four
    /// have no `401`, and a challenge names its scheme.
    pub const answers = .{
        .challenge = zoxy.extension.Answer{
            .status = 401,
            .headers = &.{.{ .name = "WWW-Authenticate", .value = "Tenant realm=\"edge\"" }},
            .body = "name your tenant in x-tenant\n",
        },
    };
    /// What one verdict's edits may copy (#424): the forwarded header and
    /// the longest tenant.
    pub const edit_bytes_max = tenant_forward_header.len + tenant_bytes_max;

    pub fn evaluate(guard: *TenantGuard, request: *const zoxy.extension.Request) zoxy.extension.Verdict {
        assert(request.cluster_index == null); // The listener phase.
        assert(guard.header.len >= 1);
        const tenant = tenantOf(request, guard.header) orelse {
            request.metrics.add(TenantGuard, .refused, 1);
            return zoxy.extension.respond(TenantGuard, .challenge);
        };
        assert(tenant.len <= tenant_bytes_max);
        guard.in_flight += 1;
        request.metrics.set(TenantGuard, .in_flight, guard.in_flight);
        // The value is the request's own, which zoxy still holds when it
        // copies the edit; `set` replaces every copy the client sent. It
        // must stay a valid field value within `edit_bytes_max`, which
        // `tenantOf` guarantees: an edit zoxy refused would answer `400`
        // without this request ever completing, and `in_flight` would
        // count it forever.
        guard.edits = .{.{ .set = .{ .name = tenant_forward_header, .value = tenant } }};
        return .{ .proceed_with = .{ .tag = tenantTag(tenant), .edits = &guard.edits } };
    }

    /// How a request it let on ended (#429): exactly once, at its
    /// access-log line, whatever ended it — the route's `ReadOnly`
    /// refusing it included.
    pub fn complete(guard: *TenantGuard, done: *const zoxy.extension.RequestCompletion) void {
        assert(guard.in_flight >= 1);
        assert(done.route_index == null); // It sits on the listener only.
        guard.in_flight -= 1;
        done.metrics.add(TenantGuard, .completed, 1);
        done.metrics.set(TenantGuard, .in_flight, guard.in_flight);
    }
};

/// The tenant `header` names, when it names exactly one `TenantGuard`
/// lets on: 1 to `tenant_bytes_max` letters, digits and dashes — a name
/// that is safe in a header and in a URL as it stands. Two lines naming
/// a tenant name none: which one an origin would read is not the edge's
/// to guess.
pub fn tenantOf(request: *const zoxy.extension.Request, header: []const u8) ?[]const u8 {
    assert(header.len >= 1);
    var tenant: ?[]const u8 = null;
    for (request.headers) |line| {
        if (!std.ascii.eqlIgnoreCase(line.name, header)) continue;
        if (tenant != null) return null;
        const value = line.value;
        if (value.len == 0 or value.len > tenant_bytes_max) return null;
        for (value) |octet| {
            if (!std.ascii.isAlphanumeric(octet) and octet != '-') return null;
        }
        tenant = value;
    }
    if (tenant) |value| assert(value.len <= tenant_bytes_max);
    return tenant;
}

/// A tenant's tag (#433): its FNV-1a hash, which the access log records
/// as `"tag":N` and every later view of the request carries. Never zero,
/// which would mean no tag.
pub fn tenantTag(tenant: []const u8) u64 {
    assert(tenant.len >= 1);
    return @max(std.hash.Fnv1a_64.hash(tenant), 1);
}

/// The route this sits on is read-only: anything but `GET` and `HEAD` is
/// refused once the route is chosen, before a connection is taken for it.
pub const ReadOnly = struct {
    refused: u64 = 0,

    pub fn evaluate(guard: *ReadOnly, request: *const zoxy.extension.Request) zoxy.extension.Verdict {
        assert(request.cluster_index != null); // The route phase.
        switch (request.method) {
            .get, .head => return .proceed,
            else => {
                guard.refused += 1;
                return .{ .reject = .forbidden };
            },
        }
    }
};

/// What every response leaving the edge carries, whatever its origin
/// sent (#424): edits the response filters could state too, here in code
/// beside the build's other policies. They see the origin's final head
/// only — the edge's own pages, `TenantGuard`'s challenge among them,
/// are zoxy's and never shown to a response policy.
pub const SecurityHeaders = struct {
    /// Responses it edited: its own count, since a response policy
    /// declares no metrics yet.
    edited: u64 = 0,

    const edits = [_]zoxy.extension.Edit{
        .{ .set = .{ .name = "x-content-type-options", .value = "nosniff" } },
        .{ .set = .{ .name = "x-frame-options", .value = "DENY" } },
        .{ .remove = "x-powered-by" },
    };

    /// What its edits copy, which the stream's scratch is priced by.
    pub const edit_bytes_max = blk: {
        var total: u32 = 0;
        for (edits) |edit| total += edit.bytes();
        break :blk total;
    };

    comptime {
        assert(edits.len <= zoxy.extension.edits_per_verdict_max);
    }

    pub fn evaluate(policy: *SecurityHeaders, response: *const zoxy.extension.Response) zoxy.extension.ResponseVerdict {
        // A final response: interim and upgrade responses divert first.
        assert(response.status >= 200);
        assert(response.status != 101);
        policy.edited += 1;
        return .{ .edits = &edits };
    }
};

/// At most `connections_max` client connections open on its listener at
/// once (#425). Past that, a new one is closed with a FIN before its
/// first byte is read: no handshake, no request head, no request policy.
/// It counts a connection up when it lets it on, and `complete` counts it
/// down at the connection's release.
pub const ConnectionCap = struct {
    connections_max: u32 = 1024,
    /// Connections it let on that have not been released.
    open: u32 = 0,

    pub const metrics_prefix = "connection_cap";
    pub const counters = .{ .refused = "Connections closed for the listener being at its cap." };
    pub const gauges = .{ .open = "Client connections open on the listener." };

    pub fn evaluate(cap: *ConnectionCap, connection: *const zoxy.extension.Connection) zoxy.extension.ConnectionVerdict {
        assert(connection.route_index == null); // The listener's phase.
        assert(cap.open <= cap.connections_max);
        if (cap.open == cap.connections_max) {
            connection.metrics.add(ConnectionCap, .refused, 1);
            return .reject;
        }
        cap.open += 1;
        connection.metrics.set(ConnectionCap, .open, cap.open);
        return .proceed;
    }

    /// Heard once for each connection it let on, at its release.
    pub fn complete(cap: *ConnectionCap, done: *const zoxy.extension.ConnectionCompletion) void {
        assert(cap.open >= 1);
        assert(done.done_ns >= done.started_ns);
        cap.open -= 1;
        done.metrics.set(ConnectionCap, .open, cap.open);
    }
};

/// The edge's control plane (#434, #428): `PUT /endpoints` with a body of
/// comma- or newline-separated `IP:port` literals makes them the
/// application's endpoints, in both `app_clusters`, without a reload.
/// Anything but a `PUT` is `405`.
///
/// Each cluster applies the list all at once or not at all, but the two
/// are asked in turn and nothing rolls back: the second can refuse for
/// room (`SlotsExhausted`, `409`) while slots of its own still drain,
/// leaving `api` on the new list and `search` on the old. The answer
/// names which, and the `PUT` is idempotent — an endpoint already in a
/// set keeps its slot — so the operator retries once the drain is done.
///
/// No authentication: where its listener is bound is this example's only
/// guard, and whoever reaches it moves all of the application's traffic.
/// A real build guards the route with a request policy — a token, or on
/// a mutual-TLS listener the client certificate's names (#432) — or
/// serves it on a `unix:` socket.
pub const EndpointsControl = struct {
    /// The application clusters' sets, taken at `bind`: what the handler
    /// changes while it serves.
    sets: [app_clusters.len]?zoxy.extension.EndpointSet = @splat(null),
    /// Lists both clusters took: what an operator's tooling would expose.
    /// A list only the first took is not counted.
    updates: u64 = 0,
    /// The list being parsed, per request: the handler runs to
    /// completion, so one serves every call.
    parsed: [endpoints_max]zoxy.extension.EndpointSet.Endpoint = undefined,

    pub const response_bytes_max = 2048;

    pub fn bind(
        control: *EndpointsControl,
        site: *const zoxy.extension.PolicySite,
        startup: *const zoxy.extension.Startup,
    ) !void {
        // A handler route sends to no cluster.
        assert(site.route_index != null);
        assert(site.cluster_index == null);
        for (app_clusters, &control.sets) |name, *set| {
            set.* = startup.endpointSet(name) orelse return error.EndpointSlotsMissing;
        }
    }

    pub fn handle(
        control: *EndpointsControl,
        request: *const zoxy.extension.Request,
        body: []const u8,
        response: *zoxy.extension.HandlerResponse,
    ) void {
        assert(request.cluster_index == null);
        for (control.sets) |set| assert(set != null);
        response.header("Content-Type", "text/plain; charset=utf-8");
        if (request.method != .put) {
            response.status = 405;
            response.header("Allow", "PUT");
            response.write("PUT a comma-separated list of IP:port endpoints\n");
            return;
        }
        const list = control.parse(body) orelse {
            response.status = 400;
            response.print("not a list of 1 to {d} IP:port endpoints\n", .{endpoints_max});
            return;
        };
        for (app_clusters, control.sets, 0..) |name, set, index| {
            set.?.replace(list) catch |err| {
                response.status = if (err == error.SlotsExhausted) 409 else 400;
                response.print("{s} refused the list: {s}", .{ name, @errorName(err) });
                if (index > 0) response.print(", after {s} took it", .{app_clusters[0]});
                response.write("\n");
                return;
            };
        }
        control.updates += 1;
        response.print("{d} endpoint(s) now serve", .{list.len});
        for (app_clusters) |name| response.print(" {s}", .{name});
        response.write("\n");
    }

    /// `body` as endpoints, weight 1 each, or null when it is not a list
    /// of 1 to `endpoints_max` IP literals with ports. Validation beyond
    /// the syntax — a zero port, a duplicate — is the set's.
    fn parse(control: *EndpointsControl, body: []const u8) ?[]const zoxy.extension.EndpointSet.Endpoint {
        assert(control.parsed.len == endpoints_max);
        var count: u16 = 0;
        var literals = std.mem.tokenizeAny(u8, body, ", \t\r\n");
        while (literals.next()) |literal| {
            if (count == endpoints_max) return null;
            const address = std.Io.net.IpAddress.parseLiteral(literal) catch return null;
            control.parsed[count] = .{ .address = address };
            count += 1;
        }
        assert(count <= endpoints_max);
        if (count == 0) return null;
        return control.parsed[0..count];
    }
};

/// The build's extension instances: options select these by address, so
/// they live as long as the server does.
pub const Instances = struct {
    least_in_flight: LeastInFlight = .{},
    path_affinity: PathAffinity = .{},
    tenant_guard: TenantGuard = .{},
    read_only: ReadOnly = .{},
    security_headers: SecurityHeaders = .{},
    connection_cap: ConnectionCap = .{},
    endpoints_control: EndpointsControl = .{},
};

/// What the command line discovered.
pub const Plan = struct {
    listen: std.Io.net.IpAddress,
    /// The control plane's own listener: bind it where only operators
    /// reach, loopback say, since what it answers changes the edge.
    control: std.Io.net.IpAddress,
    /// The application's endpoints: the `api` and `search` clusters both
    /// draw on them.
    app: []const std.Io.net.IpAddress,
    /// The static-content endpoints.
    static: []const std.Io.net.IpAddress,
    /// Log every request to standard output, its tenant's tag in it: the
    /// binary does, and the simulator tests, which read no log, do not.
    log_requests: bool = false,
};

/// zoxy-edge's options: one HTTP listener, its connections capped by
/// `ConnectionCap`, its requests guarded by `TenantGuard` and its
/// responses edited by `SecurityHeaders`, with `/static` read-only and
/// path-affine, `/search` and everything else to the application through
/// one shared `LeastInFlight`; and the control plane's listener, whose
/// one route `EndpointsControl` answers. Allocated in `arena`, which the
/// caller keeps for as long as the options run.
pub fn options(
    arena: std.mem.Allocator,
    instances: *Instances,
    plan: *const Plan,
) error{OutOfMemory}!zoxy.Options {
    assert(plan.app.len >= 1);
    assert(plan.app.len <= endpoints_max);
    assert(plan.static.len >= 1);
    const routes = try arena.dupe(zoxy.Options.Listener.Route, &.{
        .{
            .prefix = "/static",
            .cluster = "static",
            .request_policies = try arena.dupe(zoxy.extension.Selection, &.{App.policy(&instances.read_only)}),
        },
        .{ .prefix = "/search", .cluster = "search" },
        .{ .prefix = "/", .cluster = "api" },
    });
    const control_routes = try arena.dupe(zoxy.Options.Listener.Route, &.{
        .{ .prefix = "/endpoints", .handler = App.handler(&instances.endpoints_control) },
    });
    const listeners = try arena.dupe(zoxy.Options.Listener, &.{ .{
        .bind = .{ .ip = plan.listen },
        .protocol = .{ .http = .{
            .target = .{ .routes = routes },
            .request_policies = try arena.dupe(zoxy.extension.Selection, &.{App.policy(&instances.tenant_guard)}),
            .response_policies = try arena.dupe(
                zoxy.extension.Selection,
                &.{App.responsePolicy(&instances.security_headers)},
            ),
            .max_body_bytes = zoxy.defaults.max_body_bytes,
            .keepalive_requests = zoxy.defaults.keepalive_requests,
        } },
        .connection_policies = try arena.dupe(
            zoxy.extension.Selection,
            &.{App.connectionPolicy(&instances.connection_cap)},
        ),
    }, .{
        .bind = .{ .ip = plan.control },
        .protocol = .{ .http = .{
            .target = .{ .routes = control_routes },
            .max_body_bytes = zoxy.defaults.max_body_bytes,
            .keepalive_requests = zoxy.defaults.keepalive_requests,
        } },
    } });
    const app = try endpoints(arena, plan.app);
    const clusters = try arena.dupe(zoxy.Options.Cluster, &.{
        // Slots for the endpoints the control plane may add (#428).
        .{
            .name = app_clusters[0],
            .endpoints = app,
            .endpoint_slots = endpoints_max,
            .pick = App.picker(&instances.least_in_flight),
        },
        .{
            .name = app_clusters[1],
            .endpoints = app,
            .endpoint_slots = endpoints_max,
            .pick = App.picker(&instances.least_in_flight),
        },
        .{
            .name = "static",
            .endpoints = try endpoints(arena, plan.static),
            .pick = App.picker(&instances.path_affinity),
        },
    });
    return .{
        .listeners = listeners,
        .clusters = clusters,
        .access_log = if (plan.log_requests) .{ .sink = .stdout } else null,
        .timeouts = zoxy.defaults.timeouts,
        .limits = zoxy.defaults.limits,
    };
}

fn endpoints(
    arena: std.mem.Allocator,
    addresses: []const std.Io.net.IpAddress,
) error{OutOfMemory}![]const zoxy.Options.Cluster.Endpoint {
    const list = try arena.alloc(zoxy.Options.Cluster.Endpoint, addresses.len);
    for (addresses, list) |address, *endpoint| endpoint.* = .{ .address = .{ .ip = address } };
    assert(list.len == addresses.len);
    return list;
}
