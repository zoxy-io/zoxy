//! zoxy-edge's proxy (#417): what this build adds to zoxy, and the options
//! it runs, stated in code. Nothing here reads a file or names JSON — the
//! stock binary's front-end is not a module this package can import, and
//! it needs none: the endpoints arrive from its command line, which is
//! the "discovery" a build does before its options exist.
//!
//! The build lists two picker types and two request policies:
//!
//! - `LeastInFlight` picks the endpoint with the fewest requests in
//!   flight. One instance serves both the `api` and `search` clusters, so
//!   what it counts is shared between them.
//! - `PathAffinity` hashes the request path to an endpoint, so one path
//!   keeps landing on one endpoint while the set holds still — the
//!   `static` cluster's cache affinity.
//! - `TenantGuard`, on the listener, refuses a request that names no
//!   tenant, before the filters and the routing run.
//! - `ReadOnly`, on the `/static` route, refuses anything but a read once
//!   the route is chosen and before any connection is taken for it.
//!
//! Each obeys the contract every extension does: run to completion, no
//! allocation, no clock, no syscall, nothing kept from a view past the
//! call — so the simulator replays a seed exactly with them in it.
//!
//! `LeastInFlight` and `TenantGuard` also count what they do in series of
//! their own (#435), which the metrics endpoint renders once per cluster
//! and per listener: `zoxy_ext_least_in_flight_picks{cluster="api"}`.

const std = @import("std");

const zoxy = @import("zoxy");

const assert = std.debug.assert;

pub const extensions: zoxy.Extensions = .{
    .pickers = &.{ LeastInFlight, PathAffinity },
    .request_policies = &.{ TenantGuard, ReadOnly },
};

pub const App = zoxy.App(extensions);

/// The header a request names its tenant in.
pub const tenant_header = "x-tenant";

/// The endpoint with the fewest requests in flight; among equals, the one
/// offered first, so the choice is a function of what zoxy offered.
pub const LeastInFlight = struct {
    /// Clusters that selected this instance.
    clusters: u16 = 0,

    pub const metrics_prefix = "least_in_flight";
    pub const counters = .{ .picks = "Picks the least-in-flight picker made." };
    pub const gauges = .{ .chosen_in_flight = "Requests in flight at the endpoint the last pick chose." };

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

/// A request names its tenant, or is refused before anything else looks
/// at it.
pub const TenantGuard = struct {
    /// The header a request names its tenant in.
    header: []const u8 = tenant_header,

    pub const metrics_prefix = "tenant_guard";
    pub const counters = .{ .refused = "Requests refused for naming no tenant." };

    pub fn evaluate(guard: *TenantGuard, request: *const zoxy.extension.Request) zoxy.extension.Verdict {
        assert(request.cluster_index == null); // The listener phase.
        assert(guard.header.len >= 1);
        for (request.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, guard.header) and header.value.len >= 1) {
                return .proceed;
            }
        }
        request.metrics.add(TenantGuard, .refused, 1);
        return .{ .reject = .forbidden };
    }
};

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

/// The build's extension instances: options select these by address, so
/// they live as long as the server does.
pub const Instances = struct {
    least_in_flight: LeastInFlight = .{},
    path_affinity: PathAffinity = .{},
    tenant_guard: TenantGuard = .{},
    read_only: ReadOnly = .{},
};

/// What the command line discovered.
pub const Plan = struct {
    listen: std.Io.net.IpAddress,
    /// The application's endpoints: the `api` and `search` clusters both
    /// draw on them.
    app: []const std.Io.net.IpAddress,
    /// The static-content endpoints.
    static: []const std.Io.net.IpAddress,
};

/// zoxy-edge's options: one HTTP listener guarded by `TenantGuard`, with
/// `/static` read-only and path-affine, `/search` and everything else to
/// the application through one shared `LeastInFlight`. Allocated in
/// `arena`, which the caller keeps for as long as the options run.
pub fn options(
    arena: std.mem.Allocator,
    instances: *Instances,
    plan: *const Plan,
) error{OutOfMemory}!zoxy.Options {
    assert(plan.app.len >= 1);
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
    const listeners = try arena.dupe(zoxy.Options.Listener, &.{.{
        .bind = .{ .ip = plan.listen },
        .protocol = .{ .http = .{
            .target = .{ .routes = routes },
            .request_policies = try arena.dupe(zoxy.extension.Selection, &.{App.policy(&instances.tenant_guard)}),
            .max_body_bytes = zoxy.defaults.max_body_bytes,
            .keepalive_requests = zoxy.defaults.keepalive_requests,
        } },
    }});
    const app = try endpoints(arena, plan.app);
    const clusters = try arena.dupe(zoxy.Options.Cluster, &.{
        .{ .name = "api", .endpoints = app, .pick = App.picker(&instances.least_in_flight) },
        .{ .name = "search", .endpoints = app, .pick = App.picker(&instances.least_in_flight) },
        .{
            .name = "static",
            .endpoints = try endpoints(arena, plan.static),
            .pick = App.picker(&instances.path_affinity),
        },
    });
    return .{
        .listeners = listeners,
        .clusters = clusters,
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
