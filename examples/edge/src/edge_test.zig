//! zoxy-edge under the simulator (#417): this build's own pickers and
//! policies through zoxy's serving path, on `zoxy.testing.Bed` — the bed
//! zoxy runs its own extensions through — held to the zero-allocation
//! gate, which also replays the seed and compares the traces.

const std = @import("std");

const zoxy = @import("zoxy");

const edge = @import("edge.zig");

const Bed = zoxy.testing.Bed(edge.extensions);

/// Selected by address from the options, so as long-lived as they are.
/// The gate's two runs select these same instances: state they keep
/// carries from the first run into the second. Only counts that return
/// to zero once a run drains — `TenantGuard.in_flight`,
/// `ConnectionCap.open` — steer a choice, which `exercise` asserts as it
/// begins and ends. A build whose picker keeps other steering state
/// (round-robin's cursor, say) resets it at the start of its scenario, or
/// the replay would diverge for a reason that is not a bug.
var instances: edge.Instances = .{};

fn loopback(port: u16) std.Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
}

const app_endpoints = [_]std.Io.net.IpAddress{ loopback(29001), loopback(29002) };
const static_endpoints = [_]std.Io.net.IpAddress{ loopback(29101), loopback(29102), loopback(29103) };

const plan: edge.Plan = .{
    .listen = loopback(28080),
    .app = &app_endpoints,
    .static = &static_endpoints,
};

const tenant = "Host: edge\r\nx-tenant: acme\r\nConnection: close\r\n\r\n";

fn expectLine(client: *const Bed.Client, line: []const u8) !void {
    if (std.mem.indexOf(u8, client.response(), line) != null) return;
    std.debug.print("expected '{s}' in:\n{s}\n", .{ line, client.response() });
    return error.TestExpectedLine;
}

fn answeredBy(bed: *const Bed, endpoints: []const std.Io.net.IpAddress) u32 {
    var total: u32 = 0;
    for (endpoints) |endpoint| total += bed.answered(endpoint);
    return total;
}

fn isOneOf(body: []const u8, endpoints: []const std.Io.net.IpAddress) bool {
    var buffer: [64]u8 = undefined;
    for (endpoints) |endpoint| {
        const label = std.fmt.bufPrint(&buffer, "{f}", .{endpoint}) catch unreachable;
        if (std.mem.eql(u8, body, label)) return true;
    }
    return false;
}

/// The whole edge, once: both clusters behind the shared picker, the
/// path-affine one twice on one path, and a refusal at each phase.
fn exercise(bed: *Bed) !void {
    // Every request it let on has completed, in the run before this one
    // too: the count a limit would hold starts each run at zero.
    try std.testing.expectEqual(@as(u32, 0), instances.tenant_guard.in_flight);
    try std.testing.expectEqual(@as(u32, 0), instances.connection_cap.open);
    const read_only_refusals_before = instances.read_only.refused;
    const edited_before = instances.security_headers.edited;

    const orders = bed.request(0, "GET /orders HTTP/1.1\r\n" ++ tenant);
    const search = bed.request(0, "GET /search?q=zig HTTP/1.1\r\n" ++ tenant);
    const asset = bed.request(0, "GET /static/app.js HTTP/1.1\r\n" ++ tenant);
    const asset_again = bed.request(0, "GET /static/app.js HTTP/1.1\r\n" ++ tenant);
    const upload = bed.request(0, "POST /static/app.js HTTP/1.1\r\nContent-Length: 0\r\n" ++ tenant);
    const anonymous = bed.request(0, "GET /orders HTTP/1.1\r\nHost: edge\r\nConnection: close\r\n\r\n");
    const two_tenants = bed.request(0, "GET /orders HTTP/1.1\r\nx-tenant: other\r\n" ++ tenant);
    try bed.run();

    // `api` and `search` both pick through the one `LeastInFlight`.
    try std.testing.expectEqual(@as(?u16, 200), orders.status());
    try std.testing.expect(isOneOf(orders.body(), &app_endpoints));
    // Every response an origin sent leaves with the edge's headers
    // (#424); the edge's own pages are zoxy's, and never shown to it.
    try expectLine(orders, "x-content-type-options: nosniff\r\n");
    try expectLine(orders, "x-frame-options: DENY\r\n");
    try std.testing.expect(std.mem.indexOf(u8, anonymous.response(), "x-frame-options") == null);
    try std.testing.expectEqual(@as(?u16, 200), search.status());
    try std.testing.expect(isOneOf(search.body(), &app_endpoints));
    // Counted by the build's own series (#435), which start at zero with
    // each run: one pick in each cluster, summed — and each pick heard
    // its outcome once (#423), neither one failing.
    try std.testing.expectEqual(@as(u64, 2), bed.counter(edge.LeastInFlight, .picks));
    try std.testing.expectEqual(@as(u64, 2), bed.counter(edge.LeastInFlight, .completed));
    try std.testing.expectEqual(@as(u64, 0), bed.counter(edge.LeastInFlight, .failed));

    // One path, one endpoint, on the cluster `PathAffinity` serves.
    try std.testing.expectEqual(@as(?u16, 200), asset.status());
    try std.testing.expect(isOneOf(asset.body(), &static_endpoints));
    try std.testing.expectEqualStrings(asset.body(), asset_again.body());

    // A write to the read-only route is refused once it is routed, and a
    // request with no tenant is challenged before anything looks at it
    // (#431) — neither one reaches an origin.
    try std.testing.expectEqual(@as(?u16, 403), upload.status());
    try std.testing.expectEqual(read_only_refusals_before + 1, instances.read_only.refused);
    try std.testing.expectEqual(@as(?u16, 401), anonymous.status());
    try std.testing.expect(std.mem.indexOf(u8, anonymous.response(), "WWW-Authenticate: Tenant realm=\"edge\"\r\n") != null);
    // Nor does one that names two tenants: which one counts is not the
    // edge's to guess.
    try std.testing.expectEqual(@as(?u16, 401), two_tenants.status());
    try std.testing.expectEqual(@as(u64, 2), bed.counter(edge.TenantGuard, .refused));
    // Every request it let on completed once (#429) — the upload the
    // route refused after it included — and none is still counted.
    try std.testing.expectEqual(@as(u64, 5), bed.counter(edge.TenantGuard, .completed));
    try std.testing.expectEqual(@as(u32, 0), instances.tenant_guard.in_flight);
    // One response policy call per origin response: the four answered,
    // and none of the edge's own pages.
    try std.testing.expectEqual(edited_before + 4, instances.security_headers.edited);
    // Every connection let on was released, and none met the cap.
    try std.testing.expectEqual(@as(u32, 0), instances.connection_cap.open);
    try std.testing.expectEqual(@as(u64, 0), bed.counter(edge.ConnectionCap, .refused));
    try std.testing.expectEqual(@as(u32, 2), answeredBy(bed, &app_endpoints));
    try std.testing.expectEqual(@as(u32, 2), answeredBy(bed, &static_endpoints));
}

test "zoxy-edge: one picker instance serves two clusters, and each phase refuses (#417)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const options = try edge.options(arena.allocator(), &instances, &plan);
    const bed = try std.testing.allocator.create(Bed);
    defer std.testing.allocator.destroy(bed);
    const binds_before = instances.least_in_flight.clusters;
    try bed.setUp(std.testing.allocator, &options, 0x0edfe);
    defer bed.tearDown();
    // Bound once for each cluster that selected it.
    try std.testing.expectEqual(binds_before + 2, instances.least_in_flight.clusters);
    try exercise(bed);
}

test "zoxy-edge: no allocation after startup, and the seed replays (#417)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const options = try edge.options(arena.allocator(), &instances, &plan);
    try zoxy.testing.expectNoAllocationAfterStartup(Bed, &options, 0x0edfe, exercise);
}

/// Instances of their own, so their cap is not the gate's: at zero, the
/// first connection is past it.
var capped: edge.Instances = .{ .connection_cap = .{ .connections_max = 0 } };

test "zoxy-edge: a connection past the cap is closed before a byte is read (#425)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const options = try edge.options(arena.allocator(), &capped, &plan);
    const bed = try std.testing.allocator.create(Bed);
    defer std.testing.allocator.destroy(bed);
    try bed.setUp(std.testing.allocator, &options, 0x0edfe);
    defer bed.tearDown();
    const refused = bed.request(0, "GET /orders HTTP/1.1\r\n" ++ tenant);
    try bed.run();
    // Closed without a byte written, and before any request policy ran.
    try std.testing.expectEqual(@as(usize, 0), refused.response().len);
    try std.testing.expectEqual(@as(u64, 1), bed.counter(edge.ConnectionCap, .refused));
    try std.testing.expectEqual(@as(u64, 0), bed.counter(edge.TenantGuard, .completed));
    try std.testing.expectEqual(@as(u32, 0), capped.connection_cap.open);
    try std.testing.expectEqual(@as(u32, 0), answeredBy(bed, &app_endpoints));
}
