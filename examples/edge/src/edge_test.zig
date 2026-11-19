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
/// carries from the first run into the second. None of these four lets
/// that state steer a choice — a build whose picker does (round-robin's
/// cursor, say) resets it at the start of its scenario, or the replay
/// would diverge for a reason that is not a bug.
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
    const picks_before = instances.least_in_flight.picks;
    const tenant_refusals_before = instances.tenant_guard.refused;
    const read_only_refusals_before = instances.read_only.refused;

    const orders = bed.request(0, "GET /orders HTTP/1.1\r\n" ++ tenant);
    const search = bed.request(0, "GET /search?q=zig HTTP/1.1\r\n" ++ tenant);
    const asset = bed.request(0, "GET /static/app.js HTTP/1.1\r\n" ++ tenant);
    const asset_again = bed.request(0, "GET /static/app.js HTTP/1.1\r\n" ++ tenant);
    const upload = bed.request(0, "POST /static/app.js HTTP/1.1\r\nContent-Length: 0\r\n" ++ tenant);
    const anonymous = bed.request(0, "GET /orders HTTP/1.1\r\nHost: edge\r\nConnection: close\r\n\r\n");
    try bed.run();

    // `api` and `search` both pick through the one `LeastInFlight`.
    try std.testing.expectEqual(@as(?u16, 200), orders.status());
    try std.testing.expect(isOneOf(orders.body(), &app_endpoints));
    try std.testing.expectEqual(@as(?u16, 200), search.status());
    try std.testing.expect(isOneOf(search.body(), &app_endpoints));
    try std.testing.expectEqual(picks_before + 2, instances.least_in_flight.picks);

    // One path, one endpoint, on the cluster `PathAffinity` serves.
    try std.testing.expectEqual(@as(?u16, 200), asset.status());
    try std.testing.expect(isOneOf(asset.body(), &static_endpoints));
    try std.testing.expectEqualStrings(asset.body(), asset_again.body());

    // A write to the read-only route is refused once it is routed, and a
    // request with no tenant before anything looks at it — neither one
    // reaches an origin.
    try std.testing.expectEqual(@as(?u16, 403), upload.status());
    try std.testing.expectEqual(read_only_refusals_before + 1, instances.read_only.refused);
    try std.testing.expectEqual(@as(?u16, 403), anonymous.status());
    try std.testing.expectEqual(tenant_refusals_before + 1, instances.tenant_guard.refused);
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
