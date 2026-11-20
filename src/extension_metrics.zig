//! The slots behind a build's own counters and gauges (#435): reserved at
//! startup from the config and the build's lists, priced in the banner
//! beside zoxy's labeled metrics (§5), and handed into every serving call
//! made for their site.
//!
//! A site is a cluster whose picker is metered, a listener whose policy
//! list holds a metered type, or a route whose list does. Each site holds
//! one block per metered type it selects: the series is per site and per
//! type, so two selections of one type at one site — two instances, or
//! one named twice — count into the same block.
//!
//! A build that meters nothing, the stock binary among them, has no
//! table at all: every lookup answers empty slots, and its banner prices
//! nothing for it.

const std = @import("std");

const config_module = @import("config.zig");
const counters_module = @import("counters.zig");
const extension = @import("extension.zig");
const io_module = @import("io/io.zig");
const router = @import("http/router.zig");

const assert = std.debug.assert;

const Config = config_module.Config;
const Metrics = extension.Metrics;

/// A site, as its labels name it.
pub const Site = union(enum) {
    cluster: []const u8,
    listener: *const io_module.Address,
    route: RouteSite,

    pub const RouteSite = struct {
        listener: *const io_module.Address,
        route: *const router.Route,
    };
};

pub fn Table(comptime extensions: extension.Extensions) type {
    const families = extension.metered(extensions);
    return struct {
        const Self = @This();

        /// Whether this build meters anything.
        pub const enabled = families.len >= 1;

        /// Every site's blocks, in walk order: clusters, then each
        /// listener's own list and its routes' lists in turn.
        blocks: []Block = &.{},
        /// A cluster's picker slots, by cluster index; empty slots for a
        /// stock or unmetered picker.
        clusters: []Metrics = &.{},
        /// Per listener, one entry per selection in its policy list.
        listeners: [][]Metrics = &.{},
        /// Per listener, per route, one entry per selection in the
        /// route's policy list.
        routes: [][][]Metrics = &.{},

        /// One metered type's slots at one site.
        pub const Block = struct {
            /// Its type's index in `extension.metered`.
            family: u16,
            /// The site's labels, braces included: `{cluster="api"}`.
            label: []const u8,
            counters: []u64,
            gauges: []u64,
        };

        /// What `init` takes from the startup arena for `config` (§5):
        /// the lookup arrays, the blocks, their cells and their labels.
        /// It walks the sites `init` walks and measures the labels `init`
        /// renders, through the same functions, so the banner's term is
        /// what `init` then asks for.
        pub fn tableBytes(config: *const Config) u64 {
            if (!enabled) return 0;
            var total: u64 = 0;
            total += @as(u64, config.clusters.len) * @sizeOf(Metrics);
            total += @as(u64, config.listeners.len) * (@sizeOf([]Metrics) + @sizeOf([][]Metrics));
            for (config.clusters) |*cluster| {
                const family = pickerFamily(cluster) orelse continue;
                total += blockBytes(family, .{ .cluster = cluster.name });
            }
            for (config.listeners) |*listener| {
                total += listSiteBytes(listener.request_policies, .{ .listener = &listener.bind_address });
                total += @as(u64, listener.routes.len) * @sizeOf([]Metrics);
                for (listener.routes) |*route| {
                    const site: Site = .{ .route = .{ .listener = &listener.bind_address, .route = route } };
                    total += listSiteBytes(route.request_policies, site);
                }
            }
            return total;
        }

        fn listSiteBytes(selections: []const extension.Selection, site: Site) u64 {
            var total: u64 = @as(u64, selections.len) * @sizeOf(Metrics);
            for (selections, 0..) |selection, position| {
                const family = policyFamily(selection) orelse continue;
                if (firstOf(selections, position, family) != position) continue;
                total += blockBytes(family, site);
            }
            return total;
        }

        fn blockBytes(family: u16, site: Site) u64 {
            assert(family < families.len);
            const shape = shapes[family];
            assert(shape.counters + shape.gauges >= 1);
            const cells: u64 = @as(u64, shape.counters) + shape.gauges;
            return @sizeOf(Block) + cells * @sizeOf(u64) + labelBytes(site);
        }

        pub fn init(table: *Self, arena: std.mem.Allocator, config: *const Config) error{OutOfMemory}!void {
            table.* = .{};
            if (!enabled) return;
            table.blocks = try arena.alloc(Block, blockCount(config));
            var built: u32 = 0;
            table.clusters = try arena.alloc(Metrics, config.clusters.len);
            for (config.clusters, table.clusters) |*cluster, *slots| {
                slots.* = .{};
                const family = pickerFamily(cluster) orelse continue;
                slots.* = try table.build(arena, &built, family, .{ .cluster = cluster.name });
            }
            table.listeners = try arena.alloc([]Metrics, config.listeners.len);
            table.routes = try arena.alloc([][]Metrics, config.listeners.len);
            for (config.listeners, table.listeners, table.routes) |*listener, *own, *routes| {
                own.* = try table.buildList(arena, &built, listener.request_policies, .{
                    .listener = &listener.bind_address,
                });
                routes.* = try arena.alloc([]Metrics, listener.routes.len);
                for (listener.routes, routes.*) |*route, *slots| {
                    slots.* = try table.buildList(arena, &built, route.request_policies, .{
                        .route = .{ .listener = &listener.bind_address, .route = route },
                    });
                }
            }
            assert(built == table.blocks.len);
        }

        /// One list's slots, position by position: a later selection of
        /// a type already met at this site shares its block.
        fn buildList(
            table: *Self,
            arena: std.mem.Allocator,
            built: *u32,
            selections: []const extension.Selection,
            site: Site,
        ) error{OutOfMemory}![]Metrics {
            const slots = try arena.alloc(Metrics, selections.len);
            for (selections, slots, 0..) |selection, *slot, position| {
                slot.* = .{};
                const family = policyFamily(selection) orelse continue;
                const first = firstOf(selections, position, family);
                assert(first <= position);
                slot.* = if (first == position)
                    try table.build(arena, built, family, site)
                else
                    slots[first];
            }
            assert(slots.len == selections.len);
            return slots;
        }

        fn build(table: *Self, arena: std.mem.Allocator, built: *u32, family: u16, site: Site) error{OutOfMemory}!Metrics {
            assert(built.* < table.blocks.len);
            const shape = shapes[family];
            const block = &table.blocks[built.*];
            block.* = .{
                .family = family,
                .label = try renderLabel(arena, site),
                .counters = try arena.alloc(u64, shape.counters),
                .gauges = try arena.alloc(u64, shape.gauges),
            };
            @memset(block.counters, 0);
            @memset(block.gauges, 0);
            built.* += 1;
            return .{ .counters = block.counters, .gauges = block.gauges };
        }

        fn blockCount(config: *const Config) u32 {
            var count: u32 = 0;
            for (config.clusters) |*cluster| {
                if (pickerFamily(cluster) != null) count += 1;
            }
            for (config.listeners) |*listener| {
                count += listBlockCount(listener.request_policies);
                for (listener.routes) |*route| count += listBlockCount(route.request_policies);
            }
            return count;
        }

        fn listBlockCount(selections: []const extension.Selection) u32 {
            var count: u32 = 0;
            for (selections, 0..) |selection, position| {
                const family = policyFamily(selection) orelse continue;
                if (firstOf(selections, position, family) == position) count += 1;
            }
            return count;
        }

        /// The first position in `selections`, up to `position`, whose
        /// type is `family` — the one that owns the site's block. Quadratic
        /// in a list's length, which is the build's own and short, and run
        /// at startup only: never on the serving path.
        fn firstOf(selections: []const extension.Selection, position: usize, family: u16) usize {
            assert(position < selections.len);
            for (selections[0..position], 0..) |earlier, index| {
                if (policyFamily(earlier) == family) return index;
            }
            return position;
        }

        /// A cluster's picker slots.
        pub fn picker(table: *const Self, cluster_index: u16) Metrics {
            if (!enabled) return .{};
            assert(cluster_index < table.clusters.len);
            return table.clusters[cluster_index];
        }

        /// A listener's policy slots, parallel to its list; empty in a
        /// build that meters nothing.
        pub fn listenerPolicies(table: *const Self, listener_index: u16) []const Metrics {
            if (!enabled) return &.{};
            assert(listener_index < table.listeners.len);
            return table.listeners[listener_index];
        }

        /// A route's policy slots, parallel to its list.
        pub fn routePolicies(table: *const Self, listener_index: u16, route_index: u16) []const Metrics {
            if (!enabled) return &.{};
            assert(listener_index < table.routes.len);
            assert(route_index < table.routes[listener_index].len);
            return table.routes[listener_index][route_index];
        }

        const Shape = struct { counters: u32, gauges: u32 };

        /// Each family's declared counter and gauge counts.
        const shapes: [families.len]Shape = blk: {
            var collected: [families.len]Shape = undefined;
            for (families, &collected) |Family, *shape| {
                shape.* = .{
                    .counters = extension.counterCount(Family),
                    .gauges = extension.gaugeCount(Family),
                };
            }
            break :blk collected;
        };

        fn pickerFamily(cluster: *const Config.Cluster) ?u16 {
            const selection = switch (cluster.pick) {
                .extension => |selection| selection,
                .rr, .p2c, .hash => return null,
            };
            return familyIn(extensions.pickers, selection);
        }

        fn policyFamily(selection: extension.Selection) ?u16 {
            return familyIn(extensions.request_policies, selection);
        }

        fn familyIn(comptime list: []const type, selection: extension.Selection) ?u16 {
            assert(selection.index < list.len);
            inline for (list, 0..) |Listed, index| {
                if (selection.index == index) {
                    if (comptime !extension.isMetered(Listed)) return null;
                    return comptime extension.familyIndex(extensions, Listed);
                }
            }
            unreachable;
        }
    };
}

/// A site's labels as the exposition writes them, braces included:
/// `{cluster="api"}`, `{listener="0.0.0.0:8080"}`, or
/// `{listener="0.0.0.0:8080",route="api.example.com/v1 x-canary=1"}` — a
/// route is named by what it matches, which the loader holds unique per
/// listener (`RouteDuplicate`). Cluster names and route parts are escaped;
/// an address carries nothing to escape (`pathIsRenderable`, at load).
pub fn writeLabel(writer: *std.Io.Writer, site: Site) std.Io.Writer.Error!void {
    switch (site) {
        .cluster => |name| {
            assert(name.len >= 1);
            try writer.writeAll("{cluster=\"");
            try counters_module.Labeled.writeEscaped(writer, name);
            try writer.writeAll("\"}");
        },
        .listener => |address| {
            try writeListener(writer, address);
            try writer.writeAll("}");
        },
        .route => |route_site| {
            try writeListener(writer, route_site.listener);
            try writer.writeAll(",route=\"");
            try writeRoute(writer, route_site.route);
            try writer.writeAll("\"}");
        },
    }
}

fn writeListener(writer: *std.Io.Writer, address: *const io_module.Address) std.Io.Writer.Error!void {
    if (address.* == .unix) assert(io_module.Address.pathIsRenderable(address.unix));
    try writer.print("{{listener=\"{f}\"", .{address.*});
}

fn writeRoute(writer: *std.Io.Writer, route: *const router.Route) std.Io.Writer.Error!void {
    assert(route.prefix.len >= 1);
    if (route.host) |host| try counters_module.Labeled.writeEscaped(writer, host);
    try counters_module.Labeled.writeEscaped(writer, route.prefix);
    const header = route.header orelse return;
    assert(header.name.len >= 1);
    try writer.writeAll(" ");
    try counters_module.Labeled.writeEscaped(writer, header.name);
    switch (header.kind) {
        .present => {},
        .equals => {
            try writer.writeAll("=");
            try counters_module.Labeled.writeEscaped(writer, header.value);
        },
        // Filters only: a route's header is present or equals (#302).
        .contains => unreachable,
    }
}

/// The bytes `writeLabel` writes for `site`, measured without a buffer.
fn labelBytes(site: Site) u64 {
    var discarding: std.Io.Writer.Discarding = .init(&.{});
    writeLabel(&discarding.writer, site) catch unreachable;
    const bytes = discarding.fullCount();
    assert(bytes >= "{cluster=\"\"}".len);
    return bytes;
}

/// `site`'s labels, rendered once into the startup arena at exactly the
/// length `labelBytes` measures.
fn renderLabel(arena: std.mem.Allocator, site: Site) error{OutOfMemory}![]const u8 {
    const bytes = labelBytes(site);
    const label = try arena.alloc(u8, @intCast(bytes));
    var writer = std.Io.Writer.fixed(label);
    writeLabel(&writer, site) catch unreachable;
    assert(writer.buffered().len == label.len);
    return label;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const Options = @import("Options.zig");

const TestMetered = struct {
    pub const metrics_prefix = "metered";
    pub const counters = .{ .seen = "Requests seen.", .refused = "Requests refused." };
    pub const gauges = .{ .level = "A level." };

    pub fn evaluate(_: *TestMetered, _: *const extension.Request) extension.Verdict {
        return .proceed;
    }
};

const TestPlain = struct {
    pub fn evaluate(_: *TestPlain, _: *const extension.Request) extension.Verdict {
        return .proceed;
    }
};

const TestPicker = struct {
    pub const metrics_prefix = "picker";
    pub const counters = .{ .picks = "Picks." };

    pub fn pick(_: *TestPicker, _: *const extension.Candidates, _: *const extension.PickInput) u16 {
        return 0;
    }
};

const test_extensions: extension.Extensions = .{
    .pickers = &.{TestPicker},
    .request_policies = &.{ TestMetered, TestPlain },
};

/// Two clusters, one with a metered picker; a listener whose list names
/// the metered type twice around an unmetered one; a host-and-header
/// route that names it once more, and a catch-all that names nothing.
/// Every array lives in `arena`: the config keeps its selections by
/// reference, so none may live in this frame.
fn testConfig(
    arena: std.mem.Allocator,
    first: *TestMetered,
    second: *TestMetered,
    plain: *TestPlain,
    picker: *TestPicker,
) !Config {
    const policies = test_extensions.request_policies;
    const origin = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000");
    const endpoints = try arena.dupe(Options.Cluster.Endpoint, &.{.{ .address = .{ .ip = origin } }});
    const routes = try arena.dupe(Options.Listener.Route, &.{
        .{
            .host = "api.example.com",
            .prefix = "/v1",
            .header = .{ .name = "x-canary", .predicate = .{ .equals = "1" } },
            .cluster = "api",
            .request_policies = try arena.dupe(extension.Selection, &.{extension.select(policies, first)}),
        },
        .{ .prefix = "/", .cluster = "web" },
    });
    const listeners = try arena.dupe(Options.Listener, &.{.{
        .bind = .{ .ip = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080") },
        .protocol = .{ .http = .{
            .target = .{ .routes = routes },
            .request_policies = try arena.dupe(extension.Selection, &.{
                extension.select(policies, first),
                extension.select(policies, plain),
                extension.select(policies, second),
            }),
            .max_body_bytes = 0,
            .keepalive_requests = 0,
        } },
    }});
    const clusters = try arena.dupe(Options.Cluster, &.{
        .{
            .name = "api",
            .endpoints = endpoints,
            .pick = .{ .extension = extension.select(test_extensions.pickers, picker) },
        },
        .{ .name = "web", .endpoints = endpoints, .pick = .p2c },
    });
    const options: Options = .{
        .listeners = listeners,
        .clusters = clusters,
        .timeouts = .{ .connect_ms = 1_000, .idle_ms = 5_000, .head_ms = 2_000, .tunnel_ms = 60_000, .health_interval_ms = 2_000 },
        .limits = .{},
    };
    return config_module.resolve(arena, &options);
}

test "extension metrics: one block per site and metered type, priced as init takes it (#435)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var first: TestMetered = .{};
    var second: TestMetered = .{};
    var plain: TestPlain = .{};
    var picker: TestPicker = .{};
    const config = try testConfig(arena_state.allocator(), &first, &second, &plain, &picker);
    const T = Table(test_extensions);
    comptime assert(T.enabled);

    // Every byte `init` asks for, against the banner's prediction.
    var counting = std.testing.FailingAllocator.init(arena_state.allocator(), .{});
    var table: T = undefined;
    try table.init(counting.allocator(), &config);
    try testing.expectEqual(T.tableBytes(&config), counting.allocated_bytes);

    // The picker's cluster, the listener, and the guarded route.
    try testing.expectEqual(@as(usize, 3), table.blocks.len);
    try testing.expectEqualStrings("{cluster=\"api\"}", table.blocks[0].label);
    try testing.expectEqualStrings("{listener=\"127.0.0.1:8080\"}", table.blocks[1].label);
    try testing.expectEqualStrings(
        "{listener=\"127.0.0.1:8080\",route=\"api.example.com/v1 x-canary=1\"}",
        table.blocks[2].label,
    );
    try testing.expectEqual(@as(usize, 1), table.picker(0).counters.len);
    try testing.expectEqual(@as(usize, 0), table.picker(1).counters.len);

    // The listener's list: the type named twice shares one block, and
    // the unmetered selection between them has none.
    const own = table.listenerPolicies(0);
    try testing.expectEqual(@as(usize, 3), own.len);
    try testing.expectEqual(@as(usize, 0), own[1].counters.len);
    own[0].add(TestMetered, .seen, 2);
    own[2].add(TestMetered, .seen, 1);
    own[2].set(TestMetered, .level, 7);
    try testing.expectEqual(@as(u64, 3), own[0].counter(TestMetered, .seen));
    try testing.expectEqual(@as(u64, 7), own[0].gauge(TestMetered, .level));
    try testing.expectEqual(@as(u64, 0), own[0].counter(TestMetered, .refused));

    // The route is its own site: the same instance counts apart there.
    const routes = config.listeners[0].routes;
    try testing.expectEqualStrings("/v1", routes[0].prefix);
    const guarded = table.routePolicies(0, 0);
    try testing.expectEqual(@as(usize, 1), guarded.len);
    try testing.expectEqual(@as(u64, 0), guarded[0].counter(TestMetered, .seen));
    try testing.expectEqual(@as(usize, 0), table.routePolicies(0, 1).len);
}

test "extension metrics: a build that meters nothing has no table and prices none (#435)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var first: TestMetered = .{};
    var second: TestMetered = .{};
    var plain: TestPlain = .{};
    var picker: TestPicker = .{};
    const config = try testConfig(arena_state.allocator(), &first, &second, &plain, &picker);
    // The stock build lists nothing; this one lists only unmetered types.
    inline for (.{ extension.Extensions{}, extension.Extensions{ .request_policies = &.{TestPlain} } }) |extensions| {
        const T = Table(extensions);
        comptime assert(!T.enabled);
        try testing.expectEqual(@as(u64, 0), T.tableBytes(&config));
        var table: T = undefined;
        try table.init(testing.failing_allocator, &config);
        try testing.expectEqual(@as(usize, 0), table.blocks.len);
        try testing.expectEqual(@as(usize, 0), table.listenerPolicies(0).len);
        try testing.expectEqual(@as(usize, 0), table.picker(0).counters.len);
    }
}

test "extension metrics: a unix listener and an escaped cluster name label as they render (#435)" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const unix: io_module.Address = .{ .unix = "/run/zoxy.sock" };
    try writeLabel(&aw.writer, .{ .listener = &unix });
    try testing.expectEqualStrings("{listener=\"unix:/run/zoxy.sock\"}", aw.written());
    aw.clearRetainingCapacity();
    try writeLabel(&aw.writer, .{ .cluster = "a\"b" });
    try testing.expectEqualStrings("{cluster=\"a\\\"b\"}", aw.written());
    try testing.expectEqual(@as(u64, aw.written().len), labelBytes(.{ .cluster = "a\"b" }));
}
