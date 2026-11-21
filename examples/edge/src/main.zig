//! zoxy-edge (#417): a proxy built on zoxy by a separate package and
//! configured entirely in code — its extensions and its options are
//! `edge.zig`; this file is only its command line.
//!
//!     zoxy-edge [--check] LISTEN APP STATIC
//!
//! LISTEN is the `IP:port` to accept on; APP and STATIC are
//! comma-separated `IP:port` lists: the application's endpoints, and the
//! static-content ones. Discovery here is the command line; a build that
//! asks a registry or DNS does so at this same point — before its options
//! exist, with the whole startup sequence still ahead of it.
//!
//! The supported entry points, in the order a build calls them
//! (DESIGN.md §13):
//!
//! 1. discover what the options need — here, parse the command line;
//! 2. build `zoxy.Options` (`edge.options`), selecting extension instances
//!    with `App.picker` and `App.policy`;
//! 3. `App.serve`, which resolves the options, prices them and prints the
//!    banner, takes the fd budget and the log sink, builds the server,
//!    binds the extensions and runs to the drain — or `App.check`, which
//!    does the same up to what a start would ask the box for, and binds
//!    nothing.
//!
//! The options, and every instance they select, are read for the
//! process's whole life: here they sit in the startup arena and in a
//! static, and neither is ever freed.

const std = @import("std");

const zoxy = @import("zoxy");

const edge = @import("edge.zig");

const assert = std.debug.assert;

/// Endpoints one list may name.
const endpoints_max = 32;

/// The build's extension instances. Static, because the options select
/// them by address and the server reads them for the process's life.
var instances: edge.Instances = .{};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    assert(args.len >= 1);
    const check = args.len == 5 and std.mem.eql(u8, args[1], "--check");
    const positional = if (check) args[2..] else args[1..];
    if (positional.len != 3) {
        std.debug.print("usage: zoxy-edge [--check] LISTEN APP STATIC\n", .{});
        return 2;
    }
    const arena_before = init.arena.queryCapacity();
    const plan: edge.Plan = .{
        .listen = try address(positional[0]),
        .app = try addresses(arena, positional[1]),
        .static = try addresses(arena, positional[2]),
        .log_requests = true,
    };
    const options = try edge.options(arena, &instances, &plan);
    const startup: edge.App.Startup = .{
        .build = .{ .version = "zoxy-edge" },
        .source = "zoxy-edge's options",
        .options_arena_bytes = init.arena.queryCapacity() - arena_before,
    };
    if (check) return @backingInt(try edge.App.check(init, &options, &startup));
    try edge.App.serve(init, &options, &startup);
    return 0;
}

fn address(literal: []const u8) !std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parseLiteral(literal) catch |err| {
        std.debug.print("zoxy-edge: '{s}' is not an IP:port literal\n", .{literal});
        return err;
    };
}

fn addresses(arena: std.mem.Allocator, list: []const u8) ![]const std.Io.net.IpAddress {
    var parsed: std.ArrayList(std.Io.net.IpAddress) = .empty;
    var literals = std.mem.splitScalar(u8, list, ',');
    while (literals.next()) |literal| {
        if (parsed.items.len == endpoints_max) {
            std.debug.print("zoxy-edge: more than {d} endpoints in '{s}'\n", .{ endpoints_max, list });
            return error.TooManyEndpoints;
        }
        try parsed.append(arena, try address(literal));
    }
    // `splitScalar` yields at least one literal, and `address` refuses an
    // empty one, so a list that got here names an endpoint.
    assert(parsed.items.len >= 1);
    assert(parsed.items.len <= endpoints_max);
    return parsed.items;
}
