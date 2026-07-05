//! Host-tool CLI for the config JSON Schema (docs/DESIGN.md §7 Phase 6, slice 1):
//!
//!   config_tool emit                            → write the schema to stdout
//!   config_tool check <schema.json> [config…]   → drift gate + strict parse
//!
//! `check` regenerates the schema in memory and byte-compares it to the
//! committed <schema.json> (a stale file fails, prompting `zig build schema`),
//! then strict-parses each config file. Rooted at `b.graph.host` and importing
//! only `config_schema` (which pulls in `config.zig`) — no OpenSSL, since the
//! config graph is FFI-free.

const std = @import("std");
const schema = @import("config_schema");
const config = schema.config_zig;

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len >= 2 and std.mem.eql(u8, args[1], "emit")) return emit(init.io);
    if (args.len >= 3 and std.mem.eql(u8, args[1], "check")) return check(init.io, gpa, args[2..]);
    std.log.err("usage: config_tool <emit | check <schema.json> [config.json ...]>", .{});
    return error.Usage;
}

/// Write the generated schema to stdout (captured by `zig build schema`).
fn emit(io: std.Io) !void {
    var buf: [64 * 1024]u8 = undefined;
    var file_writer = std.Io.File.stdout().writer(io, &buf);
    try schema.write(&file_writer.interface);
    try file_writer.flush();
}

/// Fail if the committed schema is stale, then strict-parse each config file.
fn check(io: std.Io, gpa: std.mem.Allocator, paths: []const [:0]const u8) !void {
    assert_paths(paths);

    var buf: [64 * 1024]u8 = undefined; // the generated schema is a few KiB
    var generated = std.Io.Writer.fixed(&buf);
    try schema.write(&generated);
    const want = generated.buffered();

    const committed = std.Io.Dir.cwd().readFileAlloc(io, paths[0], gpa, .unlimited) catch |err| {
        std.log.err("config_tool: cannot read schema {s}: {s}", .{ paths[0], @errorName(err) });
        return err;
    };
    if (!std.mem.eql(u8, want, committed)) {
        std.log.err("config_tool: {s} is stale — run `zig build schema`", .{paths[0]});
        return error.SchemaStale;
    }

    for (paths[1..]) |config_path| {
        const text = std.Io.Dir.cwd().readFileAlloc(io, config_path, gpa, .unlimited) catch |err| {
            std.log.err(
                "config_tool: cannot read config {s}: {s}",
                .{ config_path, @errorName(err) },
            );
            return err;
        };
        var diagnostic: config.Diagnostic = .{};
        var parsed = config.parse_diagnostic(gpa, text, &diagnostic) catch |err| {
            if (diagnostic.unknown_field) |field| {
                std.log.err("config_tool: {s}: unknown field {s}", .{ config_path, field });
            } else {
                std.log.err("config_tool: {s}: {s}", .{ config_path, @errorName(err) });
            }
            return err;
        };
        parsed.deinit();
    }
}

fn assert_paths(paths: []const [:0]const u8) void {
    std.debug.assert(paths.len >= 1); // check requires at least a schema path
    std.debug.assert(paths[0].len > 0);
}
