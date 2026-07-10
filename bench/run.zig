//! Tier-1 loopback benchmark (DESIGN.md §9): the same constant-throughput
//! zrk load (coordinated-omission-corrected) against the origin directly
//! and through zoxy, printed as comparable bands — never single numbers;
//! compare bands across runs. Also witnesses the zero-alloc promise from
//! the outside: zoxy's RSS must not grow across the measured run.
//!
//! By default an nginx origin is spawned with a generated config (the dev
//! shell provides nginx); pass `--origin host:port` to reuse any live
//! HTTP origin instead. zoxy is drained with SIGTERM at the end, so every
//! run also exercises the drain path. Core pinning is deliberately left
//! to the caller (taskset) until the CI band policy needs it.

const std = @import("std");
const Io = std.Io;

const zrk = @import("zrk");

const assert = std.debug.assert;

const zoxy_port: u16 = 18180;
const origin_port: u16 = 19180;
const work_directory = ".zig-cache/zoxy-bench";

const Flags = struct {
    rate: u64 = 20_000,
    connections: u32 = 32,
    duration_s: u64 = 10,
    origin: ?[]const u8 = null,
    zoxy_path: []const u8 = "zig-out/bin/zoxy",
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    const flags = try parseFlags(args);

    try Io.Dir.cwd().createDirPath(io, work_directory);

    var origin_child: ?std.process.Child = null;
    const origin_address = flags.origin orelse spawn_origin: {
        origin_child = try spawnNginx(arena, io);
        break :spawn_origin try std.fmt.allocPrint(arena, "127.0.0.1:{d}", .{origin_port});
    };
    defer if (origin_child) |*child| {
        child.kill(io);
        _ = child.wait(io) catch {};
    };

    var zoxy_child = try spawnZoxy(arena, io, flags.zoxy_path, origin_address);
    var zoxy_running = true;
    defer if (zoxy_running) zoxy_child.kill(io);

    // Warm both paths up and prove they answer before measuring.
    _ = try awaitResponsive(arena, io, originPortOf(origin_address), "origin");
    _ = try awaitResponsive(arena, io, zoxy_port, "zoxy");

    const rss_before_kb = try readRssKb(arena, io, zoxy_child.id);

    std.debug.print(
        "bench: rate {d}/s, {d} connections, {d}s per run\n",
        .{ flags.rate, flags.connections, flags.duration_s },
    );
    const direct = try loadTest(arena, io, originPortOf(origin_address), &flags);
    const proxied = try loadTest(arena, io, zoxy_port, &flags);

    const rss_after_kb = try readRssKb(arena, io, zoxy_child.id);

    printReport("direct ", &direct);
    printReport("proxied", &proxied);
    printOverhead(&direct, &proxied);

    std.debug.print("zoxy RSS: {d} KiB -> {d} KiB\n", .{ rss_before_kb, rss_after_kb });

    // Drain, not just death: SIGTERM and wait for a clean exit (§8).
    try std.posix.kill(zoxy_child.id.?, .TERM);
    const term = try zoxy_child.wait(io);
    zoxy_running = false;
    const drained_cleanly = term == .exited and term.exited == 0;
    std.debug.print("zoxy drain: {s}\n", .{if (drained_cleanly) "clean exit" else "UNCLEAN"});

    // The outside witness of the zero-alloc promise: serving 2x
    // duration_s of load must not grow the resident set beyond noise.
    const rss_flat = rss_after_kb <= rss_before_kb + 1024;
    if (!rss_flat) {
        std.debug.print("FAIL: zoxy RSS grew under load\n", .{});
    }
    const completed = direct.snapshot.counters.completed > 0 and
        proxied.snapshot.counters.completed > 0;
    if (!completed) {
        std.debug.print("FAIL: a run completed zero requests\n", .{});
    }
    return if (rss_flat and completed and drained_cleanly) 0 else 1;
}

fn parseFlags(args: []const [:0]const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--rate")) {
            index += 1;
            flags.rate = try std.fmt.parseUnsigned(u64, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--connections")) {
            index += 1;
            flags.connections = try std.fmt.parseUnsigned(u32, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--seconds")) {
            index += 1;
            flags.duration_s = try std.fmt.parseUnsigned(u64, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--origin")) {
            index += 1;
            flags.origin = args[index];
        } else if (std.mem.eql(u8, arg, "--zoxy")) {
            index += 1;
            flags.zoxy_path = args[index];
        } else {
            std.debug.print(
                "usage: bench [--rate N] [--connections N] [--seconds N] " ++
                    "[--origin host:port] [--zoxy path]\n",
                .{},
            );
            return error.InvalidArguments;
        }
    }
    assert(flags.rate >= 1);
    assert(flags.connections >= 1);
    assert(flags.duration_s >= 1);
    return flags;
}

fn originPortOf(origin_address: []const u8) u16 {
    const colon = std.mem.lastIndexOfScalar(u8, origin_address, ':').?;
    return std.fmt.parseUnsigned(u16, origin_address[colon + 1 ..], 10) catch
        @panic("invalid --origin port");
}

fn spawnNginx(arena: std.mem.Allocator, io: Io) !std.process.Child {
    const prefix = work_directory ++ "/nginx";
    try Io.Dir.cwd().createDirPath(io, prefix ++ "/logs");
    const conf_path = prefix ++ "/bench.conf";
    const conf = try std.fmt.allocPrint(arena,
        \\daemon off;
        \\worker_processes 1;
        \\pid nginx.pid;
        \\error_log logs/error.log crit;
        \\events {{ worker_connections 1024; }}
        \\http {{
        \\    access_log off;
        \\    server {{
        \\        listen 127.0.0.1:{d};
        \\        location / {{ return 200 "zoxy-bench-origin\n"; }}
        \\    }}
        \\}}
        \\
    , .{origin_port});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = conf_path, .data = conf });

    return std.process.spawn(io, .{
        .argv = &.{ "nginx", "-p", prefix, "-c", "bench.conf" },
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print(
            "bench: could not spawn nginx ({t}); is the dev shell loaded? " ++
                "Use --origin host:port to reuse a live origin.\n",
            .{err},
        );
        return err;
    };
}

fn spawnZoxy(
    arena: std.mem.Allocator,
    io: Io,
    zoxy_path: []const u8,
    origin_address: []const u8,
) !std.process.Child {
    const config_path = work_directory ++ "/zoxy.json";
    const config_json = try std.fmt.allocPrint(arena,
        \\{{
        \\    "listeners": [
        \\        {{ "bind": "127.0.0.1:{d}", "cluster": "origin" }}
        \\    ],
        \\    "clusters": {{
        \\        "origin": {{ "endpoints": ["{s}"] }}
        \\    }},
        \\    "timeouts": {{
        \\        "connect_ms": 5000,
        \\        "idle_ms": 60000,
        \\        "drain_deadline_ms": 5000
        \\    }}
        \\}}
        \\
    , .{ zoxy_port, origin_address });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = config_json });

    return std.process.spawn(io, .{
        .argv = &.{ zoxy_path, config_path },
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("bench: could not spawn {s} ({t}); run `zig build` first\n", .{
            zoxy_path,
            err,
        });
        return err;
    };
}

/// Short probing runs double as warmup; a target that never answers is a
/// setup failure, reported before any numbers are printed.
fn awaitResponsive(arena: std.mem.Allocator, io: Io, port: u16, label: []const u8) !void {
    var attempt: u8 = 0;
    while (attempt < 10) : (attempt += 1) {
        var cfg = benchConfig(port, 4, 100);
        cfg.duration_ns = std.time.ns_per_s / 2;
        const report = zrk.runner.run(arena, io, &cfg, null, null) catch |err| {
            if (attempt == 9) return err;
            io.sleep(Io.Duration.fromNanoseconds(200 * std.time.ns_per_ms), .awake) catch {};
            continue;
        };
        if (report.snapshot.counters.completed > 0) return;
        io.sleep(Io.Duration.fromNanoseconds(200 * std.time.ns_per_ms), .awake) catch {};
    }
    std.debug.print("bench: {s} on port {d} never answered\n", .{ label, port });
    return error.TargetUnresponsive;
}

fn loadTest(
    arena: std.mem.Allocator,
    io: Io,
    port: u16,
    flags: *const Flags,
) !zrk.runner.Report {
    var cfg = benchConfig(port, flags.connections, flags.rate);
    cfg.duration_ns = flags.duration_s * std.time.ns_per_s;
    return zrk.runner.run(arena, io, &cfg, null, null);
}

fn benchConfig(port: u16, connections: u32, rate: u64) zrk.cli.Config {
    return .{
        .url = .{ .scheme = .http, .host = "127.0.0.1", .port = port, .target = "/" },
        .connections = connections,
        .rate = rate,
        .timeout_ns = 2 * std.time.ns_per_s,
        .interval_ns = std.time.ns_per_s,
        .plain = true,
    };
}

fn printReport(label: []const u8, report: *const zrk.runner.Report) void {
    const hist = &report.snapshot.hist;
    const counters = &report.snapshot.counters;
    const rate_achieved =
        @as(f64, @floatFromInt(counters.completed)) / report.elapsed_s;
    // zrk histograms record microseconds (the wrk2 convention).
    std.debug.print(
        "{s}  {d:.0} req/s  p50 {d} us  p90 {d} us  p99 {d} us  max {d} us  " ++
            "({d} completed, {d} errors)\n",
        .{
            label,
            rate_achieved,
            hist.valueAtPercentile(50.0),
            hist.valueAtPercentile(90.0),
            hist.valueAtPercentile(99.0),
            hist.max(),
            counters.completed,
            counters.connect_errors + counters.write_errors + counters.status_errors,
        },
    );
}

fn printOverhead(direct: *const zrk.runner.Report, proxied: *const zrk.runner.Report) void {
    const direct_p50 = direct.snapshot.hist.valueAtPercentile(50.0);
    const proxied_p50 = proxied.snapshot.hist.valueAtPercentile(50.0);
    const hop_us = proxied_p50 -| direct_p50;
    std.debug.print("hop overhead: +{d} us p50 (band, not a single number — §9)\n", .{hop_us});
}

fn readRssKb(arena: std.mem.Allocator, io: Io, pid: ?std.process.Child.Id) !u64 {
    const path = try std.fmt.allocPrint(arena, "/proc/{d}/status", .{pid.?});
    // procfs advertises size 0, so this must stream, not trust st_size.
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var read_buffer: [8192]u8 = undefined;
    var file_reader = file.reader(io, &read_buffer);
    var status_buffer: [8192]u8 = undefined;
    const status_len = try file_reader.interface.readSliceShort(&status_buffer);
    const status = status_buffer[0..status_len];
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "VmRSS:")) {
            const digits_start = std.mem.indexOfAny(u8, line, "0123456789").?;
            const digits_end = std.mem.indexOfScalarPos(u8, line, digits_start, ' ').?;
            return std.fmt.parseUnsigned(u64, line[digits_start..digits_end], 10);
        }
    }
    return error.RssUnavailable;
}
