//! Tier-0 pinned profiler (DESIGN.md §9): drive a fixed zrk load through a
//! real zoxy against a loopback nginx origin, sample ONLY the zoxy pid with
//! perf, and fold the result into a flamegraph. zoxy is pinned to one core so
//! the hardware PMU and LBR call-graph stay on a single core type — on a
//! hybrid Intel part an unpinned process migrates between the cpu_core and
//! cpu_atom PMUs and samples read as zero. Everything else (this process, its
//! zrk load threads, the inherited nginx) is pinned off that core so the load
//! generator never steals it.
//!
//! Run via `zig build profile`, which builds a ReleaseFast zoxy and passes its
//! path as the first argument; perf, flamegraph and nginx come from the dev
//! shell. Tooling stays in Zig, not bash (TIGER_STYLE): the perf orchestration
//! and the perf-script -> stackcollapse -> flamegraph pipeline run as
//! file-redirected child processes here rather than a shell pipe.

const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;

const affinity = @import("affinity.zig");
const zrk = @import("zrk");

const assert = std.debug.assert;

const origin_port: u16 = 19190;
const zoxy_l4_port: u16 = 18190;
const zoxy_http_port: u16 = 18191;
const work_directory = ".zig-cache/zoxy-profile";
const perf_data_path = work_directory ++ "/zoxy.perf.data";
const script_path = work_directory ++ "/zoxy.script";
const folded_path = work_directory ++ "/zoxy.folded";
const svg_path = work_directory ++ "/zoxy-flamegraph.svg";
const report_path = work_directory ++ "/zoxy.report";

const Flags = struct {
    rate: u64 = 100_000,
    connections: u32 = 64,
    threads: u32 = 4,
    duration_s: u64 = 30,
    freq: u32 = 4000,
    /// Core to dedicate to zoxy; null auto-picks the last P-core (or last cpu).
    zoxy_cpu: ?u16 = null,
    /// Which listener to drive: the L4 relay or the L7 reverse proxy.
    protocol: Protocol = .l4,
    zoxy_path: []const u8 = "zig-out/bin/zoxy-profile",

    const Protocol = enum { l4, http };

    fn zoxyPort(flags: *const Flags) u16 {
        return switch (flags.protocol) {
            .l4 => zoxy_l4_port,
            .http => zoxy_http_port,
        };
    }
};

pub fn main(init: std.process.Init) !u8 {
    if (comptime builtin.os.tag != .linux) {
        std.debug.print("profile: perf profiling is Linux-only\n", .{});
        return 1;
    }
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    const flags = try parseFlags(args);

    try Io.Dir.cwd().createDirPath(io, work_directory);

    // Topology: dedicate one core to zoxy, run everything else off it. Pin
    // ourselves first so the nginx/zoxy/perf children and the zrk load threads
    // all inherit the "everything else" mask; zoxy is then re-pinned alone.
    // Non-null: `main` already returned above on non-Linux, the only case
    // `dedicate` yields null.
    const zoxy_cpu = affinity.dedicate(io, flags.zoxy_cpu).?;

    var origin_child = try spawnNginx(arena, io);
    defer origin_child.kill(io);

    var zoxy_child = try spawnZoxy(arena, io, flags.zoxy_path, &flags);
    var zoxy_running = true;
    defer if (zoxy_running) zoxy_child.kill(io);
    const zoxy_pid = zoxy_child.id orelse return error.NoZoxyPid;
    affinity.pinChildTo(zoxy_pid, zoxy_cpu);

    // Warm up and prove the path serves before spending a measured run on it.
    try awaitResponsive(arena, io, &flags);
    std.debug.print(
        "profile: zoxy pid {d} pinned to cpu {d}; driving {s} listener; origin + load pinned off it\n",
        .{ zoxy_pid, zoxy_cpu, @tagName(flags.protocol) },
    );

    // Record only the zoxy pid for the load's duration while zrk saturates it.
    var perf_child = try spawnPerf(arena, io, zoxy_pid, &flags);
    std.debug.print(
        "profile: measuring {d}s at {d} req/s over {d} connections\n",
        .{ flags.duration_s, flags.rate, flags.connections },
    );
    const report = try loadTest(arena, io, &flags);
    const perf_term = try perf_child.wait(io);
    if (perf_term != .exited or perf_term.exited != 0) {
        std.debug.print("profile: perf record exited abnormally ({any})\n", .{perf_term});
        return 1;
    }

    printReport(&report);
    try generateFlamegraph(arena, io);
    try printTopSymbols(io);

    // Drain, not just death (§8): SIGTERM and wait for the clean exit.
    try std.posix.kill(zoxy_pid, .TERM);
    _ = try zoxy_child.wait(io);
    zoxy_running = false;
    return 0;
}

fn parseFlags(args: []const [:0]const u8) !Flags {
    var flags: Flags = .{};
    var zoxy_path_set = false;
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--rate")) {
            index += 1;
            flags.rate = try std.fmt.parseUnsigned(u64, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--connections")) {
            index += 1;
            flags.connections = try std.fmt.parseUnsigned(u32, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--threads")) {
            index += 1;
            flags.threads = try std.fmt.parseUnsigned(u32, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--seconds")) {
            index += 1;
            flags.duration_s = try std.fmt.parseUnsigned(u64, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--freq")) {
            index += 1;
            flags.freq = try std.fmt.parseUnsigned(u32, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--cpu")) {
            index += 1;
            flags.zoxy_cpu = try std.fmt.parseUnsigned(u16, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--protocol")) {
            index += 1;
            if (std.mem.eql(u8, args[index], "l4")) {
                flags.protocol = .l4;
            } else if (std.mem.eql(u8, args[index], "http")) {
                flags.protocol = .http;
            } else {
                std.debug.print("profile: --protocol must be l4 or http\n", .{});
                return error.InvalidArguments;
            }
        } else if (!zoxy_path_set and !std.mem.startsWith(u8, arg, "--")) {
            // First bare argument is the zoxy binary (passed by `zig build`).
            flags.zoxy_path = arg;
            zoxy_path_set = true;
        } else {
            std.debug.print(
                "usage: profile [zoxy-path] [--rate N] [--connections N] " ++
                    "[--threads N] [--seconds N] [--freq N] [--cpu N]\n",
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

// --- process orchestration --------------------------------------------------

fn spawnNginx(arena: std.mem.Allocator, io: Io) !std.process.Child {
    const prefix = work_directory ++ "/nginx";
    try Io.Dir.cwd().createDirPath(io, prefix ++ "/logs");
    const conf_path = prefix ++ "/profile.conf";
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
        \\        location / {{ return 200 "zoxy-profile-origin\n"; }}
        \\    }}
        \\}}
        \\
    , .{origin_port});
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = conf_path, .data = conf });

    return std.process.spawn(io, .{
        .argv = &.{ "nginx", "-p", prefix, "-c", "profile.conf" },
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("profile: could not spawn nginx ({t}); is the dev shell loaded?\n", .{err});
        return err;
    };
}

fn spawnZoxy(
    arena: std.mem.Allocator,
    io: Io,
    zoxy_path: []const u8,
    flags: *const Flags,
) !std.process.Child {
    // Both listeners always exist so the flag only picks which one zrk
    // drives; the idle one adds no load.
    const config_path = work_directory ++ "/zoxy.json";
    const config_json = try std.fmt.allocPrint(arena,
        \\{{
        \\    "listeners": [
        \\        {{ "bind": "127.0.0.1:{d}", "cluster": "origin", "protocol": "l4" }},
        \\        {{ "bind": "127.0.0.1:{d}", "cluster": "origin", "protocol": "http" }}
        \\    ],
        \\    "clusters": {{ "origin": {{ "endpoints": ["127.0.0.1:{d}"] }} }},
        \\    "timeouts": {{ "connect_ms": 5000, "idle_ms": 60000, "drain_deadline_ms": 5000 }}
        \\}}
        \\
    , .{ zoxy_l4_port, zoxy_http_port, origin_port });
    _ = flags;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = config_json });

    return std.process.spawn(io, .{
        .argv = &.{ zoxy_path, config_path },
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("profile: could not spawn {s} ({t}); run `zig build` first\n", .{ zoxy_path, err });
        return err;
    };
}

fn spawnPerf(
    arena: std.mem.Allocator,
    io: Io,
    zoxy_pid: std.process.Child.Id,
    flags: *const Flags,
) !std.process.Child {
    // cycles:u + LBR: hardware call-graph from the branch-record MSRs, no frame
    // pointers or DWARF CFI needed. `-- sleep N` bounds the recording to the
    // load window; perf self-terminates when sleep exits and writes the data.
    const pid = try std.fmt.allocPrint(arena, "{d}", .{zoxy_pid});
    const freq = try std.fmt.allocPrint(arena, "{d}", .{flags.freq});
    const seconds = try std.fmt.allocPrint(arena, "{d}", .{flags.duration_s});
    return std.process.spawn(io, .{
        .argv = &.{
            "perf", "record", "-p",           pid,   "-e", "cycles:u",
            "-F",   freq,     "--call-graph", "lbr", "-o", perf_data_path,
            "--",   "sleep",  seconds,
        },
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("profile: could not spawn perf ({t}); is the dev shell loaded?\n", .{err});
        return err;
    };
}

// --- load (zrk, in-process, like bench/run.zig) -----------------------------

fn benchConfig(port: u16, rate: u64, connections: u32, threads: u32) zrk.cli.Config {
    return .{
        .url = .{ .scheme = .http, .host = "127.0.0.1", .port = port, .target = "/" },
        .threads = threads,
        .connections = connections,
        .rate = rate,
        .timeout_ns = 2 * std.time.ns_per_s,
        .interval_ns = std.time.ns_per_s,
        .plain = true,
    };
}

fn awaitResponsive(arena: std.mem.Allocator, io: Io, flags: *const Flags) !void {
    const attempts_max: u8 = 10;
    const retry_sleep = Io.Duration.fromNanoseconds(200 * std.time.ns_per_ms);
    var attempt: u8 = 0;
    while (attempt < attempts_max) : (attempt += 1) {
        var config = benchConfig(flags.zoxyPort(), 20_000, 16, 2);
        config.duration_ns = std.time.ns_per_s / 2;
        const report = zrk.runner.run(arena, io, &config, null, null) catch {
            if (attempt == attempts_max - 1) return error.TargetUnresponsive;
            io.sleep(retry_sleep, .awake) catch {};
            continue;
        };
        if (report.snapshot.counters.completed > 0) return;
        io.sleep(retry_sleep, .awake) catch {};
    }
    return error.TargetUnresponsive;
}

fn loadTest(arena: std.mem.Allocator, io: Io, flags: *const Flags) !zrk.runner.Report {
    var config = benchConfig(flags.zoxyPort(), flags.rate, flags.connections, flags.threads);
    config.duration_ns = flags.duration_s * std.time.ns_per_s;
    return zrk.runner.run(arena, io, &config, null, null);
}

fn printReport(report: *const zrk.runner.Report) void {
    const hist = &report.snapshot.hist;
    const counters = &report.snapshot.counters;
    const rate_achieved = @as(f64, @floatFromInt(counters.completed)) / report.elapsed_s;
    std.debug.print(
        "load: {d:.0} req/s  p50 {d} us  p99 {d} us  ({d} completed, {d} socket-errors)\n",
        .{
            rate_achieved,
            hist.valueAtPercentile(50.0),
            hist.valueAtPercentile(99.0),
            counters.completed,
            counters.socketErrors(),
        },
    );
}

// --- flamegraph pipeline (file-redirected children, no shell pipe) ----------

fn generateFlamegraph(arena: std.mem.Allocator, io: Io) !void {
    _ = arena;
    try runToFile(io, &.{ "perf", "script", "-i", perf_data_path }, script_path);
    try runToFile(io, &.{ "stackcollapse-perf.pl", script_path }, folded_path);
    try runToFile(io, &.{
        "flamegraph.pl", "--title",
        "zoxy under load (cycles:u, LBR call-graph) — see run for path",
        folded_path,
    }, svg_path);
    std.debug.print("profile: flamegraph -> {s}\n", .{svg_path});
}

/// Spawn `argv` with stdout redirected to `out_path` — the Zig stand-in for a
/// shell `argv > out_path`. Each flamegraph stage reads a file arg and writes
/// its stage output, so no inter-process pipe is needed.
fn runToFile(io: Io, argv: []const []const u8, out_path: []const u8) !void {
    const out = try Io.Dir.cwd().createFile(io, out_path, .{});
    defer out.close(io);
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdout = .{ .file = out },
        .stderr = .ignore,
    }) catch |err| {
        std.debug.print("profile: could not spawn {s} ({t}); is the dev shell loaded?\n", .{ argv[0], err });
        return err;
    };
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) {
        std.debug.print("profile: {s} failed ({any})\n", .{ argv[0], term });
        return error.PipelineStageFailed;
    }
}

fn printTopSymbols(io: Io) !void {
    runToFile(io, &.{
        "perf",    "report",        "-i", perf_data_path,
        "--stdio", "--no-children", "-g", "none",
    }, report_path) catch return;
    const file = Io.Dir.cwd().openFile(io, report_path, .{}) catch return;
    defer file.close(io);
    var read_buffer: [64 * 1024]u8 = undefined;
    var file_reader = file.reader(io, &read_buffer);
    var content: [64 * 1024]u8 = undefined;
    const len = file_reader.interface.readSliceShort(&content) catch return;
    std.debug.print("profile: top self-time symbols\n", .{});
    var lines = std.mem.splitScalar(u8, content[0..len], '\n');
    var shown: u8 = 0;
    while (lines.next()) |line| {
        if (shown >= 12) break;
        const trimmed = std.mem.trimStart(u8, line, " ");
        if (trimmed.len == 0 or trimmed[0] < '0' or trimmed[0] > '9') continue;
        std.debug.print("  {s}\n", .{line});
        shown += 1;
    }
}
