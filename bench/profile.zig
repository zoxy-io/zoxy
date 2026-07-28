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
const zio = @import("zio");
const spawn_path = @import("spawn_path.zig");
const constants = @import("zoxy").constants;

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
    /// Open connections zrk holds. Since zrk 1.x these are coroutines over
    /// a small thread pool, not a thread each, so this scales to the
    /// conn-slot ceiling without the load generator taking over the box —
    /// which is what makes a per-connection-cost sweep possible here.
    connections: u32 = 64,
    /// zrk's load threads, independent of `connections`. Kept small: they
    /// share every core except zoxy's.
    threads: u8 = 2,
    duration_s: u64 = 30,
    freq: u32 = 4000,
    /// Core to dedicate to zoxy; null auto-picks the last P-core (or last cpu).
    zoxy_cpu: ?u16 = null,
    /// Which listener to drive: the L4 relay or the L7 reverse proxy.
    protocol: Protocol = .l4,
    /// zoxy's §8 per-exchange deadline, in ms; 0 (the default) leaves it
    /// disabled, which is also the shipped default. Non-zero puts the
    /// deadline's arming path on every request, so this is the flag that
    /// makes its cost measurable rather than argued about.
    request_ms: u32 = 0,
    /// Optional hard ceiling on the settled load: refuse the run if the
    /// box flattens above it. 0 (the default) asks only that the load has
    /// stopped falling, and reports where — see `awaitQuietBox` for why
    /// no absolute default is defensible.
    quiesce_load: f64 = 0,
    /// How long to wait for the load to flatten before measuring anyway
    /// and saying so. Sized against the decay it exists to wait out: a
    /// row drives ~7 cores, and a ~60s EWMA needs ~160s to fall from
    /// there to a low floor, so this leaves real margin rather than the
    /// 22 seconds the first version left.
    quiesce_timeout_s: u64 = 300,
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
    // See bench/run.zig: zrk's runner needs zio's Io (connect-with-timeout
    // isn't implemented on the default std.Io.Threaded backend), so the
    // profiler builds the same zio.Runtime zrk's own CLI would.
    const rt = try zio.Runtime.init(arena, .{});
    defer rt.deinit();
    const io = rt.io();
    const environ = init.minimal.environ;
    const args = try init.minimal.args.toSlice(arena);
    const flags = try parseFlags(args);

    try Io.Dir.cwd().createDirPath(io, work_directory);

    // Topology: dedicate one core to zoxy, run everything else off it. Pin
    // ourselves first so the nginx/zoxy/perf children and the zrk load threads
    // all inherit the "everything else" mask; zoxy is then re-pinned alone.
    // Non-null: `main` already returned above on non-Linux, the only case
    // `dedicate` yields null.
    const zoxy_cpu = affinity.dedicate(io, flags.zoxy_cpu).?;

    const cycles_event = try preflight(io, &flags, zoxy_cpu) orelse
        return refuseNoPtraceAttach();

    var origin_child = try spawnNginx(arena, io, environ);
    defer origin_child.kill(io);

    var zoxy_child = try spawnZoxy(arena, io, flags.zoxy_path, flags.connections, flags.request_ms);
    var zoxy_running = true;
    defer if (zoxy_running) zoxy_child.kill(io);
    const zoxy_pid = zoxy_child.id orelse return error.NoZoxyPid;
    affinity.pinChildTo(zoxy_pid, zoxy_cpu);

    // Warm up and prove the path serves before spending a measured run on it.
    try awaitResponsive(arena, io, &flags);
    std.debug.print(
        "profile: zoxy pid {d} pinned to cpu {d} ({s}); driving {s} listener; origin + load pinned off it\n",
        .{ zoxy_pid, zoxy_cpu, cycles_event, @tagName(flags.protocol) },
    );

    // Record only the zoxy pid for the load's duration while zrk saturates it.
    var perf_child = try spawnPerf(arena, io, environ, zoxy_pid, cycles_event, &flags);
    std.debug.print(
        "profile: measuring {d}s at {d} req/s over {d} connections\n",
        .{ flags.duration_s, flags.rate, flags.connections },
    );
    const ring_scratch = try arena.alloc(u8, proc_scratch_bytes);
    const ring_before = readRingSample(io, zoxy_pid, ring_scratch);
    const report = try loadTest(arena, io, &flags);
    printRingDelta(io, zoxy_pid, &ring_before, report.snapshot.counters.completed, ring_scratch);
    const perf_term = try perf_child.wait(io);
    if (perf_term != .exited or perf_term.exited != 0) {
        std.debug.print("profile: perf record exited abnormally ({any})\n", .{perf_term});
        return 1;
    }

    printReport(&report);
    try generateFlamegraph(arena, io, environ);
    try printTopSymbols(arena, io, environ);

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
            flags.threads = try std.fmt.parseUnsigned(u8, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--seconds")) {
            index += 1;
            flags.duration_s = try std.fmt.parseUnsigned(u64, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--freq")) {
            index += 1;
            flags.freq = try std.fmt.parseUnsigned(u32, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--cpu")) {
            index += 1;
            flags.zoxy_cpu = try std.fmt.parseUnsigned(u16, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--quiesce-load")) {
            index += 1;
            flags.quiesce_load = try std.fmt.parseFloat(f64, args[index]);
            // A gate is only worth having if a typo cannot switch it off
            // while still looking switched on: negative and NaN would trip
            // an assert deep in the wait, and `inf` is worse — it passes
            // every check and prints "box quiet" for any load at all. 0 is
            // the one documented way to disable it.
            if (!(flags.quiesce_load >= 0) or !std.math.isFinite(flags.quiesce_load)) {
                std.debug.print("profile: --quiesce-load must be finite and >= 0 (0 disables)\n", .{});
                return error.InvalidArguments;
            }
        } else if (std.mem.eql(u8, arg, "--request-ms")) {
            index += 1;
            flags.request_ms = try std.fmt.parseUnsigned(u32, args[index], 10);
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
                "usage: profile [zoxy-path] [--rate N] [--connections N] [--threads N] " ++
                    "[--seconds N] [--freq N] [--cpu N] [--quiesce-load F] [--request-ms N] " ++
                    "[--protocol l4|http]\n",
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

fn spawnNginx(arena: std.mem.Allocator, io: Io, environ: std.process.Environ) !std.process.Child {
    const prefix = work_directory ++ "/nginx";
    try Io.Dir.cwd().createDirPath(io, prefix ++ "/logs");
    const conf_path = prefix ++ "/profile.conf";
    const conf = try std.fmt.allocPrint(arena,
        \\daemon off;
        \\worker_processes 1;
        \\pid nginx.pid;
        \\error_log logs/error.log crit;
        \\events {{ worker_connections 32768; }}
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

    const nginx_bin = try spawn_path.resolve(arena, io, environ, "nginx");
    return std.process.spawn(io, .{
        .argv = &.{ nginx_bin, "-p", prefix, "-c", "profile.conf" },
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("profile: could not spawn nginx ({t}); is the dev shell loaded?\n", .{err});
        return err;
    };
}

/// Conn slots for a run of `connections` connections, with headroom for the
/// churn a reject or a reconnect leaves behind. Without this the config
/// carried no `limits` block at all, so every run above the default
/// silently spent its window shedding at the admission wall (§8) — the
/// profile would have been of the shed path, not the serving path, and
/// nothing in the output would have said so.
///
/// Both bounds come from `constants`, not from literals here: a ceiling
/// that later moves has to move this with it, and a raised one would
/// otherwise cap a run below the maximum it was aimed at without saying so.
/// Effective pool size for a run of `connections` clients — used for both
/// pools, because they are pinned to each other at the ceiling and for the
/// same reason at the effective size: on the L7 path a busy client
/// connection holds an upstream slot, so leaving `upstream_slots` at its
/// lean default would profile the §8 shed path instead of the proxy. That
/// is not hypothetical — it is what a cloud c10k run measured before the
/// ceilings were pinned (IMPLEMENTATION_NOTES.md).
fn connSlotsFor(connections: u32) u32 {
    assert(connections >= 1);
    const wanted = @as(u64, connections) + connections / 8 + 64;
    const slots: u32 = @intCast(@min(wanted, constants.conn_slots_max));
    assert(slots >= 1);
    assert(slots <= constants.conn_slots_max);
    return @max(slots, constants.conn_slots_default);
}

fn spawnZoxy(
    arena: std.mem.Allocator,
    io: Io,
    zoxy_path: []const u8,
    connections: u32,
    request_ms: u32,
) !std.process.Child {
    assert(connections >= 1);
    // Rejected by the spawned zoxy's own config validation, but only after
    // a spawn and ~2s of `awaitResponsive` retries that report the generic
    // TargetUnresponsive — so catch it here, where the flag was set.
    assert(request_ms <= constants.timeout_ms_max);
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
        \\    "timeouts": {{ "connect_ms": 5000, "idle_ms": 60000, "drain_deadline_ms": 5000,
        \\                   "request_ms": {d} }},
        \\    "limits": {{ "conn_slots": {d}, "upstream_slots": {d} }}
        \\}}
        \\
    , .{
        zoxy_l4_port,
        zoxy_http_port,
        origin_port,
        request_ms,
        connSlotsFor(connections),
        connSlotsFor(connections),
    });
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

/// Reads a small sysfs/procfs file into `buffer`. Null when the file is
/// absent or unreadable — every caller documents its own fallback.
fn readSmallFile(io: Io, path: []const u8, buffer: []u8) ?[]const u8 {
    assert(buffer.len > 0);
    const file = Io.Dir.cwd().openFile(io, path, .{}) catch return null;
    defer file.close(io);
    var read_buffer: [256]u8 = undefined;
    var file_reader = file.reader(io, &read_buffer);
    const len = file_reader.interface.readSliceShort(buffer) catch return null;
    assert(len <= buffer.len);
    return buffer[0..len];
}

/// Whether a sysfs cpu mask (`"0-3"`, `"0,2-3"`) names `cpu`.
///
/// The content is a kernel-owned sysfs file, but it is still parsed as
/// untrusted: a segment that does not parse, or whose bounds are
/// reversed, is skipped rather than trusted or fatal. Skipping can only
/// ever *narrow* the answer to "not this PMU", and every caller's
/// fallback for that is a correct-but-less-specific event.
fn cpuListContains(list: []const u8, cpu: u16) bool {
    var ranges = std.mem.splitScalar(u8, list, ',');
    while (ranges.next()) |range_raw| {
        const range = std.mem.trim(u8, range_raw, " \n\t");
        if (range.len == 0) continue;
        const dash = std.mem.indexOfScalar(u8, range, '-');
        if (dash) |at| assert(at < range.len);
        const low_text = if (dash) |at| range[0..at] else range;
        const high_text = if (dash) |at| range[at + 1 ..] else range;
        // Malformed segment: not a cpu id, so it names no cpu (see above).
        const low = std.fmt.parseUnsigned(u16, low_text, 10) catch continue;
        const high = std.fmt.parseUnsigned(u16, high_text, 10) catch continue;
        if (low > high) continue;
        assert(low <= high);
        if (cpu >= low and cpu <= high) return true;
    }
    return false;
}

/// The cycles event to sample zoxy with, qualified by the PMU that owns
/// the dedicated core.
///
/// This matters on a hybrid part. An unqualified `cycles:u` binds to a
/// single PMU — cpu_atom, as perf resolves it here — while `dedicate`
/// deliberately pins zoxy to a *P*-core. The two never meet, so the run
/// records zero samples and still renders a flamegraph, which reads like
/// a measurement instead of the failure it is. Naming the PMU that owns
/// the chosen cpu keeps the pairing correct whichever core is picked,
/// including a `--cpu` override onto an E-core.
fn cyclesEventFor(io: Io, cpu: u16) []const u8 {
    var buffer: [256]u8 = undefined;
    const event = event: {
        if (readSmallFile(io, "/sys/devices/cpu_core/cpus", &buffer)) |list| {
            if (cpuListContains(list, cpu)) break :event "cpu_core/cycles/u";
        }
        if (readSmallFile(io, "/sys/devices/cpu_atom/cpus", &buffer)) |list| {
            if (cpuListContains(list, cpu)) break :event "cpu_atom/cycles/u";
        }
        break :event "cycles:u";
    };
    // Every arm names a cycles event, PMU-qualified or plain. An empty or
    // unrelated event is what silently records nothing, which is the bug
    // this function exists to prevent.
    assert(event.len > 0);
    assert(std.mem.indexOf(u8, event, "cycles") != null);
    return event;
}

/// The remedy for a box whose `ptrace_scope` forbids the attach. Split
/// out of `main` so the preflight costs it one line, not twelve.
fn refuseNoPtraceAttach() u8 {
    std.debug.print(
        \\profile: kernel.yama.ptrace_scope is not 0, so `perf record -p` cannot
        \\  attach to zoxy and the recording would come back empty. Either:
        \\    sudo sysctl -w kernel.yama.ptrace_scope=0
        \\  or run this profile as root.
        \\
    , .{});
    return 1;
}

/// Whether `perf record -p` can attach to zoxy at all.
///
/// zoxy is spawned as *our* child so it can be pinned, warmed up and
/// drained on SIGTERM; perf is its sibling, not its ancestor. Under
/// `yama/ptrace_scope > 0` the kernel refuses that attach — and perf
/// reports success anyway, writing a header-only perf.data. Checked up
/// front so a misconfigured box costs a message rather than a full load
/// window and an empty flamegraph.
fn ptraceScopeAllowsAttach(io: Io) bool {
    var buffer: [16]u8 = undefined;
    const content = readSmallFile(io, "/proc/sys/kernel/yama/ptrace_scope", &buffer) orelse
        return true;
    assert(content.len <= buffer.len);
    const text = std.mem.trim(u8, content, " \n\t");
    assert(text.len <= content.len);
    // Absent, empty or unreadable all mean "no yama restriction to prove",
    // which is the permissive answer every non-yama kernel gives.
    if (text.len == 0) return true;
    return std.mem.eql(u8, text, "0");
}

fn spawnPerf(
    arena: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    zoxy_pid: std.process.Child.Id,
    event: []const u8,
    flags: *const Flags,
) !std.process.Child {
    // LBR: hardware call-graph from the branch-record MSRs, no frame
    // pointers or DWARF CFI needed. `-- sleep N` bounds the recording to the
    // load window; perf self-terminates when sleep exits and writes the data.
    assert(event.len > 0);
    const pid = try std.fmt.allocPrint(arena, "{d}", .{zoxy_pid});
    const freq = try std.fmt.allocPrint(arena, "{d}", .{flags.freq});
    const seconds = try std.fmt.allocPrint(arena, "{d}", .{flags.duration_s});
    const perf_bin = try spawn_path.resolve(arena, io, environ, "perf");
    // `sleep` is resolved for the same reason every argv[0] here is: a
    // spawned child inherits no PATH, and perf must exec this itself. A
    // bare "sleep" fails, and perf reports the failure as
    //   Failed to collect '<event>' for the 'sleep' workload: No such file
    //   or directory
    // which reads as a PMU problem and sends you hunting the wrong bug —
    // it cost an afternoon before the empty-environment repro pinned it.
    const sleep_bin = try spawn_path.resolve(arena, io, environ, "sleep");
    return std.process.spawn(io, .{
        .argv = &.{
            perf_bin, "record",  "-p",           pid,   "-e", event,
            "-F",     freq,      "--call-graph", "lbr", "-o", perf_data_path,
            "--",     sleep_bin, seconds,
        },
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("profile: could not spawn perf ({t}); is the dev shell loaded?\n", .{err});
        return err;
    };
}

// --- load (zrk, in-process, like bench/run.zig) -----------------------------

fn benchConfig(port: u16, rate: u64, connections: u32, threads: u8) zrk.cli.Config {
    return .{
        .url = .{ .scheme = .http, .host = "127.0.0.1", .port = port, .target = "/" },
        .connections = connections,
        .threads = threads,
        .rate = rate,
        .timeout_ns = 2 * std.time.ns_per_s,
        .interval_ns = std.time.ns_per_s,
        .plain = true,
    };
}

/// Everything that must hold before a measured window opens, settled here
/// rather than discovered after: the two ways this harness can record
/// nothing at all (perf cannot attach, no PMU cycles event) and the one way
/// it can record the wrong thing (a busy box). Null means perf cannot
/// attach and the caller prints the fix; `error.BoxBusy` means the box
/// never went quiet.
fn preflight(io: Io, flags: *const Flags, zoxy_cpu: u16) !?[]const u8 {
    assert(flags.quiesce_load >= 0);
    if (!ptraceScopeAllowsAttach(io)) return null;
    const cycles_event = cyclesEventFor(io, zoxy_cpu);
    assert(cycles_event.len >= 1);
    // Before anything is spawned, so the wait is not itself adding load.
    try awaitQuietBox(io, flags);
    return cycles_event;
}

/// One sample of the loop's io_uring and scheduling counters, every field
/// cumulative since process start (§9) — deltas across the measured window
/// are what mean anything, the absolutes include startup.
///
/// All of it comes from `/proc`, so the proxy needs no instrumentation and
/// the numbers are the kernel's own rather than something zoxy reports
/// about itself.
const RingSample = struct {
    /// SQEs the loop has written: every op it has submitted.
    sqes: u64,
    /// CQEs the kernel has produced: every completion delivered.
    cqes: u64,
    /// Times this process blocked and was woken. The loop blocks in
    /// `io_uring_enter`, so this is the nearest thing to an enter count
    /// obtainable here — the syscall tracepoint needs a
    /// `perf_event_paranoid` this box does not grant, and counting inside
    /// libxev would be a fork change. It counts the enters that *slept*,
    /// which is the half that matters: completions per wake is the loop's
    /// batch depth, and batch depth is what separates "submission-bound"
    /// from "already coalescing".
    ///
    /// Undercounts by every non-blocking enter, and overcounts by every
    /// other voluntary block on this thread — the second only matters if
    /// there ever is one, which §3's one-thread-one-loop says there is
    /// not. Reported batch depth is therefore a lower bound on the truth
    /// in the first case and an upper bound in the second.
    wakes: u64,
    /// Whether the CQ has overflowed, or null when that cannot be told.
    /// Overflowed completions are parked in a kernel list and delivered
    /// late, or dropped outright once that fills — either way the §8
    /// budget that sized the ring was wrong, and nothing else in this
    /// harness would notice.
    ///
    /// Nullable because the one case that must never be reported as a
    /// confident "no" is the one this exists to catch: fdinfo lists every
    /// pending SQE and CQE, one line each, *before* `CqOverflowList:`, so
    /// a ring deep enough to overflow is also a ring whose fdinfo can run
    /// past any fixed read. A missing header then means "did not read far
    /// enough", never "no overflow".
    overflowed: ?bool,
};

/// Highest fd number scanned when looking for the ring. The fd is not
/// assumed because it depends on how many files the process opened first,
/// which is not this harness's business to know; the bound is what keeps
/// the search finite.
const ring_fd_scan_max: u8 = 64;

/// The load average counts as "still falling" while each poll is below
/// the previous one by more than this factor. A ~60s EWMA sampled every
/// 2s decays by `exp(-2/60)` = 0.967 per poll while it is genuinely
/// decaying, so anything above 0.99 is flat rather than falling — the gap
/// between the two is what keeps noise from reading as decay.
const settle_decay_ratio: f64 = 0.99;
/// Consecutive flat polls before the box counts as settled. Two, so a
/// single noisy sample cannot end the wait on its own.
const settle_polls: u32 = 2;

/// The `u64` after `key:` in a `/proc` `key:<whitespace>value` table, or
/// null when the key is absent or its value will not parse. Kernel-owned
/// text, still parsed as untrusted: every caller's fallback for null is to
/// report nothing rather than to report a zero.
fn procField(content: []const u8, key: []const u8) ?u64 {
    assert(key.len >= 1);
    assert(content.len >= 1);
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, key)) continue;
        if (line.len <= key.len or line[key.len] != ':') continue;
        const value = std.mem.trim(u8, line[key.len + 1 ..], " \t");
        return std.fmt.parseUnsigned(u64, value, 10) catch null;
    }
    return null;
}

/// Read the head of a `/proc` file that may be large, into `out`.
///
/// `readSmallFile`'s 256-byte internal buffer is fine for the fixed-size
/// files this harness otherwise reads, and wrong for io_uring's fdinfo:
/// procfs regenerates that text on every read, and once the ring carries
/// thousands of in-flight ops — one printed line each — the read through a
/// small internal buffer fails outright rather than returning a prefix.
/// That failure is what made `readRingSample` skip the ring's own fd and
/// then report no ring at all, on exactly the busy c10k rows the counters
/// were added for.
///
/// A large internal buffer and a small destination: take one big bite,
/// keep the head, which is where every counter this harness wants lives.
fn readProcHead(io: Io, path: []const u8, out: []u8, scratch: []u8) ?[]const u8 {
    assert(out.len > 0);
    assert(scratch.len >= out.len);
    const file = Io.Dir.cwd().openFile(io, path, .{}) catch return null;
    defer file.close(io);
    var file_reader = file.reader(io, scratch);
    const len = file_reader.interface.readSliceShort(out) catch return null;
    assert(len <= out.len);
    return out[0..len];
}

/// Scratch for `readProcHead`, sized from the worst case rather than
/// guessed at — the previous two sizes were both round numbers and both
/// too small.
///
/// io_uring's fdinfo renders a line per pending SQE and CQE, ~89 and ~34
/// bytes, and `constants.in_flight_ops_max` is what bounds how many there
/// can be: ~57k ops at the compiled ceiling, so ~5 MB of text at the
/// worst moment. The kernel appears to want the whole record to fit
/// rather than handing back a prefix, which is why a 64 KiB buffer still
/// failed the busiest c10k rows while working on quieter ones.
const proc_scratch_bytes: usize = 8 << 20;

/// Whether a `/proc` list section named by `header` has any entry under
/// it, or null when the text does not settle it. fdinfo prints list
/// headers unconditionally and indents their entries, while the next
/// section's key starts at column zero — so the first line after the
/// header is the whole answer.
///
/// Null rather than false when the header is absent or ends the text,
/// because for this caller those mean "the read stopped short", and the
/// read stops short precisely when the ring is busiest. Every other parser
/// in this file answers "cannot tell" with null; a bare `bool` here would
/// be the one place that turns an unread file into a confident negative.
fn procListHasEntry(content: []const u8, header: []const u8) ?bool {
    assert(header.len >= 1);
    assert(content.len >= 1);
    const at = std.mem.indexOf(u8, content, header) orelse return null;
    const rest = content[at + header.len ..];
    const newline = std.mem.indexOfScalar(u8, rest, '\n') orelse return null;
    const next_line = rest[newline + 1 ..];
    if (next_line.len == 0) return null;
    return next_line[0] == ' ' or next_line[0] == '\t';
}

/// Sample the ring and scheduling counters for `pid`, or null if the ring
/// fdinfo cannot be found or read — a harness that cannot measure must say
/// so, not print zeroes that read as "no work happened".
fn readRingSample(io: Io, pid: i32, scratch: []u8) ?RingSample {
    assert(pid > 0);
    // A bounded *head* read, deliberately. The counters this exists for
    // sit in the first few hundred bytes; what follows them is a line per
    // pending SQE and CQE, so the file's length scales with in-flight ops
    // and is unbounded in practice. Asking for more of it is not free:
    // procfs regenerates the text per read, so a large destination means
    // many reads of a file that is changing underneath them, and the read
    // fails outright. Sizing this at 64 KiB to "be safe" is exactly what
    // broke four of five c10k rows with `no sample at end of window` —
    // the counters were unreadable precisely when the ring was busy.
    //
    // A full buffer is therefore evidence of a truncated read rather than
    // of a large complete one; the two are indistinguishable from content
    // alone, so the length is what `overflowed` keys its "cannot tell"
    // off, and on a busy ring it will indeed say so.
    var buffer: [4096]u8 = undefined;
    var path_buffer: [64]u8 = undefined;
    var fd: u32 = 0;
    var readable: u32 = 0;
    while (fd < ring_fd_scan_max) : (fd += 1) {
        assert(fd < ring_fd_scan_max);
        const path = std.fmt.bufPrint(
            &path_buffer,
            "/proc/{d}/fdinfo/{d}",
            .{ pid, fd },
        ) catch continue;
        const content = readProcHead(io, path, &buffer, scratch) orelse continue;
        readable += 1;
        // `SqMask` is io_uring's own marker: no other fd type prints it.
        if (std.mem.indexOf(u8, content, "SqMask:") == null) continue;
        // Both counters print near the top, ahead of any per-entry list,
        // so they survive a truncated read; the overflow flag does not.
        const sqes = procField(content, "SqTail") orelse return null;
        const cqes = procField(content, "CqTail") orelse return null;
        // The list header is always printed, so its presence proves
        // nothing; what distinguishes an overflow is an *entry* under it.
        // Entries are indented (`PollList` prints its own the same way)
        // and the next section key is not, so the first following line
        // decides it. Getting this backwards reads `NAPI:` as an overflow
        // and cries wolf on every run. A filled buffer means the header
        // may simply lie past what was read, which is "cannot tell".
        const truncated = content.len == buffer.len;
        const overflowed = if (truncated) null else procListHasEntry(content, "CqOverflowList:");
        var status_buffer: [4096]u8 = undefined;
        const status_path = std.fmt.bufPrint(&path_buffer, "/proc/{d}/status", .{pid}) catch return null;
        const status = readProcHead(io, status_path, &status_buffer, scratch) orelse return null;
        const wakes = procField(status, "voluntary_ctxt_switches") orelse return null;
        assert(cqes <= sqes); // A completion the loop never submitted is impossible.
        return .{ .sqes = sqes, .cqes = cqes, .wakes = wakes, .overflowed = overflowed };
    }
    // Say which way it failed. "No ring under fd 64" and "no fdinfo at all"
    // are different bugs — the first means the scan bound is too low for a
    // process whose low fds are taken, the second means the pid is wrong or
    // gone — and a bare null made a whole c10k sweep unattributable.
    std.debug.print(
        "profile: ring  no io_uring fd under {d} for pid {d} ({d} fdinfo entries readable)\n",
        .{ ring_fd_scan_max, pid, readable },
    );
    return null;
}

/// Report what the ring did across the measured window: ops and
/// completions per request, and the batch depth that says whether the loop
/// is submission-bound. Silent when either sample is missing — see
/// `readRingSample`.
fn printRingDelta(io: Io, pid: i32, before: *const ?RingSample, completed: u64, scratch: []u8) void {
    assert(pid > 0);
    const start = before.* orelse return;
    const end = readRingSample(io, pid, scratch) orelse {
        std.debug.print("profile: ring  unavailable (no sample at end of window)\n", .{});
        return;
    };
    // Every counter is cumulative and this process never restarted, so a
    // counter that went backwards means the sample is not of the same ring
    // — say so rather than print a saturated zero that reads as "idle".
    if (end.sqes < start.sqes or end.cqes < start.cqes or end.wakes < start.wakes) {
        std.debug.print("profile: ring  discarded (counters went backwards)\n", .{});
        return;
    }
    if (completed == 0) return;
    const sqes = end.sqes - start.sqes;
    const cqes = end.cqes - start.cqes;
    const wakes = end.wakes - start.wakes;
    assert(completed >= 1);
    const per_request = @as(f64, @floatFromInt(cqes)) / @as(f64, @floatFromInt(completed));
    const batch = if (wakes >= 1)
        @as(f64, @floatFromInt(cqes)) / @as(f64, @floatFromInt(wakes))
    else
        0;
    std.debug.print(
        "profile: ring  sqes {d} ({d:.2}/req)  cqes {d} ({d:.2}/req)  " ++
            "wakes {d} ({d:.1} cqes/wake)  cq-overflow {s}\n",
        .{
            sqes,
            @as(f64, @floatFromInt(sqes)) / @as(f64, @floatFromInt(completed)),
            cqes,
            per_request,
            wakes,
            batch,
            if (end.overflowed) |o| (if (o) "YES" else "no") else "unknown",
        },
    );
}

/// The 1-minute load average, or null when `/proc/loadavg` is absent, will
/// not parse, or parses to something a load average cannot be — callers
/// treat all three as "cannot tell", never as zero. Negative and NaN are
/// rejected rather than asserted for the same reason `cpuListContains`
/// skips a malformed range: this is kernel-owned text, but it is still
/// parsed as untrusted, and refusing to answer can only narrow the gate,
/// never widen it.
fn readLoadAverage(io: Io) ?f64 {
    var buffer: [64]u8 = undefined;
    const content = readSmallFile(io, "/proc/loadavg", &buffer) orelse return null;
    var fields = std.mem.tokenizeScalar(u8, content, ' ');
    const first = fields.next() orelse return null;
    assert(first.len >= 1);
    const load = std.fmt.parseFloat(f64, first) catch return null;
    if (!(load >= 0)) return null; // Also catches NaN, which no comparison holds for.
    return load;
}

/// Hold the run until the box is quiet (§9).
///
/// A Tier-0 number means something only because perf samples are CPU time
/// on a core this harness pinned — and a core it did not actually get is
/// measuring contention, not the proxy. That failure is silent: the run
/// completes, prints a smaller number, and looks exactly like a real
/// result. So gate on it rather than trusting the operator to notice, and
/// print the load either way so the report carries the evidence.
///
/// There is deliberately **no absolute threshold**. A fixed number cannot
/// tell a busy neighbour from an ordinary desktop: 0.5 is unreachable on
/// a box whose idle floor is 1.5, and trivially passed on one idle at 0.1
/// while a neighbour is spinning up. What is universal is the *shape* —
/// the 1-minute average is a ~60s EWMA, so after this harness's own
/// previous row (which drives about seven cores) it falls steeply and
/// then flattens at whatever this box's floor happens to be. Wait for the
/// flattening, report the floor it settled at, and let a row taken beside
/// a neighbour carry that evidence rather than hide it.
///
/// The first version got this wrong in a way worth recording. It waited
/// for load <= 0.5 with a 180s timeout, and decaying from ~7 to 0.5 takes
/// `60 * ln(14)` = 158s on a *perfectly* idle box. Twenty-two seconds of
/// margin, so back-to-back rows failed on any ambient load at all — which
/// read as neighbour contention and was mostly self-inflicted.
///
/// `--quiesce-load` still imposes a hard ceiling for anyone who wants
/// one, but defaults off: the settled value is reported either way, and a
/// number in the report beats a refusal whose cause has to be guessed.
fn awaitQuietBox(io: Io, flags: *const Flags) !void {
    assert(flags.quiesce_timeout_s >= 1);
    assert(flags.quiesce_load >= 0);
    const poll_s: u64 = 2;
    const poll = Io.Duration.fromNanoseconds(poll_s * std.time.ns_per_s);
    const attempts_max: u64 = @max(@divFloor(flags.quiesce_timeout_s, poll_s), 1);
    var attempt: u64 = 0;
    var previous: f64 = 0;
    var flat_polls: u32 = 0;
    while (attempt < attempts_max) : (attempt += 1) {
        // No procfs is not evidence of a busy box; a gate that cannot read
        // its input must not invent a verdict. It prints nothing either,
        // so a report from such a box is silent about load rather than
        // claiming a clean one.
        const observed = readLoadAverage(io) orelse return;
        assert(observed >= 0);
        // Falling by less than the decay would predict — or rising, which
        // means a neighbour just started and waiting only wastes time.
        const flattened = attempt >= 1 and observed > previous * settle_decay_ratio;
        flat_polls = if (flattened) flat_polls + 1 else 0;
        previous = observed;
        if (flat_polls >= settle_polls) {
            if (flags.quiesce_load > 0 and observed > flags.quiesce_load) {
                std.debug.print(
                    "profile: box settled at load {d:.2}, over the {d:.2} ceiling asked for\n",
                    .{ observed, flags.quiesce_load },
                );
                return error.BoxBusy;
            }
            std.debug.print(
                "profile: box settled at load {d:.2} after {d}s\n",
                .{ observed, attempt * poll_s },
            );
            return;
        }
        // The only error is cancellation; a cut-short sleep just means the
        // next poll happens sooner, which the loop bound already covers.
        io.sleep(poll, .awake) catch {};
    }
    std.debug.print(
        "profile: load never settled in {d}s (last {d:.2}); measuring anyway, " ++
            "treat this row as suspect\n",
        .{ flags.quiesce_timeout_s, previous },
    );
}

fn awaitResponsive(arena: std.mem.Allocator, io: Io, flags: *const Flags) !void {
    const attempts_max: u8 = 10;
    const retry_sleep = Io.Duration.fromNanoseconds(200 * std.time.ns_per_ms);
    var attempt: u8 = 0;
    while (attempt < attempts_max) : (attempt += 1) {
        // A 16-connection probe over one thread: this only has to prove the
        // path serves before the measured window, so it deliberately does
        // not inherit the run's connection count or thread pool.
        var config = benchConfig(flags.zoxyPort(), 20_000, 16, 1);
        config.duration_ns = std.time.ns_per_s / 2;
        const report = zrk.runner.run(arena, io, &config, 0, null, null, null) catch {
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
    return zrk.runner.run(arena, io, &config, 0, null, null, null);
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

fn generateFlamegraph(arena: std.mem.Allocator, io: Io, environ: std.process.Environ) !void {
    try runToFile(arena, io, environ, &.{ "perf", "script", "-i", perf_data_path }, script_path);
    try requireSamples(io);
    try runToFile(arena, io, environ, &.{ "stackcollapse-perf.pl", script_path }, folded_path);
    try runToFile(arena, io, environ, &.{
        "flamegraph.pl", "--title",
        "zoxy under load (user cycles, LBR call-graph) — see run for path",
        folded_path,
    }, svg_path);
    std.debug.print("profile: flamegraph -> {s}\n", .{svg_path});
}

/// A sample-free recording folds and renders exactly like a real one —
/// into an empty flamegraph that reads as a measurement. The preflight
/// checks cover the two causes seen so far; this catches every other one,
/// so a profile is never quietly nothing.
fn requireSamples(io: Io) !void {
    var buffer: [1]u8 = undefined;
    const head = readSmallFile(io, script_path, &buffer) orelse "";
    assert(head.len <= buffer.len);
    // One byte of `perf script` output is one sample folded; zero bytes is
    // a recording that captured nothing at all.
    if (head.len > 0) return;
    std.debug.print(
        \\profile: perf recorded zero samples — no flamegraph written.
        \\  Check that the event bound to the PMU owning zoxy's core, and that
        \\  perf could attach (kernel.yama.ptrace_scope, perf_event_paranoid).
        \\
    , .{});
    return error.NoSamplesRecorded;
}

/// Spawn `argv` with stdout redirected to `out_path` — the Zig stand-in for a
/// shell `argv > out_path`. Each flamegraph stage reads a file arg and writes
/// its stage output, so no inter-process pipe is needed. argv[0] is resolved
/// against $PATH ourselves (see spawn_path.zig: zio doesn't do it for a bare
/// name the way the default std.Io.Threaded backend does).
fn runToFile(
    arena: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    argv: []const []const u8,
    out_path: []const u8,
) !void {
    assert(argv.len > 0);
    const out = try Io.Dir.cwd().createFile(io, out_path, .{});
    defer out.close(io);
    const resolved_argv = try arena.dupe([]const u8, argv);
    resolved_argv[0] = try spawn_path.resolve(arena, io, environ, argv[0]);
    var child = std.process.spawn(io, .{
        .argv = resolved_argv,
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

fn printTopSymbols(arena: std.mem.Allocator, io: Io, environ: std.process.Environ) !void {
    runToFile(arena, io, environ, &.{
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
