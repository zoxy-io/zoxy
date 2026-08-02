//! Tier-1 loopback benchmark (DESIGN.md §9): the same constant-throughput
//! zrk load (coordinated-omission-corrected) against the origin directly,
//! through zoxy, and through haproxy as the state-of-the-art reference,
//! printed as comparable bands — never single numbers; compare bands
//! across runs. Also witnesses the §5 closed form from the outside: the
//! slabs are lazily resident (IMPLEMENTATION_NOTES "lazy fault-in"), a
//! saturating warmup drives RSS toward its bound, and the measured run
//! must hold RSS under the banner's memory total plus a fixed overhead
//! slack — the budget as a machine-checked ceiling, every run.
//!
//! By default an nginx origin is spawned with a generated config (the dev
//! shell provides nginx and haproxy); pass `--origin host:port` to reuse
//! any live HTTP origin instead. zoxy is drained with SIGTERM at the end,
//! so every run also exercises the drain path. Core pinning is
//! deliberately left to the caller (taskset) until the CI band policy
//! needs it.
//!
//! zrk's runner calls io.net.connect with a timeout; the default
//! std.Io.Threaded backend (init.io) still stubs that path with a TODO
//! panic, so the harness drives zrk off its own zio.Runtime instead — the
//! same runtime zrk's own CLI (main.zig) constructs for itself. Single
//! executor: this call is synchronous per scenario, and the dedicated-core
//! split below already reserves everything but the proxy's core for this
//! process.

const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;

const affinity = @import("affinity.zig");
const zrk = @import("zrk");
const zio = @import("zio");
const spawn_path = @import("spawn_path.zig");

const assert = std.debug.assert;

const zoxy_port: u16 = 18180;
const zoxy_http_port: u16 = 18181;
const origin_port: u16 = 19180;
const haproxy_port: u16 = 17180;
const haproxy_http_port: u16 = 17181;
const overload_http_port: u16 = 18291;
const work_directory = ".zig-cache/zoxy-bench";

/// The overload scenario's shape (§9): a second zoxy shrunk via the
/// config `limits` block so offered load ≫ capacity is loopback-feasible,
/// and a connection count far past its relay buffers so both §8 rungs
/// fire — accept-RSTs at the conn wall, 503s at the relay-buffer rung.
/// The 5xx witness is the thinnest gate (most excess dies at the conn
/// wall first): if it flakes on a fast box, raise `overload_connections`
/// or shrink `relay_buffers` rather than deleting the gate.
const overload_limits = .{ .conn_slots = 64, .relay_buffers = 4, .upstream_slots = 8 };
const overload_connections: u32 = 256;

comptime {
    // The scenario's premise, pinned: the offered connections must
    // overwhelm the conn wall, and the relay rung must sit inside it so
    // admitted requests still contend for buffers (the 503 witness).
    assert(overload_connections > overload_limits.conn_slots);
    assert(overload_limits.relay_buffers < overload_limits.conn_slots);
    assert(overload_limits.relay_buffers >= 1);
}

/// The bulk response the large-body bands request. 256 KiB is 64 relay
/// buffers' worth (§5's 4 KiB halves), so a request is dominated by the
/// recv→send→recv loop rather than by its head — which is the point: these
/// bands price a *byte*, where the keep-alive bands price a request. The
/// path is served by the origin from a file of this size.
const large_body_bytes: u32 = 256 * 1024;
const large_body_target = "/large.bin";

/// The saturating warmup's per-run length (§9 RSS gate). Long enough to
/// fault every pool the scenario touches to the peak the measured bands
/// will hold — that peak is O(connections), reached within the first
/// second — while staying noise beside the ten-second bands. The
/// keep-alive leg alone stretches past this when the offered rate is too
/// low to cycle the whole head ring (see `saturate`).
const saturate_duration_s: u64 = 2;

/// Slack over the banner total for what a live process holds outside the
/// §5 closed form: text+rodata, libc, thread stacks, and the io_uring
/// SQ/CQ and buf_ring mappings (~2 MiB measured at the bench shape).
/// Generous on purpose — the ceiling gate exists to catch a *breach of
/// the closed form*, not to re-measure the runtime's overhead every run.
const rss_ceiling_slack_kb: u64 = 8 * 1024;

comptime {
    assert(saturate_duration_s >= 1);
    // The ceiling must stay meaningfully below the smallest §5 budget a
    // bench shape prints (~31 MiB), or the gate gates nothing.
    assert(rss_ceiling_slack_kb <= 16 * 1024);
}

/// The §9 rate floor, as a percentage of the offered rate. A band that
/// cannot keep up is a finding, not a pass: the error gates check *how*
/// requests failed and never *whether* they happened, which is how a TLS
/// band delivering 704 of 2000 req/s once went green
/// (IMPLEMENTATION_NOTES.md). Every band this applies to has measured
/// within a fraction of a percent of its offer, so the floor sits far
/// enough below to leave loopback jitter alone while catching a collapse.
/// The overload scenario is exempt by construction — it offers far past
/// capacity on purpose.
const rate_floor_percent: u64 = 90;

const Flags = struct {
    rate: u64 = 20_000,
    // Connection: close is one TCP handshake per request, so on loopback
    // it is connect-bound: at this rate the TIME_WAIT population
    // (rate x 60 s) already exceeds the ~28k ephemeral-port pool, so the
    // run leans on net.ipv4.tcp_tw_reuse (on by default on modern Linux
    // and in the dev shell) to reclaim source ports. Without it, lower
    // --close-rate toward ~400/s or the socket-error gate will trip on
    // port exhaustion, not a proxy fault. This is a latency band (the
    // per-request hop cost), never a throughput number.
    close_rate: u64 = 2_000,
    /// Requests per second for the large-body bands. At
    /// `large_body_bytes` each, 400/s offers ~100 MiB/s through the hop —
    /// enough that per-byte cost dominates, and well inside what loopback
    /// and a 4 KiB relay buffer sustain, so the band measures the proxy
    /// rather than the generator.
    large_rate: u64 = 400,
    connections: u32 = 32,
    duration_s: u64 = 10,
    origin: ?[]const u8 = null,
    zoxy_path: []const u8 = "zig-out/bin/zoxy",
};

/// The one header that turns a run into the Connection: close scenario.
/// zrk emits user headers verbatim and only falls back to its default
/// keep-alive when no Connection header is supplied, so this both forces
/// the origin/proxy to close after each response and makes zrk reconnect
/// for the next request — each a completed, CO-corrected sample.
const close_headers = [_]zrk.cli.Header{.{ .name = "Connection", .value = "close" }};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const rt = try zio.Runtime.init(arena, .{});
    defer rt.deinit();
    const io = rt.io();
    const environ = init.minimal.environ;
    const args = try init.minimal.args.toSlice(arena);
    const flags = try parseFlags(args);

    try Io.Dir.cwd().createDirPath(io, work_directory);

    // Dedicate one core to the proxy under test and pin this process (its
    // zrk load threads) and the inherited origin off it, so bands measure
    // the proxy, not contention with the generator (§3). Both proxies
    // share that core since scenarios run sequentially; pinning happens
    // before spawning so children inherit the mask.
    const proxy_cpu = affinity.dedicate(io, null);

    var origin_child: ?std.process.Child = null;
    const origin_address = flags.origin orelse spawn_origin: {
        origin_child = try spawnNginx(arena, io, environ);
        break :spawn_origin try std.fmt.allocPrint(arena, "127.0.0.1:{d}", .{origin_port});
    };
    // kill() blocks until the child dies and reaps it (and sets id null),
    // so a wait() after it would trip wait's id != null assertion — UB
    // that manifested as a SEGV in this ReleaseFast harness.
    defer if (origin_child) |*child| child.kill(io);

    var zoxy_child = try spawnZoxy(arena, io, flags.zoxy_path, origin_address);
    var zoxy_running = true;
    defer if (zoxy_running) zoxy_child.kill(io);
    // The banner is the first thing zoxy prints, so a failed bind or a
    // binary that does not speak §5 surfaces here, before any load runs.
    const banner = try readBanner(io, &zoxy_child);

    var haproxy_child = try spawnHaproxy(arena, io, environ, origin_address);
    defer haproxy_child.kill(io);

    if (proxy_cpu) |cpu| {
        affinity.pinChildTo(zoxy_child.id.?, cpu);
        affinity.pinChildTo(haproxy_child.id.?, cpu);
        std.debug.print("bench: proxy under test pinned to cpu {d}; origin + load off it\n", .{cpu});
    }

    const direct_port = originPortOf(origin_address);
    try warmUp(arena, io, direct_port);
    try saturate(arena, io, &flags, banner.head_buffers);

    const modes =
        try runMeasuredWindow(arena, io, direct_port, &flags, zoxy_child.id, banner.total_kb);

    // The §9 overload scenario runs against its own shrunken zoxy — the
    // primary is idle during it, so its RSS window stays clean.
    const overload_ok = try runOverload(arena, io, &flags, origin_address, proxy_cpu);

    const drained_cleanly = try drainChild(io, &zoxy_child, &zoxy_running, "zoxy");
    const passed = benchPassed(&modes, banner.total_kb, &flags, drained_cleanly) and overload_ok;
    return if (passed) 0 else 1;
}

/// The three measured band matrices, plus the RSS reading that closed
/// their shared window — what `benchPassed` gates on.
const MeasuredModes = struct {
    keep_alive: Runs,
    close_mode: Runs,
    large_body: Runs,
    rss_after_kb: u64,
};

/// Run the full band matrix for every scenario inside one RSS window,
/// then print the bands beside the window's climb toward the §5 budget.
/// Both modes on both zoxy protocols run inside the window, so the
/// ceiling is held across reconnect-heavy close load too — not just
/// steady keep-alive. The haproxy references share the window; zoxy is
/// idle during them, so they cannot inflate its resident set.
fn runMeasuredWindow(
    arena: std.mem.Allocator,
    io: Io,
    direct_port: u16,
    flags: *const Flags,
    zoxy_pid: ?std.process.Child.Id,
    budget_kb: u64,
) !MeasuredModes {
    assert(direct_port != 0);
    assert(budget_kb > 0);
    const rss_before_kb = try readRssKb(arena, io, zoxy_pid);
    // A live proxy always has resident pages; a zero reading means the
    // RSS probe failed, not that the process shrank to nothing.
    assert(rss_before_kb > 0);
    std.debug.print(
        "bench: keep-alive {d}/s, close {d}/s, {d} connections, {d}s per run\n",
        .{ flags.rate, flags.close_rate, flags.connections, flags.duration_s },
    );
    const keep_alive = try runMode(arena, io, direct_port, flags, .keep_alive);
    const close_mode = try runMode(arena, io, direct_port, flags, .close);
    const large_body = try runMode(arena, io, direct_port, flags, .large_body);
    const rss_after_kb = try readRssKb(arena, io, zoxy_pid);

    printMode("keep-alive", &keep_alive, .keep_alive);
    printMode("Connection: close", &close_mode, .close);
    printMode("large body", &large_body, .large_body);
    std.debug.print("zoxy RSS: {d} KiB -> {d} KiB (budget {d} KiB)\n", .{
        rss_before_kb,
        rss_after_kb,
        budget_kb,
    });
    return .{
        .keep_alive = keep_alive,
        .close_mode = close_mode,
        .large_body = large_body,
        .rss_after_kb = rss_after_kb,
    };
}

/// Drain, not just death (§8): SIGTERM, wait for a clean exit, report.
/// Clears `running` so the caller's guarded defer cannot double-kill.
fn drainChild(
    io: Io,
    child: *std.process.Child,
    running: *bool,
    label: []const u8,
) !bool {
    assert(label.len > 0);
    assert(running.*);
    try std.posix.kill(child.id.?, .TERM);
    // A child whose stderr this harness piped (the banner gate) writes
    // its drain-time counter dump there: forward it to the run log for
    // the band review, reading to EOF *before* the reap — the read is
    // what observes the exit, and `wait` may tear the pipe down.
    if (child.stderr != null) forwardStderr(io, child);
    const term = try child.wait(io);
    running.* = false;
    const drained_cleanly = term == .exited and term.exited == 0;
    std.debug.print("{s} drain: {s}\n", .{ label, if (drained_cleanly) "clean exit" else "UNCLEAN" });
    return drained_cleanly;
}

/// Pump the child's piped stderr into this process's own until EOF. The
/// child has been told to exit, so EOF is guaranteed; the cap is misuse
/// insurance (a chatty child), not a liveness need.
fn forwardStderr(io: Io, child: *const std.process.Child) void {
    assert(child.stderr != null);
    const chunks_max: u32 = 128;
    var read_buffer: [8192]u8 = undefined;
    var file_reader = child.stderr.?.reader(io, &read_buffer);
    var forwarded: u64 = 0;
    var chunk_index: u32 = 0;
    while (chunk_index < chunks_max) : (chunk_index += 1) {
        var chunk: [8192]u8 = undefined;
        const read = file_reader.interface.readSliceShort(&chunk) catch |err| {
            // Surfaced, not gated: the dump is band-review context, and a
            // torn pipe must not turn a finished run red — but it must
            // say so, or a missing dump reads as a zoxy bug.
            std.debug.print("bench: child stderr unreadable ({t})\n", .{err});
            return;
        };
        if (read == 0) return;
        assert(read <= chunk.len);
        forwarded += read;
        std.debug.print("{s}", .{chunk[0..read]});
    }
    std.debug.print("bench: child stderr still open after {d} KiB forwarded; giving up\n", .{
        forwarded / 1024,
    });
}

/// The §9 overload scenario: offered load ≫ capacity against a zoxy
/// whose pools are shrunk via the config `limits` block. Asserts the §8
/// promise from the outside: flat memory, admitted work served (2xx),
/// all excess shed with a correct status (5xx and accept-RSTs — the
/// latter are the conn-slot wall, so zrk's connect errors are exempt
/// from the health gate), bounded latency for what was admitted, and a
/// clean drain. SIGUSR1 lands the counter dump in the run log first.
fn runOverload(
    arena: std.mem.Allocator,
    io: Io,
    flags: *const Flags,
    origin_address: []const u8,
    proxy_cpu: ?u16,
) !bool {
    assert(flags.duration_s >= 1);
    assert(flags.rate >= 1);
    var child = try spawnOverloadZoxy(arena, io, flags.zoxy_path, origin_address);
    var running = true;
    defer if (running) child.kill(io);
    if (proxy_cpu) |cpu| {
        affinity.pinChildTo(child.id.?, cpu);
    }
    _ = try awaitResponsive(arena, io, overload_http_port, "zoxy overload");

    // The same saturate-then-measure discipline as the primary (§9): the
    // shrunken pools are lazily resident too, and an overload burst is
    // its own saturation — the walls this scenario exists to hit fault
    // everything a longer run can touch.
    var config = benchConfig(overload_http_port, overload_connections, flags.rate, "/");
    config.duration_ns = saturate_duration_s * std.time.ns_per_s;
    _ = try zrk.runner.run(arena, io, &config, 0, null, null, null);

    const rss_before_kb = try readRssKb(arena, io, child.id);
    config.duration_ns = flags.duration_s * std.time.ns_per_s;
    const report = try zrk.runner.run(arena, io, &config, 0, null, null, null);
    const rss_after_kb = try readRssKb(arena, io, child.id);

    std.debug.print("-- overload (offered >> capacity) --\n", .{});
    printReport("zoxy overload", &report, .keep_alive);
    std.debug.print("zoxy overload RSS: {d} KiB -> {d} KiB\n", .{ rss_before_kb, rss_after_kb });

    // The counter dump (sheds, pressure engagements) lands in the run
    // log for the human band review before the drain.
    try std.posix.kill(child.id.?, .USR1);
    const drained_cleanly = try drainChild(io, &child, &running, "zoxy overload");
    return overloadPassed(rss_before_kb, rss_after_kb, &report, drained_cleanly);
}

/// The overload gates. The stall gate holds `timeouts` — and only
/// `timeouts` — under 1% of completions, because that is the one
/// client-visible failure that belongs to *admitted* work: a request that
/// completed is a sample whatever its status, and one that never got an
/// answer is a timeout.
///
/// Connect, write and read errors are all the conn-slot wall's RST,
/// observed at whichever syscall the generator happened to be in when it
/// landed. Measured (#82): with `timeouts` at zero the three are the
/// whole of zrk's `socketErrors()`, and on the four runs that captured
/// zoxy's counters alongside, that total landed within 0.1% of its
/// `shed_conn_slots` — one socket error per connection the wall refused.
/// How they divide is pure race: across six runs the connect share ranged
/// 28–54%, write 43–71%, read 1.3–3.3%. The old gate exempted the connect share
/// as "the shed working as designed", ignored the write share, and failed
/// the run on the read share, so it measured how much load was refused
/// rather than how well the proxy served what it took: 2–14% against a 1%
/// ceiling, with `timeouts` at zero every time.
///
/// A relay that genuinely breaks mid-exchange is still gated — by
/// `proxiesHealthy` on the keep-alive, close and large-body bands, where
/// no RST wall fires and a socket error can only be the proxy's fault.
/// What this band cannot do is tell the two apart, so it does not try.
fn overloadPassed(
    rss_before_kb: u64,
    rss_after_kb: u64,
    report: *const zrk.runner.Report,
    drained_cleanly: bool,
) bool {
    assert(rss_before_kb > 0);
    assert(rss_after_kb > 0);
    const counters = &report.snapshot.counters;
    // Flatness is sound here where the primary window's gate is a
    // ceiling instead (`benchPassed`): this zoxy's *entire* pool budget
    // (~0.75 MiB at `overload_limits`) sits inside the tolerance, so
    // lazy fault-in can never trip it — only an allocation can.
    const rss_flat = rss_after_kb <= rss_before_kb + 1024;
    if (!rss_flat) {
        std.debug.print("FAIL: overload zoxy RSS grew under overload\n", .{});
    }
    // Admitted work is served AND the excess is shed with a status: both
    // ends of the §8 promise, witnessed in one run.
    const served = counters.status_class[2] > 0;
    if (!served) {
        std.debug.print("FAIL: overload run served no 2xx at all\n", .{});
    }
    const shed_witnessed = counters.status_class[5] > 0;
    if (!shed_witnessed) {
        std.debug.print("FAIL: overload run witnessed no 5xx shed status\n", .{});
    }
    // Bounded latency for admitted work: every completion (2xx and fast
    // 5xx sheds alike) landed within zrk's wire timeout, or it would be
    // a timeout here, not a sample.
    const stalls = counters.timeouts;
    const stalls_ok = stalls * 100 < counters.completed;
    if (!stalls_ok) {
        std.debug.print(
            "FAIL: overload stall rate too high ({d} of {d} completed)\n",
            .{ stalls, counters.completed },
        );
    }
    // The band log is read by a human (§9), so print the split every run
    // rather than only when the gate trips: a threshold whose margin is
    // invisible until it fails cannot be watched across runs, which is how
    // this one sat mis-specified (#82). The refused count is the wall's
    // work, not a fault — it belongs in the log, never in the verdict.
    const refused = counters.connect_errors + counters.write_errors + counters.read_errors;
    std.debug.print(
        "zoxy overload refused {d} at the wall (connect {d}, write {d}, read {d}); {d} timed out\n",
        .{ refused, counters.connect_errors, counters.write_errors, counters.read_errors, stalls },
    );
    if (!drained_cleanly) {
        std.debug.print("FAIL: overload zoxy did not drain cleanly\n", .{});
    }
    return rss_flat and served and shed_witnessed and stalls_ok and drained_cleanly;
}

/// A second zoxy with its pools shrunk through the config `limits`
/// block (§5) — the §8 rungs become reachable at loopback-feasible load.
fn spawnOverloadZoxy(
    arena: std.mem.Allocator,
    io: Io,
    zoxy_path: []const u8,
    origin_address: []const u8,
) !std.process.Child {
    const config_path = work_directory ++ "/zoxy-overload.json";
    const config_json = try std.fmt.allocPrint(arena,
        \\{{
        \\    "listeners": [
        \\        {{ "bind": "127.0.0.1:{d}", "cluster": "origin", "protocol": "http" }}
        \\    ],
        \\    "clusters": {{
        \\        "origin": {{ "endpoints": ["{s}"] }}
        \\    }},
        \\    "timeouts": {{
        \\        "connect_ms": 5000,
        \\        "idle_ms": 60000,
        \\        "drain_deadline_ms": 5000
        \\    }},
        \\    "limits": {{
        \\        "conn_slots": {d},
        \\        "relay_buffers": {d},
        \\        "upstream_slots": {d}
        \\    }}
        \\}}
        \\
    , .{
        overload_http_port,
        origin_address,
        overload_limits.conn_slots,
        overload_limits.relay_buffers,
        overload_limits.upstream_slots,
    });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = config_json });

    return std.process.spawn(io, .{
        .argv = &.{ zoxy_path, config_path },
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("bench: could not spawn overload {s} ({t})\n", .{ zoxy_path, err });
        return err;
    };
}

/// What the harness reads off the §5 banner, from the outside — no
/// import of zoxy's constants, so the numbers gate what the binary
/// *said*, not what the source says it should have.
const Banner = struct {
    /// The closed-form memory total: the RSS ceiling `benchPassed` holds.
    total_kb: u64,
    /// The head-ring entry count: the saturation floor — the kernel
    /// consumes the ring FIFO, so only that many served requests prove
    /// the ring's slab fully resident (`saturate`).
    head_buffers: u64,
};

/// Read the banner off the child's piped stderr, forward it verbatim to
/// the run log (bug reports paste the banner; the pipe must not eat it),
/// and parse the two numbers the RSS gates need. Bounded by the banner's
/// own shape — it ends at the "  config  " line — so a child that dies
/// first or prints something else is a setup failure surfaced here.
fn readBanner(io: Io, child: *const std.process.Child) !Banner {
    assert(child.id != null);
    assert(child.stderr != null);
    const banner_lines_max: u32 = 32;
    const total_prefix = "  memory  total ";
    // "+ head buffers" cannot match the upstream line, which spells
    // "+ upstream head buffers".
    const ring_marker = "+ head buffers ";
    const last_line_prefix = "  config  ";
    var read_buffer: [4096]u8 = undefined;
    var file_reader = child.stderr.?.reader(io, &read_buffer);
    const reader = &file_reader.interface;
    var banner: Banner = .{ .total_kb = 0, .head_buffers = 0 };
    var line_index: u32 = 0;
    while (line_index < banner_lines_max) : (line_index += 1) {
        // `takeDelimiter` advances past the newline (its Exclusive
        // sibling stops *at* it and would yield empty lines forever);
        // null is EOF — a child that died before finishing its banner.
        const maybe_line = reader.takeDelimiter('\n') catch |err| {
            std.debug.print("bench: zoxy banner unreadable ({t})\n", .{err});
            return error.BannerUnreadable;
        };
        const line = maybe_line orelse {
            std.debug.print("bench: zoxy banner ended early\n", .{});
            return error.BannerUnreadable;
        };
        std.debug.print("{s}\n", .{line});
        if (std.mem.startsWith(u8, line, total_prefix)) {
            banner.total_kb = try leadingInteger(line[total_prefix.len..]);
        }
        if (std.mem.indexOf(u8, line, ring_marker)) |marker| {
            banner.head_buffers = try leadingInteger(line[marker + ring_marker.len ..]);
        }
        if (std.mem.startsWith(u8, line, last_line_prefix)) {
            // The banner's last line; both numbers must have preceded it.
            // A zero-entry ring cannot happen here: the bench config
            // always declares an http listener, which the loader answers
            // with head_buffers >= 1.
            if (banner.total_kb == 0 or banner.head_buffers == 0) {
                std.debug.print("bench: banner is missing its §5 numbers\n", .{});
                return error.BannerUnreadable;
            }
            return banner;
        }
    }
    std.debug.print("bench: no banner end within {d} lines\n", .{banner_lines_max});
    return error.BannerUnreadable;
}

/// The decimal integer a banner field starts with. A field with none —
/// including an empty one, reachable from a version-skewed binary's
/// output — is a banner this harness cannot trust, never a panic.
fn leadingInteger(text: []const u8) !u64 {
    const end = std.mem.indexOfNone(u8, text, "0123456789") orelse text.len;
    assert(end <= text.len);
    if (end == 0) return error.BannerUnreadable;
    const value = try std.fmt.parseUnsigned(u64, text[0..end], 10);
    assert(value > 0 or text[0] == '0');
    return value;
}

/// Drive RSS toward its §5 bound before the window opens (§9). The
/// pools are lazily resident, so an unwarmed window would hold the
/// ceiling trivially at a fraction of the budget: every scenario runs
/// briefly at the measured connection count on both zoxy ports, and the
/// keep-alive leg runs long enough to cycle the whole head ring (FIFO
/// selection walks every buffer). This makes the ceiling gate
/// non-vacuous; it cannot make *flatness* sound — small heads fault
/// only the first page of each buffer, so later traffic may legally
/// fault pages no warmup provably reaches (`benchPassed`).
fn saturate(arena: std.mem.Allocator, io: Io, flags: *const Flags, head_buffers: u64) !void {
    assert(flags.rate >= 1);
    assert(flags.connections >= 1);
    assert(head_buffers >= 1);
    var warm_flags = flags.*;
    // Three full ring cycles: margin over the exact count, since close
    // responses and pipelined turnarounds can serve without a fresh bind.
    const ring_seconds: u64 = (3 * head_buffers) / flags.rate + 1;
    warm_flags.duration_s = @max(saturate_duration_s, ring_seconds);
    std.debug.print(
        "bench: saturating warmup — {d}s keep-alive + {d}s close + {d}s large-body, both zoxy ports\n",
        .{ warm_flags.duration_s, saturate_duration_s, saturate_duration_s },
    );
    const zoxy_ports = [_]u16{ zoxy_port, zoxy_http_port };
    for (zoxy_ports) |port| {
        _ = try loadTest(arena, io, port, &warm_flags, .keep_alive);
    }
    warm_flags.duration_s = saturate_duration_s;
    for (zoxy_ports) |port| {
        _ = try loadTest(arena, io, port, &warm_flags, .close);
        _ = try loadTest(arena, io, port, &warm_flags, .large_body);
    }
}

/// Prove every path answers before measuring; the short probes double as
/// warmup. A target that never responds is a setup failure, surfaced
/// before any numbers are printed.
fn warmUp(arena: std.mem.Allocator, io: Io, direct_port: u16) !void {
    assert(direct_port != 0);
    _ = try awaitResponsive(arena, io, direct_port, "origin");
    _ = try awaitResponsive(arena, io, zoxy_port, "zoxy L4");
    _ = try awaitResponsive(arena, io, zoxy_http_port, "zoxy L7");
    _ = try awaitResponsive(arena, io, haproxy_port, "haproxy tcp");
    _ = try awaitResponsive(arena, io, haproxy_http_port, "haproxy http");
}

/// One scenario's bands plus what they were asked to do, so the gates can
/// name the failing band and compare its result against its own offer.
const Band = struct {
    label: []const u8,
    scenario: Scenario,
    runs: *const Runs,
};

/// The §9 pass/fail: RSS under the banner ceiling (the §5 closed form
/// witnessed from outside), both baselines alive, both proxied modes
/// healthy, and a clean drain. Prints each failure so a red run
/// explains itself.
fn benchPassed(
    modes: *const MeasuredModes,
    budget_kb: u64,
    flags: *const Flags,
    drained_cleanly: bool,
) bool {
    const rss_after_kb = modes.rss_after_kb;
    const bands = [_]Band{
        .{ .label = "keep-alive", .scenario = .keep_alive, .runs = &modes.keep_alive },
        .{ .label = "close", .scenario = .close, .runs = &modes.close_mode },
        .{ .label = "large body", .scenario = .large_body, .runs = &modes.large_body },
    };
    // A live proxy always has resident pages; a zero reading means the
    // RSS probe failed, not that the process shrank to nothing.
    assert(rss_after_kb > 0);
    assert(budget_kb > 0);
    // The §5 closed form, held from the outside: resident memory never
    // exceeds what the banner promised plus the fixed overhead a live
    // process carries beside its pools. This is the whole RSS gate —
    // growth *inside* the budget is lazy fault-in working as designed
    // (measured: small heads fault only the first page of an 8 KiB
    // buffer, so which pages are resident depends on coalescing and
    // delivery sizes no warmup can provably pre-cover), and `saturate`
    // exists to push RSS toward this bound so holding it means
    // something, not to make flatness sound.
    const rss_bounded = rss_after_kb <= budget_kb + rss_ceiling_slack_kb;
    if (!rss_bounded) {
        std.debug.print(
            "FAIL: zoxy RSS {d} KiB exceeds the §5 budget {d} KiB + {d} KiB slack\n",
            .{ rss_after_kb, budget_kb, rss_ceiling_slack_kb },
        );
    }
    var bands_ok = true;
    for (bands) |band| {
        const offered = band.scenario.rate(flags);
        // The direct baseline gates on liveness too: if the origin cannot
        // keep up, every proxied band beside it is bounded by the origin and
        // the comparison measures nothing.
        if (band.runs.direct.snapshot.counters.completed == 0) {
            std.debug.print("FAIL: {s} direct baseline completed zero requests\n", .{band.label});
            bands_ok = false;
        }
        // The proxied bands carry the hard §9 invariants: complete requests
        // and a socket-error rate under 1% (a relay stall must not pass
        // silently; faithfully relayed 4xx/5xx are excluded).
        if (!proxiesHealthy(band.label, band.runs)) bands_ok = false;
        // And *every* path holds its offered rate — by reflection over
        // `Runs`, so adding a path to that struct is what puts it under the
        // floor, instead of also remembering a line here. The gate exists
        // because a band once delivered 704 of 2000 req/s through green
        // error checks (IMPLEMENTATION_NOTES.md); a gate you have to
        // remember to extend reopens that hole the first time someone
        // doesn't. The reference bands are in scope for the same reason the
        // baseline is: haproxy missing the offer means the *offer* is wrong,
        // and a comparison against a reference that could not keep up
        // measures nothing.
        inline for (@typeInfo(Runs).@"struct".fields) |field| {
            comptime assert(field.type == zrk.runner.Report);
            if (!rateHeld(band.label, field.name, offered, &@field(band.runs, field.name))) {
                bands_ok = false;
                if (comptime std.mem.eql(u8, field.name, "direct")) {
                    std.debug.print("       (the origin, not the proxy, is the limit here)\n", .{});
                }
            }
        }
    }
    return rss_bounded and bands_ok and drained_cleanly;
}

fn parseFlags(args: []const [:0]const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--rate")) {
            index += 1;
            flags.rate = try std.fmt.parseUnsigned(u64, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--close-rate")) {
            index += 1;
            flags.close_rate = try std.fmt.parseUnsigned(u64, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--large-rate")) {
            index += 1;
            flags.large_rate = try std.fmt.parseUnsigned(u64, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--connections")) {
            index += 1;
            flags.connections = try std.fmt.parseUnsigned(u32, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--seconds")) {
            index += 1;
            flags.duration_s = try std.fmt.parseUnsigned(u64, args[index], 10);
        } else if (std.mem.eql(u8, arg, "--origin")) {
            index += 1;
            // zoxy's config resolves endpoints with parseLiteral (no DNS),
            // so a hostname would make the spawned proxy exit at config
            // parse and surface here as a misleading "never answered".
            // Reject it up front, with the port the harness relies on.
            _ = std.Io.net.IpAddress.parseLiteral(args[index]) catch {
                std.debug.print(
                    "bench: --origin must be an IP literal with a port " ++
                        "(e.g. 127.0.0.1:9000); hostnames are not resolved\n",
                    .{},
                );
                return error.InvalidOrigin;
            };
            flags.origin = args[index];
        } else if (std.mem.eql(u8, arg, "--zoxy")) {
            index += 1;
            flags.zoxy_path = args[index];
        } else {
            std.debug.print(
                "usage: bench [--rate N] [--close-rate N] [--connections N] " ++
                    "[--seconds N] [--origin host:port] [--zoxy path]\n",
                .{},
            );
            return error.InvalidArguments;
        }
    }
    assert(flags.rate >= 1);
    assert(flags.close_rate >= 1);
    assert(flags.connections >= 1);
    assert(flags.duration_s >= 1);
    return flags;
}

fn originPortOf(origin_address: []const u8) u16 {
    // Both callers (--origin, validated in parseFlags; and the generated
    // "127.0.0.1:{port}") are guaranteed to parse.
    const address = std.Io.net.IpAddress.parseLiteral(origin_address) catch unreachable;
    return address.getPort();
}

fn spawnNginx(arena: std.mem.Allocator, io: Io, environ: std.process.Environ) !std.process.Child {
    const prefix = work_directory ++ "/nginx";
    try Io.Dir.cwd().createDirPath(io, prefix ++ "/logs");
    // The bulk body the large-body bands request, written once. `alias`
    // resolves relative to nginx's own prefix (`-p`), so the config needs no
    // absolute path and the file lives beside the logs it never fills.
    const body_name = "large.bin";
    const body = try arena.alloc(u8, large_body_bytes);
    // A fixed non-uniform fill: nothing here compresses or dedupes, but a
    // constant byte would make an accidental short read look identical to a
    // correct one in a hex dump.
    for (body, 0..) |*byte, index| byte.* = @truncate(index);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = prefix ++ "/" ++ body_name, .data = body });
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
        \\        location = {s} {{ default_type application/octet-stream; alias {s}; }}
        \\    }}
        \\}}
        \\
    , .{ origin_port, large_body_target, body_name });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = conf_path, .data = conf });

    const nginx_bin = try spawn_path.resolve(arena, io, environ, "nginx");
    return std.process.spawn(io, .{
        .argv = &.{ nginx_bin, "-p", prefix, "-c", "bench.conf" },
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
    // Both protocols on one process (§6, §7): the L4 relay and the L7
    // reverse proxy serve the same origin, so one run bands both paths.
    // idle_ms stays below nginx's default 75 s keepalive_timeout so
    // parked upstream connections are reaped before the origin closes
    // them (§5).
    const config_json = try std.fmt.allocPrint(arena,
        \\{{
        \\    "listeners": [
        \\        {{ "bind": "127.0.0.1:{d}", "cluster": "origin", "protocol": "l4" }},
        \\        {{ "bind": "127.0.0.1:{d}", "cluster": "origin", "protocol": "http" }}
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
    , .{ zoxy_port, zoxy_http_port, origin_address });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = config_json });

    // stderr is piped so `readBanner` can gate on the §5 total (the
    // banner is diagnostics, and zoxy keeps stdout for the access log's
    // `stdout` sink). Between the banner and the drain nothing else
    // lands there, and the drain-time counter dump — a few KiB against a
    // 64 KiB pipe — is forwarded into the run log by `drainChild`, so
    // the band review keeps it and the pipe can never fill.
    return std.process.spawn(io, .{
        .argv = &.{ zoxy_path, config_path },
        .stdout = .inherit,
        .stderr = .pipe,
    }) catch |err| {
        std.debug.print("bench: could not spawn {s} ({t}); run `zig build` first\n", .{
            zoxy_path,
            err,
        });
        return err;
    };
}

/// haproxy is the state-of-the-art reference band, not a gate: same
/// origin, same load, `mode tcp` to match zoxy's L4 relay and
/// `nbthread 1` to match zoxy's single event-loop thread. Timeouts mirror
/// the generated zoxy config so neither proxy wins by timing out earlier.
fn spawnHaproxy(
    arena: std.mem.Allocator,
    io: Io,
    environ: std.process.Environ,
    origin_address: []const u8,
) !std.process.Child {
    const conf_path = work_directory ++ "/haproxy.conf";
    const conf = try std.fmt.allocPrint(arena,
        \\global
        \\    nbthread 1
        \\    maxconn 4096
        \\
        \\defaults
        \\    mode tcp
        \\    timeout connect 5s
        \\    timeout client 60s
        \\    timeout server 60s
        \\
        \\listen bench
        \\    bind 127.0.0.1:{d}
        \\    server origin {s}
        \\
        \\listen bench_http
        \\    mode http
        \\    bind 127.0.0.1:{d}
        \\    server origin {s}
        \\
    , .{ haproxy_port, origin_address, haproxy_http_port, origin_address });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = conf_path, .data = conf });

    // -db keeps haproxy in the foreground so kill() reaches the process
    // itself, not a forked-off daemon.
    const haproxy_bin = try spawn_path.resolve(arena, io, environ, "haproxy");
    return std.process.spawn(io, .{
        .argv = &.{ haproxy_bin, "-db", "-f", conf_path },
        .stdout = .ignore,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print(
            "bench: could not spawn haproxy ({t}); is the dev shell loaded?\n",
            .{err},
        );
        return err;
    };
}

/// Short probing runs double as warmup; a target that never answers is a
/// setup failure, reported before any numbers are printed.
fn awaitResponsive(arena: std.mem.Allocator, io: Io, port: u16, label: []const u8) !void {
    assert(port != 0);
    assert(label.len > 0);
    const probe_attempts_max: u8 = 10;
    // The retry sleep is best-effort pacing; a spurious wake only means
    // the next probe runs a touch sooner, which is harmless.
    const retry_sleep = Io.Duration.fromNanoseconds(200 * std.time.ns_per_ms);
    var attempt: u8 = 0;
    while (attempt < probe_attempts_max) : (attempt += 1) {
        var config = benchConfig(port, 4, 100, "/");
        config.duration_ns = std.time.ns_per_s / 2;
        const report = zrk.runner.run(arena, io, &config, 0, null, null, null) catch |err| {
            if (attempt == probe_attempts_max - 1) return err;
            io.sleep(retry_sleep, .awake) catch {};
            continue;
        };
        if (report.snapshot.counters.completed > 0) return;
        io.sleep(retry_sleep, .awake) catch {};
    }
    std.debug.print("bench: {s} on port {d} never answered\n", .{ label, port });
    return error.TargetUnresponsive;
}

/// What one band measures. `keep_alive` and `close` differ only in
/// persistence and rate; `large_body` swaps the tiny origin reply for a
/// bulk one, so the bands show per-*byte* cost rather than per-request cost
/// — the number the record layer's price (and so a future kTLS decision)
/// has to be judged against.
const Scenario = enum {
    keep_alive,
    close,
    large_body,

    fn rate(scenario: Scenario, flags: *const Flags) u64 {
        return switch (scenario) {
            .keep_alive => flags.rate,
            .close => flags.close_rate,
            .large_body => flags.large_rate,
        };
    }

    fn target(scenario: Scenario) []const u8 {
        return switch (scenario) {
            .keep_alive, .close => "/",
            .large_body => large_body_target,
        };
    }

    /// Bytes of response body each completed request carries, for the
    /// throughput line. The small reply is not measured that way: at that
    /// size the framing dominates and a MB/s figure would mislead.
    fn bodyBytes(scenario: Scenario) ?u32 {
        return switch (scenario) {
            .keep_alive, .close => null,
            .large_body => large_body_bytes,
        };
    }
};

fn loadTest(
    arena: std.mem.Allocator,
    io: Io,
    port: u16,
    flags: *const Flags,
    scenario: Scenario,
) !zrk.runner.Report {
    assert(port != 0);
    assert(flags.duration_s >= 1);
    var config = benchConfig(
        port,
        flags.connections,
        scenario.rate(flags),
        scenario.target(),
    );
    config.duration_ns = flags.duration_s * std.time.ns_per_s;
    if (scenario == .close) {
        config.headers = &close_headers;
    }
    const report = try zrk.runner.run(arena, io, &config, 0, null, null, null);
    assert(report.launched >= 1);
    return report;
}

/// The five bands of one persistence mode: the direct baseline, zoxy's
/// two protocols, and the haproxy references.
/// One scenario's bands. Every field is a path the same offered load ran
/// against, and `bandsHealthy` reflects over them — so a path added here is
/// gated by that alone, with no second list to keep in step.
const Runs = struct {
    direct: zrk.runner.Report,
    l4: zrk.runner.Report,
    l7: zrk.runner.Report,
    tcp: zrk.runner.Report,
    http: zrk.runner.Report,
};

/// One full band matrix for a scenario. The paths are identical across
/// scenarios so the bands are directly comparable.
fn runMode(
    arena: std.mem.Allocator,
    io: Io,
    direct_port: u16,
    flags: *const Flags,
    scenario: Scenario,
) !Runs {
    assert(direct_port != 0);
    return .{
        .direct = try loadTest(arena, io, direct_port, flags, scenario),
        .l4 = try loadTest(arena, io, zoxy_port, flags, scenario),
        .l7 = try loadTest(arena, io, zoxy_http_port, flags, scenario),
        .tcp = try loadTest(arena, io, haproxy_port, flags, scenario),
        .http = try loadTest(arena, io, haproxy_http_port, flags, scenario),
    };
}

fn benchConfig(port: u16, connections: u32, rate: u64, target: []const u8) zrk.cli.Config {
    assert(port != 0);
    assert(connections >= 1);
    assert(rate >= 1);
    assert(target.len >= 1 and target[0] == '/');
    return .{
        .url = .{ .scheme = .http, .host = "127.0.0.1", .port = port, .target = target },
        .connections = connections,
        .rate = rate,
        .timeout_ns = 2 * std.time.ns_per_s,
        .interval_ns = std.time.ns_per_s,
        .plain = true,
    };
}

fn printReport(label: []const u8, report: *const zrk.runner.Report, scenario: Scenario) void {
    const hist = &report.snapshot.hist;
    const counters = &report.snapshot.counters;
    const rate_achieved =
        @as(f64, @floatFromInt(counters.completed)) / report.elapsed_s;
    // A bulk band's headline number is bytes per second, not requests: the
    // whole point is what a byte costs through the hop (§9).
    if (scenario.bodyBytes()) |body_bytes| {
        const mib_per_s = rate_achieved * @as(f64, @floatFromInt(body_bytes)) /
            (1024 * 1024);
        std.debug.print(
            "{s}  {d:.0} req/s  {d:.0} MiB/s  p50 {d} us  p99 {d} us  " ++
                "({d} completed, {d} socket-errors, {d} status-errors)\n",
            .{
                label,
                rate_achieved,
                mib_per_s,
                hist.valueAtPercentile(50.0),
                hist.valueAtPercentile(99.0),
                counters.completed,
                counters.socketErrors(),
                counters.status_errors,
            },
        );
        return;
    }
    // zrk histograms record microseconds (the wrk2 convention). Socket
    // errors (connect + read + write + timeouts, via zrk's socketErrors())
    // are the relay-stall modes and are shown separately from status
    // errors — a proxy faithfully relaying a 4xx/5xx is healthy, but a
    // relay that times out is not, and omitting timeouts/read_errors
    // (as the old sum did) would hide exactly that.
    std.debug.print(
        "{s}  {d:.0} req/s  p50 {d} us  p90 {d} us  p99 {d} us  max {d} us  " ++
            "({d} completed, {d} socket-errors, {d} status-errors)\n",
        .{
            label,
            rate_achieved,
            hist.valueAtPercentile(50.0),
            hist.valueAtPercentile(90.0),
            hist.valueAtPercentile(99.0),
            hist.max(),
            counters.completed,
            counters.socketErrors(),
            counters.status_errors,
        },
    );
}

fn printOverhead(
    direct: *const zrk.runner.Report,
    proxied_l4: *const zrk.runner.Report,
    proxied_l7: *const zrk.runner.Report,
    reference_tcp: *const zrk.runner.Report,
    reference_http: *const zrk.runner.Report,
) void {
    const direct_p50 = direct.snapshot.hist.valueAtPercentile(50.0);
    const l4_p50 = proxied_l4.snapshot.hist.valueAtPercentile(50.0);
    const l7_p50 = proxied_l7.snapshot.hist.valueAtPercentile(50.0);
    const tcp_p50 = reference_tcp.snapshot.hist.valueAtPercentile(50.0);
    const http_p50 = reference_http.snapshot.hist.valueAtPercentile(50.0);
    std.debug.print(
        "hop overhead p50: zoxy L4 +{d} us, zoxy L7 +{d} us, " ++
            "haproxy tcp +{d} us, haproxy http +{d} us " ++
            "(bands, not single numbers — §9)\n",
        .{
            l4_p50 -| direct_p50,
            l7_p50 -| direct_p50,
            tcp_p50 -| direct_p50,
            http_p50 -| direct_p50,
        },
    );
}

/// One mode's bands under a labelled header, then its hop overheads.
fn printMode(label: []const u8, runs: *const Runs, scenario: Scenario) void {
    assert(label.len > 0);
    if (scenario.bodyBytes()) |body_bytes| {
        std.debug.print("-- {s} ({d} KiB per response) --\n", .{ label, body_bytes / 1024 });
    } else {
        std.debug.print("-- {s} --\n", .{label});
    }
    printReport("direct      ", &runs.direct, scenario);
    printReport("zoxy L4     ", &runs.l4, scenario);
    printReport("zoxy L7     ", &runs.l7, scenario);
    printReport("haproxy tcp ", &runs.tcp, scenario);
    printReport("haproxy http", &runs.http, scenario);
    printOverhead(&runs.direct, &runs.l4, &runs.l7, &runs.tcp, &runs.http);
}

/// Did the band deliver what was offered (§9)? Compares the achieved rate
/// against `rate_floor_percent` of the offer and prints both numbers, since
/// the useful part of a shortfall is its size.
fn rateHeld(
    mode: []const u8,
    path: []const u8,
    offered: u64,
    report: *const zrk.runner.Report,
) bool {
    assert(mode.len > 0);
    assert(path.len > 0);
    assert(offered >= 1);
    assert(report.elapsed_s > 0);
    const achieved = @as(f64, @floatFromInt(report.snapshot.counters.completed)) /
        report.elapsed_s;
    const floor = @as(f64, @floatFromInt(offered * rate_floor_percent)) / 100;
    if (achieved >= floor) return true;
    std.debug.print(
        "FAIL: {s} {s} delivered {d:.0} of {d} req/s offered ({d}% floor)\n",
        .{ mode, path, achieved, offered, rate_floor_percent },
    );
    return false;
}

/// The §9 hard invariant on the proxied bands: both zoxy protocols
/// complete requests and keep their socket-error rate (relay stalls, not
/// faithfully relayed 4xx/5xx) under 1%.
fn proxiesHealthy(mode: []const u8, runs: *const Runs) bool {
    assert(mode.len > 0);
    return proxyHealthy(mode, "L4", &runs.l4) and proxyHealthy(mode, "L7", &runs.l7);
}

/// A single proxied band's health, printing the offending band so a
/// failure is actionable — a high close-mode rate usually means loopback
/// ephemeral-port exhaustion, so lower --close-rate rather than blame the
/// proxy.
fn proxyHealthy(mode: []const u8, path: []const u8, report: *const zrk.runner.Report) bool {
    assert(mode.len > 0);
    assert(path.len > 0);
    const counters = &report.snapshot.counters;
    if (counters.completed == 0) {
        std.debug.print("FAIL: zoxy {s} {s} completed zero requests\n", .{ path, mode });
        return false;
    }
    const socket_errors = counters.socketErrors();
    if (socket_errors * 100 > counters.completed) {
        std.debug.print(
            "FAIL: zoxy {s} {s} socket-error rate too high ({d} of {d} completed)\n",
            .{ path, mode, socket_errors, counters.completed },
        );
        return false;
    }
    return true;
}

fn readRssKb(arena: std.mem.Allocator, io: Io, pid: ?std.process.Child.Id) !u64 {
    assert(pid != null);
    // macOS has no procfs; libproc's PROC_PIDTASKINFO reports the resident
    // set in bytes. proc_pidinfo lives in libSystem, which every darwin
    // binary links, so no extra linking or @cImport is needed.
    if (comptime builtin.os.tag.isDarwin()) {
        var info: darwin.proc_taskinfo = undefined;
        const size = darwin.proc_pidinfo(
            pid.?,
            darwin.PROC_PIDTASKINFO,
            0,
            &info,
            @sizeOf(darwin.proc_taskinfo),
        );
        if (size != @sizeOf(darwin.proc_taskinfo)) return error.RssUnavailable;
        return info.pti_resident_size / 1024;
    }
    const path = try std.fmt.allocPrint(arena, "/proc/{d}/status", .{pid.?});
    // procfs advertises size 0, so this must stream, not trust st_size.
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var read_buffer: [8192]u8 = undefined;
    var file_reader = file.reader(io, &read_buffer);
    var status_buffer: [8192]u8 = undefined;
    const status_len = try file_reader.interface.readSliceShort(&status_buffer);
    assert(status_len > 0);
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

/// Minimal libproc surface for the darwin branch of readRssKb. Field
/// layout mirrors <sys/proc_info.h> struct proc_taskinfo exactly —
/// proc_pidinfo validates buffersize against it.
const darwin = struct {
    const PROC_PIDTASKINFO: c_int = 4;

    const proc_taskinfo = extern struct {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: i32,
        pti_faults: i32,
        pti_pageins: i32,
        pti_cow_faults: i32,
        pti_messages_sent: i32,
        pti_messages_received: i32,
        pti_syscalls_mach: i32,
        pti_syscalls_unix: i32,
        pti_csw: i32,
        pti_threadnum: i32,
        pti_numrunning: i32,
        pti_priority: i32,
    };

    extern "c" fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: ?*anyopaque,
        buffersize: c_int,
    ) c_int;
};
