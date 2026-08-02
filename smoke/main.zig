//! Tier 0.5 — the live gate (DESIGN.md §9): the shipped binary, on a real
//! kernel, against a real origin, on every change.
//!
//! The three deterministic gates run the real data path against virtual
//! sockets and a virtual clock. That is what makes them exhaustive, and it
//! is also what they cannot answer: both bugs that motivated this tier
//! were found by *running* the thing (#129's phantom access-log line per
//! keep-alive connection, #130's health probes idling out their whole
//! timeout). Each was afterwards teachable to the simulator; neither was
//! caught by it first, because each needed the shape to be known before it
//! could be looked for.
//!
//! So this gate asserts *equalities on real output*, never thresholds: a
//! shared runner's timing noise must not be able to move a verdict. N
//! requests produce exactly N access-log lines. Anything whose verdict
//! needs a run-to-run comparison is Tier 1's job (`zig build bench`) and
//! would make a per-change gate that fails on noise.
//!
//! The origin lives in this process (smoke/origin.zig) rather than being
//! nginx; the load is this file's own client (smoke/client.zig) rather
//! than zrk. Both are deliberate — see those files.

const std = @import("std");

const client_module = @import("client.zig");
const origin_module = @import("origin.zig");

const Io = std.Io;

const assert = std.debug.assert;

const work_directory = ".zig-cache/zoxy-smoke";
const config_path = work_directory ++ "/zoxy.json";
const access_log_path = work_directory ++ "/access.log";
const zoxy_log_path = work_directory ++ "/zoxy.log";

/// The L7 load: keep-alive connections, each serving the same count. Both
/// numbers are above one on purpose — the access-log equality this gate
/// exists for is a per-*request* claim that a per-*connection* bug
/// satisfies, so a single request on a single connection could not tell
/// the two apart (#129).
const keep_alive_connections: u8 = 4;
const requests_per_connection: u32 = 16;

/// Connections closed before the drain; the rest are still open when
/// SIGTERM lands. Both teardown paths — a client that left and a drain
/// that reaped — must write nothing, and only running both proves it.
const connections_closed_early: u8 = 2;

/// The L4 load: one exchange per connection, each connection closed by the
/// client. An L4 connection *is* its own log unit (§8), so this is the
/// other half of the line arithmetic.
const l4_connections: u8 = 2;

const http_exchanges: u32 = @as(u32, keep_alive_connections) * requests_per_connection;
const access_log_lines_expected: u32 = http_exchanges + l4_connections;

/// What the harness holds open against the origin at its peak: every live
/// client connection can have an upstream connection of its own, parked or
/// leased, plus the odd straggler mid-teardown.
const origin_connections_peak: u8 = keep_alive_connections + l4_connections + 2;

/// The drain's cap on waiting for the connections left open above. A
/// drain cannot tell an idle keep-alive connection from one about to send
/// a request, so it waits for both and reaps what is left at this
/// deadline (§8) — which is the whole of this run's shutdown cost, and
/// therefore the number to keep small. Short enough to stay a gate that
/// runs in a second; long enough that nothing here is racing it, since
/// the load is finished before SIGTERM is sent.
const drain_deadline_ms: u32 = 300;

/// zoxy's pools, shrunk from the lean defaults (§5). Nothing here is a
/// scenario — the load is a handful of connections — so the smallest
/// config that serves it starts fastest and keeps the process's resident
/// set a number a human can read at a glance.
const zoxy_limits = .{ .conn_slots = 32, .relay_buffers = 16, .upstream_slots = 16 };

comptime {
    assert(keep_alive_connections >= 2);
    assert(requests_per_connection >= 2);
    assert(connections_closed_early >= 1);
    assert(connections_closed_early < keep_alive_connections);
    assert(l4_connections >= 1);
    // The origin serves this harness and nothing else, so its pool has to
    // cover the peak with room for the wake-up connections `stop` sends.
    assert(origin_connections_peak < origin_module.serve_tasks);
    // Every client connection needs a slot and a relay buffer at once.
    assert(zoxy_limits.relay_buffers >= keep_alive_connections + l4_connections);
    assert(zoxy_limits.conn_slots >= zoxy_limits.relay_buffers);
}

/// The whole run's wall-clock budget. Fifty times what a run takes, so it
/// is never a verdict on speed — it exists because every wait in this
/// harness is a wait on the process under test, and the failure this gate
/// most wants to catch loudly (a proxy that will not drain, #130's
/// neighbourhood) is exactly the one that would otherwise wedge a build
/// step until CI's own timeout killed it with no diagnosis.
const watchdog_budget_ns: u64 = 30 * std.time.ns_per_s;

/// The origin's serve tasks take its address, and the clients hold
/// readers and writers pointing into their own buffers — both want
/// storage that outlives no scope and moves for no reason, which is what
/// static means here (§5's discipline, applied to the harness).
var origin: origin_module.Origin = undefined;
var clients: [keep_alive_connections]client_module.Client = undefined;
var l4_client: client_module.Client = undefined;

/// The proxy the watchdog kills if it fires, published by `spawnZoxy`.
/// Zero until then — the watchdog can outlive the spawn failing.
var watchdog_child_pid = std.atomic.Value(i32).init(0);

const Flags = struct {
    zoxy_path: []const u8 = "zig-out/bin/zoxy",
};

/// The ports zoxy is told to bind. Kernel-assigned rather than fixed: a
/// per-change gate must not fail because a developer's other terminal is
/// already on 18080.
const Ports = struct {
    http: u16,
    l4: u16,
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    const flags = try parseFlags(args);

    // Armed before anything that can block, and cancelled by the defer on
    // every exit path — success, failure, or a propagated error.
    var watchdog: Io.Group = .init;
    try watchdog.concurrent(io, watchdogTask, .{io});
    defer watchdog.cancel(io);

    try prepareWorkDirectory(io);
    try origin.start(io, origin_connections_peak);
    // Ordered against the child's own teardown below: defers unwind
    // last-declared-first, so zoxy is always gone before this runs — which
    // is what releases the origin tasks parked in `read` on its upstream
    // connections.
    defer origin.stop();

    const ports = try reservePorts(io);
    try writeConfig(arena, io, &ports, origin.port);
    var child = try spawnZoxy(io, flags.zoxy_path);
    var running = true;
    defer if (running) child.kill(io);

    try awaitListening(io, ports.http);
    try runLoad(io, &ports);

    const drained_cleanly = try drain(io, &child, &running);
    const lines = try readAccessLog(arena, io);
    return if (gatePassed(io, &lines, drained_cleanly)) 0 else 1;
}

/// The wall-clock backstop. Nothing in this harness can bound its own
/// wait — a `read` on a proxy that accepted and went quiet, a `wait` on
/// one that will not exit, an origin task parked on a socket the proxy
/// never closed — so the bound is one budget over the whole run, held out
/// here where no wedged operation can be holding it.
///
/// It ends the process rather than reporting upward, because there is no
/// upward: the thread that would receive the report is the wedged one.
/// The proxy is killed first, so a run that times out leaves no orphan
/// holding the ports the next one will ask the kernel for.
fn watchdogTask(io: Io) void {
    io.sleep(Io.Duration.fromNanoseconds(watchdog_budget_ns), .awake) catch |err| {
        // The run finished and cancelled this task, which is every
        // ordinary exit; nothing else cancels it.
        assert(err == error.Canceled);
        return;
    };
    std.debug.print(
        "FAIL: smoke run exceeded its {d}s budget — something is wedged, not slow\n",
        .{watchdog_budget_ns / std.time.ns_per_s},
    );
    const pid = watchdog_child_pid.load(.acquire);
    if (pid != 0) {
        std.posix.kill(pid, .KILL) catch {};
    }
    printZoxyLog(io);
    std.process.exit(3);
}

/// What one run of the access log said, as counts rather than text: the
/// gate's verdicts are equalities over these.
const LogCounts = struct {
    http: u32 = 0,
    l4: u32 = 0,
    /// Lines that were neither, so "the file holds exactly what it should"
    /// is checkable rather than merely "it holds at least that".
    other: u32 = 0,
    /// HTTP lines that both completed and carried the origin's status —
    /// the outcome every request in this load is owed.
    http_ok: u32 = 0,
};

/// The §9 pass/fail, printed so a red run explains itself without a
/// rerun. Every clause is an equality against a number this harness
/// decided before the run started.
fn gatePassed(io: Io, lines: *const LogCounts, drained_cleanly: bool) bool {
    // Both are counted off the same lines, in the same pass, so a total
    // below its own subset would mean the counter itself is wrong — which
    // no comparison below would otherwise notice.
    assert(lines.http_ok <= lines.http);
    assert(access_log_lines_expected == http_exchanges + l4_connections);
    var passed = true;
    if (lines.http != http_exchanges) {
        std.debug.print(
            "FAIL: {d} http access-log lines for {d} requests (#129 is exactly this)\n",
            .{ lines.http, http_exchanges },
        );
        passed = false;
    }
    if (lines.l4 != l4_connections) {
        std.debug.print(
            "FAIL: {d} l4 access-log lines for {d} connections\n",
            .{ lines.l4, l4_connections },
        );
        passed = false;
    }
    if (lines.other != 0) {
        std.debug.print("FAIL: {d} access-log lines of no known kind\n", .{lines.other});
        passed = false;
    }
    if (lines.http_ok != lines.http) {
        std.debug.print(
            "FAIL: {d} of {d} http lines did not complete with the origin's 200\n",
            .{ lines.http - lines.http_ok, lines.http },
        );
        passed = false;
    }
    if (!drained_cleanly) {
        std.debug.print("FAIL: zoxy did not drain cleanly on SIGTERM\n", .{});
        passed = false;
    }
    if (passed) {
        std.debug.print(
            "smoke: {d} http + {d} l4 exchanges, {d} access-log lines, clean drain\n",
            .{ lines.http, lines.l4, access_log_lines_expected },
        );
    } else {
        printZoxyLog(io);
    }
    return passed;
}

/// The load: every L7 connection serves its whole share before the next
/// one opens, then some are closed and the rest are left for the drain.
fn runLoad(io: Io, ports: *const Ports) !void {
    assert(ports.http != 0);
    assert(ports.l4 != 0);
    var host_buffer: [32]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buffer, "127.0.0.1:{d}", .{ports.http});
    for (&clients) |*client| {
        try client.connect(io, ports.http);
        var request: u32 = 0;
        while (request < requests_per_connection) : (request += 1) {
            try expectOriginResponse(try client.get(host, "/"));
        }
        assert(client.requests == requests_per_connection);
    }
    for (clients[0..connections_closed_early]) |*client| {
        client.close();
    }
    try runL4Load(io, ports.l4, host);
}

/// The L4 leg (§6): the same HTTP exchange through the byte relay, which
/// neither parses nor frames it. One connection per exchange, closed by
/// the client — an L4 line describes a connection, not a request.
fn runL4Load(io: Io, port: u16, host: []const u8) !void {
    assert(port != 0);
    assert(host.len >= 1);
    var index: u8 = 0;
    while (index < l4_connections) : (index += 1) {
        // One static slot reused across the loop, on the same terms as
        // `clients`: a connection is closed before the next is opened, so
        // there is never more than one of these alive.
        try l4_client.connect(io, port);
        defer l4_client.close();
        try expectOriginResponse(try l4_client.get(host, "/"));
    }
    assert(index == l4_connections);
}

/// The response the origin sends, checked byte-count and all: a hop that
/// truncated or re-framed a body is a data-path bug this tier sees before
/// any counter does.
fn expectOriginResponse(response: client_module.Response) !void {
    // The client parses both out of the wire and bounds them there; a
    // value outside those bounds reaching here would mean the two files
    // disagree about what a response is.
    assert(response.status >= 100);
    assert(response.body_bytes <= client_module.response_body_bytes_max);
    if (response.status != 200) {
        std.debug.print("smoke: origin answered {d}, not 200\n", .{response.status});
        return error.UnexpectedStatus;
    }
    if (response.body_bytes != origin_module.body.len) {
        std.debug.print(
            "smoke: body was {d} bytes, not {d}\n",
            .{ response.body_bytes, origin_module.body.len },
        );
        return error.UnexpectedBody;
    }
}

/// Drain, not just death (§8): SIGTERM, then a wait that both reaps the
/// child and reports whether it left of its own accord. Clears `running`
/// so the caller's guarded defer cannot double-kill.
fn drain(io: Io, child: *std.process.Child, running: *bool) !bool {
    assert(running.*);
    assert(child.id != null);
    try std.posix.kill(child.id.?, .TERM);
    const term = try child.wait(io);
    running.* = false;
    return term == .exited and term.exited == 0;
}

/// Count what the run wrote. The whole file is read at once: the log is
/// bounded by the load this harness issued, and a file bigger than the
/// cap is itself the finding.
fn readAccessLog(arena: std.mem.Allocator, io: Io) !LogCounts {
    const bytes_max = @as(usize, access_log_lines_expected + 64) * 1024;
    const text = try Io.Dir.cwd().readFileAlloc(io, access_log_path, arena, .limited(bytes_max));
    assert(text.len <= bytes_max);
    var counts: LogCounts = .{};
    var remaining = std.mem.splitScalar(u8, text, '\n');
    while (remaining.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.indexOf(u8, line, "\"kind\":\"http\"") != null) {
            counts.http += 1;
            const completed = std.mem.indexOf(u8, line, "\"outcome\":\"ok\"") != null;
            const answered = std.mem.indexOf(u8, line, "\"status\":200") != null;
            if (completed and answered) counts.http_ok += 1;
        } else {
            if (std.mem.indexOf(u8, line, "\"kind\":\"l4\"") != null) {
                counts.l4 += 1;
            } else {
                counts.other += 1;
            }
        }
    }
    return counts;
}

/// Two loopback ports the kernel is not using, held open together so it
/// cannot hand out the same one twice, then released for zoxy to bind.
/// There is a window between the release and zoxy's bind; nothing can
/// close it from out here, and it is far smaller than the collision a
/// hard-coded pair would carry on a shared runner.
fn reservePorts(io: Io) !Ports {
    var http_address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var http_listener = try http_address.listen(io, .{ .mode = .stream });
    var l4_address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var l4_listener = try l4_address.listen(io, .{ .mode = .stream });
    const ports: Ports = .{
        .http = http_listener.socket.address.getPort(),
        .l4 = l4_listener.socket.address.getPort(),
    };
    http_listener.deinit(io);
    l4_listener.deinit(io);
    assert(ports.http != 0);
    assert(ports.l4 != 0);
    assert(ports.http != ports.l4);
    return ports;
}

/// Both protocols against one origin (§6, §7), with the access log on a
/// file rather than stdout: the file is what this gate counts, and a pipe
/// nobody drains is a drop rung (§8) waiting to make the count a lie.
fn writeConfig(arena: std.mem.Allocator, io: Io, ports: *const Ports, origin_port: u16) !void {
    assert(origin_port != 0);
    const config_json = try std.fmt.allocPrint(arena,
        \\{{
        \\    "listeners": [
        \\        {{ "bind": "127.0.0.1:{d}", "cluster": "origin", "protocol": "http" }},
        \\        {{ "bind": "127.0.0.1:{d}", "cluster": "origin", "protocol": "l4" }}
        \\    ],
        \\    "clusters": {{
        \\        "origin": {{ "endpoints": ["127.0.0.1:{d}"] }}
        \\    }},
        \\    "access_log": {{ "sink": "file", "path": "{s}" }},
        \\    "timeouts": {{
        \\        "connect_ms": 2000,
        \\        "idle_ms": 30000,
        \\        "drain_deadline_ms": {d}
        \\    }},
        \\    "limits": {{
        \\        "conn_slots": {d},
        \\        "relay_buffers": {d},
        \\        "upstream_slots": {d}
        \\    }}
        \\}}
        \\
    , .{
        ports.http,
        ports.l4,
        origin_port,
        access_log_path,
        drain_deadline_ms,
        zoxy_limits.conn_slots,
        zoxy_limits.relay_buffers,
        zoxy_limits.upstream_slots,
    });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = config_json });
}

/// A fresh work directory every run: the file sink is append-only by
/// design (§8, so an external rotation is safe), which makes a stale log
/// from the last run indistinguishable from this one's output.
fn prepareWorkDirectory(io: Io) !void {
    try Io.Dir.cwd().createDirPath(io, work_directory);
    Io.Dir.cwd().deleteFile(io, access_log_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

/// zoxy's own output goes to a file rather than this process's stderr:
/// the banner and the drain-time counter dump are a hundred lines of
/// post-mortem that a green per-change gate should not print. A red one
/// prints its tail (`printZoxyLog`).
fn spawnZoxy(io: Io, zoxy_path: []const u8) !std.process.Child {
    assert(zoxy_path.len >= 1);
    const log_file = try Io.Dir.cwd().createFile(io, zoxy_log_path, .{});
    defer log_file.close(io);
    const child = std.process.spawn(io, .{
        .argv = &.{ zoxy_path, config_path },
        .stdout = .{ .file = log_file },
        .stderr = .{ .file = log_file },
    }) catch |err| {
        std.debug.print(
            "smoke: could not spawn {s} ({t}); run `zig build` first\n",
            .{ zoxy_path, err },
        );
        return err;
    };
    // Everything that can wedge from here on is a wait on this process,
    // so the watchdog needs it before the first of those waits.
    assert(child.id != null);
    watchdog_child_pid.store(child.id.?, .release);
    return child;
}

/// Wait for the listener to answer a connect, and nothing more: a probe
/// that sent a *request* would be an exchange, and every exchange in this
/// run is one the line arithmetic already counted. An accepted connection
/// that asks nothing owes no line (§8), so this one is invisible to the
/// gate by construction.
fn awaitListening(io: Io, port: u16) !void {
    assert(port != 0);
    const attempts_max: u16 = 200;
    const retry_delay = Io.Duration.fromNanoseconds(25 * std.time.ns_per_ms);
    var attempt: u16 = 0;
    while (attempt < attempts_max) : (attempt += 1) {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        const stream = address.connect(io, .{ .mode = .stream }) catch {
            // The pause is pacing, not correctness: a sleep that failed
            // or woke early only means the next probe runs sooner, and
            // the attempt cap is what bounds the wait either way.
            io.sleep(retry_delay, .awake) catch {};
            continue;
        };
        stream.close(io);
        return;
    }
    assert(attempt == attempts_max);
    std.debug.print("smoke: zoxy never listened on port {d}\n", .{port});
    printZoxyLog(io);
    return error.ZoxyNeverListened;
}

/// The head of zoxy's captured output, for a failing run — the banner and
/// whatever it said before giving up. Best-effort: this runs when
/// something has already gone wrong, so an unreadable log must not
/// replace the failure that is being reported.
fn printZoxyLog(io: Io) void {
    var buffer: [16 * 1024]u8 = undefined;
    const file = Io.Dir.cwd().openFile(io, zoxy_log_path, .{}) catch return;
    defer file.close(io);
    var read_buffer: [4096]u8 = undefined;
    var file_reader = file.reader(io, &read_buffer);
    const read = file_reader.interface.readSliceShort(&buffer) catch return;
    assert(read <= buffer.len);
    if (read == 0) return;
    std.debug.print("-- {s} --\n{s}\n", .{ zoxy_log_path, buffer[0..read] });
}

fn parseFlags(args: []const [:0]const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--zoxy")) {
            index += 1;
            if (index == args.len) return error.InvalidArguments;
            flags.zoxy_path = args[index];
        } else {
            std.debug.print("usage: smoke [--zoxy path]\n", .{});
            return error.InvalidArguments;
        }
    }
    assert(flags.zoxy_path.len >= 1);
    return flags;
}
