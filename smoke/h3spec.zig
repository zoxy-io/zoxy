//! The HTTP/3 conformance gate (#449, DESIGN.md §9, §12): h3spec — an
//! implementation of QUIC and HTTP/3 that shares no code with this proxy,
//! run as a client against the shipped binary — with the verdict an
//! equality, as h2spec's is: the cases that fail are exactly the
//! deviations §12 records, and the one that cannot run is exactly the one
//! §12 says cannot. A deviation fixed fails the gate as loudly as a
//! regression does.
//!
//! Merge tier, beside `h2spec` and `bench`, and not in `ci`: h3spec is a
//! Haskell binary, and §9's rule is that a per-change gate adds no
//! dependency. The harness runs it from PATH, or from where `--h3spec`
//! points. Pinned to the version its counts were taken against, since a
//! newer h3spec adds cases.
//!
//! The origin is smoke's own (smoke/origin.zig), in this process. The
//! config is the defaults but for what HTTP/3 needs said — a TLS listener
//! and its QUIC binding — and a QUIC pool wide enough for the whole run:
//! h3spec opens a connection per case and closes few of them, so each one
//! holds its slot until its idle window ends, and a pool that filled would
//! answer the late cases with Retries and then silence.

const std = @import("std");

const origin_module = @import("origin.zig");

const Io = std.Io;

const assert = std.debug.assert;

const work_directory = ".zig-cache/zoxy-h3spec";
const config_path = work_directory ++ "/zoxy.json";
const zoxy_log_path = work_directory ++ "/zoxy.log";
const report_path = work_directory ++ "/h3spec.log";
const tls_cert_path = work_directory ++ "/cert.pem";
const tls_key_path = work_directory ++ "/key.pem";
const tls_cert_pem = @embedFile("tls_cert_pem");
const tls_key_pem = @embedFile("tls_key_pem");

/// The h3spec version the counts below were taken against.
const version_number = "0.1.15";
const version_expected = "h3spec " ++ version_number;
/// Every case h3spec 0.1.15 has: a run that reports fewer lost some.
const cases_expected: u32 = 86;
/// h3spec's report for 86 cases is some 10 KiB; past this, it is not one.
const report_bytes_max: usize = 1024 * 1024;
/// QUIC connections the proxy may hold: one per case, with room over.
const quic_connections: u32 = 128;

/// An h3spec case this gate expects to fail — named by the description
/// h3spec prints — each one a deviation §12 records and argues. None, at
/// 0.1.15: zoxy fails no case.
const deviations = [_][]const u8{};

/// The cases h3spec reports pending: ones it cannot run against this
/// server at all. §12 records why.
const pendings = [_][]const u8{
    // §12: 0-RTT is out of scope (#449), so no session ticket is offered
    // and no early-data key ever exists for h3spec to send CRYPTO under.
    "MUST send PROTOCOL_VIOLATION if CRYPTO in 0-RTT is received [TLS 8.3]",
};

const Flags = struct {
    zoxy_path: []const u8 = "zig-out/bin/zoxy",
    h3spec_path: []const u8 = "h3spec",
};

/// One run's tally of h3spec's report.
const Tally = struct {
    cases: u32 = 0,
    failed: u32 = 0,
    pending: u32 = 0,
    unexpected: u32 = 0,
};

/// h3spec's own summary — `N examples, M failures, K pending` — which is
/// written apart from the case lines, so the walk is held to it.
const Summary = struct { examples: u32, failures: u32, pending: u32 };

const Outcome = enum { passed, failed, pending };

var origin: origin_module.Origin = undefined;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    const flags = try parseFlags(args);
    return run(arena, io, &flags) catch |err| {
        std.debug.print("FAIL: the h3spec run could not finish ({t})\n", .{err});
        printZoxyLog(io);
        return 1;
    };
}

fn run(arena: std.mem.Allocator, io: Io, flags: *const Flags) !u8 {
    try Io.Dir.cwd().createDirPath(io, work_directory);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tls_cert_path, .data = tls_cert_pem });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tls_key_path, .data = tls_key_pem });
    try checkVersion(arena, io, flags.h3spec_path);
    try origin.start(io, 8);
    defer origin.stop();
    const port = try reservePort(io);
    try writeConfig(arena, io, port, origin.port);
    var child = try spawnZoxy(io, flags.zoxy_path);
    var running = true;
    defer if (running) child.kill(io);
    // `Server.start` binds the QUIC endpoints before the TCP listeners, so
    // the TCP one answering means the UDP one is bound too.
    try awaitListening(io, port);
    const report = try runH3spec(arena, io, flags.h3spec_path, port);
    assert(report.len >= 1);
    const tally = judge(report);
    var passed = tallyPassed(&tally, summaryOf(report));
    try std.posix.kill(child.id.?, .TERM);
    const term = try child.wait(io);
    running = false;
    if (!exitedCleanly(term)) {
        std.debug.print("FAIL: zoxy did not drain cleanly on SIGTERM\n", .{});
        passed = false;
    }
    if (!passed) {
        printZoxyLog(io);
        return 1;
    }
    std.debug.print(
        "h3spec: {d} cases, failing exactly what §12 records ({d}), {d} pending as recorded, clean drain\n",
        .{ cases_expected, deviations.len, pendings.len },
    );
    return 0;
}

fn exitedCleanly(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

/// The counts are 0.1.15's: another version is another gate.
fn checkVersion(arena: std.mem.Allocator, io: Io, h3spec_path: []const u8) !void {
    const result = std.process.run(arena, io, .{ .argv = &.{ h3spec_path, "-v" } }) catch |err| {
        std.debug.print("h3spec: could not run {s} ({t}); install h3spec {s}, or pass --h3spec\n", .{
            h3spec_path, err, version_number,
        });
        return err;
    };
    // The whole of what it prints, not a prefix: 0.1.150 is not 0.1.15.
    const printed = std.mem.trim(u8, result.stdout, " \r\n");
    if (!std.mem.eql(u8, printed, version_expected)) {
        std.debug.print("FAIL: {s} is not {s}: {s}\n", .{ h3spec_path, version_expected, printed });
        return error.H3specVersion;
    }
    assert(version_expected.len > version_number.len);
}

fn runH3spec(arena: std.mem.Allocator, io: Io, h3spec_path: []const u8, port: u16) ![]const u8 {
    assert(port != 0);
    const port_text = try std.fmt.allocPrint(arena, "{d}", .{port});
    const log_file = try Io.Dir.cwd().createFile(io, report_path, .{});
    defer log_file.close(io);
    // `-n`: the fixture's chain is throwaway; the signature is still
    // checked, so a transcript gone wrong fails every case.
    var child = try std.process.spawn(io, .{
        .argv = &.{ h3spec_path, "-n", "127.0.0.1", port_text },
        .stdout = .{ .file = log_file },
        .stderr = .{ .file = log_file },
    });
    // Its own exit is a failure count, which the report says better. Its
    // run is bounded by its own per-case timeout (two seconds) over a
    // fixed number of cases.
    _ = try child.wait(io);
    return Io.Dir.cwd().readFileAlloc(io, report_path, arena, .limited(report_bytes_max));
}

/// Walk the report's case lines — each ending in h3spec's mark — into a
/// pass, a recorded deviation, a recorded pending case, or a finding. A
/// recorded one that ran clean is a finding too.
fn judge(report: []const u8) Tally {
    var tally: Tally = .{};
    // At least one apiece: a list with nothing recorded is a legal one.
    var deviations_storage: [@max(deviations.len, 1)]bool = @splat(false);
    var pendings_storage: [@max(pendings.len, 1)]bool = @splat(false);
    const deviations_seen: []bool = deviations_storage[0..deviations.len];
    const pendings_seen: []bool = pendings_storage[0..pendings.len];
    var lines = std.mem.splitScalar(u8, report, '\n');
    var visited: u32 = 0;
    while (lines.next()) |line| : (visited += 1) {
        assert(visited <= report_bytes_max);
        const case, const outcome = caseOf(line) orelse continue;
        tally.cases += 1;
        switch (outcome) {
            .passed => {},
            .failed => {
                tally.failed += 1;
                const index = indexOf(&deviations, case) orelse {
                    std.debug.print("FAIL: h3spec \"{s}\" failed, and is no recorded deviation\n", .{case});
                    tally.unexpected += 1;
                    continue;
                };
                deviations_seen[index] = true;
            },
            .pending => {
                tally.pending += 1;
                const index = indexOf(&pendings, case) orelse {
                    std.debug.print("FAIL: h3spec \"{s}\" is pending, and §12 does not say why\n", .{case});
                    tally.unexpected += 1;
                    continue;
                };
                pendings_seen[index] = true;
            },
        }
    }
    tally.unexpected += unseen(&deviations, deviations_seen, "failed");
    tally.unexpected += unseen(&pendings, pendings_seen, "pending");
    assert(tally.failed + tally.pending <= tally.cases);
    return tally;
}

/// A recorded case that did not come out as recorded — fixed, or gone
/// from h3spec — is one to delete here and in §12.
fn unseen(recorded: []const []const u8, seen: []const bool, comptime what: []const u8) u32 {
    assert(recorded.len == seen.len);
    var count: u32 = 0;
    for (recorded, seen) |case, was| {
        if (was) continue;
        std.debug.print("FAIL: h3spec \"{s}\" is recorded " ++ what ++ " and was not; delete it here and in §12\n", .{case});
        count += 1;
    }
    return count;
}

/// A case line's description and mark: `  <description> [✔]`, `[✘]` or
/// `[‐]`, indented under its section as hspec writes it. Anything else — a
/// section heading, a trace, the summary — is not one.
fn caseOf(line: []const u8) ?struct { []const u8, Outcome } {
    if (!std.mem.startsWith(u8, line, "  ")) return null;
    const marks = [_]struct { text: []const u8, outcome: Outcome }{
        .{ .text = " [✔]", .outcome = .passed },
        .{ .text = " [✘]", .outcome = .failed },
        .{ .text = " [‐]", .outcome = .pending },
    };
    const trimmed = std.mem.trimEnd(u8, line, " \r");
    for (marks) |mark| {
        if (!std.mem.endsWith(u8, trimmed, mark.text)) continue;
        const case = std.mem.trim(u8, trimmed[0 .. trimmed.len - mark.text.len], " ");
        if (case.len == 0) return null;
        return .{ case, mark.outcome };
    }
    return null;
}

fn indexOf(recorded: []const []const u8, case: []const u8) ?usize {
    for (recorded, 0..) |one, index| {
        if (std.mem.eql(u8, one, case)) return index;
    }
    return null;
}

/// The summary line's three counts, or null if the report has none.
fn summaryOf(report: []const u8) ?Summary {
    var lines = std.mem.splitScalar(u8, report, '\n');
    var visited: u32 = 0;
    while (lines.next()) |line| : (visited += 1) {
        assert(visited <= report_bytes_max);
        var words = std.mem.tokenizeAny(u8, line, " ,");
        const examples = std.fmt.parseInt(u32, words.next() orelse continue, 10) catch continue;
        if (!std.mem.eql(u8, words.next() orelse continue, "examples")) continue;
        const failures = std.fmt.parseInt(u32, words.next() orelse continue, 10) catch continue;
        if (!std.mem.startsWith(u8, words.next() orelse continue, "failure")) continue;
        const pending = std.fmt.parseInt(u32, words.next() orelse "0", 10) catch 0;
        return .{ .examples = examples, .failures = failures, .pending = pending };
    }
    return null;
}

fn tallyPassed(tally: *const Tally, summary: ?Summary) bool {
    assert(tally.failed + tally.pending <= tally.cases);
    var passed = tally.unexpected == 0;
    if (tally.cases != cases_expected) {
        std.debug.print("FAIL: h3spec: {d} cases reported, {d} expected\n", .{ tally.cases, cases_expected });
        passed = false;
    }
    // The case lines, held to what h3spec says it ran: a stray line taken
    // for a case, or a case lost to an interleaving, shows here.
    const said = summary orelse Summary{ .examples = 0, .failures = 0, .pending = 0 };
    if (said.examples != tally.cases or said.failures != tally.failed or said.pending != tally.pending) {
        std.debug.print("FAIL: h3spec: its summary says {d}/{d}/{d}, its case lines {d}/{d}/{d}\n", .{
            said.examples, said.failures, said.pending, tally.cases, tally.failed, tally.pending,
        });
        passed = false;
    }
    const verdict = if (passed) "ok" else "FAIL";
    std.debug.print("h3spec: {s}, {d} cases, {d} failed ({d} recorded), {d} pending\n", .{
        verdict, tally.cases, tally.failed, deviations.len, tally.pending,
    });
    return passed;
}

fn writeConfig(arena: std.mem.Allocator, io: Io, port: u16, origin_port: u16) !void {
    assert(origin_port != 0);
    assert(port != 0);
    const config = try std.fmt.allocPrint(arena,
        \\{{
        \\    "listeners": [
        \\        {{ "bind": "127.0.0.1:{d}",
        \\          "tls": {{ "cert": "{s}", "key": "{s}" }},
        \\          "http": {{ "cluster": "origin", "quic": {{ "bind": "127.0.0.1:{d}" }} }} }}
        \\    ],
        \\    "clusters": {{ "origin": {{ "endpoints": ["127.0.0.1:{d}"] }} }},
        \\    "limits": {{ "conn_slots": {d}, "h2_streams": {d}, "quic_connections": {d}, "tls_engines": {d} }}
        \\}}
        \\
    , .{ port, tls_cert_path, tls_key_path, port, origin_port, 2 * quic_connections, 2 * quic_connections, quic_connections, quic_connections });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = config });
}

/// Kernel-assigned, as smoke's are: free for TCP when it is asked. The QUIC
/// binding takes the same number on UDP, which a collision there would
/// fail loudly at zoxy's start.
fn reservePort(io: Io) !u16 {
    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try address.listen(io, .{ .mode = .stream });
    const port = listener.socket.address.getPort();
    listener.deinit(io);
    assert(port != 0);
    return port;
}

fn spawnZoxy(io: Io, zoxy_path: []const u8) !std.process.Child {
    assert(zoxy_path.len >= 1);
    const log_file = try Io.Dir.cwd().createFile(io, zoxy_log_path, .{});
    defer log_file.close(io);
    const child = std.process.spawn(io, .{
        .argv = &.{ zoxy_path, config_path },
        .stdout = .{ .file = log_file },
        .stderr = .{ .file = log_file },
    }) catch |err| {
        std.debug.print("h3spec: could not spawn {s} ({t}); run `zig build` first\n", .{ zoxy_path, err });
        return err;
    };
    assert(child.id != null);
    return child;
}

/// Wait for the TLS listener to answer a connect, as smoke does.
fn awaitListening(io: Io, port: u16) !void {
    assert(port != 0);
    const attempts_max: u16 = 200;
    const retry_delay = Io.Duration.fromNanoseconds(25 * std.time.ns_per_ms);
    var attempt: u16 = 0;
    while (attempt < attempts_max) : (attempt += 1) {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        const stream = address.connect(io, .{ .mode = .stream }) catch {
            // Pacing, not correctness: `attempts_max` bounds the wait.
            io.sleep(retry_delay, .awake) catch {};
            continue;
        };
        stream.close(io);
        return;
    }
    assert(attempt == attempts_max);
    std.debug.print("h3spec: zoxy never listened on port {d}\n", .{port});
    return error.ZoxyNeverListened;
}

/// The head of zoxy's captured output, for a failing run.
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
        const value_index = index + 1;
        if (value_index == args.len) return usage();
        const value = args[value_index];
        index = value_index;
        if (std.mem.eql(u8, args[value_index - 1], "--zoxy")) {
            flags.zoxy_path = value;
            continue;
        }
        if (!std.mem.eql(u8, args[value_index - 1], "--h3spec")) return usage();
        flags.h3spec_path = value;
    }
    return flags;
}

fn usage() error{InvalidArguments} {
    std.debug.print("usage: zoxy-h3spec [--zoxy path] [--h3spec path]\n", .{});
    return error.InvalidArguments;
}
