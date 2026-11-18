//! The HTTP/2 conformance gate (#277, DESIGN.md §9, §12): h2spec — an
//! implementation of RFC 9113 that shares no code with this proxy — run
//! against the shipped binary, over h2c and over TLS, with the verdict an
//! equality: the cases that fail are exactly the deviations §12 records,
//! no more and no fewer, out of every case h2spec has. A deviation fixed
//! fails the gate as loudly as a regression does, so the record cannot
//! rot into excuses.
//!
//! Merge tier, like `zig build bench`, and not in `ci`: h2spec is a Go
//! binary, and §9's rule is that a per-change gate adds no dependency.
//! The dev shell provides it (devenv.nix); the harness runs it from PATH,
//! or from where `--h2spec` points.
//!
//! The origin is smoke's own (smoke/origin.zig), in this process. The
//! config is the defaults but for what HTTP/2 needs said — `h2c`, `h2` in
//! ALPN, the stream pool — and an upstream pool the origin's tasks can
//! all serve at once, so a deviation is the shipped behaviour's.

const std = @import("std");

const origin_module = @import("origin.zig");

const Io = std.Io;

const assert = std.debug.assert;

const work_directory = ".zig-cache/zoxy-h2spec";
const config_path = work_directory ++ "/zoxy.json";
const zoxy_log_path = work_directory ++ "/zoxy.log";
const tls_cert_path = work_directory ++ "/cert.pem";
const tls_key_path = work_directory ++ "/key.pem";
const tls_cert_pem = @embedFile("tls_cert_pem");
const tls_key_pem = @embedFile("tls_key_pem");

/// Every case h2spec has, on either transport: a run that reports fewer
/// lost some, and is not the run this gate judges.
const cases_expected: u32 = 145;
/// h2spec's report for 145 cases is some 20 KiB; past this, it is not one.
const report_bytes_max: usize = 1024 * 1024;

/// The longest field value h2spec writes in its header cases. Its default,
/// 4000, makes the two fields of 6.10/1 a list past the 8 KiB this proxy
/// advertises (SETTINGS_MAX_HEADER_LIST_SIZE) — which ends the connection
/// calm (§8, a deviation §12 records) and would leave that case testing
/// the bound rather than CONTINUATION.
const header_length_max = "3000";

/// Upstream connections the proxy may hold, parked or busy: under the
/// origin's tasks, each of which a parked connection occupies (see
/// `origin_module.serve_tasks`). h2spec's concurrency cases open more
/// streams than this, and the ones past it are shed `503` — an answer,
/// which is all those cases ask for.
const upstream_slots: u8 = 8;
const stream_slots: u8 = 8;

comptime {
    assert(upstream_slots + 1 < origin_module.serve_tasks);
}

const Transport = enum { h2c, tls };

/// An h2spec case this gate expects to fail — named by the section and
/// the description h2spec's report gives it, on one transport or (null)
/// both — each one a deviation §12 records and argues.
const Deviation = struct {
    transport: ?Transport,
    package: []const u8,
    case: []const u8,
};

const deviations = [_]Deviation{
    // §12: an h2c listener serves HTTP/1.1 too, so octets that are not
    // the preface are an HTTP/1.1 request, and answered as one.
    .{ .transport = .h2c, .package = "http2/3.5", .case = "Sends invalid connection preface" },
};

const Flags = struct {
    zoxy_path: []const u8 = "zig-out/bin/zoxy",
    h2spec_path: []const u8 = "h2spec",
};

const Ports = struct { h2c: u16, tls: u16 };

/// One run's tally of h2spec's report.
const Tally = struct {
    cases: u32 = 0,
    failed: u32 = 0,
    /// Failures that are recorded deviations, and deviations this
    /// transport owes that did not fail.
    expected_failed: u32 = 0,
    unexpected: u32 = 0,
};

var origin: origin_module.Origin = undefined;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const args = try init.minimal.args.toSlice(arena);
    const flags = try parseFlags(args);
    return run(arena, io, &flags) catch |err| {
        std.debug.print("FAIL: the h2spec run could not finish ({t})\n", .{err});
        printZoxyLog(io);
        return 1;
    };
}

fn run(arena: std.mem.Allocator, io: Io, flags: *const Flags) !u8 {
    try Io.Dir.cwd().createDirPath(io, work_directory);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tls_cert_path, .data = tls_cert_pem });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tls_key_path, .data = tls_key_pem });
    try origin.start(io, upstream_slots + 1);
    // Unwound after the child's own teardown below, which is what lets
    // the origin's tasks parked in `read` return.
    defer origin.stop();
    const ports = try reservePorts(io);
    try writeConfig(arena, io, &ports, origin.port);
    var child = try spawnZoxy(io, flags.zoxy_path);
    var running = true;
    defer if (running) child.kill(io);
    try awaitListening(io, ports.h2c);
    try awaitListening(io, ports.tls);

    // Both transports run and report before the verdict: a run that
    // fails on both should say so.
    var passed = true;
    for ([_]Transport{ .h2c, .tls }) |transport| {
        const port = switch (transport) {
            .h2c => ports.h2c,
            .tls => ports.tls,
        };
        const report = try runH2spec(arena, io, flags.h2spec_path, transport, port);
        const tally = try judge(transport, report);
        if (!transportPassed(transport, &tally)) passed = false;
    }
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
        "h2spec: {d} cases over h2c and over TLS, failing exactly what §12 records ({d}), clean drain\n",
        .{ cases_expected, deviations.len },
    );
    return 0;
}

fn exitedCleanly(term: std.process.Child.Term) bool {
    if (term != .exited) return false;
    return term.exited == 0;
}

/// h2spec over one transport, its report read back whole. Its exit
/// status is not the verdict — it fails whenever any case does, the
/// recorded ones included — so the JUnit report is, and one left by an
/// earlier run is deleted first: a run that wrote none must not be judged
/// by the last one's.
fn runH2spec(
    arena: std.mem.Allocator,
    io: Io,
    h2spec_path: []const u8,
    transport: Transport,
    port: u16,
) ![]const u8 {
    assert(port != 0);
    const report_path = try std.fmt.allocPrint(arena, work_directory ++ "/h2spec-{t}.xml", .{transport});
    const log_path = try std.fmt.allocPrint(arena, work_directory ++ "/h2spec-{t}.log", .{transport});
    const port_text = try std.fmt.allocPrint(arena, "{d}", .{port});
    const common = [_][]const u8{
        h2spec_path,           "-h",              "127.0.0.1", "-p", port_text, "-P",        "/",
        "--max-header-length", header_length_max, "-o",        "3",  "-j",      report_path,
    };
    Io.Dir.cwd().deleteFile(io, report_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    const tls_flags = [_][]const u8{ "-t", "-k" };
    const argv: []const []const u8 = switch (transport) {
        .h2c => &common,
        .tls => &(common ++ tls_flags),
    };
    const log_file = try Io.Dir.cwd().createFile(io, log_path, .{});
    defer log_file.close(io);
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdout = .{ .file = log_file },
        .stderr = .{ .file = log_file },
    }) catch |err| {
        std.debug.print(
            "h2spec: could not run {s} ({t}); it is in the dev shell (devenv.nix), or pass --h2spec\n",
            .{ h2spec_path, err },
        );
        return err;
    };
    _ = try child.wait(io);
    const report = Io.Dir.cwd().readFileAlloc(io, report_path, arena, .limited(report_bytes_max)) catch |err| {
        std.debug.print("FAIL: h2spec {t} wrote no report ({t}); its output is in {s}\n", .{ transport, err, log_path });
        return err;
    };
    assert(report.len <= report_bytes_max);
    return report;
}

/// Walk the report's cases: each a pass, a recorded deviation, or a
/// finding — and a recorded deviation that passed is a finding too.
fn judge(transport: Transport, report: []const u8) !Tally {
    var tally: Tally = .{};
    var owed: [deviations.len]bool = undefined;
    for (deviations, 0..) |deviation, index| {
        owed[index] = deviation.transport == null or deviation.transport.? == transport;
    }
    var rest = report;
    var cases: u32 = 0;
    // Bounded: a report holding twice the cases h2spec has is not its.
    while (std.mem.indexOf(u8, rest, "<testcase ")) |start| : (cases += 1) {
        if (cases == cases_expected * 2) return error.H2specReportOverrun;
        rest = rest[start + 1 ..];
        // A case ends at its close, or — were one ever written
        // self-closed — where the next begins, so a failure is never read
        // into the case before it.
        const close = std.mem.indexOf(u8, rest, "</testcase>") orelse return error.H2specReportCut;
        const next = std.mem.indexOf(u8, rest, "<testcase ") orelse rest.len;
        const end = @min(close, next);
        const case = rest[0..end];
        rest = rest[end..];
        tally.cases += 1;
        const failed = std.mem.indexOf(u8, case, "<failure") != null or
            std.mem.indexOf(u8, case, "<error") != null;
        if (std.mem.indexOf(u8, case, "<skipped") != null) {
            reportCase(transport, case, "skipped");
            tally.unexpected += 1;
            continue;
        }
        const recorded = deviationOf(transport, case);
        if (failed) tally.failed += 1;
        if (recorded) |index| {
            if (failed) {
                tally.expected_failed += 1;
                owed[index] = false;
            }
            continue;
        }
        if (failed) {
            reportCase(transport, case, "failed");
            tally.unexpected += 1;
        }
    }
    for (deviations, owed) |deviation, still_owed| {
        if (!still_owed) continue;
        std.debug.print(
            "FAIL: h2spec {t}: {s} \"{s}\" passed — a recorded deviation no longer is; delete it here and in §12\n",
            .{ transport, deviation.package, deviation.case },
        );
        tally.unexpected += 1;
    }
    assert(tally.expected_failed <= tally.failed);
    assert(tally.cases == cases);
    return tally;
}

fn transportPassed(transport: Transport, tally: *const Tally) bool {
    assert(tally.expected_failed <= tally.failed);
    var passed = tally.unexpected == 0;
    if (tally.cases != cases_expected) {
        std.debug.print(
            "FAIL: h2spec {t}: {d} cases reported, {d} expected\n",
            .{ transport, tally.cases, cases_expected },
        );
        passed = false;
    }
    const verdict = if (passed) "ok" else "FAIL";
    std.debug.print("h2spec {t}: {s}, {d} cases, {d} failed ({d} recorded)\n", .{
        transport, verdict, tally.cases, tally.failed, tally.expected_failed,
    });
    return passed;
}

/// The recorded deviation `case` is, if it is one this transport owes.
fn deviationOf(transport: Transport, case: []const u8) ?usize {
    const package = attribute(case, "package") orelse return null;
    const name = attribute(case, "classname") orelse return null;
    for (deviations, 0..) |deviation, index| {
        if (deviation.transport) |only| {
            if (only != transport) continue;
        }
        if (!std.mem.eql(u8, deviation.package, package)) continue;
        if (std.mem.eql(u8, deviation.case, name)) return index;
    }
    return null;
}

fn reportCase(transport: Transport, case: []const u8, what: []const u8) void {
    const package = attribute(case, "package") orelse "?";
    const name = attribute(case, "classname") orelse "?";
    std.debug.print("FAIL: h2spec {t}: {s} \"{s}\" {s}, and is no recorded deviation\n", .{
        transport, package, name, what,
    });
}

/// An attribute's raw value from a case's opening tag: h2spec writes
/// them double-quoted, and the deviations are spelled as it writes them.
fn attribute(case: []const u8, comptime name: []const u8) ?[]const u8 {
    const key = " " ++ name ++ "=\"";
    const tag_end = std.mem.indexOfScalar(u8, case, '>') orelse return null;
    const tag = case[0..tag_end];
    const at = std.mem.indexOf(u8, tag, key) orelse return null;
    const value = tag[at + key.len ..];
    const close = std.mem.indexOfScalar(u8, value, '"') orelse return null;
    assert(close < value.len);
    return value[0..close];
}

fn writeConfig(arena: std.mem.Allocator, io: Io, ports: *const Ports, origin_port: u16) !void {
    assert(origin_port != 0);
    const config = try std.fmt.allocPrint(arena,
        \\{{
        \\    "listeners": [
        \\        {{ "bind": "127.0.0.1:{d}", "http": {{ "cluster": "origin", "h2c": true }} }},
        \\        {{ "bind": "127.0.0.1:{d}", "http": {{ "cluster": "origin" }},
        \\          "tls": {{ "cert": "{s}", "key": "{s}", "alpn": ["h2"] }} }}
        \\    ],
        \\    "clusters": {{ "origin": {{ "endpoints": ["127.0.0.1:{d}"] }} }},
        \\    "limits": {{ "upstream_slots": {d}, "h2_streams": {d} }}
        \\}}
        \\
    , .{ ports.h2c, ports.tls, tls_cert_path, tls_key_path, origin_port, upstream_slots, stream_slots });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = config_path, .data = config });
}

/// Kernel-assigned, as smoke's are: a merge gate must not fail because
/// something else on the box holds a fixed port.
fn reservePorts(io: Io) !Ports {
    var h2c_address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var h2c_listener = try h2c_address.listen(io, .{ .mode = .stream });
    var tls_address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var tls_listener = try tls_address.listen(io, .{ .mode = .stream });
    const ports: Ports = .{
        .h2c = h2c_listener.socket.address.getPort(),
        .tls = tls_listener.socket.address.getPort(),
    };
    h2c_listener.deinit(io);
    tls_listener.deinit(io);
    assert(ports.h2c != 0);
    assert(ports.tls != 0);
    assert(ports.h2c != ports.tls);
    return ports;
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
        std.debug.print("h2spec: could not spawn {s} ({t}); run `zig build` first\n", .{ zoxy_path, err });
        return err;
    };
    assert(child.id != null);
    return child;
}

/// Wait for a listener to answer a connect, as smoke does.
fn awaitListening(io: Io, port: u16) !void {
    assert(port != 0);
    const attempts_max: u16 = 200;
    const retry_delay = Io.Duration.fromNanoseconds(25 * std.time.ns_per_ms);
    var attempt: u16 = 0;
    while (attempt < attempts_max) : (attempt += 1) {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        const stream = address.connect(io, .{ .mode = .stream }) catch {
            // Pacing, not correctness: a sleep that failed or woke early
            // only runs the next probe sooner, and `attempts_max` bounds
            // the wait either way.
            io.sleep(retry_delay, .awake) catch {};
            continue;
        };
        stream.close(io);
        return;
    }
    assert(attempt == attempts_max);
    std.debug.print("h2spec: zoxy never listened on port {d}\n", .{port});
    return error.ZoxyNeverListened;
}

/// The head of zoxy's captured output, for a failing run. Best-effort:
/// an unreadable log must not replace the failure being reported.
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
        if (!std.mem.eql(u8, args[value_index - 1], "--h2spec")) return usage();
        flags.h2spec_path = value;
    }
    return flags;
}

fn usage() error{InvalidArguments} {
    std.debug.print("usage: zoxy-h2spec [--zoxy path] [--h2spec path]\n", .{});
    return error.InvalidArguments;
}
