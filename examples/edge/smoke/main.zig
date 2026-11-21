//! zoxy-edge on real sockets (#417): the binary this package builds,
//! started against live origins on loopback, asked what its simulator
//! test asks (`src/edge_test.zig`), checked with `--check`, and drained
//! by SIGTERM. The proxy runs on `XevIo` — io_uring on Linux — so this is
//! the one place this package's extensions meet a real kernel.
//!
//! Its own origins, in this process: three, each answering every request
//! with `200` and its own address, which is how a response says which
//! endpoint a pick chose, and with the `x-edge-tenant` lines it was sent,
//! which is how a response says what the edge forwarded. Usage:
//! `zoxy-edge-smoke <zoxy-edge> <log>`.
//!
//! Bounded in wall-clock time by a watchdog: a proxy that stops answering
//! or never drains ends the run with its log printed, not as a CI timeout
//! with nothing to read.

const std = @import("std");

const Io = std.Io;

const assert = std.debug.assert;

/// Requests one origin serves before its task gives up: a bound, not a
/// policy — this run sends a handful.
const origin_requests_max: u32 = 1024;
/// Head bytes one request may spend at an origin.
const head_bytes_max = 2048;
/// The widest response this run reads back.
const response_bytes_max = 4096;
/// The `x-edge-tenant` values one request's head may carry to an origin,
/// comma-joined: room for the one the edge sets, and for the forgery a
/// broken edge would have let through beside it.
const tenant_lines_bytes_max = 128;
/// The most of the proxy's log a failing run prints.
const log_bytes_max = 64 * 1024;
/// The whole run's wall-clock bound, generous beside the second or so it
/// takes.
const deadline_s = 120;

/// The proxy the watchdog kills if the deadline passes; zero until spawned.
var watched_pid: std.atomic.Value(i32) = .init(0);

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) {
        std.debug.print("usage: zoxy-edge-smoke <zoxy-edge> <log>\n", .{});
        return 2;
    }
    const log_path = args[2];
    var watchdog: Io.Group = .init;
    try watchdog.concurrent(io, watch, .{io});
    defer watchdog.cancel(io);
    var app: Origin = undefined;
    var static_a: Origin = undefined;
    var static_b: Origin = undefined;
    try app.start(io);
    defer app.stop();
    try static_a.start(io);
    defer static_a.stop();
    try static_b.start(io);
    defer static_b.stop();

    const listen_port = try freePort(io);
    const listen = try std.fmt.allocPrint(arena, "127.0.0.1:{d}", .{listen_port});
    const static_list = try std.fmt.allocPrint(arena, "{s},{s}", .{ static_a.label(), static_b.label() });
    // The pre-flight first: it resolves the options and asks the box for
    // what a start would, and binds nothing.
    try expectCheckPasses(io, args[1], listen, app.label(), static_list);
    // The pre-flight's own process was waited for; it never gets a pid
    // the watchdog would have to know.

    // The banner and the drain's counter dump (§8) go to a log, read
    // back only when the run fails.
    const log_file = try Io.Dir.cwd().createFile(io, log_path, .{ .read = true });
    defer log_file.close(io);
    var child = try std.process.spawn(io, .{
        .argv = &.{ args[1], listen, app.label(), static_list },
        .stdout = .{ .file = log_file },
        .stderr = .{ .file = log_file },
    });
    var running = true;
    defer if (running) child.kill(io);
    watched_pid.store(child.id.?, .release);
    awaitListening(io, listen_port) catch |err| {
        printLog(io, arena, log_path);
        return err;
    };

    var passed = exercise(io, listen_port, &app, &static_a, &static_b);
    try std.posix.kill(child.id.?, .TERM);
    const term = try child.wait(io);
    running = false;
    passed = expectTagLogged(io, arena, log_path) and passed;
    if (!passed or !term.success()) {
        if (!term.success()) std.debug.print("FAIL: zoxy-edge did not drain cleanly on SIGTERM: {any}\n", .{term});
        printLog(io, arena, log_path);
        return 1;
    }
    std.debug.print("zoxy-edge smoke: routes, pickers, both policy phases, the tenant's challenge, " ++
        "header and tag over XevIo, clean drain\n", .{});
    return 0;
}

/// What the simulator test asks, asked of the real binary.
fn exercise(io: Io, port: u16, app: *const Origin, static_a: *const Origin, static_b: *const Origin) bool {
    const tenant = "Host: edge\r\nx-tenant: acme\r\nConnection: close\r\n\r\n";
    var passed = true;
    var buffer: [response_bytes_max]u8 = undefined;
    // `api` and `search` pick through the one shared `LeastInFlight`, over
    // the one application endpoint.
    passed = expectBody(io, port, "GET /orders HTTP/1.1\r\n" ++ tenant, &buffer, app.label()) and passed;
    // The tenant reaches the origin in the header the edge sets (#424),
    // and a copy the client forged does not.
    passed = expectHeader(
        io,
        port,
        "GET /orders HTTP/1.1\r\nx-edge-tenant: forged\r\n" ++ tenant,
        &buffer,
        "X-Saw-Tenant: acme\r\n",
    ) and passed;
    passed = expectBody(io, port, "GET /search?q=zig HTTP/1.1\r\n" ++ tenant, &buffer, app.label()) and passed;
    // One path, one endpoint, twice.
    var first: [64]u8 = undefined;
    const first_body = bodyOf(exchange(io, port, "GET /static/app.js HTTP/1.1\r\n" ++ tenant, &buffer));
    const first_len = @min(first_body.len, first.len);
    @memcpy(first[0..first_len], first_body[0..first_len]);
    const is_static = std.mem.eql(u8, first[0..first_len], static_a.label()) or
        std.mem.eql(u8, first[0..first_len], static_b.label());
    if (!is_static) {
        std.debug.print("FAIL: /static/app.js answered by '{s}'\n", .{first[0..first_len]});
        passed = false;
    }
    passed = expectBody(io, port, "GET /static/app.js HTTP/1.1\r\n" ++ tenant, &buffer, first[0..first_len]) and passed;
    // A refusal at each phase: the route's `403`, and the listener's own
    // challenge (#431), to a request that names no tenant or one that is
    // not a tenant name.
    passed = expectStatus(io, port, "POST /static/app.js HTTP/1.1\r\nContent-Length: 0\r\n" ++ tenant, &buffer, "403") and passed;
    const anonymous = "GET /orders HTTP/1.1\r\nHost: edge\r\nConnection: close\r\n\r\n";
    passed = expectHeader(io, port, anonymous, &buffer, "WWW-Authenticate: Tenant realm=\"edge\"\r\n") and passed;
    passed = expectStatus(io, port, anonymous, &buffer, "401") and passed;
    const unnamed = "GET /orders HTTP/1.1\r\nHost: edge\r\nx-tenant: a b\r\nConnection: close\r\n\r\n";
    passed = expectStatus(io, port, unnamed, &buffer, "401") and passed;
    return passed;
}

/// `line`, CRLF and all, somewhere in the response's head.
fn expectHeader(io: Io, port: u16, request: []const u8, buffer: []u8, line: []const u8) bool {
    const response = exchange(io, port, request, buffer);
    const head_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse response.len;
    if (std.mem.indexOf(u8, response[0..@min(head_end + 2, response.len)], line) != null) return true;
    std.debug.print("FAIL: {s}expected the line '{s}', got:\n{s}\n", .{ request, line, response });
    return false;
}

/// The access log (#433): `acme`'s requests carry its tag, the FNV-1a
/// hash `TenantGuard` tags them with, as the number `tag`.
fn expectTagLogged(io: Io, arena: std.mem.Allocator, log_path: []const u8) bool {
    const bytes = Io.Dir.cwd().readFileAlloc(io, log_path, arena, .limited(log_bytes_max)) catch |err| {
        std.debug.print("FAIL: the proxy's log could not be read: {s}\n", .{@errorName(err)});
        return false;
    };
    // `"tag":` and a u64's twenty digits.
    var expected: [32]u8 = undefined;
    const tag = @max(std.hash.Fnv1a_64.hash("acme"), 1);
    const field = std.fmt.bufPrint(&expected, "\"tag\":{d}", .{tag}) catch unreachable;
    if (std.mem.indexOf(u8, bytes, field) != null) return true;
    std.debug.print("FAIL: no access-log line carries {s}\n", .{field});
    return false;
}

fn expectBody(io: Io, port: u16, request: []const u8, buffer: []u8, body: []const u8) bool {
    const response = exchange(io, port, request, buffer);
    if (std.mem.startsWith(u8, response, "HTTP/1.1 200 ") and std.mem.eql(u8, bodyOf(response), body)) return true;
    std.debug.print("FAIL: {s}expected 200 '{s}', got:\n{s}\n", .{ request, body, response });
    return false;
}

fn expectStatus(io: Io, port: u16, request: []const u8, buffer: []u8, status: []const u8) bool {
    const response = exchange(io, port, request, buffer);
    if (response.len > 12 and std.mem.eql(u8, response[9..12], status)) return true;
    std.debug.print("FAIL: {s}expected {s}, got:\n{s}\n", .{ request, status, response });
    return false;
}

fn bodyOf(response: []const u8) []const u8 {
    const end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return "";
    return response[end + 4 ..];
}

/// One request on a connection of its own, read to the close it asks for.
fn exchange(io: Io, port: u16, request: []const u8, buffer: []u8) []const u8 {
    var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = address.connect(io, .{ .mode = .stream }) catch return "";
    defer stream.close(io);
    var write_buffer: [512]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    writer.interface.writeAll(request) catch return "";
    writer.interface.flush() catch return "";
    var read_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var received: usize = 0;
    // Bounded by the buffer: each read adds at least an octet, or ends.
    while (received < buffer.len) {
        const got = reader.interface.readSliceShort(buffer[received..]) catch break;
        if (got == 0) break;
        received += got;
    }
    assert(received <= buffer.len);
    return buffer[0..received];
}

fn printLog(io: Io, arena: std.mem.Allocator, log_path: []const u8) void {
    const bytes = Io.Dir.cwd().readFileAlloc(io, log_path, arena, .limited(log_bytes_max)) catch return;
    std.debug.print("--- zoxy-edge's output ---\n{s}\n", .{bytes});
}

/// The run's wall-clock bound: past the deadline, kill the proxy if one
/// was spawned and end the process. Cancelled on every ordinary exit.
fn watch(io: Io) void {
    io.sleep(Io.Duration.fromSeconds(deadline_s), .awake) catch return;
    std.debug.print("FAIL: the zoxy-edge smoke ran past {d} s\n", .{deadline_s});
    const pid = watched_pid.load(.acquire);
    if (pid != 0) std.posix.kill(pid, .KILL) catch {};
    std.process.exit(1);
}

fn expectCheckPasses(io: Io, edge: []const u8, listen: []const u8, app: []const u8, static: []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = &.{ edge, "--check", listen, app, static },
        .stdout = .ignore,
    });
    const term = try child.wait(io);
    if (!term.success()) {
        std.debug.print("FAIL: zoxy-edge --check refused its own options: {any}\n", .{term});
        return error.CheckRefused;
    }
}

/// A loopback port nothing listens on, as the kernel picks one.
fn freePort(io: Io) !u16 {
    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{ .mode = .stream });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    assert(port != 0);
    return port;
}

fn awaitListening(io: Io, port: u16) !void {
    const attempts_max: u16 = 400;
    var attempt: u16 = 0;
    while (attempt < attempts_max) : (attempt += 1) {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        const stream = address.connect(io, .{ .mode = .stream }) catch {
            io.sleep(Io.Duration.fromNanoseconds(25 * std.time.ns_per_ms), .awake) catch {};
            continue;
        };
        stream.close(io);
        return;
    }
    std.debug.print("FAIL: zoxy-edge never listened on port {d}\n", .{port});
    return error.NeverListened;
}

/// One live origin: a task that accepts, answers one request with `200`
/// and its own address, and closes.
const Origin = struct {
    io: Io,
    listener: Io.net.Server,
    port: u16,
    label_buffer: [32]u8,
    label_len: u8,
    group: Io.Group,
    stopping: std.atomic.Value(bool),

    fn start(origin: *Origin, io: Io) !void {
        origin.io = io;
        origin.group = .init;
        origin.stopping = .init(false);
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        origin.listener = try address.listen(io, .{ .mode = .stream });
        errdefer origin.listener.deinit(io);
        origin.port = origin.listener.socket.address.getPort();
        assert(origin.port != 0);
        const text = try std.fmt.bufPrint(&origin.label_buffer, "127.0.0.1:{d}", .{origin.port});
        origin.label_len = @intCast(text.len);
        try origin.group.concurrent(io, serve, .{origin});
    }

    fn label(origin: *const Origin) []const u8 {
        return origin.label_buffer[0..origin.label_len];
    }

    /// Stop accepting and join the task: the flag, then a connection of
    /// this process's own to wake the accept it is blocked in.
    fn stop(origin: *Origin) void {
        origin.stopping.store(true, .release);
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(origin.port) };
        if (address.connect(origin.io, .{ .mode = .stream })) |stream| {
            stream.close(origin.io);
        } else |_| {}
        origin.group.await(origin.io) catch {};
        origin.listener.deinit(origin.io);
    }

    fn serve(origin: *Origin) void {
        var served: u32 = 0;
        while (served < origin_requests_max) : (served += 1) {
            const stream = origin.listener.accept(origin.io) catch return;
            defer stream.close(origin.io);
            if (origin.stopping.load(.acquire)) return;
            origin.answer(stream);
        }
    }

    fn answer(origin: *Origin, stream: Io.net.Stream) void {
        var read_buffer: [head_bytes_max]u8 = undefined;
        var reader = stream.reader(origin.io, &read_buffer);
        // Every `x-edge-tenant` line's value, comma-joined: one is what
        // the edge set, and two would be a forgery it let through.
        var tenants: [tenant_lines_bytes_max]u8 = undefined;
        var tenants_len: usize = 0;
        var lines: u32 = 0;
        // Read to the blank line that ends the head; no body is read.
        while (lines < head_bytes_max / 2) : (lines += 1) {
            const line = (reader.interface.takeDelimiter('\n') catch return) orelse return;
            if (line.len == 0 or (line.len == 1 and line[0] == '\r')) break;
            const name = "x-edge-tenant:";
            if (line.len < name.len or !std.ascii.eqlIgnoreCase(line[0..name.len], name)) continue;
            const value = std.mem.trim(u8, line[name.len..], " \t\r");
            const separator: usize = @intFromBool(tenants_len != 0);
            if (tenants_len + separator + value.len > tenants.len) return;
            if (separator == 1) tenants[tenants_len] = ',';
            @memcpy(tenants[tenants_len + separator ..][0..value.len], value);
            tenants_len += separator + value.len;
        }
        assert(tenants_len <= tenants.len);
        var write_buffer: [512]u8 = undefined;
        var writer = stream.writer(origin.io, &write_buffer);
        writer.interface.print(
            "HTTP/1.1 200 OK\r\nX-Saw-Tenant: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
            .{ tenants[0..tenants_len], origin.label_len, origin.label() },
        ) catch return;
        writer.interface.flush() catch return;
    }
};
