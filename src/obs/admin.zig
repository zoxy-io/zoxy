//! Minimal admin plane: a blocking TCP listener, served by one dedicated
//! thread, that answers every HTTP request with the Prometheus-style metrics
//! exposition. Deliberately not on the io_uring data path — the workers never
//! touch it, it holds no locks the workers see (counters are atomics), and it
//! allocates nothing: both the response head and body live in fixed buffers.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const assert = std.debug.assert;

const constants = @import("../constants.zig");
const Metrics = @import("metrics.zig").Metrics;
const tls = @import("../tls/openssl.zig");
const Ip4Address = std.Io.net.Ip4Address;

/// Gauge lines appended for the TLS hook heap when TLS is configured;
/// counted into the body-size comptime check alongside the Metrics fields.
const tls_heap_gauge_count = 5;

/// Sized for every counter in `Metrics` plus one labeled series per worker
/// slot; the comptime check in `serve_one` keeps this honest as counters grow.
const body_bytes_max = 32 * 1024;
const head_bytes_max = 256;
const accept_backlog = 8;

pub const Admin = struct {
    fd: posix.socket_t,
    metrics: *const Metrics,

    pub const OpenError = error{
        SocketCreateFailed,
        SetSockOptFailed,
        BindFailed,
        ListenFailed,
    };

    /// Open a *blocking* listener (unlike the data-path listeners: this one
    /// is drained by a dedicated thread, not an io_uring loop).
    pub fn open(address: Ip4Address, metrics: *const Metrics) OpenError!Admin {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.SocketCreateFailed;
        const fd: posix.socket_t = @intCast(rc);
        assert(fd >= 0);
        errdefer _ = linux.close(fd);

        // REUSEPORT as well as REUSEADDR: during a hot restart the draining
        // predecessor still holds this port — the successor must bind beside
        // it or die *after* the listener handoff, taking both processes (and
        // the handed-off accept queues) down. Scrapes during the overlap hit
        // either process; the survivor owns the port once the drain ends.
        const on: c_int = 1;
        posix.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&on)) catch
            return error.SetSockOptFailed;
        posix.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, std.mem.asBytes(&on)) catch
            return error.SetSockOptFailed;

        var sa = sockaddr_in(address);
        if (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS) {
            return error.BindFailed;
        }
        if (linux.errno(linux.listen(fd, accept_backlog)) != .SUCCESS) {
            return error.ListenFailed;
        }
        return .{ .fd = fd, .metrics = metrics };
    }

    pub fn close(admin: *Admin) void {
        _ = linux.close(admin.fd);
        admin.* = undefined;
    }

    /// The bound address, resolving an ephemeral port assigned by the kernel.
    pub fn bound_address(admin: Admin) Ip4Address {
        var sa: linux.sockaddr.in = undefined;
        var len: posix.socklen_t = @sizeOf(linux.sockaddr.in);
        const rc = linux.getsockname(admin.fd, @ptrCast(&sa), &len);
        assert(linux.errno(rc) == .SUCCESS);
        assert(sa.family == linux.AF.INET);
        return .{ .bytes = @bitCast(sa.addr), .port = std.mem.bigToNative(u16, sa.port) };
    }

    /// Serve forever, one connection at a time. The admin plane is best-effort
    /// by design: per-connection errors are dropped, never fatal.
    pub fn run(admin: *Admin) void {
        while (true) admin.serve_one();
    }

    /// Accept one connection, answer it with the metrics exposition, close it.
    pub fn serve_one(admin: *Admin) void {
        const rc = linux.accept4(admin.fd, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(rc) != .SUCCESS) return;
        const fd: posix.socket_t = @intCast(rc);
        assert(fd >= 0);
        defer _ = linux.close(fd);

        // Best-effort drain of the request head so the peer is not reset
        // mid-write; the response is the same whatever was asked.
        var request_buf: [1024]u8 = undefined;
        _ = linux.read(fd, &request_buf, request_buf.len);

        var body_buf: [body_bytes_max]u8 = undefined;
        comptime { // every counter line must fit: name prefix + u64 digits + newline
            const fields = @typeInfo(Metrics).@"struct".fields;
            const lines = fields.len + constants.workers_max + tls_heap_gauge_count;
            assert(lines * 64 <= body_bytes_max);
        }
        var body_writer = std.Io.Writer.fixed(&body_buf);
        admin.metrics.write_text(&body_writer) catch return;
        write_tls_heap_stats(&body_writer) catch return;
        const body = body_writer.buffered();
        assert(body.len > 0);
        assert(body.len <= body_bytes_max);

        var head_buf: [head_bytes_max]u8 = undefined;
        const head = std.fmt.bufPrint(&head_buf, "HTTP/1.0 200 OK\r\n" ++
            "Content-Type: text/plain; version=0.0.4\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n\r\n", .{body.len}) catch return;
        write_all(fd, head);
        write_all(fd, body);
    }
};

/// The TLS hook heap's gauges (docs/DESIGN.md §6) — absent entirely on a
/// plaintext deployment (no hook installed). `live` is the FFI analogue of
/// pool occupancy; `rejections` counts load-shed OpenSSL operations; carved
/// vs capacity is how much of the reserved TLS heap has ever been needed.
fn write_tls_heap_stats(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    const stats = tls.memory_hook_stats_if_installed() orelse return;
    assert(stats.region_bytes > 0); // an installed hook has a region
    assert(stats.carved_bytes <= stats.region_bytes);
    try writer.print("zoxy_tls_heap_live {d}\n", .{stats.live_count});
    try writer.print("zoxy_tls_heap_allocations_total {d}\n", .{stats.allocation_count});
    try writer.print("zoxy_tls_heap_rejections_total {d}\n", .{stats.rejection_count});
    try writer.print("zoxy_tls_heap_carved_bytes {d}\n", .{stats.carved_bytes});
    try writer.print("zoxy_tls_heap_capacity_bytes {d}\n", .{stats.region_bytes});
}

/// Blocking best-effort write of the whole buffer; gives up on any error.
fn write_all(fd: posix.socket_t, bytes: []const u8) void {
    assert(bytes.len > 0);
    var sent: usize = 0;
    while (sent < bytes.len) { // bounded: every iteration sends >= 1 byte or returns
        const rc = linux.write(fd, bytes[sent..].ptr, bytes.len - sent);
        if (linux.errno(rc) != .SUCCESS) return;
        if (rc == 0) return;
        sent += rc;
        assert(sent <= bytes.len);
    }
}

fn sockaddr_in(address: Ip4Address) linux.sockaddr.in {
    return .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, address.port),
        .addr = @bitCast(address.bytes),
    };
}

// ---- tests ----------------------------------------------------------------

test "admin: serves the metrics exposition over HTTP" {
    // The mod test binary shares one process-global hook; with it installed
    // the exposition must include the TLS heap gauges.
    tls.install_memory_hook_for_tests();
    var metrics = Metrics{};
    metrics.requests.add(7);
    metrics.accepted.add(2);

    var admin = try Admin.open(Ip4Address.loopback(0), &metrics);
    defer admin.close();
    const port = admin.bound_address().port;

    // Blocking loopback client: connect, send a request, then let serve_one
    // (same thread) accept and respond before we read the reply back.
    const client: posix.socket_t = blk: {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        try std.testing.expect(linux.errno(rc) == .SUCCESS);
        break :blk @intCast(rc);
    };
    defer _ = linux.close(client);
    var sa = sockaddr_in(Ip4Address.loopback(port));
    try std.testing.expect(
        linux.errno(linux.connect(client, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) == .SUCCESS,
    );
    const request = "GET /metrics HTTP/1.0\r\n\r\n";
    _ = linux.write(client, request, request.len);

    admin.serve_one();

    var response_buf: [body_bytes_max + head_bytes_max]u8 = undefined;
    var response_len: usize = 0;
    while (true) { // read to EOF (serve_one closed its end)
        const rc = linux.read(client, response_buf[response_len..].ptr, 512);
        try std.testing.expect(linux.errno(rc) == .SUCCESS);
        if (rc == 0) break;
        response_len += rc;
    }
    const response = response_buf[0..response_len];
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.0 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "zoxy_requests 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "zoxy_accepted 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "zoxy_rejected 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "zoxy_tls_heap_live ") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "zoxy_tls_heap_capacity_bytes ") != null);
}
